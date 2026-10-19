package tls_client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/fhttp/http2/hpack"
	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/tls-client/bandwidth"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"golang.org/x/net/proxy"
)

const defaultIdleConnectionTimeout = 90 * time.Second
const CHROME_MAX_FIELD_SECTION_SIZE = 262144

type roundTripper struct {
	initialStreamID   uint32
	allowHTTP         bool
	clientHelloId     tls.ClientHelloID
	certificatePinner CertificatePinner

	dialer proxy.ContextDialer

	bandwidthTracker bandwidth.BandwidthTracker

	clientSessionCache tls.ClientSessionCache

	badPinHandlerFunc BadPinHandlerFunc
	// cachedConnections and dialLocks are the roundTripper's own mutex's.
	cachedConnections map[string]net.Conn
	cachedTransports  map[string]http.RoundTripper
	// setups are the first dials for addresses no transport is cached for,
	// under cachedTransportsLck: the requests to an address wait for its own,
	// and those to other addresses go on.
	setups map[string]*setup
	// dialLocks have the connections to one address dialed one after
	// another, apart from those to every other address.
	dialLocks map[string]*dialLock

	// cachedKinds records which kind of transport is cached for each address, so
	// a later handshake to the same address can tell whether it still fits the
	// protocol the server just negotiated.
	//
	// It holds the kind rather than the ALPN string because several protocols
	// share one transport: a server that negotiates nothing and one that
	// negotiates "http/1.1" both get the HTTP/1 transport, and comparing the raw
	// strings would throw away a perfectly good transport when a load balancer
	// omits ALPN on one connection.
	//
	// It has a mutex of its own rather than sharing cachedTransportsLck: a
	// reconnect from the transport's own dialer reads it with no other lock
	// held, and a transport is cached, and its kind with it, under
	// cachedTransportsLck.
	cachedKinds    map[string]transportKind
	cachedKindsLck sync.Mutex

	headerPriority        *http2.PriorityParam
	headerRepresentation  func(hpack.HeaderField) hpack.Representation
	maxEncoderTableSize   uint32
	windowUpdateDelay     time.Duration
	maxHeaderFramePayload uint32
	maxDataFramePayload   uint32
	// dynamicRecordSizingDisabled has TLS write records as large as what is
	// written allows from a connection's first byte.
	dynamicRecordSizingDisabled bool
	// falseStart is every connection's tls.Config.FalseStart.
	falseStart bool
	// maxMergedHeadAndBody is the HTTP/1.1 transport's MaxMergedHeadAndBody.
	maxMergedHeadAndBody int
	// strictMaxConcurrentStreams is the HTTP/2 transport's
	// StrictMaxConcurrentStreams.
	strictMaxConcurrentStreams bool
	settings                   map[http2.SettingID]uint32
	transportOptions           *TransportOptions
	serverNameOverwrite        string
	priorities                 []http2.Priority
	pseudoHeaderOrder          []string
	settingsOrder              []http2.SettingID
	sync.Mutex

	cachedTransportsLck sync.Mutex
	connectionFlow      uint32

	forceHttp1   bool
	disableHttp3 bool
	proxyURL     string

	// racer handles HTTP/3 racing (nil if racing is disabled)
	racer *protocolRacer

	// HTTP/3 specific settings
	http3Settings          map[uint64]uint64
	http3SettingsOrder     []uint64
	http3PriorityParam     uint32
	http3PseudoHeaderOrder []string
	http3SendGreaseFrames  bool

	insecureSkipVerify          bool
	withRandomTlsExtensionOrder bool
	disableIPV6                 bool
	disableIPV4                 bool

	// lookup, when set, has requests to one host share the HTTP/2
	// connections of others (coalesce.go): every address that negotiates h2
	// is then served by shared, one transport, whose pool can see them all.
	lookup LookupFunc
	shared *http2.Transport
	// stashed are the addresses whose connection, dialed to find out the
	// protocol, waits in cachedConnections to be taken up: a request to one
	// is not offered another's.
	stashed sync.Map
}

// http3Config contains all parameters needed to build an HTTP/3 transport
type http3Config struct {
	clientSessionCache     tls.ClientSessionCache
	insecureSkipVerify     bool
	serverNameOverwrite    string
	transportOptions       *TransportOptions
	http3Settings          map[uint64]uint64
	http3SettingsOrder     []uint64
	http3PriorityParam     uint32
	http3PseudoHeaderOrder []string
	http3SendGreaseFrames  bool
	proxyURL               string
}

// transportKind is which of the three transports an ALPN result maps to.
// Several protocols share one, which is why the kind rather than the protocol
// string is what gets compared on a reconnect.
type transportKind int

const (
	transportHTTP1 transportKind = iota
	transportHTTP2
	transportHTTP3
)

func kindForProtocol(protocol string) transportKind {
	switch protocol {
	case http2.NextProtoTLS:
		return transportHTTP2
	case http3.NextProtoH3:
		return transportHTTP3
	default:
		return transportHTTP1
	}
}

// errProtocolChanged is returned by dialTLS when the handshake negotiated a
// protocol the cached transport for that address cannot speak.
var errProtocolChanged = errors.New("tls-client: the server negotiated a protocol the cached transport does not speak")

func (rt *roundTripper) cachedKind(addr string) (transportKind, bool) {
	rt.cachedKindsLck.Lock()
	defer rt.cachedKindsLck.Unlock()

	kind, ok := rt.cachedKinds[addr]
	return kind, ok
}

func (rt *roundTripper) setCachedKind(addr string, kind transportKind) {
	rt.cachedKindsLck.Lock()
	defer rt.cachedKindsLck.Unlock()

	rt.cachedKinds[addr] = kind
}

// dropCachedTransport forgets the transport cached for addr.
//
// This lives here rather than in dialTLS because it writes cachedTransports,
// and dialTLS runs without the lock that guards it whenever a cached transport
// dials a replacement connection. It is only dropped when it is still the one
// that failed, and its kind with it, so a transport another goroutine has
// already replaced is left alone, and its kind too.
func (rt *roundTripper) dropCachedTransport(addr string, stale http.RoundTripper) {
	rt.cachedTransportsLck.Lock()
	if rt.cachedTransports[addr] == stale {
		delete(rt.cachedTransports, addr)
		// Its kind with it, and only its: one cached since is another
		// transport's.
		rt.cachedKindsLck.Lock()
		delete(rt.cachedKinds, addr)
		rt.cachedKindsLck.Unlock()
	}
	// The shared HTTP/2 transport's idle connections are other hosts' too.
	shared := false
	for _, t := range rt.cachedTransports {
		shared = shared || t == stale
	}
	rt.cachedTransportsLck.Unlock()
	dropping(addr)

	if closer, ok := stale.(interface{ CloseIdleConnections() }); ok && !shared {
		closer.CloseIdleConnections()
	}
}

func (rt *roundTripper) CloseIdleConnections() {
	rt.cachedTransportsLck.Lock()
	defer rt.cachedTransportsLck.Unlock()

	type closeIdler interface {
		CloseIdleConnections()
	}

	for _, transport := range rt.cachedTransports {
		if tr, ok := transport.(closeIdler); ok {
			tr.CloseIdleConnections()
		}
	}
}

func (rt *roundTripper) getHttp3Settings() map[uint64]uint64 {
	if len(rt.http3Settings) == 0 {
		return nil
	}

	// Build settings in the correct order
	orderedSettings := make(map[uint64]uint64)
	if len(rt.http3SettingsOrder) > 0 {
		for _, id := range rt.http3SettingsOrder {
			if val, ok := rt.http3Settings[id]; ok {
				orderedSettings[id] = val
			}
		}
		return orderedSettings
	}

	return rt.http3Settings
}

func buildHTTP3Transport(cfg *http3Config) (http.RoundTripper, error) {
	utlsConfig := &tls.Config{
		ClientSessionCache: cfg.clientSessionCache,
		InsecureSkipVerify: cfg.insecureSkipVerify,
		OmitEmptyPsk:       true,
	}
	if cfg.transportOptions != nil {
		utlsConfig.RootCAs = cfg.transportOptions.RootCAs
		utlsConfig.Certificates = cfg.transportOptions.Certificates
	}

	if cfg.serverNameOverwrite != "" {
		utlsConfig.ServerName = cfg.serverNameOverwrite
	}

	t3 := &http3.Transport{
		TLSClientConfig: utlsConfig,
		EnableDatagrams: true, // Chrome enables H3_DATAGRAM (setting 0x33)
	}

	if cfg.proxyURL != "" {
		parsedURL, parseErr := url.Parse(cfg.proxyURL)
		if parseErr != nil {
			return nil, fmt.Errorf("can not use proxy for HTTP/3: invalid proxy url: %w", parseErr)
		}

		// Only SOCKS5 can tunnel UDP (via UDP ASSOCIATE), which QUIC requires. Every other
		// scheme would leave the QUIC connection unproxied and leak the real IP, so refuse
		// here instead of silently dialing direct.
		if parsedURL.Scheme != "socks5" && parsedURL.Scheme != "socks5h" {
			return nil, fmt.Errorf("can not use proxy for HTTP/3: proxy scheme %q only supports TCP and can not tunnel QUIC/UDP traffic. Use a socks5:// proxy or disable HTTP/3", parsedURL.Scheme)
		}

		t3.Dial = newSOCKS5QUICDialer(cfg.proxyURL)
	}

	http3Settings := cfg.http3Settings

	if http3Settings != nil {
		settingsCopy := make(map[uint64]uint64, len(http3Settings))
		for k, v := range http3Settings {
			settingsCopy[k] = v
		}
		http3Settings = settingsCopy
	}

	// Add random GREASE setting only for browsers that send it (Chrome)
	// Firefox sends GREASE frames but not random GREASE settings
	// Use priority parameter as identification: Chrome has it, Firefox doesn't
	if cfg.http3PriorityParam > 0 {
		greaseID := generateGREASESettingID()
		greaseValue := generateGREASESettingValue()

		if http3Settings == nil {
			http3Settings = make(map[uint64]uint64)
		}
		http3Settings[greaseID] = greaseValue

		// Set the order if available, and append GREASE at the end
		if len(cfg.http3SettingsOrder) > 0 {
			orderWithGrease := make([]uint64, len(cfg.http3SettingsOrder)+1)
			copy(orderWithGrease, cfg.http3SettingsOrder)
			orderWithGrease[len(cfg.http3SettingsOrder)] = greaseID
			t3.AdditionalSettingsOrder = orderWithGrease
		}
	} else {
		// Just use the settings order as-is without random GREASE
		if len(cfg.http3SettingsOrder) > 0 {
			t3.AdditionalSettingsOrder = cfg.http3SettingsOrder
		}
	}

	t3.AdditionalSettings = http3Settings

	if len(cfg.http3PseudoHeaderOrder) > 0 {
		t3.PseudoHeaderOrder = cfg.http3PseudoHeaderOrder
	}

	// Enable GREASE frames based on profile (Chrome sends GREASE frames, Firefox doesn't)
	t3.SendGreaseFrames = cfg.http3SendGreaseFrames

	t3.PriorityParam = cfg.http3PriorityParam

	if cfg.transportOptions != nil {
		t3.DisableCompression = cfg.transportOptions.DisableCompression

		maxResponseHeaderBytes, convErr := Int64ToInt(cfg.transportOptions.MaxResponseHeaderBytes)
		if convErr != nil {
			return nil, fmt.Errorf("error converting MaxResponseHeaderBytes to int: %w", convErr)
		}

		if maxResponseHeaderBytes > 0 {
			t3.MaxResponseHeaderBytes = maxResponseHeaderBytes
		} else if maxResponseHeaderBytes < 0 {
			// -1 means don't send SETTINGS_MAX_FIELD_SECTION_SIZE (Firefox behavior)
			t3.MaxResponseHeaderBytes = -1
		} else {
			t3.MaxResponseHeaderBytes = profileDefaultMaxResponseHeaderBytes(cfg)
		}
	} else {
		t3.MaxResponseHeaderBytes = profileDefaultMaxResponseHeaderBytes(cfg)
	}

	return t3, nil
}

func profileDefaultMaxResponseHeaderBytes(cfg *http3Config) int {
	if cfg.http3PriorityParam > 0 {
		return CHROME_MAX_FIELD_SECTION_SIZE
	}
	return -1
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := rt.getDialTLSAddr(req)

	if rt.racer != nil && !rt.forceHttp1 && !rt.disableHttp3 && strings.ToLower(req.URL.Scheme) == "https" {
		return rt.racer.race(req, addr, rt.getTransport)
	}

	// A connection dialed for the request spoke another protocol than the
	// transport it was dialed for, which is dropped: nothing of the request
	// was sent, and it goes again, on a transport set up for what the server
	// speaks now, a few times at most.
	for changes := 0; ; changes++ {
		resp, err := rt.roundTrip(req, addr)
		if !errors.Is(err, errProtocolChanged) || changes == protocolChanges {
			return resp, err
		}
	}
}

// protocolChanges is how many times a request goes again for a protocol a
// server changed: one a server that changes it now and then needs, a few for
// requests at once that take each other's connections.
const protocolChanges = 3

// roundTrip sends req to addr once: on a connection of a host it may share
// one with, or by the transport cached for addr, set up when there is none.
func (rt *roundTripper) roundTrip(req *http.Request, addr string) (*http.Response, error) {
	for {
		rt.cachedTransportsLck.Lock()
		if shared := rt.shared; shared != nil && rt.cachedTransports[addr] == nil && strings.ToLower(req.URL.Scheme) == "https" {
			rt.cachedTransportsLck.Unlock()
			if resp, sent, err := rt.coalesced(shared, req, addr); sent {
				return resp, err
			}
			rt.cachedTransportsLck.Lock()
		}
		if t, ok := rt.cachedTransports[addr]; ok {
			rt.cachedTransportsLck.Unlock()

			resp, err := t.RoundTrip(req)
			if err != nil && errors.Is(err, errProtocolChanged) {
				rt.dropCachedTransport(addr, t)
			}

			return resp, err
		}

		// No transport for addr yet. The first request to it sets one up,
		// with no lock held while it dials, and the others to it wait for
		// that, no longer than their contexts let them; the requests to other
		// addresses go on.
		s, waiting := rt.setups[addr]
		if !waiting {
			s = &setup{done: make(chan struct{})}
			rt.setups[addr] = s
		}
		rt.cachedTransportsLck.Unlock()

		if waiting {
			waitingForSetup(addr)
			select {
			case <-s.done:
				// Set up, or not: one that failed leaves the next request to
				// set one up for itself, as each did after the one before.
				continue
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}

		if err := rt.setUp(req, addr, s); err != nil {
			if errors.Is(err, ErrBadPinDetected) && rt.badPinHandlerFunc != nil {
				rt.badPinHandlerFunc(req)
			}

			return nil, err
		}
	}
}

// setup is a first dial for an address, which the requests to it wait for.
type setup struct {
	done chan struct{}
}

// waitingForSetup is told of each request that waits for another's setup of
// addr, reconnected of each connection a transport dialed for addr once its
// handshake is done, and dropping of each transport for addr dropped: the
// tests' seams.
var (
	waitingForSetup = func(addr string) {}
	reconnected     = func(addr string) {}
	dropping        = func(addr string) {}
)

// setUp sets up the transport for addr, and caches it, holding
// cachedTransportsLck only to cache it: the dial that finds out what the
// server speaks holds no lock, and other addresses go on. s is closed once
// it is done, whatever came of it.
func (rt *roundTripper) setUp(req *http.Request, addr string, s *setup) error {
	conn, err := rt.discover(req, addr)

	rt.cachedTransportsLck.Lock()
	if err == nil {
		err = rt.cache(addr, conn)
	}
	delete(rt.setups, addr)
	rt.cachedTransportsLck.Unlock()
	close(s.done)

	return err
}

// getTransport sets up the transport for addr, and caches it, while the
// caller holds cachedTransportsLck, as the protocol racer does.
func (rt *roundTripper) getTransport(req *http.Request, addr string) error {
	conn, err := rt.discover(req, addr)
	if err != nil {
		return err
	}

	return rt.cache(addr, conn)
}

// discover is the connection that finds out what the server at addr speaks,
// dialed within req's context: nil for plain http, which needs none.
func (rt *roundTripper) discover(req *http.Request, addr string) (*tls.UConn, error) {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		return nil, nil
	case "https":
	default:
		return nil, fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	ctx := req.Context()
	unlock, err := rt.lockDial(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// One left by a transport since dropped would never be taken up.
	if stale := rt.takeStashed(addr); stale != nil {
		_ = stale.Close()
	}

	return rt.handshake(ctx, "tcp", addr)
}

// cache caches the transport for addr that what was negotiated on conn calls
// for, or the HTTP/1 transport for plain http (conn nil), and stashes conn for
// it to take up. cachedTransportsLck is held.
func (rt *roundTripper) cache(addr string, conn *tls.UConn) error {
	if conn == nil {
		rt.cachedTransports[addr] = rt.buildHttp1Transport()
		return nil
	}

	negotiatedProtocol := conn.ConnectionState().NegotiatedProtocol

	// Create a transport based on the results of ALPN if no http1 is
	// enforced.
	switch negotiatedProtocol {
	case http2.NextProtoTLS:
		if rt.shared != nil {
			rt.cachedTransports[addr] = rt.shared
			rt.setCachedKind(addr, transportHTTP2)
			break
		}
		utlsConfig := &tls.Config{ClientSessionCache: rt.clientSessionCache, InsecureSkipVerify: rt.insecureSkipVerify, OmitEmptyPsk: true,
			DynamicRecordSizingDisabled: rt.dynamicRecordSizingDisabled, FalseStart: rt.falseStart}
		if rt.transportOptions != nil {
			utlsConfig.RootCAs = rt.transportOptions.RootCAs
			utlsConfig.Certificates = rt.transportOptions.Certificates
		}

		if rt.serverNameOverwrite != "" {
			utlsConfig.ServerName = rt.serverNameOverwrite
		}

		idleConnectionTimeout := defaultIdleConnectionTimeout

		if rt.transportOptions != nil && rt.transportOptions.IdleConnTimeout != nil {
			idleConnectionTimeout = *rt.transportOptions.IdleConnTimeout
		}

		t2 := http2.Transport{
			DialTLSContext:  rt.dialTLSHTTP2,
			TLSClientConfig: utlsConfig,
			ConnectionFlow:  rt.connectionFlow,
			HeaderPriority:  rt.headerPriority,
			IdleConnTimeout: idleConnectionTimeout,

			HeaderRepresentation:       rt.headerRepresentation,
			MaxEncoderHeaderTableSize:  rt.maxEncoderTableSize,
			WindowUpdateDelay:          rt.windowUpdateDelay,
			MaxHeaderFramePayload:      rt.maxHeaderFramePayload,
			MaxDataFramePayload:        rt.maxDataFramePayload,
			StrictMaxConcurrentStreams: rt.strictMaxConcurrentStreams,
			InitialStreamID:            rt.initialStreamID,
			AllowHTTP:                  rt.allowHTTP,
		}

		if rt.transportOptions != nil {
			t2.DisableCompression = rt.transportOptions.DisableCompression

			t1 := t2.GetT1()
			if t1 != nil {
				t1.DisableKeepAlives = rt.transportOptions.DisableKeepAlives
				t1.DisableCompression = rt.transportOptions.DisableCompression
				t1.MaxIdleConns = rt.transportOptions.MaxIdleConns
				t1.MaxIdleConnsPerHost = rt.transportOptions.MaxIdleConnsPerHost
				t1.MaxConnsPerHost = rt.transportOptions.MaxConnsPerHost
				// Only set MaxResponseHeaderBytes if > 0 (HTTP/1.1 transport doesn't understand -1)
				if rt.transportOptions.MaxResponseHeaderBytes > 0 {
					t1.MaxResponseHeaderBytes = rt.transportOptions.MaxResponseHeaderBytes
				}
				t1.WriteBufferSize = rt.transportOptions.WriteBufferSize
				t1.ReadBufferSize = rt.transportOptions.ReadBufferSize
				t1.IdleConnTimeout = idleConnectionTimeout
			}
		}

		if rt.pseudoHeaderOrder == nil {
			t2.PseudoHeaderOrder = []string{}
		} else {
			t2.PseudoHeaderOrder = rt.pseudoHeaderOrder
		}

		if rt.settings == nil {
			// when we not provide a map of custom http2 settings
			t2.Settings = map[http2.SettingID]uint32{
				http2.SettingMaxConcurrentStreams: 1000,
				http2.SettingMaxFrameSize:         16384,
				http2.SettingInitialWindowSize:    6291456,
				http2.SettingHeaderTableSize:      65536,
			}

			keys := make([]http2.SettingID, len(t2.Settings))

			i := 0
			// attention: the order might be random here for default values!
			for k := range t2.Settings {
				keys[i] = k
				i++
			}

			t2.SettingsOrder = keys
		} else {
			// use custom http2 settings
			t2.Settings = rt.settings
			t2.SettingsOrder = rt.settingsOrder
		}

		t2.Priorities = rt.priorities

		t2.PushHandler = &http2.DefaultPushHandler{}
		if rt.lookup != nil {
			t2.Coalesce = rt.coalescable
			rt.shared = &t2
		}
		rt.cachedTransports[addr] = &t2
		rt.setCachedKind(addr, transportHTTP2)
	case http3.NextProtoH3:
		t3, err := buildHTTP3Transport(&http3Config{
			clientSessionCache:     rt.clientSessionCache,
			insecureSkipVerify:     rt.insecureSkipVerify,
			serverNameOverwrite:    rt.serverNameOverwrite,
			transportOptions:       rt.transportOptions,
			http3Settings:          rt.getHttp3Settings(),
			http3SettingsOrder:     rt.http3SettingsOrder,
			http3PriorityParam:     rt.http3PriorityParam,
			http3PseudoHeaderOrder: rt.http3PseudoHeaderOrder,
			http3SendGreaseFrames:  rt.http3SendGreaseFrames,
			proxyURL:               rt.proxyURL,
		})
		if err != nil {
			return err
		}
		rt.cachedTransports[addr] = t3
		rt.setCachedKind(addr, transportHTTP3)
	default:
		rt.cachedTransports[addr] = rt.buildHttp1Transport()
		rt.setCachedKind(addr, transportHTTP1)
	}

	// Stash the connection just established for use servicing the
	// actual request (should be near-immediate).
	rt.Lock()
	rt.cachedConnections[addr] = conn
	rt.Unlock()
	rt.stashed.Store(addr, true)

	return nil
}

// dialTLS is the transports' own dial, with the context of the request a
// connection is dialed for: the connection a setup stashed for addr, or one
// dialed now.
func (rt *roundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	unlock, err := rt.lockDial(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// If we have the connection from when we determined the HTTPS
	// cachedTransports to use, return that.
	if conn := rt.takeStashed(addr); conn != nil {
		return conn, nil
	}

	conn, err := rt.handshake(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	reconnected(addr)

	negotiatedProtocol := conn.ConnectionState().NegotiatedProtocol
	negotiatedKind := kindForProtocol(negotiatedProtocol)

	// The connection is the transport's that dialed it, which takes it only
	// when it speaks what the transport does.
	//
	// Servers do change their mind: an address behind a load balancer can offer
	// http/1.1 on one connection and h2 on the next. Handing the new connection to
	// the cached transport regardless means an HTTP/1 transport reading an HTTP/2
	// SETTINGS frame as if it were a status line, which fails with a "malformed
	// HTTP response" naming the raw frame bytes and keeps failing for that address
	// until the whole client is thrown away.
	//
	// Nor does this dial build a transport for what it found, when the server
	// changed its mind or the transport was dropped as it dialed: only a setup
	// builds one, under the lock that guards the transports. Report it, and
	// RoundTrip drops the transport and sends the request again, on one set up
	// for what the server speaks now.
	if cachedKind, ok := rt.cachedKind(addr); ok && cachedKind == negotiatedKind {
		return conn, nil
	}

	_ = conn.Close()

	return nil, fmt.Errorf("%w: %s negotiated %q", errProtocolChanged, addr, negotiatedProtocol)
}

// handshake dials addr and shakes hands as the profile says, within ctx, and
// holds the server to the pins it has.
func (rt *roundTripper) handshake(ctx context.Context, network, addr string) (*tls.UConn, error) {
	if network == "tcp" && rt.disableIPV6 {
		network = "tcp4"
	}

	if network == "tcp" && rt.disableIPV4 {
		network = "tcp6"
	}

	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		// A proxy's dialer can say how it was cut short, not why.
		return nil, contextOr(ctx, err)
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	if rt.serverNameOverwrite != "" {
		host = rt.serverNameOverwrite
	}

	tlsConfig := &tls.Config{ClientSessionCache: rt.clientSessionCache, ServerName: host, InsecureSkipVerify: rt.insecureSkipVerify, OmitEmptyPsk: true,
		DynamicRecordSizingDisabled: rt.dynamicRecordSizingDisabled, FalseStart: rt.falseStart}
	if rt.transportOptions != nil {
		tlsConfig.RootCAs = rt.transportOptions.RootCAs
		tlsConfig.KeyLogWriter = rt.transportOptions.KeyLogWriter
		tlsConfig.Certificates = rt.transportOptions.Certificates
	}

	rawConn = rt.bandwidthTracker.TrackConnection(ctx, rawConn)

	conn := tls.UClient(rawConn, tlsConfig, rt.clientHelloId, rt.withRandomTlsExtensionOrder, rt.forceHttp1, rt.disableHttp3)
	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()

		return nil, err
	}

	err = rt.certificatePinner.Pin(conn, host)

	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

// takeStashed takes the connection a setup stashed for addr, if there is one.
func (rt *roundTripper) takeStashed(addr string) net.Conn {
	rt.Lock()
	defer rt.Unlock()

	conn := rt.cachedConnections[addr]
	if conn != nil {
		delete(rt.cachedConnections, addr)
		rt.stashed.Delete(addr)
	}

	return conn
}

// dialLock is an address's: holders are the dials that hold it or wait for
// it, under the roundTripper's own mutex.
type dialLock struct {
	held    chan struct{}
	holders int
}

// lockDial waits, no longer than ctx lets it, until nothing else dials addr,
// and is what lets addr be dialed again. Connections to one address are
// dialed one after another, as the roundTripper had dialed every one, so a
// connection after the first resumes its session; one to another address is
// not held up by them.
func (rt *roundTripper) lockDial(ctx context.Context, addr string) (unlock func(), err error) {
	rt.Lock()
	l := rt.dialLocks[addr]
	if l == nil {
		l = &dialLock{held: make(chan struct{}, 1)}
		rt.dialLocks[addr] = l
	}
	l.holders++
	rt.Unlock()

	select {
	case l.held <- struct{}{}:
		return func() {
			<-l.held
			rt.forgetDialLock(addr, l)
		}, nil
	case <-ctx.Done():
		rt.forgetDialLock(addr, l)
		return nil, ctx.Err()
	}
}

// forgetDialLock lets go of l, and forgets it once nothing holds it or waits
// for it.
func (rt *roundTripper) forgetDialLock(addr string, l *dialLock) {
	rt.Lock()
	defer rt.Unlock()

	if l.holders--; l.holders == 0 {
		delete(rt.dialLocks, addr)
	}
}

func (rt *roundTripper) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network == "tcp" && rt.disableIPV6 {
		network = "tcp4"
	}
	return rt.dialer.DialContext(ctx, network, addr)
}

func (rt *roundTripper) buildHttp1Transport() *http.Transport {
	utlsConfig := &tls.Config{ClientSessionCache: rt.clientSessionCache, InsecureSkipVerify: rt.insecureSkipVerify, OmitEmptyPsk: true,
		DynamicRecordSizingDisabled: rt.dynamicRecordSizingDisabled, FalseStart: rt.falseStart}
	if rt.transportOptions != nil {
		utlsConfig.RootCAs = rt.transportOptions.RootCAs
		utlsConfig.Certificates = rt.transportOptions.Certificates
	}

	if rt.serverNameOverwrite != "" {
		utlsConfig.ServerName = rt.serverNameOverwrite
	}

	idleConnectionTimeout := defaultIdleConnectionTimeout

	if rt.transportOptions != nil && rt.transportOptions.IdleConnTimeout != nil {
		idleConnectionTimeout = *rt.transportOptions.IdleConnTimeout
	}

	t := &http.Transport{DialContext: rt.dial, DialTLSContext: rt.dialTLS, TLSClientConfig: utlsConfig, ConnectionFlow: rt.connectionFlow, IdleConnTimeout: idleConnectionTimeout,
		MaxMergedHeadAndBody: rt.maxMergedHeadAndBody}

	if rt.transportOptions != nil {
		t.DisableKeepAlives = rt.transportOptions.DisableKeepAlives
		t.DisableCompression = rt.transportOptions.DisableCompression
		t.MaxIdleConns = rt.transportOptions.MaxIdleConns
		t.MaxIdleConnsPerHost = rt.transportOptions.MaxIdleConnsPerHost
		t.MaxConnsPerHost = rt.transportOptions.MaxConnsPerHost
		// Only set MaxResponseHeaderBytes if > 0 (HTTP/1.1 transport doesn't understand -1)
		if rt.transportOptions.MaxResponseHeaderBytes > 0 {
			t.MaxResponseHeaderBytes = rt.transportOptions.MaxResponseHeaderBytes
		}
		t.WriteBufferSize = rt.transportOptions.WriteBufferSize
		t.ReadBufferSize = rt.transportOptions.ReadBufferSize
	}

	return t
}

// dialTLSHTTP2 is the HTTP/2 transport's dial, with the context of the
// request the connection is dialed for, which ends it.
func (rt *roundTripper) dialTLSHTTP2(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	return rt.dialTLS(ctx, network, addr)
}

// dialTLSForWebsocket establishes a TLS connection for WebSocket use.
// Unlike dialTLS, this method doesn't cache connections or create transports -
// it simply performs the TLS handshake with the same fingerprinting configuration.
func (rt *roundTripper) dialTLSForWebsocket(ctx context.Context, network, addr string) (net.Conn, error) {
	if network == "tcp" && rt.disableIPV6 {
		network = "tcp4"
	}

	if network == "tcp" && rt.disableIPV4 {
		network = "tcp6"
	}

	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	if rt.serverNameOverwrite != "" {
		host = rt.serverNameOverwrite
	}

	tlsConfig := &tls.Config{
		ClientSessionCache:          rt.clientSessionCache,
		ServerName:                  host,
		InsecureSkipVerify:          rt.insecureSkipVerify,
		OmitEmptyPsk:                true,
		DynamicRecordSizingDisabled: rt.dynamicRecordSizingDisabled,
		FalseStart:                  rt.falseStart,
	}
	if rt.transportOptions != nil {
		tlsConfig.RootCAs = rt.transportOptions.RootCAs
		tlsConfig.KeyLogWriter = rt.transportOptions.KeyLogWriter
		tlsConfig.Certificates = rt.transportOptions.Certificates
	}

	rawConn = rt.bandwidthTracker.TrackConnection(ctx, rawConn)

	// Force HTTP/1.1 for WebSocket connections (WebSocket doesn't work over HTTP/2)
	conn := tls.UClient(rawConn, tlsConfig, rt.clientHelloId, rt.withRandomTlsExtensionOrder, true, true)
	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}

	err = rt.certificatePinner.Pin(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func (rt *roundTripper) getDialTLSAddr(req *http.Request) string {
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(host, "443")
}

func newRoundTripper(clientProfile profiles.ClientProfile, transportOptions *TransportOptions, serverNameOverwrite string, insecureSkipVerify, withRandomTlsExtensionOrder, forceHttp1, disableHttp3, disableSessionTickets, enableH3Racing bool, certificatePins map[string][]string, badPinHandlerFunc BadPinHandlerFunc, disableIPV6, disableIPV4 bool, bandwidthTracker bandwidth.BandwidthTracker, proxyURL string, dialer ...proxy.ContextDialer) (http.RoundTripper, error) {
	pinner, err := NewCertificatePinner(certificatePins)
	if err != nil {
		return nil, fmt.Errorf("can not instantiate certificate pinner: %w", err)
	}

	var clientSessionCache tls.ClientSessionCache

	withSessionResumption := !disableSessionTickets && supportsSessionResumption(clientProfile.GetClientHelloId())

	if withSessionResumption {
		clientSessionCache = tls.NewLRUClientSessionCache(32)
	}

	rt := &roundTripper{
		dialer:                      dialer[0],
		certificatePinner:           pinner,
		badPinHandlerFunc:           badPinHandlerFunc,
		transportOptions:            transportOptions,
		clientSessionCache:          clientSessionCache,
		serverNameOverwrite:         serverNameOverwrite,
		settings:                    clientProfile.GetSettings(),
		settingsOrder:               clientProfile.GetSettingsOrder(),
		priorities:                  clientProfile.GetPriorities(),
		headerPriority:              clientProfile.GetHeaderPriority(),
		headerRepresentation:        clientProfile.GetHeaderRepresentation(),
		maxEncoderTableSize:         clientProfile.GetMaxEncoderHeaderTableSize(),
		windowUpdateDelay:           clientProfile.GetWindowUpdateDelay(),
		maxHeaderFramePayload:       clientProfile.GetMaxHeaderFramePayload(),
		maxDataFramePayload:         clientProfile.GetMaxDataFramePayload(),
		dynamicRecordSizingDisabled: clientProfile.GetDynamicRecordSizingDisabled(),
		falseStart:                  clientProfile.GetFalseStart(),
		maxMergedHeadAndBody:        clientProfile.GetMaxMergedHeadAndBody(),
		strictMaxConcurrentStreams:  clientProfile.GetStrictMaxConcurrentStreams(),
		pseudoHeaderOrder:           clientProfile.GetPseudoHeaderOrder(),
		insecureSkipVerify:          insecureSkipVerify,
		forceHttp1:                  forceHttp1,
		disableHttp3:                disableHttp3,
		withRandomTlsExtensionOrder: withRandomTlsExtensionOrder,
		connectionFlow:              clientProfile.GetConnectionFlow(),
		clientHelloId:               clientProfile.GetClientHelloId(),
		cachedTransports:            make(map[string]http.RoundTripper),
		cachedConnections:           make(map[string]net.Conn),
		setups:                      make(map[string]*setup),
		dialLocks:                   make(map[string]*dialLock),
		cachedKinds:                 make(map[string]transportKind),
		disableIPV6:                 disableIPV6,
		disableIPV4:                 disableIPV4,
		bandwidthTracker:            bandwidthTracker,
		initialStreamID:             clientProfile.GetStreamID(),
		allowHTTP:                   clientProfile.GetAllowHTTP(),
		http3Settings:               clientProfile.GetHttp3Settings(),
		http3SettingsOrder:          clientProfile.GetHttp3SettingsOrder(),
		http3PriorityParam:          clientProfile.GetHttp3PriorityParam(),
		http3PseudoHeaderOrder:      clientProfile.GetHttp3PseudoHeaderOrder(),
		http3SendGreaseFrames:       clientProfile.GetHttp3SendGreaseFrames(),
		proxyURL:                    proxyURL,
	}

	// Create protocol racer if HTTP/3 racing is enabled
	if enableH3Racing {
		rt.racer = newProtocolRacer(
			clientSessionCache,
			insecureSkipVerify,
			serverNameOverwrite,
			transportOptions,
			clientProfile.GetSettings(),
			rt.cachedTransports,
			&rt.cachedTransportsLck,
			rt.dropCachedTransport,
			pinner,
			badPinHandlerFunc,
			bandwidthTracker,
			clientProfile.GetHttp3Settings(),
			clientProfile.GetHttp3SettingsOrder(),
			clientProfile.GetHttp3PriorityParam(),
			clientProfile.GetHttp3PseudoHeaderOrder(),
			clientProfile.GetHttp3SendGreaseFrames(),
			proxyURL,
		)
	}

	if len(dialer) > 0 {
		rt.dialer = dialer[0]
	} else {
		rt.dialer = proxy.Direct
	}

	return rt, nil
}

func supportsSessionResumption(id tls.ClientHelloID) bool {
	spec, err := id.ToSpec()
	if err != nil {
		spec, err = tls.UTLSIdToSpec(id)
		if err != nil {
			return false
		}
	}

	for _, ext := range spec.Extensions {
		if _, ok := ext.(*tls.UtlsPreSharedKeyExtension); ok {
			return true
		}
	}

	return false
}
