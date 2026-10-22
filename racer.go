package tls_client

import (
	"context"
	"errors"
	"github.com/igor-lemon/utls/behavior"
	"sync"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/tls-client/bandwidth"
	tls "github.com/igor-lemon/utls"
)

type protocolRacer struct {
	clientHelloID   tls.ClientHelloID
	chromeBehavior  bool
	behavior        behavior.Policy
	protocolCache   map[string]string
	protocolCacheMu sync.RWMutex

	clientSessionCache  tls.ClientSessionCache
	insecureSkipVerify  bool
	serverNameOverwrite string
	transportOptions    *TransportOptions
	settings            map[http2.SettingID]uint32
	cachedTransports    map[string]http.RoundTripper
	cachedTransportsLck *sync.Mutex
	certificatePinner   CertificatePinner
	badPinHandlerFunc   BadPinHandlerFunc
	bandwidthTracker    bandwidth.BandwidthTracker

	// dropTransport forgets the transport cached for an address so the next
	// attempt builds one from a fresh handshake. It is the round tripper's own
	// eviction, handed over because a raced request returns from RoundTrip
	// before the branch that would otherwise do it.
	dropTransport func(addr string, stale http.RoundTripper)

	// HTTP/3 specific settings
	http3Settings          map[uint64]uint64
	http3SettingsOrder     []uint64
	http3PriorityParam     uint32
	http3PseudoHeaderOrder []string
	http3SendGreaseFrames  bool

	proxyURL string
}

func newProtocolRacer(
	clientSessionCache tls.ClientSessionCache,
	insecureSkipVerify bool,
	serverNameOverwrite string,
	transportOptions *TransportOptions,
	settings map[http2.SettingID]uint32,
	cachedTransports map[string]http.RoundTripper,
	cachedTransportsLck *sync.Mutex,
	dropTransport func(addr string, stale http.RoundTripper),
	certificatePinner CertificatePinner,
	badPinHandlerFunc BadPinHandlerFunc,
	bandwidthTracker bandwidth.BandwidthTracker,
	http3Settings map[uint64]uint64,
	http3SettingsOrder []uint64,
	http3PriorityParam uint32,
	http3PseudoHeaderOrder []string,
	http3SendGreaseFrames bool,
	proxyURL string,
) *protocolRacer {
	return &protocolRacer{
		protocolCache:          make(map[string]string),
		clientSessionCache:     clientSessionCache,
		insecureSkipVerify:     insecureSkipVerify,
		serverNameOverwrite:    serverNameOverwrite,
		transportOptions:       transportOptions,
		settings:               settings,
		cachedTransports:       cachedTransports,
		cachedTransportsLck:    cachedTransportsLck,
		dropTransport:          dropTransport,
		certificatePinner:      certificatePinner,
		badPinHandlerFunc:      badPinHandlerFunc,
		bandwidthTracker:       bandwidthTracker,
		http3Settings:          http3Settings,
		http3SettingsOrder:     http3SettingsOrder,
		http3PriorityParam:     http3PriorityParam,
		http3PseudoHeaderOrder: http3PseudoHeaderOrder,
		http3SendGreaseFrames:  http3SendGreaseFrames,
		proxyURL:               proxyURL,
	}
}

// race races HTTP/3 and HTTP/2 connections and uses whichever responds first.
// Similar to Chrome's "Happy Eyeballs" approach.
func (pr *protocolRacer) race(req *http.Request, addr string, getTransportFunc func(*http.Request, string) error) (*http.Response, error) {
	// Try cached protocol first if available
	if resp, err, shouldRace := pr.tryUseCachedProtocol(req, addr, getTransportFunc); !shouldRace {
		return resp, err
	}

	// No cached protocol or it failed - start racing
	return pr.startRace(req, addr, getTransportFunc)
}

func (pr *protocolRacer) tryUseCachedProtocol(req *http.Request, addr string, getTransportFunc func(*http.Request, string) error) (*http.Response, error, bool) {
	pr.protocolCacheMu.RLock()
	protocol, found := pr.protocolCache[addr]
	pr.protocolCacheMu.RUnlock()
	if !found {
		return nil, nil, true
	}
	transport, err := pr.getOrCreateTransport(protocol, addr, req, getTransportFunc)
	if err != nil {
		pr.clearProtocolCache(addr)
		return nil, nil, true
	}
	// Once a request has been dispatched an arbitrary error is not permission
	// to replay it. The selected transport owns its bounded safe retry policy.
	resp, err := pr.roundTrip(transport, req, addr)
	if err != nil {
		pr.clearProtocolCache(addr)
	}
	return resp, err, false
}

func (pr *protocolRacer) getOrCreateTransport(protocol, addr string, req *http.Request, getTransportFunc func(*http.Request, string) error) (http.RoundTripper, error) {
	key := pr.getTransportKey(protocol, addr)
	pr.cachedTransportsLck.Lock()
	defer pr.cachedTransportsLck.Unlock()
	if tr := pr.cachedTransports[key]; tr != nil {
		return tr, nil
	}
	if protocol != "h3" {
		if err := getTransportFunc(req, addr); err != nil {
			return nil, err
		}
		return pr.cachedTransports[addr], nil
	}
	tr, err := buildHTTP3Transport(pr.getHTTP3Config())
	if err == nil {
		pr.cachedTransports[key] = tr
	}
	return tr, err
}

func (pr *protocolRacer) startRace(req *http.Request, addr string, getTransportFunc func(*http.Request, string) error) (*http.Response, error) {
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	results := make(chan racingResult, 2)
	go pr.prepareHTTP3(ctx, req, addr, getTransportFunc, results)
	go pr.prepareHTTP2(ctx, req, addr, getTransportFunc, results)
	var lastErr error
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case result := <-results:
			if result.err != nil {
				lastErr = result.err
				continue
			}
			if err := req.Context().Err(); err != nil {
				return nil, err
			}
			// Cancel only the unused connection job. The winning request and its
			// response body retain the original caller context.
			cancel()
			pr.cacheWinningProtocol(addr, result.protocol)
			return pr.roundTrip(result.transport, req, addr)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("http3 racing: both connection attempts failed")
	}
	return nil, lastErr
}
func (pr *protocolRacer) prepareHTTP3(ctx context.Context, req *http.Request, addr string, getTransportFunc func(*http.Request, string) error, results chan<- racingResult) {
	tr, err := pr.getOrCreateTransport("h3", addr, req, getTransportFunc)
	if err == nil {
		err = tr.(interface {
			Preconnect(context.Context, string) error
		}).Preconnect(ctx, addr)
	}
	results <- racingResult{protocol: "h3", transport: tr, err: err}
}
func (pr *protocolRacer) prepareHTTP2(ctx context.Context, req *http.Request, addr string, getTransportFunc func(*http.Request, string) error, results chan<- racingResult) {
	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		results <- racingResult{protocol: "h2", err: context.Cause(ctx)}
		return
	case <-timer.C:
	}
	tr, err := pr.getOrCreateTransport("h2", addr, req.WithContext(ctx), getTransportFunc)
	results <- racingResult{protocol: "h2", transport: tr, err: err}
}

// roundTrip sends the request over transport and, when the dial underneath
// reports that the server has moved to a protocol this transport cannot speak,
// forgets the transport so the next attempt builds one that fits.
//
// Clearing the protocol cache alone does not recover from that: the race it
// falls back to reaches for the same cached transport and fails on the same
// mismatch, for every request from then on.
//
// addr is the dial address rather than the transport's cache key, because only
// the transport stored under that key dials through the round tripper. The
// HTTP/3 transport brings its own dialer and never reports this.
func (pr *protocolRacer) roundTrip(transport http.RoundTripper, req *http.Request, addr string) (*http.Response, error) {
	resp, err := transport.RoundTrip(req)
	if err != nil && errors.Is(err, errProtocolChanged) && pr.dropTransport != nil {
		pr.dropTransport(addr, transport)
	}

	return resp, err
}

func (pr *protocolRacer) getTransportKey(protocol, addr string) string {
	if protocol == "h3" {
		return addr + ":h3"
	}
	return addr
}

func (pr *protocolRacer) clearProtocolCache(addr string) {
	pr.protocolCacheMu.Lock()
	delete(pr.protocolCache, addr)
	pr.protocolCacheMu.Unlock()
}

func (pr *protocolRacer) cacheWinningProtocol(addr, protocol string) {
	pr.protocolCacheMu.Lock()
	pr.protocolCache[addr] = protocol
	pr.protocolCacheMu.Unlock()

}

func (pr *protocolRacer) handleCachedProtocolError(err error, addr string, req *http.Request) {
	if errors.Is(err, ErrBadPinDetected) && pr.badPinHandlerFunc != nil {
		pr.badPinHandlerFunc(req)
	}
	pr.clearProtocolCache(addr)
}

func (pr *protocolRacer) getHTTP3Config() *http3Config {
	return &http3Config{
		clientHelloID:          pr.clientHelloID,
		chromeBehavior:         pr.chromeBehavior,
		behavior:               pr.behavior.Clone(),
		clientSessionCache:     pr.clientSessionCache,
		insecureSkipVerify:     pr.insecureSkipVerify,
		serverNameOverwrite:    pr.serverNameOverwrite,
		transportOptions:       pr.transportOptions,
		http3Settings:          pr.http3Settings,
		http3SettingsOrder:     pr.http3SettingsOrder,
		http3PriorityParam:     pr.http3PriorityParam,
		http3PseudoHeaderOrder: pr.http3PseudoHeaderOrder,
		http3SendGreaseFrames:  pr.http3SendGreaseFrames,
		proxyURL:               pr.proxyURL,
	}
}

type racingResult struct {
	protocol  string
	transport http.RoundTripper
	err       error
}
