package tls_client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	tls "github.com/igor-lemon/utls"
)

// QUICEndpoint is where QUIC goes to an origin whose DNS HTTPS record names
// h3: the name's addresses, the first of which is dialed (as Chromium's
// QuicSessionPool dials the first of its endpoint's), and the ECH configs of
// that record.
type QUICEndpoint struct {
	Addrs []netip.Addr
	ECH   []byte
}

// HTTP3FromDNS is how a client with no proxy goes over HTTP/3 to an https
// origin whose DNS HTTPS record names h3, where its profile says so
// (dns.https_h3), as Chromium's DNS_ALPN_H3 job does
// (HttpStreamFactory::JobController): a QUIC connection, and the request's TCP
// one held back behind it as the profile says (quic.tcp_wait_*); the first of
// them up takes the request, and the other is let finish apart. A QUIC
// connection up takes every request after it; one that failed where TCP did
// not has QUIC to the origin not tried again for a while (quic.broken_*).
type HTTP3FromDNS struct {
	// Endpoint resolves addr (host:port) as a request's TCP connection to it
	// would, within ctx: the context a request goes on with, carrying what was
	// resolved for its dial; and, when the HTTPS record the connection takes
	// names h3, where QUIC goes (true). A name that does not resolve says
	// false, and its TCP dial says why.
	Endpoint func(ctx context.Context, addr string) (context.Context, QUICEndpoint, bool)
	// State is the session's, shared by its clients; Key is what it keeps
	// this client's servers under (its top-level site), asked of each
	// request.
	State *QUICState
	Key   func() string
	// Tap, when set, is told of the datagrams of every QUIC connection made:
	// it is asked, with the context of the request the connection is made
	// for, once the connection's socket is there, and what it gives (nil:
	// nothing) is told of each datagram the socket writes and reads, and of
	// its end.
	Tap func(ctx context.Context, local, remote net.Addr) QUICPacketTap
}

// WithHTTP3FromDNS has a client go over HTTP/3 to an origin whose HTTPS
// record names h3, as HTTP3FromDNS says, where its profile asks for it
// (dns.https_h3) and it has no proxy.
func WithHTTP3FromDNS(h HTTP3FromDNS) HttpClientOption {
	return func(config *httpClientConfig) {
		config.http3FromDNS = &h
	}
}

// dnsH3 is a round tripper's HTTP3FromDNS and the HTTP/3 transport it goes
// over, made once; attempts are the QUIC connections being made, by address,
// which a request to one joins; altOf, where the QUIC connection made last
// for an address went, when an alternative service led to it.
type dnsH3 struct {
	HTTP3FromDNS
	once     sync.Once
	t3       *http3.Transport
	err      error
	mu       sync.Mutex
	attempts map[string]*quicAttempt
	altOf    map[string]string
}

// quicJob is where a request's QUIC connection goes, as one of Chromium's
// QUIC jobs: to its endpoint, on port (0: the request's own), an alternative
// service's dest (host:port) or, empty, the origin the HTTPS record of its
// name led to; server is the service that breaks or works as one, origin the
// server its RTT is kept for and TCP waits by.
type quicJob struct {
	dest     string
	server   quicServer
	origin   quicServer
	endpoint QUICEndpoint
	port     uint16
}

// quicAttempt is a QUIC connection being made: underWay is closed once its
// first packet has gone, when a request's TCP connection begins to wait.
type quicAttempt struct {
	quicJob
	underWay chan struct{}
	began    sync.Once
}

type quicAttemptKey struct{}

// errNoQUICEndpoint is a QUIC dial that was given no endpoint.
var errNoQUICEndpoint = errors.New("tls-client: QUIC dialed without the endpoint an HTTPS record gave")

func newDNSH3(h *HTTP3FromDNS) *dnsH3 {
	if h == nil {
		return nil
	}
	return &dnsH3{HTTP3FromDNS: *h, attempts: map[string]*quicAttempt{}, altOf: map[string]string{}}
}

// uses says whether req goes as d says: https, on a client that may speak
// HTTP/3 and has no proxy, whose profile asks for it.
func (d *dnsH3) uses(rt *roundTripper, req *http.Request) bool {
	return d != nil && strings.EqualFold(req.URL.Scheme, "https") && !rt.forceHttp1 && !rt.disableHttp3 &&
		rt.proxyURL == "" && rt.behavior.Flag("dns.https_h3")
}

// transport is the HTTP/3 transport d's connections are made by, as the
// profile says, dialing where an attempt says.
func (d *dnsH3) transport(rt *roundTripper) (*http3.Transport, error) {
	d.once.Do(func() {
		built, err := buildDNSH3Transport(&http3Config{
			chromeBehavior:         rt.chromeBehavior,
			behavior:               rt.behavior.Clone(),
			clientHelloID:          rt.clientHelloId,
			clientSessionCache:     rt.quicSessionCache,
			insecureSkipVerify:     rt.insecureSkipVerify,
			serverNameOverwrite:    rt.serverNameOverwrite,
			transportOptions:       rt.transportOptions,
			http3Settings:          rt.getHttp3Settings(),
			http3SettingsOrder:     rt.http3SettingsOrder,
			http3PriorityParam:     rt.http3PriorityParam,
			http3PseudoHeaderOrder: rt.http3PseudoHeaderOrder,
			http3SendGreaseFrames:  rt.http3SendGreaseFrames,
		})
		if err != nil {
			d.err = err
			return
		}
		t3 := built.(*http3.Transport)
		t3.Dial = d.dial(rt)
		d.mu.Lock()
		d.t3 = t3
		d.mu.Unlock()
	})
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.t3, d.err
}

// closeIdle closes the QUIC connections no request is on.
func (d *dnsH3) closeIdle() {
	if d == nil {
		return
	}
	d.mu.Lock()
	t3 := d.t3
	d.mu.Unlock()
	if t3 != nil {
		t3.CloseIdleConnections()
	}
}

// dial is the HTTP/3 transport's: to the first address of the attempt its
// context carries, offering the ECH of its record, telling the attempt it is
// under way once its first packet went; and it keeps watch on what it made.
func (d *dnsH3) dial(rt *roundTripper) func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		a, _ := ctx.Value(quicAttemptKey{}).(*quicAttempt)
		if a == nil || len(a.endpoint.Addrs) == 0 {
			return nil, errNoQUICEndpoint
		}
		port := uint64(a.port)
		if port == 0 {
			_, portText, _ := net.SplitHostPort(addr)
			p, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				return nil, err
			}
			port = p
		}
		remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.endpoint.Addrs[0].Unmap(), uint16(port)))
		// A refusal fails the connection whatever its certificate says, and
		// the request goes over TCP: QUIC offers ECH once.
		if len(a.endpoint.ECH) > 0 {
			tlsCfg.EncryptedClientHelloConfigList = a.endpoint.ECH
		}
		conn, err := dialQUIC(withQUICTap(ctx, d.Tap), remote, tlsCfg, cfg, func() { a.began.Do(func() { close(a.underWay) }) })
		if err != nil {
			return nil, err
		}
		go d.watch(rt, conn, a.server, a.origin)
		return conn, nil
	}
}

// watched is what watch reads of a QUIC connection.
type watched interface {
	Context() context.Context
	HandshakeComplete() <-chan struct{}
	ConnectionStats() quic.ConnectionStats
}

// watch keeps, once conn goes away, its smoothed RTT for origin where its
// handshake was done, unless QUIC to s, the service it went to, is broken
// then (QuicSessionPool's ServerNetworkStats of a session that goes away,
// kept for its server).
func (d *dnsH3) watch(rt *roundTripper, conn watched, s, origin quicServer) {
	<-conn.Context().Done()
	if d.State.isBroken(s) {
		return
	}
	select {
	case <-conn.HandshakeComplete():
		d.State.setRTT(origin, conn.ConnectionStats().SmoothedRTT, rt.behavior)
	default:
	}
}

// dialQUIC and buildDNSH3Transport are the tests' seams.
var (
	dialQUIC            = dialQUICAt
	buildDNSH3Transport = buildHTTP3Transport
)

// attempt is the QUIC connection to addr being made, joined when one is, else
// a new one as job says, with whether it is new.
func (d *dnsH3) attempt(addr string, job quicJob) (*quicAttempt, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a := d.attempts[addr]; a != nil {
		return a, false
	}
	a := &quicAttempt{quicJob: job, underWay: make(chan struct{})}
	d.attempts[addr] = a
	if job.dest == "" {
		delete(d.altOf, addr)
	} else {
		d.altOf[addr] = job.dest
	}
	return a, true
}

// preconnect makes a's QUIC connection, apart from any request: it goes on
// whatever becomes of the request it was made for, ended by QUIC's own
// handshake timeouts, and is the session's from then on.
func (d *dnsH3) preconnect(t3 *http3.Transport, ctx context.Context, addr string, a *quicAttempt) error {
	err := t3.Preconnect(context.WithValue(context.WithoutCancel(ctx), quicAttemptKey{}, a), addr)
	d.mu.Lock()
	if d.attempts[addr] == a {
		delete(d.attempts, addr)
	}
	d.mu.Unlock()
	if err == nil {
		d.State.workedFor(a.server)
	}
	return err
}

// roundTrip sends req to addr (send), and keeps what its answer says of
// addr's alternative services (learn).
func (d *dnsH3) roundTrip(rt *roundTripper, req *http.Request, addr string) (*http.Response, error) {
	res, err := d.send(rt, req, addr)
	if err == nil {
		d.learn(rt, addr, res)
	}
	return res, err
}

// learn keeps what an answer of addr says of its alternative services, where
// the profile follows them (quic.alt_svc), as Chromium's
// HttpNetworkTransaction::ProcessAltSvcHeader: the Alt-Svc fields, joined as
// one value, replace what was kept when quiche reads them whole; a value it
// cannot read changes nothing, nor does an answer of 421.
func (d *dnsH3) learn(rt *roundTripper, addr string, res *http.Response) {
	values := res.Header.Values("Alt-Svc")
	if res.StatusCode == http.StatusMisdirectedRequest || !rt.behavior.Flag("quic.alt_svc") {
		return
	}
	if entries, ok := parseAltSvc(strings.Join(values, ", ")); ok {
		d.State.learnAltSvc(quicServer{d.Key(), addr}, entries, rt.behavior)
	}
}

// taking says where the QUIC connection made last for addr went, the server
// it breaks or works as, and whether it takes a request: one an HTTPS record
// led to does; one an alternative service led to while addr advertises one
// to go to there still (alts), as Chromium asks for a session to an
// alternative service it would go to (GetAdvertisedAltSvcInternal).
func (d *dnsH3) taking(addr string, alts []string) (quicServer, bool) {
	d.mu.Lock()
	dest, byAlt := d.altOf[addr]
	d.mu.Unlock()
	if !byAlt {
		return quicServer{d.Key(), addr}, true
	}
	return quicServer{d.Key(), dest}, slices.Contains(alts, dest)
}

// send sends req to addr as Chromium's JobController would with an
// alternative job or a DNS ALPN job: on the QUIC connection up for addr that
// takes it; else to the first alternative service addr advertises
// (altRoundTrip); else over TCP when QUIC to addr is broken; at once over a
// TCP connection addr has, a QUIC connection made apart where its record
// names h3 (the main job is not held back then,
// quic.tcp_waits_with_connection); else the two raced, TCP at once beside
// QUIC where the connection addr had went as the connections that wait were
// cleaned up.
func (d *dnsH3) send(rt *roundTripper, req *http.Request, addr string) (*http.Response, error) {
	t3, err := d.transport(rt)
	if err != nil {
		return nil, err
	}
	alts := d.alternatives(rt, addr)
	if made, takes := d.taking(addr, alts); takes && t3.HasConn(addr) {
		res, took, err := d.onQUIC(rt, t3, req, addr, made)
		if took {
			return res, err
		}
		again, ok := resent(req)
		if !ok {
			return nil, err
		}
		req = again
	}
	// Whether addr has a TCP connection is asked before the connections that
	// wait are cleaned up, as Chromium asks it of its main job's socket group
	// (TargettedSocketGroupHasActiveSocket) before that job's socket request
	// cleans up: one there, even one that goes then, holds no main job back.
	free := !rt.behavior.Flag("quic.tcp_waits_with_connection") && rt.hasTCPConn(addr)
	rt.reapUnused("")
	if len(alts) > 0 {
		return d.altRoundTrip(rt, t3, req, addr, alts[0])
	}
	s := quicServer{d.Key(), addr}
	if d.State.isBroken(s) {
		return rt.tcpRoundTrip(req, addr)
	}
	if free && rt.hasTCPConn(addr) {
		quicDone := make(chan error, 1)
		go func() {
			ctx, ep, h3 := d.Endpoint(context.WithoutCancel(req.Context()), addr)
			if !h3 {
				close(quicDone)
				return
			}
			a, _ := d.attempt(addr, quicJob{server: s, origin: s, endpoint: ep})
			quicDone <- d.preconnect(t3, ctx, addr, a)
		}()
		res, err := rt.tcpRoundTrip(req, addr)
		go d.settled(s, quicDone, err == nil, rt)
		return res, err
	}
	ctx, ep, h3 := d.Endpoint(req.Context(), addr)
	req = req.WithContext(ctx)
	if !h3 {
		return rt.tcpRoundTrip(req, addr)
	}
	return d.race(rt, t3, req, addr, quicJob{server: s, origin: s, endpoint: ep}, free)
}

// altRoundTrip sends req to addr as Chromium's JobController would with an
// alternative job to dest: a QUIC connection to dest's first address and
// port, named as addr's host is, and the request's TCP connection held back
// behind it whatever connection addr has (the main job is blocked), as long
// as the session's state says of addr; but at once over an HTTP/2 connection
// addr has (quic.alt_svc_tcp_waits_with_h2), the QUIC connection made
// apart. The first up takes the request, the other made apart; a dest whose
// name does not resolve leaves the request to TCP.
func (d *dnsH3) altRoundTrip(rt *roundTripper, t3 *http3.Transport, req *http.Request, addr, dest string) (*http.Response, error) {
	_, ep, _ := d.Endpoint(req.Context(), dest)
	if len(ep.Addrs) == 0 {
		return rt.tcpRoundTrip(req, addr)
	}
	_, portText, _ := net.SplitHostPort(dest)
	port, _ := strconv.ParseUint(portText, 10, 16)
	job := quicJob{dest: dest, server: quicServer{d.Key(), dest}, origin: quicServer{d.Key(), addr}, endpoint: ep, port: uint16(port)}
	if !rt.behavior.Flag("quic.alt_svc_tcp_waits_with_h2") && rt.hasHTTP2Conn(addr) {
		quicDone := make(chan error, 1)
		go func() {
			a, _ := d.attempt(addr, job)
			quicDone <- d.preconnect(t3, req.Context(), addr, a)
		}()
		res, err := rt.tcpRoundTrip(req, addr)
		go d.settled(job.server, quicDone, err == nil, rt)
		return res, err
	}
	return d.race(rt, t3, req, addr, job, false)
}

// settled marks s broken when its QUIC connection failed where TCP did not
// (MaybeReportBrokenAlternativeService), once QUIC is done; a channel closed
// with nothing was no QUIC at all.
func (d *dnsH3) settled(s quicServer, quicDone chan error, tcpWorked bool, rt *roundTripper) {
	if err, tried := <-quicDone; tried && err != nil && tcpWorked {
		d.State.markBroken(s, rt.behavior)
	}
}

// race makes req's QUIC connection as job says and, as long after it is under
// way as the session's state says of job's origin (at once when free, a main
// job not held back), its TCP one, or takes a TCP connection addr has then;
// the first up takes the request. TCP goes at once when QUIC fails, and a
// request both fail says TCP's error, as Chromium reports its main job's.
func (d *dnsH3) race(rt *roundTripper, t3 *http3.Transport, req *http.Request, addr string, job quicJob, free bool) (*http.Response, error) {
	s := job.server
	a, made := d.attempt(addr, job)
	quicDone := make(chan error, 1)
	if made {
		go func() { quicDone <- d.preconnect(t3, req.Context(), addr, a) }()
	} else {
		// One being made is joined: its result is the request's too.
		go func() {
			quicDone <- t3.Preconnect(context.WithValue(context.WithoutCancel(req.Context()), quicAttemptKey{}, a), addr)
		}()
	}
	tcpDone := make(chan error, 1)
	tcpStarted := false
	startTCP := func() {
		if !tcpStarted {
			tcpStarted = true
			// A connection addr has takes the request at once, as a main job
			// takes an idle socket or a session its pool has.
			if rt.hasTCPConn(addr) {
				tcpDone <- nil
				return
			}
			go func() {
				// Its connection is made whoever takes the request, as a
				// connect job goes on for the pool once its request went
				// elsewhere; within the request's deadline.
				ctx, cancel := apart(req.Context())
				defer cancel()
				tcpDone <- rt.connectTCP(req.WithContext(ctx), addr)
			}()
		}
	}
	var tcpWait <-chan time.Time
	underWay := a.underWay
	var quicErr, tcpErr error
	quicOpen, tcpOpen := true, true
	if free {
		startTCP()
	}
	for {
		select {
		case <-underWay:
			underWay = nil
			if wait := d.State.tcpWait(job.origin, rt.behavior); wait > 0 {
				timer := time.NewTimer(wait)
				defer timer.Stop()
				tcpWait = timer.C
			} else {
				startTCP()
			}
		case <-tcpWait:
			startTCP()
		case err := <-quicDone:
			quicOpen = false
			if err == nil {
				if tcpStarted && tcpOpen {
					// TCP's connection, made, waits unused.
					go func() {
						if <-tcpDone == nil {
							rt.leftUnused(addr)
						}
					}()
				}
				res, took, err := d.onQUIC(rt, t3, req, addr, s)
				if took {
					return res, err
				}
				// The connection went before the request did, or refused it
				// unprocessed: TCP's takes it.
				again, ok := resent(req)
				if !ok {
					return nil, err
				}
				return rt.tcpRoundTrip(again, addr)
			}
			quicErr = err
			if tcpStarted && !tcpOpen {
				return nil, tcpErr
			}
			startTCP()
			underWay = nil
		case err := <-tcpDone:
			tcpOpen = false
			if err == nil {
				res, err := rt.tcpRoundTrip(req, addr)
				if quicOpen {
					go d.settled(s, quicDone, err == nil, rt)
				} else if quicErr != nil && err == nil {
					d.State.markBroken(s, rt.behavior)
				}
				return res, err
			}
			tcpErr = err
			if !quicOpen {
				return nil, tcpErr
			}
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
}

// onQUIC sends req on addr's QUIC connection, and says false when that
// connection could not take it (it went before the request did, or refused
// it unprocessed), the request's body closed then as after any failure. A
// request it failed before its answer, for whatever reason but its own
// context's, goes again over TCP, its body again, where the profile says
// (quic.retry_over_tcp): Chromium's QuicHttpStream says ERR_QUIC_PROTOCOL_ERROR
// of any request it sent that failed (ComputeResponseStatus), which
// HttpNetworkTransaction restarts with alternative services off
// (retry_without_alt_svc_on_quic_errors). QUIC to s is broken once TCP has
// answered (MarkAlternativeServiceBroken, once Chromium has read the body).
// The connections that wait unused are cleaned up first, as the restarted
// transaction's socket request cleans its pool up.
func (d *dnsH3) onQUIC(rt *roundTripper, t3 *http3.Transport, req *http.Request, addr string, s quicServer) (*http.Response, bool, error) {
	res, err := t3.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})
	if errors.Is(err, http3.ErrNoCachedConn) {
		return nil, false, err
	}
	if err == nil || !rt.behavior.Flag("quic.retry_over_tcp") || req.Context().Err() != nil {
		return res, true, err
	}
	again, ok := resent(req)
	if !ok {
		return nil, true, err
	}
	rt.reapUnused("")
	res, err = rt.tcpRoundTrip(again, addr)
	if err == nil {
		d.State.markBroken(s, rt.behavior)
	}
	return res, true, err
}

// resent is req to send again, with its body again when it has one, and
// false when that body cannot be had again.
func resent(req *http.Request) (*http.Request, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	again := req.Clone(req.Context())
	again.Body = body
	return again, true
}

// apart is ctx without its cancellation and with its deadline: what a
// request starts that goes on after it.
func apart(ctx context.Context) (context.Context, context.CancelFunc) {
	detached := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(detached, deadline)
	}
	return context.WithCancel(detached)
}

// hasTCPConn says whether addr has a TCP connection, made or being made, as
// Chromium asks whether a request's socket group has a socket
// (TargettedSocketGroupHasActiveSocket): one waiting to be taken up, a setup
// going on, or one its transport holds.
func (rt *roundTripper) hasTCPConn(addr string) bool {
	rt.Lock()
	stashed := rt.cachedConnections[addr] != nil
	rt.Unlock()
	rt.cachedTransportsLck.Lock()
	_, settingUp := rt.setups[addr]
	transport := rt.cachedTransports[addr]
	rt.cachedTransportsLck.Unlock()
	switch t := transport.(type) {
	case *http2.Transport:
		return stashed || settingUp || t.HasConn(addr)
	case *http.Transport:
		return stashed || settingUp || t.HasConn("https", addr)
	}
	return stashed || settingUp
}

// hasHTTP2Conn says whether addr has an HTTP/2 connection a request may go
// on, made or being made (Chromium's HasAvailableSpdySession).
func (rt *roundTripper) hasHTTP2Conn(addr string) bool {
	rt.cachedTransportsLck.Lock()
	t, ok := rt.cachedTransports[addr].(*http2.Transport)
	rt.cachedTransportsLck.Unlock()
	return ok && t.HasConn(addr)
}

// connectTCP makes the TCP connection a request to addr goes on and leaves it
// for addr's transport to take up when it sends, as Chromium's connect job
// makes a socket its pool keeps whichever request it goes to: the setup
// already going on for addr is waited for; with a transport cached for addr,
// a connection is made for it to take.
func (rt *roundTripper) connectTCP(req *http.Request, addr string) error {
	rt.cachedTransportsLck.Lock()
	_, cached := rt.cachedTransports[addr]
	s, waiting := rt.setups[addr]
	if !cached && !waiting {
		s = &setup{done: make(chan struct{})}
		rt.setups[addr] = s
	}
	rt.cachedTransportsLck.Unlock()
	switch {
	case waiting:
		// Done or not, it is the setup's: a request that waits for it waits
		// no longer than the setup's own request lets it go on.
		<-s.done
		return nil
	case !cached:
		return rt.setUp(req, addr, s)
	}
	conn, err := rt.discover(req, addr)
	if err != nil {
		return err
	}
	kind, known := rt.cachedKind(addr)
	if negotiated := kindForProtocol(conn.ConnectionState().NegotiatedProtocol); !known || kind != negotiated {
		// The transport speaks another protocol: the next setup takes this
		// connection, as dialTLS leaves one.
		rt.leaveChanged(addr, conn)
		rt.cachedTransportsLck.Lock()
		stale := rt.cachedTransports[addr]
		rt.cachedTransportsLck.Unlock()
		rt.dropCachedTransport(addr, stale)
		return nil
	}
	rt.stash(addr, conn)
	return nil
}

// stash leaves conn for addr's transport to take up, the one it replaces
// closed.
func (rt *roundTripper) stash(addr string, conn net.Conn) {
	rt.Lock()
	if previous := rt.cachedConnections[addr]; previous != nil {
		rt.letGo(previous)
	}
	rt.cachedConnections[addr] = conn
	rt.stashedAt[addr] = time.Now()
	delete(rt.unusedStash, addr)
	rt.Unlock()
	rt.stashed.Store(addr, true)
}

// peek reads what the server sends a connection that waits to be taken up,
// as Chromium reads each of its connections right after its handshake
// whether or not anything reads it yet (SSLClientSocketImpl::DoPeek): its
// session tickets are cached as they come, and the data after them is left
// for its transport, which also meets whatever error the reading met. The
// peek is done once its channel in peeks is closed.
func (rt *roundTripper) peek(conn net.Conn) {
	p, ok := conn.(interface{ Peek() error })
	if !ok {
		return
	}
	done := make(chan struct{})
	rt.peeks.Store(conn, done)
	go func() {
		_ = p.Peek()
		close(done)
	}()
}

// alive says whether conn, waiting to be taken up, was not closed by its
// server: while its peek reads, it was not, the peek having met nothing
// else; else as connected says, which would wait for a read going on.
func (rt *roundTripper) alive(conn net.Conn) bool {
	if done, ok := rt.peeks.Load(conn); ok {
		select {
		case <-done.(chan struct{}):
		default:
			return true
		}
	}
	return connected(conn)
}

// letGo closes conn, which waited to be taken up and no longer does.
func (rt *roundTripper) letGo(conn net.Conn) {
	_ = conn.Close()
	rt.peeks.Delete(conn)
}

// leftUnused has the connection waiting for addr's transport be one that
// waited unused when it is taken up (Transport.UnusedIdle): a request it loses
// before any of its answer goes again, as on a socket Chromium's pool kept.
// It is read as it waits (peek); one a setup left for its transport to take
// at once is not, as a peek finishing a false start would hold up what that
// transport asks of it (ConnectionState waits for the handshake).
func (rt *roundTripper) leftUnused(addr string) {
	rt.Lock()
	defer rt.Unlock()
	if conn := rt.cachedConnections[addr]; conn != nil {
		rt.unusedStash[addr] = true
		rt.peek(conn)
	}
}

// reapUnused closes the connections left waiting to be taken up, but the one
// for the address but, that waited longer than
// http.unused_idle_connection_timeout_ms or that their servers closed, as
// Chromium's socket pool, when a socket is asked of it, cleans up the idle
// sockets never used past their time and those no longer usable
// (CleanupIdleSockets, unused_idle_socket_timeout, IsUsable).
func (rt *roundTripper) reapUnused(but string) {
	limit := time.Duration(rt.behavior.Uint("http.unused_idle_connection_timeout_ms")) * time.Millisecond
	rt.Lock()
	defer rt.Unlock()
	for addr, conn := range rt.cachedConnections {
		if addr != but && (time.Since(rt.stashedAt[addr]) >= limit || !rt.alive(conn)) {
			rt.letGo(conn)
			delete(rt.cachedConnections, addr)
			delete(rt.stashedAt, addr)
			delete(rt.unusedStash, addr)
			rt.stashed.Delete(addr)
		}
	}
}

// tcpRoundTrip sends req to addr over TCP, again on a transport set up for
// what the server speaks now when it changed its protocol, a few times at
// most.
func (rt *roundTripper) tcpRoundTrip(req *http.Request, addr string) (*http.Response, error) {
	for changes := 0; ; changes++ {
		resp, err := rt.roundTrip(req, addr)
		if !errors.Is(err, errProtocolChanged) || changes == protocolChanges {
			return resp, err
		}
	}
}
