package tls_client

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/tls-client/bandwidth"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
)

// peeked counts the peeks the round tripper keeps.
func peeked(rt *roundTripper) int {
	n := 0
	rt.peeks.Range(func(any, any) bool { n++; return true })
	return n
}

func TestAConnectionThatWaitsHasItsTicketCachedAsItComes(t *testing.T) {
	// QUIC up first, TCP's connection left and never taken up: its server's
	// ticket is cached all the same, so the next TCP connection resumes, as
	// Chrome's does.
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	policy := dnsH3Policy(t, nil)
	state := NewQUICState()
	c := h3Client(t, policy, &recordSays{h3: true}, state, resuming(policy))
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool { return stashed(rt, o.addr) }) {
		t.Fatal("no TCP connection left")
	}
	time.Sleep(100 * time.Millisecond)
	c.CloseIdleConnections()
	state.markBroken(quicServer{"https://a.test", o.addr}, policy)
	got, resumed := resumedOver(t, c, "https://"+o.addr+"/again")
	if got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if !resumed {
		t.Error("the new TCP connection resumed no session: the ticket of the one left was never read")
	}
}

func TestAnHTTP1ConnectionThatWaitsIsTakenUpWhileItIsRead(t *testing.T) {
	// An HTTP/1.1 server says nothing after its tickets: the peek of the
	// connection that lost to QUIC reads on, and the request that takes it
	// up, once QUIC's went, goes on it at once, its answer read through.
	h1 := new(atomic.Bool)
	h1.Store(true)
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, h1: h1})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool { return stashed(rt, o.addr) }) {
		t.Fatal("no TCP connection left")
	}
	_ = o.quicConn(t, 0).CloseWithError(0, "")
	time.Sleep(100 * time.Millisecond)
	answered := make(chan string, 1)
	go func() { answered <- came(t, c, "https://"+o.addr+"/again") }()
	select {
	case got := <-answered:
		if got != "HTTP/1.1" {
			t.Errorf("came over %q, want the TCP connection left", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request that took up the connection being read hangs")
	}
	if o.tcpConns.Load() != 1 {
		t.Errorf("%d TCP connections, want the one left", o.tcpConns.Load())
	}
	if n := peeked(rt); n != 0 {
		t.Errorf("%d peeks kept of connections taken up", n)
	}
}

// puttingSessions is a session cache that says the key of each session put
// in it.
type puttingSessions struct {
	tls.ClientSessionCache
	puts chan string
}

func (c *puttingSessions) Put(key string, cs *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, cs)
	if cs != nil {
		c.puts <- key
	}
}

func TestAConnectionLeftForTheNextSetupHasItsTicketCached(t *testing.T) {
	// A TLS 1.3 server that gives its tickets and says nothing more.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &stdtls.Config{Certificates: []stdtls.Certificate{coalescingCert(t, "a.test")}, NextProtos: []string{"h2"}}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				server := stdtls.Server(raw, cfg)
				_ = server.Handshake()
				_, _ = io.Copy(io.Discard, server)
			}()
		}
	}()
	raw, err := newRoundTripper(profiles.Chrome_133_PSK, nil, "", true, false, false, false, false, false,
		nil, nil, false, false, bandwidth.NewNopeTracker(), "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	rt := raw.(*roundTripper)
	sessions := &puttingSessions{ClientSessionCache: rt.clientSessionCache, puts: make(chan string, 8)}
	rt.clientSessionCache = sessions
	addr := ln.Addr().String()
	for _, leave := range []func(*tls.UConn){
		func(conn *tls.UConn) { rt.leaveChanged(addr, conn) },
		func(conn *tls.UConn) { rt.stash(addr, conn); rt.leftUnused(addr) },
	} {
		conn, err := rt.handshake(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		leave(conn)
		select {
		case <-sessions.puts:
		case <-time.After(5 * time.Second):
			t.Fatal("no ticket cached for the connection left")
		}
	}
	// Each left is let go of with the idle connections, and its peek with
	// it; the one it replaced before them.
	if n := peeked(rt); n != 2 {
		t.Errorf("%d peeks kept, want the two connections left", n)
	}
	rt.CloseIdleConnections()
	if n := peeked(rt); n != 0 {
		t.Errorf("%d peeks kept of connections let go of", n)
	}
}

func TestAConnectionThatWentAsItWasCleanedUpHoldsNoTCPBack(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout string // http.unused_idle_connection_timeout_ms
		closed  bool   // by its server
		none    bool   // closed with the idle ones before
	}{
		{name: "closed by its server", timeout: "60000", closed: true},
		{name: "past its time", timeout: "1"},
		{name: "none", timeout: "60000", none: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := dialQUIC
			// The dials made apart end (ended), the client waits for them,
			// and dialQUIC is put back, in that order.
			var dials sync.WaitGroup
			ended := make(chan struct{})
			t.Cleanup(func() {
				dials.Wait()
				dialQUIC = saved
			})
			h1 := new(atomic.Bool)
			h1.Store(true)
			o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, h1: h1})
			policy := dnsH3Policy(t, map[string]string{"http.unused_idle_connection_timeout_ms": tc.timeout})
			state := NewQUICState()
			c := h3Client(t, policy, &recordSays{h3: true}, state)
			t.Cleanup(func() { close(ended) })
			if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
				t.Fatalf("came over %q, want HTTP/3", got)
			}
			rt := c.(*httpClient).built
			if !waitFor(2*time.Second, func() bool { return stashed(rt, o.addr) }) {
				t.Fatal("no TCP connection left")
			}
			if tc.closed {
				o.tcp.CloseClientConnections()
				if !waitFor(time.Second, func() bool { return o.tcpClosed.Load() == 1 }) {
					t.Fatal("the server did not close it")
				}
			}
			// QUIC's connection goes, and its RTT is made a second's: a TCP
			// connection held back waits 1.5 s.
			_ = o.quicConn(t, 0).CloseWithError(0, "")
			s := quicServer{"https://a.test", o.addr}
			if !waitFor(time.Second, func() bool {
				state.mu.Lock()
				defer state.mu.Unlock()
				_, ok := state.rttsByKey[s]
				return ok
			}) {
				t.Fatal("no RTT kept")
			}
			state.setRTT(s, time.Second, policy)
			if tc.none {
				c.CloseIdleConnections()
			}
			// QUIC is under way and never up.
			dials.Add(1)
			dialQUIC = func(ctx context.Context, _ *net.UDPAddr, _ *tls.Config, _ *quic.Config, sent func()) (*quic.Conn, error) {
				defer dials.Done()
				sent()
				select {
				case <-ctx.Done():
				case <-ended:
				}
				return nil, errors.New("no QUIC")
			}
			began := time.Now()
			if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/1.1" {
				t.Fatalf("came over %q, want a new TCP connection's", got)
			}
			took := time.Since(began)
			switch {
			case tc.none && took < 1400*time.Millisecond:
				t.Errorf("with no connection there TCP went after %v, want the 1.5 s wait", took)
			case !tc.none && took > time.Second:
				t.Errorf("TCP went after %v, want at once beside QUIC", took)
			}
			if o.tcpConns.Load() != 2 {
				t.Errorf("%d TCP connections, want a new one", o.tcpConns.Load())
			}
		})
	}
}

func TestAConnectionThatWentAsItWasCleanedUpIsNotTakenAndTheFirstUpTakesTheRequest(t *testing.T) {
	// QUIC up first again: a TCP connection left that its server closed, or
	// that waited past its time, is cleaned up, and a new one made at once
	// beside QUIC's loses to it, as Chrome's main job does, which is not held
	// back: the request goes over HTTP/3.
	for _, tc := range []struct {
		name    string
		timeout string
		closed  bool
	}{
		{name: "closed by its server", timeout: "60000", closed: true},
		{name: "past its time", timeout: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h1 := new(atomic.Bool)
			h1.Store(true)
			o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, h1: h1})
			c := h3Client(t, dnsH3Policy(t, map[string]string{"http.unused_idle_connection_timeout_ms": tc.timeout}),
				&recordSays{h3: true}, NewQUICState())
			if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
				t.Fatalf("came over %q, want HTTP/3", got)
			}
			rt := c.(*httpClient).built
			if !waitFor(2*time.Second, func() bool { return stashed(rt, o.addr) }) {
				t.Fatal("no TCP connection left")
			}
			if tc.closed {
				o.tcp.CloseClientConnections()
				if !waitFor(time.Second, func() bool { return o.tcpClosed.Load() == 1 }) {
					t.Fatal("the server did not close it")
				}
			}
			_ = o.quicConn(t, 0).CloseWithError(0, "")
			time.Sleep(100 * time.Millisecond)
			if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/3.0" {
				t.Errorf("came over %q, want the QUIC connection up first", got)
			}
			if !waitFor(time.Second, func() bool { return o.tcpConns.Load() == 2 }) {
				t.Errorf("%d TCP connections, want a new one made beside QUIC's", o.tcpConns.Load())
			}
		})
	}
}

func TestARequestOnTheQUICConnectionCleansNothingUp(t *testing.T) {
	// A request on the QUIC connection up asks no socket of the pool: the
	// TCP connection left waits on, past its time.
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	c := h3Client(t, dnsH3Policy(t, map[string]string{"http.unused_idle_connection_timeout_ms": "1"}),
		&recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool { return stashed(rt, o.addr) }) {
		t.Fatal("no TCP connection left")
	}
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want the QUIC connection up", got)
	}
	if !stashed(rt, o.addr) || o.tcpClosed.Load() != 0 {
		t.Error("a request on the QUIC connection closed the TCP connection left")
	}
}

// countingReaper is a transport that counts the reaps asked of it.
type countingReaper struct{ reaps atomic.Int32 }

func (*countingReaper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no")
}

func (r *countingReaper) ReapIdleConns() { r.reaps.Add(1) }

func TestReapingPassesOverTheAddressWhoseRequestGoes(t *testing.T) {
	raw, err := newRoundTripper(profiles.Chrome_133.WithBehavior(dnsH3Policy(t, map[string]string{"http.unused_idle_connection_timeout_ms": "1"})),
		nil, "", true, false, false, false, false, false, nil, nil, false, false, bandwidth.NewNopeTracker(), "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	rt := raw.(*roundTripper)
	reapers := map[string]*countingReaper{"a.test:443": {}, "b.test:443": {}}
	rt.cachedTransportsLck.Lock()
	for addr, r := range reapers {
		rt.cachedTransports[addr] = r
	}
	rt.cachedTransportsLck.Unlock()
	for addr := range reapers {
		mine, _ := net.Pipe()
		rt.stash(addr, mine)
	}
	time.Sleep(5 * time.Millisecond)
	// The request to a goes: b's are reaped, a's are its own request's.
	rt.ReapIdleConnectionsBut("a.test:443")
	if reapers["a.test:443"].reaps.Load() != 0 || reapers["b.test:443"].reaps.Load() != 1 {
		t.Errorf("reaps of a and b: %d and %d, want 0 and 1", reapers["a.test:443"].reaps.Load(), reapers["b.test:443"].reaps.Load())
	}
	if !stashed(rt, "a.test:443") || stashed(rt, "b.test:443") {
		t.Error("the connections left: a's reaped or b's kept")
	}
	// Another's request reaps them all.
	c := &httpClient{built: rt}
	c.ReapIdleConnections()
	if reapers["a.test:443"].reaps.Load() != 1 || stashed(rt, "a.test:443") {
		t.Error("a's left after a reap of all")
	}
	c.ReapIdleConnectionsBut("b.test:443")
	if reapers["a.test:443"].reaps.Load() != 2 || reapers["b.test:443"].reaps.Load() != 2 {
		t.Errorf("reaps of a and b: %d and %d, want 2 and 2", reapers["a.test:443"].reaps.Load(), reapers["b.test:443"].reaps.Load())
	}
}

func TestTheConnectionsReplacedAsTheyWaitedAreForgotten(t *testing.T) {
	conn := func() *tls.UConn {
		mine, theirs := net.Pipe()
		t.Cleanup(func() { _ = theirs.Close() })
		return tls.UClient(mine, &tls.Config{}, tls.HelloChrome_Auto, false, false, false)
	}
	rt := &roundTripper{cachedConnections: map[string]net.Conn{}, stashedAt: map[string]time.Time{},
		changedConnections: map[string]*tls.UConn{}, unusedStash: map[string]bool{}}
	for range 2 {
		rt.stash("x:443", conn())
		rt.leftUnused("x:443")
	}
	rt.leaveChanged("y:443", conn())
	rt.leaveChanged("y:443", conn())
	if n := peeked(rt); n != 2 {
		t.Errorf("%d peeks kept, want the two connections left last", n)
	}
}

// tcpPair is a TCP connection and its server's end.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	mine, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	theirs := <-accepted
	t.Cleanup(func() { _ = mine.Close(); _ = theirs.Close() })
	return mine, theirs
}

func TestAConnectionThatWaitsIsLetGoOfOnceItsServerClosedIt(t *testing.T) {
	raw, err := newRoundTripper(profiles.Chrome_133.WithBehavior(dnsH3Policy(t, nil)),
		nil, "", true, false, false, false, false, false, nil, nil, false, false, bandwidth.NewNopeTracker(), "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	rt := raw.(*roundTripper)
	reaped, reapedServer := tcpPair(t)
	taken, takenServer := tcpPair(t)
	rt.stash("c.test:443", reaped)
	rt.stash("d.test:443", taken)
	// Not TLS, so not read as it waits: its socket is asked.
	rt.leftUnused("c.test:443")
	if n := peeked(rt); n != 0 {
		t.Fatalf("%d peeks kept of a connection that cannot be read so", n)
	}
	rt.reapUnused("")
	if !stashed(rt, "c.test:443") || !stashed(rt, "d.test:443") {
		t.Fatal("a connection in its time and open was reaped")
	}
	_ = reapedServer.Close()
	_ = takenServer.Close()
	if !waitFor(time.Second, func() bool { return !connected(reaped) && !connected(taken) }) {
		t.Fatal("the close did not come")
	}
	// Reaped as the connections that wait are cleaned up, and passed over
	// as one is taken up, as Chromium's pool asks IsUsable of an idle socket
	// in both.
	rt.reapUnused("d.test:443")
	if stashed(rt, "c.test:443") {
		t.Error("a connection its server closed is still left")
	}
	if conn := rt.takeStashed("d.test:443"); conn != nil {
		t.Error("a connection its server closed was taken up")
	}
}

func TestATCPConnectionThatWaitsHoldsTCPBackWhereTheProfileSaysTCPWaits(t *testing.T) {
	// quic.tcp_waits_with_connection: the request's TCP waits behind QUIC
	// whatever waits (1.5 s, the RTT made a second's), and QUIC, up first,
	// takes it.
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	policy := dnsH3Policy(t, map[string]string{"quic.tcp_waits_with_connection": "true"})
	state := NewQUICState()
	c := h3Client(t, policy, &recordSays{h3: true}, state)
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool { return stashed(rt, o.addr) }) {
		t.Fatal("no TCP connection left")
	}
	_ = o.quicConn(t, 0).CloseWithError(0, "")
	s := quicServer{"https://a.test", o.addr}
	if !waitFor(time.Second, func() bool {
		state.mu.Lock()
		defer state.mu.Unlock()
		_, ok := state.rttsByKey[s]
		return ok
	}) {
		t.Fatal("no RTT kept")
	}
	state.setRTT(s, time.Second, policy)
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/3.0" {
		t.Errorf("came over %q, want the race's QUIC", got)
	}
}

func TestARequestQUICFailedOnItsConnectionUpCleansUpTheConnectionsThatWait(t *testing.T) {
	// QUIC up first, TCP's connection left, kept unused no time: the next
	// request, failed on QUIC's connection, goes again over TCP on a new
	// connection, the one left cleaned up as the restart's socket request
	// cleans Chromium's pool up.
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, quicFails: resetting(0x200, 1)})
	c := h3Client(t, dnsH3Policy(t, map[string]string{"http.unused_idle_connection_timeout_ms": "0"}),
		&recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool { return stashed(rt, o.addr) }) {
		t.Fatal("no TCP connection left")
	}
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if o.tcpConns.Load() != 2 {
		t.Errorf("%d TCP connections, want the one left and a new one", o.tcpConns.Load())
	}
}
