package tls_client

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/httptrace"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
)

// h3Origin is an https origin on one loopback port, its TCP serving HTTP/2
// and HTTP/1.1 and its UDP HTTP/3, each request answered with the protocol
// it came over: with quicLag, every datagram of its QUIC server's comes that
// late, through a relay of the port's own; with tcpLag, its TCP server's
// first answer; silent, its UDP answers nothing.
type h3Origin struct {
	addr      string
	quicConns atomic.Int32 // QUIC connections the server took
	tcpConns  atomic.Int32 // TCP connections accepted
	firstTCP  atomic.Int64 // when the first was, Unix ns
	firstQUIC atomic.Int64
	// datagrams are what the port's UDP was sent, when the origin drops them
	// all (silent).
	datagrams atomic.Int32
	tcpClosed atomic.Int32
	tcpAsked  atomic.Int32 // requests its TCP answered
	tcp       *httptest.Server
	h3        *http3.Server
	mu        sync.Mutex
	raw       []net.Conn   // its TCP connections as they are under TLS
	quic      []*quic.Conn // and its QUIC ones
}

type originSays struct {
	quicLag, tcpLag time.Duration
	silent          bool
	// h1 has its TCP speak HTTP/1.1 alone, from the start, or once set.
	h1 *atomic.Bool
	// echKeys are its QUIC server's ECH keys: a request it opens the inner
	// hello of is answered with " ech" after the protocol.
	echKeys []tls.EncryptedClientHelloKey
	// noTickets has its TCP give no session tickets.
	noTickets bool
	// quicFails, when it says so, has its HTTP/3 fail the request it is
	// given instead of answering it.
	quicFails func(w http.ResponseWriter, r *http.Request, conn *quic.Conn) bool
}

func newH3Origin(t *testing.T, says originSays) *h3Origin {
	t.Helper()
	o := &h3Origin{}
	cert := coalescingCert(t, "a.test")
	// each request answered with the protocol it came over, and its body
	// after a space when it has one
	answer := func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		o.tcpAsked.Add(1)
		_, _ = io.WriteString(w, r.Proto)
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			_, _ = io.WriteString(w, " "+string(b))
		}
	}
	var udp net.PacketConn
	var tcp net.Listener
	for tries := 1; ; tries++ {
		var err error
		if udp, err = net.ListenPacket("udp4", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if tcp, err = net.Listen("tcp4", udp.LocalAddr().String()); err == nil {
			break
		}
		_ = udp.Close()
		if tries == 10 {
			t.Fatal(err)
		}
	}
	o.addr = tcp.Addr().String()
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(answer))
	server.Listener = lateListener{tcp, says.tcpLag, o}
	server.EnableHTTP2 = true
	server.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{cert}, SessionTicketsDisabled: says.noTickets}
	if says.h1 != nil {
		server.TLS.GetConfigForClient = func(*stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			if !says.h1.Load() {
				return nil, nil
			}
			return &stdtls.Config{Certificates: []stdtls.Certificate{cert}, NextProtos: []string{"http/1.1"},
				SessionTicketsDisabled: says.noTickets}, nil
		}
	}
	server.Config.ConnState = func(_ net.Conn, s stdhttp.ConnState) {
		switch s {
		case stdhttp.StateNew:
			o.firstTCP.CompareAndSwap(0, time.Now().UnixNano())
			o.tcpConns.Add(1)
		case stdhttp.StateClosed:
			o.tcpClosed.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	o.tcp = server
	switch {
	case says.silent:
		go func() {
			b := make([]byte, 65536)
			for {
				if _, _, err := udp.ReadFrom(b); err != nil {
					return
				}
				o.datagrams.Add(1)
			}
		}()
		t.Cleanup(func() { _ = udp.Close() })
		return o
	case says.quicLag > 0:
		inner, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go relayLate(udp, inner.LocalAddr().(*net.UDPAddr), says.quicLag)
		t.Cleanup(func() { _ = udp.Close() })
		udp = inner
	}
	h3 := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if says.quicFails != nil {
			o.mu.Lock()
			conn := o.quic[len(o.quic)-1]
			o.mu.Unlock()
			if says.quicFails(w, r, conn) {
				return
			}
		}
		said := r.Proto
		if r.TLS != nil && r.TLS.ECHAccepted {
			said += " ech"
		}
		_, _ = io.WriteString(w, said)
	}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
			NextProtos: []string{"h3"}, EncryptedClientHelloKeys: says.echKeys},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			o.firstQUIC.CompareAndSwap(0, time.Now().UnixNano())
			o.quicConns.Add(1)
			o.mu.Lock()
			o.quic = append(o.quic, conn)
			o.mu.Unlock()
			return ctx
		}}
	go func() { _ = h3.Serve(udp) }()
	t.Cleanup(func() { _ = h3.Close(); _ = udp.Close() })
	o.h3 = h3
	return o
}

// lateListener's connections write their first late, each kept as it is
// under TLS by the origin.
type lateListener struct {
	net.Listener
	lag time.Duration
	o   *h3Origin
}

func (l lateListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	l.o.mu.Lock()
	l.o.raw = append(l.o.raw, c)
	l.o.mu.Unlock()
	if l.lag == 0 {
		return c, nil
	}
	return &lateConn{Conn: c, lag: l.lag}, nil
}

// drop closes every TCP connection the origin took, TLS left unsaid.
func (o *h3Origin) drop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, c := range o.raw {
		_ = c.Close()
	}
}

type lateConn struct {
	net.Conn
	lag  time.Duration
	once sync.Once
}

func (c *lateConn) Write(b []byte) (int, error) {
	c.once.Do(func() { time.Sleep(c.lag) })
	return c.Conn.Write(b)
}

// relayLate passes each sender's datagrams to to from a socket of its own,
// and sends what comes back lag late.
func relayLate(pc net.PacketConn, to *net.UDPAddr, lag time.Duration) {
	var mu sync.Mutex
	ups := map[string]*net.UDPConn{}
	b := make([]byte, 65536)
	for {
		n, from, err := pc.ReadFrom(b)
		if err != nil {
			mu.Lock()
			for _, up := range ups {
				_ = up.Close()
			}
			mu.Unlock()
			return
		}
		mu.Lock()
		up := ups[from.String()]
		if up == nil {
			if up, err = net.DialUDP("udp4", nil, to); err != nil {
				mu.Unlock()
				return
			}
			ups[from.String()] = up
			go func(from net.Addr, up *net.UDPConn) {
				back := make([]byte, 65536)
				for {
					m, err := up.Read(back)
					if err != nil {
						return
					}
					datagram := append([]byte(nil), back[:m]...)
					time.AfterFunc(lag, func() { _, _ = pc.WriteTo(datagram, from) })
				}
			}(from, up)
		}
		mu.Unlock()
		_, _ = up.Write(b[:n])
	}
}

// dnsH3Policy is the frozen Chromium data's with Chrome 155's DNS records and
// HTTP/3 by them, changed (a key's value, or "" to leave it out).
func dnsH3Policy(t *testing.T, changes map[string]string) behavior.Policy {
	t.Helper()
	p := behavior.Legacy()
	for k, v := range map[string]string{"dns.https_records": "true", "dns.https_wait_percent": "20",
		"dns.https_wait_min_ms": "5", "dns.https_wait_max_ms": "50", "dns.resolver": `"built-in"`,
		"dns.https_h3": "true", "quic.tcp_waits_with_connection": "false", "quic.retry_over_tcp": "true",
		"http.unused_idle_connection_timeout_ms": "60000",
		// Chrome's own resends: a request on a connection that waited unused
		// goes again when it is lost.
		"h2.retries": "2", "h2.retry_errors": `["refused-stream", "goaway-no-error"]`, "h2.retry_delay_ms": "0",
		"http.connection_error_retries": "50", "http.connection_error_methods": `"any"`} {
		p[k] = json.RawMessage(v)
	}
	for k, v := range chromeDNSH3(t, nil) {
		p[k] = v
	}
	for k, v := range changes {
		if v == "" {
			delete(p, k)
			continue
		}
		p[k] = json.RawMessage(v)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

// recordSays is an Endpoint that finds every name at 127.0.0.1, its record
// naming h3 when h3 says so, and counts what it was asked.
type recordSays struct {
	h3    bool
	addrs []netip.Addr
	ech   []byte
	asked atomic.Int32
}

func (r *recordSays) endpoint(ctx context.Context, addr string) (context.Context, QUICEndpoint, bool) {
	r.asked.Add(1)
	addrs := r.addrs
	if addrs == nil {
		addrs = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	return ctx, QUICEndpoint{Addrs: addrs, ECH: r.ech}, r.h3
}

// h3Client is a client of policy whose requests go by records' word,
// sharing state.
func h3Client(t *testing.T, policy behavior.Policy, records *recordSays, state *QUICState, more ...HttpClientOption) HttpClient {
	t.Helper()
	c, err := NewHttpClient(nil, append([]HttpClientOption{WithClientProfile(profiles.Chrome_133.WithBehavior(policy)),
		WithInsecureSkipVerify(), WithTimeoutSeconds(10),
		WithHTTP3FromDNS(HTTP3FromDNS{Endpoint: records.endpoint, State: state, Key: func() string { return "https://a.test" }})}, more...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.CloseIdleConnections()
		// No QUIC connection the client is still making outlives the test:
		// its dial would read the seams the next test sets.
		d := c.(*httpClient).built.dnsH3
		if !waitFor(15*time.Second, func() bool {
			d.mu.Lock()
			defer d.mu.Unlock()
			return len(d.attempts) == 0
		}) {
			t.Error("a QUIC connection is still being made")
		}
	})
	return c
}

// came is what req came over, by the origin's word, or the error.
func came(t *testing.T, c HttpClient, url string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	res, err := c.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func TestARecordThatNamesH3SendsTheRequestOverQUICAndRacesTCPAsChrome(t *testing.T) {
	// TCP's handshake answered late: QUIC is up first, as a round trip
	// fewer has it on a network.
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	records := &recordSays{h3: true}
	c := h3Client(t, dnsH3Policy(t, nil), records, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	// QUIC has not worked in the session yet: TCP went at once too, and its
	// connection was made whoever took the request.
	if !waitFor(time.Second, func() bool { return o.tcpConns.Load() == 1 }) {
		t.Errorf("TCP connections %d, want the one raced", o.tcpConns.Load())
	}
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/3.0" {
		t.Errorf("the next came over %q, want the QUIC connection up", got)
	}
	if o.quicConns.Load() != 1 || o.tcpConns.Load() != 1 {
		t.Errorf("QUIC connections %d, TCP %d, want one each", o.quicConns.Load(), o.tcpConns.Load())
	}
	if records.asked.Load() != 1 {
		t.Errorf("records asked %d times, want once: the next went on the connection up", records.asked.Load())
	}
}

func waitFor(d time.Duration, ok func() bool) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return true
		}
	}
	return ok()
}

func TestOnceQUICWorkedTCPWaitsAndAQUICUpInTimeMakesNone(t *testing.T) {
	state := NewQUICState()
	state.workedFor(quicServer{"https://a.test", "elsewhere:443"})
	// QUIC 50 ms late: up well within the 300 ms TCP waits with no RTT known.
	o := newH3Origin(t, originSays{quicLag: 50 * time.Millisecond})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	time.Sleep(400 * time.Millisecond)
	if o.tcpConns.Load() != 0 {
		t.Errorf("%d TCP connections, want none", o.tcpConns.Load())
	}
}

func TestATCPConnectionUpFirstTakesTheRequestAndQUICTheNext(t *testing.T) {
	for _, warm := range []bool{false, true} {
		state := NewQUICState()
		if warm {
			state.workedFor(quicServer{"https://a.test", "elsewhere:443"})
		}
		o := newH3Origin(t, originSays{quicLag: 700 * time.Millisecond})
		c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
		began := time.Now()
		if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
			t.Fatalf("warm %v: came over %q, want TCP's HTTP/2", warm, got)
		}
		// Cold, TCP went at once; warm, once QUIC had been under way 300 ms.
		waited := time.Duration(o.firstTCP.Load() - began.UnixNano())
		if warm && (waited < 300*time.Millisecond || waited > 600*time.Millisecond) || !warm && waited > 200*time.Millisecond {
			t.Errorf("warm %v: TCP connected %v after the request began", warm, waited)
		}
		// QUIC came up apart, and takes the next.
		if !waitFor(3*time.Second, func() bool { return o.quicConns.Load() == 1 }) {
			t.Fatalf("warm %v: no QUIC connection", warm)
		}
		time.Sleep(800 * time.Millisecond)
		if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/3.0" {
			t.Errorf("warm %v: the next came over %q, want HTTP/3", warm, got)
		}
	}
}

func TestQUICThatFailsWhereTCPWorksIsNotTriedAgainForAWhile(t *testing.T) {
	o := newH3Origin(t, originSays{})
	state := NewQUICState()
	// The record gives no address QUIC can go to: its dial fails at once.
	records := &recordSays{h3: true, addrs: []netip.Addr{}}
	c := h3Client(t, dnsH3Policy(t, nil), records, state)
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	s := quicServer{"https://a.test", o.addr}
	if !waitFor(time.Second, func() bool { return state.isBroken(s) }) {
		t.Fatal("QUIC not broken")
	}
	// Broken: TCP alone, the record not even asked.
	asked := records.asked.Load()
	records.addrs = nil
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/2.0" || records.asked.Load() != asked {
		t.Errorf("broken: came over %q, records asked %d more times", got, records.asked.Load()-asked)
	}
	if o.quicConns.Load() != 0 {
		t.Errorf("%d QUIC connections while broken", o.quicConns.Load())
	}
}

func TestAnUnansweredQUICLeavesTheRequestToTCP(t *testing.T) {
	o := newH3Origin(t, originSays{silent: true})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	// The origin's TCP is HTTP/2 and HTTP/1.1; its UDP never answers.
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if o.datagrams.Load() == 0 {
		t.Error("QUIC was not tried")
	}
}

func TestARecordThatNamesNoH3IsTCPAlone(t *testing.T) {
	o := newH3Origin(t, originSays{})
	for _, tc := range []struct {
		name    string
		changes map[string]string
		h3      bool
	}{
		{"no h3 in the record", nil, false},
		{"a profile that does not ask", map[string]string{"dns.https_h3": "false", "quic.tcp_wait_cold_ms": "",
			"quic.tcp_wait_broken_ms": "", "quic.tcp_wait_rtt_percent": "", "quic.tcp_wait_default_ms": "",
			"quic.tcp_wait_extra_ms": "", "quic.tcp_wait_max_ms": "", "quic.tcp_waits_with_connection": "",
			"quic.retry_over_tcp": "", "quic.broken_ms": "", "quic.broken_doublings": "", "quic.broken_max_ms": "", "quic.broken_recent_max": "",
			"quic.server_rtts_max": "", "http.unused_idle_connection_timeout_ms": ""}, true},
	} {
		c := h3Client(t, dnsH3Policy(t, tc.changes), &recordSays{h3: tc.h3}, NewQUICState())
		if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
			t.Errorf("%s: came over %q", tc.name, got)
		}
	}
	if o.quicConns.Load() != 0 {
		t.Errorf("%d QUIC connections", o.quicConns.Load())
	}
}

func TestATCPConnectionUpTakesARequestAtOnceAndQUICIsMadeApart(t *testing.T) {
	o := newH3Origin(t, originSays{})
	records := &recordSays{h3: false}
	c := h3Client(t, dnsH3Policy(t, nil), records, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
		t.Fatalf("came over %q", got)
	}
	// The record names h3 now: the next request goes on the TCP connection
	// up, and QUIC is made apart; the one after on QUIC.
	records.h3 = true
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/2.0" {
		t.Errorf("came over %q, want the TCP connection up", got)
	}
	if !waitFor(2*time.Second, func() bool { return o.quicConns.Load() == 1 }) {
		t.Fatal("no QUIC connection made apart")
	}
	time.Sleep(100 * time.Millisecond)
	if got := came(t, c, "https://"+o.addr+"/third"); got != "HTTP/3.0" {
		t.Errorf("the third came over %q, want HTTP/3", got)
	}
	if o.tcpConns.Load() != 1 {
		t.Errorf("%d TCP connections, want the one", o.tcpConns.Load())
	}
}

func TestARequestBothFailSaysTCPsError(t *testing.T) {
	// Nothing listens at the port: TCP is refused, and QUIC has no address.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true, addrs: []netip.Addr{}}, NewQUICState())
	if got := came(t, c, "https://"+addr+"/"); !strings.Contains(got, "refused") {
		t.Errorf("said %q, want TCP's refusal", got)
	}
}

func TestARequestThatEndsDuringTheRaceSaysSo(t *testing.T) {
	o := newH3Origin(t, originSays{silent: true})
	state := NewQUICState()
	state.workedFor(quicServer{"https://a.test", "elsewhere:443"})
	c := h3Client(t, dnsH3Policy(t, map[string]string{"quic.tcp_wait_default_ms": "3000"}), &recordSays{h3: true}, state)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+o.addr+"/", nil)
	if _, err := c.Do(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Do = %v, want the deadline", err)
	}
	if o.tcpConns.Load() != 0 {
		t.Errorf("%d TCP connections before the wait was over", o.tcpConns.Load())
	}
}

func TestRequestsAtOnceJoinOneQUICConnection(t *testing.T) {
	o := newH3Origin(t, originSays{quicLag: 300 * time.Millisecond})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	var wg sync.WaitGroup
	got := make([]string, 3)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = came(t, c, "https://"+o.addr+"/")
		}()
	}
	wg.Wait()
	for i, g := range got {
		if g != "HTTP/2.0" {
			t.Errorf("request %d came over %q, want TCP's", i, g)
		}
	}
	if !waitFor(2*time.Second, func() bool { return o.quicConns.Load() == 1 }) {
		t.Fatalf("%d QUIC connections, want the one they joined", o.quicConns.Load())
	}
	time.Sleep(400 * time.Millisecond)
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/3.0" {
		t.Errorf("the next came over %q, want HTTP/3", got)
	}
	if o.quicConns.Load() != 1 || o.tcpConns.Load() != 1 {
		t.Errorf("QUIC connections %d, TCP %d, want one each", o.quicConns.Load(), o.tcpConns.Load())
	}
}

func TestAnHTTP1OriginsIdleConnectionTakesARequestAtOnce(t *testing.T) {
	h1 := new(atomic.Bool)
	h1.Store(true)
	o := newH3Origin(t, originSays{h1: h1})
	records := &recordSays{}
	c := h3Client(t, dnsH3Policy(t, nil), records, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/1.1" {
		t.Fatalf("came over %q", got)
	}
	records.h3 = true
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/1.1" {
		t.Errorf("came over %q, want the idle HTTP/1.1 connection", got)
	}
	if !waitFor(2*time.Second, func() bool { return o.quicConns.Load() == 1 }) {
		t.Fatal("no QUIC connection made apart")
	}
	time.Sleep(100 * time.Millisecond)
	if got := came(t, c, "https://"+o.addr+"/third"); got != "HTTP/3.0" {
		t.Errorf("the third came over %q, want HTTP/3", got)
	}
}

func TestATCPConnectionUpAndARecordWithoutH3IsTCPAlone(t *testing.T) {
	o := newH3Origin(t, originSays{})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{}, NewQUICState())
	for _, path := range []string{"/", "/again"} {
		if got := came(t, c, "https://"+o.addr+path); got != "HTTP/2.0" {
			t.Errorf("%s came over %q", path, got)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if o.quicConns.Load() != 0 {
		t.Errorf("%d QUIC connections", o.quicConns.Load())
	}
}

func TestATransportWithoutAConnectionHasOneMadeForItAndOneOfAnotherProtocolSetUp(t *testing.T) {
	for _, changes := range []bool{false, true} {
		h1 := new(atomic.Bool)
		o := newH3Origin(t, originSays{quicLag: 400 * time.Millisecond, h1: h1})
		records := &recordSays{}
		c := h3Client(t, dnsH3Policy(t, nil), records, NewQUICState())
		if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
			t.Fatalf("came over %q", got)
		}
		// Its connection closed, the HTTP/2 transport stays; TCP is made for
		// it as QUIC is under way, and wins.
		c.CloseIdleConnections()
		if !waitFor(time.Second, func() bool { return o.tcpClosed.Load() == 1 }) {
			t.Fatal("the connection was not closed")
		}
		time.Sleep(100 * time.Millisecond)
		h1.Store(changes)
		records.h3 = true
		want := "HTTP/2.0"
		if changes {
			want = "HTTP/1.1"
		}
		if got := came(t, c, "https://"+o.addr+"/again"); got != want {
			t.Errorf("changes %v: came over %q, want %q", changes, got, want)
		}
		if o.tcpConns.Load() != 2 {
			t.Errorf("changes %v: %d TCP connections, want a second, the one made for it", changes, o.tcpConns.Load())
		}
	}
}

func TestQUICThatFailsAfterTCPDidSaysTCPsError(t *testing.T) {
	saved := dialQUIC
	t.Cleanup(func() { dialQUIC = saved })
	dialQUIC = func(_ context.Context, _ *net.UDPAddr, _ *tls.Config, _ *quic.Config, sent func()) (*quic.Conn, error) {
		sent()
		time.Sleep(200 * time.Millisecond)
		return nil, errors.New("no QUIC")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+addr+"/"); !strings.Contains(got, "refused") {
		t.Errorf("said %q, want TCP's refusal", got)
	}
}

func TestAPortPastWhatAnAddressHasFailsBoth(t *testing.T) {
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://127.0.0.1:70000/"); !strings.Contains(got, "invalid port") {
		t.Errorf("said %q", got)
	}
}

func TestATCPConnectionThatLostIsReapedUnusedOrPassedOverClosed(t *testing.T) {
	// Reaped: once its time is up, on the next request.
	o := newH3Origin(t, originSays{tcpLag: 50 * time.Millisecond})
	c := h3Client(t, dnsH3Policy(t, map[string]string{"http.unused_idle_connection_timeout_ms": "1"}), &recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q", got)
	}
	time.Sleep(200 * time.Millisecond)
	if o.tcpClosed.Load() != 0 {
		t.Fatal("the connection that lost was closed before its time")
	}
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/3.0" {
		t.Fatalf("came over %q", got)
	}
	if !waitFor(time.Second, func() bool { return o.tcpClosed.Load() == 1 }) {
		t.Error("the unused connection was not reaped")
	}
	// Passed over: its server closed it, and QUIC went away; the next request
	// makes another.
	o = newH3Origin(t, originSays{tcpLag: 50 * time.Millisecond})
	state := NewQUICState()
	c = h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q", got)
	}
	time.Sleep(200 * time.Millisecond)
	o.tcp.CloseClientConnections()
	_ = o.h3.Close()
	if !waitFor(time.Second, func() bool { return o.tcpClosed.Load() == 1 }) {
		t.Fatal("the server did not close it")
	}
	time.Sleep(100 * time.Millisecond)
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/2.0" {
		t.Errorf("came over %q, want TCP's", got)
	}
	if o.tcpConns.Load() != 2 {
		t.Errorf("%d TCP connections, want another", o.tcpConns.Load())
	}
}

func TestAConnectionLeftForATransportReplacesTheOneBefore(t *testing.T) {
	rt := &roundTripper{cachedConnections: map[string]net.Conn{}, stashedAt: map[string]time.Time{}}
	a, other := net.Pipe()
	defer other.Close()
	b, _ := net.Pipe()
	rt.stash("x:443", a)
	rt.stash("x:443", b)
	if _, err := a.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("the one replaced: %v, want closed", err)
	}
	if rt.cachedConnections["x:443"] != b {
		t.Error("not the one left last")
	}
}

func TestARTTIsKeptOnceAConnectionGoesAwayUnlessBroken(t *testing.T) {
	for _, broken := range []bool{false, true} {
		o := newH3Origin(t, originSays{tcpLag: 50 * time.Millisecond})
		state := NewQUICState()
		c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
		if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
			t.Fatalf("came over %q", got)
		}
		s := quicServer{"https://a.test", o.addr}
		if broken {
			state.markBroken(s, dnsH3Policy(t, nil))
		}
		c.CloseIdleConnections()
		kept := waitFor(time.Second, func() bool {
			state.mu.Lock()
			defer state.mu.Unlock()
			return state.rttsByKey[s] != nil
		})
		if kept == broken {
			t.Errorf("broken %v: RTT kept %v", broken, kept)
		}
	}
}

func TestAnHTTP3TransportThatCannotBeMadeFailsTheRequest(t *testing.T) {
	saved := buildDNSH3Transport
	t.Cleanup(func() { buildDNSH3Transport = saved })
	buildDNSH3Transport = func(*http3Config) (http.RoundTripper, error) { return nil, errors.New("no transport") }
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://127.0.0.1:1/"); !strings.Contains(got, "no transport") {
		t.Errorf("said %q", got)
	}
}

func TestQUICOffersTheECHOfTheRecordThatNamesH3(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := echConfig(7, key)
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond,
		echKeys: []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: key.Bytes()}}})
	policy := dnsH3Policy(t, nil)
	for k, v := range echPolicy(t, nil) {
		policy[k] = v
	}
	c := h3Client(t, policy, &recordSays{h3: true, ech: echList(config)}, NewQUICState(), WithServerNameOverwrite("a.test"))
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0 ech" {
		t.Errorf("came over %q, want HTTP/3 with the inner hello opened", got)
	}
}

func TestARequestWithNoDeadlineLetsItsTCPConnectionFinishApart(t *testing.T) {
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState(), WithoutRequestTimeout())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q", got)
	}
	time.Sleep(300 * time.Millisecond)
	if o.tcpConns.Load() != 1 || o.tcpClosed.Load() != 0 {
		t.Errorf("TCP connections %d, closed %d: want the one, kept", o.tcpConns.Load(), o.tcpClosed.Load())
	}
}

func TestAnECHTheServerRefusesOverQUICLeavesTheRequestToTCP(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The server has no ECH keys: it answers the outer hello, and the client,
	// which checks no certificate, takes it as refused.
	o := newH3Origin(t, originSays{})
	policy := dnsH3Policy(t, nil)
	for k, v := range echPolicy(t, nil) {
		policy[k] = v
	}
	state := NewQUICState()
	c := h3Client(t, policy, &recordSays{h3: true, ech: echList(echConfig(7, key))}, state, WithServerNameOverwrite("a.test"))
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
		t.Errorf("came over %q, want TCP's", got)
	}
	if !waitFor(time.Second, func() bool { return state.isBroken(quicServer{"https://a.test", o.addr}) }) {
		t.Error("QUIC not broken")
	}
}

func TestATCPConnectionThatCannotBeMadeForATransportFailsWhenQUICDoes(t *testing.T) {
	saved := dialQUIC
	t.Cleanup(func() { dialQUIC = saved })
	o := newH3Origin(t, originSays{})
	records := &recordSays{}
	c := h3Client(t, dnsH3Policy(t, nil), records, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
		t.Fatalf("came over %q", got)
	}
	// Its server gone, the transport stays: its TCP connection is refused,
	// and QUIC fails after it.
	o.tcp.Close()
	c.CloseIdleConnections()
	time.Sleep(100 * time.Millisecond)
	dialQUIC = func(_ context.Context, _ *net.UDPAddr, _ *tls.Config, _ *quic.Config, sent func()) (*quic.Conn, error) {
		sent()
		time.Sleep(100 * time.Millisecond)
		return nil, errors.New("no QUIC")
	}
	records.h3 = true
	if got := came(t, c, "https://"+o.addr+"/again"); !strings.Contains(got, "refused") {
		t.Errorf("said %q, want TCP's refusal", got)
	}
}

func TestAConnectionOfAnotherProtocolReplacesTheOneLeftBefore(t *testing.T) {
	rt := &roundTripper{changedConnections: map[string]*tls.UConn{}}
	a, other := net.Pipe()
	defer other.Close()
	b, _ := net.Pipe()
	first := tls.UClient(a, &tls.Config{}, tls.HelloChrome_Auto, false, false, false)
	rt.leaveChanged("x:443", first)
	rt.leaveChanged("x:443", tls.UClient(b, &tls.Config{}, tls.HelloChrome_Auto, false, false, false))
	if _, err := a.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("the one left before: %v, want closed", err)
	}
}

func TestAConnectionItsServerDroppedWithNothingSaidIsNotTakenUp(t *testing.T) {
	// An HTTP/1.1 server that gives no session tickets says nothing after the
	// handshake: dropped, the connection that lost has nothing but its end to
	// read.
	h1 := new(atomic.Bool)
	h1.Store(true)
	o := newH3Origin(t, originSays{tcpLag: 50 * time.Millisecond, noTickets: true, h1: h1})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q", got)
	}
	time.Sleep(200 * time.Millisecond)
	o.drop()
	_ = o.h3.Close()
	time.Sleep(100 * time.Millisecond)
	var conns atomic.Int32
	req, _ := http.NewRequest("GET", "https://"+o.addr+"/again", nil)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { conns.Add(1) }}))
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if string(b) != "HTTP/1.1" {
		t.Errorf("came over %q, want TCP's", b)
	}
	if conns.Load() != 1 {
		t.Errorf("the request went on %d connections, want the new one alone", conns.Load())
	}
	if o.tcpConns.Load() != 2 {
		t.Errorf("%d TCP connections, want another", o.tcpConns.Load())
	}
}

func TestTCPGoesOnlyOnceQUICsFirstPacketHasGone(t *testing.T) {
	saved := dialQUIC
	t.Cleanup(func() { dialQUIC = saved })
	for _, sends := range []bool{true, false} {
		var gone, failed atomic.Int64
		dialQUIC = func(_ context.Context, _ *net.UDPAddr, _ *tls.Config, _ *quic.Config, sent func()) (*quic.Conn, error) {
			time.Sleep(150 * time.Millisecond)
			gone.Store(time.Now().UnixNano())
			if sends {
				// Under way, and never up.
				sent()
				time.Sleep(300 * time.Millisecond)
			}
			failed.Store(time.Now().UnixNano())
			return nil, errors.New("no QUIC")
		}
		o := newH3Origin(t, originSays{})
		c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
		if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
			t.Fatalf("sends %v: came over %q, want TCP's", sends, got)
		}
		if g := gone.Load(); g == 0 || o.firstTCP.Load() < g {
			t.Errorf("sends %v: TCP before QUIC's first packet", sends)
		}
		if sends && failed.Load() != 0 {
			t.Errorf("sends %v: TCP waited for QUIC to fail", sends)
		}
		if first := o.firstTCP.Load(); !sends && first < failed.Load() {
			t.Errorf("sends %v: TCP before QUIC failed", sends)
		}
	}
}

func TestARequestAfterItsQUICConnectionWentAwayGoesOnANewOne(t *testing.T) {
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	// The TCP connection that lost is kept unused no time, so that the next
	// request finds none, as one past a minute does.
	c := h3Client(t, dnsH3Policy(t, map[string]string{"http.unused_idle_connection_timeout_ms": "0"}),
		&recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	// Its TCP connection made, which the next request would go on at once.
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool {
		rt.cachedTransportsLck.Lock()
		defer rt.cachedTransportsLck.Unlock()
		_, settingUp := rt.setups[o.addr]
		return o.tcpConns.Load() == 1 && !settingUp
	}) {
		t.Fatal("no TCP connection made")
	}
	// The server ends its QUIC connection, as one idle past its timeout ends.
	o.mu.Lock()
	_ = o.quic[0].CloseWithError(0, "")
	o.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/3.0" {
		t.Errorf("the next came over %q, want HTTP/3 again", got)
	}
	if o.quicConns.Load() != 2 {
		t.Errorf("%d QUIC connections, want a new one", o.quicConns.Load())
	}
}

func TestAClientThatSpeaksHTTP1AloneOrGoesThroughAProxyMakesNoQUIC(t *testing.T) {
	o := newH3Origin(t, originSays{})
	records := &recordSays{h3: true}
	c := h3Client(t, dnsH3Policy(t, nil), records, NewQUICState(), WithForceHttp1())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/1.1" {
		t.Errorf("forced HTTP/1.1: came over %q", got)
	}
	// Through a proxy, names are the proxy's: none is asked, no QUIC made.
	c = h3Client(t, dnsH3Policy(t, nil), records, NewQUICState(), WithProxyUrl("http://"+deadTCP(t)))
	if got := came(t, c, "https://"+o.addr+"/"); !strings.Contains(got, "error") {
		t.Errorf("through a proxy nobody answers at: came over %q", got)
	}
	time.Sleep(100 * time.Millisecond)
	if records.asked.Load() != 0 || o.quicConns.Load() != 0 {
		t.Errorf("records asked %d times, %d QUIC connections, want none", records.asked.Load(), o.quicConns.Load())
	}
}

// deadTCP is a loopback address the machine handed out and nobody listens at.
func deadTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestQUICThatFailsAfterTCPTookTheRequestIsNotTriedAgain(t *testing.T) {
	saved := dialQUIC
	t.Cleanup(func() { dialQUIC = saved })
	dialQUIC = func(_ context.Context, _ *net.UDPAddr, _ *tls.Config, _ *quic.Config, sent func()) (*quic.Conn, error) {
		sent()
		time.Sleep(200 * time.Millisecond)
		return nil, errors.New("no QUIC")
	}
	o := newH3Origin(t, originSays{})
	state := NewQUICState()
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if !waitFor(2*time.Second, func() bool { return state.isBroken(quicServer{"https://a.test", o.addr}) }) {
		t.Error("QUIC that failed after TCP took the request is tried again")
	}
}

func TestQUICThatFailsWhereTCPFailedTooIsTriedAgain(t *testing.T) {
	saved := dialQUIC
	t.Cleanup(func() { dialQUIC = saved })
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	state := NewQUICState()
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	// TCP's connection, made and left unused...
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool {
		rt.Lock()
		defer rt.Unlock()
		return rt.cachedConnections[o.addr] != nil
	}) {
		t.Fatal("no TCP connection left unused")
	}
	// ...goes with its server, which takes no other, and QUIC's is ended.
	_ = o.tcp.Listener.Close()
	o.drop()
	o.mu.Lock()
	_ = o.quic[0].CloseWithError(0, "")
	o.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	dialQUIC = func(_ context.Context, _ *net.UDPAddr, _ *tls.Config, _ *quic.Config, sent func()) (*quic.Conn, error) {
		sent()
		time.Sleep(100 * time.Millisecond)
		return nil, errors.New("no QUIC")
	}
	// The request goes on the TCP connection at once, which is lost and none
	// made again; QUIC fails after it, which leaves QUIC to the server tried.
	if got := came(t, c, "https://"+o.addr+"/again"); !strings.Contains(got, "error") {
		t.Fatalf("came over %q, want an error", got)
	}
	time.Sleep(300 * time.Millisecond)
	if state.isBroken(quicServer{"https://a.test", o.addr}) {
		t.Error("QUIC broken where TCP failed too")
	}
}

func TestQUICThatWorkedOnceHasTCPWaitForItElsewhere(t *testing.T) {
	state := NewQUICState()
	first := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
	if got := came(t, c, "https://"+first.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	// QUIC worked in the session: to another origin, whose QUIC answers
	// 50 ms late, TCP waits 300 ms (no RTT known) and is never made.
	late := newH3Origin(t, originSays{quicLag: 50 * time.Millisecond})
	if got := came(t, c, "https://"+late.addr+"/"); got != "HTTP/3.0" {
		t.Errorf("came over %q, want HTTP/3", got)
	}
	time.Sleep(400 * time.Millisecond)
	if late.tcpConns.Load() != 0 {
		t.Errorf("%d TCP connections, want none", late.tcpConns.Load())
	}
}

func TestATCPConnectionThatLostToQUICIsLeftUnused(t *testing.T) {
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool {
		rt.Lock()
		defer rt.Unlock()
		return rt.cachedConnections[o.addr] != nil && rt.unusedStash[o.addr]
	}) {
		t.Fatal("the TCP connection QUIC beat is not left unused")
	}
	// Taken up, it says so once, to the transport that takes it.
	conn := rt.takeStashed(o.addr)
	if conn == nil || !rt.wasUnusedIdle(conn) || rt.wasUnusedIdle(conn) {
		t.Error("the connection taken up does not say once that it waited unused")
	}
}

func TestATCPConnectionLeftUnusedTakesTheNextRequestAtOnce(t *testing.T) {
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool {
		rt.Lock()
		defer rt.Unlock()
		return rt.cachedConnections[o.addr] != nil
	}) {
		t.Fatal("no TCP connection left unused")
	}
	// QUIC's connection ended and TCP's waiting unused: the next request goes
	// on it at once, as on a socket Chromium's pool kept, QUIC made apart.
	o.mu.Lock()
	_ = o.quic[0].CloseWithError(0, "")
	o.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/2.0" {
		t.Errorf("the next came over %q, want the TCP connection left", got)
	}
	if !waitFor(time.Second, func() bool { return o.quicConns.Load() == 2 }) {
		t.Errorf("%d QUIC connections, want one made apart", o.quicConns.Load())
	}
	if o.tcpConns.Load() != 1 {
		t.Errorf("%d TCP connections, want the one left unused", o.tcpConns.Load())
	}
}

func TestClosingIdleConnectionsClosesTheOneLeftUnused(t *testing.T) {
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	rt := c.(*httpClient).built
	if !waitFor(2*time.Second, func() bool {
		rt.Lock()
		defer rt.Unlock()
		return rt.cachedConnections[o.addr] != nil
	}) {
		t.Fatal("no TCP connection left unused")
	}
	c.CloseIdleConnections()
	if !waitFor(time.Second, func() bool { return o.tcpClosed.Load() == 1 }) {
		t.Error("the connection left unused is not closed with the idle ones")
	}
}

func TestAPlainHTTPRequestGoesOverTCPWhateverARecordSays(t *testing.T) {
	plain := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	defer plain.Close()
	records := &recordSays{h3: true}
	c := h3Client(t, dnsH3Policy(t, nil), records, NewQUICState())
	if got := came(t, c, plain.URL+"/"); got != "HTTP/1.1" {
		t.Errorf("came over %q, want HTTP/1.1", got)
	}
	if records.asked.Load() != 0 {
		t.Errorf("records asked %d times for plain http, want none", records.asked.Load())
	}
}

// halfMade is a QUIC connection that went away before its handshake was done.
type halfMade struct{ ctx context.Context }

func (h halfMade) Context() context.Context         { return h.ctx }
func (halfMade) HandshakeComplete() <-chan struct{} { return make(chan struct{}) }
func (halfMade) ConnectionStats() quic.ConnectionStats {
	return quic.ConnectionStats{SmoothedRTT: time.Second}
}

func TestAConnectionThatWentAwayBeforeItsHandshakeLeavesNoRTT(t *testing.T) {
	d := newDNSH3(&HTTP3FromDNS{State: NewQUICState()})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := quicServer{"https://a.test", "a.test:443"}
	d.watch(&roundTripper{behavior: dnsH3Policy(t, nil)}, halfMade{ctx}, s)
	if d.State.rttsByKey[s] != nil {
		t.Error("an RTT kept of a connection whose handshake was not done")
	}
}

// resetting is an origin's HTTP/3 that resets the stream of every request
// with code, as a server whose decoder cannot read the request's fields does
// (QPACK_DECOMPRESSION_FAILED, 0x200), after the first answered when one is.
func resetting(code uint64, answered int32) func(http.ResponseWriter, *http.Request, *quic.Conn) bool {
	var asked atomic.Int32
	return func(w http.ResponseWriter, _ *http.Request, _ *quic.Conn) bool {
		if asked.Add(1) <= answered {
			return false
		}
		str := unanswered(w)
		str.CancelRead(quic.StreamErrorCode(code))
		str.CancelWrite(quic.StreamErrorCode(code))
		return true
	}
}

// unanswered is the stream of the request w answers, taken with nothing sent:
// HTTPStream sends a 200 first, so that a client read an answer before the
// reset now and then, where a server that cannot read a request sends none
// (quic-go's own resets such a stream before any).
func unanswered(w http.ResponseWriter) *http3.Stream {
	f := reflect.ValueOf(w).Elem().FieldByName("str")
	if !f.IsValid() || f.Type() != reflect.TypeOf((*http3.Stream)(nil)) {
		panic("http3's response writer keeps its stream elsewhere")
	}
	return *(**http3.Stream)(unsafe.Pointer(f.UnsafeAddr()))
}

// closing is an origin's HTTP/3 that ends the connection of a request it is
// given with an application error, as a client that read its settings
// against what ALPS gave does (H3_SETTINGS_ERROR, 0x109).
func closing(code uint64) func(http.ResponseWriter, *http.Request, *quic.Conn) bool {
	return func(_ http.ResponseWriter, _ *http.Request, conn *quic.Conn) bool {
		_ = conn.CloseWithError(quic.ApplicationErrorCode(code), "164:settings")
		return true
	}
}

func TestARequestAQUICConnectionFailedGoesAgainOverTCPAndQUICIsBrokenAsChromes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fails func(http.ResponseWriter, *http.Request, *quic.Conn) bool
	}{
		{"its stream reset", resetting(0x200, 0)},
		{"its connection closed", closing(0x109)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// TCP's handshake answered late: QUIC is up first and takes the
			// request, which it fails.
			o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, quicFails: tc.fails})
			state := NewQUICState()
			c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
			// Chromium: HTTP_TRANSACTION_RESTART_AFTER_ERROR, ERR_QUIC_PROTOCOL_ERROR,
			// the request again with alternative services off (bench/h3alps)
			if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
				t.Fatalf("came over %q, want TCP's after QUIC's failure", got)
			}
			if !state.isBroken(quicServer{"https://a.test", o.addr}) {
				t.Fatal("QUIC not broken once TCP answered")
			}
			// broken: the next over TCP, and no QUIC connection made for it
			if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/2.0" {
				t.Errorf("the next came over %q", got)
			}
			time.Sleep(50 * time.Millisecond)
			if o.quicConns.Load() != 1 {
				t.Errorf("%d QUIC connections, want the one that failed", o.quicConns.Load())
			}
		})
	}
}

func TestARequestFailedOnAQUICConnectionUpGoesAgainOverTCPWithItsBody(t *testing.T) {
	// the first answered over HTTP/3, the second's stream reset
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, quicFails: resetting(0x200, 1)})
	state := NewQUICState()
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q", got)
	}
	req, _ := http.NewRequest("POST", "https://"+o.addr+"/post", strings.NewReader("the body"))
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(b) != "HTTP/2.0 the body" {
		t.Errorf("came over %q, want TCP's with the body again", b)
	}
	if !state.isBroken(quicServer{"https://a.test", o.addr}) {
		t.Error("QUIC not broken once TCP answered")
	}
}

// onceReader is a body that cannot be had again.
type onceReader struct{ io.Reader }

func TestARequestQUICFailedIsNotSentAgainWhenItsProfileSaysOrItsBodyCannotBeHadAgain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changes map[string]string
		body    io.Reader
		getBody func() (io.ReadCloser, error)
	}{
		{"its profile says not", map[string]string{"quic.retry_over_tcp": "false"}, nil, nil},
		{"a body that cannot be had again", nil, onceReader{strings.NewReader("once")}, nil},
		{"a body whose copy fails", nil, onceReader{strings.NewReader("once")},
			func() (io.ReadCloser, error) { return nil, errors.New("no copy") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, quicFails: resetting(0x200, 0)})
			state := NewQUICState()
			c := h3Client(t, dnsH3Policy(t, tc.changes), &recordSays{h3: true}, state)
			req, _ := http.NewRequest("POST", "https://"+o.addr+"/", tc.body)
			req.GetBody = tc.getBody
			_, err := c.Do(req)
			var se *quic.StreamError
			var he *http3.Error
			if err == nil || !errors.As(err, &se) && !errors.As(err, &he) {
				t.Fatalf("said %v, want QUIC's error", err)
			}
			if state.isBroken(quicServer{"https://a.test", o.addr}) {
				t.Error("QUIC broken with no TCP answer")
			}
			if o.tcpAsked.Load() != 0 {
				t.Errorf("TCP asked %d times", o.tcpAsked.Load())
			}
		})
	}
}

func TestARequestWithAnEmptyBodyQUICFailedGoesAgainOverTCP(t *testing.T) {
	// http.NoBody, which a caller may give with no way to have it again: it
	// is the same every time
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, quicFails: resetting(0x200, 0)})
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState())
	req, _ := http.NewRequest("POST", "https://"+o.addr+"/", nil)
	req.Body = http.NoBody
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(b) != "HTTP/2.0" {
		t.Errorf("came over %q, want TCP's", b)
	}
}

func TestARequestEndedOnQUICIsNotSentAgain(t *testing.T) {
	// its QUIC connection holds it past its deadline: its own context ends
	// it, and TCP is not asked
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, quicFails: func(http.ResponseWriter, *http.Request, *quic.Conn) bool {
		time.Sleep(300 * time.Millisecond)
		return false
	}})
	state := NewQUICState()
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+o.addr+"/", nil)
	if _, err := c.Do(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("said %v, want its deadline", err)
	}
	if o.tcpAsked.Load() != 0 || state.isBroken(quicServer{"https://a.test", o.addr}) {
		t.Errorf("TCP asked %d times, QUIC broken %v", o.tcpAsked.Load(), state.isBroken(quicServer{"https://a.test", o.addr}))
	}
}

func TestARequestBothQUICAndTCPFailedLeavesQUICUnbroken(t *testing.T) {
	var o *h3Origin
	o = newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, quicFails: func(w http.ResponseWriter, r *http.Request, conn *quic.Conn) bool {
		// TCP gone before the request comes back to it
		o.tcp.CloseClientConnections()
		_ = o.tcp.Listener.Close()
		return resetting(0x200, 0)(w, r, conn)
	}})
	state := NewQUICState()
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
	if got := came(t, c, "https://"+o.addr+"/"); !strings.HasPrefix(got, "error: ") {
		t.Fatalf("came over %q, want TCP's error", got)
	}
	if state.isBroken(quicServer{"https://a.test", o.addr}) {
		t.Error("QUIC broken where TCP did not work either")
	}
}

func TestARequestTheQUICConnectionUpRefusedUnprocessedGoesOverTCPWithItsBody(t *testing.T) {
	// H3_REQUEST_REJECTED: tried again, on no connection the transport may
	// make; TCP's takes it, its body again, and QUIC is not broken for that
	for _, answered := range []int32{0, 1} {
		o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond, quicFails: resetting(0x10b, answered)})
		state := NewQUICState()
		c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, state)
		if answered > 0 {
			if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
				t.Fatalf("came over %q", got)
			}
		}
		req, _ := http.NewRequest("POST", "https://"+o.addr+"/post", strings.NewReader("the body"))
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if string(b) != "HTTP/2.0 the body" {
			t.Errorf("%d answered: came over %q, want TCP's with the body", answered, b)
		}
		if state.isBroken(quicServer{"https://a.test", o.addr}) {
			t.Errorf("%d answered: QUIC broken for a request refused unprocessed", answered)
		}
	}
}
