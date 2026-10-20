package tls_client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/igor-lemon/tls-client/profiles"
)

// wrappedConn is a connection to a proxy as the wrapper has it: when its dial
// began, when the wrapper was handed it, and what went over it each way.
type wrappedConn struct {
	net.Conn
	began, handed  time.Time
	mu             sync.Mutex
	sent, received bytes.Buffer
	closed         bool
}

func (c *wrappedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.received.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *wrappedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.sent.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *wrappedConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *wrappedConn) what() (sent, received []byte, closed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.sent.Bytes()), bytes.Clone(c.received.Bytes()), c.closed
}

type requestKey struct{}

// holder is a ProxyConnWrapper that keeps every connection it is handed, and
// the request each was for, by the value its context carries.
type holder struct {
	mu    sync.Mutex
	conns []*wrappedConn
	of    []any
}

func (h *holder) wrap(ctx context.Context, conn net.Conn, began time.Time) net.Conn {
	held := &wrappedConn{Conn: conn, began: began, handed: time.Now()}
	h.mu.Lock()
	h.conns = append(h.conns, held)
	h.of = append(h.of, ctx.Value(requestKey{}))
	h.mu.Unlock()
	return held
}

func (h *holder) held() ([]*wrappedConn, []any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.conns), slices.Clone(h.of)
}

// socksProxy is a SOCKS proxy on a loopback port, SOCKS4, SOCKS4a and
// SOCKS5 alike (RFC 1928), which asks a SOCKS5 client for user and password
// (RFC 1929) when user is not empty, and joins each client to the address it
// asked for.
func socksProxy(t *testing.T, user, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				target, granted, ok := socksAsked(c, user, password)
				if !ok {
					return
				}
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer upstream.Close()
				if _, err := c.Write(granted); err != nil {
					return
				}
				_ = c.SetDeadline(time.Time{})
				go func() { _, _ = io.Copy(upstream, c) }()
				_, _ = io.Copy(c, upstream)
			}()
		}
	}()
	return ln.Addr().String()
}

// socksAsked reads a SOCKS client's request up to the address it asks for,
// and is that address and the answer that grants it.
func socksAsked(c net.Conn, user, password string) (string, []byte, bool) {
	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(c, b); err != nil {
			return nil
		}
		return b
	}
	upTo := func(end byte) (string, bool) {
		var s []byte
		for {
			b := read(1)
			if b == nil {
				return "", false
			}
			if b[0] == end {
				return string(s), true
			}
			s = append(s, b[0])
		}
	}
	head := read(2)
	if head == nil {
		return "", nil, false
	}
	if head[0] == 4 {
		rest := read(6)
		if rest == nil || head[1] != 1 {
			return "", nil, false
		}
		port := strconv.Itoa(int(binary.BigEndian.Uint16(rest[:2])))
		host := net.IP(rest[2:6]).String()
		if _, ok := upTo(0); !ok {
			return "", nil, false
		}
		if rest[2] == 0 && rest[3] == 0 && rest[4] == 0 && rest[5] != 0 {
			name, ok := upTo(0)
			if !ok {
				return "", nil, false
			}
			host = name
		}
		return net.JoinHostPort(host, port), []byte{0, 0x5a, 0, 0, 0, 0, 0, 0}, true
	}
	methods := read(int(head[1]))
	method := byte(0)
	if user != "" {
		method = 2
	}
	if head[0] != 5 || !slices.Contains(methods, method) {
		return "", nil, false
	}
	if _, err := c.Write([]byte{5, method}); err != nil {
		return "", nil, false
	}
	if user != "" {
		version := read(2)
		if version == nil || version[0] != 1 {
			return "", nil, false
		}
		name := read(int(version[1]))
		length := read(1)
		if name == nil || length == nil {
			return "", nil, false
		}
		given := read(int(length[0]))
		if string(name) != user || string(given) != password {
			_, _ = c.Write([]byte{1, 1})
			return "", nil, false
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return "", nil, false
		}
	}
	request := read(4)
	if request == nil || request[1] != 1 {
		return "", nil, false
	}
	var host string
	switch request[3] {
	case 1:
		host = net.IP(read(4)).String()
	case 3:
		host = string(read(int(read(1)[0])))
	default:
		return "", nil, false
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(read(2))))
	return net.JoinHostPort(host, port), []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}, true
}

// connectProxy is an HTTP proxy that opens every tunnel asked of it.
func connectProxy(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(stdhttp.StatusBadGateway)
			return
		}
		defer upstream.Close()
		w.WriteHeader(stdhttp.StatusOK)
		conn, rw, err := w.(stdhttp.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = rw.Flush()
		go func() { _, _ = io.Copy(upstream, conn) }()
		_, _ = io.Copy(conn, upstream)
	}))
	t.Cleanup(server.Close)
	return server
}

// wrappedThrough is a client whose connections go through proxyURL, each to
// the proxy through h, and whose dials go through dialer.
func wrappedThrough(t *testing.T, proxyURL string, h *holder, dialer net.Dialer) HttpClient {
	t.Helper()
	client, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_133), WithInsecureSkipVerify(),
		WithProxyUrl(proxyURL), WithTimeoutSeconds(10), WithoutRequestTimeout(), WithProxyConnWrapper(h.wrap),
		WithDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

// slowDial is a dialer whose every dial waits a while before it connects.
func slowDial(wait time.Duration) net.Dialer {
	return net.Dialer{Control: func(string, string, syscall.RawConn) error {
		time.Sleep(wait)
		return nil
	}}
}

// helloAfter says whether what a client sent, past its first skip bytes,
// begins with a TLS handshake record.
func helloAfter(sent []byte, skip int) bool {
	return len(sent) > skip+5 && sent[skip] == 22 && sent[skip+1] == 3
}

func TestEveryConnectionToAProxyGoesThroughTheWrapper(t *testing.T) {
	site := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = io.WriteString(w, "through")
	}))
	site.EnableHTTP2 = true
	site.StartTLS()
	defer site.Close()
	_, port, _ := net.SplitHostPort(site.Listener.Addr().String())
	// What each client says before its ClientHello: the handshake with the
	// proxy, up to the address it asks for, which SOCKS4a and SOCKS5 send as
	// the name the URL has and SOCKS4 as an address it looked up.
	at := binary.BigEndian.AppendUint16(nil, uint16(atoiOf(t, port)))
	begins := func(asked ...[]byte) func([]byte) int {
		whole := slices.Concat(asked...)
		return func(sent []byte) int {
			if !bytes.HasPrefix(sent, whole) {
				return -1
			}
			return len(whole)
		}
	}
	socks5 := []byte{5, 1, 0, 3, byte(len("localhost"))}
	for _, tc := range []struct {
		name, scheme, user, password string
		// handshake is how long the client's side of the handshake with the
		// proxy is, or -1 when it is not what it should be.
		handshake func(sent []byte) int
	}{
		{"socks5", "socks5", "", "", begins([]byte{5, 1, 0}, socks5, []byte("localhost"), at)},
		{"socks5 with a password", "socks5", "alice", "s3cr3t", begins([]byte{5, 2, 0, 2, 1, 5}, []byte("alice"),
			[]byte{6}, []byte("s3cr3t"), socks5, []byte("localhost"), at)},
		{"socks5h", "socks5h", "", "", begins([]byte{5, 1, 0}, socks5, []byte("localhost"), at)},
		{"socks4", "socks4", "", "", begins([]byte{4, 1}, at, []byte{127, 0, 0, 1}, []byte("nobody@0.0.0.0\x00"))},
		{"socks4a", "socks4a", "", "", begins([]byte{4, 1}, at, []byte{0, 0, 0, 1},
			[]byte("nobody@0.0.0.0\x00localhost\x00"))},
		{"http", "http", "", "", func(sent []byte) int {
			end := bytes.Index(sent, []byte("\r\n\r\n"))
			if !bytes.HasPrefix(sent, []byte("CONNECT localhost:"+port+" HTTP/1.1\r\n")) || end < 0 {
				return -1
			}
			return end + 4
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addr string
			if tc.scheme == "http" {
				addr = connectProxy(t).Listener.Addr().String()
			} else {
				addr = socksProxy(t, tc.user, tc.password)
			}
			proxyURL := tc.scheme + "://" + addr
			if tc.user != "" {
				proxyURL = tc.scheme + "://" + tc.user + ":" + tc.password + "@" + addr
			}
			h := &holder{}
			// Every dial waits, so that when it began says so.
			client := wrappedThrough(t, proxyURL, h, slowDial(50*time.Millisecond))
			ctx := context.WithValue(context.Background(), requestKey{}, tc.name)
			before := time.Now()
			if err := endsWithin(t, getting(client, "https://localhost:"+port+"/", ctx), 10*time.Second); err != nil {
				t.Fatalf("Get: %v", err)
			}
			conns, of := h.held()
			if len(conns) != 1 || of[0] != tc.name {
				t.Fatalf("handed %d connections, for %v", len(conns), of)
			}
			conn := conns[0]
			if conn.RemoteAddr().String() != addr || conn.began.Before(before) ||
				conn.handed.Sub(conn.began) < 50*time.Millisecond {
				t.Errorf("handed one to %s, dialed from %v, handed %v later", conn.RemoteAddr(),
					conn.began.Sub(before), conn.handed.Sub(conn.began))
			}
			// The handshake with the proxy went over it, and then the site's.
			sent, received, _ := conn.what()
			if skip := tc.handshake(sent); skip < 0 || !helloAfter(sent, skip) || len(received) == 0 {
				t.Errorf("sent %q…, received %d bytes", sent[:min(len(sent), 60)], len(received))
			}
			// Another request goes out on the same connection: handed none.
			if err := endsWithin(t, getting(client, "https://localhost:"+port+"/", ctx), 10*time.Second); err != nil {
				t.Fatalf("Get again: %v", err)
			}
			if conns, _ := h.held(); len(conns) != 1 {
				t.Errorf("handed %d connections for two requests on one", len(conns))
			}
		})
	}
}

func atoiOf(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTheConnectionToAnHTTPSProxyGoesThroughTheWrapperUnderItsTLS(t *testing.T) {
	// The proxy's certificate is no system's, and its handshake fails: the
	// wrapper was handed the TCP connection the ClientHello went over, which
	// the failed handshake closed.
	proxyServer := httptest.NewTLSServer(stdhttp.NotFoundHandler())
	defer proxyServer.Close()
	h := &holder{}
	client := wrappedThrough(t, proxyServer.URL, h, net.Dialer{})
	ctx := context.WithValue(context.Background(), requestKey{}, "https")
	if err := endsWithin(t, getting(client, "https://127.0.0.1:9/", ctx), 10*time.Second); err == nil {
		t.Fatal("went through a proxy whose certificate is no one's")
	}
	conns, of := h.held()
	if len(conns) != 1 || of[0] != "https" {
		t.Fatalf("handed %d connections, for %v", len(conns), of)
	}
	sent, _, closed := conns[0].what()
	if conns[0].RemoteAddr().String() != proxyServer.Listener.Addr().String() || !helloAfter(sent, 0) || !closed {
		t.Errorf("handed one to %s that sent %q… and was closed: %v", conns[0].RemoteAddr(), sent[:min(len(sent), 8)], closed)
	}
}

func TestADialToAProxyThatFailsHandsTheWrapperNothing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	for _, scheme := range []string{"socks5", "socks4", "http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			h := &holder{}
			client := wrappedThrough(t, scheme+"://"+addr, h, net.Dialer{})
			if err := endsWithin(t, getting(client, "https://127.0.0.1:9/", context.Background()), 10*time.Second); err == nil {
				t.Fatal("went through a proxy nothing answers at")
			}
			if conns, _ := h.held(); len(conns) != 0 {
				t.Errorf("handed %d connections", len(conns))
			}
		})
	}
}

func TestASOCKS4DialThatConnectsAfterItsRequestGaveUpHandsTheWrapperNothing(t *testing.T) {
	// The dial waits longer than the request does, and connects after it
	// ended: that connection is no request's, and is closed.
	site := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
	site.EnableHTTP2 = true
	site.StartTLS()
	defer site.Close()
	addr, granted := socks4Proxy(t, 0)
	h := &holder{}
	client := wrappedThrough(t, "socks4://"+addr, h, slowDial(300*time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := endsWithin(t, getting(client, site.URL, ctx), 3*time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Get: %v, want its deadline", err)
	}
	select {
	case c := <-granted:
		if !letGo(c) {
			t.Error("the connection made too late was kept")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the proxy never granted it")
	}
	if conns, _ := h.held(); len(conns) != 0 {
		t.Errorf("handed %d connections", len(conns))
	}
}

func TestADialWithinAContextThatEndedHandsTheWrapperNothing(t *testing.T) {
	// Its request gave up before it dialed: the dial to the proxy ends within
	// that context, but SOCKS4's, which takes none, and whose connection is
	// closed, the wrapper never handed it.
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	silent, _ := silentProxy(t)
	socks4, granted := socks4Proxy(t, 0)
	for _, tc := range []struct{ scheme, addr string }{
		{"socks5", silent}, {"socks4", socks4}, {"http", silent}, {"https", silent},
	} {
		t.Run(tc.scheme, func(t *testing.T) {
			h := &holder{}
			dialer, err := newConnectDialer(tc.scheme+"://"+tc.addr, 5*time.Second, nil, net.Dialer{}, nil, h.wrap,
				NewNoopLogger())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := dialer.DialContext(ended, "tcp", silent); !errors.Is(err, context.Canceled) {
				t.Errorf("DialContext: %v, want its context's end", err)
			}
			if tc.scheme == "socks4" {
				select {
				case c := <-granted:
					if !letGo(c) {
						t.Error("the connection made after its request gave up was kept")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("the proxy never granted it")
				}
			}
			if conns, _ := h.held(); len(conns) != 0 {
				t.Errorf("handed %d connections", len(conns))
			}
		})
	}
}

func TestAProxySetLaterGoesThroughTheWrapperToo(t *testing.T) {
	site := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
	site.EnableHTTP2 = true
	site.StartTLS()
	defer site.Close()
	first, second := socksProxy(t, "", ""), socksProxy(t, "", "")
	h := &holder{}
	client := wrappedThrough(t, "socks5://"+first, h, net.Dialer{})
	if err := client.SetProxy("socks5://" + second); err != nil {
		t.Fatal(err)
	}
	if err := endsWithin(t, getting(client, site.URL, context.Background()), 10*time.Second); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if conns, _ := h.held(); len(conns) != 1 || conns[0].RemoteAddr().String() != second {
		t.Errorf("handed %d connections, the first to %v", len(conns), conns)
	}
}

func TestADialerForSOCKS5DialsWithoutAContextAsWithOne(t *testing.T) {
	// x/net's SOCKS5 dialer dials by DialContext; Dial is the same, within
	// no context.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h := &holder{}
	conn, err := (&wrappingDialer{wrap: h.wrap}).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conns, of := h.held(); len(conns) != 1 || conns[0] != conn || of[0] != nil {
		t.Errorf("handed %d connections, for %v", len(conns), of)
	}
}
