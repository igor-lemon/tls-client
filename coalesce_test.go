package tls_client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	stdhttp "net/http"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"github.com/tam7t/hpkp"
	xhttp2 "golang.org/x/net/http2"
	xhpack "golang.org/x/net/http2/hpack"
)

// coalescingCert is a certificate for names, signed by itself.
func coalescingCert(t *testing.T, names ...string) stdtls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// coalescing are the certificates every server of these tests shows: wide
// for a.test, b.test and every name under wild.test and pinned.test, narrow
// for c.test alone; and the roots that take both. Served are the requests its
// servers answered, by host and path.
type coalescing struct {
	wide, narrow stdtls.Certificate
	roots        *x509.CertPool
	mu           sync.Mutex
	served       []string
}

func newCoalescing(t *testing.T) *coalescing {
	c := &coalescing{wide: coalescingCert(t, "a.test", "b.test", "*.wild.test", "*.pinned.test"),
		narrow: coalescingCert(t, "c.test"), roots: x509.NewCertPool()}
	c.roots.AddCert(c.wide.Leaf)
	c.roots.AddCert(c.narrow.Leaf)
	return c
}

// serve serves at 127.0.0.1, over TLS, HTTP/2 when h2 says so and HTTP/1.1
// alone otherwise, answering each request with the address it came from;
// it shows the narrow certificate to c.test and the wide one to every other
// name. It is the port it serves on.
func (c *coalescing) serve(t *testing.T, h2 bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &stdtls.Config{NextProtos: []string{"http/1.1"}, GetCertificate: c.certificate}
	srv := &stdhttp.Server{Handler: stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		c.mu.Lock()
		c.served = append(c.served, r.Host+r.URL.Path)
		c.mu.Unlock()
		_, _ = io.WriteString(w, r.RemoteAddr)
	}), TLSConfig: cfg}
	if h2 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	} else {
		srv.TLSNextProto = map[string]func(*stdhttp.Server, *stdtls.Conn, stdhttp.Handler){}
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func (c *coalescing) certificate(hello *stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
	if hello.ServerName == "c.test" {
		return &c.narrow, nil
	}
	return &c.wide, nil
}

// lookups keeps the hosts it was asked to find, and finds each at 127.0.0.1,
// or where at says, or fails where at says nothing.
type lookups struct {
	mu    sync.Mutex
	asked []string
	at    map[string]string
}

func (l *lookups) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asked = append(l.asked, host)
	ip, ok := l.at[host]
	if !ok {
		ip = "127.0.0.1"
	}
	if ip == "" {
		return nil, errors.New("no such host")
	}
	return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr(ip)}, nil
}

func (l *lookups) hosts() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.asked)
}

// client is a client that takes the servers' certificates on trust and dials
// 127.0.0.1 on the port of whatever host:port it dials, coalescing
// connections with l, and with the options given after its own.
func (c *coalescing) client(t *testing.T, l *lookups, opts ...HttpClientOption) HttpClient {
	t.Helper()
	client, err := NewHttpClient(NewNoopLogger(), append([]HttpClientOption{
		WithClientProfile(profiles.Chrome_133),
		WithTransportOptions(&TransportOptions{RootCAs: c.roots}),
		WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		}),
		WithConnectionCoalescing(l.lookup),
	}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

// from is the address a GET of url came from, as its answer says, or why
// there is none.
func from(client HttpClient, url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	return string(body), err
}

func mustFrom(t *testing.T, client HttpClient, url string) string {
	t.Helper()
	got, err := from(client, url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return got
}

func TestARequestGoesOutOnAConnectionToAnotherHostThatFitsIt(t *testing.T) {
	c := newCoalescing(t)
	port := c.serve(t, true)
	// m.wild.test is found at 127.0.0.1 written as IPv6.
	l := lookups{at: map[string]string{"m.wild.test": "::ffff:127.0.0.1"}}
	client := c.client(t, &l)
	at := func(host string) string { return "https://" + host + ":" + port + "/" }

	a := mustFrom(t, client, at("a.test"))
	b, w := mustFrom(t, client, at("b.test")), mustFrom(t, client, at("x.wild.test"))
	again := mustFrom(t, client, at("b.test"))
	// c.test's certificate is not the connection's: one of its own, which
	// takes nothing from a.test's.
	own := mustFrom(t, client, at("c.test"))
	later, mapped := mustFrom(t, client, at("y.wild.test")), mustFrom(t, client, at("m.wild.test"))
	if b != a || w != a || again != a || own == a || later != a || mapped != a {
		t.Errorf("a.test from %s, b.test from %s and %s, x.wild.test from %s, c.test from %s, y.wild.test from %s, "+
			"m.wild.test from %s", a, b, again, w, own, later, mapped)
	}
	// Looked up when a connection could carry it: not a.test, with none to
	// share, nor c.test, with none whose certificate is good for it, nor
	// b.test again, which had one.
	if got := l.hosts(); !slices.Equal(got, []string{"b.test", "x.wild.test", "y.wild.test", "m.wild.test"}) {
		t.Errorf("looked up %q", got)
	}
	// Each sent once, and no connection left waiting to be taken up.
	c.mu.Lock()
	served := slices.Clone(c.served)
	c.mu.Unlock()
	if len(served) != 7 {
		t.Errorf("served %q", served)
	}
	rt := client.(*httpClient).Transport.(*roundTripper)
	rt.stashed.Range(func(addr, _ any) bool {
		t.Errorf("%s waits to be taken up", addr)
		return true
	})
}

func TestAConnectionIsSharedOnlyWithAHostFoundAtItsAddress(t *testing.T) {
	c := newCoalescing(t)
	port := c.serve(t, true)
	l := lookups{at: map[string]string{"b.test": "192.0.2.1", "x.wild.test": ""}}
	client := c.client(t, &l)
	at := func(host string) string { return "https://" + host + ":" + port + "/" }

	a := mustFrom(t, client, at("a.test"))
	elsewhere, unknown := mustFrom(t, client, at("b.test")), mustFrom(t, client, at("x.wild.test"))
	if elsewhere == a || unknown == a || elsewhere == unknown {
		t.Errorf("a.test from %s, b.test from %s, x.wild.test from %s", a, elsewhere, unknown)
	}
	// Each once: dialed, the request goes out on the connection it dialed.
	if got := l.hosts(); !slices.Equal(got, []string{"b.test", "x.wild.test"}) {
		t.Errorf("looked up %q", got)
	}
}

func TestAConnectionIsSharedOnlyWithAHostOnItsPort(t *testing.T) {
	c := newCoalescing(t)
	first, second := c.serve(t, true), c.serve(t, true)
	var l lookups
	client := c.client(t, &l)
	a := mustFrom(t, client, "https://a.test:"+first+"/")
	b := mustFrom(t, client, "https://b.test:"+second+"/")
	if b == a || len(l.hosts()) != 0 {
		t.Errorf("a.test from %s, b.test from %s, looked up %q", a, b, l.hosts())
	}
}

func TestAConnectionWhoseCertificateWasNotVerifiedIsSharedWithNone(t *testing.T) {
	c := newCoalescing(t)
	port := c.serve(t, true)
	var l lookups
	client := c.client(t, &l, WithInsecureSkipVerify())
	a := mustFrom(t, client, "https://a.test:"+port+"/")
	b := mustFrom(t, client, "https://b.test:"+port+"/")
	if b == a || len(l.hosts()) != 0 {
		t.Errorf("a.test from %s, b.test from %s, looked up %q", a, b, l.hosts())
	}
}

func TestAnHTTP1ConnectionIsSharedWithNone(t *testing.T) {
	c := newCoalescing(t)
	port := c.serve(t, false)
	var l lookups
	client := c.client(t, &l)
	a := mustFrom(t, client, "https://a.test:"+port+"/")
	b := mustFrom(t, client, "https://b.test:"+port+"/")
	if b == a || len(l.hosts()) != 0 {
		t.Errorf("a.test from %s, b.test from %s, looked up %q", a, b, l.hosts())
	}
}

func TestTheHostsPinsHoldOnAConnectionShared(t *testing.T) {
	c := newCoalescing(t)
	port := c.serve(t, true)
	var l lookups
	pin := hpkp.Fingerprint(c.wide.Leaf)
	client := c.client(t, &l, WithCertificatePinning(map[string][]string{
		"held.pinned.test":   {pin},
		"broken.pinned.test": {"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}, nil))
	at := func(host string) string { return "https://" + host + ":" + port + "/" }
	a := mustFrom(t, client, at("a.test"))
	if held := mustFrom(t, client, at("held.pinned.test")); held != a {
		t.Errorf("a.test from %s, held.pinned.test from %s", a, held)
	}
	// Not shared, and dialed, the pins break the handshake.
	if got, err := from(client, at("broken.pinned.test")); !errors.Is(err, ErrBadPinDetected) {
		t.Errorf("broken.pinned.test: %q, %v", got, err)
	}
	if got := l.hosts(); !slices.Equal(got, []string{"held.pinned.test"}) {
		t.Errorf("looked up %q", got)
	}
}

func TestAHostWithAnHTTP1TransportIsOfferedNoHTTP2Connection(t *testing.T) {
	c := newCoalescing(t)
	port := c.awayThenHTTP1(t)
	var l lookups
	client := c.client(t, &l)
	if got, err := from(client, "https://b.test:"+port+"/"); err != nil || got != "h1" {
		t.Fatalf("b.test: %q, %v", got, err)
	}
	if _, err := from(client, "https://a.test:"+port+"/"); err != nil {
		t.Fatalf("a.test: %v", err)
	}
	if got, err := from(client, "https://b.test:"+port+"/"); err != nil || got != "h1" || len(l.hosts()) != 0 {
		t.Errorf("b.test again: %q, %v, looked up %q", got, err, l.hosts())
	}
}

func TestAPlainHTTPRequestIsOfferedNoHTTP2Connection(t *testing.T) {
	c := newCoalescing(t)
	port := c.serve(t, true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	plain := &stdhttp.Server{Handler: stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = io.WriteString(w, "plain")
	})}
	go func() { _ = plain.Serve(ln) }()
	t.Cleanup(func() { _ = plain.Close() })
	_, plainPort, _ := net.SplitHostPort(ln.Addr().String())
	var l lookups
	client := c.client(t, &l)
	mustFrom(t, client, "https://a.test:"+port+"/")
	if got, err := from(client, "http://a.test:"+plainPort+"/"); err != nil || got != "plain" || len(l.hosts()) != 0 {
		t.Errorf("http://a.test: %q, %v, looked up %q", got, err, l.hosts())
	}
}

func TestAProxySetAnewKeepsConnectionsShared(t *testing.T) {
	c := newCoalescing(t)
	port := c.serve(t, true)
	var l lookups
	client := c.client(t, &l)
	if err := client.SetProxy(""); err != nil {
		t.Fatal(err)
	}
	a := mustFrom(t, client, "https://a.test:"+port+"/")
	if b := mustFrom(t, client, "https://b.test:"+port+"/"); b != a {
		t.Errorf("a.test from %s, b.test from %s", a, b)
	}
}

func TestAHostIsAdoptedByTheSharedTransportUnlessItHasItsOwn(t *testing.T) {
	transport, err := newRoundTripper(profiles.Chrome_133, nil, "", false, false, false, false,
		false, false, nil, nil, false, false, nil, "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	rt := transport.(*roundTripper)
	rt.shared = &http2.Transport{}
	own := &http.Transport{}
	rt.cachedTransports["own.test:443"] = own
	rt.adopt("own.test:443")
	rt.adopt("new.test:443")
	if _, set := rt.cachedKind("own.test:443"); set || rt.cachedTransports["own.test:443"] != own {
		t.Errorf("own.test has %v, of kind set %v", rt.cachedTransports["own.test:443"], set)
	}
	if kind, _ := rt.cachedKind("new.test:443"); kind != transportHTTP2 || rt.cachedTransports["new.test:443"] != rt.shared {
		t.Errorf("new.test has %v, of kind %v", rt.cachedTransports["new.test:443"], kind)
	}
}

func TestConnectionsAreSharedOnlyWhenTheyMayBe(t *testing.T) {
	lookup := func(context.Context, string) ([]netip.Addr, error) { return nil, nil }
	for _, tc := range []struct {
		name     string
		options  *TransportOptions
		proxy    string
		server   string
		racing   bool
		coalesce bool
	}{
		{name: "direct", coalesce: true},
		{name: "with transport options", options: &TransportOptions{}, coalesce: true},
		{name: "through a proxy", proxy: "http://127.0.0.1:1"},
		{name: "a server name overwritten", server: "example.com"},
		{name: "client certificates", options: &TransportOptions{Certificates: []tls.Certificate{{}}}},
		{name: "protocol racing", racing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport, err := newRoundTripper(profiles.Chrome_133, tc.options, tc.server, false, false, false, false,
				false, tc.racing, nil, nil, false, false, nil, tc.proxy, &net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			rt := transport.(*roundTripper)
			rt.coalesceWith(lookup)
			if got := rt.lookup != nil; got != tc.coalesce {
				t.Errorf("coalesces: %v", got)
			}
		})
	}
}

func TestAHostDroppedFromTheSharedTransportLeavesTheOthersConnections(t *testing.T) {
	c := newCoalescing(t)
	port := c.serve(t, true)
	var l lookups
	client := c.client(t, &l)
	a := mustFrom(t, client, "https://a.test:"+port+"/")
	mustFrom(t, client, "https://b.test:"+port+"/")
	rt := client.(*httpClient).Transport.(*roundTripper)
	rt.dropCachedTransport("b.test:"+port, rt.shared)
	if again := mustFrom(t, client, "https://a.test:"+port+"/"); again != a {
		t.Errorf("a.test from %s, then from %s", a, again)
	}
	// The last host it serves dropped, its idle connections close.
	rt.dropCachedTransport("a.test:"+port, rt.shared)
	if again := mustFrom(t, client, "https://a.test:"+port+"/"); again == a {
		t.Errorf("a.test from %s, then from %s", a, again)
	}
}

// awayThenHTTP1 serves at 127.0.0.1 over TLS: HTTP/2 to a.test, which answers
// its first request and leaves a later one unprocessed with a GOAWAY, and
// HTTP/1.1 alone to every other name, answering 200. It is the port.
func (c *coalescing) awayThenHTTP1(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var accepted []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range accepted {
			_ = conn.Close()
		}
	})
	cfg := &stdtls.Config{GetCertificate: c.certificate, GetConfigForClient: func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
		protos := []string{"http/1.1"}
		if hello.ServerName == "a.test" {
			protos = []string{"h2"}
		}
		return &stdtls.Config{GetCertificate: c.certificate, NextProtos: protos}, nil
	}}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, raw)
			mu.Unlock()
			go func() {
				conn := stdtls.Server(raw, cfg)
				defer conn.Close()
				if conn.Handshake() != nil {
					return
				}
				if conn.ConnectionState().NegotiatedProtocol != "h2" {
					_, _ = conn.Read(make([]byte, 4096))
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
					_, _ = conn.Read(make([]byte, 4096))
					return
				}
				if _, err := io.ReadFull(conn, make([]byte, len(xhttp2.ClientPreface))); err != nil {
					return
				}
				fr := xhttp2.NewFramer(conn, conn)
				_ = fr.WriteSettings()
				var ok bytes.Buffer
				_ = xhpack.NewEncoder(&ok).WriteField(xhpack.HeaderField{Name: ":status", Value: "200"})
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					switch f := f.(type) {
					case *xhttp2.SettingsFrame:
						if !f.IsAck() {
							_ = fr.WriteSettingsAck()
						}
					case *xhttp2.HeadersFrame:
						if f.StreamID > 1 {
							_ = fr.WriteGoAway(1, xhttp2.ErrCodeNo, nil)
							continue
						}
						_ = fr.WriteHeaders(xhttp2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: ok.Bytes(),
							EndStream: true, EndHeaders: true})
					}
				}
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func TestAShareTriedAgainOnAnHTTP1ConnectionOfItsOwnGoesOverHTTP1(t *testing.T) {
	// b.test goes out on a.test's connection, which leaves it unprocessed;
	// tried again, it dials, and its server speaks HTTP/1.1: the shared
	// transport is dropped for it, and the request goes again over HTTP/1.1,
	// as any does whose host changed protocol, and so does the next.
	c := newCoalescing(t)
	port := c.awayThenHTTP1(t)
	var l lookups
	client := c.client(t, &l)
	if _, err := from(client, "https://a.test:"+port+"/"); err != nil {
		t.Fatalf("a.test: %v", err)
	}
	for _, which := range []string{"b.test", "b.test again"} {
		if got, err := from(client, "https://b.test:"+port+"/"); err != nil || got != "h1" {
			t.Errorf("%s: %q, %v", which, got, err)
		}
	}
}
