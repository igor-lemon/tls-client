package tls_client

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	stdhttp "net/http"
	"sync"
	"sync/atomic"
	"testing"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/tls-client/profiles"
)

// alpnServer serves over TLS at 127.0.0.1 what protocols says for each
// handshake, numbered from 1, one request a connection, and is its URL and
// how many handshakes it made.
func alpnServer(t *testing.T, protocols func(n int32) []string) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := coalescingCert(t, "a.test")
	handshakes := new(atomic.Int32)
	srv := &stdhttp.Server{
		Handler: stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}),
		TLSConfig: &stdtls.Config{Certificates: []stdtls.Certificate{cert},
			GetConfigForClient: func(*stdtls.ClientHelloInfo) (*stdtls.Config, error) {
				return &stdtls.Config{Certificates: []stdtls.Certificate{cert},
					NextProtos: protocols(handshakes.Add(1))}, nil
			}},
	}
	// Every answer ends its connection: each request dials one.
	srv.SetKeepAlivesEnabled(false)
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String(), handshakes
}

func h2Only(int32) []string { return []string{http2.NextProtoTLS} }

func cacheClient(t *testing.T) (HttpClient, *roundTripper) {
	t.Helper()
	client, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_133), WithInsecureSkipVerify(),
		WithTimeoutSeconds(30))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client, roundTripperOf(client)
}

func get(client HttpClient, url string) error {
	return <-getting(client, url, context.Background())
}

// cachedFor is the transport rt has cached for addr, or nil.
func cachedFor(rt *roundTripper, addr string) http.RoundTripper {
	rt.cachedTransportsLck.Lock()
	defer rt.cachedTransportsLck.Unlock()
	return rt.cachedTransports[addr]
}

// consistent fails the test unless every transport rt has cached has the
// kind it speaks cached with it, and every kind its transport.
func consistent(t *testing.T, rt *roundTripper) {
	t.Helper()
	rt.cachedTransportsLck.Lock()
	defer rt.cachedTransportsLck.Unlock()
	rt.cachedKindsLck.Lock()
	defer rt.cachedKindsLck.Unlock()
	for addr, transport := range rt.cachedTransports {
		kind, ok := rt.cachedKinds[addr]
		want := transportHTTP1
		if _, h2 := transport.(*http2.Transport); h2 {
			want = transportHTTP2
		}
		if !ok || kind != want {
			t.Errorf("%s: a %T, its kind %v (%v), want %v", addr, transport, kind, ok, want)
		}
	}
	for addr := range rt.cachedKinds {
		if _, ok := rt.cachedTransports[addr]; !ok {
			t.Errorf("%s: a kind and no transport", addr)
		}
	}
}

// seam sets one of the seams to f for the test.
func seam(t *testing.T, s *func(string), f func(string)) {
	t.Helper()
	before := *s
	*s = f
	t.Cleanup(func() { *s = before })
}

func TestAConnectionDialedForATransportDroppedMeanwhileBuildsNoOther(t *testing.T) {
	// A transport is dropped while one of its connections shakes hands: the
	// connection is no other transport's to build, and the request goes on a
	// transport set up for the address.
	for _, protocol := range []string{http2.NextProtoTLS, "http/1.1"} {
		t.Run(protocol, func(t *testing.T) { droppedWhileItDials(t, protocol) })
	}
}

func droppedWhileItDials(t *testing.T, protocol string) {
	url, handshakes := alpnServer(t, func(int32) []string { return []string{protocol} })
	client, rt := cacheClient(t)
	addr := url[len("https://"):]
	if err := get(client, url); err != nil {
		t.Fatalf("Get: %v", err)
	}
	first := cachedFor(rt, addr)
	client.CloseIdleConnections()
	var once sync.Once
	seam(t, &reconnected, func(a string) {
		if a == addr {
			once.Do(func() { rt.dropCachedTransport(a, first) })
		}
	})
	if err := get(client, url); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if now := cachedFor(rt, addr); now == nil || now == first {
		t.Errorf("cached for the address: %v (the first %v)", now, first)
	}
	consistent(t, rt)
	// The first's connection, the one dropped with its transport, and the
	// one set up for the request.
	if n := handshakes.Load(); n != 3 {
		t.Errorf("%d handshakes, want 3", n)
	}
}

func TestDroppingATransportLeavesTheKindOfOneCachedSince(t *testing.T) {
	url, _ := alpnServer(t, h2Only)
	client, rt := cacheClient(t)
	addr := url[len("https://"):]
	if err := get(client, url); err != nil {
		t.Fatalf("Get: %v", err)
	}
	first := cachedFor(rt, addr)
	// Another request sets the address up anew once the first is gone,
	// before the drop is done.
	var once sync.Once
	seam(t, &dropping, func(a string) {
		if a == addr {
			once.Do(func() {
				if err := get(client, url); err != nil {
					t.Errorf("Get: %v", err)
				}
			})
		}
	})
	rt.dropCachedTransport(addr, first)
	again := cachedFor(rt, addr)
	if again == nil || again == first {
		t.Fatalf("cached for the address: %v (the first %v)", again, first)
	}
	consistent(t, rt)
	// Its next connection is taken as its own.
	client.CloseIdleConnections()
	if err := get(client, url); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if now := cachedFor(rt, addr); now != again {
		t.Errorf("cached for the address: %v, want %v", now, again)
	}
	consistent(t, rt)
}

func TestDroppingATransportReplacedAlreadyLeavesItsReplacement(t *testing.T) {
	url, _ := alpnServer(t, h2Only)
	client, rt := cacheClient(t)
	addr := url[len("https://"):]
	if err := get(client, url); err != nil {
		t.Fatalf("Get: %v", err)
	}
	first := cachedFor(rt, addr)
	rt.dropCachedTransport(addr, first)
	consistent(t, rt)
	if err := get(client, url); err != nil {
		t.Fatalf("Get: %v", err)
	}
	again := cachedFor(rt, addr)
	// The first, dropped again late: the second and its kind stay.
	rt.dropCachedTransport(addr, first)
	if now := cachedFor(rt, addr); now != again {
		t.Errorf("cached: %v, want %v", now, again)
	}
	consistent(t, rt)
	if _, ok := rt.cachedKind(addr); !ok {
		t.Error("its kind was dropped")
	}
}

func TestRequestsGoThroughAServerThatChangesItsProtocolOnEveryConnection(t *testing.T) {
	// Bounded: many requests at once, each wanting a connection of its own
	// over HTTP/1.1, to a server that says http/1.1 and h2 by turns.
	url, _ := alpnServer(t, func(n int32) []string {
		if n%2 == 1 {
			return []string{"http/1.1"}
		}
		return []string{http2.NextProtoTLS}
	})
	client, rt := cacheClient(t)
	const goroutines, requests = 16, 8
	var answered, changed atomic.Int32
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range requests {
				switch err := get(client, url); {
				case err == nil:
					answered.Add(1)
				case errors.Is(err, errProtocolChanged):
					changed.Add(1)
				default:
					t.Errorf("Get: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	t.Logf("%d answered, %d met a protocol changed once too often", answered.Load(), changed.Load())
	if answered.Load() == 0 {
		t.Error("none answered")
	}
	consistent(t, rt)
}

func TestARequestGoesAgainOnATransportSetUpForWhatTheServerSpeaksNow(t *testing.T) {
	// HTTP/2 first, HTTP/1.1 since: the request after the change goes out on
	// a transport set up for it, and the transport after it stays.
	url, handshakes := alpnServer(t, func(n int32) []string {
		if n == 1 {
			return []string{http2.NextProtoTLS}
		}
		return []string{"http/1.1"}
	})
	client, rt := cacheClient(t)
	addr := url[len("https://"):]
	for i := range 3 {
		if err := get(client, url); err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		consistent(t, rt)
	}
	if _, h1 := cachedFor(rt, addr).(*http.Transport); !h1 {
		t.Errorf("cached: %T", cachedFor(rt, addr))
	}
	// The first; the one that found HTTP/1.1, let go of; the setup's, which
	// the second request took; the third's.
	if n := handshakes.Load(); n != 4 {
		t.Errorf("%d handshakes, want 4", n)
	}
}

// changing is a transport whose every connection speaks another protocol,
// and that is cached again as soon as it is dropped, as another request's
// setup would cache one: the request goes again until it has gone again
// protocolChanges times.
type changing struct{ sent atomic.Int32 }

func (c *changing) RoundTrip(*http.Request) (*http.Response, error) {
	c.sent.Add(1)
	return nil, errProtocolChanged
}

func TestARequestGoesAgainAFewTimesAtMost(t *testing.T) {
	_, rt := cacheClient(t)
	const addr = "example.test:443"
	c := &changing{}
	cache := func() {
		rt.cachedTransportsLck.Lock()
		rt.cachedTransports[addr] = c
		rt.setCachedKind(addr, transportHTTP1)
		rt.cachedTransportsLck.Unlock()
	}
	cache()
	seam(t, &dropping, func(a string) {
		if a == addr {
			cache()
		}
	})
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); !errors.Is(err, errProtocolChanged) {
		t.Errorf("RoundTrip: %v", err)
	}
	// Once, and again three times.
	if n := c.sent.Load(); n != 4 {
		t.Errorf("sent %d times, want 4", n)
	}
}

// failing is a transport whose every request fails, as err says.
type failing struct {
	err  error
	sent atomic.Int32
}

func (f *failing) RoundTrip(*http.Request) (*http.Response, error) {
	f.sent.Add(1)
	return nil, f.err
}

func TestARequestThatFailsOtherwiseGoesOnce(t *testing.T) {
	_, rt := cacheClient(t)
	const addr = "example.test:443"
	refused := errors.New("refused")
	f := &failing{err: refused}
	rt.cachedTransportsLck.Lock()
	rt.cachedTransports[addr] = f
	rt.setCachedKind(addr, transportHTTP1)
	rt.cachedTransportsLck.Unlock()
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); !errors.Is(err, refused) {
		t.Errorf("RoundTrip: %v", err)
	}
	if n := f.sent.Load(); n != 1 {
		t.Errorf("sent %d times", n)
	}
	// And the transport stays, its kind with it.
	if cachedFor(rt, addr) != f {
		t.Error("dropped")
	}
	consistent(t, rt)
}

func TestASetupBuildsWhatItNegotiatedWhateverKindIsLeft(t *testing.T) {
	// Upstream's ab95f96: a kind left without its transport, as a drop that
	// had not finished once left one. getTransport, as the protocol racer
	// calls it with the lock held, builds and caches what it negotiated, and
	// does not hand the connection back as if a transport had it.
	url, _ := alpnServer(t, h2Only)
	_, rt := cacheClient(t)
	addr := url[len("https://"):]
	rt.setCachedKind(addr, transportHTTP1)
	req, err := http.NewRequest(http.MethodGet, url+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.cachedTransportsLck.Lock()
	err = rt.getTransport(req, addr)
	_, h2 := rt.cachedTransports[addr].(*http2.Transport)
	rt.cachedTransportsLck.Unlock()
	if err != nil || !h2 {
		t.Fatalf("getTransport: %v, cached an HTTP/2 transport: %v", err, h2)
	}
	consistent(t, rt)
}
