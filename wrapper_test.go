package tls_client

import (
	"context"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	tls "github.com/bogdanfinn/utls"
	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/tls-client/profiles"
)

// wrapper is what a client's round tripper is wrapped in: it keeps the round
// trippers it was handed, and the path of every request it sends on them. It
// has no CloseIdleConnections of its own.
type wrapper struct {
	mu     sync.Mutex
	handed []http.RoundTripper
	paths  []string
}

func (w *wrapper) wrap(rt http.RoundTripper) http.RoundTripper {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.handed = append(w.handed, rt)
	return wrapped{w, rt}
}

func (w *wrapper) sent() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.paths)
}

type wrapped struct {
	w  *wrapper
	rt http.RoundTripper
}

func (r wrapped) RoundTrip(req *http.Request) (*http.Response, error) {
	r.w.mu.Lock()
	r.w.paths = append(r.w.paths, req.URL.Path)
	r.w.mu.Unlock()
	return r.rt.RoundTrip(req)
}

// wrapping is a server over TLS and HTTP/2 that sends /from to /to and answers
// any other path with the address the request came from, and a client of it,
// whose round tripper w wraps.
func wrapping(t *testing.T, w *wrapper) (*httptest.Server, HttpClient) {
	t.Helper()
	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(rw stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/from" {
			stdhttp.Redirect(rw, r, "/to", stdhttp.StatusFound)
			return
		}
		_, _ = io.WriteString(rw, r.RemoteAddr)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_133), WithInsecureSkipVerify(),
		WithTransportWrapper(w.wrap))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return srv, client
}

func TestEveryRequestGoesThroughWhatItsRoundTripperIsWrappedIn(t *testing.T) {
	var w wrapper
	srv, client := wrapping(t, &w)
	if got, err := from(client, srv.URL+"/from"); err != nil || got == "" {
		t.Fatalf("GET /from: %q, %v", got, err)
	}
	// The redirect's hop too.
	if got := w.sent(); !slices.Equal(got, []string{"/from", "/to"}) {
		t.Errorf("sent %q through the wrapper", got)
	}
	c := client.(*httpClient)
	if len(w.handed) != 1 || w.handed[0] != c.built || c.Transport != (wrapped{&w, c.built}) {
		t.Errorf("handed %v; built %p, sending by %v", w.handed, c.built, c.Transport)
	}
}

func TestAClientNothingWrapsSendsByTheRoundTripperItBuilt(t *testing.T) {
	client, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_133))
	if err != nil {
		t.Fatal(err)
	}
	if c := client.(*httpClient); c.built == nil || c.Transport != c.built {
		t.Errorf("built %p, sending by %v", c.built, c.Transport)
	}
}

func TestAWrappedClientClosesTheIdleConnectionsOfItsRoundTripper(t *testing.T) {
	var w wrapper
	srv, client := wrapping(t, &w)
	first := mustFrom(t, client, srv.URL+"/")
	if again := mustFrom(t, client, srv.URL+"/"); again != first {
		t.Fatalf("from %s, then %s: the connection was not kept", first, again)
	}
	client.CloseIdleConnections()
	if after := mustFrom(t, client, srv.URL+"/"); after == first {
		t.Errorf("from %s again: its idle connection was not closed", after)
	}
}

func TestAWrappedClientDialsForAWebsocketAsItsRoundTripperDoes(t *testing.T) {
	var w wrapper
	srv, client := wrapping(t, &w)
	conn, err := client.GetTLSDialer()(context.Background(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if u, ok := conn.(*tls.UConn); !ok || !u.ConnectionState().HandshakeComplete {
		t.Errorf("dialed a %T", conn)
	}
	if got := w.sent(); len(got) != 0 {
		t.Errorf("sent %q through the wrapper", got)
	}
}

func TestSetProxyWrapsTheRoundTripperItBuilds(t *testing.T) {
	var w wrapper
	_, client := wrapping(t, &w)
	c := client.(*httpClient)
	before := c.built
	if err := client.SetProxy("http://127.0.0.1:1"); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	if len(w.handed) != 2 || w.handed[1] != c.built || c.built == before || c.Transport != (wrapped{&w, c.built}) {
		t.Errorf("handed %v; built %p, before %p, sending by %v", w.handed, c.built, before, c.Transport)
	}
	// And a client nothing wraps sends by the one SetProxy built.
	plain, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_133))
	if err != nil {
		t.Fatal(err)
	}
	p := plain.(*httpClient)
	before = p.built
	if err := plain.SetProxy("http://127.0.0.1:1"); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	if p.built == before || p.Transport != p.built {
		t.Errorf("built %p, before %p, sending by %v", p.built, before, p.Transport)
	}
}
