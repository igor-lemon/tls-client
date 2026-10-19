package tls_client

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/tls-client/profiles"
)

// pit serves at 127.0.0.1 over TLS (h2 and http/1.1, or http/1.1 alone) the
// first let connections it takes, and holds every later one: taken, never
// answered, so a client's handshake hangs. caught has each held one.
type pit struct {
	net.Listener
	let    atomic.Int32
	taken  atomic.Int32
	mu     sync.Mutex
	held   []net.Conn
	caught chan net.Conn
}

func (p *pit) Accept() (net.Conn, error) {
	for {
		c, err := p.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if p.taken.Add(1) <= p.let.Load() {
			return c, nil
		}
		p.mu.Lock()
		p.held = append(p.held, c)
		p.mu.Unlock()
		p.caught <- c
	}
}

func (p *pit) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.held {
		_ = c.Close()
	}
}

// servePit is the URL a pit that lets let connections through serves at.
func servePit(t *testing.T, let int32, h2 bool) (string, *pit) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &pit{Listener: ln, caught: make(chan net.Conn, 16)}
	p.let.Store(let)
	cert := coalescingCert(t, "a.test")
	cfg := &stdtls.Config{NextProtos: []string{"http/1.1"}, Certificates: []stdtls.Certificate{cert}}
	srv := &stdhttp.Server{Handler: stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}), TLSConfig: cfg}
	if h2 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	} else {
		srv.TLSNextProto = map[string]func(*stdhttp.Server, *stdtls.Conn, stdhttp.Handler){}
	}
	go func() { _ = srv.ServeTLS(p, "", "") }()
	t.Cleanup(func() {
		p.release()
		_ = srv.Close()
	})
	return "https://" + ln.Addr().String(), p
}

func pitClient(t *testing.T) HttpClient {
	t.Helper()
	client, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_133), WithInsecureSkipVerify(),
		WithTimeoutSeconds(30))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

// getting sends a GET of url in ctx, and says how it ended.
func getting(client HttpClient, url string, ctx context.Context) <-chan error {
	ended := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			ended <- err
			return
		}
		res, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
		}
		ended <- err
	}()
	return ended
}

func endsWithin(t *testing.T, ended <-chan error, limit time.Duration) error {
	t.Helper()
	select {
	case err := <-ended:
		return err
	case <-time.After(limit):
		t.Fatalf("still going after %v", limit)
		return nil
	}
}

func caughtWithin(t *testing.T, p *pit) net.Conn {
	t.Helper()
	select {
	case c := <-p.caught:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no connection held")
		return nil
	}
}

// letGo says the client closed its end of c within two seconds.
func letGo(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := io.Copy(io.Discard, c)
	return !errors.Is(err, os.ErrDeadlineExceeded)
}

func roundTripperOf(client HttpClient) *roundTripper { return client.(*httpClient).built }

// emptied says that rt holds no setup and no dial lock, within a second.
func emptied(t *testing.T, rt *roundTripper) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); ; time.Sleep(5 * time.Millisecond) {
		rt.cachedTransportsLck.Lock()
		setups := len(rt.setups)
		rt.cachedTransportsLck.Unlock()
		rt.Lock()
		locks := len(rt.dialLocks)
		rt.Unlock()
		if setups == 0 && locks == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d setups and %d dial locks left", setups, locks)
		}
	}
}

func TestAConnectionsHandshakeEndsWithItsRequestsContext(t *testing.T) {
	for _, tc := range []struct {
		name string
		// let is how many connections the server takes before it holds one.
		let int32
	}{
		{"the first, which finds out what the server speaks", 0},
		{"one the HTTP/2 transport dials later", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, p := servePit(t, tc.let, true)
			client := pitClient(t)
			if tc.let > 0 {
				if err := endsWithin(t, getting(client, url, context.Background()), 5*time.Second); err != nil {
					t.Fatalf("Get: %v", err)
				}
				client.CloseIdleConnections()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			if err := endsWithin(t, getting(client, url, ctx), 3*time.Second); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Get: %v, want its deadline", err)
			}
			if took := time.Since(start); took > time.Second {
				t.Errorf("ended after %v", took)
			}
			if !letGo(caughtWithin(t, p)) {
				t.Error("the connection was not let go of")
			}
			emptied(t, roundTripperOf(client))
		})
	}
}

func TestAHandshakeThatHangsHoldsUpNoOtherAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		let  int32
	}{
		{"the first", 0},
		{"one the HTTP/2 transport dials later", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hanging, p := servePit(t, tc.let, true)
			// One the client has a connection to, and two it has none to yet.
			open, _ := servePit(t, 100, true)
			fresh, _ := servePit(t, 100, true)
			plain, _ := servePit(t, 100, false)
			client := pitClient(t)
			for _, url := range []string{open, hanging}[:1+tc.let] {
				if err := endsWithin(t, getting(client, url, context.Background()), 5*time.Second); err != nil {
					t.Fatalf("Get: %v", err)
				}
			}
			if tc.let > 0 {
				client.CloseIdleConnections()
				if err := endsWithin(t, getting(client, open, context.Background()), 5*time.Second); err != nil {
					t.Fatalf("Get: %v", err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			hung := getting(client, hanging, ctx)
			caughtWithin(t, p)
			for _, url := range []string{open, fresh, plain} {
				start := time.Now()
				if err := endsWithin(t, getting(client, url, context.Background()), 5*time.Second); err != nil {
					t.Errorf("Get %s: %v", url, err)
				}
				if took := time.Since(start); took > time.Second {
					t.Errorf("Get %s waited %v", url, took)
				}
			}
			cancel()
			if err := endsWithin(t, hung, 3*time.Second); !errors.Is(err, context.Canceled) {
				t.Errorf("the hung one: %v", err)
			}
			emptied(t, roundTripperOf(client))
		})
	}
}

// waitedFor has waitingForSetup say on the channel it returns each address a
// request waits for another's setup of.
func waitedFor(t *testing.T) <-chan string {
	t.Helper()
	waited := make(chan string, 8)
	before := waitingForSetup
	waitingForSetup = func(addr string) { waited <- addr }
	t.Cleanup(func() { waitingForSetup = before })
	return waited
}

func TestARequestWaitsForItsAddressesSetupNoLongerThanItsContextLets(t *testing.T) {
	waited := waitedFor(t)
	url, p := servePit(t, 0, true)
	client := pitClient(t)
	long, cancel := context.WithCancel(context.Background())
	first := getting(client, url, long)
	caughtWithin(t, p)
	ctx, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer stop()
	start := time.Now()
	second := getting(client, url, ctx)
	<-waited
	if err := endsWithin(t, second, 3*time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the second: %v, want its deadline", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the second ended after %v", took)
	}
	cancel()
	if err := endsWithin(t, first, 3*time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("the first: %v", err)
	}
	// One connection, the first's: the second never dialed.
	select {
	case <-p.caught:
		t.Error("dialed again")
	case <-time.After(100 * time.Millisecond):
	}
	emptied(t, roundTripperOf(client))
}

func TestARequestSetsUpItsOwnOnceTheSetupItWaitedForFailed(t *testing.T) {
	waited := waitedFor(t)
	url, p := servePit(t, 0, true)
	client := pitClient(t)
	first := getting(client, url, context.Background())
	held := caughtWithin(t, p)
	second := getting(client, url, context.Background())
	<-waited
	// The first's handshake fails; the second sets up its own, which the
	// server answers.
	p.let.Store(2)
	_ = held.Close()
	if err := endsWithin(t, first, 3*time.Second); err == nil {
		t.Error("the first was answered")
	}
	if err := endsWithin(t, second, 5*time.Second); err != nil {
		t.Errorf("the second: %v", err)
	}
	emptied(t, roundTripperOf(client))
}

func TestASetupLetsGoOfAConnectionLeftBehind(t *testing.T) {
	url, _ := servePit(t, 100, true)
	client := pitClient(t)
	rt := roundTripperOf(client)
	addr := url[len("https://"):]
	left, other := net.Pipe()
	defer other.Close()
	rt.Lock()
	rt.cachedConnections[addr] = left
	rt.Unlock()
	rt.stashed.Store(addr, true)
	if err := endsWithin(t, getting(client, url, context.Background()), 5*time.Second); err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = other.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := other.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("the connection left behind: %v", err)
	}
}

func TestDialsToOneAddressGoOneAfterAnother(t *testing.T) {
	rt := &roundTripper{dialLocks: map[string]*dialLock{}}
	unlockA, err := rt.lockDial(context.Background(), "a:443")
	if err != nil {
		t.Fatal(err)
	}
	// Another dial of a waits no longer than its context lets it.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := rt.lockDial(ctx, "a:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a again: %v", err)
	}
	if took := time.Since(start); took < 100*time.Millisecond || took > time.Second {
		t.Errorf("a again waited %v", took)
	}
	// Another address's does not wait.
	unlockB, err := rt.lockDial(context.Background(), "b:443")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	// Let go of, a is dialed again.
	got := make(chan error, 1)
	go func() {
		unlock, err := rt.lockDial(context.Background(), "a:443")
		if err == nil {
			unlock()
		}
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("a again before a was let go of: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unlockA()
	if err := endsWithin(t, got, time.Second); err != nil {
		t.Errorf("a again: %v", err)
	}
	unlockB()
	if len(rt.dialLocks) != 0 {
		t.Errorf("dial locks left: %v", rt.dialLocks)
	}
}

func TestASecondDialToAnAddressWaitsForTheFirstNoLongerThanItsContextLets(t *testing.T) {
	for _, tc := range []struct {
		name string
		// second sends the second request: through the transport cached for
		// the address, or by a setup of its own once that one was dropped.
		second func(rt *roundTripper, addr string)
	}{
		{"the transport's own dial", func(*roundTripper, string) {}},
		{"a setup's", func(rt *roundTripper, addr string) {
			rt.cachedTransportsLck.Lock()
			cached := rt.cachedTransports[addr]
			rt.cachedTransportsLck.Unlock()
			rt.dropCachedTransport(addr, cached)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// HTTP/1.1, so that each request waiting for a connection dials one.
			url, p := servePit(t, 1, false)
			client := pitClient(t)
			if err := endsWithin(t, getting(client, url, context.Background()), 5*time.Second); err != nil {
				t.Fatalf("Get: %v", err)
			}
			client.CloseIdleConnections()
			ctx, cancel := context.WithCancel(context.Background())
			first := getting(client, url, ctx)
			caughtWithin(t, p)
			tc.second(roundTripperOf(client), url[len("https://"):])
			short, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer stop()
			if err := endsWithin(t, getting(client, url, short), 3*time.Second); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("the second: %v, want its deadline", err)
			}
			select {
			case <-p.caught:
				t.Error("the second dialed while the first did")
			default:
			}
			cancel()
			if err := endsWithin(t, first, 3*time.Second); !errors.Is(err, context.Canceled) {
				t.Errorf("the first: %v", err)
			}
			emptied(t, roundTripperOf(client))
		})
	}
}
