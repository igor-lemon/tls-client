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
	"strings"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/tls-client/profiles"
)

// silentProxy takes connections and never says a word on them; taken has
// each one.
func silentProxy(t *testing.T) (string, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	taken := make(chan net.Conn, 8)
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
			taken <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for _, c := range held {
			_ = c.Close()
		}
	})
	return ln.Addr().String(), taken
}

// throughProxy is a client whose connections go through proxyURL, and whose
// dials take timeout at most; it sets no deadline of its own on a request.
func throughProxy(t *testing.T, proxyURL string, timeout time.Duration) HttpClient {
	t.Helper()
	client, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_133), WithInsecureSkipVerify(),
		WithProxyUrl(proxyURL), WithTimeoutMilliseconds(int(timeout.Milliseconds())), WithoutRequestTimeout())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestADialThroughAProxyThatNeverAnswersEndsWithItsRequestsContext(t *testing.T) {
	for _, tc := range []struct {
		scheme string
		// timeout is the dial's: SOCKS4's talk with the proxy takes no
		// context, and ends at it.
		timeout time.Duration
	}{
		{"socks5", 30 * time.Second},
		{"socks5h", 30 * time.Second},
		{"socks4", time.Second},
		{"socks4a", time.Second},
		{"http", 30 * time.Second},
		{"https", 30 * time.Second},
	} {
		t.Run(tc.scheme, func(t *testing.T) {
			addr, taken := silentProxy(t)
			client := throughProxy(t, tc.scheme+"://"+addr, tc.timeout)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			// An address, which SOCKS4 looks up nowhere.
			err := endsWithin(t, getting(client, "https://127.0.0.1:9/", ctx), 3*time.Second)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Get: %v, want its deadline", err)
			}
			// At its deadline, not at the dial's timeout.
			if took := time.Since(start); took > 700*time.Millisecond {
				t.Errorf("ended after %v", took)
			}
			select {
			case c := <-taken:
				if !letGo(c) {
					t.Error("the connection to the proxy was not let go of")
				}
			case <-time.After(time.Second):
				t.Fatal("the proxy was never dialed")
			}
		})
	}
}

// socks4Proxy grants every SOCKS4 request, after delay, and joins its client
// to the address asked for; granted says each time it granted one.
func socks4Proxy(t *testing.T, delay time.Duration) (string, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	granted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				head := make([]byte, 8)
				if _, err := io.ReadFull(c, head); err != nil || head[0] != 4 || head[1] != 1 {
					return
				}
				// The user ID, ended by a NUL.
				for one := make([]byte, 1); ; {
					if _, err := io.ReadFull(c, one); err != nil {
						return
					}
					if one[0] == 0 {
						break
					}
				}
				target := net.JoinHostPort(net.IP(head[4:8]).String(), itoa(binary.BigEndian.Uint16(head[2:4])))
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer upstream.Close()
				time.Sleep(delay)
				if _, err := c.Write([]byte{0, 0x5a, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				granted <- c
				go func() { _, _ = io.Copy(upstream, c) }()
				_, _ = io.Copy(c, upstream)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), granted
}

func itoa(n uint16) string {
	var b bytes.Buffer
	b.WriteString(strings.TrimLeft(string([]byte{'0' + byte(n/10000), '0' + byte(n/1000%10), '0' + byte(n/100%10), '0' + byte(n/10%10), '0' + byte(n%10)}), "0"))
	return b.String()
}

func TestAConnectionThroughSOCKS4KeepsNoDeadline(t *testing.T) {
	// The dial's timeout bounds the talk with the proxy, not the connection
	// it opens: the server answers after the timeout, and is heard.
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {
		time.Sleep(600 * time.Millisecond)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	addr, _ := socks4Proxy(t, 0)
	client := throughProxy(t, "socks4://"+addr, 300*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := endsWithin(t, getting(client, server.URL, ctx), 5*time.Second); err != nil {
		t.Errorf("Get: %v", err)
	}
}

func TestAConnectionSOCKS4OpensTooLateIsClosed(t *testing.T) {
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	addr, granted := socks4Proxy(t, 400*time.Millisecond)
	client := throughProxy(t, "socks4://"+addr, 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := endsWithin(t, getting(client, server.URL, ctx), 3*time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Get: %v, want its deadline", err)
	}
	select {
	case c := <-granted:
		if !letGo(c) {
			t.Error("the connection opened too late was kept")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the proxy never granted it")
	}
}

func TestAProxysAnswerSaysNothingOfTheRequestsContextWhileItLasts(t *testing.T) {
	// The proxy answers well within the context: the request goes through,
	// and the connection keeps no deadline of the CONNECT's.
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {
		time.Sleep(600 * time.Millisecond)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	proxyServer := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(stdhttp.StatusBadGateway)
			return
		}
		w.WriteHeader(stdhttp.StatusOK)
		conn, rw, err := w.(stdhttp.Hijacker).Hijack()
		if err != nil {
			return
		}
		_ = rw.Flush()
		go func() { _, _ = io.Copy(upstream, conn) }()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
		_ = upstream.Close()
	}))
	defer proxyServer.Close()
	client := throughProxy(t, proxyServer.URL, 300*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = res.Body.Close()
}

// deadlined is a context whose deadline is the one given, and that has not
// ended, as a context is until its own timer says it has.
type deadlined struct {
	context.Context
	deadline time.Time
}

func (d deadlined) Deadline() (time.Time, bool) { return d.deadline, true }

func TestContextOr(t *testing.T) {
	cut := errors.New("i/o timeout")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"none ended", context.Background(), cut},
		{"ended", cancelled, context.Canceled},
		{"past its deadline, its timer yet to say so", deadlined{context.Background(), time.Now().Add(-time.Millisecond)}, context.DeadlineExceeded},
		{"before its deadline", deadlined{context.Background(), time.Now().Add(time.Hour)}, cut},
	} {
		if got := contextOr(tc.ctx, cut); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
