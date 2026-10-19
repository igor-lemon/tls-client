package tls_client

import (
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	http2 "github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/tls-client/bandwidth"
	"github.com/igor-lemon/tls-client/profiles"
)

// heldConn is a server's connection whose second write, the flight that
// carries its Finished in a full TLS 1.2 handshake, waits for release; held
// is closed once it waits.
type heldConn struct {
	net.Conn
	writes  int
	held    chan struct{}
	release chan struct{}
}

func (c *heldConn) Write(b []byte) (int, error) {
	if c.writes++; c.writes == 2 {
		close(c.held)
		<-c.release
	}
	return c.Conn.Write(b)
}

// heldServer is a TLS 1.2 server offering protocols, whose one connection
// answers ping with pong, its Finished held until the connection it hands
// over is released.
func heldServer(t *testing.T, protocols ...string) (string, chan *heldConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &stdtls.Config{Certificates: []stdtls.Certificate{coalescingCert(t, "a.test")}, MaxVersion: stdtls.VersionTLS12,
		NextProtos: protocols}
	conns := make(chan *heldConn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = raw.Close() }()
		held := &heldConn{Conn: raw, held: make(chan struct{}), release: make(chan struct{})}
		conns <- held
		server := stdtls.Server(held, cfg)
		buf := make([]byte, 4)
		if _, err := io.ReadFull(server, buf); err == nil {
			_, _ = server.Write([]byte("pong"))
		}
	}()
	return ln.Addr().String(), conns
}

func falseStartingTripper(t *testing.T, on bool) *roundTripper {
	t.Helper()
	rt, err := newRoundTripper(profiles.Chrome_133.WithFalseStart(on), nil, "", true, false, false, false, false, false,
		nil, nil, false, false, bandwidth.NewNopeTracker(), "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	return rt.(*roundTripper)
}

func TestAConnectionFalseStartsAsItsProfileSays(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protocols []string
		dial      func(rt *roundTripper, addr string) (net.Conn, error)
	}{
		{"a request's connection", []string{"h2"}, func(rt *roundTripper, addr string) (net.Conn, error) {
			return rt.handshake(context.Background(), "tcp", addr)
		}},
		{"a websocket's", []string{"http/1.1"}, func(rt *roundTripper, addr string) (net.Conn, error) {
			return rt.dialTLSForWebsocket(context.Background(), "tcp", addr)
		}},
	} {
		for _, on := range []bool{true, false} {
			rt := falseStartingTripper(t, on)
			addr, conns := heldServer(t, tc.protocols...)
			dialed := make(chan net.Conn, 1)
			go func() {
				conn, err := tc.dial(rt, addr)
				if err != nil {
					t.Errorf("%s: %v", tc.name, err)
				}
				dialed <- conn
			}()
			held := <-conns
			var conn net.Conn
			if on {
				// Over while the server's Finished waits.
				select {
				case conn = <-dialed:
				case <-time.After(5 * time.Second):
					t.Fatalf("%s: the handshake waited for the server's Finished", tc.name)
				}
				<-held.held
			} else {
				<-held.held
				select {
				case <-dialed:
					t.Fatalf("%s: the handshake was over before the server's Finished", tc.name)
				case <-time.After(100 * time.Millisecond):
				}
			}
			close(held.release)
			if conn == nil {
				conn = <-dialed
			}
			if conn == nil {
				t.FailNow()
			}
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("%s: Write: %v", tc.name, err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "pong" {
				t.Fatalf("%s: read %q, %v", tc.name, buf, err)
			}
			_ = conn.Close()
		}
	}
}

func TestTheTransportsAreGivenTheProfilesFalseStart(t *testing.T) {
	// What a transport would dial with itself: its own TLS configuration,
	// HTTP/1.1's and HTTP/2's.
	for _, on := range []bool{true, false} {
		rt := falseStartingTripper(t, on)
		if got := rt.buildHttp1Transport().TLSClientConfig.FalseStart; got != on {
			t.Errorf("a profile false starting %v: the HTTP/1.1 transport %v", on, got)
		}
		addr, conns := heldServer(t, "h2")
		go func() {
			held := <-conns
			close(held.release)
		}()
		conn, err := rt.handshake(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		rt.cachedTransportsLck.Lock()
		err = rt.cache(addr, conn)
		transport := rt.cachedTransports[addr]
		rt.cachedTransportsLck.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if got := transport.(*http2.Transport).TLSClientConfig.FalseStart; got != on {
			t.Errorf("a profile false starting %v: the HTTP/2 transport %v", on, got)
		}
		_ = conn.Close()
	}
}

func TestAProfileSaysWhetherItFalseStarts(t *testing.T) {
	if profiles.Chrome_133.GetFalseStart() || !profiles.Chrome_133.WithFalseStart(true).GetFalseStart() ||
		profiles.Chrome_133.WithFalseStart(true).WithFalseStart(false).GetFalseStart() {
		t.Error("WithFalseStart is not what GetFalseStart says")
	}
}
