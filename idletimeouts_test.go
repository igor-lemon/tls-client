package tls_client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/igor-lemon/fhttp/http2"
	"github.com/igor-lemon/tls-client/bandwidth"
	"github.com/igor-lemon/tls-client/profiles"
)

// TestTheTransportsKeepIdleConnectionsAsTheirOptionsSay: IdleConnTimeout is
// HTTP/1.1's and HTTP/2's unless HTTP2IdleConnTimeout says HTTP/2's, zero
// included; IdleConnReapOnRequest reaches the HTTP/1.1 transport.
func TestTheTransportsKeepIdleConnectionsAsTheirOptionsSay(t *testing.T) {
	d := func(v time.Duration) *time.Duration { return &v }
	for _, tc := range []struct {
		name         string
		options      *TransportOptions
		http1, http2 time.Duration
		reap         bool
	}{
		{"none", nil, defaultIdleConnectionTimeout, defaultIdleConnectionTimeout, false},
		{"both", &TransportOptions{IdleConnTimeout: d(time.Minute)}, time.Minute, time.Minute, false},
		{"http2-never", &TransportOptions{IdleConnTimeout: d(5 * time.Minute), HTTP2IdleConnTimeout: d(0), IdleConnReapOnRequest: true}, 5 * time.Minute, 0, true},
		{"http2-own", &TransportOptions{HTTP2IdleConnTimeout: d(time.Second)}, defaultIdleConnectionTimeout, time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := newRoundTripper(profiles.Chrome_133, tc.options, "", true, false, false, false, false, false,
				nil, nil, false, false, bandwidth.NewNopeTracker(), "", &net.Dialer{})
			if err != nil {
				t.Fatal(err)
			}
			rt := raw.(*roundTripper)
			if h1, h2 := rt.idleTimeouts(); h1 != tc.http1 || h2 != tc.http2 {
				t.Fatalf("idle timeouts %v and %v, want %v and %v", h1, h2, tc.http1, tc.http2)
			}
			alone := rt.buildHttp1Transport()
			if alone.IdleConnTimeout != tc.http1 || alone.IdleConnReapOnRequest != tc.reap {
				t.Errorf("HTTP/1.1 transport: %v, reap %v", alone.IdleConnTimeout, alone.IdleConnReapOnRequest)
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
			defer conn.Close()
			rt.cachedTransportsLck.Lock()
			err = rt.cache(addr, conn)
			transport := rt.cachedTransports[addr]
			rt.cachedTransportsLck.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			t2 := transport.(*http2.Transport)
			if t2.IdleConnTimeout != tc.http2 {
				t.Errorf("HTTP/2 transport idle timeout %v, want %v", t2.IdleConnTimeout, tc.http2)
			}
		})
	}
}
