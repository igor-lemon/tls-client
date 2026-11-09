package tls_client

import (
	"context"
	stdtls "crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/tls-client/bandwidth"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
)

// resumingSite is an https server of HTTP/1.1 that says whether each request
// came on a resumed connection; sites of one key take each other's tickets.
func resumingSite(t *testing.T, key [32]byte, resumed *[]bool, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(_ stdhttp.ResponseWriter, r *stdhttp.Request) {
		mu.Lock()
		*resumed = append(*resumed, r.TLS.DidResume)
		mu.Unlock()
	}))
	server.TLS = &stdtls.Config{SessionTicketKey: key}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// A ticket a server gave on one port is offered on another of its name where
// the profile keys its sessions by name alone, as crypto/tls does, and not
// where it keys them by host and port, as Chromium's SSLClientSessionCache
// does ("tls.session_cache_key": "host-port").
func TestASessionIsOfferedOnlyToItsPortWhereTheProfileKeysByHostAndPort(t *testing.T) {
	key := [32]byte{1, 2, 3}
	for _, tc := range []struct {
		key      string
		resumesB bool
	}{{"", true}, {"server-name", true}, {"host-port", false}} {
		t.Run(tc.key, func(t *testing.T) {
			var mu sync.Mutex
			var resumed []bool
			a := resumingSite(t, key, &resumed, &mu)
			b := resumingSite(t, key, &resumed, &mu)
			p := behavior.Generic()
			if tc.key != "" {
				p["tls.session_cache_key"] = json.RawMessage(`"` + tc.key + `"`)
			}
			client, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_152_PSK.WithBehavior(p)),
				WithInsecureSkipVerify(), WithTimeoutSeconds(10))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)
			for _, url := range []string{a.URL, a.URL, b.URL} {
				req, _ := http.NewRequest(http.MethodGet, url+"/", nil)
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = res.Body.Close()
				client.CloseIdleConnections()
			}
			mu.Lock()
			defer mu.Unlock()
			if len(resumed) != 3 || resumed[0] || !resumed[1] || resumed[2] != tc.resumesB {
				t.Errorf("resumed %v, want [false true %v]", resumed, tc.resumesB)
			}
		})
	}
}

func TestASessionCacheKeyIsTheHostAndPortWhereTheProfileSays(t *testing.T) {
	p := behavior.Policy{"tls.session_cache_key": json.RawMessage(`"host-port"`),
		"quic.session_cache_key": json.RawMessage(`"server-name"`)}
	if got := sessionCacheKey(p, "tls.session_cache_key", "example.com:8443"); got != "example.com:8443" {
		t.Errorf("host-port: %q", got)
	}
	if got := sessionCacheKey(p, "quic.session_cache_key", "example.com:8443"); got != "" {
		t.Errorf("server-name: %q", got)
	}
	if got := sessionCacheKey(behavior.Policy{}, "tls.session_cache_key", "example.com:8443"); got != "" {
		t.Errorf("none: %q", got)
	}
}

// Every QUIC dial gives its connection the key of its origin's host and port
// where the profile says quic.session_cache_key host-port, as quiche's
// QuicServerId: the profile's own, through SOCKS5, and a record's, whose
// alternative's port is not the origin's. None where it keys them by name.
func TestEveryQUICDialKeysItsSessionsAsTheProfileSays(t *testing.T) {
	saved := dialQUIC
	t.Cleanup(func() { dialQUIC = saved })
	var dialed *tls.Config
	dialQUIC = func(_ context.Context, _ *net.UDPAddr, tlsCfg *tls.Config, _ *quic.Config, _ func()) (*quic.Conn, error) {
		dialed = tlsCfg
		return nil, errors.New("not dialed")
	}
	given, cancel := context.WithCancel(context.Background())
	cancel()
	for _, key := range []string{"host-port", "server-name"} {
		cfg := &quic.Config{Behavior: behavior.Policy{"quic.session_cache_key": json.RawMessage(`"` + key + `"`)}}
		want := func(addr string) string {
			if key == "host-port" {
				return addr
			}
			return ""
		}
		own := &tls.Config{}
		_, _ = dialProfileQUIC(given, "127.0.0.1:8443", own, cfg)
		socks := &tls.Config{}
		_, _ = newSOCKS5QUICDialer("socks5://127.0.0.1:1")(given, "example.com:8443", socks, cfg)
		a := &quicAttempt{quicJob: quicJob{endpoint: QUICEndpoint{Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
			port: 9443}, underWay: make(chan struct{})}
		record := &tls.Config{}
		_, _ = (&dnsH3{}).dial(nil)(context.WithValue(context.Background(), quicAttemptKey{}, a), "example.com:443", record, cfg)
		if own.SessionCacheKey != want("127.0.0.1:8443") || socks.SessionCacheKey != want("example.com:8443") ||
			dialed != record || record.SessionCacheKey != want("example.com:443") {
			t.Errorf("%s: own %q, SOCKS5 %q, a record's %q", key, own.SessionCacheKey, socks.SessionCacheKey,
				record.SessionCacheKey)
		}
	}
}

// A websocket's TLS connection keeps its sessions by the same key: by name, a
// ticket of one port is offered on another, by host and port it is not.
func TestAWebsocketsSessionIsKeptByHostAndPortWhereTheProfileSays(t *testing.T) {
	key := [32]byte{7, 8, 9}
	for _, tc := range []struct {
		key      string
		resumesB bool
	}{{"server-name", true}, {"host-port", false}} {
		var mu sync.Mutex
		var resumed []bool
		a := resumingSite(t, key, &resumed, &mu)
		b := resumingSite(t, key, &resumed, &mu)
		p := behavior.Generic()
		p["tls.session_cache_key"] = json.RawMessage(`"` + tc.key + `"`)
		made, err := newRoundTripper(profiles.Chrome_152_PSK.WithBehavior(p), nil, "", true, false, false, false, false, false,
			nil, nil, nil, false, false, bandwidth.NewNopeTracker(), "", 0, &net.Dialer{})
		if err != nil {
			t.Fatal(err)
		}
		rt := made.(*roundTripper)
		for _, s := range []*httptest.Server{a, a, b} {
			conn, err := rt.dialTLSForWebsocket(context.Background(), "tcp", s.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example\r\nConnection: close\r\n\r\n")
			_, _ = io.ReadAll(conn)
			_ = conn.Close()
		}
		mu.Lock()
		if len(resumed) != 3 || resumed[0] || !resumed[1] || resumed[2] != tc.resumesB {
			t.Errorf("%s: resumed %v, want [false true %v]", tc.key, resumed, tc.resumesB)
		}
		mu.Unlock()
	}
}
