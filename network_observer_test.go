package tls_client

import (
	"context"
	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/tls-client/profiles"
	"github.com/igor-lemon/utls/behavior"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type observedTCP struct {
	net.Conn
	reads *atomic.Int64
}

func (c observedTCP) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.reads.Add(int64(n))
	return n, e
}

func TestNetworkObserverReachesDirectAndProxySocketsOnce(t *testing.T) {
	origin := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Method != "GET" {
			t.Errorf("origin received %s instead of tunneled GET", r.Method)
			w.WriteHeader(405)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	for _, proxy := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "proxy"}[proxy], func(t *testing.T) {
			var sockets, readBytes, proxyTrace atomic.Int64
			options := &TransportOptions{NetworkObserver: &NetworkObserver{TCPConnection: func(ctx context.Context, c net.Conn) net.Conn {
				if _, ok := c.(*net.TCPConn); !ok {
					t.Errorf("not raw TCP before TLS/proxy handshake: %T", c)
				}
				sockets.Add(1)
				return observedTCP{c, &readBytes}
			}}}
			opts := []HttpClientOption{WithClientProfile(profiles.Chrome_133), WithForceHttp1(), WithTransportOptions(options)}
			if proxy {
				proxyServer := connectProxy(t)
				opts = append(opts, WithProxyUrl(proxyServer.URL), WithProxyConnWrapper(func(ctx context.Context, c net.Conn, began time.Time) net.Conn { proxyTrace.Add(1); return c }))
			}
			client, e := NewHttpClient(NewNoopLogger(), opts...)
			if e != nil {
				t.Fatal(e)
			}
			defer client.CloseIdleConnections()
			// Options are snapshots; edits to the caller's callback cannot replace the
			// observer of an already constructed independent client.
			options.NetworkObserver.TCPConnection = func(context.Context, net.Conn) net.Conn { t.Error("caller mutation leaked"); return nil }
			req, _ := http.NewRequest("GET", origin.URL, nil)
			res, e := client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(res.Body)
			res.Body.Close()
			if e != nil || string(b) != "ok" {
				t.Fatal("body", string(b), e)
			}
			if sockets.Load() != 1 || readBytes.Load() <= 2 {
				t.Fatal("missing or duplicate raw receive observer", sockets.Load(), readBytes.Load())
			}
			if proxy && proxyTrace.Load() != 1 {
				t.Fatal("lost existing proxy wrapper")
			}
		})
	}
}

func TestNetworkObserverReachesAllHTTP3ConfigurationModes(t *testing.T) {
	for _, native := range []bool{false, true} {
		p := nativeConfigPolicy(t)
		if !native {
			for k, v := range behavior.Legacy() {
				if _, ok := p[k]; !ok {
					p[k] = v
				}
			}
			p["quic.enabled"] = []byte("true")
		}
		count := 0
		obs := &NetworkObserver{QUIC: func(e quic.NetworkEvent) {
			count++
			if e.ReceivedBytes != 7 {
				t.Error(e)
			}
		}}
		raw, e := buildHTTP3Transport(&http3Config{behavior: p, clientHelloID: profiles.Chrome_133.GetClientHelloId(), transportOptions: &TransportOptions{NetworkObserver: obs}})
		if e != nil {
			t.Fatal(e)
		}
		tr := raw.(*http3.Transport)
		defer tr.Close()
		if tr.QUICConfig == nil || tr.QUICConfig.NetworkObserver == nil {
			t.Fatal("discarded QUIC observer")
		}
		tr.QUICConfig.NetworkObserver(quic.NetworkEvent{ReceivedBytes: 7})
		if count != 1 {
			t.Fatal("missing or duplicate QUIC observer")
		}
	}
}

func TestNetworkObserverNilPreservesCallerTransportOptions(t *testing.T) {
	cfg := &httpClientConfig{}
	WithTransportOptions(nil)(cfg)
	if cfg.transportOptions != nil {
		t.Fatal("invented options")
	}
	p := &TransportOptions{ReadBufferSize: 777}
	WithTransportOptions(p)(cfg)
	p.ReadBufferSize = 888
	if cfg.transportOptions.ReadBufferSize != 777 {
		t.Fatal("options not copied")
	}
	if cfg.networkProxyWrapper() != nil {
		t.Fatal("invented proxy observer")
	}
	conn, other := net.Pipe()
	defer conn.Close()
	defer other.Close()
	rt := &roundTripper{}
	if rt.observeTCP(context.Background(), conn) != conn {
		t.Fatal("nil observer changed connection")
	}
	cfg.wrapProxyConn = func(_ context.Context, c net.Conn, _ time.Time) net.Conn { return c }
	if cfg.networkProxyWrapper() == nil {
		t.Fatal("lost original proxy wrapper")
	}
}

func TestOwnerNetworkObserverPreservesOtherTransportOptions(t *testing.T) {
	cfg := &httpClientConfig{}
	WithTransportOptions(&TransportOptions{ReadBufferSize: 777})(cfg)
	calls := 0
	sink := &NetworkObserver{HTTP2RTT: func(net.Addr, time.Duration) { calls++ }}
	WithNetworkObserver(sink)(cfg)
	sink.HTTP2RTT = nil
	if cfg.transportOptions.ReadBufferSize != 777 || cfg.transportOptions.NetworkObserver == nil || cfg.transportOptions.NetworkObserver.HTTP2RTT == nil {
		t.Fatal("owner binding changed options or retained mutable callback")
	}
	cfg.transportOptions.NetworkObserver.HTTP2RTT(nil, time.Second)
	if calls != 1 {
		t.Fatal("owner hook missing")
	}
	WithNetworkObserver(nil)(cfg)
	if cfg.transportOptions.ReadBufferSize != 777 || cfg.transportOptions.NetworkObserver != nil {
		t.Fatal("explicit nil sink changed other options")
	}
	empty := &httpClientConfig{}
	WithNetworkObserver(nil)(empty)
	if empty.transportOptions == nil {
		t.Fatal("missing transport snapshot")
	}
}
