package tls_client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
	"math/big"
	"testing"
	"time"
)

func nativeConfigPolicy(t *testing.T) behavior.Policy {
	t.Helper()
	p := behavior.Generic()
	var data behavior.Policy
	if err := json.Unmarshal([]byte(`{"quic.config":"explicit", "quic.enabled":false,
 "quic.versions":[1], "quic.dedicated_socket":false, "quic.source_cid_bytes":4,
 "quic.initial_dcid_bytes":8, "quic.stream_receive_window":524288,
 "quic.max_stream_receive_window":6291456, "quic.connection_receive_window":786432,
 "quic.max_connection_receive_window":15728640, "quic.incoming_bidi_streams":0,
 "quic.incoming_uni_streams":100, "quic.idle_timeout_ms":30000,
 "quic.keep_alive_ms":10000, "quic.initial_packet_bytes":1280,
 "quic.datagrams":true, "quic.max_udp_payload":1452, "quic.active_cid_limit":4,
 "quic.ack_timer_ms":25, "quic.max_ack_delay_ms":26}`), &data); err != nil {
		t.Fatal(err)
	}
	for k, v := range data {
		p[k] = v
	}
	return p
}

func TestHTTP3ExplicitConfigReachesNativeAndAdapterTransports(t *testing.T) {
	for _, adapter := range []bool{false, true} {
		p := nativeConfigPolicy(t)
		if adapter {
			for k, v := range behavior.Legacy() {
				if _, ok := p[k]; !ok {
					p[k] = v
				}
			}
			p["quic.enabled"] = json.RawMessage("true")
		}
		raw, err := buildHTTP3Transport(&http3Config{behavior: p})
		if err != nil {
			t.Fatal(err)
		}
		tr := raw.(*http3.Transport)
		q := tr.QUICConfig
		if q == nil {
			t.Fatalf("adapter=%v: explicit QUIC configuration was discarded", adapter)
		}
		if q.InitialStreamReceiveWindow != 524288 || q.MaxStreamReceiveWindow != 6291456 || q.InitialConnectionReceiveWindow != 786432 || q.MaxConnectionReceiveWindow != 15728640 || q.KeepAlivePeriod != 10*time.Second || q.InitialPacketSize != 1280 || q.MaxIncomingStreams != -1 || q.MaxIncomingUniStreams != 100 || q.MaxIdleTimeout != 30*time.Second || !q.EnableDatagrams || len(q.Versions) != 1 || q.Versions[0] != 1 {
			t.Fatalf("adapter=%v: configuration changed: %+v", adapter, q)
		}
		if !tr.EnableDatagrams || q.Policy().Uint("quic.source_cid_bytes") != 4 || tr.TLSClientConfig.Behavior.Uint("quic.initial_packet_bytes") != 1280 {
			t.Fatal("policy did not reach transport and TLS")
		}
		if tr.Dial != nil {
			t.Fatal("shared socket replaced by dedicated dialer")
		}
		p["quic.initial_packet_bytes"] = json.RawMessage("1250")
		if q.Policy().Uint("quic.initial_packet_bytes") != 1280 {
			t.Fatal("caller mutated live policy")
		}
	}
	p := nativeConfigPolicy(t)
	p["quic.keep_alive_ms"] = json.RawMessage("0")
	p["quic.incoming_uni_streams"] = json.RawMessage("0")
	p["quic.dedicated_socket"] = json.RawMessage("true")
	p["quic.source_cid_bytes"] = json.RawMessage("0")
	raw, err := buildHTTP3Transport(&http3Config{behavior: p})
	if err != nil {
		t.Fatal(err)
	}
	tr := raw.(*http3.Transport)
	if tr.QUICConfig.KeepAlivePeriod != 0 || tr.QUICConfig.MaxIncomingUniStreams != -1 || tr.Dial == nil {
		t.Fatal("explicit zeros lost")
	}
}

func TestIndependentQUICFactorySelectionAndSessionOwnership(t *testing.T) {
	p := nativeConfigPolicy(t)
	p["quic.tls_source"] = json.RawMessage(`"independent"`)
	p["quic.session_cache"] = json.RawMessage("true")
	p["quic.session_cache_entries"] = json.RawMessage("1")
	factory := func(params []byte) (tls.ClientHelloSpec, error) {
		return tls.ClientHelloSpec{Extensions: []tls.TLSExtension{&tls.GenericExtension{Id: 57, Data: append([]byte{}, params...)}}}, nil
	}
	if _, err := buildHTTP3Transport(&http3Config{behavior: p}); err == nil {
		t.Fatal("missing factory accepted")
	}
	raw, err := buildHTTP3Transport(&http3Config{behavior: p, quicClientHelloSpec: factory})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := raw.(*http3.Transport).TLSClientConfig.QUICClientHelloSpec([]byte{15, 0})
	if err != nil || !bytes.Equal(spec.Extensions[0].(*tls.GenericExtension).Data, []byte{15, 0}) {
		t.Fatal("factory not connected", err)
	}
	q := p.Clone()
	delete(q, "quic.tls_source")
	if _, err := buildHTTP3Transport(&http3Config{behavior: q, quicClientHelloSpec: factory}); err == nil {
		t.Fatal("unselected factory accepted")
	}
	cp := profiles.Firefox_148.WithBehavior(p).WithQUICClientHelloSpec(factory)
	if profiles.Firefox_148.GetQUICClientHelloSpec() != nil {
		t.Fatal("original profile mutated")
	}
	for _, disable := range []bool{false, true} {
		opts := []HttpClientOption{WithClientProfile(cp), WithProtocolRacing()}
		if disable {
			opts = append(opts, WithDisableSessionTickets())
		}
		client, err := NewHttpClient(NewNoopLogger(), opts...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.CloseIdleConnections)
		rt := client.(*httpClient).Transport.(*roundTripper)
		if rt.quicClientHelloSpec == nil || rt.racer.getHTTP3Config().quicClientHelloSpec == nil {
			t.Fatal("racing route lost factory")
		}
		if (rt.quicSessionCache == nil) != disable {
			t.Fatal("QUIC cache choice ignored")
		}
		// The source TCP preset has no PSK; independent QUIC state cannot enable it.
		if rt.clientSessionCache != nil {
			t.Fatal("QUIC cache leaked into TCP")
		}
	}
	// A one-entry JSON cache really evicts; capacity is not a write-only option.
	cache := profileSessionCache(p, "quic.session_cache_entries", "quic.session_cache_sessions_per_entry")
	a, b := &tls.ClientSessionState{}, &tls.ClientSessionState{}
	cache.Put("a", a)
	cache.Put("b", b)
	if _, ok := cache.Get("a"); ok {
		t.Fatal("capacity ignored")
	}
	if got, ok := cache.Get("b"); !ok || got != b {
		t.Fatal("retained session lost")
	}
	if _, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Firefox_148.WithBehavior(p))); err == nil {
		t.Fatal("missing factory accepted at constructor")
	}
	if _, err := NewHttpClient(NewNoopLogger(), WithClientProfile(cp.WithBehavior(q))); err == nil {
		t.Fatal("unselected factory accepted at constructor")
	}
}

func TestASessionCacheKeepsAsManySessionsAnEntryAsTheProfileSays(t *testing.T) {
	for _, tc := range []struct {
		policy string
		kept   int
	}{
		{`{"tls.session_cache_entries": 4, "tls.session_cache_sessions_per_entry": 2}`, 2},
		{`{"tls.session_cache_entries": 4}`, 1},
		{`{"tls.session_cache_sessions_per_entry": 2}`, 2},
		{`{}`, 1},
	} {
		var p behavior.Policy
		if err := json.Unmarshal([]byte(tc.policy), &p); err != nil {
			t.Fatal(err)
		}
		cache := profileSessionCache(p, "tls.session_cache_entries", "tls.session_cache_sessions_per_entry")
		taker := cache.(interface {
			Take(string) (*tls.ClientSessionState, bool)
		})
		for range 3 {
			cache.Put("a", tls13Session(t))
		}
		kept := 0
		for {
			if _, ok := taker.Take("a"); !ok {
				break
			}
			kept++
		}
		if kept != tc.kept {
			t.Errorf("%s: %d sessions kept, want %d", tc.policy, kept, tc.kept)
		}
	}
}

// tls13Session is a client's TLS 1.3 session of a self-signed certificate, as
// the session encoding of utls reads one.
func tls13Session(t *testing.T) *tls.ClientSessionState {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1),
		NotAfter: time.Now().Add(time.Hour)}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte{0x03, 0x04, 2, 0x13, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7, 0, 0, 0, 0, 0}
	entry := append([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}, der...)
	entry = append(entry, 0, 0)
	b = append(b, byte(len(entry)>>16), byte(len(entry)>>8), byte(len(entry)))
	b = append(b, entry...)
	b = append(b, 0, 0, 0)
	b = append(b, make([]byte, 12)...)
	state, err := tls.ParseSessionState(b)
	if err != nil {
		t.Fatal(err)
	}
	session, err := tls.NewResumptionState([]byte("ticket"), state)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestAClientsCachesKeepTheSessionsAnEntryTheirProfileSays(t *testing.T) {
	// TCP's two a key, QUIC's three: each cache reads its own.
	p := behavior.Generic()
	p["tls.session_cache_entries"] = json.RawMessage("4")
	p["tls.session_cache_sessions_per_entry"] = json.RawMessage("2")
	p["quic.session_cache_entries"] = json.RawMessage("4")
	p["quic.session_cache_sessions_per_entry"] = json.RawMessage("3")
	client, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_152_PSK.WithBehavior(p)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	rt := client.(*httpClient).Transport.(*roundTripper)
	if rt.clientSessionCache == nil || rt.quicSessionCache == nil {
		t.Fatalf("no session caches: TCP %v, QUIC %v", rt.clientSessionCache != nil, rt.quicSessionCache != nil)
	}
	for name, tc := range map[string]struct {
		cache tls.ClientSessionCache
		kept  int
	}{"TCP": {rt.clientSessionCache, 2}, "QUIC": {rt.quicSessionCache, 3}} {
		for range 4 {
			tc.cache.Put("a", tls13Session(t))
		}
		kept := 0
		for {
			if _, ok := tc.cache.(interface {
				Take(string) (*tls.ClientSessionState, bool)
			}).Take("a"); !ok {
				break
			}
			kept++
		}
		if kept != tc.kept {
			t.Errorf("%s: %d kept, want %d", name, kept, tc.kept)
		}
	}
}
