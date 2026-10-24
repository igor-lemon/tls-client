package tls_client

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/igor-lemon/tls-client/bandwidth"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
	"golang.org/x/crypto/cryptobyte"
)

// chromeECH is how Chrome 155 offers ECH, as tls-forge's profiles say.
const chromeECH = `{"tls.ech": true, "tls.ech_inner_own": [0, 43, 65037],
 "tls.ech_inner_omitted": [11, 23, 35, 65281], "tls.ech_inner_min_version": 772,
 "tls.ech_padding_block": 32, "tls.ech_kems": [32], "tls.ech_kdfs": [1], "tls.ech_aeads": [1, 2, 3],
 "tls.ech_chacha_without_aes": true, "tls.ech_outer_psk": "none", "tls.ech_retries": 1,
 "tls.ech_retry_without": true}`

// echPolicy is Chrome's, with changes (a key's value, or "" to leave it out).
func echPolicy(t *testing.T, changes map[string]string) behavior.Policy {
	t.Helper()
	var p behavior.Policy
	if err := json.Unmarshal([]byte(chromeECH), &p); err != nil {
		t.Fatal(err)
	}
	for k, v := range changes {
		if v == "" {
			delete(p, k)
			continue
		}
		p[k] = json.RawMessage(v)
	}
	return p
}

func echConfig(id uint8, key *ecdh.PrivateKey) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
		b.AddUint8(0)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.test")) })
		b.AddUint16(0)
	})
	return b.BytesOrPanic()
}

func echList(configs ...[]byte) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range configs {
			b.AddBytes(c)
		}
	})
	return b.BytesOrPanic()
}

// echSite is a server of crypto/tls's for secret.test, public.test its ECH
// provider's name, which keeps what each connection's handshake said.
type echSite struct {
	addr       string
	roots      *x509.CertPool
	key, stale *ecdh.PrivateKey
	good, old  []byte // ECHConfigs: one the server opens, one it does not
	mu         sync.Mutex
	seen       []stdtls.ConnectionState
	errs       []error
}

// newECHSite serves with keys (none: no ECH); public is whether its
// certificate is good for the provider's name too.
func newECHSite(t *testing.T, keys func(s *echSite) []stdtls.EncryptedClientHelloKey, public bool) *echSite {
	t.Helper()
	s := &echSite{roots: x509.NewCertPool()}
	s.key, _ = ecdh.X25519().GenerateKey(rand.Reader)
	s.stale, _ = ecdh.X25519().GenerateKey(rand.Reader)
	s.good, s.old = echConfig(0x11, s.key), echConfig(0x66, s.stale)
	names := []string{"secret.test"}
	if public {
		names = append(names, "public.test")
	}
	cert := coalescingCert(t, names...)
	s.roots.AddCert(cert.Leaf)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s.addr = ln.Addr().String()
	cfg := &stdtls.Config{Certificates: []stdtls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	if keys != nil {
		cfg.EncryptedClientHelloKeys = keys(s)
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = raw.Close() }()
				conn := stdtls.Server(raw, cfg)
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				err := conn.Handshake()
				s.mu.Lock()
				s.seen = append(s.seen, conn.ConnectionState())
				s.errs = append(s.errs, err)
				s.mu.Unlock()
				buf := make([]byte, 1)
				_, _ = conn.Read(buf)
			}()
		}
	}()
	return s
}

// echDialer reaches the site whatever the address, its connections saying
// configs, or nothing of ECH with none.
type echDialer struct {
	site    string
	configs []byte
	mu      sync.Mutex
	dials   int
}

type echConn struct {
	net.Conn
	configs []byte
}

func (c echConn) ECHConfigList() []byte { return c.configs }

func (d *echDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *echDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, network, d.site)
	if err != nil || d.configs == nil {
		return conn, err
	}
	return echConn{conn, d.configs}, nil
}

// handshake shakes hands with the site as secret.test over the dialer, the
// profile Chrome 133's with policy, checking certificates or not.
func (s *echSite) handshake(t *testing.T, d *echDialer, policy behavior.Policy, insecure bool) (*tls.UConn, error) {
	t.Helper()
	rt, err := newRoundTripper(profiles.Chrome_133.WithBehavior(policy), &TransportOptions{RootCAs: s.roots}, "", insecure,
		false, false, false, false, false, nil, nil, false, false, bandwidth.NewNopeTracker(), "", d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := rt.(*roundTripper).handshake(ctx, "tcp", "secret.test:443")
	if conn != nil {
		t.Cleanup(func() { _ = conn.Close() })
	}
	return conn, err
}

// accepted is what the server said of each connection: whether it took ECH.
func (s *echSite) accepted(t *testing.T, want int) []bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.seen)
		var out []bool
		for _, st := range s.seen {
			out = append(out, st.ECHAccepted)
		}
		s.mu.Unlock()
		if n >= want || time.Now().After(deadline) {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func goodKey(s *echSite) []stdtls.EncryptedClientHelloKey {
	return []stdtls.EncryptedClientHelloKey{{Config: s.good, PrivateKey: s.key.Bytes(), SendAsRetry: true}}
}

func TestAConnectionOffersTheECHItsDialerFound(t *testing.T) {
	s := newECHSite(t, goodKey, true)
	conn, err := s.handshake(t, &echDialer{site: s.addr, configs: echList(s.good)}, echPolicy(t, nil), false)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.ConnectionState().ECHAccepted || conn.ConnectionState().ServerName != "secret.test" {
		t.Errorf("%+v", conn.ConnectionState())
	}
	if got := s.accepted(t, 1); len(got) != 1 || !got[0] {
		t.Errorf("the server saw %v", got)
	}
}

// noECH is Chrome's policy without ECH, said off when off is.
func noECH(t *testing.T, off bool) behavior.Policy {
	t.Helper()
	p := echPolicy(t, nil)
	for k := range p {
		delete(p, k)
	}
	if off {
		p["tls.ech"] = json.RawMessage("false")
	}
	return p
}

func TestAConnectionOffersNoECHWithoutConfigsOrAProfileThatOffersIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		configs []byte
		policy  behavior.Policy
	}{
		{"no configs", nil, echPolicy(t, nil)},
		{"configs, and a profile that says nothing of ECH", []byte("unread"), noECH(t, false)},
		{"configs, and a profile that offers none", []byte("unread"), noECH(t, true)},
	} {
		s := newECHSite(t, goodKey, true)
		conn, err := s.handshake(t, &echDialer{site: s.addr, configs: tc.configs}, tc.policy, false)
		if err != nil || conn.ConnectionState().ECHAccepted {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestARefusedOfferIsMadeAgainOnceAsChromeMakesIt(t *testing.T) {
	loop := func(s *echSite) []stdtls.EncryptedClientHelloKey {
		// A config the server sends to retry with, but cannot open.
		return []stdtls.EncryptedClientHelloKey{{Config: s.good, PrivateKey: s.stale.Bytes(), SendAsRetry: true}}
	}
	var refused *tls.ECHRejectionError
	for _, tc := range []struct {
		name     string
		keys     func(s *echSite) []stdtls.EncryptedClientHelloKey
		configs  func(s *echSite) []byte
		policy   map[string]string
		insecure bool
		public   bool
		want     []bool // what the server took, connection by connection
		ech      bool   // whether the connection had ECH taken
		err      bool
	}{
		{"configs the server sends instead", goodKey, func(s *echSite) []byte { return echList(s.old) }, nil, false, true,
			[]bool{false, true}, true, false},
		{"none: again without ECH", nil, func(s *echSite) []byte { return echList(s.good) }, nil, false, true,
			[]bool{false, false}, false, false},
		{"none, and a profile that goes on with none", nil, func(s *echSite) []byte { return echList(s.good) },
			map[string]string{"tls.ech_retry_without": "false"}, false, true, []bool{false}, false, true},
		{"refused again: once is all", loop, func(s *echSite) []byte { return echList(s.old) }, nil, false, true,
			[]bool{false, false}, false, true},
		{"no retries", goodKey, func(s *echSite) []byte { return echList(s.old) }, map[string]string{"tls.ech_retries": "0"},
			false, true, []bool{false}, false, true},
		{"a refusal no certificate of the public name signs, checked", goodKey,
			func(s *echSite) []byte { return echList(s.old) }, nil, false, false, []bool{false}, false, true},
		{"a refusal no certificate of the public name signs, unchecked", goodKey,
			func(s *echSite) []byte { return echList(s.old) }, nil, true, false, []bool{false, true}, true, false},
	} {
		s := newECHSite(t, tc.keys, tc.public)
		d := &echDialer{site: s.addr, configs: tc.configs(s)}
		conn, err := s.handshake(t, d, echPolicy(t, tc.policy), tc.insecure)
		got := s.accepted(t, len(tc.want))
		if (err != nil) != tc.err || len(got) != len(tc.want) || d.dials != len(tc.want) {
			t.Errorf("%s: %v, the server saw %v over %d dials", tc.name, err, got, d.dials)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: connection %d took ECH: %v", tc.name, i+1, got[i])
			}
		}
		if err == nil && conn.ConnectionState().ECHAccepted != tc.ech {
			t.Errorf("%s: ECH %v", tc.name, conn.ConnectionState().ECHAccepted)
		}
		if tc.name == "refused again: once is all" && !errors.As(err, &refused) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestAnOfferAgainIsMadeWithinItsRequestsTime(t *testing.T) {
	s := newECHSite(t, goodKey, true)
	o := echOffer{left: 1}
	refusal := &tls.ECHRejectionError{RetryConfigList: echList(s.good)}
	if next, ok := o.again(refusal, echPolicy(t, nil)); !ok || !next.refused || next.left != 0 {
		t.Errorf("%+v %v", next, ok)
	}
	if _, ok := o.again(errors.New("another"), echPolicy(t, nil)); ok {
		t.Error("another error makes the offer again")
	}
	// A context that ends with the refusal makes nothing again.
	ctx, cancel := context.WithCancel(context.Background())
	d := &cancelling{echDialer: echDialer{site: s.addr, configs: echList(s.old)}, cancel: cancel}
	rt, err := newRoundTripper(profiles.Chrome_133.WithBehavior(echPolicy(t, nil)), &TransportOptions{RootCAs: s.roots}, "",
		false, false, false, false, false, false, nil, nil, false, false, bandwidth.NewNopeTracker(), "", d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.(*roundTripper).handshake(ctx, "tcp", "secret.test:443"); err == nil || d.dials != 1 {
		t.Errorf("%v after %d dials", err, d.dials)
	}
}

// cancelling ends its context once the connection it dialed has been
// refused: when its server closes.
type cancelling struct {
	echDialer
	cancel context.CancelFunc
}

func (c *cancelling) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := c.echDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &cancelOnClose{ECHConn: conn.(ECHConn), cancel: c.cancel}, nil
}

type cancelOnClose struct {
	ECHConn
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	c.cancel()
	return c.ECHConn.Close()
}
