package tls_client

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
)

// resuming is the profile of h3Client with a pre_shared_key slot, whose
// sessions are kept and resumed.
func resuming(policy behavior.Policy) HttpClientOption {
	return WithClientProfile(profiles.Chrome_133_PSK.WithBehavior(policy))
}

// resumedOver is what a request to url came over, by the origin's word, and
// whether its connection resumed a session.
func resumedOver(t *testing.T, c HttpClient, url string) (string, bool) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	res, err := c.Do(req)
	if err != nil {
		return "error: " + err.Error(), false
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b), res.TLS != nil && res.TLS.DidResume
}

// stashed says whether a connection waits for addr's transport.
func stashed(rt *roundTripper, addr string) bool {
	rt.Lock()
	defer rt.Unlock()
	return rt.cachedConnections[addr] != nil
}

// quicConn is the origin's i-th QUIC connection, once its handshake is done.
func (o *h3Origin) quicConn(t *testing.T, i int) *quic.Conn {
	t.Helper()
	if !waitFor(2*time.Second, func() bool { return int(o.quicConns.Load()) > i }) {
		t.Fatalf("%d QUIC connections, want %d", o.quicConns.Load(), i+1)
	}
	o.mu.Lock()
	conn := o.quic[i]
	o.mu.Unlock()
	select {
	case <-conn.HandshakeComplete():
	case <-time.After(2 * time.Second):
		t.Fatal("no handshake")
	}
	return conn
}

func TestATicketIsOfferedOnlyOverTheProtocolThatGaveIt(t *testing.T) {
	t.Run("TCP's not over QUIC", func(t *testing.T) {
		// QUIC up first, TCP's connection left; QUIC's goes, and the next
		// request takes TCP's, whose server's ticket is read with its answer.
		// The QUIC connection made apart, once that answer is read, resumes
		// with QUIC's ticket: its server knows no TCP one.
		saved := dialQUIC
		t.Cleanup(func() { dialQUIC = saved })
		o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
		policy := dnsH3Policy(t, nil)
		c := h3Client(t, policy, &recordSays{h3: true}, NewQUICState(), resuming(policy))
		if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
			t.Fatalf("came over %q, want HTTP/3", got)
		}
		rt := c.(*httpClient).built
		if !waitFor(2*time.Second, func() bool { return stashed(rt, o.addr) }) {
			t.Fatal("no TCP connection left")
		}
		_ = o.quicConn(t, 0).CloseWithError(0, "")
		time.Sleep(100 * time.Millisecond)
		answered := make(chan struct{})
		dialQUIC = func(ctx context.Context, remote *net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, sent func()) (*quic.Conn, error) {
			<-answered
			return saved(ctx, remote, tlsCfg, cfg, sent)
		}
		if got := came(t, c, "https://"+o.addr+"/again"); got != "HTTP/2.0" {
			t.Fatalf("came over %q, want the TCP connection left", got)
		}
		close(answered)
		if !o.quicConn(t, 1).ConnectionState().TLS.DidResume {
			t.Error("the QUIC connection made apart resumed no session")
		}
	})
	t.Run("QUIC's not over TCP", func(t *testing.T) {
		// TCP up first: its ticket comes with its answer, QUIC's after it.
		// Then QUIC is broken and the connections closed: the next request's
		// new TCP connection resumes with TCP's.
		o := newH3Origin(t, originSays{quicLag: 100 * time.Millisecond})
		policy := dnsH3Policy(t, nil)
		state := NewQUICState()
		c := h3Client(t, policy, &recordSays{h3: true}, state, resuming(policy))
		if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/2.0" {
			t.Fatalf("came over %q, want TCP's", got)
		}
		o.quicConn(t, 0)
		time.Sleep(300 * time.Millisecond)
		c.CloseIdleConnections()
		state.markBroken(quicServer{"https://a.test", o.addr}, policy)
		got, resumed := resumedOver(t, c, "https://"+o.addr+"/again")
		if got != "HTTP/2.0" {
			t.Fatalf("came over %q, want TCP's", got)
		}
		if !resumed {
			t.Error("the new TCP connection resumed no session")
		}
		if o.tcpConns.Load() != 2 {
			t.Errorf("%d TCP connections, want a new one", o.tcpConns.Load())
		}
	})
}

func TestEveryQUICTransportKeepsItsSessionsWithQUICs(t *testing.T) {
	// The race's TCP is let go of as its QUIC wins, so no request of it
	// reads a ticket of TCP's: its QUIC's cache is held to be QUIC's here.
	c, err := NewHttpClient(nil, WithClientProfile(profiles.Chrome_133_PSK), WithProtocolRacing())
	if err != nil {
		t.Fatal(err)
	}
	rt := c.(*httpClient).built
	if rt.quicSessionCache == nil || rt.quicSessionCache == rt.clientSessionCache {
		t.Fatal("QUIC's sessions are not kept apart from TCP's")
	}
	if rt.racer.quicSessionCache != rt.quicSessionCache || rt.racer.getHTTP3Config().clientSessionCache != rt.quicSessionCache {
		t.Error("the racer's HTTP/3 transports keep their sessions elsewhere")
	}
}
