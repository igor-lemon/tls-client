package tls_client

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
)

// A completed peer handshake is not publication in the client's pool. Hold the
// return from the actual client dial after its peer completed the handshake.
// There are no fake handshakes, response retries or synthetic protocol values.
func TestAltSvcPeerHandshakeDoesNotPublishClientPool(t *testing.T) {
	saved := dialQUIC
	t.Cleanup(func() { dialQUIC = saved })
	o := newH3Origin(t, originSays{})
	held, release := make(chan struct{}), make(chan struct{})
	var holdOnce, releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	defer letGo()
	target, err := strconv.Atoi(portOf(o))
	if err != nil {
		t.Fatal(err)
	}
	dialQUIC = func(ctx context.Context, remote *net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, began func()) (*quic.Conn, error) {
		c, err := saved(ctx, remote, tlsCfg, cfg, began)
		if err == nil && remote.Port == target {
			holdOnce.Do(func() { close(held) })
			<-release
		}
		return c, err
	}
	state := NewQUICState()
	state.workedFor(quicServer{"https://a.test", "elsewhere.test:443"})
	c := h3Client(t, altSvcPolicy(t, map[string]string{"quic.alt_svc_tcp_waits_with_h2": "false"}), &recordSays{}, state)
	if got := came(t, c, altURL(o, "/", `h3=":`+portOf(o)+`"`)); got != "HTTP/2.0" {
		t.Fatal(got)
	}
	if got := came(t, c, "https://"+o.addr+"/b"); got != "HTTP/2.0" {
		t.Fatal(got)
	}
	o.quicConn(t, 0)
	select {
	case <-held:
	case <-time.After(2 * time.Second):
		t.Fatal("actual client dial did not reach publication gate")
	}
	d := c.(*httpClient).built.dnsH3
	d.mu.Lock()
	tr := d.t3
	d.mu.Unlock()
	if tr.HasConn(o.addr) {
		t.Fatal("unpublished client dial already cached")
	}
	// While the actual client dial remains unpublished, the existing H2 socket
	// serves the next request. Server handshake completion alone is insufficient.
	if got := came(t, c, "https://"+o.addr+"/c"); got != "HTTP/2.0" {
		t.Fatalf("unpublished dial took request over %q, wanted existing HTTP/2.0", got)
	}
	if o.tcpAsked.Load() != 3 {
		t.Fatal("unexpected request count before publication", o.tcpAsked.Load())
	}
	letGo()
	if !waitFor(2*time.Second, func() bool { return tr.HasConn(o.addr) }) {
		t.Fatal("client did not publish after real dial returned")
	}
	if got := came(t, c, "https://"+o.addr+"/d"); got != "HTTP/3.0" {
		t.Fatal(got)
	}
	if o.tcpAsked.Load() != 3 {
		t.Fatal("ready QUIC request went over TCP", o.tcpAsked.Load())
	}
	if o.tcpConns.Load() != 1 || o.quicConns.Load() != 1 {
		t.Fatal("duplicate connections", o.tcpConns.Load(), o.quicConns.Load())
	}
}

// Keep the original peer-readiness budget: two seconds to accept and two for
// its handshake. Client publication must complete within that same budget.
func altSvcReadyForNextRequest(t *testing.T, c HttpClient, o *h3Origin) {
	t.Helper()
	began := time.Now()
	o.quicConn(t, 0)
	d := c.(*httpClient).built.dnsH3
	ready := func() bool {
		d.mu.Lock()
		tr := d.t3
		d.mu.Unlock()
		return tr != nil && tr.HasConn(o.addr)
	}
	if !waitFor(4*time.Second-time.Since(began), ready) {
		t.Fatal("peer handshake completed but client did not publish a usable QUIC connection")
	}
}
