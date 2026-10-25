package tls_client

import (
	"context"
	"net"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	tls "github.com/igor-lemon/utls"
	"golang.org/x/net/ipv4"
)

// tapped keeps what a QUIC connection's socket told it.
type tapped struct {
	mu          sync.Mutex
	wrote, read [][]byte
	closed      int
}

func (t *tapped) Wrote(b []byte) {
	t.mu.Lock()
	t.wrote = append(t.wrote, slices.Clone(b))
	t.mu.Unlock()
}
func (t *tapped) Read(b []byte) { t.mu.Lock(); t.read = append(t.read, slices.Clone(b)); t.mu.Unlock() }
func (t *tapped) Closed()       { t.mu.Lock(); t.closed++; t.mu.Unlock() }

func (t *tapped) said() (wrote, read [][]byte, closed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.wrote), slices.Clone(t.read), t.closed
}

func TestASocketTellsItsTapOfEveryDatagram(t *testing.T) {
	peer := loopbackUDP(t)
	socket := loopbackUDP(t)
	tap := &tapped{}
	c := newSentFirst(socket, nil)
	c.tap = tap
	if _, err := c.WriteTo([]byte("one"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.WriteMsgUDP([]byte("two"), nil, peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	wrote, _, _ := tap.said()
	if len(wrote) != 2 || string(wrote[0]) != "one" || string(wrote[1]) != "two" {
		t.Errorf("told of %q written", wrote)
	}
	if runtime.GOOS != "windows" {
		for _, b := range []string{"back", "again"} {
			if _, err := peer.WriteTo([]byte(b), socket.LocalAddr()); err != nil {
				t.Fatal(err)
			}
		}
		for want := 2; want > 0; {
			ms := []ipv4.Message{{Buffers: [][]byte{make([]byte, 16)}, OOB: make([]byte, 64)}, {}}
			n, err := c.ReadBatch(ms[:1], 0)
			if err != nil {
				t.Fatal(err)
			}
			want -= n
		}
		if _, read, _ := tap.said(); len(read) != 2 || string(read[0]) != "back" || string(read[1]) != "again" {
			t.Errorf("told of %q read", read)
		}
	}
	// A write that fails sends nothing: the tap is told of none.
	_ = socket.Close()
	_, _ = c.WriteTo([]byte("three"), peer.LocalAddr())
	_, _, _ = c.WriteMsgUDP([]byte("four"), nil, peer.LocalAddr().(*net.UDPAddr))
	ms := []ipv4.Message{{Buffers: [][]byte{make([]byte, 16)}}}
	_, _ = c.ReadBatch(ms, 0)
	if wrote, read, _ := tap.said(); len(wrote) != 2 || runtime.GOOS != "windows" && len(read) != 2 {
		t.Errorf("told of %q written and %q read after the socket closed", wrote, read)
	}
}

func TestAConnectedSocketTellsItsTapOfWhatItWrites(t *testing.T) {
	peer := loopbackUDP(t)
	socket, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	tap := &tapped{}
	c := newConnectedSocket(socket, nil)
	c.tap = tap
	if _, err := c.WriteTo([]byte("one"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if wrote, _, _ := tap.said(); len(wrote) != 1 || string(wrote[0]) != "one" {
		t.Errorf("told of %q", wrote)
	}
}

type tapKey struct{}

func TestAQUICConnectionTellsItsTapOfItsDatagramsAndItsEnd(t *testing.T) {
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	tap := &tapped{}
	var asked []string
	var mu sync.Mutex
	records := &recordSays{h3: true}
	state := NewQUICState()
	c := h3Client(t, dnsH3Policy(t, nil), records, state, WithHTTP3FromDNS(HTTP3FromDNS{Endpoint: records.endpoint,
		State: state, Key: func() string { return "https://a.test" },
		Tap: func(ctx context.Context, local, remote net.Addr) QUICPacketTap {
			mu.Lock()
			defer mu.Unlock()
			said, _ := ctx.Value(tapKey{}).(string)
			asked = append(asked, said+" "+remote.String())
			return tap
		}}))
	req, _ := http.NewRequestWithContext(context.WithValue(context.Background(), tapKey{}, "the request"), "GET",
		"https://"+o.addr+"/", nil)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.Proto != "HTTP/3.0" {
		t.Fatalf("came over %s", res.Proto)
	}
	mu.Lock()
	if want := []string{"the request " + o.addr}; !slices.Equal(asked, want) {
		t.Errorf("the tap was asked %q, want %q", asked, want)
	}
	mu.Unlock()
	c.CloseIdleConnections()
	if !waitFor(2*time.Second, func() bool { _, _, closed := tap.said(); return closed == 1 }) {
		t.Fatal("the tap was not told of the socket's end")
	}
	wrote, read, closed := tap.said()
	if len(wrote) == 0 || wrote[0][0]&0x80 == 0 || len(read) == 0 || closed != 1 {
		t.Errorf("told of %d written (the first's form %#x), %d read, closed %d times", len(wrote), wrote[0][0], len(read), closed)
	}
}

func TestAQUICDialTellsTheTapItsContextCarriesWhateverElseItSays(t *testing.T) {
	// Neither connected nor asked to say when its first datagram goes: the
	// tap alone has the socket wrapped.
	o := newH3Origin(t, originSays{})
	remote, err := net.ResolveUDPAddr("udp4", o.addr)
	if err != nil {
		t.Fatal(err)
	}
	tap := &tapped{}
	ctx, cancel := context.WithTimeout(withQUICTap(context.Background(),
		func(context.Context, net.Addr, net.Addr) QUICPacketTap { return tap }), 5*time.Second)
	defer cancel()
	tlsCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "a.test"}
	conn, err := dialQUICAt(ctx, remote, tlsCfg, connectedPolicy(t, false), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.CloseWithError(0, "")
	if !waitFor(2*time.Second, func() bool { _, _, closed := tap.said(); return closed == 1 }) {
		t.Fatal("the tap was not told of the socket's end")
	}
	if wrote, read, _ := tap.said(); len(wrote) == 0 || len(read) == 0 {
		t.Errorf("told of %d written and %d read", len(wrote), len(read))
	}
	// A context that carries no tap, or a tap that gives none, has none told.
	if quicTapOf(context.Background(), nil, nil) != nil || withQUICTap(context.Background(), nil) != context.Background() {
		t.Error("a tap where none was given")
	}
	none := withQUICTap(context.Background(), func(context.Context, net.Addr, net.Addr) QUICPacketTap { return nil })
	if quicTapOf(none, nil, nil) != nil {
		t.Error("a tap where the one given gave none")
	}
}

func TestAQUICDialThatFailsTellsTheTapOfTheSocketsEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports ICMP errors otherwise")
	}
	tap := &tapped{}
	ctx := withQUICTap(context.Background(), func(context.Context, net.Addr, net.Addr) QUICPacketTap { return tap })
	tlsCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "a.test"}
	if _, err := dialQUICAt(ctx, closedUDPPort(t, net.IPv4(127, 0, 0, 1)), tlsCfg, connectedPolicy(t, true), nil); err == nil {
		t.Fatal("dialled a closed port")
	}
	if _, _, closed := tap.said(); closed != 1 {
		t.Errorf("told of the socket's end %d times", closed)
	}
}
