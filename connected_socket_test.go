package tls_client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
	"golang.org/x/net/ipv4"
)

func TestAConnectedSocketWritesWithoutAnAddress(t *testing.T) {
	peer := loopbackUDP(t)
	socket, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	var said atomic.Int32
	c := newConnectedSocket(socket, func() { said.Add(1) })
	// quic-go names the server's address; a connected socket takes none
	if _, err := c.WriteTo([]byte("a"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.WriteMsgUDP([]byte("b"), nil, peer.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if said.Load() != 1 {
		t.Errorf("said %d times, want once", said.Load())
	}
	b := make([]byte, 8)
	for _, want := range []string{"a", "b"} {
		if n, _, err := peer.ReadFrom(b); err != nil || string(b[:n]) != want {
			t.Errorf("the peer read %q, %v, want %q", b[:n], err, want)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	if _, err := peer.WriteTo([]byte("back"), socket.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	ms := []ipv4.Message{{Buffers: [][]byte{make([]byte, 16)}, OOB: make([]byte, 64)}}
	if n, err := c.ReadBatch(ms, 0); err != nil || n != 1 || string(ms[0].Buffers[0][:ms[0].N]) != "back" {
		t.Errorf("read %d in a batch, %q, %v", n, ms[0].Buffers[0][:ms[0].N], err)
	}
	// without a callback nothing is said
	quiet := newConnectedSocket(socket, nil)
	if _, err := quiet.WriteTo([]byte("c"), nil); err != nil {
		t.Fatal(err)
	}
}

// closedUDPPort is a loopback address of ip's family nothing listens on for
// UDP: a datagram sent to it is answered by ICMP port unreachable.
func closedUDPPort(t *testing.T, ip net.IP) *net.UDPAddr {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("no loopback address %s here: %v", ip, err)
	}
	addr := c.LocalAddr().(*net.UDPAddr)
	_ = c.Close()
	return addr
}

func connectedPolicy(t *testing.T, connected bool) *quic.Config {
	t.Helper()
	p := behavior.Legacy()
	p["quic.connected_socket"] = json.RawMessage(map[bool]string{true: "true", false: "false"}[connected])
	p["quic.handshake_idle_timeout_ms"] = json.RawMessage("500")
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return &quic.Config{Behavior: p, Versions: []quic.Version{quic.Version1}}
}

func TestAQUICConnectionToAPortNobodyListensOnFailsAtOnceAsChromes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports ICMP errors otherwise")
	}
	for _, ip := range []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback} {
		t.Run(ip.String(), func(t *testing.T) {
			remote := closedUDPPort(t, ip)
			tlsCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "a.test"}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := time.Now()
			_, err := dialQUICAt(ctx, remote, tlsCfg, connectedPolicy(t, true), nil)
			took := time.Since(start)
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("dialled a closed port connected: %v, want the refusal", err)
			}
			if took > 400*time.Millisecond {
				t.Errorf("the refusal took %s, past the first probe", took)
			}
			// an unconnected socket hears nothing of it, and waits out its idle time
			start = time.Now()
			_, err = dialQUICAt(ctx, remote, tlsCfg, connectedPolicy(t, false), nil)
			if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatalf("dialled a closed port unconnected: %v", err)
			}
			if took := time.Since(start); took < 500*time.Millisecond {
				t.Errorf("an unconnected socket gave up after %s, before its idle time", took)
			}
		})
	}
}

func TestASocketThatCannotBeConnectedFailsTheDial(t *testing.T) {
	// port 0 is no address to connect to
	_, err := dialQUICAt(context.Background(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, connectedPolicy(t, true), nil)
	if err == nil {
		t.Fatal("dialled port 0")
	}
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "dial" {
		t.Skipf("this system connects a socket to port 0: %v", err)
	}
}
