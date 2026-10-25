package tls_client

import (
	"context"
	"net"
	"runtime"
	"sync/atomic"
	"testing"

	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"golang.org/x/net/ipv4"
)

func TestASocketSaysOnceItsFirstDatagramHasGone(t *testing.T) {
	for _, how := range []string{"WriteTo", "WriteMsgUDP"} {
		peer := loopbackUDP(t)
		socket := loopbackUDP(t)
		var said atomic.Int32
		c := newSentFirst(socket, func() { said.Add(1) })
		if said.Load() != 0 {
			t.Fatalf("%s: said before anything was written", how)
		}
		for range 2 {
			var err error
			if how == "WriteTo" {
				_, err = c.WriteTo([]byte("x"), peer.LocalAddr())
			} else {
				_, _, err = c.WriteMsgUDP([]byte("x"), nil, peer.LocalAddr().(*net.UDPAddr))
			}
			if err != nil {
				t.Fatal(err)
			}
			if said.Load() != 1 {
				t.Errorf("%s: said %d times, want once", how, said.Load())
			}
		}
		b := make([]byte, 8)
		if n, _, err := peer.ReadFrom(b); err != nil || string(b[:n]) != "x" {
			t.Errorf("%s: the peer read %q, %v", how, b[:n], err)
		}
		if runtime.GOOS == "windows" {
			// quic-go reads a socket there a datagram at a time, not in batches.
			continue
		}
		if _, err := peer.WriteTo([]byte("back"), socket.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		ms := []ipv4.Message{{Buffers: [][]byte{make([]byte, 16)}, OOB: make([]byte, 64)}}
		if n, err := c.ReadBatch(ms, 0); err != nil || n != 1 || string(ms[0].Buffers[0][:ms[0].N]) != "back" {
			t.Errorf("%s: read %d in a batch, %q, %v", how, n, ms[0].Buffers[0][:ms[0].N], err)
		}
	}
}

func TestAFirstWriteThatFailsSaysTheConnectionIsUnderWayToo(t *testing.T) {
	socket := loopbackUDP(t)
	var said atomic.Int32
	c := newSentFirst(socket, func() { said.Add(1) })
	_ = socket.Close()
	if _, err := c.WriteTo([]byte("x"), socket.LocalAddr()); err == nil {
		t.Fatal("wrote on a closed socket")
	}
	if said.Load() != 1 {
		t.Errorf("said %d times, want once", said.Load())
	}
}

func loopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestAQUICConnectionIsMadeWhetherOrNotItsFirstPacketIsWaitedFor(t *testing.T) {
	o := newH3Origin(t, originSays{})
	config := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	conn, err := dialProfileQUIC(context.Background(), o.addr, config.Clone(), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.CloseWithError(0, "")
	var said atomic.Int32
	remote, err := net.ResolveUDPAddr("udp4", o.addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err = dialQUICAt(context.Background(), remote, config.Clone(), &quic.Config{}, func() { said.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.CloseWithError(0, "")
	if said.Load() != 1 {
		t.Errorf("said %d times that its first packet went, want once", said.Load())
	}
}
