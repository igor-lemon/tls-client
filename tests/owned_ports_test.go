package tests

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

// TCP and UDP have independent ephemeral-port allocators. Reserve both before
// starting an oracle; only a setup EADDRINUSE may select another owned pair.
func reserveOwnedH3Ports(listenUDP func() (net.PacketConn, error), listenTCP func(string) (net.Listener, error)) (net.PacketConn, net.Listener, error) {
	var last error
	for range 32 {
		packets, err := listenUDP()
		if err != nil {
			return nil, nil, err
		}
		tcp, err := listenTCP(packets.LocalAddr().String())
		if err == nil {
			return packets, tcp, nil
		}
		_ = packets.Close()
		last = err
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("reserve owned TCP/UDP pair: %w", last)
}
func listenOwnedH3Ports() (net.PacketConn, net.Listener, error) {
	return reserveOwnedH3Ports(func() (net.PacketConn, error) { return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}) }, func(addr string) (net.Listener, error) { return net.Listen("tcp4", addr) })
}

type ownedPacketStub struct{ closed bool }

func (s *ownedPacketStub) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, io.EOF }
func (s *ownedPacketStub) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (s *ownedPacketStub) Close() error                              { s.closed = true; return nil }
func (s *ownedPacketStub) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (s *ownedPacketStub) SetDeadline(time.Time) error      { return nil }
func (s *ownedPacketStub) SetReadDeadline(time.Time) error  { return nil }
func (s *ownedPacketStub) SetWriteDeadline(time.Time) error { return nil }

type ownedListenerStub struct{}

func (*ownedListenerStub) Accept() (net.Conn, error) { return nil, io.EOF }
func (*ownedListenerStub) Close() error              { return nil }
func (*ownedListenerStub) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func TestOwnedH3PortsReleaseOnlyCollidingSetupPairs(t *testing.T) {
	var sockets []*ownedPacketStub
	attempts := 0
	udp := func() (net.PacketConn, error) { s := &ownedPacketStub{}; sockets = append(sockets, s); return s, nil }
	packets, tcp, err := reserveOwnedH3Ports(udp, func(addr string) (net.Listener, error) {
		attempts++
		if addr != "127.0.0.1:12345" {
			t.Fatal(addr)
		}
		if attempts == 1 {
			return nil, &net.OpError{Err: syscall.EADDRINUSE}
		}
		return &ownedListenerStub{}, nil
	})
	if err != nil || packets == nil || tcp == nil || attempts != 2 || !sockets[0].closed || sockets[1].closed {
		t.Fatalf("bad setup lifecycle attempts%d err%v sockets%+v", attempts, err, sockets)
	}
	packets.Close()
	tcp.Close()
	for _, failure := range []error{syscall.EACCES, io.ErrUnexpectedEOF} {
		attempts = 0
		sockets = nil
		_, _, err = reserveOwnedH3Ports(udp, func(string) (net.Listener, error) { attempts++; return nil, failure })
		if !errors.Is(err, failure) || attempts != 1 || !sockets[0].closed {
			t.Fatal("noncollision retried or socket leaked", err)
		}
	}
	attempts = 0
	sockets = nil
	_, _, err = reserveOwnedH3Ports(udp, func(string) (net.Listener, error) { attempts++; return nil, syscall.EADDRINUSE })
	if !errors.Is(err, syscall.EADDRINUSE) || attempts != 32 {
		t.Fatal("unbounded setup", attempts, err)
	}
	for _, s := range sockets {
		if !s.closed {
			t.Fatal("collision leaked UDP")
		}
	}
	_, _, err = reserveOwnedH3Ports(func() (net.PacketConn, error) { return nil, syscall.EACCES }, func(string) (net.Listener, error) { t.Fatal("TCP attempted after UDP failure"); return nil, nil })
	if !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
}
