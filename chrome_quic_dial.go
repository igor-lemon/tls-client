package tls_client

import (
	"context"
	cryptorand "crypto/rand"
	"net"
	"sync"

	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"golang.org/x/net/ipv4"
)

// A dedicated socket has no source-ID demultiplexing requirement. A shared
// socket must retain its nonempty IDs; never just erase the wire parameter.
type emptyQUICConnectionIDs struct{}

func (emptyQUICConnectionIDs) ConnectionIDLen() int { return 0 }
func (emptyQUICConnectionIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionID{}, nil
}

func dialChromeQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return dialProfileQUIC(ctx, addr, tlsCfg, cfg)
}

type profileQUICConnectionIDs struct{ length int }

func (g profileQUICConnectionIDs) ConnectionIDLen() int { return g.length }
func (g profileQUICConnectionIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	b := make([]byte, g.length)
	_, err := cryptorand.Read(b)
	return quic.ConnectionIDFromBytes(b), err
}
func dialProfileQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	remote, err := resolveUDPAddr(ctx, addr, nil)
	if err != nil {
		return nil, err
	}
	return dialQUICAt(ctx, remote, tlsCfg, cfg, nil)
}

// dialQUICAt makes a QUIC connection to remote over a UDP socket of its own,
// with source connection IDs as long as the profile says, the socket
// connected to remote where the profile says quic.connected_socket; sent,
// when there is one, is called once its first datagram has gone out, and
// the tap ctx carries (withQUICTap) is told of every datagram and of the
// socket's end.
func dialQUICAt(ctx context.Context, remote *net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, sent func()) (*quic.Conn, error) {
	network := "udp4"
	local := &net.UDPAddr{IP: net.IPv4zero}
	if remote.IP.To4() == nil {
		network = "udp6"
		local.IP = net.IPv6unspecified
	}
	var socket *net.UDPConn
	var err error
	connected := cfg.Policy().Flag("quic.connected_socket")
	if connected {
		socket, err = net.DialUDP(network, local, remote)
	} else {
		socket, err = net.ListenUDP(network, local)
	}
	if err != nil {
		return nil, err
	}
	tap := quicTapOf(ctx, socket.LocalAddr(), remote)
	var packets net.PacketConn = socket
	var s *quicSocket
	switch {
	case connected:
		s = newConnectedSocket(socket, sent)
	case sent != nil || tap != nil:
		s = newSentFirst(socket, sent)
	}
	if s != nil {
		s.tap = tap
		packets = s
	}
	closed := func() {
		_ = socket.Close()
		if tap != nil {
			tap.Closed()
		}
	}
	// quic.DialEarly uses a single-use transport that permits zero source IDs.
	transport := &quic.Transport{Conn: packets, ConnectionIDGenerator: profileQUICConnectionIDs{cfg.Policy().Int("quic.source_cid_bytes")}}
	conn, err := transport.DialEarly(ctx, remote, tlsCfg, cfg)
	if err != nil {
		_ = transport.Close()
		closed()
		return nil, err
	}
	go func() { <-conn.Context().Done(); _ = transport.Close(); closed() }()
	return conn, nil
}

// quicSocket is a QUIC connection's socket of its own. With sent, it calls
// it once the first datagram written to it has gone, whatever became of the
// write: when its connection is under way, as Chromium's QUIC job is once it
// sent its first packet. Connected, it is connected to the server, as
// Chrome's is: an ICMP error the server's host answers a datagram with comes
// back to it as the error of its next read or write, which ends the
// connection at once; quic-go writes to an address, which a connected socket
// takes none of. With tap, it tells it of every datagram it writes and
// reads. It is all quic-go asks of a *net.UDPConn (OOBCapablePacketConn),
// and reads its batches as quic-go reads the socket's (ipv4.PacketConn), so
// the connection reads and writes as it would on the socket itself.
type quicSocket struct {
	*net.UDPConn
	batch     *ipv4.PacketConn
	connected bool
	once      sync.Once
	sent      func()
	tap       QUICPacketTap
}

func newSentFirst(socket *net.UDPConn, sent func()) *quicSocket {
	return &quicSocket{UDPConn: socket, batch: ipv4.NewPacketConn(socket), sent: sent}
}

func newConnectedSocket(socket *net.UDPConn, sent func()) *quicSocket {
	s := newSentFirst(socket, sent)
	s.connected = true
	return s
}

func (c *quicSocket) said() {
	if c.sent != nil {
		c.once.Do(c.sent)
	}
}

func (c *quicSocket) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	defer c.said()
	if c.connected {
		addr = nil
	}
	n, oobn, err := c.UDPConn.WriteMsgUDP(b, oob, addr)
	if err == nil {
		c.wrote(b[:n], oob)
	}
	return n, oobn, err
}

func (c *quicSocket) WriteTo(b []byte, addr net.Addr) (int, error) {
	defer c.said()
	var n int
	var err error
	if c.connected {
		n, err = c.UDPConn.Write(b)
	} else {
		n, err = c.UDPConn.WriteTo(b, addr)
	}
	if err == nil {
		c.wrote(b[:n], nil)
	}
	return n, err
}

// wrote tells the tap of the datagrams a write of b with oob sent.
func (c *quicSocket) wrote(b, oob []byte) {
	if c.tap == nil {
		return
	}
	for _, d := range datagramsOf(b, oob) {
		c.tap.Wrote(d)
	}
}

// ReadFrom is how quic-go reads a socket it cannot read in batches, one
// datagram at a time (its basicConn: Windows, and any system it has no OOB
// path for).
func (c *quicSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if err == nil && c.tap != nil {
		c.tap.Read(b[:n])
	}
	return n, addr, err
}

func (c *quicSocket) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	n, err := c.batch.ReadBatch(ms, flags)
	if c.tap != nil {
		for _, m := range ms[:max(n, 0)] {
			if len(m.Buffers) > 0 {
				c.tap.Read(m.Buffers[0][:min(m.N, len(m.Buffers[0]))])
			}
		}
	}
	return n, err
}
