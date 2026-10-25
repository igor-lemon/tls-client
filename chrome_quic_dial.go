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
// when there is one, is called once its first datagram has gone out.
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
	var packets net.PacketConn = socket
	if connected {
		packets = newConnectedSocket(socket, sent)
	} else if sent != nil {
		packets = newSentFirst(socket, sent)
	}
	// quic.DialEarly uses a single-use transport that permits zero source IDs.
	transport := &quic.Transport{Conn: packets, ConnectionIDGenerator: profileQUICConnectionIDs{cfg.Policy().Int("quic.source_cid_bytes")}}
	conn, err := transport.DialEarly(ctx, remote, tlsCfg, cfg)
	if err != nil {
		_ = transport.Close()
		_ = socket.Close()
		return nil, err
	}
	go func() { <-conn.Context().Done(); _ = transport.Close(); _ = socket.Close() }()
	return conn, nil
}

// quicSocket is a QUIC connection's socket of its own. With sent, it calls
// it once the first datagram written to it has gone, whatever became of the
// write: when its connection is under way, as Chromium's QUIC job is once it
// sent its first packet. Connected, it is connected to the server, as
// Chrome's is: an ICMP error the server's host answers a datagram with comes
// back to it as the error of its next read or write, which ends the
// connection at once; quic-go writes to an address, which a connected socket
// takes none of. It is all quic-go asks of a *net.UDPConn
// (OOBCapablePacketConn), and reads its batches as quic-go reads the
// socket's (ipv4.PacketConn), so the connection reads and writes as it would
// on the socket itself.
type quicSocket struct {
	*net.UDPConn
	batch     *ipv4.PacketConn
	connected bool
	once      sync.Once
	sent      func()
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
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (c *quicSocket) WriteTo(b []byte, addr net.Addr) (int, error) {
	defer c.said()
	if c.connected {
		return c.UDPConn.Write(b)
	}
	return c.UDPConn.WriteTo(b, addr)
}

func (c *quicSocket) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	return c.batch.ReadBatch(ms, flags)
}
