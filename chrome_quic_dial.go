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
// with source connection IDs as long as the profile says; sent, when there is
// one, is called once its first datagram has gone out.
func dialQUICAt(ctx context.Context, remote *net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, sent func()) (*quic.Conn, error) {
	network := "udp4"
	local := &net.UDPAddr{IP: net.IPv4zero}
	if remote.IP.To4() == nil {
		network = "udp6"
		local.IP = net.IPv6unspecified
	}
	socket, err := net.ListenUDP(network, local)
	if err != nil {
		return nil, err
	}
	var packets net.PacketConn = socket
	if sent != nil {
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

// sentFirst is a QUIC connection's socket that calls sent once the first
// datagram written to it has gone, whatever became of the write: when its
// connection is under way, as Chromium's QUIC job is once it sent its first
// packet. It is all quic-go asks of a *net.UDPConn (OOBCapablePacketConn), and
// reads its batches as quic-go reads the socket's (ipv4.PacketConn), so the
// connection reads and writes as it would on the socket itself.
type sentFirst struct {
	*net.UDPConn
	batch *ipv4.PacketConn
	once  sync.Once
	sent  func()
}

func newSentFirst(socket *net.UDPConn, sent func()) *sentFirst {
	return &sentFirst{UDPConn: socket, batch: ipv4.NewPacketConn(socket), sent: sent}
}

func (c *sentFirst) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	defer c.once.Do(c.sent)
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (c *sentFirst) WriteTo(b []byte, addr net.Addr) (int, error) {
	defer c.once.Do(c.sent)
	return c.UDPConn.WriteTo(b, addr)
}

func (c *sentFirst) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	return c.batch.ReadBatch(ms, flags)
}
