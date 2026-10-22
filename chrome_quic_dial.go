package tls_client

import (
	"context"
	"net"

	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
)

// A dedicated socket has no source-ID demultiplexing requirement. A shared
// socket must retain its nonempty IDs; never just erase the wire parameter.
type emptyQUICConnectionIDs struct{}

func (emptyQUICConnectionIDs) ConnectionIDLen() int { return 0 }
func (emptyQUICConnectionIDs) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionID{}, nil
}

func dialChromeQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	remote, err := resolveUDPAddr(ctx, addr, nil)
	if err != nil {
		return nil, err
	}
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
	// quic.DialEarly uses a single-use transport that permits zero source IDs.
	conn, err := quic.DialEarly(ctx, socket, remote, tlsCfg, cfg)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	go func() { <-conn.Context().Done(); _ = socket.Close() }()
	return conn, nil
}
