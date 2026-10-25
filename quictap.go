package tls_client

import (
	"context"
	"net"
)

// A QUICPacketTap is told of a QUIC connection's datagrams as its socket
// wrote and read them, one at a time, and of the socket's end. What it is
// given it may not keep.
type QUICPacketTap interface {
	Wrote(b []byte)
	Read(b []byte)
	Closed()
}

// quicTap is what a QUIC connection's socket asks for the tap it tells of
// its datagrams (HTTP3FromDNS.Tap).
type quicTap = func(ctx context.Context, local, remote net.Addr) QUICPacketTap

type quicTapKey struct{}

// withQUICTap is ctx carrying tap to the QUIC connection dialed with it.
func withQUICTap(ctx context.Context, tap quicTap) context.Context {
	if tap == nil {
		return ctx
	}
	return context.WithValue(ctx, quicTapKey{}, tap)
}

// quicTapOf is the tap of the QUIC connection dialed with ctx, its socket's
// from local to remote, or nil.
func quicTapOf(ctx context.Context, local, remote net.Addr) QUICPacketTap {
	if tap, _ := ctx.Value(quicTapKey{}).(quicTap); tap != nil {
		return tap(ctx, local, remote)
	}
	return nil
}
