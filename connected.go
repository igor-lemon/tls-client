package tls_client

import (
	"net"
	"syscall"
)

// connected says whether conn's peer has not closed it, as Chromium's socket
// pool asks of an idle socket never used before it hands it out
// (IdleSocket::IsUsable, IsConnected): data waiting is no reason against it.
// The connections a connection is made on are looked through (NetConn) down
// to the socket; one that cannot be peeked at is taken as connected.
func connected(conn net.Conn) bool {
	for {
		if c, ok := conn.(syscall.Conn); ok {
			return peerOpen(c)
		}
		inner, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			return true
		}
		conn = inner.NetConn()
	}
}
