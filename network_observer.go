package tls_client

import (
	"context"
	"net"
	"time"
)

func (c *httpClientConfig) networkProxyWrapper() ProxyConnWrapper {
	existing := c.wrapProxyConn
	if c.transportOptions == nil || c.transportOptions.NetworkObserver == nil || c.transportOptions.NetworkObserver.TCPConnection == nil {
		return existing
	}
	observe := c.transportOptions.NetworkObserver.TCPConnection
	return func(ctx context.Context, conn net.Conn, began time.Time) net.Conn {
		conn = observe(ctx, conn)
		if existing != nil {
			conn = existing(ctx, conn, began)
		}
		return conn
	}
}

func (rt *roundTripper) observeTCP(ctx context.Context, conn net.Conn) net.Conn {
	// Built-in proxies already observe the underlying socket before CONNECT.
	if rt.proxyURL == "" && rt.transportOptions != nil && rt.transportOptions.NetworkObserver != nil && rt.transportOptions.NetworkObserver.TCPConnection != nil {
		return rt.transportOptions.NetworkObserver.TCPConnection(ctx, conn)
	}
	return conn
}
