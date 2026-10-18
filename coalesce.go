package tls_client

import (
	"errors"
	"net"
	"net/netip"
	"strconv"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	tls "github.com/igor-lemon/utls"
)

// Connection coalescing (WithConnectionCoalescing): a request to a host goes
// out on an HTTP/2 connection to another, as Chrome sends it when the
// connection fits (Chromium's SpdySessionPool and SpdySession::CanPool). The
// shared transport's pool asks coalescable when it holds no connection for a
// host:port, and a request to a host the client has no transport for yet is
// offered the pool's connections before it dials (coalesced).

// coalesceWith has rt share its HTTP/2 connections across hosts, looking
// hosts up with lookup, unless lookup is nil or its connections are not for
// sharing: through a proxy, Chrome pools none, and a connection's address is
// the proxy's; with a server name overwritten, every connection was verified
// for that one; with client certificates, Chrome pools none on which one was
// sent, which only the handshake knew; and protocol racing dials apart.
func (rt *roundTripper) coalesceWith(lookup LookupFunc) {
	if rt.proxyURL != "" || rt.serverNameOverwrite != "" || rt.racer != nil ||
		rt.transportOptions != nil && len(rt.transportOptions.Certificates) > 0 {
		return
	}
	rt.lookup = lookup
}

// coalesced sends req to addr, a host:port rt has no transport for yet, on a
// connection of the shared transport's that fits, when one does; sent is
// false when none did, and nothing was sent.
func (rt *roundTripper) coalesced(shared *http2.Transport, req *http.Request, addr string) (resp *http.Response, sent bool, err error) {
	resp, err = shared.RoundTripOpt(req, http2.RoundTripOpt{OnlyCachedConn: true})
	if errors.Is(err, http2.ErrNoCachedConn) {
		return nil, false, nil
	}
	if errors.Is(err, errProtocolChanged) {
		// Tried again on a connection of its own, which spoke HTTP/1.1.
		rt.dropCachedTransport(addr, shared)
	}
	return resp, true, err
}

// coalescable is the connection of conns, the shared transport's that can
// take a request, that req to addr may go out on, or nil: one whose
// certificate was verified, without an error then, and is good for the host,
// on which the host's pins hold, at an address lookup finds the host at and
// on its port; the first such address, then the oldest connection. None while
// a connection dialed for addr waits to be taken up, which the request is
// to go out on.
func (rt *roundTripper) coalescable(req *http.Request, addr string, conns []net.Conn) net.Conn {
	if _, waiting := rt.stashed.Load(addr); waiting {
		return nil
	}
	host, port, _ := net.SplitHostPort(addr)
	var fit []net.Conn
	var at []netip.Addr
	for _, conn := range conns {
		// Every connection of the shared pool's is one dialTLS made.
		uconn := conn.(*tls.UConn)
		state := uconn.ConnectionState()
		if len(state.VerifiedChains) == 0 || state.VerifiedChains[0][0].VerifyHostname(host) != nil ||
			rt.certificatePinner.Pin(uconn, host) != nil {
			continue
		}
		// An address that is no IP's parses as none, which no lookup finds.
		remote, _ := netip.ParseAddrPort(uconn.RemoteAddr().String())
		if strconv.Itoa(int(remote.Port())) != port {
			continue
		}
		fit, at = append(fit, conn), append(at, remote.Addr())
	}
	if len(fit) == 0 {
		// Looked up only when a connection could carry it.
		return nil
	}
	// A lookup that fails finds nothing.
	found, _ := rt.lookup(req.Context(), host)
	for _, ip := range found {
		for i, conn := range fit {
			if at[i] == ip.Unmap() {
				rt.adopt(addr)
				return conn
			}
		}
	}
	return nil
}

// adopt has the requests to addr go to the shared transport, whose pool now
// holds a connection for it, and the connections dialed for it later be
// taken as HTTP/2 ones; unless addr has a transport of its own by now.
func (rt *roundTripper) adopt(addr string) {
	rt.cachedTransportsLck.Lock()
	defer rt.cachedTransportsLck.Unlock()
	if rt.cachedTransports[addr] == nil {
		rt.cachedTransports[addr] = rt.shared
	}
	if rt.cachedTransports[addr] == rt.shared {
		rt.setCachedKind(addr, transportHTTP2)
	}
}
