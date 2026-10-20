package tls_client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	_ "github.com/bdandy/go-socks4" // due to that proxy.FromURL() does support socks4
	http "github.com/igor-lemon/fhttp"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/igor-lemon/fhttp/http2"
)

type directDialer struct {
	dialer net.Dialer
}

func newDirectDialer(timeout time.Duration, localAddr *net.TCPAddr, _dialer net.Dialer) proxy.ContextDialer {
	_dialer.Timeout = timeout
	if nil != localAddr {
		_dialer.LocalAddr = localAddr
	}

	return &directDialer{
		dialer: _dialer,
	}
}

func (d *directDialer) Dial(network, addr string) (net.Conn, error) {
	return d.dialer.Dial(network, addr)
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}

type socksContextDialer struct {
	// within is the dialer of a dial within a context: SOCKS5's one, SOCKS4's
	// one of the dial's own.
	within func(ctx context.Context) proxy.Dialer
}

func newSocksContextDialer(socksDialer proxy.Dialer) socksContextDialer {
	return socksContextDialer{
		within: func(context.Context) proxy.Dialer { return socksDialer },
	}
}

// DialContext dials address through the proxy within ctx. SOCKS5's dialer
// takes ctx, its talk with the proxy too. SOCKS4's takes none: the request
// waits for it no longer than ctx lets it, a connection it makes after that
// is closed, and its talk with the proxy ends at the dial's timeout
// (deadlineDialer).
func (s *socksContextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	socksDialer := s.within(ctx)
	if d, ok := socksDialer.(proxy.ContextDialer); ok {
		return d.DialContext(ctx, network, address)
	}

	type dialed struct {
		conn net.Conn
		err  error
	}
	done := make(chan dialed, 1)
	go func() {
		conn, err := socksDialer.Dial(network, address)
		done <- dialed{conn, err}
	}()

	select {
	case d := <-done:
		if d.err != nil {
			return nil, d.err
		}
		_ = d.conn.SetDeadline(time.Time{})
		return d.conn, nil
	case <-ctx.Done():
		go func() {
			if d := <-done; d.err == nil {
				_ = d.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// contextOr is why ctx ended, when it did, what cut a dial short; else err.
func contextOr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		// Past it, though its own timer has yet to say so: a connection's
		// deadline set to the same time went off first.
		return context.DeadlineExceeded
	}
	return err
}

// deadlineDialer dials as its dialer does, and gives each connection a
// deadline of the dialer's timeout, for a talk over it that takes no context:
// a SOCKS4 proxy's. Whoever takes the connection clears it. Each goes through
// wrap, when set, with ctx, the context of the dial it is for, unless that
// ended before it connected: the dial has been given up on, and the
// connection is closed (socksContextDialer).
type deadlineDialer struct {
	dialer net.Dialer
	ctx    context.Context
	wrap   ProxyConnWrapper
}

func (d *deadlineDialer) Dial(network, address string) (net.Conn, error) {
	began := time.Now()
	conn, err := d.dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}
	if d.ctx.Err() == nil {
		conn = wrapConn(d.ctx, d.wrap, conn, began)
	}
	if d.dialer.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(d.dialer.Timeout))
	}
	return conn, nil
}

// wrappingDialer dials as its dialer does, within the context it is given,
// and each connection goes through wrap, when set: SOCKS5's connection to its
// proxy, which x/net's dialer talks over within that context.
type wrappingDialer struct {
	dialer net.Dialer
	wrap   ProxyConnWrapper
}

func (d *wrappingDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *wrappingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	began := time.Now()
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return wrapConn(ctx, d.wrap, conn, began), nil
}

// wrapConn is conn, dialed to a proxy within ctx from began, as wrap has the
// client talk over it, or as it is without a wrap.
func wrapConn(ctx context.Context, wrap ProxyConnWrapper, conn net.Conn, began time.Time) net.Conn {
	if wrap == nil {
		return conn
	}
	return wrap(ctx, conn, began)
}

// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// stolen from https://github.com/caddyserver/forwardproxy/blob/master/httpclient/httpclient.go

// connectDialer allows to configure one-time use HTTP CONNECT client
type connectDialer struct {
	logger          Logger
	cachedH2RawConn net.Conn
	DefaultHeader   http.Header

	// overridden DialTLS allows user to control establishment of TLS connection
	// MUST return connection with completed Handshake, and NegotiatedProtocol
	DialTLS            func(network string, address string) (net.Conn, string, error)
	cachedH2ClientConn *http2.ClientConn
	ProxyUrl           url.URL

	Dialer net.Dialer // overridden dialer allow to control establishment of TCP connection

	Timeout           time.Duration
	cacheH2Mu         sync.Mutex
	EnableH2ConnReuse bool

	// wrap is what each connection to the proxy goes through; nil, nothing.
	wrap ProxyConnWrapper
}

// newConnectDialer creates a dialer to issue CONNECT requests and tunnel traffic via HTTP/S proxy.
// proxyUrlStr must provide Scheme and Host, may provide credentials and port.
// Example: https://username:password@golang.org:443
func newConnectDialer(proxyUrlStr string, timeout time.Duration, localAddr *net.TCPAddr, configDialer net.Dialer, connectHeaders http.Header, wrap ProxyConnWrapper, logger Logger) (proxy.ContextDialer, error) {
	proxyUrl, err := url.Parse(proxyUrlStr)
	if err != nil {
		return nil, err
	}

	if proxyUrl.Host == "" {
		return nil, errors.New("invalid url `" + proxyUrlStr +
			"`, make sure to specify full url like https://username:password@hostname.com:443/")
	}

	_dialer := configDialer
	_dialer.Timeout = timeout
	if nil != localAddr {
		_dialer.LocalAddr = localAddr
	}

	switch proxyUrl.Scheme {
	case "http":
		if proxyUrl.Port() == "" {
			proxyUrl.Host = net.JoinHostPort(proxyUrl.Host, "80")
		}
	case "https":
		if proxyUrl.Port() == "" {
			proxyUrl.Host = net.JoinHostPort(proxyUrl.Host, "443")
		}
	case "socks4", "socks4a":
		return handleSocks4ProxyDialer(proxyUrl, _dialer, wrap)
	case "socks5", "socks5h":
		return handleSocks5ProxyDialer(proxyUrl, _dialer, wrap)
	case "":
		return nil, errors.New("specify scheme explicitly (https://)")
	default:
		return nil, errors.New("scheme " + proxyUrl.Scheme + " is not supported")
	}

	dialer := &connectDialer{
		logger:            logger,
		ProxyUrl:          *proxyUrl,
		Dialer:            _dialer,
		Timeout:           timeout,
		DefaultHeader:     connectHeaders.Clone(),
		EnableH2ConnReuse: true,
		wrap:              wrap,
	}

	if proxyUrl.User != nil {
		if proxyUrl.User.Username() != "" {
			// example format (with credentials): http://root:xxx@127.0.0.1:12312
			password, _ := proxyUrl.User.Password()
			dialer.DefaultHeader.Set("Proxy-Authorization", "Basic "+
				base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.Username()+":"+password)))

		}
	}
	return dialer, nil
}

func handleSocks5ProxyDialer(proxyUrl *url.URL, dialer net.Dialer, wrap ProxyConnWrapper) (proxy.ContextDialer, error) {
	var proxyAuth *proxy.Auth
	if proxyUrl.User != nil {
		password, _ := proxyUrl.User.Password()
		proxyAuth = &proxy.Auth{
			User:     proxyUrl.User.Username(),
			Password: password,
		}
	} else {
		proxyAuth = nil
	}

	socksDialer, err := proxy.SOCKS5("tcp", proxyUrl.Host, proxyAuth, &wrappingDialer{dialer: dialer, wrap: wrap})
	if err != nil {
		return nil, fmt.Errorf("failed to create socks5 proxy: %w", err)
	}

	scd := newSocksContextDialer(socksDialer)

	return &scd, nil
}

func handleSocks4ProxyDialer(proxyUrl *url.URL, dialer net.Dialer, wrap ProxyConnWrapper) (proxy.ContextDialer, error) {
	if _, err := proxy.FromURL(proxyUrl, &deadlineDialer{dialer: dialer}); err != nil {
		return nil, fmt.Errorf("failed to create socks4 proxy dialer: %w", err)
	}

	// A dialer of go-socks4's for each dial, made as that one was, over a
	// deadlineDialer of the dial's context, which hands its connection to the
	// proxy to wrap with that context.
	scd := socksContextDialer{within: func(ctx context.Context) proxy.Dialer {
		socks4Dialer, _ := proxy.FromURL(proxyUrl, &deadlineDialer{dialer: dialer, ctx: ctx, wrap: wrap})
		return socks4Dialer
	}}
	return &scd, nil
}

func (c *connectDialer) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// Users of context.WithValue should define their own types for keys
type ContextKeyHeader struct{}

// ctx.Value will be inspected for optional ContextKeyHeader{} key, with `http.Header` value,
// which will be added to outgoing request headers, overriding any colliding c.DefaultHeader
func (c *connectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	req := (&http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)

	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}

	if ctxHeader, ctxHasHeader := ctx.Value(ContextKeyHeader{}).(http.Header); ctxHasHeader {
		for k, v := range ctxHeader {
			req.Header[k] = v
		}
	}

	connectHttp2 := func(rawConn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		pr, pw := io.Pipe()
		req.Body = pr

		resp, err := h2clientConn.RoundTrip(req)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = rawConn.Close()
			return nil, errors.New("Proxy responded with non 200 code: " + resp.Status)
		}

		return newHttp2Conn(rawConn, pw, resp.Body), nil
	}

	connectHttp1 := func(rawConn net.Conn) (net.Conn, error) {
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		deadline := time.Now().Add(c.Timeout)
		err := rawConn.SetDeadline(deadline)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		// And no longer than the request is wanted.
		stop := context.AfterFunc(ctx, func() { _ = rawConn.SetDeadline(time.Now()) })

		err = req.Write(rawConn)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.logger.Error("deadline exceeded while trying to write proxy connection")
			}

			_ = rawConn.Close()
			return nil, err
		}

		resp, err := http.ReadResponse(bufio.NewReader(rawConn), req)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.logger.Error("deadline exceeded while trying to read proxy connection")
			}

			_ = rawConn.Close()
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = rawConn.Close()
			return nil, errors.New("Proxy responded with non 200 code: " + resp.Status)
		}

		// A request let go of as the proxy answered may find the deadline
		// past: it is no longer wanted.
		stop()
		rawConn.SetDeadline(time.Time{})

		return rawConn, nil
	}

	if c.EnableH2ConnReuse {
		c.cacheH2Mu.Lock()
		unlocked := false
		if c.cachedH2ClientConn != nil && c.cachedH2RawConn != nil {
			if c.cachedH2ClientConn.CanTakeNewRequest() {
				rc := c.cachedH2RawConn
				cc := c.cachedH2ClientConn
				c.cacheH2Mu.Unlock()
				unlocked = true

				proxyConn, err := connectHttp2(rc, cc)
				if err == nil {
					return proxyConn, err
				}
				// else: carry on and try again
			}
		}
		if !unlocked {
			c.cacheH2Mu.Unlock()
		}
	}

	var err error
	var rawConn net.Conn
	negotiatedProtocol := ""
	switch c.ProxyUrl.Scheme {
	case "http":
		began := time.Now()
		rawConn, err = c.Dialer.DialContext(ctx, network, c.ProxyUrl.Host)

		if err != nil {
			return nil, err
		}
		rawConn = wrapConn(ctx, c.wrap, rawConn, began)
	case "https":
		if c.DialTLS != nil {
			rawConn, negotiatedProtocol, err = c.DialTLS(network, c.ProxyUrl.Host)
			if err != nil {
				return nil, err
			}
		} else {
			tlsConf := tls.Config{
				NextProtos: []string{"h2", "http/1.1"},
				ServerName: c.ProxyUrl.Hostname(),
			}
			// As tls.Dialer dials with no dialer of its own, the TCP
			// connection through the wrapper.
			began := time.Now()
			var tcp net.Dialer
			dialed, err := tcp.DialContext(ctx, network, c.ProxyUrl.Host)
			if err != nil {
				return nil, err
			}
			dialed = wrapConn(ctx, c.wrap, dialed, began)
			tlsConn := tls.Client(dialed, &tlsConf)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = dialed.Close()
				return nil, err
			}
			negotiatedProtocol = tlsConn.ConnectionState().NegotiatedProtocol
			rawConn = tlsConn
		}
	default:
		return nil, errors.New("scheme " + c.ProxyUrl.Scheme + " is not supported")
	}

	switch negotiatedProtocol {
	case "":
		fallthrough
	case "http/1.1":
		return connectHttp1(rawConn)
	case "h2":
		t := http2.Transport{}
		h2clientConn, err := t.NewClientConn(rawConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		proxyConn, err := connectHttp2(rawConn, h2clientConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		if c.EnableH2ConnReuse {
			c.cacheH2Mu.Lock()
			c.cachedH2ClientConn = h2clientConn
			c.cachedH2RawConn = rawConn
			c.cacheH2Mu.Unlock()
		}
		return proxyConn, err
	default:
		_ = rawConn.Close()
		return nil, errors.New("negotiated unsupported application layer protocol: " +
			negotiatedProtocol)
	}
}

func newHttp2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	return errors.Join(h.in.Close(), h.out.Close())
}

func (h *http2Conn) CloseConn() error {
	return h.Conn.Close()
}

func (h *http2Conn) CloseWrite() error {
	return h.in.Close()
}

func (h *http2Conn) CloseRead() error {
	return h.out.Close()
}
