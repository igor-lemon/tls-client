package tls_client

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	tls "github.com/igor-lemon/utls"
)

type forwardProxyDialer interface {
	ForwardProxyURL() *url.URL
	DialProxyContext(context.Context, string, string) (net.Conn, error)
}

// Implemented by a proxy dialer with one partition-scoped outer H2 pool.
type sharedForwardProxyDialer interface {
	RoundTripProxyHTTP(*http.Request, http.RoundTripper) (*http.Response, error)
	ProxyHTTP2Protocol(*tls.Conn) http.RoundTripper
	CloseIdleProxyConnections()
}

func (rt *roundTripper) forwardHTTPTransport() http.RoundTripper {
	t := rt.buildHttp1Transport()
	d, ok := rt.dialer.(forwardProxyDialer)
	if !ok || !rt.behavior.Flag("proxy.forward_http") {
		return t
	}
	u := d.ForwardProxyURL()
	if u == nil {
		return t
	}
	t.Proxy = http.ProxyURL(u)
	t.DialContext = d.DialProxyContext
	t.DialTLSContext = d.DialProxyContext
	forward := forwardProxyTransport{Transport: t}
	if u.User != nil {
		password, _ := u.User.Password()
		forward.proxyAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+password))
	}
	if u.Scheme == "https" {
		if shared, ok := d.(sharedForwardProxyDialer); ok {
			forward.shared = shared
			t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{"h2": func(_ string, c *tls.Conn) http.RoundTripper { return shared.ProxyHTTP2Protocol(c) }}
			return forward
		}
		h2, err := http2.ConfigureTransports(t)
		if err != nil {
			return forwardProxyFailure{err}
		}
		// The no-dial pool returns a lost/changed ALPN connection to the proxy
		// transport for negotiation. It must never dial an origin directly.
		h2.AllowHTTP, h2.Behavior = true, rt.behavior.Clone()
		h2.Settings, h2.SettingsOrder, h2.ConnectionFlow = rt.settings, rt.settingsOrder, rt.connectionFlow
		h2.HeaderPriority, h2.PseudoHeaderOrder, h2.Priorities = rt.headerPriority, rt.pseudoHeaderOrder, rt.priorities
		h2.HeaderRepresentation, h2.MaxEncoderHeaderTableSize = rt.headerRepresentation, rt.maxEncoderTableSize
		h2.WindowUpdateDelay = rt.windowUpdateDelay
		h2.MaxHeaderFramePayload, h2.MaxDataFramePayload = rt.maxHeaderFramePayload, rt.maxDataFramePayload
		h2.StrictMaxConcurrentStreams, h2.InitialStreamID = rt.strictMaxConcurrentStreams, rt.initialStreamID
		h2.DisableCompression, h2.IdleConnTimeout = t.DisableCompression, t.IdleConnTimeout
		if enabled, known := h2.Settings[http2.SettingEnablePush]; !known || enabled != 0 {
			h2.PushHandler = &http2.DefaultPushHandler{}
		}
		forward.h2 = h2
	}
	return forward
}

type forwardProxyTransport struct {
	*http.Transport
	h2        *http2.Transport
	proxyAuth string
	shared    sharedForwardProxyDialer
}

type forwardProxyFailure struct{ err error }

func (t forwardProxyFailure) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

func (t forwardProxyTransport) CloseIdleConnections() {
	t.Transport.CloseIdleConnections()
	if t.shared != nil {
		t.shared.CloseIdleProxyConnections()
	}
	if t.h2 != nil {
		t.h2.CloseIdleConnections()
	}
}

func (t forwardProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := *req
	original := req.HeaderFor
	copy.HeaderFor = func(protocol string, header http.Header) http.Header {
		if original != nil {
			if h := original(protocol, header); h != nil {
				header = h
			}
		}
		if protocol != http.ProtocolHTTP1 {
			if t.proxyAuth != "" {
				header = header.Clone()
				header.Set("Proxy-Authorization", t.proxyAuth)
				header[http.HeaderOrderKey] = append(append([]string(nil), header[http.HeaderOrderKey]...), "proxy-authorization")
			}
			return header
		}
		header = header.Clone()
		for name := range header {
			if strings.EqualFold(name, "connection") {
				delete(header, name)
			}
		}
		header.Set("Proxy-Connection", "keep-alive")
		order := append([]string(nil), header[http.HeaderOrderKey]...)
		found := false
		for i, name := range order {
			if strings.EqualFold(name, "connection") {
				order[i], found = "proxy-connection", true
			}
		}
		if !found {
			order = append(order, "proxy-connection")
		}
		header[http.HeaderOrderKey] = order
		return header
	}
	var res *http.Response
	var err error
	if t.shared != nil {
		res, err = t.shared.RoundTripProxyHTTP(&copy, t.Transport)
	} else {
		res, err = t.Transport.RoundTrip(&copy)
	}
	if err == nil && res.StatusCode == 407 {
		res.Body.Close()
		return nil, fmt.Errorf("proxy: HTTP 407 Proxy Authentication Required")
	}
	return res, err
}
