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
)

type forwardProxyDialer interface {
	ForwardProxyURL() *url.URL
	DialProxyContext(context.Context, string, string) (net.Conn, error)
}

func (rt *roundTripper) forwardHTTPTransport() http.RoundTripper {
	t := rt.buildHttp1Transport()
	d, ok := rt.dialer.(forwardProxyDialer)
	if !ok || !rt.chromeBehavior {
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
		h2, err := http2.ConfigureTransports(t)
		if err != nil {
			return forwardProxyFailure{err}
		}
		// The no-dial pool returns a lost/changed ALPN connection to the proxy
		// transport for negotiation. It must never dial an origin directly.
		h2.AllowHTTP, h2.ChromeBehavior = true, rt.chromeBehavior
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
}

type forwardProxyFailure struct{ err error }

func (t forwardProxyFailure) RoundTrip(*http.Request) (*http.Response, error) { return nil, t.err }

func (t forwardProxyTransport) CloseIdleConnections() {
	t.Transport.CloseIdleConnections()
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
	res, err := t.Transport.RoundTrip(&copy)
	if err == nil && res.StatusCode == 407 {
		res.Body.Close()
		return nil, fmt.Errorf("proxy: HTTP 407 Proxy Authentication Required")
	}
	return res, err
}
