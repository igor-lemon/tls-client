package tls_client

import (
	"context"
	"fmt"
	http "github.com/igor-lemon/fhttp"
	"net"
	"net/url"
	"strings"
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
	return forwardProxyTransport{t}
}

type forwardProxyTransport struct{ *http.Transport }

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
				order[i] = "proxy-connection"
				found = true
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
