package tls_client

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/tls-client/profiles"
	"github.com/igor-lemon/utls/behavior"
	"golang.org/x/net/proxy"
)

// forwardingDialer is a proxy dialer whose proxy forwards plain HTTP, as
// tls-forge's dialer of an HTTP proxy is.
type forwardingDialer struct{ addr string }

func (d forwardingDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d forwardingDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.addr)
}

func (d forwardingDialer) ForwardProxyURL() *url.URL { return &url.URL{Scheme: "http", Host: d.addr} }

func (d forwardingDialer) DialProxyContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.DialContext(ctx, network, addr)
}

// forwardedHead is the head of the one request a proxy is sent, of a Chrome
// 133 client whose behavior is the legacy Chromium one with these laid over
// it ("" takes one out).
func forwardedHead(t *testing.T, laid map[string]string) []string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	head := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(conn)
		var lines []string
		for {
			line, err := r.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
			lines = append(lines, strings.TrimRight(line, "\r\n"))
		}
		head <- lines
		conn.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
	}()
	p := behavior.Legacy()
	p["proxy.forward_http"] = json.RawMessage("true")
	for k, v := range laid {
		if v == "" {
			delete(p, k)
			continue
		}
		p[k] = json.RawMessage(v)
	}
	dialer := forwardingDialer{ln.Addr().String()}
	client, err := NewHttpClient(NewNoopLogger(), WithClientProfile(profiles.Chrome_133.WithBehavior(p)),
		WithProxyDialerFactory(func(string, time.Duration, *net.TCPAddr, http.Header, Logger) (proxy.ContextDialer, error) {
			return dialer, nil
		}), WithTimeoutSeconds(5))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://site.test/page", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = http.Header{"Connection": {"keep-alive"}, "Accept": {"*/*"},
		http.HeaderOrderKey: {"host", "connection", "accept"}}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return <-head
}

func TestAForwardedRequestSaysProxyConnectionAsTheProfileSays(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  string
	}{
		{`"keep-alive"`, "Proxy-Connection: keep-alive"},
		{`"close"`, "Proxy-Connection: close"},
		// A profile that says none: keep-alive, as before.
		{"", "Proxy-Connection: keep-alive"},
	} {
		lines := forwardedHead(t, map[string]string{"proxy.connection_value": tc.value})
		if len(lines) < 3 || lines[0] != "GET http://site.test/page HTTP/1.1" || lines[2] != tc.want {
			t.Errorf("%s: %q", tc.value, lines)
		}
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "connection:") {
				t.Errorf("%s: a Connection field went to the proxy: %q", tc.value, lines)
			}
		}
	}
}
