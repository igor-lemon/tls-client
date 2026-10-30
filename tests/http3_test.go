package tests

import (
	"github.com/stretchr/testify/require"
	"io"
	"strings"
	"testing"

	http "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
)

func TestHTTP3(t *testing.T) {
	endpoint := newOwnedHTTP3Peer(t, 3)
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_144),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithProtocolRacing(),
		tls_client.WithDebug(),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(client.CloseIdleConnections)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()
	require.Equal(t, "HTTP/3.0", resp.Proto)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(body), "it does support HTTP/3!") {
		t.Fatal("Response did not contain HTTP3 result")
	}
}

func TestDisableHTTP3(t *testing.T) {
	endpoint := newOwnedHTTP2TracePeer(t)
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_144),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithDisableHttp3(),
		tls_client.WithDebug(),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(client.CloseIdleConnections)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()
	require.Equal(t, "HTTP/2.0", resp.Proto)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(body), "HTTP/3 (h3-29 or h3-27) was not used to request this page") {
		t.Fatal("Response did contain HTTP3 result")
	}
}
