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

func TestHTTP3WithChromeOnCloudflare(t *testing.T) {
	endpoint := newOwnedHTTP3Peer(t, 3)
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_144),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithProtocolRacing(),
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

	if !strings.Contains(string(body), "http=http/3") {
		t.Fatal("Response did not contain HTTP3 result")
	}
}

func TestHTTP2WithChromeOnCloudflare(t *testing.T) {
	endpoint := newOwnedHTTP2TracePeer(t)
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_144),
		tls_client.WithInsecureSkipVerify(),
		// tls_client.WithProtocolRacing(), // we explicitly disable racing and stick to the "old" behavior
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

	if !strings.Contains(string(body), "http=http/2") {
		t.Fatal("Response did contain HTTP3 result")
	}
}
