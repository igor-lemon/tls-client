package tests

import (
	"github.com/stretchr/testify/require"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	http "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
	"github.com/stretchr/testify/assert"
)

func TestWeb(t *testing.T) {
	var requests atomic.Int64
	endpoint, roots := newOwnedVerifiedTLSPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		require.Equal(t, http.MethodPost, r.Method)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Empty(t, body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(func() { require.EqualValues(t, 1, requests.Load()) })
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Firefox_110),
		tls_client.WithTransportOptions(&tls_client.TransportOptions{RootCAs: roots}),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(client.CloseIdleConnections)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}
