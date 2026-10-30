package tests

import (
	"crypto/tls"
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
	"github.com/stretchr/testify/assert"
)

// TestClient_ProtocolChangeWithRacingRecovers is the protocol change of
// TestClient_ProtocolChangeBetweenConnections with protocol racing turned on.
//
// Racing takes its own route through RoundTrip and returns before the branch
// that drops a transport the server has outgrown, so the stale transport used
// to survive every retry. The racer clears its own protocol cache when a
// request fails, which looks like recovery but is not: the next request races
// again, reaches for the very same cached transport, and fails on the same
// mismatch. The address stayed broken for the life of the client.
//
// Once the racing adapter dispatches, an error is returned to its owner;
// its caches are invalidated, and the next caller request establishes h2.
// There is no fallback replay of an unsafe request after a dispatch error.
func TestClient_ProtocolChangeWithRacingRecovers(t *testing.T) {
	var handshakes int64
	var origins atomic.Int64

	cert := selfSignedCert(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			config := &tls.Config{Certificates: []tls.Certificate{cert}}
			if atomic.AddInt64(&handshakes, 1) == 1 {
				config.NextProtos = []string{"http/1.1"}
			} else {
				config.NextProtos = []string{http2.NextProtoTLS}
			}
			return config, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go serveChangingProtocol(listener, func(r *http.Request) { origins.Add(1); require.NotEqual(t, http.MethodPost, r.Method) })

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(profiles.Chrome_133),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithProtocolRacing(),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(client.CloseIdleConnections)
	endpoint := fmt.Sprintf("https://%s/", listener.Addr().String())

	// The HTTP/3 leg has nothing to talk to here, so the HTTP/2 leg wins every
	// race. The first one negotiates http/1.1 and caches an HTTP/1 transport.
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "HTTP/1.1", resp.Proto)

	// The failed POST must not be replayed by racing. A subsequent caller
	// request is allowed to use the freshly negotiated protocol.
	req2, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader("do not replay"))
	require.NoError(t, err)
	failed, err := client.Do(req2)
	require.ErrorContains(t, err, "does not speak")
	require.Nil(t, failed)
	require.EqualValues(t, 1, origins.Load())

	for i := 3; i <= 3; i++ {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v, want a rebuilt transport speaking the protocol the server moved to", i, err)
		}

		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "HTTP/2.0", resp.Proto)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		resp.Body.Close()
	}
	require.EqualValues(t, 2, origins.Load())
}
