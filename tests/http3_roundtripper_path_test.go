package tests

import (
	"crypto/md5"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"github.com/stretchr/testify/require"
	"io"
	"testing"

	http "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
)

func TestHTTP3DirectPathChrome(t *testing.T) {
	t.Run("raw_catalogue_ALPN", func(t *testing.T) { checkRawCatalogueALPN(t, profiles.Chrome_144) })
	endpoint := newOwnedHTTP3Peer(t, 3)
	policy := ownedDNSH3Policy(t)
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_144.WithBehavior(policy)),
		tls_client.WithTimeoutSeconds(10),
		tls_client.WithInsecureSkipVerify(),
		ownedHTTP3DNSOption(),
		// No racing: the explicit DNS HTTPS route selects the direct H3 adapter.
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

	req.Header = http.Header{
		"accept":          {"*/*"},
		"accept-language": {"en-US,en;q=0.9"},
		"user-agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"},
		http.HeaderOrderKey: {
			"accept",
			"accept-language",
			"user-agent",
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, "HTTP/3.0", resp.Proto)
	var observed BrowserLeaksResponse
	require.NoError(t, json.Unmarshal(body, &observed))
	require.Equal(t, []string{":method", ":authority", ":scheme", ":path"}, ownedH3PseudoNames(observed.RequestHeaders))
	require.NoError(t, validateOwnedH3Control(observed.ControlWire, policy, [][2]uint64{{1, 65536}, {7, 100}, {51, 1}}, []uint64{33, 984832}))
	require.Equal(t, fmt.Sprintf("%x", md5.Sum([]byte(observed.H3Text))), observed.H3Hash)
	t.Logf("Chrome_144 HTTP/3 direct path test completed")
	t.Logf("Observed hash: %s", observed.H3Hash)
	t.Logf("Protocol used: %s", resp.Proto)
}

func TestHTTP3DirectPathFirefox(t *testing.T) {
	t.Run("raw_catalogue_ALPN", func(t *testing.T) { checkRawCatalogueALPN(t, profiles.Firefox_147) })
	endpoint := newOwnedHTTP3Peer(t, 2)
	policy := ownedDNSH3Policy(t)
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Firefox_147.WithBehavior(policy)),
		tls_client.WithTimeoutSeconds(10),
		tls_client.WithInsecureSkipVerify(),
		ownedHTTP3DNSOption(),
		// No racing: the explicit DNS HTTPS route selects the direct H3 adapter.
		tls_client.WithTransportOptions(&tls_client.TransportOptions{
			MaxResponseHeaderBytes: -1, // Firefox doesn't send SETTINGS_MAX_FIELD_SECTION_SIZE
		}),
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

	req.Header = http.Header{
		"accept":          {"*/*"},
		"accept-language": {"en-US,en;q=0.9"},
		"user-agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"},
		http.HeaderOrderKey: {
			"accept",
			"accept-language",
			"user-agent",
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, "HTTP/3.0", resp.Proto)
	var observed BrowserLeaksResponse
	require.NoError(t, json.Unmarshal(body, &observed))
	require.Equal(t, []string{":method", ":scheme", ":authority", ":path"}, ownedH3PseudoNames(observed.RequestHeaders))
	require.NoError(t, validateOwnedH3Control(observed.ControlWire, policy, [][2]uint64{{1, 65536}, {7, 20}, {727725890, 0}, {16765559, 1}, {51, 1}, {8, 1}}, []uint64{33}))
	require.Equal(t, fmt.Sprintf("%x", md5.Sum([]byte(observed.H3Text))), observed.H3Hash)
	t.Logf("Firefox_147 HTTP/3 direct path test completed")
	t.Logf("Observed hash: %s", observed.H3Hash)
	t.Logf("Protocol used: %s", resp.Proto)
}

// The complete technical routing fixture is the engine1 chrome155 behavior
// from the owner profile. Combining it with old catalogue hellos is an adapter
// control, not a new browser capture or a catalogue migration.
//
//go:embed testdata/direct-h3-policy.json
var ownedDNSH3JSON []byte

func ownedDNSH3Policy(t *testing.T) behavior.Policy {
	t.Helper()
	var policy behavior.Policy
	require.NoError(t, json.Unmarshal(ownedDNSH3JSON, &policy))
	require.NoError(t, policy.Validate())
	return policy
}

func checkRawCatalogueALPN(t *testing.T, profile profiles.ClientProfile) {
	endpoint := newOwnedFingerprintPeer(t)
	client, err := tls_client.NewHttpClient(nil, tls_client.WithClientProfile(profile), tls_client.WithServerNameOverwrite("owned.example"), tls_client.WithInsecureSkipVerify(), tls_client.WithTimeoutSeconds(5))
	require.NoError(t, err)
	t.Cleanup(client.CloseIdleConnections)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	require.NoError(t, err)
	res, err := client.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, "HTTP/2.0", res.Proto, "raw TCP ALPN does not advertise h3")
	_, err = io.Copy(io.Discard, res.Body)
	require.NoError(t, err)
}
