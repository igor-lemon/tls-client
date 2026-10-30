package tests

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"github.com/quic-go/qpack"
	"io"
	"testing"

	http "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
)

type BrowserLeaksResponse struct {
	ControlWire    []byte              `json:"control_wire"`
	RequestHeaders []qpack.HeaderField `json:"request_headers"`
	H3Hash         string              `json:"h3_hash"`
	H3Text         string              `json:"h3_text"`
}

// This is the raw catalogue adapter contract, not browser equivalence:
// Chrome_144 has no SETTINGS 6 value, and its unset behavior selects the
// frozen generic control ordering (priority before GREASE). An old external
// hash incorrectly asserted Chrome defaults. Explicit browser profiles and
// TestHTTP3ExplicitFieldSectionLimitComesFromProfile own their choices.
func TestHTTP3FingerprintChrome443(t *testing.T) {
	endpoint := newOwnedHTTP3Peer(t, 3)
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_144),
		tls_client.WithTimeoutSeconds(10),
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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var browserLeaksResp BrowserLeaksResponse
	if err := json.Unmarshal(body, &browserLeaksResp); err != nil {
		t.Logf("JSON unmarshal error: %v", err)
		t.Fatal(err)
	}

	expectedH3Hash := "92b6c44ee005a3249070c7399668fb47"
	expectedH3Text := "1:65536;7:100;51:1;GREASE|984832|GREASE|m,a,s,p"

	if browserLeaksResp.H3Hash != expectedH3Hash {
		t.Errorf("Chrome_144 HTTP/3 hash mismatch.\nexpected: %s\nactual  : %s", expectedH3Hash, browserLeaksResp.H3Hash)
	}

	if browserLeaksResp.H3Text != expectedH3Text {
		t.Errorf("Chrome_144 HTTP/3 fingerprint mismatch.\nexpected: %s\nactual  : %s", expectedH3Text, browserLeaksResp.H3Text)
	}

	t.Logf("Chrome_144 HTTP/3 fingerprint: %s", browserLeaksResp.H3Text)
	t.Logf("Chrome_144 HTTP/3 hash: %s", browserLeaksResp.H3Hash)
}

func TestHTTP3FingerprintFirefox135(t *testing.T) {
	endpoint := newOwnedHTTP3Peer(t, 2)
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Firefox_147),
		tls_client.WithTimeoutSeconds(10),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithProtocolRacing(),
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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var browserLeaksResp BrowserLeaksResponse
	if err := json.Unmarshal(body, &browserLeaksResp); err != nil {
		t.Logf("JSON unmarshal error: %v", err)
		t.Fatal(err)
	}

	expectedH3Hash := "d50d4e585c22bb92b6c86b592aa2d586"
	expectedH3Text := "1:65536;7:20;727725890:0;16765559:1;51:1;8:1|GREASE|m,s,a,p"

	if browserLeaksResp.H3Hash != expectedH3Hash {
		t.Errorf("Firefox_147 HTTP/3 hash mismatch.\nexpected: %s\nactual  : %s", expectedH3Hash, browserLeaksResp.H3Hash)
	}

	if browserLeaksResp.H3Text != expectedH3Text {
		t.Errorf("Firefox_147 HTTP/3 fingerprint mismatch.\nexpected: %s\nactual  : %s", expectedH3Text, browserLeaksResp.H3Text)
	}

	t.Logf("Firefox_147 HTTP/3 fingerprint: %s", browserLeaksResp.H3Text)
	t.Logf("Firefox_147 HTTP/3 hash: %s", browserLeaksResp.H3Hash)
}

// Chrome_133 has no H3 map: the legacy raw transport uses its 10 MiB
// default. This fixture records that adapter contract; it is not a recapture
// of Chrome133. Separate explicit-profile witnesses retain 262144/0/omitted.
func TestHTTP3FingerprintWithDefaultValuesForChrome(t *testing.T) {
	endpoint := newOwnedHTTP3Peer(t, 1)
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_133),
		tls_client.WithTimeoutSeconds(10),
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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var browserLeaksResp BrowserLeaksResponse
	if err := json.Unmarshal(body, &browserLeaksResp); err != nil {
		t.Logf("JSON unmarshal error: %v", err)
		t.Fatal(err)
	}

	// An unordered legacy SETTINGS map has two legal serializations. Do not
	// normalize explicit profile order. Keep received text/hash together, and
	// reject wrong/missing/extra values in either order.
	legal := map[string]bool{"6:10485760;51:1|m,a,s,p": true, "51:1;6:10485760|m,a,s,p": true}
	if !legal[browserLeaksResp.H3Text] {
		t.Errorf("legacy raw SETTINGS: %s", browserLeaksResp.H3Text)
	}
	if want := fmt.Sprintf("%x", md5.Sum([]byte(browserLeaksResp.H3Text))); browserLeaksResp.H3Hash != want {
		t.Errorf("raw fingerprint hash=%s want=%s", browserLeaksResp.H3Hash, want)
	}

	t.Logf("Chrome_133 HTTP/3 fingerprint: %s", browserLeaksResp.H3Text)
	t.Logf("Chrome_133 HTTP/3 hash: %s", browserLeaksResp.H3Hash)
}
