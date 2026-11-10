package tests

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	http "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
)

// trustAnchorsExtension is the code point of the trust_anchors extension.
const trustAnchorsExtension = 0xca34

// chromeProfile is the profile these tests use. Every Chrome profile hands
// the extension the same bytes, so one covers them all. This one is the newest,
// so it is the wiring most likely to be wrong.
const chromeProfileName = "Chrome_152_PSK"

var chromeProfile = profiles.Chrome_152_PSK

// wireProfiles are the profiles the wire tests run over. [tls-client fork]
// Both Chrome 152 profiles, the one that offers a PSK and the one that does
// not, as the fork's tests did before v1.18.0 took them down to one
// (F09-101 to F09-108 are witnessed by each).
var wireProfiles = []struct {
	name    string
	profile profiles.ClientProfile
}{{"Chrome_152", profiles.Chrome_152}, {"Chrome_152_PSK", profiles.Chrome_152_PSK}}

// chromeRootStore39Capture is the payload stable Chrome 152.0.7977.64 on
// Android sent, from the "Unknown extension 51764" data field of a tls.peet.ws
// fingerprint. It carries Chrome Root Store 39 and no MTC anchors, so it holds
// the IDs of testdata/chrome_root_store_v39.pb.
//
// It is a historical fact and never changes. One capture is enough: another
// browser with the same store sends the same IDs in another order, and order is
// not what this checks.
const chromeRootStore39Capture = "00b80582df13020108839a648c9b2d010c08839a648c9b2d010704d679090c08839a648c9b2d010a04d679090b08839a648c9b2d010d0582df13020e08839a648c9b2d010b04d67909050582df13020d0582df13021404d679090404d679090804d679090d04d679090a04d679090708839a648c9b2d011204d67909010582df13020608839a648c9b2d01080582df13021208839a648c9b2d011304d679090f0582df13021308839a648c9b2d01090582df13020f04d6790906"

// chromeListPath is the list gen_chrome_trust_anchors.go writes.
const chromeListPath = "../trust_anchors/chrome_generated.go"

var chromeCaptureField = regexp.MustCompile(`chromeCapture = "([0-9a-f]+)"`)

// chromeCapture reads the payload every Chrome profile must send from the
// generated list, so no copy of it lives in this file.
func chromeCapture(t *testing.T) string {
	t.Helper()

	source, err := os.ReadFile(chromeListPath)
	if err != nil {
		t.Fatal(err)
	}

	match := chromeCaptureField.FindSubmatch(source)
	if match == nil {
		t.Fatalf("%s holds no chromeCapture", chromeListPath)
	}

	return string(match[1])
}

// splitTrustAnchors parses a RequestedTrustAnchorList the way a server does. It
// returns the IDs in the order they arrived and fails the test on a malformed
// payload.
func splitTrustAnchors(t *testing.T, payload []byte) []string {
	t.Helper()

	if len(payload) < 2 {
		t.Fatalf("payload of %d bytes is shorter than its length field", len(payload))
	}

	list := payload[2:]
	if length := int(payload[0])<<8 | int(payload[1]); length != len(list) {
		t.Fatalf("length field says %d bytes, list holds %d", length, len(list))
	}

	var ids []string

	for i := 0; i < len(list); {
		end := i + 1 + int(list[i])
		if end > len(list) {
			t.Fatalf("ID at offset %d runs past the end of the list", i)
		}

		ids = append(ids, hex.EncodeToString(list[i+1:end]))
		i = end
	}

	return ids
}

// checkTrustAnchorIDs fails the test unless the payload holds the IDs of the
// capture, each of them once and none of them missing. The order is free,
// because Chromium writes the IDs in hash set iteration order.
func checkTrustAnchorIDs(t *testing.T, name string, capture string, payload []byte) {
	t.Helper()

	want, err := hex.DecodeString(capture)
	if err != nil {
		t.Fatal(err)
	}

	got := sortedTrustAnchorIDs(t, payload)
	expected := sortedTrustAnchorIDs(t, want)

	if len(got) != len(expected) {
		t.Fatalf("%s sent %d trust anchor IDs, expected %d", name, len(got), len(expected))
	}

	for i, id := range got {
		if id != expected[i] {
			t.Errorf("%s sent %v, expected %v", name, got, expected)
			return
		}
	}
}

// sortedTrustAnchorIDs parses a payload and returns its IDs in sorted order.
func sortedTrustAnchorIDs(t *testing.T, payload []byte) []string {
	t.Helper()

	ids := splitTrustAnchors(t, payload)
	sort.Strings(ids)

	return ids
}

// trustAnchorsFromSpec returns the payload of the single trust_anchors
// extension of the ClientHello.
func trustAnchorsFromSpec(t *testing.T, profile profiles.ClientProfile) []byte {
	t.Helper()

	spec, err := profile.GetClientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}

	var payloads [][]byte

	for _, extension := range spec.Extensions {
		if generic, ok := extension.(*tls.GenericExtension); ok && generic.Id == trustAnchorsExtension {
			payloads = append(payloads, generic.Data)
		}
	}

	if len(payloads) != 1 {
		t.Fatalf("%s sends %d trust_anchors extensions, expected 1", profile.GetClientHelloStr(), len(payloads))
	}

	return payloads[0]
}

// TestChromeTrustAnchors checks the trust_anchors extension (0xca34). The profile puts
// the IDs in a new order once per program run, the way Chromium's hash set order
// holds for the life of a process. Neither JA3 nor JA4 covers the contents of an
// extension, so client_test.go cannot detect a broken payload.
func TestChromeTrustAnchors(t *testing.T) {
	capture := chromeCapture(t)
	payloads := map[string]int{}

	for run := 1; run <= 2; run++ {
		t.Run(fmt.Sprintf("run_%d", run), func(t *testing.T) {
			payload := trustAnchorsFromSpec(t, chromeProfile)

			checkTrustAnchorIDs(t, chromeProfileName, capture, payload)

			payloads[hex.EncodeToString(payload)]++
		})
	}

	// One program run keeps one order, so every ClientHello of this test must
	// carry the same payload.
	if len(payloads) != 1 {
		t.Errorf("%s sent %d different payloads in one program run, expected 1", chromeProfileName, len(payloads))
	}

	// The IDs have far more orders than a test can meet by chance, so a payload
	// that repeats the capture means the reordering did not run.
	if payloads[capture] > 0 {
		t.Errorf("%s repeats the captured order, so the IDs were not reordered", chromeProfileName)
	}
}

// TestChromeTrustAnchorsOnTheWire checks what a server receives. It confirms that the
// payload survives the handshake and that the JA4 fingerprint does not move
// with it.
func TestChromeTrustAnchorsOnTheWire(t *testing.T) {
	// [tls-client fork] an owned peer, not tls.peet.ws: tests reach no network.
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	capture := chromeCapture(t)

	for _, wire := range wireProfiles {
		t.Run(wire.name, func(t *testing.T) {
			var ja4Values []string

			for run := 1; run <= 2; run++ {
				t.Run(fmt.Sprintf("run_%d", run), func(t *testing.T) {
					options := []tls_client.HttpClientOption{
						skipPeetCertVerify,
						tls_client.WithServerNameOverwrite("owned.example"),
						tls_client.WithClientProfile(wire.profile),
						tls_client.WithTimeoutSeconds(120),
					}

					client, err := tls_client.NewHttpClient(nil, options...)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(client.CloseIdleConnections)

					req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
					if err != nil {
						t.Fatal(err)
					}

					req.Header = defaultHeader

					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}

					defer resp.Body.Close()

					readBytes, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatal(err)
					}

					tlsApiResponse := TlsApiResponse{}
					if err := json.Unmarshal(readBytes, &tlsApiResponse); err != nil {
						t.Fatal(err)
					}

					// tls.peet.ws reports the extension as "Unknown extension 51764"
					// today and may name it once the draft lands, so match the code
					// point in decimal and not the name around it.
					data := ""
					code := strconv.Itoa(trustAnchorsExtension)

					for _, extension := range tlsApiResponse.TLS.Extensions {
						if strings.Contains(extension.Name, code) {
							data = extension.Data
							break
						}
					}

					if data == "" {
						t.Fatalf("%s sent no trust_anchors extension", wire.name)
					}

					payload, err := hex.DecodeString(data)
					if err != nil {
						t.Fatalf("%s sent %q, which is not hex", wire.name, data)
					}

					checkTrustAnchorIDs(t, wire.name, capture, payload)

					// The wire payload must be the one the profile holds.
					if want := hex.EncodeToString(trustAnchorsFromSpec(t, wire.profile)); data != want {
						t.Errorf("%s sent %s, the profile holds %s", wire.name, data, want)
					}

					if tlsApiResponse.TLS.Ja4 == "" {
						t.Fatalf("%s got no ja4 value from %s", wire.name, peetApiEndpoint)
					}

					ja4Values = append(ja4Values, tlsApiResponse.TLS.Ja4)
				})
			}

			// JA4 counts extensions but not their contents, so the payload must not
			// move the fingerprint.
			for _, value := range ja4Values {
				if value != ja4Values[0] {
					t.Errorf("%s ja4 changed between connections: %v", wire.name, ja4Values)
					break
				}
			}
		})
	}
}

// TestChromeTrustAnchorsAreAcceptedByAServer sends the extension to a server that reads
// it. Certificate verification stays on, so the whole handshake must hold.
//
// It covers the shape of the payload, not the IDs. A server that knows no ID in
// the list falls back to its normal certificate and still answers 204. The tests
// above cover the IDs.
func TestChromeTrustAnchorsAreAcceptedByAServer(t *testing.T) {
	// [tls-client fork] an owned verifying peer, not Google's: tests reach no
	// network.
	generate204Endpoint, roots := newOwnedVerifiedTLSPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, wire := range wireProfiles {
		t.Run(wire.name, func(t *testing.T) {
			client, err := tls_client.NewHttpClient(nil,
				tls_client.WithClientProfile(wire.profile),
				tls_client.WithTimeoutSeconds(30),
				tls_client.WithTransportOptions(&tls_client.TransportOptions{RootCAs: roots}),
			)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.CloseIdleConnections)

			req, err := http.NewRequest(http.MethodGet, generate204Endpoint, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header = defaultHeader

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s could not reach %s: %s", wire.name, generate204Endpoint, err)
			}

			defer resp.Body.Close()

			if _, err := io.ReadAll(resp.Body); err != nil {
				t.Fatalf("%s could not read the body: %s", wire.name, err)
			}

			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("%s got status %d from %s, expected %d", wire.name, resp.StatusCode, generate204Endpoint, http.StatusNoContent)
			}
		})
	}
}

// [tls-client fork] TestChromeTrustAnchorsMatchUpstream, which runs the
// generator against the live Chrome Root Store, is left out: tests reach no
// network. `go generate ./trust_anchors` refreshes the list.

// TestChromeTrustAnchorsSelectionRule checks which fields the generator keeps:
// every trust_anchors entry, and an additional_certs entry only with
// tls_trust_anchor: true. Today 15 of the 28 IDs come from additional_certs.
//
// It runs the generator over a frozen crs.pb and compares the result with a
// browser capture of the same store. Every other test compares generated output
// with generated output. Input and result are frozen, so a root store update
// does not touch this test.
func TestChromeTrustAnchorsSelectionRule(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join("testdata", "chrome_root_store_v39.pb"))
	if err != nil {
		t.Fatal(err)
	}

	fresh := filepath.Join(t.TempDir(), "chrome_trust_anchors_generated.go")

	cmd := exec.Command("go", "run", "gen_chrome.go", "-source", fixture, "-out", fresh)
	cmd.Dir = "../trust_anchors"

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the generator failed: %s: %s", err, out)
	}

	source, err := os.ReadFile(fresh)
	if err != nil {
		t.Fatal(err)
	}

	match := chromeCaptureField.FindSubmatch(source)
	if match == nil {
		t.Fatalf("the generator wrote no chromeCapture for %s", fixture)
	}

	generated, err := hex.DecodeString(string(match[1]))
	if err != nil {
		t.Fatal(err)
	}

	captured, err := hex.DecodeString(chromeRootStore39Capture)
	if err != nil {
		t.Fatal(err)
	}

	got := sortedTrustAnchorIDs(t, generated)
	want := sortedTrustAnchorIDs(t, captured)

	if len(got) != len(want) {
		t.Fatalf("the frozen root store gives %d IDs, the browser sent %d", len(got), len(want))
	}

	for i, id := range got {
		if id != want[i] {
			t.Fatalf("the frozen root store gives %v, the browser sent %v", got, want)
		}
	}
}
