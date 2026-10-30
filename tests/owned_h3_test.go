package tests

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"github.com/igor-lemon/utls/behavior"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/quic-go-utls/quicvarint"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func ownedH3Frame(typ uint64, payload []byte) []byte {
	out := quicvarint.Append(nil, typ)
	out = quicvarint.Append(out, uint64(len(payload)))
	return append(out, payload...)
}
func readOwnedH3Frame(r io.Reader) (uint64, []byte, error) {
	reader := quicvarint.NewReader(r)
	typ, err := quicvarint.Read(reader)
	if err != nil {
		return 0, nil, err
	}
	n, err := quicvarint.Read(reader)
	if err != nil {
		return 0, nil, err
	}
	if n > 1<<20 {
		return 0, nil, fmt.Errorf("owned H3 frame too large: %d", n)
	}
	payload := make([]byte, int(n))
	_, err = io.ReadFull(r, payload)
	return typ, payload, err
}
func ownedH3Grease(n uint64) bool { return n >= 33 && (n-33)%31 == 0 }

// The peer has no browser/profile argument or expected hash. It reads actual
// ordered SETTINGS and control frames, then independently decodes the received
// static QPACK block (the peer advertises zero dynamic capacity). controlFrames
// is only a synchronization barrier for the scenario, never fingerprint data.
func newOwnedHTTP3Peer(t *testing.T, controlFrames int, seen ...chan<- string) string {
	t.Helper()
	cert := selfSignedCert(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"},
	}, &quic.Config{})
	require.NoError(t, err)
	// The racing TCP leg has an owned, unavailable endpoint. No public DNS or
	// external service is involved and no application request reaches that leg.
	tcp, err := net.Listen("tcp4", ln.Addr().String())
	require.NoError(t, err)
	tcpDone := make(chan struct{})
	go func() {
		defer close(tcpDone)
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	var mu sync.Mutex
	var connections []*quic.Conn
	var work sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			work.Add(1)
			go func() { defer work.Done(); serveOwnedHTTP3(t, conn, controlFrames, seen...) }()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		tcp.Close()
		<-accepted
		<-tcpDone
		mu.Lock()
		active := append([]*quic.Conn(nil), connections...)
		mu.Unlock()
		for _, c := range active {
			c.CloseWithError(0, "")
		}
		work.Wait()
	})
	return "https://" + ln.Addr().String() + "/"
}
func serveOwnedHTTP3(t *testing.T, conn *quic.Conn, wantFrames int, seen ...chan<- string) {
	ctx, cancel := context.WithTimeout(conn.Context(), 5*time.Second)
	defer cancel()
	control, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return
	}
	if _, err = control.Write(append(quicvarint.Append(nil, 0), ownedH3Frame(4, nil)...)); err != nil {
		return
	}
	type observed struct {
		settings []string
		frames   []string
		raw      []byte
		err      error
	}
	got := make(chan observed, 1)
	uniDone := make(chan struct{})
	var readers sync.WaitGroup
	go func() {
		defer close(uniDone)
		for {
			stream, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			stream.SetReadDeadline(time.Now().Add(5 * time.Second))
			kind, err := quicvarint.Read(quicvarint.NewReader(stream))
			if err != nil {
				return
			}
			if kind != 0 {
				stream.SetReadDeadline(time.Now().Add(5 * time.Second))
				readers.Add(1)
				go func() { defer readers.Done(); _, _ = io.Copy(io.Discard, stream) }()
				continue
			}
			stream.SetReadDeadline(time.Now().Add(5 * time.Second))
			observation := observed{}
			for range wantFrames {
				typ, payload, err := readOwnedH3Frame(stream)
				if err != nil {
					observation.err = err
					break
				}
				observation.raw = append(observation.raw, ownedH3Frame(typ, payload)...)
				if typ == 4 {
					r := bytes.NewReader(payload)
					for r.Len() > 0 {
						key, err := quicvarint.Read(r)
						if err != nil {
							observation.err = err
							break
						}
						value, err := quicvarint.Read(r)
						if err != nil {
							observation.err = err
							break
						}
						if ownedH3Grease(key) {
							observation.settings = append(observation.settings, "GREASE")
						} else {
							observation.settings = append(observation.settings, fmt.Sprintf("%d:%d", key, value))
						}
					}
				} else if ownedH3Grease(typ) {
					observation.frames = append(observation.frames, "GREASE")
				} else {
					observation.frames = append(observation.frames, fmt.Sprint(typ))
				}
			}
			got <- observation
			return
		}
	}()
	defer func() { cancel(); <-uniDone; readers.Wait() }()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	var headers []qpack.HeaderField
	for {
		typ, payload, err := readOwnedH3Frame(stream)
		if err != nil {
			t.Errorf("owned request frames: %v", err)
			return
		}
		if typ != 1 {
			continue
		}
		decode := qpack.NewDecoder().Decode(payload)
		for {
			field, err := decode()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("owned QPACK decode: %v", err)
				return
			}
			headers = append(headers, field)
		}
		break
	}
	var obs observed
	select {
	case obs = <-got:
	case <-ctx.Done():
		t.Errorf("owned control-stream barrier: %v", ctx.Err())
		return
	}
	if obs.err != nil {
		t.Errorf("owned control stream: %v", obs.err)
		return
	}
	var pseudo []string
	for _, field := range headers {
		if strings.HasPrefix(field.Name, ":") {
			pseudo = append(pseudo, field.Name[1:2])
		}
	}
	text := strings.Join(obs.settings, ";")
	for _, frame := range obs.frames {
		text += "|" + frame
	}
	text += "|" + strings.Join(pseudo, ",")
	if len(seen) > 0 {
		select {
		case seen[0] <- text:
		case <-ctx.Done():
			return
		}
	}
	body, err := json.Marshal(map[string]any{"h3_text": text, "h3_hash": fmt.Sprintf("%x", md5.Sum([]byte(text))), "control_wire": obs.raw, "request_headers": headers, "message": "http=http/3; it does support HTTP/3!"})
	if err != nil {
		t.Errorf("owned response JSON: %v", err)
		return
	}
	var headerBlock bytes.Buffer
	encoder := qpack.NewEncoder(&headerBlock)
	if err = encoder.WriteField(qpack.HeaderField{Name: ":status", Value: "200"}); err != nil {
		t.Error(err)
		return
	}
	encoder.Close()
	if _, err = stream.Write(ownedH3Frame(1, headerBlock.Bytes())); err != nil {
		return
	}
	if _, err = stream.Write(ownedH3Frame(0, body)); err != nil {
		return
	}
	stream.Close()
}

// The old external hash mixed catalogue fallback with Chrome profile data.
// Keep both obligations: legacy raw default and explicit JSON-representable
// omission/zero/finite limits. Production browser values are unchanged.
func TestHTTP3ExplicitFieldSectionLimitComesFromProfile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings map[uint64]uint64
		want     string
	}{
		{"omitted", map[uint64]uint64{51: 1}, "51:1|m,a,s,p"},
		{"zero", map[uint64]uint64{6: 0, 51: 1}, "6:0;51:1|m,a,s,p"},
		{"finite", map[uint64]uint64{6: 262144, 51: 1}, "6:262144;51:1|m,a,s,p"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := make(chan string, 1)
			endpoint := newOwnedHTTP3Peer(t, 1, wire)
			profile := profiles.Chrome_133.WithHTTP3Parameters(tc.settings, []uint64{6, 51}, []string{":method", ":authority", ":scheme", ":path"}, 0, false)
			client, err := tls_client.NewHttpClient(nil, tls_client.WithClientProfile(profile), tls_client.WithInsecureSkipVerify(), tls_client.WithTimeoutSeconds(10), tls_client.WithProtocolRacing())
			require.NoError(t, err)
			t.Cleanup(client.CloseIdleConnections)
			req, err := http.NewRequest(http.MethodGet, endpoint, nil)
			require.NoError(t, err)
			res, err := client.Do(req)
			if tc.name == "zero" {
				require.ErrorContains(t, err, "HEADERS frame too large: 3 bytes (max: 0)")
				require.Nil(t, res)
				select {
				case got := <-wire:
					require.Equal(t, tc.want, got)
				case <-time.After(5 * time.Second):
					t.Fatal("no observed SETTINGS")
				}
				return
			}
			require.NoError(t, err)
			defer res.Body.Close()
			require.Equal(t, "HTTP/3.0", res.Proto)
			var observed BrowserLeaksResponse
			require.NoError(t, json.NewDecoder(res.Body).Decode(&observed))
			require.Equal(t, tc.want, observed.H3Text)
		})
	}
}

func TestOwnedHTTP3ParserBoundsAndKnownFrame(t *testing.T) {
	data := quicvarint.Append(nil, 6)
	data = quicvarint.Append(data, 262144)
	typ, payload, err := readOwnedH3Frame(bytes.NewReader(ownedH3Frame(4, data)))
	require.NoError(t, err)
	require.EqualValues(t, 4, typ)
	require.Equal(t, data, payload)
	_, _, err = readOwnedH3Frame(bytes.NewReader(ownedH3Frame(4, data)[:2]))
	require.Error(t, err)
	tooLarge := quicvarint.Append(nil, 4)
	tooLarge = quicvarint.Append(tooLarge, (1<<20)+1)
	_, _, err = readOwnedH3Frame(bytes.NewReader(tooLarge))
	require.ErrorContains(t, err, "too large")
	require.True(t, ownedH3Grease(33))
	require.True(t, ownedH3Grease(64))
	require.False(t, ownedH3Grease(32))
	require.False(t, ownedH3Grease(34))
}

func ownedHTTP3DNSOption() tls_client.HttpClientOption {
	return tls_client.WithHTTP3FromDNS(tls_client.HTTP3FromDNS{State: tls_client.NewQUICState(), Key: func() string { return "owned.test" }, Endpoint: func(ctx context.Context, addr string) (context.Context, tls_client.QUICEndpoint, bool) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return ctx, tls_client.QUICEndpoint{}, false
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return ctx, tls_client.QUICEndpoint{}, false
		}
		return ctx, tls_client.QUICEndpoint{Addrs: []netip.Addr{ip}}, true
	}})
}

// GREASE is a generated field: preserve its real ID/value and validate the
// configured draw range, placement and payload relationship. Only its label in
// the display fingerprint is normalized; explicit SETTINGS order stays exact.
func validateOwnedH3Control(raw []byte, policy behavior.Policy, base [][2]uint64, frames []uint64) error {
	r := bytes.NewReader(raw)
	typ, payload, err := readOwnedH3Frame(r)
	if err != nil {
		return err
	}
	if typ != 4 {
		return fmt.Errorf("first H3 frame=%d", typ)
	}
	settings := bytes.NewReader(payload)
	var got [][2]uint64
	seen := map[uint64]bool{}
	greaseAt := -1
	var grease [2]uint64
	for settings.Len() > 0 {
		key, err := quicvarint.Read(settings)
		if err != nil {
			return err
		}
		value, err := quicvarint.Read(settings)
		if err != nil {
			return err
		}
		if seen[key] {
			return fmt.Errorf("duplicate setting %d", key)
		}
		seen[key] = true
		if ownedH3Grease(key) {
			if greaseAt >= 0 {
				return fmt.Errorf("multiple GREASE settings")
			}
			greaseAt = len(got)
			grease = [2]uint64{key, value}
			n := (key - 33) / 31
			if n < policy.Uint("h3.grease_setting_n_min") || n > policy.Uint("h3.grease_setting_n_max") || value > 1<<32-1 || policy.Flag("h3.grease_setting_nonzero") && value == 0 {
				return fmt.Errorf("invalid GREASE setting draw: %v", grease)
			}
		} else {
			got = append(got, [2]uint64{key, value})
		}
	}
	if !slices.Equal(got, base) {
		return fmt.Errorf("ordered fixed SETTINGS=%v, want %v", got, base)
	}
	if greaseAt < 0 {
		return fmt.Errorf("missing GREASE setting")
	}
	wantAt := len(base)
	if policy.Text("h3.grease_setting_placement") == "before-greater-id" {
		for i, pair := range base {
			if pair[0] > grease[0] {
				wantAt = i
				break
			}
		}
	}
	if greaseAt != wantAt {
		return fmt.Errorf("GREASE at %d, want %d for ID %d", greaseAt, wantAt, grease[0])
	}
	for _, want := range frames {
		typ, payload, err := readOwnedH3Frame(r)
		if err != nil {
			return err
		}
		if want == 33 {
			if !ownedH3Grease(typ) {
				return fmt.Errorf("not a GREASE frame: %d", typ)
			}
			n := (typ - 33) / 31
			if n >= uint64(1)<<policy.Uint("h3.grease_frame_n_bits") {
				return fmt.Errorf("GREASE frame draw out of range")
			}
			lengths := policy.Numbers("h3.grease_payload_lengths")
			if len(lengths) == 0 || uint64(len(payload)) != lengths[n%uint64(len(lengths))] {
				return fmt.Errorf("GREASE payload does not follow draw")
			}
		} else {
			if typ != want {
				return fmt.Errorf("control frame=%d,want=%d", typ, want)
			}
			priority := bytes.NewReader(payload)
			stream, err := quicvarint.Read(priority)
			if err != nil {
				return err
			}
			if stream != 0 || string(payload[len(payload)-priority.Len():]) != policy.Text("h3.priority_value") {
				return fmt.Errorf("wrong priority stream/value")
			}
		}
	}
	if r.Len() != 0 {
		return fmt.Errorf("extra control frames")
	}
	return nil
}

func TestOwnedHTTP3DynamicComparisonRejectsWrongFields(t *testing.T) {
	policy := ownedDNSH3Policy(t)
	base := [][2]uint64{{1, 65536}, {7, 100}, {51, 1}}
	encode := func(pairs [][2]uint64) []byte {
		var payload []byte
		for _, pair := range pairs {
			payload = quicvarint.Append(payload, pair[0])
			payload = quicvarint.Append(payload, pair[1])
		}
		return ownedH3Frame(4, payload)
	}
	good := [][2]uint64{{1, 65536}, {7, 100}, {33, 0}, {51, 1}}
	require.NoError(t, validateOwnedH3Control(encode(good), policy, base, nil))
	for _, bad := range [][][2]uint64{
		{{1, 65536}, {7, 100}, {51, 1}, {33, 0}},          // wrong generated placement
		{{1, 65536}, {7, 99}, {33, 0}, {51, 1}},           // wrong fixed value
		{{1, 65536}, {7, 100}, {33, 0}, {33, 0}, {51, 1}}, // duplicate
		{{1, 65536}, {7, 100}, {51, 1}},                   // missing draw
		{{1, 65536}, {7, 100}, {33, 1 << 32}, {51, 1}},    // illegal value range
	} {
		require.Error(t, validateOwnedH3Control(encode(bad), policy, base, nil))
	}
}

func ownedH3PseudoNames(headers []qpack.HeaderField) []string {
	var names []string
	for _, field := range headers {
		if strings.HasPrefix(field.Name, ":") {
			names = append(names, field.Name)
		}
	}
	return names
}
