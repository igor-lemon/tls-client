package tls_client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/quic-go-utls/http3"
)

// Inspect the actual shared UDP socket; reading Config alone cannot show that
// the selected dependency implements its policy fields.
func TestHTTP3ExplicitSharedSourceCIDReachesWire(t *testing.T) {
	for _, tc := range []struct{ size, cid int }{{1250, 4}, {1300, 8}} {
		t.Run(fmt.Sprintf("%d-%d", tc.size, tc.cid), func(t *testing.T) {
			p := nativeConfigPolicy(t)
			p["quic.source_cid_bytes"] = json.RawMessage(fmt.Sprint(tc.cid))
			p["quic.initial_packet_bytes"] = json.RawMessage(fmt.Sprint(tc.size))
			raw, err := buildHTTP3Transport(&http3Config{behavior: p, insecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			tr := raw.(*http3.Transport)
			packets, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = packets.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			req, err := http.NewRequestWithContext(ctx, "GET", "https://"+packets.LocalAddr().String()+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				res, e := tr.RoundTrip(req)
				if res != nil {
					_ = res.Body.Close()
				}
				done <- e
			}()
			t.Cleanup(func() {
				cancel()
				_ = tr.Close()
				select {
				case err := <-done:
					if err == nil {
						t.Error("silent peer unexpectedly answered HTTP/3")
					}
				case <-time.After(time.Second):
					t.Error("canceled transport did not stop")
				}
			})
			if err = packets.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, 4096)
			n, _, err := packets.ReadFrom(packet)
			if err != nil {
				t.Fatal("missing actual Initial datagram", err)
			}
			packet = packet[:n]
			if n < 7 || packet[0]&0x80 == 0 {
				t.Fatal("not a QUIC long header", n)
			}
			dcid := int(packet[5])
			if dcid > 20 || 6+dcid >= n {
				t.Fatal("invalid DCID vector", dcid, n)
			}
			scid := int(packet[6+dcid])
			if scid > 20 || 7+dcid+scid > n {
				t.Fatal("invalid SCID vector", scid, n)
			}
			if scid != tc.cid {
				t.Errorf("JSON source CID bytes=%d; actual shared socket sends%d", tc.cid, scid)
			}
			if n != tc.size {
				t.Errorf("JSON Initial size=%d; actual datagram=%d", tc.size, n)
			}
		})
	}
}
