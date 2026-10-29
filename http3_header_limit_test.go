package tls_client

import (
	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/utls/behavior"
	"testing"
)

func TestHTTP3HeaderLimitIsOwnedBySettings(t *testing.T) {
	for _, priority := range []uint32{0, 984832} {
		for _, settings := range []map[uint64]uint64{nil, {}, {6: 0}, {6: 1048576}} {
			tr, err := buildHTTP3Transport(&http3Config{behavior: behavior.Legacy(), http3Settings: settings, http3PriorityParam: priority, transportOptions: &TransportOptions{MaxResponseHeaderBytes: 17}})
			if err != nil {
				t.Fatal(err)
			}
			got := tr.(*http3.Transport)
			want := 17
			if settings != nil {
				want = -1
			}
			if got.MaxResponseHeaderBytes != want {
				t.Fatalf("settings %v: limit %d, want %d", settings, got.MaxResponseHeaderBytes, want)
			}
			if value, ok := settings[6]; ok && got.AdditionalSettings[6] != value {
				t.Fatal("settings value lost")
			}
		}
	}
}
