package tls_client

import (
	"encoding/json"
	"testing"

	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/utls/behavior"
)

func TestExplicitEmptyHTTP3SettingsDoNotInheritH1Limit(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		p := behavior.Generic()
		p["h3.grease_settings"] = json.RawMessage(`false`)
		var settings map[uint64]uint64
		if explicit {
			settings = map[uint64]uint64{}
		}
		rt := roundTripper{http3Settings: settings}
		cfg := &http3Config{behavior: p, http3Settings: rt.getHttp3Settings(), transportOptions: &TransportOptions{MaxResponseHeaderBytes: 1234}}
		raw, err := buildHTTP3Transport(cfg)
		if err != nil {
			t.Fatal(err)
		}
		tr := raw.(*http3.Transport)
		want := 1234
		if explicit {
			want = -1
		}
		if tr.MaxResponseHeaderBytes != want {
			t.Fatalf("explicit=%v: H3 header policy %d want%d", explicit, tr.MaxResponseHeaderBytes, want)
		}
	}
}
