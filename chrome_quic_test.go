package tls_client

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
)

func TestChromeQUICPresetEvents(t *testing.T) {
	cert := coalescingCert(t, "a.test")
	cc := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, ServerName: "a.test", ChromeBehavior: true, QUICClientHelloSpec: chromeQUICSpec(profiles.Chrome_133.GetClientHelloId())}
	a := tls.QUICClient(&tls.QUICConfig{TLSConfig: cc})
	b := tls.QUICServer(&tls.QUICConfig{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"}}})
	a.SetTransportParameters(nil)
	b.SetTransportParameters(nil)
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	complete := 0
	for turn := 0; turn < 100; turn++ {
		x, y := a, b
		if turn%2 == 1 {
			x, y = b, a
		}
		for {
			e := x.NextEvent()
			if e.Kind == tls.QUICNoEvent {
				break
			}
			switch e.Kind {
			case tls.QUICWriteData:
				if err := y.HandleData(e.Level, e.Data); err != nil {
					t.Fatal(err)
				}
			case tls.QUICHandshakeDone:
				complete++
			}
		}
		if complete == 2 {
			return
		}
	}
	t.Fatal("incomplete", complete)
}

func TestHTTP3SupportsDynamicQPACK(t *testing.T) {
	for _, settings := range []map[uint64]uint64{{1: 1}, {7: 1}, {1: 65536, 7: 100}} {
		if _, err := buildHTTP3Transport(&http3Config{http3Settings: settings}); err != nil {
			t.Fatalf("dynamic QPACK refused: %v: %v", settings, err)
		}
	}
	tr, err := buildHTTP3Transport(&http3Config{http3Settings: map[uint64]uint64{1: 0, 7: 0}})
	if err != nil || tr == nil {
		t.Fatalf("static QPACK refused: %v", err)
	}
}

// alpsPolicy is the frozen Chromium data with ALPS for h3 kept in the QUIC
// hello and read as Chrome 155 reads it, under codepoint.
func alpsPolicy(t *testing.T, codepoint uint64) behavior.Policy {
	t.Helper()
	p := behavior.Legacy()
	over := map[string]any{
		"quic.preserve_extensions": []uint64{0, 65037, 27, 45, 51764, 10, 13, 51, 16, 43, 41, codepoint},
		"quic.alps_protocols":      []string{"h3"}, "h3.alps_reader": "quiche", "h3.alps_origin_frames": "abandon",
		"h3.alps_close_space": "transport", "h3.alps_close_code": 10, "h3.alps_close_frame_type": 6,
		"h3.alps_close_reason": "28:Error processing ALPS data: {detail}", "h3.peer_settings": "quiche",
		"h3.settings_close_space": "application", "h3.settings_close_code": 265, "h3.settings_http2": []uint64{2, 3, 4, 5},
		"h3.settings_boolean": []uint64{8, 51}, "h3.settings_boolean_names": []string{"SETTINGS_ENABLE_CONNECT_PROTOCOL", "SETTINGS_H3_DATAGRAM"},
	}
	errs := map[string]string{}
	for _, c := range []string{"data", "headers", "goaway", "max_push_id", "priority_update", "metadata", "settings_twice",
		"incomplete", "too_large", "setting_id", "setting_value", "setting_twice", "goaway_id", "goaway_extra",
		"max_push_id_id", "max_push_id_extra", "priority_update_id", "accept_ch_origin", "accept_ch_value", "origin_origin",
		"cancel_push", "push_promise"} {
		errs[c] = c
	}
	errs["http2_frame"] = "{type}"
	over["h3.alps_errors"] = errs
	settings := map[string]string{"http2": "{id}", "boolean": "{name} {value}", "capacity": "{value} {current}",
		"field_section": "{value} {current}", "blocked": "{value} {current}", "omitted_field_section": "f",
		"omitted_blocked": "b", "omitted_capacity": "c"}
	over["h3.settings_errors"] = settings
	for k, v := range over {
		p[k], _ = json.Marshal(v)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

// wrapped is an extension a profile wraps for a TCP hello, as tls-forge's
// ALPS bound to its ALPN.
type wrappedExtension struct{ tls.TLSExtension }

func (w *wrappedExtension) Unwrap() tls.TLSExtension { return w.TLSExtension }

// alpsOf is the application_settings extension of a spec and its
// codepoint, nil when it has none.
func alpsOf(spec tls.ClientHelloSpec) ([]string, uint64) {
	for _, e := range spec.Extensions {
		switch e := e.(type) {
		case *tls.ApplicationSettingsExtension:
			return e.SupportedProtocols, 17513
		case *tls.ApplicationSettingsExtensionNew:
			return e.SupportedProtocols, 17613
		}
	}
	return nil, 0
}

func TestAQUICHelloOffersALPSAsItsProfileSays(t *testing.T) {
	tcp := func(ext tls.TLSExtension) tls.ClientHelloID {
		return tls.ClientHelloID{Client: "test", Version: "1", SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{Extensions: []tls.TLSExtension{&tls.SNIExtension{},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, ext}}, nil
		}}
	}
	for _, tc := range []struct {
		name      string
		ext       tls.TLSExtension
		codepoint uint64
	}{
		{"the new codepoint", &tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}, 17613},
		{"the old codepoint", &tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}, 17513},
		{"wrapped for its ALPN", &wrappedExtension{&tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}}, 17613},
	} {
		spec, err := profileQUICSpec(tcp(tc.ext), alpsPolicy(t, tc.codepoint))([]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		protocols, codepoint := alpsOf(spec)
		if codepoint != tc.codepoint || len(protocols) != 1 || protocols[0] != "h3" {
			t.Errorf("%s: ALPS %d for %q, want %d for h3", tc.name, codepoint, protocols, tc.codepoint)
		}
	}
	// a profile that keeps no ALPS for QUIC offers none
	spec, err := profileQUICSpec(tcp(&tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}), behavior.Legacy())([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, codepoint := alpsOf(spec); codepoint != 0 {
		t.Errorf("the legacy data offered ALPS %d", codepoint)
	}
}

func TestAQUICHandshakeOfALPSSaysTheClientsEmptySettings(t *testing.T) {
	cert := coalescingCert(t, "a.test")
	pol := alpsPolicy(t, 17613)
	cc := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, ServerName: "a.test", Behavior: pol,
		QUICClientHelloSpec: profileQUICSpec(profiles.Chrome_133.GetClientHelloId(), pol)}
	a := tls.QUICClient(&tls.QUICConfig{TLSConfig: cc})
	b := tls.QUICServer(&tls.QUICConfig{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}}, NextProtos: []string{"h3"},
		ApplicationSettings: map[string][]byte{"h3": {0x04, 0x00}}}})
	a.SetTransportParameters(nil)
	b.SetTransportParameters(nil)
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	complete := 0
	for turn := 0; turn < 100 && complete < 2; turn++ {
		x, y := a, b
		if turn%2 == 1 {
			x, y = b, a
		}
		for e := x.NextEvent(); e.Kind != tls.QUICNoEvent; e = x.NextEvent() {
			switch e.Kind {
			case tls.QUICWriteData:
				if err := y.HandleData(e.Level, e.Data); err != nil {
					t.Fatal(err)
				}
			case tls.QUICHandshakeDone:
				complete++
			}
		}
	}
	if complete != 2 {
		t.Fatal("incomplete", complete)
	}
	if got := a.ConnectionState().PeerApplicationSettings; string(got) != "\x04\x00" {
		t.Errorf("the client was given %x", got)
	}
	if got := b.ConnectionState().PeerApplicationSettings; got == nil || len(got) != 0 {
		t.Errorf("the server read %x of the client's settings, want them empty", got)
	}
}
