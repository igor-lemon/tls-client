package tls_client

import (
	"context"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"testing"
	"time"
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

func TestHTTP3RefusesUnavailableDynamicQPACK(t *testing.T) {
	for _, settings := range []map[uint64]uint64{{1: 1}, {7: 1}, {1: 65536, 7: 100}} {
		if _, err := buildHTTP3Transport(&http3Config{http3Settings: settings}); err == nil {
			t.Fatalf("unsupported QPACK advertised: %v", settings)
		}
	}
	tr, err := buildHTTP3Transport(&http3Config{http3Settings: map[uint64]uint64{1: 0, 7: 0}})
	if err != nil || tr == nil {
		t.Fatalf("static QPACK refused: %v", err)
	}
}
