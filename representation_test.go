package tls_client

import (
	"net"
	"testing"

	"github.com/igor-lemon/fhttp/http2/hpack"
	"github.com/igor-lemon/tls-client/profiles"
)

func TestTheRoundTripperWritesHeadersAsItsProfileSays(t *testing.T) {
	of := func(hpack.HeaderField) hpack.Representation { return hpack.Representation{FirstStaticName: true} }
	rt, err := newRoundTripper(profiles.Chrome_133.WithHeaderRepresentation(of), nil, "", false, false, false, false,
		false, false, nil, nil, false, false, nil, "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	got := rt.(*roundTripper).headerRepresentation
	if got == nil || !got(hpack.HeaderField{}).FirstStaticName {
		t.Error("the round tripper does not write as its profile says")
	}
}

func TestTheRoundTripperTakesItsProfilesEncoderTableLimit(t *testing.T) {
	rt, err := newRoundTripper(profiles.Chrome_133.WithMaxEncoderHeaderTableSize(1<<20), nil, "", false, false, false, false,
		false, false, nil, nil, false, false, nil, "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rt.(*roundTripper).maxEncoderTableSize; got != 1<<20 {
		t.Errorf("the round tripper's limit is %d", got)
	}
}
