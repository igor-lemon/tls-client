package tls_client

import (
	"net"
	"testing"

	"github.com/igor-lemon/tls-client/profiles"
)

func TestTheRoundTripperTakesItsProfilesMaxHeaderFramePayload(t *testing.T) {
	rt, err := newRoundTripper(profiles.Chrome_133.WithMaxHeaderFramePayload(16374), nil, "", false, false, false,
		false, false, false, nil, nil, false, false, nil, "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rt.(*roundTripper).maxHeaderFramePayload; got != 16374 {
		t.Errorf("the round tripper cuts at %d", got)
	}
}
