package tls_client

import (
	"net"
	"testing"
	"time"

	"github.com/igor-lemon/tls-client/profiles"
)

func TestTheRoundTripperTakesItsProfilesWindowUpdateDelay(t *testing.T) {
	rt, err := newRoundTripper(profiles.Chrome_133.WithWindowUpdateDelay(5*time.Second), nil, "", false, false, false,
		false, false, false, nil, nil, false, false, nil, "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rt.(*roundTripper).windowUpdateDelay; got != 5*time.Second {
		t.Errorf("the round tripper waits %s", got)
	}
}
