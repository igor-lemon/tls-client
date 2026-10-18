package profiles

import (
	"testing"
	"time"
)

func TestAProfileWithAWindowUpdateDelayIsACopy(t *testing.T) {
	base := Chrome_133
	with := base.WithWindowUpdateDelay(5 * time.Second)
	if base.GetWindowUpdateDelay() != 0 {
		t.Error("the profile it was made from waits")
	}
	if got := with.GetWindowUpdateDelay(); got != 5*time.Second {
		t.Errorf("the copy waits %s", got)
	}
	if with.GetClientHelloId().Client != base.GetClientHelloId().Client || len(with.GetSettings()) != len(base.GetSettings()) {
		t.Error("the copy is another profile")
	}
}
