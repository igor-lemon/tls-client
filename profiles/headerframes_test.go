package profiles

import "testing"

func TestAProfileWithAMaxHeaderFramePayloadIsACopy(t *testing.T) {
	base := Chrome_133
	with := base.WithMaxHeaderFramePayload(16374)
	if base.GetMaxHeaderFramePayload() != 0 {
		t.Error("the profile it was made from cuts its frames")
	}
	if got := with.GetMaxHeaderFramePayload(); got != 16374 {
		t.Errorf("the copy cuts at %d", got)
	}
	if with.GetClientHelloId().Client != base.GetClientHelloId().Client || len(with.GetSettings()) != len(base.GetSettings()) {
		t.Error("the copy is another profile")
	}
}
