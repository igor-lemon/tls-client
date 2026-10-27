package profiles

import "testing"

func TestExplicitConnectionFlowIsIndependentValue(t *testing.T) {
	base := Chrome_133
	explicit := base.WithConnectionFlowSet(true)
	if base.GetConnectionFlowSet() || !explicit.GetConnectionFlowSet() || explicit.GetConnectionFlow() != base.GetConnectionFlow() {
		t.Fatal("explicit presence lost or mutated preset")
	}
	if explicit.WithConnectionFlowSet(false).GetConnectionFlowSet() {
		t.Fatal("presence cannot be cleared")
	}
}
