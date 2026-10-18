package profiles

import (
	"testing"

	"github.com/igor-lemon/fhttp/http2/hpack"
)

func TestAProfileWithAHeaderRepresentationIsACopy(t *testing.T) {
	of := func(hpack.HeaderField) hpack.Representation { return hpack.Representation{WithoutIndexing: true} }
	base := Chrome_133
	with := base.WithHeaderRepresentation(of)
	if base.GetHeaderRepresentation() != nil {
		t.Error("the profile it was made from writes otherwise")
	}
	if got := with.GetHeaderRepresentation(); got == nil || !got(hpack.HeaderField{}).WithoutIndexing {
		t.Error("the copy does not write as told")
	}
	if with.GetClientHelloId().Client != base.GetClientHelloId().Client || with.GetClientHelloId().Version != base.GetClientHelloId().Version || len(with.GetSettings()) != len(base.GetSettings()) {
		t.Error("the copy is another profile")
	}
}

func TestAProfileWithAnEncoderTableLimitIsACopy(t *testing.T) {
	base := Chrome_133
	with := base.WithMaxEncoderHeaderTableSize(1 << 20)
	if base.GetMaxEncoderHeaderTableSize() != 0 {
		t.Error("the profile it was made from has a limit")
	}
	if got := with.GetMaxEncoderHeaderTableSize(); got != 1<<20 {
		t.Errorf("the copy's limit is %d", got)
	}
	if with.GetClientHelloId().Client != base.GetClientHelloId().Client || len(with.GetSettings()) != len(base.GetSettings()) {
		t.Error("the copy is another profile")
	}
}
