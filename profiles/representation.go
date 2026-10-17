package profiles

import "github.com/igor-lemon/fhttp/http2/hpack"

// GetHeaderRepresentation is how the profile writes each header field into
// HPACK, nil for HPACK's default (hpack.Representation).
func (c ClientProfile) GetHeaderRepresentation() func(hpack.HeaderField) hpack.Representation {
	return c.headerRepresentation
}

// WithHeaderRepresentation is the profile writing each header field into
// HPACK as of says, nil for HPACK's default.
func (c ClientProfile) WithHeaderRepresentation(of func(hpack.HeaderField) hpack.Representation) ClientProfile {
	c.headerRepresentation = of
	return c
}
