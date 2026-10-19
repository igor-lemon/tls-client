package profiles

// GetFalseStart reports whether the profile's TLS 1.2 connections send their
// first request before the server's Finished where BoringSSL would
// (tls.Config.FalseStart): a full handshake, ECDHE, an AEAD and ALPN.
func (c ClientProfile) GetFalseStart() bool {
	return c.falseStart
}

// WithFalseStart is the profile false starting its TLS 1.2 connections, as
// Chrome does, when on; waiting for the server's Finished, as Go does,
// otherwise.
func (c ClientProfile) WithFalseStart(on bool) ClientProfile {
	c.falseStart = on
	return c
}
