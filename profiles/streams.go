package profiles

// GetStrictMaxConcurrentStreams reports whether the profile waits for a stream
// on a connection it holds once the server's MAX_CONCURRENT_STREAMS are all
// in use (http2.Transport.StrictMaxConcurrentStreams).
func (c ClientProfile) GetStrictMaxConcurrentStreams() bool {
	return c.strictMaxConcurrentStreams
}

// WithStrictMaxConcurrentStreams is the profile waiting, when strict, for a
// stream on a connection it holds once the server's MAX_CONCURRENT_STREAMS are
// all in use, as Chrome waits, rather than opening another connection to the
// server; not strict, another connection, as the transport does unless told.
func (c ClientProfile) WithStrictMaxConcurrentStreams(strict bool) ClientProfile {
	c.strictMaxConcurrentStreams = strict
	return c
}
