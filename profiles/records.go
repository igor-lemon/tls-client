package profiles

// GetDynamicRecordSizingDisabled reports whether the profile writes TLS
// records as large as what it writes allows from a connection's first byte
// (tls.Config.DynamicRecordSizingDisabled), where Go's TLS cuts the first
// writes of a connection into records of about 1 KiB that grow.
func (c ClientProfile) GetDynamicRecordSizingDisabled() bool {
	return c.dynamicRecordSizingDisabled
}

// WithDynamicRecordSizingDisabled is the profile writing TLS records as large
// as what it writes allows, up to 16,384 bytes, from a connection's first byte,
// when disabled; and as Go's TLS does otherwise. Chrome's records are as
// large as its writes.
func (c ClientProfile) WithDynamicRecordSizingDisabled(disabled bool) ClientProfile {
	c.dynamicRecordSizingDisabled = disabled
	return c
}

// GetMaxMergedHeadAndBody is how many bytes an HTTP/1.1 request's head and a
// body held in memory may be together for the profile to write them at once,
// its head being written at once in any case
// (http.Transport.MaxMergedHeadAndBody); 0 when it writes a request through
// the connection's buffer, as Go does.
func (c ClientProfile) GetMaxMergedHeadAndBody() int {
	return c.maxMergedHeadAndBody
}

// WithMaxMergedHeadAndBody is the profile writing an HTTP/1.1 request as
// Chrome does when limit is above zero: its head at once, whatever its size,
// and a body held in memory in the same write when the two are no more than
// limit bytes, Chrome's 1,400; as Go does otherwise.
func (c ClientProfile) WithMaxMergedHeadAndBody(limit int) ClientProfile {
	c.maxMergedHeadAndBody = limit
	return c
}
