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
