package profiles

// GetMaxDataFramePayload is the largest payload of a DATA frame of a request's
// body the profile writes (http2.Transport.MaxDataFramePayload); 0 for as large
// as the peer allows.
func (c ClientProfile) GetMaxDataFramePayload() uint32 {
	return c.maxDataFramePayload
}

// WithMaxDataFramePayload is the profile sending a request's body in DATA
// frames of at most payload bytes each, below what the peer allows; 0 for as
// large as the peer allows. Chrome writes at most 16,375, which with the
// frame's header fills a TLS record.
func (c ClientProfile) WithMaxDataFramePayload(payload uint32) ClientProfile {
	c.maxDataFramePayload = payload
	return c
}
