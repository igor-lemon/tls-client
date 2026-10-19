package profiles

// GetMaxHeaderFramePayload is the largest payload of a HEADERS or
// CONTINUATION frame the profile writes (http2.Transport.MaxHeaderFramePayload);
// 0 for as large as the peer allows.
func (c ClientProfile) GetMaxHeaderFramePayload() uint32 {
	return c.maxHeaderFramePayload
}

// WithMaxHeaderFramePayload is the profile cutting a header block into frames
// of at most payload bytes each, a HEADERS frame's priority included, below
// what the peer allows; 0 for as large as the peer allows. Chrome writes at
// most 16,374.
func (c ClientProfile) WithMaxHeaderFramePayload(payload uint32) ClientProfile {
	c.maxHeaderFramePayload = payload
	return c
}
