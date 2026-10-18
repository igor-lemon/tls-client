package profiles

import "time"

// GetWindowUpdateDelay is how long the profile waits before it tells a server
// of a little of a window its reader freed, as Chrome does
// (http2.Transport.WindowUpdateDelay); 0 for the transport's own rule.
func (c ClientProfile) GetWindowUpdateDelay() time.Duration {
	return c.windowUpdateDelay
}

// WithWindowUpdateDelay is the profile telling a server of the window its
// reader freed as Chrome does: once more than half of a window is freed and
// untold, or at the first byte freed more than delay after it last told it;
// 0 for the transport's own rule. Chrome waits five seconds.
func (c ClientProfile) WithWindowUpdateDelay(delay time.Duration) ClientProfile {
	c.windowUpdateDelay = delay
	return c
}
