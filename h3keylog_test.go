package tls_client

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAQUICConnectionsSecretsGoToTheKeyLog(t *testing.T) {
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	var keys syncBuffer
	c := h3Client(t, dnsH3Policy(t, nil), &recordSays{h3: true}, NewQUICState(),
		WithTransportOptions(&TransportOptions{KeyLogWriter: &keys}))
	if got := came(t, c, "https://"+o.addr+"/"); got != "HTTP/3.0" {
		t.Fatalf("came over %q", got)
	}
	if !strings.Contains(keys.String(), "CLIENT_TRAFFIC_SECRET_0 ") {
		t.Errorf("the key log has %q", keys.String())
	}
}

// syncBuffer is a buffer written from many goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
