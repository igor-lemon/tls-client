package tls_client

import (
	"github.com/igor-lemon/tls-client/profiles"
	"strings"
	"testing"
)

func TestLockedProfileRejectsEveryLaterRawSelection(t *testing.T) {
	for _, override := range []HttpClientOption{WithClientProfile(profiles.Chrome_133), WithClientProfile(profiles.Firefox_148), WithLockedClientProfile(profiles.Chrome_133, "another")} {
		c, err := NewHttpClient(nil, WithLockedClientProfile(profiles.Chrome_133, "profile test engine_major 1"), override)
		if err == nil {
			c.CloseIdleConnections()
			t.Fatal("raw profile override accepted")
		}
		if !strings.Contains(err.Error(), "engine_major") {
			t.Fatal(err)
		}
	}
	for _, options := range [][]HttpClientOption{{WithClientProfile(profiles.Firefox_148)}, {WithLockedClientProfile(profiles.Chrome_133, "test")}, {WithLockedClientProfile(profiles.Chrome_133, "")}} {
		c, err := NewHttpClient(nil, options...)
		if err != nil {
			t.Fatal(err)
		}
		c.CloseIdleConnections()
	}
}
