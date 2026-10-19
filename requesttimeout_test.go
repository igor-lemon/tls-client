package tls_client

import (
	"context"
	"errors"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/tls-client/profiles"
)

func TestAClientWithoutARequestTimeoutLeavesTheDeadlineToTheContext(t *testing.T) {
	server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	get := func(client HttpClient, ctx context.Context) (time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		res, err := client.Do(req)
		if err == nil {
			_ = res.Body.Close()
		}
		return time.Since(start), err
	}
	for _, tc := range []struct {
		name    string
		without bool
	}{{"the client's timeout", false}, {"the context's deadline alone", true}} {
		t.Run(tc.name, func(t *testing.T) {
			options := []HttpClientOption{WithClientProfile(profiles.Chrome_133), WithInsecureSkipVerify(), WithTimeoutMilliseconds(100)}
			if tc.without {
				options = append(options, WithoutRequestTimeout())
			}
			client, err := NewHttpClient(NewNoopLogger(), options...)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			// The dial is bounded all the same.
			if got := client.GetDialer().(*directDialer).dialer.Timeout; got != 100*time.Millisecond {
				t.Errorf("the dial's timeout: %v", got)
			}
			took, err := get(client, context.Background())
			if tc.without != (err == nil) {
				t.Errorf("with no deadline: %v after %v", err, took)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			took, err = get(client, ctx)
			if err == nil || took > time.Second {
				t.Fatalf("within the context's deadline: %v after %v", err, took)
			}
			// With two deadlines, either may end it: the client's says it
			// cancelled the request, which is no context's error.
			if tc.without && (!errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout")) {
				t.Errorf("said: %v", err)
			}
		})
	}
}
