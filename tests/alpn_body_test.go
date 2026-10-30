package tests

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/http2"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/igor-lemon/tls-client/profiles"
	"github.com/stretchr/testify/require"
)

type ownedClosingBody struct {
	reader *strings.Reader
	closed atomic.Bool
}

func (b *ownedClosingBody) Read(p []byte) (int, error) {
	if b.closed.Load() {
		return 0, errors.New("body already closed")
	}
	return b.reader.Read(p)
}
func (b *ownedClosingBody) Close() error { b.closed.Store(true); return nil }

// A RoundTripper owns/closes the body even on a dial error. Pre-dispatch ALPN
// handoff may only continue with a fresh GetBody result; an unrewindable body
// must return to its caller before a POST is emitted on the replacement.
func TestProtocolChangeOwnsRequestBodyBeforeRetry(t *testing.T) {
	for _, rewind := range []bool{false, true} {
		t.Run(map[bool]string{false: "unrewindable", true: "rewindable"}[rewind], func(t *testing.T) {
			var handshakes, posts, renewed atomic.Int64
			bodyErrors := make(chan string, 2)
			cert := selfSignedCert(t)
			listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				protocol := "http/1.1"
				if handshakes.Add(1) > 1 {
					protocol = http2.NextProtoTLS
				}
				return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{protocol}}, nil
			}})
			require.NoError(t, err)
			defer listener.Close()
			go serveChangingProtocol(listener, func(r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil {
						bodyErrors <- fmt.Sprintf("origin body: %v", err)
					} else if string(body) != "complete POST" {
						bodyErrors <- fmt.Sprintf("origin body=%q", body)
					}
				}
			})
			client, err := tls_client.NewHttpClient(nil, tls_client.WithClientProfile(profiles.Chrome_133), tls_client.WithInsecureSkipVerify(), tls_client.WithTimeoutSeconds(5))
			require.NoError(t, err)
			t.Cleanup(client.CloseIdleConnections)
			endpoint := "https://" + listener.Addr().String()
			first, err := client.Get(endpoint)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, first.Body)
			require.NoError(t, err)
			first.Body.Close()
			original := &ownedClosingBody{reader: strings.NewReader("complete POST")}
			req, err := http.NewRequest(http.MethodPost, endpoint, original)
			require.NoError(t, err)
			req.ContentLength = int64(len("complete POST"))
			if rewind {
				req.GetBody = func() (io.ReadCloser, error) {
					renewed.Add(1)
					return &ownedClosingBody{reader: strings.NewReader("complete POST")}, nil
				}
			}
			res, err := client.Do(req)
			if rewind {
				require.NoError(t, err)
				_, err = io.Copy(io.Discard, res.Body)
				require.NoError(t, err)
				res.Body.Close()
				require.EqualValues(t, 1, posts.Load())
				require.EqualValues(t, 1, renewed.Load())
			} else {
				require.ErrorContains(t, err, "does not speak")
				require.Nil(t, res)
				require.Zero(t, posts.Load())
			}
			require.Same(t, original, req.Body, "caller body ownership must not be replaced")
			next, err := client.Get(endpoint)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, next.Body)
			require.NoError(t, err)
			next.Body.Close()
			select {
			case message := <-bodyErrors:
				t.Fatal(message)
			default:
			}
		})
	}
}
