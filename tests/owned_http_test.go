package tests

import (
	"crypto/tls"
	"crypto/x509"
	http "github.com/igor-lemon/fhttp"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	stdhttp "net/http"
	stdhttptest "net/http/httptest"
	"testing"
)

// A locally trusted real TLS peer, with certificate verification enabled.
func newOwnedVerifiedTLSPeer(t *testing.T, handler http.Handler) (string, *x509.CertPool) {
	t.Helper()
	certificate := selfSignedCert(t)
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
	require.NoError(t, err)
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Close(); listener.Close(); <-done })
	return "https://" + listener.Addr().(*net.TCPAddr).String(), roots
}

// TLS/TCP negotiates real HTTP/2. The response reports the protocol actually
// observed by this independent server, preserving the old trace obligation.
func newOwnedHTTP2TracePeer(t *testing.T) string {
	t.Helper()
	server := stdhttptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("owned trace protocol=%s", r.Proto)
		}
		_, _ = io.WriteString(w, "http=http/2; HTTP/3 (h3-29 or h3-27) was not used to request this page")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}
