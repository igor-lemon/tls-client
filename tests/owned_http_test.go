package tests

import (
	"crypto/tls"
	"crypto/x509"
	http "github.com/igor-lemon/fhttp"
	"github.com/stretchr/testify/require"
	"net"
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
