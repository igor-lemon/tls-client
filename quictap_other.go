//go:build !unix

package tls_client

// datagramsOf is b: a system without UDP segmentation sends what it is given
// as one datagram.
func datagramsOf(b, _ []byte) [][]byte {
	return [][]byte{b}
}
