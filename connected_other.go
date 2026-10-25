//go:build !unix

package tls_client

import "syscall"

// peerOpen cannot peek at a socket here: it is taken as open.
func peerOpen(syscall.Conn) bool { return true }
