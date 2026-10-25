//go:build unix

package tls_client

import (
	"errors"
	"syscall"
)

// peerOpen says whether the peer of the socket under c has not closed it:
// nothing to read yet, or something; a read of nothing at all, or a reset, is
// the peer gone. Its bytes are peeked at, never read.
func peerOpen(c syscall.Conn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return true
	}
	open := true
	_ = raw.Read(func(fd uintptr) bool {
		var b [1]byte
		n, _, err := syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		open = n > 0 || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR)
		return true
	})
	return open
}
