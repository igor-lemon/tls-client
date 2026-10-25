//go:build unix

package tls_client

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	tls "github.com/igor-lemon/utls"
)

func TestAConnectionIsConnectedUntilItsPeerClosesIt(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if !connected(client) {
		t.Error("a connection with nothing to read")
	}
	_, _ = server.Write([]byte("x"))
	if !waitFor(time.Second, func() bool {
		var b [1]byte
		raw, _ := client.(syscall.Conn).SyscallConn()
		n := 0
		_ = raw.Read(func(fd uintptr) bool {
			n, _, _ = syscall.Recvfrom(int(fd), b[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
			return true
		})
		return n == 1
	}) || !connected(client) {
		t.Error("a connection with something to read")
	}
	// Under a TLS connection of ours, through NetConn.
	if !connected(tls.Client(client, &tls.Config{})) {
		t.Error("a connection under TLS")
	}
	_ = server.Close()
	b := make([]byte, 1)
	_, _ = client.Read(b) // the byte waiting
	if !waitFor(time.Second, func() bool { return !connected(client) }) {
		t.Error("a connection its peer closed")
	}
	// One that cannot be peeked at is taken as connected.
	a, _ := net.Pipe()
	if !connected(a) || !connected(unpeekable{a}) {
		t.Error("a connection with no socket")
	}
}

// unpeekable is a connection whose socket cannot be had.
type unpeekable struct{ net.Conn }

func (unpeekable) SyscallConn() (syscall.RawConn, error) { return nil, errors.New("no socket") }
