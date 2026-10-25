//go:build unix

package tls_client

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// The control message a write asks the kernel to cut into datagrams of a
// size with (Linux's UDP_SEGMENT, which quic-go's writes carry where the
// system has it: GSO).
const (
	levelUDP       = 17
	typeUDPSegment = 103
)

// datagramsOf are the datagrams a write of b with oob sends: b cut every
// segment size when oob asks for segmentation, else b alone.
func datagramsOf(b, oob []byte) [][]byte {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return [][]byte{b}
	}
	for _, m := range msgs {
		if m.Header.Level != levelUDP || m.Header.Type != typeUDPSegment || len(m.Data) < 2 {
			continue
		}
		size := int(binary.NativeEndian.Uint16(m.Data))
		if size == 0 {
			break
		}
		var out [][]byte
		for len(b) > size {
			out = append(out, b[:size])
			b = b[size:]
		}
		return append(out, b)
	}
	return [][]byte{b}
}
