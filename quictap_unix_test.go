//go:build unix

package tls_client

import (
	"encoding/binary"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// segmentation is the control message a write of segments of size bytes is
// asked with, as quic-go makes it on Linux.
func segmentation(size uint16) []byte {
	b := make([]byte, unix.CmsgSpace(2))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = levelUDP
	h.Type = typeUDPSegment
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(b[unix.CmsgSpace(0):], size)
	return b
}

func TestAWriteSegmentedIsTheDatagramsItSends(t *testing.T) {
	other := make([]byte, unix.CmsgSpace(4))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&other[0]))
	h.Level, h.Type = 0, 1
	h.SetLen(unix.CmsgLen(4))
	for _, tc := range []struct {
		name string
		data string
		oob  []byte
		want []string
	}{
		{"none asked", "abcdefgh", nil, []string{"abcdefgh"}},
		{"cut every 3 bytes", "abcdefgh", segmentation(3), []string{"abc", "def", "gh"}},
		{"cut evenly", "abcdef", segmentation(3), []string{"abc", "def"}},
		{"less than a segment", "ab", segmentation(3), []string{"ab"}},
		{"a size of 0", "abcdef", segmentation(0), []string{"abcdef"}},
		{"after another message", "abcdef", append(slices.Clone(other), segmentation(4)...), []string{"abcd", "ef"}},
		{"another message alone", "abcdef", other, []string{"abcdef"}},
		{"a message cut short", "abcdef", segmentation(3)[:3], []string{"abcdef"}},
		{"a message longer than all there is", "abcdef", func() []byte {
			b := segmentation(3)
			(*unix.Cmsghdr)(unsafe.Pointer(&b[0])).SetLen(1000)
			return b
		}(), []string{"abcdef"}},
	} {
		var got []string
		for _, d := range datagramsOf([]byte(tc.data), tc.oob) {
			got = append(got, string(d))
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestASegmentedWriteTellsTheTapOfEachDatagram(t *testing.T) {
	tap := &tapped{}
	c := &quicSocket{tap: tap}
	c.wrote([]byte("abcdefgh"), segmentation(3))
	if wrote, _, _ := tap.said(); len(wrote) != 3 || string(wrote[0]) != "abc" || string(wrote[2]) != "gh" {
		t.Errorf("told of %q", wrote)
	}
}
