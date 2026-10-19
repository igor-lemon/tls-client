package tls_client

import (
	"net"
	"testing"

	"github.com/igor-lemon/tls-client/profiles"
)

func TestTheRoundTripperTakesHowItsProfileFramesAndRecords(t *testing.T) {
	rt, err := newRoundTripper(profiles.Chrome_133.WithMaxDataFramePayload(16375).WithDynamicRecordSizingDisabled(true), nil,
		"", false, false, false, false, false, false, nil, nil, false, false, nil, "", &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	if r := rt.(*roundTripper); r.maxDataFramePayload != 16375 || !r.dynamicRecordSizingDisabled {
		t.Errorf("the round tripper frames %d, records disabled %v", r.maxDataFramePayload, r.dynamicRecordSizingDisabled)
	}
}

func TestTheHTTP1TransportWritesAsItsProfileSays(t *testing.T) {
	for _, limit := range []int{0, 1400} {
		rt, err := newRoundTripper(profiles.Chrome_133.WithMaxMergedHeadAndBody(limit), nil,
			"", false, false, false, false, false, false, nil, nil, false, false, nil, "", &net.Dialer{})
		if err != nil {
			t.Fatal(err)
		}
		if got := rt.(*roundTripper).buildHttp1Transport().MaxMergedHeadAndBody; got != limit {
			t.Errorf("a profile merging %d: the transport merges %d", limit, got)
		}
	}
}
