package profiles

import "testing"

func TestAProfileThatFramesAndRecordsAsChromeIsACopy(t *testing.T) {
	base := Chrome_133
	with := base.WithMaxDataFramePayload(16375).WithDynamicRecordSizingDisabled(true)
	if base.GetMaxDataFramePayload() != 0 || base.GetDynamicRecordSizingDisabled() {
		t.Error("the profile it was made from frames or records otherwise")
	}
	if with.GetMaxDataFramePayload() != 16375 || !with.GetDynamicRecordSizingDisabled() {
		t.Errorf("the copy frames %d, records disabled %v", with.GetMaxDataFramePayload(), with.GetDynamicRecordSizingDisabled())
	}
	if with.GetClientHelloId().Client != base.GetClientHelloId().Client || len(with.GetSettings()) != len(base.GetSettings()) {
		t.Error("the copy is another profile")
	}
}

func TestAProfileThatWritesHTTP1AsChromeIsACopy(t *testing.T) {
	base := Chrome_133
	with := base.WithMaxMergedHeadAndBody(1400)
	if base.GetMaxMergedHeadAndBody() != 0 || with.GetMaxMergedHeadAndBody() != 1400 {
		t.Errorf("the profile merges %d, its copy %d", base.GetMaxMergedHeadAndBody(), with.GetMaxMergedHeadAndBody())
	}
}
