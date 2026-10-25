package tls_client

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/igor-lemon/utls/behavior"
)

// chromeDNSH3 is Chrome 155's policy of HTTP/3 by an HTTPS record, as its
// numbers are kept apart from the rest of a profile.
func chromeDNSH3(t *testing.T, changes map[string]string) behavior.Policy {
	t.Helper()
	p := behavior.Policy{}
	for k, v := range map[string]string{"quic.tcp_wait_cold_ms": "0", "quic.tcp_wait_broken_ms": "0",
		"quic.tcp_wait_rtt_percent": "150", "quic.tcp_wait_default_ms": "300", "quic.tcp_wait_extra_ms": "0",
		"quic.tcp_wait_max_ms": "3000", "quic.broken_ms": "300000", "quic.broken_doublings": "18",
		"quic.broken_max_ms": "172800000", "quic.broken_recent_max": "200", "quic.server_rtts_max": "500"} {
		p[k] = json.RawMessage(v)
	}
	for k, v := range changes {
		p[k] = json.RawMessage(v)
	}
	return p
}

// clocked is a state whose clock the test moves.
func clocked() (*QUICState, *time.Time) {
	q := NewQUICState()
	now := time.Unix(1_000_000, 0)
	q.now = func() time.Time { return now }
	return q, &now
}

func TestTCPWaitsBehindQUICAsChromesMainJobWaits(t *testing.T) {
	p := chromeDNSH3(t, nil)
	q, _ := clocked()
	a, b := quicServer{"https://a.test", "a.test:443"}, quicServer{"https://a.test", "b.test:443"}
	q.setRTT(a, 10*time.Millisecond, p)
	// QUIC has not worked in the session: TCP goes at once, RTT or not.
	if got := q.tcpWait(a, p); got != 0 {
		t.Errorf("cold: %v", got)
	}
	q.workedFor(b)
	for _, tc := range []struct {
		name    string
		s       quicServer
		changes map[string]string
		want    time.Duration
	}{
		{"a server's RTT, half as long again", a, nil, 15 * time.Millisecond},
		{"no RTT known", b, nil, 300 * time.Millisecond},
		{"and an extra wait", b, map[string]string{"quic.tcp_wait_extra_ms": "100"}, 400 * time.Millisecond},
		{"an RTT and an extra wait", a, map[string]string{"quic.tcp_wait_extra_ms": "100"}, 115 * time.Millisecond},
		{"at most the most", b, map[string]string{"quic.tcp_wait_max_ms": "250"}, 250 * time.Millisecond},
		{"the cold wait said", b, map[string]string{"quic.tcp_wait_cold_ms": "77"}, 300 * time.Millisecond},
	} {
		if got := q.tcpWait(tc.s, chromeDNSH3(t, tc.changes)); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	q.setRTT(a, 10*time.Second, p)
	if got := q.tcpWait(a, p); got != 3*time.Second {
		t.Errorf("a long RTT: %v, want the most", got)
	}
	q.setRTT(a, 20*time.Millisecond, p)
	if got := q.tcpWait(a, p); got != 30*time.Millisecond {
		t.Errorf("an RTT measured again: %v", got)
	}
	// A server broken lately: TCP at once.
	q.markBroken(a, p)
	if got := q.tcpWait(a, chromeDNSH3(t, map[string]string{"quic.tcp_wait_broken_ms": "5"})); got != 5*time.Millisecond {
		t.Errorf("broken: %v", got)
	}
}

func TestQUICIsBrokenForLongerEachTimeItBreaksLately(t *testing.T) {
	p := chromeDNSH3(t, nil)
	q, now := clocked()
	s := quicServer{"https://a.test", "a.test:443"}
	if q.isBroken(s) {
		t.Fatal("broken before it broke")
	}
	// 300 s, then twice as long each time, as Chromium's backoff on its
	// initial delay: 600 s, 1200 s...
	for i, want := range []time.Duration{300, 600, 1200, 2400} {
		q.markBroken(s, p)
		if !q.isBroken(s) {
			t.Fatalf("break %d: not broken", i)
		}
		*now = now.Add(want*time.Second - time.Millisecond)
		if !q.isBroken(s) {
			t.Errorf("break %d: over before %v", i, want*time.Second)
		}
		*now = now.Add(time.Millisecond)
		if q.isBroken(s) {
			t.Errorf("break %d: not over at %v", i, want*time.Second)
		}
	}
	// A break while broken keeps its end, and counts.
	q.markBroken(s, p)
	*now = now.Add(time.Hour)
	q.markBroken(s, p)
	*now = now.Add(4800*time.Second - time.Hour)
	if q.isBroken(s) {
		t.Error("a break while broken moved its end")
	}
	q.markBroken(s, p)
	*now = now.Add(19200*time.Second - time.Millisecond)
	if !q.isBroken(s) {
		t.Error("the break after one while broken does not count it")
	}
	// It works again: the next break is the first.
	q.workedFor(s)
	if q.isBroken(s) {
		t.Error("broken once it worked")
	}
	q.markBroken(s, p)
	*now = now.Add(300 * time.Second)
	if q.isBroken(s) {
		t.Error("the first break after it worked lasts longer than the first")
	}
}

func TestABreakLastsAtMostTheLongestAndDoublesAsOftenAsSaid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		before  uint64
		changes map[string]string
		want    time.Duration
	}{
		{"the first", 0, nil, 300 * time.Second},
		{"the eleventh, past two days", 10, nil, 48 * time.Hour},
		{"the hundredth", 99, nil, 48 * time.Hour},
		{"doubled twice at most", 5, map[string]string{"quic.broken_doublings": "2"}, 1200 * time.Second},
		{"never doubled", 5, map[string]string{"quic.broken_doublings": "0"}, 300 * time.Second},
		{"a first that is the longest", 3, map[string]string{"quic.broken_max_ms": "300000"}, 300 * time.Second},
		{"the longest of all, never past it", 62, map[string]string{"quic.broken_doublings": "62",
			"quic.broken_ms": "86400000", "quic.broken_max_ms": "31536000000"}, 31536000000 * time.Millisecond},
	} {
		if got := brokenFor(tc.before, chromeDNSH3(t, tc.changes)); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestTheServersThatBrokeAndTheirRTTsAreRememberedAsFarAsSaid(t *testing.T) {
	p := chromeDNSH3(t, map[string]string{"quic.broken_recent_max": "2", "quic.server_rtts_max": "2"})
	q, now := clocked()
	a, b, c, d := quicServer{"k", "a:443"}, quicServer{"k", "b:443"}, quicServer{"k", "c:443"}, quicServer{"k", "d:443"}
	q.markBroken(a, p)
	q.markBroken(b, p)
	q.markBroken(c, p) // a, the least recently broken, forgotten: c, b
	*now = now.Add(300 * time.Second)
	q.markBroken(b, p) // b's second: 600 s; b, c
	q.markBroken(a, p) // a's first again: 300 s; a, b
	*now = now.Add(300 * time.Second)
	if q.isBroken(a) || !q.isBroken(b) {
		t.Errorf("a broken %v, b broken %v; want b alone", q.isBroken(a), q.isBroken(b))
	}
	// Asking whether one broke lately makes it the most recently used.
	q.workedFor(d)
	q.markBroken(c, p) // c, a; b forgotten
	q.tcpWait(a, p)    // a, c
	q.markBroken(d, p) // d, a; c forgotten
	if _, kept := q.recentByKey[c]; kept {
		t.Error("c kept, though a was asked about since")
	}
	if _, kept := q.recentByKey[a]; !kept {
		t.Error("a forgotten, though asked about last")
	}
	e := quicServer{"k", "e:443"}
	q.setRTT(a, time.Millisecond, p)
	q.setRTT(e, time.Millisecond, p)
	q.setRTT(a, 2*time.Millisecond, p) // a, e
	q.setRTT(b, time.Millisecond, p)   // b, a; e forgotten
	if got := q.tcpWait(e, p); got != 300*time.Millisecond {
		t.Errorf("e's RTT kept past the bound: %v", got)
	}
	q.workedFor(a)
	if got := q.tcpWait(a, p); got != 3*time.Millisecond {
		t.Errorf("a's RTT: %v", got)
	}
}
