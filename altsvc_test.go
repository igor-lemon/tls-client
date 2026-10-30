package tls_client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/igor-lemon/fhttp"
	quic "github.com/igor-lemon/quic-go-utls"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
)

func TestAnAltSvcValueIsReadAsQuicheReadsIt(t *testing.T) {
	type e = altSvcEntry
	for _, tc := range []struct {
		value string
		want  []altSvcEntry
		ok    bool
	}{
		{`h3=":443"`, []e{{"h3", "", 443, 86400}}, true},
		{`h3=":443"; ma=60`, []e{{"h3", "", 443, 60}}, true},
		{`h3=":443";ma=60`, []e{{"h3", "", 443, 60}}, true},
		{`h3=":443" ;  ma = 60 ; persist=1`, []e{{"h3", "", 443, 60}}, true},
		{`h3=":443"; MA=60`, []e{{"h3", "", 443, 60}}, true},
		{`h3=":443"; ma=4294967295`, []e{{"h3", "", 443, 4294967295}}, true},
		{`h3="b.test:8443"`, []e{{"h3", "b.test", 8443, 86400}}, true},
		{`h3="[::1]:443"`, []e{{"h3", "[::1]", 443, 86400}}, true},
		{`h3="a\"b:443"`, []e{{"h3", `a"b`, 443, 86400}}, true},
		{`h3="a\\b:443"`, []e{{"h3", `a\b`, 443, 86400}}, true},
		{`h3=":443", h3-29=":8443"; ma=10`, []e{{"h3", "", 443, 86400}, {"h3-29", "", 8443, 10}}, true},
		{`h3=":443",,  h2=":443", `, []e{{"h3", "", 443, 86400}, {"h2", "", 443, 86400}}, true},
		{`h%33=":443"`, []e{{"h3", "", 443, 86400}}, true},
		{`h3=":443"; v="25,26"`, []e{{"h3", "", 443, 86400}}, true},
		{`h3=":443"; v="25,26", h2=":1"`, []e{{"h3", "", 443, 86400}, {"h2", "", 1, 86400}}, true},
		{`hq=":443";quic=51303338;quic=51303334`, []e{{"hq", "", 443, 86400}}, true},
		{`h3=":443"; =5`, []e{{"h3", "", 443, 86400}}, true},
		{`h3=":443";`, []e{{"h3", "", 443, 86400}}, true},
		{`h3=":443"; `, []e{{"h3", "", 443, 86400}}, true},
		{`h3=":443" , h2=":1"`, []e{{"h3", "", 443, 86400}, {"h2", "", 1, 86400}}, true},
		{`h3="[\"::1]:443"`, nil, false},
		{"clear", nil, true},
		{"", nil, false},
		{"CLEAR", nil, false},
		{"h3", nil, false},
		{`=":443"`, nil, false},
		{`h3=:443`, nil, false},
		{`h3=`, nil, false},
		{`h3=":443`, nil, false},
		{`h3="\`, nil, false},
		{`h3=""`, nil, false},
		{`h3=":"`, nil, false},
		{`h3=":0"`, nil, false},
		{`h3=":65536"`, nil, false},
		{`h3=":44a"`, nil, false},
		{`h3="host"`, nil, false},
		{`h3="[::1]"`, nil, false},
		{`h3="[::1:443"`, nil, false},
		{`h3="a\`, nil, false},
		{`h3=":443"; ma=0`, nil, false},
		{`h3=":443"; ma=-1`, nil, false},
		{`h3=":443"; ma=4294967296`, nil, false},
		{`h3=":443"; ma`, nil, false},
		{`h3=":443"; ma=`, nil, false},
		{`h3=":443" x`, nil, false},
		{`h3=":443"; v=25`, nil, false},
		{`h3=":443"; v="25,"`, nil, false},
		{`h3=":443"; v=""`, nil, false},
		{`h3=":443"; v="25`, nil, false},
		{`h3=":443"; v="x"`, nil, false},
		{`h%3=":443"`, nil, false},
		{`h%=":443"`, nil, false},
		{`h%zz=":443"`, nil, false},
		{`hq=":443";quic=0abc`, nil, false},
		{`hq=":443";quic=xyz`, nil, false},
		{`hq=":443";quic=123456789`, nil, false},
		{`hq=":443";quic=0`, nil, false},
		{`h3=":443";quic=0`, []e{{"h3", "", 443, 86400}}, true},
		{`hq=":443"; v="25"`, []e{{"hq", "", 443, 86400}}, true},
		{`hq=":443"; v="x"`, []e{{"hq", "", 443, 86400}}, true},
		{"h3=\":443\";\tma\t=\t60", []e{{"h3", "", 443, 60}}, true},
		{"h3=\":443\"; ma=60\t; persist=1", []e{{"h3", "", 443, 60}}, true},
		{"h3=\":443\",\th2=\":1\"", []e{{"h3", "", 443, 86400}, {"h2", "", 1, 86400}}, true},
		{`h3=x:443"`, nil, false},
		{`h3="[::1]443"`, nil, false},
		{`h3=":443"; persist 11`, nil, false},
		{`h3=":443"; persist=`, nil, false},
		{`h3=":443"; v=x25"`, nil, false},
		{`h3=":443"; v="65536"`, nil, false},
		{`h3=":443"; v="25,,26"`, nil, false},
		{`hq=":443";quic=01`, nil, false},
		{`hq=":443";quic=100000000`, nil, false},
	} {
		got, ok := parseAltSvc(tc.value)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: %v, %v, want %v, %v", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAnAltAuthorityEndingInABackslashHasNoPort(t *testing.T) {
	// parseAltSvc hands it none, its backslashes paired: one alone escapes
	// nothing, and no port follows it.
	if host, port, ok := parseAltAuthority(`a\`); ok || host != "" || port != 0 {
		t.Errorf("%q, %d, %v, want none", host, port, ok)
	}
}

// altSvcPolicy is dnsH3Policy following Alt-Svc as Chrome 155 does, with
// changes.
func altSvcPolicy(t *testing.T, changes map[string]string) behavior.Policy {
	t.Helper()
	all := map[string]string{"quic.alt_svc": "true", "quic.alt_svc_user_ports": "false",
		"quic.alt_svc_remote_hosts": "true", "quic.alt_svc_tcp_waits_with_h2": "false"}
	for k, v := range changes {
		all[k] = v
	}
	return dnsH3Policy(t, all)
}

func TestAnOriginsAlternativesAreKeptAsChromiumKeepsThem(t *testing.T) {
	p := altSvcPolicy(t, map[string]string{"quic.server_rtts_max": "2"})
	q := NewQUICState()
	now := time.Unix(1000, 0)
	q.now = func() time.Time { return now }
	a := quicServer{"https://a.test", "a.test:443"}
	entries := func(value string) []altSvcEntry {
		e, ok := parseAltSvc(value)
		if !ok {
			t.Fatalf("%q not read", value)
		}
		return e
	}
	// The h3 ones alone, in order, each until its max age.
	q.learnAltSvc(a, entries(`h2=":1", h3=":2"; ma=10, h3-29=":3", h3="b.test:4"`), p)
	want := []altService{{port: 2, expires: now.Add(10 * time.Second)}, {host: "b.test", port: 4, expires: now.Add(86400 * time.Second)}}
	if got := q.altSvcOf(a); !reflect.DeepEqual(got, want) {
		t.Fatalf("kept %v, want %v", got, want)
	}
	// Good up to its max age, and no longer.
	now = now.Add(10 * time.Second)
	if got := q.altSvcOf(a); len(got) != 2 {
		t.Errorf("at its max age: %v", got)
	}
	now = now.Add(time.Nanosecond)
	if got := q.altSvcOf(a); !reflect.DeepEqual(got, want[1:]) {
		t.Errorf("past it: %v, want %v", got, want[1:])
	}
	// What a later answer says replaces it; one with no h3 forgets it, as a
	// clear does.
	q.learnAltSvc(a, entries(`h3=":5"`), p)
	if got := q.altSvcOf(a); len(got) != 1 || got[0].port != 5 {
		t.Errorf("replaced: %v", got)
	}
	q.learnAltSvc(a, entries(`h2=":1"`), p)
	if got := q.altSvcOf(a); got != nil || len(q.altsByOrigin) != 0 {
		t.Errorf("after one with no h3: %v", got)
	}
	q.learnAltSvc(a, entries(`h3=":5"`), p)
	q.learnAltSvc(a, entries(`clear`), p)
	if got := q.altSvcOf(a); got != nil {
		t.Errorf("after a clear: %v", got)
	}
	q.learnAltSvc(a, nil, p)
	// Every alternative past its time forgets the origin.
	q.learnAltSvc(a, entries(`h3=":5"; ma=1`), p)
	now = now.Add(2 * time.Second)
	if got := q.altSvcOf(a); got != nil || len(q.altsByOrigin) != 0 {
		t.Errorf("all past their time: %v", got)
	}
	// Each key's origins its own, as many as quic.server_rtts_max, the least
	// recently used forgotten first.
	b := quicServer{"https://a.test", "b.test:443"}
	other := quicServer{"https://b.test", "a.test:443"}
	q.learnAltSvc(a, entries(`h3=":5"`), p)
	q.learnAltSvc(b, entries(`h3=":6"`), p)
	if got := q.altSvcOf(other); got != nil {
		t.Errorf("another site's: %v", got)
	}
	q.altSvcOf(a)
	q.learnAltSvc(other, entries(`h3=":7"`), p)
	if q.altSvcOf(b) != nil || q.altSvcOf(a) == nil || q.altSvcOf(other) == nil {
		t.Error("not the least recently used forgotten")
	}
}

func TestAlternativesAreThoseARequestMayGoTo(t *testing.T) {
	d := newDNSH3(&HTTP3FromDNS{State: NewQUICState(), Key: func() string { return "https://a.test" }})
	p := altSvcPolicy(t, nil)
	rt := &roundTripper{behavior: p}
	learn := func(addr, value string) {
		e, ok := parseAltSvc(value)
		if !ok {
			t.Fatalf("%q not read", value)
		}
		d.State.learnAltSvc(quicServer{"https://a.test", addr}, e, p)
	}
	learn("a.test:443", `h3=":443", h3=":8443", h3="B.test:443", h3="[::1]:443", h3="a.test:444"`)
	// A port of 1024 or more is not taken for an origin below it.
	want := []string{"a.test:443", "B.test:443", "[::1]:443", "a.test:444"}
	if got := d.alternatives(rt, "a.test:443"); !reflect.DeepEqual(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
	rt.behavior = altSvcPolicy(t, map[string]string{"quic.alt_svc_user_ports": "true", "quic.alt_svc_remote_hosts": "false"})
	want = []string{"a.test:443", "a.test:8443", "a.test:444"}
	if got := d.alternatives(rt, "a.test:443"); !reflect.DeepEqual(got, want) {
		t.Errorf("with user ports and no other hosts: %v, want %v", got, want)
	}
	// One broken is passed over; for an origin on a high port any is taken.
	d.State.markBroken(quicServer{"https://a.test", "a.test:443"}, p)
	rt.behavior = p
	want = []string{"B.test:443", "[::1]:443", "a.test:444"}
	if got := d.alternatives(rt, "a.test:443"); !reflect.DeepEqual(got, want) {
		t.Errorf("one broken: %v, want %v", got, want)
	}
	learn("a.test:8443", `h3=":9443"`)
	if got := d.alternatives(rt, "a.test:8443"); !reflect.DeepEqual(got, []string{"a.test:9443"}) {
		t.Errorf("from a high port: %v", got)
	}
	// Without quic.alt_svc, or for an address that is none, there are none.
	rt.behavior = dnsH3Policy(t, nil)
	if got := d.alternatives(rt, "a.test:443"); got != nil {
		t.Errorf("without quic.alt_svc: %v", got)
	}
	rt.behavior = p
	if got := d.alternatives(rt, "a.test"); got != nil {
		t.Errorf("for no address: %v", got)
	}
}

// altURL is the URL of path at o whose answer advertises alt.
func altURL(o *h3Origin, path, alt string) string {
	return "https://" + o.addr + path + "?alt=" + url.QueryEscape(alt)
}

// portOf is the port of o's address.
func portOf(o *h3Origin) string {
	_, port, _ := net.SplitHostPort(o.addr)
	return port
}

func TestAnAlternativeServiceTakesTheRequestsAfterTheOneThatAdvertisedIt(t *testing.T) {
	// No record names h3. The first answer advertises the origin's own port:
	// the next request goes at once over the HTTP/2 connection the origin
	// has, its QUIC connection made apart, and the one after over it.
	o := newH3Origin(t, originSays{})
	c := h3Client(t, altSvcPolicy(t, nil), &recordSays{}, NewQUICState())
	if got := came(t, c, altURL(o, "/", `h3=":`+portOf(o)+`"`)); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if o.quicConns.Load() != 0 {
		t.Fatal("QUIC before any request after the answer")
	}
	if got := came(t, c, "https://"+o.addr+"/b"); got != "HTTP/2.0" {
		t.Errorf("the next came over %q, want the HTTP/2 connection at once", got)
	}
	o.quicConn(t, 0)
	if got := came(t, c, "https://"+o.addr+"/c"); got != "HTTP/3.0" {
		t.Errorf("the one after came over %q, want HTTP/3", got)
	}
	if o.tcpConns.Load() != 1 || o.quicConns.Load() != 1 {
		t.Errorf("TCP connections %d, QUIC %d, want one each", o.tcpConns.Load(), o.quicConns.Load())
	}
}

func TestAnAlternativeOnAnotherPortOrHostIsDialedThere(t *testing.T) {
	for _, host := range []string{"", "b.test"} {
		o := newH3Origin(t, originSays{})
		there := newH3Origin(t, originSays{})
		c := h3Client(t, altSvcPolicy(t, nil), &recordSays{}, NewQUICState())
		if got := came(t, c, altURL(o, "/", `h3="`+host+`:`+portOf(there)+`"`)); got != "HTTP/2.0" {
			t.Fatalf("came over %q, want TCP's", got)
		}
		if got := came(t, c, "https://"+o.addr+"/b"); got != "HTTP/2.0" {
			t.Errorf("host %q: the next came over %q, want TCP's", host, got)
		}
		there.quicConn(t, 0)
		if got := came(t, c, "https://"+o.addr+"/c"); got != "HTTP/3.0" {
			t.Errorf("host %q: the one after came over %q, want HTTP/3", host, got)
		}
		if o.quicConns.Load() != 0 || there.quicConns.Load() != 1 || there.tcpConns.Load() != 0 {
			t.Errorf("host %q: QUIC to the origin %d, to the alternative %d, TCP there %d", host,
				o.quicConns.Load(), there.quicConns.Load(), there.tcpConns.Load())
		}
	}
}

func TestAnAlternativeHoldsTCPBackWhateverConnectionTheOriginHasButHTTP2(t *testing.T) {
	// An HTTP/1.1 origin: while QUIC has not worked in the session TCP waits
	// none, and the request goes on the connection it has, QUIC made apart;
	// once QUIC worked, TCP waits 300 ms behind it (no RTT known), the
	// connection the origin has too, and QUIC takes the request.
	for _, worked := range []bool{false, true} {
		h1 := new(atomic.Bool)
		h1.Store(true)
		o := newH3Origin(t, originSays{h1: h1})
		state := NewQUICState()
		if worked {
			state.workedFor(quicServer{"https://a.test", "elsewhere.test:443"})
		}
		c := h3Client(t, altSvcPolicy(t, nil), &recordSays{}, state)
		if got := came(t, c, altURL(o, "/", `h3=":`+portOf(o)+`"`)); got != "HTTP/1.1" {
			t.Fatalf("came over %q, want TCP's", got)
		}
		want := "HTTP/1.1"
		if worked {
			want = "HTTP/3.0"
		}
		if got := came(t, c, "https://"+o.addr+"/b"); got != want {
			t.Errorf("QUIC worked %v: the next came over %q, want %s", worked, got, want)
		}
		o.quicConn(t, 0)
		if o.tcpConns.Load() != 1 {
			t.Errorf("QUIC worked %v: %d TCP connections, want the one the origin has", worked, o.tcpConns.Load())
		}
	}
	// An HTTP/2 origin, QUIC worked (bench/alt, h2known): the request at
	// once on its connection, QUIC made apart, which takes the next; where
	// the profile has TCP wait behind QUIC over HTTP/2 too, QUIC takes the
	// request that waits 300 ms.
	for _, waits := range []bool{false, true} {
		o := newH3Origin(t, originSays{})
		state := NewQUICState()
		state.workedFor(quicServer{"https://a.test", "elsewhere.test:443"})
		policy := altSvcPolicy(t, map[string]string{"quic.alt_svc_tcp_waits_with_h2": strconv.FormatBool(waits)})
		c := h3Client(t, policy, &recordSays{}, state)
		if got := came(t, c, altURL(o, "/", `h3=":`+portOf(o)+`"`)); got != "HTTP/2.0" {
			t.Fatalf("came over %q, want TCP's", got)
		}
		want := "HTTP/2.0"
		if waits {
			want = "HTTP/3.0"
		}
		if got := came(t, c, "https://"+o.addr+"/b"); got != want {
			t.Errorf("TCP waits %v: the next came over %q, want %s", waits, got, want)
		}
		o.quicConn(t, 0)
		if got := came(t, c, "https://"+o.addr+"/c"); got != "HTTP/3.0" {
			t.Errorf("TCP waits %v: the one after came over %q, want QUIC's", waits, got)
		}
		if o.tcpConns.Load() != 1 || o.quicConns.Load() != 1 {
			t.Errorf("TCP waits %v: %d TCP connections and %d QUIC, want one each", waits, o.tcpConns.Load(), o.quicConns.Load())
		}
	}
}

func TestAQUICConnectionIsTakenAsWhatItWasMadeForSays(t *testing.T) {
	// One made for an alternative is taken while the origin advertises that
	// alternative, and breaks as the alternative; one made for the origin
	// itself (its record) whatever the origin advertises, though one for an
	// alternative was made before it, and breaks as the origin.
	d := newDNSH3(&HTTP3FromDNS{State: NewQUICState(), Key: func() string { return "https://a.test" }})
	made := func(job quicJob) {
		a, _ := d.attempt("a.test:443", job)
		// Done, as preconnect forgets it.
		d.mu.Lock()
		if d.attempts["a.test:443"] == a {
			delete(d.attempts, "a.test:443")
		}
		d.mu.Unlock()
	}
	takes := func(addr string, alts []string) bool {
		_, ok := d.taking(addr, alts)
		return ok
	}
	made(quicJob{dest: "b.test:443"})
	if s, ok := d.taking("a.test:443", []string{"c.test:443", "b.test:443"}); !ok || s != (quicServer{"https://a.test", "b.test:443"}) {
		t.Errorf("one made for an alternative still advertised: %v, %v", s, ok)
	}
	if takes("a.test:443", nil) || takes("a.test:443", []string{"c.test:443"}) {
		t.Error("one made for an alternative no longer advertised is taken")
	}
	made(quicJob{})
	if s, ok := d.taking("a.test:443", []string{"c.test:443"}); !ok || s != (quicServer{"https://a.test", "a.test:443"}) {
		t.Errorf("one made for the origin's record: %v, %v", s, ok)
	}
	if !takes("a.test:443", nil) {
		t.Error("one made for the origin's record is not taken with nothing advertised")
	}
	if !takes("b.test:443", nil) {
		t.Error("an origin nothing was made for has a connection made for an alternative")
	}
}

func TestARequestFailedOnAnAlternativesConnectionBreaksTheAlternative(t *testing.T) {
	// The alternative's QUIC connection takes a request, then fails the next
	// (its stream reset), which goes again over TCP: the alternative is
	// broken, not the origin, as Chromium marks the alternative service it
	// used.
	o := newH3Origin(t, originSays{tcpLag: 100 * time.Millisecond})
	there := newH3Origin(t, originSays{quicFails: resetting(0x200, 1)})
	state := NewQUICState()
	c := h3Client(t, altSvcPolicy(t, nil), &recordSays{}, state)
	if got := came(t, c, altURL(o, "/", `h3=":`+portOf(there)+`"`)); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	// No HTTP/2 connection left: QUIC and TCP race, and QUIC is up first.
	c.CloseIdleConnections()
	if got := came(t, c, "https://"+o.addr+"/b"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want the alternative's", got)
	}
	if got := came(t, c, "https://"+o.addr+"/c"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's after QUIC failed it", got)
	}
	host, _, _ := net.SplitHostPort(o.addr)
	if !state.isBroken(quicServer{"https://a.test", net.JoinHostPort(host, portOf(there))}) {
		t.Error("the alternative is not broken")
	}
	if state.isBroken(quicServer{"https://a.test", o.addr}) {
		t.Error("the origin is broken")
	}
}

func TestAnAlternativePastItsMaxAgeOrClearedIsNotGoneTo(t *testing.T) {
	// Past its max age: no QUIC, and the QUIC connection made to it takes no
	// request.
	o := newH3Origin(t, originSays{})
	c := h3Client(t, altSvcPolicy(t, nil), &recordSays{}, NewQUICState())
	if got := came(t, c, altURL(o, "/", `h3=":`+portOf(o)+`"; ma=1`)); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	came(t, c, "https://"+o.addr+"/b")
	o.quicConn(t, 0)
	time.Sleep(1100 * time.Millisecond)
	if got := came(t, c, "https://"+o.addr+"/c"); got != "HTTP/2.0" {
		t.Errorf("past its max age came over %q, want TCP's", got)
	}
	if o.quicConns.Load() != 1 {
		t.Errorf("%d QUIC connections, want the one made before", o.quicConns.Load())
	}
	// Cleared by an answer over QUIC: once that connection went, TCP alone.
	o = newH3Origin(t, originSays{})
	c = h3Client(t, altSvcPolicy(t, nil), &recordSays{}, NewQUICState())
	came(t, c, altURL(o, "/", `h3=":`+portOf(o)+`"`))
	came(t, c, "https://"+o.addr+"/b")
	o.quicConn(t, 0)
	if got := came(t, c, altURL(o, "/c", "clear")); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3", got)
	}
	_ = o.quicConn(t, 0).CloseWithError(0, "")
	time.Sleep(100 * time.Millisecond)
	if got := came(t, c, "https://"+o.addr+"/d"); got != "HTTP/2.0" {
		t.Errorf("after a clear came over %q, want TCP's", got)
	}
	time.Sleep(100 * time.Millisecond)
	if o.quicConns.Load() != 1 {
		t.Errorf("%d QUIC connections, want none more", o.quicConns.Load())
	}
}

func TestAnAnswerOf421OrAValueQuicheCannotReadChangesNothing(t *testing.T) {
	o := newH3Origin(t, originSays{})
	// This checks learning from real 421 answers, independently of which job
	// wins the cold TCP/QUIC race. Existing policy budgets establish H3 after
	// the first advertisement; TCP fallback remains enabled.
	c := h3Client(t, altSvcPolicy(t, map[string]string{
		"quic.alt_svc_tcp_waits_with_h2": "true", "quic.tcp_wait_cold_ms": "1000", "quic.tcp_wait_max_ms": "1000",
	}), &recordSays{}, NewQUICState())
	request := func(c HttpClient, url string, status int, protocol string) {
		t.Helper()
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(res.Body)
		closeErr := res.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("incomplete response: read=%v close=%v", readErr, closeErr)
		}
		if res.StatusCode != status || res.Proto != protocol || string(body) != protocol {
			t.Fatalf("actual response: status%d protocol%s body%q; want%d/%s", res.StatusCode, res.Proto, body, status, protocol)
		}
	}
	d := c.(*httpClient).built.dnsH3
	origin := quicServer{"https://a.test", o.addr}
	kept := func() {
		t.Helper()
		got := d.State.altSvcOf(origin)
		port, err := strconv.ParseUint(portOf(o), 10, 16)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].port != uint16(port) {
			t.Fatalf("what was kept after an advertisement, unread value or421: %v", got)
		}
	}
	request(c, altURL(o, "/", `h3=":0"`), 200, "HTTP/2.0")
	if d.State.altSvcOf(origin) != nil {
		t.Fatal("a value that is not read was taken")
	}
	request(c, altURL(o, "/", `h3=":`+portOf(o)+`"`), 200, "HTTP/2.0")
	kept()
	request(c, altURL(o, "/", `h3=":0"`), 200, "HTTP/3.0")
	kept()
	request(c, altURL(o, "/", "clear")+"&status=421", 421, "HTTP/3.0")
	kept()
	// Without quic.alt_svc nothing is kept.
	c = h3Client(t, dnsH3Policy(t, nil), &recordSays{}, NewQUICState())
	request(c, altURL(o, "/", `h3=":`+portOf(o)+`"`), 200, "HTTP/2.0")
	if got := c.(*httpClient).built.dnsH3.State.altSvcOf(origin); got != nil {
		t.Fatalf("kept without quic.alt_svc: %v", got)
	}
}

func TestABrokenAlternativeIsPassedOverForTheNext(t *testing.T) {
	// The first alternative's QUIC fails where TCP works: broken, the next
	// request goes to the second, which takes the one after.
	saved := dialQUIC
	var dials sync.WaitGroup
	t.Cleanup(func() {
		dials.Wait()
		dialQUIC = saved
	})
	o := newH3Origin(t, originSays{})
	second := newH3Origin(t, originSays{})
	hole := deadTCP(t)
	_, holePort, _ := net.SplitHostPort(hole)
	dialQUIC = func(ctx context.Context, remote *net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, sent func()) (*quic.Conn, error) {
		if strconv.Itoa(remote.Port) != holePort {
			return saved(ctx, remote, tlsCfg, cfg, sent)
		}
		dials.Add(1)
		defer dials.Done()
		sent()
		time.Sleep(50 * time.Millisecond)
		return nil, errors.New("no QUIC")
	}
	state := NewQUICState()
	c := h3Client(t, altSvcPolicy(t, nil), &recordSays{}, state)
	came(t, c, altURL(o, "/", `h3=":`+holePort+`", h3=":`+portOf(second)+`"`))
	if got := came(t, c, "https://"+o.addr+"/b"); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	if !waitFor(2*time.Second, func() bool {
		return state.isBroken(quicServer{"https://a.test", net.JoinHostPort("127.0.0.1", holePort)})
	}) {
		t.Fatal("the first alternative is not broken")
	}
	if got := came(t, c, "https://"+o.addr+"/c"); got != "HTTP/2.0" {
		t.Errorf("came over %q, want TCP's", got)
	}
	second.quicConn(t, 0)
	if got := came(t, c, "https://"+o.addr+"/d"); got != "HTTP/3.0" {
		t.Errorf("came over %q, want the second alternative's QUIC", got)
	}
}

func TestAlternativesAreKeptForTheTopLevelSiteTheyWereLearntIn(t *testing.T) {
	o := newH3Origin(t, originSays{})
	var site atomic.Value
	site.Store("https://a.test")
	records := &recordSays{}
	c, err := NewHttpClient(nil, WithClientProfile(profiles.Chrome_133.WithBehavior(altSvcPolicy(t, nil))),
		WithInsecureSkipVerify(), WithTimeoutSeconds(10),
		WithHTTP3FromDNS(HTTP3FromDNS{Endpoint: records.endpoint, State: NewQUICState(), Key: func() string { return site.Load().(string) }}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	came(t, c, altURL(o, "/", `h3=":`+portOf(o)+`"`))
	site.Store("https://b.test")
	if got := came(t, c, "https://"+o.addr+"/b"); got != "HTTP/2.0" {
		t.Errorf("came over %q, want TCP's", got)
	}
	time.Sleep(100 * time.Millisecond)
	if o.quicConns.Load() != 0 {
		t.Errorf("%d QUIC connections from another site", o.quicConns.Load())
	}
}

func TestAnAlternativeWhoseNameDoesNotResolveLeavesTheRequestToTCP(t *testing.T) {
	o := newH3Origin(t, originSays{})
	asked := make(chan string, 8)
	endpoint := func(ctx context.Context, addr string) (context.Context, QUICEndpoint, bool) {
		asked <- addr
		if host, _, _ := net.SplitHostPort(addr); host == "nowhere.test" {
			return ctx, QUICEndpoint{}, false
		}
		return ctx, QUICEndpoint{Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, false
	}
	c, err := NewHttpClient(nil, WithClientProfile(profiles.Chrome_133.WithBehavior(altSvcPolicy(t, nil))),
		WithInsecureSkipVerify(), WithTimeoutSeconds(10),
		WithHTTP3FromDNS(HTTP3FromDNS{Endpoint: endpoint, State: NewQUICState(), Key: func() string { return "https://a.test" }}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	came(t, c, altURL(o, "/", `h3="nowhere.test:`+portOf(o)+`"`))
	if got := came(t, c, "https://"+o.addr+"/b"); got != "HTTP/2.0" {
		t.Errorf("came over %q, want TCP's", got)
	}
	time.Sleep(100 * time.Millisecond)
	if o.quicConns.Load() != 0 {
		t.Errorf("%d QUIC connections", o.quicConns.Load())
	}
	var names []string
	for len(asked) > 0 {
		names = append(names, <-asked)
	}
	if len(names) == 0 || names[len(names)-1] != "nowhere.test:"+portOf(o) {
		t.Errorf("asked %v, want the alternative's name last", names)
	}
}

func TestAnAlternativesPortAndHostAreHeldToTheirRules(t *testing.T) {
	d := newDNSH3(&HTTP3FromDNS{State: NewQUICState(), Key: func() string { return "https://a.test" }})
	p := altSvcPolicy(t, map[string]string{"quic.alt_svc_remote_hosts": "false"})
	rt := &roundTripper{behavior: p}
	for _, tc := range []struct {
		addr, value string
		want        []string
	}{
		// 1024 is where the ports of the rule begin, for an origin below it.
		{"a.test:443", `h3=":1023", h3=":1024"`, []string{"a.test:1023"}},
		{"a.test:1023", `h3=":1024"`, nil},
		{"a.test:1024", `h3=":1024", h3=":443"`, []string{"a.test:1024", "a.test:443"}},
		// The origin's own host in other capitals is no other host.
		{"a.test:443", `h3="A.TEST:443"`, []string{"A.TEST:443"}},
		// An address that is no host and port has none, whatever is kept.
		{"a.test", `h3=":443"`, nil},
	} {
		e, _ := parseAltSvc(tc.value)
		d.State.learnAltSvc(quicServer{"https://a.test", tc.addr}, e, p)
		if got := d.alternatives(rt, tc.addr); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s, %s: %v, want %v", tc.addr, tc.value, got, tc.want)
		}
	}
}

func TestAnAnswersAltSvcFieldsAreReadAsOneValue(t *testing.T) {
	// Chromium reads the fields joined (GetNormalizedHeader): each one's
	// alternatives, and none of any when one is not read.
	d := newDNSH3(&HTTP3FromDNS{State: NewQUICState(), Key: func() string { return "https://a.test" }})
	rt := &roundTripper{behavior: altSvcPolicy(t, nil)}
	origin := quicServer{"https://a.test", "a.test:443"}
	answer := func(fields ...string) *http.Response {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Alt-Svc": fields}}
	}
	d.learn(rt, "a.test:443", answer(`h3=":443"`, `h3=":444"; ma=60`))
	if got := d.State.altSvcOf(origin); len(got) != 2 || got[1].port != 444 {
		t.Fatalf("two fields: %v", got)
	}
	d.learn(rt, "a.test:443", answer(`h3=":445"`, `h3=":0"`))
	if got := d.State.altSvcOf(origin); len(got) != 2 || got[0].port != 443 {
		t.Errorf("a field not read let the other through: %v", got)
	}
}

func TestAnAlternativesConnectionIsTimedForItsOrigin(t *testing.T) {
	// Chromium keeps a QUIC session's RTT for the origin it is for, wherever
	// it went, and holds the origin's TCP back by that (an alternative job
	// and its main job share the origin's server id): an RTT of a second for
	// the origin holds TCP back past a slow QUIC, whatever the alternative's
	// own, and the connection's RTT is the origin's once it went.
	o := newH3Origin(t, originSays{})
	there := newH3Origin(t, originSays{quicLag: 300 * time.Millisecond})
	p := altSvcPolicy(t, nil)
	state := NewQUICState()
	origin := quicServer{"https://a.test", o.addr}
	host, _, _ := net.SplitHostPort(o.addr)
	state.workedFor(quicServer{"https://a.test", "b.test:443"})
	state.setRTT(origin, time.Second, p)
	state.setRTT(quicServer{"https://a.test", net.JoinHostPort(host, portOf(there))}, time.Millisecond, p)
	before := state.tcpWait(origin, p)
	c := h3Client(t, p, &recordSays{}, state)
	if got := came(t, c, altURL(o, "/", `h3=":`+portOf(there)+`"`)); got != "HTTP/2.0" {
		t.Fatalf("came over %q, want TCP's", got)
	}
	// With no HTTP/2 connection to the origin left, its TCP waits.
	c.CloseIdleConnections()
	if got := came(t, c, "https://"+o.addr+"/b"); got != "HTTP/3.0" {
		t.Fatalf("came over %q, want HTTP/3 ahead of the origin's TCP", got)
	}
	c.CloseIdleConnections()
	if !waitFor(2*time.Second, func() bool { return state.tcpWait(origin, p) != before }) {
		t.Error("the alternative's connection did not time its origin")
	}
}
