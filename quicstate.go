package tls_client

import (
	"container/list"
	"sync"
	"time"

	"github.com/igor-lemon/utls/behavior"
)

// QUICState is what the clients of one session know of QUIC, as Chromium's
// HttpServerProperties and QuicSessionPool know it for a profile: whether it
// has worked yet (has_quic_ever_worked_on_current_network_), the servers it
// failed for where TCP did not and until when they are not tried again
// (BrokenAlternativeServices), how often each failed lately, and each
// server's smoothed RTT as its last connection measured it
// (ServerNetworkStats), and the alternative services each origin's answers
// advertised (Alt-Svc). A server is the key a client gives (its top-level
// site, as Chromium keys them by NetworkAnonymizationKey) and its address.
// Share one across the clients of a session; NewQUICState makes one.
type QUICState struct {
	mu     sync.Mutex
	now    func() time.Time
	worked bool
	broken map[quicServer]time.Time
	// recent are the servers that broke lately and how often, the most
	// recently used first (Chromium's recently_broken LRU): kept after a
	// break ends, so that the next lasts longer, and forgotten when QUIC to
	// the server works again.
	recent      *list.List
	recentByKey map[quicServer]*list.Element
	rtts        *list.List
	rttsByKey   map[quicServer]*list.Element
	// alts are the origins' alternative services, the most recently used
	// first (learnAltSvc, altSvcOf).
	alts         *list.List
	altsByOrigin map[quicServer]*list.Element
}

type quicServer struct{ key, addr string }

type recentBreak struct {
	server quicServer
	count  uint64
}

type serverRTT struct {
	server quicServer
	rtt    time.Duration
}

// NewQUICState is a session's QUIC state, knowing nothing yet.
func NewQUICState() *QUICState {
	return &QUICState{now: time.Now, broken: map[quicServer]time.Time{},
		recent: list.New(), recentByKey: map[quicServer]*list.Element{},
		rtts: list.New(), rttsByKey: map[quicServer]*list.Element{},
		alts: list.New(), altsByOrigin: map[quicServer]*list.Element{}}
}

// isBroken says whether QUIC to s is not tried now; a break that ended is
// forgotten, the server staying recently broken.
func (q *QUICState) isBroken(s quicServer) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.brokenLocked(s)
}

func (q *QUICState) brokenLocked(s quicServer) bool {
	until, ok := q.broken[s]
	if ok && !q.now().Before(until) {
		delete(q.broken, s)
		return false
	}
	return ok
}

// markBroken has QUIC to s not tried again for as long as p says of the
// break that follows as many lately: quic.broken_ms doubled once for each
// break before it, quic.broken_doublings times at most, at most
// quic.broken_max_ms (ComputeBrokenAlternativeServiceExpirationDelay). A
// server broken already keeps the end it had, its count going up.
func (q *QUICState) markBroken(s quicServer, p behavior.Policy) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var before uint64
	if e, ok := q.recentByKey[s]; ok {
		r := e.Value.(*recentBreak)
		before = r.count
		r.count++
		q.recent.MoveToFront(e)
	} else {
		q.recentByKey[s] = q.recent.PushFront(&recentBreak{server: s, count: 1})
		for uint64(q.recent.Len()) > p.Uint("quic.broken_recent_max") {
			last := q.recent.Back()
			delete(q.recentByKey, last.Value.(*recentBreak).server)
			q.recent.Remove(last)
		}
	}
	if q.brokenLocked(s) {
		return
	}
	q.broken[s] = q.now().Add(brokenFor(before, p))
}

// brokenFor is how long a break lasts that follows before others lately.
func brokenFor(before uint64, p behavior.Policy) time.Duration {
	most := p.Uint("quic.broken_max_ms")
	ms := p.Uint("quic.broken_ms")
	for n := uint64(0); n < min(before, p.Uint("quic.broken_doublings")) && ms < most; n++ {
		ms *= 2
	}
	return time.Duration(min(ms, most)) * time.Millisecond
}

// workedFor is told QUIC to s worked: QUIC is known to work from then on,
// and s is broken no more, nor recently (ConfirmAlternativeService).
func (q *QUICState) workedFor(s quicServer) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.worked = true
	delete(q.broken, s)
	if e, ok := q.recentByKey[s]; ok {
		q.recent.Remove(e)
		delete(q.recentByKey, s)
	}
}

// setRTT keeps s's smoothed RTT, as a connection that went away after its
// handshake measured it, the servers kept at most quic.server_rtts_max, the
// least recently set forgotten first.
func (q *QUICState) setRTT(s quicServer, rtt time.Duration, p behavior.Policy) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if e, ok := q.rttsByKey[s]; ok {
		e.Value.(*serverRTT).rtt = rtt
		q.rtts.MoveToFront(e)
		return
	}
	q.rttsByKey[s] = q.rtts.PushFront(&serverRTT{server: s, rtt: rtt})
	for uint64(q.rtts.Len()) > p.Uint("quic.server_rtts_max") {
		last := q.rtts.Back()
		delete(q.rttsByKey, last.Value.(*serverRTT).server)
		q.rtts.Remove(last)
	}
}

// tcpWait is how long a request's TCP connection to s waits once its QUIC
// one is under way (QuicSessionPool::GetTimeDelayForWaitingJob, at most
// kMaxDelayTimeForMainJobSecs): quic.tcp_wait_cold_ms while QUIC has not
// worked in the session, quic.tcp_wait_broken_ms for a server broken lately,
// else quic.tcp_wait_rtt_percent of its RTT, or quic.tcp_wait_default_ms with
// none known, and quic.tcp_wait_extra_ms more; quic.tcp_wait_max_ms at most.
func (q *QUICState) tcpWait(s quicServer, p behavior.Policy) time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	ms := func(k string) time.Duration { return time.Duration(p.Uint(k)) * time.Millisecond }
	var wait time.Duration
	known, measured := q.rttsByKey[s]
	switch {
	case !q.worked:
		wait = ms("quic.tcp_wait_cold_ms")
	case q.recentlyBrokenLocked(s):
		wait = ms("quic.tcp_wait_broken_ms")
	case measured:
		wait = known.Value.(*serverRTT).rtt*time.Duration(p.Uint("quic.tcp_wait_rtt_percent"))/100 + ms("quic.tcp_wait_extra_ms")
	default:
		wait = ms("quic.tcp_wait_default_ms") + ms("quic.tcp_wait_extra_ms")
	}
	return min(wait, ms("quic.tcp_wait_max_ms"))
}

// recentlyBrokenLocked says whether s broke lately or is broken now
// (WasAlternativeServiceRecentlyBroken), the most recently used of the
// recent ones from then on.
func (q *QUICState) recentlyBrokenLocked(s quicServer) bool {
	if e, ok := q.recentByKey[s]; ok {
		q.recent.MoveToFront(e)
		return true
	}
	return q.brokenLocked(s)
}
