package tls_client

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/igor-lemon/utls/behavior"
)

// An origin's answers may advertise alternative services (Alt-Svc, RFC 7838):
// where else the origin is served, over which protocol. Chromium keeps them
// for the origin and the request's top-level site (HttpServerProperties,
// keyed by NetworkAnonymizationKey), each until its max age, and sends a
// later request to the origin over QUIC to the first of them it may use, as
// an alternative job (HttpStreamFactory::JobController), the request's TCP
// connection held back behind it as for an HTTPS record's h3.

// altSvcEntry is an alternative service as an Alt-Svc field says it
// (SpdyAltSvcWireFormat::AlternativeService): its protocol id, host (empty
// for the origin's own) and port, and how long it is good for.
type altSvcEntry struct {
	protocol string
	host     string
	port     uint16
	maxAge   uint32
}

// altSvcDefaultMaxAge is how long an alternative service that says no ma is
// good for, in seconds (RFC 7838, section 3.1).
const altSvcDefaultMaxAge = 86400

// parseAltSvc reads an Alt-Svc field value as Chromium's quiche reads it
// (SpdyAltSvcWireFormat::ParseHeaderFieldValue): "clear" is none, and a value
// it cannot read whole is not taken at all (false).
func parseAltSvc(value string) ([]altSvcEntry, bool) {
	if value == "" {
		return nil, false
	}
	if value == "clear" {
		return nil, true
	}
	var entries []altSvcEntry
	c, end := 0, len(value)
	for c != end {
		idEnd := indexFrom(value, c, '=')
		if idEnd == c {
			return nil, false
		}
		protocol, ok := percentDecode(value[c:idEnd])
		if !ok {
			return nil, false
		}
		// The IETF's draft form of advertising QUIC: hq=":443";quic=51303338.
		ietf := protocol == "hq"
		c = idEnd
		if c == end {
			return nil, false
		}
		c++
		if c == end || value[c] != '"' {
			return nil, false
		}
		c++
		authority := c
		for ; c != end && value[c] != '"'; c++ {
			if value[c] != '\\' {
				continue
			}
			c++
			if c == end {
				return nil, false
			}
		}
		if c == end {
			return nil, false
		}
		host, port, ok := parseAltAuthority(value[authority:c])
		if !ok {
			return nil, false
		}
		c++
		maxAge := uint32(altSvcDefaultMaxAge)
		paramsEnd := indexFrom(value, c, ',')
		for c != paramsEnd {
			c = skipWhite(value, c, paramsEnd)
			if c == paramsEnd {
				break
			}
			if value[c] != ';' {
				return nil, false
			}
			c++
			c = skipWhite(value, c, paramsEnd)
			if c == paramsEnd {
				break
			}
			var name strings.Builder
			for ; c != paramsEnd && value[c] != '=' && value[c] != ' ' && value[c] != '\t'; c++ {
				name.WriteByte(lowerASCII(value[c]))
			}
			c = skipWhite(value, c, paramsEnd)
			if c == paramsEnd || value[c] != '=' {
				return nil, false
			}
			c++
			c = skipWhite(value, c, paramsEnd)
			begin := c
			for ; c != paramsEnd && value[c] != ';' && value[c] != ' ' && value[c] != '\t'; c++ {
			}
			if c == begin {
				return nil, false
			}
			switch {
			case name.String() == "ma":
				if maxAge, ok = positiveUint(value[begin:c], 32); !ok {
					return nil, false
				}
			case !ietf && name.String() == "v":
				// A list of versions in quotes, which may hold commas that do
				// not end the entry.
				if value[begin] != '"' {
					return nil, false
				}
				closing := indexFrom(value, begin+1, '"')
				if closing == end {
					return nil, false
				}
				c = closing + 1
				paramsEnd = indexFrom(value, c, ',')
				// Each version a positive number of 16 bits: a list that is
				// empty or ends in a comma has an empty one.
				for v := begin + 1; v < c; {
					vEnd := v
					for vEnd < c-1 && value[vEnd] != ',' {
						vEnd++
					}
					if _, ok := positiveUint(value[v:vEnd], 16); !ok {
						return nil, false
					}
					v = vEnd + 1
				}
			case ietf && name.String() == "quic":
				// A QUIC version tag in hex, no leading zero, of 32 bits.
				if _, err := strconv.ParseUint(value[begin:c], 16, 32); err != nil || value[begin] == '0' {
					return nil, false
				}
			}
		}
		entries = append(entries, altSvcEntry{protocol: protocol, host: host, port: port, maxAge: maxAge})
		for ; c != end && (value[c] == ' ' || value[c] == '\t' || value[c] == ','); c++ {
		}
	}
	return entries, true
}

// parseAltAuthority is the host (empty for the origin's) and port of an
// alt-authority, its quotes taken off (SpdyAltSvcWireFormat::ParseAltAuthority):
// a backslash escapes the byte after it outside brackets, a quote inside them
// fails it, and the port is required. Outside brackets parseAltSvc hands it
// no quote a backslash does not escape, so quiche's check of one is left out.
func parseAltAuthority(a string) (string, uint16, bool) {
	var host strings.Builder
	c, end := 0, len(a)
	if strings.HasPrefix(a, "[") {
		for ; c != end && a[c] != ']'; c++ {
			if a[c] == '"' {
				return "", 0, false
			}
			host.WriteByte(a[c])
		}
		if c == end {
			return "", 0, false
		}
		host.WriteByte(a[c])
		c++
	} else {
		for ; c != end && a[c] != ':'; c++ {
			if a[c] == '\\' && c+1 != end {
				c++
			}
			host.WriteByte(a[c])
		}
	}
	if c == end || a[c] != ':' {
		return "", 0, false
	}
	port, ok := positiveUint(a[c+1:], 16)
	return host.String(), uint16(port), ok
}

// positiveUint reads digits alone as a number of bits wide, more than zero
// (ParsePositiveIntegerImpl).
func positiveUint(s string, bits int) (uint32, bool) {
	most := uint64(1)<<bits - 1
	var v uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		if v = v*10 + uint64(s[i]-'0'); v > most {
			return 0, false
		}
	}
	return uint32(v), v > 0
}

// percentDecode undoes the percent-encoding of a protocol id, a percent sign
// that two hex digits do not follow failing it (PercentDecode).
func percentDecode(s string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", false
		}
		out.WriteByte(byte(v))
		i += 2
	}
	return out.String(), true
}

// indexFrom is where b first is in s at or after from, or len(s).
func indexFrom(s string, from int, b byte) int {
	if i := strings.IndexByte(s[from:], b); i >= 0 {
		return from + i
	}
	return len(s)
}

// skipWhite is past the spaces and tabs at c, up to end.
func skipWhite(s string, c, end int) int {
	for c != end && (s[c] == ' ' || s[c] == '\t') {
		c++
	}
	return c
}

func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

// altService is an alternative service kept for an origin: its host (empty
// for the origin's own), port, and when it is no longer good.
type altService struct {
	host    string
	port    uint16
	expires time.Time
}

// originAlts are the alternative services kept for an origin.
type originAlts struct {
	origin quicServer
	alts   []altService
}

// altSvcALPN is the protocol id of the only QUIC an alternative service is
// taken for: version 1's (ExtractQuicVersionFromAltSvcEntry; versions that
// share its ALPN are not advertised so).
const altSvcALPN = "h3"

// learnAltSvc keeps what an answer of origin said of its alternative services
// in place of what was kept (HttpServerProperties::SetAlternativeServices):
// the h3 ones, each until its max age; none, or a clear, forgets the
// origin's. Origins are kept as servers' RTTs are, quic.server_rtts_max at
// most, the least recently used forgotten first (Chromium keeps both in one
// map of its servers).
func (q *QUICState) learnAltSvc(origin quicServer, entries []altSvcEntry, p behavior.Policy) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	var alts []altService
	for _, e := range entries {
		if e.protocol == altSvcALPN {
			alts = append(alts, altService{host: e.host, port: e.port, expires: now.Add(time.Duration(e.maxAge) * time.Second)})
		}
	}
	e, known := q.altsByOrigin[origin]
	switch {
	case len(alts) == 0 && known:
		q.alts.Remove(e)
		delete(q.altsByOrigin, origin)
	case len(alts) == 0:
	case known:
		e.Value.(*originAlts).alts = alts
		q.alts.MoveToFront(e)
	default:
		q.altsByOrigin[origin] = q.alts.PushFront(&originAlts{origin: origin, alts: alts})
		for uint64(q.alts.Len()) > p.Uint("quic.server_rtts_max") {
			last := q.alts.Back()
			delete(q.altsByOrigin, last.Value.(*originAlts).origin)
			q.alts.Remove(last)
		}
	}
}

// altSvcOf are the alternative services kept for origin that are good still,
// in the order they were advertised, those past their time forgotten
// (HttpServerProperties::GetAlternativeServiceInfos).
func (q *QUICState) altSvcOf(origin quicServer) []altService {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.altsByOrigin[origin]
	if !ok {
		return nil
	}
	now := q.now()
	kept := e.Value.(*originAlts)
	var good []altService
	for _, a := range kept.alts {
		if !a.expires.Before(now) {
			good = append(good, a)
		}
	}
	if kept.alts = good; len(good) == 0 {
		q.alts.Remove(e)
		delete(q.altsByOrigin, origin)
		return nil
	}
	q.alts.MoveToFront(e)
	return good
}

// alternatives are where the alternative services kept for addr (host:port)
// lead that a request may go to, as Chromium's JobController passes over the
// others (GetAdvertisedAltSvcInternal): each one's host and port, but those
// broken, one on a port of 1024 or more for an origin on a port below it
// unless quic.alt_svc_user_ports, and one on another host unless
// quic.alt_svc_remote_hosts.
func (d *dnsH3) alternatives(rt *roundTripper, addr string) []string {
	if !rt.behavior.Flag("quic.alt_svc") {
		return nil
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	port, _ := strconv.ParseUint(portText, 10, 16)
	var dests []string
	for _, a := range d.State.altSvcOf(quicServer{d.Key(), addr}) {
		altHost := strings.TrimSuffix(strings.TrimPrefix(a.host, "["), "]")
		if altHost == "" {
			altHost = host
		}
		dest := net.JoinHostPort(altHost, strconv.Itoa(int(a.port)))
		switch {
		case d.State.isBroken(quicServer{d.Key(), dest}):
		case !rt.behavior.Flag("quic.alt_svc_user_ports") && a.port >= 1024 && port < 1024:
		case !strings.EqualFold(altHost, host) && !rt.behavior.Flag("quic.alt_svc_remote_hosts"):
		default:
			dests = append(dests, dest)
		}
	}
	return dests
}
