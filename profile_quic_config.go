package tls_client

import (
	quic "github.com/igor-lemon/quic-go-utls"
	tls "github.com/igor-lemon/utls"
	"github.com/igor-lemon/utls/behavior"
	"time"
)

func profileQUICConfig(p behavior.Policy) *quic.Config {
	versions := make([]quic.Version, 0, len(p.Numbers("quic.versions")))
	for _, v := range p.Numbers("quic.versions") {
		versions = append(versions, quic.Version(v))
	}
	q := &quic.Config{Behavior: p.Clone(), Versions: versions,
		InitialStreamReceiveWindow: p.Uint("quic.stream_receive_window"), MaxStreamReceiveWindow: p.Uint("quic.stream_receive_window"),
		InitialConnectionReceiveWindow: p.Uint("quic.connection_receive_window"), MaxConnectionReceiveWindow: p.Uint("quic.connection_receive_window"),
		MaxIncomingStreams: int64(p.Uint("quic.incoming_bidi_streams")), MaxIncomingUniStreams: int64(p.Uint("quic.incoming_uni_streams")),
		MaxIdleTimeout:    time.Duration(p.Uint("quic.idle_timeout_ms")) * time.Millisecond,
		InitialPacketSize: uint16(p.Uint("quic.initial_packet_bytes")), EnableDatagrams: p.Flag("quic.datagrams")}
	if p.Has("quic.config") {
		q.MaxStreamReceiveWindow = p.Uint("quic.max_stream_receive_window")
		q.MaxConnectionReceiveWindow = p.Uint("quic.max_connection_receive_window")
		q.KeepAlivePeriod = time.Duration(p.Uint("quic.keep_alive_ms")) * time.Millisecond
		// quic.Config reserves zero for its defaults; negative means no streams.
		if q.MaxIncomingStreams == 0 {
			q.MaxIncomingStreams = -1
		}
		if q.MaxIncomingUniStreams == 0 {
			q.MaxIncomingUniStreams = -1
		}
	}
	return q
}

// profileSessionCache is a session cache of as many entries as key says, each
// of as many sessions as perEntry says (one where it says none), as Chrome's
// keep two: a server's second ticket for a second connection at once.
func profileSessionCache(p behavior.Policy, key, perEntry string) tls.ClientSessionCache {
	// Only unconfigured low-level callers retain the historical API contract.
	capacity := 32
	if p.Has(key) {
		capacity = p.Int(key)
	}
	return tls.NewLRUClientSessionCacheOf(capacity, p.Int(perEntry))
}
