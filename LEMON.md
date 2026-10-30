# tls-client for tls-forge

A fork of [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)
v1.16.0, on the branch `tls-forge`, for
[tls-forge](https://github.com/Sec-CH-Lemon/tls-forge). The base is
`291b8f9e1b86cc35f210bdb6bf44770bf2660ab5`, the commit Go's module proxy and
checksum database hold as v1.16.0: the tag was moved afterwards, to
`23b44420627619a30d09be5b6250e6cf2e350cf2`, with other code.

- The module is `github.com/igor-lemon/tls-client`, and it imports the forks
  of fhttp, utls, quic-go-utls and websocket at `github.com/igor-lemon/...`,
  so that one fhttp and one utls, the ones tls-forge patches, go through all
  of them. On another base:

      grep -rlE 'github\.com/bogdanfinn/(fhttp|utls|tls-client|quic-go-utls|websocket)' --include='*.go' --include=go.mod . |
        xargs perl -pi -e 's#github\.com/bogdanfinn/(fhttp|utls|tls-client|quic-go-utls|websocket)\b#github.com/igor-lemon/$1#g'

  then `git diff --name-only -- '*.go' | xargs gofmt -w`, which puts the
  renamed imports back in order, `go mod edit -require=` each fork at its
  version, and `go mod tidy`.
- At the base, `go vet` flags unkeyed fields in `profiles`, upstream as here.

## Patches

- **A client's requests through a wrapper of its round tripper**
  (`WithTransportWrapper`): every request the client sends, each hop of a
  redirect it follows too, goes through what the wrapper made of the round
  tripper the client built, when it was made and each time `SetProxy` builds
  another; what the wrapper returns may send a request on another client's
  round tripper. `CloseIdleConnections` and `GetTLSDialer` reach the round
  tripper the client built, whatever wraps it, and `GetTLSDialer` no longer
  falls back to the plain dialer, which it did only for a transport that was
  no round tripper of the client's. Unset, the client sends by its round
  tripper, as before. Tests in `wrapper_test.go`; tls-forge sends each hop
  of a redirect on the connections of its own top-level site and
  credentials with it, held end to end in tls-forge.
- **A request to another host on an HTTP/2 connection that fits it**
  (`WithConnectionCoalescing`, a `LookupFunc`): every address that negotiates
  h2 is served by one HTTP/2 transport, whose pool (fhttp's
  `http2.Transport.Coalesce`) has a request to a host it holds no connection
  for go out on one to another whose certificate was verified and is good
  for the host, on which the host's pins hold, at an address the lookup finds
  the host at and on its port, as Chrome pools them; a request to a host the
  client has no transport for is offered those connections before it dials.
  None is shared through a proxy, with a server name overwritten, client
  certificates or protocol racing, and a host whose dial found HTTP/1.1 is
  never offered one. Unset, every address has a transport of its own, as
  before. Tests in `coalesce_test.go`; that tls-forge's requests go out on
  the connections Chrome sent them on is held end to end in tls-forge.
- **A profile says how it writes headers into HPACK**
  (`profiles.ClientProfile.WithHeaderRepresentation`,
  `GetHeaderRepresentation`), which the round tripper gives its HTTP/2
  transport (fhttp's `http2.Transport.HeaderRepresentation`). Unset, as every
  catalogue profile is, headers are written as before. tls-forge sets it for
  Chromium. Tests in `representation_test.go` and
  `profiles/representation_test.go`; that the transport writes as told is
  held end to end in tls-forge.
- **A profile says how large an HPACK table it writes headers against**
  (`profiles.ClientProfile.WithMaxEncoderHeaderTableSize`,
  `GetMaxEncoderHeaderTableSize`), which the round tripper gives its HTTP/2
  transport (fhttp's `http2.Transport.MaxEncoderHeaderTableSize`): the
  largest table a server's SETTINGS can give the encoder. Unset, 4096, as
  before. tls-forge sets no limit for Chromium, which takes whatever a server
  allows. Tests in `representation_test.go` and
  `profiles/representation_test.go`; that the transport takes it is held end
  to end in tls-forge.
- **A profile says when it tells a server of its windows**
  (`profiles.ClientProfile.WithWindowUpdateDelay`, `GetWindowUpdateDelay`),
  which the round tripper gives its HTTP/2 transport (fhttp's
  `http2.Transport.WindowUpdateDelay`): what a reader frees of a window is
  told once more than half of it is, or at the first byte freed more than the
  delay after the server was last told, as Chrome does. Unset, as every
  catalogue profile is, the transport's own rule, as before. tls-forge sets
  five seconds for Chromium. Tests in `windowupdate_test.go` and
  `profiles/windowupdate_test.go`; that the transport tells as Chrome does is
  held end to end in tls-forge.
- **A profile says how large its frames and TLS records are**
  (`profiles.ClientProfile.WithMaxHeaderFramePayload`,
  `WithMaxDataFramePayload`, `WithDynamicRecordSizingDisabled`, and their
  getters), which the round tripper gives its HTTP/2 transport (fhttp's
  `http2.Transport.MaxHeaderFramePayload` and `MaxDataFramePayload`) and
  every TLS config of a connection over TCP (utls's
  `DynamicRecordSizingDisabled`): a header block is cut into frames of at most
  that much payload each, a HEADERS frame's priority included, a request's
  body into DATA frames of at most that much, below what the server allows;
  and TLS writes records as large as what is written allows from a
  connection's first byte, where Go's TLS cuts its first writes into records
  of about 1 KiB that grow. Unset, as every catalogue profile is, as before.
  tls-forge sets 16,374, 16,375 and disabled for Chromium, as Chrome writes
  them. Tests in `headerframes_test.go`, `framing_test.go`,
  `profiles/headerframes_test.go` and `profiles/framing_test.go`; that the
  transport writes as Chrome does is held end to end in tls-forge.
- **A profile says how it writes an HTTP/1.1 request**
  (`profiles.ClientProfile.WithMaxMergedHeadAndBody` and its getter), which
  the round tripper gives its HTTP/1.1 transport (fhttp's
  `http.Transport.MaxMergedHeadAndBody`): a request's head goes to the
  connection at once, whatever its size, and a body held in memory in the
  same write when the two are no more than that many bytes together, where
  the transport's 4 KiB buffer cut a larger head into pieces and wrote every
  body apart. Unset, as every catalogue profile is, as before. tls-forge sets
  1,400 for Chromium, Chrome's HttpStreamParser's limit. Tests in
  `framing_test.go` and `profiles/framing_test.go`; that the transport writes
  as Chrome does is held end to end in tls-forge.
- **A profile says whether it waits for a stream**
  (`profiles.ClientProfile.WithStrictMaxConcurrentStreams` and its getter),
  which the round tripper gives its HTTP/2 transport (fhttp's
  `http2.Transport.StrictMaxConcurrentStreams`): once the server's
  MAX_CONCURRENT_STREAMS are all in use, a request waits for a stream on the
  connection it would have gone out on, where the transport opened another
  connection to the server. Chrome waits: a server that said none at a time
  in ALPS had its requests on the one connection once its SETTINGS allowed
  some (tls-forge's bench, `alps-settings-streams-0`). Unset, as every
  catalogue profile is, another connection, as before. tls-forge sets it for
  Chromium. Tests in `framing_test.go` and `profiles/framing_test.go`; that
  the transport waits as Chrome does is held end to end in tls-forge.
- **A client that sets no deadline of its own on a request**
  (`WithoutRequestTimeout`): the client's `http.Client` sets no timer, and
  each request ends with its context, which its caller gives a deadline; the
  timeout still bounds each dial. Two timers at one deadline raced: the
  client's said `net/http: request canceled (Client.Timeout exceeded while
  awaiting headers)`, which no `errors.Is(err, context.DeadlineExceeded)`
  finds. Unset, as before. tls-forge sets it, and gives each request one
  deadline for all of it. Tests in `requesttimeout_test.go`; 2 mutants, all
  killed.
- **Dials that end with their requests' contexts, each address apart**
  (`roundtripper.go`): the HTTP/2 transport dials a connection after a host's
  first within the context of the request it is for (fhttp's
  `http2.Transport.DialTLSContext`), where it dialed with none; the first
  dial to an address, which finds out what its server speaks, holds no lock
  while it dials (`setUp`, `discover`, `cache`), and the requests to that
  address wait for it no longer than their contexts let them, a failed one
  leaving the next to dial for itself (`setups`); the connections to one
  address are dialed one after another, as every connection was, apart from
  every other address's (`lockDial`, `dialLocks`, waited for no longer than
  the context lets it); a dial through a proxy cut short by its context says
  so (`contextOr`). Before, a server that took the TCP connection and never
  answered the handshake held the request, past its deadline, and every
  other dial of the client, for good; and the first dial to an address held
  `cachedTransportsLck`, every request of the client and
  `CloseIdleConnections` with it. A connection a setup stashed for a
  transport since dropped is closed by the next setup, where `getTransport`
  panicked on it. `getTransport` keeps its contract for the protocol racer,
  which holds the lock itself. Tests in `dialcontext_test.go`
  (`waitingForSetup` is their seam); 15 mutants, all killed.
- **A dial through a proxy that ends with its request's context**
  (`connect.go`): SOCKS5's (x/net's dialer, which takes the context, where
  `Dial` was called with none), SOCKS4's (which takes none: the request
  waits for it no longer than its context, a connection made after that is
  closed, and the talk with the proxy ends at the dial's timeout,
  `deadlineDialer`), an HTTPS proxy's handshake (`tls.Dialer.DialContext`,
  where `tls.Dial` took none) and the CONNECT over an HTTP proxy (its
  deadline brought forward when the context ends). Before, a proxy that took
  the connection and never answered held the request for good, but an HTTP
  proxy's CONNECT, for the timeout. Tests in `proxycontext_test.go`; 11
  mutants, all killed.
- **A server that changes its protocol: one transport an address, and the
  request goes again** (`roundtripper.go`, the meaning of upstream's
  ab95f96 on the setups above): a connection a transport dialed for itself
  is that transport's only when it speaks what the transport does; one that
  speaks another protocol, or whose transport was dropped as it dialed,
  builds no transport (only a setup does, under the lock that guards them)
  and is reported with `errProtocolChanged`, where it built and cached
  another transport and failed the request with `protocol negotiated`; a
  transport is dropped with its kind, under the same lock, and only when it
  is still the one cached, where its kind was dropped apart and could take a
  newer transport's with it; and a request whose connection spoke another
  protocol goes again, nothing of it having been sent, on a transport set up
  for what the server speaks now, three times at most
  (`protocolChanges`), where it failed. Reproduced with seams
  (`reconnected`, `dropping`): a transport dropped while its connection
  shook hands, and a setup between a drop's two locks; and under load, a
  server that says http/1.1 and h2 by turns (`-race`: a data race on
  `cachedTransports` at 07e3f62, before the setups; `protocol negotiated`
  for a third of the requests at 5b99793). Tests in
  `transportcache_test.go`, upstream's setup test among them; 8 mutants, all
  killed. A server that changes its protocol on every connection, with many
  requests at once taking each other's connections, can still fail a few
  of them after three changes.
- **A profile says whether it false starts**
  (`ClientProfile.WithFalseStart`, `GetFalseStart`, `profiles/falsestart.go`):
  every utls configuration the round tripper builds says
  `tls.Config.FalseStart` as the profile does, the one each connection shakes
  hands with (`handshake`, `dialTLSForWebsocket`) and the ones the HTTP/2 and
  HTTP/1.1 transports keep (`cache`, `buildHttp1Transport`). The fork of utls
  sends a TLS 1.2 connection's first request before the server's Finished
  where BoringSSL would, and reads the Finished with the first read. Tests
  in `falsestart_test.go` (a request's connection and a websocket's, set and
  not, against a TLS 1.2 server whose Finished waits; the transports'
  configurations); 7 mutants, all killed.
- **A proxy's connections through a wrapper of the caller's**
  (`WithProxyConnWrapper`, a `ProxyConnWrapper`, `connect.go`): every TCP
  connection the client dials to its proxy goes through the wrapper, with
  the context of the request it is for and when its dial began, before the
  client says a word over it, and the client talks to the proxy over what
  the wrapper returns: an HTTP proxy's (the CONNECT), an HTTPS proxy's under
  its TLS (dialed as `tls.Dialer` dialed it, with no dialer of the client's,
  then `tls.Client` and `HandshakeContext`), SOCKS5's and SOCKS5h's (x/net's
  dialer over `wrappingDialer`) and SOCKS4's and SOCKS4a's (a go-socks4
  dialer for each dial, over a `deadlineDialer` of its context, which hands
  the wrapper nothing when that context ended before the connection was
  made: the dial was given up on, and the connection is closed). A dial that
  fails hands it nothing. Not a dialer of the caller's own (a proxy dialer
  factory, `WithDialContext`), nor HTTP/3's UDP association through SOCKS5.
  Unset, as before, and the dials' contexts and deadlines (S01) as they
  were. tls-forge taps a SOCKS proxy's connections with it for `fetch
  --pcap`. Tests in `proxyconnwrapper_test.go` (every scheme, with and
  without a password, the handshake each way and the site's TLS after it,
  when the dial began; a failed dial, an ended context, a SOCKS4 dial that
  connects after its request gave up, `SetProxy`); 26 mutants, all killed.

- `TransportOptions.HTTP2IdleConnTimeout` (HTTP/2's idle timeout alone, zero
  never: Chrome's SpdySession has no idle timer) and
  `TransportOptions.IdleConnReapOnRequest` (fhttp's, for the HTTP/1.1
  transport), through `roundTripper.idleTimeouts`; `ReapIdleConnections` on
  the round tripper and the client, which asks every HTTP/1.1 transport of
  it to reap (one per address here, where Chromium has one socket pool).
  Unset, as before. Test `TestTheTransportsKeepIdleConnectionsAsTheirOptionsSay`.

- ECH from the dialer (2026-10-24): a dialed connection that is an `ECHConn`
  (`ECHConfigList() []byte`, tls-forge's direct dialer after a name's HTTPS
  records) is offered ECH with those configs when the profile's policy says
  `tls.ech`; a server's refusal (`*tls.ECHRejectionError`) makes a new
  connection offering its retry configs, or none when it sent none and
  `tls.ech_retry_without` says so, `tls.ech_retries` times (`echOffer`,
  `handshakeOffering`); with InsecureSkipVerify the refusal's certificate
  is not checked either. Tests `ech_test.go`; 14 mutants, all killed.

- HTTP/3 where a name's HTTPS record names h3 (2026-10-25,
  `WithHTTP3FromDNS`, `HTTP3FromDNS`, `QUICEndpoint`, `QUICState`;
  `dnsh3.go`, `quicstate.go`): for an https request with no proxy, of a
  profile that says `dns.https_h3`, whose `Endpoint` (the caller's
  resolution and the record's ECH) says h3: a QUIC connection to the first
  address, offering that ECH, and TCP once QUIC's first datagram went
  (`sentFirst`, around `dialQUICAt`'s socket) and `tcpWait` after; the first
  up takes the request and the other is made apart, a TCP one stashed unused
  (`leftUnused`, fhttp's `UnusedIdle`; reaped by the next request past
  `http.unused_idle_connection_timeout_ms`, passed over once its peer
  closed it, `connected`), a QUIC one taking the requests after it (http3's
  `HasConn`); with a TCP connection already, the request goes on it at once
  and QUIC is made apart; QUIC that failed where TCP worked is broken
  (`markBroken`, doubling up to `quic.broken_max_ms`). HTTP/3's connections
  write their secrets to `TransportOptions.KeyLogWriter` too. As Chromium
  155's DNS ALPN job, measured on tls-forge's bench/h3 (two cohorts of
  Chrome 155 and of the library: as Chrome in each but the loopback race).
  Tests `dnsh3_test.go`, `quicstate_test.go`, `sentfirst_test.go`,
  `connected_unix_test.go`, `h3keylog_test.go`; 54 mutants: 53 killed, and
  the last was of a branch that went (accepting an ECH refusal over QUIC: a
  refused offer fails the connection whatever its certificate says).

- A QUIC connection's socket connected to its server where the profile says
  `quic.connected_socket` (2026-10-25, `chrome_quic_dial.go`: `quicSocket`
  writes without an address, `newConnectedSocket`): an ICMP unreachable the
  server's host answers with ends the connection at once, as Chrome's does,
  where quic-go's unconnected socket hears nothing of it and retransmits
  until its handshake timeout. Tests `connected_socket_test.go` (IPv4 and
  IPv6, the refusal against the wait).
- The QUIC hello keeps ALPS for the protocols of `quic.alps_protocols`
  (2026-10-25, `profileQUICSpec`; `quicExtensionID` names 17513 and 17613),
  an extension a profile wraps for its TCP hello taken as itself (`Unwrap`:
  tls-forge's ALPS bound to its ALPN, whose h2 a QUIC hello's h3 would
  leave empty). Tests `TestAQUICHelloOffersALPSAsItsProfileSays`,
  `TestAQUICHandshakeOfALPSSaysTheClientsEmptySettings`.
- A request a QUIC connection of a record's h3 failed before its answer,
  for whatever reason but its own context's, goes again over TCP, its body
  again (`GetBody`, or none), where the profile says `quic.retry_over_tcp`
  (2026-10-25, `dnsh3.go` `onQUIC`, `resent`), and QUIC to the server is
  broken once TCP's answer came, as Chromium's HttpNetworkTransaction
  restarts a request its QuicHttpStream failed (`ERR_QUIC_PROTOCOL_ERROR`)
  with alternative services off (`retry_without_alt_svc_on_quic_errors`),
  measured on Chrome 155 (tls-forge's `bench/h3alps`). A request the QUIC
  connection could not take (`http3.ErrNoCachedConn`: gone before it went,
  or refused unprocessed) goes over TCP with its body again too: before, its
  body went out closed (the up path), or the request failed with that error
  (the race's). Tests in `dnsh3_test.go` (`resetting`, `closing`,
  `originSays.quicFails`, `h3Origin.tcpAsked`); 14 mutants, 13 killed, one
  equivalent (a request whose context ended sent over TCP fails there before
  anything is written: fhttp's `encodeAndWriteHeaders` asks the context).
- Tests (2026-10-25): `resetting` resets a request's stream before any
  answer (`unanswered`, the response writer's stream read through
  reflection), as a server that cannot read the request does: through
  `HTTPStream`, which sends a 200 first, a client read that answer before the
  reset now and then, and the tests of a request QUIC failed saw a 200 with
  a failing body (about one full `-race` run in three).
- Tests (2026-10-25): a client of `h3Client` waits, when its test ends, for
  the QUIC connections it is still making (`dnsH3.attempts`, up to 15 s): a
  QUIC connection made apart after a test's last answer read `dialQUIC`
  while the next test set it (a data race under `-race`, one full run in
  five), and could have dialed through that test's stand-in.
- QUIC's TLS sessions apart from TCP's (2026-10-25, `roundTripper.quicSessionCache`
  for every HTTP/3 transport: a record's h3, `cache`'s, the racer's), as
  Chromium keeps them (its QUIC session cache and `SSLClientSessionCache`):
  with one cache, by name, a QUIC connection offered the ticket a server had
  given over TCP, which a QUIC server cannot resume, and the other way round
  (measured with tls-forge's library: a page's fetch() 40 s after it, 4 of
  4). Tests `tickets_test.go`.
- A TCP connection that waits unused for a request (2026-10-25, `dnsh3.go`,
  `roundtripper.go`, `client.go`): read as it waits (`peek`, utls's
  `Conn.Peek`, as Chromium's `SSLClientSocketImpl::DoPeek`), its session
  tickets cached as they come and its data left for its transport, one its
  server closed known as such (`alive`); cleaned up as Chromium's pool cleans
  its idle sockets up when a socket is asked of it (`CleanupIdleSockets`, no
  timer): by every request that asks the round tripper for a connection,
  the one of its own address after the request asked whether one is there
  (`free`, `reapUnused(but)`, `ReapIdleConnectionsBut`, which tls-forge calls
  for every request), and before a request QUIC failed goes again over TCP;
  where the connection there went so, TCP goes at once beside QUIC. Measured
  on Chrome 155 (tls-forge's `bench/unused`). Tests `waiting_test.go`; 24
  mutants, 23 killed, one equivalent (a time limit reached exactly).
- HTTP/3 to the alternative an origin's Alt-Svc advertises (2026-10-25,
  `altsvc.go`, `dnsh3.go`, `quicstate.go`), where the profile says
  `quic.alt_svc`, as Chromium 155's alternative job: the value read as
  quiche's `SpdyAltSvcWireFormat` reads it (the fields joined; whole or not
  at all; `clear`; `ma`, a day without), each answer but a 421's replacing
  what its origin advertised, the h3 ones kept (QUIC version 1) for the
  origin and the client's top-level site in `QUICState` (least recently
  used forgotten first, `quic.server_rtts_max` origins); the first
  alternative the profile allows that is not broken taken
  (`quic.alt_svc_user_ports`, `quic.alt_svc_remote_hosts`): a QUIC
  connection to its port, and host where it names one, named as the origin
  is, the request's TCP held back behind it by the wait of the origin's
  RTT, whatever connection the origin has, but at once on an HTTP/2 one
  (`quic.alt_svc_tcp_waits_with_h2`), QUIC made apart. A QUIC connection
  made for an alternative takes requests while the origin advertises it
  (`taking`), a request it fails breaks the alternative, and its RTT is the
  origin's. A race's TCP takes a connection the origin has once the wait
  ends, as a main job takes an idle socket. Measured on Chrome 155
  (tls-forge's `bench/alt`). Tests `altsvc_test.go`; 81 mutants of the
  parser, store and choice and 28 of the rest, all killed.
- `HTTP3FromDNS.Tap` (2026-10-25, `quictap.go`, `chrome_quic_dial.go`): a
  QUIC connection's socket tells the tap it is given (`QUICPacketTap`,
  asked with the context of the request the connection is made for) of
  every datagram it writes and reads and of its end; a write segmented by
  the system (Linux's `UDP_SEGMENT`, quic-go's GSO) as the datagrams it
  sends (`datagramsOf`, unix; elsewhere a write is one). tls-forge's
  `fetch --pcap` keeps QUIC connections so. Tests `quictap_test.go`,
  `quictap_unix_test.go`; 20 mutants, all killed. A datagram read by
  `ReadFrom` is told too (2026-10-26): quic-go reads a socket so where it
  has no OOB path (its basicConn: Windows), and tls-forge's Windows CI saw
  every datagram written and none read (run 40222769334).
- A QUIC connection a race made that ended before its request went (its
  client closed it on the server's settings against ALPS, say) breaks QUIC
  once TCP has answered the request (2026-10-25, `dnsh3.go`,
  `quicAttempt.failed`), as Chromium's job does when its session closes at
  once; a refused stream leaves the connection up and QUIC as it was.
  Before, QUIC stayed unbroken when the close came before the request, and
  the next request made a QUIC connection again: tls-forge's
  `TestAControlStreamsSettingsAreHeldToWhatALPSGaveAsChromes` failed 7 to 12
  runs of 40 under `-race`, none of 40 since. Test
  `TestAQUICConnectionThatEndsAsItIsMadeBreaksQUIC`; 5 mutants, all killed.

- A6 coordinated pins retain the restored QUIC group checks, nonblocking large
  HTTP3 setup and HTTP2 zero-window/final-stream/terminal-reader fixes.
  Runtime adapter code and browser values are unchanged in this pins-only slice.

## A6 explicit connection window presence

ClientProfile.WithConnectionFlowSet/GetConnectionFlowSet carry presence through
the direct HTTP2 and HTTP1-negotiated HTTP2 transports. Full owner profiles
mark zero explicitly; raw legacy catalogue defaults remain unchanged. Value-copy
ownership is tested in profiles/connection_flow_test.go; the owner's raw peer
checks actual zero/one/maximum increments. Dependency pins include fhttp e44d38f
and QUIC898d2ae3.

## What a race makes apart ends with CloseIdleConnections (review A5, 2026-10-28)

A race of a name's HTTPS record goes on making the connection that lost after
its request is answered: the TCP one QUIC beat, within the request's deadline,
and the QUIC one TCP beat, ended by QUIC's own handshake timeouts. Neither was
tracked: one that `CloseIdleConnections` (tls-forge's `Close`, and an evicted
site's close) ran under came up after it returned, and was kept, the TCP one
waiting unused and the QUIC one in the HTTP/3 transport's pool, past the
client's end. `apartWork` (`dnsh3.go`) is that work: `begin` gives each its
context, which `endAll` ends, and `CloseIdleConnections` ends it and waits for
it before it closes what is idle, so that a connection one kept just as it was
ended is closed with the rest. What begins after goes on until the next.
Tests `TestCloseIdleConnectionsEndsWhatARaceMakesApart` (TCP and QUIC, and the
request after it over QUIC) and `TestCloseIdleConnectionsWaitsForWhatItEnds`
(work that keeps a connection after it was ended); 8 mutants, 7 killed, and
one no test can see (`done` leaving its `AfterFunc` registered: a closure
held for each attempt until the next `CloseIdleConnections`, for good without
one, which `stop` is there to spare).

## HTTP/3 field-section size from profile settings (2026-10-29)

An explicit HTTP/3 settings map owns its field-section limit, including zero or
omission. HTTP/1's MaxResponseHeaderBytes and HTTP/3 priority no longer select
an unrelated H3 limit. Raw transports without a settings map retain their
explicit transport option or the generic http3 default.

## A11 owned catalogue fingerprint oracles

Catalogue/header/GREASE-signature/trust-anchor wire checks now use an owned
loopback TLS peer. It independently parses received ClientHello record bytes
and actual H1/H2 fields (x/net HPACK), without reading ClientProfile or the
expected fingerprint table. Salesforce JA3 and FoxIO JA4 published worked
examples and changed/truncated-input negative controls bind the decoder.
All received H2 frames remain in history; the second request's header assertion
selects its actual new odd stream and requires progress, retaining reuse coverage.

The33 browser and7 custom catalogue cases are separate subtests, without the
external-service rate-limit sleeps. PSK controls explicitly close the first idle
connection and require a distinct, cryptographically resumed handshake reported
by the owned TLS server, rather than expecting a new ClientHello on a reused
connection. Client/peer cleanup closes and joins owned resources. All catalogue,
header, random-order, signature/trust-anchor wire and decoder controls passed20
race repetitions (final6.850s). Production data/code and expected fingerprint
values are unchanged. This is bounded catalogue/engine behavior, not a new
Chrome observation or complete A11 acceptance. Remaining external H3/hooks/etc.
fixtures are separate obligations; the full two-graph suites are still pending.

Algorithm references: https://github.com/salesforce/ja3 and
https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md .

## A11 cookie scope and ownership

Cookies(u) now delegates network selection to the existing standard jar, which
owns domain/path/secure/expiration handling. The old sidecar returned unrelated
scopes, expired/foreign cookies and caller-mutated values. Metadata is copied
on input/output; skip-existing uses name+domain+path and honors deletion. Only
new updates are given to the backend, so unrelated cookies' Max-Age is not reset.
GetAllCookies inventories exact canonical source hosts instead of guessing a
registrable domain; this is a deliberate engine1 API correction. Its values
retain owned original attributes. The existing backend public-suffix-list
configuration is unchanged; this does not establish Chrome SameSite/PSL parity.

Independent before controls demonstrated HTTP/secure/path/host/expiry leaks,
mutation and same-name path collisions. After:20race offline ownership/scope
controls,20race existing API cases and20race actual four-request cookie exchange
pass. The external7-cookie count fixture is replaced by exact received cookies,
rejected foreign/expired cookies, replacement suppression, distinct paths and
empty-value deletion. Browser values and retry rules are unchanged.

A11 hook fixtures use owned loopback HTTP listeners instead of httpbin. Every
original hook ordering/error/panic/registration assertion remains; the peer
additionally checks pre-hook headers and zero/one origin request counts. The
request-failure fixture closes its own accepted socket instead of relying on DNS.
Twenty race repetitions pass, including concurrent registration.

A11 TLS service fixtures use a local certificate trusted by the client (normal
certificate verification stays enabled). Firefox's formerly external registration
POST reaches only the owned peer, which checks its method/body and answers 204.
Trust-anchor profiles retain their exact wire-extension controls and now complete
real verified TLS requests to that peer. Secure WebSocket uses the owned TLS
server and requires exact echoed message equality. Twenty race repetitions pass.

## A11 ALPN adapter ownership contract

The plain adapter's existing pre-dispatch handoff rebuilds the transport and
reuses the negotiated connection. Racing returns a dispatch error, invalidates
its cache and lets the next caller request recover; it never gains a fallback
replay for a failed POST. The formerly contradictory fixtures now check these
boundaries explicitly, with actual handshake/origin counts and complete bodies.
Twenty race repetitions pass. Existing arbitrary-error/no-replay controls remain.

A11 found an additional production body-lifetime defect: failed RoundTrip had
closed a POST body before a plain ALPN handoff reused it. The owned peer observed
an interrupted POST, including with GetBody present. The handoff now clones the
request and uses a fresh GetBody result; without one it returns the original
ALPN error before emitting that POST. Caller Request.Body is not replaced.
Twenty race repetitions pass for rewindable/unrewindable POST, recovery, exact
origin bodies, and the separate plain/racing contracts. Existing retry count and
all browser policy values remain unchanged in this pending engine1 release.

A11 standalone support pins now use the source-verified utls fc851fa, fhttp
24c1c55 and QUIC9a3076b4 published on their tls-forge branches. The root adapter
package passes under race on this module graph (35.853s); full standalone and
production fork suites remain required before final acceptance. Old standalone
module metadata and original failure transcripts remain in the private capsule.

## A11 owned HTTP/3 wire and routing witnesses

The H3 peer has no profile or expected-hash input. It accepts real QUIC,
records ordered control bytes/SETTINGS and independently decodes static QPACK
(the peer advertises zero dynamic capacity). Replies use only received fields.
Chrome144's raw catalogue has no ID6 value; nil behavior retains generic
priority-before-GREASE ordering. Chrome133 has no H3 map, so its raw transport
retains the 10 MiB default and unspecified SETTINGS map order. The old external
hash asserted different defaults. These are adapter contracts, not Chrome
recaptures. Existing browser profile data has not changed. Explicit separate
wire controls require ID6 omitted/zero/262144, with zero rejecting the response.

Direct tests now preserve the unchanged catalogue ALPN input (actual H2), and
also prove actual non-racer DNS-H3 routing with the complete technical JSON
fixture copied from root engine1 chrome155 behavior. Combining that routing
policy with catalogue hellos is deliberately not browser-equivalence evidence.
The server independently reports actual H2/H3 instead of external page strings.

Generated GREASE retains raw ID/value. The independent oracle checks JSON draw
bounds, value range, exact insertion position against fixed SETTINGS order,
frame draw/payload relationship, priority stream/value and QPACK pseudo order.
It does not freeze a random placement or require unique draws. Wrong fixed
values, placement, duplicates, absent draws and illegal ranges are rejected by
negative controls. Raw control bytes remain available beside normalized labels.
All H3/routing/body controls pass20race together (4.261s). The owned peer is a
bounded first-request technical fixture, not a complete alternate H3 server or
an independent browser implementation.
