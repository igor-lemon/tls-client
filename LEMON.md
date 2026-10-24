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
