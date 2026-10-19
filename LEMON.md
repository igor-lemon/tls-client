# tls-client for tls-forge

A fork of [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)
v1.16.0, on the branch `tls-forge`, for
[tls-forge](https://github.com/Sec-CH-Lemon/tls-forge). The base is
`291b8f9e1b86cc35f210bdb6bf44770bf2660ab5`, the commit Go's module proxy and
checksum database hold as v1.16.0: the tag was moved afterwards, to
`23b44420627619a30d09be5b6250e6cf2e350cf2`, with other code.

- The module is `github.com/igor-lemon/tls-client`, and it imports the forks
  of fhttp, quic-go-utls and websocket at `github.com/igor-lemon/...`, so that
  one fhttp, the one tls-forge patches, goes through all of them. On another
  base:

      grep -rlE 'github\.com/bogdanfinn/(fhttp|tls-client|quic-go-utls|websocket)' --include='*.go' --include=go.mod . |
        xargs perl -pi -e 's#github\.com/bogdanfinn/(fhttp|tls-client|quic-go-utls|websocket)\b#github.com/igor-lemon/$1#g'

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
