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
  renamed imports back in order, `go mod edit -require=` each fork at its version, and `go mod tidy`.
- At the base, `go vet` flags unkeyed fields in `profiles`, upstream as here.
