module github.com/igor-lemon/tls-client

go 1.24.1

require (
	github.com/bdandy/go-socks4 v1.2.3
	github.com/google/uuid v1.6.0
	github.com/igor-lemon/fhttp v0.6.10-0.20261019141341-bd9ea92137d1
	github.com/igor-lemon/quic-go-utls v1.0.10-utls.0.20261019141441-e46716ffebf5
	github.com/igor-lemon/websocket v1.5.6-barnius.0.20261019141439-6da9c97e8451
	github.com/stretchr/testify v1.11.1
	github.com/tam7t/hpkp v0.0.0-20160821193359-2b70b4024ed5
	golang.org/x/net v0.48.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/bdandy/go-errors v1.2.2 // indirect
	github.com/cloudflare/circl v1.6.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/igor-lemon/utls v1.7.8-barnius.0.20261019134924-8ce0abf27ca1
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

//replace github.com/bogdanfinn/utls => ../utls

//replace github.com/igor-lemon/quic-go-utls => ../quic-go-utls

//replace github.com/igor-lemon/websocket => ../websocket

//replace github.com/igor-lemon/fhttp => ../fhttp
