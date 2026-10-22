package tls_client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/tls-client/profiles"
	tls "github.com/igor-lemon/utls"
	"golang.org/x/net/proxy"
)

type HttpClientOption func(config *httpClientConfig)

type TransportOptions struct {
	// KeyLogWriter is an io.Writer that the TLS client will use to write the
	// TLS master secrets to. This can be used to decrypt TLS connections in
	// Wireshark and other applications.
	KeyLogWriter io.Writer
	// IdleConnTimeout is the maximum amount of time an idle (keep-alive)
	// connection will remain idle before closing itself. Zero means no limit.
	IdleConnTimeout *time.Duration
	// RootCAs is the set of root certificate authorities used to verify
	// the remote server's certificate.
	RootCAs                *x509.CertPool
	Certificates           []tls.Certificate
	MaxIdleConns           int
	MaxIdleConnsPerHost    int
	MaxConnsPerHost        int
	MaxResponseHeaderBytes int64 // Zero means to use a default limit.
	WriteBufferSize        int   // If zero, a default (currently 4KB) is used.
	ReadBufferSize         int   // If zero, a default (currently 4KB) is used.
	DisableKeepAlives      bool
	DisableCompression     bool
}

type (
	BadPinHandlerFunc  func(req *http.Request)
	ProxyDialerFactory func(proxyUrlStr string, timeout time.Duration, localAddr *net.TCPAddr, connectHeaders http.Header, logger Logger) (proxy.ContextDialer, error)
)

// ErrContinueHooks can be returned (or wrapped) by a PreRequestHookFunc to signal that
// the error should be logged but hook execution should continue to the next hook.
// By default any error returned from a hook aborts subsequent hooks and the request.
var ErrContinueHooks = errors.New("continue hooks")

// PreRequestHookFunc is called before each request is sent.
// Return an error to abort the request, or wrap ErrContinueHooks to log and continue.
type PreRequestHookFunc func(req *http.Request) error

// PostResponseContext contains response metadata for PostHook handlers.
type PostResponseContext struct {
	Request  *http.Request
	Response *http.Response
	Error    error // Non-nil if request failed
}

// PostResponseHookFunc is called after each request completes.
// Return an error to abort subsequent hooks, or wrap ErrContinueHooks to log and continue.
type PostResponseHookFunc func(ctx *PostResponseContext) error

type httpClientConfig struct {
	cookieJar          http.CookieJar
	customRedirectFunc func(req *http.Request, via []*http.Request) error
	certificatePins    map[string][]string
	defaultHeaders     http.Header
	connectHeaders     http.Header
	badPinHandler      BadPinHandlerFunc
	transportOptions   *TransportOptions
	localAddr          *net.TCPAddr

	dialer             net.Dialer
	dialContext        func(ctx context.Context, network, addr string) (net.Conn, error)
	proxyDialerFactory ProxyDialerFactory

	proxyUrl                    string
	serverNameOverwrite         string
	clientProfile               profiles.ClientProfile
	profileLock                 string
	profileOverride             bool
	timeout                     time.Duration
	withoutRequestTimeout       bool
	catchPanics                 bool
	debug                       bool
	followRedirects             bool
	insecureSkipVerify          bool
	withRandomTlsExtensionOrder bool
	forceHttp1                  bool
	disableHttp3                bool
	disableSessionTickets       bool
	enableProtocolRacing        bool

	// Establish a connection to origin server via ipv4 only
	disableIPV6 bool
	// Establish a connection to origin server via ipv6 only
	disableIPV4 bool

	enabledBandwidthTracker bool

	// lookup finds a host's addresses for connection coalescing; nil, none.
	lookup LookupFunc

	// wrapTransport is what the client's requests go through instead of the
	// round tripper it builds, made of that one; nil, nothing.
	wrapTransport func(http.RoundTripper) http.RoundTripper

	// wrapProxyConn is what each connection to the proxy goes through; nil,
	// nothing.
	wrapProxyConn ProxyConnWrapper

	preHooks  []PreRequestHookFunc
	postHooks []PostResponseHookFunc
}

// WithProxyUrl configures an HTTP client to use the specified proxy URL.
//
// proxyUrl should be formatted as:
//
//	"http://user:pass@host:port"
func WithProxyUrl(proxyUrl string) HttpClientOption {
	return func(config *httpClientConfig) {
		config.proxyUrl = proxyUrl
	}
}

// WithCharlesProxy configures the HTTP client to use a local running charles as proxy.
//
// host and port can be empty, then default 127.0.0.1 and port 8888 will be used
func WithCharlesProxy(host string, port string) HttpClientOption {
	h := "127.0.0.1"
	p := "8888"

	if host != "" {
		h = host
	}

	if port != "" {
		p = port
	}

	proxyUrl := fmt.Sprintf("http://%s:%s", h, p)

	return WithProxyUrl(proxyUrl)
}

// WithCookieJar configures a HTTP client to use the specified cookie jar.
func WithCookieJar(jar http.CookieJar) HttpClientOption {
	return func(config *httpClientConfig) {
		config.cookieJar = jar
	}
}

// WithTimeoutMilliseconds configures a hard deadline for the entire request lifecycle.
//
// This includes connection time, redirects, and reading the response body.
// WARNING: If the timer expires, the connection is forcibly closed, even if you are
// actively downloading data.
//
// - Use 0 to disable the deadline (Unlimited) for large downloads or long-polling.
// - Default is 30000 milliseconds (30 seconds).
func WithTimeoutMilliseconds(timeout int) HttpClientOption {
	return func(config *httpClientConfig) {
		config.timeout = time.Millisecond * time.Duration(timeout)
	}
}

// WithDialer configures an HTTP client to use the specified dialer. This allows the use of a custom DNS resolver
func WithDialer(dialer net.Dialer) HttpClientOption {
	return func(config *httpClientConfig) {
		config.dialer = dialer
	}
}

// WithProxyDialerFactory configures an HTTP client to use a custom proxyDialerFactory instead of newConnectDialer(). This allows to implement custom proxy dialer use cases
func WithProxyDialerFactory(proxyDialerFactory ProxyDialerFactory) HttpClientOption {
	return func(config *httpClientConfig) {
		config.proxyDialerFactory = proxyDialerFactory
	}
}

// WithTimeoutSeconds configures a hard deadline for the entire request lifecycle.
//
// This includes connection time, redirects, and reading the response body.
// WARNING: If the timer expires, the connection is forcibly closed, even if you are
// actively downloading data.
//
// - Use 0 to disable the deadline (Unlimited) for large downloads or long-polling.
// - Default is 30 seconds.
func WithTimeoutSeconds(timeout int) HttpClientOption {
	return func(config *httpClientConfig) {
		config.timeout = time.Second * time.Duration(timeout)
	}
}

// WithTimeout configures an HTTP client to use the specified request timeout.
//
// timeout is the request timeout in seconds.
// Deprecated: use either WithTimeoutSeconds or WithTimeoutMilliseconds
func WithTimeout(timeout int) HttpClientOption {
	return func(config *httpClientConfig) {
		config.timeout = time.Second * time.Duration(timeout)
	}
}

// WithoutRequestTimeout has the client set no deadline of its own on a
// request: each ends with its context, which its caller gives one. The
// timeout still bounds each dial, as the dialers take it.
func WithoutRequestTimeout() HttpClientOption {
	return func(config *httpClientConfig) {
		config.withoutRequestTimeout = true
	}
}

// WithNotFollowRedirects configures an HTTP client to not follow HTTP redirects.
func WithNotFollowRedirects() HttpClientOption {
	return func(config *httpClientConfig) {
		config.followRedirects = false
	}
}

// WithLocalAddr configures an HTTP client to use the specified local address.
func WithLocalAddr(localAddr net.TCPAddr) HttpClientOption {
	return func(config *httpClientConfig) {
		config.localAddr = &localAddr
	}
}

// WithCustomRedirectFunc configures an HTTP client to use a custom redirect func.
// The redirect func have to look like that: func(req *http.Request, via []*http.Request) error
// Please only provide a custom redirect function if you know what you are doing.
// Check docs on net/http.Client CheckRedirect
func WithCustomRedirectFunc(redirectFunc func(req *http.Request, via []*http.Request) error) HttpClientOption {
	return func(config *httpClientConfig) {
		config.customRedirectFunc = redirectFunc
	}
}

// WithRandomTLSExtensionOrder configures a TLS client to randomize the order of TLS extensions being sent in the ClientHello.
//
// Placement of GREASE and padding is fixed and will not be affected by this.
func WithRandomTLSExtensionOrder() HttpClientOption {
	return func(config *httpClientConfig) {
		config.withRandomTlsExtensionOrder = true
	}
}

// WithCertificatePinning enables SSL Pinning for the client and will throw an error if the SSL Pin is not matched.
// Please refer to https://github.com/tam7t/hpkp/#examples in order to see how to generate pins. The certificatePins are a map with the host as key.
// You can provide a BadPinHandlerFunc or nil as second argument. This function will be executed once a bad ssl pin is detected.
// BadPinHandlerFunc has to be defined like this: func(req *http.Request){}
func WithCertificatePinning(certificatePins map[string][]string, handlerFunc BadPinHandlerFunc) HttpClientOption {
	return func(config *httpClientConfig) {
		config.certificatePins = certificatePins
		config.badPinHandler = handlerFunc
	}
}

// WithDebug configures a client to log debugging information.
func WithDebug() HttpClientOption {
	return func(config *httpClientConfig) {
		config.debug = true
	}
}

// WithCatchPanics configures a client to catch all go panics happening during a request and not print the stacktrace.
func WithCatchPanics() HttpClientOption {
	return func(config *httpClientConfig) {
		config.catchPanics = true
	}
}

// WithTransportOptions configures a client to use the specified transport options.
func WithTransportOptions(transportOptions *TransportOptions) HttpClientOption {
	return func(config *httpClientConfig) {
		config.transportOptions = transportOptions
	}
}

// WithInsecureSkipVerify configures a client to skip SSL certificate verification.
func WithInsecureSkipVerify() HttpClientOption {
	return func(config *httpClientConfig) {
		config.insecureSkipVerify = true
	}
}

// WithForceHttp1 configures a client to force HTTP/1.1 as the used protocol.
func WithForceHttp1() HttpClientOption {
	return func(config *httpClientConfig) {
		config.forceHttp1 = true
	}
}

// WithDisableHttp3 configures a client to disable HTTP 3 as the used protocol. Will most likely fall back to HTTP 2
func WithDisableHttp3() HttpClientOption {
	return func(config *httpClientConfig) {
		config.disableHttp3 = true
	}
}

// WithDisableSessionTickets configures a client to disable TLS session ticket caching and resumption.
func WithDisableSessionTickets() HttpClientOption {
	return func(config *httpClientConfig) {
		config.disableSessionTickets = true
	}
}

// WithProtocolRacing configures a client to race HTTP/3 (QUIC) and HTTP/2 (TCP) connections in parallel.
// Similar to Chrome's "Happy Eyeballs" approach, this starts both connection types simultaneously
// and uses whichever connects first.
// The client will remember which protocol worked for each host and use it directly on subsequent requests.
// This option is ignored if WithForceHttp1 or WithDisableHttp3 is set.
func WithProtocolRacing() HttpClientOption {
	return func(config *httpClientConfig) {
		config.enableProtocolRacing = true
	}
}

// WithClientProfile configures a TLS client to use the specified client profile.
func WithClientProfile(clientProfile profiles.ClientProfile) HttpClientOption {
	return func(config *httpClientConfig) {
		if config.profileLock != "" {
			config.profileOverride = true
			return
		}
		config.clientProfile = clientProfile
	}
}

// WithLockedClientProfile selects an owner's validated profile and prevents
// subsequent raw profile options from bypassing that owner's compatibility gate.
// identity is diagnostic context supplied by the owner, not browser policy.
func WithLockedClientProfile(profile profiles.ClientProfile, identity string) HttpClientOption {
	return func(config *httpClientConfig) {
		if config.profileLock != "" {
			config.profileOverride = true
			return
		}
		config.clientProfile = profile
		config.profileLock = identity
		if identity == "" {
			config.profileLock = "locked profile"
		}
	}
}

// WithDefaultHeaders configures a TLS client to use a set of default headers if none are specified on the request.
func WithDefaultHeaders(defaultHeaders http.Header) HttpClientOption {
	return func(config *httpClientConfig) {
		config.defaultHeaders = defaultHeaders
	}
}

// WithServerNameOverwrite configures a TLS client to overwrite the server name being used for certificate verification and in the client hello.
// This option does only work properly if WithInsecureSkipVerify is set to true in addition
func WithServerNameOverwrite(serverName string) HttpClientOption {
	return func(config *httpClientConfig) {
		config.serverNameOverwrite = serverName
	}
}

// WithDisableIPV6 configures a dialer to use tcp4 network argument
func WithDisableIPV6() HttpClientOption {
	return func(config *httpClientConfig) {
		config.disableIPV6 = true
	}
}

// WithDisableIPV4 configures a dialer to use tcp6 network argument
func WithDisableIPV4() HttpClientOption {
	return func(config *httpClientConfig) {
		config.disableIPV4 = true
	}
}

// WithBandwidthTracker configures a client to track the bandwidth used by the client.
func WithBandwidthTracker() HttpClientOption {
	return func(config *httpClientConfig) {
		config.enabledBandwidthTracker = true
	}
}

// WithConnectHeaders configures a client to use the specified headers for the CONNECT request.
func WithConnectHeaders(headers http.Header) HttpClientOption {
	return func(config *httpClientConfig) {
		config.connectHeaders = headers
	}
}

// WithPreHook adds a pre-request hook that is called before each request is sent.
// Multiple hooks can be added and they will be executed in the order they were added.
// If any hook returns an error, the request is aborted and subsequent hooks are not called.
func WithPreHook(hook PreRequestHookFunc) HttpClientOption {
	return func(config *httpClientConfig) {
		config.preHooks = append(config.preHooks, hook)
	}
}

// WithPostHook adds a post-response hook that is called after each request completes.
// Multiple hooks can be added and they will be executed in the order they were added.
// All hooks are always executed, even if the request failed or a previous hook panicked.
func WithPostHook(hook PostResponseHookFunc) HttpClientOption {
	return func(config *httpClientConfig) {
		config.postHooks = append(config.postHooks, hook)
	}
}

// LookupFunc finds the addresses of host, as the client's dialer would.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// WithConnectionCoalescing has a request to a host the client holds no
// connection to go out on an HTTP/2 connection it holds to another, as
// Chrome sends it, when one fits: its certificate was verified and is good
// for the host, the host's certificate pins hold on it, and lookup finds the
// host at the connection's address, on its port. The first that fits, by the
// order lookup found the addresses in and then by age, carries the host's
// requests from then on, for as long as it can take them. Chrome looks the
// host up before it dials, and so does the client, with lookup; when none
// fits, it dials as before. Connections are not shared through a proxy
// (WithProxyUrl), whose address is all a connection knows, nor with a server
// name overwritten, client certificates, or protocol racing, and HTTP/1.1
// connections never are.
func WithConnectionCoalescing(lookup LookupFunc) HttpClientOption {
	return func(config *httpClientConfig) {
		config.lookup = lookup
	}
}

// WithTransportWrapper has the client send every request, each hop of a
// redirect it follows too, through what wrap makes of the round tripper it
// builds: wrap is handed that one when the client is made, and each one
// SetProxy builds in its place. What wrap returns may send a request on
// another round tripper, another client's. The client's own methods reach the
// round tripper it built, whatever wraps it: CloseIdleConnections closes its
// idle connections, and GetTLSDialer dials as it does.
func WithTransportWrapper(wrap func(http.RoundTripper) http.RoundTripper) HttpClientOption {
	return func(config *httpClientConfig) {
		config.wrapTransport = wrap
	}
}

// ProxyConnWrapper is what a connection to a proxy goes through: conn,
// dialed for the request whose context ctx is, the dial having begun at
// began. What it returns is what the client talks to the proxy over and what
// the request's tunnel goes through.
type ProxyConnWrapper func(ctx context.Context, conn net.Conn, began time.Time) net.Conn

// WithProxyConnWrapper has every connection the client dials to its proxy
// (WithProxyUrl, SetProxy) go through wrap before the client says a word over
// it: an HTTP or HTTPS proxy's, which a CONNECT goes over, and a SOCKS4,
// SOCKS4a, SOCKS5 or SOCKS5h proxy's, which the handshake goes over, the
// TCP connection under any TLS. A dial that fails hands wrap nothing, and so
// does a SOCKS4 dial that connects after its request stopped waiting for it:
// that connection is closed. A connection to an HTTPS proxy that speaks
// HTTP/2 carries later requests' tunnels too, and went through wrap once,
// with the context of the dial that made it. Not a dialer of the caller's
// own (WithProxyDialerFactory, WithDialContext), nor HTTP/3's UDP association
// through a SOCKS5 proxy (WithProtocolRacing). Unset, the client talks to the
// proxy over the connections it dials.
func WithProxyConnWrapper(wrap ProxyConnWrapper) HttpClientOption {
	return func(config *httpClientConfig) {
		config.wrapProxyConn = wrap
	}
}

// WithDialContext sets a custom dialer for TCP connections, allowing advanced networking
// (Zero-DNS, socket tagging, DPI bypass).
//
// WARNING: This overrides built-in proxy settings. If you need a proxy, you must handle the CONNECT handshake manually.
// CHECK: https://github.com/igor-lemon/tls-client/pull/218#issuecomment-3858171801
func WithDialContext(dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) HttpClientOption {
	return func(config *httpClientConfig) {
		config.dialContext = dialContext
	}
}
