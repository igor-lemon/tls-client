package tls_client

import (
	"golang.org/x/net/idna"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	http "github.com/igor-lemon/fhttp"
	"github.com/igor-lemon/fhttp/cookiejar"
)

type CookieJarOption func(config *cookieJarConfig)

type cookieJarConfig struct {
	logger            Logger
	skipExisting      bool
	debug             bool
	allowEmptyCookies bool
}

func WithSkipExisting() CookieJarOption {
	return func(config *cookieJarConfig) {
		config.skipExisting = true
	}
}

func WithAllowEmptyCookies() CookieJarOption {
	return func(config *cookieJarConfig) {
		config.allowEmptyCookies = true
	}
}

func WithDebugLogger() CookieJarOption {
	return func(config *cookieJarConfig) {
		config.debug = true
	}
}

func WithLogger(logger Logger) CookieJarOption {
	return func(config *cookieJarConfig) {
		config.logger = logger
	}
}

type CookieJar interface {
	http.CookieJar
	GetAllCookies() map[string][]*http.Cookie
}

// The standard jar owns network selection. Records retain owned metadata for
// skip-existing and inventory; they never bypass domain/path/secure/expiry.
type cookieIdentity struct{ name, domain, path string }
type cookieRecord struct {
	cookie   *http.Cookie
	host     string
	created  time.Time
	sequence uint64
}
type cookieJar struct {
	jar      *cookiejar.Jar
	config   *cookieJarConfig
	records  map[cookieIdentity]cookieRecord
	sequence uint64
	sync.RWMutex
}

func NewCookieJar(options ...CookieJarOption) CookieJar {
	realJar, _ := cookiejar.New(nil)
	config := &cookieJarConfig{}
	for _, opt := range options {
		opt(config)
	}
	if config.logger == nil {
		config.logger = NewNoopLogger()
	}
	if config.debug {
		config.logger = NewDebugLogger(config.logger)
	}
	return &cookieJar{jar: realJar, config: config, records: make(map[cookieIdentity]cookieRecord)}
}

func canonicalCookieHost(host string) (string, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), true
	}
	ascii, err := idna.Lookup.ToASCII(host)
	return strings.ToLower(ascii), err == nil && ascii != ""
}

func cookieKey(u *url.URL, c *http.Cookie) (cookieIdentity, bool) {
	host, ok := canonicalCookieHost(u.Hostname())
	if !ok || c.Name == "" {
		return cookieIdentity{}, false
	}
	domain := host
	if c.Domain != "" {
		domain = strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if strings.HasSuffix(domain, ".") || strings.HasPrefix(domain, ".") {
			return cookieIdentity{}, false
		}
		canonical, valid := canonicalCookieHost(domain)
		if !valid || canonical != domain {
			return cookieIdentity{}, false
		}
		if domain != host && (net.ParseIP(host) != nil || !strings.HasSuffix(host, "."+domain)) {
			return cookieIdentity{}, false
		}
	}
	path := c.Path
	if !strings.HasPrefix(path, "/") {
		path = "/"
		if strings.HasPrefix(u.Path, "/") {
			if end := strings.LastIndex(u.Path, "/"); end > 0 {
				path = u.Path[:end]
			}
		}
	}
	return cookieIdentity{c.Name, domain, path}, true
}

func copyJarCookie(c *http.Cookie) *http.Cookie {
	copy := *c
	copy.Unparsed = append([]string(nil), c.Unparsed...)
	return &copy
}
func expiredCookie(c *http.Cookie, created, now time.Time) bool {
	if c.MaxAge < 0 {
		return true
	}
	if c.MaxAge > 0 {
		return now.Sub(created).Seconds() >= float64(c.MaxAge)
	}
	return !c.Expires.IsZero() && !c.Expires.After(now)
}
func (j *cookieJar) prune(now time.Time) {
	for key, record := range j.records {
		if expiredCookie(record.cookie, record.created, now) {
			delete(j.records, key)
		}
	}
}

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if u == nil {
		return
	}
	j.Lock()
	defer j.Unlock()
	now := time.Now()
	j.prune(now)
	for _, c := range cookies {
		if c == nil {
			continue
		}
		key, ok := cookieKey(u, c)
		if !ok {
			continue
		}
		deletion := expiredCookie(c, now, now)
		if !deletion && !j.config.allowEmptyCookies && c.Value == "" {
			continue
		}
		if _, exists := j.records[key]; exists && j.config.skipExisting && !deletion {
			continue
		}
		owned := copyJarCookie(c)
		j.jar.SetCookies(u, []*http.Cookie{owned})
		if deletion {
			delete(j.records, key)
			continue
		}
		// Only accepted backend entries enter the metadata inventory. Query at
		// this cookie's path and (for secure cookies) HTTPS, without network I/O.
		probe := *u
		probe.Path = key.path
		probe.RawPath = ""
		if c.Secure {
			probe.Scheme = "https"
		}
		accepted := false
		for _, stored := range j.jar.Cookies(&probe) {
			if stored.Name == c.Name && stored.Value == c.Value {
				accepted = true
				break
			}
		}
		if !accepted {
			continue
		}
		j.sequence++
		host, _ := canonicalCookieHost(u.Hostname())
		j.records[key] = cookieRecord{cookie: owned, host: host, created: now, sequence: j.sequence}
	}
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	if u == nil {
		return nil
	}
	j.RLock()
	defer j.RUnlock()
	return j.jar.Cookies(u)
}

// Inventory keys are exact canonical source hosts, never a guessed registrable
// domain. Values retain their original attributes and are independently owned.
func (j *cookieJar) GetAllCookies() map[string][]*http.Cookie {
	j.Lock()
	defer j.Unlock()
	j.prune(time.Now())
	records := make([]cookieRecord, 0, len(j.records))
	for _, record := range j.records {
		records = append(records, record)
	}
	sort.Slice(records, func(a, b int) bool { return records[a].sequence < records[b].sequence })
	result := make(map[string][]*http.Cookie)
	for _, record := range records {
		result[record.host] = append(result[record.host], copyJarCookie(record.cookie))
	}
	return result
}
