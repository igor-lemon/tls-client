package tls_client

import (
	http "github.com/igor-lemon/fhttp"
	"net/url"
	"testing"
	"time"
)

func jarURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
func cookieValues(j CookieJar, u string) map[string]string {
	m := make(map[string]string)
	for _, c := range j.Cookies(jarURL(u)) {
		m[c.Name] = c.Value
	}
	return m
}
func TestCookieJarUsesProtocolScopeAndOwnsMetadata(t *testing.T) {
	jar := NewCookieJar(WithAllowEmptyCookies())
	source := jarURL("https://a.example.test/one/start")
	original := &http.Cookie{Name: "host", Value: "original", Path: "/"}
	jar.SetCookies(source, []*http.Cookie{original, {Name: "path", Value: "one", Path: "/one"}, {Name: "secure", Value: "tls", Path: "/", Secure: true}, {Name: "expired", Value: "past", Path: "/", Expires: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}, {Name: "foreign", Value: "wrong", Domain: "b.example.test", Path: "/"}})
	original.Value = "caller mutation"
	got := cookieValues(jar, "http://a.example.test/other")
	if len(got) != 1 || got["host"] != "original" {
		t.Fatalf("wrong HTTP/path/expiry/domain scope: %v", got)
	}
	if got := cookieValues(jar, "https://b.example.test/one"); len(got) != 0 {
		t.Fatalf("host-only cookie leaked to sibling: %v", got)
	}
	got = cookieValues(jar, "https://a.example.test/one/page")
	if len(got) != 3 || got["path"] != "one" || got["secure"] != "tls" {
		t.Fatalf("valid scoped cookies missing: %v", got)
	}
	all := jar.GetAllCookies()
	for _, cookies := range all {
		for _, c := range cookies {
			c.Value = "getter mutation"
		}
	}
	got = cookieValues(jar, "https://a.example.test/one/page")
	if got["host"] != "original" || got["path"] != "one" {
		t.Fatalf("getter mutated jar: %v", got)
	}
	jar.SetCookies(source, []*http.Cookie{{Name: "host", Value: "replaced", Path: "/"}})
	if got := cookieValues(jar, "https://a.example.test/")["host"]; got != "replaced" {
		t.Fatalf("replacement=%q", got)
	}
	jar.SetCookies(source, []*http.Cookie{{Name: "host", MaxAge: -1, Path: "/"}})
	if got := cookieValues(jar, "https://a.example.test/"); got["host"] != "" {
		t.Fatalf("deletion ignored: %v", got)
	}
}
func TestSkipExistingUsesCookieIdentityAndHonorsDeletion(t *testing.T) {
	jar := NewCookieJar(WithSkipExisting())
	source := jarURL("https://a.example.test/a/start")
	jar.SetCookies(source, []*http.Cookie{{Name: "sid", Value: "a1", Path: "/a"}, {Name: "sid", Value: "b1", Path: "/b"}})
	jar.SetCookies(source, []*http.Cookie{{Name: "sid", Value: "a2", Path: "/a"}})
	if a, b := cookieValues(jar, "https://a.example.test/a")["sid"], cookieValues(jar, "https://a.example.test/b")["sid"]; a != "a1" || b != "b1" {
		t.Fatalf("cookie identities collided: a=%q b=%q", a, b)
	}
	jar.SetCookies(source, []*http.Cookie{{Name: "sid", MaxAge: -1, Path: "/a"}})
	if got := cookieValues(jar, "https://a.example.test/a"); len(got) != 0 {
		t.Fatalf("skip-existing blocked deletion: %v", got)
	}
	if got := cookieValues(jar, "https://a.example.test/b")["sid"]; got != "b1" {
		t.Fatalf("deleting a changed b: %q", got)
	}
}
