package tests

import (
	"github.com/igor-lemon/fhttp/httptest"
	"io"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/igor-lemon/tls-client/profiles"

	http "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	"github.com/stretchr/testify/assert"
)

func TestClient_SkipExistingCookiesOnClientSetCookies(t *testing.T) {
	jarOptions := []tls_client.CookieJarOption{
		tls_client.WithSkipExisting(),
	}

	jar := tls_client.NewCookieJar(jarOptions...)

	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_133),
		tls_client.WithCookieJar(jar),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}
	u := &url.URL{
		Scheme: "http",
		Host:   "testhost.de",
		Path:   "/test",
	}

	assert.Equal(t, 0, len(client.GetCookies(u)))

	cookie := &http.Cookie{
		Name:   "test1",
		Value:  "test1",
		MaxAge: 1,
	}

	client.SetCookies(u, []*http.Cookie{cookie})

	assert.Equal(t, 1, len(client.GetCookies(u)))

	cookie2 := &http.Cookie{
		Name:   "test2",
		Value:  "test2",
		MaxAge: 1,
	}
	client.SetCookies(u, []*http.Cookie{cookie2})

	assert.Equal(t, 2, len(client.GetCookies(u)))

	cookie3 := &http.Cookie{
		Name:   "test1",
		Value:  "test1",
		MaxAge: 1,
	}
	client.SetCookies(u, []*http.Cookie{cookie3})

	assert.Equal(t, 2, len(client.GetCookies(u)))
}

func TestClient_SkipExistingCookiesOnSetCookiesResponse(t *testing.T) {
	var requests atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		number := requests.Add(1)
		got := map[string]string{}
		for _, cookie := range r.Cookies() {
			got[cookie.Name] = cookie.Value
		}
		if number == 1 {
			if len(got) != 0 {
				t.Errorf("first request cookies=%v", got)
			}
			http.SetCookie(w, &http.Cookie{Name: "root", Value: "s1", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "scoped", Value: "a", Path: "/scope"})
			http.SetCookie(w, &http.Cookie{Name: "expired", Value: "past", Path: "/", Expires: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)})
			http.SetCookie(w, &http.Cookie{Name: "foreign", Value: "wrong", Domain: "other.test", Path: "/"})
		} else {
			wantRoot := "s1"
			if number == 4 {
				wantRoot = ""
			}
			if got["root"] != wantRoot || got["scoped"] != "a" || len(got) != map[bool]int{true: 1, false: 2}[number == 4] {
				t.Errorf("request%d cookies=%v", number, got)
			}
			if number == 2 {
				http.SetCookie(w, &http.Cookie{Name: "root", Value: "s2", Path: "/"})
				http.SetCookie(w, &http.Cookie{Name: "scoped", Value: "b", Path: "/other"})
			}
			if number == 3 {
				http.SetCookie(w, &http.Cookie{Name: "root", Path: "/", MaxAge: -1})
			}
		}
		io.WriteString(w, "owned page")
	}))
	defer peer.Close()
	jar := tls_client.NewCookieJar(tls_client.WithSkipExisting())
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), tls_client.WithClientProfile(profiles.Chrome_133), tls_client.WithCookieJar(jar))
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	endpoint := peer.URL + "/scope/page"
	u, _ := url.Parse(endpoint)
	values := func(at *url.URL) map[string]string {
		result := map[string]string{}
		for _, cookie := range client.GetCookies(at) {
			result[cookie.Name] = cookie.Value
		}
		return result
	}
	for n := 1; n <= 4; n++ {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(body) != "owned page" {
			t.Fatalf("body=%q error=%v", body, err)
		}
		if n == 1 {
			got := values(u)
			if len(got) != 2 || got["root"] != "s1" || got["scoped"] != "a" {
				t.Fatalf("first response scope=%v", got)
			}
			client.SetCookies(u, []*http.Cookie{{Name: "root", Value: "client", Path: "/"}})
		}
	}
	other, _ := url.Parse(peer.URL + "/other/page")
	got := values(other)
	if len(got) != 1 || got["scoped"] != "b" {
		t.Fatalf("other-path cookies=%v", got)
	}
	if requests.Load() != 4 {
		t.Fatalf("requests=%d", requests.Load())
	}
}

func TestClient_ExcludeExpiredCookiesFromRequest(t *testing.T) {
	jar := tls_client.NewCookieJar()

	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_133),
		tls_client.WithCookieJar(jar),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}
	u := &url.URL{
		Scheme: "http",
		Host:   "testhost.de",
		Path:   "/test",
	}

	assert.Equal(t, 0, len(client.GetCookies(u)))

	cookieAlive := &http.Cookie{
		Name:   "test1",
		Value:  "test1",
		MaxAge: 1,
	}

	cookieExpired := &http.Cookie{
		Name:   "test2",
		Value:  "test2",
		MaxAge: -1,
	}

	client.SetCookies(u, []*http.Cookie{cookieAlive, cookieExpired})

	assert.Equal(t, 1, len(client.GetCookies(u)))

	cookieExpireExisting := &http.Cookie{
		Name:   "test1",
		Value:  "test1",
		MaxAge: -1,
	}
	client.SetCookies(u, []*http.Cookie{cookieExpireExisting})

	assert.Equal(t, 0, len(client.GetCookies(u)))
}
