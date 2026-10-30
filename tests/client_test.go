package tests

import (
	"encoding/json"
	"io"
	"testing"

	"github.com/igor-lemon/tls-client/profiles"

	http "github.com/igor-lemon/fhttp"
	tls_client "github.com/igor-lemon/tls-client"
	tls "github.com/igor-lemon/utls"
)

func TestClients(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"firefox_147", firefox_147},
		{"chrome_146_PSK", chrome_146_PSK},
		{"chrome_152_PSK", chrome_152_PSK},
		{"chrome_150_PSK", chrome_150_PSK},
		{"safari_iOS_26_0", safari_iOS_26_0},
		{"safari_iOS_18_5", safari_iOS_18_5},
		{"chrome_144", chrome_144},
		{"chrome_133", chrome_133},
		{"chrome_131", chrome_131},
		{"chrome_124", chrome_124},
		{"chrome_120", chrome_120},
		{"chrome_117", chrome_117},
		{"firefox_117", firefox_117},
		{"chrome116WithPsk", chrome116WithPsk},
		{"chrome112", chrome112},
		{"chrome111", chrome111},
		{"chrome110", chrome110},
		{"chrome109", chrome109},
		{"chrome108", chrome108},
		{"chrome107", chrome107},
		{"chrome105", chrome105},
		{"chrome104", chrome104},
		{"chrome103", chrome103},
		{"safari_16_0", safari_16_0},
		{"safari_iOS_16_0", safari_iOS_16_0},
		{"safariIos17", safariIos17},
		{"safari_iOS_18_0", safari_iOS_18_0},
		{"firefox_105", firefox_105},
		{"firefox_106", firefox_106},
		{"firefox_108", firefox_108},
		{"firefox_110", firefox_110},
		{"firefox_132", firefox_132},
		{"opera_91", opera_91},
	} {
		t.Run(tc.name, tc.run)
	}
}

func TestCustomClients(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"okhttp4Android13", okhttp4Android13},
		{"okhttp4Android12", okhttp4Android12},
		{"okhttp4Android11", okhttp4Android11},
		{"okhttp4Android10", okhttp4Android10},
		{"okhttp4Android9", okhttp4Android9},
		{"okhttp4Android8", okhttp4Android8},
		{"okhttp4Android7", okhttp4Android7},
	} {
		t.Run(tc.name, tc.run)
	}
}

var defaultHeader = http.Header{
	"accept":          {"*/*"},
	"accept-encoding": {"gzip"},
	"accept-language": {"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
	"user-agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) chrome/100.0.4896.75 safari/537.36"},
	http.HeaderOrderKey: {
		"accept",
		"accept-encoding",
		"accept-language",
		"user-agent",
	},
}

var defaultOkHttp4Header = http.Header{
	"accept-encoding": {"gzip"},
	"user-agent":      {"okhttp/4.10.0"},
	http.HeaderOrderKey: {
		"accept-encoding",
		"user-agent",
	},
}

func chrome116WithPsk(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_116_PSK),
		tls_client.WithTimeoutSeconds(120),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_112.Str()], resp, false)
	// A distinct resumed connection, rather than a second request on the first.
	client.CloseIdleConnections()

	req, err = http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_112_PSK.Str()], resp, true)
}

func chrome112(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_112),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_112.Str()], resp)
}

func chrome111(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_111),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_111.Str()], resp)
}

func chrome110(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_110),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_110.Str()], resp)
}

func chrome109(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_109),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_109.Str()], resp)
}

func chrome108(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_108),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_108.Str()], resp)
}

func chrome107(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_107),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_107.Str()], resp)
}

func chrome105(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_105),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_105.Str()], resp)
}

func chrome104(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_104),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_104.Str()], resp)
}

func chrome103(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_103),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][tls.HelloChrome_103.Str()], resp)
}

func safari_16_0(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Safari_16_0),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "safari", clientFingerprints[safari][tls.HelloSafari_16_0.Str()], resp)
}

func safari_iOS_16_0(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Safari_IOS_16_0),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "safari ios", clientFingerprints[safariIos][tls.HelloIOS_16_0.Str()], resp)
}

func safari_iOS_18_0(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Safari_IOS_18_0),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "safari ios", clientFingerprints[safariIos][profiles.Safari_IOS_18_0.GetClientHelloStr()], resp)
}

func firefox_105(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Firefox_105),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "firefox", clientFingerprints[firefox][tls.HelloFirefox_105.Str()], resp)
}

func firefox_106(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Firefox_106),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "firefox", clientFingerprints[firefox][tls.HelloFirefox_106.Str()], resp)
}

func firefox_108(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Firefox_108),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "firefox", clientFingerprints[firefox][tls.HelloFirefox_108.Str()], resp)
}

func chrome_124(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_124),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_124.GetClientHelloStr()], resp)
}

func chrome_146_PSK(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_146_PSK),
		tls_client.WithTimeoutSeconds(120),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_146.GetClientHelloStr()], resp, false)
	// A distinct resumed connection, rather than a second request on the first.
	client.CloseIdleConnections()

	req, err = http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_146_PSK.GetClientHelloStr()], resp, true)
}

func chrome_152_PSK(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_152_PSK),
		tls_client.WithTimeoutSeconds(120),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_152.GetClientHelloStr()], resp, false)
	// A distinct resumed connection, rather than a second request on the first.
	client.CloseIdleConnections()

	req, err = http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_152_PSK.GetClientHelloStr()], resp, true)
}

func chrome_150_PSK(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_150_PSK),
		tls_client.WithTimeoutSeconds(120),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_150.GetClientHelloStr()], resp, false)
	// A distinct resumed connection, rather than a second request on the first.
	client.CloseIdleConnections()

	req, err = http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_150_PSK.GetClientHelloStr()], resp, true)
}

func safari_iOS_26_0(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Safari_IOS_26_0),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "safari ios", clientFingerprints[safariIos][profiles.Safari_IOS_26_0.GetClientHelloStr()], resp)
}

func safari_iOS_18_5(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Safari_IOS_18_5),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "safari ios", clientFingerprints[safariIos][profiles.Safari_IOS_18_5.GetClientHelloStr()], resp)
}

func chrome_144(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_144),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_144.GetClientHelloStr()], resp)
}

func chrome_133(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_133),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_133.GetClientHelloStr()], resp)
}

func chrome_131(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_131),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_131.GetClientHelloStr()], resp)
}

func chrome_120(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_120),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_120.GetClientHelloStr()], resp)
}

func chrome_117(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Chrome_117),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "chrome", clientFingerprints[chrome][profiles.Chrome_117.GetClientHelloStr()], resp)
}

func firefox_147(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Firefox_147),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "firefox", clientFingerprints[firefox][profiles.Firefox_147.GetClientHelloStr()], resp)
}

func firefox_117(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Firefox_117),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "firefox", clientFingerprints[firefox][profiles.Firefox_117.GetClientHelloStr()], resp)
}

func firefox_110(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Firefox_110),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "firefox", clientFingerprints[firefox][tls.HelloFirefox_110.Str()], resp)
}

func firefox_132(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Firefox_132),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "firefox", clientFingerprints[firefox][profiles.Firefox_132.GetClientHelloStr()], resp)
}

func opera_91(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Opera_91),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "opera", clientFingerprints[opera][tls.HelloOpera_91.Str()], resp)
}

func safariIos17(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Safari_IOS_17_0),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultHeader

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "safari_IOS", clientFingerprints[safariIos][profiles.Safari_IOS_17_0.GetClientHelloStr()], resp)
}

func compareResponse(t *testing.T, clientName string, expectedValues map[string]string, resp *http.Response, resumed ...bool) {
	defer resp.Body.Close()

	readBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	tlsApiResponse := TlsApiResponse{}
	if err := json.Unmarshal(readBytes, &tlsApiResponse); err != nil {
		t.Fatal(err)
	}

	if len(resumed) > 0 && tlsApiResponse.TLS.DidResume != resumed[0] {
		t.Errorf("owned peer resumption=%v,want %v", tlsApiResponse.TLS.DidResume, resumed[0])
	}

	for key, expectedValue := range expectedValues {
		switch key {
		case ja3String:
			if tlsApiResponse.TLS.Ja3 != expectedValue {
				t.Errorf("TLS Ja3 mismatch.\nexpected: %s\nactual  : %s\nclient: %s", expectedValue, tlsApiResponse.TLS.Ja3, clientName)
			}
		case ja3Hash:
			if tlsApiResponse.TLS.Ja3Hash != expectedValue {
				t.Errorf("TLS Ja3 hash mismatch.\nexpected: %s\nactual  : %s\nclient: %s", expectedValue, tlsApiResponse.TLS.Ja3Hash, clientName)
			}
		case ja4String:
			if tlsApiResponse.TLS.Ja4R != expectedValue {
				t.Errorf("TLS Ja4 mismatch.\nexpected: %s\nactual  : %s\nclient: %s", expectedValue, tlsApiResponse.TLS.Ja4R, clientName)
			}
		case ja4Hash:
			if tlsApiResponse.TLS.Ja4 != expectedValue {
				t.Errorf("TLS Ja4 hash mismatch.\nexpected: %s\nactual  : %s\nclient: %s", expectedValue, tlsApiResponse.TLS.Ja4, clientName)
			}
		case akamaiFingerprint:
			if tlsApiResponse.HTTP2.AkamaiFingerprint != expectedValue {
				t.Errorf("akamai fingerprint mismatch.\nexpected: %s\nactual  : %s\nclient: %s", expectedValue, tlsApiResponse.HTTP2.AkamaiFingerprint, clientName)
			}
		case akamaiFingerprintHash:
			if tlsApiResponse.HTTP2.AkamaiFingerprintHash != expectedValue {
				t.Errorf("akamai fingerprint hash mismatch.\nexpected: %s\nactual  : %s\nclient: %s", expectedValue, tlsApiResponse.HTTP2.AkamaiFingerprintHash, clientName)
			}
		}
	}
}

func okhttp4Android13(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Okhttp4Android13),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultOkHttp4Header

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "okhttp4 android 13", clientFingerprints[okhttpAndroid][profiles.Okhttp4Android13.GetClientHelloStr()], resp)
}

func okhttp4Android12(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Okhttp4Android12),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultOkHttp4Header

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "okhttp4 android 12", clientFingerprints[okhttpAndroid][profiles.Okhttp4Android12.GetClientHelloStr()], resp)
}

func okhttp4Android11(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Okhttp4Android11),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultOkHttp4Header

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "okhttp4 android 11", clientFingerprints[okhttpAndroid][profiles.Okhttp4Android11.GetClientHelloStr()], resp)
}

func okhttp4Android10(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Okhttp4Android10),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultOkHttp4Header

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "okhttp4 android 10", clientFingerprints[okhttpAndroid][profiles.Okhttp4Android10.GetClientHelloStr()], resp)
}

func okhttp4Android9(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Okhttp4Android9),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultOkHttp4Header

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "okhttp4 android 9", clientFingerprints[okhttpAndroid][profiles.Okhttp4Android9.GetClientHelloStr()], resp)
}

func okhttp4Android8(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Okhttp4Android8),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultOkHttp4Header

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "okhttp4 android 8", clientFingerprints[okhttpAndroid][profiles.Okhttp4Android8.GetClientHelloStr()], resp)
}

func okhttp4Android7(t *testing.T) {
	peetApiEndpoint := newOwnedFingerprintPeer(t)
	options := []tls_client.HttpClientOption{
		skipPeetCertVerify,
		tls_client.WithServerNameOverwrite("owned.example"),
		tls_client.WithClientProfile(profiles.Okhttp4Android7),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = defaultOkHttp4Header

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	compareResponse(t, "okhttp4 android 7", clientFingerprints[okhttpAndroid][profiles.Okhttp4Android7.GetClientHelloStr()], resp)
}
