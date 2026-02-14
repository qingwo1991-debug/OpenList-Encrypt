package encrypt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestIsLocalOrPrivateHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"192.168.1.10", true},
		{"10.0.0.3", true},
		{"172.16.20.3", true},
		{"8.8.8.8", false},
		{"example.com", false},
	}
	for _, c := range cases {
		if got := isLocalOrPrivateHost(c.host); got != c.want {
			t.Fatalf("host=%s got=%v want=%v", c.host, got, c.want)
		}
	}
}

func TestUpstreamBackoffState(t *testing.T) {
	p := &ProxyServer{
		config: &ProxyConfig{
			UpstreamBackoffSeconds: 2,
		},
	}
	p.markUpstreamFailure(errors.New("boom"))
	active, remain, reason := p.upstreamBackoffState()
	if !active {
		t.Fatalf("expected active backoff")
	}
	if remain <= 0 {
		t.Fatalf("expected positive backoff remain, got %v", remain)
	}
	if reason == "" {
		t.Fatalf("expected failure reason")
	}
	time.Sleep(20 * time.Millisecond)
	p.markUpstreamSuccess()
	active, _, _ = p.upstreamBackoffState()
	if active {
		t.Fatalf("expected backoff cleared")
	}
}

func TestProxyResolverAlwaysDirect(t *testing.T) {
	t.Setenv("http_proxy", "http://127.0.0.1:9999")
	t.Setenv("https_proxy", "http://127.0.0.1:9999")
	_ = os.Setenv("HTTP_PROXY", "http://127.0.0.1:9999")
	_ = os.Setenv("HTTPS_PROXY", "http://127.0.0.1:9999")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/ping", nil)
	resolver := newProxyResolver(&ProxyConfig{})
	proxyURL, err := resolver(req)
	if err != nil {
		t.Fatalf("resolver returned err: %v", err)
	}
	if proxyURL != nil {
		t.Fatalf("expected direct connection, got proxy=%s", proxyURL.String())
	}
}

func TestHandleProxyDoesNotFastFailOnBackoff(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	parsed, err := neturl.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}
	p := &ProxyServer{
		config: &ProxyConfig{
			AlistHost:              parsed.Hostname(),
			AlistPort:              port,
			AlistHttps:             parsed.Scheme == "https",
			UpstreamBackoffSeconds: 20,
		},
		httpClient: &http.Client{Timeout: 3 * time.Second},
	}
	p.markUpstreamFailure(errors.New("boom"))

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/any/path", nil)
	rr := httptest.NewRecorder()
	p.handleProxy(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected %d from upstream, got %d body=%s", http.StatusNoContent, rr.Code, rr.Body.String())
	}
}
