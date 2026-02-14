package encrypt

import (
	"errors"
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

