package encrypt

import (
	"errors"
	"testing"
)

func TestMarkUpstreamFailureThreshold(t *testing.T) {
	p := &ProxyServer{
		config: &ProxyConfig{UpstreamBackoffSeconds: 10},
	}
	if p.shouldFastFailUpstream() {
		t.Fatalf("unexpected fast fail before failures")
	}
	p.markUpstreamFailure(errors.New("e1"))
	p.markUpstreamFailure(errors.New("e2"))
	if p.shouldFastFailUpstream() {
		t.Fatalf("should not fast fail before threshold")
	}
	p.markUpstreamFailure(errors.New("e3"))
	if !p.shouldFastFailUpstream() {
		t.Fatalf("expected fast fail after threshold")
	}
	p.markUpstreamSuccess()
	if p.shouldFastFailUpstream() {
		t.Fatalf("should recover after success")
	}
}

func TestNormalizeRulePrefix(t *testing.T) {
	got, ok := normalizeRulePrefix("movies/*")
	if !ok || got != "/movies" {
		t.Fatalf("unexpected prefix: ok=%v got=%q", ok, got)
	}
	if _, ok := normalizeRulePrefix("^/raw/.*"); ok {
		t.Fatalf("regex rule should not produce prefix")
	}
	if _, ok := normalizeRulePrefix("m*"); ok {
		t.Fatalf("wildcard-in-prefix rule should not produce literal prefix")
	}
}
