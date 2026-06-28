package responseheaders

import (
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

func TestFilterHeadersDisabledUsesDefaultAllowlist(t *testing.T) {
	src := http.Header{}
	src.Add("Content-Type", "application/json")
	src.Add("X-Request-Id", "req-123")
	src.Add("X-Test", "ok")
	src.Add("Connection", "keep-alive")
	src.Add("Content-Length", "123")

	cfg := config.ResponseHeaderConfig{
		Enabled:     false,
		ForceRemove: []string{"x-request-id"},
	}

	filtered := FilterHeaders(src, CompileHeaderFilter(cfg))
	if filtered.Get("Content-Type") != "application/json" {
		t.Fatalf("expected Content-Type passthrough, got %q", filtered.Get("Content-Type"))
	}
	if filtered.Get("X-Request-Id") != "req-123" {
		t.Fatalf("expected X-Request-Id allowed, got %q", filtered.Get("X-Request-Id"))
	}
	if filtered.Get("X-Test") != "" {
		t.Fatalf("expected X-Test removed, got %q", filtered.Get("X-Test"))
	}
	if filtered.Get("Connection") != "" {
		t.Fatalf("expected Connection to be removed, got %q", filtered.Get("Connection"))
	}
	if filtered.Get("Content-Length") != "" {
		t.Fatalf("expected Content-Length to be removed, got %q", filtered.Get("Content-Length"))
	}
}

func TestFilterHeadersEnabledUsesAllowlist(t *testing.T) {
	src := http.Header{}
	src.Add("Content-Type", "application/json")
	src.Add("X-Extra", "ok")
	src.Add("X-Remove", "nope")
	src.Add("X-Blocked", "nope")

	cfg := config.ResponseHeaderConfig{
		Enabled:           true,
		AdditionalAllowed: []string{"x-extra"},
		ForceRemove:       []string{"x-remove"},
	}

	filtered := FilterHeaders(src, CompileHeaderFilter(cfg))
	if filtered.Get("Content-Type") != "application/json" {
		t.Fatalf("expected Content-Type allowed, got %q", filtered.Get("Content-Type"))
	}
	if filtered.Get("X-Extra") != "ok" {
		t.Fatalf("expected X-Extra allowed, got %q", filtered.Get("X-Extra"))
	}
	if filtered.Get("X-Remove") != "" {
		t.Fatalf("expected X-Remove removed, got %q", filtered.Get("X-Remove"))
	}
	if filtered.Get("X-Blocked") != "" {
		t.Fatalf("expected X-Blocked removed, got %q", filtered.Get("X-Blocked"))
	}
}

func TestFilterHeadersForClaudeCodeAPIKeyImpersonationRemovesGatewayPrefixes(t *testing.T) {
	src := http.Header{}
	gatewayHeaders := map[string]string{
		"X-Litellm-Model-Id": "litellm",
		"Helicone-Id":        "helicone",
		"X-Portkey-Trace-Id": "portkey",
		"Cf-Aig-Request-Id":  "cf",
		"X-Kong-Request-Id":  "kong",
		"X-Bt-Trace-Id":      "bt",
	}
	additionalAllowed := make([]string, 0, len(gatewayHeaders)+1)
	for key, value := range gatewayHeaders {
		src.Add(key, value)
		additionalAllowed = append(additionalAllowed, key)
	}
	src.Add("X-Litellm", "not-a-prefixed-header")
	additionalAllowed = append(additionalAllowed, "X-Litellm")

	cfg := config.ResponseHeaderConfig{
		Enabled:           true,
		AdditionalAllowed: additionalAllowed,
	}

	filtered := FilterHeadersForClaudeCodeAPIKeyImpersonation(src, CompileHeaderFilter(cfg))
	for key := range gatewayHeaders {
		if filtered.Get(key) != "" {
			t.Fatalf("expected %s removed in impersonation mode, got %q", key, filtered.Get(key))
		}
	}
	if filtered.Get("X-Litellm") != "not-a-prefixed-header" {
		t.Fatalf("expected exact non-prefixed X-Litellm to remain, got %q", filtered.Get("X-Litellm"))
	}
}

func TestFilterHeadersOrdinaryAllowsGatewayPrefixesWhenAdditionalAllowed(t *testing.T) {
	src := http.Header{}
	src.Add("X-Litellm-Model-Id", "litellm")
	src.Add("Helicone-Id", "helicone")
	src.Add("X-Portkey-Trace-Id", "portkey")
	src.Add("Cf-Aig-Request-Id", "cf")
	src.Add("X-Kong-Request-Id", "kong")
	src.Add("X-Bt-Trace-Id", "bt")

	cfg := config.ResponseHeaderConfig{
		Enabled: true,
		AdditionalAllowed: []string{
			"x-litellm-model-id",
			"helicone-id",
			"x-portkey-trace-id",
			"cf-aig-request-id",
			"x-kong-request-id",
			"x-bt-trace-id",
		},
	}

	filtered := FilterHeaders(src, CompileHeaderFilter(cfg))
	for key, values := range src {
		if filtered.Get(key) != values[0] {
			t.Fatalf("expected ordinary filtering to preserve %s, got %q", key, filtered.Get(key))
		}
	}
}

func TestFilterHeadersForClaudeCodeAPIKeyImpersonationPreservesOperationalHeaders(t *testing.T) {
	src := http.Header{}
	src.Add("Content-Type", "application/json")
	src.Add("X-Request-Id", "req-123")
	src.Add("X-Ratelimit-Remaining-Requests", "42")
	src.Add("Retry-After", "3")
	src.Add("Cache-Control", "no-cache")
	src.Add("X-Litellm-Model-Id", "litellm")

	cfg := config.ResponseHeaderConfig{
		Enabled:           true,
		AdditionalAllowed: []string{"x-litellm-model-id"},
	}

	filtered := FilterHeadersForClaudeCodeAPIKeyImpersonation(src, CompileHeaderFilter(cfg))
	if filtered.Get("Content-Type") != "application/json" {
		t.Fatalf("expected Content-Type preserved, got %q", filtered.Get("Content-Type"))
	}
	if filtered.Get("X-Request-Id") != "req-123" {
		t.Fatalf("expected X-Request-Id preserved, got %q", filtered.Get("X-Request-Id"))
	}
	if filtered.Get("X-Ratelimit-Remaining-Requests") != "42" {
		t.Fatalf("expected rate limit header preserved, got %q", filtered.Get("X-Ratelimit-Remaining-Requests"))
	}
	if filtered.Get("Retry-After") != "3" {
		t.Fatalf("expected Retry-After preserved, got %q", filtered.Get("Retry-After"))
	}
	if filtered.Get("Cache-Control") != "no-cache" {
		t.Fatalf("expected Cache-Control preserved, got %q", filtered.Get("Cache-Control"))
	}
	if filtered.Get("X-Litellm-Model-Id") != "" {
		t.Fatalf("expected gateway header removed, got %q", filtered.Get("X-Litellm-Model-Id"))
	}
}

func TestFilterHeadersForClaudeCodeAPIKeyImpersonationAdditionalAllowedCannotReallowGatewayPrefix(t *testing.T) {
	src := http.Header{}
	src.Add("X-Portkey-Trace-Id", "portkey")
	src.Add("X-Extra", "ok")

	cfg := config.ResponseHeaderConfig{
		Enabled:           true,
		AdditionalAllowed: []string{"x-portkey-trace-id", "x-extra"},
	}

	filtered := FilterHeadersForClaudeCodeAPIKeyImpersonation(src, CompileHeaderFilter(cfg))
	if filtered.Get("X-Portkey-Trace-Id") != "" {
		t.Fatalf("expected AdditionalAllowed gateway header removed, got %q", filtered.Get("X-Portkey-Trace-Id"))
	}
	if filtered.Get("X-Extra") != "ok" {
		t.Fatalf("expected non-gateway AdditionalAllowed header preserved, got %q", filtered.Get("X-Extra"))
	}
}
