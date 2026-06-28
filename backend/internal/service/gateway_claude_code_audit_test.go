//go:build unit

package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const claudeCodeAPIKeyImpersonationAudit = `SAZ vs OAuth mimicry audit

Scope
- This artifact documents only safe SAZ-observed field names and current backend behavior.
- It intentionally excludes raw .saz payloads, Bearer tokens, API keys, cookies, and full request bodies.
- accepted divergence summary: keep the current UA / cc_version, static beta bundle, credential auth split, OAuth system prompt behavior, and current X-Stainless values until a later task changes them on purpose.
- API-key impersonation intentionally reuses OAuth mimicry for body, header, session, and metadata shaping while preserving upstream x-api-key authentication.

SAZ-observed field names in scope
- User-Agent
- cc_version
- anthropic-beta
- X-Stainless
- X-Claude-Code-Session-Id
- metadata.user_id
- context_management
- cache_control
- system

Accepted divergences
- User-Agent / cc_version: current OAuth mimicry keeps the repository versioned fingerprint instead of chasing the latest SAZ version.
  Implementation: backend/internal/pkg/claude/constants.go, backend/internal/service/gateway_billing_header.go, backend/internal/service/gateway_service.go
- anthropic-beta: OAuth mimicry keeps the current static/full bundle chosen by repository constants and helpers.
  Implementation: backend/internal/pkg/claude/constants.go, backend/internal/service/gateway_service.go
- Credential auth split: upstream API-key accounts stay on x-api-key auth and do not mix OAuth Bearer behavior.
  Implementation: backend/internal/service/gateway_service.go, backend/internal/service/gateway_anthropic_apikey_passthrough_test.go
- OAuth system prompt behavior: mimicry keeps the repository's existing OAuth prompt rewrite/injection behavior.
  Implementation: backend/internal/service/gateway_service.go, backend/internal/service/claude_code_detection_test.go
- OAuth X-Stainless values: mimicry keeps current OAuth fingerprint values rather than mirroring SAZ exactly.
  Implementation: backend/internal/pkg/claude/constants.go, backend/internal/service/gateway_service.go

In-scope alignments
- X-Claude-Code-Session-Id: API-key impersonation keeps emitted header session independent from generated metadata.user_id session information.
  Implementation: backend/internal/service/gateway_service.go, backend/internal/service/header_util.go, backend/internal/service/gateway_oauth_metadata_test.go
- X-Stainless casing: emitted wire keys use initial-capital X-Stainless-* casing via raw header helpers.
  Implementation: backend/internal/service/header_util.go, backend/internal/service/gateway_service.go
- Selected body defaults: OAuth mimicry fills missing tools, temperature, max_tokens, and conditional context_management defaults without overwriting explicit client values.
  Implementation: backend/internal/service/gateway_service.go, backend/internal/service/gateway_context_management_test.go

Reference map
- Header assembly and auth split: backend/internal/service/gateway_service.go
- Claude constants and default fingerprint values: backend/internal/pkg/claude/constants.go
- Header wire casing helpers: backend/internal/service/header_util.go
- Body sanitize helper for beta/body symmetry: backend/internal/service/gateway_request.go
- Session and metadata helpers: backend/internal/service/gateway_service.go
`

func TestClaudeCodeAPIKeyImpersonationAudit_IsExplicit(t *testing.T) {
	required := []string{
		"cc_version",
		"anthropic-beta",
		"X-Stainless",
		"X-Claude-Code-Session-Id",
		"Accepted divergences",
		"In-scope alignments",
		"backend/internal/service/gateway_service.go",
		"backend/internal/pkg/claude/constants.go",
		"backend/internal/service/header_util.go",
		"backend/internal/service/gateway_request.go",
	}

	for _, needle := range required {
		require.Truef(t, strings.Contains(claudeCodeAPIKeyImpersonationAudit, needle), "audit artifact missing %q", needle)
	}
}
