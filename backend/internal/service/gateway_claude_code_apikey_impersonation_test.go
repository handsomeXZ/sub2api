//go:build unit

package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

const claudeCodeAPIKeyImpersonationSessionIDForTest = "11111111-2222-4333-8444-555555555555"
const claudeCodeAPIKeyImpersonationNativeMetadataUserIDForTest = `{"device_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","account_uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","session_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}`

const (
	claudeCodeAPIKeyImpersonationSensitiveAuthForTest        = "sensitive-authorization-marker"
	claudeCodeAPIKeyImpersonationSensitiveClientKeyForTest   = "sensitive-client-key-marker"
	claudeCodeAPIKeyImpersonationSensitiveCookieForTest      = "sensitive-cookie-marker"
	claudeCodeAPIKeyImpersonationSensitiveBodyForTest        = "sensitive-body-marker"
	claudeCodeAPIKeyImpersonationSensitiveSigningForTest     = "sensitive-cch-marker"
	claudeCodeAPIKeyImpersonationSensitiveUpstreamKeyForTest = "sensitive-upstream-key-marker"
)

var claudeCodeAPIKeyImpersonationSensitiveMarkersForTest = []string{
	claudeCodeAPIKeyImpersonationSensitiveAuthForTest,
	claudeCodeAPIKeyImpersonationSensitiveClientKeyForTest,
	claudeCodeAPIKeyImpersonationSensitiveCookieForTest,
	claudeCodeAPIKeyImpersonationSensitiveBodyForTest,
	claudeCodeAPIKeyImpersonationSensitiveSigningForTest,
	claudeCodeAPIKeyImpersonationSensitiveUpstreamKeyForTest,
}

func requireHeaderKeyPresentExactly(t *testing.T, h http.Header, want string) {
	t.Helper()
	_, ok := h[want]
	require.Truef(t, ok, "expected exact header key %q to exist, got keys %v", want, sortedHeaderKeysForTest(h))

	canonical := http.CanonicalHeaderKey(strings.ToLower(want))
	if canonical != want {
		_, hasCanonical := h[canonical]
		require.Falsef(t, hasCanonical, "unexpected canonicalized key %q present alongside %q", canonical, want)
	}
}

func sortedHeaderKeysForTest(h http.Header) []string {
	return sortHeadersByWireOrder(h)
}

func newClaudeCodeAPIKeyImpersonationAccountForTest(enabled bool) *Account {
	return newClaudeCodeAPIKeyImpersonationAccountForTestWithType(enabled, AccountTypeAPIKey)
}

func newClaudeCodeAPIKeyImpersonationAccountForTestWithType(enabled bool, accountType string) *Account {
	extra := map[string]any{}
	if enabled {
		extra["claude_code_identity_impersonation_enabled"] = true
	}
	return &Account{
		ID:          701,
		Name:        "anthropic-apikey-impersonation-test",
		Platform:    PlatformAnthropic,
		Type:        accountType,
		Concurrency: 1,
		Credentials: map[string]any{
			"api_key":  claudeCodeAPIKeyImpersonationSensitiveUpstreamKeyForTest,
			"base_url": "https://api.anthropic.com",
			"model_mapping": map[string]any{
				"claude-3-7-sonnet-20250219": "claude-3-opus-20240229",
			},
		},
		Extra:       extra,
		Status:      StatusActive,
		Schedulable: true,
	}
}

func newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream *anthropicHTTPUpstreamRecorder, withIdentity bool) *GatewayService {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{MaxLineSize: defaultMaxLineSize},
		Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{
			Enabled:           false,
			AllowInsecureHTTP: true,
		}},
	}
	var identityService *IdentityService
	if withIdentity {
		identityService = NewIdentityService(&identityCacheStub{})
	}
	return &GatewayService{
		cfg:                  cfg,
		responseHeaderFilter: compileResponseHeaderFilter(cfg),
		httpUpstream:         upstream,
		rateLimitService:     &RateLimitService{},
		deferredService:      &DeferredService{},
		identityService:      identityService,
	}
}

func newClaudeCodeAPIKeyImpersonationContextForTest(target string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, target, nil)
	return c, rec
}

func addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c *gin.Context) {
	c.Request.Header.Set("Authorization", claudeCodeAPIKeyImpersonationSensitiveAuthForTest)
	c.Request.Header.Set("X-Api-Key", claudeCodeAPIKeyImpersonationSensitiveClientKeyForTest)
	c.Request.Header.Set("Cookie", claudeCodeAPIKeyImpersonationSensitiveCookieForTest)
}

func requireClaudeCodeAPIKeyImpersonationErrorSanitized(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	for _, marker := range claudeCodeAPIKeyImpersonationSensitiveMarkersForTest {
		require.NotContains(t, err.Error(), marker)
	}
}

type claudeCodeAPIKeyImpersonationFingerprintlessCacheStub struct {
	identityCacheStub
}

func (s *claudeCodeAPIKeyImpersonationFingerprintlessCacheStub) GetFingerprint(_ context.Context, _ int64) (*Fingerprint, error) {
	return &Fingerprint{UserAgent: claude.DefaultHeaders["User-Agent"]}, nil
}

func parseClaudeCodeAPIKeyImpersonationBodyForTest(t *testing.T, body []byte, apiKeyID int64) *ParsedRequest {
	t.Helper()
	parsed, err := ParseGatewayRequest(NewRequestBodyRef(body), PlatformAnthropic)
	require.NoError(t, err)
	parsed.SessionContext = &SessionContext{
		ClientIP:  "127.0.0.1",
		UserAgent: claude.DefaultHeaders["User-Agent"],
		APIKeyID:  apiKeyID,
	}
	return parsed
}

func parseClaudeCodeAPIKeyImpersonationProtocolBodyForTest(t *testing.T, body []byte, protocol string, apiKeyID int64) *ParsedRequest {
	t.Helper()
	parsed, err := ParseGatewayRequest(NewRequestBodyRef(body), protocol)
	require.NoError(t, err)
	parsed.SessionContext = &SessionContext{
		ClientIP:  "127.0.0.1",
		UserAgent: claude.DefaultHeaders["User-Agent"],
		APIKeyID:  apiKeyID,
	}
	return parsed
}

func mustResolveClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t *testing.T, headers http.Header, body []byte, apiKeyID int64) string {
	t.Helper()
	result := mustResolveClaudeCodeMetadataSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: apiKeyID, Headers: headers, Body: body})
	return result.SessionID
}

func applyClaudeCodeAPIKeyImpersonationBodyForTest(t *testing.T, body []byte, model string, systemRaw any, parsed *ParsedRequest) []byte {
	t.Helper()
	c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)

	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true)
	out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), body, systemRaw, model, parsed,
	)
	require.NoError(t, err)
	return out
}

func assertClaudeCodeAPIKeyImpersonationDefaultsFilled(t *testing.T, body []byte) {
	t.Helper()
	require.True(t, gjson.GetBytes(body, "tools").IsArray())
	require.Len(t, gjson.GetBytes(body, "tools").Array(), 0)
	require.Equal(t, "adaptive", gjson.GetBytes(body, "thinking.type").String())
	require.False(t, gjson.GetBytes(body, "thinking.budget_tokens").Exists())
	require.Equal(t, int64(claudeCodeAPIKeyImpersonationDefaultMaxTokens), gjson.GetBytes(body, "max_tokens").Int())
	require.Equal(t, "clear_thinking_20251015", gjson.GetBytes(body, "context_management.edits.0.type").String())
	require.Equal(t, "all", gjson.GetBytes(body, "context_management.edits.0.keep").String())
	require.False(t, gjson.GetBytes(body, "temperature").Exists())
}

func anthropicBodyFromResponsesBodyForTest(t *testing.T, body []byte) ([]byte, any) {
	t.Helper()
	var req apicompat.ResponsesRequest
	require.NoError(t, json.Unmarshal(body, &req))
	anthropicReq, err := apicompat.ResponsesToAnthropicRequest(&req)
	require.NoError(t, err)
	anthropicBody, err := json.Marshal(anthropicReq)
	require.NoError(t, err)
	return anthropicBody, anthropicReq.System
}

func anthropicBodyFromChatCompletionsBodyForTest(t *testing.T, body []byte) ([]byte, any) {
	t.Helper()
	var req apicompat.ChatCompletionsRequest
	require.NoError(t, json.Unmarshal(body, &req))
	responsesReq, err := apicompat.ChatCompletionsToResponses(&req)
	require.NoError(t, err)
	anthropicReq, err := apicompat.ResponsesToAnthropicRequest(responsesReq)
	require.NoError(t, err)
	anthropicBody, err := json.Marshal(anthropicReq)
	require.NoError(t, err)
	return anthropicBody, anthropicReq.System
}

func anthropicBodyForClaudeCodeAPIKeyImpersonationProtocolForTest(t *testing.T, body []byte, protocol string) []byte {
	t.Helper()
	switch protocol {
	case "responses":
		anthropicBody, _ := anthropicBodyFromResponsesBodyForTest(t, body)
		return anthropicBody
	case "chat_completions":
		anthropicBody, _ := anthropicBodyFromChatCompletionsBodyForTest(t, body)
		return anthropicBody
	default:
		return body
	}
}

func successfulAnthropicMessageResponseForImpersonationTest() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"x-request-id": []string{"rid-claude-code-apikey-impersonation"},
		},
		Body: io.NopCloser(strings.NewReader(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-3-opus-20240229","content":[],"usage":{"input_tokens":3,"output_tokens":5}}`)),
	}
}

func successfulAnthropicMessageStreamResponseForImpersonationTest() *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/event-stream"},
			"x-request-id": []string{"rid-claude-code-apikey-impersonation-stream"},
		},
		Body: io.NopCloser(strings.NewReader(strings.Join([]string{
			`event: message_start`,
			`data: {"type":"message_start","message":{"id":"msg_stream_1","type":"message","role":"assistant","model":"claude-3-opus-20240229","content":[],"stop_reason":"","usage":{"input_tokens":3}}}`,
			``,
			`event: content_block_start`,
			`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}`,
			``,
			`event: message_delta`,
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}`,
			``,
			`event: message_stop`,
			`data: {"type":"message_stop"}`,
			``,
		}, "\n") + "\n")),
	}
}

func assertClaudeCodeAPIKeyImpersonationUpstreamMimicForTest(t *testing.T, upstream *anthropicHTTPUpstreamRecorder, wantHeaderSessionID, wantMetadataSessionID string) {
	t.Helper()
	require.NotNil(t, upstream.lastReq)
	require.Equal(t, "https://api.anthropic.com/v1/messages?beta=true", upstream.lastReq.URL.String())
	require.Equal(t, claudeCodeAPIKeyImpersonationSensitiveUpstreamKeyForTest, getHeaderRaw(upstream.lastReq.Header, "x-api-key"))
	require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "authorization"))
	require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "cookie"))
	require.Equal(t, claude.DefaultHeaders["User-Agent"], getHeaderRaw(upstream.lastReq.Header, "User-Agent"))
	require.Equal(t, claude.DefaultHeaders["X-Stainless-Lang"], getHeaderRaw(upstream.lastReq.Header, "X-Stainless-Lang"))
	require.Equal(t, claude.DefaultHeaders["X-Stainless-OS"], getHeaderRaw(upstream.lastReq.Header, "X-Stainless-OS"))
	require.Equal(t, claude.DefaultHeaders["X-Stainless-Runtime"], getHeaderRaw(upstream.lastReq.Header, "X-Stainless-Runtime"))
	require.Equal(t, claude.DefaultHeaders["X-App"], getHeaderRaw(upstream.lastReq.Header, "x-app"))
	require.NotEmpty(t, getHeaderRaw(upstream.lastReq.Header, "x-client-request-id"))
	require.Equal(t, wantHeaderSessionID, getHeaderRaw(upstream.lastReq.Header, "X-Claude-Code-Session-Id"))
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "X-Stainless-OS")
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "X-Stainless-Runtime")
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "X-Stainless-Runtime-Version")
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "x-app")
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "x-client-request-id")

	beta := getHeaderRaw(upstream.lastReq.Header, "anthropic-beta")
	require.Contains(t, beta, claude.BetaClaudeCode)
	require.Contains(t, beta, claude.BetaOAuth)
	require.Contains(t, beta, claude.BetaContextManagement)
	require.NotContains(t, beta, "client-beta")

	metadataUserID := gjson.GetBytes(upstream.lastBody, "metadata.user_id").String()
	parsedUserID := requireClaudeCodeAPIKeyImpersonationMetadataJSONForTest(t, metadataUserID)
	require.Equal(t, wantMetadataSessionID, parsedUserID.SessionID)
}

func requireClaudeCodeAPIKeyImpersonationMetadataJSONForTest(t *testing.T, metadataUserID string) *ParsedUserID {
	t.Helper()
	require.NotEmpty(t, metadataUserID)
	require.False(t, strings.HasPrefix(metadataUserID, "user_"))

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(metadataUserID), &fields))
	require.Len(t, fields, 3)
	require.Contains(t, fields, "device_id")
	require.Contains(t, fields, "account_uuid")
	require.Contains(t, fields, "session_id")

	parsedUserID := ParseMetadataUserID(metadataUserID)
	require.NotNil(t, parsedUserID)
	require.True(t, parsedUserID.IsNewFormat)
	require.NotEmpty(t, parsedUserID.SessionID)
	require.Len(t, parsedUserID.DeviceID, 64)
	_, err := hex.DecodeString(parsedUserID.DeviceID)
	require.NoError(t, err)
	require.True(t, validClaudeCodeSessionID(parsedUserID.AccountUUID))
	return parsedUserID
}

func requireClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t *testing.T, metadataUserID string, input ClaudeCodeSessionIDInput) *ParsedUserID {
	t.Helper()
	parsedUserID := requireClaudeCodeAPIKeyImpersonationMetadataJSONForTest(t, metadataUserID)
	expected := mustResolveClaudeCodeMetadataSessionID(t, input)
	require.Equal(t, expected.SessionID, parsedUserID.SessionID)
	return parsedUserID
}

func assertClaudeCodeAPIKeyImpersonationExplicitReasoningPreservedForTest(t *testing.T, body []byte) {
	t.Helper()
	require.Equal(t, int64(2048), gjson.GetBytes(body, "max_tokens").Int())
	require.Equal(t, "low", gjson.GetBytes(body, "output_config.effort").String())
	require.False(t, gjson.GetBytes(body, "thinking").Exists())
	require.False(t, gjson.GetBytes(body, "context_management").Exists())
	require.False(t, gjson.GetBytes(body, "temperature").Exists())
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_BodyDefaultsFilledForMessages(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)

	out := applyClaudeCodeAPIKeyImpersonationBodyForTest(t, body, "claude-sonnet-4-6", nil, parsed)

	assertClaudeCodeAPIKeyImpersonationDefaultsFilled(t, out)
	metadata := requireClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t, gjson.GetBytes(out, "metadata.user_id").String(), ClaudeCodeSessionIDInput{APIKeyID: 77, Body: body})
	require.NotEqual(t, claudeCodeAPIKeyImpersonationSessionIDForTest, metadata.SessionID)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_MetadataUserIDIgnoresLegacyCLIUA(t *testing.T) {
	c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", "claude-cli/2.1.77 (external, cli)")
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true)

	out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), body, nil, "claude-sonnet-4-6", parsed,
	)

	require.NoError(t, err)
	metadata := requireClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t, gjson.GetBytes(out, "metadata.user_id").String(), ClaudeCodeSessionIDInput{APIKeyID: 77, Headers: c.Request.Header, Body: body})
	require.NotEqual(t, claudeCodeAPIKeyImpersonationSessionIDForTest, metadata.SessionID)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_NativeClaudeCodeSkipsSystemReminderInjection(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"model": "claude-sonnet-4-6",
		"system": []map[string]any{
			{
				"type":          "text",
				"text":          claudeCodeSystemPrompt,
				"cache_control": map[string]any{"type": "ephemeral"},
			},
		},
		"metadata": map[string]any{"user_id": claudeCodeAPIKeyImpersonationNativeMetadataUserIDForTest},
		"messages": []map[string]any{
			{"role": "user", "content": []map[string]any{{"type": "text", "text": "hello"}}},
		},
	})
	require.NoError(t, err)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	systemRaw, ok := parsed.SystemValue()
	require.True(t, ok)
	c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true)

	out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), body, systemRaw, "claude-sonnet-4-6", parsed,
	)

	require.NoError(t, err)
	require.NotContains(t, string(out), "<system-reminder>")
	require.NotContains(t, string(out), "[System Instructions]")
	require.Equal(t, claudeCodeSystemPrompt, gjson.GetBytes(out, "system.0.text").String())
	require.Equal(t, "ephemeral", gjson.GetBytes(out, "system.0.cache_control.type").String())
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_NonNativeInjectsSystemReminder(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","system":"Project instructions","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	systemRaw, ok := parsed.SystemValue()
	require.True(t, ok)
	c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", "client-sdk/9.9")
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true)

	out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), body, systemRaw, "claude-sonnet-4-6", parsed,
	)

	require.NoError(t, err)
	require.True(t, gjson.GetBytes(out, "system").IsArray())
	require.Len(t, gjson.GetBytes(out, "system").Array(), 3)
	require.Contains(t, gjson.GetBytes(out, "system.0.text").String(), "x-anthropic-billing-header:")
	require.Equal(t, claudeCodeSystemPrompt, gjson.GetBytes(out, "system.1.text").String())
	firstUserText := gjson.GetBytes(out, "messages.0.content.0.text").String()
	require.Equal(t, "<system-reminder>Project instructions</system-reminder>\n\nhello", firstUserText)
	require.Equal(t, 1, strings.Count(firstUserText, "<system-reminder>"))
	require.NotContains(t, string(out), "[System Instructions]")
	require.NotContains(t, string(out), "Understood. I will follow these instructions.")
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_NonNativeHaikuInjectsSystemReminder(t *testing.T) {
	body := []byte(`{"model":"claude-3-5-haiku-20241022","system":"Project instructions","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	systemRaw, ok := parsed.SystemValue()
	require.True(t, ok)
	c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", "client-sdk/9.9")
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true)

	out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), body, systemRaw, "claude-3-5-haiku-20241022", parsed,
	)

	require.NoError(t, err)
	require.True(t, gjson.GetBytes(out, "system").IsArray())
	firstUserText := gjson.GetBytes(out, "messages.0.content.0.text").String()
	require.Equal(t, "<system-reminder>Project instructions</system-reminder>\n\nhello", firstUserText)
	require.Equal(t, 1, strings.Count(firstUserText, "<system-reminder>"))
	require.NotContains(t, string(out), "[System Instructions]")
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_ReminderIdempotentForRepeatedTransform(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","system":"Project instructions","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", "client-sdk/9.9")
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	systemRaw, ok := parsed.SystemValue()
	require.True(t, ok)

	first, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), body, systemRaw, "claude-sonnet-4-6", parsed,
	)
	require.NoError(t, err)
	parsedAgain := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, first, 77)
	systemAgain, ok := parsedAgain.SystemValue()
	require.True(t, ok)
	cAgain, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	cAgain.Request.Header.Set("User-Agent", "client-sdk/9.9")
	cAgain.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)

	second, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), cAgain, newClaudeCodeAPIKeyImpersonationAccountForTest(true), first, systemAgain, "claude-sonnet-4-6", parsedAgain,
	)

	require.NoError(t, err)
	firstUserText := gjson.GetBytes(second, "messages.0.content.0.text").String()
	require.Equal(t, "<system-reminder>Project instructions</system-reminder>\n\nhello", firstUserText)
	require.Equal(t, 1, strings.Count(firstUserText, "<system-reminder>"))
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_ExistingReminderInputDoesNotDuplicate(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","system":"Project instructions","messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>Existing</system-reminder>\n\nhello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	systemRaw, ok := parsed.SystemValue()
	require.True(t, ok)
	c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", "client-sdk/9.9")
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true)

	out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), body, systemRaw, "claude-sonnet-4-6", parsed,
	)

	require.NoError(t, err)
	firstUserText := gjson.GetBytes(out, "messages.0.content.0.text").String()
	require.Equal(t, "<system-reminder>Existing</system-reminder>\n\nhello", firstUserText)
	require.Equal(t, 1, strings.Count(firstUserText, "<system-reminder>"))
	require.NotContains(t, firstUserText, "Project instructions")
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_DisabledSkipsSystemReminderInjection(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","system":"Project instructions","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	svc := &GatewayService{}

	out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), nil, newClaudeCodeAPIKeyImpersonationAccountForTest(false), body, "Project instructions", "claude-sonnet-4-6", nil,
	)

	require.NoError(t, err)
	require.Equal(t, string(body), string(out))
	require.NotContains(t, string(out), "<system-reminder>")
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_MetadataIdentityStableAcrossServiceInstances(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	account := newClaudeCodeAPIKeyImpersonationAccountForTest(true)

	run := func() *ParsedUserID {
		c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
		c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
		c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)
		svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true)
		out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
			context.Background(), c, account, body, nil, "claude-sonnet-4-6", parsed,
		)
		require.NoError(t, err)
		return requireClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t, gjson.GetBytes(out, "metadata.user_id").String(), ClaudeCodeSessionIDInput{APIKeyID: 77, Headers: c.Request.Header, Body: body})
	}

	first := run()
	second := run()
	require.Equal(t, first.DeviceID, second.DeviceID)
	require.Equal(t, first.AccountUUID, second.AccountUUID)
	require.Equal(t, first.SessionID, second.SessionID)
	require.NotEqual(t, claudeCodeAPIKeyImpersonationSessionIDForTest, first.SessionID)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_MetadataIdentityStableAfterCredentialRotation(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	account := newClaudeCodeAPIKeyImpersonationAccountForTest(true)

	run := func() *ParsedUserID {
		c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
		c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
		c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)
		svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true)
		out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
			context.Background(), c, account, body, nil, "claude-sonnet-4-6", parsed,
		)
		require.NoError(t, err)
		return requireClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t, gjson.GetBytes(out, "metadata.user_id").String(), ClaudeCodeSessionIDInput{APIKeyID: 77, Headers: c.Request.Header, Body: body})
	}

	before := run()
	account.Credentials["api_key"] = "rotated-upstream-key-marker"
	after := run()
	require.Equal(t, before.DeviceID, after.DeviceID)
	require.Equal(t, before.AccountUUID, after.AccountUUID)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_BodyExplicitValuesPreserved(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","max_tokens":2048,"thinking":{"type":"enabled","budget_tokens":1500},"context_management":{"edits":[{"type":"custom_strategy","keep":"none"}]},"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)

	out := applyClaudeCodeAPIKeyImpersonationBodyForTest(t, body, "claude-sonnet-4-6", nil, parsed)

	require.Equal(t, int64(2048), gjson.GetBytes(out, "max_tokens").Int())
	require.Equal(t, "enabled", gjson.GetBytes(out, "thinking.type").String())
	require.Equal(t, int64(1500), gjson.GetBytes(out, "thinking.budget_tokens").Int())
	require.Equal(t, "custom_strategy", gjson.GetBytes(out, "context_management.edits.0.type").String())
	require.Equal(t, "none", gjson.GetBytes(out, "context_management.edits.0.keep").String())
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_BodyDisabledPreservesOriginalDefaults(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	svc := &GatewayService{}

	out, err := svc.applyClaudeCodeAPIKeyImpersonationToBody(
		context.Background(), nil, newClaudeCodeAPIKeyImpersonationAccountForTest(false), body, nil, "claude-sonnet-4-6", nil,
	)

	require.NoError(t, err)
	require.Equal(t, string(body), string(out))
	require.False(t, gjson.GetBytes(out, "tools").Exists())
	require.False(t, gjson.GetBytes(out, "thinking").Exists())
	require.False(t, gjson.GetBytes(out, "max_tokens").Exists())
	require.False(t, gjson.GetBytes(out, "context_management").Exists())
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_DefaultsFilledAfterResponsesConversion(t *testing.T) {
	responsesBody := []byte(`{"model":"claude-sonnet-4-6","input":[{"role":"user","content":"hello"}]}`)
	convertedBody, systemRaw := anthropicBodyFromResponsesBodyForTest(t, responsesBody)
	require.Equal(t, int64(8192), gjson.GetBytes(convertedBody, "max_tokens").Int())
	parsed := parseClaudeCodeAPIKeyImpersonationProtocolBodyForTest(t, responsesBody, "responses", 77)

	out := applyClaudeCodeAPIKeyImpersonationBodyForTest(t, convertedBody, "claude-sonnet-4-6", systemRaw, parsed)

	assertClaudeCodeAPIKeyImpersonationDefaultsFilled(t, out)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_DefaultsFilledAfterChatCompletionsConversion(t *testing.T) {
	chatBody := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}]}`)
	convertedBody, systemRaw := anthropicBodyFromChatCompletionsBodyForTest(t, chatBody)
	require.Equal(t, int64(8192), gjson.GetBytes(convertedBody, "max_tokens").Int())
	parsed := parseClaudeCodeAPIKeyImpersonationProtocolBodyForTest(t, chatBody, "chat_completions", 77)

	out := applyClaudeCodeAPIKeyImpersonationBodyForTest(t, convertedBody, "claude-sonnet-4-6", systemRaw, parsed)

	assertClaudeCodeAPIKeyImpersonationDefaultsFilled(t, out)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_ResponsesExplicitValuesPreserved(t *testing.T) {
	responsesBody := []byte(`{"model":"claude-sonnet-4-6","max_output_tokens":2048,"reasoning":{"effort":"low"},"input":[{"role":"user","content":"hello"}]}`)
	convertedBody, systemRaw := anthropicBodyFromResponsesBodyForTest(t, responsesBody)
	parsed := parseClaudeCodeAPIKeyImpersonationProtocolBodyForTest(t, responsesBody, "responses", 77)

	out := applyClaudeCodeAPIKeyImpersonationBodyForTest(t, convertedBody, "claude-sonnet-4-6", systemRaw, parsed)

	require.Equal(t, int64(2048), gjson.GetBytes(out, "max_tokens").Int())
	require.Equal(t, "low", gjson.GetBytes(out, "output_config.effort").String())
	require.False(t, gjson.GetBytes(out, "thinking").Exists())
	require.False(t, gjson.GetBytes(out, "context_management").Exists())
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_EnabledForwardMimicsClaudeCodeAndPreservesAPIKey(t *testing.T) {
	c, rec := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
	addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c)
	c.Request.Header.Set("Anthropic-Beta", "client-beta")
	c.Request.Header.Set("X-Stainless-Lang", "python")
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)

	body := []byte(`{"model":"claude-3-7-sonnet-20250219","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	upstream := &anthropicHTTPUpstreamRecorder{resp: successfulAnthropicMessageResponseForImpersonationTest()}
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream, true)

	result, err := svc.Forward(context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), parsed)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, upstream.lastReq)

	require.Equal(t, "https://api.anthropic.com/v1/messages?beta=true", upstream.lastReq.URL.String())
	require.Equal(t, claudeCodeAPIKeyImpersonationSensitiveUpstreamKeyForTest, getHeaderRaw(upstream.lastReq.Header, "x-api-key"))
	require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "authorization"))
	require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "cookie"))
	require.Equal(t, claude.DefaultHeaders["User-Agent"], getHeaderRaw(upstream.lastReq.Header, "User-Agent"))
	require.Equal(t, claude.DefaultHeaders["X-Stainless-Lang"], getHeaderRaw(upstream.lastReq.Header, "X-Stainless-Lang"))
	require.Equal(t, claude.DefaultHeaders["X-Stainless-OS"], getHeaderRaw(upstream.lastReq.Header, "X-Stainless-OS"))
	require.Equal(t, claude.DefaultHeaders["X-Stainless-Runtime"], getHeaderRaw(upstream.lastReq.Header, "X-Stainless-Runtime"))
	require.Equal(t, claude.DefaultHeaders["X-App"], getHeaderRaw(upstream.lastReq.Header, "x-app"))
	require.NotEmpty(t, getHeaderRaw(upstream.lastReq.Header, "x-client-request-id"))
	require.Equal(t, claudeCodeAPIKeyImpersonationSessionIDForTest, getHeaderRaw(upstream.lastReq.Header, "X-Claude-Code-Session-Id"))
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "X-Stainless-OS")
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "X-Stainless-Runtime")
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "X-Stainless-Runtime-Version")
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "x-app")
	requireHeaderKeyPresentExactly(t, upstream.lastReq.Header, "x-client-request-id")

	beta := getHeaderRaw(upstream.lastReq.Header, "anthropic-beta")
	require.Contains(t, beta, claude.BetaClaudeCode)
	require.Contains(t, beta, claude.BetaOAuth)
	require.Contains(t, beta, claude.BetaContextManagement)
	require.NotContains(t, beta, "client-beta")

	require.Equal(t, "claude-3-opus-20240229", gjson.GetBytes(upstream.lastBody, "model").String())
	metadataUserID := gjson.GetBytes(upstream.lastBody, "metadata.user_id").String()
	metadata := requireClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t, metadataUserID, ClaudeCodeSessionIDInput{APIKeyID: parsed.SessionContext.APIKeyID, Headers: c.Request.Header, Body: body})
	require.NotEqual(t, getHeaderRaw(upstream.lastReq.Header, "X-Claude-Code-Session-Id"), metadata.SessionID)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_EnabledUpstreamForwardStillMimicsClaudeCodeAndPreservesAPIKey(t *testing.T) {
	c, rec := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
	addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c)
	c.Request.Header.Set("Anthropic-Beta", "client-beta")
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)

	body := []byte(`{"model":"claude-3-7-sonnet-20250219","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	upstream := &anthropicHTTPUpstreamRecorder{resp: successfulAnthropicMessageResponseForImpersonationTest()}
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream, true)
	account := newClaudeCodeAPIKeyImpersonationAccountForTestWithType(true, AccountTypeUpstream)
	wantMetadataSessionID := mustResolveClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t, c.Request.Header, body, parsed.SessionContext.APIKeyID)

	result, err := svc.Forward(context.Background(), c, account, parsed)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, http.StatusOK, rec.Code)
	assertClaudeCodeAPIKeyImpersonationUpstreamMimicForTest(t, upstream, claudeCodeAPIKeyImpersonationSessionIDForTest, wantMetadataSessionID)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_ForwardStreamMatrixMimicsAndPreservesAPIKey(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stream     bool
		upstreamFn func() *http.Response
	}{
		{name: "stream_false", stream: false, upstreamFn: successfulAnthropicMessageResponseForImpersonationTest},
		{name: "stream_true", stream: true, upstreamFn: successfulAnthropicMessageStreamResponseForImpersonationTest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
			c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
			addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c)
			c.Request.Header.Set("Anthropic-Beta", "client-beta")
			c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)

			streamLiteral := "false"
			if tc.stream {
				streamLiteral = "true"
			}
			body := []byte(`{"model":"claude-3-7-sonnet-20250219","stream":` + streamLiteral + `,"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
			parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
			require.Equal(t, tc.stream, parsed.Stream)
			upstream := &anthropicHTTPUpstreamRecorder{resp: tc.upstreamFn()}
			svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream, true)
			wantMetadataSessionID := mustResolveClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t, c.Request.Header, body, parsed.SessionContext.APIKeyID)

			result, err := svc.Forward(context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), parsed)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, tc.stream, result.Stream)
			assertClaudeCodeAPIKeyImpersonationUpstreamMimicForTest(t, upstream, claudeCodeAPIKeyImpersonationSessionIDForTest, wantMetadataSessionID)
			require.Equal(t, "claude-3-opus-20240229", gjson.GetBytes(upstream.lastBody, "model").String())
			require.Equal(t, tc.stream, gjson.GetBytes(upstream.lastBody, "stream").Bool())
			assertClaudeCodeAPIKeyImpersonationDefaultsFilled(t, upstream.lastBody)
		})
	}
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_ForwardAPIShapeMatrixMimicsAndPreservesAPIKey(t *testing.T) {
	for _, tc := range []struct {
		name       string
		protocol   string
		target     string
		body       []byte
		stream     bool
		assertBody func(*testing.T, []byte)
	}{
		{
			name:     "responses_stream_false_defaults",
			protocol: "responses",
			target:   "/v1/responses",
			body:     []byte(`{"model":"claude-3-7-sonnet-20250219","stream":false,"input":[{"role":"user","content":"hello"}]}`),
			stream:   false,
			assertBody: func(t *testing.T, body []byte) {
				assertClaudeCodeAPIKeyImpersonationDefaultsFilled(t, body)
			},
		},
		{
			name:     "responses_stream_true_explicit",
			protocol: "responses",
			target:   "/v1/responses",
			body:     []byte(`{"model":"claude-3-7-sonnet-20250219","stream":true,"max_output_tokens":2048,"reasoning":{"effort":"low"},"input":[{"role":"user","content":"hello"}]}`),
			stream:   true,
			assertBody: func(t *testing.T, body []byte) {
				assertClaudeCodeAPIKeyImpersonationExplicitReasoningPreservedForTest(t, body)
			},
		},
		{
			name:     "chat_completions_stream_false_defaults",
			protocol: "chat_completions",
			target:   "/v1/chat/completions",
			body:     []byte(`{"model":"claude-3-7-sonnet-20250219","stream":false,"messages":[{"role":"user","content":"hello"}]}`),
			stream:   false,
			assertBody: func(t *testing.T, body []byte) {
				assertClaudeCodeAPIKeyImpersonationDefaultsFilled(t, body)
			},
		},
		{
			name:     "chat_completions_stream_true_explicit",
			protocol: "chat_completions",
			target:   "/v1/chat/completions",
			body:     []byte(`{"model":"claude-3-7-sonnet-20250219","stream":true,"max_completion_tokens":2048,"reasoning_effort":"low","messages":[{"role":"user","content":"hello"}]}`),
			stream:   true,
			assertBody: func(t *testing.T, body []byte) {
				assertClaudeCodeAPIKeyImpersonationExplicitReasoningPreservedForTest(t, body)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := newClaudeCodeAPIKeyImpersonationContextForTest(tc.target)
			c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
			addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c)
			c.Request.Header.Set("Anthropic-Beta", "client-beta")
			c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)

			parsed := parseClaudeCodeAPIKeyImpersonationProtocolBodyForTest(t, tc.body, tc.protocol, 77)
			require.Equal(t, tc.stream, parsed.Stream)
			upstream := &anthropicHTTPUpstreamRecorder{resp: successfulAnthropicMessageStreamResponseForImpersonationTest()}
			svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream, true)
			account := newClaudeCodeAPIKeyImpersonationAccountForTest(true)
			metadataBody := anthropicBodyForClaudeCodeAPIKeyImpersonationProtocolForTest(t, tc.body, tc.protocol)
			wantMetadataSessionID := mustResolveClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t, c.Request.Header, metadataBody, parsed.SessionContext.APIKeyID)

			var (
				result *ForwardResult
				err    error
			)
			switch tc.protocol {
			case "responses":
				result, err = svc.ForwardAsResponses(context.Background(), c, account, tc.body, parsed)
			case "chat_completions":
				result, err = svc.ForwardAsChatCompletions(context.Background(), c, account, tc.body, parsed)
			default:
				t.Fatalf("unsupported protocol %q", tc.protocol)
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, tc.stream, result.Stream)
			assertClaudeCodeAPIKeyImpersonationUpstreamMimicForTest(t, upstream, claudeCodeAPIKeyImpersonationSessionIDForTest, wantMetadataSessionID)
			require.Equal(t, "claude-3-opus-20240229", gjson.GetBytes(upstream.lastBody, "model").String())
			require.True(t, gjson.GetBytes(upstream.lastBody, "stream").Bool())
			tc.assertBody(t, upstream.lastBody)
		})
	}
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_GeneratesSessionIDWhenIncomingHeaderInvalid(t *testing.T) {
	c, rec := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
	addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c)
	c.Request.Header.Set("X-Claude-Code-Session-Id", "not-a-valid-session-id")
	c.Request.Header.Set("x-session-affinity", "workspace-alpha")

	body := []byte(`{"model":"claude-3-7-sonnet-20250219","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	expectedSession, ok := ResolveClaudeCodeSessionID(ClaudeCodeSessionIDInput{
		APIKeyID: parsed.SessionContext.APIKeyID,
		Headers:  c.Request.Header,
		Body:     body,
	})
	require.True(t, ok)
	require.False(t, expectedSession.Preserved)
	require.Equal(t, "header:x-session-affinity", expectedSession.Source)

	upstream := &anthropicHTTPUpstreamRecorder{resp: successfulAnthropicMessageResponseForImpersonationTest()}
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream, true)

	result, err := svc.Forward(context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), parsed)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, upstream.lastReq)

	generatedSessionID := expectedSession.SessionID
	require.Equal(t, generatedSessionID, getHeaderRaw(upstream.lastReq.Header, "X-Claude-Code-Session-Id"))
	require.NotEqual(t, "not-a-valid-session-id", getHeaderRaw(upstream.lastReq.Header, "X-Claude-Code-Session-Id"))
	require.Equal(t, claudeCodeAPIKeyImpersonationSensitiveUpstreamKeyForTest, getHeaderRaw(upstream.lastReq.Header, "x-api-key"))
	require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "authorization"))
	require.Equal(t, claude.DefaultHeaders["User-Agent"], getHeaderRaw(upstream.lastReq.Header, "User-Agent"))
	require.Equal(t, "adaptive", gjson.GetBytes(upstream.lastBody, "thinking.type").String())
	require.Equal(t, int64(claudeCodeAPIKeyImpersonationDefaultMaxTokens), gjson.GetBytes(upstream.lastBody, "max_tokens").Int())

	metadataUserID := gjson.GetBytes(upstream.lastBody, "metadata.user_id").String()
	metadata := requireClaudeCodeAPIKeyImpersonationMetadataSessionForTest(t, metadataUserID, ClaudeCodeSessionIDInput{APIKeyID: parsed.SessionContext.APIKeyID, Headers: c.Request.Header, Body: body})
	require.NotEqual(t, generatedSessionID, metadata.SessionID)
	require.NotEqual(t, "not-a-valid-session-id", metadata.SessionID)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_DisabledForwardKeepsAPIKeyPassthroughHeaders(t *testing.T) {
	c, rec := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", "client-sdk/9.9")
	addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c)
	c.Request.Header.Set("Anthropic-Beta", "client-beta")
	c.Request.Header.Set("X-Stainless-Lang", "python")
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)

	body := []byte(`{"model":"claude-3-7-sonnet-20250219","max_tokens":1024,"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	upstream := &anthropicHTTPUpstreamRecorder{resp: successfulAnthropicMessageResponseForImpersonationTest()}
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream, true)

	result, err := svc.Forward(context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(false), parsed)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, upstream.lastReq)

	require.Equal(t, claudeCodeAPIKeyImpersonationSensitiveUpstreamKeyForTest, getHeaderRaw(upstream.lastReq.Header, "x-api-key"))
	require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "authorization"))
	require.Equal(t, "client-sdk/9.9", getHeaderRaw(upstream.lastReq.Header, "User-Agent"))
	require.Equal(t, "python", getHeaderRaw(upstream.lastReq.Header, "X-Stainless-Lang"))
	require.Equal(t, "client-beta", getHeaderRaw(upstream.lastReq.Header, "anthropic-beta"))
	require.Equal(t, claudeCodeAPIKeyImpersonationSessionIDForTest, getHeaderRaw(upstream.lastReq.Header, "X-Claude-Code-Session-Id"))
	require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "x-app"))
	_, hasForcedOS := upstream.lastReq.Header["X-Stainless-OS"]
	require.False(t, hasForcedOS)
	_, hasForcedRuntime := upstream.lastReq.Header["X-Stainless-Runtime"]
	require.False(t, hasForcedRuntime)
	_, hasGeneratedRequestID := upstream.lastReq.Header["x-client-request-id"]
	require.False(t, hasGeneratedRequestID)
	require.False(t, gjson.GetBytes(upstream.lastBody, "metadata.user_id").Exists())
	require.False(t, gjson.GetBytes(upstream.lastBody, "tools").Exists())
	require.False(t, gjson.GetBytes(upstream.lastBody, "thinking").Exists())
	require.Equal(t, int64(1024), gjson.GetBytes(upstream.lastBody, "max_tokens").Int())
	require.False(t, gjson.GetBytes(upstream.lastBody, "context_management").Exists())
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_DisabledForwardDoesNotApplyCloakingBoundaries(t *testing.T) {
	c, rec := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", "client-sdk/9.9")
	addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c)
	c.Request.Header.Set("Anthropic-Beta", "client-beta")
	c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)

	body := []byte(`{"model":"claude-3-7-sonnet-20250219","max_tokens":1024,"system":"redacted-system-fixture","tools":[{"name":"bash","input_schema":{"type":"object"}}],"tool_choice":{"type":"tool","name":"bash"},"messages":[{"role":"user","content":[{"type":"text","text":"redacted-user-fixture"}]}]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 77)
	resp := successfulAnthropicMessageResponseForImpersonationTest()
	resp.Header.Set("X-Portkey-Trace-Id", "portkey")
	resp.Header.Set("Helicone-Id", "helicone")
	upstream := &anthropicHTTPUpstreamRecorder{resp: resp}
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream, true)
	svc.cfg.Security.ResponseHeaders = config.ResponseHeaderConfig{
		Enabled:           true,
		AdditionalAllowed: []string{"x-portkey-trace-id", "helicone-id"},
	}
	svc.responseHeaderFilter = compileResponseHeaderFilter(svc.cfg)

	result, err := svc.Forward(context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(false), parsed)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, upstream.lastReq)
	require.Nil(t, upstream.lastTLSProfile)
	require.False(t, shouldScrubClaudeCodeAPIKeyImpersonationGatewayHeaders(c))

	require.Equal(t, "client-sdk/9.9", getHeaderRaw(upstream.lastReq.Header, "User-Agent"))
	require.Equal(t, "client-beta", getHeaderRaw(upstream.lastReq.Header, "anthropic-beta"))
	require.Equal(t, claudeCodeAPIKeyImpersonationSessionIDForTest, getHeaderRaw(upstream.lastReq.Header, "X-Claude-Code-Session-Id"))
	require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "x-app"))
	require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "x-client-request-id"))

	require.False(t, gjson.GetBytes(upstream.lastBody, "metadata.user_id").Exists())
	require.Equal(t, "redacted-system-fixture", gjson.GetBytes(upstream.lastBody, "system").String())
	require.NotContains(t, string(upstream.lastBody), "<system-reminder>")
	require.NotContains(t, string(upstream.lastBody), "[System Instructions]")
	require.Equal(t, "bash", gjson.GetBytes(upstream.lastBody, "tools.0.name").String())
	require.Equal(t, "bash", gjson.GetBytes(upstream.lastBody, "tool_choice.name").String())
	require.NotContains(t, string(upstream.lastBody), `"name":"Bash"`)

	require.Equal(t, "portkey", rec.Header().Get("X-Portkey-Trace-Id"))
	require.Equal(t, "helicone", rec.Header().Get("Helicone-Id"))
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_DisabledForwardAsKeepsOpenAICompatiblePathsOrdinary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		target   string
		body     []byte
		forward  func(context.Context, *GatewayService, *gin.Context, *Account, []byte, *ParsedRequest) (*ForwardResult, error)
	}{
		{
			name:     "responses",
			protocol: "responses",
			target:   "/v1/responses",
			body:     []byte(`{"model":"claude-3-7-sonnet-20250219","stream":false,"input":[{"role":"user","content":"redacted-user-fixture"}]}`),
			forward: func(ctx context.Context, svc *GatewayService, c *gin.Context, account *Account, body []byte, parsed *ParsedRequest) (*ForwardResult, error) {
				return svc.ForwardAsResponses(ctx, c, account, body, parsed)
			},
		},
		{
			name:     "chat_completions",
			protocol: "chat_completions",
			target:   "/v1/chat/completions",
			body:     []byte(`{"model":"claude-3-7-sonnet-20250219","stream":false,"messages":[{"role":"user","content":"redacted-user-fixture"}]}`),
			forward: func(ctx context.Context, svc *GatewayService, c *gin.Context, account *Account, body []byte, parsed *ParsedRequest) (*ForwardResult, error) {
				return svc.ForwardAsChatCompletions(ctx, c, account, body, parsed)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := newClaudeCodeAPIKeyImpersonationContextForTest(tc.target)
			c.Request.Header.Set("User-Agent", "client-sdk/9.9")
			c.Request.Header.Set("Anthropic-Beta", "client-beta")
			parsed := parseClaudeCodeAPIKeyImpersonationProtocolBodyForTest(t, tc.body, tc.protocol, 77)
			upstream := &anthropicHTTPUpstreamRecorder{resp: successfulAnthropicMessageStreamResponseForImpersonationTest()}
			svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream, true)

			result, err := tc.forward(context.Background(), svc, c, newClaudeCodeAPIKeyImpersonationAccountForTest(false), tc.body, parsed)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, http.StatusOK, rec.Code)
			require.NotNil(t, upstream.lastReq)
			require.Nil(t, upstream.lastTLSProfile)
			require.False(t, shouldScrubClaudeCodeAPIKeyImpersonationGatewayHeaders(c))

			require.Equal(t, "client-sdk/9.9", getHeaderRaw(upstream.lastReq.Header, "User-Agent"))
			require.Equal(t, "client-beta", getHeaderRaw(upstream.lastReq.Header, "anthropic-beta"))
			require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "x-app"))
			require.Empty(t, getHeaderRaw(upstream.lastReq.Header, "x-client-request-id"))
			require.False(t, gjson.GetBytes(upstream.lastBody, "metadata.user_id").Exists())
			require.NotContains(t, string(upstream.lastBody), "<system-reminder>")
		})
	}
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_FailClosedWithoutResolvableSession(t *testing.T) {
	c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
	c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
	addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c)

	body := []byte(`{"model":"claude-3-7-sonnet-20250219","max_tokens":1024,"system":"` + claudeCodeAPIKeyImpersonationSensitiveBodyForTest + `","metadata":{"billing":{"cch":"` + claudeCodeAPIKeyImpersonationSensitiveSigningForTest + `"}},"messages":[]}`)
	parsed := parseClaudeCodeAPIKeyImpersonationBodyForTest(t, body, 0)
	upstream := &anthropicHTTPUpstreamRecorder{resp: successfulAnthropicMessageResponseForImpersonationTest()}
	svc := newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(upstream, true)

	result, err := svc.Forward(context.Background(), c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), parsed)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "claude code identity impersonation requires resolvable session id")
	requireClaudeCodeAPIKeyImpersonationErrorSanitized(t, err)
	require.Nil(t, upstream.lastReq)
}

func TestGatewayService_ClaudeCodeAPIKeyImpersonation_SanitizesFailClosedErrors(t *testing.T) {
	bodyWithSession := []byte(`{"model":"claude-3-7-sonnet-20250219","max_tokens":1024,"system":"` + claudeCodeAPIKeyImpersonationSensitiveBodyForTest + `","metadata":{"billing":{"cch":"` + claudeCodeAPIKeyImpersonationSensitiveSigningForTest + `"}},"messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`)
	bodyWithoutSessionHint := []byte(`{"model":"claude-3-7-sonnet-20250219","max_tokens":1024,"system":"` + claudeCodeAPIKeyImpersonationSensitiveBodyForTest + `","metadata":{"billing":{"cch":"` + claudeCodeAPIKeyImpersonationSensitiveSigningForTest + `"}},"messages":[]}`)

	newContext := func(withSession bool) *gin.Context {
		c, _ := newClaudeCodeAPIKeyImpersonationContextForTest("/v1/messages")
		c.Request.Header.Set("User-Agent", claude.DefaultHeaders["User-Agent"])
		addSensitiveHeadersForClaudeCodeAPIKeyImpersonationTest(c)
		if withSession {
			c.Request.Header.Set("X-Claude-Code-Session-Id", claudeCodeAPIKeyImpersonationSessionIDForTest)
		}
		return c
	}

	tests := []struct {
		name   string
		svc    *GatewayService
		c      *gin.Context
		body   []byte
		parsed *ParsedRequest
		want   string
	}{
		{
			name:   "missing request body",
			svc:    newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true),
			c:      newContext(true),
			body:   nil,
			parsed: parseClaudeCodeAPIKeyImpersonationBodyForTest(t, bodyWithSession, 77),
			want:   "claude code identity impersonation requires request body",
		},
		{
			name:   "missing request context",
			svc:    newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true),
			c:      nil,
			body:   bodyWithSession,
			parsed: parseClaudeCodeAPIKeyImpersonationBodyForTest(t, bodyWithSession, 77),
			want:   "claude code identity impersonation requires request context",
		},
		{
			name:   "missing identity service",
			svc:    newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, false),
			c:      newContext(true),
			body:   bodyWithSession,
			parsed: parseClaudeCodeAPIKeyImpersonationBodyForTest(t, bodyWithSession, 77),
			want:   "claude code identity impersonation requires identity service",
		},
		{
			name:   "unresolvable session id",
			svc:    newClaudeCodeAPIKeyImpersonationGatewayServiceForTest(nil, true),
			c:      newContext(false),
			body:   bodyWithoutSessionHint,
			parsed: parseClaudeCodeAPIKeyImpersonationBodyForTest(t, bodyWithoutSessionHint, 0),
			want:   "claude code identity impersonation requires resolvable session id",
		},
		{
			name: "missing fingerprint client id",
			svc: &GatewayService{
				identityService: NewIdentityService(&claudeCodeAPIKeyImpersonationFingerprintlessCacheStub{}),
			},
			c:      newContext(true),
			body:   bodyWithSession,
			parsed: parseClaudeCodeAPIKeyImpersonationBodyForTest(t, bodyWithSession, 77),
			want:   "claude code identity impersonation requires fingerprint client id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.svc.applyClaudeCodeAPIKeyImpersonationToBody(
				context.Background(), tt.c, newClaudeCodeAPIKeyImpersonationAccountForTest(true), tt.body, nil, "claude-3-7-sonnet-20250219", tt.parsed,
			)
			require.Nil(t, out)
			requireClaudeCodeAPIKeyImpersonationErrorSanitized(t, err)
			require.Contains(t, err.Error(), tt.want)
		})
	}
}
