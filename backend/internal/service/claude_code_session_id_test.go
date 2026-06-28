//go:build unit

package service

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func mustResolveClaudeCodeSessionID(t *testing.T, input ClaudeCodeSessionIDInput) ClaudeCodeSessionIDResult {
	t.Helper()
	result, ok := ResolveClaudeCodeSessionID(input)
	require.True(t, ok)
	require.NotEmpty(t, result.SessionID)
	_, err := uuid.Parse(result.SessionID)
	require.NoError(t, err)
	return result
}

func mustResolveClaudeCodeMetadataSessionID(t *testing.T, input ClaudeCodeSessionIDInput) ClaudeCodeSessionIDResult {
	t.Helper()
	result, ok := ResolveClaudeCodeMetadataSessionID(input)
	require.True(t, ok)
	require.NotEmpty(t, result.SessionID)
	_, err := uuid.Parse(result.SessionID)
	require.NoError(t, err)
	return result
}

func TestResolveClaudeCodeSessionID_SameAPIKeyAndHintStable(t *testing.T) {
	headers := http.Header{}
	headers.Set("x-session-affinity", "workspace-alpha")
	input := ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headers}

	first := mustResolveClaudeCodeSessionID(t, input)
	second := mustResolveClaudeCodeSessionID(t, input)

	require.Equal(t, first.SessionID, second.SessionID)
	require.False(t, first.Preserved)
}

func TestResolveClaudeCodeSessionID_DifferentAPIKeyChangesID(t *testing.T) {
	headers := http.Header{}
	headers.Set("x-session-affinity", "workspace-alpha")

	first := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headers})
	second := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 202, Headers: headers})

	require.NotEqual(t, first.SessionID, second.SessionID)
}

func TestResolveClaudeCodeSessionID_DifferentHintChangesID(t *testing.T) {
	firstHeaders := http.Header{}
	firstHeaders.Set("x-session-affinity", "workspace-alpha")
	secondHeaders := http.Header{}
	secondHeaders.Set("x-session-affinity", "workspace-beta")

	first := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: firstHeaders})
	second := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: secondHeaders})

	require.NotEqual(t, first.SessionID, second.SessionID)
}

func TestResolveClaudeCodeSessionID_PreservesValidIncomingHeader(t *testing.T) {
	const incoming = "4b444cc2-915c-43a9-aada-4c616de32e6e"
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", incoming)
	headers.Set("x-session-affinity", "ignored-affinity")

	result := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headers})

	require.Equal(t, incoming, result.SessionID)
	require.True(t, result.Preserved)
	require.Equal(t, claudeCodeSessionHeader, result.Source)
}

func TestResolveClaudeCodeSessionID_FirstApprovedHeaderHintWins(t *testing.T) {
	headers := http.Header{}
	headers.Set("x-session-affinity", "affinity-wins")
	headers.Set("X-Session-ID", "session-id-loses")
	affinityOnly := http.Header{}
	affinityOnly.Set("x-session-affinity", "affinity-wins")
	sessionOnly := http.Header{}
	sessionOnly.Set("X-Session-ID", "session-id-loses")

	combined := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headers})
	first := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: affinityOnly})
	second := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: sessionOnly})

	require.Equal(t, first.SessionID, combined.SessionID)
	require.NotEqual(t, second.SessionID, combined.SessionID)
}

func TestResolveClaudeCodeSessionID_UsesRawWireCasingHint(t *testing.T) {
	headers := http.Header{"x-client-request-id": []string{"client-request-1"}}

	result := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headers})

	require.Equal(t, "header:x-client-request-id", result.Source)
}

func TestResolveClaudeCodeSessionID_MessageFallbackStableFromFirstMessages(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"one"},{"role":"assistant","content":"two"},{"role":"user","content":"three"},{"role":"assistant","content":"four"},{"role":"user","content":"tail-a"}]}`)
	bodyWithDifferentTail := []byte(`{"messages":[{"role":"user","content":"one"},{"role":"assistant","content":"two"},{"role":"user","content":"three"},{"role":"assistant","content":"four"},{"role":"user","content":"tail-b"}]}`)
	bodyWithDifferentFirstHint := []byte(`{"messages":[{"role":"user","content":"changed"},{"role":"assistant","content":"two"},{"role":"user","content":"three"},{"role":"assistant","content":"four"},{"role":"user","content":"tail-a"}]}`)

	first := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Body: body})
	second := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Body: bodyWithDifferentTail})
	third := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Body: bodyWithDifferentFirstHint})

	require.Equal(t, first.SessionID, second.SessionID)
	require.NotEqual(t, first.SessionID, third.SessionID)
	require.Equal(t, "body:messages_sha256", first.Source)
}

func TestResolveClaudeCodeSessionID_DoesNotExposeRawHintOrBody(t *testing.T) {
	const rawHint = "sensitive-affinity-value"
	const rawBodyText = "sensitive-message-content"
	headers := http.Header{}
	headers.Set("x-session-affinity", rawHint)
	body := []byte(`{"messages":[{"role":"user","content":"` + rawBodyText + `"}]}`)

	result := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headers, Body: body})

	require.NotContains(t, result.SessionID, rawHint)
	require.NotContains(t, result.SessionID, rawBodyText)
}

func TestResolveClaudeCodeMetadataSessionID_IgnoresIncomingClaudeHeader(t *testing.T) {
	const incoming = "4b444cc2-915c-43a9-aada-4c616de32e6e"
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", incoming)
	headers.Set("x-session-affinity", "workspace-alpha")

	metadata := mustResolveClaudeCodeMetadataSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headers})
	outbound := mustResolveClaudeCodeSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headers})

	require.Equal(t, incoming, outbound.SessionID)
	require.True(t, outbound.Preserved)
	require.Equal(t, "header:x-session-affinity", metadata.Source)
	require.False(t, metadata.Preserved)
	require.NotEqual(t, outbound.SessionID, metadata.SessionID)
}

func TestResolveClaudeCodeMetadataSessionID_SelectedHintStableAndChanges(t *testing.T) {
	firstHeaders := http.Header{}
	firstHeaders.Set("x-session-affinity", "workspace-alpha")
	secondHeaders := http.Header{}
	secondHeaders.Set("x-session-affinity", "workspace-beta")

	first := mustResolveClaudeCodeMetadataSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: firstHeaders})
	second := mustResolveClaudeCodeMetadataSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: firstHeaders})
	third := mustResolveClaudeCodeMetadataSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: secondHeaders})

	require.Equal(t, first.SessionID, second.SessionID)
	require.NotEqual(t, first.SessionID, third.SessionID)
}

func TestResolveClaudeCodeMetadataSessionID_PriorityOrder(t *testing.T) {
	const existingMetadataUserID = `{"device_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","account_uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","session_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}`
	bodyWithConversation := []byte(`{"conversation_id":"body-conversation","session_id":"body-session","metadata":{"user_id":` + strconv.Quote(existingMetadataUserID) + `},"messages":[{"role":"user","content":"first user"}]}`)
	bodyWithSession := []byte(`{"session_id":"body-session","metadata":{"user_id":` + strconv.Quote(existingMetadataUserID) + `},"messages":[{"role":"user","content":"first user"}]}`)
	bodyWithSessionCasing := []byte(`{"Session_id":"body-session-cased","metadata":{"user_id":` + strconv.Quote(existingMetadataUserID) + `},"messages":[{"role":"user","content":"first user"}]}`)
	bodyWithMetadata := []byte(`{"metadata":{"user_id":` + strconv.Quote(existingMetadataUserID) + `},"messages":[{"role":"user","content":"first user"}]}`)
	bodyWithFirstUser := []byte(`{"messages":[{"role":"assistant","content":"ignored"},{"role":"user","content":[{"type":"text","text":"first user"}]}]}`)

	allHeaders := http.Header{}
	allHeaders.Set("x-session-affinity", "affinity")
	allHeaders.Set("X-Session-ID", "session-header")
	allHeaders.Set("Session_id", "session-underscore")
	allHeaders.Set("X-Client-Request-Id", "client-request")
	allHeaders.Set("conversation_id", "conversation-header")

	tests := []struct {
		name       string
		headers    http.Header
		body       []byte
		selected   ClaudeCodeSessionIDInput
		wantSource string
	}{
		{
			name:       "x-session-affinity wins first",
			headers:    allHeaders,
			body:       bodyWithConversation,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: http.Header{"x-session-affinity": []string{"affinity"}}},
			wantSource: "header:x-session-affinity",
		},
		{
			name: "X-Session-ID wins after affinity",
			headers: http.Header{
				"X-Session-ID":        []string{"session-header"},
				"Session_id":          []string{"session-underscore"},
				"X-Client-Request-Id": []string{"client-request"},
				"conversation_id":     []string{"conversation-header"},
			},
			body:       bodyWithConversation,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: http.Header{"X-Session-ID": []string{"session-header"}}},
			wantSource: "header:x-session-id",
		},
		{
			name: "Session_id wins after X-Session-ID",
			headers: http.Header{
				"Session_id":          []string{"session-underscore"},
				"X-Client-Request-Id": []string{"client-request"},
				"conversation_id":     []string{"conversation-header"},
			},
			body:       bodyWithConversation,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: http.Header{"Session_id": []string{"session-underscore"}}},
			wantSource: "header:session_id",
		},
		{
			name: "X-Client-Request-Id wins after Session_id",
			headers: http.Header{
				"X-Client-Request-Id": []string{"client-request"},
				"conversation_id":     []string{"conversation-header"},
			},
			body:       bodyWithConversation,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: http.Header{"X-Client-Request-Id": []string{"client-request"}}},
			wantSource: "header:x-client-request-id",
		},
		{
			name:       "conversation_id header wins after client request",
			headers:    http.Header{"conversation_id": []string{"conversation-header"}},
			body:       bodyWithConversation,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: http.Header{"conversation_id": []string{"conversation-header"}}},
			wantSource: "header:conversation_id",
		},
		{
			name:       "body conversation_id wins before body session hints",
			body:       bodyWithConversation,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Body: []byte(`{"conversation_id":"body-conversation"}`)},
			wantSource: "body:conversation_id",
		},
		{
			name:       "body session_id wins before metadata user id",
			body:       bodyWithSession,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Body: []byte(`{"session_id":"body-session"}`)},
			wantSource: "body:session_id",
		},
		{
			name:       "body Session_id casing is considered",
			body:       bodyWithSessionCasing,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Body: []byte(`{"Session_id":"body-session-cased"}`)},
			wantSource: "body:session_id",
		},
		{
			name:       "metadata user id session wins before first user",
			body:       bodyWithMetadata,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Body: []byte(`{"metadata":{"user_id":` + strconv.Quote(existingMetadataUserID) + `}}`)},
			wantSource: "body:metadata.user_id.session_id",
		},
		{
			name:       "first user content is final fallback",
			body:       bodyWithFirstUser,
			selected:   ClaudeCodeSessionIDInput{APIKeyID: 101, Body: bodyWithFirstUser},
			wantSource: "body:first_user_text_sha256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			combined := mustResolveClaudeCodeMetadataSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: tt.headers, Body: tt.body})
			selected := mustResolveClaudeCodeMetadataSessionID(t, tt.selected)

			require.Equal(t, tt.wantSource, combined.Source)
			require.Equal(t, selected.SessionID, combined.SessionID)
		})
	}
}

func TestResolveClaudeCodeMetadataSessionID_MalformedIncomingClaudeHeaderDoesNotPoisonDerivation(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"first user"}]}`)
	headers := http.Header{}
	headers.Set("X-Claude-Code-Session-Id", "not-a-valid-session-id")
	headers.Set("X-Client-Request-Id", "client-request-1")
	headersWithoutMalformed := http.Header{}
	headersWithoutMalformed.Set("X-Client-Request-Id", "client-request-1")

	withMalformed := mustResolveClaudeCodeMetadataSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headers, Body: body})
	withoutMalformed := mustResolveClaudeCodeMetadataSessionID(t, ClaudeCodeSessionIDInput{APIKeyID: 101, Headers: headersWithoutMalformed, Body: body})

	require.Equal(t, "header:x-client-request-id", withMalformed.Source)
	require.Equal(t, withoutMalformed.SessionID, withMalformed.SessionID)
	require.NotEqual(t, "not-a-valid-session-id", withMalformed.SessionID)
}
