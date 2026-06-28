package service

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

const (
	claudeCodeSessionHeader                = "X-Claude-Code-Session-Id"
	claudeCodeSessionDerivationKey         = "sub2api:claude-code-session-id:v1"
	claudeCodeMetadataSessionDerivationKey = "sub2api:claude-code-metadata-session-id:v1"
	claudeCodeSessionMessageHintMax        = 4
)

var claudeCodeSessionHeaderHints = []string{
	"x-session-affinity",
	"X-Session-ID",
	"Session_id",
	"X-Client-Request-Id",
	"conversation_id",
}

var claudeCodeMetadataSessionBodyHintPaths = []string{
	"conversation_id",
	"session_id",
	"Session_id",
	"metadata.conversation_id",
	"metadata.session_id",
}

type ClaudeCodeSessionIDInput struct {
	APIKeyID int64
	Headers  http.Header
	Body     []byte
}

type ClaudeCodeSessionIDResult struct {
	SessionID string
	Source    string
	Preserved bool
}

func ResolveClaudeCodeSessionID(input ClaudeCodeSessionIDInput) (ClaudeCodeSessionIDResult, bool) {
	if incoming := strings.TrimSpace(firstHeaderValue(input.Headers, claudeCodeSessionHeader)); validClaudeCodeSessionID(incoming) {
		return ClaudeCodeSessionIDResult{SessionID: incoming, Source: claudeCodeSessionHeader, Preserved: true}, true
	}

	if input.APIKeyID <= 0 {
		return ClaudeCodeSessionIDResult{}, false
	}

	hint, ok := firstClaudeCodeSessionHint(input.Headers, input.Body)
	if !ok {
		return ClaudeCodeSessionIDResult{}, false
	}

	return deriveClaudeCodeSessionID(input.APIKeyID, hint, claudeCodeSessionDerivationKey), true
}

func ResolveClaudeCodeMetadataSessionID(input ClaudeCodeSessionIDInput) (ClaudeCodeSessionIDResult, bool) {
	if input.APIKeyID <= 0 {
		return ClaudeCodeSessionIDResult{}, false
	}

	hint, ok := firstClaudeCodeMetadataSessionHint(input.Headers, input.Body)
	if !ok {
		return ClaudeCodeSessionIDResult{}, false
	}

	return deriveClaudeCodeSessionID(input.APIKeyID, hint, claudeCodeMetadataSessionDerivationKey), true
}

func deriveClaudeCodeSessionID(apiKeyID int64, hint claudeCodeSessionHint, key string) ClaudeCodeSessionIDResult {
	digest := hmac.New(sha256.New, []byte(key))
	_, _ = digest.Write([]byte("api_key_id"))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(strconv.FormatInt(apiKeyID, 10)))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(hint.Source))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(hint.Value))

	return ClaudeCodeSessionIDResult{
		SessionID: uuidFromDigest(digest.Sum(nil)),
		Source:    hint.Source,
	}
}

type claudeCodeSessionHint struct {
	Source string
	Value  string
}

func firstClaudeCodeSessionHint(headers http.Header, body []byte) (claudeCodeSessionHint, bool) {
	for _, name := range claudeCodeSessionHeaderHints {
		if value := strings.TrimSpace(firstHeaderValue(headers, name)); value != "" {
			return claudeCodeSessionHint{Source: "header:" + strings.ToLower(name), Value: value}, true
		}
	}

	if value := firstMessagesHash(body); value != "" {
		return claudeCodeSessionHint{Source: "body:messages_sha256", Value: value}, true
	}

	return claudeCodeSessionHint{}, false
}

func firstClaudeCodeMetadataSessionHint(headers http.Header, body []byte) (claudeCodeSessionHint, bool) {
	for _, name := range claudeCodeSessionHeaderHints {
		if value := strings.TrimSpace(firstHeaderValue(headers, name)); value != "" {
			return claudeCodeSessionHint{Source: "header:" + strings.ToLower(name), Value: value}, true
		}
	}

	for _, path := range claudeCodeMetadataSessionBodyHintPaths {
		if value := strings.TrimSpace(gjson.GetBytes(body, path).String()); value != "" {
			return claudeCodeSessionHint{Source: "body:" + strings.ToLower(path), Value: value}, true
		}
	}

	if uid := ParseMetadataUserID(gjson.GetBytes(body, "metadata.user_id").String()); uid != nil && strings.TrimSpace(uid.SessionID) != "" {
		return claudeCodeSessionHint{Source: "body:metadata.user_id.session_id", Value: uid.SessionID}, true
	}

	if value := firstUserTextHash(body); value != "" {
		return claudeCodeSessionHint{Source: "body:first_user_text_sha256", Value: value}, true
	}

	return claudeCodeSessionHint{}, false
}

func firstHeaderValue(headers http.Header, key string) string {
	if len(headers) == 0 || key == "" {
		return ""
	}
	if value := strings.TrimSpace(getHeaderRaw(headers, key)); value != "" {
		return value
	}
	for actual, values := range headers {
		if !strings.EqualFold(actual, key) {
			continue
		}
		for _, value := range values {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func validClaudeCodeSessionID(value string) bool {
	if len(value) != 36 {
		return false
	}
	_, err := uuid.Parse(value)
	return err == nil
}

func firstMessagesHash(body []byte) string {
	messages := gjson.GetBytes(body, "messages")
	if !messages.IsArray() {
		return ""
	}

	h := sha256.New()
	count := 0
	messages.ForEach(func(_, msg gjson.Result) bool {
		if count >= claudeCodeSessionMessageHintMax {
			return false
		}
		raw := []byte(msg.Raw)
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err == nil {
			raw = compact.Bytes()
		}
		_, _ = h.Write([]byte{byte(count), 0})
		_, _ = h.Write(raw)
		count++
		return true
	})
	if count == 0 {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func firstUserTextHash(body []byte) string {
	firstUserText := strings.TrimSpace(extractFirstUserText(body))
	if firstUserText == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(firstUserText))
	return hex.EncodeToString(hash[:])
}

func uuidFromDigest(digest []byte) string {
	var id uuid.UUID
	copy(id[:], digest)
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id.String()
}
