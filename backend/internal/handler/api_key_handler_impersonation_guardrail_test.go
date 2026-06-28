package handler

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyImpersonationGuardrails_UserDTOAndPayloadsStaySwitchFree(t *testing.T) {
	t.Run("user request payloads do not accept impersonation switch", func(t *testing.T) {
		createType := reflect.TypeFor[CreateAPIKeyRequest]()
		_, hasCreateField := createType.FieldByName("ClaudeCodeIdentityImpersonationEnabled")
		require.False(t, hasCreateField)

		updateType := reflect.TypeFor[UpdateAPIKeyRequest]()
		_, hasUpdateField := updateType.FieldByName("ClaudeCodeIdentityImpersonationEnabled")
		require.False(t, hasUpdateField)
	})

	t.Run("user api key dto does not expose impersonation switch", func(t *testing.T) {
		dtoType := reflect.TypeFor[dto.APIKey]()
		_, hasDTOField := dtoType.FieldByName("ClaudeCodeIdentityImpersonationEnabled")
		require.False(t, hasDTOField)

		raw, err := json.Marshal(dto.APIKeyFromService(&service.APIKey{ID: 1, UserID: 2, Name: "demo", Key: "user-key-placeholder"}))
		require.NoError(t, err)
		require.NotContains(t, string(raw), "claude_code_identity_impersonation_enabled")
	})
}
