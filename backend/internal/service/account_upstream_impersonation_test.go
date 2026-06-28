package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClaudeCodeIdentityImpersonationAccount(t *testing.T) {
	t.Run("nil account defaults false", func(t *testing.T) {
		var account *Account
		require.False(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("missing extra defaults false", func(t *testing.T) {
		account := &Account{Platform: PlatformAnthropic, Type: AccountTypeAPIKey}
		require.False(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("empty extra defaults false", func(t *testing.T) {
		account := &Account{Platform: PlatformAnthropic, Type: AccountTypeAPIKey, Extra: map[string]any{}}
		require.False(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("existing api key account without flag defaults false", func(t *testing.T) {
		// Historical Anthropic API Key/upstream credential accounts stay default off until an administrator enables the account-level switch.
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeAPIKey,
			Extra:    map[string]any{"note": "legacy-account"},
		}
		require.False(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("nil flag value defaults false", func(t *testing.T) {
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeAPIKey,
			Extra: map[string]any{
				"claude_code_identity_impersonation_enabled": nil,
			},
		}
		require.False(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("explicit false stays false", func(t *testing.T) {
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeAPIKey,
			Extra: map[string]any{
				"claude_code_identity_impersonation_enabled": false,
			},
		}
		require.False(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("anthropic api key explicit true enables impersonation", func(t *testing.T) {
		// Enabled API-key impersonation reuses OAuth mimicry behavior, but upstream auth still stays on x-api-key.
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeAPIKey,
			Extra: map[string]any{
				"claude_code_identity_impersonation_enabled": true,
			},
		}
		require.True(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("anthropic upstream explicit true still enables impersonation", func(t *testing.T) {
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeUpstream,
			Extra: map[string]any{
				"claude_code_identity_impersonation_enabled": true,
			},
		}
		require.True(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("malformed non-bool defaults false", func(t *testing.T) {
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeAPIKey,
			Extra: map[string]any{
				"claude_code_identity_impersonation_enabled": "true",
			},
		}
		require.False(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("non-anthropic api key account stays false", func(t *testing.T) {
		account := &Account{
			Platform: PlatformOpenAI,
			Type:     AccountTypeAPIKey,
			Extra: map[string]any{
				"claude_code_identity_impersonation_enabled": true,
			},
		}
		require.False(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})

	t.Run("anthropic oauth account stays false", func(t *testing.T) {
		account := &Account{
			Platform: PlatformAnthropic,
			Type:     AccountTypeOAuth,
			Extra: map[string]any{
				"claude_code_identity_impersonation_enabled": true,
			},
		}
		require.False(t, account.IsClaudeCodeIdentityImpersonationEnabled())
	})
}
