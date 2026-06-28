//go:build unit

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSFingerprintProfileService_ClaudeCodeImpersonationDoesNotSelectDefaultTLSProfile(t *testing.T) {
	svc := &TLSFingerprintProfileService{}

	for _, tc := range []struct {
		name    string
		account *Account
	}{
		{name: "nil account"},
		{
			name: "anthropic apikey impersonation enabled",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeAPIKey,
				Extra: map[string]any{
					"claude_code_identity_impersonation_enabled": true,
				},
			},
		},
		{
			name: "anthropic upstream impersonation enabled",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeUpstream,
				Extra: map[string]any{
					"claude_code_identity_impersonation_enabled": true,
				},
			},
		},
		{
			name: "apikey impersonation does not opt into tls fingerprint flag",
			account: &Account{
				Platform: PlatformAnthropic,
				Type:     AccountTypeAPIKey,
				Extra: map[string]any{
					"claude_code_identity_impersonation_enabled": true,
					"enable_tls_fingerprint":                     true,
				},
			},
		},
		{
			name: "non anthropic impersonation flag ignored",
			account: &Account{
				Platform: PlatformOpenAI,
				Type:     AccountTypeAPIKey,
				Extra: map[string]any{
					"claude_code_identity_impersonation_enabled": true,
					"enable_tls_fingerprint":                     true,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Nil(t, svc.ResolveTLSProfile(tc.account))
		})
	}
}

func TestTLSFingerprintProfileService_DefaultTLSProfileStillRequiresExplicitTLSFingerprintFlag(t *testing.T) {
	svc := &TLSFingerprintProfileService{}

	require.Nil(t, svc.ResolveTLSProfile(&Account{
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{},
	}))

	profile := svc.ResolveTLSProfile(&Account{
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
		Extra: map[string]any{
			"enable_tls_fingerprint": true,
		},
	})
	require.NotNil(t, profile)
	require.Equal(t, "Built-in Default (Node.js 24.x)", profile.Name)
}
