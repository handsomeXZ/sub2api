package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func setupAccountImpersonationRouter(adminSvc *stubAdminService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewAccountHandler(adminSvc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	router.POST("/api/v1/admin/accounts", handler.Create)
	router.PUT("/api/v1/admin/accounts/:id", handler.Update)
	router.GET("/api/v1/admin/accounts/:id", handler.GetByID)
	router.GET("/api/v1/admin/accounts", handler.List)
	return router
}

func TestAccountHandlerImpersonation_CreateUpdateAndRead(t *testing.T) {
	adminSvc := newStubAdminService()
	adminSvc.accounts = []service.Account{{
		ID:       3,
		Name:     "upstream-account",
		Platform: service.PlatformAnthropic,
		Type:     service.AccountTypeUpstream,
		Status:   service.StatusActive,
		Extra: map[string]any{
			claudeCodeIdentityImpersonationEnabledKey: true,
			"note": "keep",
		},
	}}
	router := setupAccountImpersonationRouter(adminSvc)

	t.Run("create true maps into extra", func(t *testing.T) {
		body := map[string]any{
			"name":     "upstream-new",
			"platform": service.PlatformAnthropic,
			"type":     service.AccountTypeUpstream,
			"credentials": map[string]any{
				"base_url": "https://api.anthropic.com",
				"api_key":  "upstream-key-placeholder",
			},
			"claude_code_identity_impersonation_enabled": true,
			"concurrency": 1,
			"priority":    1,
		}
		raw, err := json.Marshal(body)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/accounts", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, adminSvc.createdAccounts, 1)
		require.Equal(t, true, adminSvc.createdAccounts[0].Extra[claudeCodeIdentityImpersonationEnabledKey])
	})

	t.Run("update false clears and survives response", func(t *testing.T) {
		body := map[string]any{
			"extra": map[string]any{
				"note": "keep",
			},
			"claude_code_identity_impersonation_enabled": false,
		}
		raw, err := json.Marshal(body)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/accounts/3", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.NotEmpty(t, adminSvc.updatedAccounts)
		last := adminSvc.updatedAccounts[len(adminSvc.updatedAccounts)-1]
		require.Equal(t, false, last.Extra[claudeCodeIdentityImpersonationEnabledKey])

		var payload struct {
			Data struct {
				ClaudeCodeIdentityImpersonationEnabled *bool `json:"claude_code_identity_impersonation_enabled"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
		require.NotNil(t, payload.Data.ClaudeCodeIdentityImpersonationEnabled)
		require.False(t, *payload.Data.ClaudeCodeIdentityImpersonationEnabled)
	})

	t.Run("update true sets and survives response", func(t *testing.T) {
		adminSvc.accounts[0].Extra[claudeCodeIdentityImpersonationEnabledKey] = false
		body := map[string]any{
			"extra": map[string]any{
				"note": "keep",
			},
			"claude_code_identity_impersonation_enabled": true,
		}
		raw, err := json.Marshal(body)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/accounts/3", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		last := adminSvc.updatedAccounts[len(adminSvc.updatedAccounts)-1]
		require.Equal(t, true, last.Extra[claudeCodeIdentityImpersonationEnabledKey])

		var payload struct {
			Data struct {
				ClaudeCodeIdentityImpersonationEnabled *bool `json:"claude_code_identity_impersonation_enabled"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
		require.NotNil(t, payload.Data.ClaudeCodeIdentityImpersonationEnabled)
		require.True(t, *payload.Data.ClaudeCodeIdentityImpersonationEnabled)
	})

	t.Run("omitted field preserves existing extra value", func(t *testing.T) {
		adminSvc.accounts[0].Extra[claudeCodeIdentityImpersonationEnabledKey] = true
		body := map[string]any{
			"extra": map[string]any{
				"note": "changed",
			},
		}
		raw, err := json.Marshal(body)
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/accounts/3", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		last := adminSvc.updatedAccounts[len(adminSvc.updatedAccounts)-1]
		require.Equal(t, true, last.Extra[claudeCodeIdentityImpersonationEnabledKey])
		require.Equal(t, "changed", last.Extra["note"])
	})

	t.Run("get detail returns true", func(t *testing.T) {
		adminSvc.accounts[0].Extra[claudeCodeIdentityImpersonationEnabledKey] = true
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/accounts/3", nil)
		router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var payload struct {
			Data struct {
				ClaudeCodeIdentityImpersonationEnabled *bool `json:"claude_code_identity_impersonation_enabled"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
		require.NotNil(t, payload.Data.ClaudeCodeIdentityImpersonationEnabled)
		require.True(t, *payload.Data.ClaudeCodeIdentityImpersonationEnabled)
	})

	t.Run("list returns explicit false", func(t *testing.T) {
		adminSvc.accounts[0].Extra[claudeCodeIdentityImpersonationEnabledKey] = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/accounts?page=1&page_size=20", nil)
		router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var payload struct {
			Data struct {
				Items []struct {
					ClaudeCodeIdentityImpersonationEnabled *bool `json:"claude_code_identity_impersonation_enabled"`
				} `json:"items"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
		var found *bool
		for i := range payload.Data.Items {
			if payload.Data.Items[i].ClaudeCodeIdentityImpersonationEnabled != nil {
				found = payload.Data.Items[i].ClaudeCodeIdentityImpersonationEnabled
				break
			}
		}
		require.NotNil(t, found)
		require.False(t, *found)
	})
}
