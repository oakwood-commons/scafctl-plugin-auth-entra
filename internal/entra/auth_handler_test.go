package entra

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPlugin creates a Plugin initialized for testing with a mock HTTP client
// and a fake host service.
func newTestPlugin(t *testing.T, httpClient *MockHTTPClient, graphClient *MockGraphClient) (*Plugin, *fakeHostService) {
	t.Helper()
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)

	p := &Plugin{}
	p.cachedHostClient = hostClient

	if httpClient == nil {
		httpClient = NewMockHTTPClient()
	}
	p.httpClient = httpClient

	if graphClient == nil {
		graphClient = NewMockGraphClient()
	}
	p.graphClient = graphClient

	err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
		BinaryName: "scafctl",
	})
	require.NoError(t, err)

	// Re-assign mocks since ConfigureAuthHandler only sets them if nil
	p.httpClient = httpClient
	p.graphClient = graphClient
	p.cachedHostClient = hostClient

	return p, fake
}

// makeTestJWT constructs a fake JWT with the given payload claims.
func makeTestJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".fakesig"
}

func TestGetAuthHandlers(t *testing.T) {
	p := &Plugin{}
	handlers, err := p.GetAuthHandlers(context.Background())
	require.NoError(t, err)
	require.Len(t, handlers, 1)

	h := handlers[0]
	assert.Equal(t, HandlerName, h.Name)
	assert.Equal(t, HandlerDisplayName, h.DisplayName)
	assert.Contains(t, h.Flows, auth.FlowInteractive)
	assert.Contains(t, h.Flows, auth.FlowDeviceCode)
	assert.Contains(t, h.Flows, auth.FlowServicePrincipal)
	assert.Contains(t, h.Flows, auth.FlowWorkloadIdentity)
	assert.Contains(t, h.Capabilities, auth.CapScopesOnLogin)
	assert.Contains(t, h.Capabilities, auth.CapScopesOnTokenRequest)
	assert.Contains(t, h.Capabilities, auth.CapTenantID)
}

func TestConfigureAuthHandler(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "mycli",
		})
		require.NoError(t, err)
		assert.Equal(t, "mycli", p.cfg.BinaryName)
		assert.NotNil(t, p.config)
		assert.NotNil(t, p.httpClient)
		assert.NotNil(t, p.graphClient)
		assert.NotNil(t, p.clock)
		assert.NotNil(t, p.openBrowser)
		assert.NotNil(t, p.oboCache)
	})

	t.Run("unknown handler", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), "unknown", sdkplugin.ProviderConfig{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})

	t.Run("custom config via settings", func(t *testing.T) {
		p := &Plugin{}
		cfg := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"test-id","tenantId":"test-tenant"}`),
		}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Settings: cfg,
		})
		require.NoError(t, err)
		assert.Equal(t, "test-id", p.config.ClientID)
		assert.Equal(t, "test-tenant", p.config.TenantID)
	})

	t.Run("invalid config JSON", func(t *testing.T) {
		p := &Plugin{}
		cfg := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{not valid json}`),
		}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Settings: cfg,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse handler config")
	})

	t.Run("embedder binary name", func(t *testing.T) {
		p := &Plugin{}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "customcli",
		})
		require.NoError(t, err)
		assert.Equal(t, "customcli", p.binaryName())
	})
}

func TestLogin(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.Login(context.Background(), "unknown", sdkplugin.LoginRequest{}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})

	t.Run("unsupported flow", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.Flow("unsupported"),
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported flow")
	})
}

func TestLogout(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		err := p.Logout(context.Background(), "unknown")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")
	})

	t.Run("clears stored secrets", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		ctx := context.Background()

		// Store some secrets
		fake.secrets[SecretKeyRefreshToken] = "test-refresh-token"
		fake.secrets[SecretKeyMetadata] = `{"claims":{}}`
		fake.secrets[SecretKeyTokenPrefix+"scope1"] = `{"accessToken":"tok1"}`

		err := p.Logout(ctx, HandlerName)
		require.NoError(t, err)

		assert.Empty(t, fake.secrets, "all secrets should be cleared after logout")
	})
}

func TestGetStatus(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.GetStatus(context.Background(), "unknown")
		assert.Error(t, err)
	})

	t.Run("not authenticated when no refresh token", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		status, err := p.GetStatus(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.False(t, status.Authenticated)
	})

	t.Run("authenticated with valid refresh token", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		ctx := context.Background()

		fake.secrets[SecretKeyRefreshToken] = "test-refresh-token"
		metadata := TokenMetadata{
			Claims: &auth.Claims{
				Subject: "testuser",
				Name:    "Test User",
			},
			RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
			LastRefresh:           time.Now(),
			TenantID:              "test-tenant",
			ClientID:              "test-client",
			Scopes:                []string{"openid"},
		}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		status, err := p.GetStatus(ctx, HandlerName)
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, "testuser", status.Claims.Subject)
		assert.Equal(t, "test-tenant", status.TenantID)
		assert.Equal(t, auth.IdentityTypeUser, status.IdentityType)
	})

	t.Run("not authenticated with expired refresh token", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		ctx := context.Background()

		fake.secrets[SecretKeyRefreshToken] = "expired-token"
		metadata := TokenMetadata{
			Claims:                &auth.Claims{Subject: "testuser"},
			RefreshTokenExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		status, err := p.GetStatus(ctx, HandlerName)
		require.NoError(t, err)
		assert.False(t, status.Authenticated)
		assert.Equal(t, "session expired", status.Reason)
	})

	t.Run("service principal env detection", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "sp-client")
		t.Setenv(EnvAzureTenantID, "sp-tenant")
		t.Setenv(EnvAzureClientSecret, "sp-secret")

		status, err := p.GetStatus(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
	})
}

func TestGetToken(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.GetToken(context.Background(), "unknown", sdkplugin.TokenRequest{})
		assert.Error(t, err)
	})

	t.Run("scope required for user flows", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		// Clear env to avoid SP/WI detection
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		_, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "scope is required")
	})

	t.Run("returns cached token", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		ctx := context.Background()

		// Clear env to avoid SP/WI detection
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		// Pre-populate cache
		fp := fingerprintHash(p.config.ClientID + ":" + p.config.TenantID + ":" + p.config.GetAuthority())
		cacheKey := fp + ":https://graph.microsoft.com/.default"
		entry := tokenCacheEntry{
			AccessToken: "cached-access-token",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Scope:       "https://graph.microsoft.com/.default",
			CachedAt:    time.Now(),
		}
		entryBytes, _ := json.Marshal(entry)
		fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryBytes)

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
			Scope: "https://graph.microsoft.com/.default",
		})
		require.NoError(t, err)
		assert.Equal(t, "cached-access-token", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
	})
}

func TestListCachedTokens(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.ListCachedTokens(context.Background(), "unknown")
		assert.Error(t, err)
	})

	t.Run("lists refresh and access tokens", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		ctx := context.Background()

		// Store a refresh token and metadata
		fake.secrets[SecretKeyRefreshToken] = "rt"
		metadata := TokenMetadata{
			RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
			LastRefresh:           time.Now(),
			LoginFlow:             auth.FlowInteractive,
			SessionID:             "sess1",
		}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		// Store a cached access token
		entry := tokenCacheEntry{
			AccessToken: "at",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			CachedAt:    time.Now(),
		}
		entryBytes, _ := json.Marshal(entry)
		fake.secrets[SecretKeyTokenPrefix+"scope1"] = string(entryBytes)

		tokens, err := p.ListCachedTokens(ctx, HandlerName)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(tokens), 2)

		// Verify refresh token entry
		var found bool
		for _, tok := range tokens {
			if tok.TokenKind == "refresh" {
				found = true
				assert.Equal(t, HandlerName, tok.Handler)
				assert.Equal(t, auth.FlowInteractive, tok.Flow)
				assert.Equal(t, "sess1", tok.SessionID)
			}
		}
		assert.True(t, found, "should have a refresh token entry")
	})
}

func TestPurgeExpiredTokens(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.PurgeExpiredTokens(context.Background(), "unknown")
		assert.Error(t, err)
	})

	t.Run("removes expired tokens", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		ctx := context.Background()

		// Expired token
		expired := tokenCacheEntry{
			AccessToken: "expired",
			ExpiresAt:   time.Now().Add(-1 * time.Hour),
		}
		expiredBytes, _ := json.Marshal(expired)
		fake.secrets[SecretKeyTokenPrefix+"expired-scope"] = string(expiredBytes)

		// Valid token
		valid := tokenCacheEntry{
			AccessToken: "valid",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}
		validBytes, _ := json.Marshal(valid)
		fake.secrets[SecretKeyTokenPrefix+"valid-scope"] = string(validBytes)

		count, err := p.PurgeExpiredTokens(ctx, HandlerName)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		// Valid token should still exist
		_, exists := fake.secrets[SecretKeyTokenPrefix+"valid-scope"]
		assert.True(t, exists, "valid token should remain")
	})
}

func TestDetectAvailableFlows(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.DetectAvailableFlows(context.Background(), "unknown")
		assert.Error(t, err)
	})

	t.Run("no env vars set", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureTenantID, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		require.Len(t, flows, 4)

		// WI and SP should be unavailable
		for _, f := range flows {
			switch f.Flow {
			case auth.FlowWorkloadIdentity:
				assert.False(t, f.Available)
			case auth.FlowServicePrincipal:
				assert.False(t, f.Available)
			case auth.FlowDeviceCode:
				assert.True(t, f.Available)
			case auth.FlowInteractive:
				assert.True(t, f.Available)
			}
		}
	})

	t.Run("service principal env vars set", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "sp-client")
		t.Setenv(EnvAzureTenantID, "sp-tenant")
		t.Setenv(EnvAzureClientSecret, "sp-secret")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)

		for _, f := range flows {
			if f.Flow == auth.FlowServicePrincipal {
				assert.True(t, f.Available)
				return
			}
		}
		t.Fatal("service principal flow not found")
	})
}

func TestStopAuthHandler(t *testing.T) {
	t.Run("unknown handler", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		err := p.StopAuthHandler(context.Background(), "unknown")
		assert.Error(t, err)
	})

	t.Run("known handler succeeds", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		err := p.StopAuthHandler(context.Background(), HandlerName)
		assert.NoError(t, err)
	})
}

func TestBinaryName(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		p := &Plugin{}
		assert.Equal(t, "scafctl", p.binaryName())
	})

	t.Run("custom", func(t *testing.T) {
		p := &Plugin{cfg: sdkplugin.ProviderConfig{BinaryName: "mycli"}}
		assert.Equal(t, "mycli", p.binaryName())
	})
}

func TestConfig(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		cfg := DefaultConfig()
		assert.NotEmpty(t, cfg.ClientID)
		assert.NotEmpty(t, cfg.TenantID)
		assert.NotEmpty(t, cfg.Authority)
	})

	t.Run("validate success", func(t *testing.T) {
		cfg := DefaultConfig()
		assert.NoError(t, cfg.Validate())
	})

	t.Run("get authority", func(t *testing.T) {
		cfg := DefaultConfig()
		assert.Contains(t, cfg.GetAuthority(), "login.microsoftonline.com")
	})

	t.Run("get authority with tenant", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.TenantID = "my-tenant"
		url := cfg.GetAuthorityWithTenant("custom-tenant")
		assert.Contains(t, url, "custom-tenant")
	})

	t.Run("qualify scope", func(t *testing.T) {
		// Fully qualified scope passes through
		assert.Equal(t, "https://graph.microsoft.com/.default", QualifyScope("https://graph.microsoft.com/.default"))
		assert.Equal(t, "api://my-api/.default", QualifyScope("api://my-api/.default"))
		// OIDC scopes pass through
		assert.Equal(t, "openid", QualifyScope("openid"))
		assert.Equal(t, "offline_access", QualifyScope("offline_access"))
	})
}

func TestParseJWTClaims(t *testing.T) {
	t.Run("valid JWT", func(t *testing.T) {
		jwt := makeTestJWT(map[string]any{
			"sub":                "user-sub",
			"name":               "Test User",
			"preferred_username": "test@example.com",
			"email":              "test@example.com",
			"iss":                "https://login.microsoftonline.com/tenant-id/v2.0",
			"tid":                "tenant-id",
			"oid":                "object-id",
			"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
		})

		claims, err := parseJWTClaims(jwt)
		require.NoError(t, err)
		assert.Equal(t, "user-sub", claims.Subject)
		assert.Equal(t, "Test User", claims.Name)
		assert.Equal(t, "test@example.com", claims.Username)
		assert.Equal(t, "test@example.com", claims.Email)
		assert.Equal(t, "tenant-id", claims.TenantID)
		assert.Equal(t, "object-id", claims.ObjectID)
		assert.False(t, claims.ExpiresAt.IsZero())
	})

	t.Run("invalid JWT format", func(t *testing.T) {
		_, err := parseJWTClaims("not-a-jwt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid JWT")
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := parseJWTClaims("header.!!!invalid!!!.sig")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid JWT payload encoding")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		payload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
		_, err := parseJWTClaims("header." + payload + ".sig")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid JWT payload JSON")
	})

	t.Run("empty id token returns empty claims", func(t *testing.T) {
		p := &Plugin{}
		claims, err := p.extractClaims(&TokenResponse{})
		require.NoError(t, err)
		assert.NotNil(t, claims)
	})
}

func TestAADSTSHints(t *testing.T) {
	tests := []struct {
		name        string
		desc        string
		wantHint    bool
		hintContain string
	}{
		{"AADSTS700016", "AADSTS700016: Application not found", true, "app registration"},
		{"AADSTS90002", "AADSTS90002: Tenant not found", true, "tenant"},
		{"AADSTS7000215", "AADSTS7000215: Invalid client secret", true, "secret"},
		{"AADSTS70011", "AADSTS70011: Invalid scope", true, "scope"},
		{"AADSTS50194", "AADSTS50194: Wrong account type", true, "account type"},
		{"AADSTS500011", "AADSTS500011: Resource not found", true, "resource"},
		{"AADSTS500113", "AADSTS500113: No redirect URI", true, "redirect URI"},
		{"AADSTS53003", "AADSTS53003: Conditional Access", true, "Conditional Access"},
		{"unknown code", "AADSTS999999: Something unknown", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := aadstsHint(tt.desc)
			if tt.wantHint {
				assert.NotEmpty(t, hint)
				assert.Contains(t, hint, tt.hintContain)
			} else {
				assert.Empty(t, hint)
			}
		})
	}
}

func TestFormatAADSTSError(t *testing.T) {
	t.Run("with hint", func(t *testing.T) {
		err := formatAADSTSError("token request failed", TokenErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "AADSTS700016: Application not found",
		})
		assert.Contains(t, err.Error(), "token request failed")
		assert.Contains(t, err.Error(), "Hint:")
	})

	t.Run("without hint", func(t *testing.T) {
		err := formatAADSTSError("token request failed", TokenErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Internal server error",
		})
		assert.Contains(t, err.Error(), "token request failed")
		assert.NotContains(t, err.Error(), "Hint:")
	})
}

func TestClaimsChallenge(t *testing.T) {
	t.Run("round-trip", func(t *testing.T) {
		ctx := context.Background()
		assert.Empty(t, claimsChallengeFromContext(ctx))

		ctx = ContextWithClaimsChallenge(ctx, `{"access_token":{"xms_cc":{"values":["cp1"]}}}`)
		assert.Equal(t, `{"access_token":{"xms_cc":{"values":["cp1"]}}}`, claimsChallengeFromContext(ctx))
	})

	t.Run("error string", func(t *testing.T) {
		err := &ClaimsChallengeError{Claims: "test", Scope: "test-scope"}
		assert.Contains(t, err.Error(), "test-scope")
	})
}

func TestCache(t *testing.T) {
	t.Run("set and get", func(t *testing.T) {
		fake := newFakeHostService()
		hostClient := newFakeHostClient(fake)
		ctx := context.Background()

		token := &auth.Token{
			AccessToken: "test-token",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Scope:       "test-scope",
			Flow:        auth.FlowDeviceCode,
		}

		err := cacheSet(ctx, hostClient, "testkey", token)
		require.NoError(t, err)

		got, err := cacheGet(ctx, hostClient, "testkey")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "test-token", got.AccessToken)
		assert.Equal(t, "Bearer", got.TokenType)
		assert.Equal(t, auth.FlowDeviceCode, got.Flow)
	})

	t.Run("get returns nil when not found", func(t *testing.T) {
		fake := newFakeHostService()
		hostClient := newFakeHostClient(fake)

		got, err := cacheGet(context.Background(), hostClient, "nonexistent")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

func TestFingerprintHash(t *testing.T) {
	h1 := fingerprintHash("test")
	h2 := fingerprintHash("test")
	h3 := fingerprintHash("different")

	assert.Equal(t, h1, h2, "same input should produce same hash")
	assert.NotEqual(t, h1, h3, "different input should produce different hash")
	assert.Len(t, h1, 64, "SHA-256 hex should be 64 chars")
}

func TestEnsureOIDCScopes(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "empty input adds all required scopes",
			input:  nil,
			expect: []string{"openid", "profile", "offline_access"},
		},
		{
			name:   "already has all scopes unchanged",
			input:  []string{"openid", "profile", "offline_access"},
			expect: []string{"openid", "profile", "offline_access"},
		},
		{
			name:   "adds missing scopes preserving existing",
			input:  []string{"api://my-app/.default"},
			expect: []string{"api://my-app/.default", "openid", "profile", "offline_access"},
		},
		{
			name:   "no duplicates when partial overlap",
			input:  []string{"openid", "api://app"},
			expect: []string{"openid", "api://app", "profile", "offline_access"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ensureOIDCScopes(tc.input)
			assert.Equal(t, tc.expect, result)
		})
	}
}

func TestEnsureOIDCScopes_DoesNotMutateInput(t *testing.T) {
	original := []string{"openid"}
	originalCopy := make([]string, len(original))
	copy(originalCopy, original)

	_ = ensureOIDCScopes(original)

	assert.Equal(t, originalCopy, original, "input slice must not be modified")
}

func TestEnsureOfflineAccess(t *testing.T) {
	assert.Equal(t, "openid offline_access", ensureOfflineAccess("openid"))
	assert.Equal(t, "openid offline_access profile", ensureOfflineAccess("openid offline_access profile"))
}

func TestGenerateSessionID(t *testing.T) {
	s1 := generateSessionID()
	s2 := generateSessionID()
	assert.NotEmpty(t, s1)
	assert.NotEqual(t, s1, s2, "each call should produce a unique ID")
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "abc", truncate("abc", 10))
	assert.Equal(t, "ab...", truncate("abcde", 2))
}

func TestGetGroups(t *testing.T) {
	t.Run("single page", func(t *testing.T) {
		graphMock := NewMockGraphClient()
		graphMock.AddResponse(http.StatusOK, graphGroupsPage{
			Value: []graphGroupEntry{
				{ID: "group1"},
				{ID: "group2"},
			},
		})

		// Need a cached token for GetGroups to work
		httpMock := NewMockHTTPClient()
		p, fake := newTestPlugin(t, httpMock, graphMock)
		ctx := context.Background()

		// Clear env to avoid SP/WI detection
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		// Pre-populate cache with a Graph token
		fp := fingerprintHash(p.config.ClientID + ":" + p.config.TenantID + ":" + p.config.GetAuthority())
		cacheKey := fp + ":https://graph.microsoft.com/.default"
		entry := tokenCacheEntry{
			AccessToken: "graph-token",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Scope:       "https://graph.microsoft.com/.default",
			CachedAt:    time.Now(),
		}
		entryBytes, _ := json.Marshal(entry)
		fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryBytes)

		groups, err := p.GetGroups(ctx)
		require.NoError(t, err)
		assert.Equal(t, []string{"group1", "group2"}, groups)

		// Verify Graph API was called with the right bearer token
		reqs := graphMock.Requests
		require.Len(t, reqs, 1)
		assert.Equal(t, "graph-token", reqs[0].BearerToken)
	})

	t.Run("rejects service principal", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "sp-client")
		t.Setenv(EnvAzureTenantID, "sp-tenant")
		t.Setenv(EnvAzureClientSecret, "sp-secret")

		_, err := p.GetGroups(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "service principal")
	})

	t.Run("graph error returns error", func(t *testing.T) {
		graphMock := NewMockGraphClient()
		graphMock.AddError(fmt.Errorf("network error"))

		httpMock := NewMockHTTPClient()
		p, fake := newTestPlugin(t, httpMock, graphMock)
		ctx := context.Background()

		// Clear env
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		// Pre-populate cache
		fp := fingerprintHash(p.config.ClientID + ":" + p.config.TenantID + ":" + p.config.GetAuthority())
		cacheKey := fp + ":https://graph.microsoft.com/.default"
		entry := tokenCacheEntry{
			AccessToken: "graph-token",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			CachedAt:    time.Now(),
		}
		entryBytes, _ := json.Marshal(entry)
		fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryBytes)

		_, err := p.GetGroups(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "network error")
	})
}

func TestServicePrincipalCredentials(t *testing.T) {
	t.Run("not available when env empty", func(t *testing.T) {
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureTenantID, "")
		assert.False(t, HasServicePrincipalCredentials())
	})

	t.Run("available when all set", func(t *testing.T) {
		t.Setenv(EnvAzureClientID, "client")
		t.Setenv(EnvAzureTenantID, "tenant")
		t.Setenv(EnvAzureClientSecret, "secret")
		assert.True(t, HasServicePrincipalCredentials())

		creds := GetServicePrincipalCredentials()
		assert.Equal(t, "client", creds.ClientID)
		assert.Equal(t, "tenant", creds.TenantID)
		assert.Equal(t, "secret", creds.ClientSecret)
	})

	t.Run("not available when partial", func(t *testing.T) {
		t.Setenv(EnvAzureClientID, "client")
		t.Setenv(EnvAzureTenantID, "")
		t.Setenv(EnvAzureClientSecret, "secret")
		assert.False(t, HasServicePrincipalCredentials())
	})
}

func TestWorkloadIdentityCredentials(t *testing.T) {
	t.Run("not available when env empty", func(t *testing.T) {
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureTenantID, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")
		assert.False(t, HasWorkloadIdentityCredentials())
	})

	t.Run("available with direct token", func(t *testing.T) {
		t.Setenv(EnvAzureClientID, "client")
		t.Setenv(EnvAzureTenantID, "tenant")
		t.Setenv(EnvAzureFederatedToken, "direct-token")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		assert.True(t, HasWorkloadIdentityCredentials())
	})
}

func TestMockHTTPClient(t *testing.T) {
	t.Run("records requests", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddResponse(200, map[string]string{"status": "ok"})

		resp, err := mock.PostForm(context.Background(), "https://example.com/token", nil)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
		_ = resp.Body.Close()

		reqs := mock.GetRequests()
		require.Len(t, reqs, 1)
		assert.Equal(t, "https://example.com/token", reqs[0].Endpoint)
	})

	t.Run("returns error", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddError(fmt.Errorf("test error"))

		_, err := mock.PostForm(context.Background(), "https://example.com", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "test error")
	})

	t.Run("reset clears state", func(t *testing.T) {
		mock := NewMockHTTPClient()
		mock.AddResponse(200, nil)
		_, _ = mock.PostForm(context.Background(), "https://example.com", nil)
		mock.Reset()
		assert.Empty(t, mock.GetRequests())
		assert.Empty(t, mock.Responses)
	})
}

func TestMockGraphClient(t *testing.T) {
	mock := NewMockGraphClient()
	mock.AddResponse(200, map[string]string{"value": "test"})

	resp, err := mock.Get(context.Background(), "https://graph.microsoft.com/v1.0/me", "bearer-tok")
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	_ = resp.Body.Close()

	require.Len(t, mock.Requests, 1)
	assert.Equal(t, "bearer-tok", mock.Requests[0].BearerToken)
}

func TestOBOCacheKey(t *testing.T) {
	k1 := oboCacheKey("token1", "scope1")
	k2 := oboCacheKey("token1", "scope2")
	k3 := oboCacheKey("token1", "scope1")

	assert.Equal(t, k1, k3)
	assert.NotEqual(t, k1, k2)
	assert.Len(t, k1, 64)
}

func TestHostClientFallbackToContext(t *testing.T) {
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)

	p := &Plugin{} // cachedHostClient is nil

	t.Run("returns nil when no client in context or cache", func(t *testing.T) {
		got := p.hostClient(context.Background())
		assert.Nil(t, got)
	})

	t.Run("returns client from context when cache is nil", func(t *testing.T) {
		ctx := sdkplugin.WithHostClient(context.Background(), hostClient)
		got := p.hostClient(ctx)
		assert.NotNil(t, got)
		assert.Same(t, hostClient, got)
	})

	t.Run("prefers cached client over context", func(t *testing.T) {
		p.cachedHostClient = hostClient
		ctxClient := newFakeHostClient(newFakeHostService())
		ctx := sdkplugin.WithHostClient(context.Background(), ctxClient)
		got := p.hostClient(ctx)
		assert.Same(t, hostClient, got)
	})
}

// --- Profile scoping tests (Issue #7) ---

// setProfileConfig simulates JSON-unmarshaled profile config by setting
// the given fields on the plugin's config and marking them as explicitly
// provided (so profileOrEnv uses config values instead of env vars).
func setProfileConfig(p *Plugin, fields map[string]string) {
	if p.config.setFields == nil {
		p.config.setFields = make(map[string]bool)
	}
	for jsonField, val := range fields {
		switch jsonField {
		case "clientId":
			p.config.ClientID = val
		case "tenantId":
			p.config.TenantID = val
		case "clientSecret":
			p.config.ClientSecret = val
		case "federatedTokenFile":
			p.config.FederatedTokenFile = val
		case "federatedToken":
			p.config.FederatedToken = val
		case "authority":
			p.config.Authority = val
		}
		p.config.setFields[jsonField] = true
	}
}

func TestSecretKey(t *testing.T) {
	p, _ := newTestPlugin(t, nil, nil)

	t.Run("no profile uses legacy key", func(t *testing.T) {
		ctx := context.Background()
		assert.Equal(t, "scafctl.auth.entra.refresh_token", p.secretKey(ctx, secretSuffixRefreshToken))
		assert.Equal(t, "scafctl.auth.entra.metadata", p.secretKey(ctx, secretSuffixMetadata))
		assert.Equal(t, "scafctl.auth.entra.token.", p.secretKey(ctx, secretSuffixTokenPrefix))
	})

	t.Run("with profile scopes key", func(t *testing.T) {
		ctx := auth.WithProfile(context.Background(), "work")
		assert.Equal(t, "scafctl.auth.entra.776f726b.refresh_token", p.secretKey(ctx, secretSuffixRefreshToken))
		assert.Equal(t, "scafctl.auth.entra.776f726b.metadata", p.secretKey(ctx, secretSuffixMetadata))
		assert.Equal(t, "scafctl.auth.entra.776f726b.token.", p.secretKey(ctx, secretSuffixTokenPrefix))
	})

	t.Run("different profiles produce different keys", func(t *testing.T) {
		ctxA := auth.WithProfile(context.Background(), "prod")
		ctxB := auth.WithProfile(context.Background(), "dev")
		assert.NotEqual(t, p.secretKey(ctxA, secretSuffixRefreshToken), p.secretKey(ctxB, secretSuffixRefreshToken))
	})

	t.Run("profile with dots does not collide with key delimiter", func(t *testing.T) {
		// "prod.token" as a profile name must not collide with the token
		// cache prefix for profile "prod".
		ctxDotted := auth.WithProfile(context.Background(), "prod.token")
		ctxPlain := auth.WithProfile(context.Background(), "prod")
		dottedKey := p.secretKey(ctxDotted, secretSuffixRefreshToken)
		plainTokenKey := p.secretKey(ctxPlain, secretSuffixTokenPrefix)
		assert.NotEqual(t, dottedKey, plainTokenKey)
		// The dotted profile name should be hex-encoded to avoid ambiguity
		assert.Contains(t, dottedKey, "70726f642e746f6b656e")
	})

	t.Run("legacy constants match no-profile keys", func(t *testing.T) {
		ctx := context.Background()
		assert.Equal(t, SecretKeyRefreshToken, p.secretKey(ctx, secretSuffixRefreshToken))
		assert.Equal(t, SecretKeyMetadata, p.secretKey(ctx, secretSuffixMetadata))
		assert.Equal(t, SecretKeyTokenPrefix, p.secretKey(ctx, secretSuffixTokenPrefix))
	})
}

func TestProfileScopedStorage(t *testing.T) {
	t.Run("store and retrieve with different profiles", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)

		// Store credentials under "work" profile
		ctxWork := auth.WithProfile(context.Background(), "work")
		workKey := p.secretKey(ctxWork, secretSuffixRefreshToken)
		workMetaKey := p.secretKey(ctxWork, secretSuffixMetadata)

		// Store credentials under "personal" profile
		ctxPersonal := auth.WithProfile(context.Background(), "personal")
		personalKey := p.secretKey(ctxPersonal, secretSuffixRefreshToken)
		personalMetaKey := p.secretKey(ctxPersonal, secretSuffixMetadata)

		// Set up fake secrets for both profiles
		fake.secrets[workKey] = "work-refresh-token"
		fake.secrets[personalKey] = "personal-refresh-token"

		workMeta := TokenMetadata{
			Claims:                &auth.Claims{Subject: "work-user"},
			RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
			TenantID:              "work-tenant",
			ClientID:              "work-client",
		}
		workMetaBytes, _ := json.Marshal(workMeta)
		fake.secrets[workMetaKey] = string(workMetaBytes)

		personalMeta := TokenMetadata{
			Claims:                &auth.Claims{Subject: "personal-user"},
			RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
			TenantID:              "personal-tenant",
			ClientID:              "personal-client",
		}
		personalMetaBytes, _ := json.Marshal(personalMeta)
		fake.secrets[personalMetaKey] = string(personalMetaBytes)

		// Verify work profile status
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		workStatus, err := p.GetStatus(ctxWork, HandlerName)
		require.NoError(t, err)
		assert.True(t, workStatus.Authenticated)
		assert.Equal(t, "work-user", workStatus.Claims.Subject)
		assert.Equal(t, "work-tenant", workStatus.TenantID)

		// Verify personal profile status
		personalStatus, err := p.GetStatus(ctxPersonal, HandlerName)
		require.NoError(t, err)
		assert.True(t, personalStatus.Authenticated)
		assert.Equal(t, "personal-user", personalStatus.Claims.Subject)
		assert.Equal(t, "personal-tenant", personalStatus.TenantID)

		// Default (no profile) should not see either
		defaultStatus, err := p.GetStatus(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.False(t, defaultStatus.Authenticated)
	})

	t.Run("logout clears only target profile", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		ctxWork := auth.WithProfile(context.Background(), "work")
		ctxPersonal := auth.WithProfile(context.Background(), "personal")

		// Populate both profiles
		fake.secrets[p.secretKey(ctxWork, secretSuffixRefreshToken)] = "work-rt"
		fake.secrets[p.secretKey(ctxWork, secretSuffixMetadata)] = `{"claims":{}}`
		fake.secrets[p.secretKey(ctxPersonal, secretSuffixRefreshToken)] = "personal-rt"
		fake.secrets[p.secretKey(ctxPersonal, secretSuffixMetadata)] = `{"claims":{}}`

		// Logout work profile
		err := p.Logout(ctxWork, HandlerName)
		require.NoError(t, err)

		// Work profile secrets should be gone
		_, workExists := fake.secrets[p.secretKey(ctxWork, secretSuffixRefreshToken)]
		assert.False(t, workExists, "work refresh token should be deleted")

		// Personal profile secrets should remain
		_, personalExists := fake.secrets[p.secretKey(ctxPersonal, secretSuffixRefreshToken)]
		assert.True(t, personalExists, "personal refresh token should remain")
	})
}

func TestProfileScopedTokenCache(t *testing.T) {
	t.Run("cached tokens isolated by profile", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		ctx := context.Background()
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		ctxWork := auth.WithProfile(ctx, "work")
		ctxPersonal := auth.WithProfile(ctx, "personal")

		fp := fingerprintHash(p.config.ClientID + ":" + p.config.TenantID + ":" + p.config.GetAuthority())
		scope := "https://graph.microsoft.com/.default"

		// Cache token under work profile
		workKey := p.tokenCachePrefix(ctxWork) + fp + ":" + scope
		workEntry := tokenCacheEntry{
			AccessToken: "work-token",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Scope:       scope,
			CachedAt:    time.Now(),
		}
		workBytes, _ := json.Marshal(workEntry)
		fake.secrets[workKey] = string(workBytes)

		// Cache token under personal profile
		personalKey := p.tokenCachePrefix(ctxPersonal) + fp + ":" + scope
		personalEntry := tokenCacheEntry{
			AccessToken: "personal-token",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Scope:       scope,
			CachedAt:    time.Now(),
		}
		personalBytes, _ := json.Marshal(personalEntry)
		fake.secrets[personalKey] = string(personalBytes)

		// Also need refresh tokens for GetToken to work
		fake.secrets[p.secretKey(ctxWork, secretSuffixRefreshToken)] = "work-rt"
		fake.secrets[p.secretKey(ctxPersonal, secretSuffixRefreshToken)] = "personal-rt"

		// GetToken for work should return work token
		workResp, err := p.GetToken(ctxWork, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "work-token", workResp.AccessToken)

		// GetToken for personal should return personal token
		personalResp, err := p.GetToken(ctxPersonal, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "personal-token", personalResp.AccessToken)
	})
}

// --- Profile config over env vars tests (Issue #8) ---

func TestResolveServicePrincipalCredentials(t *testing.T) {
	t.Run("no profile uses env vars only", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		// No profile set (default)
		t.Setenv(EnvAzureClientID, "env-client")
		t.Setenv(EnvAzureTenantID, "env-tenant")
		t.Setenv(EnvAzureClientSecret, "env-secret")

		creds := p.resolveServicePrincipalCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "env-client", creds.ClientID)
		assert.Equal(t, "env-tenant", creds.TenantID)
		assert.Equal(t, "env-secret", creds.ClientSecret)
	})

	t.Run("profile prefers config over env vars", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine"
		setProfileConfig(p, map[string]string{
			"clientId":     "config-client",
			"tenantId":     "config-tenant",
			"clientSecret": "config-secret",
		})

		t.Setenv(EnvAzureClientID, "env-client")
		t.Setenv(EnvAzureTenantID, "env-tenant")
		t.Setenv(EnvAzureClientSecret, "env-secret")

		creds := p.resolveServicePrincipalCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "config-client", creds.ClientID)
		assert.Equal(t, "config-tenant", creds.TenantID)
		assert.Equal(t, "config-secret", creds.ClientSecret)
	})

	t.Run("profile with empty config falls back to env var", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine"
		setProfileConfig(p, map[string]string{
			"clientId": "config-client",
			// tenantId and clientSecret not set → fall back to env
		})

		t.Setenv(EnvAzureClientID, "env-client")
		t.Setenv(EnvAzureTenantID, "env-tenant")
		t.Setenv(EnvAzureClientSecret, "env-secret")

		creds := p.resolveServicePrincipalCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "config-client", creds.ClientID)
		assert.Equal(t, "env-tenant", creds.TenantID)
		assert.Equal(t, "env-secret", creds.ClientSecret)
	})

	t.Run("profile with no config and no env returns nil", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine"
		p.config.ClientID = ""
		p.config.TenantID = ""
		p.config.ClientSecret = ""

		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureTenantID, "")
		t.Setenv(EnvAzureClientSecret, "")

		creds := p.resolveServicePrincipalCredentials()
		assert.Nil(t, creds)
	})

	t.Run("profile with no explicit config falls back to env vars", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine"
		// No setProfileConfig → nothing marked as set, all fall back to env

		t.Setenv(EnvAzureClientID, "env-client")
		t.Setenv(EnvAzureTenantID, "env-tenant")
		t.Setenv(EnvAzureClientSecret, "env-secret")

		creds := p.resolveServicePrincipalCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "env-client", creds.ClientID)
		assert.Equal(t, "env-tenant", creds.TenantID)
		assert.Equal(t, "env-secret", creds.ClientSecret)
	})
}

func TestResolveWorkloadIdentityCredentials(t *testing.T) {
	t.Run("no profile uses env vars only", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "env-client")
		t.Setenv(EnvAzureTenantID, "env-tenant")
		t.Setenv(EnvAzureFederatedToken, "env-fed-token")
		t.Setenv(EnvAzureFederatedTokenFile, "")

		creds := p.resolveWorkloadIdentityCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "env-client", creds.ClientID)
		assert.Equal(t, "env-tenant", creds.TenantID)
		assert.Equal(t, "env-fed-token", creds.Token)
	})

	t.Run("profile prefers config over env vars", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine-a"
		setProfileConfig(p, map[string]string{
			"clientId":       "config-client",
			"tenantId":       "config-tenant",
			"federatedToken": "config-fed-token",
		})

		t.Setenv(EnvAzureClientID, "env-client")
		t.Setenv(EnvAzureTenantID, "env-tenant")
		t.Setenv(EnvAzureFederatedToken, "env-fed-token")
		t.Setenv(EnvAzureFederatedTokenFile, "")

		creds := p.resolveWorkloadIdentityCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "config-client", creds.ClientID)
		assert.Equal(t, "config-tenant", creds.TenantID)
		assert.Equal(t, "config-fed-token", creds.Token)
	})

	t.Run("profile with empty config falls back to env var", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine-a"
		setProfileConfig(p, map[string]string{
			"clientId": "config-client",
			// tenantId and federatedToken not set → fall back to env
		})

		t.Setenv(EnvAzureClientID, "env-client")
		t.Setenv(EnvAzureTenantID, "env-tenant")
		t.Setenv(EnvAzureFederatedToken, "env-fed-token")
		t.Setenv(EnvAzureFederatedTokenFile, "")

		creds := p.resolveWorkloadIdentityCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "config-client", creds.ClientID)
		assert.Equal(t, "env-tenant", creds.TenantID)
		assert.Equal(t, "env-fed-token", creds.Token)
	})

	t.Run("profile with no token source returns nil", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine-a"
		setProfileConfig(p, map[string]string{
			"clientId": "config-client",
			"tenantId": "config-tenant",
			// no federatedToken or federatedTokenFile
		})

		t.Setenv(EnvAzureFederatedToken, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")

		creds := p.resolveWorkloadIdentityCredentials()
		assert.Nil(t, creds)
	})

	t.Run("profile with default config values falls back to env vars", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine-a"
		// Only federatedToken was explicitly set; clientId/tenantId keep defaults
		setProfileConfig(p, map[string]string{
			"federatedToken": "config-fed-token",
		})

		t.Setenv(EnvAzureClientID, "env-client")
		t.Setenv(EnvAzureTenantID, "env-tenant")
		t.Setenv(EnvAzureFederatedToken, "env-fed-token")
		t.Setenv(EnvAzureFederatedTokenFile, "")

		creds := p.resolveWorkloadIdentityCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "env-client", creds.ClientID)
		assert.Equal(t, "env-tenant", creds.TenantID)
		assert.Equal(t, "config-fed-token", creds.Token)
	})

	t.Run("profile with default authority falls back to env var", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine-a"
		setProfileConfig(p, map[string]string{
			"clientId":       "config-client",
			"tenantId":       "config-tenant",
			"federatedToken": "config-fed-token",
			// authority not set → fall back to env
		})

		t.Setenv(EnvAzureAuthorityHost, "https://custom.authority.example.com")
		t.Setenv(EnvAzureFederatedTokenFile, "")

		creds := p.resolveWorkloadIdentityCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "https://custom.authority.example.com", creds.Authority)
	})

	t.Run("profile with explicit authority uses config value", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine-a"
		setProfileConfig(p, map[string]string{
			"clientId":       "config-client",
			"tenantId":       "config-tenant",
			"federatedToken": "config-fed-token",
			"authority":      "https://explicit.authority.example.com",
		})

		t.Setenv(EnvAzureAuthorityHost, "https://env.authority.example.com")
		t.Setenv(EnvAzureFederatedTokenFile, "")

		creds := p.resolveWorkloadIdentityCredentials()
		require.NotNil(t, creds)
		assert.Equal(t, "https://explicit.authority.example.com", creds.Authority)
	})
}

func TestConfigureAuthHandlerWithProfile(t *testing.T) {
	t.Run("profile stored from config", func(t *testing.T) {
		p := &Plugin{}
		cfg := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"profile-client","tenantId":"profile-tenant","clientSecret":"profile-secret"}`),
		}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Profile:  "machine",
			Settings: cfg,
		})
		require.NoError(t, err)
		assert.Equal(t, "machine", p.cfg.Profile)
		assert.Equal(t, "profile-client", p.config.ClientID)
		assert.Equal(t, "profile-tenant", p.config.TenantID)
		assert.Equal(t, "profile-secret", p.config.ClientSecret)
	})

	t.Run("JSON unmarshal tracks set fields", func(t *testing.T) {
		p := &Plugin{}
		cfg := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"my-app","clientSecret":"s3cret"}`),
		}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Profile:  "ci",
			Settings: cfg,
		})
		require.NoError(t, err)
		assert.True(t, p.config.WasSet("clientId"))
		assert.True(t, p.config.WasSet("clientSecret"))
		assert.False(t, p.config.WasSet("tenantId"), "tenantId was not in JSON")
		assert.False(t, p.config.WasSet("authority"), "authority was not in JSON")
	})

	t.Run("empty JSON values treated as unset", func(t *testing.T) {
		p := &Plugin{}
		cfg := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"","tenantId":"","clientSecret":"real-secret"}`),
		}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Profile:  "ci",
			Settings: cfg,
		})
		require.NoError(t, err)
		// Empty strings should not be marked as set
		assert.False(t, p.config.WasSet("clientId"), "empty clientId should not be set")
		assert.False(t, p.config.WasSet("tenantId"), "empty tenantId should not be set")
		assert.True(t, p.config.WasSet("clientSecret"), "non-empty clientSecret should be set")
		// Defaults should be restored for empty required fields
		assert.Equal(t, DefaultClientID, p.config.ClientID)
		assert.Equal(t, DefaultTenantID, p.config.TenantID)
	})
}

func TestGetStatusWithProfileConfig(t *testing.T) {
	t.Run("SP via profile config without env vars", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		p.cfg.Profile = "machine"
		setProfileConfig(p, map[string]string{
			"clientId":     "sp-client",
			"tenantId":     "sp-tenant",
			"clientSecret": "sp-secret",
		})

		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureTenantID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		status, err := p.GetStatus(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
		assert.Equal(t, "sp-client", status.ClientID)
	})
}
