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
