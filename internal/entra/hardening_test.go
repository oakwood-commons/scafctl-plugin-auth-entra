// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-auth-entra/internal/clock"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cacheEntryJSON marshals a valid cached-token entry for the given access token.
func cacheEntryJSON(t *testing.T, accessToken string) string {
	t.Helper()
	entry := tokenCacheEntry{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		CachedAt:    time.Now(),
	}
	b, err := json.Marshal(entry)
	require.NoError(t, err)
	return string(b)
}

// --- (a) cache key derived from the effective identity, cleared on login ---

func TestUserSessionTokenKeyFromEffectiveIdentity(t *testing.T) {
	clearCredentialEnv(t)
	graphScope := "https://graph.microsoft.com/.default"

	// No mock responses: a cache miss that mints would blow up the response
	// queue, so this test passes only on a pure cache hit.
	p, fake := newTestPlugin(t, NewMockHTTPClient(), nil)
	ctx := context.Background()

	// Stored session metadata deliberately disagrees with the handler
	// config: minting uses the metadata identity, so the cache key must too.
	metadata := auth.HandlerMetadata{
		Claims:        &auth.Claims{ObjectID: "user-oid-1"},
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		LastLoginFlow: auth.FlowInteractive,
		SessionID:     "sess-9",
		ClientID:      "meta-client",
	}
	metadata.SetMeta(MetaKeyTenantID, "meta-tenant")
	metaBytes, err := json.Marshal(metadata)
	require.NoError(t, err)
	fake.secrets[SecretKeyRefreshToken] = "rt"
	fake.secrets[SecretKeyMetadata] = string(metaBytes)

	// Entry keyed on the effective (metadata) identity must be served.
	effectiveKey := userTokenCacheKeyFor(p, &metadata, graphScope)
	fake.secrets[effectiveKey] = cacheEntryJSON(t, "good-token")

	// Entry sharing the same session ID but keyed on the config identity
	// (no metadata client/tenant, no oid) must NOT be served.
	cfgMeta := auth.HandlerMetadata{ClientID: p.config.ClientID, SessionID: metadata.SessionID}
	cfgMeta.SetMeta(MetaKeyTenantID, p.config.TenantID)
	configKey := userTokenCacheKeyFor(p, &cfgMeta, graphScope)
	fake.secrets[configKey] = cacheEntryJSON(t, "wrong-token")

	resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
	require.NoError(t, err)
	assert.Equal(t, "good-token", resp.AccessToken, "the cache key must derive from the stored session's identity, not the config")
}

// userTokenCacheKeyFor mirrors userSessionToken's cache key for an explicit
// metadata value.
func userTokenCacheKeyFor(p *Plugin, metadata *auth.HandlerMetadata, scope string) string {
	return SecretKeyTokenPrefix + p.userSessionFingerprint(metadata) + ":" + scope
}

func TestLoginClearsUserTokenCache(t *testing.T) {
	graphScope := "https://graph.microsoft.com/.default"

	t.Run("device code login drops tokens from a previous identity", func(t *testing.T) {
		clearCredentialEnv(t)
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, DeviceCodeResponse{
			DeviceCode: "dc", UserCode: "UC", VerificationURI: "https://example.com",
			ExpiresIn: 900, Interval: 5,
		})
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "new-at", RefreshToken: "new-rt", TokenType: "Bearer", ExpiresIn: 3600,
			IDToken: makeTestJWT(map[string]any{"sub": "new-user", "oid": "new-oid", "tid": "new-tenant"}),
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		p.clock = clock.Mock{}

		// Simulate an already-logged-in identity with a cached access token.
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))
		staleKey := userTokenCacheKey(p, "sess-1", graphScope)
		fake.secrets[staleKey] = cacheEntryJSON(t, "stale-token")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowDeviceCode, Timeout: 30 * time.Second,
		}, nil)
		require.NoError(t, err)

		_, stillCached := fake.secrets[staleKey]
		assert.False(t, stillCached, "login must clear tokens cached for a previous identity")
	})

	t.Run("interactive login drops tokens from a previous identity", func(t *testing.T) {
		clearCredentialEnv(t)
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "new-at", RefreshToken: "new-rt", TokenType: "Bearer", ExpiresIn: 3600,
			IDToken: makeTestJWT(map[string]any{"sub": "new-user", "oid": "new-oid", "tid": "new-tenant"}),
		})

		p, fake := newTestPlugin(t, httpMock, nil)

		// Simulate an already-logged-in identity with a cached access token.
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))
		staleKey := userTokenCacheKey(p, "sess-1", graphScope)
		fake.secrets[staleKey] = cacheEntryJSON(t, "stale-token")

		// Simulate the browser redirecting back to the loopback callback.
		p.openBrowser = func(_ context.Context, authURL string) error {
			go func() {
				u, err := url.Parse(authURL)
				if err != nil {
					return
				}
				cb, err := url.Parse(u.Query().Get("redirect_uri"))
				if err != nil {
					return
				}
				q := cb.Query()
				q.Set("code", "auth-code-123")
				q.Set("state", u.Query().Get("state"))
				cb.RawQuery = q.Encode()
				resp, err := http.Get(cb.String()) //nolint:noctx // test helper hitting a local callback server
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
			return nil
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive, Timeout: 30 * time.Second,
		}, nil)
		require.NoError(t, err)

		_, stillCached := fake.secrets[staleKey]
		assert.False(t, stillCached, "login must clear tokens cached for a previous identity")
	})

	t.Run("second login without logout never serves the first identity's token", func(t *testing.T) {
		clearCredentialEnv(t)
		httpMock := NewMockHTTPClient()
		firstToken := TokenResponse{
			AccessToken: "first-at", RefreshToken: "first-rt", TokenType: "Bearer", ExpiresIn: 3600,
			IDToken: makeTestJWT(map[string]any{"sub": "user-1", "oid": "oid-1", "tid": "tenant-1"}),
		}
		secondToken := TokenResponse{
			AccessToken: "second-at", RefreshToken: "second-rt", TokenType: "Bearer", ExpiresIn: 3600,
			IDToken: makeTestJWT(map[string]any{"sub": "user-2", "oid": "oid-2", "tid": "tenant-2"}),
		}
		// Login #1: device code + token poll.
		httpMock.AddResponse(200, DeviceCodeResponse{
			DeviceCode: "dc-1", UserCode: "UC", VerificationURI: "https://example.com",
			ExpiresIn: 900, Interval: 5,
		})
		httpMock.AddResponse(200, firstToken)
		// GetToken #1: cache miss, mint via refresh token.
		httpMock.AddResponse(200, firstToken)
		// Login #2 (no logout): device code + token poll.
		httpMock.AddResponse(200, DeviceCodeResponse{
			DeviceCode: "dc-2", UserCode: "UC", VerificationURI: "https://example.com",
			ExpiresIn: 900, Interval: 5,
		})
		httpMock.AddResponse(200, secondToken)
		// GetToken #2: must mint again (the first identity's cache entries
		// were dropped by login #2).
		httpMock.AddResponse(200, secondToken)

		p, _ := newTestPlugin(t, httpMock, nil)
		p.clock = clock.Mock{}
		ctx := context.Background()

		_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowDeviceCode, Timeout: 30 * time.Second,
		}, nil)
		require.NoError(t, err)

		firstResp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
		require.NoError(t, err)
		require.Equal(t, "first-at", firstResp.AccessToken)

		_, err = p.Login(ctx, HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowDeviceCode, Timeout: 30 * time.Second,
		}, nil)
		require.NoError(t, err)

		secondResp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
		require.NoError(t, err)
		assert.Equal(t, "second-at", secondResp.AccessToken, "must not serve a token cached by the first identity")
	})
}

// --- (b) authority validation ---

func TestConfigAuthorityValidation(t *testing.T) {
	t.Run("default authority is valid", func(t *testing.T) {
		require.NoError(t, DefaultConfig().Validate())
	})

	t.Run("https authority accepted", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Authority = "https://login.microsoftonline.us"
		require.NoError(t, cfg.Validate())
	})

	t.Run("http authority rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Authority = "http://login.microsoftonline.com"
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})

	t.Run("host-less authority rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Authority = "login.microsoftonline.com"
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authority")
	})

	t.Run("https authority without host rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Authority = "https://"
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "host")
	})

	t.Run("ConfigureAuthHandler rejects http authority", func(t *testing.T) {
		p := &Plugin{}
		cfg := map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"cid","tenantId":"tid","authority":"http://login.example.com"}`),
		}
		err := p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			Settings: cfg,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authority")
	})
}

func TestServerConfigAuthorityValidation(t *testing.T) {
	newConfig := func(authority string) *ServerConfig {
		return &ServerConfig{
			ClientID:   "cid",
			TenantID:   "tid",
			ServerFlow: auth.FlowClientCredentials,
			Credential: CredentialConfig{ClientSecret: "env://SECRET"},
			Authority:  authority,
		}
	}

	t.Run("http authority rejected", func(t *testing.T) {
		err := newConfig("http://login.microsoftonline.com").Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})

	t.Run("host-less authority rejected", func(t *testing.T) {
		err := newConfig("login.microsoftonline.com").Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authority")
	})

	t.Run("https authority without host rejected", func(t *testing.T) {
		err := newConfig("https://").Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "host")
	})

	t.Run("https authority with port but no hostname rejected", func(t *testing.T) {
		err := newConfig("https://:443").Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "host")
	})

	t.Run("custom https authority accepted", func(t *testing.T) {
		require.NoError(t, newConfig("https://custom.auth").Validate())
	})

	t.Run("default authority accepted", func(t *testing.T) {
		require.NoError(t, newConfig("").Validate())
	})
}

// --- (c) callback error sanitization ---

func TestSanitizeControlChars(t *testing.T) {
	assert.Equal(t, "plain error text", sanitizeControlChars("plain error text"))
	assert.Equal(t, "error[31mred[0m", sanitizeControlChars("error\x1b[31mred\x1b[0m"), "ESC must be stripped")
	assert.Equal(t, "ab", sanitizeControlChars("a\x00b"), "NUL must be stripped")
	assert.Equal(t, "ab", sanitizeControlChars("a\x7fb"), "DEL must be stripped")
	assert.Equal(t, "ab", sanitizeControlChars("a\u0085b"), "C1 (NEL) must be stripped")
	assert.Equal(t, "", sanitizeControlChars("\x1b\n\t"))
}

func TestAuthCodeLoginCallbackErrorSanitized(t *testing.T) {
	clearCredentialEnv(t)
	p, _ := newTestPlugin(t, nil, nil)

	// Redirect the "browser" straight back to the loopback callback with an
	// error whose description carries terminal escape codes.
	p.openBrowser = func(_ context.Context, authURL string) error {
		go func() {
			u, err := url.Parse(authURL)
			if err != nil {
				return
			}
			cb, err := url.Parse(u.Query().Get("redirect_uri"))
			if err != nil {
				return
			}
			q := cb.Query()
			q.Set("error", "access_denied")
			q.Set("error_description", "\x1b[31mred\x1b[0m user denied consent")
			cb.RawQuery = q.Encode()
			resp, err := http.Get(cb.String()) //nolint:noctx // test helper hitting a local callback server
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}

	_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow: auth.FlowInteractive, Timeout: 30 * time.Second,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access_denied")
	assert.NotContains(t, err.Error(), "\x1b", "control characters must not survive into the returned error")
	assert.Contains(t, err.Error(), "[31mred[0m", "visible text must be kept")
}
