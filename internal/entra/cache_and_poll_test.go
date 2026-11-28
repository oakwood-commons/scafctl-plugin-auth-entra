// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-auth-entra/internal/clock"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugintest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTokenCacheKey(t *testing.T) {
	t.Parallel()

	backingStorePattern := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$`)

	t.Run("produces valid deterministic host secret key for URL and multi-token scopes", func(t *testing.T) {
		t.Parallel()

		scopes := []string{
			"https://graph.microsoft.com/.default",
			"api://my-app-id/Custom.Scope:ReadWrite",
			"https://management.azure.com//user_impersonation offline_access",
			strings.Repeat("https://graph.microsoft.com/Scope.Read ", 20),
		}
		prefixes := []string{
			SecretKeyTokenPrefix,
			"scafctl.auth.entra.776f726b2d70726f66696c65.token.",
		}

		for _, prefix := range prefixes {
			for _, scope := range scopes {
				k1 := buildTokenCacheKey(prefix, "fp-abc123", scope)
				k2 := buildTokenCacheKey(prefix, "fp-abc123", scope)
				assert.Equal(t, k1, k2)
				assert.True(t, strings.HasPrefix(k1, prefix))
				require.NoError(t, sdkplugin.ValidateHostSecretName(k1))
				require.NoError(t, validateStoreSecretName(k1))
				assert.Regexp(t, backingStorePattern, k1)
				assert.NotContains(t, k1, ":")
				assert.NotContains(t, k1, "/")
				assert.NotContains(t, k1, "..")
			}
		}
	})

	t.Run("normalizes whitespace, ordering, and duplicates while isolating distinct inputs", func(t *testing.T) {
		t.Parallel()

		kOrdered := buildTokenCacheKey(SecretKeyTokenPrefix, "fp1", "https://graph.microsoft.com/Group.Read.All https://graph.microsoft.com/User.Read")
		kReordered := buildTokenCacheKey(SecretKeyTokenPrefix, "fp1", "  https://graph.microsoft.com/User.Read\thttps://graph.microsoft.com/Group.Read.All  https://graph.microsoft.com/User.Read ")
		assert.Equal(t, kOrdered, kReordered)

		kDifferentFP := buildTokenCacheKey(SecretKeyTokenPrefix, "fp2", "https://graph.microsoft.com/Group.Read.All https://graph.microsoft.com/User.Read")
		kDifferentScope := buildTokenCacheKey(SecretKeyTokenPrefix, "fp1", "https://graph.microsoft.com/.default")
		assert.NotEqual(t, kOrdered, kDifferentFP)
		assert.NotEqual(t, kOrdered, kDifferentScope)
		assert.Empty(t, normalizeScope("   \t  "))
	})
}

func TestCrossInvocationCachingAllFlows_PlugintestHost(t *testing.T) {
	newPluginWithHost := func(t *testing.T, hostClient *sdkplugin.HostServiceClient, httpMock *MockHTTPClient) *Plugin {
		t.Helper()
		p := &Plugin{
			httpClient:       httpMock,
			graphClient:      NewMockGraphClient(),
			cachedHostClient: hostClient,
		}
		cfgCtx := sdkplugin.WithHostClient(context.Background(), hostClient)
		require.NoError(t, p.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
		}))
		p.httpClient = httpMock
		p.cachedHostClient = hostClient
		p.clock = clock.Mock{}
		return p
	}

	t.Run("device_code user session persists cached token and reuses across CLI invocations", func(t *testing.T) {
		clearCredentialEnv(t)
		hostClient, fakeHost := plugintest.NewFakeHostClient(t)
		ctx := context.Background()
		scope := "https://graph.microsoft.com/.default"

		// Invocation 1: device_code login + initial GetToken mints over HTTP and caches.
		http1 := NewMockHTTPClient()
		http1.AddResponse(http.StatusOK, DeviceCodeResponse{
			DeviceCode:      "dc-code",
			UserCode:        "ABCD-EFGH",
			VerificationURI: "https://microsoft.com/devicelogin",
			ExpiresIn:       900,
			Interval:        5,
		})
		http1.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "login-at",
			RefreshToken: "session-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken: makeTestJWT(map[string]any{
				"sub": "user-sub",
				"oid": "user-oid",
				"tid": "tenant-1",
			}),
		})
		http1.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "minted-user-at",
			RefreshToken: "session-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        scope + " offline_access",
		})

		p1 := newPluginWithHost(t, hostClient, http1)
		_, err := p1.Login(ctx, HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowDeviceCode,
			Timeout: 30 * time.Second,
		}, nil)
		require.NoError(t, err)

		tok1, err := p1.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "minted-user-at", tok1.AccessToken)
		assert.Equal(t, scope, tok1.Scope)
		require.Len(t, http1.GetRequests(), 3)

		// Verify secret store contains cached token entry under a valid key.
		var tokenSecretKeys []string
		for k := range fakeHost.Secrets() {
			if strings.HasPrefix(k, SecretKeyTokenPrefix) {
				tokenSecretKeys = append(tokenSecretKeys, k)
			}
		}
		require.Len(t, tokenSecretKeys, 1)

		// Invocation 2: fresh Plugin instance with zero queued HTTP responses must hit host cache.
		http2 := NewMockHTTPClient()
		p2 := newPluginWithHost(t, hostClient, http2)
		tok2, err := p2.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "minted-user-at", tok2.AccessToken)
		assert.Equal(t, scope, tok2.Scope)
		assert.Empty(t, http2.GetRequests(), "second CLI invocation must reuse host-cached access token without network call")

		cachedList, err := p2.ListCachedTokens(ctx, HandlerName)
		require.NoError(t, err)
		var accessInfo *auth.CachedTokenInfo
		for _, item := range cachedList {
			if item.TokenKind == "access" {
				accessInfo = item
				break
			}
		}
		require.NotNil(t, accessInfo, "ListCachedTokens must include cached access token")
		assert.Equal(t, scope, accessInfo.Scope)
		assert.Equal(t, auth.FlowDeviceCode, accessInfo.Flow)
	})

	t.Run("service_principal persists cached token and reuses across CLI invocations", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		hostClient, _ := plugintest.NewFakeHostClient(t)
		ctx := context.Background()
		scope := "https://management.azure.com/.default"

		http1 := NewMockHTTPClient()
		http1.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "sp-cached-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		p1 := newPluginWithHost(t, hostClient, http1)
		tok1, err := p1.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "sp-cached-at", tok1.AccessToken)
		require.Len(t, http1.GetRequests(), 1)

		http2 := NewMockHTTPClient()
		p2 := newPluginWithHost(t, hostClient, http2)
		tok2, err := p2.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "sp-cached-at", tok2.AccessToken)
		assert.Equal(t, scope, tok2.Scope)
		assert.Empty(t, http2.GetRequests(), "second SP invocation must reuse cached token")

		cachedList, err := p2.ListCachedTokens(ctx, HandlerName)
		require.NoError(t, err)
		require.Len(t, cachedList, 1)
		assert.Equal(t, "access", cachedList[0].TokenKind)
		assert.Equal(t, scope, cachedList[0].Scope)
		assert.Equal(t, auth.FlowServicePrincipal, cachedList[0].Flow)
	})

	t.Run("workload_identity persists cached token and reuses across CLI invocations", func(t *testing.T) {
		clearCredentialEnv(t)
		setWorkloadIdentityEnv(t)
		hostClient, _ := plugintest.NewFakeHostClient(t)
		ctx := context.Background()
		scope := "api://cluster-api/.default"

		http1 := NewMockHTTPClient()
		http1.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "wi-cached-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		p1 := newPluginWithHost(t, hostClient, http1)
		tok1, err := p1.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "wi-cached-at", tok1.AccessToken)
		require.Len(t, http1.GetRequests(), 1)

		http2 := NewMockHTTPClient()
		p2 := newPluginWithHost(t, hostClient, http2)
		tok2, err := p2.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "wi-cached-at", tok2.AccessToken)
		assert.Equal(t, scope, tok2.Scope)
		assert.Empty(t, http2.GetRequests(), "second WI invocation must reuse cached token")

		cachedList, err := p2.ListCachedTokens(ctx, HandlerName)
		require.NoError(t, err)
		require.Len(t, cachedList, 1)
		assert.Equal(t, "access", cachedList[0].TokenKind)
		assert.Equal(t, scope, cachedList[0].Scope)
		assert.Equal(t, auth.FlowWorkloadIdentity, cachedList[0].Flow)
	})

	t.Run("switching between service_principal and workload_identity in either direction isolates cache namespaces", func(t *testing.T) {
		scope := "https://management.azure.com/.default"
		profileCtx := auth.WithProfile(context.Background(), "shared-machine-profile")

		// Direction 1: service_principal -> workload_identity with identical client, tenant, authority, profile, and scope.
		clearCredentialEnv(t)
		t.Setenv(EnvAzureClientID, "shared-machine-client")
		t.Setenv(EnvAzureTenantID, "shared-machine-tenant")
		t.Setenv(EnvAzureClientSecret, "sp-secret")
		hostSPToWI, _ := plugintest.NewFakeHostClient(t)

		httpSP1 := NewMockHTTPClient().AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "sp-first-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		pSP1 := newPluginWithHost(t, hostSPToWI, httpSP1)
		tokSP1, err := pSP1.GetToken(profileCtx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "sp-first-at", tokSP1.AccessToken)
		assert.Equal(t, auth.FlowServicePrincipal, tokSP1.Flow)
		require.Len(t, httpSP1.GetRequests(), 1)

		// Switch credential source to workload identity against the same host store.
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedToken, "federated-token")

		httpWI1 := NewMockHTTPClient().AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "wi-second-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		pWI1 := newPluginWithHost(t, hostSPToWI, httpWI1)
		tokWI1, err := pWI1.GetToken(profileCtx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "wi-second-at", tokWI1.AccessToken)
		assert.Equal(t, auth.FlowWorkloadIdentity, tokWI1.Flow)
		require.Len(t, httpWI1.GetRequests(), 1, "workload_identity must not reuse service_principal cached token")

		cachedSPToWI, err := pWI1.ListCachedTokens(profileCtx, HandlerName)
		require.NoError(t, err)
		require.Len(t, cachedSPToWI, 2)

		// Direction 2: workload_identity -> service_principal with identical client, tenant, authority, profile, and scope.
		clearCredentialEnv(t)
		t.Setenv(EnvAzureClientID, "shared-machine-client")
		t.Setenv(EnvAzureTenantID, "shared-machine-tenant")
		t.Setenv(EnvAzureFederatedToken, "federated-token")
		hostWIToSP, _ := plugintest.NewFakeHostClient(t)

		httpWI2 := NewMockHTTPClient().AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "wi-first-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		pWI2 := newPluginWithHost(t, hostWIToSP, httpWI2)
		tokWI2, err := pWI2.GetToken(profileCtx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "wi-first-at", tokWI2.AccessToken)
		assert.Equal(t, auth.FlowWorkloadIdentity, tokWI2.Flow)
		require.Len(t, httpWI2.GetRequests(), 1)

		// Switch credential source to service principal against the same host store.
		t.Setenv(EnvAzureFederatedToken, "")
		t.Setenv(EnvAzureClientSecret, "sp-secret")

		httpSP2 := NewMockHTTPClient().AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "sp-second-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		pSP2 := newPluginWithHost(t, hostWIToSP, httpSP2)
		tokSP2, err := pSP2.GetToken(profileCtx, HandlerName, sdkplugin.TokenRequest{Scope: scope})
		require.NoError(t, err)
		assert.Equal(t, "sp-second-at", tokSP2.AccessToken)
		assert.Equal(t, auth.FlowServicePrincipal, tokSP2.Flow)
		require.Len(t, httpSP2.GetRequests(), 1, "service_principal must not reuse workload_identity cached token")

		cachedWIToSP, err := pSP2.ListCachedTokens(profileCtx, HandlerName)
		require.NoError(t, err)
		require.Len(t, cachedWIToSP, 2)
	})
}

func TestCacheListSecretsRegexPattern(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	prefix := SecretKeyTokenPrefix
	wantPattern := "^" + regexp.QuoteMeta(prefix)

	fake := newFakeHostService()
	var observedPatterns []string
	fake.listSecretsFunc = func(_ context.Context, pattern string) error {
		observedPatterns = append(observedPatterns, pattern)
		return nil
	}
	hostClient := newFakeHostClient(fake)

	expiredKey := buildTokenCacheKey(prefix, "fp-expired", "https://graph.microsoft.com/.default")
	validKey := buildTokenCacheKey(prefix, "fp-valid", "https://management.azure.com/.default")
	// Unescaped dots in prefix would match 'X' if prefix were compiled without QuoteMeta;
	// unanchored regex would match "other." + prefix.
	dotWildcardDecoy := "scafctlXauthXentraXtokenXdecoy"
	unanchoredDecoy := "other." + prefix + "decoy"

	require.NoError(t, cacheSet(ctx, hostClient, expiredKey, &auth.Token{
		AccessToken: "exp-tok",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(-10 * time.Minute),
		Scope:       "https://graph.microsoft.com/.default",
		Flow:        auth.FlowInteractive,
	}))
	require.NoError(t, cacheSet(ctx, hostClient, validKey, &auth.Token{
		AccessToken: "val-tok",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(time.Hour),
		Scope:       "https://management.azure.com/.default",
		Flow:        auth.FlowInteractive,
	}))
	require.NoError(t, cacheSet(ctx, hostClient, dotWildcardDecoy, &auth.Token{
		AccessToken: "decoy-dot",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(-10 * time.Minute),
	}))
	require.NoError(t, cacheSet(ctx, hostClient, unanchoredDecoy, &auth.Token{
		AccessToken: "decoy-anchor",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(-10 * time.Minute),
	}))

	entries, err := cacheListEntries(ctx, hostClient, prefix)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	purged, err := cachePurgeExpired(ctx, hostClient, prefix)
	require.NoError(t, err)
	assert.Equal(t, 1, purged)

	require.NoError(t, cacheClear(ctx, logr.Discard(), hostClient, prefix))

	assert.Equal(t, []string{wantPattern, wantPattern, wantPattern}, observedPatterns)
	assert.Contains(t, fake.secrets, dotWildcardDecoy, "non-prefix decoy must remain untouched")
	assert.Contains(t, fake.secrets, unanchoredDecoy, "unanchored decoy must remain untouched")
	assert.NotContains(t, fake.secrets, validKey)
	assert.NotContains(t, fake.secrets, expiredKey)
}

func TestFakeHostServiceSecretValidationAndRegex(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)

	invalidNames := []string{
		"",
		"scafctl.auth.entra.token.fp:https://graph.microsoft.com/.default",
		"scafctl/auth/entra/token",
		"scafctl..auth",
		".leading-dot",
		"-leading-dash",
		strings.Repeat("a", 256),
	}
	for _, bad := range invalidNames {
		err := hostClient.SetSecret(ctx, bad, "val")
		require.Error(t, err, "SetSecret should reject %q", bad)
		_, _, err = hostClient.GetSecret(ctx, bad)
		require.Error(t, err, "GetSecret should reject %q", bad)
		err = hostClient.DeleteSecret(ctx, bad)
		require.Error(t, err, "DeleteSecret should reject %q", bad)
	}

	_, err := hostClient.ListSecrets(ctx, "[invalid-regex")
	require.Error(t, err)

	_, err = hostClient.ListSecrets(ctx, strings.Repeat("a", sdkplugin.MaxHostSecretPatternLength+1))
	require.Error(t, err)
}

type recordingPollClock struct {
	mu     sync.Mutex
	events *[]string
	waits  []time.Duration
	onWait func(call int, d time.Duration) error
}

func (c *recordingPollClock) NewTicker(d time.Duration) clock.Ticker {
	return clock.Mock{}.NewTicker(d)
}

func (c *recordingPollClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.waits = append(c.waits, d)
	call := len(c.waits)
	if c.events != nil {
		*c.events = append(*c.events, "sleep:"+d.String())
	}
	fn := c.onWait
	c.mu.Unlock()
	if fn != nil {
		if err := fn(call, d); err != nil {
			return err
		}
	}
	return ctx.Err()
}

type hookHTTPClient struct {
	fn func(ctx context.Context, call int) (*http.Response, error)
	mu sync.Mutex
	n  int
}

func (h *hookHTTPClient) PostForm(ctx context.Context, _ string, _ url.Values) (*http.Response, error) {
	h.mu.Lock()
	h.n++
	call := h.n
	h.mu.Unlock()
	return h.fn(ctx, call)
}

func TestDeviceFlowPollPostResponseSpacingAndErrors(t *testing.T) {
	t.Parallel()

	t.Run("schedules each wait after HTTP response completes and honors slow_down plus transient retry", func(t *testing.T) {
		t.Parallel()

		var events []string
		recClock := &recordingPollClock{events: &events}

		mockInner := NewMockHTTPClient()
		// Poll 1: transient network failure
		mockInner.AddError(errors.New("temporary connection reset"))
		// Poll 2: authorization_pending
		mockInner.AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "authorization_pending",
			ErrorDescription: "pending",
		})
		// Poll 3: slow_down without explicit server interval (+5s -> 10s base + 1s safety = 11s)
		mockInner.AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "slow_down",
			ErrorDescription: "polling too fast",
		})
		// Poll 4: slow_down with larger server-supplied interval=20 (20s base + 1s safety = 21s)
		mockInner.AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "slow_down",
			ErrorDescription: "polling too fast",
			Interval:         20,
		})
		// Poll 5: success
		mockInner.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "polled-at",
			RefreshToken: "polled-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})

		p, _ := newTestPlugin(t, nil, nil)
		p.clock = recClock
		p.httpClient = &hookHTTPClient{
			fn: func(ctx context.Context, call int) (*http.Response, error) {
				events = append(events, "http_start")
				resp, err := mockInner.PostForm(ctx, "https://login.microsoftonline.com/common/oauth2/v2.0/token", nil)
				events = append(events, "http_end")
				_ = call
				return resp, err
			},
		}

		tok, err := p.pollForToken(context.Background(), p.config, "common", &DeviceCodeResponse{
			DeviceCode: "dc-1",
			Interval:   5,
		})
		require.NoError(t, err)
		assert.Equal(t, "polled-at", tok.AccessToken)

		// Verify strict alternation: every wait occurs strictly after the prior HTTP call completes,
		// and includes the +1s safety margin on top of the base interval.
		assert.Equal(t, []string{
			"sleep:6s", "http_start", "http_end",
			"sleep:6s", "http_start", "http_end",
			"sleep:6s", "http_start", "http_end",
			"sleep:11s", "http_start", "http_end",
			"sleep:21s", "http_start", "http_end",
		}, events)
	})

	t.Run("maps access_denied, context cancellation, AADSTS hints, and non-AADSTS errors", func(t *testing.T) {
		t.Parallel()

		// access_denied -> cancelled by user
		httpDenied := NewMockHTTPClient().AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "access_denied",
			ErrorDescription: "user denied request",
		})
		p1, _ := newTestPlugin(t, httpDenied, nil)
		p1.clock = clock.Mock{}
		_, err := p1.pollForToken(context.Background(), p1.config, "common", &DeviceCodeResponse{DeviceCode: "dc", Interval: 5})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentication cancelled by user")

		// context cancellation during sleep -> authentication timed out
		ctx, cancel := context.WithCancel(context.Background())
		p2, _ := newTestPlugin(t, NewMockHTTPClient(), nil)
		p2.clock = &recordingPollClock{
			onWait: func(_ int, _ time.Duration) error {
				cancel()
				return ctx.Err()
			},
		}
		_, err = p2.pollForToken(ctx, p2.config, "common", &DeviceCodeResponse{DeviceCode: "dc", Interval: 5})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentication timed out")

		// unrecognized error with AADSTS and CRLF lines -> formatted hint with space-normalized text,
		// preserved even if outer ctx cancels before post-poll classification.
		aadstsCtx, cancelAADSTS := context.WithCancel(context.Background())
		defer cancelAADSTS()
		httpAADSTS := NewMockHTTPClient().AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "AADSTS700016: Application not found.\r\nTrace ID: 1111\r\nCorrelation ID: 2222",
		})
		p3, _ := newTestPlugin(t, nil, nil)
		p3.clock = clock.Mock{}
		p3.httpClient = &hookHTTPClient{
			fn: func(ctx context.Context, _ int) (*http.Response, error) {
				resp, postErr := httpAADSTS.PostForm(ctx, "https://login.microsoftonline.com/common/oauth2/v2.0/token", nil)
				cancelAADSTS()
				return resp, postErr
			},
		}
		_, err = p3.pollForToken(aadstsCtx, p3.config, "common", &DeviceCodeResponse{DeviceCode: "dc", Interval: 5})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AADSTS700016: Application not found. Trace ID: 1111 Correlation ID: 2222")
		assert.Contains(t, err.Error(), "Hint:")
		assert.NotContains(t, err.Error(), "authentication timed out")
		assert.Len(t, httpAADSTS.GetRequests(), 1)

		// access_denied when outer ctx cancels right after HTTP response -> still reports cancelled by user.
		deniedCtx, cancelDenied := context.WithCancel(context.Background())
		defer cancelDenied()
		httpDeniedRace := NewMockHTTPClient().AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "access_denied",
			ErrorDescription: "user denied request",
		})
		p3b, _ := newTestPlugin(t, nil, nil)
		p3b.clock = clock.Mock{}
		p3b.httpClient = &hookHTTPClient{
			fn: func(ctx context.Context, _ int) (*http.Response, error) {
				resp, postErr := httpDeniedRace.PostForm(ctx, "https://login.microsoftonline.com/common/oauth2/v2.0/token", nil)
				cancelDenied()
				return resp, postErr
			},
		}
		_, err = p3b.pollForToken(deniedCtx, p3b.config, "common", &DeviceCodeResponse{DeviceCode: "dc", Interval: 5})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentication cancelled by user")
		assert.NotContains(t, err.Error(), "authentication timed out")

		// mid-body read timeout/reset while outer ctx is still active -> retried as transient error.
		successMock := NewMockHTTPClient().AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "after-body-reset-at",
			RefreshToken: "after-body-reset-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
		var bodyResetWaits []time.Duration
		pMidBody, _ := newTestPlugin(t, nil, nil)
		pMidBody.clock = &recordingPollClock{
			onWait: func(_ int, d time.Duration) error {
				bodyResetWaits = append(bodyResetWaits, d)
				return nil
			},
		}
		pMidBody.httpClient = &hookHTTPClient{
			fn: func(ctx context.Context, call int) (*http.Response, error) {
				if call == 1 {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(&failingReader{err: context.DeadlineExceeded}),
					}, nil
				}
				return successMock.PostForm(ctx, "https://login.microsoftonline.com/common/oauth2/v2.0/token", nil)
			},
		}
		tokAfterReset, err := pMidBody.pollForToken(context.Background(), pMidBody.config, "common", &DeviceCodeResponse{DeviceCode: "dc", Interval: 5})
		require.NoError(t, err)
		assert.Equal(t, "after-body-reset-at", tokAfterReset.AccessToken)
		// First wait is 5s + 1s = 6s; timeout error doubles base interval to 10s + 1s = 11s.
		assert.Equal(t, []time.Duration{6 * time.Second, 11 * time.Second}, bodyResetWaits)

		// unrecognized error without AADSTS -> immediate failure with sanitized description
		httpOther := NewMockHTTPClient().AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "bad_verification_code",
			ErrorDescription: "\x1b[31minvalid device code\x1b[0m",
		})
		p4, _ := newTestPlugin(t, httpOther, nil)
		p4.clock = clock.Mock{}
		_, err = p4.pollForToken(context.Background(), p4.config, "common", &DeviceCodeResponse{DeviceCode: "dc", Interval: 5})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token request failed: bad_verification_code")
		assert.NotContains(t, err.Error(), "\x1b")
		assert.Len(t, httpOther.GetRequests(), 1)
	})

	t.Run("production DefaultHTTPClient disables transport retries on device token poll so PollDeviceToken schedules every retry", func(t *testing.T) {
		t.Parallel()

		var evMu sync.Mutex
		var events []string
		recordEvent := func(ev string) {
			evMu.Lock()
			events = append(events, ev)
			evMu.Unlock()
		}

		var tokenHits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			n := tokenHits.Add(1)
			recordEvent(fmt.Sprintf("token_post:%d", n))

			switch n {
			case 1:
				// Retryable HTTP 503 non-JSON response.
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("upstream service unavailable"))
			case 2:
				// Abrupt connection close (transport-level read/EOF failure).
				if hj, ok := w.(http.Hijacker); ok {
					if conn, _, hErr := hj.Hijack(); hErr == nil {
						_ = conn.Close()
						return
					}
				}
				w.WriteHeader(http.StatusBadGateway)
			case 3:
				// HTTP 429 carrying an RFC 8628 slow_down payload (+5s -> 10s + 1s = 11s).
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(TokenErrorResponse{
					Error:            "slow_down",
					ErrorDescription: "polling too fast",
				})
			case 4:
				// HTTP 500 JSON server error.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(TokenErrorResponse{
					Error:            "temporarily_unavailable",
					ErrorDescription: "backend busy",
				})
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(TokenResponse{
					AccessToken:  "prod-polled-at",
					RefreshToken: "prod-polled-rt",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
				})
			}
		}))
		t.Cleanup(srv.Close)

		settingsRaw, err := json.Marshal(map[string]any{
			"clientId": "prod-poll-client",
			"tenantId": "common",
			"httpClient": map[string]any{
				"allowPrivateIPs": true,
			},
		})
		require.NoError(t, err)

		p := &Plugin{}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
			Settings: map[string]json.RawMessage{
				HandlerName: settingsRaw,
			},
		}))
		t.Cleanup(func() { _ = p.StopAuthHandler(context.Background(), HandlerName) })

		_, isDefault := p.httpClient.(*DefaultHTTPClient)
		require.True(t, isDefault, "ConfigureAuthHandler must wire production *DefaultHTTPClient")

		p.clock = &recordingPollClock{
			onWait: func(_ int, d time.Duration) error {
				recordEvent("sleep:" + d.String())
				return nil
			},
		}

		pollCfg := *p.config
		pollCfg.Authority = srv.URL
		tok, err := p.pollForToken(context.Background(), &pollCfg, "common", &DeviceCodeResponse{
			DeviceCode: "dc-prod",
			Interval:   5,
		})
		require.NoError(t, err)
		assert.Equal(t, "prod-polled-at", tok.AccessToken)
		assert.Equal(t, int32(5), tokenHits.Load(), "DefaultHTTPClient must not issue hidden transport retries")

		evMu.Lock()
		gotEvents := append([]string(nil), events...)
		evMu.Unlock()
		assert.Equal(t, []string{
			"sleep:6s", "token_post:1",
			"sleep:6s", "token_post:2",
			"sleep:6s", "token_post:3",
			"sleep:11s", "token_post:4",
			"sleep:11s", "token_post:5",
		}, gotEvents)
	})
}

type failingReader struct {
	err error
}

func (f *failingReader) Read(_ []byte) (int, error) {
	return 0, f.err
}
