// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	manager "github.com/oakwood-commons/go-flight/cache"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingTokenServer returns a server that counts requests and returns a fixed token.
func countingTokenServer(t *testing.T, token string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	return ts, &calls
}

func TestDefaultCacheConfig(t *testing.T) {
	cfg := DefaultCacheConfig()
	assert.Equal(t, DefaultExpiryThreshold, cfg.ExpiryThreshold)
	assert.Equal(t, DefaultSlowThreshold, cfg.SlowThreshold)
	assert.False(t, cfg.RetryOnError)
	assert.Equal(t, DefaultStoreSize, cfg.StoreSize)
	assert.Equal(t, DefaultStoreBuffer, cfg.StoreBuffer)
	assert.Equal(t, DefaultCleanupInterval, cfg.CleanupInterval)
}

func TestBuildServerMode_WithOptions_CustomCacheConfig(t *testing.T) {
	t.Setenv("TEST_CS_OPT", "secret")
	sc := &ServerConfig{
		ClientID:   "cid",
		TenantID:   "tid",
		ServerFlow: auth.FlowClientCredentials,
		Credential: CredentialConfig{ClientSecret: "env://TEST_CS_OPT"},
	}
	opts := &ServerModeOptions{
		HTTPClient: NewMockHTTPClient(),
		CacheConfig: &CacheConfig{
			ExpiryThreshold: 1 * time.Second,
			SlowThreshold:   0,
			RetryOnError:    false,
			StoreSize:       10,
			StoreBuffer:     0,
			CleanupInterval: 0,
		},
	}
	sm, err := buildServerMode(context.Background(), sc, opts)
	require.NoError(t, err)
	assert.NotNil(t, sm)
	assert.NotNil(t, sm.cacheManager)
}

func TestBuildServerMode_WithOptions_InjectedManager(t *testing.T) {
	t.Setenv("TEST_CS_INJ", "secret")
	sc := &ServerConfig{
		ClientID:   "cid",
		TenantID:   "tid",
		ServerFlow: auth.FlowClientCredentials,
		Credential: CredentialConfig{ClientSecret: "env://TEST_CS_INJ"},
	}
	ctx := context.Background()
	store := newLRUStoreAdapter(nil, 10, 0, 0)
	injectedMgr := newCacheManagerFromConfig[string, *sdkplugin.TokenResponse](CacheConfig{}, store)

	opts := &ServerModeOptions{HTTPClient: NewMockHTTPClient(), CacheManager: injectedMgr}
	sm, err := buildServerMode(ctx, sc, opts)
	require.NoError(t, err)
	assert.Same(t, injectedMgr, sm.cacheManager)
}

func TestBuildServerMode_ServerFlowCached(t *testing.T) {
	ts, calls := countingTokenServer(t, "cached-server-tok")
	defer ts.Close()

	t.Setenv("TEST_CS_SRV", "secret")
	sc := &ServerConfig{
		ClientID:   "cid",
		TenantID:   "tid",
		ServerFlow: auth.FlowClientCredentials,
		Credential: CredentialConfig{ClientSecret: "env://TEST_CS_SRV"},
	}

	sm, err := buildServerMode(context.Background(), sc, &ServerModeOptions{HTTPClient: newTestHTTPClient(ts)})
	require.NoError(t, err)

	req := sdkplugin.TokenRequest{
		ServerContext: auth.ServerContextServer,
		Scope:         "https://graph.microsoft.com/.default",
	}

	resp1, err := sm.GetToken(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "cached-server-tok", resp1.AccessToken)

	resp2, err := sm.GetToken(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "cached-server-tok", resp2.AccessToken)

	assert.Equal(t, int64(1), calls.Load(), "server CC flow should be cached — HTTP called only once")
}

func TestBuildServerMode_MachineFlowCached(t *testing.T) {
	ts, calls := countingTokenServer(t, "cached-machine-tok")
	defer ts.Close()

	t.Setenv("TEST_CS_MACH", "secret")
	sc := &ServerConfig{
		ClientID:   "cid",
		TenantID:   "tid",
		ServerFlow: auth.FlowClientCredentials,
		Credential: CredentialConfig{ClientSecret: "env://TEST_CS_MACH"},
		Delegated:  &DelegatedConfig{Machine: true},
	}

	sm, err := buildServerMode(context.Background(), sc, &ServerModeOptions{HTTPClient: newTestHTTPClient(ts)})
	require.NoError(t, err)

	req := sdkplugin.TokenRequest{
		ServerContext: auth.ServerContextDelegated,
		Scope:         "https://graph.microsoft.com/.default",
		Caller:        auth.CallerMachine,
	}

	resp1, err := sm.GetToken(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "cached-machine-tok", resp1.AccessToken)

	resp2, err := sm.GetToken(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "cached-machine-tok", resp2.AccessToken)

	assert.Equal(t, int64(1), calls.Load(), "machine CC flow should be cached — HTTP called only once")
}

func TestBuildServerMode_OBOFlowCached(t *testing.T) {
	ts, calls := countingTokenServer(t, "cached-obo-tok")
	defer ts.Close()

	t.Setenv("TEST_CS_OBO", "secret")
	sc := &ServerConfig{
		ClientID:   "cid",
		TenantID:   "tid",
		ServerFlow: auth.FlowClientCredentials,
		Credential: CredentialConfig{ClientSecret: "env://TEST_CS_OBO"},
		Delegated:  &DelegatedConfig{UserFlow: auth.FlowOnBehalfOf},
	}

	sm, err := buildServerMode(context.Background(), sc, &ServerModeOptions{HTTPClient: newTestHTTPClient(ts)})
	require.NoError(t, err)

	req := sdkplugin.TokenRequest{
		ServerContext: auth.ServerContextDelegated,
		Scope:         "api://downstream/.default",
		Assertion:     "user-jwt-xyz",
		Caller:        auth.CallerUser,
	}

	resp1, err := sm.GetToken(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "cached-obo-tok", resp1.AccessToken)

	resp2, err := sm.GetToken(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "cached-obo-tok", resp2.AccessToken)

	assert.Equal(t, int64(1), calls.Load(), "OBO flow should be cached — HTTP called only once for same assertion+scope")
}

func TestBuildServerMode_OBODifferentAssertions_NotShared(t *testing.T) {
	ts, calls := countingTokenServer(t, "obo-tok")
	defer ts.Close()

	t.Setenv("TEST_CS_OBO2", "secret")
	sc := &ServerConfig{
		ClientID:   "cid",
		TenantID:   "tid",
		ServerFlow: auth.FlowClientCredentials,
		Credential: CredentialConfig{ClientSecret: "env://TEST_CS_OBO2"},
		Delegated:  &DelegatedConfig{UserFlow: auth.FlowOnBehalfOf},
	}

	sm, err := buildServerMode(context.Background(), sc, &ServerModeOptions{HTTPClient: newTestHTTPClient(ts)})
	require.NoError(t, err)

	_, err = sm.GetToken(context.Background(), sdkplugin.TokenRequest{
		ServerContext: auth.ServerContextDelegated,
		Scope:         "scope",
		Assertion:     "user-a-jwt",
		Caller:        auth.CallerUser,
	})
	require.NoError(t, err)

	_, err = sm.GetToken(context.Background(), sdkplugin.TokenRequest{
		ServerContext: auth.ServerContextDelegated,
		Scope:         "scope",
		Assertion:     "user-b-jwt",
		Caller:        auth.CallerUser,
	})
	require.NoError(t, err)

	assert.Equal(t, int64(2), calls.Load(), "different assertions should produce different cache keys")
}

func TestBuildServerMode_Hooks_Observed(t *testing.T) {
	ts, _ := countingTokenServer(t, "tok")
	defer ts.Close()

	t.Setenv("TEST_CS_HOOK", "secret")
	sc := &ServerConfig{
		ClientID:   "cid",
		TenantID:   "tid",
		ServerFlow: auth.FlowClientCredentials,
		Credential: CredentialConfig{ClientSecret: "env://TEST_CS_HOOK"},
	}

	var hits atomic.Int64
	opts := &ServerModeOptions{
		HTTPClient: newTestHTTPClient(ts),
		Hooks: &manager.Hooks{
			OnCacheHit: func(_ string) { hits.Add(1) },
		},
	}

	sm, err := buildServerMode(context.Background(), sc, opts)
	require.NoError(t, err)

	req := sdkplugin.TokenRequest{
		ServerContext: auth.ServerContextServer,
		Scope:         "scope",
	}

	_, err = sm.GetToken(context.Background(), req)
	require.NoError(t, err)

	_, err = sm.GetToken(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, int64(1), hits.Load(), "OnCacheHit should fire on second call")
}
