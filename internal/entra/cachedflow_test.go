// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	manager "github.com/oakwood-commons/go-flight/cache"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFlowFn returns a FlowFn that counts calls and returns a fixed response.
func mockFlowFn(token string, expiresIn time.Duration) (FlowFn, *atomic.Int64) {
	var calls atomic.Int64
	fn := func(_ context.Context, _ FlowParams) (*sdkplugin.TokenResponse, error) {
		calls.Add(1)
		return &sdkplugin.TokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(expiresIn),
		}, nil
	}
	return fn, &calls
}

// mockFlowFnErr returns a FlowFn that always errors.
func mockFlowFnErr(errMsg string) (FlowFn, *atomic.Int64) {
	var calls atomic.Int64
	fn := func(_ context.Context, _ FlowParams) (*sdkplugin.TokenResponse, error) {
		calls.Add(1)
		return nil, fmt.Errorf("%s", errMsg)
	}
	return fn, &calls
}

func testManager(t *testing.T) *manager.Manager[string, *sdkplugin.TokenResponse] {
	t.Helper()
	ch := make(chan struct{})

	t.Cleanup(func() { close(ch) })
	store := newLRUStoreAdapter(ch, 100, 0, 0)
	return newCacheManagerFromConfig[string, *sdkplugin.TokenResponse](CacheConfig{
		ExpiryThreshold: 0,
		SlowThreshold:   0,
		RetryOnError:    true,
	}, store)
}

func TestCachedFlow_CacheHit(t *testing.T) {
	mgr := testManager(t)
	inner, calls := mockFlowFn("tok-1", time.Hour)
	flow := cachedFlow(inner, mgr, clientCredentialCacheKeyGenerator, nil, nil)

	params := FlowParams{ClientID: "cid", Scope: "scope1"}

	resp1, err := flow(context.Background(), params)
	require.NoError(t, err)
	assert.Equal(t, "tok-1", resp1.AccessToken)

	resp2, err := flow(context.Background(), params)
	require.NoError(t, err)
	assert.Equal(t, "tok-1", resp2.AccessToken)

	assert.Equal(t, int64(1), calls.Load(), "inner should be called only once")
}

func TestCachedFlow_CacheMiss(t *testing.T) {
	mgr := testManager(t)
	inner, calls := mockFlowFn("fresh-tok", time.Hour)
	flow := cachedFlow(inner, mgr, clientCredentialCacheKeyGenerator, nil, nil)

	params := FlowParams{ClientID: "cid", Scope: "scope-a"}
	resp, err := flow(context.Background(), params)
	require.NoError(t, err)
	assert.Equal(t, "fresh-tok", resp.AccessToken)
	assert.Equal(t, int64(1), calls.Load())
}

func TestCachedFlow_KeyGenFails_BypassesCache(t *testing.T) {
	mgr := testManager(t)
	inner, calls := mockFlowFn("direct", time.Hour)
	flow := cachedFlow(inner, mgr, clientCredentialCacheKeyGenerator, nil, nil)

	// Empty scope causes keyGen to return false
	params := FlowParams{ClientID: "cid", Scope: ""}

	_, err := flow(context.Background(), params)
	require.NoError(t, err)
	_, err = flow(context.Background(), params)
	require.NoError(t, err)

	assert.Equal(t, int64(2), calls.Load(), "inner should be called every time when key generation fails")
}

func TestCachedFlow_NilManager_BypassesCache(t *testing.T) {
	inner, calls := mockFlowFn("direct", time.Hour)
	flow := cachedFlow(inner, nil, clientCredentialCacheKeyGenerator, nil, nil)

	params := FlowParams{ClientID: "cid", Scope: "scope"}

	_, err := flow(context.Background(), params)
	require.NoError(t, err)
	_, err = flow(context.Background(), params)
	require.NoError(t, err)

	assert.Equal(t, int64(2), calls.Load(), "inner should be called every time with nil manager")
}

func TestCachedFlow_InnerError_NotCached(t *testing.T) {
	mgr := testManager(t)
	inner, calls := mockFlowFnErr("transient failure")
	flow := cachedFlow(inner, mgr, clientCredentialCacheKeyGenerator, nil, nil)

	params := FlowParams{ClientID: "cid", Scope: "scope"}

	_, err := flow(context.Background(), params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transient failure")

	_, err = flow(context.Background(), params)
	require.Error(t, err)

	assert.Equal(t, int64(2), calls.Load(), "errors should not be cached")
}

func TestCachedFlow_Hooks_OnCacheHit(t *testing.T) {
	mgr := testManager(t)
	inner, _ := mockFlowFn("tok", time.Hour)

	var hits atomic.Int64
	hooks := &manager.Hooks{
		OnCacheHit: func(_ string) { hits.Add(1) },
	}
	flow := cachedFlow(inner, mgr, clientCredentialCacheKeyGenerator, nil, hooks)

	params := FlowParams{ClientID: "cid", Scope: "scope"}

	_, err := flow(context.Background(), params)
	require.NoError(t, err)

	_, err = flow(context.Background(), params)
	require.NoError(t, err)

	assert.Equal(t, int64(1), hits.Load(), "OnCacheHit should fire on second call")
}

func TestCachedFlow_Hooks_OnFetchError(t *testing.T) {
	mgr := testManager(t)
	inner, _ := mockFlowFnErr("boom")

	var fetchErrors atomic.Int64
	hooks := &manager.Hooks{
		OnFetchError: func(_ error) { fetchErrors.Add(1) },
	}
	flow := cachedFlow(inner, mgr, clientCredentialCacheKeyGenerator, nil, hooks)

	params := FlowParams{ClientID: "cid", Scope: "scope"}

	_, err := flow(context.Background(), params)
	require.Error(t, err)

	assert.Equal(t, int64(1), fetchErrors.Load(), "OnFetchError should fire on inner error")
}

func TestCachedFlow_DedupConcurrentCalls(t *testing.T) {
	mgr := testManager(t)

	var calls atomic.Int64
	// Slow inner to ensure concurrent calls overlap
	inner := func(_ context.Context, _ FlowParams) (*sdkplugin.TokenResponse, error) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return &sdkplugin.TokenResponse{
			AccessToken: "deduped",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	}

	flow := cachedFlow(inner, mgr, clientCredentialCacheKeyGenerator, nil, nil)
	params := FlowParams{ClientID: "cid", Scope: "scope"}

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	results := make([]*sdkplugin.TokenResponse, n)
	errs := make([]error, n)

	for i := range n {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = flow(context.Background(), params)
		}(i)
	}
	wg.Wait()

	for i := range n {
		require.NoError(t, errs[i])
		assert.Equal(t, "deduped", results[i].AccessToken)
	}

	// Singleflight should deduplicate — at most 2 calls (leader + possible retry)
	assert.LessOrEqual(t, calls.Load(), int64(2), "concurrent calls should be deduplicated")
}

func TestCachedFlow_DifferentKeys_NotShared(t *testing.T) {
	mgr := testManager(t)
	inner, calls := mockFlowFn("tok", time.Hour)
	flow := cachedFlow(inner, mgr, clientCredentialCacheKeyGenerator, nil, nil)

	_, err := flow(context.Background(), FlowParams{ClientID: "cid", Scope: "scope-a"})
	require.NoError(t, err)

	_, err = flow(context.Background(), FlowParams{ClientID: "cid", Scope: "scope-b"})
	require.NoError(t, err)

	assert.Equal(t, int64(2), calls.Load(), "different scopes should produce different cache keys")
}
