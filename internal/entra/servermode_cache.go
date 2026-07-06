// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	manager "github.com/oakwood-commons/go-flight/cache"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// Default cache configuration values.
const (
	DefaultExpiryThreshold = 30 * time.Minute
	DefaultStoreSize       = 1024
	DefaultStoreBuffer     = 5 * time.Minute
	DefaultCleanupInterval = 10 * time.Minute
	DefaultSlowThreshold   = 2 * time.Second
)

// CacheConfig holds tunable parameters for the server-mode token cache.
type CacheConfig struct {
	ExpiryThreshold time.Duration // minimum TTL to cache a result
	SlowThreshold   time.Duration // follower abandons leader after this duration
	RetryOnError    bool          // followers retry independently on leader failure
	StoreSize       int           // max entries in the LRU
	StoreBuffer     time.Duration // how early before expiry an entry is considered stale
	CleanupInterval time.Duration // interval for background eviction
}

// DefaultCacheConfig returns production defaults for server-mode caching.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		ExpiryThreshold: DefaultExpiryThreshold,
		RetryOnError:    false,
		StoreSize:       DefaultStoreSize,
		StoreBuffer:     DefaultStoreBuffer,
		CleanupInterval: DefaultCleanupInterval,
		SlowThreshold:   DefaultSlowThreshold,
	}
}

func newCacheManager[k comparable, v any](opts ...manager.ManagerOption[k, v]) *manager.Manager[k, v] {
	return manager.NewManager(opts...)
}

func newCacheManagerFromConfig[k comparable, v any](cfg CacheConfig, store manager.Store[k, v]) *manager.Manager[k, v] {
	return newCacheManager(
		manager.WithExpiryThreshold[k, v](cfg.ExpiryThreshold),
		manager.WithSlowThreshold[k, v](cfg.SlowThreshold),
		manager.WithRetryFollowerOnError[k, v](cfg.RetryOnError),
		manager.WithStore("default", store),
	)
}

// KeyGenerator produces a cache key from flow params.
type KeyGenerator[K comparable] func(params FlowParams, hashFunc func(string) (string, bool)) (K, bool)

func oboCacheKeyGenerator(params FlowParams, hashFunc func(string) (string, bool)) (string, bool) {
	if hashFunc == nil {
		hashFunc = sha256Short
	}
	if params.assertion == "" || params.Scope == "" || params.ClientID == "" {
		return "", false
	}
	hashedToken, ok := hashFunc(params.assertion)
	if !ok {
		return "", false
	}
	var b strings.Builder
	b.WriteString("obo|")
	b.WriteString(params.ClientID)
	b.WriteString("|")
	b.WriteString(params.Scope)
	b.WriteString("|")
	b.WriteString(hashedToken)
	return b.String(), true
}

func clientCredentialCacheKeyGenerator(params FlowParams, _ func(string) (string, bool)) (string, bool) {
	if params.Scope == "" || params.ClientID == "" {
		return "", false
	}
	var b strings.Builder
	b.WriteString("cc|")
	b.WriteString(params.ClientID)
	b.WriteString("|")
	b.WriteString(params.Scope)
	return b.String(), true
}

func cachedFlow(
	inner FlowFn,
	mgr *manager.Manager[string, *sdkplugin.TokenResponse],
	keyGen KeyGenerator[string],
	hashFunc func(string) (string, bool),
	hooks *manager.Hooks,
) FlowFn {
	return func(ctx context.Context, params FlowParams) (*sdkplugin.TokenResponse, error) {
		key, ok := keyGen(params, hashFunc)
		if !ok || mgr == nil {
			return inner(ctx, params)
		}
		return mgr.Do(ctx, key, func(ctx context.Context) (manager.FetchResult[*sdkplugin.TokenResponse], error) {
			resp, err := inner(ctx, params)
			if err != nil {
				return manager.FetchResult[*sdkplugin.TokenResponse]{}, err
			}
			ttl := time.Until(resp.ExpiresAt)
			return manager.FetchResult[*sdkplugin.TokenResponse]{
				Value:  resp,
				TTL:    ttl,
				Policy: manager.CacheWithTTL,
			}, nil
		}, hooks)
	}
}

func sha256Short(s string) (string, bool) {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:16]), true // 128-bit, collision-safe for dedupe
}
