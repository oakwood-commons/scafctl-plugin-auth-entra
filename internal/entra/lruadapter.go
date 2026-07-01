// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-auth-entra/internal/cache"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

type lruStoreAdapter struct {
	lru *cache.LRUWithTTL[string, *sdkplugin.TokenResponse]
}

func (a *lruStoreAdapter) Get(_ context.Context, key string) (*sdkplugin.TokenResponse, bool) {
	if a.lru == nil {
		return nil, false
	}
	return a.lru.Get(key)
}

func (a *lruStoreAdapter) Set(_ context.Context, key string, value *sdkplugin.TokenResponse, ttl time.Duration) {
	if a.lru == nil {
		return
	}
	a.lru.Set(key, value, ttl)
}

func newLRUStoreAdapter(stopCh <-chan struct{}, size int, expiryBuffer, cleanupInterval time.Duration) *lruStoreAdapter {
	lru := cache.NewLRUWithTTL(
		cache.WithSize[string, *sdkplugin.TokenResponse](size),
		cache.WithExpiryBuffer[string, *sdkplugin.TokenResponse](expiryBuffer),
		cache.WithCleanupInterval[string, *sdkplugin.TokenResponse](cleanupInterval),
		cache.WithStopCh[string, *sdkplugin.TokenResponse](stopCh),
	)
	return &lruStoreAdapter{
		lru: lru,
	}
}
