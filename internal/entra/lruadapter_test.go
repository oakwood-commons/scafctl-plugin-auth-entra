// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"testing"
	"time"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
)

func TestLRUStoreAdapter_NilLRU_Get(t *testing.T) {
	a := &lruStoreAdapter{lru: nil}
	val, ok := a.Get(context.Background(), "key")
	assert.Nil(t, val)
	assert.False(t, ok)
}

func TestLRUStoreAdapter_NilLRU_Set(_ *testing.T) {
	a := &lruStoreAdapter{lru: nil}
	// Should not panic
	a.Set(context.Background(), "key", &sdkplugin.TokenResponse{AccessToken: "t"}, time.Minute)
}

func TestLRUStoreAdapter_SetThenGet(t *testing.T) {
	ch := make(chan struct{})
	defer close(ch)
	a := newLRUStoreAdapter(ch, 10, 0, 0)

	tok := &sdkplugin.TokenResponse{AccessToken: "abc123", TokenType: "Bearer"}
	a.Set(context.Background(), "mykey", tok, 5*time.Minute)

	got, ok := a.Get(context.Background(), "mykey")
	assert.True(t, ok)
	assert.Equal(t, "abc123", got.AccessToken)

}

func TestLRUStoreAdapter_GetMiss(t *testing.T) {
	ch := make(chan struct{})
	defer close(ch)

	a := newLRUStoreAdapter(ch, 10, 0, 0)

	got, ok := a.Get(context.Background(), "nonexistent")
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestNewLRUStoreAdapter_CloseStopsCleanup(t *testing.T) {
	ch := make(chan struct{})
	a := newLRUStoreAdapter(ch, 10, 0, 50*time.Millisecond)

	tok := &sdkplugin.TokenResponse{AccessToken: "x"}
	a.Set(context.Background(), "k", tok, time.Minute)

	// Closing stopCh should not panic or cause issues on subsequent use
	close(ch)
	time.Sleep(100 * time.Millisecond)

	// Adapter still usable after cleanup goroutine exits
	got, ok := a.Get(context.Background(), "k")
	assert.True(t, ok)
	assert.Equal(t, "x", got.AccessToken)
}
