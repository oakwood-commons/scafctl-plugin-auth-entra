// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"testing"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	"github.com/stretchr/testify/assert"
)

func TestClientCredentialCacheKeyGenerator(t *testing.T) {
	t.Run("valid params", func(t *testing.T) {
		key, ok := clientCredentialCacheKeyGenerator(FlowParams{ClientID: "cid", Scope: "scope"}, nil)
		assert.True(t, ok)
		assert.Equal(t, "cc|cid|scope", key)
	})

	t.Run("empty scope returns false", func(t *testing.T) {
		_, ok := clientCredentialCacheKeyGenerator(FlowParams{ClientID: "cid", Scope: ""}, nil)
		assert.False(t, ok)
	})

	t.Run("empty clientID returns false", func(t *testing.T) {
		_, ok := clientCredentialCacheKeyGenerator(FlowParams{ClientID: "", Scope: "scope"}, nil)
		assert.False(t, ok)
	})

	t.Run("both empty returns false", func(t *testing.T) {
		_, ok := clientCredentialCacheKeyGenerator(FlowParams{}, nil)
		assert.False(t, ok)
	})

	t.Run("ignores hashFunc", func(t *testing.T) {
		called := false
		key, ok := clientCredentialCacheKeyGenerator(FlowParams{ClientID: "c", Scope: "s"}, func(s string) (string, bool) {
			called = true
			return s, true
		})
		assert.True(t, ok)
		assert.Equal(t, "cc|c|s", key)
		assert.False(t, called, "hashFunc should not be called for cc key gen")
	})
}

func TestOboCacheKeyGenerator(t *testing.T) {
	alwaysHash := func(s string) (string, bool) { return "hashed-" + s, true }

	t.Run("valid params", func(t *testing.T) {
		key, ok := oboCacheKeyGenerator(FlowParams{
			assertion: "jwt-token",
			ClientID:  "cid",
			Scope:     "scope",
		}, alwaysHash)
		assert.True(t, ok)
		assert.Equal(t, "obo|cid|scope|hashed-jwt-token", key)
	})

	t.Run("empty assertion returns false", func(t *testing.T) {
		_, ok := oboCacheKeyGenerator(FlowParams{
			assertion: "",
			ClientID:  "cid",
			Scope:     "scope",
		}, alwaysHash)
		assert.False(t, ok)
	})

	t.Run("empty scope returns false", func(t *testing.T) {
		_, ok := oboCacheKeyGenerator(FlowParams{
			assertion: "jwt",
			ClientID:  "cid",
			Scope:     "",
		}, alwaysHash)
		assert.False(t, ok)
	})

	t.Run("empty clientID returns false", func(t *testing.T) {
		_, ok := oboCacheKeyGenerator(FlowParams{
			assertion: "jwt",
			ClientID:  "",
			Scope:     "scope",
		}, alwaysHash)
		assert.False(t, ok)
	})

	t.Run("hashFunc returns false", func(t *testing.T) {
		failHash := func(_ string) (string, bool) { return "", false }
		_, ok := oboCacheKeyGenerator(FlowParams{
			assertion: "jwt",
			ClientID:  "cid",
			Scope:     "scope",
		}, failHash)
		assert.False(t, ok)
	})

	t.Run("nil hashFunc uses sha256Short", func(t *testing.T) {
		key, ok := oboCacheKeyGenerator(FlowParams{
			assertion: "my-token",
			ClientID:  "cid",
			Scope:     "scope",
		}, nil)
		assert.True(t, ok)
		// Verify it starts with expected prefix and has a hash suffix
		assert.Contains(t, key, "obo|cid|scope|")
		// Hash should be 32 hex chars (128 bits)
		parts := splitKey(key)
		assert.Len(t, parts[3], 32)
	})

	t.Run("different assertions produce different keys", func(t *testing.T) {
		key1, _ := oboCacheKeyGenerator(FlowParams{assertion: "jwt-a", ClientID: "cid", Scope: "s"}, nil)
		key2, _ := oboCacheKeyGenerator(FlowParams{assertion: "jwt-b", ClientID: "cid", Scope: "s"}, nil)
		assert.NotEqual(t, key1, key2)
	})

	t.Run("same assertion same key", func(t *testing.T) {
		params := FlowParams{assertion: "jwt-x", ClientID: "cid", Scope: "s"}
		key1, _ := oboCacheKeyGenerator(params, nil)
		key2, _ := oboCacheKeyGenerator(params, nil)
		assert.Equal(t, key1, key2)
	})

	t.Run("caller type does not affect key", func(t *testing.T) {
		base := FlowParams{assertion: "jwt", ClientID: "cid", Scope: "s", Caller: auth.CallerUser}
		key1, _ := oboCacheKeyGenerator(base, nil)
		base.Caller = auth.CallerMachine
		key2, _ := oboCacheKeyGenerator(base, nil)
		assert.Equal(t, key1, key2)
	})
}

func TestSha256Short(t *testing.T) {
	t.Run("returns 32 hex chars", func(t *testing.T) {
		hash, ok := sha256Short("hello")
		assert.True(t, ok)
		assert.Len(t, hash, 32)
	})

	t.Run("deterministic", func(t *testing.T) {
		h1, _ := sha256Short("same-input")
		h2, _ := sha256Short("same-input")
		assert.Equal(t, h1, h2)
	})

	t.Run("different inputs different hashes", func(t *testing.T) {
		h1, _ := sha256Short("input-a")
		h2, _ := sha256Short("input-b")
		assert.NotEqual(t, h1, h2)
	})
}

// splitKey splits a cache key by "|" delimiter.
func splitKey(key string) []string {
	var parts []string
	start := 0
	for i, c := range key {
		if c == '|' {
			parts = append(parts, key[start:i])
			start = i + 1
		}
	}
	parts = append(parts, key[start:])
	return parts
}
