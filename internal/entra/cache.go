// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// tokenCacheEntry is the JSON representation stored in the host secret store.
type tokenCacheEntry struct {
	AccessToken string    `json:"accessToken"` //nolint:gosec // JSON field name
	TokenType   string    `json:"tokenType"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Scope       string    `json:"scope,omitempty"`
	CachedAt    time.Time `json:"cachedAt"`
	Flow        auth.Flow `json:"flow,omitempty"`
	SessionID   string    `json:"sessionId,omitempty"`
}

// cacheGet retrieves a cached token from the host secret store.
func cacheGet(ctx context.Context, hostClient *sdkplugin.HostServiceClient, fullKey string) (*auth.Token, error) {
	value, found, err := hostClient.GetSecret(ctx, fullKey)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	var entry tokenCacheEntry
	if err := json.Unmarshal([]byte(value), &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached token: %w", err)
	}

	return &auth.Token{
		AccessToken: entry.AccessToken,
		TokenType:   entry.TokenType,
		ExpiresAt:   entry.ExpiresAt,
		Scope:       entry.Scope,
		CachedAt:    entry.CachedAt,
		Flow:        entry.Flow,
		SessionID:   entry.SessionID,
	}, nil
}

// cacheSet stores a token in the host secret store cache.
func cacheSet(ctx context.Context, hostClient *sdkplugin.HostServiceClient, fullKey string, token *auth.Token) error {
	entry := tokenCacheEntry{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresAt:   token.ExpiresAt,
		Scope:       token.Scope,
		CachedAt:    time.Now(),
		Flow:        token.Flow,
		SessionID:   token.SessionID,
	}

	data, err := json.Marshal(entry) //nolint:gosec // caching token data in host secret store
	if err != nil {
		return fmt.Errorf("failed to marshal token for caching: %w", err)
	}

	return hostClient.SetSecret(ctx, fullKey, string(data))
}

// cacheClear removes all cached tokens matching the given prefix.
func cacheClear(ctx context.Context, lgr logr.Logger, hostClient *sdkplugin.HostServiceClient, prefix string) {
	keys, err := hostClient.ListSecrets(ctx, prefix+"*")
	if err != nil {
		lgr.V(1).Info("failed to list cached tokens", "error", err)
		return
	}
	for _, key := range keys {
		if err := hostClient.DeleteSecret(ctx, key); err != nil {
			lgr.V(1).Info("failed to delete cached token", "key", key, "error", err)
		}
	}
}

// cacheListEntries lists all cached token entries matching the given prefix.
func cacheListEntries(ctx context.Context, hostClient *sdkplugin.HostServiceClient, prefix string) ([]*auth.CachedTokenInfo, error) {
	keys, err := hostClient.ListSecrets(ctx, prefix+"*")
	if err != nil {
		return nil, err
	}

	var results []*auth.CachedTokenInfo
	for _, key := range keys {
		value, found, err := hostClient.GetSecret(ctx, key)
		if err != nil || !found {
			continue
		}

		var entry tokenCacheEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}

		scope := entry.Scope
		if scope == "" {
			scope = strings.TrimPrefix(key, prefix)
		}
		results = append(results, &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "access",
			TokenType: entry.TokenType,
			Scope:     scope,
			Flow:      entry.Flow,
			ExpiresAt: entry.ExpiresAt,
			CachedAt:  entry.CachedAt,
			IsExpired: !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt),
			SessionID: entry.SessionID,
		})
	}

	return results, nil
}

// cachePurgeExpired removes expired tokens matching the given prefix and returns the count removed.
func cachePurgeExpired(ctx context.Context, hostClient *sdkplugin.HostServiceClient, prefix string) (int, error) {
	keys, err := hostClient.ListSecrets(ctx, prefix+"*")
	if err != nil {
		return 0, err
	}

	count := 0
	for _, key := range keys {
		value, found, err := hostClient.GetSecret(ctx, key)
		if err != nil || !found {
			continue
		}

		var entry tokenCacheEntry
		if err := json.Unmarshal([]byte(value), &entry); err != nil {
			continue
		}

		if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
			if err := hostClient.DeleteSecret(ctx, key); err == nil {
				count++
			}
		}
	}

	return count, nil
}

// fingerprintHash returns a SHA-256 hash of the input, used for cache keys.
func fingerprintHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
