// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	"golang.org/x/sync/singleflight"
)

// OBO grant type and constants.
const (
	// OBOGrantType is the OAuth 2.0 grant type for On-Behalf-Of flow.
	OBOGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// OBORequestedTokenUse is the required parameter for OBO requests.
	OBORequestedTokenUse = "on_behalf_of"

	// oboExpiryBuffer is subtracted from the token expiry to ensure tokens
	// are refreshed before they actually expire.
	oboExpiryBuffer = 30 * time.Second
)

// OBOTokenOptions configures an On-Behalf-Of token acquisition (CLI mode).
type OBOTokenOptions struct {
	// Assertion is the access token of the upstream caller.
	Assertion string `json:"-" yaml:"-"`

	// Scope is the target resource scope to acquire.
	Scope string `json:"scope" yaml:"scope"`

	// ClientSecret is the confidential client secret for the OBO request.
	ClientSecret string `json:"-" yaml:"-"`
}

// oboCache is a concurrency-safe, in-memory cache for OBO tokens.
type oboCache struct {
	mu    sync.RWMutex
	items map[string]*oboCacheEntry
	group singleflight.Group
}

type oboCacheEntry struct {
	token     *auth.Token
	expiresAt time.Time
}

func newOBOCache() *oboCache {
	return &oboCache{
		items: make(map[string]*oboCacheEntry),
	}
}

// oboCacheKey computes a deterministic cache key for an assertion+scope pair.
func oboCacheKey(assertion, scope string) string {
	h := sha256.Sum256([]byte(assertion + "\x00" + scope))
	return hex.EncodeToString(h[:])
}

// get returns a cached token if it exists and is still valid.
func (c *oboCache) get(assertion, scope string) (*auth.Token, bool) {
	key := oboCacheKey(assertion, scope)
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return nil, false
	}
	return entry.token, true
}

// set stores a token in the cache.
func (c *oboCache) set(assertion, scope string, token *auth.Token) {
	key := oboCacheKey(assertion, scope)
	c.mu.Lock()
	c.items[key] = &oboCacheEntry{
		token:     token,
		expiresAt: token.ExpiresAt.Add(-oboExpiryBuffer),
	}
	c.mu.Unlock()
}

// GetOBOToken acquires a token using the On-Behalf-Of flow (CLI mode).
func (p *Plugin) GetOBOToken(ctx context.Context, opts OBOTokenOptions) (*auth.Token, error) {
	if opts.Assertion == "" {
		return nil, fmt.Errorf("OBO assertion (upstream access token) is required")
	}
	if opts.Scope == "" {
		return nil, fmt.Errorf("scope is required for OBO token request")
	}
	if opts.ClientSecret == "" {
		return nil, fmt.Errorf("OBO flow requires a client secret")
	}

	qualifiedScope := QualifyScope(opts.Scope)

	// Check in-memory cache
	if token, ok := p.oboCache.get(opts.Assertion, qualifiedScope); ok {
		return token, nil
	}

	// Deduplicate concurrent requests for the same assertion+scope
	key := oboCacheKey(opts.Assertion, qualifiedScope)
	v, err, _ := p.oboCache.group.Do(key, func() (any, error) {
		// Double-check cache after winning the singleflight race
		if token, ok := p.oboCache.get(opts.Assertion, qualifiedScope); ok {
			return token, nil
		}
		token, mintErr := p.mintOBOToken(ctx, opts.Assertion, qualifiedScope, opts.ClientSecret)
		if mintErr != nil {
			return nil, mintErr
		}
		p.oboCache.set(opts.Assertion, qualifiedScope, token)
		return token, nil
	})
	if err != nil {
		return nil, err
	}

	token, ok := v.(*auth.Token)
	if !ok {
		return nil, fmt.Errorf("unexpected OBO token type: %T", v)
	}
	return token, nil
}

// mintOBOToken performs the actual OBO token exchange (CLI mode).
func (p *Plugin) mintOBOToken(ctx context.Context, assertion, scope, clientSecret string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("minting OBO token", "scope", scope)

	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", p.config.GetAuthority(), p.config.TenantID)

	data := makeFormData(map[string]string{
		"grant_type":          OBOGrantType,
		"client_id":           p.config.ClientID,
		"assertion":           assertion,
		"scope":               scope,
		"requested_token_use": OBORequestedTokenUse,
		"client_secret":       clientSecret,
	})

	resp, err := p.httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("OBO token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return nil, fmt.Errorf("OBO token request failed with status %d: decode error: %w; body: %s", resp.StatusCode, decErr, string(body))
		}

		if strings.Contains(errResp.ErrorDescription, "AADSTS") {
			return nil, formatAADSTSError("OBO token request failed", errResp)
		}
		return nil, fmt.Errorf("OBO token request failed: %s - %s", errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse OBO token response: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	lgr.V(1).Info("OBO token minted successfully",
		"expiresIn", tokenResp.ExpiresIn,
		"expiresAt", expiresAt,
		"scope", scope,
	)

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        FlowOnBehalfOf,
	}, nil
}
