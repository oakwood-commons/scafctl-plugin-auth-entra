// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
)

// MetaKeyTenantID is the Metadata map key under which the entra handler
// persists the Azure tenant ID. Exported so call sites and tests share one
// source of truth for the key.
const MetaKeyTenantID = "tenantId"

const (
	// metaKeyRefreshTokenID records the versioned refresh-token secret suffix
	// bound to a HandlerMetadata revision so concurrent logins across processes
	// never pair one write's metadata with another write's refresh token.
	metaKeyRefreshTokenID = "refreshTokenId"

	// metaKeyRefreshTokenHash stores the SHA-256 hex digest of the refresh
	// token paired with a HandlerMetadata revision.
	metaKeyRefreshTokenHash = "refreshTokenSha256"

	// defaultCredentialCleanupTimeout bounds detached rollback/cleanup RPCs
	// on the host secret store so a stalled host never blocks Login or callback
	// settlement indefinitely.
	defaultCredentialCleanupTimeout = 5 * time.Second
)

// TokenResponse represents the response from the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`  //nolint:gosec // not a hardcoded credential
	RefreshToken string `json:"refresh_token"` //nolint:gosec // not a hardcoded credential
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
}

// TokenErrorResponse represents an error from the token endpoint.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	// Claims contains a base64url-encoded JSON claims challenge returned by
	// Azure AD when Conditional Access policies require step-up authentication.
	Claims string `json:"claims,omitempty"`
}

// mintToken creates a new access token for the specified scope.
func (p *Plugin) mintToken(ctx context.Context, scope string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("minting access token", "scope", scope)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Load paired refresh token and metadata under profile read lock.
	refreshToken, metadata, err := p.loadSessionCredentials(ctx)
	if err != nil {
		return nil, err
	}

	tenantID := metadata.MetaString(MetaKeyTenantID)

	// Request new access token using refresh token
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", cfg.GetAuthority(), tenantID)

	if metadata.ClientID == "" {
		return nil, fmt.Errorf("stored credentials are missing client ID, please re-authenticate with '%s auth login entra'", p.binaryName())
	}

	data := makeFormData(map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     metadata.ClientID,
		"refresh_token": refreshToken,
		"scope":         ensureOfflineAccess(scope),
	})

	resp, err := httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return nil, fmt.Errorf("token request failed with status %d: decode error: %w; body: %s", resp.StatusCode, decErr, string(body))
		}

		// Claims challenge: Conditional Access requires step-up authentication.
		if errResp.Claims != "" {
			lgr.V(0).Info("claims challenge received, interactive re-authentication required",
				"scope", scope,
			)
			return nil, &ClaimsChallengeError{
				Claims: errResp.Claims,
				Scope:  scope,
				Hint: fmt.Sprintf("re-run '%s auth login entra --flow interactive --force' "+
					"to complete the required step-up authentication", p.binaryName()),
			}
		}

		// AADSTS53003 without a claims payload
		if strings.Contains(errResp.ErrorDescription, "AADSTS53003") {
			return nil, formatAADSTSError(fmt.Sprintf("Conditional Access blocked token request for scope %q", scope), errResp)
		}

		if errResp.Error == "invalid_grant" {
			lgr.V(0).Info("token refresh failed with invalid_grant",
				"errorDescription", errResp.ErrorDescription,
				"scope", scope,
			)

			if strings.Contains(errResp.ErrorDescription, "AADSTS700016") {
				return nil, formatAADSTSError(fmt.Sprintf("token refresh failed for scope %q", scope), errResp)
			}

			if strings.Contains(errResp.ErrorDescription, "AADSTS70000") {
				return nil, fmt.Errorf("scope %q: %s: refresh token revoked or rotated", scope, errResp.ErrorDescription)
			}

			if strings.Contains(errResp.ErrorDescription, "AADSTS65001") ||
				strings.Contains(errResp.ErrorDescription, "AADSTS70011") {
				return nil, fmt.Errorf("scope %q: %s: consent required", scope, errResp.ErrorDescription)
			}

			// For genuine token expiry / revocation, clear stored credentials
			// unless a newer login has already replaced this session.
			p.logoutIfSessionMatches(ctx, metadata.SessionID)
			if errResp.ErrorDescription != "" {
				return nil, fmt.Errorf("%s: token expired", errResp.ErrorDescription)
			}
			return nil, fmt.Errorf("token expired")
		}

		if strings.Contains(errResp.ErrorDescription, "AADSTS") {
			return nil, formatAADSTSError("token request failed", errResp)
		}

		return nil, fmt.Errorf("token request failed: %s - %s", errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// If we got a new refresh token, store it (token rotation) unless a
	// concurrent login replaced the session while the HTTP request was in flight.
	if tokenResp.RefreshToken != "" && tokenResp.RefreshToken != refreshToken {
		lgr.V(1).Info("refresh token rotated, storing new token")
		if err := p.storeRotatedCredentials(ctx, tenantID, &tokenResp, metadata); err != nil {
			lgr.V(1).Info("warning: failed to update refresh token", "error", err)
		}
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	lgr.V(1).Info("access token minted successfully",
		"expiresIn", tokenResp.ExpiresIn,
		"expiresAt", expiresAt,
		"scope", scope,
		"sessionId", metadata.SessionID,
	)

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        metadata.LastLoginFlow,
		SessionID:   metadata.SessionID,
	}, nil
}

func (p *Plugin) newCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := p.cleanupTimeout
	if timeout <= 0 {
		timeout = defaultCredentialCleanupTimeout
	}
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}

func (p *Plugin) versionedRefreshKey(ctx context.Context, revID string) string {
	return p.secretKey(ctx, secretSuffixRefreshToken+"."+revID)
}

// storeCredentials securely stores the refresh token and metadata.
func (p *Plugin) storeCredentials(ctx context.Context, tenantID string, tokenResp *TokenResponse, clientID string, scopes []string, loginFlow auth.Flow, sessionID string) error {
	return p.storeCredentialsWithClaims(ctx, tenantID, tokenResp, clientID, scopes, loginFlow, sessionID, nil)
}

// storeRotatedCredentials updates stored credentials for a refresh-token
// rotation only if expectedMeta.SessionID is still the active session.
func (p *Plugin) storeRotatedCredentials(ctx context.Context, tenantID string, tokenResp *TokenResponse, expectedMeta *auth.HandlerMetadata) error {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	mu := p.profileLock(ctx)
	mu.Lock()
	defer mu.Unlock()

	curMetaRaw, found, err := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata))
	if err != nil {
		return fmt.Errorf("failed to inspect current session metadata: %w", err)
	}
	if !found {
		return nil
	}
	curMeta, parseErr := p.parseMetadata(curMetaRaw)
	if parseErr != nil || curMeta.SessionID != expectedMeta.SessionID {
		return nil
	}

	return p.storeCredentialsLocked(ctx, tenantID, tokenResp, expectedMeta.ClientID, expectedMeta.Scopes, expectedMeta.LastLoginFlow, expectedMeta.SessionID, expectedMeta.Claims)
}

// storeCredentialsWithClaims is storeCredentials with prevClaims used when
// the response carries no parsable ID token -- refresh-token rotation often
// omits it, and dropping the stored claims would lose the user oid that
// keys the user-flow token cache (issue #49).
func (p *Plugin) storeCredentialsWithClaims(ctx context.Context, tenantID string, tokenResp *TokenResponse, clientID string, scopes []string, loginFlow auth.Flow, sessionID string, prevClaims *auth.Claims) error {
	mu := p.profileLock(ctx)
	mu.Lock()
	defer mu.Unlock()

	return p.storeCredentialsLocked(ctx, tenantID, tokenResp, clientID, scopes, loginFlow, sessionID, prevClaims)
}

func (p *Plugin) storeCredentialsLocked(ctx context.Context, tenantID string, tokenResp *TokenResponse, clientID string, scopes []string, loginFlow auth.Flow, sessionID string, prevClaims *auth.Claims) error {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	// Validate refresh token is present
	if tokenResp.RefreshToken == "" {
		return fmt.Errorf("no refresh token in response (offline_access scope may be missing)")
	}

	// Generate a new session ID on initial login; preserve across rotations.
	if sessionID == "" {
		sessionID = generateSessionID()
	}
	revID := generateSessionID()

	// Extract claims and marshal metadata before mutating stored secrets.
	claims, err := p.extractClaims(tokenResp)
	switch {
	case tokenResp.IDToken == "" && prevClaims != nil:
		claims = prevClaims
	case err == nil:
	case prevClaims != nil:
		claims = prevClaims
	default:
		// Use minimal claims if extraction fails
		claims = &auth.Claims{
			TenantID: tenantID,
		}
	}

	metadata := auth.HandlerMetadata{
		Claims:        claims,
		ExpiresAt:     time.Now().Add(DefaultRefreshTokenLifetime),
		LastRefresh:   time.Now(),
		Scopes:        scopes,
		LastLoginFlow: loginFlow,
		SessionID:     sessionID,
		ClientID:      clientID,
	}
	metadata.SetMeta(MetaKeyTenantID, tenantID)
	metadata.SetMeta(metaKeyRefreshTokenID, revID)
	metadata.SetMeta(metaKeyRefreshTokenHash, fingerprintHash(tokenResp.RefreshToken))

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	metadataRaw := string(metadataBytes)

	legacyRefreshKey := p.secretKey(ctx, secretSuffixRefreshToken)
	metadataKey := p.secretKey(ctx, secretSuffixMetadata)
	verRefreshKey := p.versionedRefreshKey(ctx, revID)

	prevMetaRaw, hadPrevMeta, prevMetaErr := hostClient.GetSecret(ctx, metadataKey)
	var prevRevID string
	if prevMetaErr == nil && hadPrevMeta {
		if prevMeta, pErr := p.parseMetadata(prevMetaRaw); pErr == nil {
			prevRevID = prevMeta.MetaString(metaKeyRefreshTokenID)
		}
	}

	// 1. Write the new refresh token under a unique revision key first so no
	// existing or concurrent login's refresh token is overwritten before
	// metadata commits.
	if err := hostClient.SetSecret(ctx, verRefreshKey, tokenResp.RefreshToken); err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	// 2. Single forward commit point: write metadata pointing at verRefreshKey
	// (and its SHA-256 digest). If this fails, neither metadataKey nor
	// legacyRefreshKey nor any other writer's versioned key was modified;
	// simply remove our unreferenced verRefreshKey under a bounded timeout.
	if err := hostClient.SetSecret(ctx, metadataKey, metadataRaw); err != nil {
		cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
		defer cleanupCancel()
		_ = hostClient.DeleteSecret(cleanupCtx, verRefreshKey)
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	// 3. Best-effort mirror to legacyRefreshKey for backward compatibility.
	// Once metadataKey has committed above, loadSessionCredentials resolves the
	// refresh token from verRefreshKey via refreshTokenId, so a mirror failure
	// must never roll back, rewrite, or delete metadataKey or verRefreshKey.
	if err := hostClient.SetSecret(ctx, legacyRefreshKey, tokenResp.RefreshToken); err != nil {
		logr.FromContextOrDiscard(ctx).V(1).Info("warning: failed to mirror refresh token to legacy secret key", "error", err)
	}

	// 4. Garbage-collect the specific revision superseded by this write if it
	// is no longer referenced by metadataKey.
	if prevRevID != "" && prevRevID != revID {
		cleanupCtx, cleanupCancel := p.newCleanupContext(ctx)
		defer cleanupCancel()
		if curMetaRaw, curFound, curErr := hostClient.GetSecret(cleanupCtx, metadataKey); curErr == nil && curFound {
			if curMeta, pErr := p.parseMetadata(curMetaRaw); pErr == nil && curMeta.MetaString(metaKeyRefreshTokenID) != prevRevID {
				_ = hostClient.DeleteSecret(cleanupCtx, p.versionedRefreshKey(ctx, prevRevID))
			}
		}
	}

	return nil
}

// validStoredUserSession reports whether a usable user session is stored:
// a consistent refresh token and loadable metadata with a not-yet-expired
// refresh token, a client ID (the refresh-token request requires it), and a
// last login flow of interactive or device_code. Such a session takes
// precedence over ambient service principal / workload identity environment
// credentials in CLI mode (see cli_mode.go).
func (p *Plugin) validStoredUserSession(ctx context.Context) (*auth.HandlerMetadata, bool) {
	metadata, isUserSession, _ := p.inspectStoredSession(ctx)
	if !isUserSession {
		return nil, false
	}
	return metadata, true
}

// inspectStoredSession loads stored session credentials once and reports both
// the parsed metadata (when loadable) and whether it qualifies as an active
// interactive or device_code user session.
func (p *Plugin) inspectStoredSession(ctx context.Context) (*auth.HandlerMetadata, bool, error) {
	_, metadata, err := p.loadSessionCredentials(ctx)
	if err != nil || metadata == nil {
		return nil, false, err
	}

	if !metadata.ExpiresAt.IsZero() && time.Now().After(metadata.ExpiresAt) {
		return metadata, false, nil
	}

	if metadata.ClientID == "" {
		return metadata, false, nil
	}

	switch metadata.LastLoginFlow {
	case auth.FlowInteractive, auth.FlowDeviceCode:
		return metadata, true, nil
	default:
		return metadata, false, nil
	}
}

// loadSessionCredentials atomically reads and verifies the profile's stored
// refresh token and metadata under the profile read lock.
func (p *Plugin) loadSessionCredentials(ctx context.Context) (string, *auth.HandlerMetadata, error) {
	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()
	return p.loadSessionCredentialsUnlocked(ctx)
}

func (p *Plugin) loadSessionCredentialsUnlocked(ctx context.Context) (string, *auth.HandlerMetadata, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return "", nil, fmt.Errorf("not authenticated: host service not available")
	}

	metaRaw, metaFound, metaErr := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata))
	if metaErr != nil {
		return "", nil, fmt.Errorf("failed to load metadata: %w", metaErr)
	}
	if !metaFound {
		return "", nil, fmt.Errorf("not authenticated: session metadata not found")
	}

	metadata, err := p.parseMetadata(metaRaw)
	if err != nil {
		return "", nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	revID := metadata.MetaString(metaKeyRefreshTokenID)
	wantHash := metadata.MetaString(metaKeyRefreshTokenHash)

	var refreshToken string
	if revID != "" {
		verRT, verFound, verErr := hostClient.GetSecret(ctx, p.versionedRefreshKey(ctx, revID))
		if verErr != nil {
			return "", nil, fmt.Errorf("not authenticated: %w", verErr)
		}
		if verFound && verRT != "" {
			refreshToken = verRT
		}
	}

	if refreshToken == "" {
		legacyRT, legacyFound, legacyErr := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixRefreshToken))
		if legacyErr != nil {
			return "", nil, fmt.Errorf("not authenticated: %w", legacyErr)
		}
		if !legacyFound || legacyRT == "" {
			return "", nil, fmt.Errorf("not authenticated: secret not found: %s", p.secretKey(ctx, secretSuffixRefreshToken))
		}
		refreshToken = legacyRT
	}

	if wantHash != "" && fingerprintHash(refreshToken) != wantHash {
		return "", nil, fmt.Errorf("not authenticated: stored session credentials are inconsistent, please re-authenticate with '%s auth login entra'", p.binaryName())
	}

	return refreshToken, metadata, nil
}

// loadRefreshToken loads the stored refresh token from the host secret store,
// preferring the metadata-bound versioned secret when session metadata exists.
func (p *Plugin) loadRefreshToken(ctx context.Context) (string, error) {
	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()

	if rt, _, err := p.loadSessionCredentialsUnlocked(ctx); err == nil {
		return rt, nil
	}
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return "", fmt.Errorf("host service not available")
	}
	if _, metaFound, metaErr := hostClient.GetSecret(ctx, p.secretKey(ctx, secretSuffixMetadata)); metaErr == nil && !metaFound {
		return p.getSecret(ctx, p.secretKey(ctx, secretSuffixRefreshToken))
	}
	return "", fmt.Errorf("stored session credentials are missing or inconsistent")
}

// loadRefreshTokenStatus reports whether a refresh token entry should be listed
// by ListCachedTokens, along with any consistent metadata.
func (p *Plugin) loadRefreshTokenStatus(ctx context.Context) (bool, *auth.HandlerMetadata) {
	mu := p.profileLock(ctx)
	mu.RLock()
	defer mu.RUnlock()

	if _, metadata, err := p.loadSessionCredentialsUnlocked(ctx); err == nil && metadata != nil {
		return true, metadata
	}

	if !p.secretExists(ctx, p.secretKey(ctx, secretSuffixMetadata)) {
		rt, err := p.getSecret(ctx, p.secretKey(ctx, secretSuffixRefreshToken))
		return err == nil && rt != "", nil
	}
	return false, nil
}

func (p *Plugin) parseMetadata(raw string) (*auth.HandlerMetadata, error) {
	var metadata auth.HandlerMetadata
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Pre-canonical sessions stored tenantId at the top level; they decode
	// with no tenant and a zero ExpiresAt. Reject them so callers report
	// unauthenticated and the documented one-time re-login is triggered.
	if metadata.MetaString(MetaKeyTenantID) == "" {
		return nil, fmt.Errorf("stored session metadata is missing tenant ID (legacy format), please re-authenticate with '%s auth login entra'", p.binaryName())
	}

	return &metadata, nil
}

// extractClaims extracts normalized claims from the token response.
// It parses the ID token's payload (without signature verification -- the token
// was just received from the IdP over TLS).
func (p *Plugin) extractClaims(tokenResp *TokenResponse) (*auth.Claims, error) {
	if tokenResp.IDToken == "" {
		return &auth.Claims{}, nil
	}

	return parseJWTClaims(tokenResp.IDToken)
}

// parseJWTClaims decodes the payload of a JWT and maps standard OIDC claims
// to auth.Claims. Signature verification is intentionally skipped because the
// token was received directly from the IdP over TLS.
func parseJWTClaims(rawJWT string) (*auth.Claims, error) {
	parts := strings.SplitN(rawJWT, ".", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT: expected at least 2 parts, got %d", len(parts))
	}

	// Decode the payload (2nd segment)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload encoding: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	claims := &auth.Claims{
		Subject:  stringClaim(raw, "sub"),
		Name:     stringClaim(raw, "name"),
		Username: stringClaim(raw, "preferred_username"),
		Email:    stringClaim(raw, "email"),
		Issuer:   stringClaim(raw, "iss"),
		TenantID: stringClaim(raw, "tid"),
		ObjectID: stringClaim(raw, "oid"),
	}

	// Parse expiration timestamp
	if exp, ok := raw["exp"].(float64); ok {
		claims.ExpiresAt = time.Unix(int64(exp), 0)
	}

	return claims, nil
}

// stringClaim safely extracts a string claim from a map.
func stringClaim(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// ensureOfflineAccess appends "offline_access" to a space-delimited scope
// string when it is not already present.
func ensureOfflineAccess(scope string) string {
	for _, s := range strings.Split(scope, " ") {
		if s == "offline_access" {
			return scope
		}
	}
	return scope + " offline_access"
}

// requiredOIDCScopes returns the OIDC scopes that must always be present in
// login requests. Declared as a function returning a fixed-size array to
// prevent accidental mutation of the backing storage.
func requiredOIDCScopes() [3]string {
	return [3]string{"openid", "profile", "offline_access"}
}

// ensureOIDCScopes ensures that openid, profile, and offline_access scopes
// are present in the slice. These are required so that the token response
// includes an ID token with user identity claims (preferred_username, name).
// The returned slice is always a new allocation; the input is never modified.
func ensureOIDCScopes(scopes []string) []string {
	have := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		have[s] = true
	}
	required := requiredOIDCScopes()
	result := make([]string, len(scopes), len(scopes)+len(required))
	copy(result, scopes)
	for _, s := range required {
		if !have[s] {
			result = append(result, s)
		}
	}
	return result
}

// generateSessionID creates a new unique session identifier.
func generateSessionID() string {
	return uuid.New().String()
}

// makeFormData creates url.Values from a map for convenience.
func makeFormData(m map[string]string) url.Values {
	vals := make(url.Values, len(m))
	for k, v := range m {
		vals[k] = []string{v}
	}
	return vals
}
