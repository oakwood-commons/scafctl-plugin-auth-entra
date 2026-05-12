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

// TokenMetadata stores information about the stored credentials.
type TokenMetadata struct {
	Claims                *auth.Claims `json:"claims"`
	RefreshTokenExpiresAt time.Time    `json:"refreshTokenExpiresAt"`
	LastRefresh           time.Time    `json:"lastRefresh"`
	TenantID              string       `json:"tenantId"`
	ClientID              string       `json:"clientId,omitempty"`
	Scopes                []string     `json:"scopes,omitempty"`
	LoginFlow             auth.Flow    `json:"loginFlow,omitempty"`
	SessionID             string       `json:"sessionId,omitempty"`
}

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

	// Load refresh token
	refreshToken, err := p.loadRefreshToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("not authenticated: %w", err)
	}

	// Load metadata for tenant info
	metadata, err := p.loadMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	// Request new access token using refresh token
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", p.config.GetAuthority(), metadata.TenantID)

	if metadata.ClientID == "" {
		return nil, fmt.Errorf("stored credentials are missing client ID, please re-authenticate with '%s auth login entra'", p.binaryName())
	}

	data := makeFormData(map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     metadata.ClientID,
		"refresh_token": refreshToken,
		"scope":         ensureOfflineAccess(scope),
	})

	resp, err := p.httpClient.PostForm(ctx, endpoint, data)
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
			_ = p.logoutInternal(ctx)
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

	// If we got a new refresh token, store it (token rotation)
	if tokenResp.RefreshToken != "" && tokenResp.RefreshToken != refreshToken {
		lgr.V(1).Info("refresh token rotated, storing new token")
		if err := p.storeCredentials(ctx, metadata.TenantID, &tokenResp, metadata.ClientID, metadata.Scopes, metadata.LoginFlow, metadata.SessionID); err != nil {
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
		Flow:        metadata.LoginFlow,
		SessionID:   metadata.SessionID,
	}, nil
}

// storeCredentials securely stores the refresh token and metadata.
func (p *Plugin) storeCredentials(ctx context.Context, tenantID string, tokenResp *TokenResponse, clientID string, scopes []string, loginFlow auth.Flow, sessionID string) error {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	// Validate refresh token is present
	if tokenResp.RefreshToken == "" {
		return fmt.Errorf("no refresh token in response (offline_access scope may be missing)")
	}

	// Store refresh token
	if err := hostClient.SetSecret(ctx, SecretKeyRefreshToken, tokenResp.RefreshToken); err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Generate a new session ID on initial login; preserve across rotations.
	if sessionID == "" {
		sessionID = generateSessionID()
	}

	// Extract claims and store metadata
	claims, err := p.extractClaims(tokenResp)
	if err != nil {
		// Use minimal claims if extraction fails
		claims = &auth.Claims{
			TenantID: tenantID,
		}
	}

	metadata := &TokenMetadata{
		Claims:                claims,
		RefreshTokenExpiresAt: time.Now().Add(DefaultRefreshTokenLifetime),
		LastRefresh:           time.Now(),
		TenantID:              tenantID,
		ClientID:              clientID,
		Scopes:                scopes,
		LoginFlow:             loginFlow,
		SessionID:             sessionID,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := hostClient.SetSecret(ctx, SecretKeyMetadata, string(metadataBytes)); err != nil {
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	return nil
}

// loadRefreshToken loads the stored refresh token from the host secret store.
func (p *Plugin) loadRefreshToken(ctx context.Context) (string, error) {
	return p.getSecret(ctx, SecretKeyRefreshToken)
}

// loadMetadata loads the stored token metadata from the host secret store.
func (p *Plugin) loadMetadata(ctx context.Context) (*TokenMetadata, error) {
	raw, err := p.getSecret(ctx, SecretKeyMetadata)
	if err != nil {
		return nil, err
	}

	var metadata TokenMetadata
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
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
