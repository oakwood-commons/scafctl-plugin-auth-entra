// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	oauth "github.com/oakwood-commons/oauth-helpers"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// defaultBrowserOpener opens a URL in the system browser using the oauth-helpers package.
func defaultBrowserOpener(ctx context.Context, u string) error {
	return oauth.OpenBrowser(ctx, u)
}

// authCodeLogin performs the authorization code + PKCE authentication flow.
func (p *Plugin) authCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting authorization code + PKCE flow")

	// Determine tenant
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = p.config.TenantID
	}

	// Determine scopes
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = p.config.DefaultScopes
	}

	// Ensure offline_access is included for refresh token
	hasOfflineAccess := false
	for _, s := range scopes {
		if s == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}
	if !hasOfflineAccess {
		scopes = append(scopes, "offline_access")
	}

	// Determine timeout
	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	// Generate PKCE code verifier and challenge
	codeVerifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("entra: pkce_generate: %w", err)
	}
	codeChallenge := oauth.GenerateCodeChallenge(codeVerifier)

	// Generate random state for CSRF protection
	state, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("entra: state_generate: %w", err)
	}

	// Start local callback server for OAuth redirect
	callbackServer, err := oauth.StartCallbackServer(ctx, 0, state)
	if err != nil {
		return nil, fmt.Errorf("entra: callback_server: %w", err)
	}
	defer func() { _ = callbackServer.Close() }()

	redirectURI := callbackServer.RedirectURI

	// Build authorization URL
	scopeStr := strings.Join(scopes, " ")
	authURL := fmt.Sprintf("%s/%s/oauth2/v2.0/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&code_challenge=%s&code_challenge_method=S256&state=%s",
		p.config.GetAuthority(),
		tenantID,
		url.QueryEscape(p.config.ClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scopeStr),
		url.QueryEscape(codeChallenge),
		url.QueryEscape(state),
	)

	// Append claims parameter if provided (e.g. from a claims challenge)
	if claims := claimsChallengeFromContext(ctx); claims != "" {
		authURL += "&claims=" + url.QueryEscape(claims)
	}

	// Open browser
	lgr.V(1).Info("opening browser for authentication", "url", authURL)
	browserOpenErr := p.openBrowser(ctx, authURL)
	if browserOpenErr != nil {
		lgr.V(0).Info("failed to open browser, please open this URL manually", "url", authURL)
	}

	// Notify callback so the CLI can show a "Re-open in browser" action
	if deviceCodeCb != nil {
		deviceCodeCb(sdkplugin.DeviceCodePrompt{
			VerificationURI: authURL,
			Message:         "Open this URL in your browser to authenticate",
		})
	}

	// Wait for authorization code or timeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var authCode string
	select {
	case result := <-callbackServer.ResultChan():
		if result.Err != nil {
			errMsg := result.Err.Error()
			if strings.Contains(errMsg, "AADSTS") {
				if hint := aadstsHint(errMsg); hint != "" {
					return nil, fmt.Errorf("entra: auth_code: %w\nHint: %s", result.Err, hint)
				}
			}
			return nil, fmt.Errorf("entra: auth_code: %w", result.Err)
		}
		authCode = result.Code
		lgr.V(1).Info("received authorization code")
	case <-timer.C:
		return nil, fmt.Errorf("entra: auth_code: no response received from browser within %s; "+
			"if using a custom --client-id, ensure http://localhost is registered as a redirect URI "+
			"in the app registration, or use '--flow device-code'", timeout)
	case <-ctx.Done():
		return nil, fmt.Errorf("entra: auth_code: authentication cancelled")
	}

	// Exchange authorization code for tokens
	tokenResp, err := p.exchangeAuthCode(ctx, tenantID, authCode, redirectURI, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("entra: token_exchange: %w", err)
	}

	// Store refresh token and metadata
	if err := p.storeCredentials(ctx, tenantID, tokenResp, p.config.ClientID, scopes, "interactive", ""); err != nil {
		return nil, fmt.Errorf("entra: store_credentials: %w", err)
	}

	// Extract and return claims
	claims, err := p.extractClaims(tokenResp)
	if err != nil {
		return nil, fmt.Errorf("entra: extract_claims: %w", err)
	}

	lgr.V(1).Info("authorization code flow completed successfully",
		"subject", claims.Subject,
		"tenantId", claims.TenantID,
	)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: time.Now().Add(DefaultRefreshTokenLifetime),
	}, nil
}

// exchangeAuthCode exchanges an authorization code for tokens at the Entra
// token endpoint. This is a public client flow (PKCE) so no client_secret
// is sent.
func (p *Plugin) exchangeAuthCode(ctx context.Context, tenantID, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", p.config.GetAuthority(), tenantID)

	data := makeFormData(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     p.config.ClientID,
		"code":          code,
		"redirect_uri":  redirectURI,
		"code_verifier": codeVerifier,
	})

	resp, err := p.httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return nil, fmt.Errorf("token exchange failed with status %d: decode error: %w; body: %s", resp.StatusCode, decErr, string(body))
		}
		if strings.Contains(errResp.ErrorDescription, "AADSTS") {
			return nil, formatAADSTSError("token exchange failed", errResp)
		}
		return nil, fmt.Errorf("token exchange failed: %s - %s", errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}
