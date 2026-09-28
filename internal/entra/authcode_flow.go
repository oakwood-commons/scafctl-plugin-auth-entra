// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
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
// When browserRequired is true, a failure to open the browser aborts the
// flow with errBrowserUnavailable so the caller can fall back to device
// code; otherwise the URL is shown for manual opening and the flow waits
// for the callback as before.
func (p *Plugin) authCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt), browserRequired bool) (*sdkplugin.LoginResponse, error) {
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

	// Ensure OIDC scopes are included so the response contains an ID token
	// with user claims (preferred_username, name).
	scopes = ensureOIDCScopes(scopes)

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

	// Start local callback server for OAuth redirect. A zero CallbackPort
	// lets the OS pick an ephemeral port; a specific port keeps the
	// redirect URI predictable for SSH/devcontainer port forwarding.
	callbackServer, err := oauth.StartCallbackServer(ctx, req.CallbackPort, state)
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
		if browserRequired {
			return nil, fmt.Errorf("entra: auth_code: %w: %w", errBrowserUnavailable, browserOpenErr)
		}
		lgr.V(0).Info("failed to open browser, please open this URL manually", "url", authURL)
	}

	// Notify callback so the CLI can show a "Re-open in browser" action
	if deviceCodeCb != nil {
		deviceCodeCb(sdkplugin.DeviceCodePrompt{
			VerificationURI: authURL,
			Message:         "Open this URL in your browser to authenticate",
		})
	}

	// Ask the host to collect a pasted redirect URL in the background
	// (issue #66). In remote workspaces (DevSpaces, Codespaces) the browser
	// runs on the user's laptop and the localhost redirect cannot reach
	// this machine; the user pastes the URL the browser landed on instead.
	// Older hosts return Unimplemented from the RPC itself and
	// non-interactive hosts return Unavailable; both (and any other host
	// error) are logged at debug and left undelivered so the select below
	// keeps today's callback-only behavior.
	pasteCh := make(chan string, 1)
	promptCtx, cancelPrompt := context.WithCancel(ctx)
	defer cancelPrompt()
	if hostClient := p.hostClient(ctx); hostClient != nil {
		go func() {
			value, err := hostClient.PromptAuthResponse(promptCtx, HandlerName, authURL, redirectURI)
			if err != nil {
				logr.FromContextOrDiscard(promptCtx).V(1).Info("host paste-back prompt unavailable, waiting for callback only", "error", err)
				return
			}
			select {
			case pasteCh <- value:
			case <-promptCtx.Done():
			}
		}()
	}

	// Wait for the authorization code from the local callback, a pasted
	// redirect URL (remote workspaces), the timeout, or cancellation.
	// Whichever arrives first wins; the deferred cancelPrompt releases the
	// paste goroutine when another source wins.
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var authCode string
	select {
	case result := <-callbackServer.ResultChan():
		if result.Err != nil {
			return nil, authCallbackError(result.Err.Error())
		}
		authCode = result.Code
		lgr.V(1).Info("received authorization code")
	case pasted := <-pasteCh:
		authCode, err = parsePastedRedirect(pasted, redirectURI, state)
		if err != nil {
			return nil, err
		}
		lgr.V(1).Info("received pasted authorization response")
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

	// Drop tokens cached for any previous identity before the new session's
	// credentials land (issue #49).
	p.clearUserTokenCache(ctx)

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

// sanitizeControlChars strips C0 (U+0000-U+001F), DEL (U+007F), and C1
// (U+0080-U+009F) control characters from a string, so callback-supplied
// text cannot inject terminal escape sequences into errors printed to the
// terminal (issue #49).
func sanitizeControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x1f || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

// authCallbackError formats a redirect-supplied error message (from the HTTP
// callback or a pasted redirect URL): control characters are stripped (issue
// #49; remove the sanitize call once oakwood-commons/oauth-helpers#17 ships
// and the dependency is bumped) and a well-known AADSTS code gets a hint.
func authCallbackError(raw string) error {
	msg := sanitizeControlChars(raw)
	if hint := aadstsHint(msg); hint != "" {
		return fmt.Errorf("entra: auth_code: %s\nHint: %s", msg, hint)
	}
	return fmt.Errorf("entra: auth_code: %s", msg)
}

// effectivePath normalizes a URL path for callback comparison: a redirect
// URI without a path (http://localhost:port) and the browser's landing page
// (http://localhost:port/?code=...) address the same location, so "" and
// "/" are equivalent.
func effectivePath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// parsePastedRedirect validates a redirect URL pasted by the user (issue
// #66) and extracts the authorization code. The paste is parsed
// defensively: surrounding whitespace is trimmed and a dropped "http://"
// scheme is restored. Scheme, host, port, and path must match the running
// callback server's redirect URI exactly, and the state parameter must
// match the generated state in constant time (CSRF protection, mirroring
// the HTTP callback handler). An error= response is reported through the
// same sanitizeControlChars + AADSTS hint machinery as the callback path.
func parsePastedRedirect(pasted, redirectURI, expectedState string) (string, error) {
	raw := strings.TrimSpace(pasted)
	// Terminals and address bars often strip the scheme when copying; the
	// callback URI is always http, so restore it before parsing.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("entra: pasted response is not a valid URL")
	}
	want, err := url.Parse(redirectURI)
	if err != nil || want.Scheme == "" || want.Hostname() == "" {
		return "", fmt.Errorf("entra: pasted response does not match this login's callback URI (expected %s)", redirectURI)
	}
	if u.Scheme != want.Scheme || u.Hostname() != want.Hostname() || u.Port() != want.Port() ||
		effectivePath(u.Path) != effectivePath(want.Path) {
		return "", fmt.Errorf("entra: pasted response does not match this login's callback URI (expected %s)", redirectURI)
	}
	q := u.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(expectedState)) != 1 {
		return "", errors.New("entra: pasted response state mismatch (possible CSRF attack)")
	}
	if e := q.Get("error"); e != "" {
		msg := "OAuth error: " + e
		if d := q.Get("error_description"); d != "" {
			msg += ": " + d
		}
		return "", authCallbackError(msg)
	}
	code := q.Get("code")
	if code == "" {
		return "", errors.New("entra: pasted response contains no authorization code")
	}
	return code, nil
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
