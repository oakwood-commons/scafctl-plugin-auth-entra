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

// callbackShutdownTimeout bounds graceful draining of the localhost callback
// HTTP response after a callback result is settled.
const callbackShutdownTimeout = 5 * time.Second

type browserPreferenceKeyType struct{}

func withBrowserPreference(ctx context.Context, browser string) context.Context {
	return context.WithValue(ctx, browserPreferenceKeyType{}, browser)
}

func browserPreferenceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(browserPreferenceKeyType{}).(string)
	return v
}

// defaultBrowserOpener opens a URL in the user's preferred or system browser
// using the oauth-helpers package, logging fallback warnings when a configured
// browser preference or $BROWSER cannot be launched.
func defaultBrowserOpener(ctx context.Context, u string) error {
	return oauth.OpenBrowserWithPreference(
		ctx,
		u,
		browserPreferenceFromContext(ctx),
		oauth.WithWarningHandler(func(msg string) {
			logr.FromContextOrDiscard(ctx).V(0).Info(msg)
		}),
	)
}

// authCodeLogin performs the authorization code + PKCE authentication flow.
// When browserRequired is true, a failure to open the browser aborts the
// flow with errBrowserUnavailable so the caller can fall back to device
// code; otherwise the URL is shown for manual opening and the flow waits
// for the callback as before.
func (p *Plugin) authCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt), browserRequired, promptRequired, pasteFallback bool) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting authorization code + PKCE flow")

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	// Determine tenant
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = cfg.TenantID
	}

	// Determine scopes
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = cfg.DefaultScopes
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
	callbackOpts := []oauth.CallbackOption{oauth.WithDeferredCompletion()}
	if pages := p.cfg.AuthCallbackPages; pages != nil {
		callbackOpts = append(callbackOpts, oauth.WithCallbackPages(oauth.CallbackPages{
			SuccessHTML: pages.SuccessHTML,
			FailureHTML: pages.FailureHTML,
		}))
	}
	callbackServer, err := oauth.StartCallbackServer(ctx, req.CallbackPort, state, callbackOpts...)
	if err != nil {
		return nil, fmt.Errorf("entra: callback_server: %w", err)
	}
	drained := false
	drainCallbackServer := func() {
		if drained {
			return
		}
		drained = true
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), callbackShutdownTimeout)
		defer shutdownCancel()
		_ = callbackServer.Shutdown(shutdownCtx)
	}
	defer drainCallbackServer()

	redirectURI := callbackServer.RedirectURI

	// Build authorization URL. Include prompt=select_account so Microsoft
	// Entra always shows the account chooser ("Pick an account" / "Use
	// another account") even when only one browser SSO session is active.
	scopeStr := strings.Join(scopes, " ")
	authURL := fmt.Sprintf("%s/%s/oauth2/v2.0/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&code_challenge=%s&code_challenge_method=S256&state=%s&prompt=select_account",
		cfg.GetAuthority(),
		tenantID,
		url.QueryEscape(cfg.ClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scopeStr),
		url.QueryEscape(codeChallenge),
		url.QueryEscape(state),
	)

	// Append claims parameter if provided (e.g. from a claims challenge)
	if claims := claimsChallengeFromContext(ctx); claims != "" {
		authURL += "&claims=" + url.QueryEscape(claims)
	}

	// Open browser, forwarding any caller-requested browser preference.
	lgr.V(1).Info("opening browser for authentication", "url", authURL, "browser", req.Browser)
	opener := p.openBrowser
	if opener == nil {
		opener = defaultBrowserOpener
	}
	browserOpenErr := opener(withBrowserPreference(ctx, req.Browser), authURL)
	if browserOpenErr != nil {
		if browserRequired {
			return nil, fmt.Errorf("entra: auth_code: %w: %w", errBrowserUnavailable, browserOpenErr)
		}
		lgr.V(0).Info("failed to open browser, please open this URL manually", "url", authURL)
	}

	// Notify callback so the CLI can show the kvx status box (with Copy/Open URL
	// actions) whenever a local browser was launched, or when the host does not
	// support paste-back (e.g. older hosts or SSH port-forwarding without
	// PromptAuthResponse, where deviceCodeCb is the only channel carrying the
	// authorize URL to the CLI). On paste-back-capable hosts when headless or
	// when opening the browser failed, defer the callback so a working paste
	// prompt does not flash a browser TUI box first; if the prompt fails and the
	// flow remains callback-only, emit the suppressed URL notification once.
	localBrowserLaunched := browserOpenErr == nil && p.headlessReason() == ""
	pasteBackAvailable := p.cfg.SupportsPromptAuthResponse() && p.hostClient(ctx) != nil
	notifiedAuthURL := false
	notifyAuthURL := func() {
		if notifiedAuthURL || deviceCodeCb == nil {
			return
		}
		notifiedAuthURL = true
		deviceCodeCb(sdkplugin.DeviceCodePrompt{
			VerificationURI: authURL,
			Message:         "Open this URL in your browser to authenticate",
		})
	}
	if localBrowserLaunched || !pasteBackAvailable {
		notifyAuthURL()
	}

	// Ask the host to collect a pasted redirect URL in the background
	// (issue #66). In remote workspaces (DevSpaces, Codespaces) the browser
	// runs on the user's laptop and the localhost redirect cannot reach
	// this machine; the user pastes the URL the browser landed on instead.
	// Older hosts return Unimplemented from the RPC itself and
	// non-interactive hosts return Unavailable; both (and any other host
	// error) are logged at debug and left undelivered so the select below
	// keeps today's callback-only behavior -- unless promptRequired (an
	// implicit headless login that skipped device code because paste-back
	// was advertised), where the callback is unreachable and a prompt
	// failure is surfaced as errPromptUnavailable so the caller can fall
	// back to device code instead of waiting out the timeout.
	// pasteFallback (implicit login, paste-back advertised) also requires
	// the prompt once the browser failed to open: no callback can arrive.
	promptRequired = promptRequired || (pasteFallback && browserOpenErr != nil)
	pasteCh := make(chan string, 1)
	promptErrCh := make(chan error, 1)
	promptFallbackNotifyCh := make(chan struct{}, 1)
	promptCtx, cancelPrompt := context.WithCancel(ctx)
	defer cancelPrompt()
	if hostClient := p.hostClient(ctx); hostClient != nil {
		go func() {
			value, err := hostClient.PromptAuthResponse(promptCtx, HandlerName, authURL, redirectURI)
			if err != nil {
				if promptRequired {
					promptErrCh <- err
					return
				}
				logr.FromContextOrDiscard(promptCtx).V(1).Info("host paste-back prompt unavailable, waiting for callback only", "error", err)
				if promptCtx.Err() == nil {
					promptFallbackNotifyCh <- struct{}{}
				}
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
	var fromCallback bool
waitForAuthCode:
	for {
		select {
		case result := <-callbackServer.ResultChan():
			if result.Err != nil {
				cancelPrompt()
				drainCallbackServer()
				return nil, authCallbackError(result.Err.Error())
			}
			authCode = result.Code
			fromCallback = true
			lgr.V(1).Info("received authorization code")
			break waitForAuthCode
		case pasted := <-pasteCh:
			authCode, err = parsePastedRedirect(pasted, redirectURI, state)
			if err != nil {
				return nil, err
			}
			lgr.V(1).Info("received pasted authorization response")
			break waitForAuthCode
		case promptErr := <-promptErrCh:
			return nil, fmt.Errorf("entra: auth_code: %w: %w", errPromptUnavailable, promptErr)
		case <-promptFallbackNotifyCh:
			promptFallbackNotifyCh = nil
			if ctx.Err() == nil {
				notifyAuthURL()
			}
		case <-timer.C:
			return nil, fmt.Errorf("entra: auth_code: no response received from browser within %s; "+
				"if using a custom --client-id, ensure http://localhost is registered as a redirect URI "+
				"in the app registration, or use '--flow device-code'", timeout)
		case <-ctx.Done():
			return nil, fmt.Errorf("entra: auth_code: authentication cancelled")
		}
	}
	// Release the host prompt now rather than after the token exchange,
	// so a late paste is not accepted and then discarded.
	cancelPrompt()

	settleCallback := func(success bool) {
		callbackServer.Complete(fromCallback && success)
		drainCallbackServer()
	}

	// Exchange authorization code for tokens
	tokenResp, err := p.exchangeAuthCode(ctx, tenantID, authCode, redirectURI, codeVerifier)
	if err != nil {
		settleCallback(false)
		return nil, fmt.Errorf("entra: token_exchange: %w", err)
	}

	// Validate and extract ID token claims before mutating stored credentials
	// or clearing the previous identity's token cache, so a malformed ID token
	// never leaves partial session state behind when serving a failure page.
	claims, err := p.extractClaims(tokenResp)
	if err != nil {
		settleCallback(false)
		return nil, fmt.Errorf("entra: extract_claims: %w", err)
	}

	// Store refresh token and metadata before dropping cached access tokens
	// from any previous identity, so a credential-write failure leaves a
	// replaced session intact.
	if err := p.storeCredentials(ctx, tenantID, tokenResp, cfg.ClientID, scopes, "interactive", ""); err != nil {
		settleCallback(false)
		return nil, fmt.Errorf("entra: store_credentials: %w", err)
	}

	settleCallback(true)

	lgr.V(1).Info("authorization code flow completed successfully",
		"subject", claims.Subject,
		"tenantId", claims.TenantID,
	)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: time.Now().Add(DefaultRefreshTokenLifetime),
	}, nil
}

// sanitizeControlChars strips C0 (U+0000-U+001F), DEL (U+007F), C1
// (U+0080-U+009F), and Unicode BiDi formatting controls from a string, so
// untrusted redirect or error text cannot inject terminal escape sequences or
// bidirectional spoofing into output printed to the terminal.
func sanitizeControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x1f || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			r == 0x061c || (r >= 0x200e && r <= 0x200f) ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return -1
		}
		return r
	}, s)
}

func truncateRunes(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes])
}

// authCallbackError formats a redirect-supplied error message (from the HTTP
// callback or a pasted redirect URL): control characters are stripped for
// defense-in-depth terminal safety across both paths and a
// well-known AADSTS code gets a hint.
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
		msg := "OAuth error: " + truncateRunes(e, 128)
		if d := q.Get("error_description"); d != "" {
			msg += ": " + truncateRunes(d, 512)
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
	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	httpClient, releaseHTTP, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()

	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", cfg.GetAuthority(), tenantID)

	data := makeFormData(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     cfg.ClientID,
		"code":          code,
		"redirect_uri":  redirectURI,
		"code_verifier": codeVerifier,
	})

	resp, err := httpClient.PostForm(ctx, endpoint, data)
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
