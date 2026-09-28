// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// cliMode implements mode for interactive CLI usage.
type cliMode struct {
	p *Plugin
}

// defaultLoginFlow is the flow used when no flow is specified and no
// credentials or DefaultFlow config indicate otherwise. Interactive
// (authorization code + PKCE) is the safer default than device code: its
// code is bound to the local machine by the localhost redirect and PKCE,
// while a device code is machine-independent and the flow most abused in
// phishing. Headless environments fall back to device code via
// interactiveLogin.
const defaultLoginFlow = auth.FlowInteractive

// preferredFlow returns the flow to use when the caller did not specify
// one: config DefaultFlow when it names a user flow (interactive or device
// code), otherwise defaultLoginFlow. Credential-only flows (workload
// identity, service principal) are reached via credential detection, so a
// DefaultFlow naming them without credentials falls back to the default.
func (p *Plugin) preferredFlow() auth.Flow {
	switch f := auth.Flow(p.config.DefaultFlow); f { //nolint:exhaustive // only user flows are valid preferences
	case auth.FlowInteractive, auth.FlowDeviceCode:
		return f
	default:
		return defaultLoginFlow
	}
}

// Login performs the authentication flow in CLI mode.
//
// Flow selection precedence:
//  1. Explicit FlowWorkloadIdentity -- uses federated token from environment.
//  2. Explicit FlowServicePrincipal -- uses client credentials from environment.
//  3. Implicit credential detection -- when no flow is specified, checks for
//     workload identity and service principal environment credentials.
//  4. Explicit FlowInteractive -- authorization code + PKCE flow.
//  5. Explicit FlowDeviceCode -- device code polling flow.
//  6. Empty flow (no credentials detected) -- config DefaultFlow when it is
//     interactive or device_code, otherwise the handler default (interactive;
//     falls back to device code when no browser is available).
func (m *cliMode) Login(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	// Determine which flow to use with credential detection.
	flow := req.Flow
	if flow == "" {
		if m.p.hasWorkloadIdentityCredentials() {
			flow = auth.FlowWorkloadIdentity
		} else if m.p.hasServicePrincipalCredentials() {
			flow = auth.FlowServicePrincipal
		} else {
			flow = m.p.preferredFlow()
		}
	}

	switch flow { //nolint:exhaustive // Only Entra-supported flows are handled
	case auth.FlowWorkloadIdentity:
		return m.p.workloadIdentityLogin(ctx, req)
	case auth.FlowServicePrincipal:
		return m.p.servicePrincipalLogin(ctx, req)
	case auth.FlowInteractive:
		return m.p.interactiveLogin(ctx, req, deviceCodeCb, req.Flow == "", m.p.headlessReason())
	case auth.FlowDeviceCode:
		return m.p.deviceCodeLogin(ctx, req, deviceCodeCb)
	default:
		return nil, fmt.Errorf("unsupported flow: %s", flow)
	}
}

// Logout revokes the current session in CLI mode by clearing stored
// credentials and cached tokens.
func (m *cliMode) Logout(ctx context.Context) error {
	return m.p.logoutInternal(ctx)
}

// GetStatus returns the current authentication status in CLI mode.
//
// Credential precedence: a valid stored user session (interactive or
// device-code login) wins over ambient environment credentials, because an
// explicit user login is a stronger signal of intent than AZURE_* env vars.
// `auth logout entra` clears the stored session and restores env-credential
// behavior.
func (m *cliMode) GetStatus(ctx context.Context) (*auth.Status, error) {
	// Check for a valid stored user session first (highest priority)
	if metadata, ok := m.p.validStoredUserSession(ctx); ok {
		return &auth.Status{
			Authenticated: true,
			Claims:        metadata.Claims,
			ExpiresAt:     metadata.ExpiresAt,
			LastRefresh:   metadata.LastRefresh,
			TenantID:      metadata.MetaString(MetaKeyTenantID),
			IdentityType:  auth.IdentityTypeUser,
			ClientID:      metadata.ClientID,
			Scopes:        metadata.Scopes,
			Flow:          metadata.LastLoginFlow,
		}, nil
	}

	// Check for workload identity credentials
	if m.p.hasWorkloadIdentityCredentials() {
		return m.p.workloadIdentityStatus()
	}

	// Check for service principal credentials
	if m.p.hasServicePrincipalCredentials() {
		return m.p.servicePrincipalStatus()
	}

	// Check if we have stored credentials
	if !m.p.secretExists(ctx, m.p.secretKey(ctx, secretSuffixRefreshToken)) {
		return &auth.Status{Authenticated: false}, nil
	}

	// Load and validate metadata
	metadata, err := m.p.loadMetadata(ctx)
	if err != nil {
		return &auth.Status{Authenticated: false}, nil //nolint:nilerr // corrupted metadata = not authenticated
	}

	// Check if refresh token is expired
	if !metadata.ExpiresAt.IsZero() && time.Now().After(metadata.ExpiresAt) {
		return &auth.Status{
			Authenticated: false,
			Reason:        "session expired",
			Claims:        metadata.Claims,
		}, nil
	}

	return &auth.Status{
		Authenticated: true,
		Claims:        metadata.Claims,
		ExpiresAt:     metadata.ExpiresAt,
		LastRefresh:   metadata.LastRefresh,
		TenantID:      metadata.MetaString(MetaKeyTenantID),
		IdentityType:  auth.IdentityTypeUser,
		ClientID:      metadata.ClientID,
		Scopes:        metadata.Scopes,
		Flow:          metadata.LastLoginFlow,
	}, nil
}

// GetToken returns a valid access token in CLI mode, refreshing if necessary.
//
// Credential precedence mirrors GetStatus: a valid stored user session wins
// over ambient environment credentials, so `auth token` serves the user
// session after an explicit login even when AZURE_* env vars are set.
func (m *cliMode) GetToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	// Use the stored user session first when valid (highest priority)
	if metadata, ok := m.p.validStoredUserSession(ctx); ok {
		return m.userSessionToken(ctx, req, metadata)
	}

	// Use workload identity flow if credentials are present
	if m.p.hasWorkloadIdentityCredentials() {
		return m.p.getWorkloadIdentityToken(ctx, req)
	}

	// Use service principal flow if credentials are present
	if m.p.hasServicePrincipalCredentials() {
		return m.p.getServicePrincipalToken(ctx, req)
	}

	// No environment credentials and no valid session: fall through to the
	// session path, which reports the relevant error (missing scope, or
	// not authenticated when refreshing fails).
	return m.userSessionToken(ctx, req, nil)
}

// userSessionFingerprint derives the user-flow cache-key fingerprint from
// the effective identity of the stored session -- the metadata's client and
// tenant (the values mintToken actually sends), the authority, and the
// user oid claim when present -- rather than the handler config, so the
// cache key and the credential behind it cannot disagree (issue #49).
// With no stored session the config values are the only identity available,
// so they serve as the fallback.
func (p *Plugin) userSessionFingerprint(metadata *auth.HandlerMetadata) string {
	clientID := p.config.ClientID
	tenantID := p.config.TenantID
	oid := ""
	sessionID := ""
	if metadata != nil {
		clientID = metadata.ClientID
		tenantID = metadata.MetaString(MetaKeyTenantID)
		sessionID = metadata.SessionID
		if metadata.Claims != nil {
			oid = metadata.Claims.ObjectID
		}
	}
	// "user:" keeps user-session entries apart from SP/WI entries that
	// share the same client/tenant/authority, and the trailing sessionID
	// keeps entries apart across stored sessions: each login gets a new
	// session ID (refresh-token rotation reuses it), so a token cached for
	// an earlier session is never served to a later one.
	return fingerprintHash("user:" + clientID + ":" + tenantID + ":" + p.config.GetAuthority() + ":" + oid + ":" + sessionID)
}

// userSessionToken serves a token from the user session described by
// metadata (nil when no session is stored): cache lookup first, then
// minting via the refresh token.
func (m *cliMode) userSessionToken(ctx context.Context, req sdkplugin.TokenRequest, metadata *auth.HandlerMetadata) (*sdkplugin.TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	scope := req.Scope
	if scope == "" {
		return nil, fmt.Errorf("scope is required for token request")
	}

	// Qualify bare permission names
	qualifiedScope := QualifyScope(scope)

	minValidFor := req.MinValidFor
	if minValidFor == 0 {
		minValidFor = auth.DefaultMinValidFor
	}

	lgr.V(1).Info("getting token",
		"handler", HandlerName,
		"scope", qualifiedScope,
		"minValidFor", minValidFor,
		"forceRefresh", req.ForceRefresh,
	)

	hostClient := m.p.hostClient(ctx)
	fullKey := m.p.tokenCachePrefix(ctx) + m.p.userSessionFingerprint(metadata) + ":" + qualifiedScope

	// Check cache first (unless force refresh)
	if !req.ForceRefresh && hostClient != nil {
		token, err := cacheGet(ctx, hostClient, fullKey)
		if err == nil && token != nil && token.IsValidFor(minValidFor) {
			lgr.V(1).Info("using cached token",
				"scope", qualifiedScope,
				"expiresAt", token.ExpiresAt,
				"remainingValidity", token.TimeUntilExpiry(),
			)
			return &sdkplugin.TokenResponse{
				AccessToken: token.AccessToken,
				TokenType:   token.TokenType,
				ExpiresAt:   token.ExpiresAt,
				Scope:       token.Scope,
				Flow:        token.Flow,
				SessionID:   token.SessionID,
			}, nil
		}
		if err != nil {
			lgr.V(1).Info("cache lookup failed, will mint new token", "error", err)
		} else if token != nil {
			lgr.V(1).Info("cached token insufficient validity",
				"expiresAt", token.ExpiresAt,
				"remainingValidity", token.TimeUntilExpiry(),
				"requiredValidity", minValidFor,
			)
		}
	}

	// Mint new token
	token, err := m.p.mintToken(ctx, qualifiedScope)
	if err != nil {
		return nil, err
	}

	// Cache the token
	if hostClient != nil {
		if cacheErr := cacheSet(ctx, hostClient, fullKey, token); cacheErr != nil {
			lgr.V(1).Info("failed to cache token", "error", cacheErr)
		}
	}

	return &sdkplugin.TokenResponse{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresAt:   token.ExpiresAt,
		Scope:       token.Scope,
		Flow:        token.Flow,
		SessionID:   token.SessionID,
	}, nil
}

// ListCachedTokens returns metadata for all tokens stored by the Entra handler
// in CLI mode.
func (m *cliMode) ListCachedTokens(ctx context.Context) ([]*auth.CachedTokenInfo, error) {
	hostClient := m.p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("host service not available")
	}

	var results []*auth.CachedTokenInfo

	// Refresh token
	if m.p.secretExists(ctx, m.p.secretKey(ctx, secretSuffixRefreshToken)) {
		info := &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "refresh",
		}
		if metadata, err := m.p.loadMetadata(ctx); err == nil && metadata != nil {
			info.ExpiresAt = metadata.ExpiresAt
			info.CachedAt = metadata.LastRefresh
			info.Flow = metadata.LastLoginFlow
			info.SessionID = metadata.SessionID
		}
		if !info.ExpiresAt.IsZero() {
			info.IsExpired = time.Now().After(info.ExpiresAt)
		}
		results = append(results, info)
	}

	// Minted access tokens from cache
	entries, _ := cacheListEntries(ctx, hostClient, m.p.tokenCachePrefix(ctx))
	results = append(results, entries...)

	return results, nil
}

// PurgeExpiredTokens removes expired access tokens from the cache in CLI mode.
func (m *cliMode) PurgeExpiredTokens(ctx context.Context) (int, error) {
	hostClient := m.p.hostClient(ctx)
	if hostClient == nil {
		return 0, fmt.Errorf("host service not available")
	}

	return cachePurgeExpired(ctx, hostClient, m.p.tokenCachePrefix(ctx))
}

// DetectAvailableFlows reports which auth flows are available based on
// environment credentials or configuration in CLI mode.
func (m *cliMode) DetectAvailableFlows(_ context.Context) ([]sdkplugin.FlowAvailability, error) {
	var flows []sdkplugin.FlowAvailability

	// Workload identity flow -- check config and environment variables
	if m.p.hasWorkloadIdentityCredentials() {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowWorkloadIdentity,
			Available: true,
			Reason:    "workload identity credentials configured",
		})
	} else {
		reason := m.p.detectWorkloadIdentityUnavailableReason()
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowWorkloadIdentity,
			Available: false,
			Reason:    reason,
		})
	}

	// Service principal flow -- check config and environment variables
	if m.p.hasServicePrincipalCredentials() {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowServicePrincipal,
			Available: true,
			Reason:    "service principal credentials configured",
		})
	} else {
		reason := "service principal credentials not configured"
		var missing []string
		clientID := m.p.profileOrEnv(m.p.config.ClientID, "clientId", EnvAzureClientID)
		clientSecret := m.p.profileOrEnv(m.p.config.ClientSecret, "clientSecret", EnvAzureClientSecret)
		tenantID := m.p.profileOrEnv(m.p.config.TenantID, "tenantId", EnvAzureTenantID)
		if clientID == "" {
			missing = append(missing, EnvAzureClientID)
		}
		if clientSecret == "" {
			missing = append(missing, EnvAzureClientSecret)
		}
		if tenantID == "" {
			missing = append(missing, EnvAzureTenantID)
		}
		if len(missing) > 0 {
			reason = fmt.Sprintf("missing %s (not in config or environment)", strings.Join(missing, ", "))
		}
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowServicePrincipal,
			Available: false,
			Reason:    reason,
		})
	}

	// Device code and interactive flows are always available. Order the
	// pair so the preferred flow comes first: config DefaultFlow when
	// set, otherwise the handler default. The host picks the first
	// available entry, so this ordering decides the flow used when no
	// --flow flag is passed -- including for an implicit interactive
	// default on a headless session: a headless (browserless) session
	// reorders the pair to device code first, so the host resolves a
	// no-flag login to device code instead of an auth-code flow that
	// cannot complete. Workload identity and service principal entries
	// stay ahead so detected credentials keep precedence over DefaultFlow.
	// An explicit --flow interactive still runs the auth-code flow.
	deviceCodeFlow := sdkplugin.FlowAvailability{
		Flow:      auth.FlowDeviceCode,
		Available: true,
		Reason:    "device code flow is always available",
	}
	interactiveFlow := sdkplugin.FlowAvailability{
		Flow:      auth.FlowInteractive,
		Available: true,
		Reason:    "interactive flow is always available",
	}
	headlessReason := m.p.headlessReason()
	if m.p.preferredFlow() == auth.FlowInteractive && headlessReason == "" {
		flows = append(flows, interactiveFlow, deviceCodeFlow)
	} else {
		if headlessReason != "" {
			interactiveFlow.Reason = "interactive flow requires a browser (" +
				headlessReason + "); pass --flow interactive to force it"
		}
		flows = append(flows, deviceCodeFlow, interactiveFlow)
	}

	return flows, nil
}
