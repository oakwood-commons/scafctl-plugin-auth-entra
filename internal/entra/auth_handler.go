// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package entra implements the Microsoft Entra ID auth handler plugin.
package entra

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"

	"github.com/oakwood-commons/scafctl-plugin-auth-entra/internal/clock"
)

const (
	// HandlerName is the unique identifier for this auth handler.
	HandlerName = "entra"

	// HandlerDisplayName is the human-readable name for the handler.
	HandlerDisplayName = "Microsoft Entra ID"

	// secretKeyBase is the base prefix for all Entra auth handler secrets.
	secretKeyBase = "scafctl.auth.entra" //nolint:gosec // key prefix, not a credential

	// secretSuffixRefreshToken is the key suffix for the refresh token.
	secretSuffixRefreshToken = "refresh_token" //nolint:gosec // key suffix, not a credential

	// secretSuffixMetadata is the key suffix for token metadata.
	secretSuffixMetadata = "metadata" //nolint:gosec // key suffix, not a credential

	// secretSuffixTokenPrefix is the key suffix for cached access tokens.
	secretSuffixTokenPrefix = "token." //nolint:gosec // key suffix, not a credential

	// SecretKeyRefreshToken is the default (no-profile) secret key for the refresh token.
	SecretKeyRefreshToken = secretKeyBase + "." + secretSuffixRefreshToken //nolint:gosec // key name, not a credential

	// SecretKeyMetadata is the default (no-profile) secret key for token metadata.
	SecretKeyMetadata = secretKeyBase + "." + secretSuffixMetadata //nolint:gosec // key name, not a credential

	// SecretKeyTokenPrefix is the default (no-profile) prefix for cached access tokens.
	SecretKeyTokenPrefix = secretKeyBase + "." + secretSuffixTokenPrefix //nolint:gosec // key prefix, not a credential

	// DefaultTimeout is the default timeout for device code flow.
	DefaultTimeout = 5 * time.Minute

	// DefaultMinPollInterval is the minimum polling interval for device code flow.
	DefaultMinPollInterval = 5 * time.Second

	// DefaultRefreshTokenLifetime is the expected lifetime of refresh tokens.
	// Azure AD refresh tokens are valid for 90 days by default.
	DefaultRefreshTokenLifetime = 90 * 24 * time.Hour

	// FlowOnBehalfOf identifies the OBO flow.
	FlowOnBehalfOf = "on_behalf_of"
)

// BrowserOpenFunc is the signature for a function that opens a URL in the browser.
type BrowserOpenFunc func(ctx context.Context, url string) error

// Plugin implements the scafctl AuthHandlerPlugin interface.
type Plugin struct {
	cfg              sdkplugin.ProviderConfig
	config           *Config
	httpClient       HTTPClient
	graphClient      GraphClient
	clock            clock.Clock
	cachedHostClient *sdkplugin.HostServiceClient
	openBrowser      BrowserOpenFunc
	oboCache         *oboCache
}

// GetAuthHandlers returns the list of auth handlers exposed by this plugin.
//
//nolint:revive // ctx required by interface
func (p *Plugin) GetAuthHandlers(_ context.Context) ([]sdkplugin.AuthHandlerInfo, error) {
	return []sdkplugin.AuthHandlerInfo{
		{
			Name:        HandlerName,
			DisplayName: HandlerDisplayName,
			Flows: []auth.Flow{
				auth.FlowInteractive,
				auth.FlowDeviceCode,
				auth.FlowServicePrincipal,
				auth.FlowWorkloadIdentity,
			},
			Capabilities: []auth.Capability{
				auth.CapScopesOnLogin,
				auth.CapScopesOnTokenRequest,
				auth.CapTenantID,
				auth.CapFederatedToken,
			},
		},
	}, nil
}

// ConfigureAuthHandler stores host-side configuration and initializes the handler.
func (p *Plugin) ConfigureAuthHandler(ctx context.Context, handlerName string, cfg sdkplugin.ProviderConfig) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}

	p.cfg = cfg

	// Initialize config with defaults
	p.config = DefaultConfig()

	// Parse handler-specific settings if provided
	if raw, ok := cfg.Settings[HandlerName]; ok {
		if err := json.Unmarshal(raw, p.config); err != nil {
			return fmt.Errorf("failed to parse handler config: %w", err)
		}
	}

	// For profiles, restore defaults for fields that were not explicitly set
	// (or were set to empty) so that Validate succeeds. The actual env var
	// fallback happens later in profileOrEnv during resolve calls.
	if cfg.Profile != "" {
		if !p.config.WasSet("clientId") && p.config.ClientID == "" {
			p.config.ClientID = DefaultClientID
		}
		if !p.config.WasSet("tenantId") && p.config.TenantID == "" {
			p.config.TenantID = DefaultTenantID
		}
	}

	if err := p.config.Validate(); err != nil {
		return err
	}

	// Initialize clock
	p.clock = clock.Real{}

	// Cache the host client for later use
	p.cachedHostClient = sdkplugin.HostClientFromContext(ctx)

	// Initialize HTTP client only if not already set (e.g. by tests)
	if p.httpClient == nil {
		httpLogger := logr.FromContextOrDiscard(ctx).V(5) // high verbosity for auth HTTP
		p.httpClient = NewDefaultHTTPClient(httpLogger)
	}

	// Initialize Graph client only if not already set (e.g. by tests)
	if p.graphClient == nil {
		httpLogger := logr.FromContextOrDiscard(ctx).V(5)
		p.graphClient = NewDefaultGraphClient(httpLogger)
	}

	// Initialize browser opener (can be overridden for testing)
	if p.openBrowser == nil {
		p.openBrowser = defaultBrowserOpener
	}

	// Initialize OBO cache
	if p.oboCache == nil {
		p.oboCache = newOBOCache()
	}

	return nil
}

// Login performs the authentication flow.
//
// Flow selection precedence:
//  1. Explicit FlowWorkloadIdentity -- uses federated token from environment.
//  2. Explicit FlowServicePrincipal -- uses client credentials from environment.
//  3. Implicit credential detection -- when no flow is specified, checks for
//     workload identity and service principal environment credentials.
//  4. Explicit FlowInteractive -- authorization code + PKCE flow.
//  5. Explicit FlowDeviceCode or empty flow -- device code polling flow.
func (p *Plugin) Login(ctx context.Context, handlerName string, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	// Determine which flow to use with credential detection.
	flow := req.Flow
	if flow == "" {
		if p.hasWorkloadIdentityCredentials() {
			flow = auth.FlowWorkloadIdentity
		} else if p.hasServicePrincipalCredentials() {
			flow = auth.FlowServicePrincipal
		} else if p.config.DefaultFlow != "" {
			flow = auth.Flow(p.config.DefaultFlow)
		} else {
			flow = auth.FlowDeviceCode
		}
	}

	switch flow { //nolint:exhaustive // Only Entra-supported flows are handled
	case auth.FlowWorkloadIdentity:
		return p.workloadIdentityLogin(ctx, req)
	case auth.FlowServicePrincipal:
		return p.servicePrincipalLogin(ctx, req)
	case auth.FlowInteractive:
		return p.authCodeLogin(ctx, req, deviceCodeCb)
	case auth.FlowDeviceCode:
		return p.deviceCodeLogin(ctx, req, deviceCodeCb)
	default:
		return nil, fmt.Errorf("unsupported flow: %s", flow)
	}
}

// Logout revokes the current session.
func (p *Plugin) Logout(ctx context.Context, handlerName string) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	return p.logoutInternal(ctx)
}

// logoutInternal clears stored credentials and cached tokens.
func (p *Plugin) logoutInternal(ctx context.Context) error {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("logging out", "handler", HandlerName)

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return fmt.Errorf("host service not available")
	}

	// Clear all cached tokens
	cacheClear(ctx, lgr, hostClient, p.tokenCachePrefix(ctx))

	// Delete refresh token
	if err := hostClient.DeleteSecret(ctx, p.secretKey(ctx, secretSuffixRefreshToken)); err != nil {
		lgr.V(1).Info("failed to delete refresh token (may not exist)", "error", err)
	}

	// Delete metadata
	if err := hostClient.DeleteSecret(ctx, p.secretKey(ctx, secretSuffixMetadata)); err != nil {
		lgr.V(1).Info("failed to delete metadata (may not exist)", "error", err)
	}

	return nil
}

// GetStatus returns the current authentication status.
func (p *Plugin) GetStatus(ctx context.Context, handlerName string) (*auth.Status, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	// Check for workload identity credentials first (highest priority)
	if p.hasWorkloadIdentityCredentials() {
		return p.workloadIdentityStatus()
	}

	// Check for service principal credentials
	if p.hasServicePrincipalCredentials() {
		return p.servicePrincipalStatus()
	}

	// Check if we have stored credentials
	if !p.secretExists(ctx, p.secretKey(ctx, secretSuffixRefreshToken)) {
		return &auth.Status{Authenticated: false}, nil
	}

	// Load and validate metadata
	metadata, err := p.loadMetadata(ctx)
	if err != nil {
		return &auth.Status{Authenticated: false}, nil //nolint:nilerr // corrupted metadata = not authenticated
	}

	// Check if refresh token is expired
	if !metadata.RefreshTokenExpiresAt.IsZero() && time.Now().After(metadata.RefreshTokenExpiresAt) {
		return &auth.Status{
			Authenticated: false,
			Reason:        "session expired",
			Claims:        metadata.Claims,
		}, nil
	}

	return &auth.Status{
		Authenticated: true,
		Claims:        metadata.Claims,
		ExpiresAt:     metadata.RefreshTokenExpiresAt,
		LastRefresh:   metadata.LastRefresh,
		TenantID:      metadata.TenantID,
		IdentityType:  auth.IdentityTypeUser,
		ClientID:      metadata.ClientID,
		Scopes:        metadata.Scopes,
	}, nil
}

// GetToken returns a valid access token, refreshing if necessary.
func (p *Plugin) GetToken(ctx context.Context, handlerName string, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	lgr := logr.FromContextOrDiscard(ctx)

	// Use workload identity flow if credentials are present (highest priority)
	if p.hasWorkloadIdentityCredentials() {
		return p.getWorkloadIdentityToken(ctx, req)
	}

	// Use service principal flow if credentials are present
	if p.hasServicePrincipalCredentials() {
		return p.getServicePrincipalToken(ctx, req)
	}

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

	hostClient := p.hostClient(ctx)
	prefix := p.tokenCachePrefix(ctx)
	fp := fingerprintHash(p.config.ClientID + ":" + p.config.TenantID + ":" + p.config.GetAuthority())
	fullKey := prefix + fp + ":" + qualifiedScope

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
	token, err := p.mintToken(ctx, qualifiedScope)
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

// ListCachedTokens returns metadata for all tokens stored by the Entra handler.
func (p *Plugin) ListCachedTokens(ctx context.Context, handlerName string) ([]*auth.CachedTokenInfo, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return nil, fmt.Errorf("host service not available")
	}

	var results []*auth.CachedTokenInfo

	// Refresh token
	if p.secretExists(ctx, p.secretKey(ctx, secretSuffixRefreshToken)) {
		info := &auth.CachedTokenInfo{
			Handler:   HandlerName,
			TokenKind: "refresh",
		}
		if metadata, err := p.loadMetadata(ctx); err == nil && metadata != nil {
			info.ExpiresAt = metadata.RefreshTokenExpiresAt
			info.CachedAt = metadata.LastRefresh
			info.Flow = metadata.LoginFlow
			info.SessionID = metadata.SessionID
		}
		if !info.ExpiresAt.IsZero() {
			info.IsExpired = time.Now().After(info.ExpiresAt)
		}
		results = append(results, info)
	}

	// Minted access tokens from cache
	entries, _ := cacheListEntries(ctx, hostClient, p.tokenCachePrefix(ctx))
	results = append(results, entries...)

	return results, nil
}

// PurgeExpiredTokens removes expired access tokens from the cache.
func (p *Plugin) PurgeExpiredTokens(ctx context.Context, handlerName string) (int, error) {
	if handlerName != HandlerName {
		return 0, fmt.Errorf("unknown handler: %s", handlerName)
	}

	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return 0, fmt.Errorf("host service not available")
	}

	return cachePurgeExpired(ctx, hostClient, p.tokenCachePrefix(ctx))
}

// DetectAvailableFlows reports which auth flows are available based on
// environment credentials or configuration.
func (p *Plugin) DetectAvailableFlows(_ context.Context, handlerName string) ([]sdkplugin.FlowAvailability, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	var flows []sdkplugin.FlowAvailability

	// Workload identity flow -- check config and environment variables
	if p.hasWorkloadIdentityCredentials() {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowWorkloadIdentity,
			Available: true,
			Reason:    "workload identity credentials configured",
		})
	} else {
		reason := p.detectWorkloadIdentityUnavailableReason()
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowWorkloadIdentity,
			Available: false,
			Reason:    reason,
		})
	}

	// Service principal flow -- check config and environment variables
	if p.hasServicePrincipalCredentials() {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowServicePrincipal,
			Available: true,
			Reason:    "service principal credentials configured",
		})
	} else {
		reason := "service principal credentials not configured"
		var missing []string
		if p.cfg.Profile != "" {
			clientID := p.profileOrEnv(p.config.ClientID, "clientId", EnvAzureClientID)
			clientSecret := p.profileOrEnv(p.config.ClientSecret, "clientSecret", EnvAzureClientSecret)
			tenantID := p.profileOrEnv(p.config.TenantID, "tenantId", EnvAzureTenantID)
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
				reason = fmt.Sprintf("missing %s (not in profile config or environment)", strings.Join(missing, ", "))
			}
		} else {
			if os.Getenv(EnvAzureClientID) == "" {
				missing = append(missing, EnvAzureClientID)
			}
			if os.Getenv(EnvAzureClientSecret) == "" {
				missing = append(missing, EnvAzureClientSecret)
			}
			if os.Getenv(EnvAzureTenantID) == "" {
				missing = append(missing, EnvAzureTenantID)
			}
			if len(missing) > 0 {
				reason = fmt.Sprintf("missing environment variables: %s", strings.Join(missing, ", "))
			}
		}
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowServicePrincipal,
			Available: false,
			Reason:    reason,
		})
	}

	// Device code flow -- always available
	flows = append(flows, sdkplugin.FlowAvailability{
		Flow:      auth.FlowDeviceCode,
		Available: true,
		Reason:    "device code flow is always available",
	})

	// Interactive flow -- always available
	flows = append(flows, sdkplugin.FlowAvailability{
		Flow:      auth.FlowInteractive,
		Available: true,
		Reason:    "interactive flow is always available",
	})

	return flows, nil
}

// detectWorkloadIdentityUnavailableReason returns a specific reason why
// workload identity credentials are not available. When a profile is active it
// inspects resolved (config-then-env) values; otherwise it checks env vars only.
func (p *Plugin) detectWorkloadIdentityUnavailableReason() string {
	var tokenFile, directToken, clientID, tenantID string
	if p.cfg.Profile != "" {
		tokenFile = p.profileOrEnv(p.config.FederatedTokenFile, "federatedTokenFile", EnvAzureFederatedTokenFile)
		directToken = p.profileOrEnv(p.config.FederatedToken, "federatedToken", EnvAzureFederatedToken)
		clientID = p.profileOrEnv(p.config.ClientID, "clientId", EnvAzureClientID)
		tenantID = p.profileOrEnv(p.config.TenantID, "tenantId", EnvAzureTenantID)
	} else {
		tokenFile = os.Getenv(EnvAzureFederatedTokenFile)
		directToken = os.Getenv(EnvAzureFederatedToken)
		clientID = os.Getenv(EnvAzureClientID)
		tenantID = os.Getenv(EnvAzureTenantID)
	}

	hasTokenSource := directToken != ""
	if tokenFile != "" {
		if _, err := os.Stat(tokenFile); err == nil { //nolint:gosec // tokenFile is from trusted env var
			hasTokenSource = true
		} else if !hasTokenSource {
			// Token file is set but inaccessible, and no direct token either.
			return fmt.Sprintf("%s is set but the file is missing or inaccessible: %v", EnvAzureFederatedTokenFile, err)
		}
	}

	if !hasTokenSource {
		return fmt.Sprintf("neither %s nor %s is configured", EnvAzureFederatedTokenFile, EnvAzureFederatedToken)
	}

	// Token source exists but client/tenant are missing.
	var missing []string
	if clientID == "" {
		missing = append(missing, EnvAzureClientID)
	}
	if tenantID == "" {
		missing = append(missing, EnvAzureTenantID)
	}
	if len(missing) > 0 {
		if p.cfg.Profile != "" {
			return fmt.Sprintf("federated token is available but missing %s (not in profile config or environment)", strings.Join(missing, ", "))
		}
		return fmt.Sprintf("federated token is available but missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return "workload identity credentials not configured"
}

// StopAuthHandler performs cleanup before plugin unload.
//
//nolint:revive // all params required by interface
func (p *Plugin) StopAuthHandler(_ context.Context, handlerName string) error {
	if handlerName != HandlerName {
		return fmt.Errorf("unknown handler: %s", handlerName)
	}
	return nil
}

// hostClient returns the cached host service client or looks it up from context.
func (p *Plugin) hostClient(ctx context.Context) *sdkplugin.HostServiceClient {
	if p.cachedHostClient != nil {
		return p.cachedHostClient
	}
	return sdkplugin.HostClientFromContext(ctx)
}

// secretExists checks if a secret exists in the host secret store.
func (p *Plugin) secretExists(ctx context.Context, key string) bool {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return false
	}
	_, found, err := hostClient.GetSecret(ctx, key)
	return err == nil && found
}

// getSecret retrieves a secret value from the host secret store.
func (p *Plugin) getSecret(ctx context.Context, key string) (string, error) {
	hostClient := p.hostClient(ctx)
	if hostClient == nil {
		return "", fmt.Errorf("host service not available")
	}
	value, found, err := hostClient.GetSecret(ctx, key)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("secret not found: %s", key)
	}
	return value, nil
}

// binaryName returns the host binary name for error messages.
func (p *Plugin) binaryName() string {
	if p.cfg.BinaryName != "" {
		return p.cfg.BinaryName
	}
	return "scafctl"
}

// secretKey returns a profile-scoped secret key. It checks the context first
// and falls back to the profile set during ConfigureAuthHandler. When no
// profile is active, the key matches the legacy unscoped format for backward
// compatibility. The profile name is hex-encoded to prevent dot-delimited
// collisions (e.g. a profile named "prod.token" would otherwise overlap with
// the token cache prefix for profile "prod").
func (p *Plugin) secretKey(ctx context.Context, suffix string) string {
	profile := auth.ProfileFromContext(ctx)
	if profile == "" {
		profile = p.cfg.Profile
	}
	if profile == "" {
		return secretKeyBase + "." + suffix
	}
	return secretKeyBase + "." + hex.EncodeToString([]byte(profile)) + "." + suffix
}

// profileOrEnv returns the config value if its JSON field was explicitly
// provided during unmarshaling, otherwise falls back to the environment
// variable. This ensures that a profile intentionally setting a value equal
// to the default (e.g. tenantId = "common") is honored rather than overridden
// by an env var.
func (p *Plugin) profileOrEnv(configVal, jsonField, envVar string) string {
	if p.config.WasSet(jsonField) {
		return configVal
	}
	return os.Getenv(envVar)
}

// tokenCachePrefix returns the profile-scoped prefix for cached access tokens.
func (p *Plugin) tokenCachePrefix(ctx context.Context) string {
	return p.secretKey(ctx, secretSuffixTokenPrefix)
}
