// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package entra implements the Microsoft Entra ID auth handler plugin.
package entra

import (
	"context"
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

	// SecretKeyRefreshToken is the secret key for storing the refresh token.
	SecretKeyRefreshToken = "scafctl.auth.entra.refresh_token" //nolint:gosec // key name, not a credential

	// SecretKeyMetadata is the secret key for storing token metadata.
	SecretKeyMetadata = "scafctl.auth.entra.metadata" //nolint:gosec // key name, not a credential

	// SecretKeyTokenPrefix is the prefix for cached access tokens.
	SecretKeyTokenPrefix = "scafctl.auth.entra.token." //nolint:gosec // key prefix, not a credential

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
		if HasWorkloadIdentityCredentials() {
			flow = auth.FlowWorkloadIdentity
		} else if HasServicePrincipalCredentials() {
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
	cacheClear(ctx, lgr, hostClient)

	// Delete refresh token
	if err := hostClient.DeleteSecret(ctx, SecretKeyRefreshToken); err != nil {
		lgr.V(1).Info("failed to delete refresh token (may not exist)", "error", err)
	}

	// Delete metadata
	if err := hostClient.DeleteSecret(ctx, SecretKeyMetadata); err != nil {
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
	if HasWorkloadIdentityCredentials() {
		return p.workloadIdentityStatus()
	}

	// Check for service principal credentials
	if HasServicePrincipalCredentials() {
		return p.servicePrincipalStatus()
	}

	// Check if we have stored credentials
	if !p.secretExists(ctx, SecretKeyRefreshToken) {
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
	if HasWorkloadIdentityCredentials() {
		return p.getWorkloadIdentityToken(ctx, req)
	}

	// Use service principal flow if credentials are present
	if HasServicePrincipalCredentials() {
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
	fp := fingerprintHash(p.config.ClientID + ":" + p.config.TenantID + ":" + p.config.GetAuthority())
	cacheKey := fp + ":" + qualifiedScope

	// Check cache first (unless force refresh)
	if !req.ForceRefresh && hostClient != nil {
		token, err := cacheGet(ctx, hostClient, cacheKey)
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
		if cacheErr := cacheSet(ctx, hostClient, cacheKey, token); cacheErr != nil {
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
	if p.secretExists(ctx, SecretKeyRefreshToken) {
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
	entries, _ := cacheListEntries(ctx, hostClient)
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

	return cachePurgeExpired(ctx, hostClient)
}

// DetectAvailableFlows reports which auth flows are available based on
// environment credentials or configuration.
func (p *Plugin) DetectAvailableFlows(_ context.Context, handlerName string) ([]sdkplugin.FlowAvailability, error) {
	if handlerName != HandlerName {
		return nil, fmt.Errorf("unknown handler: %s", handlerName)
	}

	var flows []sdkplugin.FlowAvailability

	// Workload identity flow -- check environment variables
	if HasWorkloadIdentityCredentials() {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowWorkloadIdentity,
			Available: true,
			Reason:    fmt.Sprintf("%s or %s is set", EnvAzureFederatedTokenFile, EnvAzureFederatedToken),
		})
	} else {
		reason := detectWorkloadIdentityUnavailableReason()
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowWorkloadIdentity,
			Available: false,
			Reason:    reason,
		})
	}

	// Service principal flow -- check environment variables
	if HasServicePrincipalCredentials() {
		flows = append(flows, sdkplugin.FlowAvailability{
			Flow:      auth.FlowServicePrincipal,
			Available: true,
			Reason:    fmt.Sprintf("%s, %s, and %s are set", EnvAzureClientID, EnvAzureClientSecret, EnvAzureTenantID),
		})
	} else {
		missing := []string{}
		if os.Getenv(EnvAzureClientID) == "" {
			missing = append(missing, EnvAzureClientID)
		}
		if os.Getenv(EnvAzureClientSecret) == "" {
			missing = append(missing, EnvAzureClientSecret)
		}
		if os.Getenv(EnvAzureTenantID) == "" {
			missing = append(missing, EnvAzureTenantID)
		}
		reason := "service principal credentials not configured"
		if len(missing) > 0 {
			reason = fmt.Sprintf("missing environment variables: %s", strings.Join(missing, ", "))
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
// workload identity credentials are not available.
func detectWorkloadIdentityUnavailableReason() string {
	tokenFile := os.Getenv(EnvAzureFederatedTokenFile)
	directToken := os.Getenv(EnvAzureFederatedToken)
	clientID := os.Getenv(EnvAzureClientID)
	tenantID := os.Getenv(EnvAzureTenantID)

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

	// Token source exists but client/tenant env vars are missing.
	var missing []string
	if clientID == "" {
		missing = append(missing, EnvAzureClientID)
	}
	if tenantID == "" {
		missing = append(missing, EnvAzureTenantID)
	}
	if len(missing) > 0 {
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

