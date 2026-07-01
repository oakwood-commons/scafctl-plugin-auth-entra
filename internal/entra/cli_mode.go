// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"fmt"
	"os"
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

// Login performs the authentication flow in CLI mode.
//
// Flow selection precedence:
//  1. Explicit FlowWorkloadIdentity -- uses federated token from environment.
//  2. Explicit FlowServicePrincipal -- uses client credentials from environment.
//  3. Implicit credential detection -- when no flow is specified, checks for
//     workload identity and service principal environment credentials.
//  4. Explicit FlowInteractive -- authorization code + PKCE flow.
//  5. Explicit FlowDeviceCode or empty flow -- device code polling flow.
func (m *cliMode) Login(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	// Determine which flow to use with credential detection.
	flow := req.Flow
	if flow == "" {
		if m.p.hasWorkloadIdentityCredentials() {
			flow = auth.FlowWorkloadIdentity
		} else if m.p.hasServicePrincipalCredentials() {
			flow = auth.FlowServicePrincipal
		} else if m.p.config.DefaultFlow != "" {
			flow = auth.Flow(m.p.config.DefaultFlow)
		} else {
			flow = auth.FlowDeviceCode
		}
	}

	switch flow { //nolint:exhaustive // Only Entra-supported flows are handled
	case auth.FlowWorkloadIdentity:
		return m.p.workloadIdentityLogin(ctx, req)
	case auth.FlowServicePrincipal:
		return m.p.servicePrincipalLogin(ctx, req)
	case auth.FlowInteractive:
		return m.p.authCodeLogin(ctx, req, deviceCodeCb)
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
func (m *cliMode) GetStatus(ctx context.Context) (*auth.Status, error) {
	// Check for workload identity credentials first (highest priority)
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

// GetToken returns a valid access token in CLI mode, refreshing if necessary.
func (m *cliMode) GetToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	// Use workload identity flow if credentials are present (highest priority)
	if m.p.hasWorkloadIdentityCredentials() {
		return m.p.getWorkloadIdentityToken(ctx, req)
	}

	// Use service principal flow if credentials are present
	if m.p.hasServicePrincipalCredentials() {
		return m.p.getServicePrincipalToken(ctx, req)
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

	hostClient := m.p.hostClient(ctx)
	prefix := m.p.tokenCachePrefix(ctx)
	fp := fingerprintHash(m.p.config.ClientID + ":" + m.p.config.TenantID + ":" + m.p.config.GetAuthority())
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
		if m.p.cfg.Profile != "" {
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
