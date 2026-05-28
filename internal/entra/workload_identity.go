// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// Environment variable names for workload identity (Azure SDK convention).
const (
	// EnvAzureFederatedTokenFile is the path to the projected service account token.
	EnvAzureFederatedTokenFile = "AZURE_FEDERATED_TOKEN_FILE" //nolint:gosec // env var name, not a credential

	// EnvAzureFederatedToken is the raw federated token (for testing/debugging).
	EnvAzureFederatedToken = "AZURE_FEDERATED_TOKEN" //nolint:gosec // env var name, not a credential

	// EnvAzureAuthorityHost is the Azure AD authority host (optional).
	EnvAzureAuthorityHost = "AZURE_AUTHORITY_HOST"

	// clientAssertionType is the OAuth2 assertion type for federated tokens.
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// WorkloadIdentityCredentials holds the configuration for workload identity authentication.
type WorkloadIdentityCredentials struct {
	ClientID  string
	TenantID  string
	TokenFile string
	Token     string
	Authority string
}

// GetWorkloadIdentityCredentials retrieves workload identity configuration from environment variables.
func GetWorkloadIdentityCredentials() *WorkloadIdentityCredentials {
	directToken := os.Getenv(EnvAzureFederatedToken)
	tokenFile := os.Getenv(EnvAzureFederatedTokenFile)

	hasDirectToken := directToken != ""
	hasTokenFile := false
	if tokenFile != "" {
		if _, err := os.Stat(tokenFile); err == nil { //nolint:gosec // tokenFile is from trusted env var
			hasTokenFile = true
		}
	}

	if !hasDirectToken && !hasTokenFile {
		return nil
	}

	clientID := os.Getenv(EnvAzureClientID)
	tenantID := os.Getenv(EnvAzureTenantID)

	if clientID == "" || tenantID == "" {
		return nil
	}

	authority := os.Getenv(EnvAzureAuthorityHost)
	if authority == "" {
		authority = DefaultAuthority
	}

	return &WorkloadIdentityCredentials{
		ClientID:  clientID,
		TenantID:  tenantID,
		TokenFile: tokenFile,
		Token:     directToken,
		Authority: authority,
	}
}

// HasWorkloadIdentityCredentials checks if workload identity is configured and available
// via environment variables only (no profile config).
func HasWorkloadIdentityCredentials() bool {
	return GetWorkloadIdentityCredentials() != nil
}

// resolveWorkloadIdentityCredentials returns WIF credentials, preferring config
// values over environment variables when a profile is active.
func (p *Plugin) resolveWorkloadIdentityCredentials() *WorkloadIdentityCredentials {
	if p.cfg.Profile == "" {
		return GetWorkloadIdentityCredentials()
	}

	// Profile active: prefer explicitly configured values, fall back to env vars.
	// Fields that still hold DefaultConfig() values were not set by the profile,
	// so they must fall through to the environment variable.
	clientID := p.profileOrEnv(p.config.ClientID, "clientId", EnvAzureClientID)
	tenantID := p.profileOrEnv(p.config.TenantID, "tenantId", EnvAzureTenantID)
	tokenFile := p.profileOrEnv(p.config.FederatedTokenFile, "federatedTokenFile", EnvAzureFederatedTokenFile)
	directToken := p.profileOrEnv(p.config.FederatedToken, "federatedToken", EnvAzureFederatedToken)
	authority := p.profileOrEnv(p.config.Authority, "authority", EnvAzureAuthorityHost)
	if authority == "" {
		authority = DefaultAuthority
	}

	// Validate token source
	hasDirectToken := directToken != ""
	hasTokenFile := false
	if tokenFile != "" {
		if _, err := os.Stat(tokenFile); err == nil { //nolint:gosec // tokenFile is from trusted config or env var
			hasTokenFile = true
		}
	}
	if !hasDirectToken && !hasTokenFile {
		return nil
	}

	if clientID == "" || tenantID == "" {
		return nil
	}

	return &WorkloadIdentityCredentials{
		ClientID:  clientID,
		TenantID:  tenantID,
		TokenFile: tokenFile,
		Token:     directToken,
		Authority: authority,
	}
}

// hasWorkloadIdentityCredentials checks if workload identity credentials are
// available from either config (when a profile is active) or environment variables.
func (p *Plugin) hasWorkloadIdentityCredentials() bool {
	return p.resolveWorkloadIdentityCredentials() != nil
}

// GetFederatedToken returns the federated token.
func (c *WorkloadIdentityCredentials) GetFederatedToken() (string, error) {
	if c.Token != "" {
		return c.Token, nil
	}

	if c.TokenFile == "" {
		return "", fmt.Errorf("no federated token configured: set %s or %s", EnvAzureFederatedToken, EnvAzureFederatedTokenFile)
	}

	data, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read federated token file %s: %w", c.TokenFile, err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("federated token file is empty: %s", c.TokenFile)
	}

	return token, nil
}

// workloadIdentityLogin validates workload identity credentials by acquiring a token.
func (p *Plugin) workloadIdentityLogin(ctx context.Context, req sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	creds := p.resolveWorkloadIdentityCredentials()
	if creds == nil {
		var directToken, tokenFile, clientID, tenantID string
		if p.cfg.Profile != "" {
			directToken = p.profileOrEnv(p.config.FederatedToken, "federatedToken", EnvAzureFederatedToken)
			tokenFile = p.profileOrEnv(p.config.FederatedTokenFile, "federatedTokenFile", EnvAzureFederatedTokenFile)
			clientID = p.profileOrEnv(p.config.ClientID, "clientId", EnvAzureClientID)
			tenantID = p.profileOrEnv(p.config.TenantID, "tenantId", EnvAzureTenantID)
		} else {
			directToken = os.Getenv(EnvAzureFederatedToken)
			tokenFile = os.Getenv(EnvAzureFederatedTokenFile)
			clientID = os.Getenv(EnvAzureClientID)
			tenantID = os.Getenv(EnvAzureTenantID)
		}

		if directToken == "" && tokenFile == "" {
			return nil, fmt.Errorf("workload identity not configured: set %s or %s", EnvAzureFederatedTokenFile, EnvAzureFederatedToken)
		}
		if tokenFile != "" {
			if _, err := os.Stat(tokenFile); err != nil { //nolint:gosec // tokenFile is from trusted config or env var
				return nil, fmt.Errorf("workload identity token file %s: %w", tokenFile, err)
			}
		}
		if clientID == "" {
			return nil, fmt.Errorf("workload identity not configured: %s not set", EnvAzureClientID)
		}
		if tenantID == "" {
			return nil, fmt.Errorf("workload identity not configured: %s not set", EnvAzureTenantID)
		}
		return nil, fmt.Errorf("workload identity credentials not configured")
	}

	lgr.V(1).Info("validating workload identity credentials",
		"clientId", creds.ClientID,
		"tenantId", creds.TenantID,
		"tokenFile", creds.TokenFile,
	)

	// Use a default scope if none provided, qualifying bare names the same way
	// getWorkloadIdentityToken does so login validation behaves consistently.
	scope := "https://management.azure.com/.default"
	if len(req.Scopes) > 0 {
		scope = QualifyScope(req.Scopes[0])
	}

	_, err := p.acquireWorkloadIdentityToken(ctx, creds, scope)
	if err != nil {
		return nil, fmt.Errorf("workload identity authentication failed: %w", err)
	}

	lgr.V(1).Info("workload identity authentication successful",
		"clientId", creds.ClientID,
		"tenantId", creds.TenantID,
	)

	return &sdkplugin.LoginResponse{
		Claims: &auth.Claims{
			Subject:  creds.ClientID,
			TenantID: creds.TenantID,
			ClientID: creds.ClientID,
			Name:     fmt.Sprintf("Workload Identity (%s...)", creds.ClientID[:min(8, len(creds.ClientID))]),
		},
	}, nil
}

// acquireWorkloadIdentityToken exchanges the federated token for an Azure AD access token.
func (p *Plugin) acquireWorkloadIdentityToken(ctx context.Context, creds *WorkloadIdentityCredentials, scope string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	federatedToken, err := creds.GetFederatedToken()
	if err != nil {
		return nil, err
	}

	lgr.V(1).Info("exchanging federated token for access token",
		"scope", scope,
		"tokenFile", creds.TokenFile,
	)

	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", creds.Authority, creds.TenantID)

	data := makeFormData(map[string]string{
		"grant_type":            "client_credentials",
		"client_id":             creds.ClientID,
		"client_assertion_type": clientAssertionType,
		"client_assertion":      federatedToken,
		"scope":                 scope,
	})

	resp, err := p.httpClient.PostForm(ctx, tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return nil, fmt.Errorf("token request failed with status %d: decode error: %w; body: %s", resp.StatusCode, decErr, string(body))
		}

		if errResp.Error == "invalid_client" && strings.Contains(errResp.ErrorDescription, "AADSTS700024") {
			hint := "the federated token (client assertion) has expired and is no longer valid"
			if creds.TokenFile != "" {
				hint += fmt.Sprintf("; the projected service account token at %q may not have been rotated yet", creds.TokenFile)
			} else {
				hint += fmt.Sprintf("; provide a fresh token via the %s or %s environment variable", EnvAzureFederatedToken, EnvAzureFederatedTokenFile)
			}
			return nil, fmt.Errorf("token exchange failed: expired federated token (AADSTS700024): %s\nHint: %s", errResp.ErrorDescription, hint)
		}

		return nil, fmt.Errorf("token exchange failed: %s: %s", errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	lgr.V(1).Info("successfully acquired access token via workload identity",
		"scope", scope,
		"expiresIn", tokenResp.ExpiresIn,
		"expiresAt", expiresAt,
	)

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        auth.FlowWorkloadIdentity,
	}, nil
}

// getWorkloadIdentityToken gets an access token using workload identity, with caching.
func (p *Plugin) getWorkloadIdentityToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	if req.Scope == "" {
		return nil, fmt.Errorf("scope is required for workload identity token request")
	}

	qualifiedScope := QualifyScope(req.Scope)

	creds := p.resolveWorkloadIdentityCredentials()
	if creds == nil {
		return nil, fmt.Errorf("workload identity credentials not configured")
	}

	minValidFor := req.MinValidFor
	if minValidFor == 0 {
		minValidFor = auth.DefaultMinValidFor
	}

	hostClient := p.hostClient(ctx)
	prefix := p.tokenCachePrefix(ctx)
	fp := fingerprintHash(creds.ClientID + ":" + creds.TenantID + ":" + creds.Authority)
	fullKey := prefix + fp + ":" + qualifiedScope

	// Check cache first
	if !req.ForceRefresh && hostClient != nil {
		token, err := cacheGet(ctx, hostClient, fullKey)
		if err == nil && token != nil && token.IsValidFor(minValidFor) {
			return &sdkplugin.TokenResponse{
				AccessToken: token.AccessToken,
				TokenType:   token.TokenType,
				ExpiresAt:   token.ExpiresAt,
				Scope:       token.Scope,
				Flow:        token.Flow,
			}, nil
		}
		if err != nil {
			lgr.V(1).Info("cache lookup failed, will mint new token", "error", err)
		}
	}

	// Acquire new token
	token, err := p.acquireWorkloadIdentityToken(ctx, creds, qualifiedScope)
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
	}, nil
}

// workloadIdentityStatus returns the status for workload identity authentication.
func (p *Plugin) workloadIdentityStatus() (*auth.Status, error) {
	creds := p.resolveWorkloadIdentityCredentials()
	if creds == nil {
		return &auth.Status{Authenticated: false}, nil
	}

	return &auth.Status{
		Authenticated: true,
		Claims: &auth.Claims{
			Subject:  creds.ClientID,
			TenantID: creds.TenantID,
			ClientID: creds.ClientID,
			Name:     fmt.Sprintf("Workload Identity (%s...)", creds.ClientID[:min(8, len(creds.ClientID))]),
		},
		TenantID:     creds.TenantID,
		IdentityType: auth.IdentityTypeWorkloadIdentity,
		ClientID:     creds.ClientID,
	}, nil
}
