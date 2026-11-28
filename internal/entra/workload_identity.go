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
	"path/filepath"
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
	return resolveWorkloadIdentityCredentialsFromConfig(nil)
}

// HasWorkloadIdentityCredentials checks if workload identity is configured and available
// via environment variables only (no profile config).
func HasWorkloadIdentityCredentials() bool {
	return GetWorkloadIdentityCredentials() != nil
}

// resolveWorkloadIdentityCredentials returns WIF credentials, preferring
// explicitly configured values (profile or top-level config) over environment
// variables.
func (p *Plugin) resolveWorkloadIdentityCredentials() *WorkloadIdentityCredentials {
	return p.resolveWorkloadIdentityCredentialsForConfig(p.config)
}

func (p *Plugin) resolveWorkloadIdentityCredentialsForConfig(cfg *Config) *WorkloadIdentityCredentials {
	if cfg == nil && p != nil {
		cfg = p.config
	}
	return resolveWorkloadIdentityCredentialsFromConfig(cfg)
}

func resolveWorkloadIdentityCredentialsFromConfig(cfg *Config) *WorkloadIdentityCredentials {
	// Prefer explicitly configured values, fall back to env vars. Fields not
	// provided in the config fall through to the environment variable.
	clientID := cfg.profileOrEnv(cfgOrEmpty(cfg, func(c *Config) string { return c.ClientID }), "clientId", EnvAzureClientID)
	tenantID := cfg.profileOrEnv(cfgOrEmpty(cfg, func(c *Config) string { return c.TenantID }), "tenantId", EnvAzureTenantID)
	tokenFile := cfg.profileOrEnv(cfgOrEmpty(cfg, func(c *Config) string { return c.FederatedTokenFile }), "federatedTokenFile", EnvAzureFederatedTokenFile)
	directToken := cfg.profileOrEnv(cfgOrEmpty(cfg, func(c *Config) string { return c.FederatedToken }), "federatedToken", EnvAzureFederatedToken)
	// Trim any trailing slash: workload identity webhooks commonly inject
	// e.g. https://login.microsoftonline.com/, which would otherwise
	// produce a double slash in the token URL.
	authority := strings.TrimRight(cfg.profileOrEnv(cfgOrEmpty(cfg, func(c *Config) string { return c.Authority }), "authority", EnvAzureAuthorityHost), "/")
	if authority == "" {
		authority = DefaultAuthority
	}

	// Validate token source
	hasDirectToken := directToken != ""
	hasTokenFile := false
	if tokenFile != "" {
		if _, err := os.Stat(filepath.Clean(tokenFile)); err == nil { //nolint:gosec // tokenFile is from trusted config or env var
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

func cfgOrEmpty(cfg *Config, get func(*Config) string) string {
	if cfg == nil {
		return ""
	}
	return get(cfg)
}

// hasWorkloadIdentityCredentials checks if workload identity credentials are
// available from config or environment variables.
func (p *Plugin) hasWorkloadIdentityCredentials() bool {
	return p.resolveWorkloadIdentityCredentials() != nil
}

func (p *Plugin) hasWorkloadIdentityCredentialsForConfig(cfg *Config) bool {
	return p.resolveWorkloadIdentityCredentialsForConfig(cfg) != nil
}

// GetFederatedToken returns the federated token.
func (c *WorkloadIdentityCredentials) GetFederatedToken() (string, error) {
	if c.Token != "" {
		return c.Token, nil
	}

	if c.TokenFile == "" {
		return "", fmt.Errorf("no federated token configured: set %s or %s", EnvAzureFederatedToken, EnvAzureFederatedTokenFile)
	}

	token, err := sdkplugin.SecretRef("file://" + filepath.Clean(c.TokenFile)).Resolve()
	if err != nil {
		if strings.HasSuffix(err.Error(), " is empty") {
			return "", fmt.Errorf("federated token file is empty: %s", c.TokenFile)
		}
		return "", fmt.Errorf("failed to read federated token file %s: %w", c.TokenFile, err)
	}

	return token, nil
}

// workloadIdentityLogin validates workload identity credentials by acquiring a token.
func (p *Plugin) workloadIdentityLogin(ctx context.Context, req sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}

	creds := p.resolveWorkloadIdentityCredentialsForConfig(cfg)
	if creds == nil {
		// Diagnose with the same config-then-env resolution the resolver used.
		directToken := cfg.profileOrEnv(cfg.FederatedToken, "federatedToken", EnvAzureFederatedToken)
		tokenFile := cfg.profileOrEnv(cfg.FederatedTokenFile, "federatedTokenFile", EnvAzureFederatedTokenFile)
		clientID := cfg.profileOrEnv(cfg.ClientID, "clientId", EnvAzureClientID)
		tenantID := cfg.profileOrEnv(cfg.TenantID, "tenantId", EnvAzureTenantID)

		if directToken == "" && tokenFile == "" {
			return nil, fmt.Errorf("workload identity not configured: set federatedToken or federatedTokenFile in config, or the %s or %s environment variables",
				EnvAzureFederatedTokenFile, EnvAzureFederatedToken)
		}
		if tokenFile != "" {
			if _, err := os.Stat(filepath.Clean(tokenFile)); err != nil { //nolint:gosec // tokenFile is from trusted config or env var
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
	// The client credentials grant targets a single resource, so more than one
	// requested scope is rejected rather than silently dropped after the first.
	if len(req.Scopes) > 1 {
		return nil, fmt.Errorf("workload identity login accepts a single scope, got %d: %s",
			len(req.Scopes), strings.Join(req.Scopes, " "))
	}
	scope := "https://management.azure.com/.default"
	if len(req.Scopes) > 0 {
		scope = QualifyScope(req.Scopes[0])
	}

	_, err = p.acquireWorkloadIdentityToken(ctx, cfg, creds, scope)
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
func (p *Plugin) acquireWorkloadIdentityToken(ctx context.Context, cfg *Config, creds *WorkloadIdentityCredentials, scope string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	if err := validateAuthorityURL(creds.Authority); err != nil {
		return nil, fmt.Errorf("invalid workload identity authority: %w", err)
	}

	httpClient, releaseHTTP, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()

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

	resp, err := httpClient.PostForm(ctx, tokenURL, data)
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

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}

	creds := p.resolveWorkloadIdentityCredentialsForConfig(cfg)
	if creds == nil {
		return nil, fmt.Errorf("workload identity credentials not configured")
	}

	minValidFor := req.MinValidFor
	if minValidFor == 0 {
		minValidFor = auth.DefaultMinValidFor
	}

	hostClient := p.hostClient(ctx)
	prefix := p.tokenCachePrefix(ctx)
	fp := fingerprintHash("workload_identity:" + creds.ClientID + ":" + creds.TenantID + ":" + creds.Authority)
	fullKey := buildTokenCacheKey(prefix, fp, qualifiedScope)

	// Check cache first
	if !req.ForceRefresh && hostClient != nil {
		token, err := cacheGet(ctx, hostClient, fullKey)
		if cErr := contextErr(ctx, err); cErr != nil {
			return nil, cErr
		}
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
	token, err := p.acquireWorkloadIdentityToken(ctx, cfg, creds, qualifiedScope)
	if err != nil {
		return nil, err
	}

	// Cache the token
	if hostClient != nil {
		if cacheErr := cacheSet(ctx, hostClient, fullKey, token); cacheErr != nil {
			if cErr := contextErr(ctx, cacheErr); cErr != nil {
				return nil, cErr
			}
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

// workloadIdentityStatusForConfig returns the status for workload identity authentication.
func (p *Plugin) workloadIdentityStatusForConfig(cfg *Config) (*auth.Status, error) {
	creds := p.resolveWorkloadIdentityCredentialsForConfig(cfg)
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
		TokenFile:    creds.TokenFile,
		Flow:         auth.FlowWorkloadIdentity,
	}, nil
}
