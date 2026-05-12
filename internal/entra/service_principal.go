// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

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
)

// Service principal environment variable names (following Azure SDK conventions).
const (
	// EnvAzureClientID is the environment variable for the service principal client ID.
	EnvAzureClientID = "AZURE_CLIENT_ID"

	// EnvAzureTenantID is the environment variable for the Azure tenant ID.
	EnvAzureTenantID = "AZURE_TENANT_ID"

	// EnvAzureClientSecret is the environment variable for the client secret.
	EnvAzureClientSecret = "AZURE_CLIENT_SECRET" //nolint:gosec // env var name, not a credential
)

// ServicePrincipalCredentials holds the credentials for service principal authentication.
type ServicePrincipalCredentials struct {
	ClientID     string
	TenantID     string
	ClientSecret string //nolint:gosec // stores runtime secret from env vars
}

// GetServicePrincipalCredentials retrieves SP credentials from environment variables.
func GetServicePrincipalCredentials() *ServicePrincipalCredentials {
	clientID := os.Getenv(EnvAzureClientID)
	tenantID := os.Getenv(EnvAzureTenantID)
	clientSecret := os.Getenv(EnvAzureClientSecret)

	if clientID == "" || tenantID == "" || clientSecret == "" {
		return nil
	}

	return &ServicePrincipalCredentials{
		ClientID:     clientID,
		TenantID:     tenantID,
		ClientSecret: clientSecret,
	}
}

// HasServicePrincipalCredentials checks if SP credentials are configured.
func HasServicePrincipalCredentials() bool {
	return GetServicePrincipalCredentials() != nil
}

// servicePrincipalLogin validates SP credentials by acquiring a token.
func (p *Plugin) servicePrincipalLogin(ctx context.Context, req sdkplugin.LoginRequest) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting service principal login", "handler", HandlerName)

	creds := GetServicePrincipalCredentials()
	if creds == nil {
		return nil, fmt.Errorf("service principal credentials not configured: set %s, %s, and %s environment variables",
			EnvAzureClientID, EnvAzureTenantID, EnvAzureClientSecret)
	}

	// Use a default scope if none provided, qualifying bare names the same way
	// getServicePrincipalToken does so login validation behaves consistently.
	scope := "https://graph.microsoft.com/.default"
	if len(req.Scopes) > 0 {
		scope = QualifyScope(req.Scopes[0])
	}

	// Acquire a token to validate credentials
	token, err := p.acquireServicePrincipalToken(ctx, creds, scope)
	if err != nil {
		return nil, fmt.Errorf("service principal authentication failed: %w", err)
	}

	lgr.V(1).Info("service principal authentication successful",
		"clientId", creds.ClientID,
		"tenantId", creds.TenantID,
	)

	return &sdkplugin.LoginResponse{
		Claims: &auth.Claims{
			Subject:  creds.ClientID,
			TenantID: creds.TenantID,
			ClientID: creds.ClientID,
		},
		ExpiresAt: token.ExpiresAt,
	}, nil
}

// acquireServicePrincipalToken acquires a token using the client credentials flow.
func (p *Plugin) acquireServicePrincipalToken(ctx context.Context, creds *ServicePrincipalCredentials, scope string) (*auth.Token, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", p.config.GetAuthority(), creds.TenantID)

	data := makeFormData(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     creds.ClientID,
		"client_secret": creds.ClientSecret,
		"scope":         scope,
	})

	lgr.V(1).Info("requesting token via client credentials flow",
		"endpoint", endpoint,
		"scope", scope,
	)

	resp, err := p.httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr != nil {
			return nil, fmt.Errorf("token request failed with HTTP %d (could not parse error response: %w)", resp.StatusCode, decErr)
		}

		if errResp.Error == "invalid_client" {
			hint := aadstsHint(errResp.ErrorDescription)
			if hint == "" {
				hint = fmt.Sprintf("verify %s contains the correct secret value; "+
					"if the secret has been rotated or expired, regenerate it in the Azure portal",
					EnvAzureClientSecret)
			}
			return nil, fmt.Errorf("invalid client credentials: %s\nHint: %s", errResp.ErrorDescription, hint)
		}
		if errResp.Error == "unauthorized_client" {
			return nil, fmt.Errorf("client not authorized: %s\nHint: ensure the app registration has the required API permissions "+
				"and that an administrator has granted consent", errResp.ErrorDescription)
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

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	lgr.V(1).Info("acquired service principal token",
		"expiresIn", tokenResp.ExpiresIn,
		"scope", scope,
	)

	return &auth.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       scope,
		Flow:        auth.FlowServicePrincipal,
	}, nil
}

// getServicePrincipalToken gets a token for SP auth, using cache when valid.
func (p *Plugin) getServicePrincipalToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	if req.Scope == "" {
		return nil, fmt.Errorf("scope is required for service principal token request")
	}

	qualifiedScope := QualifyScope(req.Scope)

	creds := GetServicePrincipalCredentials()
	if creds == nil {
		return nil, fmt.Errorf("service principal credentials not configured")
	}

	minValidFor := req.MinValidFor
	if minValidFor == 0 {
		minValidFor = auth.DefaultMinValidFor
	}

	hostClient := p.hostClient(ctx)
	fp := fingerprintHash(creds.ClientID + ":" + creds.TenantID + ":" + p.config.GetAuthority())
	cacheKey := fp + ":" + qualifiedScope

	// Check cache first
	if !req.ForceRefresh && hostClient != nil {
		token, err := cacheGet(ctx, hostClient, cacheKey)
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
	token, err := p.acquireServicePrincipalToken(ctx, creds, qualifiedScope)
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
	}, nil
}

// servicePrincipalStatus returns the status for SP authentication.
func (p *Plugin) servicePrincipalStatus() (*auth.Status, error) {
	creds := GetServicePrincipalCredentials()
	if creds == nil {
		return &auth.Status{Authenticated: false}, nil
	}

	return &auth.Status{
		Authenticated: true,
		Claims: &auth.Claims{
			Subject:  creds.ClientID,
			TenantID: creds.TenantID,
			ClientID: creds.ClientID,
			Name:     fmt.Sprintf("Service Principal (%s...)", creds.ClientID[:min(8, len(creds.ClientID))]),
		},
		TenantID:     creds.TenantID,
		IdentityType: auth.IdentityTypeServicePrincipal,
		ClientID:     creds.ClientID,
	}, nil
}
