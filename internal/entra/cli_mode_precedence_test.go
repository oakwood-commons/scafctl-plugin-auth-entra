// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearCredentialEnv unsets every credential-relevant environment variable so
// each subtest controls ambient credentials exactly.
func clearCredentialEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvAzureClientID, "")
	t.Setenv(EnvAzureTenantID, "")
	t.Setenv(EnvAzureClientSecret, "")
	t.Setenv(EnvAzureFederatedToken, "")
	t.Setenv(EnvAzureFederatedTokenFile, "")
	t.Setenv(EnvAzureAuthorityHost, "")
}

// setServicePrincipalEnv sets a complete service principal environment.
func setServicePrincipalEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvAzureClientID, "11111111-2222-3333-4444-555555555555")
	t.Setenv(EnvAzureTenantID, "sp-tenant")
	t.Setenv(EnvAzureClientSecret, "sp-secret")
	t.Setenv(EnvAzureFederatedToken, "")
	t.Setenv(EnvAzureFederatedTokenFile, "")
}

// setWorkloadIdentityEnv sets a complete workload identity environment.
func setWorkloadIdentityEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvAzureClientID, "wi-client")
	t.Setenv(EnvAzureTenantID, "wi-tenant")
	t.Setenv(EnvAzureClientSecret, "")
	t.Setenv(EnvAzureFederatedToken, "federated-token")
	t.Setenv(EnvAzureFederatedTokenFile, "")
}

// storeUserSession stores a refresh token and metadata for a user login with
// the given flow and refresh-token expiry, mimicking what Login stores.
func storeUserSession(t *testing.T, fake *fakeHostService, flow auth.Flow, expiresAt time.Time) {
	t.Helper()
	fake.secrets[SecretKeyRefreshToken] = "stored-refresh-token"
	metadata := auth.HandlerMetadata{
		Claims: &auth.Claims{
			Subject: "stored-user",
			Name:    "Stored User",
		},
		ExpiresAt:     expiresAt,
		LastRefresh:   time.Now(),
		LastLoginFlow: flow,
		SessionID:     "sess-1",
		ClientID:      "stored-client",
		Scopes:        []string{"openid", "profile", "offline_access"},
	}
	metadata.SetMeta(MetaKeyTenantID, "user-tenant")
	metadataBytes, err := json.Marshal(metadata)
	require.NoError(t, err)
	fake.secrets[SecretKeyMetadata] = string(metadataBytes)
}

func TestCLICredentialPrecedenceStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("SP env without stored session reports service principal", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		p, _ := newTestPlugin(t, nil, nil)

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
	})

	t.Run("WI env without stored session reports workload identity", func(t *testing.T) {
		clearCredentialEnv(t)
		setWorkloadIdentityEnv(t)
		p, _ := newTestPlugin(t, nil, nil)

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeWorkloadIdentity, status.IdentityType)
	})

	t.Run("interactive session outranks SP env", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		p, fake := newTestPlugin(t, nil, nil)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeUser, status.IdentityType)
		assert.Equal(t, "stored-user", status.Claims.Subject)
		assert.Equal(t, "user-tenant", status.TenantID)
	})

	t.Run("device_code session outranks SP env", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		p, fake := newTestPlugin(t, nil, nil)
		storeUserSession(t, fake, auth.FlowDeviceCode, time.Now().Add(24*time.Hour))

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeUser, status.IdentityType)
	})

	t.Run("session outranks WI env", func(t *testing.T) {
		clearCredentialEnv(t)
		setWorkloadIdentityEnv(t)
		p, fake := newTestPlugin(t, nil, nil)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeUser, status.IdentityType)
	})

	t.Run("expired session falls back to SP env", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		p, fake := newTestPlugin(t, nil, nil)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(-1*time.Hour))

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
	})

	t.Run("expired session keeps reporting session expiry without env creds", func(t *testing.T) {
		clearCredentialEnv(t)
		p, fake := newTestPlugin(t, nil, nil)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(-1*time.Hour))

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.False(t, status.Authenticated)
		assert.Equal(t, "session expired", status.Reason)
	})

	t.Run("non-user-flow session does not outrank SP env", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		p, fake := newTestPlugin(t, nil, nil)
		storeUserSession(t, fake, auth.FlowServicePrincipal, time.Now().Add(24*time.Hour))

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
	})

	t.Run("corrupted session falls back to SP env", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		p, fake := newTestPlugin(t, nil, nil)
		fake.secrets[SecretKeyRefreshToken] = "stored-refresh-token"
		fake.secrets[SecretKeyMetadata] = `{not json`

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
	})

	t.Run("logout restores SP env credentials", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		p, fake := newTestPlugin(t, nil, nil)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))

		require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
	})

	t.Run("logout restores WI env credentials", func(t *testing.T) {
		clearCredentialEnv(t)
		setWorkloadIdentityEnv(t)
		p, fake := newTestPlugin(t, nil, nil)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))

		require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))

		status, err := p.GetStatus(ctx, HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeWorkloadIdentity, status.IdentityType)
	})
}

func TestCLICredentialPrecedenceToken(t *testing.T) {
	ctx := context.Background()
	graphScope := "https://graph.microsoft.com/.default"

	t.Run("session token served despite SP env", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		httpClient := NewMockHTTPClient()
		httpClient.AddResponse(200, TokenResponse{
			AccessToken:  "user-access-token",
			RefreshToken: "stored-refresh-token", // same token: no rotation
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        graphScope + " offline_access",
		})
		p, fake := newTestPlugin(t, httpClient, nil)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
		require.NoError(t, err)
		assert.Equal(t, "user-access-token", resp.AccessToken)
		assert.Equal(t, auth.FlowInteractive, resp.Flow)

		requests := httpClient.GetRequests()
		require.Len(t, requests, 1)
		assert.Equal(t, "refresh_token", requests[0].Data.Get("grant_type"))
		assert.Equal(t, "stored-refresh-token", requests[0].Data.Get("refresh_token"))
		assert.Equal(t, "stored-client", requests[0].Data.Get("client_id"))
		assert.Contains(t, requests[0].Endpoint, "/user-tenant/oauth2/v2.0/token")
	})

	t.Run("session token served despite WI env", func(t *testing.T) {
		clearCredentialEnv(t)
		setWorkloadIdentityEnv(t)
		httpClient := NewMockHTTPClient()
		httpClient.AddResponse(200, TokenResponse{
			AccessToken:  "user-access-token",
			RefreshToken: "stored-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
		p, fake := newTestPlugin(t, httpClient, nil)
		storeUserSession(t, fake, auth.FlowDeviceCode, time.Now().Add(24*time.Hour))

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
		require.NoError(t, err)
		assert.Equal(t, "user-access-token", resp.AccessToken)

		requests := httpClient.GetRequests()
		require.Len(t, requests, 1)
		assert.Equal(t, "refresh_token", requests[0].Data.Get("grant_type"))
	})

	t.Run("SP token served without stored session (unchanged)", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		httpClient := NewMockHTTPClient()
		httpClient.AddResponse(200, TokenResponse{
			AccessToken: "sp-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		p, _ := newTestPlugin(t, httpClient, nil)

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
		require.NoError(t, err)
		assert.Equal(t, "sp-access-token", resp.AccessToken)

		requests := httpClient.GetRequests()
		require.Len(t, requests, 1)
		assert.Equal(t, "client_credentials", requests[0].Data.Get("grant_type"))
		assert.Contains(t, requests[0].Endpoint, "/sp-tenant/oauth2/v2.0/token")
	})

	t.Run("expired session falls back to SP token", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		httpClient := NewMockHTTPClient()
		httpClient.AddResponse(200, TokenResponse{
			AccessToken: "sp-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		p, fake := newTestPlugin(t, httpClient, nil)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(-1*time.Hour))

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
		require.NoError(t, err)
		assert.Equal(t, "sp-access-token", resp.AccessToken)

		requests := httpClient.GetRequests()
		require.Len(t, requests, 1)
		assert.Equal(t, "client_credentials", requests[0].Data.Get("grant_type"))
	})

	t.Run("logout restores SP token", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)
		httpClient := NewMockHTTPClient()
		httpClient.AddResponse(200, TokenResponse{
			AccessToken: "sp-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		p, fake := newTestPlugin(t, httpClient, nil)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))

		require.NoError(t, p.Logout(ctx, HandlerName, sdkplugin.LogoutRequest{}))

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
		require.NoError(t, err)
		assert.Equal(t, "sp-access-token", resp.AccessToken)

		requests := httpClient.GetRequests()
		require.Len(t, requests, 1)
		assert.Equal(t, "client_credentials", requests[0].Data.Get("grant_type"))
	})

	t.Run("WI env served without stored session", func(t *testing.T) {
		clearCredentialEnv(t)
		setWorkloadIdentityEnv(t)
		httpClient := NewMockHTTPClient()
		httpClient.AddResponse(200, TokenResponse{
			AccessToken: "wi-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		p, _ := newTestPlugin(t, httpClient, nil)

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
		require.NoError(t, err)
		assert.Equal(t, "wi-access-token", resp.AccessToken)

		requests := httpClient.GetRequests()
		require.Len(t, requests, 1)
		assert.Equal(t, "client_credentials", requests[0].Data.Get("grant_type"))
		assert.Equal(t, "federated-token", requests[0].Data.Get("client_assertion"))
	})
}
