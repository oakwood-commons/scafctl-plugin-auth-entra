package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oakwood-commons/scafctl-plugin-auth-entra/internal/clock"
)

// --- mintToken tests ---

func TestMintToken(t *testing.T) {
	t.Run("success with refresh token", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        "https://graph.microsoft.com/.default",
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		ctx := context.Background()

		// Pre-populate stored credentials
		fake.secrets[SecretKeyRefreshToken] = "old-refresh-token"
		metadata := TokenMetadata{
			TenantID: "test-tenant",
			ClientID: "test-client",
			Scopes:   []string{"openid"},
		}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		token, err := p.mintToken(ctx, "https://graph.microsoft.com/.default")
		require.NoError(t, err)
		assert.Equal(t, "new-access-token", token.AccessToken)
		assert.Equal(t, "Bearer", token.TokenType)

		// Verify the request was sent with correct form data
		reqs := httpMock.GetRequests()
		require.Len(t, reqs, 1)
		assert.Equal(t, "refresh_token", reqs[0].Data.Get("grant_type"))
		assert.Equal(t, "test-client", reqs[0].Data.Get("client_id"))
		assert.Equal(t, "old-refresh-token", reqs[0].Data.Get("refresh_token"))
	})

	t.Run("no refresh token stored", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.mintToken(context.Background(), "scope")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not authenticated")
	})

	t.Run("missing client ID in metadata", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		fake.secrets[SecretKeyRefreshToken] = "refresh-token"
		metadata := TokenMetadata{TenantID: "t", ClientID: ""}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		_, err := p.mintToken(context.Background(), "scope")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing client ID")
	})

	t.Run("claims challenge error", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(400, TokenErrorResponse{
			Error:            "interaction_required",
			ErrorDescription: "AADSTS50076: some CAP policy",
			Claims:           "eyJhY2Nlc3NfdG9rZW4iOnt9fQ",
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		fake.secrets[SecretKeyRefreshToken] = "rt"
		metadata := TokenMetadata{TenantID: "t", ClientID: "c"}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		_, err := p.mintToken(context.Background(), "scope")
		require.Error(t, err)
		var ccErr *ClaimsChallengeError
		assert.ErrorAs(t, err, &ccErr)
		assert.Equal(t, "scope", ccErr.Scope)
	})

	t.Run("invalid_grant triggers logout", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(400, TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "token expired",
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		fake.secrets[SecretKeyRefreshToken] = "rt"
		metadata := TokenMetadata{TenantID: "t", ClientID: "c"}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		_, err := p.mintToken(context.Background(), "scope")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token expired")
		// Should have cleared stored secrets (logout)
		assert.Empty(t, fake.secrets)
	})

	t.Run("AADSTS error with hint", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(400, TokenErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "AADSTS700016: Application not found",
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		fake.secrets[SecretKeyRefreshToken] = "rt"
		metadata := TokenMetadata{TenantID: "t", ClientID: "c"}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		_, err := p.mintToken(context.Background(), "scope")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Hint:")
	})

	t.Run("refresh token rotation stores new token", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken:  "at",
			RefreshToken: "rotated-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		fake.secrets[SecretKeyRefreshToken] = "old-rt"
		metadata := TokenMetadata{
			TenantID:  "t",
			ClientID:  "c",
			LoginFlow: auth.FlowDeviceCode,
			SessionID: "sess",
		}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		_, err := p.mintToken(context.Background(), "scope")
		require.NoError(t, err)

		// Verify refresh token was updated
		assert.Equal(t, "rotated-rt", fake.secrets[SecretKeyRefreshToken])
	})
}

// --- storeCredentials tests ---

func TestStoreCredentials(t *testing.T) {
	t.Run("stores refresh token and metadata", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)

		tokenResp := &TokenResponse{
			AccessToken:  "at",
			RefreshToken: "rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}

		err := p.storeCredentials(context.Background(), "tenant", tokenResp, "client", []string{"openid"}, auth.FlowDeviceCode, "")
		require.NoError(t, err)

		assert.Equal(t, "rt", fake.secrets[SecretKeyRefreshToken])
		assert.Contains(t, fake.secrets[SecretKeyMetadata], "tenant")
		assert.Contains(t, fake.secrets[SecretKeyMetadata], "client")
	})

	t.Run("rejects missing refresh token", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)

		tokenResp := &TokenResponse{AccessToken: "at"}
		err := p.storeCredentials(context.Background(), "t", tokenResp, "c", nil, "", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no refresh token")
	})

	t.Run("generates session ID when empty", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)

		tokenResp := &TokenResponse{RefreshToken: "rt"}
		err := p.storeCredentials(context.Background(), "t", tokenResp, "c", nil, "", "")
		require.NoError(t, err)

		var md TokenMetadata
		_ = json.Unmarshal([]byte(fake.secrets[SecretKeyMetadata]), &md)
		assert.NotEmpty(t, md.SessionID)
	})

	t.Run("preserves existing session ID", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)

		tokenResp := &TokenResponse{RefreshToken: "rt"}
		err := p.storeCredentials(context.Background(), "t", tokenResp, "c", nil, "", "keep-me")
		require.NoError(t, err)

		var md TokenMetadata
		_ = json.Unmarshal([]byte(fake.secrets[SecretKeyMetadata]), &md)
		assert.Equal(t, "keep-me", md.SessionID)
	})

	t.Run("extracts claims from ID token", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)

		jwt := makeTestJWT(map[string]any{
			"sub":  "user-sub",
			"name": "Test User",
			"tid":  "jwt-tenant",
		})
		tokenResp := &TokenResponse{RefreshToken: "rt", IDToken: jwt}
		err := p.storeCredentials(context.Background(), "t", tokenResp, "c", nil, "", "")
		require.NoError(t, err)

		var md TokenMetadata
		_ = json.Unmarshal([]byte(fake.secrets[SecretKeyMetadata]), &md)
		assert.Equal(t, "user-sub", md.Claims.Subject)
		assert.Equal(t, "Test User", md.Claims.Name)
	})
}

// --- makeFormData tests ---

func TestMakeFormData(t *testing.T) {
	data := makeFormData(map[string]string{
		"grant_type": "authorization_code",
		"client_id":  "test-id",
	})
	assert.Equal(t, []string{"authorization_code"}, data["grant_type"])
	assert.Equal(t, []string{"test-id"}, data["client_id"])
}

// --- device code flow tests ---

func TestDeviceCodeFlow(t *testing.T) {
	t.Run("successful device code login", func(t *testing.T) {
		httpMock := NewMockHTTPClient()

		// Step 1: device code request
		httpMock.AddResponse(200, DeviceCodeResponse{
			DeviceCode:      "device-code-123",
			UserCode:        "ABCD-1234",
			VerificationURI: "https://microsoft.com/devicelogin",
			ExpiresIn:       900,
			Interval:        5,
			Message:         "Go to https://microsoft.com/devicelogin and enter ABCD-1234",
		})

		// Step 2: first poll returns authorization_pending
		httpMock.AddResponse(400, TokenErrorResponse{
			Error:            "authorization_pending",
			ErrorDescription: "user has not yet authorized",
		})

		// Step 3: second poll returns success
		httpMock.AddResponse(200, TokenResponse{
			AccessToken:  "device-access-token",
			RefreshToken: "device-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken: makeTestJWT(map[string]any{
				"sub":  "device-user",
				"name": "Device User",
				"tid":  "device-tenant",
			}),
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		p.clock = clock.Mock{}

		var gotPrompt sdkplugin.DeviceCodePrompt
		cb := func(prompt sdkplugin.DeviceCodePrompt) {
			gotPrompt = prompt
		}

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowDeviceCode,
			Timeout: 30 * time.Second,
		}, cb)
		require.NoError(t, err)
		assert.Equal(t, "device-user", resp.Claims.Subject)
		assert.Equal(t, "Device User", resp.Claims.Name)

		// Verify device code callback was called
		assert.Equal(t, "ABCD-1234", gotPrompt.UserCode)
		assert.Equal(t, "https://microsoft.com/devicelogin", gotPrompt.VerificationURI)
	})

	t.Run("device code request fails", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(400, TokenErrorResponse{
			Error:            "invalid_scope",
			ErrorDescription: "AADSTS70011: Invalid scope",
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		p.clock = clock.Mock{}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowDeviceCode,
			Timeout: 5 * time.Second,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device_code_request")
	})

	t.Run("expired token during polling", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, DeviceCodeResponse{
			DeviceCode: "dc", UserCode: "UC", VerificationURI: "https://example.com",
			ExpiresIn: 900, Interval: 5,
		})
		httpMock.AddResponse(400, TokenErrorResponse{
			Error: "expired_token", ErrorDescription: "code expired",
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		p.clock = clock.Mock{}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowDeviceCode,
			Timeout: 5 * time.Second,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
	})

	t.Run("authorization declined", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, DeviceCodeResponse{
			DeviceCode: "dc", UserCode: "UC", VerificationURI: "https://example.com",
			ExpiresIn: 900, Interval: 5,
		})
		httpMock.AddResponse(400, TokenErrorResponse{
			Error: "authorization_declined", ErrorDescription: "user declined",
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		p.clock = clock.Mock{}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowDeviceCode,
			Timeout: 5 * time.Second,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cancelled")
	})

	t.Run("slow_down increases interval", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, DeviceCodeResponse{
			DeviceCode: "dc", UserCode: "UC", VerificationURI: "https://example.com",
			ExpiresIn: 900, Interval: 5,
		})
		// slow_down response
		httpMock.AddResponse(400, TokenErrorResponse{
			Error: "slow_down", ErrorDescription: "slow down",
		})
		// Then success
		httpMock.AddResponse(200, TokenResponse{
			AccessToken:  "at",
			RefreshToken: "rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		p.clock = clock.Mock{}

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowDeviceCode,
			Timeout: 30 * time.Second,
		}, nil)
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

// --- service principal flow tests ---

func TestServicePrincipalLogin(t *testing.T) {
	t.Run("successful SP login", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "sp-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		t.Setenv(EnvAzureClientID, "sp-client-id")
		t.Setenv(EnvAzureTenantID, "sp-tenant-id")
		t.Setenv(EnvAzureClientSecret, "sp-secret")

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowServicePrincipal,
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, "sp-client-id", resp.Claims.Subject)
		assert.Equal(t, "sp-tenant-id", resp.Claims.TenantID)
	})

	t.Run("SP login without env vars", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureTenantID, "")
		t.Setenv(EnvAzureClientSecret, "")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowServicePrincipal,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
	})

	t.Run("SP token request fails", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(401, TokenErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "AADSTS7000215: Invalid client secret",
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		t.Setenv(EnvAzureClientID, "sp-client-id")
		t.Setenv(EnvAzureTenantID, "sp-tenant-id")
		t.Setenv(EnvAzureClientSecret, "wrong-secret")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowServicePrincipal,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid client credentials")
	})

	t.Run("SP unauthorized_client error", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(400, TokenErrorResponse{
			Error:            "unauthorized_client",
			ErrorDescription: "The client does not have permission",
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		t.Setenv(EnvAzureClientID, "sp-client-id")
		t.Setenv(EnvAzureTenantID, "sp-tenant-id")
		t.Setenv(EnvAzureClientSecret, "secret")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowServicePrincipal,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not authorized")
	})
}

// --- service principal token ---

func TestGetServicePrincipalToken(t *testing.T) {
	t.Run("acquires and caches token", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "sp-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		t.Setenv(EnvAzureClientID, "sp-client")
		t.Setenv(EnvAzureTenantID, "sp-tenant")
		t.Setenv(EnvAzureClientSecret, "sp-secret")

		resp, err := p.getServicePrincipalToken(context.Background(), sdkplugin.TokenRequest{
			Scope: "https://graph.microsoft.com/.default",
		})
		require.NoError(t, err)
		assert.Equal(t, "sp-at", resp.AccessToken)
		assert.Equal(t, auth.FlowServicePrincipal, resp.Flow)
	})

	t.Run("scope required", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "c")
		t.Setenv(EnvAzureTenantID, "t")
		t.Setenv(EnvAzureClientSecret, "s")

		_, err := p.getServicePrincipalToken(context.Background(), sdkplugin.TokenRequest{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "scope is required")
	})
}

// --- workload identity tests ---

func TestWorkloadIdentityLogin(t *testing.T) {
	t.Run("successful WI login", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "wi-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)

		// Create a temp token file
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("federated-token-content"), 0o600))

		t.Setenv(EnvAzureClientID, "wi-client-id")
		t.Setenv(EnvAzureTenantID, "wi-tenant-id")
		t.Setenv(EnvAzureFederatedTokenFile, tokenFile)
		t.Setenv(EnvAzureClientSecret, "")

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowWorkloadIdentity,
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, "wi-client-id", resp.Claims.Subject)
		assert.Equal(t, "wi-tenant-id", resp.Claims.TenantID)

		// Verify form data
		reqs := httpMock.GetRequests()
		require.Len(t, reqs, 1)
		assert.Equal(t, "client_credentials", reqs[0].Data.Get("grant_type"))
		assert.Equal(t, "federated-token-content", reqs[0].Data.Get("client_assertion"))
	})

	t.Run("WI login without env vars", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureTenantID, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")
		t.Setenv(EnvAzureClientSecret, "")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowWorkloadIdentity,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
	})

	t.Run("WI token exchange fails with AADSTS700024", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(401, TokenErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "AADSTS700024: Client assertion is expired",
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("expired-token"), 0o600))

		t.Setenv(EnvAzureClientID, "wi-client")
		t.Setenv(EnvAzureTenantID, "wi-tenant")
		t.Setenv(EnvAzureFederatedTokenFile, tokenFile)
		t.Setenv(EnvAzureClientSecret, "")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowWorkloadIdentity,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AADSTS700024")
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("WI with direct token", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "wi-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		t.Setenv(EnvAzureClientID, "wi-client")
		t.Setenv(EnvAzureTenantID, "wi-tenant")
		t.Setenv(EnvAzureFederatedToken, "direct-federated-token")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureClientSecret, "")

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowWorkloadIdentity,
		}, nil)
		require.NoError(t, err)
		assert.NotNil(t, resp)

		reqs := httpMock.GetRequests()
		require.Len(t, reqs, 1)
		assert.Equal(t, "direct-federated-token", reqs[0].Data.Get("client_assertion"))
	})
}

func TestGetWorkloadIdentityToken(t *testing.T) {
	t.Run("acquires and caches token", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "wi-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		t.Setenv(EnvAzureClientID, "wi-client")
		t.Setenv(EnvAzureTenantID, "wi-tenant")
		t.Setenv(EnvAzureFederatedToken, "federated-token")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureClientSecret, "")

		resp, err := p.getWorkloadIdentityToken(context.Background(), sdkplugin.TokenRequest{
			Scope: "https://management.azure.com/.default",
		})
		require.NoError(t, err)
		assert.Equal(t, "wi-at", resp.AccessToken)
		assert.Equal(t, auth.FlowWorkloadIdentity, resp.Flow)
	})

	t.Run("scope required", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "c")
		t.Setenv(EnvAzureTenantID, "t")
		t.Setenv(EnvAzureFederatedToken, "tok")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureClientSecret, "")

		_, err := p.getWorkloadIdentityToken(context.Background(), sdkplugin.TokenRequest{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "scope is required")
	})
}

func TestWorkloadIdentityStatus(t *testing.T) {
	t.Run("authenticated with credentials", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "wi-client-id")
		t.Setenv(EnvAzureTenantID, "wi-tenant-id")
		t.Setenv(EnvAzureFederatedToken, "tok")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureClientSecret, "")

		status, err := p.GetStatus(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Equal(t, auth.IdentityTypeWorkloadIdentity, status.IdentityType)
		assert.Equal(t, "wi-client-id", status.ClientID)
	})
}

// --- OBO flow tests ---

func TestOBOFlow(t *testing.T) {
	t.Run("successful OBO token", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "obo-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)

		token, err := p.GetOBOToken(context.Background(), OBOTokenOptions{
			Assertion:    "upstream-token",
			Scope:        "api://downstream/.default",
			ClientSecret: "client-secret",
		})
		require.NoError(t, err)
		assert.Equal(t, "obo-access-token", token.AccessToken)
		assert.Equal(t, FlowOnBehalfOf, string(token.Flow))

		// Verify request form data
		reqs := httpMock.GetRequests()
		require.Len(t, reqs, 1)
		assert.Equal(t, OBOGrantType, reqs[0].Data.Get("grant_type"))
		assert.Equal(t, "upstream-token", reqs[0].Data.Get("assertion"))
		assert.Equal(t, OBORequestedTokenUse, reqs[0].Data.Get("requested_token_use"))
	})

	t.Run("OBO uses in-memory cache", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "obo-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)

		opts := OBOTokenOptions{
			Assertion:    "upstream",
			Scope:        "api://test/.default",
			ClientSecret: "secret",
		}

		// First call mints
		tok1, err := p.GetOBOToken(context.Background(), opts)
		require.NoError(t, err)

		// Second call hits cache (no additional HTTP request)
		tok2, err := p.GetOBOToken(context.Background(), opts)
		require.NoError(t, err)

		assert.Equal(t, tok1.AccessToken, tok2.AccessToken)
		assert.Len(t, httpMock.GetRequests(), 1, "should only make one HTTP request")
	})

	t.Run("OBO missing assertion", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.GetOBOToken(context.Background(), OBOTokenOptions{
			Scope:        "scope",
			ClientSecret: "secret",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "assertion")
	})

	t.Run("OBO missing scope", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.GetOBOToken(context.Background(), OBOTokenOptions{
			Assertion:    "tok",
			ClientSecret: "secret",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "scope is required")
	})

	t.Run("OBO missing client secret", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.GetOBOToken(context.Background(), OBOTokenOptions{
			Assertion: "tok",
			Scope:     "scope",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client secret")
	})

	t.Run("OBO token request fails", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(400, TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "AADSTS500011: API resource not found",
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		_, err := p.GetOBOToken(context.Background(), OBOTokenOptions{
			Assertion:    "tok",
			Scope:        "bad-scope",
			ClientSecret: "secret",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AADSTS500011")
	})
}

// --- oboCache tests ---

func TestOBOCache(t *testing.T) {
	t.Run("get returns false for missing", func(t *testing.T) {
		c := newOBOCache()
		_, ok := c.get("assertion", "scope")
		assert.False(t, ok)
	})

	t.Run("get returns token after set", func(t *testing.T) {
		c := newOBOCache()
		token := &auth.Token{
			AccessToken: "cached",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
		}
		c.set("assertion", "scope", token)

		got, ok := c.get("assertion", "scope")
		assert.True(t, ok)
		assert.Equal(t, "cached", got.AccessToken)
	})

	t.Run("get evicts expired entries", func(t *testing.T) {
		c := newOBOCache()
		token := &auth.Token{
			AccessToken: "expired",
			ExpiresAt:   time.Now().Add(-1 * time.Hour),
		}
		c.set("assertion", "scope", token)

		_, ok := c.get("assertion", "scope")
		assert.False(t, ok)
	})
}

// --- loadRefreshToken tests ---

func TestLoadRefreshToken(t *testing.T) {
	t.Run("returns stored token", func(t *testing.T) {
		p, fake := newTestPlugin(t, nil, nil)
		fake.secrets[SecretKeyRefreshToken] = "my-refresh-token"

		token, err := p.loadRefreshToken(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "my-refresh-token", token)
	})

	t.Run("error when not found", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		_, err := p.loadRefreshToken(context.Background())
		assert.Error(t, err)
	})
}

// --- GetFederatedToken tests ---

func TestGetFederatedToken(t *testing.T) {
	t.Run("reads from file", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("file-token"), 0o600))

		creds := &WorkloadIdentityCredentials{
			ClientID:  "c",
			TenantID:  "t",
			TokenFile: tokenFile,
		}
		tok, err := creds.GetFederatedToken()
		require.NoError(t, err)
		assert.Equal(t, "file-token", tok)
	})

	t.Run("uses direct token", func(t *testing.T) {
		creds := &WorkloadIdentityCredentials{
			ClientID: "c",
			TenantID: "t",
			Token:    "direct-token",
		}
		tok, err := creds.GetFederatedToken()
		require.NoError(t, err)
		assert.Equal(t, "direct-token", tok)
	})

	t.Run("prefers direct token over file", func(t *testing.T) {
		creds := &WorkloadIdentityCredentials{
			ClientID:  "c",
			TenantID:  "t",
			Token:     "direct",
			TokenFile: "/nonexistent",
		}
		tok, err := creds.GetFederatedToken()
		require.NoError(t, err)
		assert.Equal(t, "direct", tok)
	})

	t.Run("error when nothing configured", func(t *testing.T) {
		creds := &WorkloadIdentityCredentials{ClientID: "c", TenantID: "t"}
		_, err := creds.GetFederatedToken()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no federated token configured")
	})

	t.Run("error on missing file", func(t *testing.T) {
		creds := &WorkloadIdentityCredentials{
			ClientID:  "c",
			TenantID:  "t",
			TokenFile: "/nonexistent/token",
		}
		_, err := creds.GetFederatedToken()
		assert.Error(t, err)
	})

	t.Run("error on empty file", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "empty")
		require.NoError(t, os.WriteFile(tokenFile, []byte(""), 0o600))

		creds := &WorkloadIdentityCredentials{
			ClientID:  "c",
			TenantID:  "t",
			TokenFile: tokenFile,
		}
		_, err := creds.GetFederatedToken()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})
}

// --- Login flow auto-detection tests ---

func TestLoginFlowAutoDetection(t *testing.T) {
	t.Run("auto-detects workload identity", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "wi-at", TokenType: "Bearer", ExpiresIn: 3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		t.Setenv(EnvAzureClientID, "wi-client")
		t.Setenv(EnvAzureTenantID, "wi-tenant")
		t.Setenv(EnvAzureFederatedToken, "direct-token")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureClientSecret, "")

		// Login with empty flow -- should auto-detect WI
		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		assert.Equal(t, "wi-client", resp.Claims.Subject)
	})

	t.Run("auto-detects service principal", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken: "sp-at", TokenType: "Bearer", ExpiresIn: 3600,
		})

		p, _ := newTestPlugin(t, httpMock, nil)
		t.Setenv(EnvAzureClientID, "sp-client")
		t.Setenv(EnvAzureTenantID, "sp-tenant")
		t.Setenv(EnvAzureClientSecret, "sp-secret")
		t.Setenv(EnvAzureFederatedToken, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")

		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{}, nil)
		require.NoError(t, err)
		assert.Equal(t, "sp-client", resp.Claims.Subject)
	})
}

// --- Validate config tests ---

func TestConfigValidate(t *testing.T) {
	t.Run("empty clientId fails", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.ClientID = ""
		assert.Error(t, cfg.Validate())
	})

	t.Run("empty tenantId fails", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.TenantID = ""
		assert.Error(t, cfg.Validate())
	})
}

// --- servicePrincipalStatus tests ---

func TestServicePrincipalStatus(t *testing.T) {
	t.Run("returns status with truncated client ID", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "abcdefgh-1234-5678-9012-1234567890ab")
		t.Setenv(EnvAzureTenantID, "sp-tenant")
		t.Setenv(EnvAzureClientSecret, "secret")

		status, err := p.servicePrincipalStatus()
		require.NoError(t, err)
		assert.True(t, status.Authenticated)
		assert.Contains(t, status.Claims.Name, "abcdefgh")
		assert.Equal(t, auth.IdentityTypeServicePrincipal, status.IdentityType)
	})
}

// --- Benchmarks ---

func BenchmarkFingerprintHash(b *testing.B) {
	for b.Loop() {
		fingerprintHash("test-client-id:test-tenant-id")
	}
}

func BenchmarkMakeFormData(b *testing.B) {
	m := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     "test-client-id",
		"redirect_uri":  "http://localhost:8080/callback",
		"code":          "auth-code-12345",
		"code_verifier": "pkce-verifier-abcdef",
	}
	for b.Loop() {
		makeFormData(m)
	}
}

func BenchmarkParseJWTClaims(b *testing.B) {
	jwt := makeTestJWT(map[string]any{
		"sub":                "user-sub",
		"name":               "Test User",
		"preferred_username": "test@example.com",
		"email":              "test@example.com",
		"iss":                "https://login.microsoftonline.com/tid/v2.0",
		"tid":                "tenant-id",
		"oid":                "object-id",
		"exp":                float64(time.Now().Add(1 * time.Hour).Unix()),
	})
	for b.Loop() {
		_, _ = parseJWTClaims(jwt)
	}
}

func BenchmarkOBOCacheKey(b *testing.B) {
	for b.Loop() {
		oboCacheKey("upstream-token-value-that-is-fairly-long", "api://downstream-api/.default")
	}
}

func BenchmarkCacheGetMiss(b *testing.B) {
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)
	ctx := context.Background()
	for b.Loop() {
		_, _ = cacheGet(ctx, hostClient, "nonexistent-key")
	}
}

func BenchmarkCacheSetAndGet(b *testing.B) {
	fake := newFakeHostService()
	hostClient := newFakeHostClient(fake)
	ctx := context.Background()
	token := &auth.Token{
		AccessToken: "benchmark-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		Scope:       "https://graph.microsoft.com/.default",
	}
	_ = cacheSet(ctx, hostClient, "bench-key", token)
	for b.Loop() {
		_, _ = cacheGet(ctx, hostClient, "bench-key")
	}
}

func BenchmarkAADSTSHint(b *testing.B) {
	for b.Loop() {
		aadstsHint("AADSTS700016: Application not found in directory")
	}
}

func BenchmarkQualifyScope(b *testing.B) {
	for b.Loop() {
		QualifyScope("https://graph.microsoft.com/.default")
	}
}

// --- exchangeAuthCode tests ---

func TestExchangeAuthCode(t *testing.T) {
	t.Run("successful exchange", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken:  "exchange-at",
			RefreshToken: "exchange-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestJWT(map[string]any{"sub": "user"}),
		})

		p, _ := newTestPlugin(t, httpMock, nil)

		tokenResp, err := p.exchangeAuthCode(context.Background(), "tenant-id", "auth-code", "http://localhost:8080/callback", "pkce-verifier")
		require.NoError(t, err)
		assert.Equal(t, "exchange-at", tokenResp.AccessToken)
		assert.Equal(t, "exchange-rt", tokenResp.RefreshToken)

		reqs := httpMock.GetRequests()
		require.Len(t, reqs, 1)
		assert.Equal(t, "authorization_code", reqs[0].Data.Get("grant_type"))
		assert.Equal(t, "auth-code", reqs[0].Data.Get("code"))
		assert.Equal(t, "http://localhost:8080/callback", reqs[0].Data.Get("redirect_uri"))
		assert.Equal(t, "pkce-verifier", reqs[0].Data.Get("code_verifier"))
	})

	t.Run("HTTP error with AADSTS", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(400, TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "AADSTS70011: Invalid scope",
		})

		p, _ := newTestPlugin(t, httpMock, nil)

		_, err := p.exchangeAuthCode(context.Background(), "t", "code", "http://localhost/cb", "verifier")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AADSTS70011")
		assert.Contains(t, err.Error(), "Hint:")
	})

	t.Run("HTTP error without AADSTS", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(400, TokenErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "code is expired",
		})

		p, _ := newTestPlugin(t, httpMock, nil)

		_, err := p.exchangeAuthCode(context.Background(), "t", "code", "http://localhost/cb", "verifier")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token exchange failed")
		assert.Contains(t, err.Error(), "code is expired")
	})

	t.Run("HTTP error with unparseable body", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		// Add a raw response that can't be decoded as TokenErrorResponse
		httpMock.mu.Lock()
		httpMock.Responses = append(httpMock.Responses, &MockResponse{
			StatusCode: 500,
			Body:       nil,
		})
		httpMock.mu.Unlock()

		p, _ := newTestPlugin(t, httpMock, nil)

		_, err := p.exchangeAuthCode(context.Background(), "t", "code", "http://localhost/cb", "verifier")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status 500")
	})

	t.Run("network error", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddError(fmt.Errorf("connection refused"))

		p, _ := newTestPlugin(t, httpMock, nil)

		_, err := p.exchangeAuthCode(context.Background(), "t", "code", "http://localhost/cb", "verifier")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "connection refused")
	})
}

// --- GetToken additional tests ---

func TestGetTokenAdditional(t *testing.T) {
	t.Run("force refresh bypasses cache", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken:  "fresh-at",
			RefreshToken: "fresh-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        "https://graph.microsoft.com/.default",
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		ctx := context.Background()

		// Clear env to avoid SP/WI detection
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		// Pre-populate cache with a stale token
		fp := fingerprintHash(p.config.ClientID + ":" + p.config.TenantID + ":" + p.config.GetAuthority())
		cacheKey := fp + ":https://graph.microsoft.com/.default"
		entry := tokenCacheEntry{
			AccessToken: "stale-cached-token",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(1 * time.Hour),
			Scope:       "https://graph.microsoft.com/.default",
			CachedAt:    time.Now(),
		}
		entryBytes, _ := json.Marshal(entry)
		fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryBytes)

		// Also need refresh token + metadata for mintToken
		fake.secrets[SecretKeyRefreshToken] = "refresh-token"
		metadata := TokenMetadata{
			TenantID:  "common",
			ClientID:  p.config.ClientID,
			LoginFlow: auth.FlowDeviceCode,
			SessionID: "sess",
		}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://graph.microsoft.com/.default",
			ForceRefresh: true,
		})
		require.NoError(t, err)
		assert.Equal(t, "fresh-at", resp.AccessToken)
		assert.Len(t, httpMock.GetRequests(), 1, "should have made an HTTP request despite cache")
	})

	t.Run("cache miss mints and stores", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken:  "minted-at",
			RefreshToken: "minted-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        "https://graph.microsoft.com/.default",
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		ctx := context.Background()

		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		// Set up refresh token + metadata (no cache)
		fake.secrets[SecretKeyRefreshToken] = "refresh-token"
		metadata := TokenMetadata{
			TenantID:  "common",
			ClientID:  p.config.ClientID,
			LoginFlow: auth.FlowDeviceCode,
			SessionID: "sess",
		}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
			Scope: "https://graph.microsoft.com/.default",
		})
		require.NoError(t, err)
		assert.Equal(t, "minted-at", resp.AccessToken)

		// Verify token was cached
		fp := fingerprintHash(p.config.ClientID + ":" + p.config.TenantID + ":" + p.config.GetAuthority())
		cacheKey := SecretKeyTokenPrefix + fp + ":https://graph.microsoft.com/.default"
		assert.Contains(t, fake.secrets, cacheKey)
	})

	t.Run("mint failure propagates error", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(401, TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "token expired or revoked",
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		ctx := context.Background()

		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		fake.secrets[SecretKeyRefreshToken] = "expired-rt"
		metadata := TokenMetadata{TenantID: "t", ClientID: "c"}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		_, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
			Scope: "https://graph.microsoft.com/.default",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token expired")
	})

	t.Run("expired cached token triggers refresh", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(200, TokenResponse{
			AccessToken:  "refreshed-at",
			RefreshToken: "refreshed-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        "api://myapi/.default",
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		ctx := context.Background()

		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureClientSecret, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")

		// Expired cache entry
		fp := fingerprintHash(p.config.ClientID + ":" + p.config.TenantID + ":" + p.config.GetAuthority())
		cacheKey := fp + ":api://myapi/.default"
		entry := tokenCacheEntry{
			AccessToken: "expired-at",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(-10 * time.Minute),
			Scope:       "api://myapi/.default",
			CachedAt:    time.Now().Add(-1 * time.Hour),
		}
		entryBytes, _ := json.Marshal(entry)
		fake.secrets[SecretKeyTokenPrefix+cacheKey] = string(entryBytes)

		// Set up refresh token + metadata
		fake.secrets[SecretKeyRefreshToken] = "rt"
		metadata := TokenMetadata{TenantID: "common", ClientID: p.config.ClientID}
		metadataBytes, _ := json.Marshal(metadata)
		fake.secrets[SecretKeyMetadata] = string(metadataBytes)

		resp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
			Scope: "api://myapi/.default",
		})
		require.NoError(t, err)
		assert.Equal(t, "refreshed-at", resp.AccessToken)
	})
}

// --- QualifyScope multi-token test ---

func TestQualifyScopeMultiToken(t *testing.T) {
	t.Run("qualifies multiple space-separated scopes", func(t *testing.T) {
		result := QualifyScope("User.Read Group.Read.All")
		assert.Equal(t, "https://graph.microsoft.com/User.Read https://graph.microsoft.com/Group.Read.All", result)
	})

	t.Run("preserves already-qualified scopes in multi-token", func(t *testing.T) {
		result := QualifyScope("https://graph.microsoft.com/.default offline_access")
		assert.Equal(t, "https://graph.microsoft.com/.default offline_access", result)
	})

	t.Run("mixes bare and qualified scopes", func(t *testing.T) {
		result := QualifyScope("openid profile User.Read")
		assert.Equal(t, "openid profile https://graph.microsoft.com/User.Read", result)
	})
}

// --- workloadIdentityLogin error branch tests ---

func TestWorkloadIdentityLoginErrors(t *testing.T) {
	t.Run("missing token file env var", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureTenantID, "")
		t.Setenv(EnvAzureFederatedTokenFile, "")
		t.Setenv(EnvAzureFederatedToken, "")
		t.Setenv(EnvAzureClientSecret, "")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowWorkloadIdentity,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
	})

	t.Run("token file does not exist", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "client")
		t.Setenv(EnvAzureTenantID, "tenant")
		t.Setenv(EnvAzureFederatedTokenFile, "/nonexistent/path/token")
		t.Setenv(EnvAzureFederatedToken, "")
		t.Setenv(EnvAzureClientSecret, "")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowWorkloadIdentity,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("missing client ID with token file", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := dir + "/token"
		require.NoError(t, os.WriteFile(tokenFile, []byte("tok"), 0o600))

		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "")
		t.Setenv(EnvAzureTenantID, "tenant")
		t.Setenv(EnvAzureFederatedTokenFile, tokenFile)
		t.Setenv(EnvAzureFederatedToken, "")
		t.Setenv(EnvAzureClientSecret, "")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowWorkloadIdentity,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), EnvAzureClientID)
	})

	t.Run("missing tenant ID with token file", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := dir + "/token"
		require.NoError(t, os.WriteFile(tokenFile, []byte("tok"), 0o600))

		p, _ := newTestPlugin(t, nil, nil)
		t.Setenv(EnvAzureClientID, "client")
		t.Setenv(EnvAzureTenantID, "")
		t.Setenv(EnvAzureFederatedTokenFile, tokenFile)
		t.Setenv(EnvAzureFederatedToken, "")
		t.Setenv(EnvAzureClientSecret, "")

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowWorkloadIdentity,
		}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), EnvAzureTenantID)
	})
}
