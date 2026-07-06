// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWIFCredential_Apply(t *testing.T) {
	t.Run("reads token file and sets params", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("my-federated-jwt\n"), 0o600))

		cred := &WIFCredential{
			Token:               sdkplugin.SecretRef("file://" + tokenFile),
			ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		}
		params := url.Values{}
		err := cred.Apply(params)
		require.NoError(t, err)
		assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", params.Get("client_assertion_type"))
		assert.Equal(t, "my-federated-jwt", params.Get("client_assertion"))
	})

	t.Run("trims whitespace from token", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("  spaced-token  \n"), 0o600))

		cred := &WIFCredential{Token: sdkplugin.SecretRef("file://" + tokenFile), ClientAssertionType: "jwt-bearer"}
		params := url.Values{}
		err := cred.Apply(params)
		require.NoError(t, err)
		assert.Equal(t, "spaced-token", params.Get("client_assertion"))
	})

	t.Run("error when file does not exist", func(t *testing.T) {
		cred := &WIFCredential{Token: sdkplugin.SecretRef("file:///nonexistent/path/token"), ClientAssertionType: "jwt-bearer"}
		params := url.Values{}
		err := cred.Apply(params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolving WIF token")
	})

	t.Run("error when file is empty", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte(""), 0o600))

		cred := &WIFCredential{Token: sdkplugin.SecretRef("file://" + tokenFile), ClientAssertionType: "jwt-bearer"}
		params := url.Values{}
		err := cred.Apply(params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("error when file is whitespace only", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("   \n\t\n"), 0o600))

		cred := &WIFCredential{Token: sdkplugin.SecretRef("file://" + tokenFile), ClientAssertionType: "jwt-bearer"}
		params := url.Values{}
		err := cred.Apply(params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("resolves from env var", func(t *testing.T) {
		t.Setenv("TEST_WIF_TOKEN", "env-federated-jwt")
		cred := &WIFCredential{Token: sdkplugin.SecretRef("env://TEST_WIF_TOKEN"), ClientAssertionType: "jwt-bearer"}
		params := url.Values{}
		err := cred.Apply(params)
		require.NoError(t, err)
		assert.Equal(t, "env-federated-jwt", params.Get("client_assertion"))
	})
}

func TestSecretCredential_Apply(t *testing.T) {
	t.Run("sets client_secret param", func(t *testing.T) {
		cred := &SecretCredential{Secret: "my-client-secret"}
		params := url.Values{}
		err := cred.Apply(params)
		require.NoError(t, err)
		assert.Equal(t, "my-client-secret", params.Get("client_secret"))
	})

	t.Run("error when secret is empty", func(t *testing.T) {
		cred := &SecretCredential{Secret: ""}
		params := url.Values{}
		err := cred.Apply(params)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client secret is empty")
	})
}

// testHTTPClient wraps an httptest.Server to implement HTTPClient.
type testHTTPClient struct {
	serverURL string
	client    *http.Client
}

func (c *testHTTPClient) PostForm(_ context.Context, endpoint string, data url.Values) (*http.Response, error) {
	// Ignore the endpoint param and use the test server URL directly.
	_ = endpoint
	return c.client.PostForm(c.serverURL, data)
}

func newTestHTTPClient(ts *httptest.Server) *testHTTPClient {
	return &testHTTPClient{serverURL: ts.URL, client: ts.Client()}
}

func TestExecuteTokenRequest(t *testing.T) {
	t.Run("success parses token response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TokenResponse{
				AccessToken: "access-token-123",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		}))
		defer ts.Close()

		client := newTestHTTPClient(ts)
		data := url.Values{"grant_type": {"client_credentials"}, "scope": {"https://graph.microsoft.com/.default"}}
		resp, err := executeTokenRequest(context.Background(), client, ts.URL, data)
		require.NoError(t, err)
		assert.Equal(t, "access-token-123", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, "https://graph.microsoft.com/.default", resp.Scope)
		assert.False(t, resp.ExpiresAt.IsZero())
	})

	t.Run("error on non-200 with parseable body", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(TokenErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "The provided grant is invalid.",
			})
		}))
		defer ts.Close()

		client := newTestHTTPClient(ts)
		data := url.Values{"grant_type": {"client_credentials"}}
		_, err := executeTokenRequest(context.Background(), client, ts.URL, data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
		assert.Contains(t, err.Error(), "The provided grant is invalid.")
	})

	t.Run("error on non-200 with unparseable body", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("not json"))
		}))
		defer ts.Close()

		client := newTestHTTPClient(ts)
		data := url.Values{"grant_type": {"client_credentials"}}
		_, err := executeTokenRequest(context.Background(), client, ts.URL, data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token request failed with HTTP 500")
	})

	t.Run("error when access_token is empty in response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TokenResponse{
				AccessToken: "",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		}))
		defer ts.Close()

		client := newTestHTTPClient(ts)
		data := url.Values{"grant_type": {"client_credentials"}}
		_, err := executeTokenRequest(context.Background(), client, ts.URL, data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token response missing access_token")
	})

	t.Run("error when HTTP call fails", func(t *testing.T) {
		// Use a client pointed at a closed server.
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		ts.Close()

		client := newTestHTTPClient(ts)
		data := url.Values{"grant_type": {"client_credentials"}}
		_, err := executeTokenRequest(context.Background(), client, ts.URL, data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token request failed")
	})
}

func TestOboFlow(t *testing.T) {
	t.Run("sends correct OBO form data and returns token", func(t *testing.T) {
		var receivedForm url.Values
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			receivedForm = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TokenResponse{
				AccessToken: "obo-token",
				TokenType:   "Bearer",
				ExpiresIn:   1800,
			})
		}))
		defer ts.Close()

		cred := &SecretCredential{Secret: "my-secret"}
		client := newTestHTTPClient(ts)
		flow := oboFlow(ts.URL, cred, client)

		resp, err := flow(context.Background(), FlowParams{
			assertion: "caller-jwt",
			Scope:     "api://downstream/.default",
			ClientID:  "my-client-id",
		})
		require.NoError(t, err)
		assert.Equal(t, "obo-token", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, "api://downstream/.default", resp.Scope)

		// Assert form params
		assert.Equal(t, OBOGrantType, receivedForm.Get("grant_type"))
		assert.Equal(t, "my-client-id", receivedForm.Get("client_id"))
		assert.Equal(t, "caller-jwt", receivedForm.Get("assertion"))
		assert.Equal(t, "api://downstream/.default", receivedForm.Get("scope"))
		assert.Equal(t, OBORequestedTokenUse, receivedForm.Get("requested_token_use"))
		assert.Equal(t, "my-secret", receivedForm.Get("client_secret"))
	})

	t.Run("error when credential Apply fails", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("should not reach server")
		}))
		defer ts.Close()

		cred := &SecretCredential{Secret: ""} // will fail Apply
		client := newTestHTTPClient(ts)
		flow := oboFlow(ts.URL, cred, client)

		_, err := flow(context.Background(), FlowParams{
			assertion: "jwt",
			Scope:     "scope",
			ClientID:  "cid",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "applying server credential")
	})

	t.Run("error when token endpoint returns error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(TokenErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "assertion is expired",
			})
		}))
		defer ts.Close()

		cred := &SecretCredential{Secret: "secret"}
		client := newTestHTTPClient(ts)
		flow := oboFlow(ts.URL, cred, client)

		_, err := flow(context.Background(), FlowParams{
			assertion: "expired-jwt",
			Scope:     "scope",
			ClientID:  "cid",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_grant")
	})
}

func TestClientCredentialFlow(t *testing.T) {
	t.Run("sends correct CC form data and returns token", func(t *testing.T) {
		var receivedForm url.Values
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			receivedForm = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TokenResponse{
				AccessToken: "cc-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		}))
		defer ts.Close()

		cred := &SecretCredential{Secret: "cc-secret"}
		client := newTestHTTPClient(ts)
		flow := clientCredentialFlow(ts.URL, cred, client)

		resp, err := flow(context.Background(), FlowParams{
			Scope:    "https://graph.microsoft.com/.default",
			ClientID: "cc-client-id",
		})
		require.NoError(t, err)
		assert.Equal(t, "cc-token", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, "https://graph.microsoft.com/.default", resp.Scope)

		// Assert form params
		assert.Equal(t, "client_credentials", receivedForm.Get("grant_type"))
		assert.Equal(t, "cc-client-id", receivedForm.Get("client_id"))
		assert.Equal(t, "https://graph.microsoft.com/.default", receivedForm.Get("scope"))
		assert.Equal(t, "cc-secret", receivedForm.Get("client_secret"))
		// OBO-specific params should NOT be present
		assert.Empty(t, receivedForm.Get("assertion"))
		assert.Empty(t, receivedForm.Get("requested_token_use"))
	})

	t.Run("error when credential Apply fails", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("should not reach server")
		}))
		defer ts.Close()

		cred := &SecretCredential{Secret: ""} // will fail Apply
		client := newTestHTTPClient(ts)
		flow := clientCredentialFlow(ts.URL, cred, client)

		_, err := flow(context.Background(), FlowParams{
			Scope:    "scope",
			ClientID: "cid",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "applying server credential")
	})

	t.Run("error when token endpoint returns error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(TokenErrorResponse{
				Error:            "unauthorized_client",
				ErrorDescription: "client not authorized",
			})
		}))
		defer ts.Close()

		cred := &SecretCredential{Secret: "secret"}
		client := newTestHTTPClient(ts)
		flow := clientCredentialFlow(ts.URL, cred, client)

		_, err := flow(context.Background(), FlowParams{
			Scope:    "scope",
			ClientID: "cid",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unauthorized_client")
	})
}

// tokenServer returns an httptest.Server that responds with a valid token and
// records the form data it received. Callers must defer ts.Close().
func tokenServer(t *testing.T, accessToken string) (*httptest.Server, *url.Values) {
	t.Helper()
	var received url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		received = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	return ts, &received
}

func TestEntraServerMode_GetToken(t *testing.T) {
	t.Run("routes server context to client_credentials flow", func(t *testing.T) {
		ts, received := tokenServer(t, "server-token")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)

		sm := &entraServerMode{
			strategies: map[auth.ServerContext]FlowFn{
				auth.ServerContextServer:    clientCredentialFlow(ts.URL, cred, client),
				auth.ServerContextDelegated: delegatedDispatch(oboFlow(ts.URL, cred, client), clientCredentialFlow(ts.URL, cred, client)),
			},
			credential: cred,
			clientID:   "my-client",
		}

		resp, err := sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
			Scope:         "https://graph.microsoft.com/.default",
		})
		require.NoError(t, err)
		assert.Equal(t, "server-token", resp.AccessToken)
		assert.Equal(t, "client_credentials", received.Get("grant_type"))
		assert.Equal(t, "my-client", received.Get("client_id"))
		assert.Equal(t, "https://graph.microsoft.com/.default", received.Get("scope"))
	})

	t.Run("routes delegated context with user caller to OBO flow", func(t *testing.T) {
		ts, received := tokenServer(t, "obo-user-token")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)

		sm := &entraServerMode{
			strategies: map[auth.ServerContext]FlowFn{
				auth.ServerContextServer:    clientCredentialFlow(ts.URL, cred, client),
				auth.ServerContextDelegated: delegatedDispatch(oboFlow(ts.URL, cred, client), clientCredentialFlow(ts.URL, cred, client)),
			},
			credential: cred,
			clientID:   "my-client",
		}

		resp, err := sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "api://downstream/.default",
			Assertion:     "user-jwt",
			Caller:        auth.CallerUser,
		})
		require.NoError(t, err)
		assert.Equal(t, "obo-user-token", resp.AccessToken)
		assert.Equal(t, OBOGrantType, received.Get("grant_type"))
		assert.Equal(t, "user-jwt", received.Get("assertion"))
		assert.Equal(t, OBORequestedTokenUse, received.Get("requested_token_use"))
	})

	t.Run("routes delegated context with machine caller to CC flow", func(t *testing.T) {
		ts, received := tokenServer(t, "machine-cc-token")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)

		sm := &entraServerMode{
			strategies: map[auth.ServerContext]FlowFn{
				auth.ServerContextServer:    clientCredentialFlow(ts.URL, cred, client),
				auth.ServerContextDelegated: delegatedDispatch(oboFlow(ts.URL, cred, client), clientCredentialFlow(ts.URL, cred, client)),
			},
			credential: cred,
			clientID:   "my-client",
		}

		resp, err := sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "api://downstream/.default",
			Caller:        auth.CallerMachine,
		})
		require.NoError(t, err)
		assert.Equal(t, "machine-cc-token", resp.AccessToken)
		assert.Equal(t, "client_credentials", received.Get("grant_type"))
		// Machine CC should NOT have OBO params
		assert.Empty(t, received.Get("assertion"))
		assert.Empty(t, received.Get("requested_token_use"))
	})

	t.Run("error on unknown server context", func(t *testing.T) {
		sm := &entraServerMode{
			strategies: map[auth.ServerContext]FlowFn{},
			clientID:   "cid",
		}

		_, err := sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: "unknown",
			Scope:         "scope",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no strategy configured for context")
	})

	t.Run("passes clientID from entraServerMode to flow", func(t *testing.T) {
		ts, received := tokenServer(t, "tok")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)

		sm := &entraServerMode{
			strategies: map[auth.ServerContext]FlowFn{
				auth.ServerContextServer: clientCredentialFlow(ts.URL, cred, client),
			},
			credential: cred,
			clientID:   "override-client-id",
		}

		_, err := sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextServer,
			Scope:         "scope",
		})
		require.NoError(t, err)
		assert.Equal(t, "override-client-id", received.Get("client_id"))
	})

	t.Run("error on CallerUser when delegation is nil", func(t *testing.T) {
		ts, _ := tokenServer(t, "tok")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)

		// Only server context registered — no delegated
		sm := &entraServerMode{
			strategies: map[auth.ServerContext]FlowFn{
				auth.ServerContextServer: clientCredentialFlow(ts.URL, cred, client),
			},
			credential: cred,
			clientID:   "cid",
		}

		_, err := sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "scope",
			Assertion:     "user-jwt",
			Caller:        auth.CallerUser,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no strategy configured for context")
	})

	t.Run("error on CallerMachine when delegation is nil", func(t *testing.T) {
		ts, _ := tokenServer(t, "tok")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)

		// Only server context registered — no delegated
		sm := &entraServerMode{
			strategies: map[auth.ServerContext]FlowFn{
				auth.ServerContextServer: clientCredentialFlow(ts.URL, cred, client),
			},
			credential: cred,
			clientID:   "cid",
		}

		_, err := sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "scope",
			Caller:        auth.CallerMachine,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no strategy configured for context")
	})

	t.Run("machine delegation with WIF credential uses client_assertion", func(t *testing.T) {
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("wif-federated-jwt"), 0o600))

		ts, received := tokenServer(t, "wif-machine-token")
		defer ts.Close()

		cred := &WIFCredential{
			Token:               sdkplugin.SecretRef("file://" + tokenFile),
			ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		}
		client := newTestHTTPClient(ts)

		sm := &entraServerMode{
			strategies: map[auth.ServerContext]FlowFn{
				auth.ServerContextServer:    clientCredentialFlow(ts.URL, cred, client),
				auth.ServerContextDelegated: delegatedDispatch(nil, clientCredentialFlow(ts.URL, cred, client)),
			},
			credential: cred,
			clientID:   "wif-client",
		}

		resp, err := sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "api://downstream/.default",
			Caller:        auth.CallerMachine,
		})
		require.NoError(t, err)
		assert.Equal(t, "wif-machine-token", resp.AccessToken)
		assert.Equal(t, "client_credentials", received.Get("grant_type"))
		assert.Equal(t, "wif-federated-jwt", received.Get("client_assertion"))
		assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", received.Get("client_assertion_type"))
		// Should NOT have client_secret
		assert.Empty(t, received.Get("client_secret"))
	})

	t.Run("user non-OBO flow matching server sends CC grant", func(t *testing.T) {
		ts, received := tokenServer(t, "user-cc-token")
		defer ts.Close()

		cred := &SecretCredential{Secret: "cc-secret"}
		client := newTestHTTPClient(ts)

		// UserFlow = client_credentials (matches serverFlow), so user route is CC not OBO
		sm := &entraServerMode{
			strategies: map[auth.ServerContext]FlowFn{
				auth.ServerContextServer:    clientCredentialFlow(ts.URL, cred, client),
				auth.ServerContextDelegated: delegatedDispatch(clientCredentialFlow(ts.URL, cred, client), clientCredentialFlow(ts.URL, cred, client)),
			},
			credential: cred,
			clientID:   "my-client",
		}

		resp, err := sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "api://downstream/.default",
			Assertion:     "user-jwt",
			Caller:        auth.CallerUser,
		})
		require.NoError(t, err)
		assert.Equal(t, "user-cc-token", resp.AccessToken)
		// Should be CC grant, NOT OBO
		assert.Equal(t, "client_credentials", received.Get("grant_type"))
		assert.Empty(t, received.Get("assertion"))
		assert.Empty(t, received.Get("requested_token_use"))
		assert.Equal(t, "cc-secret", received.Get("client_secret"))
	})
}

func TestDelegatedDispatch(t *testing.T) {
	t.Run("routes user caller to user flow", func(t *testing.T) {
		ts, received := tokenServer(t, "user-token")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)
		dispatch := delegatedDispatch(oboFlow(ts.URL, cred, client), clientCredentialFlow(ts.URL, cred, client))

		resp, err := dispatch(context.Background(), FlowParams{
			assertion: "user-assertion",
			Scope:     "scope",
			ClientID:  "cid",
			Caller:    auth.CallerUser,
		})
		require.NoError(t, err)
		assert.Equal(t, "user-token", resp.AccessToken)
		assert.Equal(t, OBOGrantType, received.Get("grant_type"))
		assert.Equal(t, "user-assertion", received.Get("assertion"))
	})

	t.Run("routes machine caller to machine flow", func(t *testing.T) {
		ts, received := tokenServer(t, "machine-token")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)
		dispatch := delegatedDispatch(oboFlow(ts.URL, cred, client), clientCredentialFlow(ts.URL, cred, client))

		resp, err := dispatch(context.Background(), FlowParams{
			Scope:    "scope",
			ClientID: "cid",
			Caller:   auth.CallerMachine,
		})
		require.NoError(t, err)
		assert.Equal(t, "machine-token", resp.AccessToken)
		assert.Equal(t, "client_credentials", received.Get("grant_type"))
	})

	t.Run("error when user flow is nil", func(t *testing.T) {
		ts, _ := tokenServer(t, "tok")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)
		dispatch := delegatedDispatch(nil, clientCredentialFlow(ts.URL, cred, client))

		_, err := dispatch(context.Background(), FlowParams{
			Caller: auth.CallerUser,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delegated user flow not configured")
	})

	t.Run("error when machine flow is nil", func(t *testing.T) {
		ts, _ := tokenServer(t, "tok")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)
		dispatch := delegatedDispatch(oboFlow(ts.URL, cred, client), nil)

		_, err := dispatch(context.Background(), FlowParams{
			Caller: auth.CallerMachine,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delegated machine flow not configured")
	})

	t.Run("error on unsupported caller type", func(t *testing.T) {
		ts, _ := tokenServer(t, "tok")
		defer ts.Close()

		cred := &SecretCredential{Secret: "s"}
		client := newTestHTTPClient(ts)
		dispatch := delegatedDispatch(oboFlow(ts.URL, cred, client), clientCredentialFlow(ts.URL, cred, client))

		_, err := dispatch(context.Background(), FlowParams{
			Caller: "unknown",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported caller type for delegation")
	})
}

func TestServerConfigValidate(t *testing.T) {
	t.Run("missing clientId", func(t *testing.T) {
		sc := &ServerConfig{TenantID: "tid", ServerFlow: auth.FlowClientCredentials, Credential: CredentialConfig{ClientSecret: "env://SECRET"}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clientId is required")
	})

	t.Run("missing tenantId", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", ServerFlow: auth.FlowClientCredentials, Credential: CredentialConfig{ClientSecret: "env://SECRET"}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tenantId is required")
	})

	t.Run("missing serverFlow", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid", Credential: CredentialConfig{}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "serverFlow is required")
	})

	t.Run("disallowed serverFlow", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid", ServerFlow: auth.FlowDeviceCode}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not allowed")
	})

	t.Run("workload_identity missing wifToken", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid", ServerFlow: auth.FlowWorkloadIdentity}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.wifToken is required")
	})

	t.Run("workload_identity invalid scheme", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid", ServerFlow: auth.FlowWorkloadIdentity, Credential: CredentialConfig{WIFToken: "plain-value"}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.wifToken")
	})

	t.Run("client_credentials missing clientSecret", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid", ServerFlow: auth.FlowClientCredentials}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.clientSecret is required")
	})

	t.Run("client_credentials invalid scheme", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid", ServerFlow: auth.FlowClientCredentials, Credential: CredentialConfig{ClientSecret: "bare-value"}}
		err := sc.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credential.clientSecret")
	})

	t.Run("valid workload_identity config", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid", ServerFlow: auth.FlowWorkloadIdentity, Credential: CredentialConfig{WIFToken: "file:///var/run/token"}}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid client_credentials config", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid", ServerFlow: auth.FlowClientCredentials, Credential: CredentialConfig{ClientSecret: "env://SECRET"}}
		err := sc.Validate()
		assert.NoError(t, err)
	})

	t.Run("default authority", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid"}
		assert.Equal(t, DefaultAuthority, sc.GetAuthority())
	})

	t.Run("custom authority", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "tid", Authority: "https://custom.auth"}
		assert.Equal(t, "https://custom.auth", sc.GetAuthority())
	})

	t.Run("token URL", func(t *testing.T) {
		sc := &ServerConfig{ClientID: "cid", TenantID: "my-tenant"}
		assert.Equal(t, "https://login.microsoftonline.com/my-tenant/oauth2/v2.0/token", sc.TokenURL())
	})
}

func TestActivateServerMode(t *testing.T) {
	newCSServerConfig := func(t *testing.T) *ServerConfig {
		t.Helper()
		t.Setenv("TEST_CS", "my-client-secret")
		return &ServerConfig{
			ClientID:   "cid",
			TenantID:   "tid",
			ServerFlow: auth.FlowClientCredentials,
			Credential: CredentialConfig{
				ClientSecret: "env://TEST_CS",
			},
			Delegated: &DelegatedConfig{
				UserFlow: auth.FlowOnBehalfOf,
				Machine:  true,
			},
		}
	}

	newWIFServerConfig := func(t *testing.T) *ServerConfig {
		t.Helper()
		dir := t.TempDir()
		tokenFile := filepath.Join(dir, "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("federated-token"), 0o600))
		return &ServerConfig{
			ClientID:   "cid",
			TenantID:   "tid",
			ServerFlow: auth.FlowWorkloadIdentity,
			Credential: CredentialConfig{
				WIFToken: sdkplugin.SecretRef("file://" + tokenFile),
			},
			Delegated: &DelegatedConfig{
				UserFlow: auth.FlowOnBehalfOf,
				Machine:  true,
			},
		}
	}

	t.Run("succeeds with client_credentials and obo user flow", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newCSServerConfig(t)
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		assert.NotNil(t, p.mode)
	})

	t.Run("succeeds with wif credential", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newWIFServerConfig(t)
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		assert.NotNil(t, p.mode)
	})

	t.Run("resolves SecretCredential for client_credentials", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newCSServerConfig(t)
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		sm := p.mode.(*entraServerMode)
		_, ok := sm.credential.(*SecretCredential)
		assert.True(t, ok, "expected SecretCredential")
	})

	t.Run("resolves WIFCredential for workload_identity", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newWIFServerConfig(t)
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		sm := p.mode.(*entraServerMode)
		_, ok := sm.credential.(*WIFCredential)
		assert.True(t, ok, "expected WIFCredential")
	})

	t.Run("sets clientID and tenantID on entraServerMode", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newCSServerConfig(t)
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		sm := p.mode.(*entraServerMode)
		assert.Equal(t, "cid", sm.clientID)
		assert.Equal(t, "tid", sm.tenantID)
	})

	t.Run("registers server and delegated strategies", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newCSServerConfig(t)
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		sm := p.mode.(*entraServerMode)
		assert.Contains(t, sm.strategies, auth.ServerContextServer)
		assert.Contains(t, sm.strategies, auth.ServerContextDelegated)
	})

	t.Run("no delegated strategy when delegated is nil", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newCSServerConfig(t)
		sc.Delegated = nil
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		sm := p.mode.(*entraServerMode)
		assert.Contains(t, sm.strategies, auth.ServerContextServer)
		assert.NotContains(t, sm.strategies, auth.ServerContextDelegated)

		// GetToken must fail for CallerUser
		_, err = sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "scope",
			Assertion:     "user-jwt",
			Caller:        auth.CallerUser,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no strategy configured for context")

		// GetToken must fail for CallerMachine
		_, err = sm.GetToken(context.Background(), sdkplugin.TokenRequest{
			ServerContext: auth.ServerContextDelegated,
			Scope:         "scope",
			Caller:        auth.CallerMachine,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no strategy configured for context")
	})

	t.Run("user only delegation (no machine)", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newCSServerConfig(t)
		sc.Delegated = &DelegatedConfig{UserFlow: auth.FlowOnBehalfOf}
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		assert.NotNil(t, p.mode)
	})

	t.Run("machine only delegation (no user)", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newCSServerConfig(t)
		sc.Delegated = &DelegatedConfig{Machine: true}
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		assert.NotNil(t, p.mode)
	})

	t.Run("user flow matches server flow", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := newCSServerConfig(t)
		sc.Delegated = &DelegatedConfig{UserFlow: auth.FlowClientCredentials, Machine: true}
		err := p.activateServerMode(context.Background(), sc)
		require.NoError(t, err)
		assert.NotNil(t, p.mode)
	})

	t.Run("fails when client_secret env var is missing", func(t *testing.T) {
		t.Setenv("TEST_MISSING_CS", "")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		sc := &ServerConfig{
			ClientID:   "cid",
			TenantID:   "tid",
			ServerFlow: auth.FlowClientCredentials,
			Credential: CredentialConfig{
				ClientSecret: "env://TEST_MISSING_CS",
			},
		}
		err := p.activateServerMode(context.Background(), sc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolving server credential")
	})

	t.Run("ActivateServerMode via settings bytes", func(t *testing.T) {
		t.Setenv("TEST_CS2", "secret-val")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		settings := []byte(`{
			"clientId": "from-settings",
			"tenantId": "from-settings-tid",
			"serverFlow": "client_credentials",
			"credential": {"clientSecret": "env://TEST_CS2"},
			"delegated": {"userFlow": "obo", "machine": true}
		}`)
		err := p.ActivateServerMode(context.Background(), settings)
		require.NoError(t, err)
		sm := p.mode.(*entraServerMode)
		assert.Equal(t, "from-settings", sm.clientID)
		assert.Equal(t, "from-settings-tid", sm.tenantID)
	})

	t.Run("ActivateServerMode invalid JSON", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		err := p.ActivateServerMode(context.Background(), []byte(`{invalid}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse server config")
	})

	t.Run("ActivateServerMode validation failure", func(t *testing.T) {
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		err := p.ActivateServerMode(context.Background(), []byte(`{"clientId": "", "tenantId": "tid", "serverFlow": "client_credentials", "credential": {"clientSecret": "env://X"}}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clientId is required")
	})

	t.Run("ActivateServerMode delegated validation failure", func(t *testing.T) {
		t.Setenv("TEST_CS3", "val")
		p := &Plugin{config: DefaultConfig(), httpClient: NewMockHTTPClient()}
		err := p.ActivateServerMode(context.Background(), []byte(`{
			"clientId": "cid",
			"tenantId": "tid",
			"serverFlow": "client_credentials",
			"credential": {"clientSecret": "env://TEST_CS3"},
			"delegated": {"userFlow": "device_code"}
		}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not allowed")
	})
}

func TestValidateDelegatedFlow(t *testing.T) {
	serverFlow := auth.FlowClientCredentials

	t.Run("both empty", func(t *testing.T) {
		err := validateDelegatedFlow(&DelegatedConfig{}, serverFlow)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must enable at least one")
	})

	t.Run("userFlow not allowed", func(t *testing.T) {
		err := validateDelegatedFlow(&DelegatedConfig{UserFlow: auth.FlowDeviceCode}, serverFlow)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not allowed")
	})

	t.Run("userFlow does not match server and is not obo", func(t *testing.T) {
		err := validateDelegatedFlow(&DelegatedConfig{UserFlow: auth.FlowWorkloadIdentity}, serverFlow)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be")
		assert.Contains(t, err.Error(), "match serverFlow")
	})

	t.Run("valid obo only", func(t *testing.T) {
		err := validateDelegatedFlow(&DelegatedConfig{UserFlow: auth.FlowOnBehalfOf}, serverFlow)
		assert.NoError(t, err)
	})

	t.Run("valid user matches server flow", func(t *testing.T) {
		err := validateDelegatedFlow(&DelegatedConfig{UserFlow: auth.FlowClientCredentials}, serverFlow)
		assert.NoError(t, err)
	})

	t.Run("valid machine only", func(t *testing.T) {
		err := validateDelegatedFlow(&DelegatedConfig{Machine: true}, serverFlow)
		assert.NoError(t, err)
	})

	t.Run("valid obo + machine", func(t *testing.T) {
		err := validateDelegatedFlow(&DelegatedConfig{UserFlow: auth.FlowOnBehalfOf, Machine: true}, serverFlow)
		assert.NoError(t, err)
	})

	t.Run("wif server flow obo valid", func(t *testing.T) {
		err := validateDelegatedFlow(&DelegatedConfig{UserFlow: auth.FlowOnBehalfOf, Machine: true}, auth.FlowWorkloadIdentity)
		assert.NoError(t, err)
	})

	t.Run("wif server flow user matches", func(t *testing.T) {
		err := validateDelegatedFlow(&DelegatedConfig{UserFlow: auth.FlowWorkloadIdentity}, auth.FlowWorkloadIdentity)
		assert.NoError(t, err)
	})
}

func TestAllowedServerFlows(t *testing.T) {
	allowed := allowedServerFlows()
	assert.Contains(t, allowed, auth.FlowWorkloadIdentity)
	assert.Contains(t, allowed, auth.FlowClientCredentials)
	assert.NotContains(t, allowed, auth.FlowDeviceCode)
	assert.NotContains(t, allowed, auth.FlowInteractive)
	assert.NotContains(t, allowed, auth.FlowOnBehalfOf)
}

func TestAllowedUserFlows(t *testing.T) {
	allowed := allowedUserFlows()
	assert.Contains(t, allowed, auth.FlowOnBehalfOf)
	assert.Contains(t, allowed, auth.FlowClientCredentials)
	assert.Contains(t, allowed, auth.FlowWorkloadIdentity)
	assert.NotContains(t, allowed, auth.FlowDeviceCode)
	assert.NotContains(t, allowed, auth.FlowInteractive)
}
