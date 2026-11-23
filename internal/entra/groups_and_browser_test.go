// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oakwood-commons/httpc"
	"github.com/oakwood-commons/scafctl-plugin-auth-entra/internal/clock"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// startPluginAuthGRPCServer starts a real gRPC AuthHandlerServiceServer backed
// by p and returns a connected proto.AuthHandlerServiceClient.
func startPluginAuthGRPCServer(t *testing.T, p *Plugin) proto.AuthHandlerServiceClient {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	proto.RegisterAuthHandlerServiceServer(srv, &sdkplugin.AuthHandlerGRPCServer{Impl: p})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop() })

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return proto.NewAuthHandlerServiceClient(conn)
}

// storeProfileUserSession writes a canonical user session (refresh token +
// metadata) under profile in fake.
func storeProfileUserSession(t *testing.T, p *Plugin, fake *fakeHostService, profile string, flow auth.Flow, expiresAt time.Time, tenantID, clientID, refreshToken string) {
	t.Helper()
	ctx := auth.WithProfile(context.Background(), profile)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.secrets[p.secretKey(ctx, secretSuffixRefreshToken)] = refreshToken
	metadata := auth.HandlerMetadata{
		Claims: &auth.Claims{
			Subject:  "user-" + profile,
			ObjectID: "oid-" + profile,
			Name:     "User " + profile,
		},
		ExpiresAt:     expiresAt,
		LastRefresh:   time.Now(),
		LastLoginFlow: flow,
		SessionID:     "sess-" + profile,
		ClientID:      clientID,
		Scopes:        []string{"openid", "profile", "offline_access"},
	}
	metadata.SetMeta(MetaKeyTenantID, tenantID)
	raw, err := json.Marshal(metadata)
	require.NoError(t, err)
	fake.secrets[p.secretKey(ctx, secretSuffixMetadata)] = string(raw)
}

func TestGetGroups_GRPCRoundTripAndPrecedence(t *testing.T) {
	t.Run("satisfies sdkplugin.AuthGroupsProvider and serves paginated groups over gRPC", func(t *testing.T) {
		clearCredentialEnv(t)

		var impl sdkplugin.AuthHandlerPlugin = &Plugin{}
		_, implementsGroups := impl.(sdkplugin.AuthGroupsProvider)
		require.True(t, implementsGroups, "*Plugin must satisfy sdkplugin.AuthGroupsProvider")

		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "delegated-graph-token",
			RefreshToken: "user-rt-1",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        graphGroupsScope + " offline_access",
		})

		// Simulate >200 groups paginated across two Graph /me/memberOf pages.
		page1 := make([]graphGroupEntry, 150)
		for i := range page1 {
			page1[i] = graphGroupEntry{ID: fmt.Sprintf("grp-page1-%03d", i)}
		}
		page2 := make([]graphGroupEntry, 75)
		for i := range page2 {
			page2[i] = graphGroupEntry{ID: fmt.Sprintf("grp-page2-%03d", i)}
		}
		nextPageURL := "https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.group?$skiptoken=page2"

		graphMock := NewMockGraphClient()
		graphMock.AddResponse(http.StatusOK, graphGroupsPage{
			NextLink: nextPageURL,
			Value:    page1,
		})
		graphMock.AddResponse(http.StatusOK, graphGroupsPage{
			Value: append(page2, graphGroupEntry{ID: ""}), // empty IDs ignored cleanly
		})

		p, fake := newTestPlugin(t, httpMock, graphMock)
		storeProfileUserSession(t, p, fake, "corp", auth.FlowInteractive, time.Now().Add(24*time.Hour), "corp-tenant", "corp-client", "user-rt-1")

		grpcClient := startPluginAuthGRPCServer(t, p)
		resp, err := grpcClient.GetGroups(context.Background(), &proto.GetGroupsRequest{
			HandlerName: HandlerName,
			Profile:     "corp",
			Settings:    []byte(`{"authority":"https://login.microsoftonline.us","tenantId":"corp-tenant","clientId":"corp-client"}`),
		})
		require.NoError(t, err)
		assert.Empty(t, resp.GetError())
		require.Len(t, resp.GetGroups(), 225)
		assert.Equal(t, "grp-page1-000", resp.GetGroups()[0])
		assert.Equal(t, "grp-page2-074", resp.GetGroups()[224])

		// Token refresh honored both the "corp" profile secret keys and the
		// per-RPC sovereign cloud authority from GetGroupsRequest.Settings.
		tokenReqs := httpMock.GetRequests()
		require.Len(t, tokenReqs, 1)
		assert.Equal(t, "https://login.microsoftonline.us/corp-tenant/oauth2/v2.0/token", tokenReqs[0].Endpoint)
		assert.Equal(t, "refresh_token", tokenReqs[0].Data.Get("grant_type"))
		assert.Equal(t, "user-rt-1", tokenReqs[0].Data.Get("refresh_token"))

		require.Len(t, graphMock.Requests, 2)
		assert.Equal(t, graphGroupsMemberOfURL, graphMock.Requests[0].URL)
		assert.Equal(t, nextPageURL, graphMock.Requests[1].URL)
		assert.Equal(t, "delegated-graph-token", graphMock.Requests[0].BearerToken)
	})

	t.Run("stored interactive user session succeeds even when ambient AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are set", func(t *testing.T) {
		clearCredentialEnv(t)
		setServicePrincipalEnv(t)

		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "user-graph-token",
			RefreshToken: "stored-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        graphGroupsScope + " offline_access",
		})
		graphMock := NewMockGraphClient()
		graphMock.AddResponse(http.StatusOK, graphGroupsPage{
			Value: []graphGroupEntry{{ID: "grp-alpha"}, {ID: "grp-beta"}},
		})

		p, fake := newTestPlugin(t, httpMock, graphMock)
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))

		grpcClient := startPluginAuthGRPCServer(t, p)
		resp, err := grpcClient.GetGroups(context.Background(), &proto.GetGroupsRequest{
			HandlerName: HandlerName,
		})
		require.NoError(t, err)
		assert.Empty(t, resp.GetError())
		assert.Equal(t, []string{"grp-alpha", "grp-beta"}, resp.GetGroups())

		tokenReqs := httpMock.GetRequests()
		require.Len(t, tokenReqs, 1)
		assert.Equal(t, "refresh_token", tokenReqs[0].Data.Get("grant_type"), "must mint user token rather than SP client_credentials")
	})

	t.Run("stored device_code user session succeeds even when ambient workload identity credentials are set", func(t *testing.T) {
		clearCredentialEnv(t)
		setWorkloadIdentityEnv(t)

		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "device-user-graph-token",
			RefreshToken: "stored-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        graphGroupsScope + " offline_access",
		})
		graphMock := NewMockGraphClient()
		graphMock.AddResponse(http.StatusOK, graphGroupsPage{
			Value: []graphGroupEntry{{ID: "grp-wi-override"}},
		})

		p, fake := newTestPlugin(t, httpMock, graphMock)
		storeUserSession(t, fake, auth.FlowDeviceCode, time.Now().Add(24*time.Hour))

		groups, err := p.GetGroups(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.Equal(t, []string{"grp-wi-override"}, groups)

		tokenReqs := httpMock.GetRequests()
		require.Len(t, tokenReqs, 1)
		assert.Equal(t, "refresh_token", tokenReqs[0].Data.Get("grant_type"))
	})

	t.Run("rejects service principal and workload identity when no valid user session is stored", func(t *testing.T) {
		t.Run("ambient service principal only", func(t *testing.T) {
			clearCredentialEnv(t)
			setServicePrincipalEnv(t)
			p, _ := newTestPlugin(t, nil, nil)

			grpcClient := startPluginAuthGRPCServer(t, p)
			resp, err := grpcClient.GetGroups(context.Background(), &proto.GetGroupsRequest{HandlerName: HandlerName})
			require.NoError(t, err)
			assert.Empty(t, resp.GetGroups())
			assert.Contains(t, resp.GetError(), "service principal")
		})

		t.Run("ambient workload identity only", func(t *testing.T) {
			clearCredentialEnv(t)
			setWorkloadIdentityEnv(t)
			p, _ := newTestPlugin(t, nil, nil)

			grpcClient := startPluginAuthGRPCServer(t, p)
			resp, err := grpcClient.GetGroups(context.Background(), &proto.GetGroupsRequest{HandlerName: HandlerName})
			require.NoError(t, err)
			assert.Empty(t, resp.GetGroups())
			assert.Contains(t, resp.GetError(), "workload identity")
		})

		t.Run("expired user session with ambient SP env is rejected", func(t *testing.T) {
			clearCredentialEnv(t)
			setServicePrincipalEnv(t)
			p, fake := newTestPlugin(t, nil, nil)
			storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(-1*time.Hour))

			_, err := p.GetGroups(context.Background(), HandlerName)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "service principal")
		})

		t.Run("stored session created with non-user flow is rejected without env vars", func(t *testing.T) {
			clearCredentialEnv(t)
			p, fake := newTestPlugin(t, nil, nil)
			storeUserSession(t, fake, auth.FlowServicePrincipal, time.Now().Add(24*time.Hour))

			_, err := p.GetGroups(context.Background(), HandlerName)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "service principal")

			storeUserSession(t, fake, auth.FlowWorkloadIdentity, time.Now().Add(24*time.Hour))
			_, err = p.GetGroups(context.Background(), HandlerName)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "workload identity")
		})

		t.Run("logout clears user session and restores SP rejection", func(t *testing.T) {
			clearCredentialEnv(t)
			setServicePrincipalEnv(t)
			p, fake := newTestPlugin(t, nil, nil)
			storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))

			require.NoError(t, p.Logout(context.Background(), HandlerName, sdkplugin.LogoutRequest{}))

			_, err := p.GetGroups(context.Background(), HandlerName)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "service principal")
		})
	})

	t.Run("profile and per-RPC settings isolation under concurrent -race calls", func(t *testing.T) {
		clearCredentialEnv(t)

		httpMock := NewMockHTTPClient()
		graphMock := NewMockGraphClient()
		p, fake := newTestPlugin(t, httpMock, graphMock)

		// Pre-populate profile-scoped sessions and cached user Graph tokens for
		// "work" (US Gov authority) and "personal" (public cloud authority), while
		// "ci" has no user session and receives SP credentials via per-RPC Settings.
		storeProfileUserSession(t, p, fake, "work", auth.FlowInteractive, time.Now().Add(24*time.Hour), "work-tid", "work-cid", "work-rt")
		storeProfileUserSession(t, p, fake, "personal", auth.FlowDeviceCode, time.Now().Add(24*time.Hour), "personal-tid", "personal-cid", "personal-rt")

		workCfg, err := parseHandlerConfig([]byte(`{"authority":"https://login.microsoftonline.us","tenantId":"work-tid","clientId":"work-cid"}`))
		require.NoError(t, err)
		personalCfg, err := parseHandlerConfig([]byte(`{"authority":"https://login.microsoftonline.com","tenantId":"personal-tid","clientId":"personal-cid"}`))
		require.NoError(t, err)

		ctxWork := auth.WithProfile(context.Background(), "work")
		ctxPersonal := auth.WithProfile(context.Background(), "personal")

		workMeta := &auth.HandlerMetadata{
			Claims:    &auth.Claims{ObjectID: "oid-work"},
			SessionID: "sess-work",
			ClientID:  "work-cid",
		}
		workMeta.SetMeta(MetaKeyTenantID, "work-tid")
		fake.secrets[p.tokenCachePrefix(ctxWork)+p.userSessionFingerprintWithConfig(workCfg, workMeta)+":"+graphGroupsScope] = cacheEntryJSON(t, "tok-work")

		personalMeta := &auth.HandlerMetadata{
			Claims:    &auth.Claims{ObjectID: "oid-personal"},
			SessionID: "sess-personal",
			ClientID:  "personal-cid",
		}
		personalMeta.SetMeta(MetaKeyTenantID, "personal-tid")
		fake.secrets[p.tokenCachePrefix(ctxPersonal)+p.userSessionFingerprintWithConfig(personalCfg, personalMeta)+":"+graphGroupsScope] = cacheEntryJSON(t, "tok-personal")

		// Graph mock dispatches deterministically by bearer token for concurrent calls.
		p.graphClient = &tokenRoutingGraphClient{
			groupsByToken: map[string][]string{
				"tok-work":     {"grp-work-1", "grp-work-2"},
				"tok-personal": {"grp-personal-1"},
			},
		}

		grpcClient := startPluginAuthGRPCServer(t, p)

		const workers = 8
		var wg sync.WaitGroup
		for range workers {
			wg.Add(3)
			go func() {
				defer wg.Done()
				resp, rpcErr := grpcClient.GetGroups(context.Background(), &proto.GetGroupsRequest{
					HandlerName: HandlerName,
					Profile:     "work",
					Settings:    []byte(`{"authority":"https://login.microsoftonline.us","tenantId":"work-tid","clientId":"work-cid"}`),
				})
				assert.NoError(t, rpcErr)
				assert.Empty(t, resp.GetError())
				assert.Equal(t, []string{"grp-work-1", "grp-work-2"}, resp.GetGroups())
			}()
			go func() {
				defer wg.Done()
				resp, rpcErr := grpcClient.GetGroups(context.Background(), &proto.GetGroupsRequest{
					HandlerName: HandlerName,
					Profile:     "personal",
					Settings:    []byte(`{"authority":"https://login.microsoftonline.com","tenantId":"personal-tid","clientId":"personal-cid"}`),
				})
				assert.NoError(t, rpcErr)
				assert.Empty(t, resp.GetError())
				assert.Equal(t, []string{"grp-personal-1"}, resp.GetGroups())
			}()
			go func() {
				defer wg.Done()
				resp, rpcErr := grpcClient.GetGroups(context.Background(), &proto.GetGroupsRequest{
					HandlerName: HandlerName,
					Profile:     "ci",
					Settings:    []byte(`{"clientId":"ci-sp","tenantId":"ci-tid","clientSecret":"ci-secret"}`),
				})
				assert.NoError(t, rpcErr)
				assert.Empty(t, resp.GetGroups())
				assert.Contains(t, resp.GetError(), "service principal")
			}()
		}
		wg.Wait()
	})

	t.Run("error cases: unknown handler, unconfigured, server mode, non-200 HTTP, invalid JSON, invalid settings", func(t *testing.T) {
		clearCredentialEnv(t)

		// Unconfigured plugin
		unconfigured := &Plugin{}
		_, err := unconfigured.GetGroups(context.Background(), HandlerName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")

		// Unknown handler
		p, fake := newTestPlugin(t, nil, nil)
		_, err = p.GetGroups(context.Background(), "other")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown handler")

		// Non-200 Graph HTTP status
		storeUserSession(t, fake, auth.FlowInteractive, time.Now().Add(24*time.Hour))
		fake.secrets[userTokenCacheKey(p, "sess-1", graphGroupsScope)] = cacheEntryJSON(t, "tok-1")
		p.graphClient = NewMockGraphClient().AddResponse(http.StatusForbidden, map[string]string{"error": "insufficient_privileges"})
		_, err = p.GetGroups(context.Background(), HandlerName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 403")

		// Invalid Graph JSON response
		p.graphClient = &staticBodyGraphClient{status: http.StatusOK, body: "{not-json"}
		_, err = p.GetGroups(context.Background(), HandlerName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse Graph memberOf response")

		// Invalid per-RPC authority in settings
		badSettingsCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			"authority": json.RawMessage(`"http://insecure.example.com"`),
		})
		_, err = p.GetGroups(badSettingsCtx, HandlerName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https://")

		// Invalid per-RPC httpClient in settings
		badHTTPSettingsCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			"httpClient": json.RawMessage(`{"timeout":"not-a-duration"}`),
		})
		_, err = p.GetGroups(badHTTPSettingsCtx, HandlerName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "httpClient config")

		// Server mode rejects GetGroups cleanly
		t.Setenv("TEST_SERVER_SECRET", "s3cr3t")
		serverPlugin := &Plugin{}
		require.NoError(t, serverPlugin.ActivateServerMode(context.Background(), json.RawMessage(`{
			"clientId": "srv-client",
			"tenantId": "srv-tenant",
			"serverFlow": "client_credentials",
			"credential": {"clientSecret": "env://TEST_SERVER_SECRET"}
		}`)))
		t.Cleanup(func() { _ = serverPlugin.StopAuthHandler(context.Background(), HandlerName) })

		_, err = serverPlugin.GetGroups(context.Background(), HandlerName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported in server mode")
	})
}

type tokenRoutingGraphClient struct {
	groupsByToken map[string][]string
}

func (c *tokenRoutingGraphClient) Get(_ context.Context, _, bearerToken string) (*http.Response, error) {
	ids, ok := c.groupsByToken[bearerToken]
	if !ok {
		return jsonTestResponse(http.StatusUnauthorized, map[string]string{"error": "unexpected token"}), nil
	}
	entries := make([]graphGroupEntry, len(ids))
	for i, id := range ids {
		entries[i] = graphGroupEntry{ID: id}
	}
	return jsonTestResponse(http.StatusOK, graphGroupsPage{Value: entries}), nil
}

type staticBodyGraphClient struct {
	status int
	body   string
}

func (c *staticBodyGraphClient) Get(_ context.Context, _, _ string) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.status,
		Body:       io.NopCloser(strings.NewReader(c.body)),
	}, nil
}

func TestInteractiveLogin_BrowserPreference(t *testing.T) {
	t.Run("forwards LoginRequest.Browser over gRPC and preserves empty default", func(t *testing.T) {
		clearCredentialEnv(t)

		for _, wantBrowser := range []string{"msedge", "chrome", ""} {
			t.Run("browser="+wantBrowser, func(t *testing.T) {
				httpMock := pasteTokenResponse()
				p, _ := newTestPlugin(t, httpMock, nil)
				p.headlessReason = func() string { return "" }

				var gotBrowser string
				p.openBrowser = func(ctx context.Context, authURL string) error {
					gotBrowser = browserPreferenceFromContext(ctx)
					completeLoopbackCallback(t, authURL, "BROWSER-PREF-CODE")
					return nil
				}

				grpcClient := startPluginAuthGRPCServer(t, p)
				stream, err := grpcClient.Login(context.Background(), &proto.LoginRequest{
					HandlerName: HandlerName,
					Flow:        string(auth.FlowInteractive),
					Browser:     wantBrowser,
				})
				require.NoError(t, err)

				var gotResult *proto.LoginResult
				for {
					msg, recvErr := stream.Recv()
					if errors.Is(recvErr, io.EOF) {
						break
					}
					require.NoError(t, recvErr)
					require.Empty(t, msg.GetError())
					if r := msg.GetResult(); r != nil {
						gotResult = r
					}
				}
				require.NotNil(t, gotResult)
				assert.Equal(t, "paste-subject", gotResult.GetClaims().GetSubject())
				assert.Equal(t, wantBrowser, gotBrowser)
			})
		}
	})

	t.Run("defaultBrowserOpener launches configured browser executable via oauth.OpenBrowserWithPreference", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX shell script browser stub requires unix-like OS")
		}
		clearCredentialEnv(t)

		tmpDir := t.TempDir()
		urlCaptureFile := filepath.Join(tmpDir, "opened-url.txt")
		fakeBrowserScript := filepath.Join(tmpDir, "fake-edge")
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$1\" > %q\n", urlCaptureFile)
		require.NoError(t, os.WriteFile(fakeBrowserScript, []byte(script), 0o755)) //nolint:gosec // executable test stub

		httpMock := pasteTokenResponse()
		p, _ := newTestPlugin(t, httpMock, nil)
		p.headlessReason = func() string { return "" }
		// Keep production defaultBrowserOpener untouched so Login exercises
		// oauth.OpenBrowserWithPreference end-to-end.

		loginDone := make(chan error, 1)
		go func() {
			_, loginErr := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow:    auth.FlowInteractive,
				Browser: fakeBrowserScript,
				Timeout: 10 * time.Second,
			}, nil)
			loginDone <- loginErr
		}()

		var launchedURL string
		require.Eventually(t, func() bool {
			b, err := os.ReadFile(urlCaptureFile) //nolint:gosec // test temp file
			if err != nil || len(b) == 0 {
				return false
			}
			launchedURL = string(b)
			return true
		}, 5*time.Second, 20*time.Millisecond, "configured browser executable must receive authorization URL")

		completeLoopbackCallback(t, launchedURL, "REAL-OPENER-CODE")
		require.NoError(t, <-loginDone)
	})

	t.Run("defaultBrowserOpener logs warning via logr and falls back to system default when preferred browser fails", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("xdg-open PATH stub is linux-specific")
		}

		tmpDir := t.TempDir()
		fallbackFile := filepath.Join(tmpDir, "fallback-url.txt")
		fakeXdgOpen := filepath.Join(tmpDir, "xdg-open")
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$1\" > %q\n", fallbackFile)
		require.NoError(t, os.WriteFile(fakeXdgOpen, []byte(script), 0o755)) //nolint:gosec // executable test stub
		t.Setenv("PATH", tmpDir)

		ctx, logLines := capturingLogger()
		targetURL := "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=test"
		err := defaultBrowserOpener(withBrowserPreference(ctx, filepath.Join(tmpDir, "missing-browser")), targetURL)
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			b, readErr := os.ReadFile(fallbackFile) //nolint:gosec // test temp file
			return readErr == nil && string(b) == targetURL
		}, 3*time.Second, 20*time.Millisecond, "xdg-open fallback must receive URL")

		joined := strings.Join(*logLines, "\n")
		assert.Contains(t, joined, "falling back to system default browser")
	})
}

func TestPerRPCRequestSettings_AllRPCsAndClientIsolation(t *testing.T) {
	t.Run("effectiveConfig supports nested handler key, null, and rejects malformed nested values", func(t *testing.T) {
		p, _ := newTestPlugin(t, nil, nil)

		nestedCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			HandlerName: json.RawMessage(`{"clientId":"nested-cid","tenantId":"nested-tid","authority":"https://login.microsoftonline.us"}`),
		})
		cfg, err := p.effectiveConfig(nestedCtx)
		require.NoError(t, err)
		assert.Equal(t, "nested-cid", cfg.ClientID)
		assert.Equal(t, "nested-tid", cfg.TenantID)
		assert.Equal(t, "https://login.microsoftonline.us", cfg.GetAuthority())
		assert.Equal(t, DefaultClientID, p.config.ClientID, "p.config must never be mutated")

		nullCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			HandlerName: json.RawMessage(`null`),
		})
		nullCfg, err := p.effectiveConfig(nullCtx)
		require.NoError(t, err)
		assert.Equal(t, DefaultClientID, nullCfg.ClientID)
		assert.Equal(t, DefaultTenantID, nullCfg.TenantID)

		for _, badVal := range []string{`"bad-string"`, `123`, `[]`} {
			badCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
				HandlerName: json.RawMessage(badVal),
			})
			_, err := p.effectiveConfig(badCtx)
			require.Error(t, err, "malformed nested settings %s must fail fast", badVal)
			assert.Contains(t, err.Error(), "failed to parse handler config")
		}
	})

	t.Run("GetStatus, GetToken, DetectAvailableFlows, and Login honor per-RPC Settings without mutating p.config", func(t *testing.T) {
		clearCredentialEnv(t)

		httpMock := NewMockHTTPClient()
		p, fake := newTestPlugin(t, httpMock, nil)
		p.clock = clock.Mock{}
		p.headlessReason = func() string { return "" }

		origClientID := p.config.ClientID
		origTenantID := p.config.TenantID
		origAuthority := p.config.GetAuthority()

		// 1. GetStatus with SP settings on StatusRequest.Settings (no prior WithRequestSettings).
		spSettings := map[string]json.RawMessage{
			"clientId":     json.RawMessage(`"sp-req-client"`),
			"tenantId":     json.RawMessage(`"sp-req-tenant"`),
			"clientSecret": json.RawMessage(`"sp-req-secret"`),
		}
		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{Settings: spSettings})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)
		assert.Equal(t, auth.IdentityTypeServicePrincipal, st.IdentityType)
		assert.Equal(t, "sp-req-client", st.ClientID)
		assert.Equal(t, "sp-req-tenant", st.TenantID)

		// 2. GetStatus with WI settings on StatusRequest.Settings.
		wiSettings := map[string]json.RawMessage{
			"clientId":       json.RawMessage(`"wi-req-client"`),
			"tenantId":       json.RawMessage(`"wi-req-tenant"`),
			"federatedToken": json.RawMessage(`"wi-req-token"`),
		}
		stWI, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{Settings: wiSettings})
		require.NoError(t, err)
		assert.True(t, stWI.Authenticated)
		assert.Equal(t, auth.IdentityTypeWorkloadIdentity, stWI.IdentityType)
		assert.Equal(t, "wi-req-client", stWI.ClientID)

		// Invalid settings on GetStatus fail fast.
		_, err = p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{
			Settings: map[string]json.RawMessage{"authority": json.RawMessage(`"http://bad.example.com"`)},
		})
		require.Error(t, err)

		// 3. DetectAvailableFlows honors defaultFlow, SP config, and missing federatedTokenFile config diagnostic.
		detectSPCtx := sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			"clientId":           json.RawMessage(`"det-client"`),
			"tenantId":           json.RawMessage(`"det-tenant"`),
			"clientSecret":       json.RawMessage(`"det-secret"`),
			"defaultFlow":        json.RawMessage(`"device_code"`),
			"federatedTokenFile": json.RawMessage(`"/nonexistent/per-rpc-wif-token"`),
		})
		flows, err := p.DetectAvailableFlows(detectSPCtx, HandlerName)
		require.NoError(t, err)
		require.Len(t, flows, 4)
		assert.False(t, flows[0].Available)
		assert.Contains(t, flows[0].Reason, "federatedTokenFile (config)")
		assert.True(t, flows[1].Available)
		assert.Equal(t, auth.FlowDeviceCode, flows[2].Flow, "defaultFlow: device_code in per-RPC settings must order device_code ahead of interactive")

		_, err = p.DetectAvailableFlows(sdkplugin.WithRequestSettings(context.Background(), map[string]json.RawMessage{
			"authority": json.RawMessage(`"http://bad.example.com"`),
		}), HandlerName)
		require.Error(t, err)

		// 4. GetToken honors SP and WI per-RPC Settings (including sovereign authority).
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "sp-gov-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		tokSP, err := p.GetToken(auth.WithProfile(context.Background(), "sp-prof"), HandlerName, sdkplugin.TokenRequest{
			Scope: "https://graph.microsoft.com/.default",
			Settings: map[string]json.RawMessage{
				"authority":    json.RawMessage(`"https://login.microsoftonline.us"`),
				"clientId":     json.RawMessage(`"sp-gov-cid"`),
				"tenantId":     json.RawMessage(`"sp-gov-tid"`),
				"clientSecret": json.RawMessage(`"sp-gov-sec"`),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "sp-gov-at", tokSP.AccessToken)
		assert.Equal(t, "https://login.microsoftonline.us/sp-gov-tid/oauth2/v2.0/token", httpMock.GetRequests()[0].Endpoint)

		httpMock.Reset()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "wi-gov-at",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
		tokWI, err := p.GetToken(auth.WithProfile(context.Background(), "wi-prof"), HandlerName, sdkplugin.TokenRequest{
			Scope: "https://management.azure.com/.default",
			Settings: map[string]json.RawMessage{
				"authority":      json.RawMessage(`"https://login.microsoftonline.us"`),
				"clientId":       json.RawMessage(`"wi-gov-cid"`),
				"tenantId":       json.RawMessage(`"wi-gov-tid"`),
				"federatedToken": json.RawMessage(`"wi-gov-assertion"`),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "wi-gov-at", tokWI.AccessToken)
		assert.Equal(t, "https://login.microsoftonline.us/wi-gov-tid/oauth2/v2.0/token", httpMock.GetRequests()[0].Endpoint)

		// Invalid httpClient in TokenRequest.Settings fails fast.
		_, err = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope: "https://graph.microsoft.com/.default",
			Settings: map[string]json.RawMessage{
				"clientId":     json.RawMessage(`"sp-cid"`),
				"tenantId":     json.RawMessage(`"sp-tid"`),
				"clientSecret": json.RawMessage(`"sp-sec"`),
				"httpClient":   json.RawMessage(`{"timeout":"bad-duration"}`),
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "httpClient config")

		// 5. Login (SP, WI, device_code, interactive) honors LoginRequest.Settings.
		httpMock.Reset()
		httpMock.AddResponse(http.StatusOK, TokenResponse{AccessToken: "sp-login-at", TokenType: "Bearer", ExpiresIn: 3600})
		spLoginResp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Settings: spSettings, // auto-detects SP from per-RPC settings
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, "sp-req-client", spLoginResp.Claims.Subject)

		httpMock.Reset()
		httpMock.AddResponse(http.StatusOK, TokenResponse{AccessToken: "wi-login-at", TokenType: "Bearer", ExpiresIn: 3600})
		wiLoginResp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Settings: wiSettings, // auto-detects WI from per-RPC settings
		}, nil)
		require.NoError(t, err)
		assert.Equal(t, "wi-req-client", wiLoginResp.Claims.Subject)

		httpMock.Reset()
		httpMock.AddResponse(http.StatusOK, DeviceCodeResponse{
			DeviceCode: "dc-settings", UserCode: "UC-1", VerificationURI: "https://microsoft.com/devicelogin",
			ExpiresIn: 900, Interval: 5,
		})
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "dc-at",
			RefreshToken: "dc-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestJWT(map[string]any{"sub": "dc-sub", "tid": "dc-tid"}),
		})
		ctxDevProfile := auth.WithProfile(context.Background(), "dev-dc")
		_, err = p.Login(ctxDevProfile, HandlerName, sdkplugin.LoginRequest{
			Settings: map[string]json.RawMessage{
				"authority":     json.RawMessage(`"https://login.microsoftonline.us"`),
				"clientId":      json.RawMessage(`"dc-client"`),
				"tenantId":      json.RawMessage(`"dc-tenant"`),
				"defaultFlow":   json.RawMessage(`"device_code"`),
				"defaultScopes": json.RawMessage(`["api://custom/.default"]`),
			},
			Timeout: 30 * time.Second,
		}, nil)
		require.NoError(t, err)
		dcReqs := httpMock.GetRequests()
		require.Len(t, dcReqs, 2)
		assert.Equal(t, "https://login.microsoftonline.us/dc-tenant/oauth2/v2.0/devicecode", dcReqs[0].Endpoint)
		assert.Equal(t, "dc-client", dcReqs[0].Data.Get("client_id"))
		assert.Contains(t, dcReqs[0].Data.Get("scope"), "api://custom/.default")
		assert.Equal(t, "dc-rt", fake.secrets[p.secretKey(ctxDevProfile, secretSuffixRefreshToken)])

		// Interactive Login with LoginRequest.Settings
		httpMock.Reset()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "int-at",
			RefreshToken: "int-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      makeTestJWT(map[string]any{"sub": "int-sub", "tid": "int-tid"}),
		})
		var gotAuthURL string
		p.openBrowser = func(_ context.Context, authURL string) error {
			gotAuthURL = authURL
			completeLoopbackCallback(t, authURL, "INT-SETTINGS-CODE")
			return nil
		}
		ctxIntProfile := auth.WithProfile(context.Background(), "int-prof")
		_, err = p.Login(ctxIntProfile, HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
			Settings: map[string]json.RawMessage{
				"authority":     json.RawMessage(`"https://login.microsoftonline.us"`),
				"clientId":      json.RawMessage(`"int-client"`),
				"tenantId":      json.RawMessage(`"int-tenant"`),
				"defaultScopes": json.RawMessage(`["api://interactive/.default"]`),
			},
		}, nil)
		require.NoError(t, err)
		parsedAuthURL, err := url.Parse(gotAuthURL)
		require.NoError(t, err)
		assert.Equal(t, "login.microsoftonline.us", parsedAuthURL.Host)
		assert.Equal(t, "/int-tenant/oauth2/v2.0/authorize", parsedAuthURL.Path)
		assert.Equal(t, "int-client", parsedAuthURL.Query().Get("client_id"))
		assert.Contains(t, parsedAuthURL.Query().Get("scope"), "api://interactive/.default")

		// Base plugin config must remain completely untouched after all per-RPC overrides.
		assert.Equal(t, origClientID, p.config.ClientID)
		assert.Equal(t, origTenantID, p.config.TenantID)
		assert.Equal(t, origAuthority, p.config.GetAuthority())
		assert.Empty(t, p.config.ClientSecret)
		assert.Empty(t, p.config.FederatedToken)
	})

	t.Run("httpClientForConfig and graphClientForConfig isolate init-time httpClient from per-RPC profiles omitting httpClient", func(t *testing.T) {
		p := &Plugin{}
		// Configure initial profile with an ultra-restrictive 1ns timeout on DefaultHTTPClient/DefaultGraphClient.
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
			Settings: map[string]json.RawMessage{
				HandlerName: json.RawMessage(`{"httpClient":{"timeout":"1ns","retryMax":0}}`),
			},
		}))
		t.Cleanup(func() { _ = p.StopAuthHandler(context.Background(), HandlerName) })
		initHTTPClient := p.httpClient
		initGraphClient := p.graphClient

		// Same httpClient config reuses the initialized clients without rebuilding.
		sameCfg, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"1ns","retryMax":0}}`))
		require.NoError(t, err)
		gotHTTP, err := p.httpClientForConfig(context.Background(), sameCfg)
		require.NoError(t, err)
		assert.Same(t, initHTTPClient, gotHTTP)
		gotGraph, err := p.graphClientForConfig(context.Background(), sameCfg)
		require.NoError(t, err)
		assert.Same(t, initGraphClient, gotGraph)

		// A per-RPC config omitting httpClient (cfg.HTTPClient == nil) must NOT
		// inherit the initial profile's 1ns timeout; it builds clean default clients
		// and reuses those cached instances across subsequent calls.
		cleanCfg, err := parseHandlerConfig([]byte(`{"tenantId":"other-tenant"}`))
		require.NoError(t, err)
		cleanHTTP, err := p.httpClientForConfig(context.Background(), cleanCfg)
		require.NoError(t, err)
		assert.NotSame(t, initHTTPClient, cleanHTTP)
		cleanHTTP2, err := p.httpClientForConfig(context.Background(), cleanCfg)
		require.NoError(t, err)
		assert.Same(t, cleanHTTP, cleanHTTP2, "repeated calls with identical effective httpClient config must reuse the cached HTTPClient")

		cleanGraph, err := p.graphClientForConfig(context.Background(), cleanCfg)
		require.NoError(t, err)
		assert.NotSame(t, initGraphClient, cleanGraph)
		cleanGraph2, err := p.graphClientForConfig(context.Background(), cleanCfg)
		require.NoError(t, err)
		assert.Same(t, cleanGraph, cleanGraph2, "repeated calls with identical effective httpClient config must reuse the cached GraphClient")

		// Verify a per-RPC Graph client succeeds against a real HTTP test server
		// while reusing a single keep-alive TCP connection across repeated calls.
		var newConns atomic.Int32
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(5 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"value":[{"id":"g1"}]}`))
		}))
		ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				newConns.Add(1)
			}
		}
		ts.Start()
		defer ts.Close()

		// Semantically equivalent durations ("5s" vs "5000ms") resolve to the same cache entry.
		loopbackCfgA, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"5s","allowPrivateIPs":true}}`))
		require.NoError(t, err)
		loopbackCfgB, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"5000ms","allowPrivateIPs":true,"enableCache":false}}`))
		require.NoError(t, err)
		loopbackGraphA, err := p.graphClientForConfig(context.Background(), loopbackCfgA)
		require.NoError(t, err)
		loopbackGraphB, err := p.graphClientForConfig(context.Background(), loopbackCfgB)
		require.NoError(t, err)
		assert.Same(t, loopbackGraphA, loopbackGraphB)

		for range 4 {
			resp, reqErr := loopbackGraphA.Get(context.Background(), ts.URL, "bearer-test")
			require.NoError(t, reqErr)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}
		assert.Equal(t, int32(1), newConns.Load(), "cached per-RPC GraphClient must reuse keep-alive connections across calls")
	})

	t.Run("per-RPC HTTP and Graph client caches preserve circuit breaker state across RPCs, isolate distinct configs, and close idle connections on LRU eviction and shutdown", func(t *testing.T) {
		clearCredentialEnv(t)

		// 1. Circuit breaker state persists across repeated RPCs sharing custom per-RPC httpClient settings.
		var plainHits atomic.Int32
		plainFailingTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			plainHits.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
		}))
		defer plainFailingTS.Close()

		p := &Plugin{clientCacheSize: 2}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
		}))

		cbCfgJSON := `{"httpClient":{"timeout":"2s","retryMax":1,"retryWaitMin":"1ms","retryWaitMax":"2ms","allowPrivateIPs":true,"enableCircuitBreaker":true,"circuitBreakerMaxFailures":2,"circuitBreakerOpenTimeout":"1m"}}`
		cbCfg1, err := parseHandlerConfig([]byte(cbCfgJSON))
		require.NoError(t, err)
		cbCfg2, err := parseHandlerConfig([]byte(cbCfgJSON))
		require.NoError(t, err)

		// Call #1 and #2 build separate *Config instances (simulating two separate RPCs)
		// that resolve to the SAME cached *DefaultHTTPClient, accumulating 2 failures to open the breaker.
		hc1, err := p.httpClientForConfig(context.Background(), cbCfg1)
		require.NoError(t, err)
		resp1, err1 := hc1.PostForm(context.Background(), plainFailingTS.URL, url.Values{"grant_type": {"client_credentials"}})
		if resp1 != nil {
			_ = resp1.Body.Close()
		}
		require.Error(t, err1)

		hc2, err := p.httpClientForConfig(context.Background(), cbCfg2)
		require.NoError(t, err)
		assert.Same(t, hc1, hc2)
		resp2, err2 := hc2.PostForm(context.Background(), plainFailingTS.URL, url.Values{"grant_type": {"client_credentials"}})
		if resp2 != nil {
			_ = resp2.Body.Close()
		}
		require.Error(t, err2)
		hitsBeforeOpen := plainHits.Load()
		assert.GreaterOrEqual(t, hitsBeforeOpen, int32(2))

		// Call #3 with the same per-RPC HTTP config MUST fail fast with ErrCircuitBreakerOpen
		// without making any network request to plainFailingTS.
		cbCfg3, err := parseHandlerConfig([]byte(cbCfgJSON))
		require.NoError(t, err)
		hc3, err := p.httpClientForConfig(context.Background(), cbCfg3)
		require.NoError(t, err)
		_, err3 := hc3.PostForm(context.Background(), plainFailingTS.URL, url.Values{"grant_type": {"client_credentials"}})
		require.Error(t, err3)
		assert.ErrorIs(t, err3, httpc.ErrCircuitBreakerOpen)
		assert.Equal(t, hitsBeforeOpen, plainHits.Load(), "open circuit breaker must short-circuit before hitting upstream")

		// A distinct per-RPC HTTP config gets its own isolated client whose breaker is still closed.
		otherCBCfg, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"3s","retryMax":1,"retryWaitMin":"1ms","retryWaitMax":"2ms","allowPrivateIPs":true,"enableCircuitBreaker":true,"circuitBreakerMaxFailures":2,"circuitBreakerOpenTimeout":"1m"}}`))
		require.NoError(t, err)
		hcOther, err := p.httpClientForConfig(context.Background(), otherCBCfg)
		require.NoError(t, err)
		assert.NotSame(t, hc1, hcOther)

		// 2. Bounded LRU eviction & StopAuthHandler close idle transport connections.
		var closedConns atomic.Int32
		keepAliveTS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"value":[{"id":"grp-1"}]}`))
		}))
		keepAliveTS.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				closedConns.Add(1)
			}
		}
		keepAliveTS.Start()
		defer keepAliveTS.Close()

		evictPlugin := &Plugin{clientCacheSize: 2}
		require.NoError(t, evictPlugin.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
		}))

		cfgK1, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"4s","allowPrivateIPs":true}}`))
		require.NoError(t, err)
		cfgK2, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"5s","allowPrivateIPs":true}}`))
		require.NoError(t, err)
		cfgK3, err := parseHandlerConfig([]byte(`{"httpClient":{"timeout":"6s","allowPrivateIPs":true}}`))
		require.NoError(t, err)

		gc1, err := evictPlugin.graphClientForConfig(context.Background(), cfgK1)
		require.NoError(t, err)
		gc2, err := evictPlugin.graphClientForConfig(context.Background(), cfgK2)
		require.NoError(t, err)
		assert.Equal(t, 2, evictPlugin.graphClientCache.Len())

		// Open one idle keep-alive connection on both gc1 and gc2.
		for _, gc := range []GraphClient{gc1, gc2} {
			r, getErr := gc.Get(context.Background(), keepAliveTS.URL, "tok")
			require.NoError(t, getErr)
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
		assert.Equal(t, int32(0), closedConns.Load(), "keep-alive connections remain idle before eviction")

		// Touch K1 so K2 becomes the least-recently-used entry, then insert K3.
		gc1Again, err := evictPlugin.graphClientForConfig(context.Background(), cfgK1)
		require.NoError(t, err)
		assert.Same(t, gc1, gc1Again)

		_, err = evictPlugin.graphClientForConfig(context.Background(), cfgK3)
		require.NoError(t, err)
		assert.Equal(t, 2, evictPlugin.graphClientCache.Len(), "cache must stay bounded at clientCacheSize")

		// Evicting K2 must close K2's idle keep-alive socket promptly while keeping K1's open.
		require.Eventually(t, func() bool {
			return closedConns.Load() == 1
		}, 2*time.Second, 10*time.Millisecond, "LRU eviction must close evicted client's idle connections")

		gc1StillCached, err := evictPlugin.graphClientForConfig(context.Background(), cfgK1)
		require.NoError(t, err)
		assert.Same(t, gc1, gc1StillCached, "promoted MRU entry K1 must survive eviction")

		// StopAuthHandler closes all remaining cached clients (closing K1's idle connection).
		require.NoError(t, evictPlugin.StopAuthHandler(context.Background(), HandlerName))
		require.Eventually(t, func() bool {
			return closedConns.Load() == 2
		}, 2*time.Second, 10*time.Millisecond, "StopAuthHandler must close remaining cached idle connections")
	})

	t.Run("concurrent -race stress over bounded HTTP and Graph client caches", func(t *testing.T) {
		p := &Plugin{clientCacheSize: 4}
		require.NoError(t, p.ConfigureAuthHandler(context.Background(), HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
		}))

		const goroutines = 24
		const iterations = 20
		var wg sync.WaitGroup
		for g := range goroutines {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for i := range iterations {
					sec := ((id + i) % 8) + 1 // 8 distinct configs > cache size 4 -> continuous hits, misses, promotions, evictions
					raw := fmt.Sprintf(`{"httpClient":{"timeout":"%ds","allowPrivateIPs":true}}`, sec)
					cfg, parseErr := parseHandlerConfig([]byte(raw))
					assert.NoError(t, parseErr)

					hc, hErr := p.httpClientForConfig(context.Background(), cfg)
					assert.NoError(t, hErr)
					assert.NotNil(t, hc)

					gc, gErr := p.graphClientForConfig(context.Background(), cfg)
					assert.NoError(t, gErr)
					assert.NotNil(t, gc)
				}
			}(g)
		}
		wg.Wait()

		assert.LessOrEqual(t, p.httpClientCache.Len(), 4)
		assert.LessOrEqual(t, p.graphClientCache.Len(), 4)
		assert.Equal(t, DefaultClientID, p.config.ClientID, "p.config must never be mutated")
		require.NoError(t, p.StopAuthHandler(context.Background(), HandlerName))
	})
}
