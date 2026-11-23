// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func configureCustomPages(t *testing.T, p *Plugin) (*sdkplugin.AuthCallbackPages, string, string) {
	t.Helper()
	successDoc := "<!doctype html><html><body>ENTRA-BLUEPRINT-SUCCESS</body></html>"
	failureDoc := "<!doctype html><html><body>ENTRA-BLUEPRINT-FAILURE</body></html>"
	pages := &sdkplugin.AuthCallbackPages{
		SuccessHTML: []byte(successDoc),
		FailureHTML: []byte(failureDoc),
	}
	cfgCtx := sdkplugin.WithHostClient(context.Background(), p.cachedHostClient)
	require.NoError(t, p.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{
		BinaryName:        "mycli",
		AuthCallbackPages: pages,
	}))
	return pages, successDoc, failureDoc
}

func jsonTestResponse(status int, payload any) *http.Response {
	b, _ := json.Marshal(payload)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

func TestAuthCodeLogin_WithholdsSuccessUntilFatalStepsFinish(t *testing.T) {
	clearCredentialEnv(t)

	exchangeEntered := make(chan struct{})
	releaseExchange := make(chan struct{})

	validJWT := makeTestJWT(map[string]any{
		"sub":                "sub-123",
		"oid":                "oid-123",
		"tid":                "tid-123",
		"preferred_username": "alice@example.com",
	})

	p, _ := newTestPlugin(t, nil, nil)
	p.httpClient = &blockingPostFormClient{
		onPost: func() (*http.Response, error) {
			close(exchangeEntered)
			<-releaseExchange
			return jsonTestResponse(http.StatusOK, TokenResponse{
				AccessToken:  "entra-at",
				RefreshToken: "entra-rt",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				IDToken:      validJWT,
			}), nil
		},
	}
	_, wantSuccess, _ := configureCustomPages(t, p)

	type browserOutcome struct {
		status int
		body   string
		csp    string
		err    error
	}
	browserCh := make(chan browserOutcome, 1)
	p.openBrowser = func(_ context.Context, authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		redirectURI := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")
		go func() {
			resp, getErr := http.Get(redirectURI + "/?code=ENTRA-CODE&state=" + url.QueryEscape(state)) //nolint:noctx
			if getErr != nil {
				browserCh <- browserOutcome{err: getErr}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			b, readErr := io.ReadAll(resp.Body)
			browserCh <- browserOutcome{
				status: resp.StatusCode,
				body:   string(b),
				csp:    resp.Header.Get("Content-Security-Policy"),
				err:    readErr,
			}
		}()
		return nil
	}

	loginDone := make(chan error, 1)
	go func() {
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, nil)
		loginDone <- err
	}()

	<-exchangeEntered

	// While exchangeAuthCode is blocked, browser response MUST still be pending.
	select {
	case out := <-browserCh:
		t.Fatalf("browser received premature response before exchange/storage/claims completed: %+v", out)
	case <-time.After(60 * time.Millisecond):
	}

	close(releaseExchange)
	require.NoError(t, <-loginDone)

	out := <-browserCh
	require.NoError(t, out.err)
	assert.Equal(t, http.StatusOK, out.status)
	assert.Equal(t, wantSuccess, out.body)
	assert.Contains(t, out.csp, "default-src 'none'")
}

func TestAuthCodeLogin_PostCallbackFailuresServeSafeFailurePage(t *testing.T) {
	clearCredentialEnv(t)

	validJWT := makeTestJWT(map[string]any{
		"sub":                "sub-123",
		"oid":                "oid-123",
		"tid":                "tid-123",
		"preferred_username": "alice@example.com",
	})

	tests := []struct {
		name         string
		setup        func(p *Plugin, fake *fakeHostService, httpMock *MockHTTPClient)
		wantTermErr  string
		forbidInHTML string
	}{
		{
			name: "token exchange failure",
			setup: func(_ *Plugin, _ *fakeHostService, httpMock *MockHTTPClient) {
				httpMock.AddResponse(http.StatusBadRequest, TokenErrorResponse{
					Error:            "invalid_grant",
					ErrorDescription: "AADSTS70008: confidential exchange detail",
				})
			},
			wantTermErr:  "token_exchange",
			forbidInHTML: "AADSTS70008",
		},
		{
			name: "storeCredentials failure",
			setup: func(_ *Plugin, fake *fakeHostService, httpMock *MockHTTPClient) {
				httpMock.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "at-secret",
					RefreshToken: "rt-secret",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      validJWT,
				})
				fake.setSecretErr = errors.New("keyring locked")
			},
			wantTermErr:  "store_credentials",
			forbidInHTML: "keyring locked",
		},
		{
			name: "extractClaims failure",
			setup: func(_ *Plugin, _ *fakeHostService, httpMock *MockHTTPClient) {
				httpMock.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "at-secret",
					RefreshToken: "rt-secret",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      "not-a-valid-jwt",
				})
			},
			wantTermErr:  "extract_claims",
			forbidInHTML: "not-a-valid-jwt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpMock := NewMockHTTPClient()
			p, fake := newTestPlugin(t, httpMock, nil)
			_, wantSuccess, wantFailure := configureCustomPages(t, p)
			tt.setup(p, fake, httpMock)

			type browserOutcome struct {
				status int
				body   string
				err    error
			}
			browserCh := make(chan browserOutcome, 1)
			p.openBrowser = func(_ context.Context, authURL string) error {
				u, parseErr := url.Parse(authURL)
				if parseErr != nil {
					return parseErr
				}
				redirectURI := u.Query().Get("redirect_uri")
				state := u.Query().Get("state")
				go func() {
					resp, getErr := http.Get(redirectURI + "/?code=CODE-ERR&state=" + url.QueryEscape(state)) //nolint:noctx
					if getErr != nil {
						browserCh <- browserOutcome{err: getErr}
						return
					}
					b, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					browserCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
				}()
				return nil
			}

			_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow: auth.FlowInteractive,
			}, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantTermErr)
			assert.Empty(t, fake.secrets, "failed login must not persist session credentials")

			out := <-browserCh
			require.NoError(t, out.err)
			assert.Equal(t, http.StatusServiceUnavailable, out.status)
			assert.Equal(t, wantFailure, out.body)
			assert.NotEqual(t, wantSuccess, out.body)
			assert.NotContains(t, out.body, tt.forbidInHTML)
		})
	}
}

type blockingPostFormClient struct {
	onPost func() (*http.Response, error)
}

func (b *blockingPostFormClient) PostForm(_ context.Context, _ string, _ url.Values) (*http.Response, error) {
	return b.onPost()
}

func TestAuthCodeLogin_NilCallbackPagesAndDirectErrorDrain(t *testing.T) {
	clearCredentialEnv(t)

	t.Run("older host with nil AuthCallbackPages serves neutral 503 helper failure page", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "AADSTS70008: older-host-secret-detail",
		})
		p, _ := newTestPlugin(t, httpMock, nil)
		cfgCtx := sdkplugin.WithHostClient(context.Background(), p.cachedHostClient)
		require.NoError(t, p.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{
			BinaryName:        "scafctl",
			AuthCallbackPages: nil,
		}))

		type browserOutcome struct {
			status int
			body   string
			err    error
		}
		browserCh := make(chan browserOutcome, 1)
		p.openBrowser = func(_ context.Context, authURL string) error {
			u, _ := url.Parse(authURL)
			redirectURI := u.Query().Get("redirect_uri")
			state := u.Query().Get("state")
			go func() {
				resp, getErr := http.Get(redirectURI + "/?code=CODE-NIL&state=" + url.QueryEscape(state)) //nolint:noctx
				if getErr != nil {
					browserCh <- browserOutcome{err: getErr}
					return
				}
				b, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				browserCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
			}()
			return nil
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, nil)
		require.Error(t, err)

		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Contains(t, out.body, "Authentication Failed")
		assert.NotContains(t, out.body, "AADSTS70008")
	})

	t.Run("direct callback OAuth error drains 400 FailureHTML cleanly without socket reset", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		p, _ := newTestPlugin(t, httpMock, nil)
		_, _, wantFailure := configureCustomPages(t, p)

		type browserOutcome struct {
			status int
			body   string
			err    error
		}
		browserCh := make(chan browserOutcome, 1)
		p.openBrowser = func(_ context.Context, authURL string) error {
			u, _ := url.Parse(authURL)
			redirectURI := u.Query().Get("redirect_uri")
			state := u.Query().Get("state")
			go func() {
				resp, getErr := http.Get(redirectURI + "/?error=access_denied&error_description=AADSTS65004%3A+consent-declined&state=" + url.QueryEscape(state)) //nolint:noctx
				if getErr != nil {
					browserCh <- browserOutcome{err: getErr}
					return
				}
				b, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				browserCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
			}()
			return nil
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access_denied")

		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusBadRequest, out.status)
		assert.Equal(t, wantFailure, out.body)
		assert.NotContains(t, out.body, "AADSTS65004")
	})
}

func TestAuthCodeLogin_DeviceCodeCallbackGating(t *testing.T) {
	clearCredentialEnv(t)

	t.Run("desktop browser launch notifies deviceCodeCb with VerificationURI", func(t *testing.T) {
		httpMock := pasteTokenResponse()
		p, _ := newTestPlugin(t, httpMock, nil)
		advertisePasteBack(p)
		p.headlessReason = func() string { return "" }
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "DESKTOP-CODE")
			return nil
		}

		var prompts []sdkplugin.DeviceCodePrompt
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, func(prompt sdkplugin.DeviceCodePrompt) {
			prompts = append(prompts, prompt)
		})
		require.NoError(t, err)
		require.Len(t, prompts, 1)
		u, parseErr := url.Parse(prompts[0].VerificationURI)
		require.NoError(t, parseErr)
		assert.Equal(t, "select_account", u.Query().Get("prompt"))
	})

	t.Run("headless session on paste-back host skips deviceCodeCb", func(t *testing.T) {
		httpMock := pasteTokenResponse()
		p, fake := newTestPlugin(t, httpMock, nil)
		advertisePasteBack(p)
		p.headlessReason = func() string { return "no DISPLAY or WAYLAND_DISPLAY (headless session)" }
		p.openBrowser = func(_ context.Context, _ string) error {
			return errors.New("xdg-open: not found")
		}
		fake.promptFunc = func(_ context.Context, req *proto.PromptAuthResponseRequest) (string, error) {
			return validPasteFromRequest(t, req, url.Values{"code": {"HEADLESS-PASTE"}}), nil
		}

		called := false
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, func(_ sdkplugin.DeviceCodePrompt) {
			called = true
		})
		require.NoError(t, err)
		assert.False(t, called, "headless paste-back login should not emit browser status box prompt")
	})

	t.Run("browser open error on desktop paste-back host skips deviceCodeCb", func(t *testing.T) {
		httpMock := pasteTokenResponse()
		p, fake := newTestPlugin(t, httpMock, nil)
		advertisePasteBack(p)
		p.headlessReason = func() string { return "" }
		p.openBrowser = func(_ context.Context, _ string) error {
			return errors.New("browser opener failed")
		}
		fake.promptFunc = func(_ context.Context, req *proto.PromptAuthResponseRequest) (string, error) {
			return validPasteFromRequest(t, req, url.Values{"code": {"DESKTOP-PASTE"}}), nil
		}

		called := false
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, func(_ sdkplugin.DeviceCodePrompt) {
			called = true
		})
		require.NoError(t, err)
		assert.False(t, called, "browser open failure on paste-back host should go straight to paste prompt")
	})

	t.Run("headless explicit interactive login on host without paste-back still notifies deviceCodeCb", func(t *testing.T) {
		httpMock := pasteTokenResponse()
		p, _ := newTestPlugin(t, httpMock, nil)
		// Host does NOT advertise PromptAuthResponse (e.g. SSH port forwarding on older host).
		p.headlessReason = func() string { return "no DISPLAY or WAYLAND_DISPLAY (headless session)" }
		p.openBrowser = func(_ context.Context, authURL string) error {
			completeLoopbackCallback(t, authURL, "SSH-FORWARD-CODE")
			return errors.New("xdg-open: not found")
		}

		var prompts []sdkplugin.DeviceCodePrompt
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, func(prompt sdkplugin.DeviceCodePrompt) {
			prompts = append(prompts, prompt)
		})
		require.NoError(t, err)
		require.Len(t, prompts, 1, "non-paste-back host must still receive VerificationURI via deviceCodeCb")
		u, parseErr := url.Parse(prompts[0].VerificationURI)
		require.NoError(t, parseErr)
		assert.Equal(t, "select_account", u.Query().Get("prompt"))
	})
}
