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
	"net/http/httptrace"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
				fake.setSecretKeyErr = map[string]error{
					SecretKeyRefreshToken: errors.New("keyring locked"),
				}
			},
			wantTermErr:  "store_credentials",
			forbidInHTML: "keyring locked",
		},
		{
			name: "storeCredentials metadata write failure on fresh login",
			setup: func(_ *Plugin, fake *fakeHostService, httpMock *MockHTTPClient) {
				httpMock.AddResponse(http.StatusOK, TokenResponse{
					AccessToken:  "at-secret",
					RefreshToken: "rt-secret",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					IDToken:      validJWT,
				})
				fake.setSecretKeyErr = map[string]error{
					SecretKeyMetadata: errors.New("metadata keyring locked"),
				}
			},
			wantTermErr:  "store_credentials",
			forbidInHTML: "metadata keyring locked",
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

			st, statusErr := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			require.NoError(t, statusErr)
			assert.False(t, st.Authenticated, "failed fresh login must not leave a usable session")
			_, tokErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{Scope: "https://graph.microsoft.com/.default"})
			require.Error(t, tokErr)

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
	mu       sync.Mutex
	lastData url.Values
	onPost   func() (*http.Response, error)
}

func (b *blockingPostFormClient) PostForm(_ context.Context, _ string, data url.Values) (*http.Response, error) {
	b.mu.Lock()
	b.lastData = data
	b.mu.Unlock()
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

	t.Run("desktop browser open error plus unavailable or unimplemented paste prompt emits suppressed deviceCodeCb once", func(t *testing.T) {
		for name, promptErr := range map[string]error{
			"unavailable":   status.Error(codes.Unavailable, "host is non-interactive"),
			"unimplemented": status.Error(codes.Unimplemented, "PromptAuthResponse not implemented"),
		} {
			t.Run(name, func(t *testing.T) {
				httpMock := pasteTokenResponse()
				p, fake := newTestPlugin(t, httpMock, nil)
				advertisePasteBack(p)
				p.headlessReason = func() string { return "" }
				p.openBrowser = func(_ context.Context, _ string) error {
					return errors.New("browser opener failed")
				}
				fake.promptFunc = func(_ context.Context, _ *proto.PromptAuthResponseRequest) (string, error) {
					return "", promptErr
				}

				var prompts []sdkplugin.DeviceCodePrompt
				_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
					Flow: auth.FlowInteractive,
				}, func(prompt sdkplugin.DeviceCodePrompt) {
					prompts = append(prompts, prompt)
					completeLoopbackCallback(t, prompt.VerificationURI, "MANUAL-CALLBACK-CODE")
				})
				require.NoError(t, err)
				require.Len(t, prompts, 1, "suppressed URL notification must be emitted once when paste prompt fails")
				u, parseErr := url.Parse(prompts[0].VerificationURI)
				require.NoError(t, parseErr)
				assert.Equal(t, "select_account", u.Query().Get("prompt"))

				reqs := httpMock.GetRequests()
				require.Len(t, reqs, 1)
				assert.Equal(t, "MANUAL-CALLBACK-CODE", reqs[0].Data.Get("code"))
			})
		}
	})

	t.Run("desktop browser launch plus unavailable paste prompt does not duplicate deviceCodeCb", func(t *testing.T) {
		httpMock := pasteTokenResponse()
		p, fake := newTestPlugin(t, httpMock, nil)
		advertisePasteBack(p)
		p.headlessReason = func() string { return "" }
		promptFailed := make(chan struct{})
		fake.promptFunc = func(_ context.Context, _ *proto.PromptAuthResponseRequest) (string, error) {
			defer close(promptFailed)
			return "", status.Error(codes.Unavailable, "host is non-interactive")
		}
		p.openBrowser = func(_ context.Context, authURL string) error {
			go func() {
				<-promptFailed
				time.Sleep(15 * time.Millisecond)
				completeLoopbackCallback(t, authURL, "DESKTOP-AFTER-PROMPT-ERR")
			}()
			return nil
		}

		var prompts []sdkplugin.DeviceCodePrompt
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, func(prompt sdkplugin.DeviceCodePrompt) {
			prompts = append(prompts, prompt)
		})
		require.NoError(t, err)
		require.Len(t, prompts, 1, "URL notification already sent on browser launch must not fire twice")
	})
}

func TestAuthCodeLogin_PasteBackCompetingCallbackDrainsFailurePage(t *testing.T) {
	clearCredentialEnv(t)

	validJWT := makeTestJWT(map[string]any{
		"sub":                "sub-123",
		"oid":                "oid-123",
		"tid":                "tid-123",
		"preferred_username": "alice@example.com",
	})

	t.Run("competing callback arriving during paste-back exchange drains 503 FailureHTML cleanly", func(t *testing.T) {
		exchangeEntered := make(chan struct{})
		releaseExchange := make(chan struct{})

		blocker := &blockingPostFormClient{
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

		p, fake := newTestPlugin(t, nil, nil)
		p.httpClient = blocker
		_, wantSuccess, wantFailure := configureCustomPages(t, p)
		advertisePasteBack(p)
		p.headlessReason = func() string { return "" }

		var capturedAuthURL string
		p.openBrowser = func(_ context.Context, authURL string) error {
			capturedAuthURL = authURL
			return nil
		}
		fake.promptFunc = func(_ context.Context, req *proto.PromptAuthResponseRequest) (string, error) {
			return validPasteFromRequest(t, req, url.Values{"code": {"PASTED-CODE"}}), nil
		}

		loginDone := make(chan error, 1)
		go func() {
			_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow: auth.FlowInteractive,
			}, nil)
			loginDone <- err
		}()

		<-exchangeEntered

		u, err := url.Parse(capturedAuthURL)
		require.NoError(t, err)
		redirectURI := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")

		type browserOutcome struct {
			status int
			body   string
			err    error
		}
		browserCh := make(chan browserOutcome, 1)
		competingSent := make(chan struct{})
		var sentOnce sync.Once
		go func() {
			traceCtx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
				WroteRequest: func(httptrace.WroteRequestInfo) {
					sentOnce.Do(func() { close(competingSent) })
				},
			})
			req, reqErr := http.NewRequestWithContext(traceCtx, http.MethodGet, redirectURI+"/?code=COMPETING-CODE&state="+url.QueryEscape(state), nil)
			if reqErr != nil {
				browserCh <- browserOutcome{err: reqErr}
				return
			}
			resp, doErr := http.DefaultClient.Do(req)
			if doErr != nil {
				browserCh <- browserOutcome{err: doErr}
				return
			}
			b, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			browserCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
		}()

		<-competingSent
		// Give the loopback server handler a moment to park in resolveDeferred
		// before releasing the paste-back exchange.
		select {
		case out := <-browserCh:
			t.Fatalf("competing callback completed prematurely before settle: %+v", out)
		case <-time.After(25 * time.Millisecond):
		}

		close(releaseExchange)
		require.NoError(t, <-loginDone)

		blocker.mu.Lock()
		exchangedCode := blocker.lastData.Get("code")
		blocker.mu.Unlock()
		assert.Equal(t, "PASTED-CODE", exchangedCode)

		out := <-browserCh
		require.NoError(t, out.err, "competing callback must drain cleanly without socket reset")
		assert.Equal(t, http.StatusServiceUnavailable, out.status, "unexchanged competing callback must receive failure status")
		assert.Equal(t, wantFailure, out.body)
		assert.NotEqual(t, wantSuccess, out.body)
	})

	t.Run("in-flight callback during context cancellation drains 503 FailureHTML cleanly", func(t *testing.T) {
		exchangeEntered := make(chan struct{})
		releaseExchange := make(chan struct{})

		p, _ := newTestPlugin(t, nil, nil)
		p.httpClient = &blockingPostFormClient{
			onPost: func() (*http.Response, error) {
				close(exchangeEntered)
				<-releaseExchange
				return nil, context.Canceled
			},
		}
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
				resp, getErr := http.Get(redirectURI + "/?code=CANCEL-CODE&state=" + url.QueryEscape(state)) //nolint:noctx
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

		loginCtx, cancelLogin := context.WithCancel(context.Background())
		loginDone := make(chan error, 1)
		go func() {
			_, err := p.Login(loginCtx, HandlerName, sdkplugin.LoginRequest{
				Flow: auth.FlowInteractive,
			}, nil)
			loginDone <- err
		}()

		<-exchangeEntered
		cancelLogin()
		close(releaseExchange)

		require.Error(t, <-loginDone)
		out := <-browserCh
		require.NoError(t, out.err, "cancelled callback must drain cleanly without socket reset")
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Equal(t, wantFailure, out.body)
	})
}

func TestAuthCodeLogin_MetadataWriteFailureAccountReplacement(t *testing.T) {
	clearCredentialEnv(t)

	aliceJWT := makeTestJWT(map[string]any{
		"sub":                "alice-sub",
		"oid":                "alice-oid",
		"tid":                "alice-tid",
		"preferred_username": "alice@example.com",
	})
	bobJWT := makeTestJWT(map[string]any{
		"sub":                "bob-sub",
		"oid":                "bob-oid",
		"tid":                "bob-tid",
		"preferred_username": "bob@example.com",
	})

	runBrowserCallback := func(p *Plugin) <-chan struct {
		status int
		body   string
		err    error
	} {
		ch := make(chan struct {
			status int
			body   string
			err    error
		}, 1)
		p.openBrowser = func(_ context.Context, authURL string) error {
			u, parseErr := url.Parse(authURL)
			if parseErr != nil {
				return parseErr
			}
			redirectURI := u.Query().Get("redirect_uri")
			state := u.Query().Get("state")
			go func() {
				resp, getErr := http.Get(redirectURI + "/?code=REPLACE-CODE&state=" + url.QueryEscape(state)) //nolint:noctx
				if getErr != nil {
					ch <- struct {
						status int
						body   string
						err    error
					}{err: getErr}
					return
				}
				b, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				ch <- struct {
					status int
					body   string
					err    error
				}{status: resp.StatusCode, body: string(b), err: readErr}
			}()
			return nil
		}
		return ch
	}

	t.Run("metadata write failure rolls back refresh token so previous account stays consistent", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		// 1. Initial Alice login succeeds.
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-1",
			RefreshToken: "alice-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})
		// 2. Replacement Bob login exchanges code for Bob's tokens, then fails metadata SetSecret.
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at-1",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      bobJWT,
		})
		// 3. Subsequent GetToken force-refresh must send alice-rt (never bob-rt).
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-2",
			RefreshToken: "alice-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		_, wantSuccess, wantFailure := configureCustomPages(t, p)

		aliceBrowserCh := runBrowserCallback(p)
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "alice-tid",
		}, nil)
		require.NoError(t, err)
		aliceOut := <-aliceBrowserCh
		require.NoError(t, aliceOut.err)
		assert.Equal(t, http.StatusOK, aliceOut.status)

		// Inject key-specific failure on metadata only for the replacement login.
		fake.mu.Lock()
		fake.setSecretKeyErr = map[string]error{
			SecretKeyMetadata: errors.New("metadata write quota exceeded"),
		}
		fake.mu.Unlock()

		bobBrowserCh := runBrowserCallback(p)
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "bob-tid",
		}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "store_credentials")

		bobOut := <-bobBrowserCh
		require.NoError(t, bobOut.err)
		assert.Equal(t, http.StatusServiceUnavailable, bobOut.status)
		assert.Equal(t, wantFailure, bobOut.body)
		assert.NotEqual(t, wantSuccess, bobOut.body)
		assert.NotContains(t, bobOut.body, "metadata write quota exceeded")

		// Stored refresh token must be rolled back to Alice's token, never left as Bob's.
		assert.Equal(t, "alice-rt", fake.secrets[SecretKeyRefreshToken])

		st, statusErr := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, statusErr)
		require.True(t, st.Authenticated)
		require.NotNil(t, st.Claims)
		assert.Equal(t, "alice-sub", st.Claims.Subject)
		assert.Equal(t, "alice@example.com", st.Claims.Username)

		tokResp, tokErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://graph.microsoft.com/.default",
			ForceRefresh: true,
		})
		require.NoError(t, tokErr)
		assert.Equal(t, "alice-at-2", tokResp.AccessToken)

		reqs := httpMock.GetRequests()
		require.Len(t, reqs, 3)
		assert.Equal(t, "alice-rt", reqs[2].Data.Get("refresh_token"), "mintToken must never send Bob's refresh token paired with Alice's metadata")
		assert.Contains(t, reqs[2].Endpoint, "/alice-tid/oauth2/v2.0/token")
	})

	t.Run("metadata write failure when rollback also fails clears both secrets so no mismatched session remains usable", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-1",
			RefreshToken: "alice-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at-1",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      bobJWT,
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		_, wantSuccess, wantFailure := configureCustomPages(t, p)

		aliceBrowserCh := runBrowserCallback(p)
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "alice-tid",
		}, nil)
		require.NoError(t, err)
		<-aliceBrowserCh

		// Allow Bob's initial refresh-token write, then fail metadata write AND
		// fail the rollback refresh-token write so storeCredentials must purge both.
		bobRTWrites := 0
		fake.mu.Lock()
		fake.setSecretFunc = func(name, value string) error {
			if name == SecretKeyRefreshToken && value == "bob-rt" && bobRTWrites == 0 {
				bobRTWrites++
				return nil
			}
			return errors.New("keyring permanently unavailable")
		}
		fake.mu.Unlock()

		bobBrowserCh := runBrowserCallback(p)
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "bob-tid",
		}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "store_credentials")

		bobOut := <-bobBrowserCh
		require.NoError(t, bobOut.err)
		assert.Equal(t, http.StatusServiceUnavailable, bobOut.status)
		assert.Equal(t, wantFailure, bobOut.body)
		assert.NotEqual(t, wantSuccess, bobOut.body)
		assert.NotContains(t, bobOut.body, "keyring permanently unavailable")

		assert.NotContains(t, fake.secrets, SecretKeyRefreshToken)
		assert.NotContains(t, fake.secrets, SecretKeyMetadata)

		st, statusErr := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, statusErr)
		assert.False(t, st.Authenticated, "no mismatched session may remain usable when rollback fails")

		_, tokErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope: "https://graph.microsoft.com/.default",
		})
		require.Error(t, tokErr)
		assert.Contains(t, tokErr.Error(), "not authenticated")
	})
}
