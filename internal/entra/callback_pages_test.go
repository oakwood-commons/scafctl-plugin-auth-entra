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
	"strings"
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
				fake.setSecretErr = errors.New("keyring locked")
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

type funcPostFormClient struct {
	fn func(ctx context.Context, endpoint string, data url.Values) (*http.Response, error)
}

func (f *funcPostFormClient) PostForm(ctx context.Context, endpoint string, data url.Values) (*http.Response, error) {
	return f.fn(ctx, endpoint, data)
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

	t.Run("legacy mirror write failure after metadata commits keeps committed session intact without rewriting metadata", func(t *testing.T) {
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
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at-2",
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

		// Allow Bob's versioned refresh-token write and metadata commit, then
		// fail the legacy SecretKeyRefreshToken mirror write. Because metadataKey
		// is the single forward commit point, storeCredentials must keep Bob's
		// committed session intact and never rewrite or delete SecretKeyMetadata.
		bobMetaWrites := 0
		bobMetaDeletes := 0
		var fnMu sync.Mutex
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, name, _ string) error {
			fnMu.Lock()
			defer fnMu.Unlock()
			if name == SecretKeyMetadata {
				bobMetaWrites++
			}
			if name == SecretKeyRefreshToken {
				return errors.New("legacy refresh_token mirror failed")
			}
			return nil
		}
		fake.deleteSecretFunc = func(_ context.Context, name string) error {
			fnMu.Lock()
			defer fnMu.Unlock()
			if name == SecretKeyMetadata {
				bobMetaDeletes++
			}
			return nil
		}
		fake.mu.Unlock()

		bobBrowserCh := runBrowserCallback(p)
		resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "bob-tid",
		}, nil)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, "bob-sub", resp.Claims.Subject)

		bobOut := <-bobBrowserCh
		require.NoError(t, bobOut.err)
		assert.Equal(t, http.StatusOK, bobOut.status)
		assert.Equal(t, wantSuccess, bobOut.body)
		assert.NotEqual(t, wantFailure, bobOut.body)

		fnMu.Lock()
		assert.Equal(t, 1, bobMetaWrites, "metadataKey must be written once to commit and never rewritten on legacy mirror failure")
		assert.Equal(t, 0, bobMetaDeletes, "metadataKey must never be deleted on legacy mirror failure")
		fnMu.Unlock()

		st, statusErr := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, statusErr)
		require.True(t, st.Authenticated)
		require.NotNil(t, st.Claims)
		assert.Equal(t, "bob-sub", st.Claims.Subject)
		assert.Equal(t, "bob@example.com", st.Claims.Username)
		assert.Equal(t, "bob-tid", st.TenantID)

		tokResp, tokErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://graph.microsoft.com/.default",
			ForceRefresh: true,
		})
		require.NoError(t, tokErr)
		assert.Equal(t, "bob-at-2", tokResp.AccessToken)

		reqs := httpMock.GetRequests()
		require.Len(t, reqs, 3)
		assert.Equal(t, "bob-rt", reqs[2].Data.Get("refresh_token"), "versioned refresh token must serve committed session even when legacy mirror fails")
	})
}

func TestLogoutIfSessionMatches_RequiresPositiveSessionProof(t *testing.T) {
	clearCredentialEnv(t)

	seedBobSession := func(t *testing.T) (*Plugin, *fakeHostService, string) {
		t.Helper()
		p, fake := newTestPlugin(t, nil, nil)
		bobToken := &TokenResponse{
			AccessToken:  "bob-at",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken: makeTestJWT(map[string]any{
				"sub":                "bob-sub",
				"oid":                "bob-oid",
				"tid":                "bob-tid",
				"preferred_username": "bob@example.com",
			}),
		}
		require.NoError(t, p.storeCredentials(context.Background(), "bob-tid", bobToken, p.config.ClientID, []string{"openid", "profile", "offline_access"}, auth.FlowInteractive, "bob-session-id"))
		fake.secrets[SecretKeyTokenPrefix+"cached-graph"] = `{"accessToken":"bob-cached-at"}`
		return p, fake, "bob-session-id"
	}

	t.Run("GetSecret RPC error on metadata does not delete stored session", func(t *testing.T) {
		p, fake, sessionID := seedBobSession(t)
		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata {
				return errors.New("transient secret store RPC failure")
			}
			return nil
		}
		fake.mu.Unlock()

		p.logoutIfSessionMatches(context.Background(), sessionID)

		// Restore healthy reads and confirm Bob's session and cached token remain intact.
		fake.mu.Lock()
		fake.getSecretFunc = nil
		_, hasCached := fake.secrets[SecretKeyTokenPrefix+"cached-graph"]
		fake.mu.Unlock()
		assert.True(t, hasCached, "cached token must not be cleared on metadata GetSecret error")

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated, "session must remain authenticated when metadata read fails")
		assert.Equal(t, "bob-sub", st.Claims.Subject)
	})

	t.Run("corrupted or unparseable metadata does not delete stored secrets", func(t *testing.T) {
		p, fake, sessionID := seedBobSession(t)
		fake.mu.Lock()
		fake.secrets[SecretKeyMetadata] = "{corrupt-json"
		fake.mu.Unlock()

		p.logoutIfSessionMatches(context.Background(), sessionID)

		fake.mu.Lock()
		assert.Equal(t, "bob-rt", fake.secrets[SecretKeyRefreshToken])
		assert.Contains(t, fake.secrets, SecretKeyTokenPrefix+"cached-graph")
		fake.mu.Unlock()
	})

	t.Run("empty or absent metadata does not delete stored secrets", func(t *testing.T) {
		p, fake, sessionID := seedBobSession(t)
		fake.mu.Lock()
		delete(fake.secrets, SecretKeyMetadata)
		fake.mu.Unlock()

		p.logoutIfSessionMatches(context.Background(), sessionID)

		fake.mu.Lock()
		assert.Equal(t, "bob-rt", fake.secrets[SecretKeyRefreshToken])
		assert.Contains(t, fake.secrets, SecretKeyTokenPrefix+"cached-graph")
		fake.mu.Unlock()
	})

	t.Run("matching SessionID deletes session when metadata is readable and valid", func(t *testing.T) {
		p, fake, sessionID := seedBobSession(t)

		p.logoutIfSessionMatches(context.Background(), sessionID)

		fake.mu.Lock()
		assert.Empty(t, fake.secrets)
		fake.mu.Unlock()
	})
}

func TestAuthCodeLogin_OverlappingLoginsAndBoundedCleanup(t *testing.T) {
	clearCredentialEnv(t)

	aliceJWT := makeTestJWT(map[string]any{
		"sub":                "alice-sub",
		"oid":                "alice-oid",
		"tid":                "alice-tid",
		"preferred_username": "alice@example.com",
	})
	charlieJWT := makeTestJWT(map[string]any{
		"sub":                "charlie-sub",
		"oid":                "charlie-oid",
		"tid":                "charlie-tid",
		"preferred_username": "charlie@example.com",
	})
	bobJWT := makeTestJWT(map[string]any{
		"sub":                "bob-sub",
		"oid":                "bob-oid",
		"tid":                "bob-tid",
		"preferred_username": "bob@example.com",
	})

	newSharedStorePlugin := func(t *testing.T, fake *fakeHostService, httpMock *MockHTTPClient) (*Plugin, string, string) {
		t.Helper()
		p := &Plugin{
			cachedHostClient: newFakeHostClient(fake),
			httpClient:       httpMock,
			graphClient:      NewMockGraphClient(),
		}
		cfgCtx := sdkplugin.WithHostClient(context.Background(), p.cachedHostClient)
		require.NoError(t, p.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{
			BinaryName: "scafctl",
		}))
		p.httpClient = httpMock
		_, wantSuccess, wantFailure := configureCustomPages(t, p)
		return p, wantSuccess, wantFailure
	}

	attachBrowserCallback := func(p *Plugin, code string) <-chan struct {
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
				resp, getErr := http.Get(redirectURI + "/?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)) //nolint:noctx
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

	t.Run("overlapping cross-process login committing while first login fails metadata write keeps committed session consistent", func(t *testing.T) {
		fake := newFakeHostService()

		// Seed initial Alice session.
		initMock := NewMockHTTPClient()
		initMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at",
			RefreshToken: "alice-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})
		pluginInit, _, _ := newSharedStorePlugin(t, fake, initMock)
		initBrowser := attachBrowserCallback(pluginInit, "ALICE-CODE")
		_, err := pluginInit.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "alice-tid",
		}, nil)
		require.NoError(t, err)
		<-initBrowser

		// Process A (Charlie) and Process B (Bob) share the host secret store.
		mockA := NewMockHTTPClient()
		mockA.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "charlie-at",
			RefreshToken: "charlie-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      charlieJWT,
		})
		pluginA, _, wantFailureA := newSharedStorePlugin(t, fake, mockA)
		browserA := attachBrowserCallback(pluginA, "CHARLIE-CODE")

		mockB := NewMockHTTPClient()
		mockB.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at-1",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      bobJWT,
		})
		mockB.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at-2",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      bobJWT,
		})
		pluginB, wantSuccessB, _ := newSharedStorePlugin(t, fake, mockB)
		browserB := attachBrowserCallback(pluginB, "BOB-CODE")

		// Block Login A (Charlie) inside SetSecret(SecretKeyMetadata) until
		// Login B (Bob) commits, then fail Login A's metadata write.
		loginAMetadataBlocked := make(chan struct{})
		releaseLoginAFailure := make(chan struct{})
		var blockedOnce sync.Once
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, name, value string) error {
			if name == SecretKeyMetadata && strings.Contains(value, "charlie-sub") {
				blockedOnce.Do(func() { close(loginAMetadataBlocked) })
				<-releaseLoginAFailure
				return errors.New("charlie metadata write failed")
			}
			return nil
		}
		fake.mu.Unlock()

		loginADone := make(chan error, 1)
		go func() {
			_, aErr := pluginA.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow:     auth.FlowInteractive,
				TenantID: "charlie-tid",
			}, nil)
			loginADone <- aErr
		}()

		<-loginAMetadataBlocked

		// While Login A is waiting on its failing metadata write, Login B commits.
		_, err = pluginB.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "bob-tid",
		}, nil)
		require.NoError(t, err)
		outB := <-browserB
		require.NoError(t, outB.err)
		assert.Equal(t, http.StatusOK, outB.status)
		assert.Equal(t, wantSuccessB, outB.body)

		// Now let Login A's metadata write fail and run its rollback/cleanup.
		close(releaseLoginAFailure)
		errA := <-loginADone
		require.Error(t, errA)
		assert.Contains(t, errA.Error(), "store_credentials")
		outA := <-browserA
		require.NoError(t, outA.err)
		assert.Equal(t, http.StatusServiceUnavailable, outA.status)
		assert.Equal(t, wantFailureA, outA.body)

		// Verify Login B's committed session was NOT clobbered by Login A's rollback.
		st, statusErr := pluginB.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, statusErr)
		require.True(t, st.Authenticated)
		require.NotNil(t, st.Claims)
		assert.Equal(t, "bob-sub", st.Claims.Subject)
		assert.Equal(t, "bob@example.com", st.Claims.Username)
		assert.Equal(t, "bob-tid", st.TenantID)

		tokResp, tokErr := pluginB.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://graph.microsoft.com/.default",
			ForceRefresh: true,
		})
		require.NoError(t, tokErr)
		assert.Equal(t, "bob-at-2", tokResp.AccessToken)

		reqsB := mockB.GetRequests()
		require.Len(t, reqsB, 2)
		assert.Equal(t, "bob-rt", reqsB[1].Data.Get("refresh_token"), "refresh must use Bob's refresh token, never Alice's or Charlie's")
		assert.Contains(t, reqsB[1].Endpoint, "/bob-tid/oauth2/v2.0/token")

		// Verify Charlie's unreferenced versioned secret was deleted.
		fake.mu.Lock()
		for k, v := range fake.secrets {
			assert.NotEqual(t, "charlie-rt", v, "failed login A's refresh token must not remain in %s", k)
			assert.NotEqual(t, "alice-rt", v, "superseded Alice refresh token must not overwrite Bob in %s", k)
		}
		fake.mu.Unlock()
	})

	t.Run("same-process overlapping login and refresh rotation remain serialized and consistent", func(t *testing.T) {
		aliceRefreshEntered := make(chan struct{})
		releaseAliceRefresh := make(chan struct{})
		var refreshOnce sync.Once

		routingClient := &funcPostFormClient{
			fn: func(_ context.Context, _ string, data url.Values) (*http.Response, error) {
				switch data.Get("grant_type") {
				case "authorization_code":
					if data.Get("code") == "ALICE-CODE" {
						return jsonTestResponse(http.StatusOK, TokenResponse{
							AccessToken:  "alice-at",
							RefreshToken: "alice-rt",
							TokenType:    "Bearer",
							ExpiresIn:    3600,
							IDToken:      aliceJWT,
						}), nil
					}
					return jsonTestResponse(http.StatusOK, TokenResponse{
						AccessToken:  "bob-at-1",
						RefreshToken: "bob-rt",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken:      bobJWT,
					}), nil
				case "refresh_token":
					if data.Get("refresh_token") == "alice-rt" {
						refreshOnce.Do(func() { close(aliceRefreshEntered) })
						<-releaseAliceRefresh
						return jsonTestResponse(http.StatusOK, TokenResponse{
							AccessToken:  "alice-rotated-at",
							RefreshToken: "alice-rotated-rt",
							TokenType:    "Bearer",
							ExpiresIn:    3600,
						}), nil
					}
					return jsonTestResponse(http.StatusOK, TokenResponse{
						AccessToken:  "bob-at-2",
						RefreshToken: "bob-rt",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken:      bobJWT,
					}), nil
				default:
					return nil, errors.New("unexpected grant_type")
				}
			},
		}

		p, fake := newTestPlugin(t, nil, nil)
		p.httpClient = routingClient
		configureCustomPages(t, p)

		// 1. Log in as Alice.
		aliceBrowser := attachBrowserCallback(p, "ALICE-CODE")
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "alice-tid",
		}, nil)
		require.NoError(t, err)
		<-aliceBrowser

		// 2. Start an in-flight GetToken refresh for Alice (which will rotate
		// alice-rt -> alice-rotated-rt) alongside concurrent status reads, and
		// commit Bob's Login while Alice's HTTP refresh is in flight.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
				Scope:        "https://graph.microsoft.com/.default",
				ForceRefresh: true,
			})
		}()
		go func() {
			defer wg.Done()
			for range 5 {
				_, _ = p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
			}
		}()

		<-aliceRefreshEntered

		bobBrowser := attachBrowserCallback(p, "BOB-CODE")
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "bob-tid",
		}, nil)
		require.NoError(t, err)
		<-bobBrowser

		// Release Alice's late refresh response; storeRotatedCredentials must
		// see that SessionID changed to Bob and leave Bob's credentials intact.
		close(releaseAliceRefresh)
		wg.Wait()

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, "bob-sub", st.Claims.Subject)
		assert.Equal(t, "bob-rt", fake.secrets[SecretKeyRefreshToken])

		tokResp, err := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://graph.microsoft.com/.default",
			ForceRefresh: true,
		})
		require.NoError(t, err)
		assert.Equal(t, "bob-at-2", tokResp.AccessToken)
	})

	t.Run("detached cleanup RPCs carry a bounded timeout so stalled cleanup never hangs login", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at",
			RefreshToken: "bob-rt",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      bobJWT,
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		p.cleanupTimeout = 45 * time.Millisecond
		_, _, wantFailure := configureCustomPages(t, p)

		deleteCalled := make(chan bool, 1)
		fake.mu.Lock()
		fake.setSecretKeyErr = map[string]error{
			SecretKeyMetadata: errors.New("metadata write failed"),
		}
		fake.deleteSecretFunc = func(ctx context.Context, _ string) error {
			_, hasDeadline := ctx.Deadline()
			select {
			case deleteCalled <- hasDeadline:
			default:
			}
			<-ctx.Done()
			return ctx.Err()
		}
		fake.mu.Unlock()

		browserCh := attachBrowserCallback(p, "STALLED-CLEANUP-CODE")
		started := time.Now()
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow: auth.FlowInteractive,
		}, nil)
		elapsed := time.Since(started)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "store_credentials")
		assert.Less(t, elapsed, 2*time.Second, "bounded cleanup timeout must prevent stalled DeleteSecret from hanging Login")

		hasDeadline := <-deleteCalled
		assert.True(t, hasDeadline, "detached cleanup context must carry an explicit timeout deadline")

		out := <-browserCh
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Equal(t, wantFailure, out.body)
	})
}
