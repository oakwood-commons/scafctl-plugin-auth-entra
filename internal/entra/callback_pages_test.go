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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
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

		require.NoError(t, p.logoutIfSessionMatches(context.Background(), sessionID))

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

		require.NoError(t, p.logoutIfSessionMatches(context.Background(), sessionID))

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

		require.NoError(t, p.logoutIfSessionMatches(context.Background(), sessionID))

		fake.mu.Lock()
		assert.Equal(t, "bob-rt", fake.secrets[SecretKeyRefreshToken])
		assert.Contains(t, fake.secrets, SecretKeyTokenPrefix+"cached-graph")
		fake.mu.Unlock()
	})

	t.Run("matching SessionID deletes session when metadata is readable and valid", func(t *testing.T) {
		p, fake, sessionID := seedBobSession(t)

		require.NoError(t, p.logoutIfSessionMatches(context.Background(), sessionID))

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

	t.Run("post-commit SetSecret error or uncertain metadata read preserves active refresh token revision", func(t *testing.T) {
		aliceJWT := makeTestJWT(map[string]any{
			"sub":                "alice-sub",
			"oid":                "alice-oid",
			"tid":                "alice-tid",
			"preferred_username": "alice@example.com",
		})

		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-1",
			RefreshToken: "alice-rt-committed",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-refreshed",
			RefreshToken: "alice-rt-committed",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})

		p, fake := newTestPlugin(t, httpMock, nil)
		configureCustomPages(t, p)

		// Simulate a gRPC deadline error arriving AFTER the host already persisted SecretKeyMetadata.
		committedThenErrored := false
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, name, value string) error {
			if name == SecretKeyMetadata && !committedThenErrored {
				committedThenErrored = true
				fake.mu.Lock()
				fake.secrets[name] = value
				fake.mu.Unlock()
				return errors.New("rpc error: code = DeadlineExceeded desc = context deadline exceeded after write")
			}
			return nil
		}
		fake.mu.Unlock()

		browserCh := attachBrowserCallback(p, "POST-COMMIT-ERR-CODE")
		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "alice-tid",
		}, nil)
		require.Error(t, err)
		<-browserCh

		// Because metadata actually committed on the host before the RPC error,
		// verRefreshKey MUST NOT have been deleted -- the profile remains usable.
		st, statusErr := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, statusErr)
		require.True(t, st.Authenticated, "committed metadata must keep its versioned refresh token")
		assert.Equal(t, "alice-sub", st.Claims.Subject)

		tokResp, tokErr := p.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://graph.microsoft.com/.default",
			ForceRefresh: true,
		})
		require.NoError(t, tokErr)
		assert.Equal(t, "alice-at-refreshed", tokResp.AccessToken)

		// Also verify that if rollback's GetSecret(metadataKey) itself fails with an
		// uncertain error, verRefreshKey is preserved rather than blindly deleted.
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "bob-at-uncertain",
			RefreshToken: "bob-rt-uncertain",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			IDToken:      aliceJWT,
		})
		var readAfterErr bool
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, name, _ string) error {
			if name == SecretKeyMetadata {
				readAfterErr = true
				return errors.New("uncertain metadata write error")
			}
			return nil
		}
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata && readAfterErr {
				return errors.New("transient metadata read failure during rollback")
			}
			return nil
		}
		fake.mu.Unlock()

		browserCh2 := attachBrowserCallback(p, "UNCERTAIN-READ-CODE")
		_, err = p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:     auth.FlowInteractive,
			TenantID: "alice-tid",
		}, nil)
		require.Error(t, err)
		<-browserCh2

		fake.mu.Lock()
		fake.setSecretFunc = nil
		fake.getSecretFunc = nil
		var retainedUncertain bool
		for k, v := range fake.secrets {
			if strings.HasPrefix(k, SecretKeyRefreshToken+".") && v == "bob-rt-uncertain" {
				retainedUncertain = true
			}
		}
		fake.mu.Unlock()
		assert.True(t, retainedUncertain, "uncertain metadata read during rollback must preserve candidate refresh token revision")
	})

	t.Run("two overlapping successful writes across processes keep pending revisions safe and sweep aged orphans later", func(t *testing.T) {
		aliceJWT := makeTestJWT(map[string]any{"sub": "alice-sub", "oid": "alice-oid", "tid": "tid-1"})
		bobJWT := makeTestJWT(map[string]any{"sub": "bob-sub", "oid": "bob-oid", "tid": "tid-1"})
		carolJWT := makeTestJWT(map[string]any{"sub": "carol-sub", "oid": "carol-oid", "tid": "tid-1"})
		daveJWT := makeTestJWT(map[string]any{"sub": "dave-sub", "oid": "dave-oid", "tid": "tid-1"})

		var nowMu sync.Mutex
		curNow := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
		nowFn := func() time.Time {
			nowMu.Lock()
			defer nowMu.Unlock()
			return curNow
		}
		advanceClock := func(d time.Duration) {
			nowMu.Lock()
			curNow = curNow.Add(d)
			nowMu.Unlock()
		}

		sharedFake := newFakeHostService()
		sharedHost := newFakeHostClient(sharedFake)

		newProcPlugin := func(mock *MockHTTPClient) *Plugin {
			pl := &Plugin{
				httpClient:        mock,
				nowFunc:           nowFn,
				orphanGracePeriod: 10 * time.Minute,
			}
			cfgCtx := sdkplugin.WithHostClient(context.Background(), sharedHost)
			require.NoError(t, pl.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))
			pl.httpClient = mock
			pl.headlessReason = func() string { return "" }
			return pl
		}

		// Seed initial session A.
		mockInit := NewMockHTTPClient()
		mockInit.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "at-a", RefreshToken: "rt-a", TokenType: "Bearer", ExpiresIn: 3600, IDToken: aliceJWT,
		})
		pInit := newProcPlugin(mockInit)
		chInit := attachBrowserCallback(pInit, "CODE-A")
		_, err := pInit.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)
		<-chInit

		// Coordinate two separate plugin processes (p1 -> B, p2 -> C) so both
		// snapshot session A before either writes metadata, and BOTH succeed.
		p1Snapshotted := make(chan struct{})
		releaseP1Meta := make(chan struct{})
		var p1Once sync.Once
		sharedFake.mu.Lock()
		sharedFake.setSecretFunc = func(_ context.Context, name, value string) error {
			if name == SecretKeyMetadata && strings.Contains(value, "bob-sub") {
				p1Once.Do(func() { close(p1Snapshotted) })
				<-releaseP1Meta
			}
			return nil
		}
		sharedFake.mu.Unlock()

		mock1 := NewMockHTTPClient()
		mock1.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "at-b", RefreshToken: "rt-b", TokenType: "Bearer", ExpiresIn: 3600, IDToken: bobJWT,
		})
		p1 := newProcPlugin(mock1)
		ch1 := attachBrowserCallback(p1, "CODE-B")

		p1Done := make(chan error, 1)
		go func() {
			_, lErr := p1.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
			p1Done <- lErr
		}()
		<-p1Snapshotted

		// Also stage a fresh pending revision from a concurrent writer whose
		// metadata has not committed yet -- an immediate sweep MUST NOT delete it.
		pendingRevKey := pInit.versionedRefreshKey(context.Background(), pInit.formatRefreshRevisionID())
		sharedFake.mu.Lock()
		sharedFake.secrets[pendingRevKey] = "rt-pending-inflight"
		sharedFake.mu.Unlock()

		// Start p2 before releasing p1 so both p1 and p2 snapshot prevRevID == A.
		p2Snapshotted := make(chan struct{})
		releaseP2Meta := make(chan struct{})
		var p2Once sync.Once
		sharedFake.mu.Lock()
		sharedFake.setSecretFunc = func(_ context.Context, name, value string) error {
			if name == SecretKeyMetadata && strings.Contains(value, "carol-sub") {
				p2Once.Do(func() { close(p2Snapshotted) })
				<-releaseP2Meta
			}
			return nil
		}
		sharedFake.mu.Unlock()

		mock2 := NewMockHTTPClient()
		mock2.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "at-c", RefreshToken: "rt-c", TokenType: "Bearer", ExpiresIn: 3600, IDToken: carolJWT,
		})
		p2 := newProcPlugin(mock2)
		ch2 := attachBrowserCallback(p2, "CODE-C")
		p2Done := make(chan error, 1)
		go func() {
			_, lErr := p2.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
			p2Done <- lErr
		}()
		<-p2Snapshotted

		// Both p1 and p2 read prevRevID == A! Now commit B, then commit C.
		close(releaseP1Meta)
		require.NoError(t, <-p1Done)
		<-ch1

		close(releaseP2Meta)
		require.NoError(t, <-p2Done)
		<-ch2

		sharedFake.mu.Lock()
		sharedFake.setSecretFunc = nil
		// Immediately at T0: A was collected, C is active, and pendingRevKey MUST still exist!
		_, pendingStillThere := sharedFake.secrets[pendingRevKey]
		var hasA, hasB, hasC bool
		for k, v := range sharedFake.secrets {
			if strings.HasPrefix(k, SecretKeyRefreshToken+".") {
				switch v {
				case "rt-a":
					hasA = true
				case "rt-b":
					hasB = true
				case "rt-c":
					hasC = true
				}
			}
		}
		sharedFake.mu.Unlock()
		assert.False(t, hasA, "initial revision A must be collected immediately")
		assert.True(t, hasB, "recent revision B stays protected during orphanGracePeriod")
		assert.True(t, hasC, "winning revision C must be retained")
		assert.True(t, pendingStillThere, "immediate sweep must never delete another writer's fresh pending revision")

		// Advance clock past orphanGracePeriod (15m > 10m), stage a NEW fresh
		// pending revision at T0+15m, and trigger a rotation/login D -> aged
		// orphans (B and the abandoned T0 pending key) are collected while D
		// and the new T0+15m pending key remain intact!
		advanceClock(15 * time.Minute)
		freshPendingKey := pInit.versionedRefreshKey(context.Background(), pInit.formatRefreshRevisionID())
		sharedFake.mu.Lock()
		sharedFake.secrets[freshPendingKey] = "rt-fresh-pending"
		sharedFake.mu.Unlock()

		mock4 := NewMockHTTPClient()
		mock4.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "at-d", RefreshToken: "rt-d", TokenType: "Bearer", ExpiresIn: 3600, IDToken: daveJWT,
		})
		p4 := newProcPlugin(mock4)
		ch4 := attachBrowserCallback(p4, "CODE-D")
		_, err = p4.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
		require.NoError(t, err)
		<-ch4

		sharedFake.mu.Lock()
		var remainingVersioned []string
		for k, v := range sharedFake.secrets {
			if strings.HasPrefix(k, SecretKeyRefreshToken+".") {
				remainingVersioned = append(remainingVersioned, v)
			}
		}
		sharedFake.mu.Unlock()
		assert.ElementsMatch(t, []string{"rt-d", "rt-fresh-pending"}, remainingVersioned,
			"deferred sweep must collect aged orphaned revisions (rt-b and stale pending) while keeping active rt-d and fresh pending revision")
	})

	t.Run("canceled readers and writers waiting behind a blocked profileLock return promptly", func(t *testing.T) {
		clearCredentialEnv(t)

		aliceJWT := makeTestJWT(map[string]any{"sub": "alice-sub", "oid": "alice-oid", "tid": "tid-1"})
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken: "at-1", RefreshToken: "rt-1", TokenType: "Bearer", ExpiresIn: 3600, IDToken: aliceJWT,
		})
		p, fake := newTestPlugin(t, httpMock, NewMockGraphClient())

		writeEntered := make(chan struct{})
		releaseWrite := make(chan struct{})
		var writeOnce sync.Once
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, _ string, _ string) error {
			writeOnce.Do(func() { close(writeEntered) })
			<-releaseWrite
			return nil
		}
		fake.mu.Unlock()

		ch := attachBrowserCallback(p, "LOCK-CODE")
		writerDone := make(chan struct{})
		writerErrCh := make(chan error, 1)
		t.Cleanup(func() {
			select {
			case <-releaseWrite:
			default:
				close(releaseWrite)
			}
			<-writerDone
		})
		go func() {
			defer close(writerDone)
			_, wErr := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{Flow: auth.FlowInteractive}, nil)
			writerErrCh <- wErr
		}()
		<-writeEntered

		// While the credential writer holds profileLock across SetSecret, all
		// read/write RPCs with short deadlines must abort on ctx.Done() promptly.
		started := time.Now()

		statusCtx, cancelStatus := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancelStatus()
		_, err := p.GetStatus(statusCtx, HandlerName, sdkplugin.StatusRequest{})
		require.ErrorIs(t, err, context.DeadlineExceeded)

		tokCtx, cancelTok := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancelTok()
		_, err = p.GetToken(tokCtx, HandlerName, sdkplugin.TokenRequest{Scope: "https://graph.microsoft.com/.default", ForceRefresh: true})
		require.ErrorIs(t, err, context.DeadlineExceeded)

		grpCtx, cancelGrp := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancelGrp()
		_, err = p.GetGroups(grpCtx, HandlerName)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		listCtx, cancelList := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancelList()
		_, err = p.ListCachedTokens(listCtx, HandlerName)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		purgeCtx, cancelPurge := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancelPurge()
		_, err = p.PurgeExpiredTokens(purgeCtx, HandlerName)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		logoutCtx, cancelLogout := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancelLogout()
		err = p.Logout(logoutCtx, HandlerName, sdkplugin.LogoutRequest{})
		require.ErrorIs(t, err, context.DeadlineExceeded)

		assert.Less(t, time.Since(started), 5*time.Second, "canceled callers must not block behind stalled profileLock holder")

		close(releaseWrite)
		require.NoError(t, <-writerErrCh)
		<-ch

		st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		assert.True(t, st.Authenticated)
	})
}

type funcGraphClient struct {
	fn func(ctx context.Context, reqURL, bearerToken string) (*http.Response, error)
}

func (f *funcGraphClient) Get(ctx context.Context, reqURL, bearerToken string) (*http.Response, error) {
	return f.fn(ctx, reqURL, bearerToken)
}

func TestCrossProcessSessionRead_RetriesWhenRotationDeletesPreviousRevision(t *testing.T) {
	clearCredentialEnv(t)
	// Configure ambient service principal credentials so any false negative in
	// cross-process user-session loading would lose user-session precedence.
	t.Setenv(EnvAzureClientID, "ambient-sp-client")
	t.Setenv(EnvAzureTenantID, "ambient-sp-tenant")
	t.Setenv(EnvAzureClientSecret, "ambient-sp-secret")

	aliceJWT := makeTestJWT(map[string]any{
		"sub":                "alice-sub",
		"oid":                "alice-oid",
		"tid":                "alice-tid",
		"preferred_username": "alice@example.com",
	})

	newSharedProc := func(t *testing.T, sharedHost *sdkplugin.HostServiceClient, httpMock *MockHTTPClient, graph GraphClient) *Plugin {
		t.Helper()
		pl := &Plugin{
			httpClient:  httpMock,
			graphClient: graph,
		}
		cfgCtx := sdkplugin.WithHostClient(context.Background(), sharedHost)
		require.NoError(t, pl.ConfigureAuthHandler(cfgCtx, HandlerName, sdkplugin.ProviderConfig{BinaryName: "scafctl"}))
		pl.httpClient = httpMock
		if graph != nil {
			pl.graphClient = graph
		}
		return pl
	}

	seedAndFindVerKey := func(t *testing.T) (*fakeHostService, *sdkplugin.HostServiceClient, string) {
		t.Helper()
		sharedFake := newFakeHostService()
		sharedHost := newFakeHostClient(sharedFake)
		seeder := newSharedProc(t, sharedHost, NewMockHTTPClient(), nil)
		require.NoError(t, seeder.storeCredentials(
			context.Background(),
			"alice-tid",
			&TokenResponse{
				AccessToken:  "alice-at-v1",
				RefreshToken: "alice-rt-v1",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				IDToken:      aliceJWT,
			},
			seeder.config.ClientID,
			[]string{"openid", "profile", "offline_access"},
			auth.FlowInteractive,
			"alice-session",
		))
		var verKeyA string
		sharedFake.mu.Lock()
		for k, v := range sharedFake.secrets {
			if strings.HasPrefix(k, SecretKeyRefreshToken+".") && v == "alice-rt-v1" {
				verKeyA = k
				break
			}
		}
		sharedFake.mu.Unlock()
		require.NotEmpty(t, verKeyA)
		return sharedFake, sharedHost, verKeyA
	}

	// installRotationInterleaving pauses readerPlugin immediately after it has
	// loaded revision A's metadata (right as it reads verKeyA), runs a full
	// refresh-token rotation in writerPlugin (committing revision B, mirroring
	// rt-v2 to SecretKeyRefreshToken, and deleting verKeyA), and then resumes
	// readerPlugin so its verKeyA read observes the deleted revision.
	installRotationInterleaving := func(t *testing.T, sharedFake *fakeHostService, sharedHost *sdkplugin.HostServiceClient, verKeyA string) {
		t.Helper()
		writerMock := NewMockHTTPClient()
		writerMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-v2",
			RefreshToken: "alice-rt-v2",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
		writerPlugin := newSharedProc(t, sharedHost, writerMock, nil)

		var triggered atomic.Bool
		sharedFake.mu.Lock()
		sharedFake.getSecretFunc = func(_ context.Context, name string) error {
			if name == verKeyA && triggered.CompareAndSwap(false, true) {
				tok, rotErr := writerPlugin.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
					Scope:        "https://management.azure.com/.default",
					ForceRefresh: true,
				})
				require.NoError(t, rotErr)
				assert.Equal(t, "alice-at-v2", tok.AccessToken)
			}
			return nil
		}
		sharedFake.mu.Unlock()
	}

	t.Run("GetStatus retries paired read and preserves user session over ambient SP credentials", func(t *testing.T) {
		sharedFake, sharedHost, verKeyA := seedAndFindVerKey(t)
		installRotationInterleaving(t, sharedFake, sharedHost, verKeyA)

		readerPlugin := newSharedProc(t, sharedHost, NewMockHTTPClient(), nil)
		st, err := readerPlugin.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, auth.IdentityTypeUser, st.IdentityType, "user session must retain precedence over ambient SP credentials")
		assert.Equal(t, auth.FlowInteractive, st.Flow)
		require.NotNil(t, st.Claims)
		assert.Equal(t, "alice-sub", st.Claims.Subject)

		sharedFake.mu.Lock()
		_, verAExists := sharedFake.secrets[verKeyA]
		legacyVal := sharedFake.secrets[SecretKeyRefreshToken]
		sharedFake.mu.Unlock()
		assert.False(t, verAExists, "writer rotation must have deleted superseded revision A")
		assert.Equal(t, "alice-rt-v2", legacyVal)
	})

	t.Run("GetToken retries paired read and refreshes with rotated revision B token", func(t *testing.T) {
		sharedFake, sharedHost, verKeyA := seedAndFindVerKey(t)
		installRotationInterleaving(t, sharedFake, sharedHost, verKeyA)

		readerMock := NewMockHTTPClient()
		readerMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-v3",
			RefreshToken: "alice-rt-v2",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
		readerPlugin := newSharedProc(t, sharedHost, readerMock, nil)

		tok, err := readerPlugin.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://graph.microsoft.com/.default",
			ForceRefresh: true,
		})
		require.NoError(t, err)
		assert.Equal(t, "alice-at-v3", tok.AccessToken)
		assert.Equal(t, auth.FlowInteractive, tok.Flow)

		reqs := readerMock.GetRequests()
		require.Len(t, reqs, 1)
		assert.Equal(t, "refresh_token", reqs[0].Data.Get("grant_type"), "must use user refresh_token grant, never ambient SP client_credentials")
		assert.Equal(t, "alice-rt-v2", reqs[0].Data.Get("refresh_token"))
	})

	t.Run("GetGroups retries paired read and succeeds despite ambient SP credentials", func(t *testing.T) {
		sharedFake, sharedHost, verKeyA := seedAndFindVerKey(t)
		installRotationInterleaving(t, sharedFake, sharedHost, verKeyA)

		readerMock := NewMockHTTPClient()
		readerMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-graph-at",
			RefreshToken: "alice-rt-v2",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
		var seenBearer string
		graph := &funcGraphClient{
			fn: func(_ context.Context, _ string, bearerToken string) (*http.Response, error) {
				seenBearer = bearerToken
				return jsonTestResponse(http.StatusOK, map[string]any{
					"value": []map[string]string{{"id": "grp-eng"}, {"id": "grp-sec"}},
				}), nil
			},
		}
		readerPlugin := newSharedProc(t, sharedHost, readerMock, graph)

		groups, err := readerPlugin.GetGroups(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.Equal(t, []string{"grp-eng", "grp-sec"}, groups)
		assert.Equal(t, "alice-graph-at", seenBearer)
	})

	t.Run("legacy fallback hash mismatch caused by concurrent rotation retries and succeeds", func(t *testing.T) {
		sharedFake, sharedHost, verKeyA := seedAndFindVerKey(t)
		// Simulate a state where verKeyA was already absent so the reader falls
		// back to SecretKeyRefreshToken, and a concurrent rotation commits B
		// right before SecretKeyRefreshToken is read.
		sharedFake.mu.Lock()
		delete(sharedFake.secrets, verKeyA)
		sharedFake.mu.Unlock()

		writerMock := NewMockHTTPClient()
		writerMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-v2",
			RefreshToken: "alice-rt-v2",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
		writerPlugin := newSharedProc(t, sharedHost, writerMock, nil)

		var triggered atomic.Bool
		sharedFake.mu.Lock()
		sharedFake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyRefreshToken && triggered.CompareAndSwap(false, true) {
				_, rotErr := writerPlugin.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
					Scope:        "https://management.azure.com/.default",
					ForceRefresh: true,
				})
				require.NoError(t, rotErr)
			}
			return nil
		}
		sharedFake.mu.Unlock()

		readerPlugin := newSharedProc(t, sharedHost, NewMockHTTPClient(), nil)
		st, err := readerPlugin.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, err)
		require.True(t, st.Authenticated)
		assert.Equal(t, auth.IdentityTypeUser, st.IdentityType)
		assert.Equal(t, "alice-sub", st.Claims.Subject)
	})

	t.Run("legacy metadata without refreshTokenSha256 retries when concurrent login replaces session", func(t *testing.T) {
		sharedFake := newFakeHostService()
		sharedHost := newFakeHostClient(sharedFake)

		legacyMeta := auth.HandlerMetadata{
			Claims:        &auth.Claims{Subject: "alice-legacy", TenantID: "alice-tid"},
			ExpiresAt:     time.Now().Add(time.Hour),
			LastRefresh:   time.Now(),
			LastLoginFlow: auth.FlowInteractive,
			SessionID:     "legacy-session",
			ClientID:      DefaultClientID,
		}
		legacyMeta.SetMeta(MetaKeyTenantID, "alice-tid")
		legacyBytes, err := json.Marshal(legacyMeta)
		require.NoError(t, err)
		sharedFake.secrets[SecretKeyMetadata] = string(legacyBytes)
		sharedFake.secrets[SecretKeyRefreshToken] = "alice-legacy-rt"

		bobJWT := makeTestJWT(map[string]any{"sub": "bob-new", "oid": "bob-oid", "tid": "bob-tid"})
		writerPlugin := newSharedProc(t, sharedHost, NewMockHTTPClient(), nil)

		var triggered atomic.Bool
		sharedFake.mu.Lock()
		sharedFake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyRefreshToken && triggered.CompareAndSwap(false, true) {
				require.NoError(t, writerPlugin.storeCredentials(
					context.Background(),
					"bob-tid",
					&TokenResponse{
						AccessToken:  "bob-at",
						RefreshToken: "bob-rt",
						TokenType:    "Bearer",
						ExpiresIn:    3600,
						IDToken:      bobJWT,
					},
					writerPlugin.config.ClientID,
					[]string{"openid", "profile", "offline_access"},
					auth.FlowInteractive,
					"bob-session",
				))
			}
			return nil
		}
		sharedFake.mu.Unlock()

		readerPlugin := newSharedProc(t, sharedHost, NewMockHTTPClient(), nil)
		rt, meta, loadErr := readerPlugin.loadSessionCredentials(context.Background())
		require.NoError(t, loadErr)
		assert.Equal(t, "bob-rt", rt, "must not pair Bob's refresh token with Alice's un-hashed legacy metadata")
		require.NotNil(t, meta)
		assert.Equal(t, "bob-new", meta.Claims.Subject)
	})

	t.Run("exhausting bounded read retries propagates transient concurrent-change error across public RPCs without ambient fallback", func(t *testing.T) {
		// Ambient SP credentials are already set above; also test with ambient
		// workload identity credentials so neither machine flow can mask an
		// actively rotating user session.
		for _, modeName := range []string{"ambient-service-principal", "ambient-workload-identity"} {
			t.Run(modeName, func(t *testing.T) {
				if modeName == "ambient-workload-identity" {
					t.Setenv(EnvAzureFederatedToken, "ambient-federated-jwt")
				}

				sharedFake, sharedHost, _ := seedAndFindVerKey(t)
				writerPlugin := newSharedProc(t, sharedHost, NewMockHTTPClient(), nil)

				var rotations atomic.Int32
				var inWriter atomic.Bool
				installExhaustingHook := func() {
					rotations.Store(0)
					sharedFake.mu.Lock()
					sharedFake.getSecretFunc = func(_ context.Context, name string) error {
						if strings.HasPrefix(name, SecretKeyRefreshToken+".") && !inWriter.Load() {
							n := rotations.Add(1)
							if int(n) <= maxSessionCredentialReadAttempts {
								inWriter.Store(true)
								defer inWriter.Store(false)
								require.NoError(t, writerPlugin.storeCredentials(
									context.Background(),
									"alice-tid",
									&TokenResponse{
										AccessToken:  "alice-at-rot",
										RefreshToken: "alice-rt-rot-" + string(rune('0'+n)),
										TokenType:    "Bearer",
										ExpiresIn:    3600,
										IDToken:      aliceJWT,
									},
									writerPlugin.config.ClientID,
									[]string{"openid", "profile", "offline_access"},
									auth.FlowInteractive,
									"alice-session",
								))
							}
						}
						return nil
					}
					sharedFake.mu.Unlock()
				}

				readerMock := NewMockHTTPClient()
				readerPlugin := newSharedProc(t, sharedHost, readerMock, NewMockGraphClient())

				installExhaustingHook()
				st, statusErr := readerPlugin.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
				require.ErrorIs(t, statusErr, errSessionCredentialsChangedConcurrently, "GetStatus must propagate transient contention error instead of ambient fallback")
				assert.Nil(t, st)

				installExhaustingHook()
				tok, tokErr := readerPlugin.GetToken(context.Background(), HandlerName, sdkplugin.TokenRequest{
					Scope:        "https://graph.microsoft.com/.default",
					ForceRefresh: true,
				})
				require.ErrorIs(t, tokErr, errSessionCredentialsChangedConcurrently, "GetToken must propagate transient contention error instead of minting ambient machine token")
				assert.Nil(t, tok)
				assert.Empty(t, readerMock.GetRequests(), "GetToken must not issue ambient SP/WI token requests")

				installExhaustingHook()
				groups, grpErr := readerPlugin.GetGroups(context.Background(), HandlerName)
				require.ErrorIs(t, grpErr, errSessionCredentialsChangedConcurrently, "GetGroups must propagate transient contention error instead of reporting unsupported machine flow")
				assert.Nil(t, groups)

				installExhaustingHook()
				cached, listErr := readerPlugin.ListCachedTokens(context.Background(), HandlerName)
				require.ErrorIs(t, listErr, errSessionCredentialsChangedConcurrently)
				assert.Nil(t, cached)
			})
		}
	})
}

func TestMidOperationCancellation_PropagatesContextError(t *testing.T) {
	clearCredentialEnv(t)

	aliceJWT := makeTestJWT(map[string]any{
		"sub":                "alice-sub",
		"oid":                "alice-oid",
		"tid":                "alice-tid",
		"preferred_username": "alice@example.com",
	})

	seedAlice := func(t *testing.T, httpMock *MockHTTPClient, nowFn func() time.Time) (*Plugin, *fakeHostService) {
		t.Helper()
		p, fake := newTestPlugin(t, httpMock, NewMockGraphClient())
		p.nowFunc = nowFn
		p.orphanGracePeriod = 10 * time.Minute
		require.NoError(t, p.storeCredentials(
			context.Background(),
			"alice-tid",
			&TokenResponse{
				AccessToken:  "alice-at-init",
				RefreshToken: "alice-rt-init",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				IDToken:      aliceJWT,
			},
			p.config.ClientID,
			[]string{"openid", "profile", "offline_access"},
			auth.FlowInteractive,
			"alice-session",
		))
		return p, fake
	}

	t.Run("mintToken rotation propagates cancellation during storeRotatedCredentials SetSecret", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusOK, TokenResponse{
			AccessToken:  "alice-at-rotated",
			RefreshToken: "alice-rt-rotated",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
		p, fake := seedAlice(t, httpMock, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var rotationWriteHit bool
		fake.mu.Lock()
		fake.setSecretFunc = func(_ context.Context, name, _ string) error {
			if strings.HasPrefix(name, SecretKeyRefreshToken+".") {
				rotationWriteHit = true
				cancel()
				return status.Error(codes.Canceled, "context canceled during rotation write")
			}
			return nil
		}
		fake.mu.Unlock()

		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://graph.microsoft.com/.default",
			ForceRefresh: true,
		})
		require.Error(t, err)
		assert.Nil(t, tok)
		assert.True(t, rotationWriteHit, "cancellation must trigger inside storeRotatedCredentials after HTTP refresh")
		assert.True(t, isContextErr(err), "expected context error, got %v", err)

		// Initial session must remain intact after pre-commit rotation cancellation.
		fake.mu.Lock()
		fake.setSecretFunc = nil
		fake.mu.Unlock()
		st, statusErr := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, statusErr)
		assert.True(t, st.Authenticated)
	})

	t.Run("mintToken rotation propagates cancellation during storeRotatedCredentials metadata check and legacy mirror", func(t *testing.T) {
		t.Run("during metadata GetSecret inside storeRotatedCredentials", func(t *testing.T) {
			httpMock := NewMockHTTPClient()
			httpMock.AddResponse(http.StatusOK, TokenResponse{
				AccessToken:  "alice-at-rotated",
				RefreshToken: "alice-rt-rotated",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			})
			p, fake := seedAlice(t, httpMock, nil)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// GetToken reads SecretKeyMetadata twice before rotation (inspectStoredSession +
			// loadSessionCredentials in mintToken); the 3rd read is inside storeRotatedCredentials.
			metaReads := 0
			fake.mu.Lock()
			fake.getSecretFunc = func(_ context.Context, name string) error {
				if name == SecretKeyMetadata {
					metaReads++
					if metaReads == 3 {
						cancel()
						return context.Canceled
					}
				}
				return nil
			}
			fake.mu.Unlock()

			tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
				Scope:        "https://graph.microsoft.com/.default",
				ForceRefresh: true,
			})
			require.ErrorIs(t, err, context.Canceled)
			assert.Nil(t, tok)
			assert.Equal(t, 3, metaReads)
		})

		t.Run("during legacy refresh token mirror SetSecret", func(t *testing.T) {
			httpMock := NewMockHTTPClient()
			httpMock.AddResponse(http.StatusOK, TokenResponse{
				AccessToken:  "alice-at-rotated",
				RefreshToken: "alice-rt-rotated",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			})
			p, fake := seedAlice(t, httpMock, nil)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			fake.mu.Lock()
			fake.setSecretFunc = func(_ context.Context, name, _ string) error {
				if name == SecretKeyRefreshToken {
					cancel()
					return context.DeadlineExceeded
				}
				return nil
			}
			fake.mu.Unlock()

			tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
				Scope:        "https://graph.microsoft.com/.default",
				ForceRefresh: true,
			})
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Nil(t, tok)
		})
	})

	t.Run("PurgeExpiredTokens propagates cancellation during ListSecrets GetSecret and DeleteSecret", func(t *testing.T) {
		baseTime := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

		seedSweepFixtures := func(t *testing.T) (*Plugin, *fakeHostService) {
			t.Helper()
			var mu sync.Mutex
			curNow := baseTime
			nowFn := func() time.Time {
				mu.Lock()
				defer mu.Unlock()
				return curNow
			}
			p, fake := seedAlice(t, NewMockHTTPClient(), nowFn)

			// Seed two aged orphan refresh revisions created at T0, then advance past grace period.
			orphan1 := p.versionedRefreshKey(context.Background(), p.formatRefreshRevisionID())
			orphan2 := p.versionedRefreshKey(context.Background(), p.formatRefreshRevisionID())
			expiredCacheKey := SecretKeyTokenPrefix + "expired-entry"
			expiredBytes, err := json.Marshal(tokenCacheEntry{
				AccessToken: "expired-at",
				TokenType:   "Bearer",
				ExpiresAt:   time.Now().Add(-1 * time.Hour),
				CachedAt:    time.Now().Add(-2 * time.Hour),
			})
			require.NoError(t, err)

			fake.mu.Lock()
			fake.secrets[orphan1] = "rt-orphan-1"
			fake.secrets[orphan2] = "rt-orphan-2"
			fake.secrets[expiredCacheKey] = string(expiredBytes)
			fake.mu.Unlock()

			mu.Lock()
			curNow = baseTime.Add(30 * time.Minute)
			mu.Unlock()
			return p, fake
		}

		t.Run("canceled during orphan sweep ListSecrets after access-token purge", func(t *testing.T) {
			p, fake := seedSweepFixtures(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var hitRefreshList bool
			fake.mu.Lock()
			fake.listSecretsFunc = func(_ context.Context, pattern string) error {
				if pattern == "^"+regexp.QuoteMeta(SecretKeyRefreshToken+".") {
					hitRefreshList = true
					cancel()
					return status.Error(codes.DeadlineExceeded, "deadline exceeded listing refresh revisions")
				}
				return nil
			}
			fake.mu.Unlock()

			purged, err := p.PurgeExpiredTokens(ctx, HandlerName)
			require.Error(t, err)
			assert.Zero(t, purged, "must not report a successful partial purge count on cancellation")
			assert.True(t, hitRefreshList)
			assert.True(t, isContextErr(err), "expected context error, got %v", err)
		})

		t.Run("canceled during orphan sweep metadata GetSecret", func(t *testing.T) {
			p, fake := seedSweepFixtures(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var hitMetaRead bool
			fake.mu.Lock()
			fake.getSecretFunc = func(_ context.Context, name string) error {
				if name == SecretKeyMetadata {
					hitMetaRead = true
					cancel()
					return context.Canceled
				}
				return nil
			}
			fake.mu.Unlock()

			purged, err := p.PurgeExpiredTokens(ctx, HandlerName)
			require.ErrorIs(t, err, context.Canceled)
			assert.Zero(t, purged)
			assert.True(t, hitMetaRead)
		})

		t.Run("canceled during orphan sweep DeleteSecret after deleting first orphan", func(t *testing.T) {
			p, fake := seedSweepFixtures(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			orphanDeletes := 0
			fake.mu.Lock()
			fake.deleteSecretFunc = func(_ context.Context, name string) error {
				if strings.HasPrefix(name, SecretKeyRefreshToken+".") {
					orphanDeletes++
					if orphanDeletes == 2 {
						cancel()
						return context.DeadlineExceeded
					}
				}
				return nil
			}
			fake.mu.Unlock()

			purged, err := p.PurgeExpiredTokens(ctx, HandlerName)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Zero(t, purged)
			assert.Equal(t, 2, orphanDeletes)
		})

		t.Run("canceled during cachePurgeExpired DeleteSecret", func(t *testing.T) {
			p, fake := seedSweepFixtures(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			fake.mu.Lock()
			fake.deleteSecretFunc = func(_ context.Context, name string) error {
				if strings.HasPrefix(name, SecretKeyTokenPrefix) {
					cancel()
					return context.Canceled
				}
				return nil
			}
			fake.mu.Unlock()

			purged, err := p.PurgeExpiredTokens(ctx, HandlerName)
			require.ErrorIs(t, err, context.Canceled)
			assert.Zero(t, purged)
		})
	})

	t.Run("ListCachedTokens and Logout propagate mid-operation cancellation", func(t *testing.T) {
		p, fake := seedAlice(t, NewMockHTTPClient(), nil)
		entryBytes, err := json.Marshal(tokenCacheEntry{
			AccessToken: "cached-at",
			TokenType:   "Bearer",
			ExpiresAt:   time.Now().Add(time.Hour),
			CachedAt:    time.Now(),
		})
		require.NoError(t, err)
		fake.mu.Lock()
		fake.secrets[SecretKeyTokenPrefix+"k1"] = string(entryBytes)
		fake.mu.Unlock()

		listCtx, cancelList := context.WithCancel(context.Background())
		defer cancelList()
		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if strings.HasPrefix(name, SecretKeyTokenPrefix) {
				cancelList()
				return context.Canceled
			}
			return nil
		}
		fake.mu.Unlock()

		entries, err := p.ListCachedTokens(listCtx, HandlerName)
		require.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, entries)

		fake.mu.Lock()
		fake.getSecretFunc = nil
		logoutCtx, cancelLogout := context.WithCancel(context.Background())
		defer cancelLogout()
		fake.deleteSecretFunc = func(_ context.Context, name string) error {
			if strings.HasPrefix(name, SecretKeyTokenPrefix) {
				cancelLogout()
				return context.DeadlineExceeded
			}
			return nil
		}
		fake.mu.Unlock()

		err = p.Logout(logoutCtx, HandlerName, sdkplugin.LogoutRequest{})
		require.ErrorIs(t, err, context.DeadlineExceeded)

		fake.mu.Lock()
		fake.deleteSecretFunc = nil
		fake.mu.Unlock()

		st, statusErr := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
		require.NoError(t, statusErr)
		assert.False(t, st.Authenticated, "session must be logged out even when post-metadata cache sweep was canceled")

		remaining, listErr := p.ListCachedTokens(context.Background(), HandlerName)
		require.NoError(t, listErr)
		for _, item := range remaining {
			assert.NotEqual(t, "refresh", item.TokenKind, "canceled Logout must not leave a legacy refresh-token split-brain entry")
		}
	})

	t.Run("mintToken invalid_grant propagates cancellation from logoutIfSessionMatches including stringified host errors", func(t *testing.T) {
		httpMock := NewMockHTTPClient()
		httpMock.AddResponse(http.StatusBadRequest, TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "refresh token expired",
		})
		p, fake := seedAlice(t, httpMock, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Simulate scafctl HostServiceServer stringifying a canceled SecretStore
		// error inside GetSecretResponse.Error (plain string error, no gRPC status)
		// on the 3rd metadata read (inside logoutIfSessionMatches).
		metaReads := 0
		fake.mu.Lock()
		fake.getSecretFunc = func(_ context.Context, name string) error {
			if name == SecretKeyMetadata {
				metaReads++
				if metaReads == 3 {
					cancel()
					return errors.New("host GetSecret: context canceled")
				}
			}
			return nil
		}
		fake.mu.Unlock()

		tok, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{
			Scope:        "https://graph.microsoft.com/.default",
			ForceRefresh: true,
		})
		require.ErrorIs(t, err, context.Canceled, "must return context.Canceled rather than 'token expired'")
		assert.Nil(t, tok)
		assert.Equal(t, 3, metaReads)
	})
}
