// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
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

// advertisePasteBack marks the plugin as configured by a host that
// advertises the PromptAuthResponse capability (issue #66).
func advertisePasteBack(p *Plugin) {
	p.cfg.HostCapabilities = &sdkplugin.HostCapabilities{PromptAuthResponse: true}
}

// validPasteFromRequest builds the URL the user's browser lands on for the
// authorization request the plugin sent: the same redirect URI and state,
// with the given extra query parameters (code, error, ...).
func validPasteFromRequest(t *testing.T, req *proto.PromptAuthResponseRequest, extra url.Values) string {
	t.Helper()
	require.NotNil(t, req, "plugin must have called PromptAuthResponse")

	u, err := url.Parse(req.AuthorizationUrl)
	require.NoError(t, err)
	state := u.Query().Get("state")
	require.NotEmpty(t, state, "authorization URL must carry a state")

	q := url.Values{}
	for k, v := range extra {
		q[k] = v
	}
	q.Set("state", state)
	return req.RedirectUri + "/?" + q.Encode()
}

// tamperPaste rewrites the paste URL through mod before the user "pastes"
// it, keeping every other component the plugin sent intact.
func tamperPaste(t *testing.T, paste string, mod func(u *url.URL)) string {
	t.Helper()
	u, err := url.Parse(paste)
	require.NoError(t, err)
	mod(u)
	return u.String()
}

// pasteTokenResponse stubs the token endpoint for a successful exchange.
func pasteTokenResponse() *MockHTTPClient {
	httpMock := NewMockHTTPClient()
	httpMock.AddResponse(200, TokenResponse{
		AccessToken:  "paste-access-token",
		RefreshToken: "paste-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		IDToken: makeTestJWT(map[string]any{
			"sub":                "paste-subject",
			"oid":                "paste-oid",
			"tid":                "paste-tenant",
			"preferred_username": "paste-user",
		}),
	})
	return httpMock
}

// assertLoginStoredSession asserts the login stored credentials and served
// claims the same way the callback path does.
func assertLoginStoredSession(t *testing.T, p *Plugin, fake *fakeHostService) {
	t.Helper()
	assert.Equal(t, "paste-refresh-token", fake.secrets[SecretKeyRefreshToken])
	assert.Contains(t, fake.secrets, SecretKeyMetadata)

	st, err := p.GetStatus(context.Background(), HandlerName, sdkplugin.StatusRequest{})
	require.NoError(t, err)
	assert.True(t, st.Authenticated)
	require.NotNil(t, st.Claims)
	assert.Equal(t, "paste-subject", st.Claims.Subject)
	assert.Equal(t, auth.FlowInteractive, st.Flow)
}

// TestPasteBackValidRedirectCompletesLogin covers acceptance criterion 1: a
// valid pasted redirect completes login and stores credentials exactly like
// the callback path. The paste comes from the fake host (user pasted the
// address-bar URL), deviating only by surrounding whitespace and a dropped
// scheme, which must parse defensively.
func TestPasteBackValidRedirectCompletesLogin(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := pasteTokenResponse()
	p, fake := newTestPlugin(t, httpMock, nil)
	advertisePasteBack(p)
	p.openBrowser = func(_ context.Context, _ string) error { return nil }
	fake.promptFunc = func(_ context.Context, req *proto.PromptAuthResponseRequest) (string, error) {
		paste := validPasteFromRequest(t, req, url.Values{"code": {"PASTED-CODE"}, "session_state": {"live-evidence-param"}})
		return " \n" + strings.TrimPrefix(paste, "http://") + "  \n", nil
	}

	resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow: auth.FlowInteractive,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "paste-subject", resp.Claims.Subject)

	// The same code verifier and redirect URI must drive the exchange.
	reqs := httpMock.GetRequests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "authorization_code", reqs[0].Data.Get("grant_type"))
	assert.Equal(t, "PASTED-CODE", reqs[0].Data.Get("code"))
	redirect := reqs[0].Data.Get("redirect_uri")
	assert.True(t, strings.HasPrefix(redirect, "http://localhost:"), "exchange must reuse the callback redirect URI")

	assertLoginStoredSession(t, p, fake)
}

// TestPasteBackCallbackStillWins covers acceptance criterion 4: a real
// localhost callback that arrives first completes the login, and the paste
// prompt is canceled (desktop behavior unchanged).
func TestPasteBackCallbackStillWins(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := pasteTokenResponse()
	p, fake := newTestPlugin(t, httpMock, nil)
	advertisePasteBack(p)
	p.openBrowser = func(_ context.Context, authURL string) error {
		// The browser (on this machine) completes the redirect locally.
		au, err := url.Parse(authURL)
		require.NoError(t, err)
		state := au.Query().Get("state")
		redirect := au.Query().Get("redirect_uri")
		resp, err := http.Get(redirect + "/?code=REAL-CODE&state=" + url.QueryEscape(state)) //nolint:noctx // test helper hitting a local server
		require.NoError(t, err)
		_ = resp.Body.Close()
		return nil
	}
	promptCanceled := make(chan struct{})
	fake.promptFunc = func(ctx context.Context, _ *proto.PromptAuthResponseRequest) (string, error) {
		<-ctx.Done() // the paste never arrives first
		close(promptCanceled)
		return "", ctx.Err()
	}

	resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow: auth.FlowInteractive,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "paste-subject", resp.Claims.Subject)

	// The callback's code, not a paste, drove the exchange.
	reqs := httpMock.GetRequests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "REAL-CODE", reqs[0].Data.Get("code"))

	// The winning source canceled the paste prompt (whichever wins cancels
	// the rest).
	select {
	case <-promptCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("paste prompt goroutine was not canceled after the callback won")
	}
}

// TestPasteBackRejectedValues covers acceptance criterion 2: a wrong state
// or a wrong scheme, host, port, or path is rejected with a clear error.
func TestPasteBackRejectedValues(t *testing.T) {
	tests := []struct {
		name        string
		mod         func(u *url.URL)
		wantErrLens []string
	}{
		{
			name: "wrong state",
			mod: func(u *url.URL) {
				q := u.Query()
				q.Set("state", "TAMPERED-STATE")
				u.RawQuery = q.Encode()
			},
			wantErrLens: []string{
				"state mismatch",
			},
		},
		{
			name: "missing state",
			mod:  func(u *url.URL) { q := u.Query(); q.Del("state"); u.RawQuery = q.Encode() },
			wantErrLens: []string{
				"state mismatch",
			},
		},
		{
			name: "wrong scheme",
			mod:  func(u *url.URL) { u.Scheme = "https" },
			wantErrLens: []string{
				"does not match this login's callback URI",
			},
		},
		{
			name: "wrong host",
			mod:  func(u *url.URL) { u.Host = "evil.example.com:" + u.Port() },
			wantErrLens: []string{
				"does not match this login's callback URI",
			},
		},
		{
			name: "wrong port",
			mod:  func(u *url.URL) { u.Host = u.Hostname() + ":9999" },
			wantErrLens: []string{
				"does not match this login's callback URI",
			},
		},
		{
			name: "wrong path",
			mod:  func(u *url.URL) { u.Path = "/evil" },
			wantErrLens: []string{
				"does not match this login's callback URI",
			},
		},
		{
			name: "no code",
			mod:  func(u *url.URL) { q := u.Query(); q.Del("code"); u.RawQuery = q.Encode() },
			wantErrLens: []string{
				"no authorization code",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearCredentialEnv(t)

			// No token response stubbed: a rejected paste must fail the
			// login itself, never reach the exchange.
			p, fake := newTestPlugin(t, nil, nil)
			advertisePasteBack(p)
			p.openBrowser = func(_ context.Context, _ string) error { return nil }
			fake.promptFunc = func(_ context.Context, req *proto.PromptAuthResponseRequest) (string, error) {
				return tamperPaste(t, validPasteFromRequest(t, req, url.Values{"code": {"PASTED-CODE"}}), tt.mod), nil
			}

			started := time.Now()
			_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow:    auth.FlowInteractive,
				Timeout: 30 * time.Second,
			}, nil)
			require.Error(t, err)
			for _, want := range tt.wantErrLens {
				assert.Contains(t, err.Error(), want)
			}
			// Rejected promptly, not by the 30s timeout.
			assert.Less(t, time.Since(started), 10*time.Second)
		})
	}
}

// TestPasteBackNotAURL covers acceptance criterion 2's parse requirement:
// garbage that cannot parse as a URL fails cleanly.
func TestPasteBackNotAURL(t *testing.T) {
	clearCredentialEnv(t)

	p, fake := newTestPlugin(t, nil, nil)
	advertisePasteBack(p)
	p.openBrowser = func(_ context.Context, _ string) error { return nil }
	fake.promptFunc = func(_ context.Context, _ *proto.PromptAuthResponseRequest) (string, error) {
		return "not a url at all", nil
	}

	_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow:    auth.FlowInteractive,
		Timeout: 30 * time.Second,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid URL")
}

// TestPasteBackErrorReported covers acceptance criterion 3: a pasted
// error= is sanitized and reported through the AADSTS hint machinery.
func TestPasteBackErrorReported(t *testing.T) {
	t.Run("AADSTS error is sanitized with hint", func(t *testing.T) {
		clearCredentialEnv(t)

		p, fake := newTestPlugin(t, nil, nil)
		advertisePasteBack(p)
		p.openBrowser = func(_ context.Context, _ string) error { return nil }
		fake.promptFunc = func(_ context.Context, req *proto.PromptAuthResponseRequest) (string, error) {
			return validPasteFromRequest(t, req, url.Values{
				"error": {"access_denied"},
				// ESC-delimited: stripping the control characters must
				// yield the clean text.
				"error_description": {"AADSTS700016: \x1bapp not found\x1b"},
			}), nil
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowInteractive,
			Timeout: 30 * time.Second,
		}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OAuth error: access_denied: AADSTS700016: app not found")
		assert.Contains(t, err.Error(), "Hint: the application was not found")
		assert.NotContains(t, err.Error(), "\x1b", "control characters must be stripped")
	})

	t.Run("plain error passthrough", func(t *testing.T) {
		clearCredentialEnv(t)

		p, fake := newTestPlugin(t, nil, nil)
		advertisePasteBack(p)
		p.openBrowser = func(_ context.Context, _ string) error { return nil }
		fake.promptFunc = func(_ context.Context, req *proto.PromptAuthResponseRequest) (string, error) {
			return validPasteFromRequest(t, req, url.Values{
				"error":             {"access_denied"},
				"error_description": {"user declined consent"},
			}), nil
		}

		_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
			Flow:    auth.FlowInteractive,
			Timeout: 30 * time.Second,
		}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "entra: auth_code: OAuth error: access_denied: user declined consent")
	})
}

// TestPasteBackUnsupportedHostsUnchanged covers acceptance criterion 5: an
// older host (Unimplemented) or a non-interactive host (Unavailable)
// changes nothing -- the flow keeps waiting for the callback exactly as
// before, and still times out cleanly.
func TestPasteBackUnsupportedHostsUnchanged(t *testing.T) {
	promptErrs := map[string]error{
		"unimplemented older host":         status.Error(codes.Unimplemented, "PromptAuthResponse not implemented"),
		"unavailable non-interactive host": status.Error(codes.Unavailable, "host is non-interactive"),
	}

	for name, promptErr := range promptErrs {
		t.Run(name, func(t *testing.T) {
			clearCredentialEnv(t)

			// This plugin session has NOT been advertised paste-back; the
			// host client still answers the RPC with an error.
			httpMock := NewMockHTTPClient()
			p, fake := newTestPlugin(t, httpMock, nil)
			p.openBrowser = func(_ context.Context, _ string) error { return nil }
			fake.promptFunc = func(_ context.Context, _ *proto.PromptAuthResponseRequest) (string, error) {
				return "", promptErr
			}

			// No callback arrives; the error must be today's timeout
			// error, proving the wait continued after the prompt error.
			_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
				Flow:    auth.FlowInteractive,
				Timeout: 150 * time.Millisecond,
			}, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no response received from browser within")

			req, calls := fake.promptRequest()
			assert.Equal(t, 1, calls, "the plugin must have attempted the paste prompt once")
			assert.NotEmpty(t, req.GetRedirectUri(), "prompt request must carry the expected redirect URI")
		})
	}
}

// TestPasteBackHeadlessLoginSelectsInteractive covers acceptance criterion
// 6: headless plus host support -- a no-flag login selects interactive, and
// the paste completes the flow even though the browser cannot open.
func TestPasteBackHeadlessLoginSelectsInteractive(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := pasteTokenResponse()
	p, fake := newTestPlugin(t, httpMock, nil)
	advertisePasteBack(p)
	p.headlessReason = func() string { return "no DISPLAY or WAYLAND_DISPLAY (headless session)" }
	p.openBrowser = func(_ context.Context, _ string) error {
		return errors.New("xdg-open: not found") // headless: no browser
	}
	fake.promptFunc = func(_ context.Context, req *proto.PromptAuthResponseRequest) (string, error) {
		return validPasteFromRequest(t, req, url.Values{"code": {"PASTED-CODE"}}), nil
	}

	ctx, logLines := capturingLogger()
	resp, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil) // no flag at all
	require.NoError(t, err)
	assert.Equal(t, "paste-subject", resp.Claims.Subject)

	// Interactive ran to completion; no device code was started.
	assert.NotContains(t, strings.Join(*logLines, "\n"), "falling back to device code")
	reqs := httpMock.GetRequests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "authorization_code", reqs[0].Data.Get("grant_type"))
	assert.Equal(t, "PASTED-CODE", reqs[0].Data.Get("code"))
}

// TestPasteBackHeadlessWithoutSupportKeepsFallback covers acceptance
// criterion 6's other half: headless without host support keeps the #62
// behavior (fall back to device code on a no-flag login).
func TestPasteBackHeadlessWithoutSupportKeepsFallback(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, _ := newTestPlugin(t, httpMock, nil)
	p.headlessReason = func() string { return "no DISPLAY or WAYLAND_DISPLAY (headless session)" }
	p.openBrowser = func(_ context.Context, _ string) error {
		return errors.New("xdg-open: not found")
	}

	ctx, logLines := capturingLogger()
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
	require.Error(t, err)
	require.Len(t, httpMock.GetRequests(), 1)
	assert.Contains(t, httpMock.GetRequests()[0].Endpoint, "/oauth2/v2.0/devicecode")
	assert.Contains(t, strings.Join(*logLines, "\n"), "falling back to device code")
}

// TestPasteBackBrowserAndPromptFailureFallsBack: with a display detected,
// an implicit login whose browser open AND paste prompt both fail has no
// way to receive a code, so it falls back to device code.
func TestPasteBackBrowserAndPromptFailureFallsBack(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, fake := newTestPlugin(t, httpMock, nil)
	advertisePasteBack(p)
	p.openBrowser = func(_ context.Context, _ string) error { return errors.New("no opener") }
	fake.promptFunc = func(_ context.Context, _ *proto.PromptAuthResponseRequest) (string, error) {
		return "", status.Error(codes.Unavailable, "host is non-interactive")
	}

	ctx, logLines := capturingLogger()
	_, err := p.interactiveLogin(ctx, sdkplugin.LoginRequest{Timeout: time.Minute}, nil, true, "")
	require.Error(t, err) // no device code mock response configured
	assert.Contains(t, err.Error(), "device_code_request")
	assert.Contains(t, strings.Join(*logLines, "\n"), "falling back to device code")
}

// TestPasteBackHeadlessDetectAvailableFlowsOrdering covers acceptance
// criterion 6's host-facing half: with host support, interactive stays
// first in the flow list even on headless sessions; an explicit device_code
// preference still wins. Without support, the #62 ordering is unchanged.
func TestPasteBackHeadlessDetectAvailableFlowsOrdering(t *testing.T) {
	headlessStub := func() string { return "no DISPLAY or WAYLAND_DISPLAY (headless session)" }

	t.Run("host support keeps interactive first on headless", func(t *testing.T) {
		clearCredentialEnv(t)
		p, _ := newTestPlugin(t, nil, nil)
		advertisePasteBack(p)
		p.headlessReason = headlessStub

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.Equal(t, auth.FlowInteractive, firstAvailableFlow(t, flows))

		var interactive *sdkplugin.FlowAvailability
		for i := range flows {
			if flows[i].Flow == auth.FlowInteractive {
				interactive = &flows[i]
			}
		}
		require.NotNil(t, interactive)
		assert.NotContains(t, interactive.Reason, "requires a browser",
			"a paste-back-capable host makes interactive usable on headless sessions")
	})

	t.Run("host support honors defaultFlow device_code", func(t *testing.T) {
		clearCredentialEnv(t)
		p, _ := newTestPlugin(t, nil, nil)
		advertisePasteBack(p)
		p.headlessReason = headlessStub
		p.config.DefaultFlow = string(auth.FlowDeviceCode)

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.Equal(t, auth.FlowDeviceCode, firstAvailableFlow(t, flows))
	})

	t.Run("no host support keeps #62 ordering on headless", func(t *testing.T) {
		clearCredentialEnv(t)
		p, _ := newTestPlugin(t, nil, nil)
		p.headlessReason = headlessStub

		flows, err := p.DetectAvailableFlows(context.Background(), HandlerName)
		require.NoError(t, err)
		assert.Equal(t, auth.FlowDeviceCode, firstAvailableFlow(t, flows))
	})
}

// TestPasteBackHeadlessPromptFailureFallsBack: a host that advertised
// paste-back but whose prompt fails at runtime must not strand an implicit
// headless login on the unreachable callback; it falls back to device code.
func TestPasteBackHeadlessPromptFailureFallsBack(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, fake := newTestPlugin(t, httpMock, nil)
	advertisePasteBack(p)
	p.openBrowser = func(_ context.Context, _ string) error { return nil }
	fake.promptFunc = func(_ context.Context, _ *proto.PromptAuthResponseRequest) (string, error) {
		return "", status.Error(codes.Unavailable, "host is non-interactive")
	}

	ctx, logLines := capturingLogger()
	_, err := p.interactiveLogin(ctx, sdkplugin.LoginRequest{Timeout: time.Minute}, nil, true,
		"no DISPLAY or WAYLAND_DISPLAY (headless session)")
	require.Error(t, err) // no device code mock response configured
	assert.Contains(t, err.Error(), "device_code_request")
	assert.Contains(t, strings.Join(*logLines, "\n"), "falling back to device code")
}

// TestPasteBackHostResolvedLoginFallsBackOnPromptFailure: the host passes a
// no-flag login's resolved flow back as req.Flow, so a headless paste-back
// session arrives at interactiveLogin via FlowInteractive. That
// host-resolved login must stay fallback-eligible: a runtime prompt failure
// diverts to device code instead of waiting out the unreachable callback.
// Covers the gap the empty-Flow tests leave (both review threads on PR #67).
func TestPasteBackHostResolvedLoginFallsBackOnPromptFailure(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, fake := newTestPlugin(t, httpMock, nil)
	advertisePasteBack(p)
	p.headlessReason = func() string { return "no DISPLAY or WAYLAND_DISPLAY (headless session)" }
	p.openBrowser = func(_ context.Context, _ string) error {
		return errors.New("xdg-open: not found")
	}
	fake.promptFunc = func(_ context.Context, _ *proto.PromptAuthResponseRequest) (string, error) {
		return "", status.Error(codes.Unavailable, "host is non-interactive")
	}

	ctx, logLines := capturingLogger()
	// req.Flow carries the host-resolved interactive flow, not a user flag.
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{
		Flow:    auth.FlowInteractive,
		Timeout: 30 * time.Second,
	}, nil)
	require.Error(t, err) // no device code mock response configured
	assert.Contains(t, err.Error(), "device_code_request")
	assert.Contains(t, strings.Join(*logLines, "\n"), "falling back to device code")
}

// TestPasteBackHostResolvedLoginCompletesViaPaste: the same host-resolved
// headless Login with a working prompt completes via the paste and never
// diverts to device code.
func TestPasteBackHostResolvedLoginCompletesViaPaste(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := pasteTokenResponse()
	p, fake := newTestPlugin(t, httpMock, nil)
	advertisePasteBack(p)
	p.headlessReason = func() string { return "no DISPLAY or WAYLAND_DISPLAY (headless session)" }
	p.openBrowser = func(_ context.Context, _ string) error {
		return errors.New("xdg-open: not found")
	}
	fake.promptFunc = func(_ context.Context, req *proto.PromptAuthResponseRequest) (string, error) {
		return validPasteFromRequest(t, req, url.Values{"code": {"PASTED-CODE"}}), nil
	}

	resp, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{
		Flow: auth.FlowInteractive,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "paste-subject", resp.Claims.Subject)
	reqs := httpMock.GetRequests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "PASTED-CODE", reqs[0].Data.Get("code"))
}

// TestPasteBackDisplayKeepsExplicitInteractiveSemantics: with a display
// detected, an interactive login whose prompt fails keeps the explicit
// wait for the callback (the callback can plausibly arrive on a desktop)
// -- no divert to device code.
func TestPasteBackDisplayKeepsExplicitInteractiveSemantics(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, fake := newTestPlugin(t, httpMock, nil)
	advertisePasteBack(p)
	p.headlessReason = func() string { return "" } // display: callback plausible
	p.openBrowser = func(_ context.Context, _ string) error { return nil }
	fake.promptFunc = func(_ context.Context, _ *proto.PromptAuthResponseRequest) (string, error) {
		return "", status.Error(codes.Unavailable, "host is non-interactive")
	}

	ctx, logLines := capturingLogger()
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{
		Flow:    auth.FlowInteractive,
		Timeout: 150 * time.Millisecond,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no response received from browser within")
	assert.NotContains(t, strings.Join(*logLines, "\n"), "falling back to device code")
}
