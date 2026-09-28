// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturingLogger returns a context whose logger records formatted messages
// into the returned slice, so tests can assert user-facing V(0) notices.
func capturingLogger() (context.Context, *[]string) {
	var lines []string
	lgr := funcr.New(func(_, args string) { lines = append(lines, args) }, funcr.Options{})
	return logr.NewContext(context.Background(), lgr), &lines
}

func TestBrowserUnavailableReason(t *testing.T) {
	getenv := func(vars map[string]string) func(string) string {
		return func(k string) string { return vars[k] }
	}

	tests := []struct {
		name string
		goos string
		vars map[string]string
		want string // "" means a browser is plausible
	}{
		{"linux without display or wayland", "linux", nil, "no DISPLAY or WAYLAND_DISPLAY"},
		{"linux with DISPLAY", "linux", map[string]string{"DISPLAY": ":0"}, ""},
		{"linux with wayland only", "linux", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, ""},
		{"darwin without display env", "darwin", nil, ""},
		{"windows", "windows", nil, ""},
		{"ssh session without X forwarding", "linux", map[string]string{"SSH_CONNECTION": "10.0.0.1 5000 10.0.0.2 22"}, "no DISPLAY or WAYLAND_DISPLAY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := browserUnavailableReason(tt.goos, getenv(tt.vars))
			if tt.want == "" {
				assert.Empty(t, got)
			} else {
				assert.Contains(t, got, tt.want)
			}
		})
	}
}

// TestImplicitLoginDefaultInteractive covers acceptance criterion 1: no
// flow, no env credentials, no config -> browser-based interactive flow.
func TestImplicitLoginDefaultInteractive(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, _ := newTestPlugin(t, httpMock, nil)
	// A browser is available for the up-front check; the callback probe
	// drives the flow to its error.
	p.headlessReason = func() string { return "" }
	var gotPort string
	p.openBrowser = func(_ context.Context, authURL string) error {
		gotPort = probeCallback(t, authURL)
		return nil
	}

	// No Flow given: Login resolves to the interactive default, opens the
	// browser, and waits on the local callback.
	_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{}, nil)
	require.Error(t, err) // probed callback without a code -> flow error
	assert.Contains(t, err.Error(), "no authorization code received")
	assert.NotEmpty(t, gotPort, "browser must open against a local callback server")

	// The device code flow must not have been started.
	assert.Empty(t, httpMock.GetRequests())
}

// TestImplicitLoginBrowserFailureFallsBack covers acceptance criterion 2
// via the in-flight trigger: opening the browser fails on the implicit
// flow -> device code with a notice.
func TestImplicitLoginBrowserFailureFallsBack(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, _ := newTestPlugin(t, httpMock, nil)
	// Headless detection is quiet; this test drives the browser-open
	// failure path.
	p.headlessReason = func() string { return "" }
	p.openBrowser = func(_ context.Context, _ string) error {
		return errors.New("xdg-open: not found")
	}

	ctx, logLines := capturingLogger()
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{}, nil)
	require.Error(t, err) // no device code mock response configured
	assert.Contains(t, err.Error(), "device_code_request")
	assert.Contains(t, strings.Join(*logLines, "\n"), "falling back to device code")

	// The auth-code flow was abandoned for the device code flow.
	requests := httpMock.GetRequests()
	require.NotEmpty(t, requests)
	assert.Contains(t, requests[0].Endpoint, "/oauth2/v2.0/devicecode")
}

// TestImplicitLoginHeadlessFallsBackUpFront exercises interactiveLogin's
// up-front headless branch directly: the Linux no-DISPLAY signal cannot be
// forced portably through Login on every platform.
func TestImplicitLoginHeadlessFallsBackUpFront(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, _ := newTestPlugin(t, httpMock, nil)
	browserOpened := false
	p.openBrowser = func(_ context.Context, _ string) error {
		browserOpened = true
		return nil
	}

	ctx, logLines := capturingLogger()
	_, err := p.interactiveLogin(ctx, sdkplugin.LoginRequest{}, nil, true,
		"no DISPLAY or WAYLAND_DISPLAY (headless session)")
	require.Error(t, err) // no device code mock response configured
	assert.Contains(t, err.Error(), "device_code_request")
	assert.Contains(t, strings.Join(*logLines, "\n"), "falling back to device code")
	assert.False(t, browserOpened, "headless detection diverts before any browser attempt")

	requests := httpMock.GetRequests()
	require.NotEmpty(t, requests)
	assert.Contains(t, requests[0].Endpoint, "/oauth2/v2.0/devicecode")
}

// TestExplicitInteractiveDoesNotFallBack: browser-open failure on an
// explicit --flow interactive keeps the manual-open wait instead of
// diverting to device code.
func TestExplicitInteractiveDoesNotFallBack(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, _ := newTestPlugin(t, httpMock, nil)
	// Even a headless session must not divert an explicit flow.
	p.headlessReason = func() string { return "no DISPLAY or WAYLAND_DISPLAY (headless session)" }
	p.openBrowser = func(_ context.Context, _ string) error {
		return errors.New("no browser")
	}

	ctx, logLines := capturingLogger()
	_, err := p.Login(ctx, HandlerName, sdkplugin.LoginRequest{
		Flow:    auth.FlowInteractive,
		Timeout: 100 * time.Millisecond,
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no response received from browser within")
	assert.NotContains(t, strings.Join(*logLines, "\n"), "falling back to device code")

	// The device code flow must not have been started.
	assert.Empty(t, httpMock.GetRequests())
}

// TestDefaultFlowDeviceCodeStillSelected covers acceptance criterion 3:
// defaultFlow: device_code in config still selects device code when no
// --flow is passed.
func TestDefaultFlowDeviceCodeStillSelected(t *testing.T) {
	clearCredentialEnv(t)

	httpMock := NewMockHTTPClient()
	p, _ := newTestPlugin(t, httpMock, nil)
	p.config.DefaultFlow = string(auth.FlowDeviceCode)

	_, err := p.Login(context.Background(), HandlerName, sdkplugin.LoginRequest{}, nil)
	require.Error(t, err) // no device code mock response configured
	assert.Contains(t, err.Error(), "device_code_request")

	requests := httpMock.GetRequests()
	require.NotEmpty(t, requests)
	assert.Contains(t, requests[0].Endpoint, "/oauth2/v2.0/devicecode")
}
