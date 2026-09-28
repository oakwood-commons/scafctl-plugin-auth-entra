// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"errors"
	"os"
	"runtime"

	"github.com/go-logr/logr"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// errBrowserUnavailable is returned by the auth-code flow when opening the
// browser failed and the caller marked the browser as required, so the
// caller can fall back to device code.
var errBrowserUnavailable = errors.New("cannot open a browser")

// errPromptUnavailable is returned by the auth-code flow when the host's
// paste-back prompt failed on a login that depends on it (implicit and
// headless), so the caller can fall back to device code.
var errPromptUnavailable = errors.New("host paste-back prompt unavailable")

// defaultHeadlessReason reports why a browser cannot be opened on this
// machine, or "" when one plausibly can.
func defaultHeadlessReason() string {
	return browserUnavailableReason(runtime.GOOS, os.Getenv)
}

// browserUnavailableReason reports why a browser cannot be opened, or ""
// when one plausibly can. Only cheap environment signals are used: a
// graphical Linux session always has DISPLAY or WAYLAND_DISPLAY, so
// headless servers, containers, and SSH sessions without X forwarding are
// detected up front. A TTY check is deliberately absent -- this plugin
// runs as a gRPC subprocess of the host binary and never owns the user's
// terminal, so "no TTY" would be true even for a fully interactive login.
func browserUnavailableReason(goos string, getenv func(string) string) string {
	if goos == "linux" && getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == "" {
		return "no DISPLAY or WAYLAND_DISPLAY (headless session)"
	}
	return ""
}

// interactiveLogin runs the authorization-code flow. When the flow was
// chosen implicitly (no --flow passed, no credentials detected) and no
// browser is available, it falls back to device code with a one-line
// notice instead of waiting out the callback timeout. An explicit
// --flow interactive keeps the manual-open wait, so SSH/devcontainer
// port forwarding (--callback-port) keeps working.
//
// When the host advertises paste-back support (issue #66), the headless
// fallbacks are disabled: the user completes the flow by pasting the
// redirect URL back through the host, which works without a browser on
// this machine, so interactive stays usable in remote workspaces where
// device code may be blocked by Conditional Access.
func (p *Plugin) interactiveLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt), implicit bool, headlessReason string) (*sdkplugin.LoginResponse, error) {
	pasteBack := p.cfg.SupportsPromptAuthResponse()
	if implicit && headlessReason != "" && !pasteBack {
		return p.deviceCodeFallback(ctx, req, deviceCodeCb, headlessReason)
	}
	// With paste-back the flow can complete without a local browser, so a
	// browser-open failure degrades to the prompt + wait instead of an
	// abort; without it, browserRequired keeps the implicit fallback.
	browserRequired := implicit && !pasteBack
	promptRequired := implicit && pasteBack && headlessReason != ""
	resp, err := p.authCodeLogin(ctx, req, deviceCodeCb, browserRequired, promptRequired)
	if implicit && errors.Is(err, errBrowserUnavailable) {
		return p.deviceCodeFallback(ctx, req, deviceCodeCb, "opening the browser failed")
	}
	if errors.Is(err, errPromptUnavailable) {
		return p.deviceCodeFallback(ctx, req, deviceCodeCb, headlessReason+"; host paste-back prompt failed")
	}
	return resp, err
}

// deviceCodeFallback runs the device code flow, logging why the browser
// flow was not used.
func (p *Plugin) deviceCodeFallback(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt), reason string) (*sdkplugin.LoginResponse, error) {
	logr.FromContextOrDiscard(ctx).V(0).Info(
		"no browser available (" + reason + "), falling back to device code; pass --flow interactive to force the browser flow",
	)
	return p.deviceCodeLogin(ctx, req, deviceCodeCb)
}
