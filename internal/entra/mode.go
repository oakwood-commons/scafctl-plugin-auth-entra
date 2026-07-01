// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"

	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// mode defines behavior for state-dependent operations.
// Plugin dispatches to the active mode after handler-name validation.
type mode interface {
	Login(ctx context.Context, req sdkplugin.LoginRequest, cb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error)
	Logout(ctx context.Context) error
	GetStatus(ctx context.Context) (*auth.Status, error)
	GetToken(ctx context.Context, req sdkplugin.TokenRequest) (*sdkplugin.TokenResponse, error)
	ListCachedTokens(ctx context.Context) ([]*auth.CachedTokenInfo, error)
	PurgeExpiredTokens(ctx context.Context) (int, error)
	DetectAvailableFlows(ctx context.Context) ([]sdkplugin.FlowAvailability, error)
}
