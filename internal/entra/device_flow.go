// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// DeviceCodeResponse represents the response from the device code endpoint.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// deviceCodeLogin performs the device code authentication flow.
func (p *Plugin) deviceCodeLogin(ctx context.Context, req sdkplugin.LoginRequest, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	lgr.V(1).Info("starting device code authentication flow")

	// Determine tenant
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = p.config.TenantID
	}

	// Determine scopes
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = p.config.DefaultScopes
	}

	// Ensure offline_access is included for refresh token
	hasOfflineAccess := false
	for _, s := range scopes {
		if s == "offline_access" {
			hasOfflineAccess = true
			break
		}
	}
	if !hasOfflineAccess {
		scopes = append(scopes, "offline_access")
	}

	// Determine timeout
	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return p.performDeviceCodeFlow(ctx, req, tenantID, scopes, deviceCodeCb)
}

// performDeviceCodeFlow executes the device code authentication flow.
func (p *Plugin) performDeviceCodeFlow(ctx context.Context, _ sdkplugin.LoginRequest, tenantID string, scopes []string, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	// Step 1: Request device code
	deviceCode, err := p.requestDeviceCode(ctx, tenantID, scopes)
	if err != nil {
		return nil, fmt.Errorf("entra: device_code_request: %w", err)
	}

	lgr.V(1).Info("device code obtained",
		"userCode", deviceCode.UserCode,
		"verificationURI", deviceCode.VerificationURI,
	)

	// Step 2: Notify callback with device code info
	if deviceCodeCb != nil {
		deviceCodeCb(sdkplugin.DeviceCodePrompt{
			UserCode:        deviceCode.UserCode,
			VerificationURI: deviceCode.VerificationURI,
			Message:         deviceCode.Message,
		})
	}

	// Step 3: Poll for token
	tokenResp, err := p.pollForToken(ctx, tenantID, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("entra: token_poll: %w", err)
	}

	// Step 4: Store credentials
	if err := p.storeCredentials(ctx, tenantID, tokenResp, p.config.ClientID, scopes, "device_code", ""); err != nil {
		return nil, fmt.Errorf("entra: store_credentials: %w", err)
	}

	// Step 5: Extract and return claims
	claims, err := p.extractClaims(tokenResp)
	if err != nil {
		return nil, fmt.Errorf("entra: extract_claims: %w", err)
	}

	lgr.V(1).Info("authentication successful",
		"subject", claims.Subject,
		"tenantId", claims.TenantID,
	)

	return &sdkplugin.LoginResponse{
		Claims:    claims,
		ExpiresAt: time.Now().Add(DefaultRefreshTokenLifetime),
	}, nil
}

func (p *Plugin) requestDeviceCode(ctx context.Context, tenantID string, scopes []string) (*DeviceCodeResponse, error) {
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/devicecode", p.config.GetAuthority(), tenantID)

	data := makeFormData(map[string]string{
		"client_id": p.config.ClientID,
		"scope":     strings.Join(scopes, " "),
	})

	resp, err := p.httpClient.PostForm(ctx, endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp TokenErrorResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return nil, fmt.Errorf("device code request failed with status %d: decode error: %w; body: %s", resp.StatusCode, decErr, string(body))
		}
		if strings.Contains(errResp.ErrorDescription, "AADSTS") {
			return nil, formatAADSTSError("device code request failed", errResp)
		}
		return nil, fmt.Errorf("device code request failed: %s - %s", errResp.Error, errResp.ErrorDescription)
	}

	var deviceCode DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceCode); err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	return &deviceCode, nil
}

func (p *Plugin) pollForToken(ctx context.Context, tenantID string, deviceCode *DeviceCodeResponse) (*TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", p.config.GetAuthority(), tenantID)

	minPollInterval := p.config.MinPollInterval
	if minPollInterval == 0 {
		minPollInterval = DefaultMinPollInterval
	}

	interval := time.Duration(deviceCode.Interval) * time.Second
	if interval < minPollInterval {
		interval = minPollInterval
	}

	ticker := p.clock.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("authentication timed out")
		case <-ticker.C():
			data := makeFormData(map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   p.config.ClientID,
				"device_code": deviceCode.DeviceCode,
			})

			resp, err := p.httpClient.PostForm(ctx, endpoint, data)
			if err != nil {
				// Network error, log and continue polling
				lgr.V(1).Info("transient network error during token poll, continuing", "error", err)
				continue
			}

			if resp.StatusCode == http.StatusOK {
				var tokenResp TokenResponse
				if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
					_ = resp.Body.Close()
					return nil, fmt.Errorf("failed to parse token response: %w", err)
				}
				_ = resp.Body.Close()
				return &tokenResp, nil
			}

			var errResp TokenErrorResponse
			if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr != nil {
				_ = resp.Body.Close()
				return nil, fmt.Errorf("token request failed with HTTP %d (could not parse error response: %w)", resp.StatusCode, decErr)
			}
			_ = resp.Body.Close()

			switch errResp.Error {
			case "authorization_pending":
				continue
			case "slow_down":
				slowDownIncr := p.config.SlowDownIncrement
				if slowDownIncr == 0 {
					slowDownIncr = 5 * time.Second
				}
				interval += slowDownIncr
				ticker.Reset(interval)
				lgr.V(1).Info("slow_down received, increasing poll interval", "newInterval", interval)
				continue
			case "expired_token":
				return nil, fmt.Errorf("authentication timed out")
			case "authorization_declined":
				return nil, fmt.Errorf("authentication cancelled by user")
			default:
				if strings.Contains(errResp.ErrorDescription, "AADSTS") {
					return nil, formatAADSTSError("token request failed", errResp)
				}
				return nil, fmt.Errorf("token request failed: %s - %s", errResp.Error, errResp.ErrorDescription)
			}
		}
	}
}
