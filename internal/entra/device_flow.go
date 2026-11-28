// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	oauth "github.com/oakwood-commons/oauth-helpers"
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

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	// Determine tenant
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = cfg.TenantID
	}

	// Determine scopes
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = cfg.DefaultScopes
	}

	// Ensure OIDC scopes are included so the response contains an ID token
	// with user claims (preferred_username, name).
	scopes = ensureOIDCScopes(scopes)

	// Determine timeout
	timeout := req.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return p.performDeviceCodeFlow(ctx, cfg, req, tenantID, scopes, deviceCodeCb)
}

// performDeviceCodeFlow executes the device code authentication flow.
func (p *Plugin) performDeviceCodeFlow(ctx context.Context, cfg *Config, _ sdkplugin.LoginRequest, tenantID string, scopes []string, deviceCodeCb func(sdkplugin.DeviceCodePrompt)) (*sdkplugin.LoginResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	// Step 1: Request device code
	deviceCode, err := p.requestDeviceCode(ctx, cfg, tenantID, scopes)
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
	tokenResp, err := p.pollForToken(ctx, cfg, tenantID, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("entra: token_poll: %w", err)
	}

	// Step 4: Validate and extract claims before mutating stored credentials
	claims, err := p.extractClaims(tokenResp)
	if err != nil {
		return nil, fmt.Errorf("entra: extract_claims: %w", err)
	}

	// Step 5: Store credentials and clear cached tokens from any previous
	// identity atomically under profileLock.
	if err := p.storeCredentials(ctx, tenantID, tokenResp, cfg.ClientID, scopes, "device_code", ""); err != nil {
		return nil, fmt.Errorf("entra: store_credentials: %w", err)
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

func (p *Plugin) requestDeviceCode(ctx context.Context, cfg *Config, tenantID string, scopes []string) (*DeviceCodeResponse, error) {
	httpClient, releaseHTTP, err := p.httpClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()

	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/devicecode", cfg.GetAuthority(), tenantID)

	data := makeFormData(map[string]string{
		"client_id": cfg.ClientID,
		"scope":     strings.Join(scopes, " "),
	})

	resp, err := httpClient.PostForm(ctx, endpoint, data)
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

// maxDeviceTokenResponseBytes bounds a single device-code token response body (1 MiB).
const maxDeviceTokenResponseBytes = 1 << 20

// sanitizeDeviceErrorText normalizes CR/LF/TAB/space runs to single spaces,
// strips remaining terminal control characters, and caps length to maxRunes.
func sanitizeDeviceErrorText(s string, maxRunes int) string {
	replaced := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(s)
	cleaned := sanitizeControlChars(strings.Join(strings.Fields(replaced), " "))
	return truncateRunes(cleaned, maxRunes)
}

func isRetryableDevicePollStatus(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests ||
		statusCode == 0 ||
		(statusCode >= http.StatusInternalServerError && statusCode != http.StatusNotImplemented)
}

func (p *Plugin) pollForToken(ctx context.Context, cfg *Config, tenantID string, deviceCode *DeviceCodeResponse) (*TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)
	httpClient, releaseHTTP, err := p.devicePollHTTPClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer releaseHTTP()

	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", cfg.GetAuthority(), tenantID)

	minPollInterval := cfg.MinPollInterval
	if minPollInterval == 0 {
		minPollInterval = DefaultMinPollInterval
	}

	var sleepFn func(context.Context, time.Duration) error
	if p.clock != nil {
		sleepFn = p.clock.Sleep
	}

	pollCfg := oauth.DevicePollConfig{
		Interval:             time.Duration(deviceCode.Interval) * time.Second,
		MinInterval:          minPollInterval,
		SlowDownIncrement:    cfg.SlowDownIncrement,
		RetryTransientErrors: true,
		Sleep:                sleepFn,
		OnSlowDown: func(newInterval time.Duration) {
			lgr.V(1).Info("slow_down received, increasing poll interval", "newInterval", newInterval)
		},
		OnTransientError: func(err error) {
			lgr.V(1).Info("transient network error during token poll, continuing", "error", err)
		},
	}

	tokenResp, err := oauth.PollDeviceToken(ctx, pollCfg, func(ctx context.Context) (*TokenResponse, *oauth.DevicePollError, error) {
		data := makeFormData(map[string]string{
			"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
			"client_id":   cfg.ClientID,
			"device_code": deviceCode.DeviceCode,
		})

		resp, err := httpClient.PostForm(ctx, endpoint, data)
		if err != nil {
			return nil, nil, err
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxDeviceTokenResponseBytes+1))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, nil, readErr
		}
		if len(body) > maxDeviceTokenResponseBytes {
			if isRetryableDevicePollStatus(resp.StatusCode) {
				return nil, nil, fmt.Errorf("transient token endpoint HTTP %d", resp.StatusCode)
			}
			return nil, &oauth.DevicePollError{
				Cause: fmt.Errorf("token response exceeded maximum size (%d bytes)", maxDeviceTokenResponseBytes),
			}, nil
		}

		if resp.StatusCode == http.StatusOK {
			var parsed TokenResponse
			if decErr := json.Unmarshal(body, &parsed); decErr != nil {
				return nil, &oauth.DevicePollError{
					Cause: fmt.Errorf("failed to parse token response: %w", decErr),
				}, nil
			}
			return &parsed, nil, nil
		}

		var errResp TokenErrorResponse
		if decErr := json.Unmarshal(body, &errResp); decErr != nil {
			if isRetryableDevicePollStatus(resp.StatusCode) {
				return nil, nil, fmt.Errorf("transient token endpoint HTTP %d", resp.StatusCode)
			}
			return nil, &oauth.DevicePollError{
				Cause: fmt.Errorf("token request failed with HTTP %d (could not parse error response: %w)", resp.StatusCode, decErr),
			}, nil
		}

		errCode := strings.TrimSpace(errResp.Error)
		if isRetryableDevicePollStatus(resp.StatusCode) {
			switch errCode {
			case "authorization_pending", "slow_down", "expired_token", "authorization_declined", "access_denied":
			default:
				if cleanCode := sanitizeDeviceErrorText(errCode, 128); cleanCode != "" {
					return nil, nil, fmt.Errorf("transient token endpoint HTTP %d (%s)", resp.StatusCode, cleanCode)
				}
				return nil, nil, fmt.Errorf("transient token endpoint HTTP %d", resp.StatusCode)
			}
		}

		pollErr := &oauth.DevicePollError{
			Code:        errResp.Error,
			Description: errResp.ErrorDescription,
			Interval:    errResp.Interval,
		}
		switch errCode {
		case "authorization_pending", "slow_down", "expired_token", "authorization_declined", "access_denied":
		default:
			sanitized := TokenErrorResponse{
				Error:            sanitizeDeviceErrorText(errResp.Error, 128),
				ErrorDescription: sanitizeDeviceErrorText(errResp.ErrorDescription, 512),
				Interval:         errResp.Interval,
				Claims:           errResp.Claims,
			}
			if strings.Contains(sanitized.ErrorDescription, "AADSTS") {
				pollErr.Cause = formatAADSTSError("token request failed", sanitized)
			} else {
				pollErr.Cause = fmt.Errorf("token request failed: %s - %s", sanitized.Error, sanitized.ErrorDescription)
			}
		}
		return nil, pollErr, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, oauth.ErrDeviceAccessDenied):
			return nil, fmt.Errorf("authentication cancelled by user: %w", err)
		case errors.Is(err, oauth.ErrDeviceCodeExpired):
			return nil, fmt.Errorf("authentication timed out: %w", err)
		case ctx.Err() != nil && isContextErr(err):
			return nil, fmt.Errorf("authentication timed out: %w", err)
		default:
			return nil, err
		}
	}
	return tokenResp, nil
}
