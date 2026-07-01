// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// FlowFn is a function that executes a token flow given params.
type FlowFn func(ctx context.Context, params FlowParams) (*sdkplugin.TokenResponse, error)

// FlowParams contains the inputs for a server-mode token flow.
type FlowParams struct {
	assertion string          // the inbound bearer token (assertion for OBO)
	Scope     string          // desired downstream scope
	ClientID  string          // client ID for the token request
	Caller    auth.CallerType // caller type for delegation routing
}

// oboFlow returns a FlowFn that performs the On-Behalf-Of token exchange.
func oboFlow(tokenURL string, cred ServerCredential, httpClient HTTPClient) FlowFn {
	return func(ctx context.Context, params FlowParams) (*sdkplugin.TokenResponse, error) {
		data := url.Values{
			"grant_type":          {OBOGrantType},
			"client_id":           {params.ClientID},
			"assertion":           {params.assertion},
			"scope":               {params.Scope},
			"requested_token_use": {OBORequestedTokenUse},
		}
		if err := cred.Apply(data); err != nil {
			return nil, fmt.Errorf("applying server credential: %w", err)
		}
		return executeTokenRequest(ctx, httpClient, tokenURL, data)
	}
}

// clientCredentialFlow returns a FlowFn that performs the client_credentials grant.
func clientCredentialFlow(tokenURL string, cred ServerCredential, httpClient HTTPClient) FlowFn {
	return func(ctx context.Context, params FlowParams) (*sdkplugin.TokenResponse, error) {
		data := url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {params.ClientID},
			"scope":      {params.Scope},
		}
		if err := cred.Apply(data); err != nil {
			return nil, fmt.Errorf("applying server credential: %w", err)
		}
		return executeTokenRequest(ctx, httpClient, tokenURL, data)
	}
}

// executeTokenRequest posts form data to the token endpoint and parses the response.
func executeTokenRequest(ctx context.Context, httpClient HTTPClient, tokenURL string, data url.Values) (*sdkplugin.TokenResponse, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	resp, err := httpClient.PostForm(ctx, tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != 200 {
		var errResp TokenErrorResponse
		if decErr := json.NewDecoder(resp.Body).Decode(&errResp); decErr != nil {
			return nil, fmt.Errorf("token request failed with HTTP %d", resp.StatusCode)
		}
		if strings.Contains(errResp.ErrorDescription, "AADSTS") {
			return nil, formatAADSTSError("token request failed", errResp)
		}
		return nil, fmt.Errorf("token request failed: %s - %s", errResp.Error, errResp.ErrorDescription)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	lgr.V(1).Info("token acquired", "scope", data.Get("scope"), "expiresAt", expiresAt)

	return &sdkplugin.TokenResponse{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresAt:   expiresAt,
		Scope:       data.Get("scope"),
	}, nil
}

// delegatedDispatch returns a FlowFn that routes by CallerType within the delegated context.
func delegatedDispatch(userFlow, machineFlow FlowFn) FlowFn {
	return func(ctx context.Context, params FlowParams) (*sdkplugin.TokenResponse, error) {
		switch params.Caller {
		case auth.CallerUser:
			if userFlow == nil {
				return nil, fmt.Errorf("delegated user flow not configured")
			}
			return userFlow(ctx, params)
		case auth.CallerMachine:
			if machineFlow == nil {
				return nil, fmt.Errorf("delegated machine flow not configured")
			}
			return machineFlow(ctx, params)
		default:
			return nil, fmt.Errorf("unsupported caller type for delegation: %s", params.Caller)
		}
	}
}

// allowedServerFlows returns the set of flows permitted as the top-level server flow.
func allowedServerFlows() map[auth.Flow]struct{} {
	return map[auth.Flow]struct{}{
		auth.FlowWorkloadIdentity:  {},
		auth.FlowClientCredentials: {},
	}
}

// allowedUserFlows returns the set of flows permitted for delegated user flow.
func allowedUserFlows() map[auth.Flow]struct{} {
	return map[auth.Flow]struct{}{
		auth.FlowOnBehalfOf:        {},
		auth.FlowWorkloadIdentity:  {},
		auth.FlowClientCredentials: {},
	}
}

func isAllowedServerFlow(flow auth.Flow) bool {
	_, ok := allowedServerFlows()[flow]
	return ok
}

// validateDelegatedFlow validates the DelegatedConfig against the server flow.
// Rules:
//   - At least one of UserFlow or Machine must be enabled.
//   - UserFlow (if set) must be in allowedUserFlows().
//   - If UserFlow is not OBO, it must match the server flow.
func validateDelegatedFlow(config *DelegatedConfig, serverFlow auth.Flow) error {
	if config.UserFlow == "" && !config.Machine {
		return fmt.Errorf("delegated config must enable at least one of userFlow or machine")
	}
	if config.UserFlow != "" {
		if _, ok := allowedUserFlows()[config.UserFlow]; !ok {
			return fmt.Errorf("delegated userFlow %q is not allowed", config.UserFlow)
		}
		if config.UserFlow != auth.FlowOnBehalfOf && config.UserFlow != serverFlow {
			return fmt.Errorf("delegated userFlow %q must be %q or match serverFlow %q",
				config.UserFlow, auth.FlowOnBehalfOf, serverFlow)
		}
	}
	return nil
}
