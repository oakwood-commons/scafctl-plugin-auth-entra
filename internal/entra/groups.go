// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// graphGroupsMemberOfURL is the Graph API endpoint for paginated group memberships.
	graphGroupsMemberOfURL = "https://graph.microsoft.com/v1.0/me/memberOf/microsoft.graph.group?$select=id&$top=999"

	// graphGroupsScope is the OAuth scope used to obtain a Graph access token.
	graphGroupsScope = "https://graph.microsoft.com/.default"
)

// graphGroupsPage is the paged JSON response from Graph /me/memberOf.
type graphGroupsPage struct {
	NextLink string            `json:"@odata.nextLink"`
	Value    []graphGroupEntry `json:"value"`
}

// graphGroupEntry is a single entry in the /me/memberOf response.
type graphGroupEntry struct {
	ID string `json:"id"`
}

// getGroups returns the ObjectIDs of all Microsoft Entra groups the authenticated
// user belongs to. It always calls the Microsoft Graph API (bypassing the 200-group
// JWT token limit) and handles pagination transparently.
//
// Credential precedence mirrors GetStatus and GetToken: a valid stored user
// session (interactive or device_code) takes precedence over ambient
// service-principal or workload-identity credentials, so developers with
// AZURE_* environment variables set can still resolve group memberships after
// logging in interactively. Non-user flows are rejected only when no valid user
// session is stored for the target profile (or when the stored/resolved token
// belongs to a non-user flow).
func (p *Plugin) getGroups(ctx context.Context) ([]string, error) {
	lgr := logr.FromContextOrDiscard(ctx)

	cfg, err := p.effectiveConfig(ctx)
	if err != nil {
		return nil, err
	}
	ctx = withResolvedConfig(ctx, cfg)

	graphClient, err := p.graphClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// /me/memberOf requires a delegated (user) token. Honor a valid stored
	// interactive/device-code user session first before rejecting ambient or
	// configured non-user flows, inspecting stored session credentials once.
	if metadata, hasUserSession, loadErr := p.inspectStoredSession(ctx); !hasUserSession {
		if p.hasWorkloadIdentityCredentialsForConfig(cfg) {
			return nil, fmt.Errorf("group membership queries are not supported for workload identity flows")
		}
		if p.hasServicePrincipalCredentialsForConfig(cfg) {
			return nil, fmt.Errorf("group membership queries are not supported for service principal flows")
		}
		if loadErr == nil && metadata != nil {
			if flowErr := rejectNonUserGroupFlow(metadata.LastLoginFlow); flowErr != nil {
				return nil, flowErr
			}
		}
	}

	// Acquire a Graph access token via the existing token machinery.
	tokenResp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphGroupsScope})
	if err != nil {
		return nil, fmt.Errorf("failed to acquire Graph token for group lookup: %w", err)
	}
	if flowErr := rejectNonUserGroupFlow(tokenResp.Flow); flowErr != nil {
		return nil, flowErr
	}

	// Paginate through all group memberships.
	groups := make([]string, 0)
	nextURL := graphGroupsMemberOfURL

	for nextURL != "" {
		lgr.V(1).Info("fetching group memberships from Graph", "url", nextURL)

		resp, err := graphClient.Get(ctx, nextURL, tokenResp.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("graph memberOf request failed: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read Graph memberOf response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("graph memberOf returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 512))
		}

		var page graphGroupsPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("failed to parse Graph memberOf response: %w", err)
		}

		for _, entry := range page.Value {
			if entry.ID != "" {
				groups = append(groups, entry.ID)
			}
		}

		nextURL = page.NextLink
		lgr.V(2).Info("fetched group membership page", "pageSize", len(page.Value), "hasMore", nextURL != "")
	}

	lgr.V(1).Info("fetched all group memberships", "count", len(groups))
	return groups, nil
}

// rejectNonUserGroupFlow returns an error when flow represents a non-delegated
// machine identity that cannot call Microsoft Graph /me/memberOf.
func rejectNonUserGroupFlow(flow auth.Flow) error {
	switch flow { //nolint:exhaustive // only machine flows are rejected here
	case auth.FlowWorkloadIdentity:
		return fmt.Errorf("group membership queries are not supported for workload identity flows")
	case auth.FlowServicePrincipal, auth.FlowClientCredentials:
		return fmt.Errorf("group membership queries are not supported for service principal flows")
	default:
		return nil
	}
}

// truncate limits s to at most n bytes for safe error message embedding.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
