// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/scafctl-plugin-sdk/auth"
	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

const (
	// graphGroupsHost is the default commercial Microsoft Graph API hostname.
	graphGroupsHost = "graph.microsoft.com"

	// graphGroupsMemberOfPath is the Graph API path and query for paginated group memberships.
	graphGroupsMemberOfPath = "/v1.0/me/memberOf/microsoft.graph.group?$select=id&$top=999"

	// graphGroupsScope is the default commercial OAuth scope used to obtain a Graph access token.
	graphGroupsScope = "https://" + graphGroupsHost + "/.default"

	// maxGraphGroupPages bounds Graph /me/memberOf pagination against cyclic nextLink responses.
	maxGraphGroupPages = 1000

	// maxGraphGroupPageBytes bounds a single Graph /me/memberOf page body (4 MiB).
	maxGraphGroupPageBytes = 4 << 20
)

// graphHostForAuthority maps an Entra authority URL to its corresponding
// Microsoft Graph API hostname, defaulting to commercial graph.microsoft.com.
func graphHostForAuthority(authority string) string {
	u, err := url.Parse(authority)
	if err != nil {
		return graphGroupsHost
	}
	switch strings.ToLower(u.Hostname()) {
	case "login.microsoftonline.us":
		return "graph.microsoft.us"
	case "login.chinacloudapi.cn", "login.partner.microsoftonline.cn":
		return "microsoftgraph.chinacloudapi.cn"
	case "login.microsoftonline.eaglex.ic.gov":
		return "graph.eaglex.ic.gov"
	case "login.microsoftonline.microsoft.scloud":
		return "graph.microsoft.scloud"
	default:
		return graphGroupsHost
	}
}

func graphScopeForAuthority(authority string) string {
	return "https://" + graphHostForAuthority(authority) + "/.default"
}

func graphMemberOfURLForHost(graphHost string) string {
	return "https://" + graphHost + graphGroupsMemberOfPath
}

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

	graphClient, releaseGraph, err := p.graphClientForConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer releaseGraph()

	// /me/memberOf requires a delegated (user) token. Honor a valid stored
	// interactive/device-code user session first before rejecting ambient or
	// configured non-user flows, inspecting stored session credentials once.
	if metadata, hasUserSession, loadErr := p.inspectStoredSession(ctx); !hasUserSession {
		if tErr := isTransientSessionLoadErr(ctx, loadErr); tErr != nil {
			return nil, tErr
		}
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

	graphHost := graphHostForAuthority(cfg.GetAuthority())
	graphScope := graphScopeForAuthority(cfg.GetAuthority())

	// Acquire a Graph access token via the existing token machinery.
	tokenResp, err := p.GetToken(ctx, HandlerName, sdkplugin.TokenRequest{Scope: graphScope})
	if err != nil {
		return nil, fmt.Errorf("failed to acquire Graph token for group lookup: %w", err)
	}
	if flowErr := rejectNonUserGroupFlow(tokenResp.Flow); flowErr != nil {
		return nil, flowErr
	}

	// Paginate through all group memberships.
	groups := make([]string, 0)
	nextURL := graphMemberOfURLForHost(graphHost)
	pagesFetched := 0

	for nextURL != "" {
		if pagesFetched >= maxGraphGroupPages {
			return nil, fmt.Errorf("graph memberOf exceeded maximum page count (%d)", maxGraphGroupPages)
		}
		pagesFetched++

		lgr.V(1).Info("fetching group memberships from Graph", "url", nextURL)

		resp, err := graphClient.Get(ctx, nextURL, tokenResp.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("graph memberOf request failed: %w", err)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxGraphGroupPageBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read Graph memberOf response: %w", err)
		}
		if len(body) > maxGraphGroupPageBytes {
			return nil, fmt.Errorf("graph memberOf response exceeded maximum page size (%d bytes)", maxGraphGroupPageBytes)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("graph memberOf returned HTTP %d: %s", resp.StatusCode, sanitizeControlChars(truncate(string(body), 512)))
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

		if page.NextLink != "" {
			if err := validateGraphNextLink(page.NextLink, graphHost); err != nil {
				return nil, err
			}
		}
		nextURL = page.NextLink
		lgr.V(2).Info("fetched group membership page", "pageSize", len(page.Value), "hasMore", nextURL != "")
	}

	lgr.V(1).Info("fetched all group memberships", "count", len(groups))
	return groups, nil
}

// validateGraphNextLink ensures an @odata.nextLink URL uses HTTPS on the
// expected Microsoft Graph origin before forwarding the delegated bearer token.
func validateGraphNextLink(rawURL, expectedHost string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid Graph @odata.nextLink URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("refusing non-HTTPS Graph @odata.nextLink scheme %q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("refusing Graph @odata.nextLink URL with userinfo")
	}
	if !strings.EqualFold(u.Hostname(), expectedHost) || (u.Port() != "" && u.Port() != "443") {
		return fmt.Errorf("refusing cross-origin Graph @odata.nextLink host %q (expected %q)", u.Host, expectedHost)
	}
	return nil
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
