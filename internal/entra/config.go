// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"fmt"
	"strings"
	"time"
)

// DefaultClientID is the Azure CLI public client ID shipped with scafctl.
// This well-known public client supports the device code flow.
const DefaultClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

// DefaultTenantID is the default multi-tenant tenant identifier.
const DefaultTenantID = "common"

// DefaultAuthority is the default Azure AD authority URL.
const DefaultAuthority = "https://login.microsoftonline.com"

// DefaultGraphResourceURI is the base URI for Microsoft Graph API scopes.
const DefaultGraphResourceURI = "https://graph.microsoft.com/"

// Config holds Entra-specific configuration.
type Config struct {
	// ClientID is the Azure application/client ID.
	ClientID string `json:"clientId" yaml:"clientId"`

	// TenantID is the default Azure tenant ID.
	TenantID string `json:"tenantId" yaml:"tenantId"`

	// Authority is the Azure AD authority URL.
	Authority string `json:"authority,omitempty" yaml:"authority,omitempty"`

	// DefaultScopes are requested during initial login if not specified.
	DefaultScopes []string `json:"defaultScopes,omitempty" yaml:"defaultScopes,omitempty"`

	// DefaultFlow is the authentication flow used when no explicit flow is
	// requested and no environment credentials are detected.
	DefaultFlow string `json:"defaultFlow,omitempty" yaml:"defaultFlow,omitempty"`

	// MinPollInterval is the minimum interval between device code poll requests.
	MinPollInterval time.Duration `json:"-" yaml:"-"`

	// SlowDownIncrement is added to poll interval when server returns slow_down.
	SlowDownIncrement time.Duration `json:"-" yaml:"-"`
}

// DefaultConfig returns the default Entra configuration.
func DefaultConfig() *Config {
	return &Config{
		ClientID:          DefaultClientID,
		TenantID:          DefaultTenantID,
		Authority:         DefaultAuthority,
		DefaultScopes:     []string{"openid", "profile"},
		MinPollInterval:   DefaultMinPollInterval,
		SlowDownIncrement: 5 * time.Second,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("clientId is required")
	}
	if c.TenantID == "" {
		return fmt.Errorf("tenantId is required")
	}
	return nil
}

// GetAuthority returns the full authority URL for the configured tenant.
func (c *Config) GetAuthority() string {
	authority := c.Authority
	if authority == "" {
		authority = DefaultAuthority
	}
	return authority
}

// GetAuthorityWithTenant returns the full authority URL for a specific tenant.
func (c *Config) GetAuthorityWithTenant(tenantID string) string {
	return fmt.Sprintf("%s/%s", c.GetAuthority(), tenantID)
}

// QualifyScope returns a fully-qualified scope string. If the input contains
// spaces (multiple scopes), each token is qualified individually and the
// results are joined back with spaces. Bare permission names like
// "Group.Read.All" are prefixed with the Microsoft Graph resource URI;
// scopes that already contain a scheme or are well-known OIDC scopes are
// returned unchanged.
func QualifyScope(scope string) string {
	if strings.Contains(scope, " ") {
		tokens := strings.Fields(scope)
		for i, t := range tokens {
			tokens[i] = qualifySingleScope(t)
		}
		return strings.Join(tokens, " ")
	}
	return qualifySingleScope(scope)
}

// qualifySingleScope qualifies a single scope token.
func qualifySingleScope(scope string) string {
	// Already qualified or well-known OIDC scope
	if strings.Contains(scope, "://") || strings.Contains(scope, "/") {
		return scope
	}
	switch scope {
	case "openid", "profile", "offline_access", "email":
		return scope
	}
	return DefaultGraphResourceURI + scope
}
