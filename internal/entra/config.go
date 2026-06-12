// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"encoding/json"
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

	// ClientSecret is the client secret for service principal authentication.
	// When set under a profile, this value takes precedence over the
	// AZURE_CLIENT_SECRET environment variable.
	ClientSecret string `json:"clientSecret,omitempty" yaml:"clientSecret,omitempty"` //nolint:gosec // config field name, not a credential

	// FederatedTokenFile is the path to the projected service account token
	// for workload identity federation. When set under a profile, this value
	// takes precedence over AZURE_FEDERATED_TOKEN_FILE.
	FederatedTokenFile string `json:"federatedTokenFile,omitempty" yaml:"federatedTokenFile,omitempty"`

	// FederatedToken is a raw federated token for workload identity federation.
	// When set under a profile, this value takes precedence over
	// AZURE_FEDERATED_TOKEN.
	FederatedToken string `json:"federatedToken,omitempty" yaml:"federatedToken,omitempty"` //nolint:gosec // config field name, not a credential

	// AdditionalScopes are always merged into the final scope set,
	// regardless of whether the caller provided scopes or DefaultScopes
	// were used. Duplicates are suppressed.
	AdditionalScopes []string `json:"additionalScopes,omitempty" yaml:"additionalScopes,omitempty"`

	// InjectOIDCScopes controls whether openid, profile, and offline_access
	// scopes are automatically appended to every login request. When nil
	// (the default), OIDC scopes are injected. Set to false to disable.
	InjectOIDCScopes *bool `json:"injectOidcScopes,omitempty" yaml:"injectOidcScopes,omitempty"`

	// MinPollInterval is the minimum interval between device code poll requests.
	MinPollInterval time.Duration `json:"-" yaml:"-"`

	// SlowDownIncrement is added to poll interval when server returns slow_down.
	SlowDownIncrement time.Duration `json:"-" yaml:"-"`

	// setFields tracks which JSON keys were explicitly provided during
	// unmarshaling so that profileOrEnv can distinguish "explicitly set to
	// the default value" from "not set at all."
	setFields map[string]bool `json:"-" yaml:"-"`
}

// UnmarshalJSON implements custom JSON unmarshaling that tracks which fields
// were explicitly present in the input. This lets profileOrEnv distinguish
// "field set to the default value" from "field not provided."
func (c *Config) UnmarshalJSON(data []byte) error {
	// Detect which keys are present in the raw JSON.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.setFields = make(map[string]bool, len(raw))
	for k, v := range raw {
		// Treat explicit empty strings (e.g. "clientId":"") as unset so that
		// profileOrEnv falls back to environment variables per Issue #8.
		if string(v) != `""` {
			c.setFields[k] = true
		}
	}

	// Unmarshal into an alias to avoid infinite recursion.
	type alias Config
	return json.Unmarshal(data, (*alias)(c))
}

// WasSet reports whether a JSON field (by its json tag name) was explicitly
// present in the unmarshaled config. Returns false when the config was not
// populated from JSON at all (e.g. DefaultConfig).
func (c *Config) WasSet(jsonField string) bool {
	if c.setFields == nil {
		return false
	}
	return c.setFields[jsonField]
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

// ShouldInjectOIDCScopes reports whether OIDC scopes (openid, profile,
// offline_access) should be automatically appended to login requests.
// Returns true when InjectOIDCScopes is nil (unset) or explicitly true.
func (c *Config) ShouldInjectOIDCScopes() bool {
	if c.InjectOIDCScopes == nil {
		return true
	}
	return *c.InjectOIDCScopes
}

// MergeAdditionalScopes returns a new slice containing the input scopes plus
// any AdditionalScopes not already present. The input slice is never mutated.
func (c *Config) MergeAdditionalScopes(scopes []string) []string {
	if len(c.AdditionalScopes) == 0 {
		return scopes
	}
	have := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		have[s] = true
	}
	out := make([]string, len(scopes), len(scopes)+len(c.AdditionalScopes))
	copy(out, scopes)
	for _, s := range c.AdditionalScopes {
		if !have[s] {
			out = append(out, s)
			have[s] = true
		}
	}
	return out
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
