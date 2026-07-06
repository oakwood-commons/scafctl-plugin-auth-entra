// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"fmt"
	"net/url"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

// ServerCredential provides the server's proof-of-identity for the token endpoint.
type ServerCredential interface {
	Apply(params url.Values) error
}

// WIFCredential implements ServerCredential by resolving a projected token
// via SecretRef. The token is re-read on every call because projected service
// account tokens rotate.
type WIFCredential struct {
	Token               sdkplugin.SecretRef
	ClientAssertionType string
}

// Apply resolves the federated token and sets the WIF client assertion params.
func (c *WIFCredential) Apply(params url.Values) error {
	assertion, err := c.Token.Resolve()
	if err != nil {
		return fmt.Errorf("resolving WIF token: %w", err)
	}
	if assertion == "" {
		return fmt.Errorf("WIF token resolved to empty value")
	}
	params.Set("client_assertion_type", c.ClientAssertionType)
	params.Set("client_assertion", assertion)
	return nil
}

// SecretCredential implements ServerCredential using a static client secret.
type SecretCredential struct {
	Secret string
}

// Apply sets the client_secret on the token request params.
func (c *SecretCredential) Apply(params url.Values) error {
	if c.Secret == "" {
		return fmt.Errorf("client secret is empty")
	}
	params.Set("client_secret", c.Secret)
	return nil
}
