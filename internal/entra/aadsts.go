// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package entra

import (
	"fmt"
	"strings"
)

// aadstsHint returns a human-readable hint for well-known AADSTS error codes.
func aadstsHint(desc string) string {
	switch {
	case strings.Contains(desc, "AADSTS700016"):
		return fmt.Sprintf(
			"the application was not found in the directory; verify that %s contains "+
				"the correct app registration client ID and that %s matches the tenant "+
				"where that app is registered",
			EnvAzureClientID, EnvAzureTenantID,
		)

	case strings.Contains(desc, "AADSTS90002"):
		return fmt.Sprintf(
			"the tenant was not found; verify that %s contains a valid tenant ID or "+
				"verified domain name",
			EnvAzureTenantID,
		)

	case strings.Contains(desc, "AADSTS7000215"):
		return fmt.Sprintf(
			"the client secret is invalid or has expired; regenerate the secret in the "+
				"Azure portal and update %s",
			EnvAzureClientSecret,
		)

	case strings.Contains(desc, "AADSTS70011"):
		return "the requested scope is invalid or not registered on the application"

	case strings.Contains(desc, "AADSTS50194"):
		return fmt.Sprintf(
			"the application is not configured for the account type being used; "+
				"verify %s is correct",
			EnvAzureTenantID,
		)

	case strings.Contains(desc, "AADSTS500011"):
		return "the target API resource was not found in this tenant"

	case strings.Contains(desc, "AADSTS500113"):
		return "no redirect URI is registered for this application; " +
			"add http://localhost under 'Mobile and desktop applications' in the Azure portal, " +
			"or use '--flow device-code'"

	case strings.Contains(desc, "AADSTS53003"):
		return "a Conditional Access policy blocked this request; " +
			"re-authenticate interactively so the required claims can be satisfied"
	}

	return ""
}

// formatAADSTSError builds a complete error message for a token endpoint error
// response, appending an actionable hint when one is available.
func formatAADSTSError(prefix string, errResp TokenErrorResponse) error {
	hint := aadstsHint(errResp.ErrorDescription)
	if hint != "" {
		return fmt.Errorf("%s: %s: %s\nHint: %s", prefix, errResp.Error, errResp.ErrorDescription, hint)
	}
	return fmt.Errorf("%s: %s: %s", prefix, errResp.Error, errResp.ErrorDescription)
}
