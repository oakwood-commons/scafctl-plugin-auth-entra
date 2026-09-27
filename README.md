# scafctl-plugin-auth-entra

A [scafctl](https://github.com/oakwood-commons/scafctl) auth handler plugin for
**Microsoft Entra ID** (formerly Azure Active Directory).

## Supported Auth Flows

| Flow | Description |
| ------ | ------------- |
| `interactive` | Authorization code + PKCE (browser-based) |
| `device-code` | Device code polling (headless/SSH) |
| `service-principal` | Client credentials (CI/CD) |
| `workload-identity` | Federated token (Kubernetes pods) |

## Installation

~~~bash
scafctl build plugin --force \
  --name auth-entra \
  --kind auth-handler \
  --version 0.1.0 \
  --platform darwin/arm64=./dist/scafctl-plugin-auth-entra
~~~

Or install from the catalog:

~~~bash
scafctl install plugin auth-entra
~~~

## Configuration

Add the handler to your scafctl config (`~/.config/scafctl/config.yaml`):

~~~yaml
auth:
  handlers:
    entra:
      clientId: "<your-app-registration-client-id>"
      tenantId: "<your-tenant-id>"
~~~

### Environment Variables

| Variable | Description |
| ---------- | ------------- |
| `AZURE_CLIENT_ID` | App registration client ID (service principal / workload identity) |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_SECRET` | Client secret (service principal flow) |
| `AZURE_FEDERATED_TOKEN_FILE` | Path to projected SA token (workload identity) |
| `AZURE_FEDERATED_TOKEN` | Raw federated token (workload identity, testing) |
| `AZURE_AUTHORITY_HOST` | Custom authority host (defaults to `login.microsoftonline.com`) |

### Credential Precedence

In CLI mode, credentials are resolved in this order:

1. **Stored user session** — a refresh token from an earlier `interactive` or
   `device-code` login that has not expired.
2. **Workload identity** — `AZURE_FEDERATED_TOKEN_FILE` / `AZURE_FEDERATED_TOKEN`
   (or config `federatedToken`/`federatedTokenFile`) plus client and tenant IDs.
3. **Service principal** — `AZURE_CLIENT_SECRET` (or config `clientSecret`)
   plus client and tenant IDs.

An explicit user login is a stronger signal of intent than ambient
environment variables: once a user session is stored, `auth status`, `auth
token`, and every provider call use the logged-in user even on machines where
the `AZURE_*` service principal / workload identity variables are set (common
for Terraform and the Azure SDKs).

`scafctl auth logout entra` clears the stored session and restores
environment-credential behavior. An expired or corrupted session is ignored
and falls back to environment credentials the same way.

Note: `scafctl auth login entra --flow interactive` consults the resulting
status before running the flow. On a machine with SP/WI env variables set and
no stored user session, use `--force` (or unset the variables) for the first
interactive login; scafctl's pre-login check reports the env credential as
"already authenticated" regardless of identity type.

## Usage

~~~bash
# Interactive login
scafctl auth login --handler entra --flow interactive

# Device code login
scafctl auth login --handler entra --flow device-code

# Check status
scafctl auth status --handler entra

# Get a token
scafctl auth token --handler entra --scope "https://graph.microsoft.com/.default"

# Logout
scafctl auth logout --handler entra
~~~

## Profiles

Credentials are stored per profile. Every request arriving at the plugin
carries a profile on its context; the profile is only ever taken from that
per-request context -- an empty profile always means the **default
(unscoped)** session (`scafctl.auth.entra.*` keys), never the configured
`activeProfile`. The host resolves the active profile before the call when
the active session is intended.

**Breaking change:** the secret-key profile is no longer back-filled from
the `activeProfile` the host applied when configuring the plugin. A host
that configures the plugin with an active profile but does not attach
profile metadata to individual auth calls now reads, writes, and clears
only the default (unscoped) session; profile-scoped credentials stored by
earlier plugin versions under such a host are ignored (log in again to
recreate them in the session the host requests). Hosts that resolve the
active profile per request are unaffected.

Consequences for `scafctl auth logout`:

- `auth logout entra` (no `--profile`, with `activeProfile` set): the host
  resolves the active profile, so the active session is logged out.
- `auth logout entra --profile default`: the default (unscoped) session is
  logged out; the active profile's secrets are left intact.
- `auth logout --all`: the host iterates *handlers* without setting a
  profile, so this clears each handler's default (unscoped) session.
  Profile-scoped sessions (including the `activeProfile` session) are not
  touched. To log out of a profile-scoped session, use
  `auth logout entra --profile <name>` (or the global `--auth-profile`).

## Development

~~~bash
# Build
task build

# Test
task test

# Lint
task lint

# Install locally
task publish:local
~~~

## License

Apache-2.0
