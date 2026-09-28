# scafctl-plugin-auth-entra

A [scafctl](https://github.com/oakwood-commons/scafctl) auth handler plugin for
**Microsoft Entra ID** (formerly Azure Active Directory).

## Supported Auth Flows

| Flow | Description |
| ------ | ------------- |
| `interactive` | Authorization code + PKCE, opens a browser (default when no flow is given; in remote workspaces the redirect URL can be pasted back through the host) |
| `device-code` | Device code polling (headless/SSH; automatic fallback when no browser is available and the host has no paste-back support) |
| `service-principal` | Client credentials (CI/CD) |
| `workload-identity` | Federated token (Kubernetes pods) |

## Installation

~~~bash
# Build and install into the local scafctl catalog
task publish:local

# Or build a catalog artifact manually
scafctl build plugin --force \
  --name entra \
  --kind auth-handler \
  --version 0.1.0 \
  --platform darwin/arm64=./dist/scafctl-plugin-auth-entra
~~~

The catalog artifact name must be `entra` (not `auth-entra`): releases and
scafctl's official-handler lookup both resolve this handler as `entra`.

Or install the official release from the catalog:

~~~bash
scafctl auth handlers install entra
~~~

## Configuration

Add the handler to your scafctl config (`~/.config/scafctl/config.yaml`).
Settings live in the typed `auth.entra` block; an `auth.handlers.entra`
block is not forwarded to this plugin:

~~~yaml
auth:
  entra:
    clientId: "<your-app-registration-client-id>"
    tenantId: "<your-tenant-id>"
~~~

### Config Keys

Keys under `auth.entra`:

| Key | Default | Notes |
| --- | --- | --- |
| `clientId` | Azure CLI public client ID | App registration client ID |
| `tenantId` | `common` | Tenant GUID, `organizations`, or `common` |
| `authority` | `https://login.microsoftonline.com` | Authority URL; must be `https://` with a host. See the sovereign-cloud note |
| `defaultScopes` | `openid profile` | Scopes requested at interactive/device-code login when no `--scope` is given; service-principal and workload-identity logins ignore it and default to a fixed `https://graph.microsoft.com/.default` / `https://management.azure.com/.default` unless `--scope` is passed |
| `defaultFlow` | `interactive` | `interactive` or `device_code`; used when no flow is requested and no service-principal/workload-identity credentials are detected (in config or environment). `interactive` still falls back to device code on headless machines |
| `clientSecret` | - | Service principal secret (top-level or per-profile); overrides `AZURE_CLIENT_SECRET` |
| `federatedTokenFile` | - | Workload identity token file (top-level or per-profile); overrides `AZURE_FEDERATED_TOKEN_FILE` |
| `federatedToken` | - | Raw workload identity token for testing (top-level or per-profile); overrides `AZURE_FEDERATED_TOKEN` |
| `httpClient` | - | HTTP client settings for token requests (timeouts, retries); response caching/compression stay off unless enabled here |
| `activeProfile` | - | Profile scafctl resolves when none is given (host-side; not forwarded to the plugin) |
| `profiles.<name>.*` | - | Per-profile overrides of the keys above |

`clientSecret`, `federatedTokenFile`, and `federatedToken` work at the top
level without a profile; a profile overlays them
(`scafctl auth login entra --profile <name>`). Other keys under
`auth.entra` are not recognized and are ignored.

### Sovereign Clouds

For a national (sovereign) cloud, set `authority` to the cloud's login
host, e.g. `https://login.microsoftonline.us` for Azure US Government.
The interactive flow reports its authorize URL as the verification URI,
and scafctl cancels the login unless that URL's host is trusted: the
built-in trusted list for `entra` is `login.microsoftonline.com` and
`login.microsoft.com`. Also set the cloud's login host in
`auth.trustedVerificationDomains` (or
`auth.handlers.entra.trustedVerificationDomains`) so the login proceeds.

### Environment Variables

| Variable | Description |
| ---------- | ------------- |
| `AZURE_CLIENT_ID` | App registration client ID (service principal / workload identity) |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_SECRET` | Client secret (service principal flow) |
| `AZURE_FEDERATED_TOKEN_FILE` | Path to projected SA token (workload identity) |
| `AZURE_FEDERATED_TOKEN` | Raw federated token (workload identity, testing) |
| `AZURE_AUTHORITY_HOST` | Authority URL for the workload identity flow only (defaults to `https://login.microsoftonline.com`); other flows use the `authority` config key |

Setting the matching config key (`clientId`, `tenantId`, `authority`,
`clientSecret`, `federatedTokenFile`, `federatedToken`) takes precedence
over the environment variable.

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

The handler is a positional argument (`scafctl auth login entra`), not a
`--handler entra` flag:

~~~bash
# Interactive login (default; no --flow needed). Opens a browser via
# authorization code + PKCE; falls back to device code automatically on
# headless machines (no DISPLAY/WAYLAND_DISPLAY, SSH sessions).
scafctl auth login entra

# Device code login, e.g. to opt out of the browser flow entirely
scafctl auth login entra --flow device-code

# Login with a specific tenant and/or custom app registration
scafctl auth login entra --tenant <tenant-id> --client-id <client-id>

# Interactive login over SSH or in a devcontainer: forward the port and
# pin it so the redirect URI is predictable
scafctl auth login entra --flow interactive --callback-port 8400

# Remote workspace (DevSpaces/Codespaces) paste-back login: the browser
# runs on your laptop, the redirect cannot reach the workspace, so paste
# the URL you landed on back into the prompt
scafctl auth login entra --scope "https://graph.microsoft.com/.default"

# Non-interactive service principal / workload identity (credentials
# from env vars or config, see above)
scafctl auth login entra --flow service-principal
scafctl auth login entra --flow workload-identity

# Check status
scafctl auth status entra

# Get a token
scafctl auth token entra --scope "https://graph.microsoft.com/.default"

# Logout
scafctl auth logout entra
~~~

`openid profile offline_access` are always requested for interactive
login, so the response contains an ID token and a refresh token. `--scope`
is optional; pass one (e.g. `--scope "https://graph.microsoft.com/.default"`)
only when the login should also consent to a specific API.

### Remote workspaces (paste-back login)

In OpenShift DevSpaces, GitHub Codespaces, and similar remote workspaces,
the browser runs on your laptop while this plugin runs inside the
workspace: the `http://localhost` redirect lands on the laptop and never
reaches the plugin, and device code may be blocked by Conditional Access
policies.

On hosts that support paste-back, interactive login works there anyway:

1. The plugin starts its callback server and prints the authorization URL.
2. Open that URL in any browser (your laptop's) and sign in. After consent,
   the browser is redirected to `http://localhost:<port>/?code=...&state=...`
   and will usually show a connection error there -- the callback listener
   runs inside the workspace and is unreachable from the laptop. That error
   is expected: authentication already succeeded, and the authorization
   code is in the address bar.
3. Copy the address-bar URL and paste it into the prompt the host shows
   (the scheme may be dropped when copying; it is restored automatically).
4. The paste is strictly validated -- scheme, host, port, and path must
   match this login's callback URI and the `state` must match -- and then
   exchanged exactly like a real redirect. A mismatched paste fails the
   login with a clear error.

With host paste-back support, a headless no-flag login selects interactive
instead of device code, and device code is used only via `--flow
device-code` or a `defaultFlow: device_code` config. On hosts without
paste-back support the previous behavior is unchanged (device code first on
headless sessions).

`--callback-port` still works over SSH port forwarding without paste-back:
forward the port (e.g. `ssh -L 8400:localhost:8400`) and pass
`--flow interactive --callback-port 8400` so the redirect URI is
predictable. Devcontainers can forward the port in their `ports`
configuration the same way.

### Upgrade Note

**Breaking change:** stored session metadata moved to the canonical
`auth.HandlerMetadata` schema. Sessions stored by plugin versions v0.3.0 and
earlier are rejected as legacy; log in once (`scafctl auth login entra`)
after upgrading to recreate the session.

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
