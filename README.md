# scafctl-plugin-auth-entra

A [scafctl](https://github.com/oakwood-commons/scafctl) auth handler plugin for
**Microsoft Entra ID** (formerly Azure Active Directory).

## Supported Auth Flows

| Flow | Description |
|------|-------------|
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
|----------|-------------|
| `AZURE_CLIENT_ID` | App registration client ID (service principal / workload identity) |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_SECRET` | Client secret (service principal flow) |
| `AZURE_FEDERATED_TOKEN_FILE` | Path to projected SA token (workload identity) |
| `AZURE_FEDERATED_TOKEN` | Raw federated token (workload identity, testing) |
| `AZURE_AUTHORITY_HOST` | Custom authority host (defaults to `login.microsoftonline.com`) |

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
