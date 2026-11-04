# Wiz MCP: facts this project relies on

Sources: the Wiz docs extract supplied with the project (pages *Wiz MCP*, *AI Platform Tools*,
*AI Skills Library*, *Quotas & Limits*), Wiz's connector definition in
`aws/tools-for-devops-agent` PR #181 (2026-11-02), and live probes of `https://mcp.app.wiz.io/`.

## Server
- Remote, Wiz-hosted, Streamable HTTP at `https://mcp.app.wiz.io` (root path). GA since 2026-07-02.
  Not available in Wiz for Gov.
- Toolsets narrow the catalog: `https://mcp.app.wiz.io?toolset=<name>` (documented: `threat_intel`,
  `devops`). No toolset = full catalog.
- **Gateway mode (default)**: only two tools are exposed, `discover` (selects the right tool) and
  `execute` (runs it). Gateway mode can be disabled to expose 150+ tools directly.
- Activity is logged in Settings > Audit Log with a `Wiz-MCP-Server*remote` user agent.

## Authentication for CI (headless)
- Create a **Wiz MCP Integration** (service account): Settings > Deployments > Integrations > Wiz MCP
  (`https://app.wiz.io/settings/deployments/integrations/new/wiz-mcp`). Remote MCP must be enabled under
  Settings > Tenant > AI Features. The integration can be scoped to Projects.
- Send three headers: `Wiz-Client-Id`, `Wiz-Client-Secret`, `Wiz-DataCenter` (e.g. `us17`, from
  Tenant Info > Data Centers and Regions).
- The server's OAuth endpoint only supports `authorization_code` (+PKCE) and `refresh_token`
  (no `client_credentials`), and sign-in sessions expire (30 days by default). Use headers in CI.

## Tools used by this workflow (name → scope)
| Tool | Scope | Why |
|---|---|---|
| `list_code_repositories` | `read:repositories` | find the repository / branch resource |
| `list_findings` | `read:vulnerabilities` (+ others for non-vuln types) | "Show me findings on repository branch REPO_BRANCH_ID" |
| `list_vulnerability_findings` | `read:vulnerabilities` | vulnerability findings with filters |
| `get_vulnerability_finding` | `read:vulnerabilities` | "severity and fix version for the finding" |
| `list_package_dependencies` | `read:sbom_artifacts` | "Is log4j a direct dependency?" (cross-check) |
| `get_vulnerability_assessment_settings` | `read:scanner_settings` | diagnostics: "Are lock files being scanned in repository branches?" |

**Least privilege:** grant the service account only `read:repositories`, `read:vulnerabilities`,
`read:sbom_artifacts` (optionally `read:scanner_settings`). The catalog contains write tools
(e.g. `create_penetration_test_finding` needs `create:penetration_test_findings`); never grant `create:*`.

## Limits
- Wiz MCP Server: 10 calls/s per user or service account, 100 calls/s per tenant, 2 minutes per query.
- Wiz Code multi-branch scanning: up to 3 additional branches, configured per repository.
- Repositories larger than 10 GB are not scanned.
