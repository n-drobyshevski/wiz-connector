# wiz-connector

A scheduled **GitHub Agentic Workflow** (gh-aw, engine **Copilot**) that every *N* hours asks the
**Wiz MCP server** for open vulnerability findings on a Maven repository, keeps only the ones
fixable by bumping a **direct** dependency (`mvn dependency:tree`), and maintains **one compact,
Copilot-ready GitHub issue**. Developers then run `/wiz-maven-bumps <issue>` in Copilot (VS Code
agent mode) or assign the issue to the Copilot cloud agent.

```
 schedule (every 6h)
   │
   ├─ steps (runner, deterministic) ── mvn dependency:tree -DoutputType=json ─► wizconnector deps
   │                                     direct-deps.json  (direct deps + exact edit location)
   ├─ agent (Copilot, read-only, firewalled) ── Wiz MCP discover/execute ─► findings.json
   │                                     list_code_repositories → list_findings / list_vulnerability_findings
   └─ safe-output job publish-wiz-report (issues: write, deterministic)
                                         wizconnector report  → join, validate, pick target versions
                                         wizconnector publish → create / update / close ONE issue
```

The LLM only fetches data. Joining, version selection, rendering and issue writes are plain,
tested Python (stdlib only), so the issue is identical for identical inputs.

## What the issue looks like

```
**Goal:** bump 4 direct Maven dependencies to fix 8 CVEs (2 critical, 1 CISA-KEV) ...
**Copilot:** in VS Code agent mode run `/wiz-maven-bumps <this issue URL>`, or assign this issue to Copilot.

| # | Dependency                          | Bump                       | Severity       | CVEs                        | Edit                         |
| 1 | org.apache.logging.log4j:log4j-core | 2.14.1 → 2.17.1 (minor)    | CRITICAL · KEV | CVE-2021-44228, ... +1      | core/pom.xml <version>       |
| 3 | com.fasterxml.jackson.core:jackson-databind | 2.9.8 → 2.12.7.1   | HIGH           | CVE-2020-36518, ...         | pom.xml <jackson.version>    |

### Fix commands (run from the repository root)
mvn -B -ntp org.codehaus.mojo:versions-maven-plugin:2.23.0:use-dep-version -Dincludes=org.apache.logging.log4j:log4j-core -DdepVersion=2.17.1 ...
mvn -B -ntp org.codehaus.mojo:versions-maven-plugin:2.23.0:set-property -Dproperty=jackson.version -DnewVersion=2.12.7.1 ...
git diff --stat ; mvn -B -ntp verify ; mvn ... maven-dependency-plugin:3.11.0:tree -Dincludes=...
### Rules / Acceptance criteria (checklist)
<details> Not included: transitive, no fix yet, already fixed, not in tree </details>
<details> Machine-readable JSON (wiz-connector/maven-upgrades@v1), one upgrade per line </details>
```

- **Direct only.** A finding is kept when its package is a depth-1 dependency of any reactor
  module (sibling modules excluded) *and* a fixed version exists. Transitive findings are counted
  under *Not included*.
- **Target version** = the smallest listed fix that fixes *every* CVE of that dependency,
  respecting per-release-line fixes (`2.12.7.1` vs `2.13.4.2`), preferring non-pre-releases.
- **Edit location** is resolved from the POMs: literal `<version>`, `${property}` (and where it is
  defined), `dependencyManagement`, or "managed outside the repo" (BOM / external parent).
- **Stale data** (current tree already at a fixed version) is dropped.
- **Size**: about 4.5 KB for 4 upgrades; automatically shrunk below 60 KB.
- Everything Copilot needs is visible Markdown; the hidden `<!-- wiz-connector:... fingerprint=... -->`
  marker is only used for de-duplication.

## Install in a Maven repository

### 1. Wiz
1. Settings › Tenant › AI Features: enable the remote Wiz MCP server.
2. Settings › Deployments › Integrations › **Wiz MCP**: create an integration (service account),
   scoped to the right Projects, with **read-only** scopes: `read:repositories`,
   `read:vulnerabilities`, `read:sbom_artifacts`. Never grant `create:*`: in Gateway mode the
   agent's `execute` tool can reach every tool the account is allowed to use.
3. Note the client ID/secret and your **data center** (Tenant Info › Data Centers and Regions, e.g. `us17`).

Details and sources: [docs/wiz-mcp.md](docs/wiz-mcp.md).

### 2. Secrets (repository or organization)
| Secret | Value |
|---|---|
| `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, `WIZ_DATACENTER` | from step 1 |
| `COPILOT_GITHUB_TOKEN` | only without org-billed Copilot CLI: fine-grained PAT of a Copilot-licensed user, *Account › Copilot Requests: Read*; then remove `copilot-requests: write` from the workflow |

### 3. Workflow
```bash
gh extension install github/gh-aw                       # v1.0.1+
gh aw add n-drobyshevski/wiz-connector/wiz-maven-vulns@v1
gh aw compile --validate --strict
git add .github/workflows/wiz-maven-vulns.md .github/workflows/wiz-maven-vulns.lock.yml .github/aw/actions-lock.json
git commit -m "Add Wiz direct-dependency tracker" && git push
gh aw run wiz-maven-vulns          # first run: Actions › Run workflow with staged=true (dry run)
```
Each run checks out this repository at `ref: v1` for the scripts. If this repository is private,
give both `actions/checkout` steps a `token:` that can read it (e.g. `${{ secrets.WIZ_CONNECTOR_TOKEN }}`).

### 4. Copilot files
Copy [`copilot/`](copilot) into the target repository:

| File | Purpose |
|---|---|
| `.github/skills/wiz-maven-bumps/SKILL.md` | `/wiz-maven-bumps <issue>` in VS Code (Copilot and Local harness), Copilot CLI and the cloud agent |
| `.github/instructions/maven-pom.instructions.md` | POM editing rules (`applyTo: pom.xml,**/pom.xml`) |
| `.github/copilot-instructions.md` | lines to append: build command and pointer to the skill |
| `.github/workflows/copilot-setup-steps.yml` | JDK + Maven cache for cloud-agent sessions |
| `.mcp.json` | optional: query Wiz from VS Code with per-developer OAuth sign-in |

Notes for VS Code: reading the issue uses the GitHub MCP server (`issue_read`) or `gh issue view`;
on Copilot Business/Enterprise the "MCP servers in Copilot" policy must be enabled. OAuth sign-in for
remote MCP servers in Copilot-harness sessions has an open bug (microsoft/vscode#339960): start the
server from *MCP: List Servers* and sign in there.

## Configuration

| What | Where |
|---|---|
| Interval | `on.schedule: every 6h` (`daily`, `every 12h`, or cron); recompile after frontmatter edits |
| Maven project directory | `MAVEN_DIR` in the *Resolve direct Maven dependencies* step |
| Model | `engine.model` and `safe-outputs.threat-detection.engine.model` |
| Issue label | `--label wiz-sca` on `wizconnector publish` |
| Cloud-agent flow | `publish --on-change replace --assignee @copilot` and a `COPILOT_ASSIGN_TOKEN` secret (user PAT; `GITHUB_TOKEN` cannot assign Copilot) passed as env to the publish step. `replace` closes the old issue and opens a new one when findings change, because the cloud agent ignores edits made after assignment |
| Keep the issue open when clean | `publish --keep-open` |

### Keeping Anthropic models out
Claude models are not used anywhere, and this is enforced, not assumed:
`engine.model` is pinned (the default `auto` lets the Copilot gateway choose any model),
`models.allowed: ["gpt-*"]` is enforced by the gh-aw firewall, and the threat-detection job (which
would otherwise try a small Claude model first) is pinned too. Also: set the org-wide Copilot model
policy, avoid `.github/agents/*.agent.md` files naming Claude models, and confirm with
`gh aw audit <run-url> --models`.

## Safety model
- The agent job is read-only and firewalled; only the `publish-wiz-report` job has `issues: write`.
- The publish job bypasses gh-aw's sanitizer, so the Python validates every Wiz value: CVE/GHSA ids,
  Maven coordinates and versions must match strict patterns, URLs must be `https://*.wiz.io/…`, and no
  free text (descriptions, titles) is copied into the issue. Malformed records are dropped and counted.
- A Wiz outage never closes the issue: the agent reports missing data instead of calling the publish
  tool, and `report` exits non-zero if the findings contain `error`.
- Wiz credentials live only in `mcp-servers.wiz.headers` (never in `env:`).

## Local development
```bash
python -m unittest discover -s tests -v
mvn -B -ntp org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree -DoutputType=json -DappendOutput=true -DoutputFile=/tmp/tree.json
python -m wizconnector deps   --tree /tmp/tree.json --repo-root . --out /tmp/direct-deps.json
python -m wizconnector report --deps /tmp/direct-deps.json --findings findings.json --out-dir /tmp/out
python -m wizconnector publish --repo owner/name --out-dir /tmp/out --dry-run
python tests/validate_workflow.py main_workflow_schema.json workflows/*.md shared/mcp/*.md
```
The findings format is [schemas/wiz-findings.schema.json](schemas/wiz-findings.schema.json).
`shared/mcp/wiz.md` is a reusable Wiz MCP import for other gh-aw workflows.

## Known gaps
- Not yet run against a live Wiz tenant: Wiz does not publish the input/output shapes behind
  Gateway mode, so the agent discovers them at runtime. Check the first runs with `gh aw logs`.
- The frontmatter is validated against gh-aw v1.0.1's JSON schema in CI; `gh aw compile --strict` in
  the target repository is still the authoritative check.
- The `findings_json` fallback input is limited to 10 KB on gh-aw v1.0.1 (normal path is the file).
- Release this repository with a `v1` tag (the workflow pins `ref: v1`).
