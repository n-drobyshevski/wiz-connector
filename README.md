# wiz-connector

A scheduled **GitHub Agentic Workflow** (gh-aw, engine **Copilot**) that every *N* hours asks the
**Wiz MCP server** for open vulnerability findings on a Maven repository, keeps only the ones
fixable by bumping a **direct** dependency (`mvn dependency:tree`), and maintains **one compact,
Copilot-ready GitHub issue** plus **one automated pull request** with every bump that can be
applied mechanically. Copilot (VS Code agent mode, `/wiz-maven-bumps <issue>`, or the cloud agent)
only gets the rows that need judgment and any build breakage.

```
 schedule (every 6h)
   │
   ├─ steps (runner, deterministic) ── scripts/resolve-deps.sh: mvn dependency:tree -DoutputType=json
   │                                     → direct-deps.txt (scopes the agent's Wiz queries)
   ├─ agent (Copilot, read-only, firewalled) ── Wiz MCP discover/execute ─► findings.json
   │                                     list_code_repositories → list_findings / list_vulnerability_findings
   └─ safe-output job publish-wiz-report (issues: write, deterministic)
                                         resolve-deps.sh again on the same commit (trusted inventory)
                                         wizconnector report  → join, validate, pick target versions
                                         wizconnector apply   → run the safe bumps, re-check, mvn verify
                                         wizconnector publish → create / update / close ONE issue
                                         wizconnector pr      → one PR on wiz-connector/maven-bumps
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
- **Target version** = the smallest listed fix that fixes *every* CVE of that dependency in
  *every* module, respecting per-release-line fixes (`2.12.7.1` vs `2.13.4.2`), never below a
  version another module already uses, keeping the artifact flavour (`-jre` stays `-jre`), and
  preferring non-pre-releases.
- **Shared properties** (e.g. `jackson.version` for several Jackson artifacts) are flagged: the
  target must exist for every artifact using the property.
- **Edit location** is resolved from the POMs: literal `<version>`, `${property}` (and where it is
  defined), `dependencyManagement`, or "managed outside the repo" (BOM / external parent).
- **Stale data** (current tree already at a fixed version) is dropped.
- **Size**: about 4.5 KB for 4 upgrades; automatically shrunk below 60 KB.
- Everything Copilot needs is visible Markdown; the hidden `<!-- wiz-connector:... fingerprint=... -->`
  marker is only used for de-duplication.

## Automated PR
The publish job runs the same command plan the issue shows (as argument lists, no shell), for rows
that are safe to automate: literal `<version>`s and properties used only by the vulnerable artifact,
up to `WIZ_AUTO_PR_MAX_BUMP`. It then re-resolves the tree to confirm each row reached its target in
every module, runs `mvn -B -ntp verify`, and commits **only the changed `pom.xml` files** to
`wiz-connector/maven-bumps` as `github-actions[bot]`.

| Situation | What happens |
|---|---|
| bumps applied, build green | PR ready for review; `Fixes #issue` when nothing is left for Copilot |
| build fails | PR is a **draft** with the build-log tail; Copilot fixes the breakage on the branch |
| rows need judgment (external BOM/parent, shared property, above max bump) | marked `Copilot` in the issue's **Status** column; Copilot pushes them to the same branch |
| a person or Copilot pushed to the branch | the bot stops rewriting it |
| same result as last run | nothing is pushed |
| nothing left to apply | the bot's PR is closed and its branch deleted |

Settings (repository variables, see below): `WIZ_AUTO_PR=false` turns it off (issue only),
`WIZ_AUTO_PR_MAX_BUMP=minor` keeps major bumps for Copilot. Requirements: *Settings › Actions ›
General › Allow GitHub Actions to create and approve pull requests*. Pushes made with `GITHUB_TOKEN`
do not trigger other workflows, so CI does not run on the PR; add a `WIZ_PR_TOKEN` secret (fine-grained
PAT or GitHub App token with contents and pull-requests write) to get CI on it.

## Install in a Maven repository

### Quick setup (one command)
After the Wiz part below, from inside the target repository (with a local clone of wiz-connector):
```bash
gh extension install github/gh-aw                                   # once, v1.0.1+
bash ../wiz-connector/scripts/setup.sh                              # interactive
# or non-interactive:
bash ../wiz-connector/scripts/setup.sh --yes --schedule "daily around 9am on weekdays" \
     --datacenter us17 --max-bump minor --commit                    # WIZ_CLIENT_ID/SECRET from env
bash ../wiz-connector/scripts/setup.sh --doctor                     # check everything, any time
```
`setup.sh` does the following:
- installs the workflow (`gh aw add`, or `--local` to copy it from the clone) and sets the run time;
- with `--on-pom-change`, also runs on `pom.xml` pushes;
- compiles the workflow, copies the Copilot files and sets the repository variables;
- asks only for missing secrets, tests them against Wiz before saving, and passes them through stdin;
- allows GitHub Actions to open pull requests, keeping your default token permission;
- creates the label, and commits with `--commit`.

`--doctor` lists what is missing or misconfigured and shows the last runs. The manual steps below
do the same by hand.

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
| `COPILOT_GITHUB_TOKEN` | only without org-billed Copilot CLI (e.g. a personal account): fine-grained PAT of a Copilot-licensed user, *Account › Copilot Requests: Read*. `setup.sh --copilot-auth pat` removes `copilot-requests: write` and stores it |
| `WIZ_CONNECTOR_TOKEN` | needed while wiz-connector is private: fine-grained PAT with *Contents: Read* on this repository; setup.sh asks for it when it detects a private repo |
| `WIZ_PR_TOKEN` | optional: token used to push the bump branch and open the PR, so CI runs on it |

### 3. Workflow
```bash
gh extension install github/gh-aw                       # v1.0.1+
gh aw add <owner>/wiz-connector/wiz-maven-vulns@v1          # <owner>: where this repository lives
gh aw compile --validate --strict
git add .github/workflows/wiz-maven-vulns.md .github/workflows/wiz-maven-vulns.lock.yml .github/aw/actions-lock.json
git commit -m "Add Wiz direct-dependency tracker" && git push
gh aw run wiz-maven-vulns          # first run: Actions › Run workflow with staged=true (dry run)
```
Each run checks out this repository at `ref: v1` for the scripts (frontmatter `checkout:` and
the publish job), using `WIZ_CONNECTOR_TOKEN` if set (required while this repository is private).
Pin a commit SHA instead of the tag for stricter supply-chain control.

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

## Run time, manual runs and settings

### When it runs
| Trigger | How |
|---|---|
| Schedule | `setup.sh --schedule "<gh-aw schedule>"`: `every 6h` (default), `every 12h on weekdays`, `daily around 9am on weekdays`, `daily between 22:00 and 02:00`, `weekly on monday` (fuzzy, UTC). Fixed time in your zone: `--cron "30 7 * * 1-5" --timezone Europe/Paris`. The run time is the one setting that needs a recompile, which setup.sh does |
| Manual | *Actions › wiz-maven-vulns › Run workflow*: tick **staged** for a dry run, and override *auto_pr*, *max_bump* or *min_severity* for this run only. CLI: `gh aw run wiz-maven-vulns` |
| From the issue | comment `/wiz-scan` on the tracking issue (users with write access or above); gh-aw reacts and posts a status comment with the run link |
| After dependency changes | `setup.sh --on-pom-change [branch]` adds a push trigger on `**/pom.xml`, so the issue and PR refresh right after a merge (each run is one Copilot agent run); `--on-pom-change ''` removes it |

### Settings: repository variables, no recompile
*Settings › Secrets and variables › Actions › Variables* (setup.sh writes them; a manual run can
override the first three):

| Variable | Default | Effect |
|---|---|---|
| `WIZ_AUTO_PR` | `true` | `false` = issue only, no automated PR |
| `WIZ_AUTO_PR_MAX_BUMP` | `major` | highest bump applied automatically (`patch`, `minor`, `major`); bigger ones go to Copilot |
| `WIZ_MIN_SEVERITY` | `LOW` | hide CVEs below this level (`MEDIUM`, `HIGH`, `CRITICAL`); CISA-KEV and unknown severity are always listed |
| `WIZ_MAVEN_DIR` | `.` | directory of the root `pom.xml`, relative to the repository root |
| `WIZ_ISSUE_LABEL` | `wiz-sca` | label of the tracking issue (and of the PR) |

### Advanced (edit the workflow)
| What | Where |
|---|---|
| Model | `engine.model` and `safe-outputs.threat-detection.engine.model` (recompile) |
| Cloud-agent flow | `publish --on-change replace --assignee @copilot` and a `COPILOT_ASSIGN_TOKEN` secret (user PAT; `GITHUB_TOKEN` cannot assign Copilot) passed as env to the publish step. `replace` closes the old issue and opens a new one when findings change, because the cloud agent ignores edits made after assignment |
| Keep the issue open when clean | `publish --keep-open` |
| Issues created by a custom token | `publish --trusted-author <login>` (default: the GitHub Actions bot) |

### Model policy
Only the pinned GPT model is used:
- `engine.model` is pinned (the default `auto` lets the Copilot gateway choose any model family);
- `models.allowed: ["gpt-*"]` is enforced by the agent job's API proxy;
- the threat-detection job (whose default alias may pick another model family) is pinned to the
  same model; with the Copilot provider an unavailable model fails the run instead of being
  substituted. The `models.allowed` policy itself is not applied to the detection job; to enforce
  it there too, compile with `GHAW_POLICY_MODELS_ALLOWED='gpt-*'`.
Also set the org-wide Copilot model policy (it covers Copilot in VS Code too), keep
`.github/agents/*.agent.md` files free of other `model:` choices, and check runs with
`gh aw audit <run-url> --models`.

## Safety model
- The agent job is read-only and firewalled; only the `publish-wiz-report` job has write
  permissions (`issues`, `pull-requests`, and `contents` to push the bump branch).
- The automated PR contains only `pom.xml` changes produced by validated versions-maven-plugin
  commands; the bot never force-pushes over commits made by anyone else.
- The agent can write `/tmp/gh-aw/agent/`, so the publish job takes only `findings.json` from it and
  rebuilds the dependency inventory itself from the same commit.
- The publish job bypasses gh-aw's sanitizer, so the Python validates every value: CVE/GHSA ids,
  Maven coordinates, versions, property names and paths must match strict patterns (anything else
  becomes "edit by hand", never a command), URLs must be `https://*.wiz.io/…`, and no free text
  (descriptions, titles) is copied into the issue. Malformed records are dropped and counted.
- Fail closed: the issue is closed only when Wiz answered (`wiz_scope` names the repository) and
  nothing actionable is left. An `error`, a missing `findings` key or all-malformed records fail the job.
- Only issues opened by the bot whose first line is the exact marker are updated or closed; an
  edited body is restored on the next run. The Copilot skill applies the same author/marker check
  before running any command.
- Wiz credentials live only in `mcp-servers.wiz.headers` (never in `env:`).

## Test repository
[`test-repo/`](test-repo) is a deliberately vulnerable multi-module Spring Boot app in which every
dependency exercises one branch: literal, property with a child override, external-parent property,
BOM-managed, test scope, `-jre` flavour, transitive-only and sibling module. It comes with
Wiz-shaped sample findings and golden expectations. CI resolves it live, renders the issue, runs
the issue's fix commands plus the "edit by hand" changes, runs `mvn verify`, and checks that nothing
is left. `scripts/make-test-repo.sh <dir>` exports it as a standalone repository with the workflow
and Copilot files installed, to try the real pipeline against Wiz.

## Local development
```bash
python -m unittest discover -s tests -v
mvn -B -ntp org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree -DoutputType=json -DappendOutput=true -DoutputFile=/tmp/tree.json
bash scripts/resolve-deps.sh /tmp/wiz        # or the three steps by hand:
python -m wizconnector deps   --tree /tmp/tree.json --repo-root . --out /tmp/direct-deps.json
python -m wizconnector report --deps /tmp/direct-deps.json --findings findings.json --out-dir /tmp/out
python -m wizconnector publish --repo owner/name --out-dir /tmp/out --dry-run
python tests/validate_workflow.py main_workflow_schema.json workflows/*.md shared/mcp/*.md
bash scripts/setup.sh --help                 # setup / doctor for a target repository
bash tests/e2e_test_repo.sh                  # live end-to-end on test-repo/
```
The findings format is [schemas/wiz-findings.schema.json](schemas/wiz-findings.schema.json).
`shared/mcp/wiz.md` is a reusable Wiz MCP import for other gh-aw workflows.

## Known gaps
- Not yet run against a live Wiz tenant: Wiz does not publish the input/output shapes behind
  Gateway mode, so the agent discovers them at runtime. Check the first runs with `gh aw logs`.
- The frontmatter is validated against gh-aw v1.0.1's JSON schema in CI; `gh aw compile --strict` in
  the target repository is still the authoritative check.
- The `findings_json_b64` fallback input is limited to 10 KB on gh-aw v1.0.1 (normal path is the file).
- The publish job runs Maven a second time (about a minute with the Maven cache): the price of not
  trusting agent-writable files.
- `--on-change replace` with `@copilot` assignment starts a new cloud-agent session whenever the
  findings change; close or merge the previous Copilot PR to avoid duplicates.
- Release this repository with a `v1` tag (the workflow pins `ref: v1`).
