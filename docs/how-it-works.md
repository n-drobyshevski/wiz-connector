# How it works

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

The model only fetches data. Joining, version selection, rendering and issue/PR writes are plain,
tested Python (stdlib only), so the output is identical for identical inputs.

## The issue

```
**Goal:** bump 4 direct Maven dependencies to fix 8 CVEs (2 critical, 1 CISA-KEV) ...
**Copilot:** in VS Code agent mode run `/wiz-maven-bumps <this issue URL>`, or assign this issue to Copilot.

| # | Dependency                          | Bump                       | Severity       | CVEs                   | Edit                      | Status  |
| 1 | org.apache.logging.log4j:log4j-core | 2.14.1 → 2.17.1 (minor)    | CRITICAL · KEV | CVE-2021-44228, ... +1 | core/pom.xml <version>    | PR      |
| 3 | org.yaml:snakeyaml                  | 1.29 → 2.0 (major)         | CRITICAL       | CVE-2022-1471, ... +2  | add <snakeyaml.version>   | Copilot |

### Fix commands (bash, from the repository root)
mvn -B -ntp org.codehaus.mojo:versions-maven-plugin:2.23.0:use-dep-version -Dincludes=... -DdepVersion=2.17.1 ...
git diff --stat ; mvn -B -ntp verify ; mvn ... maven-dependency-plugin:3.11.0:tree -Dincludes=...
### Rules / Acceptance criteria (checklist)
<details> Not included: transitive, no fix yet, already fixed, below min severity, not in tree </details>
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

## The automated PR

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

Requirements: *Settings › Actions › General › Allow GitHub Actions to create and approve pull
requests* (setup.sh enables it). Pushes made with `GITHUB_TOKEN` do not trigger other workflows, so
CI does not run on the PR unless you add a `WIZ_PR_TOKEN` secret.

## Copilot in VS Code

`/wiz-maven-bumps <issue URL>` (skill in `copilot/.github/skills/`) checks that the issue was opened by
the bot, switches to the bot's branch, does only the rows marked `Copilot` plus any build breakage,
and pushes to the same branch. Reading the issue uses the GitHub MCP server (`issue_read`) or
`gh issue view`. On Copilot Business/Enterprise the "MCP servers in Copilot" policy must be enabled.
