---
description: Every 6h, fetch open Wiz vulnerability findings for this repo, keep only DIRECT Maven dependencies we can bump, and maintain one compact Copilot-ready tracking issue
on:
  schedule: every 6h
  workflow_dispatch:
    inputs:
      staged:
        description: Dry run (render the issue in the job summary, do not touch issues)
        type: boolean
        default: false

permissions:
  contents: read
  # Copilot inference billed to the org (needs "Copilot CLI billed to the organization").
  # Without org billing: remove this line and set the COPILOT_GITHUB_TOKEN secret instead.
  copilot-requests: write

engine:
  id: copilot
  # Pin a non-Anthropic model: the default "auto" lets the Copilot gateway pick any model.
  model: gpt-5.4
  mcp:
    tool-timeout: 3m          # Wiz allows 2-minute queries; the gateway default is 60s

models:
  allowed: ["gpt-*"]          # enforced by the agent job's API proxy (detection is pinned below)

strict: true
timeout-minutes: 25

concurrency:
  group: wiz-maven-vulns-${{ github.repository }}
  cancel-in-progress: false

env:
  MAVEN_DIR: "."              # directory of the root (reactor) pom.xml, relative to the repo root
  WIZ_AUTO_PR: "true"         # apply safe bumps and open/update one PR; "false" = issue only
  WIZ_AUTO_PR_MAX_BUMP: major # patch | minor | major: highest bump applied automatically

# Declaring checkouts here keeps gh-aw's default checkout of this repository; an actions/checkout
# inside steps: would silently replace it.
checkout:
  - {}
  - repository: n-drobyshevski/wiz-connector
    ref: v1                   # pin a commit SHA for stricter supply-chain control
    path: .wiz-connector

network:
  allowed:
    - defaults                # mcp.app.wiz.io is added automatically from mcp-servers.wiz.url

tools:
  github: false               # the agent needs no GitHub access
  edit:                       # to write /tmp/gh-aw/agent/wiz/findings.json
  bash: ["cat", "jq", "wc", "head", "base64"]

mcp-servers:
  wiz:
    url: "https://mcp.app.wiz.io"
    headers:
      Wiz-Client-Id: "${{ secrets.WIZ_CLIENT_ID }}"
      Wiz-Client-Secret: "${{ secrets.WIZ_CLIENT_SECRET }}"
      Wiz-DataCenter: "${{ secrets.WIZ_DATACENTER }}"
    # Gateway mode (Wiz default) exposes only these two tools. They can reach any Wiz tool,
    # so least privilege comes from the service-account scopes (read-only, see README).
    allowed: [discover, execute]

steps:
  # Runs on the runner, outside the agent firewall, before the agent starts.
  - name: Set up JDK
    uses: actions/setup-java@v6
    with:
      distribution: temurin
      java-version: "21"
      cache: maven
  - name: Resolve direct Maven dependencies
    run: |
      set -euo pipefail
      OUT=/tmp/gh-aw/agent/wiz
      bash .wiz-connector/scripts/resolve-deps.sh "$OUT"
      cp .wiz-connector/schemas/wiz-findings.schema.json "$OUT/"
      printf 'repository=%s\nbranch=%s\n' "$GITHUB_REPOSITORY" "$GITHUB_REF_NAME" > "$OUT/context.txt"

safe-outputs:
  staged: ${{ github.event_name == 'workflow_dispatch' && inputs.staged }}
  allowed-domains: ["app.wiz.io"]   # keep Wiz portal links in sanitized agent outputs
  create-issue: false         # the custom job below is the only writer
  noop:
    report-as-issue: false
  threat-detection:
    engine:
      id: copilot
      model: gpt-5.4          # detection would otherwise try a small Claude model first
  jobs:
    publish-wiz-report:
      description: >-
        Join the Wiz findings with the direct Maven dependencies, create, update or close the single
        tracking issue, and open the automated bump PR. Call exactly once, after writing
        /tmp/gh-aw/agent/wiz/findings.json.
      runs-on: ubuntu-latest
      max: 1
      output: Tracking issue and bump PR reconciled
      artifacts:
        - /tmp/gh-aw/agent/wiz/
      permissions:
        contents: write           # push the wiz-connector/maven-bumps branch (pom.xml changes only)
        issues: write
        pull-requests: write
      inputs:
        summary:
          description: One line, e.g. "findings=12 other=40"
          required: true
          type: string
        findings_json_b64:
          description: ONLY if writing findings.json failed, the same JSON document base64-encoded (max 10 KB)
          required: false
          type: string
      steps:
        # The agent can write /tmp/gh-aw/agent, so only findings.json is taken from it. The
        # dependency inventory is rebuilt here from the same commit.
        - name: Check out the repository (same commit as the agent run)
          uses: actions/checkout@v6
          with:
            ref: ${{ github.sha }}
            persist-credentials: false
        - name: Check out wiz-connector scripts
          uses: actions/checkout@v6
          with:
            repository: n-drobyshevski/wiz-connector
            ref: v1
            path: .wiz-connector
            persist-credentials: false
        - name: Set up JDK
          uses: actions/setup-java@v6
          with:
            distribution: temurin
            java-version: "21"
            cache: maven
        - name: Rebuild the dependency inventory (trusted)
          run: bash .wiz-connector/scripts/resolve-deps.sh "$RUNNER_TEMP/wiz-inventory"
        - name: Join, render, auto-apply and publish
          env:
            GH_TOKEN: ${{ github.token }}
            # A PAT or GitHub App token makes CI run on the bump PR (GITHUB_TOKEN pushes do not
            # trigger workflows). Falls back to GITHUB_TOKEN.
            PR_TOKEN: ${{ secrets.WIZ_PR_TOKEN || github.token }}
            GH_AW_AGENT_OUTPUT: ${{ runner.temp }}/gh-aw/safe-jobs/agent_output.json
            # custom jobs do not inherit staged mode: pass it explicitly (dry run of issue + PR)
            GH_AW_SAFE_OUTPUTS_STAGED: ${{ github.event_name == 'workflow_dispatch' && inputs.staged }}
            RUN_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
          run: |
            set -euo pipefail
            INV="$RUNNER_TEMP/wiz-inventory"
            R="$RUNNER_TEMP/wiz-report"
            export PYTHONPATH="$GITHUB_WORKSPACE/.wiz-connector"
            report() {
              python3 -m wizconnector report \
                --deps "$INV/direct-deps.json" --maven-version-file "$INV/maven-version.txt" \
                --findings "$(dirname "$GH_AW_AGENT_OUTPUT")/agent/wiz/findings.json" \
                --agent-output "$GH_AW_AGENT_OUTPUT" --maven-dir "$MAVEN_DIR" \
                --run-url "$RUN_URL" --out-dir "$R" "$@"
            }
            report
            if [ "$WIZ_AUTO_PR" = "true" ]; then
              # deterministic: the same command plan the issue shows, run without a shell
              python3 -m wizconnector apply --out-dir "$R" --repo-root . --maven-dir "$MAVEN_DIR" \
                --max-bump "$WIZ_AUTO_PR_MAX_BUMP" || echo "::warning::auto-apply failed; issue only"
              [ -f "$R/apply-result.json" ] && report --apply-result "$R/apply-result.json"
            fi
            python3 -m wizconnector publish --out-dir "$R" --label wiz-sca
            if [ "$WIZ_AUTO_PR" = "true" ]; then
              git remote set-url origin "https://x-access-token:${PR_TOKEN}@${GITHUB_SERVER_URL#https://}/${GITHUB_REPOSITORY}.git"
              GH_TOKEN="$PR_TOKEN" python3 -m wizconnector pr --out-dir "$R" --repo-root . --base "$GITHUB_REF_NAME"
            fi
---

# Wiz → direct Maven dependency bumps

You are a read-only data-export step. A deterministic script joins your output with
`mvn dependency:tree` and writes the issue, so copy values exactly as Wiz returns them and
never invent CVEs, versions or fixed versions.

## Inputs
- Repository: `${{ github.repository }}`; the scanned branch is in `/tmp/gh-aw/agent/wiz/context.txt`
- `/tmp/gh-aw/agent/wiz/direct-deps.txt`: this repo's direct Maven dependencies, one
  `groupId:artifactId:version` per line. Read it first.
- `/tmp/gh-aw/agent/wiz/wiz-findings.schema.json`: the JSON schema of your output.

## Wiz MCP
The `wiz` server runs in Gateway mode: call `discover` to select a Wiz tool by name, then
`execute` to run it. Ask for these tools **by name**:

| Step | Wiz tool | Use |
|---|---|---|
| A | `list_code_repositories` | find the Wiz repository for `${{ github.repository }}` and its branch id |
| B | `list_findings` | OPEN vulnerability findings on that repository branch |
| B' | `list_vulnerability_findings` | fallback: OPEN vulnerability findings filtered to the repository |
| C | `get_vulnerability_finding` | only when a finding lacks its fixed version |

Never use a tool that creates, updates or deletes anything. Prefer filtered, paginated queries
(Wiz limits: 10 calls/s, 2 minutes per query).

## Steps
1. Step A: locate the repository by name and URL. Use the default branch Wiz scanned unless
   the branch in `context.txt` is also scanned.
2. Step B: fetch OPEN vulnerability findings for that branch; paginate until done. Keep only
   Maven/Java library findings.
3. Write `/tmp/gh-aw/agent/wiz/findings.json` with **only** the findings whose artifactId is in
   `direct-deps.txt` (case-insensitive); count the other Maven findings in `other_findings_count`.
   Per finding: `cve` (CVE/GHSA id), `package` (`groupId:artifactId`), `version`,
   `fixed_versions` (array, `[]` if none), `severity`, and `cvss`, `has_exploit`, `cisa_kev`,
   `url` when available. Always add `wiz_scope` with the Wiz `resource_name` and/or `resource_id`
   of the repository, the branch and the number of tool calls: without it an empty list is
   rejected.
4. Call `publish_wiz_report` once with `summary: "findings=<n> other=<m>"`.
   Only if you could not write the file, also pass the JSON document base64-encoded as
   `findings_json_b64` (`jq -c . file | base64 -w0`).

## When Wiz fails
If authentication fails, Wiz is unreachable, or Wiz does not know this repository, do **not**
call `publish_wiz_report` (an empty list would close the tracking issue). Report it with the
missing-data safe output, naming what failed.
