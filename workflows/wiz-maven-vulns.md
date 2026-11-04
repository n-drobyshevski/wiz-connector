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
  allowed: ["gpt-*"]          # firewall-enforced: no other model family can be called

strict: true
timeout-minutes: 25

concurrency:
  group: wiz-maven-vulns-${{ github.repository }}
  cancel-in-progress: false

network:
  allowed:
    - defaults                # mcp.app.wiz.io is added automatically from mcp-servers.wiz.url

tools:
  github: false               # the agent needs no GitHub access
  edit:                       # to write /tmp/gh-aw/agent/wiz/findings.json
  bash: ["cat", "jq", "wc", "head"]

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
  - name: Check out wiz-connector scripts
    uses: actions/checkout@v6
    with:
      repository: n-drobyshevski/wiz-connector
      ref: v1
      path: .wiz-connector
      persist-credentials: false
  - name: Resolve direct Maven dependencies
    env:
      MAVEN_DIR: "."            # directory of the root (reactor) pom.xml
    run: |
      set -euo pipefail
      OUT=/tmp/gh-aw/agent/wiz
      mkdir -p "$OUT"
      rm -f "$OUT/dependency-tree.json"          # the plugin appends to an existing file
      cd "$MAVEN_DIR"
      MVN=mvn; [ -x ./mvnw ] && MVN=./mvnw
      "$MVN" -v | head -1 > "$OUT/maven-version.txt"
      # From the reactor root, no -pl: every module becomes its own tree root.
      "$MVN" -B -ntp org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree \
        -DoutputType=json -DappendOutput=true -DoutputFile="$OUT/dependency-tree.json" > "$OUT/mvn-tree.log" 2>&1 \
        || { tail -50 "$OUT/mvn-tree.log"; exit 1; }
      if grep -Eq 'The POM for .* is missing' "$OUT/mvn-tree.log"; then
        grep -E 'The POM for .* is missing' "$OUT/mvn-tree.log"
        echo "::error::dependency tree is incomplete (missing POMs); fix repository access first"
        exit 1
      fi
      PYTHONPATH="$GITHUB_WORKSPACE/.wiz-connector" python3 -m wizconnector deps \
        --tree "$OUT/dependency-tree.json" --repo-root . --out "$OUT/direct-deps.json"
      cp "$GITHUB_WORKSPACE/.wiz-connector/schemas/wiz-findings.schema.json" "$OUT/"

safe-outputs:
  staged: ${{ github.event_name == 'workflow_dispatch' && inputs.staged }}
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
        Join the Wiz findings with the direct Maven dependencies and create, update or close the single
        tracking issue. Call exactly once, after writing /tmp/gh-aw/agent/wiz/findings.json.
      runs-on: ubuntu-latest
      max: 1
      output: Tracking issue reconciled
      artifacts:
        - /tmp/gh-aw/agent/wiz/
      permissions:
        contents: read
        issues: write
      inputs:
        summary:
          description: One line, e.g. "findings=12 other=40"
          required: true
          type: string
        findings_json:
          description: ONLY if writing findings.json failed, the same JSON document as a string (max 10 KB)
          required: false
          type: string
      steps:
        - name: Check out wiz-connector scripts
          uses: actions/checkout@v6
          with:
            repository: n-drobyshevski/wiz-connector
            ref: v1
            path: .wiz-connector
            persist-credentials: false
        - name: Join, render and publish
          env:
            GH_TOKEN: ${{ github.token }}
            GH_AW_AGENT_OUTPUT: ${{ runner.temp }}/gh-aw/safe-jobs/agent_output.json
            RUN_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
          run: |
            set -euo pipefail
            D="$(dirname "$GH_AW_AGENT_OUTPUT")/agent/wiz"
            export PYTHONPATH="$GITHUB_WORKSPACE/.wiz-connector"
            python3 -m wizconnector report \
              --deps "$D/direct-deps.json" \
              --findings "$D/findings.json" --agent-output "$GH_AW_AGENT_OUTPUT" \
              --maven-version-file "$D/maven-version.txt" \
              --run-url "$RUN_URL" --out-dir "$RUNNER_TEMP/wiz-report"
            python3 -m wizconnector publish --out-dir "$RUNNER_TEMP/wiz-report" --label wiz-sca
---

# Wiz → direct Maven dependency bumps

You are a read-only data-export step. A deterministic script joins your output with
`mvn dependency:tree` and writes the issue, so copy values exactly as Wiz returns them and
never invent CVEs, versions or fixed versions.

## Inputs
- Repository: `${{ github.repository }}`, branch `${{ github.ref_name }}`
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
   `${{ github.ref_name }}` is also scanned.
2. Step B: fetch OPEN vulnerability findings for that branch; paginate until done. Keep only
   Maven/Java library findings.
3. Write `/tmp/gh-aw/agent/wiz/findings.json` with **only** the findings whose artifactId is in
   `direct-deps.txt` (case-insensitive); count the other Maven findings in `other_findings_count`.
   Per finding: `cve` (CVE/GHSA id), `package` (`groupId:artifactId`), `version`,
   `fixed_versions` (array, `[]` if none), `severity`, and `cvss`, `has_exploit`, `cisa_kev`,
   `url` when available. Add `wiz_scope` (repository name/id, branch, tool calls).
4. Call `publish_wiz_report` once with `summary: "findings=<n> other=<m>"`.
   Only if you could not write the file, also pass the JSON document as `findings_json`.

## When Wiz fails
If authentication fails, Wiz is unreachable, or Wiz does not know this repository, do **not**
call `publish_wiz_report` (an empty list would close the tracking issue). Report it with the
missing-data safe output, naming what failed.
