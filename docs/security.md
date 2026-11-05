# Safety model

- The agent job is read-only and firewalled; only the `publish-wiz-report` job has write
  permissions (`issues`, `pull-requests`, and `contents` to push the bump branch).
- The Wiz service account gets read scopes only (`read:repositories`, `read:vulnerabilities`,
  `read:sbom_artifacts`): in Gateway mode the agent's `execute` tool can reach every tool the account
  is allowed to use. Credentials live only in `mcp-servers.wiz.headers`, never in `env:`.
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
