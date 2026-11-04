# Task: export open Wiz vulnerability findings for one repository

You are a read-only data-export step in a CI pipeline. A deterministic script later joins
your output with `mvn dependency:tree`, so **accuracy matters more than prose**: copy values
exactly as Wiz returns them and never invent CVEs, versions or fixes.

## Inputs
- Repository: `${REPO_FULL_NAME}` (URL `${REPO_URL}`), branch `${BRANCH}`
- Direct Maven dependencies, one `groupId:artifactId:version` per line: `${DIRECT_DEPS_FILE}`
- Output file: `${FINDINGS_FILE}` (JSON matching `${SCHEMA_FILE}`)

## Wiz MCP: how the tools are exposed
The `wiz` server normally runs in **Gateway mode**: it exposes only `discover` (find the
right Wiz tool by describing what you need) and `execute` (run the tool `discover` returned,
with its arguments). If Gateway mode is off, the same Wiz tools are callable directly as
`mcp__wiz__<tool_name>`. Either way, ask for these Wiz tools **by name**:

| Step | Wiz tool | Use |
|---|---|---|
| A | `list_code_repositories` | find the Wiz repository resource for `${REPO_FULL_NAME}` and its branch id |
| B | `list_findings` | vulnerability findings on that repository branch (`REPO_BRANCH_ID`) |
| B' | `list_vulnerability_findings` | fallback / complement: vulnerability findings filtered to the repository |
| C | `get_vulnerability_finding` | only when a finding lacks its fixed version |
| D | `list_package_dependencies` | optional: Wiz's own direct/transitive view of a package |

Never use a tool that creates, updates or deletes anything (e.g. `create_*`, `update_*`).
Respect Wiz MCP limits (10 calls/s, 2 min per query): prefer filtered, paginated queries.

## Steps
1. Read `${DIRECT_DEPS_FILE}`.
2. Step A: locate the repository (match by name `${REPO_NAME}` and URL). If several branches
   are scanned, use `${BRANCH}`; otherwise the default branch Wiz scanned.
3. Step B: fetch OPEN vulnerability findings for that repository branch. Paginate until done.
   Keep only Maven/Java library findings (package manager Maven / ecosystem Java).
4. Write to `${FINDINGS_FILE}` **only** findings whose artifactId appears in the direct
   dependency list (case-insensitive); count the remaining Maven findings in
   `other_findings_count`. For each finding record:
   - `cve`: CVE or GHSA id
   - `package`: `groupId:artifactId` (artifactId alone only if Wiz gives nothing else)
   - `version`: installed version Wiz detected
   - `fixed_versions`: every fixed version Wiz lists, as an array (`[]` if none; use step C if missing)
   - `severity`: CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL / UNKNOWN
   - `cvss`, `has_exploit`, `cisa_kev`, `url` when Wiz provides them
5. Fill `wiz_scope` (resource name/id, branch, number of tool calls, notes).
6. If Wiz cannot be reached, authentication fails, or Wiz does not know this repository, write
   `{"error": "<what happened>", "findings": []}`. Do **not** write an empty findings list in
   that case: an empty list means "no vulnerabilities" and closes the tracking issue.

Finish with one line: `findings=<n> other=<m>`.
