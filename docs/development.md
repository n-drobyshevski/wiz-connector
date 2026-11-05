# Development

```bash
python -m unittest discover -s tests -v
bash scripts/resolve-deps.sh /tmp/wiz        # mvn dependency:tree + inventory for the current repo
python -m wizconnector report --deps /tmp/wiz/direct-deps.json --findings findings.json --out-dir /tmp/out
python -m wizconnector publish --repo owner/name --out-dir /tmp/out --dry-run
python tests/validate_workflow.py main_workflow_schema.json workflows/*.md shared/mcp/*.md
bash tests/e2e_test_repo.sh                  # live end-to-end on test-repo/ (JDK 17+, Maven)
```
The findings format is [schemas/wiz-findings.schema.json](../schemas/wiz-findings.schema.json).
`shared/mcp/wiz.md` is a reusable Wiz MCP import for other gh-aw workflows.

## Test repository
[`test-repo/`](../test-repo) is a deliberately vulnerable multi-module Spring Boot app in which every
dependency exercises one branch: literal, property with a child override, external-parent property,
BOM-managed, test scope, `-jre` flavour, transitive-only and sibling module. It comes with Wiz-shaped
sample findings and golden expectations. CI resolves it live, renders the issue, auto-applies the
safe rows, makes the "edit by hand" changes, runs `mvn verify`, and checks that nothing is left.
`scripts/make-test-repo.sh <dir>` exports it as a standalone repository with the workflow and Copilot
files installed.

## Known gaps
- Not yet run against a live Wiz tenant: Wiz does not publish the input/output shapes behind
  Gateway mode, so the agent discovers them at runtime. Check the first runs with `gh aw logs`.
- The frontmatter is validated against gh-aw v1.0.1's JSON schema in CI; `gh aw compile --strict` in
  the target repository is still the authoritative check.
- The `findings_json_b64` fallback input is limited to 10 KB on gh-aw v1.0.1 (the normal path is the file).
- The publish job runs Maven a second time (about a minute with the Maven cache): the price of not
  trusting agent-writable files.
