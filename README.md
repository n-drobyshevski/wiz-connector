# wiz-connector

A scheduled **GitHub Agentic Workflow** (engine: Copilot) for Maven repositories. Every few hours it
asks **Wiz** for open vulnerability findings, keeps the ones you can fix by bumping a **direct**
dependency, and maintains:

- **one tracking issue** with each bump, the file to edit and the exact command;
- **one pull request** that already applies every bump that can be done mechanically.

Copilot (`/wiz-maven-bumps <issue>` in VS Code, or the cloud agent) only gets the rows that need
judgment and any build breakage.

## How it works
1. `mvn dependency:tree` finds the direct dependencies and where each version is declared.
2. The Copilot agent reads open findings from the Wiz MCP server (read-only).
3. Plain Python joins the two, picks the minimal safe version, applies the safe bumps, runs
   `mvn verify`, then creates or updates the issue and the PR.

Details: [docs/how-it-works.md](docs/how-it-works.md).

## Quick start
You need `git`, `gh` with `gh extension install github/gh-aw`, Python 3.10+ and bash (Git Bash on
Windows). No local JDK.

1. **Wiz:** enable the remote MCP server and create a *Wiz MCP Integration* with read-only scopes
   ([docs/wiz-mcp.md](docs/wiz-mcp.md)).
2. **Install:** from inside the target repository:
   ```bash
   bash ../wiz-connector/scripts/setup.sh --commit && git push   # interactive; asks for missing secrets
   bash ../wiz-connector/scripts/setup.sh --doctor                # check the setup any time
   ```
3. **First run:** *Actions › wiz-maven-vulns › Run workflow* with **staged** ticked (dry run).

## Everyday use
- **Re-run now:** comment `/wiz-scan` on the tracking issue.
- **Run time:** `setup.sh --schedule "daily around 9am on weekdays"`.
- **Behaviour:** repository variables, no recompile needed:
  - `WIZ_AUTO_PR` turns the automated PR on or off;
  - `WIZ_AUTO_PR_MAX_BUMP` caps the bumps applied automatically;
  - `WIZ_MIN_SEVERITY` hides lower-severity CVEs;
  - `WIZ_MAVEN_DIR` points to the root `pom.xml`.

All options: [docs/configuration.md](docs/configuration.md).

## More
- [docs/security.md](docs/security.md): safety model
- [docs/development.md](docs/development.md): tests, test repository, known gaps
- [test-repo/](test-repo): a deliberately vulnerable app to try it end to end
