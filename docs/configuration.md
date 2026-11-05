# Configuration

## When it runs
| Trigger | How |
|---|---|
| Schedule | `setup.sh --schedule "<gh-aw schedule>"`: `every 6h` (default), `every 12h on weekdays`, `daily around 9am on weekdays`, `daily between 22:00 and 02:00`, `weekly on monday` (fuzzy, UTC). Fixed time in your zone: `--cron "30 7 * * 1-5" --timezone Europe/Paris`. The run time is the one setting that needs a recompile, which setup.sh does |
| Manual | *Actions › wiz-maven-vulns › Run workflow*: tick **staged** for a dry run, and override *auto_pr*, *max_bump* or *min_severity* for this run only. CLI: `gh aw run wiz-maven-vulns` |
| From the issue | comment `/wiz-scan` on the tracking issue (users with write access or above) |
| After dependency changes | `setup.sh --on-pom-change [branch]` adds a push trigger on `**/pom.xml` (each run is one Copilot agent run); `--on-pom-change ''` removes it |

## Repository variables (no recompile)
*Settings › Secrets and variables › Actions › Variables*. setup.sh writes them; a manual run can
override the first three.

| Variable | Default | Effect |
|---|---|---|
| `WIZ_AUTO_PR` | `true` | `false` = issue only, no automated PR |
| `WIZ_AUTO_PR_MAX_BUMP` | `major` | highest bump applied automatically (`patch`, `minor`, `major`); bigger ones go to Copilot |
| `WIZ_MIN_SEVERITY` | `LOW` | hide CVEs below this level; CISA-KEV and unknown severity are always listed |
| `WIZ_MAVEN_DIR` | `.` | directory of the root `pom.xml`, relative to the repository root |
| `WIZ_ISSUE_LABEL` | `wiz-sca` | label of the tracking issue (and of the PR) |

## Secrets
| Secret | Value |
|---|---|
| `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, `WIZ_DATACENTER` | the Wiz MCP Integration (see [wiz-mcp.md](wiz-mcp.md)) |
| `COPILOT_GITHUB_TOKEN` | only without org-billed Copilot CLI (e.g. a personal account): fine-grained PAT of a Copilot-licensed user, *Account › Copilot Requests: Read*. `setup.sh --copilot-auth pat` removes `copilot-requests: write` and stores it |
| `WIZ_CONNECTOR_TOKEN` | while this repository is private: fine-grained PAT with *Contents: Read* on it; setup.sh asks for it when it detects a private repo |
| `WIZ_PR_TOKEN` | optional: token used to push the bump branch and open the PR, so CI runs on it |

## Manual install (what setup.sh does)
```bash
gh extension install github/gh-aw                       # v1.0.1+
gh aw add n-drobyshevski/wiz-connector/wiz-maven-vulns@v1
gh aw compile --validate --strict
git add .github/workflows/wiz-maven-vulns.md .github/workflows/wiz-maven-vulns.lock.yml .github/aw/actions-lock.json
git commit -m "Add Wiz direct-dependency tracker" && git push
gh aw run wiz-maven-vulns          # first run: Actions › Run workflow with staged=true (dry run)
```
Then copy [`copilot/`](../copilot) into the target repository:

| File | Purpose |
|---|---|
| `.github/skills/wiz-maven-bumps/SKILL.md` | `/wiz-maven-bumps <issue>` in VS Code, Copilot CLI and the cloud agent |
| `.github/instructions/maven-pom.instructions.md` | POM editing rules (`applyTo: pom.xml,**/pom.xml`) |
| `.github/copilot-instructions.md` | lines to append: build command and pointer to the skill |
| `.github/workflows/copilot-setup-steps.yml` | JDK + Maven cache for cloud-agent sessions |
| `.mcp.json` | optional: query Wiz from VS Code with per-developer OAuth sign-in |

Each run checks out this repository at `ref: v1` for the scripts, using `WIZ_CONNECTOR_TOKEN` if set.
Pin a commit SHA instead of the tag for stricter supply-chain control.

## Advanced (edit the workflow)
| What | Where |
|---|---|
| Model | `engine.model` and `safe-outputs.threat-detection.engine.model` (recompile) |
| Cloud-agent flow | `publish --on-change replace --assignee @copilot` plus a `COPILOT_ASSIGN_TOKEN` secret (user PAT) passed as env to the publish step. `replace` opens a new issue when findings change, because the cloud agent ignores edits made after assignment |
| Keep the issue open when clean | `publish --keep-open` |
| Issues created by a custom token | `publish --trusted-author <login>` (default: the GitHub Actions bot) |

## Model policy
- `engine.model` is pinned (the default `auto` lets the Copilot gateway choose any model family);
- `models.allowed: ["gpt-*"]` is enforced by the agent job's API proxy;
- the threat-detection job is pinned to the same model; to apply `models.allowed` there too, compile
  with `GHAW_POLICY_MODELS_ALLOWED='gpt-*'`.

Also set the org-wide Copilot model policy (it covers Copilot in VS Code too) and check runs with
`gh aw audit <run-url> --models`.
