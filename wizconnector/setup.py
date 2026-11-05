"""One-command setup and health check for a target repository.

Run inside the target repository (a clone of this repo provides the files):
  bash /path/to/wiz-connector/scripts/setup.sh                       # interactive
  bash /path/to/wiz-connector/scripts/setup.sh --schedule "daily around 9am on weekdays" --yes
  bash /path/to/wiz-connector/scripts/setup.sh --cron "30 7 * * 1-5" --timezone Europe/Paris
  bash /path/to/wiz-connector/scripts/setup.sh --doctor

Setup: installs the workflow (gh aw add, or --local copy), sets the run time, optionally adds a
trigger on pom.xml changes, compiles, copies the Copilot files, sets repository variables
(settings that change without recompiling), asks for missing secrets, allows GitHub Actions to
open PRs, creates the label, and optionally commits. Doctor: checks all of it plus the last runs.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent           # wiz-connector checkout
WORKFLOW = "wiz-maven-vulns"
WF_MD = Path(".github/workflows") / f"{WORKFLOW}.md"
WF_LOCK = Path(".github/workflows") / f"{WORKFLOW}.lock.yml"
SECRETS = ("WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET", "WIZ_DATACENTER")
_CRON = re.compile(r"^(\S+\s+){4}\S+$")
_TZ = re.compile(r"^[A-Za-z]+(?:/[A-Za-z0-9_+\-]+){1,2}$|^UTC$")
_FUZZY = re.compile(r"^[a-z0-9:\- ]{3,80}$")
_BRANCH = re.compile(r"^[A-Za-z0-9._/\-]{1,100}$")

OK, BAD, WARN = "✅", "❌", "⚠️ "


# --------------------------------------------------------------------------- helpers
def sh(*args: str, check: bool = False, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, input=input_text, check=check)


def gh(*args: str, **kw) -> subprocess.CompletedProcess:
    return sh("gh", *args, **kw)


def say(msg: str) -> None:
    print(msg, flush=True)


def ask(prompt: str, default: str, assume_yes: bool) -> str:
    if assume_yes or not sys.stdin.isatty():
        return default
    val = input(f"{prompt} [{default}]: ").strip()
    return val or default


# --------------------------------------------------------------------------- frontmatter edits
def _split(text: str) -> tuple[str, str]:
    if not text.startswith("---\n"):
        raise ValueError("workflow has no frontmatter")
    end = text.index("\n---\n", 4)
    return text[: end + 1], text[end + 1:]


def _block(lines: list[str], key: str) -> tuple[int, int] | None:
    """[start, end) of a two-space-indented key under `on:` including its nested lines."""
    for i, ln in enumerate(lines):
        if ln.startswith(f"  {key}:"):
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > 2):
                j += 1
            while j > i + 1 and not lines[j - 1].strip():
                j -= 1
            return i, j
    return None


def set_schedule(text: str, schedule: str | None = None, cron: str | None = None, timezone: str | None = None) -> str:
    fm, body = _split(text)
    lines = fm.split("\n")
    span = _block(lines, "schedule")
    if span is None:
        raise ValueError("no `schedule:` under `on:` in the workflow")
    if cron:
        if not _CRON.match(cron):
            raise ValueError(f"cron needs 5 fields: {cron!r}")
        new = ["  schedule:", f'    - cron: "{cron}"']
        if timezone:
            if not _TZ.match(timezone):
                raise ValueError(f"timezone must be an IANA name like Europe/Paris: {timezone!r}")
            new.append(f'      timezone: "{timezone}"')
    else:
        if not schedule or not _FUZZY.match(schedule):
            raise ValueError(f"unsupported schedule {schedule!r} (e.g. 'every 6h', 'daily around 9am on weekdays')")
        new = [f"  schedule: {schedule}"]
    lines[span[0]:span[1]] = new
    return "\n".join(lines) + body


def set_pom_trigger(text: str, branch: str | None) -> str:
    """Add (branch) or remove (None) a push trigger on pom.xml changes."""
    fm, body = _split(text)
    lines = fm.split("\n")
    span = _block(lines, "push")
    if span:
        start = span[0] - 1 if span[0] > 0 and lines[span[0] - 1].strip().startswith("# Refresh right after") else span[0]
        del lines[start:span[1]]
    if branch:
        if not _BRANCH.match(branch):
            raise ValueError(f"bad branch name {branch!r}")
        sched = _block(lines, "schedule")
        at = sched[1] if sched else lines.index("on:") + 1
        lines[at:at] = ["  # Refresh right after dependency changes land (each run is one Copilot agent run).",
                        "  push:", f"    branches: [{branch}]", '    paths: ["**/pom.xml"]']
    return "\n".join(lines) + body


def set_copilot_pat(text: str) -> str:
    """Drop `copilot-requests: write` (org-billed inference) so the COPILOT_GITHUB_TOKEN secret is used."""
    fm, body = _split(text)
    out = [ln for ln in fm.split("\n") if ln.strip() != "copilot-requests: write"
           and not ln.strip().startswith(("# Copilot inference billed", "# Personal account / no org billing",
                                          "# and stores the COPILOT_GITHUB_TOKEN"))]
    return "\n".join(out) + body


def connector_is_private() -> bool | None:
    r = gh("api", "repos/n-drobyshevski/wiz-connector", "-q", ".private")
    return None if r.returncode else r.stdout.strip() == "true"


def read_schedule(text: str) -> str:
    fm, _ = _split(text)
    lines = fm.split("\n")
    span = _block(lines, "schedule")
    if not span:
        return "(none)"
    block = [ln.strip() for ln in lines[span[0]:span[1]] if ln.strip() and not ln.strip().startswith("#")]
    return " ".join(block).replace("schedule:", "").strip()


# --------------------------------------------------------------------------- Wiz credential check
def check_wiz(client_id: str, secret: str, datacenter: str, url: str = "https://mcp.app.wiz.io/") -> tuple[bool, str]:
    req = urllib.request.Request(url, method="POST", data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "wiz-connector-setup", "version": "1"}},
    }).encode(), headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                          "Wiz-Client-Id": client_id, "Wiz-Client-Secret": secret, "Wiz-DataCenter": datacenter})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code} {exc.read(200).decode(errors='replace')}"
    except (urllib.error.URLError, OSError) as exc:
        return False, str(exc)


# --------------------------------------------------------------------------- setup
def _repo_slug(arg: str | None) -> str:
    if arg:
        return arg
    r = gh("repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner")
    if r.returncode or not r.stdout.strip():
        sys.exit("error: cannot detect the repository; run inside a clone with a GitHub remote or pass --repo")
    return r.stdout.strip()


def _copy_copilot_files(dest: Path) -> list[str]:
    done = []
    for rel in ("skills/wiz-maven-bumps/SKILL.md", "instructions/maven-pom.instructions.md",
                "workflows/copilot-setup-steps.yml"):
        src, dst = SRC / "copilot/.github" / rel, dest / ".github" / rel
        if not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            done.append(str(dst.relative_to(dest)))
    ci = dest / ".github/copilot-instructions.md"
    snippet = (SRC / "copilot/.github/copilot-instructions.md").read_text(encoding="utf-8")
    snippet = "\n".join(ln for ln in snippet.splitlines() if not ln.startswith("<!--")).strip() + "\n"
    if not ci.exists() or "wiz-maven-bumps" not in ci.read_text(encoding="utf-8"):
        with open(ci, "a", encoding="utf-8") as fh:
            fh.write(("\n" if ci.exists() and ci.stat().st_size else "") + snippet)
        done.append(str(ci.relative_to(dest)))
    if not (dest / ".mcp.json").exists():
        shutil.copyfile(SRC / "copilot/.mcp.json", dest / ".mcp.json")
        done.append(".mcp.json")
    return done


def cmd_setup(a) -> int:
    root = Path.cwd()
    if not (root / ".git").exists():
        sys.exit("error: run this inside the target repository (no .git here)")
    if gh("auth", "status").returncode:
        sys.exit("error: `gh` is not logged in: run `gh auth login`")
    if gh("aw", "version").returncode:
        sys.exit("error: gh-aw is missing: run `gh extension install github/gh-aw`")
    repo = _repo_slug(a.repo)
    say(f"Setting up wiz-connector in {repo}")

    maven_dir = ask("Maven project directory (where the root pom.xml is)", a.maven_dir, a.yes)
    if not (root / maven_dir / "pom.xml").is_file():
        sys.exit(f"error: no pom.xml in {maven_dir!r}")

    # 1. workflow file
    md = root / WF_MD
    if not md.exists():
        if a.local:
            md.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SRC / "workflows" / f"{WORKFLOW}.md", md)
            say(f"{OK} copied {WF_MD} from {SRC}")
        else:
            r = gh("aw", "add", f"n-drobyshevski/wiz-connector/{WORKFLOW}@{a.ref}")
            if r.returncode or not md.exists():
                sys.exit(f"error: gh aw add failed: {r.stderr.strip()[:300]} (retry with --local)")
            say(f"{OK} installed {WF_MD} via gh aw add (@{a.ref})")
    text = md.read_text(encoding="utf-8")

    # 2. run time + optional pom trigger
    if a.cron:
        text = set_schedule(text, cron=a.cron, timezone=a.timezone)
    else:
        sched = a.schedule or ask("Run time (gh-aw schedule, e.g. 'every 6h', 'daily around 9am on weekdays')",
                                  read_schedule(text), a.yes)
        text = set_schedule(text, schedule=sched)
    if a.on_pom_change is not None:
        text = set_pom_trigger(text, a.on_pom_change or None)
    if a.copilot_auth == "pat":
        text = set_copilot_pat(text)
    md.write_text(text, encoding="utf-8")
    say(f"{OK} schedule: {read_schedule(text)}" + (f"; also on pom.xml pushes to {a.on_pom_change}" if a.on_pom_change else ""))
    if a.copilot_auth == "pat":
        say(f"{OK} Copilot auth: COPILOT_GITHUB_TOKEN secret (org-billed `copilot-requests` removed)")

    # 3. compile
    if not a.no_compile:
        r = gh("aw", "compile", WORKFLOW, "--strict")
        if r.returncode:
            sys.exit(f"error: gh aw compile failed:\n{(r.stdout + r.stderr)[-2000:]}")
        say(f"{OK} compiled {WF_LOCK}")

    # 4. Copilot files
    if not a.no_copilot_files:
        for f in _copy_copilot_files(root):
            say(f"{OK} added {f}")

    # 5. repository variables (no recompile needed to change these later)
    values = {"WIZ_MAVEN_DIR": maven_dir, "WIZ_AUTO_PR": a.auto_pr, "WIZ_AUTO_PR_MAX_BUMP": a.max_bump,
              "WIZ_MIN_SEVERITY": a.min_severity, "WIZ_ISSUE_LABEL": a.label}
    for k, v in values.items():
        r = gh("variable", "set", k, "--repo", repo, "--body", v)
        say(f"{OK if not r.returncode else BAD} variable {k}={v}" + (f" ({r.stderr.strip()[:120]})" if r.returncode else ""))

    # 6. secrets (asked only if missing)
    existing = gh("secret", "list", "--repo", repo, "--json", "name")
    have = {s["name"] for s in json.loads(existing.stdout or "[]")} if not existing.returncode else set()
    creds = {}
    for name in SECRETS:
        if name in have and not a.rotate_secrets:
            say(f"{OK} secret {name} already set")
            continue
        val = os.environ.get(name) or (a.datacenter if name == "WIZ_DATACENTER" else None)
        if not val and not a.yes and sys.stdin.isatty():
            val = (input if name == "WIZ_DATACENTER" else getpass.getpass)(f"{name}: ").strip()
        if not val:
            say(f"{WARN}secret {name} missing: set it later with `gh secret set {name} --repo {repo}`")
            continue
        creds[name] = val
    if len(creds) == 3 and not a.skip_wiz_check:
        good, detail = check_wiz(creds["WIZ_CLIENT_ID"], creds["WIZ_CLIENT_SECRET"], creds["WIZ_DATACENTER"])
        say(f"{OK if good else BAD} Wiz MCP accepts these credentials: {detail}")
        if not good:
            sys.exit("error: Wiz rejected the credentials; secrets not saved")
    # optional tokens: Copilot PAT (no org billing), wiz-connector checkout (private repo), PR token (CI on PR)
    optional = []
    if a.copilot_auth == "pat":
        optional.append(("COPILOT_GITHUB_TOKEN", "fine-grained PAT of a Copilot user, Account > Copilot Requests: Read", True))
    if connector_is_private():
        optional.append(("WIZ_CONNECTOR_TOKEN", "fine-grained PAT, Contents: read on n-drobyshevski/wiz-connector", True))
    if a.auto_pr == "true":
        optional.append(("WIZ_PR_TOKEN", "optional: PAT so CI runs on the bump PR (Enter to skip)", False))
    for name, why, required in optional:
        if name in have and not a.rotate_secrets:
            say(f"{OK} secret {name} already set")
            continue
        val = os.environ.get(name)
        if not val and not a.yes and sys.stdin.isatty():
            val = getpass.getpass(f"{name} ({why}): ").strip()
        if val:
            creds[name] = val
        elif required:
            say(f"{WARN}secret {name} missing ({why}): `gh secret set {name} --repo {repo}`")
    for name, val in creds.items():
        r = gh("secret", "set", name, "--repo", repo, input_text=val)
        say(f"{OK if not r.returncode else BAD} secret {name} saved")

    # 7. allow GitHub Actions to open PRs (only this flag; the default token permission is kept)
    if a.auto_pr == "true":
        cur = gh("api", f"repos/{repo}/actions/permissions/workflow")
        perm = json.loads(cur.stdout or "{}").get("default_workflow_permissions", "read") if not cur.returncode else "read"
        r = gh("api", "-X", "PUT", f"repos/{repo}/actions/permissions/workflow",
               "-f", f"default_workflow_permissions={perm}", "-F", "can_approve_pull_request_reviews=true")
        say(f"{OK if not r.returncode else WARN} Actions may create pull requests"
            + ("" if not r.returncode else " (needs admin; enable it in Settings > Actions > General)"))

    # 8. label
    gh("label", "create", a.label, "--repo", repo, "--color", "B60205", "--description", "Managed by wiz-connector")

    # 9. commit
    if a.commit:
        files = [str(WF_MD), str(WF_LOCK), ".github/aw", ".gitattributes", ".github/skills", ".github/instructions",
                 ".github/workflows/copilot-setup-steps.yml", ".github/copilot-instructions.md", ".mcp.json"]
        sh("git", "add", "--", *[f for f in files if (root / f).exists()])
        r = sh("git", "commit", "-m", "Add wiz-connector (Wiz -> direct Maven dependency bumps)")
        say(f"{OK if not r.returncode else WARN} committed" + ("" if not r.returncode else ": nothing to commit"))
    say("\nNext:")
    say("  1. " + ("git push" if a.commit else "commit the files above (or re-run with --commit), then git push"))
    say(f"  2. first run as a dry run: Actions > {WORKFLOW} > Run workflow > staged, or `gh aw run {WORKFLOW}`")
    say("  3. later: comment /wiz-scan on the tracking issue to re-run it now")
    say(f"  4. check everything: bash {SRC}/scripts/setup.sh --doctor")
    return 0


# --------------------------------------------------------------------------- doctor
def cmd_doctor(a) -> int:
    root = Path.cwd()
    problems = 0

    def check(ok: bool, good: str, bad: str, warn_only: bool = False) -> None:
        nonlocal problems
        if ok:
            say(f"{OK} {good}")
        else:
            say(f"{WARN if warn_only else BAD} {bad}")
            problems += 0 if warn_only else 1

    md = root / WF_MD
    check(md.exists(), f"{WF_MD} present", f"{WF_MD} missing: run setup")
    text = md.read_text(encoding="utf-8") if md.exists() else ""
    check((root / WF_LOCK).exists(), f"{WF_LOCK} present", f"{WF_LOCK} missing: run `gh aw compile {WORKFLOW}`")
    if text:
        say(f"   schedule: {read_schedule(text)}")
        check("slash_command" in text, "manual re-run: comment /wiz-scan on the tracking issue",
              "no /wiz-scan trigger (older workflow version: `gh aw update`)", warn_only=True)
    repo = _repo_slug(a.repo)
    vars_ = gh("variable", "list", "--repo", repo, "--json", "name,value")
    vmap = {v["name"]: v["value"] for v in json.loads(vars_.stdout or "[]")} if not vars_.returncode else {}
    for k, d in (("WIZ_MAVEN_DIR", "."), ("WIZ_AUTO_PR", "true"), ("WIZ_AUTO_PR_MAX_BUMP", "major"),
                 ("WIZ_MIN_SEVERITY", "LOW"), ("WIZ_ISSUE_LABEL", "wiz-sca")):
        say(f"   {k} = {vmap.get(k, d)}" + ("" if k in vmap else " (default)"))
    mdir = vmap.get("WIZ_MAVEN_DIR", ".")
    check((root / mdir / "pom.xml").is_file(), f"pom.xml found in {mdir}", f"no pom.xml in {mdir} (WIZ_MAVEN_DIR)")
    sec = gh("secret", "list", "--repo", repo, "--json", "name")
    names = {s["name"] for s in json.loads(sec.stdout or "[]")} if not sec.returncode else set()
    for name in SECRETS:
        check(name in names, f"secret {name} set", f"secret {name} missing: `gh secret set {name} --repo {repo}`")
    if connector_is_private():
        check("WIZ_CONNECTOR_TOKEN" in names, "secret WIZ_CONNECTOR_TOKEN set (wiz-connector is private)",
              "wiz-connector is private but WIZ_CONNECTOR_TOKEN is missing: the checkout of the scripts will fail")
    check("copilot-requests: write" in text or "COPILOT_GITHUB_TOKEN" in names,
          "Copilot engine auth (org billing or COPILOT_GITHUB_TOKEN)",
          "no Copilot auth: keep `copilot-requests: write` with org billing, or set COPILOT_GITHUB_TOKEN")
    if vmap.get("WIZ_AUTO_PR", "true") == "true":
        perm = gh("api", f"repos/{repo}/actions/permissions/workflow")
        can = json.loads(perm.stdout or "{}").get("can_approve_pull_request_reviews") if not perm.returncode else None
        check(can is True, "GitHub Actions may create pull requests",
              "GitHub Actions may not create PRs: Settings > Actions > General (or run setup)",
              warn_only=can is None)
        check("WIZ_PR_TOKEN" in names, "WIZ_PR_TOKEN set: CI runs on the bump PR",
              "no WIZ_PR_TOKEN: CI will not run on the bump PR (optional)", warn_only=True)
    check((root / ".github/skills/wiz-maven-bumps/SKILL.md").exists(), "Copilot skill /wiz-maven-bumps present",
          "Copilot skill missing (run setup)", warn_only=True)
    if all(os.environ.get(n) for n in SECRETS):
        good, detail = check_wiz(*(os.environ[n] for n in SECRETS))
        check(good, f"Wiz MCP accepts the credentials in your environment ({detail})", f"Wiz MCP rejected them: {detail}")
    runs = gh("run", "list", "--repo", repo, "--workflow", WF_LOCK.name, "--limit", "3",
              "--json", "conclusion,status,event,createdAt,url")
    if not runs.returncode:
        items = json.loads(runs.stdout or "[]")
        if not items:
            say(f"{WARN}no runs yet: `gh aw run {WORKFLOW}`")
        for r in items:
            mark = OK if r.get("conclusion") == "success" else (WARN if r.get("status") != "completed" else BAD)
            say(f"{mark} run {r.get('createdAt', '')[:16]} {r.get('event')}: {r.get('conclusion') or r.get('status')} {r.get('url')}")
    say("\nAll good." if not problems else f"\n{problems} problem(s) found.")
    return 1 if problems else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="setup.sh", description="Set up or check wiz-connector in this repository")
    ap.add_argument("--doctor", action="store_true", help="only check the setup")
    ap.add_argument("--repo", help="owner/name (default: the current clone's GitHub repo)")
    ap.add_argument("--ref", default="v1", help="wiz-connector version to install (gh aw add)")
    ap.add_argument("--local", action="store_true", help="copy the workflow from this checkout instead of gh aw add")
    when = ap.add_mutually_exclusive_group()
    when.add_argument("--schedule", help="gh-aw schedule: 'every 6h', 'daily around 9am on weekdays', 'weekly on monday'")
    when.add_argument("--cron", help="fixed cron (5 fields), e.g. '30 7 * * 1-5'")
    ap.add_argument("--timezone", help="IANA timezone for --cron, e.g. Europe/Paris")
    ap.add_argument("--on-pom-change", nargs="?", const="main", default=None, metavar="BRANCH",
                    help="also run when pom.xml changes on BRANCH (default main); pass '' to remove")
    ap.add_argument("--maven-dir", default=".")
    ap.add_argument("--auto-pr", choices=["true", "false"], default="true")
    ap.add_argument("--max-bump", choices=["patch", "minor", "major"], default="major")
    ap.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW")
    ap.add_argument("--label", default="wiz-sca")
    ap.add_argument("--datacenter", help="Wiz data center, e.g. us17 (WIZ_DATACENTER)")
    ap.add_argument("--copilot-auth", choices=["org", "pat"], default="org",
                    help="org: Copilot billed to the organization (copilot-requests: write); "
                         "pat: personal account, uses the COPILOT_GITHUB_TOKEN secret")
    ap.add_argument("--rotate-secrets", action="store_true", help="ask for the secrets even if set")
    ap.add_argument("--skip-wiz-check", action="store_true", help="do not test the credentials against Wiz")
    ap.add_argument("--no-compile", action="store_true")
    ap.add_argument("--no-copilot-files", action="store_true")
    ap.add_argument("--commit", action="store_true", help="git commit the added files")
    ap.add_argument("--yes", action="store_true", help="non-interactive: use defaults and flags only")
    a = ap.parse_args(argv)
    if a.timezone and not a.cron:
        ap.error("--timezone needs --cron (gh-aw fuzzy schedules are UTC)")
    try:
        return cmd_doctor(a) if a.doctor else cmd_setup(a)
    except ValueError as exc:
        sys.exit(f"error: {exc}")


if __name__ == "__main__":
    sys.exit(main())
