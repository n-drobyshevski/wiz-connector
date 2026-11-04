"""Render the compact, agent-oriented GitHub issue.

Optimised for GitHub Copilot (VS Code agent mode, Copilot CLI, Copilot cloud agent):
  * every actionable fact is visible Markdown (table, fix commands, checklist): the cloud agent
    never sees HTML comments and <details> handling is undocumented;
  * exact, copy-pasteable commands so the agent runs a plugin instead of rewriting large POMs;
  * identifiers only (CVE ids, coordinates, versions): no third-party free text enters the prompt;
  * the hidden marker / fingerprint is used only by the de-duplicating publisher.
"""

from __future__ import annotations

import hashlib
import json
import re

from . import commands as cmdmod
from . import mvnversion as mv
from .findings import Result, Upgrade

MARKER = "wiz-connector:maven-direct-vulns"
SCHEMA = "wiz-connector/maven-upgrades@v1"
MAX_BODY = 60_000            # GitHub limit is 65,536; gh-aw's is 65,000
TABLE_CVES = 3
SKILL = "wiz-maven-bumps"
PR_BRANCH = "wiz-connector/maven-bumps"

# shared with the apply step (wizconnector.commands); aliases kept for older imports
VERSIONS_PLUGIN, DEPENDENCY_PLUGIN = cmdmod.VERSIONS_PLUGIN, cmdmod.DEPENDENCY_PLUGIN
_SAFE_COORD, _SAFE_VERSION, _SAFE_PROP, _SAFE_PATH = (cmdmod.SAFE_COORD, cmdmod.SAFE_VERSION,
                                                      cmdmod.SAFE_PROP, cmdmod.SAFE_PATH)
_ok, _md, edit_hint = cmdmod.ok, cmdmod.md, cmdmod.edit_hint


def fingerprint(result: Result) -> str:
    key = [[u.ga, u.current, u.target, sorted(f.cve for f in u.cves)] for u in result.upgrades]
    return hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()[:16]


def compact_json(data: dict) -> str:
    """Valid JSON, one top-level key per line and one upgrade per line: cheap in tokens, easy to diff."""
    def one(v):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))

    lines = []
    for k, v in data.items():
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            inner = ",\n".join("  " + one(x) for x in v)
            lines.append(f' {one(k)}:[\n{inner}\n ]')
        else:
            lines.append(f" {one(k)}:{one(v)}")
    return "{\n" + ",\n".join(lines) + "\n}"


def _edits(u: Upgrade) -> list[dict]:
    seen, out = set(), []
    for d in u.declarations:
        key = json.dumps({k: d.get(k) for k in ("kind", "file", "property", "section")}, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def row_of(u: Upgrade) -> dict:
    return {"ga": u.ga, "current": u.current, "target": u.target, "bump": u.bump,
            "edit": _edits(u), "shared_with": u.shared_with}


def fix_commands(ups: list[Upgrade], applied_rows: set[int] | None = None) -> list[str]:
    """One command per property / literal coordinate; a property is bumped once, to the highest
    target of the rows using it. Anything unusual becomes an "edit by hand" comment."""
    cmds, manual = cmdmod.plan([row_of(u) for u in ups])
    return cmdmod.render_lines(cmds, manual, applied_rows)


def _sev(u: Upgrade) -> str:
    tags = [u.max_severity]
    if u.kev:
        tags.append("KEV")
    elif u.exploit:
        tags.append("exploit")
    return " · ".join(tags)


def _cve_cell(u: Upgrade) -> str:
    ids = [f.cve for f in u.cves]
    shown = ", ".join(ids[:TABLE_CVES])
    return shown + (f" +{len(ids) - TABLE_CVES}" if len(ids) > TABLE_CVES else "")


def payload(result: Result, repo: str, ref: str | None, generated_at: str, run_url: str | None,
            maven: str | None = None) -> dict:
    def up(u: Upgrade) -> dict:
        return {
            "ga": u.ga,
            "current": u.current,
            "target": u.target,
            "bump": u.bump,
            "severity": u.max_severity,
            "cvss": u.max_cvss or None,
            "kev": u.kev,
            "exploit": u.exploit,
            "cves": [f.cve for f in u.cves],
            "unfixed_cves": [f.cve for f in u.unfixed_cves],
            "modules": u.modules,
            "scopes": u.scopes,
            "edit": [{k: v for k, v in d.items() if k in ("kind", "file", "property", "section", "used_in", "boms", "external_parent")}
                     for d in _edits(u)],
            "also_transitive_in": u.also_transitive_in,
            "module_versions": u.module_versions,
            "shared_with": u.shared_with,
        }

    return {
        "schema": SCHEMA,
        "repo": repo,
        "ref": ref,
        "generated_at": generated_at,
        "run_url": run_url,
        "maven": maven,
        "maven_dir": result.maven_dir,
        "fingerprint": fingerprint(result),
        "upgrades": [up(u) for u in result.upgrades],
        "excluded": {
            "transitive": result.skipped_transitive,
            "no_fix": {u.ga: [f.cve for f in u.cves] for u in result.no_fix},
            "already_fixed": result.already_fixed,
            "not_in_maven_tree": result.unmatched,
            "rejected_records": result.rejected,
            "below_min_severity": result.below_threshold,
        },
    }


def title(result: Result, prefix: str) -> str:
    n = len(result.upgrades)
    cves = sum(len(u.cves) for u in result.upgrades)
    return f"{prefix} {n} direct Maven dependenc{'y' if n == 1 else 'ies'} to bump ({cves} CVEs)"


def automation(apply_result: dict | None, result: Result) -> dict | None:
    """Status of the automated PR, embedded in the issue (only when it matches these findings)."""
    if not apply_result or apply_result.get("fingerprint") != fingerprint(result):
        return None
    return {"branch": PR_BRANCH,
            "applied_rows": [int(i) for i in apply_result.get("applied_rows", [])],
            "pending": {str(k): str(v) for k, v in apply_result.get("pending", {}).items()},
            "verify_ok": (apply_result.get("verify") or {}).get("ok")}


def body(result: Result, repo: str, ref: str | None, generated_at: str, run_url: str | None,
         verify_cmd: str = "mvn -B -ntp verify", maven: str | None = None, apply_result: dict | None = None) -> str:
    data = payload(result, repo, ref, generated_at, run_url, maven)
    auto = automation(apply_result, result)
    if auto and auto["applied_rows"]:
        data["automation"] = auto
    ups = list(result.upgrades)
    text = _body(ups, data, verify_cmd)
    # progressively shrink until it fits the body limit
    shrinkers = [
        lambda: data.__setitem__("excluded", {k: (dict(list(v.items())[:30]) if isinstance(v, dict) else v)
                                              for k, v in data["excluded"].items()}),
        lambda: [u.__setitem__(k, u[k][:25] + [f"+{len(u[k]) - 25} more"])
                 for u in data["upgrades"] for k in ("cves", "unfixed_cves", "modules", "also_transitive_in", "shared_with")
                 if len(u[k]) > 25],
        lambda: data.__setitem__("excluded", {"truncated": True}),
        lambda: [u.update(module_versions={}, edit=u["edit"][:5]) for u in data["upgrades"]],
    ]
    for shrink in shrinkers:
        if len(text) <= MAX_BODY:
            return text
        shrink()
        text = _body(ups, data, verify_cmd)
    while len(text) > MAX_BODY and len(ups) > 1:
        keep = max(1, len(ups) * 3 // 4)
        ups, data["upgrades"] = ups[:keep], data["upgrades"][:keep]
        data["truncated_upgrades"] = len(result.upgrades) - keep
        text = _body(ups, data, verify_cmd)
    if len(text) > MAX_BODY:          # a single pathological row: drop the JSON block, then hard-cap
        data["omit_json"] = True
        text = _body(ups, data, verify_cmd)
    return text if len(text) <= MAX_BODY else text[:MAX_BODY - 200] + "\n\n(truncated to fit the issue size limit)\n"


def _body(ups: list[Upgrade], data: dict, verify_cmd: str) -> str:
    n_cves = sum(len(u.cves) for u in ups)
    n_crit = sum(1 for u in ups if u.max_severity == "CRITICAL")
    n_kev = sum(1 for u in ups if u.kev)
    run = f" · [run]({data['run_url']})" if data.get("run_url") else ""
    ref = f" @ `{_md(data['ref'])}`" if data.get("ref") else ""
    mvn = f" ({_md(data['maven'])})" if data.get("maven") else ""
    mdir = data.get("maven_dir") or "."
    mdir_ok = _ok(_SAFE_PATH, mdir) or mdir == "."
    gas = ",".join(u.ga for u in ups if _ok(_SAFE_COORD, u.ga))
    lines = [
        f"<!-- {MARKER} fingerprint={data['fingerprint']} -->",
        f"> Generated by wiz-connector from Wiz findings + `mvn dependency:tree`{mvn}{ref} · {data['generated_at']}{run}",
        "",
        f"**Goal:** bump {len(ups)} direct Maven dependenc{'y' if len(ups) == 1 else 'ies'} to fix {n_cves} CVEs"
        f" ({n_crit} critical, {n_kev} CISA-KEV). Only direct dependencies are listed: each row is fixed by editing one version declaration.",
        "",
    ]
    auto = data.get("automation")
    applied = set(auto["applied_rows"]) if auto else set()
    if auto:
        left = [i for i in range(1, len(ups) + 1) if i not in applied]
        build = {True: "build passes", False: "**build fails** (PR is a draft)", None: "build not run"}[auto["verify_ok"]]
        lines += [
            f"**Automated PR** (branch `{auto['branch']}`): rows {', '.join(map(str, sorted(applied)))} applied, {build}.",
            f"**Copilot:** " + (f"do rows {', '.join(map(str, left))} on top of branch `{auto['branch']}`"
                                if left else f"only fix the build on branch `{auto['branch']}`" if auto["verify_ok"] is False
                                else "nothing left; review and merge the automated PR")
            + f" (VS Code agent mode: `/{SKILL} <this issue URL>`).",
            "",
            "| # | Dependency | Bump | Severity | CVEs | Edit | Status |",
            "|--:|---|---|---|---|---|---|",
        ]
    else:
        lines += [
            f"**Copilot:** in VS Code agent mode run `/{SKILL} <this issue URL>`, or assign this issue to Copilot.",
            "",
            "| # | Dependency | Bump | Severity | CVEs | Edit |",
            "|--:|---|---|---|---|---|",
        ]
    for i, u in enumerate(ups, 1):
        edits = "<br>".join(edit_hint(d) for d in _edits(u)) or "locate declaration"
        if u.shared_with:
            edits += " (shared property)"
        others = sorted(set(u.module_versions.values()) - {u.current}, key=mv.sort_key)
        cur = f"`{_md(u.current)}`" + (f" (also {', '.join('`' + _md(v) + '`' for v in others)})" if others else "")
        status = (" PR |" if i in applied else " Copilot |") if auto else ""
        lines.append(
            f"| {i} | `{_md(u.ga)}` | {cur} → `{_md(u.target)}` ({u.bump}) | {_sev(u)} | {_cve_cell(u)} | {edits} |{status}"
        )
    lines += [
        "",
        "### Fix commands (bash, from the repository root)",
        "```bash",
        *([f"cd {mdir}"] if mdir != "." and mdir_ok else []),
        *fix_commands(ups, applied if auto else None),
        "git diff --stat   # versions-maven-plugin only WARNs when a version is managed elsewhere: every Edit file must change",
        verify_cmd,
        f"mvn -B -ntp {DEPENDENCY_PLUGIN}:tree -Dincludes={gas}",
        "```",
        "",
        "### Rules",
        "- Change only the declarations in **Edit** (a newer patch on the same release line is fine).",
        "- Do not add, remove or exclude dependencies and do not pin transitive dependencies.",
        "- `major`/`minor` bumps: check release notes; fix only compile/test breakage caused by the bump.",
        "- One PR titled `fix(deps): security bumps from Wiz`, listing the CVEs fixed and `Fixes` this issue.",
        "",
        "Re-run now: comment `/wiz-scan` on this issue, or *Actions › wiz-maven-vulns › Run workflow*.",
        "",
        "### Acceptance criteria",
    ]
    for u in ups:
        modules = ", ".join("`" + _md(m.split(":")[-1]) + "`" for m in u.modules)
        lines.append(f"- [ ] `{_md(u.ga)}` resolves to ≥ `{_md(u.target)}` in {modules}")
    lines.append(f"- [ ] `{verify_cmd}` is green")

    ex = data["excluded"]
    excluded_lines = []
    if ex.get("transitive"):
        n = sum(len(v) for v in ex["transitive"].values())
        excluded_lines.append(f"- **Transitive** (fixed by bumping the parent dependency, not listed): {n} CVEs in "
                              + ", ".join(f"`{_md(g)}`" for g in ex["transitive"]))
    if ex.get("no_fix"):
        excluded_lines.append("- **Direct, no fixed version yet:** " + ", ".join(f"`{_md(g)}` ({len(v)})" for g, v in ex["no_fix"].items()))
    if ex.get("already_fixed"):
        excluded_lines.append("- **Already fixed in current tree** (stale Wiz data): " + ", ".join(f"`{_md(g)}`" for g in ex["already_fixed"]))
    if ex.get("not_in_maven_tree"):
        excluded_lines.append(f"- **Not in the Maven tree** (other ecosystem/branch): {len(ex['not_in_maven_tree'])} packages")
    if ex.get("below_min_severity"):
        n = sum(len(v) for v in ex["below_min_severity"].values())
        excluded_lines.append(f"- **Below the minimum severity** (`WIZ_MIN_SEVERITY`): {n} CVEs in "
                              + ", ".join(f"`{_md(g)}`" for g in ex["below_min_severity"]))
    if ex.get("rejected_records"):
        excluded_lines.append(f"- **Rejected:** {ex['rejected_records']} malformed Wiz records")
    if ex.get("truncated"):
        excluded_lines.append("- (exclusion details truncated to fit the issue size limit)")
    if data.get("truncated_upgrades"):
        excluded_lines.append(f"- **{data['truncated_upgrades']} lower-priority upgrades omitted** to fit the issue size"
                              " limit; they will appear once the rows above are fixed.")
    if excluded_lines:
        lines += ["", "<details><summary>Not included</summary>", "", *excluded_lines, "", "</details>"]

    if data.get("omit_json"):
        return "\n".join(lines + ["", "(machine-readable block omitted: too large)", ""])
    lines += [
        "",
        f"<details><summary>Machine-readable ({SCHEMA})</summary>",
        "",
        "```json",
        compact_json(data),
        "```",
        "</details>",
        "",
    ]
    return "\n".join(lines)
