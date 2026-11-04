"""Render the compact, agent-oriented GitHub issue."""

from __future__ import annotations

import hashlib
import json

from .findings import Result, Upgrade

MARKER = "wiz-connector:maven-direct-vulns"
SCHEMA = "wiz-connector/maven-upgrades@v1"
MAX_BODY = 60_000          # GitHub hard limit is 65,536 characters
TABLE_CVES = 3


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


def edit_hint(decl: dict) -> str:
    k = decl.get("kind")
    if k == "literal":
        sec = " (dependencyManagement)" if decl.get("section") == "dependencyManagement" else ""
        return f"`{decl['file']}` `<version>`{sec}"
    if k == "property":
        return f"`{decl['file']}` `<{decl['property']}>`"
    if k == "external-property":
        return f"override `<{decl['property']}>` in top POM"
    if k == "managed-external":
        return f"add `<dependencyManagement>` override in `{decl.get('file', 'pom.xml')}`"
    if k == "project-version":
        return f"`{decl['file']}` uses `${{project.version}}`"
    return "locate declaration"


def _edits(u: Upgrade) -> list[dict]:
    seen, out = set(), []
    for d in u.declarations:
        key = json.dumps({k: d.get(k) for k in ("kind", "file", "property", "section")}, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


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


def payload(result: Result, repo: str, ref: str | None, generated_at: str, run_url: str | None) -> dict:
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
        }

    return {
        "schema": SCHEMA,
        "repo": repo,
        "ref": ref,
        "generated_at": generated_at,
        "run_url": run_url,
        "fingerprint": fingerprint(result),
        "upgrades": [up(u) for u in result.upgrades],
        "excluded": {
            "transitive": result.skipped_transitive,
            "no_fix": {u.ga: [f.cve for f in u.cves] for u in result.no_fix},
            "already_fixed": result.already_fixed,
            "not_in_maven_tree": result.unmatched,
        },
    }


def title(result: Result, prefix: str) -> str:
    n = len(result.upgrades)
    cves = sum(len(u.cves) for u in result.upgrades)
    return f"{prefix} {n} direct Maven dependenc{'y' if n == 1 else 'ies'} to bump ({cves} CVEs)"


def body(result: Result, repo: str, ref: str | None, generated_at: str, run_url: str | None,
         verify_cmd: str = "mvn -B -ntp verify") -> str:
    data = payload(result, repo, ref, generated_at, run_url)
    ups = list(result.upgrades)
    text = _body(ups, data, verify_cmd)
    # progressively shrink until it fits GitHub's body limit
    shrinkers = [
        lambda: data.__setitem__("excluded", {k: dict(list(v.items())[:30]) for k, v in data["excluded"].items()}),
        lambda: [u.__setitem__("cves", u["cves"][:25] + [f"+{len(u['cves']) - 25} more"])
                 for u in data["upgrades"] if len(u["cves"]) > 25],
        lambda: data.__setitem__("excluded", {"truncated": True}),
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
    return text


def _body(ups: list[Upgrade], data: dict, verify_cmd: str) -> str:
    n_cves = sum(len(u.cves) for u in ups)
    n_crit = sum(1 for u in ups if u.max_severity == "CRITICAL")
    n_kev = sum(1 for u in ups if u.kev)
    run = f" · [run]({data['run_url']})" if data.get("run_url") else ""
    ref = f" @ `{data['ref']}`" if data.get("ref") else ""
    lines = [
        f"<!-- {MARKER} fingerprint={data['fingerprint']} -->",
        f"> Auto-generated by wiz-connector from Wiz findings + `mvn dependency:tree`{ref} · {data['generated_at']}{run}",
        "",
        f"**Goal:** bump {len(ups)} direct Maven dependenc{'y' if len(ups) == 1 else 'ies'} to fix {n_cves} CVEs"
        f" ({n_crit} critical, {n_kev} CISA-KEV). Only direct dependencies are listed: each row is fixed by editing one version declaration.",
        "",
        "| # | Dependency | Bump | Severity | CVEs | Edit |",
        "|--:|---|---|---|---|---|",
    ]
    for i, u in enumerate(ups, 1):
        edits = "<br>".join(edit_hint(d) for d in _edits(u)) or "locate declaration"
        lines.append(
            f"| {i} | `{u.ga}` | `{u.current}` → `{u.target}` ({u.bump}) | {_sev(u)} | {_cve_cell(u)} | {edits} |"
        )
    lines += [
        "",
        "### Instructions for the implementing agent",
        "1. For each row change only the declaration in **Edit** to the **Bump** target"
        " (a newer patch on the same release line is fine). If a property is shared by several artifacts, bump it once.",
        "2. Do not add, remove or exclude dependencies and do not pin transitive dependencies.",
        "3. `major`/`minor` bumps: read the release notes for breaking changes and fix compilation/test failures.",
        f"4. Verify: `{verify_cmd}` passes, then `mvn -B -ntp dependency:tree -Dincludes=<groupId>:<artifactId>`"
        " shows the resolved version ≥ target in every listed module.",
        "5. Open one PR titled `fix(deps): security bumps from Wiz` that lists the CVEs fixed and links this issue.",
        "",
        "### Acceptance criteria",
    ]
    for u in ups:
        modules = ", ".join("`" + m.split(":")[-1] + "`" for m in u.modules)
        lines.append(f"- [ ] `{u.ga}` resolves to ≥ `{u.target}` in {modules}")
    lines.append(f"- [ ] `{verify_cmd}` is green")

    ex = data["excluded"]
    excluded_lines = []
    if ex.get("transitive"):
        n = sum(len(v) for v in ex["transitive"].values())
        excluded_lines.append(f"- **Transitive** (fix by bumping the parent dependency, not listed): {n} CVEs in "
                              + ", ".join(f"`{g}`" for g in ex["transitive"]))
    if ex.get("no_fix"):
        excluded_lines.append("- **Direct, no fixed version yet:** " + ", ".join(f"`{g}` ({len(v)})" for g, v in ex["no_fix"].items()))
    if ex.get("already_fixed"):
        excluded_lines.append("- **Already fixed in current tree** (stale Wiz data): " + ", ".join(f"`{g}`" for g in ex["already_fixed"]))
    if ex.get("not_in_maven_tree"):
        excluded_lines.append(f"- **Not in the Maven tree** (other ecosystem/branch): {len(ex['not_in_maven_tree'])} packages")
    if ex.get("truncated"):
        excluded_lines.append("- (exclusion details truncated to fit the issue size limit)")
    if data.get("truncated_upgrades"):
        excluded_lines.append(f"- **{data['truncated_upgrades']} lower-priority upgrades omitted** to fit the issue size"
                              " limit; they will appear once the rows above are fixed.")
    if excluded_lines:
        lines += ["", "<details><summary>Not included</summary>", "", *excluded_lines, "", "</details>"]

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
