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

from .findings import Result, Upgrade

MARKER = "wiz-connector:maven-direct-vulns"
SCHEMA = "wiz-connector/maven-upgrades@v1"
MAX_BODY = 60_000            # GitHub limit is 65,536; gh-aw's is 65,000
TABLE_CVES = 3
VERSIONS_PLUGIN = "org.codehaus.mojo:versions-maven-plugin:2.23.0"
DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.11.0"
SKILL = "wiz-maven-bumps"

# POM-derived strings end up in shell commands a coding agent will run: allow only plain tokens.
_SAFE_COORD = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*:[A-Za-z0-9_][A-Za-z0-9_.\-]*$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-+]{0,63}$")
_SAFE_PROP = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}$")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./\-]{0,255}$")


def _ok(regex: re.Pattern, value) -> bool:
    return isinstance(value, str) and bool(regex.match(value)) and ".." not in value.split("/")


def _md(value) -> str:
    """Neutralise characters that could break out of a Markdown code span / table cell."""
    return str(value).replace("`", "'").replace("|", "/").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


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
    f, prop = _md(decl.get("file", "pom.xml")), _md(decl.get("property", ""))
    if k == "literal":
        sec = " (dependencyManagement)" if decl.get("section") == "dependencyManagement" else ""
        return f"`{f}` `<version>`{sec}"
    if k == "property":
        return f"`{f}` `<{prop}>`"
    if k == "external-property":
        return f"add `<{prop}>` to `<properties>` of the top POM"
    if k == "managed-external":
        return f"pin in `<dependencyManagement>` of `{f}`"
    if k == "project-version":
        return f"`{f}` uses `${{project.version}}`"
    return "locate declaration"


def _edits(u: Upgrade) -> list[dict]:
    seen, out = set(), []
    for d in u.declarations:
        key = json.dumps({k: d.get(k) for k in ("kind", "file", "property", "section")}, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def fix_commands(ups: list[Upgrade]) -> list[str]:
    """One command per edit location; shared properties are bumped once to the highest target."""
    from . import mvnversion as mv

    props: dict[tuple, tuple[str, list[str]]] = {}
    lines: list[str] = []
    manual: list[str] = []
    literal_done: set[str] = set()
    for i, u in enumerate(ups, 1):
        safe = _ok(_SAFE_COORD, u.ga) and _ok(_SAFE_VERSION, u.target) and _ok(_SAFE_VERSION, u.current)
        for d in _edits(u):
            kind = d.get("kind")
            if not safe or not _ok(_SAFE_PATH, d.get("file", "pom.xml")) or (
                    kind == "property" and not _ok(_SAFE_PROP, d.get("property"))):
                manual.append(f"# {i}. row {i}: edit by hand (unusual characters in its POM declaration)")
                continue
            if kind == "property":
                key = (d["file"], d["property"])
                cur = props.get(key)
                if cur is None or mv.compare(u.target, cur[0]) > 0:
                    props[key] = (u.target, (cur[1] if cur else []) + [u.ga.split(":")[1]])
                else:
                    cur[1].append(u.ga.split(":")[1])
            elif kind == "literal" and u.ga not in literal_done:
                literal_done.add(u.ga)
                lines.append(f"# {i}. {u.ga.split(':')[1]} {u.current} -> {u.target} ({d['file']})")
                lines.append(f"mvn -B -ntp {VERSIONS_PLUGIN}:use-dep-version -Dincludes={u.ga} "
                             f"-DdepVersion={u.target} -DprocessProperties=true -DgenerateBackupPoms=false")
            elif kind in ("external-property", "managed-external", "project-version", "unknown"):
                manual.append(f"# {i}. {u.ga} -> {u.target}: edit by hand, {edit_hint(d)}")
    for (file, prop), (target, arts) in sorted(props.items()):
        lines.append(f"# property {prop} in {file} -> {target} (used by {', '.join(sorted(set(arts)))})")
        lines.append(f"mvn -B -ntp {VERSIONS_PLUGIN}:set-property -Dproperty={prop} "
                     f"-DnewVersion={target} -DgenerateBackupPoms=false")
    return lines + manual


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
        }

    return {
        "schema": SCHEMA,
        "repo": repo,
        "ref": ref,
        "generated_at": generated_at,
        "run_url": run_url,
        "maven": maven,
        "fingerprint": fingerprint(result),
        "upgrades": [up(u) for u in result.upgrades],
        "excluded": {
            "transitive": result.skipped_transitive,
            "no_fix": {u.ga: [f.cve for f in u.cves] for u in result.no_fix},
            "already_fixed": result.already_fixed,
            "not_in_maven_tree": result.unmatched,
            "rejected_records": result.rejected,
        },
    }


def title(result: Result, prefix: str) -> str:
    n = len(result.upgrades)
    cves = sum(len(u.cves) for u in result.upgrades)
    return f"{prefix} {n} direct Maven dependenc{'y' if n == 1 else 'ies'} to bump ({cves} CVEs)"


def body(result: Result, repo: str, ref: str | None, generated_at: str, run_url: str | None,
         verify_cmd: str = "mvn -B -ntp verify", maven: str | None = None) -> str:
    data = payload(result, repo, ref, generated_at, run_url, maven)
    ups = list(result.upgrades)
    text = _body(ups, data, verify_cmd)
    # progressively shrink until it fits the body limit
    shrinkers = [
        lambda: data.__setitem__("excluded", {k: (dict(list(v.items())[:30]) if isinstance(v, dict) else v)
                                              for k, v in data["excluded"].items()}),
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
    mvn = f" ({data['maven']})" if data.get("maven") else ""
    gas = ",".join(u.ga for u in ups if _ok(_SAFE_COORD, u.ga))
    lines = [
        f"<!-- {MARKER} fingerprint={data['fingerprint']} -->",
        f"> Generated by wiz-connector from Wiz findings + `mvn dependency:tree`{mvn}{ref} · {data['generated_at']}{run}",
        "",
        f"**Goal:** bump {len(ups)} direct Maven dependenc{'y' if len(ups) == 1 else 'ies'} to fix {n_cves} CVEs"
        f" ({n_crit} critical, {n_kev} CISA-KEV). Only direct dependencies are listed: each row is fixed by editing one version declaration.",
        "",
        f"**Copilot:** in VS Code agent mode run `/{SKILL} <this issue URL>`, or assign this issue to Copilot.",
        "",
        "| # | Dependency | Bump | Severity | CVEs | Edit |",
        "|--:|---|---|---|---|---|",
    ]
    for i, u in enumerate(ups, 1):
        edits = "<br>".join(edit_hint(d) for d in _edits(u)) or "locate declaration"
        lines.append(
            f"| {i} | `{_md(u.ga)}` | `{_md(u.current)}` → `{_md(u.target)}` ({u.bump}) | {_sev(u)} | {_cve_cell(u)} | {edits} |"
        )
    lines += [
        "",
        "### Fix commands (run from the repository root)",
        "```bash",
        *fix_commands(ups),
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
                              + ", ".join(f"`{g}`" for g in ex["transitive"]))
    if ex.get("no_fix"):
        excluded_lines.append("- **Direct, no fixed version yet:** " + ", ".join(f"`{g}` ({len(v)})" for g, v in ex["no_fix"].items()))
    if ex.get("already_fixed"):
        excluded_lines.append("- **Already fixed in current tree** (stale Wiz data): " + ", ".join(f"`{g}`" for g in ex["already_fixed"]))
    if ex.get("not_in_maven_tree"):
        excluded_lines.append(f"- **Not in the Maven tree** (other ecosystem/branch): {len(ex['not_in_maven_tree'])} packages")
    if ex.get("rejected_records"):
        excluded_lines.append(f"- **Rejected:** {ex['rejected_records']} malformed Wiz records")
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
