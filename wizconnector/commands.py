"""Fix-command planning shared by the issue renderer and the auto-apply step.

The SAME plan is rendered as text for Copilot (issue "Fix commands") and executed by
`wizconnector apply` as argv lists without a shell, so the two can never drift apart.
Every token placed in a command must match a strict pattern; anything else becomes an
"edit by hand" item.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import mvnversion as mv

VERSIONS_PLUGIN = "org.codehaus.mojo:versions-maven-plugin:2.23.0"
DEPENDENCY_PLUGIN = "org.apache.maven.plugins:maven-dependency-plugin:3.11.0"

# POM-derived strings end up in commands a coding agent (or the apply step) runs: plain tokens only.
SAFE_COORD = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*:[A-Za-z0-9_][A-Za-z0-9_.\-]*$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-+]{0,63}$")
SAFE_PROP = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,127}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./\-]{0,255}$")


def ok(regex: re.Pattern, value) -> bool:
    return isinstance(value, str) and bool(regex.match(value)) and ".." not in value.split("/")


def md(value) -> str:
    """Neutralise characters that could break out of a Markdown code span / table cell."""
    return (str(value).replace("`", "'").replace("|", "/").replace("\n", " ").replace("\r", " ")
            .replace("<", "&lt;").replace(">", "&gt;"))


def edit_hint(decl: dict) -> str:
    k = decl.get("kind")
    f, prop = md(decl.get("file", "pom.xml")), md(decl.get("property", ""))
    if k == "literal":
        sec = " (dependencyManagement)" if decl.get("section") == "dependencyManagement" else ""
        return f"`{f}` `<version>`{sec}"
    if k == "property":
        return f"`{f}` `<{prop}>`"
    if k == "external-property":
        return f"add `<{prop}>` to `<properties>` of `{f}`"
    if k == "managed-external":
        return f"pin in `<dependencyManagement>` of `{f}`"
    if k == "project-version":
        return f"`{f}` uses `${{project.version}}`"
    return "locate declaration"


@dataclass
class Command:
    kind: str                      # use-dep-version | set-property
    rows: list[int]                # 1-based issue rows this command fixes
    gas: list[str]
    target: str
    args: list[str]                # Maven goal + -D arguments (no shell syntax)
    comment: str
    property: str | None = None
    files: list[str] = field(default_factory=list)
    shared_with: list[str] = field(default_factory=list)   # other artifacts versioned by the same property

    def argv(self, mvn: str = "mvn") -> list[str]:
        return [mvn, "-B", "-ntp", *self.args]

    def text(self) -> str:
        return " ".join(self.argv())


@dataclass
class Manual:
    row: int
    ga: str
    target: str
    reason: str                    # "edit by hand: ..." / "unusual characters"


def plan(rows: list[dict]) -> tuple[list[Command], list[Manual]]:
    """rows: dicts with ga, current, target, edit (declarations) and shared_with, in issue order."""
    props: dict[str, Command] = {}
    literals: list[Command] = []
    manual: list[Manual] = []
    seen_literal: set[str] = set()
    for i, r in enumerate(rows, 1):
        ga, cur, target = r.get("ga"), r.get("current"), r.get("target")
        safe = ok(SAFE_COORD, ga) and ok(SAFE_VERSION, target) and ok(SAFE_VERSION, cur)
        for d in r.get("edit", []):
            kind = d.get("kind")
            if not safe or not ok(SAFE_PATH, d.get("file", "pom.xml")) or (
                    kind in ("property", "external-property") and not ok(SAFE_PROP, d.get("property"))):
                manual.append(Manual(i, str(ga), str(target), "unusual characters in its POM declaration"))
                continue
            if kind == "property":
                c = props.get(d["property"])
                if c is None:
                    c = props[d["property"]] = Command("set-property", [], [], target, [], "", property=d["property"])
                if mv.compare(target, c.target) > 0:
                    c.target = target
                if i not in c.rows:
                    c.rows.append(i)
                if ga not in c.gas:
                    c.gas.append(ga)
                if d["file"] not in c.files:
                    c.files.append(d["file"])
                c.shared_with = sorted(set(c.shared_with) | set(r.get("shared_with", [])))
            elif kind == "literal" and ga not in seen_literal:
                seen_literal.add(ga)
                literals.append(Command(
                    "use-dep-version", [i], [ga], target,
                    [f"{VERSIONS_PLUGIN}:use-dep-version", f"-Dincludes={ga}", f"-DdepVersion={target}",
                     "-DprocessProperties=true", "-DgenerateBackupPoms=false"],
                    f"{i}. {ga.split(':')[1]} {cur} -> {target} ({d['file']})", files=[d["file"]]))
            elif kind in ("external-property", "managed-external", "project-version", "unknown"):
                manual.append(Manual(i, ga, target, "edit by hand, " + edit_hint(d).replace("`", "")))
    for prop, c in sorted(props.items()):
        c.shared_with = [g for g in c.shared_with if g not in c.gas]
        c.args = [f"{VERSIONS_PLUGIN}:set-property", f"-Dproperty={prop}", f"-DnewVersion={c.target}",
                  "-DgenerateBackupPoms=false"]
        c.comment = (f"property {prop} ({', '.join(sorted(c.files))}) -> {c.target}"
                     f" for {', '.join(g.split(':')[1] for g in sorted(c.gas))}")
    return literals + [props[p] for p in sorted(props)], manual


def render_lines(cmds: list[Command], manual: list[Manual], applied_rows: set[int] | None = None) -> list[str]:
    lines = []
    for c in cmds:
        done = applied_rows is not None and set(c.rows) <= applied_rows
        lines.append(f"# {c.comment}" + ("   [already applied in the automated PR]" if done else ""))
        if c.shared_with:
            lines.append(f"#   SHARED with {', '.join(g.split(':')[1] for g in c.shared_with)}: {c.target} must exist"
                         " for them too (micro-patches such as jackson-databind 2.12.7.1 do not); otherwise use the"
                         " next common release, or pin the vulnerable artifact with use-dep-version instead")
        lines.append(c.text())
    for m in manual:
        if m.reason.startswith("unusual"):
            lines.append(f"# {m.row}. row {m.row}: edit by hand ({m.reason})")
        else:
            lines.append(f"# {m.row}. {m.ga.split(':')[1]} -> {m.target}: {m.reason}")
    return lines
