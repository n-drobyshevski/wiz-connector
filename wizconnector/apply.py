"""Deterministically apply the safe fix commands and verify them.

  python -m wizconnector apply --out-dir R [--repo-root .] [--maven-dir .]

Reads R/report.json, runs the planned versions-maven-plugin commands (argv lists, no shell)
for rows that are safe to automate, re-resolves the dependency tree to see which rows really
reached their target in every module, runs the build, and writes R/apply-result.json.
POM edits are left in the working tree for `wizconnector pr`.

Not automated (left for Copilot / a human): "edit by hand" rows (external parent / BOM /
external property), properties shared with other artifacts (the target may not exist for
them), bumps above --max-bump, and anything a command did not actually change.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from . import commands as cmdmod
from . import mvnversion as mv
from .maventree import build_inventory, load_trees

BUMP_ORDER = {"patch": 0, "minor": 1, "major": 2, "unknown": 3}
Runner = Callable[[list[str], Path], tuple[int, str]]


def _run(argv: list[str], cwd: Path, timeout: int = 1800) -> tuple[int, str]:
    try:
        res = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return res.returncode, (res.stdout or "") + (res.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"{type(exc).__name__}: {exc}"


def _mvn(project: Path) -> str:
    return "./mvnw" if (project / "mvnw").is_file() else "mvn"


def resolved_versions(project: Path, run: Runner = _run) -> dict[str, list[str]]:
    """GA -> resolved versions of DIRECT dependencies across all reactor modules."""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "tree.json"
        rc, log = run([_mvn(project), "-B", "-ntp", f"{cmdmod.DEPENDENCY_PLUGIN}:tree", "-DoutputType=json",
                       "-DappendOutput=true", f"-DoutputFile={out}"], project)
        if rc != 0 or not out.is_file():
            raise RuntimeError("dependency:tree failed after applying the bumps:\n" + log[-3000:])
        inv = build_inventory(load_trees([out]))
    return {g: sorted(set(d.module_versions.values()) | {d.version}, key=mv.sort_key) for g, d in inv.direct.items()}


def apply(report: dict, project: Path, verify_cmd: str = "mvn -B -ntp verify", max_bump: str = "major",
          run: Runner = _run) -> dict:
    rows = report.get("upgrades", [])
    cmds, manual = cmdmod.plan(rows)
    pending: dict[int, str] = {m.row: m.reason for m in manual}
    ran: list[dict] = []
    limit = BUMP_ORDER.get(max_bump, 2)
    for c in cmds:
        bumps = [rows[i - 1].get("bump", "unknown") for i in c.rows]
        if c.shared_with:
            reason = "property shared with " + ", ".join(g.split(":")[1] for g in c.shared_with)
        elif any(BUMP_ORDER.get(b, 3) > limit for b in bumps):
            reason = f"bump above --max-bump {max_bump}"
        else:
            reason = None
        if reason:
            for i in c.rows:
                pending.setdefault(i, reason)
            continue
        rc, log = run(c.argv(_mvn(project)), project)
        ran.append({"command": c.text(), "rows": c.rows, "exit": rc})
        if rc != 0:
            for i in c.rows:
                pending.setdefault(i, "command failed")

    applied: list[int] = []
    error = None
    if ran:
        try:
            versions = resolved_versions(project, run)
        except RuntimeError as exc:
            versions, error = {}, str(exc)[-1500:]
        for i, r in enumerate(rows, 1):
            if i in pending:
                continue
            vs = versions.get(r["ga"])
            if vs and all(mv.compare(v, r["target"]) >= 0 for v in vs):
                applied.append(i)
            elif any(i in x["rows"] for x in ran):
                pending[i] = "command did not reach the target (managed elsewhere?)"
    for i in range(1, len(rows) + 1):
        if i not in applied:
            pending.setdefault(i, "not automated")

    verify = {"cmd": verify_cmd, "ran": False, "ok": None, "log_tail": ""}
    if applied and not error:
        argv = shlex.split(verify_cmd)
        if argv and argv[0] == "mvn":
            argv[0] = _mvn(project)
        rc, log = run(argv, project)
        verify.update(ran=True, ok=rc == 0, log_tail=_tail(log))
    return {
        "schema": "wiz-connector/apply-result@v1",
        "fingerprint": report.get("fingerprint"),
        "applied_rows": applied,
        "pending": {str(i): pending[i] for i in sorted(pending)},
        "commands": ran,
        "verify": verify,
        "error": error,
    }


def _tail(log: str, lines: int = 40) -> str:
    keep = [ln for ln in log.splitlines() if ln.strip() and "Picked up JAVA_TOOL_OPTIONS" not in ln]
    return "\n".join(keep[-lines:])[-4000:]


def main(out_dir: str, repo_root: str, maven_dir: str, verify_cmd: str, max_bump: str) -> dict:
    out = Path(out_dir)
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    project = (Path(repo_root) / maven_dir).resolve()
    result = apply(report, project, verify_cmd, max_bump)
    (out / "apply-result.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    return result
