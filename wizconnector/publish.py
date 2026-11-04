"""Create / update / close the single tracking issue (idempotent, de-duplicated by a hidden marker)."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass

from .render import MARKER

_FP = re.compile(re.escape(MARKER) + r" fingerprint=([0-9a-f]+)")
_JSON = re.compile(r"```json\n(.*?)\n```", re.S)


@dataclass
class Plan:
    action: str                 # create | update | replace | noop | close | none
    number: int | None = None
    duplicates: tuple = ()
    comment: str | None = None


def previous_upgrades(body: str) -> dict[str, str]:
    m = _JSON.search(body or "")
    if not m:
        return {}
    try:
        data = json.loads(m.group(1))
    except json.JSONDecodeError:
        return {}
    return {u["ga"]: u.get("target") for u in data.get("upgrades", []) if isinstance(u, dict) and "ga" in u}


def delta_comment(old: dict[str, str], new: dict[str, str]) -> str | None:
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    retarget = sorted(g for g in set(old) & set(new) if old[g] != new[g])
    if not (added or removed or retarget):
        return "Wiz findings changed (CVE list updated); dependency targets are unchanged."
    parts = []
    if added:
        parts.append("**New:** " + ", ".join(f"`{g}` → `{new[g]}`" for g in added))
    if retarget:
        parts.append("**New target:** " + ", ".join(f"`{g}` `{old[g]}` → `{new[g]}`" for g in retarget))
    if removed:
        parts.append("**Resolved / no longer listed:** " + ", ".join(f"`{g}`" for g in removed))
    return "Issue body refreshed from the latest Wiz scan.\n\n" + "\n".join(f"- {p}" for p in parts)


def plan(existing: list[dict], new_fingerprint: str, new_upgrades: dict[str, str], close_when_clean: bool,
         on_change: str = "update") -> Plan:
    """on_change="update" edits the open issue in place (best when humans run Copilot in VS Code on
    the current issue). on_change="replace" closes it and opens a fresh one, for issues assigned to
    the Copilot cloud agent, which ignores edits and comments made after assignment."""
    ours = sorted((i for i in existing if MARKER in (i.get("body") or "")), key=lambda i: i["number"])
    if not ours:
        return Plan("create") if new_upgrades else Plan("none")
    keep, dups = ours[0], tuple(i["number"] for i in ours[1:])
    if not new_upgrades:
        if close_when_clean:
            return Plan("close", keep["number"], dups,
                        "Wiz reports no open vulnerabilities in direct Maven dependencies any more. Closing.")
        return Plan("noop", keep["number"], dups)
    m = _FP.search(keep.get("body") or "")
    if m and m.group(1) == new_fingerprint:
        return Plan("noop", keep["number"], dups)
    comment = delta_comment(previous_upgrades(keep.get("body", "")), new_upgrades)
    return Plan("replace" if on_change == "replace" else "update", keep["number"], dups, comment)


def _assign(repo: str, number: int, assignees: list[str]) -> None:
    """Assigning Copilot ("@copilot") needs a user token (fine-grained PAT) in COPILOT_ASSIGN_TOKEN;
    GITHUB_TOKEN and GitHub App tokens are rejected for Copilot assignment. Failures are non-fatal."""
    import os
    env = dict(os.environ)
    if os.environ.get("COPILOT_ASSIGN_TOKEN"):
        env["GH_TOKEN"] = os.environ["COPILOT_ASSIGN_TOKEN"]
    args = ["gh", "issue", "edit", str(number), "--repo", repo]
    for a in assignees:
        args += ["--add-assignee", a]
    res = subprocess.run(args, capture_output=True, text=True, env=env)
    if res.returncode:
        print(f"::warning::could not assign {assignees} to #{number}: {res.stderr.strip()[:300]}")


def _gh(*args: str, input_text: str | None = None) -> str:
    res = subprocess.run(["gh", *args], input=input_text, capture_output=True, text=True, check=True)
    return res.stdout


def execute(repo: str, label: str, title: str, body_file: str, fingerprint: str,
            upgrades: dict[str, str], close_when_clean: bool = True, assignees: list[str] | None = None,
            extra_labels: list[str] | None = None, dry_run: bool = False, on_change: str = "update") -> Plan:
    existing = json.loads(_gh("issue", "list", "--repo", repo, "--label", label, "--state", "open",
                              "--limit", "100", "--json", "number,title,body"))
    p = plan(existing, fingerprint, upgrades, close_when_clean, on_change)
    if dry_run:
        return p
    labels = [label, *(extra_labels or [])]
    if p.action in ("create", "update", "replace"):
        for lb in labels:
            _gh("label", "create", lb, "--repo", repo, "--force", "--color", "B60205",
                "--description", "Managed by wiz-connector")
    if p.action in ("create", "replace"):
        old = p.number
        args = ["issue", "create", "--repo", repo, "--title", title, "--body-file", body_file]
        for lb in labels:
            args += ["--label", lb]
        out = _gh(*args).strip()
        p.number = int(out.rstrip("/").rsplit("/", 1)[-1]) if out else None
        if assignees and p.number:
            _assign(repo, p.number, assignees)
        if p.action == "replace" and old:
            _gh("issue", "close", str(old), "--repo", repo, "--reason", "not planned",
                "--comment", f"Superseded by #{p.number}: {p.comment or 'findings changed'}")
    elif p.action == "update":
        _gh("issue", "edit", str(p.number), "--repo", repo, "--title", title, "--body-file", body_file)
        if p.comment:
            _gh("issue", "comment", str(p.number), "--repo", repo, "--body", p.comment)
    elif p.action == "close":
        _gh("issue", "close", str(p.number), "--repo", repo, "--reason", "completed", "--comment", p.comment or "")
    for d in p.duplicates:
        _gh("issue", "close", str(d), "--repo", repo, "--reason", "not planned",
            "--comment", f"Duplicate of #{p.number} (managed by wiz-connector).")
    return p
