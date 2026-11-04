"""wiz-connector CLI.

  python -m wizconnector deps    --tree T.json [--tree ...] --repo-root . --out direct-deps.json
  python -m wizconnector report  --tree T.json --repo-root . --findings wiz-findings.json --out-dir out/
  python -m wizconnector publish --repo owner/name --out-dir out/ [--label wiz-sca] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import findings as fnd
from . import publish as pub
from . import render
from .maventree import build_inventory, load_trees
from .pomlocate import PomIndex, locate


def _inventory(trees: list[str], repo_root: str):
    roots = load_trees([Path(t) for t in trees])
    if not roots:
        sys.exit("error: no dependency trees found (did `mvn dependency:tree -DoutputType=json` run?)")
    inv = build_inventory(roots)
    index = PomIndex(Path(repo_root))
    for d in inv.direct.values():
        d.declarations = [dict(locate(index, m, d.ga), module=m) for m in sorted(d.modules)]
    return inv


def _gh_output(**kv) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for k, v in kv.items():
            fh.write(f"{k}={v}\n")


def _load_findings(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if data.get("error"):
            sys.exit(f"error: findings file reports a fetch error: {data['error']}")
        data = data.get("findings", [])
    if not isinstance(data, list):
        sys.exit("error: findings file must be a list or an object with a 'findings' list")
    return data


def cmd_deps(a) -> None:
    inv = _inventory(a.tree, a.repo_root)
    out = inv.to_json()
    Path(a.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
    # compact package list the agent can use to scope Wiz queries
    Path(a.out).with_suffix(".txt").write_text(
        "\n".join(f"{d['ga']}:{d['version']}" for d in out["direct"]) + "\n", encoding="utf-8")
    print(f"{len(out['direct'])} direct, {len(out['transitive'])} transitive, {len(out['reactor'])} modules")
    _gh_output(direct_count=len(out["direct"]))


def cmd_report(a) -> None:
    inv = _inventory(a.tree, a.repo_root)
    res = fnd.evaluate(_load_findings(a.findings), inv)
    now = a.generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = render.payload(res, a.repo, a.ref, now, a.run_url)
    (out / "report.json").write_text(json.dumps(data, indent=1), encoding="utf-8")
    (out / "issue-title.txt").write_text(render.title(res, a.title_prefix), encoding="utf-8")
    (out / "issue-body.md").write_text(render.body(res, a.repo, a.ref, now, a.run_url, a.verify_cmd), encoding="utf-8")
    summary = (f"{res.total_findings} Wiz findings -> {len(res.upgrades)} direct upgrades "
               f"({sum(len(u.cves) for u in res.upgrades)} CVEs); excluded: "
               f"{sum(len(v) for v in res.skipped_transitive.values())} transitive, "
               f"{len(res.no_fix)} direct w/o fix, {len(res.already_fixed)} already fixed, "
               f"{len(res.unmatched)} packages not in tree")
    print(summary)
    _gh_output(upgrade_count=len(res.upgrades), fingerprint=data["fingerprint"])
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(f"### wiz-connector\n{summary}\n")


def cmd_publish(a) -> None:
    out = Path(a.out_dir)
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    upgrades = {u["ga"]: u["target"] for u in data["upgrades"]}
    p = pub.execute(
        repo=a.repo, label=a.label, title=(out / "issue-title.txt").read_text(encoding="utf-8").strip(),
        body_file=str(out / "issue-body.md"), fingerprint=data["fingerprint"], upgrades=upgrades,
        close_when_clean=not a.keep_open, assignees=[x for x in (a.assignee or "").split(",") if x],
        extra_labels=[x for x in (a.extra_labels or "").split(",") if x], dry_run=a.dry_run,
    )
    print(f"issue action: {p.action} #{p.number or '-'}")
    _gh_output(issue_action=p.action, issue_number=p.number or "")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="wizconnector")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("deps", help="direct/transitive inventory from dependency:tree JSON")
    d.add_argument("--tree", action="append", required=True)
    d.add_argument("--repo-root", default=".")
    d.add_argument("--out", default="direct-deps.json")
    d.set_defaults(fn=cmd_deps)

    r = sub.add_parser("report", help="join Wiz findings with direct deps and render the issue")
    r.add_argument("--tree", action="append", required=True)
    r.add_argument("--repo-root", default=".")
    r.add_argument("--findings", required=True)
    r.add_argument("--out-dir", default="wiz-report")
    r.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "local/repo"))
    r.add_argument("--ref", default=os.environ.get("GITHUB_REF_NAME"))
    r.add_argument("--run-url", default=None)
    r.add_argument("--generated-at", default=None)
    r.add_argument("--title-prefix", default="[wiz-sca]")
    r.add_argument("--verify-cmd", default="mvn -B -ntp verify")
    r.set_defaults(fn=cmd_report)

    p = sub.add_parser("publish", help="create/update/close the tracking issue via gh")
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    p.add_argument("--out-dir", default="wiz-report")
    p.add_argument("--label", default="wiz-sca")
    p.add_argument("--extra-labels", default="")
    p.add_argument("--assignee", default="")
    p.add_argument("--keep-open", action="store_true", help="do not close the issue when nothing is left")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_publish)

    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
