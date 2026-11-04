"""wiz-connector CLI.

  python -m wizconnector deps    --tree T.json [--tree ...] --repo-root . --out direct-deps.json
  python -m wizconnector report  (--deps direct-deps.json | --tree T.json --repo-root .)
                                 --findings findings.json [--agent-output agent_output.json] --out-dir out/
  python -m wizconnector publish --repo owner/name --out-dir out/ [--label wiz-sca] [--dry-run]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import findings as fnd
from . import publish as pub
from . import render
from .maventree import Inventory, build_inventory, load_trees
from .pomlocate import PomIndex, locate

SAFE_JOB_TYPE = "publish_wiz_report"


def _inventory_from_trees(trees: list[str], repo_root: str, maven_dir: str = ".") -> Inventory:
    roots = load_trees([Path(t) for t in trees])
    if not roots:
        sys.exit("error: no dependency trees found (did `mvn dependency:tree -DoutputType=json` run?)")
    inv = build_inventory(roots)
    inv.maven_dir = maven_dir
    index = PomIndex(Path(repo_root))
    for d in inv.direct.values():
        d.declarations = [dict(locate(index, m, d.ga), module=m) for m in sorted(d.modules)]
    return inv


def _inventory(a) -> Inventory:
    if a.deps:
        return Inventory.from_json(json.loads(Path(a.deps).read_text(encoding="utf-8")))
    if not a.tree:
        sys.exit("error: pass --deps or --tree")
    return _inventory_from_trees(a.tree, a.repo_root, a.maven_dir)


def _gh_output(**kv) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for k, v in kv.items():
            fh.write(f"{k}={v}\n")


def _summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")


def _from_agent_output(path: str):
    """gh-aw fallback: the agent passed the findings document as a tool input. Base64 is preferred
    because gh-aw's sanitizer rewrites URLs, mentions and `{{` inside plain string inputs."""
    try:
        out = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    items = [i for i in out.get("items", []) if i.get("type") == SAFE_JOB_TYPE]
    for item in items[:1]:
        try:
            if isinstance(item.get("findings_json_b64"), str) and item["findings_json_b64"].strip():
                return json.loads(base64.b64decode(item["findings_json_b64"], validate=True).decode("utf-8"))
            if isinstance(item.get("findings_json"), str) and item["findings_json"].strip():
                return json.loads(item["findings_json"])
        except (ValueError, json.JSONDecodeError) as exc:
            sys.exit(f"error: findings passed through the agent output are not valid JSON ({exc})")
    return None


def _load_findings(path: str, agent_output: str | None) -> tuple[list[dict], dict]:
    """Return (records, document). Fails closed: only a well-formed answer from Wiz may close the issue."""
    p = Path(path)
    if p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            sys.exit(f"error: {path} is not valid JSON ({exc})")
    elif agent_output and (data := _from_agent_output(agent_output)) is not None:
        pass
    else:
        sys.exit(f"error: findings file {path} not found and no findings in the agent output")
    if isinstance(data, list):
        data = {"findings": data}
    if not isinstance(data, dict):
        sys.exit("error: findings must be an object with a 'findings' list")
    if data.get("error"):
        # an outage must never look like "no vulnerabilities" (which closes the issue)
        sys.exit(f"error: the agent reported a Wiz fetch error: {str(data['error'])[:300]!r}")
    if not isinstance(data.get("findings"), list):
        sys.exit("error: findings document has no 'findings' list")
    return data["findings"], data


def _scope_known(doc: dict) -> bool:
    scope = doc.get("wiz_scope") or {}
    return isinstance(scope, dict) and any(isinstance(scope.get(k), str) and scope[k].strip()
                                           for k in ("resource_id", "resource_name"))


def cmd_deps(a) -> None:
    inv = _inventory_from_trees(a.tree, a.repo_root, a.maven_dir)
    out = inv.to_json()
    Path(a.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
    # compact list the agent uses to scope its Wiz queries
    Path(a.out).with_suffix(".txt").write_text(
        "\n".join(f"{d['ga']}:{d['version']}" for d in out["direct"]) + "\n", encoding="utf-8")
    print(f"{len(out['direct'])} direct, {len(out['transitive'])} transitive, {len(out['reactor'])} modules")
    _gh_output(direct_count=len(out["direct"]))


def cmd_report(a) -> None:
    inv = _inventory(a)
    records, doc = _load_findings(a.findings, a.agent_output)
    res = fnd.evaluate(records, inv)
    if records and res.rejected == len(records):
        sys.exit(f"error: all {len(records)} findings were rejected as malformed; refusing to publish")
    if not records and not _scope_known(doc):
        sys.exit("error: empty findings without wiz_scope.resource_id/resource_name: cannot tell "
                 "'no vulnerabilities' from 'repository not found'; refusing to close the issue")
    now = a.generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    maven = a.maven
    if a.maven_version_file and Path(a.maven_version_file).is_file():
        first = (Path(a.maven_version_file).read_text(encoding="utf-8").strip().splitlines() or [""])[0]
        maven = re.sub(r"\s*\(.*$", "", first)[:60] or maven      # "Apache Maven 3.9.11 (hash)" -> "Apache Maven 3.9.11"
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = render.payload(res, a.repo, a.ref, now, a.run_url, maven)
    (out / "report.json").write_text(json.dumps(data, indent=1), encoding="utf-8")
    (out / "issue-title.txt").write_text(render.title(res, a.title_prefix), encoding="utf-8")
    (out / "issue-body.md").write_text(
        render.body(res, a.repo, a.ref, now, a.run_url, a.verify_cmd, maven), encoding="utf-8")
    summary = (f"{res.total_findings} Wiz findings -> {len(res.upgrades)} direct upgrades "
               f"({sum(len(u.cves) for u in res.upgrades)} CVEs); excluded: "
               f"{sum(len(v) for v in res.skipped_transitive.values())} transitive, "
               f"{len(res.no_fix)} direct w/o fix, {len(res.already_fixed)} already fixed, "
               f"{len(res.unmatched)} packages not in tree, {res.rejected} rejected records")
    print(summary)
    _gh_output(upgrade_count=len(res.upgrades), fingerprint=data["fingerprint"])
    _summary(f"### wiz-connector\n{summary}")


def cmd_publish(a) -> None:
    out = Path(a.out_dir)
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    upgrades = {u["ga"]: u["target"] for u in data["upgrades"]}
    staged = os.environ.get("GH_AW_SAFE_OUTPUTS_STAGED", "").lower() == "true"
    p = pub.execute(
        repo=a.repo, label=a.label, title=(out / "issue-title.txt").read_text(encoding="utf-8").strip(),
        body_file=str(out / "issue-body.md"), fingerprint=data["fingerprint"], upgrades=upgrades,
        close_when_clean=not a.keep_open, assignees=[x for x in (a.assignee or "").split(",") if x],
        extra_labels=[x for x in (a.extra_labels or "").split(",") if x], dry_run=a.dry_run or staged,
        on_change=a.on_change,
        trusted_authors=tuple(x.strip() for x in a.trusted_author.split(",") if x.strip()) or pub.DEFAULT_TRUSTED_AUTHORS,
    )
    mode = " (dry run)" if a.dry_run or staged else ""
    print(f"issue action: {p.action} #{p.number or '-'}{mode}")
    _gh_output(issue_action=p.action, issue_number=p.number or "")
    _summary(f"issue action: **{p.action}** #{p.number or '-'}{mode}")
    if a.dry_run or staged:
        _summary("<details><summary>Rendered issue</summary>\n\n"
                 + (out / "issue-body.md").read_text(encoding="utf-8") + "\n</details>")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="wizconnector")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("deps", help="direct/transitive inventory (with edit locations) from dependency:tree JSON")
    d.add_argument("--tree", action="append", required=True)
    d.add_argument("--repo-root", default=".", help="repository root (edit paths are relative to it)")
    d.add_argument("--maven-dir", default=".", help="reactor root relative to --repo-root (where fix commands run)")
    d.add_argument("--out", default="direct-deps.json")
    d.set_defaults(fn=cmd_deps)

    r = sub.add_parser("report", help="join Wiz findings with direct deps and render the issue")
    r.add_argument("--deps", help="inventory written by `deps` (preferred; no POMs needed)")
    r.add_argument("--tree", action="append")
    r.add_argument("--repo-root", default=".")
    r.add_argument("--maven-dir", default=".")
    r.add_argument("--findings", required=True)
    r.add_argument("--agent-output", help="gh-aw agent_output.json: fallback source of findings_json")
    r.add_argument("--out-dir", default="wiz-report")
    r.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "local/repo"))
    r.add_argument("--ref", default=os.environ.get("GITHUB_REF_NAME"))
    r.add_argument("--run-url", default=None)
    r.add_argument("--generated-at", default=None)
    r.add_argument("--maven", default=None, help="Maven version string shown in the issue footer")
    r.add_argument("--maven-version-file", default=None)
    r.add_argument("--title-prefix", default="[wiz-sca]")
    r.add_argument("--verify-cmd", default="mvn -B -ntp verify")
    r.set_defaults(fn=cmd_report)

    p = sub.add_parser("publish", help="create/update/replace/close the tracking issue via gh")
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    p.add_argument("--out-dir", default="wiz-report")
    p.add_argument("--label", default="wiz-sca")
    p.add_argument("--extra-labels", default="")
    p.add_argument("--assignee", default="", help="comma-separated; '@copilot' assigns the Copilot cloud agent")
    p.add_argument("--on-change", choices=["update", "replace"], default="update")
    p.add_argument("--keep-open", action="store_true", help="do not close the issue when nothing is left")
    p.add_argument("--trusted-author", default=",".join(pub.DEFAULT_TRUSTED_AUTHORS),
                   help="comma-separated logins whose marked issues may be updated/closed")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_publish)

    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
