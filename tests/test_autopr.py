"""Auto-apply + automated PR: planning, apply decisions (fake Maven) and PR branch handling
(real git with a local bare remote, stub `gh`)."""

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from wizconnector import apply as applymod
from wizconnector import commands
from wizconnector import pr as prmod

ROW = lambda ga, cur, tgt, edit, bump="minor", shared=(): {  # noqa: E731
    "ga": ga, "current": cur, "target": tgt, "bump": bump, "edit": edit, "shared_with": list(shared),
    "cves": ["CVE-2021-44228"]}
LIT = [{"kind": "literal", "file": "pom.xml"}]


class PlanTests(unittest.TestCase):
    def test_argv_has_no_shell_and_matches_text(self):
        cmds, manual = commands.plan([ROW("a:b", "1.0", "2.0", LIT)])
        self.assertEqual(manual, [])
        self.assertEqual(cmds[0].argv()[:3], ["mvn", "-B", "-ntp"])
        self.assertEqual(" ".join(cmds[0].argv()), cmds[0].text())
        self.assertIn("-Dincludes=a:b", cmds[0].argv())

    def test_property_merges_rows_and_keeps_highest_target(self):
        prop = [{"kind": "property", "file": "pom.xml", "property": "x.version"}]
        cmds, _ = commands.plan([ROW("g:a", "1.0", "1.2", prop), ROW("g:b", "1.0", "1.3", prop)])
        self.assertEqual((len(cmds), cmds[0].rows, cmds[0].target), (1, [1, 2], "1.3"))


class FakeMaven:
    """Pretends to run Maven: records argv, 'applies' use-dep-version, reports a tree."""

    def __init__(self, versions, verify_rc=0, effective=True):
        self.versions, self.verify_rc, self.effective, self.calls = dict(versions), verify_rc, effective, []

    def __call__(self, argv, cwd):
        self.calls.append(argv)
        goal = next((a for a in argv if ":" in a and not a.startswith("-")), "")
        if goal.endswith(":use-dep-version") and self.effective:
            ga = next(a.split("=", 1)[1] for a in argv if a.startswith("-Dincludes="))
            self.versions[ga] = next(a.split("=", 1)[1] for a in argv if a.startswith("-DdepVersion="))
        if goal.endswith(":tree"):
            out = next(a.split("=", 1)[1] for a in argv if a.startswith("-DoutputFile="))
            children = [{"groupId": g.split(":")[0], "artifactId": g.split(":")[1], "version": v, "scope": "compile"}
                        for g, v in self.versions.items()]
            Path(out).write_text(json.dumps({"groupId": "x", "artifactId": "app", "version": "1", "children": children}))
        if argv[-1] == "verify":
            return self.verify_rc, "BUILD FAILURE: boom" if self.verify_rc else "BUILD SUCCESS"
        return 0, "ok"


class ApplyTests(unittest.TestCase):
    def test_decisions(self):
        prop = [{"kind": "property", "file": "pom.xml", "property": "jackson.version"}]
        report = {"fingerprint": "f", "upgrades": [
            ROW("a:lit", "1.0", "2.0", LIT),
            ROW("a:shared", "1.0", "1.1", prop, shared=["a:other"]),
            ROW("a:major", "1.0", "3.0", LIT, bump="major"),
            ROW("a:bom", "1.0", "1.5", [{"kind": "managed-external", "file": "pom.xml"}]),
        ]}
        fake = FakeMaven({"a:lit": "1.0", "a:shared": "1.0", "a:major": "1.0", "a:bom": "1.0"})
        res = applymod.apply(report, Path("."), max_bump="minor", run=fake)
        self.assertEqual(res["applied_rows"], [1])
        self.assertIn("shared", res["pending"]["2"])
        self.assertIn("max-bump", res["pending"]["3"])
        self.assertIn("edit by hand", res["pending"]["4"])
        self.assertTrue(res["verify"]["ok"])
        self.assertFalse(any("-Dproperty=jackson.version" in " ".join(c) for c in fake.calls))

    def test_ineffective_command_and_failing_build(self):
        report = {"fingerprint": "f", "upgrades": [ROW("a:lit", "1.0", "2.0", LIT)]}
        res = applymod.apply(report, Path("."), run=FakeMaven({"a:lit": "1.0"}, effective=False))
        self.assertEqual(res["applied_rows"], [])
        self.assertIn("did not reach", res["pending"]["1"])
        self.assertFalse(res["verify"]["ran"])
        res = applymod.apply(report, Path("."), run=FakeMaven({"a:lit": "1.0"}, verify_rc=1))
        self.assertEqual((res["applied_rows"], res["verify"]["ok"]), ([1], False))


def git(cwd, *args, env=None):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=env).stdout.strip()


class PrTests(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td)
        self.remote = self.td / "remote.git"
        git(self.td, "init", "-q", "--bare", str(self.remote))
        self.repo = self.td / "repo"
        self.repo.mkdir()
        (self.repo / "pom.xml").write_text("<project><version>1.0</version></project>\n")
        (self.repo / "README.md").write_text("hi\n")
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "-c", "user.name=dev", "-c", "user.email=dev@example.com", "commit", "-qm", "base")
        git(self.repo, "remote", "add", "origin", str(self.remote))
        git(self.repo, "push", "-q", "origin", "main")
        self.base = git(self.repo, "rev-parse", "HEAD")
        # stub gh: logs calls, answers `pr list` from a file
        self.bin = self.td / "bin"
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text('#!/usr/bin/env bash\necho "$*" >> "$GH_LOG"\n'
                      'case "$1 $2" in "pr list") cat "$GH_PRS" 2>/dev/null || echo "[]";;\n'
                      '"pr create") echo "https://github.com/acme/app/pull/8";; esac\n')
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
        self.log, self.prs = self.td / "gh.log", self.td / "prs.json"
        self.env = {"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "GH_LOG": str(self.log), "GH_PRS": str(self.prs)}
        self.out = self.td / "out"
        self.out.mkdir()
        (self.out / "report.json").write_text(json.dumps({"fingerprint": "f", "upgrades": [ROW("a:b", "1.0", "2.0", LIT)]}))

    def _run(self, applied=(1,), verify_ok=True, issue=7):
        (self.out / "apply-result.json").write_text(json.dumps({
            "fingerprint": "f", "applied_rows": list(applied), "pending": {} if applied else {"1": "x"},
            "verify": {"cmd": "mvn -B -ntp verify", "ran": True, "ok": verify_ok, "log_tail": "boom"}}))
        old = dict(os.environ)
        os.environ.update(self.env)
        try:
            return prmod.run("acme/app", self.repo, self.out, issue, "main", ["wiz-sca"])
        finally:
            os.environ.clear()
            os.environ.update(old)

    def _bump(self):
        git(self.repo, "checkout", "-q", "--detach", self.base)
        (self.repo / "pom.xml").write_text("<project><version>2.0</version></project>\n")
        (self.repo / "README.md").write_text("changed by the build\n")

    def _remote_sha(self):
        return git(self.remote, "rev-parse", f"refs/heads/{prmod.PR_BRANCH}")

    def test_create_draft_only_poms_then_unchanged(self):
        self._bump()
        o = self._run(verify_ok=False)
        self.assertEqual((o.action, o.number), ("created", 8))
        calls = self.log.read_text()
        self.assertIn("--draft", calls)
        files = git(self.remote, "show", "--name-only", "--format=", prmod.PR_BRANCH).split()
        self.assertEqual(files, ["pom.xml"])                       # README change never committed
        author = git(self.remote, "log", "-1", "--format=%ae", prmod.PR_BRANCH)
        self.assertEqual(author, prmod.BOT_EMAIL)
        body = (self.out / "pr-body.md").read_text()
        self.assertTrue(body.startswith(prmod.PR_MARKER))
        self.assertIn("Refs #7", body)
        # next run: same changes, PR exists -> no new push, PR marked ready when the build passes
        first = self._remote_sha()
        self.prs.write_text(json.dumps([{"number": 8, "isDraft": True, "author": {"login": "app/github-actions"},
                                         "body": body}]))
        self._bump()
        o = self._run(verify_ok=True)
        self.assertEqual((o.action, self._remote_sha()), ("unchanged", first))
        self.assertIn("pr ready 8", self.log.read_text())
        self.assertIn("Fixes #7", (self.out / "pr-body.md").read_text())

    def test_foreign_commit_blocks_rewrite(self):
        self._bump()
        self._run()
        work = self.td / "human"
        git(self.td, "clone", "-q", "-b", prmod.PR_BRANCH, str(self.remote), str(work))
        (work / "pom.xml").write_text("<project><version>2.1</version></project>\n")
        git(work, "-c", "user.name=dev", "-c", "user.email=dev@example.com", "commit", "-qam", "manual fix")
        git(work, "push", "-q", "origin", prmod.PR_BRANCH)
        human = self._remote_sha()
        self._bump()
        o = self._run()
        self.assertEqual(o.action, "skipped")
        self.assertEqual(self._remote_sha(), human)

    def test_close_when_nothing_left(self):
        self.prs.write_text(json.dumps([{"number": 8, "isDraft": False, "author": {"login": "app/github-actions"},
                                         "body": prmod.PR_MARKER + "\nx"}]))
        git(self.repo, "checkout", "-q", "--detach", self.base)
        o = self._run(applied=())
        self.assertEqual((o.action, o.number), ("closed", 8))
        self.assertIn("pr close 8", self.log.read_text())

    def test_failed_apply_never_closes_the_pr(self):
        self.prs.write_text(json.dumps([{"number": 8, "isDraft": False, "author": {"login": "app/github-actions"},
                                         "body": prmod.PR_MARKER + "\nx"}]))
        git(self.repo, "checkout", "-q", "--detach", self.base)
        old = dict(os.environ)
        os.environ.update(self.env)
        try:
            o = prmod.run("acme/app", self.repo, self.out, 7, "main", [])          # no apply-result.json
            self.assertEqual(o.action, "skipped")
            (self.out / "apply-result.json").write_text(json.dumps(
                {"fingerprint": "f", "applied_rows": [], "pending": {}, "error": "dependency:tree failed"}))
            self.assertEqual(prmod.run("acme/app", self.repo, self.out, 7, "main", []).action, "skipped")
        finally:
            os.environ.clear()
            os.environ.update(old)
        self.assertNotIn("pr close", self.log.read_text() if self.log.exists() else "")

    def test_foreign_pr_on_branch_is_ignored(self):
        self.prs.write_text(json.dumps([{"number": 9, "isDraft": False, "author": {"login": "mallory"},
                                         "body": prmod.PR_MARKER}]))
        git(self.repo, "checkout", "-q", "--detach", self.base)
        o = self._run(applied=())
        self.assertEqual(o.action, "none")


if __name__ == "__main__":
    unittest.main()
