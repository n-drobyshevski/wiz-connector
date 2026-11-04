"""setup.sh / doctor against a temporary repository and a stub `gh` (no network)."""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STUB = r'''#!/usr/bin/env python3
import json, os, sys, shutil, pathlib
a = sys.argv[1:]
state = pathlib.Path(os.environ["GH_STATE"])
log = state / "calls.jsonl"
entry = {"args": a}
if a[:2] == ["secret", "set"]:
    entry["stdin"] = sys.stdin.read()
with open(log, "a") as fh:
    fh.write(json.dumps(entry) + "\n")
def load(name, default):
    p = state / name
    return json.loads(p.read_text()) if p.exists() else default
if a[:2] in (["auth", "status"], ["aw", "version"]):
    sys.exit(0)
if a[:2] == ["repo", "view"]:
    print("acme/app"); sys.exit(0)
if a[:2] == ["aw", "add"]:
    dst = pathlib.Path(".github/workflows"); dst.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(os.environ["WIZ_SRC"] + "/workflows/wiz-maven-vulns.md", dst / "wiz-maven-vulns.md"); sys.exit(0)
if a[:2] == ["aw", "compile"]:
    pathlib.Path(".github/workflows/wiz-maven-vulns.lock.yml").write_text("# compiled\n"); sys.exit(0)
if a[:2] == ["variable", "set"]:
    v = load("vars.json", {}); v[a[2]] = a[a.index("--body") + 1]; (state / "vars.json").write_text(json.dumps(v)); sys.exit(0)
if a[:2] == ["variable", "list"]:
    print(json.dumps([{"name": k, "value": v} for k, v in load("vars.json", {}).items()])); sys.exit(0)
if a[:2] == ["secret", "set"]:
    s = load("secrets.json", []); s.append(a[2]); (state / "secrets.json").write_text(json.dumps(sorted(set(s)))); sys.exit(0)
if a[:2] == ["secret", "list"]:
    print(json.dumps([{"name": n} for n in load("secrets.json", [])])); sys.exit(0)
if a[0] == "api" and "-X" not in a:
    print(json.dumps(load("perm.json", {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": False}))); sys.exit(0)
if a[0] == "api" and "-X" in a:
    (state / "perm.json").write_text(json.dumps({"default_workflow_permissions": a[a.index("-f") + 1].split("=")[1],
                                                 "can_approve_pull_request_reviews": True})); sys.exit(0)
if a[:2] == ["run", "list"]:
    print("[]"); sys.exit(0)
sys.exit(0)
'''


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td)
        self.repo, self.state, self.bin = self.td / "repo", self.td / "state", self.td / "bin"
        for d in (self.repo, self.state, self.bin):
            d.mkdir()
        (self.repo / "pom.xml").write_text("<project/>\n")
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        gh = self.bin / "gh"
        gh.write_text(STUB)
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
        self.env = {**os.environ, "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}", "GH_STATE": str(self.state),
                    "WIZ_SRC": str(ROOT), "PYTHONPATH": str(ROOT)}
        for k in ("WIZ_CLIENT_ID", "WIZ_CLIENT_SECRET", "WIZ_DATACENTER"):
            self.env.pop(k, None)

    def run_setup(self, *args, extra_env=None):
        env = {**self.env, **(extra_env or {})}
        return subprocess.run(["bash", str(ROOT / "scripts/setup.sh"), *args], cwd=self.repo, env=env,
                              capture_output=True, text=True, stdin=subprocess.DEVNULL)

    def calls(self):
        return [json.loads(ln) for ln in (self.state / "calls.jsonl").read_text().splitlines()]

    def test_setup_then_doctor(self):
        r = self.run_setup("--yes", "--schedule", "daily around 9am on weekdays", "--on-pom-change", "develop",
                           "--datacenter", "us17", "--max-bump", "minor", "--skip-wiz-check",
                           extra_env={"WIZ_CLIENT_ID": "id-123", "WIZ_CLIENT_SECRET": "s3cr3t"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        md = (self.repo / ".github/workflows/wiz-maven-vulns.md").read_text()
        self.assertIn("  schedule: daily around 9am on weekdays\n", md)
        self.assertIn("    branches: [develop]\n", md)
        self.assertTrue((self.repo / ".github/workflows/wiz-maven-vulns.lock.yml").exists())
        for f in (".github/skills/wiz-maven-bumps/SKILL.md", ".github/instructions/maven-pom.instructions.md",
                  ".github/workflows/copilot-setup-steps.yml", ".github/copilot-instructions.md", ".mcp.json"):
            self.assertTrue((self.repo / f).exists(), f)
        vars_ = json.loads((self.state / "vars.json").read_text())
        self.assertEqual(vars_["WIZ_AUTO_PR_MAX_BUMP"], "minor")
        self.assertEqual(vars_["WIZ_MAVEN_DIR"], ".")
        calls = self.calls()
        # secrets go through stdin, never through argv
        sets = {c["args"][2]: c["stdin"] for c in calls if c["args"][:2] == ["secret", "set"]}
        self.assertEqual(sets, {"WIZ_CLIENT_ID": "id-123", "WIZ_CLIENT_SECRET": "s3cr3t", "WIZ_DATACENTER": "us17"})
        self.assertFalse(any("s3cr3t" in " ".join(c["args"]) for c in calls))
        # PR permission enabled without downgrading the existing default token permission
        put = next(c["args"] for c in calls if c["args"][0] == "api" and "-X" in c["args"])
        self.assertIn("default_workflow_permissions=write", put)
        self.assertIn("can_approve_pull_request_reviews=true", put)
        self.assertTrue(any(c["args"][:2] == ["aw", "add"] for c in calls))

        # re-running setup keeps existing secrets and does not ask again
        r = self.run_setup("--yes", "--skip-wiz-check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("already set", r.stdout)

        d = self.run_setup("--doctor")
        self.assertIn("schedule: daily around 9am on weekdays", d.stdout)
        self.assertIn("/wiz-scan", d.stdout)
        self.assertEqual(d.returncode, 0, d.stdout)

    def test_doctor_reports_missing_pieces(self):
        d = self.run_setup("--doctor")
        self.assertEqual(d.returncode, 1)
        self.assertIn("wiz-maven-vulns.md missing", d.stdout)
        self.assertIn("secret WIZ_CLIENT_SECRET missing", d.stdout)

    def test_local_copy_and_cron_timezone(self):
        r = self.run_setup("--yes", "--local", "--cron", "30 7 * * 1-5", "--timezone", "Europe/Paris",
                           "--no-copilot-files", "--skip-wiz-check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        md = (self.repo / ".github/workflows/wiz-maven-vulns.md").read_text()
        self.assertIn('    - cron: "30 7 * * 1-5"\n      timezone: "Europe/Paris"\n', md)
        self.assertFalse((self.repo / ".mcp.json").exists())
        self.assertFalse(any(c["args"][:2] == ["aw", "add"] for c in self.calls()))

    def test_bad_input_is_rejected(self):
        r = self.run_setup("--yes", "--local", "--schedule", "every 6h; rm -rf /")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unsupported schedule", r.stderr)
        r = self.run_setup("--timezone", "Europe/Paris", "--schedule", "daily")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
