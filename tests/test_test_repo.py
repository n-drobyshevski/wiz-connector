"""Golden test on test-repo/ (a deliberately vulnerable multi-module Spring Boot app).

Offline: uses the dependency tree captured from a real `mvn dependency:tree` run
(tests/fixtures/test-repo-tree.json). CI additionally regenerates the tree live
(`.github/workflows/ci.yml`, job test-repo-e2e) and applies the fix commands.
Set WIZ_TEST_REPO_TREE to check a freshly generated tree instead.
"""

import json
import os
import unittest
from pathlib import Path

from wizconnector import findings as fnd
from wizconnector import render
from wizconnector.maventree import build_inventory, load_trees
from wizconnector.pomlocate import PomIndex, locate

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT / "test-repo"
TREE = Path(os.environ.get("WIZ_TEST_REPO_TREE", ROOT / "tests" / "fixtures" / "test-repo-tree.json"))


def inventory():
    inv = build_inventory(load_trees([TREE]))
    idx = PomIndex(REPO)
    for d in inv.direct.values():
        d.declarations = [dict(locate(idx, m, d.ga), module=m) for m in sorted(d.modules)]
    return inv


class TestRepoGolden(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads((REPO / "expected.json").read_text())
        doc = json.loads((REPO / "wiz-findings.sample.json").read_text())
        cls.result = fnd.evaluate(doc["findings"], inventory())

    def test_upgrades_match_expected(self):
        got = [{"ga": u.ga, "current": u.current, "target": u.target, "bump": u.bump,
                "severity": u.max_severity, "kev": u.kev, "cves": sorted(f.cve for f in u.cves),
                "edit_kinds": sorted({d["kind"] for d in u.declarations})}
               for u in self.result.upgrades]
        self.assertEqual(got, self.expected["upgrades"])

    def test_exclusions_match_expected(self):
        ex = self.expected["excluded"]
        self.assertEqual(sorted(self.result.skipped_transitive), ex["transitive"])
        self.assertEqual(self.result.already_fixed, ex["already_fixed"])
        self.assertEqual(sorted(self.result.unmatched), ex["not_in_maven_tree"])
        self.assertEqual(self.result.rejected, ex["rejected_records"])

    def test_branches_exercised(self):
        ups = {u.ga: u for u in self.result.upgrades}
        # child override: batch already resolves 1.10.0, api does not
        ct = ups["org.apache.commons:commons-text"]
        self.assertEqual(ct.module_versions, {"com.example.wizdemo:api": "1.9", "com.example.wizdemo:batch": "1.10.0"})
        self.assertEqual({d["file"] for d in ct.declarations}, {"pom.xml", "batch/pom.xml"})
        # flavour kept
        self.assertEqual(ups["com.google.guava:guava"].target, "32.0.0-jre")
        # unfixed CVE kept separately on a fixable row
        self.assertEqual([f.cve for f in ups["com.fasterxml.jackson.core:jackson-databind"].unfixed_cves], ["CVE-2023-35116"])
        # sibling module is never a dependency row; transitive spring-web never listed
        self.assertNotIn("com.example.wizdemo:api", ups)
        self.assertNotIn("org.springframework:spring-web", ups)

    def test_min_severity_filter_keeps_kev(self):
        doc = json.loads((REPO / "wiz-findings.sample.json").read_text())
        res = fnd.evaluate(doc["findings"], inventory(), "HIGH")
        ups = {u.ga: u for u in res.upgrades}
        log4j = ups["org.apache.logging.log4j:log4j-core"]
        self.assertEqual(sorted(f.cve for f in log4j.cves), ["CVE-2021-44228", "CVE-2021-45046"])   # KEV kept
        self.assertEqual(log4j.target, "2.16.0")              # MEDIUM CVEs hidden -> lower target
        self.assertEqual(res.below_threshold["org.apache.logging.log4j:log4j-core"], ["CVE-2021-44832", "CVE-2021-45105"])
        body = render.body(res, "r", None, "t", None)
        self.assertIn("Below the minimum severity", body)
        self.assertIn("/wiz-scan", body)

    def test_fix_commands_and_body(self):
        cmds = render.fix_commands(self.result.upgrades)
        want = self.expected["fix_commands"]
        self.assertEqual(sum(":use-dep-version " in c for c in cmds), want["use-dep-version"])
        self.assertEqual(sum(":set-property " in c for c in cmds), want["set-property"])
        self.assertEqual(sum("edit by hand" in c for c in cmds), want["edit_by_hand"])
        body = render.body(self.result, "acme/wiz-demo-app", "main", "t", None)
        self.assertNotIn("evil.example", body)
        self.assertNotIn("$(id)", body)
        self.assertLess(len(body), 12_000)


if __name__ == "__main__":
    unittest.main()
