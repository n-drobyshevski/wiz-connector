import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from wizconnector import findings as fnd
from wizconnector import mvnversion as mv
from wizconnector import publish, render
from wizconnector.maventree import build_inventory, load_trees
from wizconnector.pomlocate import PomIndex, locate

FIX = Path(__file__).parent / "fixtures"
SAMPLE = FIX / "sample-project"


def sample_inventory():
    inv = build_inventory(load_trees([SAMPLE / "dependency-tree.json"]))
    idx = PomIndex(SAMPLE)
    for d in inv.direct.values():
        d.declarations = [dict(locate(idx, m, d.ga), module=m) for m in sorted(d.modules)]
    return inv


class VersionTests(unittest.TestCase):
    def test_ordering(self):
        ordered = ["1.0-alpha1", "1.0-beta", "1.0-rc1", "1.0-SNAPSHOT", "1.0", "1.0-sp1", "1.0.1", "1.1", "2.9.10", "2.9.10.8", "2.10.0"]
        for a, b in zip(ordered, ordered[1:]):
            self.assertEqual(mv.compare(a, b), -1, f"{a} < {b}")
            self.assertEqual(mv.compare(b, a), 1, f"{b} > {a}")

    def test_equivalences(self):
        for a, b in [("1", "1.0.0"), ("1.0", "1.0.RELEASE"), ("5.3.18.RELEASE", "5.3.18"), ("1.0-ga", "1.0-final")]:
            self.assertEqual(mv.compare(a, b), 0, f"{a} == {b}")

    def test_fixes_per_line(self):
        fx = ["2.12.7.1", "2.13.4.2"]
        self.assertTrue(mv.fixes("2.12.7.1", fx))
        self.assertTrue(mv.fixes("2.12.9", fx))
        self.assertFalse(mv.fixes("2.13.0", fx))     # 2.13 line needs 2.13.4.2
        self.assertTrue(mv.fixes("2.14.0", fx))      # above highest fix
        self.assertFalse(mv.fixes("2.9.8", fx))

    def test_minimal_safe_version(self):
        self.assertEqual(mv.minimal_safe_version("2.9.8", [["2.12.6.1", "2.13.2.1"], ["2.12.7.1", "2.13.4.2"]]), "2.12.7.1")
        self.assertEqual(mv.minimal_safe_version("2.14.1", [["2.15.0", "2.12.2"], ["2.17.1", "2.12.4"]]), "2.17.1")
        self.assertEqual(mv.minimal_safe_version("1.0", [["2.0.0-rc1"]]), "2.0.0-rc1")   # pre-release only as last resort
        self.assertEqual(mv.minimal_safe_version("1.0", [["2.0.0-rc1", "2.0.0"]]), "2.0.0")


class TreeTests(unittest.TestCase):
    def test_direct_vs_transitive(self):
        inv = build_inventory(load_trees([SAMPLE / "dependency-tree.json"]))
        self.assertEqual(sorted(inv.reactor), ["com.example:core", "com.example:sample-parent", "com.example:web"])
        self.assertEqual(sorted(inv.direct), [
            "com.fasterxml.jackson.core:jackson-databind", "junit:junit", "org.apache.commons:commons-text",
            "org.apache.logging.log4j:log4j-core", "org.springframework:spring-webmvc"])
        # jackson reaches `web` only through the reactor module `core`: still direct, never transitive
        self.assertNotIn("com.fasterxml.jackson.core:jackson-databind", inv.transitive)
        self.assertEqual(inv.direct["com.fasterxml.jackson.core:jackson-databind"].modules, {"com.example:core"})
        self.assertIn("org.springframework:spring-core", inv.transitive)
        self.assertEqual(inv.transitive["org.springframework:spring-core"].via, {"org.springframework:spring-webmvc"})

    def test_concatenated_and_duplicate_objects(self):
        text = (SAMPLE / "dependency-tree.json").read_text()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.json"
            p.write_text(text + "\n" + text)  # appended twice
            self.assertEqual(len(load_trees([p])), 3)


class PomLocateTests(unittest.TestCase):
    def test_sample_declarations(self):
        idx = PomIndex(SAMPLE)
        self.assertEqual(locate(idx, "com.example:core", "org.apache.logging.log4j:log4j-core"),
                         {"kind": "literal", "file": "core/pom.xml", "section": "dependencies", "value": "2.14.1"})
        jd = locate(idx, "com.example:core", "com.fasterxml.jackson.core:jackson-databind")
        self.assertEqual((jd["kind"], jd["file"], jd["property"]), ("property", "pom.xml", "jackson.version"))
        ct = locate(idx, "com.example:web", "org.apache.commons:commons-text")
        self.assertEqual((ct["kind"], ct["file"], ct["section"]), ("literal", "pom.xml", "dependencyManagement"))

    def test_external_parent_and_bom(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pom.xml").write_text(textwrap.dedent("""\
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.2.0</version><relativePath/></parent>
                  <groupId>acme</groupId><artifactId>app</artifactId><version>1</version>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>software.amazon.awssdk</groupId><artifactId>bom</artifactId><version>2.20.0</version><type>pom</type><scope>import</scope></dependency>
                  </dependencies></dependencyManagement>
                  <dependencies>
                    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency>
                    <dependency><groupId>com.h2database</groupId><artifactId>h2</artifactId><version>${h2.version}</version></dependency>
                    <dependency><groupId>${project.groupId}</groupId><artifactId>lib</artifactId><version>${project.version}</version></dependency>
                  </dependencies>
                </project>"""))
            idx = PomIndex(root)
            sy = locate(idx, "acme:app", "org.yaml:snakeyaml")
            self.assertEqual(sy["kind"], "managed-external")
            self.assertEqual(sy["external_parent"], "org.springframework.boot:spring-boot-starter-parent")
            self.assertTrue(sy["boms"][0].startswith("software.amazon.awssdk:bom:2.20.0"))
            h2 = locate(idx, "acme:app", "com.h2database:h2")
            self.assertEqual((h2["kind"], h2["property"]), ("external-property", "h2.version"))
            self.assertEqual(locate(idx, "acme:app", "acme:lib")["kind"], "project-version")

    def test_inherited_dependency_from_parent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "child").mkdir()
            (root / "pom.xml").write_text(
                "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>"
                "<properties><guava.version>31.0-jre</guava.version></properties>"
                "<dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId>"
                "<version>${guava.version}</version></dependency></dependencies></project>")
            (root / "child" / "pom.xml").write_text(
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>"
                "<artifactId>child</artifactId></project>")
            d = locate(PomIndex(root), "g:child", "com.google.guava:guava")
            self.assertEqual((d["kind"], d["file"], d["property"]), ("property", "pom.xml", "guava.version"))


class FindingsTests(unittest.TestCase):
    def setUp(self):
        self.inv = sample_inventory()
        self.raw = json.loads((FIX / "wiz-findings.json").read_text())["findings"]

    def test_parse_package_variants(self):
        self.assertEqual(fnd.parse_package("g:a"), ("g", "a"))
        self.assertEqual(fnd.parse_package("g:a:1.0"), ("g", "a"))
        self.assertEqual(fnd.parse_package("pkg:maven/g.x/a-b@1.2?type=jar"), ("g.x", "a-b"))
        self.assertEqual(fnd.parse_package("a"), (None, "a"))
        self.assertEqual(fnd.split_versions("2.15.0, 2.12.2 | >=2.3.1"), ["2.15.0", "2.12.2", "2.3.1"])

    def test_evaluate(self):
        res = fnd.evaluate(self.raw, self.inv)
        ups = {u.ga: u for u in res.upgrades}
        self.assertEqual(list(ups)[0], "org.apache.logging.log4j:log4j-core")  # KEV sorts first
        self.assertEqual(ups["org.apache.logging.log4j:log4j-core"].target, "2.17.1")
        self.assertEqual(len(ups["org.apache.logging.log4j:log4j-core"].cves), 4)  # artifact-only + purl matched
        self.assertEqual(ups["com.fasterxml.jackson.core:jackson-databind"].target, "2.12.7.1")
        self.assertEqual(ups["org.apache.commons:commons-text"].target, "1.10.0")
        self.assertNotIn("org.springframework:spring-beans", ups)
        self.assertEqual(set(res.skipped_transitive), {"org.springframework:spring-beans", "org.springframework:spring-web"})
        self.assertEqual([u.ga for u in res.no_fix], ["org.springframework:spring-webmvc"])
        self.assertEqual(list(res.unmatched), ["lodash"])

    def test_stale_finding_dropped(self):
        raw = [{"cve": "CVE-1", "package": "junit:junit", "fixed_versions": "4.11", "severity": "HIGH"}]
        res = fnd.evaluate(raw, self.inv)
        self.assertEqual(res.upgrades, [])
        self.assertEqual(res.already_fixed, {"junit:junit": ["CVE-1"]})

    def test_duplicate_cve_merged(self):
        raw = [{"cve": "CVE-9", "package": "junit:junit", "fixed_versions": "4.13.1", "severity": "LOW"},
               {"cve": "CVE-9", "package": "junit", "fixed_versions": "4.13.2", "severity": "HIGH", "cisa_kev": True}]
        u = fnd.evaluate(raw, self.inv).upgrades[0]
        self.assertEqual((len(u.cves), u.max_severity, u.kev, u.target), (1, "HIGH", True, "4.13.1"))


class RenderPublishTests(unittest.TestCase):
    def setUp(self):
        raw = json.loads((FIX / "wiz-findings.json").read_text())["findings"]
        self.res = fnd.evaluate(raw, sample_inventory())

    def test_body_is_compact_and_parseable(self):
        b = render.body(self.res, "acme/x", "main", "2026-11-04T00:00Z", None)
        self.assertIn(render.MARKER, b)
        self.assertLess(len(b), 8000)
        data = json.loads(b.split("```json\n", 1)[1].split("\n```", 1)[0])
        self.assertEqual(data["schema"], render.SCHEMA)
        self.assertEqual([u["ga"] for u in data["upgrades"]][0], "org.apache.logging.log4j:log4j-core")
        self.assertEqual(publish.previous_upgrades(b)["org.apache.commons:commons-text"], "1.10.0")

    def test_body_respects_size_limit(self):
        many = [{"cve": f"CVE-2020-{i:05d}", "package": "junit:junit", "fixed_versions": "4.13.1", "severity": "LOW"}
                for i in range(8000)]
        res = fnd.evaluate(many, sample_inventory())
        b = render.body(res, "acme/x", None, "t", None)
        self.assertLessEqual(len(b), render.MAX_BODY)
        json.loads(b.split("```json\n", 1)[1].split("\n```", 1)[0])

    def test_fingerprint_stable_and_sensitive(self):
        fp = render.fingerprint(self.res)
        self.assertEqual(fp, render.fingerprint(self.res))
        self.res.upgrades[0].target = "9.9.9"
        self.assertNotEqual(fp, render.fingerprint(self.res))

    def test_publish_plan(self):
        b = render.body(self.res, "acme/x", None, "t", None)
        fp = render.fingerprint(self.res)
        ups = {u.ga: u.target for u in self.res.upgrades}
        self.assertEqual(publish.plan([], fp, ups, True).action, "create")
        self.assertEqual(publish.plan([], fp, {}, True).action, "none")
        existing = [{"number": 7, "body": b}, {"number": 9, "body": b}, {"number": 3, "body": "unrelated"}]
        p = publish.plan(existing, fp, ups, True)
        self.assertEqual((p.action, p.number, p.duplicates), ("noop", 7, (9,)))
        p = publish.plan(existing, "different", {**ups, "new:dep": "1.0"}, True)
        self.assertEqual(p.action, "update")
        self.assertIn("`new:dep`", p.comment)
        self.assertEqual(publish.plan(existing, fp, {}, True).action, "close")
        self.assertEqual(publish.plan(existing, fp, {}, False).action, "noop")


if __name__ == "__main__":
    unittest.main()
