#!/usr/bin/env bash
# Live end-to-end check on test-repo/ (needs JDK 17+, Maven, network to Maven Central):
#   1. resolve the dependency tree with the workflow's own script and compare with the golden test
#   2. render the issue from the sample Wiz findings
#   3. auto-apply the safe rows exactly as the workflow's publish job does (wizconnector apply),
#      then make the "edit by hand" changes the way Copilot would
#   4. mvn verify, re-resolve, re-report: nothing actionable may be left (the issue would close)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$(mktemp -d)}"
rm -rf "$WORK/app" && mkdir -p "$WORK" && cp -r "$HERE/test-repo" "$WORK/app"
rm -rf "$WORK"/app/*/target "$WORK/app/target"
export PYTHONPATH="$HERE" WIZ_CONNECTOR="$HERE"
FINDINGS="$HERE/test-repo/wiz-findings.sample.json"

echo "::group::1. resolve + golden comparison"
GITHUB_WORKSPACE="$WORK/app" bash "$HERE/scripts/resolve-deps.sh" "$WORK/before"
WIZ_TEST_REPO_TREE="$WORK/before/dependency-tree.json" python3 -m unittest -v tests.test_test_repo
echo "::endgroup::"

echo "::group::2. render issue"
python3 -m wizconnector report --deps "$WORK/before/direct-deps.json" --findings "$FINDINGS" \
  --maven-version-file "$WORK/before/maven-version.txt" --repo acme/wiz-demo-app \
  --out-dir "$WORK/report"
echo "::endgroup::"

echo "::group::3. auto-apply (as the publish job does) + manual edits (as Copilot would)"
(cd "$WORK/app" && git init -q && git add -A && git -c user.email=ci@example.invalid -c user.name=ci commit -qm base)
python3 -m wizconnector apply --out-dir "$WORK/report" --repo-root "$WORK/app"
python3 -c '
import json, sys
got = json.load(open(sys.argv[1]))
want = json.load(open(sys.argv[2]))["auto_apply"]
assert got["applied_rows"] == want["applied_rows"], (got["applied_rows"], want)
assert sorted(map(int, got["pending"])) == want["pending_rows"], got["pending"]
assert got["verify"]["ok"] is want["verify_ok"], got["verify"]
print("auto-apply matches expected.json:", got["applied_rows"])
' "$WORK/report/apply-result.json" "$HERE/test-repo/expected.json"
cd "$WORK/app"
# the two rows left for Copilot ("edit by hand")
python3 - <<'EOF'
import re
p = "pom.xml"
s = open(p).read()
s = s.replace("  </properties>",
              "    <snakeyaml.version>2.0</snakeyaml.version>\n  </properties>\n\n"
              "  <dependencyManagement>\n    <dependencies>\n      <dependency>\n"
              "        <groupId>com.fasterxml.jackson.core</groupId>\n        <artifactId>jackson-databind</artifactId>\n"
              "        <version>2.13.4.2</version>\n      </dependency>\n    </dependencies>\n  </dependencyManagement>", 1)
open(p, "w").write(s)
EOF
git diff --stat
echo "::endgroup::"

echo "::group::4. verify + re-report"
mvn -B -ntp -q verify
GITHUB_WORKSPACE="$WORK/app" bash "$HERE/scripts/resolve-deps.sh" "$WORK/after"
cd "$HERE"
python3 -m wizconnector report --deps "$WORK/after/direct-deps.json" --findings "$FINDINGS" --out-dir "$WORK/after/report"
left="$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['upgrades']))" "$WORK/after/report/report.json")"
echo "::endgroup::"
if [ "$left" != "0" ]; then
  echo "::error::$left upgrades still listed after applying the fixes"
  exit 1
fi
echo "test-repo e2e OK: issue commands + manual edits fix every listed CVE"
