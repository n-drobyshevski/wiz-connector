#!/usr/bin/env bash
# Resolve the direct Maven dependencies of the checked-out repository.
#   resolve-deps.sh <out-dir>
# env: MAVEN_DIR      directory of the root (reactor) pom.xml, relative to the repo root (default ".")
#      WIZ_CONNECTOR  path of the wiz-connector checkout (default "$GITHUB_WORKSPACE/.wiz-connector")
# Writes <out-dir>/{dependency-tree.json,direct-deps.json,direct-deps.txt,maven-version.txt,mvn-tree.log}
set -euo pipefail

OUT="${1:?usage: resolve-deps.sh <out-dir>}"
ROOT="${GITHUB_WORKSPACE:-$PWD}"
MAVEN_DIR="${MAVEN_DIR:-.}"
WIZ_CONNECTOR="${WIZ_CONNECTOR:-$ROOT/.wiz-connector}"

case "$MAVEN_DIR" in /*|*..*) echo "::error::MAVEN_DIR must be a relative path inside the repository"; exit 1;; esac
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
rm -f "$OUT/dependency-tree.json"                # the plugin appends to an existing file

cd "$ROOT/$MAVEN_DIR"
MVN=mvn
[ -x ./mvnw ] && MVN=./mvnw
"$MVN" -v 2>/dev/null | head -1 > "$OUT/maven-version.txt" || true

# From the reactor root and without -pl: every module becomes its own tree root.
if ! "$MVN" -B -ntp org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree \
    -DoutputType=json -DappendOutput=true -DoutputFile="$OUT/dependency-tree.json" > "$OUT/mvn-tree.log" 2>&1; then
  tail -50 "$OUT/mvn-tree.log"
  exit 1
fi
if grep -Eq 'The POM for .* is missing' "$OUT/mvn-tree.log"; then
  grep -E 'The POM for .* is missing' "$OUT/mvn-tree.log"
  echo "::error::dependency tree is incomplete (missing POMs); fix repository access first"
  exit 1
fi

PYTHONPATH="$WIZ_CONNECTOR" python3 -m wizconnector deps \
  --tree "$OUT/dependency-tree.json" --repo-root "$ROOT" --maven-dir "$MAVEN_DIR" \
  --out "$OUT/direct-deps.json"
