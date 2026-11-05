#!/usr/bin/env bash
# Export test-repo/ as a standalone Git repository with the wiz-connector gh-aw workflow and the
# Copilot files installed, ready to push to GitHub and connect to Wiz.
#   scripts/make-test-repo.sh <target-dir>
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:?usage: make-test-repo.sh <target-dir>}"
if [ -e "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
  echo "error: $DEST exists and is not empty" >&2
  exit 1
fi
mkdir -p "$DEST"

# the app (golden expectations stay in wiz-connector; the sample findings are useful for dry runs)
cp -R "$SRC/test-repo/." "$DEST/"
rm -rf "$DEST/expected.json" "$DEST/target" "$DEST"/*/target
# the scheduled workflow (equivalent to `gh aw add <owner>/wiz-connector/wiz-maven-vulns@v1`)
mkdir -p "$DEST/.github/workflows"
cp "$SRC/workflows/wiz-maven-vulns.md" "$DEST/.github/workflows/"
# Copilot consumer files
cp -r "$SRC/copilot/.github/." "$DEST/.github/"
cp "$SRC/copilot/.mcp.json" "$DEST/.mcp.json"
printf 'target/\n.idea/\n*.iml\n' > "$DEST/.gitignore"

cd "$DEST"
git init -q -b main
git add -A
if git commit -qm "wiz-connector test repository" 2>/dev/null; then
  echo "Committed $(git rev-list --count HEAD) commit in $DEST"
else
  echo "Files staged in $DEST (configure git user.name/user.email, then commit)"
fi
cat <<EOF

Next steps:
  cd $DEST
  gh repo create <owner>/wiz-demo-app --private --source . --push
  bash $SRC/scripts/setup.sh --local --commit && git push   # schedule, compile, variables, secrets
  # Wiz: include the new repository in your Wiz Code GitHub connector and wait for the first scan
  gh workflow run wiz-maven-vulns.lock.yml -f staged=true   # dry run, issue + PR rendered in the summary
  bash $SRC/scripts/setup.sh --doctor
EOF
