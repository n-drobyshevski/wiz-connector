#!/usr/bin/env bash
# Set up (or check with --doctor) wiz-connector in the repository you are in.
#   cd my-maven-repo && bash /path/to/wiz-connector/scripts/setup.sh [--help]
# Needs git, gh (+ gh-aw) and Python 3.10+. No JDK or Maven: the workflow installs them on the runner.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"

# python3 on Linux/macOS; python or `py -3` on Windows (Git Bash). Skips the Microsoft Store stub.
PY=()
for cand in "python3" "python" "py -3"; do
  read -r -a try <<< "$cand"
  if command -v "${try[0]}" >/dev/null 2>&1 &&
     "${try[@]}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
    PY=("${try[@]}")
    break
  fi
done
if [ ${#PY[@]} -eq 0 ]; then
  echo "error: Python 3.10+ not found (tried python3, python, py -3). Install it from python.org." >&2
  exit 1
fi

case "$(uname -s 2>/dev/null)" in MINGW*|MSYS*|CYGWIN*) SEP=";" ;; *) SEP=":" ;; esac
export PYTHONPATH="$HERE${PYTHONPATH:+$SEP$PYTHONPATH}"
export PYTHONIOENCODING=utf-8        # status marks (✅ ❌) on Windows consoles
exec "${PY[@]}" -m wizconnector.setup "$@"
