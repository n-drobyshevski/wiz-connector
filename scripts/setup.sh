#!/usr/bin/env bash
# Set up (or check with --doctor) wiz-connector in the repository you are in.
#   cd my-maven-repo && bash /path/to/wiz-connector/scripts/setup.sh [--help]
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m wizconnector.setup "$@"
