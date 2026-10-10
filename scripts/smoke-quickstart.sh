#!/usr/bin/env bash
# Run the README quick start exactly as written.
#
# The commands between the quickstart markers in README.md are extracted and
# executed, so the documented flow cannot drift from what the code does. Run
# from anywhere; it needs `npm install` to have been done and a free port
# (override with PORT=...).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$(mktemp)"
trap 'rm -f "$SCRIPT"' EXIT

# If any step fails, do not leave the background registry running.
echo "trap 'kill \$(jobs -p) 2>/dev/null || true' EXIT" > "$SCRIPT"
awk '/<!-- quickstart:start -->/{on=1; next} /<!-- quickstart:end -->/{on=0} on' "$ROOT/README.md" \
  | sed '/^```/d' >> "$SCRIPT"

[ "$(wc -l < "$SCRIPT")" -gt 1 ] || { echo "no quick start found in README.md" >&2; exit 1; }

cd "$ROOT"
bash -euo pipefail "$SCRIPT"
echo "quick start OK"
