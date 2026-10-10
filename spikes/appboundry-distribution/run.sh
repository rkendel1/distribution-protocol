#!/usr/bin/env bash
# Reproduce every result in SPIKE-RESULTS.md.
#
#   APPBOUNDRY_DIR=/path/to/appboundry SYNAPSE_DIR=/path/to/synapse ./run.sh
#
# Requirements: an AppBoundry checkout with `pnpm install` done (its vitest is used
# so AppBoundry's TypeScript sources load exactly as its own tests load them), a
# Synapse checkout, Node 18.17+ and a distribution-protocol checkout (this one).
# Nothing in AppBoundry or Synapse is modified.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DP="$(cd "$HERE/../.." && pwd)"
export APPBOUNDRY_DIR="${APPBOUNDRY_DIR:-/home/user/appboundry}"
export SYNAPSE_DIR="${SYNAPSE_DIR:-/home/user/synapse}"
VITEST="$APPBOUNDRY_DIR/node_modules/.bin/vitest"
OUT="$HERE/results"; mkdir -p "$OUT"
status=0

{
  echo "date:                  $(date -u +%FT%TZ)"
  echo "node:                  $(node -v)"
  echo "distribution-protocol: $(git -C "$DP" rev-parse HEAD)  ($(git -C "$DP" log -1 --format=%s))"
  echo "appboundry:            $(git -C "$APPBOUNDRY_DIR" rev-parse HEAD)  branch $(git -C "$APPBOUNDRY_DIR" branch --show-current)"
  echo "synapse:               $(git -C "$SYNAPSE_DIR" rev-parse HEAD)  branch $(git -C "$SYNAPSE_DIR" branch --show-current)"
  echo "appboundry worktree:   $(git -C "$APPBOUNDRY_DIR" status --porcelain | wc -l) modified/untracked files (must be 0)"
  echo "synapse worktree:      $(git -C "$SYNAPSE_DIR" status --porcelain | wc -l) modified/untracked files (must be 0)"
} | tee "$OUT/environment.txt"

echo; echo "== 1. spike tests (cross-repository)"
"$VITEST" run --config "$HERE/vitest.config.mjs" --root "$HERE" --reporter=verbose > "$OUT/spike.txt" 2>&1 || status=1
grep -E "Test Files|Tests " "$OUT/spike.txt"

echo; echo "== 1b. calling-ABI survey of every .wasm in AppBoundry and Synapse (static; nothing executed)"
{ node "$HERE/survey-abi.mjs" "$APPBOUNDRY_DIR"; echo; node "$HERE/survey-abi.mjs" "$SYNAPSE_DIR"; } | tee "$OUT/abi-survey.txt"

echo; echo "== 2. AppBoundry's own existing tests for the paths the spike relies on"
(cd "$APPBOUNDRY_DIR" && "$VITEST" run --reporter=verbose \
  packages/appboundry/test/pr204-appboundry-package.test.ts \
  packages/appboundry/test/pr206-artifact-to-platform-compatibility.test.ts \
  packages/appboundry/test/pr235-capability-composition-runtime.test.ts \
  packages/sdk/test/pr18-application-package.test.ts \
  packages/core/test/pr50-application-host-boundary.test.ts \
  packages/cli/test/application-conformance.test.ts) > "$OUT/appboundry-existing.txt" 2>&1 || status=1
grep -E "Test Files|Tests " "$OUT/appboundry-existing.txt"

echo; echo "== 3. distribution-protocol's own existing tests for the paths the spike relies on"
(cd "$DP" && node --test \
  packages/cli/src/http-e2e.test.mjs \
  packages/cli/src/auth-e2e.test.mjs \
  packages/conformance/src/artifact-http.test.mjs \
  packages/conformance/src/registry-auth.test.mjs \
  packages/conformance/src/acquire-stream.test.mjs) > "$OUT/dp-existing.txt" 2>&1 || status=1
grep -E "^# (tests|pass|fail)" "$OUT/dp-existing.txt"

echo; echo "== 4. AppBoundry build (to document the pnpm build state on this commit)"
(cd "$APPBOUNDRY_DIR" && pnpm build) > "$OUT/appboundry-build.txt" 2>&1; echo "pnpm build exit code: $?  (see results/appboundry-build.txt)"
git -C "$APPBOUNDRY_DIR" status --porcelain | wc -l | xargs echo "appboundry worktree changes after run (must be 0):"

exit $status
