#!/usr/bin/env bash
# run-all.sh — run each SDK's bench (or just the ones named) and collect the
# JSON records under results/sdk/<profile>/<sdk>.json.
#
# H8/E1.3: profile-scoped (not just results/sdk/<sdk>.json) so a p0 run and a
# p2 run can coexist on disk and both show up in the same collect.py/
# report.py table — a flat single-file-per-language layout meant "run at p0
# AND p2" (per the E1.3 acceptance) silently clobbered the earlier profile's
# record with the later one. collect.py's loader walks both this layout and
# the old flat one for backward compatibility with any results/ tree from
# before this change.
#
# Usage: run-all.sh [sdk1 sdk2 ...]   (default: all languages with a run.sh)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="${BENCH_RESULTS_DIR:-$HERE/../results}/sdk/${BENCH_PROFILE:-p0-plaintext}"
mkdir -p "$RESULTS"

# Source the seed env so SDK benches hit a provisioned tenant/client. Lives
# under .seed/ (client secrets kept out of the shareable results/ tree — see
# A7 in claude_dev/benchmark-improvement-plan.md); fall back to the old
# results/ location for a seed written before that move.
SEED_ENV="${BENCH_SEED_DIR:-$HERE/../.seed}/${BENCH_TARGET:-axiam}.seed.env"
LEGACY_SEED_ENV="${BENCH_RESULTS_DIR:-$HERE/../results}/${BENCH_TARGET:-axiam}.seed.env"
if [ -f "$SEED_ENV" ]; then
  source "$SEED_ENV"
elif [ -f "$LEGACY_SEED_ENV" ]; then
  source "$LEGACY_SEED_ENV"
fi

# H8: fail fast (naming the exact missing var) rather than let a language
# bench discover an empty/placeholder id later with a confusing error.
for var in BENCH_RESOURCE_ID BENCH_SUBJECT_ID BENCH_TENANT_SLUG BENCH_CLIENT_ID BENCH_CLIENT_SECRET; do
  if [ -z "${!var:-}" ]; then
    echo "[sdk] FATAL: $var is empty after sourcing $SEED_ENV — run 'just target=${BENCH_TARGET:-axiam} bench-seed' first (H8: seed env must reach the SDK bench)." >&2
    exit 1
  fi
done

if [ "$#" -gt 0 ]; then
  SDKS=("$@")
else
  mapfile -t SDKS < <(find "$HERE" -mindepth 2 -maxdepth 2 -name run.sh -printf '%h\n' | xargs -n1 basename | sort)
fi

for sdk in "${SDKS[@]}"; do
  run="$HERE/$sdk/run.sh"
  [ -f "$run" ] || { echo "[sdk] no run.sh for $sdk — skipping"; continue; }
  echo "[sdk] running $sdk bench"
  out="$RESULTS/$sdk.json"
  if bash "$run" > "$out" 2>"$RESULTS/$sdk.log"; then
    status=$(sed -n 's/.*"status": *"\([^"]*\)".*/\1/p' "$out" | head -1)
    echo "[sdk] $sdk -> $out (status=${status:-?})"
  else
    echo "[sdk] $sdk FAILED — see $RESULTS/$sdk.log"
  fi
done

echo "[sdk] collect with: python3 $HERE/collect.py --results ${BENCH_RESULTS_DIR:-$HERE/../results}"
