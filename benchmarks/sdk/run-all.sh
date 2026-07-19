#!/usr/bin/env bash
# run-all.sh — run each SDK's bench (or just the ones named) and collect the
# JSON records under results/sdk/<sdk>.json.
#
# Usage: run-all.sh [sdk1 sdk2 ...]   (default: all languages with a run.sh)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="${BENCH_RESULTS_DIR:-$HERE/../results}/sdk"
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
