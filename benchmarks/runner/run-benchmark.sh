#!/usr/bin/env bash
# run-benchmark.sh — orchestrate one or more benchmark cells.
#
# For each (target, profile, scenario) it:
#   1. sources the security profile env (profiles/<profile>.env)
#   2. sources the seed env (results/<target>.seed.env)
#   3. starts resource sampling for the target's containers
#   4. runs the k6 scenario (warm-up + measured + cooldown)
#   5. writes a k6 summary JSON, a resource CSV, and a run-metadata JSON
#      under results/<target>/<profile>/<scenario>.*
#
# Bring the target up first (just bench-up target=… profile=…) and seed it
# (just bench-seed target=…). This script does NOT manage container lifecycle —
# that separation lets you re-run scenarios against a warm target.
#
# Usage:
#   run-benchmark.sh --target axiam --profile p2-tls13 [--scenario all|<file>]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
RESULTS="${BENCH_RESULTS_DIR:-$BENCH/results}"

TARGET=axiam
PROFILE=p0-plaintext
SCENARIO=all
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --scenario) SCENARIO="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

# --- profile + seed wiring -------------------------------------------------
PROFILE_ENV="$BENCH/profiles/${PROFILE}.env"
[ -f "$PROFILE_ENV" ] || { echo "no such profile: $PROFILE_ENV" >&2; exit 1; }
# shellcheck disable=SC1090
source "$PROFILE_ENV"

SEED_ENV="$RESULTS/${TARGET}.seed.env"
if [ -f "$SEED_ENV" ]; then source "$SEED_ENV"; else
  echo "[run] WARN: no seed env ($SEED_ENV) — scenarios needing a tenant/client may fail"
fi

export BENCH_TARGET="$TARGET"
export BENCH_HOST="${BENCH_HOST:-localhost}"
# BENCH_PORT is set by the profile env (8090 plaintext, 8443 TLS).

# Scenario set
if [ "$SCENARIO" = "all" ]; then
  mapfile -t SCENARIOS < <(cd "$BENCH/scenarios" && ls ./*.js | sed 's#^\./##')
else
  SCENARIOS=("$SCENARIO")
fi

# gRPC authz scenarios are AXIAM-only; drop them for other targets.
filter_scenarios() {
  local out=()
  for s in "${SCENARIOS[@]}"; do
    if { [ "$s" = "authz_check_grpc.js" ] || [ "$s" = "authz_batch_grpc.js" ]; } && [ "$TARGET" != "axiam" ]; then
      echo "[run] skipping $s (AXIAM-only) for target $TARGET"; continue
    fi
    out+=("$s")
  done
  SCENARIOS=("${out[@]}")
}
filter_scenarios

command -v k6 >/dev/null || { echo "[run] k6 not installed — see https://k6.io/docs/get-started/installation/" >&2; exit 1; }

# Container name filter for the resource sampler (matches this target's stack).
RES_FILTER="bench-${TARGET}"
# Measured-window seconds (k6 measure stage) for sampling duration. Parse e.g. 120s.
DUR_S="$(echo "${BENCH_DURATION:-120s}" | sed 's/s$//')"
WARM_S="$(echo "${BENCH_WARMUP:-30s}" | sed 's/s$//')"
SAMPLE_INTERVAL="${BENCH_SAMPLE_INTERVAL:-1}"

K6_VER="$(k6 version 2>/dev/null | head -1)"
HOST_CPUS="$(nproc 2>/dev/null || echo unknown)"
HOST_MEM_MIB="$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo unknown)"

run_one() {
  local scenario="$1"
  local name="${scenario%.js}"
  local outdir="$RESULTS/$TARGET/$PROFILE"
  mkdir -p "$outdir"
  local k6sum="$outdir/$name.k6.json"
  local rescsv="$outdir/$name.res.csv"
  local meta="$outdir/$name.meta.json"

  echo "[run] === $TARGET / $PROFILE / $name ==="

  # Start the resource sampler for the measure window (skip the warm-up first).
  ( sleep "$WARM_S"; bash "$BENCH/resource/sampler.sh" "$RES_FILTER" "$rescsv" "$SAMPLE_INTERVAL" "$DUR_S" ) &
  local sampler_pid=$!

  # Run k6. summary-export gives end-of-test aggregated metrics as JSON.
  set +e
  ( cd "$BENCH/scenarios" && BENCH_PROTO_ROOT="$BENCH/../proto" \
      k6 run --quiet --summary-export "$k6sum" "$scenario" )
  local k6rc=$?
  set -e
  wait "$sampler_pid" 2>/dev/null || true

  # Write run metadata (joined by report.py).
  cat > "$meta" <<EOF
{
  "target": "$TARGET",
  "profile": "$PROFILE",
  "scenario": "$name",
  "k6_exit_code": $k6rc,
  "k6_version": "$K6_VER",
  "vus": ${BENCH_VUS:-50},
  "warmup": "${BENCH_WARMUP:-30s}",
  "duration": "${BENCH_DURATION:-120s}",
  "scheme": "${BENCH_SCHEME:-http}",
  "tls_min": "${BENCH_TLS_MIN:-}",
  "client_auth": "$([ -n "${BENCH_CLIENT_CERT:-}" ] && echo x509 || echo none)",
  "caps": { "cpus": "${BENCH_CPUS:-2}", "mem": "${BENCH_MEM:-1024m}" },
  "host": { "cpus": "$HOST_CPUS", "mem_mib": "$HOST_MEM_MIB" },
  "k6_summary_file": "$name.k6.json",
  "resource_csv": "$name.res.csv"
}
EOF
  echo "[run] wrote $k6sum, $rescsv, $meta"
}

for s in "${SCENARIOS[@]}"; do
  run_one "$s"
done

echo "[run] done. Aggregate with: python3 $HERE/report.py --results $RESULTS"
