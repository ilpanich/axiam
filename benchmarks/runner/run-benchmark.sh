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
# Bring the target up first (just target=… profile=… bench-up) and seed it
# (just target=… bench-seed). This script does NOT manage container lifecycle —
# that separation lets you re-run scenarios against a warm target.
#
# Usage:
#   run-benchmark.sh --target axiam --profile p2-tls13 [--scenario all|<file>]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
RESULTS="${BENCH_RESULTS_DIR:-$BENCH/results}"
SEED_DIR="${BENCH_SEED_DIR:-$BENCH/.seed}"

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

# Seed env (client secrets/passwords) lives under .seed/, NOT results/ — see A7
# in claude_dev/benchmark-improvement-plan.md and docs/methodology.md. Fall back
# to the old results/ location for one release cycle so a stale seed from before
# this change still works without a re-seed.
SEED_ENV="$SEED_DIR/${TARGET}.seed.env"
LEGACY_SEED_ENV="$RESULTS/${TARGET}.seed.env"
if [ -f "$SEED_ENV" ]; then
  source "$SEED_ENV"
elif [ -f "$LEGACY_SEED_ENV" ]; then
  echo "[run] WARN: using legacy seed env at $LEGACY_SEED_ENV — re-run 'just target=$TARGET bench-seed' to move it under .seed/"
  source "$LEGACY_SEED_ENV"
else
  echo "[run] WARN: no seed env ($SEED_ENV) — scenarios needing a tenant/client may fail"
fi

# Refuse to start the k6 matrix without a passing post-seed smoke check for this
# target (runner/seed.sh writes results/<target>.seed.ok only after every
# scenario-critical flow — ROPC/login, client_credentials, introspect, refresh,
# userinfo, and for AXIAM a REST authz check — returned the expected status).
# This is what makes "deliberately break the seeded Keycloak client" refuse to
# run instead of burning a full k6 matrix on a wall of failed checks.
SEED_OK_MARKER="$RESULTS/${TARGET}.seed.ok"
if [ "${BENCH_SKIP_SEED_CHECK:-0}" != "1" ] && [ ! -f "$SEED_OK_MARKER" ]; then
  echo "[run] REFUSING to start: no seed-ok marker for target '$TARGET' ($SEED_OK_MARKER)." >&2
  echo "      Run 'just target=$TARGET bench-seed' first — it seeds the target AND" >&2
  echo "      smoke-checks every scenario-critical flow before writing this marker." >&2
  echo "      (Override only for debugging: BENCH_SKIP_SEED_CHECK=1.)" >&2
  exit 1
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

# The authz scenarios (gRPC and REST) are AXIAM-only; drop them for other targets.
AXIAM_ONLY_SCENARIOS="authz_check_grpc.js authz_batch_grpc.js authz_check_rest.js authz_batch_rest.js"

# OAuth2 client-flow scenarios need a seeded confidential client (and, ideally, a
# configured OIDC issuer). Skip them when OAuth2 isn't set up so a missing OAuth2
# config doesn't fail the run — either the operator opts out (BENCH_SKIP_OAUTH2=1)
# or the axiam client wasn't seeded (empty BENCH_CLIENT_SECRET). `just bench-up`
# now configures OAuth2 and seed.sh provisions the client, so by default none are
# skipped. jwks_fetch is intentionally excluded — it needs no client.
OAUTH2_SCENARIOS="oauth2_client_credentials.js token_introspection.js token_refresh.js userinfo.js"
skip_oauth2() {
  [ "${BENCH_SKIP_OAUTH2:-0}" = "1" ] && return 0
  [ "$TARGET" = "axiam" ] && [ -z "${BENCH_CLIENT_SECRET:-}" ] && return 0
  return 1
}

filter_scenarios() {
  local out=()
  for s in "${SCENARIOS[@]}"; do
    if [ "$TARGET" != "axiam" ] && [[ " $AXIAM_ONLY_SCENARIOS " == *" $s "* ]]; then
      echo "[run] skipping $s (AXIAM-only) for target $TARGET"; continue
    fi
    if [[ " $OAUTH2_SCENARIOS " == *" $s "* ]] && skip_oauth2; then
      echo "[run] skipping $s (OAuth2 not configured — seed a client or unset BENCH_SKIP_OAUTH2)"; continue
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

# Rate-limit posture, read from the RUNNING server container so meta.json records
# what actually ran (not what someone intended). Prefer the AXIAM_BENCH_RL_POSTURE
# marker the compose sets; fall back to inferring from the effective login limit;
# competitors have no AXIAM per-IP limiter, so they are "n/a". report.py refuses
# to compare cells whose postures aren't mutually comparable.
detect_rl_posture() {
  [ "$TARGET" = "axiam" ] || { echo "n/a"; return; }
  command -v docker >/dev/null 2>&1 || { echo "unknown"; return; }
  local env_dump marker limit
  env_dump="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "bench-${TARGET}-server" 2>/dev/null)" || { echo "unknown"; return; }
  marker="$(printf '%s\n' "$env_dump" | sed -n 's/^AXIAM_BENCH_RL_POSTURE=//p' | head -1)"
  if [ -n "$marker" ]; then echo "$marker"; return; fi
  limit="$(printf '%s\n' "$env_dump" | sed -n 's/^AXIAM__RATE_LIMIT__LOGIN_PER_MIN=//p' | head -1)"
  if [ -n "$limit" ] && [ "$limit" -ge 100000 ] 2>/dev/null; then echo "neutralized"
  elif [ -n "$limit" ]; then echo "prod"
  else echo "unknown"; fi
}
RL_POSTURE="$(detect_rl_posture)"
echo "[run] rate-limit posture: $RL_POSTURE"

# --- Reproducibility metadata (methodology.md §7 / A4) ----------------------
# Host facts that don't change across scenarios in this run — gathered once.
HOST_KERNEL="$(uname -r 2>/dev/null || echo unknown)"
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
CPU_MODEL="$(awk -F: '/model name/ {gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null)"
[ -n "$CPU_MODEL" ] || CPU_MODEL="unknown"
CPU_GOVERNOR="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
BATCH_SIZE="${BENCH_BATCH_SIZE:-5}"

# Naive JSON string escaping (backslash + double-quote only — sufficient for
# the plain ASCII strings embedded here: image names, kernel/cpu strings).
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# Container names that make up each target's stack, with a role used to look
# up its CPU cap default (mirrors targets/<name>/docker-compose.yml — see A4/A5
# in claude_dev/benchmark-improvement-plan.md). The tls-edge container only
# exists for AXIAM under a non-native TLS profile (p1/p3); docker inspect
# simply finds nothing for containers that aren't running and is skipped.
container_specs_for_target() {
  case "$TARGET" in
    axiam)
      cat <<EOF
bench-axiam-server server
bench-axiam-tls edge
bench-axiam-surrealdb db
bench-axiam-rabbitmq mq
EOF
      ;;
    keycloak)
      cat <<EOF
bench-keycloak server
bench-keycloak-postgres db
EOF
      ;;
    zitadel)
      cat <<EOF
bench-zitadel server
bench-zitadel-postgres db
EOF
      ;;
  esac
}

# Default CPU cap per role, matching each target's docker-compose.yml default
# (report.py's bottleneck attribution falls back to these when a container's
# actual cap env var wasn't exported into this shell).
role_default_cpu_cap() {
  case "$1" in
    server) echo "${BENCH_CPUS:-2}" ;;
    db)     echo "${BENCH_DB_CPUS:-2}" ;;
    mq)     echo "${BENCH_MQ_CPUS:-1}" ;;
    edge)   echo "${BENCH_EDGE_CPUS:-1}" ;;
    *)      echo "2" ;;
  esac
}

# Emits the JSON array for meta.json's "containers" field: one entry per
# running container in this target's stack, with image, image_digest (from
# `docker inspect`), role, and its CPU cap. The cap is read straight off the
# running container (`HostConfig.NanoCpus`, what `--cpus`/compose `cpus:`
# actually sets) rather than trusted from this shell's env — BENCH_DB_CPUS/
# BENCH_MQ_CPUS/BENCH_EDGE_CPUS are only exported inside `just bench-up`'s own
# subshell, so a separate `bench-run` invocation would otherwise silently miss
# a non-default cap the operator set at bench-up time. Falls back to the
# compose-file default only if NanoCpus is unset (no `--cpus` was applied).
containers_json() {
  local first=1 line cname role img dig cap nanocpus
  echo -n "["
  while read -r line; do
    [ -z "$line" ] && continue
    cname="${line%% *}"; role="${line#* }"
    docker inspect "$cname" >/dev/null 2>&1 || continue
    img="$(docker inspect --format '{{.Config.Image}}' "$cname" 2>/dev/null || echo unknown)"
    dig="$(docker inspect --format '{{index .RepoDigests 0}}' "$cname" 2>/dev/null || echo '')"
    [ -z "$dig" ] && dig="unknown"
    nanocpus="$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$cname" 2>/dev/null || echo 0)"
    if [ -n "$nanocpus" ] && [ "$nanocpus" != "0" ]; then
      cap="$(awk -v n="$nanocpus" 'BEGIN{printf "%.3f", n/1000000000}')"
    else
      cap="$(role_default_cpu_cap "$role")"
    fi
    [ "$first" -eq 1 ] || echo -n ","
    first=0
    printf '{"name":"%s","role":"%s","image":"%s","image_digest":"%s","cpu_cap":%s}' \
      "$(json_escape "$cname")" "$role" "$(json_escape "$img")" "$(json_escape "$dig")" "$cap"
  done < <(container_specs_for_target)
  echo -n "]"
}

run_one() {
  local scenario="$1"
  local name="${scenario%.js}"
  local outdir="$RESULTS/$TARGET/$PROFILE"
  mkdir -p "$outdir"
  local k6sum="$outdir/$name.k6.json"
  local rescsv="$outdir/$name.res.csv"
  local hostcsv="$outdir/$name.host.csv"
  local meta="$outdir/$name.meta.json"

  echo "[run] === $TARGET / $PROFILE / $name ==="

  local scenario_sha256
  scenario_sha256="$(sha256sum "$BENCH/scenarios/$scenario" 2>/dev/null | awk '{print $1}')"
  [ -n "$scenario_sha256" ] || scenario_sha256="unknown"

  # Start the resource + host-telemetry samplers for the measure window (skip
  # the warm-up first) — both write CSVs the report joins against the k6
  # summary (docs/methodology.md §5/§7, A6).
  ( sleep "$WARM_S"; bash "$BENCH/resource/sampler.sh" "$RES_FILTER" "$rescsv" "$SAMPLE_INTERVAL" "$DUR_S" ) &
  local sampler_pid=$!
  ( sleep "$WARM_S"; bash "$BENCH/resource/host-sampler.sh" "$hostcsv" "$SAMPLE_INTERVAL" "$DUR_S" ) &
  local host_sampler_pid=$!

  # Run k6. summary-export gives end-of-test aggregated metrics as JSON.
  set +e
  ( cd "$BENCH/scenarios" && BENCH_PROTO_ROOT="$BENCH/../proto" \
      k6 run --quiet --summary-export "$k6sum" "$scenario" )
  local k6rc=$?
  set -e
  wait "$sampler_pid" 2>/dev/null || true
  wait "$host_sampler_pid" 2>/dev/null || true

  # k6_cpu_cores_avg over the measure window, straight from the host.csv this
  # run just wrote (methodology §7 / A4). Skip the header line; tolerate a
  # missing/empty file (e.g. host-sampler.sh not executable on this host).
  local k6_cpu_cores_avg="0"
  if [ -f "$hostcsv" ]; then
    k6_cpu_cores_avg="$(awk -F, 'NR>1 && $6!="" {s+=$6; n++} END{if(n>0) printf "%.3f", s/n; else print 0}' "$hostcsv")"
  fi

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
  "rate_limits": "$RL_POSTURE",
  "caps": { "cpus": "${BENCH_CPUS:-2}", "mem": "${BENCH_MEM:-1024m}" },
  "host": { "cpus": "$HOST_CPUS", "mem_mib": "$HOST_MEM_MIB" },
  "k6_summary_file": "$name.k6.json",
  "resource_csv": "$name.res.csv",
  "host_csv": "$name.host.csv",
  "scenario_sha256": "$scenario_sha256",
  "batch_size": $BATCH_SIZE,
  "host_kernel": "$(json_escape "$HOST_KERNEL")",
  "docker_version": "$(json_escape "$DOCKER_VERSION")",
  "cpu_model": "$(json_escape "$CPU_MODEL")",
  "cpu_governor": "$(json_escape "$CPU_GOVERNOR")",
  "k6_cpu_cores_avg": $k6_cpu_cores_avg,
  "containers": $(containers_json)
}
EOF
  echo "[run] wrote $k6sum, $rescsv, $hostcsv, $meta"
}

for s in "${SCENARIOS[@]}"; do
  run_one "$s"
done

echo "[run] done. Aggregate with: python3 $HERE/report.py --results $RESULTS"
