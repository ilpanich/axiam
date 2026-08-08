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
#   run-benchmark.sh --target axiam --profile p2-tls13 --dry-run
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
SEED_DIR="${BENCH_SEED_DIR:-$BENCH/.seed}"

TARGET=axiam
PROFILE=p0-plaintext
SCENARIO=all
DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --scenario) SCENARIO="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

# --- dry-run mode ----------------------------------------------------------
# A full `bench-matrix` pass is hours long, and a break that only shows up in
# the k6 client contract (a scenario whose setup() can't log in, a seeded
# client the target rejects, a gRPC dial against the wrong port, a profile
# whose certs don't load, a cell silently skipped by filter_scenarios) does not
# announce itself until that cell's turn comes round — potentially an hour or
# more in. Dry-run runs the EXACT same code path (same profile env, same seed
# env, same scenario filter + rotation, same k6 invocation, same samplers,
# same meta.json) with the measurement window collapsed to a few seconds, and
# grades each cell on whether the k6 client could connect, send its request and
# get the RIGHT answer back — not on how fast it was.
#
# What changes vs a measured run, and why:
#   - load model shrunk to BENCH_DRY_VUS x BENCH_DRY_DURATION (2 VUs / 5s).
#     Enough VUs to exercise the per-VU cookie jar / gRPC dial, short enough
#     that a full matrix dry run finishes in minutes.
#   - the p95 latency threshold is relaxed to BENCH_DRY_MAX_P95_MS (30s). A dry
#     run deliberately skips the post-seed settle gate (below), so it measures
#     INSIDE the transient window where p95 legitimately blows past the 2000ms
#     production gate — failing a dry run on that would be a false alarm about
#     the one thing a dry run is not checking. Correctness stays strict: the
#     per-cell verdict below fails on a SINGLE failed check.
#   - the settle gate is skipped (it can burn up to BENCH_SETTLE_TIMEOUT_SECS =
#     600s per cell doing nothing but waiting) and the inter-cell pause is 0.
#   - results land under results/dry-run/ by default, so a dry run never mixes
#     5-second cells into the tree `bench-report` aggregates.
# Every one of these is still overridable, so `BENCH_SETTLE=1 ... --dry-run`
# remains possible when you want to rehearse the gate itself.
if [ "$DRY_RUN" = "1" ]; then
  export BENCH_VUS="${BENCH_DRY_VUS:-2}"
  export BENCH_WARMUP="${BENCH_DRY_WARMUP:-2s}"
  export BENCH_DURATION="${BENCH_DRY_DURATION:-5s}"
  export BENCH_COOLDOWN="${BENCH_DRY_COOLDOWN:-1s}"
  export BENCH_MAX_P95_MS="${BENCH_DRY_MAX_P95_MS:-30000}"
  BENCH_SETTLE="${BENCH_SETTLE:-0}"
  BENCH_CELL_PAUSE="${BENCH_CELL_PAUSE:-0}"
  RESULTS="${BENCH_RESULTS_DIR:-$BENCH/results/dry-run}"
else
  RESULTS="${BENCH_RESULTS_DIR:-$BENCH/results}"
fi

# H6: absolutize RESULTS (relative to the CALLER's cwd, which is what a relative
# BENCH_RESULTS_DIR means to whoever set it). k6 is invoked from a different
# directory below, so a relative path made it write .res.csv/.host.csv/.meta.json
# to the right place while `--summary-export` silently failed with "no such file
# or directory" — losing the ONE artifact report.py actually reads, and leaving a
# cell that looks present but has no k6 summary. Fail-fast on an
# unresolvable path rather than repeating that.
case "$RESULTS" in
  /*) : ;;
  *)  mkdir -p "$RESULTS" && RESULTS="$(cd "$RESULTS" && pwd)" \
        || { echo "[run] cannot resolve BENCH_RESULTS_DIR='$RESULTS'" >&2; exit 1; } ;;
esac

# Append-only verdict ledger for dry runs: one TSV row per scenario
# (target, profile, scenario, verdict, detail). The justfile's `bench-dry-run`
# points every cell at ONE file via BENCH_DRY_RUN_TSV and appends its own
# bench-up/bench-seed rows to it, so the end-of-matrix table covers stack
# bring-up and seeding as well as the k6 cells.
DRY_TSV="${BENCH_DRY_RUN_TSV:-$RESULTS/dry-run.tsv}"
DRY_FAILURES=0
record_dry() {
  [ "$DRY_RUN" = "1" ] || return 0
  mkdir -p "$(dirname "$DRY_TSV")"
  printf '%s\t%s\t%s\t%s\t%s\n' "$TARGET" "$PROFILE" "$1" "$2" "$3" >> "$DRY_TSV"
  [ "$2" = "FAIL" ] && DRY_FAILURES=$((DRY_FAILURES + 1))
  return 0
}

# --- profile + seed wiring -------------------------------------------------
# Anchor the cert dir to an ABSOLUTE path before sourcing the profile. The
# profile derives BENCH_CLIENT_CERT/KEY/CA_CERT from ${BENCH_CERTS_DIR:-profiles/certs},
# a path relative to the benchmarks root. But run_one() launches k6 with
# CWD=$BENCH/scenarios, so a relative cert path resolves to the non-existent
# $BENCH/scenarios/profiles/certs/... and k6's open() fails at init time
# ("can't find the client certificate") — the p3-mtls instant-fail. Making the
# dir absolute here fixes every consumer at once: k6's tlsAuth open(), seed.sh's
# curl --cert, and the justfile readiness probe all resolve the same files
# regardless of their working directory.
export BENCH_CERTS_DIR="${BENCH_CERTS_DIR:-$BENCH/profiles/certs}"
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

# E3/J12: the fixture-scale record written by runner/bulk-seed.sh. A cell run
# against a 10x fixture is NOT comparable to one run against the base fixture,
# so the scale has to travel with the measurement rather than with whoever
# remembers which command they ran. Absent file = base fixture (scale 1).
BULK_ENV="$SEED_DIR/${TARGET}.bulk.env"
if [ -f "$BULK_ENV" ]; then
  source "$BULK_ENV"
  echo "[run] fixture scale: ${BENCH_SEED_SCALE}x (${BENCH_SEED_USERS_TOTAL:-?} users, ${BENCH_SEED_RESOURCES_TOTAL:-?} resources, depth ${BENCH_SEED_DEPTH:-?}, deny_ratio ${BENCH_SEED_DENY_RATIO:-0}) — see runner/bulk-seed.sh"
fi

# Refuse to start the k6 matrix without a passing post-seed smoke check for this
# target (runner/seed.sh writes results/<target>.seed.ok only after every
# scenario-critical flow — ROPC/login, client_credentials, introspect, refresh,
# userinfo, and for AXIAM a REST authz check — returned the expected status).
# This is what makes "deliberately break the seeded Keycloak client" refuse to
# run instead of burning a full k6 matrix on a wall of failed checks.
SEED_OK_MARKER="$RESULTS/${TARGET}.seed.ok"
# A dry run defaults RESULTS to results/dry-run/, but a manual `bench-seed`
# writes its marker to the plain results/ root — so a standalone
# `just dry=1 bench-run` after an ordinary seed would otherwise be refused for
# a target that IS correctly seeded. Fall back to the root marker in dry-run
# mode only (`bench-dry-run` seeds with BENCH_RESULTS_DIR already pointed at
# the dry-run tree, so it finds the first path and never needs this).
if [ "$DRY_RUN" = "1" ] && [ ! -f "$SEED_OK_MARKER" ] && [ -f "$BENCH/results/${TARGET}.seed.ok" ]; then
  SEED_OK_MARKER="$BENCH/results/${TARGET}.seed.ok"
fi
if [ "${BENCH_SKIP_SEED_CHECK:-0}" != "1" ] && [ ! -f "$SEED_OK_MARKER" ]; then
  echo "[run] REFUSING to start: no seed-ok marker for target '$TARGET' ($SEED_OK_MARKER)." >&2
  echo "      Run 'just target=$TARGET bench-seed' first — it seeds the target AND" >&2
  echo "      smoke-checks every scenario-critical flow before writing this marker." >&2
  echo "      (Override only for debugging: BENCH_SKIP_SEED_CHECK=1.)" >&2
  record_dry "(seed-marker)" "FAIL" "no seed-ok marker at $SEED_OK_MARKER"
  exit 1
fi

export BENCH_TARGET="$TARGET"
export BENCH_HOST="${BENCH_HOST:-localhost}"

# BENCH_PORT is set by the profile env (8090 plaintext, 8443 TLS).

# G2: base URL for the post-seed settle gate's canary probes (same
# scheme/host/port the k6 scenarios below hit). Built here, once, since it's
# only used for the cheap out-of-band canary requests, never by k6 itself.
BASE="${BENCH_SCHEME:-http}://${BENCH_HOST}:${BENCH_PORT:-8090}"

# Scenario set
if [ "$SCENARIO" = "all" ]; then
  mapfile -t SCENARIOS < <(cd "$BENCH/scenarios" && ls ./*.js | sed 's#^\./##')
else
  SCENARIOS=("$SCENARIO")
fi

# The authz scenarios (gRPC and REST) are AXIAM-only; drop them for other targets.
# userinfo_grpc.js (axiam.v1.UserInfoService/GetUserInfo) is AXIAM's own gRPC
# identity read — the counterpart of Zitadel's zitadel_userinfo_grpc.js; it dials
# AXIAM's proto and has no equivalent on Keycloak, so it is AXIAM-only too. The
# two vendors' gRPC-userinfo scenarios pair up cross-vendor in report.py.
#
# Run-5 J1c added three more AXIAM-only entries. grpc_admin_validate.js and
# grpc_infra.js dial AXIAM's own gRPC surface (and, for the latter, a path
# AXIAM deliberately does not route — see that scenario's header). oauth2_revoke.js
# is REST but AXIAM-only for the same reason the authz REST scenarios are:
# it exists to exercise a specific AXIAM limiter family, not to compare
# vendors, and publishing its throughput against Keycloak/Zitadel would be
# comparing a deliberately throttled cell to an unthrottled one.
AXIAM_ONLY_SCENARIOS="authz_check_grpc.js authz_batch_grpc.js authz_check_rest.js authz_batch_rest.js userinfo_grpc.js grpc_admin_validate.js grpc_infra.js oauth2_revoke.js"

# D4: Zitadel's gRPC identity scenario (AuthService/GetMyUser, the gRPC
# counterpart of userinfo.js — see scenarios/zitadel_userinfo_grpc.js and
# scenarios/proto/zitadel/README.md) dials Zitadel's own vendored proto and
# has no equivalent on AXIAM or Keycloak; drop it for other targets, mirroring
# how AXIAM_ONLY_SCENARIOS is handled above.
ZITADEL_ONLY_SCENARIOS="zitadel_userinfo_grpc.js"

# OAuth2 client-flow scenarios need a seeded confidential client (and, ideally, a
# configured OIDC issuer). Skip them when OAuth2 isn't set up so a missing OAuth2
# config doesn't fail the run — either the operator opts out (BENCH_SKIP_OAUTH2=1)
# or the axiam client wasn't seeded (empty BENCH_CLIENT_SECRET). `just bench-up`
# now configures OAuth2 and seed.sh provisions the client, so by default none are
# skipped. jwks_fetch is intentionally excluded — it needs no client.
OAUTH2_SCENARIOS="oauth2_client_credentials.js token_introspection.js token_refresh.js userinfo.js oauth2_revoke.js"
skip_oauth2() {
  [ "${BENCH_SKIP_OAUTH2:-0}" = "1" ] && return 0
  [ "$TARGET" = "axiam" ] && [ -z "${BENCH_CLIENT_SECRET:-}" ] && return 0
  return 1
}

# Skips are recorded into the dry-run ledger too (as SKIP rows), not just
# echoed: "which cells does the matrix actually intend to run" is precisely the
# kind of thing you want confirmed up front. An OAuth2 skip in particular is
# usually NOT intentional — it means the confidential client wasn't seeded —
# and today that only surfaces as one line scrolling past mid-matrix.
filter_scenarios() {
  local out=()
  for s in "${SCENARIOS[@]}"; do
    if [ "$TARGET" != "axiam" ] && [[ " $AXIAM_ONLY_SCENARIOS " == *" $s "* ]]; then
      echo "[run] skipping $s (AXIAM-only) for target $TARGET"
      record_dry "${s%.js}" "SKIP" "AXIAM-only scenario, target is $TARGET (expected)"; continue
    fi
    if [ "$TARGET" != "zitadel" ] && [[ " $ZITADEL_ONLY_SCENARIOS " == *" $s "* ]]; then
      echo "[run] skipping $s (Zitadel-only) for target $TARGET"
      record_dry "${s%.js}" "SKIP" "Zitadel-only scenario, target is $TARGET (expected)"; continue
    fi
    if [[ " $OAUTH2_SCENARIOS " == *" $s "* ]] && skip_oauth2; then
      echo "[run] skipping $s (OAuth2 not configured — seed a client or unset BENCH_SKIP_OAUTH2)"
      record_dry "${s%.js}" "SKIP" "OAuth2 not configured — seed a client or unset BENCH_SKIP_OAUTH2"; continue
    fi
    # I16 (improvement-after-run4-benchmark.md §D): an explicit, operator-set
    # exclusion list — space-separated scenario filenames in
    # BENCH_SCENARIO_EXCLUDE — so a cell that needs a DIFFERENT container
    # envelope than the rest of the matrix (e.g. Keycloak's login cells
    # needing BENCH_MEM=4096m per the H7 diagnosis, while everything else
    # stays at the shared 2048 cap) can be split into its own `bench-up`/
    # `bench-run` pass without also re-running the whole matrix twice.
    # Unset by default (empty), so this is a no-op unless the operator
    # deliberately sets it.
    if [ -n "${BENCH_SCENARIO_EXCLUDE:-}" ] && [[ " ${BENCH_SCENARIO_EXCLUDE} " == *" $s "* ]]; then
      echo "[run] skipping $s (BENCH_SCENARIO_EXCLUDE)"
      record_dry "${s%.js}" "SKIP" "excluded via BENCH_SCENARIO_EXCLUDE (run separately, e.g. a different BENCH_MEM cap)"; continue
    fi
    out+=("$s")
  done
  SCENARIOS=("${out[@]}")
}
filter_scenarios

# G2 item 2: cell-order rotation. Run 3 found EVERY historical batch cell was
# corrupted because the matrix always ran scenarios in the same (alphabetical)
# order and the batch scenarios always landed as cell 1-2, right after seed —
# squarely inside the post-seed serialized-DB transient window (see the settle
# gate below and PRIVATE_BENCH_ANALYSIS.md §1). Rotating the EXECUTED order
# (i.e. after filter_scenarios, so it matches what actually runs and what
# cell_order_index below counts) by the run index means no scenario is
# systematically first across a median-of-N `bench-matrix` (repeat=N): run-1
# starts at scenario 1, run-2 at scenario 2, etc. — a left-rotation by
# (BENCH_RUN_INDEX - 1) mod N. Deterministic (pure function of run index +
# scenario count) and changes only the ORDER, never WHICH scenarios run.
# BENCH_RUN_INDEX is set by justfile's bench-matrix loop (BENCH_RUN_INDEX=$i,
# one per repeat pass); a manual single `bench-run` invocation (no matrix)
# defaults to 1 — no rotation, natural (alphabetical) order.
BENCH_RUN_INDEX="${BENCH_RUN_INDEX:-1}"
rotate_scenarios() {
  local n=${#SCENARIOS[@]} idx="$BENCH_RUN_INDEX" shift_by
  [ "$n" -gt 1 ] || return 0
  case "$idx" in ''|*[!0-9]*) idx=1 ;; esac
  shift_by=$(( (idx - 1) % n ))
  [ "$shift_by" -gt 0 ] || return 0
  SCENARIOS=( "${SCENARIOS[@]:$shift_by}" "${SCENARIOS[@]:0:$shift_by}" )
  echo "[run] cell-order rotation: run index $idx -> shifted scenario order by $shift_by (BENCH_RUN_INDEX)"
}
rotate_scenarios

command -v k6 >/dev/null || { echo "[run] k6 not installed — see https://k6.io/docs/get-started/installation/" >&2; exit 1; }

# Container name filter for the resource sampler (matches this target's stack).
RES_FILTER="bench-${TARGET}"
# Measured-window seconds (k6 measure stage) for sampling duration. Parse e.g. 120s.
DUR_S="$(echo "${BENCH_DURATION:-120s}" | sed 's/s$//')"
WARM_S="$(echo "${BENCH_WARMUP:-30s}" | sed 's/s$//')"
SAMPLE_INTERVAL="${BENCH_SAMPLE_INTERVAL:-1}"

# Every host fact below is embedded in meta.json as a JSON *string*, so it must
# be exactly one line. The idiom `$(cmd 2>/dev/null || echo unknown)` does NOT
# guarantee that: a command that prints an empty line to stdout and *then*
# fails runs the fallback too, yielding the literal two-line value
# "\nunknown". `docker version --format …` does exactly this when the daemon is
# unreachable — the raw newline lands mid-string and every consumer of that
# cell's meta.json dies with "Invalid control character", report.py included.
# Take the first non-empty line and default to "unknown" instead.
first_line() { printf '%s' "${1-}" | tr -d '\r' | awk 'NF {print; exit}'; }
host_fact() { local v; v="$(first_line "${1-}")"; printf '%s' "${v:-unknown}"; }

K6_VER="$(host_fact "$(k6 version 2>/dev/null | head -1)")"
HOST_CPUS="$(host_fact "$(nproc 2>/dev/null)")"
HOST_MEM_MIB="$(host_fact "$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)")"

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

# A5/J4: the login-bucket budget `token_refresh.js` paces its session-pool
# pre-mint inside.
#
# Under `rl=prod` the whole k6 fleet is ONE IP against a 10/min login ceiling.
# Run 5's rl-prod refresh cell burned that budget on re-logins and reported
# 4.4% errors (run 4: 2.4%) that were login throttling wearing a refresh
# cell's clothes. Pre-minting one session per VU, paced inside the bucket,
# means the cell measures the refresh path and any error it does report is the
# refresh path's.
#
# Read from the ceiling the RUNNING container actually has, not from a second
# copy of the number in this script -- the same reason `detect_rl_posture`
# above reads the container rather than trusting intent. 0 (the neutralized
# default) means no pacing, so every non-prod cell is untouched.
detect_login_per_min() {
  [ "$RL_POSTURE" = "prod" ] || { echo 0; return; }
  local limit
  limit="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "bench-${TARGET}-server" 2>/dev/null \
    | sed -n 's/^AXIAM__RATE_LIMIT__LOGIN_PER_MIN=//p' | head -1)"
  # Shipped `internet` default when the container leaves it unset.
  echo "${limit:-10}"
}
export BENCH_LOGIN_PER_MIN="${BENCH_LOGIN_PER_MIN:-$(detect_login_per_min)}"
echo "[run] refresh session-pool login budget: ${BENCH_LOGIN_PER_MIN}/min (0 = unpaced)"

# --- Reproducibility metadata (methodology.md §7 / A4) ----------------------
# A9: git commit of the working tree this run executed from. Recorded
# unconditionally (harmless when the AXIAM image was pulled prebuilt) but
# especially meaningful when the target was launched with `just build=1 …`
# (or BENCH_BUILD=1 / a `--build` compose invocation): a locally-built image
# has no useful RepoDigests/tag provenance of its own (see image_id fallback
# in containers_json below), so build_ref is what actually pins the source
# for that binary. $BENCH is this repo's benchmarks/ dir, so its parent is
# the repo root.
BUILD_REF="$(git -C "$BENCH/.." rev-parse HEAD 2>/dev/null || echo unknown)"

# I18 (improvement-after-run4-benchmark.md §D): preflight provenance check.
# Run 4's build_ref (6875e4b) was NOT an ancestor of origin/main — the image
# had been built from a fix branch before it was merged, so a run whose
# report implicitly claims "this measures main" was silently wrong; nothing
# caught it until manual review well after the matrix finished. Fail fast
# instead — before this cell's (or the whole matrix's) hours of k6 time are
# spent — unless build_ref resolves as an ancestor of origin/main.
# BENCH_ALLOW_UNMERGED_BUILD_REF=1 opts out for a DELIBERATE pre-merge
# validation run (e.g. exercising a fix branch before it lands); never the
# default, and any such run's output must be labeled non-canonical
# downstream. Skipped (not run) for target != axiam — build_ref is
# meaningful only for AXIAM's own working tree, never a competitor's.
if [ "$TARGET" = "axiam" ] && [ "$BUILD_REF" != "unknown" ] \
   && [ "${BENCH_ALLOW_UNMERGED_BUILD_REF:-0}" != "1" ]; then
  if git -C "$BENCH/.." rev-parse --verify -q origin/main >/dev/null 2>&1; then
    if ! git -C "$BENCH/.." merge-base --is-ancestor "$BUILD_REF" origin/main 2>/dev/null; then
      echo "[run] FATAL (A9/I18): build_ref $BUILD_REF is not an ancestor of origin/main — this run's image was built from unmerged work, not what a reader of the report would understand \"main\" to mean." >&2
      echo "[run]   Fix: merge/rebase the branch this was built from onto main and rebuild, OR re-run with BENCH_ALLOW_UNMERGED_BUILD_REF=1 for a deliberate pre-merge validation pass (label the result non-canonical in any report)." >&2
      exit 1
    fi
  else
    # C3 precedent: warn, never silently skip, when a check can't run —
    # a sandboxed/offline environment with no `origin` fetched is the
    # expected reason, not a hard failure (git fetch origin main fixes it).
    echo "[run] WARN (A9/I18): origin/main is not resolvable locally (run 'git fetch origin main' first) — cannot verify build_ref's provenance against main; proceeding unchecked." >&2
  fi
fi

# Host facts that don't change across scenarios in this run — gathered once.
HOST_KERNEL="$(host_fact "$(uname -r 2>/dev/null)")"
DOCKER_VERSION="$(host_fact "$(docker version --format '{{.Server.Version}}' 2>/dev/null)")"
CPU_MODEL="$(host_fact "$(awk -F: '/model name/ {gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null)")"
CPU_GOVERNOR="$(host_fact "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)")"
BATCH_SIZE="${BENCH_BATCH_SIZE:-5}"

# C3: warn (never fail) when the governor isn't 'performance' — on laptop
# hardware, 'powersave'/'ondemand'/'schedutil' let the CPU idle down between
# k6 iterations and ramp back up mid-measurement, adding run-to-run variance
# that the A6 host telemetry (mhz_avg / clock_variance) can catch after the
# fact but can't prevent. See "Running on a laptop" in docs/methodology.md.
if [ "$CPU_GOVERNOR" != "performance" ] && [ "$CPU_GOVERNOR" != "unknown" ]; then
  echo "[run] WARN: CPU governor is '$CPU_GOVERNOR', not 'performance' — this can add clock-scaling variance to the run. Fix: sudo cpupower frequency-set -g performance (see docs/methodology.md 'Running on a laptop')." >&2
fi

# C3: idle gap between cells (default 60s) so heat dissipates and the
# previous cell's allocations/caches settle before the next measurement
# starts — set BENCH_CELL_PAUSE=0 to disable.
CELL_PAUSE="${BENCH_CELL_PAUSE:-60}"

# JSON string escaping for the plain ASCII strings embedded here: image names,
# kernel/cpu strings, and the AXIAM__* env dump. Backslash and double-quote
# first, then the control characters that would otherwise be emitted raw inside
# a JSON string and make the whole meta.json unparseable — newline especially,
# since axiam_env_json() feeds this arbitrary container env values.
json_escape() {
  printf '%s' "${1-}" \
    | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' \
    | awk 'NR>1 { printf "\\n" } { printf "%s", $0 }'
}

# --- H1: post-seed settle gate v2 (concurrent burst probe) ------------------
# Run 3 found a ~5-7 min window right after `bench-seed` where the AXIAM stack
# serves everything at ~45 req/s with SurrealDB pinned at ~1 core (~22 ms
# serialized unit), then spontaneously recovers — see
# claude_dev/postseed-transient-investigation.md and
# PRIVATE_BENCH_ANALYSIS.md §1. Because the matrix always ran scenarios in the
# same order, this window silently corrupted every "first cell after seed"
# ever measured.
#
# G2's original gate (`canary_probe()`/`settle_gate()`, superseded below) sent
# ONE request per second and required BENCH_SETTLE_STABLE_SECS consecutive
# ticks under BENCH_SETTLE_MAX_MS. Measured result: it passed in ~34s, deep
# inside the ~6-minute clamp. The reason is structural, not a threshold bug:
# the clamp is a CONCURRENCY ceiling (~44 ops/s observed in-window vs ~730
# ops/s settled), not a per-request latency problem — the ~22ms serialized
# unit IS fast at 1 request/second whether the server can sustain 44 ops/s or
# 730 ops/s. A serial canary can never see the difference; only asking for
# more concurrent throughput than the clamp allows can. H1 replaces it with a
# short CONCURRENT burst probe (curl-parallel, kept out of the gate's own k6
# usage so the gate has no k6-scenario dependency): BENCH_SETTLE_BURST_VUS
# concurrent closed-loop workers hammer the same clamp-sensitive endpoint
# (AXIAM: POST /api/v1/authz/check, authenticated as the seeded bench user)
# for BENCH_SETTLE_BURST_SECS seconds and the gate requires either
# BENCH_SETTLE_PROBE_THR ops/s or better, OR p50 latency under
# BENCH_SETTLE_PROBE_P50_MS ms, UNDER THAT CONCURRENCY. In-window measured
# ~44 ops/s, settled ~730-750 ops/s — the 400 ops/s default threshold sits far
# from both, so there is no realistic false pass/fail at the boundary. See
# "Post-seed settle gate v2" in docs/methodology.md for the full writeup.
BENCH_SETTLE="${BENCH_SETTLE:-1}"                                # 0 to skip entirely (quick manual runs)
BENCH_SETTLE_BURST_VUS="${BENCH_SETTLE_BURST_VUS:-20}"            # concurrent probe workers
BENCH_SETTLE_BURST_SECS="${BENCH_SETTLE_BURST_SECS:-15}"          # seconds each probe attempt runs
BENCH_SETTLE_PROBE_THR="${BENCH_SETTLE_PROBE_THR:-400}"           # ops/s pass threshold (OR'd with p50 below)
BENCH_SETTLE_PROBE_P50_MS="${BENCH_SETTLE_PROBE_P50_MS:-150}"     # p50-under-load pass threshold (ms)
BENCH_SETTLE_RETRY_SECS="${BENCH_SETTLE_RETRY_SECS:-30}"          # gap between failed probe attempts
BENCH_SETTLE_TIMEOUT_SECS="${BENCH_SETTLE_TIMEOUT_SECS:-600}"     # hard cap, then warn + proceed
BENCH_SETTLE_DRAIN_SECS="${BENCH_SETTLE_DRAIN_SECS:-5}"           # post-burst drain pause (see settle_gate() tail)
# Legacy G2 tunables — no longer consulted by the v2 burst probe (kept so a
# script exporting them doesn't fail; BENCH_SETTLE_STABLE_SECS/MAX_MS were the
# serial-canary knobs this gate replaces).
BENCH_SETTLE_STABLE_SECS="${BENCH_SETTLE_STABLE_SECS:-30}"
BENCH_SETTLE_MAX_MS="${BENCH_SETTLE_MAX_MS:-100}"
SETTLE_WAIT_SECS=0        # recorded in every cell's meta.json this run produces
SETTLE_TIMEOUT_HIT=0      # 1 -> meta.json's settle_timeout: true
SETTLE_PROBE_THR_USED="$BENCH_SETTLE_PROBE_THR"  # recorded in meta.json as settle_probe_thr

_CANARY_JAR=""

# p3-mtls: the server REQUIRES a verified client cert on the REST surface, so
# every probe request needs one exactly like seed.sh's `_CURL_MTLS` and k6's
# `tlsAuth`. Without it the TLS handshake is rejected before any HTTP request
# exists: curl writes `000` for http_code, burst_probe() counts zero OK
# samples, and the gate reports "0.0 ops/s, p50 999999ms, n=0" every attempt
# until it burns the full BENCH_SETTLE_TIMEOUT_SECS — a hang that looks like a
# never-clearing clamp but is really an auth-layer failure. BENCH_CLIENT_CERT/
# KEY come from the profile env sourced above, already absolutized via
# BENCH_CERTS_DIR. Empty for p0/p1/p2, where the array expands to nothing.
_SETTLE_CURL_MTLS=()
if [ -n "${BENCH_CLIENT_CERT:-}" ] && [ -n "${BENCH_CLIENT_KEY:-}" ]; then
  _SETTLE_CURL_MTLS=(--cert "$BENCH_CLIENT_CERT" --key "$BENCH_CLIENT_KEY")
fi

# Lazily logs in once (as the seeded bench user) and reuses the cookie jar +
# CSRF token for every probe tick thereafter — a fresh login per burst would
# itself be an expensive, different signal from the endpoint under test.
_ensure_axiam_session() {
  [ -s "$_CANARY_JAR" ] && return 0
  _CANARY_JAR="$(mktemp)"
  if [ -n "${BENCH_USERNAME:-}" ] && [ -n "${BENCH_PASSWORD:-}" ] && [ -n "${BENCH_ORG_SLUG:-}" ]; then
    curl -sSk --max-time 5 "${_SETTLE_CURL_MTLS[@]}" -c "$_CANARY_JAR" -o /dev/null -X POST "$BASE/api/v1/auth/login" \
      -H "Content-Type: application/json" \
      -d "{\"org_slug\":\"${BENCH_ORG_SLUG}\",\"tenant_slug\":\"${BENCH_TENANT_SLUG:-default}\",\"username_or_email\":\"${BENCH_USERNAME}\",\"password\":\"${BENCH_PASSWORD}\"}" \
      2>/dev/null || true
  fi
}

# Runs for up to $1 seconds hammering the clamp-sensitive endpoint as fast as
# it can (closed-loop, no think time — this is deliberately a concurrency
# probe, not a steady-rate one) and appends one "<http_code>\t<time_total_s>"
# line per completed request to file $2. Never errors the caller: a
# connection failure just yields fewer/no lines, which fails the threshold
# check in burst_probe() below rather than aborting the gate.
_burst_worker() {
  local secs="$1" outfile="$2" deadline
  deadline=$(( $(date +%s) + secs ))
  if [ "$TARGET" = "axiam" ] && [ -s "$_CANARY_JAR" ] && [ -n "${BENCH_RESOURCE_ID:-}" ] \
     && awk -F'\t' '$6=="axiam_csrf"{f=1} END{exit !f}' "$_CANARY_JAR" 2>/dev/null; then
    local csrf; csrf="$(awk -F'\t' '$6=="axiam_csrf"{v=$7} END{print v}' "$_CANARY_JAR")"
    while [ "$(date +%s)" -lt "$deadline" ]; do
      curl -sSk --max-time 5 "${_SETTLE_CURL_MTLS[@]}" -b "$_CANARY_JAR" -o /dev/null -w '%{http_code}\t%{time_total}\n' \
        -X POST "$BASE/api/v1/authz/check" -H "Content-Type: application/json" \
        -H "X-CSRF-Token: $csrf" -d "{\"action\":\"read\",\"resource_id\":\"${BENCH_RESOURCE_ID}\"}" \
        2>/dev/null >> "$outfile"
    done
    return 0
  fi
  # Fallback (no seeded authz session on axiam, or a non-axiam target): burst
  # the same cheap target-appropriate endpoint the old canary used. Still a
  # real concurrency signal even when the clamp-specific endpoint is unusable.
  local url="$BASE/health"
  case "$TARGET" in
    keycloak) url="$BASE/realms/${BENCH_REALM:-bench}/protocol/openid-connect/certs" ;;
    zitadel)  url="$BASE/oauth/v2/keys" ;;
  esac
  while [ "$(date +%s)" -lt "$deadline" ]; do
    curl -sSk --max-time 5 "${_SETTLE_CURL_MTLS[@]}" -o /dev/null -w '%{http_code}\t%{time_total}\n' "$url" 2>/dev/null >> "$outfile"
  done
}

# Fires BENCH_SETTLE_BURST_VUS concurrent workers for BENCH_SETTLE_BURST_SECS
# seconds and echoes "<ops_per_sec> <p50_ms> <n_ok>". Always returns 0 (a
# probe that collects zero samples reports "0 999999 0", which simply fails
# the caller's threshold check rather than erroring the gate).
burst_probe() {
  [ "$TARGET" = "axiam" ] && _ensure_axiam_session
  local tmpdir; tmpdir="$(mktemp -d)"
  local vus="$BENCH_SETTLE_BURST_VUS" secs="$BENCH_SETTLE_BURST_SECS"
  local pids=() i t_start t_end elapsed
  t_start=$(date +%s.%N)
  for ((i = 0; i < vus; i++)); do
    _burst_worker "$secs" "$tmpdir/w$i.log" &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  t_end=$(date +%s.%N)
  elapsed="$(awk -v a="$t_start" -v b="$t_end" 'BEGIN{d=b-a; if(d<=0)d=0.001; printf "%.3f", d}')"

  cat "$tmpdir"/w*.log 2>/dev/null > "$tmpdir/all.log" || : > "$tmpdir/all.log"
  local n_ok ops_per_sec p50_ms
  n_ok="$(awk -F'\t' '$1!="000" && $1!="" {c++} END{print c+0}' "$tmpdir/all.log")"
  ops_per_sec="$(awk -v n="$n_ok" -v e="$elapsed" 'BEGIN{printf "%.1f", (e>0)?n/e:0}')"
  p50_ms="$(awk -F'\t' '$1!="000" && $1!="" {print $2*1000}' "$tmpdir/all.log" \
            | sort -n | awk '{a[NR]=$1} END{if(NR==0){print 999999}else{print a[int((NR+1)/2)]}}')"
  rm -rf "$tmpdir"
  echo "$ops_per_sec $p50_ms $n_ok"
}

# Repeats burst_probe() every BENCH_SETTLE_RETRY_SECS until it clears
# BENCH_SETTLE_PROBE_THR ops/s OR BENCH_SETTLE_PROBE_P50_MS p50 (under
# BENCH_SETTLE_BURST_VUS concurrency), or BENCH_SETTLE_TIMEOUT_SECS elapses
# (then warns and proceeds anyway, setting SETTLE_TIMEOUT_HIT=1). Sets
# SETTLE_WAIT_SECS to the wall-clock seconds actually waited either way.
settle_gate() {
  if [ "$BENCH_SETTLE" = "0" ]; then
    echo "[run] BENCH_SETTLE=0 — skipping post-seed settle gate"
    return 0
  fi
  echo "[run] post-seed settle gate v2: concurrent burst probe (${BENCH_SETTLE_BURST_VUS} workers x ${BENCH_SETTLE_BURST_SECS}s), needs >= ${BENCH_SETTLE_PROBE_THR} ops/s OR p50 < ${BENCH_SETTLE_PROBE_P50_MS}ms under that concurrency; retry every ${BENCH_SETTLE_RETRY_SECS}s; hard timeout ${BENCH_SETTLE_TIMEOUT_SECS}s"
  echo "      — a serial 1 rps canary cannot see this: the clamp is a CONCURRENCY ceiling (~44 ops/s in-window vs ~730-750 ops/s settled), not per-request latency (the ~22ms serialized unit is 'fast' at 1 rps either way). See 'Post-seed settle gate v2' in docs/methodology.md and PRIVATE_BENCH_ANALYSIS.md §1. Set BENCH_SETTLE=0 to skip."
  local start_ts now_ts result ops p50 nok attempt=0 zero_streak=0
  start_ts=$(date +%s)
  while :; do
    attempt=$((attempt + 1))
    result="$(burst_probe)"
    ops="$(awk '{print $1}' <<<"$result")"
    p50="$(awk '{print $2}' <<<"$result")"
    nok="$(awk '{print $3}' <<<"$result")"
    now_ts=$(date +%s)
    SETTLE_WAIT_SECS=$(( now_ts - start_ts ))
    echo "[run] settle probe #$attempt: ${ops} ops/s, p50 ${p50}ms, n=${nok} samples (elapsed ${SETTLE_WAIT_SECS}s)"
    # A probe that completes ZERO requests is not a slow server — it is a
    # broken probe (TLS handshake refused, wrong port/scheme, missing client
    # cert, server down). "0.0 ops/s, n=0" is indistinguishable from a
    # never-clearing clamp in the pass/fail check below, so without this the
    # gate silently burns the whole BENCH_SETTLE_TIMEOUT_SECS on a condition
    # no amount of waiting can fix. Bail out after two consecutive empty
    # probes and print the actual transport error curl reports.
    if [ "${nok:-0}" -eq 0 ]; then
      zero_streak=$((zero_streak + 1))
      if [ "$zero_streak" -ge 2 ]; then
        SETTLE_TIMEOUT_HIT=1
        echo "[run] WARN: settle probe completed ZERO requests twice in a row — the probe cannot reach $BASE at all (this is a connectivity/auth failure, not the post-seed clamp; waiting longer will not help). Diagnostic:" >&2
        curl -sSk --max-time 5 "${_SETTLE_CURL_MTLS[@]}" -o /dev/null -w '      http_code=%{http_code} tls=%{ssl_verify_result}\n' "$BASE/health" 2>&1 | sed 's/^/      /' >&2
        echo "[run] WARN: giving up on the gate after ${SETTLE_WAIT_SECS}s and proceeding (settle_timeout: true in meta.json) — the cell itself will fail loudly if the target really is unreachable." >&2
        break
      fi
    else
      zero_streak=0
    fi
    if awk -v o="$ops" -v t="$BENCH_SETTLE_PROBE_THR" 'BEGIN{exit !(o>=t)}' \
       || awk -v p="$p50" -v m="$BENCH_SETTLE_PROBE_P50_MS" 'BEGIN{exit !(p<m)}'; then
      echo "[run] settle gate: PASSED (${ops} ops/s / p50 ${p50}ms) — proceeding after ${SETTLE_WAIT_SECS}s"
      break
    fi
    if [ "$SETTLE_WAIT_SECS" -ge "$BENCH_SETTLE_TIMEOUT_SECS" ]; then
      SETTLE_TIMEOUT_HIT=1
      echo "[run] WARN: settle gate hit its ${BENCH_SETTLE_TIMEOUT_SECS}s timeout without clearing ${BENCH_SETTLE_PROBE_THR} ops/s (last probe: ${ops} ops/s, p50 ${p50}ms) — proceeding anyway (settle_timeout: true will be recorded in meta.json)" >&2
      break
    fi
    echo "[run] settle gate: not yet — retrying in ${BENCH_SETTLE_RETRY_SECS}s"
    sleep "$BENCH_SETTLE_RETRY_SECS"
  done
  [ -z "$_CANARY_JAR" ] || rm -f "$_CANARY_JAR"
  # H1 follow-up (found live): a burst_probe() worker that's still mid-request
  # when its BENCH_SETTLE_BURST_SECS window ends gets killed by `wait` above
  # without waiting for its in-flight curl to finish — under the clamp, a
  # request queued behind the shared single DB connection
  # (AXIAM__DB__POOL_SIZE=1) can still be executing server-side seconds after
  # the client gave up on it. Observed live: the scenario's own setup() login
  # — issued immediately after the LAST burst probe, whether it passed or hit
  # BENCH_SETTLE_TIMEOUT_SECS — landed behind that straggler traffic on the
  # same connection and came back 200 but missing its auth cookie twice in a
  # row; a login retried moments later (once the queue had drained) always
  # succeeded cleanly. A short drain pause here — after the LAST burst
  # regardless of pass/timeout, before handing control to the scenario —
  # gives any still-in-flight requests from that burst time to actually
  # finish server-side instead of leaking into the very first request of the
  # cell the gate was supposed to protect.
  echo "[run] settle gate: draining ${BENCH_SETTLE_DRAIN_SECS}s for any straggler burst traffic to finish server-side before the cell starts"
  sleep "$BENCH_SETTLE_DRAIN_SECS"
}

# --- G2 item 3: self-describing labeled passes ------------------------------
# Dumps every AXIAM__* env var the server container actually received
# (straight off `docker inspect`, like detect_rl_posture() above — what
# ACTUALLY ran, not what the shell that called `bench-up` intended) into each
# cell's meta.json under "axiam_env", so a labeled pass (pool size, batch
# strategy, decision cache, rate-limit posture, hash concurrency, ...) is
# identifiable from the metadata alone rather than the results-directory name
# (PRIVATE_BENCH_ANALYSIS.md §2.2).
#
# CRITICAL (A7 — shared archives contain no secret material): the VALUE of any
# key matching AXIAM_ENV_REDACT_RE (case-insensitive) is NEVER written — only
# the key NAME (so the setting's presence stays visible) with a literal
# "<redacted>" placeholder value. `just bench-pack`'s leak check (justfile)
# filters out every line containing that literal string before scanning
# packed content for SECRET/PASSWORD, specifically so these legitimately-named
# (and fully redacted) keys don't trip it — see the comment there.
AXIAM_ENV_REDACT_RE='PASSWORD|SECRET|KEY|PEPPER|PEM|TOKEN'
# J9/E1: the AXIAM__* prefix is not the whole story. `RUST_LOG` governs whether
# the `axiam::perf` stage-timing events an investigation pass depends on are
# emitted at all, and it carries NO prefix — so run 5's I5 pass recorded a
# complete-looking `axiam_env` while the one variable the runbook needed was
# silently absent from the container (PRIVATE_BENCH_ANALYSIS.md §2.6). Capture
# these unprefixed runtime knobs alongside the AXIAM__* dump so their absence
# is visible in the metadata rather than discovered after the k6 hours are
# spent. Extend this list, not the prefix test, when a new one matters.
AXIAM_ENV_EXTRA_KEYS='RUST_LOG RUST_BACKTRACE'
axiam_env_extra_re() {
  # "^(RUST_LOG|RUST_BACKTRACE)=" — built from the list so the two never drift.
  printf '^(%s)=' "$(printf '%s' "$AXIAM_ENV_EXTRA_KEYS" | tr ' ' '|')"
}
axiam_env_json() {
  [ "$TARGET" = "axiam" ] || { echo -n "{}"; return; }
  command -v docker >/dev/null 2>&1 || { echo -n "{}"; return; }
  local env_dump line k v first=1 extra_re
  extra_re="$(axiam_env_extra_re)"
  env_dump="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "bench-${TARGET}-server" 2>/dev/null)" || { echo -n "{}"; return; }
  echo -n "{"
  while IFS= read -r line; do
    case "$line" in
      AXIAM__*=*) : ;;
      *) printf '%s' "$line" | grep -qE "$extra_re" || continue ;;
    esac
    k="${line%%=*}"
    v="${line#*=}"
    [ "$first" -eq 1 ] || echo -n ","
    first=0
    echo
    if printf '%s' "$k" | grep -qiE "$AXIAM_ENV_REDACT_RE"; then
      printf '    "%s": "<redacted>"' "$(json_escape "$k")"
    else
      printf '    "%s": "%s"' "$(json_escape "$k")" "$(json_escape "$v")"
    fi
  done <<< "$env_dump"
  [ "$first" -eq 1 ] || echo
  echo -n "}"
}

# --- J9/E1: required-env preflight ------------------------------------------
# BENCH_REQUIRE_ENV is a space-separated list of environment variable NAMES a
# runbook pass declares it depends on (e.g. `BENCH_REQUIRE_ENV="RUST_LOG"` for
# a stage-timing investigation). Every name is checked against what the server
# container ACTUALLY received — `docker inspect`, the same source of truth
# axiam_env_json() and detect_rl_posture() use — because the failure mode this
# closes is precisely a variable that the invoking shell exported and the
# container never saw. A container is created once by `bench-up`; exporting the
# variable later, for `bench-run`, changes nothing.
#
# Empty (the default) means "assert nothing", so ordinary matrix runs are
# unaffected. Names are matched exactly against the `NAME=` prefix, so a
# variable present but set to the empty string still counts as absent — an
# empty RUST_LOG emits no events, which is the condition being guarded.
#
# Populated by env_missing() and consumed by the meta.json writer, so every
# cell records WHICH required names were missing, not just that something was.
AXIAM_ENV_MISSING=""
env_missing() {
  # Echoes the space-separated subset of $1 that the server container lacks.
  local want="$1" name miss="" env_dump
  [ -n "$want" ] || { echo -n ""; return; }
  command -v docker >/dev/null 2>&1 || { echo -n "$want"; return; }
  env_dump="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "bench-${TARGET}-server" 2>/dev/null)" || { echo -n "$want"; return; }
  for name in $want; do
    printf '%s\n' "$env_dump" | grep -qE "^${name}=.+" || miss="${miss:+$miss }$name"
  done
  echo -n "$miss"
}

# JSON array of the missing names, for meta.json.
env_missing_json() {
  local n first=1
  echo -n "["
  for n in $AXIAM_ENV_MISSING; do
    [ "$first" -eq 1 ] || echo -n ", "
    first=0
    printf '"%s"' "$(json_escape "$n")"
  done
  echo -n "]"
}

# Fails the run before any k6 time is spent (the I18 build_ref precedent).
# BENCH_REQUIRE_ENV_SOFT=1 downgrades to a warning for an exploratory pass.
require_env_preflight() {
  local want="${BENCH_REQUIRE_ENV:-}"
  [ -n "$want" ] || return 0
  if [ "$TARGET" != "axiam" ]; then
    echo "[run] WARN (J9/E1): BENCH_REQUIRE_ENV is set but target is '$TARGET' — the check inspects AXIAM's server container only; skipping." >&2
    return 0
  fi
  AXIAM_ENV_MISSING="$(env_missing "$want")"
  [ -n "$AXIAM_ENV_MISSING" ] || { echo "[run] env preflight OK — bench-${TARGET}-server carries all of: $want"; return 0; }
  echo "[run] FATAL (J9/E1): bench-${TARGET}-server is missing required env: $AXIAM_ENV_MISSING" >&2
  echo "[run]   The container's environment is fixed when 'bench-up' creates it — exporting the variable for 'bench-run' is too late." >&2
  echo "[run]   Fix: RUST_LOG='axiam=debug' just target=$TARGET profile=$PROFILE bench-up   (then re-run this cell)" >&2
  echo "[run]   Or set BENCH_REQUIRE_ENV_SOFT=1 to downgrade this to a warning." >&2
  [ "${BENCH_REQUIRE_ENV_SOFT:-0}" = "1" ] || exit 1
  echo "[run] WARN: BENCH_REQUIRE_ENV_SOFT=1 — proceeding with incomplete env; the cell's metadata records the gap." >&2
}

# Container names that make up each target's stack, with a role used to look
# up its CPU cap default (mirrors targets/<name>/docker-compose.yml — see A4/A5
# in claude_dev/benchmark-improvement-plan.md). The tls-edge container only
# exists for AXIAM under the nginx-fronted p1-tls12 profile now (p2/p3 terminate
# TLS/mTLS in-process natively — D3); docker inspect simply finds nothing for
# containers that aren't running and is skipped.
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

# Default mem cap per role (MiB), matching each target's docker-compose.yml
# default. C2: this is how a `dbcaps=uncapped` DB mem cap (or any other
# non-default BENCH_*_MEM) ends up recorded in meta.json alongside the CPU
# cap — same fallback role as role_default_cpu_cap() above.
role_default_mem_mib() {
  local raw
  case "$1" in
    server) raw="${BENCH_MEM:-1024m}" ;;
    db)     raw="${BENCH_DB_MEM:-1024m}" ;;
    mq)     raw="${BENCH_MQ_MEM:-512m}" ;;
    edge)   raw="${BENCH_EDGE_MEM:-128m}" ;;
    *)      raw="1024m" ;;
  esac
  echo "${raw%[mM]}"
}

# Emits the JSON array for meta.json's "containers" field: one entry per
# running container in this target's stack, with image, image_digest (from
# `docker inspect`), image_id, role, and its CPU + mem cap. Both caps are read
# straight off the running container (`HostConfig.NanoCpus`/`HostConfig.Memory`,
# what `--cpus`/`--memory` (compose `cpus:`/`mem_limit:`) actually set) rather
# than trusted from this shell's env — BENCH_DB_CPUS/BENCH_DB_MEM/BENCH_MQ_CPUS/
# BENCH_EDGE_CPUS are only exported inside `just bench-up`'s own subshell, so
# a separate `bench-run` invocation would otherwise silently miss a
# non-default cap the operator set at bench-up time (this is how a C2
# `dbcaps=uncapped` run ends up correctly recorded even though `bench-run` is
# a separate process from `bench-up`). Falls back to the compose-file default
# only if the inspected value is unset (no `--cpus`/`--memory` was applied).
#
# A9: `image` is `.Config.Image` — what the container was actually launched
# as (e.g. reflects BENCH_AXIAM_IMAGE at `bench-up` time, so it tracks the
# real tag rather than a value hardcoded here). `image_digest` is the
# RepoDigests[0] entry when one exists (pulled-by-digest or a registry image
# docker has resolved); for a LOCALLY-BUILT image (`just build=1 …` /
# `--build`) RepoDigests is empty (no registry involved), which is exactly
# the "unknown" gap this fixes: we now fall back to the image ID — first the
# container's own `.Image` field (the sha256 the container was created
# against), then `docker image inspect` on the image ref itself — so
# image_digest is only ever the literal "unknown" when docker can give us
# neither. `image_id` is always populated (when obtainable) as a sibling
# field so a digest-vs-id distinction is never lost even when image_digest
# did find a real RepoDigest. Together with build_ref (git commit, above)
# this makes every binary in the stack identifiable even when the tag string
# is stale or generic (e.g. ":latest").
containers_json() {
  local first=1 line cname role img dig id cap nanocpus mem_bytes mem_mib
  echo -n "["
  while read -r line; do
    [ -z "$line" ] && continue
    cname="${line%% *}"; role="${line#* }"
    docker inspect "$cname" >/dev/null 2>&1 || continue
    img="$(docker inspect --format '{{.Config.Image}}' "$cname" 2>/dev/null || echo unknown)"
    dig="$(docker inspect --format '{{index .RepoDigests 0}}' "$cname" 2>/dev/null || echo '')"
    # RepoDigests is empty (or the literal Go zero-value "<no value>" if the
    # index itself is out of range) for locally-built images — fall back to
    # the container's own image ID, then to `docker image inspect` on the
    # image ref, before giving up and recording "unknown".
    [ "$dig" = "<no value>" ] && dig=""
    id="$(docker inspect --format '{{.Image}}' "$cname" 2>/dev/null || echo '')"
    [ "$id" = "<no value>" ] && id=""
    if [ -z "$id" ]; then
      id="$(docker image inspect --format '{{.Id}}' "$img" 2>/dev/null || echo '')"
      [ "$id" = "<no value>" ] && id=""
    fi
    if [ -z "$dig" ]; then
      if [ -n "$id" ]; then dig="$id"; else dig="unknown"; fi
    fi
    [ -n "$id" ] || id="unknown"
    nanocpus="$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$cname" 2>/dev/null || echo 0)"
    if [ -n "$nanocpus" ] && [ "$nanocpus" != "0" ]; then
      cap="$(awk -v n="$nanocpus" 'BEGIN{printf "%.3f", n/1000000000}')"
    else
      cap="$(role_default_cpu_cap "$role")"
    fi
    mem_bytes="$(docker inspect --format '{{.HostConfig.Memory}}' "$cname" 2>/dev/null || echo 0)"
    if [ -n "$mem_bytes" ] && [ "$mem_bytes" != "0" ]; then
      mem_mib="$(awk -v b="$mem_bytes" 'BEGIN{printf "%.0f", b/1048576}')"
    else
      mem_mib="$(role_default_mem_mib "$role")"
    fi
    [ "$first" -eq 1 ] || echo -n ","
    first=0
    printf '{"name":"%s","role":"%s","image":"%s","image_digest":"%s","image_id":"%s","cpu_cap":%s,"mem_cap_mib":%s}' \
      "$(json_escape "$cname")" "$role" "$(json_escape "$img")" "$(json_escape "$dig")" "$(json_escape "$id")" "$cap" "$mem_mib"
  done < <(container_specs_for_target)
  echo -n "]"
}

# --- dry-run verdict --------------------------------------------------------
# Grades one cell's k6 summary on CLIENT CORRECTNESS only: did the scenario's
# setup() succeed, did the VUs actually send requests, and did every response
# match what the scenario expected. Deliberately says nothing about throughput
# or latency — see the dry-run block at the top for why a 5-second unsettled
# window is not a performance measurement.
#
# Reads the same `--summary-export` JSON report.py consumes, so the checks are
# the harness's own metrics (lib/metrics.js), which every scenario feeds
# through doOp() or recordGrpcResult():
#   bench_ok       successful logical operations
#   bench_failed   failed ones (a non-expected HTTP status / non-OK gRPC code)
#   bench_fallback iterations that measured a FALLBACK op rather than the
#                  labelled one (e.g. a userinfo setup() that could not mint a
#                  real user token and silently used client_credentials). A
#                  measured run only annotates these in the report; for a dry
#                  run it is a first-class warning, since it means the cell
#                  will not produce the comparison you think it will.
#   bench_throttled 429 / RESOURCE_EXHAUSTED — surfaced by name because "the
#                  rate-limit posture is wrong for this run" looks identical to
#                  a broken client unless you can see it.
# Prints "<VERDICT>\t<detail>" and always exits 0 — a verdict is data, not an
# error condition for the caller's `set -e`.
dry_verdict() {
  local summary="$1" k6rc="$2" rescsv="$3"
  python3 - "$summary" "$k6rc" "$rescsv" <<'PY' 2>/dev/null || echo -e "FAIL\tcould not evaluate the k6 summary (python3 missing or summary unreadable)"
import json, os, sys

summary, k6rc, rescsv = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def out(verdict, detail):
    print("%s\t%s" % (verdict, detail))
    sys.exit(0)

if not os.path.exists(summary) or os.path.getsize(summary) == 0:
    out("FAIL", "k6 wrote no summary (exit %d) — it died before/at init: bad "
                "scenario options, unreadable certs, or a setup() that threw" % k6rc)
try:
    with open(summary) as fh:
        metrics = (json.load(fh) or {}).get("metrics", {}) or {}
except Exception as exc:
    out("FAIL", "unparseable k6 summary (exit %d): %s" % (k6rc, exc))

def count(name):
    return int((metrics.get(name) or {}).get("count", 0) or 0)

checks = metrics.get("checks") or {}
passes, fails = int(checks.get("passes", 0) or 0), int(checks.get("fails", 0) or 0)
ok, failed = count("bench_ok"), count("bench_failed")
fallback, throttled = count("bench_fallback"), count("bench_throttled")
p95 = (metrics.get("bench_op_latency_ms") or {}).get("p(95)")
p95s = "p95=%.0fms" % p95 if isinstance(p95, (int, float)) else "p95=n/a"

if ok == 0 and passes == 0:
    out("FAIL", "no operation completed at all (exit %d, %d failed) — the k6 "
                "client could not reach the target or every response was rejected"
                % (k6rc, failed))
if failed or fails:
    detail = "%d/%d operations failed" % (failed or fails, (failed or fails) + ok)
    if throttled:
        detail += " (%d rate-limited: 429/RESOURCE_EXHAUSTED — check the rl= posture)" % throttled
    out("FAIL", detail + " — see the .dryrun.log for k6's check breakdown")
if fallback:
    out("WARN", "ok=%d but %d iteration(s) measured a FALLBACK op (bench_fallback) "
                "— this cell will not measure the operation it is labelled with" % (ok, fallback))
# The samplers write one CSV row per second of the measure window; an empty one
# means the cell would produce no resource data in the real matrix (typically
# resource/sampler.sh not executable, or docker stats unavailable).
if os.path.exists(rescsv):
    with open(rescsv) as fh:
        rows = sum(1 for _ in fh)
    if rows < 2:
        out("WARN", "ok=%d, %s, but the resource sampler wrote no rows — the "
                    "matrix would record no container CPU/mem for this cell" % (ok, p95s))
else:
    out("WARN", "ok=%d, %s, but no resource CSV was written" % (ok, p95s))
out("PASS", "ok=%d, %s" % (ok, p95s))
PY
}

run_one() {
  local scenario="$1"
  local cell_order_index="${2:-1}"
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
  # A dry run additionally tees k6's own output to <scenario>.dryrun.log, so a
  # failing cell's verdict can point at k6's check breakdown / setup() stack
  # trace instead of asking you to re-run to see it.
  local k6rc dry_log="$outdir/$name.dryrun.log"
  set +e
  if [ "$DRY_RUN" = "1" ]; then
    ( cd "$BENCH/scenarios" && BENCH_PROTO_ROOT="$BENCH/../proto" \
        BENCH_ZITADEL_PROTO_ROOT="$BENCH/scenarios/proto/zitadel" \
        k6 run --quiet --summary-export "$k6sum" "$scenario" ) 2>&1 | tee "$dry_log"
    k6rc=${PIPESTATUS[0]}
  else
    ( cd "$BENCH/scenarios" && BENCH_PROTO_ROOT="$BENCH/../proto" \
        BENCH_ZITADEL_PROTO_ROOT="$BENCH/scenarios/proto/zitadel" \
        k6 run --quiet --summary-export "$k6sum" "$scenario" )
    k6rc=$?
  fi
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
  "build_ref": "$(json_escape "$BUILD_REF")",
  "k6_cpu_cores_avg": $k6_cpu_cores_avg,
  "containers": $(containers_json),
  "settle_wait_secs": $SETTLE_WAIT_SECS,
  "settle_timeout": $([ "$SETTLE_TIMEOUT_HIT" = "1" ] && echo true || echo false),
  "settle_probe_thr": $SETTLE_PROBE_THR_USED,
  "cell_order_index": $cell_order_index,
  "dry_run": $([ "$DRY_RUN" = "1" ] && echo true || echo false),
  "axiam_env": $(axiam_env_json),
  "connection_model": "$([ "${BENCH_NO_CONN_REUSE:-false}" = "true" ] && echo no-reuse || { [ "${BENCH_NO_VU_CONN_REUSE:-false}" = "true" ] && echo per-iteration-vu-pool || echo pooled-per-vu; })",
  "no_connection_reuse": ${BENCH_NO_CONN_REUSE:-false},
  "no_vu_connection_reuse": ${BENCH_NO_VU_CONN_REUSE:-false},
  "seed_scale": ${BENCH_SEED_SCALE:-1},
  "seed_fixture": {
    "users_total": ${BENCH_SEED_USERS_TOTAL:-null},
    "resources_total": ${BENCH_SEED_RESOURCES_TOTAL:-null},
    "roles_total": ${BENCH_SEED_ROLES_TOTAL:-null},
    "tenants_extra": ${BENCH_SEED_TENANTS_EXTRA:-0},
    "resource_depth": ${BENCH_SEED_DEPTH:-null},
    "deny_ratio": ${BENCH_SEED_DENY_RATIO:-0}
  },
  "axiam_env_required": "$(json_escape "${BENCH_REQUIRE_ENV:-}")",
  "axiam_env_missing": $(env_missing_json),
  "axiam_env_complete": $([ -z "$AXIAM_ENV_MISSING" ] && echo true || echo false)
}
EOF
  echo "[run] wrote $k6sum, $rescsv, $hostcsv, $meta"

  if [ "$DRY_RUN" = "1" ]; then
    local verdict detail line
    line="$(dry_verdict "$k6sum" "$k6rc" "$rescsv")"
    verdict="${line%%$'\t'*}"; detail="${line#*$'\t'}"
    echo "[dry] $name: $verdict — $detail"
    record_dry "$name" "$verdict" "$detail"
  fi
}

SCENARIO_COUNT=${#SCENARIOS[@]}

# J9/E1: assert the runbook-required container env BEFORE the settle gate and
# the first cell — the whole point is to fail in seconds rather than after the
# k6 hours that produced run 5's empty stage-timing logs.
require_env_preflight

# G2 item 1: gate the FIRST cell of this run behind the settle check (once —
# not per cell; every cell in this run records the same settle_wait_secs /
# settle_timeout since they all measure the same post-seed settle event).
if [ "$SCENARIO_COUNT" -gt 0 ]; then
  settle_gate
fi

scenario_idx=0
for s in "${SCENARIOS[@]}"; do
  scenario_idx=$((scenario_idx + 1))
  run_one "$s" "$scenario_idx"
  # C3: pause between cells (not after the last one) so heat dissipates and
  # allocations/caches from this cell settle before the next measurement.
  if [ "$scenario_idx" -lt "$SCENARIO_COUNT" ] && [ "$CELL_PAUSE" -gt 0 ] 2>/dev/null; then
    echo "[run] pausing ${CELL_PAUSE}s between cells (BENCH_CELL_PAUSE=0 to disable)"
    sleep "$CELL_PAUSE"
  fi
done

if [ "$DRY_RUN" = "1" ]; then
  echo
  echo "[dry] === $TARGET / $PROFILE — $SCENARIO_COUNT scenario(s) exercised ==="
  awk -F'\t' -v t="$TARGET" -v p="$PROFILE" \
    '$1==t && $2==p {printf "  %-6s %-28s %s\n", $4, $3, $5}' "$DRY_TSV" 2>/dev/null || true
  if [ "$SCENARIO_COUNT" -eq 0 ]; then
    # Every scenario was filtered out. The real matrix would "succeed" here and
    # silently produce an empty cell set — worth failing a dry run over.
    echo "[dry] NO scenario ran for $TARGET / $PROFILE — every one was filtered out (see the SKIP rows above)."
    record_dry "(no-scenarios)" "FAIL" "every scenario was filtered out for this target/profile"
    exit 1
  fi
  if [ "$DRY_FAILURES" -gt 0 ]; then
    echo "[dry] $DRY_FAILURES cell(s) FAILED — the real matrix would break here. Logs: $RESULTS/$TARGET/$PROFILE/*.dryrun.log"
    exit 1
  fi
  echo "[dry] all cells for $TARGET / $PROFILE passed the client contract."
  exit 0
fi

echo "[run] done. Aggregate with: python3 $HERE/report.py --results $RESULTS"
