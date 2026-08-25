#!/usr/bin/env bash
# dry-run.sh — rehearse the SDK matrix in minutes instead of hours.
#
# The SDK counterpart to `just bench-dry-run`. Every language bench still runs
# for real — real toolchain, real build, real SDK package, real profile env,
# real seed env, real HTTP(S) against a live AXIAM — with the measured window
# collapsed to a handful of iterations. Each language is graded on the CLIENT
# CONTRACT (did it build, did it construct a client, did all four contractual
# ops complete without errors, did it emit a well-formed axiam.sdk-bench/v1
# record) rather than on throughput.
#
# What this catches before you spend ~20 minutes per profile on the real pass:
#   * an SDK whose published package moved and no longer compiles against the
#     bench glue (build failure — the single most common cause of a red cell),
#   * a bench wired to a profile env it cannot resolve (TLS paths, missing CA),
#   * a seeded fixture the SDK cannot actually use (wrong tenant/org slug,
#     inactive bench user, a resource with no grant) — which reads as eleven
#     independent "errors: 2000" cells in the real run,
#   * a language whose toolchain simply isn't installed here (reported SKIP,
#     never FAIL — that is a fact about this machine, not about the SDK).
#
# PREREQUISITES — this talks to a live server, so the stack must be up AND
# seeded for the profile you are rehearsing:
#
#     just target=axiam profile=p2-tls13 bench-up
#     just target=axiam profile=p2-tls13 bench-seed
#     just target=axiam profile=p2-tls13 sdk-dry-run
#
# Both are verified up front (a connect probe plus a real login against the
# seeded fixture), so a missing prerequisite is one actionable line instead of
# eleven differently-worded copies of it.
#
# Usage:
#   bash sdk/dry-run.sh                 # every language with a run.sh
#   bash sdk/dry-run.sh python go       # just these
#
# Knobs (env):
#   SDK_DRY_ITERATIONS  (10)   timed iterations per op
#   SDK_DRY_WARMUP      (2)    warm-up iterations per op
#   SDK_DRY_CONCURRENCY (2)    concurrent callers (refresh is serial by spec)
#   SDK_DRY_TIMEOUT     (900)  per-language wall clock, INCLUDING a cold build
#
# Unlike `sdk-bench-all` this does NOT stop at the first broken language: a
# failure is recorded and the sweep carries on, so one pass gives you the full
# list of what to fix. Exits non-zero if anything FAILED.
#
# Records land under results/dry-run/sdk/<profile>/ — never results/sdk/ —
# for the same reason the k6 dry run is quarantined: a 10-iteration number is
# not a measurement, and `sdk/collect.py` / `just bench-report` must never be
# able to pick one up and publish it as one.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"

TARGET="${BENCH_TARGET:-axiam}"
PROFILE="${BENCH_PROFILE:-p0-plaintext}"

# Quarantined tree (see the header). BENCH_RESULTS_DIR is deliberately NOT
# honoured as the base here — pointing a dry run at the real results root is
# never what anyone means, and doing it silently is how a rehearsal number ends
# up in a published table.
OUT="${SDK_DRY_RESULTS_DIR:-$BENCH/results/dry-run}/sdk/$PROFILE"
mkdir -p "$OUT"
TSV="$OUT/dry-run.tsv"
: > "$TSV"

ITER="${SDK_DRY_ITERATIONS:-10}"
WARMUP="${SDK_DRY_WARMUP:-2}"
CONC="${SDK_DRY_CONCURRENCY:-2}"
PER_SDK_TIMEOUT="${SDK_DRY_TIMEOUT:-900}"

note() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TSV"; }

# ---------------------------------------------------------------------------
# Prerequisite 1 — the seed env exists and carries every id a bench needs.
# ---------------------------------------------------------------------------
# Same lookup and same fail-fast list as run-all.sh, so a bench never discovers
# an empty id later with a confusing language-specific error.
SEED_ENV="${BENCH_SEED_DIR:-$BENCH/.seed}/$TARGET.seed.env"
LEGACY_SEED_ENV="${BENCH_RESULTS_DIR:-$BENCH/results}/$TARGET.seed.env"
if [ -f "$SEED_ENV" ]; then
  # shellcheck disable=SC1090
  set -a; . "$SEED_ENV"; set +a
elif [ -f "$LEGACY_SEED_ENV" ]; then
  # shellcheck disable=SC1090
  set -a; . "$LEGACY_SEED_ENV"; set +a
else
  echo "[sdk-dry-run] FATAL: no seed env at $SEED_ENV" >&2
  echo "               run:  just target=$TARGET profile=$PROFILE bench-seed" >&2
  exit 1
fi
for var in BENCH_RESOURCE_ID BENCH_SUBJECT_ID BENCH_TENANT_SLUG BENCH_ORG_SLUG BENCH_CLIENT_ID BENCH_CLIENT_SECRET BENCH_USERNAME BENCH_PASSWORD; do
  if [ -z "${!var:-}" ]; then
    echo "[sdk-dry-run] FATAL: $var is empty after sourcing $SEED_ENV" >&2
    echo "               re-run: just target=$TARGET profile=$PROFILE bench-seed" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Prerequisite 2 — something is serving THIS profile.
# ---------------------------------------------------------------------------
# shellcheck disable=SC1091
source "$HERE/_preflight.sh"
preflight_target || exit 1

# ---------------------------------------------------------------------------
# Prerequisite 3 — the fixture is usable, not merely present.
# ---------------------------------------------------------------------------
# A reachable server with a stale or half-seeded fixture is the failure this
# whole script exists to make cheap: without this probe every language builds
# (minutes each) and then fails identically on `login`, which reads as "all
# eleven SDKs are broken". One login up front turns that into one line.
#
# AXIAM-only: it is the only target whose fixture shape this probe knows, and
# the competitors' SDK arms do not exist. Anything else is left to the benches.
fixture_probe() {
  [ "$TARGET" = "axiam" ] || return 0
  local base="${BENCH_SCHEME:-http}://${BENCH_HOST:-localhost}:${BENCH_PORT:-8090}"
  local args=(-sk -o /dev/null -w '%{http_code}' --max-time 20)
  # p3-mtls terminates client-cert auth in-process: an anonymous probe is
  # refused at the handshake and would report a healthy fixture as broken.
  if [ -n "${BENCH_CLIENT_CERT:-}" ] && [ -n "${BENCH_CLIENT_KEY:-}" ]; then
    args+=(--cert "$BENCH_CLIENT_CERT" --key "$BENCH_CLIENT_KEY")
  fi
  local code
  code=$(curl "${args[@]}" -X POST "$base/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"org_slug\":\"$BENCH_ORG_SLUG\",\"tenant_slug\":\"$BENCH_TENANT_SLUG\",\"username_or_email\":\"$BENCH_USERNAME\",\"password\":\"$BENCH_PASSWORD\"}")
  [ "$code" = "200" ] && return 0

  echo "[sdk-dry-run] FATAL: the stack is up but the seeded fixture is not usable." >&2
  echo "               POST $base/api/v1/auth/login as '$BENCH_USERNAME' answered HTTP $code" >&2
  echo "               (org_slug=$BENCH_ORG_SLUG tenant_slug=$BENCH_TENANT_SLUG)" >&2
  echo >&2
  case "$code" in
    401|403) echo "               401/403 usually means the bench user is locked, inactive, or" >&2
             echo "               PendingVerification past its grace period — re-seed:" >&2 ;;
    400)     echo "               400 usually means the org/tenant slug pair does not resolve —" >&2
             echo "               the volume was dropped or seeded under different slugs:" >&2 ;;
    000)     echo "               000 means curl never got a response (TLS or connect failure)" >&2
             echo "               despite the readiness probe passing — check the profile certs:" >&2 ;;
    *)       echo "               Re-seed and retry:" >&2 ;;
  esac
  echo >&2
  echo "                 just target=$TARGET profile=$PROFILE bench-seed" >&2
  return 1
}
fixture_probe || exit 1

# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------
if [ "$#" -gt 0 ]; then
  SDKS=("$@")
else
  mapfile -t SDKS < <(find "$HERE" -mindepth 2 -maxdepth 2 -name run.sh -printf '%h\n' | xargs -n1 basename | sort)
fi

export BENCH_TARGET="$TARGET"
export BENCH_PROFILE="$PROFILE"
export SDK_BENCH_ITERATIONS="$ITER"
export SDK_BENCH_WARMUP="$WARMUP"
export SDK_BENCH_CONCURRENCY="$CONC"

echo "[sdk-dry-run] $TARGET @ $PROFILE -> ${BENCH_SCHEME:-http}://${BENCH_HOST:-localhost}:${BENCH_PORT:-8090}"
echo "[sdk-dry-run] ${#SDKS[@]} language(s), iterations=$ITER warmup=$WARMUP concurrency=$CONC, ${PER_SDK_TIMEOUT}s each (build included)"
echo "[sdk-dry-run] records -> $OUT"
echo

started=$(date +%s)
for sdk in "${SDKS[@]}"; do
  run="$HERE/$sdk/run.sh"
  if [ ! -f "$run" ]; then
    note "$sdk" SKIP "no run.sh — not a wired language"
    continue
  fi
  printf '[sdk-dry-run] %-11s ... ' "$sdk"
  rec="$OUT/$sdk.json"
  log="$OUT/$sdk.dryrun.log"
  # Every bench runs with stdin closed. A bench that inherits an interactive terminal's
  # stdin can wedge the whole sweep: the Gradle daemon client (sdk/kotlin) forwards
  # System.in and only sends its `CloseInput`/`Finished` shutdown handshake once that
  # stream hits EOF, so on a tty it hangs AFTER a successful build. No bench reads stdin,
  # so this costs nothing and removes the failure mode for all eleven languages at once.
  t0=$(date +%s)
  timeout --signal=TERM --kill-after=30 "$PER_SDK_TIMEOUT" bash "$run" > "$rec" 2>"$log" </dev/null
  rc=$?
  secs=$(( $(date +%s) - t0 ))

  # `timeout` reports 124 on TERM; a bench that ignored TERM and was KILLed
  # surfaces as 137. Both mean the same thing to the operator.
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
    note "$sdk" FAIL "timed out after ${PER_SDK_TIMEOUT}s (build + run) — raise SDK_DRY_TIMEOUT or see $sdk.dryrun.log"
    echo "FAIL (timeout)"
    continue
  fi

  read -r verdict detail < <(SDK_NAME="$sdk" RC="$rc" SECS="$secs" python3 "$HERE/_dryrun_verdict.py" "$rec")
  note "$sdk" "$verdict" "$detail"
  echo "$verdict"
done
elapsed=$(( $(date +%s) - started ))

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
{
  echo "# SDK bench dry run"
  echo
  echo "Rehearsed \`$TARGET\` @ \`$PROFILE\` in $((elapsed / 60))m $((elapsed % 60))s"
  echo "at iterations=$ITER warmup=$WARMUP concurrency=$CONC."
  echo
  echo "Verdicts grade the SDK client contract (build, construct, four ops without"
  echo "errors, well-formed \`axiam.sdk-bench/v1\` record) — **not** performance."
  echo "These iteration counts are far too small to mean anything as a measurement."
  echo
  echo "| Verdict | SDK | Detail |"
  echo "|---|---|---|"
  awk -F'\t' '{ printf "| %s | `%s` | %s |\n", $2, $1, $3 }' "$TSV"
} > "$OUT/SUMMARY.md"

echo
echo "──────────── SDK DRY RUN SUMMARY ────────────"
awk -F'\t' '{ printf "  %-5s %-11s %s\n", $2, $1, $3 }' "$TSV"
echo
awk -F'\t' '
  { n[$2]++ }
  END { printf "  %d PASS, %d WARN, %d SKIP, %d FAIL\n", n["PASS"], n["WARN"], n["SKIP"], n["FAIL"] }
' "$TSV"
echo "  elapsed: $((elapsed / 60))m $((elapsed % 60))s — wrote $OUT/SUMMARY.md"

# Flag-then-END, not `{exit 0}`: an awk `exit` inside a rule still runs the END
# block, so `$2=="FAIL"{exit 0} END{exit 1}` would always report clean.
if awk -F'\t' '$2=="FAIL"{f=1} END{exit !f}' "$TSV"; then
  echo
  echo "  Do NOT start the real SDK pass yet — the languages above marked FAIL would break it."
  echo "  Per-language output: $OUT/<sdk>.dryrun.log (stderr) and $OUT/<sdk>.json (record)"
  exit 1
fi
echo
echo "  Every wired language built and satisfied the client contract."
echo "  Safe to run: just target=$TARGET profile=$PROFILE sdk-bench-all"
