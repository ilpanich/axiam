#!/usr/bin/env bash
# The AXIAM deployment-profile guard (T23.10.2(a)).
#
# A minimal-profile pass files its cells under a "minimal" label and a banner; if the
# overlay silently did not apply, full-profile cells would carry it. Two things stand
# between that and a published figure, and both are pinned here with a stub `docker`
# (no daemon, no stack, no k6):
#
#   1. meta.json's `axiam_deploy_profile` is read off the server container's
#      AXIAM__AMQP__ENABLED — `minimal` for false, `full` otherwise.
#   2. BENCH_EXPECT_DEPLOY makes the runner refuse to start a cell whose stack is the
#      other profile (exit non-zero, naming the fix) and say OK when they agree.
#
# It also asserts the overlay itself still removes what the minimal profile removes
# (the broker, its URL, its signing key), since a regression there would leave a
# "minimal" stack with a broker dependency and no error.
#
# Hermetic: runs in CI on every PR. Usage: deploy-profile-selftest.sh   (from benchmarks/)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail=0
say() { echo "[deploy-profile-selftest] $*" >&2; fail=1; }

mkdir -p "$T/bin"
# A stub docker: `inspect` of the server container prints an env dump whose
# AXIAM__AMQP__ENABLED is $STUB_AMQP; everything else is empty/benign.
cat > "$T/bin/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  inspect)
    # docker inspect -f '{{range .Config.Env}}…' bench-axiam-server
    for a in "$@"; do
      case "$a" in
        *Config.Env*) [ -n "${STUB_AMQP:-}" ] && printf 'AXIAM__AMQP__ENABLED=%s\nAXIAM_BENCH_RL_POSTURE=neutralized\n' "$STUB_AMQP" || printf 'AXIAM_BENCH_RL_POSTURE=neutralized\n'; exit 0 ;;
      esac
    done
    exit 1 ;;
  version) echo "stub" ;;
  *) exit 0 ;;
esac
STUB
cat > "$T/bin/k6" <<'STUB'
#!/usr/bin/env bash
[ "${1:-}" = "version" ] && echo "k6 v0.0.0 (stub)"
exit 1
STUB
chmod +x "$T/bin/docker" "$T/bin/k6"

run_cell() {  # STUB_AMQP EXPECT -> output on stdout, status in $rc
  local amqp="$1" expect="$2" out="$T/out-$1-$2"
  mkdir -p "$out"
  PATH="$T/bin:$PATH" STUB_AMQP="$amqp" BENCH_EXPECT_DEPLOY="$expect" BENCH_SKIP_SEED_CHECK=1 BENCH_CLIENT_SECRET=1 BENCH_ALLOW_UNMERGED_BUILD_REF=1 \
    BENCH_RESULTS_DIR="$out" BENCH_SEED_DIR="$T/seed" BENCH_CELL_PAUSE=0 \
    bash "$HERE/run-benchmark.sh" --target axiam --profile p0-plaintext --scenario jwks_fetch --dry-run \
    > "$out/runner.log" 2>&1 || true
  cat "$out/runner.log"
}

# 1. mismatch: a full stack under a minimal pass, and the reverse
for pair in "true minimal" "false full" ; do
  set -- $pair
  log="$(run_cell "$1" "$2")"
  grep -q "FATAL (T23.10.2(a)): this pass expects the AXIAM '$2' profile" <<<"$log" \
    || say "AMQP_ENABLED=$1 under BENCH_EXPECT_DEPLOY=$2 was not refused"
done
# the default (variable absent from the container) is `full`
log="$(run_cell "" minimal)"
grep -q "expects the AXIAM 'minimal' profile but bench-axiam-server is 'full'" <<<"$log" \
  || say "a container with no AXIAM__AMQP__ENABLED was not read as the full profile"

# 2. agreement proceeds, and records the profile in the ledger-adjacent log line
log="$(run_cell false minimal)"
grep -q "deploy profile OK — bench-axiam-server is the AXIAM 'minimal' profile" <<<"$log" \
  || say "a minimal stack under BENCH_EXPECT_DEPLOY=minimal was not accepted"
meta="$(find "$T/out-false-minimal" -name '*.meta.json' | head -1)"
if [ -z "$meta" ]; then say "no meta.json was written for the minimal cell (the runner died before recording it?)"
elif ! grep -q '"axiam_deploy_profile": "minimal"' "$meta"; then say "meta.json does not record axiam_deploy_profile: minimal"; fi
log="$(run_cell true full)"
grep -q "deploy profile OK — bench-axiam-server is the AXIAM 'full' profile" <<<"$log" \
  || say "a full stack under BENCH_EXPECT_DEPLOY=full was not accepted"

meta="$(find "$T/out-true-full" -name '*.meta.json' | head -1)"
if [ -n "$meta" ] && ! grep -q '"axiam_deploy_profile": "full"' "$meta"; then say "meta.json does not record axiam_deploy_profile: full"; fi

# 3. unset asserts nothing
mkdir -p "$T/out-none"
PATH="$T/bin:$PATH" STUB_AMQP=true BENCH_SKIP_SEED_CHECK=1 BENCH_CLIENT_SECRET=1 BENCH_ALLOW_UNMERGED_BUILD_REF=1 BENCH_RESULTS_DIR="$T/out-none" BENCH_SEED_DIR="$T/seed" BENCH_CELL_PAUSE=0 \
  bash "$HERE/run-benchmark.sh" --target axiam --profile p0-plaintext --scenario jwks_fetch --dry-run > "$T/out-none/runner.log" 2>&1 || true
if grep -q "FATAL (T23.10.2(a))" "$T/out-none/runner.log"; then say "an unset BENCH_EXPECT_DEPLOY still failed the run"; fi

# 4. the overlay still removes the broker
overlay="$BENCH/targets/axiam/docker-compose.minimal.yml"
for needle in 'AXIAM__AMQP__ENABLED: "false"' 'AXIAM__AMQP__URL: !reset null' 'AXIAM__AMQP__SIGNING_KEY: !reset null' \
              'AXIAM__AMQP__TLS__CA_CERT_PATH: !reset null' 'depends_on: !override' 'volumes: !override []' 'profiles: ["full-profile-only"]'; do
  grep -qF -- "$needle" "$overlay" || say "docker-compose.minimal.yml lost: $needle"
done
if grep -E '^\s+rabbitmq:\s*\{' "$overlay" | grep -qv '#'; then say "the overlay makes the server depend on rabbitmq"; fi

[ "$fail" -eq 0 ] || { echo "[deploy-profile-selftest] FAILED" >&2; exit 1; }
echo "[deploy-profile-selftest] OK — the runner reads the AXIAM deployment profile off the container, refuses a stack that is not the profile the pass says, and the minimal overlay still removes the broker."
