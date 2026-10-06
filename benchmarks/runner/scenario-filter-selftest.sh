#!/usr/bin/env bash
# M1 regression guard: an extension-less `--scenario` must still be filtered.
#
# `--scenario authz_check_rest` used to be passed through verbatim. Two things
# broke at once and only one of them was audible:
#
#   * `k6 run scenarios/authz_check_rest` is not a file — loud, and the reason
#     the bug looked harmless;
#   * every membership test in run-benchmark.sh's filter_scenarios() compares
#     against `.js`-suffixed names (PENDING_SCENARIOS, AXIAM_ONLY_SCENARIOS,
#     ZITADEL_ONLY_SCENARIOS, OAUTH2_SCENARIOS, BENCH_SCENARIO_EXCLUDE), so an
#     extension-less name matched NONE of them and silently bypassed the lot —
#     including the pending-scenario guard, whose entire job is to stop a
#     not-yet-runnable cell from being run.
#
# So this asserts the filters, not the filename: it drives the REAL runner in
# dry-run mode with extension-less names that must be skipped, and checks the
# dry-run ledger records the skip against the normalized `.js` cell name.
# Running a scenario the filters let through needs k6 and a live stack and is out
# of scope here — but WHICH scenarios get through is not: BENCH_LIST_SCENARIOS=1
# makes the runner print its survivors and stop, and check_runs below pins that
# set per competitor target (keycloak, zitadel, authentik).
#
# Hermetic: no docker, no k6, no seeded stack (BENCH_SKIP_SEED_CHECK=1; the
# runner never reaches its k6 invocation because every scenario is filtered
# out first). Runs in CI on every PR.
# Usage: scenario-filter-selftest.sh          (from benchmarks/)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT

fail=0

# target, scenario-as-typed, expected cell name in the ledger, why it must skip
check_skip() {
  local target="$1" typed="$2" cell="$3" why="$4"
  local out="$FIX/$target-$cell"
  mkdir -p "$out"
  # The runner exits non-zero here by design (every scenario filtered out, and
  # in this environment it also has no k6) — the ledger row is the assertion.
  BENCH_SKIP_SEED_CHECK=1 BENCH_RESULTS_DIR="$out" \
    bash "$HERE/run-benchmark.sh" --target "$target" --profile p0-plaintext \
      --scenario "$typed" --dry-run >"$out/runner.log" 2>&1 || true

  # Literal match on the TSV row prefix (fixed-string, real tabs) rather than
  # a regex over names that contain regex metacharacters.
  local want
  want="$(printf '%s\tp0-plaintext\t%s\tSKIP\t' "$target" "$cell")"
  if ! grep -qF "$want" "$out/dry-run.tsv" 2>/dev/null; then
    echo "[scenario-filter-selftest] '--scenario $typed' (target $target) was NOT skipped as $cell ($why)." >&2
    echo "  ledger: $(cat "$out/dry-run.tsv" 2>/dev/null || echo '<no dry-run.tsv written>')" >&2
    fail=1
  fi
}

# Pending guard — the costliest bypass: this cell is pending precisely because
# running it unsupervised turns a skip into a red matrix cell.
#
# The fixture must name a cell that is ACTUALLY in PENDING_SCENARIOS, so it
# moves whenever that list does. It read `scim_provisioning` until 2026-09-12,
# when that cell was un-pended after its first clean run — which turned this
# guard red while the filter it guards was working perfectly. Now
# `oauth2_client_credentials_reactor_hook`, the one entry still pending
# (no admin-session helper in lib/auth.js, nothing answering the reactor queue).
check_skip axiam    oauth2_client_credentials_reactor_hook \
                    oauth2_client_credentials_reactor_hook "pending scenario"
# Target-scoping guard — an AXIAM-only cell run against another vendor.
check_skip keycloak authz_check_rest     authz_check_rest  "AXIAM-only scenario"
# Same guard, for the two cells that were missing from AXIAM_ONLY_SCENARIOS for
# several releases. Their setup() throws "target <t> has no OPAQUE endpoint", so
# the bug did not hide — it presented a capability gap as a red benchmark cell on
# every competitor arm of every matrix pass. A scenario-side guard cannot fix
# that; only the filter list can, which is why these are asserted here.
check_skip keycloak opaque_login_start    opaque_login_start    "AXIAM-only scenario"
check_skip zitadel  opaque_register_start opaque_register_start "AXIAM-only scenario"
# The two T21 cells. oauth2_discovery's adapter method exists on the axiam
# adapter alone, and oauth2_code_pkce drives an AXIAM-only authorize leg.
check_skip keycloak oauth2_discovery      oauth2_discovery      "AXIAM-only scenario"
check_skip zitadel  oauth2_code_pkce      oauth2_code_pkce      "AXIAM-only scenario"
# The already-correct spelling must behave identically — normalization is
# idempotent, not a second code path.
check_skip axiam    oauth2_client_credentials_reactor_hook.js \
                    oauth2_client_credentials_reactor_hook "pending scenario, spelled with .js"

# authentik (T23.10.1). The AXIAM-only / Zitadel-only lists are written as "every
# target except X", so a new target inherits the exclusions without being named —
# which is exactly how a new target could silently be handed a cell that cannot
# run on it (a red cell that reads as "the product is broken"). These pin that for
# the fourth target, one cell per reason a scenario is not runnable there.
check_skip authentik authz_check_rest        authz_check_rest        "AXIAM-only scenario"
check_skip authentik opaque_login_start      opaque_login_start      "AXIAM-only scenario"
check_skip authentik userinfo_grpc           userinfo_grpc           "AXIAM-only scenario (gRPC identity read)"
check_skip authentik oauth2_discovery        oauth2_discovery        "AXIAM-only scenario"
check_skip authentik zitadel_userinfo_grpc   zitadel_userinfo_grpc   "Zitadel-only scenario"

# The positive half: the EXACT set each competitor runs under `--scenario all`,
# via the runner's own BENCH_LIST_SCENARIOS=1 (it prints the survivors of every
# filter and stops — no k6, no stack). A skip-assertion proves a cell is dropped;
# only this proves nothing else got through, and that the shared five (client
# credentials, introspection, JWKS, userinfo, password login) plus token_refresh
# are still there. A scenario added to scenarios/ without a decision about the
# competitors lands here and fails, which is the point: decide (extend a filter
# list in run-benchmark.sh, or extend this expectation) in the same commit.
check_runs() {
  local target="$1"; shift
  local out="$FIX/runs-$target"
  mkdir -p "$out"
  local got want
  # BENCH_CLIENT_SECRET only has to be non-empty: AXIAM's OAuth2 scenarios are dropped
  # when no confidential client was seeded, and this test seeds nothing.
  got="$(BENCH_CLIENT_SECRET=1 BENCH_LIST_SCENARIOS=1 BENCH_SKIP_SEED_CHECK=1 BENCH_RESULTS_DIR="$out" \
          bash "$HERE/run-benchmark.sh" --target "$target" --profile p0-plaintext --scenario all 2>/dev/null \
          | grep -E '^[a-z0-9_]+\.js$' | sort | tr '\n' ' ')"
  want="$(printf '%s\n' "$@" | sort | tr '\n' ' ')"
  if [ "$got" != "$want" ]; then
    echo "[scenario-filter-selftest] target $target would run a different scenario set than expected." >&2
    echo "  want: $want" >&2
    echo "  got:  $got" >&2
    fail=1
  fi
}
SHARED="jwks_fetch.js oauth2_client_credentials.js oauth2_password_login.js token_introspection.js token_refresh.js userinfo.js"
# shellcheck disable=SC2086
check_runs keycloak  $SHARED
# shellcheck disable=SC2086
check_runs zitadel   $SHARED zitadel_userinfo_grpc.js
# shellcheck disable=SC2086
check_runs authentik $SHARED

# Run 6 (T23.10.2(a)): AXIAM runs EVERYTHING that is not pending, opt-in or competitor-
# only — the runbook's cell list quotes this set, so a scenario added or dropped has to
# be decided here, in the same commit, and the runbook updated with it.
# shellcheck disable=SC2086
check_runs axiam authz_batch_grpc.js authz_batch_rest.js authz_check_grpc.js authz_check_rest.js \
  device_authorization.js device_flow_poll.js device_verify.js grpc_admin_validate.js grpc_infra.js \
  jwks_fetch.js oauth2_authorize.js oauth2_client_credentials.js oauth2_code_pkce.js oauth2_discovery.js \
  oauth2_password_login.js oauth2_revoke.js opaque_login_start.js opaque_register_start.js \
  scim_provisioning.js token_exchange.js token_introspection.js token_refresh.js uma2_perm.js \
  uma_ticket_grant.js userinfo.js userinfo_grpc.js

# BENCH_SCENARIO_ONLY (the minimal-profile pass runs a chosen SET behind one settle gate):
# exactly the named cells survive, an unknown name is a hard error rather than an empty run.
only_out="$FIX/only"; mkdir -p "$only_out"
got="$(BENCH_SCENARIO_ONLY="jwks_fetch.js userinfo.js" BENCH_LIST_SCENARIOS=1 BENCH_SKIP_SEED_CHECK=1 BENCH_RESULTS_DIR="$only_out" \
        bash "$HERE/run-benchmark.sh" --target keycloak --profile p0-plaintext --scenario all 2>/dev/null \
        | grep -E '^[a-z0-9_]+\.js$' | sort | tr '\n' ' ')"
[ "$got" = "jwks_fetch.js userinfo.js " ] || { echo "[scenario-filter-selftest] BENCH_SCENARIO_ONLY kept '$got', expected exactly 'jwks_fetch.js userinfo.js'" >&2; fail=1; }
if BENCH_SCENARIO_ONLY="jwks_fetch.js userinfo_typo.js" BENCH_LIST_SCENARIOS=1 BENCH_SKIP_SEED_CHECK=1 BENCH_RESULTS_DIR="$only_out" \
     bash "$HERE/run-benchmark.sh" --target keycloak --profile p0-plaintext --scenario all >"$only_out/typo.log" 2>&1; then
  echo "[scenario-filter-selftest] a BENCH_SCENARIO_ONLY name that is not a scenario file did not fail the runner" >&2; fail=1
fi

[ "$fail" -eq 0 ] || { echo "[scenario-filter-selftest] FAILED" >&2; exit 1; }
echo "[scenario-filter-selftest] OK — extension-less --scenario names are normalized before filtering."
