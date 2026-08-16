#!/usr/bin/env bash
# N1 regression guard for the nested-resource depth sweep's harness wiring.
#
# The sweep's failure modes are all silent ones, which is why they get a
# hermetic test rather than a comment:
#
#   * A labelled sweep cell leaking into the default `--scenario all` set would
#     add hours to every future matrix AND publish one arbitrary depth as
#     though it were "the" nested number — the exact reading the ladder exists
#     to prevent.
#   * The gRPC arm running against a competitor would dial AXIAM's proto at a
#     server that has never heard of it and report the resulting flood as a
#     measurement.
#   * `nested_report.py` computing a depth SLOPE for the capability-gap arm
#     would credit a product with a constant-cost nested check it does not
#     implement. A flat line and "there is no such operation" look identical in
#     a table and mean completely different things.
#   * A rung whose depth never reached meta.json would be filed under a
#     directory named after a depth nobody ran.
#
# Hermetic: no docker, no k6, no seeded stack, no network. The runner is driven
# in dry-run mode with BENCH_SKIP_SEED_CHECK=1 and every scenario it is asked
# about is one the filters must reject, so it never reaches its k6 invocation.
# Usage: nested-selftest.sh          (from benchmarks/)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT

fail=0
note() { echo "[nested-selftest] $*" >&2; }

# --- 1. The sweep cells must be filtered OUT of the auto-discovered set -----
run_all() {  # TARGET -> ledger path on stdout
  local target="$1"
  local out="$FIX/all-$target"
  mkdir -p "$out"
  # Exits non-zero by design in this environment (no k6, nothing to reach) —
  # the ledger rows are the assertion, not the exit code.
  BENCH_SKIP_SEED_CHECK=1 BENCH_RESULTS_DIR="$out" \
    bash "$HERE/run-benchmark.sh" --target "$target" --profile p0-plaintext \
      --scenario all --dry-run >"$out/runner.log" 2>&1 || true
  echo "$out/dry-run.tsv"
}

ledger="$(run_all axiam)"
for cell in authz_nested_rest authz_nested_grpc; do
  want="$(printf 'axiam\tp0-plaintext\t%s\tSKIP\t' "$cell")"
  if ! grep -qF "$want" "$ledger" 2>/dev/null; then
    note "'--scenario all' did NOT skip $cell — a labelled sweep rung would run as a default matrix cell."
    fail=1
  fi
done

# --- 2. Named explicitly, the REST arm is accepted for every target ---------
# (the filters must not reject it; whether it then runs is k6's business, which
# this hermetic test deliberately never reaches). Asserted as the ABSENCE of a
# skip row, so the check holds whether or not k6 happens to be installed.
for target in axiam keycloak zitadel; do
  out="$FIX/named-$target"
  mkdir -p "$out"
  BENCH_SKIP_SEED_CHECK=1 BENCH_RESULTS_DIR="$out" \
    bash "$HERE/run-benchmark.sh" --target "$target" --profile p0-plaintext \
      --scenario authz_nested_rest.js --dry-run >"$out/runner.log" 2>&1 || true
  skip="$(printf '%s\tp0-plaintext\tauthz_nested_rest\tSKIP\t' "$target")"
  if grep -qF "$skip" "$out/dry-run.tsv" 2>/dev/null; then
    note "an explicitly-named authz_nested_rest was SKIPPED for target $target — the sweep cannot run it."
    note "  ledger: $(cat "$out/dry-run.tsv")"
    fail=1
  fi
done

# --- 3. The gRPC arm stays AXIAM-only --------------------------------------
for target in keycloak zitadel; do
  out="$FIX/grpc-$target"
  mkdir -p "$out"
  BENCH_SKIP_SEED_CHECK=1 BENCH_RESULTS_DIR="$out" \
    bash "$HERE/run-benchmark.sh" --target "$target" --profile p0-plaintext \
      --scenario authz_nested_grpc.js --dry-run >"$out/runner.log" 2>&1 || true
  want="$(printf '%s\tp0-plaintext\tauthz_nested_grpc\tSKIP\t' "$target")"
  if ! grep -qF "$want" "$out/dry-run.tsv" 2>/dev/null; then
    note "authz_nested_grpc was NOT skipped for target $target — it would dial AXIAM's proto at a server that has never heard of it."
    fail=1
  fi
done

# --- 4. nested_report.py over a fixture sweep tree ---------------------------
SWEEP="$FIX/results/nested"

mk_cell() {  # TARGET DEPTH SCENARIO P95 THROUGHPUT ERRORRATE EXITCODE
  local target="$1" depth="$2" scenario="$3" p95="$4" thr="$5" err="$6" rc="$7"
  local dir="$SWEEP/d$depth/$target/p0-plaintext"
  mkdir -p "$dir"
  cat > "$dir/$scenario.meta.json" <<EOF
{
  "target": "$target",
  "profile": "p0-plaintext",
  "scenario": "$scenario",
  "k6_exit_code": $rc,
  "k6_version": "v0.selftest",
  "vus": 50,
  "warmup": "20s",
  "duration": "60s",
  "rate_limits": "neutralized",
  "connection_model": "pooled-per-vu",
  "build_ref": "selftest",
  "k6_summary_file": "$scenario.k6.json",
  "dry_run": false,
  "nested_authz": { "depth": $depth, "kc_mode": "wildcard", "prefix": "bench-nest" }
}
EOF
  cat > "$dir/$scenario.k6.json" <<EOF
{
  "metrics": {
    "bench_ok": { "count": 1000, "rate": $thr },
    "bench_failed": { "count": 0 },
    "bench_error_rate": { "value": $err },
    "bench_op_latency_ms": { "med": $p95, "p(95)": $p95, "p(99)": $p95 }
  }
}
EOF
}

# AXIAM: a real, rising ladder over both transports.
mk_cell axiam 0 authz_nested_rest 10.0 900.0 0.0 0
mk_cell axiam 8 authz_nested_rest 14.0 700.0 0.0 0
mk_cell axiam 0 authz_nested_grpc 4.0 2000.0 0.0 0
mk_cell axiam 8 authz_nested_grpc 6.0 1700.0 0.0 0
# Keycloak: a ladder too (URI resolution, not inheritance — but a real ladder).
mk_cell keycloak 0 authz_nested_rest 20.0 400.0 0.0 0
mk_cell keycloak 8 authz_nested_rest 21.0 395.0 0.0 0
# Zitadel: the capability-gap arm. Deliberately given a FLAT pair — the exact
# data shape that would tempt a naive reader into "constant-cost nested check".
mk_cell zitadel 0 authz_nested_rest 8.0 1100.0 0.0 0
mk_cell zitadel 8 authz_nested_rest 8.1 1098.0 0.0 0

rc=0
python3 "$HERE/nested_report.py" --results "$SWEEP" >"$FIX/report.log" 2>&1 || rc=$?
SUMMARY="$SWEEP/SUMMARY.md"
if [ "$rc" -ne 0 ]; then
  note "nested_report.py exited $rc on an all-valid fixture: $(cat "$FIX/report.log")"
  fail=1
fi
if [ ! -s "$SUMMARY" ]; then
  note "nested_report.py wrote no SUMMARY.md"
  fail=1
else
  # The capability-gap arm must be refused a slope, by name.
  if ! grep -q "Depth-invariant by construction" "$SUMMARY"; then
    note "the zitadel arm was not labelled depth-invariant — a flat ladder would read as a measurement result."
    fail=1
  fi
  # Exactly the three non-invariant series get a sensitivity line
  # (axiam REST, axiam gRPC, keycloak REST) — never four.
  n_slopes="$(grep -c 'Depth sensitivity,' "$SUMMARY" || true)"
  if [ "$n_slopes" != "3" ]; then
    note "expected 3 depth-sensitivity statements (axiam REST/gRPC, keycloak REST), found $n_slopes"
    fail=1
  fi
  # Both transports must appear as their own ladders.
  for want in "axiam — REST" "axiam — gRPC" "keycloak — REST" "zitadel — REST"; do
    if ! grep -qF "$want" "$SUMMARY"; then
      note "SUMMARY.md is missing the '$want' ladder"
      fail=1
    fi
  done
  # The gRPC ladder must never enter a cross-target row.
  if awk '/^## Cross-target/,/^## /' "$SUMMARY" | grep -q "gRPC p95"; then
    note "the AXIAM-only gRPC ladder leaked into the cross-target table"
    fail=1
  fi
fi

# --- 5. An invalid rung must be reported AND must fail the exit code --------
mk_cell axiam 16 authz_nested_rest 999.0 3.0 0.42 1
rc=0
python3 "$HERE/nested_report.py" --results "$SWEEP" >"$FIX/report2.log" 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then
  note "nested_report.py exited 0 with an invalid rung present — a broken ladder would look publishable."
  fail=1
fi
if ! grep -q "Invalid rungs" "$SUMMARY"; then
  note "an invalid rung was not listed in the summary's 'Invalid rungs' table"
  fail=1
fi

# --- 6. The depth knob must reach meta.json --------------------------------
# run_one()'s meta template is the only place the sweep's rung label is
# recorded; nested_report.py reads `nested_authz.depth` and skips any cell
# without it, so a template that stopped emitting it would produce an EMPTY
# summary rather than a wrong one — silent either way.
if ! grep -q '"nested_authz"' "$HERE/run-benchmark.sh"; then
  note "run-benchmark.sh's meta.json template no longer emits nested_authz — every rung would be unlabelled."
  fail=1
fi
if ! grep -q 'BENCH_AUTHZ_DEPTH' "$HERE/run-benchmark.sh"; then
  note "run-benchmark.sh no longer records BENCH_AUTHZ_DEPTH into meta.json"
  fail=1
fi

# --- 7. The justfile ladder validator rejects a malformed depth -------------
# Guarded on `just` being present: this is the only assertion that needs it,
# and the rest of the suite must still run on a machine without it. The
# validator runs BEFORE any bring-up, so no docker is involved either way.
if command -v just >/dev/null 2>&1; then
  if ( cd "$BENCH" && just nesteddepths="0 notanumber" bench-nested ) >"$FIX/just.log" 2>&1; then
    note "'just nesteddepths=\"0 notanumber\" bench-nested' did NOT fail — a malformed rung would clamp to depth 0 and be filed under the depth nobody ran."
    fail=1
  fi
  if ( cd "$BENCH" && just nesteddepths="99" bench-nested ) >"$FIX/just2.log" 2>&1; then
    note "'just nesteddepths=\"99\" bench-nested' did NOT fail — depth 99 exceeds MAX_NESTED_DEPTH and would measure AXIAM's depth-overflow error path."
    fail=1
  fi
else
  echo "[nested-selftest] note: 'just' not installed — skipping the ladder-validator assertions."
fi

[ "$fail" -eq 0 ] || { note "FAILED"; exit 1; }
echo "[nested-selftest] OK — sweep cells stay out of the default matrix, the gRPC arm stays AXIAM-only, and the capability-gap arm is refused a depth slope."
