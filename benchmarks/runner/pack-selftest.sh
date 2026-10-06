#!/usr/bin/env bash
# J13/E2 regression guard for the `bench-pack` manifest.
#
# Builds a fixture results tree carrying one of every artifact shape run 5
# produced, runs the REAL selection logic (pack-filelist.sh — not a
# re-implementation of it, which would have agreed with the bug) over that
# tree, and asserts both directions:
#
#   * every investigation artifact survives — run 5's shareable archive
#     silently dropped `rl-prod-summary.md`, `sdk-report.md`, `nsenter.log`
#     and `h5-revocation.log`, i.e. exactly the files carrying the verdicts
#     (PRIVATE_BENCH_ANALYSIS.md §2.6);
#   * nothing from `dry-run/` or a seed file does — a dry run's artifacts are
#     diagnostics that must never be mistaken for measurements, and seed files
#     hold client secrets.
#
# Hermetic: no docker, no k6, no seeded stack. Runs in CI on every PR.
# Usage: pack-selftest.sh          (from benchmarks/)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT

mkdir -p "$FIX/axiam/p2-tls13" "$FIX/dry-run/axiam/p2-tls13" "$FIX/section-12_4-B1"

# --- must survive: the five shapes the old allow-list already handled ...
: > "$FIX/axiam/p2-tls13/authz_check_rest.k6.json"
: > "$FIX/axiam/p2-tls13/authz_check_rest.res.csv"
: > "$FIX/axiam/p2-tls13/authz_check_rest.host.csv"
: > "$FIX/axiam/p2-tls13/authz_check_rest.meta.json"
: > "$FIX/report.md"
# ... and the four J13 dropped in run 5.
: > "$FIX/rl-prod-summary.md"
: > "$FIX/sdk-report.md"
: > "$FIX/section-12_4-B1/nsenter.log"
: > "$FIX/section-12_4-B1/h5-revocation.log"

# ... and the shapes run 6 adds (T23.10.2(a)): the pinned-image table, the at-rest
# memory samples of each stack, the minimal-profile tree, and the investigation logs.
mkdir -p "$FIX/provenance" "$FIX/resting/keycloak" "$FIX/resting/axiam-minimal" \
         "$FIX/minimal-profile/run-1/axiam/p0-plaintext" "$FIX/investigations"
: > "$FIX/provenance/images.txt"
for stage in fresh fixture; do
  : > "$FIX/resting/keycloak/$stage-samples.csv"
  : > "$FIX/resting/keycloak/$stage-summary.txt"
  : > "$FIX/resting/keycloak/$stage-meta.json"
done
: > "$FIX/resting/axiam-minimal/fixture-summary.txt"
: > "$FIX/minimal-profile/run-1/axiam/p0-plaintext/jwks_fetch.meta.json"
: > "$FIX/minimal-profile/run-1/axiam/p0-plaintext/jwks_fetch.k6.json"
: > "$FIX/investigations/refresh-stage-timings.log"
: > "$FIX/RUN6-NOTES.md"

# --- must NOT survive
: > "$FIX/dry-run/axiam/p2-tls13/authz_check_rest.k6.json"
: > "$FIX/dry-run/axiam/p2-tls13/authz_check_rest.meta.json"
: > "$FIX/dry-run/SUMMARY.md"
: > "$FIX/axiam.seed.env"
: > "$FIX/axiam.seed.ok"

LIST="$(bash "$HERE/pack-filelist.sh" "$FIX")"
fail=0

for want in images.txt fresh-summary.txt fixture-summary.txt fixture-samples.csv fixture-meta.json \
            refresh-stage-timings.log RUN6-NOTES.md \
            rl-prod-summary.md sdk-report.md nsenter.log h5-revocation.log \
            report.md authz_check_rest.k6.json authz_check_rest.res.csv \
            authz_check_rest.host.csv authz_check_rest.meta.json; do
  printf '%s\n' "$LIST" | grep -q "/$want\$" || {
    echo "[pack-selftest] MISSING from the archive manifest: $want" >&2; fail=1; }
done

# Match on the path RELATIVE to the fixture root: $FIX is a mktemp path that
# could itself contain either word, which would make this assertion fire on
# the harness rather than on the manifest.
REL="$(printf '%s\n' "$LIST" | sed "s|^$FIX/||")"
for deny in dry-run seed; do
  if printf '%s\n' "$REL" | grep -q -- "$deny"; then
    echo "[pack-selftest] LEAKED into the archive manifest (matched '$deny'):" >&2
    printf '%s\n' "$REL" | grep -- "$deny" >&2
    fail=1
  fi
done

[ "$fail" -eq 0 ] || { echo "[pack-selftest] FAILED" >&2; exit 1; }
echo "[pack-selftest] OK — $(printf '%s\n' "$LIST" | wc -l | tr -d ' ') files selected; investigation artifacts kept, dry-run/seed excluded."
