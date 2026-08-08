#!/usr/bin/env bash
# Print, one per line, every file under a results tree that `just bench-pack`
# should place in a shareable archive.
#
# This lives in its own script rather than inline in the justfile for one
# reason: `bench-pack-selftest` has to exercise the SAME selection logic the
# real archive uses. Run 5 shipped an archive that silently dropped every
# investigation artifact (J13 — see PRIVATE_BENCH_ANALYSIS.md §2.6); a
# self-test that re-implemented the patterns would have agreed with the bug.
#
# Usage: pack-filelist.sh [results-dir]     (default: ./results)
set -euo pipefail

ROOT="${1:-results}"

# Two prune arms, both exclusions by construction rather than by after-the-fact
# scanning:
#
#   <root>/dry-run — a dry run writes real-LOOKING artifacts (k6 summaries,
#   res/host CSVs, meta.json) for 5-second unsettled windows. They are
#   diagnostics, never measurements, so they must never reach a shared archive.
#   meta.json does carry "dry_run": true, but pruning the whole subtree is the
#   guarantee that does not depend on anyone reading that field.
#
#   *seed* — seed material (client secrets, the bench user's password) normally
#   lives in .seed/, outside the results tree entirely, so this find never
#   reaches it. But run-benchmark.sh still honours a LEGACY seed env at
#   <root>/<target>.seed.env, and the include list below is broad enough to
#   match arbitrary new artifacts. Pruning by name keeps the legacy path out
#   without relying on bench-pack's post-pack secret scan to catch it.
#
# The include list is deliberately by EXTENSION, not by filename. The J13
# failure mode was an allow-list of five exact shapes (*.k6.json, *.res.csv,
# *.host.csv, *.meta.json, report.md) that could not anticipate
# `rl-prod-summary.md`, `h5-revocation.log`, `nsenter.log` or `sdk-report.md`.
# Matching *.md / *.log / *.csv / *.json means the NEXT investigation's
# artifact is packed by default instead of discovered missing afterwards.
find "$ROOT" \
  \( -path "$ROOT/dry-run" -o -name '*seed*' \) -prune -o \
  \( -name '*.json' -o -name '*.csv' -o -name '*.md' -o -name '*.log' \
  -o -name '*.txt' -o -name '*.tsv' \) -type f -print
