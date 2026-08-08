#!/usr/bin/env bash
# J8 regression guard for median.py's pass provenance.
#
# Run 5 merged two of three requested C# passes and reported it as "median of
# 2 (2 ok)" — truthful about what it received, silent about what it never got.
# This builds three pass directories where one language is deliberately absent
# from one pass, and asserts the merger names the absentee and fails.
#
# Hermetic: stdlib python only, no SDK toolchains, no AXIAM stack.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

rec() {  # rec <dir> <sdk> <p95>
  mkdir -p "$1/sdk/p2-tls13"
  cat > "$1/sdk/p2-tls13/$2.json" <<EOF
{
  "schema": "axiam.sdk-bench/v1",
  "sdk": "$2",
  "profile": "p2-tls13",
  "target": "axiam",
  "status": "ok",
  "iterations": 10,
  "concurrency": 16,
  "ops": {
    "login":        { "p50_ms": 1, "p95_ms": $3, "p99_ms": 3, "throughput_rps": 10, "errors": 0 },
    "refresh":      { "p50_ms": 1, "p95_ms": $3, "p99_ms": 3, "throughput_rps": 10, "errors": 0 },
    "check_access": { "p50_ms": 1, "p95_ms": $3, "p99_ms": 3, "throughput_rps": 10, "errors": 0 },
    "batch_check":  { "p50_ms": 1, "p95_ms": $3, "p99_ms": 3, "throughput_rps": 10, "errors": 0 }
  },
  "notes": ""
}
EOF
}

# go: present in all three passes. csharp: missing from pass 2 — the run-5 shape.
for i in 1 2 3; do rec "$TMP/sdk-run-$i" go "$i"; done
rec "$TMP/sdk-run-1" csharp 1
rec "$TMP/sdk-run-3" csharp 3

fail=0

set +e
OUT="$(python3 "$HERE/median.py" --runs "$TMP/sdk-run-1" "$TMP/sdk-run-2" "$TMP/sdk-run-3" --out "$TMP/merged" 2>&1)"
RC=$?
set -e

[ "$RC" -ne 0 ] || { echo "[median-selftest] expected a non-zero exit for an incomplete merge, got 0" >&2; fail=1; }
printf '%s\n' "$OUT" | grep -q "sdk-run-2" || {
  echo "[median-selftest] the missing pass (sdk-run-2) is not named in the output:" >&2
  printf '%s\n' "$OUT" >&2; fail=1; }

CS="$TMP/merged/sdk/p2-tls13/csharp.json"
GO="$TMP/merged/sdk/p2-tls13/go.json"
[ -f "$CS" ] && [ -f "$GO" ] || { echo "[median-selftest] merged records were not written despite the failure exit — the report must still be produced" >&2; fail=1; }

python3 - "$CS" "$GO" <<'PY' || fail=1
import json, sys
cs, go = (json.load(open(p)) for p in sys.argv[1:3])
ok = True
if cs.get("passes_missing") != ["sdk-run-2"]:
    print(f"[median-selftest] csharp passes_missing={cs.get('passes_missing')!r}, want ['sdk-run-2']"); ok = False
if cs.get("passes_requested") != 3 or cs.get("passes_present") != 2:
    print(f"[median-selftest] csharp requested/present = {cs.get('passes_requested')}/{cs.get('passes_present')}, want 3/2"); ok = False
if "sdk-run-2" not in (cs.get("notes") or ""):
    print("[median-selftest] csharp notes do not name the absent pass"); ok = False
if go.get("passes_missing"):
    print(f"[median-selftest] go should be complete, got passes_missing={go.get('passes_missing')!r}"); ok = False
# The median itself must still be right: go saw p95 1, 2, 3 across passes.
if go["ops"]["check_access"]["p95_ms"] != 2:
    print(f"[median-selftest] go median p95 = {go['ops']['check_access']['p95_ms']}, want 2"); ok = False
sys.exit(0 if ok else 1)
PY

# --allow-partial is the deliberate opt-out and must succeed.
python3 "$HERE/median.py" --runs "$TMP/sdk-run-1" "$TMP/sdk-run-2" "$TMP/sdk-run-3" \
  --out "$TMP/merged2" --allow-partial >/dev/null 2>&1 || {
  echo "[median-selftest] --allow-partial should exit 0" >&2; fail=1; }

[ "$fail" -eq 0 ] || { echo "[median-selftest] FAILED" >&2; exit 1; }
echo "[median-selftest] OK — an absent pass is named, fails the merge, and still writes the records."
