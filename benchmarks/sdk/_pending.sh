#!/usr/bin/env bash
# _pending.sh — emit a valid axiam.sdk-bench/v1 record with status "pending".
# Used by language scaffolds whose SDK (already implemented in ilpanich/axiam-<lang>-sdk)
# has no bench glue wired up yet. Sourced or called as: _pending.sh <sdk-name>
emit_pending() {
  local sdk="${1:?sdk name}"
  # Every SDK is released; report its real version even in the pending fallback
  # (this path is now only hit when a package/tooling isn't installed locally).
  local ver
  case "$sdk" in
    rust) ver="1.0.0-alpha7" ;;
    python) ver="1.0.0a2" ;;
    *) ver="1.0.0-alpha2" ;;
  esac
  cat <<EOF
{
  "schema": "axiam.sdk-bench/v1",
  "sdk": "$sdk",
  "sdk_version": "$ver",
  "language_runtime": "n/a",
  "target": "${BENCH_TARGET:-axiam}",
  "profile": "${BENCH_PROFILE:-p0-plaintext}",
  "status": "pending",
  "iterations": 0,
  "concurrency": 0,
  "ops": {
    "login":         {"p50_ms":0,"p95_ms":0,"p99_ms":0,"throughput_rps":0,"errors":0},
    "refresh":       {"p50_ms":0,"p95_ms":0,"p99_ms":0,"throughput_rps":0,"errors":0},
    "check_access":  {"p50_ms":0,"p95_ms":0,"p99_ms":0,"throughput_rps":0,"errors":0},
    "batch_check":   {"p50_ms":0,"p95_ms":0,"p99_ms":0,"throughput_rps":0,"errors":0}
  },
  "client_cpu_ms_total": 0,
  "client_rss_mib_peak": 0,
  "notes": "$sdk bench is wired but its toolchain/SDK package is not installed here — see sdk/$sdk/TODO.md to run it."
}
EOF
}

# Allow direct invocation.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  emit_pending "${1:?usage: _pending.sh <sdk-name>}"
fi
