#!/usr/bin/env bash
# _pending.sh — emit a valid axiam.sdk-bench/v1 record with status "pending".
# Used by language scaffolds whose SDK (already implemented under sdks/<lang>)
# has no bench glue wired up yet. Sourced or called as: _pending.sh <sdk-name>
emit_pending() {
  local sdk="${1:?sdk name}"
  cat <<EOF
{
  "schema": "axiam.sdk-bench/v1",
  "sdk": "$sdk",
  "sdk_version": "unreleased",
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
  "notes": "SDK bench glue not yet wired — see sdk/$sdk/TODO.md (the $sdk SDK itself is implemented)."
}
EOF
}

# Allow direct invocation.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  emit_pending "${1:?usage: _pending.sh <sdk-name>}"
fi
