#!/usr/bin/env bash
# sampler.sh — sample CPU + memory of a target's containers via `docker stats`.
#
# Writes one CSV row per sample over the measure window:
#   epoch_ms,container,cpu_cores,mem_mib
#
# CPU is normalised to cores (docker reports % of a single core, so 200% = 2.0
# cores). The report aggregates these into cpu_cores_avg/p95 and mem_mib_avg/p95
# and combines with k6 throughput to derive efficiency metrics.
#
# Usage: sampler.sh <name-filter> <out.csv> <interval-seconds> <duration-seconds>
set -euo pipefail

FILTER="${1:?container name filter, e.g. bench-axiam}"
OUT="${2:?output csv path}"
INTERVAL="${3:-1}"
DURATION="${4:-120}"

echo "epoch_ms,container,cpu_cores,mem_mib" > "$OUT"

end=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$end" ]; do
  ts=$(($(date +%s%N)/1000000))
  # --no-stream gives one snapshot; format CPU% and MemUsage for matching containers.
  # NOTE: `grep … || true` MUST be grouped with braces. Written as
  # `stats | grep || true | while` bash parses it as `(stats|grep) || (true|while)`,
  # so the row-writing `while` only runs when grep finds NOTHING — i.e. no samples
  # are ever written on the happy path. The braces keep it one 3-stage pipeline
  # while still tolerating grep's exit 1 on a momentary no-match.
  docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' 2>/dev/null \
    | { grep -E "$FILTER" || true; } \
    | while IFS=$'\t' read -r name cpu mem; do
        [ -z "${name:-}" ] && continue
        # "12.34%" -> cores (12.34/100)
        cpu_cores=$(printf '%s' "$cpu" | sed 's/%//' | awk '{printf "%.4f", $1/100}')
        # "123.4MiB / 1GiB" -> take the used side, normalise to MiB
        used=$(printf '%s' "$mem" | awk -F'/' '{print $1}' | tr -d ' ')
        mib=$(printf '%s' "$used" | awk '
          /GiB/ {sub(/GiB/,""); printf "%.2f", $1*1024; next}
          /MiB/ {sub(/MiB/,""); printf "%.2f", $1; next}
          /KiB/ {sub(/KiB/,""); printf "%.2f", $1/1024; next}
          /GB/  {sub(/GB/,"");  printf "%.2f", $1*953.674; next}
          /MB/  {sub(/MB/,"");  printf "%.2f", $1*0.953674; next}
          /B/   {sub(/B/,"");   printf "%.4f", $1/1048576; next}
          {print "0"}')
        echo "${ts},${name},${cpu_cores},${mib}" >> "$OUT"
      done || true
  sleep "$INTERVAL"
done

echo "[sampler] wrote $(($(wc -l < "$OUT") - 1)) samples to $OUT" >&2
