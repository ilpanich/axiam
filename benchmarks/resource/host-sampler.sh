#!/usr/bin/env bash
# host-sampler.sh — sample host-level telemetry (CPU frequency, thermal, host
# utilization, k6 CPU headroom) at a fixed cadence over the measure window.
#
# This is the thermal-throttling honesty telemetry (A6 in
# claude_dev/benchmark-improvement-plan.md): docker stats (resource/sampler.sh)
# measures time-based core utilization and cannot tell a core running at
# 3.9 GHz from one at 2.2 GHz. A *constant* sustained-clock reduction would
# depress absolute numbers uniformly and be invisible to it — this script
# records the clock/thermal state directly so the report can say so honestly.
#
# Writes one CSV row per sample over the measure window:
#   epoch_ms,cpu_mhz_avg,cpu_mhz_min,temp_c_max,host_cpu_util_pct,k6_cpu_cores
#
# All sources are no-sudo:
#   - cpu_mhz_avg/min: mean/min over /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq
#   - temp_c_max:      max over /sys/class/thermal/thermal_zone*/temp (skips
#                      zones that error to read; value is milli-C, divided by 1000)
#   - host_cpu_util_pct: delta of (total-idle)/total between samples, from /proc/stat
#   - k6_cpu_cores:    sum of %cpu (as cores, i.e. /100) for `pgrep -x k6` processes
#
# A host with no cpufreq driver (e.g. some VMs/containers) reports 0 for the
# MHz columns rather than failing — the columns are best-effort telemetry, not
# a validity gate.
#
# Usage: host-sampler.sh <out.csv> <interval-seconds> <duration-seconds>
set -euo pipefail

OUT="${1:?output csv path}"
INTERVAL="${2:-1}"
DURATION="${3:-120}"

echo "epoch_ms,cpu_mhz_avg,cpu_mhz_min,temp_c_max,host_cpu_util_pct,k6_cpu_cores" > "$OUT"

# Read the aggregate `cpu ` line from /proc/stat as "idle total" (jiffies).
read_proc_stat() {
  awk '/^cpu /{
    idle = $5
    total = 0
    for (i = 2; i <= NF; i++) total += $i
    print idle, total
  }' /proc/stat
}

prev_idle=0
prev_total=0
read -r prev_idle prev_total < <(read_proc_stat)

end=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$end" ]; do
  ts=$(($(date +%s%N)/1000000))

  # --- CPU frequency (mean/min), MHz, over all online cores -----------------
  mhz_avg=0
  mhz_min=0
  freqs=()
  for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq; do
    [ -r "$f" ] || continue
    v="$(cat "$f" 2>/dev/null || echo '')"
    [ -n "$v" ] && freqs+=("$v")
  done
  if [ "${#freqs[@]}" -gt 0 ]; then
    mhz_avg="$(printf '%s\n' "${freqs[@]}" | awk '{s+=$1; n++} END{if(n>0) printf "%.1f", s/n/1000; else print 0}')"
    mhz_min="$(printf '%s\n' "${freqs[@]}" | awk 'NR==1{m=$1} {if($1<m) m=$1} END{printf "%.1f", m/1000}')"
  fi

  # --- Thermal: max zone temperature, C -------------------------------------
  temp_max=0
  for z in /sys/class/thermal/thermal_zone*/temp; do
    [ -r "$z" ] || continue
    t="$(cat "$z" 2>/dev/null || echo '')"
    [ -z "$t" ] && continue
    t_c="$(awk -v t="$t" 'BEGIN{printf "%.1f", t/1000}')"
    if awk -v a="$t_c" -v b="$temp_max" 'BEGIN{exit !(a>b)}'; then temp_max="$t_c"; fi
  done

  # --- Host CPU utilization: delta of (total-idle)/total --------------------
  host_util=0
  idle=0; total=0
  read -r idle total < <(read_proc_stat)
  d_idle=$(( idle - prev_idle ))
  d_total=$(( total - prev_total ))
  if [ "$d_total" -gt 0 ]; then
    host_util="$(awk -v di="$d_idle" -v dt="$d_total" 'BEGIN{printf "%.1f", (1 - di/dt) * 100}')"
  fi
  prev_idle=$idle; prev_total=$total

  # --- k6 CPU headroom: sum %cpu across k6 processes, as cores --------------
  k6_cores=0
  k6_pids="$(pgrep -x k6 2>/dev/null | paste -sd, - || true)"
  if [ -n "$k6_pids" ]; then
    k6_cores="$(ps -o %cpu= -p "$k6_pids" 2>/dev/null | awk '{s+=$1} END{printf "%.2f", s/100}')"
    [ -n "$k6_cores" ] || k6_cores=0
  fi

  echo "${ts},${mhz_avg},${mhz_min},${temp_max},${host_util},${k6_cores}" >> "$OUT"
  sleep "$INTERVAL"
done

echo "[host-sampler] wrote $(($(wc -l < "$OUT") - 1)) samples to $OUT" >&2
