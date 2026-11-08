#!/usr/bin/env bash
# Does this VM deliver steady CPU? About five minutes, no containers.
#
# Runbook: claude_dev/bench-vm-runbook.md §7. Shared vCPUs lose time to other
# tenants ("steal"), and the harness records clock and temperature but not
# steal — on a VM it is the variance that would otherwise go unseen. Two checks:
#
#   1. consistency: three identical sysbench CPU runs on every vCPU; the spread
#      of their events/s;
#   2. steal under load: a fourth run with vmstat sampling beside it; the mean
#      of vmstat's `st` column.
#
# The thresholds are OPERATOR HEURISTICS chosen for this runbook, not values
# from benchmarks/docs/methodology.md:
#
#   spread <= 5 % and steal <= 2 %   PROCEED                       exit 0
#   spread <= 10 % and steal <= 5 %  PROCEED, watch the steal log  exit 0
#   otherwise                        RECREATE the instance          exit 3
#
# Results: ~/bench/logs/qualify.txt (quote it in the run notes).
#
# Usage:  ./05-qualify.sh             Then: the run, bench-vm-runbook.md §9
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"
# shellcheck source=versions.env
source "$HERE/versions.env"
need sysbench "Run 00-host-prepare.sh."
need vmstat "Run 00-host-prepare.sh."

SECS="${QUALIFY_SECS:-60}"
THREADS="$(nproc)"
mkdir -p "$BENCH_DIR/logs"
OUT="$BENCH_DIR/logs/qualify.txt"

eps() { sysbench cpu --threads="$THREADS" --time="$SECS" run | awk '/events per second/ {print $NF}'; }

say "Consistency: 3 x ${SECS}s of sysbench cpu on $THREADS threads"
runs=()
for i in 1 2 3; do runs+=("$(eps)"); ok "run $i: ${runs[-1]} events/s"; done

say "Steal under load: a fourth run with vmstat beside it"
tmp="$(mktemp)"
vmstat -n 5 $(( SECS / 5 + 1 )) > "$tmp" &
vm_pid=$!
fourth="$(eps)"
wait "$vm_pid"
# The `st` column, found by name in vmstat's header (its position moved between
# procps versions); the first sample is the since-boot average and is skipped.
steal="$(awk 'NR==2 {for (i=1;i<=NF;i++) if ($i=="st") c=i; next}
              NR>3 && c {s+=$c; n++} END {if (n) printf "%.2f", s/n; else print "nan"}' "$tmp")"
rm -f "$tmp"

read -r spread mean < <(printf '%s\n' "${runs[@]}" | awk '{v[NR]=$1; s+=$1; if (NR==1||$1<lo) lo=$1; if (NR==1||$1>hi) hi=$1}
                          END {m=s/NR; printf "%.2f %.1f\n", (hi-lo)/m*100, m}')

verdict="RECREATE"; code=3
if [[ "$steal" != nan ]]; then
    if awk -v a="$spread" -v b="$steal" 'BEGIN {exit !(a<=5 && b<=2)}'; then verdict="PROCEED"; code=0
    elif awk -v a="$spread" -v b="$steal" 'BEGIN {exit !(a<=10 && b<=5)}'; then verdict="PROCEED, watch the steal log during the run"; code=0
    fi
fi

{
    echo "# bench-vm qualify — $(date -u +%FT%TZ) — $(hostname)"
    echo "cpu:         $(lscpu | sed -n 's/^Model name: *//p' | head -1), $THREADS vCPUs"
    echo "sysbench:    ${runs[*]} events/s (mean $mean, spread ${spread} %); 4th run $fourth"
    echo "steal:       ${steal} % mean under load"
    echo "verdict:     $verdict"
    echo "thresholds:  operator heuristics (bench-vm-runbook.md §7), not methodology values"
} | tee "$OUT"

if (( code != 0 )); then
    warn "Delete the instance and create a new one (it usually lands on another hypervisor), or ask the provider about dedicated CPUs."
fi
exit "$code"
