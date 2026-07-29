#!/usr/bin/env bash
# run-improvement-tasks.sh — per-task data collection for the pre-MVP plan
# (claude_dev/improvement-after-serious-benchmark.md).
#
# Every task in that plan that needs a LIVE benchmark run has a subcommand
# here. Each subcommand is standalone: bring the stack up, collect exactly the
# data that task's decision needs, tear the stack down, and write a
# SUMMARY.md with the measured numbers plus the acceptance criterion, so the
# task can be closed (or a follow-up opened) from the summary alone.
#
# Run them one at a time, in whatever spare time you have:
#
#   cd benchmarks
#   ./run-improvement-tasks.sh list                # what exists + time estimates
#   ./run-improvement-tasks.sh g1-timeline         # start here (blocks G2/G3/G8)
#   ./run-improvement-tasks.sh g3-batch            # etc.
#   ./run-improvement-tasks.sh pack                # shareable archive at the end
#
# Results land under results/tasks/<task>/ (own subtree per task, so nothing
# collides with the matrix in results/run-*/). Each task prints its verdict at
# the end and writes it to results/tasks/<task>/SUMMARY.md.
#
# Laptop prep (per docs/methodology.md §10) applies to every task: on AC power,
# `sudo cpupower frequency-set -g performance`, background apps closed, and the
# whole session in ONE turbo mode. The runner warns if the governor is wrong.
set -euo pipefail
cd "$(dirname "$0")"
BENCH_DIR=$PWD

TASKS_ROOT=$PWD/results/tasks
PLAN=../claude_dev/improvement-after-serious-benchmark.md

# Container names are fixed by the compose files (targets/axiam/docker-compose.yml).
C_SERVER=bench-axiam-server
C_DB=bench-axiam-surrealdb
C_MQ=bench-axiam-rabbitmq

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

log()  { printf '\n\033[1;36m[%s]\033[0m %s\n' "${TASK:-run}" "$*"; }
warn() { printf '\033[1;33m[%s] WARNING: %s\033[0m\n' "${TASK:-run}" "$*" >&2; }
die()  { printf '\033[1;31m[%s] ERROR: %s\033[0m\n' "${TASK:-run}" "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null || die "$1 is required but not installed"; }
need_base() { need docker; need just; need k6; need python3; }

# H1 item 2: fail-fast guard against the same "wrong results dir" fault class
# as the bench-matrix clobber bug (benchmarks/justfile) — every artifact this
# script writes must land under results/tasks/<task-id>/, nothing else. $1
# must already exist (callers `mkdir -p` first) so `cd .. && pwd` can resolve
# it to a real absolute path; compared as a real path prefix (not a string
# prefix) so e.g. "results/tasks/g2-verify-evil" cannot falsely match
# "results/tasks/g2-verify".
assert_within_tasks_root() { # $1=dir (already created)
  local dir="$1" abs
  abs="$(cd "$dir" && pwd)" || die "internal: cannot resolve results dir '$dir'"
  case "$abs" in
    "$TASKS_ROOT"|"$TASKS_ROOT"/*) : ;;
    *) die "internal: refusing to write outside $TASKS_ROOT (resolved '$dir' -> '$abs') — results-dir clobber guard" ;;
  esac
}

# Stack lifecycle. Any extra AXIAM__* knobs are passed as leading env assignments
# by the caller (they reach the server through the compose pass-through).
#
# TASK_OUT (set by each task right after summary_open) is where seeding writes
# its `<target>.seed.ok` marker. run-benchmark.sh REFUSES to start a cell unless
# that marker exists in the cell's own BENCH_RESULTS_DIR (A2.3 fail-closed
# gate), and every cell here gets its own directory so repeats don't overwrite
# each other — so `cell` copies the marker in. Seeding once per stack and
# reusing the marker is exactly right: it is a "this stack was provisioned and
# smoke-checked" flag, not per-cell state.
TASK_OUT=""

bench_up_seed() { # $1=target [$2=profile] [$3.. extra just args]
  local target=$1 profile=${2:-p0-plaintext}; shift 2 || shift $# || true
  [ -n "$TASK_OUT" ] || die "internal: TASK_OUT not set before bench_up_seed"
  mkdir -p "$TASK_OUT"
  assert_within_tasks_root "$TASK_OUT"
  log "bringing up $target ($profile) and seeding"
  BENCH_RESULTS_DIR="$TASK_OUT" just target="$target" profile="$profile" "$@" bench-up
  BENCH_RESULTS_DIR="$TASK_OUT" just target="$target" profile="$profile" "$@" bench-seed
  [ -f "$TASK_OUT/${target}.seed.ok" ] || \
    warn "no seed-ok marker at $TASK_OUT/${target}.seed.ok — cells will refuse to start"
}

bench_down() { # $1=target [$2=profile]
  just target="${1}" profile="${2:-p0-plaintext}" bench-down >/dev/null 2>&1 || true
}

# Run ONE k6 cell into its own results subtree.
# usage: cell <target> <profile> <scenario.js> <outdir>
# NOTE: run-benchmark.sh writes the cell files to <outdir>/<target>/<profile>/,
# so always locate artifacts with k6_file/res_files (which recurse), never with
# a flat <outdir>/*.k6.json glob.
cell() {
  local target=$1 profile=$2 scenario=$3 outdir=$4
  mkdir -p "$outdir"
  assert_within_tasks_root "$outdir"
  [ -f "$TASK_OUT/${target}.seed.ok" ] && cp "$TASK_OUT/${target}.seed.ok" "$outdir/"
  BENCH_RESULTS_DIR="$outdir" just target="$target" profile="$profile" \
    scenario="$scenario" bench-run
}

# Throughput (successful ops/s) + p50/p95 + fallback count from a k6 summary.
# usage: k6_stat <file.k6.json> <thr|p50|p95|fallback|err>
k6_stat() {
  python3 - "$1" "$2" <<'PY'
import json, sys
try:
    m = json.load(open(sys.argv[1]))["metrics"]
except Exception:
    print("NA"); raise SystemExit
what = sys.argv[2]
lat = m.get("bench_op_latency_ms", {})
vals = {
    "thr": m.get("bench_ok", {}).get("rate"),
    "p50": lat.get("med"),
    "p95": lat.get("p(95)"),
    "fallback": m.get("bench_fallback", {}).get("count", 0),
    "err": m.get("bench_error_rate", {}).get("value"),
}
v = vals.get(what)
print("NA" if v is None else (f"{v:.1f}" if isinstance(v, float) else v))
PY
}

# Find the single .k6.json a cell produced (scenario name varies).
k6_file() { find "$1" -name '*.k6.json' -print -quit 2>/dev/null; }

# --- reading the running stack's own configuration ---------------------------
# `just bench-up` bootstraps throwaway DB credentials inside its own recipe
# shell (AXIAM__DB__USERNAME=bench / AXIAM__DB__PASSWORD=bench-local-only-pw)
# and writes them to no file, so neither this script's environment nor
# docker/.secrets/env knows them on a machine that never supplied real ones.
# The containers are the source of truth, whatever the credentials came from.

# Value of one env var inside a running container ("" if absent/not running).
container_env() { # $1=container $2=VAR
  docker inspect "$1" -f '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | sed -n "s/^$2=//p" | head -1 || true
}

# Value following a flag on a running container's command line ("" if absent) —
# the datastore takes its credentials as `start --user X --pass Y ...`.
container_cmd_flag() { # $1=container $2=flag (e.g. --pass)
  docker inspect "$1" -f '{{json .Config.Cmd}}' 2>/dev/null \
    | python3 -c '
import json, sys
try:
    argv = json.load(sys.stdin)
except Exception:
    raise SystemExit
if not isinstance(argv, list):
    raise SystemExit
flag = sys.argv[1]
print(next((argv[i + 1] for i, v in enumerate(argv) if v == flag and i + 1 < len(argv)), ""))
' "$2" || true
}

# --- talking to SurrealDB with no AXIAM in the path (g1-dbdirect) ------------
# `surreal sql` is an SQL REPL "with pipe support" — it has NO --query flag
# (passing one aborts with "unexpected argument '--query' found" before it ever
# connects). The statement goes in on STDIN, which is why the container needs
# `docker run -i`. Set by task_g1_dbdirect once it has resolved the running
# stack's own connection details.
DBD_NET=""; DBD_IMG=""; DBD_USER=""; DBD_PASS=""

# H1 item 4: the probe statement, in ONE place so the pre-flight, the timing
# loop and the manual-fallback snippet in the summary cannot drift apart.
#
# This is the ACTUAL query the authz hot path issues — copied from
# `SurrealPermissionRepository::get_role_permission_grants_for_roles`
# (crates/axiam-db/src/repository/permission.rs, the query D6
# `claude_dev/surrealdb-tuning-report.md` §2 names as round-trip 4, the last
# of the 3-4 serial round-trips `axiam-authz::engine::check_access` makes per
# check), same SELECT list and the same `out.*` dereference of every `grants`
# edge — the only change is dropping `AND meta::id(in) IN $role_ids`, since a
# bare `surreal sql` session run from this script (no AXIAM code, no seed
# lookup) has no bound role UUIDs to hand it; `out.tenant_id != NONE` keeps
# the same "every edge must dereference `out`" cost shape without needing
# one. The table is `grants` (`RELATE role -> grants -> permission`); there
# is NO `role_permission_grant` table — that is the Rust *method* name.
DBD_QUERY='SELECT meta::id(in) AS role_id, meta::id(out.id) AS record_id, out.tenant_id AS tenant_id, out.action AS action, out.description AS description, out.created_at AS created_at, out.updated_at AS updated_at, scope_ids FROM grants WHERE out.tenant_id != NONE;'

surreal_direct() { # $1=statement -> JSON result on stdout, diagnostics on stderr
  printf '%s\n' "$1" | docker run --rm -i --network "$DBD_NET" "$DBD_IMG" sql \
    --endpoint "http://$C_DB:8000" --username "$DBD_USER" --password "$DBD_PASS" \
    --namespace axiam --database axiam --hide-welcome --json
}

# H1 item 4: a single long-lived `surreal sql` session shared across the
# whole timing loop, instead of one `docker run` PER QUERY (the old
# surreal_direct() above — kept only for the pre-flight and the manual
# fallback snippet, both one-shot). A fresh `docker run` pays container-start
# overhead (~500 ms, measured) on every iteration, which used to swamp the
# actual query latency the probe exists to measure. Started with bash
# `coproc` so this script can write one statement to its stdin and read
# exactly one result back per round trip, same shape as the real hot path's
# "await one query, get one result" pattern. `surreal sql --json` prints
# each result as one compact JSON line followed by ONE blank separator line
# (verified empirically — `DEFINE TABLE ...` -> `[null]\n\n`, a SELECT ->
# `[[{...}]]\n\n`); dbd_read_result skips blank lines to land on the next
# real result.
DBD_COPROC_PID=""
dbd_session_start() { # sets DBD_COPROC[0]/[1] (bash coproc fds) + DBD_COPROC_PID
  coproc DBD_COPROC { docker run --rm -i --network "$DBD_NET" "$DBD_IMG" sql \
    --endpoint "http://$C_DB:8000" --username "$DBD_USER" --password "$DBD_PASS" \
    --namespace axiam --database axiam --hide-welcome --json ; }
  # `coproc NAME { ... }` makes bash set NAME_PID (DBD_COPROC_PID) itself —
  # no manual assignment needed (and $COPROC_PID only exists for the
  # anonymous `coproc { ... }` form, not this named one).
  sleep 1  # let the container's TCP handshake + auth land before the first send
}

dbd_session_stop() {
  [ -n "$DBD_COPROC_PID" ] || return 0
  exec {DBD_COPROC[1]}>&- 2>/dev/null || true   # close stdin -> surreal sql exits
  wait "$DBD_COPROC_PID" 2>/dev/null || true
  DBD_COPROC_PID=""
}

# Sends one statement on the open session and reads back its one result line
# (skipping the blank separator line(s) surreal sql --json emits). Returns 1
# (result on stdout is empty) if the session's stdout closed / errored.
dbd_session_query() { # $1=statement -> result JSON line on stdout
  printf '%s\n' "$1" >&"${DBD_COPROC[1]}" || return 1
  local line
  while IFS= read -r -u "${DBD_COPROC[0]}" line; do
    [ -n "$line" ] && { printf '%s\n' "$line"; return 0; }
  done
  return 1
}

# Did that statement actually succeed? The exit status alone cannot tell you:
# ONLY connection/auth failures exit non-zero. A missing or renamed table exits
# 0 and reports `["The table 'x' does not exist"]` on stdout; a parse error
# exits 0 having printed nothing at all on stdout. So judge the SHAPE of the
# result instead — a statement that ran returns a list of ROWS
# (`[[{"count":N}]]`), a rejected one returns a bare string — scanning from the
# last line up so a trailing diagnostic cannot fool it.
surreal_result_ok() { # stdin = combined output of ONE surreal_direct call
  python3 -c '
import json, sys
for line in reversed(sys.stdin.read().splitlines()):
    line = line.strip()
    if not line:
        continue
    try:
        res = json.loads(line)
    except ValueError:
        continue          # a stderr diagnostic, not the result — keep looking
    sys.exit(0 if isinstance(res, list) and res and not isinstance(res[0], str) else 1)
sys.exit(1)                # no JSON at all (parse error / never connected)
'
}

# Continuous telemetry: per-container CPU/mem AND RabbitMQ queue depth, 1 Hz.
# The queue depth is what distinguishes the "audit backlog" hypothesis (G1).
#
# The PID comes back in the global SAMPLER_PID rather than on stdout, and it is
# deliberately NOT called as `pid=$(sampler_start ...)`. Command substitution
# reads its child's stdout until EOF, and this function backgrounds a subshell
# that never exits — the subshell inherits the substitution pipe as fd 1 and
# holds it open forever, so EOF never arrives and the caller blocks in read()
# for good. Worse, an async command in a non-interactive shell has SIGINT set
# to ignore (POSIX, job control off), so the sampler survives Ctrl-C while the
# parent stays blocked on it: the run becomes uninterruptible and only SIGTERM
# ends it. Keeping the PID off stdout also makes the sampler a direct child of
# this shell, so `wait` in sampler_stop actually reaps it.
SAMPLER_PID=""
sampler_start() { # $1=csv  -> sets SAMPLER_PID
  local out=$1
  echo "epoch_s,container,cpu_cores,mem_mib,mq_messages" > "$out"
  (
    while :; do
      local now; now=$(date +%s)
      docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' 2>/dev/null \
        | grep '^bench-' \
        | while IFS=$'\t' read -r name cpu mem; do
            local cores used
            cores=$(printf '%s' "$cpu" | tr -d '%' | awk '{printf "%.4f", $1/100}')
            used=$(printf '%s' "$mem" | awk -F'/' '{print $1}' | tr -d ' ' \
              | awk '/GiB/{printf "%.1f", $1*1024; next} /MiB/{printf "%.1f", $1+0; next} /KiB/{printf "%.2f", $1/1024; next} {print 0}')
            printf '%s,%s,%s,%s,\n' "$now" "$name" "$cores" "$used" >> "$out"
          done
      # Total ready+unacked messages across all queues (best effort: the broker
      # may not be up, or rabbitmqctl may be slow — never fail the probe on it).
      local depth
      depth=$(docker exec "$C_MQ" rabbitmqctl list_queues messages --no-table-headers 2>/dev/null \
              | awk '{s+=$1} END{print s+0}') || depth=""
      [ -n "$depth" ] && printf '%s,%s,,,%s\n' "$(date +%s)" "$C_MQ-queues" "$depth" >> "$out"
      sleep 1
    done
  ) >/dev/null 2>&1 &
  SAMPLER_PID=$!
}

sampler_stop() { # $1=pid
  [ -n "${1:-}" ] || return 0
  kill "$1" 2>/dev/null || true
  # The subshell's in-flight `sleep` / `docker exec` child outlives the kill;
  # take the whole family down so nothing keeps writing telemetry.csv.
  pkill -P "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

# Cleanup must be ARMED BEFORE the first long-running child of a task starts,
# not after — a trap installed on the line below a hang never runs at all, which
# is how interrupted G1 tasks used to leave their bench containers up. INT/TERM
# are trapped alongside EXIT so Ctrl-C tears the stack down instead of orphaning
# it.
CLEANUP_TARGET=""
CLEANUP_PROFILE=""
cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ -n "${SAMPLER_PID:-}" ]; then sampler_stop "$SAMPLER_PID"; SAMPLER_PID=""; fi
  if [ -n "$CLEANUP_TARGET" ]; then
    # Only reached when a task did NOT finish normally (the clean paths disarm
    # first), so say so — bench_down itself is silent.
    warn "interrupted — tearing down the $CLEANUP_TARGET stack"
    bench_down "$CLEANUP_TARGET" "$CLEANUP_PROFILE"
    CLEANUP_TARGET=""; CLEANUP_PROFILE=""
  fi
  return $rc
}
# Re-arming is cheap and idempotent: tasks that cycle several stacks (g3/g4/g5/
# g8) call this again before each bench_up_seed so the trap always names the
# stack that is actually up. An empty profile falls back to bench_down's default.
arm_cleanup() { # $1=target [$2=profile]
  CLEANUP_TARGET=$1
  CLEANUP_PROFILE=${2:-}
  # `|| true` keeps `set -e` from aborting cleanup half-way when the task is
  # dying on a non-zero status — teardown must always run to completion.
  trap 'cleanup || true; exit 130' INT TERM
  trap 'cleanup || true' EXIT
}
disarm_cleanup() { trap - EXIT INT TERM; CLEANUP_TARGET=""; CLEANUP_PROFILE=""; }

# Mean CPU of one container over a time range in the sampler CSV.
cpu_mean() { # $1=csv $2=container-substring [$3=from_epoch] [$4=to_epoch]
  python3 - "$@" <<'PY'
import csv, sys
path, sub = sys.argv[1], sys.argv[2]
lo = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else 0
hi = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else 10**12
vals = []
for r in csv.DictReader(open(path)):
    if sub in r["container"] and r["cpu_cores"] and lo <= int(r["epoch_s"]) <= hi:
        vals.append(float(r["cpu_cores"]))
print(f"{sum(vals)/len(vals):.2f}" if vals else "NA")
PY
}

summary_open() { # $1=outdir $2=title
  SUMMARY=$1/SUMMARY.md
  TASK_OUT=$1
  mkdir -p "$1"
  assert_within_tasks_root "$1"
  {
    echo "# $2"
    echo
    echo "- collected: $(date -Iseconds)"
    echo "- host: $(uname -srm) · governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
    echo "- plan: \`claude_dev/improvement-after-serious-benchmark.md\`"
    echo
  } > "$SUMMARY"
}
s() { echo "$*" >> "$SUMMARY"; }          # write a summary line
sp() { echo "$*" | tee -a "$SUMMARY"; }   # write AND print

finish() {
  echo
  log "done — summary written to ${SUMMARY#$BENCH_DIR/}"
  echo "----------------------------------------------------------------"
  cat "$SUMMARY"
  echo "----------------------------------------------------------------"
}

# ---------------------------------------------------------------------------
# G1 — post-seed serialized-DB transient (Opus task; these are its probes)
# ---------------------------------------------------------------------------
# The plan's G1 asks: reproduce the window, then bisect the trigger. These three
# probes answer, in order: WHEN does it end, is it TIME-based or TRAFFIC-based,
# and is it the SERVER or the DATASTORE. Run g1-timeline first.

task_g1_timeline() {
  need_base
  local out=$TASKS_ROOT/g1-timeline
  rm -rf "$out"; summary_open "$out" "G1 — post-seed transient: recovery timeline"
  local iters=${G1_ITERS:-20} dur=${G1_CELL_SECS:-20}

  # The settle gate (G2) exists precisely to hide this window — turn it OFF here,
  # measuring the window IS the point. Harmless if the knob isn't present yet.
  export BENCH_SETTLE=0
  export BENCH_WARMUP=5s BENCH_DURATION=${dur}s BENCH_VUS=${G1_VUS:-50}

  arm_cleanup axiam
  bench_up_seed axiam
  local t0; t0=$(date +%s)
  local tel=$out/telemetry.csv; sampler_start "$tel"

  s "Probe: immediately after \`bench-seed\`, run ${iters} short authz_check_rest cells"
  s "(${dur}s measured each, ${BENCH_VUS} VUs) and watch when throughput recovers."
  s
  s "| # | minutes after seed | thr (ops/s) | p50 (ms) | DB CPU (cores) | server CPU |"
  s "|---|---|---|---|---|---|"

  local recovered_at=""
  for i in $(seq 1 "$iters"); do
    local d=$out/iter-$(printf '%02d' "$i") cs ce
    cs=$(date +%s)
    cell axiam p0-plaintext authz_check_rest.js "$d" >/dev/null 2>&1 || warn "cell $i failed"
    ce=$(date +%s)
    local f thr p50 dbcpu srvcpu mins
    f=$(k6_file "$d"); thr=NA; p50=NA
    [ -n "$f" ] && { thr=$(k6_stat "$f" thr); p50=$(k6_stat "$f" p50); }
    dbcpu=$(cpu_mean "$tel" "$C_DB" "$cs" "$ce")
    srvcpu=$(cpu_mean "$tel" "$C_SERVER" "$cs" "$ce")
    mins=$(awk -v a="$cs" -v b="$t0" 'BEGIN{printf "%.1f", (a-b)/60}')
    sp "| $i | $mins | $thr | $p50 | $dbcpu | $srvcpu |"
    # First cell to clear 2x the clamped rate counts as recovery.
    if [ -z "$recovered_at" ] && [ "$thr" != NA ] \
       && awk -v t="$thr" 'BEGIN{exit !(t > 200)}'; then
      recovered_at=$mins
    fi
  done

  sampler_stop "$SAMPLER_PID"; SAMPLER_PID=""; disarm_cleanup; bench_down axiam
  s
  s "## Verdict"
  if [ -n "$recovered_at" ]; then
    s "- Transient REPRODUCED and ended at **~${recovered_at} min** after seed."
  else
    s "- No recovery within $(awk -v i="$iters" -v d="$dur" 'BEGIN{printf "%.0f", i*(d+35)/60}') min — either the window is longer than this probe, or it did not reproduce. Check the table: a sustained ~45 ops/s with DB ≈1.0 core IS the transient; a healthy stack reads ~740 ops/s with DB ≈2.0."
  fi
  s "- Queue-depth column of \`telemetry.csv\` (rows tagged \`$C_MQ-queues\`): if the"
  s "  audit backlog drains to ~0 at the same minute throughput recovers, the AMQP"
  s "  ingestion hypothesis is supported; if the queue is empty throughout, it is refuted."
  s "- Next: \`g1-idle\` (time-based vs traffic-based) and \`g1-isolate\` (server vs datastore)."
  finish
}

task_g1_idle() {
  need_base
  local out=$TASKS_ROOT/g1-idle
  rm -rf "$out"; summary_open "$out" "G1 — is the window time-based or traffic-based?"
  local wait_min=${G1_IDLE_MIN:-8}
  export BENCH_SETTLE=0 BENCH_WARMUP=5s BENCH_DURATION=${G1_CELL_SECS:-20}s BENCH_VUS=${G1_VUS:-50}

  arm_cleanup axiam
  bench_up_seed axiam
  local tel=$out/telemetry.csv; sampler_start "$tel"

  log "idling ${wait_min} min after seed with NO load (this is the whole experiment)"
  s "The stack is seeded, then left **completely idle** for ${wait_min} minutes before"
  s "the first request. If the first cell is then FAST, the window is background work"
  s "that completes on wall-clock time (a cold-start/compaction class of cause). If it"
  s "is still ~45 ops/s, the stack only warms up in response to TRAFFIC (a cache/"
  s "connection/JIT-of-query-plan class of cause). This single bit splits G1's"
  s "hypothesis space in half."
  s
  sleep $((wait_min * 60))

  local d=$out/after-idle cs ce; cs=$(date +%s)
  cell axiam p0-plaintext authz_check_rest.js "$d" >/dev/null 2>&1 || warn "cell failed"
  ce=$(date +%s)
  local f thr p50 dbcpu; f=$(k6_file "$d"); thr=NA; p50=NA
  [ -n "$f" ] && { thr=$(k6_stat "$f" thr); p50=$(k6_stat "$f" p50); }
  dbcpu=$(cpu_mean "$tel" "$C_DB" "$cs" "$ce")

  # A second cell right after, to show whether traffic itself is what warms it.
  local d2=$out/second-cell cs2 ce2; cs2=$(date +%s)
  cell axiam p0-plaintext authz_check_rest.js "$d2" >/dev/null 2>&1 || true
  ce2=$(date +%s)
  local f2 thr2; f2=$(k6_file "$d2"); thr2=NA
  [ -n "$f2" ] && thr2=$(k6_stat "$f2" thr)

  sampler_stop "$SAMPLER_PID"; SAMPLER_PID=""; disarm_cleanup; bench_down axiam
  sp "- first cell after ${wait_min} min idle: **${thr} ops/s** (p50 ${p50} ms, DB ${dbcpu} cores)"
  sp "- immediately following cell:          **${thr2} ops/s**"
  s
  s "## Verdict"
  s "- \`~740 ops/s\` on the first cell ⇒ **time-based**: idling through the window cures it."
  s "- \`~45 ops/s\` on the first cell and faster on the second ⇒ **traffic-based** warm-up."
  s "- Both slow ⇒ the window is longer than ${wait_min} min; re-run with G1_IDLE_MIN=15."
  finish
}

task_g1_isolate() {
  need_base
  local out=$TASKS_ROOT/g1-isolate
  rm -rf "$out"; summary_open "$out" "G1 — server or datastore?"
  export BENCH_SETTLE=0 BENCH_WARMUP=5s BENCH_DURATION=${G1_CELL_SECS:-20}s BENCH_VUS=${G1_VUS:-50}

  arm_cleanup axiam
  bench_up_seed axiam
  local tel=$out/telemetry.csv; sampler_start "$tel"

  probe() { # $1=label -> prints thr
    local d=$out/$1
    cell axiam p0-plaintext authz_check_rest.js "$d" >/dev/null 2>&1 || true
    local f; f=$(k6_file "$d"); [ -n "$f" ] && k6_stat "$f" thr || echo NA
  }

  # H1 item 3: after a DB restart, the server's connection/pool needs to
  # re-sign-in before it can serve anything real — hitting it with a k6 cell
  # immediately (the old behavior) measured that re-signin failure itself
  # (recorded n=1 request, unusable) rather than the post-restart clamp.
  # `/ready` (crates/axiam-api-rest/src/health.rs) exists exactly for this:
  # unlike `/health` (always 200, a pure liveness probe), it re-checks DB
  # connectivity through the same pool the authz path uses and returns 503
  # until that succeeds — so polling it to 200 is a direct signal the pool
  # has re-signed in, not a fixed guess at a sleep duration.
  wait_for_ready() { # $1=base_url $2=timeout_secs -> 0 once /ready is 200
    local base="$1" timeout="${2:-90}" start now code
    start=$(date +%s)
    while :; do
      code="$(curl -sSk --max-time 5 -o /dev/null -w '%{http_code}' "$base/ready" 2>/dev/null || echo 000)"
      [ "$code" = "200" ] && { log "$base/ready is 200 — pool re-signed in"; return 0; }
      now=$(date +%s)
      if [ $((now - start)) -ge "$timeout" ]; then
        warn "timed out after ${timeout}s waiting for $base/ready to return 200 (last code: $code) — proceeding anyway"
        return 1
      fi
      sleep 1
    done
  }

  s "Restarting ONE container at a time inside the clamped window. Whatever state"
  s "the transient lives in dies with the container that owns it."
  s
  local a b c
  a=$(probe baseline);                     sp "- baseline (in-window):            **${a} ops/s**"
  log "restarting $C_SERVER only"
  docker restart "$C_SERVER" >/dev/null; sleep 20
  b=$(probe after-server-restart);         sp "- after restarting the SERVER only: **${b} ops/s**"
  log "restarting $C_DB only"
  docker restart "$C_DB" >/dev/null; sleep 25
  wait_for_ready "http://localhost:${BENCH_APP_PORT:-8090}" "${G1_ISOLATE_READY_TIMEOUT:-90}"
  # H1 item 3: also run this probe as a FULL-length cell (not the 20s G1
  # micro-cell used everywhere else in this task) — a longer measured window
  # gives it enough samples to be statistically usable even if the pool is
  # still settling right as measurement starts.
  local saved_warmup=$BENCH_WARMUP saved_duration=$BENCH_DURATION
  export BENCH_WARMUP="${G1_ISOLATE_FULL_WARMUP:-30s}" BENCH_DURATION="${G1_ISOLATE_FULL_DURATION:-120s}"
  c=$(probe after-db-restart)
  export BENCH_WARMUP="$saved_warmup" BENCH_DURATION="$saved_duration"
  sp "- after restarting the DATASTORE:   **${c} ops/s** (full-length cell, after /ready wait)"

  sampler_stop "$SAMPLER_PID"; SAMPLER_PID=""; disarm_cleanup; bench_down axiam
  s
  s "## Verdict"
  s "- Clamp survives a server restart but clears on a datastore restart ⇒ the state is"
  s "  **SurrealDB-side** (background compaction / index build / warm-up) — and is then a"
  s "  candidate production cold-start defect, not just a bench artifact."
  s "- Clamp clears on the server restart ⇒ it is **AXIAM-side** (DB pool/session warm-up)."
  s "- Neither clears it ⇒ it is time-based background work; cross-check with \`g1-idle\`."
  s "- Note a restart also drops caches, so read this together with \`g1-idle\`."
  finish
}

task_g1_dbdirect() {
  need_base
  local out=$TASKS_ROOT/g1-dbdirect
  rm -rf "$out"; summary_open "$out" "G1 — does the clamp exist without AXIAM in the path?"
  export BENCH_SETTLE=0
  arm_cleanup axiam
  bench_up_seed axiam

  # Same query shape the authz hot path uses, issued straight at SurrealDB from an
  # ephemeral container on the bench network — no AXIAM server involved.
  local net; net=$(docker inspect "$C_DB" -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null || echo "")
  local img; img=$(docker inspect "$C_DB" -f '{{.Config.Image}}' 2>/dev/null || echo "surrealdb/surrealdb:v3")
  # Credential resolution, most-authoritative-last so an operator override still
  # wins: this shell's environment, then docker/.secrets/env, then the running
  # containers (see container_env — bench-up's bootstrapped defaults exist
  # nowhere else, which is what used to make this task bail out on a perfectly
  # healthy stack).
  local user=${AXIAM__DB__USERNAME:-} pass=${AXIAM__DB__PASSWORD:-}
  if [ -f ../docker/.secrets/env ]; then . ../docker/.secrets/env || true; fi
  user=${user:-${AXIAM__DB__USERNAME:-}}; pass=${pass:-${AXIAM__DB__PASSWORD:-}}
  [ -n "$user" ] || user=$(container_env "$C_SERVER" AXIAM__DB__USERNAME)
  [ -n "$pass" ] || pass=$(container_env "$C_SERVER" AXIAM__DB__PASSWORD)
  [ -n "$user" ] || user=$(container_cmd_flag "$C_DB" --user)
  [ -n "$pass" ] || pass=$(container_cmd_flag "$C_DB" --pass)
  DBD_NET=$net; DBD_IMG=$img; DBD_USER=$user; DBD_PASS=$pass

  s "Issues a repeated read straight at SurrealDB (no AXIAM server in the path) during"
  s "the post-seed window. If the DB alone is slow, AXIAM is exonerated entirely."
  s
  if [ -z "$net" ] || [ -z "$pass" ]; then
    # Say WHICH lookup failed — they have different fixes.
    local missing="the DB network"
    [ -n "$net" ] && missing="the DB credentials"
    [ -z "$net" ] && [ -z "$pass" ] && missing="the DB network or credentials"
    warn "could not resolve $missing from the running stack — is it up?"
    s "- **NOT RUN automatically** (could not resolve $missing). Resolve manually"
    s "  and re-run the loop below:"
    s '```bash'
    s "echo '$DBD_QUERY' \\"
    s "| docker run --rm -i --network ${net:-<network>} $img sql \\"
    s "  --endpoint http://$C_DB:8000 --username ${user:-<user>} --password <pass> \\"
    s "  --namespace axiam --database axiam --hide-welcome --pretty"
    s '```'
    s "(\`surreal sql\` is a REPL with pipe support — it has no \`--query\` flag, so the"
    s "statement goes on stdin and \`docker run\` needs \`-i\`.)"
    s
    s "The credentials are whatever \`just bench-up\` used: your exported"
    s "\`AXIAM__DB__USERNAME\`/\`AXIAM__DB__PASSWORD\` if you set them, otherwise its"
    s "throwaway local defaults. Read them back off the running stack with:"
    s '```bash'
    s "docker inspect $C_SERVER -f '{{range .Config.Env}}{{println .}}{{end}}' | grep AXIAM__DB__"
    s '```'
    disarm_cleanup; bench_down axiam; finish; return
  fi
  # Pre-flight the query once before timing anything. A wrong credential (or a
  # renamed table) would otherwise fill db-direct.csv with rows of pure
  # container-start overhead that read like plausible timings — the worst
  # possible failure for a task whose whole output is a trend line. Both gates
  # are needed: the exit status catches an unusable connection, surreal_result_ok
  # catches a statement that was rejected while still exiting 0. This one-shot
  # preflight still uses surreal_direct() (fresh docker run) deliberately —
  # it's cheap to pay container-start overhead exactly once, and doing it
  # this way keeps the preflight independent of the persistent session's own
  # health (a good sanity check before committing to it).
  if ! surreal_direct "$DBD_QUERY" \
        > "$out/preflight.log" 2>&1 \
     || ! surreal_result_ok < "$out/preflight.log"; then
    warn "the direct SurrealDB query failed as user '$user' — not timing it; see preflight.log"
    s "- **NOT RUN.** The credentials resolved, but the probe query itself failed as"
    s "  user \`$user\`. First lines of \`preflight.log\`:"
    s '```'
    head -5 "$out/preflight.log" 2>/dev/null | sed 's/^/  /' >> "$SUMMARY" || true
    s '```'
    disarm_cleanup; bench_down axiam; finish; return
  fi
  log "pre-flight query OK as user '$user' — opening one long-lived session for the timing loop"

  # H1 item 4: ONE persistent `surreal sql` session (dbd_session_start/query/
  # stop, defined above) for the ENTIRE timing loop below — not a fresh
  # `docker run` per query (the old behavior: ~500 ms flat container-start
  # overhead added to every one of 30 rows, which is most of what those rows
  # measured). Two segments in the SAME file/session so "in-window" vs
  # "settled" is a within-file comparison rather than two separate runs that
  # could differ for unrelated reasons:
  #   - "window": DBD_ITERS rows starting immediately (same cadence as
  #     before: DBD_INTERVAL_SECS apart, default 2s) — this is the segment
  #     that used to be the whole probe.
  #   - "baseline": after waiting DBD_BASELINE_WAIT_SECS (default 420s = 7min,
  #     comfortably past the ~5-7min window G1 measured — see
  #     PRIVATE_BENCH_ANALYSIS.md §1), DBD_BASELINE_ITERS more rows at the
  #     same cadence. Without this segment the probe is inconclusive by
  #     construction: a flat trend across ONLY in-window rows cannot
  #     distinguish "the DB is slow throughout, unrelated to the window" from
  #     "the DB would be fast if measured after the window" — G1's original
  #     verdict on this probe.
  # Every row is individually timestamped (epoch_ms) and carries its own ok
  # flag: a mid-run failure (the stack going away, a restart) would otherwise
  # time a fast error path and read as "the clamp cleared".
  local dbd_iters=${G1_DBDIRECT_ITERS:-30}
  local dbd_interval=${G1_DBDIRECT_INTERVAL_SECS:-2}
  local dbd_baseline_wait=${G1_DBDIRECT_BASELINE_WAIT_SECS:-420}
  local dbd_baseline_iters=${G1_DBDIRECT_BASELINE_ITERS:-15}

  dbd_session_start
  {
    echo "iteration,epoch_ms,elapsed_ms,ok,segment"
    local i st et ok line
    for i in $(seq 1 "$dbd_iters"); do
      st=$(date +%s%3N)
      ok=1
      line="$(dbd_session_query "$DBD_QUERY")" || ok=0
      et=$(date +%s%3N)
      [ "$ok" -eq 1 ] && { surreal_result_ok <<<"$line" || ok=0; }
      echo "$i,$st,$((et - st)),$ok,window"
      sleep "$dbd_interval"
    done
  } > "$out/db-direct.csv"
  log "window segment done — waiting ${dbd_baseline_wait}s (same session) before the baseline segment"
  sleep "$dbd_baseline_wait"
  {
    local i st et ok line
    for i in $(seq 1 "$dbd_baseline_iters"); do
      st=$(date +%s%3N)
      ok=1
      line="$(dbd_session_query "$DBD_QUERY")" || ok=0
      et=$(date +%s%3N)
      [ "$ok" -eq 1 ] && { surreal_result_ok <<<"$line" || ok=0; }
      echo "$i,$st,$((et - st)),$ok,baseline"
      sleep "$dbd_interval"
    done
  } >> "$out/db-direct.csv"
  dbd_session_stop

  s "- raw timings: \`db-direct.csv\` — ONE long-lived session for the whole probe (no"
  s "  per-row container-start overhead). \`segment\` is \`window\` (the ${dbd_iters} rows"
  s "  starting immediately after seed) or \`baseline\` (${dbd_baseline_iters} rows collected"
  s "  after an additional ${dbd_baseline_wait}s wait, same session — the post-window"
  s "  comparison segment the old probe never collected). Ignore any row with \`ok=0\`:"
  s "  the query failed there, so its timing measures an error path, not the datastore."
  s "- \`window\` flat/slow and \`baseline\` fast in the SAME file/session ⇒ the"
  s "  serialization is inside SurrealDB and cleared on its own by the time the"
  s "  baseline segment ran. Both segments flat/slow ⇒ either the wait wasn't long"
  s "  enough (bump \`G1_DBDIRECT_BASELINE_WAIT_SECS\`) or the DB isn't the bottleneck."
  disarm_cleanup; bench_down axiam
  finish
}

# ---------------------------------------------------------------------------
# G2 — prove the harness countermeasures work on a live stack
# ---------------------------------------------------------------------------
task_g2_verify() {
  need_base
  local out=$TASKS_ROOT/g2-verify
  rm -rf "$out"; summary_open "$out" "G2 — settle gate, cell rotation, self-describing meta"
  export BENCH_RESULTS_DIR=$out
  export BENCH_WARMUP=5s BENCH_DURATION=30s

  log "running a 2-repeat mini matrix (one target, one profile) to exercise the new machinery"
  arm_cleanup axiam p0-plaintext
  just target=axiam profiles="p0-plaintext" targets="axiam" repeat=2 bench-matrix || \
    warn "mini matrix returned non-zero — inspect the output above"

  s "## Checks"
  python3 - "$out" >> "$SUMMARY" <<'PY'
import glob, json, os, sys
root = sys.argv[1]
metas = sorted(glob.glob(os.path.join(root, "**", "*.meta.json"), recursive=True))
if not metas:
    print("- ❌ no meta.json produced — the mini matrix did not run"); raise SystemExit
have_settle = [m for m in metas if "settle_wait_secs" in json.load(open(m))]
have_order  = [m for m in metas if "cell_order_index" in json.load(open(m))]
have_env    = [m for m in metas if json.load(open(m)).get("axiam_env")]
print(f"- cells produced: {len(metas)}")
print(f"- `settle_wait_secs` present: {len(have_settle)}/{len(metas)} "
      + ("✅" if len(have_settle) == len(metas) else "❌"))
print(f"- `cell_order_index` present: {len(have_order)}/{len(metas)} "
      + ("✅" if len(have_order) == len(metas) else "❌"))
print(f"- `axiam_env` knob dump present: {len(have_env)}/{len(metas)} "
      + ("✅" if len(have_env) == len(metas) else "❌"))
# rotation: the first-executed scenario must differ between run-1 and run-2
first = {}
for m in metas:
    d = json.load(open(m))
    run = next((p for p in m.split(os.sep) if p.startswith("run-")), "run-?")
    idx = d.get("cell_order_index")
    if idx is not None and (run not in first or idx < first[run][0]):
        first[run] = (idx, d.get("scenario"))
if len(first) >= 2:
    names = {v[1] for v in first.values()}
    print(f"- first-executed scenario per run: "
          + ", ".join(f"{r}={v[1]}" for r, v in sorted(first.items()))
          + ("  ✅ rotated" if len(names) > 1 else "  ❌ NOT rotated"))
# secret hygiene of the new env dump
leaks = []
for m in metas:
    for k, v in (json.load(open(m)).get("axiam_env") or {}).items():
        if any(t in k.upper() for t in ("PASSWORD", "SECRET", "KEY", "PEPPER", "PEM", "TOKEN")):
            if v != "<redacted>":
                leaks.append(f"{os.path.basename(m)}:{k}")
print(f"- secret redaction in `axiam_env`: " + ("✅ clean" if not leaks else f"❌ LEAKED {leaks[:5]}"))
PY
  s
  s "Acceptance (plan G2): every cell carries the three new fields, the first-executed"
  s "scenario differs between run-1 and run-2, and no secret value appears in \`axiam_env\`."
  unset BENCH_RESULTS_DIR
  disarm_cleanup; bench_down axiam
  finish
}

# ---------------------------------------------------------------------------
# G3 — the clean batch A/B (needs G2's settle gate merged)
# ---------------------------------------------------------------------------
task_g3_batch() {
  need_base
  local out=$TASKS_ROOT/g3-batch
  rm -rf "$out"; summary_open "$out" "G3 — batch strategy A/B on a settled stack"
  local reps=${G3_REPEAT:-3}

  s "The four authz cells under both \`AXIAM__AUTHZ__BATCH_STRATEGY\` values, ${reps}×"
  s "each, **on a settled stack** (this is what run 3 could not do — every historical"
  s "batch cell was corrupted by the post-seed transient). A warm-up cell runs first"
  s "in every pass so no measured cell is ever the first request after seeding."
  s
  s "| strategy | scenario | run | thr (ops/s) | p50 (ms) | p95 (ms) |"
  s "|---|---|---|---|---|---|"

  for strategy in concurrent coalesced; do
    export AXIAM__AUTHZ__BATCH_STRATEGY=$strategy
    arm_cleanup axiam p0-plaintext
    bench_up_seed axiam
    # Belt and braces: even with the settle gate, burn one throwaway cell.
    BENCH_WARMUP=5s BENCH_DURATION=20s cell axiam p0-plaintext authz_check_rest.js \
      "$out/$strategy/warmup" >/dev/null 2>&1 || true
    for r in $(seq 1 "$reps"); do
      for sc in authz_check_rest authz_batch_rest authz_check_grpc authz_batch_grpc; do
        local d=$out/$strategy/run-$r/$sc
        cell axiam p0-plaintext "$sc.js" "$d" >/dev/null 2>&1 || warn "$strategy/$sc run $r failed"
        local f; f=$(k6_file "$d")
        [ -n "$f" ] && s "| $strategy | $sc | $r | $(k6_stat "$f" thr) | $(k6_stat "$f" p50) | $(k6_stat "$f" p95) |"
      done
    done
    disarm_cleanup; bench_down axiam
    unset AXIAM__AUTHZ__BATCH_STRATEGY
  done

  s
  s "## Decision inputs (plan G3 criterion)"
  python3 - "$out" >> "$SUMMARY" <<'PY'
import glob, json, os, statistics, sys
root = sys.argv[1]
def med(strategy, scen, key):
    vals = []
    for f in glob.glob(os.path.join(root, strategy, "run-*", scen, "**", "*.k6.json"),
                       recursive=True):
        m = json.load(open(f))["metrics"]
        vals.append(m["bench_ok"]["rate"] if key == "thr"
                    else m["bench_op_latency_ms"]["p(95)"])
    return statistics.median(vals) if vals else None
for strategy in ("concurrent", "coalesced"):
    single = med(strategy, "authz_check_rest", "thr")
    batch = med(strategy, "authz_batch_rest", "thr")
    bg = med(strategy, "authz_batch_grpc", "thr")
    bg95 = med(strategy, "authz_batch_grpc", "p95")
    if not (single and batch):
        print(f"- **{strategy}**: incomplete data"); continue
    checks = batch * 5  # the bench batches 5 checks per request
    print(f"- **{strategy}**: singles {single:.0f}/s · batch {batch:.0f} req/s "
          f"= **{checks:.0f} checks/s** → batch/single = **{checks/single:.2f}×** "
          + ("✅ beats singles" if checks > single else "❌ worse than singles"))
    if bg95:
        print(f"  - gRPC batch p95 {bg95:.0f} ms "
              + ("✅ under the 2 s gate" if bg95 < 2000 else "❌ breaches the 2 s gate"))
PY
  s
  s "Ship whichever strategy wins as the default (plan G3), keep the other selectable,"
  s "and paste this table into \`claude_dev/authz-batch-investigation.md\`."
  finish
}

# ---------------------------------------------------------------------------
# G4 — refresh-token cell must stop measuring a fallback
# ---------------------------------------------------------------------------
task_g4_refresh() {
  need_base
  local out=$TASKS_ROOT/g4-refresh
  rm -rf "$out"; summary_open "$out" "G4 — token_refresh measures a real rotation"

  s "| target | thr (ops/s) | p50 (ms) | bench_fallback | HTTP reqs / iteration | verdict |"
  s "|---|---|---|---|---|---|"
  for target in axiam keycloak; do
    arm_cleanup "$target" p0-plaintext
    bench_up_seed "$target"
    # A control cell: client_credentials, so we can check refresh is NOT ~½ of it.
    cell "$target" p0-plaintext oauth2_client_credentials.js "$out/$target/cc" >/dev/null 2>&1 || true
    cell "$target" p0-plaintext token_refresh.js "$out/$target/refresh" >/dev/null 2>&1 || true
    disarm_cleanup; bench_down "$target"
    local fr; fr=$(k6_file "$out/$target/refresh")
    if [ -z "$fr" ]; then s "| $target | — | — | — | — | ❌ cell did not run |"; continue; fi
    local thr p50 fb rpi verdict
    thr=$(k6_stat "$fr" thr); p50=$(k6_stat "$fr" p50); fb=$(k6_stat "$fr" fallback)
    rpi=$(python3 -c "
import json,sys
m=json.load(open('$fr'))['metrics']
it=m.get('iterations',{}).get('count',0); hr=m.get('http_reqs',{}).get('count',0)
print(f'{hr/it:.2f}' if it else 'NA')")
    verdict='❌ still a fallback'
    [ "$fb" = "0" ] && verdict='✅ real rotation'
    s "| $target | $thr | $p50 | $fb | $rpi | $verdict |"
  done

  s
  s "## Acceptance (plan G4)"
  s "- \`bench_fallback == 0\` for **both** AXIAM and Keycloak;"
  s "- ~**1.0** HTTP request per iteration (2.0 is the client-credentials fallback signature);"
  s "- AXIAM refresh throughput is **not** ≈ ½ × its client-credentials cell — compare"
  s "  against the `<target>/cc` cell in this directory."
  s "- If AXIAM still shows a fallback, the diagnosis in"
  s "  \`claude_dev/refresh-harness-diagnosis.md\` lists what to check next."
  finish
}

# ---------------------------------------------------------------------------
# G5 — decision-cache hit-rate sweep (does the 3× survive a realistic key space?)
# ---------------------------------------------------------------------------
task_g5_cache_sweep() {
  need_base
  local out=$TASKS_ROOT/g5-cache-sweep
  rm -rf "$out"; summary_open "$out" "G5 — decision cache vs cache-key cardinality"
  local scen=${G5_SCENARIO:-authz_check_rest.js}
  local ks=${G5_KEYSPACES:-"1 100 10000"}
  # H5: p2-tls13, NOT p0-plaintext. On p0 the login cookies are marked `Secure`
  # and k6's jar refuses to replay them over http://, so every cookie-session
  # scenario (this one included) dies in setup() — see
  # claude_dev/postseed-transient-investigation.md §8.3. Override with
  # G5_PROFILE only if that has been fixed.
  local prof=${G5_PROFILE:-p2-tls13}

  s "Run 3 measured the cache at K=1 (every VU hammering ONE subject/resource pair) —"
  s "the friendliest possible hit rate. This sweeps the key space to bound the real"
  s "win, and records the memory cost at the largest K."
  s
  s "| cache | K (distinct subject×resource pairs) | thr (ops/s) | p50 (ms) | server mem (MiB) |"
  s "|---|---|---|---|---|"

  for enabled in false true; do
    export AXIAM__AUTHZ__DECISION_CACHE_ENABLED=$enabled
    arm_cleanup axiam "$prof"
    # The profile must reach bench_up_seed too, not just the cells: for
    # p1/p2/p3 it is what brings up the TLS listener the cells dial (the
    # native-TLS compose overlay for axiam, the nginx edge for the
    # competitors) and publishes :8443. Bringing the stack up as p0 and then
    # pointing p2 cells at :8443 gives ONE refused connection per cell and a
    # silently empty result file — which is exactly what the first attempt at
    # this sweep produced.
    bench_up_seed axiam "$prof"
    BENCH_WARMUP=5s BENCH_DURATION=20s cell axiam "$prof" authz_check_rest.js \
      "$out/warmup-$enabled" >/dev/null 2>&1 || true
    for k in $ks; do
      local d=$out/cache-$enabled/k-$k
      # BENCH_AUTHZ_KEYSPACE is read by the sweep-capable scenario (task G5's
      # code change). With an older scenario it is simply ignored — the row then
      # reads the same for every K, which is itself the signal that the scenario
      # change has not landed yet.
      BENCH_AUTHZ_KEYSPACE=$k cell axiam "$prof" "$scen" "$d" >/dev/null 2>&1 || true
      local f mem; f=$(k6_file "$d")
      mem=$(python3 - "$d" <<'PY'
import csv, glob, os, sys
vals = []
for p in glob.glob(os.path.join(sys.argv[1], "**", "*.res.csv"), recursive=True):
    for r in csv.DictReader(open(p)):
        if r["container"].endswith("-server"):
            vals.append(float(r["mem_mib"]))
print(f"{sum(vals)/len(vals):.0f}" if vals else "NA")
PY
)
      [ -n "$f" ] && s "| $enabled | $k | $(k6_stat "$f" thr) | $(k6_stat "$f" p50) | $mem |"
    done
    disarm_cleanup; bench_down axiam
    unset AXIAM__AUTHZ__DECISION_CACHE_ENABLED
  done

  s
  s "## Decision inputs (plan G5)"
  s "- The ship-decision needs the cache-ON/OFF ratio **at the largest K**, not at K=1."
  s "- If the win collapses toward 1.0× as K grows, the default should stay opt-in and the"
  s "  public doc's \"3×\" must be labeled as a best-case, small-key-space figure."
  s "- Memory at K=10000 bounds \`DECISION_CACHE_MAX_ENTRIES\` guidance."
  s "- The live-stack revocation check is now automated: \`runner/h5-revocation-check.sh\`"
  s "  (run it against BOTH a cache-ON and a cache-OFF stack — the OFF run is the control)."
  s "- On a host where the shared rate-limit counter clamps the authz endpoint to ~20 ops/s"
  s "  (see \`claude_dev/postseed-transient-investigation.md\`), these cells measure the clamp,"
  s "  not the cache: the ~40 ms counter write sits OUTSIDE the cache and dominates. Report the"
  s "  ON/OFF RATIO with that caveat and never the absolute level."
  finish
}

# ---------------------------------------------------------------------------
# G6 — memory retention (delegates to the dedicated script)
# ---------------------------------------------------------------------------
task_g6_memory() {
  [ -x ./run-memory-experiment.sh ] || die "run-memory-experiment.sh missing or not executable"
  log "delegating to run-memory-experiment.sh (builds two images — allow ~1h)"
  ./run-memory-experiment.sh "${1:-both}"
  echo
  log "when it finishes, paste results/d9-summary.md into:"
  echo "  - claude_dev/memory-retention-experiment.md §6"
  echo "  - $PLAN §G6 (replace the placeholder)"
}

# ---------------------------------------------------------------------------
# G8 — B2 conviction: is HTTP/2 multiplexing the TLS token-issuance penalty?
# ---------------------------------------------------------------------------
task_g8_tls_h1() {
  need_base
  local out=$TASKS_ROOT/g8-tls-h1
  rm -rf "$out"; summary_open "$out" "G8 — TLS 1.3 token issuance: h2 vs h1 vs plaintext"

  s "Three cells of the SAME operation, each run **after a warm-up cell** so none of"
  s "them is the first request after seeding (that is what invalidated run 3's"
  s "conviction cell). If p2-h1 ≈ p0, HTTP/2 multiplexing is convicted."
  s

  run_cc_cell() { # $1=label $2=profile [$3=BENCH_NGINX_CONF]
    local label=$1 profile=$2 nginx=${3:-}
    [ -n "$nginx" ] && export BENCH_NGINX_CONF=$nginx || unset BENCH_NGINX_CONF
    arm_cleanup axiam "$profile"
    bench_up_seed axiam "$profile"
    BENCH_WARMUP=5s BENCH_DURATION=20s cell axiam "$profile" authz_check_rest.js \
      "$out/$label/warmup" >/dev/null 2>&1 || true
    cell axiam "$profile" oauth2_client_credentials.js "$out/$label/cc" >/dev/null 2>&1 || true
    cell axiam "$profile" token_refresh.js "$out/$label/refresh" >/dev/null 2>&1 || true
    disarm_cleanup; bench_down axiam "$profile"
    unset BENCH_NGINX_CONF
  }

  run_cc_cell p0-plaintext p0-plaintext
  run_cc_cell p2-native    p2-tls13
  run_cc_cell p2-h1        p2-tls13 tls13-h1.conf

  s "| cell | negotiated HTTP | thr (ops/s) | p50 (ms) | Δ vs p0 |"
  s "|---|---|---|---|---|"
  python3 - "$out" >> "$SUMMARY" <<'PY'
import glob, json, os, sys
root = sys.argv[1]
def stats(label):
    f = glob.glob(os.path.join(root, label, "cc", "**", "*.k6.json"), recursive=True)
    if not f: return None
    m = json.load(open(f[0]))["metrics"]
    # k6 tags http_req_duration by protocol when available; fall back to "?"
    proto = "?"
    for k in m:
        if k.startswith("http_req_duration{") and "http_version" in k:
            proto = k.split("http_version:")[1].rstrip("}")
            break
    return m["bench_ok"]["rate"], m["bench_op_latency_ms"]["med"], proto
base = stats("p0-plaintext")
for label in ("p0-plaintext", "p2-native", "p2-h1"):
    st = stats(label)
    if not st:
        print(f"| {label} | — | — | — | cell missing |"); continue
    thr, p50, proto = st
    delta = "baseline" if label == "p0-plaintext" or not base else f"{100*(thr-base[0])/base[0]:+.1f}%"
    print(f"| {label} | {proto} | {thr:.0f} | {p50:.1f} | {delta} |")
PY
  s
  s "## Verdict (plan G8)"
  s "- **p2-h1 within ~15% of p0** ⇒ HTTP/2 convicted. Next step is h2 tuning on the"
  s "  actix listener (\`max_concurrent_streams\`, stream/connection window sizes), then"
  s "  re-measure; if no setting recovers it, publish the documented position."
  s "- **p2-h1 also ~−50%** ⇒ HTTP/2 acquitted; move to per-request server-side timing"
  s "  at p2 vs p0 (TLS read/write vs handler) — the fallback path in the plan."
  s "- Check the negotiated-protocol column: the h1 cell must NOT read \`2\`."
  finish
}

# ---------------------------------------------------------------------------
# G9 — rate-limited cells must report coherent metrics
# ---------------------------------------------------------------------------
task_g9_rlprod() {
  need_base
  local out=$TASKS_ROOT/g9-rlprod
  rm -rf "$out"; summary_open "$out" "G9 — metric coherence under a 429 storm"
  export BENCH_RESULTS_DIR=$out
  arm_cleanup axiam p0-plaintext
  bench_up_seed axiam p0-plaintext rl=prod
  for sc in oauth2_client_credentials token_introspection authz_check_rest; do
    cell axiam p0-plaintext "$sc.js" "$out/$sc" >/dev/null 2>&1 || true
  done
  disarm_cleanup; bench_down axiam
  unset BENCH_RESULTS_DIR

  s "With the production per-IP posture active, nearly every request is a 429."
  s
  s "G9 established that run-3's apparently contradictory cell (\`bench_ok\` 13.6/s at"
  s "a 1.00 error rate) was **not** a counting bug: \`doOp()\` only ever counts a"
  s "status-match as ok, and the rate limiters start with a full burst, so a genuine"
  s "handful of successes lands at test start while the retry storm that follows"
  s "drives the *fraction* to ~1.00. The two metrics were each correct and together"
  s "illegible. The fix is the \`bench_throttled\` counter, so a posture pass can be"
  s "read directly: \`bench_failed ≈ bench_throttled\` means \"purely rate-limited\","
  s "\`bench_failed >> bench_throttled\` means something else is also broken."
  s
  s "| scenario | ok ops | throttled (429/RESOURCE_EXHAUSTED) | other failures | reads as |"
  s "|---|---|---|---|---|"
  for sc in oauth2_client_credentials token_introspection authz_check_rest authz_check_grpc; do
    local f; f=$(k6_file "$out/$sc")
    if [ -z "$f" ]; then s "| $sc | — | — | — | cell missing |"; continue; fi
    python3 - "$f" "$sc" >> "$SUMMARY" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))["metrics"]
ok = m.get("bench_ok", {}).get("count", 0)
failed = m.get("bench_failed", {}).get("count", 0)
thr = m.get("bench_throttled", {}).get("count")
if thr is None:
    verdict = "⚠ bench_throttled absent — scenario not yet wired to the shared classifier"
    thr = "—"; other = "—"
else:
    other = failed - thr
    verdict = ("✅ purely rate-limited" if failed and other <= 0.02 * failed
               else f"❌ {other} failures beyond throttling — investigate")
print(f"| {sys.argv[2]} | {ok} | {thr} | {other} | {verdict} |")
PY
  done
  s
  s "Acceptance (plan G9.3): every rate-limited cell resolves to \"purely rate-limited\","
  s "and \`bench_throttled\` is present on **gRPC** cells too (they use the shared"
  s "\`recordGrpcResult()\` classifier rather than their own copy)."
  finish
}

# ---------------------------------------------------------------------------
# G10 — SDK benches: first validated records
# ---------------------------------------------------------------------------
task_g10_sdk() {
  need_base
  local out=$TASKS_ROOT/g10-sdk
  rm -rf "$out"; summary_open "$out" "G10 — SDK client-side benches against a live target"
  local langs=${G10_LANGS:-"rust python typescript go java csharp php"}

  s "Each SDK bench must emit ONE spec-conformant \`axiam.sdk-bench/v1\` record with"
  s "\`status: \"ok\"\`, twice in a row, against a seeded p0 target (plan G10 / E1.1)."
  s "Each language's sibling repo must be checked out next to this workspace."
  s
  arm_cleanup axiam p0-plaintext
  bench_up_seed axiam
  s "| sdk | attempt 1 | attempt 2 | notes |"
  s "|---|---|---|---|"
  for lang in $langs; do
    local d=$out/$lang; mkdir -p "$d"
    local r1 r2
    just sdk="$lang" sdk-bench > "$d/attempt-1.log" 2>&1 && r1=ok || r1=fail
    just sdk="$lang" sdk-bench > "$d/attempt-2.log" 2>&1 && r2=ok || r2=fail
    local st1 st2
    st1=$(grep -o '"status"[[:space:]]*:[[:space:]]*"[a-z]*"' "$d/attempt-1.log" | tail -1 | grep -o '[a-z]*"$' | tr -d '"' || echo "$r1")
    st2=$(grep -o '"status"[[:space:]]*:[[:space:]]*"[a-z]*"' "$d/attempt-2.log" | tail -1 | grep -o '[a-z]*"$' | tr -d '"' || echo "$r2")
    local note=""
    grep -qi "no such file\|not found\|cannot find" "$d/attempt-1.log" && note="sibling SDK repo missing?"
    s "| $lang | ${st1:-$r1} | ${st2:-$r2} | $note |"
  done
  disarm_cleanup; bench_down axiam
  s
  s "For every non-\`ok\` row, fix per that language's \`sdk/<lang>/TODO.md\` and re-run"
  s "just that language: \`G10_LANGS=python ./run-improvement-tasks.sh g10-sdk\`."
  s "Once ≥7 are ok, run \`just sdk-bench-all\` and build the overhead-vs-wire table (E1.3)."
  finish
}

# ---------------------------------------------------------------------------
# packaging
# ---------------------------------------------------------------------------
task_pack() {
  log "packing shareable results (secret-scanned by the justfile recipe)"
  just bench-pack
  echo
  log "task summaries collected so far:"
  find "$TASKS_ROOT" -name SUMMARY.md 2>/dev/null | sort | sed 's|^|  |' || echo "  (none yet)"
}

# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
run-improvement-tasks.sh — per-task benchmark data collection for
$PLAN

Usage: ./run-improvement-tasks.sh <task>

  Task            Plan  Est.    What it answers
  --------------------------------------------------------------------------
  g1-timeline     G1    ~25m    When does the post-seed window end? (run first)
  g1-idle         G1    ~15m    Is it time-based or traffic-based?
  g1-isolate      G1    ~10m    Does it live in the server or the datastore?
  g1-dbdirect     G1    ~14m    Is it visible with AXIAM out of the path? (H1: now includes a post-window baseline segment)
  g2-verify       G2    ~10m    Do settle gate + rotation + meta dump work live?
  g3-batch        G3    ~90m    Clean batch A/B: does batch beat singles?
  g4-refresh      G4    ~15m    Is the refresh cell a real rotation now?
  g5-cache-sweep  G5    ~60m    Does the cache 3x survive a realistic key space?
  g6-memory       G6    ~90m    Does jemalloc fix the post-burst retention?
  g8-tls-h1       G8    ~25m    Is HTTP/2 the TLS token-issuance penalty?
  g9-rlprod       G9    ~10m    Are rate-limited cells' metrics coherent?
  g10-sdk         G10   ~30m    Do the SDK benches emit valid records?
  pack            —     ~1m     Build the shareable archive + list summaries

Each task writes results/tasks/<task>/SUMMARY.md with its verdict.
Estimates include bring-up + seed. g1-timeline is ~55s per iteration, so
G1_ITERS=8 gives a ~12m first look; the default 20 iterations is ~25m.
Ctrl-C at any point tears the bench stack down before exiting.

Knobs: G1_ITERS, G1_CELL_SECS, G1_VUS, G1_IDLE_MIN, G1_ISOLATE_READY_TIMEOUT,
G1_ISOLATE_FULL_WARMUP, G1_ISOLATE_FULL_DURATION, G1_DBDIRECT_ITERS,
G1_DBDIRECT_INTERVAL_SECS, G1_DBDIRECT_BASELINE_WAIT_SECS,
G1_DBDIRECT_BASELINE_ITERS, G3_REPEAT, G5_KEYSPACES, G10_LANGS. Order that
matters: g1-* before g3/g8 (they need the settle gate to be trustworthy),
g2-verify after the G2/H1 code lands.
EOF
}

TASK=${1:-}
case "$TASK" in
  list|help|-h|--help|"") usage ;;
  g1-timeline)    task_g1_timeline ;;
  g1-idle)        task_g1_idle ;;
  g1-isolate)     task_g1_isolate ;;
  g1-dbdirect)    task_g1_dbdirect ;;
  g2-verify)      task_g2_verify ;;
  g3-batch)       task_g3_batch ;;
  g4-refresh)     task_g4_refresh ;;
  g5-cache-sweep) task_g5_cache_sweep ;;
  g6-memory)      shift; task_g6_memory "$@" ;;
  g8-tls-h1)      task_g8_tls_h1 ;;
  g9-rlprod)      task_g9_rlprod ;;
  g10-sdk)        task_g10_sdk ;;
  pack)           task_pack ;;
  *) die "unknown task '$TASK' — run './run-improvement-tasks.sh list'" ;;
esac
