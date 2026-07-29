#!/usr/bin/env bash
# h6-connection-probe.sh — count the TCP connections a load generator actually
# opens to a listener, and how the server's worker threads share the work.
#
# WHY THIS EXISTS. The whole HTTP/2 hypothesis in
# claude_dev/b2-tls-h2-investigation.md §1.2-1.3 rests on one unmeasured
# premise: that under h2 the load generator's N concurrent clients COLLAPSE
# onto ~one TCP connection, which actix then pins to ~one worker thread — so a
# 2-worker server loses half its capacity. Every throughput table in the world
# is circumstantial next to simply counting the connections. This script counts
# them, and reads per-thread CPU of the server process at the same time.
#
# It infers nothing from throughput. Run it DURING a measured cell:
#
#   runner/h6-connection-probe.sh --port 8090 --secs 20
#   runner/h6-connection-probe.sh --port 8443 --secs 20
#
# Method notes:
#   * Connections are counted from the SERVER's network namespace via
#     nsenter + /proc/net/tcp, not from the host — the host namespace also
#     contains docker-proxy's own sockets and would double count.
#   * State 01 is ESTABLISHED (see net/tcp_states.h); the listening socket is
#     state 0A and is excluded.
#   * Per-thread CPU comes from the HOST's /proc/<container-pid>/task/*/stat,
#     sampled at the start and end of the window (the server image is
#     distroless, so there is no shell to run inside it). The threads that
#     matter are named `actix-server wo` — one per actix worker, i.e. one per
#     BENCH_CPUS. If ONE of them carries the load while the other idles, the
#     connection-pinning mechanism of b2-tls-h2-investigation.md §1.2 is
#     happening; if both are equal, it is not.
set -euo pipefail

CONTAINER=${CONTAINER:-bench-axiam-server}
PORT=8090
SECS=20
INTERVAL=2

while [ $# -gt 0 ]; do
  case "$1" in
    --container) CONTAINER="$2"; shift 2 ;;
    --port)      PORT="$2"; shift 2 ;;
    --secs)      SECS="$2"; shift 2 ;;
    --interval)  INTERVAL="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

PID="$(docker inspect -f '{{.State.Pid}}' "$CONTAINER" 2>/dev/null || true)"
[ -n "$PID" ] && [ "$PID" != "0" ] || { echo "[h6-conn] container '$CONTAINER' is not running" >&2; exit 1; }

# ---- connection census (server-side netns) ---------------------------------
census() {
  nsenter -t "$PID" -n cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | python3 -c '
import sys
port = int(sys.argv[1])
est = 0
peers = set()
for line in sys.stdin:
    f = line.split()
    if len(f) < 4 or f[0] == "sl":
        continue
    try:
        lp = int(f[1].split(":")[1], 16)
        rip, rp = f[2].split(":")
        rp = int(rp, 16)
        st = f[3]
    except (ValueError, IndexError):
        continue
    if st != "01" or lp != port:
        continue
    est += 1
    peers.add(rip)
print(est, len(peers))
' "$PORT"
}

# ---- per-thread CPU of the server process ----------------------------------
# Returns "<threadname> <utime+stime ticks>" for every thread, so two samples
# subtract to a per-thread CPU delta over the interval.
threads() {
  # Read the container's threads from the HOST's /proc: a container process is
  # an ordinary host process in a different namespace, so /proc/<host-pid>/task
  # is fully readable. (nsenter -m into the container is not an option — the
  # server image is distroless and has no shell to run there.)
  python3 - "$PID" <<'PY'
import os, sys
pid = sys.argv[1]
base = "/proc/%s/task" % pid
try:
    tids = os.listdir(base)
except OSError:
    raise SystemExit
for tid in tids:
    try:
        with open("%s/%s/stat" % (base, tid)) as f:
            stat = f.read()
    except OSError:
        continue
    # /proc/<tid>/stat: field 2 is "(comm)" and may contain spaces/parens, so
    # split on the LAST ")" — utime/stime are then fields 12 and 13 of the rest.
    try:
        close = stat.rindex(")")
    except ValueError:
        continue
    name = stat[stat.index("(") + 1:close]
    rest = stat[close + 1:].split()
    try:
        # /proc comm may contain spaces ("actix-server wo"); the reader
        # below splits on whitespace, so collapse them or the busiest
        # threads in this very process silently vanish from the table.
        print("%s|%s" % (name.replace(" ", "_"), tid), int(rest[11]) + int(rest[12]))
    except (IndexError, ValueError):
        continue
PY
}

echo "container=$CONTAINER pid=$PID port=$PORT sampling ${SECS}s every ${INTERVAL}s"
echo
printf '%-8s %-14s %s\n' "t(s)" "established" "distinct peer IPs"
THREADS_A="$(threads)"
t=0
max_est=0; min_est=999999
while [ "$t" -lt "$SECS" ]; do
  read -r est peers <<<"$(census)"
  printf '%-8s %-14s %s\n' "$t" "${est:-?}" "${peers:-?}"
  [ -n "${est:-}" ] && { [ "$est" -gt "$max_est" ] && max_est=$est; [ "$est" -lt "$min_est" ] && min_est=$est; } || true
  sleep "$INTERVAL"
  t=$((t + INTERVAL))
done
echo
echo "established connections to :$PORT — min=$min_est max=$max_est"
echo

echo "per-thread CPU over ${SECS}s (cores; 100 ticks = 1 core-second):"
printf '%s\n---\n%s\n' "$THREADS_A" "$(threads)" | SECS="$SECS" python3 -c '
import os, sys
raw = sys.stdin.read().split("---")
def parse(block):
    # Key on "comm|tid" alone — NOT on line position: /proc/<pid>/task listing
    # order is not stable between samples, and keying on position silently
    # subtracts one thread from another and reports every thread as idle.
    out = {}
    for line in block.split("\n"):
        p = line.split()
        if len(p) == 2:
            out[p[0]] = int(p[1])
    return out
a, b = parse(raw[0]), parse(raw[1])
rows = []
for k, v in b.items():
    if k in a and v - a[k] >= 0:
        rows.append((v - a[k], k))
rows.sort(reverse=True)
secs = float(os.environ.get("SECS", "1")) or 1.0
total = sum(t for t, _ in rows)
for ticks, name in rows[:12]:
    if ticks:
        print("  %-34s %6.3f" % (name, ticks / 100.0 / secs))
if not total:
    print("  (all threads idle during the sample)")
else:
    print("  %-34s %6.3f" % ("TOTAL", total / 100.0 / secs))
'
