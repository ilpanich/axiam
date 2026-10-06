#!/usr/bin/env bash
# resting-sample.sh — the memory of a RUNNING benchmark stack at rest, no load.
#
# T23.10.2(a) / G-10 / G-8. Run 6 has two memory questions the per-cell sampler
# cannot answer, because it only runs while k6 is driving load:
#
#   * Keycloak 26.8's release notes headline "reduced memory usage". What is at
#     rest is a different thing from what is under load, and a claim about
#     memory needs both, at the product's defaults. (benchmarks/README.md, "Keycloak
#     26.8's reduced-memory claim", says what the release notes verifiably credit.)
#   * G-8's whole-stack resting footprint, for all four targets and for AXIAM's
#     minimal profile, as the released image ran in THIS harness under THESE caps
#     (benchmarks/resting-footprint/measure.sh measured the native binary beside
#     SurrealDB and RabbitMQ containers, which is not the same thing).
#
# It does not start, seed or stop anything: bring a stack up (`bench-up`), call
# this, seed, call it again. Two stages are the convention:
#     fresh   straight after bench-up: a freshly migrated, empty datastore
#     seeded  after bench-seed: the benchmark fixture, still no load
#
# Method (what the numbers mean):
#   * the containers are the target's own (the same list run-benchmark.sh records in
#     meta.json), so every container in the stack is counted, including authentik's
#     worker and AXIAM's broker;
#   * wait SETTLE seconds, then sample every INTERVAL seconds for DURATION seconds;
#   * one sample of one container = `rss_kib`, the sum of VmRSS of every process in
#     it (RssAnon + RssFile + RssShmem, read from /proc/<pid>/status for the host
#     PIDs `docker top` lists; Linux hosts only), `rss_anon_kib` (RssAnon: heap and
#     stacks, no mapped files) and `cgroup_working_set_kib` (what `docker stats`
#     reports: cgroup usage minus inactive page cache — the figure a container
#     memory limit is judged against);
#   * the headline is the MEDIAN over the samples, per container, and of the
#     per-sample stack total. Medians, not means: one JIT or GC step is not a state.
#
# Output (under $OUT, default results/resting/<target>[-minimal]/):
#   <stage>-samples.csv  <stage>-summary.txt  <stage>-meta.json
# `bench-pack` includes all three (*.csv, *.txt, *.json).
#
# A figure from this script is "at rest, not under load". The container caps are
# the stack's own (docker inspect) and are recorded; a JVM sizes its heap as a
# percentage of its container limit, so a Keycloak figure is only meaningful with
# its cap beside it.
#
# Usage:  resting-sample.sh <target> <stage> [out-dir]
#   target  axiam | keycloak | zitadel | authentik     (AXIAM minimal: say so via DEPLOY=minimal)
#   stage   fresh | seeded | <any label>
# Env:    SETTLE (90) INTERVAL (5) DURATION (60) DEPLOY (full|minimal, default: read off the stack)
set -euo pipefail

TARGET="${1:?usage: resting-sample.sh <target> <stage> [out-dir]}"
STAGE="${2:?usage: resting-sample.sh <target> <stage> [out-dir]}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
SETTLE="${SETTLE:-90}"
INTERVAL="${INTERVAL:-5}"
DURATION="${DURATION:-60}"

case "$TARGET" in
  axiam)     CONTAINERS="bench-axiam-server bench-axiam-surrealdb bench-axiam-rabbitmq" ;;
  keycloak)  CONTAINERS="bench-keycloak bench-keycloak-postgres" ;;
  zitadel)   CONTAINERS="bench-zitadel bench-zitadel-postgres" ;;
  authentik) CONTAINERS="bench-authentik bench-authentik-worker bench-authentik-postgres" ;;
  *) echo "[resting] unknown target '$TARGET'" >&2; exit 2 ;;
esac

# Only the containers that exist: AXIAM's minimal profile has no broker, and the
# nginx edge is not part of a p0 stack. A listed container that is not RUNNING is
# an error for the first one (the server), a skip for the rest.
LIVE=""
for c in $CONTAINERS; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || true)" = "true" ]; then
    LIVE="${LIVE:+$LIVE }$c"
  fi
done
FIRST="${CONTAINERS%% *}"
case " $LIVE " in *" $FIRST "*) ;; *) echo "[resting] $FIRST is not running — bring the stack up first (just target=$TARGET bench-up)" >&2; exit 1 ;; esac

DEPLOY="${DEPLOY:-}"
if [ -z "$DEPLOY" ]; then
  DEPLOY=n/a
  if [ "$TARGET" = "axiam" ]; then
    amqp="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' bench-axiam-server 2>/dev/null | sed -n 's/^AXIAM__AMQP__ENABLED=//p' | head -1)"
    case "$amqp" in false|FALSE|False|0) DEPLOY=minimal ;; *) DEPLOY=full ;; esac
  fi
fi

SUFFIX=""
[ "$DEPLOY" != minimal ] || SUFFIX="-minimal"
OUT="${3:-$BENCH/results/resting/$TARGET$SUFFIX}"
mkdir -p "$OUT"
SAMPLES="$OUT/$STAGE-samples.csv"
SUMMARY="$OUT/$STAGE-summary.txt"
META="$OUT/$STAGE-meta.json"

PROC_OK=1
host_pid_of() { docker top "$1" -eo pid 2>/dev/null | tail -n +2 | tr -d ' ' | grep -E '^[0-9]+$' || true; }
probe_pid="$(host_pid_of "$FIRST" | head -1)"
if [ -z "$probe_pid" ] || [ ! -r "/proc/$probe_pid/status" ]; then
  PROC_OK=0
  echo "[resting] WARN: host /proc is not readable for the container's processes (Docker Desktop, or a remote daemon?) — recording the cgroup working set only; rss_kib and rss_anon_kib will read NA." >&2
fi

container_rss() {  # NAME -> "rss_kib,rss_anon_kib"
  local total=0 anon=0 p v a
  for p in $(host_pid_of "$1"); do
    [ -r "/proc/$p/status" ] || continue
    v="$(awk '/^VmRSS:/ {print $2}' "/proc/$p/status" 2>/dev/null || true)"
    a="$(awk '/^RssAnon:/ {print $2}' "/proc/$p/status" 2>/dev/null || true)"
    total=$(( total + ${v:-0} )); anon=$(( anon + ${a:-0} ))
  done
  echo "$total,$anon"
}
stats_kib() {  # NAME -> docker stats' memory usage in KiB
  docker stats --no-stream --format '{{.MemUsage}}' "$1" | python3 -I -c '
import re, sys
used = sys.stdin.read().split("/")[0].strip()
m = re.match(r"([0-9.]+)\s*([KMGT]?i?B)", used)
f = {"B": 1/1024, "KiB": 1, "KB": 1000/1024, "MiB": 1024, "MB": 1e6/1024, "GiB": 1048576, "GB": 1e9/1024}
print(round(float(m.group(1)) * f[m.group(2)]))'
}

echo "[resting] $TARGET ($DEPLOY) stage=$STAGE: settling ${SETTLE}s, then sampling ${DURATION}s every ${INTERVAL}s — containers: $LIVE"
sleep "$SETTLE"

echo "epoch_s,container,rss_kib,rss_anon_kib,cgroup_working_set_kib" > "$SAMPLES"
END=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$END" ]; do
  ts="$(date +%s)"
  for c in $LIVE; do
    if [ "$PROC_OK" = 1 ]; then r="$(container_rss "$c")"; else r="NA,NA"; fi
    echo "$ts,$c,$r,$(stats_kib "$c")" >> "$SAMPLES"
  done
  sleep "$INTERVAL"
done

# --- provenance: what exactly ran, with which caps --------------------------
{
  echo "{"
  echo "  \"target\": \"$TARGET\", \"deploy_profile\": \"$DEPLOY\", \"stage\": \"$STAGE\","
  echo "  \"measured\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"settle_secs\": $SETTLE, \"duration_secs\": $DURATION, \"interval_secs\": $INTERVAL,"
  echo "  \"load\": \"none (at rest)\", \"rss_source\": \"$([ "$PROC_OK" = 1 ] && echo /proc || echo cgroup-only)\","
  echo "  \"host_kernel\": \"$(uname -r)\", \"docker_version\": \"$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)\","
  echo "  \"containers\": ["
  first=1
  for c in $LIVE; do
    [ "$first" = 1 ] || echo ","
    first=0
    img="$(docker inspect -f '{{.Config.Image}}' "$c")"
    # RepoDigests is a property of the image, not of the container.
    dig="$(docker image inspect -f '{{index .RepoDigests 0}}' "$(docker inspect -f '{{.Image}}' "$c")" 2>/dev/null || true)"
    dig="${dig#*@}"
    [ -n "$dig" ] && [ "$dig" != "<no value>" ] || dig="$(docker inspect -f '{{.Image}}' "$c")"
    nano="$(docker inspect -f '{{.HostConfig.NanoCpus}}' "$c")"
    mem="$(docker inspect -f '{{.HostConfig.Memory}}' "$c")"
    started="$(docker inspect -f '{{.State.StartedAt}}' "$c")"
    printf '    {"name": "%s", "image": "%s", "image_digest": "%s", "cpu_cap": %s, "mem_cap_mib": %s, "started_at": "%s"}' \
      "$c" "$img" "$dig" "$(awk -v n="$nano" 'BEGIN{printf "%.2f", n/1e9}')" "$(awk -v b="$mem" 'BEGIN{printf "%.0f", b/1048576}')" "$started"
  done
  echo
  echo "  ]"
  echo "}"
} > "$META"

# --- summary ------------------------------------------------------------------
python3 -I - "$SAMPLES" "$TARGET" "$DEPLOY" "$STAGE" > "$SUMMARY" <<'PY'
import csv, statistics, sys, collections
rows = list(csv.DictReader(open(sys.argv[1])))
by_ts = collections.defaultdict(dict)
def num(x):
    return None if x in ("NA", "") else int(x)
for r in rows:
    by_ts[r["epoch_s"]][r["container"]] = (num(r["rss_kib"]), num(r["rss_anon_kib"]), num(r["cgroup_working_set_kib"]))
names = sorted({r["container"] for r in rows})
mib = lambda k: k / 1024
print(f"target: {sys.argv[2]}   deploy profile: {sys.argv[3]}   stage: {sys.argv[4]}   samples: {len(by_ts)}   (at rest, no load)")
def med(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else None
def fmt(v):
    return "      NA" if v is None else f"{mib(v):8.1f}"
print(f"{'container':28s} {'RSS MiB':>8s} {'anon MiB':>9s} {'cgroup working set MiB':>24s}")
for c in names:
    col = lambda i: med([v[c][i] for v in by_ts.values() if c in v])
    print(f"{c:28s} {fmt(col(0))} {fmt(col(1)):>9s} {fmt(col(2)):>24s}")
tot = lambda i: [sum(x[i] for x in v.values() if x[i] is not None) for v in by_ts.values() if all(x[i] is not None for x in v.values())]
t0, t1, t2 = med(tot(0)), med(tot(1)), med(tot(2))
print(f"{'STACK TOTAL (median)':28s} {fmt(t0)} {fmt(t1):>9s} {fmt(t2):>24s}")
PY
cat "$SUMMARY"
