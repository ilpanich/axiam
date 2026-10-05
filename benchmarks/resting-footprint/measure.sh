#!/usr/bin/env bash
# measure.sh — the resting footprint of an AXIAM stack, at rest, not under load.
#
# T23.8.3 / G-8. Two modes, same method, so the figures are comparable:
#
#   minimal   axiam-server (AXIAM__AMQP__ENABLED=false) + SurrealDB
#   full      axiam-server (AMQP on)                    + SurrealDB + RabbitMQ
#
# Method (what the published numbers mean):
#   * SurrealDB and RabbitMQ run as Docker containers with the same caps the
#     benchmark harness gives them (SurrealDB 2 CPU / 1 GiB, RabbitMQ 1 CPU /
#     512 MiB), on a FRESH data volume. The database is freshly migrated and
#     holds no tenant, user or traffic.
#   * axiam-server runs as the NATIVE release binary built with
#     `--features jemalloc` (what the shipped image builds), uncapped, against
#     the SurrealDB container — not as a container. Say so wherever the number
#     is quoted.
#   * Wait for GET /ready to answer 200, settle for SETTLE seconds (default 60),
#     then sample every INTERVAL seconds (default 5) for DURATION seconds
#     (default 120). One sample = every component's resident set.
#   * "RSS" of a component = the sum of VmRSS (RssAnon + RssFile + RssShmem) of
#     every process in it, read from /proc/<pid>/status. A shared library mapped
#     by two processes of one component is counted twice (RabbitMQ runs several
#     Erlang helper processes); the cgroup's own figure, as `docker stats`
#     reports it (usage minus inactive page cache), is recorded next to it for
#     the two containers.
#   * The headline is the MEDIAN over the samples, per component, and the median
#     of the per-sample total.
#
# Needs: a running Docker daemon, the release binary, openssl, curl, python3.
# Usage: measure.sh minimal|full <path-to-axiam-server> <out-dir>
# Writes <out-dir>/<mode>-samples.csv, <mode>-summary.txt and <mode>-server.log.
set -euo pipefail

MODE="${1:?mode: minimal|full}"
BIN="${2:?path to the axiam-server release binary}"
OUT="${3:?output directory}"
SETTLE="${SETTLE:-60}"
INTERVAL="${INTERVAL:-5}"
DURATION="${DURATION:-120}"
SURREAL_IMAGE="${SURREAL_IMAGE:-surrealdb/surrealdb:v3}"
RABBIT_IMAGE="${RABBIT_IMAGE:-rabbitmq:4-management-alpine}"
HTTP_PORT="${HTTP_PORT:-8090}"
SURREAL_PORT="${SURREAL_PORT:-18000}"

case "$MODE" in minimal|full) ;; *) echo "mode must be minimal or full" >&2; exit 2;; esac
mkdir -p "$OUT"
WORK="$(mktemp -d)"
SAMPLES="$OUT/$MODE-samples.csv"
SUMMARY="$OUT/$MODE-summary.txt"
SERVER_LOG="$OUT/$MODE-server.log"
SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill -TERM "$SERVER_PID" 2>/dev/null || true
  docker rm -f rf-surrealdb rf-rabbitmq >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

rand_hex() { openssl rand -hex "$1"; }

# --- credentials and keys: generated per run, never written to the output -----
DB_USER=root
DB_PASS="$(rand_hex 24)"
PEPPER="$(rand_hex 32)"
EMAIL_KEY="$(rand_hex 32)"
openssl genpkey -algorithm ed25519 -out "$WORK/jwt.pem" 2>/dev/null
openssl pkey -in "$WORK/jwt.pem" -pubout -out "$WORK/jwt.pub.pem"

# --- SurrealDB ----------------------------------------------------------------
mkdir -p "$WORK/surreal-data" && chown 65532:65532 "$WORK/surreal-data"
docker rm -f rf-surrealdb rf-rabbitmq >/dev/null 2>&1 || true
docker run -d --name rf-surrealdb --cpus 2 --memory 1g \
  -p "127.0.0.1:${SURREAL_PORT}:8000" -v "$WORK/surreal-data:/data" \
  "$SURREAL_IMAGE" start --user "$DB_USER" --pass "$DB_PASS" --log info \
  surrealkv:/data/axiam.db >/dev/null
for _ in $(seq 1 60); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' rf-surrealdb 2>/dev/null || true)" == "healthy" ]] && break
  docker exec rf-surrealdb /surreal isready >/dev/null 2>&1 && break
  sleep 1
done
docker exec rf-surrealdb /surreal isready >/dev/null

# --- RabbitMQ (full only) -----------------------------------------------------
declare -a SERVER_AMQP_ENV=(AXIAM__AMQP__ENABLED=false)
if [[ "$MODE" == "full" ]]; then
  BROKER_TLS_DIR="$WORK/broker-tls" BROKER_HOST=localhost \
    bash "$(dirname "$0")/../../scripts/gen-broker-tls.sh" >/dev/null
  chmod -R a+rX "$WORK/broker-tls"
  BROKER_PASS="$(rand_hex 16)"
  docker run -d --name rf-rabbitmq --cpus 1 --memory 512m \
    -p 127.0.0.1:5671:5671 \
    -e RABBITMQ_DEFAULT_USER=axiam -e RABBITMQ_DEFAULT_PASS="$BROKER_PASS" \
    -v "$WORK/broker-tls:/etc/rabbitmq/tls:ro" \
    -v "$(cd "$(dirname "$0")/../../docker" && pwd)/rabbitmq-tls.conf:/etc/rabbitmq/conf.d/20-tls.conf:ro" \
    "$RABBIT_IMAGE" >/dev/null
  for _ in $(seq 1 90); do
    docker exec rf-rabbitmq rabbitmq-diagnostics -q check_running >/dev/null 2>&1 && break
    sleep 1
  done
  docker exec rf-rabbitmq rabbitmq-diagnostics -q check_running >/dev/null
  SERVER_AMQP_ENV=(
    AXIAM__AMQP__ENABLED=true
    "AXIAM__AMQP__URL=amqps://axiam:${BROKER_PASS}@localhost:5671"
    "AXIAM__AMQP__TLS__CA_CERT_PATH=$WORK/broker-tls/ca.pem"
    "AXIAM__AMQP__SIGNING_KEY=$(rand_hex 32)"
  )
fi

# --- the server ---------------------------------------------------------------
(
  exec env \
    "AXIAM__DB__URL=127.0.0.1:${SURREAL_PORT}" "AXIAM__DB__USERNAME=$DB_USER" \
    "AXIAM__DB__PASSWORD=$DB_PASS" AXIAM__DB__NAMESPACE=axiam AXIAM__DB__DATABASE=axiam \
    AXIAM__SERVER__HOST=127.0.0.1 "AXIAM__SERVER__PORT=$HTTP_PORT" AXIAM__GRPC__HOST=127.0.0.1 \
    AXIAM__AUTH__SECRET_PROVIDER=env "AXIAM__AUTH__PEPPER=$PEPPER" \
    "AXIAM__AUTH__EMAIL_ENCRYPTION_KEY=$EMAIL_KEY" \
    "AXIAM__AUTH__JWT_PRIVATE_KEY_PEM=$(cat "$WORK/jwt.pem")" \
    "AXIAM__AUTH__JWT_PUBLIC_KEY_PEM=$(cat "$WORK/jwt.pub.pem")" \
    "AXIAM__GDPR_AUDIT_DLQ_FILE=$WORK/gdpr-audit-dlq.jsonl" \
    RUST_LOG=axiam=info "${SERVER_AMQP_ENV[@]}" \
    "$BIN"
) > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

READY=0
for _ in $(seq 1 180); do
  kill -0 "$SERVER_PID" 2>/dev/null || { echo "server exited early; see $SERVER_LOG" >&2; exit 1; }
  [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HTTP_PORT}/ready" || true)" == "200" ]] && { READY=1; break; }
  sleep 1
done
[[ "$READY" == 1 ]] || { echo "server never became ready; see $SERVER_LOG" >&2; exit 1; }
curl -s "http://127.0.0.1:${HTTP_PORT}/health" > "$OUT/$MODE-health.json"
echo "ready; settling ${SETTLE}s"
sleep "$SETTLE"

# --- sampling -----------------------------------------------------------------
vmrss_kib() { awk '/^VmRSS:/ {s+=$2} END {print s+0}' "$@" 2>/dev/null; }
container_rss_kib() {
  local pids
  pids="$(docker top "$1" -eo pid | tail -n +2 | tr -d ' ')"
  local total=0 f
  for p in $pids; do
    [[ -r /proc/$p/status ]] || continue
    total=$(( total + $(vmrss_kib "/proc/$p/status") ))
  done
  echo "$total"
}
stats_kib() {  # docker stats' memory figure for a container, in KiB
  docker stats --no-stream --format '{{.MemUsage}}' "$1" | python3 -c '
import re,sys
used=sys.stdin.read().split("/")[0].strip()
m=re.match(r"([0-9.]+)\s*([KMG]i?B|B)",used)
f={"B":1/1024,"KiB":1,"KB":1000/1024,"MiB":1024,"MB":1e6/1024,"GiB":1048576,"GB":1e9/1024}
print(round(float(m.group(1))*f[m.group(2)]))'
}

echo "epoch_s,component,rss_kib,cgroup_working_set_kib" > "$SAMPLES"
END=$(( $(date +%s) + DURATION ))
while [[ "$(date +%s)" -lt "$END" ]]; do
  ts="$(date +%s)"
  echo "$ts,axiam-server,$(vmrss_kib "/proc/$SERVER_PID/status"),NA" >> "$SAMPLES"
  echo "$ts,surrealdb,$(container_rss_kib rf-surrealdb),$(stats_kib rf-surrealdb)" >> "$SAMPLES"
  [[ "$MODE" == "full" ]] && echo "$ts,rabbitmq,$(container_rss_kib rf-rabbitmq),$(stats_kib rf-rabbitmq)" >> "$SAMPLES"
  sleep "$INTERVAL"
done
kill -0 "$SERVER_PID" 2>/dev/null || { echo "server died during sampling" >&2; exit 1; }

# --- summary ------------------------------------------------------------------
python3 - "$SAMPLES" "$MODE" > "$SUMMARY" <<'PY'
import csv, statistics, sys, collections
rows = list(csv.DictReader(open(sys.argv[1])))
by_ts = collections.defaultdict(dict)
for r in rows:
    by_ts[r["epoch_s"]][r["component"]] = (int(r["rss_kib"]),
        None if r["cgroup_working_set_kib"] == "NA" else int(r["cgroup_working_set_kib"]))
comps = sorted({r["component"] for r in rows})
mib = lambda k: k / 1024
print(f"mode: {sys.argv[2]}   samples: {len(by_ts)}")
for c in comps:
    rss = [v[c][0] for v in by_ts.values() if c in v]
    line = f"{c:13s} RSS median {mib(statistics.median(rss)):8.1f} MiB  min {mib(min(rss)):8.1f}  max {mib(max(rss)):8.1f}"
    ws = [v[c][1] for v in by_ts.values() if c in v and v[c][1] is not None]
    if ws:
        line += f"   | cgroup working set median {mib(statistics.median(ws)):8.1f} MiB"
    print(line)
tot = [sum(x[0] for x in v.values()) for v in by_ts.values()]
print(f"{'TOTAL':13s} RSS median {mib(statistics.median(tot)):8.1f} MiB  min {mib(min(tot)):8.1f}  max {mib(max(tot)):8.1f}")
PY
cat "$SUMMARY"
