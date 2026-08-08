#!/usr/bin/env bash
# bulk-seed.sh — inflate the seeded AXIAM bench fixture to N x scale (E3 / J12).
#
# Prerequisites: the axiam stack is up (`just target=axiam ... bench-up`) and
# `just target=axiam bench-seed` has completed, so .seed/axiam.seed.env carries
# the tenant/org the bulk rows attach to.
#
# The generated SurrealQL goes straight into the datastore's own CLI inside the
# container. SurrealDB is deliberately NOT port-published by the bench compose
# file (targets/axiam/docker-compose.yml), so `docker exec` is the access path
# — and using the container's `/surreal` client rather than an HTTP POST means
# the load speaks the same protocol version as the server it is loading.
#
# Usage:
#   runner/bulk-seed.sh [--scale N] [--verify-only] [-- <bulk-seed.py args>]
#
# Env knobs (all optional):
#   BENCH_SEED_SCALE     multiplier, default 10
#   BENCH_SEED_USERS     base users per tenant, default 1000
#   BENCH_SEED_RESOURCES base resources per tenant, default 200
#   BENCH_SEED_ROLES     base roles per tenant, default 50
#   BENCH_SEED_TENANTS   extra tenants, default 0
#   BENCH_SEED_DEPTH     resource-tree depth, default 4
#   BENCH_SEED_DENY_RATIO fraction of grants written as deny, default 0.05
#   BENCH_SEED_BATCH     statements per transaction, default 1000
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
SEED_DIR="${BENCH_SEED_DIR:-$BENCH/.seed}"
SEED_ENV="$SEED_DIR/axiam.seed.env"
RESULTS="${BENCH_RESULTS_DIR:-$BENCH/results}"
DB_CONTAINER="${BENCH_DB_CONTAINER:-bench-axiam-surrealdb}"

VERIFY_ONLY=0
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --scale) BENCH_SEED_SCALE="$2"; shift 2 ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    --) shift; EXTRA=("$@"); break ;;
    *) echo "[bulk-seed] unknown argument: $1" >&2; exit 2 ;;
  esac
done

SCALE="${BENCH_SEED_SCALE:-10}"
USERS="${BENCH_SEED_USERS:-1000}"
RESOURCES="${BENCH_SEED_RESOURCES:-200}"
ROLES="${BENCH_SEED_ROLES:-50}"
TENANTS="${BENCH_SEED_TENANTS:-0}"
DEPTH="${BENCH_SEED_DEPTH:-4}"
DENY_RATIO="${BENCH_SEED_DENY_RATIO:-0.05}"
BATCH="${BENCH_SEED_BATCH:-1000}"

[ -f "$SEED_ENV" ] || {
  echo "[bulk-seed] $SEED_ENV not found — run 'just target=axiam bench-seed' first." >&2
  exit 1
}
# shellcheck disable=SC1090
source "$SEED_ENV"
[ -n "${BENCH_TENANT_ID:-}" ] || { echo "[bulk-seed] BENCH_TENANT_ID is empty in $SEED_ENV" >&2; exit 1; }

docker inspect "$DB_CONTAINER" >/dev/null 2>&1 || {
  echo "[bulk-seed] container $DB_CONTAINER is not running — bring the stack up first." >&2
  exit 1
}

# The datastore credentials the compose file gave the container. Read them back
# off `docker inspect` rather than trusting this shell, for the same reason
# run-benchmark.sh does: what ACTUALLY ran is the only reliable source.
db_env() { docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$DB_CONTAINER" 2>/dev/null | sed -n "s/^$1=//p" | head -1; }
DB_USER="${AXIAM__DB__USERNAME:-$(db_env SURREAL_USER)}"
DB_PASS="${AXIAM__DB__PASSWORD:-$(db_env SURREAL_PASS)}"
DB_NS="${AXIAM__DB__NAMESPACE:-axiam}"
DB_DB="${AXIAM__DB__DATABASE:-axiam}"
if [ -z "$DB_USER" ] || [ -z "$DB_PASS" ]; then
  # The bench compose passes them on the command line, not the environment.
  CMDLINE="$(docker inspect -f '{{json .Config.Cmd}}' "$DB_CONTAINER" 2>/dev/null || echo '[]')"
  DB_USER="${DB_USER:-$(printf '%s' "$CMDLINE" | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a[a.index("--user")+1] if "--user" in a else "")')}"
  DB_PASS="${DB_PASS:-$(printf '%s' "$CMDLINE" | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a[a.index("--pass")+1] if "--pass" in a else "")')}"
fi
[ -n "$DB_USER" ] && [ -n "$DB_PASS" ] || {
  echo "[bulk-seed] could not determine datastore credentials — export AXIAM__DB__USERNAME/PASSWORD." >&2
  exit 1
}

# One `surreal sql` invocation, reading SurrealQL on stdin.
sql() {
  docker exec -i "$DB_CONTAINER" /surreal sql \
    --endpoint http://localhost:8000 \
    --username "$DB_USER" --password "$DB_PASS" \
    --namespace "$DB_NS" --database "$DB_DB" \
    --hide-welcome "$@"
}

# Row counts for the tables the load touches. Printed before and after so the
# operator sees the delta rather than a claim about it — the same "publish the
# receipts" rule the benchmark docs apply to throughput numbers.
counts() {
  printf 'SELECT count() FROM user GROUP ALL;
SELECT count() FROM resource GROUP ALL;
SELECT count() FROM role GROUP ALL;
SELECT count() FROM permission GROUP ALL;
SELECT count() FROM grants GROUP ALL;
SELECT count() FROM has_role GROUP ALL;
SELECT count() FROM tenant GROUP ALL;
' | sql 2>/dev/null | tr -d '\n' | sed 's/}\]\[/}] [/g'
}

echo "[bulk-seed] target tenant $BENCH_TENANT_ID in $DB_CONTAINER ($DB_NS/$DB_DB)"
echo "[bulk-seed] BEFORE: $(counts)"

if [ "$VERIFY_ONLY" = "1" ]; then
  exit 0
fi

echo "[bulk-seed] scale=${SCALE}x -> $((USERS * SCALE)) users, $((RESOURCES * SCALE)) resources (depth $DEPTH), $((ROLES * SCALE)) roles per tenant; extra tenants=$TENANTS; batch=$BATCH"

SQL_FILE="$(mktemp)"
trap 'rm -f "$SQL_FILE"' EXIT
python3 "$HERE/bulk-seed.py" \
  --tenant-id "$BENCH_TENANT_ID" \
  --org-id "${BENCH_ORG_ID:-}" \
  --scale "$SCALE" \
  --users "$USERS" \
  --resources "$RESOURCES" \
  --roles "$ROLES" \
  --tenants "$TENANTS" \
  --depth "$DEPTH" \
  --deny-ratio "$DENY_RATIO" \
  --batch "$BATCH" \
  "${EXTRA[@]+"${EXTRA[@]}"}" > "$SQL_FILE"

START="$(date +%s)"
if ! sql < "$SQL_FILE" > "$RESULTS/bulk-seed.log" 2>&1; then
  echo "[bulk-seed] FAILED — see $RESULTS/bulk-seed.log (last 20 lines):" >&2
  tail -20 "$RESULTS/bulk-seed.log" >&2
  exit 1
fi
# `surreal sql` exits 0 even when individual statements error, so the log is
# the real verdict. A failed transaction reports its error inline.
if grep -qiE '"?(error|Parse error|thrown)' "$RESULTS/bulk-seed.log"; then
  echo "[bulk-seed] FAILED — the datastore reported errors (see $RESULTS/bulk-seed.log):" >&2
  grep -iE '"?(error|Parse error|thrown)' "$RESULTS/bulk-seed.log" | head -10 >&2
  exit 1
fi
ELAPSED=$(( $(date +%s) - START ))

echo "[bulk-seed] loaded in ${ELAPSED}s"
echo "[bulk-seed] AFTER:  $(counts)"

# Record the fixture scale next to the seed env so run-benchmark.sh can put it
# in each cell's metadata — a throughput number measured against a 10x fixture
# is not comparable to one measured against the base fixture, and the archive
# has to say which it was.
{
  echo "export BENCH_SEED_SCALE=$SCALE"
  echo "export BENCH_SEED_USERS_TOTAL=$((USERS * SCALE))"
  echo "export BENCH_SEED_RESOURCES_TOTAL=$((RESOURCES * SCALE))"
  echo "export BENCH_SEED_ROLES_TOTAL=$((ROLES * SCALE))"
  echo "export BENCH_SEED_TENANTS_EXTRA=$TENANTS"
  echo "export BENCH_SEED_DEPTH=$DEPTH"
  echo "export BENCH_SEED_DENY_RATIO=$DENY_RATIO"
} > "$SEED_DIR/axiam.bulk.env"
chmod 600 "$SEED_DIR/axiam.bulk.env"
echo "[bulk-seed] wrote $SEED_DIR/axiam.bulk.env (sourced by run-benchmark.sh into cell metadata)"
