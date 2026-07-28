#!/usr/bin/env bash
# H2 — per-operation clamp probe (reproduction for
# claude_dev/postseed-transient-investigation.md).
#
# Runs a short closed-loop burst against ONE AXIAM operation at a fixed
# concurrency and prints a single TSV row:
#
#     <op>  vus=<n>  ops_s=<r>  p50_ms=<ms>  n=<count>  pct2xx=<pct>
#
# Purpose: separate the operations that are pinned by the synchronous shared
# rate-limit write (`RateLimitShared` -> `rate_limit_bucket` UPSERT) from the
# ones that are not. On a stack where the bucket write is expensive the two
# groups differ by 5-40x and the pinned group does not scale with `vus` at
# all — that difference IS the measurement.
#
# Usage (stack already up + seeded via `just target=axiam bench-up`/`bench-seed`):
#
#     benchmarks/runner/h2-clamp-probe.sh authz 20 15
#     for op in health jwks userinfo resources roles users authz cc introspect revoke login; do
#       benchmarks/runner/h2-clamp-probe.sh "$op" 1 8
#     done
#
# Why curl and not k6: every credential is minted ONCE up front, outside the
# measured window, and the published server image sets `Secure` on its session
# cookies — which k6's cookie jar refuses to replay over plaintext http, so
# every cookie-session k6 scenario dies in setup() on `p0-plaintext` (see
# §8.3 of the investigation note). curl does not care.
set -uo pipefail

OP="${1:?usage: h2-clamp-probe.sh <op> [vus] [secs]}"
W="${2:-20}"
SECS="${3:-15}"

HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
BASE="${H2_BASE:-http://localhost:${BENCH_APP_PORT:-8090}}"
SEED_ENV="${BENCH_SEED_DIR:-$BENCH/.seed}/axiam.seed.env"
[ -f "$SEED_ENV" ] || { echo "[h2-probe] no seed env at $SEED_ENV — run 'just target=axiam bench-seed'" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "$SEED_ENV"; set +a

# Requests per curl process. One process does R requests over ONE kept-alive
# connection, which amortises process spawn (~3 ms) and lifts the harness
# ceiling to ~4 000 ops/s, far above anything AXIAM produces — so a pinned op
# (~20 ops/s) can never be confused with a harness limit.
R="${H2_REPEAT:-25}"

STATE="${H2_STATE:-${TMPDIR:-/tmp}/h2-clamp-probe}"
mkdir -p "$STATE"
# Session cookies and access tokens expire in 900 s. A burst run with an
# expired credential silently measures the 401 path, which is ~50x faster and
# reads as "recovered" — re-mint anything older than 5 minutes.
find "$STATE" -maxdepth 1 -type f -mmin +5 -delete 2>/dev/null

mint() {
  if [ ! -s "$STATE/cc.tok" ]; then
    curl -sSk -X POST "$BASE/oauth2/token?tenant_id=$BENCH_TENANT_ID" \
      -d "grant_type=client_credentials&client_id=$BENCH_CLIENT_ID&client_secret=$BENCH_CLIENT_SECRET&scope=openid" \
      | jq -r '.access_token // empty' > "$STATE/cc.tok"
  fi
  if [ ! -s "$STATE/user.jar" ]; then
    curl -sSk -c "$STATE/user.jar" -o /dev/null -X POST "$BASE/api/v1/auth/login" \
      -H 'Content-Type: application/json' \
      -d "{\"org_id\":\"$BENCH_ORG_ID\",\"tenant_id\":\"$BENCH_TENANT_ID\",\"username_or_email\":\"$BENCH_USERNAME\",\"password\":\"$BENCH_PASSWORD\"}"
    awk -F'\t' '$6=="axiam_access"{print $7}' "$STATE/user.jar" > "$STATE/user.tok"
    awk -F'\t' '$6=="axiam_csrf"{print $7}'   "$STATE/user.jar" > "$STATE/user.csrf"
  fi
  if [ ! -s "$STATE/admin.jar" ]; then
    curl -sSk -c "$STATE/admin.jar" -o /dev/null -X POST "$BASE/api/v1/auth/login" \
      -H 'Content-Type: application/json' \
      -d "{\"org_slug\":\"${BENCH_ORG_SLUG:-bench-org}\",\"tenant_slug\":\"${BENCH_TENANT_SLUG:-default}\",\"username_or_email\":\"${BENCH_ADMIN_USERNAME:-admin}\",\"password\":\"${BENCH_ADMIN_PASSWORD:-Bench@Admin123!}\"}"
  fi
}
mint
CCTOK="$(cat "$STATE/cc.tok" 2>/dev/null)"
UTOK="$(cat "$STATE/user.tok" 2>/dev/null)"
CSRF="$(cat "$STATE/user.csrf" 2>/dev/null)"
[ -n "$UTOK" ] || { echo "[h2-probe] login produced no access cookie (see §8.3 of the note)" >&2; exit 1; }

# Emit "-o /dev/null <url>" R times so curl discards every body (a single -o
# applies to the FIRST url only; the rest would land on stdout and corrupt the
# -w stream).
rep() { local u="$1" i; for ((i = 0; i < R; i++)); do printf -- '-o\n/dev/null\n%s\n' "$u"; done; }

req() { # R requests on one kept-alive connection; appends "<code> <secs>" lines to $1
  local out="$1"
  case "$OP" in
    health)     curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' $(rep "$BASE/health") ;;
    jwks)       curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' $(rep "$BASE/oauth2/jwks?tenant_id=$BENCH_TENANT_ID") ;;
    discovery)  curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' $(rep "$BASE/.well-known/openid-configuration") ;;
    userinfo)   curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' -H "Authorization: Bearer $UTOK" $(rep "$BASE/oauth2/userinfo") ;;
    resources)  curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' -b "$STATE/admin.jar" $(rep "$BASE/api/v1/resources") ;;
    roles)      curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' -b "$STATE/admin.jar" $(rep "$BASE/api/v1/roles") ;;
    users)      curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' -b "$STATE/admin.jar" $(rep "$BASE/api/v1/users") ;;
    authz)      curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' -X POST \
                  -b "$STATE/user.jar" -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" \
                  -d "{\"action\":\"read\",\"resource_id\":\"$BENCH_RESOURCE_ID\"}" \
                  $(rep "$BASE/api/v1/authz/check") ;;
    cc)         curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' -X POST \
                  -d "grant_type=client_credentials&client_id=$BENCH_CLIENT_ID&client_secret=$BENCH_CLIENT_SECRET&scope=openid" \
                  $(rep "$BASE/oauth2/token?tenant_id=$BENCH_TENANT_ID") ;;
    introspect) curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' -X POST \
                  -d "token=$CCTOK&client_id=$BENCH_CLIENT_ID&client_secret=$BENCH_CLIENT_SECRET" \
                  $(rep "$BASE/oauth2/introspect?tenant_id=$BENCH_TENANT_ID") ;;
    revoke)     curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' -X POST \
                  -d "token=$CCTOK&client_id=$BENCH_CLIENT_ID&client_secret=$BENCH_CLIENT_SECRET" \
                  $(rep "$BASE/oauth2/revoke?tenant_id=$BENCH_TENANT_ID") ;;
    login)      curl -sSk --max-time "$SECS" -w '%{http_code} %{time_total}\n' -X POST \
                  -H 'Content-Type: application/json' \
                  -d "{\"org_id\":\"$BENCH_ORG_ID\",\"tenant_id\":\"$BENCH_TENANT_ID\",\"username_or_email\":\"$BENCH_USERNAME\",\"password\":\"$BENCH_PASSWORD\"}" \
                  $(rep "$BASE/api/v1/auth/login") ;;
    *) echo "[h2-probe] unknown op '$OP' (health jwks discovery userinfo resources roles users authz cc introspect revoke login)" >&2; exit 2 ;;
  esac >> "$out" 2>/dev/null
}

tmp="$(mktemp -d)"; T0=$(date +%s); end=$(( T0 + SECS ))
for i in $(seq 1 "$W"); do
  ( while [ "$(date +%s)" -lt "$end" ]; do req "$tmp/$i"; done ) &
done
wait
ELAPSED=$(( $(date +%s) - T0 )); [ "$ELAPSED" -lt 1 ] && ELAPSED=1

cat "$tmp"/* 2>/dev/null | sort -k2,2n | awk -v l="$OP" -v w="$W" -v s="$ELAPSED" '
  { n++; if ($1 ~ /^2/) ok++; t[n] = $2 * 1000 }
  END {
    if (n == 0) { printf "%s\tvus=%s\tops_s=0\tp50_ms=NA\tn=0\tpct2xx=NA\n", l, w; exit }
    printf "%s\tvus=%s\tops_s=%.1f\tp50_ms=%.0f\tn=%d\tpct2xx=%.0f\n",
           l, w, n / s, t[int(n / 2) + 1], n, 100 * ok / n
  }'
rm -rf "$tmp"
