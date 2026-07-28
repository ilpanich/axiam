#!/usr/bin/env bash
# H5 / plan step 3 — automated live-stack revocation check for the D7 decision
# cache (criterion C7 of claude_dev/decision-cache-decision.md).
#
# WHY THIS EXISTS
# ---------------
# `cargo test -p axiam-authz --test decision_cache_integration_test` proves the
# ENGINE's invalidation contract against mutable mock repositories. It cannot
# prove that the REST mutation handlers reach that contract over the wire, and
# the decision note therefore carried a MANUAL curl procedure (§4.2 steps 1-5).
# This script is that procedure, automated, so C7 is re-runnable rather than a
# one-off observation.
#
# WHAT IT CHECKS (against a running `just target=axiam bench-up` + `bench-seed`)
#
#   A. Layer 1 — event-driven invalidation, END TO END.
#      Warm a real cache entry for the seeded (benchuser, bench-resource, read)
#      tuple, then revoke the role assignment through the REST admin API
#      (DELETE /api/v1/roles/{role}/users/{user} -> the `invalidate_subject`
#      hook) and immediately re-check. The decision MUST already be deny. An
#      allow here means the hook did not fire over the wire.
#
#   B. Layer 2 — bounded staleness when the invalidation event is SUPPRESSED.
#      Re-grant, re-warm, then delete the `has_role` edge DIRECTLY IN SURREALDB
#      (`docker exec … /surreal sql`), which no handler observes — the exact
#      "out-of-band write" the note's threat model calls out. With the cache ON
#      the server must keep answering allow (that is the stale window, and
#      observing it is what proves the suppression really worked), and it must
#      flip to deny within the configured TTL. With the cache OFF the very
#      first poll must already deny — that is the control that shows the stale
#      window is the cache's doing and nothing else's.
#
# Both halves are FUNCTIONAL, not throughput: they are unaffected by the
# per-request rate-limit-counter clamp documented in
# claude_dev/postseed-transient-investigation.md, so they are valid on any host.
#
# USAGE
#   benchmarks/runner/h5-revocation-check.sh            # auto-detects cache on/off
#   EXPECT_CACHE=off benchmarks/runner/h5-revocation-check.sh
#
# Env knobs: BENCH_SCHEME/BENCH_HOST/BENCH_PORT (default https/localhost/8443 —
# run under p2-tls13; a p0-plaintext stack needs BENCH_SCHEME=http
# BENCH_PORT=8090), BENCH_ADMIN_EMAIL/BENCH_ADMIN_PASSWORD, TTL_SECS (default:
# read from the server container), POLL_MS, SERVER_CONTAINER, DB_CONTAINER.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_ROOT="$(cd "$HERE/.." && pwd)"

SCHEME="${BENCH_SCHEME:-https}"
HOST="${BENCH_HOST:-localhost}"
PORT="${BENCH_PORT:-8443}"
BASE="${BENCH_BASE_URL:-$SCHEME://$HOST:$PORT}"
SERVER_CONTAINER="${SERVER_CONTAINER:-bench-axiam-server}"
DB_CONTAINER="${DB_CONTAINER:-bench-axiam-surrealdb}"
POLL_MS="${POLL_MS:-200}"
ADMIN_EMAIL="${BENCH_ADMIN_EMAIL:-admin@bench.dev}"
ADMIN_PW="${BENCH_ADMIN_PASSWORD:-Bench@Admin123!}"
ROLE_NAME="${BENCH_ROLE_NAME:-bench-reader}"

FAILURES=0
note()  { printf '[h5-revocation] %s\n' "$*"; }
pass()  { printf '[h5-revocation] PASS  %s\n' "$*"; }
fail()  { printf '[h5-revocation] FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
die()   { printf '[h5-revocation] ERROR %s\n' "$*" >&2; exit 2; }

command -v jq >/dev/null || die "jq is required"
command -v docker >/dev/null || die "docker is required (out-of-band DB write)"

# --- fixtures ---------------------------------------------------------------
SEED_ENV="$BENCH_ROOT/.seed/axiam.seed.env"
[ -f "$SEED_ENV" ] || die "missing $SEED_ENV — run 'just target=axiam bench-seed' first"
# shellcheck disable=SC1090
source "$SEED_ENV"
: "${BENCH_TENANT_SLUG:?}" "${BENCH_ORG_SLUG:?}" "${BENCH_USERNAME:?}" "${BENCH_PASSWORD:?}"
: "${BENCH_SUBJECT_ID:?}" "${BENCH_RESOURCE_ID:?}"

# --- what is the server actually configured with? ---------------------------
srv_env() { docker inspect "$SERVER_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null; }
CACHE_ENABLED="$(srv_env | sed -n 's/^AXIAM__AUTHZ__DECISION_CACHE_ENABLED=//p')"
TTL_SECS="${TTL_SECS:-$(srv_env | sed -n 's/^AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS=//p')}"
TTL_SECS="${TTL_SECS:-5}"
EXPECT_CACHE="${EXPECT_CACHE:-${CACHE_ENABLED:-unknown}}"
[ "$EXPECT_CACHE" = "true" ] && EXPECT_CACHE=on
[ "$EXPECT_CACHE" = "false" ] && EXPECT_CACHE=off
case "$EXPECT_CACHE" in on|off) ;; *) die "cannot determine cache state (set EXPECT_CACHE=on|off)";; esac
note "target=$BASE  cache=$EXPECT_CACHE  ttl=${TTL_SECS}s  poll=${POLL_MS}ms"

DB_USER="$(srv_env | sed -n 's/^AXIAM__DB__USERNAME=//p')"
DB_PASS="$(srv_env | sed -n 's/^AXIAM__DB__PASSWORD=//p')"
DB_NS="$(srv_env | sed -n 's/^AXIAM__DB__NAMESPACE=//p')"; DB_NS="${DB_NS:-axiam}"
DB_DB="$(srv_env | sed -n 's/^AXIAM__DB__DATABASE=//p')"; DB_DB="${DB_DB:-axiam}"
[ -n "$DB_USER" ] && [ -n "$DB_PASS" ] || die "could not read DB credentials from $SERVER_CONTAINER"

# Run one SQL statement straight against the datastore, bypassing AXIAM
# entirely — this is how the invalidation event is suppressed in test B.
db_sql() {
  echo "$1" | docker exec -i "$DB_CONTAINER" /surreal sql \
    --endpoint http://localhost:8000 --user "$DB_USER" --pass "$DB_PASS" \
    --ns "$DB_NS" --db "$DB_DB" --json 2>/dev/null | grep -v '^#' | tr -d '\t' | grep -v '^$'
}

now_ms() { date +%s%3N; }

# --- sessions ---------------------------------------------------------------
ADMIN_JAR="$(mktemp)"; USER_JAR="$(mktemp)"
trap 'rm -f "$ADMIN_JAR" "$USER_JAR"' EXIT

login() {  # JAR USERNAME PASSWORD -> prints nothing, exits non-zero on failure
  local jar="$1" u="$2" p="$3" body
  body=$(curl -sSk -c "$jar" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"org_slug\":\"$BENCH_ORG_SLUG\",\"tenant_slug\":\"$BENCH_TENANT_SLUG\",\"username_or_email\":\"$u\",\"password\":\"$p\"}")
  awk -F'\t' '$6=="axiam_access"{f=1} END{exit !f}' "$jar" || { echo "$body" >&2; return 1; }
}
csrf_of() { awk -F'\t' '$6=="axiam_csrf"{v=$7} END{print v}' "$1"; }

api() {  # JAR METHOD PATH [BODY] -> body, then "\n<http_code>"
  local jar="$1" method="$2" path="$3" data="${4:-}" csrf
  csrf="$(csrf_of "$jar")"
  if [ -n "$data" ]; then
    curl -sSk -b "$jar" -c "$jar" -X "$method" "$BASE$path" -H 'Content-Type: application/json' \
      -H "X-CSRF-Token: $csrf" -d "$data" -w $'\n%{http_code}'
  else
    curl -sSk -b "$jar" -c "$jar" -X "$method" "$BASE$path" -H "X-CSRF-Token: $csrf" -w $'\n%{http_code}'
  fi
}

# The measured operation: one real authorization decision for the seeded tuple,
# as benchuser. Prints "allow" | "deny" | "err:<code>".
check() {
  local resp code body
  resp=$(api "$USER_JAR" POST /api/v1/authz/check \
    "{\"action\":\"read\",\"resource_id\":\"$BENCH_RESOURCE_ID\"}")
  code="${resp##*$'\n'}"; body="${resp%$'\n'*}"
  [ "$code" = "200" ] || { echo "err:$code"; return; }
  # NB: `.allowed // empty` is WRONG here — jq's `//` treats `false` as empty,
  # so a deny would read as a malformed body.
  case "$(echo "$body" | jq -r 'if .allowed == true then "allow" elif .allowed == false then "deny" else "err" end')" in
    allow) echo allow ;;
    deny)  echo deny ;;
    *)     echo "err:body:$(echo "$body" | tr -d '\n' | cut -c1-160)" ;;
  esac
}

login "$ADMIN_JAR" admin "$ADMIN_PW" || die "admin login failed"
login "$USER_JAR" "$BENCH_USERNAME" "$BENCH_PASSWORD" || die "benchuser login failed"

ROLE_ID=$(api "$ADMIN_JAR" GET /api/v1/roles | sed '$d' \
  | jq -r --arg n "$ROLE_NAME" '[.. | objects | select(.name==$n) | .id] | first // empty')
[ -n "$ROLE_ID" ] || die "role '$ROLE_NAME' not found — is the stack seeded?"
note "role=$ROLE_ID user=$BENCH_SUBJECT_ID resource=$BENCH_RESOURCE_ID"

grant() {  # (re-)assign the seeded role; also a cache-invalidating mutation
  api "$ADMIN_JAR" POST "/api/v1/roles/$ROLE_ID/users" \
    "{\"user_id\":\"$BENCH_SUBJECT_ID\",\"resource_id\":\"$BENCH_RESOURCE_ID\"}" >/dev/null
}
# NOTE: the seeded assignment is RESOURCE-SCOPED, and `unassign_from_user`
# without `?resource_id=` deletes only the *global* (resource_id = NONE)
# assignment — while still answering 204. Omitting the query parameter here
# makes the revocation a silent no-op, and the "stale allow" that follows is
# then a correct allow, not a cache bug. The DB assertion below exists so that
# failure mode can never be mistaken for a broken invalidation hook.
revoke_via_api() {
  local resp code left
  resp=$(api "$ADMIN_JAR" DELETE \
    "/api/v1/roles/$ROLE_ID/users/$BENCH_SUBJECT_ID?resource_id=$BENCH_RESOURCE_ID")
  code="${resp##*$'\n'}"
  [ "$code" = "204" ] || die "REST revocation returned HTTP $code (expected 204): ${resp%$'\n'*}"
  left=$(db_sql "SELECT count() FROM has_role WHERE in = user:\`$BENCH_SUBJECT_ID\` GROUP ALL;")
  case "$left" in
    *'"count":0'*|'[[]]'|'[]') : ;;
    *) die "REST revocation returned 204 but the has_role edge is still in the datastore ($left) — the mutation itself did not happen, so this says nothing about the cache" ;;
  esac
}
revoke_out_of_band() {  # no handler runs -> no invalidation event
  db_sql "DELETE has_role WHERE in = user:\`$BENCH_SUBJECT_ID\`;" >/dev/null
}

# ===========================================================================
# Test A — Layer 1: invalidation over the wire must deny IMMEDIATELY
# ===========================================================================
note "--- A: event-driven invalidation (REST role unassign) ---"
grant
[ "$(check)" = allow ] || die "precondition failed: seeded user is not allowed before revocation"
[ "$(check)" = allow ] || die "precondition failed: second check not allowed (entry not cacheable?)"
note "A: entry warm (two consecutive allows)"

t_rev=$(now_ms)
revoke_via_api
a_decision="$(check)"
t_dec=$(now_ms)
if [ "$a_decision" = deny ]; then
  pass "A: deny served $((t_dec - t_rev)) ms after the REST revocation (invalidation hook fired end to end)"
else
  fail "A: expected deny immediately after revocation, got '$a_decision' — the invalidate_subject hook did not reach the cache over the wire"
fi

# ===========================================================================
# Test B — Layer 2: suppressed event, stale allow must be bounded by the TTL
# ===========================================================================
note "--- B: suppressed invalidation (out-of-band DB delete) ---"
grant
[ "$(check)" = allow ] || die "precondition failed: re-grant did not restore the allow"
t_insert=$(now_ms)   # this check was the miss that (re-)inserted the entry
[ "$(check)" = allow ] || die "precondition failed: entry not warm before the out-of-band delete"

revoke_out_of_band
left=$(db_sql "SELECT count() FROM has_role WHERE in = user:\`$BENCH_SUBJECT_ID\` GROUP ALL;")
case "$left" in
  *'"count":0'*|'[[]]'|'[]') : ;;
  *) die "out-of-band delete did not land (has_role still present: $left) — test B would be meaningless" ;;
esac
t_del=$(now_ms)
note "B: has_role edge deleted directly in SurrealDB at t+$((t_del - t_insert)) ms after the cache insert"

stale_allows=0
deadline=$((t_insert + TTL_SECS * 1000 + 5000))
t_first_deny=""
while :; do
  d="$(check)"
  t_now=$(now_ms)
  case "$d" in
    allow) stale_allows=$((stale_allows + 1)) ;;
    deny)  t_first_deny=$t_now; break ;;
    err:*) die "unexpected response during poll: $d" ;;
  esac
  [ "$t_now" -gt "$deadline" ] && break
  sleep "$(awk -v m="$POLL_MS" 'BEGIN{printf "%.3f", m/1000}')"
done

if [ -z "$t_first_deny" ]; then
  fail "B: still allowing $(( (t_now - t_insert) / 1000 ))s after the out-of-band revocation — the TTL bound did not hold"
else
  age_ms=$((t_first_deny - t_insert))
  since_del=$((t_first_deny - t_del))
  note "B: first deny at entry-age ${age_ms} ms (${since_del} ms after the DB delete); stale allows observed: $stale_allows"
  if [ "$EXPECT_CACHE" = on ]; then
    if [ "$stale_allows" -lt 1 ]; then
      fail "B: no stale allow observed with the cache ON — the suppression or the warm-up did not work, so the TTL bound was not actually exercised"
    else
      pass "B: stale allow observed ($stale_allows polls) — the suppressed-event window is real"
    fi
    # The entry is stamped at INSERT and a hit does not refresh it, so the
    # bound is measured from t_insert, not from the delete. 1.5 s of slack
    # covers one clamped request (p50 ~1 s on a rate-limit-clamped host).
    if [ "$age_ms" -le $((TTL_SECS * 1000 + 1500)) ]; then
      pass "B: stale allow bounded by the TTL (${age_ms} ms <= ${TTL_SECS}s + 1.5s slack)"
    else
      fail "B: stale allow outlived the TTL (${age_ms} ms > ${TTL_SECS}s + 1.5s slack)"
    fi
  else
    if [ "$stale_allows" -eq 0 ]; then
      pass "B (control, cache OFF): the very first check after the out-of-band delete already denied — no stale window without the cache"
    else
      fail "B (control, cache OFF): $stale_allows stale allow(s) with the cache disabled — something other than the decision cache is caching decisions"
    fi
  fi
fi

# --- restore the fixture so the stack stays usable for benchmarking ---------
grant
restored="$(check)"
[ "$restored" = allow ] && note "fixture restored (allow)" || fail "could not restore the seeded assignment (got '$restored')"

echo
if [ "$FAILURES" -eq 0 ]; then
  note "ALL CHECKS PASSED (cache=$EXPECT_CACHE)"
else
  note "$FAILURES CHECK(S) FAILED (cache=$EXPECT_CACHE)"
fi
exit $((FAILURES > 0))
