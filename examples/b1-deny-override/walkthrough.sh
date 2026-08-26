#!/usr/bin/env bash
# walkthrough.sh — B1 deny-override canonical scenario.
#
# "Grant admin on /fleet, deny on /fleet/decommissioned" — the exact scenario
# from claude_dev/deny-override-design.md §2.2, driven end to end over the
# public REST API. This is the reference implementation the five flagship SDK
# repos (rust, typescript, python, go, java) link to when demonstrating their
# own deny-override examples: read this script if you want to see the raw
# wire calls behind whatever helper your language's SDK wraps them in.
#
# Requires a running AXIAM instance that has already been bootstrapped (see
# README.md — this repo's own `scripts/e2e-bootstrap.sh` does that against
# `docker/docker-compose.e2e.yml`). Nothing here is SDK-specific: every call
# is plain curl against the REST API documented in `docs/api/README.md`.
#
# Usage:
#   AXIAM_URL=http://localhost:8090 ./walkthrough.sh
#
# Exit code is non-zero if any of the three deny-override assertions fail,
# so this script doubles as the B1 CI smoke check (see
# .github/workflows/examples-smoke.yml).

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (matches scripts/e2e-bootstrap.sh's defaults so the two can
# be run back to back with no extra setup).
# ---------------------------------------------------------------------------
AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
# The TENANT-level administrator scripts/e2e-bootstrap.sh provisions inside
# `default` — not the organization-level super-admin. Bootstrap's super-admin
# lives in the organization's own scope and signs in with no tenant at all
# (see examples/b6-organization-scope); this scenario is about one tenant, so
# it uses the administrator of that tenant.
ADMIN_EMAIL="${E2E_TENANT_ADMIN_EMAIL:-tenant-admin@axiam.dev}"
ADMIN_PASSWORD="${E2E_TENANT_ADMIN_PASSWORD:-Tenant@Admin123!}"

# A run-unique suffix so the script is safe to re-run against a stack that
# already has a previous run's fixtures in it.
RUN_ID="$(date +%s)-$$"
TECH_USERNAME="fleet-tech-${RUN_ID}"
TECH_EMAIL="fleet-tech-${RUN_ID}@example.invalid"
TECH_PASSWORD="Fleet@Tech123!"

ADMIN_JAR="$(mktemp)"
TECH_JAR="$(mktemp)"
trap 'rm -f "${ADMIN_JAR}" "${TECH_JAR}"' EXIT

log()  { printf '\033[36m[b1-deny-override]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[b1-deny-override] PASS:\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[b1-deny-override] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required on PATH"; }
require curl
require jq

# ---------------------------------------------------------------------------
# Small helper: authenticated, CSRF-safe POST that also asserts the HTTP
# status code.
#
# Mirrors sdks/CONTRACT.md §3's non-browser pattern: capture the
# X-CSRF-Token response header at login and echo it back on every
# state-changing request afterwards, rather than reading a JS-only cookie.
# Built on an args array (not string interpolation) so the header value
# always reaches curl as a single argument.
# ---------------------------------------------------------------------------
api_expect() {
  local method="$1" jar="$2" csrf="$3" path="$4" body="$5" want_status="$6"
  local resp status tmp
  tmp="$(mktemp)"
  local args=(-sS -o "${tmp}" -w '%{http_code}' -X "${method}" -c "${jar}" -b "${jar}"
    -H "Content-Type: application/json")
  [ -n "${csrf}" ] && args+=(-H "X-CSRF-Token: ${csrf}")
  [ -n "${body}" ] && args+=(-d "${body}")
  status=$(curl "${args[@]}" "${AXIAM_URL}${path}")
  resp="$(cat "${tmp}")"
  rm -f "${tmp}"
  if [ "${status}" != "${want_status}" ]; then
    fail "${method} ${path} -> ${status} (wanted ${want_status}): ${resp}"
  fi
  printf '%s' "${resp}"
}

# ---------------------------------------------------------------------------
# 0. Wait for the server (same health-check loop as e2e-bootstrap.sh).
# ---------------------------------------------------------------------------
log "waiting for ${AXIAM_URL}/health ..."
for i in $(seq 1 30); do
  status=$(curl -s -o /dev/null -w '%{http_code}' "${AXIAM_URL}/health" 2>/dev/null || true)
  [ "${status}" = "200" ] && break
  sleep 2
  [ "${i}" = "30" ] && fail "server never became healthy"
done

# ---------------------------------------------------------------------------
# 1. Log in as the tenant admin (cookie session + CSRF token).
# ---------------------------------------------------------------------------
log "logging in as ${ADMIN_EMAIL} (org=${ORG_SLUG} tenant=${TENANT_SLUG})"
ADMIN_LOGIN_HEADERS="$(mktemp)"
ADMIN_LOGIN_BODY=$(curl -sS -D "${ADMIN_LOGIN_HEADERS}" -c "${ADMIN_JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_SLUG}\",\"username_or_email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login")
ADMIN_CSRF=$(grep -i '^x-csrf-token:' "${ADMIN_LOGIN_HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
rm -f "${ADMIN_LOGIN_HEADERS}"
[ -n "${ADMIN_CSRF}" ] || fail "no X-CSRF-Token on the admin login response"
TENANT_ID=$(printf '%s' "${ADMIN_LOGIN_BODY}" | jq -r '.user.tenant_id')
[ "${TENANT_ID}" != "null" ] || fail "login did not return a tenant_id: ${ADMIN_LOGIN_BODY}"
log "authenticated (tenant_id=${TENANT_ID})"

# ---------------------------------------------------------------------------
# 2. Build the resource hierarchy:
#      /fleet -> /fleet/decommissioned -> /fleet/decommissioned/unit-7
# (§2.2 of the design doc, verbatim.)
# ---------------------------------------------------------------------------
log "creating resource hierarchy /fleet -> decommissioned -> unit-7"
FLEET_ID=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/resources \
  '{"name":"fleet","resource_type":"fleet","parent_id":null}' 201 | jq -r '.id')
DECOMMISSIONED_ID=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/resources \
  "{\"name\":\"decommissioned\",\"resource_type\":\"fleet-segment\",\"parent_id\":\"${FLEET_ID}\"}" 201 | jq -r '.id')
UNIT7_ID=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/resources \
  "{\"name\":\"unit-7\",\"resource_type\":\"fleet-unit\",\"parent_id\":\"${DECOMMISSIONED_ID}\"}" 201 | jq -r '.id')
log "fleet=${FLEET_ID} decommissioned=${DECOMMISSIONED_ID} unit-7=${UNIT7_ID}"

# ---------------------------------------------------------------------------
# 3. One permission ("fleet:admin"), two roles: an allow role and a deny role.
#    This is deliberately two roles rather than one role carrying both grants
#    — a role's grants apply everywhere it is *assigned*, so the allow and
#    the deny need independent assignment points (/fleet and /decommissioned
#    respectively) to reproduce the design doc's row 3.
# ---------------------------------------------------------------------------
# permission.action and role.name are UNIQUE per tenant (schema.rs), so both
# carry RUN_ID — otherwise a second run against a persistent stack (a local
# rerun, or a CI runner that reuses a volume) would 500 on a name collision.
# fleet/decommissioned/unit-7 above need no such suffix: resource.name has no
# uniqueness constraint.
log "creating permission + allow/deny roles"
PERMISSION_ID=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/permissions \
  "{\"action\":\"fleet:admin:${RUN_ID}\",\"description\":\"Administer fleet vehicles\"}" 201 | jq -r '.id')

ALLOW_ROLE_ID=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/roles \
  "{\"name\":\"fleet-operator-${RUN_ID}\",\"description\":\"Grants fleet:admin across the fleet tree\",\"is_global\":false}" 201 | jq -r '.id')
DENY_ROLE_ID=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/roles \
  "{\"name\":\"fleet-decommission-lockout-${RUN_ID}\",\"description\":\"Denies fleet:admin on decommissioned units\",\"is_global\":false}" 201 | jq -r '.id')

# effect defaults to "allow" when omitted; spelled out here for clarity.
api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" "/api/v1/roles/${ALLOW_ROLE_ID}/permissions" \
  "{\"permission_id\":\"${PERMISSION_ID}\",\"scope_ids\":[],\"effect\":\"allow\"}" 204 >/dev/null

# The deny grant. This is the whole feature in one field.
api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" "/api/v1/roles/${DENY_ROLE_ID}/permissions" \
  "{\"permission_id\":\"${PERMISSION_ID}\",\"scope_ids\":[],\"effect\":\"deny\"}" 204 >/dev/null

# ---------------------------------------------------------------------------
# 4. A test user, and the two role assignments that create the scenario:
#      allow fleet-operator  @ /fleet
#      deny  decommission-lockout @ /fleet/decommissioned
# ---------------------------------------------------------------------------
log "creating test user ${TECH_USERNAME} and assigning roles"
TECH_USER_ID=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/users \
  "{\"username\":\"${TECH_USERNAME}\",\"email\":\"${TECH_EMAIL}\",\"password\":\"${TECH_PASSWORD}\"}" 201 | jq -r '.id')

api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" "/api/v1/roles/${ALLOW_ROLE_ID}/users" \
  "{\"user_id\":\"${TECH_USER_ID}\",\"resource_id\":\"${FLEET_ID}\"}" 204 >/dev/null
api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" "/api/v1/roles/${DENY_ROLE_ID}/users" \
  "{\"user_id\":\"${TECH_USER_ID}\",\"resource_id\":\"${DECOMMISSIONED_ID}\"}" 204 >/dev/null

# ---------------------------------------------------------------------------
# 5. Log in as fleet-tech and run the three checks that prove deny-override.
# ---------------------------------------------------------------------------
log "logging in as ${TECH_USERNAME} to run the checks as the subject itself"
TECH_LOGIN_HEADERS="$(mktemp)"
curl -sS -D "${TECH_LOGIN_HEADERS}" -c "${TECH_JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_SLUG}\",\"username_or_email\":\"${TECH_USERNAME}\",\"password\":\"${TECH_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login" >/dev/null
TECH_CSRF=$(grep -i '^x-csrf-token:' "${TECH_LOGIN_HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
rm -f "${TECH_LOGIN_HEADERS}"
[ -n "${TECH_CSRF}" ] || fail "no X-CSRF-Token on the fleet-tech login response"

check() {
  local resource_id="$1"
  api_expect POST "${TECH_JAR}" "${TECH_CSRF}" /api/v1/authz/check \
    "{\"action\":\"fleet:admin:${RUN_ID}\",\"resource_id\":\"${resource_id}\"}" 200
}

# Asserts a check result's allowed/reason_code, with a labeled pass/fail line.
assert_check() {
  local label="$1" result="$2" want_allowed="$3" want_reason="$4"
  local allowed reason
  allowed="$(printf '%s' "${result}" | jq -r '.allowed')"
  reason="$(printf '%s' "${result}" | jq -r '.reason_code')"
  if [ "${allowed}" = "${want_allowed}" ] && [ "${reason}" = "${want_reason}" ]; then
    ok "${label} -> allowed=${allowed} reason_code=${reason}"
  else
    fail "${label}: expected allowed=${want_allowed} reason_code=${want_reason}, got: ${result}"
  fi
}

log "row 1 — check on /fleet itself: expect allow (only the allow role applies)"
RESULT_FLEET=$(check "${FLEET_ID}")
assert_check "/fleet" "${RESULT_FLEET}" "true" "allowed"

log "row 3 — check on /fleet/decommissioned: expect deny (the deny beats the inherited allow)"
RESULT_DECOM=$(check "${DECOMMISSIONED_ID}")
assert_check "/fleet/decommissioned" "${RESULT_DECOM}" "false" "denied_by_rule"

log "cascade — check on /fleet/decommissioned/unit-7: expect deny (cascades two levels down)"
RESULT_UNIT7=$(check "${UNIT7_ID}")
assert_check "/fleet/decommissioned/unit-7" "${RESULT_UNIT7}" "false" "denied_by_rule"

log "all three deny-override assertions passed."
