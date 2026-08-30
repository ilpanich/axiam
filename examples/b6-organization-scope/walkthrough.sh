#!/usr/bin/env bash
# walkthrough.sh — B6 organization-level access.
#
# One administrator, every tenant: an organization-level principal creates two
# tenants and administers both with no grant written into either and no second
# sign-in — and then the boundary, where a tenant administrator holding an
# identically-named global role reaches nothing outside its own tenant.
#
# This is the scenario behind the defect organization scope exists to fix:
# creating a tenant left it unreachable by everybody, the super-admin who had
# just created it included. See docs/admin/organization-scope.md.
#
# Requires a running AXIAM instance that has already been bootstrapped (see
# README.md; this repo's `scripts/e2e-bootstrap.sh` does that against
# `docker/docker-compose.e2e.yml`). Plain curl against the REST API — no SDK
# dependency, so it cannot drift from what the wire actually does.
#
# Usage:
#   AXIAM_URL=http://localhost:8090 ./walkthrough.sh
#
# Exit code is non-zero if any assertion fails, so this doubles as the B6 CI
# smoke check.

set -euo pipefail

AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@axiam.dev}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Test@Admin123!}"

RUN_ID="$(date +%s)-$$"
TENANT_A_SLUG="alpha-${RUN_ID}"
TENANT_B_SLUG="beta-${RUN_ID}"
TA_USERNAME="tenant-admin-${RUN_ID}"
TA_EMAIL="tenant-admin-${RUN_ID}@example.invalid"
# The third principal: organization-level like the super-admin, but with its
# role assignment confined to tenant A.
SA_USERNAME="alpha-only-admin-${RUN_ID}"
SA_EMAIL="alpha-only-admin-${RUN_ID}@example.invalid"
# Freshly generated per run rather than a literal. This account is created and
# used inside this script and nowhere else, so there is nothing to be gained by
# pinning it — and a credential-shaped string in an example is a finding
# wherever the example gets copied to. `Ax1!` satisfies every character-class
# rule in the password policy; the hex tail supplies the length.
TA_PASSWORD="Ax1!$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
SA_PASSWORD="Ax1!$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"

ORG_JAR="$(mktemp)"
TA_JAR="$(mktemp)"
SA_JAR="$(mktemp)"
trap 'rm -f "${ORG_JAR}" "${TA_JAR}" "${SA_JAR}"' EXIT

log()  { printf '\033[36m[b6-organization-scope]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[b6-organization-scope] PASS:\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[b6-organization-scope] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required on PATH"; }
require curl
require jq

# Authenticated, CSRF-safe request that asserts the status code, and optionally
# carries `X-Axiam-Tenant` — the header an organization principal uses to say
# which tenant it is acting on.
api_expect() {
  local method="$1" jar="$2" csrf="$3" path="$4" body="$5" want_status="$6" tenant="${7:-}"
  local resp status tmp
  tmp="$(mktemp)"
  local args=(-sS -o "${tmp}" -w '%{http_code}' -X "${method}" -c "${jar}" -b "${jar}"
    -H "Content-Type: application/json")
  [ -n "${csrf}" ]  && args+=(-H "X-CSRF-Token: ${csrf}")
  [ -n "${tenant}" ] && args+=(-H "X-Axiam-Tenant: ${tenant}")
  [ -n "${body}" ]  && args+=(-d "${body}")
  status=$(curl "${args[@]}" "${AXIAM_URL}${path}")
  resp="$(cat "${tmp}")"
  rm -f "${tmp}"
  if [ "${status}" != "${want_status}" ]; then
    fail "${method} ${path} -> ${status} (wanted ${want_status}): ${resp}"
  fi
  printf '%s' "${resp}"
}

log "waiting for ${AXIAM_URL}/health ..."
for i in $(seq 1 30); do
  status=$(curl -s -o /dev/null -w '%{http_code}' "${AXIAM_URL}/health" 2>/dev/null || true)
  [ "${status}" = "200" ] && break
  sleep 2
  [ "${i}" = "30" ] && fail "server never became healthy"
done

# ---------------------------------------------------------------------------
# 1. Sign in with NO tenant.
#
# The bootstrap super-admin lives in the organization's reserved tenant, so it
# names no tenant at all. A tenant user omitting the tenant is simply not found
# there and gets the same enumeration-safe 401 as a wrong password.
# ---------------------------------------------------------------------------
log "signing in at organization level (org=${ORG_SLUG}, no tenant)"
HDRS="$(mktemp)"
ORG_LOGIN=$(curl -sS -D "${HDRS}" -c "${ORG_JAR}" -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"username_or_email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login")
ORG_CSRF=$(grep -i '^x-csrf-token:' "${HDRS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
rm -f "${HDRS}"
[ -n "${ORG_CSRF}" ] || fail "no X-CSRF-Token on the login response: ${ORG_LOGIN}"

ORG_LEVEL=$(printf '%s' "${ORG_LOGIN}" | jq -r '.user.organization_level')
[ "${ORG_LEVEL}" = "true" ] \
  || fail "expected organization_level=true, got ${ORG_LEVEL}: ${ORG_LOGIN}"
ORG_TENANT_ID=$(printf '%s' "${ORG_LOGIN}" | jq -r '.user.tenant_id')
ok "signed in with no tenant; organization_level=true (org tenant ${ORG_TENANT_ID})"

# The organization id, needed to create tenants under it.
ORG_ID=$(api_expect GET "${ORG_JAR}" "" /api/v1/organizations '' 200 \
  | jq -r 'if type == "array" then .[0].id else .items[0].id end')
[ "${ORG_ID}" != "null" ] || fail "could not resolve the organization id"

# ---------------------------------------------------------------------------
# 2. Create a tenant.
#
# This seeds the new tenant's permissions AND its default roles, and assigns
# them to nobody. Before organization scope it seeded permissions only, so the
# tenant had no roles at all and the next step was impossible for everyone.
# ---------------------------------------------------------------------------
log "creating tenant ${TENANT_A_SLUG}"
TENANT_A=$(api_expect POST "${ORG_JAR}" "${ORG_CSRF}" "/api/v1/organizations/${ORG_ID}/tenants" \
  "{\"name\":\"Alpha\",\"slug\":\"${TENANT_A_SLUG}\"}" 201 | jq -r '.id')
ok "tenant ${TENANT_A_SLUG} created (${TENANT_A})"

# ---------------------------------------------------------------------------
# 3. Administer it immediately — same token, one header, no new grant.
# ---------------------------------------------------------------------------
log "listing users in ${TENANT_A_SLUG} with X-Axiam-Tenant"
api_expect GET "${ORG_JAR}" "" /api/v1/users '' 200 "${TENANT_A}" >/dev/null
ok "organization admin administers a tenant it was never granted anything in"

# ---------------------------------------------------------------------------
# 4. A second tenant, reached by the same rule with no new write anywhere.
# ---------------------------------------------------------------------------
log "creating tenant ${TENANT_B_SLUG} and reaching it too"
TENANT_B=$(api_expect POST "${ORG_JAR}" "${ORG_CSRF}" "/api/v1/organizations/${ORG_ID}/tenants" \
  "{\"name\":\"Beta\",\"slug\":\"${TENANT_B_SLUG}\"}" 201 | jq -r '.id')
api_expect GET "${ORG_JAR}" "" /api/v1/users '' 200 "${TENANT_B}" >/dev/null
ok "a tenant created seconds ago is reachable with no grant, restart or re-login"

# ---------------------------------------------------------------------------
# 5. The boundary.
#
# A TENANT administrator in tenant A, holding a *global* role — `is_global`,
# no resource — which reaches every resource in tenant A and nothing outside
# it. Both roles here are called `operations` and both are global; only the
# tenant they live in decides how far they reach.
# ---------------------------------------------------------------------------
log "creating a tenant-level admin in ${TENANT_A_SLUG}"
TA_USER=$(api_expect POST "${ORG_JAR}" "${ORG_CSRF}" /api/v1/users \
  "{\"username\":\"${TA_USERNAME}\",\"email\":\"${TA_EMAIL}\",\"password\":\"${TA_PASSWORD}\"}" \
  201 "${TENANT_A}" | jq -r '.id')

# Activate it — new accounts are PendingVerification and cannot sign in.
api_expect PUT "${ORG_JAR}" "${ORG_CSRF}" "/api/v1/users/${TA_USER}" \
  '{"status":"Active"}' 200 "${TENANT_A}" >/dev/null

# Tenant A's seeded `super-admin` role — proof that step 2 really did seed
# roles, since without them there would be nothing here to assign.
ROLES=$(api_expect GET "${ORG_JAR}" "" '/api/v1/roles?search=super-admin' '' 200 "${TENANT_A}")
TA_ROLE=$(printf '%s' "${ROLES}" | jq -r '.items[] | select(.name == "super-admin") | .id')
if [ -z "${TA_ROLE}" ] || [ "${TA_ROLE}" = "null" ]; then
  fail "tenant ${TENANT_A_SLUG} has no seeded super-admin role: ${ROLES}"
fi
ok "the new tenant was seeded with its default roles"

# Assignment goes on the *role*, not the user: `/users/{id}/roles` is a
# read-only view of what a user holds. No `resource_id`, which makes this a
# global grant inside the tenant — the tenant admin administers all of
# `alpha` and, as the boundary check below proves, nothing outside it.
api_expect POST "${ORG_JAR}" "${ORG_CSRF}" "/api/v1/roles/${TA_ROLE}/users" \
  "{\"user_id\":\"${TA_USER}\"}" 204 "${TENANT_A}" >/dev/null

log "signing in as the tenant admin (tenant named, as it must be)"
HDRS="$(mktemp)"
TA_LOGIN=$(curl -sS -D "${HDRS}" -c "${TA_JAR}" -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_A_SLUG}\",\"username_or_email\":\"${TA_USERNAME}\",\"password\":\"${TA_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login")
rm -f "${HDRS}"
TA_LEVEL=$(printf '%s' "${TA_LOGIN}" | jq -r '.user.organization_level')
[ "${TA_LEVEL}" = "false" ] \
  || fail "a tenant user must not be organization_level: ${TA_LOGIN}"
ok "tenant admin signed in; organization_level=false"

log "tenant admin lists users in its OWN tenant"
api_expect GET "${TA_JAR}" "" /api/v1/users '' 200 >/dev/null
ok "tenant admin administers its own tenant"

# The header is refused for a principal that is not organization-level — a 403
# rather than a silent fallback, so a client that asks wrongly is told so
# instead of being served a different tenant's data.
log "tenant admin tries to reach ${TENANT_B_SLUG} with the header"
api_expect GET "${TA_JAR}" "" /api/v1/users '' 403 "${TENANT_B}" >/dev/null
ok "a tenant principal cannot act on another tenant, header or not"

# ---------------------------------------------------------------------------
# 6. The middle ground: an ORGANIZATION principal restricted to one tenant.
#
# Steps 1–4 gave one administrator every tenant; step 5 gave another exactly
# one, permanently, by where its account lives. Neither expresses the common
# case: an organization-level operator who should administer *some* of the
# organization's tenants.
#
# A `tenant_scope` on the role assignment expresses it. The assignment applies
# only while acting on a tenant it names, and nowhere else — the organization's
# own scope included, because an account confined to two tenants is not an
# organization-wide administrator.
# ---------------------------------------------------------------------------
log "creating an organization-level account restricted to ${TENANT_A_SLUG}"
# Created in the ORGANIZATION scope: no X-Axiam-Tenant, so this account's record
# lives where the super-admin's does. That is what makes it organization-level;
# the restriction below is what makes it narrow.
SA_USER=$(api_expect POST "${ORG_JAR}" "${ORG_CSRF}" /api/v1/users \
  "{\"username\":\"${SA_USERNAME}\",\"email\":\"${SA_EMAIL}\",\"password\":\"${SA_PASSWORD}\"}" \
  201 | jq -r '.id')
api_expect PUT "${ORG_JAR}" "${ORG_CSRF}" "/api/v1/users/${SA_USER}" \
  '{"status":"Active"}' 200 >/dev/null

# The organization scope's own super-admin role — the same one the bootstrap
# administrator holds. Assigning THIS role is what makes the point: the account
# below is refused things not because it lacks a permission, but because its
# assignment names the tenants it reaches.
ORG_ROLES=$(api_expect GET "${ORG_JAR}" "" '/api/v1/roles?search=super-admin' '' 200)
ORG_ROLE=$(printf '%s' "${ORG_ROLES}" | jq -r '.items[] | select(.name == "super-admin") | .id')
if [ -z "${ORG_ROLE}" ] || [ "${ORG_ROLE}" = "null" ]; then
  fail "the organization scope has no super-admin role: ${ORG_ROLES}"
fi

api_expect POST "${ORG_JAR}" "${ORG_CSRF}" "/api/v1/roles/${ORG_ROLE}/users" \
  "{\"user_id\":\"${SA_USER}\",\"tenant_scope\":[\"${TENANT_A}\"]}" 204 >/dev/null
ok "assigned the organization super-admin role, scoped to ${TENANT_A_SLUG} alone"

log "signing in (no tenant named — it is an organization principal)"
HDRS="$(mktemp)"
SA_LOGIN=$(curl -sS -D "${HDRS}" -c "${SA_JAR}" -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"username_or_email\":\"${SA_USERNAME}\",\"password\":\"${SA_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login")
SA_CSRF=$(grep -i '^x-csrf-token:' "${HDRS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
rm -f "${HDRS}"
[ -n "${SA_CSRF}" ] || fail "no X-CSRF-Token on the login response: ${SA_LOGIN}"
SA_LEVEL=$(printf '%s' "${SA_LOGIN}" | jq -r '.user.organization_level')
[ "${SA_LEVEL}" = "true" ] \
  || fail "the restricted account must still be organization_level: ${SA_LOGIN}"
ok "signed in; organization_level=true, and yet:"

log "  /auth/me reports the tenants it reaches, and withholds the wildcard"
SA_ME=$(api_expect GET "${SA_JAR}" "" /api/v1/auth/me '' 200 "${TENANT_A}")
SA_REACH=$(printf '%s' "${SA_ME}" | jq -r '.user.reachable_tenant_ids | join(",")')
[ "${SA_REACH}" = "${TENANT_A}" ] \
  || fail "reachable_tenant_ids should be exactly ${TENANT_A}, got '${SA_REACH}'"
# `*` short-circuits every client-side permission check. Emitting it for an
# account the server refuses organization-level actions is how an admin UI ends
# up rendering buttons that answer 403.
printf '%s' "${SA_ME}" | jq -e '.permissions | index("*") == null' >/dev/null \
  || fail "a restricted principal must not be handed the wildcard: ${SA_ME}"
ok "  reachable_tenant_ids=[${TENANT_A_SLUG}], no wildcard"

log "  it administers ${TENANT_A_SLUG}"
api_expect GET "${SA_JAR}" "" /api/v1/users '' 200 "${TENANT_A}" >/dev/null
ok "  the tenant it was given works normally"

log "  it cannot reach ${TENANT_B_SLUG}"
# Refused at the header, not as a denial on every request that follows: the
# difference between one clear answer and a session that looks switched and
# then fails everywhere.
api_expect GET "${SA_JAR}" "" /api/v1/users '' 403 "${TENANT_B}" >/dev/null
ok "  a tenant its assignment does not name is refused"

log "  it cannot see ${TENANT_B_SLUG} in the tenant roster either"
SA_TENANTS=$(api_expect GET "${SA_JAR}" "" "/api/v1/organizations/${ORG_ID}/tenants" '' 200)
printf '%s' "${SA_TENANTS}" | jq -e --arg b "${TENANT_B}" \
  '[.items[].id] | index($b) == null' >/dev/null \
  || fail "the roster must be filtered to the tenants in reach: ${SA_TENANTS}"
ok "  the roster lists only what it can act on"

log "  and it is not an organization administrator"
# The half the authorization engine structurally cannot enforce: creating a
# tenant names no tenant, so there is nothing for a tenant scope to be compared
# against. The guard is explicit, and this is what proves it is there.
api_expect POST "${SA_JAR}" "${SA_CSRF}" "/api/v1/organizations/${ORG_ID}/tenants" \
  "{\"name\":\"Should Not Exist\",\"slug\":\"nope-${RUN_ID}\"}" 403 >/dev/null
ok "  organization-level actions are refused"

printf '\n'
ok "all assertions passed"
log "same global flag, two reaches: the role in the organization tenant is"
log "organization-wide; the one in ${TENANT_A_SLUG} is tenant-wide. That is why"
log "the admin UI no longer labels both of them \"Global\"."
