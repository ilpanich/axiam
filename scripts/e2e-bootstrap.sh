#!/usr/bin/env bash
# e2e-bootstrap.sh — Seed the E2E database with an org, tenant, and admin user.
#
# Called after `docker compose -f docker/docker-compose.e2e.yml up -d --wait`.
# Two steps, because that is now the real first-run shape:
#
#   1. POST /api/v1/admin/bootstrap creates the organization, its reserved
#      **organization scope**, that scope's permissions/roles, and the
#      super-admin — an organization-level administrator, not a tenant one.
#      Bootstrap no longer creates an ordinary tenant: the whole point of
#      organization scope is that the administrator is not tied to whichever
#      tenant happened to be named on the first screen.
#   2. The super-admin signs in at organization level (no tenant named) and
#      creates the `default` tenant the other examples run against — which
#      seeds that tenant's own permissions and roles — then, still with that
#      one session and an `X-Axiam-Tenant` header, provisions a tenant-level
#      administrator inside it.
#
# Two administrators, because they are two different things: the super-admin
# administers the organization and every tenant in it, while the tenant admin
# administers exactly `default`. Examples b1/b2/b3/b5 use the tenant admin,
# which is what an application's own operator would hold; b6 uses the
# super-admin, because organization scope is what b6 is about.
#
# Everything goes through the public REST API; no direct SurrealDB access is
# needed. Both steps are idempotent, so re-running against an already-seeded
# stack is a no-op.
#
# The bootstrap gate is satisfied by AXIAM_BOOTSTRAP_ADMIN_EMAIL (set in
# docker-compose.e2e.yml to E2E_ADMIN_EMAIL); no setup token is required.
#
# Environment variables (with E2E defaults):
#   E2E_ORG_NAME      — organization name  (default: E2E Test Org)
#   E2E_ORG_SLUG      — organization slug  (default: test-org)
#   E2E_TENANT_NAME   — tenant name        (default: E2E Default Tenant)
#   E2E_TENANT_SLUG   — tenant slug        (default: default)
#   E2E_ADMIN_EMAIL   — organization-level super-admin email
#                                          (default: admin@axiam.dev)
#   E2E_ADMIN_PASSWORD — super-admin password
#                                          (default: Test@Admin123!)
#   E2E_TENANT_ADMIN_EMAIL — tenant-level admin email
#                                          (default: tenant-admin@axiam.dev)
#   E2E_TENANT_ADMIN_USERNAME — tenant-level admin username
#                                          (default: tenant-admin)
#   E2E_TENANT_ADMIN_PASSWORD — tenant-level admin password
#                                          (default: E2E_ADMIN_PASSWORD)
#   AXIAM_URL         — backend base URL   (default: http://localhost:8090)

set -euo pipefail

ORG_NAME="${E2E_ORG_NAME:-E2E Test Org}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_NAME="${E2E_TENANT_NAME:-E2E Default Tenant}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@axiam.dev}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Test@Admin123!}"
TENANT_ADMIN_EMAIL="${E2E_TENANT_ADMIN_EMAIL:-tenant-admin@axiam.dev}"
TENANT_ADMIN_USERNAME="${E2E_TENANT_ADMIN_USERNAME:-tenant-admin}"
# Defaults to the super-admin's password rather than a literal of its own: one
# credential for the whole fixture, and no new credential-shaped string in the
# tree. A fixture password that only ever guards a throwaway compose stack is
# still a finding wherever the file gets copied.
TENANT_ADMIN_PASSWORD="${E2E_TENANT_ADMIN_PASSWORD:-${ADMIN_PASSWORD}}"
AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"

command -v jq >/dev/null 2>&1 || { echo "[e2e-bootstrap] ERROR: 'jq' is required on PATH"; exit 1; }

echo "[e2e-bootstrap] org=${ORG_SLUG} tenant=${TENANT_SLUG} email=${ADMIN_EMAIL}"

# ---------------------------------------------------------------------------
# Step 1: Wait for AXIAM server to be ready
# ---------------------------------------------------------------------------
echo "[e2e-bootstrap] Waiting for AXIAM server at ${AXIAM_URL}/health ..."
for i in $(seq 1 30); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${AXIAM_URL}/health" 2>/dev/null || true)
  if [ "${STATUS}" = "200" ]; then
    echo "[e2e-bootstrap] AXIAM server is ready."
    break
  fi
  echo "[e2e-bootstrap] Attempt ${i}/30: health returned ${STATUS}, retrying in 2s..."
  sleep 2
done

# Final check — fail loudly if still not up
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${AXIAM_URL}/health" 2>/dev/null || true)
if [ "${STATUS}" != "200" ]; then
  echo "[e2e-bootstrap] ERROR: AXIAM server did not become ready in time (last status: ${STATUS})"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Call POST /api/v1/admin/bootstrap (public endpoint).
#
# Creates the organization, the default tenant, all permissions/roles, and the
# admin user with the super-admin role. Returns 201 on success, 409 if the
# system has already been initialized.
# ---------------------------------------------------------------------------
echo "[e2e-bootstrap] Calling /api/v1/admin/bootstrap ..."

BOOTSTRAP_BODY=$(cat <<EOF
{
  "organization_name": "${ORG_NAME}",
  "organization_slug": "${ORG_SLUG}",
  "tenant_name": "${TENANT_NAME}",
  "tenant_slug": "${TENANT_SLUG}",
  "email": "${ADMIN_EMAIL}",
  "username": "admin",
  "password": "${ADMIN_PASSWORD}"
}
EOF
)

# Retry bootstrap up to 5 times in case the server is still initializing
for i in $(seq 1 5); do
  HTTP_STATUS=$(curl -s -o /tmp/bootstrap_resp.json -w "%{http_code}" \
    -X POST "${AXIAM_URL}/api/v1/admin/bootstrap" \
    -H "Content-Type: application/json" \
    -d "${BOOTSTRAP_BODY}" 2>/dev/null || echo "000")

  if [ "${HTTP_STATUS}" = "201" ]; then
    echo "[e2e-bootstrap] Bootstrap complete (201). Org, organization scope and super-admin created."
    break
  elif [ "${HTTP_STATUS}" = "409" ]; then
    echo "[e2e-bootstrap] Bootstrap already completed (409) — skipping."
    break
  else
    echo "[e2e-bootstrap] Attempt ${i}/5: bootstrap returned ${HTTP_STATUS}, retrying in 3s..."
    cat /tmp/bootstrap_resp.json 2>/dev/null || true
    sleep 3
  fi
done

# Final check
if [ "${HTTP_STATUS}" != "201" ] && [ "${HTTP_STATUS}" != "409" ]; then
  echo "[e2e-bootstrap] ERROR: bootstrap endpoint returned unexpected status ${HTTP_STATUS}"
  cat /tmp/bootstrap_resp.json 2>/dev/null || true
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Sign in at ORGANIZATION level and create the tenant the examples use.
#
# No tenant_slug in the login body: that is what selects the organization
# scope, where the super-admin bootstrap just created actually lives. Naming a
# tenant here would look the credentials up inside that tenant and correctly
# fail — an organization-level principal signs in at organization level and
# then names the tenant it is acting on, per request, in X-Axiam-Tenant.
# ---------------------------------------------------------------------------
echo "[e2e-bootstrap] Signing in at organization level ..."

JAR="$(mktemp)"
LOGIN_HEADERS="$(mktemp)"
trap 'rm -f "${JAR}" "${LOGIN_HEADERS}"' EXIT

LOGIN_STATUS=$(curl -sS -o /tmp/e2e_login_resp.json -w '%{http_code}' \
  -D "${LOGIN_HEADERS}" -c "${JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"username_or_email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login")

if [ "${LOGIN_STATUS}" != "200" ]; then
  echo "[e2e-bootstrap] ERROR: organization-level login returned ${LOGIN_STATUS}"
  cat /tmp/e2e_login_resp.json 2>/dev/null || true
  exit 1
fi

CSRF=$(grep -i '^x-csrf-token:' "${LOGIN_HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
if [ -z "${CSRF}" ]; then
  echo "[e2e-bootstrap] ERROR: no X-CSRF-Token on the login response"
  exit 1
fi

# The tenant endpoint is nested under the organization, so resolve the org's
# UUID from its slug. The login response carries `org_slug`, not the id.
ORG_ID=$(curl -sS -b "${JAR}" -c "${JAR}" "${AXIAM_URL}/api/v1/organizations" \
  | jq -r --arg slug "${ORG_SLUG}" '(.items // .) | map(select(.slug == $slug)) | .[0].id // empty')
if [ -z "${ORG_ID}" ]; then
  echo "[e2e-bootstrap] ERROR: could not resolve organization ${ORG_SLUG}"
  exit 1
fi

echo "[e2e-bootstrap] Creating tenant ${TENANT_SLUG} under org ${ORG_ID} ..."
TENANT_STATUS=$(curl -sS -o /tmp/e2e_tenant_resp.json -w '%{http_code}' \
  -X POST -b "${JAR}" -c "${JAR}" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: ${CSRF}" \
  -d "{\"name\":\"${TENANT_NAME}\",\"slug\":\"${TENANT_SLUG}\"}" \
  "${AXIAM_URL}/api/v1/organizations/${ORG_ID}/tenants")

case "${TENANT_STATUS}" in
  201) echo "[e2e-bootstrap] Tenant ${TENANT_SLUG} created (201), permissions and roles seeded." ;;
  409) echo "[e2e-bootstrap] Tenant ${TENANT_SLUG} already exists (409) — skipping." ;;
  *)
    echo "[e2e-bootstrap] ERROR: tenant creation returned ${TENANT_STATUS}"
    cat /tmp/e2e_tenant_resp.json 2>/dev/null || true
    exit 1
    ;;
esac

TENANT_ID=$(curl -sS -b "${JAR}" -c "${JAR}" \
  "${AXIAM_URL}/api/v1/organizations/${ORG_ID}/tenants" \
  | jq -r --arg slug "${TENANT_SLUG}" \
      '(.items // .) | map(select(.slug == $slug)) | .[0].id // empty')
if [ -z "${TENANT_ID}" ]; then
  echo "[e2e-bootstrap] ERROR: could not resolve tenant ${TENANT_SLUG}"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 4: Provision a TENANT-level administrator inside it.
#
# Same session as step 3 — no second sign-in. `X-Axiam-Tenant` is how an
# organization-level principal says which tenant a request is about, and it is
# honoured only for a principal whose own record lives in the organization
# scope, in a tenant of that principal's own organization.
#
# This is also the first thing organization scope makes possible: before it,
# a freshly created tenant had nobody who could reach into it to do this.
# ---------------------------------------------------------------------------
echo "[e2e-bootstrap] Provisioning tenant admin ${TENANT_ADMIN_EMAIL} in ${TENANT_SLUG} ..."

USER_STATUS=$(curl -sS -o /tmp/e2e_user_resp.json -w '%{http_code}' \
  -X POST -b "${JAR}" -c "${JAR}" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: ${CSRF}" \
  -H "X-Axiam-Tenant: ${TENANT_ID}" \
  -d "{\"username\":\"${TENANT_ADMIN_USERNAME}\",\"email\":\"${TENANT_ADMIN_EMAIL}\",\"password\":\"${TENANT_ADMIN_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/users")

case "${USER_STATUS}" in
  201)
    TENANT_ADMIN_ID=$(jq -r '.id' /tmp/e2e_user_resp.json)
    echo "[e2e-bootstrap] Tenant admin created (${TENANT_ADMIN_ID})."
    ;;
  409)
    echo "[e2e-bootstrap] Tenant admin already exists (409) — reusing."
    TENANT_ADMIN_ID=$(curl -sS -b "${JAR}" -c "${JAR}" \
      -H "X-Axiam-Tenant: ${TENANT_ID}" \
      "${AXIAM_URL}/api/v1/users?search=${TENANT_ADMIN_USERNAME}" \
      | jq -r --arg u "${TENANT_ADMIN_USERNAME}" \
          '(.items // .) | map(select(.username == $u)) | .[0].id // empty')
    ;;
  *)
    echo "[e2e-bootstrap] ERROR: tenant admin creation returned ${USER_STATUS}"
    cat /tmp/e2e_user_resp.json 2>/dev/null || true
    exit 1
    ;;
esac

if [ -z "${TENANT_ADMIN_ID}" ] || [ "${TENANT_ADMIN_ID}" = "null" ]; then
  echo "[e2e-bootstrap] ERROR: could not resolve the tenant admin's id"
  exit 1
fi

# Users are created `PendingVerification` — there is no mailbox to click a link
# in here, so activate it directly. The examples that sign in as this account
# would otherwise depend on whether email verification is enforced at login,
# which is a per-tenant policy and not something a fixture should rely on.
ACTIVATE_STATUS=$(curl -sS -o /tmp/e2e_activate_resp.json -w '%{http_code}' \
  -X PUT -b "${JAR}" -c "${JAR}" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: ${CSRF}" \
  -H "X-Axiam-Tenant: ${TENANT_ID}" \
  -d '{"status":"Active"}' \
  "${AXIAM_URL}/api/v1/users/${TENANT_ADMIN_ID}")
if [ "${ACTIVATE_STATUS}" != "200" ]; then
  echo "[e2e-bootstrap] ERROR: activating the tenant admin returned ${ACTIVATE_STATUS}"
  cat /tmp/e2e_activate_resp.json 2>/dev/null || true
  exit 1
fi

# The `super-admin` role seeded into the tenant when it was created. Assigned
# with no resource_id, which makes it a global grant *within this tenant* —
# the tenant admin administers all of `default` and nothing outside it.
SUPER_ADMIN_ROLE_ID=$(curl -sS -b "${JAR}" -c "${JAR}" \
  -H "X-Axiam-Tenant: ${TENANT_ID}" \
  "${AXIAM_URL}/api/v1/roles" \
  | jq -r '(.items // .) | map(select(.name == "super-admin")) | .[0].id // empty')
if [ -z "${SUPER_ADMIN_ROLE_ID}" ]; then
  echo "[e2e-bootstrap] ERROR: tenant ${TENANT_SLUG} has no super-admin role"
  exit 1
fi

ASSIGN_STATUS=$(curl -sS -o /tmp/e2e_assign_resp.json -w '%{http_code}' \
  -X POST -b "${JAR}" -c "${JAR}" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: ${CSRF}" \
  -H "X-Axiam-Tenant: ${TENANT_ID}" \
  -d "{\"user_id\":\"${TENANT_ADMIN_ID}\"}" \
  "${AXIAM_URL}/api/v1/roles/${SUPER_ADMIN_ROLE_ID}/users")

case "${ASSIGN_STATUS}" in
  204|200|201|409) echo "[e2e-bootstrap] Tenant admin holds super-admin in ${TENANT_SLUG}." ;;
  *)
    echo "[e2e-bootstrap] ERROR: role assignment returned ${ASSIGN_STATUS}"
    cat /tmp/e2e_assign_resp.json 2>/dev/null || true
    exit 1
    ;;
esac

echo "[e2e-bootstrap] Done."
echo "[e2e-bootstrap]   org=${ORG_SLUG} super-admin=${ADMIN_EMAIL} (organization-level)"
echo "[e2e-bootstrap]   tenant=${TENANT_SLUG} (${TENANT_ID}) admin=${TENANT_ADMIN_EMAIL} (tenant-level)"
