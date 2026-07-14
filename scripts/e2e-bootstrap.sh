#!/usr/bin/env bash
# e2e-bootstrap.sh — Seed the E2E database with an org, tenant, and admin user.
#
# Called after `docker compose -f docker/docker-compose.e2e.yml up -d --wait`.
# Performs the entire first-run provisioning through the public
# POST /api/v1/admin/bootstrap endpoint, which creates the organization, the
# default tenant, the seeded permissions/roles, and the admin user with the
# super-admin role — all in one call. No direct SurrealDB access is needed.
#
# The bootstrap gate is satisfied by AXIAM_BOOTSTRAP_ADMIN_EMAIL (set in
# docker-compose.e2e.yml to E2E_ADMIN_EMAIL); no setup token is required.
#
# Environment variables (with E2E defaults):
#   E2E_ORG_NAME      — organization name  (default: E2E Test Org)
#   E2E_ORG_SLUG      — organization slug  (default: test-org)
#   E2E_TENANT_NAME   — tenant name        (default: Default)
#   E2E_TENANT_SLUG   — tenant slug        (default: default)
#   E2E_ADMIN_EMAIL   — admin email        (default: admin@axiam.dev)
#   E2E_ADMIN_PASSWORD — admin password    (default: Test@Admin123!)
#   AXIAM_URL         — backend base URL   (default: http://localhost:8090)

set -euo pipefail

ORG_NAME="${E2E_ORG_NAME:-E2E Test Org}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_NAME="${E2E_TENANT_NAME:-Default}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@axiam.dev}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Test@Admin123!}"
AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"

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
    echo "[e2e-bootstrap] Bootstrap complete (201). Org, tenant and admin user created."
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

echo "[e2e-bootstrap] Done. org=${ORG_SLUG} tenant=${TENANT_SLUG} admin=${ADMIN_EMAIL}"
