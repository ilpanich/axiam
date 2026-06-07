#!/usr/bin/env bash
# e2e-bootstrap.sh — Seed the E2E database with an org, tenant, and admin user.
#
# Called after `docker compose -f docker/docker-compose.e2e.yml up -d --wait`.
# Creates the org + tenant directly via SurrealDB HTTP API (no AXIAM auth required),
# then calls POST /api/v1/admin/bootstrap (public endpoint, D-09) to create the
# admin user with the super-admin role.
#
# Environment variables (with E2E defaults):
#   E2E_ORG_SLUG      — organization slug (default: test-org)
#   E2E_TENANT_SLUG   — tenant slug        (default: default)
#   E2E_ADMIN_EMAIL   — admin email        (default: admin@axiam.dev)
#   E2E_ADMIN_PASSWORD — admin password    (default: Test@Admin123!)
#   AXIAM_URL         — backend base URL   (default: http://localhost:8090)
#   SURREAL_URL       — SurrealDB HTTP URL (default: http://localhost:8000)

set -euo pipefail

ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@axiam.dev}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Test@Admin123!}"
AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"
SURREAL_URL="${SURREAL_URL:-http://localhost:8000}"

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
# Step 2: Create org + tenant directly via SurrealDB HTTP API.
#
# The AXIAM API endpoints for org/tenant require authentication, but no admin
# user exists yet (that's what we're bootstrapping). We use SurrealDB's built-in
# HTTP SQL endpoint instead, which accepts root credentials.
# ---------------------------------------------------------------------------
echo "[e2e-bootstrap] Creating org '${ORG_SLUG}' and tenant '${TENANT_SLUG}' via SurrealDB..."

# Generate deterministic UUIDs for the org and tenant so the bootstrap call
# can reference them. We use date-based seeds for reproducibility.
ORG_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")
TENANT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")

SURREAL_RESPONSE=$(curl -sf \
  -X POST "${SURREAL_URL}/sql" \
  -H "Accept: application/json" \
  -H "Content-Type: text/plain" \
  -H "surreal-ns: axiam" \
  -H "surreal-db: axiam" \
  -u "root:root" \
  --data-binary "
CREATE type:record('organization', '${ORG_ID}') SET
  name = 'E2E Test Org',
  slug = '${ORG_SLUG}',
  metadata = {},
  created_at = time::now(),
  updated_at = time::now();

CREATE type:record('tenant', '${TENANT_ID}') SET
  organization_id = '${ORG_ID}',
  name = 'E2E Default Tenant',
  slug = '${TENANT_SLUG}',
  metadata = {},
  is_active = true,
  created_at = time::now(),
  updated_at = time::now();
" 2>&1) || {
  echo "[e2e-bootstrap] ERROR: SurrealDB SQL failed. Response: ${SURREAL_RESPONSE}"
  exit 1
}

echo "[e2e-bootstrap] Org and tenant created."

# ---------------------------------------------------------------------------
# Step 3: Call POST /api/v1/admin/bootstrap (public endpoint).
#
# This creates the admin user with the super-admin role and seeds all
# permissions for the tenant. Returns 201 on success, 404 if already done.
# ---------------------------------------------------------------------------
echo "[e2e-bootstrap] Calling /api/v1/admin/bootstrap ..."

BOOTSTRAP_BODY=$(cat <<EOF
{
  "org_id": "${ORG_ID}",
  "tenant_id": "${TENANT_ID}",
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
    echo "[e2e-bootstrap] Bootstrap complete (201). Admin user created."
    break
  elif [ "${HTTP_STATUS}" = "404" ]; then
    echo "[e2e-bootstrap] Bootstrap already completed (404) — skipping."
    break
  else
    echo "[e2e-bootstrap] Attempt ${i}/5: bootstrap returned ${HTTP_STATUS}, retrying in 3s..."
    cat /tmp/bootstrap_resp.json 2>/dev/null || true
    sleep 3
  fi
done

# Final check
if [ "${HTTP_STATUS}" != "201" ] && [ "${HTTP_STATUS}" != "404" ]; then
  echo "[e2e-bootstrap] ERROR: bootstrap endpoint returned unexpected status ${HTTP_STATUS}"
  cat /tmp/bootstrap_resp.json 2>/dev/null || true
  exit 1
fi

echo "[e2e-bootstrap] Done. org=${ORG_SLUG} tenant=${TENANT_SLUG} admin=${ADMIN_EMAIL}"
