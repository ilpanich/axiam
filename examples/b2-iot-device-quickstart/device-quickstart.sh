#!/usr/bin/env bash
# device-quickstart.sh — B2 OAuth2 Device Authorization Grant (RFC 8628),
# played out end to end on a headless "device" (this script) and a human
# approver (the already-bootstrapped tenant admin).
#
# See docs/api/device-flow.md for the full protocol reference this script
# exercises. mTLS device provisioning (the follow-on for devices that hold a
# client certificate rather than a typed-in code) is explicitly NOT covered
# here — see README.md "Not covered" and docs/pki/README.md.
#
# Requires a running, bootstrapped AXIAM instance (see
# scripts/e2e-bootstrap.sh) and curl + jq on PATH.
#
# Usage:
#   AXIAM_URL=http://localhost:8090 ./device-quickstart.sh

set -euo pipefail

AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@axiam.dev}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Test@Admin123!}"

RUN_ID="$(date +%s)-$$"
CLIENT_NAME="headless-sensor-${RUN_ID}"

ADMIN_JAR="$(mktemp)"
trap 'rm -f "${ADMIN_JAR}"' EXIT

log()  { printf '\033[36m[b2-iot-device]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[b2-iot-device] PASS:\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[b2-iot-device] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required on PATH"; }
require curl
require jq

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

log "waiting for ${AXIAM_URL}/health ..."
for i in $(seq 1 30); do
  status=$(curl -s -o /dev/null -w '%{http_code}' "${AXIAM_URL}/health" 2>/dev/null || true)
  [ "${status}" = "200" ] && break
  sleep 2
  [ "${i}" = "30" ] && fail "server never became healthy"
done

# ---------------------------------------------------------------------------
# 0. The human side logs in once, up front — this stands in for "the person
#    with the sensor picks up their phone". A device client needs no
#    end-user credential of its own; only the approver authenticates.
# ---------------------------------------------------------------------------
log "logging in as the approving admin (${ADMIN_EMAIL})"
ADMIN_LOGIN_HEADERS="$(mktemp)"
curl -sS -D "${ADMIN_LOGIN_HEADERS}" -c "${ADMIN_JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_SLUG}\",\"username_or_email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login" >/dev/null
ADMIN_CSRF=$(grep -i '^x-csrf-token:' "${ADMIN_LOGIN_HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
rm -f "${ADMIN_LOGIN_HEADERS}"
[ -n "${ADMIN_CSRF}" ] || fail "no X-CSRF-Token on the admin login response"

# ---------------------------------------------------------------------------
# 1. Register the device as an OAuth2 client. Real deployments do this once,
#    ahead of time, from fleet-provisioning tooling — not per boot. No
#    redirect_uris: a device never receives a browser redirect.
# ---------------------------------------------------------------------------
log "registering device client '${CLIENT_NAME}'"
CLIENT_JSON=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/oauth2-clients \
  "{\"name\":\"${CLIENT_NAME}\",\"redirect_uris\":[],\"grant_types\":[\"urn:ietf:params:oauth:grant-type:device_code\"],\"scopes\":[\"openid\"]}" \
  201)
CLIENT_ID=$(printf '%s' "${CLIENT_JSON}" | jq -r '.client_id')
if [ "${CLIENT_ID}" = "null" ] || [ -z "${CLIENT_ID}" ]; then
  fail "no client_id in response: ${CLIENT_JSON}"
fi
log "client_id=${CLIENT_ID}"

# ---------------------------------------------------------------------------
# 2. Device side: start the flow. Unauthenticated — the device holds no
#    credential of its own yet, that's the whole point of RFC 8628.
# ---------------------------------------------------------------------------
log "device: POST /oauth2/device_authorization"
DEVICE_AUTH_TMP="$(mktemp)"
DEVICE_AUTH_STATUS=$(curl -sS -o "${DEVICE_AUTH_TMP}" -w '%{http_code}' \
  -X POST "${AXIAM_URL}/oauth2/device_authorization" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "scope=openid")
DEVICE_AUTH_BODY="$(cat "${DEVICE_AUTH_TMP}")"
rm -f "${DEVICE_AUTH_TMP}"
[ "${DEVICE_AUTH_STATUS}" = "200" ] || fail "device_authorization -> ${DEVICE_AUTH_STATUS}: ${DEVICE_AUTH_BODY}"

DEVICE_CODE=$(printf '%s' "${DEVICE_AUTH_BODY}" | jq -r '.device_code')
USER_CODE=$(printf '%s' "${DEVICE_AUTH_BODY}" | jq -r '.user_code')
INTERVAL=$(printf '%s' "${DEVICE_AUTH_BODY}" | jq -r '.interval')
log "device shows: go to the verification URL and enter ${USER_CODE} (polling every ${INTERVAL}s)"

# ---------------------------------------------------------------------------
# 3. Human side: look the code up, then approve it. Both endpoints are
#    authenticated + CSRF-protected (docs/api/device-flow.md §3) — this is
#    why they live under /api/v1 rather than /oauth2.
# ---------------------------------------------------------------------------
log "human: GET /api/v1/device/verify?user_code=${USER_CODE}"
VERIFY_JSON=$(curl -sS -b "${ADMIN_JAR}" \
  "${AXIAM_URL}/api/v1/device/verify?user_code=${USER_CODE}")
FOUND=$(printf '%s' "${VERIFY_JSON}" | jq -r '.found')
[ "${FOUND}" = "true" ] || fail "verify did not find the code: ${VERIFY_JSON}"
log "human sees: client=$(printf '%s' "${VERIFY_JSON}" | jq -r '.client_id // .client_name // "?"') scopes=$(printf '%s' "${VERIFY_JSON}" | jq -c '.scopes // empty')"

log "human: POST /api/v1/device/decide {approved: true}"
api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/device/decide \
  "{\"user_code\":\"${USER_CODE}\",\"approved\":true}" 200 >/dev/null
ok "human approved ${USER_CODE}"

# ---------------------------------------------------------------------------
# 4. Device side: poll the token endpoint. The very first poll is expected
#    to (usually) come back authorization_pending — that is normal per RFC
#    8628 §3.5, not a bug, so the loop treats it as "keep going" rather than
#    an error. tenant_id must be a UUID; resolve it once from the admin
#    login's /api/v1/auth/me the same way a real device's operator tooling
#    would (baked into the device's config, in practice).
# ---------------------------------------------------------------------------
TENANT_ID=$(curl -sS -b "${ADMIN_JAR}" "${AXIAM_URL}/api/v1/auth/me" | jq -r '.tenant_id')
[ "${TENANT_ID}" != "null" ] || fail "could not resolve tenant_id from /api/v1/auth/me"

log "device: polling POST /oauth2/token?tenant_id=${TENANT_ID}"
TOKEN_JSON=""
for attempt in $(seq 1 15); do
  TMP="$(mktemp)"
  STATUS=$(curl -sS -o "${TMP}" -w '%{http_code}' \
    -X POST "${AXIAM_URL}/oauth2/token?tenant_id=${TENANT_ID}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    --data-urlencode "device_code=${DEVICE_CODE}" \
    --data-urlencode "client_id=${CLIENT_ID}")
  BODY="$(cat "${TMP}")"
  rm -f "${TMP}"

  if [ "${STATUS}" = "200" ]; then
    TOKEN_JSON="${BODY}"
    break
  fi

  ERROR=$(printf '%s' "${BODY}" | jq -r '.error // "unknown_error"')
  case "${ERROR}" in
    authorization_pending)
      log "attempt ${attempt}: authorization_pending — device keeps polling at ${INTERVAL}s"
      ;;
    slow_down)
      INTERVAL=$((INTERVAL + 5))
      log "attempt ${attempt}: slow_down — device raises its interval to ${INTERVAL}s"
      ;;
    access_denied|expired_token|invalid_grant)
      fail "device flow ended: ${ERROR}"
      ;;
    *)
      fail "unexpected token-endpoint error: ${BODY}"
      ;;
  esac
  sleep "${INTERVAL}"
done

[ -n "${TOKEN_JSON}" ] || fail "gave up waiting for approval after 15 polls"

ACCESS_TOKEN=$(printf '%s' "${TOKEN_JSON}" | jq -r '.access_token')
if [ "${ACCESS_TOKEN}" = "null" ] || [ -z "${ACCESS_TOKEN}" ]; then
  fail "no access_token in final response: ${TOKEN_JSON}"
fi

ok "device obtained an access token (expires_in=$(printf '%s' "${TOKEN_JSON}" | jq -r '.expires_in')s)"
log "device flow complete."
