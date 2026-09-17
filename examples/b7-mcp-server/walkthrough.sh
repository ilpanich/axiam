#!/usr/bin/env bash
# walkthrough.sh — B7 MCP authorization handshake, driven end to end over
# plain curl, in the style of examples/b1-deny-override: 401 -> discovery ->
# registration -> PKCE + resource -> token -> tool call, in each of the three
# ways a client can arrive that docs/api/mcp.md documents.
#
# Requires a running, bootstrapped AXIAM instance (see README.md — this
# repo's own scripts/e2e-bootstrap.sh does that against
# docker/docker-compose.e2e.yml) and builds + starts THIS example's own MCP
# server as a side effect (killed on exit).
#
# Usage:
#   AXIAM_URL=http://localhost:8090 ./walkthrough.sh
#   MODE=pre-registered ./walkthrough.sh   # or: dcr | cimd | all (default)
#
# Exit code is non-zero if any assertion fails, so this script doubles as the
# B7 CI smoke check (see .github/workflows/examples-smoke.yml).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
ADMIN_EMAIL="${E2E_TENANT_ADMIN_USERNAME:-tenant-admin}"
ADMIN_PASSWORD="${E2E_TENANT_ADMIN_PASSWORD:-${E2E_ADMIN_PASSWORD:-Test@Admin123!}}"
MCP_PORT="${MCP_PORT:-8091}"
MCP_HOST="127.0.0.1"
MCP_RESOURCE="http://${MCP_HOST}:${MCP_PORT}/mcp"
MODE="${MODE:-all}" # pre-registered | dcr | cimd | all

RUN_ID="$(date +%s)-$$"

ADMIN_JAR="$(mktemp)"
USER_JAR="$(mktemp)"
MCP_SERVER_LOG="$(mktemp)"
MCP_SERVER_PID=""
PUBLISHER_DIR="$(mktemp -d)"
PUBLISHER_PID=""

log()  { printf '\033[36m[b7-mcp-server]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[b7-mcp-server] PASS:\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[b7-mcp-server] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -n "${MCP_SERVER_PID}" ]; then kill "${MCP_SERVER_PID}" 2>/dev/null || true; fi
  if [ -n "${PUBLISHER_PID}" ]; then kill "${PUBLISHER_PID}" 2>/dev/null || true; fi
  rm -f "${ADMIN_JAR}" "${USER_JAR}" "${MCP_SERVER_LOG}"
  rm -rf "${PUBLISHER_DIR}"
}
trap cleanup EXIT

require() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required on PATH"; }
require curl
require jq
require node
require npm
require openssl
require python3

# ---------------------------------------------------------------------------
# Small helpers, mirroring examples/b1-deny-override/walkthrough.sh.
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

# GET AUTHZ_ENDPOINT with a cookie jar and the given --data-urlencode args,
# without following the redirect. Prints "<status>\n<location>" — everything
# past the first two arguments is passed straight to `curl -G`.
authorize_no_follow() {
  local jar="$1"; shift
  local headers status location
  headers="$(mktemp)"
  status=$(curl -sS -D "${headers}" -o /dev/null -w '%{http_code}' -c "${jar}" -b "${jar}" -G "${AUTHZ_ENDPOINT}" "$@")
  location="$(grep -i '^location:' "${headers}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)"
  rm -f "${headers}"
  printf '%s\n%s\n' "${status}" "${location}"
}

# base64url(sha256(verifier)) — RFC 7636 §4.2, no padding.
pkce_challenge() {
  printf '%s' "$1" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# The JWT's `<field>` claim, read without a signature check (this script is
# asserting what the SERVER minted, not re-verifying it).
jwt_claim() {
  local jwt="$1" field="$2" payload
  payload="$(printf '%s' "${jwt}" | cut -d. -f2 | tr '_-' '/+')"
  case $(( ${#payload} % 4 )) in
    2) payload="${payload}==" ;;
    3) payload="${payload}=" ;;
  esac
  printf '%s' "${payload}" | base64 -d 2>/dev/null | jq -r ".${field}"
}

# ---------------------------------------------------------------------------
# 0. Wait for AXIAM, log in as the tenant admin, build + start the MCP server.
# ---------------------------------------------------------------------------
log "waiting for ${AXIAM_URL}/health ..."
for i in $(seq 1 30); do
  status=$(curl -s -o /dev/null -w '%{http_code}' "${AXIAM_URL}/health" 2>/dev/null || true)
  [ "${status}" = "200" ] && break
  sleep 2
  [ "${i}" = "30" ] && fail "AXIAM never became healthy"
done

log "logging in as ${ADMIN_EMAIL} (tenant admin)"
ADMIN_LOGIN_HEADERS="$(mktemp)"
ADMIN_LOGIN_BODY=$(curl -sS -D "${ADMIN_LOGIN_HEADERS}" -c "${ADMIN_JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_SLUG}\",\"username_or_email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login")
ADMIN_CSRF=$(grep -i '^x-csrf-token:' "${ADMIN_LOGIN_HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2- || true)
rm -f "${ADMIN_LOGIN_HEADERS}"
[ -n "${ADMIN_CSRF}" ] || fail "no X-CSRF-Token on the admin login response: ${ADMIN_LOGIN_BODY}"
TENANT_ID=$(printf '%s' "${ADMIN_LOGIN_BODY}" | jq -r '.user.tenant_id')
[ "${TENANT_ID}" != "null" ] || fail "login did not return a tenant_id"

# ---------------------------------------------------------------------------
# The organization baseline, raised once for both self-registration modes.
#
# A tenant may refuse a registration mode its organization allows; it may not
# admit callers the organization does not (`validate_tenant_overrides` in
# crates/axiam-core/src/models/settings.rs). Both modes below are more
# permissive than the shipped baseline -- `dynamic_registration: disabled` and
# CIMD off -- so each tenant PUT is refused with 400 until the org baseline
# allows them. That refusal is the interlock working, not a bug: an operator
# fronting an MCP server has to make this same decision at org level first.
#
# PUT /organizations/{id}/settings takes the flat SetOrgSettings shape while
# GET returns SecuritySettings grouped by policy, so the groups are merged
# back into one object rather than a body being hand-written -- that way this
# step carries every other baseline value through untouched.
# ---------------------------------------------------------------------------
ORG_ID=$(api_expect GET "${ADMIN_JAR}" "" /api/v1/organizations "" 200 \
  | jq -r --arg slug "${ORG_SLUG}" '.items[] | select(.slug == $slug) | .id' | head -1)
if [ -z "${ORG_ID}" ] || [ "${ORG_ID}" = "null" ]; then
  fail "could not resolve the organization id for slug ${ORG_SLUG}"
fi

log "raising the org baseline: anonymous registration, CIMD over plaintext loopback"
ORG_BASELINE=$(api_expect GET "${ADMIN_JAR}" "" "/api/v1/organizations/${ORG_ID}/settings" "" 200 \
  | jq -c --arg res "${MCP_RESOURCE}" '[.password, .mfa, .lockout, .token, .email, .certificate, .notification,
            .opaque, .privacy, .webauthn, .oidc] | add
           | .dynamic_registration = "anonymous"
           | .external_client_allowed_resources = [$res]
           | .cimd.enabled = true
           | .cimd.allow_http = true
           | .cimd.trusted_client_id_domains = ["127.0.0.1"]')
api_expect PUT "${ADMIN_JAR}" "${ADMIN_CSRF}" "/api/v1/organizations/${ORG_ID}/settings" \
  "${ORG_BASELINE}" 200 >/dev/null
ok "org baseline permits what the tenant settings below ask for"

log "creating a disposable end user"
MCP_USERNAME="mcp-user-${RUN_ID}"
MCP_EMAIL="mcp-user-${RUN_ID}@example.invalid"
MCP_PASSWORD="Mcp$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')@1aA"
api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/users \
  "{\"username\":\"${MCP_USERNAME}\",\"email\":\"${MCP_EMAIL}\",\"password\":\"${MCP_PASSWORD}\"}" 201 >/dev/null

log "logging in as ${MCP_USERNAME} (the end user every authorization request below acts as)"
USER_LOGIN_HEADERS="$(mktemp)"
curl -sS -D "${USER_LOGIN_HEADERS}" -c "${USER_JAR}" -b "${USER_JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_SLUG}\",\"username_or_email\":\"${MCP_USERNAME}\",\"password\":\"${MCP_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login" >/dev/null
USER_CSRF=$(grep -i '^x-csrf-token:' "${USER_LOGIN_HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2- || true)
rm -f "${USER_LOGIN_HEADERS}"
[ -n "${USER_CSRF}" ] || fail "no X-CSRF-Token on the end user's login response"

log "building the MCP server (npm ci && npm run build)"
(cd "${SCRIPT_DIR}" && npm ci --silent && npm run build --silent) >/dev/null

log "starting the MCP server on ${MCP_RESOURCE}"
AXIAM_URL="${AXIAM_URL}" AXIAM_TENANT_ID="${TENANT_ID}" MCP_HOST="${MCP_HOST}" MCP_PORT="${MCP_PORT}" \
  node "${SCRIPT_DIR}/dist/server.js" >"${MCP_SERVER_LOG}" 2>&1 &
MCP_SERVER_PID=$!
for i in $(seq 1 20); do
  status=$(curl -s -o /dev/null -w '%{http_code}' "http://${MCP_HOST}:${MCP_PORT}/health" 2>/dev/null || true)
  [ "${status}" = "200" ] && break
  sleep 1
  if [ "${i}" = "20" ]; then
    cat "${MCP_SERVER_LOG}" >&2
    fail "the MCP server never became healthy"
  fi
done

# ---------------------------------------------------------------------------
# 1. The handshake every mode shares: 401 -> RFC 9728 document -> RFC 8414
#    discovery. See examples/b7-mcp-server/requests-protected-resource-metadata.md.
# ---------------------------------------------------------------------------
log "1. unauthenticated tools/list -> 401 with the RFC 6750 challenge, no error= (no credential presented)"
HEADERS="$(mktemp)"
STATUS=$(curl -sS -D "${HEADERS}" -o /dev/null -w '%{http_code}' -X POST "${MCP_RESOURCE}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
[ "${STATUS}" = "401" ] || fail "expected 401 with no credential, got ${STATUS}"
CHALLENGE=$(grep -i '^www-authenticate:' "${HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
rm -f "${HEADERS}"
[ -n "${CHALLENGE}" ] || fail "no WWW-Authenticate header on the 401"
printf '%s' "${CHALLENGE}" | grep -q 'error=' && fail "no-credential 401 must carry no error= parameter: ${CHALLENGE}"
ok "401 carries: ${CHALLENGE}"

METADATA_URL=$(printf '%s' "${CHALLENGE}" | sed -n 's/.*resource_metadata="\([^"]*\)".*/\1/p')
[ -n "${METADATA_URL}" ] || fail "could not parse resource_metadata from the challenge"

log "2. the document the challenge points at -> 200, no credential needed"
METADATA=$(curl -sS -o /dev/null -w '%{http_code}' "${METADATA_URL}")
[ "${METADATA}" = "200" ] || fail "GET ${METADATA_URL} -> ${METADATA} (wanted 200, unauthenticated)"
METADATA_DOC=$(curl -sS "${METADATA_URL}")
RESOURCE_IN_DOC=$(printf '%s' "${METADATA_DOC}" | jq -r '.resource')
[ "${RESOURCE_IN_DOC}" = "${MCP_RESOURCE}" ] || fail "document's resource (${RESOURCE_IN_DOC}) != ${MCP_RESOURCE}"
AXIAM_ISSUER=$(printf '%s' "${METADATA_DOC}" | jq -r '.authorization_servers[0]')
ok "document names authorization_servers[0]=${AXIAM_ISSUER}"

log "3. discovery at the named authorization server"
DISCOVERY=$(curl -sS "${AXIAM_ISSUER}/.well-known/oauth-authorization-server")
AUTHZ_ENDPOINT=$(printf '%s' "${DISCOVERY}" | jq -r '.authorization_endpoint')
TOKEN_ENDPOINT=$(printf '%s' "${DISCOVERY}" | jq -r '.token_endpoint')
[ "${AUTHZ_ENDPOINT}" != "null" ] || fail "discovery carried no authorization_endpoint"
ok "authorization_endpoint=${AUTHZ_ENDPOINT}"

# Calls an MCP tool over one fresh session: initialize, then tools/call. Reads
# the access token from stdin so a caller never has to worry about quoting it.
call_mcp_tool() {
  local token tool_name arguments session_id init_headers
  token="$1"; tool_name="$2"; arguments="$3"
  init_headers="$(mktemp)"
  curl -sS -D "${init_headers}" -o /dev/null -X POST "${MCP_RESOURCE}" \
    -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
    -H "Authorization: Bearer ${token}" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"walkthrough","version":"0.1.0"}}}'
  session_id=$(grep -i '^mcp-session-id:' "${init_headers}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
  rm -f "${init_headers}"
  [ -n "${session_id}" ] || fail "initialize did not return an Mcp-Session-Id"
  curl -sS -X POST "${MCP_RESOURCE}" \
    -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
    -H "Authorization: Bearer ${token}" -H "Mcp-Session-Id: ${session_id}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"${tool_name}\",\"arguments\":${arguments}}}"
}

# Finishes a code + PKCE + resource flow that has already produced $CODE,
# $REDIRECT_URI and $VERIFIER, and proves the token: minted for the MCP
# server, accepted by it, refused by AXIAM's own API (I3).
redeem_and_prove() {
  local client_id="$1" code="$2" redirect_uri="$3" verifier="$4" label="$5"
  local tokens access_token
  tokens=$(curl -sS -X POST "${TOKEN_ENDPOINT}?tenant_id=${TENANT_ID}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=${code}" \
    --data-urlencode "redirect_uri=${redirect_uri}" \
    --data-urlencode "client_id=${client_id}" \
    --data-urlencode "code_verifier=${verifier}" \
    --data-urlencode "resource=${MCP_RESOURCE}")
  access_token=$(printf '%s' "${tokens}" | jq -r '.access_token')
  if [ "${access_token}" = "null" ] || [ -z "${access_token}" ]; then
    fail "${label}: token redemption failed: ${tokens}"
  fi
  AUD=$(jwt_claim "${access_token}" aud)
  [ "${AUD}" = "${MCP_RESOURCE}" ] || fail "${label}: aud=${AUD}, wanted ${MCP_RESOURCE}"
  ok "${label}: token minted with aud=${AUD}"

  local list_result
  list_result=$(call_mcp_tool "${access_token}" list_widgets '{}')
  printf '%s' "${list_result}" | grep -q 'left-flange' || fail "${label}: list_widgets did not return the seeded widgets: ${list_result}"
  ok "${label}: the MCP server accepted the token and ran list_widgets"

  local reset_result
  reset_result=$(call_mcp_tool "${access_token}" reset_widgets '{"confirm":false}')
  printf '%s' "${reset_result}" | grep -q '"isError":true' || fail "${label}: reset_widgets(confirm:false) should be a no-op error, got: ${reset_result}"
  ok "${label}: reset_widgets ran under the granted scope (mcp:tools was requested and consented)"

  local axiam_status
  axiam_status=$(curl -sS -o /dev/null -w '%{http_code}' "${AXIAM_URL}/api/v1/auth/me" \
    -H "Authorization: Bearer ${access_token}")
  [ "${axiam_status}" = "401" ] || fail "${label}: AXIAM's own API must refuse an MCP-bound token (I3), got ${axiam_status}"
  ok "${label}: AXIAM's own API refused the MCP-bound token (I3)"
}

# ---------------------------------------------------------------------------
# Mode 1 — pre-registered: an administrator creates the client.
# See requests-public-client.md and requests-resource-indicators.md.
# ---------------------------------------------------------------------------
run_pre_registered() {
  log "=== pre-registered mode ==="
  local redirect_uri="http://127.0.0.1/callback"
  local client
  client=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/oauth2-clients \
    "{\"name\":\"b7-preregistered-${RUN_ID}\",\"redirect_uris\":[\"${redirect_uri}\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"scopes\":[\"openid\",\"profile\",\"mcp:tools\"],\"token_endpoint_auth_method\":\"none\",\"allowed_resources\":[\"${MCP_RESOURCE}\"]}" \
    201)
  printf '%s' "${client}" | jq -e 'has("client_secret") | not' >/dev/null \
    || fail "a public registration must mint no client_secret: ${client}"
  local client_id; client_id=$(printf '%s' "${client}" | jq -r '.client_id')
  ok "registered ${client_id} with no secret"

  local port=51703 verifier challenge
  verifier="verifier-${RUN_ID}-long-enough-for-rfc-7636-section-4-1"
  challenge=$(pkce_challenge "${verifier}")

  local result status location
  result=$(authorize_no_follow "${USER_JAR}" \
    --data-urlencode "response_type=code" \
    --data-urlencode "client_id=${client_id}" \
    --data-urlencode "redirect_uri=http://127.0.0.1:${port}/callback" \
    --data-urlencode "scope=openid profile mcp:tools" \
    --data-urlencode "code_challenge=${challenge}" \
    --data-urlencode "code_challenge_method=S256" \
    --data-urlencode "resource=${MCP_RESOURCE}")
  status=$(printf '%s' "${result}" | sed -n 1p)
  location=$(printf '%s' "${result}" | sed -n 2p)
  [ "${status}" = "302" ] || fail "pre-registered authorize -> ${status} (wanted 302, straight to a code — no consent for an admin-created client)"
  case "${location}" in
    "http://127.0.0.1:${port}/callback"*) ;;
    *) fail "expected the code back on the loopback port actually used: ${location}" ;;
  esac
  local code; code=$(printf '%s' "${location}" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  [ -n "${code}" ] || fail "no code in ${location}"

  redeem_and_prove "${client_id}" "${code}" "http://127.0.0.1:${port}/callback" "${verifier}" "pre-registered"
}

# ---------------------------------------------------------------------------
# Mode 2 — dynamic client registration: the client creates itself.
# See requests-dynamic-registration.md.
# ---------------------------------------------------------------------------
run_dcr() {
  log "=== dynamic client registration mode ==="
  api_expect PUT "${ADMIN_JAR}" "${ADMIN_CSRF}" "/api/v1/tenants/${TENANT_ID}/settings" \
    "{\"dynamic_registration\":\"anonymous\",\"dcr_allowed_scopes\":[\"openid\",\"profile\",\"mcp:tools\"],\"dcr_allowed_redirect_hosts\":[],\"external_client_allowed_resources\":[\"${MCP_RESOURCE}\"],\"dcr_max_clients\":20,\"dcr_unused_client_ttl_days\":30}" \
    200 >/dev/null

  local discovery reg_endpoint
  discovery=$(curl -sS "${AXIAM_ISSUER}/.well-known/oauth-authorization-server?tenant_id=${TENANT_ID}")
  reg_endpoint=$(printf '%s' "${discovery}" | jq -r '.registration_endpoint')
  [ "${reg_endpoint}" != "null" ] || fail "registration_endpoint absent after enabling dynamic_registration"
  ok "registration_endpoint advertised: ${reg_endpoint}"

  local redirect_uri="http://127.0.0.1/callback"
  local registered client_id
  registered=$(curl -sS -X POST "${reg_endpoint}" \
    -H "Content-Type: application/json" \
    -d "{\"client_name\":\"b7-dcr-${RUN_ID}\",\"redirect_uris\":[\"${redirect_uri}\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"],\"token_endpoint_auth_method\":\"none\",\"scope\":\"openid profile mcp:tools\"}")
  client_id=$(printf '%s' "${registered}" | jq -r '.client_id')
  if [ "${client_id}" = "null" ] || [ -z "${client_id}" ]; then
    fail "DCR registration failed: ${registered}"
  fi
  printf '%s' "${registered}" | jq -e 'has("client_secret") | not' >/dev/null \
    || fail "a none registration must mint no client_secret: ${registered}"
  ok "self-registered as ${client_id}"

  local port=51704 verifier challenge result status location
  verifier="verifier-${RUN_ID}-dcr-long-enough-for-rfc-7636-4-1"
  challenge=$(pkce_challenge "${verifier}")
  local authz_args=(
    --data-urlencode "response_type=code"
    --data-urlencode "client_id=${client_id}"
    --data-urlencode "redirect_uri=http://127.0.0.1:${port}/callback"
    --data-urlencode "scope=openid profile mcp:tools"
    --data-urlencode "code_challenge=${challenge}"
    --data-urlencode "code_challenge_method=S256"
    --data-urlencode "resource=${MCP_RESOURCE}"
  )

  result=$(authorize_no_follow "${USER_JAR}" "${authz_args[@]}")
  status=$(printf '%s' "${result}" | sed -n 1p)
  location=$(printf '%s' "${result}" | sed -n 2p)
  [ "${status}" = "302" ] || fail "DCR authorize -> ${status} (wanted 302)"
  printf '%s' "${location}" | grep -q 'consent' \
    || fail "D4 — a self-registered client's first authorization must go to consent: ${location}"
  ok "D4 honoured: first authorization redirected to consent"

  api_expect POST "${USER_JAR}" "${USER_CSRF}" /api/v1/account/consents/oidc-scopes \
    "{\"client_id\":\"${client_id}\",\"scopes\":[\"openid\",\"profile\",\"mcp:tools\"]}" 200 >/dev/null

  result=$(authorize_no_follow "${USER_JAR}" "${authz_args[@]}")
  status=$(printf '%s' "${result}" | sed -n 1p)
  location=$(printf '%s' "${result}" | sed -n 2p)
  [ "${status}" = "302" ] || fail "post-consent DCR authorize -> ${status} (wanted 302 with a code)"
  local code; code=$(printf '%s' "${location}" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  [ -n "${code}" ] || fail "no code in ${location}"

  redeem_and_prove "${client_id}" "${code}" "http://127.0.0.1:${port}/callback" "${verifier}" "DCR"
}

# ---------------------------------------------------------------------------
# Mode 3 — Client ID Metadata Documents: the client is the same everywhere.
# See requests-client-id-metadata-documents.md.
# ---------------------------------------------------------------------------
run_cimd() {
  log "=== Client ID Metadata Document mode ==="
  local pub_port=8099
  cat >"${PUBLISHER_DIR}/client.json" <<JSON
{
  "client_id": "http://127.0.0.1:${pub_port}/client.json",
  "client_name": "Example Editor",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "openid profile mcp:tools"
}
JSON
  python3 -m http.server "${pub_port}" --bind 127.0.0.1 --directory "${PUBLISHER_DIR}" \
    >/dev/null 2>&1 &
  PUBLISHER_PID=$!
  for i in $(seq 1 10); do
    status=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${pub_port}/client.json" 2>/dev/null || true)
    [ "${status}" = "200" ] && break
    sleep 1
    [ "${i}" = "10" ] && fail "the throwaway CIMD publisher never came up"
  done

  local client_id="http://127.0.0.1:${pub_port}/client.json"

  log "I1 — a URL-shaped client_id is an unknown client while cimd is disabled"
  local url_status opaque_status
  url_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${AXIAM_URL}/oauth2/token?tenant_id=${TENANT_ID}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" --data-urlencode "code=nope" \
    --data-urlencode "redirect_uri=http://127.0.0.1/callback" --data-urlencode "client_id=${client_id}" \
    --data-urlencode "code_verifier=x")
  opaque_status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${AXIAM_URL}/oauth2/token?tenant_id=${TENANT_ID}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=authorization_code" --data-urlencode "code=nope" \
    --data-urlencode "redirect_uri=http://127.0.0.1/callback" --data-urlencode "client_id=oa_never_registered" \
    --data-urlencode "code_verifier=x")
  [ "${url_status}" = "${opaque_status}" ] \
    || fail "I1: a URL client_id (${url_status}) must be refused exactly as an unknown opaque one (${opaque_status})"
  ok "I1 holds: both refused with ${url_status}"

  api_expect PUT "${ADMIN_JAR}" "${ADMIN_CSRF}" "/api/v1/tenants/${TENANT_ID}/settings" \
    "{\"dcr_allowed_scopes\":[\"openid\",\"profile\",\"mcp:tools\"],\"external_client_allowed_resources\":[\"${MCP_RESOURCE}\"],\"cimd\":{\"enabled\":true,\"allow_http\":true,\"trusted_client_id_domains\":[\"127.0.0.1\"],\"trusted_redirect_domains\":[],\"restrict_same_domain\":false,\"confidential_only\":false}}" \
    200 >/dev/null

  local port=51705 verifier challenge result status location
  verifier="verifier-${RUN_ID}-cimd-long-enough-for-rfc-7636-4-1"
  challenge=$(pkce_challenge "${verifier}")
  local authz_args=(
    --data-urlencode "response_type=code"
    --data-urlencode "client_id=${client_id}"
    --data-urlencode "redirect_uri=http://127.0.0.1:${port}/callback"
    --data-urlencode "scope=openid profile mcp:tools"
    --data-urlencode "code_challenge=${challenge}"
    --data-urlencode "code_challenge_method=S256"
    --data-urlencode "resource=${MCP_RESOURCE}"
  )

  result=$(authorize_no_follow "${USER_JAR}" "${authz_args[@]}")
  status=$(printf '%s' "${result}" | sed -n 1p)
  location=$(printf '%s' "${result}" | sed -n 2p)
  [ "${status}" = "302" ] || fail "CIMD authorize -> ${status} (wanted 302)"
  printf '%s' "${location}" | grep -q 'consent' \
    || fail "D4 — a CIMD-materialised client's first authorization must go to consent: ${location}"
  ok "the document materialised a client, and D4 forced consent"

  api_expect POST "${USER_JAR}" "${USER_CSRF}" /api/v1/account/consents/oidc-scopes \
    "{\"client_id\":\"${client_id}\",\"scopes\":[\"openid\",\"profile\",\"mcp:tools\"]}" 200 >/dev/null

  result=$(authorize_no_follow "${USER_JAR}" "${authz_args[@]}")
  status=$(printf '%s' "${result}" | sed -n 1p)
  location=$(printf '%s' "${result}" | sed -n 2p)
  [ "${status}" = "302" ] || fail "post-consent CIMD authorize -> ${status} (wanted 302 with a code)"
  local code; code=$(printf '%s' "${location}" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
  [ -n "${code}" ] || fail "no code in ${location}"

  redeem_and_prove "${client_id}" "${code}" "http://127.0.0.1:${port}/callback" "${verifier}" "CIMD"

  kill "${PUBLISHER_PID}" 2>/dev/null || true
  PUBLISHER_PID=""
}

case "${MODE}" in
  pre-registered) run_pre_registered ;;
  dcr) run_dcr ;;
  cimd) run_cimd ;;
  all) run_pre_registered; run_dcr; run_cimd ;;
  *) fail "unknown MODE=${MODE} (want pre-registered | dcr | cimd | all)" ;;
esac

log "all B7 assertions passed (MODE=${MODE})."
