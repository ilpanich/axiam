#!/usr/bin/env bash
# smoke-test.sh — proves the built server actually runs, end to end, against
# a bootstrapped AXIAM: register a public client, complete a PKCE + resource
# code flow, and call an MCP tool with the resulting token. This is the
# narrower "does the server run" proof `examples/b5-rp-logout-app` also has;
# `walkthrough.sh` is the wider protocol-level proof (all three registration
# modes, both audience and scope refusals).
#
# Usage: AXIAM_URL=http://localhost:8090 ./smoke-test.sh
# (run from this directory, after `npm ci && npm run build`)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
ADMIN_EMAIL="${E2E_TENANT_ADMIN_USERNAME:-tenant-admin}"
ADMIN_PASSWORD="${E2E_TENANT_ADMIN_PASSWORD:-${E2E_ADMIN_PASSWORD:-Test@Admin123!}}"
MCP_PORT="${MCP_PORT:-8092}"
MCP_RESOURCE="http://127.0.0.1:${MCP_PORT}/mcp"

RUN_ID="$(date +%s)-$$"
ADMIN_JAR="$(mktemp)"
USER_JAR="$(mktemp)"
SERVER_LOG="$(mktemp)"
SERVER_PID=""

log()  { printf '\033[36m[b7-mcp-server]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[b7-mcp-server] PASS:\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[b7-mcp-server] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -n "${SERVER_PID}" ]; then kill "${SERVER_PID}" 2>/dev/null || true; fi
  rm -f "${ADMIN_JAR}" "${USER_JAR}" "${SERVER_LOG}"
}
trap cleanup EXIT

require() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required on PATH"; }
require curl
require jq
require node
require openssl

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

pkce_challenge() {
  printf '%s' "$1" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

log "waiting for ${AXIAM_URL}/health ..."
for i in $(seq 1 30); do
  status=$(curl -s -o /dev/null -w '%{http_code}' "${AXIAM_URL}/health" 2>/dev/null || true)
  [ "${status}" = "200" ] && break
  sleep 2
  [ "${i}" = "30" ] && fail "AXIAM never became healthy"
done

log "logging in as ${ADMIN_EMAIL} (admin)"
ADMIN_HEADERS="$(mktemp)"
ADMIN_BODY=$(curl -sS -D "${ADMIN_HEADERS}" -c "${ADMIN_JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_SLUG}\",\"username_or_email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login")
ADMIN_CSRF=$(grep -i '^x-csrf-token:' "${ADMIN_HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2- || true)
rm -f "${ADMIN_HEADERS}"
[ -n "${ADMIN_CSRF}" ] || fail "no X-CSRF-Token on the admin login response: ${ADMIN_BODY}"
TENANT_ID=$(printf '%s' "${ADMIN_BODY}" | jq -r '.user.tenant_id')
[ "${TENANT_ID}" != "null" ] || fail "login did not return a tenant_id"

log "registering a public client with allowed_resources=${MCP_RESOURCE}"
CLIENT_JSON=$(api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/oauth2-clients \
  "{\"name\":\"b7-smoke-${RUN_ID}\",\"redirect_uris\":[\"http://127.0.0.1/callback\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"scopes\":[\"openid\",\"profile\",\"mcp:tools\"],\"token_endpoint_auth_method\":\"none\",\"allowed_resources\":[\"${MCP_RESOURCE}\"]}" \
  201)
CLIENT_ID=$(printf '%s' "${CLIENT_JSON}" | jq -r '.client_id')

log "creating a test end user"
TEST_USERNAME="b7-smoke-user-${RUN_ID}"
TEST_PASSWORD="Sm$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')@1aA"
api_expect POST "${ADMIN_JAR}" "${ADMIN_CSRF}" /api/v1/users \
  "{\"username\":\"${TEST_USERNAME}\",\"email\":\"${TEST_USERNAME}@example.invalid\",\"password\":\"${TEST_PASSWORD}\"}" \
  201 >/dev/null

log "building and starting the MCP server on port ${MCP_PORT}"
(cd "${SCRIPT_DIR}" && npm run build --silent) >/dev/null
AXIAM_URL="${AXIAM_URL}" AXIAM_TENANT_ID="${TENANT_ID}" MCP_HOST="127.0.0.1" MCP_PORT="${MCP_PORT}" \
  node "${SCRIPT_DIR}/dist/server.js" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 20); do
  status=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${MCP_PORT}/health" 2>/dev/null || true)
  [ "${status}" = "200" ] && break
  sleep 1
  if [ "${i}" = "20" ]; then
    cat "${SERVER_LOG}" >&2
    fail "the MCP server never became healthy"
  fi
done
ok "server is up"

log "unauthenticated call -> 401 with a WWW-Authenticate challenge"
HEADERS="$(mktemp)"
STATUS=$(curl -sS -D "${HEADERS}" -o /dev/null -w '%{http_code}' -X POST "${MCP_RESOURCE}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
[ "${STATUS}" = "401" ] || fail "expected 401, got ${STATUS}"
grep -qi '^www-authenticate: bearer resource_metadata=' "${HEADERS}" \
  || fail "no bearer challenge on the 401: $(cat "${HEADERS}")"
rm -f "${HEADERS}"
ok "401 carried the challenge"

log "logging in as ${TEST_USERNAME} and completing the code + PKCE + resource flow"
curl -sS -c "${USER_JAR}" -b "${USER_JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_SLUG}\",\"username_or_email\":\"${TEST_USERNAME}\",\"password\":\"${TEST_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login" >/dev/null

VERIFIER="verifier-${RUN_ID}-smoke-long-enough-for-rfc-7636-4-1"
CHALLENGE=$(pkce_challenge "${VERIFIER}")
AUTHZ_HEADERS="$(mktemp)"
curl -sS -D "${AUTHZ_HEADERS}" -o /dev/null -c "${USER_JAR}" -b "${USER_JAR}" -G "${AXIAM_URL}/oauth2/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "redirect_uri=http://127.0.0.1:51706/callback" \
  --data-urlencode "scope=openid profile mcp:tools" \
  --data-urlencode "code_challenge=${CHALLENGE}" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "resource=${MCP_RESOURCE}"
LOCATION=$(grep -i '^location:' "${AUTHZ_HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
rm -f "${AUTHZ_HEADERS}"
CODE=$(printf '%s' "${LOCATION}" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
[ -n "${CODE}" ] || fail "no code in the authorize redirect: ${LOCATION}"

TOKENS=$(curl -sS -X POST "${AXIAM_URL}/oauth2/token?tenant_id=${TENANT_ID}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=${CODE}" \
  --data-urlencode "redirect_uri=http://127.0.0.1:51706/callback" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "code_verifier=${VERIFIER}" \
  --data-urlencode "resource=${MCP_RESOURCE}")
ACCESS_TOKEN=$(printf '%s' "${TOKENS}" | jq -r '.access_token')
if [ "${ACCESS_TOKEN}" = "null" ] || [ -z "${ACCESS_TOKEN}" ]; then
  fail "token redemption failed: ${TOKENS}"
fi
ok "token issued"

log "calling the MCP server with the token: initialize -> tools/call list_widgets"
INIT_HEADERS="$(mktemp)"
curl -sS -D "${INIT_HEADERS}" -o /dev/null -X POST "${MCP_RESOURCE}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke-test","version":"0.1.0"}}}'
SESSION_ID=$(grep -i '^mcp-session-id:' "${INIT_HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
rm -f "${INIT_HEADERS}"
[ -n "${SESSION_ID}" ] || fail "initialize did not return an Mcp-Session-Id"

RESULT=$(curl -sS -X POST "${MCP_RESOURCE}" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" -H "Mcp-Session-Id: ${SESSION_ID}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_widgets","arguments":{}}}')
printf '%s' "${RESULT}" | grep -q 'left-flange' || fail "list_widgets did not return the seeded widgets: ${RESULT}"
ok "tool call succeeded: ${RESULT}"

log "b7-mcp-server is proven to run end to end."
