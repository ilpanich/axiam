#!/usr/bin/env bash
# smoke-test.sh — full runtime proof for B5: this script registers the RP
# app as an AXIAM OAuth2 client, starts the built app (`npm run build` must
# have already run), and drives ALL THREE pieces end to end with curl and a
# single shared cookie jar (curl's jar is domain-scoped, so one jar safely
# carries both AXIAM's session cookie and this app's `rp_session` cookie
# across the redirect chain below):
#
#   1. Login with AXIAM (PAR -> authorize -> callback -> exchange -> id_token
#      validated) — proven by the final page reading "Logged in as sub=...".
#   2. RP-Initiated Logout (GET /logout -> AXIAM end_session -> back to this
#      app) — proven by the final page reading "Not logged in.".
#   3. Back-Channel Logout — (2) above causes AXIAM to POST a logout token to
#      this app's own /backchannel-logout receiver as a side effect of
#      ending the session; proven via the debug endpoint
#      /internal/backchannel-log (AXIAM_ENABLE_DEBUG_ENDPOINT=true).
#
# Usage: AXIAM_URL=http://localhost:8090 ./smoke-test.sh
# (run from this directory, after `npm ci && npm run build`)

set -euo pipefail

AXIAM_URL="${AXIAM_URL:-http://localhost:8090}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
# The tenant-level admin seeded by scripts/e2e-bootstrap.sh (the
# organization-level super-admin signs in with no tenant — see b6). By
# username rather than email: an email next to a password is a credential
# pair as far as a secret scanner is concerned, fixture or not.
ADMIN_EMAIL="${E2E_TENANT_ADMIN_USERNAME:-tenant-admin}"
ADMIN_PASSWORD="${E2E_TENANT_ADMIN_PASSWORD:-${E2E_ADMIN_PASSWORD:-Test@Admin123!}}"
RP_PORT="${RP_PORT:-9999}"
RP_URL="http://localhost:${RP_PORT}"

# Where AXIAM should POST logout tokens.
#
# This is the ONE url in this script that AXIAM DIALS ITSELF. Every other url
# here is dialled by curl standing in for a browser, so every other url is
# resolved in *this script's* network namespace — but a `backchannel_logout_uri`
# is resolved in AXIAM's. Those are the same place only when AXIAM runs on this
# host.
#
# They are not the same place in CI, which runs AXIAM in the
# `axiam-e2e-server` container while this script runs on the runner: there,
# `localhost` names the container, nothing listens on ${RP_PORT} inside it, and
# all three delivery attempts are refused. The symptom is silence at both ends —
# AXIAM logs `back-channel logout delivery failed` (which examples-smoke.yml
# does not print), and this app never sees a request at all, so step 3 below
# times out with no other evidence. `.github/workflows/examples-smoke.yml`
# therefore sets this to `http://host.docker.internal:${RP_PORT}` and layers
# `docker-compose.host-gateway.override.yml`, which maps that name to the
# runner host.
#
# Default: same as RP_URL, which is correct whenever AXIAM and this script
# share a network namespace (running the server with `just run`, or any
# non-containerised local repro).
RP_BACKCHANNEL_URL="${RP_BACKCHANNEL_URL:-${RP_URL}}"

RUN_ID="$(date +%s)-$$"
JAR="$(mktemp)"
SERVER_LOG="$(mktemp)"
SERVER_PID=""

log()  { printf '\033[36m[b5-rp-logout-app]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[b5-rp-logout-app] PASS:\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[b5-rp-logout-app] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ -n "${SERVER_PID}" ]; then
    kill "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -f "${JAR}" "${SERVER_LOG}"
}
trap cleanup EXIT

require() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required on PATH"; }
require curl
require jq
require node

api_expect() {
  local method="$1" csrf="$2" path="$3" body="$4" want_status="$5"
  local resp status tmp
  tmp="$(mktemp)"
  local args=(-sS -o "${tmp}" -w '%{http_code}' -X "${method}" -c "${JAR}" -b "${JAR}"
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
  [ "${i}" = "30" ] && fail "AXIAM server never became healthy"
done

# ---------------------------------------------------------------------------
# 1. Admin sets up: register this app as an OAuth2 client, create a
#    disposable end user to log in as.
# ---------------------------------------------------------------------------
log "logging in as ${ADMIN_EMAIL} (admin)"
HEADERS="$(mktemp)"
LOGIN_BODY=$(curl -sS -D "${HEADERS}" -c "${JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_SLUG}\",\"username_or_email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login")
ADMIN_CSRF=$(grep -i '^x-csrf-token:' "${HEADERS}" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
rm -f "${HEADERS}"
[ -n "${ADMIN_CSRF}" ] || fail "no X-CSRF-Token on the admin login response"
TENANT_ID=$(printf '%s' "${LOGIN_BODY}" | jq -r '.user.tenant_id')
[ "${TENANT_ID}" != "null" ] || fail "login did not return a tenant_id"

log "registering this app as an AXIAM OAuth2 client (back-channel uri: ${RP_BACKCHANNEL_URL}/backchannel-logout)"
CLIENT_JSON=$(api_expect POST "${ADMIN_CSRF}" /api/v1/oauth2-clients \
  "{\"name\":\"b5-rp-logout-app-${RUN_ID}\",\"redirect_uris\":[\"${RP_URL}/callback\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"scopes\":[\"openid\",\"profile\"],\"post_logout_redirect_uris\":[\"${RP_URL}/\"],\"backchannel_logout_uri\":\"${RP_BACKCHANNEL_URL}/backchannel-logout\"}" \
  201)
CLIENT_ID=$(printf '%s' "${CLIENT_JSON}" | jq -r '.client_id')
CLIENT_SECRET=$(printf '%s' "${CLIENT_JSON}" | jq -r '.client_secret')

log "creating a test end user"
TEST_USERNAME="rp-demo-user-${RUN_ID}"
TEST_EMAIL="rp-demo-user-${RUN_ID}@example.invalid"
# Generated per run rather than a literal: a username/password pair in source
# is a secret-scanner finding wherever an example gets copied to.
TEST_PASSWORD="Rp$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')@1aA"
api_expect POST "${ADMIN_CSRF}" /api/v1/users \
  "{\"username\":\"${TEST_USERNAME}\",\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}" \
  201 >/dev/null

# ---------------------------------------------------------------------------
# 2. Start the app (already built — `npm run build` before this script).
# ---------------------------------------------------------------------------
log "starting the RP app on ${RP_URL}"
AXIAM_URL="${AXIAM_URL}" \
AXIAM_TENANT_ID="${TENANT_ID}" \
AXIAM_CLIENT_ID="${CLIENT_ID}" \
AXIAM_CLIENT_SECRET="${CLIENT_SECRET}" \
AXIAM_REDIRECT_URI="${RP_URL}/callback" \
AXIAM_POST_LOGOUT_REDIRECT_URI="${RP_URL}/" \
AXIAM_ENABLE_DEBUG_ENDPOINT="true" \
PORT="${RP_PORT}" \
  node dist/server.js >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!

for i in $(seq 1 20); do
  status=$(curl -s -o /dev/null -w '%{http_code}' "${RP_URL}/health" 2>/dev/null || true)
  [ "${status}" = "200" ] && break
  sleep 1
  if [ "${i}" = "20" ]; then
    cat "${SERVER_LOG}" >&2
    fail "RP app never became healthy"
  fi
done

# ---------------------------------------------------------------------------
# 3. Log in AS THE TEST USER directly at AXIAM (same jar, so AXIAM's
#    axiam_access cookie is on hand when the redirect chain below reaches
#    /oauth2/authorize) — this stands in for "already has a browser session"
#    the way a real SSO flow would after the user's first-ever login.
# ---------------------------------------------------------------------------
log "logging in as ${TEST_USERNAME} (this is the AXIAM session /login will reuse)"
curl -sS -c "${JAR}" -b "${JAR}" \
  -H "Content-Type: application/json" \
  -d "{\"org_slug\":\"${ORG_SLUG}\",\"tenant_slug\":\"${TENANT_SLUG}\",\"username_or_email\":\"${TEST_USERNAME}\",\"password\":\"${TEST_PASSWORD}\"}" \
  "${AXIAM_URL}/api/v1/auth/login" >/dev/null

# ---------------------------------------------------------------------------
# 4. The whole login dance, in one followed redirect chain:
#      RP /login -> (server-side PAR push) -> AXIAM /oauth2/authorize
#      (auto-approved: AXIAM session cookie already in the jar)
#      -> RP /callback (server-side code exchange + §12.4 ID-token checks)
#      -> RP /
# ---------------------------------------------------------------------------
log "GET ${RP_URL}/login (follows the full PAR + authorize + callback chain)"
HOME_BODY=$(curl -sS -L -c "${JAR}" -b "${JAR}" "${RP_URL}/login")
if ! printf '%s' "${HOME_BODY}" | grep -q "^Logged in as sub="; then
  cat "${SERVER_LOG}" >&2
  fail "expected 'Logged in as sub=...' after the login chain, got: ${HOME_BODY}"
fi
ok "login chain complete: $(printf '%s' "${HOME_BODY}" | head -1)"

# ---------------------------------------------------------------------------
# 5. RP-Initiated Logout: RP /logout -> AXIAM /oauth2/end_session (ends the
#    AXIAM session AND fires a best-effort back-channel logout POST back to
#    THIS app, since this app just participated in that session) -> RP /.
# ---------------------------------------------------------------------------
log "GET ${RP_URL}/logout (follows the RP-Initiated Logout redirect)"
LOGOUT_BODY=$(curl -sS -L -c "${JAR}" -b "${JAR}" "${RP_URL}/logout")
if ! printf '%s' "${LOGOUT_BODY}" | grep -q "^Not logged in\.$"; then
  cat "${SERVER_LOG}" >&2
  fail "expected 'Not logged in.' after logout, got: ${LOGOUT_BODY}"
fi
ok "RP-Initiated Logout complete: session ended, redirected back with no session"

# ---------------------------------------------------------------------------
# 6. Back-Channel Logout: delivery is best-effort (docs/api/logout.md
#    "Delivery" — up to 3 attempts, 500ms/2s backoff), so poll briefly
#    rather than asserting instantaneously.
# ---------------------------------------------------------------------------
log "polling ${RP_URL}/internal/backchannel-log for the logout token AXIAM should have delivered"
BACKCHANNEL_OK=""
for i in $(seq 1 10); do
  COUNT=$(curl -sS "${RP_URL}/internal/backchannel-log" | jq -r '.verified_jti_count')
  if [ "${COUNT}" -ge 1 ] 2>/dev/null; then
    BACKCHANNEL_OK=1
    break
  fi
  sleep 1
done
if [ -z "${BACKCHANNEL_OK}" ]; then
  cat "${SERVER_LOG}" >&2
  # The app log above distinguishes the two causes, which is why it prints an
  # arrival line before validating anything:
  #   - a "back-channel logout: POST received" line means AXIAM reached us and
  #     the token was refused; the rejection reason is the next line.
  #   - NO such line means AXIAM never reached us: it could not dial
  #     RP_BACKCHANNEL_URL from its own network namespace (see the comment on
  #     that variable), and its own log holds three
  #     "back-channel logout delivery failed" warnings.
  fail "no verified back-channel logout token arrived within 10s of RP-Initiated Logout" \
    "(registered back-channel uri: ${RP_BACKCHANNEL_URL}/backchannel-logout — reachable from AXIAM?)"
fi
ok "back-channel logout token received and verified (§12.7.3 checklist passed)"

log "all three B5 pieces proved end to end: login, RP-Initiated Logout, Back-Channel Logout."
