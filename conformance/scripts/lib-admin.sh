# lib-admin.sh — authenticate against AXIAM's admin API (W9). Sourced, not run.
#
# Extracted in W9 because there are now two registrars (FAPI and Basic OP) and
# a conformance user to provision, and three copies of an authentication dance
# is three chances for them to disagree about which one is correct.
#
# What it corrects: the harness previously assumed a bearer token in
# AXIAM_ADMIN_TOKEN, and nothing in AXIAM's admin flow issues one. An
# administrator signs in at POST /api/v1/auth/login with an ORG SLUG (login is
# ambiguous without it — "must provide org_id or org_slug") and receives a
# session: an HttpOnly cookie, plus an X-CSRF-Token response header that every
# subsequent mutating request must echo. Miss the CSRF header and writes fail
# with an error about the token rather than about the credential, which sends
# you looking in the wrong place.
#
# A bearer is still honoured when AXIAM_ADMIN_TOKEN is set, for a deployment
# that provisions with a service account's client_credentials token.
#
# Exports: axiam_api (method path [body]) — a curl wrapper carrying whichever
# credential was established, and the CSRF header when there is one.

# shellcheck shell=bash

_ADMIN_JAR=""
_ADMIN_CSRF=""
_ADMIN_MODE=""

# The base URL the HARNESS uses. Distinct from AXIAM_ISSUER, which is the name
# the suite's CONTAINER uses; see suite.env.
axiam_admin_base() {
  echo "${AXIAM_ADMIN_BASE_URL:-$AXIAM_ISSUER}"
}

# TLS: verify against the conformance CA rather than disabling verification.
# The harness mints AXIAM's certificate from that CA (gen-certs.sh), so there is
# a correct answer available and no reason to accept any certificate — this
# connection carries an administrator's password.
axiam_ca_bundle() {
  local ca="${AXIAM_CA:-certs/ca.crt}"
  case "$ca" in /*) echo "$ca" ;; *) echo "$HERE/$ca" ;; esac
}

admin_login() {
  : "${AXIAM_ISSUER:?set AXIAM_ISSUER in conformance/suite.env}"
  export CURL_CA_BUNDLE="${CURL_CA_BUNDLE:-$(axiam_ca_bundle)}"

  if [ -n "${AXIAM_ADMIN_TOKEN:-}" ]; then
    _ADMIN_MODE="bearer"
    echo "[admin] authenticating with AXIAM_ADMIN_TOKEN (bearer)"
    return 0
  fi

  local user="${AXIAM_ADMIN_USER:?set AXIAM_ADMIN_USER or AXIAM_ADMIN_TOKEN}"
  local slug="${AXIAM_ADMIN_ORG_SLUG:?set AXIAM_ADMIN_ORG_SLUG}"
  local pass="${AXIAM_ADMIN_PASSWORD:-}"
  if [ -z "$pass" ]; then
    read -r -s -p "[admin] password for $user in org $slug: " pass; echo
  fi

  _ADMIN_JAR="$(mktemp)"; local hdr; hdr="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f '$_ADMIN_JAR' '$hdr'" EXIT

  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' -D "$hdr" -c "$_ADMIN_JAR" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg s "$slug" --arg u "$user" --arg p "$pass" \
          '{org_slug:$s, username_or_email:$u, password:$p}')" \
    "$(axiam_admin_base)/api/v1/auth/login") || true

  if [ "$code" != "200" ]; then
    echo "[admin] login failed with HTTP $code for $user in org $slug" >&2
    echo "[admin] check AXIAM_ADMIN_ORG_SLUG / AXIAM_ADMIN_USER / AXIAM_ADMIN_PASSWORD" >&2
    exit 1
  fi

  _ADMIN_CSRF=$(grep -i '^x-csrf-token:' "$hdr" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
  [ -n "$_ADMIN_CSRF" ] || { echo "[admin] no X-CSRF-Token on the login response" >&2; exit 1; }
  _ADMIN_MODE="session"
  echo "[admin] signed in as $user (session + CSRF)"
}

# axiam_api <METHOD> <path> [json-body]
axiam_api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" "$(axiam_admin_base)$path" -H "Content-Type: application/json")
  case "$_ADMIN_MODE" in
    bearer)  args+=(-H "Authorization: Bearer $AXIAM_ADMIN_TOKEN") ;;
    session) args+=(-b "$_ADMIN_JAR" -c "$_ADMIN_JAR" -H "X-CSRF-Token: $_ADMIN_CSRF") ;;
    *) echo "[admin] admin_login was not called" >&2; exit 1 ;;
  esac
  [ -n "$body" ] && args+=(-d "$body")
  curl "${args[@]}"
}
