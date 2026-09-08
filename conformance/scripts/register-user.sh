#!/usr/bin/env bash
# register-user.sh — provision the end user the Basic OP plan authenticates as (W9).
#
# The plan requests `openid profile email address phone`, and several modules
# assert that the claims those scopes cover actually come back. A user without
# a phone number and an address therefore produces results that look like an
# AXIAM defect and are missing test data — which is the most expensive kind of
# false finding, because it sends you into the server.
#
# It takes two APIs to make one user, and that is a fact about AXIAM rather
# than an accident here:
#
#   POST /api/v1/users   creates the account. Its CreateUserRequest carries
#                        username, email and password and nothing else — there
#                        is no phone or address field on it.
#   PATCH /scim/v2/Users SCIM is where W7 put `phoneNumbers` and `addresses`,
#                        so it is the only write path that can set them.
#
# The status update in between is not optional either: a user created over REST
# is PendingVerification and has a 24-hour grace period, after which the login
# this plan depends on starts failing with "account is pending verification" —
# a fixture that works today and breaks tomorrow.
set -euo pipefail

# Read by lib-env.sh's conf_load and lib-admin.sh's axiam_ca_bundle. A comment
# line may not BEGIN with the linter's own name — it is parsed as a directive.
# shellcheck disable=SC2034
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"

# shellcheck disable=SC1091
. "$SCRIPTS/lib-env.sh"
conf_load
# shellcheck disable=SC1091
. "$SCRIPTS/lib-admin.sh"

: "${AXIAM_ISSUER:?set AXIAM_ISSUER in conformance/suite.env}"
: "${AXIAM_TENANT_ID:?set AXIAM_TENANT_ID in conformance/suite.env}"

USER_EMAIL="${CONFORMANCE_USER:-conformance-user@axiam.dev}"
USER_NAME="${USER_EMAIL%%@*}"
USER_PASS="${CONFORMANCE_USER_PASSWORD:-}"
if [ -z "$USER_PASS" ]; then
  # Generated rather than defaulted to a literal: this account can complete an
  # authorization and mint tokens, and a password committed in a repository is
  # one somebody eventually points at something that matters. It is written
  # back into suite.local.env, which is gitignored for exactly this reason.
  USER_PASS="Conf-$(openssl rand -hex 12)!aA1"
fi

# lib-admin may already be initialised when sourced from register-clients.sh;
# calling it again would prompt a second time.
if [ -z "${_ADMIN_MODE:-}" ]; then admin_login; fi

TENANT_QS="?tenant_id=${AXIAM_TENANT_ID}"

echo "[register-user] creating $USER_EMAIL"
RESP=$(axiam_api POST "/api/v1/users$TENANT_QS" "$(jq -n \
  --arg u "$USER_NAME" --arg e "$USER_EMAIL" --arg p "$USER_PASS" \
  '{username: $u, email: $e, password: $p}')")
USER_ID=$(jq -r '.id // empty' <<<"$RESP")

if [ -z "$USER_ID" ]; then
  # Re-running the registrar must not be a hard error: iterating on a plan
  # means running this repeatedly, and the account outlives the iteration.
  USER_ID=$(axiam_api GET "/api/v1/users$TENANT_QS&search=$USER_NAME" \
    | jq -r --arg e "$USER_EMAIL" '(.items // .) | map(select(.email == $e)) | .[0].id // empty')
  [ -n "$USER_ID" ] || { echo "[register-user] could not create or find the user: $RESP" >&2; exit 1; }
  echo "[register-user]   already existed: $USER_ID"
else
  echo "[register-user]   created: $USER_ID"
fi

echo "[register-user] activating (a REST-created user is PendingVerification)"
axiam_api PUT "/api/v1/users/$USER_ID$TENANT_QS" '{"status":"Active"}' >/dev/null

echo "[register-user] setting phone and address over SCIM"
SCIM=$(axiam_api PATCH "/scim/v2/Users/$USER_ID$TENANT_QS" "$(jq -n '{
  schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  Operations: [
    { op: "replace", path: "phoneNumbers",
      value: [ { value: "+1 555 0100", type: "mobile", primary: true } ] },
    { op: "replace", path: "addresses",
      value: [ {
        formatted: "742 Evergreen Terrace\nSpringfield, IL 62704\nUS",
        streetAddress: "742 Evergreen Terrace",
        locality: "Springfield",
        region: "IL",
        postalCode: "62704",
        country: "US",
        type: "home",
        primary: true
      } ] }
  ]
}')")
if ! jq -e '.id // .schemas' >/dev/null 2>&1 <<<"$SCIM"; then
  echo "[register-user] SCIM patch did not return a user resource:" >&2
  echo "$SCIM" >&2
  exit 1
fi

conf_write_local "CONFORMANCE_USER=$USER_EMAIL" "CONFORMANCE_USER_PASSWORD=$USER_PASS"

echo "[register-user] $USER_EMAIL is Active with a phone number and an address"
