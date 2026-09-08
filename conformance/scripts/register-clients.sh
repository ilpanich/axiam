#!/usr/bin/env bash
# register-clients.sh — provision the clients a conformance plan needs, and
# write their ids back into suite.env (X5.2, extended in W9).
#
#   register-clients.sh          # the FAPI 2.0 clients (default, X5.2)
#   register-clients.sh basic    # the Basic OP clients + test user (W9)
#
# The FAPI clients are registered with `profile: "fapi2"`, which is the whole
# X5.1 switch: the server then refuses the registration outright unless it also
# carries require_par, an mTLS authentication method, and certificate-bound
# access tokens. So if this script succeeds, those clients are FAPI-shaped by
# construction rather than by this script remembering to set four fields.
#
# Requires: jq, curl, openssl, and an admin credential (see lib-admin.sh).
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
PROFILE="${1:-fapi2}"

# shellcheck disable=SC1091
. "$SCRIPTS/lib-env.sh"
conf_load
# shellcheck disable=SC1091
. "$SCRIPTS/lib-admin.sh"

command -v jq >/dev/null || { echo "[register] jq is required" >&2; exit 1; }
: "${AXIAM_ISSUER:?set AXIAM_ISSUER in conformance/suite.env}"

CERTS="${CONFORMANCE_CERTS_DIR:-$HERE/certs}"

# The suite's redirect URIs. Derived from the suite's own BASE_URL rather than
# configured, because a mismatch here fails a whole plan at its first
# authorization step and deriving it removes the chance to typo it. The alias
# in the path is the plan's `alias` field and must match it exactly.
SUITE="${SUITE_BASE_URL:-https://localhost.emobix.co.uk:8442}"

# W9. The clients are created inside the tenant the plans name. Without this a
# client lands in whatever tenant the admin's session defaults to, and an
# authorization request carrying tenant_id then cannot find it — which surfaces
# as `invalid_client` on a client you just watched get created.
TENANT_QS=""
[ -n "${AXIAM_TENANT_ID:-}" ] && TENANT_QS="?tenant_id=${AXIAM_TENANT_ID}"

admin_login
api() { axiam_api "$@"; }

# Results go to the GITIGNORED local file, never to the committed suite.env —
# from W9 these include client SECRETS. See lib-env.sh.
write_env() { conf_write_local "$@"; }

# ---------------------------------------------------------------------------
# W9 — the Basic OP lane
# ---------------------------------------------------------------------------
if [ "$PROFILE" = "basic" ]; then
  # Two clients that differ ONLY in token_endpoint_auth_method. That is the
  # point: `oidcc-basic-certification-test-plan` treats client_secret_basic
  # (RFC 6749 §2.3.1, the Authorization header) and client_secret_post (the
  # body) as separate concerns, and W8 was the first time AXIAM could answer
  # the first at all. Registering both from one function keeps every other
  # field identical, so any difference in a result is attributable to the
  # method rather than to a stray field.
  #
  # `standard` profile, NOT fapi2: the Basic profile requires neither PAR nor
  # certificate-bound tokens, and a fapi2 client would refuse the plan's
  # ordinary authorization requests for reasons that are the FAPI profile
  # working correctly.
  #
  # browser_sso is what makes an unattended run possible at all: the suite's
  # cross-site redirect reaches a sign-in page instead of a 401. See
  # docs/admin/browser-login-hop.md for the cookie and the 60-second PAR
  # window that bounds how long the hop may take.
  mk_basic_client() {
    local name="$1" method="$2" alias="$3"
    api POST "/api/v1/oauth2-clients$TENANT_QS" "$(jq -n \
      --arg n "$name" --arg m "$method" \
      --arg r1 "$SUITE/test/a/$alias/callback" \
      --arg r2 "$SUITE/test/a/$alias/callback?dummy1=lorem&dummy2=ipsum" '{
        name: $n,
        redirect_uris: [$r1, $r2],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scopes: ["openid", "profile", "email", "address", "phone"],
        profile: "standard",
        require_par: false,
        token_endpoint_auth_method: $m,
        browser_sso: true
      }')"
  }

  echo "[register] creating the client_secret_basic client"
  B_RESP=$(mk_basic_client "axiam-conformance-basic" "client_secret_basic" "axiam-oidcc-basic")
  CLIENT_BASIC_ID=$(jq -r '.client_id // empty' <<<"$B_RESP")
  CLIENT_BASIC_SECRET=$(jq -r '.client_secret // empty' <<<"$B_RESP")
  [ -n "$CLIENT_BASIC_ID" ] || { echo "[register] failed: $B_RESP" >&2; exit 1; }
  echo "[register]   client_id=$CLIENT_BASIC_ID"

  echo "[register] creating the client_secret_post client"
  P_RESP=$(mk_basic_client "axiam-conformance-basic-post" "client_secret_post" "axiam-oidcc-basic")
  CLIENT_BASIC_POST_ID=$(jq -r '.client_id // empty' <<<"$P_RESP")
  CLIENT_BASIC_POST_SECRET=$(jq -r '.client_secret // empty' <<<"$P_RESP")
  [ -n "$CLIENT_BASIC_POST_ID" ] || { echo "[register] failed: $P_RESP" >&2; exit 1; }
  echo "[register]   client_id=$CLIENT_BASIC_POST_ID"

  write_env \
    "CLIENT_BASIC_ID=$CLIENT_BASIC_ID" \
    "CLIENT_BASIC_SECRET=$CLIENT_BASIC_SECRET" \
    "CLIENT_BASIC_POST_ID=$CLIENT_BASIC_POST_ID" \
    "CLIENT_BASIC_POST_SECRET=$CLIENT_BASIC_POST_SECRET"

  bash "$SCRIPTS/register-user.sh"
  echo "[register] suite.env updated. Next: just conformance-run-basic"
  exit 0
fi

# ---------------------------------------------------------------------------
# X5.2 — the FAPI 2.0 lane
# ---------------------------------------------------------------------------
for f in client-mtls.crt client-self-signed.crt; do
  [ -f "$CERTS/$f" ] || { echo "[register] missing $CERTS/$f — run 'just conformance-certs'" >&2; exit 1; }
done

SUBJECT_DN=$(openssl x509 -in "$CERTS/client-mtls.crt" -noout -subject -nameopt rfc2253 | sed 's/^subject=//')
THUMBPRINT=$(openssl x509 -in "$CERTS/client-self-signed.crt" -outform der \
  | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

REDIRECT="$SUITE/test/a/axiam-fapi2-mtls/callback"
REDIRECT2="$SUITE/test/a/axiam-fapi2-self-signed/callback"

echo "[register] creating the tls_client_auth client"
MTLS_RESP=$(api POST "/api/v1/oauth2-clients$TENANT_QS" "$(jq -n \
  --arg dn "$SUBJECT_DN" --arg r1 "$REDIRECT" --arg r2 "$REDIRECT2" '{
    name: "axiam-conformance-mtls",
    redirect_uris: [$r1, $r2],
    grant_types: ["authorization_code", "refresh_token", "client_credentials"],
    scopes: ["openid"],
    profile: "fapi2",
    require_par: true,
    token_endpoint_auth_method: "tls_client_auth",
    tls_client_auth_subject_dn: $dn,
    tls_client_certificate_bound_access_tokens: true
  }')")
CLIENT_MTLS_ID=$(jq -r '.client_id // empty' <<<"$MTLS_RESP")
[ -n "$CLIENT_MTLS_ID" ] || { echo "[register] failed: $MTLS_RESP" >&2; exit 1; }
echo "[register]   client_id=$CLIENT_MTLS_ID"

echo "[register] creating the self_signed_tls_client_auth client"
SS_RESP=$(api POST "/api/v1/oauth2-clients$TENANT_QS" "$(jq -n \
  --arg tp "$THUMBPRINT" --arg r1 "$REDIRECT" --arg r2 "$REDIRECT2" '{
    name: "axiam-conformance-self-signed",
    redirect_uris: [$r1, $r2],
    grant_types: ["authorization_code", "refresh_token", "client_credentials"],
    scopes: ["openid"],
    profile: "fapi2",
    require_par: true,
    token_endpoint_auth_method: "self_signed_tls_client_auth",
    self_signed_tls_client_auth_thumbprints: [$tp],
    tls_client_certificate_bound_access_tokens: true
  }')")
CLIENT_SELF_SIGNED_ID=$(jq -r '.client_id // empty' <<<"$SS_RESP")
[ -n "$CLIENT_SELF_SIGNED_ID" ] || { echo "[register] failed: $SS_RESP" >&2; exit 1; }
echo "[register]   client_id=$CLIENT_SELF_SIGNED_ID"

write_env "CLIENT_MTLS_ID=$CLIENT_MTLS_ID" "CLIENT_SELF_SIGNED_ID=$CLIENT_SELF_SIGNED_ID"

echo "[register] suite.env updated. Next: just conformance-run"
