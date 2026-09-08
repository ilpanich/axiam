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
    # W9 follow-up. Without this the FAPI lane cannot complete a single
    # authorization either: `/oauth2/authorize` answers a cross-site redirect
    # from a client that is not `browser_sso` with a 401 JSON body, which is
    # why 30 of the 31 modules in the 2026-09-08 run finished INTERRUPTED. It
    # is not a relaxation of the profile — the return leg re-runs the PAR,
    # PKCE and FAPI gates unchanged (basic-op-gap-plan.md §5, row G0).
    browser_sso: true,
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
    # W9 follow-up. Without this the FAPI lane cannot complete a single
    # authorization either: `/oauth2/authorize` answers a cross-site redirect
    # from a client that is not `browser_sso` with a 401 JSON body, which is
    # why 30 of the 31 modules in the 2026-09-08 run finished INTERRUPTED. It
    # is not a relaxation of the profile — the return leg re-runs the PAR,
    # PKCE and FAPI gates unchanged (basic-op-gap-plan.md §5, row G0).
    browser_sso: true,
    token_endpoint_auth_method: "self_signed_tls_client_auth",
    self_signed_tls_client_auth_thumbprints: [$tp],
    tls_client_certificate_bound_access_tokens: true
  }')")
CLIENT_SELF_SIGNED_ID=$(jq -r '.client_id // empty' <<<"$SS_RESP")
[ -n "$CLIENT_SELF_SIGNED_ID" ] || { echo "[register] failed: $SS_RESP" >&2; exit 1; }
echo "[register]   client_id=$CLIENT_SELF_SIGNED_ID"

# ---------------------------------------------------------------------------
# The private_key_jwt lane (RFC 7523 §2.2) — never provisioned until now
# ---------------------------------------------------------------------------
#
# `conformance-run` has always driven three plans and this script has always
# created two clients, so the private-key-jwt plan could not run: its template
# renders `${CLIENT_PRIVATE_KEY_JWT_ID}` into an empty string and the suite
# refuses the configuration. That is a third of the FAPI 2.0 surface — the
# OTHER client-authentication family the profile defines — and its absence was
# invisible because the plan failed before reaching a module.
#
# TWO clients, not one, because the plan needs a second registration to prove
# an assertion minted for one client is refused for another
# (`ensure-authorization-code-is-bound-to-client` and its siblings). They are
# generated with distinct kids for the same reason.
#
# The keypair is split at the trust boundary: AXIAM registers the PUBLIC set as
# the client's credential, and the suite is handed the PRIVATE set because the
# suite is the client and has to sign with it. `conf_write_local` puts the
# private halves in the gitignored file — they are secrets, and suite.env is
# tracked.
echo "[register] creating the two private_key_jwt clients"
for n in 1 2; do
  KEYS=$(python3 "$SCRIPTS/gen-client-jwks.py" --kid "axiam-conformance-pkjwt-$n")
  PUB=$(jq -c '.public' <<<"$KEYS")
  PRIV=$(jq -c '.private' <<<"$KEYS")

  # `jwks` is a STRING on the wire, not an object: OAuth2Client stores the key
  # set verbatim so that what AXIAM verifies against is byte-for-byte what was
  # registered. `--arg` (not `--argjson`) is therefore correct here and a
  # mistake everywhere else in this file.
  RESP=$(api POST "/api/v1/oauth2-clients$TENANT_QS" "$(jq -n \
    --arg name "axiam-conformance-pkjwt-$n" \
    --arg jwks "$PUB" --arg r1 "$REDIRECT" --arg r2 "$REDIRECT2" '{
      name: $name,
      redirect_uris: [$r1, $r2],
      grant_types: ["authorization_code", "refresh_token", "client_credentials"],
      scopes: ["openid"],
      profile: "fapi2",
      require_par: true,
      browser_sso: true,
      token_endpoint_auth_method: "private_key_jwt",
      jwks: $jwks,
      # The private_key_jwt plan runs sender_constrain=dpop — the other half of
      # FAPI 2.0. Certificate-bound tokens belong to the mTLS lane; asking for
      # both here would bind a token to a certificate this client never
      # presents. (No apostrophes in this comment: it sits inside a
      # single-quoted jq program.)
      dpop_bound_access_tokens: true
    }')")
  ID=$(jq -r '.client_id // empty' <<<"$RESP")
  [ -n "$ID" ] || { echo "[register] failed (pkjwt $n): $RESP" >&2; exit 1; }
  echo "[register]   client_id=$ID"

  if [ "$n" = 1 ]; then
    PKJWT_1_ID="$ID"; PKJWT_1_JWKS="$PRIV"
  else
    PKJWT_2_ID="$ID"; PKJWT_2_JWKS="$PRIV"
  fi
done

write_env \
  "CLIENT_MTLS_ID=$CLIENT_MTLS_ID" \
  "CLIENT_SELF_SIGNED_ID=$CLIENT_SELF_SIGNED_ID" \
  "CLIENT_PRIVATE_KEY_JWT_ID=$PKJWT_1_ID" \
  "CLIENT_PRIVATE_KEY_JWT_JWKS=$PKJWT_1_JWKS" \
  "CLIENT_PRIVATE_KEY_JWT_2_ID=$PKJWT_2_ID" \
  "CLIENT_PRIVATE_KEY_JWT_2_JWKS=$PKJWT_2_JWKS"

echo "[register] suite.env updated. Next: just conformance-run"
