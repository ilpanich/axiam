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
  # THREE clients, and which one goes in which config block is not
  # interchangeable — the suite reads all three by name and two of them must
  # use the SAME client authentication method.
  #
  #   config.client              -> `client`, client_secret_basic
  #   config.client2             -> `client2`, ALSO client_secret_basic
  #   config.client_secret_post  -> `client_secret_post`, the post method
  #
  # `client2` is the plan's SECOND client under the plan-level variant, which
  # is client_secret_basic. `oidcc-refresh-token` runs its second half as
  # client2 and authenticates it with an HTTP Basic header; when client2 was
  # the post client AXIAM refused that header — correctly, and it says so:
  # "an Authorization header using the Basic scheme was presented by a client
  # registered for client_secret_post; it is ignored and the request is
  # authenticated by the form-body secret (SEC-093: the registration decides)"
  # — and the module failed CheckTokenEndpointHttpStatus200 with a 401. The
  # server was right and the harness was wrong, which is why the fix is here.
  #
  # The post client belongs under a block named exactly `client_secret_post`.
  # `OIDCCServerTestClientSecretPost.configureClient()` is one statement:
  #
  #     config.add("client", config.get("client_secret_post"))
  #
  # so with no such block `client` becomes JSON null and the next condition
  # reports "As static client was selected, the test configuration must contain
  # a client configuration" — a message about `client`, thrown because a
  # DIFFERENT key was missing. An earlier session read that message literally,
  # observed that `client` rendered fine, and recorded the module as
  # not-root-caused.
  #
  # Registering all three from one function keeps every other field identical,
  # so any difference in a result is attributable to the method rather than to
  # a stray field.
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
        browser_sso: true,
        # The honour lane from W4, and without it a third of this plan tests
        # nothing.
        #
        # `authn_request_params` defaults to `ignore`, which means AXIAM drops
        # `prompt`, `max_age`, `acr_values`, `id_token_hint`, `login_hint`,
        # `display`, `ui_locales` and `claims_locales` before any decision sees
        # them. The Basic OP plan has whole families of modules that do nothing
        # but send those parameters and assert on the result — so on `ignore`
        # they do not test a relaxed AXIAM, they test an AXIAM that was never
        # asked the question.
        #
        # It showed up as three FAILUREs and an INTERRUPTED that all looked
        # like defects in the honour lane: prompt-none-not-logged-in,
        # max-age-1, max-age-10000, prompt-login. The W9 row of the gap plan
        # specified these clients as `standard`/`honour`/`browser_sso` from the
        # start; only the third was ever written down here.
        # (No apostrophes in this comment: it sits inside a single-quoted jq
        # program.)
        #
        # Legal on `standard` and refused on `fapi2`, which is why the FAPI
        # clients above must NOT carry it.
        authn_request_params: "honour"
      }')"
  }

  # The organization switch that makes `address` and `phone` releasable at all.
  #
  # `docs/conformance/README.md` lists this as one of three things the recipes
  # do not do for you, and the first run after that sentence was written duly
  # did not do it: `oidcc-scope-address`, `oidcc-scope-phone` and
  # `oidcc-scope-all` all reported UserInfo returning `sub, tenant_id, org_id`
  # and nothing else, for a user who demonstrably had both a telephone number
  # and a postal address. Nothing failed loudly — the first of the four release
  # gates in `axiam_oauth2::sensitive` simply answered no, which is what it is
  # for.
  #
  # A step a runbook asks a human to remember is a step that gets forgotten, so
  # the registrar performs it. It is the operator decision the switch is meant
  # to record, taken by the person setting up a conformance rig for a throwaway
  # organization; `settings.oidc.sensitive_scopes_enabled` is read at release
  # time from the TENANT, which inherits the organization's value.
  #
  # Read-modify-write, because the endpoint takes the whole settings document
  # and a hand-built one would silently reset every other policy in it.
  echo "[register] enabling sensitive scopes at the organization level"
  ORG_ID=$(api GET "/api/v1/organizations" | jq -r --arg s "$AXIAM_ADMIN_ORG_SLUG" \
    '.items[] | select(.slug == $s) | .id')
  [ -n "$ORG_ID" ] || { echo "[register] no organization with slug $AXIAM_ADMIN_ORG_SLUG" >&2; exit 1; }
  ORG_SETTINGS=$(api GET "/api/v1/organizations/$ORG_ID/settings")
  UPDATED=$(jq '.oidc = ((.oidc // {}) + {sensitive_scopes_enabled: true})' <<<"$ORG_SETTINGS")
  api PUT "/api/v1/organizations/$ORG_ID/settings" "$UPDATED" >/dev/null
  CHECK=$(api GET "/api/v1/organizations/$ORG_ID/settings" | jq -r '.oidc.sensitive_scopes_enabled')
  [ "$CHECK" = "true" ] || {
    echo "[register] sensitive_scopes_enabled did not stick (got '$CHECK') — address/phone will be withheld" >&2
    exit 1
  }
  echo "[register]   organization $ORG_ID: sensitive_scopes_enabled=true"

  echo "[register] creating the client_secret_basic client"
  B_RESP=$(mk_basic_client "axiam-conformance-basic" "client_secret_basic" "axiam-oidcc-basic")
  CLIENT_BASIC_ID=$(jq -r '.client_id // empty' <<<"$B_RESP")
  CLIENT_BASIC_SECRET=$(jq -r '.client_secret // empty' <<<"$B_RESP")
  [ -n "$CLIENT_BASIC_ID" ] || { echo "[register] failed: $B_RESP" >&2; exit 1; }
  echo "[register]   client_id=$CLIENT_BASIC_ID"

  echo "[register] creating the second client_secret_basic client (the plan's client2)"
  B2_RESP=$(mk_basic_client "axiam-conformance-basic-2" "client_secret_basic" "axiam-oidcc-basic")
  CLIENT_BASIC_2_ID=$(jq -r '.client_id // empty' <<<"$B2_RESP")
  CLIENT_BASIC_2_SECRET=$(jq -r '.client_secret // empty' <<<"$B2_RESP")
  [ -n "$CLIENT_BASIC_2_ID" ] || { echo "[register] failed: $B2_RESP" >&2; exit 1; }
  echo "[register]   client_id=$CLIENT_BASIC_2_ID"

  echo "[register] creating the client_secret_post client"
  P_RESP=$(mk_basic_client "axiam-conformance-basic-post" "client_secret_post" "axiam-oidcc-basic")
  CLIENT_BASIC_POST_ID=$(jq -r '.client_id // empty' <<<"$P_RESP")
  CLIENT_BASIC_POST_SECRET=$(jq -r '.client_secret // empty' <<<"$P_RESP")
  [ -n "$CLIENT_BASIC_POST_ID" ] || { echo "[register] failed: $P_RESP" >&2; exit 1; }
  echo "[register]   client_id=$CLIENT_BASIC_POST_ID"

  write_env \
    "CLIENT_BASIC_ID=$CLIENT_BASIC_ID" \
    "CLIENT_BASIC_SECRET=$CLIENT_BASIC_SECRET" \
    "CLIENT_BASIC_2_ID=$CLIENT_BASIC_2_ID" \
    "CLIENT_BASIC_2_SECRET=$CLIENT_BASIC_2_SECRET" \
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
# The third lane's callback. Its absence was invisible for as long as the
# private_key_jwt clients could not authenticate at all: PAR answered
# `401 invalid_client` before it ever looked at `redirect_uri`. With the
# assertion verifier wired, the very next answer became
# `400 invalid_request: redirect_uri is not registered for this client`, which
# would have failed all 56 modules of that lane for a second reason.
#
# Every client gets all three. A plan's `client` and `client2` are drawn from
# different lanes — the mTLS plan's client2 IS the self-signed client — so a
# client that only knew its own lane's callback would break the cross-client
# modules (`par-attempt-to-use-request_uri-for-different-client` and friends).
REDIRECT3="$SUITE/test/a/axiam-fapi2-private-key-jwt/callback"

# …and each of those three again with a query string on it.
#
# Not padding. Every FAPI plan's SECOND-client block sends
# `callback?dummy1=lorem&dummy2=ipsum` and nothing else, which is the suite
# checking RFC 6749 §3.1.2: a registered redirect_uri may carry a query
# component, and the server must compare the whole thing rather than the path.
# AXIAM compares the whole thing — correctly — so an unregistered dummy
# variant is answered `400 invalid_request: redirect_uri is not registered for
# this client` at PAR, and because every FAPI flow begins at PAR the module
# dies there with no assertion about the behaviour it was written to test.
# It cost `happy-flow` and `user-rejects-authentication` in the first run after
# client authentication started working at all.
#
# Built as one JSON array rather than six `--arg`s: three registrations share
# this list, and a list that has to be retyped three times is a list that will
# eventually differ in one of them.
DUMMY_QS='?dummy1=lorem&dummy2=ipsum'
REDIRECT_URIS=$(jq -n \
  --arg r1 "$REDIRECT" --arg r2 "$REDIRECT2" --arg r3 "$REDIRECT3" \
  --arg q "$DUMMY_QS" \
  '[$r1, $r2, $r3, ($r1 + $q), ($r2 + $q), ($r3 + $q)]')

echo "[register] creating the tls_client_auth client"
MTLS_RESP=$(api POST "/api/v1/oauth2-clients$TENANT_QS" "$(jq -n \
  --arg dn "$SUBJECT_DN" --argjson redirects "$REDIRECT_URIS" '{
    name: "axiam-conformance-mtls",
    redirect_uris: $redirects,
    grant_types: ["authorization_code", "refresh_token", "client_credentials"],
    scopes: ["openid", "profile"],
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
  --arg tp "$THUMBPRINT" --argjson redirects "$REDIRECT_URIS" '{
    name: "axiam-conformance-self-signed",
    redirect_uris: $redirects,
    grant_types: ["authorization_code", "refresh_token", "client_credentials"],
    scopes: ["openid", "profile"],
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

# Signing keys for the mTLS lane's two clients.
#
# These are NOT credentials — an mTLS client authenticates with its certificate
# and AXIAM is never given these key sets. They exist because the FAPI 2.0 plan
# runs `ValidateClientPrivateKeysAreDifferent` as a setup step for *every*
# module, whatever `client_auth_type` is: the profile's modules may sign a
# request object, so the suite insists both test clients have a usable signing
# key and that the two are not the same key.
#
# The mTLS plan shipped `"jwks": {"keys": []}` for both, so that step failed
# with "no key available to sign jwt" and took six modules with it — including
# `happy-flow`, which made the lane look far worse than it was.
#
# Only the PRIVATE halves are written: the suite signs with them, and there is
# no counterpart to register because these clients prove themselves at the TLS
# layer. Distinct kids, because "are these two clients different" is the exact
# question the failing step asks.
echo "[register] minting signing keys for the mTLS lane's two clients"
MTLS_KEYS=$(python3 "$SCRIPTS/gen-client-jwks.py" --kid "axiam-conformance-mtls-sig")
SS_KEYS=$(python3 "$SCRIPTS/gen-client-jwks.py" --kid "axiam-conformance-self-signed-sig")
write_env \
  "CLIENT_MTLS_JWKS=$(jq -c '.private' <<<"$MTLS_KEYS")" \
  "CLIENT_SELF_SIGNED_JWKS=$(jq -c '.private' <<<"$SS_KEYS")"

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
    --arg jwks "$PUB" --argjson redirects "$REDIRECT_URIS" '{
      name: $name,
      redirect_uris: $redirects,
      grant_types: ["authorization_code", "refresh_token", "client_credentials"],
      scopes: ["openid", "profile"],
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
