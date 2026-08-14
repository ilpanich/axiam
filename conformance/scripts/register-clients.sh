#!/usr/bin/env bash
# register-clients.sh — provision the two FAPI 2.0 clients the conformance
# plans need, and write their ids back into suite.env (X5.2).
#
# Both are registered with `profile: "fapi2"`, which is the whole X5.1 switch:
# the server then refuses the registration outright unless it also carries
# require_par, an mTLS authentication method, and certificate-bound access
# tokens. So if this script succeeds, the clients are FAPI-shaped by
# construction rather than by this script remembering to set four fields.
#
# Usage: register-clients.sh
# Requires: AXIAM_ADMIN_TOKEN (env or suite.env), jq, curl, openssl.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
set -a; . "$HERE/suite.env"; set +a

command -v jq >/dev/null || { echo "[register] jq is required" >&2; exit 1; }

: "${AXIAM_ISSUER:?set AXIAM_ISSUER in conformance/suite.env}"
: "${AXIAM_ADMIN_TOKEN:?set AXIAM_ADMIN_TOKEN (an admin bearer token for the target tenant)}"

CERTS="${CONFORMANCE_CERTS_DIR:-$HERE/certs}"
for f in client-mtls.crt client-self-signed.crt; do
  [ -f "$CERTS/$f" ] || { echo "[register] missing $CERTS/$f — run 'just conformance-certs'" >&2; exit 1; }
done

# The AXIAM admin API is on the same host as the issuer. `-k` because a
# conformance deployment routinely fronts a private CA; the credential is a
# bearer token over a loopback/lab connection, not a production secret path.
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -k -X "$method" "$AXIAM_ISSUER$path"
              -H "Authorization: Bearer $AXIAM_ADMIN_TOKEN"
              -H "Content-Type: application/json")
  [ -n "$body" ] && args+=(-d "$body")
  curl "${args[@]}"
}

SUBJECT_DN=$(openssl x509 -in "$CERTS/client-mtls.crt" -noout -subject -nameopt rfc2253 | sed 's/^subject=//')
THUMBPRINT=$(openssl x509 -in "$CERTS/client-self-signed.crt" -outform der \
  | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# The suite's redirect URI. Fixed by the suite's own BASE_URL, so it is derived
# rather than configured — a mismatch here is the single most common cause of a
# whole plan failing at its first authorization step, and deriving it removes
# the chance to typo it.
REDIRECT="${SUITE_BASE_URL:-https://localhost.emobix.co.uk:8442}/test/a/axiam-fapi2-mtls/callback"
REDIRECT2="${SUITE_BASE_URL:-https://localhost.emobix.co.uk:8442}/test/a/axiam-fapi2-self-signed/callback"

echo "[register] creating the tls_client_auth client"
MTLS_RESP=$(api POST /api/v1/oauth2-clients "$(jq -n \
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
SS_RESP=$(api POST /api/v1/oauth2-clients "$(jq -n \
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

# Rewrite suite.env in place. Only the two CLIENT_*_ID lines are touched, so an
# operator's edits to issuer, tenant or paths survive a re-registration.
python3 - "$HERE/suite.env" "$CLIENT_MTLS_ID" "$CLIENT_SELF_SIGNED_ID" <<'PY'
import re, sys
path, mtls, self_signed = sys.argv[1:4]
src = open(path).read()
src = re.sub(r"^CLIENT_MTLS_ID=.*$", f"CLIENT_MTLS_ID={mtls}", src, flags=re.M)
src = re.sub(r"^CLIENT_SELF_SIGNED_ID=.*$", f"CLIENT_SELF_SIGNED_ID={self_signed}", src, flags=re.M)
open(path, "w").write(src)
PY

echo "[register] suite.env updated. Next: just conformance-run"
