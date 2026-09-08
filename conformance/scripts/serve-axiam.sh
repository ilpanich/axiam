#!/usr/bin/env bash
# serve-axiam.sh — run AXIAM as the system under test for a conformance run (W9).
#
# Why this exists rather than `just run-local`: a conformance run needs three
# things run-local deliberately does not do.
#
#   1. TLS. The suite is an HTTPS client and several modules assert on transport
#      properties. run-local serves plain HTTP on 8090 and sets
#      COOKIE_SECURE=false, which is right for a laptop and wrong here.
#   2. A non-loopback bind. The suite runs in a container and reaches the host
#      through the docker bridge gateway, so a listener on 127.0.0.1 is
#      invisible to it — the failure looks like a connection refused with no
#      AXIAM log line to pair it with.
#   3. An issuer that matches the name the suite dialled. In OIDC the issuer is
#      an identity claim, not a route: it appears in the discovery document and
#      in the `iss` of every ID token, and the suite checks all three agree.
#      Getting this wrong produces a signature-ish error a long way from its
#      cause.
#
# It reuses run-local's secrets directory rather than minting its own, so a
# database seeded by `just bootstrap-local` is still readable here.
#
# Usage: serve-axiam.sh
# Requires: a built binary (cargo build -p axiam-server --no-default-features)
#           and `just conformance-certs` already run.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=conformance/scripts/lib-env.sh
# shellcheck disable=SC1091
. "$SCRIPTS_DIR/lib-env.sh"
conf_load

: "${AXIAM_TLS_PORT:?set AXIAM_TLS_PORT in conformance/suite.env}"
: "${AXIAM_MTLS_PORT:?set AXIAM_MTLS_PORT in conformance/suite.env}"

resolve() { case "$1" in /*) echo "$1" ;; *) echo "$HERE/$1" ;; esac; }
CERT="$(resolve "${AXIAM_SERVER_CERT:-certs/server.crt}")"
KEY="$(resolve "${AXIAM_SERVER_KEY:-certs/server.key}")"
CA="$(resolve "${AXIAM_CA:-certs/ca.crt}")"

for f in "$CERT" "$KEY" "$CA"; do
  [ -f "$f" ] || { echo "[serve] missing $f — run 'just conformance-certs'" >&2; exit 1; }
done

BIN="${AXIAM_BIN:-$ROOT/target/debug/axiam-server}"
[ -x "$BIN" ] || {
  echo "[serve] no binary at $BIN" >&2
  echo "[serve] build it once: cargo build -p axiam-server --no-default-features" >&2
  exit 1
}

# --- the same secrets run-local uses --------------------------------------
SECRETS_DIR="$ROOT/docker/.secrets"
PRIV="$SECRETS_DIR/jwt_ed25519.pem"
PUB="$SECRETS_DIR/jwt_ed25519.pub.pem"
mkdir -p "$SECRETS_DIR"
if [ ! -f "$PRIV" ] || [ ! -f "$PUB" ]; then
  openssl genpkey -algorithm ed25519 -out "$PRIV"
  openssl pkey -in "$PRIV" -pubout -out "$PUB"
  chmod 600 "$PRIV"
fi
AXIAM__AUTH__JWT_PRIVATE_KEY_PEM="$(cat "$PRIV")"
AXIAM__AUTH__JWT_PUBLIC_KEY_PEM="$(cat "$PUB")"
export AXIAM__AUTH__JWT_PRIVATE_KEY_PEM AXIAM__AUTH__JWT_PUBLIC_KEY_PEM

gen_hex_key() {
  local f="$SECRETS_DIR/$1"
  if [ ! -f "$f" ]; then openssl rand -hex 32 > "$f"; chmod 600 "$f"; fi
  cat "$f"
}
AXIAM__AUTH__MFA_ENCRYPTION_KEY="$(gen_hex_key mfa_enc.hex)"
AXIAM__FEDERATION_ENCRYPTION_KEY="$(gen_hex_key federation_enc.hex)"
AXIAM__EMAIL_ENCRYPTION_KEY="$(gen_hex_key email_enc.hex)"
export AXIAM__AUTH__MFA_ENCRYPTION_KEY AXIAM__FEDERATION_ENCRYPTION_KEY AXIAM__EMAIL_ENCRYPTION_KEY

export AXIAM__AMQP__URL="${AXIAM__AMQP__URL:-amqps://axiam:axiam@localhost:5671}"
export AXIAM__AMQP__TLS__CA_CERT_PATH="${AXIAM__AMQP__TLS__CA_CERT_PATH:-$SECRETS_DIR/broker-tls/ca.pem}"

# --- what makes this a conformance target ---------------------------------
export AXIAM__SERVER__HOST="${AXIAM__SERVER__HOST:-0.0.0.0}"
# The BACK channel's port, not the issuer's. AXIAM_TLS_PORT belongs to the
# nginx sidecar (`conformance/nginx-axiam.conf`), which serves the admin SPA so
# that the `/login` hop `/oauth2/authorize` redirects to actually exists — the
# single reason 65 modules finished WAITING/INTERRUPTED in the first run.
#
# This listener stays a DIRECT rustls listener because it must: FAPI 2.0's
# `tls_client_auth` and `self_signed_tls_client_auth` need the peer certificate
# verified in the handshake, and `axiam_oauth2::mtls` refuses a forwarded
# `X-Client-Certificate` header by construction, with no setting to enable it.
# Discovery tells mTLS clients where to find this listener through RFC 8705 §5
# `mtls_endpoint_aliases`, set below.
export AXIAM__SERVER__PORT="$AXIAM_MTLS_PORT"
export AXIAM__SERVER__TLS__ENABLED=true
export AXIAM__SERVER__TLS__CERT_PATH="$CERT"
export AXIAM__SERVER__TLS__KEY_PATH="$KEY"

# `optional`, and this is load-bearing rather than lax. ONE listener serves both
# lanes: the FAPI plans authenticate with a client certificate, and the Basic OP
# plan's clients have none at all. `required` would refuse the Basic clients in
# the handshake — forty failures for a reason that is this line — and `off`
# would leave the FAPI clients with no way to present the credential they are
# registered under. A presented certificate is still verified against the CA
# below; `optional` widens who may connect, not who may authenticate.
export AXIAM__SERVER__TLS__CLIENT_AUTH="${AXIAM__SERVER__TLS__CLIENT_AUTH:-optional}"
export AXIAM__SERVER__TLS__CLIENT_CA_PATH="$CA"

# The issuer the suite will compare against. Must equal AXIAM_ISSUER in
# suite.env; both are derived from AXIAM_TLS_PORT so they cannot drift.
export AXIAM__AUTH__OAUTH2_ISSUER_URL="${AXIAM_ISSUER}"

# RFC 8705 §5. Set to this listener's own base URL, which is what makes the
# split above legible to a client instead of merely true: the discovery document
# gains `mtls_endpoint_aliases` naming the token, userinfo, PAR, introspection,
# revocation and device-authorization endpoints on the mTLS host, while the
# front channel (`authorization_endpoint`, `jwks_uri`, `end_session_endpoint`)
# and the `issuer` itself stay on the origin the browser uses.
#
# Empty collapses the deployment to one listener and omits the member — a valid
# deployment, and one where no mTLS client can authenticate through the proxy.
export AXIAM__AUTH__OAUTH2_MTLS_BASE_URL="${AXIAM_MTLS_BASE_URL:-}"

# The tenant the discovery document describes.
#
# AXIAM's OAuth2 endpoints that authenticate a CLIENT — token, PAR,
# introspection, revocation, device authorization, end-session — take a required
# `tenant_id`, and `/oauth2/authorize` needs one for any request without a
# principal, which is every browser arriving from a relying party. Until the
# document published them, a conformance client that followed it exactly got
# `400 missing field tenant_id` at the token endpoint, and no plan could
# complete a single authorization.
#
# Setting this makes the bare well-known document — the only one a plan can use,
# because its retrieval location must equal `issuer` — publish endpoint URLs
# carrying the tenant. It changes NO endpoint behaviour; a request that arrives
# without the parameter is refused exactly as before.
#
# ORDER OF OPERATIONS. The value comes from suite.local.env, which
# `conformance-register` writes after discovering it from the admin session. So
# the first ever run on a fresh deployment is: register, then RESTART this
# server. The warning below is what tells you which of the two situations you
# are in, rather than leaving you to infer it from a 401 twenty minutes later.
export AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID="${AXIAM_TENANT_ID:-}"
if [ -z "${AXIAM_TENANT_ID:-}" ]; then
  echo "[serve] WARNING: no AXIAM_TENANT_ID — discovery will publish endpoints" >&2
  echo "[serve]          with no tenant, and every authorization will be refused." >&2
  echo "[serve]          Run 'just conformance-register' and restart this." >&2
fi

echo "[serve] issuer    $AXIAM__AUTH__OAUTH2_ISSUER_URL (served by the nginx sidecar)"
echo "[serve] mTLS base $AXIAM__AUTH__OAUTH2_MTLS_BASE_URL"
echo "[serve] tenant    ${AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID:-<none — authorizations will fail>}"
echo "[serve] listener  https://$AXIAM__SERVER__HOST:$AXIAM__SERVER__PORT (client_auth=$AXIAM__SERVER__TLS__CLIENT_AUTH)"
echo "[serve] cert      $CERT"
echo "[serve] client CA $CA"

exec env RUST_LOG="${RUST_LOG:-axiam=debug,info}" "$BIN"
