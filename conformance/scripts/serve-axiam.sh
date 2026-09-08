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

# shellcheck disable=SC1091
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib-env.sh"
conf_load

: "${AXIAM_TLS_PORT:?set AXIAM_TLS_PORT in conformance/suite.env}"

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
export AXIAM__SERVER__PORT="$AXIAM_TLS_PORT"
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

echo "[serve] issuer   $AXIAM__AUTH__OAUTH2_ISSUER_URL"
echo "[serve] listener  https://$AXIAM__SERVER__HOST:$AXIAM__SERVER__PORT (client_auth=$AXIAM__SERVER__TLS__CLIENT_AUTH)"
echo "[serve] cert      $CERT"
echo "[serve] client CA $CA"

exec env RUST_LOG="${RUST_LOG:-axiam=debug,info}" "$BIN"
