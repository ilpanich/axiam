#!/usr/bin/env bash
# Generate a private CA and a broker server certificate for RabbitMQ's AMQPS
# listener (A6).
#
# The prod compose stack talks to the broker over `amqps://…:5671`, which needs
# a certificate the server trusts. There is deliberately no verification-skip
# option in AXIAM's AMQP client (see `AmqpTlsConfig`), so *something* has to
# issue that certificate. This script is the batteries-included answer for a
# self-hosted stack.
#
# Two other paths are equally supported and neither needs this script:
#
#   1. **Bring your own certificate.** Drop `ca.pem`, `server.pem` and
#      `server.key` into docker/.secrets/broker-tls/ from your own PKI (Let's
#      Encrypt, an internal CA, cert-manager) and the compose stack picks them
#      up unchanged.
#   2. **Use AXIAM's own CA.** `axiam-pki` issues X.509 certificates from an
#      organization CA, and a broker certificate is an ordinary server
#      certificate. Issuing the broker's cert from the same CA that signs your
#      device and service certificates is good dogfooding and gives you one
#      trust root to rotate instead of two.
#
# Idempotent: existing files are left alone, so re-running before `just prod-up`
# is safe and will not silently rotate a cert out from under a running broker.
set -euo pipefail

OUT_DIR="${BROKER_TLS_DIR:-docker/.secrets/broker-tls}"
# The compose service name is what the server connects to, so it is what must
# appear in the certificate's SAN. A hostname mismatch is a hard failure — that
# is the point of verifying.
BROKER_HOST="${BROKER_HOST:-rabbitmq}"
DAYS="${BROKER_CERT_DAYS:-825}"

mkdir -p "$OUT_DIR"

if [[ -f "$OUT_DIR/server.pem" && -f "$OUT_DIR/server.key" && -f "$OUT_DIR/ca.pem" ]]; then
  echo "→ Broker TLS material already present in $OUT_DIR — leaving it alone."
  echo "  (Delete the directory and re-run to rotate.)"
  exit 0
fi

echo "→ Generating a private CA and broker certificate in $OUT_DIR"
echo "  broker hostname (SAN): $BROKER_HOST"

# --- CA -------------------------------------------------------------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out "$OUT_DIR/ca.key" 2>/dev/null
openssl req -x509 -new -key "$OUT_DIR/ca.key" -sha256 -days "$DAYS" \
  -subj "/CN=AXIAM Broker CA/O=AXIAM" \
  -out "$OUT_DIR/ca.pem" 2>/dev/null

# --- Broker server certificate -------------------------------------------
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out "$OUT_DIR/server.key" 2>/dev/null
openssl req -new -key "$OUT_DIR/server.key" \
  -subj "/CN=${BROKER_HOST}/O=AXIAM" \
  -out "$OUT_DIR/server.csr" 2>/dev/null

# SAN is mandatory: modern TLS stacks ignore CN entirely, so a certificate
# without a matching SAN fails verification no matter what CN says.
cat > "$OUT_DIR/server.ext" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${BROKER_HOST}, DNS:localhost, IP:127.0.0.1
EOF

openssl x509 -req -in "$OUT_DIR/server.csr" \
  -CA "$OUT_DIR/ca.pem" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -out "$OUT_DIR/server.pem" -days "$DAYS" -sha256 \
  -extfile "$OUT_DIR/server.ext" 2>/dev/null

rm -f "$OUT_DIR/server.csr" "$OUT_DIR/server.ext" "$OUT_DIR/ca.srl"

# The broker runs as a non-root user inside its container and must be able to
# read its own key; the CA key must not travel anywhere.
chmod 644 "$OUT_DIR/ca.pem" "$OUT_DIR/server.pem"
chmod 644 "$OUT_DIR/server.key"
chmod 600 "$OUT_DIR/ca.key"

echo "→ Done."
echo "   ca.pem      trust anchor (mounted read-only into both containers)"
echo "   server.pem  broker certificate, SAN=${BROKER_HOST}"
echo "   server.key  broker private key"
echo "   ca.key      CA private key — keep it, it is what rotates the above"
echo ""
echo "Rotation: delete $OUT_DIR and re-run, then restart both containers."
echo "Certificates expire in ${DAYS} days."
