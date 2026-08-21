#!/usr/bin/env bash
# Mint the private CA and server certificate the Compose Vault listener needs.
#
# Idempotent: existing material is left alone, so bring-your-own certificates
# dropped into docker/.secrets/vault-tls/ survive a `just prod-up`. Delete the
# directory to rotate.
#
# The SAN covers `vault`, `localhost` and `127.0.0.1`, so one set of material
# serves both the Compose network and an operator running `vault` on the host
# through the published port.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker/.secrets/vault-tls"

if [[ -f "$DIR/server.pem" && -f "$DIR/server-key.pem" && -f "$DIR/ca.pem" ]]; then
    echo "→ Vault TLS material already present in $DIR (delete it to rotate)"
    exit 0
fi

echo "→ Generating Vault TLS material in $DIR"
mkdir -p "$DIR"

openssl genpkey -algorithm ed25519 -out "$DIR/ca-key.pem"
openssl req -x509 -new -key "$DIR/ca-key.pem" -sha256 -days 3650 \
    -subj "/CN=AXIAM Vault Dev CA" -out "$DIR/ca.pem"

# RSA rather than Ed25519 for the leaf: Vault's TLS listener is fine with
# either, but some client tooling in the wild still is not, and this material
# exists to be convenient.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DIR/server-key.pem"
openssl req -new -key "$DIR/server-key.pem" -subj "/CN=vault" -out "$DIR/server.csr"

cat > "$DIR/server.ext" <<EXT
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:vault, DNS:localhost, IP:127.0.0.1
EXT

openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca-key.pem" \
    -CAcreateserial -out "$DIR/server.pem" -days 825 -sha256 -extfile "$DIR/server.ext"

rm -f "$DIR/server.csr" "$DIR/server.ext"
chmod 600 "$DIR"/*-key.pem
# Vault runs as uid 100 in the official image, the bind mount carries the host
# uid through unchanged, and a 0600 file owned by the host user is unreadable
# to it — the listener then dies with "error loading TLS cert: permission
# denied" and the container restart-loops. The server key is therefore 0644,
# the same trade gen-broker-tls.sh makes for the broker key. The CA key stays
# 0600: it is what rotates the rest and no container ever reads it.
chmod 644 "$DIR/server.pem" "$DIR/ca.pem" "$DIR/server-key.pem"

echo "→ Done. CA: $DIR/ca.pem"
