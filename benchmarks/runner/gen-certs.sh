#!/usr/bin/env bash
# gen-certs.sh — generate a throwaway CA + server cert + client cert for the
# TLS / mTLS security profiles. Test-only material; profiles/certs is gitignored.
set -euo pipefail

DIR="${BENCH_CERTS_DIR:-$(dirname "$0")/../profiles/certs}"
mkdir -p "$DIR"
cd "$DIR"

if [ -f ca.crt ] && [ "${1:-}" != "--force" ]; then
  echo "[gen-certs] certs already exist in $DIR (use --force to regenerate)"
  exit 0
fi

echo "[gen-certs] generating test CA + server + client certs in $DIR"

# Key algorithm: RSA-2048. Ed25519 is rejected by Keycloak/Zitadel, which
# terminate TLS in-process on Java (Quarkus/Vert.x) and Go respectively —
# Vert.x throws "Unsupported algorithm identifier" on an Ed25519 server key.
# AXIAM fronts TLS with nginx (which accepts Ed25519), but the benchmark shares
# ONE cert across all targets, so it must use a key type every stack supports.
# RSA-2048 is the universal choice (nginx, Java, Go, k6); using the same cert
# everywhere keeps the head-to-head TLS-handshake cost comparable.

# CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 30 \
  -subj "/CN=AXIAM Bench Test CA/O=axiam-benchmark"

# Server cert (SAN: localhost) signed by CA
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost/O=axiam-benchmark"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 30 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth")

# Client cert for mTLS signed by CA
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=bench-client/O=axiam-benchmark"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 30 \
  -extfile <(printf "extendedKeyUsage=clientAuth")

rm -f server.csr client.csr
chmod 600 ./*.key
echo "[gen-certs] done. CA=$DIR/ca.crt server=$DIR/server.crt client=$DIR/client.crt"
