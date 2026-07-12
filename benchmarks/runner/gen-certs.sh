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

# CA
openssl req -x509 -newkey ed25519 -nodes -keyout ca.key -out ca.crt -days 30 \
  -subj "/CN=AXIAM Bench Test CA/O=axiam-benchmark"

# Server cert (SAN: localhost) signed by CA
openssl req -newkey ed25519 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost/O=axiam-benchmark"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 30 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth")

# Client cert for mTLS signed by CA
openssl req -newkey ed25519 -nodes -keyout client.key -out client.csr \
  -subj "/CN=bench-client/O=axiam-benchmark"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 30 \
  -extfile <(printf "extendedKeyUsage=clientAuth")

rm -f server.csr client.csr
chmod 600 ./*.key
echo "[gen-certs] done. CA=$DIR/ca.crt server=$DIR/server.crt client=$DIR/client.crt"
