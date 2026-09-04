#!/usr/bin/env bash
# gen-certs.sh — generate a throwaway CA + server cert + client cert for the
# TLS / mTLS security profiles. Test-only material; profiles/certs is gitignored.
set -euo pipefail

DIR="${BENCH_CERTS_DIR:-$(dirname "$0")/../profiles/certs}"
mkdir -p "$DIR"
cd "$DIR"

# Reuse existing material only while it is still VALID. This guard used to test
# EXISTENCE alone, and the certs below are minted with `-days 30`, so they
# simply went stale in place: on 2026-09-04 the CA and both leaves minted on
# 2026-08-02 had expired three days earlier, and `bench-up` printed "certs
# already exist in ..." and carried on regardless.
#
# The k6 matrix never notices, for the same reason it never noticed the missing
# CA keyUsage documented below: every scenario passes BENCH_VERIFY_TLS=false
# because it measures TLS cost, not trust. The SDK benches DO verify the chain
# (each trusts this CA via BENCH_CA_CERT), so an expired CA takes the entire
# p2/p3 SDK matrix down at its first HTTPS call with
# "SSL peer certificate ... was not OK" — eleven languages failing identically,
# which reads as eleven broken SDKs rather than one dead CA.
#
# -checkend takes a margin in seconds. Two days is comfortably longer than a
# full matrix pass, so material cannot expire in the MIDDLE of one — the worst
# version of this failure, where early cells are measurements and later ones
# are TLS errors.
CERT_MARGIN_SECS="${BENCH_CERT_MARGIN_SECS:-172800}"
certs_still_valid() {
  local f
  for f in ca.crt server.crt client.crt; do
    [ -f "$f" ] || return 1
    openssl x509 -in "$f" -noout -checkend "$CERT_MARGIN_SECS" >/dev/null 2>&1 || return 1
  done
  # Chain-verify rather than trust three independent expiry checks: a partial
  # regeneration leaves behind leaf certs signed by a CA that is no longer on
  # disk: each file is individually in-date while the chain they form is broken.
  openssl verify -CAfile ca.crt server.crt >/dev/null 2>&1 || return 1
  openssl verify -CAfile ca.crt client.crt >/dev/null 2>&1 || return 1
}
if [ -f ca.crt ] && [ "${1:-}" != "--force" ]; then
  if certs_still_valid; then
    echo "[gen-certs] certs already exist in $DIR and are valid (use --force to regenerate)"
    exit 0
  fi
  echo "[gen-certs] certs in $DIR are expired, expiring within $((CERT_MARGIN_SECS / 86400))d, or no longer a valid chain — regenerating"
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
#
# keyUsage=keyCertSign,cRLSign is REQUIRED, not decoration. `openssl req -x509`
# adds basicConstraints=CA:TRUE on its own but NOT keyUsage, and RFC 5280
# §4.2.1.3 says a CA certificate's keyUsage SHOULD assert keyCertSign. TLS
# stacks that enforce strict X.509 (OpenSSL's X509_V_FLAG_X509_STRICT — on by
# default in Python 3.13+'s ssl module, among others) therefore REJECT a chain
# signed by a CA without it: "CA cert does not include key usage extension".
# The k6 scenarios and seed.sh never noticed because they pass -k / skip server
# verification (BENCH_VERIFY_TLS=false — we measure TLS cost, not trust), but
# the SDK benches DO verify: every one of them trusts this CA via
# BENCH_CA_CERT, so without this line the whole p2/p3 SDK matrix fails at the
# first HTTPS call with an error that reads like an SDK bug.
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 30 \
  -subj "/CN=AXIAM Bench Test CA/O=axiam-benchmark" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Server cert (SAN: localhost) signed by CA
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost/O=axiam-benchmark"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 30 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE")

# Client cert for mTLS signed by CA
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=bench-client/O=axiam-benchmark"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 30 \
  -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE")

rm -f server.csr client.csr
chmod 600 ./*.key
# The server key is mounted into every target's TLS process. AXIAM's distroless
# image runs as non-root UID 65532 and can't read a 0600 key owned by the host
# user (Keycloak/Zitadel happen to run as UID 1000 and can). These are throwaway,
# gitignored, test-only keys, so world-readable is acceptable here.
chmod 644 server.key
echo "[gen-certs] done. CA=$DIR/ca.crt server=$DIR/server.crt client=$DIR/client.crt"
