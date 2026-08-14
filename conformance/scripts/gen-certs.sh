#!/usr/bin/env bash
# gen-certs.sh — throwaway client certificates for the two FAPI 2.0 client-auth
# variants (X5.2).
#
# Deliberately a separate script from `benchmarks/runner/gen-certs.sh` rather
# than a reuse of it. That one makes ONE client certificate for a load
# generator; this one makes TWO with different trust stories, and the difference
# is the point of the exercise:
#
#   client-mtls        — issued by a CA, for `tls_client_auth`. AXIAM matches
#                        the registered subject DN / SAN against it, and the
#                        deployment's listener must trust the issuing CA.
#   client-self-signed — chains to nothing, for `self_signed_tls_client_auth`.
#                        The certificate IS the credential; AXIAM matches its
#                        x5t#S256 thumbprint.
#
# NOTHING here is fit for production. These keys are written unencrypted to a
# gitignored directory so a conformance run is one command.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${CONFORMANCE_CERTS_DIR:-$HERE/certs}"
DAYS="${CONFORMANCE_CERT_DAYS:-30}"

mkdir -p "$DIR"
cd "$DIR"

echo "[conformance/gen-certs] writing throwaway client certs to $DIR"

# --- a CA, for the tls_client_auth variant --------------------------------
if [ ! -f ca.key ]; then
  openssl genrsa -out ca.key 4096 2>/dev/null
  openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.crt \
    -subj "/CN=AXIAM Conformance Test CA/O=axiam-conformance" 2>/dev/null
  echo "[conformance/gen-certs] created CA"
fi

# --- client 1: PKI mTLS ---------------------------------------------------
if [ ! -f client-mtls.key ]; then
  openssl req -newkey rsa:2048 -nodes -keyout client-mtls.key -out client-mtls.csr \
    -subj "/CN=axiam-conformance-mtls/O=axiam-conformance" 2>/dev/null
  openssl x509 -req -in client-mtls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client-mtls.crt -days "$DAYS" \
    -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:axiam-conformance-mtls") 2>/dev/null
  rm -f client-mtls.csr
  echo "[conformance/gen-certs] created client-mtls (CA-issued)"
fi

# --- client 2: self-signed ------------------------------------------------
if [ ! -f client-self-signed.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout client-self-signed.key -out client-self-signed.crt -days "$DAYS" \
    -subj "/CN=axiam-conformance-self-signed/O=axiam-conformance" \
    -addext "extendedKeyUsage=clientAuth" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "subjectAltName=DNS:axiam-conformance-self-signed" 2>/dev/null
  echo "[conformance/gen-certs] created client-self-signed"
fi

chmod 600 ./*.key

# The values an operator needs in order to register the two clients. Printed
# rather than written into suite.env by this script, because
# `conformance-register` is what fills suite.env in and having two writers of
# one file is how they disagree.
echo
echo "[conformance/gen-certs] registration values:"
echo
echo "  tls_client_auth (client-mtls)"
echo "    tls_client_auth_subject_dn: $(openssl x509 -in client-mtls.crt -noout -subject -nameopt rfc2253 | sed 's/^subject=//')"
echo "    tls_client_auth_san_dns:    axiam-conformance-mtls"
echo
echo "  self_signed_tls_client_auth (client-self-signed)"
echo "    x5t#S256 thumbprint:        $(openssl x509 -in client-self-signed.crt -outform der \
  | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
echo
echo "  The deployment's mTLS listener must trust $DIR/ca.crt for the first client."
echo "  Run 'just conformance-register' to create both clients and fill in suite.env."
