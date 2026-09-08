#!/usr/bin/env bash
# gen-certs.sh — throwaway certificates for a conformance run (X5.2).
#
# Deliberately a separate script from `benchmarks/runner/gen-certs.sh` rather
# than a reuse of it. That one makes ONE client certificate for a load
# generator; this one makes THREE with different trust stories, and the
# difference is the point of the exercise:
#
#   client-mtls        — issued by a CA, for `tls_client_auth`. AXIAM matches
#                        the registered subject DN / SAN against it, and the
#                        deployment's listener must trust the issuing CA.
#   client-self-signed — chains to nothing, for `self_signed_tls_client_auth`.
#                        The certificate IS the credential; AXIAM matches its
#                        x5t#S256 thumbprint.
#   server             — AXIAM's OWN listener certificate (W9). The suite dials
#                        the issuer over HTTPS and a browser completes the
#                        interactive modules against it, so the deployment under
#                        test needs a TLS identity whose SAN covers the name the
#                        suite uses. Added in W9 because the first actual run
#                        found this missing: every module failed in the TLS
#                        handshake before AXIAM logged anything, which reads as
#                        forty failures and is one.
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

# The docker bridge gateway address, which is what `host.docker.internal`
# resolves to inside the suite's container on Linux. Discovered rather than
# assumed: 172.17.0.1 is only docker's default, and a host with a conflicting
# route or a custom bridge gets a different one.
GATEWAY_IP="${CONFORMANCE_GATEWAY_IP:-$(docker network inspect bridge \
  --format '{{ (index .IPAM.Config 0).Gateway }}' 2>/dev/null || true)}"
GATEWAY_IP="${GATEWAY_IP:-172.17.0.1}"

# --- AXIAM's own listener certificate (W9) --------------------------------
#
# The SAN list is the whole substance of this block. The suite reaches AXIAM by
# the name in AXIAM_ISSUER, which on Linux is `host.docker.internal` (mapped to
# the docker bridge gateway by the compose file's extra_hosts); a human
# finishing an interactive module reaches the same server as `localhost`. Both
# names must be in the certificate or one of the two audiences breaks, and
# which one broke is not obvious from the error either audience reports.
if [ ! -f server.key ]; then
  openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -subj "/CN=host.docker.internal/O=axiam-conformance" 2>/dev/null
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days "$DAYS" \
    -extfile <(printf "extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:host.docker.internal,DNS:localhost,DNS:localhost.emobix.co.uk,IP:127.0.0.1,IP:$GATEWAY_IP") 2>/dev/null
  rm -f server.csr
  echo "[conformance/gen-certs] created server cert (SAN: host.docker.internal, localhost, 127.0.0.1, $GATEWAY_IP)"
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
echo "  AXIAM's listener (W9)"
echo "    cert: $DIR/server.crt   key: $DIR/server.key"
echo "    SANs: host.docker.internal, localhost, localhost.emobix.co.uk, 127.0.0.1, $GATEWAY_IP"
echo
echo "  The deployment's mTLS listener must trust $DIR/ca.crt for the first client."
echo "  Run 'just conformance-register' to create both clients and fill in suite.env."
