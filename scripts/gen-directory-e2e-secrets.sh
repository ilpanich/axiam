#!/usr/bin/env bash
# Mint everything the directory e2e stack needs, at run time (T23.3.6, G-3).
#
# Nothing here is committed and nothing is a literal: the CA, both servers'
# certificates and every password are generated into docker/.secrets/directory/
# (gitignored, like the broker's). That is deliberate on two counts. A committed
# private key or password in a test fixture is what CodeQL's
# `hardcoded-cryptographic-value` family exists to catch, and a directory e2e
# that trusted a checked-in CA would be a test that proves a bind over a
# certificate anyone can mint.
#
#   ca.pem / ca.key        the throwaway CA the tenant's `trust_anchors_pem` holds
#   openldap.pem/.key      OpenLDAP's server certificate, SAN = its fixed address
#   samba.pem/.key         Samba AD DC's server certificate, SAN = its fixed address
#   env                    KEY=VALUE, read by `docker compose --env-file` AND by
#                          the Rust tests (they never see the shell's environment
#                          for these, so a missing export cannot make them pass)
#
# The two servers have FIXED addresses on a compose network of their own
# (docker-compose.directory.yml). Fixed so the certificates can name them before
# either container starts, and so the tests reach a *private, non-loopback*
# address: the T23.3.7 address guard always refuses loopback, and refuses a
# private range unless AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS lists it — the
# tests set that list, which is exactly what an operator does.
#
# Idempotent: existing material is left alone (rotate by deleting the directory).
set -euo pipefail

OUT_DIR="${DIRECTORY_E2E_DIR:-docker/.secrets/directory}"
DAYS="${DIRECTORY_E2E_CERT_DAYS:-30}"
SUBNET="${DIRECTORY_E2E_SUBNET:-172.28.77.0/24}"
OPENLDAP_IP="${DIRECTORY_E2E_OPENLDAP_IP:-172.28.77.10}"
SAMBA_IP="${DIRECTORY_E2E_SAMBA_IP:-172.28.77.11}"

mkdir -p "$OUT_DIR"

if [[ -f "$OUT_DIR/env" && -f "$OUT_DIR/ca.pem" && -f "$OUT_DIR/openldap.pem" && -f "$OUT_DIR/samba.pem" ]]; then
  echo "-> Directory e2e material already present in $OUT_DIR - leaving it alone."
  echo "   (Delete the directory and re-run to rotate; recreate the containers after.)"
  exit 0
fi

echo "-> Generating a throwaway CA, two server certificates and the e2e passwords in $OUT_DIR"

# --- CA ---------------------------------------------------------------------
# RSA-2048: the one key type every server in the stack (GnuTLS in Debian's slapd,
# GnuTLS in Samba) and rustls agree on without a flag.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT_DIR/ca.key" 2>/dev/null
openssl req -x509 -new -key "$OUT_DIR/ca.key" -sha256 -days "$DAYS" \
  -subj "/CN=AXIAM directory e2e CA/O=AXIAM" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT_DIR/ca.pem" 2>/dev/null

issue() { # name, dns, ip
  local name="$1" dns="$2" ip="$3"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT_DIR/$name.key" 2>/dev/null
  openssl req -new -key "$OUT_DIR/$name.key" -subj "/CN=${dns}/O=AXIAM" \
    -out "$OUT_DIR/$name.csr" 2>/dev/null
  # The SAN is what rustls checks, against the URL's host. The tests connect by
  # address (ldaps://<ip>), so the IP SAN is the one that matters; the DNS name
  # is there for a human running ldapsearch by hand.
  cat > "$OUT_DIR/$name.ext" <<EXT
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${dns}, DNS:localhost, IP:${ip}
EXT
  openssl x509 -req -in "$OUT_DIR/$name.csr" -CA "$OUT_DIR/ca.pem" -CAkey "$OUT_DIR/ca.key" \
    -CAcreateserial -out "$OUT_DIR/$name.pem" -days "$DAYS" -sha256 \
    -extfile "$OUT_DIR/$name.ext" 2>/dev/null
  rm -f "$OUT_DIR/$name.csr" "$OUT_DIR/$name.ext"
}
issue openldap "openldap.example.test" "$OPENLDAP_IP"
issue samba "dc1.example.test" "$SAMBA_IP"
rm -f "$OUT_DIR/ca.srl"

# --- Passwords --------------------------------------------------------------
# Shaped to satisfy Active Directory's default complexity rule (upper, lower,
# digit, >= 7) as well as slapd's, and random per run. Distinct per role, so a
# test can use one role's value as "the wrong password" for another.
pw() { printf '%s%s%s' "$1" "$(openssl rand -hex 14)" "$2"; }
{
  echo "DIRECTORY_E2E_SUBNET=${SUBNET}"
  echo "DIRECTORY_E2E_OPENLDAP_IP=${OPENLDAP_IP}"
  echo "DIRECTORY_E2E_SAMBA_IP=${SAMBA_IP}"
  echo "OPENLDAP_ADMIN_PW=$(pw Ad 1)"
  echo "OPENLDAP_BIND_PW=$(pw Bn 2)"
  echo "OPENLDAP_USER_PW=$(pw Us 3)"
  echo "SAMBA_ADMIN_PW=$(pw Ad 4)"
  echo "SAMBA_BIND_PW=$(pw Bn 5)"
  echo "SAMBA_USER_PW=$(pw Us 6)"
  echo "WRONG_PW=$(pw Wr 7)"
} > "$OUT_DIR/env"

# The servers run as non-root inside their containers (slapd) or read the files
# as root (Samba); the keys must be readable either way. The directory is
# throwaway, gitignored, and holds no key that is valid for anything outside
# this stack (the same posture as scripts/gen-broker-tls.sh).
chmod 644 "$OUT_DIR"/*.pem "$OUT_DIR/openldap.key" "$OUT_DIR/samba.key"
chmod 600 "$OUT_DIR/ca.key" "$OUT_DIR/env"

echo "-> Done: ca.pem openldap.{pem,key} samba.{pem,key} env"
