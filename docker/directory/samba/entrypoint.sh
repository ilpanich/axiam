#!/bin/sh
# Provision and start the e2e Samba Active Directory domain controller
# (T23.3.6). Mounted into the pinned instantlinux/samba-dc image and run INSTEAD
# of that image's own entrypoint (which is driven by Docker secrets and a jinja
# template; see docker-compose.directory.yml). Runs as root, as a DC must
# (it binds 389/636 and writes security.NTACL extended attributes).
#
# Required environment (compose passes it; nothing here is a literal):
#   E2E_ADMIN_PW   Administrator's password
#   E2E_BIND_PW    the read-only service account's (reader)
#   E2E_USER_PW    every seeded person's
# Required mounts: /tls-src with ca.pem, server.pem, server.key.
set -eu

: "${E2E_ADMIN_PW:?}" "${E2E_BIND_PW:?}" "${E2E_USER_PW:?}"

REALM=EXAMPLE.TEST
DOMAIN=EXAMPLE

rm -f /etc/samba/smb.conf /etc/krb5.conf
samba-tool domain provision \
  --server-role=dc --use-rfc2307 \
  --domain="$DOMAIN" --realm="$REALM" \
  --adminpass="$E2E_ADMIN_PW" \
  --option="posix:eadb = /var/lib/samba/private/eadb.tdb" --dns-backend=NONE >/tmp/provision.log 2>&1 || { cat /tmp/provision.log; exit 1; }

# The directory's own TLS: the CA the tests mint, and a TLS 1.2 floor (a GnuTLS
# priority string; this Samba has no `tls min protocol`). Without these Samba
# would generate a self-signed certificate of its own, which no tenant anchor
# could name. DNS is not provisioned, so its self-update service is switched off
# rather than left to fail in the log.
TLS=/var/lib/samba/private/tls
mkdir -p "$TLS"
cp /tls-src/ca.pem "$TLS/ca.pem"
cp /tls-src/server.pem "$TLS/cert.pem"
cp /tls-src/server.key "$TLS/key.pem"
chmod 600 "$TLS/key.pem"
cat > /etc/samba/e2e-global.conf <<CONF
tls enabled = yes
tls cafile = $TLS/ca.pem
tls certfile = $TLS/cert.pem
tls keyfile = $TLS/key.pem
tls priority = NORMAL:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1
CONF
awk '{ print } /^\[global\]/ { print "\tinclude = /etc/samba/e2e-global.conf" }' /etc/samba/smb.conf > /tmp/smb.conf
sed -e 's/, dnsupdate$//' /tmp/smb.conf > /etc/samba/smb.conf

# Seed through the local sam.ldb (no network, no password to type for the admin).
# sAMAccountName is the login name (CN follows it).
user() { # name given surname mail
  samba-tool user create "$1" "$E2E_USER_PW" \
    --given-name="$2" --surname="$3" --mail-address="$4" >/dev/null
}
samba-tool user create reader "$E2E_BIND_PW" >/dev/null
user alice Alice Example alice@example.test
user bob Bob Example bob@example.test
user adminuser Admin User adminuser@example.test
user 'odd(name)' Odd Name odd@example.test
user dave Dave Disabled dave@example.test
# Disabled the AD way: userAccountControl bit 0x2.
samba-tool user disable dave >/dev/null

# staff: alice directly; devs (and so bob) by NESTING.
samba-tool group add staff >/dev/null
samba-tool group add devs >/dev/null
samba-tool group add admins >/dev/null
samba-tool group addmembers staff alice,devs >/dev/null
samba-tool group addmembers devs bob >/dev/null
# A group nobody mapped: it must grant nothing.
samba-tool group addmembers admins alice >/dev/null

touch /tmp/ready
# Foreground, one process (a test directory, not a performance one).
exec samba -i -M single
