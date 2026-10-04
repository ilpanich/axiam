#!/bin/sh
# Start the e2e OpenLDAP (T23.3.6). Mounted into the pinned osixia/openldap image
# and run INSTEAD of that image's own bootstrap (see docker-compose.directory.yml
# for why the image is used only as a pinned slapd). Runs as the unprivileged
# `openldap` user (911); everything it writes is under /tmp/e2e.
#
# Required environment (compose passes it; nothing here is a literal):
#   E2E_ADMIN_PW   the directory manager's password (cn=admin,dc=example,dc=test)
#   E2E_BIND_PW    the read-only service account's (cn=reader,...)
#   E2E_USER_PW    every seeded person's
# Required mounts: /tls-src with ca.pem, server.pem, server.key; /e2e (this dir).
set -eu

: "${E2E_ADMIN_PW:?}" "${E2E_BIND_PW:?}" "${E2E_USER_PW:?}"

W=/tmp/e2e
hash() { slappasswd -s "$1"; }
fill() { # template, output
  sed -e "s|@LDAPI_UID@|$(id -u)|g" \
      -e "s|@LDAPI_GID@|$(id -g)|g" \
      -e "s|@ADMIN_HASH@|$(hash "$E2E_ADMIN_PW")|g" \
      -e "s|@READER_HASH@|$(hash "$E2E_BIND_PW")|g" \
      -e "s|@USER_HASH@|$(hash "$E2E_USER_PW")|g" \
      "$1" > "$2"
}

mkdir -p "$W/tls" "$W/db" "$W/run" "$W/slapd.d"
cp /tls-src/ca.pem "$W/tls/ca.pem"
cp /tls-src/server.pem "$W/tls/server.pem"
cp /tls-src/server.key "$W/tls/server.key"
chmod 600 "$W/tls/server.key"

umask 077
fill /e2e/config.ldif.tmpl "$W/config.ldif"
fill /e2e/data.ldif.tmpl "$W/data.ldif"

slapadd -n 0 -F "$W/slapd.d" -l "$W/config.ldif"
slapadd -n 1 -F "$W/slapd.d" -l "$W/data.ldif"
# The LDIFs held password hashes; they have done their job.
rm -f "$W/config.ldif" "$W/data.ldif"

# `-d stats` keeps slapd in the foreground and logs to stderr (docker logs).
exec slapd -F "$W/slapd.d" -h "ldapi://%2Ftmp%2Fe2e%2Frun%2Fldapi ldap:/// ldaps:///" -d stats
