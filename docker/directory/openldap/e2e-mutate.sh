#!/bin/sh
# Change the running e2e directory the way a directory administrator would, so a
# test can make an entry vanish or be disabled (T23.3.6). Local administrator
# over ldapi: no password is typed or passed, and nothing reaches the network.
#
#   e2e-mutate.sh add-user <name>      a person with the seeded password
#   e2e-mutate.sh disable-user <name>  ppolicy's permanent lock (D-31)
#   e2e-mutate.sh delete-user <name>
set -eu

action="${1:?action}"
name="${2:?name}"
case "$name" in
  *[!a-z0-9-]*|'') echo "refusing a name outside [a-z0-9-]" >&2; exit 64 ;;
esac
dn="uid=${name},ou=people,dc=example,dc=test"

case "$action" in
  add-user)
    : "${E2E_USER_PW:?}"
    ldapadd -Q -Y EXTERNAL -H ldapi://%2Ftmp%2Fe2e%2Frun%2Fldapi <<LDIF
dn: ${dn}
objectClass: inetOrgPerson
uid: ${name}
cn: ${name}
sn: Test
displayName: ${name} Test
mail: ${name}@example.test
userPassword: $(slappasswd -s "$E2E_USER_PW")
LDIF
    ;;
  disable-user)
    ldapmodify -Q -Y EXTERNAL -H ldapi://%2Ftmp%2Fe2e%2Frun%2Fldapi <<LDIF
dn: ${dn}
changetype: modify
replace: pwdAccountLockedTime
pwdAccountLockedTime: 000001010000Z
LDIF
    ;;
  delete-user)
    ldapdelete -Q -Y EXTERNAL -H ldapi://%2Ftmp%2Fe2e%2Frun%2Fldapi "$dn"
    ;;
  *) echo "unknown action" >&2; exit 64 ;;
esac
