#!/bin/sh
# Change the running e2e domain controller the way a directory administrator
# would, so a test can make an entry vanish or be disabled (T23.3.6). Local
# administrator through the DC's own sam.ldb: nothing reaches the network.
#
#   e2e-mutate.sh add-user <name>      a person with the seeded password
#   e2e-mutate.sh disable-user <name>  userAccountControl bit 0x2
#   e2e-mutate.sh delete-user <name>
set -eu

action="${1:?action}"
name="${2:?name}"
case "$name" in
  *[!a-z0-9-]*|'') echo "refusing a name outside [a-z0-9-]" >&2; exit 64 ;;
esac

case "$action" in
  add-user)
    : "${E2E_USER_PW:?}"
    samba-tool user create "$name" "$E2E_USER_PW" \
      --given-name="$name" --surname=Test --mail-address="${name}@example.test"
    ;;
  disable-user) samba-tool user disable "$name" ;;
  delete-user) samba-tool user delete "$name" ;;
  *) echo "unknown action" >&2; exit 64 ;;
esac
