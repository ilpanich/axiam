#!/usr/bin/env bash
# Back up the three things that cannot be rebuilt.
#
#   1. The VAULT RAFT SNAPSHOT. Losing Vault loses `opaque_setup_key`, which
#      means a password reset for every user in every tenant. Raft snapshots are
#      consistent and can be taken while Vault runs — one of the reasons these
#      manifests do not use the `file` backend.
#   2. The SURREALDB DATA. Every user, role, resource, certificate and audit
#      record.
#   3. The OPENTOFU STATE. It holds the datastore password, the broker password
#      and the server's Vault token. It is a secret; see D5 in
#      claude_dev/rpi5-k3s-opentofu-plan.md and §6 of the operator guide.
#
# WHAT THIS DOES NOT BACK UP, ON PURPOSE: your unseal shares. They are not on
# this machine, which is the point of the ceremony. A backup of the sealed data
# plus the shares in the same place is not a backup, it is a copy of the keys.
#
# THE ARCHIVE IS A SECRET. It is written mode 0600 into a directory this script
# creates mode 0700. Copy it OFF THE PI — a backup on the disk you are backing
# up survives exactly the failures you were not worried about.
#
# Usage:
#   ./04-backup.sh                          # -> ~/axiam-backups/axiam-<date>.tar.gz
#   ./04-backup.sh --out /mnt/usb           # somewhere else
#   ./04-backup.sh --rsync user@host:path/  # and push it off the device
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

NS="${AXIAM_NAMESPACE:-axiam}"
OUT_DIR="${HOME}/axiam-backups"
STATE_DIR="${AXIAM_TOFU_STATE_DIR:-${HOME}/axiam-infra/state}"
RSYNC_TARGET=""

while (( $# )); do
    case "$1" in
        --out) OUT_DIR="${2:?--out needs a directory}"; shift 2 ;;
        --rsync) RSYNC_TARGET="${2:?--rsync needs a target}"; shift 2 ;;
        -h | --help) sed -n '2,28p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

need kubectl
STAMP="$(date +%F-%H%M)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT_DIR"; chmod 700 "$OUT_DIR"

# ---------------------------------------------------------------------------
# 1. Vault Raft snapshot
# ---------------------------------------------------------------------------
# Needs a token with `read` on `sys/storage/raft/snapshot`, which the `axiam`
# policy deliberately does NOT grant — the server's token is read-only on one
# path. Issue a short-lived one for this, or use the root token if you have not
# revoked it yet (you should have).
if [[ -n "${VAULT_TOKEN:-}" ]]; then
    say "Taking a Vault Raft snapshot"
    if kubectl -n "$NS" exec vault-0 -- \
        env VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/vault/tls/ca.crt \
            VAULT_TOKEN="$VAULT_TOKEN" \
        vault operator raft snapshot save /tmp/vault.snap >/dev/null 2>&1
    then
        kubectl -n "$NS" cp "${NS}/vault-0:/tmp/vault.snap" "$WORK/vault.snap" >/dev/null 2>&1
        kubectl -n "$NS" exec vault-0 -- rm -f /tmp/vault.snap >/dev/null 2>&1 || true
        ok "Vault snapshot: $(stat -c%s "$WORK/vault.snap" 2>/dev/null || echo 0) bytes"
    else
        warn "Snapshot failed. The commonest cause is scope: the 'axiam' policy
  grants read on one KV path and nothing on sys/. Issue a short-lived token with
  a policy that permits 'read' on 'sys/storage/raft/snapshot', use it here, and
  revoke it. Continuing WITHOUT a Vault snapshot."
    fi
else
    warn "VAULT_TOKEN is not set, so no Vault snapshot was taken. This backup
  therefore does NOT protect the OPAQUE setup key, and restoring from it means a
  password reset for every user in every tenant. Take one:
      read -rs VAULT_TOKEN && export VAULT_TOKEN
      ./04-backup.sh
      unset VAULT_TOKEN"
fi

# ---------------------------------------------------------------------------
# 2. SurrealDB
# ---------------------------------------------------------------------------
# `surreal export` through the running server, rather than copying the surrealkv
# directory out from under a live process. The pod's own credentials are used —
# they are already in its environment, so nothing new is exposed.
say "Exporting SurrealDB"
if kubectl -n "$NS" exec surrealdb-0 -- sh -c '
      /surreal export --endpoint http://127.0.0.1:8000 \
        --username "$SURREALDB_USER" --password "$SURREALDB_PASS" \
        --namespace axiam --database axiam /tmp/axiam.surql' >/dev/null 2>&1
then
    kubectl -n "$NS" cp "${NS}/surrealdb-0:/tmp/axiam.surql" "$WORK/axiam.surql" >/dev/null 2>&1
    kubectl -n "$NS" exec surrealdb-0 -- rm -f /tmp/axiam.surql >/dev/null 2>&1 || true
    ok "SurrealDB export: $(stat -c%s "$WORK/axiam.surql" 2>/dev/null || echo 0) bytes"
else
    warn "surreal export failed. Check \`kubectl -n $NS exec surrealdb-0 -- /surreal
  export --help\` against the image you are running: the flag names have changed
  between majors, and this is the kind of thing to discover during a backup and
  not during a restore. Continuing WITHOUT a datastore export."
fi

# ---------------------------------------------------------------------------
# 3. OpenTofu state
# ---------------------------------------------------------------------------
if [[ -d "$STATE_DIR" ]]; then
    say "Copying OpenTofu state from $STATE_DIR"
    mkdir -p "$WORK/tofu-state"
    cp -a "$STATE_DIR/." "$WORK/tofu-state/"
    ok "State copied. It is ENCRYPTED only if you configured the encryption
  passphrase (encryption.tofu); it holds the datastore password, the broker
  password and the server's Vault token either way."
else
    warn "No OpenTofu state at $STATE_DIR. Set AXIAM_TOFU_STATE_DIR if it lives
  elsewhere — a backup without it cannot reproduce the credentials, and those
  credentials are honoured only on the FIRST boot of an empty volume, so they
  cannot simply be re-minted."
fi

# ---------------------------------------------------------------------------
# 4. What was running, so a restore knows what to restore into
# ---------------------------------------------------------------------------
kubectl -n "$NS" get deploy,statefulset -o jsonpath='{range .items[*]}{.kind}/{.metadata.name}{"\t"}{.spec.template.spec.containers[*].image}{"\n"}{end}' \
    > "$WORK/images.txt" 2>/dev/null || true
kubectl -n "$NS" get pvc -o wide > "$WORK/pvcs.txt" 2>/dev/null || true
{
    echo "AXIAM backup taken $(date -Is)"
    echo "node: $(uname -srm)"
    echo "k3s:  $(k3s --version 2>/dev/null | head -1 || echo unknown)"
} > "$WORK/MANIFEST.txt"

# ---------------------------------------------------------------------------
# 5. One archive, 0600
# ---------------------------------------------------------------------------
ARCHIVE="${OUT_DIR}/axiam-${STAMP}.tar.gz"
tar -czf "$ARCHIVE" -C "$WORK" .
chmod 600 "$ARCHIVE"
ok "Wrote $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

if [[ -n "$RSYNC_TARGET" ]]; then
    need rsync
    say "Pushing to $RSYNC_TARGET"
    rsync -a --chmod=F600 "$ARCHIVE" "$RSYNC_TARGET"
    ok "Copied off the device."
else
    warn "STILL ON THE PI. A backup on the disk you are backing up protects you
  from the failures you were not worried about. Re-run with
  --rsync user@host:backups/, or copy it by hand, now rather than later."
fi
