#!/usr/bin/env bash
# Seed AXIAM's secrets into a running Vault.
#
# Idempotent in the way that matters: a key already present is left alone. That
# is not politeness — regenerating `opaque_setup_key` would make every OPAQUE
# registration record in every tenant unopenable, requiring a password reset for
# every user. Only missing keys are minted.
#
# Usage:
#   VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=... scripts/vault-seed.sh
#
# Optional:
#   VAULT_MOUNT   KV v2 mount point         (default: secret)
#   VAULT_PATH    path within the mount     (default: axiam)
#   VAULT_CACERT  CA bundle for the listener
set -euo pipefail

MOUNT="${VAULT_MOUNT:-secret}"
SECRET_PATH="${VAULT_PATH:-axiam}"
: "${VAULT_ADDR:?VAULT_ADDR is required}"
: "${VAULT_TOKEN:?VAULT_TOKEN is required}"

CURL=(curl --fail --silent --show-error --header "X-Vault-Token: ${VAULT_TOKEN}")
if [[ -n "${VAULT_CACERT:-}" ]]; then
    CURL+=(--cacert "${VAULT_CACERT}")
elif [[ "${VAULT_SKIP_VERIFY:-}" == "true" ]]; then
    # Only for the self-signed Compose stack. Never in production, which is why
    # this is an explicit opt-in rather than a default.
    CURL+=(--insecure)
fi

# Enable KV v2 at the mount if it is not already there. A 400 means "already
# enabled", which is success for our purposes.
if ! "${CURL[@]}" "${VAULT_ADDR}/v1/sys/mounts/${MOUNT}" >/dev/null 2>&1; then
    echo "→ Enabling KV v2 at ${MOUNT}/"
    "${CURL[@]}" --request POST \
        --data '{"type":"kv","options":{"version":"2"}}' \
        "${VAULT_ADDR}/v1/sys/mounts/${MOUNT}" >/dev/null 2>&1 || true
fi

# Read what is already there, so existing values survive.
EXISTING="$("${CURL[@]}" "${VAULT_ADDR}/v1/${MOUNT}/data/${SECRET_PATH}" 2>/dev/null || echo '{}')"

# The payload decision — which secrets to keep and which to mint — lives in
# `vault_seed_payload.py` so it can be unit-tested. This script does the I/O.
PAYLOAD="$(JWT_PRIVATE_KEY_PEM="${JWT_PRIVATE_KEY_PEM:-}" \
           JWT_PUBLIC_KEY_PEM="${JWT_PUBLIC_KEY_PEM:-}" \
           python3 "$(dirname "${BASH_SOURCE[0]}")/vault_seed_payload.py" "$EXISTING")"

"${CURL[@]}" --request POST --data "${PAYLOAD}" \
    "${VAULT_ADDR}/v1/${MOUNT}/data/${SECRET_PATH}" >/dev/null

echo "→ Seeded ${MOUNT}/${SECRET_PATH}"
