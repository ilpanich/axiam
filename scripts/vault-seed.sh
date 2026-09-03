#!/usr/bin/env bash
# Seed AXIAM's secrets into a running Vault.
#
# Idempotent in the way that matters: a key already present is left alone. That
# is not politeness — regenerating `opaque_setup_key` would make every OPAQUE
# registration record in every tenant unopenable, requiring a password reset for
# every user. Only missing keys are minted.
#
# That guarantee is only as good as the READ it rests on, which is why this
# script never turns a failed request into "the Vault is empty". It waits for
# Vault to be *active* (not merely listening, not merely unsealed), it hands the
# read's HTTP status to `vault_seed_payload.py` rather than its body alone, and
# it writes with KV v2's `cas` so the write is pinned to the version that was
# read. A sealed Vault, a standby node, a revoked token or a TLS failure now
# stops the seeder instead of rotating every key under a live datastore.
#
# Usage:
#   VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=... scripts/vault-seed.sh
#
# Optional:
#   VAULT_MOUNT          KV v2 mount point         (default: secret)
#   VAULT_PATH           path within the mount     (default: axiam)
#   VAULT_CACERT         CA bundle for the listener
#   VAULT_READY_TIMEOUT  seconds to wait for an active node (default: 60)
set -euo pipefail

MOUNT="${VAULT_MOUNT:-secret}"
SECRET_PATH="${VAULT_PATH:-axiam}"
READY_TIMEOUT="${VAULT_READY_TIMEOUT:-60}"
: "${VAULT_ADDR:?VAULT_ADDR is required}"
: "${VAULT_TOKEN:?VAULT_TOKEN is required}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# TLS options, shared by the token-carrying calls and the token-free health
# probe. An array rather than a string so a CA path containing a space is a path
# containing a space and not two arguments.
TLS_OPTS=()
if [[ -n "${VAULT_CACERT:-}" ]]; then
    TLS_OPTS+=(--cacert "${VAULT_CACERT}")
elif [[ "${VAULT_SKIP_VERIFY:-}" == "true" ]]; then
    # Only for the self-signed Compose stack. Never in production, which is why
    # this is an explicit opt-in rather than a default.
    TLS_OPTS+=(--insecure)
fi

CURL=(curl --silent --show-error "${TLS_OPTS[@]}" --header "X-Vault-Token: ${VAULT_TOKEN}")

# The body of the last `vault_request`. A file rather than a second return
# value: a Vault error body may span lines, and `read` would silently truncate
# it — which is the class of bug this whole script is being hardened against.
BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT

# Run a request; echo the HTTP status and leave the body in $BODY_FILE.
# A transport failure — connection refused, a TLS trust error — yields `000`,
# which every caller treats as "no answer" rather than as a negative answer.
vault_request() {
    local method="$1" url="$2"
    local args=("${CURL[@]}" --request "$method" --output "$BODY_FILE" --write-out '%{http_code}')
    if [[ $# -ge 3 ]]; then
        args+=(--data "$3")
    fi
    : > "$BODY_FILE"
    local status
    status="$("${args[@]}" "$url" 2>/dev/null || true)"
    [[ "$status" =~ ^[0-9]{3}$ ]] || status="000"
    printf '%s\n' "$status"
}

# ---------------------------------------------------------------------------
# 1. Wait for an ACTIVE node
# ---------------------------------------------------------------------------
#
# `sys/health` distinguishes the states that matter and needs no token: 200 is
# initialised, unsealed and active; 429 is unsealed but standby; 501 is
# uninitialised; 503 is sealed. Only 200 can serve a write.
#
# This wait is the difference between a correct seeder and a destructive one.
# Vault with Raft storage returns from `sys/unseal` while the node is still a
# standby contending for leadership, and every request in that window is
# refused. `just prod-up` unseals and seeds back to back, so without this the
# read below lands in that window on every restart-driven run.
echo "→ Waiting for an active Vault at ${VAULT_ADDR} (up to ${READY_TIMEOUT}s)"
health_status="000"
deadline=$((SECONDS + READY_TIMEOUT))
while ((SECONDS < deadline)); do
    health_status="$(curl --silent --show-error "${TLS_OPTS[@]}" \
        --output /dev/null --write-out '%{http_code}' \
        "${VAULT_ADDR}/v1/sys/health" 2>/dev/null || true)"
    if [[ "$health_status" == "200" ]]; then
        break
    fi
    sleep 1
done
if [[ "$health_status" != "200" ]]; then
    case "$health_status" in
        429) reason="unsealed but standby — no node has taken leadership" ;;
        501) reason="not initialised" ;;
        503) reason="sealed" ;;
        000) reason="no answer — check VAULT_ADDR and the CA bundle" ;;
        *) reason="answered HTTP ${health_status}" ;;
    esac
    echo "✗ Vault is not ready to serve a write: ${reason}." >&2
    echo "  Nothing has been written. Seeding a Vault that cannot answer a read" >&2
    echo "  is how every key gets regenerated under a live datastore." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Make sure the KV v2 mount exists
# ---------------------------------------------------------------------------
#
# Only acted on when Vault answers positively that the mount is absent. A 403
# means the seeding token cannot read `sys/mounts` — legitimate for a narrowly
# scoped credential — so the mount is left alone and the read below decides.
mount_status="$(vault_request GET "${VAULT_ADDR}/v1/sys/mounts/${MOUNT}")"
case "$mount_status" in
    200) ;;
    400 | 404)
        echo "→ Enabling KV v2 at ${MOUNT}/"
        enable_status="$(vault_request POST "${VAULT_ADDR}/v1/sys/mounts/${MOUNT}" \
            '{"type":"kv","options":{"version":"2"}}')"
        # 400 here is "path is already in use", which is success for our
        # purposes — something else got there first.
        case "$enable_status" in
            200 | 204 | 400) ;;
            *)
                echo "✗ Could not enable KV v2 at ${MOUNT}/: HTTP ${enable_status}" >&2
                cat "$BODY_FILE" >&2
                exit 1
                ;;
        esac
        ;;
    403)
        echo "→ The token cannot read sys/mounts/${MOUNT}; assuming the mount exists"
        ;;
    *)
        echo "✗ Could not determine whether ${MOUNT}/ is mounted: HTTP ${mount_status}" >&2
        cat "$BODY_FILE" >&2
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# 3. Read what is already there — and refuse to guess
# ---------------------------------------------------------------------------
read_status="$(vault_request GET "${VAULT_ADDR}/v1/${MOUNT}/data/${SECRET_PATH}")"
read_body="$(cat "$BODY_FILE")"

# The payload decision — which secrets to keep, which to mint, and which version
# the write is pinned to — lives in `vault_seed_payload.py` so it can be
# unit-tested. This script does the I/O. A status other than 200 or 404 makes
# the builder exit non-zero, and `set -e` stops here with nothing written.
PAYLOAD="$(JWT_PRIVATE_KEY_PEM="${JWT_PRIVATE_KEY_PEM:-}" \
           JWT_PUBLIC_KEY_PEM="${JWT_PUBLIC_KEY_PEM:-}" \
           python3 "${HERE}/vault_seed_payload.py" \
               --http-status "$read_status" "$read_body")"

# ---------------------------------------------------------------------------
# 4. Write, pinned to the version that was read
# ---------------------------------------------------------------------------
write_status="$(vault_request POST "${VAULT_ADDR}/v1/${MOUNT}/data/${SECRET_PATH}" "$PAYLOAD")"
case "$write_status" in
    200 | 204) ;;
    *)
        echo "✗ Writing ${MOUNT}/${SECRET_PATH} failed: HTTP ${write_status}" >&2
        cat "$BODY_FILE" >&2
        if [[ "$write_status" == "400" ]] && grep -q "check-and-set" "$BODY_FILE"; then
            echo "  The secret changed between this seeder's read and its write." >&2
            echo "  Nothing was overwritten. Re-run it." >&2
        fi
        exit 1
        ;;
esac

echo "→ Seeded ${MOUNT}/${SECRET_PATH}"
