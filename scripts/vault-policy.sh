#!/usr/bin/env bash
# Write AXIAM's Vault policy from docker/vault/axiam-policy.hcl.
#
# Separate from `vault-seed.sh` because the two need different credentials and
# happen at different times: seeding writes secrets, this writes an ACL rule.
# Both want a privileged token; only this one is safe to re-run against a live
# deployment, and re-running it is the point.
#
# WHY YOU MIGHT BE RUNNING THIS BY HAND: a policy is evaluated per request, not
# baked into the token at issue time. So applying it repairs an ALREADY RUNNING
# server's token in place — no restart, no re-init, no re-seed, no data loss.
# That is the fix for
#
#   vault: .../secret/data/axiam/ca-keys/<org>/<ca> answered 403 Forbidden on
#   write — check the token's policy has create and update on this path
#
# on a stack brought up by a `just prod-up` from 1.0.0-beta09 or earlier, whose
# policy granted read on the deployment secrets and nothing on the CA prefix.
#
# Usage:
#   VAULT_ADDR=https://127.0.0.1:8200 VAULT_TOKEN=<root or a policy-writing
#   token> scripts/vault-policy.sh
#
# Optional:
#   VAULT_POLICY_NAME  policy to write            (default: axiam)
#   VAULT_CACERT       CA bundle for the listener
#   VAULT_SKIP_VERIFY  `true` for the self-signed Compose stack only
set -euo pipefail

POLICY_NAME="${VAULT_POLICY_NAME:-axiam}"
POLICY_FILE="$(dirname "${BASH_SOURCE[0]}")/../docker/vault/axiam-policy.hcl"
: "${VAULT_ADDR:?VAULT_ADDR is required, e.g. https://127.0.0.1:8200}"
: "${VAULT_TOKEN:?VAULT_TOKEN is required (needs update on sys/policies/acl/${POLICY_NAME})}"

if [[ ! -r "$POLICY_FILE" ]]; then
    echo "✗ Policy file not found: $POLICY_FILE" >&2
    exit 1
fi

CURL=(curl --fail --silent --show-error --header "X-Vault-Token: ${VAULT_TOKEN}")
if [[ -n "${VAULT_CACERT:-}" ]]; then
    CURL+=(--cacert "${VAULT_CACERT}")
elif [[ "${VAULT_SKIP_VERIFY:-}" == "true" ]]; then
    # Only for the self-signed Compose stack. Never in production, which is why
    # this is an explicit opt-in rather than a default.
    CURL+=(--insecure)
fi

# The HCL goes through Python rather than a shell heredoc so quoting inside the
# policy — which is full of it — cannot corrupt the JSON envelope.
BODY="$(python3 -c 'import json,sys; print(json.dumps({"policy": open(sys.argv[1], encoding="utf-8").read()}))' "$POLICY_FILE")"

"${CURL[@]}" --request PUT --data "$BODY" \
    "${VAULT_ADDR}/v1/sys/policies/acl/${POLICY_NAME}" >/dev/null

echo "→ Wrote the '${POLICY_NAME}' policy from docker/vault/axiam-policy.hcl"
echo "  Policies are evaluated per request, so every token already carrying"
echo "  '${POLICY_NAME}' has the new capabilities now. Nothing needs restarting."
