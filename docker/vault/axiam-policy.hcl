# The Vault policy `axiam-server` runs with.
#
# ONE source of truth. `scripts/vault-policy.sh` writes this file to Vault,
# `just prod-up` calls that script, and docs/deployment/vault.md §5.4 quotes it
# — so the local stack and the documented production ceremony cannot drift, and
# neither can drift from what the server actually needs.
#
# The shape is "read-only on the deployment secrets, plus writes confined to the
# CA-key prefix". Both halves are load-bearing, and the second half is the one
# that was missing until 1.0.0-beta09: a token with only the first half boots
# fine, serves every request, and then answers the first CA generation with
#
#   vault: .../secret/data/axiam/ca-keys/<org>/<ca> answered 403 Forbidden on
#   write — check the token's policy has create and update on this path
#
# because CA key custody inherits AXIAM__AUTH__VAULT_ADDR / _TOKEN when no
# AXIAM__PKI__VAULT_* pair is set, which is the intended single-Vault
# arrangement. See docs/pki/README.md#ca-key-custody.

# ---------------------------------------------------------------------------
# The deployment's fixed startup secrets. READ ONLY.
# ---------------------------------------------------------------------------
#
# The server reads this path once at boot and never writes it. A token that
# could also write turns a leak into a way to REPLACE the JWT signing key
# rather than merely to read it, so the capability stays off even though the
# same token writes elsewhere below.
#
# Exact paths, no glob: `secret/data/axiam` and `secret/data/axiam/*` are
# different rules in Vault, and the second does not match the first.
path "secret/data/axiam" {
  capabilities = ["read"]
}

path "secret/metadata/axiam" {
  capabilities = ["read"]
}

# ---------------------------------------------------------------------------
# CA signing keys. CREATED AT RUNTIME, one secret per CA.
# ---------------------------------------------------------------------------
#
# Nothing here is known at deployment time, so nothing is seeded: AXIAM writes
# each key itself at `secret/data/axiam/ca-keys/<org_id>/<ca_id>` when a CA is
# generated, reads it back to sign with, and deletes it on revocation.
#
# BOTH TIERS, under this one glob. A tenant signing CA is a `ca_certificate`
# row like any other — it just carries a `tenant_id` and a `parent_ca_id` — and
# `CaKeyStore::store` is keyed by `(organization_id, ca_id)` with no tenant
# segment at all. So an organization root and every tenant intermediate beneath
# it land side by side under `<org_id>/`, and one rule covers them.
#
# That is deliberate, and the alternative was considered: a `<org>/<tenant>/`
# layout would let a policy grant one tenant's CAs and not another's. It would
# also mean a CA whose Vault path depends on a column that is NULL for an
# organization CA, and a locator that could not be rebuilt from the id alone.
# Per-tenant scoping is available where it belongs instead — a deployment that
# wants it sets `AXIAM__PKI__VAULT_PREFIX` per tenant and gives each its own
# token.
#
# Both `create` and `update`, and not because the write is sloppy: it refuses
# to overwrite (`cas: 0`). Vault's KV v2 engine asks for `create` on a path that
# has never held a version and `update` on one that has, and a CA id that is
# re-created after a revocation deleted its metadata takes the first branch on
# some versions and the second on others. Granting one of the two produces a
# 403 that appears only sometimes, which is the worst kind.
path "secret/data/axiam/ca-keys/*" {
  capabilities = ["create", "read", "update"]
}

# Revocation deletes the *metadata* path, not the data path. A KV v2 delete on
# the data path soft-deletes the latest version and leaves it readable by
# version number, which for a CA signing key is not deletion.
path "secret/metadata/axiam/ca-keys/*" {
  capabilities = ["delete"]
}

# ---------------------------------------------------------------------------
# WHAT THIS POLICY DOES NOT COVER
# ---------------------------------------------------------------------------
#
# `AXIAM__PKI__CA_KEY_STORE=vault_pki` — the custodian where Vault's own PKI
# engine generates the key and it never leaves. It touches the `pki/` and
# `pki_int/` mounts, not KV, so none of the rules above reach it and adopting it
# fails the same way this policy was written to stop: cleanly at boot, then a
# 403 on the first CA. Its policy is a different set of paths and is documented
# in docs/pki/README.md; add it here, or give that custodian its own token via
# `AXIAM__PKI__VAULT_TOKEN`.
#
# Leaf certificates — user, service and device — need nothing here. Their
# private keys are returned once at issuance and never stored, by AXIAM or by
# Vault; `CertService` only ever *loads* a CA key to sign with.
#
# The seeding credential. `scripts/vault-seed.sh` needs `create`/`update` on
# `secret/data/axiam`, which this policy deliberately withholds. It is a
# separate, short-lived token — see docs/deployment/vault.md §5.4.
