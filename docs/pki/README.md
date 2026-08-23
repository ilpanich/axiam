# AXIAM PKI / Certificate Guide

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Last verified:** 2026-07-06

Task-oriented walkthrough of the certificate lifecycle: issuing an
organization CA certificate, issuing leaf certificates for users, services,
or IoT devices, binding a certificate for mTLS authentication, and
revocation. See also: [Admin Guide](../admin/README.md),
[Deployment Guide](../deployment/README.md), [API docs](../api/README.md).

## Security model

- Certificates are X.509, generated with either **RSA-4096** or **Ed25519**
  keys (`key_algorithm`).
- **Private keys are returned exactly once**, in the response body of the
  generate call, and are **never stored server-side**. Save the
  `private_key_pem` field immediately — it cannot be retrieved again; if
  lost, revoke the certificate and issue a new one.
- CA signing private keys are the one exception that IS persisted. Where they
  are kept is a per-CA decision — see [CA key custody](#ca-key-custody) below.
- Every leaf certificate is issued under an organization CA certificate
  (`issuer_ca_id`) and inherits its trust chain.

## Issue an organization CA certificate

CA certificates are organization-scoped and are the trust root every leaf
certificate in that organization chains to.

```
POST /api/v1/organizations/{org_id}/ca-certificates
{
  "subject": "CN=Acme Corp Root CA",
  "key_algorithm": "Ed25519",
  "validity_days": 3650
}
```

Response (`201`) is a `GeneratedCaCertificate`: the stored CA certificate
metadata plus `private_key_pem` — the CA's signing private key, returned
only this once. Store it in your secrets manager immediately (or, in a
Kubernetes deployment, seed it into `AXIAM__PKI__ENCRYPTION_KEY`-protected
storage per your operational process) — AXIAM itself never persists the
plaintext key.

## Import a CA you already have (BYOK)

Generation makes a key AXIAM chose. Import takes one your organization already
has — from an offline root, an existing internal PKI, or an HSM ceremony — and
puts AXIAM in the chain rather than at the top of it. Without it, every
AXIAM-issued certificate chains to a root nothing else in your estate trusts.

```
POST /api/v1/organizations/{org_id}/ca-certificates/import
{
  "public_cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
}
```

Note what the body does **not** contain: subject, validity window, key
algorithm. All three are read out of the certificate. A request that could name
them separately could name a subject the certificate does not have, and AXIAM
would enforce the claim while every relying party read the certificate.

The certificate is refused unless it is genuinely usable as a CA:

| Refusal | Why |
| --- | --- |
| Not a PEM-encoded X.509 certificate | Nothing to import. |
| Basic Constraints does not say `CA:TRUE` | A leaf imported as a CA appears in the issuing-CA list and everything it signs is rejected by anything that checks the chain. |
| Already expired | Leaf validity is capped to the CA's, so it could never issue anything. |
| Public key algorithm is neither Ed25519 nor RSA | AXIAM cannot sign with it. |
| The supplied key does not match the certificate | Storing the pair would produce a CA that lists as issuable and dies at the first signature. |

`private_key_pem` is **optional**, and the two cases are genuinely different:

- **With a key**, AXIAM takes custody of it (see below) and can issue against
  the CA.
- **Without one**, the certificate is registered as a trust anchor and nothing
  more. It records custody `external`, and `/api/v1/certificates` refuses to
  issue against it with a message saying so — rather than failing at the point
  of use with an error about a missing key.

Importing needs `ca_certificates:generate`, the same permission as generating:
from every relying party's point of view the two are the same act, because both
decide what this organization's certificates chain to.

RSA CAs arrive this way only. rcgen's `ring` backend cannot *generate* RSA keys,
so `POST .../ca-certificates` with `Rsa4096` fails — while an RSA root from an
existing PKI is exactly what this endpoint is for.

## CA key custody

Every CA record says who holds its signing key, in a `key_custody` field with
three values:

| Custody | Where the key is | How it gets there |
| --- | --- | --- |
| `database` | AES-256-GCM ciphertext in the CA record, under `pki_encryption_key` | The default, and what every AXIAM deployment had before this was configurable |
| `vault` | A HashiCorp Vault KV v2 secret; the record holds only a path | `AXIAM__PKI__VAULT_ADDR` + `AXIAM__PKI__VAULT_TOKEN` configured |
| `external` | Nowhere in AXIAM | An import with no `private_key_pem` |

**It is recorded per CA, not read from configuration**, and that is the point.
A deployment that adopts Vault does not thereby move the CAs it already has:
those records still say `database`, their keys are still sealed into them, and
the signing path asks the record rather than the environment. Switching custody
is a decision about *new* CAs.

### Why Vault rather than the database

Database custody is a real control with a bounded reach, and it is worth being
plain about the bound: the key and the thing that opens it are in the same blast
radius. Whoever holds a database dump *and* one process's `pki_encryption_key`
holds every CA in the deployment, and nothing anywhere records that they read
it.

A key in Vault is a different proposition. Access is a policy that can be scoped
and revoked, every read is audited by something that is not AXIAM, and a
database dump on its own is inert.

### Configuring Vault custody

```sh
AXIAM__PKI__VAULT_ADDR=https://vault.internal:8200
AXIAM__PKI__VAULT_TOKEN=<token with create/read/delete on the prefix>
AXIAM__PKI__VAULT_MOUNT=secret            # optional, Vault's own default
AXIAM__PKI__VAULT_PREFIX=axiam/ca-keys    # optional
AXIAM__PKI__VAULT_CA_CERT_PATH=/etc/ssl/vault-ca.pem   # see below
AXIAM__PKI__CA_KEY_STORE=vault            # optional; implied by the two above
```

An address and a token with no explicit `CA_KEY_STORE` means `vault` — an
operator who wired up both did so in order to use it, and a third variable whose
only outcome is being forgotten is not a safety feature. Setting
`CA_KEY_STORE=vault` *without* them is a **startup failure**, not a fallback: an
operator who asked for Vault and silently got the database would have exactly
the property they were trying to stop having.

`VAULT_CA_CERT_PATH` is required whenever Vault's listener certificate comes
from an internal PKI. reqwest is built with `rustls-tls`, whose roots are
compiled in, so there is no `SSL_CERT_FILE` to fall back on and the handshake
simply fails. An unreadable file is a startup failure rather than a silent
fallback to the built-in roots.

Each CA gets its **own** secret at `<mount>/data/<prefix>/<org_id>/<ca_id>`,
with the PEM in a single `private_key_pem` field — one per CA rather than one
secret with a field per CA, because Vault policy paths are the unit of access
control. A policy that grants read on one organization's CAs and not another's
is a path glob; it could not be written at all if every key shared one secret.

A minimal policy:

```hcl
path "secret/data/axiam/ca-keys/*" {
  capabilities = ["create", "read", "update"]
}
path "secret/metadata/axiam/ca-keys/*" {
  capabilities = ["delete"]
}
```

Revocation deletes the Vault *metadata* path, not the data path: a KV v2 delete
on the data path soft-deletes the latest version and leaves it readable by
version number, which for a CA signing key is not deletion. A failure to reach
Vault during revocation is logged and does not block the revocation — the record
is the truth of what exists, and AXIAM will not sign with a revoked CA whatever
the custodian still holds. What is left behind is an orphaned secret: a cleanup
task, not a security failure.

### What Vault custody is not, yet

The key still reaches AXIAM's memory to sign with. Vault holds it and audits
access; it does not perform the signature. The stronger property — a key that
never leaves the custodian — needs certificate *issuance* to move there too,
which means Vault's PKI secrets engine (or a KMS) doing the signing rather than
storing the key. The `CaKeyStore` port is deliberately addressed by key
*reference* rather than by key, so an implementation that answers a sign call
without ever answering a load one slots in beside these rather than replacing
them. That, and an external KMS, are the next steps.

Nothing about the wire changes when that happens: `key_custody` gains a value
and CAs created before it keep working.

## Issue a leaf certificate

Leaf certificates are tenant-scoped and are issued for a user, a service, or
an IoT device — set `cert_type` accordingly:

```
POST /api/v1/certificates
{
  "issuer_ca_id": "<ca-certificate-uuid>",
  "subject": "CN=jdoe@example.com",
  "cert_type": "User",
  "key_algorithm": "Ed25519",
  "validity_days": 365,
  "metadata": {}
}
```

`cert_type` is one of `User` (authenticate a human user), `Service`
(authenticate a service/service-account), or `Device` (authenticate an IoT
device). Response (`201`) is a `GeneratedCertificate`: the stored
certificate metadata plus `private_key_pem`, again returned only once. A
tenant may cap `validity_days` via its `max_certificate_validity_days`
metadata setting; requests exceeding that cap are rejected.

## Bind a certificate for mTLS (service accounts)

For a `Service`-type certificate that authenticates a service account over
mTLS, bind the issued certificate to the service account explicitly:

```
POST /api/v1/service-accounts/{sa_id}/bind-certificate
{ "certificate_id": "<certificate-uuid>" }
```

This links the certificate to the service account record so the service
account's authorization context is resolved correctly once the certificate
authenticates.

**IoT device (`Device`-type) certificates do not use this bind step.**
Instead, when a device presents its client certificate over mTLS, AXIAM's
device-auth service (`axiam-pki::mtls::DeviceAuthService`) computes the
certificate's SHA-256 fingerprint, looks it up directly (a `Device`
certificate is globally addressable by fingerprint), checks it is `Active`
and unexpired, and cryptographically verifies the full chain up to the
issuing organization's CA certificate before accepting the connection. If no
active CA certificate for that organization exists, the check fails
closed — a fingerprint match alone is never sufficient to authenticate a
device.

## Revoke a certificate

Revoking a CA certificate:

```
POST /api/v1/organizations/{org_id}/ca-certificates/{id}/revoke
```

Revoking a leaf (user/service/device) certificate:

```
POST /api/v1/certificates/{id}/revoke
```

Revoke a leaf certificate immediately if its private key may have been
exposed, if the user/service/device it authenticates is decommissioned, or
as part of routine credential rotation. Revoke a CA certificate only when
retiring that CA entirely — every leaf certificate it issued becomes
untrusted once its issuing CA is revoked, so plan a migration to a new CA
(issue the new CA, re-issue leaf certificates under it, then revoke the old
CA) rather than revoking a CA that still has active leaf certificates
depending on it.
