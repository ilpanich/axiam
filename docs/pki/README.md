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
| `vault_pki` | Inside Vault's **PKI secrets engine**, and nowhere else — AXIAM never holds it | `AXIAM__PKI__CA_KEY_STORE=vault_pki` |
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

### Moving a CA you already have into Vault

Because custody is recorded **per CA**, configuring Vault does not move the CAs
that already exist — their keys stay sealed in their rows, and the signing path
keeps reading the record rather than the environment. That is what lets adoption
be non-disruptive, and it is also why adopting Vault alone does not get your
existing keys out of the database.

Move one explicitly:

```
POST /api/v1/organizations/{org_id}/ca-certificates/{id}/migrate-custody
```

or press **Move to Vault** beside the CA's *Key* column in the admin UI. Both
require `ca_certificates:manage`.

The response names both ends of the move:

```json
{
  "ca_certificate_id": "…",
  "previous_custody": "database",
  "key_custody": "vault",
  "key_locator": "axiam/ca-keys/<org_id>/<ca_id>"
}
```

**Effective immediately — no restart.** The row is the authority on where a key
lives and the signing path reads it per request.

The order is copy, record, then release: the key is loaded from the custodian
the row names, handed to the configured one, and only then is the row updated
and the old copy deleted. A failure before the record is written leaves the CA
exactly as it was and issuance is unaffected; a failure of the final delete
leaves an orphaned secret behind, which is a cleanup task and the same trade-off
revocation already makes. The row's own ciphertext is cleared in the same
statement that records the new custodian — a key in Vault *and* still sealed in
its row has not been moved, it has been duplicated.

Three cases are refused rather than silently doing nothing:

- the CA is already under the configured custodian;
- the CA is `external` — AXIAM holds no key for it, so there is nothing to move;
- the CA is under `vault_pki`, which never hands its key over. That is the
  stronger property, and migrating out of it would weaken the CA.

### What KV custody is not

Under `vault` custody the key still reaches AXIAM's memory to sign with. Vault
holds it and audits access; it does not perform the signature. That is custody,
and it is a real improvement on a database column — but it is not the strongest
thing available.

`vault_pki` is. Read on.

## Custody in Vault's PKI engine (`vault_pki`)

Vault's PKI secrets engine generates the key inside itself, exposes no API that
exports it, and signs on AXIAM's behalf. The private key of a CA under this
custodian has **never existed in the AXIAM process**. A compromise of AXIAM —
a memory dump, a malicious build, an operator with a shell — yields
certificates that Vault's audit log records, and no key.

The arrangement follows [HashiCorp's own PKI walkthrough][pki-tutorial]
literally:

1. `POST <root_mount>/root/generate/internal` — a root whose key stays in Vault.
   `internal` rather than `exported` is what makes that true.
2. `POST <int_mount>/intermediate/generate/internal` — a second key, also kept,
   and a CSR.
3. `POST <root_mount>/issuer/<root>/sign-intermediate` — the root signs it, with
   `max_path_length=0` so the intermediate can sign leaves and nothing else.
4. `POST <int_mount>/intermediate/set-signed` — the signed certificate goes back
   to the mount holding its key, which is now an issuer.
5. `POST <int_mount>/issuer/<int>/sign-verbatim` — every leaf, thereafter.

[pki-tutorial]: https://developer.hashicorp.com/vault/tutorials/pki/pki-engine

The two tiers are not ceremony. A root that signs exactly one intermediate and
nothing else can have that intermediate revoked and replaced without
redistributing the trust anchor, which is the one PKI operation that is
otherwise impossible to perform quietly. Pass `issue_from_root: true` to skip
the intermediate; the default does not, and the default is the safer one.

### Both ways in: generate, or bring your own

| | What happens | What AXIAM keeps |
| --- | --- | --- |
| `POST .../ca-certificates` | Vault generates the root and the intermediate | The certificates. No key, and `private_key_pem` is **absent** from the response |
| `POST .../ca-certificates/import` with `private_key_pem` | The key and certificate go to Vault as one bundle (`issuers/import/bundle`) | The certificate. The key is not stored here |

On the import path the supplied key does pass through AXIAM's memory on its way
to Vault — it has to, because AXIAM is what received the HTTP request. What the
operator gets is that AXIAM never *stores* it and every later use of it is
Vault's.

### What the response looks like

A generated `vault_pki` CA answers with **no** `private_key_pem`, because there
is none, and with `chain_pem` holding the root's certificate. Keep it: Vault
returns a generated root's certificate exactly once, and without it nothing
outside Vault can validate a chain to an AXIAM-issued leaf. Leaf issuance
returns `chain_pem` too, for the same reason.

RSA-4096 CAs can be *generated* under this custodian and no other: Vault
generates RSA keys and rcgen's `ring` backend does not.

### Configuring PKI custody

```sh
AXIAM__PKI__VAULT_ADDR=https://vault.internal:8200   # shared with KV custody
AXIAM__PKI__VAULT_TOKEN=<token with the policy below>
AXIAM__PKI__VAULT_CA_CERT_PATH=/etc/ssl/vault-ca.pem # as for KV custody
AXIAM__PKI__VAULT_PKI_ROOT_MOUNT=pki                 # optional, Vault's own convention
AXIAM__PKI__VAULT_PKI_INT_MOUNT=pki_int              # optional
AXIAM__PKI__CA_KEY_STORE=vault_pki                   # required — not implied
```

The address and token are the same two variables KV custody uses: one Vault
should not be configured twice. `CA_KEY_STORE=vault_pki` is required rather than
implied, because an address and a token alone still mean `vault` — moving where
new CAs' keys are *generated* is not something an upgrade should do on its own.

Both mounts are enabled by the operator, not by AXIAM, and shared by every CA.
Enabling a mount per CA would need `sys/mounts` write, a permission that can
rewrite the whole Vault; sharing two mounts and addressing issuers by the id
Vault minted keeps the token's policy to the PKI paths themselves. Vault has
supported multiple issuers per mount since 1.11.

```sh
vault secrets enable -path=pki pki
vault secrets tune -max-lease-ttl=87600h pki
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int
```

**Tune the mounts.** A PKI mount's `max_lease_ttl` defaults to 30 days, and
Vault silently caps a longer request to it rather than failing — a ten-year root
becomes a month-long one. AXIAM records what came back rather than what it asked
for, so the record stays truthful, and logs Vault's warning at `WARN`. Neither
is a substitute for tuning the mount.

A minimal policy:

```hcl
path "pki/root/generate/internal"        { capabilities = ["update"] }
path "pki/issuer/+/sign-intermediate"    { capabilities = ["update"] }
path "pki/issuer/+"                      { capabilities = ["delete"] }
path "pki/key/+"                         { capabilities = ["delete"] }

path "pki_int/intermediate/generate/internal" { capabilities = ["update"] }
path "pki_int/intermediate/set-signed"        { capabilities = ["update"] }
path "pki_int/issuers/import/bundle"          { capabilities = ["update"] }
path "pki_int/issuer/+/sign-verbatim"         { capabilities = ["update"] }
path "pki_int/issuer/+"                       { capabilities = ["delete"] }
path "pki_int/key/+"                          { capabilities = ["delete"] }
```

`sign-verbatim` takes the CSR's subject and extensions as given, because AXIAM
has already decided what the certificate says — subject, validity, algorithm,
and the tenant policy behind them. A Vault role would restate a subset of those
rules in a second place and the two would drift. The cost is real and worth
naming: the policy on that path is what stands between a compromised AXIAM and a
certificate for any name at all. An operator who wants Vault to enforce names as
well can add a role against the same issuer; what they cannot do is have
neither.

Revocation deletes the issuer and then the key, at both tiers — in that order,
because Vault refuses to delete a key an issuer still references.

### What `vault_pki` does not remove

The subscriber's key. Leaf keys are still generated by AXIAM and returned once,
exactly as under every other custodian; what moved to Vault is the *signature*.
A CSR carries the public half and nothing else.

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
certificate metadata plus `private_key_pem`, again returned only once — and,
when the issuing CA is under `vault_pki` custody, `chain_pem` holding the chain
the signer returned. A tenant may cap `validity_days` via its
`max_certificate_validity_days` metadata setting; requests exceeding that cap
are rejected.

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

## Turn on mutual TLS using a CA AXIAM generated

Binding a certificate (above) tells AXIAM which principal a certificate
belongs to. It does not tell the **TLS listener** to ask for one. That is a
separate switch, and this section is about setting it without hand-copying
certificates onto the server.

### The two settings, and why they used to be manual

The rustls listener verifies client certificates when two environment
variables are set:

| Variable | Meaning |
|---|---|
| `AXIAM__SERVER__TLS__CLIENT_AUTH` | `off` (default), `optional`, or `required` |
| `AXIAM__SERVER__TLS__CLIENT_CA_PATH` | PEM bundle of the CAs client certificates may chain to |

Setting them by hand means getting a copy of your organization CA's
certificate onto the server volume yourself, keeping it in step with the CA
you actually issue from, and remembering to replace it when you rotate — for
a CA that AXIAM generated, holds, and already shows you on a page.

### Flagging a CA instead

Mark an organization CA as an mTLS trust anchor, from the organization's
**Certificates** tab (the *Trust for mTLS* action) or over the API:

```
PUT /api/v1/organizations/{org_id}/ca-certificates/{id}/mtls-trust-anchor
{ "enabled": true }
```

Requires `ca_certificates:manage` — its own permission, because deciding what
the deployment accepts as a client identity is a broader act than issuing
under a CA.

At the **next server start**, AXIAM then:

1. collects every flagged CA that is `Active` and unexpired, across all
   organizations (there is one TLS listener per process, presenting one trust
   store);
2. writes their **public** certificates as a single PEM bundle to
   `AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH` — defaulting to
   `client-ca-bundle.pem` beside `AXIAM__SERVER__TLS__CERT_PATH`;
3. sets `CLIENT_AUTH=optional` and points `CLIENT_CA_PATH` at that bundle.

`optional`, never `required`: a server that suddenly refuses every client
without a certificate would lock every browser out of the admin UI the moment
you flag a CA — including yours. `optional` verifies a certificate when one is
offered and leaves password and passkey logins working, which is what an IoT
deployment actually wants: devices authenticate by certificate, people do not.

### Your own settings always win

If you have set `CLIENT_AUTH` or `CLIENT_CA_PATH` yourself, AXIAM fills in only
what you left unset and logs what it did. A `required` you configured is never
relaxed to `optional`, and a bundle you curated is never replaced with one
assembled from database rows.

### The private key never leaves its custodian

Only `public_cert_pem` is written to the volume. The CA's signing key stays
wherever its custodian put it — in Vault, under your own policy (see
[CA key custody](#ca-key-custody)) — and is never copied to disk.

Nothing is weakened by the copy. A trust anchor is public by construction: it
is what the server hands every client during the handshake, and every device
that validates an AXIAM-issued chain already holds it.

### Why a restart

rustls builds its `RootCertStore` once, when the listener is constructed, and
actix-web binds that config for the life of the process. There is no supported
way to add a root to a server that is already serving, so flagging a CA changes
what the *next* boot trusts. The API says so — `restart_required` is always
`true` in the response — rather than letting the toggle imply otherwise.

### Full walkthrough

```bash
# 1. Generate the organization CA in the admin UI, or:
curl -X POST https://axiam.example.com/api/v1/organizations/$ORG/ca-certificates \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"subject":"CN=Acme Root CA","key_algorithm":"Ed25519","validity_days":3650}'
# With Vault custody configured, the signing key is created in Vault and the
# response carries no private_key_pem. That is the intended shape.

# 2. Flag it as an mTLS trust anchor.
curl -X PUT \
  https://axiam.example.com/api/v1/organizations/$ORG/ca-certificates/$CA/mtls-trust-anchor \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true}'
# → {"restart_required":true, "message":"This CA will be added to the mTLS
#    client trust store when the server next starts. …"}

# 3. Make sure the bundle has somewhere to go. Skip if CERT_PATH is set —
#    the bundle defaults to that directory.
export AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH=/etc/axiam/tls/client-ca-bundle.pem

# 4. Restart. The startup log names the bundle and the resulting mode:
#    "mTLS client trust store built from flagged organization CAs"
#      anchors=1 bundle=/etc/axiam/tls/client-ca-bundle.pem client_auth=Optional

# 5. Issue a Device certificate under that CA and hand it to the device
#    (see "Issue a leaf certificate" above). It now authenticates by mTLS.
```

If flagged CAs exist but no bundle path can be derived, startup logs a warning
and leaves client authentication **off** — a permissive failure, not a hole,
since `optional` admits nobody it would otherwise have refused. It never
refuses to boot: the flag is set at runtime through the API, and failing
startup would let one admin request brick the next restart.

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
