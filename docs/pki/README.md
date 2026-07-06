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
- CA signing private keys are the one exception that IS persisted, and they
  are encrypted at rest with **AES-256-GCM** (the `AXIAM__PKI__ENCRYPTION_KEY`
  secret — see the [deployment guide's required-secrets table](../deployment/README.md#required-secrets--environment)).
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
