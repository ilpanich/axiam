# Suspending a tenant

**Since:** the 2026-11 security-audit release (SA-13). Before it, a tenant's
`Suspended` status was stored and shown but not enforced; it is now a real
stop. The normative route-by-route rules live in
[Organization scope](organization-scope.md#suspending-a-tenant); this page is
the operator's view of the same feature.

## When to use it

Use it to take a tenant offline without losing its data: an unpaid account, a
compromise under investigation, a customer on hold. If the tenant should be
gone for good, delete it instead (after
[exporting its audit trail](README.md#deleting-a-tenant-export-its-audit-trail-first)).

## How

An organization principal sets the status:

```http
PUT /api/v1/organizations/{org_id}/tenants/{tenant_id}
{ "status": "Suspended" }
```

`{ "status": "Active" }` lifts it. The admin console's tenant page sends the
same request.

**A tenant that was already `Suspended` before the upgrade** keeps its sessions
and refresh tokens: the revocation runs only inside the status write, and no
migration performs it. Before upgrading, set the organization's own tenant back
to `Active` if it is suspended (it cannot be suspended any more, and while it is
the organization's principals are refused). Once the upgrade is complete
(no replica of the previous release is still serving), send
`{ "status": "Suspended" }` again for every tenant that should stay suspended;
that write runs the revocation, and an old replica's does not (it also still
mints sessions for a suspended tenant, so a re-suspend sent mid-rollout can
leave sessions that return when the suspension is lifted). See the
[upgrade notes](../deployment/README.md#sa-13--tenant-suspension-is-enforced).

## What stops

Everything that authenticates or authorizes one of the tenant's own principals
answers `tenant_suspended`:

- password, MFA, WebAuthn, OPAQUE, federated and device (mTLS) sign-in;
- the token endpoint for every grant, refresh, and token exchange;
- REST requests, gRPC calls, AMQP authorization requests, and SCIM
  provisioning tokens (a suspended tenant's SCIM token is a plain `401`).

REST answers `403`, the OAuth2 token endpoint `400`, gRPC `PERMISSION_DENIED`.
A password sign-in reveals `tenant_suspended` only after the password
verified, so the code tells an anonymous caller nothing about the tenant.

**Sessions and refresh tokens are revoked** in the same transaction as the
status write. Nothing is revoked if the write itself fails.

**What keeps working.** The tenant's data is kept as it is, and scheduled
directory (LDAP/AD) sync keeps writing the tenant's users while it is
suspended. AMQP **audit ingestion** is still recorded, so the tenant's trail loses nothing while it is
suspended. Organization principals can read the tenant, export its audit trail,
change its status and delete it; any other write to it (creating users or
roles, changing settings, issuing signing CAs) is refused with
`403 tenant_suspended`.

## Lifting it

Setting the status back to `Active` restores sign-in, but through **new**
sessions: the revoked sessions and refresh tokens are not brought back, so users
sign in again, and applications refresh from a fresh login.

**Suspension is not a credential reset.** It revokes sessions and OAuth2 refresh
tokens, nothing else. These survive it:

- SCIM provisioning tokens: refused while the tenant is suspended, valid again
  the moment it is lifted;
- OAuth2 client secrets and service-account secrets;
- certificates (device and service);
- user passwords.

If the suspension answers a compromise, revoke or rotate these **before**
lifting it.

## Limits

- **The organization's own tenant cannot be suspended**
  (`409 organization_tenant_not_suspendable`). It holds the organization
  principals, the only principals that can lift a suspension.
- A tenant that is `Suspended` is not the same as an account that is locked or
  deactivated; those are per-user and unchanged.

## What to tell integrators

An application or monitor that talks to a tenant must treat `tenant_suspended`
as a distinct, non-retryable state, not as a bad credential. The code is part of
the SDK contract ([`sdks/CONTRACT.md`](../../sdks/CONTRACT.md) §2) and of the
deployment upgrade notes
([SA-13](../deployment/README.md#sa-13--tenant-suspension-is-enforced)).
