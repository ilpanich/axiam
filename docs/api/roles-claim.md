# The `roles` scope and access-token claim

**Since:** SA-18 (security audit 2026-11-14, finding N15, decision D-1)

An AXIAM access token can carry the names of its subject's roles, so that a
resource server or SDK can make a coarse role check (`require_role`) without a
round trip. It does so only when the client asked for, and is allowed, the
`roles` scope.

## Asking for it

`roles` is an ordinary OAuth2 scope:

- A client obtains it only if `roles` is in its registered `scopes` (for a
  dynamically registered or CIMD client, also in the tenant's
  `dcr_allowed_scopes`). A request naming it from any other client is refused
  `invalid_scope`, as for any unregistered scope. No existing client has it
  until an administrator adds it.
- A **service account** registers no scopes. On the client-credentials grant
  it may send `scope=roles` — and nothing else; any other scope is still
  refused `invalid_scope`.

It is advertised in discovery: `roles` is in `scopes_supported` and in
`claims_supported`.

## What the claim contains

```json
{ "sub": "…", "scope": "openid roles", "roles": ["auditor", "billing-admin"] }
```

- The **names** of the subject's roles in the token's tenant whose assignment
  names **no resource** — assigned directly, or inherited through a group the
  subject belongs to.
- A role assigned only on a resource (resource-specific assignment) is **not**
  included, whatever the role's `is_global` flag says.
- Sorted and de-duplicated: a role held directly and through a group appears
  once.

| Grant | Carries `roles` when `roles` is granted |
|---|---|
| Authorization code, refresh, CIBA, device, native provider-ID-token sign-in | yes — the user's roles |
| Client credentials (service account `sa_…`) | yes — the account's roles |
| Client credentials (OAuth2 client) | yes, always `[]` — a client holds no roles |
| Token exchange (RFC 8693) | only if `roles` survives the scope narrowing; recomputed for the subject |
| ID token, UserInfo | **never** |

## Absent is not empty

- **Absent** — the `roles` scope was not granted. The token says nothing
  about roles; a role check must fail closed.
- **`[]`** — the scope was granted and the subject holds no global role.

## A snapshot, not an authority

The claim is computed when the token is minted (each refresh recomputes it).
A role assigned or withdrawn afterwards is reflected only in the next token,
so the claim is **stale for at most one access-token lifetime** (15 minutes by
default, `AXIAM__AUTH__ACCESS_TOKEN_LIFETIME_SECS`).

Use it for UI gating and coarse guards. For an authorization decision that
must reflect the current state — or one that depends on a resource, a scope or
a deny grant — call `require_access` (REST `/api/v1/authz/check`, gRPC
`AuthorizationService`, AMQP), which evaluates the RBAC engine live and is the
authoritative check.

The SDK side of this (D-1): `require_role` reads only the `roles` claim and
fails closed when it is absent; it never derives roles from `scope`. A
separate `require_scope` checks OAuth2 scopes.
