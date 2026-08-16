# SCIM provisioning tokens — design

Closes the operational gap `docs/api/scim-provisioning.md` states plainly: the
SCIM bearer principal is a tenant user, its credential is a **15-minute access
token**, and wiring Okta or Entra therefore requires a scheduled job that
refreshes the token and pushes the new value into the IdP through the IdP's own
management API before the old one expires.

That is a real cost, and it exists because AXIAM had no long-lived machine
credential. This adds one, scoped as narrowly as the problem allows.

## The shape of the problem

Okta's SCIM connector ("HTTP Header" auth mode) and Entra's provisioning
("Secret Token" field) both take **one static bearer string, pasted once**.
Neither can perform an OAuth2 exchange. So the credential must be:

- presentable directly as `Authorization: Bearer <value>`,
- long-lived enough to paste and forget,
- revocable without rotating anything else.

## What this is *not*

**Not a general-purpose API key.** A token issued here is accepted on
`/scim/v2/*` and **nowhere else** — not `/api/v1/*`, not `/oauth2/*`, not gRPC.
That containment is the entire reason this is a defensible addition to a system
whose security standards otherwise say "short-lived access tokens (15 min)".
A credential that lives for a year and opens every door would be a straight
downgrade; one that lives for a year and opens exactly the door an IdP needs is
the thing the deployment already had to fake with a cron job.

**Not a second authorization system.** The token carries no permissions. It
resolves to an existing tenant user and the *user's* RBAC decides everything,
through the same `require_scim_provision` check that runs today.

## Model

```rust
pub struct ScimToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The tenant user this token authenticates as.
    pub user_id: Uuid,
    /// Operator-facing label, e.g. "okta-production".
    pub name: String,
    /// SHA-256 (hex) of the handle. The plaintext is returned exactly once.
    pub token_hash: String,
    /// Who minted it — for the audit trail.
    pub created_by: Uuid,
    pub expires_at: DateTime<Utc>,
    /// Stamped on each accepted request, best-effort.
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
```

### Binding to a user, not to a permission

The alternative — a standalone credential carrying `scim:provision` itself —
was rejected. Binding to a user means:

- **Revocation already works.** Unassign the role, deactivate the user, or
  delete the user, and every token bound to them stops working immediately.
  A permission-carrying token would need its own revocation story that
  operators would have to learn and remember to use.
- **The audit trail names a principal that exists.** Every SCIM write is
  already attributed to a user id; that stays true.
- **SEC-098 semantics are unchanged.** `scim:provision` confers tenant-wide
  password-setting. That warning is attached to the permission, and it keeps
  applying because the permission is still what is being checked.

The cost is that an operator must create a provisioner user first. That is
already step 1 of the documented setup, so nothing new is asked of them.

### Handle format

`axiam_scim_<43 chars base64url>` — 32 bytes of entropy, the same generator and
the same SHA-256-hex-at-rest treatment as refresh tokens
(`axiam_auth::token::generate_refresh_token` / `hash_refresh_token`).

The `axiam_scim_` prefix is deliberate and load-bearing: a credential designed
to be pasted into a third-party console and left there is a credential that will
eventually be pasted somewhere else by mistake. A fixed, greppable prefix is what
lets GitGuardian (already in this repo's CI), GitHub secret scanning, and an
operator's own `grep` find it. An opaque base64 blob is indistinguishable from
every other opaque base64 blob.

### Expiry

Chosen per token at creation, bounded by `AXIAM__SCIM_TOKEN_MAX_LIFETIME_DAYS`
(default 365). There is no "never expires" option: a credential with no expiry
is one nobody ever revisits, and the whole point of pasting it into an IdP is
that it is then out of sight. A bounded lifetime forces one deliberate renewal
decision per year rather than none ever.

## Authentication path

`axiam-scim` gains a `ScimPrincipal` extractor:

```rust
pub enum ScimPrincipal {
    /// Today's path, unchanged: a JWT-bearing tenant user.
    Jwt(Box<AuthenticatedUser>),
    /// A provisioning token, resolved to the user it is bound to.
    Token(ScimTokenPrincipal),
}
```

Resolution order is by prefix, not by trial: a bearer value starting with
`axiam_scim_` is looked up as a provisioning token; anything else goes to the
existing JWT path. Trying both in sequence would turn every malformed JWT into a
database lookup, and would make the failure mode ("which credential did it think
this was?") unanswerable from the response.

`require_scim_provision` moves from `&AuthenticatedUser` to `&ScimPrincipal` and
calls `RequirePermission::check_subject(tenant_id, user_id, authz)` — the seam
that already exists for exactly this case ("a caller that may be a machine
rather than a user"), so no new authorization code is introduced.

Rejections, all answering 401 with no distinction on the wire (an attacker
probing handles learns nothing about which arm failed):

| Condition | Why |
|---|---|
| No row for the hash | Unknown or forged handle |
| `revoked_at` set | Explicitly revoked |
| `expires_at` past | Lapsed |
| Bound user inactive/deleted | The principal is gone |

`last_used_at` is stamped on success, best-effort: a failure to write it must
never fail the request it is describing.

## Admin API

Tenant-scoped, gated on new permissions in `PERMISSION_REGISTRY`:

| Route | Permission |
|---|---|
| `POST /api/v1/scim-tokens` | `scim_tokens:create` |
| `GET /api/v1/scim-tokens` | `scim_tokens:list` |
| `DELETE /api/v1/scim-tokens/{id}` | `scim_tokens:revoke` |

`POST` returns the plaintext handle once, in the same
one-time-reveal shape as service-account secrets. `GET` never returns it —
the list is metadata only (name, bound user, expiry, last used, revoked).

Creation is **not** allowed to mint a token for an arbitrary user id without
that user actually holding `scim:provision`: the handler checks it and refuses
otherwise. A token that authenticates as somebody who cannot use SCIM is a
credential that only ever produces 403s, and creating it silently is a trap.

Separate permissions from `scim:provision` on purpose — minting a credential
for a provisioner is an administrative act, and the provisioner itself should
not be able to mint more of them.

## Frontend

A **SCIM Provisioning** page (`/scim-tokens`), gated on `scim_tokens:list`:

- create a token (pick the provisioner user, name it, set expiry) with the
  existing `SecretRevealModal` for the one-time handle,
- list tokens with status (active / expired / revoked) and last-used,
- revoke with confirmation.

The create dialog offers every tenant user and lets the server's check decide.
Filtering the list client-side would need a cross-subject authorization probe
(`/api/v1/authz/check/batch` with `subject_id`), which is gated on
`authz:check_as` — a permission a token administrator has no other reason to
hold, so requiring it would break the page for exactly the operator it is for.
The server's refusal names the missing permission and what to do about it,
which is the information the filter would have conveyed anyway.

## Out of scope

- Making `service_account` able to hold RBAC roles. That is the deeper fix
  (`RoleRepository::assign_to_user` hard-scopes `has_role` to the `user` table)
  and it belongs in `axiam-db`/`axiam-authz`. This design routes around it
  rather than pretending it is fixed; the Service Accounts page gains a note
  pointing operators here instead of down that dead end.
- Splitting `scim:provision`'s password capability behind a second permission
  (the follow-on `axiam_scim::auth` already suggests).
