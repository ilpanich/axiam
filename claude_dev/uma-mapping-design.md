# UMA 2.0 in AXIAM — what maps onto what (X2)

> Companion to `claude_dev/extra-B-track-features.md` §X2. This file exists to
> settle one decision before any endpoint is written: **what a UMA resource
> scope is, in AXIAM's authorization model.** Everything else in X2 is
> plumbing that follows from it.

## The problem

UMA 2.0 and AXIAM both use the word "scope", and they do not mean the same
thing.

| | UMA 2.0 | AXIAM |
|---|---|---|
| Resource | a thing a resource server protects | `resources` row, hierarchical |
| Scope | **a verb** on that resource — `view`, `edit`, `album:delete` | a **sub-resource narrower** — `pii`, `salary` — attached to a resource |
| Verb | (the scope *is* the verb) | `action`, from the permission model |

A UMA ticket says "the client needs scopes `[view, edit]` on resource X". An
AXIAM `AccessRequest` is `{ subject, action, resource_id, scope: Option<name> }`.
So there are two candidate mappings and they are not equivalent.

## The decision

**A UMA resource scope maps to the AXIAM `action`**, evaluated against the
registered resource:

```rust
AccessRequest { tenant_id, subject_id, action: <uma scope name>, resource_id, scope: None }
```

The resource's declared scope set — stored as ordinary AXIAM `Scope` rows on
that resource, per §X2's "no parallel resource store" — is the **allow-list of
scope names a resource server may ask for**, not an input to the decision. A
ticket naming a scope the resource never declared is refused at request time
rather than evaluated and denied, because those are different failures and the
resource server should be able to tell them apart.

## Why not map UMA scope onto AXIAM `scope`

Because of how `grant_applies` treats a wildcard grant. A `PermissionGrant`
with an empty `scope_ids` matches **any** requested scope:

```rust
Some(scope_id) => grant.scope_ids.is_empty() || grant.scope_ids.contains(&scope_id),
```

That is correct for its own model — a grant of `read` that names no scopes
means "read, unrestricted". But if UMA scopes rode on that field, a single
unscoped grant of whatever fixed action we invented (`uma:access`) would
satisfy **every scope on the resource at once**: registering a new `delete`
scope would silently widen every existing grant to include it. A resource
server would add a scope and hand out authority nobody granted.

Mapping verb to verb has no such failure. Granting `view` grants `view`. A new
`delete` scope is unreachable until someone grants `delete`.

## What this buys, and what it costs

**Buys.** Deny-override (B1) applies to RPTs for free and with no special
casing: a `PermissionEffect::Deny` grant on action `view` vetoes an RPT for
`view` exactly as it vetoes a live check, because it *is* the same check. This
is what §X2's "a deny rule must veto an RPT exactly as it vetoes a live check"
requires, and it is only automatic under this mapping.

**Costs.** An AXIAM deployment that already uses sub-resource scopes (`pii`)
cannot express "UMA scope = that narrower" — a UMA client asks for verbs. That
is the right trade: UMA's own model has no sub-resource concept to map onto, so
nothing is lost that UMA could have expressed.

## Consequences to hold to

- **The ticket is evaluated at mint time, not at introspection time.** An RPT
  carries `{resource_id, resource_scopes, exp}` for pairs the engine allowed
  when the RPT was issued. A grant revoked afterwards does not retroactively
  empty a live RPT — RPT lifetime is bounded (min of subject-token remaining,
  configured max, 300 s default) precisely so that window is short.
- **Partial grants are refused, not trimmed.** If a ticket names three pairs
  and the engine allows two, v1 answers `access_denied` rather than issuing a
  two-pair RPT. Trimming would make an RPT's contents depend on evaluation
  order and hand the client a token that silently does less than it asked for.
  (Claims-gathering, which is the spec's answer to partial grants, is deferred.)
- **Scope names are matched exactly.** No prefix or wildcard matching, in
  either direction. `album:view` does not imply `album:view:thumbnail`.
