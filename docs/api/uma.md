# UMA 2.0 — Protection API and the ticket grant

A service guards resources it does not own. A caller arrives without the
authority to touch them, and the service needs a way to say *what* the caller
would need — precisely, and without becoming the authority itself.

User-Managed Access is that mechanism. The guarding service (the **resource
server**) registers its resources, asks AXIAM to mint a **permission ticket**
describing what a given request requires, and the ticket is exchanged for a
**Requesting Party Token** (RPT) that says the authorization engine agreed.

**The one rule everything below serves: the resource server never decides.** It
describes what it needs; AXIAM decides whether the requesting party may have
it, using the same RBAC check a live request would run. That is why a deny rule
vetoes an RPT exactly as it vetoes anything else — it *is* the same check.

The mapping rationale, including why a UMA scope became an AXIAM action rather
than an AXIAM scope, is in
[`claude_dev/uma-mapping-design.md`](../../claude_dev/uma-mapping-design.md).

## What maps onto what

| UMA | AXIAM | Note |
|---|---|---|
| resource set `_id` | the resource id | **the same id** — there is no parallel resource store |
| resource set `name` / `type` | `resource.name` / `resource.resource_type` | |
| `resource_scopes` | `Scope` rows on that resource | the allow-list of names a resource server may ask for |
| a resource scope, when evaluated | the AXIAM **`action`** | `view` on the resource, not a sub-resource scope |
| PAT | an access token with the `uma_protection` scope | ordinary client-credentials token |
| RPT | an access token with a `permissions` claim | ordinary token; the claim is what makes it an RPT |

A resource registered through UMA is an ordinary AXIAM resource. It appears in
the admin UI, role assignments cascade through it, and the authorization engine
already understands it. The only thing marking it as UMA-registered is a
read-only provenance field, `uma_registered_by`, which the admin UI shows as a
badge.

## Discovery

```http
GET /.well-known/uma2-configuration
```

Advertises the token, introspection, permission and resource-registration
endpoints. It deliberately does **not** advertise a
`claims_interaction_endpoint`: interactive claims-gathering is not implemented,
and advertising an endpoint that 404s is worse than staying quiet, because a
conforming client routes on the strength of this document.

## 1. Get a PAT

A Protection API Token is an ordinary client-credentials token that carries the
`uma_protection` scope.

```http
POST /oauth2/token?tenant_id=<uuid>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<id>&client_secret=<secret>&scope=uma_protection
```

It must be a **client** token. A user token is refused with `403`, because a
permission ticket is bound to the `client_id` that minted it and a user token
carries no client identity to bind to.

## 2. Register a resource set

```http
POST /uma2/rreg/resource_set
Authorization: Bearer <PAT>
Content-Type: application/json

{ "name": "invoice-7", "type": "document", "resource_scopes": ["view", "pay"] }
```

→ `201` with `_id`, which **is** the AXIAM resource id.

`GET`, `PUT`, `DELETE` on `/uma2/rreg/resource_set/{id}` read, replace and
deregister. `GET /uma2/rreg/resource_set` lists the ids **this client**
registered — not the tenant's whole resource tree, which a protection scope
does not entitle a caller to enumerate.

**`PUT` replaces the scope list; it does not merge.** Removing a scope narrows
what tickets may be requested, so a merge would keep an authority the resource
server was trying to drop. A scope that survives an update keeps its id, because
permission grants reference scope ids and recreating one would detach every
grant that named it.

## 3. Request a permission ticket

```http
POST /uma2/perm
Authorization: Bearer <PAT>
Content-Type: application/json

[ { "resource_id": "<uuid>", "resource_scopes": ["view"] } ]
```

→ `201 { "ticket": "…" }`

The ticket is opaque, 256-bit, **single-use**, and lives 60 seconds. Only its
hash is stored.

Scope names are validated **here**, against the resource's declared set, rather
than at exchange time. Asking for a scope the resource never declared is a
`400`, not a denial — a ticket naming an undeclared scope could never be
redeemed, so minting one would hand back a credential guaranteed to fail a
minute later instead of an error the caller can act on now. "Undeclared" and
"denied" are different failures and the resource server should be able to tell
them apart.

## 4. Exchange it for an RPT

```http
POST /oauth2/token?tenant_id=<uuid>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:uma-ticket
&client_id=<id>&client_secret=<secret>
&ticket=<ticket>
&claim_token=<the requesting party's access token>
```

→ `200` with an access token carrying a `permissions` claim.

**`claim_token` is required**, though UMA 2.0 §3.3.1 marks it optional. Its
other two ways to name a requesting party — an RPT presented for incremental
authorization, and interactive claims-gathering — are both deferred, so this is
the only channel that exists. Requiring it and saying so beats resolving to some
default subject and minting an RPT for a party nobody named.

The ticket is **consumed before the request is evaluated**. Evaluating first
would let two concurrent redemptions both pass and both mint, which is what
single-use exists to prevent.

### Lifetime

`min(claim_token's remaining life, configured ceiling, 300 s)`. An RPT must
never outlive the token that authorised it. There is **no refresh token** —
re-run the grant.

### Partial grants are refused whole

If a ticket names three pairs and the engine allows two, the answer is
`access_denied` for the whole ticket, not a two-pair RPT. Trimming would make an
RPT's contents depend on evaluation order and hand the client a token that
silently does less than it asked for. UMA's own answer to this is
claims-gathering, which v1 defers.

## 5. Read an RPT

The `permissions` claim is readable in the token and echoed by introspection:

```http
POST /oauth2/introspect?tenant_id=<uuid>
```

```json
{ "active": true, "permissions": [ { "resource_id": "…", "resource_scopes": ["view"], "exp": 1760000000 } ] }
```

The shape is Keycloak's, so a resource server migrating from Keycloak reads it
without a translation layer. A non-RPT omits the key entirely rather than
returning an empty array, so "no permissions" and "not an RPT" stay
distinguishable.

**The claim is a record of a decision already made, not a live answer.**
Introspection echoes it; nothing re-evaluates it. A grant revoked after issuance
does not retroactively empty a live RPT — which is precisely why RPT lifetime is
bounded rather than long.

## The `WWW-Authenticate: UMA` challenge

A resource server refusing a request can tell the caller where to get authority
(UMA 2.0 §3.2):

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: UMA realm="example", as_uri="https://id.example", ticket="<ticket>"
```

A client parsing this should **not** exchange the ticket automatically. The
`as_uri` names an authorization server the client has not necessarily chosen to
trust, and auto-exchanging would send the user's `claim_token` to whatever host
the 403 pointed at.

## Errors

| Where | Status / `error` | Meaning |
|---|---|---|
| Protection API | `401` | PAT missing, malformed, or expired |
| Protection API | `403` | not a PAT — wrong subject kind, or no `uma_protection` scope |
| `/uma2/perm` | `400` | a scope the resource has not declared |
| ticket grant | `invalid_request` | `ticket` or `claim_token` absent, or an unsupported `claim_token_format` |
| ticket grant | `invalid_grant` | ticket unknown, expired, used, or presented by the wrong client; or `claim_token` invalid, expired, or cross-tenant |
| ticket grant | `access_denied` (**403**) | the requesting party is not authorized for every requested pair |

**The four ticket refusals answer one message on purpose.** Unknown, expired,
consumed and wrong-client are indistinguishable to the caller, because a caller
who could tell them apart could probe for live ticket handles.

**A wrong-client attempt changes nothing.** The `client_id` is matched inside
the consume statement rather than checked on the row afterwards, so a ticket
leaked to another client is not merely unusable by them — their failed attempt
does not *burn* it either. Checking after the fact would let anyone who obtained
a ticket destroy the rightful holder's.

## Single-use: guaranteed on a persistent storage engine

Ticket single-use is enforced in two layers: the guarded `UPDATE` runs inside an
explicit transaction, so the storage engine arbitrates and aborts every loser of
a concurrent redemption, and a per-attempt redemption nonce is read back after
that transaction commits, so a conflict the engine silently missed is still
caught. A second redemption needs both to fail on the same ticket.

The first layer is a property of the engine, so the guarantee is **conditional
on running a persistent one**. On `surrealkv` (what `docker-compose` and the k8s
StatefulSet run) and on `rocksdb`, the probe in `tools/surreal-race-probe`
measured zero double redemptions in 40 000 and 9 600 contended attempts
respectively. On SurrealDB's in-memory `memory` datastore it is **not**
guaranteed — that engine arbitrates at the same rate and then silently misses —
and a deployment MUST NOT use it. See
[ilpanich/axiam#302](https://github.com/ilpanich/axiam/issues/302) for the
history: the earlier nonce-only mechanism, its measured ~1-in-640 residual, and
the repairs that proved worse than the defect.

The practical consequence for a client is unchanged: **never retry a ticket
exchange.** A failed exchange has already spent the ticket, so a retry is
useless regardless of how the race was decided. Request a new ticket instead.

## Not implemented in v1

- **Interactive claims-gathering** (`request_submitted`, the redirect dance).
  API-to-API consumers rarely exercise it and Keycloak deployments
  overwhelmingly use the non-interactive path.
- **Party-to-party sharing UIs.**
- **Incremental authorization** — presenting an existing RPT to widen it.

None are advertised in discovery.
