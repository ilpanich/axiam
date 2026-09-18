# Client ID metadata documents (CIMD)

AXIAM can accept a `client_id` that is a **URL**, fetch the JSON document
published at that URL, and treat what it finds there as the client's
registration. The client is never registered here: it is registered *by its
own publisher*, once, and every AXIAM deployment that trusts that publisher
reads the same file.

This is what lets a desktop MCP client — Claude Code, VS Code, MCP Inspector —
be the same client at your deployment and at everybody else's, with nothing
created in advance and no `client_secret` anywhere.

It is **off by default, on every tenant**. A deployment that changes nothing
treats a URL-shaped `client_id` exactly as it treated one before this feature
existed: an unknown client. Nothing is fetched, nothing is written, and
discovery says nothing about it.

Turning it on is a decision about **whose files you will fetch**, and the
settings page will not let you skip it. Read
[What it costs you](#what-it-costs-you) before enabling it.

---

## The draft this implements

`draft-ietf-oauth-client-id-metadata-document`.

**No revision is pinned here, and that is a deliberate gap rather than an
oversight.** The session that implemented this had no egress to
`datatracker.ietf.org` or `ietf.org`, so the revision current at the time could
not be read, and a number written from memory would be a claim the code cannot
support. What is implemented is the draft's stable core — the URL rules, the
document shape, and the metadata members RFC 7591 §2 already defines —
cross-checked against Keycloak's `cimd` feature, whose validation list AXIAM
treats as the reference behaviour. If you are relying on a specific revision,
read the document rules below and compare them against it; they are stated in
full precisely so that you can.

---

## How a request becomes a client

1. A request arrives at `/oauth2/authorize`, `/oauth2/par` or `/oauth2/token`
   with a `client_id` that starts `https://` (or `http://`, see
   [`cimd.allow_http`](#every-policy-field)).
2. If the tenant has `cimd.enabled` false, **nothing else happens** and the
   request is answered as an unknown client.
3. The URL is checked against the rules in
   [The URL rules](#the-url-rules). A URL that fails any of them, or whose host
   is not on `cimd.trusted_client_id_domains`, stops here — before anything is
   fetched.
4. The document is fetched (through AXIAM's shared SSRF guard, with a size cap,
   a timeout and a redirect limit) or served from cache.
5. The document is checked against
   [The document rules](#the-document-rules).
6. A **shadow client row** is created or refreshed: `managed_by: cimd`, the URL
   as its `client_id`, the document's name, callbacks, grants and scopes — and
   the *tenant's* audiences, never the document's.
7. Everything after that is the ordinary code flow. The client is a row like
   any other, so the loopback redirect matcher, the consent gate, the RFC 8707
   `resource` check and the FAPI refusals all apply without knowing where it
   came from.

Every failure at steps 2 to 5 produces the same outcome: no row, therefore the
unknown-client refusal the request would have received anyway. A client that
does not work will not tell its author *why* from the wire — that is
deliberate, because the caller is unauthenticated — so the reason is in the
server log at `debug`, and the first successful materialisation is an audit
event (`oauth2.client_registered`, with `managed_by: cimd`).

---

## Every policy field

All nine live on the tenant's OIDC policy under `cimd`, resolved through the
ordinary organization-baseline-plus-tenant-override chain (see
[`docs/admin/organization-scope.md`](organization-scope.md)).

They are editable from three places in the admin console, and which one you
want follows from the two ordering rules below. The **organization Settings
tab** (Organizations → an organization → Settings → *Client ID metadata
documents*) edits the baseline, and is the **only** surface that can turn
`cimd.enabled` or `cimd.allow_http` on — neither tenant surface can, because
neither may widen what the organization set. The **tenant settings page**
(Settings → *Client ID Metadata Documents*) states the signed-in tenant's own
posture, and the **per-tenant security overrides panel** (Organizations → a
tenant → *Override client ID metadata documents*) lets an organization
administrator state one on a tenant's behalf. Both tenant surfaces take the
posture over whole: checked means this tenant's nine fields, unchecked means it
inherits the organization's nine and keeps following them. Every refusal in
[The two interlocks](#the-two-interlocks) and every bound below is mirrored in
the form, in the words the API answers with, so a posture that would be refused
cannot be saved from any of the three.

| Field | Default | What it does |
| --- | --- | --- |
| `cimd.enabled` | `false` | Whether a URL-shaped `client_id` is resolved at all. |
| `cimd.allow_http` | `false` | Permit an `http://` `client_id` and an `http://` fetch. **Development only** — see the warning below. |
| `cimd.trusted_client_id_domains` | `[]` | Hosts whose documents this tenant will fetch, as globs. An empty list resolves nothing, and enabling CIMD with an empty list is **refused**. |
| `cimd.trusted_redirect_domains` | `[]` | Hosts a document's `redirect_uris` may point at, as globs. The loopback hosts are **always** allowed, so an empty list means "loopback only" — which is the desktop MCP profile. |
| `cimd.restrict_same_domain` | `true` | Require every redirect host to equal the `client_id`'s host. **Turn this off for desktop clients** — see [The two profiles](#the-two-profiles). |
| `cimd.confidential_only` | `false` | Refuse a document whose `token_endpoint_auth_method` is `none`, admitting only `private_key_jwt` clients. |
| `cimd.min_cache_secs` | `300` | The floor under a document's cache lifetime. Refused below 60. |
| `cimd.max_cache_secs` | `259200` (3 days) | The ceiling on a document's cache lifetime. Refused above 604800 (7 days). |
| `cimd.max_metadata_bytes` | `5000` | The hard cap on how many bytes of a document are read. Refused at 0 or above 65536. |

The posture is stored, inherited and overridden **whole**. A tenant either
accepts its organization's CIMD policy or states its own in full; there is no
per-field merge, because a half-merged posture — this tenant's trusted
publishers under the organization's `enabled` — is one neither party wrote.

Two of the nine are **ordered** against the organization baseline, because they
are the two that can *widen*: a tenant may not set `cimd.enabled` or
`cimd.allow_http` true when its organization has them false. The other seven
name this tenant's own publishers, callbacks and bounds, and are neither
validated against the baseline nor clamped.

### Glob syntax

The same tiny grammar `dcr_allowed_redirect_hosts` uses, and for the same
reason — a host allow-list in front of a security check is no place for a
general-purpose matcher:

* `mcp.example.com` — that host exactly, case-insensitively.
* `*.example.com` — any host with at least one label before `example.com`. It
  does **not** match `example.com` itself, and it does **not** match
  `evil-example.com`: the match lands on a label boundary, not on a suffix.
* `*` — any host. **Refused for `cimd.trusted_client_id_domains`, admitted for
  `cimd.trusted_redirect_domains`.** So is a wildcard over a whole top-level
  domain (`*.com`, `*.io`), which is the same posture spelled longer. The
  trusted-publisher list is what decides whose server AXIAM will make an
  outbound request to on an unauthenticated caller's word, an empty list is
  refused for that reason, and a control with a one-character bypass is not
  the control. A redirect domain is not a fetch target: it bounds where a
  document may point a browser, the loopback hosts are allowed whatever the
  list says, and an empty list there means "loopback only" rather than
  "nothing".
* Anything else containing `*` matches nothing at all.

An entry that is a URL, a path or a `host:port` is **refused at the settings
page** rather than silently matching nothing.

The wildcard refusal is a **floor, not a public-suffix check.**
`*.github.io`, `*.pages.dev` and any other shared-hosting domain still pass,
because a tenant fronting hobbyist MCP tools may reasonably trust one and
nothing here should second-guess that. What bounds shared hosting is the
per-tenant quota and the sweep below, not this rule.

---

## The two interlocks

The settings API refuses two combinations outright. Both are security controls
rather than validation niceties.

### D3 — you must name your audiences first

Enabling CIMD while `external_client_allowed_resources` is empty is refused.

A client materialised from somebody else's document inherits that list as its
`allowed_resources`, and **an empty list is not "no audiences"** — it leaves
the client able to obtain exactly the `axiam:user` tokens AXIAM's own APIs
accept. So the empty list is not the safe default for this mechanism, it is the
dangerous one. Name the MCP servers this tenant fronts before strangers'
clients may ask for tokens.

This is the same interlock that guards `dynamic_registration: anonymous`; see
[Dynamic client registration](dynamic-client-registration.md) and
[Resource indicators](../api/resource-indicators.md).

### You must name your publishers first

Enabling CIMD while `cimd.trusted_client_id_domains` is empty is refused.

The draft's premise is that any URL is a valid client identifier. AXIAM does
not implement that premise, and this is the one place it deliberately departs
from it. The fetch is triggered by an **unauthenticated** request that names
the URL, so an unrestricted list is an outbound request whose target a stranger
chooses — bounded only by the SSRF guard's address rules, which stop
`169.254.169.254` but not `some-host-you-have-never-heard-of.example`. Naming
the publishers you actually front costs one settings field and removes the
class.

---

## The URL rules

A `client_id` URL must satisfy all of these, or it is not resolved:

| Rule | Why |
| --- | --- |
| Scheme is `https` (or `http` with `cimd.allow_http`) | The document *is* the registration. Over plaintext it is rewritable in transit by anybody on the path, who would then be choosing this client's redirect URIs. |
| A path component is present, and is not just `/` | `https://example.com` identifies a host, and a host is not a client: every party who can publish anything under that origin would otherwise be the same client. |
| No `.` or `..` path segment | Two spellings of one document are two `client_id`s, two shadow rows and two consent records for one client. |
| No query string | The identifier's own equality would depend on parameter order. |
| No fragment | A fragment never reaches the server, so it can only create a second spelling. |
| No userinfo (`https://user:pw@…`) | A credential does not belong in a public identifier. |
| The URL is its own canonical form | AXIAM's own rule. The string is compared against the document's `client_id`, used as a cache key, and stored as the row's `client_id` for later exact-match lookup. `https://Example.com/a` and `https://example.com/a` would not agree across those three. Present the canonical spelling — lowercase host, no default port. |
| The host matches `cimd.trusted_client_id_domains` | See above. |

---

## The document rules

The document is JSON (`application/json`, or any `+json` media type), and its
members are RFC 7591 §2's. Members AXIAM cannot act on — `client_uri`,
`logo_uri`, `contacts`, `tos_uri`, `policy_uri`, `software_statement` — are
ignored, as RFC 7591 §2 requires.

| Rule | Detail |
| --- | --- |
| `client_id` equals the URL it was fetched from | Required. Without it, a document copied from another publisher, or served by a host that mirrors other people's files, would become that other client. |
| `redirect_uris` names at least one URI | Every grant a CIMD client may hold is completed through a browser redirect. |
| Each redirect URI is `https`, or `http` on `127.0.0.1`, `localhost` or `[::1]` | RFC 8252 §7.3. A loopback callback never leaves the user's machine. |
| Each redirect host is on `cimd.trusted_redirect_domains` | Loopback is always allowed whatever the list says. |
| With `cimd.restrict_same_domain`, each redirect host equals the `client_id` host | Off for desktop clients; see below. |
| No redirect URI carries a fragment | RFC 6749 §3.1.2. |
| `token_endpoint_auth_method` is `none` or `private_key_jwt` | A client whose registration is a public file cannot hold a shared secret. Absent means `none`. `cimd.confidential_only` refuses `none`. |
| `private_key_jwt` names **exactly one** of `jwks` or `jwks_uri`, and an `https` `jwks_uri` | RFC 7591 §2. AXIAM fetches that URI to obtain the credential that authenticates the client. |
| A `none` document registers neither `jwks` nor `jwks_uri` | A client that authenticates with nothing does not also register a key. |
| `grant_types` ⊆ `{authorization_code, refresh_token}`, and includes `authorization_code` | Client credentials and token exchange mint a token on the strength of the client's own identity, and the identity of a CIMD client is a file a stranger publishes. |
| `response_types` ⊆ `{code}` | AXIAM issues authorization codes. |
| `scope` ⊆ `dcr_allowed_scopes` | The tenant's external-client scope list governs both external mechanisms. It is named for DCR because DCR defined it; a CIMD client is an externally registered client too. It may not contain `address` or `phone` — see [Dynamic client registration](dynamic-client-registration.md). |

### What the document may not decide

| The document may name | Decided by |
| --- | --- |
| `redirect_uris`, `scope`, `grant_types`, `token_endpoint_auth_method` | the document, within the rules above |
| **audiences** (`allowed_resources`) | **the tenant** — `external_client_allowed_resources`, always (D3) |
| **profile** | **forced to `standard`**: a CIMD client can never carry a FAPI profile |
| **provenance** (`managed_by`) | **forced to `cimd`** |
| **consent** | **forced on**: the first authorization per user goes to the consent screen |
| **a shared secret** | cannot exist |

### A client an administrator created is never overwritten

If a `client_id` in this tenant already names a client whose `managed_by` is
not `cimd` — an administrator's, or one that registered through RFC 7591 — then
a document published at that address is **ignored entirely**. The existing
registration stands, with its own callbacks, its own secret and its own
audiences. The refusal is enforced twice: once in the resolver, where it is
logged with the client's provenance, and once in the repository, whose refresh
statement will only ever match a `cimd` row.

---

## The two profiles

### Desktop MCP clients (Claude Code, VS Code, MCP Inspector)

```text
cimd.enabled                  = true
cimd.allow_http               = false
cimd.trusted_client_id_domains = [ "<the publisher's host>" ]
cimd.trusted_redirect_domains  = []          # loopback is always allowed
cimd.restrict_same_domain      = false       # ← required
cimd.confidential_only         = false
external_client_allowed_resources = [ "https://mcp.example.com/mcp" ]
dcr_allowed_scopes                = [ "openid", "profile" ]
```

**`restrict_same_domain` must be off**, and the reason is structural rather
than a matter of taste: these clients receive their callback on
`http://127.0.0.1:<random port>/…` (RFC 8252 §7.3), which can never share a
host with an `https://` `client_id`. A tenant that left the rule on would
refuse every desktop client, every time, with the rule doing exactly what it
says. Keycloak's own guidance turns it off for the same clients for the same
reason.

What you give up by turning it off is a cross-check — that the party publishing
the document is the party receiving the code — and what stands in its place is
that the redirect is on the loopback interface of the machine the person is
sitting at. A code delivered there is delivered to them.

The publisher host is whatever URL the client documents as its `client_id`;
take it from the client's own documentation rather than from here, and put it
in `cimd.trusted_client_id_domains` verbatim. If you front several such
clients, list each host.

### Server-side clients

```text
cimd.enabled                  = true
cimd.trusted_client_id_domains = [ "*.partner.example" ]
cimd.trusted_redirect_domains  = [ "*.partner.example" ]
cimd.restrict_same_domain      = true
cimd.confidential_only         = true
```

Here every constraint can be kept: the client publishes its document and
receives its callback on the same domain, and it authenticates with
`private_key_jwt` rather than with nothing.

---

## What it costs you

Enabling this means an unauthenticated request can cause your authorization
server to make an outbound HTTP request. Every bound below exists because of
that sentence, and none of them is a tuning knob.

| Bound | What it stops |
| --- | --- |
| `cimd.trusted_client_id_domains` | Choosing *which host* your server connects to. |
| The SSRF guard | Private, loopback, link-local, CGNAT and cloud-metadata addresses, including the IPv4-mapped IPv6 spellings of each (`::ffff:169.254.169.254`). The address is resolved, canonicalised, validated and then **pinned into the connection**, so a DNS answer that changes between the check and the connect cannot be used. |
| The redirect policy | A publisher redirecting your server somewhere it would not have gone: automatic redirects are off, every hop is re-validated in full, and the hop count is bounded. |
| `cimd.max_metadata_bytes` | A publisher returning an unbounded body. The cap is applied **while reading**, not after, so a chunked response cannot be buffered first. |
| The request timeout | A publisher that accepts the connection and never answers. |
| `cimd.min_cache_secs` | One outbound fetch per authorization request. A document is read once per TTL, not once per sign-in. |
| `cimd.max_cache_secs` | A stranger pinning a live client registration at your deployment forever after taking their document down. |
| `dcr_max_clients` | How many distinct documents this tenant holds at once. Counted separately from your self-registered clients and against the same number, so neither mechanism can exhaust the other's allowance — and checked **before the fetch**, so a tenant at its ceiling is not an outbound amplifier either. A refresh of a document you already hold never counts. |
| `dcr_unused_client_ttl_days` | A shadow row outliving its use. See [Cleaning up](#cleaning-up). |

What none of them stops is a caller naming **many different URLs on a host you
have trusted**: each new path is a cache miss and therefore one fetch. The
bound there is the per-IP rate limit on the endpoint the request arrived at
(`AXIAM__RATE_LIMIT__TOKEN_PER_MIN` and its siblings, see
[rate-limit sizing](../deployment/rate-limit-sizing.md)) and the fact that the
host is one you chose. It is an amplifier pointed at *your publisher*, not a
way into your network — and AXIAM refuses `*` (and `*.com`) in
`cimd.trusted_client_id_domains` for exactly this reason, so the list always
names a publisher you chose.

A cached document survives a publisher outage for up to 24 hours past its TTL
(the same stale-while-revalidate window AXIAM gives a federated identity
provider's JWKS), because a publisher having a bad afternoon should not sign
every one of its users out of every MCP server they are using. After that the
client stops working, which is what a withdrawn document should mean.

### `cimd.allow_http` does more than its name says

AXIAM's SSRF guard couples the scheme rule to the address rule — it is the same
seam that lets an integration test point a fetch at a loopback mock server — so
a tenant that allows `http` **also allows the first hop to resolve to a private
address**. Redirect hops are still validated strictly. Use it on a development
deployment and nowhere else.

---

## Cleaning up

`cimd` rows are swept on `dcr_unused_client_ttl_days` (30 days by default,
`0` to disable), reported at `GET /health/jobs` under **`cimd_unused_clients`**
— its own counter beside `dcr_unused_clients`, because the two sweeps delete
different things for different reasons.

**The clock is last presented, not last registered.** Every authorize, token
and PAR request that resolves a document refreshes its row, including one
served from AXIAM's in-memory document cache with no outbound fetch at all. So
a document in daily use is never swept however old its registration is, and
one nobody has presented for a month is — and if that document is still
published, the next request materialises it again.

That last property is why the sweep is *consistent* with what a CIMD row is
rather than at odds with it. An earlier version of this page argued there
should be no sweeper: unlike a self-registered client, a CIMD client's
registration is not a row somebody created once, it is a file that either still
exists or does not, and a row whose document has been withdrawn stops working
within a day of its TTL expiring whatever the row says. All of that is true,
and all of it is about TTL semantics rather than about storage — and a cache
that is never evicted is not a cache. An inert row is still listed on the
OAuth2 clients page, still counted in every sweep, and still a permanent write
a stranger made at the cost of one unauthenticated request. Deleting one and
letting the next request bring it back is exactly what a cache should do.

To retire a row immediately, delete it through the admin API, or remove the
publisher from `cimd.trusted_client_id_domains` — the second also stops it
being recreated by the next request.

Setting `cimd.enabled` back to `false` stops every URL-shaped `client_id`
resolving immediately. It does not delete the rows already materialised; those
become ordinary unused clients, refusing every request that needs a fresh
document.

---

## See also

- [Dynamic client registration](dynamic-client-registration.md) — the other way
  a client AXIAM's operator did not create comes into existence, and the shared
  `external_client_allowed_resources` policy.
- [Public clients](public-clients.md) — `token_endpoint_auth_method: none` and
  the loopback redirect matcher a CIMD client depends on.
- [Resource indicators](../api/resource-indicators.md) — what
  `allowed_resources` does, and why a stranger must not choose it.
