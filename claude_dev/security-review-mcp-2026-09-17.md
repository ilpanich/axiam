# Security review — the MCP authorization surfaces (Phase 21, T21.8)

**Date:** 2026-09-17.
**Against:** `claude/t21-8-mcp-harness`, cut from `claude/t21-7-mcp-docs`
(`abdb3b6`), which carries T21.1 through T21.7.
**Scope:** the five surfaces
[`mcp-authorization-server-plan.md`](mcp-authorization-server-plan.md) §4's T8
names — the unauthenticated write endpoint (T21.4a), the outbound fetch
(T21.5), audience confusion (T21.3), the loopback matcher (T21.2a) and tenant
isolation under path issuers (T21.6).
**Companion:** every claim below that says "asserted" is asserted by
`crates/axiam-api-rest/tests/mcp_authorization_test.rs`, which this task wrote
alongside this document. A finding with no test is a finding this review could
not reproduce, and says so.

---

## 0. Summary

One finding was fixed in this session. Four were filed and are now closed —
see the remediation note below. Three areas the plan flagged as likely holes
were attacked and did not yield, and are recorded as verifications rather than
left as silence — a reviewer who reads "nothing found in tenant isolation"
deserves to know what was tried.

| ID | Finding | Severity | State |
|---|---|---|---|
| **MCP-02** | The `axiam` URI scheme is a valid absolute URI, so AXIAM's own token audiences were registrable and requestable as RFC 8707 resources. `client_credentials` could thereby mint a token carrying the **user** audience. | **Medium** | **Fixed** — `013903d` |
| **MCP-03** | `cimd.trusted_client_id_domains` refuses the empty list and accepts `*`, which means the same thing. The interlock T21.5 added to remove the "stranger chooses the fetch target" class is defeated by one character. | Medium | **Closed** — `0a273ec` ([#469](https://github.com/ilpanich/axiam/issues/469)) |
| **MCP-04** | `managed_by: cimd` shadow rows are bounded by no quota and swept by nothing. A tenant whose trusted publisher list names shared hosting grows client rows without limit. | Medium | **Closed** — `0b216c6` ([#470](https://github.com/ilpanich/axiam/issues/470)) |
| **MCP-05** | In `anonymous` mode a stranger can fill `dcr_max_clients` (default 20) in about four minutes and deny registration to legitimate clients for `dcr_unused_client_ttl_days` (default 30). | Medium | **Closed** — `c4d9ea2` ([#471](https://github.com/ilpanich/axiam/issues/471)) |
| **MCP-01** | A refusal raised *before* the redirect matcher runs is answered directly rather than redirected, so a desktop client on an ephemeral loopback port never learns its authorization failed. Fail-closed; an interoperability defect, not a vulnerability. | Low | **Closed** — `b8bc508` ([#472](https://github.com/ilpanich/axiam/issues/472)) |
| **MCP-06** | The "no `tenant_id` on a tenant path" check matches the raw query string, where the extractor that consumes it matches the percent-decoded one. | Informational | **Accepted** — pinned by a test as of `#472` |

| ID | Verified, no finding |
|---|---|
| **V1** | The loopback matcher widens a registration by a port and by nothing else. |
| **V2** | T21.6's `enforce_issuer` / `enforce_tenant_path_binding` do close the shared-JWKS hole. |
| **V3** | An initial access token is single-use under concurrent redemption. |

**Nothing here blocks the phase.** MCP-02 was the only finding that reached
past an invariant, and it is closed.

**Remediation, 2026-09-17.** All four filed findings were decided and costed in
[`issues-469-472-fix-plan.md`](issues-469-472-fix-plan.md) and fixed, across two
pull requests split by generated-artifact exposure: MCP-01 and the IPv6
loopback gap found with it on one branch ([#475](https://github.com/ilpanich/axiam/pull/475)),
which shares no file with the others and merged first; MCP-03, MCP-04 and
MCP-05 on another ([#476](https://github.com/ilpanich/axiam/pull/476)), because
they share `settings.rs`, `cleanup.rs` and both operator pages and their
decisions cascade. The state column above carries each commit.

Three things this document or the plan had slightly wrong were found in the
course of it, and each is recorded where it belongs rather than here: §7's
account of what MCP-06's acceptance rests on (the mechanism it names is
observable only behind a credential — a stranger gets a `401` before the
extractor is reached); and, in the fix plan's own §1 and §4, two cost claims —
that `CimdPolicy`'s doc comments do not reach the OpenAPI spec, and that
`OidcPolicy` lives in the settings JSON. Both were false, and each changed what
the commit relying on it could do.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Registration endpoint, policy, abuse controls | T21.4a | `axiam-api-rest/src/handlers/dcr.rs` (565), `axiam-oauth2/src/dcr.rs` (919) | **read in full** |
| The sweeper | T21.4a | `axiam-server/src/cleanup.rs` §`sweep_unused_dcr_clients` | **read in full** |
| Single-use redemption | T21.4a | `axiam-db/src/repository/oauth2_registration_token.rs` | **read in full** + concurrency test |
| CIMD resolution and fetch | T21.5 | `axiam-oauth2/src/cimd.rs`, bounds and ordering | read in full for the fetch path; validation sampled |
| The SSRF guard the fetch uses | SEC-094 | `axiam-pki/src/ssrf.rs` (1088) | **read in full** |
| Resource indicators | T21.3 | `axiam-oauth2/src/resource.rs` (475) | **read in full** |
| Audience pinning and its sibling | T21.3 | `axiam-auth/src/token.rs` §`decode_access_token`, §`..._any_audience` | **read in full** |
| Redirect matching | T21.2a | `axiam-oauth2/src/redirect_uri.rs` (285) + every call site | **read in full** |
| Issuer and tenant-path binding | T21.6 | `axiam-auth/src/token.rs` §`enforce_issuer`; `axiam-api-rest/src/extractors/auth.rs` §`enforce_tenant_path_binding`; `middleware/tenant_path.rs` (301) | **read in full** |
| Introspection tenant scoping | T21.3/T21.6 | `axiam-oauth2/src/token.rs` §`introspect_token` | targeted |

**A live stack was available, in part, and this is worth recording** because
two earlier documents in this series state that it was not. There is no Docker
daemon *running* in this sandbox, but `dockerd` starts: see §13. What could not
be done is pulling the conformance suite image, whose blob CDN the egress
policy refuses. Everything in this review was therefore established either by
reading code or by the Rust harness, which runs a real server against a real
in-memory SurrealDB — not by a deployment.

Sampled rather than exhausted, and named as such: the CIMD document-validation
rules beyond the fetch bounds (T21.5's own tests cover them and I did not
re-derive them), the admin UI surfaces of T21.2b and T21.4b, and the frontend
`returnTo` third validation T21.6's amendment 1 describes.

---

## 2. MCP-02 — AXIAM's own audiences were valid resource indicators

**Severity: Medium. Fixed in this session (`013903d`).**

RFC 8707 §2 says a `resource` is an absolute URI without a fragment.
`axiam_oauth2::resource::normalise` implements exactly that, and deliberately
admits any scheme — its own test says so:

```rust
// crates/axiam-oauth2/src/resource.rs, before this change
#[test]
fn any_absolute_uri_scheme_is_a_resource() {
    for raw in ["http://127.0.0.1:8931/mcp", "urn:example:orders", …] {
```

That generosity is correct and was argued for: a `urn:` resource is legitimate,
and an MCP server reached over loopback `http` in development is a resource like
any other. The problem is what else it admits. AXIAM's two built-in audiences
are spelled

```rust
// crates/axiam-auth/src/token.rs:19,23
pub const AUD_USER: &str = "axiam:user";
pub const AUD_M2M: &str = "axiam:m2m";
```

and a scheme followed by a path is all an absolute URI needs. `axiam:user`
parses, carries no fragment, and was therefore a resource indicator like any
other — registrable in `allowed_resources` and nameable in `resource`.

### Why that is not merely untidy

I3 says AXIAM's own extractors must refuse a resource-bound token, and the
mechanism that enforces it is the `aud` pin in `decode_access_token`. Naming
`axiam:user` as the resource does not defeat that check; it satisfies it. The
boundary stops being a boundary.

The sharpest case is `client_credentials`. Without `resource` it mints
`axiam:m2m`, which the user-facing extractors refuse. With
`resource=axiam:user` it minted a token stamped with the **user** audience —
the one claim `check_user_aud_and_parse_jti` gates on — from a grant that has
no end user in it. That is a shape no other path in the server can produce, and
it is reached by an operator writing one plausible-looking string into a
settings field.

The authorization-code direction is less severe (the end user is present
either way) but has the same character: a token an operator believes is scoped
to an MCP server is indistinguishable from one scoped to AXIAM.

`external_client_allowed_resources` is the field that makes this worth a
Medium rather than a Low. D3 has externally registered clients — DCR and CIMD,
so parties nobody vetted — inherit that list wholesale. An operator who adds
`axiam:user` to it, for any reason, hands the user audience to every stranger
who self-registers.

### The fix

`normalise` now refuses the whole `axiam` scheme, not the two literals, so an
audience added later is covered without anybody having to remember this rule
exists. It is checked after parsing, against the scheme `url` resolved, so
`AXIAM:user` cannot slip past a byte comparison on the input. Every door
answers `invalid_target`: registration refuses the entry, and the token
endpoint refuses the parameter even if a row somehow holds one — `is_allowed`
normalises both sides, so a stored reserved value does not authorise itself.

Fail-closed, and reachable by no existing deployment: `allowed_resources` ships
in this same unreleased version, so no stored row can contain one.

Asserted at both doors by `mcp02_a_builtin_audience_is_refused_as_a_resource`,
and at the parser by
`resource::tests::axiams_own_audiences_are_refused_as_resources`.

---

## 3. MCP-03 — the CIMD trusted-publisher interlock admits `*`

**Severity: Medium. Filed as [#469](https://github.com/ilpanich/axiam/issues/469) (T21.5).**

T21.5's amendment 2 records a deliberate decision, and its reasoning is right:

> AXIAM refuses the empty list, and the reason is the sentence the task itself
> opens with: the fetch is triggered by an **unauthenticated** request that
> names the URL. An unrestricted list is therefore an outbound request whose
> target a stranger chooses […] The guard is what keeps the fetch out of the
> private network; the trusted list is what keeps it from being a
> general-purpose request-forgery primitive, and there is no second control
> that does that job.

The settings validator implements the refusal:

```rust
// crates/axiam-core/src/models/settings.rs:759
if cimd.trusted_client_id_domains.is_empty() {
    violations.push("cimd.trusted_client_id_domains: … an unrestricted list is an \
                     outbound fetch a stranger chooses the target of …");
}
```

and then, forty lines down, the entry-shape check tells the operator what a
valid entry looks like:

```rust
// crates/axiam-core/src/models/settings.rs:795
"{field}: {entry:?} is not a host pattern. Write a host (mcp.example.com), \
 a leftmost-label wildcard (*.example.com) or * — not a URL, a path or a host:port"
```

`*` is admitted, and `host_glob_matches` documents it as "a tenant that wants
no host restriction". So the list the amendment refuses to let an operator
leave empty, it invites them to fill with a value that means the same thing —
and the error message that explains the refusal is the same message that
recommends the workaround.

**Impact.** A tenant on `trusted_client_id_domains: ["*"]` has exactly the
posture amendment 2 set out to remove: an unauthenticated `GET /oauth2/authorize`
with a URL-shaped `client_id` causes AXIAM to fetch any public URL the caller
names. The SSRF guard still holds — private addresses, IPv4-mapped forms,
metadata endpoints and redirects to any of them are refused (§4) — so this is
not an internal-network primitive. It is an outbound request forgery against
the public internet with AXIAM's source address, its TLS client, and no
attribution to the caller.

**Not a default.** CIMD is off by default and the field ships empty, so no
deployment has this posture without an operator choosing it. That is what keeps
it Medium.

**Recommended fix**, for whoever takes it: refuse `*` in
`trusted_client_id_domains` specifically, with a message that says what the
list is for — and leave it admissible in `trusted_redirect_domains`, where the
amendment's own reasoning shows empty is a working posture and the entries are
not fetch targets. One condition and one message, in the validator that already
holds the empty-list refusal.

Not fixed here because it is a behaviour change to a settings field on a
surface this task does not otherwise touch, and because the message needs
drafting against the operator page — which is T21.5's document, not T21.8's.

---

## 4. MCP-04 — CIMD shadow rows are unbounded and never reclaimed

**Severity: Medium. Filed as [#470](https://github.com/ilpanich/axiam/issues/470) (T21.5).**

Every successful CIMD resolution upserts a `managed_by: cimd` row keyed by the
document URL. Two bounds that exist for the other externally registered
provenance do not exist for this one:

* **No quota.** `dcr_max_clients` is enforced by counting
  `count_by_managed_by(tenant_id, ManagedBy::Dcr)`
  (`handlers/dcr.rs:217`). Nothing counts `ManagedBy::Cimd`.
* **No sweep.** `sweep_unused_dcr_clients` takes
  `list_all_by_managed_by(ManagedBy::Dcr)`, and its doc comment says plainly
  why CIMD is excluded:

  > Not `cimd` either: a CIMD shadow row is a cache of a document the client
  > publishes, so deleting it would be re-materialised on the next request and
  > the TTL would mean nothing.

That argument is correct about *TTL semantics* and does not follow to *storage*.
A cache that is never evicted is not a cache.

**Impact.** The row count is bounded by the number of distinct URLs that both
match `trusted_client_id_domains` and serve a valid document. For the profile
the documentation recommends — a named publisher, `*.vendor.example` — that is
small and the finding is theoretical. It stops being theoretical the moment a
tenant trusts shared hosting, which is a natural thing to do because shared
hosting is where a small tool publishes a JSON file: `*.github.io`,
`*.pages.dev`, an object-store domain. Any third party who can publish under
that domain can then mint unbounded client rows in that tenant, each of which
is a permanent write, at the cost of one unauthenticated request each. It
compounds with MCP-03: `*` makes every domain shared hosting.

**Recommended fix.** The cheap half is a quota: count `Cimd` beside `Dcr`
against a bound, refusing resolution above it. The complete half is eviction on
last-seen — a `last_resolved_at` stamp and a sweep that deletes rows nothing has
presented for a window, which is coherent with the cache argument rather than
against it, because a row deleted while its document is still published *is*
re-materialised on the next request, exactly as the comment says. That is the
behaviour a cache should have.

Not fixed here: it needs a schema field, a migration, a repository method and a
job registration, which is T21.5's shape of change rather than a review's.

---

## 5. MCP-05 — registration quota exhaustion denies registration for a month

**Severity: Medium. Filed as [#471](https://github.com/ilpanich/axiam/issues/471) (T21.4a).**

In `dynamic_registration: anonymous`, the quota is a per-tenant ceiling on rows
that anybody may create:

```rust
// crates/axiam-api-rest/src/handlers/dcr.rs:226
if existing >= u64::from(policy.dcr_max_clients) {
    return Err(DcrError::ClientQuotaExhausted { limit: policy.dcr_max_clients });
}
```

with `DEFAULT_DCR_MAX_CLIENTS = 20` and `DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS =
30`. The only control in front of it is the per-IP rate limit,
`dcr_per_min: 5`.

So: twenty registrations, four minutes from one address, and the tenant's
registration endpoint answers `ClientQuotaExhausted` to every legitimate client
until the sweeper runs — **thirty days later**, because a client that was never
authorized is swept on `created_at + ttl`. A handful of source addresses
removes the four minutes. Nothing about this requires a credential, and the
rows are cheap to make and expensive to wait out.

The quota is doing its job — it bounds storage, and that is what it was written
for. What is missing is that the same number is also the availability budget,
and one unauthenticated stranger can spend all of it.

**Also worth recording, and much less serious:** the quota check (step 4) and
the write (step 6) are separated by an `await`, so concurrent registrations can
overshoot the ceiling by the number in flight. Storage overshoot of a handful of
rows is not a finding on its own; it is noted because the same ordering is what
makes the denial above cheap to reach in bursts.

**Recommended fix**, in rough order of value:

1. **Sweep an unauthorized registration far sooner than an unused one.** A
   client registered and never authorized within, say, an hour is abandoned or
   hostile; a client that authorized once and went quiet for a month is what
   the 30-day TTL is for. These are different clocks and today they are one.
   This alone turns a month of denial into an hour.
2. A per-IP or per-subnet share of the quota, so that one source cannot hold
   all of it.
3. Documenting on `docs/admin/dynamic-client-registration.md` that `anonymous`
   mode's quota is reachable by strangers, and that `initial_access_token` mode
   has no such exposure — which is a real reason to prefer it that the page does
   not currently give.

Not fixed here for the same reason as MCP-04: the first item is a change to the
sweeper's policy and needs a settings field to be configurable, which is T21.4a's
surface.

`initial_access_token` mode is **not** affected: a caller holding no handle is
refused at step 2, before the quota is consulted.

---

## 6. MCP-01 — a loopback client on an ephemeral port is not told its errors

**Severity: Low. Filed as [#472](https://github.com/ilpanich/axiam/issues/472) (T21.2a).**

T21.2a introduced `redirect_uri_matches` and routed the authorization and PAR
endpoints through it, so that RFC 8252 §7.3's port allowance applies where a
`redirect_uri` is validated. Five sites in
`crates/axiam-api-rest/src/handlers/oauth2.rs` still ask the question with an
exact comparison instead:

```
oauth2.rs:565   Some(uri) if client.redirect_uris.iter().any(|r| r == uri)
oauth2.rs:663   …
oauth2.rs:734   …
oauth2.rs:791   …
oauth2.rs:1452  .filter(|client| client.redirect_uris.contains(candidate))
oauth2.rs:4554  if client.redirect_uris.iter().any(|r| r == uri)
```

Each decides *may this error be reported by redirecting?* For a client that
registered `http://127.0.0.1/callback` and is listening on
`http://127.0.0.1:49999/callback`, the answer is no, and the error is rendered
into the browser instead.

**I initially wrote this finding wider than it is, and the harness corrected
me.** The first probe used `response_type=token`, expecting it to take one of
those paths; it is redirected correctly, because that refusal is raised after
the matcher has already run. The finding is confined to refusals raised
*before* it — `response_type` absent entirely (`:1452`), and the `request_uri`
refusals (`:4554`). Both probes are in the harness, the negative and the
positive, so the boundary is pinned rather than described.

**Impact.** Fail-closed in the direction that matters: no error is ever
redirected to a URI that was not registered, so this is not an open-redirect
finding and the exact comparison is the safe error to make. What it costs is
interoperability, on exactly the client family this phase exists to serve. The
desktop client's loopback listener waits for a callback that never arrives and
eventually times out with nothing to report, while the user is looking at an
error page in a browser the client cannot read.

**Recommended fix.** Route the six sites through
`any_redirect_uri_matches`, which is the function that already answers this
question for the success path. The change is mechanical; it is filed rather
than made because those six sites sit in a 4,500-line handler file this task
otherwise does not touch, and a redirect-decision change belongs in a commit a
reviewer can see on its own.

Asserted as today's behaviour by
`mcp01_an_error_is_not_redirected_to_an_ephemeral_loopback_port`, which names
the fix in its failure message so that whoever makes it is told to invert the
test.

---

## 7. MCP-06 — the tenant-path query guard reads the raw query string

**Severity: Informational. Accepted.**

A `tenant_id` query parameter on a `/t/{T}` path is refused, which is the right
answer and closes the "two selectors that can disagree" question (V2). The
check is:

```rust
// crates/axiam-api-rest/src/middleware/tenant_path.rs:219
.query_string()
.split('&')
.any(|pair| pair == "tenant_id" || pair.starts_with("tenant_id="))
```

That is a match on the **raw** query string, while the extractor downstream
matches on the **percent-decoded** one. `tenant%5Fid=…` decodes to the key
`tenant_id` and is not caught here.

It is not exploitable, and the reason is the same structural property T21.3's
amendment 2 relied on: the middleware appends `&tenant_id={path tenant}`, so
the handler's extractor then sees two pairs decoding to one non-sequence field
and `serde_urlencoded` answers `duplicate field`. The request is refused with a
`400` — a different `400` from the intended one, with a less helpful message,
but a refusal.

Recorded rather than fixed because the fix (decode before comparing) puts a
decoder in front of a security check, which is the thing `redirect_uri.rs` and
`resource.rs` both argue against at length, to buy a better error message on a
request that is already refused. If it is ever fixed, the argument for it should
be the message and not the security.

**The refusal is now pinned** (#472,
`mcp06_a_percent_encoded_tenant_id_on_a_tenant_path_is_still_refused`). What
the acceptance rests on is the extractor's field type and a dependency's
duplicate-field behaviour, neither of which is a property of the guard — so
nothing the guard's own tests cover would notice if either changed, and no case
in the crate sent the encoded spelling. The test changes no behaviour and
deliberately does not pin the error *code*, which would pin the half of this
finding the acceptance leaves alone.

One correction to the paragraph above, found in writing that test. "The request
is refused with a `400`" is true only of a request that carries a credential:
authentication is refused before the query is deserialised, so a stranger
sending `tenant%5Fid=` gets a `401` and never reaches the extractor at all. The
acceptance is unaffected — the request is refused either way, and the `401` is
if anything the better answer — but the mechanism it names is observable only
behind a credential, and the test asserts both.

---

## 8. V1 — the loopback matcher does not widen the host

**Verified. No finding.**

`redirect_uri_matches` compares scheme, host, path, query, fragment, username
*and* password, and applies the port allowance only when the **registered** URI
is `http` on one of the three loopback hosts. The doubled guard is what makes
the classic attack uninteresting: `http://127.0.0.1@evil.example.com/callback`
fails on the host (`evil.example.com` ≠ `127.0.0.1`) *and* on the userinfo
(`127.0.0.1` ≠ empty).

Every candidate the plan's brief named was driven against the live authorization
endpoint, not against the function:

| Candidate | Refused because |
|---|---|
| `http://127.0.0.1@evil.example.com/callback` | host, and userinfo |
| `http://localhost.evil.example.com/callback` | host is compared whole, never by suffix |
| `http://evil.example.com/callback` | host |
| `http://127.0.0.1:8080/callback/../../evil` | `url` resolves dot segments, so the path differs |
| `http://127.0.0.1:8080/%63allback` | the serialised path keeps the two spellings distinct — under-matching, which fails closed |
| `https://127.0.0.1:8080/callback` | `https` never takes the allowance (I6) |
| `http://[::1]:8080/callback` | the three loopback hosts are not interchangeable |

One consistency note, not a finding: the matcher accepts `[::1]` as a loopback
host, and T21.4a's own tests record that **no** `[::1]` redirect URI can be
registered through either endpoint today. The matcher's `[::1]` arm is therefore
unreachable. T21.4a has already filed that; it is repeated here only so the two
records agree.

Asserted by `v1_the_loopback_allowance_does_not_widen_the_host`.

---

## 9. V2 — tenant isolation holds under path issuers

**Verified. No finding.** This was the plan's highest-severity area and the one
I expected to yield.

The exposure is real and T21.6's amendment 2 states it exactly: the JWKS is
shared, so tenant `A`'s token verifies as a signature when presented on tenant
`B`'s path. Two checks close it, and both are in the right place.

`enforce_issuer` (`axiam-auth/src/token.rs:1561`) refuses a token whose `iss`
names a tenant that its `tenant_id` claim does not, so a token cannot be
internally ambiguous. It is a no-op with the flag off, where `jsonwebtoken`'s
pinned-issuer check is kept verbatim — so I1 holds by construction rather than
by assertion.

`enforce_tenant_path_binding` (`axiam-api-rest/src/extractors/auth.rs:933`)
refuses a principal whose tenant is not the tenant the path named. It sits in
`extract_user`, which is the funnel **both** arms of the extractor pass through
— the cached-identity arm and the fresh-parse arm each call it — so a route
mounted under the scope later inherits it. Placing it after the decode rather
than in the scope middleware is correct for the stated reason: the middleware
cannot decode a token.

Attacked, against live routes:

* A tenant-`A` token on `/t/{B}/oauth2/userinfo` → `401`, the same refusal an
  uncredentialed request gets, so the holder is not told tenant `B` exists.
* `/t/{A}/oauth2/authorize?tenant_id={B}` → `400 invalid_request`, refused by
  the scope middleware before any handler runs.
* The control — a tenant-`A` token on `/t/{A}` — passes, so the two refusals
  above are refusals and not a route that never worked.

Two further things checked while here, neither a finding:

* **Introspection is tenant-scoped.** `introspect_token` compares the token's
  `tenant_id` against the request's and answers `active: false` when they
  differ (`axiam-oauth2/src/token.rs`, the `token_tenant != tenant_id` arm), so
  the shared key set does not make introspection a cross-tenant read. This is
  the place I expected the shared JWKS to leak and it does not.
* **The tenant scope mounts the OAuth2 endpoints only**, not `/api/v1`, so the
  organization-level tenant header — which resolves *after*
  `enforce_tenant_path_binding` has run against the token's home tenant — does
  not meet the path selector on any route today. Worth knowing before anybody
  mounts an API route under `/t/{tenant_id}`: the binding is checked against
  the principal's home tenant, and the header can move the effective tenant
  afterwards. Not reachable now; a note for whoever widens the scope.

Asserted by `v2_a_tenant_path_binds_the_token_to_that_tenant`.

---

## 10. V3 — the SSRF guard, and single-use under concurrency

**Verified. No finding.**

### SEC-094 is closed on the path CIMD actually uses

The plan asked specifically whether `to_canonical()` is on the path used, since
the guard once failed to fold IPv4-mapped IPv6 and *pinned* the attacker's
address into the connection. It is, and the implementation is better than the
one-line fix the earlier review proposed:

```rust
// crates/axiam-pki/src/ssrf.rs:339
IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
    Some(v4) => is_disallowed_ipv4(v4),          // ::ffff:a.b.c.d
    None => { if is_ipv4_compatible_v6(v6) { return true; }  // ::/96
              is_disallowed_ipv6(v6) }
}
```

`::/96` is handled by hand because `to_canonical` does *not* fold it — a detail
the one-line fix would have missed.

The properties that matter, each confirmed by reading `resolve_and_pick` and
`guarded_fetch_with_cap`:

* **Every** resolved address is classified, not just the one dialled
  (`addrs.iter().find(|ip| is_disallowed_ip(**ip))`), so an `A`/`AAAA` pair with
  one good and one bad answer is refused rather than resolved past.
* **Rebinding between check and connect is closed by pinning**: the validated
  address goes into `ClientBuilder::resolve()` and the client is built fresh per
  fetch, with no pooling across requests.
* **Redirects are re-validated per hop and never followed automatically**
  (`Policy::none()`, manual re-issue), and the test seam is honoured on the
  first hop only — `hop_allow_private = allow_private && hop == 0` — so
  `cimd.allow_http` cannot be turned into "redirect me to `169.254.169.254`".
* **Bounds are each enforced and each tested** by T21.5: `https`-unless-
  `allow_http`, a 10-second client timeout, a `Content-Length` gate plus a
  *streaming* cap at `max_metadata_bytes`, and a JSON content-type check.

**Ordering is right, which is the thing most easily got wrong.**
`cimd::resolve` runs `validate_client_id_url` — which includes the
`trusted_client_id_domains` check — *before* `cache.get_or_fetch`. An
untrusted host is never contacted. That is what makes MCP-03 a policy finding
rather than an unauthenticated-SSRF finding.

### The initial access token is single-use under concurrency

`consume_by_token_hash` is a conditional update, not a read-then-write:

```sql
UPDATE oauth2_registration_token SET used_at = $now
 WHERE token_hash = $token_hash AND tenant_id = $tenant_id
   AND used_at IS NONE AND expires_at > $now
```

and `register_inner` spends it **before** writing the client, which is the
order that makes the guarantee hold (the handler's own comment argues this, and
the argument is correct: the reverse order leaves a window in which two
registrations on one handle both create a client).

Driven rather than assumed: four registrations on one handle, built up front and
polled together, produce exactly one `201`. Honest about the limit — the actix
test runtime is single-threaded, so these interleave at `await` points rather
than across cores. That is still the window a two-phase implementation opens,
because that window *is* an `await`; it is not a proof against a multi-node
deployment, where the guarantee rests on SurrealDB's transaction semantics for
the statement above.

Asserted by `v3_an_initial_access_token_survives_concurrent_redemption`.

### The sweeper deletes only what it should

Checked against the plan's question directly. `list_all_by_managed_by` filters
`WHERE managed_by = $managed_by` in the query rather than in Rust, so `admin`
and `cimd` rows are never even read. `ttl_days == 0` is never due. A tenant
whose settings cannot be read is skipped — the fail-closed direction for a
sweep that deletes. A per-row delete failure is logged and the sweep continues,
which is right because the next row may be another tenant's.

### The DCR host glob is anchored

`host_glob_matches` requires the byte before the matched suffix to be `.`:

```rust
return host.len() > suffix.len() + 1
    && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
```

so `evil-example.com` does not match `*.example.com`, which is the failure the
plan asked about and the reason this is not `ends_with`. A pattern with `*`
anywhere but the whole leftmost label matches nothing at all — fail-closed.

---

## 11. What I did not find, and where I would look next

This review did not reach: the CIMD document-validation rules beyond the fetch
bounds; the two admin UI surfaces; the frontend `returnTo` validation T21.6
amended; and the interaction between the `managed_by` consent lane and W7's
sensitive-scope records, which T21.4a's amendments 1 and 3 reason about
carefully and which I read but did not attack.

The one I would give to the next reviewer is the last. Two consent lanes
writing into one namespace (`oidc_scope_release:<client_id>`), distinguished by
a version string, is a design whose correctness rests on a prefix never
colliding. The amendment argues the prefix cannot collide and I believe the
argument; I did not try to make it.

---

## 12. Invariants

Checked against §1 of the plan, for this task's own change:

* **I1** — the MCP-02 fix refuses a value no stored row can contain, since
  `allowed_resources` ships unreleased. Every existing request takes the path it
  took before. The regression gate is green.
* **I2** — untouched; a request without `resource` still mints
  `axiam:user` / `axiam:m2m`, asserted unchanged by `resource_indicators_test`.
* **I3** — strengthened, not relaxed: the fix removes the one way a resource
  indicator could reach the built-in audiences. The harness asserts the refusal
  at `/api/v1/auth/me` on every one of its four end-to-end runs.
* **I5** — untouched. No FAPI behaviour changed and the runbook needs no
  amendment.
* **I8** — no new crate edge; `scripts/check-crate-layering.py` clean.
* **I9** — no new route.

No existing test's expectation was changed by this task.


---

## 13. Appendix — the I1 conformance condition, discharged

The plan's §1 records the maintainer's ruling of 2026-09-17 and the one
condition attached to it: T21.2's unconditional `none` in
`token_endpoint_auth_methods_supported` is acceptable **provided it does not
impact the OIDF conformance tests (Basic OP and FAPI 2.0)**. §1 records the
condition as undischarged and assigns it to this task, ahead of everything
else. This appendix discharges it.

### The suite could not be run, and this is not that

There is no Docker daemon running in this sandbox, but — contrary to the
environment notes carried into this task and into two earlier documents in this
series — **`dockerd` starts**, and did. What stops the run is one hop further
on: `registry.gitlab.com` serves the pinned manifest, and its blob CDN,
`cdn.registry.gitlab-static.net`, is refused by this environment's egress
policy with a `403` on `CONNECT`. Per the proxy's own guidance an organization
policy denial is reported rather than retried or routed around, so the image
could not be pulled and no plan was executed.

That correction is worth recording on its own: "no Docker daemon" has been
repeated as a settled fact and is only half true, and the half that is false is
the half a future session would waste time rediscovering.

### What was done instead, and why it is stronger than a run

The suite is open source and the pin is a release tag. The module's source at
exactly `release-v5.2.4` — the version `conformance/suite.env` pins — was read
from `gitlab.com`, which the egress policy does allow. That is a better answer
than a green run, because a run shows the module passing on one configuration
while the source shows **why**, for every configuration.

The chain, module to assertion:

1. `FAPI2SPFinalDiscoveryEndpointVerification.performEndpointVerification()`
   delegates to its abstract parent for everything about client-authentication
   metadata.
2. `AbstractFAPI2SPFinalDiscoveryEndpointVerification` makes exactly one check
   of the field in question:

   ```java
   callAndContinueOnFailure(profileBehavior.getDiscoveryTokenEndpointAuthMethodsCheck(),
                            Condition.ConditionResult.FAILURE, "FAPI2-SP-FINAL-5.3.2.1-6");
   ```
3. All three of AXIAM's plans set `"fapi_profile": "plain_fapi"`, so
   `profileBehavior` is the base `FAPI2ProfileBehavior`, whose
   `getDiscoveryTokenEndpointAuthMethodsCheck()` returns
   `CheckDiscEndpointTokenEndpointAuthMethodsSupportedContainsPrivateKeyOrTlsClient`.
4. That condition supplies an **accepted** list and nothing else:

   ```java
   protected List<String> getAcceptedAuthMethods() {
       return List.of("private_key_jwt", "tls_client_auth");
   }
   ```
5. Its parent evaluates `validate(env, …, getAcceptedAuthMethods(), 1, …)`, and
   `AbstractValidateJsonArray.validate` counts how many of the **accepted**
   values appear in the server's array and fails only if that count is below
   the minimum:

   ```java
   if (countMatchingElements(setValues, serverValues.getAsJsonArray()) < minimumMatchesRequired) {
       errorMessage = errorMessageNotEnough;
   }
   ```

`countMatchingElements` iterates the *accepted* list looking into the server's
array. **It never iterates the server's array looking for values that are not
accepted.** An extra entry is therefore not merely tolerated; it is
structurally invisible to this condition. AXIAM advertises `tls_client_auth`
and `private_key_jwt`, so the count is 2 against a minimum of 1, and `none`
cannot change that number.

The variant-specific checks are the same shape:
`EnsureServerConfigurationSupportsMTLS` and
`EnsureServerConfigurationSupportsPrivateKeyJwt` both scan for a method they
require and throw only when they find none.

### The two other ways it could have objected, both closed

* **`ValidateServerMetadataAgainstSchema`** runs at `FAILURE` severity, so a
  schema enum on the field would have been the second way to fail. There is
  none: `json-schemas/rfc8414/oauth_authorization_server_metadata.json` gives
  `token_endpoint_auth_methods_supported` as
  `{"type": "array", "items": {"type": "string"}}`. The condition's own doc
  comment says it is "purely structural (types/formats of whatever fields are
  present)" and it strips unknown-property errors before failing.
* **`CheckForUnexpectedParametersInServerMetadata`** is `WARNING`, not
  `FAILURE`, and concerns member *names* rather than values. Checked anyway for
  the members this phase adds: `registration_endpoint` **and**
  `client_id_metadata_document_supported` are both in the schema's
  `properties`, so neither produces even a warning on a tenant that enables
  them.

### Conclusion

`none` in `token_endpoint_auth_methods_supported` **cannot** cause
`fapi2-security-profile-final-discovery-end-point-verification` to fail, on any
of AXIAM's three plans, at the pinned suite version. This is a property of the
condition's implementation rather than an observation of one run, so it holds
for the Basic OP plan too — that plan does not run this module at all, and
nothing in it asserts on the field.

The maintainer's condition is **discharged**, on source-level evidence. §1's
standing caveat — that the existing evidence was circumstantial because `none`
is "not a weak credential but the absence of one, and a check could single it
out" — is answered directly: no check singles out anything, because no check
looks at what the server advertises beyond the values it requires.

**What a maintainer with a working registry should still do**, and what to look
for: run

```bash
conformance/scripts/run-some.sh \
  conformance/plans/fapi2-security-profile-final-mtls.json \
  fapi2-security-profile-final-test-plan \
  fapi2-security-profile-final-discovery-end-point-verification
```

for each of the three plans, and confirm `FINISHED / PASSED`. The log entry to
read is `Contents of 'token_endpoint_auth_methods_supported' in discovery
document matches expectations`, whose `actual` will list all six advertised
methods and whose `minimum_matches_required` will be `1`. If it ever reports
otherwise, the suite's condition has changed and this appendix is the thing to
re-derive.
