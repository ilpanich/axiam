# F4 — Consolidated security review of the B-track (2026-08-10)

> **Scope:** the features the B and A tracks added after the 2026-08-04 close of
> [`security-analysis-2026-08-02.md`](security-analysis-2026-08-02.md). That
> document's §24 closed it at the pre-B-track HEAD, so none of the work below
> had been reviewed by it — five mentions of B-track vocabulary in 209 KB of
> text, all incidental.
>
> **Reviewer:** Opus 5, per the F4 model recommendation.
>
> **Verdict:** one finding to fix (SEC-088), two to decide on (SEC-089,
> SEC-090), one accepted residual restated with its bound (SEC-091). Nothing
> found is remotely exploitable today; SEC-088 is a latent type confusion that
> becomes exploitable the moment someone writes the first consumer of a surface
> that is currently unused, which is precisely when it is cheapest to fix.

---

## 1. What was reviewed, and how

F4's brief names seven surfaces. One of them was never built, so this review
covers six.

| Surface | Task | Files | Depth |
|---|---|---|---|
| Token exchange | B3 | `crates/axiam-oauth2/src/token_exchange.rs` (544 ln) | **read in full** |
| Device authorization grant | B2 | `device.rs` (280), `device_service.rs` (364) | **read in full** |
| Back-channel logout / RP-initiated logout | B5 | `logout.rs` (446) | read in full |
| PAR | B5a | `par.rs` (295) | sampled |
| Deny-override engine | B1 | `crates/axiam-authz/src/engine.rs` (1120) | sampled — see §6 |
| AMQP TLS (`amqps://`) | A6 | `crates/axiam-amqp/src/{connection,config}.rs` | sampled |
| gRPC strict revocation | A4 | `crates/axiam-api-grpc/src/services/authorization.rs` | sampled |
| SCIM 2.0 | B4 | — | **not implemented; out of scope** |

"Sampled" means the security-relevant paths were read and the invariants
checked, but not every branch. §6 states honestly what that leaves open, because
a review that does not say where it stopped is asking to be over-trusted — which
is the same failure mode as a green test suite over code nothing calls
(CONTRACT §16.7, and the reason that clause exists).

---

## 2. SEC-088 — token exchange mints a token whose `sub_kind` contradicts its `sub`

**Severity: medium (latent — no consumer today). Fix before the first consumer
lands.**

`TokenExchangeService::exchange` rewrites the subject kind whenever the target
audience is the machine audience, while passing the subject's `sub` through
untouched:

```rust
// crates/axiam-oauth2/src/token_exchange.rs:369-377
let sub_kind = if audience == AUD_M2M {
    SubjectKind::OAuth2Client
} else {
    subject.sub_kind
};

let access_token = issue_exchanged_token(
    &subject.sub,   // <-- unchanged: still the USER's UUID
    sub_kind,       // <-- now claims to be an OAuth2 client
    …
```

The REST extractor documents the invariant this breaks, in the same repository:

```rust
// crates/axiam-api-rest/src/extractors/auth.rs:129-135
/// **Its meaning depends on which principal obtained the token**, so do not
/// treat it as an OAuth2 `client_id` without checking `claims.sub_kind`:
///
/// * `sub_kind = oauth2_client` → the OAuth2 `client_id` (`oa_…`) …
/// * `sub_kind = service_account` → the service-account **UUID** …
```

So the contract is *"`sub_kind` tells you how to interpret `sub`"*, and token
exchange produces the one combination the contract says cannot occur: a user
UUID labelled `oauth2_client`. A consumer that follows the documented rule — the
correct thing to do — will look up a user UUID in the OAuth2 client table.
Best case that is a not-found. Worst case it is whatever a future
`client_id`-keyed lookup does with an attacker-influencable string.

Nothing consumes `AuthenticatedServiceAccount` today; the extractor's own doc
comment says so, and that is why this is medium rather than high. It is also why
it is cheap: the rename in §17.2 residual 7 was justified with *"no route
consumes this extractor today, so the rename is free — which is why it happens
now rather than after something depends on it."* The identical argument applies
here, and the same window is still open.

**Why the rewrite exists at all** is worth keeping: the common case is narrowing
a user token to an M2M token so a service can call a machine API, and the
audience genuinely changes. The bug is not the audience change — it is
relabelling the *subject* to match the audience. Those are two different
questions and the code conflates them.

**Recommended fix.** Leave `sub_kind` as `subject.sub_kind` unconditionally, and
let the audience alone carry the "this is for the machine API" fact. If a
downstream consumer really needs to know that a token reached the M2M audience
by exchange rather than by client-credentials, that is what `act` and the audit
record are for — and for impersonation, the audit record is already documented
as the only surviving evidence (`token_exchange.rs:86-96`).

**Regression test to add:** exchange a user token to `aud=axiam:m2m`, decode the
result, and assert `sub_kind == User` and `sub == <user uuid>` — i.e. that the
pair remains self-consistent. Name it after what it stops.

---

## 3. SEC-089 — the exchange audience allow-list is the client's `redirect_uris`

**Severity: low-medium. A decision, not obviously a defect.**

```rust
// crates/axiam-oauth2/src/token_exchange.rs:331
if !is_builtin_audience(t) && !client.redirect_uris.iter().any(|u| u == t) {
    return Err(OAuth2Error::InvalidTarget(…));
}
```

The reasoning given — *"an unconstrained `aud` would let a service mint tokens
addressed at systems it has no relationship with — the mesh equivalent of an
open redirect"* — is right, and having *an* allow-list is the important part.
The concern is which list.

`redirect_uris` is a browser-callback list. Its entries are added for the
authorization-code flow, they are reviewed as *"where may this client send a
user's browser"*, and adding one is routine and low-privilege. Reusing it as the
token-audience allow-list means that a change reviewed under one question
silently answers a second, more sensitive one: *"for whom may this client mint
tokens"*. The two lists also drift for ordinary reasons — a client that stops
using the browser flow would have its redirect URIs pruned, and would lose
exchange targets as a side effect nobody predicted.

**Options, in preference order:**

1. Add a distinct `allowed_token_targets` (or `resource_indicators`) column to
   the client registration. One migration, and the review question matches the
   privilege granted.
2. Keep the reuse and make it loud: name it in the OpenAPI description of the
   grant and in `docs/api/token-exchange.md`, in the operator's words — *"adding
   a redirect URI also authorises it as a token audience"*.

Doing neither leaves an operator with a true belief that they edited a callback
list and a false belief about what else changed.

---

## 4. SEC-090 — an impersonation exchange resets the actor-chain depth bound

**Severity: low.**

The chain bound is checked on the way in:

```rust
// token_exchange.rs:259-266
if let Some(act) = subject.act.as_ref()
    && act.depth() >= MAX_ACT_CHAIN_DEPTH
{ … refuse … }
```

and the new `act` is built only for delegation:

```rust
// token_exchange.rs:364-367
let act = actor_sub.as_ref().map(|actor| ActClaim {
    sub: actor.clone(),
    act: subject.act.clone().map(Box::new),
});
```

For impersonation `actor_sub` is `None`, so `act` is `None` and the subject's
existing chain is dropped. Dropping it is *correct* for impersonation — the
whole point is a token indistinguishable from one the subject obtained directly,
and `token_exchange.rs:86-96` says so. But it also means the depth counter
resets: delegate to the cap, impersonate once, delegate to the cap again.

The practical bound is that impersonation requires `MAY_IMPERSONATE_GRANT`, so
this is not reachable by a client that only has the exchange grant. And the
lifetime cap (`subject_remaining.min(max_lifetime_secs)`, line 354) still
applies at every hop, so a longer chain buys no additional lifetime. What is
lost is only the *audit linkage* — which the impersonation path already
documents as living in the audit record instead.

**Recommendation:** no code change. Add a sentence to
`claude_dev/token-exchange-design.md` saying the depth bound is per unbroken
delegation chain and that impersonation deliberately starts a new one, so the
next reader does not discover it as a surprise.

---

## 5. SEC-091 — an exchange does not consult revocation (restated residual)

**Severity: accepted residual. Bounded — recorded so it is not rediscovered as
new.**

`decode_access_token` (`crates/axiam-auth/src/token.rs:539`) validates
signature, issuer, audience membership and `exp`, with 60 s leeway. It performs
no revocation lookup, by design — that is the standing posture for access tokens
across the product, with strict revocation offered as the A4 gRPC opt-in.

Token exchange inherits that posture, so a logged-out-but-unexpired access token
can still be exchanged. Two things bound the consequence, and both are already
in the code rather than aspirational:

* **Lifetime cannot be laundered.** `lifetime = subject_remaining.min(max)`
  (line 354) means the exchanged token dies no later than its subject would
  have. An exchange cannot outlive the revoked credential's original expiry.
* **Privilege cannot be widened.** `narrow_scopes` (line 128) intersects
  requested ∩ subject ∩ client, refusing rather than silently dropping.

So the window is "≤ the subject's remaining lifetime, at ≤ the subject's
privilege" — the same window a revoked access token already has everywhere else.
This is not a new exposure introduced by B3; it is the existing one, unchanged.

**Recommendation:** state it in `docs/security-profiles.md` alongside the
existing access-token revocation posture, so an operator evaluating token
exchange sees the bound without having to derive it. If A4-style strict
revocation is ever extended beyond gRPC, the exchange path should be on the list
of call sites.

---

## 6. Surfaces reviewed without findings, and what "no findings" means here

**Device authorization grant (B2) — no findings.** This is the strongest code in
the B-track and the brute-force surface F4 asked about is genuinely closed:

* `device_code` is 256 bits of CSPRNG (`device.rs:87-93`), stored only as
  SHA-256. Not guessable, and the choice of SHA-256 over a KDF is justified
  correctly — there is no offline-guessing threat against a 256-bit random
  string, and the poll path runs every few seconds by design.
* `user_code` is 8 characters over a 20-symbol confusable-free alphabet
  (`device.rs:42-45`) ≈ 34.6 bits, comfortably above RFC 8628 §5.1's floor.
* The poll interval is enforced **before** the grant state is examined
  (`device_service.rs:198-220`), so a device cannot outrun `slow_down` by being
  in a lucky state. The comment says exactly that, and the code does it.
* Unknown and already-redeemed device codes collapse to the same
  `invalid_grant` (`device_service.rs:222-227`) — no oracle for which codes have
  existed.
* Redemption is atomic and the check is *"this statement redeemed it"* rather
  than *"status was approved a moment ago"* (`device_service.rs:249-256`), which
  is the right shape for a concurrent double-poll.
* An approved grant with no subject is refused as a server error rather than
  minting a token for nobody (`device_service.rs:257-262`).

**Back-channel logout (B5) — no findings.** AXIAM is the *issuer* of logout
tokens here, so RP-side validation is out of scope. The two things an issuer can
get wrong are both handled and both tested: the `events` member is present and
exact (`logout.rs:63-69`, test at :236), and `nonce` is absent — its presence is
how an ID token gets accepted as a logout token, and Back-Channel Logout 1.0
§2.4 forbids it (test at :251, asserting on the serialized JSON rather than on
the struct, which is the assertion that actually catches it).

**What "no findings" does not mean.** PAR, the deny-override engine, AMQP TLS
and the gRPC strict-revocation interceptor were **sampled, not exhausted**. For
those four, "no findings" means "nothing found in the paths read", and the
deny-override engine in particular is 1120 lines of precedence logic where the
failure mode is a privilege escalation that no amount of reading reliably
catches. It has its own design document with a precedence table
(`claude_dev/deny-override-design.md`) and a property-test suite; **a dedicated
review pass against that table, not another read-through, is the right next
step** and is recorded here as outstanding rather than quietly counted as done.

---

## 7. Disposition

| ID | Finding | Severity | Action |
|---|---|---|---|
| SEC-088 | Exchange mints `sub_kind`/`sub` mismatch | Medium (latent) | **Fix** — drop the rewrite, add the self-consistency test |
| SEC-089 | Audience allow-list reuses `redirect_uris` | Low-medium | **Decide** — separate column, or document loudly |
| SEC-090 | Impersonation resets the actor-chain bound | Low | Document in the design doc |
| SEC-091 | Exchange does not consult revocation | Accepted | Document the bound in `security-profiles.md` |
| SEC-092 | Unrecognised grant `effect` read back as `allow` | Low | **Fixed** — the grant is dropped; see §8 |
| — | Deny-override engine (B1) | — | **Closed** by the §8 precedence pass |

None of these block the already-merged B-track. SEC-088 should be fixed while
the surface it corrupts is still unused, which is the only reason it is cheap.

---

## 8. Addendum — the deny-override precedence pass (2026-08-10)

§6 recorded the B1 engine as *sampled, not exhausted*, and said a dedicated pass
against the precedence table — not another read-through — was the right next
step. This is that pass. It is recorded here rather than in a new document
because it closes an item this review opened.

### 8.1 The table is enforced. The tests for it were in the wrong place.

Every row of `deny-override-design.md` §2.2 is correctly implemented, and
`evaluate_grants` is a clean one-pass deny-short-circuit whose result provably
does not depend on scan order. No precedence defect was found.

But the *tests* for rows 3, 4, 7 and 8 all lived in `engine.rs`'s unit module,
against `evaluate_grants` — a function that takes the applicable role IDs as an
argument. Those four rows are claims about a layer that function never runs:
that a deny arriving through the hierarchy, through a group, or through a global
role is *applicable* and reaches the evaluator at all. The unit test for row 4
even says so in its own comment ("the ancestor-scoped role carries the deny"),
then constructs two role IDs that are applicable by construction.

**Demonstration, not argument.** Delete the ancestor clause from
`applicable_role_ids` — a one-line change that silently drops every inherited
deny:

```
--- integration ---   3 failed  (2 of them the new deny-override rows)
--- unit ---         72 passed
```

Row 4 inverts from `DeniedByRule` to `Allow` — a privilege escalation — and the
entire unit suite stays green. That is the shape of gap §6 predicted, found by
attacking the tests rather than the code.

**Closed by** seven end-to-end tests in
`crates/axiam-authz/tests/authz_engine_test.rs` covering rows 3, 4, 5, 7, 8,
§2.3's scope interaction, and batch-vs-single equivalence. All seven fail when
the deny short-circuit is disabled; two fail under the applicability mutation
above.

The batch case is worth naming separately: `evaluate_batch` re-derives
applicability from its own coalesced lookups rather than calling `check_access`,
so it is a genuinely independent traversal of the same table. It asserts
equality against the single path rather than against a literal, so the two
cannot drift even if both change.

### 8.2 SEC-092 — an uninterpretable grant read back as permission

`PermissionGrantRow::try_into_grant` mapped an **unrecognised** `effect` to
`PermissionEffect::Allow`. The comment defending that choice weighed exactly two
options — fail the read, or default to allow — and picked the second because the
first takes authorization down over one bad row. Both are worse than the third
option it did not consider.

`from_wire` trims and lowercases, so casing is *not* how this happens; the
realistic paths are a truncated write, a row edited outside the API, and — the
one worth planning for — a **rolling upgrade in which a newer node writes a
third effect** an older node cannot parse. Under the old default every such
grant read back as an allow on the old node: deny-override defeated by version
skew.

Defaulting to `Deny` is not the fix either. In this engine `Deny` is not "ignore
this grant", it is an active override that masks the action for every holder of
the role — one malformed row would revoke access tenant-wide.

**Fixed** by dropping the grant (`Ok(None)`): it contributes neither an allow nor
a deny, the decision falls through to the remaining grants and ultimately to
default-deny, and the row is logged at `error` rather than `warn`, because
reaching that branch means the datastore was written outside both the API
validator and the v25 schema `ASSERT`.

Severity is **low**: the write path and the schema constraint both reject these
values, so no supported path produces one today. It is recorded because the
*direction* of the old default was wrong, and because the version-skew case is a
future this design should not have to be lucky about.

### 8.3 Two things deliberately left alone

- **`unwrap_or(&empty_ancestors)` in `evaluate_batch`.** If the coalesced
  ancestors lookup ever missed, an ancestor-scoped deny would be silently
  dropped — a widening fallback. It is unreachable today (the same `has_roles`
  filter gates both the population loop and the consumer), so changing it would
  be an untestable edit to a live authorization path. Named here so the next
  person to touch that filter knows what it is holding up.
- **`grants_by_role` is keyed by bare `role_id` across tenants** in the batch
  path, while the dedup set is keyed by `(tenant_id, role_id)`. A cross-tenant
  batch therefore rests on UUIDv4 uniqueness rather than on the key. Not a
  finding — a collision is not a thing that happens — but the isolation
  invariant is stated in the wrong place, and a future non-random ID scheme
  would make it a real one.
