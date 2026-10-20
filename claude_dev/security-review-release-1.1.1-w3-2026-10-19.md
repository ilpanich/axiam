# Security review — release 1.1.1, wave W3 (F4)

**Date:** 2026-10-19.
**Against:** `claude/release-1.1.1-w3`, the whole wave diff
`origin/main..71c4ee193` (`main` at `6b15aa36a`; 12 commits, 47 files, 2 691
lines added and 239 removed). Every commit carries a signature (`gpgsig` header
in 12 of 12; the sandbox has no `gpg.ssh.allowedSignersFile`, so `%G?` cannot
verify them here).
**Scope:** every W3 task of the release-1.1.1 plan (§4):

| Task | Issue | Commit(s) | What |
|---|---|---|---|
| W3.1 | #675 (3) | `159565de5` | the admin `PUT` makes a confidential device-only client public, clearing its secret |
| W3.2 | #712 | `502ee243c` | the confidential-grant count reads the live tenants once |
| W3.3 | #676 | `430c4021a` | the `rate_limit_bucket` sweep's cutoff on the datastore clock; v109 index |
| W3.4 | #678 | `bb3a741ff` | a hint-cap count whose conflict outlives the retries refuses (`slow_down`) |
| W3.5 | #679 | `306b4a92e` | every refusal of a client-credential check costs one verify |
| W3.6 | #680 | `1ffc71385` | the admin `PUT` refuses a grant registration would refuse on a `dcr`/`cimd` row |
| W3.7 | #681 | `e0b4bf0bb`, `7a9b002ca` | device tokens carry `client_id`, `ConsoleSignIn`; a public DPoP client's refresh token bound to its key (v109 field) |
| W3.8 | #683 | `74b56fdda` | `/device_authorization` resolves `client_id` from body, header or assertion; JSON parse errors |
| W3.9 | #705 | `0e6ab8d31` | a UMA resource server sees only the resource sets it registered (T-488) |
| W3.10 | #677 | `f5bc5bc6d` | "a leaked device code is worth nothing" reworded |
| W3.11 | #684 | `71c4ee193` | text and hygiene; spec regenerated |

**Method:** the method and severity scale of the 1.1.0 wave reviews
([`security-review-release-1.1.0-w3-2026-10-15.md`](security-review-release-1.1.0-w3-2026-10-15.md)).
Adversarial reading of the diff and of every sibling path it implies, against
[`threat-model-stride.md`](threat-model-stride.md) and `Axiam.json` (model
2.42.0, now 488 threats), the plan's §10 rules, RFC 6749 §2.3, RFC 7521 §4.2,
RFC 8628 §3.1/§3.4/§5.6, RFC 9068 §2.2, RFC 9449 §5, UMA 2.0 Federated
Authorization §3–§4, and the OWASP ASVS 5.0 areas the diff touches (V2
anti-automation, V6 authentication, V7/V9 session and tokens, V8
authorization, V16 logging). Every commit message was read in full and its
claims are answered in §3 … §11. Claims were checked against the code; the
OpenAPI document was regenerated from the head and compared byte for byte; the
full test binaries of every crate the wave touched were run (§14). Two probes
were run and removed, not committed (§14). This review fixes nothing. Every
Low and Informational finding is filed on milestone `1.1.x` (§15). IDs:
`R111W3-nn`.

The maintainer has not commented on any of the wave's issues (#675 … #684,
#705, #712 read on 2026-10-19), so every §11 default applies: D-4 yes (W3.1),
D-6 yes (W3.7).

---

## 0. Summary

**No Medium or higher. Two Low, two Informational.**

The wave does what its eleven issues ask, on the paths they name, with the
tests they name. The two Opus tasks (W3.1, W3.7) are sound in what they
enforce; the one Low on them is about what the conversion *leaves behind*.

| ID | Finding | Severity | Surface → threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R111W3-01** | The #675 conversion leaves the client's outstanding refresh tokens (and pending device grants) live. A token issued while the client was confidential could be redeemed only with the secret; after the `PUT` it refreshes on `client_id` alone, for anyone holding it, for the rest of its rotating life. The guide presents "a client not registered for DPoP keeps its refresh tokens" as a convenience and does not say that their protection changed. Confirmed by probe (§3.3). | **Low** | `oauth2_clients.rs::update`, `token.rs::handle_refresh_token` → T-289, T-254 | wave (W3.1) | Issue #749 |
| **R111W3-02** | `/uma2/perm` mints a permission ticket for any resource of the tenant that declares the scope — another resource server's set, or one made through `/api/v1/resources` — and its `201`/`400` answer tells a resource server which ids exist and which scopes they declare. W3.9's guide sentence "a resource server sees only what it registered" and T-488's "indistinguishable" hold for `/uma2/rreg` only. Tickets for administrator-made resources are relied on by `uma_test.rs`, so the fix is a decision. | **Low** | `uma.rs::request_ticket`, `handlers/uma.rs::permission_request` → T-488 | pre-existing; W3.9's text overstates | Issue #745 |
| R111W3-03 | The admin `PUT` on a `dcr`/`cimd` row still widens two members that registration bounds: `allowed_resources` beyond the tenant's `external_client_allowed_resources` (D3, "the single most important line" of `dcr::validate`) and `redirect_uris` beyond `dcr_allowed_redirect_hosts`. W3.6 bounded grants and #636 scopes. | Informational | `oauth2_clients.rs::update` → T-289 | pre-existing (W3.6's sibling) | Issue #746 |
| R111W3-04 | Text and hygiene: an implementation note in the public schema (W3.8); "a `dcr`/`cimd` row can never be device-only" (W3.6) is false for a row an administrator gave the device grant before #680; "the two approval endpoints answer it `403`" holds only for a device token whose audience is `axiam:user`; T-424's "the datastore's clock" is one clock only for the shipped single-node SurrealDB; no `EXPLAIN` pin guards the v109 index the sweep relies on. | Informational | various | wave | Issue #747 |

**What held** (each is argued in its section):

* **W3.1 × W3.7 (§3).** Fail-closed on an unbound refresh token of a public
  DPoP-bound client is right; binding on first use would bind a stolen token to
  its thief. The cost is stated in both guides. A converted client that is not
  DPoP-bound is unaffected by W3.7 — but not "safe" in the sense the guide
  implies (R111W3-01).
* **W3.7 (i) (§4).** No route newly admits a device token. Every
  session-validated route answers it `401` as before; the two device routes now
  `403`; the CIBA approval routes `401`. The one widened acceptance — a device
  token as `actor_token` presented by its own client — matches the code grant's
  and the documented #518 rule.
* **W3.7 v109 (§5).** Additive; the two scope tests pin the whole migration;
  the refresh rotation copies the binding to the successor; the refusal comes
  before the token is consumed, so a thief's wrong-key attempt neither spends
  the token nor triggers the family revocation.
* **W3.5 (§7).** `verify-probe` is absent from every non-test build (resolver 3,
  `cargo tree -e normal,build` shows no feature on `axiam-oauth2` under
  `axiam-server`); the `TEST_ONLY_INVERSIONS` reason is accurate. The assertion
  residual is stated in T-289.
* **W3.4 (§6.3), W3.3 (§6.1), W3.6 (§8), W3.8 (§9), W3.9 (§10)** as asked; the
  spec is byte-identical to `--dump-openapi` from the head.
* **§10 rules (§11).** Every fix carries its test; the documents moved in the
  same commits; threat-model entries amended in both copies, dated, no version
  bump; `sdks/CONTRACT.md` untouched; one migration (v109, W3.3 extended by
  W3.7); no new crate; no new route.

---

## 1. What was reviewed, and how

* Commit messages: all twelve, in full, against the code (§3 … §11).
* Threat model: every added sentence of `threat-model-stride.md` was searched
  for in `Axiam.json` after normalising Markdown: 194 of 194 present (the two
  non-matches are T-488's heading and badge lines, which Threat Dragon stores
  as `title`, `type`, `severity` and `status`). T-488 is threat number 488 on
  the "Resource server (protected API)" actor of the OAuth2/OIDC diagram,
  `threatTop` 488, model version 2.42.0 unchanged.
* Issues: #675 … #684, #705, #712 and their comments (none).
* Probes: (1) a copy of `device_flow_test.rs` with one added test — a
  confidential-era refresh token refreshed after the conversion (§3.3);
  (2) an `EXPLAIN` of the sweep's selection against the migrated schema
  (§6.2). Both were removed before the commit.

## 2. Plan vs tree

* `main` is at `6b15aa36a`, not the plan's `6b7b258`; the wave branch is cut
  from it. The tree wins.
* **v109 without v108.** On this branch the migration list jumps from 107 to
  109; v108 is W1's (plan §10). This is safe only because the waves merge into
  the plan branch in the order W1 → W3 and nobody runs a wave branch against a
  persistent datastore: under today's runner a datastore that recorded v109
  would never apply v108 (exactly #704, which W4.1 hardens). The orchestrator
  merges W1 before W3, keeps both entries in `MIGRATIONS` and the newest-version
  assertion at 109; W4.1's contiguity test then passes with both.
* Every executor recorded stale line numbers; each function was found by name.
  The handler of `/device_authorization` is `handlers/oauth2.rs::device_authorization_inner`;
  the refresh-token store is `axiam-db/src/repository/oauth2_refresh_token.rs`;
  the rule lives in `axiam-oauth2/src/dpop.rs`. `axiam-api-rest` has no
  `dpop_test` binary; the DPoP device tests live in `device_flow_test`.
* W3.5's counter is `cfg(any(test, feature = "verify-probe"))` rather than the
  row's `#[cfg(test)]`, because the doubles live in an integration test (§7).
* W3.7's row says minting `client_id` makes `/verify` answer `403`. In the tree
  the session check would still answer `401` first; hence `ConsoleSignIn`'s
  ordering (§4). The executor's reading is correct.
* W3.9's ordinary resource in the test is made through the repository, not the
  `/api/v1/resources` route; provenance cannot be set through that route
  (`provenance_cannot_be_forged_through_the_ordinary_resource_api`), so the
  substitution tests the same state.
* W3.11 (f): the phrase lived in the threat model, not in `cleanup.rs`; fixed
  there.

---

## 3. W3.1 × W3.7 — the conversion and the refresh binding (orchestrator point 1)

### 3.1 The conversion itself

`update` (`oauth2_clients.rs`) admits `token_endpoint_auth_method: none` on a
confidential client only when `holds_only_device_grants` is true of **both**
the stored grants and the grants the request would produce (the request's, or
the stored ones when it sends none): at least one device-grant spelling, and
nothing outside `{device (both spellings), refresh_token}`. Every other
crossing returns `400` before anything is written. The write is
`update_if_unchanged(…, stored.updated_at)`, so the stored grants the decision
read are the ones the write lands on; a concurrent edit makes it a conflict,
not a conversion of a row the check never saw. `update_once` writes
`client_secret_hash = ''` in the same `UPDATE` that sets a public method, so no
reader ever sees `none` beside a live hash (SEC-093's shape). The merged row
still passes `fapi::validate_registration` (no `fapi2`, no mTLS binding, no key
set beside `none`; `Some("")` clears `jwks`/`jwks_uri`, so the guide's "clear
those in the same request" is possible). The audit row is written after the
conditional write lands, awaited, and a failed append is logged rather than
undoing a durable conversion — the pattern of the other admin writes. The
console still refuses the change client-side; the guide says so.
**Confirmed.**

### 3.2 Fail-closed on an unbound token

`enforce_refresh_token_binding` refuses, for a public DPoP-bound client, a
stored token whose `dpop_jkt` is `NONE` — every pre-v109 token of such a
client, and every token issued while a converted client was confidential. The
executor's argument holds:

* The server cannot tell the legitimate device's first refresh from a thief's.
  Binding on first use binds whichever arrives first, and under rotation the
  other is then refused as a replay — the thief keeps the grant.
* A token issued while the client was confidential was protected by the
  secret; the conversion cleared it.
* The cost is one device-flow run per affected grant, borne only by public
  DPoP-bound clients. It is stated in `docs/admin/public-clients.md` (the
  conversion's fourth bullet, and "Refresh tokens of a DPoP-bound public
  client") and in `docs/api/device-flow.md` §4. The CHANGELOG upgrade note is
  W8.4's (§13).

**Confirmed.**

### 3.3 A converted client that is not DPoP-bound — R111W3-01

`refresh_token_binding` is `None` for a client without
`dpop_bound_access_tokens`, so W3.7 reads nothing for it: it is **unaffected**,
as the executor says. It is not thereby *safe*. Before the conversion its
outstanding refresh tokens could be redeemed only with the client secret
(`handle_refresh_token`: `carries_no_credential && !is_public()` →
`invalid_client`). After it, `carries_no_credential` is the public client's
normal case, `authenticate_client_credential` accepts nothing for a public
client, and the same token refreshes on `client_id` alone.

Probe (a copy of `device_flow_test.rs`, removed): a `client_secret_post`
device client with `refresh_token` runs the flow **with** its secret and
receives a refresh token; a refresh without the secret is `401
invalid_client`; after `PUT {"token_endpoint_auth_method":"none"}` the same
refresh without any credential is `200` with a new access and refresh token
(`probe_r111w3_confidential_era_refresh_token_needs_no_secret_after_conversion`:
passed, i.e. both assertions held; §14).

What that changes: a refresh token that leaked while the client was
confidential (log, backup, a device's storage) was worth nothing without the
secret; after the conversion it is a bearer credential for the grant's
remaining life. Rotation and T-254's replay detection still apply — a thief
who refreshes first is noticed when the device's next refresh is a replay and
the family is revoked — which is the posture of every public client and the
reason this is **Low**, not higher. Pending device grants issued while
confidential behave the same way (they redeem on `client_id` alone after the
conversion; the existing test shows it for an approved one).

The guide says "A client not registered for DPoP keeps its refresh tokens",
which reads as a convenience; neither it nor T-289's #675 amendment says that
the tokens' protection changed. D-4 asked for the secret to be cleared; it did
not ask for the client's credentials-in-flight to be downgraded.

**Proposed fix:** in the conversion, after the conditional write,
`refresh_token_repo.revoke_all_for_client(tenant_id, client_id)` (the method
exists) and delete the client's pending device grants; one more field in the
audit row (`refresh_tokens_revoked`). The fleet runs the device flow once —
which a fleet that sends no secret could not have avoided anyway, because its
refresh tokens were unusable without one. Or, if the maintainer prefers to keep
them, state the residual in T-289's #675 amendment and in the guide.
**Test:** extend `a_confidential_device_client_converts_to_public_and_its_flow_needs_only_its_client_id`:
a refresh token issued (with the secret) before the `PUT` is `invalid_grant`
after it; a device flow run after the `PUT` still refreshes.

---

## 4. W3.7 (i) — `ConsoleSignIn` and every route that takes a user token (orchestrator point 2)

`RequestScopeHandles::apply` gains `Admit`. Order inside `apply`: the DPoP
proof's single use is recorded; then, under `ConsoleSignInOnly`, a token with
`client_id` is `403 authorization_denied`; then the session check; then the
active tenant. Signature, audience and binding are `extract_user`'s, before
`apply`. Only `device::verify` and `device::decide` take `ConsoleSignIn`.

Every reader of a device token, before and after (the token is `sub_kind:
user`, `aud` `axiam:user` or the device's `resource`, no `sid`, a random `jti`,
and now `client_id`):

| Reader | Before | After | Why |
|---|---|---|---|
| `AuthenticatedUser`, `MaybeAuthenticatedUser`, `AuthenticatedPrincipal` (user branch), `authenticate_presented_token` (POST UserInfo) | `401` | `401` | `apply(…, AnyUserToken)`: the session check falls back to the `jti`, which names no session; `client_id` is not read |
| `/api/v1/device/verify`, `/decide` | `401` | `403` | `ConsoleSignIn`, before the session check |
| CIBA approval routes (`ciba_approval.rs:187,309`) | `401` | `401` | `AuthenticatedUser` first, in-handler `minted_for_client` after |
| `release_sensitive_claims` (UserInfo) | unreached | unreached | behind the session check |
| `AuthenticatedPrincipal` machine branch | n/a | n/a | chosen by `aud == axiam:m2m`, not by `client_id` |
| token exchange `subject_token` | accepted | accepted | reads no `client_id` |
| token exchange `actor_token` (`actor_token_client`) | refused (no `client_id`, not `axiam:m2m`) | accepted **only** when presented by the device client it names | the #518 rule: the actor is a party the exchanging client can show it is; the code-grant token already had this; `docs/api/token-exchange.md` lists the device grant |
| UMA `claim_token` (`handlers/oauth2.rs:4559`) | accepted | accepted | reads `sub`/`tenant_id` only |
| gRPC `AuthInterceptor`, `TokenService` | accepted | accepted | audience and sender constraint only; introspection derives `client_id` from `sub_kind` |
| REST introspection, revocation | unchanged | unchanged | access-token responses hard-code `client_id: None`; revocation acts on refresh tokens |

No route newly admits a device token; two `401`s became `403`s; one acceptance
became consistent with the code grant's. The `actor_token` widening needs the
device client to hold the token-exchange grant (admin-only; DCR refuses it) and
to present its own device's token, which it already obtained. **Confirmed.**

`AccessTokenSpec::user(…).aud().scopes().cnf().client_id().issue()` replaces
`issue_access_token_bound`; the claims other than `client_id` are unchanged
(`a_device_grant_token_names_its_client_and_no_session` asserts `client_id`
and the absent `sid`).

Text: `docs/api/device-flow.md` §3/§4 say "the two approval endpoints answer it
`403`". A device token minted for a `resource` audience is refused `401` by
`extract_user`'s audience narrowing before `ConsoleSignIn` is reached
(R111W3-04 (c)). The `403` body changed from the handler's own JSON to the
shared `AxiamApiError` shape (`error` unchanged, `message` changed): contract
§14 text for W7.1 (§13).

---

## 5. W3.7 (ii) — v109's field and the rotation (orchestrator point 3)

* **Additivity.** `DEFINE FIELD IF NOT EXISTS dpop_jkt ON TABLE
  oauth2_refresh_token TYPE option<string>`; no index, no `UPDATE`, no
  backfill. `#[surreal(default)]` on both row structs, so a pre-v109 row
  decodes to `None` (`the_dpop_binding_round_trips_and_a_pre_v109_row_has_none`
  unsets the field and reads it back). Plan §10 says one migration per wave
  number; extending the unreleased v109 rather than adding v110 is the
  minimum. **Confirmed.**
* **Scope tests.** `v109_adds_only_the_sweep_index` restricts itself to the
  `rate_limit_bucket` statements and forbids `UPDATE`/`REMOVE`/`DELETE`/`OVERWRITE`
  in the whole migration; `v109_adds_the_refresh_tokens_optional_dpop_jkt_and_nothing_else`
  pins the migration to exactly its two statements. Together they are
  stronger than one test was. The newest-version assertion is 109 and names
  both. **Confirmed.**
* **Every writer.** The four `CreateRefreshToken` sites in production code —
  the code grant (`token.rs:~2299`), the refresh rotation (`~2969`), the
  device poll (`device_service.rs:473`), CIBA (`token_ciba.rs:269`, always
  `None`: a public CIBA client is refused at registration) — call
  `refresh_token_binding`. No other site creates a refresh token.
* **The rotation copies the binding.** At refresh, `enforce_refresh_token_binding`
  admits only `bound == presented`; the successor's `dpop_jkt` is
  `refresh_token_binding(&client, cnf)`, i.e. `presented`, i.e. the bound key.
  `a_public_dpop_clients_refresh_token_is_bound_to_its_key` checks the
  successor refuses the other key and admits the bound one. **Confirmed.**
* **Order.** The check sits after client authentication, the lookup, the
  `rotated_at` replay handling, the account check and the scope narrowing, and
  before `pre_issue_ext_claims`, the mint, the successor's `create` and the
  predecessor's `revoke_rotated`/`supersede`. A wrong-key refresh therefore
  neither consumes the token nor revokes the family. (A thief holding an
  *already rotated* token still triggers T-254's family revocation — that is
  the replay rule, unchanged and intended.)
* **No proof.** A DPoP-bound client's refresh without a verified proof is
  refused `invalid_client` by `certificate_binding_for` before the binding
  check, so `refresh_token_binding`'s `None` for a missing `cnf` never reaches
  `enforce` as "unbound and admitted".

---

## 6. W3.3 and W3.4 — the sweep and the hint cap (orchestrator points 8, 9)

### 6.1 The cutoff on the datastore clock

`delete_stale_once` evaluates `updated_at < time::now() -
duration::from_secs($retention)` in the selection and again in the `DELETE`
(per record, so a row a limiter touched between the two is kept). The only
writer of `updated_at` is `increment_by` (`updated_at = time::now()`), so both
sides of the comparison are the datastore's. Retention is `2L + margin` (21
minutes for the hint cap's 10-minute window). The previous-window row of a
hint is read until the end of the window after its own, i.e. at most `2W`
after its last write on the reader's clock; it can be deleted only when the
datastore is `2L + margin` past that write. The row cannot be deleted early
unless the **reader's** clock leads the datastore's by more than the margin —
the assumption T-424 and `CibaHintCap`'s doc now state. The sweeping
replica's clock is no longer an input. `the_sweep_ignores_the_application_clock`
keeps a 20-minute-old previous-window row. **Confirmed**, with one text caveat:
"the datastore's clock" is one clock for the shipped single-node SurrealDB
(`k8s/surrealdb/statefulset.yml`, `replicas: 1`); a clustered SurrealDB
evaluates `time::now()` on whichever compute node runs the statement
(R111W3-04 (d)).

### 6.2 Is the index used? — R111W3-04

Yes. Probe: `run_migrations` on an in-memory datastore, then `EXPLAIN` of the
selection exactly as `delete_stale_once` writes it. SurrealDB 3.3.4 folds
`time::now() - duration::from_secs($retention)` into a datetime constant and
plans an `IndexScan` on `rate_limit_bucket_updated_at` (`access: "<d'…'"`,
`limit: $limit`); the same selection with a bound `$cutoff` plans the same
scan. So "a pass no longer scans the table" (T-424's #676 amendment) holds.
The `DELETE $ids WHERE …` acts on the selected record ids and needs no index.

What is missing is the repository's own convention for an index a hot or
periodic path depends on: an `EXPLAIN` pin (`authz_query_plan_test.rs`,
`x3_wave2_query_plan_test.rs`). Nothing fails if a later planner or a
rewritten predicate stops folding the expression and the sweep falls back to
a table scan (R111W3-04 (e)). **Confirmed**, with that hygiene item.

### 6.3 A conflict that outlives the retries (W3.4)

`admit` maps an error from `retry_on_write_conflict(increment_by)` to
`Ok(false)` only when `is_write_conflict` matches the rendered message (the
markers `retry_on_write_conflict` itself retries on); every other error is
`server_error`, as is a failed `peek_bucket` after the count, which leaves the
count in place. A refusal is never an admission, so contention cannot bypass
the cap: an attacker who forces contention on a hint obtains more `429`s for
that (client, hint), which is the cap's own answer to the flood.
`a_count_that_fails_otherwise_is_a_server_error` pins the outage case;
`forty_concurrent_calls_produce_no_server_error` the contention case against
the in-memory datastore; the existing concurrency test now asserts no call
errs. **Confirmed.**

---

## 7. W3.5 — one verify per refusal (orchestrator point 4)

* **The feature.** `verify-probe = []` in `axiam-oauth2`, switched on by
  `[dev-dependencies] axiam-oauth2 = { path = ".", features = ["verify-probe"] }`.
  The workspace uses `resolver = "3"`: a dev-dependency's features are
  activated only when a target that needs dev-dependencies is built. `cargo
  tree -p axiam-server -e normal,build -i axiam-oauth2 -f '{p} {f}'` (with and
  without default features) shows `axiam-oauth2` with **no** features; the
  Dockerfile builds `cargo build --release -p axiam-server`. Under a
  workspace-wide `cargo test` the feature is unified into every test binary,
  which is harmless: the probe is a thread-local counter and changes no
  decision. **Unreachable from a release build: confirmed.**
* **The inversion.** `check-crate-layering.py` treats a crate's edge to itself
  as not "strictly lower", so the self dev-dependency must be declared; the
  reason given ("a self dev-dependency that switches on `verify-probe` for
  `tests/token_service.rs` … no other build carries the counter") is accurate.
  The checker passes (19 crates, 62 production edges, 4 declared test-only
  inversions).
* **The arms.** `spend_one_verify` (body secret, else Basic secret, else
  nothing) is called in the `NotFound` arms of the code, client-credentials
  and refresh grants (after their no-credential refusals), in
  `authenticate_client`'s `NotFound` and tenant-mismatch arms, in CIBA's token
  path, in the `sa_` branch (`spend_verify_on`), in the Basic-registered
  client's no-header refusal with a body secret, and in
  `verify_client_credential`'s public-client-with-credential refusal (the
  device grant's spend moved there; the device grant still costs exactly one).
  The equaliser hash needs an all-zero HMAC-SHA256 tag and its verdict is
  `black_box`ed. A request with no secret costs none, as a known client's does
  not.
* **Residual.** An assertion presented for an unknown client costs no
  signature verify, while a known client's assertion costs one. T-289's #679
  amendment states it; a dummy-key verify was the plan's explicit non-goal.
  **Confirmed.**

## 8. W3.6 — the admin `PUT`'s grant bound (orchestrator point 5)

`grants_refused_by_registration_policy` runs first after the row is read,
asks `dcr::grant_refusal` (the predicate `dcr::validate` now calls, so the two
cannot disagree) with the tenant's `dynamic_registration` for a `dcr` row and
`None` for `cimd` (CIBA never), exempts a grant the stored row holds, and
fails closed on a policy read error. `admin_put_of_a_grant_registration_would_refuse_is_422_on_dcr_and_cimd_rows_only`
covers the three grants on both row kinds, the held grant and the admin
control. **Confirmed for grants.**

Other members, asked by the orchestrator:

* **scope** — bounded by #636's `scopes_outside_ceiling` (`422
  scope_exceeds_ceiling`), unchanged.
* **`token_endpoint_auth_method`** — a crossing to public needs a device-only
  stored row; a crossing to confidential is refused. A confidential-to-
  confidential change (`client_secret_post` → `client_secret_basic`, →
  `private_key_jwt` with keys, → `tls_client_auth`) widens nothing a stranger
  can use: each is a stronger or equal authentication of the same client.
* **`redirect_uris`** — the admin `PUT` checks structure
  (`validate_redirect_uris`: absolute, `https` except loopback, no fragment)
  but not the tenant's `dcr_allowed_redirect_hosts`, which `dcr::validate`
  applies. **Widenable** (R111W3-03).
* **`allowed_resources`** — `dcr::validate` sets it to the tenant's
  `external_client_allowed_resources`, verbatim ("the single most important
  line in this module"), and nothing re-applies the policy at token time; the
  admin `PUT` accepts any validated list. **Widenable** (R111W3-03).

Both need an administrator; R110W3-07 graded the grant case Informational, and
these are the same class. The commit message's "a `dcr`/`cimd` row can never
be device-only" is false for a row an administrator gave the device grant
before #680; such a row can be made public by W3.1's rule, which weakens
nothing (R111W3-04 (b)).

## 9. W3.8 — `client_id` on `/device_authorization` (orchestrator point 6)

`resolve_client_id(req.client_id, ctx)`: body and header disagreeing →
`invalid_request` before any lookup; body, else Basic header, else the
assertion's `sub`/`iss`, else `invalid_request "client_id is required"`.

* **A public client must still send `client_id`.** It has no header and no
  assertion (presenting either is a credential, which a public client is
  refused), so without a body `client_id` it gets `invalid_request`.
  **Confirmed.**
* **The assertion's id.** `ctx.assertion_client_id()` reads the *unverified*
  assertion, as at the token endpoint: it only routes the lookup.
  `authenticate_device_authorization` → `authenticate_device_client` →
  `authenticate_client_credential` verifies the assertion against the loaded
  client's registered key and requires `iss` and `sub` to equal that client's
  id, so a forged assertion naming another client is checked against that
  client's key and fails. A body id plus an assertion for another client is
  checked against the body client's key and fails. So the id the request
  *ends up authenticated as* is one a verified assertion names; the id used
  for the lookup is not yet verified, by design. **Confirmed.**
* The route's limiter is per address (`build_governor` +
  `RateLimitShared::new`), not client-keyed, so the optional body id changes no
  bucket. `FormConfig::error_handler(par_form_error)` answers a malformed body
  in JSON (`a_malformed_device_authorization_body_is_a_json_invalid_request`).
* The new schema description of `client_id` carries "The handler resolves it
  with `resolve_client_id`, as the token endpoint does" — an implementation
  note in the public spec, the class W3.11 (e) removed (R111W3-04 (a)).

## 10. W3.9 — UMA ownership (orchestrator point 7)

`registered_by_pat` reads the resource in the PAT's tenant and returns
`NotFound { entity: "resource", id }` unless `uma_registered_by == pat.client_id`.
The repository's own unknown-id error is `take_first_or_not_found(rows,
"resource", &id_str)`, the same entity and the same id string.

* **Is the echoed id an oracle?** No. The id in the body is the one the caller
  put in the path, in all three cases (own-missing, foreign, ordinary); it
  carries nothing the caller did not send. The residual timing difference (a
  row decoded vs none) is a single indexed read either way and would reveal
  only that a UUIDv4 the caller already holds exists in its tenant. The check
  precedes the network gate, every write and the scope sync.
* **Upgrade note.** Resources made through `/api/v1/resources`, and UMA
  resource sets registered before provenance existed, have no
  `uma_registered_by` and are no longer readable, updatable or deletable
  through `/uma2/rreg`; T-488's residual says so; W8.4 must too (§13).
* **The sibling path.** `/uma2/perm` (`request_ticket`) checks only that each
  requested scope is declared on the resource id, in the tenant: a resource
  server may mint a ticket — and, with a requesting party's claim token, an
  RPT — for another server's set or an administrator's resource, and the
  `201`/`400 invalid_resource_id|invalid_scope` answer tells it which ids
  exist and which scopes they declare. `uma_test.rs` relies on tickets for an
  administrator-made resource (`an_allowed_pair_yields_an_rpt_carrying_the_permissions_claim`
  uses the fixture's repository-made resource), so restricting tickets to
  registered sets is a product decision, not a one-line fix. Meanwhile
  `docs/api/uma.md`'s "A resource server sees only what it registered" and
  T-488's "indistinguishable" are true of `/uma2/rreg` only (R111W3-02).

---

## 11. The §10 rules, against the wave

| Rule | Held? |
|---|---|
| Signed commits | 12 of 12 carry `gpgsig` |
| Every fix carries its row's test | yes — each named test exists and was run (§14); W3.10/W3.11 are text with checkers |
| Documents move in the same commit | yes; W3.1 also moved `docs/api/device-flow.md` and T-289, which stated the refusal as absolute |
| Threat model in both copies, dated, no version bump | yes — 194/194 sentences present in `Axiam.json`; T-488 added as number 488; version 2.42.0, counts left to W8.3 |
| `sdks/CONTRACT.md` untouched | yes (`git diff --stat` empty) |
| Only W3.3 (extended by W3.7) adds a migration, v109, additive, scope test, newest-version bump | yes (§5); v108 absent on this branch (§2) |
| No new crate; layering | yes; one declared self inversion (§7) |
| No new route; every credential refusal costs one verify | yes; W3.5 pays the rule's debt, with the stated assertion residual |
| W3.8/W3.11 regenerate the spec in-wave | yes; byte-identical to `--dump-openapi` from the head (§14) |
| No model name in code or docs | none found in the diff (commit trailers only) |

## 12. Executors' follow-ups, confirmed or rejected

| Executor note | Verdict |
|---|---|
| W3.1: the console still refuses the conversion client-side | Confirmed; the guide says so. A console change is not required by #675 |
| W3.3: v108 is W1's and is not defined here | Confirmed; merge order is the orchestrator's (§2) |
| W3.4: a failed take-back is refused as decided; a failed peek stays `server_error` | Confirmed (§6.3) |
| W3.5: `cfg(test)` cannot reach an integration test; feature + self dev-dependency instead | Confirmed, and unreachable from release (§7) |
| W3.6: T-289 did not state the "grant_types unbounded" residual, so not amended | Confirmed; but `redirect_uris` and `allowed_resources` remain (R111W3-03) |
| W3.7 (i): the row's "client_id ⇒ 403" needs `ConsoleSignIn`'s ordering | Confirmed (§4) |
| W3.7 (ii): fail-closed for unbound tokens; a non-DPoP converted client unaffected | Confirmed fail-closed; "unaffected" confirmed, "safe" not (R111W3-01) |
| W3.8: no threat entry named; none amended | Confirmed |
| W3.9: §5 has no UMA element; T-488 on the resource-server actor | Confirmed: the nearest existing element; W8.3 may add a Protection API process if it wants |
| W3.9: the 404 descriptions are unchanged, so no spec regeneration | Confirmed |
| W3.11: `device_flow_test` did not complete in its session | Run here (§14) |
| W3.11 (g): the website threat-model copy is W8.3's | Confirmed |

## 13. For W7.1 and W8

**Contract (W7.1; `sdks/CONTRACT.md` untouched by this wave):**

* §14: device-grant access tokens carry RFC 9068 `client_id` and no `sid`;
  `/api/v1/device/verify` and `/decide` answer a token minted for a client
  `403 authorization_denied` in the shared error shape (message text
  changed); every other session-validated route `401`.
* §14 / the DPoP section: a public client registered for DPoP-bound tokens
  gets a refresh token bound to its proof's key (RFC 9449 §5); another key, or
  a token bound to none, is `400 invalid_grant` and not spent; the successor
  keeps the key; SDKs must keep the DPoP key as long as the refresh token.
* §14.1: `/oauth2/device_authorization` takes `client_id` from the body, the
  Basic header or the assertion; a disagreement is `invalid_request`; an
  unreadable body is a JSON `invalid_request`. A public client still sends
  `client_id`.
* `oauth2_clients.update`: `400` except the device-only conversion to `none`;
  `422 grant_exceeds_registration_policy` on `dcr`/`cimd` rows.
* §27 (CIBA): contention on a hint is `429 slow_down`, not `500`.
* UMA: `/uma2/rreg/resource_set/{id}` answers `404` for a set the PAT's client
  did not register.

**CHANGELOG upgrade notes (W8.4):**

1. Public DPoP-bound clients: every refresh token issued before 1.1.1 is
   refused `invalid_grant` once; the client signs in again (#681).
2. A confidential device-only client can be made public with `PUT …
   {"token_endpoint_auth_method":"none"}`; its secret is cleared; a
   DPoP-bound one's devices sign in again (#675) — and, pending R111W3-01,
   either "its outstanding refresh tokens are revoked" or "its outstanding
   refresh tokens now refresh without the secret".
3. Resources made through `/api/v1/resources`, and UMA sets registered
   before provenance existed, are no longer reachable through `/uma2/rreg`
   (#705).
4. Device-grant access tokens now carry `client_id`; a resource server that
   keyed on its absence must not (#681).
5. Schema v109 (index + optional field), additive.

**W8.3:** T-488 enters the counts (488 threats); the website copy is
regenerated.

---

## 14. Checks run

Each command's own exit code was captured (redirected to a log, `$?`
tested). Logs are in the session scratchpad. Cargo ran with
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, the swagger placeholder and `protoc`
installed; `libxml2-dev`/`libxmlsec1-dev` were installed for the SAML run;
`cargo clean` between crates.

| Check | Exit | Result |
|---|---|---|
| `cargo build -p axiam-server --no-default-features` | 0 | built |
| `axiam-server --dump-openapi` vs `sdks/openapi.json` | 0 / `diff` 0 | byte-identical |
| `python3 scripts/check-spec-digest.py` | 0 | digest matches (`sha256:160f9a3f…`) |
| `python3 scripts/gen-management-registry.py --check` | 0 | 202 operations / 29 namespaces in sync |
| `python3 scripts/check-remediation-evidence.py` (after `git fetch --unshallow`) | 0 | 5 verified, 0 failed, 32 skipped (no GitHub token in the sandbox), 0 unparseable |
| `bash scripts/check-doc-links.sh` | 0 | 536 links across 78 files |
| `python3 scripts/check-crate-layering.py` | 0 | 19 crates, 62 production edges inward, 4 declared test-only inversions |
| `python3 scripts/check-conflict-markers.py` | 0 | OK |
| `python3 scripts/check-config-key-coverage.py` | 0 | every key documented |
| `cargo fmt -p <crate> -- --check` for `axiam-core`, `-db`, `-auth`, `-oauth2`, `-api-rest`, `-scim`, `-directory`, `-server` | 0 ×8 | clean |
| `cargo tree -p axiam-server -e normal,build -i axiam-oauth2 -f '{p} {f}'` (± default features) | 0 | no feature on `axiam-oauth2` (§7) |
| STRIDE additions against `Axiam.json` | — | 194 of 194 sentences present (§1) |
| `cargo test -p axiam-server --no-default-features --no-fail-fast` | 0 | 28 binaries, 320 passed, 0 failed (`cleanup_task` 41, `req7_session_lifecycle` 7, `device_grant_boot_warning` 3; `req5_saml_e2e` 0 with SAML off) |
| `cargo test -p axiam-core --lib` | 0 | 524 passed |
| `cargo test -p axiam-auth --no-fail-fast` | 0 | 20 binaries, 459 passed, 0 failed, 3 ignored |
| `cargo test -p axiam-scim --no-fail-fast` | 0 | 12 binaries, 227 passed, 0 failed |
| `cargo test -p axiam-directory --no-fail-fast` | 0 | 9 binaries, 290 passed, 0 failed |
| `cargo test -p axiam-db --no-fail-fast` | 0 | 86 binaries, 1 097 passed, 0 failed, 5 ignored (plus the sweep-plan probe, 1 passed, removed) |
| `cargo test -p axiam-oauth2 --no-fail-fast` | 0 | 8 binaries, 838 passed, 0 failed (`--lib` 625, `token_service` 149) |
| `cargo test -p axiam-api-rest --no-default-features --no-fail-fast`, in seven batches with `cargo clean` between (one unbatched run hit the disk quota at compile time) | 0 ×6, 101 ×1 | 112 binaries (lib + 111), 1 927 passed, 15 failed, 3 ignored. The 15 are `federation_test`'s SAML route tests with SAML compiled out (the known sandbox artefact). Wave binaries: `device_flow_test` 40, `ciba_test` 28, `ciba_approval_test` 26, `oauth2_flow_test` 44, `oauth2_client_test` 41, `uma_test` 24, `public_client_test` 16, `token_exchange_test` 29, `par_test` 30, `resource_indicators_test` 20, `tenant_test` 24, `oauth2_userinfo_post_test` 20, `mcp_authorization_test` 14 |
| `cargo test -p axiam-api-rest --test federation_test` (default features; `libxml2-dev`, `libxmlsec1-dev` installed) | 0 | 87 passed |
| probe `probe_r111w3_confidential_era_refresh_token_needs_no_secret_after_conversion` (copy of `device_flow_test.rs`, removed) | 0 | `401` before the conversion, `200` after (R111W3-01) |
| probe `probe_sweep_plan` (`EXPLAIN`, removed) | 0 | `IndexScan` on `rate_limit_bucket_updated_at` (§6.2) |

W3.11's executor could not run `device_flow_test`, `ciba_test`,
`ciba_approval_test`, `oauth2_flow_test` and `cleanup_task`; all five pass
here on the head. `cargo clean` was run between crates and at the end.

## 15. Issue bodies

Each was filed on milestone `1.1.x`; the bodies are summarised below, and
the issue is the authoritative text.

* **R111W3-01 (Low) — #749**: the device-client conversion to public leaves
  its confidential-era refresh tokens redeemable without a credential. Fix and
  test as in §3.3.
* **R111W3-02 (Low) — #745**: `/uma2/perm` mints tickets for resources the
  resource server did not register, and answers which ids exist. Three
  options (restrict to registered sets; refuse only other servers' sets; keep
  and correct the text); test as in §10.
* **R111W3-03 (Informational) — #746**: the admin `PUT` widens a
  self-registered client's `allowed_resources` and `redirect_uris` beyond the
  registration policy. Fix: `422` with the held-value exemption; test in
  `oauth2_client_test.rs`.
* **R111W3-04 (Informational) — #747**: text and hygiene — (a) implementation
  note in the public schema (W3.8); (b) "a `dcr`/`cimd` row can never be
  device-only" (W3.6); (c) "`403`" holds for an `axiam:user` device token only;
  (d) "the datastore's clock" assumes a single SurrealDB node; (e) no `EXPLAIN`
  pin for the v109 index.

## 16. Invariants

* Nothing in this review changed code, tests, the threat model or the spec;
  the two probes were removed before the commit.
* No Medium or higher finding; nothing for the orchestrator to dispatch
  before the merge. R111W3-01's fix is small and could ride the wave if the
  orchestrator chooses; as a Low it is filed.
