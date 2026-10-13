# Security review — release 1.0.1, wave W3 (F4)

**Date:** 2026-10-13.
**Against:** `claude/release-1.0.1-w3`, the whole wave diff `v1.0.0..eac374db6`
(9 commits, 72 files, 5 501 lines added and 494 removed). Every commit carries a
signature (`gpgsig` present on all 9; the sandbox has no `allowedSignersFile`,
so `%G?` cannot verify them here).
**Scope:** every W3 task of the release-1.0.1 plan (§4): W3.1 #604
(`7f5330cf4`, the device grant asks `user_may_be_subject`, R1W1-06), W3.2 #601
(`7be5e8094`, a tombstoned tenant's clients no longer authenticate, R1W1-03),
W3.3 #610 (d) (`0807a95c6`, client deletion voids device grants and CIBA
requests), W3.4 #613 (`796c90514`, `dcr_allowed_scopes` as a ceiling at the
read points), W3.5 #602 (`6e1561195`, the purge deletes only the audit rows the
export holds, D-5, R1W1-04), W3.6 #599 (`67be51198` and its follow-up
`3c6e951d1`, the per-(client, hint) CIBA cap, the bounded pending list, the
user-keyed list bucket, D-4), W3.7 #610 (a) (`3a5392204`, test comments) and
W3.8 #610 (b) (`eac374db6`, the route-level `tls_client_auth` harness).
**Method:** adversarial reading of the diff and of every sibling path it
implies — the OAuth2 grants and every client-authenticating endpoint, client
deletion, the tenant tombstone and purge, the CIBA and device flows, audit
ingestion, export and retention — against
[`threat-model-stride.md`](threat-model-stride.md) and `Axiam.json` (model
2.40.0, 475 threats: 437 / 17 / 21), the plan's §9 rules (which carry Phase 23
plan §7), and the OWASP ASVS 5.0 areas the diff touches (V2 business logic, V4
API, V6 authentication, V7 session, V8 authorization, V9 tokens, V16 logging).
Claims were checked against the code, not the commit messages; one was checked
by a probe (§12). This review fixes nothing: every finding is reported with
evidence, a proposed fix and an issue body (§13). IDs follow the 1.0.0 reviews'
scheme (`R101W3-nn`).

---

## 0. Summary

**No High or Medium finding. The wave does what its tasks say**, each change
on the path it names and with the test it names; the follow-up `3c6e951d1`
correctly closes the user oracle the first CIBA cap opened. Four Low and five
Informational findings are reported; two of the Low ones are pre-existing
weaknesses the wave's own work sits on (the device grant authenticates no
client; an export receipt can be forged through AMQP audit ingestion and now
also sets the purge bound), and two come from the wave (the CIBA list route has
no limiter at all when the shared counter is off; the hint cap's rows are never
swept).

| ID | Finding | Severity | Surface → threat | Origin | Disposition |
|---|---|---|---|---|---|
| R101W3-01 | The device-code grant authenticates no client, at `/oauth2/device_authorization` or at the poll: a confidential, sender-constrained or `fapi2` client registered for it gets bearer tokens without its credential, its key or its profile checks; a leaked device code is redeemable by anyone; the poll ignores `client_id` and never re-reads the client. | Low | `device_service.rs`, `handlers/oauth2.rs` → T-160, T-163, T-289; RFC 6749 §3.2.1, RFC 8628 §3.4 | pre-existing (B2); confirmed by W3.3 | Reported; decide whether 1.0.1 takes the small fix |
| R101W3-02 | The scope ceiling also withholds scopes an **administrator** put on a `dcr`/`cimd` row through `PUT /api/v1/oauth2-clients/{id}`, which accepts them and which 1.0.0 honoured; an upgrade silently removes them, and the admin API still accepts what will never be served. | Informational (client-visible change) | `scope_ceiling.rs`, `oauth2_clients.rs` → T-289, T-55 | wave (W3.4) | Release note + admin-API refusal (§6, §13) |
| R101W3-03 | `tenants.audit_exported` receipts are ordinary audit rows a tenant's AMQP producer can write with any metadata: a forged receipt satisfies the deletion's export check (pre-existing, T-118) and now also supplies the `exported_through` the purge trusts as its bound, so it can undo #602. | Low | `audit_consumer.rs`, `tenants.rs`, `tenant_purge.rs` → T-118, T-472, T-13 | pre-existing, inherited by W3.5 | Reported (proposed §3) |
| R101W3-04 | `GET /api/v1/ciba/requests` lost its route limiters for a handler bucket on the shared counter, and that counter admits everything under `AXIAM__RATE_LIMIT__SHARED=off`: the route then has no limiter at all. | Low | `server.rs`, `ciba_approval.rs`, `rate_limit_counter.rs` → T-424; plan §9 / Phase 23 §7 | wave (W3.6, D-4) | Fix in wave (proposed §4) |
| R101W3-05 | The CIBA hint cap writes two `rate_limit_bucket` rows per novel (client, hint) — the previous-window read is an `UPSERT` that creates one — and nothing ever sweeps the table: an authenticated CIBA client grows it by up to 120 rows a minute (1 200 and 12 000 under the gateway and mesh presets), permanently. | Low | `ciba.rs` `CibaHintCap::admit`, `rate_limit.rs` → T-424 (availability) | wave (W3.6) | Reported (proposed §5) |
| R101W3-06 | The hint cap (3 calls per client per hint per ten minutes, refused calls counted) has no configuration and no preset: the FAPI-CIBA conformance plan and any SDK CI that drives more than three CIBA flows for one test user from one client within ten minutes will be refused, for ten to twenty minutes and longer while it retries. | Informational | `ciba.rs` → T-424 | wave (W3.6) | Reported |
| R101W3-07 | The export bound is the application clock (`Utc::now()` at export start) while audit `timestamp`s are the datastore's `time::now()`; with the app ahead of the datastore by δ, a row inserted during the export with a timestamp ≤ the bound can be missed by the offset-paged export and is then deleted by the purge. | Informational | `tenants.rs:845`, `audit.rs:355`, `tenant_purge.rs` → T-118 | pre-existing export, inherited by W3.5 | Reported |
| R101W3-08 | W3.2's residual paths: `/oauth2/device_authorization` still serves a tombstoned tenant's client and writes `device_grant` rows until the purge reaches `oauth2_client`; the device poll answers a tombstoned tenant with `server_error`; `device_grant` is not cleared at the tombstone (`ciba_request` is); an `sa_` client gets `invalid_request "unknown tenant"` where an OAuth2 client gets `invalid_client`. | Informational | `device_service.rs`, `tenant.rs`, `token.rs:1640` → T-472 | wave residual | Reported |
| R101W3-09 | Text and hygiene: the CIMD re-materialisation rationale in T-289, CHANGELOG and `client_grants.rs` (a CIMD client cannot hold either grant, and the poll authenticates no client); the client-delete OpenAPI text; the CIBA grant mints an ID token after the ceiling dropped `openid`; a mis-indented `)),` rustfmt skips; the quick-bench cell not run; the moot `audit_signature` rule; an unused `client_id` filter. | Informational | various | wave | Reported |

**What held.** Every rule of the plan's §9 holds for what the wave added (§9) with the one
exception of R101W3-04: every new refusal of a credential check (the tombstoned
tenant) is decided **after** the verify, under the same answer; no new route;
no new outbound request; no schema change (`schema.rs` changes only in its test
module); the threat-model entries move together. W3.1's predicate is CIBA's,
called (§6). W3.2 reaches every client-credential path in the tree — the four
grants directly, revocation, introspection, PAR, `bc-authorize`, token exchange
and UMA through `authenticate_client` — after the credential, with no cache to
lag; gRPC authenticates by bearer and `sa_` ids never reach the client row
(§6). W3.3 is scoped by tenant **and** client and keeps the existing
fail-and-retry order (§6). W3.4 sits at every point that reads a client's
scopes for a mint and fails closed (§6). W3.5's bound is the right one (the
receipt's `exported_through`, not its timestamp), the fail-safe keeps
everything, and nothing in the tree reads audit rows of a gone tenant (§7).
W3.6's cap is counted before the user lookup and is uniform in answer, cost
and side effects for known, unknown and inactive hints; the oracle the first
version opened is closed (§7). W3.7 touches comments only; W3.8's harness drives
the server's own listener config, verifier and `on_connect` hook, and the hook's
extraction is a move (§7). Threat-model counts agree across `Axiam.json`, the
STRIDE document and the generated website file (475: 437 / 17 / 21), no id was
added, and a generator run leaves no diff (§10).

**Verdict on merge.** Nothing blocks. R101W3-04 is a few lines and should be
fixed in the wave; R101W3-02 needs at least its release note before 1.0.1 ships.
R101W3-01 is pre-existing; its fix is small (§2) and the maintainer should
decide whether 1.0.1 takes it. The rest are for `1.0.x`.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Device grant redemption | W3.1 #604 | `device_service.rs`, `ciba.rs` `user_may_be_subject`, `handlers/oauth2.rs` device branch, `device_flow_test.rs` | **read in full**; every exit of `poll_at`; the start endpoint and the client lookup |
| Client authentication and the tenant | W3.2 #601 | `token.rs` (`authenticate_client_credential`, `verify_client_credential`, `live_tenant`, the four grants, the `sa_` branch), `token_ciba.rs`, `handlers/oauth2.rs` (UMA, token exchange, PAR, revoke, introspect), `handlers/ciba.rs`, `tenant.rs` tombstone, `cimd.rs`, `token_service.rs`, `tenant_test.rs` | **read in full**; every caller of `authenticate_client`/`_credential` listed; order against the verify |
| Client deletion | W3.3 #610 (d) | `client_grants.rs`, `device_grant.rs`, `ciba_request.rs`, `oauth2_clients.rs`, `cleanup.rs`, `boot.rs`, `cimd.rs`/`dcr.rs` grant sets | **read in full**; scoping, order, the redeem race |
| Scope ceiling | W3.4 #613 | `scope_ceiling.rs`, `scope_policy.rs`, `authorize.rs`, `token.rs`, `token_ciba.rs`, `device_service.rs`, `handlers/ciba.rs`, `handlers/oauth2.rs`, `state/mod.rs`, `boot.rs`; 1.0.0 `dcr.rs`/`cimd.rs`; `oauth2_clients.rs` update | **read in full**; every `client.scopes` reader in `axiam-oauth2` and `axiam-api-rest` listed |
| Tenant purge and audit | W3.5 #602 | `tenant_purge.rs`, `tenant.rs`, `tenants.rs` (receipt, export, delete), `audit.rs`, `schema.rs` test, `cleanup.rs`, `audit_consumer.rs`, `audit_minimisation.rs`, GDPR doc | **read in full**; **probed** (§12) |
| CIBA cap, list, bucket | W3.6 #599 | `ciba.rs` (service, `CibaHintCap`), `handlers/ciba.rs`, `handlers/ciba_approval.rs`, `server.rs`, `rate_limit.rs`, `rate_limit_counter.rs`, `ciba_request.rs`, `state/mod.rs`, `boot.rs`, frontend hook | **read in full**; known/unknown/inactive hint paths compared step by step |
| Test comments | W3.7 #610 (a) | 14 test files | every changed line is a comment (checked mechanically) |
| `tls_client_auth` at the route | W3.8 #610 (b) | `tls.rs`, `boot.rs`, `server_leaf_profile.rs` | **read**; the harness against `boot`'s listener |
| Threat model and docs | all | `Axiam.json`, STRIDE, `website/src/threatModel.ts`, CHANGELOG, GDPR, admin and DCR docs, website docs | every amended entry compared with the code (§10, §11) |

Not run: the quick-bench token cell (W3.2's plan oracle; see §6 and R101W3-09),
the frontend suites, a multi-replica deployment, a networked SurrealDB.

## 2. R101W3-01 — the device-code grant authenticates no client

**Severity: Low** (Medium on a deployment that registers the device grant on a
`fapi2` or sender-constrained client). **Pre-existing since B2**; confirmed, not
introduced, by W3.3, whose executor recorded it. Not widened by the wave: W3.1
adds the subject check, W3.3 voids the grants of a deleted client.

**Evidence.**
* `crates/axiam-api-rest/src/handlers/oauth2.rs:2141-2185` — the
  `device_code` grant is dispatched before the `TokenRequestContext` is built
  and before `materialise_if_cimd`, with the comment "Note what is deliberately
  NOT done: no client authentication" (`:2147`). `form.client_id`,
  `client_secret`, the Basic header, a client assertion, the TLS client
  certificate and the DPoP proof are never read.
* `crates/axiam-oauth2/src/device_service.rs:274-439` (`poll_at`) — the grant
  is found by the device-code hash alone; the client row is never read, so its
  existence, its `grant_types`, its `token_endpoint_auth_method`, its profile
  and its binding flags are not consulted. The access token is minted by
  `issue_access_token` (`:414`) with no `cnf`, whatever
  `dpop_bound_access_tokens` / `tls_client_certificate_bound_access_tokens`
  say; `fapi::enforce_token_request` is not called.
* `device_service.rs:152-228` (`authorize`, the start endpoint) checks only that
  `client_id` names a client of the tenant registered for the grant.
* `crates/axiam-api-rest/src/handlers/oauth2_clients.rs:422-431` —
  `KNOWN_GRANT_TYPES` admits the device grant on any client, whatever its
  authentication method or profile; `fapi::validate_registration` has no rule
  about it. (DCR and CIMD cannot register it: `dcr.rs` "only the two code
  grants", `cimd.rs:75`.)

**Against the RFCs.** RFC 8628 §3.4's token request is an RFC 6749 token
request: `client_id` is REQUIRED "if the client is not authenticating with the
authorization server as described in Section 3.2.1 of [RFC6749]", and RFC 6749
§3.2.1 says confidential clients "MUST authenticate with the authorization
server … when making requests to the token endpoint". RFC 8628 §3.1 applies
the same client-authentication requirement to the device authorization
endpoint. AXIAM's reading ("RFC 8628 performs no client authentication") holds
for public clients only.

**Consequences, for a client an administrator registered for the grant.**
1. **A leaked device code is a bearer credential for anyone**, until it expires
   or is redeemed: no secret, key or certificate of the client is needed to
   redeem it once the user approves.
2. **Confidential-client impersonation by device-code phishing.** Anyone who
   knows a confidential client's `client_id` (it is public) starts a device
   authorization in its name, shows the user a code under that client's name,
   and redeems the approval for tokens whose `client_id` is the confidential
   client's.
3. **Sender-constraint and profile bypass.** A client registered with
   `dpop_bound_access_tokens`, `tls_client_certificate_bound_access_tokens` or
   the `fapi2` profile receives an unbound bearer token through this grant.
4. **The client's current state is never consulted at the poll**: removing the
   device grant from the client, switching its method or rotating its secret
   does not stop an approved grant from redeeming (only deletion does, since
   W3.3).

**Proposed fix (small).**
1. At the poll: require `client_id` (RFC 8628 §3.4) — taken from the form or
   from the authenticated context — and refuse `invalid_grant` when it is not
   the grant's `client_id`; read the client (`get_by_client_id`), refuse
   `invalid_client` when it is gone or no longer holds the grant; for a
   non-public client run `TokenService::authenticate_client_credential` with
   the request's `TokenRequestContext` (which also gives W3.2's tenant read),
   `fapi::enforce_token_request`, and mint with `certificate_binding_for` /
   the DPoP binding as the other grants do. The dispatch then moves below the
   context construction in `token_inner`.
2. At `/oauth2/device_authorization`: authenticate a non-public client the same
   way (RFC 8628 §3.1).
3. Or, the minimum: refuse the device grant on a non-public, `fapi2` or
   sender-constrained client at registration and on update (the admin API and
   `fapi::validate_registration`), and still bind the poll to `client_id` and
   the client's current row.
4. Tests: a confidential client's grant is `invalid_client` at the poll without
   its secret and redeems with it; a poll naming another `client_id` is
   `invalid_grant`; a DPoP-bound client's device token carries `cnf.jkt`;
   removing the grant type from the client refuses an approved grant.
5. Text: T-160/T-163 state the client-authentication rule; the handler comment
   is corrected.

## 3. R101W3-03 — a forged export receipt sets the purge bound

**Severity: Low. Pre-existing** (the receipt is an ordinary audit row since
T-118); **inherited by W3.5**, which now also trusts the receipt's
`exported_through` as the bound of what the purge deletes.

**Evidence.**
* `crates/axiam-api-rest/src/handlers/tenants.rs:142-173`
  (`recent_export_receipt`) — the receipt the deletion accepts is the newest
  row in the tenant's own audit log with `action = "tenants.audit_exported"`,
  `outcome = Success`, written in the last six hours; nothing distinguishes a
  row the export handler wrote. Its `metadata.exported_through` is copied into
  the `tenants.deleted` record as `audit_exported_through` (`:769`), and the
  purge deletes every audit row of the tenant with `timestamp <=` it
  (`tenant_purge.rs` `Retain::AfterExport`).
* `crates/axiam-amqp/src/audit_consumer.rs:65-195` — an `AuditEventMessage`
  signed with the tenant's HMAC subkey (which the tenant's producers hold, per
  CONTRACT §8b) is appended with `tenant_id`, `action`, `outcome`, `metadata`
  exactly as sent (`:177-186`); no action is reserved.
* **Probe (§12):** a message signed with the tenant's subkey, `action
  tenants.audit_exported`, `outcome Success`, `metadata.exported_through
  2100-01-01T00:00:00Z` is acknowledged; the delete handler's own query returns
  it as the newest receipt; with the deletion record the handler would write
  from it, `purge_tombstoned` reports the bound `2100-01-01` and deletes every
  audit row of the tenant, the forged receipt and a row written after the
  deletion included.

**Consequence.** Whoever holds a tenant's AMQP audit subkey can (a) satisfy the
export requirement of T-118 without an export (pre-existing; the deletion still
needs an administrator with the deletion permission), and (b) since W3.5, choose
the purge bound, so the rows #602 set out to keep — the deletion's own
revocations, refusals, the hours before the deletion — go after all. Bounded by
1.0.0's behaviour (the purge deleted everything then), so not a regression; but
D-5's guarantee holds only against honest receipts.

**Proposed fix.**
1. `process_audit_event` refuses (nack, `requeue: false`) an event whose action
   is one the server writes and reads back as a control record —
   `tenants.audit_exported`, `tenants.deleted`, `tenants.purged`, the GDPR
   erasure-proof actions — or, more simply, any action in the `tenants.` and
   `gdpr.` namespaces; list them in one constant shared with the handlers.
2. Clamp the bound in the purge: `min(audit_exported_through, timestamp of the
   receipt it names)` — the receipt's `timestamp` is the datastore's, not the
   writer's — and refuse at the deletion a receipt whose `exported_through` is
   later than its own `timestamp`.
3. Tests: an AMQP event with a reserved action is not persisted; a receipt with
   `exported_through` after its timestamp is refused at the deletion; the purge
   bound never exceeds the receipt's timestamp.
4. Text: T-118 and T-472 say receipts are server-written only; CONTRACT §8b
   names the reserved actions (W5).

## 4. R101W3-04 — the CIBA list route has no limiter under `SHARED=off`

**Severity: Low. Wave-introduced** (W3.6, D-4).

**Evidence.** `crates/axiam-api-rest/src/server.rs:819-829` — W3.6 removed the
route's `build_governor(ciba_approval_per_min)` and
`RateLimitShared("ciba_approval_list")` and relies on the handler's
`shared_rate_limit.check_at_human("ciba_approval_list:{tenant}:{user}")`
(`ciba_approval.rs:299-313`). `SharedRateLimitCounter::check_at_seeded`
returns `true` at once when the shared layer is disabled
(`rate_limit_counter.rs:905-907`; `AXIAM__RATE_LIMIT__SHARED=off`, read at
`:459`). The governor the route lost was in-process and applied whatever that
switch said; no `/api/v1` scope-level limiter exists. So on a deployment that
turns the shared layer off, the route — a datastore count, a list of up to
fifty rows and a client read per distinct client per call — carries no limiter
at all, against the §9 / Phase 23 §7 rule that every route carries one; and on
every deployment, requests that fail authentication are no longer counted on
this route.

**Proposed fix.** Keep D-4's user key and add a fallback that does not depend on
the shared switch: an in-process per-user keyed limiter (a `governor`
`KeyedRateLimiter<(Uuid, Uuid)>` held in `AppState`, checked when
`!shared_rate_limit.is_enabled()`), and put back an IP-keyed
`build_governor` on the route sized for NAT (for example ten times
`ciba_approval_per_min`) as the unauthenticated backstop. Test: with the shared
counter disabled, the list answers `429` after `ciba_approval_per_min` calls of
one user, and a second user behind the same address is not refused.

## 5. R101W3-05 — the hint cap's rows are never swept

**Severity: Low** (availability, storage). **Wave-introduced** (W3.6).

**Evidence.** `CibaHintCap::admit` (`ciba.rs:912-937`) increments
`{base}:{index % 2}` and reads `{base}:{(index-1) % 2}` with
`increment_by(…, 0)` (`:932`), an `UPSERT` (`rate_limit.rs:100-106`) that
**creates** the row when it does not exist. A call naming a hint the client has
not named before therefore creates two `rate_limit_bucket` rows. Nothing in the
tree deletes from `rate_limit_bucket` (no `DELETE rate_limit_bucket` anywhere;
the cleanup job has no step for it). The bucket base is a keyed digest of an
attacker-chosen hint, so the cardinality is the caller's: an authenticated CIBA
client at the internet default (`bc_authorize_per_min` 60) adds up to 120 rows
a minute, 172 800 a day, forever (1 200 and 12 000 a minute under the gateway
and mesh presets). The hint is not stored in clear, so this is not a privacy
issue; it is unbounded growth of a table every shared limiter writes.

**Proposed fix.** Read the previous window with a `SELECT count FROM
type::record('rate_limit_bucket', $key) WHERE window_start = $prev_start`
instead of an upsert of zero; add a cleanup step that deletes
`rate_limit_bucket` rows whose `updated_at` is older than twice the longest
window in use (twenty minutes for `ciba_hint_cap:` keys, two minutes for the
limiter keys — or one generous bound for all). Test: a call for a new hint
creates one row; the sweep removes rows older than the bound and keeps current
ones.

## 6. W3.1, W3.2, W3.3 and W3.4 — grants, clients and scopes

### W3.1 (#604) — holds

`poll_at` redeems first (single use decided before anything else), reads the
tenant, re-reads the user and applies `crate::ciba::user_may_be_subject`
(`account_may_act && !is_locked_out`) — the CIBA predicate, called, not copied
(`ciba.rs:721`). `NotFound` is `invalid_grant`, any other store error
`server_error` (CIBA's mapping); nothing is minted and no refresh-token row is
written before the check. A refused account burns the grant, so the refusal
cannot be retried into a token after a reactivation (T-163's amendment says so).
The three tests (suspended, locked out, deleted) assert no token and no
refresh-token row. The device grant was the last mint path without the account
check: the code, refresh, CIBA grants, UserInfo and introspection already ask.

### W3.2 (#601) — holds, with residuals (R101W3-08)

* **Order and uniformity.** `authenticate_client_credential` runs
  `verify_client_credential` first and reads the tenant only when the
  credential checked out; `NotFound` is `invalid_client` with
  `CLIENT_AUTH_FAILED`, any other error `server_error`. A deleted tenant's
  client with a wrong credential pays one verify and gets the ordinary refusal;
  with the right credential it pays the verify **and** one indexed read and
  gets the same refusal. The extra read is on a path only the credential's
  holder can reach, so it is no oracle for "this tenant was deleted" to anyone
  who does not already authenticate as the client. A deleted tenant's client
  therefore **does** still pay the verify — uniform with every other refusal
  (§9).
* **Coverage.** Every client-credential path in the tree reaches it: the
  `authorization_code`, `client_credentials` and `refresh_token` grants and
  `exchange_ciba` call it directly and now take `org_id` from its result (the
  second tenant read is gone, so their read count is unchanged — a counting stub
  asserts it); revocation, introspection, PAR, `bc-authorize`, token exchange and
  the UMA ticket grant reach it through `authenticate_client`. `tls_client_auth`
  hands back the read it already made. CIMD materialisation reads the tenant
  itself (`cimd.rs:82`). gRPC has no client-secret path (the services
  authenticate a bearer token; no `client_secret` in `axiam-api-grpc` or
  `proto/`), and AMQP authenticates by HMAC subkey. An `sa_` id goes to the
  service-account table and never reaches the client row; its grant reads the
  tenant after its own verify (`token.rs:1636-1641`), answering
  `invalid_request "unknown tenant"` — refused, but in a different shape
  (R101W3-08).
* **Not covered:** the device grant, which authenticates no client
  (R101W3-01), so `/oauth2/device_authorization` still serves a tombstoned
  tenant's client and the poll answers `server_error` (R101W3-08).
* **Client-visible change.** For a tombstoned tenant only, the grants answer
  `401 invalid_client` (with the RFC 6749 §5.2 challenge) instead of
  `400 invalid_request "unknown tenant"`. No contract row names the old answer
  (CONTRACT §2 dispatches on the `error` field), the OpenAPI document is
  unchanged by it, and an SDK token cache that treats `invalid_client` as
  terminal stops retrying — the right outcome for a deleted tenant. No break.
* **Quick bench.** The plan's token cell was **not run** (no Docker image build
  is possible on the executor's box; the commit body says so and gives the
  reasoning: the token cell's `client_credentials` path performs the same two
  reads before and after). The orchestrator should run it on a box that can
  build the image, or record the omission in §11 of the plan.

### W3.3 (#610 (d)) — holds

Both `delete_all_for_client` statements are `WHERE tenant_id = $tenant_id AND
client_id = $client_id`, every status, idempotent, counted from `RETURN BEFORE`;
the repository tests cover another tenant's same `client_id` and another
client. `ClientGrantStores::revoke` visits refresh tokens, codes, pushed
requests, device grants, CIBA requests in that order and returns the first
failure; the administrator's `DELETE` and the sweep keep the row and retry, RFC
7592's path deletes then revokes as before (#517). A poll racing the delete
either redeemed first (and minted for the old client; the second revoke pass
voids its refresh token unless written later, the documented shared window) or
matches nothing in the guarded `UPDATE`. On the executor's question: the
device poll does not authenticate the client at all — that is R101W3-01; W3.3
narrows it (deletion now voids the grant) and widens nothing. Its stated
rationale about CIMD re-materialisation is moot, since a CIMD client can hold
neither grant (R101W3-09).

### W3.4 (#613) — holds, with R101W3-02

* **Every read point.** The ceiling is applied at `/oauth2/authorize` step 5
  (query and PAR; a request object is refused earlier), the
  `authorization_code` grant (the code's scopes, before `consume`), the
  `client_credentials` grant, the `refresh_token` grant (before the `stored ∩
  client` intersection and before rotation), the CIBA grant (before `redeem`),
  `bc-authorize` and the token-exchange grant (after `authenticate_client`, so
  a stranger costs no read) and `/oauth2/device_authorization`. Every other
  `client.scopes` reader in `axiam-oauth2` and `axiam-api-rest` is a validator
  of administrator input (`gdpr.rs:829,858`, `ssf_admin.rs:373`) or a read-back
  (`dcr.rs:785`, `oauth2_clients.rs:717`); introspection reports the token's own
  scope. The ID token at the code and refresh grants follows the narrowed set
  (`openid` checked on it, `token.rs:2240,2956`).
* **Fail closed.** For a `dcr`/`cimd` client a policy read error is
  `server_error`, never a fall-back to the row; the default port
  (`unwired()`) refuses, and both composition roots install
  `SettingsScopePolicy` on the three services. An administrator's client
  never reads it (`applies_to`).
* **The empty list, and upgrades.** 1.0.0's `dcr::validate` and
  `cimd::validate` refused every requested scope not on the effective list
  (`dcr.rs:534-539`, `cimd.rs:568-573` at `v1.0.0`), so a client registered
  while the list was empty — or before any policy existed (an absent settings
  row reads as the defaults, an empty list) — holds no scopes, and the ceiling
  strips nothing from it. Rows registered under a list that was later narrowed
  lose the withdrawn scopes — the intended fix. **One 1.0.0 path did put scopes
  outside the list on an external row:** the administrator's
  `PUT /api/v1/oauth2-clients/{id}` (`oauth2_clients.rs:805-1015`) applies
  `req.scopes` to any client, whatever its `managed_by`, and 1.0.0 honoured them;
  after the upgrade they are withheld (R101W3-02).
* **Residuals, as documented.** An access token minted before a withdrawal
  keeps its scope for its lifetime; a pending device code mints the scopes
  recorded at `device_authorization` (the poll reads no client — R101W3-01);
  both narrow at the next refresh. The device and CIBA cases are reachable only
  for an external row an administrator gave those grants (DCR and CIMD register
  only the code grants). The CIBA grant mints an ID token even when the ceiling
  removed `openid` (`token_ciba.rs:291-321`, "CIBA Core §10.1.1: an ID token is
  always returned") — on the same administrator-edited rows only (R101W3-09).

## 7. W3.5, W3.6, W3.7 and W3.8

### W3.5 (#602, D-5) — holds, with R101W3-03 and R101W3-07

* **The bound.** The receipt is written after the stream drains and the export
  reads `to: started_at` (`tenants.rs:845,866`), so `exported_through`
  (= `started_at`) is the right bound and the receipt's own timestamp is not —
  the executor's correction of the plan is right. The deletion copies it as
  `audit_exported_through`; a 1.0.0 deletion record is answered from the
  receipt it names, which is after the bound and therefore still present.
* **Fail-safe.** No `tenants.deleted` record, or no parseable time: the audit
  stage is skipped entirely (no row, no signature), the report says `null`,
  and the retention sweep governs.
* **Signatures.** `audit_signature` rows go only when no `entry_id` is still in
  the log (tested with one-sided and mixed signatures). The table is defined
  but never written today (`audit.rs:508`), so the rule is future-proofing.
* **Schema-scan exemption.** `every_tenant_scoped_table_is_purged` now allows
  exactly two keeping rules, each pinned to its table: `RevokedUntilExpiry` to
  the two certificate tables and `AfterExport` / `CoveringKeptEntries` to
  `audit_log` / `audit_signature`; any other table that keeps a row still fails
  it.
* **Kept rows.** `prune_older_than` deletes by age across tenants, so kept rows
  go at the window (tested); with retention off they stay, as documented.
  Nothing reads them: audit reads are scoped to a live tenant or the system
  log, and `orphaned_tenant_ids` excludes the audit tables, so kept rows do not
  make the id an orphan (tested). No job iterates audit rows by tenant.
* **Append-only.** The purge updates no audit row; `audit.rs`'s module doc names
  it as the second deletion path.

### W3.6 (#599, D-4) — holds, with R101W3-04, -05, -06

* **The oracle is closed.** In `initiate` (`ciba.rs:1224-1370`) the hint is
  reduced to what it names without a lookup (`name_in_hint`: the login hint as
  sent, or an `id_token_hint`'s verified subject — the same signature check for
  every hint), then `CibaHintCap::admit` runs two `increment_by` upserts, then —
  only if admitted — `resolve_subject` looks the user up. For a known, an
  unknown and an inactive or locked hint: **the answer** at the fourth call is
  the same `429 slow_down` body; **the cost** of a refusal is the same two
  upserts and nothing else; **the side effects** of a refusal are the same (no
  lookup, no row, no notification, no audit row — the `oauth2.ciba_initiated`
  row is written only after `initiate` succeeds). The admitted path is 1.0.0's
  plus the two upserts: the request is stored with or without a subject and only
  a real, permitted user is notified (detached, behind the per-user throttle) —
  D-63 unchanged. The one pre-existing difference on the admitted path (a
  username miss costs a second, e-mail lookup) is now sampled at most three
  times per hint per client per ten minutes, which makes it harder, not easier,
  to measure.
* **Counting.** One atomic `UPSERT … count + $delta` per call; a stale
  same-parity slot is reset only by a *newer* window (`window_start <
  $window_start`), so clock skew between replicas makes the cap stricter, never
  looser. The two-window rule bounds every ten-minute stretch at three
  admissions, so one client never holds a fourth open request for one hint.
* **Key.** HMAC-SHA256(signing-key PEM, `"axiam/ciba/hint-cap/v1"`): one-way,
  domain-separated, used only to key digests — acceptable separation from the
  signing use; `main.rs:391-395` asserts a non-empty PEM at start, so the
  key is never a public constant. A signing-key rotation resets every count
  once (lenient for one window), and replicas holding different PEMs during a
  rolling rotation count separately for that time.
* **Independent of `AXIAM__RATE_LIMIT__SHARED`.** The cap talks to the store
  directly, so turning the shared layer off does not turn the cap off — the
  right direction for a security bound. A datastore error is `server_error`
  (fail closed).
* **The list.** Ordered by `created_at, record_id`; client names read once per
  distinct client; `total_pending` is `max(count, listed)` so the two
  non-snapshot reads cannot make it smaller than what is shown; `truncated` is
  derived. The user-keyed bucket is checked after the `minted_for_client`
  refusal, so a token minted for a client cannot spend a user's allowance — but
  see R101W3-04 for what the route lost.
* **OpenAPI.** Regenerated: the two new required members, the list's ordering
  text, both `429` descriptions; the digest matches and the management
  registry is in sync (§12).

### W3.7 (#610 (a)) — holds

All 76 added and 50 removed lines in the 14 files are `//` or `///` comments
(checked mechanically); they now say the browser preset gives a late peer its
whole budget, which `b04c93e` made true.

### W3.8 (#610 (b)) — holds

* **The real path.** `RouteFixture::listen` writes and installs the anchor
  bundle with `TrustAnchorReload` (what flagging a CA runs), builds the
  listener with the server's own `build_rustls_server_config`
  (`ClientAuth::Optional`), installs `tls::lift_verified_client_certificate` as
  `on_connect`, and serves `register_api_v1_routes` with a real `AppState`; a
  `tokio-rustls` client presents the leaf and speaks HTTP/1.1 to
  `POST /oauth2/token`. No extractor or `PresentedCertificate` is faked; the
  issuer-path control turns red if the hook drops the path (the executor's
  mutation check).
* **The mutex.** The live verifier is a process global; the three route tests
  hold a `tokio::sync::Mutex` (no poisoning, so a failed test does not wedge the
  others) for their whole body; no other test in the binary touches the global
  verifier.
* **The extraction** moves boot's closure body to `tls.rs` unchanged — the same
  downcast, the same `peer_certificate_trust`, the same issuer path only for a
  chained certificate, the same warning on a parse failure — and `boot` passes
  the function to `on_connect`.

## 8. The Informational findings

* **R101W3-02** (W3.4) — see §6 and §13.
* **R101W3-06** (W3.6) — `MAX_REQUESTS_PER_CLIENT_HINT = 3` and
  `HINT_CAP_WINDOW_SECS = 600` are constants; no `RateLimitConfig` field, no
  preset and no environment knob moves them, and refused calls count, so a
  client that keeps retrying stays refused. The OpenID FAPI-CIBA test plan (the
  next certification target, `docs/compliance/oidc-conformance.md:570`) runs
  many modules with one configured client and one `login_hint` within minutes;
  an SDK's CIBA integration suite against a live server does the same. Both
  will meet `429 slow_down` after the third flow.
* **R101W3-07** (W3.5) — the bound and the row timestamps come from two clocks;
  see §13.
* **R101W3-08** (W3.2) — see §6 and §13.
* **R101W3-09** — see §13.

## 9. The §9 rules (Phase 23 §7), against what the wave added

| Rule | Verdict | Evidence |
|---|---|---|
| Every new route carries a limiter from its first commit | **holds** (no new route); **one existing route lost its limiter under `SHARED=off`** | R101W3-04: `/api/v1/ciba/requests` |
| Every credential-bearing outbound request uses `guarded_fetch_no_redirect` | **not exercised** | the wave adds no outbound request |
| Every refusal of a credential check costs one verify | **holds** | the tombstoned-tenant refusal is decided after `verify_client_credential` (`token.rs` `authenticate_client_credential`); W3.1's and the cap's refusals are not credential checks |
| Two-writer registries are written conditionally on the version read | **not exercised** | the cap's counter is one atomic upsert; W3.3 and W3.5 only delete |
| Schema: only W1 adds migrations | **holds** | `schema.rs` changes only in `mod tests` |
| Contract: no wave but W5 edits `CONTRACT.md`; W3.6 regenerates the spec | **holds** | `sdks/CONTRACT.md` untouched; `sdks/openapi.json` regenerated in `67be51198`/`3c6e951d1` |
| Threat model: nothing enters without its test; corrections dated | **holds** | every amendment names its tests and is dated 2026-10-13; T-422/T-424's first W3.6 text is recorded as a same-day correction |
| `[lints]` / layering | **holds** | no new crate; `axiam-oauth2` gains `hmac` (already in the graph); `check-crate-layering.py` passes |

## 10. Threat-model text against the code

| Entry | Verdict |
|---|---|
| T-39 (account re-check at every grant) | true; the device grant now asks (W3.1) |
| T-163 (device-code single use) | true |
| T-472 (tenant tombstone and purge) | true for every client-**credential** path; `/oauth2/device_authorization` is not covered (R101W3-08); the audit amendment is true against honest receipts (R101W3-03) and on agreeing clocks (R101W3-07) |
| T-289 (client deletion, refresh narrowing, ceiling) | true; "for a cimd client the re-materialised row left both live" is moot — a CIMD client can hold neither grant (R101W3-09); the ceiling's effect on administrator-added scopes is unstated (R101W3-02) |
| T-275 | true |
| T-55 | true |
| T-118 | true against honest receipts (R101W3-03) |
| T-424 | true; "the table holds two rows per (client, hint) named" — and nothing removes them (R101W3-05); the fixed figures (R101W3-06) |
| T-422 | true: answer, cost and side effects of the cap are uniform (§7) |
| T-102, T-475 (route-level tests) | true (§7) |

Totals: `Axiam.json` 2.40.0, `threatTop` 475, 437 Mitigated / 17 Open / 21 Not
applicable, matching the STRIDE document and the generated file; the eleven
entries changed against `v1.0.0` are exactly the ones above, no id was added or
removed, no status changed, and every sentence W3 added to an entry in
`Axiam.json` occurs in the STRIDE document (checked mechanically).
`claude_dev/threat-modeling-and-security.md` and `website/src/security.ts` are
left to W7.3 as the plan says.

## 11. Documentation claims

| Claim (where) | Verdict |
|---|---|
| "a re-materialised CIMD client authenticates that poll" (`client_grants.rs` module doc), "and again once a `managed_by: cimd` client was re-materialised" (CHANGELOG #610 (d)) | **false**: a CIMD client registers only the code grants, and the poll authenticates no client (R101W3-09) |
| "Clients created by an administrator never read the list and are unaffected" (CHANGELOG #613) | true, and incomplete: scopes an administrator adds to an external client are withheld (R101W3-02) |
| "drops it … from a `client_credentials` or CIBA token" (DCR guide) | true but only reachable for an administrator-edited external row |
| "every audit read is by tenant_id … kept rows neither surface anywhere" (W3.5) | true |
| "the refused path costs the same two counter upserts whoever the hint names" (T-422, handler module doc) | true |
| "`DELETE …/oauth2-clients/{id}`: its refresh tokens, authorization codes and pushed requests are revoked first" (OpenAPI) | incomplete since W3.3 (R101W3-09) |
| "`… 730 days by default`" (GDPR doc) | true (`AXIAM__AUDIT_RETENTION_DAYS`) |

## 12. Checks run

Each command with its own exit code (logs in the scratchpad;
`CARGO_INCREMENTAL=0`, swagger placeholder, no `cargo clean`).

| Check | Result |
|---|---|
| `cargo test -p axiam-oauth2 --lib` | pass (612) |
| `cargo test -p axiam-oauth2 --test token_service` | pass (136) |
| `cargo test -p axiam-db --test tenant_purge_test --test ciba_request_repository_test --test device_grant_test` | pass (7, 13, 12) |
| `cargo test -p axiam-db --lib every_tenant_scoped_table_is_purged` | pass (1) |
| `cargo test -p axiam-api-rest --no-default-features --test ciba_test --test ciba_approval_test --test device_flow_test --test dynamic_registration_test --test oauth2_client_test --test tenant_test` | pass (ciba_test 25, ciba_approval_test 23, device_flow_test 18, dynamic_registration_test 41, oauth2_client_test 32, tenant_test 23) |
| `cargo test -p axiam-server --no-default-features --test cleanup_task --test server_leaf_profile` | pass (cleanup_task 26, server_leaf_profile 6) |
| `cargo fmt -p` axiam-oauth2, axiam-api-rest, axiam-db, axiam-core, axiam-server `-- --check` | pass (all five; see R101W3-09 for the line rustfmt skips) |
| **R101W3-03 probe** — a temporary `crates/axiam-amqp/tests/zz_f4_probe.rs` (an AMQP audit event signed with the tenant's subkey forging a receipt, the delete handler's receipt query, the deletion record the handler writes, `purge_tombstoned`), run and deleted | the event is acknowledged; the handler's receipt query returns it with `exported_through` 2100-01-01; `purge_tombstoned` reports that bound and **4 audit rows deleted, 0 kept** — the two rows before the "export", the forged receipt and a row written after the deletion |
| `node website/scripts/gen-threat-model.mjs` | 475 threats (437 / 17 / 21); no diff |
| `Axiam.json` vs `v1.0.0`, and vs the STRIDE text (script) | 11 entries changed, no id added or removed, no status changed; every W3 sentence present in both |
| `python3 scripts/check-spec-digest.py` | pass (`sha256:a9a67b20…`) |
| `python3 scripts/gen-management-registry.py --check` | pass (190 operations, 28 namespaces) |
| `python3 scripts/check-crate-layering.py` | pass |
| `--dump-openapi` byte comparison | `cargo build -p axiam-server --no-default-features`, then `--dump-openapi`: byte-identical to `sdks/openapi.json` |
| Commit signatures | 9 of 9 carry `gpgsig` |
| Quick-bench token cell (plan W3.2) | **not run** (no image build possible here; nor by the executor) |

## 13. Issue bodies

### R101W3-01 (Low) — the device-code grant authenticates no client

The `urn:ietf:params:oauth:grant-type:device_code` grant is dispatched before
client authentication (`handlers/oauth2.rs:2141-2185`) and
`DeviceAuthorizationService::poll_at` (`device_service.rs:274-439`) finds the
grant by the device-code hash alone: it ignores `client_id`, never reads the
client, never authenticates it, never applies `fapi::enforce_token_request`, and
mints an access token without `cnf`. `/oauth2/device_authorization` checks only
that `client_id` exists and holds the grant. The admin API admits the grant on
any client (`oauth2_clients.rs:422-431`). For a confidential client this
contradicts RFC 6749 §3.2.1 and RFC 8628 §3.1/§3.4; consequences: a leaked
device code is redeemable by anyone; anyone can start a device flow in a
confidential client's name and redeem a phished approval for that client's
tokens; a DPoP-, mTLS-bound or `fapi2` client gets unbound bearer tokens; an
approved grant redeems after the client loses the grant type or rotates its
secret. **Fix:** at the poll require `client_id` and refuse one that is not the
grant's; read the client (gone or no longer holding the grant →
`invalid_client`); for a non-public client run
`authenticate_client_credential` with the request context, the FAPI checks and
the token binding the other grants apply; authenticate a non-public client at
`/oauth2/device_authorization` too — or, minimally, refuse the grant on
non-public, `fapi2` and sender-constrained clients at registration and update.
**Tests:** a confidential client's grant needs its secret at the poll; a
foreign `client_id` is `invalid_grant`; a DPoP-bound client's device token
carries `cnf.jkt`; removing the grant type refuses an approved grant.

### R101W3-02 (Informational) — the scope ceiling withholds administrator-added scopes

#613 bounds a `managed_by: dcr|cimd` client's scopes by the tenant's effective
`dcr_allowed_scopes` at every read point. Registration (`dcr::validate`,
`cimd::validate`) never let such a row hold a scope outside the list, but the
administrator's `PUT /api/v1/oauth2-clients/{id}` (`oauth2_clients.rs:805-1015`)
writes `scopes` (and `grant_types`) on any row whatever its `managed_by`, and
1.0.0 honoured them. After the upgrade those scopes are silently withheld —
`invalid_scope` at authorize, dropped at refresh — while the admin API keeps
accepting them and `GET` keeps showing them. **Fix:** a CHANGELOG upgrade note
in 1.0.1 ("scopes an administrator added to a self-registered or CIMD client
outside `dcr_allowed_scopes` are no longer served"); have the admin `create`/
`update` refuse (422) scopes outside the effective list on a non-`admin` row,
or exempt them by recording the administrator's grant separately; optionally a
one-off report of external rows holding scopes outside the list. **Test:** the
admin PUT of an outside scope on a DCR row is refused.

### R101W3-03 (Low) — a forged export receipt sets the purge bound

The deletion accepts the newest `tenants.audit_exported` / `Success` row of the
tenant's audit log (`tenants.rs:142-173`) and, since #602, copies its
`metadata.exported_through` into `tenants.deleted`, which bounds what the purge
deletes. The AMQP audit consumer (`audit_consumer.rs:177-186`) appends any
action and metadata a message signed with the tenant's subkey carries; tenant
producers hold that subkey. A forged receipt therefore satisfies T-118's export
requirement without an export (pre-existing) and, with an `exported_through` in
the future, makes the purge delete every audit row of the tenant (probe: bound
2100-01-01, all rows deleted, the forged receipt and a post-deletion row
included). **Fix:** reserve the server's control actions (`tenants.*`,
`gdpr.*`) in `process_audit_event`; clamp the purge bound to the named
receipt's datastore `timestamp`, and refuse at deletion a receipt whose
`exported_through` is after its own timestamp. **Tests:** a reserved action from
AMQP is not persisted; the bound never exceeds the receipt's timestamp.

### R101W3-04 (Low) — `/api/v1/ciba/requests` has no limiter under `SHARED=off`

#599 (D-4) removed the route's `build_governor` and `RateLimitShared` and counts
in the handler on the shared counter (`ciba_approval.rs:299-313`), which admits
everything when `AXIAM__RATE_LIMIT__SHARED=off`
(`rate_limit_counter.rs:905-907`). The route then has no limiter, and requests
that fail authentication are counted nowhere on it. **Fix:** an in-process
per-(tenant, user) limiter used when the shared layer is off, plus a NAT-sized
IP governor on the route as the unauthenticated backstop. **Test:** with the
shared counter disabled, one user is refused after `ciba_approval_per_min`
calls and a second user behind the same address is not.

### R101W3-05 (Low) — the CIBA hint cap's rows are never swept

`CibaHintCap::admit` (`ciba.rs:912-937`) creates two `rate_limit_bucket` rows
per novel (client, hint) — the previous-window read is an `UPSERT` of zero — and
nothing deletes from that table. An authenticated CIBA client choosing hints
adds up to 120 rows a minute at the internet default (1 200 / 12 000 under the
gateway / mesh presets), permanently. **Fix:** read the previous window with a
`SELECT`; add a cleanup step deleting `rate_limit_bucket` rows whose
`updated_at` is older than twice the longest window in use. **Test:** a new hint
creates one row; the sweep removes stale rows and keeps current ones.

### R101W3-06 (Informational) — the hint cap cannot be configured

`MAX_REQUESTS_PER_CLIENT_HINT = 3` and `HINT_CAP_WINDOW_SECS = 600` are
constants, and refused calls are counted. The FAPI-CIBA conformance plan and SDK
CIBA integration suites, which run many flows with one client and one test user
in minutes, will be refused after the third for ten to twenty minutes. **Fix:**
a `RateLimitConfig` field (and environment knob) for the per-hint allowance,
validated `>= 1`, defaulting to 3; document the conformance setting; consider
not counting refused calls (the two-window rule already bounds admissions).

### R101W3-07 (Informational) — the export bound and the row timestamps use two clocks

The export fixes `started_at = Utc::now()` on the application host
(`tenants.rs:845`) and pages `timestamp <= started_at ORDER BY timestamp DESC`
by offset (`audit.rs:355`); `audit_log.timestamp` is the datastore's
`time::now()` (schema `DEFAULT time::now()`). If the application's clock leads
the datastore's by δ, a row inserted during the export with a timestamp in
`(t0 − δ, started_at]` lands ahead of rows already paged, is not exported, and —
since #602 — is deleted by the purge as if it had been. **Fix:** take the bound
from the datastore (`RETURN time::now()` at export start), or have the purge
delete `timestamp <= exported_through − margin` (a few seconds; the retention
sweep takes the rest).

### R101W3-08 (Informational) — W3.2's residual paths

(a) `/oauth2/device_authorization` reads the client row (which lives until the
purge) and no tenant, so a tombstoned tenant's client still creates
`device_grant` rows and user codes until the purge reaches `oauth2_client`; rows
written after the purge passed `device_grant` wait for the orphan scan. (b) The
device poll reads the tenant with `get_by_id` and maps `NotFound` to
`server_error` (`device_service.rs:348-352`). (c) The tombstone transaction
deletes `ciba_request` but not `device_grant`. (d) The `sa_`
`client_credentials` path answers a tombstoned tenant `invalid_request "unknown
tenant"` (`token.rs:1636-1641`) where an OAuth2 client now gets
`invalid_client`. **Fix:** read the tenant in `DeviceAuthorizationService::
authorize` (or fold it into R101W3-01's client authentication); map the poll's
`NotFound` to `invalid_grant`; add `DELETE device_grant WHERE tenant_id = $id` to
the tombstone transaction; answer the `sa_` path's `NotFound` with
`invalid_client`.

### R101W3-09 (Informational) — text and hygiene

(a) `client_grants.rs`'s module doc ("a re-materialised CIMD client
authenticates that poll"), the #610 (d) CHANGELOG entry and T-289's amendment
justify voiding device grants and CIBA requests by CIMD re-materialisation; a
CIMD client registers only the code grants (`cimd.rs:75`) and the poll
authenticates no client — the real reason is R101W3-01. (b) The OpenAPI text of
`DELETE /api/v1/oauth2-clients/{id}` still lists only refresh tokens, codes and
pushed requests. (c) The CIBA grant mints an ID token even when the ceiling
removed `openid` (`token_ciba.rs:291-321`); reachable only on an
administrator-edited external row. (d) `boot.rs:2766` has `)),` at column 0;
rustfmt leaves the enclosing expression unformatted, so `cargo fmt --check`
passes. (e) The plan's quick-bench token cell for W3.2 was not run. (f) The
`audit_signature` purge rule acts on a table nothing writes (`audit.rs:508`).
(g) `count_pending_for_user`'s `client_id` filter has no production caller.
**Fix:** correct (a)–(b), skip the ID token (or refuse) when `openid` is gone in
(c), re-indent (d), run (e), leave (f)–(g) or remove the filter.
## 14. Invariants of the wave's behaviour changes

Every behaviour change is one a task names: the device grant refuses an account
that may not act; a deleted tenant's client is `invalid_client` everywhere it
authenticates; client deletion voids device grants and CIBA requests; an
external client's scopes are bounded by the current list; the purge keeps audit
rows after the export; `bc-authorize` refuses a fourth call per hint; the list
is oldest-first with two additive members and a per-user bucket. Two are
client-visible beyond what the CHANGELOG says: R101W3-02 (administrator-added
scopes on external rows) and R101W3-06 (the cap's fixed figures). This review
changed no file but itself; the probe test was deleted before the commit, and
the test binaries it built were removed from `target/`, which was not cleaned.
