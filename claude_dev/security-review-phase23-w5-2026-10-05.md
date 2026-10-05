# Security review — Phase 23, wave W5 (F4)

**Date:** 2026-10-05.
**Against:** `claude/phase23-w5`, the whole wave diff `3ddd8b8..21f1521` (71
commits, 204 files, about 49 200 lines added and 5 200 removed; `3ddd8b8` is the
W4 merge on `main`). T23.8.3 (the minimal profile's compose file, measurement and
documentation) ran in parallel and touches only `docker/`, `docs/`, the website's
*Operate* page, `benchmarks/` and the CHANGELOG; it is not in this diff. The fixes
of this review sit on top: `d4ff514` (P23W5-01, P23W5-02), `f380891` (P23W5-03,
-04, -05), `6ac3671` (P23W5-08), `7439a28` (P23W5-12), `9e52b1f` (the threat
model, 2.35.0), the spec and registry regeneration, and the documentation commit
that carries this file.
**Scope:** every W5 task of
[`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md):
G-6 outbound SCIM (T23.6.1 – T23.6.4; D-57, D-58; contract §31), G-7 CIBA
(T23.7.1 – T23.7.3; D-61 … D-71; contract §33 and §21.3.1), G-8 the minimal
profile (T23.8.1 and T23.8.2's fixes; D-59, D-72), the D-60 conformance harness
(`.github/workflows/fapi-conformance.yml`, `benchmarks/`, `conformance/`) and the
SAML test-harness stack fix (`5a5bddf`, tests only).
**Method:** adversarial reading of the diff and of every sibling path it implies,
against [`threat-model-stride.md`](threat-model-stride.md) (model 2.34.0: T-407 …
T-445 are this wave's) and `ThreatDragonModels/Axiam/Axiam.json`, and the OWASP
ASVS 5.0 areas the diff touches (V1 encoding and injection, V2 validation and
business logic — concurrency, V3 web frontend, V4 API, V6 authentication, V7
session management, V8 authorization, V10 OAuth/OIDC — CIBA, V11 cryptography,
V12 secure communication — SSRF, V13 configuration, V14 data protection, V16
logging). D-56 … D-72 were read verbatim and are binding; every route the diff
mounts was traced to its handler and its limiter. Every finding fixed here has a
test that failed before the fix, run and recorded (§13); a claim with no test says
so.

---

## 0. Summary

Eight findings were fixed on the branch, all wave-introduced or bookkeeping the
wave left stale. Two are the items G-6 carried here: **P23W5-01** (Medium, T-409)
— a client-credentials SCIM target's `base_url` could move without the secret, and
the next freshly minted access token went to the new host; the secret is now
bound to `base_url` as well as `token_url`. **P23W5-02** (Medium, T-418) — every
SCIM dead letter mailed every recipient of a `scim_delivery_failed` rule; it is
now one notification per target per hour, claimed in the datastore, with every
dead letter still audited (proposed **D-73**). Three are CIBA's, found here:
**P23W5-04** (Medium, T-447) — an access token AXIAM minted for an OAuth2 client
names the user and a live session, and the approval routes admitted it, so the
CIBA client that redeemed one request could open and approve the next in its
user's name; only a console sign-in decides now. **P23W5-03** (Low, T-446) — the
approval mail went to unproven addresses, a phishing relay for a client that can
call `bc-authorize`; only a vouched address is mailed (proposed **D-74**).
**P23W5-05** (Low, T-435) — decisions were audited without the deciding session.
P23W5-08 is CodeQL hygiene, P23W5-12 the website's trust-boundary table, P23W5-14
the model's `threatTop`.

Five are reported with issue bodies (§14): the same client-token approval on the
**device grant**, pre-existing since B2 (P23W5-06, Medium, T-447 stays Open); a
tarpit SCIM downstream that stalls every tenant's provisioning on a replica
(P23W5-07, Medium, wave-introduced but a design decision); the SCIM admin `PUT`
that carries no client version (P23W5-09, Low); the webhook deliverer's redirects
(P23W5-10, Informational, pre-existing, no credential carried); the conformance
workflow's gate and an input interpolated into a script (P23W5-11). T-117's
mitigation claimed notification batching that never existed: reopened (P23W5-13).
T-108 stays Open with T23.8.2's A10 issue body.

**The CIBA core held.** Single-use redemption on the two-layer arbiter, polls that
never move the version, D-63's decoy request, lockout at request, approval and
redemption (the Keycloak 26.7.x class), signed requests verified only against
registered keys, ping through the no-redirect guard with the client re-read
before the credential leaves (§8). Outbound SCIM's level-triggered deliverer, its
one guarded HTTP path, the target re-read before every credential leaves and
reconciliation's refusal to touch foreign accounts held (§7). The `boot.rs` move
composes the full profile exactly as `main.rs` did (§9).

| ID | Finding | Severity | Surface / threat | Disposition |
|---|---|---|---|---|
| **P23W5-01** | A client-credentials SCIM target's `base_url` could be moved without the secret; the next attempt minted a fresh access token at the unchanged `token_url` and presented it to the new host — an administrator who never held the secret collects a live token for the real downstream. | Medium | §31 `PUT`, deliverer; D-57 → **T-409** | **Fixed** — `d4ff514` (T-409 Mitigated; contract §31.3 rule 2 amended) |
| **P23W5-02** | One notification mail per SCIM dead letter: a target down, or refusing AXIAM's credential, mails each recipient of a `scim_delivery_failed` rule once per reference — a tenant's worth at the next reconciliation. | Medium | dead-letter row, notification rules; D-58 → **T-418** | **Fixed** — `d4ff514` (proposed D-73, schema v84; T-418 Mitigated) |
| **P23W5-03** | The CIBA approval mail went to whatever address an account carried, proven or not: a self-registered account with a stranger's address plus a client that can call `bc-authorize` makes AXIAM mail that stranger up to three times a minute, quoting client-chosen text. | Low | `CibaMailNotifier` → **T-446** (new) | **Fixed** — `f380891` (proposed D-74) |
| **P23W5-04** | The approval routes admitted an access token AXIAM minted for an OAuth2 client (it names the user and a live session): the CIBA client holding one from an earlier redemption could open and approve its next request in the user's name. | Medium | `/api/v1/ciba/requests/*` → **T-447** (new), T-431 | **Fixed** — `f380891` (contract §33 amended) |
| **P23W5-05** | `ciba.approved` / `ciba.denied` recorded the user but not the deciding session, which T-435 required; the request row that holds it is swept, and a refusal stores none. | Low | approval audit → **T-435** | **Fixed** — `f380891` (T-435 Mitigated) |
| **P23W5-06** | The device grant's `/api/v1/device/decide` admits the same client-minted token: a relying party holding a user's `openid` token approves a device flow it started and gets its device client's scopes and a refresh token. | Medium | device grant (B2) → **T-447** | **Reported** (pre-existing; §14) |
| **P23W5-07** | One `scim_push` consumer per replica, one attempt at a time for every tenant: a downstream that never answers costs 10–20 s per attempt, and a reconciliation of 10 000 users stalls every tenant's provisioning on that replica for more than a day. The 10 000-member dead-letter bound is untested. | Medium | deliverer, reconciliation; T-414 | **Reported** (wave-introduced, needs a decision; §14) |
| **P23W5-08** | CodeQL hygiene: credential literals in two tests, `assert_eq!`/`assert_ne!` on decrypted credentials and `auth_req_id`s (printed on failure), loop bindings named `token`, one formatted into an assertion. | Informational | tests | **Fixed** — `d4ff514`, `6ac3671` |
| **P23W5-09** | The SCIM admin `PUT` is conditional on the version the server reads, not one the client read: two administrators saving forms are last-writer-wins on everything but the credential binding. | Low | §31 `PUT`; T-416 | **Reported** (§14) |
| **P23W5-10** | The webhook deliverer still uses `guarded_fetch` and re-sends the signed request to a redirect target. No credential travels (an HMAC over a timestamped body), every hop is SSRF-checked. | Informational | webhooks; T-112 | **Reported** (pre-existing; §14) |
| **P23W5-11** | `fapi-conformance.yml`: the gate is red on every unattended run (interactive modules), and the report step interpolates `inputs.axiam_image` into a shell script. | Informational | CI harness (D-60) | **Reported** (§14) |
| **P23W5-12** | The website's Security page said "Five trust boundaries"; the model has ten. | Informational | `website/src/security.ts` | **Fixed** — `7439a28` |
| **P23W5-13** | T-117 claimed notifications are "delivered in configurable batches"; nothing batches them, and a request-path event an attacker can produce in volume mails each recipient once per event. | Medium | notification rules → **T-117** | **Reported** (pre-existing; T-117 reopened; §14) |
| **P23W5-14** | The model's `threatTop` stayed at 443 when T-444 and T-445 entered. | Informational | `Axiam.json` | **Fixed** — `9e52b1f` (447) |

**Verdict on merge.** Nothing open blocks W5. The eight fixes are in and pinned,
the threat model is at **2.35.0 — 447 threats, 426 mitigated / 21 open** — and the
three artifacts and the website agree. The contract amendments are in place
(1.57 §31.3 rule 2, 1.58 §33; both unreleased), and the OpenAPI spec and the
management registry are regenerated. Two proposed decisions go to the maintainer
with this review: **D-73** (one SCIM failure notification per target per hour)
and **D-74** (the CIBA mail to a vouched address only, which leaves federated
accounts unmailed); both are implemented, and either is a one-line change if the
maintainer decides otherwise. P23W5-06, -07, -09, -10, -11 and -13 are issue
bodies for the wave PR (§14), with T23.8.2's A4, A6, A7, A8, A10, A11 and A12.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| SCIM target store, credential sealing, URL binding, conditional writes, link and state rows | T23.6.1 | `db/…/scim_target.rs`, `core/…/scim_target.rs`, schema v79 | **read in full** |
| Provisioning source, provisioner, deliverer, client, token cache, wire | T23.6.2 | `axiam-scim/src/outbound/{deliverer,client,provisioner,wire}.rs`, `core/provisioning.rs`, the repository hooks | **read in full** (deliverer, client); targeted (hooks, wire) |
| Reconciliation, erasure propagation, dead-letter notification | T23.6.3 | `outbound/reconcile.rs`, `audit/notification.rs`, `boot.rs` composition, `account_deletion.rs` (diff) | **read in full** (adoption, deprovision, notification) |
| SCIM management routes, console | T23.6.4 | `handlers/scim_targets.rs`, `pages/scim-targets/*`, `services/scimTargets.ts` | targeted: binding, tenant fence, human-only, rendering |
| `bc-authorize`, signed requests, hints, the request store, the CIBA grant | T23.7.1 | `oauth2/src/{ciba,ciba_signed_request,token_ciba}.rs`, `db/…/ciba_request.rs`, `handlers/ciba.rs` | **read in full** (service, grant, store statements); targeted (signed-request claims) |
| Approval API and page, notifier, ping | T23.7.2 | `handlers/ciba_approval.rs`, `ciba_notifier.rs`, `ciba_ping.rs`, `pages/ciba/*` | **read in full** |
| Contract §33, e2e, ping flow test | T23.7.3 | `sdks/CONTRACT.md` §33, `frontend/e2e/ciba.spec.ts`, `ciba_ping_flow_test.rs` | targeted |
| In-process dispatcher, outcome table, mail channel, lease, refusals, `/health` | T23.8.1, T23.8.2 | `amqp/src/outbound/{inprocess,outcome}.rs`, `mail_inprocess.rs`, `server/src/{profile,messaging}.rs`, `minimal_profile_lease.rs` | **read in full** (dispatcher, outcome); targeted (lease) |
| The `boot.rs` move | T23.8.1 | `3ddd8b8:main.rs`, `d79f81e^:main.rs` against `d79f81e:boot.rs` + `main.rs` | **line-set comparison** (§9) |
| Conformance harness | D-60 | `.github/workflows/fapi-conformance.yml`, `benchmarks/justfile`, `docker-compose.conformance.yml`, `conformance/scripts/run-plan.sh` | **read in full** (workflow); targeted (rest) |
| Logging and test hygiene (CodeQL) | all | every added Rust and TypeScript line | **every added line**, by script and by eye (§6) |

Tests ran against the in-memory SurrealDB harness and the loopback receivers of
the suites (§13). Not run here: the live-broker tests (`#[ignore]`d, no broker),
the Playwright CIBA spec (CI's E2E job is its first run, as T23.7.3 says), the
conformance suite (no network).

---

## 2. P23W5-01 — a client-credentials `base_url` moved without the secret (T-409)

**Severity: Medium. Fixed in `d4ff514`; T-409 Mitigated.**

D-57 bound a credential to "its URL": `base_url` for a bearer target, `token_url`
for a client-credentials target. The client secret does go to `token_url` only —
but every SCIM request then carries the access token minted with it, and the
token cache is keyed by the target's `updated_at`, which any write moves. So a
write changing only `base_url` made the next attempt fetch a fresh token from the
unchanged `token_url` and send it to the new host. An administrator holding
`scim_targets:write`, who was never given the secret, could point `base_url` at a
public host they run and receive a live access token for the real downstream,
usable there with whatever that downstream grants AXIAM for its whole lifetime —
the "disclosure by redirection" rule 2 exists to stop, through the one door it
left open. Bounded only by the human-only permission, the audit row naming
`base_url`, and the address policy (the host must be public).

**Fix.** `moves_credential` (repository) and `check_binding` (handler) treat a
`base_url` change of a client-credentials target as a move of the credential:
`400` naming `base_url` and nothing written, unless the secret is in the same
write. The repository check runs against the very row its conditional write
replaces, so a racing write cannot slip a URL past it (T-416). The console's
`credentialRequiredFor` mirrors it. Contract §31.3 rule 2 (and the §27.5 row) are
amended in place — 1.57 is unreleased — as are the core docs, the website's
outbound SCIM page and the G-6 CHANGELOG entry.

**Tests.** `scim_target_repository_test::a_client_credentials_base_url_needs_the_credential_too`
— the inversion of `a_client_credentials_base_url_may_change_without_the_credential`
— failed before the fix at "a client-credentials base_url moved without the secret
must be refused"; it also pins that a refused move changes nothing and that a
rename still needs nothing. `scim_targets_test::a_client_secret_does_not_follow_the_token_url_nor_a_switch_of_kind`
now expects `400` naming `base_url`, the stored base unchanged, and `200` with the
secret; `scimTargets.test.ts` and `ScimTargetsPage.test.tsx` pin the console.

---

## 3. P23W5-02 — one mail per dead letter (T-418, proposed D-73)

**Severity: Medium. Fixed in `d4ff514`; T-418 Mitigated.**

T23.6.3 wrapped the `scim_push` consumer's audit log in `NotifyingAuditLog`, so
the dispatcher's `scim_push.delivery_failed` row reaches a tenant's rules for
`scim_delivery_failed`; `NotificationDispatcher::dispatch` enqueues one mail per
matched recipient **per row**. A downstream that refuses AXIAM's credential
dead-letters every reference at once (bearer `401`/`403`), and one that is down
dead-letters each after its retry budget; enabling a target or the nightly run
queues the whole tenant. Ten thousand users in scope meant ten thousand mails per
recipient, and whoever can make the downstream refuse could set it off — the
alert flood that buries the real one (T-117) and burns the mail quota.

**Fix — the decision (proposed D-73).** *At most one `scim_delivery_failed`
notification per target per hour; every dead letter keeps its audit row and its
count.* Of the two shapes the carry list offered, "notify on the transition into
failure" alone floods again on a flapping target — one that refuses one user's
representation (`HTTP 400`) while accepting the rest alternates success and dead
letter on every change — so the bound is a window, not an edge. `NotifyingAuditLog`
now takes a `NotificationGate` (no constructor without one) asked only for a
notifiable row, after the append; `axiam_server::scim_notification` implements it
for the `scim_push` consumer by claiming `scim_target_state.failure_notified_at`
with a conditional write (schema **v84**; `ScimTargetStateRepository::claim_failure_notification`,
the `claim_reconciliation` pattern, retried on write conflict, so replicas agree).
A target of another tenant, or one deleted since, claims nothing; a gate that
cannot decide stays silent and logs once rather than failing open into the flood.
The console's `state` (`dead_lettered_total`, `last_failure_reason`) shows the size
of the outage the one mail announces. Rejected: an in-memory per-process window
(N replicas send N mails), a digest mail (a new template and a scheduler for one
event), changing the generic dispatcher for every event (T-117's own issue, §14).

**Tests.** `scim_dead_letter_notification_test::a_targets_dead_letters_mail_each_recipient_once_an_hour_not_once_each`
(fifty dead letters → two mails; another target notifies on its own; a dead letter
naming no target of the tenant notifies nobody; an hour later it notifies again;
53 rows appended) failed before the fix with **100** mails — run with the gate
forced open, since the gate's module is new. `scim_target_repository_test::claim_failure_notification_succeeds_once_per_interval`,
`concurrent_failure_notification_claims_have_one_winner` (eight claimants, one
winner), `schema::tests::v84_adds_only_the_failure_notification_claim`; the
existing `a_scim_dead_letter_row_mails_every_recipient_of_a_matching_rule` now goes
through the composition's own builder.

---

## 4. P23W5-03 — the approval mail to an unproven address (T-446, proposed D-74)

**Severity: Low. Fixed in `f380891`.**

`CibaMailNotifier` mailed an account that "may take part in the grant", and
`account_may_act` admits `PendingVerification` whatever its age (deliberately —
federated accounts are pending for life). A self-registration may carry anybody's
address, and `email` is unique per tenant, so the address's real owner cannot even
hold an account there. A client that can call `bc-authorize` — registered by an
administrator or with an initial access token (D-62) — names that account and has
AXIAM mail the stranger up to three times a minute, from the tenant's own sender,
with a client name and a 64-character binding message it chose ("Call +… to keep
your account") and a genuine link. The stranger can approve nothing (the page
needs a sign-in as the account), so this is a notification-abuse and phishing
channel, not a takeover. Self-registration already lets anyone make AXIAM send one
activation mail to any address; the CIBA channel is repeatable and carries
client-written text.

**Fix — the decision (proposed D-74).** *The approval mail goes only to an address
D-25's rule vouches for — `email_verified_at` set, or the account `Active` — the
rule the SAML IdP applies to an email `NameID` and SSF to an email subject.* An
unvouched address is the same quiet no-op as an account that may not sign in: the
request is stored and answered as before (T-422) and waits on the approval page.
**Consequence for the maintainer:** a federated account stays `PendingVerification`
and has no vouched address unless one was verified, so it gets no approval mail;
CIBA deployments are normally local accounts, and D-25 accepted the same for
`NameID`s. Reverting it is one condition in `ciba_notifier.rs`.

**Test.** `ciba_notifier_test::an_address_nothing_vouches_for_is_not_mailed`
failed before the fix ("an unverified address of a pending account is not
mailed"); with `email_verified_at` set the same account is mailed.

---

## 5. P23W5-04 and -05 — who decides, and the record of it (T-447, T-431, T-435)

**P23W5-04 — Severity: Medium. Fixed in `f380891`.** The approval routes take an
`AuthenticatedUser`, and the extractor admits any `axiam:user` access token whose
session is live — reading `sid` before `jti` precisely so that OAuth2-issued
tokens work at UserInfo. A token from the code, refresh **or CIBA** grant
therefore authenticates as the user at `/api/v1/ciba/requests/{id}`; CSRF does
not apply to a bearer. The CIBA client that redeemed request 1 holds such a
token, and with request 2's record id (the id is "a handle, not a secret", D-68;
it travels in the mail and the page URL) it opened the page and approved it —
`a_token_minted_for_a_client_cannot_decide_a_request` got **200** before the fix.
The record id is what made this Medium rather than High: a client learns it from
the user's mail, a shared screen, a referrer or a log, not from AXIAM. **Fix:**
`session_evidence` treats a token carrying `client_id` as no session — `403`, on
`GET`, `approve` and `deny` — since a console sign-in's token carries none.
Contract §33 already said the page "is the console's job and is not SDK surface";
it now says this too (amended in place, 1.58 unreleased), and the OpenAPI
describes the `403` on all three routes.

**P23W5-05 — Severity: Low. Fixed in `f380891`.** T-435 was to close with each
decision audited "with the approving user and session"; the rows named the user
but not the session. The request row holds `approval_session_id` for an approval
only, and is swept ten minutes after expiry. The rows now carry `session_id`.
`both_decisions_are_audited_without_the_binding_message` failed before at "the
deciding session is recorded" (`Null`).

---

## 6. P23W5-08 — CodeQL hygiene

**Severity: Informational. Fixed in `d4ff514` and `6ac3671`.**

Every added Rust and TypeScript line was scanned by script (PEM blocks; `let`,
loop and format bindings named `secret`, `key`, `password`, `token`; credential-
named fields assigned a literal; assertion, `panic!`, `expect` and `tracing`
messages formatting a body or a credential; `assert_eq!`/`assert_ne!` over a
credential, which print both sides on failure) and the 72 hits read by eye.
Fixed: `ciba_test.rs` bound the FAPI notification-token values in a loop variable
named `token`, as literals, and formatted it into the assertion message (now made
at run time by length, the message names the length); `models/ciba.rs`
`ping_credentials_never_print` used two credential literals (run-time UUIDs);
`assert_ne!` on an `auth_req_id` in `ciba_test.rs` and `ciba.rs`, and `assert_eq!`
on a decrypted SCIM credential in three places in `scim_targets_test.rs` and two
in `scim_target_repository_test.rs` (now `assert!` with a fixed message); two loop
bindings named `token` in `scim_targets_test.rs`; a `password` binding (an `Amr`
list) in `ciba.rs`; a credential literal in `scimTargets.test.ts`. The rest are
bindings of non-secret values (`let key = ed25519_signing_key()` used only to
sign, `let token = w.admin_token()` passed to a request builder) or
`token_url` fields. No added `tracing` line formats a credential, a token, a body
or a URL: the SCIM deliverer's reasons are a fixed vocabulary
(`a_transport_reason_never_carries_the_error_text`), the ping deliverer's too
(`no_reason_carries_a_credential_or_the_endpoint`), and the CIBA service logs
client and request ids only.

---

## 7. Outbound SCIM — reviewed adversarially (G-6)

**Verdict: sound, beyond P23W5-01/-02/-07/-09.** Probes:

* **One way out.** `client::send` is the only `guarded_fetch_no_redirect` call in
  `outbound/`, with the deliverer's `allow_private`, `false` except through the
  `#[doc(hidden)]` test seam, pinned by a source scan
  (`the_outbound_modules_use_the_no_redirect_guarded_fetch_and_nothing_else`); the
  token request goes through it too. A `3xx` is a retry, never followed.
* **Credential handling.** Sealed under `pki_encryption_key`, write-only, never
  projected (`assert_no_credential` checks every member name of every response);
  opened only in `authorize`, after which the target is read again and compared by
  `updated_at` before the credential leaves (T-406's lesson) — on a cache hit too.
  The header is `set_sensitive`; the token cache is memory-only, keyed by target
  version, capped at an hour. The Basic header in `fetch_access_token` is built
  through two transient `String`s that are not zeroized; `HeaderValue` itself
  holds the bytes unzeroized either way, so this buys nothing to fix.
* **Tenant fence.** Every repository statement carries `tenant_id`; the state row's
  record id is the target id, guarded by `tenant_id` in the `WHERE`; another
  tenant's target is `404` on every route.
* **What travels.** `{resource_type, axiam_id}` only (T-415); the DLQ has the
  seven-day TTL; erasure deletes downstream through the link, which survives the
  cascade until the `DELETE` succeeds, and `erase_pending` is retried by
  reconciliation.
* **A hostile downstream.** Adoption takes exactly one resource carrying our
  `externalId`; reconciliation adopts only an id of this tenant that should not be
  there and never touches another; downstream ids are bounded, `.`/`..` refused,
  percent-encoded as path segments (`%` included); the filter is query-encoded.
  Nothing a downstream answers is written into AXIAM.
* **Two writers.** The administrator's update is conditional on the version the
  repository read (T-406); the deliverer never writes the target row; state rows
  are atomic increments (32 retries on write conflict). P23W5-09 is the
  human-versus-human case.
* **The 10 000-member bound** dead-letters a group too large to push, and no test
  pins it (carry item 6): reported with P23W5-07.

---

## 8. CIBA — reviewed adversarially (G-7)

**Verdict: sound, beyond P23W5-03/-04/-05.** Probes:

* **Client authentication** at `bc-authorize` is `TokenService::authenticate_client`,
  the token endpoint's, then D-17, the grant, and a refusal of a row edited to
  `none`; failures are the token endpoint's audit row, detached. The per-client
  bucket is counted after authentication, so a stranger cannot spend a client's
  allowance.
* **Signed requests (D-61).** A client that registered an algorithm must sign,
  under exactly that algorithm, verified against its registered keys; parameters
  come from the JWT only; `jti` is spent after verification; a client that
  registered none has `request` refused. `request_uri` is refused.
* **The hint is no oracle (D-63).** Unknown, locked and suspended users get a
  stored request with no subject and the same response; the hint is resolved after
  all validation; the notification is detached. One residual, accepted: a
  `login_hint` that is not a username costs a second lookup (by email), a timing
  difference an authenticated, rate-limited client could measure — the same
  property the login path has, and what it reveals (that a username exists) the
  `id_token_hint` path cannot.
* **The `id_token_hint`.** Deployment key, `aud` = this client, `iss` the root or
  this tenant's issuer; expiry not checked, as CIBA allows; the user lookup is
  tenant-scoped. A hint for another tenant's user finds nobody (a decoy).
* **The store.** Approve and deny are conditional on `pending`, the version, the
  user and `expires_at`; polls are a compare-and-set on `last_polled_at` that never
  moves the version; redemption is the X6 two-layer arbiter, conditional on the
  client; only after it is the subject re-read, so a refused account burns the
  approval.
* **Lockout (D-69).** `user_may_be_subject` = `account_may_act` and not
  `is_locked_out`, at request, approval and redemption.
  `ciba_client_authentication_failures_meet_the_same_lockout` and the limiter tests
  pin the Keycloak 26.7.x class.
* **Tokens (D-67).** `sid` is the approving session; AXIAM's resource endpoints
  check it on every request (`is_session_active`), so ending the session ends the
  tokens there. A refresh token only for a client holding the grant.
* **Ping (D-65).** Only the record id is queued; the deliverer re-reads the
  request (only `approved`/`denied` ping; `redeemed` is delivered without a call)
  and the client, opens the sealed endpoint credentials, reads the client again
  and sends only if it is the same version with the same endpoint, through the one
  guarded no-redirect call. The ping body carries `auth_req_id`, which cannot be
  redeemed without the client's authentication; an endpoint moved by an
  administrator between request and ping receives a token the client supplied for
  its old endpoint, which authenticates AXIAM to the client and grants nothing.
* **The page.** Binding message rendered as text, `sanitizeReturnTo` on the mail
  link, the step-up through the login hop with nothing consumed on the way back
  (T-404's lesson), `frame-ancestors 'none'` from the console's server.
* **Notification throttle.** Three per user per minute, fixed, shared across
  clients. With P23W5-03 it reaches only vouched addresses. Residual stated in
  T-424: 180 an hour; what defeats prompt fatigue is that no prompt approves.

### Threats flipped (carry item 3)

T-424, T-431, T-433 and T-435 are **Mitigated** at 2.35.0, each citing tests that
exist and pass (§13): T-424 — `a_flood_of_requests_for_one_user_sends_at_most_three_mails_a_minute`,
`a_request_for_nobody_sends_no_mail`, `a_request_for_mfa_needs_a_step_up_and_then_approves`;
T-431 — `the_routes_need_a_session_and_a_csrf_token`,
`a_token_minted_for_a_client_cannot_decide_a_request` (new), `a_decision_on_a_stale_version_is_refused`,
the page tests and the e2e spec; T-433 — `the_address_guard_refuses_an_internal_endpoint_at_delivery`,
`a_redirect_is_not_followed`, `the_clients_current_registration_decides`; T-435 —
`both_decisions_are_audited_without_the_binding_message` (amended).

---

## 9. The minimal profile (G-8) and the `boot.rs` move — reviewed (carry item 10)

**The move.** `boot.rs` was created in `d79f81e`. Its non-comment code lines were
compared as sets with `d79f81e^:main.rs`: of the 91 lines present before and absent
after (in `boot.rs`, `main.rs`, `profile.rs` or `messaging.rs`), every one is a
path rename (`axiam_server::x` → `crate::x`), a struct made `pub`, a channel
creation folded into `OutboundTransport::publisher`, or one of: the PKI encryption
key read once in `main.rs` and passed as `config.pki_encryption_key` instead of
read twice in the body; the AMQP signing key resolved under `if
config.amqp.enabled` with the same `expect`; the reactor gate's `match` gaining an
`UnavailableReactorTransport` arm reachable only with AMQP off; the decision-cache
broadcast's `match` gaining the AMQP manager and key as conditions that are always
`Some` in the full profile; the mail publisher wrapped in `MailTransportPublisher::Amqp`
with the same channel. The 190 lines new in `boot.rs` are the profile, the lease,
`ServeOptions` (whose `admit_private_networks_for_tests` defaults to `false` and
`on_lease_lost` to the production exit), the in-process arms and the listener seam.
The webhook publisher became the `OutboundPublisher` port over the same
`AmqpOutboundPublisher` and the same confirm channel; the topology pins pass. In
the full profile `serve` composes what `main` composed. Later commits to `boot.rs`
(T23.7.2, T23.8.2) are feature changes reviewed with their surfaces.

**The profile.** The in-process dispatcher calls the same deliverers through the
same outcome table (`outcome::decide`, shared and table-tested for both
transports); retries are bounded sleeping tasks (1 024), a full retry capacity is
a dead letter with a stated reason; enqueue from inside a delivery (`converge_groups_of`)
is `try_send`, so it cannot deadlock the consumer. Boot refuses the broadcast, any
enabled reactor and a live lease; a lost lease stops in order (D-72). T-445 records
the trade. A SCIM dead letter caused by in-process retry capacity is not counted on
the target's `state` (the deliverer never sees it); it is audited and, with
P23W5-02, notified — minor, noted in §15.

---

## 10. Verdicts on the orchestrator's carry list

1. **T-409 — fixed** (P23W5-01): `base_url` bound for client-credentials targets,
   repository rule, handler `400`, contract §31.3 rule 2 amended, the test inverted
   and failing first; T-409 Mitigated.
2. **T-418 — fixed** (P23W5-02) with a window: one notification per target per
   hour, claimed in the datastore; proposed D-73. **T-117 corrected** — and,
   corrected, it is not mitigated: reopened (P23W5-13).
3. **T-424, T-431, T-433, T-435 — flipped to Mitigated** (§8), T-431 after
   P23W5-04 and T-435 after P23W5-05.
4. **`account_may_act` does not read `locked_until` — accepted, not a defect,
   pre-existing (P23W1) and unchanged by W5.** A refresh token, or a code issued
   before the lockout, or an OP-cookie session at `/oauth2/authorize`, still yields
   tokens for a user under brute-force lockout. Lockout is a gate on *new*
   password authentication against guessing; it is triggered by the attacker's
   failures, not the user's, so making it revoke existing grants would hand every
   attacker who knows a username a way to sign the user out everywhere — T-35's
   "lockout weaponised to deny service". The credentials that survive it were
   earned by an authentication that happened before it. CIBA checks lockout
   because a CIBA approval is a new authentication event the lockout must cover
   (T-429); it also checks it at redemption, where the consequence — a locked user's
   approved request is spent — is the stricter choice D-69 made. No issue body.
5. **CIBA mail to unverified addresses — fixed** (P23W5-03; proposed D-74), with
   the federated-account consequence stated.
6. **SCIM residuals.** The 10 000-member dead letter untested and the sequential
   consumer — **reported** together (P23W5-07); the tarpit case makes the second
   Medium. The admin `PUT` without a client version — **reported** (P23W5-09, Low):
   the credential binding already stops the dangerous case (a stale form cannot
   move the URL back without the credential), the rest is a lost edit.
7. **The webhook deliverer's `guarded_fetch` — reported, Informational**
   (P23W5-10). No credential is carried: the request has no `Authorization` header
   and the HMAC signature covers one timestamped body, which the redirect target
   already receives. Every hop is SSRF-checked. No issue exists; one is drafted.
8. **`fapi-conformance.yml` — reported** (P23W5-11), with the script injection of
   `inputs.axiam_image` folded in.
9. **"Five trust boundaries" — fixed** (P23W5-12).
10. **The `boot.rs` move — confirmed** (§9).
11. **T-108 — kept Open** with T23.8.2's A10 issue body. A counter, an operator
    signal and a dead-letter sink for request rows need decisions (where the
    counter surfaces, whether `/health` changes shape, which sink) that are not
    small or safe inside this wave.
12. **T23.8.2's other issue bodies** — A4, A6, A7, A8, A11, A12 — are referenced in
    §14, not rewritten.

### W4 §15 — was it honoured?

* **The dispatcher.** One `spawn_outbound_consumer` for every kind, guarded by a
  source test; the webhook topology byte for byte; `scim_push` and `ciba_ping` DLQs
  with the seven-day TTL; the in-process path keeps the deliverer's contract and
  the audit vocabulary. **Honoured.**
* **Read-modify-write.** SCIM targets and CIBA requests are written conditionally
  on the version read; SCIM state is atomic; the deliverers re-read before a
  credential leaves. **Honoured** (P23W5-09 is the client-version half).
* **SSRF.** Every credential-bearing outbound request of the wave — SCIM calls, the
  SCIM token request, the CIBA ping — goes through `guarded_fetch_no_redirect`
  with `allow_private = false`. **Honoured.** The SCIM credential was D-49's shape,
  but did not stay bound to the endpoint that receives what it yields (P23W5-01).
* **Marker-driven state.** CIBA consumption is bound to the client and the
  `auth_req_id` holder; the step-up return leg consumes nothing. **Honoured.**
* **Erasure.** Only references and record ids queue; a SCIM erasure survives as an
  id-only link until the downstream `DELETE`; CIBA rows are swept. **Honoured.**
* **Logging once per request.** The deliverers log fixed reasons once per attempt;
  no loop logs per iteration. **Honoured.**
* **Tenant-distinct identifiers.** CIBA `iss`/`aud` checks are per tenant issuer;
  a SCIM access token is the downstream's, minted per target. **Honoured.**
* **Threat ids from T-407.** T-407 … T-445 (W5), T-446, T-447 (this review).
  **Honoured**, except `threatTop` (P23W5-14).

---

## 11. Rate limits, CSRF, CSP, console

* **Rate limits.** Every new inbound route has a bucket of its own: the four SCIM
  writes (`scim_target_create`, `_update`, `_delete`, `_reconcile`, 30 a minute,
  never preset), `bc-authorize` (`bc_authorize_per_min`, in the machine presets,
  plus a per-client bucket after authentication), the three approval routes
  (`ciba_approval_get`, `_approve`, `_deny`, 30, never preset), and the CIBA grant
  counts against `token_per_min`. Reads of the SCIM registry are unlimited, as for
  every administrator read. Each limiter is pinned by a test that counts it
  (`scim_targets_test::every_write_route_has_its_own_bucket_and_reads_are_not_limited`,
  `ciba_test::the_limiter_counts_bc_authorize`,
  `ciba_approval_test::each_route_has_a_rate_limit_bucket_of_its_own`).
* **CSRF.** The SCIM writes and both CIBA decisions go through `/api/v1`'s
  double-submit middleware; `bc-authorize` is client-authenticated and reads no
  cookie. P23W5-04 closed the bearer-token path CSRF never covered.
* **CSP.** Unchanged: no new HTML-serving handler; the console's own policy
  (`frame-ancestors 'none'`) frames the approval page.
* **Console.** *SCIM targets* is gated on `scim_targets:read`/`:write`, never shows
  a credential, asks for it when a URL or the kind changes; the CIBA page renders
  server text and the binding message as React text (no `dangerouslySetInnerHTML`
  in either page).

---

## 12. Threat-model reconciliation

Model **2.35.0** (from 2.34.0), in all three artifacts and the website, in
`9e52b1f`; `node website/scripts/gen-threat-model.mjs` → *447 threats (426
mitigated, 21 open)*, no diff left.

| Change | Entry |
|---|---|
| Client-credentials secret bound to `base_url` | **T-409** Mitigated (P23W5-01) |
| One failure notification per target per hour | **T-418** Mitigated (P23W5-02, D-73) |
| CIBA controls verified | **T-424**, **T-433** Mitigated; **T-431** Mitigated (with P23W5-04); **T-435** Mitigated (with P23W5-05) |
| Approval mail only to a vouched address | **T-446** added (sign-in request notification, I, Medium, Mitigated) |
| A client-minted token approves a pending grant | **T-447** added ( `/oauth2/authorize (+ consent)`, E, Medium, **Open** — device grant) |
| Batched notifications never existed | **T-117** reopened (P23W5-13) |
| Tarpit downstream quantified | **T-414** amended (P23W5-07) |
| `threatTop` | 443 → 447 (P23W5-14) |

Counts: STRIDE *Information disclosure* 105 (6 open), *Elevation of privilege* 86
(3 open); severity *Medium* 185 (9 open), *High* 187 (9 open), *Low* 34 (1 open);
diagram *OAuth2 / OIDC* 85 threats / 1 open, *Audit, webhooks, email &
notifications* 55 / 5. Open register 21. §9 of the STRIDE document records this
review as its example of a review raising findings with no threat.

---

## 13. Checks run

All exit codes captured from cargo itself (a log per step plus `$?`, through a
wrapper), test binaries deleted between steps for the disk.

```bash
export CARGO_INCREMENTAL=0
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
# before each fix — each new or amended test failed:
cargo test -p axiam-db --test scim_target_repository_test -- a_client_credentials_base_url   # 1 failed (P23W5-01)
cargo test -p axiam-server --test scim_dead_letter_notification_test                          # 1 failed: 100 mails, not 2 (P23W5-02, gate forced open)
cargo test -p axiam-oauth2 --test ciba_notifier_test                                          # 1 failed (P23W5-03)
cargo test -p axiam-api-rest --test ciba_approval_test -- a_token_minted_for_a_client both_decisions_are_audited
                                                                                              # 2 failed: 200 not 403 (P23W5-04); session Null (P23W5-05)
# after:
cargo test -p axiam-db --test scim_target_repository_test                                    # 32 passed
cargo test -p axiam-db --lib schema                                                           # 64 passed
cargo test -p axiam-core --lib                                                                # 493 passed
cargo test -p axiam-oauth2 --test ciba_notifier_test                                          # 8 passed
cargo test -p axiam-oauth2 --lib ciba                                                         # 35 passed
cargo test -p axiam-audit                                                                     # 14 + 31 passed
cargo test -p axiam-api-rest --test ciba_approval_test                                        # 16 passed
cargo test -p axiam-api-rest --test ciba_test                                                 # 21 passed
cargo test -p axiam-api-rest --test scim_targets_test                                         # 24 passed
cargo test -p axiam-server --test scim_dead_letter_notification_test                          # 2 passed
(cd frontend && npx vitest run src/services/scimTargets.test.ts src/pages/scim-targets)       # 24 passed
node website/scripts/gen-threat-model.mjs                                                     # 447 threats (426 / 21)
```

The remaining checks — fmt, clippy on both toolchains and both feature sets, the
`axiam-api-rest` suite in batches, the spec and registry, and the repository
scripts — are recorded in the addendum at the end of this file with their
results.

---

## 14. Issue bodies for the reported findings (not filed)

T23.8.2's issue bodies are in
[`audit-durability-review-minimal-profile-2026-10-05.md`](audit-durability-review-minimal-profile-2026-10-05.md)
§8 and are not repeated here: **A4** (the in-process dispatcher's lost deliveries
leave no terminal row, Low), **A6** (CONTRACT §8 on a minimal-profile server, Low),
**A7** (the GDPR audit dead-letter file is configured nowhere, Medium), **A8**
(GDPR request audits are fire-and-forget, Medium), **A10** (request-audit loss is
silent — T-108, Medium), **A11** (the gRPC listener has no orderly stop, Low),
**A12** (the full profile's abrupt exits, Medium).

### P23W5-06 (Medium) — a relying party's access token approves a device authorization in its user's name

`POST /api/v1/device/decide` (and `GET /api/v1/device/verify`) take an
`AuthenticatedUser`, which admits any live `axiam:user` access token — a console
sign-in's, and equally one AXIAM minted for any OAuth2 client of the tenant
through the code, refresh or CIBA grant (the extractor reads `sid` so that such
tokens work at UserInfo). CSRF does not apply to a bearer token. A relying party
that holds a user's access token — even one granted only `openid` — starts a
device authorization for a device client it controls, so it knows the
`user_code`, and approves it with the user's token: the device client then
redeems tokens for that user with its own registered scopes and a refresh token,
without the user ever seeing a consent page. Present since B2. The W5 F4 review
closed the same hole on the CIBA approval routes (`f380891`,
`session_evidence` refuses a token carrying `client_id`). **Proposed fix:** the
same rule on `/api/v1/device/verify` and `/decide` — a token with a `client_id`
claim is `403` — with a test that redeems a code-grant token and fails to
approve a device flow with it; contract and OpenAPI note the `403`. Consider
whether other `/api/v1` routes that act *as* the person (consent, credential
changes) want the same rule; scope is a separate decision. Threat: T-447.

### P23W5-07 (Medium) — a tarpit SCIM downstream stalls every tenant's provisioning on a replica

Each replica runs one `scim_push` consumer with one delivery in flight, for every
tenant (the in-process dispatcher too). An attempt waits up to 10 s per request
(`REQUEST_TIMEOUT`), 20 s with a client-credentials token request. A tenant
administrator registers a target whose host accepts connections and never
answers; enabling it starts a reconciliation that queues every user and group in
scope; at 10 000 references that is more than a day of attempts, each retried on
the backoff schedule up to `AXIAM__SCIM_PUSH__MAX_ATTEMPTS` — during which every
other tenant's SCIM pushes on that replica wait. Webhooks, SSF and sign-ins are
unaffected (separate kinds). Also uncovered: no test pins the 10 000-member group
dead letter (`MAX_GROUP_MEMBERS`). **Proposed fix (a decision):** a per-target
breaker in the deliverer — when `consecutive_failures` is at or above a threshold
(say 5) and `last_failure_at` is within the current backoff, return `Retry`
("target is failing; backing off") without a network call — and/or a per-target
concurrency budget with more than one delivery in flight per consumer. Tests: a
loopback server that never answers, ten references for it and one for a healthy
target, the healthy delivery completing within one timeout; a group repository
reporting 10 001 members dead-letters with the fixed reason. Threat: T-414.

### P23W5-09 (Low) — the SCIM target `PUT` is last-writer-wins between administrators

`PUT /api/v1/scim-targets/{id}` is conditional on the `updated_at` the server
reads during the request (contract §31.3 rule 4), not on one the client read. Two
administrators who opened the edit form at the same version both save; the
second silently overwrites the first's scope, mapping or deprovision policy. The
credential binding still refuses a stale form that would move a URL back without
the credential, so this is a lost edit, not a disclosure. **Proposed fix:** an
optional `expected_updated_at` (or `If-Match` with the `updated_at`) in
`ScimTargetInput`, passed to `ScimTargetUpdate::expected_updated_at` — which the
repository already honours — and sent by the console from the target it loaded;
`409` as today. Contract §31 and the SDKs gain the field (additive). Test: two
`PUT`s carrying the same version, the second `409`.

### P23W5-10 (Informational) — the webhook deliverer follows redirects

`WebhookDelivery` sends through `axiam_federation::ssrf::guarded_fetch`, which
follows up to its redirect limit, re-validating every hop and re-sending the same
request — `X-Axiam-Signature` (HMAC-SHA256 over the timestamp and body), the
timestamp, event and delivery headers, and the body — to the `Location`. No
credential travels: there is no `Authorization` header and the signature
authenticates exactly the body the redirect target receives anyway. But the
receiver's operator can forward deliveries (personal data in event bodies) to a
host the tenant administrator never registered, and the rule W4 §15 set for the
wave's new kinds ("never `guarded_fetch`") does not hold for the oldest one.
**Proposed fix:** `guarded_fetch_no_redirect` with a `3xx` classified as a retry,
as SSF, SCIM and CIBA ping do; a CHANGELOG note, since a receiver behind a
redirect today stops receiving. Test: a loopback receiver answering `307`, never
followed, retried.

### P23W5-11 (Informational) — `fapi-conformance.yml`: the gate is red by design, and an input reaches a script

The workflow drives no browser, so interactive modules end `WAITING` (or are
recorded not finished) on every unattended run, and the final step fails the job
whenever `steps.run.outcome != 'success'` — every run is red, so the gate
signals nothing (D-60 counts the baseline green by comparing non-interactive
modules with the 2026-09-25 baseline, which the gate does not do). Separately,
"Render the report" interpolates `${{ inputs.axiam_image }}` directly into the
`run:` script (`if [ -n "${{ inputs.axiam_image }}" ]`), a template injection for
anyone who may dispatch the workflow (write access, so low impact); the "Select
the AXIAM image" step already passes it through `env:`. **Proposed fix:** have
`conformance-run`/the reporter emit a machine-readable summary and gate on "no
non-interactive module `FAILED` and none below its baseline", tolerating
`WAITING`/`SKIPPED` in smoke runs; or add a headless browser driver for the
interactive modules — in which case the 30 s per-module timeout is too short for
the 60/62 s modules and `timeout-minutes` must grow. Pass `inputs.axiam_image`
through `env:` in the report step. Secrets handling otherwise holds: the
per-run administrator password is masked and travels through `GITHUB_ENV`; the
client keys and certificates are generated per run; the artifacts carry reports,
raw results and, on failure, debug-level server and rig logs of a throwaway
deployment.

### P23W5-13 (Medium) — notification rules mail once per event; T-117's batching does not exist

T-117 ("alert flooding buries a real incident") was Mitigated by "notifications
are delivered in configurable batches through the mail queue". Nothing batches
them: `NotificationDispatcher::dispatch` enqueues one mail per matched recipient
per audit row. A rule for an event an attacker can produce in volume — failed
sign-ins (`LoginFailure`), spread over addresses and accounts so that per-address
and per-account limits do not stop it — mails each recipient once per event. The
W5 F4 review bounded the one background event, `scim_delivery_failed`, to one
notification per target per hour (D-73) with a `NotificationGate` on
`NotifyingAuditLog`; the request path (the audit middleware's sink) has no gate.
**Proposed fix:** a per-(tenant, rule, event) window — the first event mails, the
rest within N minutes are counted, and the next mail says how many were
suppressed — claimed in the datastore like D-73, configurable per rule with a safe
default; or a digest mail per window. Tests: a burst of a hundred `LoginFailure`
rows mails each recipient once, and the next window's mail carries the count.
Threat: T-117 (reopened at 2.35.0).

---

## 15. What W6 must take from this review

W6 (plan §5) is G-10 (benchmark run 6 with four targets), G-11 (the RADIUS spike)
and the comparison refresh. From this review:

* **G-10.** The minimal profile is a benchmark configuration now; measure it as
  T23.8.3 documents it (single instance, the lease held), and say in the report
  that its outbound deliveries are lost on restart (T-445) so that no reader
  mistakes its footprint for the full profile's. Do not benchmark with the
  approval or SCIM routes' limits raised without saying so — both are never
  preset. A benchmark that enables a SCIM target on a dead host will reproduce
  P23W5-07: keep targets disabled, or point them at a loopback server that
  answers.
* **G-11 (RADIUS spike).** A RADIUS server is a new authentication path and a new
  trust boundary (NAS ↔ AXIAM). Carry the lessons this wave paid for: the
  brute-force lockout and the limiters must cover it from the first commit (the
  Keycloak 26.7.x class, T-429); an unknown user must not be an oracle (D-63's
  decoy); the shared secret per NAS is a credential sealed under
  `pki_encryption_key`, write-only and bound to the NAS address it was registered
  for (P23W5-01's lesson: bind a credential to every endpoint that receives what
  it yields); Message-Authenticator required, MD5-only attributes treated as the
  weakness they are (RFC 9765's Blast-RADIUS guidance). A spike writes these into
  its threat entries even if it ships nothing.
* **The comparison refresh.** CIBA and outbound SCIM are claims now: state what
  AXIAM does *not* do (push mode; a user code; federated accounts get no approval
  mail under D-74; SCIM provisioning is one attempt at a time per replica until
  P23W5-07 is decided).
* **SDK fan-outs (D-35).** §31 (1.57): the credential binding now includes
  `base_url` of a client-credentials target — every SDK documents it at both call
  sites. §33 (1.58): the approval page is not SDK surface, and a client-minted
  token is `403` there; an SDK must not offer an "approve" helper. Both
  amendments are in place, so the fan-out issues cite the amended text.
* **Decisions for the maintainer.** D-73 and D-74 (§3, §4; proposed rows in the wave report); P23W5-06's
  device-grant fix and P23W5-07's breaker are the two reported items most worth
  scheduling before 1.0.
* **Notifications.** Any new notification event raised by a background process
  goes through a `NotificationGate` — `NotifyingAuditLog` has no constructor
  without one — and a request-path event waits on P23W5-13.
* **Approval surfaces.** Any route where a person approves a grant takes a console
  sign-in only (no `client_id` claim), CSRF on cookies, the version read, and
  audits the deciding session.
* **New threat ids** start at **T-448** (`threatTop` is 447).

## 16. Invariants

I1 (nothing registered today changes behaviour) holds with these deliberate,
CHANGELOG-recorded changes, all to surfaces new in this unreleased wave: an update
that moves `base_url` of a client-credentials SCIM target without the credential
is `400` (`d4ff514`; contract 1.57 §31.3 rule 2 amended in place); a target's
dead letters reach the notification rules at most once an hour, and schema **v84**
adds `scim_target_state.failure_notified_at` (`d4ff514`); the CIBA approval
routes answer `403` to an access token minted for an OAuth2 client (`f380891`;
contract 1.58 §33 amended in place; OpenAPI describes the `403`); the CIBA
approval mail goes only to a vouched address, so a federated account in
`PendingVerification` is no longer mailed (`f380891`); the CIBA decision audit
rows gain `session_id` (`f380891`). No SDK-visible field changed shape.
