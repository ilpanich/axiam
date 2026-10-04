# Security review — Phase 23, wave W4 (F4)

**Date:** 2026-10-04.
**Against:** `claude/phase23-w4`, the whole wave diff `c447dfd..f0189f5` (59
commits, 158 files, about 56 400 lines added; `c447dfd` is the W3 merge on
`main`). The fixes and pins of this review sit on top: `8c3db3f` (P23W4-01), `8693925`
(P23W4-02), `06d19fc` (P23W4-03), `96a2c6b` (P23W4-04), `a3ad895` (P23W4-05), `050ab54` (pins),
`72a3d57` (the spec regenerated), and the documentation commit that carries this
file.
**Scope:** the W4 tasks of
[`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md):
G-2's last six — T23.2.8 (contract §29, D-37 … D-42), T23.2.5 (the §29 routes,
IdP metadata, SP metadata import, promote, D-34, D-43), T23.2.4 (single logout,
schema v76), T23.2.6 (the console page), T23.2.9 (documentation) and T23.2.7
(the samael and Keycloak end-to-end tests, D-54) — and all of G-5 — T23.5.1 (the
shared outbound dispatcher, D-36), T23.5.2 (SET issuance, streams, the receiver
API, discovery, schema v77, D-44 … D-51), T23.5.3 (push and poll delivery, the
outbox, the event sources, the step-up record, schema v78, D-52, D-53,
`guarded_fetch_no_redirect`) and T23.5.4 (website, T-402 … T-405).
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) (model
2.29.0: T-357 … T-405 are this wave's) and `ThreatDragonModels/Axiam/Axiam.json`,
and the OWASP ASVS 5.0 areas the diff touches (V1 encoding and injection, V2
validation and business logic — concurrency, V3 web frontend, V4 API, V6
authentication, V7 session management, V8 authorization, V10 OAuth/OIDC and
SAML federation, V11 cryptography, V12 secure communication — SSRF, V13
configuration, V14 data protection, V16 logging). D-34 … D-54 were read
verbatim and are binding; every route the diff mounts was traced to its handler
and its limiter.
Every finding fixed here has a test that failed before the fix; a claim with no
test says so.

---

## 0. Summary

Five findings were fixed on the branch, all wave-introduced or siblings the
wave's own changes missed. The one that matters is **P23W4-01** (Low): every SSF
stream write was read-modify-write, so a receiver's write that overlapped an
administrator's put back the status, allowance, receiver binding or subject
format the administrator had just changed — a `disabled` that D-51 says only an
administrator may lift included — and the push deliverer could send a header
supplied for a new endpoint to the old one, against D-49. Writes are now
conditional on the version they were read at (new **T-406**). **P23W4-02** (Low)
closes T-404's residual: the step-up record is consumed only after the
authorization service accepted the request, and never by a return leg in the
session that was asked to step up. **P23W4-03** turns an unsignable held event's
`ERROR` line from one per half-second look into one per poll, and removes a
`Duration` underflow on the long-poll path. P23W4-04 is CodeQL hygiene (two key
literals, a TOTP secret in an assertion message, stale test descriptions);
P23W4-05 bounds `AcsEndpoint.index` in the published schema. One decision goes
to the maintainer: audience squatting is not harmless where SETs share one
issuer (P23W4-11, Low; T-390's residual corrected, receiver guidance on the
website).

**D-38's single logout holds.** Every SP message is verified against its
registered certificate, per node on the POST binding (the receiver's placement
rule, SHA-1 refused) and over the exact octets on the Redirect binding;
`verify_signed_xml` is called nowhere in production code (§7). The SP registry,
the credential routes, metadata import and D-54's tree normalisation held; SET
issuance held against token confusion at every verifier AXIAM runs, now pinned
(§8). The shared dispatcher kept the webhook topology byte for byte, and
`guarded_fetch_no_redirect` is `guarded_fetch`'s first hop exactly (§9).

| ID | Finding | Severity | Surface / threat | Disposition |
|---|---|---|---|---|
| **P23W4-01** | SSF stream writes were read-modify-write: a receiver's `PATCH`/`PUT`/status write overlapping an administrator's change put the old status, allowance, binding and subject format back (undoing a `disabled`); the deliverer read the endpoint and the header in two reads, so a header supplied for a new endpoint could reach the old one. | Low | §32 receiver API, §32 admin `PUT`, push deliverer; D-49, D-51 → **T-406** | **Fixed** — `8c3db3f` (T-406 added) |
| **P23W4-02** | The step-up record was consumed on the return-leg marker alone, before the client and `redirect_uri` were validated, and by a return leg in the very session that was asked to step up: any page could spend it and suppress the user's `assurance-level-change`. | Low | `/oauth2/authorize`; T-404 | **Fixed** — `8693925` (T-404's residual closed) |
| **P23W4-03** | A held event the deployment key cannot sign was logged at `ERROR` on every half-second look of a long poll — about sixty lines per waiting receiver per half minute; `POLL_LONG_POLL_MAX - started.elapsed()` could underflow and panic. | Informational | `/ssf/v1/poll/{id}`; T-403, T-405 | **Fixed** — `06d19fc` |
| **P23W4-04** | CodeQL hygiene: an Ed25519 private key literal in `saml_idp_slo_test.rs` (and its W3 sibling in `saml_idp_sso_test.rs`), a TOTP enrolment body (`secret_base32`) formatted into an assertion message, `secret`/`key`-named bindings flowing into assertions; two stale delivery-test descriptions. | Informational | tests | **Fixed** — `96a2c6b` |
| **P23W4-05** | OpenAPI typed `AcsEndpoint.index` as `int32` with no maximum while the model and contract §29.2 say `u16`. | Informational | §29 schema | **Fixed** — `a3ad895`, spec `72a3d57` |
| **P23W4-06** | Five older cleanup jobs (`sso_handoff_code`, `revocation_feed`, `dcr_unused_clients`, `cimd_unused_clients`, `dcr_registration_tokens`) record into `/health/jobs` but are not registered at start, so one that never runs is never reported stalled (found by T23.2.4). | Low | `/health/jobs`; T-129 | **Reported** (ilpanich/axiam#535) (pre-existing) |
| **P23W4-07** | The console has no control for `saml_idp_enabled` or `ssf_enabled` and no SSF stream page: an administrator cannot see from the console which third parties receive security events about the tenant's users, nor switch either surface off there. | Informational | console; §29, §32 | **Reported** (ilpanich/axiam#536) (gap; the settings API and `get_idp` cover it) |
| **P23W4-08** | The server's consumer supervisor loop is copied per outbound kind (webhook, `ssf_push`); G-6 would add a third copy. | Informational | `axiam-server` `main.rs`; D-36 | **Reported** (ilpanich/axiam#537) (maintainability) |
| **P23W4-09** | Untested: a Keycloak-initiated logout towards AXIAM, and AXIAM's front-channel SLO towards a real SP's `SingleLogoutService`. All SLO tests use a synthetic SP or samael. | Informational | SLO; T-370 … T-380 | **Reported** (ilpanich/axiam#538) (coverage) |
| **P23W4-10** | SSF residuals: an erased subject can stay in the buffer or the push DLQ up to seven days (T-402); a receiver token outlives its OAuth2 client's deletion by up to 15 minutes; the primary and retry `ssf_push` queues have no TTL. | Low | SSF; T-402, T-385 | **Accepted** (§10) |
| **P23W4-11** | Audience squatting is not harmless everywhere D-47 says it is: without per-tenant issuers every tenant's SETs share `iss` and the key, so a receiver that adopts a conventional audience before its stream exists and accepts unauthenticated pushes would accept SETs a squatting tenant pushes, about subjects it chooses (an email subject included). | Low | SSF; T-390, D-45, D-47 | **Reported** (ilpanich/axiam#539) — T-390's residual corrected, receiver guidance on the website; whether SSF should require per-tenant issuers is the maintainer's decision |

**Verdict on merge.** Nothing open blocks W4. The five fixes are in and pinned,
the threat model is at **2.30.0 — 406 threats, 389 mitigated / 17 open** — and
the three artifacts and the website agree. P23W4-06 … -09 and -11 should be filed
before the phase's PR merges (§14); P23W4-11 needs a maintainer decision first. The OpenAPI spec is regenerated (`72a3d57`: the SSF
`409`s and `AcsEndpoint.index`'s maximum).

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| SLO: receiving, verification, replay, revocation, chain, cookies, IdP-initiated trigger | T23.2.4 | `handlers/saml_idp_slo.rs`, `saml_idp/logout.rs`, `saml_idp/request.rs` (diff), `db/…/saml_logout_run.rs`, `saml_sp_session.rs`, schema v76 | **read in full** |
| SP registry and credential routes, IdP metadata, metadata import, D-54 | T23.2.5, T23.2.7 | `handlers/saml_admin.rs`, `saml_idp/{sp_metadata,idp_metadata}.rs`, `db/…/saml_idp_credential.rs` (promote), `saml_service_provider.rs`, `saml_sp.rs` validator | targeted: tenant fence, human-only, D-42 refusals, promote, parse/normalise, fetch |
| SET issuance, subject policy, receiver update rules, discovery | T23.5.2 | `axiam-oauth2/src/ssf.rs` | **read in full** (production half) |
| Receiver API, poll, admin registry | T23.5.2, T23.5.3 | `handlers/ssf.rs`, `handlers/ssf_admin.rs`, `state/bundles.rs` | **read in full** |
| Push deliverer, outbox, no-redirect fetch, dispatcher | T23.5.1, T23.5.3 | `ssf_delivery.rs`, `axiam-pki/src/ssrf.rs` (diff), `axiam-amqp/src/outbound/*` (consumer, topology), `webhook_consumer.rs` | **read in full** (deliverer, fetch); targeted (amqp) |
| Event sources | T23.5.3 | `ssf_emitter.rs`, `db/…/session.rs` (diff), `handlers/oauth2.rs` (step-up), `scim/users.rs` (diff), `db/…/ssf_step_up.rs` | **read in full** (emitter, step-up); targeted (call sites) |
| Cascades, erasure, sweeps | T23.2.4, T23.5.2/3 | `db/…/tenant.rs`, `user.rs` (diff), `cleanup.rs`, `job_health.rs` | **read in full** (diff) |
| Every verifier over the deployment key | — | `axiam-auth/src/token.rs`, `service.rs`, `webauthn.rs`, `axiam-oauth2/src/{logout,token,token_exchange}.rs` | targeted: required claims, `typ` |
| Rate limits, request log, CSRF, CSP | all | `server.rs` (diff), `config/rate_limit.rs`, `middleware/{request_span,csrf}.rs` | **read in full** (diff) |
| Console | T23.2.6 | `frontend/src/pages/saml/*`, `services/saml.ts`, router, nav | targeted: gating, rendering, secrets |
| Logging and test hygiene (CodeQL) | all | every added `tracing::` line, assertion and panic message, format argument, binding and literal in Rust and TypeScript | **every added line**, by script and by eye |

Tests ran against the in-memory SurrealDB harness and the loopback receivers of
the test suites (§13). The Keycloak round trip is `#[ignore]`d and was not run
here (it needs a Keycloak, which T23.2.7 took from Maven Central because
`quay.io` is blocked; T23.2.7 ran it twice).

---

## 2. P23W4-01 — overlapping stream writes undid each other (T-406)

**Severity: Low. Fixed in `8c3db3f`; T-406 added.**

Every write of an SSF stream read the stream, decided, and wrote the **whole**
configuration back: `apply_receiver_update` and `update_stream_status` start from
`SsfStreamUpdate::from_stream(&stream)`, and the administrator's `update_stream`
builds a full `SsfStreamUpdate` from its input after checking it against `old`.
`SsfStreamRepository::update` then wrote every column unconditionally. Two writes
that overlap lose one. The case that matters: a receiver's `PATCH` (or status
`POST`) reads the stream while it is `enabled`; an administrator disables it,
narrows `events_allowed`, re-binds `receiver_client_id` or switches
`subject_format` from `email` to `iss_sub`; the receiver's write lands and puts
all of it back. The administrator's response and audit row say `disabled`; the
stream is `enabled` and events flow to a third party the administrator cut off
— the one thing D-51 says a receiver cannot do. The window is the gap between a
read and a write (milliseconds), which a receiver widens by writing at its
rate limit (60 a minute per route). The deliverer had the same shape across two
reads: `streams.get` for the endpoint, then `decrypt_authorization_header`. A
header supplied together with a new endpoint in between was opened and sent to
the old endpoint, against D-49's "a credential never follows the endpoint to
another origin".

**Fix.** `SsfStreamUpdate` carries `expected_updated_at`, which `from_stream`
sets and the administrator's handler sets from the stream it checked; the
repository writes `… WHERE tenant_id = $tenant_id AND updated_at =
$expected_updated_at RETURN VALUE meta::id(id)` and, when nothing was written
but the stream exists, answers `Conflict`. The receiver's three writes decide
again from a fresh read when overtaken — so the D-51 check always judges the
status the write would replace, and an administrator's `disabled` turns the
retry into the `403` it should be — and answer `409` only if the stream kept
changing over three attempts. The administrator's `PUT` answers `409`; the
console reloads. The deliverer reads the stream again after opening the header
and pushes only if it is still the version it signed against and whose endpoint
it holds; otherwise the attempt is a retry on the D-36 schedule. Contract 1.56
(unreleased) amended in place: §32.3 rule 4 and §32.6.

**Tests.** `ssf_stream_repository_test::a_write_prepared_from_an_overtaken_read_does_not_land`
failed before the fix at "a write from an overtaken read is refused as a
conflict" (the late write landed and re-enabled the stream);
`ssf_delivery_test::a_credential_supplied_for_a_new_endpoint_never_reaches_the_old_one`
(a repository wrapper moves the endpoint between the deliverer's two reads)
failed before the fix at "the new endpoint's credential reached the old
endpoint". Residual (T-406): the deliverer's second read and the send are two
steps, so an endpoint moved after that read is used once with the header that
was stored *for it*; header and endpoint still belong together. Why Low and not
Medium: the race needs an administrator write inside a receiver's
read-to-write gap, the receiver regains only what it was already receiving, and
the administrator's next read shows it.

---

## 3. P23W4-02 — the step-up record could be spent by any page (T-404)

**Severity: Low. Fixed in `8693925`; T-404's residual closed.**

T23.5.3 consumed the `ssf_step_up` row as soon as `/oauth2/authorize` saw the
return-leg marker (`axiam_login_hop=1`), right after resolving the session and
before the authorization service validated the client, the `redirect_uri` or
anything else, and in whatever session the request carried. The marker is a
query parameter, so a third-party page that navigated the user's browser to
`/oauth2/authorize?axiam_login_hop=1` while the user was mid-step-up (the OP
cookie is `SameSite=Lax`, sent on a top-level navigation) consumed the row with
the session that started the step-up: nothing was emitted, and the real return
leg found no row — the user's `assurance-level-change` was suppressed. It could
not forge one (an emission needs a new session of the same user at another
level). The carry list asked whether to move the call after client validation;
moving it alone would not have been enough, because the attacker can name a
real public client and its registered `redirect_uri`.

**Fix.** Two rules, both needed. The row is consumed only once
`authorize_service.authorize` has accepted the request (any `Ok` outcome); and
`SsfStepUpRepository::take` takes the requesting session and deletes only
`WHERE previous_session_id != $current_session_id`, so a return leg made in the
session that was asked to step up — which stepped nothing up — leaves the row
for the real one. A forged return leg after the user holds the new session is,
by construction, a valid authorization request in that session: the event it
emits is the true one.

**Tests.** `ssf_test::a_return_leg_the_authorization_endpoint_refuses_spends_nothing`
(no client, an unknown client, a `redirect_uri` the client never registered —
then the real return leg emits) and the amended
`ssf_test::the_same_session_returning_emits_nothing` (the row is left) failed
before the fix; `ssf_step_up_test::a_take_in_the_asking_session_leaves_the_record`
pins the repository rule.

---

## 4. P23W4-03 — one `ERROR` per look of a long poll

**Severity: Informational. Fixed in `06d19fc`.**

When the deployment key cannot sign a held event (`SsfError::Signing`), the poll
handler keeps the event and, on a long poll, looks at the buffer again every
500 ms for up to 30 s — logging `a held SSF event could not be signed` at
`ERROR` on every look: about sixty lines per waiting receiver per half minute,
sustained for as long as the receiver keeps polling. The precondition is an
operator fault (an unusable key breaks token issuance too), so this is log
hygiene rather than a vulnerability, but an `ERROR` flood is how a real alert
gets lost. The same loop computed `POLL_LONG_POLL_MAX - started.elapsed()` after
the 30-second check; `Duration` subtraction panics on underflow, so a request
crossing the cap between the two reads of the clock would have panicked the
handler.

**Fix.** The line is written once per request; the sleep uses
`saturating_sub`. **Test.**
`ssf_test::an_unsignable_held_event_is_logged_once_per_poll_and_an_abandoned_poll_frees_its_slot`
(a capturing subscriber, a state whose signing key is unusable, a long poll
abandoned after 1.7 s) failed before the fix with four lines; it also pins that
an abandoned long poll gives its wait slot back (D-53 (11), carry item 6). The
underflow has no test (a timing race); the fix is the standard library's
saturating form.

---

## 5. P23W4-04 — CodeQL hygiene

**Severity: Informational. Fixed in `96a2c6b`.**

Every added line of the wave in Rust and TypeScript was scanned by script (PEM
blocks; byte arrays of key length; `let`/loop/format bindings named `secret`,
`key`, `password`, `token`; assertion, `panic!`, `expect` and `tracing` messages
formatting a body, a header, a token, a SET or a key) and the hits read by eye.
Fixed: the Ed25519 deployment key as a PEM literal in the new
`saml_idp_slo_test.rs` — and the same literal in `saml_idp_sso_test.rs`, a W3
suite this wave extended, which W3's hygiene pass missed — both now generated
once per binary with `rcgen` behind a `OnceLock`; `assert_eq!(status, 200,
"{text}")` on the TOTP enrolment response in `ssf_test.rs`, whose body carries
`secret_base32`; `let secret = marker()` flowing into an assertion in
`sp_metadata.rs`'s tests (now `probe`); `const key = pemBlock("PRIVATE KEY")`
formatted into a template in `samlForm.test.ts` (now `block`). The stale doc of
`ssf_delivery_test::a_redirect_is_not_followed` (it described the old
second-hop refusal) and the test named
`a_redirect_to_a_private_address_is_refused_by_the_guard_too` (renamed
`a_redirect_to_a_reachable_receiver_is_not_followed_either`, with T-392's
citation) are corrected (carry item 9). No added `tracing` line formats a
token, a SET, an `Authorization` value, a cookie, an assertion, a `NameID` or a
`SessionIndex`: the handlers log tenant, SP, stream and run ids, fixed reasons
and error kinds, and the deliverer's reasons are a fixed vocabulary
(`a_transport_reason_never_carries_the_error_text`).

---

## 6. P23W4-05 — `AcsEndpoint.index` without a maximum

**Severity: Informational. Fixed in `a3ad895`; spec `72a3d57`.**

The model is `u16` and contract §29.2 says "an unsigned 16-bit integer", but
utoipa published `{"type": "integer", "format": "int32", "minimum": 0}`, so a
generated SDK accepts 70 000 and learns of the bound from a `400`. The field
carries `#[schema(maximum = 65535)]`. **Test:**
`openapi::saml_schema_tests::the_acs_endpoint_index_is_bounded_to_sixteen_bits`
failed before the fix (carry item 5).

---

## 7. SAML single logout (D-37 … D-39) — reviewed adversarially (item 1)

**Verdict: sound.** Probes, each against the code as merged:

* **Verification, never `verify_signed_xml`.** `grep` over every crate's `src/`:
  the only call is a test helper (`saml_idp/tests.rs`). `verify` requires a
  signature on every `LogoutRequest` and on every `LogoutResponse` from an SP
  with a certificate; POST is `verify_post_signature` (samael's per-node
  `reduce_xml_to_signed_with_allowed_algorithms`, SHA-2 only) after
  `signature_placement` found exactly one DSig `Signature`, the root's child,
  with one `Reference` to the root's `ID`; Redirect is
  `RedirectQuery::verify_signature` over `SAMLRequest|SAMLResponse=…[&RelayState=…]&SigAlg=…`
  exactly as received (raw, still percent-encoded), RSA-SHA-256/384/512 only,
  the key type checked. A Redirect document carrying an enveloped signature is
  refused; a query carrying both messages, either twice, or a message in the
  parameter of the other kind is refused. `SigAlg` is covered by the signature;
  a `SigAlg` naming another algorithm than the one used fails as an invalid
  signature, with no separate comparison — T-370 now says exactly that (carry
  item 3: T-377 said only that `SigAlg` is a kept log parameter; the wording the
  carry list quoted is not in the model, and T-370 is where the rule belongs).
* **Before verification nothing is trusted.** Parse (size, markup declarations,
  encodings, no recovery, no network), kind, placement, `RelayState` ≤ 80 bytes,
  `Destination` byte-equal to the tenant's SLO URL, SP by `Issuer` **in the
  path's tenant**, a disabled SP refused, then the signature. Refusal pages are
  generic, set no cookie and sign nothing.
* **Replay (T-371).** `{sp_id}:{ID}` UNIQUE per tenant on `saml_logout_run`,
  claimed before anything is resolved, kept ten minutes. The accepted
  `IssueInstant` window is at most 300 + 60 s behind and 60 s ahead, so a
  replay must arrive within 420 s of the first use: inside the ten minutes.
* **Resolution (T-379).** Participants by (path tenant, verified SP,
  `SessionIndex`) and then `NameID` value **and** format equal to the row's;
  with no index, by (tenant, SP, `NameID`). An SP names only sessions it took
  part in.
* **Revocation feed (§4 G-2's acceptance).** Each session: back-channel logout
  to its OIDC clients, then `AuthService::logout` → `SessionRepository::invalidate`,
  which publishes the session id's hash to the revocation feed and, with SSF,
  reports `session-revoked` through the sink. Revoke first, then propagate; a
  failed revocation answers an error page, signs nothing and clears the cookies.
* **Open redirect (T-375).** Every outbound message goes to the SP's
  **registered** `slo_url` on its registered binding (validated at write by the
  ACS URL rule); a location is never read from a message
  (`a_message_naming_another_location_is_answered_at_the_registered_one`, `the_trigger_reads_no_destination_from_its_query`). `RelayState` is the
  initiator's own, ≤ 80 bytes, URL-encoded on Redirect and HTML-escaped by the
  D-27 form page on POST, echoed to that SP only. The IdP-initiated trigger
  takes no redirect parameter at all.
* **Chain (T-383).** `InResponseTo` is consumed once on the X6 arbiter, by
  SHA-256 of a 256-bit outbound `ID`, and only from the SP the request went to;
  an unsigned response from an SP without a certificate only advances the chain
  and marks it partial. A third party cannot drive someone else's chain without
  the `ID`.
* **Signing oracle (T-373).** AXIAM signs a `LogoutRequest` only for sessions
  already ended and a `LogoutResponse` only to a verified request; Redirect
  signatures are detached (no XML signature exists), POST signatures are
  enveloped and re-verified. A malicious registered SP can obtain a signed
  `LogoutResponse` naming its own `slo_url` and an `InResponseTo` of its
  choosing (a checked NCName) — D-38 accepted that; it is rooted at
  `LogoutResponse`, which D-23's placement rule refuses at every SP AXIAM
  controls.
* **The cross-site `403` (T-378).** `/sso/logout` refuses
  `Sec-Fetch-Site: cross-site` after the D-20 check; a browser without fetch
  metadata is admitted (D-26). `same-site` is admitted: a sibling subdomain can
  sign the visitor out, which is D-26's accepted rule.
* **Cookies.** Every answer to a verified message (`deliver`, `logged_out`, the
  revocation-failure page) clears the three API cookies and every OP-cookie copy
  for the tenant; `/slo` never reads the OP cookie.
* **D-20.** `tenant_serving_saml` runs before the query or body is read; every
  other method and sub-path is the `default_service` `404`; with the switch off
  and in a build without `saml` the answer is identical
  (`saml_idp_e2e_test`).
* **Status oracle (accepted).** A disabled SP's request gets `403`, an unknown
  issuer `400`: an unauthenticated sender learns that an entity id is
  registered-but-disabled. SP entity ids are public metadata; not worth a second
  answer shape.
* **Cascades (item 8).** `saml_sp_session` and `saml_logout_run` go with the
  tenant (one transaction), with the SP (`SP_DELETE_CASCADE`) and by both
  erasure paths (`SAML_ERASURE_STATEMENTS`, in the erasure's transaction); both
  are swept and registered in `/health/jobs`. A run whose SP was deleted
  mid-chain finds no participant row and ends partial.

---

## 8. SP registry, metadata import, SET issuance — reviewed (items 2, 3)

* **Tenant isolation and principals.** Every §29 route checks the permission,
  then `require_own_tenant`; the repositories put `tenant_id` in every `WHERE`.
  `AuthenticatedUser` refuses a non-user audience with `401` (D-43); `saml_sp`,
  `saml_idp` and `ssf_streams` are on the human-only list
  (`permissions.rs`).
* **D-42's four refusals** (`encrypt_assertions`, an SP certificate the SSO
  decoder refuses or below RSA-2048/P-256, a changed `entity_id`, a group outside
  the tenant) are in the handler after the validator. **Promote** is one
  transaction that checks `next` and the validity window with `THROW`, retires
  the old `active` (key destroyed) before the `next` row takes the slot, and is
  retried on write conflict so the race's loser reads `409`.
* **`parse_sp_metadata`.** Markup declarations and other encodings are refused
  on the bytes before any parser (no DTD, so no entity); 512 KiB; libxml without
  recovery or network, its default depth bound; one `EntityDescriptor` root (an
  aggregate is refused); URLs only through `guarded_fetch` with
  `allow_private = false`, every redirect hop re-validated, errors collapsed to
  three categories (T-356's lesson). **D-54's tree rewrite** touches only
  `cacheDuration` on `SPSSODescriptor` (removed) and a missing ACS `index`
  (added, unqualified); libxml's `has_attribute`/`get_attribute` ignore
  namespaces, so a prefixed `foo:index` suppresses the default and samael then
  refuses the document — fail closed. Re-serialisation preserves namespaces;
  what it can change (character references written as characters, attribute
  whitespace normalised by libxml) does not change what the validator sees, and
  the draft is never stored without the administrator submitting it through the
  validator. The warning text carries the SP's `Location` with control
  characters stripped and cut to 200 characters; the console renders it, and
  every server message, as React text — no `dangerouslySetInnerHTML` in
  `pages/saml` — so there is no XSS.
* **SET issuance (T-389).** `alg: EdDSA`, `typ: secevent+jwt`, the deployment
  key's `kid`; claims `iss`, `aud` (one string), `iat`, `jti`, `txn`, `sub_id`,
  `events` with one member; **no `sub`, no `exp`** (the claim type has no field
  for either). Pinned now against every verifier AXIAM runs over the same key
  (`ssf::tests::a_set_is_refused_by_every_verifier_axiam_runs`, `050ab54`): the
  access-token middleware and token exchange (`decode_access_token`, which
  requires `sub`, `exp`, `iat`, `iss` and the AXIAM audiences), introspection
  (`decode_access_token_any_audience`, same required claims), the
  `id_token_hint` of `/oauth2/authorize` and end-session (`decode_id_token_hint`
  — `exp` not checked, but `IdTokenClaims` requires `sub`), and an RP's
  back-channel logout verifier (`typ` and the back-channel-logout event, which a
  SET carries neither of). The MFA challenge and WebAuthn state tokens require
  `sub`, `purpose`, `tenant_id` and `exp`. `iss` is the tenant issuer where
  tenant issuer paths are on, else the root issuer — so with them off every
  tenant's SETs share `iss` and the key, and D-47's deployment-wide unique
  audience is what separates them (T-390).
* **Subject policy (D-46).** `email` only on an administrator-chosen stream and
  only for an address D-25 vouches for; otherwise not sent, never downgraded to
  `iss_sub`.

---

## 9. Receiver API, push, poll, event sources — reviewed (items 4 … 7)

Beyond P23W4-01 … -03, probes that did not yield:

* **Receiver token.** `parse_validated_claims` (cookie first, then `Bearer`/
  `DPoP`), then `sub_kind == OAuth2Client` and `ssf.manage`; a user's cookie is
  `403`. One `404` for another receiver's, another tenant's, a malformed id and
  a switched-off tenant (`owned_stream`). `POST`/`DELETE` are `403`;
  `status_actor` stops a receiver from lifting an administrator's non-`enabled`
  status (now also under concurrency, P23W4-01). Verification is claimed in the
  datastore (one `UPDATE … WHERE last_verification_at = NONE OR
  last_verification_at <= $cutoff`; it does not touch `updated_at`, so it never
  conflicts with a configuration write).
* **The header.** Sealed under `pki_encryption_key`, never projected,
  write-only in every input type's `Debug`; moving the endpoint to another
  origin needs it again (both paths); the deliverer pairs it with its endpoint
  (P23W4-01).
* **`guarded_fetch_no_redirect` against `guarded_fetch`'s first hop**, line by
  line: the same parse, host and port; the same `https` rule waived only with
  `allow_private`; the same `resolve_and_pick` (fresh A/AAAA, every address
  judged, the operator allow-list, metadata never); the same `pinned_client`
  (resolve pinned, `redirect::Policy::none()`, 10 s); the same `Content-Length`
  cap. The only difference is that a `3xx` is returned. `allow_private` is
  reachable only through the `#[doc(hidden)]` `admitting_private_networks_for_tests`,
  pinned by a source scan (`push_goes_through_the_no_redirect_guarded_fetch_and_nothing_else`).
* **Status mapping (D-49, D-53 (8)).** `2xx` delivered; `400` with a known
  `err` dead-lettered with the code, without one `HTTP 400`; `401`/`403`
  dead-lettered; `404`/`408`/`429`/`5xx` retried; `3xx` retried, never followed;
  any other `4xx` dead-lettered. The body is read only for a `400`, capped at
  64 KiB, never logged.
* **Dispatcher (D-36).** The webhook kind keeps its queue, exchange and DLQ
  names, its declare arguments and its wire bytes (`topology.rs`, `wire.rs`
  pins); only `axiam.ssf_push.dlq` carries a TTL (seven days).
* **Poll.** `ack` and `setErrs` delete only `(tenant, stream, jti)` rows of the
  token's stream; 32 KiB body (`PayloadConfig`), 1 000 `ack`, 100 `setErrs`, a
  `jti` over 64 bytes ignored, `maxEvents` clamped to 100; one long poll per
  stream per instance, released on drop — now pinned on cancellation; the buffer
  is bounded (1 000, oldest dropped) and expires in seven days, swept on
  `/health/jobs`.
* **Event sources (D-52, D-53).** `session-revoked` comes only from
  `invalidate`, `invalidate_user_sessions` and `invalidate_user_sessions_except`
  (never `consume*`, never expiry), after the write commits; `account-purged`
  captures the subject before the tombstone or the erasure (`users::delete`,
  SCIM `DELETE`, Art. 17). `txn` is a `tokio::task_local!` scoped to the
  operation's future: it cannot outlive the request, and a spawned task does not
  inherit it. The emitter is a no-op without an outbox and when `ssf_enabled` is
  off (`streams_for` checks the switch after the indexed read, before any user
  read); `announce_status` checks the switch too (D-53 (7)).
* **Account status (item 12).** No new session→principal path: SLO ends
  sessions (it grants nothing), the receiver token is a client's, the step-up
  record rides the existing authorize path (`account_may_act` via
  `check_session_holder`). `PendingVerification` is not refused anywhere new.
* **`x IN $ids` (item 8, carry item 1).** The wave's only other `IN $…` query
  on a table with a compound index is the poll `ack`
  (`ssf_event_buffer.jti IN $jtis` over `(tenant_id, stream_id, jti)`); the
  SP registry's `groups_outside_tenant` is `meta::id(id) IN $ids` on `group`.
  Both match every bound value — pinned with five and with two values
  (`an_acknowledgement_naming_many_rows_deletes_every_one`,
  `groups_outside_tenant_names_exactly_the_ones_that_are_not_the_tenants`,
  `050ab54`). The pre-existing `IN` queries (`role.rs`, `permission.rs`, `scope.rs`,
  `audit.rs`, `directory_config.rs`, `user.rs`, `certificate.rs`) are on edge
  `in` fields, `meta::id`, or lower-cased expressions, not on a compound unique
  index's second column, and each has multi-value tests in its suite; no change.

---

## 10. Verdicts on the orchestrator's carry list

1. **`x IN $ids` siblings — checked, none affected** (§9); two pins added.
2. **Five cleanup jobs not registered — reported** (P23W4-06, pre-existing;
   issue body in §14). They record outcomes but are not in `SWEEP_JOBS`, so
   `/health/jobs` lists them only after a first run and never reports one that
   never starts. Some are conditional on a feature; the issue says how to
   register them so a disabled feature does not read as stalled.
3. **T-377 / `SigAlg` — wording fixed** in T-370 (the verification rule) and
   T-377 (the log), §7.
4. **No console control for the switches, no SSF page — a gap, not a security
   defect; reported** (P23W4-07). Both switches default off and are disable-only
   layered settings an operator changes through §27's settings API (the
   management registry and every SDK have it); `get_idp` shows SAML's state in
   the console. What is missing is visibility: which third parties receive
   events about the tenant's users is visible only through the API. That is
   worth a page (GDPR Art. 30 records), not a merge blocker.
5. **`AcsEndpoint.index` — fixed** (P23W4-05).
6. **SSF residuals.** *Audience squatting* (D-47) — **reported, not accepted
   as stated** (P23W4-11): T-390 said a squat "buys nothing a receiver accepts,
   because the receiver configures the audience its own stream was given". That
   holds for a receiver that takes `aud` from its stream, requires the push
   `Authorization` header or checks a per-tenant `iss`. Without per-tenant
   issuers (`AXIAM__AUTH__TENANT_ISSUER_PATHS` off) every tenant's SETs share
   `iss` and the key, so a receiver that adopted a conventional audience (its own
   URL) before its stream was registered, and accepts unauthenticated pushes,
   accepts SETs a squatting tenant pushes to it — `session-revoked`,
   `account-disabled` and the rest, about a subject the squatter chooses: an
   email subject is vouched for by D-25 when the squatter's own account with the
   victim's address is `Active`. Preconditions are several and the legitimate
   registration then fails with `409`, so Low; requiring per-tenant issuers for
   SSF is a change to D-45 and the maintainer's to decide (§14). T-390's residual is
   corrected and the website tells receivers what to check. The rest are
   **accepted, each with its reason.** *Erased subject in buffer
   or DLQ up to seven days* (T-402): the rows have no user column to delete by
   and the DLQ is a broker queue; seven days is D-48's bound and is stated. A
   `user_id` column on `ssf_event_buffer` would let erasure remove the buffered
   rows — noted for G-6 (§15), not a W4 change. *Receiver token after client
   deletion*: an access token is not re-checked against its client anywhere in
   AXIAM; 15 minutes is the access-token lifetime, and stream binding is by
   `client_id`, so a re-created client of the same id is the same receiver.
   *Primary and retry queues without TTL*: a message in the retry queue has a
   per-message TTL (the backoff); one in the primary queue is pending delivery,
   not retained after need, and dropping it by TTL would lose the event
   silently — queue depth is the operator's alert. Not changed.
7. **Duplicated consumer supervisor loop — reported** (P23W4-08).
8. **Step-up record consumed before client validation — fixed**
   (P23W4-02): wave-introduced, and moving the call was necessary but not
   sufficient.
9. **Poll `ERROR` every 500 ms — fixed** (P23W4-03).
10. **Stale test descriptions — fixed** (P23W4-04).
11. **Keycloak-initiated logout and front-channel SLO towards a real SP —
    reported as a coverage gap** (P23W4-09).

### W3 §15 — was it honoured?

* **T23.2.4.** Logout messages are signed with the IdP credential, Redirect
  detached, POST enveloped and re-verified; SP messages are verified with the
  receiver's placement rule and `verify_post_signature` (SHA-2, per node) or
  over the received octets — never `verify_signed_xml`. T-312 decided (D-37,
  per-SP random `SessionIndex`). `saml_idp_slo` and `saml_idp_sso_logout`
  buckets; the D-20 `404`. **Honoured.**
* **T23.2.5.** `encrypt_assertions` and an unparseable or weak SP certificate
  refused; import only through `guarded_fetch`, nothing trusted from an
  unsigned document (the signature is reported, never evaluated); the metadata
  endpoint has the D-20 `404` (no publishable credential included) and
  `saml_idp_metadata`; the SP registry's element entered with T23.2.8.
  **Honoured.**
* **CSP.** The SLO POST binding renders through the D-27 auto-post function, so
  `exactly_one_handler_sets_its_own_policy` still holds unchanged (run, §13).
  **Honoured.**
* **Logging.** No SLO or SSF parameter joined `KEPT_QUERY_PARAMETERS`
  (`SigAlg` was already there); no route carries a bearer value in its path.
  **Honoured.**
* **Directory.** No shared counter became reachable from `axiam-auth`; the
  unknown-name lockout stays per process. **Carried** (G-8).
* **Filing.** P23W3-07 … -11 are #529 … #533; the one W3 item held back stays
  with the maintainer, as W3 §14 says. **Honoured.**
* **Threat ids from T-357.** T-357 … T-405. **Honoured.**

---

## 11. Rate limits, CSRF, CSP, console (items 9, 11, 13)

* **Rate limits (§7 rule 6).** Every new inbound route has a bucket of its own:
  the seven §29 writes (`saml_sp_create`, `_update`, `_delete`, `_parse`,
  `saml_idp_credential_issue`, `_promote`, `_retire`, all
  `AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN`), IdP metadata, SLO and the
  IdP-initiated trigger (`end_session_per_min`), the three SSF admin writes
  (`ssf_stream_create`, `_update`, `_delete`), and each receiver route and both
  discovery forms (`ssf_stream`, `ssf_status`, `ssf_verify`, `ssf_poll`,
  `ssf_configuration`, `ssf_configuration_tenant`). The three new keys are
  listed as never preset and pinned by the config tests; administrator reads
  are unlimited, as elsewhere.
* **CSRF.** The §29 and §32 administrator writes go through the existing
  cookie-path CSRF middleware like every management route; `/slo` POST is a
  cross-site SAML binding that reads no cookie; the receiver API's cookie path
  admits only an OAuth2 client token, which no browser cookie carries.
* **CSP.** Unchanged: one setter, D-27's narrower policy, pinned.
* **Console.** `/saml` and its nav entry are gated on `saml_sp:read`, writes on
  `saml_sp:write`, credential actions on `saml_idp:credential`; no key,
  ciphertext or custody is ever displayed (fingerprints, serial, validity
  only); `400`/`404`/`409`/`503` messages are shown verbatim as React text with
  a private-key block blanked.

---

## 12. Threat-model reconciliation

Model **2.30.0** (from 2.29.0), each change in its fixing commit, all three
artifacts and the website regenerated together
(`node website/scripts/gen-threat-model.mjs` → *406 threats (389 mitigated, 17
open)*, no diff left):

| Change | Entry | Commit |
|---|---|---|
| Stream writes conditional on their version; header paired with its endpoint | **T-406** added (ssf_stream + ssf_event_buffer + ssf_step_up, Tampering, Low, Mitigated) | `8c3db3f` |
| Step-up record consumed only after validation, never by the asking session | **T-404** amended (residual closed) | `8693925` |
| One `ERROR` per poll; slot released on cancellation | **T-403**, **T-405** amended | `06d19fc` |
| Renamed redirect test | **T-392** amended (citation) | `96a2c6b` |
| `SigAlg` rule and log wording | **T-370**, **T-377** amended | documentation commit |
| Audience squatting without per-tenant issuers | **T-390** amended (residual corrected) | documentation commit |

Every W4 surface maps to an element: the SP registry and §29 routes (T-357 …
T-365), IdP metadata (T-366 … T-369), SLO and its stores (T-370 … T-384), the
SSF receiver, transmitter, store and flows (T-385 … T-406). Counts: STRIDE
*Tampering* 81, severity *Low* 29 (1 open), diagram *Audit, webhooks, email &
notifications* 40 threats / 3 open, open register 17. Reported findings
(P23W4-06 … -09, -11) are pre-existing, gaps or a decision; their entries should
be amended when they are acted on.

---

## 13. Checks run

All exit codes were captured from cargo itself (log plus `$?`), one step at a
time, with test binaries deleted between steps to stay inside the disk quota.

```bash
export CARGO_INCREMENTAL=0
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
# before the fixes — each new test failed:
cargo test -p axiam-db --test ssf_stream_repository_test a_write_prepared              # 1 failed (P23W4-01)
cargo test -p axiam-oauth2 --test ssf_delivery_test a_credential_supplied              # 1 failed (P23W4-01)
cargo test -p axiam-api-rest --no-default-features --test ssf_test -- \
  the_same_session_returning_emits_nothing \
  a_return_leg_the_authorization_endpoint_refuses_spends_nothing \
  an_unsignable_held_event                                                             # 3 failed (P23W4-02 ×2, P23W4-03: 4 lines)
cargo test -p axiam-api-rest --lib saml_schema_tests                                   # 1 failed (P23W4-05)
# after:
cargo fmt --all --check                                                                # clean
cargo clippy -p axiam-core -p axiam-db -p axiam-oauth2 -p axiam-federation \
  -p axiam-api-rest -p axiam-server --all-targets -- -D warnings                       # clean
cargo clippy -p axiam-federation -p axiam-api-rest -p axiam-server \
  --all-targets --no-default-features -- -D warnings                                   # clean
cargo test -p axiam-core --lib                                                         # 473 passed
cargo test -p axiam-db --test saml_idp_credential_test                                 # 17 passed
cargo test -p axiam-db --test saml_service_provider_test                               # 15 passed
cargo test -p axiam-db --test saml_slo_test                                            # 17 passed
cargo test -p axiam-db --test ssf_event_buffer_test                                    # 6 passed
cargo test -p axiam-db --test ssf_session_sink_test                                    # 8 passed
cargo test -p axiam-db --test ssf_step_up_test                                         # 9 passed
cargo test -p axiam-db --test ssf_stream_repository_test                               # 12 passed
cargo test -p axiam-oauth2 --lib                                                       # 551 passed
cargo test -p axiam-oauth2 --test ssf_delivery_test                                    # 31 passed
cargo test -p axiam-federation --lib                                                   # 308 passed (saml)
cargo test -p axiam-federation --lib --no-default-features                             # 138 passed
cargo test -p axiam-amqp --lib                                                         # 146 passed (topology and wire pins)
cargo test -p axiam-api-rest --lib                                                     # 276 passed
cargo test -p axiam-api-rest --lib --no-default-features                               # 271 passed
cargo test -p axiam-api-rest --test ssf_test                                           # 56 passed
cargo test -p axiam-api-rest --test ssf_test --no-default-features                     # 56 passed
cargo test -p axiam-api-rest --test saml_idp_slo_test                                  # 26 passed
cargo test -p axiam-api-rest --test saml_idp_sso_test                                  # 20 passed
cargo test -p axiam-api-rest --test saml_admin_test                                    # 38 passed
cargo test -p axiam-api-rest --test saml_admin_test --no-default-features              # 28 passed
cargo test -p axiam-api-rest --test saml_idp_e2e_test                                  # 10 passed
cargo test -p axiam-api-rest --test saml_idp_e2e_test --no-default-features            # 1 passed
cargo test -p axiam-server --test cleanup_task --no-default-features                   # 24 passed
(cd frontend && npx vitest run src/pages/saml)                                         # 109 passed
python3 scripts/check-crate-layering.py                                                # OK, 19 crates
scripts/check-doc-links.sh                                                             # OK
python3 scripts/check-spec-digest.py                                                   # OK
python3 scripts/gen-management-registry.py --check                                     # OK, 184 operations, 27 namespaces
python3 scripts/check-config-key-coverage.py                                           # OK
python3 scripts/check-frontend-coverage.py                                             # OK, 47 modules
python3 scripts/check-amqp-transport.py                                                # OK
node website/scripts/gen-threat-model.mjs                                              # 406 threats (389 / 17), no diff
(cd website && npx tsc --noEmit -p . && npx oxlint src/docs/integrate.ts)              # clean (the SSF guidance)
```

`saml_idp_slo_test` and `saml_idp_sso_test` are gated on `saml` and compile to
nothing without it (0 tests, exit 0); `saml_idp_e2e_test` keeps its one
plain-build test (the routes are absent). The clippy runs print one pre-existing
configuration note from `axiam-opaque` (the MSRV in `clippy.toml` and
`Cargo.toml` differ), not a lint. **Spec:** `cargo build -p axiam-server
--no-default-features`, `--dump-openapi`, `check-spec-digest.py` and
`gen-management-registry.py --check` pass after `72a3d57`; the website API index
and contract anchors regenerate with no diff. **Intermediate commits:** each of
`8c3db3f`, `8693925`, `06d19fc`, `96a2c6b` and `a3ad895` was checked out and
clippy-checked in its own state (`-p axiam-core -p axiam-db -p axiam-oauth2
--tests`, `-p axiam-api-rest --no-default-features --lib --test ssf_test`, `-p
axiam-server --no-default-features --test cleanup_task`, all `-D warnings`):
clean. **Not run:** the Keycloak round trip (`#[ignore]`d, it needs a Keycloak;
T23.2.7 ran it twice), the live-broker dispatcher test (`#[ignore]`d, no
broker), the conformance suite (no network).

---

## 14. Issue bodies for the reported findings (not filed)

### P23W4-06 (Low) — five cleanup jobs are not registered in `/health/jobs` at start

`crates/axiam-server/src/cleanup.rs` records the outcome of `sso_handoff_code`,
`revocation_feed`, `dcr_unused_clients`, `cimd_unused_clients` and
`dcr_registration_tokens` into `JobHealth`, but `job_health::SWEEP_JOBS` — the
list `main` registers at start-up — does not name them. A registered job that
never runs is reported stalled after three intervals (T-129); an unregistered
one appears in `GET /health/jobs` only after its first run, so a sweep that never
starts (a panic in its setup, a misconfigured interval) is never reported. Found
by T23.2.4 while registering the SLO sweeps. Proposed: register each of the five
when its feature is enabled (the revocation feed's and DCR/CIMD's switches are
known at start), extend
`the_slo_sweeps_are_recorded_by_the_cleanup_loop_and_registered` to assert that
every name `cleanup.rs` records is registered, and record the rule in T-129.
Tests: a source-scan pin over `cleanup.rs`'s recorded names, a health snapshot
listing each before its first run.

### P23W4-07 (Informational) — the console cannot show or switch the SAML IdP and SSF surfaces

The console's *SAML Service Providers* page explains `saml_idp_enabled` but
cannot change it, and there is no SSF page and no `ssf_enabled` control at all
(`frontend-coverage-matrix.md` rows `saml_admin`, `ssf_admin`). Both are
disable-only layered settings changed through §27's settings API; the streams
are administered through §32's API. So an administrator cannot see from the
console which third parties receive security events about the tenant's users,
nor turn either surface off there during an incident. Proposed: a settings
control for both switches (organization and tenant scope, with the layered
"disabled above" state shown); an SSF page listing streams with receiver,
audience, method, endpoint, status and who set it, `events_delivered` beside
`events_allowed`, never the `authorization_header` (write-only), saying that
moving a push endpoint to another origin requires the header again, and
handling `409` (T-406) by reloading. Tests: vitest for both controls and the
page; the Playwright permission matrix for `ssf_streams:read`/`write`.

### P23W4-08 (Informational) — the outbound consumer supervisor loop is copied per kind

`crates/axiam-server/src/main.rs` supervises the webhook consumer and the
`ssf_push` consumer with two copies of the same reconnect-and-restart loop
(about 30 lines each, T23.5.1's note); G-6 (outbound SCIM) would add a third,
and a fix to one copy (backoff, shutdown, health) can miss the others. Proposed:
one `spawn_outbound_consumer(kind, deliverer, …)` in `axiam-server` (or in
`axiam-amqp`'s outbound module, behind the D-36 ports) that both kinds call;
no behaviour change, pinned by the existing consumer tests and a supervisor
test that restarts a failing consumer.

### P23W4-09 (Informational) — single logout is untested against a real SP

T23.2.7's oracle covers samael (SP-initiated SLO over both bindings, the
`LogoutResponse` verified by samael) and Keycloak for sign-on only. Untested: a
logout **initiated by Keycloak** towards AXIAM's `/slo` (Keycloak's own
`LogoutRequest` shape, `SessionIndex` handling and signature), and AXIAM's
**front-channel propagation to a real SP's `SingleLogoutService`** (Keycloak
receiving AXIAM's signed `LogoutRequest` and answering with its
`LogoutResponse`). Proposed: extend `saml_idp_keycloak_roundtrip_test` with both
(a Keycloak session brokered to AXIAM, logged out from each side), wired into
CI's compose job like the sign-on tests. Tests: each direction on both bindings
Keycloak supports, the AXIAM session gone from `/oauth2/revocations`, and
Keycloak's session gone.

### P23W4-11 (Low) — SSF audience squatting where SETs share one issuer (decision first)

D-47 makes a stream's audience unique across the deployment so that one tenant
cannot collect SETs addressed to another tenant's receiver. It does not stop a
tenant administrator from registering an audience **before** its owner does,
and T-390 assumed that this buys nothing. That holds only when the receiver
takes its `aud` from the stream it was given, requires the push `Authorization`
header it supplied, or checks a per-tenant `iss`. Where the deployment serves no
per-tenant issuers (`AXIAM__AUTH__TENANT_ISSUER_PATHS` off), every tenant's SETs
carry the same `iss` and the same key, so a receiver that adopted a conventional
audience (its own URL) before its stream was registered and accepts
unauthenticated pushes accepts SETs a squatting tenant pushes to its endpoint:
`session-revoked`, `account-disabled`, `credential-change` and the rest, about a
subject the squatter chooses — an `email` subject is vouched for by D-25 when the
squatter's own account carrying the victim's address is `Active`. The
legitimate registration then fails with `409`. Options for the maintainer: (a)
require per-tenant issuers for SSF — `ssf_enabled` cannot be turned on (or
discovery answers its `404`) unless the deployment serves
`{root}/t/{tenant}`, so `iss` always separates tenants (a SET cannot simply
carry a per-tenant `iss` the deployment does not serve: SSF §7.2 discovers the
transmitter from it); (b) the same, only for deployments with more than one
tenant; (c) keep D-45 and rely on the guidance this review added to the
website (take `aud` from the stream, require the push header, serve per-tenant
issuers where tenants do not trust one another). (a) and (b) change D-45 and
contract §32 and are best decided before 1.56 ships, while no receiver has
integrated. Tests for (a)/(b): `ssf_enabled` refused (or discovery `404`) with
paths off; with paths on, a SET from tenant A does not verify with tenant B's
issuer.

---

## 15. What W5 must take from this review

* **The D-36 dispatcher (G-6, G-8).** A new kind is one line in the macro and
  its own topology: keep the webhook kind's names and arguments untouched
  (RabbitMQ refuses a redeclaration), give the new DLQ the same seven-day
  `x-message-ttl` if it holds personal data (outbound SCIM payloads do), and do
  not add a third copy of the supervisor loop (P23W4-08). G-8's in-process path
  implements the same two ports; it must keep the deliverer's contract (one
  attempt, classify, never decide) and the audit vocabulary.
* **Read-modify-write (T-406's lesson).** Any registry with two writers — an
  administrator and a remote party (SCIM targets in G-6, CIBA's pending
  requests in G-7) — writes conditionally on the version it read, and a
  credential read separately from the endpoint it goes to is re-checked against
  that endpoint's version before sending.
* **SSRF.** Every outbound request carrying a credential goes through
  `guarded_fetch_no_redirect` with `allow_private = false` (never
  `guarded_fetch`, whose request closure is re-sent to a redirect `Location`);
  error text reaching an audit row or an administrator is a fixed vocabulary
  (T-356's lesson); the write-time policy is the webhook one, the delivery-time
  guard is the real one. A G-6 SCIM target's bearer token is D-49's header:
  sealed, write-only, never following the endpoint to another origin.
* **Marker-driven state (T-404's lesson).** A query parameter that only says "a
  return leg is being made" consumes nothing until the request it rides on has
  been validated, and never in the session that started the flow. CIBA's
  polling and ping/push modes must bind every consumption to the client and the
  `auth_req_id` holder, not to a marker.
* **Erasure.** A queue or buffer that holds a subject gets a user column (or a
  digest of one) so erasure can remove it; T-402's seven-day residual should
  not be copied into outbound SCIM.
* **Logging.** A loop that retries a failing operation logs once per request,
  not once per iteration.
* **Tenant-distinct identifiers (T-390's lesson, P23W4-11).** A token or
  message another party verifies with a deployment-wide key must carry
  something that separates tenants and that the verifier checks — CIBA's
  `iss`/`aud` and any outbound SCIM token included; a uniqueness index alone
  does not stop a tenant from claiming an identifier first.
* **New threat ids** start at **T-407**.

## 16. Invariants

I1 (nothing registered today changes behaviour) holds with these deliberate,
CHANGELOG-recorded changes, all to surfaces new in this unreleased wave: an SSF
stream write prepared from an overtaken read is refused with `409` (the
administrator's `PUT`) or decided again from a fresh read (the receiver's three
writes, `409` after three attempts), and a push attempt that finds the stream
changed is retried (`8c3db3f`); the step-up record is consumed only by a validated
authorization request in a new session (`8693925`); an unsignable held event is
logged once per poll (`06d19fc`); `AcsEndpoint.index` is published with
`maximum: 65535` (`a3ad895`). Contract 1.56 (unreleased) is amended in place in §32.3
rule 4 and §32.6; the OpenAPI spec carries the new `409`s and the bound
(`72a3d57`); no SDK-visible field changed shape.
