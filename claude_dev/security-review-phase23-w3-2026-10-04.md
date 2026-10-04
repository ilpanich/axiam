# Security review — Phase 23, wave W3 (F4)

**Date:** 2026-10-04.
**Against:** `claude/phase23-w3`, the whole wave diff `a79b5a3..1c16c61` (174
files, about 47 600 lines added; `a79b5a3` is the W2 merge on `main`). The
fixes and pins of this review sit on top: `82bc6a0`, `4acc49d`, `06d061b`,
`db3d5f0`, `236ba35`, `9528f91`, `03e9066`, `3d58a46` (the spec regenerated),
and the documentation commit that carries this file.
**Scope:** the W3 tasks of
[`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md):
G-2's first three — T23.2.1 (SP registry, `saml_idp_enabled`, the sealed
signing credential, D-20, D-21), T23.2.2 (the `saml_idp` issuance library,
D-22, and **D-23, the fix of a Critical pre-existing signature-confusion defect
in the SAML SP**), T23.2.3 (the SSO endpoint, pending requests, the cookie path,
D-24 … D-27) — and all of G-3's remaining tasks — T23.3.3 (JIT and linking,
D-28, D-29), T23.3.4 (group mapping, D-30), T23.3.5 (sync, D-31), T23.3.7 (the
address guard and the frame relay, contract §30, D-19, D-32), T23.3.8 (the §30
routes and console, D-33) and T23.3.6 (the real-server e2e).
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) (model
2.23.0: T-67, T-160, T-291 … T-355) and
`ThreatDragonModels/Axiam/Axiam.json`, and the OWASP ASVS 5.0 areas the diff
touches (V1 encoding and injection, V3 web frontend — CSP, V6 authentication,
V7 session management, V10 OAuth/OIDC and SAML federation, V11 cryptography,
V12 secure communication, V13 configuration, V16 logging). The D-23 fix was
read against the `samael 0.0.22` and `quick-xml 0.41` sources it relies on. Every
finding fixed here has a test that failed before the fix; a claim with no test
says so.

---

## 0. Summary

Five findings were fixed on the branch, all wave-introduced or missed siblings
of the wave's own fixes; one more is the wave's own fix of a pre-existing
Critical, which this review confirms. The two Mediums both sit in G-3's account
lifecycle. **Linking** — the administrator act D-28 built to retire every
credential the directory does not decide — missed **federation links**: a social
or upstream-IdP identity bound to the account kept signing it in (P23W3-01).
And **T-332**, which the wave itself left open, is closed with a per-(tenant,
login name) failure counter for names AXIAM holds no account for (P23W3-02). The
two Lows close T-325 (the request tracer logged every query value, the SAML
handle and `RelayState` among them — and, before this wave, OAuth2 `state`,
reset tokens and search terms; P23W3-03) and turn the §30 address guard's
answers from an internal-DNS oracle into one message for host names (P23W3-04,
new **T-356**).

**The D-23 fix holds.** Every attack shape this review could build against the
placement rule, per-node verification, duplicate IDs, namespaces, the
Response-only-signed case and `PreDigest` failed closed (§7). The defect is in
every release that shipped SAML federation; the advisory issue body and a
maintainer note are in §14.

The SAML IdP surfaces (registry, credential, issuance, SSO endpoint, cookie
path, CSP) held: no cross-tenant, replay, ACS-redirection or takeover path was
found. The directory's guard, relay, mapping and sync held beyond the findings.

| ID | Finding | Severity | Surface / threat | Disposition |
|---|---|---|---|---|
| **P23W3-01** | Linking an account to its directory entry deleted passkeys, revoked certificates, sessions and refresh tokens — but left **federation links**: an upstream OIDC/SAML identity bound to the account kept opening sessions without the directory deciding. | **Medium** | `POST …/directory/links`; T-336, D-28 | **Fixed** — `06d061b` |
| **P23W3-02** | T-332: with `jit_provisioning` on, an unknown name reached the directory on every attempt; no counter existed for names without an account. | **Medium** | `/api/v1/auth/login` (JIT); T-332 | **Fixed** — `236ba35` (T-332 closed) |
| **P23W3-03** | T-325: `tracing-actix-web`'s root span recorded every query value — the SAML `handle`, `RelayState`, `SAMLRequest`; also (pre-existing) `state`, `login_hint`, `id_token_hint`, reset/GDPR tokens, search terms, and the `/account/export/{token}` segment. | Low | every route; T-325 | **Fixed** — `9528f91` (T-325 closed) |
| **P23W3-04** | The §30 write routes told a tenant administrator whether a host name did not resolve or resolved into a private range, loopback, the metadata service or an own listener: an oracle for the deployment's internal DNS at 30 writes/min. | Low | §30 `PUT`/`PATCH`; T-300 → **T-356** | **Fixed** — `03e9066` (T-356 added) |
| **P23W3-05** | JIT's lost-race branch ran the group mapping before the winner's status check, re-adding memberships to an account that may not sign in (granting nothing). | Informational | JIT; T-341 | **Fixed** — `db3d5f0` |
| **P23W3-06** | The SP verifier checked only the first `ds:Signature` and bound the assertion to any `Reference` naming it, verified or not — signature confusion, an authentication bypass. Pre-existing; fixed in the wave by D-23 (`c3db35c`). | **Critical** | SAML SP ACS; T-67 | **Fixed in the wave**, confirmed here; issue to file after `main` (§14) |
| **P23W3-07** | IdP metadata signatures are never checked on the SP side (`fetch_idp_metadata`: HTTPS + SSRF guard only), and the metadata is fetched on every sign-in. The signing certificate is pinned in the configuration, so the exposure is the SSO redirect target. (Item 3.) | Low | SAML SP; T-67 vicinity | **Reported** (pre-existing, absent control) |
| **P23W3-08** | The SP verifier accepts any algorithm xmlsec does (`rsa-sha1` included) and does not refuse DTD-bearing responses — both of which the wave's IdP receiver refuses. A missed sibling in the *pre-existing* code. | Low | SAML SP; T-67, T-320 | **Reported** (pre-existing) |
| **P23W3-09** | `/oauth2/authorize` has no rate limiter at all; T23.2.3 found it when the preset the plan named did not exist. (Item 14.) | Low | `/oauth2/authorize`; §7 rule 6 | **Reported** (pre-existing) |
| **P23W3-10** | No certificate is bound to a user (D-29): linking revokes by convention. (Item 10.) | Low | PKI × linking; T-336 residual | **Reported** (follow-up decided by D-29) |
| **P23W3-11** | The tenant email provider override — an SMTP host and port, or an HTTP API `api_url` — is not held to any outbound address policy, and `…/email-config/test` connects on demand: T-300's class, for email. | **Medium** | `email_config` (tenant scope) | **Reported** (pre-existing sibling of the address guard) |
| **P23W3-12** | Deleting or disabling a directory leaves its accounts' sessions and passkeys working and stops deprovisioning. (Item 6.) | Low | §30 `DELETE`/disable | **Accepted** — documented (§30.3 rule 5), confirmed in the console, audited with the live-account count; one console sentence corrected |
| **P23W3-13** | No sweep has a multi-replica guard; the first full sync run reports every already-`Inactive` account, administrator suspensions included. (Item 9.) | Informational | sync; T-349 | **Accepted** |
| **P23W3-14** | A JIT account is `Active`, so D-25 asserts its directory-supplied `mail` as an email `NameID`: a directory administrator can give an entry an address that exists at an email-keyed SP but in no AXIAM account. | Informational | SAML IdP × directory; D-25, T-334 | **Accepted** (the tenant trusts its own directory; assumption 7) |

**Verdict on merge.** Nothing open blocks W3. The five fixes are in and pinned,
the threat model is at **2.24.0 — 356 threats, 340 mitigated / 16 open** — and
the three artifacts and the website agree. P23W3-11 (Medium) and P23W3-07 …
-10 should be filed before the phase's PR merges (§14). **P23W3-06 is filed only
after the fix is on `main`**, with the maintainer deciding on a patch release
and advisory first (§14, maintainer note). The OpenAPI spec is regenerated
(`3d58a46`: the linking operation's description names the links).

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| SP verifier, D-23 placement rule, per-node verification | T23.2.2 | `axiam-federation/src/saml.rs` §`verify_signature`, `check_signature_placement`, `bind_signature_to_assertion`; `samael::crypto::xmlsec::reduce_xml_to_signed`, `collect_id_attributes`, `predigest_result`; `quick-xml` text draining | **read in full** + the upstream sources |
| SP registry, validator, `saml_idp_enabled`, `SamlSigning`, credential store and service | T23.2.1 | `models/saml_sp.rs`, `saml_sp.rs`, `models/settings.rs`, `pki/saml_signing.rs`, `cert.rs`, `mtls.rs`, `db/…/saml_idp_credential.rs`, `saml_service_provider.rs`, tenant cascade | targeted: ACS rule, key custody, refusals |
| Issuance library | T23.2.2 | `saml_idp/{mod,sign,xml,pairwise}.rs` | targeted: signing, self-check, failure responses, pairwise, D-25 |
| Receiving `AuthnRequest` | T23.2.3 | `saml_idp/request.rs` | **read in full** |
| SSO endpoint, pending requests, binding cookie, OP cookie path, `return_to` SAML arm | T23.2.3 | `handlers/saml_idp.rs`, `db/…/saml_authn_request.rs`, `login_hop.rs`, `returnTo.ts`, `middleware/csrf.rs` | **read in full** |
| CSP middleware (D-27) | T23.2.3 | `middleware/security_headers.rs`, every CSP setter in the crate | **read in full** + grep |
| Rate limiting of the new routes | T23.2.3, T23.3.8 | `server.rs` | **read in full** (diff) |
| JIT, linking, lost race | T23.3.3 | `axiam-auth/src/service/directory.rs`, `service.rs` | **read in full** |
| Group mapping, cache flush | T23.3.4 | `groups.rs`, `group_lookup.rs`, `dn.rs`, `db/…/group.rs` | targeted: ordering, owner marker, fail-closed |
| Sync | T23.3.5 | `sync.rs`, `sync_lookup.rs`, `cleanup.rs` | targeted: deactivation order, CAS, valve, replicas |
| Address guard, frame relay, IP classifier | T23.3.7 | `address.rs`, `frame.rs`, `relay.rs`, `client.rs`, `ip_class.rs` | **read in full** (`frame.rs` lengths and nesting) |
| §30 routes, console | T23.3.8 | `handlers/directory.rs`, `frontend/src/pages/directory/*` | **read in full** (handler); console targeted |
| Real-server e2e | T23.3.6 | `directory_e2e.rs`, compose, secrets script | read; **run** |
| Logging and test hygiene (CodeQL) | all | every added `tracing::` line, assertion and panic message, format argument, loop variable and literal in Rust and TypeScript tests | **every added line**, by script and by eye |

Tests ran against the in-memory SurrealDB harness, the in-process TLS test
directory, and — for the directory e2e — a real OpenLDAP and Samba AD DC in
Docker (§13).

---

## 2. P23W3-01 — linking left the account's federation links

**Severity: Medium. Fixed in `06d061b`.**

D-28's rule for linking is that everything the account holds that
**authenticates without the directory deciding** is retired, so that disabling
the person in the directory closes every way in. T23.3.3 retired passkeys,
`User` certificates, sessions and refresh tokens; T-336 recorded that set as
complete. A federation link — an upstream OIDC or SAML identity bound to the
account (`federation_link`) — is exactly such a credential: the federated
sign-in resolves the link to the account and opens a session. Passkeys were
deleted for the same reason; the link was simply not on the list. Between an
offboarding in the directory and the sync job's next run (up to 24 h for a
vanished entry), and indefinitely if the directory is later disabled
(P23W3-12), a linked account kept a sign-in nobody in the directory could see.

**Fix.** `retire_local_credentials` deletes every link of the account after the
passkeys and before the certificates, sessions and refresh tokens (sessions
stay last). A deleted link is not re-made at the next upstream sign-in: both
federated provisioning paths (`oidc.rs`, `saml.rs` `provision_or_link_*`) look
links up by external subject and otherwise *create* a new account — they never
link by name or address — so that sign-in collides with the existing account
and fails. The count is in `DirectoryLinkOutcome` and in the
`directory.account_linked` audit row; a failure is reported at the new
`federation_links` stage and is retried like the others. The REST response is
unchanged. Contract §30.3 rule 6, the operator guide, the design document, the
website and the console copy name the links.

**Test.** `p23w3_01_linking_removes_the_accounts_federation_links` failed before
the fix at "no federation link may outlive linking".

---

## 3. P23W3-02 — no counter for names AXIAM holds no account for (T-332)

**Severity: Medium. Fixed in `236ba35`; T-332 closed.**

With `jit_provisioning` on, `login_unknown_user` asks the directory about a
name no AXIAM account holds. The per-account counter that brakes T-302 has no
account to count against, so the login endpoint was a password-spraying relay
into the corporate directory for every never-signed-in user, bounded only by
the per-IP limits and whatever lockout the directory enforces (often none for
service-bound searches, and a lockout there is itself a denial of service on
the user).

**Fix.** `axiam_auth::unknown_name_lockout::UnknownNameLockout`, one per
process, shared by every clone of `AuthService`. It is keyed by tenant and the
login name as typed, trimmed and lower-cased; counts only failures the
directory decided (`InvalidCredentials` — a wrong password or no such entry; an
unusable directory counts against nobody, as for accounts); and applies **the
tenant's own lockout policy** with the shape `increment_failed_logins` gives an
account — locked at `max_failed_login_attempts`, for `lockout_duration_secs`,
growing by the backoff to the cap. A locked name is answered exactly as an
unknown user (dummy verify included) **without asking the directory**, even
with the right password; success clears it. It is bounded: at most 50 000 names,
idle entries forgotten after the maximum lockout (an hour at least), and a full
table makes room from the least recently failed *unlocked* name, so spraying
other names cannot free a locked one.

Why in memory and not in the shared rate-limit counter: `axiam-auth` (layer 1)
cannot reach `axiam-db`'s `SharedRateLimitCounter` without a new port, and the
per-process bound is the one the in-memory governor already accepts. Residual,
in T-332: N replicas give a name at most N × the policy per window; a restart
forgets it; whoever guesses at a name can lock it out of its first sign-in —
the account lockout's own trade-off.

**Tests.** `p23w3_02_guessing_at_an_unknown_name_stops_reaching_the_directory`
failed before the fix (the right password provisioned after three failures);
`p23w3_02_failures_below_the_threshold_still_provision`; four unit tests.

---

## 4. P23W3-03 — query values in the request log (T-325)

**Severity: Low. Fixed in `9528f91`; T-325 closed.**

`DefaultRootSpanBuilder` records `http.target` = path and query, verbatim, and
the JSON formatter prints a span's fields on every event inside it. T23.2.3
recorded the SAML continue `handle`, `RelayState` and `SAMLRequest` there. The
handle is bearer-ish but bound to a per-handle `HttpOnly` cookie, single-use
and ten minutes long, so the SAML half alone is Low; reading every route turned
up more: `/oauth2/authorize`'s `state` (the RP's CSRF token) and `login_hint`
(personal data), `end_session`'s `id_token_hint` (a signed JWT with claims),
the password-reset `token` and GDPR cancellation `token` in query strings, the
GDPR export token in the `/account/export/{token}` path, and administrators'
`search` terms. With the shipped `axiam=info` filter the span is recorded only
where an operator enables `tracing_actix_web` — which is what one does to get
request logs.

**Is the fix local and safe?** Yes. `RedactingRootSpanBuilder` records the
default's field set, span name **and target** (so `RUST_LOG` selects it exactly
as before), with `http.target` = `redacted_target(path, query, pattern)`: every
query value becomes `[redacted]` unless the parameter is on a short allow-list
of structural ones; names stay; a `{token}` route segment is redacted.
`on_request_end` delegates to the default. An allow-list, so a parameter added
later is redacted by default. It reads one header, `User-Agent`, as before; the
W8 pin that guarded "no Authorization header in the request log" now pins the
new builder and its single header read.

**Tests.** Three in `request_span::tests`, the last running a request through
`TracingLogger` with a capturing subscriber; `t9_4_…` failed before the server
was rewired.

---

## 5. P23W3-04 — the guard's answers were an internal-DNS oracle (T-356)

**Severity: Low. Fixed in `03e9066`; T-356 added (Mitigated).**

`write_config` answered a guard refusal with the guard's own sentence and
audited its specific rule. For a host **name**, "could not be resolved" versus
"resolves to a private address outside the deployment's allowed networks" (or
loopback, link-local, metadata, own listener) tells a tenant administrator —
in a multi-tenant deployment, a customer — which names exist in the
deployment's resolver and where they point
(`postgres.default.svc.cluster.local` → private), thirty times a minute, with
the specific rule repeated in an audit log the same administrator can read.

**Decision: unify, rather than extend T-300's residual.** For a host name every
resolution-dependent refusal is one message and one audit rule,
`address_guard.not_permitted`; the specific rule goes to the operator's log. An
IP literal, an IPv6 literal and an unparseable URL keep their specific answers
— they reveal nothing the administrator did not type. The cost is an
administrator who cannot tell a typo from an unlisted network; the message says
to check both, and the operator's log says which. D-33 is untouched. What a
*successful* write reveals (the name resolved into a permitted range) is
inherent and is T-356's residual.

**Test.** `p23w3_04_a_refused_host_name_gets_one_answer_whatever_it_resolves_to`
failed before the fix (four names, four answers). Contract §30.3 rule 1 amended
in place (1.54 unreleased; status and code unchanged).

---

## 6. P23W3-05 — the lost race mapped groups before the status check

**Severity: Informational. Fixed in `db3d5f0`.**

Item 8. In `provision_directory_account`'s `AlreadyExists` branch the loser
continues with the winner's account, and the mapping ran before
`complete_authenticated_login` checked its status. An account deactivated in
between had directory memberships re-added and was then refused. Nothing was
granted (an `Inactive` account acts nowhere), but a write for an account that
may not act is the wrong order. The status is now checked first, with the same
error. **Test:** `p23w3_05_a_lost_race_to_an_inactive_account_maps_no_groups`
(a repository that plants an `Inactive` winner between the probe and the
create) failed before the fix.

---

## 7. The D-23 fix (`c3db35c`) — reviewed adversarially (item 4)

**Verdict: sound.** The probes, each against the code as merged:

* **First-signature-only (the original bug).** `reduce_xml_to_signed` walks
  **every** `ds:Signature` (`find_signature_nodes`) and verifies each with its
  own `XmlSecSignatureContext` against the configured certificate only — the key
  is set as the context's `signKey`, so `KeyInfo` is never consulted. Any
  unverifiable signature fails the whole document.
* **Placement.** `check_signature_placement` finds `Signature` elements in
  **any** namespace by local name and refuses a non-DSig one outright; a DSig
  one must be the direct child of the `samlp:Response` root (namespace-checked)
  or of a `saml:Assertion` (namespace-checked) that is the root's child; one per
  parent; exactly one `SignedInfo/Reference`, `URI="#<parent ID>"`, parent `ID`
  non-empty. Signatures nested in `ds:Object`, `Extensions`, `Advice`, a sibling
  of the assertion, or a second one in a parent are refused. The root must be a
  `samlp:Response`, so a signed `LogoutResponse` cannot be the document either.
* **Reference resolution and duplicate IDs.** `collect_id_attributes` registers
  every `ID` attribute and refuses a duplicate or a non-`NCName` value before
  xmlsec resolves `#id`, so "the parent's ID" names exactly one element. A
  namespaced `foo:ID` is read by both `xmlGetProp`-based lookups (placement and
  registration) while serde reads only `ID`; if both are present and differ, the
  binding step's `assertion.get_attribute("ID") == claimed_assertion_id` fails
  closed.
* **The consumed assertion.** Exactly one element with local name `Assertion`
  in the document; it must be the root's child, carry the deserialised ID and
  its own enveloped signature referencing it. An assertion in another namespace
  that serde binds could carry no admitted signature (placement requires the
  SAML namespace), so it is refused.
* **Response-only signed.** Still refused (the assertion must carry its own
  signature) — strict, as before; interoperable with every IdP that signs
  assertions, which is the default of the major ones.
* **`PreDigest`.** With one signature the single pre-digest payload is returned;
  with two (Response + Assertion) exactly one response-rooted payload is
  required. The returned payload is discarded and the original document is
  deserialised — safe because every admitted signature covers its whole parent
  under the enveloped transform and the IdP chose the transforms (they are inside
  the signed `SignedInfo`).
* **Parser differential.** `quick-xml 0.41` concatenates text across comments
  and processing instructions (`drain_text`), so the comment-truncation class
  (`user@evil<!---->.example`) does not apply; libxml with default options does
  not substitute entities, and exclusive c14n of an entity reference fails, so
  an internal-entity trick fails closed. That the SP accepts a DTD at all, and
  `rsa-sha1`, is P23W3-08 — hardening, not a bypass.
* **Siblings.** There is no SP-side SLO; the IdP's own output check
  (`sign::verify_output`) uses the same per-node primitive; the IdP receiver
  (`request.rs`) has its own placement rule (one enveloped signature on the root,
  DSig namespace) and restricts algorithms to SHA-2. IdP metadata is not signed
  at all (P23W3-07).

The issue body (to file after the fix reaches `main`) and the maintainer note
are in §14.

---

## 8. SAML IdP — registry, credential, issuance, SSO endpoint, CSP

Probes that did not yield:

* **SP selection and signatures.** The SP is chosen by issuer within the path's
  tenant; a registered certificate means every signature is checked whether or
  not signing is required, and a signed request from an SP with no certificate is
  treated as unsigned (D-26). A Redirect-binding document carrying an enveloped
  signature is refused; the Redirect signature is over the octets received
  (`RedirectQuery` keeps them percent-encoded).
* **ACS redirection (T-318).** The ACS is resolved against the registration
  only (by URL, by index, or default; both is malformed) and re-checked by
  `check_acs_url`; non-POST bindings are refused; refusals before that point are
  error pages that post nowhere; policy refusals after it post unsigned
  status-only failures to the registered ACS.
* **Replay and the handle (T-319, T-322, T-330).** `replay_key` is UNIQUE per
  tenant and consumed rows outlive the `IssueInstant` window; the handle is 256
  bits, stored as its digest; the continue leg requires the per-handle
  `HttpOnly; Secure; SameSite=Lax` binding cookie (constant-time) **before** it
  reads a session or consumes anything, so a leaked or logged handle is worthless
  in another browser; `consume` on the X6 arbiter decides single use.
* **Session resolution (T-328, item 13).** The OP cookie is resolved through the
  tenant-keyed digest lookup, expiry filtered in the repository, then
  `check_session_holder` → `account_may_act` — the same as `/oauth2/authorize`;
  `PendingVerification` is served (T-160), suspended statuses are not.
* **`ForceAuthn` (T-323)** is bound to the row's `created_at`; a forged hop
  marker lands on `AuthnFailed`. `IsPassive` never hops.
* **IdP-initiated (D-26).** Refused for `Sec-Fetch-Site: cross-site`; a browser
  that sends no fetch metadata is admitted (accepted in D-26).
* **`return_to`.** The SAML arm is one exact path per call, server and SPA, the
  T23.1.3 audit list re-run against it.
* **D-27 CSP (item 2).** The auto-post page's policy is `default-src 'none';
  script-src 'nonce-…'; form-action <ACS origin>; frame-ancestors 'none';
  base-uri 'none'` — narrower than the global policy in every directive but
  `script-src` and `form-action` (`object-src`, `style-src`, `img-src` fall
  back to `'none'`); the origin comes from `url::Url::origin`, so it cannot
  carry `;` or a newline. It is the **only** setter in the crate (grep). Both
  facts are now pinned (`4acc49d`): a source-scan test fails the day a second
  file names the header, and a unit test pins the five directives.
* **Rate limiting (item 14).** The three SSO routes carry a per-route governor
  and their own shared buckets (`end_session_per_min`); the directory writes
  carry `directory_admin`. Directory reads are unlimited, as other
  authenticated administrator reads are. `/oauth2/authorize` has no limiter
  (P23W3-09, pre-existing).
* **Credential custody (D-21).** The key is sealed through the database
  custodian, selected only by `get_active_sealed`, destroyed on retire, decoded
  into `Zeroizing` buffers; `SamlSigning` is refused by issuance, CSR signing,
  bind, device login and mTLS; failure responses are never signed.

---

## 9. Directory — JIT, linking, mapping, sync, guard, relay, routes

Beyond P23W3-01, -02, -04, -05, probes that did not yield:

* **`account_may_act` on the new session paths (item 13).** JIT and directory
  sign-in go through `complete_authenticated_login`'s `check_user_status` — the
  new-sign-in rule, stricter than `account_may_act`, which is right for a fresh
  password sign-in (T-160 is about *existing* credentials; JIT accounts are
  `Active`). Linking creates no session. Sync's `Inactive` is refused by the OP
  cookie (`account_may_act`), passkey sign-in (`ensure_can_sign_in` on the
  discoverable path, the password step on the other), the OAuth2 grants and
  federated sign-in (P23W1-01/-04). `PendingVerification` is never refused by
  `account_may_act`.
* **Mapping (D-30).** Removes before it adds, owns only `source = directory`
  edges, fails closed, flushes the decision cache locally and by broadcast
  (sibling check: the sync job's membership removal goes through the same mapper
  and therefore the same flush; the admin API's own `add_member`/`remove_member`
  already flush — `invalidate_subject`/`invalidate_tenant` in `handlers/groups.rs`).
  The P23W2-01 rule sits at the API and at the repository's
  `WHERE` (one statement).
* **Address guard and relay (T-300, T-331, item 12).** One classifier for every
  guard (IPv4-mapped, 6to4, NAT64 and `::/96` embeddings folded); resolve once,
  connect to the vetted `SocketAddr`, TLS name the URL host; the relay checks the
  declared length (≤ 4 length octets, header included in the cap) before
  allocating, refuses indefinite lengths and multi-octet tags, bounds nesting.
  Sibling sweep: every other outbound HTTP fetch uses `guarded_fetch`; the
  **tenant email provider does not** (P23W3-11, pre-existing).
* **Delete/disable (item 6, P23W3-12)** and **replicas (item 9, P23W3-13)**:
  §11.

---

## 10. Logging and test hygiene (CodeQL) — item 11

Every added line of the wave diff in Rust and TypeScript was scanned by script
(format arguments and named fields in `tracing`, `assert*`, `panic!`,
`expect`, `format!`; loop variables; `let` bindings named `secret`, `key`,
`password`; PEM blocks; byte-array literals of key length; JSON password
fields) and the hits read by eye. Fixed in `82bc6a0`: a hard-coded
`PairwiseKey::new([7; 32])`; an Ed25519 JWT pair as PEM literals in the new
`directory_provisioning_test.rs` (now generated with `rcgen`); key-named
bindings that flow into assertion arguments (`saml_idp::tests`), two
`let mut key = [0u8; 32]` buffers and a `for key in` loop. No added `tracing`
line formats a password, secret, cookie, handle, token, DN or attribute value
(the handlers log tenant, SP record id, fixed reasons and error kinds). The
TypeScript tests mint bind values at run time and log nothing. The tests this
review adds name their cases and format no sensitive value.

---

## 11. Verdicts on the orchestrator's items

1. **T-325 — fixed** (P23W3-03). Local (one builder, one `wrap`), safe (same
   fields, name and target; only values change), and it closes more than the
   SAML half. The continue handle alone would have been an acceptable Low (cookie
   binding, single use, ten minutes); the pre-existing reset token and
   `id_token_hint` were not.
2. **D-27 — confirmed and pinned** (`4acc49d`). Strictly narrower but for the
   two directives D-27 names; the only CSP setter.
3. **IdP metadata signatures — Low, pre-existing, absent control; reported**
   (P23W3-07). The SP pins the signing certificate in its configuration and never
   takes it from metadata, so a forged metadata document cannot forge
   assertions; what it controls is the `AuthnRequest` destination (a phishing
   redirect) and the binding, behind HTTPS and the SSRF guard. Metadata is also
   fetched on every SP-initiated sign-in, uncached.
4. **D-23 — sound** (§7). Issue body and maintainer note in §14.
5. **T-332 — fixed** (P23W3-02) with a local, bounded counter on the tenant's
   policy; per-process residual stated.
6. **Delete/disable — accepted as documented** (P23W3-12). Refusing would block
   incident response (D-33's point), deactivating on delete would lock every
   directory user out of a reconfiguration with no re-enable (D-31: sync never
   re-enables), and the remaining credentials are AXIAM-side ones an
   administrator controls. Contract §30.3 rule 5, the operator guide and both
   console dialogs say so, and the audit row carries the live-account count. The
   console's *disable* warning said passkeys "keep working until they expire";
   passkeys do not expire — corrected to "until you deactivate the accounts".
   Candidate for W4/G-6: an optional "deactivate its accounts" on delete.
7. **Guard error text — fixed** (P23W3-04, T-356), not left in T-300's residual.
8. **JIT lost race — fixed** (P23W3-05), trivially.
9. **No multi-replica guard — accepted** (P23W3-13). Sync writes are
   idempotent or compare-and-set from a live status; duplicated reads and audit
   rows are the cost; reports of already-`Inactive` accounts are once per state
   change (deduplicated in the state row) and change nothing. A lease belongs to
   G-8's deployment-profile work, for every sweep at once.
10. **Certificates not bound to users — reported** (P23W3-10), as D-29 decided.
11. **CodeQL hygiene — fixed** (§10, `82bc6a0`).
12. **Siblings.** D-23's rule: IdP side consistent; pre-existing SHA-1/DTD on
    the SP is P23W3-08. Address guard: the email provider is P23W3-11. Frame
    relay: no other `ldap3` stream. CSP: one setter, pinned. Decision-cache flush:
    the sync path inherits it through the mapper. P23W2-01 at the API: the email
    configuration's sibling is the already-filed #525. Linking's revocation set:
    federation links were the miss (P23W3-01).
13. **`account_may_act`** — applied on every new session→principal path (§8,
    §9); never refuses `PendingVerification`.
14. **§7 rule 6** — the SSO routes and the directory writes are limited;
    `/oauth2/authorize` is not (P23W3-09, reported).
15. **Anything else** — P23W3-11 (email provider SSRF class) and P23W3-14 (D-25
    × directory-supplied addresses, accepted).

---

## 12. Threat-model reconciliation

Model **2.24.0** (from 2.23.0), each change in its fixing commit, all three
artifacts and the website regenerated together
(`node website/scripts/gen-threat-model.mjs` → *356 threats (340 mitigated, 16
open)*, no diff left):

| Change | Entry | Commit |
|---|---|---|
| Linking deletes federation links | **T-336** amended (description, mitigation, test) | `06d061b` |
| Unknown-name lockout | **T-332** Open → Mitigated; T-302's pointer updated | `236ba35` |
| Redacting request span | **T-325** Open → Mitigated | `9528f91` |
| One answer for host names | **T-356** added (Directory sign-in, I, Low, Mitigated); T-300 points to it | `03e9066` |

Every W3 surface maps to an element and entries: the SSO endpoint and
`saml_authn_request` (T-317 … T-330), the issuer and credential store (T-304 …
T-316), the directory connector, sync job and stores (T-291 … T-356). The SP
registry store and the §29 management routes get their element with T23.2.5
(no route exists yet). The §30 management routes act through the *Directory
sign-in* process's guard and the `directory_config` store (T-298, T-300, T-356).
Counts: STRIDE category *Information disclosure* 81, severity *Low* 17 (1 open),
*Medium* open 5, diagram *Federation* 97 threats / 4 open, open register 16.
Reported findings (P23W3-07 … -11) are pre-existing; their entries should be
amended when they are fixed.

---

## 13. Checks run

All exit codes were captured from cargo itself (log plus `$?`).

```bash
export CARGO_INCREMENTAL=0
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
# before the fixes — each new test failed:
cargo test -p axiam-auth --test directory_provisioning_test        # 17 passed, 3 failed (P23W3-01, -02, -05)
cargo test -p axiam-api-rest --test client_secret_basic_test t9_4  # 1 failed (P23W3-03 pin)
cargo test -p axiam-api-rest --test directory_config_test p23w3_04 # 1 failed (P23W3-04)
# after:
cargo fmt --all --check                                             # clean
cargo clippy -p axiam-auth -p axiam-core -p axiam-db -p axiam-directory \
  -p axiam-federation -p axiam-api-rest -p axiam-server --all-targets -- -D warnings   # clean
cargo clippy -p axiam-federation -p axiam-api-rest -p axiam-server \
  --all-targets --no-default-features -- -D warnings               # clean
cargo test -p axiam-auth --test directory_provisioning_test        # 20 passed
cargo test -p axiam-auth --lib unknown_name_lockout                # 4 passed
cargo test -p axiam-auth --test directory_account_test             # 12 passed
cargo test -p axiam-api-rest --test directory_config_test          # 28 passed
cargo test -p axiam-api-rest --test client_secret_basic_test t9_4  # 2 passed
cargo test -p axiam-api-rest --lib -- request_span security_headers saml_idp   # 9 passed
cargo test -p axiam-core --lib saml_signing                        # 2 passed
cargo test -p axiam-db --test directory_group_mapping_test         # 13 passed
cargo test -p axiam-directory --test group_mapping_test            # 14 passed
cargo test -p axiam-federation --lib saml_idp                      # 58 passed
(cd frontend && npx vitest run src/pages/directory)                # 60 passed
AXIAM_E2E_DIRECTORY=1 cargo test -p axiam-server --test directory_e2e   # see below
python3 scripts/check-crate-layering.py                            # OK, 19 crates
scripts/check-doc-links.sh                                         # OK
python3 scripts/check-frontend-coverage.py                         # OK, 43 modules
python3 scripts/check-config-key-coverage.py                       # OK
node website/scripts/gen-threat-model.mjs                          # 356 threats (340 / 16), no diff
```

The intermediate commits `06d061b` and `db3d5f0` were each compile- and
clippy-checked in their own state (`cargo clippy -p axiam-auth --tests`).
**Directory e2e:** run after all five fixes against the real OpenLDAP and
Samba AD DC (`scripts/gen-directory-e2e-secrets.sh`, `docker compose -f
docker/docker-compose.directory.yml … up -d --wait`, torn down with `down -v`):
**18 passed** — JIT, mapping, nesting, the disabled account, the seven injection
payloads, the config-time refusals (by status), StartTLS and sync, unchanged by
the unknown-name lockout and the unified guard answer. **Spec:**
`cargo build -p axiam-server --no-default-features`, `--dump-openapi`,
`check-spec-digest.py` and `gen-management-registry.py --check` pass after
`3d58a46`. Not run: the conformance suite (no network).

---

## 14. Issue bodies for the reported findings

### P23W3-06 (Critical) — file **after** the D-23 fix is on `main`

**SAML SP: signature confusion let a document the IdP signed for another
purpose vouch for a forged assertion (fixed in Phase 23 W3, D-23).**
`SamlFederationService::handle_saml_response_for` verified the response with
`samael`'s `verify_signed_xml`, which verifies only the **first** `ds:Signature`
in document order, and `bind_signature_to_assertion` accepted **any**
`Reference` naming the assertion, verified or not. A response containing a
document the upstream IdP had genuinely signed with its assertion key for
another purpose — a signed `LogoutRequest`, `LogoutResponse` or error
`Response` placed in `Extensions`, beside the assertion or in its `Advice` —
ahead of a forged, dummy-signed assertion passed both checks, and the ACS signed
in (or just-in-time provisioned) whatever subject the forged assertion named.
Precondition: the attacker holds any message the tenant's IdP signed with its
assertion key (logout traffic is the usual source); no IdP credential is needed.
Affected: every AXIAM release that shipped SAML federation up to and including
1.0.0-beta17. Fixed by `c3db35c`: a `ds:Signature` is accepted only as the
enveloped child of the `Response` root or of its `Assertion`, at most one per
parent, each referencing its parent's `ID`; any other `Signature` element
refuses the document; every signature is verified on its own node against the
configured certificate; IDs must be unique `NCName`s; the consumed assertion
must carry its own verified signature. Tests:
`a_signed_assertion_free_document_cannot_vouch_for_a_forged_assertion`,
`no_signed_gadget_vouches_for_a_forged_assertion_wherever_it_is_placed` (27
placements), `a_valid_response_with_an_extra_unsigned_signature_is_refused`.
Workaround for deployments that cannot upgrade: disable SAML federation
configurations, or have the IdP sign logout and error messages with a key other
than the assertion key. T-67 amended.

**Maintainer note (not for publication).** The probe test describing the
attack sat on a public branch before the fix (D-23's reason for fixing in W3),
so the window is open now. Recommended: (1) cut a patch release of the current
line (1.0.0-beta17 → beta17.1 or beta18) carrying only `c3db35c` and its tests
as soon as W3 merges, rather than waiting for the phase; (2) publish a GitHub
Security Advisory (GHSA) with a CVE request, CVSS 3.1 about 9.1
(`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`, an authentication bypass with a gadget
precondition), crediting the internal review; (3) file the issue above only
after the advisory is published or the patch is out, linking it; (4) the SDKs
are unaffected (no SDK verifies SAML), so no SDK release is needed; (5) operators
need rotate nothing, but should review the audit log for SAML-federated
sign-ins and just-in-time provisioned accounts whose subject had never signed in
before, since the fix cannot detect past use. Nothing has been published by this review.

### P23W3-11 — filed as ilpanich/axiam#529 (Medium) — the tenant email provider is held to no outbound address policy

`EmailConfigOverride.provider` at tenant scope lets a tenant administrator
(`email_config:write`) set an SMTP `host`/`port` or an HTTP provider's
`api_url`; `axiam-email` connects to them with `lettre`'s `relay` /
`starttls_relay` and `reqwest` directly — no `guarded_fetch`, no
`axiam_core::ip_class` check — and `POST /api/v1/tenants/{t}/email-config/test`
does it on demand, answering with the provider's error. That is T-300's class
for email: a tenant administrator can make AXIAM open TCP connections to
loopback, link-local (the metadata service) and private addresses, send an SMTP
`EHLO`/`STARTTLS` or an HTTP `POST` carrying the provider API key there, and
read connect/refuse/timeout differences from the error. Proposed: run the
directory guard's rule (resolve once, refuse loopback, link-local, metadata,
unspecified, multicast, special-purpose, own listeners; private only inside an
operator allow-list) on save and at connect, pinning the vetted address; send
`api_url` through `guarded_fetch`; make the test endpoint's error generic for
resolution-dependent refusals (the P23W3-04 lesson); rate-limit the test route.
Tests: each refused class at save and at send, rebinding, the test endpoint's
answer.

### P23W3-07 — filed as ilpanich/axiam#530 (Low) — IdP metadata is neither signature-checked nor cached

`SamlFederationService::fetch_idp_metadata` fetches the IdP's metadata over
HTTPS through the SSRF guard and uses its entity ID, SSO URL and binding; it
never checks a metadata signature, and `build_authn_request` fetches it on
every SP-initiated sign-in. The assertion signing certificate is pinned in the
federation configuration and never taken from metadata, so a forged metadata
document cannot forge assertions — but whoever can serve it (a compromised or
re-pointed metadata host) chooses the HTTPS URL users are redirected to with
the `AuthnRequest`, a phishing redirect, and every sign-in depends on the
metadata host being up. Proposed: an optional metadata signing certificate on
the configuration (verified with the same per-node primitive as D-23, placement
on the `EntityDescriptor` root only), refuse an unsigned document when one is
set; cache the parsed metadata honouring `validUntil`/`cacheDuration` with a cap;
audit a change of SSO URL host. Tests: a signed, an unsigned and a tampered
document; the cache hit.

### P23W3-08 — filed as ilpanich/axiam#531 (Low) — the SP verifier accepts SHA-1 and DTD-bearing responses

The IdP receiver added in W3 restricts XML signatures to SHA-2
(`reduce_xml_to_signed_with_allowed_algorithms`) and refuses any document
carrying a `<!DOCTYPE`/markup declaration on the bytes; the SP verifier, which
D-23 rewrote, calls `reduce_xml_to_signed` without an algorithm list (so
`rsa-sha1` signatures verify) and parses `SAMLResponse` with libxml defaults and
`quick-xml` without refusing a DTD. Neither is exploitable today (entities are
not substituted and c14n refuses entity references; a SHA-1 collision would need
the IdP to sign attacker-prepared content), but both are the hardening the
receiver already has. Proposed: pass the receiver's allow-list (or the
configuration's, defaulting to SHA-2) and refuse markup declarations before
parsing, both in `handle_saml_response_for`; document the SHA-1 refusal as a
behaviour change for IdPs still signing with it. Tests: a SHA-1-signed valid
response refused, a DTD-bearing response refused before parsing.

### P23W3-09 — filed as ilpanich/axiam#532 (Low) — `/oauth2/authorize` has no rate limiter

`server.rs` mounts `/oauth2/authorize` (bare and per-tenant) with no governor
and no `RateLimitShared` bucket; T23.2.3 found it when the preset the plan
named for SAML did not exist. Every request reads the client and, with a
cookie, the session and the account; for a CIMD-enabled tenant a novel
URL-shaped `client_id` triggers an outbound fetch until `dcr_max_clients`.
Plan §7 rule 6 ("a limiter that forgets a route is the Keycloak 26.7 lesson")
applies. Proposed: wrap both mounts with the browser-endpoint preset
(`end_session_per_min`, as the SAML SSO routes are) under a bucket of their own,
`oauth2_authorize`; pin it with a `429` test on both mounts; record it in
`rate-limit-sizing.md`.

### P23W3-10 — filed as ilpanich/axiam#533 (Low) — bind certificates to users (D-29 follow-up)

No certificate row carries a user: a certificate authenticates as the service
account it is bound to, and directory linking (D-28) revokes a user's `User`
certificates by convention (`metadata.user_id`, or a subject CN equal to the
username or email, ignoring case), over-matching on purpose. Proposed: an
optional `user_id` on `certificate` (schema migration, set by issuance and CSR
signing for `User` certificates, an SDK-visible field and contract text),
revocation by `user_id` in linking, user deletion and erasure, and the
convention kept only for rows issued before the migration. Tests: linking
revokes by `user_id` and leaves a same-CN certificate of another user alone.

---

## 15. What W4 must take from this review

* **T23.2.4 (SLO).** AXIAM will sign `LogoutRequest`/`LogoutResponse` — the
  exact gadget D-23 defends against at every SP, AXIAM's included. Sign logout
  messages with the IdP credential only if the SP side's placement rule is in
  every consumer AXIAM controls (it is); verify an SP's signed logout messages
  with `request.rs`'s placement rule and `verify_post_signature` (SHA-2 only,
  per node) and the Redirect signature over the received octets — **never**
  `verify_signed_xml`. Decide T-312 (`SessionIndex` per SP). SLO routes get
  their own rate-limit buckets (§7 rule 6) and the D-20 `404`.
* **T23.2.5 (SP registry routes, metadata).** Refuse `encrypt_assertions`
  while D-2's encryption is unimplemented, and a signing SP whose certificate
  does not parse; SP metadata import must go through `guarded_fetch` and should
  not trust an unsigned document for anything security-bearing; the IdP metadata
  endpoint needs the D-20 `404` and a limiter. The SP registry store gets its
  threat-model element in the commit that adds the routes.
* **CSP.** A second page that sets its own policy must update
  `exactly_one_handler_sets_its_own_policy` and prove itself narrower (D-27).
* **Logging.** New query parameters are redacted by default; adding one to
  `KEPT_QUERY_PARAMETERS` needs a reason. A new route carrying a bearer value in
  its *path* needs its parameter named `{token}` or added to
  `REDACTED_PATH_PARAMETERS`.
* **Directory.** If a shared counter becomes reachable from `axiam-auth`
  (G-8's profile work), move the unknown-name lockout onto it to remove the
  per-replica multiplier. An optional "deactivate its accounts" on directory
  delete (P23W3-12) is a candidate, not a precondition.
* **File** P23W3-07 … -11 before the phase PR merges; file P23W3-06 only after
  `main` carries `c3db35c` and the maintainer has decided on the advisory.
* **New threat ids** start at **T-357**.

## 16. Invariants

I1 (nothing registered today changes behaviour) holds with these deliberate,
CHANGELOG-recorded changes: a directory link now also deletes the account's
federation links (`06d061b`); a name with no AXIAM account that has failed the
tenant's lockout threshold against the directory is answered as an unknown user
without the directory being asked, until the lockout expires (`236ba35`); the
request tracer's `http.target` carries `[redacted]` for every non-structural
query value and for the export token's path segment (`9528f91`); a §30 write
refused for what a host *name* resolved to gets one message and the audit rule
`address_guard.not_permitted` (`03e9066`); JIT's lost race refuses an inactive
winner before mapping (`db3d5f0`, same answer). Contract 1.54 (unreleased) is
amended in place in §30.3 rules 1 and 6 — no shape, status or code changed; the
OpenAPI description of `link_account` names the links (spec regenerated); no
SDK-visible field changed.
