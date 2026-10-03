# Security review — Phase 23, wave W2 (F4)

**Date:** 2026-10-03.
**Against:** `claude/phase23-w2`, the whole wave diff `6181c05..debb2c2`
(116 files, about 19 100 lines added; `6181c05` is the W1 merge on `main`).
The two fixes of this review sit on top: `f1f8e00`, `b6e7577`.
**Scope:** the W2 tasks of
[`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md):
T23.1.4 (honour-lane audit, D-12, D-14), T23.1.5 (X7.7/X7.8 audit, the Basic
rate-limit key, D-17), T23.1.6 and T23.1.7 (conformance documents,
`report.py`, `export-evidence.py`), T23.1.8 (D-11 per-tenant OP cookie, D-16
logout hop — the new inbound surface), T23.3.1 (`axiam-directory`,
`DirectoryConfig`, schema v70, D-15) and T23.3.2 (the LDAP client, the
directory login path, the D-18 marker, schema v71, the local-password
refusals — the new outbound surface, and where most of the weight of this
review sits).
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) (T-30,
T-39, T-160, T-237, T-238, T-239, T-253, T-290 … T-303) and the OWASP ASVS 5.0
areas the diff touches (V6 authentication, V7 session management, V10 OAuth
and OIDC, V11 cryptography, V12 secure communication, V13 configuration, V16
logging). Every finding fixed here has a test that failed before the fix. A
claim with no test says so.

---

## 0. Summary

Two findings were fixed on the branch, both in T23.3.1's storage layer and
both wave-introduced. The weightier one (P23W2-01) is the classic directory
connector mistake — **a write-only secret that survives a change of where it
is sent is not write-only** — and it was not only present but pinned by a test
as intended behaviour. No route writes a directory configuration yet, so it
was latent; T23.3.8 would have exposed it to every tenant administrator.

The T23.1.8 surfaces (per-tenant cookie, logout hop) and the T23.3.2 login
path held: no cross-tenant, cross-user or takeover path was found, and the
directory login path is refused, counted and equalised as its threats claim.
What W2 leaves open is concentrated where W3 will build: the directory host is
not address-guarded (T-300) and `ldap3` has no frame cap, both harmless while
nothing can write a configuration and both blockers for T23.3.8.

| ID | Finding | Severity | Surface / threat | Disposition |
|---|---|---|---|---|
| **P23W2-01** | `DirectoryConfigRepository::update` kept the stored bind secret whenever no new secret was sent, whatever else changed. Repointing the URL (with one's own CA as the anchor) would have delivered the write-only secret to that host in the next service bind; a test pinned the URL change as intended. Latent: no write route exists until T23.3.8. | **Medium** | `directory_config`; T-298, D-15 | **Fixed** — `f1f8e00` |
| **P23W2-02** | The tenant delete, made a two-statement transaction by T23.3.1, never checked the response: a rolled-back delete answered `Ok`, the handler answered `204` and audited "tenant deleted" for a tenant that still existed, ciphertext included. | Low | `DELETE /api/v1/organizations/{org}/tenants/{t}`; T-298 | **Fixed** — `b6e7577` |
| **P23W2-03** | A `require_par` client's unpushed request from an anonymous `browser_sso` browser takes the login hop and is refused only after sign-in. Nothing is issued. (Item 1.) | Low | `/oauth2/authorize`; T-238, FAPI 2.0 §5.3.1.2 | **Reported** (pre-existing), ilpanich/axiam#524 |
| **P23W2-04** | Tenant deletion cascades to nothing but `directory_config`: users (hashes, MFA secrets, personal data), sessions, OAuth2 clients and refresh tokens, federation and email configuration (SMTP ciphertext), webhooks and CA material survive. The handler's comment says the audit trail "went with it"; it did not. (Item 5.) | Medium | Tenant lifecycle; GDPR Art. 17, T-118 | **Reported** (pre-existing), ilpanich/axiam#523 |
| **P23W2-05** | P23W2-01's sibling in `email_config`: saving an SMTP provider without re-typing the password keeps the stored one while the host changes, so the SMTP `AUTH` goes to the new host. | Low | `email_config`; SMTP secret | **Reported** (pre-existing), ilpanich/axiam#525 |
| **P23W2-06** | Discovery publishes no `revocation_endpoint_auth_methods_supported` / `introspection_endpoint_auth_methods_supported`; RFC 8414 then defaults both to `client_secret_basic` alone. (Item 3.) | Informational | Discovery; interop | **Reported** (pre-existing), ilpanich/axiam#526 |
| **P23W2-07** | A phone number replaced through SCIM keeps `phone_number_verified_at`. Latent: nothing sets it today. (Item 3.) | Informational | SCIM; X7 G8 | **Reported** (pre-existing), ilpanich/axiam#526 |
| **P23W2-08** | Logout-hop residuals: a hinted logout whose cookie names another session orphans that row; tenant copies outlive `tenant_issuer_paths` being turned off; non-canonical UUID spellings get no cookie; the hop now revokes the row a forged navigation's cookie names. (Item 2.) | Low | `/oauth2/authorize/logout`; T-290 | **Accepted residual** |
| **P23W2-09** | T-300: the directory host is not held to `guarded_fetch`'s address policy. Nothing can write a configuration today (no route, no writer in production code). (Item 6.) | Medium (latent) | Directory sign-in; T-300 | **Accepted residual** until T23.3.8, which must close it |
| **P23W2-10** | `ldap3`'s codec has no per-message size cap; a hostile directory can make one connection buffer what it sends within the 5 s operation timeout, in a process every tenant shares. Same "no writer today" bound. (Item 6.) | Low (latent) | Directory sign-in; T-295 | **Accepted residual** until T23.3.8, which must close it |
| **P23W2-11** | A directory sign-in costs `max(Argon2id, bind)`, so a directory account answers measurably later than a local or unknown one. (Item 6.) | Low | `/api/v1/auth/login`; T-301 | **Accepted residual** |
| **P23W2-12** | `export-evidence.py` builds file names from suite-supplied module names without sanitising them, and talks to `SUITE_BASE_URL` with verification off. (Item from T23.1.6.) | Informational | Maintainer tooling | **Accepted** |
| **P23W2-13** | T23.1.8's threat-model text landed in its third commit, not with the two code commits it describes (§7 rule 2). | Informational | Process | **Noted** (history is not rewritten) |

**Verdict on merge.** Nothing open blocks W2. Both fixes are in and pinned.
P23W2-04 (Medium) and P23W2-03 should be filed before the phase's PR merges
(issue bodies in §11); P23W2-03 is worth landing before the G-1 submission
because a reviewer reading the module log will see a sign-in precede the
refusal. P23W2-09 and P23W2-10 are not W2 defects — no configuration can be
written — but they are **binding preconditions on T23.3.8** (§12).

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Per-tenant OP cookie, mint/clear list | T23.1.8 | `middleware/csrf.rs` §`op_session_cookie_paths` and its callers in `auth.rs`, `webauthn.rs`, `federation.rs`, `opaque.rs` | **read in full** (diff) + every mint and clear site |
| Tenant-path resolution, `client_query_of`, stale-copy removal | T23.1.8 | `handlers/oauth2.rs` §`resolve_authorize_principal`, `middleware/tenant_path.rs` | **read in full** |
| Logout hop, bounce, `finish_logout` | T23.1.8 | `handlers/oauth2.rs` §`end_session`, §`end_session_at_cookie_path`, `server.rs`, `permissions.rs` | **read in full** |
| Org-level logout | T23.1.8 | `handlers/auth.rs` §`logout`, every `session_id` consumer | targeted, sibling sweep |
| Basic rate-limit key | T23.1.5 | `extractors/rate_limit.rs`, `middleware/rate_limit_shared.rs`, `client_secret_basic.rs` | **read in full** (diff) |
| D-17 | T23.1.5 | `fapi.rs`, `token.rs` (revoke, introspect), PAR handler; every `authenticate_client` call | **read in full** + sibling sweep |
| D-12, D-14 | T23.1.4 | `authn_params.rs`, `honour.rs`, `fapi.rs` | **read in full** (diff) |
| Conformance tooling | T23.1.6/7 | `conformance/scripts/export-evidence.py`, `report.py` | **read in full** |
| Directory model, repository, schema v70, cascade, key wiring | T23.3.1 | `axiam-core/models/directory.rs`, `axiam-db/repository/directory_config.rs`, `tenant.rs`, `schema.rs`, `main.rs`, `secrets.rs` | **read in full** |
| LDAP client, TLS, escaping, authenticator | T23.3.2 | `axiam-directory/src/{client,tls,escape,authenticator,config}.rs` | **read in full** (`config.rs` URL rules targeted) |
| Directory login path, marker, refusals | T23.3.2 | `axiam-auth/src/service.rs`, `password_reset.rs`, `axiam-db/repository/user.rs` §`mark_directory_account`, `opaque.rs`, `opaque_enrollment.rs`, `scim/users.rs`, gRPC `user.rs` | **read in full** + every `password_hash` / OPAQUE writer |
| Logging hygiene | all | every added `tracing::` line and every added assertion or panic message | **every line** |

Tests were run against the in-memory SurrealDB harness; no live stack, no
directory but the in-process test one, and no network.

---

## 2. P23W2-01 — a write-only secret that could be redirected

**Severity: Medium (latent until T23.3.8). Fixed in `f1f8e00`.**

D-15 makes the bind secret write-only: encrypted at rest, never returned by a
read, redacted from `Debug`, decrypted only at bind time. The point is that an
administrator who can edit the directory configuration cannot recover the
credential of the customer's directory service account — an account that can
read every user and group in the corporate directory, which an AXIAM tenant
administrator is not necessarily entitled to.

`SurrealDirectoryConfigRepository::update` took `bind_secret: None` to mean
"keep the stored ciphertext", and kept it **whatever else the update
changed**. The test `an_update_without_a_secret_keeps_the_stored_one` changed
the URL and asserted the secret survived. So an editor could save
`url = ldaps://collector.example`, `trust_anchors_pem = [their CA]`, no
secret; the next sign-in in that tenant would decrypt the stored secret and
send it, as the service bind, to their host — which presents a certificate
chaining to the anchor they chose, so verification succeeds. Disclosure by
redirection, past every read-path control. This is the shape of more than one
published LDAP-federation advisory in competing products, and the reason those
products now demand the credential again on a connection change.

No route writes a configuration yet (T23.3.8 adds them), and no production
code calls `create` or `update`, so nothing deployed was exposed. Fixed here
rather than handed to W3 because the repository is the one writer every future
route goes through, and the rule belongs at that layer, not in a handler that
might forget it.

**Fix.** Without a new secret, the `UPDATE` carries a guard in its `WHERE`:
`url`, `start_tls`, `bind_dn` and `trust_anchors_pem` must equal the stored
values. A guarded-out update changes nothing and is answered `Validation`
("…requires entering the bind secret again…"), naming the rule and none of
the values. The comparison and the write are one statement, so they cannot
race. With the secret re-entered the same change is an ordinary update.
`bind_dn` is in the set because a kept secret sent with another DN is a
credential tried against an account it was not entered for. The trait
documentation records the rule, and its `create` paragraph now names the
`Validation` error the implementation already returned for a missing key.

**Tests.** `directory_config_repository_test.rs::p23w2_01_moving_the_connection_requires_the_secret_again`
(another host, another port, StartTLS toggled, another bind DN, other trust
anchors — each refused, nothing changed, ciphertext untouched; then the move
with the secret accepted) failed before the fix on its first case. The pinning
test now changes `base_dn`, `enabled` and the nesting depth only.

---

## 3. P23W2-02 — a failed tenant delete answered success

**Severity: Low. Fixed in `b6e7577`.**

T23.3.1 made `SurrealTenantRepository::delete` a transaction —
`DELETE directory_config WHERE tenant_id = $id; DELETE type::record('tenant',
$id)` — so the two commit or roll back together, which is right: no
half-deleted tenant is possible. But the SurrealDB driver reports a failed
statement inside the `Response`, not from `.await`, and the response was not
checked (it had not been for the single statement before either, where a
failure was less likely). A rolled-back transaction therefore returned
`Ok(())`; `handlers::tenants::delete` answered `204` and wrote the
`tenant.deleted` record to the system audit log — the one record meant to
outlive the tenant — for a tenant that still existed with its encrypted bind
secret.

**Fix.** `.check()` on the response; a failure is an error and nothing is
recorded as deleted. **Test.**
`p23w2_02_a_tenant_delete_that_fails_is_reported_and_removes_nothing` defines
an event that `THROW`s on the directory row's deletion, asserts the delete is
an error and that the tenant and its configuration are both still there; it
failed before the fix. `tenant_test` (the HTTP surface) still passes.

---

## 4. T23.1.8 — the per-tenant cookie and the logout hop

Probes that did not yield, and the residuals of P23W2-08:

* **One list.** Every setter (`op_session_cookies`) and remover
  (`clear_op_session_cookies`, `clear_presented_op_session_cookie`) is built
  from `op_session_cookie_paths`; the setter that takes a path is private. Mint
  sites checked: password (`cookie_response_from_output`, also OPAQUE, MFA
  verify and forced enrolment), both WebAuthn ceremonies, the federation
  handoff (`issue_sso_session`). No other site sets `axiam_op_session`; the
  three API-cookie clear sites (`logout`, `finish_logout`, the CSRF
  middleware's own) either clear every copy or never touched it.
* **Tenant-keyed reads.** Both readers (`resolve_authorize_principal`, the
  hop) hash the cookie and look the digest up in the request's tenant; the
  shared value cannot name a session across tenants
  (`d11_a_tenant_cookie_never_resolves_on_another_tenants_path_in_either_direction`,
  `p23w1_10_the_cookie_hop_never_ends_another_tenants_session`).
* **Two tenant selectors.** `/t/A/oauth2/authorize/logout?tenant_id=B` is
  refused `400` by `TenantPathScope` (pinned). The percent-encoded spelling
  `tenant%5Fid=B` passes the scope's literal check, but the rewritten query
  then carries the field twice and `web::Query`'s derived deserialiser refuses
  a duplicate field — fail closed. No handler on the scope parses the query by
  hand (`form_urlencoded::parse` of the query string appears only in
  `dcr.rs`, for `access_token`). This last claim is from reading, not a test.
* **Open redirect.** The hop's continuation goes through the same
  `finish_logout` as `end_session`: exact match on the named client's
  `post_logout_redirect_uris`, the client looked up in the request's tenant,
  `state` echoed only on a redirect, nothing reflected (pinned by
  `p23w1_10_the_cookie_hop_validates_its_continuation_as_end_session_does`).
  The bounce's `Location` is built from the typed tenant and a constant path,
  never from the request.
* **Rate limiting (§7 rule 6).** The hop is the wave's only new inbound
  route; it carries a per-route governor and the shared
  `oauth2_end_session_cookie` bucket on both mounts (pinned, `429`).
* **Logout CSRF.** Claimed equal to `end_session`'s, and it is, with one
  honest difference: a forged top-level navigation to `end_session` (or the
  hop) now also **revokes** the row the browser's cookie names, where it used
  to clear the cookies only. Nobody but that browser can observe the
  difference — the row is reachable only through a cookie the same response
  removes, OAuth2 refresh grants do not depend on it since schema v68, and
  there is no back-channel fan-out — so the nuisance class is unchanged.
* **Org-level logout** (`principal_tenant_id`). Sibling sweep: the only other
  handler that uses the caller's own `session_id` with a tenant is
  `change_password`, which already used `principal_tenant_id`; the admin
  `revoke_all_sessions` calls act on a target in the acting tenant, correctly.
* **Accepted residuals (P23W2-08).** (a) A hinted logout ends the hinted
  session; a second session named by this browser's cookie loses its cookies
  and keeps its row, reachable only by a copy taken earlier (in T-290). (b) A
  tenant copy minted while `tenant_issuer_paths` was on survives the flag being
  turned off; its path is then unmounted, and the row it names is revoked by
  the next logout regardless. (c) Upper-case or unhyphenated tenant segments
  route but carry no cookie (cookie paths match byte for byte) and fail closed
  as `login_required`. None widens access.
* **I1.** `end_session` without a hint `sid` now answers a `302` to the hop
  first, then exactly what it answered before. A relying party following
  redirects (every browser) sees no difference beyond one hop.

---

## 5. T23.1.4 and T23.1.5 — the audits' fixes

* **D-12.** Essential `claims.id_token.auth_time` on `fapi2` is refused; a
  voluntary one is not; an *unreadable* member (`42`, `"yes"`, `[]`, an
  `essential` that is not a boolean) is treated as essential on `fapi2` only
  and is never a parse error, so the honour and ignore lanes are untouched. A
  real FAPI client sends well-formed JSON; the refusal of a malformed member
  is the rule an unreadable `acr` already follows. I1 holds.
* **D-14.** `max_age=0` folds into `asked_for_interaction`; the return leg
  issues a code whose `auth_time` is the hop's new authentication. A forged
  return-leg marker with `max_age=0` skips the interaction exactly as with
  `prompt=login` and no more: positive `max_age` values are still evaluated on
  the return leg, `auth_time` stays truthful, and `prompt=none` + `max_age=0`
  is `login_required`. P23W1-08 applies unchanged; nothing new opens.
* **`id_token_hint` without `iss`.** The hint must name the session's subject
  and the requesting client. User ids are globally unique UUIDs, so a hint
  minted in tenant B cannot name a session subject in tenant A even where a
  CIMD `client_id` (a URL) exists in both; with one signing key per deployment
  the `iss` comparison would add nothing. Confirmed.
* **D-17.** `enforce_client_authentication` runs after authentication at PAR,
  revocation and introspection, and is the first step of
  `enforce_token_request` (token grants, token exchange, UMA). Every
  `authenticate_client` call site was checked; the device authorization
  endpoint authenticates no client by design. Complete.
* **The Basic rate-limit key.** The header is decoded with the same function
  the handlers use; the form's `client_id` wins, as in `resolve_client_id`,
  and a request naming two ids is refused before a secret is compared, so a
  disagreement cannot charge guesses to another bucket. Rotating header ids
  buys exactly what rotating form ids always bought (D8's documented
  trade-off): fresh buckets for ids that do not exist, never a second budget
  against one real client. The parse is bounded by actix's header size limit
  (base64 and percent-decoding, linear). Accepted as designed, not a finding.
* **Discovery auth methods (P23W2-06), SCIM phone verification (P23W2-07),
  the admin API not writing phone/address.** The first two are reported
  below; the third is a plan divergence with no security effect (SCIM is the
  documented writer).

---

## 6. T23.3.1 and T23.3.2 — the directory

Probes that did not yield:

* **Filter injection (T-291).** One function puts a login name into a filter;
  it escapes RFC 4515's five octets and every byte outside printable ASCII;
  the template must carry exactly one placeholder (`replacen(…, 1)`, so a
  login name containing `{username}` stays literal); 256-byte cap. No DN is
  ever built; the user bind uses the DN the search returned, refused when
  empty (an empty DN with a password is an anonymous bind on some servers).
* **Transport (T-292, T-293).** Plaintext refused at save, at the
  authenticator and at `connect`; verification never disabled; per-tenant
  anchors are the whole trust store; the URL rules refuse userinfo (raw and
  parsed), path, query, fragment, whitespace. TLS 1.2 is the floor, a
  documented deviation from the project's TLS 1.3 rule (AD on Windows Server
  2019 and earlier), recorded in T-292 and the operator note.
* **Empty password (T-294).** Refused in `AuthService` before the
  authenticator, in the authenticator and in the client; the service bind
  refuses an empty stored secret too.
* **Exactly one entry, referrals (T-296).** References and intermediates
  skipped and never counted; the second entry stops the read; `sizeLimit 2`;
  `referral` results are `Misconfigured`. The hand-written BER parser is
  fallible at every step (no `SearchEntry::construct` panic).
* **Pool (T-295, T-297).** Two permits (tenant, global) with timeouts, so no
  deadlock; user-bound connections are never pooled; generation-keyed reuse.
* **Login path (T-301, T-302, T-297's entry binding).** Lockout before the
  directory; status and empty password refused with the equalising verify and
  no bind; failed binds counted, unusable directories not; the returned
  identifier must equal the marker (renaming a directory account's AXIAM
  `username` through SCIM or the admin API therefore buys nothing — the bind
  resolves the other entry and is refused, counted); MFA policy applies after
  the bind; no fallback to the local hash anywhere.
* **The marker (D-18).** `mark_directory_account` sets the marker, replaces
  the hash with an Argon2id hash of 32 random bytes and deletes the OPAQUE
  record in one transaction, tenant-scoped on both statements (the `user_id`
  column of `opaque_credential` is the string form the `DELETE` binds;
  `marking_sets_the_marker_and_retires_every_local_credential` reads the record
  back as gone). `CreateUser`/`UpdateUser` cannot carry it.
* **Every password and OPAQUE writer.** `password_hash` is written by
  `UserRepository::create` / `create_with_consent` (new accounts only, never
  marked), bootstrap (the first account), `change_password` (refused for a
  directory account before anything is verified), `confirm_reset` (refused,
  token spent), SCIM `PATCH` (refused, `mutability`) and SCIM `create` (new
  account); SCIM `PUT` writes no password for anyone. Password history is
  written only beside those writes. The OPAQUE record has one writer,
  `store_credential`, which re-reads the account and refuses. `login/start`
  serves a directory account the decoy; `login/finish` refuses it.
  gRPC `ValidateCredentials` answers `valid: false` without verifying or
  counting — right: that RPC has no directory client and must never become a
  second, uncounted password check.
* **Serialisation of the marker.** `User` is never serialised to a client
  (responses use `UserResponse`); its OpenAPI component is referenced by no
  path; `Debug` redacts it; the Art. 15 export carries it on purpose; both
  erasures clear it. An `entryUUID` is an identifier, not a secret.
* **`opaque_mode = required`.** Blocks `/auth/login` and therefore directory
  accounts. Fails closed (no sign-in, no fallback); the plan already assigns
  refusing that configuration combination to T23.3.8.
* **IPv6 literal URLs.** `ldap3` cannot derive a server name from a bracketed
  address, so verification fails and the connection is refused: closed, and
  documented in the operator note.
* **The key.** Optional, in `ALL_KEYS`, absent → `Unavailable` before any
  socket, never a boot failure; `Zeroizing` plaintext; no associated data
  (the same accepted residual as the SMTP password).
* **Tenant cascade (item 5).** The new cascade is a transaction (P23W2-02 for
  its error path). That nothing else cascades is pre-existing: P23W2-04.

**P23W2-09 (T-300), accepted until T23.3.8.** Can a tenant reach internal
hosts today? No: there is no management route, and no production code calls
`DirectoryConfigRepository::create`/`update` or
`UserRepository::mark_directory_account` (only the server constructs the
repository, read-only, for the authenticator). Only a party with write access
to the database can create a configuration, and that party is outside the
model. So T-300 stays open with its reason; it must not ship with a write
route (§12).

**P23W2-10 (frame cap), accepted until T23.3.8.** Recorded as T-295's
residual. Today the directory is chosen by nobody but the database operator.
Once a tenant administrator chooses it, a hostile server can make one
connection buffer what it can send in the 5 s operation timeout, up to the
per-tenant permit count, in a process every tenant shares — a cross-tenant
memory-exhaustion lever. It must be bounded (a length-checking codec wrapper
or a capped reader beneath `ldap3`) before tenant administrators can save a
URL.

**P23W2-11 (T-301), accepted.** The residual is stated in T-301 and bounded by
the per-IP login limits and the per-account lockout; it tells "directory
account" from "local or unknown", not a password.

---

## 7. Logging hygiene (CodeQL `rust/cleartext-logging`)

Every `tracing::` line the wave adds was read. They log `tenant_id`,
`user_id`, `session_id`, `client_id`, fixed reason text, error kinds
(`DirectoryAuthError` is a closed set with no payload) and the directory's
diagnostic at `debug` only — never a password, bind secret, cookie value or
digest, token, or `LoginResult`. Logging `user_id` and `session_id` through
`tracing` is established practice (49 such lines on `main` that CodeQL has
passed); the W1 alert was on a test **panic** message formatting `{user_id:?}`,
not on `tracing`. Every added `assert!`/`panic!`/`expect` message was read:
none formats a secret, a token, a cookie, a digest, an identifier or a
`LoginResult`; the directory tests name their cases, and the `{other:?}` panics
format `DirectoryAuthError` / `ConfigError` values, whose `Debug` reads no
sensitive field. The two tests this review adds name their cases too. Nothing
to fix.

---

## 8. Verdicts on the orchestrator's items

1. **`require_par` and the login hop — Low, pre-existing, reported
   (P23W2-03).** The hop was introduced with `browser_sso` on the bare path
   (the Basic OP plan's W3, [`basic-op-gap-plan.md`](basic-op-gap-plan.md)
   §4.0). T23.1.8 did not widen it: before T23.1.8 a tenant-path request
   also took the hop (T21.6 built the tenant `return_to`) and ended in
   `login_required` instead of the PAR refusal. Nothing is issued either way
   (`AuthorizeService::authorize` step 1b refuses `ParRequired`, answered in
   place, never redirected). The refusal should precede the hop: it is
   decidable without a principal from the client row
   `resolve_authorize_principal` already holds and the query's `request_uri`,
   exactly like the `response_type` pre-check beside it. Cost today: a user
   signs in for nothing, and a conformance reviewer sees a sign-in precede the
   error page (REVIEW-JUDGEMENTS open item 6). No probing value: whether a
   client requires PAR is not secret.
2. **T23.1.8 residuals** — §4 and P23W2-08 (accepted); the threat-model timing
   is P23W2-13.
3. **T23.1.5** — §5; P23W2-06 and -07 reported, the limiter accepted as
   designed.
4. **T23.1.4** — §5; all three confirmed.
5. **Tenant cascade** — P23W2-04 reported; the new cascade's transaction is
   sound, its error path was P23W2-02 (fixed).
6. **T23.3.2** — §6. T-300 stays open with its reason until T23.3.8 (no writer
   exists); timing, OPAQUE-required, IPv6 and the codec cap as above; the
   marker transaction, the writer sweep, serialisation and gRPC all held.
7. **Wave-wide** — logging §7; rate limiting §4; every threat id the wave
   cites exists except `T-304`, which the plan's G-2 note names as the first
   id W3 will allocate (a forward reference, correct); the three artifacts
   agree (§9).

---

## 9. Threat-model reconciliation

Every new or changed surface in W2 and in this review maps to an entry. No
threat was added here; T-298 was amended in `threat-model-stride.md`,
`Axiam.json` and `threat-modeling-and-security.md` in each fixing commit, and
the model stays at **2.20.0, 303 threats, 289 mitigated / 14 open**
(`node website/scripts/gen-threat-model.mjs` after each commit).

| Surface | Entry |
|---|---|
| `claims.id_token.auth_time` essential on `fapi2` (D-12) | T-239 (W2) |
| `max_age=0` as `prompt=login` (D-14) | T-239 (W2), T-238 (marker residual unchanged) |
| D-17 at PAR, introspection, revocation | T-253 (W2) |
| Basic header `client_id` selects the rate-limit bucket | T-253 (W2) |
| Per-tenant OP cookie, mint/clear list, tenant `return_to` | T-237, T-238 (W2) |
| `/oauth2/authorize/logout` and the `end_session` bounce | T-290 (W2) |
| Org-level logout in the principal's tenant | T-237 (W2) |
| `axiam-directory` crate, `DirectoryConfig`, schema v70, D-15 key | T-298, T-299 (W2) |
| Kept secret keeps its connection (P23W2-01) | **T-298 (amended here)** |
| Tenant delete cascade and its error path (P23W2-02) | **T-298 (amended here)** |
| LDAP client: escaping, TLS, pool, referrals, empty password | T-291 … T-297 (W2) |
| Directory host address policy | T-300 (W2, open; P23W2-09) |
| Directory login path: lockout, counting, equalisation, entry binding | T-297, T-301, T-302 (W2) |
| Marker (schema v71) and the local-password refusals | T-303 (W2) |
| Conformance documents, `report.py`, `export-evidence.py` | no surface (maintainer tooling) |

The stale sentence in the stride document's open-threat summary ("the
thirteen that remain are the ones that were always here") was corrected in
this review's documentation commit: fourteen remain, and T-300 is the one this
phase added. Reported findings (P23W2-03 … -07) are pre-existing; their
entries should be amended when they are fixed.

---

## 10. Checks run

All exit codes were captured from cargo itself (log plus `$?`).

```bash
export CARGO_INCREMENTAL=0
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
cargo fmt --all --check                                           # clean
cargo clippy -p axiam-db -p axiam-core --all-targets -- -D warnings   # clean
cargo test -p axiam-db --test directory_config_repository_test    # 22 passed (2 new)
cargo test -p axiam-db --test repository_test                     # 11 passed
cargo test -p axiam-db --test req14_tenant_isolation_test         # 7 passed
cargo test -p axiam-db --lib tenant                               # 21 passed
cargo test -p axiam-api-rest --test tenant_test                   # 20 passed
python3 scripts/check-crate-layering.py                           # OK, 19 crates
scripts/check-doc-links.sh                                        # OK
node website/scripts/gen-threat-model.mjs                         # 303 threats (289 mitigated, 14 open)
```

Each new test was run against the pre-fix code and failed: P23W2-01 on its
first case ("another host: a moved connection kept the stored secret"),
P23W2-02 on "a cancelled tenant delete must not be reported as a success".
No route or utoipa doc changed, so the OpenAPI spec was not regenerated; no
`CONTRACT.md` change (it stays at 1.53). Not run: the conformance suite (no
network) and a live directory.

---

## 11. Issue bodies for the reported findings

**P23W2-04 (Medium) — Deleting a tenant deletes nothing but the tenant row
and its directory configuration.** `SurrealTenantRepository::delete` removes
`directory_config` (T23.3.1) and the tenant row, and nothing else. Every
tenant-scoped table keeps the deleted tenant's rows: users (Argon2id hashes,
encrypted MFA secrets, e-mail, phone, address), sessions, OAuth2 clients and
refresh tokens, federation configurations (encrypted client secrets),
`email_config` (the encrypted SMTP password or provider API key), webhooks
(HMAC secrets), certificates and CA material, roles, groups, consents and
audit rows. The handler (`handlers/tenants.rs::delete`) says "the tenant's own
audit entries … went with it"; they did not. Live use is mostly closed — the
OAuth2 grants refuse an unknown tenant and password sign-in needs the
tenant's settings — but the AXIAM session refresh path and access-token
validation were not checked, and the residue alone defeats GDPR Art. 17 for
every data subject of the tenant and leaves encrypted credentials for systems
outside AXIAM in the database. Proposed: decide the policy (hard cascade in
one transaction, or a tombstoned tenant purged by the cleanup job with the
same order the user erasure uses), revoke sessions and refresh tokens first,
keep the system-log `tenant.deleted` record, correct the handler comment, and
add a test that deletes a populated tenant and asserts every tenant-scoped
table is empty for it and that its last session can no longer refresh.

**P23W2-03 (Low) — A `require_par` client's unpushed request asks an
anonymous browser to sign in before it is refused.** For a `browser_sso`
client registered `require_par` (every `fapi2` client), an anonymous browser
presenting an authorization request without `request_uri` is sent through the
login hop; after sign-in the return leg is refused `invalid_request` ("this
client must use pushed authorization requests"). Nothing is issued, but a user
signs in for nothing, and a FAPI conformance reviewer sees a sign-in precede
the error page (`docs/conformance/REVIEW-JUDGEMENTS.md`, open item 6). The
refusal is decidable without a principal: in
`handlers/oauth2.rs::resolve_authorize_principal`, beside the `response_type`
pre-check, refuse `client.require_par && q.request_uri.is_none()` with
`OAuth2Error::ParRequired`, answered in place (never redirected, as the
handler's existing arm does). Add an anonymous-browser test on the bare and
the tenant path asserting `400`, no `Location` to `/login`, and the PAR
wording.

**P23W2-05 (Low) — An SMTP password is kept when the SMTP host changes.**
`SurrealEmailConfigRepository::preserve_omitted_secret` carries the stored
SMTP password forward whenever a save omits it and the provider kind is
unchanged, whatever the host. An administrator who may edit the email
configuration but was never given the password can repoint `host` at a server
they run and receive it in the next `AUTH`. P23W2-01 closed the same shape for
the directory bind secret. Proposed: keep an omitted SMTP password only when
`host`, `port` and the TLS mode are unchanged, otherwise refuse with
`400 validation_error`; API-key providers are unaffected (their endpoint is
fixed by the kind). Test both scopes.

**P23W2-06 + P23W2-07 (Informational) — two small gaps found by the W2
audits.** (a) The discovery documents publish no
`revocation_endpoint_auth_methods_supported` or
`introspection_endpoint_auth_methods_supported`; RFC 8414 §2 says that when
omitted the default is `client_secret_basic`, so a client reading discovery
literally will not use `client_secret_post`, `private_key_jwt` or mTLS at
those endpoints although AXIAM accepts them. Publish both, derived from the
same list as `token_endpoint_auth_methods_supported`. (b) SCIM `PUT`/`PATCH`
replacing `phoneNumbers` leaves `phone_number_verified_at` as it was, so a
future verification flow would vouch for a number it never saw. Nothing sets
the column today; clear it whenever the stored number changes, in
`UserRepository::update`, so every writer inherits it.

---

## 12. What W3 must take from this review

* **T23.3.8 (directory management routes) may not ship without:**
  1. **T-300 closed in the same commit as the first write route**: at minimum
     refuse loopback, link-local (including `169.254.169.254`), unspecified,
     multicast and AXIAM's own listener addresses after resolution, with the
     resolved address pinned for the connection (the `guarded_fetch` rule
     against DNS rebinding — which needs a connector beneath `ldap3`, since
     the TLS server name must stay the hostname), and an operator-level
     allow-list for the private ranges directories live in.
  2. **A frame cap** beneath `ldap3` (P23W2-10).
  3. **`config::validate` on every write** — the repository does not run it
     (its documentation says so); the authenticator re-checks only transport
     and anchors.
  4. **The P23W2-01 rule surfaced in the API**: a `PUT`/`PATCH` that moves the
     connection without a secret is a `400` naming the rule; the console must
     ask for the secret again when the URL, StartTLS, bind DN or anchors
     change. The audit row for a configuration change must not carry the
     secret, and should record that the connection moved.
  5. The `opaque_mode = required` × directory refusal the plan assigns there.
* **T23.3.3 (JIT provisioning) and linking**: marking an *existing* local
  account revokes nothing — its sessions, refresh tokens, passkeys and user
  certificates keep working. Linking must call `revoke_all_sessions` and
  decide what happens to its passkeys and certificates (T-303's residual
  names only passkeys). The JIT seam must keep the unknown-name answer and
  timing identical when the bind fails.
* **T23.2.x (SAML SSO on the login hop)**: add the SSO path to
  `op_session_cookie_paths` and to its pinning test in the same commit; read
  the cookie only through the tenant-keyed lookup; a SAML `AuthnRequest`
  carrying `ForceAuthn` is P23W1-08's marker question again — bind it, or
  require `authenticated_at` to post-date the outbound leg, rather than inherit
  the residual; and refuse what is decidable without a principal **before**
  the hop (the P23W2-03 lesson), so an SP that is unknown, disabled or
  misconfigured never puts a user through a sign-in.
* **New ids** start at **T-304** (none were allocated here).

## 13. Invariants

I1 (nothing registered today changes behaviour) holds for both fixes: no route
writes a directory configuration, so P23W2-01 changes nothing deployed, and
P23W2-02 changes only the answer to a tenant delete that already failed (now an
error instead of a false `204`). The wave's own deliberate changes, all
recorded in the CHANGELOG: an essential `id_token.auth_time` (or an unreadable
one) is refused on `fapi2` (D-12); `max_age=0` on the honour lane yields a code
after re-authentication (D-14); a `fapi2` row edited to a shared-secret method
is refused at PAR, introspection and revocation (D-17); a Basic client is
rate-limited under its own `client_id` in the `client_id` and `ip_client_id`
key modes; a sign-in on a deployment with per-tenant issuers sets a second OP
cookie and browser SSO works on `/t/{tenant_id}/oauth2/authorize` (D-11);
`end_session` without a hint `sid` bounces through the hop and ends the
cookie's session (D-16); an organization-level principal's logout ends its
session; and directory accounts — of which none can exist until T23.3.3 —
sign in through their directory and are refused at every local password door.
No contract (1.53), OpenAPI or SDK-visible shape changed in this review.
