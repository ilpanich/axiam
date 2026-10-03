# Security review — Phase 23, wave W1 (F4)

**Date:** 2026-10-03.
**Against:** `claude/phase23-w1`, the whole wave diff `129683b..28553c9`
(73 files, about 9 500 lines; `129683b` is `main` at branch time).
**Scope:** the six W1 tasks of
[`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md):
T23.1.1–T23.1.3 (G-1 audits and their five fixes), T23.4.1 (G-4, RFC 7592 —
the only new inbound surface, and where the weight of this review sits), and
the documentation tasks T23.9.1, T23.12.1, T23.15.1.
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) (T-237,
T-238, T-239, T-240, T-255, T-258, T-272…T-280, T-289) and the OWASP ASVS 5.0
areas the diff touches (V7 session management, V8 authorization, V10 OAuth
and OIDC, V2 validation, V16 logging). Every finding fixed here has a test
that failed before the fix. A claim with no test says so.

---

## 0. Summary

Four findings were fixed on the branch. Three of them are the same defect
seen from three sides — **an account status change revokes no credential, so
every place that turns a credential back into a principal must re-read the
account, and three such places did not, or did it wrongly** — and the wave
was where that rule was first written down, by T23.1.3, which recorded
`/oauth2/authorize` as "the one place". It was not.

| ID | Finding | Severity | Element / threat | State |
|---|---|---|---|---|
| **P23W1-01** | The OAuth2 `refresh_token` grant never re-read the account. A relying party holding a locked or deactivated user's refresh token kept minting access and ID tokens indefinitely (each rotation stamps a fresh `expires_at`). | **High** | `/oauth2/token`; T-39, T-237 | **Fixed** — `f45a059`, narrowed by `d8b889a` |
| **P23W1-04** | A federated sign-in (OIDC, SAML, OAuth2 "Sign in with …") never read the linked account's status: suspending an account in AXIAM, including through SCIM `active: false`, was undone by the user's next SSO. | **High** | Federated sign-in; T-160 | **Fixed** — `ad23052` |
| **P23W1-03** | Regression in T23.1.3: holding the OP cookie to the password sign-in rule *including the email-verification grace period* refused every federated account a day after provisioning (federated accounts are `PendingVerification` for life). Browser sign-on ended for the federated population. | **Medium** | `/oauth2/authorize`; T-237 | **Fixed** — `d8b889a` |
| **P23W1-02** | `bearer_token` matched the literal `Bearer `; a lower-case scheme (legal, RFC 9110 §11.1) was read as no token and answered with the bare challenge. | Low | `/oauth2/register`, RFC 7592 | **Fixed** — `7d667ce` |
| **P23W1-05** | The admin `DELETE /api/v1/oauth2-clients/{id}` revokes nothing; for a CIMD client the row re-materialises on its next request and its old refresh tokens are live again. (Item (b).) | Medium | `/api/v1/oauth2-clients`; T-289 neighbour | **Reported** (pre-existing) |
| **P23W1-06** | RFC 8693 `actor_token` is not bound to the exchanging client: any valid same-tenant access token is accepted as the actor. (Item (a).) | Medium | Token exchange; T-55 family | **Reported** (pre-existing) |
| **P23W1-07** | The AXIAM session refresh (`AuthService::refresh`) still applies the grace period, so a federated account's SPA session stops refreshing a day after provisioning — P23W1-03's twin on a path W1 did not touch. | Medium | Session refresh | **Reported** (pre-existing) |
| **P23W1-08** | The login-hop marker is unbound; forging `axiam_login_hop=1` skips a `prompt=login` interaction. `auth_time` stays truthful. (Item (c).) | Low | `/oauth2/authorize`; T-238 | **Accepted residual** |
| **P23W1-09** | The bearer / `axiam_access` path at `/oauth2/authorize` does not re-read the account. (Item (d).) | Low | `/oauth2/authorize`; T-39 | **Accepted residual** (bounded to 15 min by P23W1-01) |
| **P23W1-10** | `end_session` without an `id_token_hint` `sid` clears the OP cookie but cannot revoke the session row. (Item (e).) | Low | `end_session`; T-237 | **Accepted residual** |
| **P23W1-11** | `claims.id_token.sub` with a `value` is dropped on every lane; OIDC Core §5.5.1 says to answer positively only for that subject. The other `claims` sibling, essential `id_token.auth_time` on `fapi2`, is D-12. | Low | `/oauth2/authorize`; T-239 | **Reported** (pre-existing) |
| **P23W1-12** | UserInfo and introspection do not re-read the account: a suspended user's access token is answered until `exp`, and introspection reports their refresh token `active`. | Low | Resource endpoints; T-39 | **Reported** (pre-existing) |
| **P23W1-13** | A `PUT` (or an admin update) that narrows scopes leaves outstanding refresh tokens with the wider scope list. | Low | `/oauth2/token`; T-289 | **Reported** (pre-existing) |
| **P23W1-14** | The RFC 7592 token has no recognisable prefix for secret scanners. (Item (f).) | Informational | T-289 | **Accepted**, recommended before GA |
| **P23W1-15** | Refused RFC 7592 requests write an audit row into whatever tenant the query names; one indexed row fetch separates "unknown client" from "wrong token". | Informational | T-289 | **Accepted** |

**Verdict on merge.** Nothing open blocks W1. The two High findings are fixed
and pinned; P23W1-03 was a regression the wave itself introduced and is fixed.
P23W1-05, -06 and -07 are pre-existing, Medium, and should be filed before the
phase's PR merges (issue bodies in §11). Item (g) is a Low-risk unknown that a
single-module conformance re-run settles before the G-1 submission (§8 (g)).

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| RFC 7592 handlers | T23.4.1 | `axiam-api-rest/src/handlers/dcr.rs` (1 210) | **read in full** |
| RFC 7592 pure half | T23.4.1 | `axiam-oauth2/src/dcr.rs` §`validate`, §`validate_update`, minting | **read in full** |
| Storage, CAS, delete | T23.4.1 | `axiam-db/src/repository/oauth2_client.rs` (the four new methods), schema v68/v69 | **read in full** |
| Routing, limiter, body limit, `PUBLIC_PATHS` | T23.4.1 | `server.rs` §`oauth2_scope`, `permissions.rs`, `middleware/authz.rs` §matcher, `middleware/csrf.rs`, `middleware/tenant_path.rs`, `rate_limit_shared.rs` | targeted |
| OpenAPI scheme | T23.4.1 | `openapi.rs`, `sdks/openapi.json` (digest + registry checked) | targeted |
| `claims` and PAR `request` | T23.1.1 | `authn_params.rs`, `fapi.rs`, `handlers/oauth2.rs` §PAR | **read in full** (diff) |
| Evidence snapshot, clamp | T23.1.2 | `token.rs` (both grants), `session.rs`, `federation.rs`, `federation_login.rs`, `oidc.rs` | **read in full** (diff) + every call site |
| OP cookie, hop | T23.1.3 | `handlers/oauth2.rs` §`resolve_authorize_principal`, `login_hop.rs`, `service.rs` §`check_session_holder` | **read in full** |
| Siblings of the account-status rule | — | `token.rs` (every grant), `token_exchange.rs`, `device_service.rs`, `extractors/auth.rs`, gRPC `middleware/`, `services/token.rs`, AMQP, UserInfo, introspection, every federated callback, `users.rs` | targeted, every principal-resolving path |

Tests were run against the in-memory SurrealDB harness; no live stack, and no
network (so the conformance suite could not be run; see §8 (g)).

---

## 2. P23W1-01 — the OAuth2 grants never re-read the account

**Severity: High. Fixed in `f45a059` (rule narrowed in `d8b889a`).**

Locking or deactivating a user through `PUT /api/v1/users/{id}` revokes no
credential (`users.rs` flushes the decision cache and stops); only deletion,
SCIM deprovisioning and a credential reset call `revoke_all_sessions`. The
design relies on every place that turns a credential back into a principal
re-reading the account. T23.1.3 found `/oauth2/authorize` did not and
recorded it, in T-237 and the CHANGELOG, as "the one place". `TokenService::
handle_refresh_token` is another: it authenticates the client, finds the
refresh token, and mints — the user row is read only to fill `username` into a
re-issued ID token. Every rotation writes `expires_at = now +
refresh_token_lifetime_secs`, so the chain never ends. T-39's "the 15-minute
lifetime bounds the window" was false for an account disable.

A suspended user's relying parties therefore kept full access for as long as
they kept refreshing, which is ASVS 5.0 V7.4.2's failure exactly. The code
grant is the second half: the bearer and `axiam_access` path at the
authorization endpoint does not re-read the account (item (d)), and redeeming
the code it buys is what converts a 15-minute credential into a long-lived one.

**Fix.** `TokenService::ensure_account_may_act`, called in the
`authorization_code` grant after the code is spent and in the `refresh_token`
grant before anything is minted or rotated, applies
`axiam_auth::service::account_may_act` — now the single rule behind
`AuthService::check_session_holder` too. A refused or removed account is
`invalid_grant`; nothing is revoked, so reactivation restores the grant.
Device-grant and token-exchange refresh tokens go through the same refresh
grant and inherit it; token exchange mints no refresh token and its lifetime
is capped by the subject token's `exp`.

**Tests.** `token_service.rs::p23w1_01_*` (locked, inactive, deleted and a
removed account on both grants, no successor row written; the active,
no-user and pending twins) and `oauth2_flow_test.rs::
p23w1_01_a_suspended_accounts_refresh_token_mints_nothing_until_reactivated`
(locked and inactive refused over HTTP, then reactivation restores the same
token) — each failed before the fix.

---

## 3. P23W1-04 — a federated sign-in revives a suspended account

**Severity: High. Fixed in `ad23052`.**

`OidcFederationService::provision_or_link_identity` returns the linked user
with no status read, `create_session_and_tokens` checks none, and none of the
four federated callbacks (OIDC JSON and form, SAML JSON and form, plus the
plain OAuth2 provider) asked. Suspending an account in AXIAM — the operator's
lever, and what SCIM `active: false` does — leaves the upstream account alone,
so "Sign in with Okta" signed the suspended user straight back in with a fresh
session, access token and OP cookie. T-160 names this threat and had closed
it on the token-exchange path only. The website's SCIM page says
"Deactivation is immediate and complete"; on this path it was not.

**Fix.** `sso_login_post_auth`, which every federated sign-in passes through
before a session or handoff code exists (verified: `federation.rs:2105, 2322`,
`federation_login.rs:553, 852`), applies `check_session_holder` before the
reactor gate. The handoff redemption one minute later is not re-gated; the
window is the handoff TTL (60 s).

**Test.** `sec095_federated_login_gate_test.rs::
p23w1_04_a_suspended_account_is_not_signed_back_in_by_its_identity_provider`
— a Locked account received `200` and a session before the fix.

---

## 4. P23W1-03 — the T23.1.3 fix ended browser sign-on for federated users

**Severity: Medium (availability regression introduced in W1). Fixed in
`d8b889a`.**

`check_session_holder` was the password sign-in rule, grace period included.
`UserRepository::create` writes `PendingVerification` for every row and
federation provisioning never moves a federated user off it — the
token-exchange code says so in a comment and T-160 records the decision. So
once a federated account's grace period (24 h by default) ended, its OP
cookie was refused, the hop sent it round `/login`, and the return leg
answered `login_required`: browser SSO stopped for every federated user a day
after their first sign-in. P23W1-01 as first committed reused the same rule
and would have refused their codes and refresh tokens too; it was narrowed
before anything else was built on it.

**Fix.** `account_may_act` refuses `Locked`, `Inactive`, `Anonymized` and
`Deleted` and never `PendingVerification` — T-160's rule. The grace period
remains where it belongs, on password sign-in (`AuthService::login`).

**Tests.** `oauth2_login_hop_test.rs::p23w1_03_an_op_session_survives_a_
pending_verification_status` (it replaces `an_op_session_follows_the_email_
verification_grace_period`, which pinned the regression) and
`token_service.rs::p23w1_03_a_code_for_a_pending_account_past_its_grace_period_
is_redeemed`, plus the pending row of the refresh twin.

---

## 5. P23W1-02 — the `Bearer` scheme was case-sensitive

**Severity: Low. Fixed in `7d667ce`.** `strip_prefix("Bearer ")` read
`bearer <token>` as no token at all, answered with `WWW-Authenticate: Bearer`,
which tells a client to discard a good credential. Now
`eq_ignore_ascii_case`; an empty token, `Bearer<token>` and any other scheme
are still no token. Test `p23w1_02_the_bearer_scheme_is_matched_case_
insensitively`; a pin `p23w1_an_oversized_update_is_refused_before_it_is_read`
was added for the 16 KiB `PayloadConfig` on `PUT`, which had none.

---

## 6. T23.4.1 probes that did not yield

* **Minting and storage.** `generate_refresh_token`: 32 bytes from
  `rand::rng()` (ThreadRng, a ChaCha CSPRNG reseeded from the OS — the
  docstring's "the operating system's CSPRNG" is loose but not wrong in
  effect), base64url; only `hash_refresh_token` (SHA-256 hex) is stored, in the
  same `CREATE` as the row; `create_with_registration_access_token` refuses a
  non-`dcr` input and an empty digest. 256 bits makes an unsalted digest
  sufficient.
* **Digest lookup and timing.** One `SELECT` with tenant, `client_id`,
  `managed_by = 'dcr'` and the digest, via the `(tenant_id, client_id)`
  index. The comparison is on a digest of attacker input, so a timing leak on
  it says nothing about the stored token. The four 401 cases — unknown client,
  wrong token, other tenant, no-token client — produce the same status, body,
  `WWW-Authenticate: Bearer error="invalid_token"`, `Cache-Control`/`Pragma`
  headers, one query and one audit row. The only difference is whether the
  index yields a row to filter (P23W1-15); `client_id` is not a secret.
  No-token requests skip the query, but differ in the challenge already, and
  that difference depends only on the request.
* **Header parsing.** First `Authorization` header only (actix `get`); extra
  spaces trimmed; `Bearer ` with nothing after it is no token; Basic refused;
  case fixed (P23W1-02). `access_token` in the query is `400` even beside a
  good header, and `TenantPathScope` appends `tenant_id` without dropping it.
  No form body is read.
* **CAS under concurrency.** `replace_dcr_registration` is the X6 two-layer
  shape (guarded `UPDATE` in a transaction; read-back of the new digest as the
  nonce). The interleaving where layer 1 does not abort and the first caller's
  read-back lands between the two writes would report two successes — but both
  callers hold the same original token, so no principal crosses a boundary; it
  degrades to "the later writer wins", which is the sequential outcome.
  `rfc7592_racing_updates_on_one_token_have_one_winner` exercises the real
  storage path. `PUT` versus `DELETE` resolves to one `401`.
* **The write fence.** `DcrRegistrationReplacement` has eight fields (name,
  redirects, grants, scopes, auth method — refused if changed — `jwks`,
  `jwks_uri`, `allowed_resources` from the tenant). The `UPDATE` names exactly
  those plus the digest and `updated_at`. Profile, X7 flags, `managed_by`,
  tenant, mTLS/DPoP bindings, secret, post-logout and back-channel URIs are
  unreachable by construction; `a_registration_cannot_opt_itself_…` and
  `an_update_cannot_opt_itself_…` pin it. An administrator-elevated flag on a
  `dcr` row survives a self-service `PUT`; that is the administrator's choice.
* **`validate` reuse.** Redirects go through both `validate_redirect_uris` and
  the tenant host glob (loopback always allowed, label-anchored glob);
  `jwks_uri` must be `https` and is fetched only through `ssrf::guarded_fetch`
  (SEC-054, IP-pinned); `jwks` must parse and is bounded by the 16 KiB body;
  `client_name` is length-bounded by the body only and rendered by React
  (escaped); there is no `logo_uri` member; scopes are within
  `dcr_allowed_scopes` as of now; `allowed_resources` is overwritten with the
  tenant's list. A `client_secret` in the body is verified with the keyed
  constant-time hasher.
* **DELETE.** Conditional on the digest in a transaction; `revoke_all_for_
  client` is scoped `(tenant_id, client_id)`; codes, PAR handles and device
  codes die with client authentication; the quota is a row count, so the slot
  is freed. Not revoking the users' sessions is right (a stranger must not end
  other people's sessions).
* **Audit redaction.** No token, prefix or digest anywhere; `client_id` only in
  the minted shape; asserted under a `TRACE` subscriber.
* **Rate limiting.** One resource, three methods, one per-route governor plus
  the shared counter keyed `oauth2_register_client:{ip}`. Under `/t/{tenant}`
  the scope is mounted again (a second governor), but the shared counter's key
  carries no path, so the two mounts share one allowance where the shared
  layer is on. A trailing slash or an extra segment does not route; a
  percent-encoded `client_id` routes to the same resource and bucket.
* **`PUBLIC_PATHS`.** `/oauth2/register/*` is segment-anchored; nothing else
  is mounted beneath `/oauth2/register`; `..` fails closed in the matcher and
  actix does not resolve dot-segments, so `/oauth2/register/%2e%2e/…` routes to
  nothing. CSRF is exempt for `/oauth2/` and the credential is never ambient.
* **CORS.** The global restrictive policy applies; a bearer-only route gains
  nothing from CORS laxity.
* **`no-store`.** On the 201, 200 (read and replace), 204, 400 and 401; the
  500 lacks `Pragma` and carries no secret.
* **OpenAPI.** Own `registration_access_token` HTTP-bearer scheme on the three
  operations; digest and management registry verified in sync.

---

## 7. G-1 fixes — completeness and regressions

* **`check_session_holder` (T23.1.3).** Missed siblings: the OAuth2 grants
  (P23W1-01) and federated sign-in (P23W1-04), both fixed; the wrong rule for
  federated accounts (P23W1-03), fixed. gRPC and AMQP accept access tokens
  only, with the optional strict-revocation session check — 15-minute window,
  T-39. UserInfo and introspection: P23W1-12. The session refresh path still
  uses the grace period: P23W1-07.
* **The `claims` refusal (T23.1.1).** On `fapi2`, every `userinfo` member is
  honoured; `id_token` identity claims are truthfully omitted (OIDC Core
  §5.5.1 forbids an error for an unreturned claim); `id_token.acr` is now
  refused; essential `id_token.auth_time` is dropped (D-12, open);
  `id_token.sub` with a value is dropped on **every** lane (P23W1-11).
* **PAR `request` refusal ordering.** After the `request_uri` refusal and
  before CIMD materialisation and client authentication; it names only what
  the caller sent. Correct.
* **D-9 snapshot.** Written at code exchange from the code's snapshot, copied
  verbatim at rotation; device and exchange paths write `None` (fallback to the
  live session, as before). Emission gating unchanged.
* **D-10 clamp.** Every site that dates a federated session: the four callbacks
  clamp at verification, and `issue_sso_session` clamps again at the point of
  record, which covers the handoff redemption and the plain OAuth2 provider
  (whose instant is always `None`). Complete.

---

## 8. Verdicts on the executors' open items

**(a) Actor token not bound to the exchanging client — Medium, reported
(P23W1-06).** RFC 8693 §1.1 makes `actor_token` the identity of the acting
party; accepting any same-tenant access token lets a client that has seen
another party's token (an MCP server receives them by design) name that party
as `act.sub` in a delegation it performs itself. No privilege is added — the
issued token is bounded by the subject token and the client's own grant — but
`act` is the attribution every downstream audit and policy reads, and a
resource server that admits only a named agent (`act.sub`) can be satisfied by
a borrowed token. Pre-existing code (B3); the guide states the limitation.

**(b) Admin DELETE revokes nothing — Medium, reported (P23W1-05).** For a DCR
or admin client the refresh tokens are dead anyway (the grant fails client
authentication and `oa_` identifiers are never reissued). For a **CIMD**
client they are not: the `client_id` is a URL, the next request re-materialises
the shadow row, and every refresh token issued before the delete works again.
An administrator deleting an abusive CIMD client has revoked nothing.

**(c) Unbound login-hop marker — Low, accepted residual (P23W1-08).** Forging
the marker skips only an interaction the forger's own request asked for; the
principal, `auth_time`, `acr` and `amr` are unchanged, so a relying party that
checks `auth_time` (which OIDC Core expects of one that relies on
re-authentication) is not deceived. The realistic abuser is a walk-up user at
an unlocked browser defeating an RP's `prompt=login` step-up. Recommended
follow-up, not blocking: on a marked return leg with `prompt=login`, require
the session's `authenticated_at` to post-date the outbound leg (or bind the
marker to a short-lived server nonce).

**(d) Bearer / `axiam_access` path skips the account re-read — Low, accepted
residual (P23W1-09).** The credential is a 15-minute access token, the window
every access-token consumer already has (T-39). Its only escalation — buying a
code and redeeming it into a long-lived refresh token — is closed by
P23W1-01, which re-reads the account at both grants.

**(e) `end_session` without an `id_token_hint` `sid` — Low, accepted residual
(P23W1-10).** The cookie's `Path=/oauth2/authorize` keeps it from reaching
`end_session`, so the handler can expire it but not read it. The surviving row
is usable only by whoever holds the cookie value, which this browser no longer
does. Worth folding into D-11's cookie-path decision.

**(f) No token prefix — Informational, accepted (P23W1-14).** The value is
opaque to SDKs (CONTRACT §28.12), so adding a prefix later (`axiam_rat_`, as
the initial access token has `axiam_dcr_`) is not a breaking change.
Recommended before GA so GitHub secret-scanning custom patterns can match it.

**(g) FAPI `test-claims-parameter-identity-claims` — Low risk, unresolved
without a run.** The plans run `openid: openid_connect`, `fapi_profile:
plain_fapi`. What is known locally: the 09-18 and 09-25 evidence records the
module as `WARNING` on every variant and nothing about its request; the
refusal fires only for a `claims` that names `id_token.acr` or does not parse.
To my knowledge of the suite, the identity-claims module requests identity
claims (`given_name`, `family_name`, … in `id_token` and `userinfo`) and the
ACR-requesting conditions belong to the Brazil profile, not `plain_fapi`; if
so the outcome is unchanged. This could not be verified offline. Before
T23.1.7's submission, run the one module on one variant
(`conformance/scripts/run-some.sh conformance/plans/fapi2-security-profile-final-private-key-jwt.json fapi2-security-profile-final-test-plan fapi2-security-profile-final-test-claims-parameter-identity-claims`)
and read the authorization request in the log for `"acr"`.

---

## 9. Threat-model reconciliation

Every new or changed surface in W1 and in this review maps to an entry, and
every entry changed here was changed in both `threat-model-stride.md` and
`Axiam.json` in the fixing commit. No threat was added: the model stays at
**2.18.0, 289 threats, 276 mitigated / 13 open**
(`node website/scripts/gen-threat-model.mjs` after each commit).

| Surface | Entry |
|---|---|
| `GET`/`PUT`/`DELETE /oauth2/register/{client_id}`, the registration access token, schema v69, `PUBLIC_PATHS` widening, the limiter bucket, the 16 KiB limit, audit redaction | T-289 (W1) |
| Bearer parsing at the registration endpoints (P23W1-02) | T-289 (interop, no text change) |
| `claims.id_token.acr` on `fapi2`; `request` at PAR | T-239 (W1) |
| Evidence snapshot on the refresh token (schema v68); upstream instant clamp | T-240 (W1) |
| OP cookie account re-read | T-237 (W1; corrected by P23W1-01 and P23W1-03) |
| `return_to` validator, hop | T-238 (W1) |
| OAuth2 grants re-read the account (P23W1-01) | T-39 (amended) |
| Federated sign-in re-reads the account (P23W1-04) | T-160 (amended) |
| VC design, front-channel decline, agents guide | no surface (documentation) |

Reported findings (P23W1-05…-07, -11…-13) are pre-existing and not in W1's
surfaces; their entries should be amended when they are fixed.

---

## 10. Test commands run

All exit codes were captured from cargo itself (log plus `$?`).

```bash
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
cargo fmt --all --check
cargo clippy -p axiam-auth -p axiam-oauth2 -p axiam-api-rest --all-targets -- -D warnings
cargo test -p axiam-auth --lib                           # 259 passed, 1 ignored
cargo test -p axiam-auth --test auth_service_test        # 45 passed
cargo test -p axiam-oauth2 --lib                         # 506 passed
cargo test -p axiam-oauth2 --test token_service          # 123 passed
cargo test -p axiam-api-rest --lib                       # 248 passed
cargo test -p axiam-api-rest --test dynamic_registration_test   # 38 passed
cargo test -p axiam-api-rest --test mcp_authorization_test      # 14 passed
cargo test -p axiam-api-rest --test oauth2_login_hop_test       # 30 passed
cargo test -p axiam-api-rest --test oauth2_honour_lane_test     # 30 passed
cargo test -p axiam-api-rest --test par_test                    # 29 passed
cargo test -p axiam-api-rest --test oauth2_flow_test            # 42 passed
cargo test -p axiam-api-rest --test federation_test             # 78 passed
cargo test -p axiam-api-rest --test sec095_federated_login_gate_test   # 6 passed
cargo test -p axiam-api-rest --test federation_first_time_sso_test     # 6 passed
cargo test -p axiam-api-rest --test federation_login_providers_test    # 40 passed
python3 scripts/check-crate-layering.py
scripts/check-doc-links.sh
python3 scripts/check-spec-digest.py
python3 scripts/gen-management-registry.py --check
node website/scripts/gen-threat-model.mjs
```

Each new test was also run against the pre-fix code and failed (P23W1-01: the
two refusal tests in `token_service` and the HTTP test; P23W1-02, -03 and -04:
their named tests). Not run: `axiam-server` integration tests (the shared rule
changed only in `axiam-auth` and its callers, all covered above) and the
conformance suite (no network).

---

## 11. Issue bodies for the reported findings

See the orchestrator report; the same text is kept here so the record stands
on its own.

**P23W1-05 (Medium) — Admin client deletion revokes nothing, and a deleted
CIMD client's refresh tokens come back.** `DELETE /api/v1/oauth2-clients/{id}`
(`handlers/oauth2_clients.rs::delete`) removes the row and nothing else. For a
`dcr` or admin client that is harmless in practice — the refresh grant fails
client authentication and `oa_` identifiers are never reissued — but for a
`managed_by: cimd` client the `client_id` is the metadata URL, and
`materialise_if_cimd` recreates the shadow row on the client's next request,
at which point every refresh token issued before the deletion is live again.
The RFC 7592 self-service delete added in T23.4.1 already calls
`RefreshTokenRepository::revoke_all_for_client`; the admin path should do the
same (before the row is deleted, failing the delete if revocation fails), and
a test should delete a CIMD client, let it re-materialise, and refresh with an
old token. Amend T-289's residual and the CIMD entries when fixed.

**P23W1-06 (Medium) — RFC 8693 `actor_token` is not bound to the exchanging
client.** `token_exchange.rs` accepts as `actor_token` any valid access token
whose `tenant_id` matches, and writes its `sub` into `act`. A client that holds
someone else's token — an MCP server is handed users' and agents' tokens by
design — can therefore perform a delegation attributed to that other party.
Privileges are not widened (the issued token is bounded by the subject token
and the client's grant), but `act` is what audits, the `act` chain depth cap
and any resource-server policy keyed on the acting agent read. Proposed: require
the actor token's `azp`/`client_id` to equal the authenticated exchanging
client, or its `sub` to be that client's service account, with an explicit,
audited opt-out per client; or implement `may_act` on the subject token. The
*Identity for agents* guide already states the limitation and should be
updated with the fix.

**P23W1-07 (Medium) — Federated accounts' AXIAM sessions stop refreshing a
day after provisioning.** `AuthService::refresh` applies `check_user_status`
with the email-verification grace period. Every account is created
`PendingVerification` and federation provisioning never moves a federated
user off it, so after `email_verification_grace_period_hours` (24 by default)
a federated user's session refresh is refused and the admin SPA drops them
every 15 minutes. P23W1-03 fixed the same mistake at `/oauth2/authorize` and
the OAuth2 grants; the session refresh path should use
`axiam_auth::service::account_may_act` (refuse suspended statuses, never
`PendingVerification`), leaving the grace period to password sign-in. Add a
test that refreshes a session of a pending account created before the grace
period.

**P23W1-11 (Low) — `claims.id_token.sub` with a `value` is ignored.** OIDC
Core §5.5.1 says that when `sub` is requested with a specific value for the ID
Token, the server must answer positively only if that subject is the
authenticated one. `parse_claims_acr` reads only `id_token.acr`, and nothing
else reads `sub`, so the request is silently dropped on every lane (on `fapi2`
it is the analogue of the refused `id_token_hint`). Either honour it on the
honour lane and refuse it on `fapi2` (treat it as security-bearing in
`AuthnRequestParams`), or refuse it everywhere. Track with D-12 (essential
`auth_time` on `fapi2`).

**P23W1-12 (Low) — UserInfo and introspection do not re-read the account.**
`userinfo_claims_for` reads the user row when claims need it but never its
status, and `/oauth2/introspect` reports a suspended user's refresh token as
`active: true`. Both are bounded (an access token by its 15-minute `exp`; the
refresh token can no longer be redeemed since P23W1-01), but introspection is
the documented "immediate revocation" answer of T-39 and should say `active:
false` for a suspended account's tokens. Apply `account_may_act` in
introspection (both token kinds) and in UserInfo.

**P23W1-13 (Low) — Narrowing a client does not narrow its outstanding refresh
tokens.** A `PUT /oauth2/register/{client_id}` (or an administrator's update,
or a tenant withdrawing a scope from `dcr_allowed_scopes`) that removes a scope
leaves every refresh token issued earlier with the wider `scopes`, and the
refresh grant copies them forward; the resource binding is kept (T21.3) but
the scope list is not intersected with the client's current registration.
Intersect at refresh (`stored.scopes ∩ client.scopes`), and record it in T-289
and T-55.

---

## 12. What I did not find, and where I would look next

The registration endpoint family held: no cross-client, cross-tenant or
widening path was found, and the four indistinguishable `401`s are
indistinguishable in everything observable but one index row fetch. Where I
would look next: the `users.rs` update path itself (revoking on a status change
would make every re-read a second line rather than the only one), tenant
*status* (a suspended tenant's `dcr` clients can still be read, replaced and
deleted, and `effective_policy` does not consult it), and the D-11 cookie-path
decision, which also decides P23W1-10.

## 13. Invariants

I1 (nothing registered today changes behaviour) holds for every fix except the
deliberate ones: a suspended account is now refused at the two user-bound
grants and at federated sign-in, and a pending account is served again at
`/oauth2/authorize`. No contract, OpenAPI or SDK-visible shape changed; the
refusals are existing error codes (`invalid_grant`, the sign-in error).
