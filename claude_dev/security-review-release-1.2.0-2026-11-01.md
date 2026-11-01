# Security review — release 1.2.0, combined (F4, W5.3)

**Date:** 2026-11-01.
**Against:** `claude/social-gap-1.2.0` at `e8de849`, the whole plan diff
`origin/main...HEAD` (59 commits, 169 files, about 22 600 lines added). It
ships G-A native sign-in with a provider ID token (#816), G-B `axiam_idp_hint`
and `default_idp` (#817), G-C refresh-token replay revokes the session (#818),
G-D `client_id` and `axiam_exchanged` on exchanged tokens (#819), the
administrator OAuth2-client audit (#834), W4.0 (#836), the version bump to
1.2.0, contract 1.65 and the release and upgrade notes.
**Scope:** what the per-wave reviews could not see. Each wave had its own F4
review with two addenda
([W1](security-review-social-gap-w1-2026-10-30.md),
[W2](security-review-social-gap-w2-2026-10-31.md),
[W3](security-review-social-gap-w3-2026-10-31.md)) and the SDK contract had
[its own](sdk-contract-1.65-conformance-review.md). Their closed findings are
not re-opened here. This review covers the interactions *between* the waves
(G-A × G-C, G-A × G-D, G-A × G-B, D-N12 sessions × logout, `default_idp` ×
the per-tenant native trust), the release invariants in the final tree, schema
v110 to v113 taken together, the defaults and their upgrade text, the
security-relevant documentation against the code, and a targeted regression
gate. Plan: [`social-login-gap-plan-2026-10-30.md`](social-login-gap-plan-2026-10-30.md)
§4.1, §5 (D-N1 … D-N38), §7, §8.
**Method:** reading the final tree, not the reports. Every invariant was
re-derived from the code or by running the check; the threat-model counts
were re-derived from `ThreatDragonModels/Axiam/Axiam.json`; every Rust
identifier cited in T-37, T-254, T-471 and T-489 … T-494 was looked up (all
that are test names exist; the rest are field, setting or audit-value names).

Throw-away probes, kept out of the tree (deleted before this commit):

- *REST* (`crates/axiam-api-rest/tests/f4r12_probe.rs`, a copy of
  `provider_id_token_test.rs`'s harness with two tests appended):
  (1) a native sign-in, one rotation, then the **predecessor replayed by its
  own client**: `400`, the successor is then refused, UserInfo with the
  rotated access token is `401`, and the audit row reads
  `response: "revoked_session"`, `token_client_id` = the presenting client —
  G-C revokes exactly the native session; (2) a native sign-in, then
  **RP-initiated logout** with the native ID token as `id_token_hint`: the
  session row is gone and the original access token is `401` at UserInfo, but
  **the refresh token still rotates (`200`)** and mints an access token naming
  the dead `sid` (F4-R12-01).
- *DB* (`crates/axiam-db/tests/f4r12_upgrade_probe.rs`): a fully migrated
  datastore with v110 … v113 un-applied (their fields, index and table
  removed, their `_migration` stamps deleted) and 1.1.3-shaped
  `oauth2_refresh_token` rows written, then `run_migrations` twice: both
  succeed, 110 … 113 are each recorded once, `idx_refresh_token_session` and
  the replay table's unique index exist.

This review fixes nothing; every finding is a recommendation.

---

## 0. Summary

The release holds together. The four items touch each other in fewer places
than their surface suggests, and where they do the result is the intended
one: a native sign-in's refresh token lives under a session of its own
(D-N12), so a replay of it (G-C) revokes that device and nothing else — the
cleanest case G-C has (probe 1); a native access token is an ordinary
client-bound user token to token exchange, never an exchanged one, and the
provider's ID token is still refused by X4 by name and by shape; nothing on
the native grant reads `axiam_idp_hint`, `default_idp` or `fresh`, and the
native session has no browser cookie, so it can never become an OP session
behind the login hop. Every invariant holds in the final tree, v110 … v113 are
additive and re-apply over a 1.1.3 schema, every new capability is off, and
every suite the waves touched is green (§10).

The findings are in the seams. The important one: **ending a native session
does not end its refresh token** (F4-R12-01, Low). RP-initiated logout,
`/api/v1/auth/logout` with the native token, and the session's own expiry
remove the row, but the OAuth2 refresh token — which slides — keeps minting
access tokens. Those die at AXIAM's session check, but are `active` at
introspection and valid at any JWT-verifying resource server, and the user's
session list no longer shows the device that still holds a working grant.
This is the pre-existing "OAuth2 refresh tokens are not session-scoped" rule,
but D-N12 was chosen *so that* logout would end native tokens, and the docs,
CONTRACT §37.2 rule 8 and the grant's module docs say it does. Two more Lows (the
per-tenant native trust is per *organization* under inheritance, and the
documented mitigation does not hold there; the G-C "ends the console session"
text is true only until the console session first rotates) and three
Informational items follow. No High, no Medium.

| ID | Severity | Where | Finding | Fix |
|---|---|---|---|---|
| **F4-R12-01** | **Low** | `crates/axiam-auth/src/service.rs:1305` (`logout`); `crates/axiam-api-rest/src/handlers/oauth2.rs` `end_session` (`:6507`), `end_session_at_cookie_path`; `crates/axiam-api-rest/src/handlers/auth.rs:680`; `crates/axiam-oauth2/src/provider_id_token.rs:529-602`; `crates/axiam-oauth2/src/token.rs:3293` (sliding expiry); docs `native-sign-in.md` "The session it creates", CONTRACT §37.2 rule 8 | Invalidating or outliving a native session leaves its OAuth2 refresh token live: it rotates and mints access tokens with a dead `sid` (probe 2). The native client is never recorded as a session participant, so no back-channel logout reaches it either. Docs say logout "ends the session and so the tokens". | S (revoke by session on single-session logout, reusing G-C's `revoke_all_for_session` and its v110 index) or XS (correct the text), maintainer decision |
| **F4-R12-02** | Low | `crates/axiam-federation/src/provider_resolution.rs:50` with `native_login.rs:771`; `docs/api/native-sign-in.md:132-143`; T-489; upgrade notes §3 | An organization-tenant provider with `allow_tenant_inheritance` carries its `native_login` block into every tenant of the organization. The D-N18 residual is then per organization, and the documented mitigation ("keep apps with different privilege in different tenants") does not separate them. | XS (docs + T-489 sentence) |
| **F4-R12-03** | Low | `crates/axiam-auth/src/service.rs:1188-1262` (`refresh` consumes the row, creates a new id); `crates/axiam-oauth2/src/token.rs:1273`; `docs/deployment/README.md:2792-2801`; CHANGELOG *Changed* | G-C invalidates the session id the replayed refresh token names. For a browser code grant that is the console session as it was at `/oauth2/authorize`; once the console has refreshed (which consumes that row and mints a new id), the invalidation is a no-op and the console/SSO session survives. The refresh tokens are still all revoked (the security property holds); the documented "ends the console (SSO) session: the user is signed out of every relying party sharing it" does not. | XS (text) |
| F4-R12-04 | Info | `crates/axiam-oauth2/src/token_exchange.rs:107`; `docs/api/token-exchange.md:121-127`; T-471 | The actor table omits the native grant. A native token is accepted as an `actor_token` by its own client (`act.sub` = the user), which is right; combined with D-N18, a client that redeemed *another app's* token through the per-tenant trust gets an actor-attributable token for that user. Same residual, one more consequence, unstated. | XS |
| F4-R12-05 | Info | `docs/deployment/README.md:2804`; CHANGELOG *Changed* ("a token revoked at logout is not a replay") | Reads as if logout revokes refresh tokens; only `/oauth2/revoke`, password reset and the user-wide revocations do (see F4-R12-01). | XS |
| F4-R12-06 | Info | `crates/axiam-api-rest/src/handlers/oauth2.rs` `handle_provider_id_token` (`native_request` arm) | A request missing `provider`/`id_token`/`nonce` returns `invalid_request` without a `federation.native_login` row, unlike every other refusal after step 1 (the handler doc says "every attempt that passes step 1 is audited"). Nothing is spent; only the audit promise is broken. | XS |

---

## 1. Invariant verdicts

| # | Invariant | Verdict | Evidence |
|---|---|---|---|
| 1 | X4 refuses ID tokens by name and by shape; its tests unchanged since `main` | **Holds** | `git diff origin/main...HEAD --numstat`: `external_token_exchange_test.rs` 45 / **0**, `token_exchange_test.rs` 174 / 0, `keycloak_cross_vendor_token_exchange_test.rs` 2 / 0 — append-only (one new test, fixture fields). In `axiam-federation/src/token_exchange.rs` the only removed lines are the inline marker loop and `typ` match, replaced by `crate::token_shape` with the same four claims, the same six types and the same normalisation (trim, ASCII-lowercase, strip `application/`); a marker the match does not know refuses (`_ => true`). Its in-file test module gained a `#[cfg(test)]` seam and lost nothing. The name refusal (`TOKEN_TYPE_ID_TOKEN`, `TOKEN_TYPE_REFRESH_TOKEN`, `axiam-oauth2/src/token_exchange.rs:575-590`) is unchanged; `refresh_and_id_subject_token_types_are_refused_by_name`, `refresh_and_id_token_types_are_refused_from_either_header_or_claim`, `no_named_type_is_accepted_by_both_paths` and `the_token_exchange_still_refuses_the_same_id_token` are green. |
| 2 | No refresh token from token exchange | **Holds** | Structural: `TokenExchangeResponse` (`token_exchange.rs:156`) has no refresh member; both the internal (`:850`) and external paths build it. |
| 3 | `fapi2` grace window as T-254 decided | **Holds** | `fapi.rs` changed only by two fixture fields; `refresh_rotation_grace_secs` is `fapi2`-only, 60 s. The only removed lines in `token.rs` are two `record_refresh_replay` calls (re-signatured) and the old `client_id: None` comment on introspection. In-window presentations still take the live-row branch and are accepted; G-C acts only on the not-found/superseded branch. |
| 4 | Crate layering | **Holds** | `scripts/check-crate-layering.py`: "19 crates, 62 internal production edge(s), all pointing inward; 4 declared test-only inversion(s)." |
| 5 | `missing_docs` on `axiam-authz`, `axiam-directory` | **Holds** | Neither crate is in the diff; `cargo clippy -p <crate> --lib -- -D warnings` clean for both (§10). |
| 6 | Every migration since 1.1.0 additive | **Holds** | v110 … v113 are `DEFINE … IF NOT EXISTS` only, `option<…>` with no `DEFAULT` or backfill (v112's `created_at` default is on a new table); pinned by `v110…`, `v111…`, `v112…`, `v113_adds_only_the_client_default_idp_column` and `is_additive`; schema tests green; the upgrade probe re-applies them over a v109 datastore with rows, twice. |
| 7 | Spec, registry, links | **Holds** | `check-spec-digest.py` matches (`sha256:d8ba5eff…`, `info.version` 1.2.0); `gen-management-registry.py --check`: 202 operations, 29 namespaces, in sync; `check-doc-links.sh`: 559 links across 79 files. |
| 8 | Threat model | **Holds** | Re-derived from `Axiam.json`: version 2.45.0, 494 threats, numbers 1 … 494 with no gap or duplicate, 463 Mitigated / 21 Open / 10 NotApplicable, and every per-diagram count and severity split in `threat-model-stride.md` §5 matches the model (OAuth2 92, federation 128, …). T-489 … T-494 are new and Mitigated; T-37, T-254, T-471 amended. |

---

## 2. F4-R12-01 (Low) — ending a native session does not end its refresh token

**Where.** `issue_provider_id_token_grant` (`provider_id_token.rs:529`) creates
a session whose `expires_at` is sign-in + the refresh lifetime and a refresh
token naming it (`session_id: Some(session.id)`, `:588`). It records no
`session_client` participant (only `/oauth2/authorize` does, `oauth2.rs:2318`).
Every single-session ending is `AuthService::logout` →
`SessionRepository::invalidate`, which deletes the row and touches no OAuth2
refresh token: RP-initiated logout (`end_session`, `:6507`, reached with the
native ID token, which carries `sid`), the cookie-path logout, and
`POST /api/v1/auth/logout` (which takes the session from the bearer token's
`sid`, so a native access token logs out its own session the same way). The
refresh grant never asks whether `stored.session_id` is live — deliberately,
because console refresh consumes browser session rows (`token.rs:975-994`) —
and rotation slides the expiry (`token.rs:3293`).

**Scenario.** (a) The app signs the user out with `end_session`; probe 2: the
session is gone, UserInfo refuses the old access token, and the refresh token
still rotates and mints a fresh access token naming the dead session. (b) A
lost phone: the user or an administrator ends that device's session (or the
session simply passes its fixed `expires_at`); whoever holds the app's
storage keeps a sliding grant. The fresh access tokens are refused by AXIAM's
own session-validated APIs and UserInfo, but `POST /oauth2/introspect`
(which checks no session) reports them `active`, and a resource server that
verifies the JWT locally accepts them for 15 minutes each, indefinitely. The
user's session list no longer shows the device. The only levers that do end
it are user-wide: password reset/change, disable/delete,
`revoke_all_sessions` (they all call `revoke_all_for_user`), and a G-C replay.
No back-channel logout is ever sent to the native client (no participant row).

**Why it is in this review.** It is the pre-existing rule for every OAuth2
refresh token (`service.rs:1356`: "OAuth2 tokens are not session-scoped"), so
browser clients behave the same. But D-N12 chose a session *for* this
property, and the text promises it: `docs/api/native-sign-in.md` ("logging
out, a password reset or an administrator's revocation ends the session and
so the tokens"), CONTRACT §37.2 rule 8 ("so logout, a password reset or an
administrator's revocation ends the tokens"), the module docs of
`provider_id_token.rs` ("ending the session (logout, …) ends the tokens"). For
the native session specifically the fix is safe in a way it is not for
browser sessions: its id never rotates (nobody holds its console credential),
so "revoke the refresh tokens of this session" means exactly "of this
device".

**Recommendation (maintainer decision).** (A, preferred, S) make
`AuthService::logout` also call `refresh_token_repo.revoke_all_for_session`
— the G-C repository method, served by the v110 index — at least for
sessions with no `browser_token_hash`; record the native client as a session
participant at issue so back-channel logout reaches it; add the probe-2
scenario as a test. Optionally cap the native refresh chain at the session's
`expires_at`. (B, XS) keep the behaviour and correct the three texts: logout
ends the session and its access tokens at AXIAM's session check; the refresh
token ends only through `/oauth2/revoke` or a user-wide revocation, so an app
calls `/oauth2/revoke` on sign-out. Either way CONTRACT §37.2 rule 8 changes
(a text-only contract fix).

---

## 3. F4-R12-02 (Low) — under inheritance the native trust is per organization

**Where.** `resolve_native_provider` (`native_login.rs:771`) resolves against
`effective_providers` (`provider_resolution.rs:50`): the tenant's own enabled
configurations plus the organization tenant's enabled, inheritable,
unshadowed ones. An organization provider's `native_login` block therefore
applies in every tenant of the organization, and the user is resolved (or
JIT-provisioned) in whichever tenant the request names.

**Scenario.** An organization operator enables native sign-in on the
organization's Google provider for the consumer app's iOS client ID and
leaves inheritance on. Following `docs/api/native-sign-in.md`'s advice, the
staff app lives in another tenant. A leaked consumer-app token and its raw nonce (the W2 "holder of a leaked
token" case) still redeem there through any client holding the grant: the separation the docs offer as
the D-N18 mitigation is not one. A tenant administrator can only opt out by
shadowing the provider (a configuration of the same override key, even a
disabled one).

**Recommendation (XS).** Say it in the D-N18 paragraph, T-489 and upgrade
notes §3: "per tenant — and, for an inherited organization provider, per
organization"; the mitigation is different *providers*, or no inheritance for
a provider with native sign-in on, or a shadowing configuration in the tenant
that must not accept it. No code change is needed for 1.2.0.

---

## 4. F4-R12-03 (Low) — G-C reaches the console session only until it rotates

**Where.** A browser code grant's refresh token carries the session id of the
console session at `/oauth2/authorize` (`user.session_id`). `AuthService::refresh`
consumes that row and creates a new one (new id, same `browser_token_hash`),
so after the first console refresh the id the OAuth2 grant names is gone.
G-C's `invalidate(session_id)` is then an idempotent delete of nothing, and
the live console session (and the OP cookie behind every other relying party)
survives.

**What still holds.** `revoke_all_for_session` keys on the same id, which
every rotation of the OAuth2 chain copies, so the successor and every refresh
token issued under that sign-in are revoked: the BCP property G-C exists for
is intact, and the audit row is `revoked_session` (the delete does not fail).
The other relying parties' *access* tokens already named the consumed row and
were refused at the session check since the console rotated.

**Recommendation (XS).** Qualify `docs/deployment/README.md` "What the session
covers", the CHANGELOG *Changed* line and the `RefreshReuseResponse` rustdoc:
the replay revokes every refresh token issued under that sign-in; it ends the
console/SSO session too only while that session has not been refreshed since
the code was issued. If ending the SSO session is wanted, it needs a lineage
key on the session (out of scope; a later item).

---

## 5. Informational

- **F4-R12-04 — native tokens as actors.** `actor_token_client` admits a token
  with `client_id` and no exchange marker; a native token qualifies, so its
  own client can present it as `actor_token` (`act.sub` = the user). That is
  the code-grant rule and correct. Under D-N18 a client that redeemed another
  listed app's token gains the same attribution; it is the same residual. Add
  "native sign-in" to the "code, refresh, CIBA or device grant" row of
  `docs/api/token-exchange.md`'s actor table and one clause to T-489.
- **F4-R12-05 — "a token revoked at logout".** `docs/deployment/README.md:2804`
  and the CHANGELOG list it among non-replays; single-session logout revokes no
  refresh token (F4-R12-01). Say "revoked by `/oauth2/revoke`, a password
  reset or a user-wide revocation".
- **F4-R12-06 — unaudited `invalid_request`.** In `handle_provider_id_token`
  the `native_request` arm returns without `audit.refused(...)`; the other
  step-2 refusals write one. Add the call (reason `invalid_request`) or narrow
  the handler's doc comment.

---

## 6. Cross-wave interactions — what holds

- **G-A × G-C.** The native refresh token names the native session; the
  session's console credential is a random hash nobody holds, so its id never
  rotates. A replay by the token's own client revokes that session and every
  refresh token under it — this device only; other devices' native sessions
  and the user's browser sessions are untouched (probe 1, `revoked_session`).
  A public native client without DPoP revokes on its own `client_id`, as W1
  decided (#821); with DPoP the proof is required.
- **G-A × G-D.** A native access token carries `client_id` and `sid` and no
  `axiam_exchanged`: as a `subject_token` it is an ordinary user token, and the
  exchanged result carries the marker and no `sid`; as an `actor_token` see
  F4-R12-04. The AXIAM ID token the grant returns is refused by name at B3;
  the provider's ID token is refused by X4 by name and shape and accepted by
  the grant only with ID-token shape — one marker list, partitioned by test.
  `admissible_session` refuses an exchanged token (`axiam_exchanged`) at the
  session-validated APIs.
- **G-A × G-B.** `TokenRequest` has no hint member; nothing in
  `provider_id_token.rs` or `native_login.rs` reads `axiam_idp_hint`,
  `default_idp` or `fresh`; the server never reads `fresh` back
  (`FRESH_LOGIN_PARAM` is written in `login_hop.rs:690` only). The native
  session has `browser_token_hash: None`, so it cannot satisfy
  `/oauth2/authorize` or be resumed by the SSO round trip (#832/#835).
- **`default_idp` × native trust.** Independent: `default_idp` steers the
  browser hop only and is admin-only (DCR/RFC 7592/CIMD cannot set it, and
  DCR grants are limited to `authorization_code`/`refresh_token`, so the
  native grant is admin-only too). Neither narrows the other; the per-client
  binding stays the D-N18 residual.
- **G-B × `login.post_auth` × SSO round trip × native.** The native grant runs
  the gate (#828) before any session exists; the browser federated leg runs it
  in the federation callback as before; the resumed hop then finds an OP
  session and issues a code. The hop record is bound to the start's `state`
  (D-N29). Nothing here depends on the hint.
- **D-N12 × logout / back-channel.** See F4-R12-01; access tokens die at the
  session check as promised.

## 7. Schema v110 … v113 together

- Additive and idempotent (invariant 6; upgrade probe).
- Upgrade from 1.1.3 (v109): new fields are `option<…>` on SCHEMAFULL tables,
  so existing rows read `NONE` and resolve to the defaults —
  `revoke_session` (`refresh_reuse_response_defaults_round_trips_and_tightens`
  UNSETs the column), native sign-in disabled
  (`an_omitted_native_login_block_is_disabled_and_an_unrelated_update_keeps_it`),
  no `default_idp`. `idx_refresh_token_session` builds from existing rows and is
  non-unique.
- Purge/sweep: `every_tenant_scoped_table_is_purged` is green;
  `federation_id_token_replay` has no `tenant_id`, is deliberately absent from
  `TENANT_PURGE_ORDER` (comment in `tenant_purge.rs`), and is swept by the new
  `federation_id_token_replay` cleanup job (required constructor argument in
  `cleanup.rs`; `cleanup_task` green). The other three versions add columns to
  tables already purged.
- F4-W2-15: the dev-database note (drop the table and the v112 stamp) is in
  upgrade notes §2 and the CHANGELOG upgrade box; still to go into the PR
  description as W2 asked.

## 8. Defaults and upgrade text

- **Off by default:** `native_login.enabled` false per provider (v111 reads
  `NONE` as disabled), and the grant per client (admin API only); the
  discovery listing of the grant (D-N15) opens nothing. `axiam_idp_hint` and
  `default_idp` change nothing for a client that sends neither.
- **G-C:** `revoke_session` default (D-N2), `refuse` tighten-only (D-N8:
  `refresh_reuse_response_is_at_least` on validation and on the clearing path,
  `settings.rs:2012`, `:2335`). The pre-1.2.0-client `PUT` reset to the stricter
  value is stated.
- **Upgrade notes and CHANGELOG** state the behaviour change, the opt-out, the
  schema, the off-by-default grant, the SDK server floor (D-N33: `native_login`
  required in federation-config responses), the C SOVERSION 3 and C++
  SOVERSION 5, and the open C165-24/-28. Accurate, bar F4-R12-01 (logout),
  F4-R12-03 (console session reach) and F4-R12-05.

## 9. Documentation against the code

Checked against the code: `docs/api/native-sign-in.md` (order of checks,
nonce rule, azp-first audience, deployment-wide single use, `exp` + 120 s,
per-tenant-and-address bucket, consent spends the token), CONTRACT §37
(errors table matches the handler: `invalid_request` for a missing/over-long
nonce, `unauthorized_client`, `invalid_grant` with the one description, `429
rate_limit_exceeded` with `Retry-After: 60`, `server_error` with a
description), §12.1 / §26.2 (`idp_hint`, PAR carrying the begin URL's hint,
D-N36), `docs/admin/oidc-authn-parameters.md` and `browser-login-hop.md`
(`fresh` written last, first leg and honour lane only, never read back),
`docs/api/token-exchange.md` (`client_id`, `axiam_exchanged`, not echoed by
introspection), `docs/deployment/README.md` G-C, and T-37, T-254, T-471,
T-489 … T-494. Deviations: F4-R12-01 … -05. (A minor one not filed: §37.2 rule
2 says the slug is compared "exactly"; the server trims surrounding
whitespace first. The SDK rule — send as given — is unaffected.)

## 10. Regression gate

Environment as `CLAUDE.md` asks (`CARGO_INCREMENTAL=0`, no debug info,
swagger-ui placeholder, `protoc` present). All exit 0 unless stated.

| Suite | Command | Result |
|---|---|---|
| REST, ten binaries | `cargo test -p axiam-api-rest --no-default-features --test provider_id_token_test --test oauth2_flow_test --test token_exchange_test --test external_token_exchange_test --test oauth2_idp_hint_test --test oauth2_honour_lane_test --test par_test --test oauth2_client_test --test federation_login_providers_test --test rate_limit_bucket_names_test` | **340 passed**, 0 failed: 21 / 46 / 31 / 28 / 19 / 42 / 31 / 46 / 55 / 21 (the plan's after-counts exactly) |
| axiam-oauth2 | `cargo test -p axiam-oauth2 --lib --test token_service` | **lib 659, token_service 166** passed |
| axiam-federation | `cargo test -p axiam-federation --no-default-features --lib` | **200 passed** with SAML off (53 `native_login`, the `token_shape`/`token_exchange` tests among them); and with default features (libxml2 is present here), `cargo test -p axiam-federation --lib`: **404 passed**, the plan's W2 after-count |
| axiam-db | `cargo test -p axiam-db --lib --test schema_test --test federation_id_token_replay_test` | **lib 340** (`every_tenant_scoped_table_is_purged` and the v110 … v113 pins among them), **schema_test 13**, **federation_id_token_replay_test 4** passed |
| axiam-auth | `cargo test -p axiam-auth --lib` | **280 passed**, 1 ignored (pre-existing live-service ignore) |
| axiam-server | `cargo test -p axiam-server --no-default-features --lib --test cleanup_task` | **lib 175, cleanup_task 65** passed |
| clippy | `cargo clippy -p axiam-authz --lib -- -D warnings`; same for `axiam-directory` | both clean (no warnings) |
| scripts | `check-crate-layering.py`, `check-spec-digest.py`, `gen-management-registry.py --check`, `check-doc-links.sh` | all green |
| frontend | `cd frontend && npx vitest run` | **124 files, 2490 tests** passed (the plan's W4.0 count) |
| probes | `f4r12_probe` (2), `f4r12_upgrade_probe` (1) | passed; findings as stated; deleted |

Not run: the OIDF conformance suite, a real Google/Apple token, `npm run
test:a11y`, the full workspace in one invocation, the eleven SDK suites (their
own CI and the contract review cover them).

## 11. Needs a maintainer decision

1. **F4-R12-01:** (A) revoke a session's refresh tokens on single-session
   logout (at least for browser-less sessions) and record the native client as
   a participant, or (B) document that logout ends the native session's
   access tokens but not its refresh token, and tell apps to call
   `/oauth2/revoke`. (B) is text-only for 1.2.0; (A) is the behaviour D-N12
   was chosen for. Either way, CONTRACT §37.2 rule 8 is corrected.
2. **F4-R12-02, -03, -05:** text fixes, recommended for the release PR.
3. **F4-R12-04, -06:** any later commit.

Nothing here blocks the release on security grounds beyond the decision in
item 1; no finding is High or Medium.

---

## Addendum 1 — sweeps re-check (2026-11-01)

**Against:** `claude/social-gap-1.2.0` at `92bf8d3`, the commits since this
review (`5ae4c02..92bf8d3`): `a377893` and `0274ad2` (D-N39 … D-N42 recorded),
`d6083b2` (#839), `2da13a6` (#840), `60f0cdf` (#841), `9c040db` (#842),
`92bf8d3` (D-N42). 24 files, about 1 350 lines added. Method as above: the
final tree read, every claim of the commit messages re-derived from the code,
the touched suites run, one throw-away probe (deleted before this commit).

**Probe** (appended to a copy of `provider_id_token_test.rs`, restored with
`git checkout`): a native sign-in, then the session row deleted directly —
the state `AuthService::logout` leaves when `session_invalidate` succeeds and
`refresh_tokens_revoke` fails — then the retry the `500` invites:
`POST /api/v1/auth/logout` with the same bearer token is **`401`**, the
refresh token still rotates (**`200`**), and only `end_session` with the
native ID token as `id_token_hint` then revokes it (F4-R12-07).

### A1.1 Status of the review's findings and of the sweep items

| Item | Status | Evidence |
|---|---|---|
| **F4-R12-01** (Low) | **Closed** by #839 (`d6083b2`, D-N39 option A), with the residuals F4-R12-07 and F4-R12-08 below | `AuthService::logout` (`service.rs:1336`) now calls `revoke_all_for_session` beside `invalidate`; it is the only caller of `SessionRepository::invalidate` outside the two replay paths, so `POST /auth/logout`, `end_session`, `end_session_at_cookie_path` and SAML SLO (`saml_idp_slo.rs:607`) all revoke. The user-wide paths (password reset/change, disable/delete, `revoke_all_sessions`, SCIM `revoke_live_credentials`, directory sync, and now MFA reset) already used `revoke_all_for_user`. A failed write fails every logout path: `/auth/logout` 500, `end_session` and the cookie hop `logout_incomplete_page` (500, cookies cleared, no RP redirect), SAML SLO `revocation_failed`. A logout-revoked token is not stamped `rotated_at` (`revoke_all_for_session` sets `revoked` only), so `find_rotated` does not see it: re-presented, it is `invalid_grant` with no G-C revocation and no `oauth2.refresh_token_replayed` row (pinned in `rp_logout_of_a_native_session_revokes_its_refresh_token`). The texts it contradicted (native-sign-in.md "The session it creates", CONTRACT §37.2 rule 8, the `provider_id_token.rs` module docs) are now true without a contract change. **Participant recording is safe:** the row is written in `handle_provider_id_token` only on the grant's success, with the session id the grant itself just created (`NativeSignIn::session_id`), the authenticated client's `client_id` and the resolved subject — no request field names a session, so a native client can only ever join its own sign-in's session. Its failure is logged and swallowed, as at `/oauth2/authorize`. **Not covered** (and not claimed by any text): a native session that passes its fixed `expires_at` is swept while its sliding refresh chain continues — the optional cap of §2 was not taken. Info; later. |
| **F4-R12-02** (Low) | **Closed** (`2da13a6`) | native-sign-in.md gains "An inherited organization provider spans the organization" with the three separations (different providers, no inheritance, a shadowing configuration); upgrade notes §3 and T-489 say "per organization" for an inherited provider. |
| **F4-R12-03** (Low) | **Closed** (text, `2da13a6`) | Deployment guide "What the session covers" and the CHANGELOG *Changed* line now say the console/SSO session ends only while it has not been refreshed since the code was issued, and that the refresh tokens are revoked either way; the lineage key is named as absent. The `RefreshReuseResponse` rustdoc (`settings.rs:164`) never claimed the console session ends — "the console sign-in included" is about its refresh tokens — so it needed no change. The same root cause now has a second consequence on the logout side: F4-R12-08. |
| F4-R12-04 (Info) | **Closed** (`2da13a6`) | token-exchange.md's actor table lists the native sign-in grant, with a paragraph on the D-N18 consequence; T-489 gains the clause. |
| F4-R12-05 (Info) | **Closed** (`2da13a6`) | Deployment guide and CHANGELOG: "revoked by a logout of its session (D-N39), by `/oauth2/revoke`, by a password reset or by another user-wide revocation" — true since D-N39. |
| F4-R12-06 (Info) | **Closed** (code, `2da13a6`) | The `native_request` arm now calls `audit.refused(state, None, e.error_code())` after the client check and the bucket, so an unauthenticated caller writes no row; pinned in `a_missing_parameter_is_invalid_request`; native-sign-in.md's reason codes list the request-level OAuth2 codes. |
| **#841 / D-N40** | **Closed** (`60f0cdf`), one Info (F4-R12-11) | `MfaMethodService::reset_mfa` revokes `revoke_all_for_user` after the sessions; the repository is a required constructor argument, wired in `AppState::for_test` and `boot.rs` (the same `SurrealRefreshTokenRepository` the directory sync holds). **Failure ordering:** the steps run in sequence with `?` — credentials, user row, sessions, refresh tokens — so the only half-states are "credentials gone, sessions and tokens live" (a failure at the session step, unchanged) and "sessions gone, tokens live" (a failure at the new step). Neither is the reverse hole (tokens revoked over a live session cannot happen, and would be harmless). In the second state the old refresh tokens still mint access tokens until the retry — refused at AXIAM's session check, `active` at introspection — which is exactly the pre-#841 behaviour, bounded now by the 500. **Retryable:** every step is idempotent and an administrator retries with their own session; a self-service caller has just lost theirs, but self-service reset is allowed only when the tenant does not enforce MFA, so a password sign-in gives a full session and the retry works. Tests: the service unit (another user's tokens untouched) and the end-to-end `oauth2_flow_test` case. |
| **#842 / D-N41** | **Closed** (`9c040db`), one Info (F4-R12-09) | `revoke_after_code_replay` adds `revoke_all_for_session` beside the §10.5 `invalidate`, attempted independently; the answer stays `invalid_grant` on every branch (no 500, no oracle beyond the timing the rustdoc already states). Reached only after client authentication and only for a code row with `used = true` and the same `client_id` and `redirect_uri` (`replayed_session`); used codes are deleted by the next `oauth2_auth_code` sweep, which bounds the window. **× G-C:** a token revoked here carries no `rotated_at`, so a later refresh presentation of the live token is a stale credential (no second revocation, no replay row — pinned end to end); a predecessor that *was* rotated before the code replay is a G-C replay as before, whose writes are then idempotent no-ops (count 0, `revoked_session`). **Race with a concurrent refresh:** closed by the refresh grant's create-before-retire order (`token.rs:3355`): the successor is inserted with the same `session_id` *before* the predecessor's CAS (`revoke_rotated`/`supersede`, both `revoked = false`). If the single-statement `revoke_all_for_session` lands before the insert, the CAS then fails, the successor is revoked and the refresh answers `invalid_grant`; if it lands after, it revokes the successor itself. The only escape is the orphan clean-up failing as well (logged at `warn`), a double fault. The same argument covers logout (D-N39) and G-C. |
| **D-N42** | **Closed** (`92bf8d3`), one Info (F4-R12-10) | The spec diff is exactly the two `500` entries (`GET /oauth2/end_session`, `GET /oauth2/authorize/logout`) and `x-axiam-spec-digest`; the registry diff is `spec_digest` only (202 operations, 29 namespaces). Re-derived: `cargo build -p axiam-server --no-default-features` then `--dump-openapi` is **byte-identical** to `sdks/openapi.json`; `check-spec-digest.py` matches `sha256:b07d6d7b…`; `gen-management-registry.py --check` in sync. `sdks/CONTRACT.md` and `proto/` unchanged. |

### A1.2 Invariants re-checked at `92bf8d3`

| # | Invariant | Verdict |
|---|---|---|
| 1 | X4 tests unchanged | **Holds** — `external_token_exchange_test.rs`, `token_exchange_test.rs`, `keycloak_cross_vendor_token_exchange_test.rs` untouched since `5ae4c02` (vs `origin/main` still 45/0, 174/0, 2/0); suites green at 28 and 31. |
| 2 | No refresh token from exchange | **Holds** — `token_exchange.rs` untouched. |
| 3 | `fapi2` grace | **Holds** — `fapi.rs` untouched; the only `token.rs` hunks are `revoke_after_code_replay` and two doc comments; `supersede`/`revoke_rotated` and the rotation lane choice unchanged. |
| 4 | Crate layering | **Holds** — 19 crates, 62 inward edges, 4 declared test-only inversions. `MfaMethodService` takes the core `RefreshTokenRepository` trait; no new edge. |
| 5 | `missing_docs` crates | **Holds** — `axiam-authz`, `axiam-directory` not in the diff; clippy `-D warnings` clean on both. |
| 6 | No migration | **Holds** — `crates/axiam-db` untouched; no schema version. |
| 7 | Spec, registry, links | **Holds** — see D-N42; `check-doc-links.sh` 560 links across 79 files. |
| 8 | Threat model | **Holds** — `Axiam.json` 2.45.0, 494 threats, 1 … 494 unique; the diff amends the mitigation text of T-249, T-250 and T-489 only. |

### A1.3 New findings

| ID | Severity | Where | Finding | Fix |
|---|---|---|---|---|
| **F4-R12-07** | **Low** | `crates/axiam-auth/src/service.rs:1336` (`logout`); `handlers/auth.rs:686`; `handlers/oauth2.rs` `end_session_at_cookie_path`; upgrade notes §1a, CHANGELOG ("retry is safe") | The two logout writes run independently, so the common partial failure — session deleted, revocation failed — leaves a state the advertised retry cannot reach through the credential the caller used. `/auth/logout`'s bearer token is now refused at the session check (`401`, probe); the cookie hop's `500` page cleared the cookies, and even with one the lookup finds no row and answers the ordinary logged-out page — "signed out" over a live refresh token, the outcome D-N39 exists to prevent, one request later. SAML SLO probably the same (the session index no longer resolves; not probed). Only `end_session` with an `id_token_hint` naming the session, or `/oauth2/revoke` with the token, recovers. | S: in `logout`, revoke the refresh tokens first and delete the session only when that succeeded (every failure then leaves the session live, so the same credential retries), keeping `failed_writes`; or XS: name the recovery paths in place of "retry is safe". |
| **F4-R12-08** | **Low** | upgrade notes §1a "Limit"; CHANGELOG *Changed* ("Logging a session out now revokes its refresh tokens"); `docs/api/logout.md` | The documented limit is the common case, not an edge, and is stated only in the upgrade notes. A code grant names the session id current at `/oauth2/authorize`; the console's refresh replaces that row under a new id, and with 15-minute access tokens nearly every browser session that outlives one access token has refreshed. From then on `POST /auth/logout` and the cookie-hop logout end the console session but none of the code grants issued before the refresh. The mirror image is pre-existing (same root as F4-R12-03): RP-initiated logout with that RP's `id_token_hint` now revokes the grant's refresh tokens, but its `invalidate` of the old id is a no-op, so the OP/SSO session survives and the next `/oauth2/authorize` signs the user straight back in. The native case, the one D-N39 was decided for, is unaffected (its session id never rotates). Acceptable for 1.2.0 as documented behaviour. | XS now: state the limit in the CHANGELOG line, `docs/api/logout.md` and the deployment guide. Later (file an issue): a session lineage key, which closes this, F4-R12-03 and the RP-logout mirror together. |
| F4-R12-09 | Info | `crates/axiam-oauth2/src/token.rs` `revoke_after_code_replay`; T-250 | A code replay writes no audit row, only logs. Since D-N41 it revokes refresh tokens of *other* clients' grants under that session — an effect a relying party and the user see, with no audit trail; the comparable G-C path writes `oauth2.refresh_token_replayed` with `response` and `failed_writes`. The trigger is also cheap for a public client (the spent code, its `client_id` and `redirect_uri`, before PKCE, until the next sweep), the position W1 accepted for G-C (#821). | Post-1.2.0: an `oauth2.authorization_code_replayed` row in G-C's vocabulary (the outcome enum is already shared), or one sentence in T-250 that it is log-only. |
| F4-R12-10 | Info | `handlers/auth.rs` `logout` and `reset_mfa` `#[utoipa::path]`; `sdks/openapi.json` | D-N42 declared the two browser endpoints' 500 but not `POST /api/v1/auth/logout` (spec: `204`, `401`) or `POST /api/v1/users/{user_id}/reset-mfa` (`204`, `401`, `403`, `404`), which the CHANGELOG and upgrade notes now document as answering `500` on a failed revocation. Both could 500 before on a database error; 1.2.0 makes it a documented outcome. These are SDK-read endpoints, unlike the two declared. | XS, maintainer decision: declare both before the SDK PRs re-vendor `openapi.json` (one regeneration, digest only in the registry), or leave it to the next spec change. |
| F4-R12-11 | Info | `crates/axiam-api-rest/src/handlers/auth.rs` `reset_mfa`; `docs/api/logout.md` | Two small consequences of the sweeps. (a) `reset_mfa` emits the SSF `credential-change` events only after `MfaMethodService::reset_mfa` returns `Ok`; a failure at the new refresh-token step comes after the factors were evicted, and the retry reads `had_totp = false` and no passkeys, so those events are never sent (pre-existing for the session step; #841 adds a second failure point). (b) `docs/api/logout.md`, the normative logout page, was not updated for D-N39: it does not say logout revokes the session's refresh tokens, nor describe the `500` page, nor that native clients are participants; and its "expiry on the hint is not checked" now means an old ID token (sent in a `GET` URL) also revokes that grant's refresh tokens. Back-channel fan-out also runs *before* the logout writes, so on the `500` path the relying parties were already told the session ended — the conservative direction, but unstated. | XS: read the evicted factors before calling the service and emit from that list on success of the factor steps, or record it; one paragraph in `logout.md`. |

### A1.4 Regression gate

Environment as `CLAUDE.md` asks (`CARGO_INCREMENTAL=0`, no debug info,
swagger-ui placeholder, `protoc` present). All exit 0.

| Suite | Command | Result |
|---|---|---|
| axiam-auth | `cargo test -p axiam-auth --lib --test mfa_methods_test --test auth_service_test` | **lib 282** (1 ignored, pre-existing; +2 `logout_tests`), **auth_service_test 47**, **mfa_methods_test 23** |
| axiam-oauth2 | `cargo test -p axiam-oauth2 --lib --test token_service` | **lib 659**, **token_service 169** (+3, #842) |
| REST, six binaries | `cargo test -p axiam-api-rest --no-default-features --test oauth2_flow_test --test provider_id_token_test --test end_session_test --test auth_test --test token_exchange_test --test external_token_exchange_test` | **oauth2_flow_test 49** (+3), **provider_id_token_test 24** (+3; 25 with the probe), **end_session_test 16**, **auth_test 33**, **token_exchange_test 31**, **external_token_exchange_test 28** |
| axiam-server | `cargo test -p axiam-server --no-default-features --lib` | **175 passed** |
| clippy | `cargo clippy -p axiam-authz --lib -- -D warnings`; same for `axiam-directory` | both clean |
| spec | `cargo build -p axiam-server --no-default-features`, `--dump-openapi` vs `sdks/openapi.json` | byte-identical |
| scripts | `check-crate-layering.py`, `check-spec-digest.py`, `gen-management-registry.py --check`, `check-doc-links.sh` | all green |
| probe | F4-R12-07 retry probe | passed as stated; deleted |

### A1.5 Open after two sweeps

For the release PR description. Nothing here is High or Medium, and nothing
blocks 1.2.0 on security grounds.

1. **F4-R12-07 (Low)** — a half-failed logout cannot be retried with the
   credential that started it; reorder the writes (S) or correct "retry is
   safe" (XS).
2. **F4-R12-08 (Low)** — the D-N39 limit (console refresh, then logout) is
   the common case and stated only in the upgrade notes; state it in the
   CHANGELOG, `logout.md` and the deployment guide now, and file the session
   lineage key (it also closes F4-R12-03's residual and the RP-logout mirror).
3. **F4-R12-10 (Info)** — `/api/v1/auth/logout` and `/api/v1/users/{user_id}/reset-mfa`
   do not declare their documented `500`; decide before the SDK PRs
   re-vendor `openapi.json`.
4. **F4-R12-09, F4-R12-11 (Info)** — code-replay audit row; SSF events lost
   on a retried MFA reset; `logout.md` update. Any later commit.
5. **F4-R12-01 residual (Info)** — a native session's expiry does not end its
   sliding refresh chain (the optional cap); not claimed by any text; later.
6. Carried from earlier reviews: F4-W2-15's dev-database note in the PR
   description; the contract review's C165-24 and C165-28 (D-N38).

---

## Addendum 2 — targeted pass (2026-11-01, D-N43, D-N44, #843)

| Item | Commit | Change |
|---|---|---|
| F4-R12-07 (Low) | `c442c7c` | `AuthService::logout` revokes the session's refresh tokens first and deletes the session only on success; a failed logout is retryable with the same credential (tests `a_failed_revocation_leaves_the_session_for_a_retry_with_the_same_credential`, `a_failed_session_delete_after_the_revocation_is_retryable`). The cookie-hop and IdP-initiated SAML SLO failure pages keep the OP-session cookie (the credential their retry needs); `end_session` with a hint and SP-initiated SLO still clear every cookie. T-249 amended. |
| F4-R12-08 (Low) | `c6819a4` | The D-N39 limit (after a console refresh, `/auth/logout` and the cookie hop don't reach code grants issued earlier; RP logout with the grant's `id_token_hint` does; the SSO session survives that RP logout) stated in the CHANGELOG, `docs/api/logout.md` and the deployment guide; follow-up #844 (session lineage key). |
| F4-R12-11 (docs part) | `c6819a4` | `docs/api/logout.md` updated for D-N39; back-channel fan-out runs before the logout writes. |
| F4-R12-10 (Info) | `54fe63f` | The 500 of `POST /api/v1/auth/logout` and `POST /api/v1/users/{user_id}/reset-mfa` declared; spec and registry regenerated (`openapi.json` `782ad971…`, registry `e701c8ad…`) and re-vendored in all eleven SDK PRs. |

**Open (Info, recorded):** F4-R12-09 (a code replay writes no audit row), F4-R12-11 first part (a retried MFA reset sends no SSF events for factors the failed attempt already evicted), the F4-R12-01 residual (a native session's expiry does not cap its refresh chain), #844 (session lineage key).
