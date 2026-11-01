# Security review — social-login gap plan, wave W1 (F4)

**Date:** 2026-10-30.
**Against:** `claude/social-gap-w1`, the wave diff `85721de..3c7d031` (39 files,
about 2 650 lines added; `85721de` is the plan branch `claude/social-gap-1.2.0`).
Commits: `f978dff` (G-C, #818 — a refused refresh-token replay revokes its
session), `9f1c855` (G-D, #819 — exchanged tokens carry `client_id` and the
`axiam_exchanged` marker), `9e761ad` (plan text: D-N8, D-N9, the §3.4
correction), `3c7d031` (threat model 2.45.0: T-37, T-254, T-471 amended).
**Scope:** W1 of [`social-login-gap-plan-2026-10-30.md`](social-login-gap-plan-2026-10-30.md)
— §3.3 (G-C), §3.4 and its dated correction (G-D), the decisions D-N2, D-N4,
D-N8, D-N9 (§5), the commit gate (§6); read against
[`t254-refresh-grace-decision.md`](t254-refresh-grace-decision.md) (§1–§6 and the
new §7), [`token-exchange-design.md`](token-exchange-design.md) and
[`external-token-exchange-design.md`](external-token-exchange-design.md) on actor
tokens, #518 and D-5, and `CLAUDE.md` *Security Standards*.
**Method:** adversarial reading of the code, not of the commit messages: every
changed function, the sibling paths each one implies (the authorization-code
replay path, the fapi2 grace lane, the rotation race, every reader of
`AccessTokenClaims::client_id`, every writer of the new marker), the settings
write/read/clamp paths, the v110 DDL, the tests' assertions, and the three
threat-model amendments against the code they describe. One suspicion was
confirmed by a throw-away probe test (§2), kept out of the tree. This review
fixes nothing; every finding is a recommendation.

---

## 0. Summary

No Critical, High or Medium finding. **Both security properties the wave sets
out to deliver hold.** G-C revokes the replayed token's session and its refresh
tokens on every lane that refuses a replay, leaves the fapi2 grace exactly as
T-254 decided, and cannot be raced into leaving a usable successor behind (§3).
G-D's marker closes the actor-laundering route the executor found, for every
exchange shape, and no other token a client can obtain carries the marker or
can be made to (§4).

Two Lows, both in G-C. The revocation runs before — and without — the client
and sender-constraint checks, so a rotated token's bytes are a session kill
switch for whoever holds them through *any* client of the tenant, which
diverges from the authorization-code precedent the plan cites and is pinned by
no test (F4-W1-01). And the audit row says `refused` both for "the tenant
chose not to revoke" and for "the revocation failed half-way", so the one case
an operator must be told about is indistinguishable from policy (F4-W1-02).
Four Informational items follow.

| ID | Severity | Where | Finding |
|---|---|---|---|
| **F4-W1-01** | **Low** | `crates/axiam-oauth2/src/token.rs:2920`, `:1137`, `:1152` | A refused replay revokes before any client-ownership or sender-constraint check: any holder of a rotated token's bytes, authenticating as *any* client of the tenant (a public `client_id`, a DCR-registered client), revokes the session; diverges from the code-replay path, which binds the lookup to `client_id` and `redirect_uri`; untested. |
| **F4-W1-02** | **Low** | `crates/axiam-oauth2/src/token.rs:1205` | A revocation that failed (wholly or half-way) is audited `response: "refused"`, the value a `refuse` tenant also produces; the failure that leaves the attacker's successor live is invisible to an operator querying the audit log. |
| **F4-W1-03** | Informational | `crates/axiam-db/src/repository/oauth2_refresh_token.rs:535` | The "family" is the browser session, so one client's replay also revokes *other* clients' refresh tokens under that session and the console session; no back-channel logout is sent to those RPs. Same capability as RP-initiated logout, but silent; worth one sentence in the operator docs. |
| **F4-W1-04** | Informational | `crates/axiam-oauth2/tests/token_service.rs`, `crates/axiam-oauth2/src/token_exchange.rs:108` | Test gaps: the cross-client replay (F4-W1-01), a failing `invalidate` (only `revoke_all_for_session` is made to fail), and the `act` / `ext_exchange` fail-closed arms of `actor_token_client` are pinned by nothing. |
| **F4-W1-05** | Informational | `crates/axiam-auth/src/token.rs:1094` | `////// * **client_id is the exchanging client** …` — six slashes is a plain comment, not rustdoc; the bullet that documents the #819 contract is missing from `issue_exchanged_token`'s rendered docs. |
| **F4-W1-06** | Informational | `crates/axiam-core/src/models/settings.rs:250`, `:1396` | `#[schema(value_type = String)]` publishes `refresh_reuse_response` in `sdks/openapi.json` as a bare `string` with no `enum`, so the two legal values are invisible to the eleven SDKs' generators; and `SetOrgSettings` defaults the field, so an organization `PUT` written before 1.2.0 silently moves a `refuse` organization back to `revoke_session` (the strict direction — not a weakening, but an operator surprise). |

---

## 1. Invariant verdicts

| # | Invariant | Verdict | Evidence |
|---|---|---|---|
| 1 | X4 still refuses ID tokens by name and by shape; `every_id_token_marker_is_refused`, `refresh_and_id_subject_token_types_are_refused_by_name` unchanged | **Holds** | `axiam-federation` is untouched by the diff (`git diff --stat 85721de..HEAD -- crates/axiam-federation` empty); `every_id_token_marker_is_refused` is at `crates/axiam-federation/src/token_exchange.rs:817`, unchanged. The name refusals at `token_exchange.rs:579-592` are unchanged; `refresh_and_id_subject_token_types_are_refused_by_name` (`token_exchange.rs:1851`) is not in the diff and passes (`cargo test -p axiam-oauth2 --lib -- token_exchange refresh_reuse`: 35 passed). |
| 2 | No refresh token from token exchange | **Holds** | `TokenExchangeResponse` (`token_exchange.rs:156`) has no `refresh_token` field, so none can be serialized; `requested_token_type` other than access token is still refused (`:566`). The new REST test asserts `body.get("refresh_token").is_none()` for both B3 shapes. |
| 3 | The fapi2 grace (in-window accepted, 60 s) exactly as T-254 decided | **Holds** | `crates/axiam-oauth2/src/fapi.rs` is untouched (`FAPI2_REFRESH_ROTATION_GRACE_SECS = 60`, `:974`). The live-row branch (`token.rs:2945-2956`) still accepts when `refresh_rotation_grace_secs(&client).is_some()`; `record_refresh_replay` computes `response = None` when `accepted_under_grace` (`:1065`), so `respond_to_refused_replay` is never reached in the window. `supersede`/`revoke_rotated` WHERE clauses unchanged. Pinned by `g_c_a_fapi2_replay_inside_the_grace_is_accepted_and_revokes_nothing` (run, passes). |
| 4 | Crate layering | **Holds** | `python3 scripts/check-crate-layering.py` → "Crate layering OK: 19 crates, 62 internal production edge(s), all pointing inward; 4 declared test-only inversion(s)." The only new cross-crate edge is `axiam-api-rest::scope_policy` → `axiam_oauth2::refresh_reuse`, an existing direction. |
| 5 | `missing_docs` clean on axiam-authz / axiam-directory | **Holds (untouched)** | `git diff --stat 85721de..HEAD -- crates/axiam-authz crates/axiam-directory` is empty; neither crate depends on a changed public item that would add an undocumented re-export. |
| 6 | #518 / D-5: no obtainable token becomes an acceptable `actor_token` naming a non-consenting party | **Holds** | §4 below, attack by attack. |

---

## 2. F4-W1-01 (Low) — the revocation precedes, and ignores, the client and sender binding

**Where.** `TokenService::refresh`, the not-found branch, `token.rs:2920`:
`rotated_predecessor(tenant_id, &token_hash)` → `record_refresh_replay` →
`respond_to_refused_replay` (`:1152`). The ownership check
`stored.client_id != client_id` (`:2934`) and the DPoP refresh binding
(`enforce_refresh_token_binding`, further down) are on the *live-row* path only;
the doc comment at `:1137` makes the omission deliberate ("a rotated credential
in a second client's hands is more evidence of a leak, not less").

**What an attacker must hold.** The raw bytes of a rotated refresh token
(lookup is by its SHA-256 within the path's tenant), plus the ability to pass
client authentication as *any* client of that tenant whose registration lists
`refresh_token`. A public client passes with its `client_id` alone
(`carries_no_credential && …is_public()`), and where DCR is open anyone can
register one. Nothing about the *token's* client is required.

**Confirmed by probe.** A throw-away test (not committed) appended to
`token_service.rs`: a rotated row issued to `victim-client`, presented by
`client-1` → refused `invalid_grant`, and `revoke_all_for_session` and
`invalidate` both called with the victim's session. Passed.

**Failure scenario.** (a) A `fapi2` or DPoP-bound public client: its refresh
tokens are sender-constrained, so a leaked old token (log line, crash dump,
backup, a proxy that recorded a request body) is worthless to the thief for
*redemption* — but since G-C it is a kill switch for the user's session, usable
through any public client of the tenant, for as long as `find_rotated` finds the
row (30 days + 7 on `standard`, 7 days + 60 s on `fapi2`). (b) The
authorization-code replay path the plan cites as the precedent does **not**
behave this way: `revoke_after_code_replay` asks
`code_repo.replayed_session(tenant_id, code_hash, client_id, redirect_uri)`
(`token.rs:2045`), i.e. only the client the code was issued to, at its
redirect URI, triggers the revocation. The plan's "do what the code-replay path
does" and the threat model's T-254 sentence "That is what the authorization-code
replay path already does" overstate the equivalence on this point.

**Why only Low.** The attacker needs a credential leak first; the effect is
availability (one session signed out, re-login fixes it); and on `standard` the
BCP reasoning holds regardless of who presents. The T-254 amendment does state
the client is not compared, so this is a documented choice — but one with no
test and a different shape from its precedent.

**Recommended fix.** Either (preferred) revoke only when the presenting client
is the token's client (`rotated.client_id == client_id`), recording a
cross-client presentation as `response: "refused"` plus a `presenting_client`
key so the leak signal is kept without handing out the kill switch; or, if the
maintainer keeps the current rule, at least require the token's own client for
sender-constrained rows (`dpop_jkt.is_some()` or a `fapi2` client), pin the
chosen behaviour with a test, and correct the "what the code-replay path does"
sentences in T-254 and `t254-refresh-grace-decision.md` §7.

---

## 3. G-C — the questions, answered

**3.1 Denial of service.** See F4-W1-01 for what must be held. Beyond it: the
revocation is idempotent (`revoke = false` in the UPDATE's WHERE), served by
the new `idx_refresh_token_session (tenant_id, session_id)` rather than a table
scan, and a repeated replay of the same token costs one settings read, one
DELETE that finds nothing and one UPDATE that matches nothing — bounded by the
token endpoint's existing rate limiter. A token revoked at logout is not a
replay (`find_rotated` requires `rotated_at != NONE`) and revokes nothing;
`revoke_all_for_session` deliberately leaves `rotated_at` unstamped, so the
revoked successor is a stale credential, not a second trigger. Pinned by
`revoke_all_for_session_revokes_that_session_and_nothing_else` (the
`find_rotated(... "gc-succ")` assertion).

**3.2 Client comparison.** Not safe in the sense the plan's precedent implies;
F4-W1-01.

**3.3 Race with a concurrent rotation (T-37).** Clean. Rotation is
`get_by_token_hash(T2)` → `create(T3)` → `revoke_rotated(T2)`, and the
revocation is one `UPDATE … WHERE session_id = $s AND revoked = false`.
Revocation before `create(T3)`: T2 is already `revoked`, so `revoke_rotated`
(`WHERE revoked = false AND expires_at > now`) reports `NotFound`, T3 is
best-effort revoked, and the request returns `invalid_grant` — T3's raw value
and the new access token are never returned, so a cleanup failure leaves an
unreachable row, not a usable credential. Revocation between `create` and
`revoke_rotated`: T3 already carries the session id and is caught by the
UPDATE. Revocation after: T3 is caught. The access token a winning rotation may
already have returned carries the invalidated `sid`, so the session check and
the revocation feed stop it as for any logout. The fapi2 `supersede` path keeps
`revoked = false` in its WHERE too.

**3.4 Session row already gone.** `invalidate` is a `DELETE … WHERE tenant_id`
that succeeds on no row, still drops the validity-cache entry and publishes the
id to the feed (harmless: a hash of a dead session); the SSF sink fires only
when a row was really removed. `revoke_all_for_session` still runs, so the
refresh tokens are revoked even when the session was reaped first. Correct.

**3.5 Failure handling.** Not failing closed is right *for the response*: the
request is refused either way, a `500` would be an oracle ("your replay reached
a revocation"), and the code-replay path answers the same. What is wrong is the
audit value — F4-W1-02. Both writes are attempted independently (verified: the
`invalidate` result is held in a local and the second write runs regardless).

**3.6 Fallback on a settings read failure.** Holds. `refresh_reuse::resolve`
maps `Err` to `RefreshReuseResponse::default()` = `RevokeSession`; an unwired
service holds `default_policy()` (also `RevokeSession`); `decode_oauth2` maps an
absent or unparseable column to the default. Every fallback is the stricter
value. Both composition roots (`axiam-server/src/boot.rs:1313`,
`axiam-api-rest/src/state/mod.rs:750`) wire the settings-backed policy; they are
the only two `TokenService::new` call sites outside tests.

**3.7 Tighten-only clamp, create and update.** Holds on every path found:
`validate_tenant_override` (ordering `revoke_session` > `refuse`) runs in both
REST tenant writes (`handlers/settings.rs:594` full settings `PUT`, `:772`
override `PUT`); an organization change runs `reconcile_tenant_overrides` →
`clamp_overrides_to_org` (`:294`); and `get_effective_settings` clamps again on
**read** (`repository/settings.rs:1178`), so a stored weaker override — pre-V16
row, direct DB write, failed reconcile — is still ignored. Rank is explicit, not
declaration order. Pinned by
`g_c_a_tenant_may_tighten_the_refresh_reuse_response_and_never_relax_it` and
`g_c_a_baseline_that_tightens_clears_a_weaker_tenant_override`.

**3.8 Schema v110.** Additive: `DEFINE FIELD IF NOT EXISTS … TYPE
option<string> ASSERT $value = NONE OR $value IN ['revoke_session','refuse']`,
`DEFINE INDEX IF NOT EXISTS idx_refresh_token_session … COLUMNS tenant_id,
session_id`; no `UPDATE`, `REMOVE`, `DEFAULT` or backfill (pinned by
`v110_adds_only_the_refresh_reuse_setting_and_the_session_index`, which also
checks `is_additive`). The ASSERT is exercised by
`refresh_reuse_response_defaults_round_trips_and_tightens` (writing
`'revoke_family'` errors). Migration ordering test bumped to 110.

**3.9 Revocation-feed publication.** Through `SessionRepository::invalidate`,
after the statement's `.check()` — a failed DELETE is not published. Pinned end
to end by `g_c_a_refused_refresh_replay_revokes_its_session_end_to_end`, which
reads `/oauth2/revocations` and asserts the replayed session's hash is listed
and the other session's is not (run, passes).

**3.10 The audit row never carries the token.** Holds. The metadata gains only
`"response": response.map(RefusedReplayResponse::as_str)` — a static string or
`null`. Unit (`g_c_the_audit_row_carries_the_response_and_never_the_token`:
neither raw nor hash in the serialized metadata) and end to end (no refresh
token of the three in the row). Tracing at `token.rs:1152-1210` logs
`session_id` and counts only.

---

## 4. G-D and #518 / D-5 — attack by attack

The rule (`actor_token_client`, `token_exchange.rs:107`): `None` for any token
carrying `axiam_exchanged`, `act` or `ext_exchange`; otherwise the `client_id`
claim; otherwise `sub` for an `axiam:m2m` token; otherwise `None`. The actor is
accepted only when that equals the authenticated client.

| Attempt | Result |
|---|---|
| B3 delegation result as actor (own client, other client) | Refused — marker and `act`. Pinned: `an_exchanged_token_is_refused_as_an_actor_even_by_its_own_client` (all four presentations `400`, run, passes). |
| B3 impersonation result as actor | Refused — marker (no `act`). Same test. |
| X4 result as actor | Refused — marker and `ext_exchange`. `an_x4_token_names_its_client_and_is_never_that_clients_actor`, `an_external_exchange_result_is_refused_as_its_own_clients_actor_token`. |
| Laundering: foreign code-grant token as subject, then result as actor | Refused at step 2 — the regression test above *is* the executor's probe. |
| `client_credentials` token as actor | Accepted only for the client whose `sub` it is (unchanged #518 behaviour). `issue_client_credentials_token` never sets `client_id` or the marker; a service account's token has a UUID `sub`. |
| Marker-less exchanged token with `act` / `ext_exchange` (minted before #819) | Refused by the `act`/`ext_exchange` arms; it also carries no `client_id`, so the pre-#819 arms refused it too. Not pinned by a test of its own (F4-W1-04). |
| Can anything else set `axiam_exchanged`? | **No.** The field is `AccessTokenSpec::exchanged: bool`, private, set only in `AccessTokenSpec::exchanged()` (`token.rs:719`), whose only production caller is `issue_exchanged_token` (`:1132`). Pre-issue reactors write only into `ext`, a nested `BTreeMap<String,String>` (`token.rs:278`, explicitly not `#[serde(flatten)]`), so a reactor key named `axiam_exchanged` or `client_id` lands at `ext.axiam_exchanged`, not top level. UMA/RPT (`issue_rpt`), CIBA (`token_ciba.rs:261`), device (`device_service.rs:533`), code (`token.rs:2433`) and refresh (`:3078`) build their specs with `user`/`client_id`/`permissions`, never `exchanged`. Claim mappers act on ID tokens/UserInfo, not on `AccessTokenClaims`. |
| Can anything else mint a marker-less token with `client_id = A` and `sub = U` without U's consent? | Only the code, refresh, CIBA and device grants set `client_id` (grep of `.client_id(Some` outside tests: four sites, plus the exchange). Each requires U's authentication/approval for client A — the very evidence #518 accepts. RPTs carry no `client_id`. |
| Crafted claim set | Requires the tenant's Ed25519 signing key; the actor token goes through `decode_access_token` (signature, issuer, expiry, audience) and the tenant check before the rule. |

**Forward note for W2.** The native social sign-in grant will mint a
client-bound token; it must use the code/refresh issuance shape (`client_id` =
the native client, no marker), which makes its token an acceptable actor for
that client — correct, because the user authenticated to that client.

**4.1 Every reader of the `client_id` claim**, and whether adding it to exchanged
tokens changes its decision:

| Reader | Effect of an exchanged token now carrying `client_id` | Verdict |
|---|---|---|
| `actor_token_client` (`token_exchange.rs:107`) | Neutralised by the marker check that precedes it. | Clean |
| REST introspection (`token.rs:3460`) | Now echoes the claim for **all** JWT access tokens (code, refresh, CIBA, device, exchange). Who may introspect: any *confidential* client of the token's tenant (public clients refused, T21.2; cross-tenant → `active:false`). Disclosure: none beyond the JWT payload the caller already presents in the request. RFC 7662 §2.2 `client_id` is "the client that requested this token" — for an exchange, the exchanging client is the correct answer. Never derived from `sub`. | Clean |
| gRPC `IntrospectToken` (`api-grpc/src/services/token.rs:205`) | Prefers the claim, then the `sub_kind` fallback. Behaviour change for code/refresh/CIBA/device tokens (previously `""`), and for an exchanged token whose subject is a client (previously the subject's `sub`, now the exchanging client) — both RFC-correct. Same tenant gate (`caller_tenant`), same inactive-response blanking. | Clean |
| `AuthenticatedUser::minted_for_client` (`extractors/auth.rs:414`) | True for exchanged tokens now → `Admit::ConsoleSignInOnly` and the CIBA approval page refuse them `403`. They carried no `sid` and were already refused by the session check; this only tightens. | Clean |
| `admissible_session` (`extractors/auth.rs:1358`), principal rate-limit keying | Exchanged tokens never carry `sid`, and now carry `client_id` *and* the marker, so they are always `grant_without_session` → keyed by address, never as a session principal. Before #819 an impersonation token (no `sid`, `act`, `ext_exchange` or `client_id`) fell through to `user_session_of`; it is now excluded — strictly tighter. No bypass: the marker can only be added, not removed, by a token holder. | Clean |
| `release_sensitive_claims` at UserInfo (`handlers/oauth2.rs:3847`) | Keys consent on the claim. An exchanged token has no `sid` and is refused by the `AuthenticatedUser` session check before UserInfo runs; even if admitted, it would look up consent under the *exchanging* client, which must itself have the user's consent record for the exact scope set — a client that never obtained consent finds none. | Clean |
| UMA PAT (`handlers/uma.rs:85`) | Keys on `sub_kind` and `sub`, not `client_id`. Unchanged by W1. | Clean (not in W1 scope) |
| Logout, back-channel logout, DPoP/`cnf`, SSF, rate-limit client identity (`middleware/rate_limit_shared.rs:446`) | None reads the access-token claim: logout keys on the ID token / session, DPoP on `cnf` and the proof, SSF on stream configuration, the rate limiter on the request form / Basic header. | Clean |

---

## 5. F4-W1-02 (Low) — a failed revocation is audited as policy

**Where.** `respond_to_refused_replay`, `token.rs:1205`: `if invalidated &&
revoked { RevokedSession } else { Refused }`.

**Failure scenario.** A datastore fault makes `revoke_all_for_session` fail
after `invalidate` succeeded (or the reverse). The attacker's successor refresh
token stays live — exactly the outcome G-C exists to prevent — and the only
records are an `error` log line and an audit row with `response: "refused"`,
identical to a tenant that chose `refuse` or a token that named no session. An
operator querying `oauth2.refresh_token_replayed` for "replays we failed to
contain" cannot find it; a half-revocation (session gone, tokens live) is
reported as nothing having been done.

**Recommended fix.** A third audit value — `revocation_failed` (or
`partial`, carrying which of the two writes failed) — kept off the wire
response, plus a test that makes `invalidate` fail. Optionally one retry of the
failed write. The `400 invalid_grant` answer should stay as it is.

---

## 6. Informational

**F4-W1-03 — the family is the browser session.** `revoke_all_for_session`
revokes every refresh token with that `session_id`, whatever client it was
issued to (the repository test pins this as intended: `gc-sibling`, client
`oa_b`), and `invalidate` ends the console/SSO session. A client can therefore
sign the user out of every RP sharing the session by replaying its *own*
rotated token, and those RPs receive no back-channel logout token (the replay
path does not run the logout fan-out). RP-initiated logout already gives an RP
the power to end the session, so this is not a new capability; but the
operator docs (`docs/deployment/README.md`, the G-C section) should say "every
client's refresh tokens under that sign-in", and the threat model's "the user's
other sessions are untouched" is accurate but invites the reading that other
*clients* are untouched.

**F4-W1-04 — test gaps.** (a) No test presents a rotated token through a client
other than its own (F4-W1-01's behaviour is documented, unpinned). (b)
`MockSessionRepo::invalidate` never fails, so the "attempted independently"
claim is pinned only in one direction. (c) The threat model already concedes
that the `act`/`ext_exchange` arms of `actor_token_client` have no dedicated
test; a unit test with a hand-built `AccessTokenClaims` (marker `None`, `act`
`Some`, `client_id` = the exchanging client) would pin the fail-closed fallback
for the price of ten lines.

**F4-W1-05 — rustdoc dropped.** `crates/axiam-auth/src/token.rs:1094` begins
`//////`; four or more slashes is an ordinary comment, so the `client_id` /
marker bullet is absent from `issue_exchanged_token`'s rendered docs. Replace
with `///`.

**F4-W1-06 — the setting's API surface.** `#[schema(value_type = String)]` on
`OAuth2Policy::refresh_reuse_response` and `SetOrgSettings::refresh_reuse_response`
(and `value_type = Option<String>` on the override) emits a bare `string` in
`sdks/openapi.json`; dropping the override lets the `ToSchema` enum render
`enum: [revoke_session, refuse]` for the W4 SDK work. Separately, because the
organization body defaults the field, a pre-1.2.0 client that `PUT`s
organization settings returns a `refuse` organization to `revoke_session` — the
strict direction, so not a security defect, but worth a line in the upgrade
note.

---

## 7. Tests — do they assert what they claim; §10 hygiene

- The nine `g_c_*` unit tests, the two end-to-end tests, the repository and
  schema tests and the settings tests each assert the side effect they name
  (logs of `invalidate` and `revoke_all_for_session` calls with the exact
  session, the audit `response`, the feed's hash list, the successor's refusal,
  the other session's survival). The `refuse` end-to-end test drives the real
  settings wiring rather than a fixed policy.
- G-D tests decode the issued token and assert `client_id`, the marker, `sub`,
  the absence of `refresh_token`, the introspected `client_id`, and the exact
  #518 error description on all four laundering presentations.
- **§10 rule:** no assertion message interpolates a token, secret, hash or
  whole body. The interpolated values are `client_id`s and fixed labels
  (`"exchange status for {client_id}"`, `"{label}: …"`); the token-absence
  checks (`!rendered.contains(&raw)`) carry static messages. Note that
  `assert_eq!` prints both operands on failure; every compared operand is a
  claim value, status or error string, never a credential.
- **Fake credentials** are built at run time (`generate_refresh_token()`,
  fixture-created client secrets, a run-time Ed25519 test key). `"oa_exchanger"`
  and `"revoke_family"` are identifiers, not credentials.

## 8. Threat-model text against the code

- **T-37** — matches: refused lanes listed correctly (standard; fapi2 after
  grace; superseded row off fapi2), default and tighten-only rule correct,
  D-N4 residual stated.
- **T-254** — matches on mechanism, failure handling, `response` values, v110,
  feed, tests (every named test exists and asserts what is claimed). Two
  corrections recommended: "That is what the authorization-code replay path
  already does" overstates the equivalence (F4-W1-01), and "the audit row then
  says `refused` rather than claim a revocation" describes the behaviour
  F4-W1-02 recommends changing.
- **T-471** — matches: marker on all three shapes, the three-arm rule, REST
  echo, gRPC preference, the named tests (run), and the honest "not pinned"
  sentence for the `act`/`ext_exchange` arms.

## 9. Checks run

```text
python3 scripts/check-crate-layering.py                                   # OK, exit 0
cargo test -p axiam-oauth2 --test token_service g_c_                       # 9 passed
cargo test -p axiam-oauth2 --lib -- token_exchange refresh_reuse          # 35 passed
cargo test -p axiam-api-rest --no-default-features \
    --test token_exchange_test --test oauth2_flow_test                    # 46 + 31 passed
# probe (scratchpad, not committed): cross-client replay revokes the
# victim session — passed, confirming F4-W1-01; tree restored afterwards.
```

Not run: the full workspace suite, the `axiam-federation` and `axiam-db` test
targets (both read; federation is untouched), clippy (`missing_docs` crates are
untouched), and `check-spec-digest.py` (the spec diff was read; regenerating it
needs the server build).

---

## Addendum — sweep (2026-10-30)

**Against:** `dc5e4f5..09242b6` on `claude/social-gap-w1` — `4241409` (#821,
F4-W1-01), `e398312` (#822, F4-W1-02), `09242b6` (#823, F4-W1-03 … 06). 14
files, about 635 lines added. Each finding was re-checked against the code
rather than the commit messages. Two throw-away probe tests ran and were kept
out of the tree (§A.2).

### A.1 Per-finding verdicts

| ID | Verdict | Evidence |
|---|---|---|
| **F4-W1-01** | **Closed** | `respond_to_refused_replay` now returns `RefusedUnverifiedPresenter` before either write unless `presenter_may_revoke` holds (`crates/axiam-oauth2/src/token.rs:1245`). `presenter_may_revoke` (`:1323`) is the live refresh path's own checks and nothing new: `replayed.client_id != client.client_id` (the live path's ownership check, `:3066`), then `certificate_binding_for` and `dpop::enforce_refresh_token_binding` against the row's `dpop_jkt` — the same two calls, in the same order, that the live path makes before it redeems. Client authentication and `fapi::enforce_token_request` have already run on both branches before the row is looked up. Pinned by `f4w101_a_replay_through_another_client_revokes_nothing` (the case my first-pass probe built), `f4w101_a_bound_replay_without_its_proof_revokes_nothing` (no proof, and another key's proof), `f4w101_a_bound_replay_with_its_proof_revokes_the_session`, and `f4w101_a_public_clients_own_bearer_replay_revokes_the_session`. |
| **F4-W1-02** | **Closed** | `RevocationFailed { session, refresh_tokens }` (`token.rs:114`, built at `:1294`) maps to `response: "revocation_failed"`. `failed_writes` (`:1174`) is a list of the static strings `session_invalidate` / `refresh_tokens_revoke`, and `null` otherwise. The two writes are still attempted independently. Pinned in both directions: the existing test now expects `["refresh_tokens_revoke"]`, and `f4w102_a_failed_session_invalidation_is_audited_as_revocation_failed` drives the new failing `MockSessionRepo::invalidate` alone and with both writes failing. `f4w102_failed_writes_is_null_unless_the_revocation_failed` covers the success case. |
| **F4-W1-03** | **Closed** | `RefreshReuseResponse`'s rustdoc (and therefore the published schema), `t254-refresh-grace-decision.md` §7, the CHANGELOG and `docs/deployment/README.md` ("What 'the session' covers") now say that every client's refresh tokens under the sign-in and the console session are revoked, and that no back-channel logout is sent. That matches `revoke_all_for_session` and `invalidate`; the dispatch of back-channel logout is still only in `handlers/oauth2.rs`. |
| **F4-W1-04** | **Closed** | (a) cross-client: `f4w101_a_replay_through_another_client_revokes_nothing`. (b) failing `invalidate`: `f4w102_a_failed_session_invalidation_is_audited_as_revocation_failed`. (c) the fail-closed arms: `token_exchange.rs` gains `f4w104_an_unmarked_token_with_act_is_never_an_actor`, `f4w104_an_unmarked_token_with_ext_exchange_is_never_an_actor`, `f4w104_the_marker_alone_refuses_the_actor`, plus a control (`f4w104_a_plain_client_bound_token_names_its_client`) that proves the fixture would otherwise be accepted. Each assertion tests what its name says. |
| **F4-W1-05** | **Closed** | `crates/axiam-auth/src/token.rs:1094` is `///`. |
| **F4-W1-06** | **Closed** | The three `#[schema(value_type = …)]` overrides were removed. `sdks/openapi.json` now has `components.schemas.RefreshReuseResponse` = `{type: string, enum: [revoke_session, refuse]}`, referenced by `$ref` from `OAuth2Policy` and `SetOrgSettings`, and by `oneOf [$ref, null]` from the tenant override. **Spec checked by regeneration, not just by digest:** `cargo build -p axiam-server --no-default-features` and `--dump-openapi` produce a file byte-identical to the committed `sdks/openapi.json` (`cmp` silent); `check-spec-digest.py` passes; `management-registry.json`'s digest follows. The `PUT`-resets-`refuse` behaviour is documented on the field, in the CHANGELOG and in the deployment guide, with the workaround. |

### A.2 The coordinator's specific questions

**Does `presenter_may_revoke` reuse the live path's checks?** Yes — it calls the
same functions, not a reimplementation (A.1, F4-W1-01). It has no side effects.
`certificate_binding_for` only reads `ctx`, and `enforce_refresh_token_binding`
is pure. No DPoP `jti` is consumed and nothing is written, so a refused presenter
leaves no state behind that the live path would later trip over.

**Is there a gap now that the row stores no mTLS thumbprint?** No exploitable
one, and the reasoning differs by client type:

- *Confidential clients.* For these, RFC 8705 §4 binds a refresh token to the
  client's authentication, not to a certificate. Both the live path and the
  presenter check require that authentication (secret, `private_key_jwt`, or
  `tls_client_auth` / `self_signed_tls_client_auth`, whose certificate is
  checked against the registration). `certificate_binding_for` then only
  requires that *a* certificate be present. So a presenter needs the client's
  credential, which is the same bar as redeeming.
- *Public clients.* This is the case where an unbound refresh token would
  matter. I probed it: a public client (`none`) registered with
  `tls_client_certificate_bound_access_tokens: true`, presenting an unrelated
  self-asserted certificate. The probe answered `invalid_client` both for a live
  token and for a replay, and nothing was revoked. The reason is that
  `carries_no_client_credential` counts a presented certificate as a
  credential, and a public client must present none. Without a certificate,
  `certificate_binding_for` refuses. Such a registration can therefore never
  redeem or revoke: it is an unusable configuration, not a gap.
- *Public DPoP-bound clients.* These are the public sender-constrained shape
  that works, and the row's `dpop_jkt` covers them.

The CHANGELOG's phrase "DPoP/mTLS sender constraint" is accurate in that sense.
For mTLS the constraint is enforced through client authentication.

**Does the check order (policy → session → presenter) open an oracle or bypass?**
No.

- *No response oracle.* All four outcomes return from one site,
  `Err(InvalidGrant("refresh token already consumed"))` (`token.rs:3056`, and
  `:3090` on the live-row branch), after `record_refresh_replay` has returned
  `()`. Nothing the response carries depends on the `response` value.
- *No timing oracle for an unverified presenter.* Every path short of a
  verified presenter does exactly one settings read and no writes: policy
  `refuse`, no session, and wrong client or missing proof all do the same work.
  Only a verified presenter, which is the token's own client, pays for the two
  writes. So a third party cannot learn the tenant's policy, or whether the row
  names a session.
- *No bypass.* The presenter check is the last gate before the writes, and no
  path reaches `invalidate` or `revoke_all_for_session` without passing it.
- *The ordering is not a security property.* It only makes
  `refused_unverified_presenter` mean "a revocation that would otherwise have
  run was withheld", as documented.

**Is the client response byte-identical across `refused`,
`refused_unverified_presenter` and `revocation_failed`?** Yes, by construction
(see above). The tests assert it: every `f4w101_*` case and
`f4w102_a_failed_session_invalidation_is_audited_as_revocation_failed` goes
through `assert_refused_as_consumed` (the same code and description);
`f4w102_failed_writes_is_null_unless_the_revocation_failed` discards the
response and asserts only the audit row.

**Do the new audit keys ever carry a token?** No.

- `token_client_id` is `replayed.client_id`, a client identifier read from the
  row (`token.rs:1152`).
- `failed_writes` is a list of two static strings.
- The new `warn!` at the presenter refusal logs `session_id` and the presenting
  `client_id` only.
- `g_c_the_audit_row_carries_the_response_and_never_the_token` still runs over
  the whole metadata object, which now includes both keys.
- `audit_minimisation.rs`'s module text was updated to list them.

**Do the threat model and docs match the code?** Yes, on all four points:

- T-254 in both copies (`threat-model-stride.md`, `Axiam.json` and the
  regenerated `website/src/threatModel.ts`) is tightened in place at 2.45.0,
  with no status change.
- `t254-refresh-grace-decision.md` §7 adds "Who may trigger it", whose two
  bullets are exactly `presenter_may_revoke`, and replaces the sentence my
  review flagged ("That is what the authorization-code replay path already
  does") with the qualified version.
- Its pinning table names tests that exist and pass.
- The deployment guide's three new paragraphs match the code.

### A.3 New findings

| ID | Severity | Where | Finding |
|---|---|---|---|
| **F4-W1-07** | Informational | `crates/axiam-oauth2/src/token.rs:3066` | The new leak signal (`token_client_id` ≠ `client_id`) exists only on the not-found branch. On the live-row branch — a `fapi2` row superseded less than 60 s ago, or a superseded row whose client has since left `fapi2` and that has not yet expired — the ownership check runs *before* `record_refresh_replay`. A presentation through another client is therefore refused `"refresh token was not issued to this client"` with no session marker and no audit row. This is pre-existing and narrow (a ≤ 60 s window, or a registration change), and the response differs from the not-found branch's, as it always has. Recommended: record a replay before the ownership refusal when `stored.rotated_at.is_some()`, with `response: "refused_unverified_presenter"`, so the leak is audited on both branches. |
| **F4-W1-08** | Informational | `sdks/openapi.json`, `components.schemas.RefreshReuseResponse.description` | Removing the `value_type` override publishes the enum's rustdoc verbatim, including intra-doc links (`` [`Self::RevokeSession`] ``, `` [`Self::Refuse`] ``) that mean nothing to an SDK reader. This is cosmetic: a `#[schema(description = …)]` or a plainer first paragraph would fix it, and the contract (the `enum`) is correct. |

The sweep introduced nothing at Low or above. The unused-configuration
question (a public, certificate-bound registration is accepted by
`validate_registration` but can never redeem) is a usability point for a later
cleanup, not a security finding.

### A.4 Checks run (sweep)

```text
cargo test -p axiam-oauth2 --test token_service -- g_c_ f4w10 t254_    # exit 0, 24 passed
cargo test -p axiam-oauth2 --lib -- token_exchange refresh_reuse      # exit 0, 39 passed
cargo test -p axiam-core --lib -- g_c_                                # exit 0, 4 passed
cargo build -p axiam-server --no-default-features                     # exit 0
./target/debug/axiam-server --dump-openapi | cmp - sdks/openapi.json  # identical
python3 scripts/check-spec-digest.py                                  # exit 0
# probes (appended to token_service.rs, then the file restored; tree clean):
#   public + tls_client_certificate_bound_access_tokens, any certificate:
#   live redemption -> invalid_client; replay -> nothing revoked.
```

Not re-run for the sweep: the REST integration targets (the sweep changes no
REST handler or extractor; the first pass ran `token_exchange_test` and
`oauth2_flow_test` green) and the full workspace suite.

---

## Addendum 2 — second sweep (2026-10-30)

**Against:** `fe5de4e..4119629` — `4119629` (#824: F4-W1-07, F4-W1-08). It
touches 10 files and adds about 140 lines. The only production change is one
guarded call in the refresh grant's live-row ownership branch
(`crates/axiam-oauth2/src/token.rs:3066`); the rest is rustdoc, the regenerated
spec, two tests and documentation. This is the final F4 pass on W1. Under the
1.1.2 plan's §1.4 rule there is no third sweep round, so anything new below is
for the final PR's "Open after two sweeps" list.

### B.1 Verdicts

| ID | Verdict | Evidence |
|---|---|---|
| **F4-W1-07** | **Closed** | Before the ownership refusal, `if stored.rotated_at.is_some() { self.record_refresh_replay(tenant_id, &client, &stored, false, ctx).await; }`. The cross-client presentation of a live superseded row (in-window `fapi2`, or a row whose client has left `fapi2`) is now marked and audited with `token_client_id`. `presenter_may_revoke` fails on the client comparison, so nothing is revoked. Pinned by `f4w107_a_live_superseded_row_through_another_client_is_recorded_and_revokes_nothing` (both shapes; it also asserts that nothing was rotated) and `f4w107_a_never_rotated_row_through_another_client_is_not_recorded`. |
| **F4-W1-08** | **Closed** | Every intra-doc link in the text that reaches the spec for this setting is now a code span: `RefreshReuseResponse` (both bullets), `OAuth2Policy` and the override field. A scan of the regenerated `components.schemas` found no `` [`…`] `` in any `refresh_reuse` description. The links that remain in `TenantSettingsOverride` (`CimdPolicy`, `OidcPolicy::…`) were there before W1 and belong to other fields. **The spec was regenerated again:** `cargo build -p axiam-server --no-default-features`, then `--dump-openapi`, is byte-identical to the committed `sdks/openapi.json`, `check-spec-digest.py` passes, and `management-registry.json` follows the new digest. |

### B.2 The coordinator's questions

**Is the client response byte-identical?** Yes. `record_refresh_replay` returns
`()`, and the branch still returns the same literal
`InvalidGrant("refresh token was not issued to this client")`.
`assert_refused_as_not_this_clients` asserts the code and the exact description
for both shapes and for the never-rotated row.

**Oracle, write amplification, DoS — what must the presenter hold?** Two
things:

1. They must pass client authentication as *some* client of the tenant whose
   registration holds `refresh_token`, and pass that client's
   `fapi::enforce_token_request`. All of that runs before the row lookup
   (`token.rs:3018`). For a public client this is only its `client_id`.
2. They must hold the **raw bytes** of a refresh token whose row is still live
   and carries `rotated_at`, because the lookup is by that token's hash within
   the tenant.

Without the bytes, this branch is unreachable.

- **Writes per request.** One settings read, one session-marker update and one
  audit insert, with no revocation. That is exactly what the not-found branch
  has cost a holder of rotated-token bytes since #821, which deliberately left
  recording open to any client. The new branch adds a route to the same writes,
  not a new class of write, and it is bounded by the token endpoint's rate
  limiter.
- **Repeated presentation.** Spamming the same bytes inflates the victim
  session's "Replay refused" counter and the audit log. That is noise in the
  places an operator should be looking anyway, and it is attributable: each row
  names the presenting client and the token's client.
- **Oracles.**
  - The response text on this branch ("not issued to this client") already
    told a holder of the bytes that the token is live and someone else's.
    That predates W1 and is unchanged.
  - The only new signal is timing: a rotated foreign row now costs three
    datastore round trips where a never-rotated one costs none. It tells a
    party who already holds the token whether that token has been rotated.
    This is negligible and recorded here rather than raised.
- **No bypass.** The branch still returns before any rotation or issuance, and
  the recording path cannot revoke, because the presenter check fails on the
  client comparison whatever the policy is.

**Is the never-rotated row still unrecorded?** Yes. The guard is
`stored.rotated_at.is_some()`, and the `f4w107_a_never_rotated_row…` test
asserts no marker, no audit row, no invalidation and no revocation.

**Policy → session → presenter: `refused` under a `refuse` policy or a
session-less row — is that acceptable?** Yes. `response` describes what the
endpoint *did*, and under `refuse` or with no session there was no revocation
to withhold. The leak evidence does not depend on `response`, because
`token_client_id` and `client_id` are written on every row. An operator
looking for tokens that surfaced in the wrong client's hands should query
`token_client_id != client_id`, not `response = "refused_unverified_presenter"`.
Some documentation states the latter unconditionally, which is F4-W1-09.

**Do the T-254 texts match the code?** In substance, yes:

- `t254-refresh-grace-decision.md` §7 (the new paragraph and its table row),
  T-254 in `threat-model-stride.md`, `Axiam.json` and the regenerated
  `website/src/threatModel.ts`, and the deployment guide all describe the
  `rotated_at` guard, the unchanged answer, no revocation, and no record for a
  never-rotated row.
- Every test named there exists and passes.
- The imprecisions are in F4-W1-09.

### B.3 New finding — for the final PR's "Open after two sweeps" list

| ID | Severity | Where | Finding |
|---|---|---|---|
| **F4-W1-09** | Informational | `docs/deployment/README.md:2773-2776`; `claude_dev/t254-refresh-grace-decision.md:302-305`, `:317`; T-254 (#824 sentence) | The documentation says, unconditionally, that a cross-client presentation is audited `response: "refused_unverified_presenter"`. The code (`token.rs:3066` comment, `respond_to_refused_replay`) gives `refused` when the tenant's policy is `refuse` or the row names no session. Separately, the decision record's sentence "nothing distinguishes 'another client's token' from 'consumed'" holds only on the not-found branch: the live-row branch answers "not issued to this client", as §7's own later paragraph says. Neither affects behaviour. Recommended: qualify the `response` value by policy and session, and tell operators to find leaks with `token_client_id != client_id`. |

Nothing at Low or above. No defect from the first pass or either sweep remains
open in code.

### B.4 Checks run (second sweep)

```text
cargo build -p axiam-server --no-default-features                       # exit 0
./target/debug/axiam-server --dump-openapi | cmp - sdks/openapi.json    # identical (cmp exit 0)
python3 scripts/check-spec-digest.py                                    # exit 0
cargo test -p axiam-oauth2 --test token_service -- g_c_ f4w10 t254_     # exit 0, 26 passed (both f4w107_* ok)
```
