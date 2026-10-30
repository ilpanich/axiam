# T-254 — the refresh-rotation grace window

Decision record, in the form of [`basic-op-gap-plan.md`](basic-op-gap-plan.md)
§10: what was on the table, what it costs, what the maintainer answered, and
what was built.

| Decision | Answer | Consequence |
|---|---|---|
| **Confine the FAPI 2.0 refresh-rotation grace window to `fapi2` clients** | **Yes** | Every other client returns to the pre-065f37c behaviour: the predecessor is revoked at rotation and a second presentation is refused |
| **Mark every presentation of an already-rotated refresh token, accepted or refused** | **Yes** | Schema v60, a per-outcome counter on the session, an `oauth2.refresh_token_replayed` audit action, and a session listing in the admin UI |

Answered by the maintainer on **2026-09-12**. Both parts were required; neither
was optional, and the second is the reason the first is not merely a rollback.

---

## 1. What was on the table

Commit `065f37c` (2026-09-09), one of eight fixes the OpenID Foundation's
conformance suite prompted, made refresh rotation **supersede** rather than
revoke. `TokenService::refresh` called `RefreshTokenRepository::supersede`,
which brought the predecessor's `expires_at` forward to `now + 60s` instead of
setting `revoked = true`. Inside that window a second presentation of the old
token was answered `200` and rotated again.

FAPI 2.0 Security Profile §5.3.2.1-9 requires exactly that: an authorization
server that rotates refresh tokens shall keep accepting the previous one for a
period after issuing its successor. It is the only recovery a client has from a
rotation response lost in transit — under immediate revocation the client holds
a token the server has destroyed, has not been given the replacement, and can
do nothing but start a whole new authorization. The OIDF module that measures
it, `fapi2-security-profile-final-refresh-token`, sleeps thirty seconds and
then replays the old token expecting a `200`.

**The defect is not the window. It is where the window was applied.** The
profile that *requires* the grace also sender-constrains every token: on
`fapi2`, replaying a refresh token inside the window needs the client's private
key as well as the token, so the window costs an attacker holding a leaked
bearer string precisely nothing. AXIAM applied the same sixty seconds to
**every** client profile. On `standard` the refresh token *is* the credential,
and a leaked one gained a sixty-second replay window in which the server could
not tell the thief from an honest retry — a second live chain forked from the
same session, silently. That is T-254, and it was recorded **open** at
1.0.0-beta13 rather than absorbed.

## 2. The two options, and why the second one alone was not enough

The threat-model entry named two ways to close it.

**(a) In-window reuse detection** — revoke the whole family when a superseded
token is presented *after its successor has itself been used*. This is the
OAuth 2.0 Security BCP §4.14.2 reuse-detection idea, and it is the more
sophisticated answer. It also has a false-positive mode that is exactly the
case the window exists for: a client whose rotation response was lost retries
with the old token, having never received (and therefore never used) the
successor — but a *concurrent* request from the same client on a second
connection may have. Getting that wrong logs out a conformant client. And it
does nothing for the ordinary case: an attacker who replays the leaked token
*before* the honest client retries is indistinguishable either way.

**(b) Confine the grace to sender-constrained clients** — the window applies
only where the profile both requires it and pays for it with a second factor.
This is the smaller change, it is exactly reversible, and it restores a property
every existing deployment had before beta13 rather than inventing a new one.

**Decision: (b).** But (b) alone leaves the `fapi2` window unobserved, and
leaves a refused replay on `standard` looking identical to an ordinary expired
token in the logs — which is how T-254 came to be discoverable only by reading
a diff. So the decision is (b) **plus** an obligation the model had not asked
for: *whatever the window, a replay is marked*.

## 3. What was built

### 3.1 The window is a `fapi2` behaviour

`axiam_oauth2::fapi::refresh_rotation_grace_secs(&client) -> Option<i64>`. It
sits beside `auth_code_lifetime_secs`, the existing per-client profile gate, in
the module whose whole job is "what does `profile: fapi2` change" — deliberately
not a second mechanism. It reads `client.profile` and nothing else: **the
registration decides, never the request.** No header, parameter or grant shape
buys a `standard` client a window, and a client sender-constrained by its own
choice without being on the profile does not get one either (asserted by
`nothing_but_the_profile_buys_a_grace_window`).

`TokenService::refresh` picks one of two retirement lanes from it:

| Client | Retirement | Second presentation |
|---|---|---|
| `profile: fapi2` | `supersede` — `expires_at` brought forward to `now + 60s` | `200`, rotates again (and is marked) |
| everything else | `revoke_rotated` — `revoked = true` | `400 invalid_grant`, "refresh token already consumed" (and is marked) |

`revoke_rotated` is new and is deliberately not `revoke`. The two mean
different things: `revoke` is "this grant is over" (logout, password reset,
RFC 7009), and a later presentation of such a token is an ordinary stale
credential; `revoke_rotated` is "this token has been succeeded", and a later
presentation of *that* is a replay. Both lanes keep
`revoked = false AND expires_at > time::now()` in the WHERE, so two concurrent
rotations cannot both find a live row and the loser still gets `NotFound` — the
single-use race T-37 closes is untouched.

### 3.2 A replay is always marked

Both lanes stamp `rotated_at` **in the same statement that retires the row**. A
second write could be lost, and what it would leave behind is a rotated token
that does not say so — the exact blind spot. That one column is what makes a
replay recognisable:

- **A live row carrying `rotated_at`** can only be a superseded FAPI token. It
  is accepted if the client's registration *still* says `fapi2`, refused
  otherwise — the registration decides now, not when the row was written.
- **`find_rotated`** answers the refused case, where the read path has already
  filtered the row away. It ignores `revoked` and `expires_at` (a replay of a
  token that has since run out is still a replay) but requires `rotated_at`, so
  a credential revoked at logout stays an ordinary stale credential rather than
  being filed as a security event.

Three records follow, and none of them can fail a request (T-15-04):

1. **A durable marker on the session** the token's `session_id` names, through
   the new `SessionRepository::mark_refresh_replay`. One atomic UPDATE
   incrementing in place — a read-then-write would lose increments under
   exactly the concurrency this records, and SEC-032 settled that argument for
   the failed-attempt counter — wrapped in `retry_on_write_conflict` so a
   contended write on the busiest table cannot reintroduce the T-262 class.
   Two counters, not one plus a flag: an accepted grace retry and a refusal are
   read differently, and a single total cannot be read back into them.
2. **An audit row**, `oauth2.refresh_token_replayed`, naming the client, its
   profile, the session and a `disposition` of `accepted_under_fapi_grace` or
   `refused`. One action for both dispositions, so an operator who wants "all
   replays" needs to know one name; `outcome` follows the request and
   `disposition` is spelled out rather than inferred from it. **Never the token
   or its digest** — an audit log that recorded the credential would be a place
   to steal one from, and a test asserts it.
3. **A view**, `GET /api/v1/users/{user_id}/sessions`, serving a derived
   `refresh_replay_verdict` the admin UI renders as an amber "FAPI grace retry"
   or a red "Replay refused". Two visibly different badges, not one badge with a
   number in it: telling the mechanism working from a security event at a glance
   is what the marker is *for*. A refusal outranks any number of accepted
   retries on the same session.

### 3.3 Schema v60

Four optional columns, additive, backfilling nothing, no index —
`oauth2_refresh_token.rotated_at`, and `session.refresh_replay_at` /
`refresh_replay_grace_accepted` / `refresh_replay_refused`. Absent reads as
"never rotated" and "never replayed", which is the honest value: nothing
recorded whether a pre-v60 token was rotated, so nothing may claim it was, and a
backfill guessing "rotated" would file every stale token of the deploy window as
a security event.

## 4. What this costs, and what it does not

**Cost.** A `standard` client whose rotation response is lost in transit is
locked out of that grant and must re-authorize — exactly its position before
065f37c, and exactly what every deployment of AXIAM before 1.0.0-beta13 had. A
deployment that wants the recovery can have it, by registering the client
`profile: fapi2` and accepting the rest of the bundle, which includes the
sender-constraining that makes the window affordable. That is the whole point:
the window and the second factor arrive together or not at all.

**Not a cost.** FAPI conformance is unmoved — the five clients
`conformance/scripts/register-clients.sh` creates all carry `profile: "fapi2"`,
so `fapi2-security-profile-final-refresh-token` still sleeps thirty seconds,
replays, and is answered `200`.

**Invariant 4** of [`basic-op-gap-plan.md`](basic-op-gap-plan.md) — a client
registered today on `standard` gets the behaviour it had before beta13 — is
restored by this change rather than merely preserved by it. Every new test
carries its twin, as the W-waves did.

## 5. Where it is pinned

| Property | Test |
|---|---|
| A `standard` client gets no window; a `fapi2` client gets exactly one | `fapi.rs::a_standard_client_gets_no_refresh_rotation_grace`, `::a_fapi2_client_gets_the_profiles_grace_window` |
| Nothing but the profile buys a window | `fapi.rs::nothing_but_the_profile_buys_a_grace_window` |
| Sixty, not thirty — longer than the module that measures it | `fapi.rs::the_grace_window_is_comfortably_longer_than_the_module_that_measures_it` |
| Rotation supersedes on `fapi2`, revokes elsewhere | `token_service.rs::t254_a_fapi2_rotation_supersedes_on_the_grace_clock`, `::t254_a_standard_rotation_revokes_the_predecessor` |
| A replay inside the grace is served and marked accepted | `token_service.rs::t254_a_replay_inside_the_fapi_grace_is_accepted_and_marked` |
| A replay on `standard` is refused and marked refused | `token_service.rs::t254_a_replay_on_a_standard_client_is_refused_and_marked` |
| The registration decides *now*, not when the row was written | `token_service.rs::t254_the_registration_decides_a_superseded_row_is_refused_off_fapi` |
| An ordinary stale credential is not a replay | `token_service.rs::t254_an_ordinary_stale_refresh_token_is_not_a_replay`, `oauth2_refresh_token.rs::find_rotated_ignores_a_token_that_was_merely_revoked` |
| The audit record never carries the token | `token_service.rs::t254_the_replay_audit_record_never_carries_the_token` |
| Both lanes report `NotFound` to the loser of a race | `oauth2_refresh_token.rs::both_rotation_lanes_report_not_found_to_the_loser` |
| `supersede` can only bring the expiry forward | `oauth2_refresh_token.rs::supersede_can_only_ever_bring_the_expiry_forward` |
| The counters increment, per outcome, and a refusal outranks a retry | `session.rs::mark_refresh_replay_counts_each_outcome_separately` |
| A pre-v60 row reads as unmarked and can still be marked | `session.rs::a_pre_v60_row_reads_as_unmarked_and_can_still_be_marked`, `oauth2_refresh_token.rs::a_pre_v60_refresh_token_row_is_readable_and_is_not_a_replay` |
| End to end: refused on `standard`, and audited | `oauth2_flow_test.rs::refresh_token_rotation_retires_old_on_a_standard_client`, `::a_refused_refresh_replay_is_audited` |
| The session listing serves the marker and no token | `user_sessions_test.rs` (5 tests) |
| The two badges are visibly different | `UserSessionsDialog.test.tsx` (6 tests) |

## 6. Not done

- **The OIDF conformance suite was not re-run.** The environment this change
  was made in has no Docker daemon, and
  [`fapi-conformance-runbook.md`](fapi-conformance-runbook.md) needs one. The
  registrar's `profile: "fapi2"` on all five FAPI clients is the argument that
  the FAPI plans are unmoved, and it is an argument, not a run. The Basic OP
  plan's `oidcc-refresh-token` module runs against a `standard` client; it
  obtains and uses a refresh token and does not replay a rotated one, and its
  2026-09-08 `FAILED` (before the grace existed) was the `client2`
  `client_secret_basic` registration, not the window. Re-run all four plans
  before the next release.
- **In-window reuse detection** (option (a) above) is not implemented and is
  not scheduled. It would narrow the remaining `fapi2` window further; the
  window is already gated behind possession of the client's private key, so it
  is an improvement rather than a fix.
- **No configuration knob.** Sixty seconds stays a constant. A deployment that
  shortened it below the profile's floor would silently stop conforming, and one
  that lengthened it would widen the window for every tenant at once. If a
  deployment ever needs to differ, it belongs on the client's registration,
  where the profile switch already lives.

## 7. Amendment 2026-10-30 — G-C

Recorded in [`social-login-gap-plan-2026-10-30.md`](social-login-gap-plan-2026-10-30.md)
§3.3 (#818) and landed in f978dff. §1–§6 above are the 2026-09-12 record and are
left as written; where this section changes what they describe, it says so.

**What changed.** A presentation of an already-rotated refresh token that is
*refused* no longer stops at the refusal and the marker. That covers every
replay on a `standard` client, a replay on a `fapi2` client after its 60-second
grace (the row `supersede` expired, which `find_rotated` still finds), and a
superseded row whose client has since left `fapi2` (§5's
`t254_the_registration_decides_…` case). Each is still answered `400
invalid_grant` ("refresh token already consumed") and still marked and audited
as §3.2 describes. Under the default it now also invalidates the session the
token names (`SessionRepository::invalidate`, which drops the validity cache and
publishes to the revocation feed, so every access token carrying that `sid`
stops at its next request). It also revokes every refresh token issued under
that session, the successor included, through the new
`RefreshTokenRepository::revoke_all_for_session`. Only that session is
touched; the user's other sessions, on the same client or another, are not. The
authorization-code replay path does the same for a replayed code (RFC 6749
§10.5), and, as there, only the token's own client may trigger it (below). The
`oauth2.refresh_token_replayed` row gains `response`: `revoked_session`,
`refused` or `refused_unverified_presenter`, and `null` on an accepted `fapi2`
retry; and `token_client_id`, the client the rotated token was issued to, beside
the presenting `client_id`. It still carries neither the token nor its digest. Schema v110 adds the setting's column and an index on
`oauth2_refresh_token(tenant_id, session_id)`. It is additive and backfills
nothing.

**Why §2's false-positive argument does not reach these lanes.** §2 rejected
family revocation because a client whose rotation response was lost retries with
the old token, having never received the successor, and revoking would log out
a conformant client. That argument is about a token that can still be redeemed,
and so about the `fapi2` window. On a lane with no window open, that client
already holds a dead token and no successor: it cannot continue either way (§4's
"cost"), so revoking the session takes nothing from it that it still had. It
takes everything from whoever holds the successor, who may be the thief who won
the race. The one false positive left is a client that sends two refreshes with
the same token concurrently. That is a client defect, and the OAuth 2.0 Security
BCP declines to accommodate it. This is not §2's option (a): (a) acts *inside*
the window, on a presentation that is accepted, and it stays not done.

**What stayed.** The `fapi2` window is exactly as §3.1 built it (decision D-N4
of the plan): inside it a presentation is accepted, rotated again and marked
`accepted_under_fapi_grace`, and it revokes nothing, even when the successor has
already been used. The window is sender-constrained, the conformance runs were
made with it, and in-window reuse detection remains §6's improvement rather than
a fix. A token revoked at logout is not a replay (`find_rotated` requires
`rotated_at`) and revokes nothing. So is a replayed token that names no session
(a grant with no session behind it). The two rotation lanes, the `NotFound` to
the loser of a race, and the seven-day retention bound of 2026-10-22 (T-254) are
unchanged. A replay later than that bound is neither recorded nor revoking.

**The setting.** `oauth2.refresh_reuse_response`, set as `refresh_reuse_response`
in the organization and tenant settings bodies: `revoke_session` (the default,
D-N2) or `refuse`. `refuse` keeps the behaviour §3 built: refuse, mark, audit.
It is tighten-only like every ordered security setting (D-N8), ordered
`revoke_session` > `refuse`. A tenant may choose `refuse` only under an
organization on `refuse`. That is validated on write, and a tenant override
weaker than a baseline that tightens is cleared. "Available per tenant" in D-N2 is
met through the organization. A failed read of the setting falls back to
`revoke_session`, the stricter. This is a policy knob over the *response*. It is
not the knob §6 declines: the sixty seconds remain a constant.

**Who may trigger it (F4-W1-01, #821).** The wave's F4 review found the first
cut revoking before, and without, any check of who presented the token: the
bytes of a rotated token, presented through *any* client of the tenant, signed
the user out. The code-replay path does not behave that way —
`replayed_session` matches only a code issued to the presenting client, at its
redirect URI — and the revocation now follows it. It runs only when the
presenter is the token's own, proven client:

- the authenticated client (for a public client, the one its `client_id`
  names) is the client the rotated row was issued to — the live path's
  ownership check; and
- the request passes the sender-constraint check the successful refresh runs on
  that token: the registration's certificate and DPoP requirements
  (`certificate_binding_for`) and, for a public DPoP-bound client, a proof by
  the key in the row's `dpop_jkt` (`dpop::enforce_refresh_token_binding`). A
  refresh-token row carries no certificate thumbprint; a certificate-bound
  client proves itself by its client authentication, which has already run.

Otherwise the answer is the same `invalid_grant` with the same description, so
nothing distinguishes "another client's token" from "consumed"; the replay is
still marked and audited; nothing is revoked; and the row's `response` is
`refused_unverified_presenter`. The checks run after the policy and the session
(policy `refuse` or no session → `refused`), so the value always means a
revocation that would otherwise have run was withheld. A rotated token leaked
through a log, a dump or a proxy is evidence, not a way to sign the user out;
a sender-constrained token stays worthless without its key. A public client
identified by its `client_id` alone, presenting its own bearer token, is the
`standard` lane and still revokes.

**Failure.** As on the code-replay path, a failed invalidate or revoke is logged
at `error` and the answer stays `invalid_grant`. It is never a `500`, which
would tell the presenter that its replay reached a revocation. The two writes
are attempted independently, and the audit row then says `refused` rather than
claim a revocation that did not complete.

**Where it is pinned.**

| Property | Test |
|---|---|
| A `standard` replay invalidates its session and revokes that session's refresh tokens | `token_service.rs::g_c_a_standard_replay_revokes_the_session_it_names` |
| A `fapi2` replay after the grace revokes; inside it, nothing is revoked | `token_service.rs::g_c_a_fapi2_replay_after_the_grace_revokes_the_session`, `::g_c_a_fapi2_replay_inside_the_grace_is_accepted_and_revokes_nothing` |
| A superseded row refused off `fapi2` revokes | `token_service.rs::g_c_a_superseded_row_refused_off_fapi_revokes_the_session` |
| `refuse` keeps §3's behaviour | `token_service.rs::g_c_the_refuse_setting_restores_the_previous_behaviour` |
| A logout-revoked token, or a replay naming no session, revokes nothing | `token_service.rs::g_c_a_logout_revoked_token_presented_again_revokes_nothing`, `::g_c_a_replay_naming_no_session_revokes_nothing` |
| A failed revocation still answers `invalid_grant`, and the row says `refused` | `token_service.rs::g_c_a_failed_revocation_still_answers_invalid_grant` |
| The row carries `response` and never the token | `token_service.rs::g_c_the_audit_row_carries_the_response_and_never_the_token` |
| Only the token's own, proven client revokes (#821): another client, or a bound token without its key's proof, revokes nothing and is audited `refused_unverified_presenter`; the proven own client, and a public client's own bearer token, revoke | `token_service.rs::f4w101_a_replay_through_another_client_revokes_nothing`, `::f4w101_a_bound_replay_without_its_proof_revokes_nothing`, `::f4w101_a_bound_replay_with_its_proof_revokes_the_session`, `::f4w101_a_public_clients_own_bearer_replay_revokes_the_session` |
| The policy port defaults to, and fails to, `revoke_session` | `refresh_reuse.rs::an_unwired_service_revokes_by_default`, `::a_fixed_policy_answers_what_it_was_given`, `::a_failed_read_falls_back_to_the_stricter_default` |
| The setting's default, its spellings, and tighten-only (D-N8) | `axiam-core` `settings.rs::g_c_the_refresh_reuse_response_defaults_to_revoke_session`, `::g_c_the_wire_spelling_round_trips_and_nothing_else_parses`, `::g_c_a_tenant_may_tighten_the_refresh_reuse_response_and_never_relax_it`, `::g_c_a_baseline_that_tightens_clears_a_weaker_tenant_override`; `settings_repository_gaps_test.rs::refresh_reuse_response_defaults_round_trips_and_tightens` |
| The revocation reaches that session and no other; v110 is what it says | `oauth2_refresh_token.rs::revoke_all_for_session_revokes_that_session_and_nothing_else`, `schema.rs::v110_adds_only_the_refresh_reuse_setting_and_the_session_index` |
| End to end: session gone and on the revocation feed, successor refused, another session still refreshing, one audit row | `oauth2_flow_test.rs::g_c_a_refused_refresh_replay_revokes_its_session_end_to_end` |
| End to end: an organization on `refuse` keeps the successor working | `oauth2_flow_test.rs::g_c_an_organization_on_refuse_keeps_the_previous_behaviour_end_to_end` |

The §5 tests are unchanged. The threat model records this as a dated amendment
to T-37 and T-254 at model 2.45.0. The operator's account is
`docs/deployment/README.md`, "Refresh-token replay revokes the session (G-C,
#818)", with the upgrade note, and `docs/admin/organization-scope.md`.
