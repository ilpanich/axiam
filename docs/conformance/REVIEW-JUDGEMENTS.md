# REVIEW judgements

The OpenID Foundation suite ends some modules in `REVIEW`. That is a terminal
verdict and not a failure: the module's own assertions held, and what is left is
a condition only a person can decide, usually *"if the server does not return an
error to the client, it must show an error page — upload a screenshot"* or *"the
server must ask the user to log in for a second time — upload a screenshot"*. A
certification reviewer reads the suite log and the image and decides. This file
is where AXIAM writes down, ahead of that reading, what it thinks they will find
and why.

**A certification submission is this file plus a green run.** The run says what
the suite measured; this file says what the suite could not, module by module,
so a reviewer does not have to reconstruct it. It is published with the reports
beside it, green and red alike (see [`README.md`](README.md)).

## How to read an entry, and what an entry may claim

Every entry has the same six parts: the suite log and the evidence file it rests
on; what the suite could not decide (the module's own condition, quoted from
`evidence/<date>/manifest.json`); what AXIAM does, with the file and the test
that pins it; why that is conformant, with the clause; what the existing
evidence does and does not show; and what is left for the maintainer's run.

Three rules keep the file honest.

1. **Nothing here is a result of a run that was not made.** Every statement about
   what a module did cites the report or evidence file it comes from, by log id
   or file name. The suite logs themselves are not in this repository; a sentence
   that can only be known from a log reads *"to be confirmed by the maintainer's
   run"*, never as a finding.
2. **A judgement is prose over a log the suite produced.** It does not replace
   the log. The log ids below are the 2026-09-25 baseline; the maintainer's
   final run (the maintainer runs the Basic OP and FAPI 2.0 suites personally,
   before the release tag — decision of 2026-10-03) produces new ones, and the
   entry is updated with them, **alongside** the old, never over them.
3. **A judgement that needs a decision the specifications and the code do not
   pin is written as open.** Those are marked *Open, for the maintainer* and
   collected at the end.

**Status of this revision.** The Basic OP entries (T23.1.6) and the FAPI 2.0
entries (T23.1.7) are written from the 2026-09-25 reports and evidence, against
the tree at `claude/phase23-w2`. No entry has been confirmed against a final run
yet; every entry's verdict below is *proposed*. The FAPI claims entry describes
D-12 (an essential `claims.id_token.auth_time` refused on `fapi2`) as decided and
landing in W2, because it had not landed when that entry was written.

## Index

| Plan | Module | 2026-09-25 log | Evidence | Proposed judgement |
|---|---|---|---|---|
| Basic OP | `oidcc-prompt-login` | `c0oSGcvXhBtjj9D` | [`oidcc-basic-static__prompt-login__d4f4ba0105.jpg`](evidence/2026-09-25/oidcc-basic-static__prompt-login__d4f4ba0105.jpg) | Conformant; the image shows the re-authentication page, the log must show the first sign-in |
| Basic OP | `oidcc-max-age-1` | `RSzk3w8Kxro3IYC` | [`oidcc-basic-static__max-age-1__f77ce8cb67.jpg`](evidence/2026-09-25/oidcc-basic-static__max-age-1__f77ce8cb67.jpg) | Conformant; same shape as `prompt-login` |
| Basic OP | `oidcc-ensure-registered-redirect-uri` | `szkbM07X3ihnZoY` | [`oidcc-basic-static__ensure-registered-redirect-uri__f39dea4139.jpg`](evidence/2026-09-25/oidcc-basic-static__ensure-registered-redirect-uri__f39dea4139.jpg) | Conformant; the page is the one RFC 6749 §3.1.2.4 asks for |
| Basic OP | `oidcc-ensure-request-object-with-redirect-uri` | `d93KQKPrWLutU8W` | [`oidcc-basic-static__ensure-request-object-with-redirect-uri__f39dea4139.jpg`](evidence/2026-09-25/oidcc-basic-static__ensure-request-object-with-redirect-uri__f39dea4139.jpg) | Conformant on the evidence, with one point the live log must confirm |
| FAPI 2.0 | `ensure-unsigned-authorization-request-without-using-par-fails` | `hubHxFIqq4NIObo` (`mtls`), `73MqxLgoSS6V38N` (`self-signed`), `c0Rb6Ejn7RpJoRQ` (`private-key-jwt`) | [`…__dc2918eeb2.jpg`](evidence/2026-09-25/fapi2-security-profile-final-mtls__ensure-unsigned-authorization-request-without-using-par-fails__dc2918eeb2.jpg), the same bytes for all three | Conformant on the evidence: an error page carrying `invalid_request`; two points the log must settle (wording; whether a sign-in came first) |
| FAPI 2.0 | `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `H2OiSzJ5MolJxvg`, `yhcCDPi0oikE4FC`, `xHPfInpD8AbPbaU` | [`…__3bfc90363d.jpg`](evidence/2026-09-25/fapi2-security-profile-final-mtls__par-ensure-reused-request-uri-prior-to-auth-completion-succeeds__3bfc90363d.jpg) (`mtls`, `self-signed`), [`…__736d1520ee.jpg`](evidence/2026-09-25/fapi2-security-profile-final-private-key-jwt__par-ensure-reused-request-uri-prior-to-auth-completion-succeeds__736d1520ee.jpg) (`private-key-jwt`) | Conformant; the image is the login page, the log must show which visit it is |
| FAPI 2.0 | `test-claims-parameter-identity-claims` (`WARNING`) | `E3LMGPfxxRnrBff`, `Ifh31qq9b0lDMpw`, `v440VDWfwxP7kKo` | none (a `WARNING` uploads nothing) | **Open.** Not the "claims not supported" deviation (discovery says `true`); the reason is in the log only |

The four Basic OP modules have been `REVIEW` in every Basic OP report since
[2026-09-10](2026-09-10-oidcc-basic-static.md) and were `WAITING` (no assertion
evaluated) in the [first run](2026-09-08-oidcc-basic-static.md). The 2026-09-25
run is the basis here because it is the latest and the evidence directory for it
carries a manifest.

| Module | 09-10 | 09-11 | 09-13 | 09-14 | 09-15 | 09-18 | 09-25 |
|---|---|---|---|---|---|---|---|
| `oidcc-prompt-login` | `NzTkhxhgIcOnymK` | `lsmkIKtRWtAzsm2` | `dzezmF9hZtpvqud` | `Hs95VQwMAF0MLG7` | `HqW61KWtkTynPan` | `Wn53ebplRWoTJct` | `c0oSGcvXhBtjj9D` |
| `oidcc-max-age-1` | `KW1GJh03tS2k0Db` | `oDS1h6X4BAFk77Z` | `smprIqbHX4adKSi` | `2r0TbyoI8XWdzaY` | `JlLF4Y1sCO5U2kA` | `TjfkMswA5L2FTqI` | `RSzk3w8Kxro3IYC` |
| `oidcc-ensure-registered-redirect-uri` | `SIqVqn22QkzYxg3` | `8wfFuThDy0ScdSQ` | `EF4RAQiVpVFLp2Y` | `cv76nYakHKATiIP` | `KslW7yWosTsUOda` | `wJNBWt0skisglOR` | `szkbM07X3ihnZoY` |
| `oidcc-ensure-request-object-with-redirect-uri` | `9b3TPXckjNdzyzD` | `pRbuhlhRPdg6S0g` | `5JdP3I0fF39ZSa4` | `yucPsfL0E27CITu` | `ChosCSgDZp0Kx6z` | `cuBn2aq0Q8OzDRU` | `d93KQKPrWLutU8W` |

Log ids are copied from the `Modules that did not pass` table of each dated
`*-oidcc-basic-static.md` report. Evidence directories exist for
[2026-09-15](evidence/2026-09-15/), [2026-09-18](evidence/2026-09-18/) and
[2026-09-25](evidence/2026-09-25/).

---

# Basic OP (OpenID Connect Core, Basic Certification Profile)

The four Basic OP clients are registered `profile: standard`, `browser_sso: true`
and `authn_request_params: honour` (`conformance/scripts/register-clients.sh`,
`mk_basic_client`). The last field matters for the first two entries: on the
default `ignore` lane AXIAM drops `prompt` and `max_age` before any decision sees
them, and the same register script's comment records that the plan's `prompt`
and `max_age` modules then test nothing. The browser is driven by
`conformance/scripts/drive-browser.mjs` in Chromium, one browser context per
test, so a module that signs in and then asks again sees its own session.

## `oidcc-prompt-login`

**Suite log.** `c0oSGcvXhBtjj9D`, in
[`2026-09-25-oidcc-basic-static.md`](2026-09-25-oidcc-basic-static.md), verdict
`REVIEW`. Evidence:
[`oidcc-basic-static__prompt-login__d4f4ba0105.jpg`](evidence/2026-09-25/oidcc-basic-static__prompt-login__d4f4ba0105.jpg),
one image uploaded, listed in
[`evidence/2026-09-25/manifest.json`](evidence/2026-09-25/manifest.json).

**What the suite could not decide.** The condition, verbatim from the manifest:

> The server must ask the user to login for a second time; a screenshot of this
> must be uploaded.

The suite can see that the browser was sent somewhere. It cannot tell whether
that somewhere asked a person to authenticate again, so it asks for a picture of
the page.

**What the image shows.** Read, not classified by size or hash. It is AXIAM's
sign-in page at the credentials step ("Workspace: test-org (organization)"), with
a notice above the form reading **"Please sign in again to continue."**, an empty
username field, a password field showing only its placeholder dots
(`placeholder="••••••••"` in `frontend/src/pages/LoginPage.tsx`; the driver takes
this shot before typing anything, per the comment in `drive-browser.mjs`),
`Back`, `Cancel` and `Sign in` buttons, and `Sign in with a passkey`. The
notice is what distinguishes a second sign-in from a first: it is rendered only
when the page was reached with `reauth=1`, and the page ends the browser's
existing session when it is
(`frontend/src/pages/LoginPage.test.tsx`:
`ends the existing session and says so when ?reauth=1 is present`, and its twin
`does not sign the browser out when reauth was not asked for`, which asserts the
notice is absent otherwise).

**What AXIAM does.**

- `prompt=login` on a client registered `honour` always asks for an interaction,
  however fresh the session: `crates/axiam-oauth2/src/honour.rs`, `evaluate`
  (`asked_for_interaction` → `Outcome::Interact`, reason `PromptAsked`), pinned by
  `honour.rs::t1_5_prompt_login_always_interacts`.
- The interaction is a redirect to `/login?return_to=…&reauth=1`
  (`login_hop.rs::build_interaction_redirect`, `Reason::requires_reauthentication`
  is true for `PromptAsked`), with `Cache-Control: no-store`. The SPA, on
  `reauth=1`, ends the session the browser still holds before showing the form,
  so that the next sign-in is a new authentication event with a new
  `authenticated_at`.
- The request that comes back from the sign-in page carries the hop marker
  (`axiam_login_hop`). It is answered, not sent round again, so the chain
  terminates: `oauth2_honour_lane_test.rs::the_return_leg_of_a_prompt_login_hop_does_not_hop_again`.
- The ID token then carries the **new** `auth_time`:
  `oauth2_honour_lane_test.rs::t1_5_prompt_login_reauthenticates_and_moves_auth_time_forward`
  (mirrors the suite's own module; it builds the second session with a helper
  rather than driving the real sign-in page, so the sign-in-page half is
  evidenced by the live run and the image, not by that test).
- A forged marker cannot make an old session look reauthenticated: the code is
  issued, but `auth_time` is still the old authentication
  (`oauth2_honour_lane_test.rs::a_forged_return_leg_marker_cannot_make_an_old_session_look_reauthenticated`).

**Why that is conformant.** OpenID Connect Core 1.0 §3.1.2.1, `prompt=login`:
*"The Authorization Server SHOULD prompt the End-User for reauthentication. If
it cannot reauthenticate the End-User, it MUST return an error, typically
`login_required`."* AXIAM prompts; where a reauthentication cannot be produced
(`max_age=0`, which no clock can satisfy, or a return leg that still fails the
test) it returns `login_required` rather than a code
(`honour.rs::max_age_zero_is_refused_rather_than_looped_after_a_reauthentication`).

**Does the existing evidence suffice?** For the condition as worded, yes: the
image is a sign-in page and carries the notice that only a re-authentication
produces. It cannot show, by itself, three things a reviewer will want, and none
of them is in this repository because the suite log is not:

1. that a first authentication preceded it and succeeded;
2. that the second authorization request carried `prompt=login`;
3. that the second sign-in completed and the resulting ID token had a later
   `auth_time`, if the module checks it.

All three are in the module's log (`<SUITE_BASE_URL>/log-detail.html?log=<id>`).
*To be confirmed by the maintainer's run:* read them there, and view the image —
the notice is the only thing that tells the first sign-in from the second, so an
image without it belongs to the first visit and the module is not evidenced. The
checklist in `claude_dev/fapi-conformance-runbook.md` has the item.

**Open, for the maintainer.** None specific to this module. Whether a reviewer
accepts one screenshot plus the log is the Foundation's decision; nothing in the
repository decides it.

---

## `oidcc-max-age-1`

**Suite log.** `RSzk3w8Kxro3IYC`, in
[`2026-09-25-oidcc-basic-static.md`](2026-09-25-oidcc-basic-static.md), verdict
`REVIEW`. Evidence:
[`oidcc-basic-static__max-age-1__f77ce8cb67.jpg`](evidence/2026-09-25/oidcc-basic-static__max-age-1__f77ce8cb67.jpg),
one image uploaded.

**What the suite could not decide.** The same condition as `oidcc-prompt-login`,
verbatim from the manifest:

> The server must ask the user to login for a second time; a screenshot of this
> must be uploaded.

**What the image shows.** The same page as `prompt-login`'s, with the same
notice. The two files differ in bytes (`f77ce8cb67` against `d4f4ba0105`) and not
in content — they are the same page captured at different render instants — and
each module produced its own capture, so each is independently evidenced (the
2026-09-18 evidence README makes the same point for that run; before then the two
had shared one file).

**What AXIAM does.**

- `max_age` is compared in whole seconds, floored, never in the relying party's
  favour: the session is too old when `elapsed >= max_age`
  (`honour.rs`, `evaluate`, `max_age_unmet`; `elapsed_secs`). For `max_age=1`
  against a session older than a second the answer is `Outcome::Interact` with
  reason `MaxAgeExceeded`, which is a `reauth=1` hop exactly as for
  `prompt=login`. Pinned by
  `honour.rs::t2_2_an_expired_max_age_reauthenticates_and_then_proceeds`, which
  uses `max_age=1` and a two-second-old session, and by
  `oauth2_honour_lane_test.rs::t2_2_an_expired_max_age_reauthenticates_and_the_second_token_is_fresh`
  at `max_age=60`.
- A satisfied bound asks for nothing (`honour.rs::t2_3_a_satisfied_max_age_is_invisible`;
  `oauth2_honour_lane_test.rs::t2_3_a_satisfied_max_age_does_not_reauthenticate`,
  which mirrors `oidcc-max-age-10000`, a module that **passed** on 2026-09-25 —
  it is in the passed list of the report).
- On the return leg the bound is checked again, and a session that is still too
  old is `login_required`, never a code. A forged hop marker therefore cannot
  satisfy `max_age` with an old session
  (`oauth2_honour_lane_test.rs::a_forged_return_leg_marker_cannot_satisfy_max_age_with_an_old_session`).
- The ID token carries `auth_time` on the honour lane whether or not `max_age`
  was sent (`t1_5_…` above reads it from a token issued with no `max_age`).

**Why that is conformant.** OpenID Connect Core 1.0 §3.1.2.1, `max_age`:
*"If the elapsed time is greater than this value, the OP MUST attempt to actively
re-authenticate the End-User. … When `max_age` is used, the ID Token returned
MUST include an `auth_time` Claim Value."* AXIAM re-authenticates at *greater
than or equal to* the bound, which is one boundary instant stricter than the
clause requires and never looser; and it emits `auth_time`.

**Does the existing evidence suffice?** The same answer as `oidcc-prompt-login`:
sufficient for the condition's wording, and unable to show on its own that the
first sign-in happened or that the second request carried `max_age=1`. One point
is specific to this module and *to be confirmed by the maintainer's run*: that
the module leaves the session more than a whole second old before it asks again,
since AXIAM would not reauthenticate a session younger than the bound. The
2026-09-25 image is itself the evidence that it did on that run; the log shows
how.

**Open, for the maintainer.** None specific to this module.

---

## `oidcc-ensure-registered-redirect-uri`

**Suite log.** `szkbM07X3ihnZoY`, in
[`2026-09-25-oidcc-basic-static.md`](2026-09-25-oidcc-basic-static.md), verdict
`REVIEW`. Evidence:
[`oidcc-basic-static__ensure-registered-redirect-uri__f39dea4139.jpg`](evidence/2026-09-25/oidcc-basic-static__ensure-registered-redirect-uri__f39dea4139.jpg),
one image uploaded.

**What the suite could not decide.** The condition, verbatim from the manifest:

> Show redirect URI error page

This is the shape the driver's header comment describes for every `…ErrorPage`
condition: *if* the server does not return the error to the client, it must show
an error page and a screenshot is the evidence. Two answers are right — an error
delivered over the protocol, or an error page. For a **redirect URI** error the
first is not available, and must not be (below), so the page is the only right
answer and the suite cannot judge whether what the browser was shown is one.

**What the image shows.** A plain error page headed **"This authorization request
cannot be completed"**, the sentence **"redirect_uri not registered"**, `Error
code: invalid_request`, and *"Nothing has been shared with the application that
sent you here. Return to it and start again."* No sign-in form, no redirect.

**What AXIAM does.**

- The client is looked up, then the presented `redirect_uri` is compared with the
  client's registered list **before any other check that could redirect an
  error**: `crates/axiam-oauth2/src/authorize.rs`, `AuthorizeService::authorize`,
  steps 1 and 2. The comparison is `redirect_uri::any_redirect_uri_matches`,
  which for every non-loopback URI is a byte-for-byte string comparison — no
  prefix, no wildcard, no normalisation
  (`redirect_uri.rs::https_uris_are_still_matched_exactly`,
  `::a_registered_query_must_be_presented_unchanged`).
- A mismatch is `OAuth2Error::InvalidRedirectUri("redirect_uri not registered")`,
  wire code `invalid_request`, and the handler answers it **in place**, never by
  redirecting: `crates/axiam-api-rest/src/handlers/oauth2.rs` (the `Err(e)` arm
  that sends `InvalidClient | InvalidRedirectUri | ParRequired` to
  `authorize_error_response`). For a browser that asks for HTML that is the page
  in the image; for any other caller it is a `400` JSON body.
- This holds for an anonymous browser too, which is what the suite is when it
  arrives, because the check runs before the login hop:
  `oauth2_login_hop_test.rs::an_anonymous_refusal_never_redirects_to_a_return_to_the_request_carried`
  (unregistered target: `400`, no `Location`) and
  `::a_declined_sign_in_is_reported_only_to_a_registered_redirect_uri`.
  For an authenticated caller:
  `oauth2_flow_test.rs::invalid_redirect_uri_rejected_at_authorize`
  (`400`, `invalid_request`, a description naming `redirect_uri`) and
  `authorize.rs::authorize_redirect_uri_mismatch_returns_invalid_redirect_uri`.
  The same registered-list comparison guards PAR
  (`par_test.rs::par_refuses_an_unregistered_redirect_uri`).

**Why that is conformant.** RFC 6749 §3.1.2.4 and §4.1.2.1: *"If the request
fails due to a missing, invalid, or mismatching redirection URI … the
authorization server SHOULD inform the resource owner of the error and MUST NOT
automatically redirect the user-agent to the invalid redirection URI."* OpenID
Connect Core 1.0 §3.1.2.1 requires the `redirect_uri` to match a registered value
by simple string comparison, and §3.1.2.6 defers to RFC 6749 §4.1.2.1 for the
error response, including the case where the `redirect_uri` is invalid.
Redirecting an error to an unregistered URI
would be an open redirect; the page is the required behaviour, and the module's
condition is the request to show it.

**Does the existing evidence suffice?** Yes. The image is the page the condition
names, it carries the specific message and `invalid_request`, and it was taken
from the browser the driver actually used. The same bytes (`f39dea4139`) were
uploaded on 2026-09-15 and 2026-09-18, so the page is stable across runs.

**Not pinned by a Rust test.** The HTML text of this page for
`InvalidRedirectUri` is not asserted by any test in `crates/` (a search for the
page title finds only the handler); the evidence is the screenshot. The branch
that renders HTML is exercised for another error by
`oauth2_login_hop_test.rs::the_login_hop_reflects_no_request_parameter_into_a_body`.
This is an observation for a later hardening task and not a doubt about the
behaviour, which the `400`/no-`Location` tests above pin.

**Open, for the maintainer.** None.

---

## `oidcc-ensure-request-object-with-redirect-uri`

**Suite log.** `d93KQKPrWLutU8W`, in
[`2026-09-25-oidcc-basic-static.md`](2026-09-25-oidcc-basic-static.md), verdict
`REVIEW`. Evidence:
[`oidcc-basic-static__ensure-request-object-with-redirect-uri__f39dea4139.jpg`](evidence/2026-09-25/oidcc-basic-static__ensure-request-object-with-redirect-uri__f39dea4139.jpg),
one image uploaded.

**What the suite could not decide.** The same condition as the previous module,
verbatim from the manifest:

> Show redirect URI error page

**What the image shows.** The same page, byte for byte (`f39dea4139`) — the
"This authorization request cannot be completed" page with `redirect_uri not
registered` and `Error code: invalid_request`. Both modules uploaded one file and
the manifest lists it under both.

**What AXIAM does.** The same as above, plus one thing about request objects.
AXIAM accepts no request object on any carrier. A `request` parameter is refused
with `request_not_supported` and a non-PAR `request_uri` with
`request_uri_not_supported`
(`authorize.rs`, `RequestObject::into_error`; `handlers/oauth2.rs`,
`classify_request_object`; `handlers/oauth2.rs::request_object_tests::t12_1_a_request_object_by_value_is_classified`;
`par_test.rs::a_request_object_pushed_to_par_is_refused_with_request_not_supported`),
and discovery says so: `request_parameter_supported: false`
(`oidc.rs::discovery_tells_the_truth_about_request_objects_and_claims`). That
refusal is **ordered after** the `redirect_uri` check (`authorize.rs` step 2d
follows step 2, with a comment saying why), so a request object can never cause
AXIAM to redirect anywhere: if the `redirect_uri` the request carries is not
registered, the answer is the page in the image whatever else the request holds.

**Why that is conformant.** For the page: the clauses of the previous entry. For
the request object: OpenID Connect Core 1.0 §3.1.2.6 defines `request_not_supported`
for an OP that does not support the `request` parameter, and §6.1 permits an OP
not to support it, provided discovery says so, which it does. The relevant
property for this module is that nothing about a request object loosens the
`redirect_uri` rule.

**What the evidence can and cannot settle.** The page text, `redirect_uri not
registered`, is the message raised at step 2 of `AuthorizeService::authorize`,
which fires when the **query-string** `redirect_uri` matches no registered value.
It is not the message a request object earns (`request_not_supported`) and not
the one a missing `redirect_uri` earns. The page therefore shows that AXIAM
judged the query `redirect_uri` unregistered on this run. **To be confirmed by
the maintainer's run, from the module's log:** exactly which `redirect_uri` the
module placed in the query and which in the request object. The repository holds
the screenshot and the report, not the log, so it cannot say. If the log shows a
registered URI in the query and an unregistered one only inside the object, the
page in the image could not have come from step 2 and the entry must be
rewritten rather than relied on.

**Does the existing evidence suffice?** For the condition, yes, as for the
previous module. The one point above is a reading of the log, not a new capture.

**Open, for the maintainer.** Whether a reviewer expects an OP that does not
support request objects to satisfy this module by the page alone is the
Foundation's call; the entry states AXIAM's behaviour and the clause, and does
not claim to know their reading.

---

# FAPI 2.0 Security Profile (Final)

Three plans, one per client-authentication variant, run by the same harness
against the same clients registered `profile: fapi2`, `require_par: true`,
`browser_sso: true` (`conformance/scripts/register-clients.sh`). The variant
blocks are in `conformance/plans/fapi2-security-profile-final-*.json`:
`fapi_profile: plain_fapi`, `openid: openid_connect`, and, for `mtls` and
`self-signed`, `client_auth_type: mtls` with `sender_constrain: mtls`; for
`private-key-jwt`, `client_auth_type: private_key_jwt` with
`sender_constrain: dpop`. The two mTLS plans therefore name the same suite
variant and differ in the client's credential (a CA-issued certificate against a
self-signed one). The competitor-gap plan's "four FAPI variants" counts the Basic
OP plan with these three; there is no fourth FAPI variant.

Per-variant 2026-09-25 plan ids, from the three
`2026-09-25-fapi2-security-profile-final-*.md` reports: `mtls` `A6nvEhaNVt4hQ`
(37 modules), `self-signed` `9xDkyLVW61B39` (37), `private-key-jwt`
`IKxIaLZ4ZWC1z` (56). Module names below omit the prefix
`fapi2-security-profile-final-`. Each entry's evidence is the image the module
uploaded, listed in [`evidence/2026-09-25/manifest.json`](evidence/2026-09-25/manifest.json).
The FAPI plans ran on the same build as the Basic OP plan: `origin/main` at
`8a0af1033` (1.0.0-beta16) plus a lockfile update, per
[`evidence/2026-09-25/README.md`](evidence/2026-09-25/README.md). **That build
predates the Phase 23 W1 gates** (T23.1.1, 2026-10-02: `git merge-base
--is-ancestor 3b9b8f6 8a0af1033` is false), so the 2026-09-25 logs say nothing
about them; the maintainer's run is the first against the tree these entries
describe.

---

## `ensure-unsigned-authorization-request-without-using-par-fails`

**Suite log.** One per variant, each verdict `REVIEW` in that variant's
2026-09-25 report, each with one image uploaded (`images_uploaded: 1` in the
manifest):

| Variant | Suite log | Evidence |
|---|---|---|
| `mtls` | `hubHxFIqq4NIObo` | [`fapi2-security-profile-final-mtls__ensure-unsigned-authorization-request-without-using-par-fails__dc2918eeb2.jpg`](evidence/2026-09-25/fapi2-security-profile-final-mtls__ensure-unsigned-authorization-request-without-using-par-fails__dc2918eeb2.jpg) |
| `self-signed` | `73MqxLgoSS6V38N` | [`fapi2-security-profile-final-self-signed__ensure-unsigned-authorization-request-without-using-par-fails__dc2918eeb2.jpg`](evidence/2026-09-25/fapi2-security-profile-final-self-signed__ensure-unsigned-authorization-request-without-using-par-fails__dc2918eeb2.jpg) |
| `private-key-jwt` | `c0Rb6Ejn7RpJoRQ` | [`fapi2-security-profile-final-private-key-jwt__ensure-unsigned-authorization-request-without-using-par-fails__dc2918eeb2.jpg`](evidence/2026-09-25/fapi2-security-profile-final-private-key-jwt__ensure-unsigned-authorization-request-without-using-par-fails__dc2918eeb2.jpg) |

**What the suite could not decide.** The condition, verbatim from the manifest
(identical for the three variants):

> If the server does not return an invalid_request error back to the client, it
> must show an error page saying the request is invalid as it is missing the
> request_object - upload a screenshot of the error page.

Two answers are right: an `invalid_request` delivered to the client, or an error
page. The suite cannot judge whether what the browser was shown is an error page
saying the request is invalid, so it asks for the picture.

**What the image shows.** Read, not classified by size or hash. The `mtls` file
was viewed; the other two have the same MD5 (`dc2918eeb2cce9fb05d1907defe9f99c`,
in the manifest and on disk), so they are the same bytes. It is a plain,
unstyled page headed **"This authorization request cannot be completed"**, the
sentence **"this client must use pushed authorization requests (RFC 9126); send
parameters to /oauth2/par first"**, `Error code: invalid_request`, and *"Nothing
has been shared with the application that sent you here. Return to it and start
again."* There is no sign-in form and no variant-specific content, which is why
three variants produce one file. The image does not show the request that
earned it or whether a sign-in page came first (below).

**What AXIAM does.**

- A client registered `require_par` that reaches `/oauth2/authorize` without a
  pushed request is refused `OAuth2Error::ParRequired`, wire code
  `invalid_request`: `crates/axiam-oauth2/src/authorize.rs`,
  `AuthorizeService::authorize`, step 1b, after the client lookup and **before**
  the `redirect_uri` comparison (`error.rs`: `ParRequired` → `invalid_request`).
  The sentence is the one in the image.
- It is answered **in place**, never by redirecting:
  `crates/axiam-api-rest/src/handlers/oauth2.rs`, the arm that sends
  `InvalidClient | InvalidRedirectUri | ParRequired` to
  `authorize_error_response` (a page for a browser that accepts HTML, `400` JSON
  otherwise). The comment gives the reason: `redirect_uri` arrived by the very
  channel the client forbade and had not been validated, so redirecting to it
  would defeat the setting.
- A `fapi2` client cannot be registered without `require_par`
  (`fapi.rs`, `FapiRegistrationError::ParNotRequired`, "FAPI 2.0 §5.3.1.2
  requires pushed authorization requests"), so the refusal holds for every
  client the plan registers.
- Pinned by `par_test.rs::a_require_par_client_cannot_authorize_directly` (`400`,
  not `302`), `oauth2_login_hop_test.rs::t0_4_the_return_leg_still_refuses_a_require_par_client_sending_inline_parameters`
  and `::m7_a_fapi2_return_leg_with_inline_parameters_is_par_required` (`400`, no
  `Location`, `invalid_request`, the wording above).
- **What those tests do not pin, from reading the code.** They drive a request
  that already holds an OP session. For an *anonymous* browser,
  `resolve_authorize_principal` in `handlers/oauth2.rs` has no `require_par`
  check, and the `browser_sso` conformance clients take the login hop first, so
  the refusal is rendered on the return leg, after a sign-in. `drive-browser.mjs`
  can capture an error page on either path (its `visit()` records an `error`
  shot both when no sign-in form appears and when sign-in is followed by neither
  consent nor the suite's callback). **Which one produced the 2026-09-25 image
  is in the module's log and is to be confirmed by the maintainer's run.** The
  tests above cover the second leg and nothing covers the first.

**Why that is conformant.** FAPI 2.0 Security Profile §5.3.1.2, as
`fapi.rs` cites it, requires the authorization server to require pushed
authorization requests, and an unpushed request is refused. The condition
accepts an error page as an alternative to an `invalid_request` returned to the
client, and the page carries the code the condition names. Not redirecting is
RFC 6749 §4.1.2.1: an error goes to a `redirect_uri` only after it has been
validated, and this request's has not been. The wording differs from the
condition's ("missing the request_object"): AXIAM supports no request object on
any carrier (`request_parameter_supported: false`, see the Basic OP entry
`oidcc-ensure-request-object-with-redirect-uri`), and its refusal is for the
absence of PAR. The 2026-09-25 evidence README records the same caveat ("a
wording divergence, not a behavioural one"); whether the Foundation's reviewer
reads it the same way is theirs to decide.

**Does the existing evidence suffice?** For the condition as worded, yes: an
error page, in a browser, carrying `invalid_request`, for all three variants. It
cannot show, and *to be confirmed by the maintainer's run* from each variant's
log: that the request the module sent carried no `request_uri`; that no sign-in
was asked for first, or if it was, that the reviewer is shown that; and, for the
final run, that the image still says `invalid_request` (T23.1.1 changed the
`fapi2` gate after the baseline, though not this refusal).

**Open, for the maintainer.** (1) The wording divergence above. (2) Whether an
anonymous request from a `require_par` client should be refused before the login
hop, as `response_type` and a dead `request_uri` already are, rather than after
sign-in. It is decidable without a principal. This entry does not propose it and
no code was changed; the 2026-09-25 verdict does not depend on it, but a reviewer
who reads the log and sees a sign-in precede the refusal may ask.

---

## `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`

**Suite log.** One per variant, each verdict `REVIEW`, each with one image:

| Variant | Suite log | Evidence |
|---|---|---|
| `mtls` | `H2OiSzJ5MolJxvg` | [`fapi2-security-profile-final-mtls__par-ensure-reused-request-uri-prior-to-auth-completion-succeeds__3bfc90363d.jpg`](evidence/2026-09-25/fapi2-security-profile-final-mtls__par-ensure-reused-request-uri-prior-to-auth-completion-succeeds__3bfc90363d.jpg) |
| `self-signed` | `yhcCDPi0oikE4FC` | [`fapi2-security-profile-final-self-signed__par-ensure-reused-request-uri-prior-to-auth-completion-succeeds__3bfc90363d.jpg`](evidence/2026-09-25/fapi2-security-profile-final-self-signed__par-ensure-reused-request-uri-prior-to-auth-completion-succeeds__3bfc90363d.jpg) |
| `private-key-jwt` | `xHPfInpD8AbPbaU` | [`fapi2-security-profile-final-private-key-jwt__par-ensure-reused-request-uri-prior-to-auth-completion-succeeds__736d1520ee.jpg`](evidence/2026-09-25/fapi2-security-profile-final-private-key-jwt__par-ensure-reused-request-uri-prior-to-auth-completion-succeeds__736d1520ee.jpg) |

**What the suite could not decide.** The condition, verbatim from the manifest:

> The login page should be shown, if not upload a screenshot of the error page.

The module presents one `request_uri` twice, before any authorization has
completed, and expects the login page both times. The suite cannot tell whether
the page the browser reached is a login page, so it asks for the picture.

**What the image shows.** Read, not classified by size or hash. The `mtls` and
`private-key-jwt` files were viewed; the `self-signed` file has the `mtls`
file's MD5 (`3bfc90363df62c9171faa8c166887ce2`), so it is the same bytes. Both
viewed images show AXIAM's sign-in page at the credentials step: "Workspace:
test-org (organization)", an empty, focused "Username or email" field, a
password field showing only placeholder dots, `Back`, `Cancel` and `Sign in`
buttons, and `Sign in with a passkey`. They look the same; they differ in bytes
(`3bfc90363d` against `736d1520ee`), as two captures of a live page do. Neither
carries the notice "Please sign in again to continue.", which is right here:
this module does not ask for a re-authentication, and the notice is rendered only
for `reauth=1` (see `oidcc-prompt-login`). The image does not show which of the
module's two visits it belongs to.

**What AXIAM does.**

- `/oauth2/par` stores the pushed request under a handle valid for 60 seconds
  (`par.rs`, `REQUEST_URI_LIFETIME_SECS`), keyed by its hash.
- `/oauth2/authorize` answers an anonymous browser with the login hop. Before it
  does, it asks `ParService::peek` (`par.rs`) about the handle. `peek` is a
  **read**: it refuses what was already dead (unknown, expired, spent, issued to
  another client) and spends nothing, and it returns `()` rather than the pushed
  parameters so that nothing can authorize from it
  (`handlers/oauth2.rs`, the block headed "The handle, before a person is asked
  to sign in for it", whose comment names this module as the property it must
  keep). A handle presented a second time before any authorization is still
  unspent and unexpired, so the second visit reaches the login page too.
- The handle is spent in `ParService::consume`, in the handler, after a principal
  exists, by the repository's guarded `UPDATE` inside a transaction with a nonce
  read-back, so that two racing authorizations produce one code (X6, issue #302;
  `crates/axiam-db/src/repository/pushed_auth_request.rs` module header).
- Pinned by `par.rs::a_live_handle_passes_and_is_not_spent` (its doc comment
  names this module), `oauth2_login_hop_test.rs::an_unconsumed_request_uri_still_reaches_the_login_page_twice`
  (two anonymous requests with one live handle, both `302` to
  `/login?return_to=`, and the handle still spendable afterwards), and in the
  database `permission_ticket_test.rs::pushed_auth_request_find_unconsumed_reads_without_spending`
  (two reads, neither spends) with `::pushed_auth_request_consume_serialises`
  (exactly one winner among racers). The opposite case is pinned too, so the
  early refusal cannot swallow this one: `par.rs::a_gone_handle_is_refused_with_the_shared_sentence`
  and `par_test.rs::a_request_uri_works_once_and_then_never_again`.
- The module's twin `par-attempt-reuse-request_uri`, which presents a handle
  **after** an authorization completed and requires a refusal, is `PASSED` in all
  three 2026-09-25 reports (it is in each report's passed list).

**Why that is conformant.** The single-use rule the repository cites for a
pushed request (`par.rs`, RFC 9126 §2.2) is about redeeming it for an
authorization. Showing a login page redeems nothing: no code is minted and no
principal exists. AXIAM spends the handle where a code is minted and nowhere
earlier, which is what the module's name asks for (the suite names it
*"…succeeds"*), and what its twin asks for after completion.

**Does the existing evidence suffice?** For the condition as worded, yes: the
image is the login page, the alternative being an error page. A `REVIEW` and not
a `FAILED` is what each report records; the reports say nothing more. *To be
confirmed by the maintainer's run*, from each variant's log: which visit the
image comes from; that the first visit stopped at the login page and the second
signed in and completed (the driver is built that way, and quotes the suite's own
refusal for signing in on the first, in `drive-browser.mjs`, `STOP_AT_LOGIN_SUFFIX`);
and the interval between the push and the second request, which must stay inside
the 60-second lifetime or the second request is refused as gone, which is
AXIAM working as intended and the module failing.

**Open, for the maintainer.** None specific to this module.

---

## `test-claims-parameter-identity-claims`

**Suite log.** Verdict `WARNING`, on **all three** variants, not on
`private-key-jwt` alone as the competitor-gap plan's §4 G-1 table has it. The
2026-09-25 reports:

| Variant | Suite log |
|---|---|
| `mtls` | `E3LMGPfxxRnrBff` |
| `self-signed` | `Ifh31qq9b0lDMpw` |
| `private-key-jwt` | `v440VDWfwxP7kKo` |

The same module is `WARNING` on every variant in every FAPI report from
2026-09-10 to 2026-09-25 (seven dates, 21 reports; the ids are in the "Modules
that did not pass" tables of the dated reports). A `WARNING` uploads no
evidence, so there is no image and no manifest row, and **the reports record
nothing about why**: they carry a verdict and a log id.

**What the suite could not decide.** Nothing; a `WARNING` is a decided, non-fatal
verdict, which the report defines as "a non-fatal deviation; permitted, but worth
understanding before submitting". What is open is the *reason*, which only the
log holds. The module's name says it requests identity claims through the OpenID
Connect `claims` parameter; what it requests, in which member, and which
condition raised the warning is **to be confirmed by the maintainer's run**.

**What the image shows.** There is none.

**What AXIAM does with `claims`.** This is the design question (competitor-gap
plan §4 G-1, Design item 2): is the warning the "`claims` parameter not
supported" deviation FAPI permits? **The repository does not support that
reading for the 2026-09-25 build.**

- Discovery publishes `claims_parameter_supported: true`
  (`crates/axiam-oauth2/src/oidc.rs`, the `claims_parameter_supported: true`
  line; asserted on the serialised document by
  `oidc.rs::discovery_tells_the_truth_about_request_objects_and_claims`). That is
  also the value at the 2026-09-25 build base: `git show
  8a0af1033:crates/axiam-oauth2/src/oidc.rs` has `true`. The evidence READMEs of
  2026-09-18 and 2026-09-25 say the suite runs the module "although AXIAM
  advertises `claims_parameter_supported: false`"; for 2026-09-25 that sentence
  is wrong about the build, and the remediation plan of 2026-09-12 (§10.1)
  already warned that the recorded cause of the warning predates the commit that
  set the value to `true`. Several comments and one compliance row still say
  `false` (`authn_params.rs` lines 104 and 420,
  `docs/compliance/oidc-conformance.md` row 35); they are stale, and the code
  and its test say `true`.
- What is honoured: the `userinfo` member, for the claims in
  `claims_request::RELEASABLE` (profile and email claims; never `phone_number`,
  `phone_number_verified` or `address`, which stay behind the consent
  ceremony). The `id_token` member is **ignored**, with one exception: its `acr`
  member, which is read on the honour lane only
  (`crates/axiam-oauth2/src/claims_request.rs`; `authn_params.rs`,
  `parse_claims_acr`). A `fapi2` client is never on the honour lane.
- On `fapi2`, `fapi.rs::enforce_authorization_request` refuses the parameters
  AXIAM would otherwise drop, and `claims` is one of them **only** when it asks
  for `id_token.acr` or cannot be read well enough to rule that out
  (`authn_params.rs`, `security_bearing_present`). A `claims` that asks only for
  `userinfo` members, or for other `id_token` members, is served, not refused.

So the warning is not "the OP does not support `claims`": AXIAM advertises and
partly honours it. What the suite objected to is in the log. One possibility the
code makes live, offered as a hypothesis and not a finding: if the module asks
for identity claims in the `id_token` member, AXIAM ignores that member, and the
ID token would not carry them. The Phase 23 W1 security review (§8 item (g),
`claude_dev/security-review-phase23-w1-2026-10-03.md`) recalls that the module
requests `given_name`, `family_name` and similar in `id_token` and `userinfo`,
and that the ACR-requesting conditions belong to the Brazil profile and not to
`plain_fapi`, and says plainly that this could not be verified offline.

**What changed since the baseline, and what lands next.**

- **W1, T23.1.1 (`3b9b8f6`, 2026-10-02).** A `fapi2` client's
  `claims.id_token.acr` is now refused `invalid_request`. Before, it was dropped
  silently, which is the downgrade OIDC Core §5.5.1.1 says to treat as a failed
  authentication. Pinned by
  `fapi.rs::a_fapi2_client_may_send_claims_for_userinfo_but_not_for_id_token_acr`.
  The gate's comment (`authn_params.rs`) and the T-239 amendment in
  `claude_dev/threat-model-stride.md` say a `userinfo`-only `claims`, "the shape
  the FAPI suite's `test-claims-parameter-identity-claims` module sends", stays
  unrefused. **That is the author's statement of the module's shape and nothing
  in this repository verifies it.**
- **W2, D-12 (decided 2026-10-03, rides T23.1.4).** An **essential**
  `claims.id_token.auth_time` is to be refused on `fapi2` exactly as
  `id_token.acr` is, because OIDC Core §2 makes `auth_time` REQUIRED when
  requested as essential and today it is dropped. At the time of writing it has
  not landed on `claude/phase23-w2` (`authn_params.rs` there has no `auth_time`
  handling at `5e3df3c`); this entry describes it as decided and landing in W2,
  and must be re-read against the code once it does.
- Neither change touches `claims` for `userinfo` members.

**Why that is conformant.** For the part the code settles: AXIAM does not
silently discard a request it cannot satisfy on the one lane where discarding
would manufacture an assurance (`id_token.acr`, and with D-12 an essential
`auth_time`), and it serves the `userinfo` member it supports. The repository
cites no FAPI 2.0 clause that requires or forbids `claims` support for an OP,
and it cannot say whether the Foundation's `WARNING` is a deviation a reviewer
accepts; the runbook's own definition is that it is "a permitted deviation the
suite wants you to notice". Whether this one is acceptable cannot be concluded
without the log.

**Does the existing evidence suffice?** No, and none exists to be sufficient:
a verdict and three log ids. *To be confirmed by the maintainer's run* (F4
item (g), runbook checklist §3): the one module on one variant, the saved log's
authorization request URL-decoded for its `claims` parameter, looking for
`"acr"` and `"auth_time"` under `id_token`, and the condition that raised the
warning. If the module requests `acr`, a `fapi2` client's request now ends
`invalid_request` where the baseline ended `WARNING`, and the verdict can change
to a failure; that would be a finding to judge before the submission, not a
harness defect. It is unknown without a run whether the module requests `acr` or
an essential `auth_time`.

**Open, for the maintainer.** If the log shows the warning comes from identity
claims requested in the `id_token` member being ignored, clearing it would mean
honouring the `id_token` member of `claims` on the `fapi2` lane, or on the honour
lane only. **That is a product and security decision this entry does not take and
no code implements.** The code argues against doing it casually: `claims_request.rs`
records that the ID token deliberately carries no more than OIDC Core §5.4 says
(the §5.4 work that removed `tenant_id`, `org_id` and `email` from it), and
honouring §5.5 there "would put claims back that were deliberately taken out".
The alternative is to publish the warning as a documented, accepted `WARNING`,
with this entry as its account. Either way the maintainer decides, after the
log. Until then the proposed judgement is only: **a `WARNING` on every
variant, reason unread, not the "not supported" deviation.**

---

# Open questions, collected

For the maintainer. None of them blocks writing the entries above; each is
something the repository cannot decide. Items 1 to 3 are the Basic OP entries'
(T23.1.6); items 4 to 7 are the FAPI 2.0 entries' (T23.1.7).

1. **The log-only points.** Three facts the Basic OP entries need can be read
   only from the suite logs of the final run, and are marked in the entries:
   the first sign-in and the second request's parameters for `prompt-login` and
   `max-age-1`; the delay before `max-age-1`'s second request; and which
   `redirect_uri` the request-object module placed where.
2. **The skipped module.** The Basic OP plan's single `SKIPPED` module is not
   named in any published report (before T23.1.6 `report.py` counted skipped
   modules without listing them). The acceptance wording, "every module `PASSED`
   or a documented `SKIPPED`", needs it named and its reason read from its log
   in the final run; the new report lists it.
3. **Reviewer acceptance.** Whether the Foundation's reviewer accepts a single
   screenshot plus the log for the four modules is theirs to decide; this file
   states AXIAM's behaviour, the code that pins it and the clause. The same holds
   for the two FAPI `REVIEW` modules, including the wording divergence in
   `ensure-unsigned-authorization-request-without-using-par-fails`.
4. **The FAPI log-only points (T23.1.7).** Read from the final run's logs and
   written into the entries: for the unsigned-request module, the request the
   suite sent and whether a sign-in page preceded the refusal; for the
   reused-`request_uri` module, which visit the image belongs to and the interval
   between the push and the second request (60-second lifetime); for the claims
   module, the authorization request's `claims` value and the condition that
   raised the warning (F4 item (g)).
5. **The claims `WARNING`: honour or accept.** If the log shows identity claims
   requested in the `id_token` member being ignored, either the `id_token` member
   is honoured on the `fapi2` lane (or the honour lane only), or the warning is
   published as accepted with its entry as the account. A product and security
   decision; nothing in the repository takes it, and no code implements it.
6. **Refuse an unpushed request before the login hop?** A `require_par` client's
   request with no `request_uri` is refused only after sign-in today (return
   leg). Whether to refuse it earlier is the maintainer's; nothing here proposes
   it.
7. **D-12 and the stale `false`.** Re-read the claims entry once D-12 (an
   essential `claims.id_token.auth_time` refused on `fapi2`, T23.1.4) lands. Four
   places still say discovery publishes `claims_parameter_supported: false`
   though the code and its test say `true`: the 2026-09-18 and 2026-09-25
   evidence READMEs, comments in `authn_params.rs`, and row 35 of
   `docs/compliance/oidc-conformance.md`. They are outside this task's files and
   are not edited here.

## Sign-off

Filled in by the maintainer after the final run. Left blank deliberately.

| Plan | Final-run plan id | Image digest | Every entry above confirmed against these logs | Date |
|---|---|---|---|---|
| Basic OP | | | | |
| FAPI 2.0 `mtls` | | | | |
| FAPI 2.0 `self-signed` | | | | |
| FAPI 2.0 `private-key-jwt` | | | | |
