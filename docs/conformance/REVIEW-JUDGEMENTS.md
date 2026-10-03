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

**Status of this revision.** Written from the 2026-09-25 reports and evidence,
against the tree at `claude/phase23-w2`. No entry has been confirmed against a
final run yet; every entry's verdict below is *proposed*.

## Index

| Plan | Module | 2026-09-25 log | Evidence | Proposed judgement |
|---|---|---|---|---|
| Basic OP | `oidcc-prompt-login` | `c0oSGcvXhBtjj9D` | [`oidcc-basic-static__prompt-login__d4f4ba0105.jpg`](evidence/2026-09-25/oidcc-basic-static__prompt-login__d4f4ba0105.jpg) | Conformant; the image shows the re-authentication page, the log must show the first sign-in |
| Basic OP | `oidcc-max-age-1` | `RSzk3w8Kxro3IYC` | [`oidcc-basic-static__max-age-1__f77ce8cb67.jpg`](evidence/2026-09-25/oidcc-basic-static__max-age-1__f77ce8cb67.jpg) | Conformant; same shape as `prompt-login` |
| Basic OP | `oidcc-ensure-registered-redirect-uri` | `szkbM07X3ihnZoY` | [`oidcc-basic-static__ensure-registered-redirect-uri__f39dea4139.jpg`](evidence/2026-09-25/oidcc-basic-static__ensure-registered-redirect-uri__f39dea4139.jpg) | Conformant; the page is the one RFC 6749 §3.1.2.4 asks for |
| Basic OP | `oidcc-ensure-request-object-with-redirect-uri` | `d93KQKPrWLutU8W` | [`oidcc-basic-static__ensure-request-object-with-redirect-uri__f39dea4139.jpg`](evidence/2026-09-25/oidcc-basic-static__ensure-request-object-with-redirect-uri__f39dea4139.jpg) | Conformant on the evidence, with one point the live log must confirm |
| FAPI 2.0 | three modules | — | — | Written by T23.1.7, below |

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

# FAPI 2.0 — written by T23.1.7

*This section is a placeholder. T23.1.7 writes the entries; T23.1.6 wrote the
structure above and the four Basic OP entries only.* The modules to be written up,
with their 2026-09-25 logs (copied from the dated reports and
[`evidence/2026-09-25/manifest.json`](evidence/2026-09-25/manifest.json)), are:

| Module (prefix `fapi2-security-profile-final-` omitted) | Verdict | `mtls` | `self-signed` | `private-key-jwt` |
|---|---|---|---|---|
| `ensure-unsigned-authorization-request-without-using-par-fails` | `REVIEW` | `hubHxFIqq4NIObo` | `73MqxLgoSS6V38N` | `c0Rb6Ejn7RpJoRQ` |
| `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` | `REVIEW` | `H2OiSzJ5MolJxvg` | `yhcCDPi0oikE4FC` | `xHPfInpD8AbPbaU` |
| `test-claims-parameter-identity-claims` | `WARNING` | `E3LMGPfxxRnrBff` | `Ifh31qq9b0lDMpw` | `v440VDWfwxP7kKo` |

The three FAPI 2.0 plans are `mtls`, `self-signed` and `private-key-jwt`; there is
no fourth variant. The `WARNING` is recorded in all three 2026-09-25 reports, not
only in `private-key-jwt`'s (the competitor-gap plan's §4 G-1 table attributes it
to that variant alone; the reports are the evidence).

---

# Open questions, collected

For the maintainer. None of them blocks writing the entries above; each is
something the repository cannot decide.

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
   states AXIAM's behaviour, the code that pins it and the clause.

## Sign-off

Filled in by the maintainer after the final run. Left blank deliberately.

| Plan | Final-run plan id | Image digest | Every entry above confirmed against these logs | Date |
|---|---|---|---|---|
| Basic OP | | | | |
| FAPI 2.0 `mtls` | | | | |
| FAPI 2.0 `self-signed` | | | | |
| FAPI 2.0 `private-key-jwt` | | | | |
