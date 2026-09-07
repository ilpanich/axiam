# OIDC Core 1.0 Conformance Matrix

**Standard:** OpenID Connect Core 1.0, OpenID Connect Discovery 1.0

**Test locations:**
- `crates/axiam-api-rest/tests/oauth2_flow_test.rs` — OIDC happy-path tests, and the
  X7.1 invariant-4 pins P1/P2
- `crates/axiam-api-rest/tests/oidc_conformance.rs` — MUST-gap conformance tests (Phase 7)
- `crates/axiam-server/tests/req5_oidc_e2e.rs` — service-layer alg:none rejection
- `crates/axiam-oauth2/src/fapi.rs` — the profile-confusion matrix (X7.1, plan §7)
- `crates/axiam-oauth2/src/authn_params.rs` — the authentication-request parameter parser
- `crates/axiam-api-rest/src/handlers/oauth2.rs` — request-object classification (T12.*)

---

## OpenID Connect Discovery 1.0 §3

| # | MUST | Spec Ref | Status | Evidence |
|---|------|----------|--------|----------|
| 1 | Discovery endpoint MUST return issuer | Discovery §3 | Pass | `oauth2_flow_test.rs::oidc_discovery_document` |
| 2 | Discovery endpoint MUST return authorization_endpoint | Discovery §3 | Pass | `oauth2_flow_test.rs::oidc_discovery_document` |
| 3 | Discovery endpoint MUST return token_endpoint | Discovery §3 | Pass | `oauth2_flow_test.rs::oidc_discovery_document` |
| 4 | Discovery endpoint MUST return jwks_uri | Discovery §3 | Pass | `oauth2_flow_test.rs::oidc_discovery_document` |
| 5 | Discovery endpoint MUST return response_types_supported | Discovery §3 | Pass | `oidc_conformance.rs::discovery_doc_has_all_required_fields` |
| 6 | Discovery endpoint MUST return subject_types_supported | Discovery §3 | Pass | `oidc_conformance.rs::discovery_doc_has_all_required_fields` |
| 7 | Discovery endpoint MUST return id_token_signing_alg_values_supported | Discovery §3 | Pass | `oauth2_flow_test.rs::oidc_discovery_document` + `oidc_conformance.rs::discovery_doc_has_all_required_fields` |
| 8 | id_token_signing_alg_values_supported MUST NOT contain "none" | Discovery §3 / Core §3.1.3.7 | Pass | `oidc_conformance.rs::discovery_doc_excludes_alg_none` |
| 9 | All 7 REQUIRED fields present in a single exhaustive check | Discovery §3 | Pass | `oidc_conformance.rs::discovery_doc_has_all_required_fields` |

## OpenID Connect Core 1.0 — Token Endpoint

| # | MUST | Spec Ref | Status | Evidence |
|---|------|----------|--------|----------|
| 10 | id_token MUST be returned when openid scope is requested | Core §3.1.3.3 | Pass | `oauth2_flow_test.rs::oidc_id_token_in_auth_code_flow` |
| 11 | id_token MUST NOT be returned without openid scope | Core §3.1.3.3 | Pass | `oauth2_flow_test.rs::oidc_no_id_token_without_openid_scope` |
| 12 | id_token iss MUST match discovery issuer | Core §3.1.3.7 | Pass | `oidc_conformance.rs::id_token_iss_matches_discovery_issuer` |
| 13 | id_token MUST contain sub, aud, iss, iat, exp | Core §2 | Pass | `oauth2_flow_test.rs::oidc_id_token_in_auth_code_flow` |
| 14 | id_token MUST contain nonce when nonce was sent | Core §3.1.3.7 | Pass | `oauth2_flow_test.rs::oidc_id_token_in_auth_code_flow` |
| 15 | id_token MUST NOT use alg:none at service layer | Core §3.1.3.7 | Pass | `req5_oidc_e2e.rs::oidc_rejects_alg_none` (line 179) |
| 16 | id_token MUST use EdDSA algorithm | Core §3.1.3.7 | Pass | `oauth2_flow_test.rs::oidc_jwks_endpoint` (alg=EdDSA) |

## OpenID Connect Core 1.0 — UserInfo Endpoint

| # | MUST | Spec Ref | Status | Evidence |
|---|------|----------|--------|----------|
| 17 | UserInfo MUST return sub | Core §5.3 | Pass | `oauth2_flow_test.rs::oidc_userinfo_returns_sub` |
| 18 | UserInfo MUST require authentication | Core §5.3 | Pass | `oauth2_flow_test.rs::oidc_userinfo_requires_auth` |
| 19 | UserInfo MUST return email when email scope present | Core §5.4 | Pass | `oauth2_flow_test.rs::oidc_userinfo_with_email_scope` |
| 20 | UserInfo MUST return preferred_username when profile scope present | Core §5.4 | Pass | `oauth2_flow_test.rs::oidc_userinfo_with_profile_scope` |

## JSON Web Key Set (RFC 7517)

| # | MUST | Spec Ref | Status | Evidence |
|---|------|----------|--------|----------|
| 21 | JWKS MUST return valid Ed25519 public key | RFC 7517 | Pass | `oauth2_flow_test.rs::oidc_jwks_endpoint` |
| 22 | JWKS key MUST have kty=OKP, crv=Ed25519, alg=EdDSA, use=sig | RFC 7517 | Pass | `oauth2_flow_test.rs::oidc_jwks_endpoint` |

---

## OpenID Connect Core 1.0 — authentication-request parameters (X7.1, wave W1)

What this wave pins is **refusal and non-regression**, not honouring: AXIAM
parses the nine OIDC authentication-request parameters and acts on none of
them. The per-client `authn_request_params` switch defaults to `ignore`, which
is what every client registered before schema v54 decodes to, and the `honour`
lane that would act on them is a later wave. Rows 23–26 therefore record the
*current, deliberate* posture; rows 27–30 record the refusals that are final.

| # | Behaviour | Spec Ref | Status | Evidence |
|---|-----------|----------|--------|----------|
| 23 | `prompt`, `max_age`, `acr_values`, `claims`, `id_token_hint` are accepted and ignored for a `standard`/`ignore` client, with no change to the redirect, the token response or the ID token | Core §3.1.2.1 | Ignored (by design, invariant 4) | `oauth2_flow_test.rs::p1_a_standard_client_is_unchanged_by_every_new_parameter` |
| 24 | `login_hint`, `display`, `ui_locales`, `claims_locales` are accepted and ignored **for a `standard`/`ignore` client** — the login URL such a client's browser is sent to is byte-identical to W3's, with no `login_hint`, `display` or `ui_locale` on it | Core §3.1.2.1, §5.2 | Ignored (by design, invariant 4) | same as row 23; `oauth2_cosmetic_params_test.rs::m5_m6_i4_twin_an_ignore_lane_client_gets_the_w3_login_url_byte_for_byte`, `::i4_twin_the_interaction_arm_is_unreachable_for_an_ignore_lane_client` |
| 25 | `auth_time`, `acr` and `amr` are **not** emitted merely because a request asked for them — an `ignore`-lane client receives none of the three however much it asks | Core §2, §3.1.3.7 | Not emitted for `ignore` (still true after W4) | `oauth2_flow_test.rs::p1_…` asserts their absence; `oauth2_honour_lane_test.rs::t3_5_…`, `::t2_1_i4_twin_…` |
| 26 | The same parameters are carried by PAR and by the inline query string, and parse identically from either | RFC 9126 §2.1 | Pass | `authn_params.rs::the_par_carrier_parses_identically_to_the_inline_one` |
| 27 | A `fapi2` client is **refused** the five security-bearing parameters with `invalid_request` | FAPI 2.0 §5.3.1 | Pass | `fapi.rs::m1_m4_security_bearing_parameters_are_refused_for_a_fapi_client`; `oauth2_flow_test.rs::a_fapi_client_is_refused_the_security_bearing_parameters` |
| 28 | A `fapi2` registration may not set `authn_request_params: honour`, on create or on update | FAPI 2.0 §5.3.1 | Pass | `fapi.rs::m1_m6_fapi_plus_honour_is_refused_at_creation`, `::…_on_update` |
| 29 | A `fapi2` registration may not register the `address` or `phone` scope, on create or on update | Core §5.4 (GDPR) | Pass | `fapi.rs::m8_fapi_plus_sensitive_scopes_is_refused_at_creation`, `::…_on_update` |
| 30 | A `fapi2` client sending none of the nine is unaffected by all of the above | — | Pass | `oauth2_flow_test.rs::p2_a_fapi_client_sending_none_of_them_is_unaffected`; `fapi.rs::p2_a_fapi_client_sending_none_of_them_is_unaffected` |

## OpenID Connect Core 1.0 — request objects (X7 G12)

AXIAM implements neither form of request object and says so, rather than
failing with a generic error. `request_uri` by reference would have the
authorization server fetch a URL the request chose — an SSRF primitive that
PAR (RFC 9126 §1) made unnecessary and that FAPI 2.0 does not ask for.

| # | Behaviour | Spec Ref | Status | Evidence |
|---|-----------|----------|--------|----------|
| 31 | A `request` parameter is refused with `request_not_supported` | Core §3.1.2.6, §6.1 | Pass (refused) | `handlers/oauth2.rs::request_object_tests::t12_1_a_request_object_by_value_is_classified` |
| 32 | A `request_uri` that is not a `urn:ietf:params:oauth:request_uri:` value is refused with `request_uri_not_supported`, classified before the PAR consume path | Core §3.1.2.6, §6.2 | Pass (refused) | `…::t12_2_a_request_object_by_reference_is_classified` |
| 33 | A genuine PAR handle is untouched by that classification | RFC 9126 §2.2 | Pass | `…::t12_3_a_par_handle_is_not_a_request_object` |
| 34 | `request_parameter_supported: false` is published; `request_uri_parameter_supported` is **omitted** (its default `true` is truthful for PAR handles) | Discovery §3 | Pass | `oidc.rs::discovery_tells_the_truth_about_request_objects_and_claims` |

## OpenID Connect Core 1.0 — session evidence (X7.2, wave W2)

This wave records **when and how** an end user authenticated, and emits none of
it. `auth_time`, `acr` and `amr` are now storable, snapshottable and
mintable — and the gate that decides who receives them
(`fapi::emits_session_evidence`) answers *no* for every client, including one
an operator has already registered with `authn_request_params: honour`. Row 25
above says the same thing from the request side; rows 40–46 say it from the
token side, and add the properties that make the record worth having when the
honour lane (W4) opens.

The reason to land the record before the claim is that a record can only be
made at the moment it is true. `session.created_at` cannot stand in for
`auth_time` because refresh rotation writes a new session row on every refresh
(row 42), and a code's evidence cannot be looked up at redemption because by
then the session it came from may be gone (row 43).

| # | Behaviour | Spec Ref | Status | Evidence |
|---|-----------|----------|--------|----------|
| 40 | An ID token issued to any client registered today carries exactly the members it carried before X7.2: no `auth_time`, no `acr`, no `amr`, and no `null` placeholder for any of them | Core §2 | Not emitted (by design, invariant 4) | `oauth2_flow_test.rs::t2_6_an_ignore_lane_client_gets_the_same_id_token_though_the_session_now_has_evidence`; `token.rs::an_id_token_with_no_evidence_has_exactly_todays_claim_set` |
| 41 | The emitting lane is exactly `standard` + `authn_request_params: honour`. No `fapi2` client is on it at any setting, and no client registered today is on it | Core §2 | Opened by W4, per client | `fapi.rs::session_evidence_reaches_the_honour_lane_and_nobody_else` |
| 42 | Refresh rotation **copies** `authenticated_at` and `amr` to the session it creates rather than restamping them, so a session that is never re-authenticated never reports itself as younger | Core §12.2 | Pass | `session_evidence_rotation_test.rs::refresh_rotation_preserves_the_authentication_event` |
| 43 | The authorization code snapshots the session's evidence at issuance, with the session's instant and not the code's | Core §3.1.3.3 | Pass | `oauth2_flow_test.rs::t2_6_…` (asserts `auth_time` equals the session's, three hours old) |
| 44 | A federated login is dated by the **upstream** provider — OIDC `auth_time`, SAML `AuthnInstant`, carried across the SSO handoff hop — and only falls back to AXIAM's clock when the provider asserted no instant | Core §2 | Pass | `session.rs::upstream_evidence_prefers_the_upstream_instant`; `handlers/federation.rs::issue_sso_session` |
| 45 | `amr` records what was actually verified: `pwd` alone for a password login, `pwd otp mfa` for TOTP, `pwd hwk mfa` for a security key behind a password, `hwk user` for a usernameless passkey (whose ceremony requires user verification), `fed` for a federated sign-in | RFC 8176 §2 | Pass | `session_evidence_rotation_test.rs` (password); the five call sites in `service.rs`, `webauthn.rs`, `federation.rs` |
| 46 | A session row written before schema v55 reads back with `authenticated_at = created_at` and an empty `amr` — the strict direction in both cases, since neither can make a session look fresher or stronger than it is | — | Pass | `repository/session.rs::decode_evidence` + its tests; `schema.rs::schema_v55_adds_only_optional_columns_and_backfills_nothing` |

## OpenID Connect Core 1.0 — the browser login hop (X7.3, wave W3)

Every row above about `prompt`, `max_age` and `id_token_hint` describes a
parameter that was, until this wave, **unreachable**: `/oauth2/authorize`
required an access token, `axiam_access` is `SameSite=Strict`, and a Strict
cookie is not sent on the cross-site top-level navigation that *is* a relying
party's redirect. A signed-in user arrived at the authorization endpoint
anonymous, and an anonymous request was answered with a 401 JSON body. There
was no login page to reach.

W3 adds one, opt-in per client (`browser_sso`, schema v54, default `false`),
behind a second cookie that exists so the first three do not have to change.
It honours **no** authentication-request parameter: a `browser_sso` client that
sends `prompt=none` gets exactly the answer row 23 describes. What changes is
only how a request with *no principal* is answered, and only for a client that
asked.

| # | Behaviour | Spec Ref | Status | Evidence |
|---|-----------|----------|--------|----------|
| 47 | An unauthenticated authorization request for a client registered `browser_sso: false` — which is every client registered today — is answered with the **byte-identical** 401 JSON body AXIAM has always sent, with no `Location` header, whatever authentication-request parameters it carries | — (invariant 4) | Pass | `oauth2_login_hop_test.rs::t0_1_an_unauthenticated_request_for_a_non_browser_sso_client_is_todays_401` |
| 48 | An unauthenticated request for a `browser_sso` client is redirected to the sign-in page with a `return_to` that is a **path** on this deployment — no scheme, no host, no `//`, no traversal — naming `/oauth2/authorize` and nothing else | Core §3.1.2.1 | Pass | `…::t0_2_an_anonymous_browser_sso_request_is_sent_to_the_login_page`; `login_hop.rs::every_open_redirect_shape_is_refused`; `handlers/oauth2.rs::t0_3_return_to_must_resolve_onto_an_origin_this_deployment_owns`; `returnTo.test.ts` |
| 49 | `return_to` is validated by the builder, by the return leg, and by the SPA before it navigates — the last check by the same four rules, because the login page is reachable with a `return_to` the server never built | Core §3.1.2.1 | Pass | `login_hop.rs::the_shape_the_server_builds_is_the_shape_it_accepts`; `LoginPage.test.tsx` ("refuses … and goes to the dashboard instead") |
| 50 | The return leg re-runs **every** gate: `require_par`, exact `redirect_uri`, PKCE, and the `fapi2` profile checks. Nothing is cached across the hop | RFC 9126 §2.2; FAPI 2.0 §5.3.1.2 | Pass | `…::t0_4_the_return_leg_still_refuses_a_require_par_client_sending_inline_parameters`; `fapi.rs::m7_browser_sso_does_not_change_what_a_request_may_contain` |
| 51 | The hop terminates: a request carrying the server's own `axiam_login_hop` marker is never redirected a second time, and is answered `login_required` instead | Core §3.1.2.6 | Pass | `…::the_loop_guard_answers_the_return_leg_instead_of_redirecting_again`; `login_hop.rs::the_marker_makes_the_second_leg_recognisable` |
| 52 | A pushed request that expired during the hop (a `request_uri` lives 60 s) is refused `invalid_request_uri` with a description saying so — and **only** on the return leg, so an ordinary request with a dead handle keeps today's `invalid_request` | Core §3.1.2.6; RFC 9126 §2.2 | Pass | `…::a_pushed_request_that_expired_during_the_hop_fails_with_invalid_request_uri` |
| 53 | The `axiam_op_session` cookie is `HttpOnly; Secure; SameSite=Lax; Path=/oauth2/authorize`, with the session's lifetime. `Lax` is load-bearing: it is sent on a top-level navigation and not inside a frame, so cross-site iframe probing fails closed — and so, deliberately, does hidden-iframe silent renew | Core §3.1.2.1 | Pass | `csrf.rs::t0_6_the_op_session_cookie_attributes_are_pinned`; `oauth2_login_hop_test.rs::t0_6_a_browser_login_sets_the_op_session_cookie_with_its_intended_attributes` |
| 54 | The three API cookies are unchanged — still `SameSite=Strict` — and the OP cookie is separate bytes, not a copy of the access or refresh token | — (SEC-046) | Pass | `csrf.rs::the_api_cookies_are_still_strict_and_unscoped_by_the_op_session_cookie`; `…::t0_6_a_browser_login_sets_…` |
| 55 | A live OP session does not authorize a client that did not opt in: for `browser_sso: false` the cookie is not read at all, and the refusal is the same 401 as for a browser with no cookie | — (invariant 4) | Pass | `…::t0_5_the_op_session_cookie_is_not_honoured_for_a_client_that_did_not_opt_in` |
| 56 | An anonymous caller cannot learn which client ids exist: an unknown `client_id`, an unknown tenant and an opted-out client all answer with the same 401 | — | Pass | `…::an_unknown_client_id_is_refused_the_same_way_as_one_that_did_not_opt_in`; `…::without_a_tenant_an_anonymous_request_gets_todays_401_even_for_a_browser_sso_client` |
| 57 | Logging out — through the API or through RP-initiated `end_session` — clears the OP cookie, and the value it held authorizes nothing afterwards | RP-Initiated Logout §2 | Pass | `…::logging_out_clears_the_op_session_cookie_and_the_session_it_names` |
| 58 | Refresh rotation **copies** the OP browser-session digest (the cookie was not reissued), while a fresh sign-in **replaces** it and advances `authenticated_at` — the one event that moves what row 42 pins in place | Core §12.2 | Pass | `session_evidence_rotation_test.rs::reauthentication_moves_the_authentication_event_that_rotation_preserves` |
| 59 | A request carrying an access token is unaffected: its tenant comes from the token, and the new `tenant_id` query parameter is ignored for it | — (invariant 4) | Pass | `…::a_token_bearing_request_is_unaffected_and_ignores_the_tenant_parameter` |

## OpenID Connect Core 1.0 — the honour lane (X7.4, wave W4)

Everything above this section describes parameters AXIAM **read and did not
act on**. This is the wave where a relying party that asks for a security
property gets it, or is told it cannot have it — never a token that quietly
does not have it. It is opt-in per client
(`authn_request_params: honour`, schema v54, default `ignore`), refused for
`fapi2` at both layers, and invisible to every client registered today.

Three things decide every row below, and they are worth stating before the
table:

1. **The `acr` claim is derived from the session's evidence by a function that
   cannot see the request.** `acr::acr_for(amr: &[Amr]) -> Acr` takes the
   evidence and nothing else; there is no parameter through which the request
   could reach it. The request's `acr_values` decide only whether a step-up is
   offered and *which satisfied value* is reported — never what the claim says.
2. **`max_age = 0` is a value, not an absence**, and `elapsed >= max_age` has
   no leeway in the relying party's disfavour. See the note below for the
   consequence.
3. **The login hop is the only interaction mechanism**, and its marker is what
   makes every requirement terminate: a requirement that survives one
   interaction is answered, not retried.

| # | Behaviour | Spec Ref | Status | Evidence |
|---|-----------|----------|--------|----------|
| 60 | `prompt=none` with no usable session is answered `login_required`, **redirected to the relying party** with `state` and `iss` and no code — never with a sign-in page | Core §3.1.2.1, §3.1.2.6 | Pass | `oauth2_honour_lane_test.rs::t1_1_and_t1_7_prompt_none_without_a_session_is_login_required_at_the_relying_party` |
| 61 | `prompt=none` with a session that satisfies the request yields a code, no interaction, and an ID token carrying the evidence | Core §3.1.2.1 | Pass | `…::t1_2_prompt_none_with_a_session_yields_a_code` |
| 62 | An authentication-request parameter on the query string beside a `request_uri` is refused `invalid_request` — a browser may not top up somebody's pushed request | RFC 9126 §4 | Pass (honour lane) | `…::t1_3_an_inline_parameter_beside_a_request_uri_is_invalid_request` |
| 63 | `prompt=none` combined with any other value is `invalid_request` | Core §3.1.2.1 | Pass | `…::t1_4_prompt_none_combined_with_another_value_is_invalid_request` |
| 64 | `prompt=login` always reauthenticates, and the ID token issued afterwards carries a strictly later `auth_time` | Core §3.1.2.1 | Pass | `…::t1_5_prompt_login_reauthenticates_and_moves_auth_time_forward` |
| 65 | The sign-in page refuses the same `reauth` destination more than three times in a minute and shows an error rather than a fourth form | — | Pass | `reauth.test.ts::recordReauthAttempt (T1.6)` |
| 66 | `prompt=none` from an iframe-shaped request (no `Lax` cookie on a sub-frame navigation) is `login_required` — the login-status probe fails closed | Core §3.1.2.1 | Pass | `…::t1_1_and_t1_7_…` (same request, no cookie) |
| 67 | `max_age=0` always reauthenticates — a one-second-old session does not satisfy it, and neither does the authentication the reauthentication produces, so the chain terminates in `login_required` and never in a code | Core §3.1.2.1 | Pass (see note) | `…::t2_1_max_age_zero_always_reauthenticates_and_never_yields_a_code`; `honour.rs::t2_1_…`, `::max_age_zero_is_refused_rather_than_looped_after_a_reauthentication` |
| 68 | A session older than `max_age` reauthenticates; the token issued after the return leg carries a fresh `auth_time` (mirrors `OIDCCMaxAge1`) | Core §3.1.2.1 | Pass | `…::t2_2_an_expired_max_age_reauthenticates_and_the_second_token_is_fresh` |
| 69 | Two requests with different, satisfied `max_age` bounds report the same `auth_time` and the same `sub`, and neither reauthenticates (mirrors `OIDCCMaxAge10000`) | Core §3.1.2.1 | Pass | `…::t2_3_a_satisfied_max_age_does_not_reauthenticate` |
| 70 | A refreshed ID token's `auth_time` equals the original's (mirrors `OIDCCRefreshToken`) | Core §12.2 | Pass | `…::t2_4_a_refreshed_id_token_carries_the_original_auth_time` |
| 71 | A malformed value (`max_age=-1`, `max_age=abc`, `prompt=teleport`) is `invalid_request` on the honour lane and **dropped**, with a code issued, on the `ignore` lane | Core §3.1.2.1 | Pass | `…::t2_7_a_malformed_value_is_invalid_request_on_the_honour_lane` and `::t2_7_i4_twin_…`; `fapi.rs::t2_7_…` |
| 72 | A request for an authentication context class the session does not satisfy is **never** echoed into the `acr` claim: it produces a step-up, and a declined step-up produces a token saying what the session actually proved | Core §3.1.2.1, §5.5.1.1 | Pass | `…::t3_1_and_t3_3_an_acr_request_is_never_echoed_into_the_claim`; `acr.rs::the_claim_is_derived_from_evidence_the_request_cannot_reach`, `::an_unknown_requested_value_is_never_echoed` |
| 73 | An **essential** `claims.id_token.acr` that cannot be satisfied is refused `unmet_authentication_requirements`, never with a token | Core §5.5.1.1; `unmet_authentication_requirements` 1.0 | Pass | `…::t3_2_an_unmet_essential_acr_is_refused_rather_than_downgraded` |
| 74 | The reported class is the **most-preferred satisfied** value in the relying party's order, not the highest achieved | Core §3.1.2.1 | Pass | `…::t3_4_the_reported_class_is_the_most_preferred_one_that_is_satisfied`; `acr.rs::t3_4_…` |
| 75 | `acr_values` on an `ignore`-lane client is ignored and its ID token carries no `acr` at all | — (invariant 4) | Pass | `…::t3_5_acr_values_on_an_ignore_lane_client_produces_no_claim` |
| 76 | An `id_token_hint` must name this end user **and** this client; one that does not verify is treated as naming somebody else, never as absent | Core §3.1.2.1 | Pass | `…::an_id_token_hint_is_honoured_and_a_mismatched_one_reauthenticates`; `honour.rs::an_unverifiable_hint_is_treated_as_naming_somebody_else` |
| 77 | `select_account` is handled as `login`, and yields `account_selection_required` only where a hint mismatch survives the interaction | Core §3.1.2.1, §3.1.2.6 | Pass | `honour.rs::select_account_is_handled_as_login`, `::select_account_names_the_account_when_a_hint_still_does_not_match` |
| 78 | The outcome of every `prompt=none` request is audited per client (`oauth2.prompt_none.code` / `.login_required`), so the silent-authentication oracle is countable | — | Pass | `handlers/oauth2.rs::audit_prompt_none` |
| 79 | A federated session whose upstream `acr`/`amr` the operator has not mapped satisfies only the `1fa` floor | Core §2 | Pass (strict by default) | `acr.rs::single_factor_is_the_answer_for_everything_else` (`fed`); `handlers/federation.rs::issue_sso_session` |
| 80 | A session row written before schema v55 (`amr = []`) satisfies only the `1fa` floor and never presents as fresh beyond its creation — no backfill | — | Pass | `acr.rs::a_session_with_no_recorded_evidence_satisfies_only_the_floor`; row 46 |

## OpenID Connect Core 1.0 — the cosmetic parameters on the honour lane (wave W5)

Rows 23–24 record what happens on the `ignore` lane and stay true. These rows
record what a client registered `authn_request_params: honour` gets instead —
per client, and never for `fapi2`, whose registration cannot hold `honour`
(row 28).

The four are **never refused** on an honest `fapi2` row: they change no token,
so ignoring one costs a relying party nothing it can detect, and refusing
`login_hint` — which client libraries send by reflex — would break working FAPI
clients for no security gain. What a `fapi2` client is denied is the
*mechanism*: the server assembles a presentation only on the honour lane, so
no `/login?login_hint=` is ever built for it.

| # | Behaviour | Spec Ref | Status | Evidence |
|---|-----------|----------|--------|----------|
| 81 | `login_hint` is forwarded to the sign-in page **only when a page is being shown anyway**, and pre-fills the username field | Core §3.1.2.1 | Pass | `oauth2_cosmetic_params_test.rs::t5_1_a_hint_is_never_a_reason_to_show_a_login_page`; `LoginPagePresentation.test.tsx` |
| 82 | **No server-side lookup is performed on `login_hint`, on any path.** The response for a hint naming an existing account and one naming none is byte-identical apart from the echoed value — uniform by construction, not by two branches kept equal | Core §3.1.2.1 (enumeration) | Pass | `oauth2_cosmetic_params_test.rs::t5_1_the_response_is_identical_whether_or_not_the_hinted_account_exists`; `login_hop.rs::the_login_hint_is_echoed_and_never_interpreted` |
| 83 | A hostile `login_hint` appears in the DOM **only** as the username input's `value` — React value binding, no `dangerouslySetInnerHTML` | Core §3.1.2.1 | Pass (T5.2) | `LoginPagePresentation.test.tsx::shows a hostile hint only as the input's value` |
| 84 | `display ∈ {page, popup, touch, wap}` is forwarded; anything else is dropped rather than refused. `popup` selects a compact layout; the value is never rendered as text and never used as a class name of its own | Core §3.1.2.1 | Pass (T6.1) | `oauth2_cosmetic_params_test.rs::t6_1_display_is_allow_listed_and_never_echoed_verbatim`; `locale.rs::display_is_allow_listed_and_only_popup_is_compact` |
| 85 | `ui_locales` is matched **on the server** by RFC 4647 §3.4 lookup, in the relying party's preference order, against the five locales AXIAM ships (`en`, `it`, `fr`, `de`, `es`); the *selected tag* is forwarded and the raw value never crosses into the SPA | Core §3.1.2.1; RFC 4647 §3.4 | Pass (T6.1) | `locale.rs` unit tests; `oauth2_cosmetic_params_test.rs::t6_1_ui_locales_is_matched_on_the_server_and_forwarded_as_one_tag` |
| 86 | A `ui_locales` value that matches nothing selects nothing and appears in no redirect the server builds | Core §3.1.2.1 | Pass (T6.2) | `oauth2_cosmetic_params_test.rs::t6_2_a_hostile_ui_locales_reaches_no_redirect_the_server_builds`; `locale.rs::a_hostile_ui_locales_selects_nothing` |
| 87 | `claims_locales` is accepted, is not an error, and selects **no page language** — it is not read by the UI-locale selection at all | Core §3.1.2.1, §5.2 (`OIDCCClaimsLocales`) | Pass | `oauth2_cosmetic_params_test.rs::claims_locales_alone_leaves_the_page_in_the_default_locale`; `login_hop.rs::claims_locales_never_reaches_the_ui_locale_selection` |
| 88 | The selected locale is announced to assistive technology as `<html lang>`, and restored when the sign-in page is left | WCAG 2.2 SC 3.1.1 | Pass | `LoginPagePresentation.test.tsx::sets <html lang> to %s`, `::restores <html lang> when the page goes away` |
| 89 | An honest `fapi2` client is refused none of the four, and is offered the mechanism for none of them | FAPI 2.0 §5.3.1 | Pass (M5/M6) | `oauth2_cosmetic_params_test.rs::m5_m6_an_honest_fapi2_client_is_refused_nothing_and_offered_no_mechanism`; `fapi.rs::m5_m6_the_cosmetic_four_are_not_refused_for_an_honest_fapi_client`, `::a_fapi_row_edited_to_honour_is_refused_at_request_time` |

**Not covered, and stated rather than implied.** There is no per-tenant default
language: `ui_locales` that matches nothing falls through to the deployment
default, English. The admin console is not translated — `ui_locales` is an
authentication-request parameter and cannot reach it. Both are recorded in
`claude_dev/basic-op-gap-plan.md` §4.6's W5 amendment, with the reasoning.

## OpenID Connect Discovery 1.0 §3 — X7.1 additions

| # | Behaviour | Spec Ref | Status | Evidence |
|---|-----------|----------|--------|----------|
| 35 | `claims_parameter_supported: false` — only `claims.id_token.acr` is ever read, and a partially-honoured `claims` is worse than an unsupported one | Discovery §3 | Pass | `oidc.rs::discovery_tells_the_truth_about_request_objects_and_claims` |
| 36 | `acr_values_supported` publishes exactly `urn:axiam:acr:1fa` and `urn:axiam:acr:mfa` — a fixed vocabulary, not an operator-configurable one | Discovery §3 | Pass | `oidc.rs::discovery_advertises_the_two_axiam_acr_urns` |
| 37 | `claims_supported` includes `auth_time`, `acr`, `amr` as server capabilities (row 25 records that no client receives them yet) | Discovery §3 | Pass | `oidc.rs::discovery_advertises_the_three_authentication_evidence_claims` |
| 38 | `id_token_signing_alg_values_supported` remains exactly `["EdDSA"]` — escalation B was answered **no**, so no RSA key enters the JWKS | Discovery §3 | Pass | `oidc.rs::the_id_token_algorithm_list_is_still_eddsa_only` + row 8 |
| 39 | Every signed token names its verifying key in the header `kid`, and that `kid` is the one the JWKS publishes | RFC 7515 §4.1.4 | Pass | `token.rs::every_signed_token_names_its_verifying_key`; `oidc.rs::the_published_kid_is_the_one_the_signer_stamps` |

---

## Notes

- **alg:none at HTTP layer:** The `/oauth2/token` handler does not accept client-supplied
  algorithm preferences (algorithm is fixed at EdDSA in `AuthConfig`). The service-layer
  rejection test (`req5_oidc_e2e.rs::oidc_rejects_alg_none`) provides authoritative
  evidence. No HTTP-layer test is needed because there is no algorithm-selection code
  path in the handler itself.

- **"Ignored (by design)" is a status, not a gap.** Rows 23–25 describe
  behaviour the plan's invariant 4 requires: a client registered before X7.1
  must not change behaviour, and every client registered today is on the
  `ignore` lane. When the honour lane lands (plan waves W2–W5), these rows gain
  an `authn_request_params: honour` column rather than flipping to Pass — the
  `ignore` behaviour stays, and stays tested, because it remains the default.

- **Not yet Basic OP.** These rows close the gates, the refusals, the session
  record and now the login hop — not the certification. The remaining Basic OP
  work — the honour lane, POST userinfo, the sensitive scopes,
  `client_secret_basic` and the harness itself — is waves W5–W9 of
  `claude_dev/basic-op-gap-plan.md` §8. **No conformance run has been executed
  against any of it:** there is no docker daemon in the environment these waves
  were implemented in, `docs/conformance/` does not exist, and baseline run #0
  has never happened, so runs #1 and #2 have nothing to be compared against
  either.

- **The login hop reaches the parameters; W4 reads them.** Rows 47–59 make
  `prompt`, `max_age` and `id_token_hint` *reachable*, because there is now a
  browser session at `/oauth2/authorize` for them to be about; rows 60–80 are
  what reading them does. Rows 23–25 still describe what happens on the
  `ignore` lane: nothing, which is every client registered today.

- **The tenant on an anonymous authorization request.** `/oauth2/authorize`
  takes an optional `tenant_id`, read **only** when the request carries no
  access token — every session, client and code in AXIAM is tenant-scoped, and
  an anonymous browser has no token to take a tenant from. It is the same
  parameter `/oauth2/end_session`, `/oauth2/token` and the tenant-scoped
  discovery document already take. It is ignored whenever a principal was
  resolved from a token, so no client registered today can observe it. The
  published `authorization_endpoint` does not yet carry it; a relying party on
  the hop must add it, and making discovery emit a tenant-scoped
  `authorization_endpoint` is a W9 question rather than a W3 one, since it
  would change the document every client already reads.

- **`prompt=consent` is treated as `login` in W4, and W7 supersedes it.** Plan
  §4.2 sends it to a first-party consent screen that G8 (wave W7) renders. That
  screen does not exist yet, and the two available answers were *ignore it* —
  the silent downgrade the whole lane exists to prevent — or refuse with
  `interaction_required`. W4 treats it as `login`. The argument: OIDC Core
  §3.1.2.1 says the server "SHOULD prompt the End-User for consent" and leaves
  the OP to choose the ceremony; a fresh credential check *is* an interaction,
  performed by the user, before any code is issued; nothing is asserted about
  it, because there is no consent claim to be false and no consent-gated data to
  release until W7 defines the sensitive scopes; and `interaction_required`
  would make the honour lane unusable for every relying party whose library
  sends `prompt=consent` by reflex, which pushes operators back to `ignore`
  where `max_age` and `prompt=none` are dropped silently too. W7 replaces the
  ceremony behind the same redirect and no relying party has to change.

- **`consent_required` and `interaction_required` are unreachable in W4.**
  `consent_required` needs a consent-gated scope and there are none until W7;
  every `prompt=none` refusal the honour lane can produce has a more specific
  name than `interaction_required`. Both variants exist in `OAuth2Error` — the
  four OIDC interaction codes are one vocabulary and splitting it across waves
  is how a code comes to be spelled twice — and neither is raised by any branch.
  The audit action `oauth2.prompt_none.consent_required` the plan names is,
  for the same reason, not written.

- **`max_age=0` cannot be satisfied by any code, and that is the honest
  answer.** The plan fixes the comparison as `elapsed >= max_age` with no
  special case and no leeway; an authentication is never zero seconds old, so
  `max_age=0` always demands a reauthentication and the reauthentication it
  produces fails the same comparison. The relying party gets an interaction and
  then `login_required`. A rounder comparison (`>`) would let it succeed, at the
  cost of the one guarantee the parameter exists to give. Note that the OpenID
  Foundation's Basic OP plan exercises `max_age=1` and `max_age=10000`, not
  `max_age=0`.

- **A pushed `prompt=none` from an anonymous browser cannot be read before the
  hop.** The handle is consumed inside the authorization handler, after the
  principal has been resolved, so a PAR client's `prompt=none` is not visible
  at the moment the login redirect would be built. It is not converted into a
  code either: the return leg carries the hop marker, and `prompt=none` on a
  marked request is `login_required` (`honour.rs::prompt_none_on_a_return_leg_is_refused_however_good_the_session_is`).
  A relying party that needs silent authentication over PAR sees
  `invalid_request_uri` or `login_required`, never a token minted behind an
  interaction it forbade.

- **A refreshed ID token reports the class the authentication achieved.** A
  refresh carries no authorization request, so there is no relying-party
  preference for row 74's rule to express. Where the original token may have
  reported the weaker of two satisfied classes because the relying party listed
  it first, the refreshed one reports what the session proves. Both are true of
  the same authentication; `auth_time` and `amr` are identical either way.

- **Cross-site hidden-iframe silent renew is not supported, and fails closed.**
  A consequence of the `SameSite=Lax` cookie in row 53, recorded in the plan's
  §9 as a decision rather than discovered as a bug. Relying parties renew with
  a top-level `prompt=none` navigation (rows 60–61) or with a refresh token.

---

*Generated: Phase 7, Plan 02 — 2026-06-07*
*Rows 23–39 added: X7.1 wave W1 — 2026-09-07*
*Rows 40–46 added: X7.2 wave W2 — 2026-09-07*
*Rows 47–59 added: X7.3 wave W3 — 2026-09-07*
*Rows 60–80 added: X7.4 wave W4 — 2026-09-07*
*Rows 81–89 added: wave W5 (cosmetic parameters + SPA i18n) — 2026-09-07*
