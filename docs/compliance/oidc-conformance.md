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
- `crates/axiam-api-rest/tests/oauth2_userinfo_post_test.rs` — `POST /oauth2/userinfo`
  and the RFC 6750 carriers (W6, T10.*)
- `crates/axiam-api-rest/tests/oauth2_sensitive_scopes_test.rs` — the `address` and
  `phone` scopes end to end (W7, T8.*, M8, M10)
- `crates/axiam-db/tests/w7_sensitive_columns_test.rs` — the storage, erasure and
  projection of the two columns (W7)
- `crates/axiam-oauth2/src/sensitive.rs` — the four gates, and which party closes each

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

## OpenID Connect Core 1.0 — UserInfo Endpoint (`GET`)

These four rows are the invariant-4 twin of wave W6: `POST` was added beside
`GET`, and a `GET` UserInfo request is byte-for-byte the request it was before.
None of them moved, and none of them may.

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

## OpenID Connect Core 1.0 — the UserInfo endpoint on `POST` (wave W6)

OIDC Core §5.3 requires an OP to accept both methods, and the two conformance
modules `OIDCCUserInfoPostHeader` and `OIDCCUserInfoPostBody` fail without it.
RFC 6750 gives `POST` a second carrier for the access token — an `access_token`
form field (§2.2) beside the `Authorization` header (§2.1) — and forbids using
more than one carrier in one request (§2).

This is the **resource-server** side of a token, so unlike every other wave in
this series it is not per client: there is no lane switch here, and invariants
1, 2 and 3 (opt-in per client, refused on `fapi2`, stricter default) are `n/a`
by design rather than by omission. Invariant 4 is the live one, and rows 17–20
above are its twin. Invariant 5 holds because the code the two methods share
was split, not changed: `parse_validated_claims` keeps reading the cookie and
then the header in that order, and `enforce_sender_constraint` is reached by
both carriers.

| # | Behaviour | Spec Ref | Status | Evidence |
|---|-----------|----------|--------|----------|
| 90 | `POST /oauth2/userinfo` is routed and answers a valid request — the endpoint supports both methods | Core §5.3 (`OIDCCUserInfoPostHeader`) | Pass (T10.1) | `oauth2_userinfo_post_test.rs::t10_1_post_with_a_header_token_answers_exactly_what_get_answers` |
| 91 | The `POST` answer is **byte-identical** to the `GET` answer for the same token — status, every header, and the body. Nothing about a UserInfo response depends on the method | Core §5.3 | Pass (T10.1, invariant 4) | same test (`Answer` equality) |
| 92 | The access token is accepted in an `access_token` **form field**, and answers the same body as the header carrier | RFC 6750 §2.2 (`OIDCCUserInfoPostBody`) | Pass (T10.2) | `oauth2_userinfo_post_test.rs::t10_2_post_with_a_form_field_token_answers_the_same_body` |
| 93 | A request presenting the token by **two** methods is refused `400 invalid_request`, and the refusal echoes neither token | RFC 6750 §2 | Pass (T10.3) | `oauth2_userinfo_post_test.rs::t10_3_two_carriers_is_refused_and_the_refusal_names_neither_token` |
| 94 | The `axiam_access` cookie presented together with a form field is refused too — not an RFC 6750 method, but a second credential naming a possibly different subject | RFC 6750 §2 (extended) | Pass | `oauth2_userinfo_post_test.rs::a_cookie_and_a_form_field_together_are_refused_too` |
| 95 | An **empty** `access_token` field transmits no token and is therefore not a second carrier: an empty field beside a real header is answered, not refused | RFC 6750 §2.2 | Pass | `oauth2_userinfo_post_test.rs::an_empty_form_field_is_not_a_second_carrier` |
| 96 | `?access_token=…` authenticates **neither** method. The deprecated §2.3 form is never read rather than refused — refusing it would mean reading a credential out of a URL first | RFC 6750 §2.3 | Pass | `oauth2_userinfo_post_test.rs::a_query_string_access_token_authenticates_neither_method` |
| 97 | A body-carried access token reaches no log line, on the success path or the failure path, at `TRACE` level — and no error body echoes it | OWASP ASVS 5.0 V7 / plan §4.9 hazard 1 | Pass | `oauth2_userinfo_post_test.rs::the_body_carried_credential_never_reaches_a_log` |
| 98 | The form type's `Debug` redacts the token, so the most natural diagnostic line anyone would write cannot disclose it | plan §4.9 hazard 1 | Pass | `oauth2_userinfo_post_test.rs::the_form_type_redacts_its_token_when_printed` |
| 99 | `/oauth2` carries no CSRF middleware and `parse_validated_claims` prefers the cookie, so a cookie-authenticated cross-site `POST` would disclose PII — it fails closed because `axiam_access` is `SameSite=Strict; HttpOnly`, pinned here rather than asserted in a comment. A **same-site** cookie `POST` does authenticate, which is what makes the attribute load-bearing | plan §4.9 hazard 2; SEC-046 | Pass | `oauth2_userinfo_post_test.rs::the_access_cookie_is_strict_so_a_cross_site_post_cannot_be_authenticated_by_it` |
| 100 | A DPoP-bound token verifies on `POST` — on both carriers — and the **same proof minted for `GET` does not**. No method-specific branch was added: `verified_dpop_thumbprint` builds `htm` from `req.method()` and `htu` from the configured issuer plus `req.path()` (SEC-102) | RFC 9449 §7.1 | Pass | `oauth2_userinfo_post_test.rs::a_dpop_bound_token_verifies_on_post_and_only_with_a_post_proof` |
| 101 | A certificate-bound token — the `fapi2` shape — presented on `POST` with no client certificate is refused, not read as unbound, and refused identically to the way `GET` refuses it. The positive direction needs a real TLS handshake: `TestRequest` cannot populate `conn_data`, so it is **not** asserted here | RFC 8705 §3.2 | Partial (negative direction only; see note) | `oauth2_userinfo_post_test.rs::an_mtls_bound_token_is_not_downgraded_to_a_bearer_token_on_post` |
| 102 | An unauthenticated `POST` is the same 401 as an unauthenticated `GET`, byte for byte — the new method added no way in and no different refusal | Core §5.3; invariant 4 | Pass | `oauth2_userinfo_post_test.rs::an_unauthenticated_post_is_the_same_401_as_an_unauthenticated_get` |
| 103 | The `DPoP` authorization scheme is still accepted on `POST`; the shared scheme parsing was not narrowed back to `Bearer` | RFC 9449 §7.1 | Pass | `oauth2_userinfo_post_test.rs::the_dpop_authorization_scheme_is_still_accepted_on_post` |

**Row 101, stated rather than implied.** `enforce_sender_constraint` reads the
verified client certificate from `HttpRequest::conn_data`, and actix-web's
`TestRequest` constructs every request with `conn_data: None` and exposes no
way to set it. A test asserting that a certificate-bound token *succeeds* on
`POST` would need a TLS listener and a real handshake — an integration harness
this repository does not have, for `GET` either. What is asserted instead is
the direction a mistake would show up in: a `POST` arm that skipped the check
would answer `200` to a bound token presented with no certificate, and it
answers `401`. The structural argument behind it is that both methods reach
`enforce_sender_constraint` through the same `validate_presented_token`, whose
only method-dependent input is the `req.method()` that row 100 exercises.

**`POST /oauth2/authorize` (G11) is not implemented, deliberately.**
`OIDCCEnsurePostRequestSucceeds` warns; it does not fail. RFC 6749 §3.1 makes
`POST` optional at the authorization endpoint. The reasoning, and the condition
that would reopen it, are in `claude_dev/basic-op-gap-plan.md` §4.9.

## OpenID Connect Core 1.0 — the `address` and `phone` scopes (wave W7)

OIDC Core §5.4 defines two scopes that release categories of personal data
AXIAM has no other use for: a postal address and a telephone number. Nothing in
this system authenticates against them, sends to them, or looks anything up by
them. They exist to be released to a relying party the end user has agreed to,
and everything below is the machinery that decides whether that has happened.

**Four gates, each closed by a different party**, and every one of them is asked
again at the moment of release rather than once at authorization:

1. the **organization** enabled `sensitive_scopes_enabled` (off by default);
2. the **operator** registered the scope on the client;
3. the **end user** consented, per client and per scope set, and has not
   withdrawn;
4. the client is **not** on the `fapi2` profile.

The five invariants this series carries hold as follows. **I1** — opt-in per
client — is the registered scope set, which `authorize.rs` step 5 has always
enforced. **I2** — refused on `fapi2` at both layers — is rows 112–114. **I3** —
stricter default — is the switch, off in `system_defaults()`, in the migration's
`DEFAULT false`, and in the settings row decoder's fallback. **I4** — nothing
existing changes — is row 104, and it is structural rather than careful: the two
scopes were unregistrable before this wave, so no client in any existing
deployment carries them. **I5** — shared code only tightens — is additive
columns, additive optional claims, an additive SCIM mapping and an additive
discovery field.

| # | Behaviour | Spec Ref | Status | Evidence |
|---|-----------|----------|--------|----------|
| 104 | No client registered before this wave can reach any of it: `address` and `phone` were unregistrable, so no authorization request could name them and pass the registered-scope check. Asserted in both halves — registration refused while the capability is off, and an unregistered scope answered `invalid_scope` exactly as before | plan invariant 4 | Pass (I4) | `oauth2_sensitive_scopes_test.rs::i4_the_scopes_are_unregistrable_and_unrequestable_with_the_switch_off` |
| 105 | The tenant capability refuses the scopes at **registration** and again at the **authorization endpoint**, so a client registered while the capability was on is refused once it is turned off | plan §4.8 | Pass (T8.1) | `oauth2_sensitive_scopes_test.rs::t8_1_the_switch_refuses_registration_and_then_refuses_the_request` |
| 106 | A tenant may switch the capability off for itself; the reverse — enabling what its organization forbade — is refused by the settings model, because releasing personal data is the less-restrictive direction | GDPR Art. 5(1)(c) | Pass | `oauth2_sensitive_scopes_test.rs::a_tenant_may_switch_the_capability_off_for_itself`; `settings.rs::a_tenant_may_not_enable_sensitive_scopes_its_org_disabled`, `::clamping_drops_a_tenant_optin_the_org_has_since_withdrawn` |
| 107 | A first authorization for a client and scope set sends the browser to a **consent screen** — `/consent`, not the sign-in page, and carrying no `reauth`: the end user is signed in, and re-entering a password answers no question about consent | Core §3.1.2.1 | Pass (T8.2) | `oauth2_sensitive_scopes_test.rs::t8_2_a_first_authorization_asks_and_prompt_none_is_refused`; `ConsentPage.test.tsx` |
| 108 | `prompt=none` on such a request is refused `consent_required` | Core §3.1.2.6 | Pass (T8.2) | same test |
| 109 | The consent hop is bounded at one redirect: a request that comes back still unconsented is answered `access_denied` to the relying party, with its `state`, rather than redirected again | Core §3.1.2.6; plan §4.0 | Pass | `oauth2_sensitive_scopes_test.rs::a_return_leg_without_consent_is_access_denied_rather_than_a_second_redirect` |
| 110 | Consent is per relying party and per scope set: another client asks for itself, and a client that later widens its request re-prompts rather than inheriting | GDPR Art. 4(11) ("specific") | Pass | `oauth2_sensitive_scopes_test.rs::consent_does_not_carry_from_one_relying_party_to_another`, `::widening_the_scope_set_asks_again` |
| 111 | With consent recorded, UserInfo returns `phone_number`, `phone_number_verified` and `address`, and the **ID token carries none of them** — asserted by running the whole code flow and decoding what the relying party received | Core §5.4 (`OIDCCScopeAddress`, `OIDCCScopePhone`) | Pass (T8.3) | `oauth2_sensitive_scopes_test.rs::t8_3_userinfo_releases_the_claims_and_the_id_token_does_not` |
| 112 | A `fapi2` client may not **register** either scope, on create or on the merged update path, whatever the tenant capability says | FAPI 2.0 §5.3.1 | Pass (T8.5, M8 layer 1) | `oauth2_sensitive_scopes_test.rs::t8_5_a_fapi2_client_may_not_register_a_sensitive_scope`; `fapi.rs::m8_fapi_plus_sensitive_scopes_is_refused_at_creation`, `::m8_fapi_plus_sensitive_scopes_is_refused_on_update` |
| 113 | A `fapi2` **request** naming either scope is refused `invalid_scope` whatever the row says — including a row edited in the database past the registration gate, and including an honest row, so the two are indistinguishable to the relying party | FAPI 2.0 §5.3.1; plan §7 M8 | Pass (T8.5, M8 layer 2) | `fapi.rs::t8_5_a_fapi2_request_asking_for_a_sensitive_scope_is_refused_however_the_row_was_edited`, `::an_honest_fapi2_row_asking_for_a_sensitive_scope_is_refused_at_the_same_gate` |
| 114 | A `fapi2`-issued access token releases neither claim at UserInfo, regardless of scope, capability or consent record — the third and last place the profile is asked, and the only one where no authorization request is in hand | plan §7 M10 | Pass (M10) | `oauth2_sensitive_scopes_test.rs::m10_a_fapi2_issued_token_releases_nothing_at_userinfo` |
| 115 | Withdrawal takes effect on the **next UserInfo call with the same access token** — not on the next token. The release gate re-reads the record on every call, so a fifteen-minute token and a thirty-day refresh do not outlive the consent behind them | GDPR Art. 7(3) | Pass (T8.4) | `oauth2_sensitive_scopes_test.rs::t8_4_withdrawal_takes_effect_on_the_next_call_with_the_same_token`, `::withdrawal_removes_every_scope_set_for_that_client` |
| 116 | Turning the capability off likewise stops release for tokens already in relying parties' hands | GDPR Art. 5(1)(c) | Pass | `oauth2_sensitive_scopes_test.rs::turning_the_switch_off_stops_release_for_tokens_already_issued` |
| 117 | An access token that names **no** relying party releases nothing. That is every token issued before this wave, and every token minted by a login, a device flow or an exchange: there is no consent record such a token could be matched against, and "any consent this subject ever gave" would hand an address to a client the subject consented to a *different* client receiving | RFC 9068 §2.2; GDPR Art. 4(11) | Pass | `oauth2_sensitive_scopes_test.rs::a_token_naming_no_client_releases_nothing`; `token.rs::a_pre_w7_token_decodes_with_no_client_id` |
| 118 | A release is audited as `userinfo.sensitive_claims_released` carrying the relying party and the claim **names**; neither value appears anywhere in the row. A call that releases nothing writes no row | GDPR Art. 5(1)(c); OWASP ASVS 5.0 V7 | Pass (T8.6) | `oauth2_sensitive_scopes_test.rs::t8_6_the_release_is_audited_by_claim_name_and_never_by_value`, `::a_call_that_releases_nothing_writes_no_release_row` |
| 119 | Consent cannot be recorded for a scope the client has not registered, for a scope outside the two, or while the capability is off — so a record cannot exist for a release that could never have been authorised | GDPR Art. 4(11) | Pass | `oauth2_sensitive_scopes_test.rs::consent_cannot_be_recorded_for_a_scope_the_client_never_registered`, `::consent_cannot_be_recorded_while_the_capability_is_off` |
| 120 | Withdrawal cannot reach the registration `terms_of_service` consent: the namespace guard is in the repository, so no caller can be the one that gets it wrong, and the invariant registration depends on (threat T-5-consent-gap) is untouched | GDPR Art. 7(1) | Pass | `oauth2_sensitive_scopes_test.rs::withdrawal_cannot_reach_the_registration_consent` |
| 121 | Erasure removes both values. Both erasure statements and the Art. 15 export write **explicit column lists**, so a new column is not covered by them — the plan's §4.8 said otherwise. Asserted by erasing a subject who has both and reading the row back, on the Art. 17 pipeline and on the administrator's tombstone | GDPR Art. 17; Art. 15 | Pass | `axiam-db/tests/w7_sensitive_columns_test.rs::anonymisation_erases_the_telephone_number_and_the_postal_address`, `::the_admin_delete_tombstone_erases_them_too` |
| 122 | Neither value reaches a log line through the most natural diagnostic anybody writes: `User`, `UserRow`, `UserRowWithId`, `UserInfoResponse` and the two SCIM output types all redact them in `Debug` while still showing presence | OWASP ASVS 5.0 V7 | Pass | `user.rs::debug_redacts_the_sensitive_columns_but_still_shows_presence`, `::debug_distinguishes_absent_from_redacted`; `w7_sensitive_columns_test.rs::the_listed_user_still_redacts_both_values_when_printed` |
| 123 | The `address` column admits exactly the six OIDC §5.1.1 members and is **not** `FLEXIBLE`, so "the `address` scope releases a postal address and nothing else" is a property of the schema rather than of everybody's care | Core §5.1.1 | Pass | `schema.rs::the_address_column_admits_exactly_the_oidc_members` |
| 124 | SCIM `phoneNumbers` and `addresses` map onto the same columns on create, replace and patch, and are returned on both the resource read and the list. Both are removable through SCIM, unlike `emails` | RFC 7643 §4.1.2 | Pass | `axiam-scim/src/users.rs`, `patch.rs`; `w7_sensitive_columns_test.rs::the_list_projection_carries_the_sensitive_columns_but_still_no_credential` |
| 125 | Discovery advertises the two scopes and the three claims **only for a tenant that has the capability**. `GET /.well-known/openid-configuration` is not tenant-scoped — plan §6 assumed it was — so it gains an optional `tenant_id`, and a caller that omits it receives the document W6 served, byte for byte. An unknown tenant is answered identically rather than `404`, so discovery is not a tenant-enumeration oracle | Discovery §3; plan §6 | Pass | `oauth2_sensitive_scopes_test.rs::discovery_advertises_the_scopes_only_for_a_tenant_that_has_them` |
| 126 | The GDPR self-service consent list marks the scope releases withdrawable and the registration consent not — withdrawing that one is an erasure, with its own endpoint and its own grace period. Plan §4.8 refers to this list as existing; it did not, and neither did any consent endpoint | GDPR Art. 7(1), Art. 15(1)(a) | Pass | `oauth2_sensitive_scopes_test.rs::the_consent_list_marks_only_the_scope_releases_withdrawable` |
| 127 | `phone_number_verified` is emitted **only alongside** `phone_number`, and is `false` rather than omitted when the number is unverified. AXIAM ships no telephone verification ceremony, so the honest default for a verification that never happened is "no" | Core §5.1 | Pass | `oauth2_sensitive_scopes_test.rs::t8_3_userinfo_releases_the_claims_and_the_id_token_does_not` |
| 128 | A request needing **both** ceremonies gets both, in order: `prompt=consent` with `address` goes to the sign-in page, and the leg that returns still reaches the consent screen rather than being read as a decline. The consent hop carries its own marker (`axiam_consent_hop`) for exactly this reason — the login marker means "has been through a first-party page", which is not the same statement as "was asked about consent and did not give it" | Core §3.1.2.1; plan §4.0 | Pass | `oauth2_sensitive_scopes_test.rs::a_login_hop_marker_is_not_mistaken_for_a_consent_one` |
| 129 | A subject with no address or no telephone number simply has the claim omitted, not nulled or emitted hollow. The suite treats a missing scope claim as a WARNING (`AbstractOIDCCReturnedClaimsServerTest`), not a failure | Core §5.3.2 | Pass | `user.rs::address_omits_absent_members`, `::an_address_with_no_members_is_empty`; `w7_sensitive_columns_test.rs::an_empty_address_is_stored_as_no_address` |

**Not asserted here, and stated rather than implied.**

- **No conformance run.** Baseline run #0 has still never happened —
  `docs/conformance/` does not exist — so nothing in this series has anything to
  compare against, and no row above claims the suite passed. Each says what the
  code does and names the test that shows it. The two module names in rows 111
  and 112 are the modules these behaviours *would* be exercised by, not modules
  that have been run.
- **The consent ceremony is a first-party page, not a protocol artefact.**
  Nothing in OIDC says what a consent screen must contain. Rows 107 and 110
  assert the ceremony AXIAM chose; Art. 4(11) is the standard they are measured
  against, not Core §3.1.2.1.
- **No telephone verification exists.** `phone_number_verified` is written by an
  administrator asserting an out-of-band check and by nothing else, which is why
  row 127 is about the claim's honesty rather than about a ceremony.

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
  record, the login hop, the honour lane, `POST /oauth2/userinfo` and now the
  sensitive scopes — not the certification. The remaining Basic OP work —
  `client_secret_basic` and the harness itself — is waves W8 and W9 of
  `claude_dev/basic-op-gap-plan.md` §8. **No conformance run has been executed
  against any of it:** `docs/conformance/` does not exist and baseline run #0
  has never happened, so runs #1 and #2 have nothing to be compared against
  either. Nothing in this file claims the suite passed; each row says what the
  code does and names the test that shows it.

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
  where `max_age` and `prompt=none` are dropped silently too.

  **W7 did not supersede it, and this is the correction rather than the
  omission.** W7 builds the consent screen, but the screen asks about a *scope
  release*, and `prompt=consent` on its own requests no consent-gated scope —
  so pointing it there would show a page that says "there is nothing to decide
  here". W4's treatment therefore stands for `prompt=consent` alone. What W7
  changes is the case where both apply: `prompt=consent` **with** `address` or
  `phone` gets the sign-in page and then the consent screen, in that order, and
  row 129 asserts the second is not skipped.

- **`consent_required` was unreachable in W4 and is reachable from W7.**
  It needs a consent-gated scope, and there were none until W7 defined the two;
  row 108 is where it is now raised. `interaction_required` remains unreachable.
  As W4 put it:
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
*Rows 90–103 added: wave W6 (`POST /oauth2/userinfo`) — 2026-09-07*
*Rows 104–129 added: wave W7 (`address` and `phone` sensitive scopes) — 2026-09-08*
