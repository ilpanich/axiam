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
| 24 | `login_hint`, `display`, `ui_locales`, `claims_locales` are accepted and ignored | Core §3.1.2.1, §5.2 | Ignored (by design) | same as row 23 |
| 25 | `auth_time`, `acr` and `amr` are **not** emitted merely because a request asked for them | Core §2, §3.1.3.7 | Not emitted (W2/W4) | `oauth2_flow_test.rs::p1_…` asserts their absence |
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
| 41 | No client is on the emitting lane — not `standard`, not `fapi2`, and not one registered `authn_request_params: honour` | Core §2 | Emitted for nobody (W4 opens the lane) | `fapi.rs::session_evidence_is_emitted_for_nobody` |
| 42 | Refresh rotation **copies** `authenticated_at` and `amr` to the session it creates rather than restamping them, so a session that is never re-authenticated never reports itself as younger | Core §12.2 | Pass | `session_evidence_rotation_test.rs::refresh_rotation_preserves_the_authentication_event` |
| 43 | The authorization code snapshots the session's evidence at issuance, with the session's instant and not the code's | Core §3.1.3.3 | Pass | `oauth2_flow_test.rs::t2_6_…` (asserts `auth_time` equals the session's, three hours old) |
| 44 | A federated login is dated by the **upstream** provider — OIDC `auth_time`, SAML `AuthnInstant`, carried across the SSO handoff hop — and only falls back to AXIAM's clock when the provider asserted no instant | Core §2 | Pass | `session.rs::upstream_evidence_prefers_the_upstream_instant`; `handlers/federation.rs::issue_sso_session` |
| 45 | `amr` records what was actually verified: `pwd` alone for a password login, `pwd otp mfa` for TOTP, `pwd hwk mfa` for a security key behind a password, `hwk user` for a usernameless passkey (whose ceremony requires user verification), `fed` for a federated sign-in | RFC 8176 §2 | Pass | `session_evidence_rotation_test.rs` (password); the five call sites in `service.rs`, `webauthn.rs`, `federation.rs` |
| 46 | A session row written before schema v55 reads back with `authenticated_at = created_at` and an empty `amr` — the strict direction in both cases, since neither can make a session look fresher or stronger than it is | — | Pass | `repository/session.rs::decode_evidence` + its tests; `schema.rs::schema_v55_adds_only_optional_columns_and_backfills_nothing` |

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

- **Not yet Basic OP.** These rows close the gates and the refusals, not the
  certification. The remaining Basic OP work — the browser login hop, session
  authentication evidence, the honour lane, POST userinfo, the sensitive
  scopes, `client_secret_basic` and the harness itself — is waves W2–W9 of
  `claude_dev/basic-op-gap-plan.md` §8.

---

*Generated: Phase 7, Plan 02 — 2026-06-07*
*Rows 23–39 added: X7.1 wave W1 — 2026-09-07*
