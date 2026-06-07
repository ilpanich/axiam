# OIDC Core 1.0 Conformance Matrix

**Standard:** OpenID Connect Core 1.0, OpenID Connect Discovery 1.0

**Test locations:**
- `crates/axiam-api-rest/tests/oauth2_flow_test.rs` — OIDC happy-path tests
- `crates/axiam-api-rest/tests/oidc_conformance.rs` — MUST-gap conformance tests (Phase 7)
- `crates/axiam-server/tests/req5_oidc_e2e.rs` — service-layer alg:none rejection

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

## Notes

- **alg:none at HTTP layer:** The `/oauth2/token` handler does not accept client-supplied
  algorithm preferences (algorithm is fixed at EdDSA in `AuthConfig`). The service-layer
  rejection test (`req5_oidc_e2e.rs::oidc_rejects_alg_none`) provides authoritative
  evidence. No HTTP-layer test is needed because there is no algorithm-selection code
  path in the handler itself.

---

*Generated: Phase 7, Plan 02 — 2026-06-07*
