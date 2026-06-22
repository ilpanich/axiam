# OAuth2 RFC Compliance Matrix

**Standards:** RFC 6749 (OAuth2), RFC 7636 (PKCE), RFC 7009 (Token Revocation),
RFC 7662 (Token Introspection)

**Test locations:**
- `crates/axiam-api-rest/tests/oauth2_flow_test.rs` — baseline 37-test suite
- `crates/axiam-api-rest/tests/oauth2_conformance.rs` — MUST-gap conformance tests (Phase 7)

---

## RFC 6749 — The OAuth 2.0 Authorization Framework

| # | MUST | RFC Ref | Status | Evidence |
|---|------|---------|--------|----------|
| 1 | Authorization code grant: successful code issuance | §4.1.2 | Pass | `oauth2_flow_test.rs::full_authorization_code_flow` |
| 2 | Authorization code grant: with PKCE S256 | §4.1 / RFC 7636 | Pass | `oauth2_flow_test.rs::full_authorization_code_flow_with_pkce` |
| 3 | Authorization code MUST be single-use | §4.1.2 | Pass | `oauth2_flow_test.rs::auth_code_is_single_use` |
| 4 | redirect_uri mismatch MUST be rejected (authorize) | §3.1.2.4 | Pass | `oauth2_flow_test.rs::invalid_redirect_uri_rejected_at_authorize` |
| 5 | redirect_uri mismatch MUST be rejected (token) | §4.1.3 | Pass | `oauth2_flow_test.rs::redirect_uri_mismatch_at_token_rejected` |
| 6 | Invalid client secret MUST return 401 invalid_client | §5.2 | Pass | `oauth2_flow_test.rs::invalid_client_secret_rejected` |
| 7 | 401 invalid_client MUST include WWW-Authenticate header | §5.2 | Pass | `oauth2_conformance.rs::invalid_client_returns_www_authenticate_header` (D-04 inline fix) |
| 8 | Unsupported response_type MUST produce error redirect | §4.1.2.1 | Pass | `oauth2_flow_test.rs::unsupported_response_type_rejected` |
| 9 | state parameter MUST be echoed in redirect | §4.1.2 | Pass | `oauth2_flow_test.rs::state_parameter_echoed_in_redirect` |
| 10 | Missing code MUST return invalid_request | §4.1.3 | Pass | `oauth2_flow_test.rs::missing_code_returns_error` |
| 11 | Unsupported grant_type MUST return error | §5.2 | Pass | `oauth2_flow_test.rs::unsupported_grant_type_returns_error` |
| 12 | token_type=Bearer MUST be present in token response | §7.1 | Pass | `oauth2_conformance.rs::token_response_includes_bearer_token_type` |
| 13 | Client credentials grant: success | §4.4 | Pass | `oauth2_flow_test.rs::client_credentials_grant` |
| 14 | Client credentials: wrong secret MUST return 401 | §5.2 | Pass | `oauth2_flow_test.rs::client_credentials_wrong_secret` |
| 15 | Client credentials: unauthorized grant type rejected | §4.4 | Pass | `oauth2_flow_test.rs::client_credentials_unauthorized_grant` |
| 16 | Refresh token grant: success + rotation | §6 | Pass | `oauth2_flow_test.rs::refresh_token_grant` |
| 17 | Old refresh token MUST be invalidated after rotation | §6 | Pass | `oauth2_flow_test.rs::refresh_token_rotation_invalidates_old` |
| 18 | Refresh token MUST be bound to issuing client | §6 | Pass | `oauth2_conformance.rs::refresh_token_bound_to_original_client` |

## RFC 7636 — PKCE

| # | MUST | RFC Ref | Status | Evidence |
|---|------|---------|--------|----------|
| 19 | S256 code_challenge_method MUST be supported | §4.2 | Pass | `oauth2_flow_test.rs::full_authorization_code_flow_with_pkce` |
| 20 | plain code_challenge_method MUST be rejected (S256-only policy) | §4.2 | Pass | `oauth2_conformance.rs::pkce_plain_method_rejected` |
| 21 | code_verifier < 43 chars MUST be rejected | §4.1 | Pass | `oauth2_conformance.rs::pkce_verifier_too_short_rejected` |
| 22 | code_verifier > 128 chars MUST be rejected | §4.1 | Pass | `oauth2_conformance.rs::pkce_verifier_too_long_rejected` |
| 23 | Wrong code_verifier MUST return invalid_grant | §4.6 | Pass | `oauth2_flow_test.rs::pkce_verification_failure` |
| 24 | code_verifier MUST be required when challenge was registered | §4.6 | Pass | `oauth2_flow_test.rs::pkce_required_when_challenge_registered` |

## RFC 7009 — Token Revocation

| # | MUST | RFC Ref | Status | Evidence |
|---|------|---------|--------|----------|
| 25 | Revocation MUST invalidate the refresh token | §2 | Pass | `oauth2_flow_test.rs::revoke_refresh_token` |
| 26 | Revocation of unknown token MUST return 200 | §2.2 | Pass | `oauth2_flow_test.rs::revoke_unknown_token_returns_200` |

## RFC 7662 — Token Introspection

| # | MUST | RFC Ref | Status | Evidence |
|---|------|---------|--------|----------|
| 27 | Active token introspection MUST return active=true | §2.2 | Pass | `oauth2_flow_test.rs::introspect_active_access_token` |
| 28 | Unknown token MUST return active=false | §2.2 | Pass | `oauth2_flow_test.rs::introspect_unknown_token_returns_inactive` |
| 29 | Introspection MUST require client authentication | §2.1 | Pass | `oauth2_flow_test.rs::introspect_requires_client_auth` |
| 30 | Revoked token MUST be reported as inactive | §2.2 | Pass | `oauth2_flow_test.rs::introspect_revoked_refresh_token` |

---

## Inline Fixes Applied (D-04)

| Finding | RFC Ref | Fix | Commit |
|---------|---------|-----|--------|
| WWW-Authenticate header absent on 401 responses | RFC 6749 §5.2 | Added `WWW-Authenticate: Bearer realm="axiam"` in `build_oauth2_error_response` | Phase 7 Plan 02 |

---

*Generated: Phase 7, Plan 02 — 2026-06-07*
