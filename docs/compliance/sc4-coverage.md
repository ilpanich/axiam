# SC#4 Test Coverage Citation Table

**Purpose:** Documents that REQ-11 (Testing Gaps — close critical testing gaps in
security-sensitive crates) is satisfied for each already-tested crate area.

**REQ-11 Acceptance Criteria (from .planning/PROJECT.md):** All security-sensitive crates
must have integration tests covering their critical paths. SC#4 = the specific sub-criterion
that crates with existing test suites are explicitly cited as evidence.

**SC#4 Cross-reference scope:** axiam-authz (authorization engine), axiam-federation (OIDC +
SAML flows), RBAC middleware enforcement, cookie-based auth, and GDPR data lifecycle.

---

## SC#4 Already-Tested Crates Citation Table

| Area | REQ-11 AC | Test File | Test Functions | SC#4 Cross-ref |
|------|-----------|-----------|----------------|----------------|
| axiam-authz: RBAC engine | AC: "gRPC authz integration tests (T19.1)" — authorization engine that gRPC and REST layers depend on | `crates/axiam-authz/tests/authz_engine_test.rs` | `direct_role_grants_access`, `default_deny_no_role`, `default_deny_wrong_action`, `group_membership_inherits_roles`, `global_role_applies_to_any_resource`, `resource_scoped_role_denied_on_unrelated_resource`, `hierarchy_inheritance`, `hierarchy_does_not_go_up`, `scope_validation`, `scoped_permission_grants_matching_scope`, `scoped_permission_denies_wrong_scope`, `wildcard_permission_grants_any_scope`, `multiple_scopes_in_grant`, `tenant_isolation` (14 tests) | SC#4: ASVS V4.1.1 default-deny; V4.1.3 tenant isolation. Covers the authorization engine used by both `AuthzMiddleware` (REST) and `AuthorizationServiceImpl` (gRPC). |
| axiam-federation: OIDC SSO | AC: "Federation OIDC flow integration tests" | `crates/axiam-server/tests/req5_oidc_e2e.rs` | `oidc_rejects_alg_none` (line 179), `oidc_rejects_invalid_signature`, `oidc_rejects_wrong_iss`, `oidc_rejects_wrong_aud`, `oidc_rejects_expired_token`, `oidc_rejects_disallowed_alg`, `oidc_rejects_unknown_kid_after_refetch`, `oidc_jwks_ttl_no_refetch_within_1h`, `oidc_rejects_wrong_nonce`, `oidc_rejects_wrong_nonce_in_claims`, `oidc_happy_path`, `oidc_jwks_served_stale_on_idp_outage` (12 tests) | SC#4: ASVS V2.9.1 cert-based federation auth; ASVS V3.6.1 federated session creation. Covers `alg:none` rejection (OIDC Core §3.1.3.7), token signature validation, JWKS caching. |
| axiam-federation: SAML SSO | AC: "Federation SAML flow integration tests" | `crates/axiam-server/tests/req5_saml_e2e.rs` | `saml_rejects_missing_signing_cert`, `saml_rejects_tampered_response`, `saml_rejects_expired_not_on_or_after`, `saml_rejects_replayed_assertion`, `saml_clock_skew_documents_current_behaviour`, `saml_happy_path` (6 tests) | SC#4: ASVS V2.9.2 cryptographic challenge verification; replay attack prevention. Covers SAML assertion signature validation, replay detection, clock skew tolerance. Feature-gated: full SAML suite runs with `--features saml`; 3 baseline `--no-default-features` failures are pre-existing (saml_acs, saml_authn, saml_metadata — not regressions). |
| RBAC middleware enforcement | AC: "RBAC enforcement integration tests" | `crates/axiam-api-rest/tests/rbac_test.rs` | `unauthenticated_returns_401` (line 306), `no_permission_returns_403` (line 324), `admin_can_access` (line 358), `self_service_owner_allowed` (line 389), `self_service_nonowner_denied` (line 414), `public_routes_no_auth_required` (line 449), `all_routes_have_permission` (line 493) (7 tests) | SC#4: ASVS V4.1.1 default-deny; V4.1.2 server-side enforcement; V4.3.1 admin-only UI. `all_routes_have_permission` asserts ROUTE_PERMISSION_MAP ↔ PERMISSION_REGISTRY parity — every registered route has a named permission. |
| Cookie-based auth | AC: "Cookie auth flow integration tests" | `crates/axiam-api-rest/tests/auth_test.rs` | `login_sets_httponly_access_cookie` (line 223), `login_sets_pathscoped_refresh_cookie` (line 300), `login_sets_csrf_cookie` (line 347), `csrf_missing_header_returns_403` (line 393), `csrf_valid_header_allows_request` (line 433), `csrf_get_request_passes_without_token` (line 480), `logout_clears_cookies` (line 521), `refresh_uses_cookie_returns_new_access_cookie` (line 590), `me_returns_user_info` (line 672), `me_returns_401_without_cookie` (line 724), `login_with_invalid_password_returns_401` (line 748), `login_with_nonexistent_user_returns_401` (line 769), `refresh_with_invalid_token_returns_401` (line 790), MFA tests (×3 starting line 865) | SC#4: ASVS V3.4.1 SameSite; V3.4.2 HttpOnly; V3.4.3 Secure; V3.4.4 Path; V3.3.1 logout; V3.2.2 session entropy. Phase 1 cookie auth. |
| GDPR data lifecycle | AC: included in REQ-11 as data-protection critical path | `crates/axiam-api-rest/tests/gdpr_test.rs` | `export_completeness` (line 53), `deletion_pseudonymization` (line 317), `consent_on_registration` (line 500), `deletion_cancel` (line 551) (4 tests) | SC#4: ASVS V8.3.1 GDPR export (Art. 15); V8.3.2 deletion/pseudonymization (Art. 17); V8.3.3 consent; append-only audit integrity preserved during deletion. |

---

## Phase 7 New Test Evidence (Plans 01–04)

These tests close gaps that were NOT previously in any crate. Also cited in `asvs-l2-checklist.md`.

| Crate | Test File | Scope | ASVS Controls |
|-------|-----------|-------|---------------|
| axiam-pki | `crates/axiam-pki/tests/ca_test.rs` | CA gen, validity bounds | V6.6.1, V6.6.2 |
| axiam-pki | `crates/axiam-pki/tests/cert_test.rs` | Leaf cert, revoked/expired CA rejection | V6.6.2, V2.9.1 |
| axiam-pki | `crates/axiam-pki/tests/mtls_test.rs` | mTLS device auth + reject cases | V2.9.1, V2.9.2 |
| axiam-pki | `crates/axiam-pki/tests/pgp_test.rs` | PGP audit-sign roundtrip, key-purpose guard | V6.4.1, V6.5.1 |
| axiam-api-rest | `crates/axiam-api-rest/tests/oauth2_conformance.rs` | RFC 6749/7636 MUST gaps (6 tests) | V2.7 (OAuth2 flow), V3.2 |
| axiam-api-rest | `crates/axiam-api-rest/tests/oidc_conformance.rs` | OIDC Core 1.0 MUST gaps (3 tests) | V2.9 (federation alg pinning) |
| axiam-api-grpc | `crates/axiam-api-grpc/tests/grpc_authz_test.rs` | gRPC authz allow/deny/invalid-arg + concurrent batch (7 tests) — **run with `cargo test -p axiam-api-grpc --features client`** | V4.1.1, V4.1.2, T19.1, T19.2 |
| frontend/e2e | `frontend/e2e/*.spec.ts` (11 specs) | Playwright cookie-auth UI flows (login, RBAC, federation) — run via CI e2e job against live backend | V3.5.1 (no sessionStorage), V3.4 (cookie auth in browser) |

---

## REQ-11 Acceptance Criteria Status

| AC Item | Status | Primary Evidence |
|---------|--------|------------------|
| gRPC authz integration tests (T19.1) | SATISFIED (Phase 7 Plan 03) | `crates/axiam-api-grpc/tests/grpc_authz_test.rs` — 5 T19.1 + 2 T19.2 tests |
| Concurrent batch authz tests (T19.2) | SATISFIED (Phase 7 Plan 03) | `grpc_authz_test.rs::batch_check_access_returns_mixed_results` + `concurrent_check_access_all_resolve_correctly` |
| PKI/certificate generation tests | SATISFIED (Phase 7 Plan 01) | 13 tests across ca_test.rs, cert_test.rs, mtls_test.rs, pgp_test.rs |
| Federation OIDC flow integration tests | SATISFIED (pre-existing) | `crates/axiam-server/tests/req5_oidc_e2e.rs` (12 tests) |
| Federation SAML flow integration tests | SATISFIED (pre-existing) | `crates/axiam-server/tests/req5_saml_e2e.rs` (6 tests) |
| RBAC enforcement integration tests | SATISFIED (pre-existing) | `crates/axiam-api-rest/tests/rbac_test.rs` (7 tests) + `middleware_test.rs` |
| Cookie auth flow integration tests | SATISFIED (pre-existing) | `crates/axiam-api-rest/tests/auth_test.rs` (16 tests) |
| GDPR export/deletion integration tests | SATISFIED (pre-existing) | `crates/axiam-api-rest/tests/gdpr_test.rs` (4 tests) |
| Frontend E2E tests for login, RBAC, federation | SATISFIED (Phase 7 Plan 04) | 11 Playwright specs rewritten to cookie-auth + live backend; CI e2e job |

**REQ-11 status: COMPLETE (all AC items satisfied)**

---

*Generated: Phase 7, Plan 05 — 2026-06-07*
