# Technical Concerns & Debt

> Generated: 2026-03-30

## Critical

### No test coverage for security-critical crates

The following crates have **zero tests** despite being security-sensitive:

| Crate | Risk |
|-------|------|
| `axiam-pki` | CA management, certificate signing, mTLS, PGP — cryptographic operations with no test validation |
| `axiam-authz` | Authorization engine — RBAC decisions untested |
| `axiam-federation` | SAML/OIDC federation — authentication bypass risk if logic is wrong |

### Unverified federation token signatures

- `crates/axiam-federation/src/oidc.rs:285` — `TODO(T19.6): Implement JWKS-based JWT signature verification`
- `crates/axiam-federation/src/saml.rs:354` — `TODO(T19.7): Implement XML signature verification`

**Impact**: Federation tokens are accepted without cryptographic verification, meaning a malicious IdP response could be accepted.

### Unencrypted client secrets in database

- `crates/axiam-db/src/repository/federation_config.rs:162` — `TODO(T19.8): encrypt client_secret with AES-256-GCM before storage`
- `crates/axiam-db/src/repository/federation_config.rs:227` — Same for update path

**Impact**: OAuth2 client secrets stored in plaintext in SurrealDB.

## Important

### TODOs deferred to Phase 19

All TODOs are tracked with `T19.x` references, indicating planned Phase 19 work:

| Location | TODO |
|----------|------|
| `axiam-api-rest/src/handlers/auth.rs:364` | T15: Dedicated service-account token with `sub_kind: "ServiceAccount"` |
| `axiam-api-rest/src/handlers/auth.rs:470` | T19: Admin user listing endpoint disabled until RBAC |
| `axiam-api-rest/src/handlers/password_reset.rs:84` | T19: Wire up email sending via EmailService |
| `axiam-api-rest/src/handlers/email_verification.rs:105` | T19: Wire up email sending via EmailService |
| `axiam-api-rest/src/handlers/mfa_methods.rs:72` | T19: Allow admin users to list MFA methods for other users |
| `axiam-api-rest/src/handlers/mfa_methods.rs:116` | T19: Allow admin users to delete MFA methods for other users |
| `axiam-api-rest/src/handlers/federation.rs:377` | T19.9: Federation metadata endpoint requires auth (should be public) |
| `axiam-auth/src/password_reset.rs:190` | T19: Invalidate active sessions on password reset |
| `axiam-audit/src/notification.rs:5,68` | T19: Wire EmailService + NotificationRule delivery |

### `expect()` in server startup

`crates/axiam-server/src/main.rs` uses `.expect()` for:
- SurrealDB connection (line 76)
- Database migrations (line 81)
- RabbitMQ connection (line 88)
- AMQP queue declaration (line 91)
- WebauthnService build (line 116)
- MFA encryption key parsing (lines 59, 64)

**Acceptable for startup** — these are fatal errors where the server cannot function. However, error messages could be more descriptive.

### `unwrap()` in production code

3 instances in `crates/axiam-oauth2/src/oidc.rs` (lines 178, 194, 195):
```rust
let jwks = build_jwks(pem).unwrap();
```
These are in test helper functions inside `#[cfg(test)]` adjacent code but the `build_jwks` call on line 178 appears to be in production JWKS endpoint logic. Should use `?` propagation.

### `expect()` in webhook handler

`crates/axiam-api-rest/src/webhook.rs:27`:
```rust
.expect("failed to build reqwest client");
```
Reqwest client construction failure during webhook delivery would panic the handler. Should return an error instead.

## Minor

### No shared test utilities

Integration tests duplicate database setup, auth config creation, and entity factory code across 20+ test files. A `test-utils` crate or shared helper module would reduce ~500 lines of boilerplate.

### No database-level repository tests

`axiam-db` has only 2 tests (schema migrations). All repository testing happens indirectly through REST API integration tests. Direct repository tests would catch data-layer bugs earlier.

### Missing error context in some repositories

Some repository error paths use generic string conversion (`.to_string()`) losing structured error information from SurrealDB.

### No `unsafe` blocks

No `unsafe` code found in the codebase — good.

### Dependency considerations

- `pgp` crate uses `rand 0.8` / `rand_core 0.6` while workspace may use `rand 0.9` — version split requires careful handling
- `surrealdb 3.x` SDK is relatively new; API may change
- `rcgen 0.13` had breaking API changes from 0.12 (already handled)

## Summary

| Severity | Count | Key Theme |
|----------|-------|-----------|
| Critical | 3 | Unverified federation tokens, unencrypted secrets, no PKI tests |
| Important | 11 | Phase 19 TODOs, startup panics, production unwraps |
| Minor | 5 | Test infrastructure, error context, dependency versions |

Most concerns are tracked under Phase 19 (`T19.x`), indicating awareness. The critical items around federation token verification and secret encryption should be prioritized.
