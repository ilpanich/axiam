# Testing Analysis

> Generated: 2026-03-30

## Overview

| Metric | Value |
|--------|-------|
| Total test functions | ~139 |
| Files with `#[cfg(test)]` | 16 |
| Integration test files | 31 |
| Test crates | primarily axiam-auth, axiam-core, axiam-email, axiam-api-rest |

## Test Organization

### Unit Tests (inline `mod tests`)

Unit tests live inside source files under `#[cfg(test)]` modules:

| Crate | Files with Tests | Approx Test Count |
|-------|-----------------|-------------------|
| axiam-email | `template.rs`, `lib.rs` | 29 |
| axiam-core | `email.rs`, `settings.rs`, `notification_rule.rs`, `email_template.rs` | 56 |
| axiam-auth | `policy.rs`, `token.rs`, `totp.rs`, `password.rs`, `password_reset.rs`, `verification.rs` | 41 |
| axiam-oauth2 | `pkce.rs`, `oidc.rs` | 9 |
| axiam-db | `schema.rs` | 2 |
| axiam-api-rest | `webhook.rs` | 2 |

### Integration Tests (`tests/` directory)

All integration tests are in `crates/axiam-api-rest/tests/`:

```
auth_test.rs            - Authentication endpoints (login, register, MFA)
audit_test.rs           - Audit logging endpoints
ca_certificate_test.rs  - CA certificate management
certificate_test.rs     - Certificate CRUD
device_auth_test.rs     - Device authorization flow
federation_test.rs      - Federation/SSO endpoints
group_test.rs           - Group management
health_test.rs          - Health check endpoint
middleware_test.rs       - JWT auth middleware, RBAC checks
oauth2_client_test.rs   - OAuth2 client management
oauth2_flow_test.rs     - OAuth2 authorization flows
organization_test.rs    - Organization CRUD
pgp_key_test.rs         - PGP key management
resource_scope_test.rs  - Resource and scope management
role_permission_test.rs - Role and permission endpoints
service_account_test.rs - Service account endpoints
settings_test.rs        - System settings
tenant_test.rs          - Tenant management
user_test.rs            - User CRUD endpoints
webhook_test.rs         - Webhook management
```

## Testing Patterns

### Database Setup Pattern

All integration tests use SurrealDB's in-memory engine (`Mem`). Common setup:

```rust
type TestDb = surrealdb::engine::local::Db;

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    // Create org, tenant, user...
}
```

### Test Auth Config Pattern

Tests use Ed25519 keypairs hardcoded as constants:

```rust
fn test_auth_config() -> AuthConfig {
    let (priv_pem, pub_pem) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: priv_pem,
        jwt_public_key_pem: pub_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}
```

### Actix-Web Test Pattern

Integration tests spin up full Actix apps with `actix_web::test`:

```rust
let app = test::init_service(
    App::new()
        .app_data(web::Data::new(db.clone()))
        .app_data(web::Data::new(auth_service.clone()))
        .configure(register_api_v1_routes)
).await;

let req = test::TestRequest::post()
    .uri("/api/v1/auth/login")
    .set_json(&login_body)
    .to_request();
let resp = test::call_service(&app, req).await;
```

### No External Mocking Libraries

Tests use real SurrealDB instances (in-memory) rather than mocking. No mockall, mockito, or similar crates. The repository trait-based design could support mocking but tests prefer real database operations.

## Test Coverage Gaps

### Crates with No Tests
- `axiam-pki` — CA, cert, mTLS, PGP modules (0 tests)
- `axiam-authz` — Authorization engine
- `axiam-amqp` — AMQP consumer/producer
- `axiam-api-grpc` — gRPC services
- `axiam-federation` — SAML/OIDC federation logic (only TODO stubs)
- `axiam-server` — Binary entry point (no unit tests)
- `axiam-audit` — Audit service (only notification module has TODOs)

### Areas with Partial Coverage
- `axiam-db` — Only schema migration tests; no repository-level tests
- `axiam-oauth2` — PKCE and OIDC tests exist, but token endpoint untested

## CI Test Configuration

Tests run via GitHub Actions CI pipeline. The `just test` command runs `cargo test` across the workspace. Individual crates can be tested with `just test-one <crate>` or `cargo test -p <crate>`.

## Observations

1. **Heavy integration-test bias**: Most tests exercise the full REST API stack (handler → service → repository → DB), which provides good end-to-end confidence but makes failures harder to isolate
2. **No test fixtures/factories**: Each test file duplicates setup code; a shared test-utils crate would reduce boilerplate
3. **`unwrap()` in tests is acceptable**: Test code uses `.unwrap()` extensively, which is standard Rust test practice
4. **No property-based testing**: No use of proptest or quickcheck
5. **No snapshot testing**: No insta or similar crate
6. **No fuzzing**: No cargo-fuzz targets
