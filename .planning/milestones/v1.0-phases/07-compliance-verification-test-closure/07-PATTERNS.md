# Phase 7: Compliance Verification & Test Closure - Pattern Map

**Mapped:** 2026-06-07
**Files analyzed:** 15 (new/modified target files)
**Analogs found:** 13 / 15 (2 are net-new with no codebase precedent)

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/axiam-api-grpc/tests/grpc_authz_test.rs` | test (integration harness) | request-response | `crates/axiam-authz/tests/authz_engine_test.rs` | role-match (same engine setup; gRPC transport is net-new) |
| `crates/axiam-api-grpc/build.rs` (MODIFY) | config (codegen) | — | `crates/axiam-api-grpc/build.rs` itself | exact (add `build_client(true)` behind feature flag) |
| `crates/axiam-pki/tests/ca_test.rs` | test (unit/integration) | request-response | `crates/axiam-authz/tests/authz_engine_test.rs` + `crates/axiam-pki/src/ca.rs` | role-match |
| `crates/axiam-pki/tests/cert_test.rs` | test (unit/integration) | request-response | same as above + `crates/axiam-pki/src/cert.rs` | role-match |
| `crates/axiam-pki/tests/mtls_test.rs` | test (unit/integration) | request-response | same as above + `crates/axiam-pki/src/mtls.rs` | role-match |
| `crates/axiam-pki/tests/pgp_test.rs` | test (unit/integration) | request-response | `crates/axiam-pki/src/pgp.rs` + `authz_engine_test.rs` | role-match |
| `crates/axiam-api-rest/tests/oauth2_conformance.rs` | test (integration) | request-response | `crates/axiam-api-rest/tests/oauth2_flow_test.rs` | exact |
| `crates/axiam-api-rest/tests/oidc_conformance.rs` | test (integration) | request-response | `crates/axiam-api-rest/tests/oauth2_flow_test.rs` + `crates/axiam-server/tests/req5_oidc_e2e.rs` | exact |
| `frontend/e2e/*.spec.ts` (11 rewrites) | test (E2E) | request-response | `frontend/e2e/login.spec.ts` (UI-only tests in it are the good parts) | partial |
| `frontend/e2e/helpers/auth.ts` | utility (test helper) | request-response | no analog — net-new | none |
| `docs/compliance/*.md` (4 files) | documentation | — | no analog — net-new doc format | none |
| `docker/docker-compose.e2e.yml` | config (CI service) | — | `docker/docker-compose.dev.yml` | exact |
| `.github/workflows/ci.yml` (MODIFY) | config (CI) | — | `.github/workflows/ci.yml` existing `test:` job | exact |

---

## Pattern Assignments

### `crates/axiam-api-grpc/tests/grpc_authz_test.rs` (test, request-response)

**Analog:** `crates/axiam-authz/tests/authz_engine_test.rs` (engine setup) + `crates/axiam-api-grpc/src/server.rs` (service wiring)

**Imports pattern** — copy from `authz_engine_test.rs` lines 1-23, then add tonic transport:
```rust
use axiam_authz::{AccessDecision, AccessRequest, AuthorizationEngine};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};
use tokio_stream::wrappers::TcpListenerStream;
// Proto-generated client stubs (requires build_client(true)):
use axiam_api_grpc::proto::authorization_service_client::AuthorizationServiceClient;
use axiam_api_grpc::proto::{CheckAccessRequest, BatchCheckAccessRequest};
```

**Type alias pattern** — copy from `authz_engine_test.rs` lines 25-32:
```rust
type TestDb = surrealdb::engine::local::Db;
type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;
```

**DB setup pattern** — copy from `authz_engine_test.rs` lines 34-78 (the `setup()` async fn: Mem DB, `use_ns("test").use_db("test")`, `run_migrations`, org/tenant/user creation via repos).

**Engine construction** — copy from `authz_engine_test.rs` lines 80-89 (`make_engine` fn, `AuthorizationEngine::new(repo, repo, repo, repo, repo)`).

**In-process gRPC server pattern** (adapt from `server.rs` lines 47-58, OMIT governor layer):
```rust
// DO NOT use build_grpc_governor_layer in tests — SmartIpKeyExtractor reads
// x-forwarded-for headers which in-process connections do not set.
// Source: crates/axiam-api-grpc/src/server.rs:47-58 (adapted — no .layer(governor))
async fn start_test_server(
    engine: TestEngine,
    user_repo: SurrealUserRepository<TestDb>,
    auth_config: axiam_auth::config::AuthConfig,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    use axiam_api_grpc::proto::authorization_service_server::AuthorizationServiceServer;
    use axiam_api_grpc::services::AuthorizationServiceImpl;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let authz_svc = AuthorizationServiceServer::new(AuthorizationServiceImpl::new(engine));
    tokio::spawn(
        Server::builder()
            .add_service(authz_svc)
            // add_service(user_svc) and add_service(token_svc) as needed
            .serve_with_incoming_shutdown(incoming, async { rx.await.ok(); }),
    );

    let endpoint = format!("http://{addr}");
    (endpoint, tx)
}
```

**Client connect + test case pattern** (T19.1):
```rust
#[tokio::test]
async fn check_access_allows_when_role_grants_permission() {
    let (db, tenant_id, user_id) = setup().await;
    let engine = make_engine(&db);
    // ... grant_user_role_permission (copy helper from authz_engine_test.rs:112-155)
    let (endpoint, _shutdown) = start_test_server(engine, ...).await;
    let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
    let mut client = AuthorizationServiceClient::new(channel);
    let resp = client.check_access(CheckAccessRequest {
        user_id: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        action: "read".into(),
        resource_id: resource_id.to_string(),
    }).await.unwrap().into_inner();
    assert!(resp.allowed);
}
```

**Error mapping pattern** — copy from `crates/axiam-api-grpc/src/services/authorization.rs` lines 40-44:
```rust
fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Status> {
    value
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument(format!("invalid {field}")))
}
```
Test that bad UUID inputs return `Status::invalid_argument` by asserting `.err().unwrap().code() == tonic::Code::InvalidArgument`.

**Landmines:**
- `[A1]` `serve_with_incoming_shutdown` + `TcpListenerStream` is the assumed tonic 0.14 idiom — verify at compile time; fallback: `serve_with_shutdown` on a fixed ephemeral port.
- `[A2]` Client stubs require `build_client(true)` — see `build.rs` section below.
- Governor layer (`build_grpc_governor_layer`) MUST be omitted from test server (no real peer IP).
- T19.2 concurrent test: spawn N `tokio::spawn(async { client.check_access(...).await })` tasks and `join_all` — exercises `AuthorizationEngine` `Arc<dyn ...>` Send+Sync bounds.

---

### `crates/axiam-api-grpc/build.rs` (MODIFY — add `client` feature)

**Analog:** `crates/axiam-api-grpc/build.rs` (the file itself, lines 1-14)

Current production content:
```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)          // ← change to conditional
        .compile_protos(
            &[
                "../../proto/axiam/v1/authorization.proto",
                "../../proto/axiam/v1/user.proto",
                "../../proto/axiam/v1/token.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
```

**Target modification** (feature-flag approach):
```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build_client = std::env::var("CARGO_FEATURE_CLIENT").is_ok();
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(build_client)
        .compile_protos(
            &[
                "../../proto/axiam/v1/authorization.proto",
                "../../proto/axiam/v1/user.proto",
                "../../proto/axiam/v1/token.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
```

Add to `crates/axiam-api-grpc/Cargo.toml`:
```toml
[features]
client = []

[dev-dependencies]
# tonic transport already in workspace
tokio-stream = { workspace = true }
```

Tests run with: `cargo test -p axiam-api-grpc --features client`

**Landmine:** `[A2]` If tonic-prost-build 0.14 does not pick up `CARGO_FEATURE_CLIENT`, fall back to a separate `axiam-api-grpc-tests` workspace crate with its own `build.rs` calling `build_client(true).build_server(false)`.

---

### `crates/axiam-pki/tests/ca_test.rs` (test, request-response)

**Analog:** `crates/axiam-authz/tests/authz_engine_test.rs` (Mem DB setup) + `crates/axiam-pki/src/ca.rs` (API surface)

**Imports + DB setup** — copy the Mem DB setup from `authz_engine_test.rs` lines 34-42, then add PKI imports:
```rust
use axiam_db::repository::SurrealCaCertificateRepository;
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_core::models::certificate::{CreateCaCertificate, KeyAlgorithm};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn test_pki_config() -> PkiConfig {
    PkiConfig { encryption_key: [0u8; 32] }  // deterministic for tests
}
```

**Core pattern** — from `ca.rs` lines 44-101, the `generate()` flow is the surface under test:
```rust
#[tokio::test]
async fn ca_generate_ed25519_roundtrip() {
    let db = setup_db().await;
    let repo = SurrealCaCertificateRepository::new(db.clone());
    let svc = CaService::new(repo, test_pki_config());

    let result = svc.generate(CreateCaCertificate {
        organization_id: uuid::Uuid::new_v4(),
        subject: "Test CA".into(),
        key_algorithm: KeyAlgorithm::Ed25519,
        validity_days: 365,
    }).await.unwrap();

    assert!(!result.private_key_pem.is_empty());
    assert!(result.certificate.public_cert_pem.contains("CERTIFICATE"));
    assert!(!result.certificate.fingerprint.is_empty());
}
```

**rcgen 0.13 API facts** (verified from `ca.rs:68-78`):
- `CertificateParams::new(Vec::<String>::new())?` — no `params.key_pair` field
- `params.self_signed(&key_pair)?` — key_pair passed as argument
- `params.not_before` / `params.not_after` use `time::OffsetDateTime`, NOT rcgen's own type

**Error-path pattern:**
```rust
#[tokio::test]
async fn ca_generate_rejects_zero_validity() {
    let db = setup_db().await;
    let svc = CaService::new(SurrealCaCertificateRepository::new(db), test_pki_config());
    let err = svc.generate(CreateCaCertificate { validity_days: 0, .. }).await;
    assert!(err.is_err());
}
```

---

### `crates/axiam-pki/tests/cert_test.rs` (test, request-response)

**Analog:** `crates/axiam-pki/src/cert.rs` (API surface) + `ca_test.rs` (CA fixture helper)

**Core pattern:** Create a CA via `CaService::generate`, then use the resulting PEM to sign a leaf cert via `CertService::generate`. The reject-cases listed in RESEARCH.md (expired CA, inactive CA, `validity_days` exceeds CA window) are the priority cases.

```rust
// Reject: inactive CA
// Scenario: revoke the CA, then try to issue a leaf cert — expect Err
let ca = svc_ca.generate(create_ca_input).await.unwrap().certificate;
svc_ca.revoke(ca.organization_id, ca.id).await.unwrap();
let err = svc_cert.generate(ca.organization_id, create_leaf_input, 365).await;
assert!(matches!(err, Err(AxiamError::Validation { .. })));
```

**Expired-CA reject test:** Store a `StoreCaCertificate` with `not_after` in the past directly via repo (Mem has no date validation), then call `CertService::generate` — verify it returns an error.

---

### `crates/axiam-pki/tests/mtls_test.rs` (test, request-response)

**Analog:** `crates/axiam-pki/src/mtls.rs` (API surface)

**Core pattern:** `DeviceAuthService::authenticate(pem: &str) -> DeviceIdentity`. Test cases per D-09:
1. Valid cert registered → returns `DeviceIdentity`
2. Unknown fingerprint (cert not in DB) → `NotFound` error
3. Expired cert (`not_after` < now, stored via repo with past date) → error
4. Revoked/inactive cert → error

```rust
#[tokio::test]
async fn mtls_rejects_expired_cert() {
    let db = setup_db().await;
    // Insert cert row with not_after = Utc::now() - 1 day via SurrealCertificateRepository
    // Call DeviceAuthService::authenticate with that cert's PEM
    // Assert Err (validation or not-found depending on check order in mtls.rs)
}
```

**Landmine:** Check which error variant `DeviceAuthService` returns for an expired cert vs unknown fingerprint — they may be the same `AxiamError::NotFound` or `AxiamError::Validation`. Read `crates/axiam-pki/src/mtls.rs` before writing asserts.

---

### `crates/axiam-pki/tests/pgp_test.rs` (test, request-response)

**Analog:** `crates/axiam-pki/src/pgp.rs` (API surface + pgp 0.19 call sites verified)

**Imports pattern** — from `pgp.rs` lines 1-21:
```rust
use pgp::composed::{ArmorOptions, Deserializable, KeyType, MessageBuilder,
    SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyDetails, KeyVersion, Password};
use rand_core::OsRng;  // rand_core 0.6 OsRng
```

**Core pattern — sign+verify roundtrip:**
```rust
#[tokio::test]
async fn pgp_sign_and_verify_audit_batch() {
    let db = setup_db().await;
    let repo = SurrealPgpKeyRepository::new(db);
    let svc = PgpService::new(repo, test_pki_config());
    // Generate Ed25519Legacy key (signing only)
    let generated = svc.generate(CreatePgpKey {
        tenant_id: uuid::Uuid::new_v4(),
        name: "Test Auditor".into(),
        email: "audit@axiam.dev".into(),
        algorithm: PgpKeyAlgorithm::Ed25519,
        purpose: PgpKeyPurpose::AuditSigning,
    }).await.unwrap();
    // sign_audit_batch → returns SignedAuditBatch with armored signature
    let batch = svc.sign_audit_batch(tenant_id, vec![/* AuditLogEntry */]).await.unwrap();
    assert!(!batch.signature.is_empty());
    // Verify: parse signed message with pgp::composed::Message::from_string()
    // and verify with public key (see pgp 0.19 trait Message::verify())
}
```

**Ed25519Legacy encryption reject (verified from `pgp.rs:173`):**
```rust
#[tokio::test]
async fn pgp_rejects_ed25519_for_encryption() {
    // generate Ed25519 key, then call encrypt_for_export with its id
    // assert Err(AxiamError::Validation { .. })
}
```

**RSA4096 encrypt test:**
```rust
// Generate PgpKeyAlgorithm::Rsa4096 / purpose = Export
// Call svc.encrypt_for_export(tenant_id, key_id, b"secret data")
// Assert Ok(EncryptedExport { ciphertext: .. })
```

**Landmine:** `pgp` uses `rand 0.8` / `rand_core 0.6` — use `rand_core::OsRng`, not `rand::thread_rng()`. Use `AeadOsRng` alias from `pgp.rs:3` for AES-GCM ops.

---

### `crates/axiam-api-rest/tests/oauth2_conformance.rs` (test, request-response)

**Analog:** `crates/axiam-api-rest/tests/oauth2_flow_test.rs` — EXACT copy of harness

**Imports + type alias** — copy `oauth2_flow_test.rs` lines 1-37 verbatim (same crate, same imports).

**`test_app!` macro** — copy `oauth2_flow_test.rs` lines 124-165 verbatim.

**Helpers** — copy `test_keypair()`, `test_auth_config()`, `setup_db()`, `create_admin_user()`, `mint_token()`, `pkce_challenge()`, `create_client()`, `do_authorize()` from `oauth2_flow_test.rs`. House style is copy (no shared util module exists).

**New tests to add** (RFC gaps from RESEARCH.md §Target 2):
```rust
// RFC 7636 §4.2 — plain method MUST be rejected
#[actix_web::test]
async fn pkce_plain_method_rejected() {
    // authorize with code_challenge_method=plain → expect error in redirect
    // or 400 response
}

// RFC 7636 §4.1 — verifier length bounds
#[actix_web::test]
async fn pkce_verifier_too_short_rejected() { /* verifier < 43 chars */ }

#[actix_web::test]
async fn pkce_verifier_too_long_rejected() { /* verifier > 128 chars */ }

// RFC 6749 §5.2 — WWW-Authenticate header on 401
#[actix_web::test]
async fn invalid_client_returns_www_authenticate_header() {
    // POST /oauth2/token with wrong secret
    // assert resp.headers().get("WWW-Authenticate").is_some()
}

// RFC 6749 §7.1 — token_type=Bearer in response
#[actix_web::test]
async fn token_response_includes_bearer_token_type() {
    // happy path token exchange
    // assert body["token_type"].as_str() == Some("Bearer")
}

// RFC 6749 §6 — cross-client refresh MUST fail
#[actix_web::test]
async fn refresh_token_bound_to_original_client() {
    // create two clients, get refresh token from client A
    // try to use it with client B credentials → invalid_grant
}
```

**Request pattern** — copy from `oauth2_flow_test.rs` lines 193-212:
```rust
let req = test::TestRequest::post()
    .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
    .uri("/api/v1/oauth2/token")
    .set_form(&[("grant_type", "authorization_code"), ...])
    .to_request();
let resp = test::call_service(&app, req).await;
assert_eq!(resp.status().as_u16(), 400);
let body: serde_json::Value = test::read_body_json(resp).await;
assert_eq!(body["error"].as_str(), Some("invalid_client"));
```

**Peer address constant** — must include `const TEST_PEER: &str = "127.0.0.1:12345";` (line 13 of analog) for rate-limiter key extractor.

---

### `crates/axiam-api-rest/tests/oidc_conformance.rs` (test, request-response)

**Analog (primary):** `crates/axiam-api-rest/tests/oauth2_flow_test.rs` — harness  
**Analog (secondary):** `crates/axiam-server/tests/req5_oidc_e2e.rs` — discovery/JWKS/claims patterns

**Imports** — same as `oauth2_conformance.rs` above; add `base64::Engine` for JWT payload decode.

**New OIDC-specific tests:**
```rust
// OIDC Discovery §3 — required fields exhaustive check
#[actix_web::test]
async fn discovery_doc_has_all_required_fields() {
    let resp = test::call_service(&app, GET "/.well-known/openid-configuration").await;
    let doc: serde_json::Value = test::read_body_json(resp).await;
    for field in ["issuer", "authorization_endpoint", "token_endpoint",
                  "jwks_uri", "response_types_supported",
                  "subject_types_supported", "id_token_signing_alg_values_supported"] {
        assert!(doc[field] != serde_json::Value::Null, "missing field: {field}");
    }
}

// OIDC Core Discovery §3 — alg list MUST NOT include "none"
#[actix_web::test]
async fn discovery_doc_excludes_alg_none() {
    let doc: serde_json::Value = ...;
    let algs = doc["id_token_signing_alg_values_supported"].as_array().unwrap();
    assert!(!algs.iter().any(|a| a == "none"));
}

// OIDC Core §3.1.3.7 — id_token iss MUST match discovery issuer
#[actix_web::test]
async fn id_token_iss_matches_discovery_issuer() {
    // full auth-code flow → extract id_token from token response
    // decode payload (base64url, no verification needed for field check)
    let parts: Vec<&str> = id_token.splitn(3, '.').collect();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1]).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    // also GET /.well-known/openid-configuration → compare iss fields
    assert_eq!(claims["iss"], discovery_doc["issuer"]);
}
```

**wiremock pattern** for alg:none at service layer — cite `req5_oidc_e2e.rs::oidc_rejects_alg_none` as evidence; only add HTTP-layer test if `oauth2/token` has a separate code path for algorithm checking.

---

### `frontend/e2e/*.spec.ts` — all 11 rewrites (test, E2E)

**Analog (structure):** `frontend/e2e/login.spec.ts` — the UI-only tests in it (no `mockAuth`) are the CORRECT pattern to follow.

**Analog (bug to eliminate):** `frontend/e2e/federation.spec.ts` lines 53-68 — `sessionStorage.setItem("axiam-auth", ...)` — this entire pattern is WRONG and must not appear in any rewritten spec.

**Playwright config** — from `frontend/playwright.config.ts` (25 lines, already correct structure):
```typescript
// baseURL: "http://localhost:5173"   ← override with E2E_BASE_URL in CI
// trace: "on-first-retry"            ← keep
// reuseExistingServer: !process.env.CI  ← keep
```

**Correct spec structure** (replace `mockAuth` with `loginAsAdmin` helper):
```typescript
import { test, expect } from "@playwright/test";
import { loginAsAdmin } from "./helpers/auth";

test.describe("Dashboard page", () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page);  // real login via UI → httpOnly cookie set
  });

  test("shows dashboard after login", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page).not.toHaveURL(/\/login/);
    await expect(page.getByRole("navigation")).toBeVisible();
  });
});
```

**Data assertions** — assert against LIVE backend responses (not `page.route(...)` mocked data). For RBAC-gated elements, navigate to a route that requires a specific permission and verify UI state (button visible vs hidden).

**Federation E2E (D-13)** — mock only the external IdP redirect using `page.route()` to intercept the IdP callback URL and complete the AXIAM side; assert AXIAM UI state after SSO:
```typescript
// Intercept the external IdP redirect — simulate callback to AXIAM
await page.route("**/federation/callback**", route => {
    // Allow AXIAM to handle its own callback (this IS the AXIAM endpoint)
    route.continue();
});
// Trigger SSO login → page.route intercepts outbound IdP redirect
await page.route("https://idp.example.com/**", route => {
    // Simulate IdP redirecting back with auth code
    const callbackUrl = "http://localhost:5173/federation/callback?code=test-code&state=...";
    route.fulfill({ status: 302, headers: { Location: callbackUrl } });
});
```

**Landmines:**
- NEVER use `sessionStorage.setItem` or `localStorage` for auth state — httpOnly cookies cannot be read/written from JS.
- Every spec that previously had `test.beforeEach(mockAuth)` must switch to `test.beforeEach(loginAsAdmin)`.
- Live backend must be running (D-13) — specs will fail with redirect-to-login if backend is down.
- Login form field labels from `login.spec.ts:8-33`: "Organization slug", "Tenant slug", "Continue" button, "Username or email", "Sign in" button.

---

### `frontend/e2e/helpers/auth.ts` (utility, request-response)

**Analog:** none — net-new. Pattern from `login.spec.ts` lines 26-33 (field labels) + RESEARCH.md §Target 4 (login helper spec).

**Target content:**
```typescript
import { Page } from "@playwright/test";

export async function loginAsAdmin(page: Page): Promise<void> {
    await page.goto("/login");
    await page.getByLabel("Organization slug").fill(
        process.env["E2E_ORG_SLUG"] ?? "test-org"
    );
    await page.getByLabel("Tenant slug").fill(
        process.env["E2E_TENANT_SLUG"] ?? "default"
    );
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByLabel("Username or email").fill(
        process.env["E2E_ADMIN_EMAIL"] ?? "admin@axiam.dev"
    );
    await page.getByLabel("Password").fill(
        process.env["E2E_ADMIN_PASSWORD"] ?? "test-admin-pass"
    );
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.waitForURL(/\/dashboard|\/$/, { timeout: 10_000 });
}
```

Field labels verified from `login.spec.ts:8,22,28,33`.

---

### `docs/compliance/{asvs-l2-checklist,oauth2-rfc-compliance,oidc-conformance,FINDINGS}.md` (documentation)

**Analog:** none — net-new doc format per D-12.

**Row format for ASVS checklist (D-12):**
```markdown
| Control ID | Control Text | Status | Evidence | Note |
|---|---|---|---|---|
| V2.1.1 | User-set passwords ≥ 12 chars | Pass | `axiam-api-rest/src/handlers/user.rs` (password validator) | — |
| V2.9.x | Cryptographic authenticators | Pass | `crates/axiam-pki/tests/mtls_test.rs` (Phase 7) | mTLS device auth |
| V3.4.1 | Cookie attributes (httpOnly, Secure, SameSite) | Pass | `auth_test.rs:253+385` | Secure=false in dev by env var (D-18) |
```

**Status values:** `Pass` / `N/A` / `Deferred (see FINDINGS.md #N)`

**FINDINGS.md row format (D-05):**
```markdown
| # | Finding | Severity | ASVS/RFC Ref | Deferral Rationale | Issue |
|---|---|---|---|---|---|
| F-01 | WWW-Authenticate header missing on /oauth2/token 401 | Low | RFC 6749 §5.2 | Cosmetic; no security impact | #123 |
```

---

### `docker/docker-compose.e2e.yml` (config, CI service)

**Analog:** `docker/docker-compose.dev.yml` — EXACT structure to replicate

**Key differences from dev compose** (from `docker-compose.dev.yml` lines 1-76):
- Use `surrealdb/surrealdb:v3` with in-memory mode (`start --log info memory`) — no volume needed in CI
- Remove `surrealdb-init` service (no volume chown needed for memory mode)
- Add bootstrap env vars: `AXIAM__BOOTSTRAP_ADMIN_EMAIL` + `AXIAM__BOOTSTRAP_ADMIN_PASSWORD`
- Add `AXIAM__AUTH__COOKIE_SECURE: "false"` (already at dev compose line 71 — copy verbatim)
- Frontend served separately by CI step (not in compose)

```yaml
services:
  surrealdb:
    image: surrealdb/surrealdb:v3
    command: start --user root --pass root --log info memory
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "/surreal", "isready"]
      interval: 10s
      timeout: 5s
      retries: 5

  rabbitmq:
    image: rabbitmq:4-management-alpine
    # ... copy from docker-compose.dev.yml lines 33-48

  axiam-server:
    image: ghcr.io/axiamhq/axiam/server:latest
    depends_on:
      surrealdb:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
    ports:
      - "8090:8090"
    environment:
      AXIAM__DB__URL: "surrealdb:8000"
      AXIAM__DB__USERNAME: root
      AXIAM__DB__PASSWORD: root
      AXIAM__AMQP__URL: "amqp://axiam:axiam@rabbitmq:5672"
      AXIAM__AUTH__COOKIE_SECURE: "false"           # D-18 — required for http://localhost
      AXIAM__BOOTSTRAP_ADMIN_EMAIL: "admin@axiam.dev"
      AXIAM__BOOTSTRAP_ADMIN_PASSWORD: "test-admin-pass"
```

---

### `.github/workflows/ci.yml` (MODIFY — add E2E job)

**Analog:** `.github/workflows/ci.yml` existing `test:` job (lines 166-198) — copy structure

**Existing job structure** (from `ci.yml` lines 166-198):
- `runs-on: ubuntu-latest`
- `services:` block for rabbitmq with healthcheck
- `env:` block for DB/AMQP URLs
- Steps: checkout, rust-toolchain, rust-cache, apt install protobuf, `cargo test --workspace`

**RUSTFLAGS guard** — `RUSTFLAGS: "-Dwarnings"` is set at top-level `env:` (line 14) and applies to all jobs including new ones. All new test code must be warning-clean.

**`build-no-saml` guard** — lines 49-63 must remain UNCHANGED (D-06). Do not add `--tests` flag to that job.

**New E2E job to append** (D-14):
```yaml
e2e:
  name: E2E Tests
  runs-on: ubuntu-latest
  needs: [build]    # gate on successful build; runs in parallel with test job
  steps:
    - uses: actions/checkout@v4
    - name: Start backend services
      run: docker compose -f docker/docker-compose.e2e.yml up -d --wait
    - name: Setup Node
      uses: actions/setup-node@v4
      with:
        node-version: "20"
        cache: "npm"
        cache-dependency-path: frontend/package-lock.json
    - name: Install frontend dependencies
      working-directory: frontend
      run: npm ci
    - name: Build frontend
      working-directory: frontend
      run: npm run build
    - name: Install Playwright Chromium
      working-directory: frontend
      run: npx playwright install chromium
    - name: Run E2E tests
      working-directory: frontend
      run: npm test
      env:
        CI: "true"
        E2E_BASE_URL: "http://localhost:5173"
        E2E_ORG_SLUG: "test-org"
        E2E_TENANT_SLUG: "default"
        E2E_ADMIN_EMAIL: "admin@axiam.dev"
        E2E_ADMIN_PASSWORD: "test-admin-pass"
    - name: Upload Playwright report
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: playwright-report
        path: frontend/playwright-report/
    - name: Stop services
      if: always()
      run: docker compose -f docker/docker-compose.e2e.yml down
```

**`playwright.config.ts` modification** — add `E2E_BASE_URL` override:
```typescript
use: {
    baseURL: process.env["E2E_BASE_URL"] ?? "http://localhost:5173",
    trace: "on-first-retry",
},
```

---

## Shared Patterns

### In-Memory SurrealDB Setup (all Rust test files)
**Source:** `crates/axiam-authz/tests/authz_engine_test.rs` lines 34-42  
**Apply to:** `grpc_authz_test.rs`, `ca_test.rs`, `cert_test.rs`, `mtls_test.rs`, `pgp_test.rs`, `oauth2_conformance.rs`, `oidc_conformance.rs`
```rust
let db = Surreal::new::<Mem>(()).await.unwrap();
db.use_ns("test").use_db("test").await.unwrap();
axiam_db::run_migrations(&db).await.unwrap();
```

### Actix Test Harness (conformance tests)
**Source:** `crates/axiam-api-rest/tests/oauth2_flow_test.rs` lines 124-165 (`test_app!` macro)  
**Apply to:** `oauth2_conformance.rs`, `oidc_conformance.rs`  
Key detail: always include `const TEST_PEER: &str = "127.0.0.1:12345";` and `.peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())` on every `TestRequest`.

### -Dwarnings Clean (all new Rust files)
**Source:** `.github/workflows/ci.yml` line 14: `RUSTFLAGS: "-Dwarnings"`  
**Apply to:** All new `.rs` files — no `#[allow(...)]` unless absolutely required; no unused imports.

### rcgen 0.13 Key API (PKI tests)
**Source:** `crates/axiam-pki/src/ca.rs` lines 68-78  
**Apply to:** `ca_test.rs`, `cert_test.rs`  
`params.self_signed(&key_pair)` — never `params.key_pair = Some(...)` (field does not exist in 0.13).

### pgp 0.19 OsRng (PKI PGP test)
**Source:** `crates/axiam-pki/src/pgp.rs` lines 20-21  
**Apply to:** `pgp_test.rs`  
Use `rand_core::OsRng` (rand_core 0.6), not `rand::thread_rng()` (rand 0.9).

### Cookie-Auth Assertion (E2E specs)
**Source:** `frontend/e2e/login.spec.ts` line 6 (UI-state assertion style)  
**Apply to:** All 11 E2E specs  
```typescript
await expect(page).not.toHaveURL(/\/login/);          // auth succeeded
await expect(page.getByRole("navigation")).toBeVisible(); // UI rendered
```
Never assert `sessionStorage` or `localStorage` token values.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `frontend/e2e/helpers/auth.ts` | utility | request-response | No shared E2E helper files exist; all specs previously used inline `mockAuth` (now defunct) |
| `docs/compliance/*.md` (4 files) | documentation | — | No compliance docs exist in the repo; format defined by D-12 and D-05 decisions |

---

## Metadata

**Analog search scope:** `crates/`, `frontend/e2e/`, `docker/`, `.github/workflows/`, `frontend/playwright.config.ts`  
**Files scanned:** 14 source files read directly  
**Pattern extraction date:** 2026-06-07

---

## PATTERN MAPPING COMPLETE

**Phase:** 7 - Compliance Verification & Test Closure  
**Files classified:** 15  
**Analogs found:** 13 / 15

### Coverage
- Files with exact analog: 4 (`oauth2_conformance.rs`, `oidc_conformance.rs`, `docker-compose.e2e.yml`, `ci.yml` E2E job)
- Files with role-match analog: 9 (all PKI tests, gRPC harness, E2E spec rewrites)
- Files with no analog: 2 (`helpers/auth.ts`, `docs/compliance/*.md`)

### Key Patterns Identified
- All Rust integration tests use `Surreal::new::<Mem>(())` + `run_migrations` + Surreal*Repository — copy from `authz_engine_test.rs`
- OAuth2/OIDC conformance tests are pure additive to `oauth2_flow_test.rs` harness — copy `test_app!` macro + helpers verbatim
- gRPC test server = `Server::builder().add_service(...).serve_with_incoming_shutdown(TcpListenerStream, rx)` — NO governor layer (SmartIpKeyExtractor panics without real peer IP)
- All 11 E2E specs replace `sessionStorage.setItem("axiam-auth", ...)` with `loginAsAdmin(page)` helper calling real UI login flow
- `AXIAM__AUTH__COOKIE_SECURE=false` env var already present in `docker-compose.dev.yml:71` — copy to `docker-compose.e2e.yml`

### File Created
`.planning/phases/07-compliance-verification-test-closure/07-PATTERNS.md`

### Ready for Planning
Pattern mapping complete. Planner can now reference analog patterns in PLAN.md files.
