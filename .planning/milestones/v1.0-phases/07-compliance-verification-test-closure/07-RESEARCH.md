# Phase 7: Compliance Verification & Test Closure — Research

**Researched:** 2026-06-07
**Domain:** Security compliance audit (OWASP ASVS L2), protocol conformance testing (OAuth2/OIDC), in-process gRPC test harness (tonic 0.14), PKI unit tests (rcgen 0.13 / pgp 0.19), Playwright E2E reconciliation
**Confidence:** HIGH (all claims verified from source files in the repo; external standards cited by spec section)

---

## Summary

Phase 7 is verification-and-closure, not feature work. Phases 1–6 built almost all of REQ-11; the only real AC-4 test gaps are `axiam-pki` (no `tests/` dir) and `axiam-api-grpc` (no `tests/` dir). The largest technical unknown is the gRPC in-process harness: `build_client(false)` in `crates/axiam-api-grpc/build.rs` means no generated client stub exists yet — the test crate's `build.rs` must regenerate protos with `build_client(true)`. The governor rate-limiting middleware attached to the server is a tower-layer complication the harness must route around or accommodate.

The OAuth2/OIDC conformance gap is smaller than it looks: `oauth2_flow_test.rs` (37 async fns, 52 KB) already covers the happy-path grant types, most RFC 6749 §5.2 error codes, PKCE S256 enforcement, and basic OIDC (discovery doc, JWKS, userinfo, id_token claims). The new `oauth2_conformance.rs` / `oidc_conformance.rs` files need to fill the remaining RFC MUST holes — primarily: plain verifier without S256 rejected, `code_challenge_method=plain` rejected, discovery doc field completeness (required OIDC Core fields present), `alg:none` rejection. These are additive to the existing harness, same `test::init_service` pattern.

The 11 Playwright specs are uniformly stale: every spec uses `sessionStorage.setItem("axiam-auth", ...)` to fake auth (e.g., `federation.spec.ts:67`), but Phase 1 migrated auth to httpOnly cookies. All must be rewritten to drive real login via the backend (`axiam-server` + seeded DB, D-13). The CI E2E job (D-14) is net-new CI plumbing — a new docker-compose service file is needed that also sets `AXIAM__AUTH__COOKIE_SECURE=false` (mirrors `docker-compose.dev.yml:71`).

**Primary recommendation:** The planner should front-load the gRPC harness (highest uncertainty, no precedent) and plan it as its own wave before the conformance tests and E2E work. PKI tests and ASVS checklist are mechanical once the PKI API surface is understood (it's all concrete services with no DB in most test cases).

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Hybrid verification. ASVS L2 → markdown checklist (control → evidence → status). OAuth2 RFC 6749/7636 + OIDC Core 1.0 → executable Rust conformance tests committed to repo.
- **D-02:** ASVS L2 scope = V2, V3, V4, V6, V7, V8, V9, V10, V14. OUT: V5, V11, V12, V13.
- **D-03:** Compliance artifacts in `docs/compliance/`: `asvs-l2-checklist.md`, `oauth2-rfc-compliance.md`, `oidc-conformance.md`, `FINDINGS.md`. Tests in crate `tests/` dirs.
- **D-04:** Severity-gated remediation. Fix Critical/High or small localized issues inline. Log Medium/Low as deferred. Beta ships with no known High holes.
- **D-05:** Deferred findings tracked in GitHub issue (label `compliance`) AND `docs/compliance/FINDINGS.md` row.
- **D-06:** Green bar = default-feature suite (`just test`, SAML ON) 100% green. The 3 `--no-default-features` SAML failures are accepted baseline (saml_acs, saml_authn, saml_metadata). Do NOT expand the `build-no-saml` guard to `--tests` in this phase.
- **D-07:** OAuth2/OIDC conformance = MUST matrix (RFC 6749 §5.2 error codes, grant types, RFC 7636 PKCE S256 enforcement, OIDC Core discovery, JWKS, userinfo, id-token validation, nonce/state, alg pinning).
- **D-08:** Conformance tests in `crates/axiam-api-rest/tests/` (e.g. `oauth2_conformance.rs`, `oidc_conformance.rs`), using Actix `test::init_service` harness.
- **D-09:** `axiam-pki` critical-path: CA keypair gen + cert signing, issuance/validation chain, mTLS verify incl. REJECT cases (expired/wrong-CA), PGP sign+verify roundtrip.
- **D-10:** `axiam-api-grpc` = in-process tonic server harness, ephemeral port, real client channel, authz over the wire (interceptors + codec + auth). Foundation for T19.1 + T19.2.
- **D-11:** Rewrite ALL 11 Playwright specs in `frontend/e2e/` to cookie-auth + RBAC-gated model. Full E2E suite green.
- **D-12:** ASVS checklist granularity = per-control rows (control ID/text → status → evidence → note).
- **D-13:** E2E runs against live `axiam-server` + seeded test DB via docker-compose. Federation flow mocks external IdP (stub redirect/callback, mirrors `req5_*` tests). E2E asserts on UI state / network, NOT sessionStorage/localStorage.
- **D-14:** E2E = separate, required CI job on every PR; runs in parallel to Rust jobs.

### Claude's Discretion

- Exact conformance-test file structure, fixture helpers, and tonic harness pattern (consistent with D-10).
- Specific ASVS control IDs that map to "N/A" vs "Deferred" — per-control during authoring.
- CI job naming, `needs:` graph, and which new checks become required status checks (consistent with D-14).

### Deferred Ideas (OUT OF SCOPE)

- Resolve the 3 `--no-default-features` SAML test failures.
- Extend `build-no-saml` CI guard to `--tests`.
- Official openid.net hosted/Docker OIDC conformance certification.
- Full ASVS L2 audit of V5, V11, V12, V13.
- Net-new capabilities surfaced by the audit (logged as findings, built in future phases).
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-11 | Testing Gaps — close critical testing gaps in security-sensitive crates | All 5 research targets directly address AC items: gRPC harness → T19.1/T19.2; PKI tests → AC-3; conformance tests → AC-2; E2E → AC-5; ASVS checklist → milestone gate |

### REQ-11 Acceptance Criteria Reconciliation

| AC Item | Status | Evidence Location |
|---------|--------|-------------------|
| gRPC authz integration tests (T19.1) | MISSING | `crates/axiam-api-grpc/` has no `tests/` dir |
| Concurrent batch authz tests (T19.2) | MISSING | same |
| PKI/certificate generation tests | MISSING | `crates/axiam-pki/` has no `tests/` dir |
| Federation OIDC flow integration tests | SATISFIED | `crates/axiam-server/tests/req5_oidc_e2e.rs` |
| Federation SAML flow integration tests | SATISFIED | `crates/axiam-server/tests/req5_saml_e2e.rs` |
| RBAC enforcement integration tests | SATISFIED | `crates/axiam-api-rest/tests/rbac_test.rs` + `middleware_test.rs` |
| Cookie auth flow integration tests | SATISFIED | `crates/axiam-api-rest/tests/auth_test.rs` |
| GDPR export/deletion integration tests | SATISFIED | `crates/axiam-api-rest/tests/gdpr_test.rs` |
| Frontend E2E tests for login, RBAC, federation | STALE | 11 specs use sessionStorage auth — must be rewritten |
</phase_requirements>

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| ASVS L2 checklist authoring | Documentation layer | All backend crates (evidence source) | Audit artifact, references code/test citations |
| OAuth2/OIDC conformance tests | API (axiam-api-rest) | axiam-oauth2 (service layer) | Tests drive HTTP endpoints via `test::init_service`; protocol conformance is endpoint-level |
| gRPC authz tests | axiam-api-grpc | axiam-authz (engine) | Tests exercise the gRPC transport + service impl; authz engine is the dependency |
| PKI critical-path tests | axiam-pki | axiam-db (mock repos) | All test cases exercise CaService/CertService/PgpService/DeviceAuthService directly |
| Frontend E2E | Browser + Frontend server | axiam-server (live backend) | Playwright drives Chromium; backend must be live (D-13); no JS token storage to assert on |
| CI E2E job | CI (GitHub Actions) | docker-compose | New job: docker-compose spins server+db, Playwright runs against it |

---

## Standard Stack

### Core (all already in workspace — no new packages)

| Library | Version | Purpose | Location |
|---------|---------|---------|----------|
| tonic | 0.14 | gRPC server + generated stubs | `Cargo.toml:49` [VERIFIED: file] |
| tonic-prost | 0.14 | prost codec for tonic | `Cargo.toml:51` [VERIFIED: file] |
| prost | 0.14 | protobuf serialization | `Cargo.toml:50` [VERIFIED: file] |
| tonic-build | 0.14 | build-time proto codegen | `Cargo.toml:52` [VERIFIED: file] |
| tonic-prost-build | 0.14 | build-time codegen (prost variant) | `Cargo.toml:53` [VERIFIED: file] |
| tower | 0.5 | middleware layering for gRPC server | `Cargo.toml:43` [VERIFIED: file] |
| tower_governor | 0.8 | rate limiting layer (gRPC) | `Cargo.toml:41` [VERIFIED: file] |
| actix-web (test) | workspace | HTTP integration test harness | in all axiam-api-rest tests [VERIFIED: file] |
| surrealdb (kv-mem) | workspace | in-memory DB for tests | `axiam-server/Cargo.toml` dev-deps [VERIFIED: file] |
| wiremock | 0.6 | mock HTTP server (IdP stub) | `axiam-server/Cargo.toml:57` [VERIFIED: file] |
| rcgen | workspace | X.509 cert generation | `axiam-pki/Cargo.toml` [VERIFIED: file] |
| pgp | workspace | OpenPGP key ops | `axiam-pki/Cargo.toml` [VERIFIED: file] |
| @playwright/test | ^1.58.2 | E2E browser test framework | `frontend/package.json` [VERIFIED: file] |

### New Dev-Dependency Required (axiam-api-grpc test crate only)

The `axiam-api-grpc/build.rs` has `build_client(false)` — no generated client stubs exist. The test crate needs its own `build.rs` or overrides to generate clients. Options:

**Option A (recommended):** Add a `tests/` directory with its own `build.rs` that recompiles protos with `build_client(true)`. This keeps the production crate server-only.

**Option B:** Add `tonic-prost-build` as a dev-dependency in `axiam-api-grpc/Cargo.toml` and conditionally enable client generation when `cfg(test)`. Tonic 0.14 does not support `cfg(test)` in build scripts — Option A is the correct pattern.

**Option C (simplest):** Use `tonic::transport::Channel` with the existing server binary — connect to an in-process `TcpListener::bind("127.0.0.1:0")` address. This requires generating client stubs or hand-writing raw tonic client calls. The generated stub approach (Option A) is strongly preferred for type safety.

---

## Package Legitimacy Audit

No new packages are installed in this phase. All dependencies are already in the workspace (verified above). No audit table required.

---

## Architecture Patterns

### System Architecture Diagram

```
Test process
  │
  ├── [axiam-pki tests]
  │     CaService/CertService/PgpService/DeviceAuthService (direct call)
  │       └── Mock repos (in-memory, no SurrealDB needed for most cases)
  │
  ├── [axiam-api-grpc tests]
  │     tokio::spawn → tonic::transport::Server (TcpListener::bind("127.0.0.1:0"))
  │       └── AuthorizationServiceImpl + TokenServiceImpl + UserServiceImpl
  │             └── AuthorizationEngine (in-memory SurrealDB repos)
  │     tonic::transport::Channel::from_static → generated stub client
  │       └── gRPC over TCP → through governor layer → service impl
  │
  ├── [oauth2_conformance / oidc_conformance tests]
  │     actix_web::test::init_service(app)
  │       └── REST endpoints (same harness as oauth2_flow_test.rs)
  │             └── real OAuth2/OIDC handlers via in-memory SurrealDB
  │
  └── [Frontend E2E — CI job]
        docker-compose (axiam-server + surrealdb + rabbitmq)
          └── AXIAM__AUTH__COOKIE_SECURE=false
          └── seeded DB (admin user + tenant + RBAC fixtures)
        Playwright → Chromium → http://localhost:PORT (frontend dev or built)
          └── Real login flow → httpOnly cookie set by backend
          └── UI-state + network assertions (NOT sessionStorage)
```

### Recommended Project Structure

```
crates/axiam-api-grpc/
└── tests/
    ├── build.rs              # proto codegen with build_client(true)
    └── grpc_authz_test.rs   # in-process harness + authz tests (T19.1)
    (batch tests can live in grpc_authz_test.rs or grpc_batch_test.rs)

crates/axiam-pki/
└── tests/
    ├── ca_test.rs            # CA keypair gen, self-signed, encrypt/decrypt
    ├── cert_test.rs          # leaf cert signed by CA, validity bounds, reject expired CA
    ├── mtls_test.rs          # DeviceAuthService: authenticate, reject expired, reject unknown
    └── pgp_test.rs           # generate Ed25519 signing + RSA4096 export; sign+verify; encrypt

crates/axiam-api-rest/tests/
├── oauth2_conformance.rs    # RFC 6749 MUST gaps + RFC 7636 edge cases
└── oidc_conformance.rs      # OIDC Core MUST gaps: alg:none reject, discovery completeness

docs/compliance/
├── asvs-l2-checklist.md     # per-control rows (D-12)
├── oauth2-rfc-compliance.md # MUST matrix with test citations
├── oidc-conformance.md      # OIDC Core MUST matrix with test citations
└── FINDINGS.md              # deferred findings (D-05)

frontend/e2e/               # rewritten (D-11)
├── login.spec.ts
├── federation.spec.ts
├── roles.spec.ts
├── users.spec.ts
├── dashboard.spec.ts
├── organizations.spec.ts
├── tenants.spec.ts
├── certificates.spec.ts
├── identity.spec.ts
├── service-accounts.spec.ts
└── settings.spec.ts

docker/docker-compose.e2e.yml   # new — for CI E2E job (D-14)
.github/workflows/ci.yml        # modified — add e2e job
```

---

## Research Target 1: gRPC In-Process Test Harness (D-10) — HIGHEST PRIORITY

### The Core Problem

`crates/axiam-api-grpc/build.rs:4` has `build_client(false)`. No generated client stubs exist in the crate. Tests must either:
1. Use a separate test-scoped `build.rs` that generates clients (recommended), or
2. Use raw `tonic::transport::Channel` with manually-constructed protobuf messages.

The production server's `start_grpc_server` function signature is:

```rust
// Source: crates/axiam-api-grpc/src/server.rs:24
pub async fn start_grpc_server<R, P, Res, S, G, U>(
    addr: SocketAddr,
    engine: AuthorizationEngine<R, P, Res, S, G>,
    user_repo: U,
    auth_config: AuthConfig,
    grpc_config: &GrpcConfig,
) -> Result<(), tonic::transport::Error>
```

All six generic type params must be concrete at the test callsite.

### In-Process Tonic 0.14 Harness Pattern

Tonic 0.14 provides `tonic::transport::Server` which can serve on a real TCP socket. The idiom is: bind port 0 → get the actual address → spawn the server → connect client → run tests → shut down. [ASSUMED — based on tonic documentation patterns; verify against tonic 0.14 release notes if unexpected API differences arise]

```rust
// Pattern for crates/axiam-api-grpc/tests/grpc_authz_test.rs
// Source: [ASSUMED: tonic 0.14 standard idiom — TcpListener::bind(0) + serve_with_shutdown]

use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};

async fn start_test_server(engine: TestEngine, ...) -> (String, impl Future) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let server = Server::builder()
        // DO NOT attach governor layer in tests — it has no peer addr context
        // and panics with SmartIpKeyExtractor against in-process connections.
        .add_service(AuthorizationServiceServer::new(AuthorizationServiceImpl::new(engine)))
        .serve_with_incoming_shutdown(incoming, async { rx.await.ok(); });

    let fut = tokio::spawn(server);
    let endpoint = format!("http://{addr}");
    (endpoint, tx, fut)
}

// Client connect:
let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
let mut client = AuthorizationServiceClient::new(channel);
```

### Critical Landmine: Governor Layer in Tests

`build_grpc_governor_layer` (`crates/axiam-api-grpc/src/middleware/rate_limit.rs:34`) uses `SmartIpKeyExtractor` which reads `x-forwarded-for` / `x-real-ip` headers. In-process tonic calls do not carry a real peer IP in these headers. The governor layer must be **omitted from the test server** to avoid panics or unexpected 429 responses. Test the governor separately (or not at all — it's already unit-testable at the config level).

### Test Build.rs for Client Generation

The test crate (`crates/axiam-api-grpc/tests/`) needs its own build script at `crates/axiam-api-grpc/tests/build.rs` — but Cargo does not support per-test-dir build scripts. The correct approach:

**Recommended:** Add `axiam-api-grpc-tests` as a separate crate in the workspace with its own `Cargo.toml` and `build.rs` that calls `tonic_prost_build::configure().build_client(true).build_server(false).compile_protos(...)`. This crate is `[[bin]]` never, `[lib]` never — it uses `[[test]]` entries.

**Alternative (simpler, acceptable for integration tests):** Add `build_client(true)` to the PRODUCTION `build.rs` but gate it on a feature flag `client`. Add `[features] client = []` and `[dev-dependencies] tonic = { features = ["transport"] }` to `axiam-api-grpc/Cargo.toml`. Tests run with `cargo test -p axiam-api-grpc --features client`. [ASSUMED — needs verification that tonic-prost-build 0.14 supports feature-gating]

**Simplest (no build.rs change):** Write the client calls using raw `tonic` channel without the generated stub. Use `prost::Message` encode/decode manually. This is verbose but avoids the build.rs problem entirely.

**The planner should choose:** Generate clients via the `client` feature flag approach (middle option) or accept the raw-message approach. The planner should document whichever is chosen as the project's gRPC test pattern.

### Type Alias for Tests (mirrors authz_engine_test.rs pattern)

```rust
// Source: crates/axiam-authz/tests/authz_engine_test.rs:24 (adapted)
type TestDb = surrealdb::engine::local::Db;
type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;
```

The gRPC test crate needs the same engine setup plus `SurrealUserRepository<TestDb>` for `UserServiceImpl`.

### T19.1 and T19.2 Test Cases

T19.1 — gRPC authz integration:
- `check_access` → Allow when role grants permission
- `check_access` → Deny when no role
- `check_access` → Deny when wrong action
- `check_access` → invalid UUID returns `Status::invalid_argument`
- `check_access` → internal DB error returns `Status::internal`

T19.2 — concurrent batch authz:
- `batch_check_access` → mix of allow/deny in one RPC
- Concurrent: spawn N tokio tasks each calling `check_access` → all resolve correctly (exercises `AuthorizationEngine` thread-safety via `Arc<dyn ...>` repo bounds)

---

## Research Target 2: OAuth2 RFC 6749/7636 + OIDC Core Conformance (D-07, D-08)

### What Already Exists in oauth2_flow_test.rs

The existing 37-test suite (52 KB) covers:
- Full auth code flow (no PKCE): `full_authorization_code_flow`
- Full auth code flow (PKCE S256): `full_authorization_code_flow_with_pkce`
- Single-use code: `auth_code_is_single_use`
- PKCE verifier mismatch → `invalid_grant`: `pkce_verification_failure`
- Invalid redirect URI: `invalid_redirect_uri_rejected_at_authorize`
- Invalid client secret: `invalid_client_secret_rejected` → `invalid_client`
- Unsupported response type: `unsupported_response_type_rejected`
- Missing code at token endpoint: `missing_code_returns_error`
- Unsupported grant type: `unsupported_grant_type_returns_error`
- Redirect URI mismatch at token: `redirect_uri_mismatch_at_token_rejected`
- State echoed: `state_parameter_echoed_in_redirect`
- PKCE required when challenge registered: `pkce_required_when_challenge_registered`
- Client credentials grant (happy path + wrong secret + unauthorized): 3 tests
- Refresh token grant + rotation + single-use: 3 tests
- Revoke refresh token + unknown token: 2 tests
- Token introspection (active, inactive, requires auth, revoked): 4 tests
- OIDC discovery doc: `oidc_discovery_document`
- OIDC JWKS endpoint: `oidc_jwks_endpoint`
- OIDC userinfo (sub, email scope, profile scope, requires auth): 4 tests
- OIDC id_token in auth code flow (claims: sub, aud, iss, nonce, iat, exp): `oidc_id_token_in_auth_code_flow`
- OIDC no id_token without openid scope: `oidc_no_id_token_without_openid_scope`

### RFC 6749 / RFC 7636 MUST Gaps (new `oauth2_conformance.rs`)

These behaviors are MUST-level but NOT yet tested:

| MUST Requirement | RFC Ref | Gap |
|-----------------|---------|-----|
| `code_challenge_method=plain` rejected (S256 is the only accepted method) | RFC 7636 §4.2 | No test asserts `plain` is rejected |
| PKCE verifier too short (< 43 chars) or too long (> 128 chars) rejected | RFC 7636 §4.1 | No length boundary tests |
| `response_type=token` (implicit) rejected — PKCE clients should not get implicit | RFC 6749 §4.2 + security BCP | Unclear if rejected; test needed |
| `WWW-Authenticate` header on 401 from /oauth2/token | RFC 6749 §5.2 | `invalid_client_secret_rejected` checks `invalid_client` error body but not the header |
| Error response MUST include `error` parameter; MAY include `error_description`, `error_uri` | RFC 6749 §5.2 | Existing tests check `body["error"]` but not that `error_description` is a string (not null) when present |
| `grant_type=password` (resource owner password) — if not supported, must return `unsupported_grant_type` | RFC 6749 §4.3 | May already be covered by `unsupported_grant_type_returns_error` — verify which grant type that test uses |
| Token response `token_type=Bearer` (case-insensitive MUST) | RFC 6749 §7.1 | Existing happy-path tests may not assert `token_type` |
| Refresh token bound to client — different client_id at refresh MUST fail | RFC 6749 §6 | No cross-client refresh test |

### OIDC Core 1.0 MUST Gaps (new `oidc_conformance.rs`)

| MUST Requirement | OIDC Ref | Gap |
|-----------------|---------|-----|
| `alg:none` id_token rejected | OIDC Core §3.1.3.7 + req5_oidc_e2e.rs | Already tested at service layer (`oidc_rejects_alg_none`). Need same assertion via HTTP endpoint in oidc_conformance.rs — or cite existing as evidence. |
| Discovery doc MUST include `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported` | OIDC Core §3.1.2.1 + Discovery §3 | `oidc_discovery_document` checks `userinfo_endpoint`, `jwks_uri`, algorithm list, but does not exhaustively assert all required fields by name |
| `userinfo_endpoint` MUST return `sub` (already tested) | OIDC Core §5.3 | Covered |
| ID token `iss` MUST match discovery `issuer` | OIDC Core §3.1.3.7 | Partially — `oidc_id_token_in_auth_code_flow` asserts `iss == "https://localhost"` but does not cross-check against the discovery doc's `issuer` field |
| `nonce` MUST be bound to the authorization request and echoed in id_token | OIDC Core §3.1.2.1 | Tested in `oidc_id_token_in_auth_code_flow` |
| Discovery `id_token_signing_alg_values_supported` MUST NOT include `none` | OIDC Core Discovery §3 | Checked in `oidc_discovery_document` (algs list) but test only checks that EdDSA is in it, not that `none` is absent |

### Test Harness Pattern (mirrors oauth2_flow_test.rs)

```rust
// Source: crates/axiam-api-rest/tests/oauth2_flow_test.rs:6–35 (pattern)
use actix_web::{App, test, web};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
// ... same imports as oauth2_flow_test.rs

// The entire oauth2_conformance.rs test file should share the same
// test_keypair(), test_auth_config(), setup_db(), create_admin_user(),
// mint_token(), pkce_challenge() helpers — either via mod.rs or copy.
// House style: copy (no shared test util modules currently exist).
```

---

## Research Target 3: axiam-pki Critical-Path Tests (D-09)

### Public API Surface to Test

All four services are concrete and well-encapsulated. Tests can drive them directly without HTTP.

```
CaService<R: CaCertificateRepository>     — ca.rs
  .generate(input: CreateCaCertificate) -> GeneratedCaCertificate  // key + cert + encrypted storage
  .get(org_id, id) -> CaCertificate
  .revoke(org_id, id) -> ()
  .list(org_id, pagination) -> PaginatedResult<CaCertificate>

CertService<CA: CaCertificateRepository, CR: CertificateRepository>  — cert.rs
  .generate(org_id, input, max_validity_days) -> GeneratedCertificate
    // leaf cert signed by CA; rejects validity_days > effective_max
    // rejects inactive CA; rejects CA outside validity window
    // caps leaf validity to CA validity window

DeviceAuthService<CR: CertificateRepository>  — mtls.rs
  .authenticate(pem: &str) -> DeviceIdentity
    // rejects: invalid PEM, unknown fingerprint, inactive cert, expired cert, unbound cert

PgpService<R: PgpKeyRepository>  — pgp.rs
  .generate(input: CreatePgpKey) -> GeneratedPgpKey
    // Ed25519Legacy for signing, RSA(4096) for export/encryption
    // AuditSigning: stores encrypted private key; returns None for private key
    // Export: does NOT store private key; returns armored private key once
  .sign_audit_batch(tenant_id, entries) -> SignedAuditBatch
  .encrypt_for_export(tenant_id, key_id, plaintext) -> EncryptedExport
    // rejects Ed25519 keys (signing only, not encryption)
```

### rcgen 0.13 API Quirks (verified from ca.rs + cert.rs source)

These are the actual API calls in the production code — tests must use the same patterns:

```rust
// Source: crates/axiam-pki/src/ca.rs:68-78 (VERIFIED)
let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;  // Ed25519
// OR: KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?;      // RSA-4096
let mut params = CertificateParams::new(Vec::<String>::new())?; // NOT params.key_pair = ...
params.distinguished_name.push(DnType::CommonName, "Test CA");
params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
params.not_before = time::OffsetDateTime::from_unix_timestamp(ts)?; // time crate, NOT rcgen type
params.not_after = time::OffsetDateTime::from_unix_timestamp(ts)?;
let cert = params.self_signed(&key_pair)?;  // pass key_pair separately

// Leaf cert signed by CA (Source: cert.rs:129-132):
let ca_certificate = ca_params.self_signed(&ca_key_pair)?; // reconstruct CA cert for signing
let cert = ee_params.signed_by(&ee_key_pair, &ca_certificate, &ca_key_pair)?;
```

Key quirk confirmed: `CertificateParams` has no `key_pair` field; pass key_pair to `self_signed()` or `signed_by()`. [VERIFIED: crates/axiam-pki/src/ca.rs:77]

### pgp 0.19 API Quirks (verified from pgp.rs source)

```rust
// Source: crates/axiam-pki/src/pgp.rs:210-228 (VERIFIED)
use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::{KeyDetails, KeyVersion, Password};
use rand_core::OsRng;  // rand_core 0.6 OsRng, NOT rand 0.9

let key_type = KeyType::Ed25519Legacy;  // signing only
// OR: KeyType::Rsa(4096);              // encryption capable

let params = SecretKeyParamsBuilder::default()
    .key_type(key_type)
    .can_certify(true).can_sign(true)
    .primary_user_id("Name <email>".into())
    ...
    .build()?;

let secret_key: SignedSecretKey = params.generate(OsRng)?;  // direct — no separate sign step

// Signing (Source: pgp.rs:135-141):
let mut msg_builder = MessageBuilder::from_bytes("label", data_vec);
msg_builder.sign(&secret_key.primary_key, Password::default(), HashAlgorithm::Sha256);
let armored = msg_builder.to_armored_string(OsRng, ArmorOptions::default())?;

// Verify (not shown in production code — tests must implement):
// Use pgp::composed::Deserializable + SignedSecretKey::from_string() to parse back
// Use pgp::composed::Message::from_string() to parse the signed message
// Verify with the public key via pgp::types::PublicKeyTrait / Message::verify()

// Encryption (Source: pgp.rs:183-191):
let mut builder = MessageBuilder::from_bytes("export.bin", plaintext_vec)
    .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
builder.encrypt_to_key(OsRng, &public_key)?;
let ciphertext = builder.to_armored_string(OsRng, ArmorOptions::default())?;
```

Key quirk: `Ed25519Legacy` is SIGNING ONLY — `pgp.rs:173` explicitly rejects it for encryption with a `Validation` error. [VERIFIED: crates/axiam-pki/src/pgp.rs:173]

### Test Mock Repositories

The PKI services all take generic repository params. For unit tests, use simple in-memory implementations (or the real Surreal Mem repos). Pattern from `authz_engine_test.rs`:

```rust
// Simplest approach: use SurrealCaCertificateRepository with Mem backend
// (same as rest of the test suite — avoids custom mock boilerplate)
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use axiam_db::repository::{SurrealCaCertificateRepository, SurrealCertificateRepository, ...};
```

Tests for **reject cases** (expired cert, wrong CA) must synthesize conditions:
- For expired cert: call `generate()` with `validity_days = 1`, then `time::sleep` OR directly create a `StoreCertificate` row with `not_after` in the past via repo methods.
- For wrong-CA scenario in `DeviceAuthService::authenticate`: register cert in DB with one CA, present a cert signed by a different CA. The fingerprint lookup will fail (no matching row) → should return `NotFound` error — verify this is the `Certificate` or `NotFound` error variant.

---

## Research Target 4: Frontend E2E Reconciliation (D-11, D-13, D-14)

### Why All 11 Specs Are Wrong

Every spec uses `sessionStorage.setItem("axiam-auth", JSON.stringify({state: {accessToken: ...}}))` to fake authentication. Example from `federation.spec.ts:53-68`:

```typescript
// Source: frontend/e2e/federation.spec.ts:53-68 (VERIFIED — THIS IS THE BUG)
async function mockAuth(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const fakeState = {
      state: { accessToken: "fake-jwt-token", isAuthenticated: true, ... },
      version: 0,
    };
    sessionStorage.setItem("axiam-auth", JSON.stringify(fakeState));
  });
}
```

Phase 1 (D-01) migrated auth to httpOnly cookies. The Zustand auth store no longer reads from sessionStorage; the backend sets `Set-Cookie: axiam_access=...; HttpOnly; SameSite=Strict`. The mock above has no effect — the app will redirect unauthenticated to `/login`.

Additionally, all data assertions are against mocked route handlers (`page.route("**/api/v1/...")`), not a live backend. D-13 requires live backend.

### Rewrite Strategy

**Login helper (replaces mockAuth):**

```typescript
// Pattern for frontend/e2e/helpers/auth.ts (new file)
import { Page } from '@playwright/test';

export async function loginAsAdmin(page: Page): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Organization slug').fill(process.env.E2E_ORG_SLUG ?? 'test-org');
  await page.getByLabel('Tenant slug').fill(process.env.E2E_TENANT_SLUG ?? 'default');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Username or email').fill(process.env.E2E_ADMIN_EMAIL ?? 'admin@axiam.dev');
  await page.getByLabel('Password').fill(process.env.E2E_ADMIN_PASSWORD ?? 'test-admin-pass');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.waitForURL(/\/dashboard|\/$/);  // wait for redirect post-login
}
```

**Cookie-based auth assertion (NOT storage):**

```typescript
// Instead of checking sessionStorage — assert UI state that only appears when authed
await expect(page.getByRole('navigation')).toBeVisible();  // nav only shown when authed
// OR: verify no redirect to /login
await expect(page).not.toHaveURL(/\/login/);
```

**Federation flow (D-13 — mock external IdP, test AXIAM side):**

The stub IdP pattern mirrors `req5_oidc_e2e.rs` (wiremock at service layer). For E2E, the equivalent is Playwright's `page.route()` intercepting the external IdP redirect and completing the callback URL. The AXIAM server handles the callback; assertions are on AXIAM UI state after successful SSO.

### playwright.config.ts Changes Required

The current config (`frontend/playwright.config.ts`) points `baseURL` to `http://localhost:5173` (Vite dev server) and runs `npm run dev`. For D-13/D-14 CI job, config needs:

```typescript
// Modified playwright.config.ts for CI E2E job:
webServer: {
  command: "npm run preview",         // or omit — CI starts docker-compose separately
  url: "http://localhost:5173",        // or frontend container port
  reuseExistingServer: !process.env.CI,
},
use: {
  baseURL: process.env.E2E_BASE_URL ?? "http://localhost:5173",
  // cookies are httpOnly — trace all requests to diagnose auth failures
  trace: "on-first-retry",
},
```

### CI docker-compose.e2e.yml (new file)

Mirrors `docker-compose.dev.yml` with:
- SurrealDB in-memory (or ephemeral volume for CI)
- `AXIAM__AUTH__COOKIE_SECURE=false` (D-18 from Phase 6)
- A seeded DB via axiam-server admin bootstrap endpoint or startup seed script
- Frontend served from a built `dist/` (not Vite dev mode)

Key env vars for CI:
```yaml
AXIAM__AUTH__COOKIE_SECURE: "false"
AXIAM__BOOTSTRAP_ADMIN_EMAIL: "admin@axiam.dev"
AXIAM__BOOTSTRAP_ADMIN_PASSWORD: "test-admin-pass"
```

### CI Job Structure (D-14)

```yaml
# .github/workflows/ci.yml — new job
e2e:
  name: E2E Tests
  runs-on: ubuntu-latest
  needs: [build]  # or run parallel — planner decides
  steps:
    - uses: actions/checkout@v4
    - name: Start services
      run: docker compose -f docker/docker-compose.e2e.yml up -d --wait
    - name: Build frontend
      working-directory: frontend
      run: npm ci && npm run build
    - name: Run E2E tests
      working-directory: frontend
      run: npx playwright install chromium && npm test
      env:
        CI: true
        E2E_BASE_URL: http://localhost:5173
    - name: Stop services
      if: always()
      run: docker compose -f docker/docker-compose.e2e.yml down
```

---

## Research Target 5: ASVS L2 Control → Evidence Mapping (D-02, D-12)

### V2: Authentication Verification

| Control | Likely Status | Evidence |
|---------|---------------|---------|
| V2.1.1 Passwords ≥ 12 chars | Pass | `axiam-api-rest/src/handlers/user.rs` (check validator) |
| V2.1.2 Passwords ≤ 128 chars max | Pass/Verify | check handler |
| V2.1.12 No password hints | N/A or Pass | login form has no hint field |
| V2.2.1 Anti-automation / rate limiting | Pass | `auth_test.rs` lockout tests; settings_test.rs |
| V2.2.2 Soft lockout after N fails | Pass | Phase 2: lockout_duration_secs=900; `lockout_test.rs` |
| V2.3.1 TOTP/MFA supported | Pass | `mfa_reset_still_revokes.rs`; MFA setup endpoint tested |
| V2.5.1 Default credentials disabled | Pass | bootstrap endpoint disabled after first admin |
| V2.7.x Federation IdP trust | Pass | `req5_oidc_e2e.rs` (verify sig, iss, aud, nonce, alg pinning) |
| V2.8.x TOTP algorithm (RFC 6238) | Verify | `axiam-auth/src/` TOTP impl; check HMAC-SHA1 vs SHA256 |
| V2.9.x Cryptographic authenticators | Verify → mTLS | `device_auth_test.rs`; `axiam-pki/tests/mtls_test.rs` (gap → Phase 7) |

### V3: Session Management

| Control | Likely Status | Evidence |
|---------|---------------|---------|
| V3.1.1 No exposed session tokens | Pass | `auth_test.rs` line ~253: Set-Cookie httpOnly; SameSite; Path assertions |
| V3.2.1 New session on login | Pass | login generates new access token (JWT) + refresh token |
| V3.2.3 Server-side session invalidation | Pass | `req7_session_lifecycle.rs` |
| V3.3.1 Session timeout | Pass | `req7_session_lifecycle.rs` |
| V3.4.1 Cookie attributes (httpOnly, Secure, SameSite) | Pass | `auth_test.rs:253+385` (header string assertions) |
| V3.4.5 CSRF protection | Pass | `auth_test.rs` CSRF double-submit tests |

### V4: Access Control

| Control | Likely Status | Evidence |
|---------|---------------|---------|
| V4.1.1 Default deny | Pass | `middleware_test.rs`; `rbac_test.rs` |
| V4.1.2 Principle of least privilege | Pass | `ROUTE_PERMISSION_MAP ↔ PERMISSION_REGISTRY` parity test |
| V4.1.3 Authorization checked server-side | Pass | AuthzMiddleware wraps all scopes |
| V4.2.1 Directory traversal | N/A | no file serving |
| V4.3.1 Admin interface protection | Pass | bootstrap_test.rs; admin endpoints require RBAC permission |

### V6: Stored Cryptography

| Control | Likely Status | Evidence |
|---------|---------------|---------|
| V6.2.1 No custom crypto | Pass | uses argon2 crate, aes-gcm crate, rcgen, pgp, jsonwebtoken |
| V6.2.2 Algorithm reviewed | Pass | argon2id (OWASP); Ed25519 JWT; AES-256-GCM for secrets |
| V6.2.3 Random number generation | Pass | OsRng used throughout; see pgp.rs, ca.rs |
| V6.2.5 Keys not stored in plaintext | Pass | CA private keys AES-256-GCM encrypted; PGP keys same |
| V6.3.1 Hashing (bcrypt/argon2) | Pass | argon2id — verify parameters in `axiam-auth` |
| V6.4.2 Key rotation | Verify | CA cert rotation flow tested? |

### V7: Error Handling and Logging

| Control | Likely Status | Evidence |
|---------|---------------|---------|
| V7.1.1 No credentials in logs | Verify | grep axiam-auth/axiam-api-rest for `tracing::` with password fields |
| V7.2.1 Audit log for auth events | Pass | `audit_test.rs`; AuditLogEntry written on login/logout |
| V7.2.2 All auth failures logged | Verify | check handlers for audit call on failure path |
| V7.3.1 Log format consistent | Verify | tracing structured output |
| V7.4.1 Error messages don't reveal internals | Verify | check 401/403/500 responses for stack traces |

### V8: Data Protection / GDPR

| Control | Likely Status | Evidence |
|---------|---------------|---------|
| V8.1.1 Sensitive data not cached | Verify | response headers: Cache-Control on auth endpoints |
| V8.2.1 Data at rest encrypted | Pass | CA keys, PGP keys, federation secrets AES-256-GCM |
| V8.3.x GDPR data subject rights | Pass | `gdpr_test.rs` (export + deletion + pseudonymization) |

### V9: Communications Security

| Control | Likely Status | Evidence |
|---------|---------------|---------|
| V9.1.1 TLS 1.2+ enforced | Pass/Cite | production: TLS 1.3 minimum in `design-document.md`; reverse-proxy config |
| V9.1.2 HSTS | Pass | nginx: `Strict-Transport-Security` header (Phase 2) |
| V9.2.1 Certificate validation (federation) | Pass | `req5_oidc_e2e.rs` JWKS verify + SAML XML signature |

### V10: Malicious Code (Phase 6 supply-chain evidence)

| Control | Likely Status | Evidence |
|---------|---------------|---------|
| V10.1.1 No malicious code | Pass | cargo-audit + cargo-deny in CI; `ci.yml:81-89` |
| V10.2.1 Dependency integrity | Pass | cargo-audit advisories scan; trivy FS scan; `ci.yml:116` |
| V10.3.1 Frontend asset integrity | Pass | SRI SHA-384 hashes in `dist/index.html` (Phase 6 D-17) |
| V10.3.2 No eval() / dynamic code | Verify | vite.config.ts `sourcemap: false`; check for eval in frontend |

### V14: Configuration

| Control | Likely Status | Evidence |
|---------|---------------|---------|
| V14.2.1 No default accounts | Pass | bootstrap endpoint disabled after first admin |
| V14.4.1 Security headers | Pass | `security_headers_test.rs` (X-Content-Type-Options, X-Frame-Options, Referrer-Policy) |
| V14.4.2 CSP | Pass | nginx.conf CSP header (Phase 2) |
| V14.5.1 HTTP method allowlist | Verify | Actix route registration vs CORS config |

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| PGP signature verification in tests | Custom verify loop | `pgp::composed::Message::from_string()` + `Message::verify()` | pgp 0.19 trait API handles format variants |
| JWT id_token decode in conformance tests | Custom base64 + JSON | `serde_json::from_slice(&base64_decode(parts[1]))` | JWT is just base64url(header).base64url(payload).sig — no crate needed for decode-only |
| RSA key generation for JWKS mocking | Custom key bytes | `rsa::RsaPrivateKey::new(&mut OsRng, 2048)` (wiremock pattern from `req5_oidc_e2e.rs`) | Already in workspace dev-deps |
| In-process gRPC client boilerplate | raw bytes | Generated stubs via `tonic-prost-build` | Type safety; proto already defined |
| Mock auth for E2E | `sessionStorage.setItem(...)` | Real login flow via Playwright | httpOnly cookies can't be injected via JS |
| Custom ASVS spreadsheet | New tooling | Markdown table (D-12) | Auditor-readable, git-versioned, no extra deps |

---

## Common Pitfalls

### Pitfall 1: Governor Layer in gRPC Tests

**What goes wrong:** Attaching `build_grpc_governor_layer` to the test server causes `SmartIpKeyExtractor` to fail on in-process connections with no real peer IP, producing unexpected 429s or panics.
**Why it happens:** `SmartIpKeyExtractor` reads `x-forwarded-for` / `x-real-ip` from gRPC metadata headers; in-process calls don't set these.
**How to avoid:** Build the test server with `Server::builder().add_service(...)` — no governor layer. Test rate limiting separately at the config level.
**Warning signs:** Tests fail with `Status::resource_exhausted` (HTTP 429 equivalent) immediately on first call.

### Pitfall 2: build_client(false) — No Generated Client Stubs

**What goes wrong:** Tests import `axiam_api_grpc::proto::authorization_service_client::AuthorizationServiceClient` but the type doesn't exist — `build_client(false)` in `build.rs:4` omits client generation.
**Why it happens:** Production crate is server-only; client stubs were intentionally excluded.
**How to avoid:** The test crate's `build.rs` must call `build_client(true)`. Or add a `client` feature to `axiam-api-grpc` and gate client generation on it. Either way, client code is only compiled for tests.
**Warning signs:** `cannot find type 'AuthorizationServiceClient'` at compile time.

### Pitfall 3: sessionStorage Auth in Playwright

**What goes wrong:** Specs call `sessionStorage.setItem("axiam-auth", ...)` but the app ignores sessionStorage after Phase 1. All specs that use `mockAuth()` end up on the unauthenticated redirect path.
**Why it happens:** Stale tests from before httpOnly cookie migration.
**How to avoid:** Rewrite to drive real login via the UI; assert on UI state / network, not storage.
**Warning signs:** Every spec that calls `mockAuth()` then `page.goto('/dashboard')` immediately redirects to `/login`.

### Pitfall 4: `--no-default-features` SAML Failures as False Regressions

**What goes wrong:** Developer runs tests locally with `--no-default-features` (Arch build), sees 3 failures (saml_acs, saml_authn, saml_metadata), treats them as regressions introduced by Phase 7 work.
**Why it happens:** These 3 failures are accepted baseline (D-06, `STATE.md:Blockers`). `just test` (default features) is the green bar.
**How to avoid:** Document clearly in `docs/compliance/FINDINGS.md` or a test README that these 3 are pre-existing. CI `build-no-saml` job is `cargo check` only, not `--tests`.
**Warning signs:** CI shows 3 failures on `build-no-saml` job — this is expected and not a gate failure.

### Pitfall 5: rcgen CertificateParams Key Pair Syntax

**What goes wrong:** `params.key_pair = Some(key_pair)` — compile error in rcgen 0.13 (field doesn't exist).
**Why it happens:** rcgen 0.12 had `key_pair` field; 0.13 removed it.
**How to avoid:** `params.self_signed(&key_pair)` — pass key_pair as argument. [VERIFIED: ca.rs:77]

### Pitfall 6: Ed25519Legacy for Encryption

**What goes wrong:** Test tries to call `pgp_service.encrypt_for_export(..., ed25519_key_id, ...)` — returns `Validation` error.
**Why it happens:** `pgp.rs:173` explicitly checks and rejects Ed25519 for encryption. Ed25519Legacy is signing only.
**How to avoid:** Generate `PgpKeyAlgorithm::Rsa4096` for export/encryption tests. [VERIFIED: pgp.rs:173]

### Pitfall 7: SurrealDB Multi-Statement Transaction Slot Offset

**What goes wrong:** `.take(0)` on a transaction result returns the `BEGIN` statement (empty), not the first real statement.
**Why it happens:** `BEGIN TRANSACTION` occupies result slot 0; first statement is slot 1. [VERIFIED: MEMORY.md]
**How to avoid:** Use `.take(1)` for the first statement's result. PKI tests using raw SurrealDB queries in fixtures must account for this.

### Pitfall 8: OIDC Conformance alg:none Already Covered at Service Layer

**What goes wrong:** Planner adds a new HTTP-level test for `alg:none` rejection but the existing service-layer test (`req5_oidc_e2e.rs::oidc_rejects_alg_none`) is already cited as evidence.
**Why it happens:** D-08 places conformance tests in `axiam-api-rest/tests/` but the existing alg:none test is in `axiam-server/tests/`. Both can be cited as evidence; a duplicate at HTTP layer is only needed if the HTTP handler has a separate code path.
**How to avoid:** Check whether `/oauth2/token` with an OIDC flow calls `OidcFederationService::verify_id_token` — if yes, cite the service test. If the handler has its own algorithm check, add an HTTP-level test.

---

## Runtime State Inventory

This is a verification/test-closure phase with no rename/refactor. No runtime state changes are introduced. Skipped.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| protobuf-compiler | axiam-api-grpc build.rs | ✓ (CI installs) | — | CI: `apt-get install protobuf-compiler` (already in ci.yml:197) |
| Docker | E2E CI job (docker-compose) | ✓ (GitHub Actions runner) | 24+ | — |
| libxmlsec1-dev | SAML-ON build | ✓ in CI (security-scan job) | — | `--no-default-features` (local) |
| @playwright/test | E2E specs | ✓ | ^1.58.2 | — |
| Chromium (Playwright) | E2E specs | requires `playwright install chromium` | — | CI: `npx playwright install chromium` |
| slopcheck | Package legitimacy audit | ✓ (pre-installed) | — | N/A |

**Missing with no fallback:** None — all dependencies are available or installable.

**Note:** The E2E CI job requires `npx playwright install chromium` before running tests (Playwright browsers are not pre-installed on GitHub Actions runners).

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | actix-rt + #[actix_web::test] (Rust); @playwright/test 1.58.2 (Frontend) |
| Config file | N/A for Rust; `frontend/playwright.config.ts` |
| Quick run (single crate) | `cargo test -p axiam-pki` / `cargo test -p axiam-api-grpc` |
| Full suite | `just test` (default features) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Command | File |
|--------|----------|-----------|---------|------|
| REQ-11 (T19.1) | gRPC authz check_access: allow + deny | integration | `cargo test -p axiam-api-grpc grpc_authz` | `crates/axiam-api-grpc/tests/grpc_authz_test.rs` — Wave 0 gap |
| REQ-11 (T19.2) | gRPC batch + concurrent authz | integration | `cargo test -p axiam-api-grpc grpc_batch` | same or separate file — Wave 0 gap |
| REQ-11 (AC-3) | PKI: CA gen + cert sign + mTLS reject | integration | `cargo test -p axiam-pki` | `crates/axiam-pki/tests/{ca,cert,mtls,pgp}_test.rs` — Wave 0 gap |
| REQ-11 (D-07) | OAuth2 RFC MUST matrix conformance | integration | `cargo test -p axiam-api-rest oauth2_conformance` | `crates/axiam-api-rest/tests/oauth2_conformance.rs` — Wave 0 gap |
| REQ-11 (D-07) | OIDC Core MUST matrix conformance | integration | `cargo test -p axiam-api-rest oidc_conformance` | `crates/axiam-api-rest/tests/oidc_conformance.rs` — Wave 0 gap |
| REQ-11 (AC-5) | Frontend E2E: login + RBAC + federation | e2e | `cd frontend && npm test` | `frontend/e2e/*.spec.ts` — all 11 rewrite required |
| D-01 | ASVS L2 checklist completeness | manual/doc | review `docs/compliance/asvs-l2-checklist.md` | `docs/compliance/asvs-l2-checklist.md` — Wave 0 gap |

### Sampling Rate

- Per task commit: `cargo test -p <affected-crate>` (per-crate, never `--workspace` locally)
- Per wave merge: `just test` (full suite, default features)
- Phase gate: `just test` green + `cd frontend && npm test` green + docs/compliance/ complete

### Wave 0 Gaps

- [ ] `crates/axiam-api-grpc/tests/grpc_authz_test.rs` — covers T19.1, T19.2
- [ ] `crates/axiam-api-grpc/tests/build.rs` (or feature flag) — client stub generation
- [ ] `crates/axiam-pki/tests/ca_test.rs` — covers D-09 CA path
- [ ] `crates/axiam-pki/tests/cert_test.rs` — covers D-09 leaf cert path
- [ ] `crates/axiam-pki/tests/mtls_test.rs` — covers D-09 mTLS reject cases
- [ ] `crates/axiam-pki/tests/pgp_test.rs` — covers D-09 PGP sign+verify
- [ ] `crates/axiam-api-rest/tests/oauth2_conformance.rs` — RFC 6749/7636 MUST gaps
- [ ] `crates/axiam-api-rest/tests/oidc_conformance.rs` — OIDC Core MUST gaps
- [ ] `docs/compliance/asvs-l2-checklist.md` — D-12 per-control rows
- [ ] `docs/compliance/oauth2-rfc-compliance.md` — D-01 MUST matrix
- [ ] `docs/compliance/oidc-conformance.md` — D-01 MUST matrix
- [ ] `docs/compliance/FINDINGS.md` — D-05 deferred findings register
- [ ] `frontend/e2e/helpers/auth.ts` — shared login helper
- [ ] `docker/docker-compose.e2e.yml` — CI E2E service config
- [ ] `.github/workflows/ci.yml` — E2E job addition (D-14)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | argon2id, TOTP, lockout, federation verify |
| V3 Session Management | yes | httpOnly cookies, refresh rotation, `req7_session_lifecycle.rs` |
| V4 Access Control | yes | AuthzMiddleware, RBAC, `rbac_test.rs` |
| V5 Input Validation | no (out of scope per D-02) | — |
| V6 Stored Cryptography | yes | AES-256-GCM, Ed25519, argon2id — never hand-rolled |
| V7 Errors & Logging | yes | AuditLogEntry, no credentials in logs |
| V8 Data Protection | yes | `gdpr_test.rs`, AES-256-GCM at rest |
| V9 Communications | yes | TLS 1.3, HSTS, cert validation |
| V10 Malicious Code | yes | cargo-audit, cargo-deny, trivy, SRI (Phase 6) |
| V11 Business Logic | no (out of scope per D-02) | — |
| V12 File Upload | no (out of scope per D-02) | — |
| V13 API | no (out of scope per D-02) | — |
| V14 Configuration | yes | security headers, CSP, HSTS, admin bootstrap |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Token storage XSS | Spoofing | httpOnly cookies (Phase 1 — verified) |
| PKCE downgrade (plain method) | Tampering | S256-only enforcement — MUST test in conformance suite |
| OAuth2 code replay | Repudiation | Single-use codes — `auth_code_is_single_use` (verified) |
| OIDC alg:none bypass | Elevation | Algorithm pinning — `req5_oidc_e2e.rs::oidc_rejects_alg_none` (verified) |
| Brute-force credential attack | DoS | Account lockout after N fails — `settings_test.rs:250` (verified) |
| CA private key exposure | Information Disclosure | AES-256-GCM encryption at rest — `ca.rs:84` (verified) |
| PGP key for wrong purpose | Tampering | Ed25519 encryption rejection — `pgp.rs:173` (verified) |
| Dependency confusion / supply chain | Tampering | cargo-audit + cargo-deny + trivy in CI — `ci.yml:81-89` (verified) |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Tonic 0.14 `serve_with_incoming_shutdown(TcpListenerStream)` is the correct in-process idiom; `tokio_stream::wrappers::TcpListenerStream` is available | Research Target 1 | API may differ; check tonic 0.14 release notes; fallback: `serve_with_shutdown` + fixed ephemeral port |
| A2 | `build_client(true)` via feature flag approach works for test-only client generation in tonic-prost-build 0.14 | Research Target 1 | May need standalone test crate with own build.rs instead |
| A3 | `code_challenge_method=plain` is not accepted (SHOULD reject per RFC 7636 §4.2 security considerations) | Research Target 2 | AXIAM may accept `plain` — test result will determine whether this is a finding or N/A |
| A4 | `WWW-Authenticate` header is not currently set on 401 responses from `/oauth2/token` | Research Target 2 | May already be present — test first; if absent it's a D-04 inline fix |
| A5 | The mocked IdP for E2E federation uses `page.route()` to intercept IdP redirect and simulate callback | Research Target 4 | May need a lightweight wiremock HTTP server container instead |

---

## Open Questions (RESOLVED)

1. **gRPC client stub approach — feature flag vs separate crate**
   - What we know: `build_client(false)` in production; tests need client stubs
   - What's unclear: Whether tonic-prost-build 0.14 supports feature-conditional client generation
   - Recommendation: Planner should prototype the feature-flag approach first; fall back to raw-message approach if blocked
   - **RESOLVED:** Feature-flag approach. `build.rs` sets `build_client(std::env::var("CARGO_FEATURE_CLIENT").is_ok())` behind a new `client` feature; tests run `--features client`. This is the chosen path in Plan 03 Task 1. Fallback (separate `axiam-api-grpc-tests` crate with its own `build.rs`) stays documented in Plan 03 Task 1 if A2 (tonic-prost-build honoring `CARGO_FEATURE_CLIENT`) proves false at execution.

2. **DeviceAuthService reject cases — how to simulate expired cert in tests**
   - What we know: `DeviceAuthService::authenticate` checks `cert.not_after > now`
   - What's unclear: Whether test repos support inserting certs with arbitrary `not_after` values
   - Recommendation: Use `SurrealCertificateRepository::create(StoreCertificate {..., not_after: Utc::now() - Duration::days(1)})` — Surreal Mem has no datetime validation
   - **RESOLVED:** Use `SurrealCertificateRepository::create(StoreCertificate { ..., not_after: Utc::now() - Duration::days(1) })`. Surreal Mem does no datetime validation, so a past `not_after` is accepted at insert and `DeviceAuthService::authenticate` exercises the expired-cert reject path when it re-checks `not_after > now`. This is the expired-cert fixture for the mTLS reject case in Plan 01.

3. **OIDC alg:none at HTTP layer vs service layer**
   - What we know: Service layer (`req5_oidc_e2e.rs`) already tests alg:none rejection
   - What's unclear: Whether the HTTP `/oauth2/token` endpoint with OIDC scope also exercises this path
   - Recommendation: Cite service test as evidence; add HTTP test only if a separate code path exists
   - **RESOLVED:** Cite the existing service-layer test `crates/axiam-server/tests/req5_oidc_e2e.rs::oidc_rejects_alg_none` as the alg:none evidence. Source inspection of `crates/axiam-api-rest/src/handlers/oauth2.rs` confirms `/oauth2/token` issues AXIAM-signed tokens and has NO separate external-`id_token` algorithm-verification code path, so no duplicate HTTP-layer alg:none test is added. Add an HTTP-layer test ONLY if a distinct `/oauth2/token` OIDC code path is later introduced.

4. **Frontend seeded DB — bootstrap vs migration script**
   - What we know: `AXIAM__BOOTSTRAP_ADMIN_EMAIL` env var seeds first admin
   - What's unclear: Whether RBAC fixtures (roles, permissions) auto-seed or require explicit test setup
   - Recommendation: Check `axiam-server/src/startup.rs` for seed logic; if roles/permissions don't auto-seed, add a CI fixture script
   - **RESOLVED:** A CI fixture script is required. Source inspection (`crates/axiam-server/src/main.rs:240-280`) shows `axiam_db::seed_permissions` runs ONLY for orgs/tenants that already exist; a fresh Mem DB has none, and there is NO env-driven auto-bootstrap (no `AXIAM__BOOTSTRAP_ADMIN_EMAIL` consumer in `main.rs`/config). The org+tenant+admin+`super-admin` role (full permissions) is created ONLY by an HTTP POST to `/api/v1/admin/bootstrap` (`crates/axiam-api-rest/src/handlers/bootstrap.rs:48-168`). So the E2E CI job MUST run a fixture step that POSTs to `/api/v1/admin/bootstrap` (org slug, tenant slug, admin email/password) before Playwright, giving `loginAsAdmin` a real org/tenant/admin with RBAC permissions. NOTE: corrects the earlier assumption that `AXIAM__BOOTSTRAP_ADMIN_EMAIL/PASSWORD` env vars alone seed the admin — they do not.

---

## Sources

### Primary (HIGH confidence — verified from source files)

- `crates/axiam-api-grpc/build.rs` — confirms `build_client(false)`, proto paths
- `crates/axiam-api-grpc/src/server.rs` — `start_grpc_server` generic signature
- `crates/axiam-api-grpc/src/middleware/rate_limit.rs` — `SmartIpKeyExtractor` governor layer
- `crates/axiam-api-grpc/src/services/authorization.rs` — `CheckAccess` + `BatchCheckAccess` impl
- `crates/axiam-pki/src/ca.rs` — `CaService::generate()`, rcgen 0.13 call sites, AES-GCM pattern
- `crates/axiam-pki/src/cert.rs` — `CertService::generate()`, reject cases (inactive CA, expired CA)
- `crates/axiam-pki/src/mtls.rs` — `DeviceAuthService::authenticate()` validation chain
- `crates/axiam-pki/src/pgp.rs` — `PgpService`, pgp 0.19 API calls, Ed25519 encryption rejection at line 173
- `crates/axiam-api-rest/tests/oauth2_flow_test.rs` — 37 existing test functions, PKCE pattern
- `crates/axiam-api-rest/tests/federation_test.rs` — harness pattern
- `crates/axiam-server/tests/req5_oidc_e2e.rs` — wiremock + RSA key pattern, alg:none test
- `crates/axiam-server/Cargo.toml` — dev-dependencies: wiremock 0.6, rsa 0.9, rand_core 0.6
- `crates/axiam-authz/tests/authz_engine_test.rs` — type alias pattern + repo setup
- `frontend/e2e/federation.spec.ts` — confirms sessionStorage bug (line 67)
- `frontend/e2e/login.spec.ts` — confirms stale test patterns
- `frontend/playwright.config.ts` — baseURL, webServer config
- `frontend/package.json` — `@playwright/test ^1.58.2`
- `docker/docker-compose.dev.yml` — `AXIAM__AUTH__COOKIE_SECURE=false` pattern (line 71)
- `.github/workflows/ci.yml` — existing job structure, `RUSTFLAGS: "-Dwarnings"`, `cargo test --workspace`
- `Cargo.toml` (workspace) — tonic 0.14, prost 0.14, tower 0.5, tower_governor 0.8, tokio 1

### Secondary (MEDIUM confidence — cited standard references)

- RFC 6749 §5.2 — error response requirements (MUST matrix)
- RFC 7636 §4.1, §4.2 — PKCE verifier length bounds, S256 requirement
- OIDC Core 1.0 §3.1.3.7, §5.3, Discovery §3 — id_token validation, userinfo, discovery doc required fields
- OWASP ASVS v4.0.x Level 2 — control families V2–V10, V14

### Tertiary (LOW confidence — training knowledge, unverified)

- tonic 0.14 `serve_with_incoming_shutdown` + `TcpListenerStream` idiom [A1]
- tonic-prost-build 0.14 feature-conditional client generation [A2]

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all from workspace Cargo.toml source files
- Architecture (gRPC harness): MEDIUM — tonic 0.14 serve pattern is [ASSUMED]; build.rs approach is HIGH
- PKI tests: HIGH — all from production source; API surface fully visible
- OAuth2/OIDC conformance gaps: HIGH — systematically compared existing test list to RFC MUST items
- E2E reconciliation: HIGH — root cause (sessionStorage) verified from source; Playwright patterns are standard
- ASVS mapping: MEDIUM — cited to test files; some "Verify" items need actual code reading during authoring

**Research date:** 2026-06-07
**Valid until:** 2026-07-07 (stable stack; no fast-moving dependencies)

---

## RESEARCH COMPLETE

**Phase:** 7 - Compliance Verification & Test Closure
**Confidence:** MEDIUM-HIGH overall (HIGH for all code findings; MEDIUM for tonic 0.14 in-process harness pattern)

### Key Findings

1. **gRPC harness is the only genuinely new infrastructure.** `build_client(false)` in `crates/axiam-api-grpc/build.rs:4` — no client stubs exist. Governor middleware must be omitted in tests (SmartIpKeyExtractor requires real peer IP). Planner must decide: feature-flag client generation vs raw-message approach vs separate test crate.

2. **OAuth2/OIDC conformance gap is smaller than it looks.** `oauth2_flow_test.rs` already covers most MUST items (37 tests). New `oauth2_conformance.rs` needs: `plain` method rejection, verifier length bounds, `WWW-Authenticate` header, `token_type=Bearer` assertion, cross-client refresh rejection. `oidc_conformance.rs` needs: discovery doc field completeness check, `none` absent from alg list, issuer cross-match.

3. **axiam-pki API is fully readable and testable directly.** CA, cert, mTLS, PGP services have concrete generic params — use Mem SurrealDB repos. Key landmines: rcgen 0.13 no `params.key_pair` field (verified), Ed25519Legacy not usable for encryption (verified from `pgp.rs:173`).

4. **All 11 E2E specs are broken by the same root cause.** Every spec calls `sessionStorage.setItem("axiam-auth", ...)` (verified: `federation.spec.ts:67`). Phase 1 httpOnly cookies made this ineffective. Rewrite requires a real login helper + live backend. `AXIAM__AUTH__COOKIE_SECURE=false` env already documented in `docker-compose.dev.yml:71`.

5. **ASVS V10 evidence is ready.** cargo-audit, cargo-deny, trivy (fs + config), npm audit, SRI all exist in `ci.yml`. The checklist need only cite `ci.yml` job steps and the Phase 6 `deny.toml` ignore entries.

### File Created

`.planning/phases/07-compliance-verification-test-closure/07-RESEARCH.md`

### Confidence Assessment

| Area | Level | Reason |
|------|-------|--------|
| gRPC harness pattern | MEDIUM | tonic 0.14 serve_with_incoming_shutdown idiom [ASSUMED] |
| gRPC build.rs gap | HIGH | Verified from source file |
| PKI tests | HIGH | All from production source |
| OAuth2/OIDC conformance gaps | HIGH | Systematic comparison of test list vs RFC |
| E2E root cause | HIGH | sessionStorage line verified in source |
| ASVS mapping | MEDIUM | Test file citations verified; some items need code reading |

### Open Questions

- tonic 0.14 in-process harness: feature-flag vs raw-message vs separate crate (A1, A2)
- DeviceAuthService reject-case fixture: how to insert expired cert in Mem DB
- Frontend seeded DB: roles/permissions auto-seed or requires fixture script

### Ready for Planning

Research complete. Planner can now create PLAN.md files.
