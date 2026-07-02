# Phase 15: SDK Foundation — Pattern Map

**Mapped:** 2026-06-29
**Files analyzed:** 16 new/modified files
**Analogs found:** 11 / 16 (5 are genuinely net-new with no codebase analog)

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/axiam-server/src/main.rs` | utility (binary entry) | request-response | `main.rs:106-116` (healthcheck block) | exact |
| `crates/axiam-api-rest/src/handlers/authz_check.rs` | handler | request-response | `handlers/groups.rs` + `axiam-api-grpc/src/services/authorization.rs` | exact (dual analog) |
| `crates/axiam-api-rest/src/openapi.rs` | config | transform | `openapi.rs:15-162` (existing `paths()` list) | exact |
| `crates/axiam-api-rest/src/permissions.rs` | config | CRUD | `permissions.rs:23-177` (PERMISSION_REGISTRY) | exact |
| `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` | test | request-response | `route_openapi_parity_test.rs:34-48` (AUTHENTICATED_SELF_SERVICE_PATHS) | exact |
| `crates/axiam-api-rest/src/config/rate_limit.rs` | config | — | `rate_limit.rs:1-60` (RateLimitConfig) | exact |
| `crates/axiam-api-rest/src/server.rs` | config | request-response | `server.rs:64-215` (scope + resource + `.wrap(build_governor(...))`) | exact |
| `sdks/{rust,…,go}/LICENSE` | config | — | root `LICENSE` file | exact (copy verbatim) |
| `.github/workflows/sdk-openapi-drift.yml` | CI | — | `.github/workflows/ci.yml:59-75` (build-no-saml job) | role-match |
| `.github/workflows/sdk-buf-gates.yml` | CI | — | `.github/workflows/ci.yml:59-75` (build-no-saml job) | role-match |
| `.github/workflows/sdk-ci-{lang}.yml` (×7) | CI | — | `.github/workflows/ci.yml:59-75` (build-no-saml job) | role-match |
| `sdks/buf.yaml` | config | — | none | no analog |
| `sdks/buf.gen.yaml` | config | — | none | no analog |
| `sdks/CONTRACT.md` | documentation | — | none | no analog |
| `sdks/openapi.json` | artifact | — | none (generated) | no analog |
| `.planning/ROADMAP.md` | documentation | — | existing ROADMAP content | exact (string fixup) |

---

## Pattern Assignments

### `crates/axiam-server/src/main.rs` (early-exit branch, ~line 117)

**Analog:** `crates/axiam-server/src/main.rs:106-116`

**Early-exit pattern — copy and extend** (lines 106-116):
```rust
// D-09: healthcheck subcommand — self-probe /health, exit 0 on 2xx, exit 1 otherwise.
// Runs before tracing init and before the async stack to keep the probe lightweight.
{
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("healthcheck") {
        let url = std::env::var("AXIAM_HEALTHCHECK_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8090/health".to_owned());
        let ok = reqwest::blocking::get(&url)
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        std::process::exit(if ok { 0 } else { 1 });
    }
}
```

**New `--dump-openapi` block to insert immediately after line 116** (before `tracing_subscriber::fmt()` at line 121):
```rust
// FND-01: dump OpenAPI spec to stdout without DB/AMQP — usable in CI.
// Must run before tracing init and before load_config() to avoid DB connection.
{
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--dump-openapi") {
        let json = serde_json::to_string_pretty(&axiam_api_rest::openapi::api_doc())
            .expect("OpenAPI serialization failed");
        println!("{json}");
        std::process::exit(0);
    }
}
```

**Key constraints:**
- `axiam_api_rest::openapi` is `pub mod` (confirmed `lib.rs:11`) — no re-export needed
- `serde_json` is already a direct dep of `axiam-server` (`Cargo.toml:39`)
- Placement: AFTER the healthcheck block (line 116), BEFORE `tracing_subscriber::fmt()` (line 121)
- Use `--no-default-features` when generating `sdks/openapi.json` (SAML excluded for determinism)

---

### `crates/axiam-api-rest/src/handlers/authz_check.rs` (NEW handler)

**Analog A:** `crates/axiam-api-rest/src/handlers/groups.rs` (utoipa annotation + RequirePermission pattern)
**Analog B:** `crates/axiam-api-grpc/src/services/authorization.rs` (check_access + batch_check_access logic)

**Imports pattern** — copy from `handlers/groups.rs:1-14`:
```rust
use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
// Note: also need AccessRequest, AccessDecision from axiam_authz::types
use axiam_authz::types::{AccessDecision, AccessRequest};
```

**Request/response schema pattern** — copy `#[derive(Debug, Deserialize, utoipa::ToSchema)]` from `groups.rs:20-25`:
```rust
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CheckAccessBody {
    pub action: String,
    pub resource_id: Uuid,
    pub scope: Option<String>,
    /// Only accepted from callers holding `authz:check_as` permission.
    pub subject_id: Option<Uuid>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CheckAccessResponse {
    pub allowed: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BatchCheckAccessBody {
    pub checks: Vec<CheckAccessBody>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BatchCheckAccessResponse {
    pub results: Vec<CheckAccessResponse>,
}
```

**utoipa annotation pattern** — copy from `groups.rs:47-56` (POST handler):
```rust
/// `POST /api/v1/authz/check`
#[utoipa::path(
    post,
    path = "/api/v1/authz/check",
    tag = "authz",
    request_body = CheckAccessBody,
    responses(
        (status = 200, description = "Authorization decision", body = CheckAccessResponse),
    ),
    security(("bearer" = []))
)]
pub async fn check_access<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    body: web::Json<CheckAccessBody>,
) -> Result<HttpResponse, AxiamApiError> {
    // ... (see handler logic below)
}
```

**RequirePermission conditional check pattern** — copy from `authz.rs:91-112` + `groups.rs:63-65`:
```rust
// groups.rs:63-65 — unconditional required permission pattern:
RequirePermission::new("groups:create", Uuid::nil())
    .check(&user, authz.get_ref().as_ref())
    .await?;

// For authz_check.rs — conditional (only when subject_id override is requested):
let effective_subject_id = if let Some(sid) = body.subject_id {
    RequirePermission::new("authz:check_as", user.tenant_id)
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // D-06: audit cross-subject queries here
    sid
} else {
    user.user_id
};
```

**AccessDecision mapping pattern** — copy from `authorization.rs:47-57`:
```rust
// gRPC analog (authorization.rs:47-57):
fn to_check_response(decision: AccessDecision) -> CheckAccessResponse {
    match decision {
        AccessDecision::Allow => CheckAccessResponse {
            allowed: true,
            deny_reason: String::new(),  // gRPC uses String; REST uses Option<String>
        },
        AccessDecision::Deny(reason) => CheckAccessResponse {
            allowed: false,
            deny_reason: reason,
        },
    }
}

// REST version uses Option<String> for reason (cleaner JSON):
fn decision_to_response(decision: AccessDecision) -> CheckAccessResponse {
    match decision {
        AccessDecision::Allow => CheckAccessResponse { allowed: true, reason: None },
        AccessDecision::Deny(reason) => CheckAccessResponse { allowed: false, reason: Some(reason) },
    }
}
```

**Batch loop pattern** — copy from `authorization.rs:118-168`:
```rust
// authorization.rs:133-166 — batch loop iterating check_req items:
let mut results = Vec::with_capacity(req.requests.len());
for check_req in req.requests {
    let access_req = AccessRequest {
        tenant_id: claims_tenant_id,
        subject_id: claims_subject_id,
        action: check_req.action,
        resource_id: parse_uuid(&check_req.resource_id, "resource_id")?,
        scope: check_req.scope,
    };
    let decision = self.engine.check_access(&access_req).await
        .map_err(|e| Status::internal(e.to_string()))?;
    results.push(to_check_response(decision));
}
// REST version: iterate body.checks, build AccessRequest per item, collect results
```

**Error handling** — `Result<HttpResponse, AxiamApiError>` propagates via `?`; `AxiamApiError` converts from `AxiamError::AuthorizationDenied` (returns HTTP 403). Pattern from `authz.rs:104-111`.

---

### `crates/axiam-api-rest/src/openapi.rs` (extend paths list)

**Analog:** `crates/axiam-api-rest/src/openapi.rs:15-162`

**Paths list pattern** (lines 15-30, add to this block):
```rust
#[openapi(
    paths(
        // ... existing handlers ...
        // Add after existing paths:
        handlers::authz_check::check_access,
        handlers::authz_check::batch_check_access,
    ),
```

**Where to add:** After the last existing `handlers::` path entry in the `paths()` macro (currently ends around line 162 before the `// SAML SP paths` comment at line 163).

---

### `crates/axiam-api-rest/src/permissions.rs` (add PERMISSION_REGISTRY entry)

**Analog:** `crates/axiam-api-rest/src/permissions.rs:23-177` (PERMISSION_REGISTRY slice)

**Entry format pattern** (lines 26-33, multi-line form for long descriptions):
```rust
// Single-line entries (short description):
("users:list", "List users in the tenant"),

// Multi-line entries (long description):
(
    "users:admin",
    "Perform administrative user actions (unlock, reset MFA)",
),
```

**New entry to append before line 177** (closing `];`):
```rust
    // Authz check-as override (FND-04, D-06)
    (
        "authz:check_as",
        "Perform an authorization check on behalf of another subject (admin override)",
    ),
```

**Auto-grant behavior:** `reconcile_default_role_grants` at `main.rs:273-289` runs on every startup and back-fills new PERMISSION_REGISTRY entries to the default admin role for all existing tenants. No manual SQL grant needed.

---

### `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` (extend AUTHENTICATED_SELF_SERVICE_PATHS)

**Analog:** `route_openapi_parity_test.rs:34-48`

**Constant pattern** (lines 34-48):
```rust
const AUTHENTICATED_SELF_SERVICE_PATHS: &[&str] = &[
    // Auth — session-guarded but no discrete permission needed
    "/api/v1/auth/logout",
    "/api/v1/auth/me",
    // ... existing entries ...
    "/api/v1/federation/saml/authn-request",
];
```

**New entries to add** (append before the closing `];`):
```rust
    // Authz check — JWT-authenticated; authz:check_as check is conditional
    // inside the handler (not a route-level gate), so these paths are not
    // in ROUTE_PERMISSION_MAP.
    "/api/v1/authz/check",
    "/api/v1/authz/check/batch",
```

**Why self-service (not ROUTE_PERMISSION_MAP):** The `authz:check_as` permission check is conditional inside the handler (only when `subject_id` override is present). The default self-check case requires only authentication. Adding to ROUTE_PERMISSION_MAP would imply every caller needs `authz:check_as`, which is wrong.

---

### `crates/axiam-api-rest/src/config/rate_limit.rs` (add authz_check_per_min)

**Analog:** `rate_limit.rs:1-60` (full file — 60 lines)

**Struct field pattern** (lines 9-27):
```rust
pub struct RateLimitConfig {
    /// Max login requests per minute per IP (default: 10).
    pub login_per_min: u32,
    // ... existing fields ...
    /// Max oauth2/revoke requests per minute per IP (default: 10).
    pub revoke_per_min: u32,
}
```

**New field to append after `revoke_per_min`:**
```rust
    /// Max authz-check requests per minute per IP (default: 300).
    /// Authz checks are read-only and high-frequency — used by UI permission gating.
    /// Kept in a dedicated bucket so heavy UI use does not consume the login/token limit.
    pub authz_check_per_min: u32,
```

**Default impl pattern** (lines 29-41):
```rust
impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_per_min: 10,
            // ... existing defaults ...
            revoke_per_min: 10,
            authz_check_per_min: 300,  // add here
        }
    }
}
```

**Validate impl pattern** (lines 43-59):
```rust
impl RateLimitConfig {
    pub fn validate(&self) {
        assert!(self.login_per_min >= 1, "login_per_min must be >= 1");
        // ... existing asserts ...
        assert!(self.revoke_per_min >= 1, "revoke_per_min must be >= 1");
        assert!(self.authz_check_per_min >= 1, "authz_check_per_min must be >= 1");  // add here
    }
}
```

---

### `crates/axiam-api-rest/src/server.rs` (register authz routes)

**Analog:** `crates/axiam-api-rest/src/server.rs:64-215`

**Rate-limit wrapping pattern** — all existing governor wraps are on `web::resource`, not `web::scope`. Copy the per-resource pattern:
```rust
// Existing pattern (server.rs:68-71):
.service(
    web::resource("/login")
        .wrap(build_governor(rate_limit_cfg.login_per_min))
        .route(web::post().to(handlers::auth::login::<C>)),
)
```

**New authz scope registration** — add to `register_api_v1_routes` in `api_scope` block (after existing `.service(...)` registrations):
```rust
// FND-04: authz-check routes — dedicated higher rate-limit tier (D-07)
.service(
    web::resource("/authz/check")
        .wrap(build_governor(rate_limit_cfg.authz_check_per_min))
        .route(web::post().to(handlers::authz_check::check_access::<C>)),
)
.service(
    web::resource("/authz/check/batch")
        .wrap(build_governor(rate_limit_cfg.authz_check_per_min))
        .route(web::post().to(handlers::authz_check::batch_check_access::<C>)),
)
```

**Note:** `AuthzMiddleware` and `CsrfMiddleware` are already wrapped on `/api/v1` scope (line 217-218), so the authz-check resources inherit them automatically — do not add them again.

---

### `sdks/{rust,typescript,python,java,csharp,php,go}/LICENSE` (7 files, NEW)

**Analog:** repo-root `LICENSE` (Apache-2.0; resolve via `git rev-parse --show-toplevel`)

**Pattern:** Copy the root `LICENSE` file verbatim into each `sdks/<lang>/LICENSE`. Do NOT copy from `Cargo.toml` license field (known wrong — project memory `project_license_apache.md`).

---

### `.github/workflows/sdk-openapi-drift.yml` (NEW CI workflow)

**Analog:** `.github/workflows/ci.yml:59-75` (build-no-saml job)

**Path-filter trigger pattern** (ci.yml lines 3-6):
```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
```

**New trigger with path filter** (copy structure, add `paths:`):
```yaml
on:
  pull_request:
    branches: [main]
    paths:
      - 'crates/axiam-api-rest/**'
      - 'crates/axiam-server/**'
  push:
    branches: [main]
    paths:
      - 'crates/axiam-api-rest/**'
      - 'crates/axiam-server/**'
```

**build-no-saml job step pattern** (ci.yml lines 59-75) — reuse for the Rust build step:
```yaml
build-no-saml:
  name: Build (SAML off / --no-default-features)
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
    - uses: dtolnay/rust-toolchain@3c5f7ea28cd621ae0bf5283f0e981fb97b8a7af9  # stable (2026-03-27)
      with:
        toolchain: stable
    - uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6  # v2.7.8
    - run: sudo apt-get update && sudo apt-get install -y protobuf-compiler
    - run: cargo check -p axiam-federation -p axiam-api-rest -p axiam-server --no-default-features
```

**Drift gate steps** — after the build step, add:
```yaml
    - name: Build axiam-server (no-saml)
      run: cargo build -p axiam-server --no-default-features
    - name: Export OpenAPI spec
      run: ./target/debug/axiam-server --dump-openapi > /tmp/openapi-fresh.json
    - name: Check drift
      run: diff sdks/openapi.json /tmp/openapi-fresh.json
```

**Pinned Action SHAs:** Copy SHA-pinned `uses:` lines verbatim from ci.yml. Never use floating tags like `@v4`. Match the existing pinned SHAs for `actions/checkout`, `dtolnay/rust-toolchain`, `Swatinem/rust-cache`.

---

### `.github/workflows/sdk-buf-gates.yml` (NEW CI workflow)

**Analog:** `.github/workflows/ci.yml:59-75` structure (path filter + minimal steps)

**Path filter:**
```yaml
on:
  pull_request:
    branches: [main]
    paths:
      - 'proto/**'
      - 'sdks/buf.yaml'
      - 'sdks/buf.gen.yaml'
```

**buf action** — no existing codebase analog; see buf.build documentation for `bufbuild/buf-action`. Add a `checkpoint:human-verify` note in the plan: verify the exact GitHub Action SHA/tag before locking.

---

### `.github/workflows/sdk-ci-{lang}.yml` (×7, NEW stub CI workflows)

**Analog:** `.github/workflows/ci.yml:59-75` (build-no-saml job — minimal checkout + install + command pattern)

**Per-SDK path filter pattern:**
```yaml
on:
  pull_request:
    branches: [main]
    paths:
      - 'sdks/rust/**'         # change per SDK
      - 'sdks/openapi.json'
      - 'sdks/buf.yaml'
      - 'sdks/buf.gen.yaml'
```

**Phase-15 stub job content** (verify scaffold only — actual build/test steps added per-SDK in Phases 16-22):
```yaml
jobs:
  scaffold-check:
    name: SDK Scaffold Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - name: Verify LICENSE file
        run: test -f sdks/rust/LICENSE  # change path per SDK
```

**Pinned SHAs:** Use the same `actions/checkout` SHA as ci.yml (`11bd71901bbe5b1630ceea73d27597364c9af683`).

---

## Shared Patterns

### Authentication / Identity extraction
**Source:** `crates/axiam-api-rest/src/extractors/auth.rs` (via `AuthenticatedUser`)
**Apply to:** `handlers/authz_check.rs`
```rust
// Pattern from groups.rs:57-58 — AuthenticatedUser is an Actix extractor:
pub async fn create<C: Connection>(
    user: AuthenticatedUser,   // JWT claims extracted here; 401 if missing
    authz: AuthzData,          // Arc<dyn AuthzChecker> from app data
    ...
)
// user.tenant_id and user.user_id are the ONLY authoritative identity sources
// Never use body fields for identity (gRPC cross-validates and rejects; REST handler ignores body identity fields entirely)
```

### Authorization guard
**Source:** `crates/axiam-api-rest/src/authz.rs:67-112`
**Apply to:** `handlers/authz_check.rs` (conditional check for subject_id override)
```rust
// RequirePermission::new(action, resource_id).check(&user, authz.get_ref().as_ref()).await?
// Returns Ok(()) on Allow, Err(AxiamApiError) with HTTP 403 on Deny
// Use user.tenant_id as resource_id for global admin permissions (is_global=true roles satisfy any resource_id)
RequirePermission::new("authz:check_as", user.tenant_id)
    .check(&user, authz.get_ref().as_ref())
    .await?;
```

### Error handling
**Source:** `crates/axiam-api-rest/src/handlers/groups.rs` (all handlers)
**Apply to:** all new handlers
```rust
// All handlers return Result<HttpResponse, AxiamApiError>
// Use ? for error propagation — AxiamApiError implements From<AxiamError> and From<DbError>
// No explicit match/catch needed at handler level
pub async fn check_access<C: Connection>(...) -> Result<HttpResponse, AxiamApiError> {
    // errors propagate via ?
    Ok(HttpResponse::Ok().json(response))
}
```

### utoipa annotation (all REST handlers)
**Source:** `crates/axiam-api-rest/src/handlers/groups.rs:47-56`
**Apply to:** both handlers in `authz_check.rs`
```rust
#[utoipa::path(
    post,
    path = "/api/v1/...",
    tag = "...",
    request_body = BodyType,
    responses(
        (status = 200, description = "...", body = ResponseType),
    ),
    security(("bearer" = []))
)]
```
Every handler that returns data in the `paths()` macro of `openapi.rs` must have this annotation. Missing annotation → Test A failure.

### Rate-limit governor
**Source:** `crates/axiam-api-rest/src/server.rs:24-38` (`build_governor` function)
**Apply to:** authz-check resource registrations in `server.rs`
```rust
// build_governor(requests_per_min) creates an independent in-memory store
// Always wrap web::resource, not web::scope — existing convention in this codebase
.service(
    web::resource("/authz/check")
        .wrap(build_governor(rate_limit_cfg.authz_check_per_min))
        .route(web::post().to(handlers::authz_check::check_access::<C>)),
)
```

### CI job structure (GitHub Actions)
**Source:** `.github/workflows/ci.yml:59-75` (build-no-saml job)
**Apply to:** all new `.github/workflows/sdk-*.yml` files
```yaml
# Pinned SHA-based actions — never use floating tags
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
- uses: dtolnay/rust-toolchain@3c5f7ea28cd621ae0bf5283f0e981fb97b8a7af9  # stable (2026-03-27)
  with:
    toolchain: stable
- uses: Swatinem/rust-cache@9d47c6ad4b02e050fd481d890b2ea34778fd09d6  # v2.7.8
# Do NOT install libxmlsec1-dev in workflows that use --no-default-features
# This is intentional: any SAML leak back into the default-off build must FAIL
```

---

## No Analog Found

Files with no close match in the codebase; planner should use RESEARCH.md patterns + external docs:

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `sdks/buf.yaml` | config | — | No buf workspace config exists; first use of buf in this repo. Use buf v2 format from RESEARCH.md §FND-02. Planner must add `checkpoint:human-verify` for plugin names. |
| `sdks/buf.gen.yaml` | config | — | No buf codegen config exists. Plugin names from RESEARCH.md are ASSUMED (MEDIUM confidence); require human verification against BSR before committing. |
| `sdks/CONTRACT.md` | documentation | — | No cross-language normative contract exists. Author from scratch using FND-03 section outline in RESEARCH.md (§1-§10 sections). |
| `sdks/openapi.json` | artifact | — | Generated artifact; not hand-authored. Created by running `cargo build -p axiam-server --no-default-features && ./target/debug/axiam-server --dump-openapi > sdks/openapi.json` after FND-01 is implemented. |
| `sdks/{lang}/` scaffold manifests (`Cargo.toml`, `package.json`, `pyproject.toml`, `pom.xml`, `*.csproj`, `composer.json`, `go.mod`) | config | — | No SDK package manifests exist in repo. Use D-11/D-12 package names from CONTEXT.md. D-13: Go module path = `github.com/axiam/axiam/sdks/go`. |

---

## Critical Ordering Constraints for Planner

1. **FND-04 before FND-01:** The authz-check handler must be registered and annotated before `--dump-openapi` is run to generate `sdks/openapi.json`. The exported JSON must include the `/authz/check` paths.
2. **PERMISSION_REGISTRY before tests:** Add `authz:check_as` to `permissions.rs` before running the parity test suite.
3. **`sdks/openapi.json` committed after FND-01 + FND-04 land:** The committed file is a snapshot — it must be regenerated after both changes are in place.
4. **buf plugin verification before buf.gen.yaml commit:** RESEARCH.md marks Rust community plugin names as ASSUMED. Planner must add a `checkpoint:human-verify` task before `sdks/buf.gen.yaml` is committed.

---

## D-13 ROADMAP Fixup Locations

**File:** `.planning/ROADMAP.md`

| Location | Stale String | Correct String |
|---|---|---|
| Phase 18 success criterion #1 | `go get github.com/axiam/axiam-go-sdk` | `go get github.com/axiam/axiam/sdks/go` |
| Phase 18 success criterion #5 | `sdk/go/vX.Y.Z` | `sdks/go/vX.Y.Z` |

Use `grep -n "axiam-go-sdk\|sdk/go/v"` in ROADMAP.md to locate exact line numbers before editing.

---

## Metadata

**Analog search scope:** `crates/axiam-api-rest/`, `crates/axiam-api-grpc/`, `crates/axiam-server/`, `.github/workflows/`
**Files scanned:** 10 source files read directly
**Pattern extraction date:** 2026-06-29
