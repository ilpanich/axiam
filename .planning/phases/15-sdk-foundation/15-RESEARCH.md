# Phase 15: SDK Foundation — Research

**Researched:** 2026-06-29
**Domain:** OpenAPI export, buf proto codegen, REST authz endpoint, SDK monorepo scaffold, cross-language contract
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**D-01:** Generate-on-build — no buf-generated gRPC stubs committed to git for any of the 6 buf-managed languages. C# uses `Grpc.Tools` MSBuild (documented exception). Each SDK build and CI runs `buf generate` into a gitignored directory.

**D-02:** Release/packaging step must regenerate-and-bundle stubs. FND-02's "single documented command" doubles as the publish-time codegen step. Reproducibility asserted from a clean checkout in CI.

**D-03:** Path-filtered per-PR drift gates. OpenAPI drift gate runs on PRs touching `crates/axiam-api-rest/**`; `buf lint` + `buf breaking` run on PRs touching `proto/**`.

**D-04:** Release-tag re-export retained as belt-and-suspenders final confirm.

**D-05:** Ship both `POST /api/v1/authz/check` (single) and `POST /api/v1/authz/check/batch` (ordered list). Batch foundational for browser TS `can()` rendering without N round-trips.

**D-06:** Subject = caller by default. Optional `subject_id` in request requires admin-level permission. Cross-subject queries written to audit log. [Exact permission name: research/discretion — see section below.]

**D-07:** Dedicated higher rate-limit tier for authz-check routes, reusing Phase-2 governor middleware. Separate bucket, higher ceiling.

**D-08:** Decision logic via the same `AuthorizationEngine::check_access` as gRPC — no divergent authz path.

**D-09:** `sdks/CONTRACT.md` is normative/binding. "Conforms to CONTRACT.md §X" is a verification checklist item in each downstream SDK phase.

**D-10:** Canonical vocabulary locked now: method-name map (`login`/`verify_mfa`/`refresh`/`logout`/`check_access`+`can`/batch-check) per-language idiom; error taxonomy (`AuthError`/`AuthzError`/`NetworkError`) with HTTP/gRPC status mapping.

**D-11:** GitHub org/namespace base = `axiam`. Derived identities: Maven groupId `io.axiam`, Packagist vendor `axiam/`, NuGet root `Axiam.*`, GitHub org `github.com/axiam`.

**D-12:** Canonical package names: Rust crate `axiam-sdk`, npm `axiam-sdk`, PyPI `axiam-sdk`, Maven `io.axiam:axiam-sdk`, NuGet `Axiam.Sdk`, Packagist `axiam/axiam-sdk`.

**D-13:** Go = monorepo subdir. Module path `github.com/axiam/axiam/sdks/go`, release tag `sdks/go/vX.Y.Z`. **ROADMAP fixup required:** Phase 18 success criteria #1 and #5 contain stale strings.

### Claude's Discretion

- Exact internal structure of the `--dump-openapi` code path (subcommand vs early-return branch in `axiam-server/src/main.rs`).
- Gitignored output directory naming for generated stubs.
- The specific permission name gating the admin subject-override (D-06) — identified by research below.

### Deferred Ideas (OUT OF SCOPE)

- Conformance test harness mechanically verifying each SDK against CONTRACT.md — future enhancement.
- Go vanity import path (`go.axiam.dev/sdk`).
- Split-out per-SDK repos.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| FND-01 | `--dump-openapi` flag on `axiam-server`; prints `api_doc()` JSON to stdout without DB/AMQP; `sdks/openapi.json` committed; CI drift gate fails on divergence | `api_doc()` confirmed in `openapi.rs`; `serde_json` already a direct dep of `axiam-server`; see §FND-01 detail |
| FND-02 | `sdks/buf.yaml` + `sdks/buf.gen.yaml`; `buf lint`/`buf breaking` in CI on `proto/**`; reproducible generation from clean checkout via single command | proto surface confirmed in 3 files; buf not locally installed; `@bufbuild/buf` npm v1.71.0 available; see §FND-02 detail |
| FND-03 | `sdks/CONTRACT.md` documenting method map, error taxonomy, CSRF/cookie, TLS, `Sensitive<T>`, AMQP HMAC, middleware interface; referenced in every SDK README | Prior research resolved all content; see §FND-03 detail |
| FND-04 | `POST /api/v1/authz/check` + `/batch`; reuses `AuthorizationEngine::check_access`; rate-limited; in OpenAPI spec; parity test updated | `AccessRequest`/`AccessDecision` types confirmed; `AuthzData` type alias confirmed; `RequirePermission` pattern confirmed; see §FND-04 detail |
| FND-05 | `sdks/{rust,typescript,python,java,csharp,php,go}/` scaffold; per-SDK path-filtered CI; Apache-2.0 LICENSE in each | `sdks/` does not yet exist; CI pattern from `build-no-saml` job confirmed; see §FND-05 detail |
</phase_requirements>

---

## Summary

Phase 15 is the shared plumbing phase — it produces five artifacts that every per-language SDK (Phases 16–22) consumes before writing any SDK client logic:

**What exists today (confirmed by codebase inspection):**
- `api_doc()` in `crates/axiam-api-rest/src/openapi.rs` — the full `utoipa::openapi::OpenApi` struct, feature-gated for SAML via `SamlApiDoc`. The `openapi` module is `pub` and `api_doc()` is `pub fn`. `serde_json` is already a direct workspace dependency of `axiam-server`.
- `AuthorizationEngine::check_access` in `crates/axiam-authz/src/engine.rs:63` — the single RBAC decision path.
- `AuthzChecker` trait + `AuthzData` type alias + `RequirePermission` guard in `crates/axiam-api-rest/src/authz.rs` — established pattern for new REST authz handlers.
- `RateLimitConfig` struct + `build_governor()` in `crates/axiam-api-rest/src/config/rate_limit.rs` + `server.rs` — the extensible rate-limit infrastructure (Phase 2).
- `PERMISSION_REGISTRY` + `ROUTE_PERMISSION_MAP` + `PUBLIC_PATHS` in `crates/axiam-api-rest/src/permissions.rs` — every new permission and route must be registered here.
- Route↔OpenAPI parity test in `tests/route_openapi_parity_test.rs` — must be extended for the `/authz/check` routes.
- `healthcheck` early-exit pattern at `main.rs:107-116` — the exact model for `--dump-openapi`.

**What does not yet exist (net-new):**
- The `--dump-openapi` early-exit branch in `main.rs`
- `sdks/` directory and all contents
- `POST /api/v1/authz/check` + `/batch` handlers
- `authz_check_per_min` rate-limit tier
- `authz:check_as` permission entry
- `sdks/buf.yaml`, `sdks/buf.gen.yaml`
- CI workflow files for drift gate, buf gates, and per-SDK paths

**Primary recommendation:** Implement the five FND requirements in wave order: FND-04 first (it modifies existing Rust crates and has tests), then FND-01 (single-binary change), then FND-02/FND-03/FND-05 (new files, no compilation risk). This sequencing keeps the Rust build green throughout.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| OpenAPI JSON export | Binary (`axiam-server`) | `axiam-api-rest` (provides `api_doc()`) | Server binary assembles all crates; `api_doc()` is the only place the full spec exists |
| Authz decision (REST) | API / Backend (`axiam-api-rest`) | `axiam-authz` (decision engine) | Handler delegates to `AuthorizationEngine` via `AuthzChecker` trait — same path as gRPC |
| Authz decision (gRPC) | API / Backend (`axiam-api-grpc`) | `axiam-authz` | Already implemented; REST handler is a parallel wrapper, not a replacement |
| Rate limiting | API / Backend (`axiam-api-rest`) | — | `build_governor()` wraps individual route scopes; config from `RateLimitConfig` |
| Proto codegen | Build tooling (`buf`) | Per-SDK build scripts | `buf generate` from `sdks/`; output gitignored per D-01 |
| OpenAPI drift gate | CI (GitHub Actions) | — | `--dump-openapi` + `git diff --exit-code`; path-filtered on `crates/axiam-api-rest/**` |
| SDK monorepo layout | Repository structure | CI | `sdks/` subtree; per-SDK GitHub Actions `paths:` filters |
| Cross-language contract | Documentation (`sdks/CONTRACT.md`) | Each SDK README | Normative document; SDKs conform; planner authors during Phase 15 |

---

## FND-01: `--dump-openapi` Implementation

### How `api_doc()` is serialized

`utoipa` v5 (workspace dep). `ApiDoc::openapi()` returns `utoipa::openapi::OpenApi` which implements `serde::Serialize`. `api_doc()` in `openapi.rs` merges in `SamlApiDoc` when `saml` feature is enabled.

Serialization call (no new deps — `serde_json` already in `axiam-server/Cargo.toml:39`): [VERIFIED: codebase inspection]

```rust
// In main.rs — immediately after the `healthcheck` early-exit block (line 116)
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

`axiam_api_rest::openapi` is a `pub mod` (confirmed `lib.rs:11`), so the call compiles without additional exports. [VERIFIED: codebase inspection]

### Feature determinism

`SamlApiDoc` is `#[cfg(feature = "saml")]`. The project-constraint `build-no-saml` CI job (`ci.yml:59`) uses `--no-default-features` and is the stable local-build path (project memory: SAML behind feature, Arch builds with `--no-default-features`). [VERIFIED: codebase inspection]

**Decision:** generate and commit `sdks/openapi.json` with `--no-default-features` (SAML paths excluded). The CI drift gate must pin the same flag set:

```bash
cargo build -p axiam-server --no-default-features
./target/debug/axiam-server --dump-openapi > /tmp/openapi-fresh.json
git diff --exit-code sdks/openapi.json /tmp/openapi-fresh.json
```

This ensures the committed file is identical on any machine regardless of whether `libxmlsec1-dev` is installed. [ASSUMED: feature-set recommendation based on project constraints — confirm with maintainer if SAML paths should be in the public SDK contract]

### First export

`sdks/openapi.json` does not exist yet. Creating it = running the command above after implementing the flag and committing the output. This is a Wave 0 task.

---

## FND-02: buf Codegen Pipeline

### buf availability

buf is NOT installed on the local machine. Available as: [VERIFIED: npm registry]
- `@bufbuild/buf` npm package v1.71.0 (`npm view @bufbuild/buf version` confirmed)
- `buf` standalone binary (GitHub releases)
- `bufbuild/buf` GitHub Action (preferred for CI)

For local dev: `npm install -g @bufbuild/buf` or use `npx @bufbuild/buf`.

### Proto surface (confirmed by codebase inspection) [VERIFIED: codebase inspection]

Three proto files at `proto/axiam/v1/`:
- `authorization.proto` — `AuthorizationService`: `CheckAccess`, `BatchCheckAccess`; messages: `CheckAccessRequest`, `CheckAccessResponse`, `BatchCheckAccessRequest`, `BatchCheckAccessResponse`
- `token.proto` — `TokenService`
- `user.proto` — `UserService`

Package: `axiam.v1`. No `buf.yaml` or `buf.gen.yaml` exists yet.

### `sdks/buf.yaml` (buf v2 format)

```yaml
version: v2
modules:
  - path: ../proto
lint:
  use:
    - DEFAULT
breaking:
  use:
    - FILE
```

Note: `sdks/buf.yaml` module path `../proto` makes `proto/axiam/v1/` the input. buf v2 allows relative paths in `modules`. [ASSUMED: buf v2 syntax from training knowledge — verify with `buf mod init` or official docs at buf.build/docs when buf is installed]

### `sdks/buf.gen.yaml` (buf v2 format)

```yaml
version: v2
plugins:
  # Rust: prost (message codegen) + tonic (service codegen)
  - remote: buf.build/community/neoeinstein-prost
    out: rust/src/gen
    opt:
      - compile_well_known_types=true
  - remote: buf.build/community/neoeinstein-tonic
    out: rust/src/gen
    opt:
      - compile_well_known_types=true
      - no_include=true
  # TypeScript: ts-proto (@grpc/grpc-js compatible stubs)
  - remote: buf.build/community/stephenh-ts-proto
    out: typescript/src/gen
    opt:
      - target=ts
      - outputServices=grpc-js
  # Go: protobuf types + gRPC service stubs
  - remote: buf.build/protocolbuffers/go
    out: go/gen
    opt:
      - paths=source_relative
  - remote: buf.build/grpc/go
    out: go/gen
    opt:
      - paths=source_relative
  # Python: protobuf types + gRPC service stubs
  - remote: buf.build/protocolbuffers/python
    out: python/axiam_sdk/gen
  - remote: buf.build/grpc/python
    out: python/axiam_sdk/gen
  # Java: protobuf types + gRPC service stubs
  - remote: buf.build/protocolbuffers/java
    out: java/src/main/java
  - remote: buf.build/grpc/java
    out: java/src/main/java
```

[ASSUMED: plugin names from prior research (STACK.md, 2026-06-28) and training knowledge — must be verified against buf.build BSR registry before locking into the plan. The `grpc/go`, `grpc/java`, `grpc/python`, `protocolbuffers/go` remote plugins are well-established; the community Rust plugins are less certain. Planner must add a human-verify checkpoint before committing buf.gen.yaml.]

**C# documented exception:** C# SDK uses `Grpc.Tools` MSBuild integration. Add `<Protobuf Include="../../proto/**/*.proto" GrpcServices="Client" />` to `sdks/csharp/Axiam.Sdk/Axiam.Sdk.csproj`. No buf plugin entry needed. Document in `sdks/CONTRACT.md` and `sdks/csharp/README.md`. [VERIFIED: confirmed in prior research STACK.md and CONTEXT.md D-01]

### Single documented command (FND-02 AC)

```bash
cd sdks && buf generate
```

This command: (1) is the reproducibility assertion for CI, (2) doubles as the release-time regenerate step (D-02). Each SDK CI job runs this before building. [ASSUMED: command form depends on buf.yaml placement — verify once buf is installed]

### Gitignored output directories (D-01)

Each SDK's generated stub directory must be in `.gitignore`:
- `sdks/rust/src/gen/`
- `sdks/typescript/src/gen/`
- `sdks/go/gen/`
- `sdks/python/axiam_sdk/gen/`
- `sdks/java/src/main/java/io/axiam/sdk/gen/` (or equivalent)

### CI jobs

**buf-gates.yml** (triggered on `proto/**` PRs):
```yaml
on:
  pull_request:
    paths: ['proto/**']
jobs:
  buf-lint:
    steps:
      - uses: bufbuild/buf-action@...
        with:
          lint: true
          breaking: true
          breaking_against: 'https://github.com/axiam/axiam.git#branch=main,subdir=proto'
```

[ASSUMED: `bufbuild/buf-action` GitHub Action name — verify on GitHub marketplace]

---

## FND-03: CONTRACT.md Content Outline

The full document is authored during planning/execution. These are the normative sections it MUST contain per FND-03 AC:

| Section | Content |
|---------|---------|
| §1 Method naming map | `login`, `verify_mfa`, `refresh`, `logout`, `check_access`, `can` (browser alias), `batch_check` per language idiom table |
| §2 Error taxonomy | `AuthError`, `AuthzError`, `NetworkError` definitions + HTTP status → error type mapping + gRPC status → error type mapping |
| §3 CSRF behavior | Browser: auto-forward `X-CSRF-Token` from response header on all `POST/PUT/PATCH/DELETE`; non-browser: same rule (server enforces regardless) |
| §4 Cookie-jar requirement | All non-browser SDKs MUST initialize HTTP client with a persistent cookie store (see PITFALLS.md Pitfall 5) |
| §5 Tenant context contract | `tenant_slug`/`tenant_id` is a non-optional constructor parameter; injected as `X-Tenant-ID` header on every request |
| §6 TLS policy | Strict TLS by default; `with_custom_ca(pem)` for dev certs; no `skip_tls_verification()` API surface |
| §7 `Sensitive<T>` requirement | Token fields in all languages must suppress `Debug`/`Display`/`toString`/`__repr__`; raw token string MUST NOT be exposed via public API |
| §8 AMQP HMAC contract | `HMAC-SHA256(secret, body)` verified against `hmac_signature` message field; failure → nack without requeue; treat as security event |
| §9 Single-flight refresh guard | Exactly one in-flight refresh at any time; concurrent 401s queue and reuse result; 401 on refresh → `AuthError` (no retry) |
| §10 Middleware/route-guard interface | Per-language framework expectations (Actix extractor, Express/Fastify middleware, FastAPI dependency, Django middleware, Spring filter, ASP.NET Core middleware, net/http handler wrapping, PHP Middleware/EventSubscriber) |

Each SDK README in Phase 16–22 must contain: "This SDK conforms to CONTRACT.md §1-§10." [VERIFIED: from REQUIREMENTS.md FND-03 AC and PITFALLS.md]

---

## FND-04: REST Authorization-Check Endpoint

### Request/response shapes (confirmed by codebase inspection) [VERIFIED: codebase inspection]

**gRPC `CheckAccessRequest` proto shape** (from `authorization.proto`):
```protobuf
message CheckAccessRequest {
  string tenant_id = 1;   // from JWT claims — NOT in REST request body
  string subject_id = 2;  // from JWT claims — NOT in REST request body (unless admin override)
  string action = 3;
  string resource_id = 4;
  optional string scope = 5;
}
```

The gRPC handler (confirmed `authorization.rs:73-115`) cross-validates body fields against JWT claims and rejects mismatches. The REST handler takes a SIMPLER approach: tenant and subject come exclusively from the `AuthenticatedUser` extractor (JWT claims), with no body redundancy.

**REST request body (`CheckAccessRequest` in handler):**
```rust
#[derive(Deserialize, ToSchema)]
struct CheckAccessBody {
    action: String,
    resource_id: Uuid,
    scope: Option<String>,
    /// Only accepted from callers holding `authz:check_as` permission.
    subject_id: Option<Uuid>,
}
```

**REST response body:**
```rust
#[derive(Serialize, ToSchema)]
struct CheckAccessResponse {
    allowed: bool,
    reason: Option<String>,  // None when allowed; deny reason when denied
}
```

**Batch request/response (mirrors gRPC `BatchCheckAccess`):**
```rust
#[derive(Deserialize, ToSchema)]
struct BatchCheckAccessBody {
    checks: Vec<CheckAccessBody>,
}

#[derive(Serialize, ToSchema)]
struct BatchCheckAccessResponse {
    results: Vec<CheckAccessResponse>,  // ordered, same length as input
}
```

### Handler logic flow

```
POST /api/v1/authz/check
  1. Extract AuthenticatedUser (JWT claims → tenant_id, user_id) — 401 if missing
  2. If body.subject_id is Some(_):
       RequirePermission::new("authz:check_as", user.tenant_id)
           .check(&user, authz.get_ref().as_ref()).await? → 403 if denied
       effective_subject = body.subject_id
       audit log: cross-subject authz query (actor=user.user_id, subject=effective_subject)
     Else:
       effective_subject = user.user_id
  3. Build AccessRequest { tenant_id: user.tenant_id, subject_id: effective_subject, action, resource_id, scope }
  4. authz.check_access(&req).await? → AccessDecision::Allow | ::Deny(reason)
  5. Return CheckAccessResponse { allowed, reason }
```

### `authz:check_as` permission

**Confirmed finding:** `PERMISSION_REGISTRY` in `crates/axiam-api-rest/src/permissions.rs` contains no permission that gates cross-subject authz queries. `users:admin` is semantically incorrect (covers unlock/reset-MFA). [VERIFIED: codebase inspection, lines 23–177]

**Recommendation:** Add new permission entry to `PERMISSION_REGISTRY`:

```rust
// In PERMISSION_REGISTRY, new entry:
("authz:check_as", "Perform an authorization check on behalf of another subject (admin override)"),
```

**File:** `crates/axiam-api-rest/src/permissions.rs` — append to `PERMISSION_REGISTRY` slice.

**Auto-grant:** `reconcile_default_role_grants` (called in `main.rs` startup loop) automatically back-fills new registry permissions to the default admin role for all existing tenants. No manual grant SQL needed. [VERIFIED: codebase inspection `main.rs:273-289`]

**Resource ID sentinel for `RequirePermission::new("authz:check_as", sentinel)`:** Use `user.tenant_id` as the resource UUID. All global admin roles (`is_global=true`) satisfy any `RequirePermission` check regardless of resource_id, so this is always correct. [VERIFIED: engine.rs:87-89 — global roles filter: `a.role.is_global || ...`]

### Parity test update

`tests/route_openapi_parity_test.rs` has three categories: `ROUTE_PERMISSION_MAP`, `PUBLIC_PATHS`, `AUTHENTICATED_SELF_SERVICE_PATHS`. The `/api/v1/authz/check` and `/api/v1/authz/check/batch` endpoints are:
- Authenticated (JWT required)
- No per-route named permission for the self-check case (the `authz:check_as` check is conditional inside the handler, not a route-level gate)

Add to `AUTHENTICATED_SELF_SERVICE_PATHS` in the parity test:
```rust
"/api/v1/authz/check",
"/api/v1/authz/check/batch",
```

Also add both paths to `openapi.rs` `paths()` list once handlers have `#[utoipa::path]` annotations.

### Rate-limit tier (D-07)

Add `authz_check_per_min: u32` (default `300`) to `RateLimitConfig` in `crates/axiam-api-rest/src/config/rate_limit.rs`:

```rust
pub struct RateLimitConfig {
    // ... existing fields ...
    /// Max authz-check requests per minute per IP (default: 300).
    /// Authz checks are read-only and high-frequency — UI permission gating.
    pub authz_check_per_min: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // ... existing defaults ...
            authz_check_per_min: 300,
        }
    }
}

impl RateLimitConfig {
    pub fn validate(&self) {
        // ... existing assertions ...
        assert!(self.authz_check_per_min >= 1, "authz_check_per_min must be >= 1");
    }
}
```

In `server.rs`, wrap the authz scope:
```rust
.service(
    web::scope("/authz")
        .wrap(build_governor(rate_limit_cfg.authz_check_per_min))
        .route("/check", web::post().to(handlers::authz_check::check_access::<DbClient>))
        .route("/check/batch", web::post().to(handlers::authz_check::batch_check_access::<DbClient>))
)
```

[VERIFIED: pattern from `server.rs` and `config/rate_limit.rs` codebase inspection]

---

## FND-05: SDK Monorepo Scaffold

### Directory structure

`sdks/` does not yet exist (confirmed `ls sdks/` → "not found"). Net-new top-level directory:

```
sdks/
├── openapi.json            # FND-01 committed export (first run)
├── buf.yaml                # FND-02 buf workspace (module path: ../proto)
├── buf.gen.yaml            # FND-02 multi-language codegen config
├── CONTRACT.md             # FND-03 normative cross-language contract
├── rust/
│   ├── LICENSE             # Apache-2.0
│   ├── Cargo.toml          # [package] axiam-sdk; publish = true
│   └── src/
│       └── lib.rs          # stub (Phase 16 fills this)
├── typescript/
│   ├── LICENSE             # Apache-2.0
│   ├── package.json        # name: "axiam-sdk"
│   └── src/index.ts        # stub
├── python/
│   ├── LICENSE             # Apache-2.0
│   ├── pyproject.toml      # name = "axiam-sdk"
│   └── axiam_sdk/__init__.py
├── java/
│   ├── LICENSE             # Apache-2.0
│   └── pom.xml             # groupId: io.axiam, artifactId: axiam-sdk
├── csharp/
│   ├── LICENSE             # Apache-2.0
│   └── Axiam.Sdk/Axiam.Sdk.csproj
├── php/
│   ├── LICENSE             # Apache-2.0
│   └── composer.json       # name: "axiam/axiam-sdk"
└── go/
    ├── LICENSE             # Apache-2.0
    └── go.mod              # module github.com/axiam/axiam/sdks/go (D-13)
```

### Per-SDK path-filtered CI (FND-05 AC)

Pattern from existing `ci.yml`: one workflow file per SDK, triggered only on per-SDK path changes + shared artifacts. Seven new workflow files:

```yaml
# .github/workflows/sdk-ci-rust.yml
on:
  pull_request:
    paths:
      - 'sdks/rust/**'
      - 'sdks/openapi.json'
      - 'sdks/buf.yaml'
      - 'sdks/buf.gen.yaml'
```

For this phase, the per-SDK CI workflows are stubs that verify the scaffold exists and the LICENSE file is present. Actual build/test steps are added per-SDK in Phases 16–22.

### Apache-2.0 LICENSE

The repo is Apache-2.0 (project memory: `project_license_apache.md`). Do NOT copy from the stale `Cargo.toml` license field (known wrong). Use the Apache-2.0 text directly. Each `sdks/<lang>/LICENSE` must match the root `LICENSE` file verbatim.

---

## D-13 ROADMAP Fixup Required

Phase 18 Go SDK in `.planning/ROADMAP.md` contains stale strings that contradict D-13:

| Location | Stale String | Correct String |
|----------|-------------|----------------|
| `ROADMAP.md` line 654, success criterion #1 | `go get github.com/axiam/axiam-go-sdk` | `go get github.com/axiam/axiam/sdks/go` |
| `ROADMAP.md` line 658, success criterion #5 | `sdk/go/vX.Y.Z` | `sdks/go/vX.Y.Z` |

The planner must include a task to apply these two string fixes to `ROADMAP.md` as part of Phase 15.

---

## Package Legitimacy Audit

Phase 15 installs no new runtime dependencies. The only tooling addition is buf CLI, used in CI only.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `@bufbuild/buf` | npm | 4+ years | 1.71.0 (current) | github.com/bufbuild/buf | Not run (CLI tool) | Approved — official Buf Inc product |

`buf` binary is a CLI tool, not a runtime library. It is published by Buf Inc (https://buf.build/), the company that maintains the BSR. `npm view @bufbuild/buf version` returned `1.71.0` confirming the package exists. [VERIFIED: npm registry]

**Packages removed due to slopcheck [SLOP] verdict:** none

**Packages flagged as suspicious [SUS]:** none

*slopcheck could not be invoked against non-Python packages. buf is verified via official source (buf.build).*

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| OpenAPI JSON serialization | Custom serializer | `serde_json::to_string_pretty()` — already a dep | `utoipa::openapi::OpenApi` implements `Serialize`; one-liner |
| Proto codegen for 5 languages | Per-language `protoc` invocations | `buf generate` | Single command, remote plugins, lint + breaking gates included |
| Rate-limit governor for authz routes | Custom token bucket | `build_governor(rate_limit_cfg.authz_check_per_min)` | Pattern already exists for 7 other routes; 2-line extension |
| Permission registry for `authz:check_as` | Ad-hoc permission check | `PERMISSION_REGISTRY` + `reconcile_default_role_grants` startup | Auto-grants to admin role on restart; idempotent; consistent with all other permissions |
| CI drift detection | Custom comparison script | `git diff --exit-code` | Standard; zero additional tooling |

---

## Common Pitfalls

### Pitfall 1: `--dump-openapi` placed after DB/AMQP init
**What goes wrong:** Server attempts to connect to SurrealDB/RabbitMQ before printing the spec; the flag is unusable in CI without a running database.
**Why it happens:** Flag parsed after config loading, which triggers DB connection.
**How to avoid:** Place the args check in the same early-exit block as `healthcheck` (main.rs:107-116), BEFORE `tracing_subscriber::fmt()` init and before `load_config()`. The `api_doc()` call needs no runtime state.
**Warning signs:** `--dump-openapi` prints "Failed to connect to SurrealDB" before the JSON.

### Pitfall 2: Drift gate feature-flag mismatch
**What goes wrong:** `sdks/openapi.json` committed with `--no-default-features` but drift gate runs with `--all-features`; SAML paths appear in the fresh export but not the committed file; gate always fails.
**Why it happens:** CI engineer doesn't pin features in both the export command and the gate command.
**How to avoid:** Both the initial export command and the CI drift gate command MUST use identical `--no-default-features` flag. Encode this in the documented command in `sdks/CONTRACT.md`.
**Warning signs:** Drift gate fails immediately after the first green run on main.

### Pitfall 3: buf plugin names guessed, not verified
**What goes wrong:** `buf.gen.yaml` specifies community plugin names that don't exist on buf.build BSR; `buf generate` fails with "plugin not found".
**Why it happens:** buf BSR plugin registry changes; community plugins move or are renamed.
**How to avoid:** Verify each `remote:` plugin name against https://buf.build/plugins before committing `buf.gen.yaml`. The Rust plugins in particular (`neoeinstein-prost`, `neoeinstein-tonic`) are community-maintained and may have moved.
**Warning signs:** `buf generate` returns "failed to resolve remote plugin".

### Pitfall 4: `authz:check_as` not in ROUTE_PERMISSION_MAP but missing from AUTHENTICATED_SELF_SERVICE_PATHS
**What goes wrong:** Parity test `every_openapi_path_is_registered` fails because `/api/v1/authz/check` is in the OpenAPI spec but not in any of the three constants.
**How to avoid:** Add to `AUTHENTICATED_SELF_SERVICE_PATHS` in `route_openapi_parity_test.rs`. The permission check for subject-override is inside the handler, not a route-level gate.
**Warning signs:** Parity test B fails with "OpenAPI paths not in ROUTE_PERMISSION_MAP, PUBLIC_PATHS, or AUTHENTICATED_SELF_SERVICE_PATHS".

### Pitfall 5: Go module path in `go.mod` doesn't match tag convention
**What goes wrong:** `go.mod` says `module github.com/axiam/axiam/sdks/go` but the release tag is `sdk/go/vX.Y.Z` instead of `sdks/go/vX.Y.Z`; Go module proxy rejects the module.
**How to avoid:** D-13 confirmed: module path = `github.com/axiam/axiam/sdks/go`, tag = `sdks/go/vX.Y.Z`. Ensure `go.mod` module declaration and CI tag template match exactly.
**Warning signs:** `go get github.com/axiam/axiam/sdks/go` returns "unknown version".

### Pitfall 6: `axiam:check_as` permission seeding order
**What goes wrong:** New `authz:check_as` permission added to PERMISSION_REGISTRY after `reconcile_default_role_grants` has already run on production; existing admin roles don't have it until the next server restart.
**How to avoid:** The startup loop at `main.rs:245-296` already handles this: `seed_permissions` + `reconcile_default_role_grants` runs on every startup. The next deployment of Phase 15 will auto-grant it.
**Warning signs:** Admin gets 403 on `subject_id` override immediately after Phase 15 deploy — resolved by server restart.

---

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|-----------------|--------|
| `protoc` per-language shell scripts | `buf generate` with remote plugins | Single command, no local tool installs except `buf` |
| Manual OpenAPI JSON export (start server, curl) | `--dump-openapi` early-exit flag | CI-safe, no DB/AMQP needed |
| No REST authz query surface | `POST /api/v1/authz/check` | Browser TS SDK `can()` unblocked |

**No deprecated approaches found in this phase's scope.** The existing `api_doc()` / `utoipa` 5 / `actix_governor` patterns are all current.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `cargo test` (Rust), all tests in `crates/axiam-api-rest/` |
| Config file | None — standard Cargo test runner |
| Quick run command | `cargo test -p axiam-api-rest --no-default-features` |
| Full suite command | `cargo test -p axiam-api-rest -p axiam-authz` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FND-01 | `--dump-openapi` exits 0 without DB/AMQP | integration | `cargo run -p axiam-server --no-default-features -- --dump-openapi \| jq .info` | ❌ Wave 0 |
| FND-01 | Drift gate: fresh export matches committed `sdks/openapi.json` | CI smoke | `diff sdks/openapi.json <(cargo run -p axiam-server --no-default-features -- --dump-openapi)` | ❌ Wave 0 |
| FND-02 | `buf lint` passes on `proto/axiam/v1/*.proto` | CI | `cd sdks && buf lint` | ❌ Wave 0 |
| FND-04 | `POST /api/v1/authz/check` returns `{allowed}` via same engine as gRPC | unit | `cargo test -p axiam-api-rest --test authz_check -- authz_check` | ❌ Wave 0 |
| FND-04 | Parity test B includes `/api/v1/authz/check` and `/batch` | unit | `cargo test -p axiam-api-rest --no-default-features every_openapi_path_is_registered` | Extends existing ✅ |
| FND-04 | Parity test A: authz-check routes have OpenAPI annotations | unit | `cargo test -p axiam-api-rest --no-default-features every_authed_route_is_in_openapi` | Extends existing ✅ |
| FND-05 | Per-SDK LICENSE files are Apache-2.0 | CI | `grep -r "Apache-2.0" sdks/*/LICENSE` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p axiam-api-rest --no-default-features`
- **Per wave merge:** `cargo test -p axiam-api-rest -p axiam-authz --no-default-features`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `crates/axiam-api-rest/src/handlers/authz_check.rs` — new handler file for FND-04
- [ ] `crates/axiam-api-rest/src/tests/authz_check_test.rs` — unit tests for FND-04
- [ ] `sdks/` directory and all scaffold files — FND-05
- [ ] `sdks/buf.yaml`, `sdks/buf.gen.yaml` — FND-02
- [ ] `sdks/openapi.json` — FND-01 first export
- [ ] `sdks/CONTRACT.md` — FND-03

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | n/a — new endpoint reuses existing session auth |
| V3 Session Management | no | n/a — existing `AuthenticatedUser` extractor handles this |
| V4 Access Control | yes | `RequirePermission` guard for `authz:check_as`; default-deny via `AuthzMiddleware` |
| V5 Input Validation | yes | `web::Json<CheckAccessBody>` — Actix validates JSON; Uuid type validates UUIDs |
| V6 Cryptography | no | n/a |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Caller checks another subject's permissions without authorization | Elevation of Privilege | `authz:check_as` permission required for `subject_id` override |
| Authz-check endpoint used to enumerate permissions | Information Disclosure | Rate-limited at 300/min per IP; decisions are boolean, not permission-list |
| Cross-tenant authz check via forged request | Spoofing | `tenant_id` taken exclusively from JWT claims (not request body) — cannot be forged |
| Audit bypass of cross-subject query | Repudiation | Audit log written before returning decision when `subject_id` override is used (D-06) |

---

## Registry Availability (D-11/D-12 Verification)

These are ops/human verification items. The table shows what is checkable programmatically vs. what requires manual reservation.

| Identity | Registry/Platform | Check Method | Status |
|----------|-----------------|--------------|--------|
| GitHub org `axiam` | github.com | `curl https://github.com/axiam 2>/dev/null` | [ASSUMED: unchecked — human must verify or reserve] |
| Crates.io `axiam-sdk` | crates.io | `cargo search axiam-sdk` | [ASSUMED: unchecked — human must verify] |
| npm `axiam-sdk` | npmjs.com | `npm view axiam-sdk` | [ASSUMED: unchecked] |
| PyPI `axiam-sdk` | pypi.org | `pip index versions axiam-sdk` | [ASSUMED: unchecked] |
| Maven `io.axiam:axiam-sdk` | search.maven.org | Portal search | [ASSUMED: unchecked — requires Sonatype account] |
| NuGet `Axiam.Sdk` | nuget.org | `nuget search Axiam.Sdk` | [ASSUMED: unchecked] |
| Packagist `axiam/axiam-sdk` | packagist.org | Portal search | [ASSUMED: unchecked] |

**Planner action:** Add a `checkpoint:human-verify` task early in Phase 15 for the human to check registry availability and reserve names before any publish pipeline is built. Common squatting risk: npm and PyPI generic "sdk" suffixes are frequently taken. If `axiam-sdk` is taken on any registry, the fallback must be decided before Phase 16+ build pipelines commit to a name.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust stable toolchain | FND-01, FND-04 | ✓ | (existing workspace) | — |
| `buf` CLI | FND-02 | ✗ locally | — | Install via `npm install -g @bufbuild/buf` (v1.71.0) or `bufbuild/buf` GitHub Action in CI |
| `serde_json` | FND-01 | ✓ | workspace dep | — |
| `actix_governor` | FND-04 rate limit | ✓ | (existing workspace dep) | — |
| GitHub Actions | FND-03 CI workflows | ✓ | — | — |

**Missing with no fallback:** none.

**Missing with fallback:** `buf` CLI not locally installed — use `npx @bufbuild/buf` for local dev or install globally. CI uses `bufbuild/buf-action`.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `sdks/openapi.json` should be generated with `--no-default-features` (SAML excluded) | FND-01, Feature determinism | If maintainer wants SAML paths in the SDK contract, the feature set changes and `build-no-saml` can't be used for export |
| A2 | buf v2 `buf.yaml` supports `modules.path: ../proto` (relative path to `proto/` from `sdks/`) | FND-02 buf.yaml | If v2 requires absolute paths or a different module structure, the path must change |
| A3 | buf remote plugin names (`neoeinstein-prost`, `neoeinstein-tonic`, `stephenh-ts-proto`) are correct current BSR identifiers | FND-02 buf.gen.yaml | If plugin names changed or moved, `buf generate` fails; planner must add human-verify checkpoint |
| A4 | `bufbuild/buf-action` is the correct GitHub Action name for buf CI | FND-02 CI | Must verify on GitHub Marketplace |
| A5 | Registry names `axiam-sdk` (npm, PyPI, crates.io) and `axiam` (GitHub org) are available | D-11/D-12 | If squatted, publish pipelines in Phases 16–22 need different names |
| A6 | `authz_check_per_min: 300` is an appropriate ceiling for the dedicated authz-check rate-limit tier | FND-04, D-07 | If too low, normal UI use trips the limit; if too high, DoS risk increases |

**If this table is empty:** Not applicable — several claims require confirmation before execution.

---

## Open Questions

1. **Should `sdks/openapi.json` include SAML paths?**
   - What we know: SAML is behind `saml` feature; local Arch builds use `--no-default-features`; `build-no-saml` CI guard exists
   - What's unclear: whether the public SDK REST contract should document SAML endpoints (useful for SDK consumers who run SAML-enabled AXIAM)
   - Recommendation: start with `--no-default-features` (simpler, deterministic); add a SAML-features export variant if requested by downstream SDK consumers

2. **buf plugin name verification**
   - What we know: prior research named the plugins; npm `@bufbuild/buf` confirmed at v1.71.0
   - What's unclear: exact current BSR plugin identifiers for Rust community plugins
   - Recommendation: planner adds a `checkpoint:human-verify` task — run `buf registry plugin list` after buf install to confirm before committing `buf.gen.yaml`

3. **Audit log schema for cross-subject authz check (D-06)**
   - What we know: `crates/axiam-amqp/src/messages.rs` defines `AuditEventMessage`; `audit_repo` is available in `main.rs` and passed as `web::Data`
   - What's unclear: which `action` string and `outcome` the audit entry should use
   - Recommendation: `action = "authz.check_as"`, `outcome = "allowed"/"denied"` following existing audit patterns

---

## Sources

### Primary (HIGH confidence)

- AXIAM codebase `crates/axiam-api-rest/src/openapi.rs` — `api_doc()` function, feature-gated SAML merge [VERIFIED: codebase inspection]
- AXIAM codebase `crates/axiam-server/src/main.rs` — early-exit pattern at lines 107–116, config loading, `serde_json` dep at `Cargo.toml:39` [VERIFIED: codebase inspection]
- AXIAM codebase `crates/axiam-authz/src/engine.rs:63` — `check_access` signature, `AccessRequest`/`AccessDecision` types [VERIFIED: codebase inspection]
- AXIAM codebase `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC handler shapes for single and batch check [VERIFIED: codebase inspection]
- AXIAM codebase `crates/axiam-api-rest/src/authz.rs` — `AuthzChecker` trait, `RequirePermission`, `AuthzData` type alias [VERIFIED: codebase inspection]
- AXIAM codebase `crates/axiam-api-rest/src/permissions.rs` — full `PERMISSION_REGISTRY` (no existing `authz:check_as`), `ROUTE_PERMISSION_MAP`, `PUBLIC_PATHS` [VERIFIED: codebase inspection]
- AXIAM codebase `crates/axiam-api-rest/src/config/rate_limit.rs` — `RateLimitConfig` struct, existing fields and defaults [VERIFIED: codebase inspection]
- AXIAM codebase `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` — test structure, three category constants [VERIFIED: codebase inspection]
- AXIAM codebase `.github/workflows/ci.yml` — CI patterns, `build-no-saml` job, pinned Actions SHA [VERIFIED: codebase inspection]
- AXIAM codebase `proto/axiam/v1/authorization.proto` — proto message and service definitions [VERIFIED: codebase inspection]
- Prior milestone research `ARCHITECTURE.md`, `STACK.md`, `PITFALLS.md`, `SUMMARY.md` (2026-06-28) — SDK architecture patterns [CITED: .planning/research/]
- `npm view @bufbuild/buf version` → `1.71.0` [VERIFIED: npm registry]

### Secondary (MEDIUM confidence)

- `.planning/REQUIREMENTS.md` FND-01..FND-05 acceptance criteria [CITED: .planning/REQUIREMENTS.md]
- `.planning/phases/15-sdk-foundation/15-CONTEXT.md` D-01..D-13 [CITED: context doc]

### Tertiary (LOW confidence)

- buf v2 `buf.yaml`/`buf.gen.yaml` syntax — from training knowledge; not verified against live buf.build docs [ASSUMED]
- buf BSR remote plugin names for Rust/TypeScript — from prior research (STACK.md); not verified against live BSR [ASSUMED]

---

## Metadata

**Confidence breakdown:**
- FND-01 implementation: HIGH — all code paths confirmed by codebase inspection
- FND-02 buf config: MEDIUM — plugin names and v2 syntax need verification once buf installed
- FND-03 contract content: HIGH — grounded in REQUIREMENTS.md, PITFALLS.md, and SUMMARY.md
- FND-04 engine reuse: HIGH — all types and patterns confirmed by codebase inspection
- FND-05 scaffold: HIGH — standard filesystem + CI pattern work
- Registry availability (D-11/D-12): LOW — human verification required

**Research date:** 2026-06-29
**Valid until:** 2026-07-30 (buf plugin versions; check buf BSR if planning beyond this date)
