# Coding Conventions

**Analysis Date:** 2026-03-28

## Naming Patterns

**Crates:**
- Use `axiam-{domain}` naming: `axiam-core`, `axiam-db`, `axiam-auth`, `axiam-api-rest`, `axiam-authz`
- Each crate owns a single domain concern

**Files:**
- Snake_case for all Rust files: `password_reset.rs`, `service_account.rs`
- Module files use `mod.rs` in subdirectories (e.g., `crates/axiam-api-rest/src/handlers/mod.rs`)
- Test files use `{domain}_test.rs` suffix in `tests/` directories

**Structs:**
- Domain models: PascalCase noun — `User`, `Tenant`, `Organization`, `Role`
- Create inputs: `Create{Entity}` — `CreateUser`, `CreateTenant`, `CreateOrganization`
- Update inputs: `Update{Entity}` — `UpdateUser`, `UpdateTenant` (all fields `Option<T>`)
- DB row structs: `{Entity}Row` (known ID) and `{Entity}RowWithId` (includes `record_id` from `meta::id`)
- Repository impls: `Surreal{Entity}Repository<C: Connection>`
- API request types: `{Action}{Entity}Request` — `CreateUserRequest`, `UpdateUserRequest`
- API response types: `{Entity}Response` — `UserResponse` (public-safe, sensitive fields stripped)
- Error types: `{Crate}Error` — `AxiamError`, `DbError`, `AuthError`, `AxiamApiError`

**Enums:**
- PascalCase variants: `UserStatus::Active`, `UserStatus::Locked`, `UserStatus::PendingVerification`
- Error enums use `#[derive(Debug, Error)]` with `thiserror`

**Functions:**
- Snake_case: `create`, `get_by_id`, `get_by_slug`, `list`, `update`, `delete`
- Private helpers: `parse_status()`, `status_to_string()`, `hash_password()`
- Test helpers: `setup()`, `test_keypair()`, `test_config()`, `mint_token()`

**Traits:**
- Repository traits: `{Entity}Repository` — `UserRepository`, `TenantRepository`, `OrganizationRepository`
- Defined in `crates/axiam-core/src/repository.rs`
- All require `Send + Sync` bounds
- Use native `impl Future<Output = ...> + Send` return types (no `async_trait` crate)

## Code Style

**Formatting:**
- Tool: `rustfmt` with `rustfmt.toml`
- Key settings in `rustfmt.toml`:
  ```toml
  edition = "2024"
  max_width = 100
  use_field_init_shorthand = true
  use_try_shorthand = true
  ```
- Run: `cargo fmt --all`

**Linting:**
- Tool: `clippy` with `.clippy.toml`
- Key settings in `.clippy.toml`:
  ```toml
  msrv = "1.93"
  cognitive-complexity-threshold = 30
  too-many-arguments-threshold = 8
  ```
- Run: `cargo clippy --workspace --all-targets -- -D warnings`
- CI enforces `RUSTFLAGS="-Dwarnings"`

**MSRV:** Rust 1.93 (edition 2024)

## Import Organization

**Order (observed pattern):**
1. Standard library (`std::`)
2. External crates (`actix_web`, `serde`, `uuid`, `chrono`, `surrealdb`, `tracing`)
3. Internal workspace crates (`axiam_core`, `axiam_db`, `axiam_auth`)
4. Local crate modules (`crate::error`, `crate::extractors`)

**Path Aliases:**
- No path aliases configured — use full crate names
- Internal crates referenced via workspace dependencies: `axiam-core = { path = "crates/axiam-core" }`

**Re-exports:**
- Each crate's `lib.rs` re-exports key public types for ergonomic access
- Example from `crates/axiam-db/src/lib.rs`: re-exports all `Surreal{Entity}Repository` types
- Example from `crates/axiam-auth/src/lib.rs`: re-exports `AuthService`, `AuthConfig`, `AuthError`

## Error Handling

**Three-layer error hierarchy:**

1. **Core errors** (`crates/axiam-core/src/error.rs`):
   - `AxiamError` — top-level enum with variants: `NotFound`, `AlreadyExists`, `AuthenticationFailed`, `AuthorizationDenied`, `Validation`, `Database`, `Certificate`, `Crypto`, `EmailDelivery`, `WebhookDelivery`, `TenantContext`, `RateLimited`, `Internal`
   - `AxiamResult<T>` type alias for `Result<T, AxiamError>`

2. **Domain-specific errors** (per crate):
   - `DbError` (`crates/axiam-db/src/error.rs`) — `Surreal`, `Migration`, `NotFound`
   - `AuthError` (`crates/axiam-auth/src/error.rs`) — `InvalidCredentials`, `AccountLocked`, `TokenExpired`, `MfaRequired`, etc.
   - Each implements `From<DomainError> for AxiamError` for automatic conversion

3. **API errors** (`crates/axiam-api-rest/src/error.rs`):
   - `AxiamApiError` — newtype wrapper around `AxiamError`
   - Implements `actix_web::ResponseError` to map domain errors to HTTP status codes
   - Returns JSON `{ "error": "error_code", "message": "human readable" }`

**Pattern: use `?` operator throughout.** Domain errors auto-convert to `AxiamError` via `From` impls. Handler return types are `Result<HttpResponse, AxiamApiError>`.

**Error mapping rules:**
| AxiamError variant | HTTP Status |
|---|---|
| `NotFound` | 404 |
| `AlreadyExists` | 409 |
| `AuthenticationFailed` | 401 |
| `AuthorizationDenied` | 403 |
| `Validation` / `TenantContext` | 400 |
| `RateLimited` | 429 |
| `Database` / `Internal` / others | 500 |

## Repository Pattern

**Trait definition** (`crates/axiam-core/src/repository.rs`):
- CRUD methods: `create`, `get_by_id`, `update`, `delete`, `list`
- Additional lookup methods: `get_by_slug`, `get_by_email`, `get_by_username`
- Tenant-scoped methods take `tenant_id: Uuid` as first parameter
- List methods take `Pagination { offset, limit }` and return `PaginatedResult<T>`
- All methods return `impl Future<Output = AxiamResult<T>> + Send`

**SurrealDB implementation** (`crates/axiam-db/src/repository/`):
- Each entity has a dedicated module file: `crates/axiam-db/src/repository/user.rs`
- Repository struct is generic: `SurrealUserRepository<C: Connection>`
- Constructor: `fn new(db: Surreal<C>) -> Self`
- UUIDs stored as strings in SurrealDB, converted with `Uuid::parse_str()`
- Enums stored as strings with helper functions: `parse_status()`, `status_to_string()`

**Row struct pattern:**
```rust
// For queries where UUID is known (CREATE, single-record fetch)
#[derive(Debug, SurrealValue)]
struct UserRow { /* all fields except id */ }

// For list queries using meta::id(id) AS record_id
#[derive(Debug, SurrealValue)]
struct UserRowWithId { record_id: String, /* rest of fields */ }

// Count queries
#[derive(Debug, SurrealValue)]
struct CountRow { total: u64 }
```

**Conversion pattern:**
```rust
impl UserRow {
    fn into_user(self, id: Uuid) -> Result<User, DbError> { /* ... */ }
}
impl UserRowWithId {
    fn try_into_user(self) -> Result<User, DbError> { /* ... */ }
}
```

**Record ID pattern:**
```rust
let id = Uuid::new_v4();
let id_str = id.to_string();
// CREATE type::record('table', $id) SET field = $value, ...
```

## API Handler Pattern

**Location:** `crates/axiam-api-rest/src/handlers/{entity}.rs`

**Structure per handler file:**
1. Request/response types at top (with `utoipa::ToSchema` derives)
2. `From<DomainModel> for Response` impl to strip sensitive fields
3. Handler functions with `#[utoipa::path(...)]` annotations
4. Handlers are generic over `C: Connection` for testability

**Handler signature pattern:**
```rust
pub async fn create<C: Connection>(
    user: AuthenticatedUser,          // JWT-extracted identity
    repo: web::Data<SurrealUserRepository<C>>,  // injected via app_data
    body: web::Json<CreateUserRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    // Convert request -> domain input
    // Call repository
    // Return response
}
```

**Route registration:** `crates/axiam-api-rest/src/server.rs` — `register_api_v1_routes::<C>()` generic function

## Module Organization

**Per-crate `lib.rs` pattern:**
```rust
//! Crate-level doc comment describing purpose.

pub mod submodule_a;
pub mod submodule_b;

pub use submodule_a::PublicType;
pub use submodule_b::OtherPublicType;
```

**Handler module (`mod.rs`):** pure `pub mod` declarations, one per entity (plural names):
```rust
pub mod users;
pub mod tenants;
pub mod organizations;
```

**Repository module (`mod.rs`):** `mod` + `pub use` for each repository type

## Derive Patterns

**Domain models** (`axiam-core`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
```
- Enums additionally derive `PartialEq, Eq` when used in assertions

**DB row structs** (`axiam-db`):
```rust
#[derive(Debug, SurrealValue)]
```
- Use `surrealdb_types::SurrealValue` derive, NOT serde `Deserialize`

**API request types**:
```rust
#[derive(Debug, Deserialize, utoipa::ToSchema)]
```

**API response types**:
```rust
#[derive(Debug, Serialize, utoipa::ToSchema)]
```

**Update structs** use `Option<T>` for all fields and derive `Default`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub email: Option<String>,
    // For nullable fields: Option<Option<T>>
    // Some(Some(val)) = set, Some(None) = clear, None = no change
    pub mfa_secret: Option<Option<String>>,
}
```

## Logging

**Framework:** `tracing` crate (not `log`)
- Subscriber: `tracing-subscriber` with `EnvFilter` and JSON formatting
- HTTP request tracing: `tracing-actix-web::TracingLogger` middleware
- Default filter: `axiam=info` (override via `RUST_LOG` env var)

**Usage pattern:**
```rust
use tracing::info;
info!("Descriptive message: {}", variable);
```

## Comments

**Module-level doc comments:** Every module file starts with `//!` doc comment:
```rust
//! User domain model.
//! SurrealDB implementation of [`UserRepository`].
```

**Struct/function doc comments:** `///` for public items, especially:
- Repository trait methods
- Handler functions (supplemented by `#[utoipa::path]`)
- Complex helper functions

**Section separators:** Use comment blocks to separate logical sections:
```rust
// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------
```

## Configuration

**Pattern:** Nested `Deserialize` structs with `#[serde(default)]`:
```rust
#[derive(Debug, Deserialize)]
struct AppConfig {
    #[serde(default)]
    server: ServerConfig,
    #[serde(default)]
    db: DbConfig,
    #[serde(default)]
    auth: AuthConfig,
}
```

**Loading:** `config` crate with layered sources (defaults + env vars with `AXIAM__` prefix)

## OpenAPI Documentation

**Pattern:** All handler functions annotated with `#[utoipa::path(...)]`:
```rust
#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = UserResponse),
    ),
    security(("bearer" = []))
)]
```

**Schema generation:** Types derive `utoipa::ToSchema` and optionally `utoipa::IntoParams` (for query params like `Pagination`)

---

*Convention analysis: 2026-03-28*
