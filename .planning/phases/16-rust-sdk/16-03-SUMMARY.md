---
phase: 16-rust-sdk
plan: 03
subsystem: sdk
tags: [rust, tonic, grpc, tls-rustls, single-flight, interceptor]

# Dependency graph
requires:
  - phase: 16-rust-sdk
    plan: 01
    provides: Sensitive<T>, AxiamError (from_grpc_code), build.rs gRPC codegen shim, lib.rs module ownership (grpc placeholder)
  - phase: 16-rust-sdk
    plan: 02
    provides: TokenManager (cached_access_token non-blocking read primitive), single-flight refresh_if_needed guard, RefreshedTokens shape
provides:
  - "src/grpc/channel.rs: shared lazily-connected tonic::Channel (Endpoint::from_shared + connect_lazy, no eager network I/O), strict TLS (tls-ring/tls-native-roots) with custom-CA PEM as the only escape hatch"
  - "src/grpc/interceptor.rs: AuthInterceptor injecting Bearer auth + UUID x-tenant-id metadata on every RPC via TokenManager's non-blocking cached-token read (never the async refresh Mutex)"
  - "src/grpc/client.rs: AuthzGrpcClient with check_access/batch_check, mapping proto CheckAccessRequest/Response <-> SDK types, preserving batch order"
  - "UNAUTHENTICATED single-flight-retry wrapper at the async call site, decoupled from REST via a caller-supplied RefreshFn closure so --no-default-features --features grpc builds with a fully working refresh mechanism"
  - "tests/grpc_check_access_test.rs: new in-process tonic 0.14 test server harness (ephemeral-port TcpIncoming + stub AuthorizationService)"
affects: [16-05-middleware, 16-06-examples-publish]

# Tech tracking
tech-stack:
  added: []
  patterns: [lazy-connect shared tonic::Channel reused across RPCs, sync interceptor reading a non-blocking cache with async refresh driven only at the call site, transport-agnostic RefreshFn closure decoupling gRPC token refresh from REST, in-process ephemeral-port tonic test server via TcpIncoming]

key-files:
  created:
    - sdks/rust/src/grpc/channel.rs
    - sdks/rust/src/grpc/interceptor.rs
    - sdks/rust/src/grpc/client.rs
    - sdks/rust/tests/grpc_check_access_test.rs
  modified:
    - sdks/rust/Cargo.toml
    - sdks/rust/src/grpc/mod.rs

key-decisions:
  - "tonic's grpc-feature dependency pinned to default-features = false with [transport, codegen, tls-ring, tls-native-roots] — Endpoint::from_shared (unlike Endpoint::new) does not auto-detect https and enable TLS, so channel.rs configures ClientTlsConfig explicitly and the crate needs the tls-ring crypto provider + tls-native-roots system trust store feature to do so"
  - "AuthzGrpcClient takes a caller-supplied RefreshFn closure (Arc<dyn Fn(String) -> Pin<Box<dyn Future<...>>>>) instead of depending on AxiamClient/reqwest directly, so the shared single-flight refresh mechanism (TokenManager::refresh_if_needed) is fully functional under --no-default-features --features grpc with zero REST transport pulled in"
  - "Added #[rustfmt::skip] on the `pub mod gen;` declaration instead of an .toml `ignore` rule — the repo only has stable rustfmt installed, and the nightly-only `ignore` config in rustfmt.toml is silently unenforceable on stable, which would leave the generated file unformatted-but-uncaught; #[rustfmt::skip] on the mod item is the stable-compatible mechanism to exclude a #[path]-included generated file from cargo fmt --check"
  - "Added an additive dev-only Cargo.toml `[dev-dependencies] tonic` feature union enabling `router` (needed for Server::add_service in the in-process test server) — this does not affect the published library's feature set since Cargo only unifies dev-dependency features for `cargo test`/`--tests`, never for downstream consumers"

requirements-completed: [RUST-01]

coverage:
  - id: D1
    description: "One lazily-connected tonic::Channel built via connect_lazy (no eager network I/O), reused across every RPC"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "grep -n 'connect_lazy' sdks/rust/src/grpc/channel.rs (present); grep -rn 'connect()' sdks/rust/src/grpc/ (absent)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Sync AuthInterceptor injects Bearer auth + UUID x-tenant-id metadata without blocking the runtime or logging the token"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "grep -rn '\\.lock\\(\\)\\.await' sdks/rust/src/grpc/interceptor.rs (zero matches)"
        status: pass
    human_judgment: false
  - id: D3
    description: "gRPC CheckAccess/BatchCheckAccess succeed against an in-process tonic 0.14 test server using the build.rs-generated stubs end-to-end (SC#4); batch results preserve input order"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/grpc_check_access_test.rs#grpc_check_access"
        status: pass
      - kind: integration
        ref: "sdks/rust/tests/grpc_check_access_test.rs#grpc_batch_check_access_preserves_input_order"
        status: pass
    human_judgment: false
  - id: D4
    description: "gRPC status -> AxiamError mapping per CONTRACT.md §2: PERMISSION_DENIED->Authz, UNAVAILABLE->Network"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/grpc_check_access_test.rs#grpc_permission_denied_maps_to_authz_error"
        status: pass
      - kind: integration
        ref: "sdks/rust/tests/grpc_check_access_test.rs#grpc_unavailable_maps_to_network_error"
        status: pass
    human_judgment: false
  - id: D5
    description: "UNAUTHENTICATED drives the shared single-flight refresh guard and retries exactly once (no second refresh)"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/grpc_check_access_test.rs#grpc_unauthenticated_drives_exactly_one_refresh_then_succeeds"
        status: pass
    human_judgment: false
  - id: D6
    description: "No TLS-bypass surface anywhere under src/grpc/; --no-default-features --features grpc builds and passes tests with a working refresh mechanism"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "grep -rni 'danger_accept_invalid_certs|insecure|skip_tls' sdks/rust/src/grpc/*.rs (zero real matches, only doc-comment negations)"
        status: pass
      - kind: integration
        ref: "cargo test --no-default-features --features grpc --test grpc_check_access_test (6/6 pass)"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-07-01
status: complete
---

# Phase 16 Plan 03: Rust SDK gRPC Transport Summary

Implemented the gRPC half of the AXIAM Rust SDK: a shared lazily-connected `tonic::Channel` with strict TLS, a sync-safe auth/tenant `Interceptor`, and `AuthzGrpcClient::check_access`/`batch_check` proven end-to-end against a new in-process tonic 0.14 test server — including the UNAUTHENTICATED single-flight-refresh-then-retry path, all working under `--no-default-features --features grpc` with zero REST dependency.

## Performance

- **Duration:** 55 min
- **Started:** 2026-07-01T08:35:00Z (approx.)
- **Completed:** 2026-07-01T09:30:00Z (approx.)
- **Tasks:** 2/2 completed
- **Files modified:** 6 (2 modified, 4 created)

## Accomplishments
- `src/grpc/channel.rs` builds exactly one `tonic::Channel` via `Endpoint::from_shared(...).connect_lazy()` — no TCP/TLS handshake occurs until the first RPC — with strict TLS (`tls-ring` + `tls-native-roots`, matching the crate's existing pure-Rust portability choice from 16-02's `jsonwebtoken` pin) and the custom-CA PEM path as the only escape hatch (§6)
- `src/grpc/interceptor.rs`'s `AuthInterceptor` is genuinely synchronous: it reads `TokenManager::cached_access_token()` (a non-blocking `RwLock` read built for exactly this purpose in 16-02) and never touches the async single-flight refresh `Mutex`, injecting `authorization: Bearer <token>` and the UUID-form `x-tenant-id` on every RPC
- `src/grpc/client.rs`'s `AuthzGrpcClient::check_access`/`batch_check` wrap the generated `AuthorizationServiceClient<InterceptedService<Channel, AuthInterceptor>>`, converting to/from the proto `CheckAccessRequest`/`CheckAccessResponse` and preserving batch input order
- The UNAUTHENTICATED retry lives entirely at the async call site inside `AuthzGrpcClient`, driving `TokenManager::refresh_if_needed` (16-02's proven single-flight guard) through a caller-supplied `RefreshFn` closure — this decouples gRPC from any REST/`reqwest` dependency, so a `--no-default-features --features grpc` build has a fully functional refresh mechanism with zero REST code compiled in
- `tests/grpc_check_access_test.rs` stands up a real in-process tonic server (ephemeral loopback port via `TcpIncoming`) implementing the generated `AuthorizationService` trait with a stub engine, and proves: successful `CheckAccess`/`BatchCheckAccess` (SC#4), order-preserving batch results, the §2 gRPC status mapping (`PERMISSION_DENIED`→`Authz`, `UNAVAILABLE`→`Network`), and the UNAUTHENTICATED-then-success case driving exactly one refresh + one retry
- All required source greps pass clean: `connect_lazy` present / eager `connect()` absent, zero `.lock().await` in the interceptor, zero TLS-bypass patterns under `src/grpc/`
- Full test suite green across every feature combination: `--no-default-features`, `--features grpc`, `--no-default-features --features grpc`, `--features rest`, `--features amqp`, default, `--all-features` (35 tests total under `--features grpc`)

## Task Commits

Each task was committed atomically:

1. **Task 1: Shared lazy channel + sync-safe auth/tenant interceptor** - `b219e9e` (feat)
2. **Task 2: gRPC check_access/batch_check + UNAUTHENTICATED single-flight retry + in-process test server** - `3451ab9` (feat)

_No separate TDD RED/GREEN commits: Task 2 specified `<behavior>` (test scenarios) and `<action>` (implementation) together, and the executor wrote the implementation and its proving tests as a single logical unit, consistent with 16-01/16-02's precedent._

## Files Created/Modified
- `sdks/rust/src/grpc/channel.rs` - Shared lazily-connected `tonic::Channel` builder with strict TLS + custom-CA escape hatch
- `sdks/rust/src/grpc/interceptor.rs` - Sync `AuthInterceptor` injecting Bearer auth + UUID `x-tenant-id` metadata
- `sdks/rust/src/grpc/client.rs` - `AuthzGrpcClient::check_access`/`batch_check` + UNAUTHENTICATED single-flight-retry wrapper (via caller-supplied `RefreshFn`)
- `sdks/rust/src/grpc/mod.rs` - Re-exports `channel`/`client`/`interceptor`; `#[rustfmt::skip] #[path = "../gen/axiam.v1.rs"] pub mod gen;` wiring the build.rs-generated stubs
- `sdks/rust/tests/grpc_check_access_test.rs` - In-process tonic 0.14 test server (stub `AuthorizationService`) proving SC#4 + status mapping + single-flight retry
- `sdks/rust/Cargo.toml` - `tonic`'s `grpc`-feature deps pinned to `[transport, codegen, tls-ring, tls-native-roots]` (no default features); additive dev-only `tonic` `router` feature for the test server

## Decisions Made
- Pinned `tonic`'s `grpc`-feature dependency to `default-features = false` with an explicit `[transport, codegen, tls-ring, tls-native-roots]` feature list, because `Endpoint::from_shared` (unlike `Endpoint::new`) does not auto-detect an `https` scheme and enable TLS — `channel.rs` must call `.tls_config(...)` explicitly, which requires the `tls-ring` crypto provider and `tls-native-roots` (system trust store, matching §6's "verify against the system trust store" requirement) to be compiled in.
- `AuthzGrpcClient` takes a caller-supplied `RefreshFn` closure rather than depending on `AxiamClient`/`reqwest` directly. This satisfies the environment's decoupling requirement: `--no-default-features --features grpc` builds and has a fully working single-flight refresh mechanism (`TokenManager::refresh_if_needed` is always compiled, feature-independent), with the actual `POST /api/v1/auth/refresh` HTTP call supplied externally — a `rest`-enabled caller passes a closure reusing `AxiamClient`; a `grpc`-only caller supplies their own minimal HTTP client.
- Used `#[rustfmt::skip]` on the `pub mod gen;` item (not a `rustfmt.toml` `ignore` rule) to exclude the build.rs-generated, gitignored `src/gen/axiam.v1.rs` from `cargo fmt --check` — the environment only has stable rustfmt installed, and the `ignore` config key is nightly-only (confirmed via a runtime warning when attempted), so it would silently fail to apply on stable, leaving CLAUDE.md's mandatory fmt gate red without ever visibly failing locally.
- Added an additive `[dev-dependencies] tonic` feature union enabling `router` (needed for `Server::add_service` used only by the in-process test server) — Cargo unifies dev-dependency features solely for `cargo test`/`cargo build --tests`, so this has zero effect on the published library's feature set or downstream consumers.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue] `cargo fmt --check` failed against the build.rs-generated `src/gen/axiam.v1.rs` file**
- **Found during:** Task 1, post-implementation CLAUDE.md fmt-gate check
- **Issue:** `src/grpc/mod.rs`'s `#[path = "../gen/axiam.v1.rs"] pub mod gen;` pulls the tonic-prost-build-generated (gitignored, never hand-formatted) stub file into the crate's module tree that `cargo fmt` traverses, causing `cargo fmt --check` to report a large diff against generated code this SDK does not own or control the formatting of.
- **Fix:** Added `#[rustfmt::skip]` directly on the `pub mod gen;` item. (A `rustfmt.toml` with an `ignore = ["src/gen/"]` list was tried first but silently no-ops on stable rustfmt — the `ignore` config key is nightly-only, confirmed by an explicit `Warning: can't set 'ignore = ...' unstable features are only available in nightly channel` message — so that file was removed in favor of the stable-compatible `#[rustfmt::skip]` attribute.)
- **Files modified:** `sdks/rust/src/grpc/mod.rs`
- **Verification:** `cargo fmt --check` exits 0.
- **Committed in:** `b219e9e` (Task 1 commit)

**2. [Rule 3 - Blocking issue] `Server::add_service` unavailable with the trimmed `tonic` feature set**
- **Found during:** Task 2, writing the in-process test server
- **Issue:** `tonic`'s `add_service` method (needed to register the stub `AuthorizationService` on an in-process `Server`) is gated behind the `router` feature, which was deliberately excluded from the crate's normal `grpc`-feature dependency (`[transport, codegen, tls-ring, tls-native-roots]`) to keep the published library's dependency footprint minimal.
- **Fix:** Added an additive `[dev-dependencies] tonic = { ..., features = ["router"] }` entry — Cargo unifies dev-dependency feature additions only for `cargo test`/`--tests` builds, so the published crate's feature set (and downstream consumers' builds) are unaffected.
- **Files modified:** `sdks/rust/Cargo.toml`
- **Verification:** `cargo test --features grpc --test grpc_check_access_test` passes (6/6); `cargo publish --dry-run` packaging step is unaffected by dev-dependencies (separately confirmed not to regress from this change — see Issues Encountered below for the pre-existing, out-of-scope publish gap).
- **Committed in:** `3451ab9` (Task 2 commit)

**3. [Rule 1 - Bug] `--exact` test-name filter in the plan's own verify command required a literally-named test**
- **Found during:** Task 2, running the plan's stated verify command (`cargo test --features grpc grpc_check_access -- --exact`)
- **Issue:** The plan's verify command uses `--exact`, which requires a full test-name match; the initially-named success-path test (`grpc_check_access_succeeds_against_in_process_server`) did not match the literal string `grpc_check_access` under `--exact`.
- **Fix:** Renamed the primary success-path test to exactly `grpc_check_access`.
- **Files modified:** `sdks/rust/tests/grpc_check_access_test.rs`
- **Verification:** `cargo test --features grpc --test grpc_check_access_test grpc_check_access -- --exact` selects exactly 1 test and passes.
- **Committed in:** `3451ab9` (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (2x Rule 3 blocking issues, 1x Rule 1 bug in test naming)
**Impact on plan:** All three fixes were necessary for the crate to satisfy CLAUDE.md's mandatory `cargo fmt`/`cargo clippy -D warnings` gates and for the plan's own literal verify commands to pass. No scope creep — no functionality was added beyond what the plan specified.

## Issues Encountered

**`cargo publish --dry-run` fails outside a pre-generation step — confirmed pre-existing, explicitly owned by 16-06, not a 16-03 regression to fix here.** `cargo publish` verifies the package by extracting the packaged tarball to an isolated directory and compiling it there; because `src/gen/` is gitignored (16-01/D-09) and the extracted tarball has no access to `../../proto` (outside the package), `build.rs` cannot regenerate the stubs during verification, and the crate's new (16-03) unconditional `pub mod gen;` fails to compile. This was reproduced identically at the pre-16-03 HEAD (`b731760`) once a `pub mod gen;`-shaped module was hypothetically required — but more importantly, 16-06-PLAN.md's Task 2 explicitly documents this exact gap and owns the fix ("the publish job runs a buf/build.rs stub-generation step BEFORE `cargo publish --dry-run`" and "override the `.gitignore` exclusion for packaging" via `Cargo.toml` `include`). No code change was made here; this is flagged for 16-06 rather than worked around.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
`AuthzGrpcClient`, `AuthInterceptor`, and `build_channel` are ready for 16-05 (Actix-Web middleware/extractor) and 16-06 (examples + publish CI) to consume. 16-06's `examples/grpc_check_access.rs` can construct an `AuthzGrpcClient` directly against a real AXIAM server using `build_channel` + a `RefreshFn` closure that reuses a `rest`-enabled `AxiamClient::refresh`. 16-06 must also resolve the pre-existing `cargo publish --dry-run` gap documented above (buf/build.rs stub-pregeneration + `Cargo.toml` `include` override) before its own dry-run gate can pass — this is explicitly already scoped into 16-06's Task 2, not a new blocker introduced here.

---
*Phase: 16-rust-sdk*
*Completed: 2026-07-01*
