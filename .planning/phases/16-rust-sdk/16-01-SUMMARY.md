---
phase: 16-rust-sdk
plan: 01
subsystem: sdk
tags: [rust, cargo, sdk, error-handling, redaction, tonic, build-rs]

# Dependency graph
requires:
  - phase: 15-sdk-foundation
    provides: sdks/CONTRACT.md (binding cross-language behavioral contract), sdks/buf.gen.yaml, proto/axiam/v1/*.proto, sdks/rust/ scaffold (placeholder Cargo.toml/lib.rs)
provides:
  - Publishable axiam-sdk Cargo manifest (v0.1.0, MSRV 1.88, feature layout: default=[rest,grpc,amqp], observability off-by-default)
  - Sensitive<T> redaction newtype (hand-written Debug/Display, pub(crate)-only expose())
  - AxiamError enum (Auth/Authz/Network) with from_http_status/from_grpc_code mapping helpers
  - Feature-gated build.rs gRPC codegen shim (tonic-prost-build, no-op without grpc feature)
  - Finalized src/lib.rs owning all Phase 16 module declarations (client/token/rest/grpc/amqp/middleware)
  - Placeholder module files so downstream plans 16-02..16-05 never edit lib.rs
affects: [16-02-rest-token, 16-03-grpc, 16-04-amqp, 16-05-middleware, 16-06-examples-publish]

# Tech tracking
tech-stack:
  added: [tokio 1, reqwest 0.12 (optional/rest), tonic 0.14 + tonic-prost + prost (optional/grpc), lapin 4 + hmac + sha2 + hex (optional/amqp), jsonwebtoken 10, thiserror 2, serde/serde_json, uuid, url, backon, tracing (optional/observability), tonic-prost-build (build-dep), wiremock + tokio-test (dev-dep)]
  patterns: [Sensitive<T> newtype for token redaction, single lib.rs module-ownership to avoid parallel-plan merge conflicts, feature-gated transport modules, HTTP/gRPC status to error-category mapping helpers]

key-files:
  created:
    - sdks/rust/build.rs
    - sdks/rust/.gitignore
    - sdks/rust/src/sensitive.rs
    - sdks/rust/src/error.rs
    - sdks/rust/src/client.rs
    - sdks/rust/src/token/mod.rs
    - sdks/rust/src/rest/mod.rs
    - sdks/rust/src/grpc/mod.rs
    - sdks/rust/src/amqp/mod.rs
    - sdks/rust/src/middleware/mod.rs
    - sdks/rust/tests/sensitive_redaction_test.rs
  modified:
    - sdks/rust/Cargo.toml
    - sdks/rust/src/lib.rs

key-decisions:
  - "Added an empty [workspace] table to sdks/rust/Cargo.toml (not in original plan) — required so `cargo build`/`cargo metadata` don't try to join the root AXIAM workspace, which uses a different edition (2024 vs this crate's 2021) and would otherwise error with 'current package believes it's in a workspace when it's not'"
  - "Created src/client.rs as an empty placeholder module (not listed in this plan's files_modified) because lib.rs's `pub mod client;` declaration (mandated by the plan's Task 2 action text) requires the file to exist for the crate to compile — treated as Rule 3 (blocking issue)"
  - "AxiamError::Network carries `source: Option<Box<dyn Error + Send + Sync>>` rather than a `#[from]`-derived NetworkErrorCause, per the plan's own fallback guidance, since no transport error types exist yet in this plan"
  - "Added a `[lints.rust] unexpected_cfgs` allow for the not-yet-declared `actix` feature flag referenced in lib.rs, scoped narrowly to that one cfg value rather than suppressing the lint crate-wide"
  - "Added #[allow(dead_code)] to Sensitive::expose(), Sensitive::clone_inner(), and the test's HoldsToken.label field — all are genuinely unused until 16-02/16-03 wire in the first internal consumers; required to satisfy CLAUDE.md's `cargo clippy -D warnings` mandate"

patterns-established:
  - "Sensitive<T>: private inner field, no public Deref/Clone/Serialize, pub(crate) expose(), hand-written Debug/Display always redacting — every later plan wraps tokens in this type"
  - "lib.rs is the single owner of all Phase 16 module declarations; downstream plans fill module bodies only, never touch lib.rs, preventing parallel-execution merge conflicts"
  - "AxiamError::from_http_status / from_grpc_code centralize the CONTRACT.md §2 status-to-category mapping so every transport module (REST/gRPC) reuses the same two functions instead of re-deriving the mapping"

requirements-completed: [RUST-01]

coverage:
  - id: D1
    description: "Publishable Cargo manifest: version 0.1.0, MSRV 1.88, feature layout default=[rest,grpc,amqp] plus off-by-default observability, all transport deps optional/feature-gated"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "cargo metadata --no-deps (feature list + default array + rust-version)"
        status: pass
      - kind: integration
        ref: "cargo build -p axiam-sdk --no-default-features"
        status: pass
    human_judgment: false
  - id: D2
    description: "Sensitive<T> redacts token values in Debug ('Sensitive(<redacted>)') and Display ('[SENSITIVE]'), including when nested inside another struct's derived Debug; expose() is pub(crate) only"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "sdks/rust/tests/sensitive_redaction_test.rs#debug_redacts_token_and_never_contains_raw_value"
        status: pass
      - kind: unit
        ref: "sdks/rust/tests/sensitive_redaction_test.rs#display_redacts_token_and_never_contains_raw_value"
        status: pass
      - kind: unit
        ref: "sdks/rust/tests/sensitive_redaction_test.rs#nested_debug_delegates_to_redacting_impl"
        status: pass
    human_judgment: false
  - id: D3
    description: "AxiamError exposes exactly Auth/Authz/Network variants; from_http_status maps 401->Auth, 403/409->Authz, 400/408/429/5xx->Network per CONTRACT.md §2"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "sdks/rust/tests/sensitive_redaction_test.rs#from_http_status_maps_to_correct_category_and_never_leaks"
        status: pass
    human_judgment: false
  - id: D4
    description: "build.rs generates gRPC stubs under src/gen/ only when the grpc feature is enabled; no-op (and warns, does not fail) when the feature is off or proto files are missing"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "cargo build -p axiam-sdk --no-default-features (no src/gen/ output)"
        status: pass
      - kind: integration
        ref: "cargo build -p axiam-sdk --features grpc (src/gen/axiam.v1.rs generated)"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-01
status: complete
---

# Phase 16 Plan 01: Rust SDK Foundation Summary

Established the `axiam-sdk` crate skeleton: a publishable Cargo manifest with the four-feature transport layout (rest/grpc/amqp default-on, observability opt-in), the `Sensitive<T>` token-redaction newtype, the three-variant `AxiamError` enum with HTTP/gRPC status mapping, and a feature-gated `build.rs` gRPC codegen shim — all proven by a green 4-assertion redaction test.

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-01T07:20:00Z (approx.)
- **Completed:** 2026-07-01T07:46:49Z
- **Tasks:** 2/2 completed
- **Files modified:** 14 (2 modified, 12 created)

## Accomplishments
- `sdks/rust/Cargo.toml` is publishable-shaped: version 0.1.0, `rust-version = "1.88"`, Apache-2.0, `default = ["rest", "grpc", "amqp"]` plus off-by-default `observability`, every transport dependency gated behind its feature
- `Sensitive<T>` redacts in both `Debug` (`Sensitive(<redacted>)`) and `Display` (`[SENSITIVE]`), with a genuinely private inner field and a `pub(crate)`-only `expose()` accessor — verified never to leak `eyJ`-prefixed values even when nested inside another struct's derived `Debug`
- `AxiamError` exposes exactly `Auth`/`Authz`/`Network` with `from_http_status`/`from_grpc_code` mapping helpers matching CONTRACT.md §2's tables exactly
- `build.rs` compiles the three AXIAM protos into `src/gen/` via `tonic-prost-build` only when the `grpc` feature is active, warning (not failing) on missing proto inputs or a disabled feature
- `src/lib.rs` is now the single, final owner of all Phase 16 module declarations — plans 16-02 through 16-05 fill in module bodies only, eliminating merge-conflict risk from parallel execution

## Task Commits

Each task was committed atomically:

1. **Task 1: Author the publishable crate manifest with feature layout and pinned deps** - `2688cd9` (feat)
2. **Task 2: Implement Sensitive<T> redaction newtype, AxiamError enum, build.rs, and crate root** - `f30d6f3` (feat)

_No TDD RED/GREEN split commits were made: the plan's `tdd="true"` task specified `<behavior>` and `<action>` together and the executor implemented + tested Task 2 in a single commit after verification passed; both the implementation and the redaction test file were part of the same logical unit of work and are captured together._

## Files Created/Modified
- `sdks/rust/Cargo.toml` - Publishable manifest: features, pinned deps, MSRV, workspace-exclusion table, docs.rs metadata
- `sdks/rust/src/lib.rs` - Crate root; `#![forbid(unsafe_code)]`; owns all Phase 16 `pub mod` declarations
- `sdks/rust/src/sensitive.rs` - `Sensitive<T>` redaction newtype
- `sdks/rust/src/error.rs` - `AxiamError` enum + HTTP/gRPC status mapping helpers
- `sdks/rust/build.rs` - Feature-gated gRPC codegen shim
- `sdks/rust/.gitignore` - Ignores `/target`, `Cargo.lock`, `/src/gen/`
- `sdks/rust/src/client.rs` - Placeholder for 16-02's `AxiamClient`
- `sdks/rust/src/token/mod.rs` - Placeholder for 16-02's `TokenManager`/JWKS verifier
- `sdks/rust/src/rest/mod.rs` - Placeholder for 16-02's REST transport
- `sdks/rust/src/grpc/mod.rs` - Placeholder for 16-03's gRPC transport
- `sdks/rust/src/amqp/mod.rs` - Placeholder for 16-04's AMQP transport
- `sdks/rust/src/middleware/mod.rs` - Placeholder for 16-05's Actix extractor
- `sdks/rust/tests/sensitive_redaction_test.rs` - 4 assertions proving redaction + error mapping

## Decisions Made
- Added an empty `[workspace]` table to `sdks/rust/Cargo.toml` (Rule 3 — blocking issue not anticipated by the plan): without it, `cargo build`/`cargo metadata` fail with "current package believes it's in a workspace when it's not" because Cargo walks up to the root AXIAM `Cargo.toml`'s `[workspace]` table. The crate is deliberately standalone (edition 2021 vs the workspace's edition 2024), so opting out via an empty `[workspace]` table in the crate's own manifest is the standard, minimal fix — it does not require touching the root workspace manifest.
- Created `src/client.rs` as an empty placeholder (Rule 3): the plan's Task 2 action text mandates `pub mod client;` in `lib.rs` but does not list `src/client.rs` in the plan's `files_modified` frontmatter. Without the file, the crate does not compile. Following the plan's own stated preference ("Prefer option (a) — commit empty placeholder module files"), this placeholder was added consistent with the other five placeholder modules.
- `AxiamError::Network` stores `source: Option<Box<dyn std::error::Error + Send + Sync>>` (the plan's documented fallback shape) rather than a `#[from]`-derived cause type, since no concrete transport error types exist until 16-02/16-03/16-04 add them.
- Added a narrowly-scoped `[lints.rust] unexpected_cfgs` allow in `Cargo.toml` for the `actix` feature value (declared in `lib.rs` ahead of its Cargo.toml entry, which 16-05 adds) rather than disabling the lint crate-wide.
- Added `#[allow(dead_code)]` to `Sensitive::expose()`, `Sensitive::clone_inner()`, and the test helper struct's `label` field, each with an inline comment explaining they are intentionally unused until later plans wire in consumers — required to keep `cargo clippy -D warnings` (CLAUDE.md mandate) green without weakening the lint elsewhere.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue] Crate incorrectly joined the root AXIAM Cargo workspace**
- **Found during:** Task 1 verification (`cargo metadata --no-deps`)
- **Issue:** `cargo metadata`/`cargo build` failed with "current package believes it's in a workspace when it's not" — Cargo auto-discovered the ancestor `/home/user/axiam/Cargo.toml` `[workspace]` table.
- **Fix:** Added an empty `[workspace]` table to `sdks/rust/Cargo.toml`, opting the crate out of the ancestor workspace (standard Cargo pattern for standalone crates nested inside a larger repo).
- **Files modified:** `sdks/rust/Cargo.toml`
- **Verification:** `cargo metadata --no-deps` and `cargo build` both succeed afterward.
- **Committed in:** `2688cd9` (part of Task 1 commit)

**2. [Rule 3 - Blocking issue] `src/client.rs` did not exist but `lib.rs` requires `pub mod client;`**
- **Found during:** Task 2 (writing `lib.rs` per the plan's own action text)
- **Issue:** The plan's Task 2 `<action>` mandates declaring `pub mod client;` in `lib.rs` (for 16-02), but `src/client.rs` is not in this plan's `files_modified` list and does not exist. Without the file, `cargo build` fails with "file not found for module `client`".
- **Fix:** Created `sdks/rust/src/client.rs` as an empty placeholder module (doc comment only), matching the plan's explicitly stated preference for option (a) placeholder files over commented-out `pub mod` lines.
- **Files modified:** `sdks/rust/src/client.rs`
- **Verification:** `cargo build --no-default-features` and `cargo build --features grpc` both succeed.
- **Committed in:** `f30d6f3` (part of Task 2 commit)

**3. [Rule 1 - Bug] `cargo clippy -D warnings` failures on genuinely-unused-for-now code**
- **Found during:** Post-implementation CLAUDE.md compliance check (`cargo clippy -D warnings` is mandated by CLAUDE.md on all changes)
- **Issue:** `Sensitive::expose()`, `Sensitive::clone_inner()`, and the redaction test's `HoldsToken.label` field all triggered `dead_code` clippy errors under `-D warnings`, since no other code in this plan calls them yet.
- **Fix:** Added `#[allow(dead_code)]` with an inline comment on each, explaining the code is intentionally present now (required by the plan/contract) but not consumed until plans 16-02/16-03.
- **Files modified:** `sdks/rust/src/sensitive.rs`, `sdks/rust/tests/sensitive_redaction_test.rs`
- **Verification:** `cargo clippy --tests -- -D warnings` (all feature combinations: none, grpc, default) exits clean.
- **Committed in:** `f30d6f3` (part of Task 2 commit)

---

**Total deviations:** 3 auto-fixed (3x Rule 1/3 — blocking issues / bug fixes)
**Impact on plan:** All three fixes were necessary for the crate to compile and pass CLAUDE.md's mandatory `cargo fmt` + `cargo clippy -D warnings` gate. No scope creep — no functionality was added beyond what the plan specified.

## Issues Encountered
None beyond the deviations documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
`axiam-sdk` now builds and tests cleanly under `--no-default-features`, `--features grpc`, and default features. `Sensitive<T>` and `AxiamError` are ready for 16-02 (REST client, `TokenManager`, JWKS verifier) to consume via `crate::Sensitive`/`crate::AxiamError`. `lib.rs` needs no further edits from any downstream Phase 16 plan — 16-02 through 16-05 fill in their respective placeholder module files only (`src/client.rs`, `src/token/mod.rs`, `src/rest/mod.rs`, `src/grpc/mod.rs`, `src/amqp/mod.rs`, `src/middleware/mod.rs`), removing merge-conflict risk in the parallel waves described in ROADMAP.md. No blockers identified.

---
*Phase: 16-rust-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED

All 14 created/modified files verified present on disk. All 3 commit hashes (`2688cd9`, `f30d6f3`, `76073ee`) verified present in `git log --oneline --all`.
