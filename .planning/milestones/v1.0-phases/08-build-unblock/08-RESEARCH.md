# Phase 8: Build Unblock (Wave 0) - Research

**Researched:** 2026-06-10
**Domain:** Rust Cargo dependency management, `-D warnings` compliance
**Confidence:** HIGH (all findings verified by running `cargo check/build` against the actual codebase)

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-12 | `axiam-server` must compile and CI build must pass under `-D warnings` | Exact dependency gaps and warning sources verified by `cargo build` output — fixes are mechanical |
</phase_requirements>

---

## Summary

`axiam-server` currently fails to compile (13 errors) because `uuid`, `chrono`, `serde_json`, and `rsa` are listed only in `[dev-dependencies]` but all four are used in `src/cleanup.rs` (main library source). Moving `uuid`, `chrono`, and `serde_json` to `[dependencies]` with `workspace = true` and adding a direct `sha2 = { workspace = true }` dependency fixes the build errors. Separately, `cleanup.rs` lines 260 and 399 use `rsa::sha2::{Digest, Sha256}` as a path to reach the `sha2` crate re-exported by `rsa`; after adding `sha2` as a direct dep these two `use` statements must be rewritten to `sha2::{Digest, Sha256}`. Once `sha2` is a direct dep, `rsa` is no longer referenced in any non-test file in `axiam-server`, so it can be dropped from `[dev-dependencies]` entirely (test files `req5_oidc_e2e.rs` and `req5_clock_skew.rs` use `rsa` types directly and must keep it, but those are test-only usages that legitimately belong in `[dev-dependencies]`). A separate set of 9 warnings in test files must be cleared before the `--tests` path (used by `cargo clippy --all-targets`) passes `-D warnings`.

**Primary recommendation:** Three changes, applied in order: (1) Cargo.toml dependency relocation, (2) cleanup.rs import fix, (3) remove unused imports/variables in test files.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Cargo dependency graph | Build system | — | Dependency placement is a Cargo manifest concern |
| Import resolution | Compiler | — | `use` statement correctness is a source-level fix |
| Warning suppression | Test source files | — | Unused-import/variable warnings live in test integration files |
| CI build gate | `.github/workflows/ci.yml` | — | `RUSTFLAGS=-Dwarnings` is set globally in the CI env |

---

## Standard Stack

No new packages required. All needed crates already exist in `[workspace.dependencies]`.

| Crate | Already in workspace? | Needs moving |
|-------|----------------------|--------------|
| `uuid` | Yes (`uuid = { version = "1", … }`) | Dev → prod deps |
| `chrono` | Yes (`chrono = { version = "0.4", … }`) | Dev → prod deps |
| `serde_json` | Yes (`serde_json = "1"`) | Dev → prod deps |
| `sha2` | Yes (`sha2 = "0.10"`) | Add fresh to prod deps |
| `rsa` | Yes (dev dep) | Keep in dev-deps (still used by test files) |

[VERIFIED: cargo build output + Cargo.toml inspection]

---

## Package Legitimacy Audit

No new packages are introduced in this phase. All crates are already present in the workspace. Legitimacy audit is not required.

---

## Current State — Exact Findings

### `crates/axiam-server/Cargo.toml` — dependency placement

**`[dependencies]`** (current — relevant crates only):
- `surrealdb = { workspace = true }` — present
- `hex = { workspace = true }` — present
- `uuid` — ABSENT
- `chrono` — ABSENT
- `serde_json` — ABSENT
- `sha2` — ABSENT

**`[dev-dependencies]`** (current):
- `uuid = { workspace = true }` — present (line 52)
- `chrono = { workspace = true }` — present (line 53)
- `serde_json = { workspace = true }` — present (line 56)
- `rsa = { version = "0.9", features = ["sha2"] }` — present (line 58)

[VERIFIED: Read crates/axiam-server/Cargo.toml]

### `crates/axiam-server/src/cleanup.rs` — problematic `use` statements

Line 260 (inside `purge_user` function body):
```rust
use rsa::sha2::{Digest, Sha256};
```

Line 399 (inside `process_export_job` function body):
```rust
use rsa::sha2::{Digest, Sha256};
```

Both must become:
```rust
use sha2::{Digest, Sha256};
```

Additional usages in cleanup.rs requiring `chrono`, `serde_json`, `uuid` to be prod deps:
- Line 33: `use chrono::Utc;`
- Line 36: `use uuid::Uuid;`
- Lines 321, 404, 425, 447, 450, 470, 508, 526, 534: `serde_json::json!(…)` / `serde_json::Value`

[VERIFIED: Read crates/axiam-server/src/cleanup.rs]

### `rsa` usage after fix

After changing both `use rsa::sha2::…` to `use sha2::…`, grep for `rsa` in `crates/axiam-server/src/` returns zero matches. `rsa` is only used in:
- `tests/req5_oidc_e2e.rs` lines 20–23: `use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, pkcs8::EncodePublicKey, traits::PublicKeyParts}`
- `tests/req5_clock_skew.rs` lines 21–23: same `rsa` imports

These are legitimate test-only uses. `rsa` must STAY in `[dev-dependencies]`. The ROADMAP's claim "drop rsa from binary deps if now unused" is correct — `rsa` is already only in dev-deps; there is nothing to drop from `[dependencies]` (it was never there).

[VERIFIED: grep on crates/axiam-server/src/]

---

## Build Failure Verification

### Binary build (lib + bin, no tests)

```
RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features
```
Result: **13 errors, 0 warnings** (confirmed by running the command)

Errors by cause:
| Error | File | Line(s) | Root cause |
|-------|------|---------|------------|
| E0432 unresolved import `chrono` | cleanup.rs | 33 | `chrono` not in `[dependencies]` |
| E0432 unresolved import `uuid` | cleanup.rs | 36 | `uuid` not in `[dependencies]` |
| E0433 cannot find `rsa` | cleanup.rs | 260, 399 | `rsa` not in `[dependencies]` (and shouldn't be — sha2 path fix resolves this) |
| E0433 cannot find `serde_json` | cleanup.rs | 321, 425, 447, 450, 470, 508, 526, 534 | `serde_json` not in `[dependencies]` |
| E0433 cannot find `chrono` | cleanup.rs | 404 | `chrono` not in `[dependencies]` |

**Consequence:** `cargo build --workspace` in CI fails because `axiam-server` (bin) is part of the workspace. This blocks all downstream compilation.

### Test compilation (library + tests)

```
RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features --tests
```
Result: **22 errors, 1 warning** — includes the 13 binary errors PLUS 9 warnings-turned-errors from test files.

[VERIFIED: both commands run and output captured]

---

## The 9 Test Warnings (must be cleared for `-D warnings` compliance)

These are warnings in test files that become errors under `-D warnings` (relevant to `cargo clippy --all-targets` in CI):

| # | Warning type | File | Line | Item |
|---|-------------|------|------|------|
| 1 | unused import | `tests/cleanup_task.rs` | 11 | `use std::sync::Arc` |
| 2 | unused import | `tests/req5_oidc_e2e.rs` | 18 | `Utc` in `use chrono::{Duration as CDuration, Utc}` |
| 3 | unused import | `tests/req5_oidc_e2e.rs` | 22 | `use rsa::pkcs8::EncodePublicKey` |
| 4 | unused imports | `tests/req5_oidc_e2e.rs` | 476 | `JwksCacheMap` and `STALE_WINDOW` in the same `use` |
| 5 | unused import | `tests/req5_secret_at_rest.rs` | 16 | `use base64::Engine` |
| 6 | unused import | `tests/req5_secret_at_rest.rs` | 17 | `use base64::engine::general_purpose::STANDARD` |
| 7 | unused variable | `tests/req5_clock_skew.rs` | 74 | `cache: Arc<JwksCache>` — prefix with `_cache` |
| 8 | unused mut | `tests/req5_secret_at_rest.rs` | 45 | `let mut result = db` — remove `mut` |
| 9 | unused variable | `tests/req7_service_account_aud.rs` | 276 | `let app = test_app!(…)` — prefix with `_app` |

The ROADMAP says "12 warnings" — the actual count is **9**. Either the ROADMAP was slightly off, or some warnings were already fixed before this research. Count confirmed by two independent runs of `cargo check --tests -p axiam-server --no-default-features`.

[VERIFIED: cargo check --tests output]

---

## CI Build Job Analysis

**Relevant CI jobs** (`.github/workflows/ci.yml`):

| Job | Command | RUSTFLAGS | Compiles tests? | Currently fails? |
|-----|---------|-----------|-----------------|-----------------|
| `build` | `cargo build --workspace` | `-Dwarnings` | No | YES (13 errors in cleanup.rs) |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` | — | Yes (`--all-targets`) | YES (13 errors + 9 warnings as errors) |
| `build-no-saml` | `cargo check -p axiam-federation -p axiam-api-rest -p axiam-server --no-default-features` | unset | No | YES (same 13 errors) |
| `test` | `cargo test --workspace` | `-Dwarnings` | Yes (implicit) | YES (same errors) |

The `build` job runs `cargo build --workspace` with `RUSTFLAGS="-Dwarnings"` set in the `env:` block. Since `axiam-server` is part of the workspace, it fails on the 13 compilation errors in `cleanup.rs`. This is the primary blocker; all other jobs cascade-fail because they also compile `axiam-server`.

**Local reproduction command (no-default-features for Arch compatibility):**
```bash
RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features
```
This reproduces the exact failure without needing SAML/libxmlsec1.

[VERIFIED: CI workflow file read; build commands run locally]

---

## Architecture Patterns

No architectural changes required. This is a pure dependency manifest + import fix.

### Fix pattern for Cargo.toml

Move from `[dev-dependencies]` to `[dependencies]`:
```toml
# [dependencies] — ADD these:
uuid = { workspace = true }
chrono = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }

# [dev-dependencies] — REMOVE these three (keep rsa):
# uuid = { workspace = true }      ← remove
# chrono = { workspace = true }    ← remove
# serde_json = { workspace = true } ← remove
# rsa = { version = "0.9", features = ["sha2"] } ← KEEP (test files use rsa types)
```

### Fix pattern for cleanup.rs import

```rust
// Before (lines 260 and 399):
use rsa::sha2::{Digest, Sha256};

// After:
use sha2::{Digest, Sha256};
```

### Fix pattern for test warning removals

Per-file actions:
- `tests/cleanup_task.rs:11` — delete `use std::sync::Arc;`
- `tests/req5_oidc_e2e.rs:18` — change to `use chrono::Duration as CDuration;` (drop `Utc`)
- `tests/req5_oidc_e2e.rs:22` — delete `use rsa::pkcs8::EncodePublicKey;`
- `tests/req5_oidc_e2e.rs:476` — change to `use axiam_federation::jwks_cache::JwksCacheEntry;`
- `tests/req5_secret_at_rest.rs:16` — delete `use base64::Engine;`
- `tests/req5_secret_at_rest.rs:17` — delete `use base64::engine::general_purpose::STANDARD;`
- `tests/req5_clock_skew.rs:74` — rename field to `_cache`
- `tests/req5_secret_at_rest.rs:45` — change `let mut result` to `let result`
- `tests/req7_service_account_aud.rs:276` — change `let app` to `let _app`

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead |
|---------|-------------|-------------|
| Dependency availability check | Custom build scripts | Standard Cargo `[dependencies]` placement |
| Warning suppression | `#[allow(…)]` attributes in prod code | Fix the underlying issue (remove unused items) |

`#[allow(unused_imports)]` is not an acceptable fix for test files when the imports are genuinely unused — remove them.

---

## Common Pitfalls

### Pitfall 1: Removing `rsa` from `[dev-dependencies]`
**What goes wrong:** The ROADMAP says "drop `rsa` from binary deps if now unused." `rsa` was NEVER in `[dependencies]` (binary deps) — it was always in `[dev-dependencies]`. After the `sha2` import fix, `rsa` is still needed in `[dev-dependencies]` for `req5_oidc_e2e.rs` and `req5_clock_skew.rs`.
**Prevention:** Do NOT remove `rsa` from `[dev-dependencies]`.

### Pitfall 2: Forgetting `sha2 = { workspace = true }` in `[dependencies]`
**What goes wrong:** Moving the `chrono`/`uuid`/`serde_json` entries and fixing the `use rsa::sha2` imports is not enough — without a direct `sha2` dep, the `sha2::{Digest, Sha256}` import resolves only because `rsa` re-exports it. That re-export is an implementation detail of the `rsa` crate with `sha2` feature, not a stable API surface.
**Prevention:** Always add `sha2 = { workspace = true }` to `[dependencies]` explicitly.

### Pitfall 3: `--tests` vs default build
**What goes wrong:** Running `cargo build -p axiam-server` (no `--tests`) passes after the Cargo.toml + cleanup.rs fix, but `cargo clippy --all-targets` still fails due to test-file warnings. Both must be fixed.
**Prevention:** Verify with both `cargo build -p axiam-server` (binary) and `cargo clippy -p axiam-server --tests -- -D warnings` (tests).

### Pitfall 4: `req5_oidc_e2e.rs:476` unused import in inner module
**What goes wrong:** The unused `JwksCacheMap` and `STALE_WINDOW` imports are inside a nested `mod` block (line 476), not at the file top level. Grep for `^use` at file top won't surface them.
**Prevention:** The exact location is line 476, inside a `mod` block. The `use` statement is `use axiam_federation::jwks_cache::{JwksCacheEntry, JwksCacheMap, STALE_WINDOW};` — drop `JwksCacheMap` and `STALE_WINDOW`, keep `JwksCacheEntry`.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness + tokio-test |
| Config file | none (Cargo workspace) |
| Quick run command | `cargo build -p axiam-server --no-default-features` |
| Full suite command | `cargo clippy -p axiam-server --tests --no-default-features -- -D warnings` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | Notes |
|--------|----------|-----------|-------------------|-------|
| REQ-12 SC1 | `cargo build -p axiam-server` succeeds | Build | `cargo build -p axiam-server --no-default-features` | Fails today (13 errors) |
| REQ-12 SC2 | cleanup.rs uses `sha2::` not `rsa::sha2::` | Static | `grep -n 'rsa::sha2' crates/axiam-server/src/cleanup.rs` | Must return 0 lines after fix |
| REQ-12 SC3 | CI `build` job goes green | CI | Run CI on branch or `cargo build --workspace` locally | Blocked by SC1 |
| REQ-12 SC4 | 9 test warnings cleared, `-D warnings` passes | Build+lint | `cargo clippy -p axiam-server --tests --no-default-features -- -D warnings` | Fails today |

### Validation Command Sequence

After completing all changes, run in order:

```bash
# 1. Binary build must succeed (zero errors, zero warnings)
RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features

# 2. Test build must also compile cleanly
RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features --tests

# 3. Clippy --all-targets must pass with -D warnings
cargo clippy -p axiam-server --all-targets --no-default-features -- -D warnings

# 4. Confirm rsa::sha2 is gone
grep -n 'rsa::sha2' crates/axiam-server/src/cleanup.rs
# Expected: no output (0 matches)

# 5. Confirm rsa still present in dev-deps (for test files)
grep 'rsa' crates/axiam-server/Cargo.toml
# Expected: only [dev-dependencies] entry remains
```

**CI criterion 3 check:** The CI `build` job runs `cargo build --workspace` with `RUSTFLAGS="-Dwarnings"`. After the fix, this must complete with 0 errors. The `build-no-saml` job runs `cargo check -p … --no-default-features` (also affected). Both jobs use Ubuntu, which has SAML/libxmlsec1 available — the `--no-default-features` flag can be omitted for CI simulation, but locally on Arch it is required.

### Wave 0 Gaps

- [ ] No new test files needed — phase is build-unblock only
- [ ] `cargo fmt -p axiam-server` should be run after edits (per project convention)
- [ ] `cargo clippy -p axiam-server --all-targets --no-default-features -- -D warnings` is the final gate

---

## Security Domain

This phase contains no security-relevant code changes. All changes are:
- Cargo dependency placement (manifest metadata)
- `use` statement path corrections
- Unused import/variable removal in test files

ASVS categories are not applicable to this phase.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | cargo build | ✓ | (stable, on PATH) | — |
| protobuf-compiler | axiam-api-grpc (workspace) | Must be present | — | Build with `-p axiam-server` scopes away from grpc |
| libxmlsec1/libxml2 | SAML feature | ✗ on Arch | — | Use `--no-default-features` (project convention) |

All fixes are source-code-only. No new tools or services required.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| — | — | — | — |

All claims in this research were verified by running cargo commands against the actual codebase. No assumed claims.

---

## Open Questions

None. All ambiguities resolved by direct code inspection and build runs.

---

## Sources

### Primary (HIGH confidence)
- `crates/axiam-server/Cargo.toml` — dependency placement verified by direct read
- `crates/axiam-server/src/cleanup.rs` — import lines 260, 399 verified by direct read
- `cargo build -p axiam-server --no-default-features` run output — 13 errors confirmed
- `cargo check --tests -p axiam-server --no-default-features` run output — 9 warnings confirmed
- `.github/workflows/ci.yml` — CI job commands and `RUSTFLAGS` setting verified by direct read
- `Cargo.toml` (workspace root) — sha2/uuid/chrono/serde_json workspace dep presence verified

---

## Metadata

**Confidence breakdown:**
- Current build state: HIGH — run confirmed
- Dependency placement: HIGH — Cargo.toml read
- Import fix locations: HIGH — source lines read and grep verified
- Warning enumeration: HIGH — cargo check output captured

**Research date:** 2026-06-10
**Valid until:** Until any commit modifies `crates/axiam-server/Cargo.toml` or `src/cleanup.rs`
