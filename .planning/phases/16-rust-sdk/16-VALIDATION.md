---
phase: 16
slug: rust-sdk
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-30
---

# Phase 16 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `16-RESEARCH.md` § Validation Architecture (success criteria → test map).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (built-in) + `tokio::test` (async) + `wiremock` (REST mocking) + in-process `tonic` test server (gRPC) |
| **Config file** | `sdks/rust/Cargo.toml` `[dev-dependencies]` (no separate test config file) |
| **Quick run command** | `cargo test -p axiam-sdk --lib` |
| **Full suite command** | `cargo test -p axiam-sdk --all-features` |
| **Estimated runtime** | ~30–60 seconds (unit fast; integration bounded by mock servers, not network) |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p axiam-sdk --lib` (fast unit: `Sensitive<T>` redaction, error mapping, HMAC sign/verify vectors, JWKS `kid` lookup)
- **After every plan wave:** Run `cargo test -p axiam-sdk --all-features` (integration: wiremock REST flows, in-process gRPC server, single-flight concurrency, AMQP HMAC nack)
- **Before `/gsd-verify-work` (phase gate):** Full suite green **AND** `cargo publish --dry-run -p axiam-sdk` succeeds **AND** `grep -r 'eyJ' target/debug/` returns empty
- **Max feedback latency:** ~60 seconds

---

## Per-Task Verification Map

> Task IDs are assigned by the planner/executor. This map is seeded from the requirement → success-criterion test map; the executor fills `Task ID` / `Plan` / `Wave` / `Status` columns as tasks are created.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | — | — | RUST-01 (SC#1) | — | `login()`→typed `LoginResult{mfa_required}`; `verify_mfa` completes two-phase flow | integration | `cargo test -p axiam-sdk login_mfa_flow -- --exact` | ❌ W0 | ⬜ pending |
| TBD | — | — | RUST-01 (SC#2) | T-DoS (thundering-herd refresh) | 5 concurrent reqs on expired token ⇒ exactly 1 refresh | integration | `cargo test -p axiam-sdk single_flight_refresh -- --exact` | ❌ W0 | ⬜ pending |
| TBD | — | — | RUST-01 (SC#3) | T-InfoDisclosure (token leak) | `grep -r 'eyJ' target/debug/` empty | CI-grep | `cargo build && [ "$(grep -r 'eyJ' target/debug/ \| wc -l)" -eq 0 ]` | ❌ W0 | ⬜ pending |
| TBD | — | — | RUST-01 (SC#3) | T-InfoDisclosure | `Sensitive<T>` Debug/Display never print raw value | unit | `cargo test -p axiam-sdk sensitive_redaction -- --exact` | ❌ W0 | ⬜ pending |
| TBD | — | — | RUST-01 (SC#4) | — | gRPC `CheckAccess`/`BatchCheckAccess` via tonic 0.14 | integration | `cargo test -p axiam-sdk --features grpc grpc_check_access -- --exact` | ❌ W0 | ⬜ pending |
| TBD | — | — | RUST-01 (SC#4) | T-Tampering/Spoofing (AMQP) | HMAC-SHA256 verified before handler; nack-without-requeue on mismatch | unit+integration | `cargo test -p axiam-sdk --features amqp amqp_hmac -- --exact` | ❌ W0 | ⬜ pending |
| TBD | — | — | RUST-01 (SC#5) | — | `cargo publish --dry-run` succeeds | CI smoke | `cargo publish --dry-run -p axiam-sdk` | ❌ W0 | ⬜ pending |
| TBD | — | — | §1–§10 conformance | T-TLS-downgrade | method names, error map, CSRF/tenant header, no insecure-skip surface | unit+CI-grep | `cargo test -p axiam-sdk contract_conformance` + `grep -rn 'danger_accept_invalid_certs\|insecure' sdks/rust/src/` (expect 0) | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

The SDK crate is currently a doc-only placeholder (Phase 15 scaffold) — **no dev-dependencies or tests exist yet**. Wave 0 must establish:

- [ ] `cargo add --dev wiremock tokio-test` (and HMAC/JWKS fixture deps as needed) — no SDK dev-dependencies exist yet
- [ ] `sdks/rust/tests/single_flight_refresh_test.rs` — RUST-01 SC#2 (wiremock + shared call counter)
- [ ] `sdks/rust/tests/sensitive_redaction_test.rs` — RUST-01 SC#3
- [ ] `sdks/rust/tests/amqp_hmac_test.rs` — RUST-01 SC#4 (AMQP half); fixtures byte-identical to `crates/axiam-amqp/src/messages.rs` test module
- [ ] `sdks/rust/tests/grpc_check_access_test.rs` — RUST-01 SC#4 (gRPC half); in-process tonic test server harness (new infrastructure — no shared harness in `sdks/rust/` yet)
- [ ] CI step for `grep -r 'eyJ' target/debug/` in `.github/workflows/` (SDK Rust workflow) — planner to verify/add
- [ ] CI lint gate `grep -rn 'danger_accept_invalid_certs\|insecure' sdks/rust/src/` (mirrors Go SDK `InsecureSkipVerify` gate)

---

## Reference Oracles

- **AMQP HMAC parity:** `crates/axiam-amqp/src/messages.rs` `sign_payload`/`verify_payload` — reuse the server test's literal fixture values and assert the SDK produces an **identical hex string** (wire-format compatibility, not self-consistency).
- **JWKS/EdDSA:** `crates/axiam-federation/src/oidc.rs` test module (`oidc.rs:660+`) — Ed25519 JWK fixture construction + JWT signing via `jsonwebtoken::{Header, encode}` with `Algorithm::EdDSA`.
- **Single-flight refresh:** `wiremock::MockServer` for `POST /api/v1/auth/refresh` + shared `Arc<AtomicUsize>` counter; 5 `tokio::spawn` tasks ⇒ assert counter == 1 after `join_all`.
- **gRPC:** in-process `tonic` test server implementing the same `AuthorizationService` trait as `crates/axiam-api-grpc/src/services/authorization.rs` with a stub engine returning canned `AccessDecision`s.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Real crates.io publish on release tag | RUST-01 (SC#5) | Side-effecting external publish; cannot run in PR CI | On tag `sdks/rust/vX.Y.Z`, confirm the publish workflow succeeded and the crate appears on crates.io |

*All other phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
