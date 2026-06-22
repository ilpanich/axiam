---
phase: 8
slug: build-unblock
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-11
---

# Phase 8 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> Wave 0 (Build Unblock) — makes `axiam-server` compile under `-D warnings`.
> Changes are confined to Cargo manifest dependency placement, `use`-path
> corrections, and unused import/variable removal in test files. **No new attack
> surface**: no auth, crypto-logic, parsing, or external-input code is modified.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| (none introduced) | This phase introduces no new trust boundary. No new data flows, endpoints, or inputs cross any boundary. | (none) |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-08-01 | Tampering | `sha2` import-path change in `cleanup.rs` (`rsa::sha2` → `sha2`) | accept | `sha2::Sha256` and `rsa::sha2::Sha256` resolve to the **identical type from the identical crate** — `rsa` re-exports the `sha2` crate (`rsa = { features = ["sha2"] }`). The edit is a re-export-path correction only; no cryptographic behaviour changes. Independently verified: `grep 'rsa::sha2' cleanup.rs` → 0, `use sha2::{Digest, Sha256}` → 2, build green under `-Dwarnings` (a type mismatch would have failed the build). | closed |
| T-08-SC | Tampering | Supply chain — cargo dependency manifest | accept | No new third-party package or version enters the dependency graph. `uuid`/`chrono`/`serde_json`/`sha2` were relocated into `axiam-server` `[dependencies]` as `{ workspace = true }` (pinned to the already-audited `[workspace.dependencies]` versions); they already existed in the workspace/dev-dep graph. Independently verified: `Cargo.lock` holds exactly **1** `sha2` version entry (already present via `rsa` + workspace), and the Cargo.lock diff for this phase was a single `+ "sha2"` line under the `axiam-server` package node. No new install task, no new registry fetch, no version bump. | closed |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-08-01 | T-08-01 | Import-path correction between identical re-exported types; zero cryptographic behaviour change; proven equivalent by a green `-Dwarnings` build. No residual risk. | Emanuele Panigati (developer) | 2026-06-11 |
| AR-08-02 | T-08-SC | Manifest dependency relocation only; no new crate or version in `Cargo.lock`; all entries inherit already-audited workspace pins. No residual supply-chain exposure. | Emanuele Panigati (developer) | 2026-06-11 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-11 | 2 | 2 | 0 | inline orchestrator (short-circuit: register_authored_at_plan_time=true, threats_open=0, both dispositions `accept` — independently re-verified against build + Cargo.lock, not rubber-stamped) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer) — both `accept`
- [x] Accepted risks documented in Accepted Risks Log — AR-08-01, AR-08-02
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-11
