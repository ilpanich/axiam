---
phase: 25
slug: security-hardening-ii-federation-pki-data-protection-infra
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-04
---

# Phase 25 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness (`cargo test`), workspace crates |
| **Config file** | none — Cargo test harness; per-crate `tests/` + `#[cfg(test)]` mods |
| **Quick run command** | `cargo test -p <crate> --lib` (scoped, disk-safe per CLAUDE.md hygiene) |
| **Full suite command** | `cargo test` (end-of-phase regression gate only) |
| **Estimated runtime** | ~30–120 s per scoped crate; full workspace multi-minute |

> Build note: any build/test touching `axiam-api-rest` (or dependents) must export
> `SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`.
> Run `cargo clean` between plan steps, never during an executor run.

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <touched-crate> --lib` (+ the specific `--test` for the negative test)
- **After every plan wave:** Run the touched crates' full test sets (`cargo test -p <crate>`)
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** ~120 seconds (scoped crate)

---

## Per-Task Verification Map

> Task IDs are assigned by the planner; rows below are the per-success-criterion
> negative-test contract from `25-RESEARCH.md` (## Validation Architecture) that the
> planner MUST map onto concrete task IDs + `<automated>` verify blocks.

| SC | Requirement | Threat Ref | Secure Behavior (negative test) | Test Type | Crate / Seam | Test Double | Status |
|----|-------------|------------|----------------------------------|-----------|--------------|-------------|--------|
| 1 | SECHRD-02 | SSRF / DNS-rebind | Discovery/webhook fetch to a host resolving to loopback/private/link-local/ULA/unspecified is rejected; validated `IpAddr` is pinned into the connection (no re-resolve between check and send) | integration | axiam-federation (shared SSRF guard) + axiam-api-rest webhook | mock resolver returning an internal IP; rebind resolver (public→internal) | ⬜ pending |
| 2 | SECHRD-05 | mTLS trust bypass | Device-cert auth against a CA that is not `Active` OR outside `not_before`/`not_after` fails closed | unit/integration | axiam-pki / axiam-auth mTLS verify path | Inactive-CA fixture; expired-CA fixture | ⬜ pending |
| 3 | SECHRD-06 | GDPR erasure durability | Forced `pseudonymize_actor` failure → user remains re-selectable AND no erasure proof written (atomic); duplicate export (queued/ready-undownloaded/failed) rejected; export contains real `sessions` data | integration | axiam-audit/erasure (extracted testable fn — Pattern 3); `SessionRepository::list_by_user` (new) | failure-injecting pseudonymize double; duplicate-request fixture | ⬜ pending |
| 4a | SECHRD-07 | OIDC nonce replay | Account-linking OIDC callback ignores request-supplied nonce; validates only against server-side `FederationLoginState`; replay rejected | integration | axiam-api-rest handlers/federation.rs (mirror `oidc_callback_public`) | replayed callback with attacker nonce | ⬜ pending |
| 4b | SECHRD-09 | Secret leakage | federation config + PKI key structs never serialize/print secrets in `Debug`/list paths | unit | axiam-federation / axiam-pki structs | assert `format!("{:?}")` and serialized output omit secret | ⬜ pending |
| 5a | SECHRD-08 | AMQP forgery / fail-open | Signing mandatory in prod; per-tenant key — a tenant-A signature does NOT validate a tenant-B message; unsigned message rejected (not warn-and-process) | unit/integration | axiam-amqp consumers (audit/authz/mail) | cross-tenant signature fixture; missing-key prod config | ⬜ pending |
| 5b | SECHRD-08 | mail delivery | ExportReady mail deliverable end-to-end (real `org_id`, backoff retry with delay) | integration | axiam-amqp mail_consumer | fake SMTP sink; forced transient failure → backoff | ⬜ pending |
| 5c | SECHRD-10 | egress/secret gaps | SMTP egress + completed k8s secret set function under tightened default-deny NetworkPolicy; CI env prefix corrected to `AXIAM__DB__*` | manual/CI | k8s manifests + `.github/workflows/ci.yml` | manifest lint / CI run | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Test fixtures: mock/rebind DNS resolver, Inactive + expired CA, failure-injecting `pseudonymize_actor`, cross-tenant AMQP signature, fake SMTP sink
- [ ] `SessionRepository::list_by_user` implemented before the SECHRD-06 export negative test can assert real `sessions` data

*Framework is Rust's built-in harness — no framework install needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| SMTP egress + secret set under default-deny NetworkPolicy | SECHRD-10 | Requires a live k8s cluster / network policy enforcement not reproducible in unit tests | Apply manifests to a kind/k8s cluster; confirm SMTP egress allowed and all referenced secrets resolve; confirm non-allowlisted egress denied |

*All other phase behaviors have automated negative-test verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
