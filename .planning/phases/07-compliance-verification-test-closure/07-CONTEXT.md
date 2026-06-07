# Phase 7: Compliance Verification & Test Closure - Context

**Gathered:** 2026-06-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Prove AXIAM meets the milestone's compliance bar (OWASP ASVS Level 2 for IAM-relevant
controls, OAuth2 RFC 6749/7636, OIDC Core 1.0) and close the *remaining* real test
gaps before the v1.0-beta community release. The success criteria and target standards
are fixed by ROADMAP.md / REQUIREMENTS.md (REQ-11) — this phase clarifies *how* to
verify and *what "done" means*, not *whether* to verify.

**In scope:**
- ASVS L2 audit checklist (IAM-relevant families) with code/test evidence.
- Executable OAuth2 RFC 6749/7636 + OIDC Core 1.0 conformance tests.
- `axiam-pki` critical-path test coverage (the only fully 0-test target crate left).
- `axiam-api-grpc` test harness + gRPC authz tests (T19.1) + concurrent batch authz (T19.2).
- Frontend Playwright E2E suite reconciliation to the cookie-auth + RBAC reality.
- Severity-gated remediation of findings; deferral register for the rest.

**Out of scope (deferred / other phases):**
- Net-new product capabilities surfaced by the audit (logged as findings, not built here).
- Official openid.net hosted conformance certification (beyond MVP-beta).
- Resolving the 3 `--no-default-features` SAML baseline failures and extending the
  `build-no-saml` guard to `--tests` (accepted deferred debt from Phase 6).
- Exhaustive ASVS families with little IAM surface (V5, V11, V12, V13 — see scope below).

### Reconciliation note (correct the stale TESTING.md map)
`.planning/codebase/TESTING.md` is dated 2026-03-30 (milestone start) and lists many
crates as "0 tests." Phases 1-6 have since built most of REQ-11's named integration
tests (REQ-11 was designed to run *as verification within each phase*). Current git
reality:
- **Already satisfied (cite, don't rebuild):** `axiam-authz` → `crates/axiam-authz/tests/authz_engine_test.rs`; `axiam-federation` → inline tests + `crates/axiam-server/tests/req5_oidc_e2e.rs`, `req5_saml_e2e.rs`; RBAC → `crates/axiam-api-rest/tests/rbac_test.rs` + `middleware_test.rs`; cookie auth → `auth_test.rs`; GDPR → `gdpr_test.rs`; session lifecycle → `req7_session_lifecycle.rs`.
- **Real AC-4 gap:** ONLY `axiam-pki` (no `tests/` dir) and `axiam-api-grpc` (no `tests/` dir).
- **Exists-but-stale:** `frontend/playwright.config.ts` + 11 specs in `frontend/e2e/` predate cookie-auth (P1) / RBAC gating (P3) / federation verify (P4).

</domain>

<decisions>
## Implementation Decisions

### Verification artifact form (REQ-11 / success criteria 1-3)
- **D-01:** **Hybrid verification.** ASVS L2 → a markdown **checklist** (control → evidence → status). OAuth2 RFC 6749/7636 + OIDC Core 1.0 → **executable Rust conformance tests** committed to the repo (so protocol regressions are caught at CI time). Matches the Phase 3/6 executable-parity house style.
- **D-02:** **ASVS L2 scope = IAM-relevant families + malicious code:** **V2** (Authentication), **V3** (Session Management), **V4** (Access Control), **V6** (Stored Cryptography), **V7** (Errors & Logging), **V8** (Data Protection / GDPR), **V9** (Communications), **V10** (Malicious Code — ties to Phase 6 supply-chain: SRI, cargo-audit, trivy), **V14** (Configuration). Explicitly OUT: V5, V11, V12, V13 (low IAM surface). "No open items" = every in-scope control is Pass, documented N/A, or Deferred-with-rationale.
- **D-03:** **Artifacts live in `docs/compliance/`** (committed, versioned, auditor-/community-discoverable): `asvs-l2-checklist.md`, `oauth2-rfc-compliance.md`, `oidc-conformance.md`, `FINDINGS.md`. Executable conformance tests live in crate `tests/` dirs (see D-08).
- **D-07:** **OAuth2/OIDC conformance test boundary = required-feature (MUST) matrix.** Systematically cover MUST-level behaviors: RFC 6749 §5.2 error codes, supported grant types + RFC 7636 PKCE **S256 enforcement**, and OIDC Core discovery-doc completeness, JWKS, userinfo, ID-token validation, nonce/state, algorithm pinning (reject `none`). Scoped to MUSTs — not exhaustive SHOULD/MAY.
- **D-08:** **Conformance tests live in `crates/axiam-api-rest/tests/`** (e.g. `oauth2_conformance.rs`, `oidc_conformance.rs`) alongside `oauth2_flow_test.rs` / `federation_test.rs`, using the established Actix `test::init_service` harness — exercises real endpoints/error responses the way an external RFC validator would.
- **D-12:** **ASVS checklist granularity = per-control rows with citations.** Each in-scope control = one row: control ID/text → status (Pass / N-A / Deferred) → evidence (`file:line` and/or test name) → note. Line-by-line auditable and traceable to code/tests.

### Gap-handling policy (scope elasticity / milestone DoD)
- **D-04:** **Severity-gated remediation.** Fix inline if a finding is (a) Critical/High security OR (b) a small, localized correction (e.g. a missing OAuth2 error code, wrong `WWW-Authenticate` header). Log Medium/Low or large-refactor findings as deferred. Beta ships with **no known High holes**, but the phase stays bounded — "test closure," not "feature rewrite."
- **D-05:** **Deferred findings tracked in two places:** a **GitHub issue** (label `compliance`) drives the work, AND a row in **`docs/compliance/FINDINGS.md`** (finding → severity → ASVS/RFC ref → deferral rationale → issue link) gives auditors a single deferred-debt view. Consistent with the project convention "issues closed on PR merge."
- **D-06:** **Milestone test-green bar = default-feature suite 100% green.** `just test` (default features, SAML ON) must pass fully. The 3 `--no-default-features` SAML failures remain an **accepted, documented baseline** (real SAML verify needs xmlsec, only built in CI/Docker). Do **not** expand the `build-no-saml` guard to `--tests` in this phase — deferred Phase 6 debt, logged not fixed.

### Test closure — PKI + gRPC (success criterion 4)
- **D-09:** **`axiam-pki` = critical-path security coverage.** Cover: CA keypair generation + cert signing, cert issuance/validation chain, mTLS verification incl. **reject cases** (expired / wrong-CA), and PGP audit-signing sign+verify roundtrip. Skip exhaustive field-permutation/error-formatting tests. Reuse the in-memory test pattern; note `rcgen 0.13` + `pgp 0.19` API quirks (see project memory).
- **D-10:** **`axiam-api-grpc` = establish an in-process tonic server harness.** Spin the tonic service on an ephemeral localhost port, connect a real client channel, exercise authz over the wire (interceptors + codec + auth), mirroring how Actix tests exercise the full HTTP stack. This harness is **new** (no gRPC test infra exists today) and is the foundation for **T19.1** (gRPC authz integration tests) and **T19.2** (concurrent batch authorization tests).

### Frontend E2E reconciliation (success criterion 5)
- **D-11:** **Rewrite all 11 Playwright specs** in `frontend/e2e/` to the current cookie-auth + RBAC-gated model and get the **full E2E suite green** — not just the 3 AC-5-required flows (login, RBAC-gated nav, federation). (User chose the thorough option; this is reconciling existing specs / test closure, not new capability, so it stays in phase domain.)
- **D-13:** **E2E runs against a live `axiam-server` + seeded test DB** (admin + RBAC fixtures) in CI via docker-compose / CI service. Federation flow **mocks the external IdP** (stub redirect/callback) the same way the backend `req5_*` tests do — test the AXIAM side end-to-end, not a real IdP. Highest fidelity; exercises cookie auth (httpOnly cookies can't be read from `sessionStorage` — old specs that asserted on token storage are *wrong*, not just incomplete).
- **D-14:** **E2E is a separate, required CI job on every PR** (spins docker-compose + seeded DB, runs parallel to the Rust jobs, required status check before merge). Fast conformance/unit tests stay in their own jobs so PR feedback isn't gated on E2E latency.

### Claude's Discretion
- Exact `deny.toml`-style exception bookkeeping is Phase 6's; here, the planner/researcher choose conformance-test file structure, fixture helpers, and the precise tonic harness pattern (consistent with D-10) from the crate's current server wiring.
- Specific ASVS control IDs that map to "N/A" vs "Deferred" — planner decides per-control during authoring, using the D-12 row format.
- CI job naming, `needs:` graph, and which new checks become required status checks (consistent with D-14).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirements & scope
- `.planning/ROADMAP.md` §"Phase 7: Compliance Verification & Test Closure" — goal, 5 success criteria, scope list
- `.planning/REQUIREMENTS.md` §REQ-11 (Testing Gaps) — acceptance criteria
- `.planning/PROJECT.md` — milestone constraints, OWASP ASVS L2 target
- `.planning/STATE.md` §Blockers/Concerns — the 3 `--no-default-features` SAML baseline failures + the deferred `build-no-saml --tests` guard note
- `.planning/phases/06-ci-cd-infrastructure-hardening/06-CONTEXT.md` — Phase 6 decisions (strict posture, supply-chain evidence for ASVS V10, OpenAPI parity-test pattern)

### External standards (verify against — no local copies)
- **OWASP ASVS v4.0.x Level 2** — control families V2, V3, V4, V6, V7, V8, V9, V10, V14 (D-02)
- **RFC 6749** (OAuth 2.0 Authorization Framework) — esp. §4 grant types, §5.2 error responses
- **RFC 7636** (PKCE) — S256 enforcement (D-07)
- **OpenID Connect Core 1.0** — §2 ID Token, §3 auth flows, §3.1.3.7 ID-token validation, discovery + JWKS + userinfo

### Test precedents & harnesses (reuse)
- `crates/axiam-api-rest/tests/oauth2_flow_test.rs` (52.6K), `oauth2_client_test.rs`, `federation_test.rs` — Actix `test::init_service` harness for new conformance tests (D-08)
- `crates/axiam-api-rest/tests/rbac_test.rs`, `middleware_test.rs` — RBAC already tested (AC reconciliation)
- `crates/axiam-server/tests/req5_oidc_e2e.rs`, `req5_saml_e2e.rs` — federation already tested + **mocked-IdP pattern** to mirror for frontend federation E2E (D-13)
- `crates/axiam-authz/tests/authz_engine_test.rs` — authz already tested (AC reconciliation); reference for gRPC authz test cases (D-10)
- `crates/axiam-api-rest/src/middleware/authz.rs` — Phase 3 `ROUTE_PERMISSION_MAP ↔ PERMISSION_REGISTRY` parity-test pattern (house style for "verify wired everywhere")

### Crates to test (currently 0 `tests/` dir)
- `crates/axiam-pki/src/` — CA, cert, mTLS, PGP modules (D-09); `rcgen 0.13` / `pgp 0.19` API quirks in project memory
- `crates/axiam-api-grpc/` — gRPC services; new tonic harness (D-10), T19.1 + T19.2

### Frontend E2E (rewrite)
- `frontend/playwright.config.ts` — Playwright config (framework locked)
- `frontend/e2e/*.spec.ts` — 11 stale specs incl. `login.spec.ts`, `federation.spec.ts`, `roles.spec.ts` (D-11)
- `frontend/package.json` — `@playwright/test ^1.58.2`; `test` / `test:ui` scripts

### CI (modify)
- `.github/workflows/ci.yml` — add the E2E job (D-14) + conformance tests run in existing test job; do not break the `build-no-saml` guard (D-06)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **Actix `test::init_service` harness** — the established full-HTTP-stack integration pattern; directly reused for OAuth2/OIDC conformance tests (D-08).
- **Mocked-IdP pattern** in `req5_oidc_e2e.rs` / `req5_saml_e2e.rs` — reuse the IdP-stubbing approach for the frontend federation E2E (D-13).
- **Phase 3 parity-test pattern** (`middleware/authz.rs`) — registry cross-check style for any "verify X covers everything" conformance assertion.
- **In-memory SurrealDB (`Mem`) + Ed25519 hardcoded test keypairs** — standard setup; reused for `axiam-pki` and conformance tests.

### Established Patterns
- **No external mocking libraries** — tests use real in-memory DB + real services; gRPC harness (D-10) should follow suit (real tonic server, real channel; mock only the external IdP).
- **`-Dwarnings` enforced in CI** (`RUSTFLAGS`) — all new tests/harnesses must be warning-clean.
- **SAML behind `saml` feature** — 3 `--no-default-features` failures are baseline (D-06); shipped Docker/CI image builds SAML-ON.
- **Per-crate builds locally; CI uses `--workspace`** — respect when adding tests (project memory: avoid full-workspace builds locally, use `-p`).

### Integration Points
- gRPC tonic harness (D-10) is **net-new infrastructure** — no precedent in the repo; highest-uncertainty item, flag for research.
- E2E live-backend job (D-13/D-14) needs docker-compose + seeded DB wiring in CI — new CI plumbing; interacts with cookie `Secure` flag (Phase 6 D-18 `AXIAM_COOKIE__SECURE=false` for http://localhost).
- Frontend cookie-auth reality (httpOnly) means E2E can't read tokens — assertions must be on UI state / network behavior, not storage (D-13).

</code_context>

<specifics>
## Specific Ideas

- User consistently chose the **rigorous/thorough option** (rewrite all 11 E2E specs, required-feature MUST matrix, per-control ASVS rows, E2E required on every PR) — continuing the strict posture established in Phase 6. Downstream should prefer the rigorous interpretation when a tradeoff arises, documenting exceptions rather than relaxing.
- User explicitly added **ASVS V10 (Malicious Code)** to scope beyond the core IAM families — connect it to Phase 6's supply-chain evidence (SRI, cargo-audit, cargo-deny, trivy) as the citations.
- **Treat the stale `TESTING.md` map as a defect of staleness, not the current state** — `axiam-authz` and `axiam-federation` are already tested; only `axiam-pki` + `axiam-api-grpc` are the real AC-4 gaps (see Reconciliation note in `<domain>`).

</specifics>

<deferred>
## Deferred Ideas

- **Resolve the 3 `--no-default-features` SAML test failures** — accepted baseline; needs the SAML-ON / xmlsec path which is CI/Docker-only. Future hardening, not this phase (D-06).
- **Extend the `build-no-saml` CI guard to `--tests`** — blocked on cleaning `-Dwarnings` drift in axiam-server test files; carried over from Phase 6, still deferred.
- **Official openid.net hosted/Docker OIDC conformance certification** — authoritative cert path, but heavyweight external tooling needing a deployed instance; beyond MVP-beta. Candidate for a post-beta certification effort.
- **Full ASVS L2 audit of out-of-scope families** (V5, V11, V12, V13) — low IAM surface; revisit if pursuing formal certification.
- **Net-new capabilities surfaced by the audit** (e.g. WebAuthn completion, additional grant types) — logged as `compliance` findings (D-05), built in their own future phases, not Phase 7.

</deferred>

---

*Phase: 7-Compliance Verification & Test Closure*
*Context gathered: 2026-06-07*
