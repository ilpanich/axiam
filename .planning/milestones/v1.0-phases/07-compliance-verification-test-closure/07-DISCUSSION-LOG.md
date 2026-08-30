# Phase 7: Compliance Verification & Test Closure - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-07
**Phase:** 7-Compliance Verification & Test Closure
**Areas discussed:** Verification artifact form, Gap-handling policy, PKI + gRPC test depth, Frontend E2E reconciliation, OAuth2/OIDC test boundary, Conformance test placement, E2E CI runtime/cost, Compliance evidence format

---

## Verification artifact form

| Option | Description | Selected |
|--------|-------------|----------|
| Hybrid | ASVS → checklist; OAuth2/OIDC → executable conformance tests | ✓ |
| Checklist docs only | Single markdown audit, no CI-time proof | |
| Executable tests only | Everything a test, incl. non-behavioral controls | |
| Official OIDC conformance suite | openid.net hosted/Docker against running instance | |

**User's choice:** Hybrid
**Notes:** ASVS controls are mostly property assertions (checklist fits); OAuth2/OIDC are behavioral protocols where tests catch regressions. Aligns with Phase 3/6 executable-parity house style.

### ASVS scope sub-question

| Option | Description | Selected |
|--------|-------------|----------|
| Core IAM families | V2,V3,V4,V6,V7,V8,V9,V14 | ✓ (+V10) |
| All 14 families | Every ASVS L2 family | |
| Auth/session/access only | V2,V3,V4,V6 | |

**User's choice:** Core IAM families **+ Malicious Code (V10)**
**Notes:** User augmented the recommended set with V10, which ties to Phase 6 supply-chain evidence (SRI, cargo-audit, trivy). Final scope: V2, V3, V4, V6, V7, V8, V9, V10, V14.

### Location sub-question

| Option | Description | Selected |
|--------|-------------|----------|
| docs/compliance/ | Committed, versioned, auditor-discoverable | ✓ |
| .planning/phases/07.../ | Internal phase artifact | |
| claude_dev/ | Existing dev-doc dir | |

**User's choice:** docs/compliance/

---

## Gap-handling policy

| Option | Description | Selected |
|--------|-------------|----------|
| Severity-gated | Fix Critical/High + small corrections inline; defer rest with rationale | ✓ |
| Fix everything found | All findings remediated before phase closes | |
| Verify-only, defer all fixes | Document everything, fix nothing now | |

**User's choice:** Severity-gated
**Notes:** Bounds the "audit phase balloon" risk while shipping beta with no known High holes.

### Tracking sub-question

| Option | Description | Selected |
|--------|-------------|----------|
| GitHub issues + FINDINGS doc | Issues drive work; doc gives deferred-debt view | ✓ |
| Roadmap backlog only | Inside GSD planning | |
| FINDINGS.md only | One register, no issues | |

**User's choice:** GitHub issues (`compliance` label) + docs/compliance/FINDINGS.md

### Green-bar sub-question

| Option | Description | Selected |
|--------|-------------|----------|
| Default-feature suite green | `just test` 100%; 3 no-saml failures stay baseline | ✓ |
| Both paths fully green | Resolve SAML failures + extend no-saml guard to --tests | |
| You decide | Planner determines | |

**User's choice:** Default-feature suite green
**Notes:** Keeps deferred Phase 6 SAML/no-saml debt out of this phase.

---

## PKI + gRPC test depth

### axiam-pki depth

| Option | Description | Selected |
|--------|-------------|----------|
| Critical-path security | CA gen+sign, cert chain, mTLS reject cases, PGP roundtrip | ✓ |
| Full coverage | Every public fn incl. edge/error formatting | |
| Smoke only | One happy-path per module | |

**User's choice:** Critical-path security

### gRPC harness

| Option | Description | Selected |
|--------|-------------|----------|
| In-process tonic server | Ephemeral port + real client channel, full stack | ✓ |
| Direct service-impl calls | Construct Request<T>, no network | |
| You decide | Researcher picks | |

**User's choice:** In-process tonic server
**Notes:** No gRPC test harness exists yet; this is net-new infra, foundation for T19.1 + T19.2.

---

## Frontend E2E reconciliation

### Approach

| Option | Description | Selected |
|--------|-------------|----------|
| Fix-required, scope to 3 flows | Repair only login/RBAC/federation | |
| Rewrite all 11 specs | Bring entire E2E suite current + green | ✓ |
| New specs for 3 flows only | Fresh specs, leave legacy rotting | |

**User's choice:** Rewrite all 11 specs
**Notes:** User chose beyond the AC-5 minimum (3 flows) — full suite reconciliation, consistent with strict posture.

### Wiring

| Option | Description | Selected |
|--------|-------------|----------|
| Live backend + seeded DB | Real server, seeded fixtures, mocked external IdP | ✓ |
| Mocked API (route intercept) | Browser fixtures, no backend | |
| You decide | Researcher determines | |

**User's choice:** Live backend + seeded DB

---

## OAuth2/OIDC test boundary

| Option | Description | Selected |
|--------|-------------|----------|
| Required-feature (MUST) matrix | RFC 6749 §5.2 errors, grants, PKCE S256, OIDC discovery/JWKS/userinfo/validation | ✓ |
| Critical-security subset | Only dangerous-case behaviors | |
| Full matrix incl. SHOULD/MAY | Exhaustive | |

**User's choice:** Required-feature MUST matrix

---

## Conformance test placement

| Option | Description | Selected |
|--------|-------------|----------|
| axiam-api-rest/tests/ | Full HTTP-stack, Actix harness, alongside oauth2_flow_test | ✓ |
| axiam-server/tests/ (e2e) | Beside req5_* full-server e2e | |
| Split by layer | oauth2 logic in axiam-oauth2 + HTTP in api-rest | |

**User's choice:** axiam-api-rest/tests/

---

## E2E CI runtime/cost

| Option | Description | Selected |
|--------|-------------|----------|
| Separate required job, every PR | docker-compose + seeded DB, parallel, required check | ✓ |
| Nightly + pre-release only | Scheduled, fast PRs | |
| Manual/label-gated | Run on label/trigger | |

**User's choice:** Separate required job, every PR

---

## Compliance evidence format

| Option | Description | Selected |
|--------|-------------|----------|
| Per-control rows + citations | control → status → file:line/test → note | ✓ |
| Per-family summary | Paragraph per family | |
| You decide | Planner chooses | |

**User's choice:** Per-control rows + citations

---

## Claude's Discretion

- Conformance-test file structure, fixture helpers, exact tonic harness pattern (within D-10).
- Per-control N/A-vs-Deferred classification during checklist authoring (D-12 row format).
- CI job naming, `needs:` graph, required-status-check designation (within D-14).

## Deferred Ideas

- Resolve 3 `--no-default-features` SAML baseline failures (accepted baseline).
- Extend `build-no-saml` guard to `--tests` (carried from Phase 6, deferred).
- Official openid.net hosted/Docker OIDC conformance certification (post-beta).
- Full ASVS L2 audit of out-of-scope families (V5, V11, V12, V13).
- Net-new capabilities surfaced by the audit (built in future phases, logged as findings).
