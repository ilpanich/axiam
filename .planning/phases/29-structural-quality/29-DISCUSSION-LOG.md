# Phase 29: Structural Quality - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-05
**Phase:** 29-structural-quality
**Areas discussed:** AppState shape, No-behavior-change boundary, Adoption vs deletion, Transaction mechanism, Intra-phase sequencing, Per-request service hoisting, Error-detection mechanism, PKI CA reconstruction

---

## AppState shape

### AppState pattern (283 handler extractions today)

| Option | Description | Selected |
|--------|-------------|----------|
| Full migration | Single `web::Data<AppState>`; handlers access deps as fields. Matches AC verbatim; rewrites all ~283 signatures — highest churn. | ✓ |
| Facade / compose-only | main.rs builds one AppState that registers individual web::Data<T>; handlers unchanged. Softer on "handlers extract from AppState". | |
| Grouped sub-states | A handful of cohesive states (AuthState/PkiState/…). Moderate churn. | |

**User's choice:** Full migration
**Notes:** Accepts the ~283-signature surface; relies on the green gate to prove no behavior change.

### Optional/conditional deps (email_config_repo)

| Option | Description | Selected |
|--------|-------------|----------|
| Option<> field | AppState carries `Option<…>`; None when unconfigured, preserving fail-closed behavior. | ✓ |
| Keep conditional out | Optional deps registered separately outside AppState (hybrid). | |
| You decide | Defer to research. | |

**User's choice:** Option<> field

---

## No-behavior-change boundary

### Reconciling QUAL-03/04 with "no behavior change"

| Option | Description | Selected |
|--------|-------------|----------|
| Intentional & in-scope | QUAL-03 (500→409) and QUAL-04 (transactional/tenant-predicated) are intentional changes; update tests asserting old behavior + add tests for the fix. | ✓ |
| Guard behind tests only | Change only where a test can lock the new behavior; flag ambiguous sites. | |
| You decide | Defer to research per-site. | |

**User's choice:** Intentional & in-scope

### Green gate strategy (disk-hygiene constrained)

| Option | Description | Selected |
|--------|-------------|----------|
| Per-crate dev + full regression gate | Narrow `-p <crate>` tests during plans; full workspace suite once at phase end. Matches CLAUDE.md build hygiene. | ✓ |
| Full workspace each plan | Entire suite after every plan. Strongest but risks ENOSPC. | |
| You decide | Defer cadence to planning. | |

**User's choice:** Per-crate dev + full regression gate

---

## Adoption vs deletion

### Backend helper adoption exhaustiveness (QUAL-02/05)

| Option | Description | Selected |
|--------|-------------|----------|
| Exhaustive | Collapse all 27 CountRow, remove dup parse_uuid, add + adopt paginate<T> everywhere, route reads through take_first_or_not_found. | ✓ |
| Mainstream-only | Adopt in core repos; leave edge repos on local copies. | |
| You decide | Defer scope to research. | |

**User's choice:** Exhaustive

### Frontend adopt-vs-delete stance (QUAL-06/07)

| Option | Description | Selected |
|--------|-------------|----------|
| Adopt canonical, delete orphans | Per module: adopt the good shared version + remove local dups; delete genuinely-orphaned modules. Profile/MFA → typed users service; delete pepper-less verify_password; construct services once. | ✓ |
| Prefer deletion (minimal) | Lean toward deleting unused shared modules over rewiring pages. | |
| You decide | Defer per-module to research. | |

**User's choice:** Adopt canonical, delete orphans

---

## Transaction mechanism

### Transaction expression (QUAL-04)

| Option | Description | Selected |
|--------|-------------|----------|
| Follow existing BEGIN/COMMIT idiom | Inline `BEGIN TRANSACTION; …; COMMIT TRANSACTION` compound SQL, consistent with user.rs/federation_login_state.rs/schema.rs. | ✓ |
| Introduce a Rust txn helper | New reusable transaction-wrapper abstraction. More surface than needed. | |
| You decide | Default to existing idiom. | |

**User's choice:** Follow existing BEGIN/COMMIT idiom

### Tenant-predication + TOCTOU closure

| Option | Description | Selected |
|--------|-------------|----------|
| Predicate every statement | Every DELETE/guard carries an explicit tenant predicate; child-guard SELECT + delete in one transaction. Defense-in-depth; closes CQ-B07/SEC-058 + CQ-B46. | ✓ |
| Transaction + single pre-check | One tenant ownership pre-check without per-statement predication. Weaker defense-in-depth. | |
| You decide | Defer per-site to research. | |

**User's choice:** Predicate every statement

---

## Intra-phase sequencing

### Plan grouping

| Option | Description | Selected |
|--------|-------------|----------|
| Security-adjacent → AppState → dedup → frontend | (1) QUAL-03+04, (2) QUAL-01+07, (3) QUAL-02+05, (4) QUAL-06. Each independently green-gated. Matches mandated order; backend/frontend separable. | ✓ |
| Fewer, larger plans | 2-3 bigger plans. Harder to review security-adjacent changes in isolation. | |
| You decide | Defer boundaries to planning. | |

**User's choice:** Security-adjacent → AppState → dedup → frontend

---

## Per-request service hoisting

### Where hoisted services live (QUAL-07)

| Option | Description | Selected |
|--------|-------------|----------|
| Singleton AppState fields | Hoist federation/reset/verification services into AppState, constructed once. Ties to QUAL-01. Guard: confirm no per-request state. | ✓ |
| Module-level once-cell | Construct once outside AppState via lazy/once-cell. Second lifecycle pattern. | |
| You decide | Default to AppState singletons where safe. | |

**User's choice:** Singleton AppState fields

---

## Error-detection mechanism

### Detecting SurrealDB index/unique violations (QUAL-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Centralized detection helper | One shared mapper inspects Surreal errors for specific index-violation markers → AlreadyExists; everything else stays 5xx. DB outage still 5xx. Tested both ways. | ✓ |
| Per-site inline match | Match error string at each create path. Duplication/drift risk. | |
| You decide | Defer approach/markers to research. | |

**User's choice:** Centralized detection helper

---

## PKI CA reconstruction

### Behavior-preserving CA reconstruction (QUAL-05)

| Option | Description | Selected |
|--------|-------------|----------|
| Parse real PEM + equivalence test | Implement from_ca_cert_pem parsing the stored CA PEM (+ key), true issuer DN; test identical issuer DN + chain verify. Share crypto helpers across ca/cert/pgp. | ✓ |
| You decide | Defer reconstruction + equivalence proof to research. | |

**User's choice:** Parse real PEM + equivalence test

---

## Claude's Discretion

- Exact `AppState` field naming/grouping and how the generic `C` threads through handler signatures.
- The precise `paginate<T>` signature/bounds and initial adoption sites.
- Exact SurrealDB index-violation marker strings (verify against real Surreal error text).
- Test harness/structure choices (follow Phase 26 CORR-04 conventions).
- Location/API of the shared `axiam-pki` crypto-helper module.

## Deferred Ideas

- A generic Rust transaction-wrapper abstraction for axiam-db (over-engineering for this phase).
- `sub_kind`-based / subject-kind authz enforcement (carried from Phase 28; its own phase).
- Broader error-taxonomy sweep beyond mainstream create paths (full audit of every `Migration`-mapped site is out of GA scope).
