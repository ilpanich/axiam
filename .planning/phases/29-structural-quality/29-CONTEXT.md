# Phase 29: Structural Quality - Context

**Gathered:** 2026-07-05
**Status:** Ready for planning

<domain>
## Phase Boundary

Clear the structural-quality debt at GA — AppState extraction, generic
pagination + shared repo-helper **adoption**, error-taxonomy correctness,
transactional multi-statement mutations, PKI/frontend dedup, and dead-code
cleanup. Requirements **QUAL-01…QUAL-07 are locked** by ROADMAP.md /
REQUIREMENTS.md — this discussion clarifies HOW to implement them, not WHAT
to build. No new capabilities.

The headline constraint is **"no behavior change (tests stay green)"** — with
the deliberate exception of QUAL-03 (error taxonomy) and QUAL-04
(transactional/tenant-predicated mutations), which *intentionally* change
observable error responses and mutation semantics for correctness (see D-05).

- **QUAL-01** — AppState extraction (CQ-B43)
- **QUAL-02** — Generic `paginate<T>` + shared repo helpers (CQ-B10)
- **QUAL-03** — Error taxonomy correctness (CQ-B11/17/18)
- **QUAL-04** — Transactional multi-statement mutations (CQ-B07/46/39-residual)
- **QUAL-05** — PKI helper deduplication (CQ-B15)
- **QUAL-06** — Frontend shared components & services adoption (CQ-F15/17/39)
- **QUAL-07** — Dead-code & per-request-construction cleanup (CQ-B47/27)

**Critical scouting finding (2026-07-05): most shared assets already exist and
are simply *unadopted*.** `crates/axiam-db/src/helpers.rs` already defines
`CountRow`, `parse_uuid`, and `take_first_or_not_found`, but 27 duplicate
`struct CountRow` and a duplicate `parse_uuid` (`federation_link.rs:44`) remain,
and a generic `paginate<T>` does not exist yet. Frontend `shared.tsx`
(`ToggleField`/`SectionCard`/…), `hooks/useCrudMutations.ts`, and a
`services/users.ts` already exist but pages don't uniformly import them. So most
of QUAL-02/05/06 is **migration + dead-module deletion**, not extraction. The
researcher MUST verify current adoption state before planning.

</domain>

<decisions>
## Implementation Decisions

> Captured interactively during discuss-phase (2026-07-05). Consistent with the
> Phase 23–28 posture: no over-engineering, reuse existing conventions/helpers,
> honest closure, and — for this phase specifically — **no behavior change on
> the pure refactors, proven by a green test suite.**

### QUAL-01 — AppState extraction
- **D-01 — Full migration.** `main.rs` composes a single `AppState<C>` and every
  handler extracts `web::Data<AppState<C>>`, accessing dependencies as fields
  (e.g. `state.user_repo`). This matches the AC verbatim ("handlers extract
  dependencies from AppState") and replaces the ~56 inline `app_data`
  registrations in `crates/axiam-server/src/main.rs`. **Accepted cost:** this
  rewrites ~283 handler `web::Data<T>` extractions across 28 handler files — a
  large surface for a no-behavior-change phase. Mitigation is the green gate
  (D-06). `AppState` is generic over the DB connection `C` because the repos are
  `Surreal…Repository<C>`.
- **D-02 — Optional deps are `Option<>` fields.** Conditionally-registered deps
  (e.g. `email_config_repo`, registered fail-closed only when
  `AXIAM__EMAIL_ENCRYPTION_KEY` is present — 28-04) become `Option<…>` fields on
  `AppState`. Handlers get `None` when unconfigured, preserving the existing
  fail-closed behavior (routes still fail closed with 500/unavailable). The
  single composition root holds everything; no dep is registered outside AppState.

### No-behavior-change boundary
- **D-03 — "No behavior change" scopes the pure refactors only.** QUAL-01
  (AppState), QUAL-02 (pagination/dedup), QUAL-05 (PKI dedup), QUAL-06 (frontend
  dedup), and QUAL-07 (dead-code) must be behavior-preserving — existing tests
  pass unchanged.
- **D-04 — QUAL-03/04 are INTENTIONAL in-scope behavior changes.** The 500→409
  error-taxonomy fixes (QUAL-03) and the transactional/tenant-predicated mutation
  fixes (QUAL-04) are deliberate correctness improvements that *do* change
  observable behavior. For these: **update** any existing test that asserts the
  old (500 / non-transactional) behavior to assert the new (409 / transactional)
  behavior, and **add** tests that lock the fix. This is the honest reading of
  the roadmap ("refactors never churn unreviewed security code" but the taxonomy
  and transaction ACs explicitly change responses).
- **D-06 — Green gate = per-crate during dev + full-workspace regression at phase end.** During each plan, run narrowly-scoped tests (`-p <crate>
  --lib`/`--test <name>`) to respect the sandbox disk quota (per CLAUDE.md build
  hygiene: `cargo clean` between plans, `SWAGGER_UI_DOWNLOAD_URL` workaround for
  `axiam-api-rest`). Run the **full workspace test suite once as the end-of-phase
  regression gate** to prove no behavior change on the pure refactors.

### QUAL-02 / QUAL-05 — Backend dedup (exhaustive)
- **D-07 — Exhaustive adoption.** Collapse ALL 27 duplicated `struct CountRow`
  into `helpers::CountRow`; remove the duplicate `parse_uuid`
  (`federation_link.rs:44`); add a generic `paginate<T>` helper and adopt it in
  every list repo; route single-record reads through
  `helpers::take_first_or_not_found`. Each site is mechanical and covered by
  existing tests (no behavior change). "Mainstream-only" was rejected — the AC
  requires the duplicates to collapse.
- **D-08 — PKI: real-PEM CA reconstruction + shared crypto helpers.** Implement
  `from_ca_cert_pem` so `CertService` reconstructs the signing CA by **parsing
  the stored CA cert PEM** (+ decrypted key) with its true issuer DN/serial/key —
  not from the subject CN / "minimal CA params" (`cert.rs:224`). Prove
  behavior-equivalence with a test: a cert signed via the new path verifies
  against the CA chain and carries the **identical issuer DN** as the old path.
  Move the keypair/fingerprint/encrypt helpers into one shared `axiam-pki` module
  used by `ca`/`cert`/`pgp` (currently triplicated).

### QUAL-03 — Error taxonomy correctness (centralized detection)
- **D-09 — One centralized detection helper.** Add a single shared mapper (in the
  db error layer / `helpers`) that inspects the SurrealDB error for **specific**
  index-violation markers (e.g. `already contains` / `Database index`) and maps
  those to `DbError::AlreadyExists` (→ HTTP 409). Everything else keeps falling
  through to `Migration`/`Database` (→ 5xx). Mainstream create paths (user create,
  edge-uniqueness) call this helper instead of the blanket
  `.map_err(|e| DbError::Migration(e.to_string()))`. A DB **outage** must still
  return 5xx — never a false 409. Tests: one genuine duplicate (→409) and one
  non-index DB error (→5xx). Per-site inline matching was rejected (drift risk).
- **D-10 — `parse_uuid` stops mislabeling corrupt reads.** `helpers::parse_uuid`
  must not label a corrupt-data read as "Migration failed" (its own error
  variant, not `Migration`).
- **D-11 — OAuth2 distinguishes DB outage from `invalid_client`.** OAuth2 handlers
  return an appropriate server error on a DB outage rather than collapsing it into
  `invalid_client` (CQ-B18).

### QUAL-04 — Transactional mutations (existing idiom + full predication)
- **D-12 — Follow the existing inline `BEGIN/COMMIT` idiom.** Express the new
  transactions as inline `BEGIN TRANSACTION; …; COMMIT TRANSACTION` compound SQL,
  consistent with the existing `user.rs:736` / `federation_login_state.rs:110` /
  `schema.rs` pattern. No new Rust transaction abstraction (rejected as
  over-engineering for this phase's needs).
- **D-13 — Predicate every statement on tenant (defense-in-depth).** For the
  role/permission edge deletes and `resource::delete` child-guard: every
  `DELETE`/guard statement inside the transaction carries an explicit tenant
  predicate (`WHERE tenant = …`), so a cross-tenant edge can never be stripped
  even if an id is spoofed; the child-guard SELECT + delete run in the **same**
  transaction (no TOCTOU). Closes the CQ-B07/SEC-058 cross-tenant edge-strip
  family and CQ-B46. Add tests for the cross-tenant and concurrent-child cases.
- **D-14 — GDPR deletion setup is transactional.** Wrap the GDPR deletion setup so
  a `create` failure after `mark_deletion_pending` cannot strand an uncancellable
  purge (CQ-B39 residual).

### QUAL-06 / QUAL-07 — Frontend adoption & dead-code (adopt canonical, delete orphans)
- **D-15 — Adopt canonical, delete orphans (per module).** For each shared module:
  if the shared version is the good/canonical impl, wire pages to it and remove
  the pages' local duplicates; if a shared module is genuinely orphaned/superseded
  (no real consumer, inferior), delete it. The researcher assesses each module
  (`ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge`/`slugify`/`useCrudMutations`).
  "Prefer deletion (minimal churn)" was rejected — the intent is to reduce
  duplication, not just prune.
- **D-16 — Profile/MFA pages → typed users service.** Profile and MFA pages call
  the typed `services/users.ts` instead of inline `api.*` calls.
- **D-17 — Delete the pepper-less `verify_password`.** Remove the second Argon2
  `verify_password` impl (`crates/axiam-db/src/repository/user.rs:872`, re-exported)
  — the pepper-less-caller trap (CQ-B47). Keep the canonical
  `axiam-auth::password::verify_password`. Confirm no live caller depends on the
  deleted impl.
- **D-18 — Per-request services become singleton AppState fields.** The
  federation/reset/verification services currently constructed per-request across
  13 sites (e.g. `PasswordResetService::new` at `password_reset.rs:162/292`,
  `EmailVerificationService::new` at `email_verification.rs:67/102`) are hoisted
  into `AppState` as shared singletons, constructed once at startup — ties
  naturally to the D-01 full migration. **Guard:** the researcher must confirm
  none of these carry per-request state (per-tenant/config) that made per-request
  construction necessary; if one does, it stays per-request and the exception is
  documented.

### Intra-phase sequencing (plan structure)
- **D-19 — Security-adjacent → AppState → dedup → frontend.** Plan order:
  1. QUAL-03 (error taxonomy) + QUAL-04 (transactions) — security-adjacent, land
     first per the roadmap mandate ("before/with AppState").
  2. QUAL-01 (AppState) + QUAL-07 service hoisting.
  3. QUAL-02 + QUAL-05 backend dedup.
  4. QUAL-06 frontend — its own plan/diff (keeps backend/frontend separable for
     review).
  Each plan is independently green-gated (D-06). "Fewer, larger plans" was
  rejected (harder to review the security-adjacent changes in isolation).

### Claude's Discretion
Prescriptive enough for the researcher/planner to nail directly — no user
decision needed:
- Exact `AppState` field naming/grouping within the single struct, and how the
  generic `C` threads through handler signatures.
- The precise `paginate<T>` signature/bounds and which repos it lands in first.
- Exact SurrealDB index-violation marker strings for D-09 (verify against the
  actual Surreal error text this codebase's index defs produce).
- Test harness/structure choices (follow the Phase 26 CORR-04 / prior-phase
  testing conventions).
- Where exactly the shared `axiam-pki` crypto-helper module lives and its API.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

The roadmap lists no external ADR/spec refs for this phase; the authoritative
references are REQUIREMENTS.md, ROADMAP.md, and the existing implementation seams
below.

### Requirements & roadmap
- `.planning/REQUIREMENTS.md` §QUAL-01…QUAL-07 (lines ~964–1020) — locked
  acceptance criteria
- `.planning/ROADMAP.md` §"Phase 29: Structural Quality" (line ~1212) — goal +
  success criteria + dependency (Phase 26) + intra-phase ordering mandate

### QUAL-01 / QUAL-07 — AppState & service hoisting
- `crates/axiam-server/src/main.rs` — ~56 `app_data` registrations (lines
  ~772–838), the conditional `email_config_repo` registration (~838), and the
  CQ-B29 notes about publishers not in app_data (~584/790)
- `crates/axiam-api-rest/src/handlers/` — 28 handler files, ~283
  `web::Data<T>` extractions to migrate (sample: `users.rs:143/197/…`)
- `crates/axiam-api-rest/src/handlers/password_reset.rs` — `PasswordResetService::new`
  (`:162`, `:292`) per-request construction
- `crates/axiam-api-rest/src/handlers/email_verification.rs` —
  `EmailVerificationService::new` (`:67`, `:102`) per-request construction

### QUAL-02 / QUAL-05 — Shared helpers & PKI dedup
- `crates/axiam-db/src/helpers.rs` — existing `CountRow` (`:18`), `parse_uuid`
  (`:33`), `take_first_or_not_found` (`:46`); add `paginate<T>` here
- `crates/axiam-db/src/repository/federation_link.rs` — duplicate `parse_uuid`
  (`:44`) to remove
- `crates/axiam-db/src/repository/*.rs` — the 27 duplicate `struct CountRow`
  definitions to collapse
- `crates/axiam-pki/src/cert.rs` — CA reconstruction "minimal CA params" comment
  (`:224`); target of `from_ca_cert_pem`
- `crates/axiam-pki/src/` — `ca`/`cert`/`pgp` modules with triplicated
  keypair/fingerprint/encrypt helpers to share

### QUAL-03 — Error taxonomy
- `crates/axiam-db/src/error.rs` — `DbError` enum (`:7`): `Migration` (`:20`),
  `AlreadyExists` (`:26`), and the `DbError → AxiamError` mapping (`:33`)
- `crates/axiam-core/src/error.rs` — `AxiamError::AlreadyExists` (`:11`)
- `crates/axiam-db/src/repository/user.rs` — blanket
  `.map_err(|e| DbError::Migration(e.to_string()))` create-path sites (`:252`,
  `:285`, `:463`, `:518`, `:631`, `:682`, `:725`, `:780`, `:817`) — the pattern
  to route through the new centralized detection helper
- OAuth2 handlers (`crates/axiam-oauth2/`, `crates/axiam-api-rest/src/handlers/oauth2*.rs`)
  — DB-outage vs `invalid_client` distinction (CQ-B18)

### QUAL-04 — Transactions
- `crates/axiam-db/src/repository/user.rs:736` — existing inline
  `BEGIN TRANSACTION; … COMMIT TRANSACTION` idiom to mirror
- `crates/axiam-db/src/repository/federation_login_state.rs:110` — same idiom
- `crates/axiam-db/src/repository/role.rs` — role/permission edge deletes
  (`delete` at `:264`)
- `crates/axiam-db/src/repository/resource.rs` — `resource::delete` child-guard
  (`:275`, child check at `:278`); child_of edge handling (`:119`/`:224`/`:230`)
- GDPR deletion setup path (account-deletion repo + `mark_deletion_pending`
  caller) — for D-14

### QUAL-06 — Frontend
- `frontend/src/components/shared.tsx` — `ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge`
- `frontend/src/hooks/useCrudMutations.ts` — shared CRUD mutation hook
- `frontend/src/lib/utils.ts` — `slugify`
- `frontend/src/services/users.ts` — typed users service for profile/MFA pages
- `frontend/src/pages/{users,roles,permissions,federation,settings,notifications}/*`
  — pages to assess for adopt-vs-delete

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/axiam-db/src/helpers.rs` — `CountRow`/`parse_uuid`/`take_first_or_not_found`
  already exist; this phase adopts them everywhere and adds `paginate<T>` alongside.
- Inline `BEGIN TRANSACTION; … COMMIT TRANSACTION` compound SQL (`user.rs:736`,
  `federation_login_state.rs:110`, `schema.rs:1223`) — the established transaction
  idiom QUAL-04 mirrors.
- Frontend `shared.tsx` + `useCrudMutations.ts` + `services/users.ts` already
  exist — QUAL-06 wires pages to them (or deletes orphans), not new extraction.
- `axiam-auth::password::verify_password` (`password.rs:53`) — the canonical
  Argon2 verifier that survives; the pepper-less `user.rs:872` copy is deleted.

### Established Patterns
- actix-web `web::Data<T>` type-keyed extraction — the full AppState migration
  changes every handler to `web::Data<AppState<C>>` and field access.
- `DbError::Migration(String)` as the blanket `.map_err` catch-all — QUAL-03
  intercepts index/unique violations before they reach it.
- 28-04 fail-closed conditional `app_data` registration — modeled as an
  `Option<>` AppState field (D-02).
- Per-verb RBAC and existing test conventions (Phase 26 CORR-04) carry forward.

### Integration Points
- `AppState<C>` → constructed in `axiam-server/src/main.rs`, registered once,
  extracted by all REST handlers; holds repos, services, config, and optional deps.
- Centralized DB-error detection helper → called by mainstream create paths in
  the repositories (replacing blanket `Migration` mapping).
- New transactions → repository methods in `role.rs`/`resource.rs` + GDPR
  deletion setup, using inline `BEGIN/COMMIT` with tenant predicates.
- Shared `axiam-pki` crypto module → used by `ca`/`cert`/`pgp`.

</code_context>

<specifics>
## Specific Ideas

- Full AppState migration is the largest single surface in the phase (~283 handler
  extractions); it is deliberately paired with the full-workspace regression gate
  to prove no behavior change (D-01 + D-06).
- QUAL-03/04 are the *only* intentional observable-behavior changes; everything
  else is behavior-preserving (D-03/D-04).
- The centralized error-detection helper must map **only** genuine unique/index
  violations to 409 — a DB outage stays 5xx (D-09).
- The PKI change must be proven signing-equivalent via an identical-issuer-DN test
  (D-08), since reconstructing the CA differently could silently alter signing.

</specifics>

<deferred>
## Deferred Ideas

- **A generic Rust transaction-wrapper abstraction** for axiam-db — rejected for
  this phase (D-12) as over-engineering; could be revisited if transactional call
  sites proliferate later.
- **`sub_kind`-based / subject-kind authz enforcement** — carried from Phase 28's
  deferred list; still its own phase.
- **Broader error-taxonomy sweep beyond mainstream create paths** — QUAL-03
  targets mainstream create/edge-uniqueness paths; a full audit of every
  `Migration`-mapped site across all repos is out of scope for GA.

None of the above are in Phase 29 scope — discussion stayed within the locked
QUAL-01…07 boundary.

</deferred>

---

*Phase: 29-structural-quality*
*Context gathered: 2026-07-05*
