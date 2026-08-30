---
phase: 24-security-hardening-i-authentication-access-control-surfaces
plan: 04
subsystem: api
tags: [rate-limiting, surrealdb, actix-web, middleware, multi-replica, fail-open]

# Dependency graph
requires:
  - phase: 24-security-hardening-i-authentication-access-control-surfaces
    provides: "24-03's fixed XForwardedForKeyExtractor (peer_addr() fallback when trusted_hops >= hops.len())"
provides:
  - "rate_limit_bucket SurrealDB table (schema v21) + SurrealRateLimitBucketRepository windowed-CAS counter"
  - "RateLimitShared async Actix middleware: SurrealDB shared-store pre-check wired before every REST build_governor(...) call site, fail-open to the in-memory governor on DB error"
affects: [24-07-gRPC-shared-rate-limit-parity, 26-correctness-resilience]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Async pre-check Actix middleware (Transform + Rc<S> Service) that awaits a DB round-trip before conditionally delegating to the inner service — NOT a governor::StateStore impl (that trait is synchronous)"
    - "Fixed-window SurrealDB counter via UPSERT ... RETURN AFTER windowed CAS, mirroring increment_failed_logins's read-before-write-in-one-statement semantics"

key-files:
  created:
    - crates/axiam-db/src/repository/rate_limit.rs
    - crates/axiam-api-rest/src/middleware/rate_limit_shared.rs
    - crates/axiam-api-rest/tests/rate_limit_shared_store_test.rs
  modified:
    - crates/axiam-db/src/schema.rs
    - crates/axiam-db/src/repository/mod.rs
    - crates/axiam-db/src/lib.rs
    - crates/axiam-api-rest/src/middleware/mod.rs
    - crates/axiam-api-rest/src/server.rs

key-decisions:
  - "seeder.rs left untouched: it only seeds tenant permissions/roles, not schema; rate_limit_bucket is applied automatically by the existing run_migrations() startup call in main.rs (schema v21, additive) — no separate seeding step exists or is needed for this table"
  - "RateLimitShared wraps ALL 20 REST build_governor(...) call sites in server.rs (login, MFA x5, password reset/change, account delete-cancel, federation OIDC/SAML x4, oauth2 token/revoke/introspect, users create, account export/delete, authz check x2) per D-01c's REST-coverage requirement — not just /login"
  - "Middleware reads Surreal<C> from req.app_data::<web::Data<Surreal<C>>>() at request time (same mechanism every repository-backed handler uses) rather than threading a DB handle through register_api_v1_routes's signature — no signature change needed on the existing route-registration function"
  - "Fixed-window (not GCRA) counter for the shared layer: acceptable per RESEARCH's 'Don't Hand-Roll' guidance since this layer only needs to be approximately right (fails open by design); the in-memory GCRA governor remains the precise fallback"

patterns-established:
  - "RateLimitShared::<C>::new(endpoint, limit) must be the LAST .wrap() call on a resource (after build_governor(...)) since actix's last-registered Transform is outermost and therefore executes first — this is how the shared pre-check runs BEFORE the in-memory governor without needing to compose them into one type"

requirements-completed: [SECHRD-03]

coverage:
  - id: D1
    description: "rate_limit_bucket table + SurrealRateLimitBucketRepository windowed-CAS counter with per-endpoint key granularity"
    requirement: "SECHRD-03"
    verification:
      - kind: unit
        ref: "crates/axiam-db/src/repository/rate_limit.rs#rate_limit_bucket_increment_sequence_and_window_reset"
        status: pass
    human_judgment: false
  - id: D2
    description: "Async shared-store rate-limit pre-check middleware enforces one combined limit across two independent app instances sharing one SurrealDB (cross-replica enforcement)"
    requirement: "SECHRD-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/rate_limit_shared_store_test.rs#rate_limit_shared_store_cross_instance"
        status: pass
    human_judgment: false
  - id: D3
    description: "Shared-store outage (DB error, or no DB/IP available) fails OPEN — request proceeds with no 5xx, never hard-blocking auth (D-01b)"
    requirement: "SECHRD-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/rate_limit_shared_store_test.rs#rate_limit_shared_store_fails_open_on_db_error"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-rest/tests/rate_limit_shared_store_test.rs#rate_limit_shared_store_fails_open_when_no_db_registered"
        status: pass
    human_judgment: false

duration: 28min
completed: 2026-07-04
status: complete
---

# Phase 24 Plan 04: Multi-replica shared rate-limit store Summary

**SurrealDB-backed windowed-CAS rate-limit counter shared across replicas via a new async Actix pre-check middleware, wired before every REST governor endpoint and failing open to the existing in-memory Governor on any DB error.**

## Performance

- **Duration:** 28 min
- **Started:** 2026-07-04T09:12:23Z (previous plan's completion commit)
- **Completed:** 2026-07-04T09:39:51Z
- **Tasks:** 2
- **Files modified:** 8 (3 created, 5 modified)

## Accomplishments

- Added `rate_limit_bucket` SurrealDB table (schema v21, additive) and `SurrealRateLimitBucketRepository::increment` — a windowed compare-and-set counter keyed by `"{endpoint}:{ip}"`, so per-endpoint limits are preserved rather than collapsed into one global bucket.
- Added `RateLimitShared`, a NEW async Actix `Transform`/`Service` middleware that runs the SurrealDB CAS increment BEFORE the existing per-replica in-memory `Governor`/`GovernorLayer` (kept byte-for-byte unchanged as the fail-open fallback per D-01b). Deliberately NOT a `governor::StateStore` impl and never calls `block_on` (`StateStore::measure_and_replace` is synchronous — RESEARCH Pitfall 1).
- Wired `RateLimitShared` onto all 20 REST resources that currently call `build_governor(...)` in `server.rs` — login, all 5 MFA endpoints, password reset/change, account-delete-cancel, both federation OIDC/SAML first-time-SSO pairs, oauth2 token/revoke/introspect, user registration, GDPR export/delete, and both authz-check endpoints — closing the multi-replica HPA gap across the full REST rate-limited surface, not just `/login`.
- Proved cross-replica enforcement: two independent app instances ("replicas") sharing one SurrealDB handle enforce a single combined limit — the request that exceeds the limit is rejected on EITHER replica, which an in-memory-only baseline would not do.
- Proved fail-open (D-01b): a broken DB handle (no namespace/database selected) and a missing `web::Data<Surreal<C>>` registration both result in the request proceeding with `200`, never a `5xx` or hard block.

## Task Commits

Each task was committed atomically:

1. **Task 1: rate_limit_bucket table + SurrealRateLimitBucketRepository windowed-CAS counter** - `136d538` (feat)
2. **Task 2: Async shared-store pre-check Actix middleware (fail-open) wired before the in-memory Governor + cross-instance test** - `a8c740c` (feat)

**Plan metadata:** (this commit, pending)

## Files Created/Modified

- `crates/axiam-db/src/repository/rate_limit.rs` - `SurrealRateLimitBucketRepository::increment` windowed-CAS counter (new)
- `crates/axiam-db/src/schema.rs` - schema v21: `rate_limit_bucket` table (additive)
- `crates/axiam-db/src/repository/mod.rs` - declares/re-exports the new `rate_limit` module
- `crates/axiam-db/src/lib.rs` - re-exports `SurrealRateLimitBucketRepository` at the crate root
- `crates/axiam-api-rest/src/middleware/rate_limit_shared.rs` - `RateLimitShared` async pre-check middleware (new)
- `crates/axiam-api-rest/src/middleware/mod.rs` - declares the new `rate_limit_shared` module
- `crates/axiam-api-rest/src/server.rs` - wires `RateLimitShared::<C>::new(endpoint, limit)` after every `build_governor(...)` call
- `crates/axiam-api-rest/tests/rate_limit_shared_store_test.rs` - cross-instance + two fail-open integration tests (new)

## Decisions Made

- `seeder.rs` was intentionally left untouched. The plan's read_first section referenced it, but `seeder.rs` only seeds tenant permissions/default roles — schema application is entirely owned by `schema::run_migrations`, already invoked at startup in `axiam-server/src/main.rs`. The new `rate_limit_bucket` table is applied automatically the same way every other additive schema version is; no seeding logic was needed or added.
- `RateLimitShared` was wired onto every REST `build_governor(...)` call site (20 total, including the `saml`-feature-gated ones), not just `/login`, matching D-01c's "REST + gRPC both this phase" coverage intent for the REST half (gRPC is out of scope for this plan — see 24-05).
- The middleware reads its `Surreal<C>` handle from `ServiceRequest::app_data::<web::Data<Surreal<C>>>()` at request time rather than changing `register_api_v1_routes`'s signature — this required zero changes to how tests or `main.rs` construct the app, since the DB handle is already registered as `web::Data` everywhere.
- Kept the shared counter a simple fixed-window (not GCRA) design, per RESEARCH's "Don't Hand-Roll" guidance — the layer only needs to be approximately right since it fails open by design; the in-memory `Governor`'s GCRA algorithm remains the precise, always-on fallback.

## Deviations from Plan

**1. [Clarification, not a functional deviation] `seeder.rs` not modified**
- **Found during:** Task 1 (rate_limit_bucket table)
- **Issue:** The plan's `<read_first>`/`<action>` text asked to "ensure `seeder.rs` applies it at startup." Reading `seeder.rs` (permission/role seeding only) and `schema.rs` (the actual migration runner, already called from `main.rs`) showed the startup schema-application path was already generic and required no change — adding a migration to `MIGRATIONS` in `schema.rs` is sufficient and is the same mechanism every other table in this codebase uses.
- **Fix:** No `seeder.rs` edit was made; `schema.rs`'s existing `run_migrations` mechanism (invoked once at server startup) applies the new table automatically.
- **Files modified:** None beyond the schema.rs migration entry already tracked in Task 1's commit.
- **Verification:** `cargo test -p axiam-db rate_limit_bucket` passes against a fresh `run_migrations`-seeded in-memory DB, proving the table is created without any seeder involvement.
- **Committed in:** `136d538` (Task 1 commit)

---

**Total deviations:** 1 clarification (no code-behavior change; documented for traceability against the plan's literal file list)
**Impact on plan:** None — the plan's `files_modified` frontmatter listed `seeder.rs` speculatively; the actual startup-application requirement was already satisfied by the existing `run_migrations` mechanism.

## Issues Encountered

- The first repo unit-test name (`increment_sequence_and_window_reset`) did not contain the substring `rate_limit_bucket`, so the plan's literal verification command (`cargo test -p axiam-db rate_limit_bucket`) filtered it out (0 tests run). Renamed to `rate_limit_bucket_increment_sequence_and_window_reset` so the verification command matches — caught immediately by running the exact verify command before considering the task done.

## User Setup Required

None - no external service configuration required. No new environment variables (reuses the existing `AXIAM__RATE_LIMIT__TRUSTED_HOPS`).

## Next Phase Readiness

- REST half of SECHRD-03's multi-replica shared rate-limit store (D-01a/D-01b/D-01d) is complete and tested; ROADMAP SC #2's shared-store half is satisfied.
- gRPC half (D-01c: store/key-extractor swap on `axiam-api-grpc/src/middleware/rate_limit.rs`, leaving CORR-01's quota math untouched) is out of scope for this plan — tracked as plan 24-07 (`depends_on: [24-04]`) in this phase's directory, which reuses `SurrealRateLimitBucketRepository` from this plan.
- No blockers for subsequent plans in this phase.

---
*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Completed: 2026-07-04*

## Self-Check: PASSED

All created/modified files and both task commit hashes (`136d538`, `a8c740c`) verified present on disk and in `git log`.
