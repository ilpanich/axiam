---
phase: 24-security-hardening-i-authentication-access-control-surfaces
plan: 07
subsystem: api
tags: [rate-limiting, grpc, tonic, tower, surrealdb, ip-spoofing, fail-open]

# Dependency graph
requires:
  - phase: 24-security-hardening-i-authentication-access-control-surfaces
    provides: "24-04's SurrealRateLimitBucketRepository::increment windowed-CAS counter and rate_limit_bucket schema table"
provides:
  - "GrpcTrustedHopsKeyExtractor: trusted_hops-aware tower_governor::KeyExtractor for gRPC, replacing SmartIpKeyExtractor"
  - "GrpcSharedRateLimitLayer/GrpcSharedRateLimitService: async SurrealDB shared-store pre-check tower::Layer for the gRPC path, fail-open to the in-memory GovernorLayer"
affects: [26-correctness-resilience]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Custom tower_governor::KeyExtractor reading tonic's TcpConnectInfo/TlsConnectInfo<TcpConnectInfo> request extensions (the ones tonic's ConnectInfoLayer actually inserts) instead of SmartIpKeyExtractor's axum::extract::ConnectInfo<SocketAddr>/bare SocketAddr lookups, which tonic never sets"
    - "Async tower::Layer/Service pre-check (clone-and-swap inner service, Box::pin(async move) with an explicit + Send future) performing its own SurrealDB round-trip before delegating — NOT a governor::StateStore impl, mirrors the REST Actix RateLimitShared shape but for tower/tonic"
    - "RPIT (impl Trait) test doubles for tower Services need an explicit `Future: Send` associated-type bound (and `+ Send` on the opaque type itself) — auto-trait leakage through an opaque return type does not implicitly satisfy a caller's `S::Future: Send` requirement without it"

key-files:
  created:
    - crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs
  modified:
    - crates/axiam-api-grpc/src/middleware/rate_limit.rs
    - crates/axiam-api-grpc/Cargo.toml
    - Cargo.toml
    - Cargo.lock

key-decisions:
  - "Production wiring of GrpcSharedRateLimitLayer into start_grpc_server/main.rs is OUT OF SCOPE for this plan (files_modified frontmatter listed only rate_limit.rs + the test file) — start_grpc_server is currently generic over repository traits (R,P,Res,S,G,U) with no concrete Surreal<C> handle threaded through it at all, so wiring requires a broader signature change than this plan's file scope allows; tracked as a gap, see Next Phase Readiness"
  - "axiam-db/surrealdb promoted from dev-dependencies to regular dependencies of axiam-api-grpc — the shared-store layer is library code (not test-only), unlike the REST plan-24-04 middleware which already had axiam-db as a regular dependency"
  - "Added http = \"1\" as an explicit workspace + crate dependency — required for the tower_governor::KeyExtractor trait signature (fn extract<T>(&self, req: &http::Request<T>)), which axiam-api-grpc had never needed directly before (it only used tonic's re-exported Request type)"
  - "endpoint key for the gRPC shared bucket uses a caller-supplied &'static str (mirrors REST's per-endpoint '{endpoint}:{ip}' key), NOT the gRPC method path — the existing single build_grpc_governor_layer(authz_per_sec) governs the WHOLE gRPC server with one quota, not per-RPC-method quotas, so a single shared-store endpoint constant preserves that same one-quota-for-everything shape rather than accidentally granting each RPC method its own independent shared-store budget"

patterns-established:
  - "GrpcSharedRateLimitLayer::new(db, endpoint, limit, trusted_hops).layer(inner) must be `.layer()`'d BEFORE build_grpc_governor_layer(...) on the same Server::builder() — tower::ServiceBuilder/Server::builder() executes the FIRST-added layer with the request FIRST (the opposite of actix's last-.wrap()-is-outermost rule established in 24-04)"

requirements-completed: [SECHRD-03]

coverage:
  - id: D1
    description: "Custom trusted_hops-aware gRPC KeyExtractor replaces SmartIpKeyExtractor, keying off the verified tonic peer address when XFF hops are insufficient, with the Quota::per_second(...).burst_size(...) throughput math left byte-for-byte unchanged"
    requirement: "SECHRD-03"
    verification:
      - kind: unit
        ref: "crates/axiam-api-grpc/src/middleware/rate_limit.rs#middleware::rate_limit::tests::uses_rightmost_trusted_xff_hop_when_enough_hops_present"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-grpc/src/middleware/rate_limit.rs#middleware::rate_limit::tests::falls_back_to_peer_addr_when_trusted_hops_exceeds_hop_count"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-grpc/src/middleware/rate_limit.rs#middleware::rate_limit::tests::errors_when_no_xff_and_no_peer_info"
        status: pass
    human_judgment: false
  - id: D2
    description: "gRPC shared-store pre-check enforces one combined limit across two independent layered service instances sharing one SurrealDB (cross-replica enforcement)"
    requirement: "SECHRD-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs#rate_limit_shared_store_cross_instance"
        status: pass
    human_judgment: false
  - id: D3
    description: "A rotating (attacker-spoofed) single-hop X-Forwarded-For header does not mint a fresh bucket when trusted_hops >= hops.len() — the shared bucket is keyed off the verified peer address (D-01d parity)"
    requirement: "SECHRD-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs#rate_limit_shared_store_peer_parity_rotating_xff"
        status: pass
    human_judgment: false
  - id: D4
    description: "A broken SurrealDB handle fails OPEN — the request proceeds to the inner service, never a hard rejection (D-01b)"
    requirement: "SECHRD-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs#rate_limit_shared_store_fails_open_on_db_error"
        status: pass
    human_judgment: false

duration: 33min
completed: 2026-07-04
status: complete
---

# Phase 24 Plan 07: gRPC rate-limit parity (key-extractor + shared store) Summary

**Custom trusted_hops-aware tower_governor::KeyExtractor keying off tonic's verified TcpConnectInfo/TlsConnectInfo peer address (replacing SmartIpKeyExtractor, which could never find tonic's real peer info at all), plus an async GrpcSharedRateLimitLayer reusing the plan-24-04 SurrealRateLimitBucketRepository, fail-open to the untouched in-memory GovernorLayer.**

## Performance

- **Duration:** 33 min
- **Started:** 2026-07-04T10:44:08Z (previous plan's completion)
- **Completed:** 2026-07-04T11:17:28Z
- **Tasks:** 2
- **Files modified:** 5 (1 created, 4 modified)

## Accomplishments

- Replaced `tower_governor::SmartIpKeyExtractor` with a new `GrpcTrustedHopsKeyExtractor` that mirrors the fixed REST `XForwardedForKeyExtractor` (plan 24-03): a configured `trusted_hops` selects the rightmost trusted XFF hop, and when `trusted_hops >= hops.len()` the header is ignored entirely and the key is derived from the verified tonic connection peer address (`TcpConnectInfo`/`TlsConnectInfo<TcpConnectInfo>` — the extension types tonic's `ConnectInfoLayer` actually inserts) instead of `hops[0]`.
- Discovered (and fixed via the new extractor, not merely documented) that `SmartIpKeyExtractor` could never resolve a real peer address on this codebase's tonic server AT ALL — it only checks for `axum::extract::ConnectInfo<SocketAddr>` or a bare `SocketAddr` extension, neither of which tonic's transport ever inserts; tonic inserts `TcpConnectInfo`/`TlsConnectInfo<TcpConnectInfo>` instead. This is a stronger fix than the plan's literal "leftmost-hop" framing implied.
- Left `Quota::per_second(authz_per_sec).burst_size(authz_per_sec * 2)` byte-for-byte unchanged (CORR-01/Phase 26 territory) — only the key extractor type/logic changed.
- Added `GrpcSharedRateLimitLayer`/`GrpcSharedRateLimitService`, a new async `tower::Layer`/`Service` that reuses `SurrealRateLimitBucketRepository::increment` (plan 24-04) with a `"{endpoint}:{ip}"` key, running conceptually BEFORE the in-memory `GovernorLayer` (documented ordering: tower's first-`.layer()`-call executes first, the opposite of actix's last-`.wrap()`-is-outermost rule from 24-04). Deliberately not a `governor::StateStore` impl and never calls `block_on`.
- Proved cross-instance enforcement, peer-parity under a rotating spoofed XFF header, and fail-open on a broken SurrealDB handle via three new integration tests exercising the tower `Service` contract directly (manually-constructed `http::Request<tonic::body::Body>` with `TcpConnectInfo` extensions) rather than a live TCP gRPC roundtrip — avoiding the flakiness/ceremony of spinning up a real server while still exercising the exact production types.

## Task Commits

Each task was committed atomically:

1. **Task 1: Custom trusted_hops-aware gRPC KeyExtractor (parity with REST) — quota math untouched** - `3cc33a8` (feat)
2. **Task 2: gRPC shared-store pre-check (fail-open) reusing the plan-24-04 repository + negative test** - `fa1064a` (feat)

**Plan metadata:** (this commit, pending)

## Files Created/Modified

- `crates/axiam-api-grpc/src/middleware/rate_limit.rs` - `GrpcTrustedHopsKeyExtractor` (Task 1) + `GrpcSharedRateLimitLayer`/`GrpcSharedRateLimitService` (Task 2), plus unit tests for the extractor
- `crates/axiam-api-grpc/Cargo.toml` - added `http` (Task 1); promoted `axiam-db`/`surrealdb` from dev- to regular dependencies (Task 2)
- `Cargo.toml` - added `http = "1"` to `[workspace.dependencies]`
- `Cargo.lock` - updated dependency graph for the new `http` edge
- `crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs` - cross-instance, peer-parity, and fail-open integration tests (new)

## Decisions Made

- Production wiring of `GrpcSharedRateLimitLayer` into `start_grpc_server`/`main.rs` was intentionally NOT done in this plan — the plan's `files_modified` frontmatter scoped this plan to exactly `crates/axiam-api-grpc/src/middleware/rate_limit.rs` and the test file. `start_grpc_server<R,P,Res,S,G,U>` is generic over repository traits with no `Surreal<C>` handle threaded through it anywhere (unlike REST, whose middleware pulls `Surreal<C>` from `web::Data` at request time — no such per-request app-data mechanism exists in tonic's `Server::builder()`), so wiring this in would require a broader signature change than this plan's declared scope. This mirrors 24-04's own summary, which explicitly deferred the gRPC half to this plan; see "Next Phase Readiness" below for the follow-up needed to make the mitigation live.
- `axiam-db`/`surrealdb` promoted from `[dev-dependencies]` to `[dependencies]` in `axiam-api-grpc/Cargo.toml` — the shared-store layer is now production library code (not test-only), unlike before when `axiam-db` was only pulled in by gRPC integration tests.
- Added `http = "1"` as a new explicit dependency (workspace + crate) — `tower_governor::KeyExtractor::extract<T>(&self, req: &http::Request<T>)` requires the raw `http` crate's `Request` type, which `axiam-api-grpc` had never depended on directly (it only used `tonic`'s re-exported types before).
- Chose a single caller-supplied `&'static str` endpoint constant for the shared-store key rather than deriving it from the gRPC method path — the existing `build_grpc_governor_layer(authz_per_sec)` already governs the WHOLE gRPC server with ONE shared quota (not per-method quotas), so a per-method shared-store key would have granted each RPC method its own independent budget, diverging from the in-memory governor's semantics it's meant to parallel.
- Test doubles built via `tower::service_fn(...)` returned as `-> impl Service<...> + Clone` needed an explicit `Future: Send` associated-type bound plus `+ Send` on the opaque return type itself — without it, `cargo test` failed with "`<... as Service<...>>::Future` cannot be sent between threads safely" at the call sites, even though the underlying concrete future is trivially Send. Auto-trait leakage through an RPIT's associated type does not automatically satisfy a caller's `S::Future: Send` bound; it must be spelled out.

## Deviations from Plan

**1. [Rule 1 - Bug, discovered not merely documented] `SmartIpKeyExtractor` could never resolve tonic's peer address at all**
- **Found during:** Task 1 (reading the current `rate_limit.rs` and `tower_governor`'s `SmartIpKeyExtractor` source)
- **Issue:** The plan's framing described the bug as "unconditionally trusts the leftmost X-Forwarded-For hop" (parity with REST's XFF fix). Reading `tower_governor::key_extractor::SmartIpKeyExtractor::extract`'s fallback chain showed its peer-address fallback (`maybe_connect_info`/`maybe_socket_addr`) only checks for an `axum::extract::ConnectInfo<SocketAddr>` extension or a bare `SocketAddr` extension — but tonic's `ConnectInfoLayer` inserts `TcpConnectInfo`/`TlsConnectInfo<TcpConnectInfo>` instead. So even with NO XFF header present at all, `SmartIpKeyExtractor` could never find a real peer address on this codebase's tonic server — it wasn't just an XFF-trust bug, the peer-address fallback path was already broken independent of any header.
- **Fix:** `GrpcTrustedHopsKeyExtractor`'s peer-address fallback (`grpc_peer_addr`) reads `TcpConnectInfo`/`TlsConnectInfo<TcpConnectInfo>` directly, mirroring `tonic::Request::remote_addr()`'s own extension lookup exactly.
- **Files modified:** `crates/axiam-api-grpc/src/middleware/rate_limit.rs` (same file already in scope for Task 1).
- **Verification:** `falls_back_to_peer_addr_when_trusted_hops_exceeds_hop_count` and `errors_when_no_xff_and_no_peer_info` unit tests exercise both the peer-found and peer-not-found paths against `TcpConnectInfo` extensions.
- **Committed in:** `3cc33a8` (Task 1 commit)

**2. [Rule 3 - Blocking] `http` crate added as an explicit dependency**
- **Found during:** Task 1 (implementing `tower_governor::KeyExtractor` for the custom extractor)
- **Issue:** The `KeyExtractor` trait signature is `fn extract<T>(&self, req: &http::Request<T>) -> Result<Self::Key, GovernorError>`, requiring the raw `http` crate's `Request<T>` type. `axiam-api-grpc` had never depended on `http` directly (only via `tonic`'s internal re-export, not exposed at the crate boundary).
- **Fix:** Added `http = "1"` to `[workspace.dependencies]` and to `axiam-api-grpc`'s `[dependencies]` (already resolved in `Cargo.lock` transitively via `tonic`, so no new network fetch was needed).
- **Files modified:** `Cargo.toml`, `crates/axiam-api-grpc/Cargo.toml`, `Cargo.lock`.
- **Verification:** `cargo build -p axiam-api-grpc` and `cargo clippy -p axiam-api-grpc --all-targets -- -D warnings` both pass clean.
- **Committed in:** `3cc33a8` (Task 1 commit)

**3. [Rule 3 - Blocking] `axiam-db`/`surrealdb` promoted from dev- to regular dependencies**
- **Found during:** Task 2 (implementing `GrpcSharedRateLimitLayer`, which reuses `SurrealRateLimitBucketRepository` in library, not test, code)
- **Issue:** `axiam-api-grpc/Cargo.toml` only had `axiam-db`/`surrealdb` in `[dev-dependencies]` (used by gRPC integration tests). Task 2's shared-store layer is production library code that needs `SurrealRateLimitBucketRepository`/`Surreal<C>` at the `[dependencies]` level.
- **Fix:** Moved `axiam-db = { workspace = true }` and `surrealdb = { workspace = true }` into `[dependencies]`; kept the `kv-mem`-featured `surrealdb` dev-dependency for tests (the same dual-declaration pattern already proven in `axiam-api-rest/Cargo.toml`).
- **Files modified:** `crates/axiam-api-grpc/Cargo.toml`.
- **Verification:** `cargo build -p axiam-api-grpc` and both scoped test commands pass.
- **Committed in:** `fa1064a` (Task 2 commit)

**4. [Rule 3 - Blocking] RPIT `Future: Send` bound needed in the new test file**
- **Found during:** Task 2 (writing `rate_limit_shared_store_test.rs`'s trivial inner `tower::service_fn` test double)
- **Issue:** `fn ok_service() -> impl Service<..., Error = Infallible> + Clone` compiled at the crate level (`cargo build`/`cargo clippy` both passed) but failed at the test's call sites with `<... as Service<...>>::Future cannot be sent between threads safely`, because `GrpcSharedRateLimitService::call`'s `Box::pin(async move {...} )` must coerce to `Pin<Box<dyn Future<...> + Send>>`, and that coercion's Send-proof is only actually evaluated once the opaque `S`/`S::Future` types are resolved at the concrete call site — an RPIT's associated type does not automatically expose its own auto-trait properties to a caller's generic bound without being spelled out.
- **Fix:** Changed the test double's signature to `-> impl Service<..., Future: Send> + Clone + Send`, explicitly asserting both the opaque service type and its associated `Future` are `Send`.
- **Files modified:** `crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs`.
- **Verification:** `cargo test -p axiam-api-grpc --test rate_limit_shared_store_test` — all 3 tests pass.
- **Committed in:** `fa1064a` (Task 2 commit)

---

**Total deviations:** 4 auto-fixed (1 bug found-and-fixed beyond the plan's literal framing, 3 blocking dependency/type-system issues)
**Impact on plan:** All four were necessary for the plan's stated behavior to actually compile and work correctly; no scope creep beyond `rate_limit.rs`, its `Cargo.toml`, and the new test file (plus the minimal workspace `Cargo.toml`/`Cargo.lock` dependency additions those changes required).

## Issues Encountered

- None beyond the deviations documented above (all self-resolved via the deviation rules; no checkpoint or human input was required).

## User Setup Required

None - no external service configuration required. No new environment variables (reuses the existing `AXIAM__RATE_LIMIT__TRUSTED_HOPS`).

## Next Phase Readiness

- The gRPC key-extractor fix (`GrpcTrustedHopsKeyExtractor`) IS live in production as soon as this commit ships — `build_grpc_governor_layer` (already wired into `server.rs`/`start_grpc_server`) now uses it unconditionally, no additional wiring needed.
- The shared-store layer (`GrpcSharedRateLimitLayer`) is fully implemented and tested but is **NOT yet wired into `start_grpc_server`/`main.rs`** — this plan's file scope excluded `server.rs`/`main.rs`, and `start_grpc_server<R,P,Res,S,G,U>` currently has no `Surreal<C>` handle threaded through it at all (unlike the REST server, which resolves `Surreal<C>` from `web::Data` at request time). Making SECHRD-03's gRPC multi-replica mitigation live in production requires a follow-up plan that either (a) adds a `Surreal<C>` parameter to `start_grpc_server` and calls `.layer(GrpcSharedRateLimitLayer::new(db, "grpc_authz", grpc_config.grpc_authz_per_sec, trusted_hops))` before `.layer(build_grpc_governor_layer(...))` in `server.rs`, or (b) an equivalent mechanism. Until then, the gRPC path still has the SAME per-replica in-memory-only multi-replica gap the REST half of 24-04 already closed — flagged here rather than silently left as a gap.
- ROADMAP SC #2 (gRPC parity) is satisfied for the key-extractor half (D-01c/D-01d); the shared-store half (D-01a/D-01c) is implemented+tested but not yet load-bearing in production pending the follow-up above.
- No blockers for subsequent plans in this phase (24-08, 24-09 are unrelated bootstrap/consent work).

---
*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Completed: 2026-07-04*

## Self-Check: PASSED

All created/modified files (`crates/axiam-api-grpc/src/middleware/rate_limit.rs`, `crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs`) and both task commit hashes (`3cc33a8`, `fa1064a`) verified present on disk and in `git log`.
