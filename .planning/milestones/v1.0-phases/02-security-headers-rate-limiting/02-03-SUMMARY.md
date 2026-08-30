---
phase: 02-security-headers-rate-limiting
plan: 03
subsystem: api
tags: [tower-governor, grpc, tonic, rate-limiting, service-mesh]

requires:
  - phase: 01-cookie-auth
    provides: gRPC server infrastructure
provides:
  - GovernorLayer on gRPC server with SmartIpKeyExtractor
  - Configurable grpc_authz_per_sec (default: 100)
affects: [grpc-services]

tech-stack:
  added: [tower-governor 0.8, governor 0.10]
  patterns: [tower layer-based rate limiting on tonic Server]

key-files:
  created:
    - crates/axiam-api-grpc/src/middleware/mod.rs
    - crates/axiam-api-grpc/src/middleware/rate_limit.rs
  modified:
    - crates/axiam-api-grpc/src/config.rs
    - crates/axiam-api-grpc/src/lib.rs
    - crates/axiam-api-grpc/src/server.rs

key-decisions:
  - "100 req/sec default — generous for service-mesh patterns where authz is called per-request"
  - "SmartIpKeyExtractor from tower-governor reads x-forwarded-for/x-real-ip automatically"
  - "GovernorLayer applied to entire Server::builder(), not per-service"
  - "NoOpMiddleware — gRPC transport doesn't use HTTP rate-limit headers"

patterns-established:
  - "gRPC middleware via .layer() on Server::builder()"
  - "GrpcConfig accepts grpc_authz_per_sec via AXIAM__GRPC__GRPC_AUTHZ_PER_SEC"

requirements-completed: [REQ-3]

duration: 10min
completed: 2026-04-06
---

# Plan 02-03: gRPC Rate Limiting Summary

**Tower-governor rate limiting on gRPC server (100 req/sec default) with SmartIpKeyExtractor**

## Performance

- **Duration:** 10 min (inline execution)
- **Tasks:** 1
- **Files modified:** 6

## Accomplishments
- GovernorLayer with SmartIpKeyExtractor applied to tonic Server::builder()
- GrpcConfig extended with grpc_authz_per_sec (default 100, configurable via env)
- Middleware module created for gRPC crate
- Consistent governor-based approach with REST rate limiting

## Task Commits

1. **Task 1: tower-governor dep + GovernorLayer + config** - `5216baf` (feat)

## Files Created/Modified
- `crates/axiam-api-grpc/src/middleware/rate_limit.rs` - build_grpc_governor_layer
- `crates/axiam-api-grpc/src/middleware/mod.rs` - Module declaration
- `crates/axiam-api-grpc/src/config.rs` - grpc_authz_per_sec field
- `crates/axiam-api-grpc/src/server.rs` - .layer(governor_layer)
- `crates/axiam-api-grpc/src/lib.rs` - pub mod middleware

## Decisions Made
- Server-wide layer (not per-service) since all gRPC endpoints should be rate-limited equally

## Deviations from Plan
- main.rs needed grpc_config clone and pass-through to start_grpc_server (plan mentioned but didn't detail the move semantics)

## Issues Encountered
None.

## Next Phase Readiness
- gRPC rate limiting complete — consistent with REST approach using governor crate

---
*Phase: 02-security-headers-rate-limiting*
*Completed: 2026-04-06*
