---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: — Client SDKs
current_phase: 17
current_phase_name: typescript-sdk
status: executing
stopped_at: Completed 17-03-PLAN.md
last_updated: "2026-07-01T12:37:16.103Z"
last_activity: 2026-07-01
last_activity_desc: Phase 17 execution started
progress:
  total_phases: 8
  completed_phases: 2
  total_plans: 18
  completed_plans: 17
  percent: 25
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-04)

**Core value:** AXIAM must be secure enough for production use as an IAM system — no beta user should be at risk.
**Current focus:** Phase 17 — typescript-sdk

## Current Position

Phase: 17 (typescript-sdk) — EXECUTING
Plan: 6 of 6
Status: Ready to execute
Last activity: 2026-07-01 — Phase 17 execution started

## Performance Metrics

**Velocity:**

- Total plans completed: 27
- Average duration: -
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 05 | 5 | - | - |
| 07 | 5 | - | - |
| 10 | 6 | - | - |
| 11 | 5 | - | - |
| 15 | 6 | - | - |

**Recent Trend:**

- Last 5 plans: -
- Trend: -

*Updated after each plan completion*
| Phase 01-cookie-based-authentication P01 | 30 | 3 tasks | 7 files |
| Phase 01-cookie-based-authentication P02 | 4 | 2 tasks | 5 files |
| Phase 01-cookie-based-authentication P03 | 23 | 1 tasks | 2 files |
| Phase 02-security-headers-rate-limiting P04 | 35 | 2 tasks | 6 files |
| Phase 02-security-headers-rate-limiting P05 | 10 | 2 tasks | 2 files |
| Phase 03-rbac-enforcement P01 | 20 | 2 tasks | 9 files |
| Phase 03-rbac-enforcement P03 | 15 | 2 tasks | 5 files |
| Phase 03-rbac-enforcement P02 | 45 | 3 tasks | 18 files |
| Phase 03 P05 | 26m | 2 tasks | 8 files |
| Phase 01-cookie-based-authentication P04 | 30m | 8 tasks | 15 files |
| Phase 01-cookie-based-authentication P05 | 45m | 6 tasks | 2 files |
| Phase 02-security-headers-rate-limiting P_UAT | 60m | 5 assertions | 4 files |
| Phase 05-email-delivery-gdpr-compliance P02 | 8 | 2 tasks | 3 files |
| Phase 05-email-delivery-gdpr-compliance P03 | 65 | 2 tasks | 8 files |
| Phase 05-email-delivery-gdpr-compliance P05 | 90m | 3 tasks | 9 files |
| Phase 06-ci-cd-infrastructure-hardening P01 | 45 | 3 tasks | 8 files |
| Phase 06 P03 | 30m | 3 tasks | 5 files |
| Phase 07-compliance-verification-test-closure P02 | 25 | 2 tasks | 6 files |
| Phase 07-compliance-verification-test-closure P03 | 25 | 2 tasks | 3 files |
| Phase 07-compliance-verification-test-closure P04 | 60 | 3 tasks | 13 files |
| Phase 07-compliance-verification-test-closure P05 | 40 | 2 tasks | 3 files |
| Phase 09 P01 | 35min | 3 tasks | 6 files |
| Phase 09-critical-remediation P03 | 44 | 3 tasks | 8 files |
| Phase 10-high-remediation P01 | 25 | 3 tasks | 4 files |
| Phase 10-high-remediation P02 | 22 | 3 tasks | 10 files |
| Phase 10-high-remediation P06 | 45 | 3 tasks | 16 files |
| Phase 10-high-remediation P04 | 38m | 3 tasks | 12 files |
| Phase 10 P05 | 7200 | 3 tasks | 19 files |
| Phase 11-medium-remediation P11-01 | 60m | 3 tasks | 17 files |
| Phase 11 P05 | 391 | 3 tasks | 22 files |
| Phase 11 P11-02 | 120 | 4 tasks | 21 files |
| Phase 12-low-remediation P01 | 45 | 3 tasks | 21 files |
| Phase 12-low-remediation P02 | 10 | 3 tasks | 5 files |
| Phase 12-low-remediation P03 | 18 | 3 tasks | 10 files |
| Phase 12-low-remediation P04 | 15 | 3 tasks | 8 files |
| Phase 13-surrealdb-connection-resilience P02 | 10 | 2 tasks | 2 files |
| Phase 15 P01 | 90min | 3 tasks | 9 files |
| Phase 15 P03 | 8 | 2 tasks | 2 files |
| Phase 15 P04 | 2 | 3 tasks | 4 files |
| Phase 15 P02 | 9 minutes | 2 tasks | 3 files |
| Phase 16-rust-sdk P01 | 25min | 2 tasks | 14 files |
| Phase 16-rust-sdk P02 | 42min | 2 tasks | 11 files |
| Phase 16-rust-sdk P04 | 55min | 2 tasks | 6 files |
| Phase 16-rust-sdk P03 | 55min | 2 tasks | 6 files |
| Phase 16-rust-sdk P05 | 30min | 1 tasks | 6 files |
| Phase 16 P06 | 45min | 2 tasks | 9 files |
| Phase 17-typescript-sdk P01 | 3min | 2 tasks | 20 files |
| Phase 17-typescript-sdk P02 | 9min | 2 tasks | 15 files |
| Phase 17-typescript-sdk P04 | 10min | 2 tasks | 8 files |
| Phase 17-typescript-sdk P03 | 18min | 2 tasks | 11 files |
| Phase 17 P05 | 12min | 2 tasks | 16 files |

## Accumulated Context

### Roadmap Evolution

- 2026-06-10 — Audit-remediation tranche added (5 phases) from `claude_dev/remediation-plan.md` (audits at commit `d69323b`). Mapped wave→phase, kept on branch `feature/full-review` (not the plan's `claude/stoic-dirac-12opcw`, and not a fresh fork off stale main):
  - Phase 8: Build Unblock (Wave 0 — CQ-B37) — REQ-12
  - Phase 9: Critical Remediation (Wave 1) — REQ-13
  - Phase 10: High Remediation (Wave 2) — REQ-14
  - Phase 11: Medium Remediation (Wave 3) — REQ-15
  - Phase 12: Low/Trivial Remediation (Wave 4) — REQ-16
- Sequential, green-build gated (8→9→10→11→12). Per-finding atomic commits happen during execute-phase.
- Note: `gsd-sdk phase.add` mis-numbered (returned 100) because the `99-followups/` sentinel dir inflates its `max+1` counter; phases were authored directly as `08`–`12` instead.
- 2026-06-28 — Milestone v1.1 Client SDKs roadmap created (phases 15–22). Foundation-first structure: Phase 15 (shared artifacts) → Phase 16 (Rust reference impl) → Phases 17–22 (parallelizable per-language SDKs). 12/12 requirements mapped. FND-04 REST authz-check endpoint added to server as part of Phase 15 scope (browser SDK authz path, Q1 resolved). `gsd-sdk phase.add` sentinel bug still present — phase dirs must be authored directly as `15`–`22`.

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Cookie auth is Phase 1 (foundational — all other work depends on stable auth mechanism)
- RBAC follows security headers/rate limiting (need defense-in-depth before exposing endpoints)
- Testing distributed across phases; final phase is compliance verification + remaining gaps
- [Phase 01-cookie-based-authentication]: Used AxiamError::AuthorizationDenied for CSRF failures (no Forbidden variant exists) — maps to HTTP 403 via ResponseError impl
- [Phase 01-cookie-based-authentication]: Login URL uses full /api/v1/auth/login path — consistent with /me and /refresh endpoints
- [Phase 01-cookie-based-authentication]: MFA challenge field renamed to challenge_token matching backend LoginSuccessResponse spec
- [Phase 01-cookie-based-authentication]: Inspect Set-Cookie header string for cookie attribute verification (httpOnly, SameSite, Path) — Cookie object does not expose these
- [Phase 01-cookie-based-authentication]: /auth/mfa/setup/enroll is CSRF exempt because setup_token in body is the auth mechanism (no session cookie exists during enrollment)
- [Phase 02-security-headers-rate-limiting]: is_locked computed from locked_until at serialization time — derived at serialization, always accurate without a separate DB boolean
- [Phase 02-security-headers-rate-limiting]: Inline unlock dialog created instead of extending ConfirmDialog — ConfirmDialog has hardcoded destructive styling not suitable for positive unlock action
- [Phase 02-security-headers-rate-limiting]: Wrap entire /users resource with rate limiter — GET at 5 req/min acceptable for admin list endpoint
- [Phase 02-security-headers-rate-limiting]: lockout_duration_secs default changed from 300 to 900 to match REQ-3 (15-minute cooldown)
- [Phase 03-rbac-enforcement]: TenantRepository has no generic list() — used OrganizationRepository::list() + list_by_organization() to enumerate all tenants for startup seeding
- [Phase 03-rbac-enforcement]: AuthzMiddleware wraps all three API scopes (/auth, /oauth2, /api/v1) with public-path allowlist for auth-exempt endpoints (D-04)
- [Phase 03-rbac-enforcement]: Audit list self-service: restrict to actor_id when caller lacks audit_logs:list permission
- [Phase 03-rbac-enforcement]: New tenants get permissions auto-seeded via seed_permissions in tenants::create handler
- [Phase 03]: 03-05: Fixed pre-existing seed_permissions bug (wrong table name 'permissions' vs 'permission') that broke RBAC grants in every seeded tenant; discovered while debugging super-admin 403
- [Phase 03]: 03-05: RBAC enforcement validated end-to-end via 7-test rbac_test + 4-test bootstrap_test; route-permission parity enforced at test time via ROUTE_PERMISSION_MAP↔PERMISSION_REGISTRY cross-check
- [Phase 01-cookie-based-authentication]: 01-04 gap closure — auth scope moved from /auth to /api/v1/auth so refresh cookie Path and admin UI URL space align with the server; oauth2 and .well-known scopes intentionally unchanged
- [Phase 01-cookie-based-authentication]: 01-05 gap closure — backend login body accepts org_slug/tenant_slug alongside UUIDs and aliases `username` to `username_or_email`, matching the admin UI's payload; slug-resolution failures map to AuthenticationFailed (401) to avoid org/tenant enumeration
- [Phase 01-cookie-based-authentication]: `.app_data(web::Data::new(rest_authz.clone()))` — using `new` (not `from`) wraps the Arc to match handler extractors typed `web::Data<Arc<dyn AuthzChecker>>`; `from` unwraps the Arc and breaks every RBAC-protected endpoint with 500
- [Phase 02-security-headers-rate-limiting]: UAT Test 1 closed via Playwright end-to-end — all 5 lockout UI assertions verified (amber Locked badge, Locked(N) filter toggle, unlock dialog, badge disappearance after unlock, "No locked accounts." empty state); screenshots at .planning/phases/02-security-headers-rate-limiting/uat-evidence/
- [Phase 02-security-headers-rate-limiting]: frontend PaginatedUsers shape aligned with backend PaginatedResult (items/limit), unblocking the admin Users page; broader pagination-contract audit filed as follow-up for other admin services
- [Phase ?]: MAIL_OUTBOUND_DLQ added to ALL_QUEUES loop first; MAIL_OUTBOUND declared separately with x-dead-letter-exchange FieldTable (D-14 explicit dead-letter routing, no broker defaults)
- [Phase ?]: Export stored as DB blob (encrypted_blob), not on-disk file — avoids filesystem lifecycle management
- [Phase 06-01]: deny.toml ignore entries for RUSTSEC-2023-0071 (rsa Marvin attack, no upstream fix), RUSTSEC-2025-0141 (bincode unmaintained via surrealdb), RUSTSEC-2023-0089 (atomic-polyfill unmaintained via surrealdb); BUSL-1.1 exception for surrealdb family; GPL-3.0 exception for actix-governor; cargo-deny 0.18.9 lacks vulnerability/unmaintained top-level advisory fields
- [Phase ?]: Distroless cc-debian12:nonroot for server runtime with SAML .so COPY'd from builder (D-08)
- [Phase ?]: axiam-server healthcheck subcommand replaces curl probe in distroless containers (D-09)
- [Phase ?]: All Dockerfile base images digest-pinned; license labels corrected to Apache-2.0 (D-04/D-10)
- [Phase 06-04]: cookie_secure config-driven via AuthConfig serde default_true() — AXIAM__AUTH__COOKIE_SECURE=false in dev compose; default true in prod (D-18)
- [Phase 06-04]: Route↔OpenAPI parity test uses three-category model: ROUTE_PERMISSION_MAP + PUBLIC_PATHS + AUTHENTICATED_SELF_SERVICE_PATHS (jwt-auth, no named permission) (D-15)
- [Phase 06-04]: vite-plugin-sri3 uses named export { sri } not default export — import corrected; SRI SHA-384 hashes in dist/index.html, sourcemap:false (D-17)
- [Phase ?]: Feature-flag approach for gRPC client stubs: CARGO_FEATURE_CLIENT in build.rs
- [Phase ?]: Governor layer omitted from gRPC test server by design (SmartIpKeyExtractor needs real peer IP)
- [Phase ?]: [Phase 07-05]: ASVS L2 checklist complete with zero open items — 103 controls (94 Pass, 4 N/A, 5 Deferred), no High/Critical deferred (ROADMAP SC #1 satisfied)
- [Phase ?]: [Phase 07-05]: 4 compliance tracking issues (#98-#101) created only after human auditor sign-off; F-05 CSP header is the only Medium deferral
- [Phase ?]: SEC-002 closed: org-nested REST routes guard path org_id against JWT user.org_id (403); org create/list restricted to super-admin
- [Phase 10-02]: PkiConfig.encryption_key is Option<[u8;32]>; absent key returns AxiamError::Internal at encrypt/decrypt call sites — no zero-key fallback (SEC-012, REQ-14 AC-5)
- [Phase 10-02]: load_key_from_env panics on malformed hex/length (startup misconfiguration), returns None for absent keys (runtime degraded mode with warn log)
- [Phase 10-04]: CQ-B03/SEC-033: sparse overrides_json column stores only tenant-explicit fields; org baseline propagates at read time
- [Phase 10-04]: CQ-B05: AMQP nacks set requeue=false with DLQ routes for audit+authz consumers (mirrors D-14 MAIL_OUTBOUND pattern)
- [Phase 10-04]: CQ-B38/SEC-056: GDPR export uses paginated audit collection (1k page size); atomic consume_ready_and_delete prevents double-download TOCTTOU
- [Phase ?]: confirm_mfa uses plain verify_code for enrollment; replay tracking begins at first login
- [Phase ?]: Pagination clamp via serde deserialize_with; SAML Conditions required; InResponseTo validated via stored request_id
- [Phase ?]: Module-level singleton dispatch for toast avoids React context overhead
- [Phase ?]: ProtectedRoute extracted to components/ to satisfy react-refresh ESLint rule; backend RBAC remains authoritative
- [Phase ?]: BFS traversal for resource descendant exclusion prevents circular picks in hierarchy picker
- [Phase 11]: 11-02: Ed25519 parse-once cached in AuthConfig (axiam-auth) not axiam-oauth2 — the real PEM-parse site (CQ-B14)
- [Phase 11]: 11-02: mTLS chain verify fails closed when issuing CA cannot be resolved (SEC-024)
- [Phase ?]: Seed script db targeting
- [Phase ?]: Just recipe delegation pattern
- [v1.1 Phase 15]: FND-04 REST authz endpoint chosen over documenting the no-`can()` limitation — adds `POST /api/v1/authz/check` to the otherwise-frozen v1.0 surface; same AuthorizationEngine as gRPC, rate-limited, included in OpenAPI spec and parity test
- [v1.1 Phase 15]: C# is the documented exception to the buf codegen pipeline — uses Grpc.Tools MSBuild instead; all other languages go through buf
- [v1.1 Phase 17]: TypeScript browser persona authz uses FND-04 REST endpoint; Node persona uses gRPC CheckAccess; separate export conditions (axiam-sdk/rest, axiam-sdk/grpc, axiam-sdk/amqp) allow tree-shaking
- [v1.1 Phase 22]: PHP gRPC guarded by `extension_loaded('grpc')` at runtime; SDK falls back to REST-only when absent; Swoole/RoadRunner documented as long-running runtime requirement for gRPC
- [Phase ?]: authz:check_as in PERMISSION_REGISTRY only, not ROUTE_PERMISSION_MAP
- [Phase ?]: Both authz-check paths in AUTHENTICATED_SELF_SERVICE_PATHS, not ROUTE_PERMISSION_MAP
- [Phase ?]: Batch validates authz:check_as once for all cross-subject checks — atomic 403
- [Phase ?]: tenant_id from authenticated user only — never from request body (T-15-03)
- [Phase ?]: sdks/CONTRACT.md is the normative/binding (D-09) cross-language SDK contract; canonical D-10 vocabulary locked in Phase 15 before any SDK is built
- [Phase ?]: bufbuild/buf-action@v1.4.0 pinned after orchestrator verification of BSR plugin names; local buf generate deferred to CI
- [v1.1 Phase 15-02]: --dump-openapi placed before tracing_subscriber::fmt() and before load_config() — usable in CI without any running infrastructure
- [v1.1 Phase 15-02]: sdks/openapi.json committed with --no-default-features (SAML excluded); drift gate pins identical feature set in both export and diff steps (Pitfall 2 avoided)
- [v1.1 Phase 15-02]: release-tag trigger (v*) and push-to-main share a single YAML push: block to avoid duplicate-key YAML parse error
- [v1.1 Phase 16-01]: sdks/rust/Cargo.toml carries an empty [workspace] table to opt out of the root AXIAM Cargo workspace (edition 2021 vs workspace edition 2024) — without it `cargo build`/`cargo metadata` error with "current package believes it's in a workspace when it's not"
- [v1.1 Phase 16-01]: src/lib.rs is the single owner of all Phase 16 module declarations (client/token/rest/grpc/amqp/middleware); placeholder module files committed in 16-01 so downstream plans 16-02..16-05 never edit lib.rs, avoiding parallel-wave merge conflicts
- [v1.1 Phase 16-01]: AxiamError::Network carries `source: Option<Box<dyn Error + Send + Sync>>` rather than a #[from]-derived cause type until concrete transport errors exist in 16-02/16-03/16-04
- [Phase 16-rust-sdk]: Pinned jsonwebtoken's rust_crypto backend feature explicitly — no default crypto provider is selected by jsonwebtoken 10, and this standalone crate has no workspace neighbor to resolve one transitively
- [Phase 16-rust-sdk]: Added optional org_slug/org_id builder methods beyond CONTRACT.md §5's tenant-only mandate — AXIAM's real login/refresh endpoints require an organization identifier; resolved org UUID is cached from the access token's org_id claim after first login
- [Phase 16-rust-sdk]: Gated client.rs and the reqwest-touching half of token/jwks.rs behind cfg(feature = "rest") to preserve 16-01's cargo build --no-default-features invariant
- [Phase ?]: [Phase 16-rust-sdk] 16-04: tracing promoted to a required (non-optional) amqp-feature dependency, independent of observability — the CONTRACT.md §8.4 security-event log on HMAC failure is a correctness/security control (T-16-11), not optional instrumentation
- [Phase ?]: [Phase 16-rust-sdk] 16-04: AckableDelivery pub(crate) trait seam (lapin::message::Delivery in prod, RecordingDelivery in tests) proves the nack-without-requeue HMAC-failure contract without a live broker
- [Phase ?]: 16-03: AuthzGrpcClient uses a caller-supplied RefreshFn closure instead of depending on AxiamClient/reqwest, so --no-default-features --features grpc has a fully working single-flight refresh mechanism with zero REST transport pulled in
- [Phase ?]: 16-03: tonic grpc-feature pinned to transport+codegen+tls-ring+tls-native-roots (no default features) since Endpoint::from_shared does not auto-enable TLS the way Endpoint::new does
- [Phase ?]: [Phase 16-rust-sdk] 16-05: AxiamUser.roles derived from the access token's scope claim (space-separated), not a roles claim — AXIAM's AccessTokenClaims has no roles field server-side
- [Phase ?]: [Phase 16-rust-sdk] 16-05: actix feature declared as ["dep:actix-web", "rest"] so the extractor reuses the single shared JwksVerifier instead of forking a second JWKS implementation
- [Phase ?]: [Phase 16-rust-sdk] 16-05: broadened JwksVerifier's cfg gate to any(feature = "rest", feature = "actix") per 16-02's documented hand-off note
- [Phase ?]: [Phase 16-rust-sdk] 16-06: Added Cargo.toml include list bundling gitignored src/gen/ gRPC stubs -- cargo package/publish follow include/exclude not .gitignore, resolving the pre-existing cargo publish --dry-run gap 16-03 flagged
- [Phase ?]: [Phase 16-rust-sdk] 16-06: SDK Rust CI regenerates gRPC stubs via cargo build --features grpc (build.rs tonic-prost-build) rather than invoking buf CLI directly -- avoids sourcing a new GitHub Action SHA pin (GitHub unreachable from this environment's egress policy) while still satisfying D-09
- [Phase ?]: [Phase 16-rust-sdk] 16-06: cargo publish --dry-run/publish require --allow-dirty in CI because the newly-included src/gen/ is gitignored-but-present by design, not because the gate is weakened
- [Phase 17-typescript-sdk]: 17-01 externalized runtime deps in tsup.config.ts so dist/ never bundles axios/jose/tough-cookie/axios-cookiejar-support/@grpc/grpc-js/amqplib
- [Phase 17-typescript-sdk]: 17-01 fixed AximClient typo to AxiamClient in README.md in addition to src/ (D-14 repo-wide intent)
- [Phase 17-typescript-sdk]: 17-02: Added jsdom devDependency (missing from 17-01 scaffold) required by vitest jsdom environment for browser-persona CSRF tests
- [Phase 17-typescript-sdk]: 17-02: login()/verifyMfa() branch on response.status===202 inside the resolved success path, not the catch block, since axios's default validateStatus resolves any 2xx (including 202) as success
- [Phase ?]: [Phase 17-typescript-sdk] 17-04: verifyPayload never throws on malformed/short/empty hex; ConsumeOptions.strict defaults true and a present signature is always verified regardless of mode
- [Phase ?]: [Phase 17-typescript-sdk] 17-04: fixed @types/node gap from 17-01 (missing devDependency + tsconfig types array) that was silently breaking tsc --noEmit on src/rest/session.ts and test/core/sensitive.test.ts
- [Phase ?]: [Phase 17-typescript-sdk] 17-03: gRPC transport built directly on grpc-js's makeClientConstructor with local Wire* types mirroring authorization.proto (src/gen unavailable, no buf CLI) behind an injectable AuthorizationServiceClientFactory seam
- [Phase ?]: [Phase 17-typescript-sdk] 17-03: TokenManager.refreshTokenValue() reads the jar against {baseUrl}/api/v1/auth/refresh (not bare baseUrl) since axiam_refresh is path-scoped server-side
- [Phase ?]: [Phase 17-typescript-sdk] 17-03: NodeSession.doRefresh and REST's inline refresh closure both drive the same module-level refreshOnce singleton guard, so REST and gRPC transparently share exactly one in-flight refresh (D-13)
- [Phase ?]: [Phase 17-typescript-sdk] 17-05: Fastify plugin marked with Symbol.for('skip-override') (fastify's own escape hatch, same mechanism fastify-plugin wraps) so axiamPlugin's preHandler hook applies to sibling routes without adding a new dependency
- [Phase ?]: [Phase 17-typescript-sdk] 17-05: examples/tsconfig.json resolves axiam-sdk/* via a paths mapping to src/*.ts rather than the package's own exports map, since dist/ is unbuilt in this sandbox (no buf CLI)
- [Phase ?]: [Phase 17-typescript-sdk] 17-05: Added a new axiam-sdk/middleware public subpath export (package.json + tsup.config.ts) and re-exported Sensitive from axiam-sdk/amqp — both needed for Task 2's examples to satisfy the plan's public-entry-points-only constraint

### Pending Todos

Deferred to Phase 19 (raised during Phase 04):

- T19.14 — per-FederationConfig registered redirect_uri allowlist for first-time SSO endpoints (needs a schema column; currently scheme/host HTTPS guard only)
- T19.15 — resolve real org_id from tenant in SSO callback session/token creation (currently `Uuid::nil()`)

Raised 2026-06-02 (SAML feature-flag work):

- Extend CI `build-no-saml` guard to `--tests` once the pre-existing `-Dwarnings` drift in axiam-server test files is cleaned (currently lib+bin `cargo check` only)

### Blockers/Concerns

- 36 Dependabot vulnerabilities on the default branch (13 high / 15 moderate / 8 low) — surfaced on push 2026-06-02; triage separately (relates to Phase 6 REQ-9 cargo-audit/cargo-deny work)
- Tracking note: `02-VERIFICATION.md` status field still reads `human_needed`, but the lone human item was closed via Playwright UAT (`02-HUMAN-UAT.md` status: complete, result: pass, evidence in uat-evidence/) — Phase 2 is complete despite the stale verification-file field
- `gsd-sdk phase.add` sentinel bug: `99-followups/` dir inflates max+1 counter → returns 100; create phase dirs 15–22 directly, do NOT use phase.add for this milestone

## Session Continuity

Last session: 2026-07-01T12:36:37.255Z
Stopped at: Completed 17-03-PLAN.md
Resume file: None
