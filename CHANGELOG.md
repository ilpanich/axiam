# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Benchmark dry-run mode (`just bench-dry-run`, `just dry=1 bench-run`) — rehearses the
  whole target × profile matrix over the same bring-up/seed/run/tear-down path in minutes,
  grading each cell on the k6 client contract (connect, request, expected response) instead
  of on performance, so a break surfaces before an hours-long matrix commits to it

### Fixed

- Stale DB handles after a reconnect: every repository was built at boot from a one-time
  `pool.handle_for_repo()` **clone** of the pooled SurrealDB connection, so when the pool's
  reconnect loop evicted a poisoned connection (observed ~7 minutes into a sustained load
  run) every repository stayed pinned to the dead one and returned 401 permanently until
  the process restarted — while `/ready`, which probes through the pool slot, still
  reported healthy. Repositories now hold a live `DbHandle` over the pool slot and resolve
  the current connection per query, so a swap is picked up on the very next query. The REST
  `AppState.db` (bootstrap handler, tenant seeder) and the gRPC layer's handle held the same
  boot-time clone and were fixed the same way
- `meta.json` could be written as invalid JSON when a host fact spanned two lines — a
  `docker version` against an unreachable daemon prints an empty line and *then* fails, so
  the `|| echo unknown` fallback produced a literal newline mid-string and took `report.py`
  down with an "Invalid control character" for the whole run

## [1.0.0-alpha21] - 2026-07-30

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha20.

## [1.0.0-alpha20] - 2026-07-30

### Added

- Opt-in rate-limit posture presets + TLS/h2 tuning surface (G7, G8 in progress)
- G9 — throttle-aware metrics and the gRPC/REST authz analysis
- G2 harness countermeasures, G4 refresh fix, G5 cache-sweep scenario
- Per-task data-collection script for the pre-MVP plan
- Run-3 benchmark page refresh + benchmark-derived sizing docs

### Changed

- Add the run-4 execution runbook
- Bump the version marker to 1.6 and record the follow-up audit findings
- Add §9 rule 6 — single-flight guard implementation invariants (contract 1.6)
- Bump frontend/coverage/website-publish Node from 20 to 22
- Bump jsonwebtoken from 10.4.0 to 11.0.0
- Bump jsdom from 29.1.1 to 30.0.1 in /frontend
- Use the obviously-fake password fixture convention in the users split test
- Verify the write-behind clamp fix on a local rl-fix-local build
- Document the write-behind shared counter and its security bound
- Note why REST and gRPC each hold their own shared counter
- Adapt the shared-store middleware suite to write-behind counting
- Serve shared rate-limit decisions from the write-behind counter
- Add write-behind SharedRateLimitCounter + increment_by
- Mark the bench admin default in h5-revocation-check.sh as a throwaway fixture
- H10(5): finalize §6 execution record with the validated H10 outcome
- H10(4): report.py — settle_timeout refusal is now scenario-aware, not session-wide
- H10(3): consistency pass — methodology.md §12 + append §6 execution record
- H10(2): E4 — fourth public benchmark draft
- H10(1): consistency pass — reconcile PRIVATE_BENCH_ANALYSIS.md with H2/H3/H4/H5/H9 verdicts
- H8(5): profile-scope SDK result storage, README truthful status table, per-language TODO notes
- H8(4): wire BENCH_CA_CERT into 5 SDK benches for p2, integrate E1.3 overhead table into report.py
- H8(3): fix refresh-op concurrency in python/typescript benches (HARNESS-SPEC required conc=1, neither implemented it)
- H8(2): fix server CSRF header-echo + go bench org_slug — both blocked every SDK bench end-to-end
- H8(1): per-language SDK bench fixes — rust seed env, python venv, ts npm link, go.sum, java compile, csharp preflight, php minimum-stability
- H7(1): confirm the REST/gRPC classifier wiring live; correct the stale G9 note
- H7(3b,4): measure the gateway rate-limit preset live; close the Keycloak p0-vs-p2 login asymmetry
- H7(1,3a,5): protocol-variant label, maintainer sign-off block, H4 control-build fix
- H6(7): measure the CC clamp control instead of asserting it, and price the noise
- H6(6): publish the B2 position — TLS priced, HTTP/2 acquitted, CC still open
- H6(5): close B2 in the private analysis
- H6(4): document bench_http_proto in the methodology metric list
- H6(3): the h2 hypothesis is refuted by counting connections
- H6(2): h6-tls-proto task + a connection/worker-affinity probe
- H6(1): capture the negotiated HTTP protocol, and make the h1 control honest
- H5(4,5): decision-cache verdict — default STAYS opt-in, flip blocked on C1/C2/C4
- H5(3): automate the live-stack revocation check; run the K-sweep under TLS
- H5(1): fix the three decision-cache defects surfaced by the G5 review
- H9: DB-pool default decision — keep pool_size=1, close negative
- H2: G1 endgame — the "post-seed transient" is the shared rate-limit write
- H1: drain pause after settle gate to prevent straggler-traffic contamination
- H4: jemalloc as the release-container default allocator (executes G6 PASS)
- H1.5: report.py refuses cells whose meta records settle_timeout:true
- H1.2: fix bench-matrix results-dir clobber + fail-fast task-script guard
- H1.1: settle gate v2 — concurrent burst probe replaces serial canary
- H3: flip authz batch strategy default to coalesced (G3 decision)
- Phase H plan from the verified 2026-07-28 G-task results
- Use UUIDv7 for persisted record identifiers
- Amend CONTRACT to 1.5 from the cross-SDK §12 conformance review
- Add CONTRACT §12 OIDC/SSO relying-party helpers (contract 1.4)
- Add SDK OIDC/SSO relying-party helpers implementation plan
- Correct the published client_id rate-limit guidance with its security caveat
- G7 rate-limit posture decision record
- G8 security-profiles update + implementation status for the pre-MVP plan
- G8 — B2 HTTP/2 investigation and the ALPN knob fix
- Bump base64 from 0.22.1 to 0.23.0
- Bump the minor-patch group in /frontend with 12 updates
- Bump actions/download-artifact from 4.3.0 to 8.0.1
- Bump taiki-e/install-action from 2.83.2 to 2.85.2
- Bump bufbuild/buf-action from 1.4.0 to 1.5.0
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump docker/login-action from 3.4.0 to 4.5.1
- Use UUIDv7 for persisted record identifiers
- Amend CONTRACT to 1.5 from the cross-SDK §12 conformance review
- Add CONTRACT §12 OIDC/SSO relying-party helpers (contract 1.4)
- Add SDK OIDC/SSO relying-party helpers implementation plan
- Run-3 analysis, D9 experiment script, pre-MVP improvement plan

### Fixed

- Select jsonwebtoken 11's rust_crypto backend explicitly
- Stop charging GET /api/v1/users to the users_create limiter
- Make g1-dbdirect's direct SurrealDB probe actually run
- Resolve g1-dbdirect's DB credentials from the running stack
- Interrupt-safe teardown for every task that holds a stack
- Unwedge the G1 tasks' telemetry sampler
- Dial gRPC over TLS in p3-mtls; record real gRPC status
- Resolve p3-mtls client cert path from any CWD

## [1.0.0-alpha19] - 2026-07-25

### Fixed

- Migrate react-router-dom v7 -> react-router v8 (GHSA-qwww-vcr4-c8h2)

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Workspace coverage improvements toward >=90% (T2-T6), scanner-clean
- Plan to push Coveralls badge over 90% with per-task model picks
- Ratchet line-coverage floor 77 -> 80 and surface achieved total
- Runtime-generate the new-password arg in confirm_reset test
- Close residual gaps in password_reset and pgp
- Satisfy rustfmt, clippy, and CodeQL on the new coverage tests
- Exclude axiam-server binary composition root from coverage
- Cover SAML/OIDC non-xmlsec logic and negative paths
- Broker-free seams for authz/audit consumers + fix auth rand_core
- Cover residual repository CRUD/error paths + seeder + nonce-replay
- Cover cleanup.rs expiry sweeps and erasure pipeline branches
- Cover federation/auth/webhook/password-reset/rbac error paths
- Round-2 test-coverage plan for server + C SDK with per-task model picks
- Bump docker/build-push-action from 6.15.0 to 7.3.0 (#213)
- Bump @testing-library/jest-dom in /frontend (#216)
- Bump actions/setup-node from 6.4.0 to 7.0.0 (#214)
- Bump dtolnay/rust-toolchain (#212)
- Test-coverage improvement plan for server + 11 SDKs (2026-07-23 baseline) (#227)
- Bump the minor-patch group in /frontend with 8 updates (#215)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#211)
- Bump actions/attest-build-provenance from 2.4.0 to 4.1.1 (#210)
- Correct model attribution and add phase dates to roadmap (#226)
- Rewrite laptop runbook for run 3 against released 1.0.0-alpha17

## [1.0.0-alpha17] - 2026-07-22

### Changed

- Updated dependencies for security fixes

## [1.0.0-alpha16] - 2026-07-22

### Added

- Add AXIAM gRPC userinfo scenario + protocol-efficiency pairing
- Implement UserInfoService and integration tests
- Add gRPC UserInfoService/GetUserInfo (contract 1.3)
- Add missing SDKs, gRPC + config docs, real benchmark data
- Implement run-2 follow-up tasks (A8, A9, D10, D11, report polish)

### Changed

- Use a random seeded-user password in userinfo tests
- Add gRPC userinfo implementation plan
- Run-2 analysis (1.0.0-alpha15) — update public/private bench docs + plan

### Fixed

- Make concurrent batch future boxable behind AuthzChecker trait

## [1.0.0-alpha15] - 2026-07-21

### Added

- F2 — DbPool of N independent handles, wire repositories, close CQ-B48
- F1 — connection-pool design doc + boundary instrumentation
- D7 — decision caching behind a flag (default off) with revocation invalidation
- D8 — configurable rate-limiter key (ip|client_id|ip_client_id)
- D3 — native mTLS (client-certificate) auth
- B1 — bound concurrent Argon2id hashing (perf + memory-DoS fix)
- AXIAM native (in-process) TLS for the p2-tls13 profile
- TLS profiles for keycloak + zitadel; RSA certs; port pre-flight
- Auto-provision Zitadel client via management API

### Changed

- Regression test for gRPC-over-TLS crypto provider
- Fix stale F1/F2 status rows (still showed "planned" post-merge)
- Mark E1.2 done (four stub SDK benches wired)
- Wire the four stub SDK benches (c, cpp, kotlin, swift)
- Cargo fmt F2 (DbPool)
- Cargo fmt F1 instrumentation wiring
- Laptop re-run runbook + Phase F (DB connection pooling)
- Cargo fmt (rustfmt CI fix)
- Per-task implementation status table
- D9 — optional jemalloc allocator for RSS-retention experiment
- Drive gRPC over TLS at p2 (native gRPC TLS wiring)
- B3 — JWKS in-process cache + HTTP caching headers (ETag/304)
- D1 — coalesce same-subject authz batches + tracing
- B2 — TLS 1.3 throughput diagnosis + fixes on token endpoints
- Zitadel gRPC benchmark coverage
- AMQP async-authz load harness design
- Real Zitadel login via session API v2 (password verification)
- SurrealDB tuning investigation — preliminary static analysis
- Re-run protocol — median-of-N, DB tuning, laptop runbook, prod posture
- Harness correctness & honesty (A1–A7)
- Expand plan E1 — implement & validate the SDK client benches
- Benchmark improvement implementation plan; refine throttling assessment
- Add public + private analysis of the first full benchmark run
- Re-enabled pepper and moved compose to latest AXIAM image version

### Fixed

- Make Keycloak and Zitadel seed users loginable
- Install ring rustls CryptoProvider so gRPC-over-TLS works
- Serialize F1 gauge tests against shared-static race (flaky CI)
- Give the E2E backend-startup step real timeout margin
- Correct actix test app-factory return type (D8 integration test)
- Fill new config fields in remaining test literals
- Clippy collapsible-if, grpc test field, OpenAPI drift
- Gate bench-up on target HTTP readiness

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Require organization context for login/refresh (#204)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Added

- Add --changelog to summarize commits into CHANGELOG.md

### Changed

- Wire org context into the TypeScript bench; list all 11 SDKs in README (#199)

### Fixed

- Wire Keycloak TLS via entrypoint; stop passing empty KC_HTTPS_*
- Correct image labeling metadata for GHCR
- Drop --optimized from Keycloak first start
- Dial gRPC plaintext regardless of HTTP TLS profile
- Merge tlsOptions() into gRPC scenarios so cert-skip applies
- Skip k6 server-cert verify for private-CA TLS profiles
- Neutralize rate limits so p0 measures endpoint capacity
- Apply the configured password pepper when hashing the admin (#200)
- Don't set AXIAM__AUTH__PEPPER (breaks bootstrap-admin login)
- Write resource CSV rows; configure OAuth2/optional secrets; skip OAuth2 when unset
- Supply org context on login; make bench-down work without secrets
- Provide mandatory AMQP signing key for the AXIAM target
- Bootstrap AXIAM secrets in bench-up; auto-track image tag
- Correct just variable-override ordering so bench-matrix works

## [1.0.0-alpha3] - 2026-07-16

Third alpha. Build/release tuning and project-infrastructure changes only. No
server runtime or API behavior changes — the OpenAPI specification is
byte-for-byte identical apart from its `info.version` string.

### Added

- **Public marketing & documentation website**, deployed to GitHub Pages.

### Changed

- **Release build profile** — added `[profile.release]` to the workspace-root
  `Cargo.toml`, tuned for execution speed first and footprint second:
  `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`.
  Cargo only honors profiles at the workspace root, so this single section
  covers `axiam-server` and every crate it links. `panic = "abort"` is
  intentionally omitted to preserve per-request panic isolation on the
  long-running REST/gRPC/AMQP server. Release builds are slower in exchange for
  faster runtime.

## [1.0.0-alpha2] - 2026-07-16

Second alpha. Adds the SDK declarative-authorization contract and release-prep
polish; no server runtime/API behavior changes.

### Added

- **CONTRACT.md §11 — Declarative Authorization Helpers**: the canonical
  `require_auth` / `require_access(action, resource[, scope])` / `require_role`
  vocabulary layered on the §10 guard, with the per-language naming map and
  normative semantics (subject propagation, 401/403/400/503 error mapping,
  fail-closed on transport error, no decision caching). Marked SHOULD-level and
  recorded as non-breaking/additive; contract version bumped to 1.1.
- README build/coverage/license badges.

### Changed

- Roadmap "Development Progress": Phase 17 (SDKs) and Phase 18 (security audit)
  marked Done.

### Fixed / CI

- Added a free-disk-space step to the heavy Rust `test` and `cargo-llvm-cov`
  jobs to prevent the RabbitMQ disk-space alarm that intermittently failed CI.

## [1.0.0-alpha1] - 2026-07-16

Patch release over `1.0.0-alpha` that fixes the release pipeline so the
aarch64 server binary and the OpenAPI drift gate build cleanly. There are no
functional or API changes — the OpenAPI specification is byte-for-byte
identical apart from its `info.version` string.

### Fixed

- **aarch64 release build** — the *Build Release Binary (aarch64)* job failed
  at "Install build dependencies" because the native `ubuntu-24.04-arm` runner
  intermittently could not reach `ports.ubuntu.com` (IPv6 unreachable, IPv4
  timeouts). The apt step now forces IPv4, prefers Azure's in-network ports
  mirror, and retries with backoff, without changing the installed package set.
- **OpenAPI version drift** — the REST spec's `info.version` was a hardcoded
  literal that fell out of sync with the crate version and failed the OpenAPI
  drift gate. It is now bound to `CARGO_PKG_VERSION`, so it always tracks the
  workspace version and cannot drift on a future version bump.

[1.0.0-alpha1]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha1

## [1.0.0-alpha] - 2026-07-15

First alpha release of AXIAM (Access eXtended Identity and Authorization
Management). This is an early, pre-production preview intended for evaluation
and feedback — APIs and data models may still change before the beta and
stable releases.

### Added

- **Multi-tenancy** — organizations as top-level entities containing fully
  data-isolated tenants; all domain entities (users, groups, roles,
  permissions, resources, certificates) are tenant-scoped.
- **Authentication** — username/password (Argon2id), MFA (TOTP), social login
  and certificate-based (mTLS) authentication; EdDSA (Ed25519) JWT access
  tokens with opaque, single-use, rotating refresh tokens.
- **Authorization** — additive, default-deny RBAC engine with role
  inheritance through hierarchical resources, scopes for sub-resource
  granularity, and group-inherited role assignments.
- **OAuth2 / OpenID Connect** — authorization server and OIDC provider
  (Authorization Code + PKCE, Client Credentials, Refresh Token).
- **Federation** — SAML SP and OpenID Connect federation for cross-domain SSO.
- **APIs** — REST (Actix-Web, OpenAPI-documented), gRPC (Tonic) for
  low-latency authz checks, and AMQP (Lapin) for async/deferred authz, audit
  ingestion and event notifications.
- **PKI** — per-tenant X.509 certificate management signed by an organization
  CA, with CA private keys encrypted at rest (AES-256-GCM); GnuPG/OpenPGP
  integration for audit signing and encrypted data exports.
- **Auditing** — append-only audit logging.
- **Webhooks** — real-time event notifications to external systems, signed
  with HMAC-SHA256.
- **Admin frontend** — React + TypeScript administration UI.
- **Packaging & deployment** — multi-arch (amd64/arm64) container images and
  standalone server binaries, Docker Compose and Kubernetes manifests.
- **Client SDKs** — Rust, TypeScript, Python, Java, C#, PHP and Go SDKs, each
  released in its own repository against the shared API contract.

[1.0.0-alpha]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha
