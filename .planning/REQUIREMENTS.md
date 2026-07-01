# Requirements — MVP Hardening & Security Compliance

> Milestone: v1.0-beta
> Created: 2026-03-30

## REQ-1: Cookie-Based Authentication

**Priority:** Critical | **Source:** OWASP ASVS 3.4.2-3.4.5, user decision

Migrate JWT token delivery from sessionStorage (XSS-vulnerable) to httpOnly secure cookies with proper CSRF protection.

### Acceptance Criteria
- [ ] Access token delivered via `Set-Cookie` with `httpOnly; Secure; SameSite=Strict; Path=/`
- [ ] Refresh token delivered via `Set-Cookie` with `httpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/refresh`
- [ ] Frontend removes all sessionStorage token handling
- [ ] Frontend API client sends credentials via cookies (no Authorization header)
- [ ] CSRF double-submit cookie pattern implemented for state-changing requests
- [ ] Logout endpoint clears cookies server-side (`Max-Age=0`)
- [ ] Refresh endpoint uses refresh cookie, returns new access cookie
- [ ] Existing integration tests updated for cookie-based auth

---

## REQ-2: Security Headers

**Priority:** High | **Source:** OWASP ASVS 14.4

Add comprehensive security headers to both backend API and frontend nginx.

### Acceptance Criteria
- [ ] Backend middleware adds: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] Nginx config adds: `Content-Security-Policy`, `Strict-Transport-Security`, `Permissions-Policy`
- [ ] CSP policy restricts scripts to self-origin (no inline, no eval)
- [ ] HSTS with `max-age=31536000; includeSubDomains`

---

## REQ-3: Rate Limiting & Brute-Force Protection

**Priority:** High | **Source:** OWASP ASVS 2.2.1

Protect authentication endpoints from brute-force and credential stuffing attacks.

### Acceptance Criteria
- [ ] Rate limiting on `/auth/login` (10 req/min per IP)
- [ ] Rate limiting on `/auth/register` (5 req/min per IP)
- [ ] Rate limiting on `/oauth2/token` (20 req/min per client)
- [ ] Rate limiting on `/auth/password-reset` (3 req/min per IP)
- [ ] Account lockout after 5 consecutive failed login attempts (15-min cooldown)
- [ ] Lockout status visible in admin UI
- [ ] gRPC brute-force protection (T19.5)

---

## REQ-4: RBAC Enforcement

**Priority:** Critical | **Source:** OWASP ASVS 4.1.1-4.1.5, user decision

Wire the existing authorization engine to ALL REST API endpoints with default-deny.

### Acceptance Criteria
- [ ] Default-deny middleware: all routes require authorization unless explicitly public
- [ ] Public endpoint allowlist: login, register, health, OIDC discovery, JWKS, federation callbacks
- [ ] Every CRUD endpoint requires the appropriate permission (e.g., `users:read`, `users:write`)
- [ ] Self-service endpoints verify `caller_user_id == target_user_id`
- [ ] Admin bootstrap endpoint: creates first admin when zero admins exist, disabled after
- [ ] Admin bootstrap configurable via `AXIAM_BOOTSTRAP_ADMIN_EMAIL` env var
- [ ] Integration test verifying every registered route has an authorization check
- [ ] Admin user listing endpoint enabled (T19.3)
- [ ] Admin MFA management for other users enabled (T19.3)

---

## REQ-5: Federation Token Verification

**Priority:** Critical | **Source:** OIDC Core §3.1.3.7, SAML Core §5

Cryptographically verify all federation tokens before accepting them.

### Acceptance Criteria
- [ ] OIDC: Fetch and cache JWKS from IdP discovery endpoint
- [ ] OIDC: Verify ID token signature using JWKS public keys
- [ ] OIDC: Validate `iss`, `aud`, `exp`, `nonce` claims
- [ ] OIDC: Pin expected algorithm per federation config (reject `none`)
- [ ] OIDC: JWKS cache with TTL (1 hour) + retry-on-failure
- [ ] SAML: Verify XML signature on SAML response
- [ ] SAML: Validate `NotOnOrAfter`, `NotBefore`, `Audience` conditions
- [ ] SAML: Track consumed assertion IDs (prevent replay)
- [ ] Clock skew tolerance: 60 seconds
- [ ] Federation client secrets encrypted at rest with AES-256-GCM (T19.8)

---

## REQ-6: Email Delivery

**Priority:** High | **Source:** T19.11, T19.12, user decision

Wire the existing EmailService to authentication flows with configurable SMTP/provider backend.

### Acceptance Criteria
- [ ] Password reset handler sends reset email via EmailService (T19.11)
- [ ] Email verification handler sends verification email via EmailService (T19.12)
- [ ] Notification dispatcher sends alerts via EmailService (T19.13)
- [ ] Email provider configurable via settings: SMTP, SendGrid, Postmark, Resend, Brevo
- [ ] Email delivery failures logged to audit with retry info
- [ ] Email templates use proper escaping (no triple-stash `{{{}}}`)
- [ ] Reset/verification URLs use server-generated tokens only

---

## REQ-7: Session Security

**Priority:** High | **Source:** OWASP ASVS 3.3.1, T19.10

Ensure session lifecycle is properly managed.

### Acceptance Criteria
- [ ] All active sessions/refresh tokens invalidated on password change
- [ ] All active sessions/refresh tokens invalidated on password reset
- [ ] Session invalidation on MFA reset
- [ ] Service-account dedicated token type with `sub_kind: "ServiceAccount"` (T15 TODO)

---

## REQ-8: GDPR Compliance

**Priority:** High | **Source:** GDPR Articles 15, 17

Implement minimum viable GDPR data subject rights.

### Acceptance Criteria
- [ ] Data export endpoint: returns all user data across all tables as JSON (Art. 15)
- [ ] Data deletion endpoint: removes user and pseudonymizes PII in audit logs (Art. 17)
- [ ] Pseudonymization replaces user identifiers with `DELETED_USER_<hash>` in audit entries
- [ ] Audit log entries preserved (immutability maintained) with PII stripped
- [ ] Consent tracking: record when user accepted terms
- [ ] Integration test: create user with data in every table, export, verify completeness
- [ ] Integration test: delete user, verify PII removed from all tables and audit pseudonymized

---

## REQ-9: CI/CD Security Hardening

**Priority:** High | **Source:** Best practice

Add security scanning to CI pipeline and harden build process.

### Acceptance Criteria
- [ ] `cargo-audit` step in CI (fail on known vulnerabilities with patches)
- [ ] `cargo-deny` step in CI (license + vulnerability + duplicate checking)
- [ ] `npm audit` step in CI for frontend
- [ ] `trivy` container image scan after Docker build
- [ ] `hadolint` Dockerfile linting
- [ ] Frontend build with `sourcemap: false` in production
- [ ] Vite SRI (Subresource Integrity) for production assets
- [ ] OpenAPI schema accuracy verification (T19.4)

---

## REQ-10: Infrastructure Hardening

**Priority:** Medium | **Source:** K8s security best practices

Harden Docker and Kubernetes deployment configurations.

### Acceptance Criteria
- [ ] Docker images run as non-root user
- [ ] Docker images use minimal base (distroless or alpine)
- [ ] K8s NetworkPolicy: server→surrealdb, server→rabbitmq, ingress→frontend, ingress→server
- [ ] K8s pod security standards verified (restricted profile)
- [ ] All K8s secrets use `secretKeyRef` (no inline values)
- [ ] Health check endpoints validated in K8s probes
- [ ] Docker compose dev environment updated for cookie auth

---

## REQ-11: Testing Gaps

**Priority:** High | **Source:** Codebase analysis

Close critical testing gaps in security-sensitive crates.

### Acceptance Criteria
- [ ] gRPC authorization integration tests (T19.1)
- [ ] Concurrent batch authorization tests (T19.2)
- [ ] PKI/certificate generation tests (axiam-pki)
- [ ] Federation OIDC flow integration tests (with mocked IdP)
- [ ] Federation SAML flow integration tests (with mocked IdP)
- [ ] RBAC enforcement integration tests (every endpoint)
- [ ] Cookie auth flow integration tests
- [ ] GDPR export/deletion integration tests
- [ ] Frontend E2E tests for login, RBAC, federation flows

---

## Audit Remediation (post-beta tranche)

> Source: `claude_dev/remediation-plan.md`, derived from `claude_dev/code-review.md`
> (`CQ-B01..B44`, `CQ-F01..F35`) and `claude_dev/security-review.md` (`SEC-002..SEC-057`),
> both at commit `d69323b`. These requirements open after the v1.0-beta milestone and are
> executed wave-by-wave with a green-build gate between waves.

## REQ-12: Build Integrity (Wave 0)

**Priority:** Blocker | **Source:** code-review CQ-B37

`axiam-server` must compile and the CI build must pass under `-D warnings`. Blocks all
subsequent remediation waves.

### Acceptance Criteria
- [ ] `cargo build -p axiam-server` succeeds (uuid/chrono/serde_json moved to `[dependencies]`, direct `sha2` dep added)
- [ ] `cleanup.rs` imports `sha2::{Digest, Sha256}` (not `rsa::sha2::{...}`); unused `rsa` dep dropped if now unused
- [ ] CI `build` job passes `-p axiam-server` including `-D warnings` (12 warnings in `req5_*/req7_*/cleanup_task` tests cleared)

---

## REQ-13: Critical Security Remediation (Wave 1)

**Priority:** Critical | **Source:** SEC-002, SEC-003, SEC-044/CQ-F27, CQ-F28, SEC-045/SEC-017

Close cross-tenant data exposure and broken authentication lifecycle defects.

### Acceptance Criteria
- [ ] Cross-org IDOR closed: org-nested routes (orgs/tenants/CA certs) return 403 when `org_id != user.org_id`; org create/list restricted to system-admin; cross-org negative tests pass
- [ ] gRPC authenticated: Tonic interceptor validates bearer JWT / mTLS identity; tenant_id/subject_id derived from verified claims; public gRPC ingress removed; interceptor accept/reject tests added
- [ ] All six frontend auth flows call real backend endpoints via a typed `auth.ts` service (reset, reset-confirm, verify-email, resend, change-password, MFA enroll/confirm); frontend↔OpenAPI contract test gates in CI
- [ ] Silent refresh succeeds (CSRF token attached, skip-list narrowed); boot refresh attempted once before declaring unauthenticated
- [ ] Federation client secrets decrypted at use and encrypted on create/update; secret never serialized; OIDC login succeeds after restart/backfill

---

## REQ-14: High Security Remediation (Wave 2)

**Priority:** High | **Source:** CQ-B01/B02/B03/B04/B05/B06/B07/B08/B09/B30/B38/B40, CQ-F01..F08, SEC-005/007/008/010/011/012/017/033/039/056

Resolve high-severity correctness, async-safety, tenant-isolation, and protocol-hardening defects. *Foundational first:* single hashing path + pepper (CQ-B09/B01) and `load_key_from_env` extraction (CQ-B43, enables SEC-012).

### Acceptance Criteria
- [ ] One password-hashing path with pepper (repo-layer hasher deleted); REST-created user logs in with pepper set
- [ ] Argon2 hash/verify and PKI keygen/sign run in `spawn_blocking` behind a bounding semaphore
- [ ] Tenant settings persist sparse overrides merged against org baseline at read time; baseline change propagates
- [ ] Tenant-scoped edge mutations (role/permission) verify both endpoints belong to tenant and run in transactions; resource hierarchy rejects cycles/orphans and drops depth-50 truncation
- [ ] GDPR purge/export correctness (re-selectable on failure, complete export, paginated audit, Failed status); SAML protocol checks (InResponseTo/Destination/Conditions/XSW); TOTP replay rejected; pagination clamped; 5xx errors generic; PKI fails fast on missing key; AMQP DLQ parity; migration idempotent/transactional
- [ ] Frontend High items fixed (real `user.id`, ConfirmDialog label, debounce cleanup, useQuery search, logout clears store, eslint+`tsc -b` in CI, org settings save, no fabricated tenant status)

---

## REQ-15: Medium Security Remediation (Wave 3)

**Priority:** Medium | **Source:** CQ-B10..B26/B39/B41/B43, CQ-F09..F19/F29/F30/F31, SEC-016/019/020/022/023/024/025/026/028/031/032/046/047/048/049/050/051/052/053/054/055

Consolidate repo/DTO patterns, add transport limits, and harden auth/infra surfaces.

### Acceptance Criteria
- [ ] Shared repo helpers + request DTOs; index/duplicate violations map to 409; OAuth2/gRPC error mapping + message-size/timeout/concurrency/TLS limits correct
- [ ] Webhook SSRF re-resolves and pins IP at delivery; rate limits on `/auth/mfa/*` + `/oauth2/introspect|revoke`; AMQP authz/mail messages authenticated/scoped; mTLS verifies chain to tenant/org CA; S256 PKCE enforced
- [ ] Auth hardening: dummy-Argon2 on user-not-found, atomic failed-login increment, reset-to-current blocked, CSRF on `/api/v1` CRUD, permission enforcement keyed off `ROUTE_PERMISSION_MAP`, bootstrap transactional + gated, self-update strips `status` + gates email change, logout revokes caller's own session
- [ ] k8s/nginx hardened: `AXIAM__` env keys + secrets, receiver-side NetworkPolicies + PSA restricted, `/oauth2/*` + `/.well-known` proxy locations, backend ports unpublished, prod compose default creds removed
- [ ] Frontend medium items: toast + `getApiErrorMessage` on all mutations, form validation, resource parent picker excludes descendants, federation edit locks type, pagination `placeholderData`, shared components/hooks, route guards + friendly 403, login handles `mfa_setup_required`/`mfa_required`

---

## REQ-16: Low / Trivial Remediation (Wave 4)

**Priority:** Low | **Source:** CQ-B27..B36/B42, CQ-F20..F35, SEC-036/037/040/041/043/057

Close remaining cleanup, dead-code, dependency, i18n, and minor security-polish findings.

### Acceptance Criteria
- [ ] Backend cleanup: shared `client_ip`/`user_agent` helper, NotificationDispatcher wired or removed, logged error handling (no silent `let _ =`/`.ok()`), typed errors, `cargo machete` dep pruning + `rand` consolidation, HIBP on sync change-password, audit-drop metric, seeder version/hash skip
- [ ] SEC-040 deny-overrides cascade implemented or CLAUDE.md wording corrected; encrypted blobs no longer `Debug`-derived/hydrated on list paths; GitHub Actions pinned by commit SHA
- [ ] Frontend trivial items: dead `Placeholder.tsx` removed, unused radix deps removed, password-policy checker on admin-create+bootstrap, safe DataTable row key, i18n / no hardcoded `en-US`, `CSS.escape` in ResourceTree, `_retry` guard + escaped cookie regex, bootstrap 404 handling, StrictMode double-fetch fixed
- [ ] Secrets cleared from React state on modal close; reset/verify tokens stripped from URL via `history.replaceState`; no full Axios error/email logging on ForgotPasswordPage
- [ ] Final whole-effort verification green: `cargo build/clippy -D warnings/test --workspace`, `cargo audit`/`cargo-deny`, `npm audit`, frontend `lint && tsc -b && vitest`, Playwright e2e gating in CI; manual smoke (login→MFA→reset/verify/change-pw→GDPR→federation-after-restart→cross-org 403→gRPC-no-creds rejected)

---

## REQ-17: SurrealDB Connection Resilience

**Priority:** High | **Source:** Phase-12 manual-smoke debugging (root-caused live; SurrealDB Rust SDK issue #5750)

The server's SurrealDB WebSocket connection must never silently lose its `use_ns`/`use_db` selection after an idle reconnect (which routes queries to the empty default namespace and returns "not found" on records that exist). The documented local first-run seed path must work end-to-end.

### Acceptance Criteria
- [x] `DbManager` keeps the active ns/db across reconnects (background guard re-issues `use_ns`/`use_db` on a detected `session::ns()`/`session::db()` mismatch)
- [x] `health_check` asserts the connection is bound to the expected ns/db (returns `DbError::SessionMismatch` on wrong ns/db), not just socket liveness
- [x] A regression test reproduces the unselected-session → NotFound failure and asserts re-selection succeeds (fails without the guard)
- [x] `scripts/e2e-bootstrap.sh` seeds the database the server reads (`db=main`) and drops the non-existent `is_active` tenant field; `just bootstrap-local` provides a one-command local first-run
- [ ] Deferred Phase-12 manual smoke (`12-HUMAN-UAT.md`, 11 items) executed against a live env (human-verify; requires `just run-local`)

---

## Dependency Map

```
REQ-1 (Cookie Auth) ──────┐
                           ├──→ REQ-4 (RBAC) ──→ REQ-6 (Email) ──→ REQ-8 (GDPR)
REQ-2 (Security Headers) ─┘          │
REQ-3 (Rate Limiting) ───────────────┘
REQ-5 (Federation Verify) ─── independent
REQ-7 (Session Security) ──── depends on REQ-1
REQ-9 (CI Hardening) ──────── independent (can run in parallel)
REQ-10 (Infra Hardening) ──── independent (can run in parallel)
REQ-11 (Testing) ──────────── runs after each REQ as verification
```

---

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| REQ-1 | Phase 1 | Complete |
| REQ-2 | Phase 2 | Complete |
| REQ-3 | Phase 2 | Complete |
| REQ-4 | Phase 3 | Complete |
| REQ-5 | Phase 4 | Pending |
| REQ-6 | Phase 5 | Complete |
| REQ-7 | Phase 4 | Pending |
| REQ-8 | Phase 5 | Complete |
| REQ-9 | Phase 6 | Complete |
| REQ-10 | Phase 6 | Complete |
| REQ-11 | Phase 7 | Complete |
| REQ-12 | Phase 8 | Pending |
| REQ-13 | Phase 9 | Complete |
| REQ-14 | Phase 10 | Complete |
| REQ-15 | Phase 11 | Complete |
| REQ-16 | Phase 12 | Complete |
| REQ-17 | Phase 13 | Complete (code) — live smoke deferred to 12-HUMAN-UAT |
| REQ-18 | Phase 14 | Complete (code) — frontend list-contract alignment; live smoke deferred to 12-HUMAN-UAT |

---
*Last updated: 2026-06-19 (Phase 14 REQ-18 — frontend list-contract alignment — added)*

---
---

# Requirements — Milestone v1.1: Client SDKs (Phase 17)

> Milestone: v1.1
> Created: 2026-06-28
> Source: `claude_dev/roadmap.md` Phase 17 (T17.1–T17.7) + `.planning/research/SUMMARY.md`
> Scope decisions (user, 2026-06-28): all 7 languages; full multi-protocol incl. AMQP; auth flows P1+P2; publish pipelines included; add REST authz-check endpoint for the browser SDK.

These SDKs wrap the **frozen v1.0 server API** (REST `/api/v1` + OAuth2/OIDC, gRPC `AuthorizationService`/`TokenService`/`UserService`, AMQP events). They are stateful auth clients, not thin codegen wrappers.

## SDK Capability Baseline (parity contract — applies to every per-language requirement below)

Every SDK requirement's acceptance criteria includes this baseline unless a language-specific protocol caveat applies (see protocol viability matrix in SUMMARY.md). The authoritative spec is **FND-03** (the written contract document).

- **Auth flows:** password login → typed `LoginResult{ mfa_required }`; two-phase MFA (`verify_mfa`); OAuth2 Client Credentials (M2M, Bearer); OAuth2 Authorization Code + PKCE (S256 only, no `plain`); OIDC discovery auto-config from `/.well-known/openid-configuration`; logout clears cookies/CSRF/local state.
- **Token lifecycle:** in-memory token manager; **single-flight refresh guard** (single-use rotating refresh token — concurrent 401s trigger exactly ONE refresh); proactive refresh at `exp − 60s` for server personas; tokens wrapped in a `Sensitive<T>`-style type that suppresses debug/display/log output.
- **Authorization:** gRPC `CheckAccess` + `BatchCheckAccess` (server personas); browser persona uses the REST authz-check endpoint (FND-04); optional TTL decision cache invalidated on logout.
- **Tenant context:** `tenant_slug`/`tenant_id` is a **non-optional constructor parameter**, injected on every request.
- **Transport security:** TLS verification strict by default; NO insecure-skip option; `with_custom_ca(pem)` for dev self-signed certs only.
- **AMQP (where viable):** event consumer for `AuditEventMessage` / `NotificationEvent` (schema: `crates/axiam-amqp/src/messages.rs`); **mandatory HMAC-SHA256 verification** of `hmac_signature` before processing; signature failure ⇒ nack without requeue.
- **Errors:** typed taxonomy — `AuthError`, `AuthzError`, `NetworkError` (per-language idioms).
- **Deliverables:** framework middleware/route guard; runnable usage examples; README/getting-started; publish-ready package metadata.

---

## FND-01: OpenAPI Spec Export

**Priority:** Critical | **Source:** research ARCHITECTURE.md (codegen source of truth)

Add a `--dump-openapi` flag to the server binary that prints `api_doc().to_pretty_json()` and exits WITHOUT starting SurrealDB or AMQP, and commit the first export as the SDK REST codegen source of truth.

### Acceptance Criteria
- [ ] `axiam-server --dump-openapi` writes the utoipa OpenAPI JSON to stdout/file with no DB/AMQP connection
- [ ] `sdks/openapi.json` committed (first export)
- [ ] CI workflow re-exports on release and **fails on drift** vs the committed file
- [ ] Flag documented in server `--help`

---

## FND-02: Multi-Language Proto Codegen (buf)

**Priority:** Critical | **Source:** research STACK.md / ARCHITECTURE.md

Establish a single `buf`-driven gRPC codegen pipeline over `proto/axiam/v1/` for all gRPC-capable SDKs, with breaking-change protection in CI.

### Acceptance Criteria
- [ ] `sdks/buf.yaml` + `sdks/buf.gen.yaml` generate stubs for Rust/TS/Go/Python/Java (C# uses `Grpc.Tools` MSBuild — documented exception)
- [ ] `buf lint` + `buf breaking` run in CI on `proto/**` changes
- [ ] Generated stubs are reproducible from a clean checkout (documented command)

---

## FND-03: Cross-Language SDK Contract Document

**Priority:** Critical | **Source:** research (arch + pitfalls converged independently)

Author the written behavioral contract all 7 SDKs conform to, so naming/behavior do not diverge across languages.

### Acceptance Criteria
- [ ] Method naming map (login/verify_mfa/refresh/logout/check_access/etc.) per language idiom
- [ ] Error taxonomy (`AuthError`/`AuthzError`/`NetworkError`) and mapping from HTTP/gRPC status
- [ ] CSRF behavior (browser), cookie-jar requirement (non-browser), `tenant_*` constructor contract
- [ ] TLS policy (strict default; `with_custom_ca`); `Sensitive<T>` token-redaction requirement
- [ ] AMQP consumer contract (HMAC verify, nack-no-requeue on failure)
- [ ] Middleware/route-guard interface expectation per framework
- [ ] Document lives at `sdks/CONTRACT.md` (or equivalent) and is referenced by every SDK README

---

## FND-04: REST Authorization-Check Endpoint

**Priority:** High | **Source:** user decision (browser SDK authz path); codebase gap (no REST authz query exists)

Add a permission-guarded, tenant-scoped REST endpoint exposing the authorization decision so the browser (REST-only) TypeScript SDK can offer a `can()` method. Mirrors gRPC `CheckAccess` semantics.

### Acceptance Criteria
- [ ] `POST /api/v1/authz/check` accepts `{ action, resource_id, scope? }`, returns `{ allowed, reason? }`
- [ ] Decision computed via the same `AuthzChecker`/`AuthorizationEngine` as gRPC (no divergent logic)
- [ ] Tenant-scoped from the authenticated session; subject is the caller (or admin-specified with permission)
- [ ] Rate-limited and included in the OpenAPI spec (so it flows into FND-01 export)
- [ ] OpenAPI route↔spec parity test updated (consistent with the Phase-6 parity gate)

---

## FND-05: SDK Monorepo Scaffold & CI

**Priority:** High | **Source:** research ARCHITECTURE.md (monorepo + path-filtered CI)

Create the `sdks/` monorepo layout and per-SDK CI so each language builds/tests independently and cheaply.

### Acceptance Criteria
- [ ] `sdks/{rust,typescript,python,java,csharp,php,go}/` directories scaffolded
- [ ] Per-SDK GitHub Actions build/test workflow, triggered by `paths:` filter (O(1) CI per change)
- [ ] Shared codegen artifacts (`openapi.json`, buf output) wired into each SDK's build
- [ ] Apache-2.0 LICENSE present in each SDK package (matches repo license)

---

## RUST-01: Rust SDK (reference implementation)

**Priority:** Critical | **Source:** roadmap T17.1 | **Protocols:** REST + gRPC + AMQP

Deliver `sdks/rust/` as the reference SDK proving the full capability baseline; establishes the `Sensitive<T>` and gRPC-channel patterns reused by the others.

### Acceptance Criteria
- [x] Full **SDK Capability Baseline** (above)
- [x] reqwest 0.12 REST + tonic 0.14 gRPC + lapin 4 AMQP (versions pinned to server workspace)
- [x] `reqwest::cookie::Jar` cookie persistence; Actix-Web middleware/extractor helper
- [x] Concurrency test: 5 concurrent requests on an expired token ⇒ exactly 1 refresh call
- [x] Examples + publish-ready `Cargo.toml`; **crates.io publish pipeline** in CI

---

## TS-01: TypeScript SDK

**Priority:** Critical | **Source:** roadmap T17.2 | **Protocols:** REST (browser+Node); gRPC + AMQP Node-only

Deliver `sdks/typescript/` with distinct browser vs Node entry points.

### Acceptance Criteria
- [x] Full baseline; **browser persona** authz via REST endpoint (FND-04); **Node persona** authz via gRPC
- [x] axios 1.7 REST + @grpc/grpc-js 1.14 (Node) + amqplib (Node); `jose` for JWKS; ts-proto 2.x stubs
- [x] Separate `axiam-sdk/rest` / `axiam-sdk/grpc` / `axiam-sdk/amqp` export conditions (browser bundlers tree-shake Node-only)
- [x] CSRF interceptor auto-forwards `X-CSRF-Token`; promise-deduplicated refresh guard (Node CSRF populated via `onAuthenticated()` jar-read — CR-01 closed in 17-08; refresh guard is per-session via `createRefreshGuard()` — CR-02 closed in 17-07)
- [x] Express + Fastify middleware; examples; **npm publish pipeline** (`axiam-sdk`)

---

## GO-01: Go SDK

**Priority:** High | **Source:** roadmap T17.7 | **Protocols:** REST + gRPC + AMQP

Deliver `sdks/go/` (second server-side reference).

### Acceptance Criteria
- [x] Full baseline; `sync.Mutex` single-flight refresh; `net/http/cookiejar`
- [x] net/http REST + grpc-go 1.81 + amqp091-go 1.10; lestrrat-go/jwx/v3 for EdDSA/JWKS
- [x] No `InsecureSkipVerify` anywhere (CI lint gate); net/http middleware
- [x] Examples; **Go module publish** (`github.com/ilpanich/axiam/sdks/go`, version tag `sdks/go/vX.Y.Z`)

---

## PY-01: Python SDK

**Priority:** High | **Source:** roadmap T17.3 | **Protocols:** REST + gRPC + AMQP

Deliver `sdks/python/` with sync + async interfaces.

### Acceptance Criteria
- [x] Full baseline; `asyncio.Lock` single-flight refresh; `httpx.Cookies` jar; `verify=True` hardcoded
- [x] httpx 0.27 (sync+async) + grpcio 1.78 + aio-pika 9.6; Pydantic v2 models; PyJWT for JWKS
- [x] FastAPI dependency + Django middleware helpers
- [x] Examples; **PyPI publish pipeline** (`axiam-sdk`)

---

## JAVA-01: Java SDK

**Priority:** High | **Source:** roadmap T17.4 | **Protocols:** REST + gRPC + AMQP

Deliver `sdks/java/` with Spring Security integration.

### Acceptance Criteria
- [ ] Full baseline; `ReentrantLock` single-flight refresh; OkHttp `CookieManager`
- [ ] OkHttp 4.12 + grpc-netty-shaded 1.82 + amqp-client 5.22; nimbus-jose-jwt 10.x + Tink for EdDSA
- [ ] Spring Security filter integration; builder requires `tenantId`
- [ ] Examples; **Maven Central publish** (`io.axiam:axiam-sdk`) incl. **GPG signing setup** task

---

## CS-01: C# SDK

**Priority:** High | **Source:** roadmap T17.5 | **Protocols:** REST + gRPC + AMQP

Deliver `sdks/csharp/` with ASP.NET Core integration.

### Acceptance Criteria
- [ ] Full baseline; `SemaphoreSlim(1,1)` single-flight refresh; `HttpClientHandler.CookieContainer`
- [ ] HttpClient + Grpc.Net.Client 2.80 + RabbitMQ.Client 7.2; native EdDSA on .NET 8+ (BouncyCastle for netstandard2.0)
- [ ] `Grpc.Tools` MSBuild codegen (documented buf exception); `Axiam.Sdk.AspNetCore` middleware sub-package
- [ ] Examples; **NuGet publish pipeline** (`Axiam.Sdk`) incl. credential setup

---

## PHP-01: PHP SDK

**Priority:** Medium | **Source:** roadmap T17.6 | **Protocols:** REST + AMQP; gRPC long-running runtimes only

Deliver `sdks/php/` (REST-first; gRPC guarded by runtime capability).

### Acceptance Criteria
- [ ] Full baseline minus standard-FPM gRPC; Guzzle `HandlerStack` single-refresh middleware; Guzzle `CookieJar`; `verify: true`
- [ ] Guzzle 7.x REST + php-amqplib 3.7 AMQP + firebase/php-jwt 6.11; optional grpc PECL behind `extension_loaded('grpc')` guard with documented Swoole/RoadRunner requirement
- [ ] Laravel + Symfony middleware helpers
- [ ] Examples; **Packagist publish** (`axiam/axiam-sdk`)

---

## v1.1 Dependency Map

```
FND-01 (OpenAPI export) ─┐
FND-02 (buf codegen) ────┼──→ all per-language SDKs
FND-03 (contract doc) ───┤
FND-04 (REST authz) ─────┘ (unblocks TS-01 browser can())
FND-05 (monorepo + CI) ──┘

RUST-01 (reference) ──→ informs patterns for ──→ TS-01, GO-01, PY-01, JAVA-01, CS-01, PHP-01
                                                  (these 6 can parallelize once FND + RUST land)
```

## v1.1 Traceability (confirmed — roadmap created 2026-06-28)

| Requirement | Phase | Description | Status |
|-------------|-------|-------------|--------|
| FND-01 | Phase 15 | OpenAPI Spec Export (`--dump-openapi` + `sdks/openapi.json` + drift gate) | Pending |
| FND-02 | Phase 15 | Multi-Language Proto Codegen (buf pipeline + lint/breaking gate) | Pending |
| FND-03 | Phase 15 | Cross-Language SDK Contract Document (`sdks/CONTRACT.md`) | Pending |
| FND-04 | Phase 15 | REST Authorization-Check Endpoint (`POST /api/v1/authz/check`) | Pending |
| FND-05 | Phase 15 | SDK Monorepo Scaffold & per-SDK path-filtered CI | Pending |
| RUST-01 | Phase 16 | Rust SDK — REST + gRPC + AMQP (reference implementation) | Complete |
| TS-01 | Phase 17 | TypeScript SDK — browser (REST) + Node (REST + gRPC + AMQP) | Pending |
| GO-01 | Phase 18 | Go SDK — REST + gRPC + AMQP | Complete |
| PY-01 | Phase 19 | Python SDK — REST + gRPC + AMQP (sync + async) | Complete |
| JAVA-01 | Phase 20 | Java SDK — REST + gRPC + AMQP + Maven Central | Pending |
| CS-01 | Phase 21 | C# SDK — REST + gRPC + AMQP + NuGet | Pending |
| PHP-01 | Phase 22 | PHP SDK — REST + AMQP; gRPC long-running runtimes only | Pending |

**Coverage: 12/12 v1.1 requirements mapped (100%)**

---
*v1.1 requirements added 2026-06-28 — Client SDKs milestone (phases 15–22). Foundation-first; 7 SDKs full multi-protocol where viable; auth flows P1+P2; publish pipelines included. Roadmap confirmed 2026-06-28.*
