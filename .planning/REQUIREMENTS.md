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
- [x] Full baseline; `ReentrantLock` single-flight refresh; OkHttp `CookieManager`
- [x] OkHttp 4.12 + grpc-netty-shaded 1.82 + amqp-client 5.22; nimbus-jose-jwt 10.x + Tink for EdDSA
- [x] Spring Security filter integration; builder requires `tenantId`
- [x] Examples; **Maven Central publish** (`io.axiam:axiam-sdk` SDK jar **and** `io.axiam:axiam-bom` Bill-of-Materials — the BOM coordinate was added during Phase 20 discuss, D-23, to align consumer dependency versions) incl. **GPG signing setup** task — CI/publish pipeline structurally proven (ephemeral-key `mvn verify -Dgpg.skip=false`); live first Central publish is a maintainer action pending namespace verification + CI secrets

---

## CS-01: C# SDK

**Priority:** High | **Source:** roadmap T17.5 | **Protocols:** REST + gRPC + AMQP

Deliver `sdks/csharp/` with ASP.NET Core integration.

### Acceptance Criteria
- [x] Full baseline; `SemaphoreSlim(1,1)` single-flight refresh; `HttpClientHandler.CookieContainer`
- [x] HttpClient + Grpc.Net.Client 2.80 + RabbitMQ.Client 7.2; BouncyCastle.Cryptography for Ed25519 (native EdDSA confirmed unavailable on .NET 8+ — 21-RESEARCH.md; netstandard2.0 leg deferred, D-01)
- [x] `Grpc.Tools` MSBuild codegen (documented buf exception); `Axiam.Sdk.AspNetCore` middleware sub-package
- [x] Examples; **NuGet publish pipeline** (`Axiam.Sdk` + `Axiam.Sdk.AspNetCore`) incl. credential setup — CI/publish pipeline structurally proven (build/test/pack + tag-triggered `dotnet nuget push`); live first publish is a maintainer action pending `NUGET_API_KEY` secret configuration

---

## PHP-01: PHP SDK

**Priority:** Medium | **Source:** roadmap T17.6 | **Protocols:** REST + AMQP; gRPC long-running runtimes only

Deliver `sdks/php/` (REST-first; gRPC guarded by runtime capability).

### Acceptance Criteria
- [x] Full baseline minus standard-FPM gRPC; Guzzle `HandlerStack` single-refresh middleware; Guzzle `CookieJar`; `verify: true`
- [x] Guzzle 7.x REST + php-amqplib 3.7 AMQP + firebase/php-jwt 6.11; optional grpc PECL behind `extension_loaded('grpc')` guard with documented Swoole/RoadRunner requirement
- [x] Laravel + Symfony middleware helpers
- [x] Examples; **Packagist publish** (`axiam/axiam-sdk`) — publish pipeline shipped (`sdk-ci-php.yml`); live publish is a maintainer `user_setup` (mirror repo + `PHP_SDK_MIRROR_TOKEN`)

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
| JAVA-01 | Phase 20 | Java SDK — REST + gRPC + AMQP + Maven Central | Complete |
| CS-01 | Phase 21 | C# SDK — REST + gRPC + AMQP + NuGet | Complete |
| PHP-01 | Phase 22 | PHP SDK — REST + AMQP; gRPC long-running runtimes only | Complete |

**Coverage: 12/12 v1.1 requirements mapped (100%)**

---
*v1.1 requirements added 2026-06-28 — Client SDKs milestone (phases 15–22). Foundation-first; 7 SDKs full multi-protocol where viable; auth flows P1+P2; publish pipelines included. Roadmap confirmed 2026-06-28.*

---

# Requirements — Milestone v1.2: MVP Release Hardening (final milestone)

> Milestone: v1.2
> Created: 2026-07-03
> Source: `claude_dev/roadmap.md` Phases 18–19 + `claude_dev/security-review-postremediation.md` + `claude_dev/code-review-postremediation.md`
> Scope decisions (user, 2026-07-03): FINAL milestone to MVP. Close all open SEC-*/CQ-*/T19.x findings. Structural-quality refactors IN scope (dedicated phase). Domain research skipped (enumerated findings, no new domain features). Phase numbering continues from Phase 23.

This milestone remediates the **open findings against `ea85872`** (both post-remediation reviews) that the v1.1 SDK work did not touch, plus the outstanding roadmap Phase 18 (Hardening & Compliance) and Phase 19 (deferred improvements) tasks. Priority order per Core Value: **security > correctness > performance > compliance > structural quality > docs.** Each acceptance criterion cites the originating finding ID; planners MUST re-verify the finding against live `main` before implementing (some may have shifted since the review commit) and adjust the fix, but MUST NOT silently drop a criterion without recording why.

## Verification baseline (applies to every requirement below)

- Every fix ships with a **regression test that fails before and passes after** (unit or integration). Security fixes additionally get a **negative test** proving the attack is now rejected.
- `cargo fmt` + `cargo clippy -D warnings` clean per touched crate; frontend `eslint .` + `tsc -b` clean when frontend is touched. Per-crate builds only (`cargo check/test -p <crate>`), never full-workspace.
- No new `unwrap()`/`expect()`/`unwrap_or([0u8;32])`-style fallbacks on security paths; secrets never serialized, logged, or defaulted to constants.
- Fail-closed is the default posture for every auth/authz/crypto/federation control.

---

## SECFIX-01: gRPC UserService & TokenService Authentication

**Priority:** Critical | **Source:** SEC-003 (was CRITICAL), SEC-026b

Attach the existing `AuthInterceptor` to `UserService` and `TokenService`; derive identity from verified JWT claims, not the request body.

### Acceptance Criteria
- [x] `UserServiceServer` and `TokenServiceServer` wrapped with `AuthInterceptor` (or a shared layer) — `server.rs`
- [x] `GetUser`, `ValidateCredentials`, `IntrospectToken` read `tenant_id`/`user_id` from `ValidatedClaims` and reject any mismatched body field (mirror `authorization.rs:73-99`)
- [x] `ValidateCredentials` accrues failed-login/lockout state via the shared helper (closes SEC-026b / T19.5 on the gRPC path)
- [x] Reject-without-token negative tests added for both services
- [x] Cross-tenant `GetUser` read returns permission error, proven by test

## SECFIX-02: Tenant Guard on Live REST Grant Path

**Priority:** Critical | **Source:** SEC-058, cross-ref SEC-007/CQ-B07

The REST `POST /api/v1/roles/{role_id}/permissions` calls `grant_to_role_with_scopes`, which is unguarded; the SEC-007 tenant guard landed only on `grant_to_role`.

### Acceptance Criteria
- [x] `grant_to_role_with_scopes` applies the `LET … IF array::len = 0 { THROW }` tenant predicate on both the empty-scope and scoped branches — `permission.rs:428-459`
- [x] Every scope id is validated to belong to the caller's tenant before `RELATE`
- [x] The tenant-isolation test is repointed at the REST-reachable `grant_to_role_with_scopes` path (not the guarded `grant_to_role`)
- [x] Negative test: caller with `permissions:grant` in tenant A cannot attach tenant B's permission to a tenant A role

## SECFIX-03: Webhook Secret — Fail-Closed Key & Encrypt-at-Rest

**Priority:** Critical | **Source:** SEC-059, SEC-031

Remove the `unwrap_or([0u8; 32])` all-zero encryption-key fallback and actually encrypt webhook HMAC secrets on write.

### Acceptance Criteria
- [x] `main.rs:389-390` no longer substitutes an all-zero key; webhook subsystem fails closed (or disables webhook registration) when `AXIAM__PKI__ENCRYPTION_KEY` is unset — mirror the PKI `Option<[u8;32]>` pattern
- [x] `encrypt_webhook_secret` is called on create AND update paths (`webhook.rs`, `handlers/webhooks.rs`); secret never bound verbatim
- [x] Response exclusion (`skip_serializing`) retained; secret rotation exposed in the update DTO
- [x] Round-trip test: stored ciphertext ≠ plaintext; delivery decrypt succeeds

## SECFIX-04: SAML Signature-to-Assertion Binding

**Priority:** Critical | **Source:** SEC-005 (XSW), cross-ref T19.7

Bind the verified XML signature to the consumed assertion and enforce the remaining protocol checks (defends against XML Signature Wrapping).

### Acceptance Criteria
- [x] `handle_saml_response` consumes only the assertion whose ID equals the signed element's reference (no independent `response.assertion` read) — `bind_signature_to_assertion` (saml.rs) rejects unless exactly one `<Assertion>` exists and a verified `<Signature>` Reference resolves to it
- [x] `Destination` validated against the real ACS URL (authenticated call site `handlers/federation.rs` `saml_acs` now passes `Some(&req.acs_url)` instead of `None`; public path `saml_acs_public` unchanged, out of scope)
- [ ] `Recipient` / `SubjectConfirmationData` validated — **DEFERRED**: out of scope for 23-04 per 23-CONTEXT.md `<deferred>` / 23-RESEARCH.md "Deferred Ideas"; tracked as the SEC-005 residual for a future phase (see 23-04-SUMMARY.md "SEC-005 Residual")
- [x] Authenticated ACS path rejects unsolicited responses (`InResponseTo` required) — `handle_saml_response` gained `require_in_response_to: bool`, `saml_acs` passes `true`
- [x] XSW negative test: a wrapped/duplicated-assertion response is rejected; Destination/InResponseTo negative tests added — `req5_saml_e2e.rs`: `saml_rejects_xsw_wrapped_assertion`, `saml_rejects_wrong_destination_on_authenticated_path`, `saml_rejects_missing_in_response_to_on_authenticated_path`

## SECFIX-05: Logout Revokes the Caller's Session

**Priority:** High | **Source:** SEC-015, CQ-F05

Make logout revoke the caller's own session from the JWT `jti` without requiring a client-supplied body.

### Acceptance Criteria
- [x] `POST /api/v1/auth/logout` derives the session from the authenticated JWT `jti`; no required `{session_id}` body (or client sends the correct body) — `LogoutRequest` DTO removed; handler revokes via `user.session_id` only
- [x] Session invalidated and all three cookies cleared server-side; a subsequent request with the old cookies is unauthenticated — `logout_clears_cookies` replay-after-logout assertion (401 on `/api/v1/auth/me`)
- [x] Frontend `handleLogout` succeeds (no 400); query cache + auth store cleared — `Topbar.tsx` posts with no body
- [x] Test: logout then reload does not re-authenticate from surviving cookies — `frontend/e2e/logout.spec.ts` (authored + tsc/eslint clean; local Playwright run deferred per CORR-04, see 23-05-SUMMARY.md)

## SECFIX-06: Password-Reset / Resend Flows Threaded with tenant_id

**Priority:** High | **Source:** SEC-044, CQ-F27

The reset/resend flows 400 because the frontend omits backend-required `tenant_id` (and resend omits `email`).

### Acceptance Criteria
- [x] `requestPasswordReset`, `confirmPasswordReset`, `resendVerification` send `{tenant_id, email/…}` matching the backend DTOs — `auth.ts` threads tenant context/email into all three calls; backend `request_reset`/`resend_verification` build a fully-substituted `action_url` into the emailed link (23-RESEARCH Pattern 6 / Pitfall 3)
- [x] Reset/verify links carry `tenant_id` so the page can forward it — `ResetPasswordPage`/`VerifyEmailPage` read `?token=&tenant_id=`; `ForgotPasswordPage` reads `?org=&tenant=` slugs (D-04)
- [x] Responses remain enumeration-safe (constant response regardless of account existence) — unresolvable/missing tenant slug funnels into the same uniform `{"sent": true}`/200 as an unknown account (D-05), proven by `unresolvable_tenant_slug_resolves_to_none_enumeration_safe`/`missing_tenant_context_resolves_to_none_enumeration_safe`
- [x] Contract test asserts request **bodies** (not just paths) — `auth-contract.spec.ts` (authored + tsc/eslint clean; local Playwright execution blocked by sandbox proxy denying the browser-binary download, see 23-06-SUMMARY.md; CI wiring remains CORR-04)

---

## SECHRD-01: TOTP Atomic Replay Protection

**Priority:** High | **Source:** SEC-008

Make the TOTP step check-and-update atomic and close the skew-boundary and enrollment-confirm replay windows.

### Acceptance Criteria
- [x] Step update is a conditional compare-and-set in the DB (`WHERE totp_last_used_step < $step`) — concurrent submissions of one code succeed at most once — `SurrealUserRepository::update_totp_step` (24-01)
- [x] The step actually matched (incl. the −1 skew window) is recorded, so a code accepted via skew is not replayable in later wall-clock steps — `verify_code_with_replay_check` (24-01)
- [x] `totp_last_used_step` seeded at enrollment-confirm time — `AuthService::confirm_mfa` (24-01)
- [x] Concurrency test: N parallel submissions of one valid code ⇒ exactly one success — `totp_step_cas_test.rs::totp_step_cas_concurrent` (24-01)

## SECHRD-02: SSRF Address Pinning (webhook + federation fetches)

**Priority:** High | **Source:** SEC-019, SEC-064

Pin the validated IP and extend the private-IP guard beyond JWKS to all federation outbound fetches.

### Acceptance Criteria
- [ ] Webhook delivery pins the validated `IpAddr` into the connection (custom resolver / `resolve()`) — no DNS-rebind between check and send (plan 25-02)
- [x] Private/loopback/link-local/ULA guard applied to OIDC discovery, token exchange, and SAML-metadata fetches (not just JWKS) — shared `axiam_federation::ssrf` module (25-01)
- [x] Resolved address pinned for those fetches too (close the JWKS DNS-rebind TOCTOU) — `ssrf::pinned_client` via `ClientBuilder::resolve()` (25-01)
- [x] Negative test: an internal/loopback `token_endpoint` from a discovery document is rejected — `ssrf_rejects_loopback_token_endpoint`, `ssrf_rejects_redirect_to_internal` (25-01)

## SECHRD-03: Rate-Limit Client-IP Keying

**Priority:** High | **Source:** SEC-048, SEC-060

Fix the XFF fallback that returns the client-controlled leftmost hop and reconcile `trusted_hops` guidance with nginx's append semantics.

### Acceptance Criteria
- [x] When `trusted_hops >= hops.len()`, ignore XFF and use `peer_addr()` (do not return `hops[0]`) — `XForwardedForKeyExtractor::extract` (24-03)
- [x] `trusted_hops` docs corrected for nginx `proxy_add_x_forwarded_for` (rightmost = real client) (24-03)
- [x] Rotating `X-Forwarded-For` per request no longer yields a fresh bucket (test) — `rate_limit_xff_rotation_rejected` (24-03)
- [x] Multi-replica shared rate-limit store implemented, or the per-replica multiplier documented loudly — `rate_limit_bucket` table + `RateLimitShared` middleware (24-04); gRPC parity implemented+tested (24-07) and wired into production `start_grpc_server`/`main.rs` (24-07 gap-closure)

## SECHRD-04: Bootstrap Atomicity & Mandatory Gate

**Priority:** High | **Source:** SEC-049

Close the initialized-check TOCTOU and require the bootstrap gate unconditionally.

### Acceptance Criteria
- [x] First-super-admin creation is a single conditional/transactional operation keyed on a uniqueness invariant (two concurrent first-run requests ⇒ at most one super-admin) — `bootstrap_lock` uniqueness-invariant CREATE folded into the admin-creation transaction (24-08)
- [x] `AXIAM_BOOTSTRAP_ADMIN_EMAIL` (or a one-time setup token) is required unconditionally — an unset var does NOT allow arbitrary bootstrap — mandatory fail-closed gate (24-08)
- [x] Concurrency test proves single-admin invariant — `bootstrap_test.rs::bootstrap_concurrent_race_single_admin` (24-08)

## SECHRD-05: mTLS CA Status & Validity Enforcement

**Priority:** Medium | **Source:** SEC-061 (SEC-024 residual)

Assert the issuing CA is Active and within its validity window before trusting it for device-cert auth.

### Acceptance Criteria
- [x] `mtls.rs` checks CA `status == Active` and current time within CA validity before `verify_signature` (25-03)
- [x] Revoked/expired CA ⇒ device auth fails closed (test) — `mtls_rejects_revoked_issuing_ca`, `mtls_rejects_expired_issuing_ca` (25-03)

## SECHRD-06: GDPR Erasure Durability & Ledger Integrity

**Priority:** High | **Source:** SEC-063, SEC-065, SEC-066, CQ-B38 residual

Never certify an erasure while PII survives; make the erasure ledger and export dedup correct.

### Acceptance Criteria
- [ ] `audit_repo.pseudonymize_actor` failure is fatal to the purge (leave re-selection flags set) — proof written only after every PII-bearing step succeeds — `cleanup.rs:327-344`
- [ ] Erasure-proof rows are unique per user (no duplicate proof on late-stage retry) — `cleanup.rs:337-380`
- [ ] Export dedup also blocks when a `ready`-but-undownloaded or `failed` job exists (not only `queued`) — `export_job.rs:102-126`
- [ ] Export includes real `sessions` data (not hardcoded `[]`) and honors per-item shutdown checks
- [ ] Tests: failed pseudonymize ⇒ user re-selected, no proof; duplicate export request rejected

## SECHRD-07: Federation Nonce From Server State (authenticated path)

**Priority:** Medium | **Source:** SEC-004 residual

The account-linking OIDC callback must derive the expected nonce from server-side state, not the request body.

### Acceptance Criteria
- [ ] `handlers/federation.rs:595-648` derives `expected_nonce` from stored login state (same as the public path), ignoring `req.nonce`
- [ ] Replay test: a request-supplied nonce cannot satisfy verification

## SECHRD-08: AMQP Signing Key & ExportReady Delivery

**Priority:** Medium | **Source:** SEC-022, SEC-055, CQ-B05 residual

Make AMQP message signing mandatory in production, per-tenant, and fix undeliverable ExportReady mail.

### Acceptance Criteria
- [ ] `AXIAM__AMQP__SIGNING_KEY` mandatory in production (fail closed; no warn-and-process)
- [ ] Signing key scoped per tenant (or per-tenant queues + broker ACLs) so a tenant-A signature can't validate a tenant-B message
- [ ] ExportReady producer resolves real `org_id` from tenant (or consumer resolves it) — `cleanup.rs:510` no longer enqueues `Uuid::nil()`
- [ ] Mail-retry republish uses a backoff delay
- [ ] Test: ExportReady mail is deliverable end-to-end

## SECHRD-09: Federation Secret Non-Serialization

**Priority:** Medium | **Source:** SEC-017, SEC-043 residual

Prevent any future handler from leaking encrypted federation/PKI secrets by serializing the model directly.

### Acceptance Criteria
- [ ] `#[serde(skip_serializing)]` on `FederationConfig` `client_secret` / `client_secret_ciphertext` / `_nonce` / `_key_version`
- [ ] `Debug` impls do not print CA/PGP/secret blobs; list queries do not hydrate encrypted columns needlessly

## SECHRD-10: Network Egress & K8s Secret Completeness

**Priority:** Medium | **Source:** SEC-053, SEC-052 residual

Allow required egress under default-deny and complete the k8s secret set.

### Acceptance Criteria
- [ ] SMTP egress NetworkPolicy (ports 25/465/587) added so verification/GDPR-export mail works in-cluster
- [ ] `0.0.0.0/0:443` egress rule tightened with pod/service cluster-CIDR exclusions
- [ ] K8s secret includes federation/email/GDPR/pepper keys; CI `test` job uses the correct `AXIAM__…` prefix

## SECHRD-11: Public-Path Allowlist Hardening

**Priority:** Medium | **Source:** T19.25

Require a segment boundary in public-path wildcard matching and normalize the path before the exclusion check.

### Acceptance Criteria
- [x] Wildcard public entries match only on a path-segment boundary (e.g. `/api/v1/auth/*` does not match `/api/v1/authz/...`)
- [x] Path normalized before the allowlist check — collapse `//`, resolve/reject `..` traversal
- [x] Negative test: a non-canonical route cannot slip past the allowlist

## SECHRD-12: Auth Crypto & Recovery Side-Channels

**Priority:** Medium | **Source:** T19.23, T19.24, T19.27, SEC-028 residual

Close remaining auth-path timing/memory/durability side-channels.

### Acceptance Criteria
- [x] Constant-time password-reset: ineligible/unknown/federated path performs an equivalent dummy hash + async wait so response time doesn't distinguish valid emails (T19.23) — 24-09
- [x] Peppered-password buffer wrapped with `zeroize` (pepper via `secrecy`) and wiped before return (T19.24) — 24-05
- [x] GDPR audit-write failure falls back to a persistent dead-letter file / audit syslog for durability (T19.27) — 24-06
- [x] Unauthenticated reset path blocks reuse of the current password; initial passwords seeded into history (SEC-028 residual) — 24-09

---

## CORR-01: gRPC Governor Throughput Semantics

**Priority:** High | **Source:** CQ-B44

The governor currently throttles the mesh to ~1 token / 100 s (per_second semantics inverted).

### Acceptance Criteria
- [ ] Use `per_millisecond(1000 / authz_per_sec)` (or `Quota::per_second`) with a separate burst — `rate_limit.rs:40-47`
- [ ] Raising `grpc_authz_per_sec` increases throughput (not decreases it)
- [ ] Test asserts sustained throughput ≈ configured rate

## CORR-02: SurrealDB Token Renewal / Reconnect

**Priority:** High | **Source:** CQ-B45

The 4-week root-token TTL with no renewal is an uptime ceiling on the control plane.

### Acceptance Criteria
- [ ] Periodic re-`signin`/handle-refresh well inside the token TTL, OR reconnect-on-auth-error path — `connection.rs`
- [ ] `health_check` surfaces auth-expiry as unhealthy (readiness alarm)
- [ ] Test/simulation proves the client recovers after token expiry without a process restart

## CORR-03: Webhook Delivery Wiring

**Priority:** High | **Source:** CQ-B22 (+ depends on SECFIX-03)

Wire webhook delivery through a durable path with retry; today `.deliver(` has zero call sites.

### Acceptance Criteria
- [ ] Delivery driven from a persistent queue (AMQP) rather than a detached `tokio::spawn`; survives restart
- [ ] HMAC-SHA256 signature header; exponential-backoff retry; delivery status written to the audit trail
- [ ] Depends on SECFIX-03 (secret encrypted on write) so the decrypt-on-deliver step succeeds
- [ ] Integration test: registered webhook receives a signed delivery; failed delivery retries

## CORR-04: Playwright Runs in CI with Body Assertions

**Priority:** High | **Source:** CQ-F36, cross-ref SEC-044/CQ-F27

The CI "e2e" job runs vitest, not Playwright — all 12 specs never execute.

### Acceptance Criteria
- [ ] CI e2e step runs `npx playwright test` (vitest kept as its own step) — `.github/workflows/ci.yml`
- [ ] The auth/login/contract specs execute against the seeded backend and gate the build
- [ ] The contract spec asserts request **bodies**, catching SECFIX-06 regressions
- [ ] `playwright-report` artifact reflects real runs

## CORR-05: Frontend Tenant Context & MFA-Setup Landing

**Priority:** High | **Source:** CQ-F29, CQ-F31

### Acceptance Criteria
- [ ] `/auth/me` (`MeResponse`/`LoginUserInfo`) emits `tenant_slug`/`org_slug`; Topbar restores tenant after hard reload (CQ-F29 — backend + frontend)
- [ ] `mfa_setup_required` landing reads the `setup_token` and enrolls via the setup endpoint (no dead end for MFA-mandated users) — CQ-F31

## CORR-06: Frontend Residual Correctness

**Priority:** Medium | **Source:** CQ-F19, CQ-F37, CQ-F38

### Acceptance Criteria
- [ ] VerifyEmailPage uses a `useRef` once-guard (no StrictMode double-fire / false "failed") — CQ-F19
- [ ] Dashboard gets a distinct query key so `["users",1,""]` no longer collides with UsersPage's different page size — CQ-F37
- [ ] Org settings form guards init on first load / tracks dirtiness (no discard of in-progress edits on refocus) — CQ-F38

---

## PERF-01: HIBP Circuit Breaker & Hot-Path Pre-Sizing

**Priority:** Medium | **Source:** T19.26

### Acceptance Criteria
- [ ] `check_hibp` wrapped in a circuit breaker that trips on repeated failure/timeout and fails open (`Ok(None)`) for a cooldown window
- [ ] Hot-path violation/segment vectors pre-sized with `Vec::with_capacity(n)` (complexity checker, authz middleware, SDK serialization maps)
- [ ] Load test: a credential-stuffing burst does not starve legitimate flows

## PERF-02: Concurrent Bounded BatchCheckAccess

**Priority:** Medium | **Source:** T19.2, CQ-B20

### Acceptance Criteria
- [ ] `BatchCheckAccess` evaluates requests concurrently with bounded concurrency (`buffer_unordered`/`FuturesUnordered`), result order preserved
- [ ] Benchmark shows improvement over the sequential implementation
- [ ] Correctness test: batch results match per-item `CheckAccess`

## PERF-03: JWKS Single-Flight Across SDKs

**Priority:** Medium | **Source:** T19.28

### Acceptance Criteria
- [ ] JWKS fetch wrapped in a single-flight promise/future so N concurrent cache-misses await one network request
- [ ] Applied consistently across Python, Go, Rust, Java, C#, TypeScript SDKs
- [ ] Test: burst of invalid-`kid` tokens triggers exactly one JWKS fetch

## PERF-04: SurrealDB Reconnect Resilience

**Priority:** Medium | **Source:** T19.33, T19.34

### Acceptance Criteria
- [ ] Reconnect loop uses exponential backoff with **full jitter**, a `max_backoff` ceiling, and a bounded retry count that surfaces a critical error (no flat-interval hammering)
- [ ] Poisoned connections (topology anomaly / handshake timeout) are dropped and regenerated, never recycled into the healthy pool
- [ ] Test/simulation: competing workers desynchronize; a failed handshake does not leak a broken handle

## PERF-05: Load Testing & Critical-Path Profiling

**Priority:** Medium | **Source:** T18.3

### Acceptance Criteria
- [ ] Load-test harness (k6 and/or criterion benches) for auth, authz check, and certificate validation
- [ ] Critical paths profiled; measurable optimizations applied where warranted
- [ ] Results documented in `claude_dev/performance-report.md` with baseline vs optimized numbers

---

## FUNC-01: Unauthenticated First-Time Federation Login

**Priority:** High | **Source:** T19.9

### Acceptance Criteria
- [ ] `POST /auth/federation/oidc/login` and `POST /auth/federation/saml/login` complete the external flow and return AXIAM access/refresh tokens for first-time users (no pre-existing local account)
- [ ] Existing authenticated endpoints remain for account-linking
- [ ] Federation metadata endpoint is public (no auth) — `handlers/federation.rs:377`
- [ ] E2e: create federation config via API, then complete a first-time login (closes CQ-B40 gap)

## FUNC-02: Session Invalidation on Password Reset

**Priority:** High | **Source:** T19.10, REQ-7 (v1.0 carryover), OWASP ASVS 3.3.1

### Acceptance Criteria
- [ ] `confirm_reset` invalidates all active sessions/refresh tokens for the user (threads `SessionRepository` into `PasswordResetService`)
- [ ] Test: after reset, prior sessions are rejected

## FUNC-03: Admin Email-Config API & Template Delivery

**Priority:** Medium | **Source:** T19.20, T19.21, T19.22

### Acceptance Criteria
- [ ] Admin REST CRUD for `email_config` (org- and tenant-scoped), guarded by `email_config:write` RBAC permission (T19.20)
- [ ] Mail consumer resolves per-org/per-tenant custom templates via `SurrealEmailTemplateRepository` (not the built-in default only) — T19.21
- [ ] `backfill_plaintext_secrets` implements the UPDATE path (encrypt + update rows where ciphertext is NULL) — T19.22

## FUNC-04: Admin User & MFA Management Endpoints

**Priority:** Medium | **Source:** codebase CONCERNS.md T19 TODOs, REQ-7

### Acceptance Criteria
- [ ] Admin user-listing endpoint enabled (RBAC-gated) — `handlers/auth.rs:470`
- [ ] Admin list/delete MFA methods for other users (RBAC-gated) — `mfa_methods.rs:72,116`
- [ ] Service-account dedicated token type with `sub_kind: "ServiceAccount"` — `handlers/auth.rs:364`

## FUNC-05: OpenAPI Login Response Schema

**Priority:** Low | **Source:** T19.4

### Acceptance Criteria
- [ ] `POST /auth/login` OpenAPI documents both `LoginSuccessResponse` and `MfaRequiredResponse` (via `oneOf` or distinct status codes) so generated SDKs model it correctly

---

## QUAL-01: AppState Extraction

**Priority:** Medium | **Source:** CQ-B43

### Acceptance Criteria
- [ ] `main.rs` composes a single `AppState` instead of ~45 inline `app_data` registrations
- [ ] Handlers extract dependencies from `AppState`; no behavior change (tests green)

## QUAL-02: Generic Pagination & Shared Repo Helpers

**Priority:** Medium | **Source:** CQ-B10

### Acceptance Criteria
- [ ] A generic `paginate<T>` helper exists and is adopted; the 24 duplicated `CountRow` definitions collapse to the shared `helpers::CountRow`
- [ ] Repos use `helpers::parse_uuid`/`take_first_or_not_found` instead of inline duplicates

## QUAL-03: Error Taxonomy Correctness

**Priority:** Medium | **Source:** CQ-B11, CQ-B17, CQ-B18

### Acceptance Criteria
- [ ] Index/unique violations on mainstream create paths map to `DbError::AlreadyExists` → HTTP 409 (not `Migration` → 500) — incl. user create, edge-uniqueness (CQ-B17)
- [ ] `helpers::parse_uuid` does not label a corrupt-data read as "Migration failed"
- [ ] OAuth2 handlers distinguish DB outage from `invalid_client` (CQ-B18)

## QUAL-04: Transactional Multi-Statement Mutations

**Priority:** Medium | **Source:** CQ-B07, CQ-B46, CQ-B38 setup

### Acceptance Criteria
- [ ] Role/permission edge deletes are transactional AND tenant-predicated (closes the cross-tenant edge-strip in CQ-B07/SEC-058 family)
- [ ] `resource::delete` child-guard + delete wrapped in one transaction (no TOCTOU — CQ-B46)
- [ ] GDPR deletion setup is transactional (a `create` failure after `mark_deletion_pending` cannot strand an uncancellable purge — CQ-B39 residual)

## QUAL-05: PKI Helper Deduplication

**Priority:** Low | **Source:** CQ-B15

### Acceptance Criteria
- [ ] `CertService` reconstructs the CA via `from_ca_cert_pem` (not from the subject CN)
- [ ] Keypair/fingerprint/encrypt helpers are shared, not triplicated across ca/cert/pgp

## QUAL-06: Frontend Shared Components & Services Adoption

**Priority:** Medium | **Source:** CQ-F15, CQ-F39, CQ-F17

### Acceptance Criteria
- [ ] Pages import the extracted `ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge`/`slugify`/`useCrudMutations` (local duplicates removed) — or the dead modules are deleted
- [ ] Profile/MFA pages call a typed users service instead of inline `api.*` calls

## QUAL-07: Dead-Code & Per-Request-Construction Cleanup

**Priority:** Low | **Source:** CQ-B47, CQ-B27

### Acceptance Criteria
- [ ] The second `verify_password` Argon2 impl (`user.rs:829-852`, re-exported) is deleted (pepper-less-caller trap)
- [ ] Federation/reset/verification services are constructed once (not per request across 9+ sites)

---

## CMPL-01: Security Audit Checklist

**Priority:** High | **Source:** T18.1

### Acceptance Criteria
- [ ] Checklist mapped to OWASP ASVS (Level 2 for IAM controls), ISO 27001, and CyberSecurity Act
- [ ] Every authentication, session, access-control, cryptography, and PKI requirement verified with a pass/fail + evidence pointer
- [ ] Findings and remediations documented in `claude_dev/security-audit.md`; open items cross-referenced to this milestone's REQ-IDs

## CMPL-02: GDPR Completeness

**Priority:** High | **Source:** T18.2, REQ-8 (v1.0 carryover)

### Acceptance Criteria
- [ ] User data export (`GET /api/v1/users/:id/export`) covers every table incl. real sessions; optional PGP encryption
- [ ] Account deletion (right to be forgotten) pseudonymizes audit PII durably (ties to SECHRD-06)
- [ ] Consent tracking recorded and exportable
- [ ] Compliance measures documented

---

## DOCS-01: Comprehensive Documentation

**Priority:** Medium | **Source:** T18.4

### Acceptance Criteria
- [ ] REST (OpenAPI), gRPC (proto), and AMQP (AsyncAPI) API docs
- [ ] Deployment guide (Docker/K8s, required env/secrets, NetworkPolicies)
- [ ] Admin guide + PKI/certificate guide
- [ ] SDK getting-started guides (link to the 7 SDK READMEs)
- [ ] Consolidated under `docs/`

---

## v1.2 Dependency Map

```
SECFIX-03 (encrypt-at-rest, fail-closed key) ── must precede ──► CORR-03 (webhook delivery decrypt)
SECFIX-06 (reset/resend bodies) ──────────────── verified by ──► CORR-04 (Playwright body assertions)
CORR-05 (/auth/me slugs) ─────────────────────── backend precedes frontend restore
SECHRD-06 (erasure durability) ───────────────── feeds ────────► CMPL-02 (GDPR completeness)
QUAL-03 (error taxonomy) / QUAL-04 (transactions) ── touch security-adjacent paths; sequence before/with QUAL-01 (AppState)
FUNC-04 (admin endpoints) ────────────────────── depends on ───► per-endpoint RBAC being enforced (already landed; re-verify)
```

Security regressions (SECFIX-01..06) are the highest priority and should land first. Structural-quality (QUAL-*) lands after security/correctness so refactors don't churn unreviewed security code.

## v1.2 Traceability (phase mapping filled by roadmapper)

| Requirement | Phase | Description | Status |
|-------------|-------|-------------|--------|
| SECFIX-01 | Phase 23 | gRPC UserService/TokenService auth (SEC-003) | Complete |
| SECFIX-02 | Phase 23 | Tenant guard on live grant path (SEC-058) | Complete |
| SECFIX-03 | Phase 23 | Webhook fail-closed key + encrypt-at-rest (SEC-059/031) | Complete |
| SECFIX-04 | Phase 23 | SAML signature↔assertion binding (SEC-005) | Complete (residual: Recipient/SubjectConfirmationData deferred) |
| SECFIX-05 | Phase 23 | Logout revokes session (SEC-015) | Complete |
| SECFIX-06 | Phase 23 | Reset/resend tenant_id (SEC-044) | Complete |
| SECHRD-01 | Phase 24 | TOTP atomic replay protection (SEC-008) | Complete |
| SECHRD-02 | Phase 25 | SSRF address pinning (SEC-019/064) | Pending |
| SECHRD-03 | Phase 24 | Rate-limit client-IP keying (SEC-048/060) | Complete (REST keying + shared store 24-03/24-04; gRPC key-extractor parity live + shared-store layer implemented+tested+wired 24-07 + 24-07 gap-closure — `GrpcSharedRateLimitLayer` now `.layer()`'d into `start_grpc_server`/`main.rs`, fail-open ahead of the in-memory governor) |
| SECHRD-04 | Phase 24 | Bootstrap atomicity + gate (SEC-049) | Complete |
| SECHRD-05 | Phase 25 | mTLS CA status/validity (SEC-061) | Complete |
| SECHRD-06 | Phase 25 | GDPR erasure durability + ledger (SEC-063/065/066) | Pending |
| SECHRD-07 | Phase 25 | Federation nonce from server state (SEC-004) | Pending |
| SECHRD-08 | Phase 25 | AMQP key + ExportReady delivery (SEC-022/055) | Pending |
| SECHRD-09 | Phase 25 | Federation secret skip_serializing (SEC-017) | Pending |
| SECHRD-10 | Phase 25 | Egress + k8s secret completeness (SEC-053/052) | Pending |
| SECHRD-11 | Phase 24 | Public-path allowlist hardening (T19.25) | Complete |
| SECHRD-12 | Phase 24 | Auth crypto/recovery side-channels (T19.23/24/27) | Complete |
| CORR-01 | Phase 26 | gRPC governor throughput (CQ-B44) | Pending |
| CORR-02 | Phase 26 | SurrealDB token renewal/reconnect (CQ-B45) | Pending |
| CORR-03 | Phase 26 | Webhook delivery wiring (CQ-B22) | Pending |
| CORR-04 | Phase 26 | Playwright in CI + body assertions (CQ-F36) | Pending |
| CORR-05 | Phase 26 | Tenant context + MFA-setup landing (CQ-F29/F31) | Pending |
| CORR-06 | Phase 26 | Frontend residual correctness (CQ-F19/37/38) | Pending |
| PERF-01 | Phase 27 | HIBP circuit breaker + pre-sizing (T19.26) | Pending |
| PERF-02 | Phase 27 | Concurrent BatchCheckAccess (T19.2/CQ-B20) | Pending |
| PERF-03 | Phase 27 | JWKS single-flight across SDKs (T19.28) | Pending |
| PERF-04 | Phase 27 | SurrealDB reconnect resilience (T19.33/34) | Pending |
| PERF-05 | Phase 27 | Load testing + profiling (T18.3) | Pending |
| FUNC-01 | Phase 28 | Unauthenticated federation login (T19.9) | Pending |
| FUNC-02 | Phase 28 | Session invalidation on reset (T19.10) | Pending |
| FUNC-03 | Phase 28 | Admin email-config API + templates (T19.20/21/22) | Pending |
| FUNC-04 | Phase 28 | Admin user/MFA endpoints + SA token | Pending |
| FUNC-05 | Phase 28 | OpenAPI login response schema (T19.4) | Pending |
| QUAL-01 | Phase 29 | AppState extraction (CQ-B43) | Pending |
| QUAL-02 | Phase 29 | Generic paginate + shared helpers (CQ-B10) | Pending |
| QUAL-03 | Phase 29 | Error taxonomy correctness (CQ-B11/17/18) | Pending |
| QUAL-04 | Phase 29 | Transactional mutations (CQ-B07/46) | Pending |
| QUAL-05 | Phase 29 | PKI helper dedup (CQ-B15) | Pending |
| QUAL-06 | Phase 29 | Frontend shared components (CQ-F15/17/39) | Pending |
| QUAL-07 | Phase 29 | Dead-code cleanup (CQ-B47/27) | Pending |
| CMPL-01 | Phase 30 | Security audit checklist (T18.1) | Pending |
| CMPL-02 | Phase 30 | GDPR completeness (T18.2) | Pending |
| DOCS-01 | Phase 30 | Comprehensive documentation (T18.4) | Pending |

**Coverage: 44/44 v1.2 requirement IDs mapped to Phases 23–30 (100%).** NOTE: the enumerated set totals **44** (SECFIX 6 + SECHRD 12 + CORR 6 + PERF 5 + FUNC 5 + QUAL 7 + CMPL 2 + DOCS 1); the earlier "42" summary undercounted by 2. Roadmap: Phase 23 SECFIX · 24–25 SECHRD · 26 CORR · 27 PERF · 28 FUNC · 29 QUAL · 30 CMPL+DOCS.

---
*v1.2 requirements added 2026-07-03 — final MVP milestone. Consolidates roadmap Phases 18–19 + all open findings from `security-review-postremediation.md` and `code-review-postremediation.md`. Priority: security > correctness > performance > compliance > structural quality > docs.*
