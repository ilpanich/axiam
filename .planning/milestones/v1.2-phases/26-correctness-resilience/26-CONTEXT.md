# Phase 26: Correctness & Resilience - Context

**Gathered:** 2026-07-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix six audit-identified correctness/resilience defects so the control plane,
DB/token layer, webhook delivery, CI, and frontend auth/tenant flows behave
correctly under real conditions:

- **CORR-01** — gRPC governor throughput semantics (throttle inverted to ~1 token/100 s)
- **CORR-02** — SurrealDB root-token renewal / reconnect (4-week TTL is an uptime ceiling)
- **CORR-03** — Webhook delivery wiring through a durable, retrying AMQP path (`.deliver()` has zero call sites)
- **CORR-04** — Playwright actually runs in CI and gates the build (today the "e2e" job runs vitest)
- **CORR-05** — Frontend tenant context restore + MFA-setup landing (no dead end)
- **CORR-06** — Frontend residual correctness (StrictMode double-fire, query-key collision, refocus edit loss)

Requirements are **locked** by ROADMAP.md / REQUIREMENTS.md. This discussion
clarifies HOW to implement them, not WHAT to build. No new capabilities.

**Dependency notes (from REQUIREMENTS.md):**
- SECFIX-03 (webhook secret encrypted at rest) **must precede** CORR-03 decrypt-on-deliver — already landed (SEC-031 decrypt exists in `webhook.rs`).
- SECFIX-06 (reset/resend request bodies) is **verified by** CORR-04's contract-spec body assertions.
- CORR-05 backend (`/auth/me` slugs) precedes the frontend restore.
- PERF-04 (Phase 27) builds reconnect/pool-poisoning resilience on the **same** `crates/axiam-db/src/connection.rs` touched by CORR-02 — keep CORR-02's design forward-compatible with a reconnect hook.

</domain>

<decisions>
## Implementation Decisions

### CORR-01 — gRPC governor throughput
- **D-01:** Correct the quota using `per_millisecond(1000 / authz_per_sec)` (or `Quota::per_second`) with a separate burst. Burst = one second's worth of tokens (= configured `grpc_authz_per_sec`) so short spikes absorb without starving. No separate burst config knob for now.
- **D-02:** The throughput test drives sustained load and asserts sustained throughput ≈ configured rate (proving the ~1/100 s inversion is gone).

### CORR-02 — SurrealDB token renewal / reconnect
- **D-03:** Belt-and-suspenders — implement **both** a proactive periodic re-`signin` background task **and** a reactive reconnect-on-auth-error path. The reactive path is the safety net for missed windows / clock skew and gives PERF-04 a reconnect hook to build on.
- **D-04:** Proactive re-signin interval = a **fraction of the token TTL** (~50–75%, e.g. ~0.6), *derived* from the TTL rather than hardcoded, and config-overridable. Self-adjusts if the TTL changes.
- **D-05:** `health_check` returns **Unhealthy** (readiness alarm) when the token is expired/unrecoverable.

### CORR-03 — Webhook delivery wiring
- **D-06:** Drive the **existing** `WebhookDeliveryService` signer/fetcher (`crates/axiam-api-rest/src/webhook.rs`) from a **durable AMQP queue** instead of the current detached `tokio::spawn` (which dies on restart and is never called). Delivery must survive a broker/consumer restart.
- **D-07:** RabbitMQ topology — a **dedicated webhook exchange/queue**; delayed retries scheduled natively via **per-message TTL + dead-letter-exchange (DLX) requeue**, attempt count carried in message headers; terminal failures land in a **real DLQ** (replayable). No external scheduler; no in-process sleep tying up consumer slots.
- **D-08:** Retry policy — bounded **exponential backoff** (default max attempts ~5) up to a ceiling; on exhaustion, route to the DLQ and write a terminal `failed` audit record.
- **D-09:** Audit granularity — write **per-attempt** records (attempt#, HTTP status/error, next-retry time) **plus** a terminal success/exhausted-failure record.
- **D-10:** Signature — **upgrade to a Stripe-style signed timestamp**. Emit `X-Axiam-Timestamp` and `X-Axiam-Signature: t=<unix>,v1=<hex HMAC-SHA256(timestamp + "." + body)>`, replacing the current body-only `X-Axiam-Signature`. Keep the existing `X-Axiam-Event` and `X-Axiam-Delivery` (delivery-id) headers.
  - ⚠ **Downstream impact:** any webhook-signature verification helpers in the SDKs/docs must be updated to the new `t=,v1=` scheme. Researcher/planner MUST locate and update them (or confirm none exist).

### CORR-04 — Playwright in CI with body assertions
- **D-11:** Wire Playwright into the **existing e2e job** (backend is already seeded there) as a **distinct blocking step** running `npx playwright test` (`frontend` script `test:e2e`), alongside a **separate blocking vitest step** (`vitest run`). Both required; reuse the running seeded backend rather than splitting jobs.
- **D-12:** **All 12 Playwright specs gate the build.** If a spec covers an unfinished feature, fix it or mark it `test.skip` with a tracking note so "green means green." The auth/login/contract specs (incl. SECFIX-06 body assertions) must execute against the seeded backend.
- **D-13:** `playwright-report` artifact reflects real runs (already uploaded in the job).

### CORR-05 — Frontend tenant context & MFA-setup landing
- **D-14:** Backend `/auth/me` (`MeResponse`/`LoginUserInfo`) emits `tenant_slug`/`org_slug`; Topbar restores tenant from those slugs after a hard reload.
- **D-15:** Tenant-restore **degrades gracefully** — if slugs are missing/unresolvable, keep the current fallback (no tenant selected / prompt to pick), never crash. Slugs are an enhancement, not a hard dependency.
- **D-16:** MFA-mandated login (`mfa_setup_required` + `setup_token`) redirects to a **dedicated MFA-setup route** that carries the `setup_token`, calls the setup enrollment endpoint, shows the QR/secret, verifies, then proceeds to the app. Bookmark/refresh-safe; mirrors the reset-password page pattern (avoids the in-memory-token dead end).

### CORR-06 — Frontend residual correctness
- **D-17:** VerifyEmailPage uses a `useRef` once-guard so StrictMode's double-mount doesn't double-fire / show a false "failed" (CQ-F19).
- **D-18:** Dashboard gets a **distinct query key** so `["users",1,""]` no longer collides with UsersPage's different page size (CQ-F37). Exact key shape at implementation discretion.
- **D-19:** Org-settings form — guard init (seed from server only on first load) + track dirtiness so a window refocus / refetch no longer discards in-progress edits, **and additionally** add a warn-on-navigate-away (unsaved-changes) guard when the form is dirty (router-level blocker / `beforeunload`). This is slightly broader than the CQ-F38 minimum but stays within the same form.

### Config knobs (cross-cutting)
- **D-20:** New knobs follow the existing nested `AXIAM__SECTION__KEY` convention, each with a **safe default** and fully overridable (nothing mandatory):
  - `AXIAM__DB__TOKEN_REFRESH_FRACTION` (default ~0.6 of TTL) — CORR-02
  - `AXIAM__WEBHOOK__MAX_ATTEMPTS` (~5) — CORR-03
  - `AXIAM__WEBHOOK__BACKOFF_BASE_MS`, `AXIAM__WEBHOOK__BACKOFF_CEILING_MS` — CORR-03
  - (exact keys/sections to be confirmed against the config module during planning)

### Claude's Discretion
- The Dashboard query-key exact shape (D-18).
- Exact retry attempt/backoff numeric defaults within the ranges above (validate against existing `axiam-amqp` mail-consumer backoff conventions from 25-08 for consistency).
- Whether new webhook config lives under a fresh `[webhook]` section vs an existing one — follow the config module's structure.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & roadmap
- `.planning/REQUIREMENTS.md` §CORR-01…CORR-06 (~lines 807–865) — locked acceptance criteria for every item.
- `.planning/REQUIREMENTS.md` §"dependency graph" (~lines 1061–1063) — SECFIX-03 → CORR-03, SECFIX-06 → CORR-04, CORR-05 backend-before-frontend.
- `.planning/ROADMAP.md` §"Phase 26: Correctness & Resilience" — goal + 5 success criteria.
- `.planning/REQUIREMENTS.md` §SECFIX-06 (~lines 655–662) — the reset/resend request bodies CORR-04's contract spec must assert.

### CORR-01 (gRPC governor)
- `crates/axiam-api-grpc/src/middleware/rate_limit.rs` — governor config (Phase-26 ownership marker already present); `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` is the tuned rate.

### CORR-02 (DB resilience)
- `crates/axiam-db/src/connection.rs` — SurrealDB client connect/signin + `health_check`; also the file PERF-04 (Phase 27) will extend — keep forward-compatible.
- `.planning/phases/13-surrealdb-connection-resilience/13-CONTEXT.md` — prior connection-resilience decisions to stay consistent with.

### CORR-03 (webhook delivery)
- `crates/axiam-api-rest/src/webhook.rs` — **existing** `WebhookDeliveryService` (HMAC-SHA256 signer, `X-Axiam-Signature/Event/Delivery` headers, SSRF-guarded fetch, SEC-031 secret decrypt, in-process backoff). This is what gets driven from AMQP; the signature scheme changes per D-10.
- `crates/axiam-core/src/models/webhook.rs` — `Webhook` model (encrypted `secret` field).
- `crates/axiam-db/src/repository/webhook.rs`, `crates/axiam-api-rest/src/handlers/webhooks.rs` — persistence + registration/rotation.
- `crates/axiam-amqp/` (connection.rs, consumers) — existing exchange/queue + backoff conventions (mail-consumer, 25-08) to mirror for topology/publisher reuse.
- `.planning/phases/25-security-hardening-ii-federation-pki-data-protection-infra/25-CONTEXT.md` — SECHRD-08 AMQP signing + mail-consumer backoff patterns.
- SDK webhook-signature verification helpers (locate in `sdks/`) — must be updated to the D-10 `t=,v1=` scheme, or confirmed absent.

### CORR-04 (CI Playwright)
- `.github/workflows/ci.yml` §`e2e` job (~lines 279–365) — currently runs `npm test` (= `vitest run`); the `npx playwright install chromium` + `playwright-report` upload steps already exist.
- `frontend/package.json` — scripts: `test` = `vitest run`, `test:e2e` = `playwright test`.
- `frontend/e2e/*.spec.ts` (12 specs) — esp. `auth-contract.spec.ts`, `login.spec.ts`, `logout.spec.ts` (body assertions / SECFIX-06).
- `docker/docker-compose.e2e.yml`, `scripts/e2e-bootstrap.sh` — seeded-backend harness the specs run against.

### CORR-05 / CORR-06 (frontend)
- `frontend/src/components/layout/Topbar.tsx` — tenant selection/restore.
- `frontend/src/lib/fetchCurrentUser.ts`, `frontend/src/stores/auth.ts`, `frontend/src/hooks/useAuthInit.ts`, `frontend/src/services/auth.ts` — `/auth/me` consumption, `mfa_setup_required`/`setup_token` handling.
- `frontend/src/pages/LoginPage.tsx`, `frontend/src/pages/VerifyEmailPage.tsx`, `frontend/src/pages/DashboardPage.tsx` — MFA landing origin, StrictMode once-guard, query-key collision.
- `crates/axiam-api-rest/src/handlers/auth.rs` — `MeResponse`/`LoginUserInfo` DTO where `tenant_slug`/`org_slug` are added.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `WebhookDeliveryService` in `crates/axiam-api-rest/src/webhook.rs`: full signer + SSRF-guarded HTTP delivery + backoff already implemented; CORR-03 wires it to a durable queue rather than rewriting it. Zero current call sites — this is the missing link.
- `X-Axiam-Signature/Event/Delivery` header scheme + `compute_signature()` helper: reused (signature body extended to include timestamp per D-10).
- SEC-031 `encrypt_webhook_secret` / decrypt-on-deliver: the SECFIX-03 dependency is already satisfied.
- `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`, `AXIAM__RATE_LIMIT__TRUSTED_HOPS`: existing nested-config precedent for the new D-20 knobs.
- Reset-password page pattern (`?token=&tenant_id=` route): the model for the dedicated MFA-setup route (D-16).
- CI e2e job already seeds the backend and installs Chromium — CORR-04 only needs to swap `npm test`→a blocking `playwright test` step + keep vitest as its own step.

### Established Patterns
- Nested `AXIAM__SECTION__KEY` env config with defaults.
- `axiam-amqp` durable consumers with backoff (audit, mail — 25-08) → topology/backoff template for the webhook consumer.
- Enumeration-safe / constant-response auth flows (SECFIX-06) — the contract spec asserts bodies without weakening this.

### Integration Points
- Webhook registration/emit path → publish to the new AMQP webhook exchange → consumer invokes `WebhookDeliveryService` → audit repository (per-attempt + terminal).
- `connection.rs` re-signin task + reactive path → `health_check` readiness → server health endpoint.
- Backend `/auth/me` slug emission → frontend Topbar/auth store restore.
- `ci.yml` e2e job → `frontend` `test`/`test:e2e` scripts → `playwright-report` artifact.

</code_context>

<specifics>
## Specific Ideas

- Webhook signature explicitly modeled on **Stripe's `t=<unix>,v1=<sig>`** scheme with a dedicated `X-Axiam-Timestamp` header.
- DB re-signin cadence expressed as a **fraction of the TTL** (self-adjusting), not an absolute interval.
- CI: "green means green" — no permanently-red or silently-skipped specs without a tracking note.

</specifics>

<deferred>
## Deferred Ideas

- **PERF-04 (Phase 27):** full-jitter exponential reconnect backoff, `max_backoff` ceiling, bounded retry, and poisoned-connection eviction in `connection.rs` — CORR-02 only adds token renewal + a reconnect hook; the resilient reconnect loop is Phase 27's.
- Webhook replay-window enforcement on the **receiver** side (SDK verification tolerance for `X-Axiam-Timestamp`) — the sender emits the signed timestamp now; SDK/consumer tolerance policy can be tuned later if not already covered when updating SDK helpers.
- Independent gRPC burst config knob (`AXIAM__GRPC__AUTHZ_BURST`) — not added now; burst is derived from the configured rate. Revisit if mesh traffic proves bursty.

None outside phase scope surfaced — discussion stayed within the six CORR items and their direct config/signature implications.

</deferred>

---

*Phase: 26-correctness-resilience*
*Context gathered: 2026-07-04*
