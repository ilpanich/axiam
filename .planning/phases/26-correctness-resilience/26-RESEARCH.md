# Phase 26: Correctness & Resilience - Research

**Researched:** 2026-07-04
**Domain:** Rust/Actix/tonic/SurrealDB/RabbitMQ control-plane correctness, React/TanStack Query frontend correctness, CI/Playwright wiring
**Confidence:** HIGH (all six defects verified directly against the current source tree, dependency source code, and a prior code-review artifact already in-repo; no invented APIs)

## Summary

This phase fixes six previously-identified, narrowly-scoped defects. Every defect
was reproduced/confirmed by reading the actual current source in this session —
none of the fixes below are speculative. The single most important finding,
which materially changes how CORR-01 and CORR-02 must be implemented, is:

1. **CORR-01's "fix" already in the tree is NOT a fix.** The current
   `build_grpc_governor_layer` code (`crates/axiam-api-grpc/src/middleware/rate_limit.rs:160-179`)
   already looks plausible (`.per_second(authz_per_sec as u64).burst_size(authz_per_sec * 2)`)
   but is **still the exact inverted bug**, because `tower_governor`'s
   `GovernorConfigBuilder::per_second(n)` sets the *replenish period* to `n`
   **seconds** (i.e. "one token every n seconds"), not "n tokens per second."
   This is independently confirmed by `claude_dev/code-review-postremediation.md`
   (CQ-B44, marked `❌ OPEN — remediation is wrong, now worse`) and by reading
   the vendored `tower_governor-0.8.0`/`governor-0.10.4` source directly. The
   correct fix must NOT use `tower_governor`'s own `.per_second()`/`.per_millisecond()`
   builder methods as "N per second" — see Pattern 1 below for the exact
   corrected construction.

2. **CORR-02's naive "just re-signin periodically" will not do what it sounds
   like it does**, because of how the SurrealDB Rust SDK's HTTP engine handles
   cloned client handles and auth-header propagation. This is documented in
   detail in Pitfall 2 and the Runtime State Inventory section below — it
   determines the correct shape of the reconnect/re-signin design and what the
   phase's test can and cannot prove.

3. **CORR-03's AMQP DLQ topology precedent already in this codebase
   (`AUDIT_EVENTS`/`AUTHZ_REQUEST`/`MAIL_OUTBOUND`) likely never actually
   dead-letters anything**, because `x-dead-letter-exchange` is set to a
   **queue name**, and no exchange with that name is ever declared anywhere
   in `axiam-amqp`. CORR-03 must NOT copy this pattern verbatim for the new
   webhook DLQ — see Pitfall 4.

4. CORR-04, CORR-05, and CORR-06 are comparatively mechanical: the CI job
   already seeds the backend and serves the built frontend on the exact URL
   Playwright's config expects (`reuseExistingServer: true`), the backend
   DTOs and frontend consumption code for the tenant-slug restore are already
   wired defensively on the frontend side (only the backend `me` handler needs
   two new fields), and the MFA-setup dead end is a well-understood
   router-state-vs-query-param bug with a proven sibling pattern
   (`ResetPasswordPage`) already in the codebase to mirror.

**Primary recommendation:** Fix CORR-01 by NOT using `tower_governor`'s
`per_second`/`per_millisecond` as if they meant "N per second" — construct the
`Quota` via an explicit period-per-token computation (see Pattern 1). Fix
CORR-02 by keeping the periodic re-signin scoped to `DbManager`'s own internal
handle (matching the literal ROADMAP/REQUIREMENTS wording "the SurrealDB
client recovers"), using `invalidate()` before any reactive re-signin attempt,
and explicitly documenting (not silently ignoring) the residual gap that
individual repository `Surreal<Client>` clones each hold an independently
expiring auth session — this is the multi-session gap Phase 27 (PERF-04,
"poisoned-connection eviction") already intends to address, per the existing
CONTEXT.md deferral. Fix CORR-03 by building a **new, self-contained** webhook
exchange/queue/DLQ trio (do not reuse the existing possibly-broken DLX
pattern), and by splitting `WebhookDeliveryService::deliver()`'s current
"loop-with-sleep" design into a single-attempt delivery function invoked once
per AMQP redelivery (the retry *schedule* moves to AMQP TTL+DLX, not
`tokio::time::sleep`).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| gRPC rate-limit quota math (CORR-01) | API/Backend (gRPC middleware) | — | Pure server-side token-bucket config; no client/DB involvement |
| DB auth-token renewal (CORR-02) | Database/Storage (connection layer) | API/Backend (health endpoint) | `DbManager` owns the SurrealDB session; `health_check` surfaces state to the backend's readiness probe |
| Webhook delivery (CORR-03) | API/Backend (producer) + Database/Storage (AMQP consumer process) | — | Emit-time publish is a REST/service-layer concern; durable delivery/retry is an AMQP-consumer concern, same process family as `axiam-server` |
| CI Playwright wiring (CORR-04) | CI/Build tooling | Browser/Client (specs drive the real frontend) | Config-only change; specs already exist and already exercise the browser tier |
| Tenant-context restore (CORR-05a) | API/Backend (`/auth/me` DTO) | Browser/Client (Topbar consumption) | Backend must emit the slugs; frontend already reads them defensively |
| MFA-setup landing (CORR-05b) | Browser/Client (new public route) | API/Backend (existing setup endpoints, no server change needed) | Purely a frontend routing/state-carrying fix; backend endpoints already exist |
| Frontend residual correctness (CORR-06) | Browser/Client | — | StrictMode guard, query-key shape, and form dirty-tracking are all client-side React concerns |

## Package Legitimacy Audit

No new external packages are introduced by this phase. All six fixes use
crates/npm packages already present in the dependency tree
(`governor`/`tower_governor`, `surrealdb`, `lapin`, `hmac`/`sha2`,
`@playwright/test`, `@tanstack/react-query`, `react-router-dom`). No
`npm install` / `cargo add` of a new dependency is required.

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Standard Stack

No new libraries. Confirmed exact in-tree versions relevant to this phase
(via `cargo tree` / vendored registry source, `[VERIFIED: local Cargo registry cache]`):

| Crate | Version | Relevance |
|-------|---------|-----------|
| `governor` | 0.10.4 | Underlying token-bucket `Quota`/`RateLimiter` (CORR-01) |
| `tower_governor` | 0.8.0 | tonic-facing `GovernorLayer`/`GovernorConfigBuilder` wrapper (CORR-01) |
| `surrealdb` | 3.1.5 | HTTP-engine client SDK (CORR-02) |
| `lapin` | (existing, unchanged) | AMQP client (CORR-03) |
| `hmac` / `sha2` | (existing, unchanged) | HMAC-SHA256 signing, already used by `webhook.rs::compute_signature` and `axiam-amqp::messages` (CORR-03) |
| `@playwright/test` | ^1.58.2 | Already a `devDependency`; `frontend/e2e/*.spec.ts` already exist (CORR-04) |
| `@tanstack/react-query` | ^5.95.2 | Query-key collision fix (CORR-06) |
| `react-router-dom` | ^7.13.2 | New public route for MFA-setup (CORR-05) |

**Installation:** none — no new packages this phase.

## Architecture Patterns

### System Architecture Diagram (CORR-03 webhook delivery, the most structurally
new piece of this phase)

```
Domain event occurs (e.g. user.created)
        |
        v
[REST handler / service] --calls--> WebhookDeliveryService::emit(tenant_id, event_type, payload)
        |                                  (NEW: publish-only, replaces today's tokio::spawn body)
        v
  repo.get_by_event(tenant_id, event_type)  -- fetch matching Webhook rows
        |
        v
  for each matching webhook:
    publish 1 message to AMQP exchange "axiam.webhook"
    (routing key = webhook_id; body = {webhook_id, delivery_id, event_type,
     payload, attempt=0}; durable, delivery_mode=2)
        |
        v
  ============ durable AMQP broker (survives process restart) ============
        |
        v
[axiam-webhook-consumer background task, spawned in main.rs like start_mail_consumer]
        |
        v
  decrypt secret -> compute_signature (Stripe-style t=,v1=, D-10)
        |
        v
  ssrf::guarded_fetch(url, ...)  -- SAME guard as today, single attempt only
        |
   +----+----------------------------+
   | success (2xx)                   | failure (network/4xx/5xx, non-SSRF)
   v                                  v
 ack + write per-attempt AUDIT   nack; republish to retry queue with
 "success" record (D-09)         TTL = backoff(attempt) via a SEPARATE
                                  per-attempt retry queue whose
                                  x-dead-letter-exchange points back at
                                  the primary exchange (D-07); attempt++
                                  in message headers; write per-attempt
                                  AUDIT "failed" record (D-09)
                                       |
                                       v
                              attempt > MAX_ATTEMPTS (D-08, default ~5)?
                                       |
                                  yes  v
                       route to axiam.webhook.dlq (real, replayable),
                       write terminal "failed" audit record (D-08/D-09)
```

### Recommended Project Structure (only new/changed files — everything else
in `axiam-amqp`/`axiam-api-rest` is additive to the existing module layout)

```
crates/axiam-amqp/src/
├── webhook_consumer.rs      # NEW — mirrors mail_consumer.rs's shape
├── connection.rs            # ADD: WEBHOOK, WEBHOOK_RETRY, WEBHOOK_DLQ queue
│                             #      consts + a NEW declare_webhook_topology()
│                             #      (do not reuse the plain-DLQ pattern; see
│                             #      Pitfall 4 — needs a real exchange_declare)
crates/axiam-api-rest/src/
├── webhook.rs                # SPLIT deliver() into:
│                             #   - emit() : fetch + publish 1 msg/webhook (no tokio::spawn, no retry loop)
│                             #   - deliver_once() : single HTTP attempt, no sleep, returns Result
│                             #   - compute_signature(): extend for D-10 t=,v1= scheme
crates/axiam-db/src/connection.rs   # CORR-02: proactive re-signin task + reactive reconnect
crates/axiam-api-grpc/src/middleware/rate_limit.rs  # CORR-01: quota construction only
crates/axiam-api-rest/src/handlers/auth.rs          # CORR-05: MeResponse/LoginUserInfo + tenant_slug/org_slug
frontend/src/pages/auth/MfaSetupPage.tsx            # NEW — CORR-05 public route
frontend/src/pages/auth/VerifyEmailPage.tsx         # CORR-06: useRef once-guard
frontend/src/pages/DashboardPage.tsx                # CORR-06: query-key rename
frontend/src/pages/organizations/OrganizationDetailPage.tsx  # CORR-06: init-guard + dirty-tracking (SettingsTab)
.github/workflows/ci.yml                            # CORR-04: add playwright test step
```

### Pattern 1: Correct gRPC governor quota construction (CORR-01)

**What:** `tower_governor::governor::GovernorConfigBuilder::per_second(n)` /
`.per_millisecond(n)` / `.per_nanosecond(n)` all set the internal `period`
field directly (`self.period = Duration::from_secs(n)`, etc. —
`[VERIFIED: tower_governor-0.8.0/src/governor.rs:120-176]`). `finish()` then
builds the quota as `Quota::with_period(self.period).allow_burst(burst_size)`
(`[VERIFIED: tower_governor-0.8.0/src/governor.rs:233-241]`). This means these
builder methods encode **"replenish 1 token every N seconds/ms/ns,"** the
*opposite* of `governor::Quota::per_second(n)` (the underlying crate's own
constructor), which means "N tokens per second" (`[VERIFIED:
governor-0.10.4/src/quota.rs:68-76]`, replenish_interval =
`1_000_000_000ns / n`). The existing in-tree code calls the **tower_governor
builder's** `.per_second(authz_per_sec)`, so it inherits the "period in
seconds" meaning — i.e. with the default `grpc_authz_per_sec = 100`, the
quota replenishes 1 token every 100 seconds (matching the reported "~1
token/100s" bug), and **raising** `grpc_authz_per_sec` makes it slower still.
This exact defect and fix are independently documented in
`claude_dev/code-review-postremediation.md` (CQ-B44).

**When to use:** any time `tower_governor`'s builder is used — never assume
`.per_second(n)` means "n per second."

**Correct fix (D-01):**

```rust
// Source: verified against governor-0.10.4/src/quota.rs + tower_governor-0.8.0/src/governor.rs
use governor::Quota;
use std::num::NonZeroU32;

pub fn build_grpc_governor_layer(authz_per_sec: u32) -> GrpcGovernorLayer {
    assert!(authz_per_sec >= 1, "grpc_authz_per_sec must be >= 1");

    // D-01: burst = one second's worth of tokens = authz_per_sec (not *2).
    let burst = NonZeroU32::new(authz_per_sec).expect("authz_per_sec >= 1 asserted above");

    // Build the underlying governor::Quota directly (bypassing
    // tower_governor's confusing per_second/per_millisecond builder methods
    // entirely) so "N tokens per second" is unambiguous:
    let quota = Quota::per_second(burst); // replenish_interval = 1s / authz_per_sec, burst = authz_per_sec

    let config = Arc::new(
        GovernorConfigBuilder::default()
            .const_period(quota.replenish_interval())   // or .period(...)
            .const_burst_size(quota.burst_size().get())
            .key_extractor(GrpcTrustedHopsKeyExtractor::new(trusted_hops_from_env()))
            .finish()
            .expect("valid GovernorConfig for gRPC rate limiter"),
    );

    GovernorLayer::new(config)
}
```

If the planner instead prefers to stay literally inside `tower_governor`'s
builder API (per the acceptance-criterion wording `per_millisecond(1000 /
authz_per_sec)`), the arithmetic must guard against **integer-division
truncation to zero** when `authz_per_sec > 1000` (`1000 / authz_per_sec == 0`
→ `Duration::from_millis(0)` → `finish()` returns `None` — the existing
`.expect("valid GovernorConfig...")` would then **panic at startup**). Prefer
`.per_nanosecond(1_000_000_000u64 / authz_per_sec as u64)` for headroom (valid
for any `authz_per_sec` up to 1e9), or use the `governor::Quota::per_second`
route above, which has no such truncation hazard since it computes the
interval in nanoseconds internally with an `NonZeroU32` guard already in
place.

### Pattern 2: SurrealDB proactive re-signin without the "signin-on-expired-handle" trap (CORR-02)

**What:** The existing `connection.rs` comment ("Re-`signin` on an
already-authenticated handle is itself rejected with 401") is accurate for
the **reactive** (already-expired) case, and is explained precisely by the
HTTP-engine transport code: every request (including `Signin` and
`Invalidate` themselves) attaches the **currently cached** auth header via
`Authenticate for RequestBuilder` (`[VERIFIED:
surrealdb-3.1.5/src/engine/remote/http/mod.rs:411-439,600-645]`), and
`send_request` calls `.error_for_status()` before ever inspecting the RPC
body (`[VERIFIED: same file, lines 621-627]`). If the currently-cached bearer
token is already expired, **every** subsequent request on that same
`Surreal<Client>` handle — `Signin`, `Invalidate`, and ordinary queries alike
— fails at the HTTP-transport layer before the server-side RPC dispatcher
ever runs. This means:

- **Proactive path (D-03/D-04) works cleanly**: re-`signin` *before* the
  cached token actually expires. The still-valid token authorizes the
  `Signin` request itself; `Command::Signin`'s handler
  (`[VERIFIED: mod.rs:779-826]`) then overwrites `session_state.auth` with
  the new token — no `invalidate()` needed, no panic risk.
- **Reactive path (the "missed window" safety net, D-03) must call
  `db.invalidate()` FIRST** — but even `invalidate()`'s own request also
  carries the stale auth header and is subject to the same
  `.error_for_status()` gate (`[VERIFIED: mod.rs:909-925]`), so if the token
  is **already** expired by the time the reactive path runs, `invalidate()`
  will *also* 401. **The only way to truly recover from an already-expired
  token via this SDK version's HTTP engine is to build a brand-new
  `Surreal<Client>` connection (fresh `Surreal::new::<Http>(...)` + fresh
  anonymous session) and re-authenticate on it — not to call any method on
  the stale handle.** Document this explicitly rather than attempting
  `invalidate()`-then-`signin()` on an already-401ing handle and treating a
  resulting error as "recovery didn't work" — it is expected to fail by
  design of the transport layer, and the reactive path's job is narrower:
  catch the auth-failure signal from a query and trigger a **reconnect**
  (new connection), not an in-place re-auth.

**Derive the interval from the TTL, don't hardcode either:**

```rust
// Source: pattern only; TTL const already exists in connection.rs as a
// SurrealQL string literal ("4w"). Represent it as a real Duration so both
// the DEFINE USER statement AND the re-signin interval derive from ONE
// source of truth (avoids needing a "4w"-style duration-string parser —
// none exists in this codebase; humantime/similar is not a dependency).
const ROOT_TOKEN_DURATION: Duration = Duration::from_secs(4 * 7 * 24 * 3600); // 4 weeks

fn root_token_duration_surql_literal() -> String {
    format!("{}s", ROOT_TOKEN_DURATION.as_secs()) // SurrealQL accepts a bare "<n>s" duration literal
}

fn re_signin_interval(fraction: f64) -> Duration {
    // D-04: fraction is config-overridable (AXIAM__DB__TOKEN_REFRESH_FRACTION, default ~0.6)
    Duration::from_secs_f64(ROOT_TOKEN_DURATION.as_secs_f64() * fraction.clamp(0.05, 0.95))
}
```

### Pattern 3: Splitting webhook delivery into emit + single-attempt-deliver (CORR-03)

```rust
// Source: pattern derived from current webhook.rs (retained) + mail_consumer.rs's
// consumer-loop shape (retained). The per-attempt retry-loop-with-sleep in the
// CURRENT deliver() is removed; AMQP TTL+DLX now owns retry scheduling (D-07).
impl<W: WebhookRepository + Clone + 'static> WebhookDeliveryService<W> {
    /// Replaces the old `deliver()`: fetch matching webhooks, publish ONE
    /// AMQP message per webhook. No tokio::spawn, no retry loop, no sleep.
    pub async fn emit(&self, publisher: &WebhookPublisher, tenant_id: Uuid,
                       event_type: String, payload: serde_json::Value) { /* ... */ }

    /// Invoked by the AMQP consumer, once per (re)delivery. No internal
    /// retry loop — returns Ok/Err for the CONSUMER to decide ack/nack.
    pub async fn deliver_once(&self, webhook_id: Uuid, delivery_id: Uuid,
                               event_type: &str, payload: &serde_json::Value)
        -> Result<StatusCode, WebhookError> { /* single ssrf::guarded_fetch call, no loop */ }
}
```

### Pattern 4: Stripe-style signed-timestamp header (CORR-03/D-10)

```rust
// Source: pattern only (Stripe's public webhook-signing scheme is
// well-documented prior art; [ASSUMED] — not verified against Stripe's own
// docs in this session, but the target format is explicitly specified by
// D-10 in 26-CONTEXT.md, so this is a locked decision, not a research
// judgment call).
fn compute_signature_v2(secret: &str, timestamp: i64, body: &str) -> String {
    let signed_payload = format!("{timestamp}.{body}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(signed_payload.as_bytes());
    format!("t={timestamp},v1={}", hex::encode(mac.finalize().into_bytes()))
}
// Headers: X-Axiam-Timestamp: <timestamp>, X-Axiam-Signature: t=<timestamp>,v1=<hex>
// X-Axiam-Event / X-Axiam-Delivery unchanged (still set from event_type / delivery_id).
```

**No SDK-side verification helper exists to update.** Confirmed by
`grep -rn` across `sdks/` for `X-Axiam-Signature`, `WebhookSignature`,
`verify_webhook`/`verifyWebhook`, `webhook_signature`: the only hits are in
`sdks/openapi.json` (the webhook CRUD *schema* — `POST/GET/PUT/DELETE
/webhooks`, response/request bodies — nothing about signature
verification). **No SDK (Rust/TS/Go/Python/Java/C#/PHP) implements a
`verify_webhook`-style helper today** — the D-10 downstream-impact warning in
CONTEXT.md is satisfied by explicitly recording "confirmed absent" rather
than needing an update.

### Pattern 5: MFA-setup landing route (CORR-05b)

Mirror `ResetPasswordPage`'s existing `?token=&tenant_id=` query-param
pattern exactly — `router.tsx` already registers `/auth/reset-password` and
`/auth/verify-email` as **top-level siblings** of the `/` (`AppLayout`) tree
(`[VERIFIED: frontend/src/router.tsx:50-58]`), so they never pass through
`AppLayout`'s `if (!isAuthenticated) return <Navigate to="/login" replace />`
guard (`[VERIFIED: frontend/src/components/layout/AppLayout.tsx:21]`) — this
is exactly why the current `/profile/mfa` navigation dead-ends (it IS nested
under `/`, so an unauthenticated setup-token carrier gets redirected to
`/login` before ever reaching the page). Add `/auth/mfa-setup` as a new
top-level sibling route in the same list.

**`TotpSetupDialog` cannot be imported by the new page as-is** — it is a
private (non-exported) function component defined inside
`frontend/src/pages/profile/MfaManagementPage.tsx`
(`[VERIFIED: grep confirms no separate TotpSetupDialog.tsx file exists]`).
The UI-SPEC calls for reusing its **inner QR/secret/code-input presentation**
inlined as a page body, not its modal chrome (there's no authenticated shell
to host a dialog over). Two viable approaches, either satisfies the UI-SPEC:
(a) extract the QR+secret+code-input JSX (lines ~153-226 of
`MfaManagementPage.tsx`) into a small shared presentational component
imported by both files, or (b) duplicate the markup into the new page. Given
this phase's narrow, correctness-only scope and to minimize blast radius on
the already-working `MfaManagementPage.tsx`, (a) is the cleaner
recommendation, but either satisfies the visual/interaction contract.

**Success-path tenant-context caveat:** `LoginPage.handleMfaSubmit`'s
existing success path calls `setTenantContext(orgTenantData.tenantSlug,
orgTenantData.orgSlug)` using slugs the user typed into the login form
itself (`[VERIFIED: frontend/src/pages/LoginPage.tsx:169]`) — that ambient
form context does **not exist** on the standalone `/auth/mfa-setup` route.
The new page's success handler must instead rely on `fetchCurrentUser()`'s
own `tenantSlug`/`orgSlug` fields (already read defensively —
`fetchCurrentUser.ts:30-31`), which in turn depend on the CORR-05a backend
`/auth/me` fix landing first. This is consistent with the already-documented
dependency ("CORR-05 backend precedes frontend restore") but is worth
calling out explicitly for the MFA-setup page's success handler too, not
just the Topbar restore.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Token-bucket rate limiting | A custom counter/refill loop | `governor::Quota` (already a dependency) — just construct it correctly (Pattern 1) | The bug is a construction-site mistake, not a missing capability |
| AMQP delayed retry | An external scheduler, cron, or in-process `sleep` loop | Native RabbitMQ **per-message TTL + dead-letter-exchange (DLX)** requeue (D-07) | AMQP already supports this natively; sleeping in a consumer loop blocks that consumer slot for the whole delay (exactly the anti-pattern the mail-consumer's own doc comments flag as a "single-consumer throughput tradeoff," `[VERIFIED: mail_consumer.rs:34-45]`) |
| Stripe-style signature | A bespoke signature envelope | `t=<unix>,v1=<hex hmac>` (D-10, industry-standard shape) | Widely-implemented pattern; keeps parity with what most webhook consumers already expect |
| Duration-string parsing ("4w") | A hand-rolled SurrealQL-duration parser | Represent the TTL as a plain `std::time::Duration` Rust constant and derive the SurrealQL literal string FROM it (Pattern 2) | No duration-string-parsing crate is a dependency; parsing "4w" back out is unnecessary work when the constant can just live as a `Duration` |
| CI test runner glue | A custom test-orchestration script | `npx playwright test` as its own CI step, `vitest run` as its own step (D-11) | `playwright.config.ts` already has `reuseExistingServer: true` and reads `E2E_BASE_URL` — no new plumbing needed, just add the missing step |

**Key insight:** every one of these six defects is a **wiring/construction
mistake** against an already-correct or already-present underlying mechanism
(governor's own `Quota::per_second`, SurrealDB's `signin`/`invalidate`
primitives, RabbitMQ's native DLX, Stripe's public signature convention,
Playwright's already-configured server-reuse, React's `useRef` idiom already
used correctly elsewhere in this exact codebase). None of the six fixes
requires inventing new machinery.

## Runtime State Inventory

This phase is a correctness/resilience fix set, not a rename/rebrand/migration.
No stored data, live-service config, OS-registered state, or secrets are
renamed or relocated by any of the six fixes. The one item worth flagging
explicitly:

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — no table/collection/key renames in this phase | none |
| Live service config | **The existing RabbitMQ AMQP topology's DLQ wiring for `AUDIT_EVENTS`/`AUTHZ_REQUEST`/`MAIL_OUTBOUND` (declared in `crates/axiam-amqp/src/connection.rs::declare_queues`) sets `x-dead-letter-exchange` to a **queue name**, but no exchange with that name is ever declared anywhere in this codebase (`grep -rn "exchange_declare"` across `axiam-amqp` returns zero hits).** Per RabbitMQ's documented DLX semantics, a `x-dead-letter-exchange` value naming a non-existent exchange causes dead-lettered messages to be **silently dropped**, not routed to the named queue, unless the empty-string default exchange + `x-dead-letter-routing-key` form is used instead. **This is out of this phase's locked scope to fix (CORR-03 only requires a NEW, self-contained webhook topology) but the planner MUST NOT copy the existing pattern for the new webhook DLQ** — see Pitfall 4. Flagging here because it is exactly the kind of "silent, no-error" runtime-state gap this inventory step exists to catch. | Use the correct DLX form for the NEW webhook topology only (code change, not data migration); flag the pre-existing queues as an out-of-scope known-gap for a future phase, do not silently assume they work |
| OS-registered state | None | none |
| Secrets/env vars | None renamed. New env vars are additive: `AXIAM__DB__TOKEN_REFRESH_FRACTION`, `AXIAM__WEBHOOK__MAX_ATTEMPTS`, `AXIAM__WEBHOOK__BACKOFF_BASE_MS`, `AXIAM__WEBHOOK__BACKOFF_CEILING_MS` | Add with safe defaults per D-20; no existing var renamed |
| Build artifacts | None | none |

## Common Pitfalls

### Pitfall 1: Trusting `tower_governor`'s `.per_second()`/`.per_millisecond()` naming
**What goes wrong:** Assuming these builder methods mean "N per second"/"N
per millisecond" (as `governor::Quota::per_second` does) when they actually
set the **replenish period** (`[VERIFIED: tower_governor-0.8.0/src/governor.rs:120-176]`).
**Why it happens:** The method names are a deliberate but confusing mirror of
`governor::Quota`'s OWN constructor names, which have the opposite meaning.
**How to avoid:** Either bypass the builder's convenience methods entirely
and construct via `governor::Quota::per_second(NonZeroU32)` +
`.const_period()`/`.const_burst_size()`, or use `per_nanosecond(1_000_000_000
/ authz_per_sec)` with the truncation guard noted in Pattern 1.
**Warning signs:** A rate-limit test that asserts sustained throughput ≈
configured rate is the only reliable warning sign — a naive "does it
compile and not immediately reject the first request" smoke test looks
identical whether the bug is present or fixed (both allow the initial burst
through).

### Pitfall 2: Assuming a re-signin on one `Surreal<Client>` clone reaches all clones
**What goes wrong:** `Surreal<C>::clone()` mints a **new session_id** and
copies the CURRENT auth/header state as a **value snapshot** into an
independent `SessionState` entry (`[VERIFIED:
surrealdb-3.1.5/src/lib.rs:336-346` + `src/engine/remote/http/mod.rs:137-251`,
specifically `handle_session_clone`/`SessionState::clone_state`]`). Every
repository in `crates/axiam-server/src/main.rs` is constructed via
`db.client().clone()` (~30 call sites), each becoming an **independently
authenticated session** on the server. A periodic re-signin task that only
touches `DbManager`'s own internally-held handle updates only that ONE
session — it does not (and structurally cannot, without a broader
Arc-indirection refactor across every repository's field type) refresh the
other ~30 already-cloned sessions used by the rest of the app.
**Why it happens:** The HTTP engine's per-session auth state is a value
copy, not a shared `Arc`/`RwLock` cell across clones — only the underlying
`reqwest::Client`/background router task is genuinely shared.
**How to avoid:** For THIS phase (narrowly scoped to `connection.rs` per
CONTEXT.md D-03..D-05), scope the re-signin/reconnect design and its test to
`DbManager`'s own handle — this matches the literal ROADMAP wording ("the
SurrealDB client recovers... without a process restart") and satisfies
`health_check`'s readiness-alarm requirement (D-05), since `health_check`
already queries via that same DbManager-owned handle. Explicitly document
(in the plan/code comments, not just here) that the other ~30 repository
clones each hold an independently-expiring session and are NOT covered by
this fix — this residual gap is the same shape of problem
"PERF-04 (Phase 27): ... poisoned-connection eviction" is already deferred to
address (per 26-CONTEXT.md's Deferred Ideas), so flagging it (not silently
fixing or silently ignoring it) is the correct scope boundary for this phase.
**Warning signs:** A test that only exercises `DbManager::health_check()`
directly will pass even though a real deployment's repository-level queries
would still 401 after the shared initial token expires — don't let a
green CORR-02 test create false confidence about the whole app's resilience.

### Pitfall 3: Reactive re-signin via `invalidate()` on an already-expired handle
**What goes wrong:** Calling `db.invalidate()` then `db.signin()` on a
handle whose cached bearer token has ALREADY expired does not recover it —
`invalidate()`'s own network request carries the stale auth header and is
rejected by the same `.error_for_status()` gate before the local auth state
is ever cleared (`[VERIFIED: surrealdb-3.1.5/src/engine/remote/http/mod.rs:909-925,621-627]`).
**Why it happens:** The HTTP engine attaches the CURRENTLY cached auth header
to every outgoing request, including auth-lifecycle commands themselves.
**How to avoid:** The proactive path (re-signin at a fraction of TTL, D-04)
is what actually protects the DbManager handle in the normal case — it
succeeds because the token is still valid at that point. The reactive path's
realistic job is: on detecting an auth failure from an ordinary query,
**build an entirely new connection** (`DbManager::connect` again) rather
than trying to resuscitate the existing handle in place.
**Warning signs:** A reactive-path test that manually expires the token
in-place and then calls `invalidate()` + `signin()` on the SAME handle and
expects success will itself fail (correctly reproducing the transport-layer
gate) — don't mistake that as a test bug; it's proof of why the reactive
path must reconnect via a fresh connection instead.

### Pitfall 4: Copying the existing AMQP DLQ pattern for the new webhook queue
**What goes wrong:** The existing `declare_queues()` sets
`x-dead-letter-exchange` to a **queue name** (e.g.
`"axiam.mail.outbound.dlq"`) with no matching `exchange_declare` anywhere in
the crate (`[VERIFIED: grep -rn "exchange_declare" crates/axiam-amqp` → zero
hits]`). By RabbitMQ's documented DLX semantics `[ASSUMED — standard
RabbitMQ behavior, not verified against a live broker in this session]`, a
`x-dead-letter-exchange` argument naming a non-existent exchange causes
dead-lettered messages to be silently dropped, not routed anywhere.
**Why it happens:** It's easy to conflate "the default (nameless) exchange
routes by queue name" with "any string in `x-dead-letter-exchange` behaves
the same way" — it does not; only the empty string `""` gets that implicit
per-queue-name routing.
**How to avoid:** For the NEW webhook topology (D-07), either (a) declare a
real named DLX exchange (`exchange_declare("axiam.webhook.dlx", Direct,
durable)`) and bind the DLQ queue to it with the routing key the primary
queue's `x-dead-letter-routing-key` will use, or (b) set
`x-dead-letter-exchange` to `""` (the default exchange) and
`x-dead-letter-routing-key` to the literal DLQ queue name — the simpler,
well-known-correct pattern. Recommend (b) for minimal new surface area.
**Warning signs:** A "does declare_queues() succeed" smoke test proves
nothing here — RabbitMQ accepts an `x-dead-letter-exchange` argument naming
a not-yet-existing exchange without error at declare time; the failure is
silent and only observable by actually forcing a message to dead-letter and
checking whether it lands in the DLQ (an integration test against a live
broker, e.g. via `just dev-up`, or the RabbitMQ management HTTP API).

### Pitfall 5: In-process sleep retry loop tying up an AMQP consumer slot
**What goes wrong:** Porting `WebhookDeliveryService::deliver()`'s current
`tokio::time::sleep` retry loop unchanged into the new AMQP consumer (mirroring
`mail_consumer.rs`'s own sleep-based backoff) would tie up a consumer/prefetch
slot for the full backoff duration on every failing delivery, serializing a
burst of failing webhooks through one consumer — `mail_consumer.rs`'s own doc
comment explicitly flags this exact tradeoff as accepted for mail only
(`[VERIFIED: mail_consumer.rs:34-45]`). D-07 explicitly rules this out for
webhooks ("No external scheduler; no in-process sleep tying up consumer
slots").
**Why it happens:** It's the path of least resistance to copy the
nearest-neighbor pattern in the codebase.
**How to avoid:** Schedule the delay via a **separate retry queue** with a
per-message TTL (`x-message-ttl`) set to the computed backoff delay and
`x-dead-letter-exchange` pointing back at the primary exchange — the message
sits in the retry queue for the TTL duration with **zero consumer attached**
(no slot held), then RabbitMQ automatically dead-letters it back to the
primary queue for redelivery once the TTL expires.
**Warning signs:** If the plan's consumer code contains a `tokio::time::sleep`
call anywhere in the webhook consumer's hot path, it has reintroduced this
exact anti-pattern.

### Pitfall 6: React Query key collision looks like a UI bug, not a cache bug
**What goes wrong:** `DashboardPage`'s stat-card query
(`["users", 1, ""]`) and `UsersPage`'s page-1/no-filter query
(also `["users", 1, ""]`) are structurally identical cache keys
(`[VERIFIED: DashboardPage.tsx:186` + `UsersPage.tsx:228]`) even though they
call `userService.list()` with different `limit` arguments (1 vs 20) —
TanStack Query's cache key does not encode the query FUNCTION's arguments
beyond what's explicitly in the key array.
**Why it happens:** Both queries happen to reduce to the same
`[entity, page, search]` shape even though they serve different purposes
(a total-count probe vs. a real paginated list).
**How to avoid:** Give the count-only query a key shape that can never
collide structurally with `["users", page, search]` (D-18) — e.g.
`["users", "dashboard-count"]`. Don't just change the `limit` value passed
to `userService.list()` while leaving the key unchanged; the FUNCTION
argument is irrelevant to TanStack Query's cache identity.
**Warning signs:** Navigating Dashboard → Users → Dashboard and seeing a
"1" on either page's count is the acceptance-visible symptom already called
out in 26-UI-SPEC.md.

## Code Examples

### VerifyEmailPage StrictMode once-guard (CORR-06/D-17)

```typescript
// Source: pattern lifted directly from this codebase's OWN proven fix,
// frontend/src/hooks/useAuthInit.ts:16-39 (already handles this exact
// StrictMode double-invoke class of bug correctly) — do not invent a new
// pattern, reuse this one verbatim.
const verifiedRef = useRef(false);

useEffect(() => {
  if (!token || !tenantId) return;
  if (verifiedRef.current) return; // StrictMode's second mount is a no-op
  verifiedRef.current = true;

  async function doVerify() {
    setVerifyState("loading");
    try {
      await authService.verifyEmail(tenantId!, token!);
      window.history.replaceState({}, document.title, window.location.pathname);
      setVerifyState("success");
    } catch (err) {
      window.history.replaceState({}, document.title, window.location.pathname);
      const axiosErr = err as AxiosError<ErrorResponse>;
      const msg = axiosErr.response?.data?.message ?? axiosErr.response?.data?.error
        ?? "Verification failed. The link may be expired or already used.";
      setErrorMessage(msg);
      setVerifyState("error");
    }
  }

  doVerify();
  // No cleanup-based `cancelled` flag — the ref guard IS the de-dup
  // mechanism; a cleanup-based cancellation here reintroduces the exact bug
  // useAuthInit.ts's own comments warn against (see useAuthInit.ts:30-37).
}, [token, tenantId]);
```

### `/auth/me` tenant_slug/org_slug emission (CORR-05a backend)

```rust
// Source: pattern only, following the exact existing `me` handler shape
// (crates/axiam-api-rest/src/handlers/auth.rs:618-667). AuthenticatedUser
// already carries `org_id: Uuid` (`[VERIFIED: extractors/auth.rs:76-85]`);
// Tenant/Organization models already have a `slug: String` field
// (`[VERIFIED: axiam-core/src/models/tenant.rs:23, organization.rs:21]`).
pub struct LoginUserInfo {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub tenant_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_slug: Option<String>,
}

pub async fn me<C: Connection>(
    user: AuthenticatedUser,
    user_repo: web::Data<SurrealUserRepository<C>>,
    role_repo: web::Data<SurrealRoleRepository<C>>,
    permission_repo: web::Data<SurrealPermissionRepository<C>>,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,       // NEW
    org_repo: web::Data<SurrealOrganizationRepository<C>>,    // NEW
) -> Result<HttpResponse, AxiamApiError> {
    // ...existing user/roles/permissions logic unchanged...
    // D-15: degrade gracefully — a lookup failure must NOT fail the whole /me call.
    let tenant_slug = tenant_repo.get_by_id(user.tenant_id).await.ok().map(|t| t.slug);
    let org_slug = org_repo.get_by_id(user.org_id).await.ok().map(|o| o.slug);
    Ok(HttpResponse::Ok().json(MeResponse {
        user: LoginUserInfo { id: user.user_id, username: u.username, email: u.email,
                              tenant_id: user.tenant_id, tenant_slug, org_slug },
        permissions,
    }))
}
```

Also add the same two fields to `cookie_response_from_output`'s
`LoginUserInfo` construction (`handlers/auth.rs:209-218`) so the fresh-login
path populates slugs immediately too (not just the post-reload `/me` path) —
`LoginPage`'s own success handler already calls `fetchCurrentUser()` right
after login in the MFA branch, so consistency between both paths avoids a
"works after reload but not on fresh login" split-brain bug.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `tower_governor` builder's `.per_second()` used as "N/sec" | Construct `governor::Quota` directly, or use `.per_nanosecond()` with a truncation guard | This phase (CORR-01) | Removes both the original 1 req/s bug AND its "fixed" 1/100s regression |
| Webhook delivery via detached `tokio::spawn` with in-process sleep retry | AMQP-durable publish + TTL/DLX-scheduled redelivery | This phase (CORR-03) | Survives process restart; no consumer-slot starvation |
| CI "e2e" job running `vitest run` under the `e2e` job name | `npx playwright test` as its own blocking step, `vitest run` kept separate | This phase (CORR-04) | 12-13 previously-dormant Playwright specs finally gate merges |

**Deprecated/outdated:** none — no library APIs are being deprecated by this
phase; all changes are internal wiring corrections.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | RabbitMQ silently drops (rather than errors at declare-time or falls back) when `x-dead-letter-exchange` names a non-existent exchange | Pitfall 4, Runtime State Inventory | If wrong, the existing AUDIT_EVENTS/AUTHZ_REQUEST/MAIL_OUTBOUND DLQs might already work fine and this flag is a false alarm — low risk either way since CORR-03 is told to build a NEW, self-contained (and correctly-wired) topology regardless, not to fix the old one |
| A2 | Stripe's public `t=<unix>,v1=<hex>` signature format is the exact literal shape D-10 wants | Pattern 4 | Low risk — this is a locked decision (D-10) quoting the format verbatim in CONTEXT.md, not a researched judgment call |
| A3 | Extracting the QR/secret/code-input JSX from `MfaManagementPage.tsx`'s private `TotpSetupDialog` into a shared component (vs. duplicating markup) is the preferred approach | Pattern 5 | Low risk — both approaches satisfy the UI-SPEC; this is a Claude's-discretion implementation choice, not a locked decision |
| A4 | 13 Playwright spec files currently exist, not the 12 CONTEXT.md/REQUIREMENTS.md describe | CORR-04 findings (see Open Questions) | Low risk — the exact count doesn't change the D-11/D-12 fix; the planner should just verify all files at execution time, not assume 12 |

**If this table is empty:** N/A — see entries above; none of them threaten
the core fixes' correctness, all are low-risk/no-decision-impact notes.

## Open Questions

1. **13 vs. 12 Playwright specs**
   - What we know: `frontend/e2e/*.spec.ts` currently contains 13 files
     (`auth-contract, certificates, dashboard, federation, identity, login,
     logout, organizations, roles, service-accounts, settings, tenants,
     users`), not the 12 CONTEXT.md/REQUIREMENTS.md describe.
   - What's unclear: whether a spec was added since the count was
     established, or whether one of these 13 is expected to be
     removed/merged.
   - Recommendation: the planner should enumerate the actual file list at
     plan time (not hardcode "12") and verify each spec against a running
     seeded backend per D-12, marking any genuinely broken one with
     `test.skip` + a tracking note rather than assuming a fixed count.

2. **Whether the pre-existing DLX gap (Pitfall 4/A1) needs a follow-up issue**
   - What we know: the pattern used for `AUDIT_EVENTS`/`AUTHZ_REQUEST`/
     `MAIL_OUTBOUND` DLQs appears structurally unable to route dead-lettered
     messages (no exchange of that name is ever declared).
   - What's unclear: whether this was already caught/fixed in a phase after
     the one that introduced it (25-08's mail-consumer references "D-14
     explicit dead-letter routing, no broker defaults" per STATE.md, which
     suggests awareness of dead-letter routing generally, but the specific
     exchange-vs-queue-name distinction may not have been tested against a
     live broker).
   - Recommendation: out of this phase's scope to fix; recommend the
     planner file a follow-up tracking note (not a blocking task) so a
     future phase verifies it against a live RabbitMQ instance.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Live SurrealDB server (HTTP engine) | CORR-02 test (simulating real token expiry requires a live server — `DbManager` is hardcoded to the HTTP engine, not generic over `Connection`, so `kv-mem` cannot substitute) | not probed this session (docker `just dev-up` pattern already documented in justfile/Phase 13 CONTEXT) | n/a | If unavailable at execution time, the reactive-reconnect logic can still be unit-tested via a mocked/injected error path; the true end-to-end "recovers after real expiry" proof needs `just dev-up` |
| Live RabbitMQ broker | CORR-03 integration test (DLX wiring, per Pitfall 4, cannot be verified via a smoke test alone) | not probed this session (docker compose services already exist per `docker/docker-compose.e2e.yml`) | n/a | Unit-test the retry/backoff math and signature format without a broker; gate the true DLX-routing proof behind a live-broker integration test |
| `npx playwright install chromium` | CORR-04 | already a CI step (`ci.yml:330-332`) | n/a | none needed — already present |

**Missing dependencies with no fallback:** none identified — all can be
addressed with existing `just dev-up`/CI infrastructure already documented
in this repo.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Backend framework | `cargo test` (built-in), per-crate scoped per CLAUDE.md build-hygiene rules |
| Frontend unit framework | `vitest` 4.1.8, config via `frontend/vite.config.ts`/`vitest` defaults |
| Frontend e2e framework | `@playwright/test` 1.58.2, config `frontend/playwright.config.ts` (already correctly wired to reuse a running server + `E2E_BASE_URL`) |
| Quick run command (backend) | `cargo test -p axiam-api-grpc --lib rate_limit` / `-p axiam-db --lib` / `-p axiam-amqp --lib` |
| Full suite command | `cargo test --workspace` (end-of-phase gate only, per disk-hygiene rules) |
| Quick run command (frontend) | `npm run lint && npx tsc -b --noEmit` (fast) |
| Full e2e command | `npm run build && npx playwright test` against a seeded backend |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CORR-01 | Raising `grpc_authz_per_sec` increases sustained throughput; governor no longer inverted | unit (sustained-load simulation against `build_grpc_governor_layer`) | `cargo test -p axiam-api-grpc --lib rate_limit -- --nocapture` | ❌ Wave 0 — add a throughput-assertion test to `rate_limit.rs`'s existing `#[cfg(test)] mod tests` |
| CORR-02 | Client recovers after root-token expiry without process restart; `health_check` surfaces auth-expiry as unhealthy | integration (requires live SurrealDB, short-TTL override) | `just dev-up && cargo test -p axiam-db --test connection_resilience_test -- --ignored` (or similar, live-broker-gated) | ❌ Wave 0 — new test file; needs a way to override `ROOT_TOKEN_DURATION` for a short test-only TTL |
| CORR-03 | Signed delivery via durable AMQP; failed delivery retries with backoff; audit trail written | integration (requires live RabbitMQ), plus unit tests for signature/backoff math | `cargo test -p axiam-api-rest --lib webhook` (unit) + `just dev-up && cargo test -p axiam-amqp --test webhook_consumer_test -- --ignored` (integration) | ❌ Wave 0 — both new |
| CORR-04 | Playwright actually runs in CI and gates the build; contract spec asserts bodies | CI job change + existing e2e specs | `npx playwright test` (already scriptable via `npm run test:e2e`) | ✅ specs exist; ❌ CI wiring (Wave 0: add the step) |
| CORR-05 | Tenant restore after hard reload; MFA-setup landing has no dead end | e2e (Playwright) + backend unit test for `/auth/me` slug emission | `cargo test -p axiam-api-rest --lib handlers::auth` (unit) + a new/extended Playwright spec | ❌ Wave 0 — new/extended spec for tenant-restore-after-reload and MFA-setup-landing flows |
| CORR-06 | VerifyEmail no false-fail under StrictMode; Dashboard/Users no cache collision; org-settings no discard-on-refocus | vitest component tests + Playwright | `npm run test` (vitest) targeted at the three components/pages | ❌ Wave 0 — add targeted vitest tests for the query-key shape and the dirty-tracking guard |

### Sampling Rate
- **Per task commit:** the scoped `cargo test -p <crate> --lib` / `npm run test -- <file>` for whichever component that task touches.
- **Per wave merge:** `cargo test --workspace` is expensive (disk-hygiene rules apply — run `cargo clean` between plan steps) and should be reserved for the phase-gate; per-wave, run the per-crate scoped tests for every crate touched in that wave.
- **Phase gate:** full `cargo test --workspace` (Rust) + `npm run lint && npx tsc -b && npm run test && npx playwright test` (frontend, against the CI-style seeded backend) green before `/gsd-verify-work`.

### Wave 0 Gaps
- [ ] `crates/axiam-api-grpc/src/middleware/rate_limit.rs` — add a sustained-throughput assertion test (CORR-01)
- [ ] `crates/axiam-db/tests/connection_resilience_test.rs` (or similar) — new, live-SurrealDB-gated, covers CORR-02's re-signin/reconnect/health_check behavior; needs a way to inject a short test-only token TTL (the current `ROOT_TOKEN_DURATION` is a private module constant — plan must decide whether to make it configurable for tests, e.g. via a `DbConfig` field or `#[cfg(test)]` override)
- [ ] `crates/axiam-amqp/tests/webhook_consumer_test.rs` (or similar) — new, live-RabbitMQ-gated, proves TTL+DLX retry scheduling and terminal DLQ routing actually work (directly exercises the Pitfall 4 concern) — do not skip this in favor of only unit-testing the backoff math
- [ ] `frontend/e2e/mfa-setup.spec.ts` (or extend an existing spec) — covers CORR-05's no-dead-end MFA-setup flow end-to-end
- [ ] `frontend/e2e/*.spec.ts` tenant-restore-after-reload assertion — covers CORR-05a's "no flash of Select tenant" non-negotiable
- [ ] `frontend/src/pages/organizations/OrganizationDetailPage.test.tsx` (or similar, vitest) — covers CORR-06's dirty-tracking/init-guard behavior without needing a full Playwright round-trip

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes (CORR-02) | Root-token renewal must not weaken the existing Argon2id/JWT/session model — this phase only affects the SurrealDB service-account (root) session, not end-user auth |
| V3 Session Management | yes (CORR-02) | The reactive reconnect path must not silently swallow a genuine authentication failure (e.g. revoked credentials) as if it were "just expiry" — `health_check` returning Unhealthy on ANY auth failure (not just expiry) is the safer default (D-05 says "expired/unrecoverable") |
| V4 Access Control | no new surface | This phase does not change RBAC/permission checks |
| V5 Input Validation | yes (CORR-03) | Webhook payload/URL validation is already handled by the existing SSRF guard (`axiam_federation::ssrf::guarded_fetch`) — reused unchanged, not re-implemented |
| V6 Cryptography | yes (CORR-03) | HMAC-SHA256 signing — reuse the existing `hmac`/`sha2` crates and the existing `compute_signature` shape, only extending it for the timestamp (D-10); never hand-roll a MAC |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Webhook signature replay (an old, previously-valid signed delivery replayed later) | Spoofing/Tampering | The Stripe-style `t=<unix>` timestamp is the standard building block for a *receiver*-side replay window check; this phase (per CONTEXT.md's Deferred Ideas) only emits the timestamp — receiver-side tolerance-window enforcement is explicitly deferred, not this phase's job |
| SurrealDB root-session hijack via a stale/leaked bearer token | Spoofing | Unaffected by this phase — token issuance/storage mechanism (`DEFINE USER ... DURATION FOR TOKEN`) is unchanged; only the renewal cadence changes |
| Webhook target SSRF (delivery URL points at an internal service) | Tampering/Elevation | Already mitigated by the existing `ssrf::guarded_fetch` guard (SEC-019/SECHRD-02) — CORR-03 reuses it unchanged in `deliver_once()`, does not bypass or duplicate it |
| Rate-limit bypass via a misconfigured/inverted quota (this phase's own bug class) | Denial of Service (self-inflicted, and also a DoS-enabling condition since a barely-throttling governor doesn't actually rate-limit) | Fixed by CORR-01 itself; the sustained-throughput test (D-02) is the regression guard against reintroducing this class of bug |

## Project Constraints (from CLAUDE.md)

- **Build/disk hygiene:** run `cargo clean` between plan steps (not during an
  executor run); prefer `-p <crate>` scoped `cargo test`/`cargo clippy`/
  `cargo fmt -- --check` over unscoped whole-workspace commands except at the
  phase-gate regression check.
- **swagger-ui egress workaround:** any build/test touching `axiam-api-rest`
  (CORR-03's webhook.rs changes, CORR-05's auth.rs changes) after a
  `target/` wipe must set
  `SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`.
- **Signed commits per roadmap task** — each plan's tasks should land as
  signed commits per the existing project convention.
- **Security standards** (Argon2id, EdDSA JWTs, AES-256-GCM at rest,
  HMAC-SHA256 webhook signatures, TLS 1.3 min) — none of these are touched or
  weakened by this phase; CORR-03's signature upgrade stays within
  HMAC-SHA256, just changes the signed payload shape (adds a timestamp
  prefix), consistent with the existing standard.
- **RBAC additive-only / no deny-override (SEC-040)** — unaffected; this
  phase does not touch the authorization engine's decision logic, only the
  gRPC transport-level rate limiter in front of it.

## Sources

### Primary (HIGH confidence — verified directly against vendored dependency
source code and this session's own reads of the live repository)
- `crates/axiam-api-grpc/src/middleware/rate_limit.rs` — current (still-buggy) governor construction
- `/root/.cargo/registry/src/.../tower_governor-0.8.0/src/governor.rs` — `GovernorConfigBuilder` period semantics
- `/root/.cargo/registry/src/.../governor-0.10.4/src/quota.rs` — `Quota::per_second`/`with_period` semantics
- `/root/.cargo/registry/src/.../surrealdb-3.1.5/src/lib.rs` — `Surreal<C>::clone()`/session_id mechanics
- `/root/.cargo/registry/src/.../surrealdb-3.1.5/src/engine/remote/http/mod.rs` — HTTP-engine session state, auth header propagation, `Signin`/`Invalidate`/`Authenticate` command handlers
- `crates/axiam-db/src/connection.rs` — current `DbManager` implementation and its own documenting comments
- `crates/axiam-api-rest/src/webhook.rs` — current `WebhookDeliveryService`
- `crates/axiam-amqp/src/{connection,mail_consumer,messages,config}.rs` — existing AMQP topology/backoff/signing conventions
- `.github/workflows/ci.yml`, `frontend/package.json`, `frontend/playwright.config.ts`, `frontend/e2e/*.spec.ts` — CI/e2e wiring
- `frontend/src/{hooks/useAuthInit.ts, lib/fetchCurrentUser.ts, pages/LoginPage.tsx, pages/auth/VerifyEmailPage.tsx, pages/DashboardPage.tsx, pages/users/UsersPage.tsx, pages/organizations/OrganizationDetailPage.tsx, components/layout/AppLayout.tsx, components/ConfirmDialog.tsx, pages/profile/MfaManagementPage.tsx, router.tsx, services/auth.ts}` — all read directly this session
- `crates/axiam-api-rest/src/handlers/auth.rs` — current `MeResponse`/`LoginUserInfo`/`me` handler
- `claude_dev/code-review-postremediation.md` (CQ-B44) — independent prior confirmation of the CORR-01 defect

### Secondary (MEDIUM confidence)
- Stripe's public `t=,v1=` webhook-signature convention (industry-standard prior art; the exact target format is a locked CONTEXT.md decision, not independently re-verified against Stripe's docs this session)

### Tertiary (LOW confidence, flagged in Assumptions Log)
- RabbitMQ's exact silent-drop behavior for a `x-dead-letter-exchange` naming a non-existent exchange (A1) — well-established general RabbitMQ knowledge, not verified against a live broker in this session

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new libraries; all versions confirmed via `cargo tree`/registry cache
- Architecture: HIGH — every pattern above was checked against the actual current source, not assumed from training knowledge
- Pitfalls: HIGH for Pitfalls 1-3, 5-6 (directly verified via source); MEDIUM for Pitfall 4 (RabbitMQ DLX runtime behavior reasoned from documented semantics, not live-broker-tested this session)

**Research date:** 2026-07-04
**Valid until:** 30 days (stable, internally-scoped fixes; no external API surface expected to shift)
