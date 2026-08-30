# Phase 26: Correctness & Resilience - Pattern Map

**Mapped:** 2026-07-04
**Files analyzed:** 15 (created/modified across CORR-01..06)
**Analogs found:** 15 / 15 (all fixes are wiring corrections against existing, in-tree analogs — no greenfield patterns needed)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/axiam-api-grpc/src/middleware/rate_limit.rs` (`build_grpc_governor_layer`) | middleware | request-response | itself (fix the construction in place) | exact — bug is a construction-site defect, not a missing pattern |
| `crates/axiam-db/src/connection.rs` (proactive re-signin task + reactive reconnect) | service/connection-manager | event-driven (background timer) + request-response (health_check) | itself, `crates/axiam-amqp/src/connection.rs::connect_with_retry` (nearest in-tree "reconnect loop with backoff" shape) | role-match |
| `crates/axiam-amqp/src/webhook_consumer.rs` (NEW) | service (AMQP consumer) | event-driven, batch-retry | `crates/axiam-amqp/src/mail_consumer.rs` | exact — same shape (consume → process → ack/nack/republish → audit) |
| `crates/axiam-amqp/src/connection.rs` (ADD: webhook exchange/queue/DLX consts + `declare_webhook_topology()`) | config/topology | pub-sub | itself (`declare_queues`), but pattern must NOT be copied verbatim (Pitfall 4 — DLX-as-queue-name bug) | partial — same file/shape, different (correct) DLX wiring |
| `crates/axiam-api-rest/src/webhook.rs` (split `deliver()` → `emit()` + `deliver_once()`) | service | request-response → publish (emit) / single-attempt HTTP (deliver_once) | itself | exact — retains signer/SSRF-guard, removes in-process retry loop |
| `crates/axiam-amqp/src/webhook_publisher.rs` (NEW, optional — or fold into `webhook_consumer.rs`/`connection.rs`) | service (AMQP publisher) | pub-sub | `crates/axiam-amqp/src/mail_publisher.rs` | exact |
| `.github/workflows/ci.yml` (`e2e` job) | CI config | batch | itself (existing job) | exact — additive step only |
| `frontend/src/pages/auth/MfaSetupPage.tsx` (NEW) | component/route | request-response | `frontend/src/pages/auth/ResetPasswordPage.tsx` | exact — identical `?token=` public-route dead-end-avoidance shape |
| `frontend/src/pages/profile/MfaManagementPage.tsx` (extract shared TOTP setup UI) | component | request-response | itself (`TotpSetupDialog`, currently private/inline) | exact — source of the extraction |
| `frontend/src/router.tsx` (register `/auth/mfa-setup`) | route config | — | itself (`/auth/reset-password`, `/auth/verify-email` entries) | exact |
| `crates/axiam-api-rest/src/handlers/auth.rs` (`LoginUserInfo` + `me` handler + `cookie_response_from_output`) | controller/DTO | request-response | itself | exact |
| `frontend/src/pages/auth/VerifyEmailPage.tsx` (StrictMode guard) | component | request-response | `frontend/src/hooks/useAuthInit.ts` (already has the identical `useRef` guard) | exact |
| `frontend/src/pages/DashboardPage.tsx` (query-key rename) | component | CRUD (read) | itself; collision partner `frontend/src/pages/users/UsersPage.tsx` | exact |
| `frontend/src/pages/organizations/OrganizationDetailPage.tsx` (`SettingsTab` dirty-tracking + nav-away guard) | component | CRUD (read+update) | itself (`SettingsTab`) | exact |
| `frontend/e2e/*.spec.ts` (extend/verify 13 existing specs) | test | request-response (e2e) | itself | exact |

## Pattern Assignments

### `crates/axiam-api-grpc/src/middleware/rate_limit.rs` (middleware, request-response)

**Analog:** itself — `build_grpc_governor_layer`, lines 160-179 (current, still-buggy state)

**Current (buggy) code** (lines 160-179):
```rust
pub fn build_grpc_governor_layer(authz_per_sec: u32) -> GrpcGovernorLayer {
    assert!(authz_per_sec >= 1, "grpc_authz_per_sec must be >= 1");
    let config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(authz_per_sec as u64)      // BUG: tower_governor's .per_second(n)
            .burst_size(authz_per_sec * 2)          // sets replenish PERIOD = n seconds,
            .key_extractor(GrpcTrustedHopsKeyExtractor::new(trusted_hops_from_env()))
            .finish()
            .expect("valid GovernorConfig for gRPC rate limiter"),
    );
    GovernorLayer::new(config)
}
```

**Fix pattern** (construct `governor::Quota` directly — per RESEARCH Pattern 1 / D-01):
```rust
use governor::Quota;
use std::num::NonZeroU32;

pub fn build_grpc_governor_layer(authz_per_sec: u32) -> GrpcGovernorLayer {
    assert!(authz_per_sec >= 1, "grpc_authz_per_sec must be >= 1");
    let burst = NonZeroU32::new(authz_per_sec).expect("authz_per_sec >= 1 asserted above");
    let quota = Quota::per_second(burst); // D-01: burst == authz_per_sec, not *2

    let config = Arc::new(
        GovernorConfigBuilder::default()
            .const_period(quota.replenish_interval())
            .const_burst_size(quota.burst_size().get())
            .key_extractor(GrpcTrustedHopsKeyExtractor::new(trusted_hops_from_env()))
            .finish()
            .expect("valid GovernorConfig for gRPC rate limiter"),
    );
    GovernorLayer::new(config)
}
```

**Test pattern** — the existing `#[cfg(test)] mod tests` block (lines 392-452) already contains the `KeyExtractor` unit tests to extend; ADD a new sustained-throughput test in the same module (D-02): drive N requests over a simulated clock and assert observed rate ≈ `authz_per_sec`, not just "first burst passes."

**Do not touch:** `GrpcSharedRateLimitLayer`/`GrpcSharedRateLimitService` (lines 238-390) — unrelated SECHRD-03 shared-store pre-check, explicitly marked out of CORR-01's scope by the file's own header comment ("HARD CONSTRAINT... untouched by this module").

---

### `crates/axiam-db/src/connection.rs` (service/connection-manager, event-driven + request-response)

**Analog:** itself (current `DbManager`) + `crates/axiam-amqp/src/connection.rs::connect_with_retry` for the reconnect-loop shape.

**Current relevant state** (lines 20-23, 65-98, 148-161):
```rust
const ROOT_TOKEN_DURATION: &str = "4w";
// ...
pub async fn connect(config: &DbConfig) -> Result<Self, surrealdb::Error> {
    Self::extend_root_token_duration(config).await;
    let db = Surreal::new::<Http>(&config.url).await?;
    db.signin(Root { username: ..., password: ... }).await?;
    db.use_ns(&config.namespace).use_db(&config.database).await?;
    Ok(Self { db })
}
pub async fn health_check(&self) -> Result<(), DbError> {
    let result = self.db.query("RETURN 1").await.map_err(DbError::Surreal)?;
    result.check().map_err(DbError::Surreal)?;
    Ok(())
}
```

**Fix pattern (D-03/D-04):** represent `ROOT_TOKEN_DURATION` as a `Duration` constant (not just a SurrealQL literal string), derive both the `DEFINE USER ... DURATION FOR TOKEN` literal AND the re-signin interval from it:
```rust
const ROOT_TOKEN_DURATION: Duration = Duration::from_secs(4 * 7 * 24 * 3600); // 4 weeks

fn root_token_duration_surql_literal() -> String {
    format!("{}s", ROOT_TOKEN_DURATION.as_secs())
}

fn re_signin_interval(fraction: f64) -> Duration {
    // AXIAM__DB__TOKEN_REFRESH_FRACTION, default ~0.6 (D-04)
    Duration::from_secs_f64(ROOT_TOKEN_DURATION.as_secs_f64() * fraction.clamp(0.05, 0.95))
}
```
Spawn a `tokio::spawn` periodic task (owned by `DbManager`, started in `connect()` or a new `DbManager::spawn_token_refresh()`) that calls `db.signin(Root {...})` on the SAME already-authenticated handle at `re_signin_interval()` — this succeeds because the still-valid cached token authorizes the new `Signin` request (Pitfall 2/3 in RESEARCH: do NOT call `invalidate()` first on the proactive path).

**Reconnect-loop shape to mirror** (`crates/axiam-amqp/src/connection.rs`, lines 82-114, `connect_with_retry`):
```rust
pub async fn connect_with_retry(config: &AmqpConfig) -> Result<Self, AmqpError> {
    let total_attempts = config.max_retries.saturating_add(1);
    for attempt in 1..=total_attempts {
        match Self::connect(config).await {
            Ok(manager) => return Ok(manager),
            Err(e) => {
                if attempt == total_attempts { /* ... error out ... */ }
                warn!(error = %e, attempt, "retrying");
                tokio::time::sleep(Duration::from_millis(config.reconnect_delay_ms)).await;
            }
        }
    }
    unreachable!("loop always returns")
}
```
Per RESEARCH Pitfall 3: the reactive path must NOT call `invalidate()`+`signin()` on the stale handle — it must build a brand-new `Surreal::new::<Http>(...)` connection (mirrors `connect()`'s own body) and swap it in.

**`health_check` fix (D-05):** on auth failure (not just any query error), return `DbError::Unhealthy`/equivalent so the readiness probe surfaces it — extend the existing `result.check().map_err(DbError::Surreal)?` branch to classify auth-specific errors distinctly if the error type allows it, else document the residual gap.

**Explicitly document (do not silently fix or ignore) Pitfall 2:** the ~30 other repository `Surreal<Client>` clones each hold an independently-expiring session snapshot (see `crates/axiam-server/src/main.rs`'s `db.client().clone()` call sites) — out of this phase's scope (deferred to PERF-04/Phase 27).

---

### `crates/axiam-amqp/src/webhook_consumer.rs` (NEW — service/AMQP consumer, event-driven)

**Analog:** `crates/axiam-amqp/src/mail_consumer.rs` (full file, 491 lines) — this is the primary template.

**Imports pattern** (lines 13-25):
```rust
use crate::connection::queues;
use crate::messages::{MailType, OutboundMailMessage};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogRepository, EmailConfigRepository, UserRepository};
use futures_lite::StreamExt;
use lapin::BasicProperties;
use lapin::Channel;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions};
use lapin::types::FieldTable;
use tracing::{error, info, warn};
```
For webhooks: swap `EmailConfigRepository`/`UserRepository` for `WebhookRepository`; import `WebhookDeliveryService::deliver_once` and `compute_signature_v2` from `axiam-api-rest::webhook` (cross-crate — check `axiam-amqp` doesn't currently depend on `axiam-api-rest`; if a dependency cycle exists, move the delivery-attempt logic into `axiam-amqp` or a shared crate — flag for planner if so).

**Consumer loop pattern** (lines 296-439, `start_mail_consumer`):
```rust
pub async fn start_mail_consumer<E, A, U>(channel: Channel, ...) {
    let mut consumer = match channel.basic_consume(queues::MAIL_OUTBOUND.into(), "axiam-mail-consumer".into(), BasicConsumeOptions::default(), FieldTable::default()).await {
        Ok(c) => c,
        Err(e) => { error!(...); return; }
    };
    while let Some(delivery_result) = consumer.next().await {
        let delivery = match delivery_result { Ok(d) => d, Err(e) => { error!(...); continue; } };
        let msg: OutboundMailMessage = match serde_json::from_slice(&delivery.data) {
            Ok(m) => m,
            Err(e) => { /* nack requeue:false — bad payload */ continue; }
        };
        let outcome = send_with_retry_and_audit(&msg, ...).await;
        match outcome {
            Ok(SendOutcome::Delivered) => { delivery.acker.ack(BasicAckOptions::default()).await; }
            Ok(SendOutcome::RetryNeeded { .. }) => { /* republish with incremented attempt_count, THEN ack original */ }
            Ok(SendOutcome::Exhausted) => { /* nack requeue:false -> DLQ; audit already written */ }
            Err(e) => { /* nack requeue:false — config/infra error */ }
        }
    }
}
```
**Diverge from mail_consumer here (per D-07/Pitfall 5):** do NOT copy the `tokio::time::sleep(backoff_delay_secs(...))` before republish (lines 369-377 of `mail_consumer.rs`) — that ties up the consumer slot. Instead: on retry-needed, publish to a **separate retry queue** with `x-message-ttl` = computed backoff and let RabbitMQ's DLX auto-redeliver to the primary queue with zero consumer attached. See `connection.rs` pattern below.

**Backoff math to reuse (not the sleep call, just the numeric shape)** (lines 47-67):
```rust
const MAIL_RETRY_INITIAL_DELAY_SECS: f64 = 10.0;
const MAIL_RETRY_BACKOFF_MULTIPLIER: f64 = 2.0;
const MAIL_RETRY_MAX_DELAY_SECS: f64 = 3600.0;
fn backoff_delay_secs(attempt_count: u32) -> f64 {
    let exponent = attempt_count.saturating_sub(1) as i32;
    (MAIL_RETRY_INITIAL_DELAY_SECS * MAIL_RETRY_BACKOFF_MULTIPLIER.powi(exponent))
        .clamp(0.0, MAIL_RETRY_MAX_DELAY_SECS)
}
```
For webhooks use `AXIAM__WEBHOOK__BACKOFF_BASE_MS`/`AXIAM__WEBHOOK__BACKOFF_CEILING_MS`/`AXIAM__WEBHOOK__MAX_ATTEMPTS` (D-20) instead of the mail-specific constants, but keep the same `base * multiplier^attempt` shape — this becomes the TTL value set on the per-message retry-queue publish, NOT a `tokio::time::sleep` argument.

**Audit pattern (per-attempt + terminal, D-09)** — mirror lines 208-234 (`CreateAuditLogEntry` construction) exactly, but write BOTH a per-attempt record (attempt#, HTTP status/error, next-retry time) and (on exhaustion) a terminal `failed` record, plus a terminal `success` record on delivery.

**Test pattern:** `#[cfg(test)] mod mail_retry_backoff_tests` (lines 445-490) — mirror this exact test shape (nonzero/increasing/clamped backoff) for the webhook backoff function.

---

### `crates/axiam-amqp/src/connection.rs` (ADD webhook topology — config/topology, pub-sub)

**Analog:** itself — `queues` module (lines 11-31) and `declare_queues()` (lines 127-188). **Do NOT copy `declare_queues`'s DLX wiring verbatim** (Pitfall 4 — `x-dead-letter-exchange` set to a queue name with no matching `exchange_declare` anywhere in the crate, which RabbitMQ silently drops).

**Current (buggy-for-new-use) DLX pattern** (lines 172-186, `MAIL_OUTBOUND` example — do not replicate):
```rust
let mut mail_args = FieldTable::default();
mail_args.insert(
    "x-dead-letter-exchange".into(),
    lapin::types::AMQPValue::LongString(queues::MAIL_OUTBOUND_DLQ.into()), // BUG: names a QUEUE, not a declared exchange
);
self.channel.queue_declare(queues::MAIL_OUTBOUND.into(), options, mail_args).await?;
```

**Correct pattern for the NEW webhook topology (D-07, Pitfall 4 recommendation (b)):** use the default (nameless, `""`) exchange + `x-dead-letter-routing-key` set to the literal target queue name — RabbitMQ's implicit per-queue-name routing on the default exchange makes this the well-known-correct minimal-surface form:
```rust
pub mod queues {
    pub const WEBHOOK: &str = "axiam.webhook";
    pub const WEBHOOK_RETRY: &str = "axiam.webhook.retry";
    pub const WEBHOOK_DLQ: &str = "axiam.webhook.dlq";
}

// WEBHOOK_RETRY: per-message TTL set at PUBLISH time (via BasicProperties::default().with_expiration(ttl_ms.to_string().into())),
// dead-letters back to WEBHOOK via the default exchange once TTL expires — no consumer attached, no slot held (D-07/Pitfall 5).
let mut retry_args = FieldTable::default();
retry_args.insert("x-dead-letter-exchange".into(), AMQPValue::LongString("".into()));
retry_args.insert("x-dead-letter-routing-key".into(), AMQPValue::LongString(queues::WEBHOOK.into()));
self.channel.queue_declare(queues::WEBHOOK_RETRY.into(), options, retry_args).await?;
```
Attempt-count is carried in message headers (`FieldTable`), not queue args — increment on each republish, check against `AXIAM__WEBHOOK__MAX_ATTEMPTS` before nack'ing to `WEBHOOK_DLQ` (real, replayable) on exhaustion.

**Existing DLQ-declare-order convention to keep** (lines 33-45, `ALL_QUEUES` comment): declare DLQ-target queues before any queue that references them, same discipline applies to the new trio.

---

### `crates/axiam-api-rest/src/webhook.rs` (split `emit()`/`deliver_once()` — service)

**Analog:** itself — current `WebhookDeliveryService::deliver()` (lines 119-287) is being split, not rewritten.

**Keep unchanged (D-06):**
- `WebhookError` enum + `From<WebhookError>`/`From<SsrfError>` mappings (lines 24-76)
- `encrypt_secret`/`encrypt_webhook_secret` (SEC-031, lines 111-117, 296-302)
- SSRF-guarded fetch call shape via `ssrf::guarded_fetch` (lines 209-217) — reused unchanged in `deliver_once()`

**Split into:**
```rust
// emit(): publish-only replacement for the current tokio::spawn body (lines 122-148 shape, minus the retry loop)
pub async fn emit(&self, publisher: &WebhookPublisher, tenant_id: Uuid, event_type: String, payload: serde_json::Value) {
    let webhooks = self.repo.get_by_event(tenant_id, &event_type).await?; // as today (line 139)
    for webhook in webhooks {
        publisher.publish(WebhookMessage { webhook_id: webhook.id, delivery_id: Uuid::new_v4(), event_type: event_type.clone(), payload: payload.clone(), attempt: 0 }).await;
    }
}

// deliver_once(): the CURRENT single-attempt body (lines 158-217) with the retry `for attempt in 0..=max_retries` loop (lines 186-275) REMOVED —
// AMQP TTL+DLX now owns retry scheduling (D-07). Decrypt secret, compute_signature_v2, guarded_fetch, return Result for the consumer to ack/nack.
pub async fn deliver_once(&self, webhook_id: Uuid, delivery_id: Uuid, event_type: &str, payload: &serde_json::Value) -> Result<StatusCode, WebhookError> { /* single ssrf::guarded_fetch call, no loop, no sleep */ }
```

**Signature upgrade (D-10)** — extend `compute_signature` (lines 289-294):
```rust
// Current (body-only, being replaced):
fn compute_signature(secret: &str, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// New (Stripe-style t=,v1=, D-10):
fn compute_signature_v2(secret: &str, timestamp: i64, body: &str) -> String {
    let signed_payload = format!("{timestamp}.{body}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(signed_payload.as_bytes());
    format!("t={timestamp},v1={}", hex::encode(mac.finalize().into_bytes()))
}
// Headers: X-Axiam-Timestamp: <timestamp>, X-Axiam-Signature: t=<timestamp>,v1=<hex>
// X-Axiam-Event / X-Axiam-Delivery unchanged (lines 213-214).
```
**No SDK-side verification helper exists to update** — confirmed absent (RESEARCH grep across `sdks/`).

**Test pattern:** the existing `#[cfg(test)] mod tests` (lines 304-455) — `signature_is_deterministic`/`different_secrets_produce_different_signatures` (lines 309-322) is the template to extend for `compute_signature_v2`; all SSRF tests (lines 332-437) and the secret round-trip test (441-454) stay unchanged/reused as-is.

---

### `crates/axiam-api-rest/src/handlers/webhooks.rs` (unchanged handler shape — registration/emit path reference)

**Analog:** itself. No structural change expected — `create`/`update` (lines 91-127, 203-248) already call `webhook_delivery.encrypt_secret(...)`; the delivery-trigger call sites elsewhere in the codebase that currently call `.deliver(...)` (zero call sites per RESEARCH finding) must be updated to call the new `.emit(...)` once CORR-03 lands. Planner should grep for `.deliver(` call sites across handlers at execution time to confirm the zero-call-site finding still holds.

---

### `.github/workflows/ci.yml` (`e2e` job — CI config)

**Analog:** itself, current `e2e` job (lines ~279-365, confirmed at lines 260-354 in this read).

**Current step to replace** (the "Serve frontend and run E2E tests" step body, `run: | ... npm test ...` — currently `vitest run`, not Playwright):
```yaml
      - name: Serve frontend and run E2E tests
        working-directory: frontend
        run: |
          npx serve dist -l 5173 &
          SERVE_PID=$!
          for i in $(seq 1 15); do curl -sf http://localhost:5173 > /dev/null 2>&1 && break || sleep 2; done
          npm test          # <-- currently = `vitest run` (WRONG for an "E2E" job per package.json line 12)
          kill $SERVE_PID || true
        env:
          CI: "true"
          E2E_BASE_URL: "http://localhost:5173"
          ...
```
**Fix (D-11):** add a distinct blocking `npx playwright test` step (uses `test:e2e` script, package.json line 13) alongside the existing `vitest run` step — both required, same job (backend already seeded there):
```yaml
          npm run test:e2e   # playwright test — the actual e2e specs
          # AND, as a separate step or appended:
          npm test           # vitest run — keep as its own blocking step
```
The `npx playwright install chromium` step (already present, per RESEARCH line ~330) needs no change. `playwright-report` upload step (`if: always()`, already present) needs no change.

**13 specs found** (not 12 as CONTEXT.md/REQUIREMENTS.md describe — planner should enumerate at plan time, not hardcode a count): `auth-contract, certificates, dashboard, federation, identity, login, logout, organizations, roles, service-accounts, settings, tenants, users`.

---

### `frontend/src/pages/auth/MfaSetupPage.tsx` (NEW — component/route, request-response)

**Analog:** `frontend/src/pages/auth/ResetPasswordPage.tsx` (full file, 231 lines) — near-exact structural template.

**Query-param + validity-guard pattern to mirror** (lines 34-54):
```typescript
export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const tenantId = searchParams.get("tenant_id") ?? searchParams.get("tenant");
  // ... canSubmit derived from token/tenantId presence + form validity ...
```
For MFA-setup: read `setup_token` from `useSearchParams()` instead of relying on router `state` (the CURRENT `/profile/mfa` navigation passes `state: { setup_token }`, which is lost on refresh/bookmark — exactly the CQ-F dead-end bug D-16 fixes). LoginPage's `navigate("/profile/mfa", { state: { setup_token: data.setup_token } })` (LoginPage.tsx lines 108-110) must instead navigate to `/auth/mfa-setup?setup_token=...` as a query param.

**Three-state render pattern to mirror** (lines 88-140): success state (lines 89-110), invalid/missing-token state (lines 112-140), and the main form (lines 143-230) — same three-way branch structure for MFA setup (success → proceed to app; invalid/missing setup_token → error message + link back to login; valid → QR/secret/code-input form).

**`useActionState` + error-response typing pattern** (lines 1-28, 56-86):
```typescript
interface ErrorResponse { message?: string; error?: string; }
const [state, formAction, isPending] = useActionState<StateType, FormData>(
  async (_prev, formData) => {
    try {
      await someService.call(...);
      window.history.replaceState({}, document.title, window.location.pathname); // strips the token from the URL bar
      return { error: null, success: true };
    } catch (err) {
      window.history.replaceState({}, document.title, window.location.pathname);
      const axiosErr = err as AxiosError<ErrorResponse>;
      const msg = axiosErr.response?.data?.message ?? axiosErr.response?.data?.error ?? "fallback message";
      return { error: msg, success: false };
    }
  },
  { error: null, success: false }
);
```

**Success-path tenant-context caveat (per RESEARCH):** the new page's success handler must call `fetchCurrentUser()` (not the ambient login-form slugs `LoginPage.handleMfaSubmit` uses at line 169) to get `tenantSlug`/`orgSlug` for `setTenantContext(...)` — this depends on the CORR-05a backend `/auth/me` slug fix landing first.

**Route registration (`frontend/src/router.tsx`):** add `/auth/mfa-setup` as a new **top-level sibling** of `/auth/reset-password` (line 50) and `/auth/verify-email` (line 54) — NOT nested under `/` (`AppLayout`), which is exactly why `/profile/mfa` currently dead-ends (`AppLayout`'s `if (!isAuthenticated) return <Navigate to="/login" replace />` guard fires before an unauthenticated setup-token carrier ever reaches the page).

---

### `frontend/src/pages/profile/MfaManagementPage.tsx` → extract shared TOTP setup UI

**Analog:** itself — `TotpSetupDialog` (private function component, lines 81-~226) is NOT exported/importable as-is.

**Extraction pattern (RESEARCH-recommended approach (a)):** pull the QR+secret+code-input JSX (lines ~153-226) into a new shared presentational component (e.g. `frontend/src/components/auth/TotpSetupPanel.tsx`), taking `setupData: TotpSetupResponse`, `code`, `onCodeChange`, `onConfirm`, `error` as props — imported by both `MfaManagementPage.tsx` (still wrapped in its existing dialog chrome) and the new `MfaSetupPage.tsx` (inlined as a page body, no dialog wrapper — there's no authenticated shell to host a modal over).

**Interface to preserve** (lines 20-30ish, `TotpSetupResponse`/`MfaEnrollResponse` shape):
```typescript
interface TotpSetupResponse {
  secret_base32: string;
  totp_uri: string; // otpauth:// URI — rendered client-side via QRCodeSVG, not a data: image
}
```
QR rendering via `<QRCodeSVG value={...} />` (import `qrcode.react`, line 4) — reuse verbatim, do not hand-roll QR generation.

---

### `crates/axiam-api-rest/src/handlers/auth.rs` (`LoginUserInfo`/`me`/`cookie_response_from_output` — controller/DTO)

**Analog:** itself.

**Current `LoginUserInfo`** (lines 66-77) — needs two new optional fields:
```rust
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LoginUserInfo {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub tenant_id: Uuid,
    // ADD (D-14):
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_slug: Option<String>,
}
```

**`me` handler** (current, lines 618-667) needs two new `web::Data<...>` repo params and graceful-degrade lookups (D-15 — a slug-lookup failure must NOT fail the whole `/me` call):
```rust
pub async fn me<C: Connection>(
    user: AuthenticatedUser,
    user_repo: web::Data<SurrealUserRepository<C>>,
    role_repo: web::Data<SurrealRoleRepository<C>>,
    permission_repo: web::Data<SurrealPermissionRepository<C>>,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,   // NEW
    org_repo: web::Data<SurrealOrganizationRepository<C>>, // NEW — resolve via tenant.organization_id
) -> Result<HttpResponse, AxiamApiError> {
    // ...existing user/roles/permissions logic (lines 624-656) unchanged...
    let tenant_slug = tenant_repo.get_by_id(user.tenant_id).await.ok().map(|t| t.slug);
    let org_id = tenant_slug.as_ref().and(/* need tenant.organization_id, see below */);
    let org_slug = /* org_repo.get_by_id(tenant.organization_id) */ .ok().map(|o| o.slug);
    Ok(HttpResponse::Ok().json(MeResponse {
        user: LoginUserInfo { id: user.user_id, username: u.username, email: u.email, tenant_id: user.tenant_id, tenant_slug, org_slug },
        permissions,
    }))
}
```
Note: `tenant_repo.get_by_id` only returns a `Tenant` (which has `organization_id`); the org lookup needs the tenant's `organization_id`, not `user.org_id` directly unless `AuthenticatedUser` already carries it (`change_password`'s existing pattern at line 747, `let tenant = tenant_repo.get_by_id(user.tenant_id).await?;` then using `tenant.organization_id`, is the exact precedent to follow for resolving org_id from tenant_id).

**Also update `cookie_response_from_output`'s `LoginUserInfo` construction** (lines 210-215) with the same two fields, so a fresh login populates slugs immediately (not just post-reload `/me`) — avoids a "works after reload but not on fresh login" split-brain.

**Frontend consumption is ALREADY WIRED defensively — no frontend change needed for the read side:**
- `frontend/src/lib/fetchCurrentUser.ts` (lines 29-31) already reads `res.data.tenant_slug ?? res.data.user?.tenant_slug` / same for org_slug.
- `frontend/src/hooks/useAuthInit.ts` (lines 57-62) already calls `setTenantContext(user.tenantSlug, user.orgSlug)` guarded by `if (user.tenantSlug && user.orgSlug)`.
Only the backend DTO/handler needs the two new fields — this is a backend-only file for CORR-05a.

---

### `frontend/src/pages/auth/VerifyEmailPage.tsx` (StrictMode guard — component)

**Analog:** `frontend/src/hooks/useAuthInit.ts` (full file, 71 lines) — copy this exact `useRef` pattern verbatim, not a new invention.

**Pattern to copy** (useAuthInit.ts lines 20-39, 55-68):
```typescript
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
      const msg = axiosErr.response?.data?.message ?? axiosErr.response?.data?.error ?? "Verification failed...";
      setErrorMessage(msg);
      setVerifyState("error");
    }
  }
  doVerify();
  // NO cleanup-based `cancelled` flag — the ref guard IS the de-dup mechanism (see useAuthInit.ts's own comment, lines 30-37, for why a cleanup-cancel reintroduces the "stuck forever" bug).
}, [token, tenantId]);
```

---

### `frontend/src/pages/DashboardPage.tsx` (query-key rename — component, CRUD read)

**Analog:** itself, current collision at line 186; collision partner `frontend/src/pages/users/UsersPage.tsx` line 228.

**Current colliding key:**
```typescript
queryKey: ["users", 1, ""],   // DashboardPage.tsx:186 — collides with UsersPage's page-1/no-filter key
```
**Fix (D-18, exact shape at discretion):**
```typescript
queryKey: ["users", "dashboard-count"],  // structurally can never collide with ["users", page, search]
```
Sibling keys in the SAME file (lines 190, 194, 198, 202 — `["groups"]`, `["roles"]`, `["certificates"]`, `["audit-logs"]`) are already collision-free singletons; the `["users", 1, ""]` entry is the only offender — verify no other dashboard stat-card query shares a `[entity, page, search]` shape with a paginated list page elsewhere.

---

### `frontend/src/pages/organizations/OrganizationDetailPage.tsx` (`SettingsTab` — component, CRUD read+update)

**Analog:** itself, current `SettingsTab` function (lines 665-~850+).

**Current bug (CQ-F38 — refetch discards in-progress edits)** (lines 670-683):
```typescript
const { data: settings, isLoading } = useQuery({
  queryKey: ["org-settings", orgId],
  queryFn: () => orgSettingsService.get(orgId),
});
const [form, setForm] = useState<SetOrgSettings | null>(null);

useEffect(() => {
  // eslint-disable-next-line react-hooks/set-state-in-effect
  if (settings) setForm(flattenOrgSettings(settings));   // BUG: re-seeds on EVERY settings-object identity change, including a window-refocus refetch, discarding dirty edits
}, [settings]);
```

**Fix pattern (D-19 — init-guard + dirtiness tracking + nav-away guard):**
```typescript
const initializedRef = useRef(false);   // mirrors useAuthInit.ts's guard idiom
const [isDirty, setIsDirty] = useState(false);

useEffect(() => {
  if (settings && !initializedRef.current) {
    setForm(flattenOrgSettings(settings));
    initializedRef.current = true;
  }
}, [settings]);

function setField<K extends keyof SetOrgSettings>(key: K, value: SetOrgSettings[K]) {
  setForm((prev) => (prev ? { ...prev, [key]: value } : prev));
  setIsDirty(true);
}

const updateMutation = useMutation({
  mutationFn: (payload: SetOrgSettings) => orgSettingsService.update(orgId, payload),
  onSuccess: () => {
    void queryClient.invalidateQueries({ queryKey: ["org-settings", orgId] });
    setIsDirty(false); // saved — safe to accept a future re-seed if orgId changes, or leave initializedRef as-is since it's per-mount
    setSaveError(""); setSaveSuccess(true); setTimeout(() => setSaveSuccess(false), 3000);
  },
  onError: (err) => { setSaveError(err instanceof Error ? err.message : "Failed to save settings."); },
});

// D-19 broader-than-minimum: warn on navigate-away when dirty (router-level blocker or beforeunload)
useEffect(() => {
  const handler = (e: BeforeUnloadEvent) => { if (isDirty) { e.preventDefault(); } };
  window.addEventListener("beforeunload", handler);
  return () => window.removeEventListener("beforeunload", handler);
}, [isDirty]);
```
`react-router-dom` v7's `useBlocker`/`unstable_usePrompt` is the in-app-navigation equivalent if a router-level blocker is preferred over `beforeunload`-only — check current `react-router-dom` version support (`^7.13.2` per RESEARCH) before committing to `useBlocker`.

**Existing `handleSubmit`/mutation-trigger shape unchanged** (lines 708-714) — only the init-effect and dirty-tracking wrapper around `setField` change.

---

## Shared Patterns

### AMQP consumer/backoff conventions (CORR-03)
**Source:** `crates/axiam-amqp/src/mail_consumer.rs` (full file) + `crates/axiam-amqp/src/connection.rs` (`queues` module, `declare_queues`)
**Apply to:** the new `webhook_consumer.rs` and `connection.rs`'s webhook topology additions.
```rust
// Backoff shape (numeric constants change per-domain, formula stays):
fn backoff_delay_secs(attempt_count: u32) -> f64 {
    let exponent = attempt_count.saturating_sub(1) as i32;
    (INITIAL_DELAY_SECS * BACKOFF_MULTIPLIER.powi(exponent)).clamp(0.0, MAX_DELAY_SECS)
}
// Bad-payload / non-retryable error -> nack requeue:false.
// Retryable failure -> republish with incremented attempt count (webhooks: via TTL retry queue, NOT a sleep).
// Exhausted -> nack requeue:false -> DLQ + terminal audit record.
```

### Audit-write shape (CORR-03, D-09)
**Source:** `crates/axiam-amqp/src/mail_consumer.rs` lines 208-234 (`CreateAuditLogEntry` construction)
**Apply to:** webhook per-attempt and terminal audit records.
```rust
let entry = CreateAuditLogEntry {
    tenant_id: ..., actor_id: ..., actor_type: ActorType::System,
    action: "webhook.delivery_attempt".into(), // or "webhook.delivery_failed" / "webhook.delivery_succeeded"
    resource_id: Some(webhook_id), outcome: AuditOutcome::Failure, // or ::Success
    ip_address: None,
    metadata: Some(serde_json::json!({ "attempt": attempt, "status": status_or_error, "next_retry_at": next_retry })),
};
audit_repo.append(entry).await
```

### `useRef` once-guard for StrictMode double-mount
**Source:** `frontend/src/hooks/useAuthInit.ts` lines 16-39
**Apply to:** `VerifyEmailPage.tsx` (CORR-06/D-17), and any other one-shot-effect page (e.g. the new `MfaSetupPage.tsx`'s enrollment-fetch effect, if it fires an auto-call on mount).

### `?token=`/query-param public-route dead-end avoidance
**Source:** `frontend/src/pages/auth/ResetPasswordPage.tsx` (full file) + `frontend/src/router.tsx` lines 50-58 (top-level sibling registration, outside `AppLayout`'s auth guard)
**Apply to:** the new `MfaSetupPage.tsx` route (CORR-05b/D-16).

### Error-response typing + `useActionState` form pattern
**Source:** `frontend/src/pages/auth/ResetPasswordPage.tsx` lines 16-19, 56-86
**Apply to:** any new auth-flow form page.

### Nested `AXIAM__SECTION__KEY` env config with safe defaults
**Source:** `crates/axiam-api-grpc/src/middleware/rate_limit.rs::trusted_hops_from_env` (lines 64-69) — the existing precedent for reading an env-configurable knob with `.unwrap_or(default)`.
```rust
std::env::var("AXIAM__RATE_LIMIT__TRUSTED_HOPS").ok().and_then(|v| v.parse().ok()).unwrap_or(0)
```
**Apply to:** `AXIAM__DB__TOKEN_REFRESH_FRACTION`, `AXIAM__WEBHOOK__MAX_ATTEMPTS`, `AXIAM__WEBHOOK__BACKOFF_BASE_MS`, `AXIAM__WEBHOOK__BACKOFF_CEILING_MS` (D-20).

## No Analog Found

None — every file in scope has a direct or role-matched in-tree analog; this phase is entirely wiring corrections against existing mechanisms (per RESEARCH's own framing: "every one of these six defects is a wiring/construction mistake against an already-correct or already-present underlying mechanism").

## Metadata

**Analog search scope:** `crates/axiam-api-grpc/src/middleware/`, `crates/axiam-db/src/`, `crates/axiam-amqp/src/`, `crates/axiam-api-rest/src/{webhook.rs,handlers/}`, `.github/workflows/`, `frontend/src/{pages,hooks,lib,components,router.tsx}`, `frontend/e2e/`
**Files scanned:** 15 target files + 8 analog files read in full/targeted ranges (rate_limit.rs, connection.rs ×2, mail_consumer.rs, webhook.rs, handlers/webhooks.rs, handlers/auth.rs, ResetPasswordPage.tsx, useAuthInit.ts, fetchCurrentUser.ts, MfaManagementPage.tsx, OrganizationDetailPage.tsx, ci.yml, package.json)
**Pattern extraction date:** 2026-07-04

## PATTERN MAPPING COMPLETE
