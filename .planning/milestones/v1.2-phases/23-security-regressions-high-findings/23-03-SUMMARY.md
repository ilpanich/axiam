---
phase: 23-security-regressions-high-findings
plan: 03
subsystem: api
tags: [webhook, encryption, aes-gcm, fail-closed, secrets, security, actix-web]

# Dependency graph
requires:
  - phase: 10-high-remediation
    provides: "PKI fail-closed Option<[u8;32]> encryption-key pattern (SEC-012) mirrored here"
provides:
  - "Fail-closed Option<[u8;32]> webhook encryption key (no all-zero/constant fallback)"
  - "WebhookDeliveryService.encrypt_secret() fail-closed encrypt entry point"
  - "Encrypt-on-write for webhook secrets on create AND update"
  - "Secret-rotation update DTO (UpdateWebhookRequest.secret / UpdateWebhook.secret)"
affects: [26-correctness-resilience]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Option<[u8;32]> fail-closed key handling for optional crypto subsystems (mirrors SEC-012 PKI pattern)"
    - "AxiamError::ServiceUnavailable -> HTTP 503 for a configured-but-currently-unavailable subsystem, distinct from AxiamError::Internal -> 500"

key-files:
  created: []
  modified:
    - crates/axiam-server/src/main.rs
    - crates/axiam-api-rest/src/webhook.rs
    - crates/axiam-api-rest/src/handlers/webhooks.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-api-rest/src/error.rs
    - crates/axiam-core/src/error.rs
    - crates/axiam-core/src/models/webhook.rs
    - crates/axiam-db/src/repository/webhook.rs
    - crates/axiam-api-rest/tests/webhook_test.rs

key-decisions:
  - "New AxiamError::ServiceUnavailable variant (503) added rather than reusing AxiamError::Internal (500) — a missing encryption key is an operator-actionable condition (configure the key), not a genuine internal bug, and the message is safe to echo to the caller (no crypto/DB internals leaked)."
  - "register_api_v1_routes<C> gained a Clone bound (was previously unconstrained beyond Connection) — required because WebhookDeliveryService's inherent methods require W: Clone; satisfied transparently by both concrete connection types already in use (DbClient, local Db)."

requirements-completed: [SECFIX-03]

coverage:
  - id: D1
    description: "Server boots when AXIAM__PKI__ENCRYPTION_KEY is unset; webhook registration is refused (503) rather than falling back to an all-zero key"
    requirement: SECFIX-03
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/webhook_test.rs#create_webhook_fails_closed_without_encryption_key"
        status: pass
    human_judgment: false
  - id: D2
    description: "Webhook secret is AES-256-GCM encrypted on create AND update; stored ciphertext differs from submitted plaintext and decrypts correctly"
    requirement: SECFIX-03
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/webhook.rs#webhook_secret_encrypt_decrypt_round_trip"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-rest/tests/webhook_test.rs#create_webhook_stores_ciphertext_not_plaintext"
        status: pass
    human_judgment: false
  - id: D3
    description: "Delivery refuses to decrypt (logs + returns) when no encryption key is configured, instead of attempting decrypt with a placeholder key"
    requirement: SECFIX-03
    verification:
      - kind: other
        ref: "code review: crates/axiam-api-rest/src/webhook.rs deliver() — let Some(encryption_key) = encryption_key else { tracing::error!(...); return; }"
        status: pass
    human_judgment: false
  - id: D4
    description: "No web::Data<Option<[u8;32]>> type collision with the email encryption key — webhook key routed exclusively through the uniquely-typed WebhookDeliveryService"
    requirement: SECFIX-03
    verification:
      - kind: other
        ref: "grep crates/axiam-server/src/main.rs — only one web::Data::new(...) of a bare Option<[u8;32]> (config.email_encryption_key at line 681); webhook_enc_key is never separately registered"
        status: pass
    human_judgment: false

duration: 30min
completed: 2026-07-03
status: complete
---

# Phase 23 Plan 03: Webhook Encryption Fail-Closed + Encrypt-at-Rest Summary

**Removed the all-zero webhook encryption-key fallback and wired the already-implemented encrypt_webhook_secret into both webhook write paths, mirroring PKI's SEC-012 fail-closed pattern.**

## Performance

- **Duration:** ~30 min
- **Started:** 2026-07-03T18:52:33Z (phase execution start)
- **Completed:** 2026-07-03T19:19:18Z
- **Tasks:** 3 completed
- **Files modified:** 9

## Accomplishments

- Closed SEC-059: `main.rs`'s `load_key_from_env(...).unwrap_or([0u8; 32])` all-zero webhook-key fallback is gone; `webhook_enc_key` is now `Option<[u8; 32]>` with no constant fallback, matching the PKI `encryption_key` template already in the same file.
- Closed SEC-031: `create` and `update` webhook handlers now call `WebhookDeliveryService::encrypt_secret()` before persisting — the previously-orphaned `encrypt_webhook_secret` helper (fully implemented and unit-tested but called from nowhere) is now the sole path secrets take on write.
- `WebhookDeliveryService.deliver()` refuses to decrypt (logs an error and returns) when no encryption key is configured, rather than ever calling `aes256gcm_decrypt` with a placeholder key.
- Added a secret-rotation path: `UpdateWebhookRequest`/`UpdateWebhook` gain `secret: Option<String>`; the repository `update()` conditionally `SET`s `secret` only when a rotation value is present.
- Two new proving negative tests: fail-closed registration returns 503 (never a silent 201) with no key configured, and the persisted secret is ciphertext that differs from the submitted plaintext but decrypts back to it.
- No `web::Data<Option<[u8;32]>>` type collision was introduced — the webhook key is routed exclusively through the uniquely-typed `WebhookDeliveryService`, confirmed by grep showing only the pre-existing email-key registration at `main.rs:681`.

## Task Commits

Each task was committed atomically:

1. **Task 1: Fail-closed key + WebhookDeliveryService.encrypt_secret + refuse delivery when key absent (D-01)** - `ce80130` (fix)
2. **Task 2: Encrypt secret on create AND update; add secret-rotation update DTO (D-02)** - `099d2ab` (fix)
3. **Task 3: Negative tests — fail-closed on missing key + stored ciphertext ≠ plaintext** - `4135f51` (test)

**Plan metadata:** (this commit, docs)

## Files Created/Modified

- `crates/axiam-server/src/main.rs` - `webhook_enc_key` is `Option<[u8; 32]>` via `load_key_from_env`, no `unwrap_or` fallback
- `crates/axiam-api-rest/src/webhook.rs` - `WebhookDeliveryService.encryption_key: Option<[u8;32]>`; new `encrypt_secret()` method; new `WebhookError::{EncryptionKeyMissing, SecretEncrypt}` variants; `From<WebhookError> for AxiamApiError`; `deliver()` checks `None` first
- `crates/axiam-core/src/error.rs` - new `AxiamError::ServiceUnavailable(String)` variant
- `crates/axiam-api-rest/src/error.rs` - maps `ServiceUnavailable` to HTTP 503 with a client-facing (non-sensitive) message
- `crates/axiam-api-rest/src/handlers/webhooks.rs` - `create`/`update` handlers take `WebhookDeliveryService`, call `encrypt_secret()` before persisting; `UpdateWebhookRequest` gains `secret: Option<String>`
- `crates/axiam-core/src/models/webhook.rs` - `UpdateWebhook` gains `secret: Option<String>`
- `crates/axiam-db/src/repository/webhook.rs` - `update()` conditionally `SET`s `secret` only when rotation value present
- `crates/axiam-api-rest/src/server.rs` - `register_api_v1_routes<C>` gains a `Clone` bound (required by the handler changes above)
- `crates/axiam-api-rest/tests/webhook_test.rs` - `test_app!` macro now constructs/registers a real `WebhookDeliveryService`; 2 new negative tests

## Decisions Made

- Added `AxiamError::ServiceUnavailable(String)` -> HTTP 503 rather than reusing the existing `AxiamError::Internal`/`WebhookDelivery` 500 variants — a missing encryption key is an operator-fixable condition (configure `AXIAM__PKI__ENCRYPTION_KEY`), not an internal bug, and stating "webhook subsystem unavailable" leaks no crypto/DB internals, so it's safe to echo directly to the caller (same treatment as the existing `RateLimited`/`EmailConfig` client-facing variants).
- `register_api_v1_routes<C: surrealdb::Connection>` gained a `+ Clone` bound. This was a necessary consequence of Task 2: the generic `create<C>`/`update<C>` handlers now take `web::Data<WebhookDeliveryService<SurrealWebhookRepository<C>>>`, and `WebhookDeliveryService`'s inherent methods (pre-existing, unchanged) require `W: Clone`. Both concrete connection types used at call sites (`DbClient` for production, local `Db` for tests) already implement `Clone`, so this is a compile-time-only widening with no runtime behavior change.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `Clone` bound to `register_api_v1_routes<C>`**
- **Found during:** Task 2 (encrypt secret on create/update)
- **Issue:** Adding `webhook_delivery: web::Data<WebhookDeliveryService<SurrealWebhookRepository<C>>>` to the generic `create<C>`/`update<C>` handlers didn't compile: `SurrealWebhookRepository<C>: Clone` (needed by `WebhookDeliveryService`'s `encrypt_secret`) requires `C: Clone`, which the generic bound on `register_api_v1_routes<C: surrealdb::Connection>` didn't carry.
- **Fix:** Added `+ Clone` to `register_api_v1_routes<C>`'s bound and to `create<C>`/`update<C>`'s own bounds. Verified both production (`DbClient`) and test (`local::Db`) connection types already derive `Clone`.
- **Files modified:** `crates/axiam-api-rest/src/server.rs`, `crates/axiam-api-rest/src/handlers/webhooks.rs`
- **Verification:** `cargo build -p axiam-api-rest` and `cargo build -p axiam-server` succeed
- **Committed in:** `099d2ab` (Task 2 commit)

**2. [Rule 3 - Blocking] Added `AxiamError::ServiceUnavailable` variant + `From<WebhookError>` mapping**
- **Found during:** Task 1 (fail-closed key + encrypt_secret)
- **Issue:** The plan calls for a "503-style webhook subsystem unavailable" error but no such `AxiamError` variant existed, and `WebhookError` (the `webhook.rs`-local error type) had no path into `AxiamApiError` for use with `?` in handlers.
- **Fix:** Added `AxiamError::ServiceUnavailable(String)` (maps to HTTP 503, client-facing message) and `impl From<WebhookError> for AxiamApiError` in `webhook.rs`, so handlers can use `webhook_delivery.encrypt_secret(&req.secret)?` directly.
- **Files modified:** `crates/axiam-core/src/error.rs`, `crates/axiam-api-rest/src/error.rs`, `crates/axiam-api-rest/src/webhook.rs`
- **Verification:** `create_webhook_fails_closed_without_encryption_key` asserts 503 + `error: "service_unavailable"`
- **Committed in:** `ce80130` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 3 - blocking compile/design gaps directly required by the plan's own acceptance criteria)
**Impact on plan:** Both changes were structurally necessary to satisfy the plan's literal acceptance criteria (a 503-style error; the generic handlers calling `encrypt_secret`). No scope creep — no other endpoints or crates touched.

## Issues Encountered

- **Sandbox environment build prerequisites were missing** (unrelated to this plan's code): `libxml2-dev` and `libxmlsec1-dev` (required transitively by the `samael` SAML dependency) were not installed; installed via `apt-get install -y libxml2-dev libxmlsec1-dev xmlsec1`. `utoipa-swagger-ui`'s build script needs to download a Swagger UI zip from GitHub, which this sandbox's session cannot reach (a pre-existing, documented limitation — see `claude_dev/code-review-postremediation.md`: "utoipa-swagger-ui fetches an asset at build time (needs network or a pre-seeded `SWAGGER_UI_DOWNLOAD_URL`)"). Worked around locally by pointing `SWAGGER_UI_DOWNLOAD_URL` at a minimal placeholder zip built in the scratchpad directory — this is a local build-only environment variable, not a code or config change, and does not affect the committed diff.
- **Sandbox disk space was exhausted mid-verification** (unrelated to this plan's code): the root filesystem hit 0 bytes available during `cargo clippy -p axiam-server`, caused by ~24GB of accumulated `target/debug` build artifacts (mostly `incremental/`) from this and prior plans' builds. Freed space by deleting `target/debug/incremental` (safe — forces recompilation without incremental caching, no effect on correctness) and clearing stale background-task output buffers. All verification commands were then re-run successfully to completion.
- No issues in the actual webhook/encryption logic itself — all three tasks matched the plan's design as written.

## User Setup Required

None - no external service configuration required. (Operators should ensure `AXIAM__PKI__ENCRYPTION_KEY` is set in production so webhook registration/delivery is not refused; this was already a requirement for PKI/CA operations per SEC-012.)

## Next Phase Readiness

- SECFIX-03 is closed: fail-closed key handling, encrypt-on-write (create + update), secret rotation, and both proving negative tests are in place and green.
- This plan is an explicit prerequisite for CORR-03 (webhook delivery wiring via AMQP, Phase 26) — the delivery path can now safely decrypt what was encrypted here.
- No blockers for the remaining Phase 23 plans (SECFIX-04 SAML, SECFIX-05 logout, SECFIX-06 reset/resend, gRPC lockout).

---
*Phase: 23-security-regressions-high-findings*
*Completed: 2026-07-03*

## Self-Check: PASSED

- All 9 modified files verified present on disk.
- All 3 task commits (`ce80130`, `099d2ab`, `4135f51`) verified present in git log.
