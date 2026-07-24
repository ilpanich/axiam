# AXIAM Coverage Plan — Coveralls ≥90% (2026-07-24)

Goal: push the **Coveralls badge for `ilpanich/axiam`** from **89.32% to over 90%**.
Scope is this repository only (server workspace + frontend); SDK repos are out of scope here.

Numbers below were measured from the Coveralls build for `main` @ `6feb6ec`
(merge of PR #228, Coveralls build 80767130 / CI run 30075155210) and the per-file
`cargo llvm-cov report` table printed by that run's "Enforce coverage floor" step.

## 1. Where we are and how big the gap really is

| Metric (Coveralls build 80767130) | Value |
|---|---|
| Combined line coverage (badge) | **89.32%** (32,124 / 35,989 lines, 3,865 missed) |
| Branch coverage | 90.48% (1,682 / 1,859) |
| Rust workspace (llvm-cov, `main.rs` excluded) | **86.61%** (30,284 / 34,964 table lines, 4,680 missed) |
| Frontend (vitest) | ~95.8% — **needs no work** |
| CI gate | `--fail-under-lines 80` in `coverage.yml` |

The gap lives entirely in the Rust workspace. Two accounting systems are in play:

- **Coveralls math**: at constant relevant-line count, 90.0% needs **≥32,391 covered
  lines → +267 newly covered lines** (Coveralls/lcov accounting). All of it must come
  from Rust (frontend is already near-ceiling).
- **llvm-cov math** (what executors measure locally): the lcov export Coveralls ingests
  counts fewer lines than the llvm-cov summary table (≈25.6k vs 34,964 for the same
  code — rates match, absolute counts don't). Working the algebra back from the
  Coveralls totals: the workspace llvm-cov rate must reach **≈87.7%** for the badge to
  hit exactly 90.0%. Plan target: **≥88.5% llvm-cov** (≈ +660 table lines) so the badge
  lands ~90.3–90.5% with margin, not 90.0-and-praying.

Every executor verifies against the **local llvm-cov TOTAL** (fast feedback); the badge
is confirmed once at the end via the CI run on `main`/the PR.

## 2. Per-crate state (llvm-cov table lines, `main.rs` excluded)

| Crate | Lines | Missed | Cover | Notes |
|---|---|---|---|---|
| axiam-db | 10,984 | 1,106 | 89.93% | spread across repositories; `connection.rs` 32.7% is low-yield (live-server paths) |
| axiam-api-rest | 8,104 | 1,087 | 86.59% | `webhook_consumer.rs` 25.9%, `health.rs` 42.1%, `handlers/federation.rs` 73.3% |
| axiam-auth | 3,908 | 366 | 90.63% | `webauthn.rs` 67.3%, `password_reset.rs` 86.4% |
| axiam-federation | 3,734 | 681 | 81.76% | `saml.rs` 71.0% (479 missed — single worst file), `oidc.rs` 88.0% |
| axiam-oauth2 | 1,460 | 162 | 88.90% | `authorize.rs` 79.8% |
| axiam-amqp | 1,234 | 553 | 55.19% | `connection.rs` **0%**, both small publishers **0%**, consumers 42–65% |
| axiam-email | 1,017 | 37 | 96.36% | done |
| axiam-server | 820 | 472 | 42.44% | **`cleanup.rs` 6.64% (422 missed) — biggest single lever**; `tls.rs` 86.4% |
| axiam-pki | 711 | 54 | 92.41% | polish only |
| axiam-api-grpc | 605 | 38 | 93.72% | `server.rs` 74.0% residuals |
| axiam-authz | 569 | 40 | 92.97% | polish only |
| axiam-audit | 405 | 42 | 89.63% | polish only |
| axiam-core | 1,413 | 42 | 97.03% | done |

## 3. Model-selection policy (Opus vs Sonnet)

"Best but cheapest that can do the job well":

- **Sonnet** — the default. Every task where this plan already names the target files,
  the uncovered branches, and an existing harness to copy. That is deliberately almost
  all of the work: the two rounds already done built harnesses for every subsystem.
- **Opus** — only where real judgment is required: security-sensitive negative-path
  design (SAML), and AMQP work that mixes seam design with live-broker CI-only
  verification. Both Opus tasks are **contingency tasks** here — the Sonnet tasks alone
  over-shoot the target ~2×, so Opus is spent only if re-measurement shows a shortfall
  (or the user wants the AMQP/SAML debt paid down anyway).
- If a Sonnet run stalls (target untestable without a refactor this plan didn't call
  for), stop and escalate that one task to Opus — don't pad with low-value tests.

## 4. Ground rules for every executor

1. Branch: work on the designated `claude/…` feature branch for the execution session;
   never push elsewhere; no PR unless asked.
2. **Additive tests only.** Production code changes only for an explicitly named seam
   or a real bug found while testing (called out in the commit message).
3. **Measure first, per crate**: `cargo llvm-cov -p <crate> --no-fail-fast --summary-only`
   — line numbers in this plan drift as `main` moves.
4. Disk hygiene (sandbox quota ~38 GB): scoped cargo commands only; `cargo clean`
   between tasks (never mid-run); for anything touching `axiam-api-rest` or its
   dependents: `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`.
5. Reuse the existing harnesses (named per task); don't build new scaffolding where one exists.
6. Definition of done per task: suite green + per-crate llvm-cov re-measured + short
   before/after note in the commit message.

## 5. Tasks (ordered by yield per unit of cost)

Existing harnesses referenced below: in-memory SurrealDB pattern (`Surreal::new::<Mem>` +
`run_migrations`, e.g. `crates/axiam-server/tests/cleanup_task.rs`,
`crates/axiam-api-rest/tests/auth_test.rs`); Actix `TestRequest`; wiremock 0.6 (dev-dep in
api-rest, email, federation, server); SAML fixtures `crates/axiam-federation/tests/fixtures/saml/`
(+ `generate.sh`); AMQP message fixtures `crates/axiam-amqp/tests/fixtures/`; tonic harness
`crates/axiam-api-grpc/tests/grpc_auth_test.rs`.

### T1. `axiam-server/src/cleanup.rs` — 6.64%, 422 missed — Model: **Sonnet** (M) · ~+330–380
The single biggest lever, one file, harness already in place. `tests/cleanup_task.rs`
deliberately tested only the *repositories* the task calls (its header cites a
local-compile limitation with the xmlsec feature — that limitation is environmental, not
architectural; CI installs `libxmlsec1-dev`). `CleanupTask<C: Connection>` is generic
over the DB connection, so it runs against `Mem`:
- Construct `CleanupTask` directly, drive `run()` with short intervals + the existing
  `watch`-shutdown pattern; assert expired sessions/tokens/replay rows/login states are
  swept and live rows survive.
- Per-sweep error branches (make one repo call fail; loop continues).
- Remaining `run_erasure_pipeline` branches (partial-failure proof paths).
If the xmlsec feature genuinely blocks compiling `axiam-server` tests in the sandbox,
develop against `cargo check -p axiam-server --tests` + push and verify via CI — do not
convert this into a refactor.

### T2. `axiam-api-rest` non-handler residuals — Model: **Sonnet** (M) · ~+230–280
- `src/webhook_consumer.rs` (25.9%, 177 missed): `start_webhook_consumer<W, A>` is
  already generic — drive it with fake repo/transport impls + wiremock receiver;
  delivery success / non-2xx / timeout → retry with `backoff_ttl_ms` growth; HMAC header;
  `WebhookRetryConfig::from_env` parse fallbacks. Extend `tests/webhook_consumer_test.rs`.
- `src/webhook.rs` (79.5%, 50 missed): signing/dispatch error arms.
- `src/health.rs` (42.1%, 22 missed): `ready` degraded/unready branches with a Mem-DB
  `AppState`.
- `src/handlers/password_reset.rs` (78.6%, 72 missed) + `extractors/rate_limit.rs`
  (81.3%, 28) + `middleware/rate_limit_shared.rs` (82.6%, 20): invalid-token, expired,
  rate-limited, cross-tenant branches via Actix `TestRequest`.

### T3. `axiam-db` repository residuals — Model: **Sonnet** (M) · ~+250–300
All Mem-DB-friendly CRUD/edge branches: `repository/user.rs` (79 missed),
`repository/email_config.rs` (77), `seeder.rs` (68), `pool.rs` (48), then the 20–30-missed
band: `audit.rs`, `ca_certificate.rs`, `permission.rs`, `group.rs`, `service_account.rs`,
`webhook.rs`, `pgp_key.rs`, `tenant.rs`, `settings.rs`, `account_deletion.rs`.
**Skip `connection.rs`** (32.7%, 183 missed): remote/retry/TLS branches need a live
server for ~1 file of yield — worst cost/benefit in the crate.

### T4. `axiam-oauth2` + `axiam-auth` residuals — Model: **Sonnet** (M) · ~+250–300
- oauth2 `src/authorize.rs` (79.8%, 119 missed): bad client, redirect_uri mismatch,
  PKCE method/verifier errors, prompt/consent branches (patterns in
  `crates/axiam-api-rest/tests/oauth2_flow_test.rs`); `token.rs` residual arms (25).
- auth `src/password_reset.rs` (86.4%, 118 missed): expiry, reuse, history-conflict,
  lockout interaction branches.
- auth `src/webauthn.rs` (67.3%, 81 missed): begin/finish failure arms with bad
  challenge/origin/tenant (webauthn config example: `tests/middleware_test.rs`).
- Small: `mfa_methods.rs` (19), `policy.rs` (26).

### T5. `axiam-api-rest/src/handlers/federation.rs` + `axiam-federation/src/oidc.rs` — Model: **Sonnet** (M) · ~+180–230
Handler layer (73.3%, 214 missed): SSO initiate/callback error paths — unknown provider,
bad/expired state, IdP error responses via a wiremock IdP (`tests/federation_test.rs`,
`federation_first_time_sso_test.rs` exist to extend). Federation `oidc.rs` (88.0%,
142 missed): discovery/JWKS fetch failures, token-response error arms, claim-validation
rejects — these are enumerable error branches, not new validation design, so Sonnet is
safe here (unlike SAML below).

### T6. Small-file sweep to lock the margin — Model: **Sonnet** (S) · ~+120–160
`axiam-server/src/tls.rs` (86.4%, 50 missed — bad PEM/cipher/config arms of
`build_rustls_server_config`); `axiam-api-grpc/src/server.rs` (74.0%, 19);
`axiam-api-rest/src/handlers/tenants.rs` (77.4%, 36), `oauth2_clients.rs` (84.4%, 35);
`axiam-audit/src/notification.rs` (88.6%, 33); `axiam-authz/src/engine.rs` residuals (24);
`axiam-email/src/providers/smtp.rs` (77.1%, 22).

### T7. `axiam-amqp` crate — 55.2%, 553 missed — Model: **Opus** (L) · ~+300–400 · **contingency**
Two rounds have only partially cracked this crate (consumers now 42–65%, but
`connection.rs`/`mail_publisher.rs`/`notification_publisher.rs` are 0% and
`webhook_publisher.rs` 39.6%). The blocker is architectural: `AmqpManager` and the
publishers talk to a live broker. Opus should decide, per file, between:
- **live-broker integration tests** — CI's coverage job already runs RabbitMQ, so
  `connect`/`declare_queues`/`declare_webhook_topology`/publish round-trips are coverable
  there (env-gated like the existing AMQP tests; sandbox verification via `just dev-up`
  where possible, otherwise CI);
- `connect_with_retry` failure arms via an unroutable port (no broker needed);
- extending the existing seam pattern for the remaining consumer dispatch branches
  (`authz_consumer.rs` 42%, `audit_consumer.rs` 60%, `mail_consumer.rs` 65%) using
  `tests/fixtures/` vectors.
Opus because it mixes seam design, CI-only verifiability, and judgment about which lines
are worth chasing — a Sonnet run here historically stalls at the transport boundary.

### T8. `axiam-federation/src/saml.rs` — 71.0%, 479 missed — Model: **Opus** (L) · ~+200–280 · **contingency**
The single worst file. Remaining misses are negative-path validation: tampered/replayed/
expired assertions, signature-wrapping variants, condition/audience failures, encoding
errors. Fixtures exist (`tests/fixtures/saml/` + `generate.sh`; pattern in
`tests/secrets_and_errors.rs`). Opus because wrong tests here would *certify broken
signature validation* — the test author must reason about what each attack class must
fail on, not just make lines green.

### T9. Re-measure + ratchet the gate — Model: **Sonnet** (S)
Full-workspace `cargo llvm-cov --workspace --no-fail-fast` (+ the gRPC client-feature
step exactly as `coverage.yml` does), confirm TOTAL ≥88.5%, push, confirm the Coveralls
badge >90% on the CI run, then ratchet `--fail-under-lines` in `coverage.yml` from 80 to
**(achieved − 2)** so the badge can't silently regress below 90% later. Optionally add
`coverage.thresholds.lines` to `frontend/vitest.config.ts` (still absent) to pin the
frontend side.

## 6. Execution order & budget

| Order | Task | Model | Effort | Est. yield (llvm-cov lines) |
|---|---|---|---|---|
| 1 | T1 cleanup.rs | Sonnet | M | +330–380 |
| 2 | T3 db residuals | Sonnet | M | +250–300 |
| 3 | T2 api-rest residuals | Sonnet | M | +230–280 |
| 4 | T4 oauth2 + auth | Sonnet | M | +250–300 |
| 5 | T5 federation handlers + oidc | Sonnet | M | +180–230 |
| 6 | T6 small-file sweep | Sonnet | S | +120–160 |
| — | **checkpoint: re-measure** — need ≥ +660 vs baseline; T1–T6 target +1,360–1,650 | | | |
| 7 | T7 amqp (only if short / debt paydown) | Opus | L | +300–400 |
| 8 | T8 saml.rs (only if short / debt paydown) | Opus | L | +200–280 |
| 9 | T9 measure + ratchet gate | Sonnet | S | lock-in |

T1–T6 are independent (different crates/files) and parallelizable, subject to the disk
budget — in a quota-limited sandbox run them **sequentially with `cargo clean` between
tasks** rather than truly in parallel. The Sonnet block alone targets roughly double the
required +660 lines, so the expected outcome is **90%+ with zero Opus spend**; T7/T8
exist for the shortfall case and as the map for retiring the two remaining structural
debt spots (AMQP transport, SAML negative paths).
