# Test-Coverage Round 2 — axiam server + C SDK (2026-07-23, evening baseline)

> Continuation of [`test-coverage-improvement-plan.md`](test-coverage-improvement-plan.md) (#227),
> scoped to the two repos still flagged on Coveralls: **ilpanich/axiam** and **ilpanich/axiam-c-sdk**.
> Baseline re-measured from the latest successful `coverage.yml` runs on `main`:
> axiam run **30040595860** (commit `604cbdf7`), axiam-c-sdk run **30024340260** (commit `854d0f7e`).
> Working branch for both repos: **`claude/test-coverage-improvement-douzbt`**.

## 1. Where we stand vs. the morning plan

| Item (morning plan) | Status now |
|---|---|
| A0 gRPC client-feature instrumentation | **Done** — `grpc_auth_test`/`grpc_userinfo_test` are in `coverage.yml`; axiam-api-grpc now 93.72% |
| A0 `main.rs` decision | **Open** — still 0% (668 instrumented lines) |
| A1 api-rest handler paths | **Partial** — crate 74.70% → 81.96% (webauthn/gdpr done; federation, webhook_consumer, auth, webhook still low) |
| A2 amqp consumers/publishers | **Open** — crate still 41.17% |
| A3 server cleanup.rs | **Open** — still 3.98% |
| A4 federation SAML | **Open** — `saml.rs` still 48.9% |
| A5 axiam-db | **Partial** — 84.44% → 87.86% (seeder/connection/nonce-replay remain) |
| A6 sweep | **Partial** — auth 90.45%, oauth2 88.90%, pki 89.73% |
| A7 ratchets | **Open** — floor still 77 |
| Phase D (C SDK) | **Done** — src/ line coverage 90.0% → **98.8%**, gate added (`--fail-under-line 96`) |

**axiam Rust workspace today: 82.08% lines (34,217 total, 6,131 missed).**
To reach 90%, missed lines must drop to ≤ 3,422 → **~2,710 more lines to cover** (less if
`main.rs` is excluded from the denominator, see R2). Frontend is at ~95.8% and needs no test work;
the Rust workspace is the entire lever on the merged Coveralls number.

Per-crate (lines / missed / coverage):

| Crate | Lines | Missed | Cov |
|---|---|---|---|
| axiam-server | 1,488 | 1,152 | **22.58%** |
| axiam-amqp | 1,280 | 753 | **41.17%** |
| axiam-federation | 2,431 | 644 | **73.51%** |
| axiam-api-rest | 8,048 | 1,452 | **81.96%** |
| axiam-db | 10,948 | 1,329 | 87.86% |
| axiam-oauth2 | 1,460 | 162 | 88.90% |
| axiam-audit | 405 | 42 | 89.63% |
| axiam-pki | 711 | 73 | 89.73% |
| axiam-auth | 3,842 | 367 | 90.45% |
| axiam-authz | 569 | 40 | 92.97% |
| axiam-api-grpc | 605 | 38 | 93.72% |
| axiam-email | 1,017 | 37 | 96.36% |
| axiam-core | 1,413 | 42 | 97.03% |

**axiam-c-sdk today: 98.8% lines (1,034/1,047), 100% functions, 70.9% branches** on the
gcovr-filtered `src/` layer. If Coveralls still displays < 90% for this repo, the number is stale
or misread (see task C1) — the uploaded `coveralls.json` from `main` carries 98.8%.

## 2. Model-selection policy (unchanged)

Same as §2 of the morning plan — **Sonnet** for pattern-following test authoring where this plan
names the files, branches, and harness to copy; **Opus** where real judgment is needed (testability
seams/refactors, security-sensitive negative-path design). A stalled Sonnet job escalates to Opus
rather than padding. Ground rules §3 of the morning plan apply verbatim (additive tests only,
measure first, reuse harnesses, disk hygiene incl.
`SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`,
gates ratcheted 1–2 pts below achieved) — only the branch name changes to
`claude/test-coverage-improvement-douzbt`.

## 3. axiam — remaining tasks to ≥90%

Estimated gains use today's per-file missed-line counts; they drift as `main` moves — re-measure
per crate before starting (`cargo llvm-cov -p <crate> --no-fail-fast --summary-only`,
`cargo clean` between crates).

### R1. axiam-amqp seam + consumer/publisher tests — Model: **Opus** (L) · ~+600 lines
Zero-covered: `src/authz_consumer.rs` (182 missed), `src/audit_consumer.rs` (172),
`src/connection.rs` (144), `src/mail_publisher.rs` (39), `src/notification_publisher.rs` (35);
low: `src/webhook_publisher.rs` (58 missed, 39.6%), `src/mail_consumer.rs` residual (100 missed).
The consume/publish loops are entangled with `lapin::Channel`; there is no lapin mock. Opus designs
a minimal seam — mirror `mail_consumer.rs`'s "extract pure logic out of the consume loop" pattern
(`send_with_retry_and_audit`) or a small trait over channel/ack — so decode/dispatch/nack-drop and
RBAC-evaluation branches become unit-testable with the trait-mock repos from `tests/mail_send.rs`
and kv-mem `setup_db()` from `tests/mail_consumer_test.rs`. CI has a live RabbitMQ service for
whatever remains transport-bound (topology declarations in `connection.rs`); live tests must also
pass locally via `just dev-up` or be `#[ignore]`d with the logic tested broker-free.
*Opus because the seam design is the task; the tests themselves are mechanical once it exists.*

### R2. axiam-server `main.rs` — Model: **Opus** (M) · ~+670 lines effective
`src/main.rs`: 668 instrumented lines at 0%. Extract cheap, testable pieces (config assembly,
service-wiring builders) into `lib.rs`-exported functions with unit tests; exclude the residual
process-lifecycle glue via `--ignore-filename-regex` in `coverage.yml` (or
`#[cfg_attr(coverage_nightly, coverage(off))]`). Either covering or excluding moves the workspace
~2 points; flag the exclusion decision in the PR description for the human.
*Opus because it is a structural refactor of the binary that composes every subsystem.*

### R3. axiam-server `cleanup.rs` — Model: **Sonnet** (M) · ~+380 lines
`src/cleanup.rs` (434 missed, 3.98%): multi-table expiry sweeps (federation/replay rows, GDPR
purges, export jobs) + per-table error handling and partial-failure continuation. Pure Mem-DB
work — copy the `Surreal::new::<Mem>` setup from `tests/cleanup_task.rs` (5 tests exist to extend).

### R4. axiam-api-rest residual paths — Model: **Sonnet** (M/L) · ~+850 lines
Copy the per-file sibling `tests/*_test.rs` app-builder (kv-mem + `actix_web::test`); wiremock IdP
pattern in `tests/federation_first_time_sso_test.rs`:
- `src/handlers/federation.rs` (380 missed, 52.5%) — SSO initiate/ACS/callback error paths, bad
  state, IdP failures, config-CRUD validation arms. Feature-gated SAML arms count too (`saml` is
  default-on in CI).
- `src/webhook_consumer.rs` (177 missed, 25.9%) — delivery failure/retry/HMAC branches broker-free;
  extend `tests/webhook_consumer_test.rs`.
- `src/handlers/auth.rs` (136 missed, 71.1%) — MFA/lockout/session-edge branches.
- `src/webhook.rs` (88 missed, 63.9%) and `src/handlers/password_reset.rs` (74 missed).
- Small-S sweep: `handlers/permissions.rs` (41), `handlers/tenants.rs` (36),
  `handlers/oauth2_clients.rs` (35), `extractors/cert_auth.rs` (32), `handlers/webauthn.rs` (28),
  `handlers/bootstrap.rs` (28), `handlers/oauth2.rs` (29), `extractors/rate_limit.rs` (28),
  `src/health.rs` (22, 42.1%), `middleware/rate_limit_shared.rs` (20).

### R5. axiam-federation — Model: **Opus** (L) · ~+350 lines
- `src/saml.rs` (462 missed, 48.9%): the improvable slice is the **non-xmlsec logic** —
  AuthnRequest construction, redirect-binding deflate+base64, RelayState, attribute/NameID
  extraction, replay detection, provisioning/linking — using the in-src `Noop*Repo`/`MemReplayRepo`
  + `make_service()` harness. Signature negative paths reuse the committed fixtures
  (`tests/fixtures/saml/`, regenerable via `generate.sh`); do not hand-craft signed XML.
- `src/oidc.rs` (107 missed, 85.6%): `provision_new_user`, token-exchange error arms,
  account-linking branches (wiremock + self-minted JWKS pattern already in-src).
- `src/discovery_cache.rs` (31 missed) SWR/expiry edges.
Accept that xmlsec-FFI verification internals stay partially uncovered; report the residual rather
than padding. *Opus per A4 rationale: wrong negative-path tests here would certify broken
signature validation.*

### R6. axiam-db residuals — Model: **Sonnet** (M) · ~+350 lines
Mem-friendly targets: `src/seeder.rs` (136 missed), `src/repository/amqp_nonce_replay.rs`
(61, **0%**), `src/pool.rs` (58), `repository/user.rs` (82), `repository/webhook.rs` (49),
`repository/certificate.rs` (49), `repository/settings.rs` (48), `repository/federation_config.rs`
(40), `repository/resource.rs` (39). Still **skip** `src/connection.rs` remote/retry/TLS branches
(183 missed — needs a live `ws://` server; low yield, flaky locally).

### R7. Sweep to lock ≥90% — Model: **Sonnet** (S/M) · ~+300 lines
`axiam-oauth2/src/authorize.rs` (119 missed: bad client, redirect_uri mismatch, PKCE errors —
patterns in api-rest `tests/oauth2_flow_test.rs`); `axiam-auth/src/password_reset.rs` (119) and
`src/webauthn.rs` (81); `axiam-pki/src/pgp.rs` (35); `axiam-audit/src/notification.rs` (33);
`axiam-email/src/providers/smtp.rs` (22 — unreachable-SMTP `127.0.0.1:1` injection pattern).

### R8. Ratchet gates — Model: **Sonnet** (S)
After re-measuring: raise `coverage.yml` `--fail-under-lines` from 77 to (achieved − 2); add
`coverage.thresholds.lines: 93` + text-summary reporter to `frontend/vitest.config.ts`.

**Budget check:** R1–R7 sum to ≈ +2,900 covered lines against the ~2,710 needed (R2 also shrinks
the denominator if exclusion is chosen), leaving slack for estimates that miss. If after R1–R7 the
workspace is still short, report the achieved number and the marginal cost — don't pad.

**Sequencing:** R3/R4/R6/R7 (Sonnet) are independent and parallelizable per-crate; R1/R2/R5 (Opus)
run whenever; R8 strictly last. Disk hygiene: `cargo clean` between crate-scoped steps.

## 4. axiam-c-sdk — tasks

Line coverage is already 98.8% with a 96 gate; work here is reconciliation + branch depth, not a
line push.

### C1. Reconcile the Coveralls display — Model: **Sonnet** (S)
Coveralls was reported (user observation, 2026-07-23) as showing the repo below 90% "across all the
repo", yet `main`'s upload carries 98.8% lines. Likely causes, in order: the page/badge showing a
**stale build** (yesterday's 90.0% pre-Phase-D state), a **non-main branch** selected, or the
**branch-coverage figure (70.9%)** being read. Verify on coveralls.io (needs a human or a network
egress that allows coveralls.io — this sandbox's proxy blocks it), confirm the default-branch badge
reflects run 30024340260+, and note that `coverage.yml` triggers on `push: branches: ["**"]`, so
low-coverage WIP branches also publish builds — consider restricting push-trigger uploads to
`main` (keep the `pull_request` trigger) so branch experiments can't muddy the repo page.

### C2. Branch-coverage depth: 70.9% → ≥80% — Model: **Sonnet** (M)
All harnesses exist (mock transport + `test_recorder_t` in `tests/test_util.h`, loopback fixture
servers, `jwt_fixture.c` Ed25519 minting). Target the known thin branches:
- `src/client.c`: `parse_login_like` with unparseable 2xx body; `axiam_check_access`/
  `axiam_batch_check` 2xx-but-invalid-JSON arms and `results` array shorter/longer than `n`
  (the `i >= n` break); `resolve_ids_from_login` cookie edges (attributes vs. bare token, missing
  `axiam_access=`, decode failure preserving prior values).
- `src/guard.c`: `extract_token` malformed/extra-space `Authorization` arms; `require_role` with
  absent or non-array `roles` claim.
- `src/jwks.c`: `parse_jwks` base64url-decode failure on `x`, short/oversized key material.
- Remaining uncovered lines: `client.c` 16-17, 21-23, 37-39; `config.c` 83-84; `sensitive.c`
  19-20; `util.c` 77 — cover or annotate.
Then add `--fail-under-branch 78` (2 pts under achieved) next to the existing line gate.

### C3. Real TLS/mTLS handshake test — Model: **Opus** (M, optional)
Today the mTLS blob wiring (`CURLOPT_CAINFO_BLOB`/`SSLCERT_BLOB`/`SSLKEY_BLOB`) is executed only
against a closed port — no successful handshake is ever proven. Build a loopback **OpenSSL
`SSL_accept` fixture server** on a background thread using the existing `gen_pki.sh` CA/cert/key
fixture, and assert one authenticated HTTPS round-trip incl. a client-cert-required path. *Opus
because the harness design (thread lifecycle, deterministic shutdown, no hangs in CI) is the hard
part; escalating only this keeps the rest of the phase on Sonnet.*

### C4. OOM/allocation-failure arms — **Not recommended**
Covering `malloc`/`calloc` failure branches needs an injectable allocator (invasive refactor) for
negligible risk reduction. Leave uncovered; optionally annotate with `GCOVR_EXCL_LINE` if the
branch gate from C2 needs the headroom — but prefer honest numbers.

## 5. Effort & model summary

| Task | Repo | Model | Size | Est. gain |
|---|---|---|---|---|
| R1 amqp seam + tests | axiam | **Opus** | L | ~+600 lines |
| R2 main.rs extract/exclude | axiam | **Opus** | M | ~2 pts workspace |
| R3 cleanup.rs | axiam | Sonnet | M | ~+380 |
| R4 api-rest residuals | axiam | Sonnet | M/L | ~+850 |
| R5 federation saml/oidc | axiam | **Opus** | L | ~+350 |
| R6 axiam-db residuals | axiam | Sonnet | M | ~+350 |
| R7 sweep | axiam | Sonnet | S/M | ~+300 |
| R8 ratchet gates | axiam | Sonnet | S | — |
| C1 Coveralls reconciliation | c-sdk | Sonnet | S | display fix |
| C2 branch depth + branch gate | c-sdk | Sonnet | M | branches 70.9→≥80% |
| C3 TLS handshake fixture | c-sdk | **Opus** | M (opt.) | closes last real gap |
| C4 OOM arms | c-sdk | — | — | skipped by design |

Roughly ⅔ of the work runs on Sonnet; Opus is reserved for the three seam/security-design tasks
(R1, R2, R5) plus the optional C3 harness.
