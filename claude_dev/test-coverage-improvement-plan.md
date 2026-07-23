# AXIAM Test-Coverage Improvement Plan — 2026-07-23 (server + 11 SDKs)

> Supersedes [`test-coverage-plan.md`](test-coverage-plan.md) (whose phases were largely executed;
> see per-repo notes). Numbers below were measured fresh on 2026-07-23 from the latest successful
> `coverage.yml` CI run on `main` of each repo (run IDs cited inline), or from a local run at the
> same commit where CI logs don't print a total. Working branch for all repos:
> **`claude/test-coverage-improvement-plan-idxnfc`**.

## 1. Current coverage status (all 12 repos)

| Repo | Line coverage | Source | CI gate | Below 90%? |
|---|---|---|---|---|
| **axiam (Rust workspace)** | **78.92%** | CI run 29956077825, 2026-07-22 | yes, `--fail-under-lines 77` | **YES — main effort** |
| axiam (frontend, vitest) | 95.82% | local lcov @ same commit | none | no |
| **axiam-php-sdk** | **88.30%** | local phpunit @ CI commit 36fcb44 (CI log prints no total; Coveralls job 185018771) | **none** | **YES** |
| **axiam-rust-sdk** | **89.34%** | CI run 29949610590, 2026-07-22 | yes, `--fail-under-lines 89` | **YES** |
| **axiam-c-sdk** | **90.0%** (950/1047) | CI run 29943785116, 2026-07-22 | **none** | borderline — treat as YES |
| **axiam-kotlin-sdk** | **91.28%** (513/562) | local Gradle/Kover @ CI commit 334a1b9 (CI log prints no %; Coveralls job 185018850) | declared (Kover `minBound(88)`) but **NOT enforced** — CI runs `koverVerify \|\| true` | borderline — treat as YES |
| axiam-java-sdk | 93.84% (1081/1152) | local `mvn verify` jacoco @ CI commit 2e4d360 (= CI run 29943727645 HEAD) | yes, jacoco:check LINE ≥ 0.92 in pom.xml | no |
| axiam-go-sdk | 93.9% (library-scoped) | CI run 29943757372 + identical local run | yes, floor 93% | no |
| axiam-csharp-sdk | 94.80% | CI run 29943737370 | yes, floor 92% | no |
| axiam-swift-sdk | ~95% | Coveralls badge (CI run 29943775387; exact % not retrievable from logs) | **none** | no |
| axiam-typescript-sdk | 95.85% | CI run 29943707181 | yes, vitest thresholds (lines 93) | no |
| axiam-python-sdk | 98.33% | CI run 29943717896 + identical local run | yes, `fail_under = 96` | no |
| axiam-cplusplus-sdk | 99.21% | CI run 29943792793 | **none** | no |

Five repos need real coverage work: **axiam server (78.92%)**, **PHP SDK (88.30%)**,
**Rust SDK (89.34%)**, **C SDK (90.0%, no gate)** and **Kotlin SDK (91.28%, gate silently
disabled)**. Everything else only needs a gate/ratchet and optional small polish.

## 2. Model-selection policy (Opus vs Sonnet)

Per-job recommendation follows "best but cheapest that can do the job well":

- **Sonnet** — pattern-following test authoring where this plan already names the target files,
  the uncovered branches, and the harness to copy from. This is the majority of the work.
- **Opus** — jobs needing real judgment: designing a testability seam/refactor, security-sensitive
  negative-path design (SAML/OAuth2), multi-crate pushes where the executor must re-measure and
  re-prioritize, or debugging CI coverage plumbing beyond a one-liner.

Each job below carries a `Model:` tag. When a Sonnet run stalls (can't make a target testable
without refactoring), stop and escalate that job to Opus rather than padding with low-value tests.

## 3. Ground rules for every executor

1. Work on branch `claude/test-coverage-improvement-plan-idxnfc` in the repo concerned; create it
   from `origin/main` if missing; push with `git push -u origin claude/test-coverage-improvement-plan-idxnfc`
   (retry up to 4× with 2/4/8/16 s backoff on network errors only). Never push elsewhere. No PRs
   unless the user asks.
2. **Additive tests only.** Production code may change only to introduce a testability seam
   explicitly called for below, or to fix a real bug found while testing (surface it in the commit
   message, don't silently fix).
3. **Measure first.** Re-generate a local per-file report before writing tests (commands per repo
   below); this plan's line numbers drift as `main` moves.
4. Reuse the named harnesses/fixtures; do not build new scaffolding where one exists.
5. Rust disk hygiene (both Rust repos): scoped commands (`cargo llvm-cov -p <crate>`), `cargo clean`
   between crates, and for anything touching `axiam-api-rest`:
   `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`.
6. Gate ratchets are set **1–2 points below the achieved value** so the first CI run passes.
7. Verification per phase: repo's full test suite green + local coverage total at/above target;
   state explicitly when a number could only be confirmed via Coveralls/CI.

---

## 4. Phase A — axiam server: 78.92% → ≥90% (the big push)

Rust workspace measured by cargo-llvm-cov (33,783 lines, 7,121 missed → need ~3,750 more covered
lines for 90%). Frontend is already at 95.82% and needs no test work.

Measurement:
```bash
cd /home/user/axiam
export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip
cargo llvm-cov -p <crate> --no-fail-fast --summary-only        # per-crate, cargo clean between
```
Harnesses to reuse: in-memory SurrealDB pattern (`type TestDb` + `setup_db()`, e.g.
`crates/axiam-api-rest/tests/auth_test.rs`, `crates/axiam-authz/tests/authz_engine_test.rs:25`);
tonic harness (`crates/axiam-api-grpc/tests/grpc_auth_test.rs:125`); wiremock 0.6 (dev-dep in
api-rest, email, federation, server); SAML fixtures `crates/axiam-federation/tests/fixtures/saml/`
(+ `generate.sh`); AMQP fixtures `crates/axiam-amqp/tests/fixtures/` with
`tests/mail_consumer_test.rs` as the consumer pattern.

### A0. CI coverage-plumbing fixes (free points) — Model: **Sonnet** (S)
- `.github/workflows/coverage.yml` runs only `--test grpc_authz_test` with `--features client`, but
  `grpc_auth_test` and `grpc_userinfo_test` also have `required-features = ["client"]` — they are
  never instrumented. Add both to the client-feature coverage step. This alone fixes
  `axiam-api-grpc/src/services/userinfo.rs` (23.08% today with a passing integration test).
- Decide `axiam-server/src/main.rs` (1,223 lines, 0%): extract testable config/wiring functions
  where cheap and mark the rest `#[cfg_attr(coverage_nightly, coverage(off))]` or exclude via
  `--ignore-filename-regex` in coverage.yml. Excluding/covering it moves the workspace ~2 points.
  If the exclusion decision feels contentious, note it in the PR description for the human.

### A1. axiam-api-rest handler error paths (74.70%, 2,036 missed — biggest crate lever) — Model: **Sonnet** (M/L)
Actix `TestRequest` + Mem-DB, copying sibling `tests/*_test.rs` per file:
- `src/handlers/webauthn.rs` — **0%**, no test file (leftover from the old plan). Register/auth
  begin+finish, bad challenge, wrong tenant. Webauthn config example: `tests/middleware_test.rs:75`.
- `src/handlers/gdpr.rs` — 5.6% at handler level (existing `tests/gdpr_test.rs` tests lower
  layers). Export/erasure endpoints, authz failures, invalid state transitions.
- `src/webhook_consumer.rs` — 25.9%. Delivery failure/retry/HMAC branches with a wiremock receiver
  (`tests/webhook_consumer_test.rs` exists to extend).
- `src/handlers/federation.rs` — 52.5%. SSO initiate/callback error paths, bad state, IdP failures
  (wiremock IdP; `tests/federation_test.rs`, `federation_first_time_sso_test.rs`).
- Small-S sweep: `handlers/auth.rs`, `password_reset.rs`, `scopes.rs`, `permissions.rs`,
  `roles.rs`, `pgp_keys.rs`, `email_verification.rs` (49–73% each) — invalid input, cross-tenant
  404s, conflicts, MFA/lockout branches.

### A2. axiam-amqp consumers/publishers (41.17%, 753 missed) — Model: **Opus** (L)
`authz_consumer.rs`, `audit_consumer.rs`, `connection.rs`, `mail_publisher.rs`,
`notification_publisher.rs`, `webhook_publisher.rs` sit at 0–40%. The handler logic is entangled
with live-broker transport; Opus should design a minimal seam (trait over
channel/ack like the SDKs' `AckableDelivery` pattern) so decode/dispatch/nack-drop branches become
unit-testable with `tests/fixtures/` vectors, keeping the diff surgical. CI has live RabbitMQ for
whatever remains transport-bound.

### A3. axiam-server cleanup loops (crate 22.58%) — Model: **Sonnet** (M)
`src/cleanup.rs` (3.98%, 434 missed): expired sessions/tokens/export-jobs pruning + error branches
with the Mem-DB pattern. (main.rs handled in A0.)

### A4. axiam-federation SAML negative paths (`src/saml.rs` 48.9%, 462 missed) — Model: **Opus** (L)
Tampered/replayed/expired assertions, signature & condition validation, encoding errors. Fixtures
`tests/fixtures/saml/` (`well_signed_response.xml`, `tampered_response.xml`,
`replayed_response.xml`, regenerable via `generate.sh`); pattern in `tests/secrets_and_errors.rs`.
Opus because designing *correct* negative-path assertions for signature-wrapping/replay classes of
attack is security-sensitive — wrong tests here would certify broken validation.

### A5. axiam-db repositories (84.44%, 1,703 missed) — Model: **Sonnet** (M)
Mem-friendly CRUD/edge branches: `repository/role.rs` (111 missed), `email_template.rs` (90),
`notification_rule.rs` (88), `oauth2_refresh_token.rs` (54), `password_history.rs` (51),
`seeder.rs` (136). Skip `connection.rs` remote/retry/TLS branches (needs live server, low yield).

### A6. Remainder sweep to lock ≥90% — Model: **Sonnet** (S/M)
- axiam-oauth2 `src/authorize.rs` (71.1%): bad client, redirect_uri mismatch, PKCE errors
  (patterns in `crates/axiam-api-rest/tests/oauth2_flow_test.rs`).
- axiam-pki `src/cert.rs` / `src/crypto.rs` (~50 missed): inline unit tests for cert-building/key
  error paths (old plan item 6, still open).
- axiam-authz `src/types.rs` (27 lines, 0%): Display/serde inline tests.
- axiam-auth residuals incl. `src/webauthn.rs` (67.3%).

### A7. Ratchet gates — Model: **Sonnet** (S)
After re-measuring: raise `--fail-under-lines` in `coverage.yml` from 77 to (achieved − 2);
add `coverage.thresholds.lines: 93` to `frontend/vitest.config.ts` plus a text-summary reporter so
the frontend number shows in CI logs.

Sequencing: A0 first (free points + correct baseline), then A1/A3/A5/A6 (Sonnet, parallelizable
per-crate), A2/A4 (Opus) whenever; A7 last. If after A0–A6 the workspace is still short of 90%,
report the achieved number and the marginal cost of the rest — don't pad.

---

## 5. Phase B — PHP SDK: 88.30% → ≥93%

Need +42 covered lines for 92%; the jobs below add ~75 → ~95%. No CI gate exists today.

Measure: `composer install && vendor/bin/phpunit --coverage-text` (pcov/xdebug; coverage CI runs
**all** suites incl. Laravel/Symfony integration). Harnesses: separate-process `\Grpc\BaseStub`
doubles (`tests/GrpcAuthzClientTest.php`, `tests/UserInfoDispatcherTest.php`), Guzzle MockHandler
(`tests/AxiamClientBehaviorTest.php`), ed25519 + JWKS fixtures, `tests/Fixtures/amqp_hmac_vectors.json`,
`verify_fixture.php`.

### B1. gRPC dispatch layer (the win) — Model: **Sonnet** (M)
- `src/AuthzDispatcher.php` (33.8%, 53 missed): gRPC `checkAccess()`/`batchCheck()` assembly +
  unwrap (incl. optional scope), `getUserInfo()` via `getUserInfoWithRefreshRetry`, lazy
  `grpcClient()`/`userInfoClient()` construction and their `AxiamException` throws when
  `grpcTarget`/`tenantId` unset, `currentSubjectId()`.
- `src/Grpc/AuthzGrpcClient.php` (59.5%): public `checkAccess()`/`batchCheckAccess()` wrappers.
- `src/Grpc/UserInfoGrpcClient.php` (83.3%): `getUserInfo()` wrapper.

### B2. Client + middleware edges — Model: **Sonnet** (S)
`src/AxiamClient.php` (93%): `getUserInfo()` delegation, `currentSubjectId()` sub-claim, refresh-
then-reverify fallback (skip the tempnam/write-failure branches). `src/Laravel/AxiamAccessMiddleware.php`
param/attribute edges; `Symfony/AxiamAccessAttributeListener` + `AccessEnforcer` small branches;
`Amqp/Hmac` odd-length-hex signature; `Auth/JwksVerifier` `jku` URL edges.

### B3. AMQP `Consumer::consume()` (45.5%) — Model: **Opus** (M, optional)
`AMQPStreamConnection` is constructed inline; needs a small injectable connection-factory seam to
test the qos/consume-closure/ack-nack wiring without a broker (`verifyAndDispatch` already fully
tested). Only worth doing with the seam — as-is it's L for little gain. Skip if B1+B2 already land ≥93%.

### B4. Add the missing CI gate — Model: **Sonnet** (S)
`coverage.yml` currently only uploads clover to Coveralls; a drop to any % passes green. Add a
threshold step (parse clover total, fail under achieved − 2; PHPUnit 9 has no built-in fail-under).

---

## 6. Phase C — Rust SDK: 89.34% → ≥92%

Need ~67 more covered lines of 2,486; gap concentrated in three files (85 missed). Gate exists at 89.

Measure (CI does this; locally requires protoc + cargo-llvm-cov, mind disk hygiene):
`cargo llvm-cov --all-features --ignore-filename-regex 'gen/axiam\.v1\.rs'`.
Harnesses: wiremock `MockServer` + `mount_jwks()`/`logged_in_client()`
(`tests/rest_auth_lifecycle_test.rs`, `tests/rest_auth_more_test.rs`), in-process tonic
`start_test_server()` (`tests/grpc_check_access_test.rs`), builder tests
(`tests/client_builder_branches_test.rs`), rcgen mTLS (`tests/mtls_client_cert_test.rs`),
`testdata/v2_reference_vectors.json`.

### C1. `src/rest/auth.rs` (35 missed, fn cover 76%) — Model: **Sonnet** (M)
`map_error_response`/`deser_err` on malformed bodies; `refresh()` non-2xx arms; `logout()` with
missing/invalid access token and non-2xx response; `absorb_session_cookies` failure;
`maybe_csrf_header` no-token; tenant/org combos in `build_login_body`.

### C2. `src/client.rs` (26 missed) + `src/token/jwks.rs` (24 missed) — Model: **Sonnet** (S/M)
Builder TLS/mTLS combos and invalid base-URL/org/tenant permutations; jwks
`force_refetch_if_allowed` throttle branches, `fetch_and_cache` HTTP-error + malformed-JWKS decode,
`verify` ErrorKind arms (extend `tests/jwks_*_test.rs`).

### C3. gRPC residuals (12 missed) — Model: **Sonnet** (S)
Error/status-mapping and channel-build failure paths via the tonic harness.

### C4. Ratchet gate 89 → 92 — Model: **Sonnet** (S)
Note: `amqp/consumer.rs` (80.08%) is dominated by the broker-dependent `consume()` loop the
workflow itself documents as un-coverable in CI — **skip it**; it bounds the ceiling ~94% and a
seam refactor there is not worth it in this pass.

---

## 7. Phase D — C SDK: 90.0% → ≥92% + gate

~21 more covered lines needed. No CI gate today. Measure:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON -DAXIAM_ENABLE_COVERAGE=ON
cmake --build build -j && ctest --test-dir build --output-on-failure
gcovr --root . --filter 'src/' --gcov-ignore-parse-errors=negative_hits.warn_once_per_file --print-summary --txt
```
Harnesses: Unity (vendored), mock transport + `test_recorder_t`/`resp_fill()` (`tests/test_util.h`),
Ed25519 JWT/JWKS fixture (`tests/jwt_fixture.{h,c}`), in-process HTTP server
(`tests/test_integration_curl.c`), PKI fixture (`tests/gen_pki.sh`).

### D1. `src/client.c` mock-transport failure sweep (88%, 47 missed) — Model: **Sonnet** (S)
One shared `failing_transport` (returns rc=1/status 0) covers five branches at once: raw_get,
`perform_refresh`, MFA verify, logout, post-refresh authz retry. Plus NULL-arg guards, slug-only
`axiam_refresh` AUTH error, single-flight follower error propagation, `json_get_long` non-number.
Skip OOM paths (need malloc interposition).

### D2. Small-S sweep: `error.c`, `jwks.c`, `guard.c` — Model: **Sonnet** (S)
error.c: status-302 fallthrough, NULL msg, unknown-kind default. jwks.c: RSA/P-256/bad-base64
key skips, two-key tail append, non-JSON document, NULL guards. guard.c: **CONTRACT §11.2
fail-closed mappings** (JWKS network failure → `AXIAM_GUARD_UNAVAILABLE`, `AXIAM_ERR_AUTH` →
`UNAUTHENTICATED`) — worth explicit tests.

### D3. `src/transport_curl.c` non-TLS portion (81%) — Model: **Sonnet** (S)
GET and custom-method-with-body through the real transport; closed-loopback-port `CURLE_*` failure
path; `connect_timeout_ms`. Leave the CA/mTLS blob lines (needs a TLS-capable in-process server —
**Opus**, M/L) as optional stretch only if D1+D2 don't clear 92%.

### D4. Add gate — Model: **Sonnet** (S)
`--fail-under-line <achieved−2>` on the gcovr invocation in `coverage.yml`.

---

## 8. Phase D2 — Kotlin SDK: 91.28% → ≥93% + make the gate real

Line 91.28% (513/562), branch only 64.38%. The Kover floor (`minBound(88)` in `build.gradle.kts`)
is advisory: `coverage.yml` never runs `koverVerify`, and `sdk-ci-kotlin.yml:34` runs
`./gradlew koverVerify --no-daemon || true` — the `|| true` swallows failures (and the step name
claims "≥ 90%" while the rule says 88). A regression to any % currently merges green.

Measure: `./gradlew test koverXmlReport` (report at `build/reports/kover/report.xml`;
`koverHtmlReport` for humans; system Gradle 8.14 + JDK 21 works, first run downloads ~450 MB).
Harnesses: `src/test/kotlin/io/axiam/sdk/TestSupport.kt` (MockWebServer factory, `fakeJwt()`,
`loginOkResponse()`), `JwksTest.kt` (real Ed25519 signing + JWKS `Dispatcher`), `MtlsTest.kt`
(okhttp-tls `HeldCertificate` in-memory PKI), `KtorPluginTest`/`KtorEnforceTest`
(`testApplication`), `RefreshTest` (concurrent-coroutine harness). All fixtures are minted in code.

### D2-1. `internal/SessionState.kt` (81.6%, worst file) — Model: **Sonnet** (M)
`isNearExpiry()` (entirely untested); `doHttpRefresh` error paths (non-UUID `tenant_id` claim →
AuthError, refresh 200 without the `axiam_access` cookie, transport IOException → NetworkError,
`attachHttpClient` guard); `resolveOrgId` malformed-UUID fallback; `decodeUnverifiedClaims` edges
(bad base64 payload, non-object JSON, JsonNull primitives, missing `exp`, base64url padding).
Drive via `client.refresh()` with tweaked `fakeJwt()` claims + MockWebServer (pattern:
`ClientExtraTest`).

### D2-2. `internal/JwksVerifier.kt` (86.5%) + `AxiamClient.kt` residuals — Model: **Sonnet** (S/M)
JwksVerifier: token signed by a key NOT in the JWKS (the `!valid` branch), JWKS endpoint 500 →
`AuthError`, no matching `kid`, invalid base-URL ctor, malformed `tenant_id` type (add a second
keypair / failing dispatcher to JwksTest's harness). AxiamClient: `verifySession` claim branches,
login 202 without `challenge_token`, logout token without `jti`, `buildUser` no-Set-Cookie,
`batchCheck` null defaults, `close()` with cache — mostly one-enqueue MockWebServer tests.

### D2-3. Ktor plugin + TlsFactory + small files — Model: **Sonnet** (S)
`ktor/AxiamAuthentication.kt`: `AxiamRequireRole` annotation path, `resourceParam` route-param
resolution, `AuthzError`→403 / `AuthError`→401 catches, plugin-missing errors (KtorEnforceTest
harness). `internal/TlsFactory.kt`: invalid/empty CA PEM, empty client chain, unsupported key alg,
`CompositeX509TrustManager.checkClientTrusted` (MtlsTest PKI). `ErrorMapper`/`RefreshGuard` edges.

### D2-4. Enforce the gate — Model: **Sonnet** (S)
Drop the `|| true` on `koverVerify` in `sdk-ci-kotlin.yml` (and/or run `koverVerify` in
`coverage.yml`), align the step name with the real floor, and ratchet `minBound` from 88 to
(achieved − 1) once D2-1..3 land.

---

## 9. Phase E — repos ≥90%: gates, ratchets, small polish

All Sonnet, all S unless noted. Do the **gate** items even if no test is added — three repos
currently measure but can regress silently.

| Repo | Jobs | Model |
|---|---|---|
| axiam-swift-sdk (~95%, **no gate**) | Add fail-under step (`llvm-cov report` + threshold at ~92) and upload the lcov as a CI artifact so per-file numbers become auditable; optional: HTTPS-path branches in `HTTPTransport.swift`, `Errors.swift` status fan-out, `JwksVerifier` reject branches (harness: `Tests/.../Support/` TestHTTPServer, MockTransport, TestSigner) | Sonnet |
| axiam-cplusplus-sdk (99.21%, **no gate**) | Add threshold gate (~95 lines); optional branch polish in `src/jwks.cpp` (70.2% branch — malformed JWK/base64url vectors via `tests/fake_transport.hpp`) and `src/client.cpp` optional-field permutations | Sonnet |
| axiam-csharp-sdk (94.80%, gate 92) | Ratchet floor to 94 in `coverage.yml`; upload lcov artifact for per-file visibility; optional edge sweep of `AxiamClient.cs`/`AxiamPolicyHandler.cs` (JwksFixture + WebApplicationFactory harness) | Sonnet |
| axiam-go-sdk (93.9%, gate 93) | Add `internal/gen/` to the profile-scoping grep (metric then tracks hand-written code, >94%) and ratchet floor to 94; optional S items: `internal/jwks/verifier.go` constructor branches, `login.go`/`authz.go` error branches (httptest fixtures). The `amqp.Consume` loop needs an interface seam over Qos/Consume/NotifyClose — **Opus (M)**, optional | Sonnet (+ optional Opus item) |
| axiam-typescript-sdk (95.85%, thresholds on) | Optional: `src/grpc/client.ts` + `callWithRefresh.ts` non-UNAUTHENTICATED/retry-exhausted branches (extend `test/grpc/*.test.ts`), then ratchet branch threshold 84 → ~90 | Sonnet |
| axiam-python-sdk (98.33%, gate 96) | Optional: batch-check `RpcError` retry branches in `grpc/client.py` (in-process gRPC server pattern in `tests/test_grpc_client.py`); Django/FastAPI 401 edges (conftest `signing_key`/`jwks_mock`) | Sonnet |
| axiam-java-sdk (93.84%, jacoco:check 0.92) | Optional polish then ratchet pom rule 0.92 → 0.93: `spring/AxiamAutoConfiguration.java` bean bodies (37.5% — needs `ApplicationContextRunner` or a stubbed `HttpSecurity`, the one M item), the two `CompositeX509TrustManager` twins (+8 lines, trivial with `testutil/TestCerts.java`), `rest/AuthAuthenticator.java` 401-reauth branches (security-relevant; MockWebServer pattern in `rest/AuthFlowTest.java`), `JwksVerifier`/`AxiamAuthenticationFilter`/`AmqpConsumer` branch edges | Sonnet |
| axiam (frontend 95.82%, no threshold) | Covered in A7 | Sonnet |

---

## 10. Suggested execution order & effort summary

| Order | Phase | Repo | Gap | Model mix | Effort |
|---|---|---|---|---|---|
| 1 | A0 | axiam CI fixes | free points | Sonnet | S |
| 2 | A1/A3/A5/A6 | axiam server | ~11 pts | Sonnet | L (parallelizable per-crate) |
| 3 | A2 + A4 | axiam server (amqp seam, SAML) | included above | Opus | L |
| 4 | B1–B4 | PHP SDK | ~5–7 pts | Sonnet (+ optional Opus B3) | M |
| 5 | C1–C4 | Rust SDK | ~3 pts | Sonnet | M |
| 6 | D1–D4 | C SDK | ~2 pts + gate | Sonnet | S/M |
| 7 | D2-1..4 | Kotlin SDK | ~2 pts + enforce gate | Sonnet | M |
| 8 | E | 7 healthy repos | gates/ratchets | Sonnet | S each |
| 9 | A7 | axiam gates | lock-in | Sonnet | S |

Every phase ends with: full suite green, local coverage re-measured, gate set at achieved−1/−2,
commit + push to `claude/test-coverage-improvement-plan-idxnfc`, and a short report of
before/after numbers (flagging any number only confirmable via CI/Coveralls).
