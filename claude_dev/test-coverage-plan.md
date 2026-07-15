# AXIAM Test-Coverage Improvement Plan (server + 7 SDKs)

## Context

AXIAM's test coverage is measured by per-repo `coverage.yml` GitHub Actions workflows that upload to Coveralls in **report-only mode** — no repo enforces a minimum. Current coverage: **axiam server 81%**, Go SDK 89%, PHP SDK 89%, C# SDK 91%, Java SDK 91%, TypeScript SDK 92%, Rust SDK 92%, Python SDK 95%.

Goal (confirmed with the user):
- **axiam server: ≥90%** (the big push)
- **every SDK: ≥93%** (Python: push toward ~96%)
- **Add CI coverage-threshold gates** after raising coverage, so gains can't silently regress
- The plan itself is committed to `claude_dev/test-coverage-plan.md` in `ilpanich/axiam` so later executor sessions (Opus/Sonnet) can read it from the repo

This plan is written to be executed by Opus or Sonnet, possibly across multiple sessions. Phases are independent per-repo; execute in the order below (largest gap first), but any phase can run standalone.

## Ground rules for the executor

- All 8 repos are cloned under `/home/user/`. Work on branch **`claude/test-coverage-plan-84ph18`** in every repo (create locally if missing); push with `git push -u origin claude/test-coverage-plan-84ph18`. Never push elsewhere. No PRs unless the user asks.
- **Additive tests only.** Do not change production code except where a bug is discovered (surface it, don't silently fix). Reuse existing test helpers/fixtures listed per repo — do not build new scaffolding when one exists.
- **Disk hygiene (Rust)**: run `cargo clean` between plan steps that compile Rust (never mid-build). Prefer scoped commands (`cargo test -p <crate> --lib`, `--test <name>`). Before building anything touching `axiam-api-rest`: `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`.
- **Measure before writing tests.** Remembered percentages are stale; each phase starts by generating a local per-file coverage report to find the actual uncovered lines, then targets those. Some axiam-server integration tests need live SurrealDB/RabbitMQ (CI provides containers); if unavailable locally, run what works (most tests use in-memory SurrealDB `Mem`) and treat CI/Coveralls as the authoritative number.
- Commit per logical unit (per crate / per module group) with clear messages; push at the end of each phase.
- CI-gate thresholds: set **1–2 points below the locally-achieved value** (or below the last Coveralls value if local measurement is partial) to avoid flaky gate failures.

## Phase 0 — Commit this plan

Copy this document to `/home/user/axiam/claude_dev/test-coverage-plan.md`, commit on `claude/test-coverage-plan-84ph18`, push. (Executor sessions for SDK phases should read it from there.)

## Phase 1 — axiam server: 81% → ≥90% (largest effort)

Tooling: **cargo-llvm-cov** (installed in CI via `.github/workflows/coverage.yml`; job `rust-coverage`). Local measurement:
```bash
cd /home/user/axiam
export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip
cargo llvm-cov --workspace --no-fail-fast --lcov --output-path lcov.info   # then per-file report:
cargo llvm-cov report --summary-only
```
If a full-workspace run is too heavy for the sandbox disk, do it per-crate (`cargo llvm-cov -p <crate>`) with `cargo clean` in between.

Test-infra facts (verified by exploration):
- Dominant DB pattern: in-memory SurrealDB — `Surreal::new::<Mem>(())` + `use_ns("test").use_db("test")`. Every integration file re-declares its own `type TestDb` + `setup_db()` (e.g. `crates/axiam-api-rest/tests/auth_test.rs:59`, `crates/axiam-authz/tests/authz_engine_test.rs:25`). **Follow the same per-file pattern for new tests** — do not refactor into a shared harness in this pass (keep the diff additive).
- HTTP mocking: **wiremock 0.6** already a dev-dep in `axiam-api-rest`, `axiam-email`, `axiam-federation`, `axiam-server`.
- Fixtures: SAML in `crates/axiam-federation/tests/fixtures/saml/`; AMQP vectors in `crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json`.
- Known-gap backlog is tracked as finding **CQ-B24** in `claude_dev/code-review.md` (line ~144, coverage table ~line 329) and `claude_dev/code-review-postremediation.md` (~line 96/201).

Prioritized work items (verify each against the fresh lcov report before writing tests):
1. **axiam-audit** (623 src lines, only 6 test fns): unit + integration tests for the audit service and especially the **middleware drop-path** (flagged untested in `claude_dev/code-review.md:145`).
2. **axiam-api-grpc** (1616 src lines): tests currently cover only `AuthorizationService`. Add coverage for **`UserService` and `TokenService`** (SEC-003 residual) and the **rate-limit middleware**. Reuse the in-memory-DB + tonic harness pattern from `crates/axiam-api-grpc/tests/grpc_auth_test.rs:45` / `grpc_authz_test.rs:109`. Note `grpc_authz_test` requires `--features client`.
3. **axiam-api-rest** residual handler gaps: **`notification_rules` handlers (zero tests anywhere)**, **webauthn handlers**, **`mfa_methods` handlers**. Follow existing actix `TestRequest` + `Mem` DB patterns from sibling test files in `crates/axiam-api-rest/tests/`.
4. **axiam-federation** (4101 src lines, 1 integration file): tests for JWKS/discovery caches, OIDC internals, and more SAML negative paths using existing fixtures + wiremock for the IdP.
5. **axiam-authz** edge cases (flagged in reviews): hierarchy **cycles/depth limits, duplicate assignments, ancestor scopes, concurrent checks**, and cover `grant_to_role_with_scopes` (the REST-reachable path — SEC-058) not just `grant_to_role`.
6. **axiam-pki** (0 inline tests): add unit tests for internal helpers (cert building, key handling) alongside the existing 7 integration files.
7. **axiam-core** (5661 lines, 31 files): cheap line-% lift — inline unit tests for domain-type validation/serde/display paths in the files the lcov report shows red.
8. If still short of 90%: `axiam-email` provider error paths (wiremock), `axiam-amqp` malformed-delivery branches, `axiam-server` config/composition error paths.

Lock-in + DX:
- Add a `coverage` recipe to `/home/user/axiam/justfile`: `cargo llvm-cov --workspace --html` (mirroring `coverage.yml`, including the `-p axiam-api-grpc --features client --test grpc_authz_test` step).
- Gate: in `.github/workflows/coverage.yml`, add `--fail-under-lines <achieved-2>` to the `cargo llvm-cov report` step (e.g. 88 if 90 is reached).

Verification: `just check` (fmt + clippy + test) passes; scoped `cargo llvm-cov` per touched crate shows the targeted files covered; workspace lcov ≥90% lines (or, if local run is partial, per-crate deltas demonstrably large enough). `cargo clean` when done.

## Phase 2 — Go SDK: 89% → ≥93%

- Run: `cd /home/user/axiam-go-sdk && go test ./... -coverprofile=coverage.out -covermode=atomic && go tool cover -func=coverage.out | sort -k3 -n` to find worst files.
- Targets (no dedicated test file today): `amqp/replay.go` (96 ln — nonce/expiry branches), `internal/jwks/claims.go` (60 — exp/iss/aud error paths), `grpc/tls.go` (43 — custom-CA/error branches), `grpc/interceptor.go` (37), `middleware/context.go` (39), root `jwks.go` (32), plus `errors.go` wrap/Unwrap/format branches and `login.go` MFA/error-response branches.
- Reuse: `httptest` server patterns from `client_test.go`/`login_test.go`/`nethttp_test.go`; in-process gRPC harness from `grpc/authzclient_test.go`; `amqp/testdata/v2_reference_vectors.json`.
- Gate: add a step to `.github/workflows/coverage.yml` after the test run: extract `go tool cover -func=coverage.out` total and fail below threshold (small shell check). Keep `-covermode=atomic` (race tests need it).
- Verify: `go vet ./... && go test ./...` green; total ≥93%.

## Phase 3 — PHP SDK: 89% → ≥93%

- Run: `cd /home/user/axiam-php-sdk && vendor/bin/phpunit --coverage-text --coverage-clover coverage.xml` (pcov driver; `composer install` first if needed). Note the default `unit` suite excludes the Laravel/Symfony `integration` suite but coverage CI runs **all** suites — measure with all suites.
- Targets: `src/Symfony/AxiamBundle.php` (**zero tests**), `src/AuthzDispatcher.php` (155 ln, REST/gRPC fallback logic), `src/Symfony/AxiamVoter.php`, `src/Rest/RefreshMiddleware.php` (401→refresh→retry), `src/Auth/RefreshGuard.php` (single-flight edges), `src/Amqp/Consumer.php` (ack/nack/drop), `src/Laravel/AxiamServiceProvider.php`, `src/Core/ErrorMapper.php` (status→exception table), `src/Laravel/AxiamGate.php`.
- Reuse: `tests/Fixtures/verify_fixture.php` (JWT/JWKS signer), ed25519 fixtures, `amqp_hmac_vectors.json`, `v2_reference_vectors.json`; Guzzle MockHandler patterns from `AxiamClientBehaviorTest`/`AuthzRestClientErrorTest`.
- Gate: add a coverage-check step in `.github/workflows/coverage.yml` (parse clover total, fail below threshold — a tiny PHP/shell script; PHPUnit 9 has no built-in fail-under).
- Verify: full `phpunit` (all suites) green; total ≥93%.

## Phase 4 — C# SDK: 91% → ≥93%

- Run: `cd /home/user/axiam-csharp-sdk && dotnet test --collect:"XPlat Code Coverage" -- DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Format=lcov` (coverlet.collector; `**/obj/**` already excluded).
- Targets: `Axiam.Sdk.AspNetCore/AxiamRequirement.cs` (**zero tests**), `Axiam.Sdk/Auth/Jwk.cs` (**zero**), `AxiamPolicyProvider.cs` (policy-name parsing), `ServiceCollectionExtensions.cs` (DI overloads), `Axiam.Sdk/Rest/AuthzRestClient.cs` (error-status branches), `Core/TenantContext.cs`, `AxiamOptions.cs` (validation), `AxiamAuthMiddleware.cs` (challenge/forbid/401), `AxiamPolicyHandler.cs`, `Amqp/AxiamAmqpConsumer.cs` (poison-message/dispose).
- Reuse: `tests/*/Fixtures/JwksFixture.cs` (Ed25519 signer), `amqp_hmac_vectors.json`, WebApplicationFactory harness in `AspNetCoreMiddlewareTests.cs`, Moq patterns in `AxiamHttpMessageHandlerTests.cs`.
- Gate: pass `/p:Threshold=<achieved-2> /p:ThresholdType=line /p:ThresholdStat=total` to `dotnet test` in `coverage.yml`.
- Verify: `dotnet test` green in both test projects; total ≥93%.

## Phase 5 — Java SDK: 91% → ≥93%

- Run: `cd /home/user/axiam-java-sdk && mvn -B verify`; inspect `target/site/jacoco/index.html`/`jacoco.xml` (generated stubs `axiam/v1/**` already excluded).
- Targets: `AxiamUser.java` (**zero tests**, trivial), `rest/AuthAuthenticator.java` (OkHttp 401-reauth give-up branch), `spring/AxiamAutoConfiguration.java` (conditional beans), `rest/AuthInterceptor.java` (CSRF/header branches), `spring/AxiamAuthenticationFilter.java` (auth-failure/anonymous), `Sensitive.java`, `amqp/AmqpConsumer.java` (cancel/redelivery/drop), and residual branches in `AxiamClient.java` (804 ln: builder validation, error mapping, close idempotency) + `internal/SessionState.java` (concurrency/expiry).
- Reuse: `src/test/java/io/axiam/sdk/testutil/TestCerts.java`, MockWebServer patterns in `rest/AuthFlowTest.java`, in-process gRPC harness in `grpc/GrpcAuthzClientTest.java`, `src/test/resources/*.json` vectors.
- Gate: add `jacoco:check` execution to `pom.xml` with a LINE-covered-ratio minimum of (achieved−2)%.
- Verify: `mvn -B verify` green incl. the new check; total ≥93%.

## Phase 6 — TypeScript SDK: 92% → ≥93–94%

- Run: `cd /home/user/axiam-typescript-sdk && npx buf generate && npm run coverage` (vitest v8 provider; `src/gen/**` excluded). buf generation is required first — gRPC stubs are gitignored.
- Targets (no dedicated test file): `src/amqp/messages.ts` (137 — DTO encode/decode), `src/rest/interceptors.ts` (103), `src/rest/client.ts` (107), `src/grpc/callWithRefresh.ts` (54 — refresh-on-UNAUTHENTICATED), `src/node/cookieJar.ts` (53), `src/core/config.ts` (33); audit `src/amqp/consumer.ts` nack/requeue edges.
- Reuse: `test/rest/mswServer.ts` (shared msw server + refresh counter), `testdata/v2_reference_vectors.json`.
- Gate: add `coverage.thresholds` (lines/statements ≈ achieved−2) to `vitest.config.ts`.
- Verify: `npm test` and `npm run coverage` green; total ≥93%.

## Phase 7 — Rust SDK: 92% → ≥93–94%

- Run: `cd /home/user/axiam-rust-sdk && cargo llvm-cov --all-features --lcov --output-path lcov.info && cargo llvm-cov report` (protoc needed for build.rs; keep `--all-features` so grpc/amqp/actix code is instrumented). `cargo clean` before/after (disk).
- Targets: `src/token/manager.rs` (202 — lifecycle/expiry, no dedicated test), `src/amqp/messages.rs` (121 — DTO serde), `src/token/refresh_guard.rs` (98 — thin), `src/client.rs` builder feature-branch combinations, `src/grpc/channel.rs` TLS-root branches, residual error paths in `src/rest/auth.rs` and `src/error.rs`. (`amqp/consumer.rs` already has ~750 lines of inline tests — skip.)
- Reuse: wiremock `MockServer` patterns in `tests/rest_auth_lifecycle_test.rs`/`tests/jwks_fetch_and_refetch_test.rs`; in-process tonic server in `tests/grpc_check_access_test.rs`; `testdata/v2_reference_vectors.json`.
- Gate: add `--fail-under-lines <achieved-2>` to the cargo-llvm-cov invocation in `coverage.yml`.
- Verify: `cargo test --all-features` green; total ≥93%.

## Phase 8 — Python SDK: 95% → ~96% (polish)

- Run: `cd /home/user/axiam-python-sdk && pip install -e ".[dev,fastapi,django]" && pytest --cov=axiam_sdk --cov-report=term-missing` (the extras are required or framework modules count as uncovered).
- Targets: `src/axiam_sdk/grpc/_tls.py` (33 — no test), `src/axiam_sdk/_models.py` (74 — no dedicated test), `_async_client.py` async error/retry branches, `_client.py` residual transport/error-mapping edges, `amqp/_consumer.py` nack/requeue/malformed-delivery, `token/refresh_guard.py` edges.
- Reuse: `tests/conftest.py` fixtures (`signing_key`, `respx_mock`, `jwks_mock`), `tests/fixtures/amqp_hmac_vectors.json`, `testdata/v2_reference_vectors.json`. (Note: `[tool.interrogate] fail-under=100` is docstring coverage — unrelated; new test code must still satisfy the repo's lint gates.)
- Gate: add `--cov-fail-under=<achieved-1>` to the pytest invocation in `coverage.yml` (or `[tool.coverage.report] fail_under` in pyproject.toml).
- Verify: `pytest` green; total ≥96%.

## Final verification (per phase and overall)

1. Per repo: full test suite green with the repo's standard command (listed in each phase), coverage total at/above target in the local report.
2. CI gates added in the same PR-branch as the tests, threshold set 1–2 points below achieved, so `coverage.yml` passes on the first CI run.
3. Push each repo's branch (`git push -u origin claude/test-coverage-plan-84ph18`, retry with backoff on network errors only).
4. After pushes, report final per-repo numbers (local measurement) vs. the starting table; where local measurement was partial (server integration tests needing live SurrealDB/RabbitMQ), state that explicitly and let Coveralls confirm on CI.
5. Rust repos: `cargo clean` at the end of each phase to respect the ~38 GB disk quota.

## Notes / risks

- The server 81→90 jump is the bulk of the work (~9 points over ~60k source lines); items 1–5 of Phase 1 are the high-yield targets identified by prior code reviews (CQ-B24). If 90% proves out of reach after items 1–7, report the achieved number and the marginal cost of the remainder rather than padding with low-value tests.
- Do not conflate Coveralls' aggregated number (server repo combines `rust-workspace` + `frontend-vitest` flags) with the Rust-only number; the 81% figure is the user's reference — track improvement in lcov lines-% for the Rust workspace.
- SDK CONTRACT.md/openapi.json copies drift from the canonical `/home/user/axiam/sdks/` versions — out of scope here; tests should follow each repo's vendored contract.
