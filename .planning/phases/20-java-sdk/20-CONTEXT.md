# Phase 20: Java SDK - Context

**Gathered:** 2026-07-02
**Status:** Ready for planning

> **Discussion note:** Interactive discuss session — the user selected the four
> originally-presented gray areas and then repeatedly chose "explore more,"
> locking **27 Java-specific decisions** across 7 question rounds. Every choice
> is grounded in the binding `sdks/CONTRACT.md` §1–§10, the `JAVA-01` pinned
> deps, and the sibling reference SDKs (Rust 16, TypeScript 17, Go 18, Python
> 19). All decisions below are **user-confirmed**. Remaining low-level items
> (exact timeout/backoff/prefetch numbers, POM plugin versions, interceptor
> ordering, package/file layout) are explicitly delegated to research/planner.

<domain>
## Phase Boundary

Phase 20 delivers `sdks/java/` — the Maven Central artifact **`io.axiam:axiam-sdk`** and
the **fifth SDK** (after Rust ref Phase 16, TypeScript Phase 17, Go Phase 18, Python
Phase 19). It implements the full client capability baseline against the frozen v1.0 APIs
in idiomatic Java on a **Java 21** baseline:

- **REST** (`OkHttp` 4.12 + `CookieManager`) — auth flow (`login` → `verifyMfa`), `refresh`,
  `logout`, `checkAccess`/`can`, `batchCheck`. JSON via **Jackson**.
- **gRPC** (`grpc-netty-shaded` 1.82 — blocking + async stubs) — `CheckAccess`, `BatchCheckAccess`.
- **AMQP** (`amqp-client` 5.22, RabbitMQ Java client) — event consumer with HMAC-SHA256
  verify-before-handler and built-in automatic recovery.
- Local JWKS verification via **nimbus-jose-jwt** 10.x (EdDSA/Ed25519, Tink-backed) for
  proactive refresh; a **Spring Security `OncePerRequestFilter`** first-class integration.

Public API is **sync-first with optional `CompletableFuture` async variants**. It conforms to
`sdks/CONTRACT.md` §1–§10 in full and **inherits the Rust/TS/Go/Python reference patterns**
wherever a Java analog exists. Java is a **non-browser** SDK, so §3 CSRF = capture
`X-CSRF-Token` from the response header (not the browser cookie double-submit the TS browser
persona uses). The novel work this phase resolves is everything Java's ecosystem forces —
Spring Security integration, GPG-signed Maven Central publishing, JAR-bundled compiled codegen,
and the JVM-idiom API surface (records, unchecked exceptions, JSpecify, ReentrantLock).

**In scope (JAVA-01):** the `sdks/java/` Maven project + all three transports + Spring Security
filter + examples + GPG-signed Maven Central publish CI, with `ReentrantLock`+`CompletableFuture`
single-flight refresh, HMAC verify, and the no-TLS-bypass gate proven by test.

**Out of scope:** any change to the AXIAM server (v1.0 APIs are frozen; the SDK is a pure external
client and MUST NOT depend on server crates); the other remaining language SDKs (Phases 21–22); the
shared foundation already delivered in Phase 15 (`buf.gen.yaml`, `CONTRACT.md`, FND-04 endpoint,
scaffold).

</domain>

<decisions>
## Implementation Decisions

> **Note:** The SDK's *behavioral* surface is already locked by the binding
> `sdks/CONTRACT.md` §1–§10 and by `JAVA-01` (pinned deps: OkHttp 4.12, grpc-netty-shaded 1.82,
> amqp-client 5.22, nimbus-jose-jwt 10.x + Tink; `ReentrantLock` single-flight; `CookieManager`
> jar; `tenantId` required builder param). The decisions below are the **HOW choices** — all
> **user-confirmed** in the 2026-07-02 discuss session. They do not restate the contract —
> downstream agents MUST read CONTRACT.md.

### Language Baseline & API Surface
- **D-01 [LOCKED]:** **Java 21 baseline.** `maven.compiler.release=21` (newest LTS), raising the
  scaffold's stale Java 11. Satisfies SC#3's Spring Boot 3.x requirement (which mandates 17+) and
  enables records + pattern matching. One toolchain compiles both the SDK and the Spring 3.x example.
- **D-02 [LOCKED]:** **Sync-first API + optional `CompletableFuture` async variants.** Public
  methods are blocking (`login`/`refresh`/`checkAccess` return values / `LoginResult`, satisfying
  SC#1 and Spring's synchronous filter). The SDK **also** exposes `*Async()` variants returning
  `CompletableFuture` for non-blocking callers. `CompletableFuture` is used internally for the §9
  single-flight guard regardless. (Java analog of Python's dual interface.)
- **D-03 [LOCKED]:** **Unchecked exceptions.** `AuthError`/`AuthzError`/`NetworkError` extend
  `RuntimeException` — idiomatic for modern Java client libs (OkHttp/Spring/AWS SDK v2), composes with
  lambdas/streams/`CompletableFuture`, no forced `throws`. Still fully typed for catching. MFA-required
  is a `LoginResult` flag, never an exception.
- **D-04 [LOCKED]:** **Immutable DTOs as Java records.** `LoginResult`, `User`, authz results are
  `record` types (native on 21, immutable, Jackson-supported) — no Lombok, no annotation processor.
  Single `LoginResult` record with an `mfaRequired` flag (Go CF-04 / TS D-18 / Py D-21); then `verifyMfa`.
- **D-05 [LOCKED]:** **JSpecify `@Nullable` on the public API** with `@NullMarked` package default.
  Annotations-only dep; the emerging cross-vendor standard (Spring 7/Micronaut/Guava). Accurate
  null-analysis contracts for consumers' IDEs/checkers.
- **D-06 [LOCKED]:** **Builder-only, explicit configuration.** All config (`baseUrl`, `tenantId`,
  timeouts, customCa) flows through the typed builder; **`tenantId` required and compiler-enforced**
  via absence of a no-arg builder path (SC#1, §5). No implicit env/system-property reading — explicit,
  testable, no ambient config.

### Concurrency, Refresh & Lifecycle
- **D-07:** **§9 single-flight = `ReentrantLock` + `CompletableFuture` in `AtomicReference`**
  (JAVA-01/§9 pinned), **one guard shared across REST + gRPC** on one session. SC#2: 5 concurrent
  threads on an expired token ⇒ exactly 1 refresh (JUnit 5 test).
- **D-08 [LOCKED]:** **Refresh = proactive JWKS/exp check + OkHttp `Authenticator` reactive fallback.**
  An OkHttp `Interceptor` injects `Authorization`/`X-Tenant-Id`/`X-CSRF-Token` and proactively refreshes
  before expiry (local nimbus JWKS/exp); OkHttp's `Authenticator` handles the reactive 401 path. Both
  funnel into the single D-07 guard. Idiomatic OkHttp; one guard for proactive + reactive + gRPC.
- **D-09 [LOCKED]:** **`AutoCloseable` lifecycle.** The client implements `AutoCloseable` (`try`-with-
  resources) with `close()`; deterministically shuts down OkHttp's dispatcher/pool, the gRPC channel,
  and the AMQP connection. (No `async with` — Java has one close idiom.)
- **D-10 [LOCKED]:** **Virtual-thread-friendly, not required (JDK 21).** I/O paths run correctly on
  virtual threads (use `ReentrantLock` not `synchronized` around I/O — §9 already mandates this) but
  never require Loom or spin SDK-owned virtual-thread executors. Consumers scale it under their own
  virtual-thread executor. No lock-in.

### Transports
- **D-11 [LOCKED]:** **gRPC — one long-lived `ManagedChannel`, closed with the client.** Single
  `grpc-netty-shaded` channel built at construction, reused across all authz RPCs (blocking + async
  stubs share it), shut down in `close()` (D-09). Auth/tenant metadata via a shared interceptor.
  Both sync (blocking stub) and async (`ListenableFuture`/`CompletableFuture`-adapted) surfaces (D-02).
- **D-12 [LOCKED]:** **gRPC default per-call deadline, overridable.** Each `CheckAccess`/`BatchCheckAccess`
  RPC carries a sane default `withDeadlineAfter` (authz is a latency-sensitive hot path; unbounded calls
  can hang a request thread), overridable via builder/per-call. Numeric value = planner.
- **D-13 [LOCKED]:** **AMQP — enable the RabbitMQ client's built-in automatic recovery** (connection +
  topology, with network-recovery-interval backoff). The SDK focuses on the §8 HMAC verify-before-handler
  + ack/nack semantics (callback consumer: handler success → ack, retryable failure → nack WITH requeue,
  drop-sentinel/HMAC-fail/parse-fail → nack WITHOUT requeue + security log; handler never sees an
  unverified message). Direct Go D-07 analog.

### Spring Security Integration
- **D-14 [LOCKED]:** **Single artifact; `OncePerRequestFilter` sets the `SecurityContext`.** One
  `io.axiam:axiam-sdk` jar contains core + transports + the Spring `OncePerRequestFilter` (Spring deps
  `optional`/`provided` scope so non-Spring consumers aren't forced to pull them). The filter builds an
  `Authentication` from the locally-verified identity (`user_id`, `tenant_id`, `roles`) and sets
  `SecurityContextHolder` — the idiomatic Spring Security contract (enables `@PreAuthorize`,
  `authorizeHttpRequests`). Matches JAVA-01's single-coordinate mandate.
- **D-15 [LOCKED]:** **Manual `SecurityFilterChain` wiring in the example + optional auto-configuration.**
  The example wires the filter explicitly in a `SecurityFilterChain` `@Bean` (satisfies SC#3's "complete
  working application context"); the jar also ships an optional `@AutoConfiguration` (via
  `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`) that auto-registers
  it when Spring Boot is present. Explicit example + zero-config convenience, no separate starter coordinate.
- **D-16 [LOCKED]:** **Target Spring Boot 3.2+ / Spring Security 6.x**, CI-test against the latest stable
  3.x (`jakarta.*` namespace). Matches the JDK 21 baseline and SC#3.

### Token Safety & Verification
- **D-17 [LOCKED]:** **`Sensitive` — hardened final class.** `final` class, `toString()`→`[SENSITIVE]`
  (§7 floor), **plus** a Jackson serializer emitting `[SENSITIVE]` and non-`Serializable`/redacting on
  any serialization path. Raw value reachable only via a **package-internal accessor**, never a public
  getter. Closes the CR-04 leak class (Go D-08 / Py D-07 analog).
- **D-18:** **Error taxonomy + redact-before-wrap (CR-04 carry-forward).** `AuthError`/`AuthzError`/
  `NetworkError` (§2, unchecked per D-03) from one central status→error mapper (HTTP §2 table + gRPC
  status codes, one source of truth). **`NetworkError` MUST redact `Set-Cookie`/`Authorization`/`Cookie`
  from any wrapped OkHttp `Response`/`Call.details()`/error before storing it** — never let a raw token
  enter the exception chain, `toString`, or logs. Regression test analogous to the sibling
  error-redaction tests, with a non-vacuous control case.
- **D-19 [LOCKED]:** **EdDSA verification = nimbus JWKS + nimbus EdDSA (Tink-backed), no hand-rolled
  crypto.** `RemoteJWKSet` (cache + rotation on unknown `kid`) sources keys; nimbus's EdDSA verifier
  (`OctetKeyPair`/Ed25519, Tink as the primitive under the hood in 10.x) checks signatures. No custom
  signature/key-conversion code — minimal security-sensitive surface. Reactive 401 fallback remains.

### Packaging, Layout & Distribution
- **D-20 [LOCKED]:** **`setuptools`→N/A; Maven with `setuptools.build_meta` analog = standard Maven POM.**
  (Build tool is Maven, pom.xml present.) The scaffold's stale Java 11 + empty `<dependencies/>` are
  filled in; `mvn verify` must pass including signing (SC#5).
- **D-21 [LOCKED]:** **gRPC codegen: generate-on-build, gitignored.** Run buf (or protobuf-maven-plugin
  + protoc-gen-grpc-java) during `mvn generate-sources` into `target/generated-sources` (gitignored);
  **compiled** stub classes are bundled into the published jar. Consumers receive compiled bytecode, never
  run protoc — the Rust/TS "bundle-into-artifact" model (Phase 15 D-01 generate-on-build), viable for Java
  because it ships a compiled artifact (unlike source-distributed Go/Python). Optional CI drift-check.
- **D-22 [LOCKED]:** **Maven Central via the Sonatype Central Portal + `maven-gpg-plugin` + CI secrets.**
  Publish with `central-publishing-maven-plugin`, sign with `maven-gpg-plugin`, attach **javadoc + sources
  jars**, complete required POM metadata (`developers`; `scm`/`licenses`/`url` already present). GPG private
  key + passphrase injected as CI secrets; tag `sdks/java/vX.Y.Z` (Phase 15 D-13) triggers release.
  Documented setup task per JAVA-01. (Live first publish may be a maintainer action if namespace/creds are
  absent in CI; the pipeline and `mvn verify` signing must still pass.)
- **D-23 [LOCKED]:** **Publish a BOM (`io.axiam:axiam-bom`).** In addition to the SDK jar, publish a
  Bill-of-Materials for dependency alignment. **NOTE:** JAVA-01 names only the single coordinate
  `io.axiam:axiam-sdk` — the BOM is a second coordinate; **reconcile JAVA-01 to list the BOM** (see
  Deferred). Expands the release/signing matrix accordingly.
- **D-24 [LOCKED]:** **JPMS = `Automatic-Module-Name: io.axiam.sdk` manifest entry** (no full
  `module-info.java`). Stable module name for module-path consumers without forcing all transitive deps
  (grpc-netty-shaded, okhttp, amqp-client) to be proper modules (which strict JPMS would require and the
  shaded/legacy deps don't cleanly satisfy). Standard library practice.

### Observability, Resilience & Testing
- **D-25 [LOCKED]:** **Logging = SLF4J API only** (no binding shipped) — the universal Java facade;
  consumers wire Logback/Log4j2; silent by default. Logs lifecycle/status only, **never** `Sensitive`
  values (redaction-aware). Off by default.
- **D-26 [LOCKED]:** **Retry = hand-rolled lightweight bounded backoff, no extra dependency.** Bounded
  exponential backoff + jitter for **idempotent ops only** (transient network / `429` / `503`, honor
  `Retry-After`); state-changing requests never auto-retry. Avoids pulling Resilience4j/Failsafe into a
  widely-consumed client jar. Numeric values = planner. Timeouts: **sane defaults, builder-overridable**
  (connect/read/write + OkHttp pool; Go CF-03 analog).
- **D-27 [LOCKED]:** **Client override safety (Go D-09 carry-forward).** The builder accepts an optional
  `OkHttpClient` (custom timeouts/proxy/interceptors), but the SDK **always re-applies its own
  `CookieManager` (§4) and strict TLS/no-bypass config (§6) over the supplied client** via `newBuilder()`
  — an override can never silently drop the cookie jar (breaks post-login) or weaken TLS (SC#4).
- **D-28:** **Testing = JUnit 5 + OkHttp `MockWebServer` + optional Testcontainers.** JUnit 5 for all
  tests incl. the SC#2 `ReentrantLock` 5-thread single-flight test; `MockWebServer` for hermetic
  REST/refresh/CSRF/error-redaction tests; the no-TLS-bypass grep gate; an **optional, tagged**
  Testcontainers smoke test for gRPC/AMQP against a real server (never in default `mvn test` — keeps the
  concurrency test deterministic). Mirrors the sibling SDKs.
- **D-29 [LOCKED]:** **Error messages are English-only, no i18n.** Developer-facing exception messages
  in English; classification via typed exceptions + codes, not localized text. Consistent with all siblings.

### Carried Forward from CONTRACT.md / siblings (apply unless research contradicts)
- **CF-01:** **§3 CSRF** — non-browser → capture `X-CSRF-Token` from the response header (stored in the
  shared thread-safe session), echo on mutating requests.
- **CF-02:** **§4 cookie jar** — `CookieManager` + `CookieHandler` per-client store (D-27 owns it).
- **CF-03:** **§6 TLS** — no `hostnameVerifier`/`sslSocketFactory` bypass anywhere (SC#4); only a
  `customCa` escape hatch; CI grep gate confirms no bypass idioms in SDK source/examples/tests.
- **CF-04:** **§5 tenant** — `tenantId` required builder param, compiler-enforced (D-06, SC#1).
- **CF-05:** **method map (camelCase)** — `login`/`verifyMfa`/`refresh`/`logout`/`checkAccess`+`can`/`batchCheck`.

### Claude's Discretion
- Internal package/module layout and file names under `sdks/java/src`.
- Exact numeric timeout/backoff/retry values, gRPC deadline, AMQP prefetch/QoS.
- Exact `*Async` method naming and `LoginResult` optional-field set beyond `mfaRequired`.
- OkHttp interceptor ordering (application vs network) and `RemoteJWKSet` cache-TTL specifics.
- POM plugin versions and the exact `central-publishing-maven-plugin`/`maven-gpg-plugin` config.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Binding contract & phase definition (read FIRST)
- `sdks/CONTRACT.md` §1–§10 — **normative/binding** cross-language behavioral contract. The Java SDK
  *implements* this. Relevant §: §1 camelCase method map (row: Java), §2 error taxonomy + status mapping
  (D-18), §3 CSRF (**Java = non-browser → `X-CSRF-Token` response header**, CF-01), §4 `CookieManager`
  (CF-02/D-27), §5 tenant (D-06/CF-04), §6 TLS no-bypass (CF-03; SC#4 gate), §7 `Sensitive` (**"Java: final
  class; `toString()` returns `[SENSITIVE]`"** → D-17), §8 AMQP HMAC protocol (D-13), §9 single-flight
  (**"Java: `ReentrantLock` + `CompletableFuture` held in `AtomicReference`"** → D-07), §10 Spring
  (**"Spring Boot: `OncePerRequestFilter` subclass registered in `SecurityFilterChain`"** → D-14/D-15).
  The **C# `Grpc.Tools` exception** in the closing notes confirms Java stays on `buf generate` (D-21).
- `.planning/ROADMAP.md` — Phase 20 goal + 5 success criteria; the `sdks/<lang>/vX.Y.Z` tag convention
  (Phase 15 D-13) the publish CI follows.
- `.planning/REQUIREMENTS.md` §JAVA-01 — acceptance criteria + pinned deps (OkHttp 4.12,
  grpc-netty-shaded 1.82, amqp-client 5.22, nimbus-jose-jwt 10.x + Tink; `ReentrantLock`; `CookieManager`;
  `tenantId` required; Spring Security filter; Maven Central `io.axiam:axiam-sdk` + GPG signing).
  **NOTE:** JAVA-01 lists only `io.axiam:axiam-sdk`; the BOM (D-23) is an added coordinate to reconcile.

### Prior-phase decisions this phase inherits
- `.planning/phases/19-python-sdk/19-CONTEXT.md` — freshest sibling. Sync+async dual surface (→ D-02),
  single `LoginResult`+flag (→ D-04), `Sensitive` multi-surface redaction (→ D-17), redact-before-wrap
  (→ D-18), generate-on-build vs commit codegen framing (→ D-21), publish/OIDC signing framing (→ D-22),
  version-floor bump precedent (→ D-01).
- `.planning/phases/18-go-sdk/18-CONTEXT.md` — non-browser reference. D-04 (typed error + redact-before-wrap
  → D-18), D-07 (closure-handler AMQP → D-13), D-06 (identity-injection middleware → D-14), D-09 (client
  override safety → D-27), CF-01/02/03 (retry/observability/defaults → D-25/D-26).
- `.planning/phases/17-typescript-sdk/17-CONTEXT.md` + `17-REVIEW.md` §CR-04 + `17-VERIFICATION.md` — the
  **token-leak-via-error** finding + `sanitizeAxiosError()` fix; **D-18's redact-before-wrap is the direct
  Java carry-forward.** Read CR-04 before implementing `NetworkError`.
- `.planning/phases/16-rust-sdk/16-CONTEXT.md` — first reference (local JWKS + OIDC discovery/rotation →
  D-19, shared-session single-flight → D-07, closure-handler AMQP → D-13, regenerate-and-bundle publish →
  D-21).
- `.planning/phases/15-sdk-foundation/15-CONTEXT.md` — D-01 (generate-on-build → D-21), D-02 (buf codegen),
  D-05 (FND-04 `/authz/check` + `/batch`), D-09/D-10 (binding contract + locked vocabulary),
  D-11/D-12/D-13 (package identities + monorepo tag scheme `sdks/java/vX.Y.Z`).

### SDK domain research (read for rationale)
- `.planning/research/ARCHITECTURE.md` — codegen source-of-truth, monorepo + path-filtered CI.
- `.planning/research/STACK.md` — buf toolchain + plugin set (protoc-gen-java / protoc-gen-grpc-java).
- `.planning/research/PITFALLS.md` — cross-language divergence trap + the **TLS-bypass pitfall**
  (`hostnameVerifier`/`sslSocketFactory` bypass for OkHttp → SC#4 gate).
- `.planning/research/FEATURES.md` — per-SDK feature matrix.
- `.planning/research/SUMMARY.md` — consolidated research synthesis (TLS-disabled anti-pattern).

### Code the SDK consumes / mirrors (reuse semantics; do NOT depend on server crates)
- `crates/axiam-amqp/src/messages.rs` — **AMQP HMAC reference impl** (§8): canonical-JSON +
  hex-HMAC-SHA256 protocol the Java verify (D-13) must match byte-for-byte (use `javax.crypto.Mac`
  HmacSHA256 + a constant-time compare like `MessageDigest.isEqual`).
- `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`), the Go/Python error+sensitive
  modules — the redaction implementations D-17/D-18 mirror in Java.
- `sdks/rust/src/`, `sdks/go/`, `sdks/python/src/axiam_sdk/` — reference trees (session/single-flight,
  grpc interceptor, amqp consumer, middleware, sensitive) — structural analogs for the Java packages.
- `proto/axiam/v1/authorization.proto`, `user.proto`, `token.proto` — proto surface the Java stubs cover;
  `CheckAccess`/`BatchCheckAccess` request/response shapes for the gRPC client.
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC `check_access`/`batch_check_access`
  semantics the Java gRPC client targets.
- REST `POST /api/v1/authz/check` + `/api/v1/authz/check/batch` (Phase 15 FND-04,
  `crates/axiam-api-rest/src/handlers/authz_check.rs`) — the endpoints `checkAccess`/`can`/`batchCheck` call.
- `sdks/buf.gen.yaml` — buf codegen config; add/confirm the Java plugin entry driving D-21's generated stubs.
- `sdks/java/{pom.xml,README.md,LICENSE}` — existing scaffold (`io.axiam:axiam-sdk`, **stale Java 11 →
  bump to 21 per D-01**, empty `<dependencies/>`, README states CONTRACT.md conformance) — Phase 20 fills it in.
- OIDC `/.well-known/jwks.json` (exact path to confirm in research) — JWKS source for D-19.

### Project-wide constraints
- License is **Apache-2.0** repo-wide — `sdks/java/LICENSE` + POM `<licenses>` already match; keep them.
  See project memory `project_license_apache.md`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `sdks/rust/`, `sdks/typescript/`, `sdks/go/`, `sdks/python/` — four complete reference implementations
  of the same contract; the Java SDK ports their structure (shared session + single-flight guard, gRPC
  interceptor/metadata, closure/callback AMQP consumer, JWKS cache, middleware) into idiomatic Java 21.
- The sibling error-redaction + `Sensitive` implementations — the exact behavior Java's `NetworkError`
  (D-18) and `Sensitive` (D-17) mirror (CR-04 carry-forward).
- `crates/axiam-amqp/src/messages.rs` — canonical HMAC sign/verify; the Java consumer reimplements
  *verification* (cannot depend on the crate) but the canonical-JSON + hex-HMAC-SHA256 protocol must be
  byte-identical (§8 / D-13); use `Mac`/HmacSHA256 + constant-time compare.
- `sdks/buf.gen.yaml` + `proto/axiam/v1/*.proto` — the codegen pipeline (Phase 15); D-21 generates Java
  stubs on build, gitignored, bundled compiled into the jar.
- `sdks/java/` scaffold (`pom.xml` with `io.axiam:axiam-sdk` + Apache-2.0 licenses/scm, LICENSE, README) —
  Phase 20 fills it in; **Java 11 → 21 (D-01), empty `<dependencies/>` populated.**

### Established Patterns
- **CONTRACT.md is binding (Phase 15 D-09):** "CONTRACT.md §1–§10 conformance verified" is a required
  acceptance checklist item for this phase.
- **No TLS bypass (§6 / SC#4):** no `hostnameVerifier`/`sslSocketFactory` override; a CI grep gate over
  `sdks/java/` (source + examples + tests) MUST return empty. Only a `customCa` escape hatch.
- **Additive-only / allow-wins / default-deny RBAC** constrains how the SDK surfaces authz `reason`
  semantics (mirrors gRPC), and how the Spring filter maps to `SecurityContext` authorities (D-14).
- **Monorepo tag release** (`sdks/java/vX.Y.Z`, Phase 15 D-13) — the publish CI follows it.
- **Codegen distribution differs by ecosystem:** Java (like Rust/TS) ships a compiled artifact, so D-21
  generates-on-build + bundles compiled classes — unlike source-distributed Go/Python which commit stubs.

### Integration Points
- New `sdks/java/src/main/java/io/axiam/sdk/` tree (REST core + `grpc`/`amqp`/`auth`/`spring` packages +
  generated stubs in `target/` + `examples/` incl. a complete Spring Boot 3.x application context).
- New per-SDK GitHub Actions workflow under `.github/workflows/` with `paths: sdks/java/**` filter:
  `mvn verify` (incl. the JUnit 5 `ReentrantLock` single-flight test SC#2 + GPG signing) + the TLS-bypass
  grep gate + the buf drift-check (D-21) + tag-triggered Central Portal publish (`sdks/java/vX.Y.Z`, SC#5).
- gRPC stubs generated from `proto/axiam/v1/` via buf into `target/generated-sources` (gitignored).

</code_context>

<specifics>
## Specific Ideas

- The Java SDK is the **Spring-ecosystem SDK** — decisions favor what enterprise Java developers expect
  (records, unchecked exceptions, JSpecify, SLF4J, `SecurityContext` integration, Maven Central + GPG)
  while staying byte-faithful to the shared contract.
- Success-criterion proof points to preserve as concrete tests: (#1) `io.axiam:axiam-sdk` in a POM +
  `tenantId` compiler-required + `login()` returns typed `LoginResult`; (#2) 5 concurrent threads on an
  expired token ⇒ **exactly 1 refresh** (JUnit 5 `ReentrantLock` single-flight test); (#3) Spring Security
  `Filter` protects a sample endpoint, compiles against Spring Boot 3.x, complete working app context;
  (#4) `OkHttpClient` uses `CookieManager`, **no `hostnameVerifier`/`sslSocketFactory` bypass anywhere**
  (grep gate); (#5) `mvn verify` passes incl. GPG signing + Central publish pipeline operational.
- **CR-04 must not recur in Java:** never wrap a raw OkHttp `Response`/`Call.details()`/error carrying
  `Set-Cookie`/`Authorization` into `NetworkError` without redacting first (D-18). Add a Java regression
  test analogous to the sibling error-redaction tests (assert the raw `axiam_access`/`axiam_refresh` value
  never appears in `toString`/JSON/log of a thrown error, with a non-vacuous control case).

</specifics>

<deferred>
## Deferred Ideas

- **JAVA-01 ↔ BOM coordinate reconciliation** — JAVA-01 names only `io.axiam:axiam-sdk`, but D-23 adds a
  published `io.axiam:axiam-bom`. **Planner should reconcile REQUIREMENTS.md JAVA-01 to list the BOM**
  (a scoped doc edit) rather than silently diverging. Expands the release/signing matrix. **Do not lose.**
- **Two-class async idiom** — N/A for Java: Java uses one client with sync + `CompletableFuture` async
  variants (D-02), not the two-class split the Python/httpx world debated. Noted for completeness.
- **Full `module-info.java` (strict JPMS)** — considered (D-24); rejected because shaded/legacy transitive
  deps aren't clean modules. Revisit only if the dependency graph becomes fully modular.
- **Resilience4j/Failsafe for retry** — considered (D-26); rejected to keep the client jar's dependency
  footprint minimal. Revisit if circuit-breaking/bulkhead needs emerge.
- **Live Maven Central first publish** — the pipeline + signing must pass `mvn verify` in-phase, but the
  first real Central release may be a maintainer action if namespace/GPG creds are absent in CI (D-22).
- **Automated cross-language conformance harness** — inherited from Phase 15–19 deferred list; Phase 20
  verifies conformance via its own §1–§10 checklist, not a mechanical suite.

### Reviewed Todos (not folded)
None — no pending todos matched this phase.

</deferred>

---

*Phase: 20-java-sdk*
*Context gathered: 2026-07-02*
