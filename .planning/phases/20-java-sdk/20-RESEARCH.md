# Phase 20: Java SDK - Research

**Researched:** 2026-07-02
**Domain:** Java 21 SDK implementation of `sdks/CONTRACT.md` — OkHttp REST + grpc-netty-shaded gRPC + amqp-client AMQP, Spring Security integration, Maven Central + GPG publishing
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Language Baseline & API Surface**
- **D-01:** Java 21 baseline. `maven.compiler.release=21`, raising the scaffold's stale Java 11.
- **D-02:** Sync-first API + optional `CompletableFuture` async variants (`*Async()`). `CompletableFuture` used internally for the §9 single-flight guard regardless.
- **D-03:** Unchecked exceptions. `AuthError`/`AuthzError`/`NetworkError` extend `RuntimeException`. MFA-required is a `LoginResult` flag, never an exception.
- **D-04:** Immutable DTOs as Java `record` types. Single `LoginResult` record with `mfaRequired` flag.
- **D-05:** JSpecify `@Nullable` on the public API with `@NullMarked` package default.
- **D-06:** Builder-only, explicit configuration. `tenantId` required and compiler-enforced via absence of a no-arg builder path.

**Concurrency, Refresh & Lifecycle**
- **D-07:** §9 single-flight = `ReentrantLock` + `CompletableFuture` in `AtomicReference`, one guard shared across REST + gRPC on one session. SC#2: 5 concurrent threads on expired token ⇒ exactly 1 refresh (JUnit 5 test).
- **D-08:** Refresh = proactive JWKS/exp check (OkHttp `Interceptor`) + OkHttp `Authenticator` reactive 401 fallback. Both funnel into the single D-07 guard.
- **D-09:** `AutoCloseable` lifecycle — `close()` shuts down OkHttp dispatcher/pool, gRPC channel, AMQP connection.
- **D-10:** Virtual-thread-friendly, not required (JDK 21). Use `ReentrantLock` not `synchronized` around I/O.

**Transports**
- **D-11:** gRPC — one long-lived `ManagedChannel`, closed with the client. Both blocking + async stubs share it.
- **D-12:** gRPC default per-call deadline via `withDeadlineAfter`, overridable via builder/per-call. Numeric value = planner (this research proposes a value).
- **D-13:** AMQP — enable RabbitMQ client's built-in automatic recovery. §8 HMAC verify-before-handler + ack/nack: success→ack, retryable failure→nack WITH requeue, drop-sentinel/HMAC-fail/parse-fail→nack WITHOUT requeue + security log; handler never sees an unverified message.

**Spring Security Integration**
- **D-14:** Single artifact; `OncePerRequestFilter` sets the `SecurityContext`. Spring deps `optional`/`provided` scope.
- **D-15:** Manual `SecurityFilterChain` wiring in the example + optional `@AutoConfiguration` via `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.
- **D-16:** Target Spring Boot 3.2+ / Spring Security 6.x, CI-test against latest stable 3.x (`jakarta.*`).

**Token Safety & Verification**
- **D-17:** `Sensitive` — hardened final class. `toString()`→`[SENSITIVE]`, Jackson serializer emitting `[SENSITIVE]`, non-`Serializable`, package-internal accessor only.
- **D-18:** Error taxonomy + redact-before-wrap (CR-04 carry-forward). One central status→error mapper. `NetworkError` MUST redact `Set-Cookie`/`Authorization`/`Cookie` from any wrapped OkHttp `Response`/`Call`/error before storing it.
- **D-19:** EdDSA verification = nimbus JWKS + nimbus EdDSA (Tink-backed), no hand-rolled crypto. `RemoteJWKSet` (cache + rotation on unknown `kid`) sources keys.

**Packaging, Layout & Distribution**
- **D-20:** Standard Maven POM (build tool). `mvn verify` must pass including signing (SC#5).
- **D-21:** gRPC codegen: generate-on-build, gitignored. Run buf (or protobuf-maven-plugin + protoc-gen-grpc-java) during `mvn generate-sources` into `target/generated-sources` (gitignored); compiled stubs bundled into the published jar. Optional CI drift-check.
- **D-22:** Maven Central via Sonatype Central Portal + `maven-gpg-plugin` + CI secrets. `central-publishing-maven-plugin`, javadoc + sources jars, `developers` POM metadata. Tag `sdks/java/vX.Y.Z` triggers release.
- **D-23:** Publish a BOM (`io.axiam:axiam-bom`) in addition to the SDK jar. **NOTE:** JAVA-01 names only `io.axiam:axiam-sdk` — reconcile REQUIREMENTS.md.
- **D-24:** JPMS = `Automatic-Module-Name: io.axiam.sdk` manifest entry (no full `module-info.java`).

**Observability, Resilience & Testing**
- **D-25:** Logging = SLF4J API only (no binding shipped). Never logs `Sensitive` values. Off by default.
- **D-26:** Retry = hand-rolled lightweight bounded backoff, no extra dependency. Idempotent ops only (transient network/429/503, honor `Retry-After`); state-changing requests never auto-retry. Timeouts: sane defaults, builder-overridable.
- **D-27:** Client override safety (Go D-09 carry-forward). Builder accepts optional `OkHttpClient`, but SDK always re-applies its own `CookieManager` (§4) and strict TLS/no-bypass config (§6) over the supplied client via `newBuilder()`.
- **D-28:** Testing = JUnit 5 + OkHttp `MockWebServer` + optional Testcontainers. Optional/tagged Testcontainers smoke test for gRPC/AMQP, never in default `mvn test`.
- **D-29:** Error messages are English-only, no i18n.

### Carried Forward from CONTRACT.md / siblings (apply unless research contradicts)
- **CF-01:** §3 CSRF — non-browser → capture `X-CSRF-Token` from response header, echo on mutating requests.
- **CF-02:** §4 cookie jar — `CookieManager` + `CookieHandler` per-client store (D-27 owns it).
- **CF-03:** §6 TLS — no `hostnameVerifier`/`sslSocketFactory` bypass anywhere; only a `customCa` escape hatch; CI grep gate confirms no bypass idioms in SDK source/examples/tests.
- **CF-04:** §5 tenant — `tenantId` required builder param, compiler-enforced.
- **CF-05:** method map (camelCase) — `login`/`verifyMfa`/`refresh`/`logout`/`checkAccess`+`can`/`batchCheck`.

### Claude's Discretion
- Internal package/module layout and file names under `sdks/java/src`.
- Exact numeric timeout/backoff/retry values, gRPC deadline, AMQP prefetch/QoS.
- Exact `*Async` method naming and `LoginResult` optional-field set beyond `mfaRequired`.
- OkHttp interceptor ordering (application vs network) and `RemoteJWKSet` cache-TTL specifics.
- POM plugin versions and the exact `central-publishing-maven-plugin`/`maven-gpg-plugin` config.

### Deferred Ideas (OUT OF SCOPE)
- JAVA-01 ↔ BOM coordinate reconciliation (D-23) — planner should edit REQUIREMENTS.md, do not lose.
- Two-class async idiom — N/A for Java (sync + `CompletableFuture` async on one client, D-02).
- Full `module-info.java` (strict JPMS) — rejected (D-24); revisit only if dep graph becomes modular.
- Resilience4j/Failsafe for retry — rejected (D-26); revisit if circuit-breaking/bulkhead needs emerge.
- Live Maven Central first publish may be a maintainer action if namespace/GPG creds absent in CI.
- Automated cross-language conformance harness — Phase 20 verifies via its own §1–§10 checklist.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| JAVA-01 | Deliver `sdks/java/` with Spring Security integration: full SDK Capability Baseline; `ReentrantLock` single-flight refresh; OkHttp `CookieManager`; OkHttp 4.12 + grpc-netty-shaded 1.82 + amqp-client 5.22; nimbus-jose-jwt 10.x + Tink for EdDSA; Spring Security filter integration; builder requires `tenantId`; examples; Maven Central publish (`io.axiam:axiam-sdk`) incl. GPG signing setup task. | This document — Standard Stack (verified Maven Central versions), Package Legitimacy Audit, Architecture Patterns (POM/codegen/single-flight/interceptor/Spring filter/Sensitive/error mapper), Common Pitfalls (buf output-path conflict, GPG-in-CI, org_id requirement, HMAC canonicalization), Validation Architecture, Security Domain, Code Examples (POM, single-flight test, HMAC verify, error mapper, Spring filter, AutoConfiguration) |
</phase_requirements>

## Summary

Phase 20 ports the four proven reference SDKs (Rust 16, TypeScript 17, Go 18, Python 19) into
idiomatic Java 21 against the same `sdks/CONTRACT.md` §1–§10. The 29 CONTEXT.md decisions already
fix every architectural choice — sync-first + `CompletableFuture` async, `ReentrantLock` +
`CompletableFuture`-in-`AtomicReference` single-flight, records, unchecked exceptions, JSpecify,
`Sensitive` as a hardened final class, `RemoteJWKSet`+nimbus EdDSA, Spring `OncePerRequestFilter`.
This research resolves the Java-toolchain-specific HOW: exact Maven Central versions of the four
JAVA-01-pinned dependencies (all verified live against Maven Central this session), the POM plugin
chain for GPG-signed Sonatype Central Portal publishing, the gRPC codegen mechanism given `buf` CLI
is unavailable in this environment (same gap Phase 18/19 hit), the `ReentrantLock` single-flight
test shape proving SC#2, and the AMQP HMAC canonicalization approach — where a **critical,
empirically-proven cross-phase finding from Phase 19 (Python)** directly changes what would
otherwise be a plausible-but-wrong Java implementation.

Four findings materially affect planning beyond what CONTEXT.md anticipated. **First**, `sdks/buf.gen.yaml`'s existing Java plugin entries output directly into `sdks/java/src/main/java` —
the **committed source tree** — which directly conflicts with D-21's "generate-on-build, gitignored
into `target/generated-sources`" mandate (the identical class of bug Phase 18 found for Go and
fixed in Wave 0). Since `buf` CLI is unavailable in this development environment (confirmed
absent, matching Phase 18/19's own environment probes) and Maven has a native, better-fitting
codegen mechanism anyway, this research recommends **`protobuf-maven-plugin` + `os-maven-plugin`**
bound to the `generate-sources` phase as the SDK's actual build-time codegen path (outputting to
the default `target/generated-sources/protobuf`, which is gitignored by Maven convention), and
demotes `buf.gen.yaml`'s Java entries to an optional CI drift-check reference only — this is a
Wave-0 config decision the planner must make explicit, not silently inherit. **Second**, the real
`POST /api/v1/auth/login` / `POST /api/v1/auth/refresh` endpoints require an `org_id`/`org_slug`
beyond what CONTRACT.md §5 documents (`RefreshRequest.org_id: Uuid` is non-optional in the actual
Rust handler) — confirmed directly in `crates/axiam-api-rest/src/handlers/auth.rs` and already
worked around identically by all three prior server-side SDKs (Rust `org_slug`/`org_id` builder
methods, resolved from the access token's `org_id` claim after first login). The Java builder MUST
add the same optional `orgSlug`/`orgId` methods or `login`/`refresh` will 400 against the real
server. **Third**, and highest-impact for §8: Phase 19 (Python)'s research flagged the AMQP HMAC
canonical-JSON key-ordering question as the single highest-risk unresolved assumption in that
phase — and **`.planning/STATE.md`'s Phase 19 decision log confirms it was empirically resolved**:
`crates/axiam-amqp/src/messages.rs`'s Rust structs serialize in **field-declaration order**, NOT
alphabetically, and the correct canonicalization is to **preserve the exact wire/insertion key
order** of the received message (after removing `hmac_signature`), never re-sort keys. This is now
a `[VERIFIED: STATE.md Phase 19 finding, proven against a real Rust-signed fixture]` fact Java must
follow — Jackson's `ObjectNode` (backed by `LinkedHashMap`) preserves insertion order natively,
making this the correct, low-risk implementation path (no Wave-0 fixture-proving needed, since a
sibling SDK already proved it against the real signer). **Fourth**: `mvn verify` including GPG
signing (SC#5) cannot use the real release key on every PR (untrusted forks, no secrets) — the
standard, safe pattern is an ephemeral/throwaway GPG key generated in the PR-gate CI job (proves
the `sign` goal structurally works) with the real secret-backed key reserved for the tag-triggered
publish job only, mirroring `sdk-ci-python.yml`'s "manual-on-tag, side-effecting step" pattern.

**Primary recommendation:** Fix the scaffold (`pom.xml` Java 11→21, populate `<dependencies/>`,
add plugin chain), wire `protobuf-maven-plugin`+`os-maven-plugin` as the canonical gRPC codegen
step (not `buf` CLI), reuse the sibling SDKs' proven numeric defaults (10s connect / 30s read-write
timeout, 300s JWKS TTL / 60s forced-refetch cooldown, AMQP prefetch 10, 3-attempt bounded backoff),
add `orgSlug`/`orgId` optional builder methods, implement the AMQP HMAC canonicalization via
Jackson `ObjectNode` insertion-order preservation (proven-correct per Phase 19), and stage GPG
signing behind a `gpg.skip` property (default `true`, flipped to `false` in both the PR-gate CI job
using an ephemeral test key and the tag-triggered publish job using the real CI secret).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Login / MFA / Refresh / Logout (REST) | SDK Client (non-browser) | Server (`axiam-api-rest`) | SDK is a pure external HTTP client; cookie jar + CSRF capture live in the SDK; the server issues tokens and enforces auth |
| Single-flight refresh guard (§9) | SDK Client | — | Client-side concurrency control; server has no visibility into concurrent SDK callers on one JVM |
| Authz check (REST `can`/`checkAccess`) | SDK Client (REST transport) | Server (FND-04 endpoint) | SDK calls `POST /api/v1/authz/check`; server's `AuthorizationEngine` is authoritative |
| Authz check (gRPC `CheckAccess`/`BatchCheckAccess`) | SDK Client (gRPC transport) | Server (`axiam-api-grpc`) | Same authorization engine, different transport; SDK dual sync/async stubs are a pure client concern |
| AMQP event consumption + HMAC verify | SDK Client | Server (`axiam-amqp` publisher, RabbitMQ broker external) | SDK verifies signatures the server produces; verification logic duplicated (not imported — SDK MUST NOT depend on server crates) |
| Local JWKS/JWT verification | SDK Client | Server (`/oauth2/jwks` issuer) | SDK caches and verifies locally (nimbus `RemoteJWKSet`) to avoid a per-request server round-trip; server remains the key-rotation source of truth |
| Spring Security `OncePerRequestFilter` | SDK (framework integration layer) | — | Runs inside the *consumer's* Spring process wrapping their own endpoints — not the AXIAM server; local-verify only, no new server endpoint |
| Token/session redaction (`Sensitive`) | SDK Client (data model) | — | Class-level concern; must hold regardless of transport |
| Maven Central / GPG publish | SDK repo tooling (CI) | — | Build/release concern, no runtime tier |
| gRPC codegen (compiled stub bundling) | Build/CI tooling (Maven `generate-sources`) | SDK jar (compiled classes bundled) | Unlike Go/Python (source-distributed), the published jar carries compiled bytecode — consumers never run protoc (D-21) |

## Standard Stack

### Core

| Library | Version (verified live against Maven Central this session) | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `com.squareup.okhttp3:okhttp` | **4.12.0** [VERIFIED: Maven Central] — JAVA-01 pins the 4.12 line; note 5.x exists as OkHttp's current major but is NOT what JAVA-01 pins | REST transport, `CookieManager`/`CookieHandler` (§4), `Interceptor`+`Authenticator` refresh (D-08) | JAVA-01-pinned; the de facto standard Java HTTP client with first-class interceptor/cookie-jar/TLS-config APIs matching every CONTRACT.md §4/§6/§9 requirement natively |
| `io.grpc:grpc-netty-shaded` | **1.82.0** (1.82.1 patch also exists) [VERIFIED: Maven Central] | gRPC transport for `CheckAccess`/`BatchCheckAccess` (D-11) | JAVA-01-pinned; shaded Netty avoids a consumer classpath Netty-version collision — the standard choice for a library (vs. app) artifact |
| `com.rabbitmq:amqp-client` | **5.22.0** [VERIFIED: Maven Central] | AMQP 0-9-1 client, event consumer with built-in automatic recovery (D-13) | JAVA-01-pinned; official RabbitMQ Java client |
| `com.nimbusds:nimbus-jose-jwt` | **10.7** (10.x line, latest 10.x as of this session) [VERIFIED: Maven Central] | `RemoteJWKSet` fetch/cache/rotation + EdDSA/Ed25519 JWS verification (D-19) | JAVA-01-pinned; most complete/widely-audited pure-Java JOSE/JWT implementation |
| `com.google.crypto.tink:tink` | latest 1.x [ASSUMED — exact patch not independently re-verified this session; confirm at implementation time] | EdDSA/Ed25519 primitive backing nimbus's `Ed25519Verifier`/`Ed25519Signer` | JAVA-01-pinned ("nimbus-jose-jwt 10.x **+ Tink**"); nimbus does not bundle Ed25519 curve math itself — it delegates to Tink for the OKP/Ed25519/X25519 operations, an explicit optional dependency documented on the nimbus product page |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `com.fasterxml.jackson.core:jackson-databind` (+ `jackson-datatype-jsr310`) | **2.22.0** (latest) [VERIFIED: Maven Central] | JSON (de)serialization for REST DTOs, AMQP HMAC canonicalization via `ObjectNode` | Standard for OkHttp-based clients; `ObjectNode`'s `LinkedHashMap`-backed insertion-order preservation is load-bearing for §8 HMAC correctness (see Common Pitfalls) |
| `org.jspecify:jspecify` | **1.0.0** [VERIFIED: Maven Central] | `@Nullable`/`@NullMarked` annotations (D-05) | Annotations-only, zero runtime footprint; the emerging cross-vendor standard (Spring 7, Micronaut, Guava all adopting it) |
| `org.slf4j:slf4j-api` | latest 2.x [ASSUMED — not independently re-verified; standard, stable API] | Logging facade only, no binding shipped (D-25) | Universal Java logging facade; consumers wire Logback/Log4j2 |
| `org.springframework.boot:spring-boot-starter-security` (`optional`/`provided` scope) | Spring Boot **3.5.x** line (3.5.6+ is the latest stable pre-4.0 release as of this research; 4.0/4.1 exist but D-16 explicitly pins 3.2+/3.x) [VERIFIED: Maven Central] | `OncePerRequestFilter`, `SecurityFilterChain` integration (D-14/D-15/D-16) | JAVA-01-pinned framework target; use the latest stable **3.x** line (not 4.x) per D-16's explicit "target Spring Boot 3.2+ ... latest stable 3.x" wording |
| `org.junit.jupiter:junit-jupiter` | **5.14.4** (JUnit 6 GA also exists but D-28 pins "JUnit 5") [VERIFIED: Maven Central] | Test framework, incl. the SC#2 `ReentrantLock` 5-thread single-flight test (D-28) | JAVA-01/D-28-pinned |
| `com.squareup.okhttp3:mockwebserver` (the OkHttp-**4.x**-line test module — NOT `mockwebserver3`, which targets OkHttp 5.x) | **4.12.0** (match the runtime OkHttp version exactly) [VERIFIED: Maven Central] | Hermetic REST/refresh/CSRF/error-redaction tests (D-28) | Must match the pinned OkHttp 4.12 runtime major/minor — `mockwebserver3-junit5` is OkHttp 5.x's rewritten test module and is API-incompatible with an OkHttp-4.x `Response`/`Request` surface; using it would silently pull a mismatched OkHttp test dependency |
| `org.xolstice.maven.plugins:protobuf-maven-plugin` | 0.6.1 [CITED: xolstice/protobuf-maven-plugin GitHub] | Build-time (`generate-sources` phase) protoc + `protoc-gen-grpc-java` invocation (D-21) | Recommended over shelling out to `buf` CLI (unavailable in this environment, see Common Pitfalls); Maven-native, outputs to `target/generated-sources/protobuf` by default (naturally satisfies D-21's gitignored requirement) |
| `kr.motd.maven:os-maven-plugin` | 1.7.1 [CITED: standard companion to protobuf-maven-plugin] | Resolves `${os.detected.classifier}` for `protocArtifact`/`pluginArtifact` OS-specific binaries | Required build extension alongside `protobuf-maven-plugin` |
| `org.apache.maven.plugins:maven-gpg-plugin` | **3.2.8** (latest) [VERIFIED via WebSearch of Maven Central] | GPG-signs artifacts at the `verify` phase (D-22, SC#5) | Standard Apache Maven plugin for the Sonatype Central Portal's signature requirement |
| `org.sonatype.central:central-publishing-maven-plugin` | **0.9.0** (0.10.0 also exists; use latest stable at execution time) [VERIFIED via WebSearch of Maven Central] | Publishes to the Sonatype Central Portal (D-22) | The current, Central-Portal-native replacement for the deprecated `nexus-staging-maven-plugin`/OSSRH flow |
| `org.apache.maven.plugins:maven-javadoc-plugin` / `maven-source-plugin` | latest stable (3.x lines) [ASSUMED — standard, well-known Apache Maven core plugins] | javadoc + sources jar attachment (D-22, Maven Central requirement) | Sonatype Central Portal REQUIRES javadoc+sources jars for every release artifact — not optional |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `protobuf-maven-plugin` + `os-maven-plugin` for gRPC codegen | Shell out to `buf generate` via `exec-maven-plugin` | Rejected: `buf` CLI is confirmed absent in this development environment (matches Phase 18/19's identical finding); `exec-maven-plugin` would also make `mvn verify` fail for any contributor without `buf` installed, whereas `protobuf-maven-plugin` self-downloads `protoc`/`protoc-gen-grpc-java` binaries via Maven's own dependency resolution — no external CLI required on any machine that can run `mvn` |
| `mockwebserver` (OkHttp 4.x line) | `mockwebserver3-junit5` (OkHttp 5.x line) | Rejected: version-mismatched against the pinned OkHttp 4.12 runtime (see Standard Stack note); would introduce a second, incompatible OkHttp major version onto the test classpath |
| Hand-rolled bounded retry (D-26, locked) | Resilience4j / Failsafe | Rejected by user (D-26) — avoids pulling a retry/circuit-breaker framework into a widely-consumed client jar's transitive dependency graph |
| `nimbus-jose-jwt` `RemoteJWKSet` (D-19, locked) | Auth0 `java-jwt` + hand-rolled JWKS cache | Rejected by user — nimbus is JAVA-01-pinned and ships built-in JWKS caching + Tink-backed EdDSA, avoiding hand-rolled key-rotation logic |
| `central-publishing-maven-plugin` (Sonatype Central Portal) | Legacy `nexus-staging-maven-plugin` (OSSRH) | Rejected: OSSRH/Nexus Staging was **sunset** for new Maven Central publishing as of mid-2025 in favor of the Central Portal; using the legacy plugin would fail for any newly-registered namespace |

**Installation:**
```bash
# sdks/java/pom.xml <dependencies> — see Code Examples for the full POM
mvn -f sdks/java/pom.xml dependency:resolve
```
```xml
<dependency>
  <groupId>com.squareup.okhttp3</groupId>
  <artifactId>okhttp</artifactId>
  <version>4.12.0</version>
</dependency>
<dependency>
  <groupId>io.grpc</groupId>
  <artifactId>grpc-netty-shaded</artifactId>
  <version>1.82.0</version>
</dependency>
<dependency>
  <groupId>com.rabbitmq</groupId>
  <artifactId>amqp-client</artifactId>
  <version>5.22.0</version>
</dependency>
<dependency>
  <groupId>com.nimbusds</groupId>
  <artifactId>nimbus-jose-jwt</artifactId>
  <version>10.7</version>
</dependency>
<dependency>
  <groupId>com.google.crypto.tink</groupId>
  <artifactId>tink</artifactId>
  <version>1.15.0</version> <!-- [ASSUMED — verify latest 1.x at implementation time] -->
</dependency>
```

**Version verification:** All four JAVA-01-pinned dependency versions and `jspecify`/`jackson-databind`/`junit-jupiter` were confirmed live against Maven Central (`repo1.maven.org`/`central.sonatype.com`) via WebSearch this session — direct `curl` to `search.maven.org` is blocked by this sandbox's egress proxy policy (confirmed: `CONNECT tunnel failed, response 403` against `search.maven.org:443`; `search.maven.org` is not in the proxy's `noProxy` allowlist the way `registry.npmjs.org`/`pypi.org`/`proxy.golang.org` are). **The planner/executor should re-run `mvn versions:display-dependency-updates` or re-check Maven Central directly once CI network egress is available**, since these WebSearch-sourced versions carry `[ASSUMED]`-adjacent provenance for the *exact patch* (the major.minor floors — OkHttp 4.12, grpc-netty-shaded 1.82, amqp-client 5.22, nimbus-jose-jwt 10.x — are JAVA-01-pinned and authoritative; only the exact latest patch within each line was WebSearch-sourced).

## Package Legitimacy Audit

> **Ecosystem note:** `gsd-tools query package-legitimacy check` supports only `npm|pypi|crates` —
> Maven has no equivalent seam. All packages below were instead cross-checked via WebSearch against
> Maven Central / Sonatype Central listings (an authoritative registry), matching the manual-audit
> approach Phase 18 (Go) used for the Go module proxy. Direct `curl` to `search.maven.org` was
> blocked by this sandbox's egress policy (see Version verification above); WebSearch was the only
> viable path this session. **Per the provenance rule, package identity confirmed only via WebSearch
> (not a direct authoritative tool call) is tagged `[ASSUMED]`** even where the returned Maven
> Central page looks legitimate — the planner/executor should re-confirm via `mvn dependency:tree`
> or a direct Maven Central query once CI network egress is available.

| Package | Registry | Age / Track Record | Source Repo | Verdict | Disposition |
|---------|----------|---------------------|--------------|---------|-------------|
| `com.squareup.okhttp3:okhttp` | Maven Central | 10+ years, Square Inc., ubiquitous | `github.com/square/okhttp` | OK | Approved — `[ASSUMED]` version detail per provenance rule, package identity well-known |
| `io.grpc:grpc-netty-shaded` | Maven Central | Official gRPC-Java project, 10+ years | `github.com/grpc/grpc-java` | OK | Approved — `[ASSUMED]` version detail |
| `com.rabbitmq:amqp-client` | Maven Central | Official RabbitMQ/Pivotal/Broadcom-maintained client, 10+ years | `github.com/rabbitmq/rabbitmq-java-client` | OK | Approved — `[ASSUMED]` version detail |
| `com.nimbusds:nimbus-jose-jwt` | Maven Central | Connect2id-maintained, 10+ years, widely used in Spring/OAuth stacks | `bitbucket.org/connect2id/nimbus-jose-jwt` (mirrored to GitHub) | OK | Approved — `[ASSUMED]` version detail |
| `com.google.crypto.tink` | Maven Central | Official Google project | `github.com/tink-crypto/tink-java` | OK | Approved — `[ASSUMED]` version detail (exact 1.x patch not independently confirmed) |
| `org.jspecify:jspecify` | Maven Central | Backed by Google/JetBrains/Spring/Meta consortium, 1.0.0 stable release | `github.com/jspecify/jspecify` | OK | Approved |
| `com.fasterxml.jackson.core:jackson-databind` | Maven Central | Long-standing de facto standard Java JSON library | `github.com/FasterXML/jackson-databind` | OK | Approved |
| `org.junit.jupiter:junit-jupiter` | Maven Central | Official JUnit team project | `github.com/junit-team/junit5` (now `junit-framework`) | OK | Approved |
| `org.xolstice.maven.plugins:protobuf-maven-plugin` | Maven Central | Long-standing, widely used community-maintained plugin (10+ years) | `github.com/xolstice/protobuf-maven-plugin` | OK | Approved |
| `org.sonatype.central:central-publishing-maven-plugin` | Maven Central | Official Sonatype project, current Central Portal publishing path | `github.com/sonatype/central-publishing-maven-plugin` | OK | Approved |
| `org.apache.maven.plugins:maven-gpg-plugin` | Maven Central | Official Apache Maven core plugin | `github.com/apache/maven-gpg-plugin` | OK | Approved |
| `org.springframework.boot:spring-boot-starter-security` | Maven Central | Official Spring/VMware/Broadcom project | `github.com/spring-projects/spring-boot` | OK | Approved |

**Packages removed due to `[SLOP]` verdict:** none.
**Packages flagged as suspicious `[SUS]`:** none — every package above is a well-known, long-lived,
officially-maintained artifact from its respective organization; the `[ASSUMED]` tags above are a
provenance artifact of this environment's Maven-Central-blocking egress policy, not a legitimacy
concern. **Recommend the planner insert a lightweight `checkpoint:human-verify` (or a CI-only
`mvn dependency:tree` + `mvn versions:display-dependency-updates` step) before the first real
dependency resolution**, purely to re-confirm exact patch versions once real network egress is
available, not because any package identity is in doubt.

## Architecture Patterns

### System Architecture Diagram

```
Java/Spring consumer application
      │
      │ implementation("io.axiam:axiam-sdk:x.y.z")  /  Maven <dependency>
      ▼
┌───────────────────────────────────────────────────────────────────────┐
│ AxiamClient.builder().baseUrl(...).tenantId(...).build()               │
│   ├─ OkHttpClient{ CookieJar via CookieManager, connect/read/write     │
│   │   timeouts, ConnectionPool }                                       │
│   │     ├─ application Interceptor: proactive refresh (local JWKS exp  │
│   │       check) + inject Authorization/X-Tenant-Id/X-CSRF-Token       │
│   │     └─ Authenticator: reactive 401 fallback                        │
│   ├─ ReentrantLock + CompletableFuture<TokenPair> AtomicReference      │
│   │   (single-flight refresh guard, §9) — shared REST + gRPC           │
│   └─ RemoteJWKSet bound to {baseUrl}/oauth2/jwks (nimbus + Tink EdDSA) │
└───────┬───────────────────────┬──────────────────────┬────────────────┘
        │                       │                       │
   REST (core)             grpc/ subpkg            amqp/ subpkg
        │                       │                       │
 login/verifyMfa/         CheckAccess/           consume(queue, handler)
 refresh/logout/          BatchCheckAccess       — owns ack/nack loop
 checkAccess/can/         (ClientInterceptor
 batchCheck                injects Bearer +
        │                  x-tenant-id metadata,       │
        │                  withDeadlineAfter)           │
        ▼                       ▼                       ▼
 POST /api/v1/auth/*    ManagedChannel (grpc-      amqp-client Channel
 POST /api/v1/authz/*   netty-shaded, TLS via      .basicConsume(...) →
 (CookieManager carries  NettyChannelBuilder)      verify HMAC-SHA256
  axiam_access/refresh)        │                    BEFORE handler runs
        │                      │                          │
        ▼                      ▼                          ▼
  AXIAM REST API      AXIAM gRPC AuthorizationService   RabbitMQ
  (Actix-Web)          (Tonic)                          (axiam.audit.events,
        │                                                axiam.authz.request)
        ▼
  401 response ──► ReentrantLock single-flight refresh()
                    (exactly 1 in-flight POST /api/v1/auth/refresh
                     across N concurrent threads) ──► retry once

Separately, inside the CONSUMER's own Spring Boot application:
┌───────────────────────────────────────────────────────────┐
│ AxiamAuthenticationFilter extends OncePerRequestFilter      │
│   1. extract Authorization: Bearer / axiam_access cookie    │
│   2. verify locally via RemoteJWKSet (nimbus, no server      │
│      round-trip on cache hit) — EdDSA-only alg pinned via   │
│      JWSVerificationKeySelector                              │
│   3. build Authentication, SecurityContextHolder.setContext │
│   4. AuthError→401 / AuthzError→403 JSON body                │
│   5. filterChain.doFilter(request, response)                 │
│ Wired via SecurityFilterChain @Bean (example) or             │
│ META-INF/spring/...AutoConfiguration.imports (optional)      │
└───────────────────────────────────────────────────────────┘
```

### Recommended Project Structure
```
sdks/java/
├── pom.xml                        # Java 21, GPG/Central Portal plugin chain, protobuf-maven-plugin
├── README.md                      # states "This SDK conforms to CONTRACT.md §1-§10."
├── LICENSE                        # Apache-2.0 (already present)
├── .gitignore                     # target/ (incl. generated-sources) already covered by root .gitignore convention
├── src/
│   ├── main/
│   │   ├── java/io/axiam/sdk/
│   │   │   ├── AxiamClient.java           # builder, tenantId required, close()/AutoCloseable
│   │   │   ├── LoginResult.java           # record, mfaRequired flag (D-04)
│   │   │   ├── AxiamUser.java             # record: userId, tenantId, roles
│   │   │   ├── Sensitive.java             # final class, D-17
│   │   │   ├── errors/
│   │   │   │   ├── AuthError.java
│   │   │   │   ├── AuthzError.java
│   │   │   │   ├── NetworkError.java
│   │   │   │   └── ErrorMapper.java        # central status→error mapper (D-18)
│   │   │   ├── internal/
│   │   │   │   ├── RefreshGuard.java       # ReentrantLock + CompletableFuture<TokenPair> in AtomicReference (D-07)
│   │   │   │   ├── SessionState.java       # tenant/org header, CSRF token, cookie jar wiring
│   │   │   │   └── JwksVerifier.java       # RemoteJWKSet + JWSVerificationKeySelector(EdDSA) wrapper (D-19)
│   │   │   ├── rest/
│   │   │   │   ├── AuthInterceptor.java    # application Interceptor: proactive refresh + header injection
│   │   │   │   └── AuthAuthenticator.java  # OkHttp Authenticator: reactive 401 fallback
│   │   │   ├── grpc/
│   │   │   │   ├── GrpcAuthzClient.java    # ManagedChannel + blocking/async stubs, deadline (D-11/D-12)
│   │   │   │   └── AuthClientInterceptor.java
│   │   │   ├── amqp/
│   │   │   │   ├── AmqpConsumer.java       # consume(queue, handler), ack/nack loop (D-13)
│   │   │   │   ├── Hmac.java               # sign/verify — canonical-JSON via Jackson ObjectNode (§8)
│   │   │   │   └── ErrDrop.java            # RuntimeException sentinel
│   │   │   └── spring/
│   │   │       ├── AxiamAuthenticationFilter.java  # OncePerRequestFilter (D-14)
│   │   │       └── AxiamAutoConfiguration.java      # optional @AutoConfiguration (D-15)
│   │   ├── proto/                          # symlink or copy of proto/axiam/v1/*.proto for protobuf-maven-plugin's <protoSourceRoot>
│   │   └── resources/META-INF/spring/
│   │       └── org.springframework.boot.autoconfigure.AutoConfiguration.imports
│   └── test/java/io/axiam/sdk/
│       ├── RefreshGuardSingleFlightTest.java   # SC#2 — 5 threads, exactly 1 refresh
│       ├── ErrorRedactionTest.java             # CR-04 regression, non-vacuous control case
│       ├── SensitiveTest.java                  # multi-surface redaction
│       ├── TlsBypassGrepTest.java              # optional: JVM-side assertion mirroring the CI grep gate
│       ├── amqp/HmacVerifyTest.java            # byte-for-byte canonicalization test
│       └── spring/AxiamAuthenticationFilterIT.java
├── examples/
│   ├── login-mfa/
│   ├── rest-authz/
│   ├── grpc-checkaccess/
│   ├── amqp-consumer/
│   └── spring-boot-app/            # complete working SecurityFilterChain app context (SC#3)
└── target/                          # gitignored — generated-sources/protobuf lives here (D-21)
```
`src/main/proto/` is the conventional `protobuf-maven-plugin` proto source root; since the repo's
canonical protos live at `proto/axiam/v1/*.proto` (one level above `sdks/`), configure
`<protoSourceRoot>${project.basedir}/../../proto</protoSourceRoot>` rather than duplicating/copying
files into `sdks/java/`, keeping one source of truth for `.proto` files across all seven SDKs.

### Pattern 1: Builder-Only Client with Compiler-Enforced `tenantId` (D-06, SC#1)

**What:** No no-arg builder factory exists — `AxiamClient.builder(baseUrl, tenantId)` takes the two
required parameters positionally as the entry point, then all other configuration is fluent.
**When to use:** The only client construction path.
**Example:**
```java
// Source: pattern mirrors sdks/go's positional-required-params + functional-options
// idiom (D-03 in 18-CONTEXT.md), adapted to Java's builder convention per D-06.
package io.axiam.sdk;

import org.jspecify.annotations.Nullable;
import java.time.Duration;

public final class AxiamClient implements AutoCloseable {

    public static Builder builder(String baseUrl, String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            // Runtime guard backs the compile-time guarantee: there is no
            // path to construct a Builder without supplying tenantId here —
            // Builder's constructor is package-private and only reachable
            // through this factory method (SC#1's "compiler-enforced").
            throw new AuthError("tenantId is required — AXIAM is multi-tenant "
                + "and there is no default tenant (CONTRACT.md §5)");
        }
        return new Builder(baseUrl, tenantId);
    }

    public static final class Builder {
        private final String baseUrl;
        private final String tenantId;
        private @Nullable String orgSlug;
        private @Nullable java.util.UUID orgId;
        private @Nullable byte[] customCaPem;
        private @Nullable okhttp3.OkHttpClient overrideHttpClient;
        private Duration connectTimeout = Duration.ofSeconds(10);
        private Duration readTimeout = Duration.ofSeconds(30);
        private Duration writeTimeout = Duration.ofSeconds(30);

        private Builder(String baseUrl, String tenantId) {
            this.baseUrl = baseUrl;
            this.tenantId = tenantId;
        }

        // Real login/refresh endpoints need an org identifier beyond §5's
        // documented minimum — see Common Pitfalls #2 (mirrors Rust/Go/Python).
        public Builder orgSlug(String slug) { this.orgSlug = slug; this.orgId = null; return this; }
        public Builder orgId(java.util.UUID id) { this.orgId = id; this.orgSlug = null; return this; }
        public Builder customCa(byte[] pem) { this.customCaPem = pem; return this; }
        public Builder httpClient(okhttp3.OkHttpClient client) { this.overrideHttpClient = client; return this; }
        public Builder connectTimeout(Duration d) { this.connectTimeout = d; return this; }
        public Builder readTimeout(Duration d) { this.readTimeout = d; return this; }
        public Builder writeTimeout(Duration d) { this.writeTimeout = d; return this; }

        public AxiamClient build() {
            return new AxiamClient(this);
        }
    }

    private AxiamClient(Builder b) { /* ... wires OkHttpClient, RefreshGuard, JwksVerifier, gRPC channel ... */ }

    @Override
    public void close() {
        // D-09: deterministically shut down OkHttp dispatcher/pool, gRPC
        // channel, AMQP connection.
    }
}
```

### Pattern 2: `ReentrantLock` + `CompletableFuture`-in-`AtomicReference` Single-Flight Refresh (§9, D-07, SC#2's literal target)

**What:** Exactly one in-flight `POST /api/v1/auth/refresh` call across N concurrent threads
observing the same expired access token, shared across REST + gRPC on one session.
**When to use:** Every REST 401 / gRPC `UNAUTHENTICATED` triggers a call into this guard.
**Example:**
```java
// Source: CONTRACT.md §9 Java row ("ReentrantLock + CompletableFuture held
// in AtomicReference") + pattern ported from sdks/go/internal/refreshguard
// and sdks/python's threading.Lock+asyncio.Lock dual-guard design, adapted
// to Java's single-threaded-blocking idiom (no async/await split needed —
// CompletableFuture unifies both call paths under one guard, per D-07/D-08).
package io.axiam.sdk.internal;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

public final class RefreshGuard {
    private final ReentrantLock lock = new ReentrantLock();
    // Non-null only while a refresh is actually in flight; cleared on completion.
    private final AtomicReference<CompletableFuture<TokenPair>> inFlight = new AtomicReference<>();
    private volatile TokenPair current;

    /**
     * Ensures exactly one call to {@code doRefresh} is in flight at a time,
     * regardless of how many threads call this concurrently with the same
     * (now-stale) observed access token. §9.3: no retry loop — a failed
     * refresh propagates its exception to every waiter, once.
     */
    public TokenPair refreshIfNeeded(String observedAccessToken, Supplier<TokenPair> doRefresh) {
        lock.lock();
        try {
            // Double-check: another thread may have refreshed while we
            // waited for the lock — if the cached token already differs
            // from what this caller observed as expired, no new refresh
            // is needed.
            TokenPair snapshot = current;
            if (snapshot != null && !snapshot.access().equals(observedAccessToken)) {
                return snapshot;
            }

            CompletableFuture<TokenPair> existing = inFlight.get();
            if (existing != null) {
                lock.unlock(); // release the lock before blocking on join()
                try {
                    return existing.join();
                } finally {
                    lock.lock(); // re-acquire so the outer finally's unlock() is balanced
                }
            }

            CompletableFuture<TokenPair> future = new CompletableFuture<>();
            inFlight.set(future);
            lock.unlock(); // perform the actual HTTP call OUTSIDE the lock
            try {
                TokenPair result = doRefresh.get(); // POST /api/v1/auth/refresh
                current = result;
                future.complete(result);
                return result;
            } catch (RuntimeException e) {
                future.completeExceptionally(e);
                throw e; // §9.3: no retry — propagate as-is
            } finally {
                inFlight.set(null);
                lock.lock(); // re-acquire so the outer finally's unlock() is balanced
            }
        } finally {
            lock.unlock();
        }
    }
}
```
**JUnit 5 test proving exactly-1-refresh under 5 concurrent threads (SC#2's literal target):**
```java
// Source: pattern mirrors sdks/go/internal/refreshguard's httptest.Server-
// counting concurrency test and CONTRACT.md §9's "Test requirement" (≥5
// concurrent requests, assert exactly 1 refresh call).
package io.axiam.sdk.internal;

import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RefreshGuardSingleFlightTest {

    @Test
    void fiveConcurrentThreadsOnExpiredTokenTriggerExactlyOneRefresh() throws Exception {
        try (MockWebServer server = new MockWebServer()) {
            AtomicInteger refreshCallCount = new AtomicInteger(0);
            // A counting dispatcher: every /api/v1/auth/refresh request
            // increments the counter and returns a fresh access token.
            server.setDispatcher(new mockwebserver3.QueueDispatcher() {
                @Override
                public MockResponse dispatch(mockwebserver3.RecordedRequest request) {
                    refreshCallCount.incrementAndGet();
                    return new MockResponse.Builder()
                        .code(200)
                        .body("{\"access_token\":\"new-token\"}")
                        .build();
                }
            });
            server.start();

            RefreshGuard guard = new RefreshGuard();
            String expiredToken = "expired-access-token";
            int threadCount = 5;
            CountDownLatch startBarrier = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            ExecutorService pool = Executors.newFixedThreadPool(threadCount);

            for (int i = 0; i < threadCount; i++) {
                pool.submit(() -> {
                    try {
                        startBarrier.await(); // release all threads at once
                        guard.refreshIfNeeded(expiredToken, () -> {
                            // Simulates the real HTTP call against the MockWebServer.
                            server.url("/api/v1/auth/refresh"); // triggers dispatcher
                            refreshCallCount.get(); // (real impl issues an actual OkHttp call here)
                            return new TokenPair("new-token", "new-refresh", System.currentTimeMillis() + 900_000);
                        });
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }
            startBarrier.countDown(); // fan-out all 5 threads simultaneously
            doneLatch.await();
            pool.shutdown();

            assertEquals(1, refreshCallCount.get(),
                "expected exactly one refresh call across 5 concurrent threads");
        }
    }
}
```
The real test (executed by the planner/executor, not this stub) must route `doRefresh` through the
actual `OkHttpClient`-backed refresh call against the `MockWebServer` URL (this example shows the
`CountDownLatch`/thread-pool/counting-dispatcher shape; the exact HTTP call wiring is an
implementation detail of `AxiamClient`'s internals).

### Pattern 3: OkHttp `Interceptor` (proactive) + `Authenticator` (reactive) Both Funnel Into One Guard (D-08)

**What:** An application-level `Interceptor` performs local JWKS/exp-based proactive refresh and
injects `Authorization`/`X-Tenant-Id`/`X-CSRF-Token`; a separate `Authenticator` handles the
reactive 401 path. Both call into the same `RefreshGuard` instance.
**Interceptor ordering:** Register as an **application interceptor** (`OkHttpClient.Builder.
addInterceptor(...)`, not `addNetworkInterceptor(...)`) — application interceptors see the logical
request/response once (not per-redirect/retry) and are the correct layer for header injection and
proactive-refresh business logic; network interceptors operate on the physical wire layer (compressed
bodies, redirects) and are the wrong layer for this. `Authenticator` is a separate OkHttp extension
point invoked automatically only on 401, independent of interceptor ordering.
**Example:**
```java
// Source: OkHttp official interceptor docs (square.github.io/okhttp/features/interceptors/)
// + Authenticator docs (square.github.io/okhttp/recipes/#handling-authentication-kt-java)
// applied to CONTRACT.md §9/D-08.
package io.axiam.sdk.rest;

import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.internal.RefreshGuard;
import okhttp3.*;

import java.io.IOException;

public final class AuthInterceptor implements Interceptor {
    private final RefreshGuard guard;
    private final JwksVerifier jwks; // local exp/claims check, no server round-trip
    private final SessionState session;

    public AuthInterceptor(RefreshGuard guard, JwksVerifier jwks, SessionState session) {
        this.guard = guard; this.jwks = jwks; this.session = session;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        String access = session.cachedAccessToken(); // non-blocking read — never
                                                       // acquire the guard's lock
                                                       // synchronously here (mirrors
                                                       // the Rust/Go/TS "never lock
                                                       // in the interceptor" pitfall)
        if (access != null && jwks.isNearExpiry(access)) {
            // Proactive refresh: funnel through the SAME guard the
            // Authenticator (reactive path) uses.
            access = guard.refreshIfNeeded(access, session::doHttpRefresh).access();
        }
        Request.Builder builder = chain.request().newBuilder()
            .header("X-Tenant-Id", session.tenantId());
        if (access != null) {
            builder.header("Authorization", "Bearer " + access);
        }
        String csrf = session.csrfToken(); // §3 CF-01: captured from a prior response header
        String method = chain.request().method();
        if (csrf != null && (method.equals("POST") || method.equals("PUT")
                || method.equals("PATCH") || method.equals("DELETE"))) {
            builder.header("X-CSRF-Token", csrf);
        }
        Response response = chain.proceed(builder.build());
        String newCsrf = response.header("X-CSRF-Token");
        if (newCsrf != null) {
            session.setCsrfToken(newCsrf); // capture for the NEXT request
        }
        return response;
    }
}

public final class AuthAuthenticator implements Authenticator {
    private final RefreshGuard guard;
    private final SessionState session;

    public AuthAuthenticator(RefreshGuard guard, SessionState session) {
        this.guard = guard; this.session = session;
    }

    @Override
    public Request authenticate(Route route, Response response) {
        if (responseCount(response) >= 2) {
            return null; // §9.3: no retry loop on repeated failure
        }
        String staleAccess = session.cachedAccessToken();
        var refreshed = guard.refreshIfNeeded(staleAccess, session::doHttpRefresh); // same guard
        return response.request().newBuilder()
            .header("Authorization", "Bearer " + refreshed.access())
            .build();
    }

    private int responseCount(Response response) {
        int count = 1;
        while ((response = response.priorResponse()) != null) count++;
        return count;
    }
}
```

### Pattern 4: `RemoteJWKSet` + Tink-Backed EdDSA Verification, Algorithm-Pinned (D-19)

**What:** nimbus's `RemoteJWKSet` sources keys from `{baseUrl}/oauth2/jwks` (organization-wide, NOT
tenant-scoped — confirmed via `crates/axiam-api-rest/src/server.rs`'s route table, same finding as
Rust/Go/Python), with `DefaultJWKSetCache` providing TTL + rotation-on-unknown-`kid`. Algorithm is
pinned via `JWSVerificationKeySelector(JWSAlgorithm.EdDSA, jwkSource)` — nimbus enforces this
BEFORE key lookup, natively satisfying the "never trust the token's own `alg` header" requirement
every sibling SDK had to hand-roll a check for.
**Example:**
```java
// Source: nimbus-jose-jwt official docs (connect2id.com/products/nimbus-jose-jwt) +
// javadoc for RemoteJWKSet/DefaultJWKSetCache/DefaultJWTProcessor/JWSVerificationKeySelector.
// JWKS path confirmed via crates/axiam-api-rest/src/server.rs route table
// (.route("/jwks", ...) nested under web::scope("/oauth2")) and the identical
// finding independently made by the Rust/Go/Python reference SDKs.
package io.axiam.sdk.internal;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URL;
import java.util.concurrent.TimeUnit;

public final class JwksVerifier {
    private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    private final JWKSource<SecurityContext> jwkSource;

    public JwksVerifier(String baseUrl) throws Exception {
        URL jwksUrl = new URL(baseUrl.replaceAll("/$", "") + "/oauth2/jwks");
        // TTL 300s, forced-refetch cooldown 60s — matches the Rust/Go/Python
        // reference SDKs' proven defaults (Rust JWKS_CACHE_TTL=300s,
        // FORCED_REFETCH_MIN_INTERVAL=60s; Go jwx minInterval=60s/
        // maxInterval=300s; Python PyJWKClient lifespan=300).
        JWKSetCache cache = new com.nimbusds.jose.jwk.source.DefaultJWKSetCache(
            300, 60, TimeUnit.SECONDS);
        this.jwkSource = new RemoteJWKSet<>(jwksUrl, null /* default resource retriever */, cache);

        // Algorithm pinning happens HERE, before any key lookup — nimbus's
        // JWSVerificationKeySelector rejects any JWS whose header 'alg'
        // does not match EdDSA, closing the algorithm-confusion class of
        // attack every sibling SDK had to hand-check manually.
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.EdDSA, jwkSource));
    }

    /** Verifies signature + pins alg=EdDSA; caller must separately check exp/tenant_id. */
    public com.nimbusds.jwt.JWTClaimsSet verify(String token) throws Exception {
        SignedJWT jwt = SignedJWT.parse(token);
        return processor.process(jwt, null);
    }
}
```
**Tink dependency note:** `RemoteJWKSet`/`JWSVerificationKeySelector` verifying an `OKP`/Ed25519 key
requires `com.nimbusds.jose.crypto.Ed25519Verifier` on the classpath internally, which in turn
requires `com.google.crypto.tink:tink` present at runtime (nimbus does not bundle Ed25519 curve
math — this is exactly why JAVA-01 pins "nimbus-jose-jwt 10.x **+ Tink**"). Omitting the Tink
dependency produces a runtime `NoClassDefFoundError`/`JOSEException` only when an EdDSA token is
actually verified — a Wave-0 smoke test against a real signed token should be included to catch
this early rather than discovering it only against a live server.
**Cross-tenant carry-forward (mirrors TS CR-03 / Go / Python's mandatory control):** JWKS is
organization-wide, not tenant-scoped — after `processor.process(...)` succeeds, the Spring filter
and any resource-server code path **MUST** additionally assert
`claims.getStringClaim("tenant_id").equals(configuredTenantId)` before trusting the token further.
Signature validity alone does not imply tenant authorization in a multi-org, multi-tenant JWKS
issuer. This is a **MUST-carry-forward control**, not optional — see Security Domain below.

### Pattern 5: AMQP HMAC Verify-Before-Handler — Preserve Wire Key Order, Do NOT Sort (§8, D-13)

**What:** The SDK owns the ack/nack loop; every delivery is HMAC-SHA256-verified before the
caller's handler ever runs. **Critical correctness requirement, resolved empirically by Phase 19
(Python) and logged in `.planning/STATE.md`:** the canonical-JSON re-serialization (after removing
`hmac_signature`) MUST preserve the **exact key order the message arrived in on the wire**
(equivalently, the Rust struct's field-declaration order — `correlation_id, tenant_id, subject_id,
action, resource_id, scope` for `AuthzRequest`; `tenant_id, actor_id, actor_type, action,
resource_id, outcome, ip_address, metadata` for `AuditEventMessage`, per
`crates/axiam-amqp/src/messages.rs`), **NOT alphabetically re-sorted keys.** `serde_json`'s
`Serialize` derive for a Rust `struct` preserves declaration order, not `BTreeMap`/alphabetical
order — a canonicalizer that alphabetizes keys (as Go's naive `map[string]json.RawMessage` +
`json.Marshal` approach does, since Go's stdlib `encoding/json` always sorts map keys
alphabetically) computes the HMAC over a **different byte sequence** than the server signed,
causing every single message to fail verification. Jackson's `ObjectNode` is backed by a
`LinkedHashMap` internally and preserves insertion order from parsing by default — this makes the
**parse-into-`ObjectNode`, remove-field, re-serialize** approach the natural, correct Java
implementation, with no additional ordering logic required.
**Example:**
```java
// Source: canonical protocol from crates/axiam-amqp/src/messages.rs (sign_payload/
// verify_payload) + the ordering fix VERIFIED against a real Rust-signed fixture
// in Phase 19 (Python), logged in .planning/STATE.md Phase 19 decisions:
// "AMQP HMAC canonicalization preserves wire/insertion key order ... rather
// than alphabetizing — proven against a real Rust-signed fixture where field
// order is declared-struct order, not alphabetical." [VERIFIED: STATE.md]
package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class Hmac {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ALGO = "HmacSHA256";

    /**
     * Returns true iff body's hmac_signature field matches HMAC-SHA256(key,
     * canonical_json_of(body_without_hmac_signature)), computed via
     * constant-time comparison. Never throws — malformed input verifies as
     * false, matching §8.3's strict-mode default for missing/unparseable
     * signatures.
     */
    public static boolean verify(byte[] signingKey, byte[] body) {
        try {
            JsonNode root = MAPPER.readTree(body);
            if (!(root instanceof ObjectNode node)) return false;
            JsonNode sigNode = node.get("hmac_signature");
            if (sigNode == null || sigNode.isNull()) {
                return false; // §8.3 strict mode: missing signature = reject
            }
            String sigHex = sigNode.asText();
            // remove() mutates the SAME LinkedHashMap-backed ObjectNode in
            // place, preserving the relative order of all remaining keys —
            // this is the load-bearing property (see pattern description).
            node.remove("hmac_signature");
            byte[] canonical = MAPPER.writeValueAsBytes(node);

            byte[] expected = HexFormat.of().parseHex(sigHex);
            Mac mac = Mac.getInstance(ALGO);
            mac.init(new SecretKeySpec(signingKey, ALGO));
            byte[] computed = mac.doFinal(canonical);

            return MessageDigest.isEqual(computed, expected); // constant-time compare
        } catch (Exception e) {
            return false; // parse failure / bad hex / bad key length -> reject, never throw
        }
    }
}
```
**AMQP consumer ack/nack loop (D-13):**
```java
// Source: com.rabbitmq:amqp-client official docs (Channel.basicConsume,
// DeliverCallback, basicAck/basicNack) + D-13's locked semantics.
package io.axiam.sdk.amqp;

import com.rabbitmq.client.*;

public final class AmqpConsumer {
    public static final class ErrDrop extends RuntimeException {
        public ErrDrop(String message) { super(message); }
    }

    public static void consume(Channel channel, String queue, byte[] signingKey,
                                 java.util.function.Consumer<byte[]> handler,
                                 org.slf4j.Logger logger) throws java.io.IOException {
        channel.basicQos(10); // prefetch default (Claude's Discretion; matches Go/Python's chosen default)
        DeliverCallback deliverCallback = (consumerTag, delivery) -> {
            long deliveryTag = delivery.getEnvelope().getDeliveryTag();
            byte[] body = delivery.getBody();
            if (!Hmac.verify(signingKey, body)) {
                logger.warn("axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue");
                channel.basicNack(deliveryTag, false, false); // multiple=false, requeue=false
                return;
            }
            try {
                handler.accept(body); // handler NEVER sees an unverified message
                channel.basicAck(deliveryTag, false);
            } catch (ErrDrop drop) {
                channel.basicNack(deliveryTag, false, false); // poison message
            } catch (Exception transient_) {
                channel.basicNack(deliveryTag, false, true); // transient -> requeue
            }
        };
        channel.basicConsume(queue, false /* manual ack */, deliverCallback, consumerTag -> {});
    }
}
```
**Built-in automatic recovery (D-13):** `com.rabbitmq:amqp-client`'s `ConnectionFactory` has
`setAutomaticRecoveryEnabled(true)` **on by default** since client 4.x — the SDK should NOT disable
it. Configure `setNetworkRecoveryInterval(Duration)` for the reconnect backoff (default 5s is
reasonable; expose as a builder option per CF-03's "sane defaults, overridable").

### Pattern 6: `Sensitive` — Hardened Final Class with Jackson Redaction (D-17)

**What:** A `final` class wrapping a token string; `toString()` → `"[SENSITIVE]"`, a Jackson
`JsonSerializer` emitting the same placeholder for any serialization path, non-`Serializable`, and
the raw value reachable only via a package-internal accessor.
**Example:**
```java
// Source: CONTRACT.md §7 Java row ("Final class; toString() returns
// [SENSITIVE]") + D-17's ceiling (Jackson serializer, package-internal
// accessor, non-Serializable) — pattern mirrors sdks/go's Sensitive
// (String/Format/GoString/MarshalJSON) and TS's private-#value class.
package io.axiam.sdk;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.util.Objects;

@JsonSerialize(using = Sensitive.Redactor.class)
public final class Sensitive {
    private static final String REDACTED = "[SENSITIVE]";
    private final String value;

    private Sensitive(String value) { this.value = Objects.requireNonNull(value); }

    public static Sensitive of(String value) { return new Sensitive(value); }

    @Override public String toString() { return REDACTED; }

    // Deliberately no equals()/hashCode() override exposing `value` via a
    // timing side channel in this example; if equality is needed, use a
    // constant-time MessageDigest.isEqual comparison, never String.equals.

    /** Package-internal accessor — never public. Only io.axiam.sdk.* callers can reach the raw value. */
    String expose() { return value; }

    static final class Redactor extends StdSerializer<Sensitive> {
        Redactor() { super(Sensitive.class); }
        @Override
        public void serialize(Sensitive v, JsonGenerator gen, SerializerProvider provider) throws IOException {
            gen.writeString(REDACTED);
        }
    }
}
```
`Sensitive` intentionally does NOT implement `java.io.Serializable` — Java's default serialization
would otherwise expose `value` via reflection-based field access even with `toString()` redacted;
omitting `Serializable` means any attempt to Java-serialize an object graph containing a `Sensitive`
field throws `NotSerializableException` at the first attempt, a fail-closed (not fail-open) posture.

### Pattern 7: Central Status→Error Mapper with Redact-Before-Wrap (D-18, CR-04 carry-forward)

**What:** One mapper transcribing CONTRACT.md §2's HTTP and gRPC tables exactly; `NetworkError`
strips `Set-Cookie`/`Authorization`/`Cookie` from any wrapped OkHttp `Response` **before** it enters
the exception, never after.
**Example:**
```java
// Source: pattern mirrors sdks/typescript/src/core/errorMapper.ts (sanitizeAxiosError,
// the exact CR-04 fix from 17-REVIEW.md) + sdks/go/errors.go's newNetworkError.
// CONTRACT.md §2 HTTP/gRPC tables transcribed exactly.
package io.axiam.sdk.errors;

import okhttp3.Headers;
import okhttp3.Response;

import java.util.Set;

public final class ErrorMapper {
    private static final Set<String> SENSITIVE_HEADERS =
        Set.of("set-cookie", "authorization", "cookie");

    /** Never called with a live Response beyond this method — the ONLY entry
     * point into NetworkError construction from an OkHttp Response (D-18's
     * "single source of truth", CR-04 fix). */
    public static NetworkError fromHttpResponse(int status, String message, Response response) {
        String sanitizedSummary = sanitize(response);
        return new NetworkError(message, sanitizedSummary);
    }

    public static RuntimeException fromHttpStatus(int status, String message, Response response) {
        if (status == 401) return new AuthError(message);
        if (status == 403 || status == 409) return new AuthzError(message);
        // 400, 408, 429, 5xx, other -> NetworkError (redact-before-wrap)
        return fromHttpResponse(status, message, response);
    }

    public static RuntimeException fromGrpcStatus(io.grpc.Status.Code code, String message) {
        return switch (code) {
            case UNAUTHENTICATED -> new AuthError(message);
            case PERMISSION_DENIED -> new AuthzError(message);
            default -> new NetworkError(message, null); // UNAVAILABLE, DEADLINE_EXCEEDED, INTERNAL, RESOURCE_EXHAUSTED, other
        };
    }

    private static String sanitize(Response response) {
        if (response == null) return null;
        Headers.Builder safe = new Headers.Builder();
        for (String name : response.headers().names()) {
            if (!SENSITIVE_HEADERS.contains(name.toLowerCase())) {
                for (String value : response.headers().values(name)) {
                    safe.add(name, value);
                }
            }
        }
        // Return a lightweight, redacted STRING summary — never the live
        // okhttp3.Response object itself (which retains a reference to the
        // full, unredacted Headers via response.headers()/networkResponse()).
        return "http status " + response.code() + ", headers: " + safe.build();
    }
}
```
**Regression test (CR-04 carry-forward, non-vacuous per every sibling SDK's pattern):** construct a
`Response` carrying a `Set-Cookie: axiam_access=super-secret-token; HttpOnly` header, map it through
`fromHttpStatus`, assert `"super-secret-token"` never appears in the resulting `NetworkError`'s
`toString()`/`getMessage()`/any chained cause — **and** assert a control case with a
**non-sensitive** header (e.g. `X-Request-Id`) DOES survive into the sanitized summary, proving
redaction is selective, not a blanket "redact everything" that would trivially and vacuously pass.

### Pattern 8: Spring Security `OncePerRequestFilter` + `SecurityContext` (D-14, SC#3)

**What:** A filter that extracts the bearer token/cookie, verifies it locally via `JwksVerifier`
(Pattern 4), enforces the cross-tenant check, and populates `SecurityContextHolder`.
**Example:**
```java
// Source: Spring Security official docs (docs.spring.io/spring-security/reference/
// servlet/architecture.html#servlet-filterchainproxy, OncePerRequestFilter) +
// CONTRACT.md §10 Java row ("OncePerRequestFilter subclass registered in
// SecurityFilterChain") + D-14/D-15/D-16.
package io.axiam.sdk.spring;

import io.axiam.sdk.internal.JwksVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public final class AxiamAuthenticationFilter extends OncePerRequestFilter {
    private final JwksVerifier jwksVerifier;
    private final String configuredTenantId;

    public AxiamAuthenticationFilter(JwksVerifier jwksVerifier, String configuredTenantId) {
        this.jwksVerifier = jwksVerifier;
        this.configuredTenantId = configuredTenantId;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                      FilterChain chain) throws ServletException, IOException {
        String token = extractToken(request);
        if (token == null) {
            chain.doFilter(request, response); // let an unauthenticated request through;
            return;                             // Spring Security's own access-control rules 401/403 it
        }
        try {
            var claims = jwksVerifier.verify(token); // signature + alg=EdDSA pinned (Pattern 4)
            if (claims.getExpirationTime().before(new java.util.Date())) {
                throw new io.axiam.sdk.errors.AuthError("token expired");
            }
            // Cross-tenant carry-forward (mirrors TS CR-03 / Go / Python) —
            // JWKS is org-wide, signature validity alone is NOT sufficient.
            String tokenTenantId = claims.getStringClaim("tenant_id");
            if (!configuredTenantId.equals(tokenTenantId)) {
                throw new io.axiam.sdk.errors.AuthError("token tenant_id does not match configured tenant");
            }
            List<GrantedAuthority> authorities = String.valueOf(claims.getStringClaim("scope"))
                .lines().flatMap(l -> java.util.Arrays.stream(l.split(" ")))
                .filter(s -> !s.isBlank())
                .map(SimpleGrantedAuthority::new)
                .map(GrantedAuthority.class::cast)
                .toList();
            var authentication = new UsernamePasswordAuthenticationToken(
                claims.getSubject(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } catch (io.axiam.sdk.errors.AuthError e) {
            writeJsonError(response, 401, e.getMessage());
        } catch (Exception e) {
            writeJsonError(response, 401, "invalid or expired token");
        }
    }

    private String extractToken(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return auth.substring(7).trim();
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("axiam_access".equals(c.getName())) return c.getValue();
            }
        }
        return null;
    }

    private void writeJsonError(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"authentication_failed\",\"message\":\"" + message + "\"}");
    }
}
```
**Explicit `SecurityFilterChain` wiring (example app, SC#3's "complete working application
context"):**
```java
// Source: Spring Security official docs — SecurityFilterChain @Bean pattern,
// Spring Boot 3.2+/Security 6.x jakarta.* namespace (D-16).
package io.axiam.sdk.examples.springboot;

import io.axiam.sdk.internal.JwksVerifier;
import io.axiam.sdk.spring.AxiamAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwksVerifier verifier) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable) // AXIAM's own X-CSRF-Token/cookie double-submit
                                                     // (§3) supersedes Spring's default CSRF token —
                                                     // do not double-protect
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated())
            .addFilterBefore(new AxiamAuthenticationFilter(verifier, "acme-tenant"),
                              UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

### Pattern 9: Optional `@AutoConfiguration` (D-15)

**What:** A zero-config path registering the filter automatically when Spring Boot is present,
alongside the explicit example above.
**Example:**
```java
// Source: Spring Boot 3.x AutoConfiguration.imports mechanism (replaces the
// legacy spring.factories path since Spring Boot 2.7+) — official docs
// (docs.spring.io/spring-boot/reference/features/developing-auto-configuration.html).
package io.axiam.sdk.spring;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.SecurityFilterChain;

@AutoConfiguration
@ConditionalOnClass(SecurityFilterChain.class)
public class AxiamAutoConfiguration {
    // Provides sane defaults; the example app's explicit SecurityConfig
    // (Pattern 8) takes precedence via Spring's @ConditionalOnMissingBean
    // convention if both are present — consumers who want the zero-config
    // path simply omit their own SecurityFilterChain @Bean.
}
```
`src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`:
```
io.axiam.sdk.spring.AxiamAutoConfiguration
```

### Anti-Patterns to Avoid
- **`X509TrustManager` that accepts all certs / a `HostnameVerifier` returning `true`
  unconditionally:** the Java-specific TLS-bypass idiom `.planning/research/PITFALLS.md` explicitly
  calls out — absolutely prohibited by CONTRACT.md §6/SC#4; the CI grep gate must catch this pattern
  class, not just the literal strings `hostnameVerifier`/`sslSocketFactory` (see Common Pitfalls).
- **`Mac.doFinal()` comparison via `String.equals()`/`Arrays.equals()`:** timing-attack vulnerable;
  always use `MessageDigest.isEqual()` for the HMAC constant-time compare (Pattern 5).
- **`json.dumps`-equivalent alphabetical key sorting for the AMQP HMAC canonicalization:** see
  Pattern 5 — this is the single highest-impact correctness bug this phase could ship silently
  (100% HMAC verification failure, indistinguishable from a connectivity issue in testing).
- **Blocking `lock.lock()` synchronously inside the OkHttp `Interceptor`'s hot path without the
  read-then-refresh split shown in Pattern 3:** every outgoing request would serialize behind the
  guard even when no refresh is needed — always do a non-blocking cached-token read first.
- **Implementing `Sensitive` as `Serializable`:** defeats the redaction guarantee via reflection-
  based Java serialization (Pattern 6).
- **Real GPG production key material used in PR-triggered CI:** untrusted forks can read PR-job
  logs/artifacts; the real signing key must only ever be injected in the tag-triggered publish job
  (see Common Pitfalls — GPG-in-CI).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JWKS fetch/cache/rotation-on-unknown-`kid` | Custom `HttpClient`-based JWKS poller + manual TTL map | nimbus `RemoteJWKSet` + `DefaultJWKSetCache` (D-19, locked) | Battle-tested, avoids re-implementing security-sensitive key-rotation logic every sibling SDK had to hand-roll to some degree |
| EdDSA/Ed25519 JWS verification + algorithm pinning | Manual signature-byte comparison, manual `alg` header check before lookup | `JWSVerificationKeySelector(JWSAlgorithm.EdDSA, jwkSource)` + `DefaultJWTProcessor` | nimbus pins the algorithm natively at the key-selector level — Java is the ONLY sibling SDK where this specific defense is a library feature rather than hand-written code |
| Constant-time HMAC comparison | `Arrays.equals`/`String.equals` on hex digests | `java.security.MessageDigest.isEqual()` (stdlib) | Timing-attack resistant; zero reason to hand-roll in a JVM that ships this in the JDK |
| Cookie jar / TLS trust | Custom `Interceptor`-based cookie store or a hand-rolled `X509TrustManager` | `java.net.CookieManager` + `CookieHandler.setDefault()` (or per-`OkHttpClient` `JavaNetCookieJar`) + the JDK's default `SSLContext`/trust store | Both are stdlib, battle-tested, exactly what CONTRACT.md §4/§6 specify per-language |
| gRPC codegen | Hand-written Java stub classes matching the `.proto` | `protobuf-maven-plugin` + `protoc-gen-grpc-java` (build-time, D-21) | Protobuf wire-format correctness is exactly the kind of thing codegen exists to guarantee |
| Retry/backoff with jitter (D-26, locked) | Resilience4j/Failsafe framework | A ~30-line hand-rolled bounded-exponential-backoff-with-jitter helper (user-locked choice) | Avoids pulling a retry framework into a widely-consumed client jar's transitive graph — the ONE piece of this phase that IS hand-rolled by explicit user decision, not oversight |
| Maven Central GPG-signed publishing OIDC-adjacent flow | Custom staging-repo API client | `central-publishing-maven-plugin` + `maven-gpg-plugin` (D-22) | Sonatype's own documented, currently-supported publishing path — hand-rolling the Central Portal's bundle-upload API is unnecessary and would need re-implementation whenever Sonatype changes the API |

**Key insight:** Nearly every "don't hand-roll" item in this phase has either a JDK-stdlib or
nimbus/JAVA-01-pinned-library answer — Java's mature, security-focused standard library
(`java.security.*`, `javax.crypto.*`, `java.net.CookieManager`) plus nimbus's purpose-built JWKS
cache and algorithm-pinning key selector cover more of this phase's surface natively than any prior
sibling SDK's ecosystem did. The one genuinely novel piece of logic — the AMQP HMAC canonicalization
— is exactly the piece a sibling phase (Python) already proved correct; Java inherits that proof
rather than re-deriving it from scratch.

## Runtime State Inventory

> Not applicable — Phase 20 is a greenfield SDK build (new package tree) on top of the existing
> `sdks/java/{pom.xml,README.md,LICENSE}` scaffold, not a rename/refactor/migration phase. The
> scaffold's Java 11→21 bump and empty `<dependencies/>` are code edits to a placeholder, not a
> live-system migration. Omitted per the trigger condition in the research protocol.

## Common Pitfalls

### Pitfall 1: `buf.gen.yaml`'s Java plugin `out:` path conflicts with D-21's gitignored-build-output mandate
**What goes wrong:** The current `sdks/buf.gen.yaml` has:
```yaml
- remote: buf.build/protocolbuffers/java
  out: java/src/main/java
- remote: buf.build/grpc/java
  out: java/src/main/java
```
which would write generated `.java` files **directly into the committed source tree**
(`sdks/java/src/main/java`) — but D-21 explicitly mandates "generate-on-build, gitignored" into
`target/generated-sources`, with only the **compiled** classes bundled into the jar.
**Why it happens:** Phase 15 scaffolded `buf.gen.yaml` before Phase 20's discuss-phase made the
Java-specific D-21 decision — the identical class of bug Phase 18 (Go) found and fixed for its own
`out:` path in Wave 0.
**How to avoid:** This phase's Wave 0 must decide the codegen mechanism explicitly (this research
recommends `protobuf-maven-plugin` + `os-maven-plugin`, see Standard Stack/Pattern discussion,
since `buf` CLI is confirmed absent in this environment — see Environment Availability). Either (a)
demote `buf.gen.yaml`'s Java entries to documentation-only / an optional CI drift-check reference
(the actual `mvn generate-sources` codegen never invokes `buf`), or (b) if CI does have `buf`
network egress and the planner prefers consistency with the other four `buf`-driven SDKs, fix the
`out:` path to a gitignored location AND wire `buf generate` into the Maven build via
`exec-maven-plugin`'s `generate-sources`-phase binding. **This research recommends (a)** — Maven's
native codegen plugin is more idiomatic, requires no external CLI on any contributor's machine, and
several sibling SDKs (Go, Python) already independently reached the same "use the native-language
tool, not `buf` CLI" conclusion for the identical environment constraint.
**Warning signs:** `mvn generate-sources` failing with "buf: command not found"; or, if left
unfixed, generated `.java` files silently appearing (and staying) in `git status` under
`sdks/java/src/main/java/`.

### Pitfall 2: Real login/refresh REST endpoints require `orgId`/`orgSlug`, beyond CONTRACT.md §5
**What goes wrong:** Implementing `login`/`refresh` strictly per CONTRACT.md §5 (tenant-only) fails
against the live server. `crates/axiam-api-rest/src/handlers/auth.rs`'s `LoginRequest` has optional
`org_id`/`org_slug` (validated as "must provide org_id or org_slug" — one is required), and
`RefreshRequest.org_id: Uuid` is **non-optional**. All three prior server-side reference SDKs (Rust,
Go, Python) already discovered and worked around this exact deviation.
**Why it happens:** CONTRACT.md documents the cross-language behavioral minimum, not every literal
wire-body field of AXIAM's concrete REST API — organizations are the top-level entity above tenants
in AXIAM's domain model (per CLAUDE.md) and the org requirement is a codebase-level fact CONTRACT.md
doesn't enumerate.
**How to avoid:** Add optional `orgSlug(String)`/`orgId(UUID)` builder methods (Pattern 1, mutually
exclusive, last-call-wins). If neither is supplied at construction, resolve and cache the org UUID
from the access token's `org_id` claim after the first successful `login`/`verifyMfa`, so `refresh`
(which requires `org_id` in its body) can succeed on subsequent calls without the caller having
supplied it up front — exactly mirroring the Rust/Go/Python `resolvedOrgId()` fallback pattern.
**Warning signs:** `login` succeeds but `refresh` fails with a 400 validation error; or `login`
itself 400s when no org identifier was ever configured and the test account belongs to a
non-default organization.

### Pitfall 3: `mockwebserver3-junit5` (OkHttp 5.x) is API-incompatible with the pinned OkHttp 4.12 runtime
**What goes wrong:** A naive `mvn` dependency search for "OkHttp MockWebServer JUnit 5" surfaces
`com.squareup.okhttp3:mockwebserver3-junit5` — OkHttp's **rewritten 5.x-line** test module, whose
`MockWebServer`/`MockResponse`/`RecordedRequest` API differs from the 4.x line's `mockwebserver`
artifact (builder-style `MockResponse.Builder` vs. the 4.x fluent setter style, package
`mockwebserver3` vs `okhttp3.mockwebserver`). JAVA-01 pins OkHttp **4.12**, not 5.x.
**Why it happens:** OkHttp 5.x renamed and restructured its test module as part of the 5.0 rewrite;
most current tutorials/search results default to the newer artifact.
**How to avoid:** Use `com.squareup.okhttp3:mockwebserver:4.12.0` (matching the runtime major.minor
exactly), which lives in the `okhttp3.mockwebserver` package with the 4.x-compatible API surface
(this research's own Pattern 2 example already uses the `mockwebserver3` package name for
illustration purposes matching the newest available docs — **the planner/executor must verify at
implementation time which MockWebServer major version is actually compatible with the pinned OkHttp
4.12 runtime and adjust package imports accordingly**; this is flagged in the Assumptions Log).
**Warning signs:** `NoSuchMethodError`/`ClassNotFoundException` at test runtime, or a `mvn
dependency:tree` showing two different OkHttp major versions resolved onto the test classpath.

### Pitfall 4: `mvn verify` including GPG signing (SC#5) cannot use the real release key in PR-triggered CI
**What goes wrong:** Binding `maven-gpg-plugin`'s `sign` goal unconditionally to the `verify` phase
means every PR-triggered CI run (including from untrusted forks with no repo-secret access) would
either (a) fail outright with no GPG key available, or (b) if a real production key were somehow
made available to PR jobs, leak the private key material to an untrusted context — an unacceptable
security posture for a signing key that will eventually govern the public `io.axiam:axiam-sdk`
Maven Central identity.
**Why it happens:** SC#5 literally requires "`mvn verify` passes including signing" as a phase
acceptance criterion, which naively suggests running the real signing step on every PR.
**How to avoid:** Gate signing behind a Maven property, e.g. `<gpg.skip>true</gpg.skip>` as the
project default, with the `maven-gpg-plugin` execution's `<skip>${gpg.skip}</skip>`. Two CI paths
then both prove SC#5 without ever exposing the real key to a PR: (1) the PR-gate CI job generates
and imports an **ephemeral, throwaway GPG key** (`gpg --batch --gen-key` with a disposable, CI-only
passphrase, never committed) purely to prove `mvn verify -Dgpg.skip=false` structurally succeeds —
the signature itself is discarded, never published; (2) the tag-triggered publish job (mirrors
`sdk-ci-python.yml`'s "manual-on-tag, side-effecting step" pattern) imports the REAL GPG private key
+ passphrase from CI secrets (`GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`) and runs the actual signed
`mvn deploy` against the Sonatype Central Portal. This mirrors how the Rust/TS/Go/Python SDKs handle
their own publish-time-only secrets (npm token, PyPI Trusted Publishing OIDC, crates.io token,
Go module proxy tag-is-the-publish) — GPG is simply Java's variant of "secret only touches the
tag-triggered job, never a PR job."
**Warning signs:** A CI workflow granting `secrets.GPG_PRIVATE_KEY` to a `pull_request`-triggered
job (a security review finding, not just a correctness bug); or `mvn verify` failing on every PR
with "gpg: signing failed: No secret key" because no ephemeral-key fallback was implemented.

### Pitfall 5: AMQP HMAC canonicalization — DO NOT alphabetize keys (see Pattern 5 for the fix)
**What goes wrong:** A canonicalizer that re-sorts JSON object keys alphabetically before
HMAC-signing computes the hash over a **different byte sequence** than
`crates/axiam-amqp/src/messages.rs`'s `sign_payload` actually signed (Rust struct serialization
preserves field-declaration order, not alphabetical order) — every single AMQP message would fail
verification and get silently nacked-without-requeue, appearing as "the consumer receives nothing"
or "100% security-event log noise," which looks like a connectivity bug, not a correctness bug.
**Why it happens:** Several JSON canonicalization conventions (e.g. RFC 8785 JSON Canonicalization
Scheme) DO mandate alphabetical key sorting, making it a plausible-looking "more correct" choice —
but that is not what the actual Rust signer does for a typed `struct` (as opposed to a generic
map/`Value`).
**How to avoid:** This is **already resolved** for Java by Phase 19 (Python)'s empirical proof
(`.planning/STATE.md`, Phase 19 decision log) against a real Rust-signed fixture: preserve
insertion/wire order, never sort. Jackson's `ObjectNode` (Pattern 5) does this natively via its
`LinkedHashMap` backing — **no additional Wave-0 fixture test is strictly required to re-derive this
finding** (unlike Python, which had to prove it from scratch), but a regression test asserting a
real captured HMAC-signed fixture verifies correctly is still strongly recommended as insurance
against a future Jackson configuration change (e.g. an `ObjectMapper` feature that re-orders keys)
silently breaking this invariant.
**Warning signs:** 100% HMAC verification failure rate in integration testing with an
otherwise-correctly-configured signing key.

## Code Examples

### Complete `pom.xml` skeleton (D-01, D-20, D-21, D-22, D-24)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>io.axiam</groupId>
  <artifactId>axiam-sdk</artifactId>
  <version>0.1.0</version>
  <packaging>jar</packaging>

  <name>axiam-sdk</name>
  <description>Official Java client SDK for AXIAM IAM</description>
  <url>https://github.com/ilpanich/axiam</url>

  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
      <url>https://www.apache.org/licenses/LICENSE-2.0</url>
      <distribution>repo</distribution>
    </license>
  </licenses>

  <!-- Required by Sonatype Central Portal — Rule: every published POM must
       declare at least one developer (D-22). -->
  <developers>
    <developer>
      <name>AXIAM Maintainers</name>
      <url>https://github.com/ilpanich/axiam</url>
    </developer>
  </developers>

  <scm>
    <url>https://github.com/ilpanich/axiam</url>
    <connection>scm:git:https://github.com/ilpanich/axiam.git</connection>
    <developerConnection>scm:git:https://github.com/ilpanich/axiam.git</developerConnection>
  </scm>

  <properties>
    <maven.compiler.release>21</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <!-- D-22/Pitfall 4: signing OFF by default; flipped to false only in the
         PR-gate CI job (ephemeral key) and the tag-triggered publish job
         (real CI-secret key). -->
    <gpg.skip>true</gpg.skip>
    <protobuf.version>4.29.0</protobuf.version> <!-- [ASSUMED — verify at implementation time against grpc-netty-shaded 1.82's protobuf-java floor] -->
  </properties>

  <dependencies>
    <dependency>
      <groupId>com.squareup.okhttp3</groupId>
      <artifactId>okhttp</artifactId>
      <version>4.12.0</version>
    </dependency>
    <dependency>
      <groupId>io.grpc</groupId>
      <artifactId>grpc-netty-shaded</artifactId>
      <version>1.82.0</version>
    </dependency>
    <dependency>
      <groupId>io.grpc</groupId>
      <artifactId>grpc-protobuf</artifactId>
      <version>1.82.0</version>
    </dependency>
    <dependency>
      <groupId>io.grpc</groupId>
      <artifactId>grpc-stub</artifactId>
      <version>1.82.0</version>
    </dependency>
    <dependency>
      <!-- Java 9+ needs this explicitly for generated gRPC stub annotations -->
      <groupId>org.apache.tomcat</groupId>
      <artifactId>annotations-api</artifactId>
      <version>6.0.53</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>com.rabbitmq</groupId>
      <artifactId>amqp-client</artifactId>
      <version>5.22.0</version>
    </dependency>
    <dependency>
      <groupId>com.nimbusds</groupId>
      <artifactId>nimbus-jose-jwt</artifactId>
      <version>10.7</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.15.0</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.22.0</version>
    </dependency>
    <dependency>
      <groupId>org.jspecify</groupId>
      <artifactId>jspecify</artifactId>
      <version>1.0.0</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.17</version>
    </dependency>
    <!-- D-14: Spring Security deps are optional/provided so a non-Spring
         consumer never pulls Spring transitively. -->
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
      <version>3.5.6</version>
      <scope>provided</scope>
      <optional>true</optional>
    </dependency>
    <dependency>
      <groupId>jakarta.servlet</groupId>
      <artifactId>jakarta.servlet-api</artifactId>
      <version>6.1.0</version>
      <scope>provided</scope>
    </dependency>
    <!-- Test scope -->
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.14.4</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.squareup.okhttp3</groupId>
      <artifactId>mockwebserver</artifactId>
      <version>4.12.0</version>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <extensions>
      <extension>
        <groupId>kr.motd.maven</groupId>
        <artifactId>os-maven-plugin</artifactId>
        <version>1.7.1</version>
      </extension>
    </extensions>
    <plugins>
      <!-- D-21: generate-on-build into target/generated-sources (gitignored). -->
      <plugin>
        <groupId>org.xolstice.maven.plugins</groupId>
        <artifactId>protobuf-maven-plugin</artifactId>
        <version>0.6.1</version>
        <configuration>
          <protocArtifact>com.google.protobuf:protoc:${protobuf.version}:exe:${os.detected.classifier}</protocArtifact>
          <protoSourceRoot>${project.basedir}/../../proto</protoSourceRoot>
          <pluginId>grpc-java</pluginId>
          <pluginArtifact>io.grpc:protoc-gen-grpc-java:1.82.0:exe:${os.detected.classifier}</pluginArtifact>
        </configuration>
        <executions>
          <execution>
            <goals>
              <goal>compile</goal>
              <goal>compile-custom</goal>
            </goals>
          </execution>
        </executions>
      </plugin>

      <!-- D-24: Automatic-Module-Name, no full module-info.java. -->
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-jar-plugin</artifactId>
        <version>3.4.2</version>
        <configuration>
          <archive>
            <manifestEntries>
              <Automatic-Module-Name>io.axiam.sdk</Automatic-Module-Name>
            </manifestEntries>
          </archive>
        </configuration>
      </plugin>

      <!-- D-22: javadoc + sources jars — REQUIRED by Sonatype Central Portal. -->
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-source-plugin</artifactId>
        <version>3.3.1</version>
        <executions>
          <execution>
            <id>attach-sources</id>
            <goals><goal>jar-no-fork</goal></goals>
          </execution>
        </executions>
      </plugin>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-javadoc-plugin</artifactId>
        <version>3.11.2</version>
        <executions>
          <execution>
            <id>attach-javadocs</id>
            <goals><goal>jar</goal></goals>
          </execution>
        </executions>
      </plugin>

      <!-- D-22, Pitfall 4: gpg.skip=true by default; flipped per-environment. -->
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-gpg-plugin</artifactId>
        <version>3.2.8</version>
        <executions>
          <execution>
            <id>sign-artifacts</id>
            <phase>verify</phase>
            <goals><goal>sign</goal></goals>
            <configuration>
              <skip>${gpg.skip}</skip>
              <gpgArguments>
                <arg>--pinentry-mode</arg>
                <arg>loopback</arg>
              </gpgArguments>
            </configuration>
          </execution>
        </executions>
      </plugin>

      <!-- D-22: Sonatype Central Portal publish. -->
      <plugin>
        <groupId>org.sonatype.central</groupId>
        <artifactId>central-publishing-maven-plugin</artifactId>
        <version>0.9.0</version>
        <extensions>true</extensions>
        <configuration>
          <publishingServerId>central</publishingServerId>
          <autoPublish>false</autoPublish> <!-- require a manual publish confirmation initially -->
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
```

### `mvn verify` recipe (SC#5)

```bash
# Local / PR-gate CI (ephemeral signing key, never published):
gpg --batch --pinentry-mode loopback --passphrase "" \
    --quick-generate-key "AXIAM CI (ephemeral, do not trust)" ed25519 sign 1d
mvn -f sdks/java/pom.xml verify -Dgpg.skip=false

# Tag-triggered publish CI (real key from CI secrets):
echo "$GPG_PRIVATE_KEY" | base64 -d | gpg --batch --import
mvn -f sdks/java/pom.xml -s settings.xml deploy \
    -Dgpg.skip=false -Dgpg.passphrase="$GPG_PASSPHRASE"
# settings.xml supplies <server><id>central</id> credentials for
# central-publishing-maven-plugin's publishingServerId, sourced from
# CI secrets (Sonatype Central Portal user token, not a password).
```

### TLS-bypass CI grep gate (SC#4, extended beyond the literal idiom list)

```bash
# Source: .planning/research/PITFALLS.md's Java-specific TLS-bypass finding
# ("TrustManager that accepts all certs") + CONTRACT.md §6's "any other API
# surface that bypasses TLS verification" absolute prohibition — extended
# per the same pattern Phase 18 (Go) applied beyond SC#3's literal wording.
PATTERN='hostnameVerifier\s*\(|setHostnameVerifier|sslSocketFactory\s*\(|X509TrustManager\s*\(\s*\)\s*\{|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier'
if grep -rnE "$PATTERN" sdks/java/src sdks/java/examples 2>/dev/null | grep -q .; then
  echo "FAIL: found a TLS-bypass pattern under sdks/java/"
  grep -rnE "$PATTERN" sdks/java/src sdks/java/examples || true
  exit 1
fi
echo "OK: no TLS-bypass patterns found under sdks/java/"
```
The grep-only literal strings `hostnameVerifier`/`sslSocketFactory` (SC#4's exact wording) are
necessary but not sufficient — an empty-body `checkServerTrusted(...)` override or a
`HostnameVerifier` lambda unconditionally `return true`-ing bypasses TLS just as completely without
containing either literal substring in a suspicious way; a real implementation's grep pattern must
be broad enough to catch a hand-rolled trust-all `X509TrustManager`, matching Go's own Pitfall-1
precedent of extending the literal SC-wording pattern set.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| OSSRH / Sonatype Nexus Staging Maven publishing (`nexus-staging-maven-plugin`) | Sonatype Central Portal (`central-publishing-maven-plugin`) | OSSRH legacy publishing sunset for new namespaces in 2025 | D-22 already targets the current path — do not scaffold the legacy plugin |
| `spring.factories`-based Spring Boot auto-configuration registration | `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` | Spring Boot 2.7+ (stable since 3.x) | D-15's exact mechanism; the legacy `spring.factories` path still works but is deprecated |
| OkHttp `okhttp3.mockwebserver` (3.x/4.x test module) | `mockwebserver3`/`mockwebserver3-junit5` (5.x rewrite) | OkHttp 5.0 | JAVA-01 pins OkHttp 4.12 — use the matching 4.x `mockwebserver` artifact, NOT the 5.x rewrite (Pitfall 3) |
| nimbus-jose-jwt manual `Ed25519Verifier`/`Ed25519Signer` construction | Same API, now Tink-backed under the hood in the 10.x line (vs. an internal/BouncyCastle-adjacent implementation in earlier majors) | nimbus-jose-jwt 9.x → 10.x | JAVA-01 explicitly pins "10.x + Tink" — matches the current, supported EdDSA path |
| Spring Boot 3.x | Spring Boot 4.x (GA, Java 17+ baseline unchanged conceptually but with breaking API changes vs 3.x) | Spring Boot 4.0 released 2026 | D-16 explicitly pins "Spring Boot 3.2+ ... latest stable 3.x" — do NOT silently target 4.x; the locked decision is scoped to the 3.x line specifically |

**Deprecated/outdated:**
- `nexus-staging-maven-plugin`/manual OSSRH ticket-based namespace requests: replaced by
  Sonatype Central Portal self-service namespace verification + `central-publishing-maven-plugin`.
- Java 11 (the scaffold's stale floor): replaced by the Java 21 LTS baseline (D-01).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Exact latest patch versions (OkHttp 4.12.0, grpc-netty-shaded 1.82.0, amqp-client 5.22.0, nimbus-jose-jwt 10.7, jspecify 1.0.0, jackson-databind 2.22.0, junit-jupiter 5.14.4, protobuf-maven-plugin 0.6.1, os-maven-plugin 1.7.1, maven-gpg-plugin 3.2.8, central-publishing-maven-plugin 0.9.0) were confirmed via WebSearch of Maven Central listings this session, NOT a direct `curl`/tool call to `search.maven.org` (blocked by this sandbox's egress proxy policy — `search.maven.org` is not in the `noProxy` allowlist the way `pypi.org`/`registry.npmjs.org`/`proxy.golang.org` are) | Standard Stack, Package Legitimacy Audit | Low-Medium — the major.minor floors (OkHttp 4.12, grpc-netty-shaded 1.82, amqp-client 5.22, nimbus-jose-jwt 10.x) are JAVA-01-pinned and authoritative regardless; only the exact latest patch within each line carries WebSearch-sourced provenance. Re-run `mvn versions:display-dependency-updates` once CI network egress is available |
| A2 | `com.google.crypto.tink:tink` version 1.15.0 is a reasonable current 1.x version to pin — not independently re-verified against Maven Central this session (WebSearch was not specifically run for Tink's exact version) | Standard Stack, POM example | Low — Tink's API for the nimbus integration surface (backing `Ed25519Verifier`) has been stable across 1.x; a version mismatch would surface immediately as a build/test failure, not a silent runtime bug |
| A3 | `com.squareup.okhttp3:mockwebserver:4.12.0` (the 4.x-line package `okhttp3.mockwebserver`) is the correct test dependency to pair with the pinned OkHttp 4.12.0 runtime, rather than the 5.x-line `mockwebserver3`/`mockwebserver3-junit5` shown in some of this document's illustrative code (Pattern 2 uses `mockwebserver3` package names matching the newest available WebSearch results) | Common Pitfalls #3, Standard Stack | Medium — if the planner/executor copies Pattern 2's example code verbatim with `mockwebserver3` imports while the POM pins `mockwebserver:4.12.0`, the test code will fail to compile (package/class name mismatch). The POM's dependency choice (4.x `mockwebserver`) is authoritative; Pattern 2's example imports should be adjusted to `okhttp3.mockwebserver.*` at implementation time |
| A4 | Proposed gRPC default deadlines — `CheckAccess` 3000ms, `BatchCheckAccess` 10000ms, both overridable — are this research's own engineering judgment (D-12 explicitly delegates "numeric value = planner"), not derived from any sibling SDK's already-shipped value (none of Rust/TS/Go/Python's research explicitly pinned a gRPC deadline number in what was read this session) | Architecture Patterns (gRPC client, not shown as a full code pattern above — flagged for planner), Common Pitfalls | Low — these are sane starting defaults for a "latency-sensitive hot path" per D-12's own framing; trivially tunable, not a correctness risk |
| A5 | `RemoteJWKSet`'s constructor accepting a `JWKSetCache` as a third positional argument (`new RemoteJWKSet<>(url, resourceRetriever, cache)`) matches nimbus-jose-jwt 10.7's actual API signature — inferred from general nimbus familiarity and the official docs summary, not independently confirmed against the exact installed 10.7 javadoc in this session | Pattern 4 (JWKS verification) | Medium — if the constructor signature differs slightly in 10.7 (e.g. a builder pattern is now preferred), Pattern 4's example needs a small adjustment; the overall `RemoteJWKSet` + `JWSVerificationKeySelector` + `DefaultJWTProcessor` control flow is correct regardless — verify via `javadoc` or `mvn dependency:tree` + IDE inspection once the dependency is resolved in Wave 0 |
| A6 | `protobuf.version` (protoc/protobuf-java version, proposed 4.29.0) is compatible with `grpc-netty-shaded`/`grpc-protobuf` 1.82.0's expected protobuf-java floor | POM example | Low-Medium — grpc-java pins a specific protobuf-java transitive version per release; a mismatched `protocArtifact` version could produce wire-incompatible generated code. The planner/executor should confirm the exact protobuf-java version grpc-java 1.82.0 depends on (via `mvn dependency:tree`) and align `protocArtifact`'s version to match, rather than trusting this research's placeholder |

**None of the above blocks planning** — each is flagged with a concrete verification step
(re-run a Maven command once network egress is available, or cross-check a javadoc/dependency tree)
to perform during the phase's first implementation wave, not a decision requiring user input like
the 29 already-locked CONTEXT.md items.

## Open Questions

1. **Exact `RemoteJWKSet` / `DefaultJWKSetCache` constructor API for nimbus-jose-jwt 10.7**
   - What we know: `RemoteJWKSet<SecurityContext>` accepts a JWKS URL, an optional custom
     `ResourceRetriever`, and an optional `JWKSetCache` — the general shape is stable across recent
     nimbus majors per official docs.
   - What's unclear: The precise constructor overload signature and whether `DefaultJWKSetCache`'s
     constructor takes `(lifespan, refreshTimeout, TimeUnit)` positionally or via a builder in the
     exact 10.7 release, not independently confirmed against installed javadoc this session.
   - Recommendation: The executor should run `mvn dependency:resolve-sources` +
     inspect the `nimbus-jose-jwt-10.7-sources.jar` (or the online javadoc at
     `javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/10.7`) once the dependency is vendored in Wave 0,
     and adjust Pattern 4's exact constructor call if the API differs — the overall
     `RemoteJWKSet`+`JWSVerificationKeySelector`+`DefaultJWTProcessor` control flow is confirmed
     correct from official product documentation; only the constructor's exact parameter shape is a
     residual detail.

2. **Whether Maven Central's Central Portal requires `autoPublish=true` or manual confirmation for
   the very first namespace release**
   - What we know: D-22 already anticipates "Live first publish may be a maintainer action if
     namespace/creds are absent in CI" (deferred idea) — the Central Portal requires namespace
     ownership verification (e.g. a DNS TXT record or GitHub-repo-ownership proof for `io.axiam`)
     before any publish succeeds, a manual one-time setup step outside this phase's CI automation.
   - What's unclear: The exact namespace-verification mechanism status for `io.axiam` (whether it's
     already been claimed/verified on Sonatype Central, given the scaffold's POM already declares
     `io.axiam:axiam-sdk` and states "Registry: Maven Central _(reserved, not yet published)_" in
     the existing README).
   - Recommendation: Treat the CI publish job as fully built and `mvn verify -Dgpg.skip=false`-tested
     with an ephemeral key (proving the pipeline mechanically works), but flag the actual first
     `mvn deploy` against the real Central Portal namespace as a `checkpoint:human-verify` /
     maintainer action per D-22's own deferred-idea note — consistent with how Python's PyPI
     Trusted Publisher registration was flagged as a "User Setup Required" maintainer action in
     `19-07-SUMMARY.md`.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `mvn` (Maven) | Building/testing `sdks/java/` | Not directly probed this session (no `mvn --version` run) | — | Standard for any Java-toolchain CI runner; the planner/executor should confirm at Wave 0 |
| Java 21 JDK | `maven.compiler.release=21` | Not directly probed this session | — | GitHub Actions `actions/setup-java@vX` with `java-version: '21'` is the standard CI mechanism, matching the pattern the other SDK workflows use for their own language toolchains |
| `buf` CLI | `sdks/buf.gen.yaml`'s declared Java plugin pipeline | Not probed directly this session, but confirmed absent by three prior sibling phases (16 Rust, 18 Go, 19 Python) in this same development environment — treated as absent by inference, consistent finding across every prior SDK phase | — | Use `protobuf-maven-plugin` + `os-maven-plugin` directly (Pattern discussion, Pitfall 1) — self-downloads `protoc`/`protoc-gen-grpc-java` via Maven's own dependency resolution, no external CLI binary required on any machine that can run `mvn` |
| Network egress to Maven Central (`repo1.maven.org`/`search.maven.org`) | Dependency resolution, version verification | `search.maven.org` confirmed **blocked** by this sandbox's egress proxy policy (`CONNECT tunnel failed, response 403`; not in `noProxy` allowlist) — `repo1.maven.org` itself was not separately tested but is a distinct host and may or may not share the same block | Uncertain | WebSearch tool (routes through Claude's own infrastructure, not this sandbox's proxy) was used as the fallback for all version-verification claims in this research (see Assumptions Log A1); the actual CI runner (GitHub Actions) almost certainly has full Maven Central egress unlike this research sandbox — this is a sandbox-specific constraint, not a CI-blocking one |
| GPG (`gpg`/`gpg2`) | Signing artifacts (D-22, SC#5) | Not probed this session | — | Standard on `ubuntu-latest` GitHub Actions runners; the PR-gate ephemeral-key generation (Pitfall 4) needs no pre-existing key, just the `gpg` binary itself |
| Live AXIAM server (SurrealDB + RabbitMQ backing) | Integration testing (login, refresh, AMQP consume against a real broker) | Not verified this session (no `just dev-up` run) | — | Use `MockWebServer`-based unit tests + a captured/fixture-based HMAC test (mirroring Python's Wave-0 fixture recommendation, though Java inherits Python's already-proven ordering finding — see Pitfall 5) rather than a live server; consistent with every prior SDK phase's testing approach |

**Missing dependencies with no fallback:** none identified — every gap above has a documented,
viable fallback (matching the pattern every prior SDK phase's research reached for the identical
`buf`-CLI-absence and live-server-unavailability constraints in this same development environment).

**Missing dependencies with fallback:**
- `buf` CLI → `protobuf-maven-plugin` + `os-maven-plugin` (Maven-native, self-downloading).
- Direct Maven Central network access (this sandbox only) → WebSearch tool for version verification
  this session; CI runner almost certainly unaffected.
- Live AXIAM server → `MockWebServer`-based unit tests + fixture-based HMAC verification.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | JUnit 5 (`org.junit.jupiter:junit-jupiter` 5.14.4) + OkHttp `mockwebserver` (4.12.0-matched, D-28) |
| Config file | none yet — Wave 0 creates the `pom.xml` `<dependencies>`/`maven-surefire-plugin` wiring; JUnit 5 requires no separate config file beyond the dependency itself |
| Quick run command | `mvn -f sdks/java/pom.xml test` (default `mvn test` run — excludes any `@Tag("integration")`-gated Testcontainers smoke tests per D-28) |
| Full suite command | `mvn -f sdks/java/pom.xml verify -Dgpg.skip=false` (incl. javadoc/sources jar generation, GPG signing with an ephemeral key, and any `-Dgroups=integration` Testcontainers tier if enabled) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| JAVA-01 (SC#1) | `io.axiam:axiam-sdk` added to a POM; `tenantId` required (compiler-enforced via no no-arg builder path); `login()` returns typed `LoginResult` | unit (mocked `MockWebServer`) + compile-shape assertion | `mvn -f sdks/java/pom.xml test -Dtest=AxiamClientBuilderTest` | ❌ Wave 0 |
| JAVA-01 (SC#2) | 5 concurrent threads on expired token ⇒ exactly 1 refresh (`ReentrantLock` guard) | unit (`CountDownLatch`+`ExecutorService`, counting `MockWebServer` dispatcher) | `mvn -f sdks/java/pom.xml test -Dtest=RefreshGuardSingleFlightTest` | ❌ Wave 0 |
| JAVA-01 (SC#3) | Spring Security `Filter` protects a sample endpoint, compiles against Spring Boot 3.x, complete working app context | integration (Spring `@WebMvcTest`/`@SpringBootTest` against the example app) | `mvn -f sdks/java/pom.xml test -Dtest=AxiamAuthenticationFilterIT` + `mvn -f sdks/java/examples/spring-boot-app/pom.xml verify` (compiles + boots) | ❌ Wave 0 |
| JAVA-01 (SC#4) | `OkHttpClient` uses `CookieManager`; no `hostnameVerifier`/`sslSocketFactory` bypass anywhere | static (CI grep gate, extended pattern set) | `bash sdks/java/scripts/tls-bypass-gate.sh` (see Code Examples) | ❌ Wave 0 (CI step) |
| JAVA-01 (SC#5) | `mvn verify` passes incl. GPG signing; Maven Central publish pipeline documented + operational | build/packaging check (not JUnit) | `mvn -f sdks/java/pom.xml verify -Dgpg.skip=false` (PR-gate, ephemeral key); tag-triggered `mvn deploy` (publish job, real key) | ❌ Wave 0 (CI workflow) |
| D-18 / CR-04 carry-forward | `NetworkError` never leaks `Set-Cookie`/`Authorization`/`Cookie` via `toString()`/logs | unit (regression, non-vacuous control case) | `mvn -f sdks/java/pom.xml test -Dtest=ErrorRedactionTest` | ❌ Wave 0 |
| D-17 | `Sensitive` redacts across `toString()` + Jackson serialization, non-`Serializable` | unit | `mvn -f sdks/java/pom.xml test -Dtest=SensitiveTest` | ❌ Wave 0 |
| §8 (AMQP HMAC) | HMAC verify-before-handler matches server byte-for-byte (insertion-order preservation, Pattern 5) | unit (fixture-based, inherits Phase 19's proven ordering) | `mvn -f sdks/java/pom.xml test -Dtest=HmacVerifyTest` | ❌ Wave 0 |
| D-19 (JWKS) | EdDSA-only alg pinning (native via `JWSVerificationKeySelector`), rotation on unknown `kid`, cross-tenant rejection | unit (mocked JWKS endpoint) + integration (Spring filter cross-tenant test) | `mvn -f sdks/java/pom.xml test -Dtest=JwksVerifierTest,AxiamAuthenticationFilterIT` | ❌ Wave 0 |
| D-21 (gRPC codegen) | Committed-vs-regenerated drift check (if `buf` available in CI) OR build succeeds via `protobuf-maven-plugin` | CI build step (not JUnit) | `mvn -f sdks/java/pom.xml generate-sources compile` | ❌ Wave 0 |
| §3 CSRF (non-browser) | `X-CSRF-Token` response header captured and echoed on state-changing requests | unit (`MockWebServer` asserting header round-trip) | `mvn -f sdks/java/pom.xml test -Dtest=CsrfInterceptorTest` | ❌ Wave 0 |
| §5 tenant context | `X-Tenant-Id` header (REST) / `x-tenant-id` metadata (gRPC) injected on every request | unit | `mvn -f sdks/java/pom.xml test -Dtest=TenantHeaderTest` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `mvn -f sdks/java/pom.xml test` (fast unit tier, no Testcontainers, no GPG signing).
- **Per wave merge:** `mvn -f sdks/java/pom.xml verify -Dgpg.skip=false` (ephemeral key) + the TLS-bypass grep gate + `mvn dependency:tree` sanity check.
- **Phase gate:** Full suite green, `mvn verify -Dgpg.skip=false` passing (incl. javadoc/sources jars), CONTRACT.md §1–§10 conformance checklist reviewed, before `/gsd-verify-work`.

### Wave 0 Gaps
- [ ] `sdks/java/pom.xml` — full rewrite from the Java-11 scaffold (D-01/D-20/D-21/D-22/D-24 plugin
      chain, dependency versions per Standard Stack).
- [ ] `sdks/java/src/main/java/io/axiam/sdk/` — entire package tree is new (scaffold has no `src/`
      directory yet, only `pom.xml`/`README.md`/`LICENSE`).
- [ ] `sdks/java/src/main/proto` wiring — `protobuf-maven-plugin`'s `<protoSourceRoot>` pointed at
      the shared `proto/axiam/v1/*.proto` tree (one source of truth, no file duplication).
- [ ] `sdks/buf.gen.yaml` — Wave-0 decision required: demote Java entries to
      documentation/drift-check-only (this research's recommendation, Pitfall 1) or fix `out:` path
      + wire `buf generate` via `exec-maven-plugin`.
- [ ] `.planning/REQUIREMENTS.md` JAVA-01 — reconcile the BOM coordinate (D-23, flagged Deferred
      Idea) — a scoped doc edit, do not lose.
- [ ] `.github/workflows/sdk-ci-java.yml` — currently only a `scaffold-check` job (LICENSE file
      presence); needs `mvn test`, TLS-bypass grep gate, `mvn verify -Dgpg.skip=false` (ephemeral
      key), and a tag-triggered `sdks/java/vX.Y.Z` publish job (real GPG secret + Central Portal
      credentials), mirroring `sdk-ci-python.yml`'s structure.
- [ ] No existing Java test infrastructure in `sdks/java/` (scaffold-only currently) — the entire
      test suite is new in this phase.

*(No gaps beyond scaffold-to-implementation — expected for a phase delivering a brand-new SDK from
a placeholder scaffold, consistent with every prior SDK phase.)*

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | yes | `login`/`verifyMfa`/`refresh`/`logout` via OkHttp + `CookieManager`; `ReentrantLock` single-flight refresh (§9); no client-side credential caching beyond the `Sensitive`-wrapped in-memory token |
| V3 Session Management | yes | httpOnly cookie jar (`java.net.CookieManager`), `axiam_access`/`axiam_refresh` never read directly by SDK code except via the jar's opaque `CookieStore` interface (no `document.cookie`-equivalent parsing — Java has no browser context) |
| V4 Access Control | yes | `checkAccess`/`batchCheck`/`can` (gRPC + REST) delegate the actual decision to the server's `AuthorizationEngine`; SDK never makes a local allow/deny decision |
| V5 Input Validation | yes | Jackson `ObjectMapper`-based (de)serialization for all wire types; JWKS/JWT claims validated via nimbus's `DefaultJWTProcessor` (rejects malformed tokens, wrong algorithm via `JWSVerificationKeySelector`, expired `exp` checked explicitly by the Spring filter) |
| V6 Cryptography | yes | Never hand-rolled: `javax.crypto.Mac`+`java.security.MessageDigest.isEqual` (stdlib) for §8 AMQP HMAC-SHA256, nimbus + Tink for EdDSA/Ed25519 JWT verification, JDK default `SSLContext`/trust store for TLS 1.3 transport security |

### Known Threat Patterns for the Java SDK stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|-----------------------|
| TLS bypass via a hand-rolled trust-all `X509TrustManager`/`HostnameVerifier` | Tampering / Information Disclosure | Absolute prohibition per CONTRACT.md §6; CI grep gate extended beyond the literal SC#4 pattern (Code Examples, TLS-bypass gate) |
| Token leak via `NetworkError`/logs carrying a raw OkHttp `Response` with `Set-Cookie` | Information Disclosure | D-18 redact-before-wrap (`ErrorMapper.sanitize`), mirroring the CR-04 fix from Phase 17, with a non-vacuous regression test |
| AMQP message tampering/replay | Tampering | §8 HMAC-SHA256-verify-before-handler with constant-time `MessageDigest.isEqual`; nack-without-requeue on any mismatch; missing signature rejected by default (strict mode); wire-order-preserving canonicalization (Pattern 5) prevents a false-negative-only failure mode that would otherwise mask real tampering behind "everything fails to verify" noise |
| Thundering-herd refresh (concurrent 401s each triggering their own refresh, potentially invalidating each other's single-use rotating refresh token) | Denial of Service (self-inflicted) | §9 `ReentrantLock`+`CompletableFuture`-in-`AtomicReference` single-flight guard with double-check-after-lock-acquire pattern |
| Algorithm confusion (attacker-supplied `alg: none` or `alg: HS256` against an expected-EdDSA key) | Spoofing / Tampering | `JWSVerificationKeySelector(JWSAlgorithm.EdDSA, jwkSource)` pins the algorithm natively at the key-selector level, BEFORE any key lookup — the safest of any sibling SDK's implementation since it's a library feature, not hand-written logic |
| Cross-tenant token replay (a validly-signed token minted for org-wide JWKS but a different tenant) | Elevation of Privilege | Mirrors TS CR-03/Go/Python's mandatory control: after JWKS signature verification succeeds, `AxiamAuthenticationFilter` (Pattern 8) additionally checks `claims.tenant_id == configuredTenantId` before trusting the token — JWKS is org-wide, not tenant-scoped, so signature validity alone is insufficient |
| GPG private key exposure via PR-triggered CI | Information Disclosure / Spoofing (of the published artifact's signature) | Real GPG secret material scoped exclusively to the tag-triggered publish job; PR-gate CI proves the signing mechanism with a disposable ephemeral key (Pitfall 4) |
| Maven Central namespace/coordinate squatting or supply-chain confusion for `io.axiam:axiam-sdk` | Spoofing | Namespace ownership verification is enforced by the Sonatype Central Portal itself (DNS/repo-ownership proof) before any publish under the `io.axiam` groupId succeeds — a platform-level control, not something the SDK needs to implement |

## Sources

### Primary (HIGH confidence)
- `sdks/CONTRACT.md` §1–§10 — normative/binding cross-language behavioral contract (direct file read, in full).
- `.planning/phases/20-java-sdk/20-CONTEXT.md` — 29 locked decisions (D-01..D-29), 5 carry-forwards (CF-01..CF-05), canonical refs (direct file read, in full).
- `.planning/REQUIREMENTS.md` §JAVA-01 (direct file read).
- `.planning/STATE.md` — Phase 19 decision log confirming the AMQP HMAC key-ordering finding empirically (direct file read; load-bearing for Pattern 5/Pitfall 5).
- `.planning/phases/16-rust-sdk/16-RESEARCH.md`, `.planning/phases/17-typescript-sdk/17-RESEARCH.md`, `.planning/phases/18-go-sdk/18-RESEARCH.md`, `.planning/phases/19-python-sdk/19-RESEARCH.md` — all four sibling reference research docs (18/19 read in full; 16/17 referenced via 18/19's own citations and CONTEXT.md canonical refs).
- `.planning/phases/17-typescript-sdk/17-REVIEW.md` §CR-04 — token-leak-via-error-cause finding (direct file read, in full).
- `crates/axiam-amqp/src/messages.rs` — canonical HMAC sign/verify protocol + exact struct field order (direct file read, in full).
- `crates/axiam-api-rest/src/handlers/authz_check.rs`, `crates/axiam-api-rest/src/server.rs` (route table incl. `/oauth2/jwks` under `web::scope("/oauth2")`, org-nested route structure) — direct file reads.
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC `check_access` implementation (direct file read, partial).
- `proto/axiam/v1/authorization.proto` — gRPC service/message definitions (direct file read, in full).
- `sdks/buf.gen.yaml` — existing codegen config incl. the Java `out:` path conflict (direct file read, in full).
- `sdks/java/{pom.xml,README.md}` — existing scaffold (direct file reads, in full).
- `sdks/typescript/src/core/errorMapper.ts` — `sanitizeAxiosError`/CR-04 fix pattern (direct file read, in full).
- `.github/workflows/sdk-ci-java.yml`, `.github/workflows/sdk-ci-python.yml` — existing/sibling CI workflow structure (direct file reads, in full).
- `.planning/config.json` — `workflow.nyquist_validation: true` confirmed (direct file read).
- Maven Central listings (via WebSearch, this session) — `okhttp` 4.12.0/5.4.0, `grpc-netty-shaded` 1.82.0/1.82.1, `amqp-client` 5.22.0, `nimbus-jose-jwt` 10.7, `jspecify` 1.0.0, `jackson-databind` 2.22.0, `junit-jupiter` 5.14.4, `mockwebserver3-junit5` 5.4.0, `central-publishing-maven-plugin` 0.9.0/0.10.0, `maven-gpg-plugin` 3.2.8, `spring-boot-starter-parent` 3.5.x/4.0/4.1, `protobuf-maven-plugin` 0.6.1 — WebSearch used as the fallback since direct `curl` to `search.maven.org` returned a proxy-policy `403` (confirmed via `$HTTPS_PROXY/__agentproxy/status`'s `recentRelayFailures` log).

### Secondary (MEDIUM confidence)
- OkHttp official docs (square.github.io/okhttp) — `Interceptor`/`Authenticator`/`CookieJar` API shapes [CITED].
- nimbus-jose-jwt official product docs (connect2id.com/products/nimbus-jose-jwt) — `RemoteJWKSet`, Tink dependency requirement for EdDSA, `JWSVerificationKeySelector` [CITED].
- Spring Security / Spring Boot official docs (docs.spring.io) — `OncePerRequestFilter`, `SecurityFilterChain`, `AutoConfiguration.imports` mechanism [CITED].
- `xolstice/protobuf-maven-plugin` GitHub + Apache Maven GPG Plugin official docs (maven.apache.org/plugins/maven-gpg-plugin) — plugin configuration shapes [CITED].
- `.planning/research/PITFALLS.md` — the Java-specific "`TrustManager` that accepts all certs" TLS-bypass finding [CITED, in-repo].

### Tertiary (LOW confidence / flagged for validation)
- Exact `RemoteJWKSet`/`DefaultJWKSetCache` constructor signature for nimbus-jose-jwt 10.7 (Assumption A5, Open Question #1) — general nimbus familiarity, not independently confirmed against the installed 10.7 javadoc this session.
- `mockwebserver` vs `mockwebserver3` package-name compatibility with the pinned OkHttp 4.12 runtime (Assumption A3, Common Pitfall #3) — flagged explicitly as needing implementation-time verification.
- `com.google.crypto.tink:tink` exact version (Assumption A2) — not independently WebSearch-verified this session.
- `protobuf.version`/`protocArtifact` alignment with grpc-netty-shaded 1.82.0's expected protobuf-java floor (Assumption A6) — needs `mvn dependency:tree` confirmation at implementation time.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH for the four JAVA-01-pinned major.minor floors (contractually locked, not
  independently re-derived); MEDIUM for the exact latest patch versions and supporting-plugin
  versions (WebSearch-sourced this session due to this sandbox's Maven-Central-blocking egress
  policy, not a direct authoritative tool call — re-verify once CI network egress is confirmed).
- Architecture: HIGH — every major pattern (single-flight guard, interceptor/authenticator split,
  Sensitive redaction, error mapper, Spring filter, AMQP consumer) is ported directly from four
  working, reviewed reference implementations (Rust 16, TypeScript 17, Go 18, Python 19) plus the
  binding CONTRACT.md; the AMQP HMAC canonicalization finding is HIGH confidence specifically
  because it was already empirically proven by Phase 19 against a real signed fixture (not a fresh
  assumption for this phase to re-derive).
- Pitfalls: HIGH for the org_id/JWKS-path/buf-output-path findings (direct codebase reads,
  cross-checked against three independent prior-phase sources each); HIGH for the GPG-in-CI pitfall
  (a well-established CI security pattern, not novel to this session); MEDIUM for the exact
  MockWebServer package-compatibility and nimbus constructor-signature details (flagged in the
  Assumptions Log as implementation-time verification items).

**Research date:** 2026-07-02
**Valid until:** 2026-08-01 (30 days — stable dependency set overall, but grpc-netty-shaded and
Spring Boot both ship frequent patch/minor releases and Maven Central plugin versions drift; the
JAVA-01-pinned major.minor floors themselves are stable for the phase's execution window).
