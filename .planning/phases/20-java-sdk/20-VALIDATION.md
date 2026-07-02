---
phase: 20
slug: java-sdk
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-02
---

# Phase 20 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `20-RESEARCH.md` § Validation Architecture. Per-task rows are
> finalized by the planner once PLAN.md task IDs exist.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | JUnit 5 (`org.junit.jupiter:junit-jupiter` 5.14.x) + OkHttp `mockwebserver` (4.12.0-matched, D-28); optional `@Tag("integration")` Testcontainers tier (never in default `mvn test`) |
| **Config file** | none yet — Wave 0 creates the `pom.xml` `<dependencies>` + `maven-surefire-plugin` wiring; JUnit 5 needs no separate config file |
| **Quick run command** | `mvn -f sdks/java/pom.xml test` (fast unit tier — excludes `@Tag("integration")` Testcontainers tests per D-28) |
| **Full suite command** | `mvn -f sdks/java/pom.xml verify -Dgpg.skip=false` (incl. javadoc/sources jars + GPG signing with an ephemeral key) |
| **Estimated runtime** | ~30–90 seconds (unit tier, mocked `MockWebServer` — no live server) |

---

## Sampling Rate

- **After every task commit:** Run `mvn -f sdks/java/pom.xml test` (fast unit tier, no Testcontainers, no GPG signing)
- **After every plan wave:** Run `mvn -f sdks/java/pom.xml verify -Dgpg.skip=false` (ephemeral key) + the TLS-bypass grep gate + `mvn -f sdks/java/pom.xml dependency:tree` sanity check
- **Before `/gsd-verify-work`:** Full suite green AND `mvn verify -Dgpg.skip=false` passing (incl. javadoc/sources jars) AND CONTRACT.md §1–§10 conformance checklist reviewed
- **Max feedback latency:** ~90 seconds

---

## Per-Task Verification Map

> Task IDs (`20-NN-MM`) are assigned by the planner. Rows below map each phase
> requirement / success-criterion to its automated verification; the planner
> binds each to the task that delivers it.

| Requirement / SC | Wave | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|------------------|------|-----------------|-----------|-------------------|-------------|--------|
| JAVA-01 SC#1 (`io.axiam:axiam-sdk` in POM; `tenantId` compiler-required; `login()` → typed `LoginResult`) | ≥1 | N/A | unit (`MockWebServer`) + compile-shape assertion | `mvn -f sdks/java/pom.xml test -Dtest=AxiamClientBuilderTest` | ❌ W0 | ⬜ pending |
| JAVA-01 SC#2 (5 concurrent threads ⇒ exactly 1 refresh) | ≥1 | prevents thundering-herd refresh | unit (`CountDownLatch`+`ExecutorService`, counting dispatcher) | `mvn -f sdks/java/pom.xml test -Dtest=RefreshGuardSingleFlightTest` | ❌ W0 | ⬜ pending |
| JAVA-01 SC#3 (Spring Security filter protects endpoint, compiles vs Spring Boot 3.x, complete app context) | ≥2 | local JWKS verify + tenant check → `SecurityContext` | integration (`@SpringBootTest`) + example build | `mvn -f sdks/java/pom.xml test -Dtest=AxiamAuthenticationFilterIT` + `mvn -f sdks/java/examples/spring-boot-app/pom.xml verify` | ❌ W0 | ⬜ pending |
| JAVA-01 SC#4 (no `hostnameVerifier`/`sslSocketFactory` bypass; `CookieManager` present) | ≥1 | no TLS bypass | static (CI grep gate, extended pattern set) | `bash sdks/java/scripts/tls-bypass-gate.sh` | ❌ W0 (CI) | ⬜ pending |
| JAVA-01 SC#5 (`mvn verify` passes incl. GPG signing; Central publish pipeline operational) | last | supply-chain integrity | build/packaging (not JUnit) | `mvn -f sdks/java/pom.xml verify -Dgpg.skip=false` (PR-gate, ephemeral key); tag-triggered `mvn deploy` (real key) | ❌ W0 (CI) | ⬜ pending |
| D-18 / CR-04 (`NetworkError` never leaks `Set-Cookie`/`Authorization`/`Cookie`) | ≥1 | info-disclosure mitigation | unit (non-vacuous regression + control) | `mvn -f sdks/java/pom.xml test -Dtest=ErrorRedactionTest` | ❌ W0 | ⬜ pending |
| D-17 (`Sensitive` redacts across `toString()` + Jackson, non-`Serializable`) | ≥1 | info-disclosure mitigation | unit | `mvn -f sdks/java/pom.xml test -Dtest=SensitiveTest` | ❌ W0 | ⬜ pending |
| §8 / AMQP HMAC (verify-before-handler byte-for-byte vs server, insertion-order preservation) | **0** | tamper/replay mitigation | unit (real cross-language fixture) | `mvn -f sdks/java/pom.xml test -Dtest=HmacVerifyTest` | ❌ **W0 — real fixture required** | ⬜ pending |
| D-19 (JWKS: EdDSA-only alg pinning, rotate on unknown `kid`, cross-tenant rejection) | ≥1 | alg-confusion + EoP mitigation | unit (mocked JWKS) + integration | `mvn -f sdks/java/pom.xml test -Dtest=JwksVerifierTest,AxiamAuthenticationFilterIT` | ❌ W0 | ⬜ pending |
| Cross-tenant token replay (`claims.tenant_id == configuredTenantId` in filter) | ≥2 | spoofing/EoP mitigation | unit | `mvn -f sdks/java/pom.xml test -Dtest=AxiamAuthenticationFilterIT` | ❌ W0 | ⬜ pending |
| §3 CSRF non-browser (`X-CSRF-Token` response header captured + echoed on mutating requests) | ≥1 | CSRF mitigation | unit (`MockWebServer` header round-trip) | `mvn -f sdks/java/pom.xml test -Dtest=CsrfInterceptorTest` | ❌ W0 | ⬜ pending |
| §5 tenant context (`X-Tenant-Id` REST / `x-tenant-id` gRPC metadata injected every request) | ≥1 | tenant isolation | unit | `mvn -f sdks/java/pom.xml test -Dtest=TenantHeaderTest` | ❌ W0 | ⬜ pending |
| D-21 (gRPC codegen builds via `protobuf-maven-plugin`; optional drift-check) | ≥1 | supply-chain/drift | CI build step | `mvn -f sdks/java/pom.xml generate-sources compile` | ❌ W0 (CI) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `sdks/java/pom.xml` — full rewrite from the Java-11 scaffold: `maven.compiler.release=21` (D-01), full `<dependencies>` (OkHttp 4.12, grpc-netty-shaded 1.82, amqp-client 5.22, nimbus-jose-jwt 10.x, Jackson, JSpecify, SLF4J API, Spring `optional`/`provided`, JUnit 5, `mockwebserver`), plugin chain (`protobuf-maven-plugin`+`os-maven-plugin` for codegen — D-21, `central-publishing-maven-plugin`, `maven-gpg-plugin`, javadoc/sources jars — D-20/D-22, `Automatic-Module-Name` — D-24)
- [ ] `sdks/java/src/main/java/io/axiam/sdk/` — entire package tree is new (scaffold has only `pom.xml`/`README.md`/`LICENSE`, no `src/`)
- [ ] `protobuf-maven-plugin` `<protoSourceRoot>` pointed at the shared `proto/axiam/v1/*.proto` tree (one source of truth, no file duplication); generated stubs into `target/generated-sources` (gitignored, compiled classes bundled)
- [ ] `sdks/buf.gen.yaml` — Wave-0 decision: demote Java entries to documentation/drift-check-only (RESEARCH Pitfall 1 — the `out:` path currently conflicts with D-21's gitignored-build-output model) OR fix `out:` path + wire `buf generate` via `exec-maven-plugin`
- [ ] `sdks/java/src/test/resources/` — **real cross-language AMQP HMAC fixture** captured from / cross-verified against `crates/axiam-amqp/src/messages.rs` (insertion-order canonicalization; inherits Phase 19's empirically-proven ordering) — **must resolve before other AMQP work**
- [ ] `sdks/java/src/test/java/.../conftest`-equivalent shared test fixtures (`MockWebServer` bootstrap, mocked JWKS endpoint, fake HMAC signing key)
- [ ] `sdks/java/scripts/tls-bypass-gate.sh` — CI grep gate (extended pattern set beyond the literal SC#4 idioms) over `sdks/java/` source + examples + tests
- [ ] `.planning/REQUIREMENTS.md` JAVA-01 — reconcile the BOM coordinate `io.axiam:axiam-bom` (D-23, flagged Deferred Idea) — a scoped doc edit, **do not lose**
- [ ] `.github/workflows/sdk-ci-java.yml` — currently only a `scaffold-check` job; needs `mvn test`, TLS-bypass grep gate, `mvn verify -Dgpg.skip=false` (ephemeral key), buf/codegen drift-check, and a tag-triggered `sdks/java/vX.Y.Z` publish job (real GPG secret + Central Portal creds), mirroring `sdk-ci-python.yml`'s structure

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Maven Central publish (Sonatype Central Portal) actually releases on a real tag | JAVA-01 SC#5 / D-22 | Requires the verified `io.axiam` namespace + Central Portal credentials + real GPG key; cannot run in unit CI, and the namespace may not be claimed yet | On first `sdks/java/vX.Y.Z` tag, confirm the publish job succeeds and `io.axiam:axiam-sdk` (+ `io.axiam:axiam-bom`) appears on Central. First publish may be a maintainer action if creds/namespace are absent (D-22 deferred note) |

*All other phase behaviors have automated verification (unit, integration, static grep, build/packaging, or CI-gate).*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (incl. the AMQP HMAC cross-language fixture)
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
