# Phase 20: Java SDK - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-02
**Phase:** 20-java-sdk
**Areas discussed (7 rounds):** JDK baseline · Async surface · Module & Spring packaging · Maven Central publish/signing · gRPC codegen distribution · Logging · Testing · Spring filter registration · Refresh trigger · JDK-21 feature use · EdDSA verification · JPMS · gRPC channel lifecycle · AMQP recovery · Retry library · Client override safety · Spring compatibility range · Timeouts · BOM · JSON library · Sensitive design · gRPC deadlines · error i18n · Exception model · DTO modeling · Nullability · Config source

> **Process note:** The user selected the four originally-presented gray areas and then
> repeatedly chose "explore more," locking 27 Java-specific decisions across 7 interactive
> question rounds. All are user-confirmed in CONTEXT.md.

---

## Round 1 — the four originally-presented gray areas

### JDK baseline
| Option | Description | Selected |
|--------|-------------|----------|
| Java 17 | LTS floor Spring Boot 3.x requires; broad reach | |
| Java 21 | Newest LTS; virtual threads, pattern matching | ✓ |
| Split core 11 / example 17 | Max reach; multi-module complexity | |

**Chosen:** Java 21 (D-01). Scaffold's Java 11 conflicts with Spring Boot 3.x (needs 17+).

### Async surface
| Option | Description | Selected |
|--------|-------------|----------|
| Sync-only public API | Blocking; CompletableFuture internal only | |
| Sync + CompletableFuture async variants | Also `*Async()` returning CompletableFuture | ✓ |

**Chosen:** Sync + CompletableFuture async variants (D-02).

### Module & Spring packaging
| Option | Description | Selected |
|--------|-------------|----------|
| Single artifact; filter sets SecurityContext | One jar; idiomatic Spring Security contract | ✓ |
| Multi-module (core + spring-boot-starter) | Cleaner isolation; extra coordinates/release | |
| Single artifact; filter sets request attribute | Simpler; bypasses Spring authz model | |

**Chosen:** Single artifact; OncePerRequestFilter sets SecurityContext (D-14).

### Maven Central publish/signing
| Option | Description | Selected |
|--------|-------------|----------|
| Central Portal + maven-gpg-plugin + CI secrets | New Sonatype portal; javadoc/sources; tag-triggered | ✓ |
| Legacy OSSRH (nexus-staging) | Older flow being sunset | |
| Configure + document, defer live release | Signing passes mvn verify; first publish maintainer action | |

**Chosen:** Central Portal + maven-gpg-plugin + CI secrets (D-22).

---

## Round 2 — codegen, logging, testing

### gRPC codegen distribution
| Option | Description | Selected |
|--------|-------------|----------|
| Generate-on-build, gitignored | Compiled stubs bundled into jar (Rust/TS model) | ✓ |
| Commit generated stubs + drift-check | Go/Python source-distribution model | |

**Chosen:** Generate-on-build, gitignored (D-21).

### Logging
| Option | Description | Selected |
|--------|-------------|----------|
| SLF4J API | Universal facade, no binding, silent by default | ✓ |
| java.util.logging | Zero-dep but non-idiomatic | |
| Injectable logger interface | Reinvents SLF4J | |

**Chosen:** SLF4J API (D-25).

### Testing
| Option | Description | Selected |
|--------|-------------|----------|
| JUnit 5 + MockWebServer + optional Testcontainers | Hermetic units + tagged smoke; sibling parity | ✓ |
| JUnit 5 + WireMock | Heavier than OkHttp's own MockWebServer | |
| JUnit 5 + Testcontainers-first | Slow, Docker-dependent, flaky concurrency test | |

**Chosen:** JUnit 5 + MockWebServer + optional Testcontainers (D-28).

---

## Round 3 — Spring wiring, refresh, JDK 21, EdDSA

### Spring filter registration
| Option | Description | Selected |
|--------|-------------|----------|
| Manual SecurityFilterChain + optional auto-config | Explicit example + zero-config convenience | ✓ |
| Manual registration only | Explicit but boilerplate for every consumer | |
| Auto-configuration only | Least boilerplate but 'magic'; SC#3 wants visible context | |

**Chosen:** Manual SecurityFilterChain in example + optional @AutoConfiguration (D-15).

### Refresh trigger
| Option | Description | Selected |
|--------|-------------|----------|
| Proactive JWKS + OkHttp Authenticator fallback | Interceptor injects + proactive; Authenticator reactive 401 | ✓ |
| Interceptor-only reactive 401 | Re-implements what Authenticator gives free | |

**Chosen:** Proactive JWKS + OkHttp Authenticator fallback, one shared guard (D-08).

### JDK 21 feature use
| Option | Description | Selected |
|--------|-------------|----------|
| Virtual-thread-friendly, not required | Correct on virtual threads, no Loom lock-in | ✓ |
| Adopt virtual threads internally | Imposes SDK threading on consumers | |
| Ignore — Java 17-style | Risks synchronized-around-I/O pinning | |

**Chosen:** Virtual-thread-friendly, not required (D-10).

### EdDSA verification
| Option | Description | Selected |
|--------|-------------|----------|
| Nimbus JWKS + nimbus EdDSA (Tink-backed), no hand-rolled crypto | Least security-sensitive surface | ✓ |
| Nimbus JWKS + explicit Tink Ed25519 verifier | Hand-written key conversion + verify | |

**Chosen:** Nimbus JWKS + nimbus EdDSA, Tink as implementation detail (D-19).

---

## Round 4 — JPMS, transports, resilience

### JPMS
| Option | Description | Selected |
|--------|-------------|----------|
| Automatic-Module-Name manifest entry | Stable module name, no strict-module dep constraints | ✓ |
| Full module-info.java | Requires all deps modular; shaded deps don't comply | |
| Neither (classpath only) | Unstable auto-derived module name | |

**Chosen:** Automatic-Module-Name: io.axiam.sdk (D-24).

### gRPC channel lifecycle
| Option | Description | Selected |
|--------|-------------|----------|
| One long-lived channel, closed with client | Idiomatic gRPC; reused across calls | ✓ |
| Channel per call / short-lived | Anti-pattern; kills connection reuse | |

**Chosen:** One long-lived ManagedChannel, closed in close() (D-11).

### AMQP recovery
| Option | Description | Selected |
|--------|-------------|----------|
| Enable built-in automatic recovery | Battle-tested RabbitMQ client reconnection | ✓ |
| Hand-rolled reconnect loop | Reinvents mature feature | |

**Chosen:** Built-in automatic connection/topology recovery (D-13).

### Retry library
| Option | Description | Selected |
|--------|-------------|----------|
| Hand-rolled lightweight backoff, no extra dep | Minimal footprint; idempotent-only | ✓ |
| Resilience4j / Failsafe | More features; heavy transitive dep on every consumer | |

**Chosen:** Hand-rolled lightweight bounded backoff (D-26).

---

## Round 5 — builder safety, compatibility, config

### Client override safety
| Option | Description | Selected |
|--------|-------------|----------|
| Allow injection; SDK re-applies jar + TLS | OkHttpClient injectable; §4/§6 invariants preserved (Go D-09) | ✓ |
| No injection; granular options only | Safest, less flexible | |
| Full injection, consumer owns config | Pushes §4/§6 safety onto caller | |

**Chosen:** Allow OkHttpClient injection; SDK re-applies CookieManager + TLS (D-27).

### Spring compatibility range
| Option | Description | Selected |
|--------|-------------|----------|
| Spring Boot 3.2+ / Security 6.x, test latest 3.x | Matches JDK 21 + SC#3; deps optional/provided | ✓ |
| Broadest 3.x (3.0+) | Wider but 3.0/3.1 EOL, more surface | |
| Pin one exact version | Simplest CI; surprises on nearby 3.x | |

**Chosen:** Spring Boot 3.2+ / Spring Security 6.x, test latest stable 3.x (D-16).

### Timeouts
| Option | Description | Selected |
|--------|-------------|----------|
| Sane defaults, builder-overridable | Reasonable defaults; every value tunable | ✓ |
| OkHttp defaults, no SDK opinion | 10s defaults may not suit authz hot path | |

**Chosen:** Sane defaults, builder-overridable (D-26 timeouts).

### BOM
| Option | Description | Selected |
|--------|-------------|----------|
| No BOM — single artifact only | JAVA-01 defines one coordinate | |
| Publish a BOM | io.axiam:axiam-bom for dependency alignment | ✓ |

**Chosen:** Publish a BOM (D-23). **Note:** JAVA-01 lists only io.axiam:axiam-sdk — reconcile to add the BOM (deferred).

---

## Round 6 — serialization, token safety, gRPC deadlines, i18n

### JSON library
| Option | Description | Selected |
|--------|-------------|----------|
| Jackson | Enterprise/Spring standard; near-zero marginal footprint | ✓ |
| Moshi | Pairs with OkHttp, lighter; extra dep for Spring users | |
| Gson | Maintenance mode; weaker records support | |

**Chosen:** Jackson (D-04 JSON).

### Sensitive design
| Option | Description | Selected |
|--------|-------------|----------|
| Redact toString + JSON + block serialization; internal accessor | Closes CR-04 leak class | ✓ |
| Contract floor only (toString) | Leaves JSON/logging leak paths open | |

**Chosen:** Hardened final Sensitive class (D-17).

### gRPC deadline
| Option | Description | Selected |
|--------|-------------|----------|
| Default per-call deadline, overridable | Prevents hung request threads on stalled channel | ✓ |
| No default deadline | Unbounded call can hang caller | |

**Chosen:** Default per-call deadline, overridable (D-12).

### Error i18n
| Option | Description | Selected |
|--------|-------------|----------|
| English-only, no i18n | Typed exceptions + codes for classification | ✓ |
| Support message i18n (ResourceBundle) | Translation upkeep, little value | |

**Chosen:** English-only, no i18n (D-29).

---

## Round 7 — exception model, DTOs, nullability, config source

### Exception model
| Option | Description | Selected |
|--------|-------------|----------|
| Unchecked (RuntimeException) | Idiomatic modern Java SDK; no forced throws | ✓ |
| Checked exceptions | Compiler-forced but noisy, breaks lambdas | |

**Chosen:** Unchecked RuntimeException subclasses (D-03).

### DTO modeling
| Option | Description | Selected |
|--------|-------------|----------|
| Java records | Native on 21, immutable, Jackson-supported, no Lombok | ✓ |
| Classes + Lombok | Annotation-processor dependency | |
| Hand-written classes | Verbose boilerplate | |

**Chosen:** Java records (D-04).

### Nullability
| Option | Description | Selected |
|--------|-------------|----------|
| JSpecify @Nullable on public API | Emerging cross-vendor standard (Spring 7 etc.) | ✓ |
| No nullability annotations | Forfeits static null-analysis | |
| JetBrains/Jakarta annotations | JSpecify is the consolidation direction | |

**Chosen:** JSpecify @Nullable + @NullMarked default (D-05).

### Config source
| Option | Description | Selected |
|--------|-------------|----------|
| Builder-only, explicit | tenantId compiler-required; no ambient config | ✓ |
| Builder + env/system-property fallback | Implicit config complicates testing; weakens tenantId guarantee | |

**Chosen:** Builder-only, explicit (D-06).

---

## Claude's Discretion (remaining after this session)

- Internal package/module layout and file names under `sdks/java/src`.
- Exact numeric timeout/backoff/retry values, gRPC deadline, AMQP prefetch/QoS.
- Exact `*Async` method naming and `LoginResult` optional-field set beyond `mfaRequired`.
- OkHttp interceptor ordering (application vs network); RemoteJWKSet cache-TTL specifics.
- POM plugin versions; exact central-publishing-maven-plugin / maven-gpg-plugin config.

## Deferred Ideas

- JAVA-01 ↔ BOM coordinate reconciliation (add io.axiam:axiam-bom to JAVA-01; don't lose).
- Full module-info.java (strict JPMS) — rejected; shaded deps not clean modules.
- Resilience4j/Failsafe for retry — rejected to keep footprint minimal.
- Live Maven Central first publish may be a maintainer action if creds/namespace absent in CI.
- Automated cross-language conformance harness — inherited deferred item.
