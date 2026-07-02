---
phase: 20-java-sdk
plan: 01
subsystem: sdk
tags: [java, maven, pom, grpc, protobuf-maven-plugin, gpg, maven-central, buf, tls-gate]

# Dependency graph
requires:
  - phase: 15-sdk-foundation
    provides: proto/axiam/v1/*.proto, sdks/buf.gen.yaml, sdks/CONTRACT.md, sdks/java/{pom.xml,README.md,LICENSE} scaffold
provides:
  - "sdks/java/pom.xml rebuilt for Java 21 with the full JAVA-01-pinned dependency set and GPG/Central Portal publish plugin chain"
  - "Maven-native gRPC codegen pipeline (protobuf-maven-plugin + os-maven-plugin) generating into gitignored target/generated-sources"
  - "buf.gen.yaml Java entries demoted to drift-check-only documentation"
  - "sdks/java/scripts/tls-bypass-gate.sh — extended TLS-bypass CI grep gate"
  - "REQUIREMENTS.md JAVA-01 reconciled to list both io.axiam:axiam-sdk and io.axiam:axiam-bom"
affects: [20-02, 20-03, 20-04, 20-05, 20-06, 20-07, 20-08, 20-09]

# Tech tracking
tech-stack:
  added: [okhttp 4.12.0, grpc-netty-shaded/grpc-protobuf/grpc-stub 1.82.0, amqp-client 5.22.0, nimbus-jose-jwt 10.7, tink 1.15.0, jackson-databind+jsr310 2.22.0, jspecify 1.0.0, slf4j-api 2.0.17, spring-boot-starter-security 3.5.6 (provided/optional), jakarta.servlet-api 6.1.0 (provided), junit-jupiter 5.14.4, okhttp3 mockwebserver 4.12.0, protobuf-maven-plugin 0.6.1, os-maven-plugin 1.7.1, maven-jar-plugin 3.4.2, maven-source-plugin 3.3.1, maven-javadoc-plugin 3.11.2, maven-gpg-plugin 3.2.8, central-publishing-maven-plugin 0.9.0]
  patterns: ["generate-on-build gRPC codegen via protobuf-maven-plugin into gitignored target/generated-sources (D-21)", "gpg.skip property gate for CI-safe signing (Pitfall 4)", "extended TLS-bypass grep gate beyond literal SC#4 substrings"]

key-files:
  created:
    - sdks/java/.gitignore
    - sdks/java/src/main/java/io/axiam/sdk/package-info.java
    - sdks/java/scripts/tls-bypass-gate.sh
  modified:
    - sdks/java/pom.xml
    - sdks/buf.gen.yaml
    - .planning/REQUIREMENTS.md

key-decisions:
  - "protobuf.version pinned to 3.25.8 (not RESEARCH.md's 4.29.0 placeholder) after confirming via `mvn dependency:tree` that grpc-protobuf 1.82.0 actually pulls com.google.protobuf:protobuf-java:3.25.8 transitively"
  - "buf.gen.yaml Java plugin entries commented out (not deleted) with an explanatory block, preserving them as an optional future CI drift-check reference per D-21"
  - "tls-bypass-gate.sh scans only sdks/java/src + sdks/java/examples with --exclude-dir=test, so a future reflection-based TLS regression test referencing these idioms as literal strings cannot self-trip the gate"

patterns-established:
  - "Pattern: gpg.skip=true default property flips to false only in PR-gate CI (ephemeral key) or tag-triggered publish (real CI secret) — never a real key on a PR job"
  - "Pattern: protoSourceRoot points at ../../proto (repo-canonical proto/axiam/v1/*.proto), never duplicating .proto files into sdks/java/"

requirements-completed: [JAVA-01]

coverage:
  - id: D1
    description: "sdks/java/pom.xml rewritten to Java 21 baseline with full JAVA-01-pinned dependency set (okhttp, grpc-netty-shaded, amqp-client, nimbus-jose-jwt+tink) and GPG/Central Portal publish plugin chain; mvn validate/dependency:resolve succeed"
    requirement: "JAVA-01"
    verification:
      - kind: other
        ref: "mvn -f sdks/java/pom.xml validate && mvn -f sdks/java/pom.xml dependency:resolve (executor-run, all four JAVA-01-pinned coordinates confirmed resolved)"
        status: pass
    human_judgment: false
  - id: D2
    description: "protobuf-maven-plugin + os-maven-plugin wired as the gRPC codegen path; generate-sources compile produces AuthorizationServiceGrpc + message classes into gitignored target/generated-sources; no generated .java leaks into the committed src tree; buf.gen.yaml Java entries demoted to comment-only"
    requirement: "JAVA-01"
    verification:
      - kind: other
        ref: "mvn -f sdks/java/pom.xml generate-sources compile (executor-run, BUILD SUCCESS) + git status --porcelain sdks/java/src/main/java (empty)"
        status: pass
    human_judgment: false
  - id: D3
    description: "TLS-bypass grep gate script created and green on the current (empty) src/examples tree; REQUIREMENTS.md JAVA-01 reconciled to list both io.axiam:axiam-sdk and io.axiam:axiam-bom coordinates"
    requirement: "JAVA-01"
    verification:
      - kind: other
        ref: "bash sdks/java/scripts/tls-bypass-gate.sh (executor-run, exit 0, OK line printed) + grep -c 'axiam-bom' .planning/REQUIREMENTS.md == 1"
        status: pass
    human_judgment: false

duration: 10min
completed: 2026-07-02
status: complete
---

# Phase 20 Plan 01: Java SDK Wave-1 Foundation Summary

**Rewrote the stale Java-11 `sdks/java/pom.xml` scaffold to a Java 21 build with the full JAVA-01-pinned dependency set, a Maven-native gRPC codegen pipeline replacing the unavailable `buf` CLI, and a GPG/Central-Portal publish plugin chain.**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-07-02T07:01:55Z
- **Completed:** 2026-07-02T07:06:54Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments
- `sdks/java/pom.xml` rebuilt: `maven.compiler.release=21`, `gpg.skip=true` default, full dependency set (okhttp 4.12.0, grpc-netty-shaded/grpc-protobuf/grpc-stub 1.82.0, amqp-client 5.22.0, nimbus-jose-jwt 10.7 + tink 1.15.0, jackson-databind + jsr310 2.22.0, jspecify 1.0.0, slf4j-api, spring-boot-starter-security provided/optional, jakarta.servlet-api provided, junit-jupiter + okhttp3 mockwebserver test scope) and the full publish plugin chain (os-maven-plugin extension, maven-jar-plugin with `Automatic-Module-Name: io.axiam.sdk`, maven-source-plugin, maven-javadoc-plugin, maven-gpg-plugin, central-publishing-maven-plugin)
- `protobuf-maven-plugin` + `os-maven-plugin` wired as the gRPC codegen path (`protoSourceRoot=../../proto`), generating `AuthorizationServiceGrpc`/`UserServiceGrpc`/`TokenServiceGrpc` + message classes into the gitignored `target/generated-sources/protobuf`; confirmed via `mvn generate-sources compile` (BUILD SUCCESS, no generated `.java` in the committed source tree)
- `sdks/buf.gen.yaml`'s Java plugin entries demoted to a commented-out, documentation/drift-check-only block explaining the authoritative codegen path is `mvn generate-sources`
- `sdks/java/scripts/tls-bypass-gate.sh` created: extended TLS-bypass grep gate scanning `sdks/java/src` + `sdks/java/examples` (excludes `scripts/` and `src/test`), exits 0 on the current empty tree
- `.planning/REQUIREMENTS.md` JAVA-01 acceptance criteria reconciled to name both `io.axiam:axiam-sdk` and `io.axiam:axiam-bom` (D-23)

## Task Commits

Each task was committed atomically:

1. **Task 1: Rewrite pom.xml to Java 21 with full dependency + publish plugin chain (D-01/D-20/D-22/D-24)** - `6b16ff2` (feat)
2. **Task 2: Wire protobuf-maven-plugin codegen from shared proto + demote buf.gen.yaml Java entries (D-21, Pitfall 1)** - `5e42db2` (docs)
3. **Task 3: TLS-bypass grep gate script + REQUIREMENTS.md BOM reconciliation (SC#4, D-23)** - `0c847ea` (feat)

_Note: Task 2's pom.xml codegen wiring was already fully specified in Task 1's rewrite (single-pass authoring); Task 2's commit captures the confirmation/verification work and the buf.gen.yaml demotion._

## Files Created/Modified
- `sdks/java/pom.xml` - Java 21 POM: full dependency set + gRPC codegen + GPG/Central Portal publish chain
- `sdks/java/.gitignore` - ignores `target/` (generated-sources + compiled classes)
- `sdks/java/src/main/java/io/axiam/sdk/package-info.java` - `@NullMarked` root package anchor (D-05)
- `sdks/buf.gen.yaml` - Java plugin entries commented out (drift-check-only)
- `sdks/java/scripts/tls-bypass-gate.sh` - extended TLS-bypass CI grep gate (executable)
- `.planning/REQUIREMENTS.md` - JAVA-01 acceptance criteria names both `io.axiam:axiam-sdk` and `io.axiam:axiam-bom`

## Decisions Made
- **protobuf.version pinned to 3.25.8** (not RESEARCH.md's 4.29.0 placeholder / Assumption A6): ran `mvn dependency:tree` against the resolved `grpc-protobuf:1.82.0` dependency and confirmed it transitively pulls `com.google.protobuf:protobuf-java:3.25.8` — aligning `protocArtifact`'s version to the actual runtime protobuf-java floor, not the research placeholder, closes the risk flagged in Assumption A6.
- **buf.gen.yaml Java entries commented out, not deleted** — preserves them as documented reference for an optional future CI drift-check comparing buf's output against the Maven build's output, per D-21's explicit "Optional CI drift-check" allowance.
- **TLS gate excludes `src/test` via `grep --exclude-dir=test`** — the plan's acceptance criteria required the gate to exclude both `scripts/` (naturally excluded since the gate only scans `src`+`examples`) and `src/test` (excluded via an explicit grep flag) so a later reflection-based TLS regression test (RESEARCH.md `TlsBypassGrepTest.java`) can reference the literal bypass-idiom strings as assertions of their absence without self-tripping this exact gate.

## Deviations from Plan

None - plan executed exactly as written. All three tasks' acceptance criteria were met on first pass; no auto-fixes, blockers, or architectural changes were needed. Maven Central was reachable via the environment's configured proxy (`repo1.maven.org`/`repo.maven.apache.org` both returned HTTP 200), so all dependency/plugin resolution and the full `generate-sources compile` cycle ran live rather than requiring a stub/offline path.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required. (Live Maven Central GPG-signed publish is explicitly deferred to a later plan per D-22/Deferred Ideas — "first real Central release may be a maintainer action if namespace/GPG creds are absent in CI.")

## Next Phase Readiness

- `sdks/java/pom.xml` is a stable, buildable foundation: `mvn -f sdks/java/pom.xml validate/dependency:resolve/generate-sources/compile` all pass on Java 21, unblocking every Wave-2+ plan that needs to `mvn test`/`mvn compile` against this POM.
- gRPC stub classes (`AuthorizationServiceGrpc`, `UserServiceGrpc`, `TokenServiceGrpc`) are generated and compile cleanly — the client wrapper work in later plans (`GrpcAuthzClient`, `AuthClientInterceptor`) has a working codegen base to build on.
- The TLS-bypass gate is in place and green on the empty tree; it will start catching real violations as soon as `rest/`/`grpc`/`spring` source lands in later plans.
- No blockers or concerns for Wave 2.

---
*Phase: 20-java-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All created files verified present on disk; all three task commit hashes (6b16ff2, 5e42db2, 0c847ea) verified present in git log.
