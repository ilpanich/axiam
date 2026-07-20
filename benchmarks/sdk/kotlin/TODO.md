# Kotlin SDK benchmark — now wired

The Kotlin bench glue is wired to the real SDK (`io.github.ilpanich:axiam-sdk-kotlin:1.0.0-alpha13`).

- **Entrypoint:** `src/main/kotlin/Bench.kt` (top-level `fun main()`, compiled to
  `io.axiam.bench.BenchKt`). It reads the `BENCH_*` / `SDK_BENCH_*` env, times the four
  canonical ops (`login`, `refresh`, `check_access`, `batch_check`) with a warm-up +
  measured loop (bounded-concurrency coroutines), and prints one `axiam.sdk-bench/v1` JSON
  record to stdout. `refresh` runs serially (concurrency 1, single-flight-guarded); the
  others run at `SDK_BENCH_CONCURRENCY`.
- **SDK dependency:** `build.gradle.kts` depends on `io.github.ilpanich:axiam-sdk-kotlin:1.0.0-alpha13`.
  `settings.gradle.kts` resolves it via an `includeBuild("../../../../axiam-kotlin-sdk")`
  composite build with an explicit `dependencySubstitution`, so it builds against the
  sibling `axiam-kotlin-sdk` checkout even before the alpha package is published to Maven
  Central — no separate local-publish step needed (Gradle composite builds substitute the
  dependency with the included project's own compiled output). Swap the version pin for the
  published-package version once `axiam-sdk-kotlin` is live on Maven Central, and drop the
  `includeBuild` block.
- **Run:** `./gradlew -q --console=plain run` (this is what `run.sh` execs), or from the
  benchmarks root: `just sdk=kotlin sdk-bench`.
- **mTLS (p3-mtls):** out of SDK-harness scope for now — see HARNESS-SPEC.md's
  "Security-profile limitation" (no AXIAM SDK bench currently drives the mTLS profile,
  even though the Kotlin SDK itself exposes `clientCertificate(...)` per CONTRACT §6.1).
- **Degradation:** `run.sh` falls back to `../_pending.sh`'s `emit_pending kotlin` if `java`
  or the gradle wrapper is missing, or if the Gradle build fails (e.g. Maven Central / Gradle
  Plugin Portal egress is blocked in a sandboxed environment — the code is still correct and
  will build wherever that egress is open). `Bench.kt` itself emits a spec-conformant
  `status: "error"` record (not a crash) when the build succeeds but the target is
  unreachable or login/the warm-up `check_access` grant fails.
