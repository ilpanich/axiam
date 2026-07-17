# Java SDK benchmark — now wired

The Java bench glue is wired to the real SDK
(`io.github.ilpanich:axiam-sdk:1.0.0-alpha2`, jar).

- **Entrypoint:** `src/main/java/io/axiam/bench/Bench.java` (main class
  `io.axiam.bench.Bench`). It reads the `BENCH_*` / `SDK_BENCH_*` env, times the
  four canonical ops (`login`, `refresh`, `check_access`, `batch_check`) with a
  warm-up + measured loop, and prints one `axiam.sdk-bench/v1` JSON record to
  stdout. `refresh` runs serially (single-flight-guarded); the others run at
  `SDK_BENCH_CONCURRENCY`.
- **Run:** `mvn -q exec:java` (this is what `run.sh` execs), or from the
  benchmarks root: `just sdk-bench sdk=java`.
- **Local .m2:** if `io.github.ilpanich:axiam-sdk` is not yet on Maven Central,
  install it locally first by running `mvn install` in the SDK repo:
  `mvn -f ../../../../axiam-java-sdk/pom.xml install`.
