# Java SDK benchmark — now wired

The Java bench glue is wired to the real SDK
(`io.github.ilpanich:axiam-sdk:1.0.0-alpha2`, jar).

- **Entrypoint:** `src/main/java/io/axiam/bench/Bench.java` (main class
  `io.axiam.bench.Bench`). It reads the `BENCH_*` / `SDK_BENCH_*` env, times the
  four canonical ops (`login`, `refresh`, `check_access`, `batch_check`) with a
  warm-up + measured loop, and prints one `axiam.sdk-bench/v1` JSON record to
  stdout. `refresh` runs serially (single-flight-guarded); the others run at
  `SDK_BENCH_CONCURRENCY`.
- **Run:** `mvn -q compile exec:java` (this is what `run.sh` execs), or from
  the benchmarks root: `just sdk=java sdk-bench`.
- **Local .m2:** if `io.github.ilpanich:axiam-sdk` is not yet on Maven Central,
  `run.sh` installs it locally itself (via `mvn -f
  ../../../../axiam-java-sdk/pom.xml install -DskipTests`) whenever
  `dependency:resolve` fails, so a bare `just sdk=java sdk-bench` is enough on
  a fresh checkout — no separate manual step required.

## H8 fix — `ClassNotFoundException: io.axiam.bench.Bench`

`mvn -q exec:java` alone never triggers Maven's `compile` phase (the
exec-maven-plugin's `exec:java` goal isn't bound to a lifecycle phase in this
pom), so `target/classes/io/axiam/bench/Bench.class` didn't exist yet and the
JVM raised `ClassNotFoundException`. Fixed by running `mvn -q compile
exec:java` (compile, then exec, in one invocation) in `run.sh`. Verified in
this environment: `mvn -f ../../../../axiam-java-sdk/pom.xml install
-DskipTests` installs the sibling SDK into `~/.m2`, `mvn -q compile` on this
directory succeeds, and `bash run.sh` prints a real `axiam.sdk-bench/v1`
record (an honest `status: "error"` pre-seed/pre-server, `"ok"` once a seeded
target is reachable).
