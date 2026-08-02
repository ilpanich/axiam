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

## H8 fix — `BENCH_CA_CERT` not wired (p0 fixed, p2 hits a separate SDK bug)

`Bench.java` never read `BENCH_CA_CERT` (HARNESS-SPEC.md's documented input
for trusting a TLS profile's throwaway CA), so every p2 run failed
immediately with a certificate-verification error. Fixed: `newClientBuilder()`
now reads the file and calls `AxiamClient.Builder.customCa(byte[])` when
`BENCH_CA_CERT` is set; `run.sh` also resolves the (relative) path to
absolute before its `cd "$HERE"`, since `profiles/*.env` sets it relative to
`benchmarks/` and this script changes directory before the JVM ever reads it.

That fix is necessary but not sufficient for p2: with the CA now trusted,
the SDK's OkHttp client still fails with `Hostname localhost not verified`
against a certificate that `curl --cacert profiles/certs/ca.crt` and every
other SDK bench here (rust/go/python/php, all validated `ok` at p2) verify
successfully — same host, same port, same certificate. This looks like a
genuine bug in `AxiamClient`'s OkHttp/`SSLContext` wiring
(`buildStrictSslContext`/hostname-verifier interaction), not a harness
issue, and needs an SDK-side investigation this task's scope didn't cover
(TLS-internals debugging, not a mechanical harness fix). p0 is unaffected
and fully validated (`ok`, double-run-clean).

## p3-mtls (CONTRACT.md §6.1)

Wired: `newClientBuilder()` — the single builder factory behind both the shared
client and the per-iteration `login` client — reads `BENCH_CLIENT_CERT`/
`BENCH_CLIENT_KEY` (file paths) and applies
`clientCertificate(byte[] certPem, byte[] keyPem)`.

Two blockers had to be cleared first, and both are worth knowing about:

1. **The bench was compiling against a stale SDK.** `pom.xml` pinned
   `1.0.0-alpha2` while the sibling checkout was at `1.0.0-alpha21`, and
   `run.sh` only installed the sibling when the dependency failed to *resolve*
   — which a stale jar in `~/.m2` never does. §6.1's `clientCertificate(...)`
   did not exist in alpha2. The version is now a `${axiam.sdk.version}`
   property that `run.sh` overrides with the version the sibling checkout
   actually declares, installing it to `~/.m2` on demand
   (`-DskipTests -Djacoco.skip=true`; the jacoco coverage gate fails a
   test-skipping install otherwise).
2. **The bench CA lacked `keyUsage=keyCertSign`** (`runner/gen-certs.sh`), so
   strict-X.509 TLS stacks rejected the chain. This is very likely the same
   root cause as the p2-tls13 "SSL handshake" failure described above — that
   note predates the fix; re-verify before treating it as an SDK bug.

```
cd benchmarks && just target=axiam profile=p3-mtls sdk=java sdk-bench
just sdk-bench-test java   # proves the cert reaches the wire, no stack needed
```

Verified: phase A (half-configured pair -> `status:"error"` naming both vars)
and phase B (stub mTLS server observes `CN=bench-client`) both pass.
