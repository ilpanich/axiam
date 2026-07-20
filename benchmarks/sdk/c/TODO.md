# C SDK benchmark — wired

The C SDK bench is now wired to the real SDK (`ilpanich/axiam-c-sdk`).
`bench.c` builds an `axiam_client_t`, logs in, and times the four canonical
CONTRACT.md §1 ops — `axiam_login`, `axiam_refresh`, `axiam_check_access`,
`axiam_batch_check` — with a warm-up + measured loop, then prints one
`axiam.sdk-bench/v1` JSON record to stdout (see `../HARNESS-SPEC.md`).

## How it's wired
- `CMakeLists.txt` pulls in the sibling `axiam-c-sdk` checkout
  (`../../../../axiam-c-sdk`, same depth as the go/rust benches' path dep)
  via `add_subdirectory()` — the lowest-egress option CMake supports (no
  vcpkg/Conan registry fetch). It builds only the static library variant
  (`AXIAM_BUILD_SHARED=OFF`) so `axiam-bench` runs standalone with no
  `LD_LIBRARY_PATH` juggling, and disables the SDK's own tests/examples.
  Swap `add_subdirectory()` for
  `find_package(axiam-c-sdk CONFIG REQUIRED)` against an installed/published
  package once the alpha is resolvable via vcpkg/Conan/apt.
- All four ops are timed with a **plain serial loop** (not just `refresh`,
  which HARNESS-SPEC.md requires to be serial for every SDK). This is the
  explicitly-allowed simplification for the C harness — see the comment at
  the top of `bench.c` — so the emitted record always reports
  `"concurrency": 1`; `SDK_BENCH_CONCURRENCY` is read but not applied, and
  the JSON `notes` field says so.
- On setup failure (server down / bad creds / missing grant) it emits a
  zeroed `status: "error"` record and exits 0 — never a crash.
- `run.sh` degrades to a `pending` record if `cmake`/a C compiler is missing,
  or if the configure/build step fails for any reason (e.g. the sibling SDK
  checkout, or its libcurl/OpenSSL dev headers, are missing).
- Per HARNESS-SPEC.md, `BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY`/`BENCH_CA_CERT`
  are **not** wired here (p3-mtls is out of SDK-bench scope, exercised by the
  k6 scenarios instead) — matching the python/typescript/go/rust reference
  benches, none of which wire them either, even though the C SDK itself does
  expose a client-cert option (CONTRACT §6.1).

## Requirements
- CMake ≥ 3.16, a C11 compiler (gcc/clang).
- libcurl + OpenSSL dev headers (`apt-get install -y libcurl4-openssl-dev
  libssl-dev`) — required to build the sibling `axiam-c-sdk`.
- The sibling checkout at `../../../../axiam-c-sdk` (i.e.
  `ilpanich/axiam-c-sdk` cloned next to this monorepo checkout).

## Run
```
cd benchmarks && just sdk=c sdk-bench
```
`BENCH_RESOURCE_ID` must be a valid UUID (the AXIAM authz endpoints reject
non-UUID resource ids).

## Verified in this environment
- The sibling `axiam-c-sdk` (libcurl/OpenSSL present) and this bench both
  compile and link cleanly (`cmake -S . -B build && cmake --build build`
  produces `build/axiam-bench`).
- No live AXIAM target is reachable here, so `run.sh` correctly emits a
  `status: "error"` record (connection refused) rather than an `ok` one.
- Smoke-tested against a minimal fake HTTP server standing in for AXIAM's
  wire contract (login/refresh/check/batch-check responses per CONTRACT.md):
  all four ops complete with zero errors and the bench emits a valid
  `status: "ok"` record. Also run clean under `valgrind --leak-check=full`
  (0 errors, all allocations freed). This exercises the same SDK code paths
  as a real server, just not a real AXIAM instance — an `ok` record against
  the real, seeded target is still pending the maintainer's laptop.
