# C++ SDK benchmark — wired

The C++ SDK bench is now wired to the real SDK (`ilpanich/axiam-cplusplus-sdk`,
`axiam::Client`). `bench.cpp` builds a `Client` and times the four canonical
CONTRACT.md §1 ops — `login`, `refresh`, `check_access`, `batch_check` — with a
warm-up + measured loop, then prints one `axiam.sdk-bench/v1` JSON record to
stdout (see `../HARNESS-SPEC.md`).

## How it's wired
- `CMakeLists.txt` builds the sibling checkout
  (`../../../../axiam-cplusplus-sdk`, i.e. `axiam-cplusplus-sdk` next to this
  repo) via `add_subdirectory()` — the least-egress path: no vcpkg/Conan
  registry fetch, just the checkout that already lives next to this repo.
  Override the path with `-DAXIAM_CPP_SDK_DIR=<path>` if your checkout lives
  elsewhere. For a reproducible published build, swap this for
  `find_package(axiam-cpp-sdk CONFIG REQUIRED)` (vcpkg manifest mode — see the
  SDK's `vcpkg.json`, currently pinned to `1.0.0-alpha12`) once the package is
  published to a registry this environment can reach.
- `axiam::Client` is a thin handle over a mutex-guarded impl (§9 single-flight
  refresh guard), so one shared `Client` (copied into each op's lambda) can be
  called concurrently from multiple worker threads safely. `login` instead
  builds and discards its own short-lived `Client` per call, mirroring what
  the op measures.
- `refresh` is timed serially (concurrency 1) because the SDK single-flight-
  guards it; the other three ops run at `SDK_BENCH_CONCURRENCY` across a
  `std::thread` worker pool (atomic work-stealing counter, matching the
  pattern in `../go/main.go`).
- Optional `BENCH_CA_CERT` / `BENCH_CLIENT_CERT` / `BENCH_CLIENT_KEY` (PEM
  file paths) are read and wired into `Client::Builder::with_custom_ca()` /
  `with_client_cert()` when set — the C++ SDK is the one SDK that exposes a
  client-cert mTLS option (CONTRACT §6.1), so this bench can additionally
  exercise `p3-mtls` where the other SDK benches cannot (see
  `../HARNESS-SPEC.md` "Security-profile limitation"). Unset by default; the
  bench runs fine against p0/p1/p2 without them.
- On setup failure (server down / bad creds / MFA-enabled bench user /
  missing seed grant / non-UUID `BENCH_RESOURCE_ID`) it emits a zeroed
  `status: "error"` record and exits 0.
- `run.sh` configures + builds into `./build` (gitignored) and execs
  `./build/axiam-bench`; if `cmake` is missing or the configure/build step
  fails (e.g. the sibling SDK checkout isn't present, or `libcurl`/`openssl`
  dev headers aren't installed — `apt-get install -y libcurl4-openssl-dev
  libssl-dev`), it falls back to a `status: "pending"` record instead of
  failing the whole run.

## Run
```
cd benchmarks && just sdk=cpp sdk-bench
```
`BENCH_RESOURCE_ID` must be a valid UUID (the AXIAM authz endpoints reject
non-UUID resource ids).
