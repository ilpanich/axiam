# SDK Benchmark Harness Specification

The protocol-level scenarios (`benchmarks/scenarios/`) measure the **server**. The
SDK harness measures the **client**: how much latency/CPU each official AXIAM SDK
adds on top of the raw wire calls, so users can pick an SDK knowing its overhead.

All 7 SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go — the `ilpanich/axiam-<lang>-sdk`
repositories) are implemented and conform to `sdks/CONTRACT.md`, and **all seven
bench directories are now wired** against their real SDK (`python/`, `typescript/`,
`rust/`, `go/`, `java/`, `csharp/`, `php/`). Each emits an `ok` record when its
SDK package/toolchain is installed and a seeded target is reachable, and degrades
to a `pending` (toolchain/package missing) or `error` (server unreachable / grant
missing) record otherwise. The compiled-language benches depend on their SDK via a
local path/replace/project reference (see each `sdk/<lang>/TODO.md`) so they build
against the sibling `axiam-<lang>-sdk` checkout when the package is not yet on the
public registry.

## What each SDK bench must do

Exercise the canonical SDK operations locked in `sdks/CONTRACT.md` §1, **through
the SDK** (not raw HTTP):

| op key         | SDK call it should make (canonical name, per-language spelling in CONTRACT.md §1) |
|-----------------|-------------------------------------------------------------------------------|
| `login`         | `login(email, password)` — `POST /api/v1/auth/login`                          |
| `refresh`       | `refresh()` — `POST /api/v1/auth/refresh`                                     |
| `check_access`  | `check_access(action, resource_id[, scope])` (or its `can` alias)             |
| `batch_check`   | `batch_check(checks)` — results in input order                                |

For each op: run a warm-up, then N timed iterations against a running, seeded
target (default AXIAM at `$BENCH_HOST:$BENCH_PORT`), and record per-op latency.

**Measure `refresh` serially (concurrency 1).** Every SDK guards `refresh()` with
a single-flight lock, so under `SDK_BENCH_CONCURRENCY` concurrent callers N
refreshes coalesce into ~1 wire call — concurrent refresh throughput would not
reflect wire cost. The reference harnesses (and all wired benches) run `login`,
`check_access` and `batch_check` at `SDK_BENCH_CONCURRENCY` but `refresh` at
concurrency 1. `refresh()` also requires a prior successful `login()` on the same
client instance.

**Out of SDK-harness scope.** `oauth2_token` (client-credentials grant),
`introspect`, and the REST `userinfo` are real AXIAM server endpoints
(`/oauth2/token`, `/oauth2/introspect`, `/oauth2/userinfo`) and are measured at
the protocol level by the k6 scenarios (`scenarios/oauth2_client_credentials.js`,
`scenarios/token_introspection.js`, `scenarios/userinfo.js`). No SDK wraps the
REST endpoints by contract — CONTRACT.md §1 does not expose `oauth2_token` /
`introspect` / a REST `userinfo` as SDK methods — so there is no SDK client call
to time for those three ops. Do not add them to an SDK bench's `ops`.

**`get_user_info` (gRPC-only, optional).** CONTRACT.md §1.1 (contract 1.3) adds a
canonical gRPC-only operation `get_user_info` (`axiam.v1.UserInfoService/GetUserInfo`).
It IS a real SDK method — but only in SDKs that ship a gRPC transport (Rust,
TypeScript, Python, Java, C#, PHP, Go). A gRPC-capable SDK bench MAY add a
`get_user_info` op: run a warm-up then N timed iterations at `SDK_BENCH_CONCURRENCY`
after a successful `login()` (the op needs the login's access token), against a
target reachable at `BENCH_GRPC_ADDR`, recording per-op latency like the other ops.
A REST-only SDK bench (Kotlin, Swift, C, C++) MUST NOT add it and should emit a
`pending` record with reason `grpc-not-supported` if asked. This op is distinct
from the protocol-level k6 `userinfo_grpc.js` scenario, which measures the server.

## Inputs (environment)

The same env the server harness uses, so `runner/*.sh` can drive both:

```
BENCH_TARGET, BENCH_SCHEME, BENCH_HOST, BENCH_PORT, BENCH_GRPC_ADDR
BENCH_TENANT_ID, BENCH_TENANT_SLUG, BENCH_ORG_ID, BENCH_ORG_SLUG, BENCH_CLIENT_ID, BENCH_CLIENT_SECRET, BENCH_USERNAME, BENCH_PASSWORD
BENCH_ACTION          (default "read")      # action for check_access/batch_check
BENCH_RESOURCE_ID     (seeded resource UUID) # subject of the authz checks
BENCH_SUBJECT_ID      (seeded user UUID)      # the bench user's id
BENCH_CA_CERT         # custom CA for server verification under TLS profiles
BENCH_CLIENT_CERT     # PEM client-certificate chain, p3-mtls only (CONTRACT.md §6.1)
BENCH_CLIENT_KEY      # its PEM private key,          p3-mtls only (CONTRACT.md §6.1)
SDK_BENCH_ITERATIONS  (default 2000)
SDK_BENCH_WARMUP      (default 200)
SDK_BENCH_CONCURRENCY (default 16)
```

### TLS inputs

All three TLS inputs are **file PATHS**, not inline PEM. Several SDKs' APIs
want PEM *content* (`AxiamClient(client_cert=…)` in Python, `clientCert` in
TypeScript, `WithClientCertificate([]byte, []byte)` in Go, …) — reading the
file is the bench's job, not the operator's.

`BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY` are **all-or-nothing**: a bench given
exactly one of the two MUST emit a `status:"error"` record naming *both*
variables (CONTRACT.md §6.1 rule 1) rather than crash or silently continue
without an identity. Both unset (p0/p1/p2) leaves the SDK's default
bearer-cookie behaviour untouched (§6.1 rule 5 — mTLS is opt-in).

Every client a bench constructs must carry the identity — including the fresh,
throwaway client the `login` op builds per iteration. A bench that configures
only its long-lived client passes three ops and fails `login` at the handshake,
which reads like a server problem rather than a harness one.

Wired in **all eleven** languages: c, cpp, csharp, go, java, kotlin, php,
python, rust, swift, typescript.

`sdk/test-client-cert-wiring.sh` proves this end-to-end without a live AXIAM
stack: it runs each bench against a stub HTTPS server that requires a client
certificate and asserts the server observed `CN=bench-client` on the wire.

#### Example: a p3-mtls SDK pass

`bench-up`/`bench-seed`/`sdk-bench-all` all take `profile=`, and the recipes
source `profiles/p3-mtls.env`, which is what sets the three TLS paths — there
is nothing to export by hand:

```bash
R=$PWD/results/p3-sdk
BENCH_RESULTS_DIR=$R just target=axiam profile=p3-mtls bench-up bench-seed
BENCH_RESULTS_DIR=$R BENCH_VUS=16 just target=axiam profile=p3-mtls bench-run
BENCH_RESULTS_DIR=$R SDK_BENCH_CONCURRENCY=16 \
  just target=axiam profile=p3-mtls sdk-bench-all      # -> $R/sdk/p3-mtls/
```

One language only, same wiring:

```bash
just target=axiam profile=p3-mtls sdk=rust sdk-bench
```

Driving a bench directly (no `just`) means supplying the profile env yourself —
the paths must be **absolute** or resolvable from your cwd, since most `run.sh`
scripts `cd` into their own directory (`sdk/_tlspaths.sh` absolutises them):

```bash
set -a; . profiles/p3-mtls.env; . .seed/axiam.seed.env; set +a
BENCH_CERTS_DIR=$PWD/profiles/certs bash sdk/go/run.sh
```

SDK clients authenticate with `tenant_slug` (`BENCH_TENANT_SLUG`, default
`"default"`), not the tenant UUID — the tenant UUID (`BENCH_TENANT_ID`) is still
needed for scenarios/adapters that address the tenant by id. Login/refresh also
require organization context (CONTRACT.md §5.1): SDK benches send `org_slug`
(`BENCH_ORG_SLUG`, default `"bench-org"`); `BENCH_ORG_ID` carries the org UUID
for id-form addressing. Both are written by `runner/seed.sh`.

`BENCH_RESOURCE_ID` and `BENCH_SUBJECT_ID` are written by `runner/seed.sh`, which
provisions a resource plus a role holding a `read` permission grant assigned to
the bench user — so `check_access(read, BENCH_RESOURCE_ID)` returns `allowed=true`.
The server rejects a non-UUID `resource_id` (400), so a bench that batches checks
must reuse this UUID, not synthesize per-index ids.

**Security profiles — all four are in scope.** Every SDK now exposes both a
custom-CA option (CONTRACT.md §6) and an mTLS client-certificate option
(§6.1), and every language bench wires all three TLS inputs, so the SDK
harness runs p0 through p3 exactly as the k6 scenarios do.

Both `BENCH_CA_CERT` and the `BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY` pair are
file **paths**; several SDKs' APIs take PEM *content* instead, in which case
the bench reads the file itself. Requirements for every bench:

- Apply the TLS material at **every** client construction site. The `login` op
  builds a fresh client per iteration; a client built without the identity
  fails the p3 handshake while the shared client succeeds, which shows up as
  `login`-only errors rather than as the configuration bug it is.
- Treat a half-configured identity (cert without key, or vice versa) as a
  setup failure: emit the `status: "error"` record naming **both** env vars
  (§6.1 rule 1). Silently downgrading to an anonymous connection produces a
  handshake rejection that names nothing.
- Treat an unreadable or non-PEM path the same way, naming the env var.
- If the bench `cd`s before opening these files, absolutize them first by
  sourcing `sdk/_tlspaths.sh` — `profiles/*.env` sets them relative to the
  benchmarks root.

`sdk/test-client-cert-wiring.sh` (`just sdk-bench-test`) enforces all of this
for every language against a stub server that requires a client certificate;
it needs no AXIAM stack. Run it after touching any bench's TLS wiring.

This section previously stated the opposite — that no SDK exposed a
client-cert option and that the SDK benches therefore covered p0–p2 only. It
outlived the SDKs by long enough that a bench written to it (`sdk/c`) shipped
with no TLS wiring at all and failed every p2/p3 run.

## Output (stdout, single JSON object) — the stable contract

Each SDK bench prints exactly one JSON object matching this schema to stdout. The
aggregator (`sdk/collect.py`) reads them and folds them into the main report's
"SDK client overhead" section.

```json
{
  "schema": "axiam.sdk-bench/v1",
  "sdk": "typescript",
  "sdk_version": "0.1.0",
  "language_runtime": "node 22.3.0",
  "target": "axiam",
  "profile": "p2-tls13",
  "status": "ok",                       // "ok" | "pending" | "error"
  "iterations": 2000,
  "concurrency": 16,
  "ops": {
    "login":         { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 },
    "refresh":        { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 },
    "check_access":   { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 },
    "batch_check":    { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 }
  },
  "client_cpu_ms_total": 0,             // optional: CPU consumed by the client process
  "client_rss_mib_peak": 0,             // optional: peak client memory
  "client_worker_threads": 0,           // optional (J8b): async-runtime worker count
  "passes_requested": 3,                // written by median.py (J8)
  "passes_present": 3,
  "passes_ok": 3,
  "passes_missing": [],
  "notes": ""
}
```

Each op record MAY additionally carry `cpu_ms` (client CPU consumed during
that op's timed window) and `cpu_us_per_call` (the same divided by completed
calls). Both are optional; `collect.py` ignores them when absent.

### Attributing client CPU (J8b)

Run 5 published a single `client_cpu_ms_total` per SDK and nothing else, which
produced an observation nobody could act on: **Rust 23.4 s — highest of every
compiled SDK, 7× Go's — alongside the best latency and throughput in the
matrix.** Two things made that number unusable, and both are harness
properties rather than SDK ones:

1. **It was a function of the host.** A bench that builds its async runtime
   with one worker per CPU reports more client CPU on a 32-core box than on a
   4-core one for identical work, because idle workers spin briefly before
   parking. Every bench must size its runtime/thread pool to
   `SDK_BENCH_CONCURRENCY`, not to the machine, and publish the resulting
   count as `client_worker_threads`.
2. **It was one number for four ops.** `login` builds a fresh client per
   iteration by contract (fresh TLS material, fresh connection); the other
   three reuse a pooled one. Aggregating them hides which is expensive.
   Per-op `cpu_ms` / `cpu_us_per_call` is what makes the next observation
   actionable.

Fix the measurement before suspecting the SDK. If a figure is still an outlier
with the runtime pinned and per-op attribution in hand, the finding is real.

### Comparing against the wire baseline (J7)

`collect.py` subtracts the matching k6 scenario's p95 from the SDK's to give a
"p95 overhead vs wire" column. Run 5 published **negative** overhead for
TypeScript — check/batch p95 21–23 ms *below* the baseline measured on the
same host against the same server. A client cannot beat the wire doing the
same work, so one side was not doing the same work, and nothing in the archive
recorded enough about the baseline to say which.

The delta is now withheld unless the baseline is comparable:

- every cell's `meta.json` records `connection_model`
  (`pooled-per-vu` | `per-iteration-vu-pool` | `no-reuse`), driven by
  `BENCH_NO_CONN_REUSE` / `BENCH_NO_VU_CONN_REUSE`. Only `pooled-per-vu`
  matches how an SDK client holds connections;
- a baseline from before this field existed is treated as *not established*,
  not as fine;
- a negative delta that survives the model check is rendered with a `⚠` and a
  footnote, because the remaining asymmetry (response validation, payload
  shape, or in-flight-vs-VU concurrency accounting) has not been ruled out.

The overhead column shows `n/c` where a delta was withheld. Publishing an
SDK-vs-wire claim requires that column to carry neither `n/c` nor `⚠`.

### Median-of-N provenance (J8)

`median.py` merges `repeat=N` passes. Run 5's C# row read "median of 2"
against `repeat=3`, and nothing recorded which pass vanished or why — a pass
that produces *no record at all* is invisible to a merger that only sees the
records it received, so "2 of 2 ok" was both true and misleading.

Merged records now carry `passes_requested` / `passes_present` / `passes_ok` /
`passes_missing` (pass directory names, not counts), `median.py` exits
non-zero when any language merged fewer passes than requested, and
`sdk-bench-all` prints an `SDK_BENCH_MEDIAN_INCOMPLETE` banner. The report is
still written either way — the numbers are valid data built on fewer passes —
but the gap can no longer be scrolled past. `SDK_BENCH_ALLOW_PARTIAL=1`
accepts it deliberately.

`status: "pending"` (the current state of the five unwired scaffolds) means "SDK
bench glue not yet wired"; the report lists these as not-yet-measured rather than
failures.

## The `refresh` op must hit the wire (I9)

`refresh` is single-flight-guarded in every SDK (CONTRACT.md §9), and every
bench times it against a **shared, already-logged-in client** at concurrency
1 (see above). Run 4's C# bench recorded `refresh` p50 1.2 microseconds
("752 k rps") because Axiam.Sdk's `RefreshGuard` reuses a completed token
result whenever it is still fresh (a wall-clock check against the ~15-minute
access-token TTL, with no per-call "is this observation stale" comparison) —
so only the very first call on a shared client ever reached the wire; every
call after it was a cache hit. The Go/Python/Rust/Java/Kotlin/PHP/C SDKs'
guards instead key off the caller's *currently observed* access token, which
updates on the shared bench client after every real refresh, so a same-client
loop keeps hitting the wire on every call — that design difference, not a
harness bug, is why those SDKs' benches never showed this. The C# bench fix
(`sdk/csharp/Program.cs`, `TimeForcedRefreshOp`) builds a fresh client + login
(both untimed) on every `refresh` iteration instead of reusing the shared one,
so a brand-new `RefreshGuard` — with nothing cached — always performs the real
`POST /api/v1/auth/refresh` call; only that call is timed.

Every `sdk/<lang>` bench now also asserts, after computing the `refresh` op's
stats and after printing the JSON record (so the numbers are still on stdout
for a human to inspect even when this fires), that the measurement is
plausibly a real HTTP round trip — and **exits non-zero** if not, so a
regression of this class fails `run-all.sh` (`[sdk] $sdk FAILED`) instead of
silently publishing a fake number:

- **C** (`sdk/c/bench.c`) has the exact check: the sibling SDK exposes
  `axiam_client_refresh_count()`, an observability counter incremented once
  per real transport round trip, so the bench asserts it equals
  `warmup + iterations` exactly (this bench's ops are all serial — see
  "Running a wired SDK bench").
- The other ten benches have no such counter available without modifying
  their SDK (out of this repo's scope — the SDKs live in separate
  `axiam-<lang>-sdk` repos), so each instead asserts the op's `p50_ms` is not
  implausibly fast: `MIN_PLAUSIBLE_REFRESH_MS = 0.2` (0.2 ms), a floor picked
  to sit ~85x below the ~17 ms average genuine wire call recorded across this
  harness while still catching a cache-hit measurement in the low
  single-digit-microsecond range (the C# bug measured 0.0012 ms) outright.
  The check only fires when the op had at least one successful (non-error)
  sample, so a genuinely broken/unreachable refresh endpoint is reported as
  errors, not misdiagnosed as a cache hit.

A literal per-language HTTP-call counter (matching the C SDK's) would be the
more precise fix for the other ten, but needs either an SDK-exposed counter
(an `axiam-<lang>-sdk` change, out of scope here) or a transport-injection
seam the bench can wrap (e.g. Go's `axiam.WithHTTPClient`, OkHttp
interceptors in Java/Kotlin) wired per language — worth doing if this class
of bug recurs in a language the floor doesn't catch cleanly.

## Comparing SDK overhead to the wire baseline

For a given op + profile, the **SDK overhead** is:

```
overhead_p95_ms = sdk.ops[op].p95_ms - server_scenario.p95(op, profile)
```

`sdk/collect.py` computes this delta where a directly comparable k6 scenario
exists:
- `login` → `oauth2_password_login` (both hit `POST /api/v1/auth/login`).
- `check_access` → `authz_check_rest` and `batch_check` → `authz_batch_rest`
  (both hit `POST /api/v1/authz/check[/batch]`, the same wire path the SDKs use),
  so these deltas are now genuinely comparable. The gRPC authz scenarios
  (`authz_check_grpc.js`, `authz_batch_grpc.js`) remain a separate AXIAM
  capability metric and are NOT used for SDK-overhead deltas.
- `refresh` has no exact wire counterpart: `scenarios/token_refresh.js` exercises
  the OAuth2 `refresh_token` grant (`/oauth2/token`), while the SDK's `refresh()`
  calls the session endpoint (`/api/v1/auth/refresh`) — different wire paths, so
  no overhead delta is computed for it.

A well-built SDK adds only serialization + connection-pooling overhead (typically
sub-millisecond p95 on localhost). Large positive overhead points at a per-call
cost the SDK should amortize (e.g. re-creating TLS connections, re-parsing JWKS,
no keep-alive).

## C++ bimodal tail — root-caused and fixed upstream (I11)

Run 4 found the C++ bench's `check`/`batch` ops paying a bimodal tail (p50
~3.3 ms, excellent — but a subset of iterations at ~264–336 ms) at every
profile. The original hypothesis (`Expect: 100-continue` on POST bodies) was
**wrong**: libcurl 8.5's `Expect` threshold is 1 MiB, not 1 KiB, so this
harness' check/batch request bodies never trigger it. The actual root cause,
found and fixed in the `axiam-cplusplus-sdk` repo (not this one), was
`CURLOPT_MAXAGE_CONN` (libcurl's default is 118 s, so a worker held open
across a long bench run silently reconnects) compounding with
`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS` (default 200 ms, burned on every fresh
connection whenever AAAA resolves but IPv6 is unroutable in the target
environment) — each silent reconnect paid a ~200 ms+ Happy-Eyeballs stall on
top of the new TCP/TLS handshake.

**Run 5 should confirm** C++ p95 is within 3x p50 at p0 (the I11 acceptance
bar) now that the upstream SDK fix has landed. If a residual tail is still
observed after that fix, look at **server-side** idle timeouts or
`Connection: close` behavior next — connection *age* is no longer a credible
suspect once `CURLOPT_MAXAGE_CONN` is addressed upstream.

## Wire baseline + median-of-3 (I15)

`just sdk-bench-all` now wires the k6 wire baseline back in automatically
(improvement-after-run4-benchmark.md §D): before the SDK pass, it runs
`oauth2_password_login.js`, `authz_check_rest.js`, and `authz_batch_rest.js`
at `BENCH_VUS=$SDK_BENCH_CONCURRENCY` (default 16, matched to the SDK bench's
own concurrency — the draft-4 lesson that an unmatched-VU baseline, e.g. the
default 50-VU ramp, produces bogus, often negative, "overhead" purely from
the load-shape mismatch). Set `SDK_BENCH_SKIP_WIRE=1` to skip it (e.g. a
quick re-run when a fresh baseline already exists on disk for that
target/profile).

`just repeat=N sdk-bench-all` (default `repeat=3`, same knob/default as the
server-side matrix's C1 median-of-N) runs the SDK pass N times into
`results/sdk-run-<i>/` and medians each op's numbers across the "ok" passes
via `sdk/median.py`, writing the merged record to the usual
`results/sdk/<profile>/<lang>.json` location. `repeat=1` keeps the old
single-pass behavior.

## Running a wired SDK bench

All seven benches are wired. To run one you need its toolchain and the SDK
package resolvable:

1. Each compiled-language manifest (`Cargo.toml` / `go.mod` / `pom.xml` /
   `*.csproj` / `composer.json`) references its SDK via a local path/replace/
   project reference to the sibling `axiam-<lang>-sdk` checkout, so it builds even
   before the alpha package is published to the public registry. Swap that for the
   published package reference once available (see each `sdk/<lang>/TODO.md`).
2. `cd benchmarks && just sdk=<lang> sdk-bench` prints one `axiam.sdk-bench/v1`
   record. `just sdk-bench-all` runs every language and folds the results in.
3. The stdout JSON contract is fixed — do not add or rename fields the aggregator
   depends on (`schema`, `sdk`, `status`, `ops.*`). Op keys stay snake_case
   (`check_access`, `batch_check`) even where the SDK method is camel/Pascal-case.
4. `python/bench.py` and `typescript/bench.mjs` remain the reference
   implementations for the timing loop, percentile math, and JSON contract.
