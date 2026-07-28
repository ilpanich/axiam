# B2 endgame — convict or acquit HTTP/2 (plan task G8)

**Status:** source analysis complete; conviction cell pending laptop hardware.
**Date:** 2026-07-26.
**Scope:** `crates/axiam-server/src/tls.rs`, `crates/axiam-server/src/main.rs`,
`docs/security-profiles.md`.
**Companion:** `benchmarks/PRIVATE_BENCH_ANALYSIS.md` §4.3,
`benchmarks/run-improvement-tasks.sh` task `g8-tls-h1`.

This is the last open hypothesis on B2. Two rounds of fixes (TLS 1.3 session
resumption; the p2 overlay rework) did not move the number, and the remaining
candidate is the transport itself. This document records **what the source
proves without any hardware**, the **exact laptop protocol** to settle it, and
the **honest framing answer** the plan asks for.

---

## 0. The measurement being explained

From run 3 (median-of-3), p2-tls13 vs p0-plaintext, native overlay:

| scenario | Δ throughput at p2 |
|---|---|
| `oauth2_client_credentials` | **−50.5%** (903 vs 1823 req/s) |
| `oauth2_introspect` | −0.2% |
| `userinfo` | −3.7% |
| login | ~0% |
| authz checks | positive |

Two properties of the degraded cells matter more than the headline number:

1. `http_req_tls_handshaking ≈ 0` — session resumption works; **TLS crypto is
   not the cost.** Whatever this is, it is not handshakes.
2. Server CPU, DB CPU and throughput all halve **in lockstep** while p50
   **exactly doubles**. A server that is *working harder* shows rising CPU; a
   server whose CPU falls with its throughput is *not being given work*. That
   is a concurrency ceiling upstream of the handlers, not a cost inside them.

Do not re-derive these numbers here — they come from the benchmark record.

---

## 1. What the source proves (no hardware required)

Versions pinned by `Cargo.lock`: actix-web **4.14.0**, actix-http **3.13.1**,
actix-server **2.6.0**, actix-rt **2.11.0**, rustls **0.23.42**, h2 **0.4.15**.

### 1.1 The `AXIAM__SERVER__TLS__HTTP2=false` knob was a no-op — proven, now fixed

The knob narrowed the rustls `ServerConfig`'s ALPN list to `http/1.1`, logged a
warning, and then served h2 anyway. The chain:

| step | file:line | what it does |
|---|---|---|
| `HttpServer::bind_rustls_0_23` | actix-web-4.14.0 `src/server.rs:587` | → `listen_rustls_0_23_inner` |
| `listen_rustls_0_23_inner` | actix-web-4.14.0 `src/server.rs:1006` | ends in `.rustls_0_23_with_config(config, acceptor_config)` |
| `HttpService::rustls_0_23_with_config` | actix-http-3.13.1 `src/service.rs:735` | **unconditionally prepends h2** |
| ALPN selection | rustls-0.23.42 `src/server/hs.rs:99-108` | picks by **server** preference order |

The prepend, verbatim (actix-http-3.13.1 `src/service.rs:747-749`):

```rust
let mut protos = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
protos.extend_from_slice(&config.alpn_protocols);
config.alpn_protocols = protos;
```

Our list is **appended**, so `h2` is always at index 0. rustls then selects with
`our_protocols.iter().find(|ours| their_protocols.contains(ours))` — first
server-listed match wins — so any client offering h2 gets h2, whatever we
configured. Every actix TLS bind carries the same prepend and documents it
("ALPN protocols "h2" and "http/1.1" are added to any configured ones",
`src/server.rs:585`, `:604`, `:995`, …), including the OpenSSL and
rustls 0.20/0.21/0.22 variants.

It cannot be compiled out either: actix-web's `rustls-0_23` feature **implies**
`http2` (`rustls-0_23 = ["__tls", "http2", ...]` in actix-web-4.14.0
`Cargo.toml`), and the prepending module is gated on `rustls-0_23` alone, not
on `http2`.

**Verdict: the knob was, definitively, a no-op on this bind.**

**What changed (this task):** `build_rustls_server_config` now **fails fast**
with `io::ErrorKind::Unsupported` when `server.tls.http2 = false`, before any
cert/key IO. The misleading `tracing::warn!` in `main.rs` is gone. Rationale: a
config key that silently does the opposite of what it says is worse than no key
— and in a benchmark context it is actively dangerous, because it can
manufacture a fake "h1 cell" and a false conviction. Refusing to boot is the
same doctrine this module already applies to every other misconfiguration
(missing cert, unreadable CA bundle, mismatched keypair).

The `http2` field itself lives in `crates/axiam-api-rest/src/config/mod.rs`,
which is outside this task's file ownership, so it was not deleted. If it is
ever removed, delete `reject_unsupported_http2_knob` with it.

**The only two ways to get a genuinely http/1.1-only TLS 1.3 endpoint:**

1. Front the plaintext bind with an edge that does not enable HTTP/2 —
   `benchmarks/targets/axiam/tls/tls13-h1.conf`. This is what the G8 conviction
   cell uses and it is the supported answer.
2. Abandon `actix_web::HttpServer` for that bind and drive
   `actix_http::H1Service::rustls_0_23` (actix-http-3.13.1
   `src/h1/service.rs:371`) on an `actix_server::Server` directly — it is the
   one rustls service factory in the tree that never touches
   `alpn_protocols`. **Not done, deliberately:** it means duplicating the
   entire `App` factory and the `HttpServer` plumbing (keep-alive, timeouts,
   `on_connect`, `AppConfig`, worker wiring) for a knob that is a diagnostic
   convenience, not a security control, and whose usefulness is unproven until
   the cell below runs. Revisit only if h2 is convicted *and* the documented
   position turns out to be unacceptable.

### 1.2 One HTTP/2 connection is served by exactly one core — proven

This is the mechanism that would make the h2 hypothesis true, and it is
verifiable from source:

1. **A TCP connection is pinned to one worker for its lifetime.** actix-server
   round-robins each accepted socket: `&self.handles[self.next]` then
   `self.next = (self.next + 1) % self.handles.len()`
   (actix-server-2.6.0 `src/accept.rs:432-438`).
2. **Each worker is a single-threaded runtime.** Worker count defaults to
   `available_parallelism()` (actix-server-2.6.0 `src/builder.rs:61`), and each
   runs its own current-thread tokio runtime.
3. **Every h2 stream is spawned onto that worker's local set.** The h2
   dispatcher does `actix_rt::spawn(...)` per request
   (actix-http-3.13.1 `src/h2/dispatcher.rs:134-135`), and `actix_rt::spawn` is
   `tokio::task::spawn_local` (actix-rt-2.11.0 `src/lib.rs:209-215`).

⇒ **N concurrent streams on one h2 connection execute on one thread.** HTTP/2
multiplexing buys ordering and header compression here, not parallelism.
HTTP/1.1 with a per-VU connection pool spreads across every worker.

### 1.3 The arithmetic matches the measurement suspiciously well

`benchmarks/targets/axiam/docker-compose.yml:33` limits the AXIAM container to
`cpus: ${BENCH_CPUS:-2}` — **two** CPUs, hence **two** actix workers.

Collapsing 50 VUs from *many* connections onto *one* h2 connection means going
from 2 usable cores to 1. That predicts, at saturation: throughput ×½, p50 ×2,
server CPU ×½ — which is exactly the observed signature. This is the single
strongest circumstantial argument for conviction, and it is *why* it must be
tested rather than assumed: a factor of two is also what a dozen other things
produce.

### 1.4 A stream-concurrency cap is **not** the cause — proven

actix-http never sets `SETTINGS_MAX_CONCURRENT_STREAMS`. Its h2 handshake
builder sets only the two windows (actix-http-3.13.1 `src/h2/mod.rs:60-71`):

```rust
let mut builder = Builder::new();
builder
    .initial_window_size(config.h2_initial_window_size())
    .initial_connection_window_size(config.h2_initial_connection_window_size());
```

`h2::server::Builder::max_concurrent_streams` exists (h2-0.4.15
`src/server.rs:858`) but is unreachable from actix, and `h2::frame::Settings`
derives `Default` (i.e. `max_concurrent_streams: None`), so the server
advertises **no** stream limit at all.

Two consequences:

- The ceiling is **not** a stream cap. Do not go looking for one.
- Because the server advertises no limit, a client is **never forced** to open
  a second connection. Go's `http2.Transport` (k6's client) only dials another
  connection when the current one cannot accept a new stream; with no
  advertised limit it assumes a large default and keeps one connection. The
  server therefore has **no lever at all** over how many h2 connections it is
  given. That is the crux of the whole problem.

### 1.5 What actix *does* expose, and what was wired up

Only two h2 settings exist on `actix_web::HttpServer`, and both are honoured on
the rustls bind (`src/server.rs:317`, `:329` setters; `:1041-1048` forwarding
inside `listen_rustls_0_23_inner`):

| new env var | actix setter | unset ⇒ |
|---|---|---|
| `AXIAM__SERVER__H2__INITIAL_STREAM_WINDOW_SIZE` | `h2_initial_window_size` | 1 MiB (`DEFAULT_H2_STREAM_WINDOW_SIZE`, actix-http `src/config.rs:19`) |
| `AXIAM__SERVER__H2__INITIAL_CONNECTION_WINDOW_SIZE` | `h2_initial_connection_window_size` | 2 MiB (`DEFAULT_H2_CONN_WINDOW_SIZE`, actix-http `src/config.rs:14`) |

Implemented as `axiam_server::tls::Http2Tuning`, loaded from the same sources
and with the same `AXIAM__…__…` idiom as `AppConfig` (`config/default.toml` +
`AXIAM__*` env, `__` separator). Both fields are `Option`; **unset means the
actix setter is never called**, so a default deployment is behaviourally
identical to before this change. Values outside `1 ..= 2^31-1` are rejected at
startup (RFC 9113 §6.5.2; `h2::server::Builder` would otherwise `assert!` inside
a worker at first handshake). Keep-alive was not exposed: it is shared by h1 and
h2, does not bear on a multiplexed-connection ceiling (the connection stays open
either way), and changing it would move p0 and p2 alike — it is not a B2 lever.

**Prediction, recorded before measurement:** window tuning will not move this
number. Flow-control windows only throttle when in-flight bytes exceed the
window; token-endpoint requests and responses are ~1 KB, three orders of
magnitude below the 1 MiB default. The knobs exist so the hypothesis can be
*falsified cheaply*, not because it is believed.

---

## 2. The laptop protocol

No live stack, Docker or k6 exists in the development sandbox. Everything below
runs on the maintainer's laptop.

### 2.1 The conviction cell (already scripted)

```bash
cd benchmarks && ./run-improvement-tasks.sh g8-tls-h1
```

Three cells of the same operation — `p0-plaintext`, `p2-native`, `p2-h1` (the
`tls13-h1.conf` edge) — each preceded by a **warm-up cell**, because the missing
warm-up is what invalidated run 3's conviction attempt. Output lands in
`benchmarks/results/tasks/g8-tls-h1/SUMMARY.md`.

**Decision rule (pre-committed, do not renegotiate after seeing the numbers):**

> **p2-h1 throughput within ~15% of p0 ⇒ HTTP/2 is CONVICTED.**
> **p2-h1 also ≈ −50% ⇒ HTTP/2 is ACQUITTED**, and the investigation moves to
> per-request server-side timing at p2 vs p0 (span around TLS read/write vs
> handler), per plan G8 step 2.

**Validity guard:** the summary's negotiated-protocol column for the `p2-h1`
cell must **not** read `2`. If it does, the edge is speaking h2 and the cell is
void — fix the edge, do not interpret the number. (Note that
`AXIAM__SERVER__TLS__HTTP2=false` can no longer be used to fake this cell: the
server now refuses to start. That is intentional.)

### 2.2 Two direct observations worth more than the throughput table

The table infers the mechanism. These two observe it, and take about a minute
each. Run them **during** the measured window of the `p2-native` CC cell and
again during `p0-plaintext`.

**(a) Count the connections.** This is the single decisive datum, because the
entire hypothesis is "50 VUs collapse onto one connection":

```bash
docker exec <axiam-container> sh -c \
  "ss -tn state established '( sport = :8090 )' | wc -l"
```

*If h2 is guilty:* p2-native ≈ 1–2; p0 ≈ 50; p2-h1 ≈ 50.
*If those are all ≈ 50,* the collapse never happened and h2 is acquitted
regardless of what the throughput table says.

**(b) Watch the worker threads.** This observes §1.2 directly:

```bash
docker exec <axiam-container> top -H -b -n 3 -p 1 | grep -i actix
```

*If h2 is guilty:* at p2-native exactly **one** worker thread sits near 100% and
the other is idle; at p0 **both** are near 100%.

**(c) Cheap corroborating control.** Re-run the `p0-plaintext` CC cell with
`BENCH_CPUS=1`. If the ceiling really is "one core", single-CPU p0 should land
at roughly the p2-native throughput measured with `BENCH_CPUS=2`. A clean match
is very hard to explain any other way.

### 2.3 The tuning matrix, if convicted

Four cells, CC only, `p2-tls13` native overlay, each after a warm-up. Set the
env vars on the AXIAM service in the native-TLS compose overlay.

| cell | `…H2__INITIAL_STREAM_WINDOW_SIZE` | `…H2__INITIAL_CONNECTION_WINDOW_SIZE` | prediction |
|---|---|---|---|
| baseline | unset (1 MiB) | unset (2 MiB) | reference |
| A — smaller | `262144` | `1048576` | no change |
| B — larger | `4194304` | `16777216` | no change |
| C — RFC default | `65535` | `65535` | no change, or slightly worse |

**Stopping rule:** if no cell moves throughput by more than ~5%, flow control is
exonerated and the tuning avenue is closed — publish the documented position.
If some cell *does* move it materially, the flow-control hypothesis is live and
worth a proper sweep (and §1.4's reasoning needs revisiting).

There is deliberately **no** `max_concurrent_streams` cell: actix cannot set it
(§1.4), and a knob that cannot reach the library is exactly the failure mode
this task was created to remove.

### 2.4 If convicted, what would actually fix it

None of these is an AXIAM config knob, which is itself the finding:

1. **Client-side pooling** (the realistic answer). Real SDK and mesh clients
   should hold more than one h2 connection per AXIAM replica, or cap streams
   per connection. This is a documentation and SDK-defaults matter, not a
   server change.
2. **Spread connections across replicas.** More CPU per replica helps only when
   connections ≥ workers; a second replica behind an LB helps immediately.
3. **Upstream ask (small, concrete, worth filing).** If actix-http advertised
   `SETTINGS_MAX_CONCURRENT_STREAMS`, well-behaved clients would open
   additional connections on their own and the ceiling would dissolve without
   any client change. `h2::server::Builder::max_concurrent_streams` already
   exists (h2-0.4.15 `src/server.rs:858`); actix-http simply never calls it and
   exposes no setter. That is a genuinely small upstream patch.
4. **Local last resort:** the `H1Service` rewrite of §1.1(2), which trades h2
   away entirely for that bind. Only if 1–3 all fail and the loss is judged
   unacceptable.

---

## 3. The honest framing question: artifact or production concern?

The plan asks whether this is a **benchmark-topology artifact** (one client
host, so h2 collapses 50 VUs onto one connection, while real clients pool) or a
**real production concern**. This determines whether G8 is a fix or a
documentation item.

**Answer: predominantly a benchmark-topology artifact, with a real but narrow
and bounded production caveat. It is a documentation item, not a code fix.**

### 3.1 The case that it is an artifact

- **The effect size is manufactured by the harness.** The −50% is not a
  property of h2; it is `2 workers → 1 worker` on a container capped at
  `BENCH_CPUS=2`. On an 8-vCPU deployment the same collapse would cost 7/8, not
  1/2. The benchmark's headline number therefore measures neither the true
  best case nor the true worst case — it measures the container's CPU quota.
- **One client host is the whole premise.** k6 runs as one process against one
  server process. Real AXIAM traffic is many independent services, each with
  its own connection pool to a load-balanced set of replicas. The pathological
  case — *all* concurrency behind *one* connection to *one* replica — is
  essentially a property of running the load generator this way.
- **The selective damage argues against a blanket transport tax.** Introspection
  (−0.2%), userinfo (−3.7%) and login (~0%) run over the identical transport
  with the identical VU count from the identical `lib/config.js`. A transport
  that halves everything would have halved them too. The reconciliation is that
  `client_credentials` at 1823 req/s is by a wide margin the highest-throughput
  scenario and the only one plausibly CPU-saturated at p0 — a per-core ceiling
  only bites when you are already at the ceiling. That is coherent, but note
  what it implies: **the degradation appears only in the one cell where the
  benchmark's own CPU cap is the binding constraint.** That is close to a
  definition of a topology artifact.

### 3.2 The case that it is real

- **§1.2 is a genuine property of the shipped server**, not of the harness. One
  h2 connection *is* served by one core, in production, always.
- **The pathological topology is plausible for an IAM.** An API gateway, a mesh
  sidecar, or a batch job that hammers `/oauth2/token` from a single process
  with a single pooled h2 connection is a realistic deployment, and token
  issuance is exactly the endpoint such a component hammers.
- **AXIAM cannot defend itself.** Per §1.4 the server advertises no stream
  limit, so it has no way to induce a client to open more connections. The
  mitigation lives entirely on the client side or in the topology.

### 3.3 Why the balance lands on "document, don't fix"

The production risk is real but *conditional on a topology the operator
controls*, and AXIAM has **no code lever** to change it — the two exposed h2
knobs cannot touch thread affinity (§1.5), the ALPN knob is unimplementable
(§1.1), and the only genuine server-side fix is upstream in actix-http (§2.4.3).
Shipping a config knob that cannot affect the outcome would repeat exactly the
mistake this task was created to correct.

So the deliverable is: an accurate `docs/security-profiles.md` note telling
operators to spread high-volume token traffic across connections and replicas
and not to expect one h2 connection to saturate a multi-core instance; a
tuning surface that exists so the flow-control hypothesis can be falsified; a
knob that now fails loudly instead of lying; and an upstream issue for
`max_concurrent_streams`.

**This holds under conviction. Under acquittal §3 is moot** — the cause is
elsewhere and this document's §1 survives only as the reference on why the h2
knob is gone. Either way TLS crypto is already exonerated by
`http_req_tls_handshaking ≈ 0`.

---

## 4. Change log for this task

| file | change |
|---|---|
| `crates/axiam-server/src/tls.rs` | `http2=false` now a hard startup error (`ErrorKind::Unsupported`), with the full source citation; `alpn_protocols()` is now a fixed `h2, http/1.1` list; new `Http2Tuning` config (two window knobs, `Option`-defaulted, validated); 8 new/updated unit tests |
| `crates/axiam-server/src/main.rs` | applies `Http2Tuning` to the `HttpServer` builder before bind; removed the misleading `http2=false` warning; startup log now reports actual ALPN and effective h2 windows |
| `docs/security-profiles.md` | ALPN section rewritten to the proven position; new HTTP/2 tuning + concurrency-ceiling section |
| `claude_dev/b2-tls-h2-investigation.md` | this document |

Verified locally: `cargo check -p axiam-server --no-default-features` clean;
`cargo test -p axiam-server --no-default-features --lib` → 28 passed, 0 failed;
`cargo fmt -p axiam-server -- --check` clean; `cargo clippy -p axiam-server
--no-default-features --lib --all-targets` clean. (`--no-default-features`
because the sandbox has no system libxml2 for the `saml` feature — the crate
documents this fallback in its own `Cargo.toml`. The changed code is outside
every `#[cfg(feature = "saml")]` block.)

**No benchmark numbers in this document were produced here.** Everything in §0
is quoted from the existing run-3 record; §2 is a protocol, and its
"predictions" are labelled as such.
