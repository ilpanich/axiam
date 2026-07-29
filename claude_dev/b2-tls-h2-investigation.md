# B2 — is TLS (or HTTP/2) the token-issuance penalty?

**Status: CLOSED as originally framed. HTTP/2 is ACQUITTED; TLS is priced.**
What is left is one narrow, precisely specified follow-up that cannot be run on
the H6 host — see §6.

**Dates.** §1 source analysis 2026-07-26 (task G8). §§0, 2-6 rewritten
2026-07-29 from live measurement (task **H6**, branch
`claude/g-benchmark-improvements-n5mjmj`), against
`ghcr.io/ilpanich/axiam/server:1.0.0-alpha19` + `surrealdb/surrealdb:v3`,
server and datastore capped at 2 CPU / 1 GiB, nginx edge at 2 CPU, rate limits
`neutralized`, 4-core host. Reproduce with
`benchmarks/run-improvement-tasks.sh h6-tls-proto`; raw cells under
`benchmarks/results/tasks/h6-tls-proto/`.

**Companions.** `claude_dev/postseed-transient-investigation.md` (H2 — the
shared rate-limit write; it reframes this whole question),
`benchmarks/PRIVATE_BENCH_ANALYSIS.md` §1/§4.3,
`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §5.

---

## 0. The claim being tested

From the 2026-07-19 benchmark matrix (median-of-3, "the G box" — a different,
roughly 5× faster machine than the H6 host), p2-tls13 native vs p0-plaintext:

| scenario | thr p0 | thr p2 | Δ |
|---|---:|---:|---:|
| `oauth2_client_credentials` | 1 823 | 903 | **−50.5%** |
| `token_introspection` | 2 230 | 2 225 | −0.2% |
| `jwks_fetch` | 27 784 | 24 309 | −12.5% |
| `userinfo` | 5 008 | 4 822 | −3.7% |
| `oauth2_password_login` | 69 | 69 | −0.5% |
| `authz_check_rest` | 737 | 747 | +1.3% |

and, from the G8 task session, `token_refresh`: p0 914, p2-native 893
(**−2.3%**), p2-h1 (nginx) 443 (−51%, with **1 059 failed ops**).

The published claim was *"TLS 1.3 still halves token issuance"*, with HTTP/2
single-connection multiplexing as the leading explanation. **Both halves of
that claim are wrong**, for different reasons, and this note gives the
measurements.

---

## 1. What the source proves (no hardware required) — unchanged from G8

Versions pinned by `Cargo.lock`: actix-web **4.14.0**, actix-http **3.13.1**,
actix-server **2.6.0**, actix-rt **2.11.0**, rustls **0.23.42**, h2 **0.4.15**.

### 1.1 `AXIAM__SERVER__TLS__HTTP2=false` was a no-op — proven, now a hard error

The knob narrowed the rustls `ServerConfig`'s ALPN list to `http/1.1`, logged a
warning, and then served h2 anyway:

| step | file:line | what it does |
|---|---|---|
| `HttpServer::bind_rustls_0_23` | actix-web-4.14.0 `src/server.rs:587` | → `listen_rustls_0_23_inner` |
| `listen_rustls_0_23_inner` | actix-web-4.14.0 `src/server.rs:1006` | ends in `.rustls_0_23_with_config(config, acceptor_config)` |
| `HttpService::rustls_0_23_with_config` | actix-http-3.13.1 `src/service.rs:735` | **unconditionally prepends h2** |
| ALPN selection | rustls-0.23.42 `src/server/hs.rs:99-108` | picks by **server** preference order |

```rust
let mut protos = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
protos.extend_from_slice(&config.alpn_protocols);
config.alpn_protocols = protos;
```

Our list is *appended*, so `h2` is always at index 0 and wins for any client
that offers it. It cannot be compiled out either: actix-web's `rustls-0_23`
feature implies `http2`, and the prepending module is gated on `rustls-0_23`
alone. **`build_rustls_server_config` now fails fast** with
`io::ErrorKind::Unsupported` when `server.tls.http2 = false`. A config key that
silently does the opposite of what it says is worse than no key — and in a
benchmark it can manufacture a fake "h1 cell" and a false conviction.

The only two ways to get a genuinely http/1.1-only TLS 1.3 endpoint remain:
(1) an edge that does not enable HTTP/2
(`benchmarks/targets/axiam/tls/tls13-h1.conf`), or (2) abandoning
`actix_web::HttpServer` for that bind in favour of a hand-built
`actix_http::H1Service::rustls_0_23`. (2) is still deliberately not done, and
§4 now says it never should be.

### 1.2 One HTTP/2 connection is served by exactly one core — still true

1. actix-server round-robins each accepted socket to a worker and it stays
   there for the connection's life (`src/accept.rs:432-438`).
2. Each worker is a single-threaded runtime; worker count defaults to
   `available_parallelism()` (`src/builder.rs:61`).
3. Every h2 stream is `actix_rt::spawn`ed onto *that* worker's local set
   (actix-http `src/h2/dispatcher.rs:134-135`; `actix_rt::spawn` is
   `tokio::task::spawn_local`).

⇒ N concurrent streams on **one** h2 connection execute on **one** thread.
This is a real property of the shipped server and §4 keeps it as operator
guidance. What §2.1 kills is not this fact but the assumption that the
benchmark ever produced the "one connection" precondition.

### 1.3 A stream-concurrency cap is not the cause — still true

actix-http never sets `SETTINGS_MAX_CONCURRENT_STREAMS`; its h2 handshake
builder sets only the two windows (`src/h2/mod.rs:60-71`), and
`h2::server::Builder::max_concurrent_streams` (h2-0.4.15 `src/server.rs:858`)
is unreachable from actix. So the server advertises **no** stream limit — it
has no lever over how many connections a client gives it. The two window knobs
that *are* exposed (`AXIAM__SERVER__H2__INITIAL_{STREAM,CONNECTION}_WINDOW_SIZE`,
implemented as `axiam_server::tls::Http2Tuning`) remain available to falsify a
flow-control hypothesis cheaply; §3 shows there is now nothing left for them to
explain.

---

## 2. What H6 measured

Two things made every previous attempt unable to answer this, and both are
fixed on this branch before any number below was taken.

**(a) Nobody knew what protocol the cells ran.** G8's summary tried to recover
the negotiated protocol from k6's `http_version` tag on `http_req_duration`;
k6 does not emit that tag into the summary unless the metric is explicitly
tagged, so the column read `?` for every cell and the conviction rested on
which conf file we believed nginx had loaded. `scenarios/lib/metrics.js` now
records **`bench_http_proto`** from k6's `res.proto` on every response, and
`report.py` renders it as an `http` column (and refuses to let a security-cost
table pass silently when its rows did not all use the same protocol). Every
number below carries its measured protocol.

**(b) The vehicle was an endpoint that cannot measure a transport.**
`POST /oauth2/token` is one of the six `RateLimitShared`-wrapped endpoints: it
performs one synchronous SurrealDB `UPSERT` of `rate_limit_bucket:<ep>:<ip>`
before the handler runs (H2 §2). On the H6 host that write costs ~40-50 ms and
pins the endpoint at ~20 ops/s **at any concurrency**. A transport cost of a
few hundred microseconds per request is not observable under a 50 ms floor.
H6 therefore uses `GET /oauth2/jwks` and `GET /oauth2/userinfo`, which are not
wrapped and run 2-3 orders of magnitude faster. This is not a workaround; it is
the only way to see a transport cost on this host at all — and §2.4 shows the
clamp live rather than asserting it.

### 2.1 The premise of the whole h2 hypothesis is false (the decisive datum)

`benchmarks/runner/h6-connection-probe.sh` counts ESTABLISHED sockets on the
server's own listener, from the server's network namespace, and reads per-thread
CPU of the two `actix-server wo` workers.

| listener | negotiated | VUs | established connections | worker CPU A / B (cores) |
|---|---|---:|---:|---|
| p0 plaintext `:8090` | HTTP/1.1 | 10 | 10 | — |
| p0 plaintext `:8090` | HTTP/1.1 | 50 | 50 | — |
| p0 plaintext `:8090` | HTTP/1.1 | 100 | 100 | 0.195 / 0.192 |
| p2 native rustls `:8090` | **HTTP/2** | 10 | **10** | 0.225 / 0.221 |
| p2 native rustls `:8090` | **HTTP/2** | 50 | **50** | 0.240 / 0.237 |
| p2 native rustls `:8090` | **HTTP/2** | 100 | **100** | 0.240 / 0.239 |

**k6 does not multiplex its VUs onto one h2 connection.** Each VU owns its own
HTTP transport, so the connection count tracks the VU count exactly, h2 or not,
and **both actix workers are within ~2% of each other at every level**. The
"50 VUs collapse onto one connection ⇒ 2 workers become 1 ⇒ throughput ×½,
p50 ×2" chain never had its first link. The fact that ×½ was *exactly* what the
G-box `client_credentials` cell showed was a coincidence, and §1.3 of the
previous version of this document called that coincidence "the single strongest
circumstantial argument for conviction". It was not evidence.

The G run's own published numbers already contained this refutation and it was
missed: `jwks_fetch` at p2 (h2, TLS) used **1.97 CPU cores** — more than one —
while running at 24 309 req/s. A workload confined to one worker cannot burn
two cores.

<!--H6-TABLES-->

---

## 6. What is still open (one measurable follow-up, for E3)

<!--H6-OPEN-->
