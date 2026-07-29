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

### 2.2 The full measurement

Closed-loop VUs, 10 s warm-up + 60 s measured, after a per-stack warm-up cell.
Every row carries the protocol it actually negotiated.

**`GET /oauth2/jwks`** (not `RateLimitShared`-wrapped)

| cell | what | VUs | http | thr (ops/s) | p50 (ms) | p95 (ms) | failed ops | Δ thr vs p0 |
|---|---|---:|:--:|---:|---:|---:|---:|---:|
| p0 | direct :8090, no TLS, no edge | 10 | 1.1 | 4310 | 1.40 | 4.20 | 0 | baseline |
| p2-native | AXIAM rustls listener, in process | 10 | 2.0 | 3760 | 1.70 | 4.84 | 0 | -12.8% |
| p2-nginx-h2 | nginx edge, TLS, `http2 on` | 10 | 2.0 | 2566 | 2.77 | 7.05 | 0 | -40.5% |
| p2-nginx-h1 | nginx edge, TLS, `http2` omitted | 10 | 1.1 | 3197 | 2.18 | 5.35 | 0 | -25.8% |
| p2-nginx-h2 → plain edge | same nginx, **no TLS**, :8080 | 10 | 1.1 | 3327 | 2.14 | 5.18 | 0 | -22.8% |
| p0 | direct :8090, no TLS, no edge | 50 | 1.1 | 5166 | 6.77 | 20.86 | 0 | baseline |
| p2-native | AXIAM rustls listener, in process | 50 | 2.0 | 5045 | 7.13 | 20.44 | 0 | -2.3% |
| p2-nginx-h2 | nginx edge, TLS, `http2 on` | 50 | 2.0 | 3320 | 11.38 | 29.86 | 0 | -35.7% |
| p2-nginx-h1 | nginx edge, TLS, `http2` omitted | 50 | 1.1 | 3728 | 10.16 | 26.05 | 0 | -27.8% |
| p2-nginx-h2 → plain edge | same nginx, **no TLS**, :8080 | 50 | 1.1 | 4214 | 9.47 | 22.09 | 0 | -18.4% |
| p0 | direct :8090, no TLS, no edge | 100 | 1.1 | 5143 | 13.87 | 37.75 | 0 | baseline |
| p2-native | AXIAM rustls listener, in process | 100 | 2.0 | 5063 | 14.69 | 39.27 | 0 | -1.6% |
| p2-nginx-h2 | nginx edge, TLS, `http2 on` | 100 | 2.0 | 3667 | 20.54 | 54.84 | 0 | -28.7% |
| p2-nginx-h1 | nginx edge, TLS, `http2` omitted | 100 | 1.1 | 3764 | 19.99 | 51.57 | 0 | -26.8% |
| p2-nginx-h2 → plain edge | same nginx, **no TLS**, :8080 | 100 | 1.1 | 4437 | 17.68 | 43.06 | 0 | -13.7% |

**`GET /oauth2/userinfo`** (not `RateLimitShared`-wrapped)

| cell | what | VUs | http | thr (ops/s) | p50 (ms) | p95 (ms) | failed ops | Δ thr vs p0 |
|---|---|---:|:--:|---:|---:|---:|---:|---:|
| p0 | direct :8090, no TLS, no edge | 10 | 1.1 | 1725 | 4.48 | 9.19 | 0 | baseline |
| p2-native | AXIAM rustls listener, in process | 10 | 2.0 | 1585 | 4.88 | 10.28 | 0 | -8.1% |
| p2-nginx-h2 | nginx edge, TLS, `http2 on` | 10 | 2.0 | 1520 | 5.14 | 10.43 | 0 | -11.9% |
| p2-nginx-h1 | nginx edge, TLS, `http2` omitted | 10 | 1.1 | 1456 | 5.37 | 11.00 | 0 | -15.6% |
| p0 | direct :8090, no TLS, no edge | 50 | 1.1 | 2230 | 18.57 | 37.25 | 0 | baseline |
| p2-native | AXIAM rustls listener, in process | 50 | 2.0 | 1947 | 21.38 | 42.99 | 0 | -12.7% |
| p2-nginx-h2 | nginx edge, TLS, `http2 on` | 50 | 2.0 | 1735 | 24.26 | 47.71 | 0 | -22.2% |
| p2-nginx-h1 | nginx edge, TLS, `http2` omitted | 50 | 1.1 | 1907 | 21.88 | 43.46 | 0 | -14.5% |
| p0 | direct :8090, no TLS, no edge | 100 | 1.1 | 2316 | 36.50 | 71.06 | 0 | baseline |
| p2-native | AXIAM rustls listener, in process | 100 | 2.0 | 2118 | 40.66 | 76.29 | 0 | -8.5% |
| p2-nginx-h2 | nginx edge, TLS, `http2 on` | 100 | 2.0 | 1857 | 46.00 | 87.69 | 0 | -19.8% |
| p2-nginx-h1 | nginx edge, TLS, `http2` omitted | 100 | 1.1 | 2030 | 41.47 | 82.13 | 0 | -12.3% |

**One-variable decompositions** (jwks, the most transport-sensitive endpoint)

| comparison | isolates | 10 VUs | 50 VUs | 100 VUs |
|---|---|---:|---:|---:|
| nginx plain edge vs p0 direct | the proxy hop | -22.8% | -18.4% | -13.7% |
| nginx TLS h1 vs nginx plain | TLS at the edge | -3.9% | -11.5% | -15.2% |
| **nginx TLS h2 vs nginx TLS h1** | **h2 vs h1** | -19.7% | -11.0% | -2.6% |
| p2-native vs p0 | what the matrix publishes | -12.8% | -2.3% | -1.6% |

Caveats stated up front, because they matter for reading the absolute numbers:

* **This is a 4-core host.** The server (2 CPU), the datastore (2 CPU), the
  broker (1 CPU), the nginx edge (2 CPU) and k6 itself all contend for those
  four cores. Absolute throughput is far below the G box's (jwks 5 166 here vs
  27 784 there) and every p2 number also pays for k6's *client*-side TLS on the
  same cores. The comparisons within a VU level are still controlled — every
  cell faces the same host — but a p2 penalty measured here is an **upper**
  bound, not a typical one.
* **At 50-100 VUs the host, not AXIAM, is the binding constraint** for jwks
  (p0 flattens at ~5 150 ops/s from 50 VUs on). That is why the p2-native
  penalty *shrinks* with load rather than growing: an extra per-request cost
  only shows in throughput while there is headroom to lose.

### 2.3 What each comparison says

**HTTP/2 vs HTTP/1.1, one variable (the last two rows of the decomposition).**
Same nginx process, same TLS 1.3, same proxy hop, same keep-alive upstream,
same connection count (50 VUs ⇒ 50 edge connections under **both** protocols —
census in §2.1). The only difference is `http2 on;`. h2 costs **−19.7% / −11.0%
/ −2.6%** at 10 / 50 / 100 VUs — real at low concurrency, converging to parity
as the host saturates. This is a property of *nginx's* h2 implementation under
CPU contention, not of AXIAM, and it points the opposite way from the original
hypothesis anyway: it is h2 doing **more** work per request, not h2 starving
workers.

**AXIAM's own listener is the cheapest TLS in the table.** p2-native (rustls +
h2, in process) costs **−12.8% / −2.3% / −1.6%** on jwks and **−8.1% / −12.7%
/ −8.5%** on userinfo versus plaintext h1. The nginx **h1** edge — the "control"
G8 wanted to use as a stand-in for "AXIAM without h2" — costs **−25.8% / −27.8%
/ −26.8%**, i.e. roughly *twice* as much as AXIAM serving h2 over its own TLS.

**Which means the G8 experiment could never have worked, transient or no
transient.** The p2-h1 cell does not remove AXIAM's h2; it *adds* an entire
nginx process and a proxy hop in front of a server that is still speaking h1 to
that proxy. Any comparison of "p2-h1 vs p2-native" is therefore
"nginx+hop+h1 vs actix+h2" — two variables changing in opposite directions,
with the confound (**−22.8% / −18.4% / −13.7% for the hop alone**, measured
here for the first time via the cleartext control on the same edge) larger than
the effect being hunted. The decision rule in the previous version of this
document ("p2-h1 within ~15% of p0 ⇒ h2 CONVICTED") would have returned
"acquitted" on a stack where h2 was free *and* on a stack where h2 was
catastrophic, because the nginx overhead dominates both.

**The h1 control is now trustworthy — and it is boring.** Every cell above has
**0 failed ops** at every VU level, including the h1 edge that recorded
**1 059 failures** in G8. The cause was not TLS, h1, or load: none of the edge
confs declared an `upstream ... keepalive`, so nginx opened and closed a fresh
TCP connection to axiam-server for *every proxied request* (`proxy_http_version
1.1` + `Connection ""` are necessary but not sufficient). Fixed in
`tls/_upstream.inc`; the upstream connection count is now stable at the offered
concurrency (§2.1).

### 2.4 The clamped control — why CC was never going to answer this

`POST /oauth2/token`, 50 VUs, 10 s warm-up + 60 s measured, same image and
caps as every cell above (`results/tasks/h6-tls-proto/_cc-control/`):

<!--CC-CONTROL-->

Both clamped by the synchronous `rate_limit_bucket` write (H2 §2), which costs
~40-50 ms here. The TLS/h2 deltas measured above are **0.3-0.5 ms per
request**. Two orders of magnitude below the floor: the cell is not a weak
discriminator, it is *no* discriminator. This is why H6 abandoned the plan's
"re-run the three CC cells settled" step rather than running it and reporting a
null.

---

## 3. So what *is* the G box's −50.5% on client_credentials?

Being adversarial about our own earlier conclusion, in the order the evidence
actually constrains it.

**It is not a transport cost, and the G run's own matrix says so.** Four cells
in that same matrix ran the same TLS 1.3, the same h2, the same client, the
same 50 VUs, against the same server: introspection −0.2%, login −0.5%,
authz −1.3% (*faster*), userinfo −3.7%, jwks −12.5%. A transport tax that
takes 50% off one POST and 0.2% off another POST on the same connection to the
same listener is not a transport tax. H6 then measured the transport directly
on this host and found the same shape: h2 costs nothing, TLS costs 2-13%
depending on how cheap the endpoint is (§2.2, §2.3).

**The shape of the CC cell is "one thing got slower per request", not "the
server lost capacity".** At 50 closed-loop VUs, 50 / 0.0254 s = 1 969 ≈ the
measured 1 823 at p0, and 50 / 0.0542 s = 923 ≈ the measured 903 at p2. The
whole delta is the p50 rising by **28.8 ms**. Nothing in TLS 1.3 costs 28.8 ms
per request with resumption working — H6 prices native TLS on this stack at
**+0.3 ms** on jwks and **+0.4 ms** on userinfo per request.

**There is exactly one known object on that box with a cost of that order, and
`/oauth2/token` is one of the six endpoints that pays it.** H2 identified a
single synchronous SurrealDB `UPSERT` of `rate_limit_bucket:<endpoint>:<ip>`
performed by `RateLimitShared` before the handler runs, and measured it at
**~22 ms on the G box** and ~40 ms on the H2/H6 host. +28.8 ms is that object's
order of magnitude, and nothing else measured on either box is.

**But this is a hypothesis, not a finding, and the honest objection to it is
strong:** `/oauth2/introspect` is wrapped by the *same* middleware and showed
−0.2% in the same matrix. If the wrap explained the CC penalty it should have
touched introspection too. Two readings survive that objection and this note
does not choose between them:

* the bucket record is **per endpoint** (`oauth2_token:<ip>` and
  `oauth2_introspect:<ip>` are different records), so a per-record cost that
  varies — which is exactly what the G box's unexplained recovery cliff
  implies — can hit one endpoint and not the other; or
* something else that is specific to the *token-minting write path* (CC is the
  only high-throughput cell in the matrix that creates a record per request)
  degrades under p2 for a reason neither box has yet exposed.

**What is settled either way:** whichever of those is true, the cause is
endpoint-specific, and the two candidate causes are both server-side work, not
the wire. Publishing the number as "TLS 1.3 halves token issuance" was wrong,
and the correction is not "it is HTTP/2 instead" — it is "it is not the
transport at all".

---

## 4. The published position

**HTTP/2 on AXIAM's listener: acquitted.** The mechanism that would have made
it expensive — all concurrency collapsing onto one connection and one worker —
does not occur with any normal client (§2.1), and AXIAM serving h2 over its own
TLS is the *cheapest* TLS configuration measured (§2.3). Note precisely what is
and is not being said: h2 is not free everywhere — at the **nginx** edge it
costs 20% at low concurrency, converging to parity as the host saturates
(§2.3). That is nginx's h2, on a contended 4-core box, and it is measured here
only because the h1/h2 pair is the one controlled comparison available. It is
not evidence about actix, and it points the wrong way for the original
hypothesis regardless: it is h2 spending *more CPU per request*, not h2
starving idle workers. The two h2 window knobs stay
(they are cheap and they let a flow-control hypothesis be falsified in one
cell), `AXIAM__SERVER__TLS__HTTP2=false` stays a hard startup error, and the
`H1Service` rewrite floated in the previous version of this note is
**withdrawn** — it would trade h2 away to fix a problem that does not exist.

**The "one h2 connection is one core" note in `docs/security-profiles.md`
stays, but bounded.** It is a true property of the actix listener and it is
real sizing guidance for a caller that funnels all its concurrency down one
connection (an API gateway, a mesh sidecar, a batch job with a single pooled
h2 client). What it is not is a general HTTP/2 tax, and the doc now says so
with the connection census attached.

**TLS 1.3 is priced, not free.** In-process rustls termination costs on the
order of 10-13% of throughput on an endpoint that does almost nothing per
request, shrinking toward the noise as the endpoint does more work or as the
box saturates for other reasons. That is a normal, publishable TLS cost. It is
not 50%.

**The benchmark's own edge is not free either, and the matrix is right to use
the native listener for p2.** See §2.3: fronting AXIAM with nginx costs far
more than AXIAM's own TLS, most of it the extra hop and the extra process
competing for the same cores.

## 5. Change log

| file | change |
|---|---|
| `benchmarks/scenarios/lib/metrics.js` | `bench_http_proto` recorded from `res.proto` on every response (`doOp`) and as `20` for gRPC (`recordGrpcResult`); `protoCode()` exported |
| `benchmarks/runner/report.py` | `http` column in the All-results and security-cost tables; `mixed(a,b)` rendering; protocol-confound warning; min-of-mins/max-of-maxes across median-of-N runs |
| `benchmarks/runner/run-benchmark.sh` | absolutize `BENCH_RESULTS_DIR` (a relative value silently lost the k6 summary export) |
| `benchmarks/targets/axiam/tls/_upstream.inc` | new — one keep-alive upstream for the edge confs (previously: a fresh backend TCP connection per proxied request) |
| `benchmarks/targets/axiam/tls/_plain-control.inc` | new — cleartext control vhost on the same edge, so the proxy hop can be priced separately from TLS |
| `benchmarks/targets/axiam/tls/tls13.conf`, `tls13-h1.conf` | now a matched pair differing only in `http2 on;`, with matched resumption/keep-alive/logging |
| `benchmarks/targets/axiam/docker-compose.yml` | mount `tls/` for the includes; publish `BENCH_EDGE_PLAIN_PORT`; `AXIAM__AUTH__COOKIE_SECURE` pass-through |
| `benchmarks/justfile` | p0-plaintext sets `AXIAM__AUTH__COOKIE_SECURE=false` (fixes H2 §8.3 — every login-based p0 cell used to die in `setup()`) |
| `benchmarks/run-improvement-tasks.sh` | new task `h6-tls-proto`; `g8-tls-h1` marked superseded |
| `benchmarks/runner/h6-connection-probe.sh` | new — connection census + actix worker CPU balance |
| `benchmarks/docs/methodology.md` | `bench_http_proto` documented in the metric list |
| `docs/security-profiles.md` | ALPN/h2 sections bounded by measurement; TLS cost stated |
| `benchmarks/PRIVATE_BENCH_ANALYSIS.md`, `PUBLIC_BENCH_ANALYSIS.md` | B2 closed; the "TLS halves token issuance" claim corrected |

## 6. What is still open — exactly one thing, and it needs a different host

The H6 host cannot answer it: `/oauth2/token` is `RateLimitShared`-wrapped and
clamped to ~20 ops/s here at any concurrency (§2.4), so a transport-scale
effect on that endpoint is unmeasurable no matter how the cell is run.

**The follow-up, for the server-class re-run (E3), stated so it cannot be
mis-run:**

> On a host where `POST /oauth2/token` is **not** clamped — verify first by
> checking that a 1-VU CC burst gets p50 well under 10 ms and that throughput
> rises with concurrency — run `oauth2_client_credentials` at p0 and at
> p2-native across at least three VU levels (e.g. 12 / 25 / 50 / 100), with
> the `http` column recorded for every cell.
>
> * If p2 throughput **scales with VUs** and sits a roughly constant *fraction*
>   below p0, the p2 penalty is a per-request cost and the remaining question
>   is what that cost is (it is not TLS crypto — §2.2 prices that).
> * If p2 throughput is **flat in VUs** at ~900 ops/s while p0 scales, the
>   ceiling is a serialization point, and the only one known on that path is
>   `RateLimitShared`'s synchronous `rate_limit_bucket` write
>   (`claude_dev/postseed-transient-investigation.md`). Then the fix is the one
>   H2 already asked for, and B2 was never a TLS bug at all.
>
> Either outcome closes it. Do not run this on any host where the clamp is
> present, and do not use `bench_op_latency_ms` alone to decide — the
> discriminator is the *shape of throughput vs concurrency*, not a single
> cell's number.
