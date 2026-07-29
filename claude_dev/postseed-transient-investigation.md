# The "post-seed transient" — G1 endgame (H2)

**Status: RESOLVED for this environment, and the resolution reframes the
finding.** What run 3 / the G run called a *post-seed transient* is, on the
box this investigation ran on, not a transient and not caused by seeding. It
is a **permanent per-request cost paid by exactly the six endpoints wrapped
with `RateLimitShared`** — the SurrealDB-backed shared rate-limit
pre-check — and it is a **product-relevant design finding**, not a bench
artifact.

> **Provenance.** Sections 1–8 are new work from task **H2** (2026-07-28,
> branch `claude/g-benchmark-improvements-n5mjmj`), run live against
> `ghcr.io/ilpanich/axiam/server:1.0.0-alpha19` + `surrealdb/surrealdb:v3`
> (3.2.3) with `just target=axiam profile=p0-plaintext bench-up`, server and
> datastore each capped at 2 CPU / 1 GiB, rate limits `neutralized`.
> `claude_dev/improvement-after-serious-benchmark.md` and
> `improvement-after-g-benchmark.md` reference this file; it had never
> actually been created, so this *is* the note, written to close H2.
> Everything below is measured on this branch unless labelled *(inherited
> from the G run)*.

---

## 1. The one-paragraph answer

Six AXIAM endpoints — `POST /api/v1/authz/check`, `POST /oauth2/token`,
`POST /oauth2/introspect`, `POST /oauth2/revoke`, `POST /api/v1/auth/login`,
and (accidentally) **`GET /api/v1/users`** — are wrapped with
`RateLimitShared` (`crates/axiam-api-rest/src/middleware/rate_limit_shared.rs`,
wired in `crates/axiam-api-rest/src/server.rs`). Before the handler runs,
that middleware performs **one synchronous, uncached, unbatched SurrealDB
write**: an `UPSERT` of a single `rate_limit_bucket:<endpoint>:<ip>` record
(`crates/axiam-db/src/repository/rate_limit.rs::increment`). On this box
that one round trip costs **~40–46 ms of datastore time, server-measured**,
while every other DB round trip in the same request costs 0–6 ms. It is the
"~22 ms serialized unit" the G run was chasing. Endpoints without the wrap
are 5–40× faster and scale with concurrency; endpoints with it sit at
**16–21 ops/s no matter how many clients you point at them**. Nothing about
seeding, data volume, storage backend, uptime, restarts or pool size changes
this. **The gRPC listener is worse:** `GrpcSharedRateLimitLayer` performs the
same bucket write as a server-wide tower layer, so *every* gRPC call pays it
(`crates/axiam-api-grpc/src/middleware/rate_limit.rs:374`,
`crates/axiam-api-grpc/src/server.rs:153`).

---

## 2. The per-operation clamp map (H2 item 1)

Closed-loop `curl` bursts, credentials minted once outside the measured
window, 25 requests per kept-alive connection (harness ceiling ≈ 4 300
ops/s, so a clamped op is unmistakable). `p50` is per-request wall time.

| operation | endpoint | `RateLimitShared`? | 1 VU ops/s | 1 VU p50 | 20 VU ops/s | 20 VU p50 |
|---|---|---|---:|---:|---:|---:|
| health | `GET /health` | no | 510 | 0.3 ms | 4 248 | 1 ms |
| jwks | `GET /oauth2/jwks` | no | 493–504 | 0.3 ms | 2 992 | 1 ms |
| userinfo | `GET /oauth2/userinfo` | no | 299–302 | 1 ms | 1 681 | 9 ms |
| discovery | `GET /.well-known/openid-configuration` | no | ~91 | 11 ms | — | — |
| resources | `GET /api/v1/resources` | no | 68–74 | 11–12 ms | 254–280 | 66–74 ms |
| roles | `GET /api/v1/roles` | no | 67–74 | 11–13 ms | 256 | 73 ms |
| **users (list!)** | `GET /api/v1/users` | **yes — `users_create`** | 14–16 | 60–65 ms | 17.9–20.0 | 967–1 106 ms |
| **authz check** | `POST /api/v1/authz/check` | **yes — `authz_check`** | 16–18 | 55–60 ms | 18.8–21.3 | 907–1 061 ms |
| **client credentials** | `POST /oauth2/token` | **yes — `oauth2_token`** | 16–18 | 51–55 ms | 20.0–21.7 | 897–1 032 ms |
| **introspection** | `POST /oauth2/introspect` | **yes — `oauth2_introspect`** | 17–19 | 49–58 ms | 20.0 | 1 002 ms |
| **revocation** | `POST /oauth2/revoke` | **yes — `oauth2_revoke`** | 17.3 | 53 ms | — | — |
| **login** | `POST /api/v1/auth/login` | **yes — `login`** | 8–11 | 95–116 ms | 19.2 | 1 032 ms |

**The correlation is 6/6 and 6/6.** Every clamped operation is wrapped;
every unclamped operation is not. The live datastore agrees: after a session
of probing, `SELECT id FROM rate_limit_bucket` contains exactly

```
rate_limit_bucket:`authz_check:172.18.0.1`
rate_limit_bucket:`login:172.18.0.1`
rate_limit_bucket:`oauth2_introspect:172.18.0.1`
rate_limit_bucket:`oauth2_revoke:172.18.0.1`
rate_limit_bucket:`oauth2_token:172.18.0.1`
rate_limit_bucket:`users_create:172.18.0.1`
```

— one row per clamped endpoint and nothing else. `oauth2_revoke` was
**predicted before it was measured** (it is wrapped, so it must be clamped);
it came back at 17.3 ops/s / 53 ms and its bucket row appeared. That is the map's
falsifiable test, and it passed.

### 2.1 The `GET /api/v1/users` case is the cleanest natural experiment

`GET /api/v1/resources`, `GET /api/v1/roles` and `GET /api/v1/users` are the
same shape: an admin-session `list` handler over a small tenant-scoped table
(1, ~4 and 2 rows respectively), same middleware scope, same session, same
datastore. Two of them cost **11–13 ms**; `users` costs **60–65 ms**. The
only difference in the wiring is that `server.rs` declares

```rust
web::resource("/users")
    .wrap(build_governor(rate_limit_cfg.register_per_min))
    .wrap(RateLimitShared::<C>::new("users_create", rate_limit_cfg.register_per_min))
    .route(web::post().to(handlers::users::create::<C>))
    .route(web::get().to(handlers::users::list::<C>))
```

so the **GET inherits the POST's rate limiter** — an actix `resource`-level
`wrap` applies to every method on the resource. Δ = **~50 ms**, attributable
to nothing but the shared rate-limit pre-check. This is also a **functional
bug independent of performance**: in the production posture
`register_per_min` is **5**, so listing users would start returning 429 after
five reads per minute per IP, and every read is charged to a *registration*
bucket. See §7.

---

## 3. Naming the serialized unit (H2 item 5's "must be named, not hand-waved")

With the datastore at `--log debug` its own tracer reports server-side
latency per RPC (`http.latency.ms`). One request of each kind, quiet stack:

```
GET /api/v1/resources   8 RPCs   0, 1, 0, 4, 0, 0, 2, 0                       ms
GET /oauth2/jwks        2 RPCs   2, 0                                          ms
GET /api/v1/users      13 RPCs   0, [39], 1, 2, 0, 0, 1, 0, 6, 1, 1, 2, 0      ms
POST /api/v1/authz/check 11 RPCs 0, [40], 3, 2, 0, 0, 1, 0, 1, 2, 0            ms
```

There is exactly **one** expensive RPC (request body 460 bytes, ~39–46 ms).
It appears only on the wrapped endpoints, it is absent from `resources` and
`jwks`, and it sits in the prefix that the wrapped endpoints have and the
unwrapped ones do not. **That RPC is the serialized unit.** On the G box the
same unit measured ~22 ms; here it is ~40 ms. The G run's "~22 ms serialized
unit" and this "~40 ms RPC" are the same object.

**CPU attribution.** At **1 VU** (16 authz ops/s — nothing else running) the
datastore container burns **91–94 % of one core** and the server 7–10 %.
16 ops/s × 57 ms ≈ 0.91 core: the unit is datastore **CPU**, not I/O wait.
At 20 VUs the datastore stays at ~100–111 % — it never uses its second
core — while throughput stays at 20 ops/s. That is the whole shape the G run
described (server idle, DB pinned at ~1.0 core, sharp per-request cost,
concurrency buying nothing).

---

## 4. Is it the datastore's fault? (H2 item 2 — db-direct with the real query)

**No — the statement itself is cheap.** Three independent non-AXIAM clients
against the *same live datastore*:

| probe | client | result |
|---|---|---|
| the exact `rate_limit_bucket` UPSERT, 200 statements | `surreal sql` CLI (real SDK client, one long-lived session) | **6 ms/stmt** (a plain `SELECT * FROM resource` on the same session: 5 ms/stmt) |
| the exact UPSERT with **bound `$key`/`$window_start`** | raw HTTP `/sql` + query-string vars | **8 ms/stmt** |
| the same UPSERT with literals | raw HTTP `/sql` | **9 ms/stmt** |
| D6 round-trip 4 (`get_role_permission_grants_for_roles` — `SELECT … FROM grants WHERE out.tenant_id != NONE`) | raw HTTP `/sql`, 20 concurrent workers | **324–612 ops/s** (never clamped; 1 worker 83–169 ops/s) |
| hot-key UPSERT contention, 1 / 4 / 20 workers on ONE record | raw HTTP `/sql` | **126 / 385 / 487 ops/s** — no contention collapse |
| ~30 000 successive versions written to one key, re-measured after each 15 s round | raw HTTP `/sql` | **122 → 114 → 142 → 99 → 128 ops/s** — no version-accumulation decay |
| `SELECT * FROM user WHERE tenant_id = …` / `FROM resource …` / `CREATE` scratch row, 20 workers | raw HTTP `/sql` | **548 / 648 / 647 ops/s** |

So SurrealDB executes AXIAM's own statements, against AXIAM's own data,
concurrently, at 300–740 ops/s — while AXIAM gets 20 ops/s out of the same
box. **The datastore is not clamped and the data shape is not the cause.**

**What is left unresolved:** *why* SurrealDB spends ~40 ms of CPU on that one
RPC when it spends 1–8 ms on the same SQL from another client. Ruled out by
measurement: parameter binding (bound vs literal: 8 vs 9 ms), datetime
typing, hot-key write contention, version accumulation, WAL/fsync (see §5 —
the in-memory backend behaves identically), and per-request root
re-authentication (every RPC in the trace authenticates "using token", not
by password; a SurrealDB *password* signin costs 57 ms here, which is
tantalisingly close to the observed per-request datastore CPU, but the trace
says it is not happening). Closing that last gap needs a capture of the exact
CBOR payload the pinned `surrealdb` 3.2.x HTTP engine puts on the wire for
`repo.increment()` — i.e. an `axiam-db`-side change (route the repository
path through F1's `instrument_query`, which today only wraps the health
checks) or a proxy in front of `/rpc`. **That does not block the verdict:**
whatever the datastore-internal reason, the *architectural* fact is that
AXIAM puts a synchronous datastore write in front of its six hottest
endpoints, and that write is the ceiling.

---

## 5. What does *not* change it (H2 items 3 and 4)

| intervention | authz @1 VU | authz @20 VU | verdict |
|---|---:|---:|---|
| baseline, ~9 min after seed | 17 ops/s (55 ms) | 20.0 ops/s | — |
| ~40 min of cumulative traffic (many thousands of requests) | 16–18 | 18.8–21.3 | **no recovery** |
| **server restart** (fresh process, same datastore) | 17 | 21.3 | no change |
| **datastore restart** (fresh `surreal` process, same volume) | 17 (55 ms) | 21.3 | **no change, no clock reset** |
| **`AXIAM__DB__POOL_SIZE=8`** (from 1) | 16 (60 ms) | 20.0 | **no change** |
| **in-memory storage backend** (`surreal start memory`) + fresh 2 s seed | 18 (55 ms) | 20.0 | **no change** |

Two of these deserve emphasis.

**5.1 The in-memory backend result kills the whole surrealkv family of
hypotheses.** A datastore with *no disk at all*, freshly created, containing
nothing but a 5-object seed and zero history, reproduces the numbers to
within noise (authz 18 ops/s @1 VU / 20.0 @20 VU; `resources` 69 / 231;
`users` 16 / 20.0). Compaction, WAL fsync, log replay, MVCC version chains
and "post-ingest index state" are all refuted as causes.

**5.2 `AXIAM__DB__POOL_SIZE` is a no-op for concurrency here.** Going from 1
to 8 changed nothing at either concurrency level. This is consistent with
D6's finding (`claude_dev/surrealdb-tuning-report.md` §1) that cloning a
`Surreal<Client>` shares the same underlying router; it is worth a separate
look at whether the F2 pool actually opens independent connections, because
the G run's "pool_size=4 = +7 % on CC" now reads as noise rather than
parallelism.

**5.3 Seed volume is not a variable (H2 item 3).** `benchmarks/runner/seed.sh`
`seed_axiam()` creates **one** org, tenant, admin, user, resource, role,
permission, grant, role-assignment and OAuth2 client — ten objects, in
**1.5–2.4 s wall clock**. There is no bulk import to scale to 10 %; a
"10 % seed" would be one object. Combined with §5.1 (fresh in-memory
datastore, same numbers) the *post-seed* framing is simply wrong for this
environment: seeding is not the trigger, because there is no trigger — the
cost is always there and is paid per request.

---

## 6. Reconciling with the G-box observation

The G run saw a **~6-minute** window at ~44 ops/s ending in a sharp cliff up
to ~715 ops/s, and G8 saw `token_refresh` at 914 ops/s while CC and authz sat
at ~45 in the same session. Both are consistent with this model and with
nothing else we tested:

* **G8's discriminator is the map.** `token_refresh` on AXIAM exercises
  `POST /api/v1/auth/refresh` (session refresh), which is **not** wrapped
  with `RateLimitShared`; CC (`/oauth2/token`) and authz
  (`/api/v1/authz/check`) both are. "Per-table/per-query" was the right
  instinct — it is per *endpoint*, and the discriminating table is
  `rate_limit_bucket`.
* **~44 ops/s on the G box vs ~20 here** is the same shape with a cheaper
  unit (~22 ms there vs ~40 ms here).
* **What we cannot explain from this box** is the G run's *recovery cliff*.
  Nothing here recovers, ever. Two readings are possible and this note does
  not pick between them: (a) the G box's ~22 ms unit occasionally drops to
  ~1 ms (some SurrealDB-side warm state we could not reproduce), or (b) the
  G run's "recovered" cells were measuring something subtly different from
  the clamped ones. Reading (b) is worth checking before any further
  "settled vs unsettled" claim is published: **`report.py` should be asked
  to confirm that the 715–2 322 ops/s AXIAM authz cells and the ~45 ops/s
  ones ran the same scenario file against the same endpoint.**

---

## 7. Verdict and action

**Verdict: product-relevant, not a bench artifact.** The bench harness did
not create this; it merely tripped over it first. Any AXIAM deployment pays
one synchronous datastore write before every authorization check, every
token issuance, every introspection, every revocation, every login and
every user listing. On a datastore where that write costs 1 ms the ceiling
is ~1 000 ops/s per endpoint; where it costs 40 ms the ceiling is 20 ops/s.
The ceiling is *set by the slowest datastore write in the deployment*, and
it does not improve with concurrency, replicas of the app, or connection
pooling.

Three distinct defects, in priority order:

1. **`GET /api/v1/users` is rate-limited as if it were user registration.**
   `web::resource("/users")` wraps both the POST and the GET, so listing
   users consumes the `register_per_min` bucket — **5/min per IP in the
   production posture**. This is a correctness bug, reachable by any admin
   UI, and it is also why `users` appears in the clamp map at all. Fix:
   split the resource, or move the wrap onto the POST route.
2. **The shared rate-limit pre-check is on the synchronous critical path of
   the six hottest endpoints, uncached and unbatched**, and is a single
   record per `(endpoint, ip)` — a deliberate global write hot-spot. The
   in-memory `governor` already runs on the same endpoints and already makes
   the real decision (`RateLimitShared` fails *open* on any store error);
   the shared store exists to make the limit hold across replicas. Options
   worth measuring (none implemented here): a short in-process TTL cache of
   the bucket count with periodic write-back; fire-and-forget the UPSERT and
   decide on the previous read (the limiter is already a fixed-window
   approximation, and it already fails open); an explicit
   `AXIAM__RATE_LIMIT__SHARED=off` for single-replica deployments; or moving
   the counter out of the datastore entirely.
3. **`AXIAM__DB__POOL_SIZE` buys no concurrency** (§5.2) — worth confirming
   against F2's pool implementation.

### 7.1 Text for the follow-up issue (do **not** file from this task — for the maintainer)

> **Title:** Shared rate-limit store puts a synchronous DB write on the
> critical path of the six hottest endpoints (and `GET /api/v1/users` is
> limited as `users_create`)
>
> **Body:**
> `RateLimitShared` (`crates/axiam-api-rest/src/middleware/rate_limit_shared.rs`)
> performs one synchronous `UPSERT` on `rate_limit_bucket:<endpoint>:<ip>`
> (`crates/axiam-db/src/repository/rate_limit.rs::increment`) before the
> handler runs, on `POST /api/v1/authz/check`, `POST /oauth2/token`,
> `POST /oauth2/introspect`, `POST /oauth2/revoke`,
> `POST /api/v1/auth/login` and — unintentionally — `GET /api/v1/users`.
> `GrpcSharedRateLimitLayer` does the same thing as a **server-wide tower
> layer** on the tonic listener (`crates/axiam-api-grpc/src/server.rs:153`),
> so every gRPC call pays it too.
>
> *Measured (2026-07-28, `server:1.0.0-alpha19` + SurrealDB 3.2.3, 2 CPU /
> 1 GiB each, rate limits neutralized, `p0-plaintext`):* those six endpoints
> are pinned at **16–21 ops/s at any concurrency from 1 to 40 VUs**
> (p50 ≈ 55–65 ms at 1 VU, ≈ 1 s at 20 VUs) while structurally identical
> endpoints without the wrap run at **68–4 248 ops/s**
> (`GET /api/v1/users` 60–65 ms vs `GET /api/v1/resources` 11–12 ms — same
> handler shape, same session, same datastore; the only difference is the
> wrap). The datastore's own tracer attributes ~39–46 ms of the request to a
> **single** RPC that only the wrapped endpoints issue; every other RPC in
> the same request is 0–6 ms. The datastore burns ~0.92 core at 16 req/s and
> the server ~8 %.
>
> The datastore is not the problem: the same `UPSERT`, same parameters, same
> live database, issued by `surreal sql` or raw HTTP `/sql`, runs at
> **6–9 ms** and scales to 487 ops/s at 20 concurrent writers on the same
> single hot key. Unaffected by: server restart, datastore restart,
> `AXIAM__DB__POOL_SIZE=8`, an **in-memory** storage backend with a fresh
> 2-second seed, ~40 minutes of cumulative traffic, and idle.
>
> **Two asks:**
> 1. **Bug:** split `web::resource("/users")` so the `GET` list route does
>    not inherit the `POST` registration limiter — today a user *list* is
>    charged to `users_create`, which is **5/min per IP** in the production
>    posture.
> 2. **Design:** get the shared-store round trip off the synchronous path
>    (in-process TTL cache + write-back, fire-and-forget UPSERT with a
>    previous-read decision, or an off switch for single-replica
>    deployments). The in-memory `governor` already makes the real decision
>    and `RateLimitShared` already fails **open** on store errors, so the
>    synchronous ordering buys strictness that the design does not otherwise
>    claim.
>
> Repro and full data: `claude_dev/postseed-transient-investigation.md`
> (H2, branch `claude/g-benchmark-improvements-n5mjmj`).

---

## 8. Consequences for the benchmark harness

**8.1 The H1 settle gate can never pass in an environment like this one.**
It bursts `POST /api/v1/authz/check` at 20 VUs and requires ≥ 400 ops/s or
p50 < 150 ms. That endpoint's ceiling here is ~20 ops/s / ~1 000 ms *by
construction*, so the gate will always spend its full
`BENCH_SETTLE_TIMEOUT_SECS` and stamp `settle_timeout: true` — which H1.5
correctly teaches `report.py` to refuse. The gate is not wrong; it is
reporting a real, permanent property of this stack on this hardware. It
should keep failing rather than be relaxed, and the timeout should be
treated as **"this box cannot produce a settled authz cell"**, not as a
flaky probe.

**8.2 Cells that need settled authz throughput cannot be produced here.**
H5 (decision-cache K-sweep), H6 (memory retention under authz load), H9 and
H10 all want authz/CC cells above the clamp. On this box they cannot get
them from the wrapped endpoints at any concurrency. Practical options, in
order of preference:

1. **Run those tasks on the G box** (or any host where the unit is ~1 ms) —
   the only option that yields comparable numbers.
2. ~~Measure the decision cache on the gRPC authz path instead.~~
   **Checked and ruled out.** `GrpcSharedRateLimitLayer`
   (`crates/axiam-api-grpc/src/middleware/rate_limit.rs:374`) calls the
   *same* `SurrealRateLimitBucketRepository::increment`, and
   `crates/axiam-api-grpc/src/server.rs:153` applies it as a tower `.layer()`
   on the whole tonic server — so **every gRPC call**, not just authz, pays
   the same synchronous bucket write. gRPC offers no escape. (This could not
   be confirmed live because the gRPC scenarios are blocked by §8.3 as
   well — the finding is from the source, and the REST measurements of the
   identical code path stand behind it.)
3. **Report the ratio, not the level.** Cache-on vs cache-off at 20 ops/s is
   uninformative because the 40 ms rate-limit write dominates and the cache
   cannot remove it — do not publish a "+x %" from clamped cells.
4. Do **not** work around it by disabling rate limits: `rl=neutralized`
   already raises the *limits*, and the shared-store write happens
   regardless of how high the limit is. Neutralizing does not skip the
   round trip.

**8.3 Separate harness bug found on the way (blocks every p0 authz cell).**
On `p0-plaintext` with `server:1.0.0-alpha19`, k6 cannot authenticate a
cookie session: `/api/v1/auth/login` returns 200 and sets `axiam_access` /
`axiam_csrf` / `axiam_refresh` with **`Secure`**
(`crates/axiam-api-rest/src/middleware/csrf.rs`, `cookie_secure` from
`crates/axiam-auth/src/config.rs:59`, default `true`), and k6's cookie jar
will not replay a `Secure` cookie over `http://`. Every scenario using
`lib/auth.js::loginSession()` dies in `setup()` with

```
Error: auth.loginSession: no axiam_access cookie (or body token) in login response
```

after exactly one HTTP request — reproduced twice, and it is why
`benchmarks/results/axiam/p0-plaintext/authz_check_rest.k6.json` in this
tree has no `iterations` metric at all. `curl` is unaffected (which is why
`seed.sh`'s smoke check and the H1 settle gate both pass). Fixes, either
is fine: run authz cells under `p2-tls13`, or plumb
`AXIAM__AUTH__COOKIE_SECURE=false` into the bench compose for plaintext
profiles only. **Until this is fixed no `p0-plaintext` authz_check_rest
number in `results/` is real.**

---

## 9. Method notes (so this is reproducible)

* Probes used: a closed-loop `curl` burst harness — committed as
  **`benchmarks/runner/h2-clamp-probe.sh`**, which reproduces the whole of §2
  against a live `bench-up`/`bench-seed` stack (one credential mint up front,
  25 requests per kept-alive connection, `--max-time` bounded, throughput
  computed from measured wall time); a busybox-based concurrent
  client for SurrealDB HTTP `/sql`; the `surreal sql` CLI for a real-SDK
  comparison; `docker stats` sampling at 5 s; and the datastore's own
  `--log debug` tracer for server-side per-RPC latency.
* **Two traps worth recording.** (i) A SurrealDB HTTP probe using **Basic**
  auth pays a full Argon2 root-password verification per request — 53 ms at
  1 worker, and it *collapses* to 2.1 ops/s at 20 concurrent workers on a
  2-CPU container. Any db-direct probe must sign in once (`POST /signin`)
  and reuse the Bearer token, exactly as `axiam-db` does; otherwise it
  measures SurrealDB's password hash and looks like a clamp. (ii) A probe
  posting to SurrealDB's `/rpc` endpoint with a Bearer header is rejected
  (`Anonymous access not allowed`) but still returns HTTP 200 — a
  status-code-only probe will happily "measure" the rejection path at full
  speed. Always assert that the write actually landed.
* Session/token expiry (900 s) silently turns a burst into a measurement of
  the 401 path, which is ~50× faster and reads as "recovered". The probe
  re-mints anything older than 5 minutes; any future harness doing
  short-cell sweeps must do the same and check `pct2xx`.
