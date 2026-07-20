# Benchmark & Performance Improvement Plan

Derived from the first full benchmark run (2026-07-19) and its two analysis
documents: [`benchmarks/PUBLIC_BENCH_ANALYSIS.md`](../benchmarks/PUBLIC_BENCH_ANALYSIS.md)
and [`benchmarks/PRIVATE_BENCH_ANALYSIS.md`](../benchmarks/PRIVATE_BENCH_ANALYSIS.md).
This plan turns every suggestion in those documents into executable tasks for
Claude agents. Each task states **which model to use** (Opus for open-ended
debugging/design/security-sensitive server work; Sonnet for well-specified,
mechanical, or config/harness work), the files involved, precise instructions,
and acceptance criteria.

**Operating constraint:** all runs stay on the Dell XPS 15 9570 laptop for now
(no budget for a VM). The plan therefore includes tasks to *control and
measure* the laptop's variability rather than escape it. A server-class re-run
is deferred until hardware is available and is explicitly out of scope here.

**A note on thermal throttling (re-examined).** The raw data does **not** show
evidence that throttling distorted the comparisons: host load was moderate
(max ~3.7 cores of 12 threads per stack, plus k6), and CPU-bound cells
repeated ~30 min apart are nearly identical (AXIAM introspection p0 vs p2:
2199 vs 2192 req/s; Keycloak — fully CPU-pegged — client-credentials p0 vs
p2: 143 vs 138 req/s over a 2-hour session). If clocks had sagged
progressively, the later CPU-bound cells would show it. **However**, `docker
stats` measures time-based core utilization and cannot distinguish a core
running at 3.9 GHz from one at 2.2 GHz — a *constant* sustained-clock
reduction would depress all absolute numbers uniformly and be invisible in
this data. So: cross-target fairness looks intact; absolute numbers are
unconfirmed until we record clock/temperature telemetry (task A6), which will
also be published in the report for honesty.

Task IDs continue the section numbering of the private analysis. Phases must
land in order; tasks within a phase are independent unless noted. Every task
follows the repo's process: feature branch, signed commit, PR per phase.

---

## Phase A — Harness correctness & honesty (all benchmark-only; no server code)

### A1. Fix `userinfo` scenario (100% errors on AXIAM & Keycloak) — **Sonnet**

*Files:* `benchmarks/scenarios/userinfo.js`, `benchmarks/scenarios/lib/auth.js`,
`benchmarks/scenarios/lib/targets.js`.

1. Add `mintUserToken()` to `lib/auth.js`: same shape as `mintToken()` but
   tries `adapter().login()` **first**, then `clientCredentials` as fallback;
   return `{access_token, refresh_token, is_user_token}`. For AXIAM, `login()`
   returns tokens via Set-Cookie only — reuse the cookie-jar extraction already
   implemented in `loginSession()` (refactor the cookie-reading part into a
   shared helper rather than duplicating it).
2. Switch `userinfo.js` `setup()` from `mintToken()` to `mintUserToken()`.
3. In `targets.js`, add `scope: 'openid'` to the **Keycloak**
   `clientCredentials()` body (today it omits scope, so KC service-account
   tokens are not OIDC-capable).
4. Emit a `bench_fallback` Counter (see A3) when the user-token mint fell back
   to client credentials, so the report can label the cell.

*Acceptance:* a local smoke run (`just target=axiam bench-up/seed`, then
`k6 run scenarios/userinfo.js` with the seed env) shows `status is 200`
passing for AXIAM and Keycloak; Zitadel unchanged.

### A2. Harden `runner/seed.sh` + post-seed smoke checks — **Sonnet**

*Files:* `benchmarks/runner/seed.sh`, `benchmarks/runner/run-benchmark.sh`.

1. Remove every `|| true` / `>/dev/null` swallow on provisioning calls
   (Keycloak client + user creation are the known offenders); check HTTP
   status of each call, print the response body on failure, and exit non-zero.
   Treat 409 (already exists) as OK but *verify* the existing object has the
   required attributes (for Keycloak: GET the client and assert
   `directAccessGrantsEnabled==true`, GET the user and assert enabled +
   password credential set — this is the presumed cause of the 100% ROPC
   failures).
2. Append a **smoke-check section** at the end of `seed.sh`: one real request
   per scenario-critical flow per target — ROPC/login, client_credentials,
   introspect (of a just-minted token), refresh (if a refresh token was
   issued), userinfo (with the user token), and for AXIAM one REST authz
   check. Any non-expected status → print body, exit 1.
3. `run-benchmark.sh`: refuse to start the k6 matrix if the smoke-check marker
   (e.g. `results/<target>.seed.ok`) is absent for the target.
4. On smoke-check failure, save the failing response bodies under
   `results/<target>/seed-failure/` for diagnosis.

*Acceptance:* deliberately breaking the seeded Keycloak client (disable direct
access grants by hand) makes `bench-run` refuse to start with a clear message.

### A3. Tag fallback operations (Zitadel login/refresh) — **Sonnet**

*Files:* `benchmarks/scenarios/lib/targets.js`, `lib/metrics.js`,
`scenarios/token_refresh.js`, `scenarios/oauth2_password_login.js`,
`benchmarks/runner/report.py`.

1. `lib/metrics.js`: add `fallback: new Counter('bench_fallback')` to `m`.
2. `targets.js`: `zitadel.login()` currently returns
   `zitadel.clientCredentials()` silently — set `fallback: true` on the built
   request object it returns. In `doOp()`, `m.fallback.add(1)` when
   `built.fallback`.
3. `token_refresh.js`: in the no-refresh-token fallback branch (the
   `doOp(a.clientCredentials())` path), also count `m.fallback.add(1)`.
4. `report.py`: read the `bench_fallback` counter from the k6 summary; if
   `> 0` for a cell, annotate it (`comparability: fallback-op`) and exclude it
   from head-to-head winner tables the same way authz cells are excluded,
   keeping it visible in the full matrix with a footnote.

*Acceptance:* re-generated `report.md` shows Zitadel's password-login and
refresh cells labeled as fallback, and they no longer appear as 🏆 candidates.

### A4. Complete `meta.json` per methodology §7 — **Sonnet**

*Files:* `benchmarks/runner/run-benchmark.sh`.

Record per cell (all obtainable without new dependencies):
- `image` + `image_digest` for every container in the stack
  (`docker inspect --format '{{.Config.Image}} {{index .RepoDigests 0}}'`).
- `scenario_sha256` (`sha256sum scenarios/<name>.js`).
- `batch_size` (`BENCH_BATCH_SIZE`, currently unrecorded default 5).
- `host_kernel` (`uname -r`), `docker_version`
  (`docker version --format '{{.Server.Version}}'`), `cpu_model`
  (from `/proc/cpuinfo`), `cpu_governor`
  (`/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor`).
- `k6_cpu_cores_avg` over the measure window (from A6's host sampler).

*Acceptance:* a fresh cell's `meta.json` contains every field above; report.py
tolerates old meta files without them.

### A5. `report.py` improvements — **Sonnet**

*Files:* `benchmarks/runner/report.py`.

1. Add **p50** to all tables (already in k6 summaries as `med`).
2. For cells with `error_rate == 1.0`, blank throughput/latency columns
   (print `—`) instead of error-path numbers.
3. **Bottleneck attribution:** the per-container `res.csv` is already parsed
   for sums — also compute per-container `cpu_avg` and emit a
   `bottleneck` column per cell: the container whose `cpu_avg ≥ 0.95 ×` its
   configured cap (read caps from meta; fall back to the compose defaults),
   else `none`. Add a per-cell per-container breakdown appendix section.
4. Surface the A3 fallback flag and the A6 clock/thermal columns.
5. Efficiency tables: add a variant computed on **server-container-only**
   CPU/mem next to the whole-stack numbers, so AXIAM's broker inclusion is
   visible rather than silently folded in.

*Acceptance:* regenerating the report from the existing 2026-07-19 `results/`
tree (no re-run needed) shows p50 columns, blanked invalid cells, a
`bottleneck` column matching the manual analysis (SurrealDB pegged on authz
cells, Keycloak server pegged everywhere, Zitadel Postgres pegged on
jwks/introspection/userinfo), and no crash on missing new meta fields.

### A6. Host telemetry: CPU frequency, temperature, k6 headroom — **Sonnet**

*This is the thermal-throttling honesty task requested by the maintainer.*

*Files:* `benchmarks/resource/sampler.sh`, `benchmarks/runner/run-benchmark.sh`,
`benchmarks/runner/report.py`, `benchmarks/docs/methodology.md`.

1. Extend `sampler.sh` (or add `host-sampler.sh` invoked alongside it) to
   append, at the same 1 s cadence, a `<scenario>.host.csv` with:
   `epoch_ms, cpu_mhz_avg, cpu_mhz_min, temp_c_max, host_cpu_util_pct,
   k6_cpu_cores`. Sources (all no-sudo):
   - MHz: mean/min over `/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq`.
   - Temp: max over `/sys/class/thermal/thermal_zone*/temp` (skip zones that
     error; divide by 1000).
   - Host util: delta over `/proc/stat`.
   - k6: sum of `%cpu` for `pgrep -x k6` processes via `ps -o %cpu=`.
2. `report.py`: per cell, report `mhz_avg`, `mhz_min/mhz_max_ratio` (within
   the measure window), `temp_max`, `k6_cores_avg`. Flag
   `clock_variance` when the window's mean MHz drops more than 15% below the
   window's max, and `generator_saturated` when
   `k6_cores_avg > 0.8 × (host_cpus − stack_cap_cpus)`. Include these columns
   in `report.md` — they get published with the results.
3. `methodology.md`: document the new columns and the interpretation rule
   (per the re-examination above: cross-cell consistency of CPU-bound cells +
   flat MHz ⇒ throttling did not distort the run; sustained-but-constant
   reduced MHz ⇒ absolute numbers are conservative).

*Acceptance:* a 2-minute dummy cell produces a host.csv with plausible values
and the report renders the new columns; unplugging/replugging AC during a test
run visibly moves `cpu_mhz_avg`.

### A7. Keep secrets out of shareable results — **Sonnet**

*Files:* `benchmarks/runner/seed.sh`, `benchmarks/justfile`.

Move `results/<target>.seed.env` (contains client secrets/passwords) to a
non-results location (`benchmarks/.seed/` — add to `.gitignore`), teach
`run-benchmark.sh`/scenarios to source it from there, and add a
`just bench-pack` recipe producing a `results-<date>.tar.xz` that contains
only `*.k6.json`, `*.res.csv`, `*.host.csv`, `*.meta.json`, `report.md`.
*Acceptance:* the packed archive contains no secret material (grep for
`SECRET\|PASSWORD` returns nothing).

---

## Phase B — Server quick wins (small diffs, big numbers)

### B1. Bound concurrent Argon2id hashing (perf + memory-DoS fix) — **Opus**

*Files:* `crates/axiam-auth` (password verification path), config plumbing in
`crates/axiam-core`/`axiam-server`, docs.

Evidence: login benchmark pegged 2 cores and reached ~970 MiB RSS ≈ 50
concurrent × 19 MiB Argon2id arenas; p95 2.1 s; container cap 1024 MiB — an
unauthenticated memory-DoS vector and a tail-latency disaster.

1. Introduce a global `tokio::sync::Semaphore` around every Argon2 hash/verify
   (login, registration, password change). Permits =
   `AXIAM__AUTH__MAX_CONCURRENT_HASHES`, default `min(num_cpus, 4)`.
   Acquire with a configurable timeout (default 5 s); on timeout return the
   existing rate-limit-style 429/503 error path (pick the one consistent with
   the REST error taxonomy — do not invent a new error shape).
2. Verify the hash itself runs under `spawn_blocking` (it should already);
   review the blocking-pool sizing while there.
3. Tests: unit test that > N concurrent verifies serialize (use a slow test
   hash config); integration test that the endpoint returns the backpressure
   error under saturation rather than OOMing.
4. Document the new config key + the DoS rationale in the security docs, and
   add it to the bench compose pass-through (`targets/axiam/docker-compose.yml`)
   so the next run exercises it.
5. Do **not** weaken Argon2id parameters — OWASP params stay.

*Acceptance:* `oauth2_password_login` bench rerun: server RSS stays under
~350 MiB, p95 under 2 s at 50 VUs (throughput should rise; record before/after
in the PR description). Security tests pass.

### B2. Diagnose & fix the TLS 1.3 throughput halving on token endpoints — **Opus**

*Files:* `crates/axiam-server/src/tls.rs`, actix server setup, possibly
`benchmarks/scenarios/lib/*`.

Evidence: p2 vs p0 — client_credentials −55%, refresh −58%, introspection
−0.3%, jwks −13.9%; in degraded cells nothing is CPU-saturated and p50 merely
doubles ⇒ per-request fixed cost, not record crypto.

Ordered hypothesis list to test (instrument, don't guess):
1. **ALPN/protocol asymmetry:** over TLS k6 negotiates h2 if offered, while
   p0 plaintext is HTTP/1.1 — compare negotiated protocol per profile
   (`k6` metric `http_req_duration` doesn't show it; log ALPN server-side or
   use `k6`'s `http_version` tag). If h2 is the culprit, compare h2-disabled.
2. **Session resumption:** confirm rustls server config enables ticket-based
   resumption; count full vs resumed handshakes (rustls exposes this via
   `ServerConnection`; add a debug counter/log).
3. **Keep-alive:** verify actix keep-alive is identical between the plaintext
   and rustls binds; capture whether k6 reuses connections at p2
   (`http_req_connecting`/`http_req_tls_handshaking` k6 sub-metrics — they are
   already in the k6 JSON; check the existing 2026-07-19 raw files FIRST, this
   may answer the question with zero new runs).
4. `TCP_NODELAY` on the TLS listener.
Fix whatever is found; explicitly do **not** enable TLS 0-RTT (replay risk on
POST token endpoints) and record that decision in `docs/security-profiles.md`.

*Acceptance:* p2 client_credentials and token_refresh within ~15% of their p0
throughput on a laptop re-run of just those cells, introspection/jwks not
regressed, and a written root-cause note added to
`benchmarks/PRIVATE_BENCH_ANALYSIS.md`.

### B3. JWKS caching verification + HTTP caching headers — **Sonnet**

*Files:* `crates/axiam-oauth2` (JWKS handler), tests.

1. Verify the per-tenant JWKS response is served from an in-process cache
   invalidated on key rotation (the 0.062 cpu·ms/req strongly suggests it —
   confirm and document; if not, add one).
2. Add `Cache-Control: public, max-age=300` (configurable) and a strong `ETag`
   (hash of the key set) with `If-None-Match`/304 handling.
3. Unit tests: 304 on matching ETag; ETag changes on rotation.

*Acceptance:* tests pass; a curl loop shows 304s; no behavior change for
consumers that ignore caching.

---

## Phase C — Re-run protocol on the laptop (config/orchestration only)

### C1. Median-of-N runs — **Sonnet**

*Files:* `benchmarks/justfile`, `benchmarks/runner/run-benchmark.sh`,
`benchmarks/runner/report.py`, `benchmarks/docs/methodology.md`.

1. Add `repeat := "3"` to the justfile; `bench-matrix` loops N times writing
   `results/run-<i>/<target>/<profile>/…` (keep the flat layout inside each
   run dir so existing code is reused).
2. `report.py`: when `results/run-*/` dirs exist, aggregate per cell by taking
   the **median independently per metric** (throughput, p50/p95/p99, cpu, mem)
   across valid runs; report `n_valid_runs` per cell and the throughput
   min–max spread as a `±%` column; a cell is valid only if ≥ 2 runs are valid.
3. Single-run layouts must keep working unchanged.

*Acceptance:* a 2-repeat mini-matrix (one target, one profile, two scenarios)
aggregates correctly and shows the spread column.

### C2. DB sensitivity + fair DB tuning — **Sonnet**

*Files:* `benchmarks/targets/*/docker-compose.yml`, `benchmarks/justfile`,
`benchmarks/docs/methodology.md`.

1. Add a `just dbcaps=uncapped bench-…` path that sets
   `BENCH_DB_CPUS`/`BENCH_DB_MEM` to 4 CPUs / 2048 MiB (already env-driven —
   just wire the justfile variable and record it in meta). Plan one AXIAM +
   one Zitadel pass with it to measure server ceilings when the DB isn't the
   wall.
2. Tune competitors' Postgres *minimally and uniformly* inside the standard
   1 GiB cap: `shared_buffers=256MB`, `effective_cache_size=512MB`,
   `max_connections=200` via compose `command:` flags on **both**
   Keycloak's and Zitadel's postgres services.
3. **Durability parity note:** document (methodology.md) Postgres
   `synchronous_commit=on` vs SurrealKV's flush/commit semantics under
   SurrealDB v3 defaults — investigate SurrealDB docs/source enough to state
   the comparison honestly; if they differ materially, add it to the public
   caveats list. Do not silently change durability settings to win.

*Acceptance:* compose files bring targets up healthy with the tuning; meta.json
records the DB caps + pg tuning flags; methodology documents the parity
statement.

### C3. Laptop variance-control runbook + cadence — **Sonnet**

*Files:* `benchmarks/docs/methodology.md` (new "Running on a laptop" section),
`benchmarks/runner/run-benchmark.sh`.

1. Runner: warn (not fail) when the CPU governor isn't `performance`; add
   `BENCH_CELL_PAUSE` (default 60 s) idle gap between cells to dissipate heat
   and let the previous cell's allocations settle.
2. Runbook (docs): plug into AC, `cpupower frequency-set -g performance`,
   optional stability mode `echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo`
   (run the whole matrix in ONE mode — never mix turbo/no-turbo runs in one
   dataset), close background apps, raise the laptop for airflow, and rely on
   A6 telemetry to verify.

*Acceptance:* runner shows the governor warning and honors the pause; docs
section exists and is linked from the README.

### C4. Prod rate-limit-posture run (AXIAM-only) — **Sonnet**

Using the existing `rl=prod` justfile path, run the AXIAM matrix once with
production limits active, and add a clearly-labeled section to `report.py`
output (`posture: prod — NOT comparable to competitors`, which `report.py`
already refuses to mix — verify that refusal works). Publish alongside the
neutralized numbers so operators see shipped-default limits, and the framing
"AXIAM ships per-IP rate limits by default; competitors don't" becomes
documented evidence.

*Acceptance:* report renders both postures without mixing them in comparison
tables.

---

## Phase D — Deeper product work

### D1. Fix the authz batch path (+ single-check p99 tail) — **Opus**

*Files:* `crates/axiam-authz`, batch handlers in `crates/axiam-api-rest` and
`crates/axiam-api-grpc`, integration tests.

Evidence: 5-check batch = 41 req/s REST / 22 req/s gRPC with p50 > 1.1 s while
the server idles at 0.07–0.11 cores and SurrealDB at ~1.2/2 — waiting, not
computing. Batch delivers *fewer* checks/s than single calls. Also: single
gRPC check p99 850 ms vs p95 173 ms.

1. Add tracing spans per batch item + per DB query; run one batch locally
   against the bench stack and read the trace — find the serialization point
   (sequential `await` per item? per-item transaction? N+1 hierarchy walk?).
2. Fix accordingly: execute items concurrently (`try_join_all`) and/or
   coalesce same-subject items into one query for roles/grants; the subject is
   identical for every item in the bench's batch, which should be the fast
   path.
3. Chase the single-check p99 tail with the same tracing (suspects:
   connection-pool exhaustion under burst, SurrealKV compaction stalls —
   check pool metrics first).
4. Integration test asserting batch-of-5 latency < 3× single-check latency.
5. Re-run the four authz cells; record before/after in the PR.

*Acceptance:* batch checks/s exceeds single-check checks/s (that's the whole
point of batching); authz_batch_grpc passes the 2 s p95 validity gate.

### D2. gRPC TLS termination — **Sonnet**

*Files:* `crates/axiam-server` (tonic listener setup),
`benchmarks/targets/axiam/docker-compose.native-tls.yml`,
`benchmarks/scenarios/lib/config.js`.

Today gRPC is plaintext in every bench profile (`BENCH_GRPC_PLAINTEXT=true`),
making the p2 matrix internally inconsistent. Tonic supports rustls: reuse the
existing server cert/key config (`AXIAM__SERVER__TLS__*` or a parallel
`AXIAM__GRPC__TLS__*` set, mirroring how the REST listener does it) to serve
gRPC over TLS when enabled. Update the native-TLS compose overlay to enable
it at p2 and set `BENCH_GRPC_PLAINTEXT=false` there; k6's gRPC client supports
TLS with skip-verify analogous to HTTP.

*Acceptance:* p2 bench run drives gRPC scenarios over TLS successfully;
plaintext default unchanged for p0.

### D3. Native mTLS (client-certificate) support — **Opus**

*Files:* `crates/axiam-server/src/tls.rs`, `crates/axiam-pki` (CA material),
auth extraction layer, `benchmarks/` p3 wiring, docs.

Today p3-mtls requires an nginx edge (rustls listener is server-auth only) —
unacceptable long-term for an IAM selling IoT mTLS, and it keeps proxy-header
identity assertion (a spoofing surface) in the trusted path.

1. Add `AXIAM__SERVER__TLS__CLIENT_AUTH = off|optional|required` +
   `AXIAM__SERVER__TLS__CLIENT_CA_PATH` (PEM bundle). Build the rustls
   `ServerConfig` with the corresponding `WebPkiClientVerifier`.
2. Expose the verified peer certificate (DER + parsed SAN/SPKI) to request
   handlers via connection extensions, so the certificate-auth flow
   (cert-mapped identities, per CLAUDE.md the PKI feature set) consumes the
   *verified* cert, never a header.
3. Wire the bench: route p3 to the native overlay in `bench-up` (mirroring the
   p2 change from commit 649798e), CA = `profiles/certs/ca.crt`, k6 already
   sends client certs via `tlsAuth`.
4. Tests: handshake rejected without cert when `required`; accepted +
   identity extracted with the bench client cert.
5. Decision to record in docs (not code): p1-tls12 stays nginx-fronted or
   N/A-by-policy — AXIAM is TLS 1.3-only natively per the security standards;
   state it in `docs/security-profiles.md`.

*Acceptance:* full p3-mtls bench run against native AXIAM (no nginx container
in `docker ps` during the run); unit/integration tests pass.

### D4. Zitadel gRPC benchmark coverage — **Sonnet**

*Files:* `benchmarks/scenarios/` (new), `benchmarks/scenarios/proto/zitadel/`
(vendored), `benchmarks/docs/methodology.md`, `benchmarks/runner/run-benchmark.sh`.

Keycloak has no gRPC — fine. Zitadel's primary API is gRPC and must be
benchmarked (maintainer requirement).

1. Vendor the minimal Zitadel proto set (auth + session services) under
   `scenarios/proto/zitadel/` with a README noting source version (pin to the
   benched Zitadel tag, currently v4.15.2).
2. New scenarios (k6 `k6/net/grpc`, mirroring `authz_check_grpc.js`
   structure): `zitadel_userinfo_grpc.js`
   (`zitadel.auth.v1.AuthService/GetMyUser` with the bench PAT/token) and
   `zitadel_introspect_equivalent` only if a comparable RPC exists — do not
   force equivalences that don't exist.
3. Comparability labeling in methodology + report: these pair with AXIAM's
   gRPC scenarios as "protocol-efficiency" measurements (REST vs gRPC within
   each vendor), NOT as cross-vendor head-to-head unless the logical op
   matches exactly; document which is which.
4. Wire the scenarios into the runner's Zitadel scenario list.

*Acceptance:* Zitadel p0 run produces valid cells for the new scenarios;
report labels them per §3.

### D5. Real Zitadel login (session API) — **Sonnet**

*Files:* `benchmarks/scenarios/lib/targets.js`, `benchmarks/runner/seed.sh`.

Replace the client-credentials fallback in `zitadel.login()` with Zitadel's
session API v2 (`/v2/sessions` create with password check factor over REST) so
`oauth2_password_login` measures an actual password verification on all three
targets. Seed: ensure the bench human user exists with a password (extend the
Zitadel management-API seeding that already provisions the machine user). If
the session flow can't return an OAuth2 access token directly, measure session
creation itself and label the cell "login (session create)" — the logical op
"password verified per request" is what must match. Keep the A3 fallback tag
for configurations where the session API is unavailable.

*Acceptance:* Zitadel login cell exercises password verification (confirm via
latency signature — it should drop from 405 req/s to a hash-bound rate — and
via Zitadel logs), and the report no longer flags it as fallback.

### D6. SurrealDB tuning & connection-pool investigation — **Opus**

*Files:* investigation notes in `claude_dev/`, potential changes in
`crates/axiam-db`, `benchmarks/targets/axiam/docker-compose.yml`.

With C2's uncapped-DB data in hand: profile the authz/token hot paths' query
patterns (`RUST_LOG=surrealdb=debug` or DB-side slow-query logging), check
`axiam-db` pool sizing vs the 50-VU load (server idle + DB pegged suggests the
DB itself is the cost, but rule out pool starvation — instrument pool
wait-time), and evaluate SurrealDB run modes for the bench DB container
(SurrealKV on NVMe vs in-memory — only as a labeled sensitivity data point,
respecting the C2 durability-parity rules). Output: a
`claude_dev/surrealdb-tuning-report.md` with findings and any code/config PRs
that follow from it.

*Acceptance:* report exists with quantified findings; any recommended change
lands as its own PR with before/after cell numbers.

### D7. Authz decision caching (design + implement behind a flag) — **Opus**

*Files:* `crates/axiam-authz`, config, docs, tests.

Only start after D1 + D6 (don't cache around a fixable inefficiency).
Design: per-tenant cache of effective-permission evaluations keyed
`(subject, resource, action, scope)`, short TTL (default ~5 s) **plus**
event-driven invalidation hooks on role/grant/resource mutations (the additive
allow-wins model of v1.0-beta makes stale-negative the only dangerous
direction — a revocation must invalidate immediately, so wire invalidation to
the mutation paths, not just TTL). Feature-flagged
(`AXIAM__AUTHZ__DECISION_CACHE_*`), default **off**; document the
staleness/security trade-off explicitly (revocation latency ≤ TTL bound even
if an invalidation event is missed). Include bench before/after.

*Acceptance:* with cache on, authz_check_rest/grpc throughput materially
increases with SurrealDB no longer pegged; revocation integration test proves
a removed grant is enforced immediately via invalidation.

### D8. Rate-limiter key configurability — **Sonnet**

*Files:* `crates/axiam-api-rest/src/config/rate_limit.rs` (+ gRPC config),
docs.

Lesson from the bench's single-source-IP constraint: per-IP keys collide for
NAT'd fleets. Add `AXIAM__RATE_LIMIT__KEY = ip|client_id|ip_client_id`
(default `ip`, current behavior) applied where a client identity is present
(token/introspect/revoke endpoints); login keeps per-IP (no client identity
yet at that point — document this). Unit tests per key mode.

*Acceptance:* tests demonstrate independent buckets per client_id under one IP
in `client_id` mode; default behavior unchanged.

### D9. Memory-retention experiment (allocator) — **Sonnet**

*Files:* experiment only; possible one-line change in `crates/axiam-server`
+ `Cargo.toml`.

Evidence: server RSS never returns to baseline after the login burst (~93 →
~646 MiB permanently). Reproduce locally (login burst, then watch RSS for
10 min), then A/B the binary with jemalloc (`tikv-jemallocator`) with decay
tuning vs default malloc. B1's semaphore will already cap the peak; this task
is about the *retention*. If jemalloc materially improves retained RSS without
throughput cost, propose it; otherwise write the negative result down in
`claude_dev/` and close. Escalate to Opus only if the data is confusing.

*Acceptance:* a short experiment note with numbers, and either a PR or a
documented "not worth it".

---

## Phase E — Deferred (tracked, not scheduled)

- **E1. SDK client-side benches: implement, validate, and run** — despite the
  README's "all 7 wired" wording, the maintainer confirms `benchmarks/sdk/` is
  effectively stubs today: none of the benches has ever produced a validated
  `status: "ok"` record against a live target, and four languages are pure
  `emit_pending` scaffolds. Treat every bench as unimplemented until it emits
  a spec-conformant OK record. Sub-tasks:

  **E1.1 Validate & repair the 7 code-bearing benches — Sonnet, one task per
  language** (`rust/`, `python/`, `typescript/`, `go/`, `java/`, `csharp/`,
  `php/` — bench sources exist but are unexecuted). For each language:
  1. Check out the sibling `ilpanich/axiam-<lang>-sdk` repo next to the
     workspace (each bench builds against it via local path/replace/project
     reference per its `TODO.md`).
  2. Bring up + seed the AXIAM target (`just target=axiam bench-up bench-seed`),
     source the seed env, then `just sdk=<lang> sdk-bench`.
  3. Fix whatever breaks — build errors, SDK API drift vs `sdks/CONTRACT.md`,
     env handling — until the bench runs its warm-up + measured loop for all
     four ops (`login`, `refresh`, `check_access`, `batch_check`) and prints
     exactly one `axiam.sdk-bench/v1` JSON record (see `sdk/HARNESS-SPEC.md`)
     with `status: "ok"`, real latency percentiles, and client-side
     CPU/RSS figures.
  4. Validate the record against the spec (`sdk/collect.py` must ingest it
     without warnings) and update the language's `TODO.md` to reflect reality.
  *Acceptance per language:* `just sdk=<lang> sdk-bench` emits a valid OK
  record twice in a row against a seeded p0 target; `collect.py` folds it in.

  **E1.2 Implement the 4 stub benches — Sonnet, one task per language**
  (`kotlin/`, `swift/`, `c/`, `cpp/` — currently `run.sh` → `emit_pending`
  only). Precondition: the corresponding `ilpanich/axiam-<lang>-sdk` repo
  must exist and be buildable — verify first; if the SDK isn't usable yet,
  stop and report instead of writing bench glue against nothing. Then follow
  the language's `TODO.md` recipe exactly: add the SDK dependency, implement
  the bench entrypoint (mirror `python/bench.py` / `typescript/bench.mjs` —
  the reference implementations: same env contract incl. the
  `BENCH_CLIENT_CERT/KEY/CA_CERT` triple for p3-mtls, warm-up + measured
  loop, four ops, one JSON record on stdout), and switch `run.sh` from
  `emit_pending` to executing it. Same acceptance as E1.1.

  **E1.3 Cross-SDK run + report integration — Sonnet.** Once ≥ the 7 primary
  benches pass E1.1: run `just sdk-bench-all` against a seeded p0 and p2
  target, extend `runner/report.py` (or `sdk/collect.py`) to emit the
  **overhead-vs-wire-baseline table** — each SDK's `check_access`/
  `batch_check` p50/p95 and throughput next to the raw
  `authz_check_rest`/`authz_batch_rest` k6 wire baseline from the same
  target/profile, plus `login`/`refresh` against their scenario baselines —
  and add the table to the published report. Fix the `sdk/README.md`
  status claims to match measured reality.
  *Acceptance:* report renders the SDK overhead table from real records;
  every SDK row links to a `status: "ok"` result file; remaining `pending`
  languages are listed as pending, not claimed as wired.
- **E2. AMQP async-authz load harness** — **Opus** (new tool: publisher/
  consumer pair measuring end-to-end decision latency + consumer throughput,
  per `benchmarks/README.md` "out of scope" note; design doc first).
- **E3. Server-class hardware re-run** — blocked on budget; when available,
  repeat Phase C protocol unchanged and update the public doc's draft label.
- **E4. Public doc refresh** — **Sonnet** — after A+B+C land and a fresh
  median-of-3 matrix exists: regenerate `benchmarks/PUBLIC_BENCH_ANALYSIS.md`
  numbers, move resolved caveats (userinfo, ROPC, TLS penalty, throttling
  telemetry) from "weaknesses" to "fixed since draft 1", keeping the honest
  tone.

---

## Execution order & dependency summary

```
Phase A (A1–A7, parallelizable)        → unblocks a fully-valid matrix
Phase B (B1, B2, B3 independent)       → biggest product wins, small diffs
Phase C (C1–C3 before the re-run;
         C4 anytime after A5)          → re-run: median-of-3 + sensitivity
   → RE-RUN MATRIX on the XPS (A6 telemetry proves/disproves clock effects)
Phase D: D1 → D6 → D7 (sequential); D2, D3, D4, D5, D8, D9 independent
Phase E: E4 after the Phase C re-run; E1/E2 when capacity allows; E3 blocked
```

Model split summary: **Opus** — B1, B2, D1, D3, D6, D7, E2 (debugging,
security-sensitive server internals, cache/verifier design). **Sonnet** —
everything in Phase A and C, B3, D2, D4, D5, D8, D9, E1, E4 (well-specified
edits with acceptance criteria above). Every Opus task should end by
recording its findings in `claude_dev/` so the next agent inherits the
evidence, not just the diff.

---

## Implementation status (updated 2026-07-19)

Implemented on branch `claude/benchmark-improvement-plan-9yxx7g`. **Every task
was implemented with the model the plan assigns to it** (Opus tasks via Opus
agents, Sonnet tasks via Sonnet agents). All code compiles and all unit/
integration tests written for these changes pass in the dev sandbox.

**One environment caveat governs the whole table:** the sandbox is **not** the
benchmark laptop — it has `cargo`/`docker`/`node`/`python` but **no `k6` and no
live target stacks**. So acceptance criteria that are a *measured benchmark
number* (throughput/RSS/p95/latency-signature) are implemented and unit-tested
here but their **measured confirmation is done by the maintainer's laptop
re-run** — marked "⏳ pending re-run" below. No benchmark number was fabricated.

Legend: ✅ done & verified in-sandbox · ⏳ code done, measured acceptance pending
the laptop re-run · ⛔ blocked on external resources (documented).

| Task | Model | Status | Notes |
|------|-------|--------|-------|
| A1 userinfo scenario fix | Sonnet | ✅ | `mintUserToken` (login-first), KC `scope=openid`; smoke-run ⏳ |
| A2 seed hardening + smoke checks | Sonnet | ✅ | fail-closed provisioning, `seed.ok` gate |
| A3 fallback tagging | Sonnet | ✅ | `bench_fallback` counter; report excludes fallback cells |
| A4 complete `meta.json` | Sonnet | ✅ | image+digest, sha256, governor, k6 cores, etc. |
| A5 `report.py` improvements | Sonnet | ✅ | p50, blank invalid cells, bottleneck column, server-only efficiency |
| A6 host telemetry (mhz/temp/k6) | Sonnet | ✅ | `host-sampler.sh` + clock/gen-saturation flags |
| A7 secrets out of results | Sonnet | ✅ | `.seed/` relocation, `just bench-pack` |
| B1 bound Argon2id concurrency | Opus | ✅ / ⏳ | configurable semaphore + acquire-timeout backpressure; RSS/p95 ⏳ |
| B2 TLS 1.3 throughput fix | Opus | ✅ / ⏳ | root-caused h2-vs-h1 ALPN; resumption+ticketer, HTTP2 knob, 0-RTT declined; ±15% ⏳ |
| B3 JWKS caching + headers | Sonnet | ✅ / ⏳ | in-proc cache, ETag/304, Cache-Control; curl-loop ⏳ |
| C1 median-of-N runs | Sonnet | ✅ | `repeat`, run-*/ aggregation, ±% spread |
| C2 DB sensitivity + fair pg tuning | Sonnet | ✅ | `dbcaps=uncapped`, uniform pg flags; durability parity flagged unverified |
| C3 laptop variance runbook | Sonnet | ✅ | governor warn + `BENCH_CELL_PAUSE`, docs |
| C4 prod rate-limit posture | Sonnet | ✅ | non-comparable section; posture-mix guard verified |
| D1 authz batch coalescing | Opus | ✅ / ⏳ | same-subject coalescing (REST+gRPC) + tracing + round-trip test; cell re-run ⏳ |
| D2 gRPC TLS termination | Sonnet | ✅ / ⏳ | bench wiring (server support pre-existed); live p2 ⏳ |
| D3 native mTLS | Opus | ✅ / ⏳ | client-auth verifier + verified-cert via `on_connect`; in-proc handshake tests pass; full p3 no-nginx run ⏳ |
| D4 Zitadel gRPC coverage | Sonnet | ✅ / ⏳ | vendored proto + `GetMyUser` scenario; live round-trip ⏳ |
| D5 real Zitadel login (session API) | Sonnet | ✅ / ⏳ | `/v2/sessions` password check; shapes confirmed on live Zitadel ⏳ |
| D6 SurrealDB tuning investigation | Opus | ✅ / ⏳ | static query-pattern + pool analysis (report exists); quantified runtime findings need uncapped-DB data ⏳ |
| D7 authz decision cache | Opus | ✅ / ⏳ | flagged (default off), event-driven invalidation; revocation proven in tests; throughput ⏳ |
| D8 rate-limiter key config | Sonnet | ✅ | `ip\|client_id\|ip_client_id`; login stays per-IP; tests pass |
| D9 allocator experiment | Sonnet | ✅ / ⏳ | opt-in `jemalloc` feature + experiment note; RSS A/B ⏳ |
| E2 AMQP async-authz harness | Opus | ✅ | design doc landed (`claude_dev/`); build-out deferred per plan |
| E1.1 validate 7 SDK benches | Sonnet | ⛔ | needs sibling `axiam-<lang>-sdk` checkouts + a live seeded target + per-language toolchains — absent in this container |
| E1.2 implement 4 stub benches | Sonnet | ⛔ | plan's own guardrail: stop-and-report when the SDK isn't usable; SDK repos not present |
| E1.3 cross-SDK run + report table | Sonnet | ⛔ | depends on E1.1 |
| E3 server-class hardware re-run | — | ⛔ | blocked on hardware/budget (explicitly out of scope in the plan) |
| E4 public doc refresh | Sonnet | ⛔ | needs the fresh median-of-3 numbers from the laptop re-run |

**Summary:** Phases **A, B, C, D fully implemented** (23/23 tasks) + **E2**.
The remaining Phase E items (E1.\*, E3, E4) are blocked on resources this
sandbox cannot provide (live target, sibling SDK repos + toolchains, server-
class hardware, fresh re-run numbers) and are the natural follow-ups after the
maintainer's re-run. Measured-number acceptance across A–D is validated by that
re-run; every logic/security change is already covered by passing tests here.
