# Benchmark run 6 — execution runbook

- **Date written**: 2026-10-06 (T23.10.2(a), Phase 23 wave W6a)
- **What run 6 measures**: the released **`1.0.0-beta18`** server image —
  `ghcr.io/ilpanich/axiam/server:1.0.0-beta18`, tag `v1.0.0-beta18` — a release the
  maintainer cuts from `main` **after W6a merges** (D-75), so it contains W1–W5 and
  this wave's harness. **Do not build the server from source** — see §1.0.
  - **Commit the tag points at: `____________` — filled in by the maintainer when the
    tag is cut.** (The provenance preflight, §1.1, checks the image's `build_ref`
    against `origin/main`; the commit is recorded here, not guessed.)
- **The four pinned versions** (fixed at W6 kickoff, 2026-10-06):

  | Target | Version | Image (default in the compose file) | Notes |
  |---|---|---|---|
  | AXIAM | **`1.0.0-beta18`** | `ghcr.io/ilpanich/axiam/server:1.0.0-beta18` (derived from the workspace version by `bench-up`) | SurrealDB `surrealdb/surrealdb:v3` (floating tag, **pinned by digest in §12.4**), RabbitMQ `rabbitmq:4-management-alpine` |
  | Keycloak | **26.8.0** | `quay.io/keycloak/keycloak:26.8.0` (`BENCH_KEYCLOAK_IMAGE`) | PostgreSQL 16. The only 26.8.x tag when this was written (Docker Hub, `keycloak/keycloak:26.8.0`, released 2026-10-01). **§1.3 re-checks quay.io for a later patch before the run.** |
  | Zitadel | **v4.19.4** | `ghcr.io/zitadel/zitadel:v4.19.4` (`BENCH_ZITADEL_IMAGE`) | PostgreSQL 16 |
  | authentik | **2026.8.3** | `ghcr.io/goauthentik/server:2026.8.3` (`BENCH_AUTHENTIK_IMAGE`) | server + worker + PostgreSQL 16, no Redis |

- **Predecessors**: [`improvement-after-run5-benchmark.md`](improvement-after-run5-benchmark.md)
  (the A/B/E items run 6 collects data for), `benchmarks/PUBLIC_BENCH_ANALYSIS.md` (the
  **sixth draft**, run 5, `1.0.0-alpha24`) and [`run5-runbook.md`](run5-runbook.md), whose
  structure this keeps.
- **Audience**: the maintainer, who executes the matrix **off the sandbox** on the G-box
  (Dell XPS 15 9570, i7-8750H, 12 logical CPUs, ~31 GiB — the box every prior draft used),
  and then sends the results back. The **seventh draft** (T23.10.2(b), wave **W6b**) is
  written from what comes back; §10 says exactly what that is, and §11 what the draft
  will consume.

Run 6 has five jobs, in this order of importance:

1. **Re-measure the matrix** against the product as it is now, with **authentik 2026.8.3 as a fourth
   target**, Keycloak 26.8.0 and Zitadel v4.19.4, on the same box with the **run-5 caps**
   (G-10). Draft seven has four targets; the three comparison documents' performance rows
   are rewritten from it.
2. **Measure Keycloak 26.8's "reduced memory usage" as Keycloak ships it** — at rest and
   under load, at its defaults, with no tuning (§2.7).
3. **Measure AXIAM's minimal profile** (no broker, one instance) — whole-stack resting
   footprint with the released image, and a small set of cells under load (§2.5, G-8).
4. **Re-run the limiter table** and the **refresh** explanation that draft six left open
   (`improvement-after-run5-benchmark.md` A1, A2), and collect the cells it asked for
   (A4, B1's gate, E3, E4) that the harness supports today (§3).
5. **Repeat the SDK pass** (§12.13), as run 5 did.

Read §0 and §1 before touching anything: several defaults changed under the harness since run 5
(§0.3), and some of them change what a plain command line measures without saying so.

> **Just want the commands?** [**§12 is a complete copy-paste script**](#12-exact-commands--the-copy-paste-reference)
> for the whole run, in order, with every environment variable and parameter spelled out.
> §0–§11 explain *why*; §12 is what you type.

---

## 0. What changed since run 5 (and what that means for the numbers)

Run 5 measured `1.0.0-alpha24` (2026-08-04). The source of this section is `CHANGELOG.md`
from `[1.0.0-alpha25]` through today's `[Unreleased]` (about forty releases) and
`improvement-after-run5-benchmark.md`; only what moves a number is listed.

### 0.1 AXIAM

| Change | Where | Effect on run-6 numbers |
|---|---|---|
| **Shared rate-limit counter is a sliding window** that counts admitted capacity, refunds downstream rejections, and gives a newly seen key its pro-rata share plus an explicit **10 % burst allowance** (not below 20/min — no machine endpoint). Rollback: `AXIAM__RATE_LIMIT__SHARED_WINDOW=fixed`. | alpha25 (A1/J1) | **The `rl=prod` table is expected to change shape.** Run 5: gRPC families admitted 1/20–1/33 of configured, REST machine endpoints over-admitted by up to +50 %. Run 6 re-runs it (§3.1); the ±10 % bar is unchanged. Do not compare run-5 prod cells as like-for-like. |
| **New rate-limit families**, all per-IP, all with a limiter wrapped around a real route: `device_authorization` 12/min, `device_verify` 10/min, `token_exchange` 120, `uma_perm` 120, `uma_ticket` 120, `par` 120, `end_session` 30, `dcr` 5, **`bc_authorize` 60** (CIBA initiation; presets 600 / 6 000), **`ciba_approval` 30** (per route, never preset), `scim` 600 (never preset), `directory_admin` 30, `saml_admin` 30, `ssf` 60, `ssf_admin` 30, `scim_target_admin` 30, `device_login` 60 (presets 300 / 3 000), `webauthn` 10. | alpha25 – today | The `internet` defaults of the families run 5 asserted are **unchanged** (token 120, introspect 600, revoke 60, authz_check 1 800, login 10; gRPC 100/s authz = 6 000/min, 500/s identity = 30 000/min, 10/s admin = 600/min, 100/s infra = 6 000/min — read off the source on 2026-10-06; the `gateway`/`mesh` presets were **not** re-compared with alpha24, whose history this repository's checkout does not reach, and gain `bc_authorize` and `device_login` rows). Only the `rl=neutralized` posture raises families (§2.6 lists which); **no scenario drives CIBA, SSF, SAML/directory/SCIM-target admin or DCR**, so those stay at their defaults in every pass and `rl-prod-check` lists them as "not checked". |
| **Refresh rotation is three datastore round trips, not five** (atomic `consume_by_token_hash`, TTL cache for the per-refresh tenant lookup). | alpha25 (A2/J2) | `token_refresh` was 839 → **545/s** between runs 4 and 5. Run 6 should move it; the stage timings (§3.2) say why. |
| **Single-use redemption is two layers** for UMA tickets, RFC 8628 device grants, PAR `request_uri`s **and the authorization code**: the guarded `UPDATE` inside an explicit transaction, plus a nonce read back after commit — one extra write and one extra read per redemption. | alpha25 (X6), later | `oauth2_authorize`, `device_flow_poll`, `uma_ticket_grant` pay it. These cells did not exist in the run-5 matrix; they have no run-5 baseline. |
| **Authorize path** reads the client's `managed_by` from a bounded 60 s cache again (a T21.4 change had added a second client read: −19 % throughput, 609 → 495/s). | beta16 | `oauth2_authorize` (new cell). |
| **AMQP is TLS-only**; the broker hop was plaintext through run 5. | alpha27 | AMQP-carrying figures are **not comparable across it**, and RabbitMQ's resident set carries TLS state. The AXIAM target has used `amqps://` since; run 5's did not. |
| **OPAQUE replaced SRP**; `opaque_login_start`, `opaque_register_start` exist. | alpha32/38 | New cells, no baseline. |
| **gRPC strict session-revocation mode** (`AXIAM__GRPC__STRICT_REVOCATION`, default `false`), read-replica routing primitive (`AXIAM__DB__READ_REPLICAS`, **off**), decision-cache broadcast (default off), session-revocation feed (default off). | alpha25 – beta13 | Defaults leave the run-5 posture. Strict mode is a labelled sensitivity cell (§3.3). The read-replica primitive has **no replica in the harness** and is not measured. |
| **Contended write is `503` + `Retry-After: 1`, not `500`.** | beta13 | `scim_provisioning` lost optimistic-concurrency races as 500s in run 5's era; they are 503s now. Read its error count with that in mind. |
| **Phase 23 features**: the SAML IdP, directory sources, the SSF transmitter, outbound SCIM provisioning, CIBA, dynamic client registration, per-tenant path issuers. | W1–W5 | All off or empty unless configured; none is driven by a benchmark scenario. They add code, background jobs and a schema (v84) to the binary: **resting RSS and boot time may be higher than alpha24's**, and §2.5 measures it. |
| **The minimal profile** (`AXIAM__AMQP__ENABLED=false`): SurrealDB and the server, no broker, **single instance by definition** (a singleton lease; a second instance is refused at boot), outbound deliveries and mail on in-process queues that are **lost on restart (T-445)**. | W5 (G-8) | §2.5. Its footprint is that of a profile that gives up the broker's durability and is **never** the full profile's. |
| **SurrealDB** `surrealdb/surrealdb:v3` is a floating tag (3.2.5 on 2026-10-05). | — | Pinned by digest in §12.4; the digest goes in the draft. A version change between runs is a confounder, so say which. |
| **Account lockout is a per-tenant / per-organization policy** (D-06): the compose variable is only the fallback for a check that cannot resolve a tenant, and the bench org's own settings row carries the shipped threshold of 5. | after run 5 | `runner/seed.sh` PUTs the neutralized threshold onto the org's settings after bootstrap (the step that actually holds). Without it `grpc_admin_validate`'s wrong-password flood locks the bench user and six later cells read 401. The dry run (§12.5) is what proves it holds on beta18. |

### 0.2 The competitors

| Target | Run 5 → run 6 | What moves a number (source: the upstream release notes and defaults, read at the tags) |
|---|---|---|
| **Keycloak** | 26.7.0 → **26.8.0** | Quarkus 3.33 → **3.40** (3.40.1 in the startup banner). **Login failures are stored in the database by default** (`login-failures:v2`) — the release notes call out "increased database connection usage and higher CPU usage on the database" — so watch Keycloak's PostgreSQL CPU in the login cell. **SCIM API and client secret rotation are enabled by default** (supported); both stay as shipped. The "use refresh tokens for client credentials" switch is deprecated (the client-credentials cell does not use it). Refresh-token expiry is now capped by the session idle timeout. Headline: *"reduced memory usage, and enhanced HTTP performance"* — see §2.7: the notes give no figure and no new flag. |
| **Zitadel** | v4.16.2 → **v4.19.4** | Every variable the target sets (`ZITADEL_DATABASE_POSTGRES_*`, `EXTERNAL*`, `TLS_*`, `FIRSTINSTANCE_*`, `SYSTEMDEFAULTS_PASSWORDHASHER_HASHER_COST`, `start-from-init --masterkey --tlsMode`) **exists unchanged in both versions' `cmd/defaults.yaml` / `cmd/setup/steps.yaml`** (diffed; the only additions are DCR, an events-table autovacuum switch that is off, a sessions-projection bulk limit, an instrumentation-detector list). v4.19.2 made session-cookie signing mandatory (a breaking change that the baseline comparison notes) — **the seed and the login cell use the session API, which this runbook could not test against v4.19.4** (the image cannot be pulled where it was written): the dry run is the check. v4.18.0 was withdrawn. |
| **authentik** | **new target**, 2026.8.3 | First measurement. §2 and §6 carry its caveats. |

### 0.3 The harness (what a plain command line does now)

| Change | Why you care |
|---|---|
| **Per-stack generated credentials for every target** (`runner/bench-creds.sh`); no credential literal anywhere. `bench-down` removes `.seed/<target>.stack.env`. | A k6 scenario run **by hand** needs the seed env exported (§12.1 note); nothing falls back to a default any more. |
| **`rl=prod` now pins the seven REST families** added since alpha24 (device_authorization, token_exchange, uma_perm, uma_ticket, par, end_session, scim) from the Rust source. | Without it they kept the neutralized 1 000 000 under the "shipped" posture and `rl-prod-check` FAILed a posture the harness never applied (`just bench-rl-posture-selftest`, CI). |
| **`deploy=minimal`** and `targets/axiam/docker-compose.minimal.yml`; `BENCH_EXPECT_DEPLOY`; `meta.json` field `axiam_deploy_profile`; a report banner. | §2.5. |
| **`BENCH_SCENARIO_ONLY`** (the inverse of `BENCH_SCENARIO_EXCLUDE`). | One invocation runs a chosen cell set behind one settle gate. |
| **`runner/pull-pinned-images.sh`**, **`runner/resting-sample.sh`**, **`runner/record-provenance.sh`**. | §12.4, §12.6. |
| **`image_digest` in `meta.json` is the registry digest.** It was the image id (the container has no `RepoDigests`; the old read always fell through), which equals the digest only on the containerd image store. | Provenance is real now; run 5's `image_digest` values are image ids where the digest and id differ. |
| `meta.json`'s `caps.mem` and the per-role fallbacks said `1024m`; the compose default is `2048m`. Fixed. | `containers[].mem_cap_mib` (read off the running container) was always right; use it. |
| `bench-pack` includes every `*.json/csv/tsv/md/log/txt` under `results/` (E2) and prunes `dry-run` and any name containing `seed`. | **Name your own artifacts accordingly** — a stage called `seeded` would be silently dropped (the resting sampler refuses it). |
| `E1`: `BENCH_REQUIRE_ENV`; `E3`: `bench-bulk-seed`; `A5`: the refresh pool is paced inside the login bucket under `rl=prod`. | §3. |
| **`bench-down` now also removes `.seed/axiam.bulk.env`.** The bulk-seed record (fixture scale, deny ratio) outlived its datastore volume and labelled every later cell a 10× fixture, exporting `BENCH_SEED_DENY_RATIO` into the next run. | §12.11's seed-size block depends on it: after it, the next stack is the base fixture again. |
| k6 was v2.1.0 in run 5. | Record `k6 version`; if yours differs, say so in `RUN6-NOTES.md` (the sandbox that wrote this ran 2.3.0). |

### 0.4 Comparability warning

> **Run 6 is not a like-for-like re-run of run 5.** Every one of these moved between the
> runs: the AXIAM server (about forty releases, W1–W5), SurrealDB's build, Keycloak
> (a Quarkus upgrade and a different default for login failures), Zitadel (three minor
> releases), the rate limiter's window, the refresh path, the AMQP transport, k6 (maybe),
> and the AXIAM scenario set (26 scenarios now, against the 11 that ran in run 5's matrix).
> The caps, the box, the profiles, the load model (50 VUs closed loop, 30 s warm-up +
> 120 s measure, median of 3) and the validity gates are the same. **Treat run 6 as the
> new baseline; say where a delta against run 5 is a product change and where it is a
> harness change, and do not claim a trend across a boundary this section lists.** Where a
> controlled comparison is wanted, §3 toggles one variable at a time.

---

## 1. Preflight — do not skip

### 1.0 The image — the published `1.0.0-beta18`, not a build

Run 6 measures a **released artifact**: `ghcr.io/ilpanich/axiam/server:1.0.0-beta18`,
published by the release pipeline from `v1.0.0-beta18`. A local build is slower, is not
what a reader can reproduce, and loses the provenance preflight. As in run 5:

1. **Check out the release tag**, not a branch. The workspace version is what `bench-up`
   turns into the image tag, *and* `build_ref` in `meta.json` is this checkout's `HEAD`.
2. **Never pass `build=1`** to any recipe.
3. **`docker login ghcr.io` first**, and **pull explicitly** (§12.4). `bench-up` falls back
   to a **local source build** when the pull fails, which in a 17-hour matrix scrolls past.

The competitors are prebuilt images and are pulled by the same script.

### 1.1 Provenance

`run-benchmark.sh` refuses to start an AXIAM cell unless `build_ref` (the checkout's
`HEAD`) is an ancestor of `origin/main`. Checking out `v1.0.0-beta18` makes that pass by
construction; verify anyway (§12.2). **`build_ref` describes the checkout, not the image**
— nothing cross-checks them, so the tag checkout is what collapses the gap.
`BENCH_ALLOW_UNMERGED_BUILD_REF=1` is for deliberate pre-merge validation only: run 6 does
not need it, and needing it means the checkout is wrong.

### 1.2 Environment

- **Same box, same caps** (§2.3). Record any difference from run 5 in `RUN6-NOTES.md`.
- **Power and thermals.** AC power, performance governor if you can; run 4's hot cells hit
  96–100 °C. `BENCH_CELL_PAUSE` defaults to 60 s between cells; leave it. `mhz_avg` is
  recorded per cell, so a throttled cell can be found rather than averaged in.
- **Nothing else on the box.** No browser, no IDE indexing, no second Docker workload.
- **Software.** Docker Engine **≥ 25** (the authentik healthcheck uses `start_interval`),
  Docker Compose **≥ 2.24** (the minimal overlay uses `!reset`/`!override`), k6, `just`,
  `jq`, `openssl`, `python3`, `curl`, `git`. A **Linux** host: the resting sampler reads
  `/proc` (without it, it records the cgroup figure only and says so).
- **Registry logins.** `docker login ghcr.io` (PAT, `read:packages`) **and `docker login`
  for Docker Hub**: anonymous Docker Hub pulls are rate-limited (the sandbox that wrote
  this was answered `429` on the third pull), and the matrix pulls PostgreSQL, SurrealDB,
  RabbitMQ and possibly Keycloak and authentik from it.
- **`docker compose config`** needs every required variable; a bare run fails with
  `required variable … is missing a value`. That is the compose files failing closed.

### 1.3 Re-check for a later patch release (quay.io is unreachable from the sandbox)

The pins were fixed on 2026-10-06 as "the latest patch of each named line". For Keycloak that
was **26.8.0 — the only 26.8.x tag on Docker Hub**; `quay.io`, the registry the compose file
names, could not be reached from the sandbox, so **whether quay.io already has a later
26.8.x patch is unverified**. Check **before** pulling (§12.3 has the commands; the same
check for Zitadel `v4.19.*` and authentik `2026.8.*` is there too):

- **No later patch** → run the pins as they are.
- **A later 26.8.N exists** → run **that** patch for Keycloak: export
  `BENCH_KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.8.N` before `pull-pinned-images.sh`
  (the compose file's default stays `26.8.0`; the exported override is the audit trail, and
  `meta.json` records the image and its digest in every cell). Read that release's notes for
  anything touching memory, HTTP, sessions, token or introspection endpoints (patch releases
  are fixes, so this is a five-minute read), and **write the version actually run in
  `RUN6-NOTES.md`** so W6b and the three comparison documents name it, not "26.8.0".
- **A later minor (26.9.x)** is **not** a patch: do not take it. The line is the decision.

### 1.4 Credentials

Everything the stacks need is generated per run (`runner/bench-creds.sh`, §0.3). You do not
export a password. If you export one anyway (`BENCH_ADMIN_PASSWORD`, say), it wins and is
what the stack file records. **Never paste a credential into `RUN6-NOTES.md`, a log, or a
chat**; `bench-pack` refuses an archive that contains `SECRET`/`PASSWORD` text.

---

## 2. The cells

### 2.1 Which scenarios each target runs

`--scenario all` is filtered per target by `run-benchmark.sh`; `runner/scenario-filter-selftest.sh`
(CI) pins every set below, so these lists are what the runner does, not a description.

| Target | Scenarios | Count |
|---|---|---|
| **Keycloak** | `jwks_fetch`, `oauth2_client_credentials`, `oauth2_password_login`, `token_introspection`, `token_refresh`, `userinfo` | 6 |
| **authentik** | the **same six as Keycloak** | 6 |
| **Zitadel** | the same six, **plus `zitadel_userinfo_grpc`** | 7 |
| **AXIAM** | **everything not pending, opt-in or competitor-only**: the six shared, `userinfo_grpc`, `authz_check_rest`, `authz_check_grpc`, `authz_batch_rest`, `authz_batch_grpc` (the run-5 AXIAM set, **11**), and 15 more — `oauth2_authorize`, `oauth2_code_pkce`, `oauth2_discovery`, `oauth2_revoke`, `device_authorization`, `device_verify`, `device_flow_poll`, `token_exchange`, `uma2_perm`, `uma_ticket_grant`, `scim_provisioning`, `opaque_login_start`, `opaque_register_start`, `grpc_admin_validate`, `grpc_infra` | 26 |

Not in the default set: `oauth2_client_credentials_reactor_hook` (pending), `authz_nested_rest` /
`authz_nested_grpc` (labelled sweep rungs; `just bench-nested` is not part of run 6).

**Labels the report applies, which every table must carry:** authentik's
`oauth2_password_login` is **`protocol-variant`** — it drives authentik's flow executor (three
client calls, about six server requests, real PBKDF2-SHA256 verify), because its ROPC grant
accepts only an app-password token and never hashes (D-79); authentik's and Zitadel's
`token_refresh` are **`fallback-op`** (they measure client credentials, because neither issues a
refresh token non-interactively); Zitadel's `userinfo` is a machine-user token.

To keep the matrix at a length one can run, run 6 splits the AXIAM set (**the head-to-head core**
runs at every profile with median-of-3; **the 15 newer AXIAM-only cells** run at `p0` only):

```text
CORE (all four targets; names a target does not run are ignored for it):
  jwks_fetch.js oauth2_client_credentials.js oauth2_password_login.js token_introspection.js
  token_refresh.js userinfo.js zitadel_userinfo_grpc.js userinfo_grpc.js
  authz_check_rest.js authz_check_grpc.js authz_batch_rest.js authz_batch_grpc.js
NEW (AXIAM only, p0, median-of-3):
  oauth2_authorize.js oauth2_code_pkce.js oauth2_discovery.js oauth2_revoke.js device_authorization.js
  device_verify.js device_flow_poll.js token_exchange.js uma2_perm.js uma_ticket_grant.js
  scim_provisioning.js opaque_login_start.js opaque_register_start.js grpc_admin_validate.js grpc_infra.js
```

CORE is the run-5 set, so every cell has a run-5 counterpart; NEW has none (§0.1).

### 2.2 Profiles

- **p0-plaintext, p2-tls13, p3-mtls** for AXIAM, Keycloak and Zitadel, as run 5.
- **authentik runs p0 and p2 only. `p3-mtls` is refused** by `bench-up` and skipped by
  `bench-matrix` and `bench-dry-run` (its listener has no client-certificate mode; measuring
  plain TLS under an mTLS label is what this harness does not do).
- **authentik's p2 is its own self-signed listener: it accepts TLS 1.2 *and* 1.3 (k6
  negotiates 1.3) and serves HTTP/1.1 only.** It cannot be pinned to 1.3 or switched to h2, so
  **every authentik p2 number must carry that sentence.** Zitadel's p3 is server-TLS only (its
  built-in TLS has no client-certificate mode), as in run 5.

### 2.3 Caps (the run-5 caps; the box and the load model are unchanged)

| Container | CPU | Memory | Variable |
|---|---|---|---|
| every server container (AXIAM, Keycloak, Zitadel, authentik server) | 2 | 2 048 MiB | `BENCH_CPUS` / `BENCH_MEM` |
| **authentik worker** | 2 | 2 048 MiB | `BENCH_AUTHENTIK_WORKER_CPUS` / `_MEM`, **defaulting to `BENCH_CPUS` / `BENCH_MEM`** (D-79) |
| every database (SurrealDB, PostgreSQL ×3) | 2 | 1 024 MiB | `BENCH_DB_CPUS` / `BENCH_DB_MEM` |
| RabbitMQ | 1 | 512 MiB | `BENCH_MQ_CPUS` / `BENCH_MQ_MEM` |

**The configured ceiling of the stacks differs, and the report must state it:** authentik
**6 CPU / 5 GiB** (server + worker + database), Keycloak and Zitadel 4 CPU / 3 GiB, AXIAM full
5 CPU / 3.5 GiB, AXIAM minimal 4 CPU / 3 GiB. Setting `BENCH_MEM` moves the authentik worker
too (it is the same variable). The efficiency figures divide by **measured** cores and memory,
not by the ceiling; authentik's "server-only" variant is server **+ worker**.

Keycloak's login cell runs at the **shared 2 GiB**. Run 5 ran the promised 4 GiB attempt: it was
stable but at ~21/s with p95 ≈ 2.5 s, **slower** than the 2 GiB survivor cells, and the
conclusion drawn (J3) was to stop raising the cap. Run 6 does not repeat it. A Keycloak
heap-knob sweep (`JAVA_OPTS_KC_HEAP`) is **not wired into the harness** and is not part of
run 6.

### 2.4 The settle gate

The post-seed settle gate runs once per `bench-run` invocation. **authentik's default threshold
is 10 ops/s** (`BENCH_SETTLE_PROBE_THR`, recorded as `settle_probe_thr`): the 400 ops/s default
is calibrated on AXIAM and authentik cannot reach it at any time (its JWKS costs about a dozen
database transactions), so it would burn the whole timeout on every cell and stamp
`settle_timeout: true`, which `report.py` turns into refused cells. **At 10 ops/s the gate is a
liveness check and nothing more** — no post-seed transient has been characterised for authentik.
Leave a quiet minute or two between `bench-seed` and `bench-run`, and **once a settled rate is
known from run 6, raise the threshold for the next run** (W6b reports the observed rate).

### 2.5 AXIAM's minimal profile — how run 6 measures it

The profile (`AXIAM__AMQP__ENABLED=false`) is a **benchmark configuration now**, measured **as
`docker/docker-compose.minimal.yml` documents it: SurrealDB and the server, a single instance,
the lease held**. The harness form is `targets/axiam/docker-compose.minimal.yml`, layered by
`just deploy=minimal … bench-up`, under the same caps as every AXIAM cell, so a minimal cell
and a full cell differ in the broker and the in-process dispatcher and in nothing else. Two
measurements, both **always one instance** (no replica count exists anywhere in the harness,
the compose file refuses `--scale`, and the server itself refuses a second live instance):

1. **Whole-stack resting footprint** (§12.6) — `runner/resting-sample.sh` with the **released
   image**, for the full profile (server + SurrealDB + RabbitMQ) and the minimal profile
   (server + SurrealDB), at two stages (`fresh`: freshly migrated, empty datastore; `fixture`:
   the benchmark fixture in place), under the harness caps. This is *not* the 2026-10-05
   measurement (207.3 MiB minimal against 330.9 MiB full): that ran the **native release
   binary** beside SurrealDB and RabbitMQ containers and counted RSS from `/proc`; run 6's
   figure is the **image** inside its cgroup. Publish both, never one against the other.
2. **A small set of cells under load** (§12.10) — the seven cells `jwks_fetch`,
   `oauth2_client_credentials`, `oauth2_password_login`, `token_introspection`, `token_refresh`,
   `userinfo` and `authz_check_rest`, at **p0 only**, median-of-3, **in their own results tree**
   (`results/minimal-profile/`) so they are never medianed with full-profile cells, plus the same
   seven cells on the full profile, back to back, as a control (`results/full-profile-control/`).
   `meta.json` records `axiam_deploy_profile`, `report.py` banner-labels the cells, and
   `BENCH_EXPECT_DEPLOY` makes a stack that is not the profile the pass says fail in seconds.

**What the report must say (W5 security review §15, binding):**

- The minimal profile's **outbound deliveries are lost on restart (T-445)**, so **no reader may
  mistake its footprint for the full profile's**: it has no broker to pay for *and* it gives up
  the durability the broker provides.
- **Outbound SCIM targets stay disabled**: none is registered anywhere in the benchmark. A target
  on a dead host reproduces **P23W5-07** (a tarpit downstream stalls every tenant's provisioning on
  a replica; issue #550). If a cell ever needs one, it points at a **loopback server that answers**.
- **Any rate limit raised for a cell is stated in the report** (§2.6), and **the approval and SCIM
  routes' limits are never preset** — they are not raised without saying so (§2.6).
- No default-matrix scenario uses reactors, asynchronous authorization over AMQP, external audit
  ingestion over AMQP or the decision-cache broadcast (all four are `unavailable` in the profile),
  and nothing here exercises a restart, so the lost-delivery trade is stated, not measured.

### 2.6 Rate-limit posture, pass by pass

| Pass | Posture | What is raised | What is **not** raised (still at its shipped default) |
|---|---|---|---|
| Core matrix, NEW cells, minimal-profile cells, §3 investigations | **`rl=neutralized`** (the compose defaults) | the **16 REST families** the compose file lists, each to 1 000 000/min — login, register, token, password_reset, mfa, introspect, revoke, authz_check, token_exchange, end_session, par, uma_perm, uma_ticket, device_authorization, **scim**, webauthn — and the **three gRPC per-second ceilings** (authz 1 000 000, identity 5 000 000, admin 1 000 000); also the per-organization **lockout threshold** (1 000 000) | `device_verify` (its OWASP bound makes a large value a **boot refusal**, so `device_verify` is a throttled cell by design), **`ciba_approval`**, `bc_authorize`, `dcr`, `ssf`, `ssf_admin`, `saml_admin`, `directory_admin`, `scim_target_admin`, `device_login`; gRPC infra (fixed, not configurable). The competitors ship no per-IP limiter, so their posture is `n/a`. |
| **Production pass** (§12.9) | **`rl=prod`** — every family the compose file neutralizes is pinned to its **shipped** value (nine by hand in the justfile, seven from the Rust source) | nothing | everything above is at its shipped value; `rl-prod-check` compares admitted against configured, ±10 % |

State **in the report**, at every table: the posture (`rate_limits` in `meta.json`), and for the
neutralized passes that **`scim_per_min` was raised to 1 000 000 for the `scim_provisioning` cell**
(the SCIM route's limit is never preset in production; it was lifted for that cell, and only
there matters), and that **`device_verify` is throttled at its shipped 10/min**. Nothing run 6 does
raises `ciba_approval_per_min`, and no scenario calls it.

Keycloak and Zitadel ship no per-IP limiter (their posture is `n/a`); authentik's stock throttles
did not act on any measured endpoint in its smoke runs (zero 429s anywhere) — the run says whether
that held.

### 2.7 Keycloak 26.8's "reduced memory usage" — what is verified, and how run 6 captures it

**Verified (read at tag `26.8.0` of the keycloak repository: the release notes and the upgrading
guide):** the highlight is *"Simpler administration with automatic index creation, reduced memory
usage, and enhanced HTTP performance"* — **no figure and no new memory flag**. The notes credit two
mechanisms: (1) **login failures stored in the database by default** (`login-failures:v2`;
"reduces memory consumption from accumulated login failure entries", at the price of more database
connections and database CPU), and (2) caching of persistent user sessions **can be disabled**
(`--spi-user-sessions--infinispan--use-caches=false`) — **opt-in, not a default**. Keycloak sizes its
JVM heap as a percentage of the container limit (`MaxRAMPercentage=70`, `InitialRAMPercentage=50`
unless `JAVA_OPTS_KC_HEAP` overrides), so **the cap is part of the result**.

**Unverified:** that the claim holds for this workload. (1) only has entries to save in a workload
that *fails* logins; the benchmark's logins succeed, so a reduction seen in run 6 must **not** be
attributed to it without evidence (an inference from the notes, not a finding). The headline's "enhanced
HTTP performance" has no detail in the notes at all.

**So run 6 measures the claim as Keycloak ships it, at the run-5 caps, with no tuning** — nothing below
the defaults, nothing above the cap:

- **At rest:** `runner/resting-sample.sh keycloak fresh|fixture` (§12.6) — RSS, anonymous RSS and the
  cgroup working set of the server and of its PostgreSQL, medians over 60 s, recorded with the caps.
- **Under load:** the per-cell `res.csv` of every Keycloak cell (`mem_mib_avg`, `mem_mib_p95`),
  compared with run 5's 26.7.0 figures (server 710–853 MiB) at the **same** cap and cells.
- **Both** are reported whichever way they come out. **The 26.8 session-cache switch is not turned
  on**; if the maintainer wants it, it is a labelled, non-default cell and a separate decision (the
  harness does not pass the option through today).

### 2.8 Not in run 6 — harness support is missing

A read replica for SurrealDB (`AXIAM__DB__READ_REPLICAS` has no replica service in the harness);
SurrealDB worker-thread tuning (not forwarded by the compose file); an AMQP async-authz benchmark (k6
has no AMQP executor); an alpha24-versus-beta18 A/B on the same harness (alpha24 predates `amqps://`,
which the target's compose now requires); a Keycloak heap-knob sweep; the Keycloak session-cache
switch; a Zitadel low-cost-bcrypt cell (wired — `BENCH_ZITADEL_HASHER_COST` — and optional, §12.12).

---

## 3. Investigations run 6 also collects

`improvement-after-run5-benchmark.md` asks for these; each is supported by the harness today, each
runs in **its own results tree** and is reported as a labelled sensitivity cell, never medianed into
the matrix. The mandatory pass is §12.7–§12.13; these are §12.11, in value order.

### 3.1 A1 — the limiter table (mandatory: it is §12.9)

`rl=prod`, then `just rl-prod-check`. Run 5: gRPC families admitted 1/20–1/33 of configured, REST
machine endpoints over-admitted by +12 %…+50 %, login exact. The sliding-window counter (§0.1) is the
fix; the ±10 % bar decides. Three families had no scenario in run 5 and have one now (`oauth2_revoke`,
`grpc_admin_validate`, `grpc_infra`); all sixteen scenario-backed families are asserted separately, and
the check is a table of PASS/FAIL, not a narrative. **A FAIL is a result.** Expected configured values
are read from the source at the checkout (§12.9 prints them first, because the check reads the *local
tree* while the image enforces the limits — they agree only at the tag).

### 3.2 A2 — `token_refresh` (545/s in run 5, down from 839)

Run the cell once with the stage-timing instrumentation on: `RUST_LOG="axiam=warn,axiam::perf=debug"`,
**exported on `bench-up`** (the container's environment is fixed when it is created — run 5 lost a whole
investigation to exporting it for `bench-run`), with `BENCH_REQUIRE_ENV="RUST_LOG"` so a missing value
fails in seconds. The events carry `stage="auth.refresh"`, `consume_us`, `user_lookup_us`,
`session_create_us`, `token_mint_us`, `handler_total_us`. **Note the directive:** the events' target is
`axiam::perf`, and tracing matches a directive against the event's target by prefix, so `axiam_oauth2=debug` (what run 5's
runbook set) does not match it while `axiam::perf=debug` does (an inference from that rule, not a finding: the grep in §12.11
proves it either way). **Check the log is non-empty before trusting the cell** (§12.11 does).

### 3.3 A4 — strict revocation (the cost of REST's posture on gRPC)

`authz_check_grpc` and `authz_check_rest` under three arms: shipped (`STRICT_REVOCATION=false`), strict
with no session cache, strict with `SESSION_VALIDATION_CACHE_TTL_SECS=5`. One pass per arm, labelled.

### 3.4 B1's performance gate and E3 — deny-present authorization and seed size

`bench-bulk-seed` at scale 10 (10 000 users, 2 000 resources, depth 4) with the default 5 % deny ratio
**and** with `BENCH_SEED_DENY_RATIO=0`, against the base fixture, on `authz_check_rest`,
`authz_check_grpc` and `authz_batch_rest`. The no-deny path should be within ±2 % of the matrix cell
from the same run; the with-deny cell is published as a new labelled cell. Bulk users cannot
authenticate (a sentinel hash), so this touches only authorization.

### 3.5 A3 — the database concurrency ceiling

`dbcaps=uncapped` (4 CPU / 2 GiB for the datastore) against `capped`, with `AXIAM__DB__POOL_SIZE` 1 and 4,
decision cache and session cache **off**, on `authz_check_rest` and `authz_check_grpc` — the
connection-pool knobs `claude_dev/db-pool-design.md` describes, which the compose file forwards. (The read
replica and SurrealDB worker threads are §2.8.)

### 3.6 authentik — the database is the ceiling

authentik's cheap endpoints are PostgreSQL-bound (the DB container hit its 2-core cap in the smoke runs;
about 14 / 23 / 72 / 203 transactions per request for JWKS / userinfo / introspection / client
credentials). A **`dbcaps=uncapped` labelled pass** on its six cells shows how much of its figure is the
2-CPU database; it is the natural follow-up, and is §12.11's last block.

---

## 4. Hand-off rules (what to send back — §10 has the list)

Run 6 is executed here and reported in W6b. **Nothing from the run enters the repository from this
runbook**; the archive travels, W6b reads it. §10 says which archive, which files, and which `meta.json`
fields carry the provenance.

---

## 5. Order, and how long it takes

| Step | §12 | Wall-clock (G-box, estimated) |
|---|---|---|
| preflight, pulls, provenance | 12.1–12.4 | 30 min |
| dry run — all four targets, all profiles, all 26 AXIAM scenarios; the minimal overlay | 12.5 | about 1.5 h |
| resting footprint — Keycloak, Zitadel, authentik, AXIAM full, AXIAM minimal | 12.6 | about 1 h |
| **core matrix**, median-of-3 (AXIAM 11 × 3 profiles, Keycloak 6 × 3, Zitadel 7 × 3, authentik 6 × 2 = 84 cells per repeat) | 12.7 | **about 17 h** (≈ 3.7 min per cell: 30 s warm-up + 120 s + cooldown + 60 s pause; plus ~4 min bring-up per target/profile) |
| NEW AXIAM cells, p0, median-of-3 (15 × 3) | 12.8 | about 3 h |
| production-posture pass + `rl-prod-check` (17 cells, once) | 12.9 | about 1.2 h |
| minimal profile + full control (7 × 3 each) | 12.10 | about 2.8 h |
| investigations | 12.11 | about 3 h |
| SDK pass | 12.13 | about 1.5 h |
| report, pack | 12.14 | 10 min |

Run it in `tmux`, over several nights. The core matrix is the only long item; §12.15 has the inline loop
that resumes it per pass if it is interrupted.

---

## 6. Gotchas

From the authentik target's smoke runs (T23.10.1), verbatim in substance:

- **Env vars.** `BENCH_AUTHENTIK_IMAGE` (default `ghcr.io/goauthentik/server:2026.8.3`);
  `BENCH_AUTHENTIK_WORKER_CPUS` and `_MEM` default to `BENCH_CPUS` and `BENCH_MEM`, so **setting `BENCH_MEM`
  also moves the worker**; `BENCH_AUTHENTIK_LISTEN_HTTP`, `_HTTPS` and `_METRICS` default to **IPv4 wildcards**,
  because authentik's stock `[::]` binding crashes on a host with no IPv6; `BENCH_AUTHENTIK_SEED_TIMEOUT`
  (default 900); `BENCH_AUTHENTIK_USER_PASSWORD` (optional override of the generated bench-user password).
- **Caps.** Server 2 CPU / 2 048m, worker the same, DB 2 CPU / 1 024m; the configured ceiling is 6 CPU / 5 GiB
  against Keycloak's 4 / 3. The worker is idle on JWKS, introspection and userinfo, but runs about 0.6 CPU on
  client_credentials and login.
- **Run order.** `bench-up` takes about 2–3 minutes on first start; `bench-seed` waits for the default blueprints,
  which arrive minutes after the server answers; **use `bench-down` between runs**, because the bootstrap variables
  only work on an empty database. It also deletes `.seed/authentik.stack.env`.
- **Profiles.** p0 is clean; p2 is authentik's own self-signed listener (TLS 1.2 and 1.3, HTTP/1.1 only), so it cannot
  be pinned to 1.3 — **every p2 number carries that transport sentence**; p3-mtls is refused by `bench-up` and skipped by
  `bench-matrix` and `bench-dry-run`.
- **Expected shape.** The cheap endpoints are PostgreSQL-bound and the database hit its 2-core cap; database cost per
  request: JWKS ≈ 14, userinfo ≈ 23, introspection ≈ 72, client_credentials ≈ 203 transactions; client_credentials with
  one client serializes on row locks; the **login cell will probably fail the validity gate at 50 VUs** through timeouts,
  like Zitadel's bcrypt cell (PBKDF2-SHA256 at 1 000 000 iterations plus the executor's extra requests); `token_refresh`
  is `fallback-op`.
- **Rate limits.** None acted anywhere; zero 429s.
- **Image digest.** The testing used the Docker Hub mirror (`authentik/server:2026.8.3`), so the digest of the image you
  run goes in the report: `images.txt` and every `meta.json` carry it.

From the Keycloak 26.8.0 smoke run in the sandbox (the image `keycloak/keycloak:26.8.0`, digest
`sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc`; **no figure from it is a measurement**):

- **It comes up and seeds unchanged.** The compose file needed **no configuration change** for 26.8.0: `start`, the
  `KC_BOOTSTRAP_ADMIN_*` variables, `KC_HOSTNAME_STRICT`, `KC_HEALTH_ENABLED`, the TLS options and the `/realms/master`
  readiness URL all work. The banner reads `Keycloak 26.8.0 on JVM (powered by Quarkus 3.40.1)`; the seed's five smoke
  checks (ROPC login, client credentials, introspection, refresh, userinfo) pass, and **all six shared scenarios pass a dry
  run at p0, p2 and p3** (18 PASS, 0 FAIL).
- **Bring-up is about 50 s** (the first `start` runs Quarkus augmentation, ~13 s, then serves in ~6 s).
- **Heap follows the cap.** Keycloak's resting RSS at 2 GiB (about 545 MiB fresh in the sandbox) is not a statement about the
  product: the JVM sizes itself from the container limit.
- **`image_digest` was wrong in run 5's metadata** (the container carries no `RepoDigests`, so the read always fell through to
  the image id). Fixed; the digest you see now is the registry's.
- **A stage label containing `seed` is dropped from the archive** (`bench-pack` prunes it); the resting sampler's stages are
  `fresh` and `fixture`.
- **Anonymous Docker Hub pulls are rate-limited** (`429`). Log in.
- **Always `bench-down`, never a hand-run `docker compose down -v`.** `bench-down` deletes `.seed/<target>.stack.env` (and the bulk-seed
  record); a bare `compose down` leaves them, and the next `bench-up` would hand a fresh stack the old stack's passwords.

Others a run needs to know:

- **The minimal overlay needs Compose ≥ 2.24.** Under an older Compose the `!reset` tags are a syntax error (loud).
- **`rl=prod` is a different posture from `rl=neutralized` for seven more families than in run 5** (§0.3).
- **Zitadel under v4.19.4 is unverified from the sandbox** (§0.2). If its seed or login cell fails the dry run, that is a harness
  finding for W6b, not a reason to change a pin.
- **AXIAM `1.0.0-beta18` could not be pulled where this was written.** The AXIAM seed, the minimal overlay's boot and every AXIAM
  scenario were **not** exercised against it: §12.5 is what proves they work.
- **`k6`'s version moves numbers slightly**; record it.
- **A throttled thermal state looks like a regression.** Check `mhz_avg` before believing a delta.

---

## 7. Checklist

- [ ] Checkout at `v1.0.0-beta18`; `grep -m1 '^version' Cargo.toml` reads `1.0.0-beta18`; the commit written into the header
- [ ] `docker login ghcr.io` and `docker login`; Docker ≥ 25, Compose ≥ 2.24
- [ ] §12.3 quay.io re-check done; the Keycloak version actually run written down
- [ ] `pull-pinned-images.sh` succeeded for every image; `pinned-images.sh` sourced in the shell that runs the matrix
- [ ] No `build=1`; `BENCH_ALLOW_UNMERGED_BUILD_REF` not set
- [ ] **`bench-dry-run` is all-PASS** across every target × profile (AXIAM: all 26 scenarios), and the minimal overlay's dry run too
- [ ] Resting pass done for five stacks; `results/resting/*/` has `fresh-` and `fixture-` files for each
- [ ] Core matrix (`BENCH_SCENARIO_ONLY` = CORE), `repeat=3`, four targets; authentik p3 skipped
- [ ] NEW cells at p0 in `results/axiam-new-cells/`
- [ ] `rl=prod` pass in `results/rl-prod/`; `rl-prod-check` run; `rl-prod-summary.md` kept
- [ ] Minimal-profile cells and the full control in their own trees; `/health` said `"profile":"minimal"`
- [ ] Investigations (§12.11) as chosen; refresh stage log non-empty
- [ ] SDK pass at p0, `repeat=3`, `SDK_BENCH_CONCURRENCY=16`
- [ ] `RUN6-NOTES.md` written (deviations, interruptions, thermal events, versions actually run)
- [ ] `just bench-report` per tree, `just bench-pack`; archive sent with `results/provenance/`

---

## 8. If the dry run fails

A FAIL is a cell that would have produced no data. Do not start the matrix. For AXIAM the likely causes, in order:
a compose variable beta18 now requires (`bench-up` prints the server's last lines), a seed step against an API that changed
(`results/dry-run/axiam/seed-failure/`), a scenario whose request shape changed (the per-cell `.dryrun.log`). **Do not loosen
a check to make a cell pass.** Send the failure back; W6a's harness may need a patch, which is a W6b fix, not a re-measurement.
Under the minimal profile a FAIL that does not occur under the full profile is a **finding** (a scenario the profile cannot serve):
record it in `RUN6-NOTES.md` and exclude that cell from the minimal set rather than hide it.

---

## 9. Reporting rules — what the draft must say

The seventh draft and the comparison rows carry these, every time a number they qualify appears:

1. **The comparability break** (§0.4), in the opening, not a footnote.
2. **Provenance**: the image reference **and digest** of every container (`images.txt`), `build_ref`, whether the merge-base check passed or was
   overridden, and that run 6 measured the **published release image**, not a build. A cell that fell back to a local build is not part of the run of record.
3. **The versions actually run** (§1.3), not the pins.
4. **Ceilings and labels**: authentik's 6 CPU / 5 GiB against Keycloak's 4 / 3 (the worker carries the server cap); authentik password login is
   **`protocol-variant`**; authentik's and Zitadel's refresh are **`fallback-op`**; authentik's p2 is *its own self-signed TLS 1.2-and-1.3, HTTP/1.1-only listener*;
   authentik has no p3.
5. **The posture** of every pass (§2.6): which limits were raised for a cell, that the SCIM route's limit was raised only for `scim_provisioning`, that
   the approval routes' limits were not raised and no scenario drives them.
6. **The minimal profile**: single instance; its outbound deliveries **lost on restart (T-445)**, so its footprint is **not** the full profile's; outbound SCIM
   targets disabled; at-rest figures **not under load**, and **not comparable** with the 2026-10-05 native-binary figures.
7. **Keycloak 26.8's memory claim**: what the notes verifiably say, that no figure and no new flag is given, that the benchmark's logins succeed so the
   login-failure mechanism cannot be credited, and the measured result at the same cap — resting and under load — whichever way it came out (§2.7).
8. **The D8 caveat, verbatim, wherever rate-limit numbers appear:** `client_id`-keyed modes are fairness controls between authenticated well-behaved clients,
   not abuse controls, because the client_id is attacker-mintable before authentication; `ip` remains the only attacker-resistant key and stays the default.
9. **Do not restate the "≥500× below capacity" claim** (it is false: authz_check is about 25×, introspect about 438×; the corrected range is 25–2 700×, authz the tightest).
10. **Sandbox figures are not measurements.** Nothing taken while this runbook was written (Keycloak's resting RSS, dry-run latencies) goes in the draft.

---

## 10. What to send back (D-76)

**One archive**, from `just bench-pack` (§12.14): `benchmarks/results-<date>.tar.xz`. It contains every `*.json`, `*.csv`,
`*.tsv`, `*.md`, `*.log` and `*.txt` under `benchmarks/results/` and **excludes** `dry-run/` and anything named `*seed*`. It carries:

| Path inside the archive | What it is | W6b uses it for |
|---|---|---|
| `results/run-{1,2,3}/<target>/<profile>/<scenario>.{k6.json,res.csv,host.csv,meta.json}` | the core matrix | every table |
| `results/report.md` | `report.py` over the core matrix | headline numbers, validity, bottlenecks |
| `results/axiam-new-cells/run-{1,2,3}/…` and its `report.md` | the NEW cells | the new-feature section |
| `results/rl-prod/**` and `results/rl-prod/rl-prod-summary.md` | the production-posture pass and the ±10 % verdict | §7 of the draft |
| `results/minimal-profile/**`, `results/full-profile-control/**` (+ each `report.md`) | the minimal-profile cells and their control | §5 |
| `results/resting/<target>[-minimal]/{fresh,fixture}-{samples.csv,summary.txt,meta.json}` | memory at rest, per stack | §5, the Keycloak memory claim, G-8 |
| `results/provenance/{images.txt,run.txt,run-after.txt}` | **the pulled image digests**, the checkout, the host and tool versions | §0 of the draft |
| `results/investigations/**` | stage timings, strict-revocation, deny/seed-size, DB-ceiling and authentik-uncapped passes | §3 of the draft |
| `results/sdk/**` and `results/sdk/sdk-report.md` | the SDK pass | §9 of the draft |
| `results/RUN6-NOTES.md` | what you did that the files cannot say | everywhere |

**The `meta.json` provenance** (one per cell; the draft quotes it): `target`, `profile`, `scenario`, `vus`, `warmup`, `duration`,
`rate_limits`, `caps`, `host` and `host_kernel`/`cpu_model`/`cpu_governor`, `docker_version`, `k6_version`, **`build_ref`**,
**`containers[]` = `{name, role, image, image_digest, image_id, cpu_cap, mem_cap_mib}` — the pulled digests**,
`settle_wait_secs`/`settle_timeout`/`settle_probe_thr`, `axiam_env` (secret names redacted), **`axiam_deploy_profile`**,
`connection_model`, `seed_scale`/`seed_fixture`. To eyeball them before sending:

```bash
cd benchmarks
jq -r '[.target,.profile,.scenario,(.build_ref[0:8]),(.containers|map("\(.name)=\(.image_digest[0:19])")|join(" "))]|@tsv' \
  results/run-1/*/*/jwks_fetch.meta.json
```

**`RUN6-NOTES.md`** (write it as you go; no credential in it):

```text
# Run 6 notes
- Tag / commit run:                v1.0.0-beta18 @ <sha>
- Keycloak version actually run:   26.8.0 / 26.8.N (why)            - Zitadel: v4.19.4 / …        - authentik: 2026.8.3 / …
- k6 version, Docker, Compose:     (from results/provenance/run.txt)
- Start / end dates, interruptions, restarts, which passes re-run and why:
- Thermal or power events (battery, throttling, fan, other load on the box):
- Dry-run result (all PASS? which WARN?):
- Anything skipped from this runbook and why:
- Anything surprising:
```

Then send the archive, the notes inside it, and say where the AXIAM tag's commit is. The maintainer, not this runbook, decides how it travels.

---

## 11. What the seventh draft will need

W6b writes `PUBLIC_BENCH_ANALYSIS.md` (seventh draft, four targets) and rewrites the three comparison documents' performance rows
and change logs. Each section consumes:

| Section of the draft / document | Data it consumes | From |
|---|---|---|
| §0 Setup at a glance — hardware, load, caps, targets and **their versions**, provenance | host, caps, k6/Docker versions, **the four versions actually run**, AXIAM tag + commit + **image digests**, SurrealDB/RabbitMQ/PostgreSQL digests, `build_ref` | `provenance/`, `meta.json`, header of this file, `RUN6-NOTES.md` |
| the comparability warning | §0 of this runbook | here |
| §1 headline tables (client credentials, introspection, JWKS, userinfo REST/gRPC, authz, refresh, login) × **four targets** | median-of-3 `throughput`, p50/p95/p99, `cpu_cores_avg`, `mem_mib_avg`, valid/label per cell; authentik's `protocol-variant` (login) and `fallback-op` (refresh) labels; authentik's p2 transport sentence | `report.md`, `run-*/…/*.meta.json` |
| §2 what changed since draft six | §0 of this runbook; deltas against run 5 with the harness/product split | here, run-5 figures |
| §3 the three mysteries → **what run 6 settled**: the limiter table (A1), `token_refresh` (A2), the DB ceiling (A3), strict revocation (A4) | `rl-prod-summary.md`; `refresh-stage-timings.log`; the §12.11 trees | `rl-prod/`, `investigations/` |
| §4 cost of TLS 1.3 / mTLS (vs p0) | p0 vs p2 vs p3 cells, per target; authentik's p2 caveat | core matrix |
| §5 resource usage — **under load** (whole-stack and server-only, authentik server + worker), **at rest** (five stacks, two stages), **the minimal profile**, **Keycloak 26.8's memory claim** (26.7.0 run-5 vs 26.8.0 at the same cap, resting and under load, said whichever way it came out) | `res.csv` `mem_mib_avg/p95`, `containers[]`; `resting/*/…-summary.txt`; the minimal and control trees; the T-445 sentence and the configured ceilings (§2.3) | `resting/`, `minimal-profile/`, `full-profile-control/` |
| §6 weaknesses and caveats — every invalid cell with its reason, the transport/ceiling/label sentences | `valid`/`reasons` in `report.md`, settle timeouts, throttled hosts (`mhz_avg`), authentik's `settle_probe_thr` and its observed settled rate | `report.md` |
| §7 production rate limits | configured vs admitted, per family; the families **not** checked (CIBA, SSF, DCR, SAML/directory/SCIM-target admin); the posture statement of §2.6 (what was raised, what was not, SCIM and approval routes) | `rl-prod-summary.md` |
| §8 full result matrix | one row per (scenario, profile, target) incl. the NEW cells (p0) | `report.md` ×2 |
| §9 SDK client benchmarks | `sdk/<profile>/*.json` incl. `sdk_version`, `client_cpu_ms_total`, `client_rss_mib_peak`, the wire baseline, `sdk-report.md` | `sdk/` |
| §10 / §11 summary | all of the above | — |
| `competitor-comparison-keycloak.md`, `-zitadel.md` — performance rows (tokens/s, introspection, server RSS, whole-stack RSS, "under 8 % of Keycloak's memory") and **dated change-log lines** | the draft's §1/§5 figures for Keycloak 26.8.0 and Zitadel v4.19.4; the resting footprint of the Zitadel stack now measured (closes the "no Zitadel stack measured at rest" note) | the draft |
| `competitor-comparison-authentik.md` — the "no performance claim" paragraph becomes a statement | authentik's figures with the label, ceiling and transport sentences | the draft |

---

## 12. Exact commands — the copy-paste reference

Everything below is literal. Run it from `benchmarks/` unless a block says otherwise. Blocks are in execution order.

### 12.0 Two rules

**Rule 1 — server-side environment variables are baked into a container at `bench-up`, not at `bench-run`.** The AXIAM compose file
forwards an explicit allow-list of names; exporting one for `bench-run` against a running stack changes nothing (run 5 lost its stage
timings to this). Put every `AXIAM__…`/`RUST_LOG` export **before `bench-up`**, and `bench-down` then `bench-up` to change one.
`BENCH_REQUIRE_ENV="NAME …"` on `bench-run` asserts the names off `docker inspect` before the first cell.

**Rule 2 — `just` variables go before the recipe name.** `target=`, `profile=`, `rl=`, `dbcaps=`, `deploy=`, `repeat=`, `scenario=`,
`targets=`, `profiles=` are `just` variables, not environment variables:

```bash
just target=axiam profile=p2-tls13 bench-run     # correct
just bench-run target=axiam                      # WRONG — silently ignored
```

### 12.1 Prerequisites

```bash
docker version --format 'docker {{.Server.Version}}'          # must be >= 25
docker compose version --short                                # must be >= 2.24
k6 version; just --version; jq --version; openssl version; python3 --version; curl --version | head -1
docker login ghcr.io          # username = GitHub handle, password = a PAT with read:packages
docker login                  # Docker Hub (anonymous pulls are rate-limited: HTTP 429)
```

> **Running a k6 scenario by hand** (not needed for this run) requires the seed env: `set -a; . profiles/p0-plaintext.env;
> . .seed/<target>.seed.env; set +a; k6 run scenarios/<name>.js`. Nothing has a default password any more.

### 12.2 Checkout and provenance preflight

```bash
cd /path/to/axiam
git fetch origin main --tags
git checkout v1.0.0-beta18
git merge-base --is-ancestor HEAD origin/main \
  && echo "OK: checkout is on main" \
  || echo "STOP: checkout is NOT on main — do not start run 6"
grep -m1 '^version' Cargo.toml          # must read: version = "1.0.0-beta18"
git rev-parse HEAD                      # write this commit into the header of run6-runbook.md and RUN6-NOTES.md
cd benchmarks
just bench-certs                        # throwaway TLS/mTLS certificates for p2/p3 (idempotent)
```

### 12.3 Re-check for a later patch release

```bash
# Keycloak 26.8.x — the registry the compose file names (unverified from the sandbox: quay.io was unreachable there)
curl -fsS 'https://quay.io/api/v1/repository/keycloak/keycloak/tag/?limit=100&onlyActiveTags=true&filter_tag_name=like:26.8' \
  | jq -r '.tags[].name' | sort -V
# the Docker Hub mirror (verified on 2026-10-06: it listed 26.8, 26.8.0 and 26.8.0-0 only):
curl -fsS 'https://hub.docker.com/v2/repositories/keycloak/keycloak/tags/?page_size=100&name=26.8' | jq -r '.results[].name' | sort -V
# if skopeo is installed, the most direct:
skopeo list-tags docker://quay.io/keycloak/keycloak | jq -r '.Tags[]' | grep -E '^26\.8\.[0-9]+$' | sort -V

# Zitadel v4.19.x and authentik 2026.8.x
skopeo list-tags docker://ghcr.io/zitadel/zitadel | jq -r '.Tags[]' | grep -E '^v4\.19\.[0-9]+$' | sort -V
curl -fsS 'https://hub.docker.com/v2/repositories/authentik/server/tags/?page_size=100&name=2026.8' | jq -r '.results[].name' | sort -V
```

If a **later patch** of a pinned line exists, set the override **now** (it is read by §12.4) and write the choice in `RUN6-NOTES.md`:

```bash
export BENCH_KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.8.N      # only if a later 26.8.N exists (§1.3)
# export BENCH_ZITADEL_IMAGE=ghcr.io/zitadel/zitadel:v4.19.N      # likewise
# export BENCH_AUTHENTIK_IMAGE=ghcr.io/goauthentik/server:2026.8.N
# quay.io blocked on this host? the same Keycloak image from Docker Hub:
# export BENCH_KEYCLOAK_IMAGE=keycloak/keycloak:26.8.0
```

### 12.4 Pull every image, record and pin its digest

```bash
# Pulls AXIAM beta18, SurrealDB, RabbitMQ, Keycloak, Zitadel, authentik and PostgreSQL; a failed pull is a hard error
# (bench-up would otherwise fall back to a LOCAL SOURCE BUILD of the AXIAM image and the run would stop measuring the release).
bash runner/pull-pinned-images.sh
source results/provenance/pinned-images.sh        # exports BENCH_*_IMAGE=<repo>@sha256:… for every image
cat results/provenance/images.txt                 # the digests the report quotes
bash runner/record-provenance.sh                  # results/provenance/run.txt (checkout, host, tool versions)
```

After the first AXIAM `bench-up`, prove the pull took (a locally built image has no `RepoDigests`):

```bash
docker inspect --format '{{.Config.Image}}' bench-axiam-server        # -> ghcr.io/ilpanich/axiam/server@sha256:…
docker image inspect --format '{{index .RepoDigests 0}}' "$(docker inspect --format '{{.Image}}' bench-axiam-server)"
```

### 12.5 Dry-run the whole matrix — the real preflight

```bash
# Every target x profile; every scenario at a collapsed window; real secrets, real images. Exits non-zero on any FAIL.
just targets="axiam keycloak zitadel authentik" profiles="p0-plaintext p2-tls13 p3-mtls" bench-dry-run
# the minimal profile's overlay, boot and seed (a FAIL here that the full profile does not have is a FINDING — §8)
just deploy=minimal targets="axiam" profiles="p0-plaintext" bench-dry-run
cat results/dry-run/SUMMARY.md
```

**Every cell must read PASS (SKIP rows are expected: AXIAM-only on competitors, authentik × p3).** Do not start §12.6 on a FAIL (§8).
Dry-run results land under `results/dry-run/` and never enter the archive. `just bench-clean` between the dry run and the real run is **not**
needed (`bench-clean` would also remove `results/provenance/`; do not run it now).

### 12.6 Resting footprint — five stacks, two stages each (no load)

```bash
for T in keycloak zitadel authentik; do
  just target=$T profile=p0-plaintext bench-up
  case $T in authentik) S=300 ;; *) S=120 ;; esac          # authentik applies its blueprints minutes after it answers
  SETTLE=$S bash runner/resting-sample.sh $T fresh         # freshly migrated, empty datastore
  just target=$T profile=p0-plaintext bench-seed
  SETTLE=60 bash runner/resting-sample.sh $T fixture       # the benchmark fixture in place, still no load
  just target=$T bench-down
done

# AXIAM, full profile (server + SurrealDB + RabbitMQ) and minimal profile (server + SurrealDB); one instance either way
for D in full minimal; do
  just deploy=$D target=axiam profile=p0-plaintext bench-up
  curl -fsS http://localhost:8090/health | jq -e --arg d "$D" '.profile == $d' >/dev/null && echo "profile $D confirmed by /health"
  SETTLE=90 bash runner/resting-sample.sh axiam fresh      # writes results/resting/axiam  or  results/resting/axiam-minimal
  just target=axiam profile=p0-plaintext bench-seed
  SETTLE=60 bash runner/resting-sample.sh axiam fixture
  just target=axiam bench-down
done
cat results/resting/*/fresh-summary.txt results/resting/*/fixture-summary.txt
```

Each summary is the median over 60 s of `rss_kib`, `rss_anon_kib` and the cgroup working set per container and for the stack. These are
**at rest, not under load**; the stage names are `fresh` and `fixture` (a name containing `seed` would be dropped from the archive).

### 12.7 The core matrix (median-of-3) — the long step

```bash
export BENCH_SCENARIO_ONLY="jwks_fetch.js oauth2_client_credentials.js oauth2_password_login.js token_introspection.js \
token_refresh.js userinfo.js zitadel_userinfo_grpc.js userinfo_grpc.js authz_check_rest.js authz_check_grpc.js \
authz_batch_rest.js authz_batch_grpc.js"
just targets="axiam keycloak zitadel authentik" profiles="p0-plaintext p2-tls13 p3-mtls" repeat=3 bench-matrix
unset BENCH_SCENARIO_ONLY
```

`bench-matrix` does bring-up, seed, run and tear-down per cell, writes pass *i* to `results/run-<i>/`, forwards `rl`/`dbcaps`/`deploy` to every
`bench-up`, **skips authentik × p3-mtls**, and runs `report.py` at the end. Do not add `build=1`. If it is interrupted, §12.15.

Per-target by hand (the shape, if you need to re-run one pair):

```bash
just target=keycloak profile=p0-plaintext bench-up
just target=keycloak bench-seed
just target=keycloak profile=p0-plaintext bench-run
just target=keycloak bench-down
```

### 12.8 The NEW AXIAM cells (p0, median-of-3)

```bash
export BENCH_SCENARIO_ONLY="oauth2_authorize.js oauth2_code_pkce.js oauth2_discovery.js oauth2_revoke.js \
device_authorization.js device_verify.js device_flow_poll.js token_exchange.js uma2_perm.js uma_ticket_grant.js \
scim_provisioning.js opaque_login_start.js opaque_register_start.js grpc_admin_validate.js grpc_infra.js"
BENCH_RESULTS_DIR="$PWD/results/axiam-new-cells" just targets="axiam" profiles="p0-plaintext" repeat=3 bench-matrix
unset BENCH_SCENARIO_ONLY
```

Neutralized posture; `scim_per_min` is raised to 1 000 000 for `scim_provisioning` and `device_verify` is throttled at its shipped 10/min — say so (§2.6).

### 12.9 The production-posture pass and the limiter assertions (A1)

```bash
# What the checkout says the shipped limits are (the check reads the LOCAL source; the image enforces its own — they agree at the tag):
python3 -c "
import importlib.util
spec = importlib.util.spec_from_file_location('rlc', 'runner/rl_prod_check.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c = m.read_configured_defaults()
for k in sorted(c): print(f'{k:30} {c[k]:>8,}')
"
# expect: token 120, introspect 600, revoke 60, authz_check 1,800, grpc_admin 600, grpc_infra 6,000, scim 600, device_authorization 12, token_exchange 120, ...

export BENCH_RESULTS_DIR="$PWD/results/rl-prod"
export BENCH_SCENARIO_ONLY="oauth2_password_login.js oauth2_client_credentials.js token_introspection.js oauth2_revoke.js \
authz_check_rest.js authz_batch_rest.js authz_check_grpc.js userinfo_grpc.js grpc_admin_validate.js grpc_infra.js \
device_authorization.js device_verify.js token_exchange.js uma2_perm.js uma_ticket_grant.js scim_provisioning.js token_refresh.js"
just rl=prod target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
just target=axiam profile=p0-plaintext bench-run
just target=axiam bench-down
just target=axiam profile=p0-plaintext rl-prod-check        # exit 1 on any family outside +/-10% of configured; results/rl-prod/rl-prod-summary.md
unset BENCH_RESULTS_DIR BENCH_SCENARIO_ONLY
```

`token_refresh` under `rl=prod` runs with its session pool paced inside the login bucket (A5); a refresh error rate near zero closes the run-5
re-login artefact (4.4 % errors). A `FAIL` is a finding, not a harness error to be tuned away.

### 12.10 The minimal profile, with a full-profile control

```bash
export BENCH_SCENARIO_ONLY="jwks_fetch.js oauth2_client_credentials.js oauth2_password_login.js token_introspection.js \
token_refresh.js userinfo.js authz_check_rest.js"
BENCH_RESULTS_DIR="$PWD/results/minimal-profile"      just deploy=minimal targets="axiam" profiles="p0-plaintext" repeat=3 bench-matrix
BENCH_RESULTS_DIR="$PWD/results/full-profile-control" just deploy=full    targets="axiam" profiles="p0-plaintext" repeat=3 bench-matrix
unset BENCH_SCENARIO_ONLY
# each run ends with report.py over its own tree; the minimal one carries the "NOT the full profile" banner
grep -c '"axiam_deploy_profile": "minimal"' results/minimal-profile/run-1/axiam/p0-plaintext/*.meta.json | head -3
```

**Single instance only. No SCIM target is registered. State in the report that the minimal profile's outbound deliveries are lost on restart
(T-445).** `BENCH_EXPECT_DEPLOY` is set by `bench-matrix` from `deploy=`, so a stack that is not the profile named fails the cell in seconds.

### 12.11 Investigations (in value order; each in its own tree)

```bash
# ---- A2: token_refresh stage timings. RUST_LOG goes on bench-up (rule 1); the target is axiam::perf ----
export BENCH_RESULTS_DIR="$PWD/results/investigations/refresh-stages"
RUST_LOG="axiam=warn,axiam::perf=debug" just target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
BENCH_REQUIRE_ENV="RUST_LOG" just target=axiam profile=p0-plaintext scenario=token_refresh.js bench-run
mkdir -p results/investigations
docker logs bench-axiam-server > results/investigations/refresh-stage-timings.log 2>&1
grep -c 'stage="auth.refresh"' results/investigations/refresh-stage-timings.log    # MUST be > 0, or the cell is worthless
just target=axiam bench-down
unset BENCH_RESULTS_DIR

# ---- A4: strict revocation. Three arms; every variable on bench-up ----
for ARM in "false 0" "true 0" "true 5"; do
  set -- $ARM
  export BENCH_RESULTS_DIR="$PWD/results/investigations/strict-revocation/strict-$1-cache-$2"
  AXIAM__GRPC__STRICT_REVOCATION=$1 AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=$2 just target=axiam profile=p0-plaintext bench-up
  just target=axiam bench-seed
  for S in authz_check_grpc.js authz_check_rest.js; do
    BENCH_REQUIRE_ENV="AXIAM__GRPC__STRICT_REVOCATION" just target=axiam profile=p0-plaintext scenario=$S bench-run
  done
  just target=axiam bench-down
done
unset BENCH_RESULTS_DIR

# ---- B1's gate and E3: deny-present authorization and seed size (the base fixture is the matrix cell) ----
for DENY in 0.05 0; do
  export BENCH_RESULTS_DIR="$PWD/results/investigations/seed-scale-10/deny-$DENY"
  just target=axiam profile=p0-plaintext bench-up
  just target=axiam bench-seed
  BENCH_SEED_DENY_RATIO=$DENY just scale=10 bench-bulk-seed
  for S in authz_check_rest.js authz_check_grpc.js authz_batch_rest.js; do
    just target=axiam profile=p0-plaintext scenario=$S bench-run
  done
  just target=axiam bench-down
done
unset BENCH_RESULTS_DIR

# ---- A3: the database ceiling. Caches off; capped vs uncapped x pool 1 vs 4 ----
for CAPS in capped uncapped; do for POOL in 1 4; do
  export BENCH_RESULTS_DIR="$PWD/results/investigations/db-ceiling/$CAPS-pool-$POOL"
  AXIAM__AUTHZ__DECISION_CACHE_ENABLED=false AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=0 AXIAM__DB__POOL_SIZE=$POOL \
    just target=axiam profile=p0-plaintext dbcaps=$CAPS bench-up
  just target=axiam bench-seed
  for S in authz_check_rest.js authz_check_grpc.js; do
    just target=axiam profile=p0-plaintext scenario=$S bench-run
  done
  just target=axiam bench-down
done; done
unset BENCH_RESULTS_DIR

# ---- authentik with an uncapped database (labelled): how much of its figure is the 2-CPU PostgreSQL ----
export BENCH_RESULTS_DIR="$PWD/results/investigations/authentik-uncapped-db"
just target=authentik profile=p0-plaintext dbcaps=uncapped bench-up
just target=authentik bench-seed
just target=authentik profile=p0-plaintext bench-run
just target=authentik bench-down
unset BENCH_RESULTS_DIR
```

### 12.12 Optional: one labelled Zitadel low-cost bcrypt cell

Zitadel's login is bcrypt-dominated (default cost 14). `BENCH_ZITADEL_HASHER_COST=4` on `bench-up`/`bench-seed` gives one latency-comparable cell; it must be labelled
**non-default** and never compared with the default-cost cell. Not part of run 6 unless you decide it is.

### 12.13 The SDK pass (as run 5)

```bash
# needs the sibling checkouts beside the axiam checkout: ../axiam-<lang>-sdk (rust, typescript, python, java, kotlin, csharp, php, go, swift, c, cplusplus); each bench reports the version it built
just target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
just target=axiam profile=p0-plaintext sdk-dry-run                                  # every SDK builds and completes its four ops (SKIP = no toolchain, never FAIL)
just target=axiam profile=p0-plaintext repeat=3 SDK_BENCH_CONCURRENCY=16 sdk-bench-all
just target=axiam bench-down
```

The matched-VU k6 wire baseline runs first (`BENCH_VUS = SDK_BENCH_CONCURRENCY`) so `p95 overhead vs wire` is populated; do not override that coupling and do not set
`SDK_BENCH_SKIP_WIRE=1` for the run of record. Run 5's checks stand: C# `refresh` reads about 1.2 ms (not 1.2 µs), `client_cpu_ms_total` and `client_rss_mib_peak` are non-zero, and
C and PHP render under the serial-bench table. Output: `results/sdk/p0-plaintext/*.json`, `results/sdk/sdk-report.md`.

### 12.14 Report, pack, send back

```bash
bash runner/record-provenance.sh -after            # results/provenance/run-after.txt
just bench-report                                   # results/report.md (the core matrix)
for D in axiam-new-cells minimal-profile full-profile-control; do python3 runner/report.py --results "results/$D"; done
$EDITOR results/RUN6-NOTES.md                       # §10's template; no credential in it
just bench-pack                                     # benchmarks/results-<date>.tar.xz; refuses an archive containing SECRET/PASSWORD text
tar -tJf results-*.tar.xz | sed 's#/[^/]*$##' | sort | uniq -c | sort -rn | head -40    # eyeball: provenance, resting, run-1..3, rl-prod, minimal-profile, investigations, sdk
```

Send `results-<date>.tar.xz` (§10), and the commit the tag points at. `just bench-pack` excludes `dry-run/` and every `*seed*` name by construction.

### 12.15 If something goes wrong

```bash
just target=axiam bench-down                         # tear a stack down and start the cell again (removes its generated credentials too)
just bench-clean                                     # DESTRUCTIVE: removes everything under results/ except .gitkeep, provenance included — archive first
just target=axiam profile=p0-plaintext dry=1 bench-run     # prove a cell connects, seeds and answers, without a measurement

# Resume the core matrix per pass (what bench-matrix does inline). Edit I/T/P to where it stopped; a pass writes results/run-I/.
export BENCH_SCENARIO_ONLY="<the CORE list from 12.7>"
for I in 1 2 3; do
  export BENCH_RESULTS_DIR="$PWD/results/run-$I" BENCH_RUN_INDEX=$I; mkdir -p "$BENCH_RESULTS_DIR"
  for T in axiam keycloak zitadel authentik; do for P in p0-plaintext p2-tls13 p3-mtls; do
    [ "$T" = authentik ] && [ "$P" = p3-mtls ] && continue
    just target=$T profile=$P bench-up && just target=$T profile=$P bench-seed && just target=$T profile=$P bench-run
    just target=$T bench-down
  done; done
done
unset BENCH_SCENARIO_ONLY BENCH_RESULTS_DIR BENCH_RUN_INDEX
```

If you change any command in §12, **dry-run it first**.
