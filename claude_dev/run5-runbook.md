# Benchmark run 5 — execution runbook

- **Date written**: 2026-08-02 (revised 2026-08-04 for the published image)
- **What run 5 measures**: the released **`1.0.0-alpha24`** server image —
  `ghcr.io/ilpanich/axiam/server:1.0.0-alpha24`, tag `v1.0.0-alpha24`,
  commit `a36ee3c`, on `main`. The run-4 fixes this runbook describes
  (`a15b78d`, `421e3e2`, `cedbc64`, `d35fa65`, originally on
  `claude/axiam-fixes-optimization-4qymzu`) are **merged and contained in that
  image**. **Do not build the server from source** — see §1.0.
- **Predecessor**: [`improvement-after-run4-benchmark.md`](improvement-after-run4-benchmark.md)
  (I-tasks) — run 5 is item 6 of its *Suggested order of execution*
- **Audience**: whoever executes the matrix. Run 5 is executed **off this
  sandbox**, on the operator's own machine.

Run 5 has two jobs. It **re-measures** the matrix now that the run-4 fixes have
landed, and it **collects the data three open investigations need** — I5 (the
TLS client-credentials plateau), I6 (the REST/gRPC authz asymmetry) and I7 (the
SurrealDB ceiling). Those three shipped as *mechanism + instrumentation*, not as
measured wins: the code changes are in, the hypotheses are stated, and run 5 is
what confirms or refutes them. **Sections 4–6 are therefore not optional
extras — they are the point of this run.**

Read §0 and §1 before touching anything. Several cells need a non-default
envelope, and two of the new knobs default to *off* — if run 5 is executed with
last run's command lines, §5's data will silently not exist.

> **Just want the commands?** [**§12 is a complete copy-paste script**](#12-exact-commands--the-copy-paste-reference)
> for the whole run, in order, with every environment variable and parameter
> spelled out. §0–§11 explain *why*; §12 is what you actually type. If you
> follow §12 top to bottom you cannot collect the wrong data.

---

## 0. What changed since run 4 (and what that means for the numbers)

Everything below is already in the published **`1.0.0-alpha24`** image — no
source build, no branch checkout, nothing to compile. It is listed because each
item moves a number you will be comparing against run 4.

| Change | Commit | Effect on run-5 numbers |
|---|---|---|
| **gRPC rate limiter ×60 units bug fixed** (I1) | `a15b78d` | gRPC now admits `configured × 60` per minute instead of `configured` per minute. Every run-4 gRPC cell under prod posture was throttled to 1/60th. **Do not compare run-4 gRPC prod cells to run-5 ones as like-for-like.** |
| **gRPC limiter scoped per method family** (I2) | `a15b78d` | `GetUserInfo` is no longer throttled by the *authz* bucket. New knobs `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` (5× authz) and `AXIAM__GRPC__GRPC_ADMIN_PER_SEC`; **unknown paths fail into the strictest bucket**. ⚠ The admin default (1× authz) and "reflection and health are unlimited" were both superseded by SEC-079 before alpha24 — see §0.1. |
| **`internet` defaults revised** (I3) | `a15b78d` | token 20→**120**/min, introspect 10→**600**/min, authz_check 300→**1800**/min, revoke 10→**60**/min. Human endpoints unchanged. `gateway`/`mesh` unchanged. |
| **Nagle disabled on the REST listener** (I5) | `421e3e2` | New `AXIAM__SERVER__TCP_NODELAY`, **default `true`**. This is the I5 candidate fix and it is *on by default*, so a plain run-5 matrix already measures the post-fix world. §4 tells you how to A/B it. |
| **Session-validation cache** (I6) | `421e3e2` | New `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`, **default `0` = OFF**. Run 5 must set it explicitly or §5 produces nothing. |
| **Two authz table scans removed** (I7) | `421e3e2` | `grants` batched read and group-inherited `has_role` were full `TableScan`s on *every uncached check on every surface*; both are now `IndexScan`. Unconditional — no flag. Expect authz numbers to move, and the capped-vs-uncapped DB gap to narrow. |
| **Batch strategy pinned to `coalesced`** (I14) | pre-existing | Run 4's compose file forced `concurrent`, silently overriding the shipped default. Run 5 finally measures the real default, and `sens-batch-concurrent` becomes a genuine A/B instead of a duplicate. Expect batch REST ≈ 4–5× singles (G3). |
| **SDK bench correctness + telemetry** (I9, I10, I13) | `d35fa65` | C# `refresh` no longer measures a cached no-op; all 11 runners now assert a real HTTP call per refresh iteration and record real client CPU/RSS; Python drives the async client; C/PHP are labelled `conc=1` and excluded from throughput comparison. |
| **Wire baseline + median-of-3** (I15) | `d35fa65` | `sdk-bench-all` runs a matched-VU k6 baseline first, so the `p95 overhead vs wire` column is populated this time. |
| **Provenance preflight** (I18) | `d35fa65` | `run-benchmark.sh` now fails fast unless the image's `build_ref` is an ancestor of `origin/main`. |
| **`rl-prod` assertions** (I19) | `d35fa65` | `just rl-prod-check` compares configured vs admitted per endpoint and writes `rl-prod-summary.md`. This is the check that caught I1 by hand. |

> **Comparability warning.** Run 5 is **not** a like-for-like re-run of run 4.
> The rate-limit defaults changed, a gRPC units bug was fixed, the batch default
> changed, and two table scans were removed. Treat run 5 as a new baseline.
> Where you do want a controlled comparison, use the A/B procedures in §4–§6,
> which toggle exactly one variable at a time.

### 0.1 What the post-run-4 security work changed (audited 2026-08-04)

The I-task fixes above landed in early August; **53 further commits reached
`main` before alpha24 was cut**, many of them from the security review series.
Four touch things this runbook asserts or measures. All four are in the alpha24
image.

| Change | Commit | What it means for run 5 |
|---|---|---|
| **gRPC admin ceiling decoupled from authz** (SEC-079) | `04dc674` | `admin_per_sec` is now the absolute `ADMIN_PER_SEC_DEFAULT` = **10/s = 600/min**, *independently of authz and of every posture preset* — it is no longer `1× authz`. Widening the mesh authz ceiling can no longer widen the administrative one. **§7's table said 6 000/min; that was wrong and is corrected below.** |
| **New gRPC `Infra` family, bounded** (SEC-079) | `04dc674` | Reflection and health used to be *unlimited*; they now take a fixed `INFRA_PER_SEC` = **100/s = 6 000/min**, deliberately not configurable per instance (so there is no env var to pin). The I2 row above still says "unlimited" — read it as historical. |
| **Client secrets are keyed, not bare SHA-256** (OBS-1) | `2fa25c1`, `8162f00` | Stored client secrets are now `HMAC-SHA256(k, secret)` under a pepper-derived key, and `AXIAM__AUTH__PEPPER` is a **fail-closed startup gate in release builds** — which is what run 5 runs. §4's citation is updated accordingly. The *conclusion* is unchanged and now explicit in the module docs: HMAC-SHA256 rather than Argon2id was chosen precisely to keep client-credentials off the KDF path. |
| **Cross-replica decision-cache invalidation** | `e5b2a26` | New `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED` (**default `false`**) publishing HMAC-signed invalidations to a RabbitMQ fanout, plus skew and heartbeat knobs. Run 5 is single-replica, so leave it off — but §5.4's revocation wording is no longer the whole story (see §5.1). |

Two harness defects that this audit found and **fixed alongside this runbook**,
both direct consequences of SEC-079:

- `runner/rl_prod_check.py` still computed `grpc_admin = grpc_authz` (1:1) and
  had no `Infra` family at all. Under `rl=prod` it would have asserted admin
  against 6 000/min while the server ships 600/min — a guaranteed spurious
  failure, and exactly the class of drift I19 exists to catch. It now extracts
  `ADMIN_PER_SEC_DEFAULT` and `INFRA_PER_SEC` from source like every other
  number.
- `benchmarks/justfile`'s `rl=prod` posture exported
  `AXIAM__GRPC__GRPC_ADMIN_PER_SEC=100`, pinning admin **ten times above** the
  shipped ceiling. Corrected to `10`. Any pre-alpha24 `rl=prod` admin figure
  measured a posture no deployment runs.

Checked and found **still accurate**, so §4–§6 stand as written: the gRPC auth
middleware still performs no session-revocation check (`middleware/auth.rs:42`
validates the token and stops), the REST extractor still calls
`is_session_active` unconditionally (`extractors/auth.rs:107`), and the REST
rate-limit defaults are unchanged at token 120 / introspect 600 / revoke 60 /
authz_check 1 800 per minute. The §5 asymmetry diagnosis is intact.

One thing to watch rather than change: the gRPC middleware now enforces an
**audience gate** (`aud` must be `user` or `m2m`, with
`allow_missing_aud_as_user` as a backward-compat escape). Bench tokens are
minted by the same server that checks them, so they carry a valid `aud` — the
§12.1 dry run is what proves it rather than assuming it.

---

## 1. Preflight — do not skip

### 1.0 The image — use the published `1.0.0-alpha24`, do not build

Run 5 measures a **released artifact**, not a working tree. Every fix in §0 is
in `ghcr.io/ilpanich/axiam/server:1.0.0-alpha24`, published by the release
pipeline from tag `v1.0.0-alpha24` (commit `a36ee3c`, gated on being on `main`
by the workflow's `verify-tag-on-main` job). A local build is slower, is not
what any reader of the report will be able to reproduce, and — because the
sandbox/CI `swagger-ui` egress workaround does not exist on an operator
machine — is a fresh source of failure for no benefit.

**This is already the harness default.** `benchmarks/justfile` ships `build :=
"0"`, and `bench-up` derives the tag from the workspace version:

```just
VER="$(grep -m1 '^version' ../Cargo.toml | cut -d'"' -f2)"
export BENCH_AXIAM_IMAGE="ghcr.io/ilpanich/axiam/server:${VER}"
```

So a checkout at tag `v1.0.0-alpha24` resolves to the right image with no
override at all. Three consequences:

1. **Check out the release tag**, not a feature branch. The workspace version is
   what picks the image tag, *and* `build_ref` in `meta.json` is this checkout's
   `HEAD` — so the tag is what makes the recorded provenance describe the image
   that actually ran (§1.1).
2. **Never pass `build=1`** to any recipe. It forces `--build` and silently
   substitutes a locally compiled binary for the released one.
3. **`docker login ghcr.io` first.** GHCR packages are private by default. If
   the pull fails, `bench-up` prints a message and **falls back to a local
   source build anyway** — which in a long `bench-matrix` run scrolls past
   unnoticed. Pull explicitly as a preflight step so the failure is loud
   (§12.1).

Competitors are unaffected: Keycloak and Zitadel were always prebuilt images.

> **Pin by digest for a multi-day run.** `BENCH_AXIAM_PULL_POLICY` defaults to
> `missing`, so a tag already present locally is never re-pulled — fine for an
> immutable release tag, but resolving the digest once and exporting
> `BENCH_AXIAM_IMAGE=ghcr.io/ilpanich/axiam/server@sha256:…` removes the
> question entirely. `meta.json` records `image`, `image_digest` and `image_id`
> per container either way. §12.1 has the commands.

### 1.1 Provenance (I18)

Run 4's `build_ref 6875e4b` was **not an ancestor of `origin/main`** — the image
had been built from a fix branch pre-merge. There was no material doubt about
content that time, but it is exactly the discipline that stops a run being
thrown away later. This is now enforced in `run-benchmark.sh`.

**Running from the release tag makes this check pass by construction.**
`build_ref` is the benchmarking checkout's `HEAD`; at `v1.0.0-alpha24` that is
`a36ee3c`, which is on `main`. Verify anyway — it costs nothing and it is what
proves the checkout and the image agree:

```bash
git fetch origin main
git checkout v1.0.0-alpha24          # the commit the alpha24 image was built from
git merge-base --is-ancestor HEAD origin/main \
  && echo "OK: checkout is on main" \
  || echo "STOP: checkout is not on main"
```

> **`build_ref` describes the checkout, not the image.** Nothing cross-checks
> the two, so running the harness from an arbitrary branch while pulling the
> alpha24 image records a `build_ref` that has no relationship to the binary
> under test. Checking out the release tag is what collapses that gap — it is
> the whole reason for step 1 in §1.0.

`BENCH_ALLOW_UNMERGED_BUILD_REF=1` exists as an escape hatch for deliberate
pre-merge validation. **Run 5 does not need it** — a released image is on `main`
by definition. If you find yourself reaching for it, you are not running the
image this runbook describes; stop and fix the checkout instead. If you use it
regardless, say so in `meta.json` and in the writeup — an unlabelled unmerged
run is how run 4's provenance footnote happened.

### 1.2 Environment sanity

- Confirm the 2-core server / 2-core DB envelope matches run 4, or record the
  difference. Capacity figures in `PUBLIC_BENCH_ANALYSIS.md` §7 are stated for
  that envelope.
- **Thermals (I8).** Run 4's hot cells hit 96–100 °C with `mhz_avg` spread
  3.16–3.87 GHz. Consider an inter-cell cooldown, and record `mhz_avg` per cell
  so a thermally-throttled cell can be identified rather than silently averaged
  in. If you can, run one cell-order-shuffle sensitivity pass to check ordering
  is not confounding results.
- Confirm `just` and `docker compose` resolve, and that `docker compose config`
  renders the target compose files without error.
- Confirm the alpha24 image **pulls** before spending any k6 time on it (§12.1).
  No source build is needed for any target in run 5, so a working `docker pull`
  is the only build-side prerequisite.

### 1.3 Watch items carried from run 4 (I8) — cheap, no work, just record

- userinfo REST 5 008 (run 3) → 4 547 (run 4), −9% on a DB-pegged cell.
  Confirm or dismiss as environment drift.
- `sens-cache-on` introspection 3 438 vs matrix 4 387 (−21%) on a
  cache-irrelevant endpoint. Run-order/DB variance suspect.

---

## 2. Standard matrix

Invocation is unchanged from run 4 — and note there is no `build=` anywhere in
it, which is exactly right: the default `build=0` pulls the alpha24 image
(§1.0), and `bench-matrix` forwards that default to every cell.

```bash
just target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
just target=axiam profile=p0-plaintext bench-run
# ... repeat per target/profile, or use bench-matrix for the full sweep
```

Run the full matrix across targets (axiam, keycloak, zitadel) and profiles
(p0-plaintext, p2-tls13, p3-mtls) as in run 4, **except** the Keycloak login
cells, which need §3.

---

## 3. Keycloak login cells — 4 GiB, run separately (I16)

Run 4 gave Keycloak 2 048 MiB. That was *necessary* (KC peaked at 1 070 MiB) but
**not sufficient** — login cells were still only 1/3 valid per profile, and the
H7 diagnosis observed a 3.28 GiB peak. Run the login cells alone at 4 096 MiB
and leave every other cell at the shared 2 048 cap, so the envelope change is
confined to the cells that need it and is visible in `meta.json` (the C2
cap-recording machinery already records `BENCH_MEM`).

```bash
# KC login cells only, 4 GiB:
BENCH_MEM=4096m just target=keycloak profile=p0-plaintext bench-up
just target=keycloak bench-seed
just target=keycloak profile=p0-plaintext scenario=oauth2_password_login.js bench-run
just target=keycloak bench-down

# The rest of Keycloak's matrix at the default 2048m, login excluded:
BENCH_SCENARIO_EXCLUDE="oauth2_password_login.js" \
  just target=keycloak profile=p0-plaintext bench-up
# ... bench-seed / bench-run as usual
```

`BENCH_SCENARIO_EXCLUDE` is new in `d35fa65` precisely so a cell needing a
different envelope can be split out without hand-editing the matrix.

---

## 4. I5 — the TLS client-credentials plateau

**What run 4 showed.** p2 (TLS) client-credentials = 1 180/s with
`bottleneck: none` and a flat p50/p95/p99 of **42.6 / 43.9 / 44.8 ms** — every
request paying a near-constant ~43 ms with nothing saturated. p0 CC = 2 727/s
through the same middleware.

**What the code review established (statically, `421e3e2`).** Two things are now
*settled* and need no measurement:

- **Client-credentials is not Argon2-bound.** Still true, but the mechanism
  changed after run 4 and the old citation is dead. OBS-1 (`2fa25c1`,
  `8162f00`) replaced the unsalted SHA-256 digest with a **keyed HMAC-SHA256**
  tag: `hash_client_secret` is now
  `client_secret::global()?.hash(secret)` at
  `crates/axiam-db/src/repository/service_account.rs:47`, delegating to
  `crates/axiam-auth/src/client_secret.rs`. HMAC-SHA256 over Argon2id was a
  deliberate choice *made to protect this measurement* — the module docs cite
  the 2 727 req/s client-credentials figure as the reason. Nothing on the path
  touches `crypto_semaphore`. The analysis's open question about whether CC
  shares the login hasher pool stays closed: it does not.
- **No lock is held across an await on the CC path**, and the rustls session
  cache is not implicated (a `Ticketer` is configured, so TLS 1.3 resumption is
  stateless and the store is off the hot path).

**The live hypothesis: Nagle + delayed ACK.** `actix-web` defaults
`tcp_nodelay: None`, which actix-http reads as *never call `set_nodelay`* — so
Nagle was on for the REST listener. `tonic` defaults it to `true`, and the gRPC
surface shows no plateau. Linux's delayed-ACK timer is **40 ms**; 42.6 − 40 ≈
2.6 ms of real work, the right order for this handler. It is TLS-only because
the plaintext bind is HTTP/1.1 (a single write, immune to Nagle) while the TLS
bind is h2, where HEADERS and DATA reach the socket as separate writes and hence
separate TLS records.

**Known gap in the hypothesis:** it does not by itself explain why CC is affected
and `token_refresh` is not (also a POST returning a JWT, p0 839 → p2 834).
Whether Nagle fires depends on the exact byte layout relative to path MSS, which
is why `response_body_bytes` is instrumented. **Closing this gap is part of the
job.**

### 4.1 Enable instrumentation

```bash
RUST_LOG=axiam_oauth2=debug,axiam_api_rest=debug
```

No feature flag, no rebuild. Measurement is always on (five `Instant::now()`
reads, ~20 ns each, against a ~370 µs handler — under 0.1%); only *reporting* is
gated by the tracing level.

### 4.2 The A/B

On the **p2-tls13** `oauth2_client_credentials` cell, with p0 as control:

| Arm | Setting |
|---|---|
| A (post-fix, new default) | `AXIAM__SERVER__TCP_NODELAY=true` |
| B (pre-I5 behaviour) | `AXIAM__SERVER__TCP_NODELAY=false` |

Also run the **H6 §6 VU sweep**, 1 → 100 VUs at p0 and p2 on CC. This has been
blocked since H6 because something else always clamped it; nothing does now.
Constant per-request cost ⇒ throughput scales with VUs. A serialization point ⇒
throughput pins.

### 4.3 Artifacts

DEBUG events on target `axiam::perf`:

- `stage="oauth2.client_credentials"` → `client_lookup_us`, `secret_verify_us`,
  `tenant_lookup_us`, `token_mint_us`, `handler_total_us`
- `stage="oauth2.token_endpoint"` → `exchange_us`, `serialize_us`,
  `response_body_bytes`

Plus k6's `bench_http_proto`, connection-reuse counters, and `tls_handshakes`.
Capture `ss -ti` against the container's network namespace during the run — a
Nagle stall shows unacked bytes with an idle congestion window. The server image
is `distroless/cc-debian12`, so there is **no shell and no `ss` inside it**;
§12.4 shows how to get there from the host.

> There is deliberately **no** "token persist" stage: client-credentials issues
> no refresh token and writes nothing. If you see a DB write on this path,
> that is itself a finding — **with one now-legitimate exception**. OBS-1's
> v1→v2 hash migration is lazy: verifying a *legacy* bare-SHA-256 secret
> returns `MatchNeedsUpgrade` and the caller persists the v2 replacement with a
> compare-and-swap, so the first successful CC call against a legacy client
> does write once. This does not affect run 5 — `runner/seed.sh` creates the
> client through `POST /api/v1/oauth2-clients` on the running server, so it is
> stored v2 from the start and every measured call is a pure read. Worth
> knowing before anyone benchmarks against a pre-OBS-1 database.

### 4.4 Decision rule

| Outcome | Reading |
|---|---|
| **Confirms Nagle** | `handler_total_us` stays ~2–4 ms while k6 p50 is ~43 ms (the 40 ms is *outside* the handler), **and** arm B reproduces 43 ms / ~1 180 rps while arm A's p50 collapses toward p0 with throughput rising. |
| **Refutes Nagle** | 43 ms persists in arm A, **or** the stage timings already sum to ~43 ms — in which case the cost is in-handler after all, and the stage breakdown tells you which one. |
| **Closes the "why only CC" gap** | Compare `response_body_bytes` against path MSS (1448 on a 1500-MTU veth) *after* adding h2 HEADERS and TLS record overhead. If the CC body lands just over one segment and `token_refresh`'s does not, that is the explanation. |

---

## 5. I6 — the REST/gRPC authz asymmetry

**What run 4 showed.** With the decision cache on, gRPC checks went
887 → 11 598/s (**13.1×**) but REST checks only 753 → 791 (**+5%**), despite p50
halving.

**What the code review established (`421e3e2`) — the run-4 hypothesis was right
about the cost and wrong about the cause.** The analysis attributed the REST
cost to "session cookie + CSRF" authentication. But
`benchmarks/scenarios/authz_check_rest.js:106` already sends
`Authorization: Bearer` — it is **already a JWT caller**. The session read happens
regardless of credential source, because `AuthenticatedUser::from_request` calls
`is_session_active()` unconditionally
(`crates/axiam-api-rest/src/extractors/auth.rs:105-115`).

Exact DB round-trips on a **cache-hit** authz check:

| Surface | Round-trips | Why |
|---|---|---|
| REST | **1** | the session read (D-15 revocation check), not covered by the decision cache |
| gRPC | **0** | `crates/axiam-api-grpc/src/middleware/auth.rs:42` validates the token and stops — it does **not** enforce the session-revocation check at all |

That asymmetry, not the credential type, is the 13.1× vs +5%.

> **Consequence worth stating plainly:** offering Bearer-JWT auth on
> `/api/v1/authz/check` — option (b) in the I6 write-up — **cannot** fix this
> cell, because it is already in use. Option (a), a session-validation cache,
> was implemented instead.

### 5.1 Enable — this defaults to OFF

```bash
AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5
```

**If run 5 is executed without setting this, §5 produces no data.** Startup emits
a `WARN` naming the active TTL; its absence means the cache is off. Check the log
line before trusting a cell.

> **Set it before `bench-up`, not before `bench-run`.** The compose file
> forwards an explicit allow-list of variable names into the container, and the
> server reads its config at start — so exporting this against an
> already-running stack changes nothing. `bench-down` then `bench-up` to change
> it. (This knob and `AXIAM__SERVER__TCP_NODELAY` are in that allow-list in the
> alpha24 image's compose file; they were not forwarded before.) §12.5 has the
> exact loop, including the `docker inspect` check that proves the value landed.
> After the fact, every cell's `meta.json` carries an `axiam_env` object dumped
> from the running container, so a finished run can be audited without a live
> stack: `jq '.axiam_env.AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS' meta.json`.

Cache semantics, for interpreting results: **positive answers only** are cached
(a revoked session is never cached, so it cannot be resurrected; a new session is
usable instantly), entries carry the row's own `expires_at` so expiry is exact,
and invalidation lives inside the repository itself. Single replica ⇒ revocation
is immediate. Multi-replica ⇒ bounded by the TTL, the same contract as the
decision cache.

> **The decision cache's half of that contract improved after run 4** (`e5b2a26`,
> §0.1): `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED` publishes HMAC-signed
> invalidations to a RabbitMQ fanout so replicas no longer wait out the TTL. It
> **defaults to `false`**, and run 5 is single-replica, so leave it off — a
> broadcast-on cell would change what §5.2's 2×2 measures. Mentioned so the
> "multi-replica ⇒ bounded by the TTL" sentence above is read as *the default
> posture*, not as the only one the product offers. The session-validation
> cache has no broadcast path of its own.

### 5.2 The matrix — a 2×2, replacing the 1-D H5 sweep

Over `authz_check_rest` and `authz_check_grpc`:

| | `SESSION_VALIDATION_CACHE_TTL_SECS=0` | `=5` |
|---|---|---|
| `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=false` | baseline | session cache only |
| `=true` | decision cache only (= run 4) | both |

The H5 K-sweep's ship-bar arithmetic predates the rate-limit fix and the ceiling
moved from 3× to 13.1×, so it needs re-running regardless — and it should now be
this 2×2 rather than a 1-D sweep, because **the two caches cover disjoint
round-trips**.

### 5.3 Decision rule

| Outcome | Reading |
|---|---|
| **Confirms** | REST `authz_check` with **both** caches on approaches the gRPC both-on number (order 10 k/s, up from 791). Decision-cache-only stays ~791. |
| **Refutes** | REST stays near 791 with both on ⇒ the remaining cost is not the session read. Look at the actix middleware chain and HTTP framing next. |

### 5.4 Revocation regression cell — mandatory

Re-run `h5-revocation-check.sh` with the session cache **on**. Expected:
revocation still immediate on a single replica; ≤ 5 s if the cell runs 2+
replicas. A cache that speeds up authz by breaking revocation is not a win —
this cell is what proves it did not.

---

## 6. I7 — the SurrealDB ceiling

**What run 4 showed.** DB-uncapped deltas post-fix: checks +89/90%, CC +64%,
userinfo +59%, introspection +42%, refresh +30% — i.e. the DB had become the
product's ceiling.

**What changed (`421e3e2`).** Two genuine full table scans on the authz read path
were found via `EXPLAIN` against the real migrated schema, and fixed:

| Query | Before | After |
|---|---|---|
| `grants` batched read | `TableScan` (`pre_decode_filter: "no (unsupported predicate)"`) | `IndexScan idx_grants_unique` |
| `has_role` group-inherited | `TableScan` | `IndexScan idx_has_role_unique` |

Causes were `WHERE meta::id(in) IN $role_ids` (a function call wrapping the
indexed field) and a correlated sub-select on the RHS. **No schema change and no
new index were needed** — the composite `(in, out)` indexes from schema v19
already covered it. Both tables were scanned on *every uncached check on every
surface*; the cost is invisible on a small seed and grows with total DB size.

### 6.1 Run

Nothing to enable — the fixes are unconditional and already in the image.

Matrix `authz_check_rest`, `authz_check_grpc` and `authz_batch_*` at both
`dbcaps=capped` and `dbcaps=uncapped`, with **both caches off**, so the plan fix
is measured in isolation rather than masked by caching.

### 6.2 Decision rule

| Signal | Reading |
|---|---|
| **Success metric** | Capped-envelope `authz_check` REST **≥ 1 000/s without cache** (run-4 baseline: 753). |
| **Strong confirmation** | The DB-uncapped delta **shrinks** (was checks +89/90%). Removing a table scan cuts per-query cost, so the capped↔uncapped gap should narrow. If it stays near +90%, the ceiling is *concurrency*, not per-query cost — and read replicas (§6.4) move up the priority list. |

### 6.3 Seed-size sensitivity — desirable, but NOT runnable as the harness stands

The idea: one labelled cell at ~10× the seed volume. Pre-fix, scan cost scaled
with total row count; post-fix it should be flat — the most direct evidence the
fix is real rather than noise.

**The harness cannot do this today.** `runner/seed.sh` provisions a single
fixture (one org/tenant/user/client) and exposes no volume knob; there is no
`BENCH_SEED_SCALE` or equivalent anywhere in `benchmarks/`. Building it means a
bulk loader that inserts ~10× the `grants` and `has_role` edge rows **across
many tenants** — both tables grow with the whole database, which is exactly why
the scans mattered — run between `bench-seed` and `bench-run`.

Treat this as follow-up tooling, not a run-5 step. See §12.6 for the same note
at the point of use. Without it, I7's evidence rests on the §6.2 decision rule
plus the `EXPLAIN` plan pins already enforced in CI.

### 6.4 Not in scope for run 5

- **Batch/pipelining** — `coalesced` already collapses 15 round-trips to 3 for
  the 5-item shape. Further pipelining should wait until run 5 shows where the
  ceiling sits *after* the scans are gone.
- **Read replicas** — design note only, `docs/deployment/authz-read-path.md` §4.
  The blocker is not plumbing but staleness semantics: a replica reintroduces a
  stale-allow window at the storage layer, where the decision cache's
  invalidation hooks cannot reach, bounded by replication lag rather than a TTL —
  and lag can degrade silently.
- **CP-3 (DB container tuning)** — now actionable, but **re-measure first**. Its
  premise ("if throughput barely moves, the wall is the connection, not DB
  capacity") was formed when the run-4 deltas partly measured per-query scan
  cost, not capacity.

### 6.5 CI guard

`cargo test -p axiam-db --test authz_query_plan_test` fails if any hot query
regresses to `TableScan`. It includes *witness* tests asserting the old query
forms genuinely do scan, so the assertions cannot quietly become tautologies.

This one is a **source-side** check and the only step in run 5 that compiles
anything. It already runs in CI on the alpha24 commit, so it is optional for the
operator — running the benchmark itself needs no Rust toolchain at all.

---

## 7. Prod-posture pass and the I19 assertions

```bash
just rl=prod target=axiam profile=p0-plaintext bench-run
just target=axiam profile=p0-plaintext rl-prod-check
# artifact: results/rl-prod-summary.md — exit 1 on any endpoint outside ±10% of configured
```

`runner/rl_prod_check.py` reads the current defaults **read-only** out of
`crates/axiam-api-rest/src/config/rate_limit.rs` and
`crates/axiam-api-grpc/src/{config.rs,middleware/rate_limit.rs}`, so it cannot
drift from the code.

> **This is a second reason the checkout must be at `v1.0.0-alpha24` (§1.0).**
> The check reads the *local source tree* while the limits it asserts are
> enforced by the *pulled image*. Those are the same numbers only when the
> checkout is the commit the image was built from. Run it from any other branch
> and a mismatch is the harness comparing two different versions, not a bug in
> the server.

Expected values at `v1.0.0-alpha24`:

| Endpoint | Configured |
|---|---|
| token | 120/min |
| introspect | 600/min |
| authz_check | 1 800/min |
| revoke | 60/min |
| gRPC authz | 6 000/min (100/s × 60) |
| gRPC identity | 30 000/min (5× authz) |
| gRPC admin | **600/min (10/s × 60)** — absolute, *not* 1× authz (SEC-079) |
| gRPC infra (reflection + health) | **6 000/min (100/s × 60)** — fixed, not configurable |
| login / register / password-reset / MFA | 10 / 5 / 3 / 5 per min (unchanged) |

> **Admin and infra changed after run 4 (SEC-079, §0.1).** Admin is now an
> absolute constant so raising the mesh authz ceiling cannot raise the
> administrative one; infra went from unlimited to a bounded 100/s. Both
> `rl_prod_check.py` and the `rl=prod` posture in the justfile were corrected
> for this alongside this runbook — an older harness asserts admin at 6 000/min
> and fails spuriously.

This is the check that caught the I1 units bug by hand last time; it has been
live-tested against a synthetic failure reproducing that exact bug (100/min
admitted vs 6 000/min configured). **All four gRPC families must be asserted
separately** — a server-wide assertion would not have caught I2, and an
authz-relative one would not catch a regression that re-coupled admin to authz.

### 7.1 I4 — refresh-under-prod errors

Run 4 saw `token_refresh` under prod posture at 2 833 failures (2.4%) at 694/s.
Refresh is unlimited; the failures line up with the harness's periodic re-login
tripping the 10/min login bucket mid-run. Either budget re-logins inside the
login limit or pre-mint a session pool in setup, then confirm the failure count
drops. If it does, that also confirms the product-docs note that session-refresh
capacity is effectively coupled to the login limit for short-session
deployments.

---

## 8. SDK pass

```bash
just target=axiam profile=p0-plaintext repeat=3 SDK_BENCH_CONCURRENCY=16 sdk-bench-all
# artifacts: results/sdk-run-{1,2,3}/ → merged into results/sdk/p0-plaintext/*.json
#            results/sdk/sdk-report.md
```

The matched-VU k6 wire baseline now runs automatically before the SDK pass
(`BENCH_VUS = SDK_BENCH_CONCURRENCY`), so the `p95 overhead vs wire` column will
be populated this time. An *unmatched* baseline produces bogus negative
overheads — that was the draft-4 lesson; do not override the VU coupling.

What to check in the output:

- **I9 guard.** Every runner now asserts a real HTTP call per refresh iteration
  (exact call counts for C via `axiam_client_refresh_count()`; a plausible-wire
  latency floor for the other ten, since none expose a counter). A tripped guard
  exits non-zero and `run-all.sh` reports FAILED rather than publishing a fake
  number. **C# `refresh` should now read ~1.2 ms, not 1.2 µs.**
- **I13 telemetry.** `client_cpu_ms_total` and `client_rss_mib_peak` were 0.0 for
  every SDK in run 4. They should now be real. Client-side efficiency is half the
  E1.3 story — an SDK burning 2× CPU at equal latency matters for IoT.
- **I10 labelling.** C and PHP run at concurrency 1 and are now rendered in a
  separate "serial benches — excluded from cross-SDK throughput comparison"
  table. Do not re-merge them into the throughput chart.
- **Python is now an async driver.** Run 4's Python `check_access` gap (p50
  30.3 ms vs 10–11 ms for Go/Java/Rust) was profiled and found to be
  **substantially a harness artifact**: a synchronous GIL-bound client driven
  through `ThreadPoolExecutor(max_workers=16)` sharing one `httpx.Client`, with
  per-call latency scaling ~linearly with thread count while aggregate throughput
  stayed flat — the Little's-Law fingerprint of a fixed-capacity queueing point
  (GIL scheduling plus httpcore's single per-pool lock), not extra per-call work.
  All four originally-suspected causes were ruled out with direct evidence. The
  runner now uses `AsyncAxiamClient` with an `asyncio.Semaphore`. **Expect the
  Python number to move substantially, and treat it as a new baseline rather than
  an SDK improvement.**
- **C++ tail (I11).** Root-caused and fixed in the C++ SDK repo — and *not* the
  `Expect: 100-continue` cause the analysis speculated (libcurl 8.5's threshold
  is 1 MiB, not 1 KiB, so check/batch bodies never trigger it). The real cause was
  `CURLOPT_MAXAGE_CONN` (libcurl default 118 s, so a long-lived worker silently
  reconnects) compounding with `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS` (default
  200 ms, burned on every fresh connection where AAAA resolves but IPv6 is
  unroutable). **Acceptance: p95 within 3× p50 at p0.** A residual tail would
  point at server-side idle timeouts or `Connection: close`, not connection age.

`SDK_BENCH_SKIP_WIRE=1` skips the baseline on a quick re-run. Do not use it for
the run of record.

---

## 9. Zitadel (I17) — known gaps, carried

- **(a) refresh** still needs an `offline_access` device/PKCE seed flow. Zitadel's
  session-token-exchange is confirmed unimplemented upstream
  (`zitadel/zitadel#7900`, "investigating") and ROPC is unsupported; the one
  plausible HTTP-only path (Custom Login UI callback-linking) is documented in
  `token_refresh.js` but **not implemented**, because it could not be verified
  against a live Zitadel. Keep the exclusion label.
- **(b) login is bcrypt-dominated.** An opt-in, default-neutral
  `ZITADEL_SYSTEMDEFAULTS_PASSWORDHASHER_HASHER_COST` override is now wired into
  the compose file (verified via `docker compose config` to resolve to Zitadel's
  own default of 14 when unset, so default runs are unaffected). If you want a
  latency-comparable row, run **one** cell with a reduced cost and label it
  clearly as non-default; otherwise keep excluding.
- **(c)** `zitadel_userinfo_grpc` now emits `bench_http_proto` — fixed.

---

## 10. Reporting

```bash
just bench-report   # folds the SDK section (with conc=1 labelling) into results/report.md
```

When writing up:

1. **State the comparability break.** §0's warning belongs in the run-5
   document's opening, not a footnote. Four separate changes moved numbers.
2. **Record provenance explicitly** — the image ref **and its digest**
   (`ghcr.io/ilpanich/axiam/server:1.0.0-alpha24@sha256:…`, straight out of
   `meta.json`'s `image`/`image_digest`), `build_ref`, and whether the
   merge-base check passed or was overridden. State plainly that run 5 measured
   the **published release image**, not a local build — that is what makes the
   numbers reproducible by a reader. If any cell fell back to a local build
   (§12.1), it is not part of the run of record; label or drop it.
3. **Report I5/I6/I7 as confirmed or refuted**, using the decision rules in
   §4.4, §5.3 and §6.2. A hypothesis that survives an honest attempt to refute it
   is worth far more than one that was never tested; and a refuted one is a
   result, not a failure — record it either way.
4. **Do not propagate the "≥500× below capacity" claim.** Run 4's docs asserted
   every revised default stays ≥500× below measured capacity. That is false:
   authz_check is ~25× (1 800/min vs ~45 000/min) and introspect ~438×. The
   corrected range is **25–2 700×, with authz the tightest**. This is already
   fixed in code, tests and `PUBLIC_BENCH_ANALYSIS.md`; do not reintroduce it.
5. **Keep the D8 caveat verbatim** wherever rate-limit numbers appear:
   `client_id`-keyed modes are fairness controls between authenticated
   well-behaved clients, not abuse controls, because the client_id is
   attacker-mintable before authentication. `ip` remains the only
   attacker-resistant key and stays the default.

---

## 11. Quick checklist

- [ ] Checkout is at tag `v1.0.0-alpha24`; `grep -m1 '^version' Cargo.toml` reads `1.0.0-alpha24` (§1.0)
- [ ] `docker login ghcr.io` done and `docker pull …/server:1.0.0-alpha24` succeeded **before** any `bench-up` (§12.1)
- [ ] No `build=1` anywhere; `docker inspect --format '{{.Config.Image}}' bench-axiam-server` shows the ghcr ref, and `RepoDigests` is non-empty (§12.1)
- [ ] `git merge-base --is-ancestor HEAD origin/main` passes; `BENCH_ALLOW_UNMERGED_BUILD_REF` **not** set (§1.1)
- [ ] **`just bench-dry-run` is all-PASS across every target × profile × scenario** (§12.1 step 6)
- [ ] `read_configured_defaults()` reports `grpc_admin_per_min` 600 and `grpc_infra_per_min` 6 000 (§12.7)
- [ ] `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED` left at its `false` default (§5.1)
- [ ] Envelope matches run 4, or the difference is recorded (§1.2)
- [ ] Full matrix run, KC login cells split out at `BENCH_MEM=4096m` (§2, §3)
- [ ] `RUST_LOG=axiam_oauth2=debug,axiam_api_rest=debug` set for the I5 cells (§4.1)
- [ ] `TCP_NODELAY` A/B run on p2 CC, with p0 control (§4.2)
- [ ] H6 VU sweep 1→100 at p0 and p2 on CC (§4.2)
- [ ] **`AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5` set** — startup WARN confirms it (§5.1)
- [ ] I6 2×2 cache matrix run on REST and gRPC (§5.2)
- [ ] `h5-revocation-check.sh` re-run with the session cache on (§5.4)
- [ ] I7 cells run with **both caches off**, capped and uncapped (§6.1)
- [ ] ~~10× seed-size sensitivity cell~~ — **not runnable**, harness has no bulk-seed tooling (§6.3)
- [ ] `rl-prod-check` passes, `rl-prod-summary.md` archived (§7)
- [ ] SDK pass with `repeat=3` and the wire baseline enabled (§8)
- [ ] C# refresh reads ~1.2 ms, not 1.2 µs (§8)
- [ ] `client_cpu_ms_total` / `client_rss_mib_peak` are non-zero (§8)
- [ ] Thermals and `mhz_avg` recorded per cell (§1.2)

> Every command in §12 was checked against the harness as it exists at tag
> **`v1.0.0-alpha24`** — the same commit the image was built from, so the
> runbook and the artifact under test cannot disagree: `just` recipes and
> variables, the scenario filenames, the runner scripts, the container names,
> and — critically — that each `AXIAM__…` variable is actually forwarded into
> the container by `targets/axiam/docker-compose.yml`. Compose uses an explicit
> allow-list, so a variable that is merely exported in your shell but absent
> from that list reaches nothing. The I5 and I6 knobs are in that list as of
> alpha24; before they were added, the §5.1 instruction would have been
> silently ignored.

---

## 12. Exact commands — the copy-paste reference

Everything below is literal. Run it from `benchmarks/` unless a block says
otherwise. Blocks are in execution order; do not reorder them.

### 12.0 The two rules that matter

**Rule 1 — run the published image, never a local build.** `build=0` (the
default) pulls `ghcr.io/ilpanich/axiam/server:1.0.0-alpha24`. Do not pass
`build=1`, and make the pull succeed in §12.1 rather than discovering the
silent build-fallback halfway through the matrix. See §1.0.

**Rule 2 — server-side environment variables are baked into the container at
`bench-up`, not at `bench-run`.**

`benchmarks/targets/axiam/docker-compose.yml` forwards an *explicit allow-list*
of variable names into the container. Exporting a variable and then running
`bench-run` against an already-running stack does nothing — the process was
started with the old value. So:

- put every `AXIAM__…` / `RUST_LOG` export **on the same line as, or before,
  `bench-up`**;
- to change any of them, **`bench-down` first, then `bench-up` again**. That is
  why the A/B blocks below always tear down between arms.

> **Run 5 broke Rule 2 and lost a whole investigation to it (J9).** The §4.3
> handler-stage breakdown produced *zero* `axiam::perf` events because
> `RUST_LOG` was exported for `bench-run` against an already-running stack. The
> variable was in the compose allow-list the whole time; the timing was wrong,
> and nothing checked. Post-J9 the harness makes that self-enforcing:
>
> - `bench-up` now sets and **echoes** `RUST_LOG` (default `axiam=warn`), so
>   the value baked into the container is part of the bring-up record;
> - `run-benchmark.sh` accepts `BENCH_REQUIRE_ENV="<names>"` and asserts each
>   name off `docker inspect` **before the settle gate and the first cell**,
>   failing in seconds rather than after hours of k6 time;
> - every cell's `meta.json` records `axiam_env_required`,
>   `axiam_env_missing` and `axiam_env_complete`, and `axiam_env` itself now
>   captures `RUST_LOG`/`RUST_BACKTRACE` alongside the `AXIAM__*` dump — so a
>   pass that ran without its required knob is visible in the artifact rather
>   than in a post-mortem.
>
> Any pass that depends on debug logging must therefore run as:
>
> ```bash
> RUST_LOG="axiam=warn,axiam_oauth2=debug,axiam_api_rest=debug" \
>   just target=axiam profile=p2-tls13 bench-up
> BENCH_REQUIRE_ENV="RUST_LOG" just target=axiam profile=p2-tls13 bench-run
> ```

`just` variables (`target=`, `profile=`, `rl=`, `dbcaps=`, `repeat=`,
`scenario=`, `targets=`, `profiles=`) are a different mechanism — they go
**before the recipe name**, never after, and are not environment variables:

```bash
just target=axiam profile=p2-tls13 bench-run     # correct
just bench-run target=axiam                      # WRONG — silently ignored
```

### 12.1 Preflight (once, before anything else)

```bash
# 1. Check out the commit the alpha24 image was built from. This does two
#    things at once: it sets the workspace version (which is what `bench-up`
#    turns into the image tag) and it sets build_ref for meta.json (§1.1).
cd /path/to/axiam
git fetch origin main --tags
git checkout v1.0.0-alpha24
git merge-base --is-ancestor HEAD origin/main \
  && echo "OK: checkout is on main" \
  || echo "STOP: checkout is NOT on main — do not start run 5"

grep -m1 '^version' Cargo.toml     # must read: version = "1.0.0-alpha24"

cd benchmarks

# 2. Authenticate to GHCR (packages are private by default) and pull the image
#    EXPLICITLY. Do not let bench-up be the first thing that tries: on a failed
#    pull it falls back to a local source build and the run silently stops
#    measuring the released artifact.
docker login ghcr.io                 # username = your GitHub handle, password = PAT with read:packages
docker pull ghcr.io/ilpanich/axiam/server:1.0.0-alpha24 \
  || echo "STOP: cannot pull the alpha24 image — fix auth before running anything"

# 3. (Recommended) Pin by digest for the whole run, so a re-pull or a stale
#    local tag can never change what is under test mid-matrix.
export BENCH_AXIAM_IMAGE="ghcr.io/ilpanich/axiam/server@$(
  docker inspect --format '{{index .RepoDigests 0}}' \
    ghcr.io/ilpanich/axiam/server:1.0.0-alpha24 | cut -d@ -f2)"
echo "$BENCH_AXIAM_IMAGE"            # record this in the writeup

# 3b. Same treatment for SurrealDB — `surrealdb/surrealdb:v3` is a floating tag
#     (see the A9 note in targets/axiam/docker-compose.yml).
docker pull surrealdb/surrealdb:v3
export BENCH_SURREALDB_IMAGE="surrealdb/surrealdb@$(
  docker inspect --format '{{index .RepoDigests 0}}' surrealdb/surrealdb:v3 | cut -d@ -f2)"

# 4. Toolchain sanity.
just --version && docker compose version

# 5. Throwaway TLS/mTLS certs for the security profiles (idempotent).
just bench-certs
```

> **Do not run a bare `docker compose -f targets/axiam/docker-compose.yml
> config`.** It fails with
> `required variable RABBITMQ_DEFAULT_USER is missing a value: required`,
> and that is the compose file working correctly, not a broken checkout. The
> AXIAM target declares eleven secrets with `:?` guards so it **fails closed**
> rather than starting with a blank credential — `AXIAM__DB__USERNAME`,
> `AXIAM__DB__PASSWORD`, `RABBITMQ_DEFAULT_USER`, `RABBITMQ_DEFAULT_PASS`,
> `AXIAM__AMQP__SIGNING_KEY`, `AXIAM__AUTH__PEPPER`,
> `AXIAM__AUTH__MFA_ENCRYPTION_KEY`, `AXIAM__EMAIL_ENCRYPTION_KEY`,
> `AXIAM__GDPR_PSEUDONYM_PEPPER` and the two JWT PEMs. `bench-up` bootstraps
> all of them into `docker/.secrets/` inside its own subshell, so they do not
> exist in your interactive shell and compose has nothing to interpolate.
>
> To render the file anyway — a pure YAML/interpolation syntax check, no
> secrets involved — stub them:
>
> ```bash
> env AXIAM__DB__USERNAME=x AXIAM__DB__PASSWORD=x \
>     RABBITMQ_DEFAULT_USER=x RABBITMQ_DEFAULT_PASS=x \
>     AXIAM__AMQP__SIGNING_KEY=x AXIAM__AUTH__PEPPER=x \
>     AXIAM__AUTH__MFA_ENCRYPTION_KEY=x AXIAM__EMAIL_ENCRYPTION_KEY=x \
>     AXIAM__GDPR_PSEUDONYM_PEPPER=x \
>     AXIAM__AUTH__JWT_PRIVATE_KEY_PEM=x AXIAM__AUTH__JWT_PUBLIC_KEY_PEM=x \
>   docker compose -f targets/axiam/docker-compose.yml config >/dev/null \
>   && echo "compose renders OK"
> ```
>
> But step 6 below is the check that actually matters — it exercises the real
> secrets, the real image and every k6 scenario.

#### 6. Dry-run the whole matrix — the real preflight

`bench-dry-run` rehearses every cell end to end: `bench-up` (real secrets, real
image), `bench-seed`, then **every k6 scenario** at a collapsed measurement
window, then `bench-down`. Verdicts grade the *client contract* — can k6
connect, send its request, and get the expected answer — not performance. It is
the cheapest way to prove the run will not die three hours in, and on this run
it is also what catches anything the post-alpha24 security work moved (§0.1):
a scenario whose token now fails the gRPC audience gate, or a seed step broken
by a changed auth requirement, shows up here as a FAIL rather than as a hole in
the results.

```bash
cd /path/to/axiam/benchmarks

just targets="axiam keycloak zitadel" \
     profiles="p0-plaintext p2-tls13 p3-mtls" \
     bench-dry-run

# -> results/dry-run/SUMMARY.md  (verdict table)
# -> results/dry-run/<target>/<profile>/<scenario>.dryrun.log  (per-cell k6 output)
# Exits non-zero if ANY cell FAILed. Results land under results/dry-run/ so they
# never mix into what bench-report aggregates.
```

**Every scenario must read PASS before you start §12.2.** A FAIL here is a cell
that would have produced no data in the real matrix. Note the dry run uses the
same `build=0` default, so it also doubles as proof that the alpha24 image pulls
and starts under every profile.

**Prove the pull actually took, after the first `bench-up` of the run.** This is
the one check that distinguishes "measured the release" from "measured a local
build that quietly replaced it":

```bash
docker inspect --format '{{.Config.Image}}' bench-axiam-server
# -> ghcr.io/ilpanich/axiam/server@sha256:...  (or :1.0.0-alpha24 if you skipped 3)
# A bare "axiam-server:latest" / any locally-built ref means the fallback fired.

docker inspect --format '{{index .RepoDigests 0}}' bench-axiam-server
# Empty / "<no value>" => locally built, NOT the published image. Stop and fix auth.
```

The same facts land in every cell's `meta.json` (`image`, `image_digest`,
`image_id` per container), so a completed run can be audited after the fact:

```bash
grep -h '"image"' results/run-*/axiam/*/*/meta.json | sort -u
```

`build=1` is the deliberate opt-out — **run 5 must not use it**. Likewise
`BENCH_ALLOW_UNMERGED_BUILD_REF=1`: a released image is on `main` by
definition, so needing it means the checkout is wrong (§1.1). If you set it
anyway, SAY SO in the writeup and `meta.json`.

### 12.2 The standard matrix (median-of-3)

This is the bulk of the run and needs no special environment.

```bash
cd /path/to/axiam/benchmarks

just targets="axiam keycloak zitadel" \
     profiles="p0-plaintext p2-tls13 p3-mtls" \
     repeat=3 \
     bench-matrix
```

`bench-matrix` handles up/seed/run/down per cell and writes each pass to
`results/run-<i>/`. `bench-report` medians across them later. It forwards
`build={{build}}` to every `bench-up`, so the default `build=0` — the published
alpha24 image — applies matrix-wide. **Do not add `build=1`.**

> Keycloak's **login** cells are excluded from this pass and run separately in
> §12.3 — they need a 4 GiB envelope. If you would rather run the matrix
> per-target by hand, use this shape:
>
> ```bash
> just target=axiam profile=p0-plaintext bench-up
> just target=axiam bench-seed
> just target=axiam profile=p0-plaintext bench-run
> just target=axiam bench-down
> ```

### 12.3 Keycloak login cells — 4 GiB, separately (I16)

Run 4 gave Keycloak 2 048 MiB; that was necessary but not sufficient (H7
observed a 3.28 GiB peak) and login cells were still 1/3 valid.

```bash
cd /path/to/axiam/benchmarks

for P in p0-plaintext p2-tls13; do
  BENCH_MEM=4096m just target=keycloak profile="$P" bench-up
  just target=keycloak bench-seed
  just target=keycloak profile="$P" scenario=oauth2_password_login.js bench-run
  just target=keycloak bench-down
done
```

And, if you ran §12.2 per-target by hand rather than via `bench-matrix`, the
rest of Keycloak's matrix at the default cap with login excluded:

```bash
export BENCH_SCENARIO_EXCLUDE="oauth2_password_login.js"
just target=keycloak profile=p0-plaintext bench-up
just target=keycloak bench-seed
just target=keycloak profile=p0-plaintext bench-run
just target=keycloak bench-down
unset BENCH_SCENARIO_EXCLUDE
```

`BENCH_MEM` is recorded into `meta.json` automatically by the C2 machinery, so
the 4 GiB cells are self-labelling.

### 12.4 I5 — the TLS client-credentials plateau

Two arms plus a control. **Tear down between arms** — `TCP_NODELAY` is read at
container start.

```bash
cd /path/to/axiam/benchmarks

# ---- Arm A: post-fix (the new shipped default) --------------------------
export RUST_LOG="axiam=warn,axiam_oauth2=debug,axiam_api_rest=debug"
export AXIAM__SERVER__TCP_NODELAY=true

just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
just target=axiam profile=p2-tls13 scenario=oauth2_client_credentials.js bench-run
docker logs bench-axiam-server > ../i5-armA-tls-nodelay-on.log 2>&1   # capture stage timings
just target=axiam bench-down

# ---- Arm B: pre-I5 behaviour (Nagle left on) ----------------------------
export AXIAM__SERVER__TCP_NODELAY=false

just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
just target=axiam profile=p2-tls13 scenario=oauth2_client_credentials.js bench-run
docker logs bench-axiam-server > ../i5-armB-tls-nodelay-off.log 2>&1
just target=axiam bench-down

# ---- Control: same two arms at p0 (plaintext) ---------------------------
for N in true false; do
  export AXIAM__SERVER__TCP_NODELAY=$N
  just target=axiam profile=p0-plaintext bench-up
  just target=axiam bench-seed
  just target=axiam profile=p0-plaintext scenario=oauth2_client_credentials.js bench-run
  docker logs bench-axiam-server > "../i5-p0-nodelay-$N.log" 2>&1
  just target=axiam bench-down
done

unset AXIAM__SERVER__TCP_NODELAY
export RUST_LOG="axiam=warn"
```

> The container name is pinned by `container_name: bench-axiam-server` in
> `targets/axiam/docker-compose.yml`, so it does not carry a compose-project
> prefix. If `docker logs` still errors, the stack is not up — check with
> `docker ps --format '{{.Names}}'`.

**What to pull out of those logs** — DEBUG events on target `axiam::perf`:

```bash
grep -o 'stage="oauth2.client_credentials".*' ../i5-armA-tls-nodelay-on.log | head
grep -o 'stage="oauth2.token_endpoint".*'     ../i5-armA-tls-nodelay-on.log | head
```

Fields: `client_lookup_us`, `secret_verify_us`, `tenant_lookup_us`,
`token_mint_us`, `handler_total_us`; and `exchange_us`, `serialize_us`,
`response_body_bytes`.

**The VU sweep** (H6 §6 — blocked since H6, finally runnable):

```bash
for VUS in 1 2 5 10 20 50 100; do
  export BENCH_RESULTS_DIR="$PWD/results/section-12_4-vusweep_vus-$(printf '%03d' "$VUS")"
  for PROF in p0-plaintext p2-tls13; do
    just target=axiam profile="$PROF" bench-up bench-seed
    BENCH_VUS=$VUS just target=axiam profile="$PROF" \
      scenario=oauth2_client_credentials.js bench-run
    just target=axiam bench-down
  done
done
```

**Kernel-level confirmation**, while an arm-B run is in flight (separate shell):

The published image is `distroless/cc-debian12:nonroot` — **no shell, no `ss`,
no `docker exec` into it**. Enter its network namespace from the host instead:

```bash
# Preferred: no extra images, Linux host.
sudo nsenter -t "$(docker inspect -f '{{.State.Pid}}' bench-axiam-server)" -n ss -ti | head -40

# Alternative if nsenter is unavailable — a throwaway container sharing the netns:
docker run --rm --net container:bench-axiam-server nicolaka/netshoot ss -ti | head -40

# A Nagle stall shows unacked bytes sitting with an idle congestion window.
```

Decision rule is §4.4.

### 12.5 I6 — REST/gRPC authz asymmetry (the 2×2)

**`AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` defaults to `0` (OFF). If
you skip these exports, this section produces nothing new.**

```bash
cd /path/to/axiam/benchmarks

for DEC in false true; do
  for SESS in 0 5; do
    export AXIAM__AUTHZ__DECISION_CACHE_ENABLED=$DEC
    export AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=$SESS
    export BENCH_RESULTS_DIR=$PWD/results/section-12_5-$DEC_$(printf '%03d' "$SESS")

    just target=axiam profile=p0-plaintext bench-up bench-seed

    # Verify the knobs actually took effect BEFORE spending a cell on it.
    # (docker inspect, not `docker exec ... env` — the released image is
    #  distroless: no shell, no coreutils, nothing to exec.)
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' bench-axiam-server \
      | grep -E 'DECISION_CACHE_ENABLED|SESSION_VALIDATION_CACHE_TTL'
    docker logs bench-axiam-server 2>&1 | grep -i 'session.validation' | head -3
    # With SESS=5 you MUST see a startup WARN naming the TTL.
    # No WARN => the cache is off => the cell is worthless. Stop and fix.

    just target=axiam profile=p0-plaintext scenario=authz_check_rest.js bench-run
    just target=axiam profile=p0-plaintext scenario=authz_check_grpc.js bench-run
    just target=axiam bench-down
  done
done

unset AXIAM__AUTHZ__DECISION_CACHE_ENABLED AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS
```

This 2×2 **replaces** the 1-D H5 K-sweep — the two caches cover disjoint
round-trips, so a single-variable sweep cannot separate them.

**Revocation regression cell — mandatory, not optional.** A cache that speeds
up authz by breaking revocation is not a win:

```bash
export AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5
just target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
bash runner/h5-revocation-check.sh
just target=axiam bench-down
unset AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS
# Expect: revocation still immediate on a single replica (<= 5s if 2+ replicas).
```

Decision rule is §5.3.

### 12.6 I7 — SurrealDB ceiling (both caches OFF)

The table-scan fixes are unconditional, so nothing to enable — but the caches
must be **off** or they mask the effect being measured.

```bash
cd /path/to/axiam/benchmarks

export AXIAM__AUTHZ__DECISION_CACHE_ENABLED=false
export AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=0

for CAPS in capped uncapped; do
  just target=axiam profile=p0-plaintext dbcaps="$CAPS" bench-up
  just target=axiam bench-seed
  for S in authz_check_rest.js authz_check_grpc.js authz_batch_rest.js; do
    just target=axiam profile=p0-plaintext dbcaps="$CAPS" scenario="$S" bench-run
  done
  just target=axiam bench-down
done

unset AXIAM__AUTHZ__DECISION_CACHE_ENABLED AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS
```

> Scenario filenames verified present: `authz_check_rest.js`,
> `authz_check_grpc.js`, `authz_batch_rest.js`, `authz_batch_grpc.js`,
> `oauth2_client_credentials.js`, `oauth2_password_login.js`,
> `token_refresh.js`. Add `authz_batch_grpc.js` to the inner loop if you want
> the gRPC batch surface too.

**Seed-size sensitivity — NOT RUNNABLE with the current harness. Skip it, or
build the tooling first.**

§6.3 describes this as the cleanest single demonstration that the I7 fix is
real, and that reasoning still holds: pre-fix, the scan cost scaled with total
row count, so post-fix it should be flat. But **the harness cannot do it
today**, and this was verified rather than assumed:

- `runner/seed.sh` provisions a *fixture* — one org, one tenant, one user, one
  client — not a bulk dataset. It exposes no volume knob (`BENCH_SEED_DIR` is a
  path, not a size).
- There is no `BENCH_SEED_SCALE`, `SEED_USERS` or equivalent anywhere in the
  harness. Do not invent one and expect it to be honoured; it will be silently
  ignored and you will measure the normal seed twice.

If you want this cell, it needs new tooling first: a bulk loader that inserts
~10x the `grants` and `has_role` edge rows **across many tenants** (the whole
point is that both tables grow with the entire database, not with one tenant),
run after `bench-seed` and before `bench-run`. Label the resulting cell
explicitly so it is never averaged in with normal-seed cells.

Without it, the I7 evidence for run 5 rests on the §6.2 decision rule — the
capped-envelope ≥ 1 000/s target and the narrowing of the DB-uncapped delta —
which is weaker but still decisive, plus the `EXPLAIN` plan pins that already
run in CI.

Decision rule is §6.2. CI guard:
`cargo test -p axiam-db --test authz_query_plan_test`.

### 12.7 Prod-posture pass + the I19 assertions

```bash
cd /path/to/axiam/benchmarks

just rl=prod target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
just rl=prod target=axiam profile=p0-plaintext bench-run
just target=axiam bench-down

# I19: configured-vs-admitted per endpoint. Exit 1 on any endpoint outside +/-10%.
just rl-prod-check
# artifact: results/rl-prod-summary.md
```

`rl=prod` sets the real shipped limits, and `rl_prod_check.py` re-extracts them
**read-only from the Rust source** — so if the two ever drift, the check fails
loudly instead of publishing a wrong comparison. That comparison is only
meaningful with the checkout at `v1.0.0-alpha24`: the script reads the local
tree, the limits are enforced by the pulled image (§7). Expected configured
values at `v1.0.0-alpha24`:

| endpoint | configured |
|---|---|
| token | 120/min |
| introspect | 600/min |
| authz_check | 1 800/min |
| revoke | 60/min |
| gRPC authz | 6 000/min (100/s x 60) |
| gRPC identity | 30 000/min (500/s x 60) |
| gRPC admin | **600/min (10/s x 60)** — absolute constant, not 1x authz (SEC-079) |
| gRPC infra (reflection + health) | **6 000/min (100/s x 60)** — fixed, no env var |
| login / register / reset / MFA | 10 / 5 / 3 / 5 per min |

Verify the extraction agrees with the source before trusting a `rl=prod` pass —
it takes a second and it is what would have caught the stale admin ratio:

```bash
python3 -c "
import importlib.util
spec = importlib.util.spec_from_file_location('rlc', 'runner/rl_prod_check.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c = m.read_configured_defaults()
for k in sorted(c): print(f'{k:28} {c[k]:>8,}')
"
# grpc_admin_per_min must read 600, grpc_infra_per_min 6,000.
```

**I4 — refresh-under-prod errors.** Run 4 saw 2 833 failures (2.4%) on
`token_refresh` under prod posture, which line up with the harness's periodic
re-login tripping the 10/min login bucket. After the pass above, check:

```bash
grep -h "token_refresh" results/run-*/axiam/p0-plaintext/*/summary.json 2>/dev/null | head
# Expect the failure count to have dropped. If it has not, the re-login budget
# still needs fixing (or a pre-minted session pool in setup).
```

### 12.8 SDK pass (median-of-3, with the wire baseline)

```bash
cd /path/to/axiam/benchmarks

just target=axiam profile=p0-plaintext repeat=3 SDK_BENCH_CONCURRENCY=16 sdk-bench-all
```

The matched-VU k6 wire baseline now runs automatically first
(`BENCH_VUS = SDK_BENCH_CONCURRENCY`) so the `p95 overhead vs wire` column is
populated. **Do not override that coupling** — an unmatched baseline produces
bogus negative overheads (the draft-4 lesson). `SDK_BENCH_SKIP_WIRE=1` exists
for quick re-runs; never use it for the run of record.

Then verify the three things run 4 got wrong:

```bash
# I9 — C# refresh must now be a REAL call: expect ~1.2 ms, NOT 1.2 us.
grep -h '"op": *"refresh"' results/sdk/p0-plaintext/*.json | grep -i csharp

# I13 — client telemetry must be non-zero (it was 0.0 for every SDK in run 4).
grep -ho '"client_cpu_ms_total": *[0-9.]*' results/sdk/p0-plaintext/*.json | sort -u | head
grep -ho '"client_rss_mib_peak": *[0-9.]*' results/sdk/p0-plaintext/*.json | sort -u | head

# I10 — C and PHP must render under the separate serial-bench table.
grep -n "conc=1\|serial benches" results/sdk/sdk-report.md
```

If any refresh row still reads in microseconds, the I9 guard should already
have failed the run — treat a microsecond row plus a passing run as a harness
bug, not a fast SDK.

### 12.9 Report

```bash
cd /path/to/axiam/benchmarks
just bench-report        # -> results/report.md, SDK section with conc=1 labelling
```

### 12.10 If something goes wrong

```bash
# Tear everything down and start the cell again:
just target=axiam bench-down

# Wipe accumulated results (DESTRUCTIVE — archive first if you care):
just bench-clean

# Archive a completed run:
just bench-pack

# Prove a cell can connect/seed/answer without spending a real measurement:
just target=axiam profile=p0-plaintext dry=1 bench-run     # -> results/dry-run/
just targets="axiam keycloak zitadel" profiles="p0-plaintext p2-tls13" bench-dry-run
```

A dry run is the cheapest way to validate a whole matrix invocation before
committing hours to it. **If you change any command in this section, dry-run it
first.**
