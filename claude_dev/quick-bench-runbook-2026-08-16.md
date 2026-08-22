# Quick Benchmark Runbook — alpha38 (AXIAM-only, p0+p2+p3, single pass)

> **Purpose.** A time-boxed alternative to the full 3-run matrix: one full AXIAM-only
> pass at profiles p0/p2/p3, plus the highest-value targeted cells from the R7
> measurement-debt table of
> [`remediation-plan-2026-08-15.md`](remediation-plan-2026-08-15.md). Companion docs:
> [`run5-runbook.md`](run5-runbook.md) (the full-matrix procedure),
> [`new-feature-bench-cells.md`](new-feature-bench-cells.md) (E4 labeled cells).
>
> **Prepared 2026-08-16 against `main` @ `651d9e4` (alpha25); refreshed 2026-08-22
> against `main` @ `044c088` (alpha38).** The refresh was not cosmetic — thirteen
> releases moved three things this runbook asserted:
>
> | Was | Is |
> |---|---|
> | The bench broker hop is plaintext, and there is no AMQP-TLS cell to run | AMQP is **TLS-only** server-side and in every stack. AMQP-carrying figures do not cross that boundary — **re-baseline, do not extend a trend line** |
> | The reactor transport is a stub (`UnavailableReactorTransport`); a hook cell would measure nothing | `LapinReactorTransport` is merged and composed. A dispatch is a real publish — and with nothing consuming the queue it measures a **timeout**, which is a worse thing to publish than the old fast failure |
> | 20 default AXIAM cells | **22** — the two `opaque_*` cells joined the set, and neither could pass until the fixes in §0 landed |
>
> **Time budget: ~8.5 h** for steps 2–6b (≈5 h matrix + ≈2.5 h targeted + ≈1 h the
> nested-resource sweep in §6b); step 7 adds ~35 min. If time runs short, cut from
> the bottom of this priority order: matrix (§2) → rl-prod (§4) → deny arms (§3) →
> nested sweep (§6b) → strict-revocation (§5) → SCIM (§6). §6b is the only step
> here that runs competitors, so cutting it costs the round its only head-to-head
> material — prefer trimming its ladder (`nesteddepths`) or its target list over
> dropping it entirely.
>
> **What this quick run does NOT discharge:** the §7 "flip every row" obligation in
> `PUBLIC_BENCH_ANALYSIS.md` is defined against a *full* rl-prod pass; §4 here populates
> the measured rows honestly but the public doc must say the pass was single-profile.
> Labeled-cell numbers are never interchangeable with default-matrix numbers
> (`new-feature-bench-cells.md` rule); `meta.json` records each cell's distinguishing
> config so they cannot be misread.

---

## 0) Changes to implement BEFORE the run

> **Status: everything in this section has landed.** Nothing here is outstanding
> work; it is kept as the record of what the harness needed and why, because two of
> the alpha38 items were silent-wrong-answer bugs rather than conveniences, and the
> reasoning is what stops them coming back.

**alpha25 items — M1 and M2, both landed.** `run-benchmark.sh` normalizes an
extension-less `--scenario` to its `.js` filename *before* `filter_scenarios()` runs,
the five copy-paste traps in `new-feature-bench-cells.md` are fixed, and
`rl_prod_check.py` reads a `run-*/` matrix tree as well as a flat one (medianing
across passes, as `report.py` does). Each is guarded by a hermetic CI self-test —
`runner/scenario-filter-selftest.sh` and `runner/rl-prod-layout-selftest.sh`, both in
the `bench-harness` job. The §4 `BENCH_RESULTS_DIR` workaround still works and is
still the recommended form there; it is no longer load-bearing.

**alpha38 items — M3 through M6, all landed.**

**M3 — the two `opaque_*` cells could not pass, for two independent reasons.**
`opaque_login_start.js` and `opaque_register_start.js` were added with the OPAQUE
work and left out of `run-benchmark.sh`'s `AXIAM_ONLY_SCENARIOS`, so auto-discovery
handed them to the Keycloak and Zitadel arms, where each `setup()` throws
`target "<t>" has no OPAQUE endpoint` — a capability gap presenting as a broken
benchmark. Separately, `opaque_mode` defaults to `disabled` per tenant and a disabled
tenant answers **404** on every `/api/v1/auth/opaque/*` route, so both cells failed
against AXIAM too. Fixed in three places: both scenarios are in
`AXIAM_ONLY_SCENARIOS`; `bench-up` generates `AXIAM__AUTH__OPAQUE_SESSION_KEY` and
`AXIAM__AUTH__OPAQUE_SETUP_KEY` (64-hex each, via the same generate-once `genhex`
helper as the other secrets) and the compose passes both; and `seed.sh` bootstraps
with `opaque_mode: optional`.

`optional`, never `required` — under `required` the server refuses password login for
the whole tenant with `403 opaque_required`, which would take `oauth2_password_login.js`
and every scenario that mints a user token down with it. Override with
`BENCH_OPAQUE_MODE` only if you know what that costs. The bench user is deliberately
not enrolled and does not need to be: `/auth/opaque/login/start` answers 200 for any
syntactically valid request via the decoy exchange, which is built to cost what a real
one costs. That is an anti-enumeration guarantee, so it is also the property the cell
measures against — a run that ever showed enrolled and unenrolled diverging would have
found a bug, not a bad fixture.

**M4 — `bench-quick`'s reactor probe had gone stale into a false negative.** It
grepped the request-path crates for `ReactorDispatcher`, which they never name; they
hold a `SharedReactorGate` and call through it. So Cell 2 kept printing "X1.4 is not
wired into any request path" about a hook that **is** wired, and the cell stayed
silently skipped instead of flagging that it needed writing. The probe now greps for
`reactor_gate`/`ReactorGate`. See §7 for why the cell still must not be run.

**M5 — five rate-limit families were invisible in the `rl-prod` table.**
`RateLimitConfig` ships sixteen REST families; `rl_prod_check.py` had rows for eleven.
`register`, `password_reset`, `mfa`, `par` and `end_session` were absent entirely
rather than degraded to the "no scenario — not checked" row that map's own design
promises, and a comment above the table asserted the coverage was complete. Anyone
counting sixteen knobs against sixteen rows would have concluded every limiter was
verified. All five now appear with `scenario=None`, so the gap is countable in the
same table as the passes. **`par` and `end_session` are the two cheapest to close** —
they have no fixture problem, nobody has written the cells.

**M6 — `docs/methodology.md`'s scenario table listed 12 of 27 scenarios.** It is the
inventory the "AXIAM-only" classification lives in, and M3 is what happens when it and
`run-benchmark.sh`'s filter lists disagree. Now complete, with the sweep rungs and the
pending cells marked as such.

**Post-run task (after §6):** if the SCIM cell passes (`k6_exit_code == 0`), un-pend it —
remove `scim_provisioning.js` from `PENDING_SCENARIOS` in
`benchmarks/runner/run-benchmark.sh` and delete the status block at
`benchmarks/scenarios/scim_provisioning.js:5-45` **in the same commit**; re-check the DTO
field names against the first real run and drop the "not yet re-checked" paragraph
(`scim_provisioning.js:47-55`).

---

## 1) Prep (~10 min)

- **Tag alpha38 first and let the release image publish.** `bench-up` defaults
  `BENCH_AXIAM_IMAGE` to `ghcr.io/ilpanich/axiam/server:<Cargo.toml version>`, so after
  the version bump it resolves to alpha38 automatically. On pull failure it falls back to a local build (`justfile:279-289`) —
  either way `meta.json` records image + digest; check `build_ref` when writing up and
  state plainly which was measured.
- `cd benchmarks`; ensure docker, k6 and jq are present.
- **Leave the settle gate ON** (default `BENCH_SETTLE=1`, timeout 600 s). With a single
  pass there is no scenario rotation (`rotate_scenarios()` no-ops at run index 1), so the
  alphabetically-first cell — `authz_batch_grpc.js` — always eats any post-seed
  transient; the gate is the only mitigation. Treat batch-cell numbers as single-pass
  indicative.
- Two standing rules: `just` variable overrides go **before** the recipe name
  (`just target=axiam bench-run`-style trailing overrides are silently ignored), and
  container env knobs go on **`bench-up`, never `bench-run`** (the J9 rule — container
  env is fixed at create time).
- **The broker hop is TLS now.** `bench-up` runs `scripts/gen-broker-tls.sh` for you and
  the compose points the server at `amqps://…:5671` with the plaintext listener off, so
  there is nothing to do here — but it changes what the numbers mean. AMQP is on the
  audit-ingestion path, so this touches far more cells than the obvious ones. **Any
  figure carrying an AMQP hop is a new baseline, not the next point on the run-5 line.**
  The Keycloak and Zitadel arms are unaffected, so cross-target comparisons are fine;
  it is the AXIAM-against-its-own-history comparisons that break.

## 2) Full AXIAM matrix — p0, p2, p3, single pass (~5 h)

```bash
just targets="axiam" profiles="p0-plaintext p2-tls13 p3-mtls" repeat=1 bench-matrix
just bench-report
```

22 cells × (~160 s + 60 s inter-cell pause) ≈ 80 min per profile, plus
bring-up/seed/settle. Optional time-saver: `BENCH_CELL_PAUSE=30` on `bench-matrix`
(~10 min saved per profile; slightly less inter-cell isolation — note it in the
write-up). Results land in `results/run-1/axiam/<profile>/…`; `report.py` auto-detects
the layout.

This pass **also discharges, for free**:

- **A2 verification** — `token_refresh.js` runs in every profile. Compare against run 5's
  regressed number; the fix (`98a8b79`, five→three datastore round trips) predicts
  recovery toward run-4 levels. If it has not recovered, that is an R7 finding to
  document, not to hide.
- **The two new E4 cells** — `device_flow_poll.js` and `token_exchange.js` are in the
  default scenario set now. Device cell semantics: `BENCH_VUS` = concurrently-polling
  devices; steady state is HTTP 400 `authorization_pending` **by design**.
- **The two OPAQUE cells** — `opaque_login_start.js` and `opaque_register_start.js`,
  first measured in this round (§0 M3 is what made them runnable). Read
  `benchmarks/docs/methodology.md` before quoting either:

  - `opaque_login_start` is the **server's half only**. The client's Argon2id
    (m=19456 KiB) and its `KE1`/`KE3` curve work are excluded deliberately — putting
    them in a k6 VU would report k6's CPU as AXIAM's. Never present this number as the
    cost of an OPAQUE login.
  - `opaque_register_start` is unauthenticated by necessity, which makes it the OPAQUE
    endpoint an attacker reaches most cheaply and the one an operator actually needs a
    number for when sizing a budget. Both share `login_per_min`.
  - **Do not chart either against the retired SRP series.** SRP's server cost was two
    modular exponentiations in a 2048–4096-bit group; OPAQUE's is a handful of
    ristretto255 scalar multiplications. Expect OPAQUE to be substantially cheaper
    server-side. That is elliptic curves versus finite-field groups — it is not
    evidence about either protocol's security, and writing it up as though it were is
    the specific error to avoid.
  - The meaningful comparison is `opaque_login_start` + `opaque_login_finish` against
    `oauth2_password_login`, whose cost is dominated by one Argon2id verification.

## 3) Targeted cell A — deny-override arms (B1 perf gate, ~40 min)

```bash
# Arm 1: no denies present (the ±2% gate vs the default matrix)
just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
BENCH_SEED_DENY_RATIO=0 just scale=10 bench-bulk-seed
BENCH_RESULTS_DIR=$PWD/results/e4-deny-none \
  just target=axiam profile=p2-tls13 scenario=authz_check_rest.js bench-run
just target=axiam bench-down

# Arm 2: denies present (the honest cost) — identical block with
#   BENCH_SEED_DENY_RATIO=0.05  and  BENCH_RESULTS_DIR=$PWD/results/e4-deny-present
```

Tear the stack down between arms. `meta.json` carries `seed_fixture.deny_ratio` so the
arms cannot be confused. **Gate:** arm 1 within ±2% of the §2 p2 `authz_check_rest`
cell; publish arm 2 as a labeled cell.

## 4) Targeted cell B — rl-prod enforcement pass (p0, ~1.5 h)

```bash
just rl=prod target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
BENCH_RESULTS_DIR=$PWD/results/rl-prod \
  just rl=prod target=axiam profile=p0-plaintext bench-run
just target=axiam bench-down
BENCH_RESULTS_DIR=$PWD/results/rl-prod \
  just target=axiam profile=p0-plaintext rl-prod-check
```

`rl=prod` must be on **`bench-up`** (it exports the limits into the container).
`rl_prod_check.py` re-extracts configured limits read-only from the Rust source (never
hardcoded), asserts admitted ≈ configured ±10% per family, writes
`results/rl-prod/rl-prod-summary.md`, and exits 1 on any FAIL.

**The table has 21 rows and 16 of them are checked.** Since §0 M5 the five families
with no scenario driving them — `register`, `password_reset`, `mfa`, `par`,
`end_session` — appear as explicit `no scenario — not checked` rows rather than being
absent. Read that as it reads: *unmeasured*, not *passing*. The write-up must not
describe this pass as verifying every shipped limiter, because it verifies sixteen of
twenty-one and says which. `par` and `end_session` are the cheap ones to close if
anyone wants that number next round. This is the pass that
flips `PUBLIC_BENCH_ANALYSIS.md` §7 rows to PASS (the SCIM row shows "no data" until §6
has run). Pre-flight sanity: the extraction snippet at `run5-runbook.md:1209-1219`
(`grpc_admin_per_min` must read 600, `grpc_infra_per_min` 6000).

## 5) Targeted cell C — gRPC strict-revocation arms (~40 min)

```bash
# Arm 1 = the §2 p2 authz_check_grpc cell (already measured — reuse it, do not re-run)

# Arm 2: knob on bench-up, proven landed via BENCH_REQUIRE_ENV
AXIAM__GRPC__STRICT_REVOCATION=true \
AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5 \
  just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
BENCH_REQUIRE_ENV="AXIAM__GRPC__STRICT_REVOCATION" \
BENCH_RESULTS_DIR=$PWD/results/e4-grpc-strict \
  just target=axiam profile=p2-tls13 scenario=authz_check_grpc.js bench-run
just target=axiam bench-down
```

`BENCH_REQUIRE_ENV` asserts the knob off `docker inspect` before the first cell — the J9
lesson; a run that silently measured the default mode is worse than no run.

## 6) Targeted cell D — SCIM supervised first run (~15 min)

```bash
just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
BENCH_ENABLE_PENDING_SCENARIOS=1 \
  just target=axiam profile=p2-tls13 scenario=scim_provisioning.js bench-run
just target=axiam bench-down
```

Prereqs are already in place (`/scim/v2` shipped, `scim_per_min = 600`, `seed.sh`
provisions the global `bench-scim` role on the bench **user** — the scenario mints a
user token because a `client_credentials` service-account subject can hold no RBAC
permission). Check `k6_exit_code == 0` in the cell's `meta.json`, then hand to Claude
for the un-pend commit (§0 post-run task).

## 6b) Targeted cell E — nested-resource authorization depth sweep (~1 h)

The one cell in this round that runs competitors. It answers a question the archive
has never had an answer to: **what does it cost to authorize a resource that sits N
levels below the one carrying the grant, and how does that cost move as N grows** —
for AXIAM, Keycloak and Zitadel, over REST and (where the capability exists at all)
gRPC.

```bash
# The default ladder — depths 0 1 2 4 8 16, all three targets, both transports
# where they exist. ~1 h.
just bench-nested

# Narrower/cheaper variants (pick one if time is short):
just nestedtargets="axiam keycloak" bench-nested          # drop the capability-gap arm
just nesteddepths="0 4 16" bench-nested                   # three rungs instead of six
just profile=p2-tls13 bench-nested                        # the same ladder over TLS 1.3

# Re-render the summary from an existing tree (no containers, no k6):
just bench-nested-report
```

`bench-nested` brings each target up **once**, seeds it **once**, and runs every rung
against that one stack — the resource chain is provisioned incrementally in `setup()`
and re-used, so a deeper rung adds levels rather than rebuilding. That is minutes
instead of hours; the cost is that later rungs meet a warmer stack than earlier ones.
`nestedpause` (default 30 s) sits between rungs and the per-cell settle gate still
runs. If a cold-stack ladder is needed, run the rungs by hand with a `bench-down`
between them and **say so in the write-up**.

Output lands in `results/nested/d<N>/<target>/<profile>/authz_nested_{rest,grpc}.*`,
one level deeper than `report.py`'s walk reaches — so `bench-report` never sees these
cells, deliberately, exactly as it never sees `results/dry-run/`. A depth ladder is
not a matrix: its cells differ in a knob, not in a target/profile coordinate.
`runner/nested_report.py` is that tree's own reader and runs automatically at the end
of the sweep, writing `results/nested/SUMMARY.md`. `bench-pack` picks the tree up by
extension, so nothing extra is needed to share it.

**Read this before quoting a single number from it.** The three arms do not run the
same product mechanism, because only one of the three has the mechanism
(`benchmarks/scenarios/lib/nested.js` carries the full reasoning; the summary repeats
the caveat on every table):

| target | what its arm actually does | depth meaningful? |
|---|---|---|
| **axiam** | A real hierarchy walk. One role assignment on the chain root cascades to the leaf; `engine.rs`'s `applicable_role_ids` accepts an assignment scoped to any ancestor, and the ancestor set comes from one recursive graph query over the `child_of` edge. | yes |
| **keycloak** | No parent/child relation exists. Nesting is expressed as URI paths over a flat resource set: one `/<root>/*` resource + one scope-based permission covers the subtree, and the decision request asks about the full leaf path with `permission_resource_format=uri` + `permission_resource_matching_uri=true`. Same administrative shape (one grant covers the subtree), different resolution mechanism. | yes |
| **zitadel** | **No per-resource decision endpoint exists at all.** Project roles ride in the token and the application decides locally. The arm measures the role-claim round trip a resource server makes before deciding — depth-invariant *by construction*. `nested_report.py` refuses to compute a slope for it and prints why. | no — capability gap |

So the publishable artifact is **per-target depth sensitivity** (each product against
itself), plus an absolute cross-target table that is never quoted without its caveat.
Do not write "AXIAM is Nx faster at depth 16" — write what each arm did.

Two failure modes worth knowing before you start:

- **Every arm's `setup()` is fail-closed.** The decision at the requested depth must
  return the expected verdict before the measured window opens. A misprovisioned
  fixture takes the SHORT deny path — *cheaper* than the walk the cell exists to
  measure — so a silent deny would publish an optimistic number for the wrong code
  path. A rung that dies in setup has told you something; do not work around it.
- **If the Keycloak probe fails on the leaf path**, that build's URI matcher did not
  recurse through `/*`. Re-run that arm with `BENCH_KC_NESTED_MODE=per-node` (one
  registered resource + permission per level) and **label it as the per-node
  control** — its decision cost is depth-flat by construction and its admin cost is
  O(N), so it is not interchangeable with the wildcard arm:

  ```bash
  BENCH_KC_NESTED_MODE=per-node just nestedtargets="keycloak" bench-nested
  ```

Depth ceiling: the ladder validator refuses anything above 40, because
`crates/axiam-db/src/repository/resource.rs` sets `MAX_ANCESTOR_DEPTH = 50` and
`get_ancestors` returns an **error** — not a truncated walk — at that many ancestors.
A rung near 50 would measure the depth-overflow path, not the authorization path.

Prerequisites: none beyond the usual (docker, k6, jq, and Keycloak/Zitadel able to
seed — `just targets="axiam keycloak zitadel" profiles="p0-plaintext" bench-dry-run`
rehearses that in minutes). The sweep provisions everything else itself: AXIAM's
resource chain through the admin REST API, and Keycloak's whole resource server
(a **dedicated** `bench-nest-rs` client — the seeded `bench-client` is deliberately
left untouched so no other cell's fixture changes under it).

## 7) Optional, if time remains (priority order)

1. **seed-scale, 1× vs 10× only** (~30 min): one p2 stack; run `authz_check_rest.js` at
   baseline into `results/e4-seed-1`, then `just scale=10 bench-bulk-seed` and re-run
   into `results/e4-seed-10`. Skip 100× — the seeding alone is long.
2. **bench-quick** (~4 min; needs a live p3 stack + seed): X5 certificate/DPoP binding
   overhead. Output in `results/quick/` — deliberately outside `bench-report`.

**SKIP — not runnable today. Both entries changed at alpha38; read them again even if
you ran this round before.**

- **Reactor hook-cost cell — still skip, for a NEW reason, and it is the more
  dangerous one.** The old reason is gone: `LapinReactorTransport` is merged and
  `axiam-server` composes it, so the transport is no longer a stub. But nothing
  consumes the reactor queue. A dispatch against a registration with no reactor behind
  it now publishes and waits out `timeout_ms` for a reply that cannot arrive, then
  resolves through `token.pre_issue`'s default `fail_open`.

  So the cell got further from measurable, not closer. The old artifact was wrong and
  *looked* wrong — a fast failure path. Today's is wrong and looks **right**: a
  per-request cost in roughly the units and shape a reader expects "+1 AMQP RTT" to
  have, which is actually a timeout. Publishing it would be worse than publishing
  nothing. Closing this needs something that answers the queue (R2.5's `reactor_serve`,
  or a hand-rolled no-op consumer), plus the still-open admin-session helper in
  `lib/auth.js`. `bench-quick`'s Cell 2 now detects the wiring correctly (§0 M4) and
  says all of this in its output.

- **amqp-tls — obsolete as a cell, because it is no longer a variable.** AMQP is
  TLS-only server-side and in every stack, so there is no plaintext arm to compare
  against; a TLS-vs-plaintext cell cannot be built without reintroducing a transport
  the server refuses. The cost is folded into every AMQP-carrying figure this round
  produces, which is why §1 says to re-baseline rather than extend the run-5 line.

## 7b) Shipped since alpha25 with no bench cell — name these as gaps, do not invent numbers

Three contract surfaces landed between alpha25 and alpha38 and none has a scenario.
That is a legitimate state for this round; what is not legitimate is a write-up that
leaves a reader assuming the round covered them. List them explicitly.

| Surface | Contract | Rate-limited? | Cell |
|---|---|---|---|
| WebAuthn / passkeys — six `/api/v1/auth/webauthn/*` routes | §24 | **No — see below** | none |
| Account lifecycle — export, delete, delete/cancel | §25 | yes (`register_per_min`, `password_reset_per_min`) | none |
| PAR — `POST /oauth2/par` | §26 | yes (`par_per_min` = 120) | none (a §0 M5 "not checked" row) |

**The WebAuthn row is a finding, not a scheduling note, and it belongs in the write-up
even though it is not a benchmark result.** The six routes registered in
`crates/axiam-api-rest/src/server.rs` carry no rate limiter — no `build_governor`, no
`RateLimitShared` — and there is no `webauthn_per_min` field in `RateLimitConfig`. The
MFA routes immediately above them in the same scope each carry `mfa_per_min`, and the
OPAQUE routes below them each carry `login_per_min`, so this reads as an omission
rather than a decision. Two of the six —
`/webauthn/authenticate/discoverable/{start,finish}` — are the unauthenticated
usernameless sign-in path.

The consequence for this round is narrow and worth stating precisely: `rl-prod` (§4)
cannot report a gap here, because a family that does not exist cannot be extracted,
compared, or listed as "not checked". It is invisible to the pass by construction. So
say it in prose. Sizing a limit is a server decision, not a benchmark one — the
benchmark's job is to have noticed.

---

## 8) After the run — hand back to Claude (Opus 5)

- `just bench-report` for the matrix tree; collect the labeled dirs
  (`results/e4-*`, `results/rl-prod`, `results/quick`, `results/nested`);
  `just bench-pack` to share (pack-filelist guards `.seed/` and secrets).
- Read `results/nested/SUMMARY.md` (§6b) before writing up anything about nested
  authorization. Publish **per-target depth sensitivity** as the headline and the
  absolute cross-target table only with its model caveat attached; state plainly
  that the Zitadel arm is a capability gap rather than a slow result, and which
  Keycloak nesting model (`wildcard` or the `per-node` control) produced the
  numbers. If any rung is listed under "Invalid rungs", it is not publishable
  until re-run or explained — `nested_report.py` exits non-zero precisely so that
  cannot be scrolled past.
- Update **`benchmarks/PUBLIC_BENCH_ANALYSIS.md`**: flip the §7 rows that now PASS
  (stating the pass was single-profile p0), close A2 with before/after (or document the
  accepted trade honestly), publish each labeled cell with its distinguishing config.
  Carry the §4 count as measured — sixteen families checked of twenty-one rows, with
  the five `not checked` ones named — rather than as "the limiters are verified".
- Update **`benchmarks/PRIVATE_BENCH_ANALYSIS.md`** and
  **`claude_dev/performance-report.md`** (A2 post-mortem section).
- Refresh the website comparison page's "measured cost" claims (the correctness half
  landed in R4.4; the numbers half was waiting on this run).
- Honesty rules (from `run5-runbook.md` §"When writing up"): record image ref **and
  digest** from `meta.json`; state whether the published image or a local build was
  measured; report refuted hypotheses as refuted; do not reintroduce the corrected
  "≥500× below capacity" claim (correct range 25–2700×); keep the D8 `client_id`-keying
  caveat wherever rate-limit numbers appear.
- Four rules specific to this round, each guarding a way its numbers can mislead:
  1. **AMQP-carrying figures are a new baseline.** The broker hop went from plaintext
     to TLS-only since run 5. Present them as a re-baseline; do not extend a trend
     line across that boundary. Competitor arms are unaffected.
  2. **The OPAQUE cells are the server's half of the handshake, first measured this
     round.** Do not chart them against the retired SRP series, and do not present
     `opaque_login_start` as the cost of an OPAQUE login — the client's Argon2id and
     curve work are excluded by design.
  3. **State the §7b gaps.** WebAuthn, account lifecycle and PAR have no cells; the
     WebAuthn routes additionally have no rate limiter for §4 to check. A round that
     stays silent about all three reads as a round that covered them.
  4. **No reactor hook number.** Not "pending a stub" any more — pending a consumer.
     See §7 for why today's available number is the more misleading one.
