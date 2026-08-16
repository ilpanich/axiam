# Quick Benchmark Runbook — alpha25 (AXIAM-only, p0+p2+p3, single pass)

> **Purpose.** A time-boxed alternative to the full 3-run matrix for the alpha25 release:
> one full AXIAM-only pass at profiles p0/p2/p3, plus the highest-value targeted cells
> from the R7 measurement-debt table of
> [`remediation-plan-2026-08-15.md`](remediation-plan-2026-08-15.md). Prepared 2026-08-16
> against `main` @ `651d9e4`; every command verified against the harness as it exists
> (file:line citations in the notes). Companion docs:
> [`run5-runbook.md`](run5-runbook.md) (the full-matrix procedure),
> [`new-feature-bench-cells.md`](new-feature-bench-cells.md) (E4 labeled cells).
>
> **Time budget: ~8 h** for steps 2–6b (≈4.5 h matrix + ≈2.5 h targeted + ≈1 h the
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

## 0) Changes for Claude (Opus 5) to implement BEFORE the run

Neither change is strictly required — every command in this runbook works against the
harness as-is — but M1 removes a real foot-gun and both should land first.

> **Status: M1 and M2 both landed.** `run-benchmark.sh` now normalizes an
> extension-less `--scenario` to its `.js` filename *before* `filter_scenarios()`
> runs, the five copy-paste traps in `new-feature-bench-cells.md` are fixed, and
> `rl_prod_check.py` reads a `run-*/` matrix tree as well as a flat one (medianing
> across passes, as `report.py` does). Each is guarded by a hermetic CI self-test —
> `runner/scenario-filter-selftest.sh` and `runner/rl-prod-layout-selftest.sh`, both
> in the `bench-harness` job. The §4 `BENCH_RESULTS_DIR` workaround still works and
> is still the recommended form there; it is no longer load-bearing.

**M1 — Scenario-name normalization (recommended; prevents a silent failure + filter
bypass).** `benchmarks/runner/run-benchmark.sh:188` passes `--scenario` through verbatim;
a name without `.js` is not a file, **and** the filter-list membership tests compare
against `.js`-suffixed names, so an extension-less name also silently bypasses the
AXIAM-only/OAuth2 filters. Replace `SCENARIOS=("$SCENARIO")` with:

```bash
case "$SCENARIO" in *.js) SCENARIOS=("$SCENARIO") ;; *) SCENARIOS=("$SCENARIO.js") ;; esac
```

Also fix the five copy-paste traps in `claude_dev/new-feature-bench-cells.md` (lines 61,
69, 99, 109, 140) that write `scenario=authz_check_rest` etc. without `.js`.
(This runbook always writes `.js`, so it works without M1 — make the fix anyway.)

**M2 — Teach `rl_prod_check.py` the matrix layout (optional; §4 avoids the issue).**
`benchmarks/runner/rl_prod_check.py:222` reads only the flat
`results/<target>/<profile>/` layout, while `bench-matrix` writes `results/run-<i>/…`
even at `repeat=1`, so a bare `just rl-prod-check` against a matrix tree reports
"no data" for every endpoint. Add a `run-*/` glob fallback in
`load_k6_admitted_per_min` (mirroring the auto-detection `report.py` already does), or
rely on the `BENCH_RESULTS_DIR` workaround baked into §4.

**Post-run task (after §6):** if the SCIM cell passes (`k6_exit_code == 0`), un-pend it —
remove `scim_provisioning.js` from `PENDING_SCENARIOS` at
`benchmarks/runner/run-benchmark.sh:274` and delete the status block at
`benchmarks/scenarios/scim_provisioning.js:5-45` **in the same commit**; re-check the DTO
field names against the first real run and drop the "not yet re-checked" paragraph
(`scim_provisioning.js:47-55`).

---

## 1) Prep (~10 min)

- **Tag alpha25 first and let the release image publish.** `bench-up` defaults
  `BENCH_AXIAM_IMAGE` to `ghcr.io/ilpanich/axiam/server:<Cargo.toml version>`
  (`benchmarks/justfile:195-200`), so after the version bump it resolves to alpha25
  automatically. On pull failure it falls back to a local build (`justfile:279-289`) —
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

## 2) Full AXIAM matrix — p0, p2, p3, single pass (~4.5 h)

```bash
just targets="axiam" profiles="p0-plaintext p2-tls13 p3-mtls" repeat=1 bench-matrix
just bench-report
```

~20 cells × (~160 s + 60 s inter-cell pause) ≈ 72 min per profile, plus
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
hardcoded), covers 16 endpoint families — including device, token-exchange, UMA and
SCIM — asserts admitted ≈ configured ±10% per family, writes
`results/rl-prod/rl-prod-summary.md`, and exits 1 on any FAIL. This is the pass that
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

**SKIP — not runnable today, by design:**
- **Reactor hook-cost cell**: the server's reactor broker transport is a deliberate
  stub (`UnavailableReactorTransport`) until the lapin transport PR lands, and the
  scenario is pending on a k6 admin-session helper
  (`oauth2_client_credentials_reactor_hook.js` in `PENDING_SCENARIOS`). `bench-quick`'s
  Cell 2 will correctly print "Not run".
- **amqp-tls**: no scenario or recipe exists (`new-feature-bench-cells.md` marks it
  optional; the bench compose keeps the broker hop plaintext deliberately).

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
- Update **`benchmarks/PRIVATE_BENCH_ANALYSIS.md`** and
  **`claude_dev/performance-report.md`** (A2 post-mortem section).
- Refresh the website comparison page's "measured cost" claims (the correctness half
  landed in R4.4; the numbers half was waiting on this run).
- Honesty rules (from `run5-runbook.md` §"When writing up"): record image ref **and
  digest** from `meta.json`; state whether the published image or a local build was
  measured; report refuted hypotheses as refuted; do not reintroduce the corrected
  "≥500× below capacity" claim (correct range 25–2700×); keep the D8 `client_id`-keying
  caveat wherever rate-limit numbers appear.
