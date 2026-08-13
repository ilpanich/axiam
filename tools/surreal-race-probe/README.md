# surreal-race-probe

Measures whether a SurrealDB storage engine actually serialises two concurrent
read-modify-writes on the same record — the "claim this row exactly once" shape
behind every single-use credential in AXIAM.

## Why this exists

Issue #302 recorded a residual double-redemption rate (~1 in 640) on the UMA
permission-ticket path and attributed it to SurrealDB not detecting write-write
conflicts. Re-measuring with this probe in 2026-08 found something narrower and
more useful: **the behaviour depends on the storage engine, and the defect is
`kv-mem`'s.**

| Datastore      | Mechanism        | Rounds × racers | Rounds admitting two winners | Attempts the engine aborted |
|----------------|------------------|-----------------|------------------------------|-----------------------------|
| `kv-mem`       | v30 transaction  | 1200 × 8        | **23**                       | 5229 / 9600 (54%)           |
| `kv-mem`       | v30 transaction  | 1200 × 8 (re-run) | **10**                     | 5219 / 9600 (54%)           |
| `kv-mem`       | v31/v32 nonce    | 1200 × 8        | **6**                        | 0 / 9600                    |
| `kv-surrealkv` | v30 transaction  | 5000 × 8        | 0                            | 21613 / 40000 (54%)         |
| `kv-surrealkv` | v31/v32 nonce    | 5000 × 8        | 0                            | 0 / 40000                   |
| `kv-rocksdb`   | v30 transaction  | 1200 × 8        | 0                            | 8154 / 9600 (85%)           |
| `kv-rocksdb`   | v31/v32 nonce    | 1200 × 8        | 0                            | 0 / 9600                    |

Measured on `surrealdb` 3.2.3 / `surrealdb-core` 3.2.4 / `surrealkv` 0.21.3,
embedded, Linux x86_64, multi-threaded tokio. Re-measured on 3.2.4 for X6 with
the same conclusions — **[`RESULTS.md`](RESULTS.md) is the authoritative,
version-pinned record**; the table above is kept because it is what the
narrative below refers to.

Read the abort column before the winners column. `kv-mem` is **not** failing to
arbitrate — it aborts contended attempts at the same 54% rate `surrealkv` does.
It arbitrates and then occasionally misses, silently, with both callers
receiving the pre-transition row and neither receiving an error. The two
persistent engines did not miss once.

This is why `docker-compose.e2e.yml` no longer runs `memory`, why the k8s
StatefulSet names `surrealkv:` explicitly, and why the serialisation tests in
`axiam-db` open a surrealkv datastore via `tests/common` rather than `Mem`.

## The canonical falsifier: `mem tx 1200 8`

```sh
cargo run --release -- mem tx 1200 8
```

**This is the test that fails the old mechanism reliably**, which is issue
#302's acceptance bar. It reproduces double redemptions dependably — 23 rounds
in 1200 on the first run, 10 on a re-run, 12 when X6 re-measured it on 3.2.4 —
where the in-tree integration test that was supposed to guard the same property
needed `cargo-llvm-cov` coverage instrumentation *plus* a saturated machine to
surface it once, and passed routinely otherwise.

`tx` is the pre-X6 mechanism: one guarded `UPDATE` inside `BEGIN`/`COMMIT`,
with no nonce, trusting the engine to abort every loser. `mem` is the engine on
which that trust is misplaced. So this invocation is the reproducer to reach
for when you need to see the defect rather than reason about it, and it is the
falsifier the layered mechanism has to survive: run `surrealkv tx` at the same
scale and the same shape yields zero.

**Do not add a `kv-mem` serialisation test to CI.** It would be flaky by
design — a defect that appears in ~1% of contended rounds cannot be asserted on
in a single CI run without either accepting intermittent reds or inflating the
round count until the job is unaffordable. The regression suite is the three
`*_serialises` / `_yield_exactly_one_winner` tests in `axiam-db`, which run on
`surrealkv` and must stay green; the `kv-mem` behaviour is documented here,
measured in [`RESULTS.md`](RESULTS.md), and prevented in production by the
deployment layer plus the startup engine attestation in
`axiam_db::engine_attestation`.

## The version-bump gate

Since X6 this probe is not only diagnostic — it is a required check.

[`.github/workflows/surreal-race-probe.yml`](../../.github/workflows/surreal-race-probe.yml)
runs on every pull request. A cheap `detect` job compares the `surrealdb`,
`surrealdb-core` and `surrealkv` versions in `Cargo.lock` against the base
commit (via [`scripts/surreal-engine-versions.sh`](../../scripts/surreal-engine-versions.sh)).
If they are unchanged the probe is skipped and the `Race probe gate` job passes
immediately; if any of them moved, the probe runs against `surrealkv` at
5000 × 8 in **both** the `tx` and `nonce` shapes and the gate fails on any
double-winner round. `Race probe gate` is the job to mark required in branch
protection — it always reports, so it never blocks an unrelated PR.

The workflow can also be triggered by hand (`workflow_dispatch`), with the
round and racer counts as inputs.

Before spending the build, the job runs
[`scripts/check-probe-pin.sh`](../../scripts/check-probe-pin.sh), which asserts
that this directory's lockfile pins the same three crates as the workspace's.
A probe measuring a different version than the server runs is a green gate that
means nothing, and the two lockfiles had already drifted once before anyone
noticed.

**If you bump SurrealDB**, the procedure is:

1. Update the workspace `Cargo.lock`.
2. Re-pin `tools/surreal-race-probe/Cargo.toml` to the same `surrealdb` version
   and `cargo update -p surrealdb --precise <version>` in this directory.
3. Run the two surrealkv shapes at 5000 × 8 locally, or let the CI job do it.
4. **Append** the numbers to [`RESULTS.md`](RESULTS.md) as a new section — do
   not overwrite the old one. What the previous version did is what makes the
   new number mean anything.
5. If the gate goes red, do not weaken it. The pinned fallback is recorded in
   `claude_dev/extra-B-track-features.md` §X6.2 — single-writer serialisation
   in front of the datastore via a RabbitMQ single-active-consumer redemption
   queue — and that is the point at which building it is justified.

## When else to re-run it

- **Changing the deployed engine** in compose or the k8s manifests.
- **Triaging an intermittent failure** of a `*_serialises` test in `axiam-db`.
  Run the probe against the engine that test uses before touching the test.

## Running it

Excluded from the workspace deliberately — its dependency set (three storage
engines, one of which builds RocksDB from C++) is far heavier than anything the
server needs, and CI should not pay for it on every commit. It carries its own
`Cargo.lock` as a consequence, which `scripts/check-probe-pin.sh` keeps aligned
with the workspace's.

```sh
cd tools/surreal-race-probe

# memory and surrealkv (fast build)
cargo run --release -- mem       tx    1200 8
cargo run --release -- surrealkv tx    5000 8
cargo run --release -- surrealkv nonce 5000 8

# rocksdb (adds a ~10 minute C++ build the first time)
cargo run --release --features rocksdb -- rocksdb tx 1200 8
```

Arguments are `<engine> [mechanism] [rounds] [racers]`:

- `engine` — `mem`, `surrealkv`, or `rocksdb`
- `mechanism` — `tx` (one guarded `UPDATE` inside `BEGIN`/`COMMIT`, which asks
  the engine to arbitrate) or `nonce` (a per-attempt nonce written then read
  back outside any transaction, which asks the engine for nothing)

  These were the two candidate mechanisms while #302 was open, and the probe
  measures them separately because they measure different things. Since X6 the
  three consume paths in `axiam-db` run **both**, layered: the transaction
  arbitrates and the nonce audits it, so a double redemption needs the `tx`
  shape and the `nonce` shape to fail on the same row. The gate therefore runs
  both, and a regression in either is a regression in the shipped mechanism.
- `rounds`, `racers` — default 1200 and 8

Correct behaviour is **exactly one winner per round**. Zero winners is also a
failure: a row consumed but claimable by nobody is a burned credential.

`PROBE_DIR` sets where the disk-backed engines write (default
`/tmp/surreal-race-probe`). Use a fresh directory per run.

## Reading the output

```
engine=surrealkv mechanism=tx rounds=5000 racers=8
  rounds with >1 winner : 0
  rounds with 0 winners : 0
  attempts aborted      : 21613 of 40000 (the engine arbitrating)
  unexpected errors     : 0
  VERDICT: exactly one winner in every round
```

A zero abort count with zero violations (the `nonce` rows above) means the
mechanism never gave the engine anything to arbitrate — it is not evidence
about the engine. Only the `tx` rows measure conflict detection.

Note the limitation: the probe drives the engines **embedded, in-process**,
while the server talks to `surreal` over HTTP. The datastore underneath is the
same, but the remote path has not been measured this way.
