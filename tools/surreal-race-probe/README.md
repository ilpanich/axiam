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
embedded, Linux x86_64, multi-threaded tokio.

Read the abort column before the winners column. `kv-mem` is **not** failing to
arbitrate — it aborts contended attempts at the same 54% rate `surrealkv` does.
It arbitrates and then occasionally misses, silently, with both callers
receiving the pre-transition row and neither receiving an error. The two
persistent engines did not miss once.

This is why `docker-compose.e2e.yml` no longer runs `memory`, why the k8s
StatefulSet names `surrealkv:` explicitly, and why the serialisation tests in
`axiam-db` open a surrealkv datastore via `tests/common` rather than `Mem`.

## When to re-run it

- **Bumping SurrealDB.** The measurements above pin one version. Conflict
  detection is not a documented guarantee, so a bump can change it in either
  direction, silently.
- **Changing the deployed engine** in compose or the k8s manifests.
- **Triaging an intermittent failure** of a `*_serialises` test in `axiam-db`.
  Run the probe against the engine that test uses before touching the test.

## Running it

Excluded from the workspace deliberately — it is diagnostic, its dependency set
(three storage engines, one of which builds RocksDB from C++) is far heavier
than anything the server needs, and CI should not pay for it on every commit.

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
- `mechanism` — `tx` (schema v30: one guarded `UPDATE` inside `BEGIN`/`COMMIT`,
  which asks the engine to arbitrate) or `nonce` (schema v31/v32: per-attempt
  nonce written then read back outside any transaction, which asks the engine
  for nothing)
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
