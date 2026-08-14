# surreal-race-probe — recorded results

Every measurement this project makes about whether SurrealDB serialises two
concurrent read-modify-writes on one row lives here, pinned to the versions it
was taken against.

It is pinned because the property is not a documented guarantee. SurrealDB says
nothing about write-write conflict detection, so a bump can change it in either
direction without a changelog entry — and AXIAM's single-use credentials
(ilpanich/axiam#302) depend on it. A number without its versions beside it is
not a measurement, it is a memory.

`.github/workflows/surreal-race-probe.yml` re-runs the surrealkv rows whenever
`Cargo.lock` moves `surrealdb`, `surrealdb-core` or `surrealkv`. **Whoever
lands that bump records the new numbers here**, as a new section — append, do
not overwrite. What the previous version did is the only thing that makes the
new number mean anything.

Correct behaviour is exactly one winner per round. Zero winners is also a
failure: a row consumed but claimable by nobody is a burned credential.

---

## surrealdb 3.2.4 / surrealdb-core 3.2.4 / surrealkv 0.21.3

**Taken:** 2026-08-13, for X6 (the change that closed #302).
**Host:** Linux x86_64, 4 vCPU, embedded engines, multi-threaded tokio.
**Probe commit:** the one that added this file.

| Datastore      | Mechanism | Rounds × racers | Rounds with >1 winner | Rounds with 0 winners | Attempts the engine aborted |
|----------------|-----------|-----------------|-----------------------|-----------------------|-----------------------------|
| `kv-surrealkv` | `tx`      | 5000 × 8        | **0**                 | 0                     | 22 834 / 40 000 (57%)       |
| `kv-surrealkv` | `nonce`   | 5000 × 8        | **0**                 | 0                     | 0 / 40 000                  |
| `kv-mem`       | `tx`      | 1200 × 8        | **12**                | 0                     | 5 377 / 9 600 (56%)         |
| `kv-mem`       | `nonce`   | 1200 × 8        | **3**                 | 0                     | 0 / 9 600                   |
| `kv-rocksdb`   | `tx`      | 1200 × 8        | **0**                 | 0                     | 4 989 / 9 600 (52%) †       |
| `kv-rocksdb`   | `nonce`   | 1200 × 8        | **0**                 | 0                     | 0 / 9 600 †                 |

† The two rocksdb runs shared the host with a concurrent `cargo test`, unlike
the four rows above them. That does not weaken a zero — contention widens the
window the probe is looking for, so a clean run under load is stronger evidence,
not weaker — but it does explain the abort rate landing at 52% against 85% on
the unloaded 3.2.3 host. Read that cell as "the engine still arbitrates", not as
a rate to compare across sections. `rocksdb` is not part of the CI gate; AXIAM
deploys `surrealkv` in compose and in the k8s StatefulSet, and re-measuring
rocksdb costs a ~20 minute C++ build.

Read the abort column before the winners column. `kv-mem` is **not** failing to
arbitrate — it aborts contended attempts at 56%, essentially the rate
`surrealkv` manages at 57%. It arbitrates and then occasionally misses,
silently, with both callers receiving the pre-transition row and neither
receiving an error.

### What changed against 3.2.3

Nothing that matters, which is the useful finding. `surrealkv` is still at zero
double winners over 40 000 contended attempts in both shapes, and its abort rate
moved from 54% to 57% — noise on a differently-loaded host, not a behaviour
change. `rocksdb` is still at zero in both shapes. `kv-mem` still leaks in both
shapes: 12 rounds in 1200 for `tx` against 23 previously, and 3 against 6 for
`nonce`. Both `kv-mem` figures bounce substantially between runs at this sample
size, which is itself the point — a 1-in-100 defect is not something a single CI
run can be trusted to catch, and it is why `kv-mem` has no test in CI (see the
README's canonical-falsifier note).

The probe's `surrealdb` pin moved from `=3.2.3` to `=3.2.4` in the same change,
so that it measures what the workspace resolves. `scripts/check-probe-pin.sh`
now enforces that alignment; before X6 the two had already drifted apart and
nothing noticed.

---

## surrealdb 3.2.3 / surrealdb-core 3.2.4 / surrealkv 0.21.3

**Taken:** 2026-08, during the #302 re-investigation, before X6.
**Host:** Linux x86_64, embedded engines, multi-threaded tokio.

| Datastore      | Mechanism | Rounds × racers   | Rounds with >1 winner | Attempts the engine aborted |
|----------------|-----------|-------------------|-----------------------|-----------------------------|
| `kv-mem`       | `tx`      | 1200 × 8          | **23**                | 5 229 / 9 600 (54%)         |
| `kv-mem`       | `tx`      | 1200 × 8 (re-run) | **10**                | 5 219 / 9 600 (54%)         |
| `kv-mem`       | `nonce`   | 1200 × 8          | **6**                 | 0 / 9 600                   |
| `kv-surrealkv` | `tx`      | 5000 × 8          | 0                     | 21 613 / 40 000 (54%)       |
| `kv-surrealkv` | `nonce`   | 5000 × 8          | 0                     | 0 / 40 000                  |
| `kv-rocksdb`   | `tx`      | 1200 × 8          | 0                     | 8 154 / 9 600 (85%)         |
| `kv-rocksdb`   | `nonce`   | 1200 × 8          | 0                     | 0 / 9 600                   |

This is the run that found the defect engine-specific: the `kv-mem` numbers
behind #302 were being read as a property of SurrealDB, and they are a property
of the engine AXIAM's tests happened to open. It is why
`docker-compose.e2e.yml` stopped running `memory`, why the k8s StatefulSet names
`surrealkv:` explicitly, and why the serialisation tests in `axiam-db` open a
surrealkv datastore via `tests/common`.

---

## Earlier: the in-tree measurements behind #302

Before this probe existed, the numbers came from `axiam-db`'s own integration
tests running against `kv-mem` under `cargo-llvm-cov` on a saturated machine.
They are recorded in `SCHEMA_V31` and in #302, and they are per-attempt
wrong-outcome rates on the permission-ticket path rather than per-round winner
counts, so they do not line up column-for-column with the tables above:

| Mechanism                                 | Wrong outcomes |
|-------------------------------------------|----------------|
| v30: transaction + `WHERE consumed = false` | 1 / 320      |
| claim keyed on a record ID                  | 30 / 1200    |
| claim on a `UNIQUE` index, in a transaction | 3 / 320      |
| v31/v32: per-attempt nonce, write then read | 1 / 640      |

Two of the three obvious repairs were worse than the defect. #302 records why no
fifth query-layer mechanism was sought: none of them reaches zero, because none
of them can — the guarantee has to come from below the query layer. X6 took it
from the engine, and kept the nonce as the layer that does not depend on the
engine being right.
