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

## surrealdb 3.3.0 / surrealdb-core 3.3.0 / surrealkv 0.21.4

**Taken:** 2026-09-25, for the dependency update in PR #501. It moved `surrealdb` and
`surrealdb-core` from 3.2.4 to 3.3.0, and `surrealkv` stayed at 0.21.4. The same bump
moved the in-memory engine `surrealmx` from 0.22.0 to 0.27.0. That crate is what
`kv-mem` runs on, and the gate does not track it.
**Host:** Linux x86_64, 4 vCPU, embedded engines, multi-threaded tokio, otherwise
idle. Each `surrealkv` run used its own fresh `PROBE_DIR`, as CI does.
**Probe commit:** the one that re-pinned this lockfile to `=3.3.0`.

| Datastore      | Mechanism | Rounds × racers | Rounds with >1 winner | Rounds with 0 winners | Attempts the engine aborted |
|----------------|-----------|-----------------|-----------------------|-----------------------|-----------------------------|
| `kv-surrealkv` | `tx`      | 5000 × 8        | **0**                 | 0                     | 14 534 / 40 000 (36%)       |
| `kv-surrealkv` | `nonce`   | 5000 × 8        | **0**                 | 0                     | 0 / 40 000                  |
| `kv-mem`       | `tx`      | 1200 × 8, ×4    | **0** in each run     | 0                     | 3 490–3 517 / 9 600 (36%)   |
| `kv-mem`       | `tx`      | 5000 × 8        | **0**                 | 0                     | 14 632 / 40 000 (37%)       |
| `kv-mem`       | `nonce`   | 1200 × 8, ×3    | **0** in each run     | 0                     | 0 / 9 600                   |
| `kv-mem`       | `nonce`   | 5000 × 8        | **0**                 | 0                     | 0 / 40 000                  |

`rocksdb` was not re-measured. It is not part of the CI gate.

### What changed against 3.2.4

For `surrealkv`, which is the engine AXIAM deploys and the one the gate measures,
nothing changed in the property AXIAM depends on. It still gives zero double winners
and zero burned rounds over 40 000 contended attempts in both shapes. Its `tx` abort
rate is 36%, down from 87% on the 12 vCPU host and 57% on the earlier 4 vCPU host.
The abort rate is the engine arbitrating, and it depends on how many racers overlap
in practice. So this number does not compare across hosts or releases. The zero in
the winners column is the measurement.

`kv-mem` did not leak in any of nine runs: 0 double winners over 78 400 contended
`tx` attempts in five runs and 68 800 `nonce` attempts in four. Every earlier section recorded leaks at
1200 × 8 (3 to 23 rounds for `tx`, 3 to 10 for `nonce`), so this is the first
measurement that reads differently. The likely cause is the `surrealmx` move from
0.22.0 to 0.27.0, but this probe cannot establish that, and a clean result does not
prove a guarantee. **Nothing downstream changes because of it.** `kv-mem` stays
excluded from deployments and from CI. The startup engine attestation still refuses
it unless the dev-only override is set. The README's canonical-falsifier note stays as
it is, because it describes the engine that the #302 decision was made on. If a later bump brings the leak back, this
section is the baseline for "it was clean on 3.3.0".

---

## surrealdb 3.2.4 / surrealdb-core 3.2.4 / surrealkv 0.21.4

**Taken:** 2026-09-18, for the dependency update in PR #481 (`8fc27c243`). It moved
the workspace's `surrealkv` from 0.21.3 to 0.21.4, and `surrealdb` / `surrealdb-core`
stayed at 3.2.4.
**Host:** Linux x86_64, 12 vCPU, embedded engines, multi-threaded tokio, otherwise
idle. Each `surrealkv` run used its own fresh `PROBE_DIR`, as CI does.
**Probe commit:** the one that re-pinned this lockfile.

| Datastore      | Mechanism | Rounds × racers | Rounds with >1 winner | Rounds with 0 winners | Attempts the engine aborted |
|----------------|-----------|-----------------|-----------------------|-----------------------|-----------------------------|
| `kv-surrealkv` | `tx`      | 5000 × 8        | **0**                 | 0                     | 34 732 / 40 000 (87%)       |
| `kv-surrealkv` | `nonce`   | 5000 × 8        | **0**                 | 0                     | 0 / 40 000                  |
| `kv-mem`       | `tx`      | 1200 × 8        | **3**                 | 0                     | 8 115 / 9 600 (85%)         |
| `kv-mem`       | `nonce`   | 1200 × 8        | **10**                | 0                     | 0 / 9 600                   |

`rocksdb` was not re-measured. It is not part of the CI gate, and the bump does
not touch it.

### What changed against surrealkv 0.21.3

Nothing in the property AXIAM depends on. `surrealkv` is still at zero double
winners and zero burned rounds over 40 000 contended attempts in both shapes. Its
`tx` abort rate went from 57% to 87%. That reads as the host (12 vCPU against 4
for the 0.21.3 row), because more racers actually run in parallel and so collide
more often. It does not read as an engine change: the abort rate is the engine
*arbitrating*, and a higher rate on a wider host is the expected direction.
`kv-mem` still leaks in both shapes. `tx` gave 3 rounds in 1200, below the 12 and
23 recorded earlier. `nonce` gave 10, above the earlier 3 and 6. The two moving in
opposite directions is the same bounce at this sample size that the 3.2.3
comparison describes, and it is not a trend. `kv-mem` remains excluded from CI,
per the README's canonical-falsifier note.

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
