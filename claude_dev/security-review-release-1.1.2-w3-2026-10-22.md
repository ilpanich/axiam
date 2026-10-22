# Security review — release 1.1.2, wave W3 (F4)

**Date:** 2026-10-22.
**Against:** `claude/release-1.1.2-w3`, the whole wave diff `dc5bfd4..3ac0b9d` (5 commits,
26 files, 1490 lines added and 76 removed): `8f0be44` (W3.1, #755, D-7), `0480d26` (W3.2,
#729), `c01ddec` (W3.3, #746, D-13), `bf305bf` (W3.4, #747) and `3ac0b9d` (W3.5, #756, D-8).
Every commit carries one `gpgsig` header.
**Scope:** plan §4 and §10; `crates/axiam-db/src/schema.rs` (the runner, the lease, the
additive rule), `crates/axiam-db/tests/schema_test.rs`, `x3_wave2_query_plan_test.rs`;
`handlers/oauth2_clients.rs::update` and `axiam-oauth2/src/dcr.rs`, read beside
`axiam-oauth2/src/cimd.rs`; the seven handler files W3.5 annotated and `openapi.rs`'s new
test; `docs/deployment/README.md`, `docs/admin/dynamic-client-registration.md`,
`docs/api/device-flow.md`; T-424 and T-447 (both copies) and `website/src/threatModel.ts`;
the two generated spec files. `k8s/server/deployment.yml` was read for the lease's
interaction with the probes.
**Method:** every commit message and the full diff read, each claim checked against the
tree. The additive rule was re-derived independently (a Python classifier over the
`SCHEMA_V*` constants) and every released tag's migration list was compared with every later
tag's. The server was built (`--no-default-features`) and its `--dump-openapi` compared
byte-for-byte with `sdks/openapi.json`. The full `axiam-db` and `axiam-oauth2` test binaries
and the three `axiam-api-rest` targets the wave touched were run (§9). A scratch test (not
committed) checked the lease's refresh and release statements against an in-memory datastore.
This review fixes nothing.

---

## 0. Summary

**No Critical, High or Medium finding.** The lease does what D-7 asks: a live row refuses
the `CREATE`, the waiter polls, the holder refreshes and deletes only its own row, an expired
or 1.1.1 row is taken over, and a migration another starter recorded is tolerated because
each migration is one transaction (§2). The additive rule is a whitelist that classifies the
105 migrations exactly as an independent reading does, and no released upgrade path reaches
it (§3). The admin `PUT` bounds a `dcr` row's resources and redirects with registration's own
predicates (§4). Every status W3.5 declares is one the handler can return, and the spec in the
tree is the one the server emits (§6).

Six **Informational** findings. The one with substance is in W3.3: a `managed_by: cimd` row's
redirects are bounded by the **DCR** host list, while CIMD registration bounds them by
`cimd.trusted_redirect_domains` and the same-domain rule. So the commit's "the two paths
cannot disagree" holds for `dcr` rows only; for `cimd` rows the admin `PUT` both admits a
redirect registration would refuse and refuses one it would admit, and the test pins that. The
other five: the lease's tests never exercise the refresh or the own-row release, and the
concurrent test passes without the lease; the shipped Deployment's liveness probe kills a
replica that waits on a dead holder's lease; the non-additive refusal says "resolve the gap by
hand" with no procedure anywhere; the login hash gate's `503` was declared, but the same gate
answers `503` on two more operations, undeclared; and two text and hygiene items.

| ID | Finding | Severity | Surface / threat | Origin | Issue | Model for the fix |
|---|---|---|---|---|---|---|
| R112W3-01 | On a `managed_by: cimd` row the admin `PUT` checks new redirect URIs against `dcr_allowed_redirect_hosts`, but CIMD registration checks them against `cimd.trusted_redirect_domains`, `restrict_same_domain` (default on), `https`-or-loopback and no fragment (`cimd.rs:423-475`). An administrator can therefore give a CIMD client a redirect its registration would refuse, as long as the host is in the DCR list, and is refused one it would accept. The new test asserts the DCR rule for both kinds. The grant check in the same handler already distinguishes the two (`oauth2_clients.rs:674`). | Informational | `oauth2_clients.rs:715-762`; `cimd.rs:423-475`; `oauth2_client_test.rs:2387-2445`; T-447's neighbours (DCR/CIMD threats) | wave (W3.3) | [#768](https://github.com/ilpanich/axiam/issues/768) | Sonnet 5.5 |
| R112W3-02 | The lease's tests do not test the lease's lifetime. `refresh_lease` never runs in any test: the 30 s test TTL is never approached, and the 1 ms one comes with a one-hour refresh. Neither the "taken over" branch nor the claim that a release never deletes a successor's row has a test. `two_concurrent_starters_…` also passes **without** the lease, because the tolerance alone satisfies its assertions, as `starters_without_mutual_exclusion_…` shows. The statements themselves are right: a scratch test confirmed them (§2.4). | Informational | `schema.rs:2657-2818`; `schema_test.rs:291-353` | wave (W3.1) | [#769](https://github.com/ilpanich/axiam/issues/769) | **Opus 5.5** |
| R112W3-03 | The shipped Deployment has a `livenessProbe` on `/health` (30 s delay, 30 s period, default threshold 3) and no `startupProbe`, and the server binds HTTP only after `run_migrations`. A replica waiting on a dead holder's lease (up to five minutes, which the guide documents) is killed after about 90 s and restarts in `CrashLoopBackOff` until the row expires. A holder whose migrations outlive the probe is killed mid-run and leaves a five-minute lease. SIGTERM during the hold also leaves the row. The guide's "A rolling update or a scale-out from zero needs no special ordering" says none of this. | Informational | `k8s/server/deployment.yml:85-91`; `main.rs:515`; `docs/deployment/README.md:229-253` | wave (W3.1; the probe is pre-existing) | [#770](https://github.com/ilpanich/axiam/issues/770) | Sonnet 5.5 |
| R112W3-04 | The non-additive gap refusal ends "resolve the gap by hand", and the guide says the same. No document says how: what to inspect, when it is safe to apply vN's statements and record `_migration` by hand, or when to restore instead. The boot error is correct and fail-closed but not actionable. | Informational | `schema.rs:2834-2841`; `docs/deployment/README.md:247-253` | wave (W3.2) | [#771](https://github.com/ilpanich/axiam/issues/771) | Sonnet 5.5 |
| R112W3-05 | W3.5 declared `503` on login for "the password-hash gate". The same gate (`acquire_hash_permit`) answers `503` on `POST /api/v1/auth/password/change` (`axiam-auth/src/service.rs:1410`) and `POST /api/v1/auth/reset/confirm` (`password_reset.rs:293, 324`), and neither declares it (`['204','401','422']`, `['200','400']`). The listing test cannot catch this, by design (D-8). | Informational | `handlers/auth.rs:1401`; `handlers/password_reset.rs:289`; `openapi.rs` `declared_refusal_tests::UNAVAILABLE` | pre-existing; the class W3.5 fixed | [#772](https://github.com/ilpanich/axiam/issues/772) | Sonnet 5.5 |
| R112W3-06 | Text and hygiene. (a) The lease's doc comment and the guide say "the datastore's clock", and W3.4 (d) qualified that phrase for a clustered SurrealDB in three places but not here. (b) The new `EXPLAIN` pin copies the sweep's selection as a string literal rather than sharing it with `delete_stale_once`, so the two can drift and the test would still pass. (c) The guide says a 1.1.1 lease row is "read as stale and replaced", but not that a 1.1.1 replica still running in a rolling update ignores the lease and deletes a 1.1.2 holder's row on its way out. That is harmless for 1.1.1 → 1.1.2, which adds no migration, and worth one sentence. | Informational | `schema.rs:2611-2650`; `README.md:233-249`; `x3_wave2_query_plan_test.rs:126-158`; `repository/rate_limit.rs:256-261` | wave (W3.1, W3.4) | [#773](https://github.com/ilpanich/axiam/issues/773) | Sonnet 5.5 |

---

## 1. What was reviewed, and how

| Point of the brief | Where answered |
|---|---|
| W3.1: setup DDL rather than v110; concurrent first boot; rollback; 1.1.1 beside 1.1.2 | §2.1, §2.2 |
| W3.1: is the wait bounded; a crashed holder; documented | §2.3; R112W3-03 |
| W3.1: 60 s refresh under 5 min; long migration; clock skew | §2.3, §2.4; R112W3-02, R112W3-06 (a) |
| W3.2: the refused set; legitimate upgrade paths; actionable error | §3; R112W3-04 |
| W3.3: held-value exemption abuse; normalisation; shared rule with `dcr::validate` | §4; R112W3-01 |
| W3.4 | §5; R112W3-06 (b) |
| W3.5: declared statuses true; the listing test; digest, drift, registry, apiIndex | §6; R112W3-05 |
| Every commit message against the code; §10 | §10 |
| Tool runs | §9 |

---

## 2. The startup lease (W3.1, #755)

### 2.1 The columns in `MIGRATION_TABLE_DDL`, not v110

Sound, and the commit body states the deviation from §10. A numbered migration is applied
**under** the lease, so on the first 1.1.2 boot the lease's `CREATE … SET holder, expires`
would precede the `DEFINE FIELD` that a v110 would carry, and a `SCHEMAFULL` table refuses
the write. The two `DEFINE FIELD IF NOT EXISTS … option<…>` are additive and idempotent.

- **Two first-boot replicas running the setup DDL together.** The DDL is retried on a write
  conflict, up to four more attempts and with no backoff (`schema.rs:2665-2673`). It commits
  nothing on a conflict, and `IF NOT EXISTS` makes a later attempt a no-op.
  `two_concurrent_starters_…` runs it on `surrealkv`. Holds.
- **Rollback to 1.1.1.** 1.1.1's runner runs its own `MIGRATION_TABLE_DDL` (a no-op on the
  existing table), `UPSERT`s `locked_at` (both new columns are `option<>`, so the row stays
  valid), migrates nothing (1.1.2 adds no migration), and deletes the row. Holds.
- **A 1.1.1 replica beside a 1.1.2 one.** 1.1.1's `UPSERT … SET locked_at` merges into a live
  1.1.2 row: `holder` and `expires` survive, so the 1.1.2 holder's refresh still matches. 1.1.1
  never reads the row, so it does not wait, and its final unconditional `DELETE` removes the
  1.1.2 holder's lease. The holder's next refresh then logs "taken over or removed" and
  carries on, and a third starter may take a fresh lease. Neither side can corrupt anything,
  because there is no migration between the two releases and the tolerance (§2.2) covers an
  overlap. The other direction: a 1.1.2 starter finds 1.1.1's row (`expires = NONE`), deletes
  it as stale and proceeds, even while that 1.1.1 replica is alive. That is no worse than
  1.1.1 alone, which had no exclusion at all. The guide does not say this; see R112W3-06 (c).

### 2.2 Acquire, tolerate, release

- **Acquire** (`schema.rs:2704-2778`) is one transaction: `DELETE … WHERE expires = NONE OR
  expires <= time::now()`, then `CREATE`. Two starters that both see an expired row both
  delete it, both create, and one loses a write conflict. A live row makes the `CREATE` fail
  with a unique violation. Either way the starter reads the row; while a live holder is
  visible it waits indefinitely, and with none visible it retries at most eight times and then
  fails the boot. A fault that is neither a conflict nor a refusal fails the boot at once.
  Both predicates evaluate `time::now()` on the datastore, so a replica's own clock is not an
  input. Holds.
- **Tolerate** (`:2874-2891`): when a migration's transaction fails and `_migration` now
  records that version, the runner continues. This is correct only because the DDL and the
  `CREATE _migration` are one transaction. A loser's `UPDATE` backfill is rolled back with
  its refused record, so a non-idempotent migration is not run twice. Could the tolerance and
  W3.2 together produce a false gap refusal? A false refusal needs a starter to see v(n+1)
  recorded and vn not. Every starter applies in ascending order and records vn before trying
  v(n+1), and a tolerated vn was already recorded by its winner. So no snapshot shows that
  shape. Holds.
- **Release** (`:2686-2700`) runs on success and on failure, and deletes only `WHERE holder
  = $holder`. Holds (verified in §2.4).

### 2.3 How long a starter waits

- **A holder that dies** leaves a row that expires at most `ttl` (five minutes) after its last
  refresh. Every other starter waits that long, logging the holder once at `info`. The guide
  documents this ("at most five minutes later"). In the shipped Kubernetes manifest the wait
  meets the liveness probe; see R112W3-03.
- **A live holder** is waited on without bound, by design: the waiter cannot tell a long
  migration from a stuck one. The refresh is a separate future in the same `select!`, so it
  goes on while a long migration's query is in flight. A holder stuck in a datastore query
  keeps its lease for as long as the connection still serves the refresh. If the datastore is
  unreachable, the refresh fails too and the lease lapses. That trade is acceptable. The
  waiter's single log line is thin for an operator, and R112W3-03 proposes a periodic one.
- **60 s refresh under a 5 min TTL** leaves four missed refreshes before a lapse. A refresh
  that errors is logged and retried on the next tick.
- **Clock skew.** Replica clocks do not matter. On a clustered SurrealDB, `time::now()` is
  read on whichever node runs each statement, so node skew must stay under about four minutes
  (TTL less one refresh) for exclusion to hold. Past that, the tolerance still keeps the
  outcome correct. R112W3-06 (a) asks for the sentence W3.4 added elsewhere.

### 2.4 R112W3-02: the lease's lifetime is untested (Informational)

The five new tests cover acquisition (an expired row, a 1.1.1 row, a live row) and the
tolerance. None covers the lease's lifetime:

- `refresh_lease` is never polled to its first tick in a test. `FAST` has a 30 s TTL and a
  200 ms refresh, but a test's migration run takes milliseconds. `no_exclusion` refreshes
  hourly. A broken refresh statement (a typo, a wrong `RETURN`, a `take` of the wrong type)
  would only log a WARN each minute and let the lease lapse during a long migration, and every
  test would still pass.
- The "taken over" branch (`Ok(false)`) and "a successor's lease is never removed" (the
  release's `WHERE holder`) have no test.
- `two_concurrent_starters_both_succeed_and_record_the_version_once` is the issue's test, and
  it holds, but it cannot fail if the lease is removed. The pending migration is additive and
  the loser's record is tolerated, so "both boot, recorded once" is also the outcome without
  exclusion, which is what `starters_without_mutual_exclusion_…` asserts.

A scratch test (`crates/axiam-db/tests/zz_scratch_lease_refresh.rs`, run and deleted, not
committed) ran the refresh and release statements verbatim against an in-memory datastore.
The refresh returns `["me"]` and pushes `expires` past `now + 200 s` for its own holder. It
returns `[]` and touches nothing for another holder. A `DELETE … WHERE holder = 'other'`
leaves the row. So the code is right, and the finding is about the tests only.

**Proposed fix.** Unit tests in `schema.rs` (the functions are private): (1) acquire with
`ttl = 300 ms`, poll `refresh_lease` with `refresh_every = 50 ms` for 1 s under
`tokio::time::timeout`, and assert that the row is still live and still ours; (2) replace the
row with another holder, poll the refresh once, and assert that the other holder's row is
unchanged; (3) release with our holder while another holds the row, and assert that the row
survives. For mutual exclusion, assert in the concurrent test that the loser **waited**:
record every `_migration_lock` holder seen while both run (or count `info` lines with a test
subscriber), or give the runner a `#[doc(hidden)]` hook that counts transactions applied, and
assert that the pending version's transaction ran once.

### 2.5 R112W3-03: the liveness probe and the lease (Informational)

`k8s/server/deployment.yml:85-91`: `livenessProbe` `/health`, `initialDelaySeconds: 30`,
`periodSeconds: 30`, default `failureThreshold: 3`, and no `startupProbe`. The server binds
HTTP after `axiam_db::run_migrations` (`main.rs:515`), so a starter answers no probe while it
waits or migrates.

- A holder dies (or is killed: OOM, node loss). The next replica waits for the row to expire,
  up to 300 s, but the kubelet kills it at about 90 s. It restarts under `CrashLoopBackOff`
  (10, 20, 40, 80, 160 s …) and boots on the first attempt after expiry, which can be well
  past five minutes.
- A holder whose migrations take longer than about 90 s is killed mid-run. Its transaction
  rolls back, which is safe, but it leaves its lease, and its successor meets the same probe.
  A long migration (a large `UPDATE` backfill, a `UNIQUE` index over a large table) can then
  never finish under the shipped manifest. The probe hazard predates W3.1, but the lease adds
  the five-minute stall to it.
- SIGTERM (a rolling update that scales the old ReplicaSet down while one of its pods
  migrates) also leaves the row. No signal handler runs before the HTTP server exists.

The guide promises "A rolling update or a scale-out from zero needs no special ordering"
without a word on probes.

**Proposed fix.** Add a `startupProbe` on `/health` to `k8s/server/deployment.yml` with
`failureThreshold × periodSeconds` at least the lease TTL plus a margin (for example
`periodSeconds: 10`, `failureThreshold: 60`), so that the liveness probe starts only once the
server is up. Add a sentence to the guide's "Schema migrations at startup": a replica waits up
to five minutes behind a dead holder, so give the orchestrator a startup allowance at least
that long, as the shipped manifest does. Optionally, log the waiter's line again every
`ttl / 5` with the elapsed time, so that a stuck boot is visible. Test: `kubeconform` (or the
repository's manifest check, if any) on the edited manifest; `check-doc-links.sh`.

---

## 3. The additive rule (W3.2, #729)

**The refused set is right.** An independent classifier (any statement beginning
`UPDATE|DELETE|REMOVE|CREATE|UPSERT|INSERT|RELATE|LET|FOR|IF|BEGIN`, any `OVERWRITE`, any
`DEFINE` not followed by `<kind> IF NOT EXISTS`) refuses exactly `1-16, 23, 24, 35, 41-46, 48,
52, 53, 67, 81, 82, 102`, which is the set the unit test pins. No migration contains `\'`, so
the splitter's lack of escape handling misclassifies nothing today. It would fail closed for
a stray `;` (a fragment that does not start with `DEFINE` is refused) and could fail open only
if a crafted literal hid a statement, which cannot happen with migrations written in-tree.

The rule is wider than #729's list on purpose: it also refuses data statements and refuses
every `OVERWRITE`, including the ones that only widen an enum (v48, v102). That is the safe
direction, and the commit body says so.

**No legitimate upgrade path is refused.** Every released tag's version set (57 tags,
`v1.0.0-beta02` … `v1.1.1`, read with `git show <tag>:crates/axiam-db/src/schema.rs`) was
compared with every later tag's: no later tag introduces a version below an earlier tag's
highest. So an operator going from any release to 1.1.2 has no gap, and v86 … v89 are
unclaimed in every tag. A gap needs a branch build, as the doc comment says. A datastore that
ran such a build under 1.1.1 has already had its gap filled by #704's runner. A rollback leaves
no gap (the newer versions stay recorded above the older list). The tolerance cannot
fabricate one (§2.2).

`every_migration_since_1_1_0_is_additive` will fail the first time a later release needs a
backfill. Its message says the gap refusal must then be reconsidered, which is the intended
friction and what the plan asked for.

**Is the error actionable?** It names the version, the name and the reason, and says
"resolve the gap by hand". No document says how; see R112W3-04.

### 3.1 R112W3-04: "resolve the gap by hand" has no procedure (Informational)

`schema.rs:2834-2841` and `docs/deployment/README.md:247-253` both end at "resolve the gap by
hand". An operator who meets this boot error has no runbook. The error is fail-closed and
correct, so the refusal itself is right, but recovering from it is left to guesswork. That
guesswork is how a hand-run backfill overwrites the data #729 protects.

**Proposed fix.** Add a short subsection under "Schema migrations at startup":

1. Read vN's statements in `crates/axiam-db/src/schema.rs` (the error names vN and its name).
2. If every statement's effect is already present (a later migration redefined or
   overwrote the same objects), record the version without running it:
   `CREATE _migration SET version = N, name = '<name>'`. Give the exact field list of
   `_migration`, read from `MIGRATION_TABLE_DDL`.
3. If it is a backfill whose target rows a later migration or the application has since
   changed, do not run it; record it as in step 2 and decide about the data separately.
4. Otherwise, restore from the backup taken before the branch build, or ask.

Then make the error point there: "…; see docs/deployment/README.md#schema-migrations-at-startup".
Test: the existing `a_gap_below_a_non_additive_migration_is_a_boot_error` gains an assertion
on the pointer; `check-doc-links.sh`.

---

## 4. The admin `PUT` on a self-registered client (W3.3, #746)

**The held-value exemption cannot be used to keep widening.** A redirect is exempt per exact
URI string (`stored.redirect_uris.contains(uri)`), and a resource per exact normalised entry.
Holding one outside URI does not exempt a second URI on the same host, because every URI not
held is checked by host. Holding an outside resource exempts that entry only. Removing a held
value and adding it back in a later `PUT` re-checks it, because it is no longer held.

**No normalisation mismatch.** `allowed_resources` is normalised by
`validate_allowed_resources` (`oauth2_clients.rs:1045-1048`) before the comparison. The
stored list was normalised the same way when it was written, and the tenant's
`external_client_allowed_resources` is normalised on the settings write
(`settings.rs:94, 458, 768`). All three go through `resource::normalise_registration`. A
redirect URI is compared as a string, and a spelling that differs from the held one is checked
by host, which fails closed.

**For `dcr` rows the rule is the one `dcr::validate` uses.** `validate` now calls
`redirect_uri_refusal` (`dcr.rs:563-567`); resources match D3 (a registration copies the
tenant's list verbatim). The refusal returns before the write, a failed policy read is an
error (fail closed), and `admin` rows are not bounded. Holds.

**For `cimd` rows it is not**; see R112W3-01.

### 4.1 R112W3-01: a CIMD client's redirects are bounded by the DCR host list (Informational)

`registration_policy_refusals` (`oauth2_clients.rs:715-762`) checks every new redirect URI
of a `dcr` **or `cimd`** row with `dcr::redirect_uri_refusal(&settings.oidc.dcr_allowed_redirect_hosts, uri)`.
A CIMD client is not registered under that list. `cimd::validate` (`cimd.rs:423-475`)
requires each redirect to be:

- `https`, or `http` on a loopback host;
- free of a fragment;
- on a host in `cimd.trusted_redirect_domains` (loopback always allowed);
- when `cimd.restrict_same_domain` is on (the default, `settings.rs:797`), on the
  `client_id` URL's own host.

The module's table (`cimd.rs:73`) says so: "`redirect_uris` | the document, within
`cimd.trusted_redirect_domains`". The grant check in the same handler already treats the two
kinds differently (`oauth2_clients.rs:674`, `mode` is `None` for CIMD).

Consequences:

- **Widening.** With `dcr_allowed_redirect_hosts = ["*.partner.example"]` and the CIMD
  defaults, an administrator can add `https://x.partner.example/cb` to a CIMD client whose
  `client_id` is `https://mcp.vendor.example/…`. CIMD registration refuses that (wrong
  domain, and not in `trusted_redirect_domains`). The `PUT` admits it. That is the #746 class
  the commit claims to close.
- **Over-refusal.** With `dcr_allowed_redirect_hosts` empty (only loopback) and
  `trusted_redirect_domains = ["*.vendor.example"]`, an administrator cannot add
  `https://mcp.vendor.example/cb2`, which registration would accept.
- **The test pins it.** `admin_put_of_a_redirect_host_outside_the_tenant_list_is_422_on_dcr_and_cimd_rows_only`
  sets only the DCR host list and asserts `200` for `https://app.allowed.test/cb` on the CIMD
  row (`oauth2_client_test.rs:2397-2437`), which CIMD registration would refuse under its
  same-domain default.
- **Mitigation.** A CIMD row's `redirect_uris` is overwritten from the document on its next
  fetch (`upsert_cimd_client`, `repository/oauth2_client.rs:1047-1064`). An admin edit
  therefore lasts at most one cache period (`cimd.max_cache_secs`). It needs an
  administrator, as R111W3-03 did. Hence Informational.

The documentation repeats the error (`dynamic-client-registration.md:354-363`: "a
`redirect_uris` entry whose host is outside `dcr_allowed_redirect_hosts`"), and so do the
utoipa 422 text and the spec.

**Proposed fix.** Extract `cimd::validate`'s per-URI checks (`cimd.rs:432-475`) into
`pub fn cimd::redirect_uri_refusal(policy: &CimdPolicy, client_host: &str, uri: &str) ->
Option<String>`, and call it from `cimd::validate` and from the handler for `ManagedBy::Cimd`
rows. The `client_host` is the stored `client_id`'s host, since a CIMD `client_id` is the
document URL. Keep `dcr::redirect_uri_refusal` for `ManagedBy::Dcr`. Alternatively, refuse
every new redirect on a `cimd` row (`422 redirect_exceeds_registration_policy`, "a CIMD
client's redirects come from its document"), since the next fetch overwrites them anyway.
That is simpler and arguably more honest. Correct the doc paragraph, the utoipa text (then
regenerate the spec, digest and registry) and the commit's claim in the CHANGELOG. **Test:**
split the redirect test. For `dcr`, as now. For `cimd`, with `dcr_allowed_redirect_hosts`
naming the host and the CIMD policy not admitting it, assert `422`. With the CIMD policy
admitting it (same host as the `client_id`, or `restrict_same_domain` off and the domain
trusted), assert `200`.

---

## 5. Text and the `EXPLAIN` pin (W3.4, #747)

(a)–(d) are as stated. The RFC sentence stays in the schema doc and the #683 note is a `//`
comment, so the regenerated spec drops it. The device-grant comment reads as the plan asks.
For (c), `ConsoleSignIn` calls `extract_user` first (`extractors/auth.rs:421`), and that
checks the audience (`check_user_aud_and_parse_jti`) before `apply`'s `minted_for_client`, so
"refused `401` by the audience check first" is true. The skew sentence (d) is on T-424,
`cleanup.rs` and `CibaHintCap`, with identical text in the md, the JSON and `threatModel.ts`.

(e) `rate_limit_bucket_sweep_selection_is_index_satisfied` passes and asserts the index and
no table scan. The selection matches `delete_stale_once`'s today
(`repository/rate_limit.rs:256-258`), but as a copied literal; see R112W3-06 (b).

---

## 6. The spec (W3.5, #756)

**Every declared status is one the handler can return:**

- `422 reserved_metadata_key`: tenants create and update. Each calls `reject_reserved_metadata`
  (`tenants.rs:198-205, 286, 668`), which refuses the reserved key.
- `409 already_exists`: certificates generate and sign-csr (`certificate` UNIQUE on
  `issuer_ca_id, serial`), and CA generate, import, `signing-cas` generate and sign-csr
  (`ca_certificate` UNIQUE on `parent_ca_id, serial`, `schema.rs:5212-5215`). An import of a
  certificate already stored meets it in ordinary use. The generated ones meet it only on a
  serial collision.
- `503`: `bounded_permit` in `cert.rs:519, 610, 866`, `ca.rs:165, 500, 668` and
  `pgp.rs:66, 169` (eight sites, seven operations, as the body says), and login's
  `acquire_hash_permit` (`axiam-auth/src/service.rs:394, 479, 572`). CA import takes no permit.
  True.
- `409 stale_version` (`NetworkConflictResponse`): every one of the ten operations calls
  `network_gate::authorize` and then a `*_claimed` write, whose `AxiamError::Conflict` goes to
  `refused_after_clearance` and is answered `409` with `reason_code: stale_version`
  (`roles.rs:352-360, 401-407, 651-663, 711-723, 833-845, 893-905, 1083-1095, 1143-1155`;
  `permissions.rs:305-318, 490-503`).

**The listing test** reads the in-process `api_doc()`, not `sdks/openapi.json`. It is the
same object the exporter serialises, and the drift job (here, the byte-for-byte comparison in
§9) holds them equal, so this is equivalent. It is robust: it looks up `paths/<escaped
path>/<method>/responses/<status>` with RFC 6901 escaping and fails with the list of missing
operations. As D-8 intends, it cannot find a handler that is not on its list, and the same
statuses on other operations show that gap; see R112W3-05.

**Generated files.** `cargo build -p axiam-server --no-default-features`, then
`--dump-openapi`, is byte-identical to `sdks/openapi.json` (`cmp` exit 0). The digest is
`sha256:2a8630a55ccbee927fa8627e43e7831dfeaa7cfb492332a3203ec02f07ebb7ec`, and
`check-spec-digest.py` agrees. The registry is in sync, and `gen-api-index.mjs` leaves no
diff. **No CI run exists on this branch** (GitHub Actions lists none for
`claude/release-1.1.2-w3`; there is no PR), so "the drift job is green" was established
locally, not read from CI.

### 6.1 R112W3-05: the hash gate's `503` on two more operations (Informational)

`acquire_hash_permit` answers `ServiceUnavailable` (→ `503`) when no Argon2 permit comes free
within the configured wait. W3.5 declared it on `POST /api/v1/auth/login`. The same call is
reached from:

- `POST /api/v1/auth/password/change` (`handlers/auth.rs:1401`), through
  `AuthService::change_password` (`axiam-auth/src/service.rs:1410`), propagated with `?`
  (`handlers/auth.rs:1463-1472`). The spec declares `204, 401, 422`.
- `POST /api/v1/auth/reset/confirm` (`handlers/password_reset.rs:289`), through
  `PasswordResetService::confirm_reset` (`axiam-auth/src/password_reset.rs:293, 324`), also
  propagated with `?`. The spec declares `200, 400`.

These are the same refusal, from the same gate, on the same kind of operation (a password
hash), so an SDK that handles login's `503` as "retry later" has no spec basis to do so here.

**Proposed fix.** Add the login `503` line to both `#[utoipa::path]`s; add both operations to
`declared_refusal_tests::UNAVAILABLE` with a comment naming the gate; regenerate the spec,
digest and registry. If another `acquire_hash_permit` caller with a REST route turns up
(`grep -rn acquire_hash_permit crates/`), treat it the same way. The DB pool's own `503`
(`axiam-db/src/pool.rs:343-360`) can answer on any route and is better stated once, in the
spec's description or CONTRACT, than per operation; that is W7.1's call. **Test:** the
extended `crypto_permit_and_login_gate_declare_503`; `check-spec-digest.py`;
`gen-management-registry.py --check`.

### 6.2 R112W3-06: text and hygiene (Informational)

(a) **The lease's clock.** `run_migrations`' doc (`schema.rs:2632`, "a lease on the
datastore's clock") and the guide (`README.md:233-234`, "five minutes on the datastore's
clock"). W3.4 (d) made "the datastore's clock" precise for a clustered SurrealDB in three
places. Add the same sentence here: on a cluster, `time::now()` is each node's, and the lease
excludes only while node skew stays under the TTL less one refresh (about four minutes). Past
that, the tolerance keeps the outcome correct.

(b) **The `EXPLAIN` pin's string.** `x3_wave2_query_plan_test.rs:141-145` repeats the
selection of `SurrealRateLimitBucketRepository::delete_stale_once`
(`repository/rate_limit.rs:256-258`) as a literal. A change to the repository's predicate
leaves the test green on the old text. Move the selection into a `pub(crate)`/`#[doc(hidden)]
pub const RATE_LIMIT_BUCKET_SWEEP_SELECTION`, used by both. The test then appends ` EXPLAIN`
in place of the `LIMIT` clause's tail, or `format!`s the same const.

(c) **A 1.1.1 replica during the roll.** Add to the guide's 1.1.1-row bullet: "A 1.1.1
replica still running during the rolling update ignores the lease and removes it when it
finishes. 1.1.2 adds no migration, so this costs nothing; a 1.1.2 holder whose lease
disappears logs it and carries on." Also, for W8.4: the upgrade note.

Test: none (text), except (b): the moved const keeps
`rate_limit_bucket_sweep_selection_is_index_satisfied` and the `cleanup_task` sweep tests
green. `check-doc-links.sh`.

---

## 7. Threat model and website copies

T-424 and T-447 carry the W3.4 amendments, dated 2026-10-22, with the same text in
`claude_dev/threat-model-stride.md`, `ThreatDragonModels/Axiam/Axiam.json` and
`website/src/threatModel.ts`. There was no version bump, as W3.4 says, and W8.3 reconciles
once. No W3 threat entry was edited for #755, #729, #746 or #756. Whether one is owed is
W8.3's to decide: the DCR/CIMD redirect threat should read R112W3-01's fix once it lands.

---

## 8. What held (summary)

- The lease's acquire/refresh/release statements, run against a datastore (§2.4).
- Its interaction with a 1.1.1 binary, a rollback and a first boot (§2.1).
- The tolerance and the gap refusal compose without a false refusal (§2.2).
- The additive classification, and the absence of a released path that meets it (§3).
- The held-value exemption and the normalisation for `dcr` rows (§4).
- Every W3.5 status, and the spec in the tree equal to the server's (§6).

---

## 9. Checks run (each tool's own exit code)

Environment: `protobuf-compiler` 3.21.12 installed; swagger-ui placeholder
(`scripts/make-swagger-ui-placeholder.sh`); `CARGO_PROFILE_DEV_DEBUG=0
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`; one target at a time; libxml2 absent, so
`axiam-api-rest` ran `--no-default-features` (CI's "Build (SAML off)" shape).

| Command | Exit |
|---|---|
| `cargo build -p axiam-server --no-default-features` | 0 |
| `./target/debug/axiam-server --dump-openapi > dump.json`; `cmp dump.json sdks/openapi.json` | 0; 0 (byte-identical) |
| `python3 scripts/check-spec-digest.py` | 0 (`sha256:2a8630a5…b7ec`) |
| `python3 scripts/gen-management-registry.py --check` | 0 (202 operations, 29 namespaces) |
| `node website/scripts/gen-api-index.mjs`; `git status --porcelain` | 0; no diff |
| `cargo test -p axiam-db --no-fail-fast` | 0 (87 binaries: 1117 passed, 0 failed, 5 ignored) |
| `cargo test -p axiam-api-rest --no-default-features --test oauth2_client_test` | 0 (43 passed, 0 failed) |
| `cargo test -p axiam-api-rest --no-default-features --test device_flow_test` | 0 (40 passed, 0 failed) |
| `cargo test -p axiam-api-rest --no-default-features --lib openapi` | 0 (15 passed, the four `declared_refusal_tests` among them) |
| `cargo test -p axiam-oauth2 --no-fail-fast` | 0 (8 binaries: 840 passed, 0 failed) |
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy -p axiam-db --lib --tests -- -D warnings` | 0 |
| `cargo clippy -p axiam-api-rest --no-default-features --lib --tests -- -D warnings` | 0 |
| `cargo clippy -p axiam-oauth2 --lib --tests -- -D warnings` | 0 |
| scratch `cargo test -p axiam-db --test zz_scratch_lease_refresh` (§2.4; deleted, not committed) | 0 (1 passed) |
| independent additive classifier over `SCHEMA_V*` (Python) | same 32 versions as the pinned set |
| tag-by-tag migration sets, 57 tags (Python over `git show`) | no later tag adds a version below an earlier tag's highest |
| `git cat-file -p <c> \| grep -c gpgsig`, five commits | 1 each |
| GitHub Actions runs on `claude/release-1.1.2-w3` | none exist (no PR) |

---

## 10. Commit messages and §10

| Commit | Claim | Verdict |
|---|---|---|
| `8f0be44` | a real lease; refresh; own-row release; tolerate; columns in the setup DDL, not v110; guide section; five tests | true (§2); the tests do not cover the refresh or the release, and the concurrent one cannot fail without the lease (R112W3-02); the guide omits the probe interaction (R112W3-03) |
| `0480d26` | whitelist rule; refused set pinned; boot error naming the version; guide bullet | true (§3); the error's "by hand" has no procedure (R112W3-04) |
| `c01ddec` | two 422 codes; held-value exemption; shared helpers so "the two paths cannot disagree" | true for `dcr` rows; **not for `cimd`** rows (R112W3-01) |
| `bf305bf` | (a)–(e) | true (§5); (e)'s "written exactly as the sweep writes it" is a copy, not a link (R112W3-06 b) |
| `3ac0b9d` | four refusals declared on the listed operations; listing test; digest | true (§6); the same hash-gate `503` is undeclared on two more operations (R112W3-05) |

§10: every commit is signed. No migration is added (v109 stays the newest, and the
newest-version assertion is unchanged); the reason the lease's columns are not a v110 is
stated in the body and holds (§2.1). No `sdks/CONTRACT.md` edit. The spec and registry are
regenerated in-wave by W3.3, W3.4 and W3.5. No new route, no new crate. Each row's test is in
its commit. No test message interpolates a token or a secret: the new assertions print
response bodies of admin-API refusals and migration error strings.

---

## 11. What could not be verified

- **CI.** No workflow has run on this branch. The drift job's verdict is inferred from the
  local byte-for-byte comparison and the three generators, not read.
- **SAML on.** `axiam-api-rest` ran without the `saml` feature (no libxml2 headers). W3 does
  not touch SAML.
- **A clustered SurrealDB** and **the Kubernetes probe behaviour** (R112W3-03) are argued
  from the manifest and the boot order, not observed.
- **Mutual exclusion under real concurrency** is not demonstrated by any test (R112W3-02).
  The argument in §2.2 rests on SurrealDB's `CREATE` refusing an existing record id and
  aborting a conflicting transaction, both of which the existing tests exercise.

---

## 12. For later tasks

- **W7.1:** CONTRACT §27.4 rule 7 gains `resource_exceeds_registration_policy` and
  `redirect_exceeds_registration_policy`, as `c01ddec` notes. Its wording for CIMD rows must
  follow R112W3-01's fix (CIMD policy, or "not editable"). If R112W3-05 is fixed, the
  password-change and reset-confirm `503` belongs in the contract's retry guidance beside
  login's. Consider one global sentence for the DB pool's `503`.
- **W8.3:** after R112W3-01's fix, the DCR/CIMD redirect threat entry (and T-447's
  neighbours) say which policy bounds an admin edit of a CIMD row. Nothing else in W3 owes a
  threat-model edit.
- **W8.4:** the 1.1.1 upgrade note "roll replicas one at a time" is withdrawn (#755), and so
  is `website/src/data.ts:525`'s copy. The [1.1.1] #704 line is qualified (#729). The two new
  422 codes (#746) are stated for `dcr` rows, and for `cimd` rows as R112W3-01's fix decides.
  Add the startup-probe note (R112W3-03) to the 1.1.2 upgrade notes if the manifest changes.

---

## 13. Issues

Filed on `ilpanich/axiam`, milestone `1.1.x` (#23). Each body is the finding's subsection and
ends with the attribution footer. Searches for the migration lock, the CIMD redirect bound,
the probes and the undeclared `503` found only #755 (which this wave closes), so there are no
duplicates.

| ID | Issue |
|---|---|
| R112W3-01 | [#768](https://github.com/ilpanich/axiam/issues/768) |
| R112W3-02 | [#769](https://github.com/ilpanich/axiam/issues/769) |
| R112W3-03 | [#770](https://github.com/ilpanich/axiam/issues/770) |
| R112W3-04 | [#771](https://github.com/ilpanich/axiam/issues/771) |
| R112W3-05 | [#772](https://github.com/ilpanich/axiam/issues/772) |
| R112W3-06 | [#773](https://github.com/ilpanich/axiam/issues/773) |

---

## Addendum — the sweep

**Date:** 2026-10-22. **Against:** `90c6e72..6d674c6` (6 commits, 18 files, 650 lines added
and 98 removed): `c0e4f6d` (#768), `1511e17` (#770), `d18bcc2` (#771), `dc91af1` (#772),
`125ce20` (#773) and `6d674c6` (#769). Every commit carries one `gpgsig` header. Each diff
was read against the finding it closes, and the four checks the orchestrator named were made
(the seam, the probe numbers, the spec, the shared CIMD predicate). The touched test binaries
were run, and two mutations of the lease were run against the new tests.

### Verdict per finding

| ID | Issue | Closed? | Evidence |
|---|---|---|---|
| R112W3-01 | #768 | **Closed** | `cimd::validate`'s per-URI checks moved, unchanged, into `pub fn cimd::redirect_uri_refusal(&CimdPolicy, client_host, uri)` (`cimd.rs:592-635`). `validate` calls it (`:432-436`), and so does the handler for `ManagedBy::Cimd` rows (`oauth2_clients.rs:756-778`). It is **shared, not copied**: the old body was removed from `validate`, and the handler holds no second copy. The `client_host` is the stored `client_id` parsed as a URL; a row whose `client_id` has no host is refused (fail closed). Both parse with `url::Url`, so the hosts compare in the same normalised form. `dcr` rows keep `dcr::redirect_uri_refusal`. New test `admin_put_of_a_redirect_on_a_cimd_row_follows_the_cimd_policy` covers four cases: a DCR-listed host outside the CIMD policy gets `422` and the row is unchanged; the client's own trusted host is accepted with the DCR list empty; another trusted host is refused under `restrict_same_domain` and accepted without it; loopback is accepted. Scheme and fragment get `400` from the shape check that runs before the policy. Doc paragraphs (DCR and CIMD guides), the utoipa text and the spec are corrected. |
| R112W3-02 | #769 | **Closed** | `two_concurrent_starters_…` now asserts that the two critical sections do not overlap: each holds 150 ms inside the lease. New `a_holder_that_outlasts_the_ttl_keeps_its_lease` (refresh) and `a_takeover_is_observable_and_the_old_holders_release_spares_it` (the `Ok(false)` branch; the old holder's refresh and release leave the successor's row and `expires` untouched). Mutations run here: **refresh disabled** fails `a_holder_that_outlasts_…`; **acquisition returns at once** (no lease) fails five tests, including `two_concurrent_starters_…`. `schema_test` passed 5 of 5 repeated runs, so the timing margins (TTL 500 ms against a 100 ms refresh; 300 ms against 600 ms) are not flaky here. |
| R112W3-03 | #770 | **Closed** | `startupProbe` on `/health`, `periodSeconds: 10`, `failureThreshold: 60`: 600 s, which covers the documented worst case (a waiter behind a dead holder, ≤ 300 s, plus its own migrations) with 300 s of margin. Until it succeeds, the liveness probe does not run. The guide says the HTTP listener binds only after the migrations, gives the numbers and what happens without the probe, says SIGTERM leaves the row, and says that another orchestrator needs the same allowance and a migration over ten minutes needs the threshold raised. A remark, not a defect: each replica's ten minutes run from its own start, so a replica waiting behind a **live** holder whose migrations run past its own window is still restarted; the guide's "a datastore whose migrations run longer than ten minutes needs the shipped `failureThreshold` raised" covers that case. |
| R112W3-04 | #771 | **Closed** | A new "Recovering from a refused migration gap" section, in four ordered steps (inspect; record without running; run in one transaction with its record; restore). The `_migration` field list is correct (`version`, `name`, `applied_at` with a default; checked against `MIGRATION_TABLE_DDL`). The boot error points to the anchor, `a_gap_below_…` asserts the pointer, and `check-doc-links.sh` passes. |
| R112W3-05 | #772 | **Closed** | `503` declared on `POST /api/v1/auth/password/change` and `POST /api/v1/auth/reset/confirm` with login's text. Both are in `declared_refusal_tests::UNAVAILABLE`. The doc comment of `change_password` names the status. |
| R112W3-06 | #773 | **Closed** | (a) The cluster-clock sentence is in `run_migrations`' doc and in the guide. (b) `RATE_LIMIT_BUCKET_SWEEP_SELECTION` (`repository/rate_limit.rs:22-30`, `#[doc(hidden)] pub`) is used by `delete_stale_once` through `format!` and by the `EXPLAIN` test, which appends ` EXPLAIN`. The SQL text is unchanged, the sweep's tests pass, and so does the plan pin. (c) The rolling-update sentence is in the guide. |

**The test seam.** `run_migrations_under_lease` (`schema.rs:2672-2689`) and
`PendingMigrations` are `#[doc(hidden)] pub`. The seam takes a closure that receives the
migrations future, so it can be reached only from Rust code. No configuration key, environment
variable or CLI flag selects it. `run_migrations` → `run_migrations_with_lease` passes the
future through unchanged (`|migrate| migrate`), and nothing outside `axiam-db`'s own tests
calls either seam (`grep` over `crates/`: only `schema.rs`, `lib.rs` and `tests/`). A
dependent crate could call it, as it can call `run_migrations_with_lease`; that is the same
trade 1.1.2 already accepted for the timings, and it grants nothing a caller with a datastore
handle does not already have.

**The spec.** `cargo build -p axiam-server --no-default-features` and then `--dump-openapi`
give output byte-identical to `sdks/openapi.json` (`cmp` 0). The new digest is
`sha256:341270842703e04dc8b5326c2d193540bc44eb21bb3adad28bce996d1f661dee`.
`check-spec-digest.py` passes (0), `gen-management-registry.py --check` passes (0), and
`gen-api-index.mjs` leaves no diff. The spec diff is the digest, the two `503`s, the
password-change description line, and the admin `PUT`'s `422` text.

**New findings: none.** Two remarks, neither a defect:

- The last case of the CIMD test is commented "Loopback is always allowed, and a held URI is
  never re-checked". Loopback is admitted there because `restrict_same_domain` was turned off
  two steps earlier. With it on, a loopback redirect fails the same-domain rule, exactly as a
  document's does. The held-URI exemption is exercised by the `dcr` test, through the same
  code path that precedes the `managed_by` branch. The comment would read better as "with
  `restrict_same_domain` off, loopback is admitted"; this can ride any later edit of the file.
- `redirect_uri_refusal` has no unit test of its own in `cimd.rs`. `validate`'s existing
  tests reach it, and the new integration test covers the handler's call.

### Checks run on `6d674c6` (each tool's own exit code)

| Command | Exit |
|---|---|
| `cargo build -p axiam-server --no-default-features`; `--dump-openapi`; `cmp` with `sdks/openapi.json` | 0; 0; 0 |
| `check-spec-digest.py` / `gen-management-registry.py --check` / `gen-api-index.mjs` (no diff) / `check-doc-links.sh` | 0 / 0 / 0 / 0 |
| `cargo test -p axiam-db --no-fail-fast` | 0 (87 binaries: 1119 passed, 0 failed, 5 ignored) |
| `cargo test -p axiam-api-rest --no-default-features --test oauth2_client_test` | 0 (44 passed) |
| `cargo test -p axiam-api-rest --no-default-features --lib openapi` | 0 (15 passed) |
| `cargo test -p axiam-oauth2 --no-fail-fast` | 0 (8 binaries: 840 passed) |
| `cargo fmt --all -- --check`; clippy `-D warnings` on `axiam-db`, `axiam-api-rest` (`--no-default-features`), `axiam-oauth2` (`--lib --tests`) | 0; 0, 0, 0 |
| `cargo test -p axiam-db --test schema_test`, 5 repeats | 0 ×5 |
| mutation: refresh tick skipped (`schema.rs`, reverted) | 101: `a_holder_that_outlasts_the_ttl_keeps_its_lease` fails |
| mutation: `acquire_lease` returns at once (reverted) | 101: five lease tests fail, `two_concurrent_starters_…` among them |
| `git cat-file -p <c> \| grep -c gpgsig`, six commits | 1 each |

Not verified: CI. There is still no workflow run on the branch. The probe's behaviour was not
observed in a cluster.

### May W3 merge?

**Yes.** All six findings (#768 … #773) are closed by the sweep and verified above. No new
finding was filed. Eleven issues close with this wave: #729, #746, #747, #755, #756 and
#768 … #773. For W8.4, also note the two new upgrade-relevant items: the `startupProbe`
(#770) and the CIMD redirect rule for admin edits (#768). For W7.1, CONTRACT §27.4 rule 7
should state the `cimd` row's rule as #768 shipped it.
