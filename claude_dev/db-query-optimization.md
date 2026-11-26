# Database work per request — measurement and optimisation

> **Sandbox figures — relative only.** Every number in this document was
> measured in a 4-vCPU development container, with SurrealDB built from
> crates.io and run on two pinned cores beside the load generator. They compare
> query shapes and server versions *with each other, on one machine*. They are
> **not benchmark results**, must not be quoted as AXIAM's throughput or
> latency, and do not replace a run on the benchmark VM (§9 lists the cells to
> re-run there).

Branch: `claude/db-query-optimization`. Harness: `tools/db-query-bench/`.
Context: `benchmarks/PUBLIC_BENCH_ANALYSIS.md` §4 (run 6c) and §5.

## 0. Summary

On every data-touching benchmark cell SurrealDB is at its CPU cap while the
AXIAM server is not, so what matters is the database CPU each request costs.
Measured statement by statement against SurrealDB 4.0.1 and 3.3.5:

1. **The request-audit worker cannot keep up, and it sheds rows.** With the
   real worker and the real repository against an otherwise idle 4.0.1
   server, one row per round trip tops out at **~415 rows/s**: at 1,000, 2,000
   and 4,000 requests/s it dropped **40%, 69% and 84%** of the audit rows
   (counted as lost; written to the dead-letter file only where one is
   configured). On 3.3.5 it tops out at ~1,150 rows/s. The benchmark's
   REST cells ran at 1,000–4,400 req/s, so the inference in the analysis (§5.1)
   holds — and the REST cells' database cost was *understated* by the rows
   never written. **Batched appends** (one `INSERT` of up to 64 rows) cut the
   database CPU per audit row by **92% on 4.0.1** (1,873 → 159 µs at 32 rows)
   and **70% on 3.3.5**, and the same worker then dropped **nothing** up to
   4,000 rows/s on either version. *Implemented.*
2. **A record fetch with `WHERE tenant_id = $tenant_id` costs 2.7× the bare
   fetch on 4.0.1** (≈ 830 vs ≈ 305 µs; on 3.3.5 ≈ 440 vs ≈ 410 µs). A bound
   parameter referenced in a predicate appears to defeat 4.0's plan reuse
   (§4.3). Checking the tenant in the repository instead is behaviour-identical
   and took the session check from 863 to 337 µs and the user read from 850 to
   379 µs on 4.0.1 (measured after the change). *Implemented for the two reads
   on every authenticated request.*
3. **One round trip per authorization check instead of three** cuts the
   database CPU of an uncached check by **32–35% on 4.0.1** (5,525 → 3,598 /
   3,748 µs in two runs; −40% on surrealkv) and 12–14% on 3.3.5. *Implemented, behind a repository method the engine uses when
   offered.*
4. **Merging the remaining round trips** (REST userinfo: session + user;
   introspection: client + tenant + user; client credentials: client + tenant).
   *Implemented after review (§8.1–8.3):* userinfo REST reads −36%,
   introspection −26%, client credentials −8% (medians, on top of item 2).
5. **What got more expensive on 4.0.1** is not one thing: a fixed per-request
   cost (2.5× on a trivial `RETURN 1`, over HTTP and WebSocket alike), every
   write statement (session `CREATE` 2.8×, audit `CREATE` 3.2× — #7667), and
   predicates over bound parameters (above). Plans are equivalent on both
   versions; no statement regressed to a table scan. #7716 does not apply:
   none of AXIAM's 88 tables defines an event.

## 1. Method

### 1.1 Servers

`download.surrealdb.com` is refused by this container's egress proxy (HTTP 403),
so the binaries were **built from crates.io**: `surrealdb-server = "=4.0.1"` and
`"=3.3.5"`, each wrapped in a three-line `main` that calls
`surrealdb_server::init(CommunityComposer())` — what the upstream `surreal`
binary does. Both with the same features (`allocator`, `storage-mem`,
`storage-surrealkv`, `http`, `cli`) and the same release profile (`opt-level 3`,
thin LTO, 16 codegen units). Upstream release binaries use fat LTO; absolute
numbers will differ from theirs; the comparison between the two versions is
like for like.

Each server ran as `surreal start --user root --pass root --bind 127.0.0.1:<port>
--log warn memory`, pinned with `taskset` to cores 0–1; the harness ran on cores
2–3. The memory engine was used for the main matrix; surrealkv — the benchmark
VM's engine — for a subset (Appendix B).

### 1.2 Schema and data

`axiam_db::run_migrations` — the production migrations — on a fresh namespace
and database (`DEFINE NAMESPACE` / `DEFINE DATABASE` first, as 4.0 requires).
Seeded through the real repositories at roughly the shape a long benchmark run
leaves behind:

| table | rows | notes |
|---|---:|---|
| `user` | 2,000 | over 3 tenants (Argon2id hashes, as production writes them) |
| `session` | 50,064 | the bench user's 64 + sessions of every user |
| `audit_log` | 300,000 | over 3 tenants |
| `resource` | 2,000 | 40 roots, each root → mid → 48 leaves |
| `has_role` | 1,340 | 2 per user; the subject: 2 global, 1 on the leaf, 1 on its parent, 1 unrelated, 1 through a group |
| `grants` | 501 | 5 per role, one deny |
| `oauth2_client` | 200 | |

### 1.3 Measurement

Every scenario calls **the repository methods AXIAM calls**, over the **HTTP
engine** AXIAM uses (`surrealdb::engine::remote::http`), so the SurrealQL is the
product's own. The rewrites under test are raw SurrealQL in the harness, except
where they became repository methods (§7).

- **Server CPU per operation**: on-CPU nanoseconds of every server thread
  (`/proc/<pid>/task/*/schedstat`, field 1), sampled before and after N
  operations, minus the server's idle rate. The idle rate is measured only
  after the connection has settled: the root sign-in's password hash otherwise
  lands in the window and reads as ~100 ms/s that never recurs (the first pass
  of this study made exactly that mistake; all figures here are from the
  corrected second pass).
- **Concurrency 16, 4,000 operations** for CPU per operation (the server busy,
  as in a benchmark); **concurrency 1, 1,000 operations** for latency (p50).
  A warm-up of 5% precedes each run.
- Batched scenarios report CPU **per row**.

Single runs, no repetitions. Cells repeated within one run varied by up to
±8%, and unchanged cells measured in runs taken at different times (the
database grows between them) by up to ±12%: differences smaller than that are
noise.

## 2. Per-statement cost (memory engine, HTTP engine, c=16)

Server CPU µs per call, 4.0.1 against 3.3.5, in the v1.3.1 forms (before this
branch). "×" is 4.0.1 ÷ 3.3.5.

| statement (repository method) | 4.0.1 | 3.3.5 | × | p50 µs (c=1) 4.0.1 / 3.3.5 |
|---|---:|---:|---:|---|
| `RETURN 1` (fixed cost of a request) | 403 | 163 | **2.47** | 796 / 351 |
| `SessionRepository::get_by_id` (revocation check) | 863 | 422 | **2.05** | 1,199 / 657 |
| `UserRepository::get_by_id` | 850 | 465 | **1.83** | 1,369 / 682 |
| `TenantRepository::get_by_id` (liveness) | 324 | 362 | 0.90 | 717 / 610 |
| `OAuth2ClientRepository::get_by_client_id` | 1,017 | 619 | **1.64** | 1,331 / 994 |
| `RoleRepository::get_user_role_assignments` | 1,337 | 1,387 | 0.96 | 1,836 / 2,027 |
| `ResourceRepository::get_ancestors` | 1,525 | 609 | **2.50** | 1,935 / 1,065 |
| `PermissionRepository::get_role_permission_grants_for_roles` (7 roles) | 2,486 | 1,417 | **1.75** | 2,929 / 1,794 |
| `SessionRepository::create` | 1,904 | 685 | **2.78** | 2,289 / 949 |
| `SessionRepository::consume_by_token_hash` | 2,730 | 1,862 | **1.47** | 3,520 / 2,175 |
| `AuditLogRepository::append` (one row) | 1,873 | 577 | **3.24** | 2,300 / 887 |

### 2.1 Plans (`EXPLAIN`, both versions)

| statement | 4.0.1 | 3.3.5 |
|---|---|---|
| session / user / tenant by id | `Values(type::record) → Filter → SelectProject` | `RecordIdScan → Filter → SelectProject` |
| client by `client_id` | `IndexScan idx_oauth2_tenant_client_id` | same index |
| session by token hash | `IndexScan idx_session_token` | same |
| `has_role` (direct / via group) | `UnionIndexScan idx_has_role_unique` | same |
| `member_of` | `UnionIndexScan idx_member_of_unique` | same |
| ancestors | `Values(recursive graph walk)` | `DynamicScan` |
| grants for roles | `UnionIndexScan idx_grants_unique` (one branch per role) | same |
| audit listing | `IndexScan idx_audit_tenant_time`, backward, limit pushed down | same |

Every statement is index- or record-id-served on both versions. **The 4.0.1
regression is not a plan regression**; the existing guard
(`crates/axiam-db/tests/authz_query_plan_test.rs`) stays green and now also
pins the one-round-trip authorization read (§7.2).

## 3. Per-endpoint cost, current and merged (memory engine)

Database CPU µs per request at c=16; the request's database work only (no
token minting, no HTTP handling). "merged" = the same statements in one
request.

| endpoint | 4.0.1 current | 4.0.1 merged | saved | 3.3.5 current | 3.3.5 merged | saved |
|---|---:|---:|---:|---:|---:|---:|
| REST userinfo (session, user) | 1,750 | 1,011 | **42%** | 815 | 612 | 25% |
| gRPC userinfo (user) | 831 | — | — | 448 | — | — |
| introspection (client, tenant, user) | 2,310 | 1,208 | **48%** | 1,595 | 953 | 40% |
| client credentials (client, tenant) | 1,376 | 1,170 | 15% | 1,019 | 834 | 18% |
| authz gRPC (assignments, ancestors, grants) | 5,525 | 3,330 | **40%** | 3,712 | 3,173 | 15% |
| authz gRPC — as implemented (§7.2) | 5,525 | 3,598 | **35%** | 3,712 | 3,177 | 14% |
| authz gRPC — two round trips (assignments + ancestors, then grants) | 5,525 | 4,534 | 18% | 3,712 | 3,531 | 5% |
| authz REST (session + the above) | 6,266 | — | — | 4,190 | — | — |
| session refresh (consume, user, create) | 5,437 | 5,178 | 5% | 3,065 | 2,746 | 10% |

Plus, on every REST request, one audit row: 1,873 µs on 4.0.1 (577 on 3.3.5)
at one row per round trip — **more than the whole of a REST userinfo's own
reads** — and ≈ 159 µs batched (§5).

Merging pays most where a request is several cheap reads (userinfo,
introspection): there the fixed per-request cost dominates. It pays least on
refresh, whose cost is its two writes.

## 4. What got more expensive on 4.0.1

### 4.1 Fixed cost of a request

A trivial `RETURN 1` costs **403 vs 163 µs** over HTTP and **164 vs 65 µs** over
WebSocket (2.5× on both transports). The HTTP engine adds ~240 µs per request
on 4.0.1 and ~100 µs on 3.3.5 over WebSocket (§6). Every round trip AXIAM makes
pays this, which is why merging round trips (§3) helps more on 4.0.1.

### 4.2 Writes (#7667)

`session` `CREATE` 2.78×, `audit_log` `CREATE` 3.24×. The cost is **per write
statement, not per request**: eight `CREATE` statements in one request cost
1,336 µs per row on 4.0.1 against 264 on 3.3.5 (5.1×) — no better than eight
requests — while one `INSERT` of eight rows costs 312 µs per row, and one of 32
rows 159 µs, *less* than 3.3.5's 175. Whatever #7667 costs, it is charged per
statement (per transaction), and a multi-row `INSERT` amortises it.

### 4.3 Predicates over bound parameters

Through the SDK (the path AXIAM uses), on 4.0.1:

| `SELECT * FROM type::record('user', $id) …` | 4.0.1 | 3.3.5 |
|---|---:|---:|
| no `WHERE` | 308 | 414 |
| `WHERE tenant_id = $tenant_id` (today's form) | 859 | 466 |
| `WHERE deleted_at = $none` (another field, another parameter) | 867 | 453 |
| `WHERE tenant_id = '<literal>'`, same text every time | 328 | 435 |
| `WHERE tenant_id = '<literal>'`, text different every time | 841 | 369 |
| `RETURN 1` with four bound but unused parameters | 430 | 144 |

Unused parameters cost nothing and a parameter in the `FROM` costs nothing; a
predicate costs ~530 µs, except — through the SDK — when it holds no parameter
and the identical query text was sent before. The most economical reading is
that 4.0.1 reuses work for a repeated, parameter-free query text and redoes it
on every execution otherwise — the same family as #7716 (event bodies
re-planned on every write), outside events. It is a reading, not a finding:
through the `/sql` endpoint a repeated literal predicate still costs the extra
~430 µs (§4.4), so the mechanism is upstream's to establish. What is measured,
and what AXIAM can act on, is the first two rows of the table. AXIAM binds every value (as
it must — inlining values would trade this for injection risk) and puts a
`WHERE tenant_id = $tenant_id` on almost every read, so it pays this almost
everywhere.

The repository can check the tenant on the fetched row instead (§7.3). For
reads keyed by an index (`oauth2_client` by `client_id`) the predicate *is*
the lookup and cannot move; those keep the cost until upstream fixes it.

### 4.4 Minimal reproduction (for upstream, not posted)

`tools/db-query-bench/upstream_repro.py` — standard library only, no AXIAM —
creates a schemafull table and times, per request: `RETURN 1`, a record fetch,
one `CREATE`, eight `CREATE`s in one request, `INSERT`s of 8 and 64 rows, and
reports that `time::now()` is fixed per statement on 4.0. It uses a bearer
token: `/sql` with Basic auth re-verifies the root password on every request,
which costs ~25 ms of server CPU and swamps everything else. Results in
Appendix A.

The predicate cost (§4.3) reproduces through `/sql` as well, with literal
values and a keep-alive connection: a record fetch costs ≈ 510 µs of server CPU
on 4.0.1 without a `WHERE` and ≈ 940 µs with one (3.3.5: ≈ 440 and ≈ 510),
whether the record is named literally or through `type::record`. The harness's
`shape.*` scenarios reproduce it through the SDK.

## 5. Audit writes

### 5.1 Does the worker shed rows? (Phase 1, task e)

The real `AuditMiddleware` and its worker, the real `SurrealAuditLogRepository`
over HTTP, an Actix test service offering one request every 1/rate seconds for
20 s, against the seeded server and nothing else running:

| server | worker | 1,000 req/s | 2,000 req/s | 4,000 req/s | worker ceiling |
|---|---|---|---|---|---:|
| 4.0.1 | v1.3.1 (one row per round trip) | **7,962 of 20,000 dropped (40%)** | 27,512 of 40,000 (69%) | 67,445 of 80,000 (84%) | ~415 rows/s |
| 4.0.1 | batched (this branch) | 0 | 0 | 0 | — |
| 3.3.5 | v1.3.1 | 0 | 13,213 of 40,000 (33%) | 53,196 of 80,000 (66%) | ~1,150 rows/s |
| 3.3.5 | batched | 0 | 0 | 0 | — |

The ceiling is latency, not CPU: one worker waits ~2.3 ms per row on 4.0.1
(887 µs on 3.3.5), so it can never exceed 1/latency however idle the database
is, and in a benchmark the database is not idle. Rows that miss the channel are
counted (`RequestAuditLoss`, `/health/jobs`) and written to the dead-letter file
when one is configured; without one they are lost.

### 5.2 Batch size

| rows per statement | 4.0.1 µs/row | 3.3.5 µs/row |
|---:|---:|---:|
| 1 (`append`, today) | 1,873 | 577 |
| 8 | 312 | 199 |
| 32 | 159 | 175 |
| 128 | 114 | 174 |

The worker writes **whatever is already queued, up to 64 rows**, and never
waits to fill a batch: a quiet server still writes each row alone and at once
(no added latency, nothing held in memory longer), and only a backlog — the
case where one row per round trip falls behind — is batched. 64 sits past the
knee on both versions; a larger batch saves little more and makes the
row-by-row retry of a refused batch longer.

### 5.3 What batching must not change, and how it is held

- **Order.** Rows are inserted in the order the requests finished. 4.0
  evaluates `time::now()` **once per statement**, so all rows of one batch share
  a `timestamp` (3.3.5 stamps each row). The listing therefore orders by
  `timestamp DESC, id DESC`: ids are UUIDv7, minted in append order by the
  single worker, so the tie-break restores the exact write order and keeps
  paging deterministic (rows tied on `timestamp` could otherwise repeat or
  vanish across a page boundary). The index still serves the scan backwards
  with the limit pushed down — no sort (pinned by `audit_repository_test`).
- **Failure semantics.** A multi-row `INSERT` is one transaction on both
  versions: a batch containing one row the schema refuses writes **nothing**
  (verified on 3.3.5 and 4.0.1 by the harness's `probe`). The repository then
  writes that batch row by row, under the same ids, so the refused row alone
  fails and every other row is written once; the worker counts and dead-letters
  exactly the rows that failed, as before.
- **`drain`.** The shutdown barrier ends a batch and is acknowledged only after
  every row queued before it has been through the append.

## 6. HTTP engine versus WebSocket (Phase 1, task d)

The same statements over `engine::remote::ws`:

| | HTTP 4.0.1 | WS 4.0.1 | HTTP 3.3.5 | WS 3.3.5 |
|---|---:|---:|---:|---:|
| `RETURN 1` | 403 | 164 | 163 | 65 |
| user read | 850 | 560 | 465 | 220 |
| REST userinfo (2 reads) | 1,750 | 1,129 | 815 | 481 |
| introspection (3 reads) | 2,310 | 1,559 | 1,595 | 1,084 |
| authz gRPC (3 round trips) | 5,525 | 4,594 | 3,712 | 3,096 |
| audit append (1 row) | 1,873 | 1,685 | 577 | 453 |

The HTTP engine costs the server **~240–290 µs per round trip** on 4.0.1 —
each request is authenticated with the root token and parsed afresh — and
~100–250 µs on 3.3.5. The WebSocket engine would save that on every round
trip, but AXIAM left it deliberately: SDK issue #5750 (a WebSocket reconnect
drops `use_ns`/`use_db`, so a server that idled answers "not found" for records
that exist) was a correctness failure in production. Merging round trips (§3,
§7.2) captures much of the same saving without reopening that. Switching
engines is listed as an option (§8), not done.

The surrealkv engine (the VM's) was measured for a subset and agrees: see
Appendix B.

## 7. What this branch changes

Each change is its own commit, keeps every answer identical, and is covered by
tests. None of them enables a cache or relaxes a check.

### 7.1 Batched audit writes

- `AuditLogRepository::append_many` (axiam-core): one result per row, in order.
  The default appends one row at a time, so every wrapper and test double keeps
  today's behaviour.
- `SurrealAuditLogRepository::append_many`: one `INSERT … RETURN NONE`; on a
  refused batch, row by row under the same ids. Minimisation (T-110) is applied
  once, before either path.
- The worker (`axiam-audit/src/middleware.rs`) drains what is queued, up to
  `MAX_APPEND_BATCH = 64`, never waiting to fill a batch.
- The audit listing orders by `timestamp DESC, id DESC` (§5.3).

Tests: `axiam-audit/tests/audit_batching_test.rs` (300 rows in 5–6 round trips
in request order; a lone row written alone; a refused row dead-lettered alone;
`drain` waits); `axiam-db/tests/audit_repository_test.rs` (every row written in
order with the single-row fields; a refused row isolated and every other row
written once; the listing order index-served).

Measured: 92% less database CPU per audit row on 4.0.1, 70% on 3.3.5; zero
rows shed up to 4,000 req/s where v1.3.1 shed 40–84% on 4.0.1.

### 7.2 One round trip per authorization check

- `RoleRepository::authorization_inputs` (axiam-core), default `None`: the
  assignments, the resource's ancestors and the grants of **every assigned
  role**, in one request. Each part keeps its own outcome (`AuthorizationInputs`),
  so the engine raises an error exactly where the three-read path would, and
  not when that path would have stopped earlier.
- `SurrealRoleRepository` implements it with the three repositories' own
  statements (now shared: `ancestors_sql`, `GRANTS_FOR_ROLES_SQL`,
  `ASSIGNMENT_COLUMNS`), so they cannot drift — and
  `authorization_inputs_test` compares the two paths' answers in case they do.
- The engine uses it when offered and keeps the applicable roles' grants
  only — the same set it asks for on the three-read path — so the decision
  cannot differ. Which roles apply (tenant scope, `inherit`, resource lineage,
  organization boundary) stays decided in Rust, once. The cost of the superset
  is grants of a few roles that do not apply; on the benchmark shape it is
  within the measured 32–35%.
- Scoped checks keep their separate scope read (4 → 2 round trips); the
  coalesced batch path is unchanged.

Tests: `axiam-authz/tests/batch_coalescing_test.rs` (an uncached check is one
round trip and none of the three reads; without the method, three; both paths
decide alike, and an unrelated role's grant never applies);
`axiam-db/tests/authorization_inputs_test.rs` (the read equals the three reads
on a hierarchy, across tenants, for an unknown subject, on an over-deep
hierarchy, and with an unreadable grant on one role);
`authz_query_plan_test::one_round_trip_grant_lookup_is_index_satisfied`. Every
existing authz suite (`authz_engine_test`, `decision_cache_integration_test`,
`organization_scope_test`) runs over the SurrealDB repositories and therefore
over the new path.

Measured: 32–35% less database CPU per uncached check on 4.0.1 (two runs),
12–14% on 3.3.5; p50 latency 6.9 → 4.5 ms (4.0.1, c=1).

### 7.3 The tenant check of the two hottest reads, in the repository

`SessionRepository::get_by_id` (behind `is_session_active_checked`, on every
authenticated REST request) and `UserRepository::get_by_id` (userinfo,
introspection, refresh, gRPC userinfo) fetch the record and compare its
`tenant_id` with the caller's in Rust — the same exact string comparison the
`WHERE` made — instead of filtering in SurrealQL. Another tenant's row is the
same `NotFound`. Test: `axiam-db/tests/tenant_scoped_record_reads_test.rs`.

Measured after the change, same seed: session read **863 → 337 µs**, user
read **850 → 379 µs** on 4.0.1 (−61%, −55%); 422 → 392 and 465 → 427 µs on
3.3.5 (−7%, −8%).

### 7.4 Effect per benchmark cell (4.0.1, database CPU per request)

Measured with the harness before and after the three changes, on the same
seeded server, at c=16; the audit row is the per-row cost of one append
before and of a 32-row batch after. "after" for authz uses the repository's
`authorization_inputs`, i.e. what the engine now issues.

| cell | before | after (measured) | change |
|---|---:|---:|---:|
| userinfo REST — reads | 1,750 | 739 | **−58%** |
| userinfo REST — reads + audit row | 3,623 | ≈ 940 | **≈ −74%** |
| userinfo gRPC | 831 | 446 | **−46%** |
| authz check gRPC | 5,525 | 3,598 / 3,748 (two runs) | −32 to −35% |
| authz check REST — reads | 6,266 | 4,466 | −29% |
| authz check REST — reads + audit row | 8,139 | ≈ 4,670 | ≈ −43% |
| token introspection — reads | 2,310 | 1,924 | −17% |
| client credentials — reads | 1,376 | unchanged code (1,538 on re-run) | — |
| any REST cell — its audit row | 1,873 | ≈ 160–200 | ≈ −90% |
| session refresh — reads and writes | 5,437 | 5,456 | within noise |

Runs taken at different times differ by up to ±12% on unchanged code (the
server's data grows between runs: the shedding tests alone added ~250,000
audit rows); differences inside one run are tighter (±8%). Refresh's user read
got cheaper, but its two writes dominate and the saving is inside that noise.

"before" for the REST cells includes the audit row the v1.3.1 worker *tried*
to write; at benchmark rates it wrote fewer than half of them on 4.0.1 (§5.1),
so the benchmark's measured REST cost understates "before", and the gain
measured on the VM will be smaller than this table — while the audit trail
becomes complete. That is the right trade, and the reason to report the loss
counter alongside every REST cell.

## 8. Options and decisions

Ranked by database CPU saved per request on 4.0.1. Each is a change of
security posture or of an established design decision; the decisions taken so
far are recorded with them.

### 8.1 A — tenant and account read with the client: **approved, implemented**

`OAuth2ClientRepository::get_by_client_id_with_context` reads the client, its
tenant and (for introspection) the token's account in one round trip; the
token service still consults them only after the credential, with the same
answers. A refused request now costs one round trip of three statements
instead of one of one — the SEC-086 "no extra read before proof" ordering,
traded for fewer round trips. Used by client credentials, the refresh grant,
introspection and revocation.

### 8.2 B — userinfo's session check and account read: **implemented, in the secure form**

Not a second authentication path: `/oauth2/userinfo` carries a route marker
(`PrefetchAccount`) that makes the **same** session check, in the same place,
read the principal's account in its round trip
(`SessionValidator::is_session_active_with_account`). The verdict is the same;
the account is handed on only after admission, only for that principal, at
most once; the handler falls back to its own read when there is none. Every
other route makes the plain check and reads nothing more.

### 8.3 Measured effect of A and B (4.0.1, three interleaved runs, medians)

| cell (reads only) | before | after | change | p50 at c=1 |
|---|---:|---:|---:|---|
| userinfo REST | 607 (577–702) | 391 (331–469) | **−36%** | 1,225 → 842 µs |
| token introspection | 1,474 (1,423–2,022) | 1,093 (1,026–1,160) | **−26%** | 2,590 → 1,603 µs |
| client credentials | 1,156 (1,137–1,589) | 1,065 (960–1,147) | −8% (−31% at c=1) | 2,015 → 1,377 µs |

"before" already includes §7.3. The spread between runs is wide on this
machine, which is why these are medians of interleaved rounds rather than one
run.

### 8.4 C — the WebSocket engine: what changed since AXIAM left it

AXIAM moved to the HTTP engine because the WebSocket engine lost its
`use_ns`/`use_db` after a reconnect (SDK #5750) and AXIAM then answered "not
found" for records that existed. In the SDK AXIAM now pins (4.0.1) the
WebSocket engine keeps a **replay log** of `use`, `signin`/`authenticate` and
`set` and re-sends it on every reconnect, before any queued request, and
retries an expired token with its refresh half; it reconnects every second
until it succeeds and pings the server to keep idle connections alive.

Probe (`db-query-bench reconnect-probe`, a namespaced record read every
200 ms for 75 s against surrealkv; the server killed with `-9` at 10 s,
restarted at 18 s, restarted gracefully at 30 s, killed and restarted at 45 s):

| engine | reads found | "not found" | errors | behaviour during the outage |
|---|---:|---:|---:|---|
| WebSocket | 301 | **0** | 2 | requests **wait** for the reconnect (one hit the probe's 5 s timeout); recovered ~1 s after each restart |
| HTTP | 313 | 0 | 56 | every request **fails fast** while the server is down; recovered on the first request after |

So the failure AXIAM left the WebSocket engine for does not reproduce on
4.0.1. What remains to weigh:

- **Waiting instead of failing.** During an outage a WebSocket request does
  not fail; it waits for the reconnect. AXIAM would need a per-query timeout
  so a request cannot hang behind a dead database (the HTTP engine gives that
  failure for free).
- **One socket per handle.** Every query of a pooled handle shares one
  connection; `AXIAM__DB__POOL_SIZE` would then matter more.
- **Evidence.** This is a 75-second probe with four restarts, not the weeks of
  idle, network blips and load-balancer timeouts that produced the original
  failure.

The saving is the fixed per-request cost: ~240–290 µs of database CPU per
round trip on 4.0.1 (§6). Recommended path, if wanted: an opt-in
`AXIAM__DB__ENGINE=ws` with a query timeout, soaked on the benchmark VM for
days (idle, restarts, a TCP-killing proxy) before it is considered as a
default. Not implemented.

### 8.4.1 C — decision: **implemented, opt-in**

`AXIAM__DB__ENGINE=ws` (default `http`). Both engines go through the SDK's
protocol-agnostic engine, so the choice is a start-up setting, not a type.
Because the SDK has no per-query timeout on its remote engines (its
`query_timeout` is honoured only by the gRPC and embedded engines), the bound
is on the request: REST by `AXIAM__DB__WS_REQUEST_DEADLINE_SECS` (default
60 s, above the 30 s SSF long poll; `503` + `Retry-After`), gRPC by the
listener's existing 30 s timeout.

### 8.5 D–F — caches: what "revocation latency" means

**Decision (accepted 5 s):** D and E are on by default since this branch, and
F was built — tenant, OAuth2 client and user record caches, 5 s TTL,
`AXIAM__DB__RECORD_CACHE_TTL_SECS`, used only by read-only hot lookups, with
credential material blanked in cached accounts and invalidation on every write
through the owning repository. The decision-cache broadcast stays opt-in (it
needs RabbitMQ, which the minimal profile has not). The benchmark gained a
`caches=default|strict|on` posture so these defaults do not make the
head-to-head silently incomparable (`benchmarks/README.md`, "Caches and
fairness").


The 262 ms of run 5 is **not** the staleness bound. It was the time for a
revocation made through the API to be visible on the same replica, where the
caches are invalidated in the same call. The bounds are:

| cache | single replica, revoked through the API | change made outside the API (DB edit, restore, purge) | several replicas |
|---|---|---|---|
| D. session validation (`AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`) | immediate | ≤ TTL | **≤ TTL** on the other replicas — no cross-replica invalidation exists for this cache |
| E. decision (`AXIAM__AUTHZ__DECISION_CACHE_ENABLED`, TTL default 5 s, max 300 s) | immediate | ≤ TTL (run 5: 5.2 s at TTL 5 s) | ≤ TTL; with `DECISION_CACHE_BROADCAST_ENABLED` (RabbitMQ) the other replicas are invalidated within milliseconds, the heartbeat bounding a lost broadcast |
| F. tenant / client / user records | does not exist yet | — | — |

With a 5 s TTL, then: milliseconds on one replica, and up to 5 seconds for a
logout, password change or role removal to reach the other replicas (the
decision cache can be brought back to milliseconds with the broadcast; the
session cache cannot, today). F would have to be built, with the same kind of
bound, and invalidation hooks in tenant suspension, client secret rotation and
account locking.

| option | saves (4.0.1) | worst-case staleness |
|---|---|---|
| D. session-validation cache on | the session read on a hit (≈ 340 µs) | TTL on other replicas |
| E. decision cache on (+ broadcast) | all of an authz check's reads on a hit | TTL without broadcast; ms with it |
| F. tenant / client / user caches | 324 / 1,017 / 379 µs per read | TTL (to be built) |
| G. refresh: consume and user read in one round trip | −5% (4.0.1), −10% (3.3.5) | none; small gain |

## 9. Re-run on the benchmark VM

Scenarios, with the loss counter (`RequestAuditLoss` on `/health/jobs`)
captured per cell:

- `oauth2_client_credentials` — audit batching;
- `token_introspection`, `userinfo` (REST) — audit batching and the tenant
  check in the repository (user read; for userinfo also the session check);
- `userinfo_grpc` — tenant check in the repository (no audit row on gRPC);
- `authz_check_rest`, `authz_check_grpc`, `authz_batch_rest`,
  `authz_batch_grpc`, `authz_nested_rest`, `authz_nested_grpc` — one round trip
  per check (the batch cells use the coalesced path, which this branch does not
  change; they move only through the audit row and the session check);
- `token_refresh`, `oauth2_refresh_grant` — audit batching and the user read.

Against 4.0.1 (what a supported deployment runs) and, for comparability with
run 6c, 3.3.5.

## Appendix A. Upstream reproduction

`tools/db-query-bench/upstream_repro.py`, 2,000 sequential requests per shape
over one keep-alive-less `urllib` client (so the absolute fixed cost includes a
TCP connect per request), server on two pinned cores, memory engine:

| shape (one request each) | 4.0.1 µs CPU / request | 3.3.5 | × |
|---|---:|---:|---:|
| `RETURN 1` | 724 | 445 | 1.6 |
| `SELECT` one record by id, with a `WHERE` | 1,019 | 573 | 1.8 |
| `CREATE` one row (schemafull, one index) | 1,825 | 718 | 2.5 |
| 8 `CREATE` statements in one request — per row | 1,384 | 227 | **6.1** |
| `INSERT` of 8 rows — per row | 272 | 187 | 1.5 |
| `INSERT` of 64 rows — per row | 92 | 140 | 0.66 |
| `time::now()` twice in one statement | same instant | distinct instants | — |

The fourth row is the one to put next to #7667: within **one** request, each
additional write statement costs 4.0.1 about six times what it costs 3.3.5,
while the same rows in one `INSERT` cost less on 4.0.1 than on 3.3.5. The cost
is charged per write statement (per transaction), not per request and not per
row. The last row is a behaviour change worth knowing about, not a defect:
anything that relied on rows of one statement being stamped apart will see ties
on 4.x.

## Appendix B. surrealkv

`surreal start … surrealkv:<dir>` — the benchmark VM's engine — on local disk,
seeded with half the sessions (25,064) and audit rows (150,000), 2,000
operations per cell at c=16, HTTP engine. The harness at this point already
ran the branch's repositories, so the session and user reads below are the
**after** forms (tenant checked in the repository); the authz rows compare the
three-read path with `authorization_inputs` directly.

| cell | 4.0.1 µs | 3.3.5 µs | × |
|---|---:|---:|---:|
| `RETURN 1` | 404 | 260 | 1.55 |
| session read (after) | 331 | 477 | 0.69 |
| user read (after) | 338 | 572 | 0.59 |
| session `CREATE` | 2,042 | 821 | 2.49 |
| userinfo REST — reads (after) | 716 | 1,018 | 0.70 |
| introspection — reads (after) | 1,793 | 2,006 | 0.89 |
| client credentials — reads | 1,419 | 1,395 | 1.02 |
| authz gRPC, three reads | 5,703 | 4,803 | 1.19 |
| authz gRPC, `authorization_inputs` | **3,445** (−40%) | 4,719 (−2%) | 0.73 |
| authz REST (after: session + one round trip) | 3,877 | 5,360 | 0.72 |
| session refresh | 5,204 | 4,228 | 1.23 |
| audit, one row per append | 2,165 | 772 | 2.80 |
| audit, 32 rows per `INSERT` — per row | **166** (−92%) | 204 (−74%) | 0.81 |

The shape is the memory engine's: the write regression (#7667) is as large on
surrealkv, and with this branch's three changes the read-heavy cells cost
*less* on 4.0.1 than the same code on 3.3.5 — the remaining 4.0.1 penalty sits
in write statements and in the fixed cost of a request.

## Appendix C. Reproducing these numbers

```bash
# servers (download.surrealdb.com is blocked here; build from crates.io)
#   see §1.1 for the three-line wrapper crate
cargo build --release   # in a crate depending on surrealdb-server = "=4.0.1"
taskset -c 0,1 ./surreal start --user root --pass root --bind 127.0.0.1:8001 --log warn memory &

# harness
cd tools/db-query-bench
cargo build --release
FIXTURE=fx.json SURREAL_ADDR=127.0.0.1:8001 taskset -c 2,3 ./target/release/db-query-bench seed
FIXTURE=fx.json SURREAL_ADDR=127.0.0.1:8001 SURREAL_PID=<pid> ENGINES=http,ws \
  taskset -c 2,3 ./target/release/db-query-bench bench            # all scenarios, TSV
./target/release/db-query-bench explain                           # plans
./target/release/db-query-bench probe                             # batch semantics
./target/release/db-query-bench audit-shed 1000 20                # the real worker
```
