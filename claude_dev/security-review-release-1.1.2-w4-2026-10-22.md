# Security review — release 1.1.2, wave W4 (F4)

**Date:** 2026-10-22.
**Against:** `claude/release-1.1.2-w4`, the whole wave diff `dc5bfd4..2c7d77c` (5 commits,
16 files, 1 230 lines added and 332 removed): `c3cc5fb` (W4.1, #726, D-6), `8394b35` (W4.2,
#727), `c26591f` (W4.3, #728), `3ad1120` and `2c7d77c` (W4.4, #730, D-14). Every commit
carries one `gpgsig` header (SSH signing; the sandbox has no `allowedSignersFile`, so `%G?`
cannot verify).
**Scope:** plan §5: `crates/axiam-api-rest/src/network_gate.rs` (`write_and_record`,
`cleared_row`), its callers in `handlers/roles.rs`, `permissions.rs` and `certificates.rs`,
`crates/axiam-authz/src/network_gate.rs` (what `GateClearance` carries),
`crates/axiam-db/src/seeder.rs` and `repository/network.rs`, `crates/axiam-server/src/main.rs`,
`docs/admin/README.md`, and T-457, T-483 and T-484 in both copies.
**Method:** that of the 1.1.1 W4 review, with its severity scale. Every commit message was read
in full and each claim checked against the tree (§9). H1 … H6 of the design note's §5.2 and the
§5.3 rows were read once more against `axiam-authz`'s `network_gate.rs` (§3). The stop path
W4.1 depends on was read in `actix-server` 2.9.8 and `actix-rt` 2.15.0 (the versions in
`Cargo.lock`). Three claims were settled by scratch tests appended to the tree, run, and
reverted (`git status` clean after; §8): the index-name collision of R112W4-04, the
organization-level half of R112W4-03, and the datastore removing a binding with its service
account (R112W4-05). The **full** test binaries of `axiam-server` (28, `--no-default-features`),
`axiam-db` (86) and `axiam-authz` (6) were run, and the ten `axiam-api-rest` binaries the wave
touches with SAML on (§8). This review fixes nothing. IDs: `R112W4-nn`.

---

## 0. Summary

**No Critical, High or Medium finding.** The wave does what its rows say. A cleared write's row
is now built from the gate's reads before the write, the write and the append run as one task
that a dropped handler does not cancel, and the two #726 tests show both properties (the drop
test was confirmed by its author to fail with the task inlined). The grants the row carries are
the grants at commit, because the epochs are read first and the claimed write compares them
(§2.2). `network_role.deleted` is written exactly when the gate marks a delete
network-sensitive. The reconcile no longer strips the network half from a tenant it cannot
read, and it cannot fail or panic the boot where 1.1.1's did not (§4). The full binaries of
every touched crate pass, `axiam-server`'s included, which W4.4's executor did not run.

One **Low** finding is in the boundary W4.1 drew. W4.1 made the write independent of the
client, but the decision-cache flush that follows a revocation is still in the handler's
future. A client that goes away after the spawn now leaves a revocation committed and its
cache entries in place on every replica, until the TTL. Four **Informational** findings
follow. An orderly stop does not wait for the spawned task (§2.4). W4.3 fixed only one of
the reconcile's two halves: an unresolved tenant still loses its organization-level actions
(§4.2). D-14 fixed the `THROW` markers but left the index names matched as substrings, and a
segment named after an index changes the refusal's class (§5). Text: `before` and the T-484
test claim (§6).

| ID | Finding | Severity | Surface / threat | Origin | Issue | Model for the fix |
|---|---|---|---|---|---|---|
| R112W4-01 | The D7 cache flush after a cleared role or grant write (`invalidate_subject` / `invalidate_tenant`, local and broadcast) and the stale-claim refusal row (`refused_after_clearance`) still run in the handler's future, after `write_and_record` returns. A client that goes away after the task is spawned now always leaves the write committed with its flush skipped. For an unassignment, a revoke or a role delete, that leaves a stale allow on every replica for up to `decision_cache_ttl_secs` (≤ 300 s) when the cache is on. | Low | `roles.rs:405-421, 664-684, 731-757, 858-884, 931-957, 1132-1151, 1199-1219`; `permissions.rs:313-345, 524-544`; `network_gate.rs:146-262`; T-484, D7 | wave (W4.1 widened a pre-existing window) | [#775](https://github.com/ilpanich/axiam/issues/775) | **Opus 5.5** |
| R112W4-02 | An orderly stop does not wait for a `write_and_record` task whose client has gone. `actix-server` waits for connections only, then stops the worker's arbiter, which drops the task between the commit and the append. T-484's W4.1 amendment calls this "a process stop, not a writer's choice", but it is the SIGTERM path, which T-444 says keeps a write and its row together. | Informational | `network_gate.rs:302-350`; `actix-server` `worker.rs:668-700`; T-484, T-444 | wave (W4.1) | [#776](https://github.com/ilpanich/axiam/issues/776) | **Opus 5.5** |
| R112W4-03 | W4.3 skips only the network half for an unresolved tenant. The organization-level half still treats `None` as "not the organization scope" and **revokes**. If the organization scope's own tenant read fails at boot, its super-admin loses every organization-level action until the next boot, and `main.rs` logs a reason that is false for that tenant. W4.3's `warn` and T-483's amendment both say these actions are "withheld" when the code revokes them. Probe: `revoked: 1`, and the grant is gone. | Informational | `seeder.rs:866-884, 962-984`; `main.rs:650-658`; T-483 | pre-existing (B-04), left by W4.3 and misdescribed by it | [#777](https://github.com/ilpanich/axiam/issues/777) | Sonnet 5.5 |
| R112W4-04 | `refusal_of` still reads the three uniqueness indexes with `contains`, and the index-clash text echoes the clashing values. `idx_network_segment_site_vlan` is a valid segment name or site key (`[A-Za-z0-9._-]`). Probe: a repeated segment *name* `idx_network_segment_site_vlan` comes back `DuplicateVlan`, and a name clash at a site keyed `idx_network_segment_site_rank` comes back `DuplicateRank` (`409 duplicate_vlan` / `duplicate_rank` for `duplicate_name`). | Informational | `repository/network.rs:122-160` | wave (W4.4 (d) fixed the markers, not the indexes) | [#778](https://github.com/ilpanich/axiam/issues/778) | Sonnet 5.5 |
| R112W4-05 | Text after W4. (a) `certificate_binding.bound`'s `before` is documented as "the account the certificate was taken from on a re-bind", but the route refuses a bound certificate (`409`), so on a success row it is `null`. The one exception is a service account deleted between the gate's read and the bind (the datastore drops its binding; probe), and then `before` names an account the certificate was **not** taken from. (b) T-484's W4.4 amendment, in both copies, cites a re-bind assertion that `2c7d77c` replaced with the `409`. (c) `write_and_record`'s doc still lists five actions and says "one of the five", omitting `network_role.deleted`, and wraps a 150-column line. | Informational | `network_gate.rs:266-291, 489-495`; `docs/admin/README.md` (the `certificate_binding.bound` row); T-484 (both copies) | wave (W4.1, W4.2, W4.4) | [#779](https://github.com/ilpanich/axiam/issues/779) | Sonnet 5.5 |

---

## 1. What was reviewed, and how

| Point of the brief | Where answered |
|---|---|
| W4.1's spawned task: shutdown, the stop's budget, a late row | §2.4; R112W4-02 |
| A panic in the task | §2.3 |
| The clearance's grant snapshot is the committed one (the epoch argument) | §2.2 |
| A write the gate did not clear; a refusal row that is lost | §2.1, §2.5; R112W4-01 |
| W4.3's skip and W4.4 (b)'s counters: the boot never fails or panics where 1.1.1's did not | §4.1; the `axiam-server` binaries (§8) |
| What the skip leaves | §4.2; R112W4-03 |
| W4.4 (d): `refusal_of` and the duplicate-name test | §5; R112W4-04 |
| W4.4 (f)/(g): `before` and `node` | §6; R112W4-05 |
| `network_role.deleted` and the W2.8 grammar; AMQP forgery (#741) | §7 |
| T-457, T-483, T-484 copies | §7 |
| H1 … H6 against the code once more | §3 |
| Test binaries, with names | §8 |

---

## 2. W4.1: the row and the write as one task (#726)

### 2.1 No write runs that the gate did not clear

`write_and_record` (`network_gate.rs:302-350`) takes the write as an unpolled future and the
`&GateClearance` as a borrow. Each of its ten callers obtains the clearance from
`network_gate::authorize` immediately before, and returns early on `Err`: the six role
assignment handlers, `roles::delete`, `permissions::grant_to_role` / `revoke_from_role` and
`certificates::bind`. Before W4.1 the same writes ran inline after the same `authorize`. The
enumeration test (`network_gate_enumeration_test`, 5/5) still sees every guarded repository
call behind the gate, `role_repo` in `roles::delete` included. The claim the write compares
(`cleared.role_claim()`) is copied out before the move, as before. `cleared_row` runs before
the spawn and touches no store. When it cannot describe the write it logs only after a
successful write (`repository_write.await?` returns first), so a refused write logs nothing
spurious. No path writes without a clearance, and none writes twice.

### 2.2 The grants on the row are the grants at commit

`authorize_network_write` reads `role_epochs` **before** `decide` for every role write it
claims (`network_gate.rs:954-970`), and `decide` then reads the role and `role_grants`. A grant
or revoke that lands between the epoch read and the grants read changes the epoch the claim
holds. So does one that lands after the grants read. Either way the `*_claimed` write's
transaction refuses with `StaleRole`, and no success row is appended (the task's `?`). So for
an assignment, unassignment, grant, revoke or delete, `ClearedRole::network_grants` is the
role's `network:` grant set at the commit, as the W4.1 body says. Two members are not
covered by the epochs. The role's **name** (a rename is a `RoleUpdate` with `is_global: None`,
which claims nothing) can be one rename behind on the row. The docs say so ("a role renamed …
is still named as it was cleared"), and the role id is on the row. The binding's `nodes` are
not covered either, because `certificate_bind` claims nothing. That is §5.3's existing
residual for the bind (T-481's class); the row records what was checked, which is what it
says.

`permission_revoke` now reads the role through `found()` (`network_gate.rs:2172`), for
the row only. A role that is not the tenant's is `None` and decided as before. A datastore
error on that read now fails the revoke with `500` where 1.1.1 did not read at all, which
fails closed.

### 2.3 Panics and cancellation

`task.await` returns `JoinError`. A panic is resumed with `std::panic::resume_unwind`
(`:344`), so the handler panics as an inline write would have. Actix-web does not catch
handler panics, so this is 1.1.1's behaviour, not a new one. A cancellation (the runtime
dropped the task) becomes `AxiamError::Internal`, `500`. It can be observed only by a handler
that is still being polled while its own worker's runtime drops tasks, which is the stop of
§2.4. The message formats the `JoinError`, which carries a task id and no value of the write.

### 2.4 The stop (R112W4-02)

`actix_web::rt::spawn` is `tokio::task::spawn_local` on the worker's arbiter. An orderly stop
(SIGTERM, or the lease or `FatalStop` path of T-444) puts each worker in
`WorkerState::Shutdown`. The worker then polls **only its connection counter**
(`actix-server-2.9.8/src/worker.rs:668-700`). When it reaches zero, or `shutdown_timeout` (20 s)
expires, the worker future completes and `Arbiter::current().stop()` ends the arbiter's
`block_on`, which drops the `LocalSet` and every task on it.

So:

- **A row landing after the stop's budget:** impossible. The task dies with its worker, before
  `serve` returns and before the audit drain. The row goes straight to `audit_repo`, not
  through the middleware queue, so the drain does not cover it in either direction.
- **A write without its row on an orderly stop:** possible. The handler's connection still
  counts while its client is connected, because the handler awaits the `JoinHandle`. Once the
  client has gone, which is exactly the case W4.1 exists for, the connection no longer counts.
  A worker with no other connection then stops at its next shutdown check (`SHUTDOWN_POLL_INTERVAL`, 1 s) and drops the task. If
  the write had committed, the row is lost. If the write was in flight, whether it commits is
  up to the datastore. T-484's amendment names "a worker whose runtime stops between the
  commit and the append" and calls it "a process stop, not a writer's choice". On the SIGTERM
  path it is an orderly stop, and T-444 says an orderly stop has "in-flight requests finished, …
  so an erasure and its row stay together". The window is small: a disconnect and a stop within
  the same few milliseconds. It cannot be chosen by an outsider, so it is rated
  Informational. Under the T-444 promise, though, the spawned task is in-flight work the stop
  does not see.

**Fix (R112W4-02):** count the tasks. Keep a `TaskTracker` (or an `Arc` counter with a
`Notify`) in `AppState`, have `write_and_record` register each task, and have the orderly
stop wait for it, bounded inside the existing budget, after the listener stops and before the
audit drain. Alternatively, correct T-484 to say the orderly stop is included and why that is
accepted. **Test:** in `minimal_profile_boot.rs`'s style, a write wrapper that pends after its
commit, its client dropped and SIGTERM raised. The row exists after `serve` returns. Today it
does not.

### 2.5 What still rides the handler's future (R112W4-01)

After `write_and_record` returns, every caller does one of two things, both still in the
handler's own future:

- **On success, the D7 flush.** `invalidate_subject(tenant, subject)` follows an assignment
  or unassignment to a user or service account. `invalidate_tenant(tenant)` follows group
  assignments, `roles::delete`, `grant_to_role` and `revoke_from_role`. The code's own
  comments mark the revocation side as "REVOCATION — security critical … a cached allow must
  not outlive the grant". `AuthorizationEngine::invalidate` drops the local cache **and**
  publishes the broadcast (`engine.rs:404-430`).
- **On a stale claim, the refusal row.** `refused_after_clearance` appends the
  `network_role.*_refused` row (`network_gate.rs:146-262`, append at `:253`).

Actix drops the handler's future when the client goes away; that is #726's premise. Before
W4.1, a disconnect *during* the write future could cancel the write before it reached the
datastore, and then there was nothing to flush. Since W4.1, a disconnect at any point after
the spawn lets the write commit and the flush is never reached. With
`decision_cache_enabled`, an unassigned `network:join` allow, a revoked grant or a deleted
role keeps serving its cached allow. That holds locally and, since the broadcast is skipped
too, on every replica, for up to `decision_cache_ttl_secs` (default 5 s,
`MAX_DECISION_CACHE_TTL_SECS` 300). The module doc of `decision_cache.rs` accepts a ≤ TTL
window only for a **missed** event "(a bug, a mutation path that forgot to call
invalidate …)". This is that bug, on the paths that must not have it. The refusal row's loss
is milder, because the write it records did not land. It is the same boundary, and #726's
own reasoning ("the refusal rows exist", T-484) counts on it.

The writer is the one who goes away, so an outsider cannot choose the window. A load
balancer's idle timeout or a client's own timeout can, though, and the result is a revocation
that reports nothing and does not take effect until the TTL. The cache is off by default,
which keeps this at **Low**.

**Fix (R112W4-01):** give `write_and_record` the post-commit work to run inside the task: an
`after: impl FnOnce(&T) -> Future` (or a second argument the handler builds, owning the
`Arc<dyn AuthzChecker>` and the ids), run between the append and `Ok(written)`. On the error
arm, move the stale-claim refusal row into the task as well, either by passing the refusal
description in or by spawning `refused_after_clearance`'s append the same way. **Test:**
extend `r111w4_02_a_handler_dropped_after_its_write_landed_still_leaves_the_row` (or add a
sibling for an unassignment) with a decision cache attached and a cached allow for the
grantee. Drop the handler after the write lands, release it, and assert the subject's entry
is gone and the broadcast was published (a recording publisher). A second case: a stale claim
whose handler is dropped still leaves its `version:stale` row.

---

## 3. H1 … H6 and §5.3, once more

The wave changes no decision. Every `GateClearance::plain(true)` in `role_assign`,
`role_unassign`, `role_update`, `role_delete`, `permission_grant`, `permission_revoke` and
`certificate_bind` gained `.reading_role` / `.at_node` / `.naming` / `.binding` decorations on
the value it already returned. No `return` was added or moved before a check, and the only
new read is `permission_revoke`'s role read (§2.2). Read against the design note:

- **H1 … H5** (profile and envelope writes) are untouched by the diff; the `profile_write` /
  `segment_write` paths have no new member.
- **§5.3 rows 1–4** (assign, quarantine, release, meta permissions): `role_assign` builds
  `cleared` after rule 2, rule 3 and the H6 check and before the bootstrap test and
  `require_all`. Both returns carry it, and the refusals return before it is used.
  `role_unassign` computes `assignment_node` before the deny branch (formerly inside it). The
  computation is pure, and the deny branch uses the same value.
- **Row 5** (grant/revoke of `network:`): unchanged decision; `naming(permission)` is the
  permission the gate already read.
- **Row 6** (`roles:delete` of a deny role): unchanged. The clearance is network-sensitive
  for any `network:` grant, as before, which is what makes W4.2's row fire for an allow-only
  role too (as the plan asks).
- **Bind** (rows 7–8): the `before` read was already there; `checked` collects the nodes that
  passed `require_all`, in `BTreeSet` order.
- **H6** (§5.3): `h6_*` unit tests and both route tests pass (§8).

`cargo test -p axiam-authz`: 206 passed, 0 failed, the same count as the W4.1 body's.

---

## 4. W4.3 and W4.4 (b): the boot

### 4.1 The boot never fails or panics where 1.1.1's did not

`main.rs` `.expect`s `reconcile_default_role_grants`. W4.3 replaced
`tenant_is_organization_scope(…)` (`Option`, never an error) with `tenant_scope(…)`, whose
error is logged and mapped to `None`. No `?` was added, so the function's error paths are
1.1.1's. `network_revoked` is a new public field of `ReconcileOutcome`. The struct has no
other users in the workspace (`axiam-scim`'s `ReconcileOutcome` is an unrelated enum), and
`seeder_default_data_test` was updated. `main.rs` reads both counters, each with its own
`warn`. All 28 `axiam-server` binaries pass on the head (`--no-default-features`, 348 tests),
including the boot tests (`minimal_profile_boot`, `healthcheck`, `server_leaf_profile`,
`audit_wraps_routes`). All 86 `axiam-db` binaries pass (1 111 tests), `seeder_default_data_test`
and `seeder_skip_test` among them. R111W4-01's failure mode (an error type changed and a
crate's binaries not run) is absent.

### 4.2 What the skip leaves (R112W4-03)

The skip is right for the network half. The other half is unchanged:
`may_hold_org_actions = organization_scope == Some(true)` (`seeder.rs:881`), so `None` means
"ordinary tenant", and `seeder.rs:962-984` **revokes** every organization-level action the
super-admin and admin hold. For an ordinary tenant that is a no-op, because it holds none. For
the **organization scope's own tenant**, one failed read at boot strips its super-admin of
`organizations:*`, the CA and tenant lifecycle actions. It is #728's harm on the other half:
an outage of organization administration until a boot that can read the tenant. The reason
`main.rs:650-658` gives ("belong to the organization scope only") is false for that tenant,
and no audit row records the change (the organization-level revocations write none, unlike
the network ones). The probe (§8) seeded an unresolved tenant whose super-admin held
`organizations:update`. The reconcile returned `revoked: 1`, and the grant was gone.

The new `warn` (`seeder.rs:871-877`) and T-483's amendment both say organization-level
actions are "withheld as usual". The code revokes them. The 1.1.1 W4 review rated #728
Informational: only a transient error reaches the read, and the next boot repairs it. This is
rated the same.

**Fix (R112W4-03):** on `None`, withhold the organization-level grants (as now) but **revoke
none**. The decision becomes three-valued, like `NetworkHalf`. Then correct the `warn` and
T-483 (dated). **Test:** a unit test beside `an_unresolved_tenant_revokes_no_network_grant_and_grants_none`:
the probe above, asserting `ReconcileOutcome::default()` and the grant kept.

A note, not a finding: `admin_may_hold` does not depend on the tenant's kind, so revoking a
`network:` permission the admin role may never hold could proceed on an unresolved tenant.
The plan's row asked to skip the whole half, and the next boot does it. Deferring a
narrowing by one boot is accepted here.

---

## 5. W4.4 (d): `refusal_of` (R112W4-04)

`thrown` (`repository/network.rs:153-160`) matches `An error occurred: <marker>` followed by
the end or `;`. That is the form SurrealDB renders, and `tx_outcome` joins statement errors
with `"; "`. `network_repository_test`, whose cases assert the typed refusals of every marker, passes, so the
form holds in the pinned engine. A marker can no longer be echoed into that form: segment
names and site keys reject `:` and spaces (`NetworkSegmentPath::parse`), and W4.4's
integration test pins the `:`.

The **indexes** still use `contains` (`:140-145`), in the order VLAN, rank, name. The clash
text is ``Database index `idx_…` already contains [<tenant>, <site>, …, <name>]``. Both the
site key and the name are echoed, and both admit `_`. So the substring
`idx_network_segment_site_vlan` or `…_rank` can arrive as a value inside a name clash. The
probe (§8) shows it:

- a second segment named `idx_network_segment_site_vlan` at one site: `Network(DuplicateVlan)`
  (expected `DuplicateName`);
- a name clash at a site keyed `idx_network_segment_site_rank`: `Network(DuplicateRank)`.

The answer is `409` with the wrong `reason_code`. A client that retries with a new VLAN or
rank, as the code tells it to, fails the same way. Nothing widens, and the writer chose the
name, so this is **Informational**. It is the issue #730 (d) raised, moved from the markers
to the indexes.

**Fix (R112W4-04):** match the index name in the position the engine writes it,
``index `<name>` `` (with the backticks), or test the names in the order name, VLAN, rank
after matching that form. **Test:** the probe, as a `network_repository_test` case beside
`a_site_cannot_repeat_a_name_a_vlan_or_a_rank`, and a `refusal_of` unit case with the echoed
value.

---

## 6. W4.4 (f), (g): what the rows record (R112W4-05)

**(g) `node`.** `cleared.node()` is `assignment_node(&role, resource_id)`, the node every
`require_all` of the assignment ran at. `r110w6_06_…` now asserts `/network`'s id for a
tenant-wide user assignment and for a service-account assignment at the root. Held.

**(f) `nodes`.** These are the nodes that passed `require_all`, so on a success row every
node at which the account holds an effective join allow. `r110w6_06_…` asserts `[root]`. Held.

**(f) `before`.** `before` is `bound_service_account(certificate_id)` at the gate's read. The
bind is `RELATE … cert_bound_to …` under `idx_cert_bound_unique` (`in` unique), so a
certificate that is still bound when the write runs answers `409`, and no success row exists
for it (`2c7d77c` pins this). On a success row `before` is therefore `null`, except when the
binding the gate read disappeared before the write. No route removes a single binding. The
expired-certificate purge removes the certificate itself, so the bind fails. **Deleting the
service account removes its `cert_bound_to` edge**: the probe (§8) related a certificate to an
account, deleted the account, and counted 0 edges. So `before = X` appears on a success row
only when X was deleted between the gate and the bind. The certificate was then not "taken
from" X, which is what `docs/admin/README.md` and T-484 say the member means. The field is
either always `null` or misleading. The member is harmless; its documentation is wrong.

T-484's W4.4 amendment (both copies) lists, under `r110w6_06_…`, "a re-bind names the account
it was taken from". `2c7d77c` replaced that step with the `409` and did not touch the text.
The account a re-bind would take is pinned only in `axiam-authz`'s unit tests
(`network_gate/tests.rs:2514`), against a store that reports a bound certificate. Through the
route, the bind never succeeds in that state.

**Fix (R112W4-05):** either drop `before` from the success row (the refusal row keeps it, where
it is meaningful), or define it as "the account the gate saw the certificate bound to; on a
success row non-null only if that account was deleted in between" in `docs/admin/README.md`,
T-484 and `ClearedBinding::before`. Correct T-484's test sentence (dated, both copies). In
`write_and_record`'s doc, add `network_role.deleted` to the list, change "one of the five" to
"one of the six" and rewrap the line. **Test:** none (text); `check-doc-links.sh`, the copy
comparison of §7.

---

## 7. Audit actions and the threat model

**`network_role.deleted`** is printable ASCII with no space, so `is_valid_audit_action`
accepts it. It is not in `RESERVED_ACTION_NAMESPACES` (`tenants.`, `gdpr.`), and neither is
any `network_role.*` action. So an AMQP producer can append a `network_role.deleted` row (or a
`network_role.revoked`, which already existed) that the console cannot tell from the server's.
That is #741's case, owned by W2.8 (D-2: stamp `metadata.source = "amqp"`). This wave adds one
more action to the set W2.8's stamp must cover, and nothing beyond it. Noted for W7.1:
`network_role.deleted` joins contract §8's informative list of server-written families (the
W4.2 body says so).

**Copies.** T-457, T-483 and T-484 were compared by script: each `> ` block of the Markdown
entry was looked up verbatim in the `mitigation` / `description` of the `Axiam.json` threat with
the same `number`. All 3 + 5 + 6 blocks are present, the three 2026-10-22 amendments included.
`Axiam.json` parses. T-457's residual (f) was already in the model from 1.1.1 W8.3, so W4.4 (e)
touched only the module doc. The doc now names the read and agrees with the entry.
`website/src/threatModel*.ts` was not regenerated (both W4.1 and W4.2 say so, for W8.3).

---

## 8. Checks run (each tool's own exit code)

`CARGO_PROFILE_{DEV,TEST}_DEBUG=0`, `CARGO_INCREMENTAL=0` (the first run with debug info hit
the sandbox's disk quota, ENOSPC in `rustc`; nothing else changed between the two runs).
`protobuf-compiler`, `libxml2-dev` and `libxmlsec1-dev` installed; swagger placeholder set.

| Command | Exit |
|---|---|
| `cargo test -p axiam-server --no-default-features --tests` (28 binaries: lib, main, and `audit_wraps_routes`, `cleanup_task`, `crl_purge_margin`, `device_grant_boot_warning`, `directory_e2e`, `directory_sync_sweep`, `federation_secret_backfill`, `grpc_client_auth`, `grpc_tls_crypto_provider`, `healthcheck`, `minimal_profile_boot`, `mtls_anchor_reload`, `notification_window_test`, `outbound_supervisor_single_copy`, `radius_e2e`, `req14_gdpr_test`, `req5_clock_skew`, `req5_oidc_e2e`, `req5_saml_e2e`, `req5_secret_at_rest`, `req7_service_account_aud`, `req7_session_lifecycle`, `scim_dead_letter_notification_test`, `scim_erasure_propagation_test`, `scim_reconcile_sweep_test`, `server_leaf_profile`) | 0 (348 passed, 0 failed) |
| `cargo test -p axiam-authz` (6 binaries) | 0 (206 passed, 0 failed) |
| `cargo test -p axiam-db --tests` (86 binaries, `seeder_default_data_test`, `seeder_skip_test`, `network_repository_test` among them) | 0 (1 111 passed, 0 failed, 5 ignored) |
| `cargo test -p axiam-api-rest` (SAML on) `--lib --test network_gate_test --test network_gate_enumeration_test --test network_decide_test --test network_routes_test --test certificate_test --test ca_certificate_test --test role_permission_test --test tenant_scoped_roles_test --test role_assignment_scope_test --test audit_test` | 0 (11 binaries: lib + the ten; 464 passed, 0 failed) |
| `cargo fmt -p axiam-api-rest -p axiam-authz -p axiam-db -p axiam-server -- --check` | 0 |
| `cargo clippy -p axiam-api-rest -p axiam-authz --lib --tests -- -D warnings` (SAML on) | 0 |
| `bash scripts/check-doc-links.sh` | 0 (537 links, 78 files) |
| `python3 scripts/check-remediation-evidence.py` | 0 (5 verified, 32 skipped) |
| `python3 scripts/check-crate-layering.py` | 0 |
| `python3 -c 'json.load(…Axiam.json)'` | 0 |
| T-457 / T-483 / T-484 copy comparison (script, §7) | all blocks verbatim |
| `git cat-file -p <c> \| grep -c gpgsig`, five commits | 1 each |
| Probe 1 (appended to `network_repository_test.rs`, reverted): repeated name `idx_network_segment_site_vlan`; name clash at site `idx_network_segment_site_rank`; a `cert_bound_to` edge after its account's `DELETE` | 0; `Network(DuplicateVlan)`, `Network(DuplicateRank)`, `Some(0)` edges |
| Probe 2 (appended to `seeder.rs` `mod tests`, reverted): an unresolved tenant whose super-admin holds `organizations:update` | 0; `ReconcileOutcome { granted: 0, revoked: 1, network_revoked: 0 }`, grant gone |

`radius_e2e` passes without Docker by skipping its body (no daemon here). W5's review covers
the RADIUS end-to-end through CI.

---

## 9. Commit messages and §10

| Commit | Claim | Verdict |
|---|---|---|
| `c3cc5fb` | row from the clearance; write and append as one spawned task; panic resumed; grants at commit; T-484 | true (§2.1–2.3). The task boundary leaves the D7 flush and the refusal row outside (R112W4-01). The "process stop" residual includes an orderly stop (R112W4-02) |
| `8394b35` | `network_role.deleted` for any `network:` grant; none without; docs; T-484 | true (§3, §7); `write_and_record`'s doc not updated (R112W4-05 c) |
| `c26591f` | unresolved kind skips the network half; one `warn`; seeder unchanged; T-483 | true for the network half; "organization-level actions are withheld as usual" is not what the code does (R112W4-03) |
| `3ad1120` | (a)–(g) | (a), (b), (c), (e), (g) true; (d) fixed for markers, not indexes (R112W4-04); (f) `before` documented for a case the route refuses (R112W4-05) |
| `2c7d77c` | the route refuses a bound certificate, `before` pinned null | true; T-484's text not corrected with it (R112W4-05 b) |

§10: every commit is signed. There is no contract edit, migration, route or crate. Each row's
test is in its own commit. Threat-model amendments are dated, and the older text stays. W4.4's
executor did not run the `axiam-server` binaries. They were run here (§8) and pass. No test
message interpolates a token, a secret or a certificate: the new assertions print audit-row
metadata, which the rows' own rule keeps free of key material (`!text.contains("BEGIN")`).

---

## 10. What could not be verified

- **R112W4-02 was not exercised.** The stop behaviour is read from `actix-server` 2.9.8 and
  `actix-rt` 2.15.0, not observed. Whether a SurrealDB write whose future is dropped
  mid-request commits server-side was not tested either.
- **R112W4-01's stale allow was not reproduced** with a cache attached. The argument is the
  control flow of §2.5, plus the W4.1 drop test, which shows the handler's future really is
  dropped after the write.
- The W4.1 body says its drop test fails with the task inlined. That was not re-run.
- The full `axiam-api-rest` suite (112 binaries) was not run here, only the ten the wave
  touches. The W4.1 and W4.2 bodies report the full suite green on their heads, and W4.4
  touched only `network_gate_test` in that crate's tests.

---

## 11. For later tasks

- **Sweep slot (§1.4):** R112W4-01 and R112W4-02 touch the same function and the same boundary,
  so take them in one Opus session, R112W4-01 first. R112W4-03, -04 and -05 fit one Sonnet
  session.
- **W7.1:** `network_role.deleted` in contract §8's informative list (from W4.2). Nothing from
  this review changes the contract, unless R112W4-05 drops `before` from the success row, in
  which case the list's member note says so.
- **W8.3:** T-483 (R112W4-03), T-484 (R112W4-02 if the text route is taken, R112W4-05 (a),
  (b)); regenerate `website/src/threatModel*.ts` (not done in W4).
- **W8.4:** the CHANGELOG lines for #726 and #727 should not claim the revocation takes effect
  despite a disconnect until R112W4-01 is fixed.

---

## 12. Issues

Filed on `ilpanich/axiam`, milestone `1.1.x`. Each body is the finding's subsection and ends
with the attribution footer. A search of the open issues for the network gate, the reconcile,
`refusal_of` and the binding row found only #726 … #730, which this wave closes, and #741
(W2's, noted in §7). There are no duplicates.

| ID | Issue |
|---|---|
| R112W4-01 | [#775](https://github.com/ilpanich/axiam/issues/775) |
| R112W4-02 | [#776](https://github.com/ilpanich/axiam/issues/776) |
| R112W4-03 | [#777](https://github.com/ilpanich/axiam/issues/777) |
| R112W4-04 | [#778](https://github.com/ilpanich/axiam/issues/778) |
| R112W4-05 | [#779](https://github.com/ilpanich/axiam/issues/779) |
