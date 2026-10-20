# Security review — release 1.1.1, wave W4 (F4)

**Date:** 2026-10-19.
**Against:** `claude/release-1.1.1-w4`, the whole wave diff `origin/main..b8ce6ca58`
(7 commits, 28 files, 1 598 lines added and 335 removed). Every commit carries a
signature (`gpgsig` header in 7 of 7; the sandbox has no `gpg.ssh.allowedSignersFile`,
so `%G?` cannot verify them here).
**Scope:** every W4 task of the release-1.1.1 plan (§5):

* W4.1 `9e1108a43` (#704): the migration runner applies every unrecorded listed version.
* W4.2 `912742f84` (#702): the organization scope's super-admin loses the network permissions.
* W4.3 `27aa45778` (#703): a cleared network-sensitive write leaves its own audit row.
* W4.4 `bbf0a6483` (#706): the decision route's decoy verification.
* W4.5 `bb670002f` (#708): a typed `NetworkConflict`, carried as `AxiamError::Network`.
* W4.6 `d6a69bbe6` (#709): the console gates the profile editor on `network:grant` too.
* W4.7 `b8ce6ca58` (#715 a, d, e): verification of (a), T-481 restated, the enumeration
  exemption pinned.

**Method:** that of the 1.1.0 W6 review (`security-review-release-1.1.0-w6-2026-10-16.md`),
with its severity scale. Every commit message was read in full and each claim is answered
below (§9). H1 … H6 of the design note's §5.2 and the §5.3 rows were read again, line by
line, against `crates/axiam-authz/src/network_gate.rs` and every REST caller, with W4.2's
change of *who holds* and W4.3's new success rows in view (§3). The migration list was
read statement by statement for what an out-of-order application does (§6). Every place
that matches on `AxiamError` was read for the new variant, gRPC, AMQP and SCIM included
(§5). The threat-model text was read against the code and the two copies compared (§10).
The issues' comments were read (#702, #703, #704, #706, #708, #709, #715: none has any).
The **full** test binaries of every crate the wave touched were run, crate by crate (§11),
and that is how the one Medium was found: a test the wave did not run fails on its head.
This review fixes nothing. IDs: `R111W4-nn`.

---

## 0. Summary

**One Medium, two Low and three Informational.**

The wave does what its rows say on the paths they name. H1 … H6 and the §5.3 table are
unchanged in the gate and still hold (§3). W4.2 withholds the six network permissions from
the organization scope's super-admin at seeding and at boot, and an organization-level
writer is refused `network:grant` in a child tenant. W4.3 appends one row after every
cleared assignment, unassignment, grant, revoke and bind. W4.4's decoy closes the
cross-tenant existence signal: whether a fingerprint is registered in another tenant no
longer decides whether a verification runs. W4.5's variant is mapped wherever
`AxiamError` is matched, and the wire is unchanged. The console and the enumeration test
do what their rows say.

One thing needs action before the wave merges:

* **R111W4-01 (Medium, wave — W4.5 × the R110W6-04 reconcile).** W4.5 changed the error
  the role transactions return for a §4.2 rule-2 refusal from `AxiamError::Conflict` to
  `AxiamError::Network(NetworkConflict::StaleRole)`. The boot reconcile still matches
  `Err(AxiamError::Conflict { reason })` to *withhold* a network permission from a
  super-admin that a group holds (`seeder.rs:880`). Every other error fails the
  reconcile, and `main.rs` `.expect`s it. **An upgraded deployment whose
  ordinary-tenant super-admin is held by a group — the state the 1.1.0 handling exists
  for — no longer boots.** Confirmed on the head:
  `seeder_default_data_test::reconcile_withholds_network_grants_from_a_group_held_super_admin`
  fails with `Migration("reconcile grant super-admin failed: the role changed since it was
  read (a group was assigned it); …")`. The wave's executors did not run that binary.

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R111W4-01** | The boot reconcile matches the old `Conflict` for the rule-2 refusal W4.5 retyped; a group-held super-admin now fails the reconcile, and the server panics at boot. Red test on the head. | **Medium** | `seeder.rs:880`; `repository/role.rs:214-220, 339-345`; `main.rs:629-634` | wave (W4.5) | **Fix in wave** |
| R111W4-02 | The success row can be skipped on a cleared path: it is built from reads made after the write and appended after further suspension points, so a client that disconnects after the commit, or a concurrent delete of the role, leaves the write with no row (and no request row either). | Low | REST `network_gate.rs:281-469`; handlers `roles.rs`, `permissions.rs`, `certificates.rs` → T-484 | wave (W4.3) | #726 |
| R111W4-03 | A cleared role delete leaves no `network_role.*` row, although deleting a role that carries a `network:` deny releases every quarantine of that role at once (§5.3's `roles:delete` row). T-484 is marked Mitigated while it says so in one sentence. | Low | `roles.rs` `delete`; gate `role_delete` → T-484 | wave (W4.3) | #727 |
| R111W4-04 | The reconcile's "unresolvable tenant fails closed" is destructive at boot: one failed tenant read revokes the six network permissions from an *ordinary* tenant's super-admin, writes six rows saying it "may not hold" them, and logs nothing about the read (`.ok()`). The next boot grants them back. | Informational | `seeder.rs:309-318, 825-862` → T-483 | wave (W4.2) | #728 |
| R111W4-05 | "Every migration is idempotent DDL, so a late application is safe" is not true of the list: 17 migrations use plain `DEFINE`, seven backfill with `UPDATE`, v42 `REMOVE`s, and three fields are `OVERWRITE`n twice. The gap that motivated #704 (v99) and this release's v108/v109 are additive, so nothing reachable today is unsafe. | Informational | `schema.rs:2484-2500` (doc), `:39-530` (list) | wave (W4.1) | #729 |
| R111W4-06 | Text and row content behind the code after W4 (seven items, §8.3). | Informational | §8.3 | wave | #730 |

The brief's points that are **not** findings, each argued in its section: an audit
append is skipped on no cleared path *by the code's own control flow* (every handler calls
`record_cleared` directly after the `Ok`, with no `?` or early return between; §4.1); a
failed append reveals nothing to the caller (§4.2); the reconcile's writer is
append-only and touches only the seeded `super-admin` and `admin` (§2.2); none of the
decoy residuals (a) … (f) is Medium, and (d) is not cross-tenant at all (§7); the new
variant is mapped exhaustively, with identical behaviour on every non-REST surface (§5);
the threat-model copies agree (§10).

---

## 1. What was reviewed, and where it is answered

| Point of the brief | Where answered |
|---|---|
| Every commit message against the code | §9 |
| §10 rules of the plan | §9.8 |
| H1 … H6 and §5.3 against `network_gate.rs`; W4.2's scope change; W4.3's rows; can an append be skipped; can a failed append reveal anything | §3, §4 |
| The migration runner: is out-of-order application ever unsafe; which migrations are not idempotent DDL | §6 |
| The reconcile: append-only writer; does it touch a non-seeded role | §2 |
| The decoy residuals (a) … (f): any Medium | §7 |
| The new `AxiamError` variant: mapped everywhere, gRPC and AMQP included | §5 |
| Threat-model text against the code (T-457, T-481, T-483, T-484); both copies | §10 |
| The executors' follow-ups: confirmed or rejected | §9 |
| Issue comments (#702, #703, #704, #706, #708, #709, #715) | none has a comment; the bodies were read |
| Checks | §11 |
| Notes for W7.1, W8.3, W8.4 | §12 |

---

## 2. R111W4-01 — the reconcile no longer recognises the rule-2 refusal (Medium)

### 2.1 The defect

The R110W6-04 fix (1.1.0, #701) made the grant's own transaction refuse a `network:`
permission to a role a group holds (§4.2 rule 2). The boot reconcile was taught to
**withhold** in that case rather than fail the boot. A release before 1.1.0 allowed a
group to hold the super-admin role, and refusing to start such a deployment would be an
outage the rule never meant to cause:

```rust
// crates/axiam-db/src/seeder.rs:876-895 (head)
match perm_repo.grant_to_role(tenant_id, super_admin_id, perm.id).await {
    Ok(()) => outcome.granted += 1,
    Err(AxiamError::Conflict { reason }) => { tracing::warn!(…"withheld"…); }
    Err(e) => { return Err(DbError::Migration(format!("reconcile grant super-admin failed: {e}"))); }
}
```

On `main` the refusal arrived as `Conflict`: `repository/role.rs`'s `network_role_raced`
built `AxiamError::Conflict { reason }`. W4.5 changed that helper to
`AxiamError::Network(NetworkConflict::StaleRole { what_landed })`
(`repository/role.rs:214-220`), and `role_tx_outcome` returns it for
`NETWORK_GRANT_TO_GROUP_HELD_ROLE` (`:339-341`). The unclaimed `grant_to_role` the
reconcile calls goes through `role_tx_outcome` (`repository/permission.rs:702`). The
`Conflict` arm is now dead, and the refusal falls into `Err(e)`. In
`crates/axiam-server/src/main.rs:629-634` the reconcile is
`.expect("Failed to reconcile default role grants for tenant")`.

**Who is hit.** Any deployment with an ordinary tenant whose `super-admin` role is
assigned to a group and does not yet hold every one of the six network permissions. That
is exactly the population the 1.1.0 handling was written for: such a tenant's super-admin
never received them in 1.1.0, so every 1.1.1 boot retries the grant. The process panics
before it serves. The organization scope tenant is not affected: since W4.2 its
super-admin may hold no network permission, so no grant is attempted there.

**Evidence.** On the head (`b8ce6ca58`), the full `seeder_default_data_test` binary
fails one test (18 passed, 1 failed):

```
reconcile_withholds_network_grants_from_a_group_held_super_admin … FAILED
a group-held super-admin does not fail the reconcile:
  Migration("reconcile grant super-admin failed: the role changed since it was read
  (a group was assigned it); read it again and retry")
```

W4.2's executor ran this binary before W4.5 existed. W4.5's executor ran the
network-repository tests and the REST pin, not the seeder binary. The plan's per-commit
gate ("the touched test binaries") did not name it, because `seeder.rs` is not a file
W4.5 touched.

**Why Medium.** It is an availability failure of the whole server at upgrade, in a state
AXIAM itself allowed and documented. It is reachable without any attacker. It is a
regression of a deliberate fix. It is not a confidentiality or integrity breach, and it
fails closed (nothing is granted), which keeps it below High.

### 2.2 The reconcile otherwise (the brief's questions)

* **Append-only writer.** `audit_network_revocation` (`seeder.rs:664-699`) calls
  `SurrealAuditLogRepository::append`, a single `CREATE type::record('audit_log', $id)`
  (`repository/audit.rs:296-336`). It never updates or deletes. A failed append is
  logged at `error` and does not stop the boot; the revocation it records has already
  committed. That is the right order: refusing to start would leave the escalation in
  place.
* **Non-seeded roles.** The reconcile finds roles by the seeded names (`super-admin`,
  `admin`, `viewer`, `:789-805`). It returns without touching anything when the three are
  not all present. The network half revokes only from `super_admin_id` and `admin_id`
  (`:839-862`). A role an operator created is not read. The name match is the
  pre-existing mechanism, and role names are unique per tenant.
* **The org scope's other global roles.** A `network:` grant to a global role is refused
  by the gate (rule 1, `permission_grant`), and so is making a network-sensitive role
  global (`role_update`). The seeded super-admin was the only door, and it is closed.

### 2.3 Proposed fix and test

Match the typed refusal (keep the `Conflict` arm only if something else can still raise
it there; nothing does):

```rust
Err(AxiamError::Network(NetworkConflict::StaleRole { what_landed })) => { tracing::warn!(… %what_landed …); }
```

**Test:** the existing
`seeder_default_data_test::reconcile_withholds_network_grants_from_a_group_held_super_admin`
is the oracle and is red today. Add to W4.5's gate (and to §10's "touched binaries" in
spirit) every test binary of a crate whose error type a commit changes. A cheaper guard:
`grep -rn 'AxiamError::Conflict' crates/` for every `match` arm whenever a refusal is
retyped. That grep finds `seeder.rs:880` and `ssf.rs:447` (the latter unrelated).

---

## 3. H1 … H6 and §5.3, line by line (once more)

All references are to `crates/axiam-authz/src/network_gate.rs` at the head unless named.
The wave changed nothing in the gate's decisions. It added the five success-action
constants (`:119-128`) and the `revoked_effect` accessor (`:689-694`). What the wave
changed is *who holds* (W4.2) and what is written after a cleared write (W4.3). "Holds" is
`subject_holds` (`:1105-1124`) → `check_at_write_time`, uncached, deny-override in force,
with the writer's own subject scope.

### 3.1 §5.2 — profiles and segments

| Rule | Code | Verdict |
|---|---|---|
| admin-class `Service-Type` refused `400` before any permission (#700) | `:1248-1255` | Holds |
| **H1** `network:profiles_write` on `S` | `:1257-1262`, node `seg.id` | Holds |
| **H2** `network:grant` on `S` | same loop | Holds |
| **H3** `filter_id ∈ S.filter_ids`; timeout ≤ cap; VLAN derived | `:1264-1285`; the input has no VLAN member | Holds (the cap is read outside the write's transaction: T-481's window, unchanged) |
| **H4** admin class needs `grant_admin` and `admin` | `:1287-1297` | Holds; unreachable under option B |
| **H5** quarantine profile needs `network:grant` at `/network/quarantine/<site>` | `:1299-1310` | Holds |
| **H6** the writer may not join `S` | `:1312-1321` | Holds |
| profile delete: H1, the placing right, H6 | `:1328-1368`, `placement_rights` `:1375-1395` | Holds |
| segment replace: `segments_write`; placing right when a placement field of a profiled segment moves; H6; frozen clearance otherwise | `:1458-1528` | Holds |
| segment delete: as above for a profiled segment | `:1530-1580` | Holds |
| the cap: `segments_write` at the root | `:1582-1606` | Holds |

### 3.2 §5.3 — assignment, grant, revoke, delete, bind

| Row | Code | Verdict |
|---|---|---|
| assign join allow / deny at `N` (`N = /network` for a global role or no resource) | `role_assign` `:1608-1691`; `assignment_node` `:1168-1174` | Holds |
| assign meta permissions: hold every one at `N` | `NetworkGrants::delegated`, `:1676-1689` | Holds |
| rule 2 (never on a group), rule 3 (no deny with `inherit: false`) | `:1643-1662`; grant side `:1897-1913` | Holds |
| **H6** on assign: no join allow to the writer or a group it is in | `:1664-1675`, `edge_reaches_writer` `:1197-1207` | Holds |
| unassign of a deny: H6, then `network:grant` at the edge's node | `role_unassign` `:1693-1744` | Holds |
| role delete carrying a deny: H6 (`writer_holds_role`), then `network:grant` at the root | `:1777-1820` | Holds |
| `permissions:grant` of `network:` (either effect): admin class `400`, scoped `400`, rule 1/2/3, H6 for a join allow on a held role, `network:grant` + the meta permission at the root | `permission_grant` `:1822-1944` | Holds |
| `permissions:revoke`: H6 for a deny on a held role, `network:grant` at the root, conditional on the effect read | `:1946-2008` | Holds |
| bind: H6 (the account is the writer), `network:grant` at every node where the account's join allow is effective | `certificate_bind` `:2075-2151` | Holds |

### 3.3 What W4.2 changes in this table

Nothing in the rules. It changes the input to every "holds" for one class of writer.
An organization-level principal acting in a child tenant is evaluated with
`SubjectScope::Organization`, and the engine carries only that principal's **global**
grants across tenants (`engine.rs:155-172`). Before W4.2 the org scope's seeded
super-admin was global and held the six. So such a principal cleared H1, H2, the §5.3
`network:grant` checks and `network:decide`'s RBAC check in every tenant of its
organization. After W4.2 it holds none of them (unless an ordinary role of the child
tenant is assigned to it, which is an explicit, gated act), and it is refused at H1/H2
and at every §5.3 row. That is the intended effect, and the gate test
`network_gate_test::an_organization_level_writer_is_refused_network_grant_in_a_child_tenant`
shows it (with the child's own super-admin as the control).

Two adjacent paths were checked. A tenant-scoped assignment (`validate_tenant_scope`,
`roles.rs:442ff`) lets an org-scope **global** role reach chosen tenants, but no global
role can carry a `network:` grant (rule 1, both directions). And the org scope's own
non-global roles apply only in the org scope tenant. **No path is left by which an
organization-level writer clears H1 … H6 in a child tenant on grants of its own scope.**

---

## 4. W4.3's success rows: can one be skipped, and can a failure reveal anything

### 4.1 By control flow: no

The eight handlers that run a §5.3 write are `roles.rs` `assign_to_user`,
`unassign_from_user`, `assign_to_service_account`, `unassign_from_service_account`,
`assign_to_group` and `unassign_from_group`, plus `permissions.rs` `grant_to_role` and
`revoke_from_role`. Each is `authorize → *_claimed write → on Err refused_after_clearance
and return → record_cleared(…)`, with no `?` and no early return between the write's
`Ok` and the call. `certificates.rs` `bind` is `authorize → bind_to_service_account(…)? →
record_cleared`. `record_cleared` returns early only for a clearance that is not
network-sensitive (the gate's own verdict) or a write kind it does not describe
(`_ => return`, `:435`), which is `RoleUpdate`, `RoleDelete` and the non-role writes.
The non-role writes have their own rows. The role-shaped two are R111W4-03.

The segment, profile and cap routes are untouched by W4.3 and keep their own rows
(before and after), as T-484's text says. The UMA and generic resource routes clear only
non-sensitive writes (they refuse the reserved subtree).

### 4.2 A failed append reveals nothing

A failure of the role, permission or grant reads, or of the append, is logged at
`error` (target `axiam::network_gate`, with the tenant, the action and the error) and
returns. The handler's response is the same `2xx` either way. No field of the response,
no header and no status depends on it. The log line carries no certificate, key or
token. The row itself carries ids, role and action names and effects
(`network_gate.rs:281-469`). The same holds for `refused_after_clearance`'s append
(`:251-260`).

### 4.3 But the row can still be lost — R111W4-02 (Low)

Two ways, both outside the handler's own control flow:

1. **Cancellation.** The repository write commits inside the handler's future, and
   `record_cleared` then awaits two or three reads (`role_name`, `network_permissions`,
   `permission_repo.get_by_id`) before its `append`. Actix drops a handler's future when
   its client goes away. The tree already treats that as a cancellation point, in
   `handlers/gdpr.rs:200-223` ("a handler dropped when its client goes"). A writer who
   closes the connection after the commit and before the append leaves the write with no
   `network_role.*` row. The generic request row is lost with it: the audit middleware's
   `try_send` runs after the inner service's future resolves
   (`axiam-audit/src/middleware.rs:532ff`). The reads before the append widen a window
   that would otherwise be one round trip. The writer is an authenticated holder of the
   rights it used, so this is repudiation by an insider, T-484's own class and severity.
2. **A concurrent role delete.** The row is described from the role *as it is after* the
   write. A role deleted between the write and `role_name` makes the read fail with
   `NotFound`, and the row is skipped ("could not be described"). A role whose grants
   change in that interval is described with grants it did not have when the gate
   cleared the write. The delete of a role with no `network:` deny needs only
   `roles:delete` (the gate adds nothing), and the delete itself leaves no network row
   (R111W4-03).

**Proposed fix.** Build the row from what the gate read, not from fresh reads: carry the
role's name and its `network:` grants on the `GateClearance` (the gate already holds
`NetworkGrants::of(role_grants(…))` for every role write). Then run the write and the
append as one spawned task that the handler awaits through its `JoinHandle`; dropping the
handle does not cancel the task. Alternatively, write the row inside the write's own
transaction, which is the only form that cannot be separated from the write. **Test:** a
unit test in `network_gate_test.rs` that drops the handler future immediately after the
repository write returns (a store wrapper that signals and then pends), then asserts the
row exists. Also a test that deletes the role between the write and the description and
still finds a row naming the role.

---

## 5. The new `AxiamError` variant

`AxiamError::Network(NetworkConflict)` (`axiam-core/src/error.rs:134-141`). `AxiamError`
is not `#[non_exhaustive]`, so every exhaustive `match` in the workspace had to name
it to compile. Every non-exhaustive one sends it to its wildcard. Each place was read:

| Surface | Mapping | New variant | Before (`Conflict`) | Verdict |
|---|---|---|---|---|
| REST `error.rs:84-170` | status, slug, message | `409`; `already_exists` when `is_uniqueness()`, else `conflict`; message is `Display` | `409` `conflict` | Same wire. The four uniqueness cases came back as `AlreadyExists` before and keep `already_exists` |
| REST `handlers/network.rs:446-457` `NetworkConflictReason::of` | `reason_code` | one exhaustive `From<&NetworkConflict>` | substring matching | Same values, pinned by `every_network_409_carries_its_reason_code` (green, §11) |
| REST `handlers/network.rs:704-740` `refused` | audit rule | explicit arm | `Conflict` arm | Same |
| REST `network_gate.rs:146-266` `refused_after_clearance` | `409 stale_version` + row | keyed on `of() == StaleVersion` | keyed on `Conflict` | Same set of errors (every `StaleVersion` variant is a former "changed since it was read" `Conflict`) |
| gRPC `services/user.rs:105`, `services/reactor.rs:202` | `Status` | wildcard → `internal` | wildcard → `internal` | Same; neither service reaches a network or role-claim write |
| AMQP consumers | match only `ReplayDetected` | n/a | n/a | Same |
| SCIM `error.rs:184-233` | SCIM error | wildcard → `500` | wildcard → `500` | Same; SCIM writes group membership, not role assignment, so it cannot meet a rule-2 refusal |
| `seeder.rs:880` | withhold on rule 2 | **falls to `Err(e)`** | withheld | **R111W4-01** |
| `ssf.rs:447` | retry on `Conflict` | n/a | n/a | Unrelated (SSF receiver writes raise no network refusal) |

**Verdict.** The variant is mapped where the wire is made, and identically to before on
every surface but one. The exception is not a wire mapping at all: it is a control-flow
match in the seeder (R111W4-01). W4.5's "the wire output is byte-identical" is confirmed
for the REST routes. "The THROW marker is matched only in `refusal_of`" is true of the
network module's markers. The role module's markers are matched in `role_tx_outcome`
(`repository/role.rs:320-361`), as before. That claim was about the network module and
is not wrong, but it should not be read as "one place in the crate".

---

## 6. The migration runner (W4.1)

### 6.1 What it does

`run_migrations` (`schema.rs:2501-2589`) reads every recorded version, then applies in
list order each listed version not recorded, one transaction each (DDL plus the
`_migration` row). It logs at `warn` when the version is below the highest recorded. The
startup lock is unchanged. `migrations_are_contiguous` asserts 1 … N with exactly 86 … 89
excepted. The list has 103 entries for 1 … 107, confirming that the hole is those four.
The executor's reading of the hole (never claimed, permanent) is right. The schema test
`a_version_below_the_highest_recorded_is_still_applied` (`schema_test.rs:157`) drops
v99's DDL and record, keeps 100 … 107, and sees v99 applied and
`idx_certificate_issuer_serial` back.

### 6.2 Is applying an older migration out of order ever unsafe? (R111W4-05, Informational)

The doc comment and commit say every migration is idempotent DDL. Reading the 103
bodies, it is not:

| Class | Versions | Out of order |
|---|---|---|
| plain `DEFINE` (no `IF NOT EXISTS` / `OVERWRITE`) | 1 … 14, 35, 41, 42 | fails if the object exists. The transaction rolls back, and the boot fails with the version named. Fail-closed, never silent |
| `UPDATE` backfill | 24, 41, 42, 43, 44, 45, 53 | runs on today's rows. v43 (`UPDATE email_config SET enabled_override = enabled WHERE scope = 'tenant'`, `:2896`) would **overwrite every tenant's explicit override** with its stored `enabled` |
| `REMOVE` | 42 (the SRP tables and fields, `:2793-2796`) | v41 applied after v42 would re-create the SRP schema v42 removed |
| a field `OVERWRITE`n twice | `user.status` (v15 → v48 adds `Deleted`), `email_template.kind` (v15 → v82), `oauth2_proof_replay.kind` (v81 → v102) | the older definition re-narrows the `ASSERT`. A user in status `Deleted`, or a v102 proof-replay row, can then no longer be written |

**Is any of it reachable?** Only for a datastore that recorded a later version and not an
earlier one. A released build carries every version up to its newest, and the runner
applied them in order, so a released datastore has no such gap. The gaps come from branch
builds run against a shared datastore: v99 was one, and this release's W1 (v108) and
W3 (v109) would be the next. Both are additive. Each carries a test that its SQL contains
no `UPDATE`, `REMOVE`, `DELETE` or `OVERWRITE` (read on `origin/claude/release-1.1.1-w1`
and `-w3`). **Nothing reachable today is unsafe.** That is why this is Informational: the
claim in the code is wrong, and the safety it asserts rests on a convention (plan §10's
"each additive") that no test ties to the runner.

**Proposed fix.** Correct the doc comment. Then make the runner refuse, with a boot error
naming the version, an out-of-order application of a migration whose SQL is not additive
(`UPDATE`, `DELETE`, `REMOVE`, `OVERWRITE`, or a `DEFINE` without `IF NOT EXISTS`); an
operator resolves it by hand. **Test:** a unit test over `MIGRATIONS` that every migration
above the newest *released* version is additive (the W1/W3 per-migration checks,
generalised), and a schema test that a recorded-gap below a non-additive migration is a
boot error, not an application.

---

## 7. The decision route's decoy (W4.4) and the residuals (a) … (f)

`verification_target` (`network_decide.rs:415-430`) returns `Decoy(caller.der)` whenever
no row **of the caller's tenant** resolves, in both forms. `resolve_certificate`
(`:438-507`) runs `authenticate_der` over it and discards the result with `let _ =`.
`authenticate_der` (`axiam-pki/src/mtls.rs:63ff`) has no cache. The caller's own
certificate is Active, chained and bound (it authenticated the request moments before),
so the decoy runs the full path: two fingerprint reads, the CA read, the parse, the
signature verify, the anchor check and the binding read. That is the work a valid
certificate of this tenant costs. The unit test
`every_path_verifies_one_certificate_and_every_refusal_the_callers` pins the selection,
and fails against the pre-fix selection (read in the diff). The answer, the audit row and
the bucket spend are unchanged; the decoy adds no early return.

| Residual (executor's list) | Who learns what | Severity |
|---|---|---|
| (a) this tenant's revoked, expired or wrong-type rows stop early in `authenticate_der` | the caller learns, by time, something about **its own tenant's** certificate it could ask the API for | not a finding (own tenant) |
| (b) an unparsable stored PEM of this tenant verifies nothing | own tenant; a corrupt row | not a finding |
| (c) the engine's no-assignment short-circuit | own tenant's subject | not a finding (already in T-457) |
| (d) ~10 % between "a certificate of my tenant" and "not of my tenant" | whether a fingerprint is **this** tenant's, which the caller can know anyway. "Unknown" and "another tenant's" take the same path, the decoy, and the commit's medians put both at 1.05–1.09 of a placement | not a finding: not cross-tenant |
| (e) a malformed body answered `400` | nothing about any certificate (decided before any read) | not a finding |
| (f) a fingerprint hit versus miss in the global read | whether a row exists **in any tenant**: the one `get_by_fingerprint_global` returns and deserialises a row for another tenant's certificate, and `NotFound` for an unknown one. After that both take the decoy | Informational — a cross-tenant difference of one indexed read (microseconds) against a verification (milliseconds), on a route that admits only a certificate-bound `network:decide` service account under its own limiter. **Not stated** in T-457's amendment or the module doc (R111W4-06 (e)) |

**None is Medium.** The cross-tenant signal R110W6-09 named is closed in the sense that
matters: whether another tenant holds the fingerprint no longer decides whether a
verification runs. What remains is (f), two orders of magnitude below what W4.4 removed.

---

## 8. R111W4-03, R111W4-04 and R111W4-06 — detail

### 8.1 R111W4-03 (Low) — a cleared role delete leaves no network row

The gate decides `RoleDelete` (`:1777-1820`): a role carrying a `network:` deny needs H6
and `network:grant` at the root, because deleting it releases every assignment of it at
once. That is a mass quarantine release, the strongest widening in §5.3. `roles.rs`
`delete` calls `refused_after_clearance` on a lost race but never `record_cleared`, and
`record_cleared` has no arm for it (`_ => return`). A role with only `network:` allows
(say `network:join`) is deleted with `roles:delete` alone and no row either. T-484's
amendment says "A role update or delete … leaves no such row", and its title is
"assignment, grant or binding", so the text is honest. But the entry is marked
**Mitigated** while the release of a whole quarantine is recorded only by the request
row (actor, path, outcome; no role name, no grants). The issue (#703) named no action for
the delete, and the executor followed it.

**Fix:** a `network_role.deleted` row carrying the role's name and its `network:` grants
as the gate read them (carried on the clearance, since the role is gone afterwards).
**Test:** in `network_gate_test.rs`, the delete of a deny role leaves exactly one such
row naming the deny, and the delete of a role with no `network:` grant leaves none.

### 8.2 R111W4-04 (Informational) — fail-closed is destructive in the reconcile

`tenant_is_organization_scope` (`seeder.rs:309-318`) turns any `get_by_id` error into
`None` with `.ok()` and logs nothing. In the seeder, `None` withholds, which is correct.
In the reconcile, `network_super_admin = (scope == Some(false))` is `false` for `None`,
so `super_admin_may_hold` answers no for all six. The revoke half then **removes** them
from an *ordinary* tenant's super-admin (`:839-862`) and writes six
`network_role.permission_revoked_by_reconcile` rows giving the reason "the seeded role
may not hold this network: permission in this tenant", which is false for that tenant.
The next boot grants them back. The tenant row was listed moments before
(`main.rs:607-617`), so only a transient datastore error reaches this. The harm is an
outage of network administration until the next restart, plus misleading rows, and the
operator gets no line saying why.

**Fix:** in the reconcile, treat `None` as "skip the network half for this tenant this
boot" and log at `warn` with the error; keep the seeder's withholding. **Test:** a unit
test of the decision (a resolved ordinary tenant, the org scope, and an unresolved one)
asserting the unresolved case revokes nothing.

### 8.3 R111W4-06 (Informational) — text and row content

* (a) REST `network_gate.rs:128-129`: "a write that lost comes back as
  `AxiamError::Conflict`". Since W4.5 it is `AxiamError::Network(StaleRole)`.
* (b) `main.rs:650-656`: the reconcile's revoke counter now also counts W4.2's network
  revocations in the organization scope, but the `warn` still says "Revoked N
  organization-level permission grant(s) from this tenant's default roles —
  organization-level actions … belong to the organization scope only". For the org
  scope tenant that reads backwards. Split the counters, or word it for both.
* (c) `docs/admin/README.md` "Audit actions of the network write gate" lists five
  actions. It omits `network_role.permission_revoked_by_reconcile` (W4.2, system actor),
  and says `network_role.assigned` is written for an assignment "to a user, service
  account or group". A network role on a group is refused (rule 2), so that row never
  names a group.
* (d) `repository/network.rs:96-98` (W4.6): "The `axiam:` prefix keeps the marker from
  colliding with any text a user can put in a field the transaction echoes." It does not.
  `refusal_of` (`:119-145`) matches by `contains` over the whole error text, and a
  uniqueness-index error echoes the clashing value (a segment name an administrator
  chose). A name containing `axiam:network_segment_version_stale` turns a
  `duplicate_name` into `stale_version`. The impact is a misleading `reason_code` to the
  administrator who chose the name. Say what the prefix does (namespacing), or match the
  `THROW` form exactly.
* (e) T-457's 2026-10-19 amendment and `network_decide.rs`'s module doc list the
  residuals without (f), the global read's hit-versus-miss difference (§7).
* (f) `certificate_binding.bound` (REST `network_gate.rs:424-434`) records the account
  bound but not the account a re-bind took the certificate from, though the gate reads it
  (`bound_service_account`, gate `:2081`) and the refusal row records it as `before`. The
  plan row also asked for "the node". The gate checks `network:grant` at every node of
  the account's join allows, and the success row names none of them.
* (g) `docs/admin/README.md` and T-484 say the assignment row's node is `none` "for the
  tenant". The gate decides a tenant-wide assignment, and every assignment of a global
  role, at `/network` (`assignment_node`), so the row's `node` is not the node the right
  was checked at.

---

## 9. Every commit message against the code

### 9.1 W4.1 `9e1108a43` (#704)

Confirmed: the runner, the warn, the removed `MigrationRecord`, the contiguity test with
N from the list, the schema test, the comment fix in `certificate_repository_test.rs`.
**Rejected:** "Every migration is idempotent DDL, so a late application is safe"
(R111W4-05). Plan vs tree (the 86 … 89 hole): confirmed.

### 9.2 W4.2 `912742f84` (#702)

Confirmed: `super_admin_may_hold` takes the tenant's kind and fails closed;
`seed_default_roles` and the reconcile use it; one audit row per network revocation,
system actor, non-fatal; the doc comments; T-483 → Mitigated in both copies; the three
tests (green, §11). Engine unchanged, doc only: confirmed (`engine.rs:155-172`, applying
only global grants across tenants). The fail-closed choice is right in the seeder and
destructive in the reconcile (R111W4-04). The `withheld` path for a group-held
super-admin was correct at this commit and was broken by W4.5 (R111W4-01).

### 9.3 W4.3 `27aa45778` (#703)

Confirmed: `record_cleared` and its call sites (§4.1); the five constants beside the
refusal actions; `revoked_effect`; logged-and-stands on failure; T-484 → Mitigated in both
copies; `docs/admin/README.md`; the two tests (green, §11). "certificate_bind always clears
network-sensitive": confirmed (`plain(true)` at `:2150`). The row can be lost by
cancellation or a concurrent delete (R111W4-02). The delete is not covered (R111W4-03).
The row's content gaps are R111W4-06 (f), (g).

### 9.4 W4.4 `bbf0a6483` (#706)

Confirmed: the selection, the discarded decoy, no early return, the module doc, the
structural unit test (fails against the old selection), the timing figures (the timing
test cannot discriminate and is not claimed as the oracle). "No doc comment that reaches
`sdks/openapi.json` changed": confirmed, and `check-spec-digest.py` passes. The executor's
residual list (a) … (f): confirmed; none Medium (§7). (f) is missing from the threat-model
text (R111W4-06 (e)).

### 9.5 W4.5 `bb670002f` (#708)

Confirmed: the typed enum and its `Display`; the single mapping; the substring matching
deleted; `name_the_stranded_profile` filling the typed variant; the db unit test; the pin
`every_network_409_carries_its_reason_code` green. "Wire `error`, `reason_code` and
`message` are unchanged": confirmed for the REST routes (§5). **Not said by the commit,
and the defect of the wave:** the change of `network_role_raced` reaches the seeder's
`Conflict` match (R111W4-01).

### 9.6 W4.6 `d6a69bbe6` (#709)

Confirmed: `canWrite = profiles_write && grant` (`ReplyProfileDialog.tsx:94-99`), the
tests, the marker renamed. The console stays a hint; the server decides per node (H1, H2
at `seg.id`). The comment's claim about the prefix is R111W4-06 (d).

### 9.7 W4.7 `b8ce6ca58` (#715 a, d, e)

Confirmed: (a) `radius_reply.rs` and the spec say `400`, matching the gate's
`3.3:admin-class` refusal; (d) T-481 restated in both copies, status Open; (e) the pin is
the signature and first statement of `ErasureUnit::prepare`, and the synthetic second
`prepare` is flagged. **Merge check:** the pinned text is unchanged on
`origin/claude/release-1.1.1-w1` and `-w3` (`cleanup.rs:2528-2529` and `:1990-1991`
there), so `every_exemption_still_names_a_real_ungated_site` survives both merges as the
branches stand. The pin covers only the prefix: a new ungated write *inside*
`ErasureUnit::prepare` would still be exempt, as it was before. That is noted, not filed.

### 9.8 The plan's §10 rules

Signed commits: 7 of 7. Every code change carries its test. The threat-model edits are
dated corrections in the entries' own text, and both copies agree (§10). No schema
change. `sdks/CONTRACT.md` untouched. No `[lints]` key added. No crate added. The
profile names: W4 writes no D3/D4 text of its own (W5.1's rename is merged later by the
orchestrator). One §10 rule was not met in substance: "the touched test binaries" was
read per file, and W4.5's change of an error type touched the seeder's behaviour without
touching the file (R111W4-01).

---

## 10. Threat-model text against the code

| Entry | Text | Code | Verdict |
|---|---|---|---|
| T-457 (amended 2026-10-19) | decoy when no row of the caller's tenant; residuals: own-tenant early refusals, unparsable PEM, engine short-circuit | §7 | Accurate; omits (f) (R111W4-06 (e)) |
| T-481 (restated 2026-10-19) | the segment, profile and cap transactions re-check the row, not the writer's rights; Open | gate and `repository/network.rs` | Accurate |
| T-483 (Mitigated 2026-10-19) | seeder withholds; reconcile revokes with one row each; the unresolved tenant fails closed | `seeder.rs` | Accurate; does not say that "fails closed" in the reconcile means revoking from an ordinary tenant (R111W4-04) |
| T-484 (Mitigated 2026-10-19) | one row after a cleared assign/unassign/grant/revoke/bind; failed append logged; role update or delete leaves none | REST `network_gate.rs` | Accurate as written. Mitigated overstates while the delete of a deny role (R111W4-03) and a cut connection (R111W4-02) leave no row |

**The two copies agree.** Every sentence the wave added to
`claude_dev/threat-model-stride.md` appears verbatim in
`ThreatDragonModels/Axiam/Axiam.json`, compared by script on the normalised text (47
sentences over five paragraphs, none missing). The JSON's status changes are exactly two,
T-483 and T-484, Open → Mitigated, matching the register rows. The model version and the
website copy were not bumped, as the commits say; that is W8.3's.

---

## 11. Checks run

Environment: `protobuf-compiler` installed, `SWAGGER_UI_DOWNLOAD_URL` set from
`scripts/make-swagger-ui-placeholder.sh`, `CARGO_INCREMENTAL=0`. The first pass ran with
line-tables-only debug information and filled the sandbox's ~39 GB disk at link time
inside `axiam-db`'s test binaries, so every result after `axiam-authz` in that pass was
void and is not reported. The second pass ran from an empty `target/`, without debug
information (`CARGO_PROFILE_{DEV,TEST}_DEBUG=0`, `…_STRIP=debuginfo`), **one test binary
at a time, each deleted after it ran**. Each line below is the tool's own exit code,
captured from `cargo`, not from a pipe.

| Check | Exit | Result |
|---|---|---|
| `cargo test -p axiam-core` (lib, every test binary, doc) | 0 | 549 passed |
| `cargo test -p axiam-authz` (lib, every test binary, doc) | 0 | 204 passed |
| `cargo test -p axiam-db --lib` | 0 | 318 passed |
| `cargo test -p axiam-db --test <each of 84>` | 0 × 83, **101 × 1** | 778 passed, 5 ignored; **`seeder_default_data_test`: 18 passed, 1 failed** (`reconcile_withholds_network_grants_from_a_group_held_super_admin`, R111W4-01) |
| `cargo test -p axiam-db --doc` | 0 | |
| `cargo test -p axiam-api-rest --no-default-features --lib` | 0 | 302 passed (W4.4's `every_path_verifies_one_certificate_and_every_refusal_the_callers` among them) |
| `cargo test -p axiam-api-rest --no-default-features --test <each of 111>` | 0 × 110, 101 × 1 | 1 620 passed, 3 ignored; `network_gate_test` 18, `network_routes_test` 33 (`every_network_409_carries_its_reason_code`), `network_decide_test` 12, `network_gate_enumeration_test` 5 — all green. `federation_test`: 69 passed, 15 failed, see below |
| `cargo test -p axiam-server --no-default-features --lib`, `--bins` | 0, 0 | 153 passed |
| `cargo test -p axiam-server --no-default-features --test` `cleanup_task`, `minimal_profile_boot`, `device_grant_boot_warning`, `healthcheck`, `server_leaf_profile`, `req14_gdpr_test`, `radius_e2e`, `notification_window_test` | 0 each | 40, 11, 3, 9, 6, 5, 2, 4 passed |
| `cargo clippy -p axiam-core --lib --tests -- -D warnings` | 0 | |
| `cargo clippy -p axiam-authz --lib --tests -- -D warnings` | 0 | |
| `cargo clippy -p axiam-db --lib --tests -- -D warnings` | 0 | |
| `cargo clippy -p axiam-api-rest --no-default-features --lib --tests -- -D warnings` | 0 | |
| `cargo clippy -p axiam-server --no-default-features --lib --tests -- -D warnings` | 0 | |
| `npm ci` / `tsc -b` / `npm run lint` (oxlint) in `frontend/` | 0 / 0 / 0 | |
| `vitest run --coverage` in `frontend/` | 0 | 122 files, 2 386 tests; lines 96.58 % (threshold 96.1) |
| `python3 scripts/check-crate-layering.py` | 0 | 19 crates, 62 edges inward |
| `python3 scripts/check-remediation-evidence.py` | 0 | 5 verified, 0 failed, 32 skipped (no egress) |
| `python3 scripts/check-spec-digest.py` | 0 | digest matches |
| `python3 scripts/check-frontend-coverage.py` | 0 | 53 handler modules recorded |
| `bash scripts/check-doc-links.sh` | 0 | 534 links in 78 files |

**`federation_test` under `--no-default-features`.** The 15 failures are every SAML
route test that is not `#[cfg(feature = "saml")]`-gated (`saml_acs_*`,
`saml_login_public_*`, `saml_metadata_*`, `saml_authn_request_*`), each answering `404`
because the SAML routes are compiled out. The sandbox has no libxml2 headers, so the
binary cannot be run with the feature on here. CI runs it with default features (only
`oidc_conformance` and `oauth2_conformance` run SAML-off, `ci.yml:256`), and the wave
touches no SAML or federation file. **Not a wave regression, and not a finding of this
review**: the ungated tests are pre-existing, and a sandbox artefact of the brief's
`--no-default-features`.

**Incident during the run.** The first pass's `ENOSPC` truncated one extracted crate in
the cargo registry (`actix-utils 3.0.2`), so the second pass's REST and server steps
first failed in the download step, with no test run. The truncated copy was removed, the
registry cache checked with `gzip -t`, and those steps were run again. The figures above
are from that third run.

---

## 12. Notes for W7.1, W8.3 and W8.4

* **W7.1 (contract §36.11 rule 5).** The decision route now verifies one certificate on
  every path but a stored PEM of the caller's tenant that does not parse. When no row of
  the caller's tenant resolves (unknown, or another tenant's, in either form), it
  verifies the caller's own. What remains cheaper or dearer: `authenticate_der`'s early
  refusals for a row of the caller's own tenant (revoked, expired, not active, a server
  or SAML-signing certificate); the engine's answer for a subject with no role
  assignment; and the global fingerprint read itself, which returns a row for another
  tenant's certificate and none for an unknown one. "The same reads" stays true;
  "the same cost" is true to within that one read.
* **W8.3 (threat model).** T-457: add (f). T-483: say that the reconcile revokes from a
  tenant it cannot resolve (or, after R111W4-04's fix, skips it). T-484: either cover the
  role delete (R111W4-03) or keep it Mitigated with the delete and the cancellation named
  as residuals. Then the model version, the counts and `website/src/threatModel.ts`.
* **W8.4 (CHANGELOG).**
  * The upgrade note: the organization scope's super-admin loses the six network
    permissions at the first boot, with one `network_role.permission_revoked_by_reconcile`
    row each. Network administration is an ordinary tenant's super-admin's.
  * The five new success actions, and that a role delete has none.
  * The runner applying an unrecorded lower version with a `warn` (#704).
  * The console gating the profile editor on `network:grant` (#709).
  * #708 has no wire change.
  * R111W4-01's fix is part of #708's entry, not a separate line.
* **Merge.**
  * W2.8 (#682, reserved audit actions and lookalikes) has not landed on its branch.
    When it does, its reserved set must include the six actions this wave adds
    (`network_role.assigned`, `.unassigned`, `.granted`, `.revoked`,
    `certificate_binding.bound`, `network_role.permission_revoked_by_reconcile`).
  * W1 and W3 keep the `ErasureUnit::prepare` pin intact (§9.7).
  * W1's v108 and W3's v109 are additive and pass `migrations_are_contiguous` in either
    merge order.

---

## 13. Issues filed

Low and Informational findings, on milestone `1.1.x`. The Medium is not filed: it is
for a fix inside the wave (§2.3).

| ID | Severity | Issue |
|---|---|---|
| R111W4-01 | Medium | — (fix in wave; proposed fix and test in §2.3) |
| R111W4-02 | Low | #726 |
| R111W4-03 | Low | #727 |
| R111W4-04 | Informational | #728 |
| R111W4-05 | Informational | #729 |
| R111W4-06 | Informational | #730 |


## 14. Invariants

* **Nothing registered before the wave changes behaviour, except as the wave says.**
  * The organization scope's super-admin loses six permissions.
  * Five success rows (plus one per reconcile revocation) are written.
  * A lower unrecorded migration is applied.
  * The decision route verifies the caller's certificate where it verified none or
    another tenant's.
  * The console hides the profile editor from a holder of `network:profiles_write`
    without `network:grant`.
  * The exception is R111W4-01, which the wave did not intend.
* **Schema.** No migration added. The runner changed (§6).
* **Contract and spec.** `sdks/CONTRACT.md` untouched. `sdks/openapi.json` unchanged,
  digest verified.
* **This review.** It changed no file but itself. No probe was added to the tree. The
  frontend's `node_modules/` and `coverage/` and the Rust `target/` were removed after
  the run, and `git status` was clean before the commit.
