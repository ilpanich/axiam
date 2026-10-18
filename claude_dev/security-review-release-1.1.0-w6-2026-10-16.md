# Security review — release 1.1.0, wave W6 (F4)

**Date:** 2026-10-16.
**Against:** `claude/release-1.1.0-w6`, the whole wave diff `3d011573e..326a8072d`
(11 commits, 92 files, 25 929 lines added and 351 removed). Every commit carries a
signature (`gpgsig` header in 11 of 11; the sandbox has no
`gpg.ssh.allowedSignersFile`, so `%G?` cannot verify them here).
**Scope:** every W6 task of the release-1.1.0 plan (§7), RADIUS D4 (#563):

* W6.1 `ef3f1ed0d`: the segment and reply-profile data model, schema v100.
* W6.2 `e9766ce35`: the network write gate and the §5.3 assignment and binding bounds.
* W6.3 `d741349b3`: the segment and profile management routes, their limiter, audit
  and veto hooks.
* W6.4 `fae9d87a5`: `POST /api/v1/network/decide`.
* W6.3b `f479c6530` + `2b0f0cc1c`: the tenant `Session-Timeout` cap route, written with
  `network:segments_write` at the root.
* W6.5 `e4dca2686`: the `rlm_rest` recipe and its end-to-end.
* W6.6 `acda86038`: contract §36 and the threat entries.
* `70c8039cf`: the network/radius schema names; the spec lists only `framed_user`.
* W6.8 `e4f8c4740` + `326a8072d`: the console's Network access section and the two
  OAuth2 client touches.

**Method:** the plan says this review "reads §5.2 H1–H6 and §5.3 against the code
line by line", and §3 and §4 do exactly that, row by row, against
`crates/axiam-authz/src/network_gate.rs` and every caller. Every commit message was
read in full and its claims are answered below. The enumeration test was read as an
attacker would read it: for a write path it does not see, not for the ones it does
(§4). The decision route was read against the note's §4.3, §6.3, §7 and §8 and
T-457/T-463/T-464/T-468 (§7). The recipe was read for injection, trust and failure
behaviour (§10). Two claims were settled by probe — a temporary test appended to
`network_gate_test.rs`, run, and removed (§2, R110W6-02): both confirmed what the
reading said. The OpenAPI document was rebuilt from the branch and compared byte for
byte (§11). The wave's own tests and CI's lints were run (§17). This review fixes
nothing. Every finding has its evidence, a proposed fix and a test; the Medium one is
proposed for a fix inside the wave, the rest have issue bodies (§18). IDs:
`R110W6-nn`.

---

## 0. Summary

**One Medium, eight Low and four Informational.**

The wave builds what the note designs, with tests that exercise it. H1–H6 are code,
the §5.3 table is code, the reserved namespace and subtree are closed on every REST
surface that could reach them (the generic resource routes and the UMA Protection
API included, which the plan did not name), and the clearance token makes a
segment, profile or cap write without the gate a compile error. The decision route
authenticates its caller properly (a token bound to the certificate of *this*
connection, re-resolved through `authenticate_der` on every request), answers no
reason, writes one row per decision with no subject and no personal data, renders
only the dictionary and fails closed on a stored profile that no longer validates.
The recipe copies nothing because AXIAM named it, verifies AXIAM's certificate, and
refuses on every failure. Two things need action before the wave merges — one
residual the wave itself entered, and one red CI gate:

* **R110W6-01 (Medium, wave — W6.2; T-482).** H6 — "a device does not configure its
  own access, whatever it holds" — is applied to profile writes, segment writes and
  binding, but not to the §5.3 doors that change **the writer's own** placement. A
  service account holding `roles:assign` and `network:grant` at a node (the role
  routes admit a machine token: `roles` is an M2M family) **assigns itself `network:join`** there,
  and — the half T-482 does not name — once quarantined **releases its own
  quarantine** by unassigning the deny. Both confirmed on the real routes (§2). The
  second defeats the property the note's §4.4 buys with deny-override. The fix is a
  handful of lines in the gate.
* **R110W6-13 (Low, CI — fix in wave).** `scripts/check-frontend-coverage.py` exits 1:
  `handlers/network.rs` and `handlers/network_decide.rs` have no row in
  `claude_dev/frontend-coverage-matrix.md`. `docs-ci.yml` runs it on any PR touching
  `docs/**` or `openapi.rs`, which the release PR does, so the check is red until two
  rows are added. Not a security defect; mechanical, and it blocks the merge.

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R110W6-01** | H6 is not applied to the §5.3 writes that change the writer's own placement: a service account with `network:grant` assigns itself a join and releases its own quarantine (also by grant, revoke and role delete). | **Medium** | `network_gate.rs:1275-1347, 1349-1387, 1420-1445, 1449-1558, 1560-1604` → T-482, T-479, note §4.4 | wave (W6.2) | **Fix in wave** |
| R110W6-02 | An administrative `Service-Type` in a profile is answered `403` naming `network:grant_admin` — a permission nobody can hold — where contract §36.2 / §36.3 rule 5 and T-478 say `400`, "refused outright". | Low | `network_gate.rs:1054-1063`; `CONTRACT.md:12820, 12886` → T-478 | wave (W6.2, W6.6) | Reported |
| R110W6-03 | `network:segments_write` alone re-places every device already joinable on a profiled segment: its VLAN, rank and `enabled` change without `network:grant` (and the quarantine segment's VLAN without H5). The note's §3.1 says the opposite. | Low | `network_gate.rs:1178-1225`; note §3.1, §4.2, §5.2 H3 → T-478 | design (D5) / wave | Reported (maintainer) |
| R110W6-04 | T-481 — the gate's reads and the write are not one transaction. Confirmed Low; one more interleaving: a grant of `network:join` to a role racing that role's assignment to a group leaves a network role on a group, after which group membership confers the join. | Low | `network_gate.rs:1529-1535` vs `:1285-1288` → T-481 | wave (W6.2) | Reported |
| R110W6-05 | T-483 — the organization scope tenant's global super-admin carries the network meta permissions (`network:decide` included) into every tenant. Confirmed Low. | Low | `models/network.rs:798`; `seeder.rs:515`; `engine.rs:161-169` → T-483 | wave (W6.2) | Reported |
| R110W6-06 | T-484 — a cleared network-sensitive assignment, grant or bind leaves only the generic request row. Confirmed Low. | Low | `network_gate.rs` (REST side) `authorize_as` → T-484 | wave (W6.2) | Reported |
| R110W6-07 | v100 lands with no v99 on this branch, and the runner applies only versions above the highest recorded: a datastore that ever ran a build with v100 and without v99 skips v99 forever. | Low | `schema.rs:2487-2490` | wave (W6.1) × W1 | Reported (merge rule) |
| R110W6-08 | Pre-existing, found by W6.2: the UMA Protection API's update and delete check only the tenant, so any resource server's PAT renames, retypes, re-scopes or deletes any resource of the tenant, not just the sets it registered. W6.2 closed the reserved subtree; the rest is open. | Low | `uma.rs:396-450, 461-485` (list filters by owner at `:516`) | pre-existing | Reported |
| R110W6-09 | T-457's two cheaper paths are real and documented; one is a **cross-tenant** existence signal (an unknown fingerprint skips `authenticate_der`, another tenant's does not), and contract §36.11 rule 5 claims "the same reads" outright. A decoy verification closes the first. | Informational | `network_decide.rs:404-426`; `CONTRACT.md:13040-13041` → T-457 | wave (W6.4, W6.6) | Reported |
| R110W6-10 | The recipe's token cache is not dropped on a `401` from the decision: after the FreeRADIUS certificate is revoked and re-issued, or AXIAM's signing key rotates, every device is refused for up to half the token's life. Fail closed; availability only. | Informational | `check-eap-tls:56-104`; `axiam_d4:100-109` → T-486 | wave (W6.5) | Reported |
| R110W6-11 | The hook keys the fingerprint on the serial "because AXIAM derives it from the key" (`freeradius.md:581`): true on this branch, false after W1.9 (#653, random serials), and on this branch two certificates over one key share a stash. Sound either way for the reason serials are unique per issuer after #653. | Informational | `axiam-d4.sh:13-17`; `freeradius.md:575-586` | wave (W6.5) × W1 | Reported (merge) |
| R110W6-12 | Stale or overclaiming text the wave left: the note's header ("nothing is built"), §3.1; contract §36.3 rule 6's rationale for the clamped store; T-478's "refused outright"; `freeradius.md`'s "claims no mitigation the model does not yet state"; the 190 / 28 counts elsewhere. | Informational | §14 | wave | Reported (W7.1 / W8.3) |
| R110W6-13 | The frontend coverage matrix has no row for `handlers/network.rs` or `handlers/network_decide.rs`; `check-frontend-coverage.py` exits 1, so `docs-ci.yml`'s gate is red on the release PR. | Low | `claude_dev/frontend-coverage-matrix.md`; `.github/workflows/docs-ci.yml:96-102` | wave (W6.3, W6.4, W6.8) | **Fix in wave** (CI gate) |

The brief's points that are **not** findings, each argued in its section: the
enumeration test sees every production write path that exists today — no raw
SurrealQL outside repositories bar the exempt bootstrap, no SCIM, directory, gRPC,
AMQP or seeder path around it (§4); the clearance token cannot be forged, copied or
deserialised (§4); the decision route's `cnf` binding is checked against the
connection's own certificate and the machine exception reaches no other route (§7.1);
the reply rendering cannot emit anything outside the dictionary and its tag encoding
is what FreeRADIUS puts on the wire (§7.8); the recipe has no shell or attribute
injection and verifies AXIAM's certificate (§10); the OpenAPI document is
byte-identical to a fresh build and the registry is 202 / 29 (§11); the console
gates nothing the server does not and never calls `/decide` (§12); the threat-model
copies agree, 487 / 453 / 24 / 10 (§13).

---

## 1. What was reviewed, and how

| Point of the brief | Where answered |
|---|---|
| 1. H1–H6 and §5.3 line by line; the enumeration test's completeness; the clearance token; the seeded super-admin and the reconcile | §3, §4, §5 |
| 2. T-481 … T-484: Medium or not; T-482 an escalation that defeats H6? | §2 (T-482: yes, Medium), §6 (T-481, T-483, T-484: Low) |
| 3. The decision oracle | §7 |
| 4. The management routes (W6.3, W6.3b) | §8 |
| 5. v100 and the v99 gap | §9 |
| 6. The `rlm_rest` recipe | §10 |
| 7. Contract §36 against the code; the spec; the registry | §11 |
| 8. The console | §12 |
| 9. CI parity | §17 |
| 10. Threat-model text against the code; both copies; the totals | §13 |
| The two contract follow-ups (a), (b) | §15 |
| Merge risks | §16 |

---

## 2. R110W6-01 — H6 stops at the writer's own assignments (T-482, and more)

**What H6 says.** The note's §5.2: "`W ≠` a subject that is itself
`network:join`-able on `S` through the same write. A service account that writes its
own segment's profile is a device configuring its own access. **Refused, whatever it
holds.** The same holds for binding (§5.3): a subject may not bind a certificate to
itself." The rule is about *self*-configuration, not about how much the writer holds;
that is why it says "whatever it holds".

**What the gate does.** H6 is applied at three places: the profile write
(`network_gate.rs:1078-1087`), the segment update (`:1212-1221`) and the bind
(`:1691-1701`). Of these, the first two are reachable only by people — the `network`
family is human-only, so a service account never reaches them — and a person is not a
device until D6. The one H6 a machine can meet is the bind. The §5.3 writes that
change who may join — `role_assign` (`:1275-1347`), `role_unassign` (`:1349-1387`),
`role_delete` (`:1420-1445`), `permission_grant` (`:1449-1558`) and
`permission_revoke` (`:1560-1604`) — never compare the grantee or the role's holders
with the writer. And these are the doors a machine *does* reach: `roles`,
`permissions` and `certificates` are `M2M_MANAGEMENT_FAMILIES`
(`permissions.rs:396-405`).

**Probe (run on the branch, removed).** A tenant with the seeded roles and one access
segment `/network/zones/hq/iot`; roles `devices` (`network:join` allow),
`net-granter` (`network:grant` allow), `network-quarantined` (`network:join` deny). A
service account holding the seeded `admin` (which carries `roles:assign`) and
`net-granter` at `/network/zones` — an enrolment agent, the use the M2M role routes
exist for:

```
PROBE self-assign join: 204 null                 POST /roles/{devices}/service-accounts {self, iot}
PROBE joins after: allowed
PROBE joins quarantined: denied_by_rule           (a network administrator quarantines it at /network/zones)
PROBE self-release: 204 null                      DELETE /roles/{quarantined}/service-accounts/{self}?resource_id={zones}
PROBE joins after release: allowed
```

**Why it is Medium and not "bounded by delegation".** T-482 argues the account
"was already trusted to confer that join on any other account". That is the
delegation bound, and it holds; H6 is a different rule, and it exists for exactly the
case where the delegation bound is satisfied. Two concrete consequences:

* **A device places itself.** An account that authenticates by a certificate bound to
  it (the device path, `POST /api/v1/auth/device`) and holds `network:grant`
  somewhere — an enrolment gateway, a provisioning agent running on a device — gives
  its own certificate a placement with one call. Without self-assignment the same
  account needs `certificates:generate` and `certificates:bind` as well, to place a
  device it controls through *another* account: the bind's H6 exists to close exactly
  that shortcut, and the assignment door re-opens it.
* **A quarantine releases itself.** §4.4's whole argument is that "no administrator
  who can grant `network:join` somewhere in `zones` can release a device by granting
  more"; release is the removal of the deny and takes `network:grant` at its node. A
  quarantined device whose own account holds `network:grant` at that node removes its
  own deny. The quarantine is the response to a device believed compromised; the
  compromised credential is what lifts it. Three more doors are open to an account
  holding `network:grant` at `/network` and the route permissions: it releases itself
  by revoking the deny from the quarantine role it holds (`permission_revoke`) or by
  deleting that role (`role_delete`), and it places itself by granting
  `network:join` to a role it holds (`permission_grant`). Read, not probed: the same
  missing comparison, in the same function shape.

The preconditions are real but ordinary (a machine account trusted to enrol devices),
the effect is the escalation T-461/T-478 exist to prevent, the design states the rule
in absolute terms, and the fix is small. Medium; fix in the wave.

**Fix (for the fixer).** In `crates/axiam-authz/src/network_gate.rs`, one helper and
five checks, each a `RefusalStatus::Forbidden` refusal with rule `"H6"` and the
existing audit action of its write (the REST side then audits it as every refusal):

1. `fn is_writer(&self, id: Uuid) -> bool { id == self.writer.subject_id }`, and a
   `writer_holds_role(holders: &RoleHolders) -> bool` over `users` and
   `service_accounts` (groups cannot hold a network role, rule 2).
2. `role_assign`, after rule 3 and before the §5.3 check: if `grants.join_allow` and
   the grantee (`User`/`ServiceAccount`) is the writer → refuse, "a subject cannot
   confer network:join on itself" (`AUDIT_ROLE_ASSIGN_REFUSED`). Self-assigning a
   deny narrows and stays allowed; self-assigning meta permissions confers nothing the
   §5.3 check does not already demand the writer hold.
3. `role_unassign`: if `grants.any_deny` and the grantee is the writer → refuse,
   "a subject cannot release its own network deny" (`AUDIT_ROLE_UNASSIGN_REFUSED`).
4. `role_delete`: if `grants.any_deny` and the writer holds the role (read
   `role_holders`) → refuse (`AUDIT_ROLE_WRITE_REFUSED`).
5. `permission_grant`: if `effect == Allow` and the action is `network:join` and the
   writer holds the role (the `holders` the function already reads at `:1529`) →
   refuse (`AUDIT_ROLE_GRANT_REFUSED`).
6. `permission_revoke`: if the role's current grant of this permission is a deny
   (read `role_grants`, as the refusal branch already does) and the writer holds the
   role → refuse.

Make it subject-agnostic (a user writer is refused too): D6 makes users devices, and
the rule then needs no revisiting. Update the design note's §5.3 table with the row
("any of the above whose grantee, or one of whose role's holders, is the writer: H6,
refused whatever it holds"), dated as a correction (R110W6-01).

**Tests.**
* `network_gate_test.rs::a_service_account_cannot_place_itself_or_release_its_own_quarantine`
  — the probe above as assertions: the self-assignment is `403`, writes nothing and
  leaves one `network_role.assign_refused` row with rule `H6`; the same account
  assigning the join to **another** account is `204`; the self-release is `403` with a
  `network_role.unassign_refused` row; a network administrator's release of the same
  deny is `204`.
* Gate unit tests (`network_gate/tests.rs`): `h6_a_subject_cannot_assign_itself_a_join`,
  `h6_a_subject_cannot_release_its_own_deny`,
  `h6_a_join_grant_to_a_role_the_writer_holds_is_refused`,
  `h6_revoking_a_deny_from_a_role_the_writer_holds_is_refused`,
  `h6_deleting_a_deny_role_the_writer_holds_is_refused`, each with its positive twin
  (another grantee or holder: cleared).
* Threat model: T-482 Open → Mitigated with those tests, in its own text and dated;
  its title widened to "assigns itself `network:join` or releases its own quarantine";
  T-479's residual list drops it; totals 487 / 454 / 23 / 10, both copies and the
  website regenerated.

---

## 3. H1–H6 and §5.3, line by line

All references are to `crates/axiam-authz/src/network_gate.rs` unless named. "Holds"
is `subject_holds` (`:928-948`): the engine's `check_access_uncached`
(`engine.rs:496-501`, the production `AuthzChecker` overrides the default at
`authz.rs:173-178`), deny-override in force, the writer's own subject scope
(`GateActor::principal`, REST `network_gate.rs:49-60`).

### 3.1 §5.2 — the profile write (`profile_write`, `:1009-1092`; delete `:1094-1113`)

| Rule (note §5.2) | Code | Verdict |
|---|---|---|
| **H1** `network:profiles_write` on `S` | `:1025-1029`, node `seg.id` | Holds |
| **H2** `network:grant` on `S` | same loop | Holds |
| **H3** `filter_id ∈ S.filter_ids` | `:1034-1043`, a `403` with rule `H3:envelope:filter_id`; repeated in the repository inside the write's transaction (claim of the segment's version, `repository/network.rs:934-940`) and at every render (`models/network.rs` `revalidate`) | Holds |
| **H3** `session_timeout_secs ≤` the cap | `:1044-1052`; the repository's `validate` again; the cap re-read at every render and clamped | Holds. A concurrent cap *lowering* between the check and the write stores a value above the new cap; reads clamp it, which only narrows |
| **H3** the VLAN derived, never chosen | `ReplyProfileInput` has no VLAN member and is `deny_unknown_fields` (`radius_reply.rs:340-364`) | Holds. But see R110W6-03: the *segment* writer chooses it |
| **H4** admin class needs `grant_admin` and `admin` | `:1054-1063` | Holds as written; vacuous under option B, and answers `403` where the contract says `400` (R110W6-02) |
| **H5** kind unchanged; a quarantine segment's profile also needs `network:grant` on `/network/quarantine/<site>` | the input has no kind; `:1065-1076` | Holds |
| **H6** the writer may not join `S` | `:1078-1087` | Holds — for a human writer, the only one these routes admit |
| Delete: H1 only | `:1094-1113` | Holds |

The 403 names the missing permission and node (`require_all`, `:963-986`, mapped to
`AuthorizationDenied { action, resource_id }` at REST `network_gate.rs:196-210`). The
internal rule stays in the audit row. As designed.

### 3.2 §5.2 — the segment writes (`:1117-1245`) and the cap (`:1249-1271`)

| Rule | Code | Verdict |
|---|---|---|
| create: `segments_write` at the parent | `:1147-1172` climbs to the nearest existing of site, branch, root | Holds |
| update / delete: at the node | `:1201-1211`, `:1229-1241` | Holds |
| H6 on the envelope (the wave's addition) | `:1212-1221` | Holds |
| kind and place immutable | `NetworkSegmentUpdate` has neither; no move variant exists | Holds |
| stranding is `409` naming the profile | repository `update_tx` (`repository/network.rs:378-386`) in the transaction; the handler names it (`handlers/network.rs` `name_the_stranded_profile`) | Holds |
| the cap: `segments_write` at the root only | `:1249-1271`, node `self.root()` | Holds; deny-override tested (`network_routes_test::a_deny_of_segments_write_at_the_root_refuses_the_cap`) |

### 3.3 §5.3 — the assignment, grant and binding rows

| Row (note §5.3) | Code | Verdict |
|---|---|---|
| assign a join **allow** at `N` (no resource: `N = /network`) | `role_assign` `:1332-1345`; `assignment_node` `:991-997` (global role or no resource → root) | Holds |
| assign a join **deny** at `N` | same (`join_deny` pushes `network:grant`) | Holds |
| **unassign** a deny | `role_unassign` `:1364-1385`, at the unassigned edge's own node (the repository deletes only the edge with that exact `resource_id`, `repository/role.rs:358-374`) | Holds — but not against the writer itself (R110W6-01) |
| assign meta permissions: hold every one at `N` | `NetworkGrants::delegated` `:778-783`, `:1338-1342` | Holds |
| `permissions:grant`/`revoke` of a `network:` permission | `permission_grant` `:1544-1556` (`network:grant` at root plus the meta action granted); `permission_revoke` `:1573-1602` | Holds — not against the writer (R110W6-01) |
| `roles:delete` of a role carrying a deny | `:1430-1443`, at the root | Holds — not against the writer (R110W6-01) |
| **bind** to an account with join allows: `network:grant` at every such node, read with the engine (a beaten allow asks nothing) | `certificate_bind` `:1703-1746`; the "beaten" test is `subject_holds(account, JOIN, node)` | Holds. Sound only because of rule 3 (a network deny is never `inherit: false`), which the code states and enforces from both sides (`:1323-1330`, `:1536-1541`) |
| bind: H6 | `:1691-1701` | Holds |
| any other path that binds at issuance | none exists: the only caller of `bind_to_service_account` is the bind handler (`certificates.rs:617`) | Holds |

§4.2's three rules: rule 1 at `:1403-1416` and `:1523-1528`; rule 2 at `:1313-1320`
and `:1530-1535`; rule 3 at `:1323-1330` and `:1536-1541`. The wave's additions — a
scoped `network:` grant is `400` (`:1514-1522`), `network:admin`/`grant_admin` allows
are `400` (`:1508-1513`), no `network:` permission is renamed or deleted
(`:1622-1668`) — are each right: a scoped deny would match only scoped checks and the
placement check is unscoped, and renaming `network:join` would release every
quarantine at once.

**One subtlety checked and found sound.** The unassign gate keys on the node the
caller names (`query.resource_id`). A caller cannot name one node to the gate and
delete another, because the repository deletes exactly the edge whose `resource_id`
equals the one named (`repository/role.rs:358`) and `has_role` is `UNIQUE(in, out)`
(`relate_subject_to_role` classifies a second assignment as a `409`, it does not move
the first), so "re-assign the deny somewhere harmless" is not a release either.

---

## 4. The enumeration test, the clearance token, and every other writer

**What the scan sees** (`tests/network_gate_enumeration_test.rs:40-89`): the
assignment, unassignment, grant, revoke and bind repository methods by name; role
update/delete; permission and resource writes (`permission_repo`, `perm_repo`,
`resource_repo`, UMA's `create_uma_registered`); the six segment/profile writes and
the cap; and the raw `->has_role->`, `->grants->`, `->cert_bound_to->` edges in
whitespace-free source. It ignores `crates/axiam-db/src/repository/` (the
implementations) and every `tests/` directory.

**What could reach the writes without it, checked one by one.**

| Path | Finding |
|---|---|
| Raw SurrealQL outside repositories | `grep` for `RELATE`, `DELETE grants`, `UPDATE grants`, `has_role`, `cert_bound_to` over `crates/*/src`: the one statement outside `axiam-db/src/repository/` is `handlers/bootstrap.rs:596`, in the exempt one-shot bootstrap |
| Repository methods under other names | `role.rs`, `permission.rs`, `certificate.rs`, `resource.rs`, `group.rs`, `service_account.rs` method lists read. Edge writers: `relate_subject_to_role` / `unrelate_subject_from_role` (private, behind the six named methods), `relate_grant` (behind the three grant methods), `bind_to_service_account`. Writers not in the scan: `service_account.delete` (deletes `has_role`, narrows), `group.add_*_member` (rule 2 keeps network roles off groups; see R110W6-04 for the race), `tenant_purge` (narrows) |
| gRPC | `axiam-api-grpc` reads only; its `assign_to_user`/`grant_to_role` calls (`services/authorization.rs:350-355`) are inside `#[cfg(test)]` |
| AMQP | `axiam-amqp` builds an engine and reads only |
| SCIM, directory sync | no role, grant, resource or binding write; group membership only (rule 2) |
| Seeder and reconcile | exempt with reasons; both limited to `SEEDED_SUPER_ADMIN_NETWORK_ACTIONS` (§5) |
| User delete and erasure purge | exempt (a user is not a device; narrows) |
| A service account's re-enable (`service_accounts:update` of `status`) | not a §5.3 write, and the note does not list it; it widens placement for an account that already holds joins and a bound certificate. Pre-existing semantics of `account_may_act`, noted, not a finding |

The scan matches receivers by name (T-480's own residual), and
`the_scan_finds_the_known_write_sites` is what stops a reformat from emptying it. For
the older writes that is the right compromise; the segment, profile and cap writes do
not depend on it.

**The clearance token** (`axiam-core/src/models/network.rs:867-934`). The fields are
private; the constructor is `pub` and `#[doc(hidden)]` because the gate lives in a
higher crate, and `only_the_gate_mints_a_clearance` pins its production callers to
the gate and the definition. The type derives `Debug, PartialEq, Eq` only — no
`Clone`, `Copy`, `Default`, `Serialize` or `Deserialize` — so it can be neither
copied into a second write nor read off the wire. Every write method checks tenant,
actor and target (`check`, `:916-933`). The repositories take it by reference, so one
handler could pass the same clearance to two writes **of the same target**; none does,
and the target binding makes that harmless. Sound.

**Who mints tokens in tests.** `network_repository_test`, `network_gate_test`,
`network_decide_test` mint clearances for setup, as fixtures; production does not.

---

## 5. The seeded super-admin exemption and the boot reconcile

`seed_default_roles` gives `super-admin` everything outside `network:` plus
`SEEDED_SUPER_ADMIN_NETWORK_ACTIONS` (`network:read` and the five meta permissions;
`models/network.rs:798-805`, `seeder.rs:515-525`), `admin` nothing in `network:`.
`reconcile_default_role_grants` takes back what W6.1 granted and grants what is
missing, on the two seeded administrative roles only (`seeder.rs:764-805`), every
tenant. `seeder_default_data_test` pins both. The API refuses a `network:` grant to any
global role, this one included (`:1523-1528`), so only the seeder makes the
exemption.

The exemption is as narrow as its documentation says: no `network:join` (holding
super-admin places no device), no administrative class, and assigning super-admin is
a tenant-wide assignment of meta permissions, so its assigner must hold all of them at
`/network` (the seeded `admin` cannot; `network_gate_test::the_seeded_super_admin_bootstraps_network_administration_and_admin_cannot`).
What it costs is rule 1's second reason — global grants cross tenants for an
organization-level subject (`engine.rs:161-169` keeps exactly `is_global` and
tenant-wide assignments) — which is T-483 (§6.2).

A neighbouring observation: the seeded `admin` holds `roles:delete`, and `role_delete`
gates only a role carrying a deny, so an `admin` can delete the seeded `super-admin`
role and with it the tenant's only bootstrap of network administration. That narrows,
and deleting the seeded super-admin was possible before the wave. Not a finding.

---

## 6. The other three residuals the wave entered

### 6.1 T-481 — the check and the write are not one transaction (R110W6-04): Low

Confirmed as the entry states it. The window is one request's (every check is
uncached), and both orders of a bind and an assignment end in a state §5.3 admits; a
writer losing `network:grant` mid-request is the same class. One interleaving the entry
does not name: `permission_grant` of a `network:join` allow to role `R` reads `R`'s
holders and finds no group (`:1529-1535`) while `role_assign` of `R` to a group reads
`R`'s grants and finds nothing network-sensitive (`:1285-1288`); both land, and `R` is a
network role held by a group. Group membership — `groups:add_member`, SCIM, directory
sync, none gated — then confers the join, which is what rule 2 exists to prevent. It
needs the two writes to interleave within one request's window, and the grant's writer
already holds `network:grant` at `/network`. Low; issue. Closing it: a version on the
role that both the grant and the assignment claim in their transactions (the
two-writer rule), or re-reading `R`'s grants and holders inside each write.

### 6.2 T-483 — the organization's super-admin (R110W6-05): Low

Confirmed. An organization-level super-admin holds the meta permissions at `/network`
in every tenant of its organization. It already holds everything else there through the
same global role (assumption 7: organization principals are trusted across their
tenants), and `network:decide` is useless to it because the decision route takes only a
certificate-bound service account of the tenant. What it departs from is the note's §7
sentence. Low; issue. Closing it costs one condition: `super_admin_may_hold` returns
`false` for `network:` actions in a tenant whose `kind` is `Organization`, and the
reconcile revokes them there; each tenant's own super-admin keeps the bootstrap.

### 6.3 T-484 — no success row of its own (R110W6-06): Low

Confirmed. The generic request row (`axiam-audit` `AuditMiddleware`, wrapping the whole
app) records actor, path and status for every cleared assignment, grant and bind; it
does not say the write was network-sensitive or at which node the join landed.
`GateClearance::is_network_sensitive` already says which writes qualify. Low; issue.

---

## 7. The decision oracle (`handlers/network_decide.rs`)

### 7.1 The caller

* **Extractor** (`:270-318`). `AuthenticatedServiceAccount` (machine audience); then
  `sub_kind == ServiceAccount`; then `cnf.x5t#S256` present (bearer and DPoP-only tokens
  refused); then a `VerifiedClientCert` on **this connection** — set only by
  `axiam-server`'s TLS `on_connect` (`tls.rs:392`), never from a header —
  `check_usable_for_device_auth` (a self-asserted certificate is refused), and its
  SHA-256 equal to the token's `x5t#S256`. The general extractor has already enforced
  the sender constraint (`extractors/auth.rs:742-788`); the restatement is belt and
  braces.
* **Handler** (`certificate_bound_caller`, `:324-347`). `authenticate_der` on the
  connection's certificate, now: it must resolve to the token's `sub` and tenant, and the
  account be `Active`. A revoked FreeRADIUS certificate stops at the next request.
* **The exception.** `CERTIFICATE_BOUND_MACHINE_ROUTES` (`permissions.rs:474-475`) is a
  table that tests read (`m2m_management_test`); nothing at runtime consults it. The
  exception *is* the extractor type of one handler: the other twelve network handlers
  take `AuthenticatedUser`, and the test pins that each refuses a service account. A
  second route could use `CertificateBoundServiceAccount` only by being written to; the
  table and its test are where a reviewer would see it. Sound.

### 7.2 `network:decide`, per site

Checked on every site node the decision reads (`:582-644`): the `zones` and
`quarantine` site nodes of the site's segments, or the `zones` node for a site with no
segment. A refusal is `403` naming the node, with a `network_decision.refused` row.
A tenant-wide grant answers every site (T-468's stated residual; the guide grants per
site). A caller scoped to `hq` asking about `branch` gets the same `403` whether
`branch` has segments or not. Sound.

### 7.3 Tenant isolation

The tenant is the token's (`:574`); every read names it (`list_site`, `list_stored`,
the cap, `service_account_repo.get_by_id`). The certificate row is read globally by
fingerprint and kept only if `tenant_id` matches (`:428`), and the identity must name
the same tenant and certificate (`:437`). Another tenant's certificate and an unknown
one share one internal reason and one answer. Sound.

### 7.4 The fingerprint form

The fingerprint form authenticates the **stored** certificate of that fingerprint
(`:416`): AXIAM takes FreeRADIUS's word that the device presented it. Under option B
that is the trust model — FreeRADIUS terminates EAP-TLS and AXIAM never sees the
handshake — and the DER form is no stronger, since a certificate is public and the
same caller could post its bytes. Acceptable as documented (T-468's residual,
contract §36.11 rule 1, the guide).

### 7.5 One cost (T-457) and the timing test

Every request past the caller's checks runs the same reads in the same order, the
caller's own account standing in as a decoy subject (`:646-666`), and one
`check_access_batch` over every enabled segment (`:710-730`). The structural test counts
the batches; the timing test interleaves 31 rounds of three kinds, compares medians in a
1.5× band, and was mutation-checked (an early return measured 0.59). Medians over
interleaved rounds are robust to a noisy CI host; the band is wide, but it caught the
mutation. **Two cheaper paths remain, and both are documented in T-457:**
`authenticate_der`'s own early refusals, and the engine's short-circuit for a subject
with no assignments (hidden by the decision cache on a repeat). R110W6-09 adds that
the first is a cross-tenant signal in the fingerprint form (an unknown fingerprint never
reaches `authenticate_der`, `:417`; another tenant's does) and proposes the decoy. The
observer is the authenticated, audited FreeRADIUS caller; a device at a NAS presents
only its own certificate. Informational.

### 7.6 No reason, and the audit row

A refusal is exactly `{"allow":false}` (`NetworkDecisionResponse`, `reply` skipped when
`None`). The row (`:740-824`) carries the site, the fingerprint, the form, method,
transport, candidates, the internal reason, and for a certificate of this tenant its id
and bound account; never subject or SANs; `ip_address` is FreeRADIUS's. The body is
`deny_unknown_fields` (`:138-152`), so no `Calling-Station-Id` or `User-Name` can be
posted. §8 and T-464 hold. Volume is bounded by the caller's allowance (T-463).

### 7.7 The limiter and the closed body

The caller's bucket `network_decide:{tenant}:{sub}` is spent at `:575`, after the
extractor's token validation and `cnf` check and before `certificate_bound_caller` and
every read the handler makes; the shared counter when on, an in-process
keyed limiter when off (`network_decide_guard.rs`), whose map is bounded by
authenticated callers. The route carries a per-address backstop of 10 × 6 000
(`server.rs:1850-1862`). The JSON body is extracted before the handler runs, so a
malformed body is a `400` without spending the bucket; that costs no read either.
Sound.

### 7.8 The reply

`render_reply` (`radius_reply.rs:512-590`) walks the dictionary table and fills each
row from typed fields; an unknown row is a refusal. It re-checks VLAN 1–4094,
`Session-Timeout` within floor and ceiling, `Idle-Timeout` within its bounds, the
`Filter-Id` pattern and the admin class, last before the wire. `revalidate`
(`models/network.rs:545-620`) checks the row against its segment's own bounds, its
dictionary, its envelope and the absolute ceiling, then clamps to the current cap; any
defect makes the segment no candidate and writes one `reply_profile.invalid` row per
(tenant, segment, version, rule) per hour per replica. Tags: `"tag": 0` on
`Tunnel-Type` and `Tunnel-Medium-Type`, no `tag` on `Tunnel-Private-Group-Id` — what
FreeRADIUS 3.2.8 emits, measured by W5.4 and asserted on the wire by the e2e
(`0000000d`, `00000006`, `3230`). Member order follows the struct field order, as
§36.11 rule 6 pins. Sound.

---

## 8. The management routes (W6.3, W6.3b)

| Property | Evidence | Verdict |
|---|---|---|
| Human-only | every handler takes `AuthenticatedUser` (`handlers/network.rs:686-1659`); `network_routes_test::a_service_account_token_is_401` | Holds |
| Tenant from the token | `principal.tenant_id` everywhere; another tenant's rows are `404` (`::another_tenants_segments_and_profiles_are_invisible`) | Holds |
| Order: body → gate → veto → conditional write → one row | each write handler; the veto runs only for a cleared write (`reactor_hooks.rs` `network_pre_*_write`, fail closed by registry default) | Holds. After the gate, which is the safer order: an approver is never asked about a write the gate refuses |
| Version-conditional writes, stranding `409` | the repository's transactions (`repository/network.rs:378-427, 701-707, 921-940, 1158-1162`) | Holds |
| The cap: `segments_write` at the root only, deny-override | `network_gate.rs:1249-1271`; four route tests | Holds |
| Audit for every write and refusal, with before/after | `audit_success`, `refused`, `after_gate`; the gate's own row for its refusals | Holds |
| Limiter: seven buckets under `network_admin_per_min`, reads unlimited | `server.rs:1740-1843`; `::every_write_route_has_its_own_bucket_and_reads_are_not_limited` | Holds; names unique and `network_`-prefixed |
| Reads: `network:read` at the root for lists, at the segment for a get | `:693`, `:736`, `:1125`, `:1157`, `:1536` | Holds; a site-scoped reader cannot list, so the unfiltered page leaks nothing |

The segment writer's reach over placed devices is R110W6-03.

---

## 9. v100, and the v99 gap

**v100** (`schema.rs:4815-4900`) defines three `SCHEMAFULL` tables with
`IF NOT EXISTS` throughout, no `UPDATE`, `REMOVE` or backfill;
`v100_adds_only_the_network_tables` pins that every statement names one of the three
tables; the newest-version assertion reads 100. Additive. The three tables are in
`TENANT_PURGE_ORDER`.

**The gap (R110W6-07).** `run_migrations` reads the highest recorded version and applies
every listed migration above it (`schema.rs:2484-2490`). Nothing checks contiguity. On
the release branch the list will read `… 98, 99, 100` and a fresh or an up-to-date
datastore applies both. A datastore that **recorded 100 without 99** — one that ran this
branch's head, or any intermediate release-branch build where W6 is merged and W1 is
not — skips v99 for ever, and v99 is W1's `certificate.serial` column and its
issuer-unique index (#653). Whether SurrealDB then drops or refuses the `serial` field
W1's repositories write on a `SCHEMAFULL` table, the unique index that refuses a
repeated serial is not there. No released build has v100, so no production deployment
is in that state; staging and dogfooding instances that ran a W6 build would be. Low;
merge rule plus a cheap hardening (issue body).

---

## 10. The `rlm_rest` recipe (W6.5)

* **The hook** (`verify.conf`, `axiam-d4.sh`). FreeRADIUS writes the client certificate
  to a file it names under `tmpdir` and runs `client` with that name; nothing from the
  certificate reaches a command line. `stash` derives serial and fingerprint with
  `openssl`, requires both to be lower-case hex (64 digits for the fingerprint), writes
  under `umask 077` with an atomic `mv`. `take` takes a hex-only serial and refuses a
  stash older than 120 s. `axiam_take` is an `exec` xlat: FreeRADIUS splits the command
  into arguments before expanding them, so `%{TLS-Client-Cert-Serial}` cannot add an
  argument, and the script re-checks it. No shell injection.
* **The directory.** A `tmpfs` owned by `freerad` (uid 101), mode `0700`
  (`docker-compose.radius-d4.yml`). The guide makes it a requirement and says why.
* **Serial keying.** A certificate's serial is the one value both the hook and the
  virtual server see. On this branch AXIAM's serials are derived from the public key, so
  two certificates over one key share a stash entry; whoever presents either holds that
  key, so a race between them changes nothing an attacker could not do directly. After
  W1.9 serials are random and unique per issuer (v99's index), FreeRADIUS trusts one
  issuer, and the keying is sound for that reason instead. The guide's stated reason
  becomes false at the merge (R110W6-11).
* **The mapping** (`check-eap-tls:111-181`). The allow must match an anchored prefix
  (`allow: true`, the dictionary name, `attributes: [`). Each attribute is looked for by
  name, number and shape and set by the recipe, never copied; the triple,
  `Session-Timeout` and `Termination-Action` are required; a present optional attribute
  that is malformed refuses; every checked attribute is initialised first, so a missing
  one cannot pass as a `false` comparison. AXIAM's only free string values are the
  decimal VLAN and a `Filter-Id` matching `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`, neither of
  which can carry a quote, so a value cannot forge a second attribute object. The token
  regex and the `Authorization` header admit only token characters (no header
  injection).
* **Who can answer.** `check_cert = yes`, `check_cert_cn = yes` against AXIAM's CA. A
  man in the middle needs a certificate for AXIAM's name from that CA.
* **The site key.** `%{client:shortname}` from `clients.conf`, validated against the
  site pattern before it is posted; never from the packet.
* **Failure modes.** AXIAM down or slow (3 s connect, 4 s request), any non-2xx, a body
  that is not the allow: reject. The pool starts empty so FreeRADIUS starts without
  AXIAM. The one gap is the token cache on a `401` (R110W6-10).

`freeradius -XC` was not re-run here: the executor's run of both profiles in the pinned
image, and the e2e (2 passed, 418 s) whose D4 case exercises every branch above, are
recorded in `e4dca26`, and nothing in the recipe changed after that commit.

---

## 11. Contract §36 and the specification

* **The spec.** `cargo build -p axiam-server --no-default-features` and
  `--dump-openapi` reproduce `sdks/openapi.json` byte for byte (`cmp` 0);
  `check-spec-digest.py` 0; `gen-management-registry.py --check` 0, **202 operations
  across 29 namespaces**, `POST /api/v1/network/decide` excluded by name. The renames of
  `70c8039` are in the document (`NetworkReplyProfile`, `RadiusServiceType` with the one
  value `framed_user`, …).
* **§36.1** twelve operations, paths and methods: match the route table. `replace_*` is
  right: each is a full-body, version-conditional replacement.
* **§36.2** shapes: `NetworkSegmentResponse`, `NetworkReplyProfile` (effective value,
  `session_timeout_clamped`), `NetworkPolicyResponse` (`updated_by`/`updated_at`
  optional) match the structs. **One mismatch:** the `service_type` row says an
  administrative value is "refused with a `400`"; the server answers `403` naming
  `network:grant_admin` (probe, §2's method):

  ```
  PROBE service_type administrative_user: 403 {"action":"network:grant_admin","error":"authorization_denied",…}
  PROBE service_type nas_prompt_user:     403 {"action":"network:grant_admin",…}
  PROBE service_type framed_user:         201
  ```

  R110W6-02.
* **§36.3** rules 1–4 and 7–10 match the gate and the handlers. Rule 6's statement is
  right, its framing is not (R110W6-12): "a read-modify-write of a clamped profile stores
  the clamped value" is not an artefact of read-modify-write; H3 refuses any
  `session_timeout_secs` above the current cap (`network_gate.rs:1044-1052` and the
  repository), so **no** replace while clamped can keep the stored value, whatever the
  client knows. That bears on follow-up (a), §15.
* **§36.11** rules 1–4, 6–8 match the handler and the recipe; rule 6's member order is
  the struct order and the compact encoding is `HttpResponse::json`'s. Rule 5's "costs
  the same reads and the same batch, whatever the answer" is stronger than the code
  (R110W6-09).
* **The manifest-namespace sentence** (§36.9: `network` is a §27.6 manifest namespace in
  1.62, natural keys site + kind + name, the profile by its segment, the policy a
  singleton) is consistent with the uniqueness the schema enforces
  (`idx_network_segment_site_name` on tenant, site, kind, name). A manifest apply goes
  through the twelve routes, so through the gate; it adds no write path.

---

## 12. The console (W6.8)

* **Gating mirrors the server, and is not relied on.** The nav item and the route need
  `network:read`; write controls show for `network:segments_write` /
  `network:profiles_write`. These are hints: the server decides every write at its node,
  and the page shows the server's `403` (permission and node from `action` /
  `resource_id`, never parsed from `message`). Nothing in the page assumes a hidden
  control is a refused one.
* **No secret, no fingerprint.** Segments, profiles and the cap carry none; nothing in
  `pages/network` or `services/network.ts` renders a certificate or a fingerprint.
* **No call to `/decide`.** `services/network.ts` has none, and
  `NetworkAccessPage.test.tsx:211` asserts no request URL contains `/decide`.
* **Error rendering.** `networkErrorMessage` returns plain strings (the server's
  `message` truncated to 500 characters, plus fixed text); React renders them as text.
  No `dangerouslySetInnerHTML` in the section.
* **The OAuth2 touches** (`326a807`): the `scope_exceeds_ceiling` slug decides the
  branch, the server's message is shown as text; the device-grant notice is static. No
  security effect.

---

## 13. Threat-model text against the code

Both copies agree entry for entry (statuses compared programmatically: no difference),
**487 threats, 453 Mitigated, 24 Open, 10 Not applicable** (the STRIDE table counts four
`**Closed**` rows as Mitigated, as before). `threatTop` is 487; no other wave branch uses
a number above T-477, so the numbering does not collide at the merge.
`gen-threat-model.mjs`, `gen-api-index.mjs` and `gen-contract-anchors.mjs` regenerate the
website copies with no diff. Every test name the W6 amendments cite resolves to a `fn`
(79 references scripted, 16 gate unit-test names checked by hand).

| Entry | Text against the code |
|---|---|
| T-457 | Accurate, its two residuals included; see R110W6-09 for the cross-tenant reading and the decoy |
| T-459 | Accurate (the route's tenant check, §7.3) |
| T-461 | Accurate; "the administrative `Service-Type` values refused under option B" — refused, with a `403` (R110W6-02) |
| T-462 | Accurate (D4 column; no CoA; plan §12 Q9) |
| T-463 | Accurate, its per-replica residuals included |
| T-464 | Accurate (closed body; fingerprints; the D6 trigger) |
| T-468 | Accurate, residuals included |
| T-478 | Accurate except "refused outright" for the admin class (R110W6-02); its title ("a segment envelope that confers more placement than they could grant") reads on R110W6-03, which its text does not address |
| T-479 | Accurate; its residual list will lose T-482 with R110W6-01 |
| T-480 | Accurate, its own residual (receiver names) stated |
| T-481 | Accurate; R110W6-04 adds the group interleaving |
| T-482 | Accurate for self-assignment; omits self-release, which is the sharper half (R110W6-01) |
| T-483, T-484 | Accurate |
| T-485 | Accurate |
| T-486 | Accurate; R110W6-10 is one more way to reach it |
| T-487 | Accurate |

---

## 14. Documentation claims

* **The design note's header** still reads "**Status: DESIGN NOTE — nothing is
  built**" (`radius-reply-profile-design.md:3-8`), above two dated corrections that say
  otherwise. **§3.1** says "the only way to put a device on VLAN 99 is to write the
  profile of the segment that owns VLAN 99" — a segment writer can also give an existing
  profiled segment VLAN 99 (R110W6-03). W8.3 (the header), the maintainer (§3.1).
* **`freeradius.md:866-868`**: "this guide claims no mitigation the model does not yet
  state" — the model now states them (W6.6). W8.3.
* **`freeradius.md:581-583`**: the serial reason (R110W6-11). At the W1 merge.
* **The 190 / 28 counts** in `website/src` and `CONTRACT.md:4146` (W6.3b's finding): still
  stale; W7.1 / W8.3.
* **Contract §36.3 rule 6** (R110W6-12), **§36.2 / rule 5** (R110W6-02), **§36.11 rule 5**
  (R110W6-09): W7.1, or the fix of R110W6-02.
* `docs/deployment/rate-limit-sizing.md`, the deployment README, `docs/admin/reactors.md`
  and the website's configuration table agree with the code (30 a minute, seven buckets;
  6 000 a minute in all three profiles; the two fail-closed hooks).

---

## 15. The two contract follow-ups of W6.8 — assessment (for the maintainer; not decided here)

**(a) A `stored_session_timeout_secs` member on `NetworkReplyProfile`.** Not needed for
safety, and it would not give a client what W6.8 hoped for. H3 refuses a
`session_timeout_secs` above the current cap on every create and replace
(`network_gate.rs:1044-1052`, and the repository's `validate`). So while a profile is
clamped, **no** write can store its old value, whatever the client knows; the clamped
store is the rule, not a read-modify-write accident (the same holds for an
`Idle-Timeout` the read pulled down). The member would only let the console show the
number a save discards. **Recommendation: do not add it in 1.62; correct §36.3 rule 6
to say that a replace while clamped stores at most the cap (H3), and let the console keep
its "above the cap of N s" sentence.** If the maintainer wants the number shown, add it as
a read-only, additive response member now, before the W7 fan-out makes it eleven changes.

**(b) Distinct `409` slugs (`stale_version` vs `conflict`).** Worth having; not as new
values of `error`. Today a stale version, a stranding envelope write and "has child
resources" all answer `error: "conflict"` (duplicates already answer `already_exists`),
and §36.3 forbids parsing `message`, so neither the console nor an SDK can tell "reload"
from "change the profile first". Changing `error` would break §2's mapping that every
SDK has (`409` → `ConflictError`, by status). **Recommendation: keep `error: "conflict"`
and add a machine-readable member on §36's `409` bodies — e.g. `reason`:
`stale_version` | `strands_profile` | `has_children` — decided before W7.1 freezes §36;
additive for every SDK, and §36.4 then names it as the one member an SDK may branch on.**
No security effect either way.

---

## 16. Merge risks

1. **Schema (W1 × W6).** W1 adds v99 and moves the newest-version assertion to 99; W6
   adds v100 and moves it to 100. Both edit the tail of `MIGRATIONS` and the same
   assertion: resolve to `…, 98, 99, 100` and 100. **Merge W1 before W6** into the release
   branch, so that no release-branch build has v100 without v99 (R110W6-07).
2. **Serials (W1.9 × W6.5).** After #653 serials are random: `freeradius.md` §5's reason
   for the serial key is false (R110W6-11), and W1 also rewrote the D3 paragraph
   "The key is the serial" (`freeradius.md:308-335`) that §5 links to. The two must be
   reconciled in the merge, not by either side alone.
3. **`radius_e2e.rs` (W1, W5, W6).** Three edits of one file — W1 52 lines, W5 578, W6
   1 312 — the largest textual merge of the release. `freeradius.md` likewise (W1 58, W5
   217, W6 366). Re-run `AXIAM_E2E_RADIUS=1 cargo test -p axiam-server
   --no-default-features --test radius_e2e` after the merge, and the `radius-e2e`
   workflow on the PR (D-4). W5.3's check of the compose files must accept the D4
   override without an `image:` line (it names none on purpose).
4. **The bucket-name test (W2).** `rate_limit_bucket_names_test.rs` scans
   `RateLimitShared` constructors; W6's seven names are literal, unique and new, so it
   should pass unchanged. The decision's per-caller bucket is spent through
   `shared_rate_limit.check_at`, which that scan does not read; its key
   (`network_decide:{tenant}:{sub}`) shares no prefix with a registered endpoint. Run the
   test after the merge. `server.rs` and `config/rate_limit.rs` will conflict textually
   with W2 and W3 (each adds fields and routes).
5. **Generated files.** `sdks/openapi.json` (W1, W3, W6), the registry's digest,
   `website/src/apiIndex.ts`, `threatModel.ts`, `threatModelSummary.ts` and
   `contractAnchors.ts`: regenerate after the merge, never hand-merge. 202 / 29 holds only
   if no other wave adds an operation (W1 and W3 move the digest only, as far as their
   branches show).
6. **Threat totals.** 487 / 453 / 24 / 10 is this branch's arithmetic; W1 … W5 change
   statuses of existing entries, so the header, §6, §7 and the website summary must be
   recomputed at the merge (and once more with R110W6-01's flip of T-482).

---

## 17. Checks run

Each command's own exit code was captured; logs are in the session scratchpad. Every
cargo command ran with `RUSTFLAGS=-Dwarnings`, `CARGO_INCREMENTAL=0`,
`CARGO_PROFILE_{DEV,TEST}_DEBUG=line-tables-only` and the swagger placeholder.

| Check | Exit | Result |
|---|---|---|
| `cargo fmt -p axiam-core -p axiam-authz -p axiam-db -p axiam-api-rest -p axiam-server -- --check` | 0 | clean |
| `cargo clippy -p axiam-core --lib --tests -- -D warnings` | 0 | clean |
| `cargo clippy -p axiam-authz --lib --tests -- -D warnings` | 0 | clean (`missing_docs` included) |
| `cargo clippy -p axiam-db --lib --tests -- -D warnings` | 0 | clean |
| `cargo clippy -p axiam-api-rest --lib --tests -- -D warnings` (default features, SAML on) | 0 | clean — the run `70c8039` did not make |
| `cargo clippy -p axiam-api-rest --lib --tests --no-default-features -- -D warnings` | 0 | clean |
| `cargo clippy -p axiam-server --lib --tests --no-default-features -- -D warnings` | 0 | clean |
| `cargo clippy -p axiam-server --lib --tests -- -D warnings` (default features) | 0 | clean |
| `cargo build -p axiam-server --no-default-features` | 0 | built |
| `axiam-server --dump-openapi` vs `sdks/openapi.json` | 0 | byte-identical (`cmp` 0) |
| `python3 scripts/check-spec-digest.py` | 0 | digest matches |
| `python3 scripts/gen-management-registry.py --check` | 0 | 202 operations / 29 namespaces in sync |
| `python3 scripts/check-crate-layering.py` | 0 | 19 crates, 62 edges inward |
| `python3 scripts/check-remediation-evidence.py` | 0 | 37 verified, 0 failed |
| `python3 scripts/check-config-key-coverage.py` | 0 | every key documented |
| `bash scripts/check-doc-links.sh` | 0 | 513 links across 78 files |
| `python3 scripts/check-conflict-markers.py` | 0 | OK |
| `python3 scripts/check-audit-ignore-sync.py` | 0 | OK |
| **`python3 scripts/check-frontend-coverage.py`** | **1** | **`handlers/network.rs` and `handlers/network_decide.rs` have no row (R110W6-13)** |
| `node website/scripts/gen-threat-model.mjs`, `gen-api-index.mjs`, `gen-contract-anchors.mjs` | 0 ×3 | no diff |
| STRIDE table vs `Axiam.json` statuses | — | identical; 487 / 453 / 24 / 10 |
| Test names cited by the W6 threat amendments | — | 79 references resolve; 16 gate unit tests by hand |
| `cargo test -p axiam-core --lib network` / `radius_reply` | 0 / 0 | 14 / 14 passed |
| `cargo test -p axiam-authz --lib` | 0 | 114 passed (the gate's unit tests included) |
| `cargo test -p axiam-db --test network_repository_test` | 0 | 21 passed |
| `cargo test -p axiam-db --test seeder_default_data_test` | 0 | 16 passed |
| `cargo test -p axiam-db --lib schema` | 0 | 76 passed (`v100_adds_only_the_network_tables`, the newest-version assertion) |
| `cargo test -p axiam-api-rest --no-default-features --test network_gate_test` | 0 | 7 passed |
| `cargo test -p axiam-api-rest --no-default-features --test network_gate_enumeration_test` | 0 | 4 passed |
| `cargo test -p axiam-api-rest --no-default-features --test network_routes_test` | 0 | 26 passed |
| `cargo test -p axiam-api-rest --no-default-features --test network_decide_test` | 0 | 12 passed (the timing test included, on a loaded 4-core host) |
| `cargo test -p axiam-api-rest --no-default-features --test m2m_management_test` | 0 | 16 passed |
| `cargo test -p axiam-api-rest --no-default-features --lib` | 0 | 283 passed (`route_openapi_parity_test`, `network_decide_guard`, `reactor_hooks`, `config::rate_limit`) |
| probe: two temporary tests appended to `network_gate_test.rs` (removed) | — | self-assignment `204`, self-release `204` (§2); admin `Service-Type` `403` naming `network:grant_admin` (§11) |
| `npm --prefix frontend ci` | 0 | 0 vulnerabilities |
| `npm run lint` (oxlint) · `npx tsc -b` · `npm run typecheck:e2e` · `npm run test:a11y` | 0 ×4 | clean; a11y 8 passed |
| `npx vitest run --coverage` | 0 | 122 files, 2 366 tests; lines 96.57 % (threshold 96.1) |

The `radius_e2e` D4 case and `freeradius -XC` were not re-run (§10): the recipe has not
changed since `e4dca26`, whose message records both. `frontend/node_modules` and
`frontend/coverage` were removed after the run.

`cargo clean` was run at the end.

---

## 18. Issue bodies

### R110W6-01 (Medium) — H6 does not stop a subject changing its own placement through §5.3

**Where:** `crates/axiam-authz/src/network_gate.rs:1275-1347` (`role_assign`),
`:1349-1387` (`role_unassign`), `:1420-1445` (`role_delete`), `:1449-1558`
(`permission_grant`), `:1560-1604` (`permission_revoke`). Threats: T-482, T-479; design
note §5.2 H6, §4.4.

**The gap.** H6 ("refused, whatever it holds") is applied to profile and segment writes
and to binding. The §5.3 writes never compare the grantee, or the role's holders, with
the writer. The role routes admit a service account (`roles` is an M2M family). A
service account holding `roles:assign` and `network:grant` at a node assigns itself a
role carrying `network:join` there (`204`, probed), and, once quarantined by a network
administrator, unassigns its own deny (`204`, probed); the same account can also
release itself by revoking the deny from the quarantine role it holds, or by deleting
that role, and place itself by granting the join to a role it holds.

**Fix:** §2 of the review — a `is_writer` helper and an `H6` refusal in each of the five
functions (join allow assigned to the writer; a deny unassigned from the writer; a
deny role the writer holds deleted; a join allow granted to a role the writer holds; a
deny revoked from a role the writer holds), subject-agnostic; the note's §5.3 table gains
the row, dated.

**Tests:** `network_gate_test.rs::a_service_account_cannot_place_itself_or_release_its_own_quarantine`
(403 + `H6` rows for self-assignment and self-release; 204 for the same writes on another
account and by another administrator); the five `h6_*` unit tests of §2. T-482 to
Mitigated with them.

### R110W6-02 (Low) — an administrative `Service-Type` is a 403 naming a permission nobody can hold

**Where:** `crates/axiam-authz/src/network_gate.rs:1054-1063` (H4 runs before any value
check); `sdks/CONTRACT.md:12820` and `:12886` (say `400`); T-478 and T-461 ("refused
outright").

**The gap.** Under option B the administrative class is disabled, so the write is legal
for nobody — `RefusalStatus::Invalid`'s own definition (`:591-593`). The gate answers it
`403` with `action: "network:grant_admin"`, which the grant gate refuses to grant
(`:1508-1513`). An administrator reading the `403` is told to obtain a permission that
cannot exist, and the contract's `400` is not what the server sends.

**Fix:** in `profile_write`, before H1: an administrative `service_type` is a `400`, rule
`3.3:admin-class`, audited as every gate refusal; keep H4's block for option A (it is
unreachable while the class is disabled). Alternatively, if the maintainer prefers the
`403`, correct §36.2, §36.3 rule 5, T-478 and T-461.

**Test:** `network_routes_test.rs::an_administrative_service_type_is_400_and_audited`
(both admin values, create and replace, one `reply_profile.write_refused` row each with
the rule; `framed_user` still `201`).

### R110W6-03 (Low) — a segment writer re-places devices without `network:grant`

**Where:** `crates/axiam-authz/src/network_gate.rs:1178-1225` (`segment_update`: only
`segments_write` at the node and H6); design note §3.1, §4.2, §5.2 H3; T-478.

**The gap.** `vlan_id`, `rank` and `enabled` are the envelope, written under
`network:segments_write`. On a segment that already has a profile, each of them changes
what every device that may join it gets: a new VLAN for all of them, a different winner
among a site's access candidates, a segment becoming a candidate. The quarantine
segment's VLAN reaches every quarantined device of the site, which is H5's reason for
asking `network:grant` on the quarantine site of a *profile* writer — but not of the
envelope writer. The note's §3.1 says "the only way to put a device on VLAN 99 is to
write the profile of the segment that owns VLAN 99"; a segment writer can give an
existing profiled segment VLAN 99 instead. The note's own §4.2 table does assign
`vlan_id` to `segments_write`, so this is a design inconsistency, not a code defect.

**Fix (maintainer decides):** either (a) a segment update that changes `vlan_id`,
`rank` or `enabled` (false → true) of a segment that has a profile also needs
`network:grant` on the segment, and on `/network/quarantine/<site>` for a quarantine
segment (H2/H5 applied to the envelope); or (b) correct §3.1 and T-478's text to say that
the VLAN of a profiled segment is the envelope writer's, and that splitting the two
duties does not stop the envelope writer re-placing devices.

**Test (for a):** `network_routes_test.rs::changing_a_profiled_segments_vlan_needs_network_grant`
(403 naming `network:grant`, then 200 with it; a quarantine segment needs it on the
quarantine site; a segment with no profile needs only `segments_write`).

### R110W6-04 (Low) — the network gate's check and the write are not one transaction (T-481)

**Where:** `crates/axiam-authz/src/network_gate.rs` (every read) and the REST callers;
for the interleaving below, `:1529-1535` (`permission_grant` reads the holders) and
`:1285-1288` (`role_assign` reads the grants).

**The gap.** As T-481 states, plus one interleaving it does not name: a grant of a
`network:join` allow to role `R` and an assignment of `R` to a group, landing within one
request's window of each other, each pass their check; `R` is then a network role held by
a group, and group membership (`groups:add_member`, SCIM, directory sync, none gated)
confers the join — the case §4.2 rule 2 exists for.

**Fix:** give `role` a version that the grant, revoke and assignment transactions each
claim (`UPDATE role SET grant_epoch += 1 WHERE version = $read`), or re-read the role's
grants and holders inside the write's transaction and `THROW` on a network-sensitive
change; the same for the account's joins inside the bind.

**Test:** a repository test that interleaves the two writes (as
`a_profile_and_an_envelope_change_racing_never_leave_a_stranded_profile` does for
profiles) and asserts no group ever holds a role with a `network:` grant.

### R110W6-05 (Low) — the organization's super-admin holds the network meta permissions in every tenant (T-483)

**Where:** `crates/axiam-core/src/models/network.rs:798-805`,
`crates/axiam-db/src/seeder.rs:515-525`, `crates/axiam-authz/src/engine.rs:161-169`.

**The gap.** The organization scope tenant's seeded super-admin is global and carries
`network:read` and the five meta permissions, and global grants are what an
organization-level subject carries into every tenant; the note's §7 says no network grant
crosses tenants.

**Fix:** `super_admin_may_hold` returns `false` for a `network:` action when the tenant's
`kind` is `Organization`; `reconcile_default_role_grants` revokes them there. Each
tenant's own super-admin keeps the bootstrap.

**Test:** `seeder_default_data_test.rs::the_organization_scope_super_admin_holds_no_network_permission`
and a gate test that an organization-level writer is refused `network:grant` in a child
tenant.

### R110W6-06 (Low) — a cleared network-sensitive write has no row of its own (T-484)

**Where:** `crates/axiam-api-rest/src/network_gate.rs:84-110` (`authorize_as` audits only
refusals); callers in `roles.rs`, `permissions.rs`, `certificates.rs`.

**The gap.** A cleared assignment, grant or bind that is network-sensitive is recorded
only by the generic request row, which says neither that it was nor where the join
landed.

**Fix:** after the repository write succeeds, when `GateClearance::is_network_sensitive()`,
append one `network_role.assigned` / `.unassigned` / `network_role.granted` /
`.revoked` / `certificate_binding.bound` row with the role, the grantee, the node and the
permissions conferred.

**Test:** `network_gate_test.rs` — each cleared network-sensitive write leaves exactly one
such row with those members; a non-network write leaves none.

### R110W6-07 (Low) — a datastore that recorded v100 without v99 never applies v99

**Where:** `crates/axiam-db/src/schema.rs:2484-2490` (`migration.version > current_version`).

**The gap.** The runner applies only versions above the highest recorded. W6 ships v100
on a branch without W1's v99 (#653: `certificate.serial` and its issuer-unique index). A
datastore that ran a build with v100 and without v99 — this branch, or a release-branch
build between the W6 and the W1 merges — skips v99 for ever.

**Fix:** merge W1 before W6. Harden the runner: read every recorded version
(`SELECT VALUE version FROM _migration`) and apply, in order, each listed migration not
recorded (every migration is idempotent DDL, so a late v99 is safe), logging the
out-of-order application; and add `migrations_are_contiguous` (versions = 1 … N) once v99
is in the list.

**Test:** a schema test that records 1 … 98 and 100, runs the migrations and asserts v99
applied (`idx_certificate_issuer_serial` exists).

### R110W6-08 (Low, pre-existing) — a UMA resource server can change resources it did not register

**Where:** `crates/axiam-api-rest/src/handlers/uma.rs:396-439` (`update_resource_set`),
`:461-485` (`delete_resource_set`), `:361-395` (`read_resource_set`); compare the list, which filters by
`uma_registered_by` (`:516`).

**The gap.** Update, delete and the scope sync check only that the resource is in the
PAT's tenant. Any resource server of the tenant renames, retypes, replaces the scopes of
or deletes any resource of the tenant — a resource another resource server registered, or
one a tenant administrator made for RBAC. W6.2 closed the reserved `/network` subtree on
these routes; the rest predates the wave.

**Fix:** refuse (`404`, as for an unknown id) a get, update or delete of a resource whose
`uma_registered_by` is not the PAT's `client_id`.

**Test:** `uma_test.rs` — resource server B gets `404` on A's resource set for get, update
and delete, and on a resource created through `/api/v1/resources`; A's own still work.

### R110W6-09 (Informational) — the decision's two cheaper paths; one is a cross-tenant signal

**Where:** `crates/axiam-api-rest/src/handlers/network_decide.rs:404-426`;
`sdks/CONTRACT.md:13040-13041`; T-457.

**The gap.** As T-457 records: an unknown fingerprint never reaches `authenticate_der`
(`:417`), another tenant's does, so the FreeRADIUS caller of tenant A can tell by time
whether a fingerprint it holds is registered in *any* tenant; and the engine answers a
subject with no assignments faster. §36.11 rule 5 says every request "costs the same
reads and the same batch, whatever the answer", which the code does not meet.

**Fix:** when no row resolves (fingerprint form) or the row is not this tenant's, run
`authenticate_der` over the caller's own certificate (`caller.der`) as a decoy and discard
the result, so every refusal pays one full verification; soften rule 5 to name the
remaining engine short-circuit.

**Test:** add the unknown fingerprint to `allow_no_candidate_and_another_tenant_cost_the_same`
and to the structural test.

### R110W6-10 (Informational) — the recipe keeps a refused token for half its life

**Where:** `docker/radius/raddb/d4/check-eap-tls:56-104`; `axiam_d4:100-109`; T-486.

**The gap.** The token is cached for `expires_in / 2`. If the decision answers `401`
(the FreeRADIUS certificate revoked and re-issued, the account re-enabled, AXIAM's signing
key rotated), the cached token is reused until the entry expires and every device is
refused meanwhile — up to 7.5 minutes with the default lifetime. Fail closed; an outage,
not an admission.

**Fix:** after `axiam_decide`, when the status is `401`, expire the cache entry
(`update control { Cache-TTL := 0 }` then `axiam_token_cache`) and fetch a token and ask
once more before rejecting.

**Test:** in the D4 e2e, revoke and re-issue FreeRADIUS's own certificate (restart with
the new one is not needed for the cache case: rotate the account's binding) and assert the
next authentication after the `401` is admitted without waiting out the TTL.

### R110W6-11 (Informational) — the serial-keyed stash, before and after W1.9

**Where:** `docker/radius/raddb/d4/axiam-d4.sh:13-17`; `docs/pki/freeradius.md:575-586`.

**The gap.** The guide justifies keying the fingerprint by serial with "AXIAM derives it
from the public key". On this branch that is true, and two certificates over one key share
a stash entry (harmless: one key holder). After W1.9 (#653) serials are random and unique
per issuer, and the sentence is false.

**Fix:** at the W1 merge, replace the reason with "serials are unique per issuer
(`idx_certificate_issuer_serial`) and this server trusts one issuer", in §5 and in
"The key is the serial".

**Test:** none beyond the e2e, re-run after the merge.

### R110W6-12 (Informational) — text the wave left stale or overclaiming

**Where:** `claude_dev/radius-reply-profile-design.md:3-8` ("nothing is built") and §3.1;
`sdks/CONTRACT.md:12889-12893` (§36.3 rule 6's rationale), `:12820`/`:12886`
(R110W6-02), `:13040-13041` (R110W6-09); T-478 ("refused outright");
`docs/pki/freeradius.md:866-868`; the 190 / 28 counts (`website/src`, `CONTRACT.md:4146`).

**Fix:** W7.1 for the contract (rule 6: a replace while clamped stores at most the cap,
H3); W8.3 for the note's header, the guide's paragraph and the counts; the maintainer for
§3.1 (R110W6-03).

**Test:** `check-doc-links.sh`; the contract-anchor generator.

### R110W6-13 (Low, CI — fix in wave) — the frontend coverage matrix has no row for the network handlers

**Where:** `claude_dev/frontend-coverage-matrix.md` (the matrix);
`scripts/check-frontend-coverage.py`; `.github/workflows/docs-ci.yml:96-102`, which runs
it on every PR touching `docs/**` or `crates/axiam-api-rest/src/openapi.rs`.

**The gap.** W6.3 and W6.4 added two handler modules and W6.8 the page for one of them;
neither row was added, so the check exits 1 ("handlers/network.rs has no row in the
matrix", "handlers/network_decide.rs has no row") and the release PR's docs job is red.

**Fix:** two rows. `network` — `network/NetworkAccessPage` (segments, reply profiles,
the cap) — **covered** — W6.3/W6.3b/W6.8, #563; writes gated by the server's write gate,
the console only hides controls. `network_decide` — — — **headless (machine-to-machine)**
— W6.4, #563: `POST /api/v1/network/decide` is FreeRADIUS's, over mTLS with a
certificate-bound service-account token (contract §36.11); the console never calls it.

**Test:** `python3 scripts/check-frontend-coverage.py` exits 0.

---

## 19. Invariants

* **Nothing registered before the wave changes behaviour, except as the wave says.** The
  changes it announces: the `network:` permission namespace is reserved (create, rename,
  delete refused); the generic resource and UMA routes refuse the `/network` subtree and
  `network_*` types; a network-sensitive role is never global, never on a group, never a
  deny with `inherit: false`, never scoped; assignment, grant, revoke, role delete and bind
  of network-sensitive roles need `network:grant` (and the meta permissions conferred);
  the seeded `admin` holds no `network:` permission and the seeded `super-admin` holds six;
  twelve management routes and one decision route exist. A tenant that uses none of
  `network:` sees no difference: the gate clears every non-network write after the reads
  it needs to know that.
* **Schema.** v100 only, additive, with its scope test and the newest-version assertion
  (§9).
* **Contract.** §36 only; no record edited. `sdks/openapi.json` byte-identical to a fresh
  build; registry 202 / 29.
* **This review.** It changed no file but itself. The two probes were a temporary block
  appended to `network_gate_test.rs`, run and removed (`git status` clean before the
  commit). The website generators were run and produced no diff.
