# Security review — release 1.1.1, wave W1 (F4)

**Date:** 2026-10-19.
**Against:** `claude/release-1.1.1-w1`, the whole wave diff `6b15aa36a..189fa248f`
(13 commits, 39 files, 3 119 lines added and 399 removed). Every commit carries a
signature (`gpgsig` header in 13 of 13; the sandbox has no
`gpg.ssh.allowedSignersFile`, so `%G?` cannot verify them here).
**Scope:** every W1 task of the release-1.1.1 plan (§2): W1.1 #664 (`bc7d9f4d2`),
W1.2 #665 (`83bec6fc0`), W1.3 #667 (`18ca1cacf`), W1.4 #669 (`b53d74bb0`), W1.5 #668
(`035f51ede`), W1.6 #714 (`6cb43c6c3`), W1.7 #689 (`140911a21`, schema v108), W1.8
#687 (`056bf289c`), W1.9 #690 (`435952fb3`), W1.10 #692 (`769d314be`), W1.11 #666
(`42ade1e40`), W1.12 #688 (`6dffb7060`), W1.13 #717 (`189fa248f`).
**Method:** adversarial reading of the diff and of the sibling paths it implies,
against [`threat-model-stride.md`](threat-model-stride.md) and `Axiam.json` (model
2.42.0, 487 threats), the plan's §1.2, §1.3 and §10 rules, and the OWASP ASVS 5.0
areas the diff touches (V2 business logic and concurrency, V9 certificates, V12
outbound requests, V13 configuration, V14 data protection and retention, V16
logging). Every commit message was checked against its code. Claims were checked
against the code, not the commit messages; three were checked by throwaway probes
(§13), removed before this commit. No issue of the wave carries a comment, so every
§11 default applies (D-7: add the markers; D-8: texts only). This review fixes
nothing: every finding has evidence, a proposed fix and an issue. IDs: `R111W1-nn`.

---

## 0. Summary

**One Medium finding, introduced by the wave; nothing High or Critical.**

* **R111W1-01 (Medium, wave — W1.7, #689 (i)).** The GDPR sweep's new first step,
  `claim_owed_erasure_records`, selects the pre-v108 owed erasures with
  `meta::id(id) IN (SELECT VALUE user_id FROM account_deletion WHERE status =
  'pending')` **inside** the `WHERE` of a scan of `user`. SurrealDB evaluates that
  subquery again for every user row, and `account_deletion`, which keeps every
  completed request, has no index on `status`. Probe (§13.1): 20 000 users beside
  2 000 deletion rows, with nothing owed, took **112.8 s** for one call; the same
  statement with the subquery hoisted into a `LET` took 0.68 s. The step runs every
  cleanup tick on every replica, before the pepper check, so a deployment without
  the GDPR pepper pays it too. It is R110W1-01's pattern, reached by nothing more
  than deletion requests accumulating. **Fix in the wave** (§2.1): read the pending
  requests once and fetch their users by record id.

One Low finding the wave introduced (R111W1-02, W1.11's cache condition), one Low
gap in W1.7's recovery (R111W1-03), and three Informational findings (one
pre-existing, two text or residual) are filed on `1.1.x` (§14).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R111W1-01** | `claim_owed_erasure_records` re-evaluates the pending-request subquery for every user row: 112.8 s for 20 000 users and 2 000 requests against 0.68 s hoisted. Every tick, every replica, with or without the pepper. | **Medium** | `account_deletion.rs` `claim_owed_erasure_records`; `cleanup.rs` `record_owed_erasures` → T-187, T-444 | wave (W1.7) | **Fix in wave** (§2.1) |
| R111W1-02 | W1.11's cache condition `this_update <= now` also applies to `current()`; `thisUpdate` follows the datastore-clocked revocation date, so while the datastore leads the replica, every CRL fetch re-signs (or answers `503` under a full gate) where the cache used to answer (probe). | Low | `crl.rs` `CaSlot::fresh`, `resign` → T-102 | wave (W1.11) | #736 |
| R111W1-03 | W1.7's recovery of an erasure cut past its point of no return writes the record but not the erasure proof (written after the anonymization), does not redo W1.5's second revocation, and the erasure's guard is armed only after the proof, so a cut before it waits out the lease; T-444 and the guide say otherwise. | Low | `cleanup.rs` `erasure_steps`, `erase_and_record`, `record_owed_erasures` → T-444, T-336 | wave (W1.5 × W1.7) | #737 |
| R111W1-04 | Two replicas run one erasure at once (`claim_for_purge` is idempotent): the record stays single; the SSF `account_purged` notification and the tick's error double. | Informational | `account_deletion.rs` `claim_for_purge` → T-444, T-187 | pre-existing (executor's flag) | #738 |
| R111W1-05 | Text behind the code: `cleanup.rs:595`, `:817`, `:1152-1160` keep the absolutes #688 corrects; T-472 still says a unit cut past its point of no return loses its record (W1.7 fixed it) and that the marker is `metadata.orphan_purge` (W1.1 changed it); the dead-letter join-error line still depends on the awaiter. | Informational | `cleanup.rs`, T-472, `dead_letter.rs` | wave | #739; **recommended in-wave** (comments and one dated sentence) |
| R111W1-06 | The sanitiser's boundary rule misses a token right after an escape ending in a token character (`\n`, `\u0022`, `%3D`) and a legacy token followed by `.word`. Not a regression. | Informational | `vault_forward.rs` → T-470 | residual of #665 | #740 |

**Verdict on merge.** R111W1-01 must be fixed in the wave: it is a standing cost
that grows with the deployment and lands on every replica's cleanup loop. The fix
is one statement (§2.1). R111W1-05 is comment-only and closes what #688 and #714
promise, so it is better taken before the PR than carried. Nothing else blocks.

**What held.** Every §10 rule holds for what the wave added (§3): no route, no
crate, no `CONTRACT.md` edit; one migration (v108, W1.7), additive, with its scope
test and the newest-version bump to 108; every new two-writer write is conditional
on the value read (the orphan claim's `CREATE` on the record id and on the rows
left, the three pending-record claims on the stamp read, every settle and release
on the stamp held). The five amended threat entries (T-108, T-336, T-444, T-470,
T-472) are byte-identical in `Axiam.json` and the STRIDE document, dated
2026-10-19, and the model version is unbumped (2.42.0). `sdks/openapi.json` and
the registry are untouched and in sync. W1.6's departure from the plan is right
(§5). v108's `tenant_purge_pending` cannot leak or outlive a purged tenant's data
(§6). The orphan marker can no longer be forged from an API (§4.1); the sanitiser
masks every input #665 names and leaves the two host names alone (§4.2); both
Vault clients are bounded (§4.3); no secret reaches the new dead-letter log line
(§8); the W1.10 seam is unreachable from configuration (§9).

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Orphan marker recognised by the nil organization and the slug; `orphan_purge` refused | W1.1 #664 | `tenant.rs` (`ORPHAN_MARKER_CONDITION`, both reads, the claim's `CREATE`), `handlers/tenants.rs`, every writer of `tenant.organization_id` and `slug` | read in full |
| Vault-reason sanitiser | W1.2 #665 | `vault_forward.rs` | read in full; **probed** the matcher (§13.3) |
| Vault client bounds | W1.3 #667 | `secrets.rs`, `main.rs`, `ca_key_store.rs`, `vault_pki.rs`, `vault.md` | read in full |
| Unique-serial violation → `409` | W1.4 #669 | `certificate.rs`, `ca_certificate.rs`, `classify_write_error`, both handlers | read in full |
| Second revocation after the anonymization | W1.5 #668 | `cleanup.rs` (`erase_and_record`), `certificate.rs` (`revoke_user_certificates`, `folded_names`, `BELONGS_TO_ACCOUNT`) | read in full |
| Orphan claim guarded from its `CREATE` | W1.6 #714 | `tenant.rs` (`claim_orphan_purge`, `orphan_claim_refusal`, `purge_orphan`), `tenant_purge.rs` (`purgeable_rows_condition`), `cleanup.rs` (`purge_orphan_unit`, `PurgeClaim`) | **read in full**; every exit walked (§5) |
| Pending-record markers, v108 | W1.7 #689 | `schema.rs` (v108, scope test, newest version), `user.rs` (`anonymize_user`), `account_deletion.rs` (the five erasure-record methods), `tenant.rs` (`remove_purged_tenant`, settle, release, claim, `purge_recorded_since`), `cleanup.rs` (`RecordClaim`, `PendingMarker`, `record_owed_erasures`, `record_pending_purges`, `erase_and_record`, `erasure_steps`, both purge units), `personal_data.rs` | **read in full**; **probed** the owed-erasure claim's cost (§13.1) |
| Texts of residual (iii) | W1.8 #687 | `cleanup.rs` docs, README, T-444, T-472 | read in full |
| Dead-letter failure logged in the blocking task | W1.9 #690 | `dead_letter.rs` (`append_off_thread`, `append_blocking`), `handlers/gdpr.rs`, the new test | read in full |
| Audit drain made observable | W1.10 #692 | `audit_hold.rs`, `boot.rs`, `lib.rs`, `main.rs`, `minimal_profile_boot.rs` | read in full |
| `current_at` keeps its instant; the cache's new condition | W1.11 #666 | `crl.rs` (`fresh`, `current`, `current_at`, `current_from`, `resign`, `sign`, `list_identity`), every caller of both; `vault_pki_test.rs` | read in full; **probed** the cache with a list dated ahead of the replica (§13.2) |
| Three absolutes | W1.12 #688 | T-444, README, `boot.rs`, `cleanup.rs` | read in full |
| Assertion labels | W1.13 #717 | `vault_ca_key_store_test.rs` | read in full |
| Threat model, docs | all | `Axiam.json`, STRIDE, `website/src/threatModel.ts`, README, `vault.md`, admin guide, GDPR guide | five entries compared byte for byte (§10) |

Not run: a real Vault, a multi-replica deployment, the frontend (untouched), a
`--dump-openapi` rebuild (no utoipa annotation and no handler doc comment changed:
the two handler files the wave touched, `tenants.rs` and `gdpr.rs`, changed a
`const`, a private function and a private function's doc only; the spec digest and
the registry check pass, §12).

---

## 2. Findings

### 2.1 R111W1-01 (Medium) — the owed-erasure claim re-reads the pending requests for every user row

**Where:** `crates/axiam-db/src/repository/account_deletion.rs` `claim_owed_erasure_records`, the second statement:

```sql
SELECT … FROM user WHERE meta::id(id) IN
    (SELECT VALUE user_id FROM account_deletion WHERE status = 'pending')
  AND status = 'Anonymized' AND erasure_audit_pending = NONE;
```

It is called from `record_owed_erasures`, the first step of every `sweep_pending_purges`. That runs every cleanup tick (300 s by default) on every replica, and also when `AXIAM__AUTH__GDPR_PSEUDONYM_PEPPER` is unset (the owed step runs before the pepper check). Threats: T-187 (availability of the cleanup sweeps), T-444. Introduced by W1.7 (#689 (i)).

SurrealDB evaluates the uncorrelated subquery again for every row of `user`, and `account_deletion` has no index on `status`. So each tick costs (users of every tenant) × (rows of `account_deletion`, which keeps every completed and cancelled request). This is the pattern of R110W1-01. Probe (throwaway test, in-memory engine, debug build, migrated schema, no owed erasure at all):

| users | `account_deletion` rows (1 % pending) | shipped statement | the same with the subquery in a `LET` |
|---|---|---|---|
| 2 000 | 200 | 1.43 s | 67 ms |
| 10 000 | 1 000 | 28.7 s | 324 ms |
| 20 000 | 2 000 | **112.8 s** | 683 ms |

The absolute figures are not production's; the quadratic growth is. A deployment with 100 000 users and 10 000 past deletion requests would spend many times the tick interval in this one statement, on every replica, every tick. That stalls the rest of the GDPR sweep, the tenant purge sweep and the sweeps after them, and loads the datastore every request shares. No attacker is needed: deletion requests only accumulate.

**Proposed fix:** read the pending requests once and look their users up by record id, so the cost is O(pending requests) and not O(users):

```sql
LET $pending = (SELECT VALUE user_id FROM account_deletion WHERE status = 'pending');
SELECT meta::id(id) AS record_id, tenant_id, username, erasure_audit_pending AS stamp
  FROM array::map($pending, |$u| type::record('user', $u))
  WHERE status = 'Anonymized' AND erasure_audit_pending = NONE;
```

At least hoist the subquery into a `LET`, which is linear in users. The take index moves from 1 to 2. The first statement (`erasure_audit_pending != NONE AND <= $cutoff`) uses `idx_user_erasure_audit_pending` and is cheap (4 ms at 20 000 users).
**Test:** in the style of `the_retention_batch_reads_the_tenant_table_once` (`certificate_repository_test.rs`). Seed 20 000 users and 2 000 `account_deletion` rows (a few pending, one of them for an anonymized account without a marker). `claim_owed_erasure_records` comes back within a few seconds and claims exactly that account; `cleanup_task.rs`'s `a_pending_request_whose_account_is_anonymized_is_completed_and_recorded_once` still passes.

**Why Medium.** The same severity as R110W1-01, for the same reasons: it needs no
attacker, it is reached by ordinary growth (every deletion request, completed or
cancelled, stays in `account_deletion` until its tenant is purged), it runs on every
replica every tick, and it delays the sweeps the GDPR and tenant-deletion promises
rest on (T-187). It is not High: no data is exposed or lost, and the work it delays
is done once the statement returns.

### 2.2 R111W1-02 (Low) — the CRL cache refuses its own list while the datastore clock leads

Milestone: **1.1.x** (Low finding of the release 1.1.1 wave W1 F4 review, `claude_dev/security-review-release-1.1.1-w1-2026-10-19.md`, finding R111W1-02, on `claude/release-1.1.1-w1`; introduced by W1.11, #666).

**Where:** `crates/axiam-pki/src/crl.rs`: `CaSlot::fresh` (the new `cached.crl.this_update <= now`), `resign` (the joiner's re-check), `list_identity`. Threats: T-102 (CRL availability), T-187.

W1.11 made `current_at` keep a past instant, and added a condition to the cache: a cached list is served only if its `thisUpdate` is not later than the instant asked about. The condition applies to `current()` too, whose instant is the replica's wall clock. But `thisUpdate` is derived from the newest revocation date on the list (`list_identity`), and that date is written by the **datastore's** clock (`revoked_at = time::now()`). The code's own docs say this clock "may be ahead of the replica's".

So after every revocation, for as long as the datastore's clock leads the replica's (up to the epoch's end), the cached list is never fresh for `current()`. Every request to the unauthenticated CRL endpoint then:
- re-signs the list: a crypto permit, the CA key read from its custodian (Vault KV under `vault` custody), a signature (RSA-4096 for an RSA CA);
- or, when the gate is saturated, answers `503` where the cached list used to answer;
- if it is a joiner, loops: wakes, finds the landed list "not fresh", and leads the next flight.

Probe (throwaway test on the `crl_test` fixture, a revocation dated 20 s ahead): with every permit held, the next `current()` failed (`ServiceUnavailable`) where the control (a normal revocation) was served from the cache; over 2 s the CA answered 149 requests, each a re-sign, against 308 cached answers for the control (Ed25519, debug build). Before W1.11 the cache served both.

The window is the clock lead, typically well under a second, rounded by `thisUpdate`'s whole seconds. A lead of seconds (a drifting NTP) turns every CRL fetch in that window into a signature. No production caller uses `current_at` (tests only).

**Proposed fix:** apply `this_update <= now` only to a named instant. Pass `follow_clock` to `fresh` and skip the condition when it is set, which is the pre-W1.11 behaviour for `current()`. The joiner's re-check in `resign` then serves the landed list.
**Test:** `crl_test.rs`: a revocation dated 20 s ahead (an `UPDATE` of `revoked_at`). `current()` once, then with every permit held, `current()` again answers the cached bytes. `current_at` of a past instant still signs at that instant (`current_at_signs_a_past_instant_at_that_instant` unchanged).

### 2.3 R111W1-03 (Low) — what the recovery of a cut erasure does not redo

Milestone: **1.1.x** (Low finding of the release 1.1.1 wave W1 F4 review, `claude_dev/security-review-release-1.1.1-w1-2026-10-19.md`, finding R111W1-03, on `claude/release-1.1.1-w1`; Low and Informational findings go to the next patch milestone).

**Where:** `crates/axiam-server/src/cleanup.rs` — `erasure_steps` (anonymization, then the erasure proof), `erase_and_record` (the guard armed after `erasure_record_stamp`, then the #668 second revocation, then the record), `record_owed_erasures` (the recovery). Threats: T-444 (#689 amendment), T-336 (#668 amendment). From W1.5 (#668) and W1.7 (#689).

W1.7 makes the next start write `gdpr.user_pseudonymized` for an erasure cut past its point of no return (the anonymization). The recovery writes only that row and completes the request. Three parts of the erasure's tail sit between the anonymization and the record, and the recovery redoes none of them:

(a) **The erasure proof.** `erasure_steps` writes the PII-free erasure proof *after* `anonymize_user`. A unit cut there (the teardown's bound), or whose proof `create` fails (a datastore error, after which `erase_and_record` returns `Err`), leaves the account anonymized and marked, with no proof. The sweep then records the erasure (`recovered: true`) and completes the deletion request, but never writes the proof. Before W1.7 the request stayed pending, which at least showed the erasure was unfinished. Now it reads as completed, with no proof behind it. The deployment guide says "The erasure and its proof, or the purge, stand".

(b) **The #668 second revocation.** A unit cut between the anonymization and `revoke_user_certificates(…, "", "", …)` is recovered without that pass. A certificate bound to the account between (b4) and the anonymization then stays active, which T-336's 2026-10-19 amendment says can no longer happen. This needs a stop and an issuance racing in the same window, so it is narrow.

(c) **The guard window.** The erasure's `RecordClaim` is armed only after the proof write and `erasure_record_stamp` return. A cut in between leaves the marker with the unit's fresh stamp and no guard to release it, so it is recorded only after the one-hour lease, not "at the next start". T-444 says "a unit that is cut releases the marker from the guard".

No record is lost and none is doubled; what goes missing is evidence (the proof) and one revocation.

**Proposed fix:** in `record_owed_erasures`, for each claimed account: (1) write the erasure proof unless one exists for `(tenant_id, user_id)` (the unique index makes a lost race harmless; the pseudonym is on the row; `erased_at` from the marker or now); (2) run `revoke_user_certificates(tenant_id, user_id, "", "", …)` once more (idempotent); then record and settle as today. Arm the unit's guard from a stamp the unit chooses and passes to `anonymize_user` (as the orphan unit does since #714), rather than from a read-back after the proof. Amend T-444 and T-336 and the guide's sentence.
**Test:** `cleanup_task.rs`: a unit held at a new step between the anonymization and the proof, cut at the teardown's bound. The next start's sweep writes the proof and the record once and completes the request, at once (not after the lease). A certificate bound to the account at that step is revoked by the recovery.

### 2.4 R111W1-04 (Informational) — two replicas erasing one account

Milestone: **1.1.x** (Informational finding of the release 1.1.1 wave W1 F4 review, `claude_dev/security-review-release-1.1.1-w1-2026-10-19.md`, finding R111W1-04, on `claude/release-1.1.1-w1`; flagged by the W1.7 executor, pre-existing).

**Where:** `crates/axiam-db/src/repository/account_deletion.rs` `claim_for_purge` (`purge_claimed_at = purge_claimed_at ?? $now`, idempotent by design); `crates/axiam-server/src/cleanup.rs` `sweep_pending_purges` / `ErasureUnit::purge`. Threat: T-444, T-187.

Every replica runs the GDPR purge sweep. Two sweeps that read the same due account both pass `claim_for_purge` and both run its erasure unit. The audit record stays single: the erasure proof's unique index fails the later unit after its anonymization and before its record, and the #689 marker is settled once (by the unit, or by a later sweep that finds the record written). Everything before the proof runs twice:
- the revocations and the audit scrub (idempotent);
- the anonymization (same pseudonym);
- the SSF `account_purged` notification, which receivers get twice;
- the losing unit reports an error for its tick on `/health/jobs`.

No data is lost, no record is doubled, and no protection is weakened.

**Proposed fix:** make the claim exclusive with a lease, as the tenant purge's is. `claim_for_purge` takes the request when `purge_claimed_at` is NONE or older than a lease, stamps it with the claimant's `now`, and answers `false` to a second claimant. The lease must cover an erasure without a request row too, e.g. a stamp on the user row. Release the claim on every exit before the point of no return. Treat the proof's unique violation as "another unit erased it", not an error.
**Test:** `cleanup_task.rs`: two sweeps over one store, run at once against one due account. One unit erases it, the other skips without an error, and the SSF sink sees one `account_purged`.

### 2.5 R111W1-05 (Informational) — text behind the code

Milestone: **1.1.x** (Informational finding of the release 1.1.1 wave W1 F4 review, `claude_dev/security-review-release-1.1.1-w1-2026-10-19.md`, finding R111W1-05, on `claude/release-1.1.1-w1`; §1.3 of the release-1.1.1 plan: a task is not done while a text says what the tree no longer does).

Text behind the code after the wave:

(a) **#688 (a) and (b), in `crates/axiam-server/src/cleanup.rs`.** #688 names these sites itself (`cleanup.rs:440/444`, `:1382/1390` at the time). W1.12 rewrote T-444, the guide and `boot.rs`, and left:
- `:595` and `:817`: "The point of no return is never crossed once the process is stopping."
- The `AuditedWork` doc at `:1152-1160`: "a replica that lost its lease writes nothing after its stop's budget" and "it never crosses it once the stop is requested".

Word them as #688 does: "starts no new crossing once the stop is requested (a crossing already being sent completes)", and "writes nothing of its own code after its budget; a statement already sent may still commit".

(b) **T-472** (STRIDE and `Axiam.json`):
- The #714 amendment ends "What remains is T-444's: … and a unit cut past its point of no return loses its record". W1.7 (#689) made that untrue: the next start records it.
- The 2026-10-14 correction still says the orphan marker is "marked `metadata.orphan_purge`", and no later note records #664 (W1.1): the marker is now recognised by the nil organization id and the `orphan-purge-<id>` slug, and the key is refused in tenant metadata (`422`).

(c) **The dead-letter join-error line (#690).** The `append_off_thread` doc and the commit say the failure line "does not depend on the caller". That is true of an I/O failure, which is logged inside the closure. The join-error branch (a panicking write task) is logged by the awaiter, so it is still lost when the awaiter was cut; only the panic hook prints then. Say so, or log the panic inside the closure with `catch_unwind`.

**Proposed fix:** the three comments of (a); one dated correction sentence on T-472 in both files (no version bump; W8.3 reconciles); one sentence in the `append_off_thread` doc.
**Test:** none (text); `check-remediation-evidence.py` and `check-doc-links.sh`.

### 2.6 R111W1-06 (Informational) — the sanitiser after an escape sequence

Milestone: **1.1.x** (Informational finding of the release 1.1.1 wave W1 F4 review, `claude_dev/security-review-release-1.1.1-w1-2026-10-19.md`, finding R111W1-06, on `claude/release-1.1.1-w1`; residual of #665, not a regression).

**Where:** `crates/axiam-pki/src/vault_forward.rs` (`redact_tokens`, `token_len`). Threat: T-470.

Since #665 a token is masked at any position whose previous character is not a token character (`[A-Za-z0-9_.-]`). Every input #665 names is masked, and `b.vault-internal.example.com` and `s.vault-1.eu-west.internal` stay intact (probe). Two cases still pass unmasked:
- A token right after an escape sequence that ends in a token character: `msg\nhvs.CAES…`, `\u0022hvs.CAES…`, `token%3Dhvs.CAES…`. This is the form a JSON-escaped or URL-encoded reason would take if Vault ever echoed one.
- A legacy `s.`/`b.` token followed by `.word` (`s.AbCdEfGh1234.next`), which the host-name rule now reads as a host.

The old whole-word matcher missed all of these too. The sanitiser is defence in depth: Vault does not echo the caller's token.

**Proposed fix:** also treat as a boundary the end of a recognised escape (`\n`, `\t`, `\r`, `\"`, `\uXXXX`, `%XX`) immediately before `hvs.`/`hvb.`/`hvr.`. The modern prefixes are distinctive enough that `[A-Za-z0-9]hvs.` followed by eight or more body characters can be masked with the preceding escape kept. Leave the legacy-prefix trade-off as documented in T-470.
**Test:** unit cases in `vault_forward::tests` for the three escapes; the host-name cases stay intact; idempotence holds.

---

## 3. The §10 rules, against what the wave added

| Rule | Held? | Evidence |
|---|---|---|
| Signed commit per item | yes | 13 of 13 carry `gpgsig` |
| A test per fix, in the same commit | yes | every code commit adds or tightens the test its row names; W1.12 is text only and names its checker |
| Documents moved with the code | **partly** | R111W1-05: three `cleanup.rs` comments and the tail of T-472 still say what the tree no longer does |
| Threat-model entries in both files, dated, no version bump | yes | §10 |
| `sdks/CONTRACT.md` untouched | yes | `git diff --stat 6b15aa36a..HEAD -- sdks/ proto/` is empty |
| Only W1.7 adds a migration, v108 | yes | `schema.rs` is touched by `140911a21` alone; v108 follows v107; the newest-version assertion reads 108 |
| v108 additive, scope test | yes | `IF NOT EXISTS` only; `v108_adds_only_the_pending_record_markers` pins the nine statements and forbids `UPDATE`, `REMOVE`, `DELETE`, `OVERWRITE`, `DEFAULT` and `tenant_id`; no backfill |
| No new crate; layering | yes | `check-crate-layering.py` exit 0 (19 crates) |
| No new route; credential-bearing requests | yes | no route; the only outbound change is W1.3's bounds on two clients that keep `Policy::none()` |
| Every two-writer write conditional | yes | §5, §6 |
| No `[lints] workspace = true` added | yes | only `axiam-audit/Cargo.toml` changed (a dev-dependency) |

---

## 4. The smaller tasks

### 4.1 W1.1 (#664) — confirmed

The marker is now `organization_id = <nil> AND slug = 'orphan-purge-' + id`.
`organization_id` comes from the URL path on create (`handlers/tenants.rs`), is not
in `UpdateTenant`, and every organization id is a server-generated v4 UUID, so no
API writes the nil one; the slug alone would not do, the pair does. Markers written
by 1.1.0 carry both (the slug and the nil id were already set), so a marker in
flight across the upgrade is still recognised. The `422 reserved_metadata_key` is
belt and braces (the key is no longer read). Tests pin both directions.

### 4.2 W1.2 (#665) — confirmed, with an Informational residual (R111W1-06)

Every input #665 names is masked, the span only: `token=hvs.…`,
`{"token":"hvs.…"}`, `"hvs.…".`, `X-Vault-Token:hvs.…`, an escaped `\"hvs.…\"`;
`b.vault-internal.example.com` and `s.vault-1.eu-west.internal` stay intact
(probe, §13.3). The scan is linear (a boundary exists only after a non-token
character, and each run is read once from it). What the boundary rule cannot see
is a token right after an escape that ends in a token character — `\nhvs.…`,
`"hvs.…`, `%3Dhvs.…` — and a legacy token followed by `.word`, which the
host-name rule now reads as a host. The old matcher missed all of these too: no
regression, a residual (R111W1-06).

### 4.3 W1.3 (#667) — confirmed

`vault_client_builder(timeout)` sets `Policy::none()`, `timeout` and
`connect_timeout(min(5 s, timeout))`; the bootstrap client and the private-CA client
both take `VAULT_TIMEOUT` (10 s), compiled in. `bootstrap_client_with_timeout` is a
`pub` test helper; `main.rs` calls `bootstrap_client()`. The error names the URL and
`(timed out)`, never the token. The table in `vault.md` §5.8 matches
`ca_key_store.rs:163` (10 s) and `vault_pki.rs:73` (60 s).

### 4.4 W1.4 (#669) — confirmed; the `409` is a W7.1/W8.2 note, not a finding

Both `create`s now classify at `check()`, where the unique violation is raised.
`classify_write_error` also turns a write conflict into `Conflict` (`409`) where it
was `Migration` (`500`) — a better answer for a retryable race. The
`(issuer_ca_id, serial)` collision is unreachable with W1.9's random serials
(159 bits) and Vault's own; the `409` is a datastore-integrity answer, not one a
client can provoke. Like the tenant handlers' undeclared `409` (slug) and `400`s,
neither the certificate routes' `409` nor W1.1's `422 reserved_metadata_key` is in
the utoipa annotations, so neither is in `sdks/openapi.json`: the spec has never
declared these handlers' refusals. Not a security finding; recorded for W7.1 (the
contract's tenant section may name `reserved_metadata_key`) and W8.2.

### 4.5 W1.5 (#668) — confirmed, with a gap in W1.7's recovery (R111W1-03)

The second pass passes empty names; `folded_names` drops them, so `$unambiguous` is
empty and only `user_id` and `metadata.user_id` match — never a name. It runs after
`anonymize_user` (whose row the issuance re-check then reads as erased), so the
window is closed from both sides for a unit that runs to its record. A unit cut
between the anonymization and that pass is recovered by W1.7's sweep, which does not
run the pass again (R111W1-03 (b)).

### 4.6 W1.8 (#687) — confirmed

The three texts now name the unit cut at the stop's bound beside the `SIGKILL`; the
test cuts a unit on its own runtime, drops the runtime, and finds the claim still
set and skipped until the lease. The plan-vs-tree note (a unit held with the stop
set gives itself up, so the test holds it with the stop unset) is right.

### 4.7 W1.12 (#688) — confirmed in the files the row names; three comments left (R111W1-05)

T-444, the README and `boot.rs` carry the three sentences as #688 words them. #688
(a) names `cleanup.rs:440/444` and `:1382/1390` — the very sites whose comments
still say it: `cleanup.rs:595` and `:817` ("The point of no return is never crossed
once the process is stopping"), and the `AuditedWork` doc at `:1152-1160` ("writes
nothing after its stop's budget", "never crosses it once the stop is requested").
The executor left them as "outside the row's files". §1.3 says a task is not done
while a document says what the tree no longer does, and the PR closes #688. These
are comments, not a document an operator reads, and the code is right; filed
Informational with the other text items (R111W1-05), with the recommendation that
the wave take the comment-only fix before the PR (§0).

### 4.8 W1.13 (#717) — confirmed; the remaining `{msg}` sites are not leak checks

The six labelled sites are the ones whose condition is a leak check: they formatted
the message exactly when it held the fixture token or PEM. The remaining
`{msg}`/`{err}` sites (lines 117, 125, 127, 147, 148, 217-219, 239, 254, 331, 339,
385, 433) assert what the message *does* contain ("403", "just vault-policy", a
path, a field name), and print it when it does not. They would print the token
only if two defects coincided (the expected text missing and the token present),
the values are fixtures, and none of these variables carries a name CodeQL's
sensitive-data heuristic matches (the alert of `057a9c5a2` was on
`certificate.subject`; #717 itself was found by reading, not by an alert). I
expect CodeQL to stay quiet; this sandbox cannot read code-scanning alerts
(`GET …/code-scanning/alerts` → 403), so the row's oracle, "CodeQL quiet on the
PR", is W8's to read on the pull request. Not a finding.

---

## 5. W1.6 (#714) — the plan's clause, and double or lost records (orchestrator point 1)

**The executor's argument is right, and the clause it declined was an alternative,
not a requirement.** #714's own text offers two fixes joined by "or": hold the
guard from the `CREATE`, *or* record nothing when a taken-over marker's report
removed nothing. The plan row wrote "and". The second fix is wrong on its own
terms: a unit that removed every row and then gave itself up at the stop, before
removing its marker (`purge_orphan_unit`: `None` from `until_stopped` after the
rows, or the `stopping()` check before `remove_purged_tenant`), releases its claim
and leaves a marker with nothing left to remove. The takeover's report then
removes nothing, and under that rule the purge of real data would go unrecorded —
a lost `tenants.purged`, which the append-only log cannot recover. The executor
took the first fix and made the case the second targeted (a stale scan's marker)
impossible instead.

**Double record.** A marker is now written only by `IF <rows left> { CREATE … }` in
one statement, hence one transaction. A stale scan whose id another replica has
purged and recorded reads no row and writes nothing. Against a purge in flight, the
two transactions both write `tenant:<id>` (the stale claim's `CREATE`, the purge's
final `DELETE`), so the engine's write-write conflict check orders them: the claim
either sees the marker and fails on the existing id, or runs after the `DELETE`,
whose transaction followed every row deletion, and sees no row. Only the call whose
`DELETE` removed the marker records (`remove_purged_tenant` returns `NotFound` to
the other), and since W1.7 that `DELETE` writes `tenant_purge_pending` in the same
transaction, so even a cut after it records once (§6). No double record remains.

**Lost record.** Every exit after the `CREATE` either removes the marker (recorded
by the remover) or releases the claim (the tombstoned sweep takes the marker over at
once and records it, with whatever counts are left). The guard is armed before the
claim's `await`, keyed by the stamp the `CREATE` will write, and its release is
`UPDATE … WHERE purge_claimed_at = $claimed_at`: a no-op when the `CREATE` did not
land, on SurrealDB 3, where `UPDATE` of a missing record id creates nothing. The
remaining loss is T-444 (iii): a release the process exit prevents waits out the
lease, and is still recorded then.

**Cost.** `purgeable_rows_condition` evaluates one `LIMIT 1` read per table (no
short-circuit, about 60) inside the claim's write transaction, once per orphan id
per daily scan. Acceptable.

---

## 6. W1.7 (#689) — v108, the markers, and two replicas (orchestrator points 2 and 3)

**Additive and scoped.** v108 is nine `IF NOT EXISTS` definitions: one optional
`user` field and its index, one `SCHEMAFULL` table with six fields. Its scope test
pins the list and forbids every rewriting keyword and `tenant_id`; the
newest-version assertion is 108; no `UPDATE` backfill (a row written before reads
`NONE`, nothing owed). `personal_data::USER_COLUMNS` declares the field, so the
personal-data gate stays green.

**`tenant_purge_pending` cannot outlive or leak a purged tenant.** The row holds
the tenant id (as its record id), `orphan`, the export time, two counts,
`purged_at` and `claimed_at` — what `tenants.purged` says, and nothing of the
tenant's data or of any person. It has no `tenant_id` field, so no tenant read, no
tenant export and the orphan scan never see it, and `every_tenant_scoped_table_is_purged`
is not tripped. It is created only in the transaction whose `DELETE` removed the
tenant row and deleted by the settle (conditional on the claim) once the record is
written; a dead-lettered record counts as written. A sweep that fails to check it
releases it for the next pass. So a marker lives from the removal to the first
sweep that can record it; it cannot accumulate, and it outlives the tenant only by
that interval, by design. One edge: a second purge of the same id while the first
marker still stands (an orphan id whose rows reappeared) fails its whole
transaction on the existing marker; the tenant row stays, the claim is released,
and the next pass — which records and clears the old marker first — completes it.
Self-healing.

**The erasure marker.** `anonymize_user` sets `erasure_audit_pending = time::now()`
in its own transaction; only `cleanup.rs` calls it in production (the other hits
are trait stubs and tests), so no other path leaves a marker to be "recovered".
Both clocks agree where they must: `purged_at` and the audit row's `timestamp` are
both the datastore's `time::now()`, so `purge_recorded_since` cannot miss the
unit's own record to a clock skew. The erasure's stamp is the datastore's and the
claim's cutoff is the application's; a skew would have to approach the one-hour
lease to matter.

**Two replicas erasing one account at once (the executor's flag): Informational,
pre-existing, filed (R111W1-04).** Every replica runs the GDPR sweep, and
`claim_for_purge` is idempotent by design (`purge_claimed_at ?? $now`), so two
sweeps that read one due account both run its unit. The record stays single: the
erasure proof's unique index fails the later unit after its anonymization and
before its record, and the marker settles once (the executor's trace is correct).
What doubles is everything before the proof: the revocations (idempotent), the
audit scrub (idempotent), the anonymization (the same pseudonym), and the SSF
`account_purged` notification, which receivers get twice; the loser also reports
an error for the tick. No data is lost, no record doubled, and no protection
weakened, so Informational.

**The recovered row's `certificates_revoked: null` (orchestrator point 3, for the
record only — not answered here).** The code's choice is safe: the count lived only
in the cut unit's memory, and `null` with `recovered: true` says "unknown", where
any number would be a fabrication in an append-only record. A consumer that
requires an integer must treat the field as nullable. Whether CONTRACT ~l.9261
("carries the count") is reworded is W7.1's.

The cost of the sweep's new claim and the parts of the erasure tail the recovery
does not redo are §2's R111W1-01 and R111W1-03.

---

## 7. W1.11 (#666) — `current_at`, and the cache's new condition (orchestrator point 6)

`current_at` has no production caller: `grep` finds it only in `crl_test.rs`. The
REST CRL endpoint and every other caller use `current()`, which still advances to
the clock (`follow_clock = true`). The Art. 17 purge's revocations (W1.5) write
`revoked_at` and never sign a list. So no wall-clock caller signs at a stale
instant. The cache's new condition, `cached.crl.this_update <= now`, applies to
`current()` too, and that is R111W1-02 (§2).

---

## 8. W1.9 (#690) — the dead-letter log line (orchestrator point 9)

The closure logs `error = %e` (an `io::Error` from `append_blocking`: open, write,
fsync, size) and the path. The record is serialised before the write and nothing
formats it into an error; `append_blocking` has no `unwrap`, `expect` or index that
could panic with record content. The join-error branch formats tokio's `JoinError`,
whose `Display` carries a panic message, and there is none to carry. No secret or
record content reaches either line. The dispatcher is captured at the call
(`get_default(Dispatch::clone)`) and entered with `with_default` inside the
closure, so the line goes where the caller's logs go. One precision for the text
(R111W1-05): the join-error line is written by the awaiter, so it still depends on
the awaiter being there; a panicking write task prints only through the panic hook
when the awaiter was cut.

---

## 9. W1.10 (#692) — the test seam (orchestrator point 5)

`ServeOptions` is not `Deserialize`; `main.rs` builds it with `ServeOptions::default()`
(`audit_hold_for_tests: None`); no environment variable, configuration key or Cargo
feature sets the field. Reaching it takes Rust code that embeds `axiam_server` as a
library and calls `serve` with it, which can already replace the whole audit
repository. It follows the two seams already there (`cleanup_step_for_tests`,
`admit_private_networks_for_tests`). `audit_hold::HeldAuditLog` is `pub(crate)`;
the public surface is a type alias. A `#[cfg(test)]` gate is impossible
(integration tests link the non-test library) and a feature gate would buy nothing
a deployment can reach. Not a finding. The global ERROR-capturing subscriber in
`minimal_profile_boot` is test-binary-only; tests in that binary that install
their own subscriber with `with_default` still see their own, and the binary
passes (§12).

---

## 10. Threat-model text against the code (§1.3)

| Entry | Task | Text matches the code? |
|---|---|---|
| T-108 | W1.9 | yes; also regenerated into `website/src/threatModel.ts` by W1.9 alone (the other four entries are not), which W8.3's regeneration evens out |
| T-336 | W1.5 | yes for a unit that runs to its record; "that residual closes" is not quite true of a unit cut between the anonymization and the second pass (R111W1-03 (b)) |
| T-444 | W1.6, W1.7, W1.8, W1.12 | the #689 amendment says "a unit that is cut releases the marker from the guard"; an erasure arms its guard only after the proof write and the stamp read (R111W1-03 (c)) |
| T-470 | W1.2 | yes |
| T-472 | W1.6, W1.11 | the #666 retention basis is right; the #714 amendment ends "a unit cut past its point of no return loses its record", which W1.7 then made untrue, and the 2026-10-14 text still says the marker is "marked `metadata.orphan_purge`" with no later note of #664 (R111W1-05) |

All five are byte-identical between `Axiam.json` and the STRIDE document (a
script compared every 2026-10-19-dated mitigation of the JSON against the
Markdown), and the model stays at 2.42.0.

---

## 11. Executors' follow-ups and plan-vs-tree notes, confirmed or rejected

| Task | Note | Verdict |
|---|---|---|
| W1.3 | no Vault rows in `README.md`; the table went to `vault.md` §5.8 with a pointer | confirmed |
| W1.4 | the CA test already lived in `certificate_repository_test.rs`; the violation is raised at `check()` | confirmed |
| W1.5 | the pass lives in `erase_and_record`, not `ErasureUnit::purge` | confirmed: it is the unit's tail and testable there |
| W1.6 | "a taken-over marker whose report removed nothing records nothing" not taken | **confirmed** (§5); the plan conjoined two alternatives |
| W1.6 | the test holds the unit at `OrphanClaimed`, `has_purgeable_rows` being gone | confirmed |
| W1.7 | the marker is set for every erasure, not only those without a request row | confirmed: a request row alone cannot be claimed against the erasure in flight |
| W1.7 | two replicas can run one erasure concurrently | confirmed, Informational, filed (R111W1-04) |
| W1.7 | the dead-letter replay residual | confirmed; documented in T-444 and the guide |
| W1.8 | the test holds the unit with the stop unset | confirmed (§4.6) |
| W1.9 | `tracing-subscriber` is a new dev-dependency of `axiam-audit` | confirmed; dev only, already in the lock |
| W1.11 | the past-instant test lives in `tests/crl_test.rs` | confirmed (it needs the datastore fixture) |
| W1.12 | README line 1850 stale; `cleanup.rs` 595, 817, 1160 left | the first confirmed; the second is R111W1-05 |
| W1.13 | line 130 folded in; six sites, not five | confirmed |

**Plan vs tree.** The plan names `main` at `6b7b258`; the branch's base is
`6b15aa36a`, which carries the plan itself. The row line numbers of W1.6, W1.7 and
W1.12 were stale, as their commits say. The plan row of W1.6 conjoined #714's two
alternatives (§5). The tree wins in each case.

---

## 12. Checks run

Every tool's own exit code is shown (redirected to a log, `$?` tested). The flags
were `CARGO_INCREMENTAL=0` and `line-tables-only` debug info, with `cargo clean`
between crates. The swagger placeholder was set and `protoc` installed.
`axiam-api-rest` ran in six batches of up to 20 test binaries: the whole suite
does not fit the sandbox's disk quota at once (a first unbatched run died at link
time with `ENOSPC`).

| Command | Exit | Counts |
|---|---|---|
| `cargo test -p axiam-core --lib` | 0 | 1 binary, 524 passed |
| `cargo test -p axiam-db` (every binary) | 0 | 86 binaries, 1 095 passed, 0 failed, 5 ignored (`tenant_purge_test` 12, `certificate_repository_test`, `ca_certificate_repository_test`, the `schema` unit tests with `v108_adds_only_the_pending_record_markers`) |
| `cargo test -p axiam-auth` | 0 | 20 binaries, 461 passed, 0 failed, 3 ignored (`vault_provider_test` 13) |
| `cargo test -p axiam-pki` | 0 | 18 binaries, 369 passed, 0 failed, 2 ignored (`crl_test` 20, `vault_pki_test` 34, `vault_ca_key_store_test` 15, lib 149) |
| `cargo test -p axiam-audit` | 0 | 6 binaries, 75 passed, 0 failed, 1 ignored (`dead_letter_failure_log` 1) |
| `cargo test -p axiam-api-rest --no-default-features` (6 batches, `--lib` and all 111 test files) | 0, **101**, 0, 0, 0, 0 | 112 binaries, 1 917 passed, **15 failed**, 3 ignored (`tenant_test` 25, `certificate_test` 17, `ca_certificate_test` 17, `crl_test` 5, `gdpr_*` 33). The 15 failures are all in `federation_test`, all SAML routes answering `404` where `400`/`401`/`200` is asserted: with `--no-default-features` the `saml` feature is off and the routes are not registered. The wave does not touch federation. |
| `cargo test -p axiam-api-rest --test federation_test` (default features, `libxml2-dev`/`libxmlsec1-dev` installed) | 0 | 87 passed, 0 failed: the 15 above pass with SAML on |
| `cargo test -p axiam-server --no-default-features` | 0 | 28 binaries, 330 passed, 0 failed (`cleanup_task` 51, `minimal_profile_boot` 11, `req14_gdpr_test` 5) |
| `cargo clippy -p axiam-core -p axiam-db -p axiam-auth -p axiam-pki -p axiam-audit -p axiam-api-rest -p axiam-server --no-default-features --lib --tests -- -D warnings` | 0 | clean |
| `cargo fmt` on the same seven crates, `--check` | 0 | clean |
| `python3 scripts/check-remediation-evidence.py` (after `git fetch --unshallow`) | 0 | 5 verified, 0 failed, 32 skipped (SDK repositories unreachable: 403) |
| `bash scripts/check-doc-links.sh` | 0 | 535 links across 78 files |
| `python3 scripts/check-crate-layering.py` | 0 | 19 crates, all edges inward |
| `python3 scripts/check-spec-digest.py` | 0 | digest matches |
| `python3 scripts/gen-management-registry.py --check` | 0 | 202 operations in sync |
| `python3 scripts/check-conflict-markers.py` | 0 | — |
| `git cat-file -p <c> \| grep -c gpgsig` for the 13 commits | — | 1 each |

Not run: a `--dump-openapi` rebuild (§1); CodeQL (§4.8).

---

## 13. Probes

Each was a throwaway test file, run and then deleted. None is in this commit.

### 13.1 The owed-erasure claim (R111W1-01)

`crates/axiam-db/tests/zz_probe_w114.rs` (deleted): an in-memory datastore with the
migrated schema; N users (`status = 'Active'`, so nothing is owed) and M
`account_deletion` rows (1 % `pending`, the rest `completed`, user ids unrelated);
`claim_owed_erasure_records(now, 1 h)` timed against the same second statement with
its subquery hoisted into a `LET`, and the first statement alone. Debug build.

| N users | M requests | shipped | hoisted | first statement |
|---|---|---|---|---|
| 2 000 | 200 | 1.43 s | 67 ms | 3.9 ms |
| 10 000 | 1 000 | 28.7 s | 324 ms | 3.7 ms |
| 20 000 | 2 000 | 112.8 s | 683 ms | 4.3 ms |

Each call claimed nothing (`owed = 0`). Multiplying both N and M by 5 multiplied
the shipped time by about 20 and the hoisted time by about 5.

### 13.2 The CRL cache with a list dated ahead of the replica (R111W1-02)

A copy of `crates/axiam-pki/tests/crl_test.rs` with two added tests (deleted).
A root CA (Ed25519), one leaf revoked, its `revoked_at` set to `time::now() + 20s`.
`current()` signed a list with `thisUpdate` 20 s after the replica's clock. Then,
with every crypto permit held, `current()` failed (`ServiceUnavailable`); the
control (a revocation dated normally) answered from the cache. Over 2 s of serial
`current()` calls the first CA answered 149 (each a re-sign), the control 308.

### 13.3 The sanitiser (R111W1-06; W1.2 confirmed)

A line-for-line Python port of `redact_tokens` / `token_len` (`is_token_char`,
`is_legacy_body_char`, `MIN_TOKEN_BODY = 8`), fed the inputs below.

| Input | Output |
|---|---|
| `token=hvs.CAESIAbcdefghijklmnop012345` | `token=[redacted]` |
| `{"token":"hvs.…"}` | `{"token":"[redacted]"}` |
| `"hvs.…".` | `"[redacted]".` |
| `X-Vault-Token:hvs.…` | `X-Vault-Token:[redacted]` |
| `\"hvs.…\"` (escaped quotes) | `\"[redacted]\"` |
| `b.vault-internal.example.com`, `s.vault-1.eu-west.internal`, `b.vaultinternal.example.com` | unchanged |
| `hvs.abc.def.ghi.jkl` | `[redacted]` |
| `msg\nhvs.…`, `\u0022hvs.…`, `token%3Dhvs.…` | **unchanged** (R111W1-06) |
| `s.AbCdEfGh1234.next` | **unchanged** (read as a host) |
| `s.longhostname1` | `[redacted]` (a one-label host masked: the safe side) |


---

## 14. Issues filed

All on `ilpanich/axiam`, milestone `1.1.x`, for 1.1.2. The body of each is the
corresponding subsection of §2, with the issue footer.

| Finding | Severity | Issue |
|---|---|---|
| R111W1-01 | Medium | not filed: fixed in the wave (§2.1 is the fix executor's brief) |
| R111W1-02 | Low | #736 |
| R111W1-03 | Low | #737 |
| R111W1-04 | Informational | #738 |
| R111W1-05 | Informational | #739 |
| R111W1-06 | Informational | #740 |

No duplicate existed: the open `1.1.x` issues were read first, and none of
#664 … #740 names these defects (the W2, W4 and W5 reviews' `R111Wn-nn` issues
concern other surfaces).

## 15. Notes for W7.1 and W8

- **CHANGELOG (W8.4).** v108 (`user.erasure_audit_pending`, `tenant_purge_pending`).
  The next start records a unit cut past its point of no return. A recovered
  `gdpr.user_pseudonymized` carries `recovered: true` and `certificates_revoked:
  null`. `orphan_purge` is refused in tenant metadata with `422
  reserved_metadata_key`. A repeated certificate serial is a `409`. The startup
  Vault read now fails after 10 s instead of hanging.
- **Upgrade note.** A tenant whose metadata already carries `orphan_purge` keeps
  it; only a create or update that sends it is refused. Nothing reads the key.
- **Contract (W7.1).** `certificates_revoked` of a recovered row is `null`
  (orchestrator point 3, recorded in §6, not answered here). The tenant section
  could name `reserved_metadata_key`.
- **Spec (W8.2).** The `422` and the `409` are not in the utoipa annotations (§4.4).
- **W8.3.** Regenerate `website/src/threatModel.ts`: W1.9 regenerated T-108 alone.
  Carry R111W1-05 (b) into T-472 if the wave has not taken it.
- **W8.** The row oracle of W1.13, "CodeQL quiet on the PR", has to be read on the
  pull request (§4.8).

