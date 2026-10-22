# Security review — release 1.1.2, wave W1 (F4)

**Date:** 2026-10-22.
**Against:** `claude/release-1.1.2-w1`, the whole wave diff `dc5bfd4..61615fb` (6 commits,
26 files, 2 454 lines added and 460 removed): `cff763d` (W1.2, #738), `74a1457` (W1.1, #737),
`a5b54f2` (W1.3, #753), `23f03a4` (W1.4, #736), `048146a` (W1.5, #740) and `61615fb` (W1.6,
#758 (e), (f)). W1.7 (#739) made no commit: its three text items were already in 1.1.1's
`fc77c562f`, and this review confirms that (§7). Every commit carries one `gpgsig` header.
**Scope:** plan §2, §10, §11 (D-11); `account_deletion.rs` (the exclusive claim, its release, the
owed-record claim, `erasure_recorded`), `user.rs` (`anonymize_user_marked`), `erasure_proof.rs`,
`oauth2_refresh_token.rs`, `audit.rs` (`pseudonymize_actor`), `cleanup.rs` (`purge_under_claim`,
`ErasureClaim`, `erase_and_record`, `record_owed_erasures`, `finish_owed_erasure`,
`remove_erased_users_roles`, `sweep_refresh_tokens`, the tick), `crl.rs`, `vault_forward.rs`; the
refresh grant in `axiam-oauth2/src/token.rs` (T-254); `network_gate_enumeration_test.rs`; T-102,
T-187, T-336, T-444, T-470, T-472 in both copies; `docs/compliance/gdpr-compliance.md`,
`docs/deployment/README.md`, `docs/admin/README.md`.
**Method:** every commit message and the full diff read, each claim checked against the tree. I
worked through the cut points and the two-replica interleavings by hand against the statements'
`WHERE` clauses (§2). Every new sweep-path query was probed at scale with a throwaway test in a
release build, R111W1-01's method; the test was removed before this commit (§9). Every
`axiam-api-rest` binary was run one at a time with SAML on, plus the full binaries of `axiam-core`,
`axiam-db`, `axiam-oauth2`, `axiam-pki`, `axiam-audit` and `axiam-server` (`--no-default-features`)
(§10). The threat-model copies were compared after decoding. This review fixes nothing.
IDs: `R112W1-nn`.

---

## 0. Summary

**No Critical, High or Medium finding.** The exclusive claim (W1.2) does what #738 asks: one
transaction re-checks the account is due, refuses a live stamp on the request or on the user row,
and takes the claim; the release is conditional on the stamp and on `deletion_pending`, so it is a
no-op past the point of no return. The recovery (W1.1) redoes the proof, the second revocation and
the record in the unit's order, under the same stamp-conditional guard, and the unit's guard is now
armed before the anonymization. No cut point I could construct records an erasure twice, loses it,
proves it twice, or leaves a live certificate or refresh-token row, short of the stall longer than
the lease that T-444 already bounds (§2). The user-row claim stamp cannot be read as an owed record
(§2.3). The CRL (W1.4) and sanitiser (W1.5) fixes are right (§5, §6).

**One Low finding blocks the merge:** W1.6 turns `network_gate_enumeration_test` red. Three of its
five tests fail, because the erasure's unassignment moved out of the pinned `ErasureUnit::prepare`
(R112W1-01). The W1.6 commit lists no `axiam-api-rest` run, the point the orchestrator flagged for
W1.3. One more Low: the new refresh-token sweep is an unbounded `DELETE` behind two full table scans
on every replica every tick. On its first run after the upgrade it deletes the whole backlog in one
statement, ahead of the Vault revocation forwarder in the same sequential tick (R112W1-02; probe:
51 s for 40 000 deletions, 3.2 s per idle tick at 200 000 rows). Four Informational findings follow.

| ID | Finding | Severity | Surface / threat | Origin | Issue | Model for the fix |
|---|---|---|---|---|---|---|
| **R112W1-01** | `network_gate_enumeration_test` fails 3 of 5 (exit 101). The erasure's `unassign_from_user` moved from `ErasureUnit::prepare`, which the `PINNED` exemption names, to `remove_erased_users_roles`, which it does not. CI's test job is red. | **Low (blocks merge)** | `cleanup.rs` `remove_erased_users_roles`; `network_gate_enumeration_test.rs:148-153, 498-530` | wave (W1.6) | [#780](https://github.com/ilpanich/axiam/issues/780) | Sonnet 5.5 |
| R112W1-02 | `delete_expired` runs `SELECT count()` plus one unbounded `DELETE` over table scans (no index on `expires_at`), with no batch bound and no write-conflict retry, every 300 s on every replica. The first run deletes every row expired since the deployment began. The sequential tick holds `vault_revocation`, `tenant_purge` and `certificate_retention` behind it. Probe: 200 000 rows, first run 51.1 s, idle tick 3.2 s. The certificate retention sweep's batched shape is the precedent. | Low | `oauth2_refresh_token.rs:569`; `cleanup.rs:504, 3509`; T-470 (forwarding delay) | wave (W1.3) | [#781](https://github.com/ilpanich/axiam/issues/781) | Sonnet 5.5 |
| R112W1-03 | Two new `audit_log` reads filter the whole tenant's trail. `erasure_recorded`'s `actor_id = … OR metadata.pseudonym = …` takes 0.78–1.07 s per owed erasure against 2.2 ms for 1.1.1's form. `pseudonymize_actor`'s query 2b takes 4.3 s per erasure, doubling the fatal scrub. Both measured at 100 000 rows in the tenant. | Informational | `account_deletion.rs:839-860`; `audit.rs` query 2b | wave (W1.1, W1.6) | [#782](https://github.com/ilpanich/axiam/issues/782) | Sonnet 5.5 |
| R112W1-04 | T-254 still says every presentation of a rotated token is recorded and audited. Since #753 the row, and so the record, goes seven days after its expiry: on `fapi2` that is 7 d + 60 s after rotation. Refusal unchanged; visibility bounded; not amended. | Informational | T-254, T-187 line 605; `token.rs` refresh grant; `REFRESH_REPLAY_RETENTION_SECS` | wave (W1.3) | [#783](https://github.com/ilpanich/axiam/issues/783) | Sonnet 5.5 |
| R112W1-05 | A unit stalled past the lease still runs the scrub and the anonymization over an account its successor erased. The scrub nils the `actor_id` of the erasure's `gdpr.user_pseudonymized` row for good, and the anonymization is re-run because it is not conditional on `deletion_pending`. W1.1 fixed only the recovery's lookup; T-444's "What stays" omits both effects. | Informational | `cleanup.rs` `erase_and_record`; `user.rs:1636`; T-444 | wave (W1.1 × W1.2) | [#784](https://github.com/ilpanich/axiam/issues/784) | **Opus 5.5** |
| R112W1-06 | Text and hygiene. (a) The guide (`README.md:2068`) and W1.3's body say the recovery re-runs step (a); it does not, and need not. (b) `delete_expired` counts with a separate `SELECT`. (c) The two new race tests run on `kv-mem`, which `axiam-db`'s own fixture documents as admitting two winners in about 2 % of rounds. | Informational | `docs/deployment/README.md`; `oauth2_refresh_token.rs`; `cleanup_task.rs` | wave (W1.1, W1.3, W1.6) | [#785](https://github.com/ilpanich/axiam/issues/785) | Sonnet 5.5 |

**Verdict on merge.** Not before R112W1-01 is fixed: it is a red CI job. Per plan §1.4, the other
five are filed and go to the wave's sweep slot in severity order. R112W1-05 is the only one that
defines behaviour under concurrency, so it takes Opus.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Exclusive purge claim, release, drop guard | W1.2 | `account_deletion.rs`, `cleanup.rs`, `erasure_proof.rs`, `personal_data.rs` | every statement, every exit; two-replica and stalled interleavings (§2) |
| Recovery with proof and revocation; guard armed from a chosen stamp | W1.1 | `cleanup.rs`, `user.rs`, `repository.rs` (defaulted method), `account_deletion.rs` | every cut point (§2.1); the default method's safety for the 13 other implementations |
| Refresh-token deletion at erasure; sweep | W1.3 | `oauth2_refresh_token.rs`, `repository.rs`, `token.rs`, `cleanup.rs`, `job_health.rs`, `boot.rs` | replay path read end to end (§3); probe (§9) |
| CRL cache with a leading datastore clock | W1.4 | `crl.rs` | the three `fresh` call sites (§5) |
| Sanitiser escape boundary | W1.5 | `vault_forward.rs` | linearity argued and the test read; literals checked (§6) |
| Network-role rows at erasure; grantee scrub; recovery race test | W1.6 | `audit.rs`, `cleanup.rs`, `boot.rs`, `docs/admin/README.md` | the row shape against W4.3's; probe (§9); the enumeration test (§4) |
| #739 verify-and-close | W1.7 | `cleanup.rs`, `dead_letter.rs`, T-472 | text compared with the issue (§7) |

---

## 2. Concurrency and exactly-once (W1.2 × W1.1 × W1.6)

The claim lives on the pending request (`purge_claimed_at`) or, when there is none, on the user
row (`erasure_audit_pending`). The record marker lives on the user row (`erasure_audit_pending`,
set by the anonymization). Both leases are one hour (`ERASURE_CLAIM_LEASE`,
`PENDING_RECORD_LEASE`). Every claim, release and settle is conditional on the stamp its holder
read.

### 2.1 A cut at every step, one replica

| Cut after | What the guards do | Next sweep | Verdict |
|---|---|---|---|
| the claim | `ErasureClaim` drop → request to epoch / user stamp to `NONE` (conditional on `deletion_pending` and the stamp) | claims at once | erased once |
| part of `prepare` (a … b4) | as above | re-runs (a … b4); each step idempotent; no second network-role row (assignments gone) | erased once; one row per removed role |
| the scrub | as above | re-runs | as above |
| inside the anonymization | `RecordClaim` (armed from the chosen stamp) → epoch if the marker carries it; `ErasureClaim` release is a no-op if the row is no longer `deletion_pending` | recovery if anonymized, else a fresh erasure | no double |
| the anonymization, before the proof (`ErasureProofOwed`) | `RecordClaim` drop → epoch | recovery: proof (dated now, `marked_at = None`), revocation, record, settle | one proof, one record, revoked (W1.1's test) |
| the proof | as above | recovery: proof → `AlreadyExists` read as written; revocation; record; settle | one proof |
| the second revocation | as above | recovery redoes it (idempotent) | revoked |
| the record | as above | `erasure_recorded` true → settle only | one record |
| a failed settle | marker keeps the unit's stamp (not released) | recovery after `PENDING_RECORD_LEASE`, finds the record, settles | one record (pre-existing #689 lag) |

The refresh-token rows (W1.3) are deleted in step (a), before the point of no return, so no
recovered erasure lacks it (R112W1-06 (a) is only about the sentence that says otherwise). No new
row can be minted between (a) and the anonymization: a deletion-pending account is `Inactive`
(`create_with_pending_flag`, `mark_deletion_pending`), and the refresh and code grants re-read it
through `ensure_account_may_act`, which refuses `Inactive`. The network-role rows (W1.6) are
written in (b3) and their `grantee.id` is cleared by the scrub that follows, in the same unit.

### 2.2 Two replicas

- **Two sweeps, one due account.** Both reach `claim_tx`; the engine serialises the two writes to
  the one row, and the retried loser re-reads and finds `$held` (or `$user_held`). One erasure, one
  `account_purged`. The `$held` read uses `idx_account_deletion_tenant_user` (`EXPLAIN`:
  `IndexScan`; 100 reads over 20 000 rows in 30 ms, §9), and it runs per due account, not per user
  row.
- **Two recoveries.** `claim_owed_erasure_records` claims each row with a conditional `UPDATE` on
  the value read, so one wins; the proof's unique index and `erasure_recorded` make the loser's
  late write, if any, a no-op. W1.6's test pins it (on `kv-mem`: R112W1-06 (c)).
- **A unit and a recovery.** The recovery claims a marker only once it is released or older than
  an hour. A unit that stalls longer than that between its proof and its record can still write
  the record after the recovery did, giving two records. The class is pre-existing (#689),
  bounded by the lease. W1.1 narrowed it: a recovery that writes the proof first now makes the
  late unit stop at `AlreadyExists`.
- **A stalled claimant past the claim lease.** B takes over and erases. A resumes, scrubs, and
  re-anonymizes. A's second anonymization overwrites the marker. If B has not settled yet, B's
  settle misses and A's `AlreadyExists` releases A's stamp, so the next recovery settles. If B has
  settled, the recovery settles an already completed request. Either way the trail has one
  record, which W1.1's pseudonym match now finds. The scrub has nilled that record's actor,
  though, and the second `account_purged` is sent: **R112W1-05**.

**Retry loop or starvation.** A recovery whose proof or revocation fails releases the marker to the
epoch. The next tick (300 s) re-claims it, so a persistent failure retries every tick with a
`warn` and a failed `gdpr_purge` job on `/health/jobs`. It does not starve: `record_owed_erasures`
goes on to the next owed erasure, and `sweep_pending_purges` runs the due erasures before it
returns the owed error. The request stays pending, and uncancellable, until the failure clears.
That is the intended fail-closed shape ("no request is completed without its proof").

### 2.3 Can the user-row claim stamp be read as an owed record?

No. `claim_owed_erasure_records` reads `erasure_audit_pending` only on `status = 'Anonymized'`
rows. `claim_tx` writes the stamp only while `deletion_pending = true`, and every anonymization,
`anonymize_user` and `anonymize_user_marked` alike, overwrites the field in the transaction that
sets `Anonymized` and clears `deletion_pending`. The stamp `erase_and_record` chooses is a fresh
`Utc::now()`, not the claim's. So the anonymization's failure-path release
(`release_erasure_record`, conditional on that stamp and not on the status) cannot match a claim
stamp on a row that was never anonymized. The tombstone sets `Deleted`, which the recovery never
reads. W1.2's argument therefore survives W1.1. Its only gap is the re-anonymization of an
already-erased row (R112W1-05), which the guards make harmless and the fix makes impossible.

### 2.4 The defaulted trait method

`UserRepository::anonymize_user_marked` defaults to `anonymize_user`, ignoring the stamp. That is
safe only for an implementation that keeps no marker. The one implementation that does,
`SurrealUserRepository`, overrides it, and its `anonymize_user` delegates with `Utc::now()`. The
other implementations are test doubles. A future datastore implementation that keeps the marker
and forgets the override would leave every cut erasure to the lease, not lose it. The trait doc
says so.

---

## 3. The refresh-token sweep and T-254 (W1.3)

**Replay detection.** On a refused lookup the refresh grant asks `find_rotated` (`tenant_id`,
`token_hash`, `rotated_at != NONE`, with no time bound). On a hit it marks the session, writes
`oauth2.refresh_token_replayed` and answers `invalid_grant`; it revokes nothing. Deleting a row
therefore changes what is **recorded**, never what is **accepted**: an absent row answers the same
`invalid_grant`. The commit's choice of `expires_at` over `revoked` is right: 1.1.1's
`delete_expired` (never scheduled) would have deleted every revoked row at once and blinded
detection from the first tick. What the seven days cost is not in the threat model:
**R112W1-04**.

**Cost.** **R112W1-02**: two scans per tick per replica, and an unbounded first run.

**Erasure.** `erase_oauth2_refresh_tokens` revokes, then deletes by `(tenant_id, user_id)`. Both
calls are idempotent and fail-closed (`?`), so the purge retries the next sweep.
`delete_all_for_user` counts with `RETURN BEFORE`, which is right. The trait change (two new
signatures) reaches `axiam-oauth2`'s mock, and every `axiam-api-rest` binary builds and passes
except R112W1-01's (§10).

---

## 4. R112W1-01: the network-gate enumeration (Low, blocks merge)

`61615fb` moved the erasure's `role_repo.unassign_from_user` into the new public
`remove_erased_users_roles`. `network_gate_enumeration_test.rs` exempts the erasure's ungated
write by a `PINNED` entry: the path suffix, `prepare`, and the start of `ErasureUnit::prepare`'s
body (#715 (e)). `cargo test -p axiam-api-rest --test network_gate_enumeration_test` exits 101:

```
every_network_relevant_write_is_gated_or_exempt_with_a_reason:
  crates/axiam-server/src/cleanup.rs::remove_erased_users_roles calls .unassign_from_user(
every_exemption_still_names_a_real_ungated_site:
  exemption crates/axiam-server/src/cleanup.rs::prepare matches no ungated write; remove it
a_second_prepare_in_cleanup_is_not_exempt:
  ErasureUnit::prepare is still found
```

The write is still the platform's act and still deliberately ungated. W1.6 made it better
recorded, since it now writes the row the gate would have written. The defect is the gate's
invariant test, not the behaviour, but it fails CI. **Fix:** exempt `remove_erased_users_roles`
(a unique name, so an `EXEMPT` entry is enough) with the reason updated, and rework or retire the
`PINNED` stray-function test. **Test:** the five tests pass, and every `axiam-api-rest` binary is
run. Issue #780.

---

## 5. The CRL cache (W1.4, #736)

`fresh(digest, now, follow_clock)` drops `this_update <= now` for `current()` only; `current_at`
keeps it (#666's property, pinned by `current_at_signs_a_past_instant_at_that_instant`). All three
call sites pass the caller's flag, including the joiner's re-check in `resign`. The digest and
`refresh_at` conditions still bind every caller, so a new revocation is never served from a stale
list. The new test (a revocation 20 s ahead; with every permit held, `current()` answers the cached
bytes) is R111W1-02's probe turned into a test. T-102 does not state the cache condition, so no
text was owed. Held.

---

## 6. The sanitiser (W1.5, #740)

- **Linear.** An attempt starts only at a boundary or right after a recognised escape. Every escape
  contains a non-token character (`\`, `%`) within six positions, so an attempt never starts inside
  a run another attempt already scanned, and `ends_with_escape` looks back a constant six
  characters. A mask skips its span. Each character is read a bounded number of times.
  `the_escape_scan_stays_linear` pins it (100× input, 1 000× bound, generous enough not to flake).
- **No literal token.** Every token in the new tests is built at run time (`fake_token`). The
  legacy host-like string is assembled with `concat`, and `hvs.abc` / `hvs.short` are below
  `MIN_TOKEN_BODY`. A grep for `hvs\.[A-Za-z0-9]{8,}` in the file finds nothing.
- **Host names intact.** `b.vault-internal.example.com` and `s.vault-1.eu-west.internal` are
  asserted unchanged, bare and after `\n`. The legacy prefixes get no escape boundary, as T-470
  documents. `\\n` (an escaped backslash, then `n`) is read as an escape and masks a following
  token, which errs on the safe side.

Held.

---

## 7. #739 (W1.7, no commit)

The three items are in `fc77c562f` (1.1.1). `fc77c562f` rewrote the three `cleanup.rs` passages
#688 corrected (15 lines, 9 removed), and W1 re-touched none of them in a way that brings the
absolutes back. `dead_letter.rs`'s `append_off_thread` doc
says the join error is seen and logged by the awaiter, which is D-11's default. T-472 carries the
2026-10-19 #739 correction of the orphan-marker sentence, identical in both copies (§8). Nothing is
left to edit. #739 can close with the wave.

---

## 8. Threat model and documents

- **Copies.** For T-102, T-187, T-336, T-444, T-470 and T-472, every paragraph of the STRIDE entry
  was looked up verbatim in the decoded strings of `Axiam.json`. All are present. The only lines
  absent are the structural metadata line and `</details>`, which the JSON stores in fields. The
  four entries this wave amended (T-187, T-336, T-444, T-470) carry a 2026-10-22 amendment each,
  and T-444 two. T-102 and T-472 are unchanged in this wave. Model version 2.43.0, unbumped (W8.3).
  The JSON parses.
- **`gdpr-compliance.md`.** The recovery sentence matches `record_owed_erasures`. The refresh-token
  paragraph matches the code; its "window in which a replay … is still detected" is R112W1-04.
- **`docs/deployment/README.md`.** The claim and recovery paragraphs match the code, including
  "that case alone sends `account_purged` a second time". The refresh-token section's "re-runs it
  harmlessly" is R112W1-06 (a).
- **`docs/admin/README.md`.** The `network_role.unassigned` row described (system actor,
  `reason: "account_erasure"`, the grantee id cleared at anonymization) is the row
  `remove_erased_users_roles` writes.

---

## 9. Probes (throwaway; removed before this commit)

`crates/axiam-db/tests/zz_probe_r112w1.rs` (deleted): an in-memory datastore with the migrated
schema, rows inserted in batches of 2 000. **Release build** (debug figures were 4–6× slower: the
first refresh run took 70.7 s for 10 000 deletions).

| Query | Data | Time | Plan |
|---|---|---|---|
| `delete_expired(now − 7 d)`, first run | 50 000 rows, 10 000 expired 30 d ago | 11.6 s | `TableScan` |
| same, idle (nothing due) | 50 000 | 0.78 s | `TableScan` |
| `delete_expired`, first run | 200 000, 40 000 expired | 51.1 s | `TableScan` |
| same, idle | 200 000 | 3.2 s | `TableScan` |
| `claim_tx`'s `$held` read ×100 | 20 000 `account_deletion` rows | 30 ms | `IndexScan idx_account_deletion_tenant_user` |
| `erasure_recorded` (shipped, `OR metadata.pseudonym`) | 200 000 `audit_log`, 100 000 in the tenant | 1.07 s, 0.78 s | `IndexScan idx_audit_tenant_actor` (tenant prefix) + `Filter` |
| 1.1.1's `actor_id = $user_id` form | same | 2.2 ms | full index |
| `pseudonymize_actor` query 2b alone | same | 4.3 s | `IndexScan` (tenant prefix) + `Filter` |
| `pseudonymize_actor`, whole | same | 8.0 s | — |

`remove_erased_users_roles` reads the role's grants once per assignment of the erased account, so
it runs per erasure and per assignment, never per user row. It was not probed.

---

## 10. Checks run (each tool's own exit code)

Environment: `protobuf-compiler`, `libxml2-dev`, `libxmlsec1-dev`, `clang` installed (SAML **on**);
swagger-ui placeholder; `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`;
each `axiam-api-rest` test binary run singly and deleted after its run.

| Command | Exit |
|---|---|
| `cargo test -p axiam-api-rest --lib` (SAML on) | 0 (308 passed) |
| `cargo test -p axiam-api-rest --test <each of 112 files>`, singly (SAML on) | **111 × 0, 1 × 101**: 2 051 passed, **3 failed** (`network_gate_enumeration_test`, R112W1-01), 9 ignored |
| `cargo test -p axiam-core` | 0 (563 passed) |
| `cargo test -p axiam-db` | 0 (1 112 passed, 5 ignored) |
| `cargo test -p axiam-oauth2` | 0 (839 passed) |
| `cargo test -p axiam-pki` | 0 (380 passed, 2 ignored; `crl_test` and `vault_forward::tests` among them) |
| `cargo test -p axiam-audit` | 0 (81 passed, 1 ignored) |
| `cargo test -p axiam-server --no-default-features` | 0 (29 binaries, 355 passed). A first run died at link time when the session's disk quota filled (exit 101, no test run); re-run on a clean `target/` |
| probe `zz_probe_r112w1` (§9; release; deleted) | 0 (3 probes)

| Other check | Exit |
|---|---|
| `cargo fmt -p axiam-core -p axiam-db -p axiam-server -p axiam-pki -p axiam-oauth2 -p axiam-api-rest -- --check` | 0 |
| `bash scripts/check-doc-links.sh` | 0 (537 links, 78 files) |
| `python3 scripts/check-remediation-evidence.py` | 0 (5 verified, 0 failed, 32 skipped) |
| `python3 scripts/check-crate-layering.py` | 0 (19 crates, 62 edges) |
| threat-model copy comparison (Python, decoded `Axiam.json`) | six entries, every paragraph present |
| `git cat-file -p <c> \| grep -c gpgsig`, six commits | 1 each |
| GitHub Actions runs on `claude/release-1.1.2-w1` | none exist (no PR) |

Clippy was not re-run. The executors report it clean for the crates they touched, and nothing
in this review depends on it.

---

## 11. Commit messages and §10

| Commit | Claim | Verdict |
|---|---|---|
| `cff763d` | exclusive leased claim; user-row stamp; release on every exit before the point of no return; `AlreadyExists` read as "another unit erased it"; T-444, T-187 | true (§2); its stalled-unit residual was corrected by `74a1457` |
| `74a1457` | guard from a chosen stamp; recovery writes proof and re-revokes; pseudonym match | true (§2.1); the stalled unit still writes before it stops (R112W1-05); `erasure_recorded`'s cost (R112W1-03 (a)) |
| `a5b54f2` | deletion at erasure; sweep keyed on `expires_at`; "the #737 recovery may re-enter it" | true but for that sentence (R112W1-06 (a)); "`EXPLAIN` was not run": it is a `TableScan` (R112W1-02); T-254 not amended (R112W1-04); `axiam-api-rest` not reported run, though it builds and passes |
| `23f03a4` | `follow_clock` on all three sites; test | true (§5) |
| `048146a` | escape boundary; linear; no literals; T-470 | true (§6) |
| `61615fb` | grantee scrub; one row per network role; recovery race test | true; breaks the enumeration test (R112W1-01); query 2b's cost (R112W1-03 (b)); race test on `kv-mem` (R112W1-06 (c)) |

§10: signed; no migration (v109 stays newest); no `CONTRACT.md` edit; no route, no crate; each
row's test in its commit. No test message interpolates a token, a secret or a Vault reason: the
sanitiser's assertions print the escape and prefix under test, not the token.

---

## 12. What could not be verified

- **CI.** No workflow has run on this branch. R112W1-01 is a local reproduction of what the test
  job will report.
- **A persistent engine at scale.** The probes ran on `kv-mem`, release build. `surrealkv`'s
  absolute figures will differ. The shape (a table scan, linear in rows) is the engine's plan, not
  the store's.
- **A real stall longer than an hour** (R112W1-05) is argued from the statements and from W1.1's
  own pinned test, not re-run with a modified test.
- **Multi-replica write conflicts on the refresh sweep** (R112W1-02) are argued from the shape (no
  retry, overlapping `DELETE`s) and from the certificate sweep's history, not observed.

---

## 13. For later tasks

- **W7.1 (contract 1.64, item (a)).** The recovered `gdpr.user_pseudonymized` row is unchanged by
  W1: `actor_id` the account, `actor_type: System`, `metadata.pseudonym`,
  `certificates_revoked: null`, `recovered: true`. The recovery's second revocation is logged, not
  counted in the row. The contract may add that a recovered erasure now also has its erasure proof,
  dated at the recovery when the unit's marker had been released. Until R112W1-05 is fixed, a
  consumer must not rely on `actor_id` alone to find the record: after a stall longer than an hour
  it is the nil UUID, and `metadata.pseudonym` is the stable key. Say that `account_purged` goes
  out once per erasure, except after a claimant stalled longer than the one-hour lease (W1.2).
- **W8.3.** T-187, T-336, T-444, T-470 carry new 2026-10-22 amendments, and T-444 has two. T-254
  owes one (R112W1-04). After R112W1-05's fix, T-444's "What stays" shrinks.
- **W8.4 (CHANGELOG).** #738 and #737 as their bodies propose; #753: "an erasure deletes the user's
  refresh-token rows, and a new `oauth2_refresh_token` cleanup job deletes rows a week past
  expiry". Upgrade note: the first run of that job deletes the whole backlog. Say so, and how long
  it took on a large table, unless R112W1-02's batching lands. #736, #740, #758 (e, f) one line
  each. #739 closes with no code change.

---

## 14. Issues

Filed on `ilpanich/axiam`, milestone `1.1.x` (#23). Each body is the finding's text and ends with
the attribution footer. A search of the open milestone found no R112W1 issue and nothing on the
refresh sweep, the enumeration test or the stalled unit's scrub.

| ID | Severity | Issue |
|---|---|---|
| R112W1-01 | Low (blocks merge) | [#780](https://github.com/ilpanich/axiam/issues/780) |
| R112W1-02 | Low | [#781](https://github.com/ilpanich/axiam/issues/781) |
| R112W1-03 | Informational | [#782](https://github.com/ilpanich/axiam/issues/782) |
| R112W1-04 | Informational | [#783](https://github.com/ilpanich/axiam/issues/783) |
| R112W1-05 | Informational | [#784](https://github.com/ilpanich/axiam/issues/784) |
| R112W1-06 | Informational | [#785](https://github.com/ilpanich/axiam/issues/785) |
