# Security review — release 1.1.0, wave W1 (F4)

**Date:** 2026-10-14.
**Against:** `claude/release-1.1.0-w1`, the whole wave diff `3d011573e..28dc3eb6`
(11 commits, 52 files, 4 627 lines added and 505 removed). Every commit carries
a signature (`gpgsig` header in 11 of 11; the sandbox has no
`gpg.ssh.allowedSignersFile`, so `%G?` cannot verify them here).
**Scope:** every W1 task of the release-1.1.0 plan (§2): W1.1 #615 (CRL
`thisUpdate` clamp, `b97741b4`), W1.2 #616 (shared CRL re-sign flight,
`da02b290`), W1.3 #617 (issuer release retried by the Vault sweep, `e9a3ecca`),
W1.4 #618 (erased account's certificate `metadata`; `certificate_retention`
sweep, `4bd98bf4`), W1.5 #619 (Vault reason sanitised at every sink,
`29943ab7`), W1.6 #620 (`bootstrap_client()`, `843f2e81`), W1.7 #621 (text; the
grace pinned to the longest CRL interval, `4f3cf47b`), W1.8 #622 (orphan purge
claim, post-create binding re-check, `404` revokes nothing, lease-conditional
failure record, `a8324435`), W1.9 #653 (random serials, schema v99,
`09c76d56`), W1.10 #651 (Ed25519 keys as PKCS#8 v1, `c51a8677`), W1.11 #649
(common-name rules, `28dc3eb6`).
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) and
`Axiam.json` (model 2.41.0, 477 threats), the plan's §10 rules, and the OWASP
ASVS 5.0 areas the diff touches (V2 business logic and concurrency, V8
authorization, V9 certificates, V12 outbound requests, V13 configuration, V14
data protection and retention, V16 logging). Claims were checked against the
code, not the commit messages; four were checked by throwaway probes (§15),
removed before this commit. This review fixes nothing: every finding has
evidence, a proposed fix and an issue body (§16). IDs: `R110W1-nn`.

---

## 0. Summary

**One Medium finding, introduced by the wave; nothing High or Critical.**

* **R110W1-01 (Medium, wave — #618).** The new `certificate_retention` sweep
  selects its batch with `tenant_id IN (SELECT VALUE meta::id(id) FROM tenant
  WHERE deleted_at = NONE)` **inside** the `WHERE` of a scan of `certificate`.
  SurrealDB evaluates that subquery once per candidate row. Probe (§15): 3 000
  past-grace rows of a tombstoned tenant beside 301 tenants — one call of
  `delete_past_retention(500)` took **36.0 s**; the same selection with the
  tenant set hoisted into a `LET` took **62 ms** (in-memory engine, debug build:
  the absolute figures are not production's, the product of rows and tenants
  is). The sweep runs every cleanup
  tick (300 s by default) on every replica, in line with the other sweeps, so
  the cost — candidate rows × tenants — stalls `dcr_registration_tokens`,
  `directory_sync`, `scim_reconcile` and the next tick's session, Vault and
  GDPR sweeps, and loads the datastore every request shares. It is reached
  without an attacker: the first ticks after the upgrade (every row past
  `notAfter` + 8 days in every live tenant is a candidate, 10 000 a tick), an
  IoT tenant issuing short-lived certificates, a deleted tenant's rows while
  its purge is in flight on another replica. The fix is one statement moved
  (§2).

One Low and four Informational findings are reported for the next patch
milestone (§16); one of the Informational ones is a **CI gate failure** the wave
must fix before it lands (R110W1-03, one command).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R110W1-01** | `delete_past_retention` re-evaluates the live-tenant subquery for every candidate row: 36 s for 3 000 candidate rows and 301 tenants against 62 ms hoisted. Runs every tick on every replica, in line with the other sweeps; first triggered by the upgrade itself. | **Medium** | `certificate.rs:895-909`, `cleanup.rs:1672-1686` → T-187 (availability of the cleanup sweeps) | wave | **Fix in wave** (proposed §2) |
| R110W1-02 | Under a `vault_pki` CA a caller's CSR is signed with `sign-verbatim`, which copies the CSR's **whole** subject; `inspect_csr` checks only the **first** CN. A second CN or any other attribute holding a newline, a bidi override or 200 characters reaches a certificate issued from 1.1.0 (probe); a relying party that reads the last CN sees another name than the row. T-461's "can no longer reach … through a certificate issued from 1.1.0" is false on that path. | Low | `ca.rs:1486-1503`, `vault_pki.rs:714-730` → T-461 | wave (incomplete fix of #649) | Issue; **recommended in-wave**, since the wave closes #649 (§3) |
| R110W1-03 | `sdks/management-registry.json` is stale: W1.11 regenerated `sdks/openapi.json` (digest `b7d07550…`) and left the registry's `spec_digest` at W1.10's `b671db54…`. `gen-management-registry.py --check` fails, and with it `ci.yml:88`. | Informational | `sdks/management-registry.json:4` | wave | **Fix in wave** (gate; one command) |
| R110W1-04 | The orphan-purge marker is recognised by `metadata.orphan_purge = true` alone, a key an administrator can write on any tenant. A tenant created with it is, once deleted, purged as an orphan (probe): the export receipt is ignored, its audit trail kept, and `tenants.purged` recorded — append-only — with `orphan: true`. | Informational | `tenant.rs:335-350,494-510` → T-472 | wave | Issue |
| R110W1-05 | `sanitise_reason` masks a token only when it is a whole whitespace-separated word: `token=hvs.…`, `{"token":"hvs.…"}` and `"hvs.…".` pass unmasked; `b.`/`s.` mask dotted host names (`b.vault-internal.example.com` → `[redacted]`) (probe). T-470 records only the third case. | Informational | `vault_forward.rs:51-90` → T-470 | wave (W1.5 extended this matcher) | Issue |
| R110W1-06 | Text and tests behind the code: T-472 still calls the kept certificate rows a "legal-obligation retention", which W1.4 withdrew; `current_at` says it signs "as of `now`" but the flight replaces an earlier instant by the wall clock; no test pins the `vault_pki` intermediate-default refusal; `[Unreleased]` carries no upgrade note for the first `certificate_retention` runs or the new `400`s on common names. | Informational | `threat-model-stride.md:434`, `crl.rs:533-540,640`, `ca.rs:254-276`, `CHANGELOG.md:8` | wave | Issue |

**What held.** Every §10 rule holds for what the wave added (§4): no route was
added; the only new outbound calls are Vault `DELETE`s on the Vault PKI client,
which never follows a redirect, and the bootstrap client keeps
`Policy::none()`; every new two-writer write is conditional
(`claim_orphan_purge` by record-id uniqueness, `drop_orphan_claim` and
`record_vault_forward_failure` on the value the claim wrote,
`delete_tombstoned_row` by `RETURN BEFORE`, `delete_past_retention` by id under
a write-conflict retry); v99 is additive, has its scope test and the
newest-version bump; `CONTRACT.md` is untouched; `sdks/openapi.json` is
**byte-identical** to a fresh `--dump-openapi` and its drift is description-only
(seven descriptions and the digest). The CRL flight (W1.2) cannot hand a caller
a list older than the state it read, cannot deadlock, and cannot leak a task or
a marker (§5). The clamp (W1.1) keeps byte identity and makes the number
monotonic across epochs for any datastore lead; `I_new ≤ 2·I_old` is correctly
derived (§6). The orphan marker is invisible to every tenant reader, and lease
expiry, takeover and a crash between claim and purge all record once (§9). The
post-create re-check plus the second revocation in `users::delete` close the
issuance/deletion window from both sides, and no key leaves for a certificate
revoked before the response (§9). The retention sweep deletes nothing a CRL
still lists while clocks agree within a day, never a CA row, never a tombstoned
tenant's row (§8). v99 cannot break the upgrade and the stored serial is the
CRL's encoding (§10). Every Ed25519 reload path reads both PKCS#8 forms (§10).
The seven amended threat entries are identical in `Axiam.json` and the STRIDE
document (§11).

**Verdict on merge.** R110W1-01 should be fixed in the wave (one `LET`, §2).
R110W1-03 must be fixed for CI to pass. R110W1-02 is Low, but the wave puts
`Closes #649` on a fix with a by-pass on one custodian and a threat-model
sentence that says otherwise; its fix is a few lines in `inspect_csr` and is
better taken now than filed. Nothing else blocks.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| CRL `thisUpdate` clamp, interval and skew conditions | W1.1 #615 | `crl.rs` (`list_identity`, `stated_revocation_time`, `RefreshEpoch`, `sign_crl`), `crl_test.rs`, PKI guide | **read in full**; derivation re-done (§6) |
| Shared CRL re-sign flight | W1.2 #616 | `crl.rs` (`CaSlot`, `Turn`, `Landing`, `resign`, `sign`), `error.rs` (`Clone`), `handlers/crl.rs` | **read in full**; every interleaving of lead/join/land/drop walked (§5) |
| Issuer release retried by the sweep | W1.3 #617 | `ca.rs` (`is_issuer_on_its_own_crl_refusal`, `release_revoked_ca`, `forward_ca_revocation_releasing`), `cert.rs` sweep, `vault_pki.rs` (`delete`, locator) | **read in full**; tests run |
| Erasure `metadata` clear; `certificate_retention` | W1.4 #618 | `certificate.rs` (`BELONGS_TO_ACCOUNT`, `clear_user_certificates_metadata`, `delete_past_retention`), `cleanup.rs`, `job_health.rs`, `tenant_purge.rs` constants, schema references to `certificate` | **read in full**; **probed** the scan cost (§15) |
| Vault reason sanitised at every sink | W1.5 #619 | `vault_forward.rs`, both handlers, `cert.rs`/`ca.rs` logs; every `CustodianRevocation::Pending` consumer located by grep | **read in full**; **probed** the matcher (§15) |
| Bootstrap Vault client | W1.6 #620 | `secrets.rs`, `main.rs`, `vault_provider_test.rs` | read in full; tests run |
| Text; grace vs longest interval | W1.7 #621 | `crl_purge_margin.rs`, `tenant_purge.rs`, admin guide, `operate.ts` | read in full; derivation re-done (§8) |
| Orphan claim; post-create re-check; `404`; lease-conditional record | W1.8 #622 | `tenant.rs` (`claim_orphan_purge`, `drop_orphan_claim`, `purge_orphan`, `purge_tombstoned`), `tenant_purge.rs` (`has_purgeable_rows`), `cleanup.rs` (`sweep_tenant_purge`), **every query on the `tenant` table** (repositories, settings, schema back-fill, SSF count), `handlers/certificates.rs`, `handlers/users.rs`, both `record_vault_forward_failure` | **read in full**; **probed** the marker key (§15) |
| Random serials; v99 | W1.9 #653 | `serial.rs`, the four signing sites, both repositories' `create`, schema v99, `classify_write_error` | read in full; tests run |
| Ed25519 PKCS#8 v1 | W1.10 #651 | `crypto.rs`, the four former `serialize_pem` sites, every `KeyPair::from_pem` / PKCS#8 loader in the workspace | read in full; tests run |
| Common-name rules | W1.11 #649 | `subject.rs`, `ca.rs` (`inspect_csr`, intermediate default), every DN-building site (`leaf_params`, `intermediate_params`, root generate, Vault `generate_root`/`generate_intermediate`/`sign_as_intermediate`/`sign_csr`, SAML credential) | read in full; **probed** the Vault CSR path (§15) |
| Threat model, docs, spec | all | `Axiam.json`, STRIDE, `website/src/threatModel.ts`, PKI/admin/GDPR/FreeRADIUS guides, `operate.ts`, `sdks/openapi.json`, `sdks/management-registry.json` | T-102, T-187, T-336, T-461, T-470, T-472, T-476 compared with the code (§11); spec rebuilt (§15) |

Not run: the `axiam-api-rest` integration suites (`certificate_test`,
`ca_certificate_test`, `user_test`, a further multi-GB build on a disk the
server build had already taken to 20 GB free; the crate-level and server tests
in §15 cover the logic they pin), the frontend, a real Vault, a multi-replica
deployment.

## 2. R110W1-01 — the retention sweep re-reads the tenant table for every candidate row

**Severity: Medium (availability). Wave-introduced (#618). Proposed for a fix in the wave.**

**Evidence.**
* `crates/axiam-db/src/repository/certificate.rs:895-909` — the batch is
  ```
  LET $doomed = (SELECT VALUE id FROM certificate
      WHERE not_after <= time::now() - 8d
        AND tenant_id IN (SELECT VALUE meta::id(id) FROM tenant WHERE deleted_at = NONE)
      LIMIT $limit);
  ```
  There is no index on `certificate.not_after` (the table's indexes are
  `schema.rs:864,928,4659,4737,4803,4832`), so the statement walks the table,
  and for every row whose date qualifies it evaluates the subquery — a scan of
  `tenant` — again.
* **Probe (§15, C):** 3 000 certificate rows 30 days past `notAfter`, in a
  tombstoned tenant (so none is deletable and every one is a candidate), 301
  tenant rows, in-memory engine, debug build: `delete_past_retention(500)`
  returned `0` after **35.999 s**; `LET $live = (SELECT VALUE meta::id(id) FROM
  tenant WHERE deleted_at = NONE); SELECT VALUE id FROM certificate WHERE
  not_after <= time::now() - 8d AND tenant_id IN $live LIMIT 500` took
  **61.8 ms**. Roughly 40 µs per (candidate row × tenant) in the debug build; a
  release build is faster by a constant, not by the product.
* `crates/axiam-server/src/cleanup.rs:1672-1686` — the sweep runs inside the
  tick, after `tenant_purge` and before `dcr_registration_tokens`,
  `directory_sync` and `scim_reconcile`; up to `CERTIFICATE_RETENTION_MAX_BATCHES`
  (20) batches a tick, stopping only on a shutdown signal. Every replica runs
  it (`cleanup_interval_secs` 300 s, `boot.rs:83`).

**Consequences.** The cost of one tick is (candidate rows examined) × (tenant
rows), on every replica, on the datastore every authentication shares:

1. **The upgrade.** On the first ticks every certificate row of every live
   tenant more than eight days past `notAfter` is a candidate: 500 per batch,
   20 batches, each candidate re-scanning the tenant table. A deployment with
   many tenants and a backlog of expired rows spends minutes per tick in this
   sweep until the backlog is gone, delaying the sweeps after it and the next
   tick (sessions, `vault_revocation`, `gdpr_purge`).
2. **Steady state with short-lived certificates** (the IoT case AXIAM targets):
   every tick's newly past-grace rows cost rows × tenants.
3. **Rows that match the date but not the tenant set** are examined on every
   tick and never removed by this sweep: a deleted tenant's rows while another
   replica holds its purge claim (up to the one-hour lease), or a failed purge.
   The batch then never fills, so the loop ends after one batch — but that one
   batch scans all of them.

Nothing here needs an attacker; a tenant administrator who issues many
short-lived certificates raises the cost for every tenant, but only as fast as
issuance allows.

**Proposed fix (one statement moved).** In `delete_past_retention`, read the
live tenants once:
```
LET $live = (SELECT VALUE meta::id(id) FROM tenant WHERE deleted_at = NONE);
LET $doomed = (SELECT VALUE id FROM certificate
    WHERE {PAST_REVOCATION_GRACE} AND tenant_id IN $live LIMIT $limit);
DELETE cert_bound_to WHERE in IN $doomed;
LET $removed = (DELETE $doomed RETURN BEFORE);
SELECT meta::id(id) AS record_id FROM $removed
```
and take statement index **4** instead of 3. Semantics are unchanged: a tenant
tombstoned between the `LET` and the `DELETE` can lose a past-grace row to this
sweep rather than to its purge, which deletes it anyway (it is past every
list). Optionally, in the same v99 the wave already owns, `DEFINE INDEX IF NOT
EXISTS idx_certificate_not_after ON TABLE certificate FIELDS not_after` (with
the scope test's expected list extended) — only if a measurement on the
production engine shows the planner uses it for `<=`; the `LET` alone removes
the product.

**Test.** `certificate_repository_test.rs`:
`the_retention_batch_reads_the_tenant_table_once` — 2 000 certificate rows past
the grace in a tombstoned tenant and 200 live tenants; `delete_past_retention(500)`
returns `0` within 5 s (the current form, scaled from the probe: about 16 s), and a
second assertion that one past-grace row of a live tenant among them is still
deleted. The existing
`the_certificate_sweep_deletes_rows_past_the_grace_and_the_crl_does_not_change`
and `the_certificate_sweep_is_bounded_and_two_replicas_remove_each_row_once`
still pass.

The same shape predates the wave in `UNFORWARDED_WHERE`
(`certificate.rs:125-130`, the Vault due list), but there the subquery runs only
for rows already filtered to `Revoked`, unforwarded and unexpired — a small set.
Not a finding; worth the same `LET` when that query is next touched.

## 3. R110W1-02 — a `vault_pki` CSR's other subject attributes bypass the common-name rules

**Severity: Low. Wave-introduced (incomplete fix of #649).**

**Evidence.**
* `crates/axiam-pki/src/ca.rs:1486-1503` — `inspect_csr` takes
  `subject.iter_common_name().next()`, the **first** CN, and runs
  `check_common_name_value` on it alone.
* `crates/axiam-pki/src/cert.rs` `leaf_params` (`:1494`) builds the DN from that
  one name, so a CSR signed **in-process** carries nothing else — safe.
* `crates/axiam-pki/src/vault_pki.rs:714-730` — under `vault_pki` custody
  `CertService::sign_csr` sends the caller's CSR to
  `issuer/<id>/sign-verbatim`, which "takes the CSR's subject and extensions as
  given" (its own doc comment, `:680-681`). Nothing checks the CSR's other
  attributes, or a second CN.
* **Probe (§15, A):** a CSR with `CN=byok-device`, `OU="evil\nline \u{202E}gnp.exe"`
  and a second `CN="second\ncn"`, signed under a `vault_pki` CA (wiremock):
  `sign_csr` **succeeded**, the CSR went to Vault byte for byte, and the row
  says `subject = "byok-device"`.

**Consequences.** On a `vault_pki` deployment, an administrator holding
`certificates:generate` (or a client of one) can still have a newline, a bidi
override or an over-long value written into an issued certificate's subject —
the exact rendering hazard #649 closes for the CN. A relying party that reads
the **last** CN (Go's `crypto/x509` `Subject.CommonName` is overwritten by each
CN in turn) authenticates a device under a name the row does not show. T-461's
amendment ("a newline or a bidi override in a common name can no longer reach
the recipe's table, an ACL or a log line through a certificate issued from
1.1.0") is false on this path. The FreeRADIUS recipe keys on the serial, and
OpenSSL's `X509_NAME_get_index_by_NID` returns the first CN, so the recipe's
own table is not reached; logs and other consumers are.

**Proposed fix.** In `inspect_csr`, after the signature check:
1. refuse a subject with more than one CN attribute
   ("the certificate signing request's subject has more than one common name");
2. refuse any attribute other than the CN **when the issuing custodian signs
   remotely** — or, simpler and matching D-2 ("every AXIAM certificate has
   exactly one distinguished-name component"), on every path: the in-process
   path discards them silently today, so a CSR with `O=`/`OU=` is already not
   honoured;
3. if (2) is judged too strict for the in-process path, at least run
   `check_common_name_value` on **every** attribute value (`attr.as_str()`;
   refuse a non-string value) so nothing unprintable reaches Vault;
4. amend T-461 (dated) to say which of these the CSR path enforces.

**Test.** `vault_pki_test.rs`: a CSR with a clean first CN and a second CN
holding `\n`, and one with an `OU` holding U+202E, are each refused with `400`
before any request reaches the `sign-verbatim` mock (`.expect(0)`); the
existing `signing_a_caller_csr_sends_the_csr_verbatim_and_states_the_usages`
still passes. `subject.rs`/`ca.rs` unit: `inspect_csr` refuses two CNs.

## 4. The §10 rules, against what the wave added

| Rule | Verdict | Evidence |
|---|---|---|
| Every new route carries a limiter from its first commit | **holds (none added)** | no route registration changed; the CRL route keeps its `crl` bucket; its `503` text is in the OpenAPI description |
| Every credential-bearing outbound request uses `guarded_fetch_no_redirect` | **holds, as the stated operator-configured exception** | the new calls are Vault `DELETE issuer/<id>` and `key/<id>` from `release_revoked_ca` (`ca.rs:1232`) through `VaultPkiCaKeyStore::delete` on the Vault PKI client (`redirect(Policy::none())`, `vault_pki.rs:247`, 60 s client timeout, and the release itself under the sweep's deadline); the bootstrap client keeps `Policy::none()` through the shared `vault_client_builder()` (`secrets.rs:260`) |
| Every refusal of a credential check costs one verify | **not exercised** | no credential check added or changed |
| Every two-writer registry is written conditionally on the version read | **holds** | `claim_orphan_purge` — `CREATE` of the orphan's own record id, `AlreadyExists` after `retry_hot_row` is "not ours"; `drop_orphan_claim` — `WHERE metadata.orphan_purge = true AND purge_claimed_at = $claimed_at`; `delete_tombstoned_row` — `WHERE deleted_at != NONE … RETURN BEFORE`, only the remover records; `record_vault_forward_failure` (both tables) — `WHERE vault_next_attempt_at = $lease`, with `$lease` the very `lease_until` the claim wrote (`cert.rs:1104,1140`, `:1214,1258`); `delete_past_retention` — chosen then deleted by id, counted from `RETURN BEFORE`, `retry_on_write_conflict`; `clear_user_certificates_metadata` — idempotent (`metadata != {}`) |
| Schema additive, only v99, scope test, newest-version bump | **holds** | `SCHEMA_V99` is two `DEFINE FIELD IF NOT EXISTS` and two `DEFINE INDEX IF NOT EXISTS … UNIQUE`; `v99_adds_only_the_certificate_serial_and_its_unique_indexes` forbids `UPDATE`/`REMOVE`/`DELETE`/`OVERWRITE`/`DEFAULT`; the newest-version assertion names 99 |
| No `CONTRACT.md` record edits; spec regenerated only where the row says | **holds, with R110W1-03** | `sdks/CONTRACT.md` not in the diff; W1.10 and W1.11 regenerated `sdks/openapi.json` (both rows say so); a fresh dump is byte-identical; the drift is seven `description`s and the digest (§15); the registry was refreshed by W1.10 but not after W1.11 |
| No new crate without a layering row; no `[lints]` on an undocumented crate | **holds** | `check-crate-layering.py`: 19 crates, all edges inward; `axiam-db` gains only a dev-dependency (`rcgen`) |

## 5. W1.2 — the shared re-sign flight (orchestrator point 1)

**Can a waiter miss a newer revocation?** No. Three facts carry it:
(a) a **joiner** never returns the flight's list as such: after a successful
outcome it re-reads the cache with **its own** entries digest
(`slot.fresh(&digest, …)`), and the cache holds only a list signed over exactly
the state the flight itself read in `sign` (the digest is recomputed there from
the rows it signs, not taken from the leader's stamps). A joiner that read a
later state misses, loops, and leads or joins the next flight; one that read an
earlier state also misses and leads, getting a list at least as new as its
read. (b) The **leader** returns its own flight's outcome, and the flight reads
the rows after the leader read its stamps, so the list is never older than the
leader's read. (c) The leader's fast path (`fresh` after the claim) lands only
a list whose digest equals the leader's. "A revocation is in the next
response" therefore holds for every caller that read it.

**Leak, deadlock, lost marker.** The marker is set only under the `flight` lock
when unset and cleared only by its own `Landing` (`land` clears then sends;
`Drop` clears only when unlanded), so a second flight cannot exist on one slot
and a landed flight cannot clear a successor's marker. Between `join_or_lead`
and `tokio::spawn` there is no `.await`, so a caller dropped there cannot strand
the marker. A panicking or cancelled flight drops its `Landing`: the marker is
cleared and every receiver sees the channel closed (`interrupted()`, `500`, for
the leader; "look again" for joiners). Neither `std` lock is held across an
`.await`; `watch::Ref`s are dropped at the end of the match arm, before the next
`send_replace` could need the write lock. The spawned task owns a clone of the
service (`Arc`s only) and ends when `sign` ends: its waits are bounded by
`permit_wait`, the custodian's key read (Vault KV client, 10 s), and the
datastore. A slot `forget`-ten mid-flight leaves the old flight to land into an
unreachable slot — harmless. Spawned flights are at most one per publishing CA.

**Bound.** A joiner answers within `permit_wait` of entering `resign` (one
`deadline` for all its turns); one that turns leader waits its own flight.
The leader's wait is unbounded by the route but bounded by the flight (the
executor's residual, confirmed — appendix).

**`AxiamError: Clone`.** Every variant holds owned `String`s or `Option<String>`
(`error.rs:11-75`); no `#[source]`, no `Drop`, no secret-bearing field. Deriving
`Clone` changes no behaviour.

**`current_at`.** `resign` uses `now.max(Utc::now())` (`crl.rs:640`): an instant
in the past named through `current_at` is signed at the wall clock. Correct for
the route (it passes `Utc::now()`), and the wave's tests name future epochs; the
doc comment ("as of `now`", `:533-540`) does not say so (R110W1-06).

## 6. W1.1 — the clamp, and `I_new ≤ 2·I_old` (orchestrator point 2)

* `list_identity` (`crl.rs:966-982`) computes `min(max(floor, newest), ceiling)`
  with `ceiling = epoch.end − 1 s`; `floor = max(epoch.start, ca.notBefore)` is
  `≤ now < epoch.end` because `why_unpublished` refuses a CA before its
  `notBefore`. Within an epoch the entry set only grows (expiry is cut by the
  epoch's `expiring_after`; retention and the purge delete only rows past
  `notAfter + 8 d`, §8), so the number rises by `thisUpdate` or, at the ceiling,
  by the count. Across a boundary the new `thisUpdate ≥ epoch.end > ceiling`.
  Holds for any datastore lead, including one longer than an epoch.
* Stated entry dates are `min(recorded, thisUpdate)` (`stated_revocation_time`),
  earlier than recorded only for a date past the epoch — a conservative
  statement for a relying party.
* **Byte identity** holds: the clamp and the stated dates are functions of the
  epoch and the stored dates; `entries_digest` stays over recorded dates, which
  within an epoch determine the list. The new test signs the same DER from a
  second service earlier in the epoch.
* **The operator rule.** A list with `thisUpdate = T ≤ E_old.end − 1` signed
  under `I_old` is next fetched at `T + I_old`; the new grid's epoch start then
  satisfies `start > T + I_old − I_new/2`, which is `≥ T` exactly when
  `I_new ≤ 2·I_old`, so the new `thisUpdate ≥ start > T` and the number is
  greater. The guide's schedule (1 → 2 → 4 → 7 days, one *old* interval between
  raises) follows: lists signed under 1 d are gone from relying parties one day
  after the first raise. The condition is stated for relying parties that fetch
  at `nextUpdate`; one that refetches at `max-age` (the epoch end) can still see
  the step, as the guide says.

## 7. W1.3, W1.5, W1.6 (orchestrator point 8)

* **W1.3 scope.** `release_revoked_ca` (`ca.rs:1232-1270`) acts only on a row
  that is `Revoked` **and** `vault_pki`, builds the key reference from that
  row's own locator (`CaService::key_ref`), and `VaultPkiCaKeyStore::delete`
  deletes `locator.issuing` and `locator.root` (`vault_pki.rs:553-569`). The
  sweep forwards only subordinate CAs, whose locator records no root (they are
  minted by `sign-intermediate`), so exactly the child's issuer and key go —
  the same deletion `CaService::revoke` already makes. `404` is success, so a
  repeat is idempotent; the release runs at most twice per attempt, under the
  sweep's deadline, inside the claim. The matcher reads Vault's text, which no
  tenant controls; a false positive would only repeat a deletion revoke had
  already attempted. Holds.
* **W1.5 coverage.** Every consumer of `CustodianRevocation::Pending { reason }`
  (grep: `handlers/certificates.rs:617`, `handlers/ca_certificates.rs:387`,
  `cert.rs:1131,1249,1322`, `ca.rs:1149`) now sanitises before the audit append
  or the log; the stored reason was already sanitised; the forward still returns
  the raw reason so the W1.3 matcher can read it, and every sink sanitises.
  The matcher's own reach is R110W1-05.
* **W1.6.** `bootstrap_client()` and the private-CA client share
  `vault_client_builder()`; the test builds its client with the function
  `main.rs` calls. Neither client has a request timeout (pre-existing; appendix).

## 8. W1.4 and W1.7 — what the retention sweep deletes (orchestrator point 4)

* **Never a row a list still names**, given clocks within a day. A list signed
  in the epoch starting at `s` names entries with `notAfter > s − E`
  (`E = I/2`), so the last list naming an entry ends before `notAfter + I ≤
  notAfter + 7 d`; `PAST_REVOCATION_GRACE` is `not_after <= time::now() − 8d`
  (datastore clock). `crl_purge_margin.rs` pins `8 d ≥ MAX_CRL_NEXT_UPDATE_SECS
  + 1 d` and the one spelling of the eight days; `RefreshEpoch`'s premise
  (`start − expiring_after = E`) is pinned by
  `epochs_are_half_the_interval_and_aligned_for_every_replica`. With the
  datastore's clock more than a day ahead, a row can leave a list mid-epoch —
  a number glitch for a certificate already expired for over a week, not a
  revocation lost.
* **Never a CA row**: the statement is on `certificate` only; `ca_certificate`
  rows remain the tenant purge's (`KEPT_REVOCATION`).
* **Never a tombstoned tenant's rows**: `tenant_id` must be a tenant row with
  `deleted_at = NONE`; the W1.8 orphan marker is tombstoned, and an orphan id has
  no row, so both stay the purge's.
* **Two replicas**: each batch is chosen, its `cert_bound_to` edges deleted,
  then its rows deleted by id and counted from `RETURN BEFORE`; the loser of a
  race deletes and counts nothing, a write conflict is replayed. A row whose
  tenant is tombstoned between choice and deletion is past every list and would
  be deleted by the purge anyway.
* **References**: `cert_bound_to` (service-account binding) is deleted
  explicitly; the `signed_by` edge is not, exactly as in the tenant purge that
  has deleted certificate rows since 1.0.0 (not a wave change);
  `certificate.user_id` is a field. Audit rows naming the certificate stay.
* **First run on upgrade**: everything past `notAfter + 8 d` in every live
  tenant goes, 10 000 rows a tick, silently (no audit row, by design; an INFO
  job record). The cost is R110W1-01; the missing upgrade note is R110W1-06.
* **Erasure step (b4)**: `clear_user_certificates_metadata` shares
  `BELONGS_TO_ACCOUNT` (and its R101W1-01 collision rule) with the revocation, so
  it reaches no row the revocation would not; it runs after the revocation
  because the convention reads `metadata.user_id`. Holds.

## 9. W1.8 — the orphan claim, the binding re-check, the lease (orchestrator point 3)

**(a) The marker row.** `claim_orphan_purge` creates `tenant:<orphan id>` with
`organization_id = <nil>`, `slug = orphan-purge-<id>`, `metadata.orphan_purge =
true`, `deleted_at = purge_claimed_at = now`, no `has_tenant` edge;
`status`/`kind` take their defaults (`Active`, `standard`). Every reader of the
`tenant` table was checked:

| Reader | Sees the marker? |
|---|---|
| `get_by_id`, `get_by_slug`, `get_organization_tenant`, `update`, `list_by_organization` (count and page), `settings::lookup_org_id` | no — each filters `deleted_at = NONE` (`tenant.rs:624,644,671,710,842,855`, `settings.rs:696`) |
| SSF shared-issuer count (`count_for_shared_issuer`) | no — `deleted_at = NONE` (`tenant.rs:889`); the marker does not bump the D-55 generation, which is correct since the count cannot change |
| Organization tenant back-fill at boot | no — reads `kind = 'organization'` (`schema.rs:2576,2617`) |
| Slug uniqueness `(organization_id, slug)` | the nil organization and a per-id slug collide with nothing |
| Orphan scan (`orphaned_tenant_ids`) | yes, by design: the tenant table is read after the data tables, so a marked id is no orphan |
| Tombstone sweep (`list_tombstoned` → `claim_purge`) | yes, by design: skipped while `purge_claimed_at` is within the one-hour lease; taken over after it and purged as `PurgeScope::Orphan` |
| Retention sweep | no — not a live tenant |
| Admin/console listings, metrics, exports, SCIM | go through the repository methods above; no other query on `tenant` exists in the workspace (grep) |

**Lease expiry and takeover.** A live claimant that outlives the lease and the
taking-over sweep both purge (idempotent steps); only the one whose final
`DELETE … RETURN BEFORE` removes the marker records, and the claimant's
`drop_orphan_claim` cannot remove a marker the sweep re-stamped. **A crash
between claim and purge** leaves the marker; no scan treats the id as an orphan
until the sweep takes it over an hour later and records it once, `orphan:
true`. A failed purge drops its own marker; a failed drop lapses with the
lease. A stale scan claims afresh, finds nothing purgeable (`has_purgeable_rows`
uses the scan's own notion) and records nothing. Holds — but the marker is
recognised by an administrator-writable key (R110W1-04).

**(b) The re-check.** Both routes re-read the account after `create`
(`certificates.rs:134,308,441`); on `Deleted`, `Anonymized`, not found, or a
failed read they revoke through `CertService::revoke` (dated, on the list,
forwarded under `vault_pki`, a pending forward audited with the sanitised
reason) and return the binding's `400` or the read's error — the
`GeneratedCertificate`, private key included, is dropped. `users::delete` revokes
once more after the tombstone, by binding and `metadata.user_id`
(`users.rs:598-622`). Interleavings of issuance (check → create → re-check) and
deletion (revoke₁ → tombstone → revoke₂): a row created before revoke₁ is
revoked by it; created between revoke₁ and revoke₂, by revoke₂ (which starts
after the row's commit); created after revoke₂, the re-check starts after the
tombstone's commit and revokes. **Does a key ever leave on a revoked
certificate?** Not on one revoked before the response: when the re-check reads
the account alive the key is returned, and revoke₂ may revoke the certificate a
moment later — the ordinary issue-then-delete order. If the re-check's own
revocation fails, the key is withheld and the row stays active and bound to a
deleted account, logged with its id (narrow: a datastore failure).
**(c)** `target = None` revokes nothing and both passes are skipped. Holds.
**(d)** Both `record_vault_forward_failure`s write `WHERE vault_next_attempt_at
= $lease` with `retry_hot_row`, and return whether they wrote; the sweep logs a
lapsed claim at debug. `$lease` is exactly what the claim stored. Holds.

## 10. W1.9, W1.10, W1.11 (orchestrator points 5, 6, 7)

* **v99 and `NONE`.** Rows written before v99 carry `serial = NONE`, which the
  UNIQUE index does not treat as colliding (`rows_without_a_recorded_serial_do_not_collide`,
  `v99_applies_over_rows_that_already_share_a_serial`, run). Roots are not
  recorded (`parent_ca_id` bound only for a child). A racing issuance cannot
  collide on 159 random bits. **Spelling**: the stored value is
  `hex(cert.serial.to_bytes_be())` and the CRL entry is
  `SerialNumber::from_slice(&cert.serial.to_bytes_be())` — the same magnitude
  from the same parser. **Vault-issued serials** are read back from the PEM Vault
  returned, so they are recorded the same way. A collision (only reachable by a
  re-recorded pre-1.1.0 certificate) surfaces as `DbError::Migration` → `500`
  rather than `409`, because `create` maps `check()` errors to `Migration`
  (`certificate.rs:411-413`) instead of `classify_write_error` — appendix.
* **W1.10 reload paths.** Every CA key a custodian returns is parsed by
  `rcgen::KeyPair::from_pem` (`cert.rs:525,878`, `crl.rs:1003`,
  `ca.rs:506,677,1701`), which reads RFC 5958 v1 and v2 alike (ring's
  `from_pkcs8_maybe_unchecked`); the local custodian decrypts to the stored PEM,
  Vault KV returns it, `vault_pki` holds no exportable key. v2 is what *ring*
  itself emits and what every key stored before 1.1.0 is; the loader did not
  change, so those keep loading, and
  `ed25519_pkcs8_v1_round_trips_to_the_same_signing_key` loads and signs with
  the new form. The SAML
  IdP credential is RSA (`saml_signing.rs`), untouched. The new PEM is built
  from a `Zeroizing` DER; the returned `String`, as before, is not zeroized.
* **W1.11 paths.** Leaf `generate`, root and signing-CA `generate`,
  `intermediate_subject`, the SAML credential subject (51 characters), and the
  CSR's first CN go through the rules; the `vault_pki` intermediate default is
  refused past 64 characters; `sign_as_intermediate` states `common_name` with
  `use_csr_values: false`. **The one path that still builds a DN without the
  check** is `sign-verbatim` with a caller's CSR (R110W1-02). An imported CA's
  subject is taken from the certificate the administrator supplied, unchecked,
  as the commit says. No refusal message repeats the value
  (`a_refusal_never_quotes_the_subject`; the CSR and intermediate-default
  messages hold no interpolated value).

## 11. Threat-model text against the code (orchestrator point 10)

The seven entries the wave edited — T-102, T-187, T-336, T-461, T-470, T-472,
T-476 — carry identical added text in `Axiam.json` and the STRIDE document
(script, §15: 63 added sentences, 0 missing); `gen-threat-model.mjs` leaves no
diff (477 threats: 443 / 19 / 15). Against the code:

| Entry | Verdict |
|---|---|
| T-102 (#615, #616) | accurate; the residuals (datastore lead, interval change, skew; the leader's wait) are the right ones |
| T-187 (#618) | accurate; its "a list keeps an expired entry for at most seven days" is `MAX_CRL_NEXT_UPDATE_SECS`; it does not mention the scan cost (R110W1-01) |
| T-336 (#622 b, c) | accurate, including the Art. 17 residual |
| T-461 (#649) | **overstates**: "can no longer reach … through a certificate issued from 1.1.0" is false under `vault_pki` CSR signing (R110W1-02) |
| T-470 (#617, #619) | accurate on the release; the sanitiser residual names one of three unmasked shapes (R110W1-05) |
| T-472 (#622 a) | accurate on the claim; its unchanged body still calls the kept rows a "security and legal-obligation retention" (`:434`), which T-187 and the GDPR guide now withdraw (R110W1-06); "every tenant read filters `deleted_at`" verified (§9) |
| T-476 (#620) | accurate |

## 12. Documentation claims

| Claim (where) | Verdict |
|---|---|
| "The number grows … on two conditions" and the raising schedule (`crl.rs` module doc, PKI guide) | true (§6) |
| "callers queued on a saturated gate all answer within about five seconds" (PKI guide) | true for joiners; the starting request waits its flight (stated in T-102) |
| "the CSR's common name … is refused, not rewritten" (OpenAPI `SignCertificateCsrRequest`, PKI guide) | true for the first CN; other attributes pass on `vault_pki` (R110W1-02) |
| "a stored CA key keeps working in either [form]" (PKI guide) | true (§10) |
| "rows written before v99 … cannot fail" (PKI guide) | true (tests run) |
| "deletes every certificate row of a live tenant more than eight days past its `notAfter` … safe on two replicas" (GDPR guide) | true; cost unstated (R110W1-01) |
| `operate.ts` job list (22 sweeps) and `vault_revocation` failure semantics | true against `SWEEP_JOBS` and `forward_pending_revocations` |
| Admin guide "kept … until eight days after it expires" | true |

## 13. Orchestrator point 9 — the spec and the registry

`./target/debug/axiam-server --dump-openapi` (built `--no-default-features`, as
the drift workflow does) is byte-identical to `sdks/openapi.json`;
`check-spec-digest.py` passes; ignoring `description` keys and the digest, the
base and head documents are equal, and seven descriptions changed or were
added (CA generate, CRL route, the two `subject` fields, the two
`private_key_pem` fields, `SignCertificateCsrRequest`). The registry is stale
(R110W1-03): regenerating it changes only `spec_digest`, `b671db54…` →
`b7d07550…`; no operation moves.

## 14. Executors' follow-ups, confirmed or rejected

| Follow-up | Verdict |
|---|---|
| The CRL flight-starting request still waits up to the permit wait plus the Vault key read | **confirmed, no issue**: bounded by the flight (permit wait + Vault KV 10 s timeout + datastore); recorded in T-102 |
| Request-path issuer-release retry not added | **rejected**: the sweep's first attempt after the revocation takes exactly that case (trigger 2), within one backoff step |
| 256-character cut of `vault_forward_last_error` | **rejected**: trigger 2 matches the untruncated reason of the refused forward itself; the cut only costs one extra forward |
| `"token".` not masked; broad `b.` prefix | **confirmed, wider** → R110W1-05 |
| Bootstrap Vault client has no request timeout | **confirmed, pre-existing** (also the private-CA client): a Vault that accepts and never answers stalls startup; worth an issue (Informational) — `vault_client_builder().timeout(VAULT_TIMEOUT)` and a test against a wiremock delay |
| Art. 17 purge revokes at b4, anonymizes after, no second revoke | **confirmed**, Informational: the account stays live (status unchanged) through the grace period, so an administrator's bound issuance between (b4) and anonymization survives; T-336 records it. Fix: a second `revoke_user_certificates` by binding after `anonymize_user`, outside the pinned pipeline order (after `run_erasure_pipeline_reporting` returns) |
| Unique-serial violation surfaces as `DbError::Migration`, not `409` | **confirmed**, Informational: `certificate.rs:411-413` (and the CA repository's `create`) map with `DbError::Migration`; use `classify_write_error(e, "certificate")`. Reachable only by re-recording a pre-1.1.0 certificate |
| No test of the `vault_pki` intermediate-default > 64 refusal | **confirmed** → R110W1-06 |
| T-472/T-102 still cite Art. 17(3)(b) | **T-472 confirmed in substance** ("legal-obligation retention", `:434`, no article number) → R110W1-06; **T-102 rejected** (no such wording) |
| A unit test pinning the CRL epoch premise | **rejected**: `epochs_are_half_the_interval_and_aligned_for_every_replica` asserts `start − expiring_after = E` |

## 15. Checks run

Each command with its own exit code (logs in the scratchpad; probe files
deleted before the commit, and their test binaries removed).

| Check | Result |
|---|---|
| `cargo build -p axiam-server --no-default-features` (swagger placeholder, `CARGO_INCREMENTAL=0`, line-tables-only) | exit 0 |
| `./target/debug/axiam-server --dump-openapi` vs `sdks/openapi.json` (`cmp`) | exit 0 — **byte-identical** |
| Base vs head `openapi.json` ignoring `description` and the digest (script) | equal; 7 descriptions changed/added |
| `python3 scripts/check-spec-digest.py` | exit 0 |
| `python3 scripts/gen-management-registry.py --check` | **exit 1 — stale** (R110W1-03); regenerating changes only `spec_digest` (file restored afterwards) |
| `python3 scripts/check-crate-layering.py` | exit 0 (19 crates, 62 edges inward) |
| `python3 scripts/check-remediation-evidence.py` | exit 0 (37 verified) |
| `bash scripts/check-doc-links.sh` | exit 0 (510 links) |
| `python3 scripts/check-config-key-coverage.py` | exit 0 |
| `node website/scripts/gen-threat-model.mjs` | exit 0; 477 (443 / 19 / 15); `git status` clean |
| Threat-amendment comparison, JSON vs STRIDE (script) | 7 entries, 63 added sentences, 0 missing |
| `cargo fmt -p <crate> -- --check` for axiam-pki, -db, -core, -auth, -api-rest, -server | exit 0 each |
| `cargo test -p axiam-pki --test crl_test --test vault_pki_test --test cert_test` | exit 0 (19, 31, 29) |
| `cargo test -p axiam-pki --lib` | exit 0 (148, 1 ignored) |
| `cargo test -p axiam-db --test certificate_repository_test --test ca_certificate_repository_test --test tenant_purge_test` | exit 0 (21, 20, 9) |
| `cargo test -p axiam-db --lib schema` | exit 0 (76) |
| `cargo test -p axiam-auth --test vault_provider_test` | exit 0 (11) |
| `cargo test -p axiam-server --no-default-features --test crl_purge_margin --test cleanup_task --test req14_gdpr_test` | exit 0 (2, 32, 5) |
| **Probe A** (R110W1-02) — temporary copy of `vault_pki_test.rs` with two tests added (A and D): CSR `CN=byok-device`, `OU="evil\nline \u{202E}gnp.exe"`, second `CN="second\ncn"`, `sign_csr` under a `vault_pki` CA (wiremock) | `sign_csr` **Ok**; CSR sent to `sign-verbatim` byte for byte; row `subject = "byok-device"`; exit 0 |
| **Probe B** (R110W1-04) — temporary copy of `tenant_purge_test.rs`: tenant created with `metadata {orphan_purge: true}`, populated, export receipt recorded, deleted, `purge_tombstoned` | report `{audit_exported_through: None, audit_rows_deleted: 0, audit_rows_kept: 2, orphan: true}`; exit 0 |
| **Probe C** (R110W1-01) — same file: 3 000 past-grace certificate rows of a tombstoned tenant, 301 tenants | `delete_past_retention(500)` → 0 rows in **35.999 s**; hoisted `LET` form **61.8 ms**; exit 0 |
| **Probe D** (R110W1-05) — same file: `sanitise_reason` on eight inputs (two runs) | `token=hvs.…`, `{"token":"hvs.…"}`, `"hvs.…".` unmasked; `b.vault-internal.example.com`, `s.vault-1.eu-west.internal` → `[redacted]`; exit 0 (both runs) |
| Commit signatures | 11 of 11 carry `gpgsig` |

## 16. Issue bodies

### R110W1-01 (Medium) — the certificate retention sweep re-reads the tenant table for every candidate row

`delete_past_retention` (`crates/axiam-db/src/repository/certificate.rs:895-909`,
#618) selects `FROM certificate WHERE not_after <= time::now() - 8d AND
tenant_id IN (SELECT VALUE meta::id(id) FROM tenant WHERE deleted_at = NONE)
LIMIT $limit`; the subquery is evaluated once per candidate row, and
`certificate` has no index on `not_after`. Measured (in-memory engine, debug
build): 3 000 candidate rows of a tombstoned tenant and 301 tenants, 36.0 s for
one call; the same selection with the tenant set in a `LET` first, 62 ms. The
sweep runs every cleanup tick (300 s) on every replica, in line before
`dcr_registration_tokens`, `directory_sync`, `scim_reconcile` and the next tick,
up to 20 batches of 500; the first ticks after the upgrade make every
past-grace row of every live tenant a candidate. **Fix:** `LET $live = (SELECT
VALUE meta::id(id) FROM tenant WHERE deleted_at = NONE);` then `tenant_id IN
$live` in `$doomed`, and `result.take(4)`. **Test:**
`the_retention_batch_reads_the_tenant_table_once` — 2 000 past-grace rows of a
tombstoned tenant and 200 live tenants: `delete_past_retention(500)` returns 0
within 5 s, and a past-grace row of a live tenant is still deleted; the two
existing sweep tests still pass.

### R110W1-02 (Low) — a `vault_pki` CSR's other subject attributes bypass the common-name rules

`inspect_csr` (`crates/axiam-pki/src/ca.rs:1486-1503`, #649) checks the CSR's
first CN only. In-process signing rebuilds the DN from that name, but under a
`vault_pki` CA `sign_csr` forwards the caller's CSR to `sign-verbatim`
(`vault_pki.rs:714-730`), which copies the CSR's whole subject. Probe: a CSR
with a clean first CN, an `OU` holding `\n` and U+202E, and a second CN holding
`\n` is accepted and sent to Vault byte for byte; the row's subject is the clean
CN. A relying party that reads the last CN (Go's `crypto/x509`) sees another
name than the row, and logs render the newline. T-461's amendment says this can
no longer happen from 1.1.0. **Fix:** in `inspect_csr`, refuse a subject with
more than one CN, and refuse any attribute other than the CN (D-2: one
component) — or at least run `check_common_name_value` on every attribute
value; amend T-461. **Test:** `vault_pki_test.rs` — two CNs, and an `OU` with
U+202E, are each `400` with no request to `sign-verbatim` (`.expect(0)`); the
verbatim test still passes.

### R110W1-03 (Informational) — `management-registry.json` stale after W1.11

W1.11 (`28dc3eb6`) regenerated `sdks/openapi.json` (digest `sha256:b7d07550…`)
without regenerating `sdks/management-registry.json`, whose `spec_digest` is
still W1.10's `sha256:b671db54…`. `python3 scripts/gen-management-registry.py
--check` fails, and `ci.yml:88` with it. **Fix:** run
`python3 scripts/gen-management-registry.py` (only `spec_digest` changes) and
commit. **Test:** the `--check` step.

### R110W1-04 (Informational) — the orphan-purge marker is recognised by an administrator-writable key

`purge_tombstoned` treats a tombstoned tenant row as an orphan's claim marker
when `metadata.orphan_purge = true` (`tenant.rs:335-350`; also the marker read
in `purge_orphan`, `:494-510`). Tenant `metadata` is free-form and written by
`tenants:create`/`tenants:update`. Probe: a tenant created with
`{"orphan_purge": true}`, deleted with an export receipt, is purged as
`PurgeScope::Orphan` — the receipt ignored, its audit trail kept for the
retention sweep instead of deleted, and `tenants.purged` written (append-only)
with `orphan: true`. **Fix:** recognise the marker by what no API can write as
well — `organization_id = <nil>` (a tenant is always created under an existing
organization) and the `orphan-purge-<id>` slug — in both reads; optionally
refuse `orphan_purge` in tenant `metadata` on create/update. **Test:**
`tenant_purge_test.rs` — a tenant whose metadata carries `orphan_purge: true` is
purged as `Tombstoned` (receipt honoured, `orphan: false`); the orphan tests
still pass.

### R110W1-05 (Informational) — the Vault-reason sanitiser misses tokens inside a word and masks host names

`sanitise_reason`/`looks_like_a_token` (`crates/axiam-pki/src/vault_forward.rs:51-90`)
test each whitespace-separated word, after trimming non-token characters from
its ends, for a token prefix at its start. Probe: `token=hvs.…`,
`{"token":"hvs.…"}` and `"hvs.…".` are left as they are; `b.vault-internal.example.com`
and `s.vault-1.eu-west.internal` become `[redacted]`. Vault does not echo
tokens, so nothing leaks today; this is the second line of defence T-470
describes, and T-470 records only the third shape. **Fix:** scan each word for
a token at any position preceded by a non-token character (`=`, `"`, `:`,
`'`, start), mask that span only; for the legacy `s.`/`b.` prefixes require a
body without `.` (legacy tokens are base62/base64url). Amend T-470. **Test:**
unit cases for the three unmasked shapes and the two host names.

### R110W1-06 (Informational) — text and tests behind the code after W1

(a) T-472 (`claude_dev/threat-model-stride.md:434` and `Axiam.json`) calls a
deleted tenant's kept certificate rows "a security and legal-obligation
retention"; W1.4 withdrew that basis in T-187 and `gdpr-compliance.md`
(Art. 6(1)(f), Art. 32). (b) `CrlService::current_at` says it answers "as of
`now`" (`crl.rs:533-540`), but `resign` signs an earlier instant at the wall
clock (`:640`); say so, or keep the named instant when it is in the past. (c) No
test pins the `vault_pki` intermediate-default refusal (`ca.rs:254-276`): a
57-character subject with no `intermediate_subject` → `400`, no request to
Vault. (d) `CHANGELOG.md` `[Unreleased]` is empty: the release notes (W8) should
carry an upgrade note that the first `certificate_retention` runs delete every
certificate row more than eight days past `notAfter` in live tenants (no audit
row, no opt-out), and that subjects with control characters, two spaces or more
than 64 characters are now `400`.

## 17. Invariants

I1 (nothing registered today changes behaviour unless the wave says so) holds
for what was read: the behaviour changes are the documented ones — CRL
`thisUpdate` clamped, a queued CRL request answers `503` within the permit wait,
the sweep re-releases a refused CA, an erased account's certificate `metadata`
is cleared, certificate rows go eight days past `notAfter`, Vault reasons are
sanitised at every sink, an orphan purge records once, a binding re-check can
answer `400` after issuing (and revoking), `DELETE` of an unknown user revokes
nothing, serials are random and unique per issuer, Ed25519 keys are returned as
v1, and common names are refused by the new rules. No contract record changed;
the OpenAPI file matches the server. This review changed no file but itself;
the probe files were removed before the commit.
