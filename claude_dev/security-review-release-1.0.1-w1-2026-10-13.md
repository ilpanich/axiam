# Security review — release 1.0.1, wave W1 (F4)

**Date:** 2026-10-13.
**Against:** `claude/release-1.0.1-w1`, the whole wave diff `v1.0.0..2b6607a8d`
(8 commits, 65 files, about 6 060 lines added and 360 removed; `v1.0.0` is
`0a90de0`, `chore(release): prepare axiam 1.0.0`). Every commit carries a
signature (`BEGIN SSH SIGNATURE` present in all 8; the sandbox has no
`gpg.ssh.allowedSignersFile`, so `%G?` reads `N` and cannot verify them here).
**Scope:** every W1 task of the release-1.0.1 plan (§2): W1.1 #609 (CRL
distribution URL, `9637c647f`), W1.2 #611(a) (Vault clients and redirects,
T-476, `b8f298564`), W1.3 #607 (per-CA re-sign, light read, `0df1c7c97`), W1.4
#608 (deterministic CRL identity, `max-age`, `fe7768172`), W1.5 #603 (Vault
sweep backoff and claim, schema v95, `f05bd401b`), W1.6 #612 (tenant signing CA
forwarded to its parent's list in Vault, schema v96, `363b40d5f`), W1.7 #610(c)
(one replica purges a tombstoned tenant, schema v97, `584424971`), W1.8 #533
(certificate ↔ user binding, deletion and erasure revoke, schema v98,
`2b6607a8d`).
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) and
`Axiam.json` (model 2.40.0, 476 threats: 438 / 17 / 21), the plan's §9 rules
(Phase 23 §7 included), and the OWASP ASVS 5.0 areas the diff touches (V2
business logic, V8 authorization, V9 certificates and tokens, V12 secure
communication / outbound requests, V13 configuration, V14 data protection, V16
logging). Claims were checked against the code, not the commit messages; four
were checked by a probe (§13). This review fixes nothing (the orchestrator's
instruction): every finding is reported with evidence, a proposed fix and an
issue body (§14). IDs: `R101W1-nn`.

---

## 0. Summary

**One Medium finding, introduced by the wave; nothing High or Critical.**

* **R101W1-01 (Medium, wave — #533).** The 1.0.0 name convention for an
  *unbound* `User` certificate — `metadata.user_id`, or a subject equal to the
  account's username or email **ignoring case** — used to run only at directory
  linking. W1.8 runs it on two new paths: the administrator's
  `DELETE /api/v1/users/{id}` and the Art. 17 purge, which the account holder
  starts themselves (`POST /api/v1/account/delete`). Usernames and emails are unique
  **case-sensitively** (`idx_user_tenant_username`, `idx_user_tenant_email`),
  so `alice` and `Alice` can both exist; deleting or erasing `Alice` revokes
  `alice`'s unbound certificate with CN `alice` (probe, §13). An account
  created *after* a certificate — by an administrator, SCIM, or federation JIT
  (which sets `username = email` from the IdP's claim) — can be named after an
  existing certificate's CN and then erased by its holder. Revocation is
  irreversible. This is the over-match #533 was filed to stop, now reachable by
  a non-administrator; every certificate issued before 1.0.1 is unbound.

Four Low and four Informational findings are reported for `1.0.x` (§14).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R101W1-01** | Admin deletion and the self-service Art. 17 purge revoke every unbound `User` certificate whose CN case-insensitively equals the account's username or email — another account's included (case-variant accounts; an account created later under an existing CN). | **Medium** | `certificate.rs:735-775`, `users.rs:553-583`, `cleanup.rs:841,1830` → T-336, T-187 | wave | **Fix in wave** (proposed §2) |
| R101W1-02 | The CRL number and `thisUpdate` are not monotonic in three cases the documentation says cannot arise: a restart with a larger `AXIAM__PKI__CRL_NEXT_UPDATE_SECS`; a revocation date ahead of the signer's clock (also a `thisUpdate` in the future); replicas whose clocks straddle a boundary. | Low | `crl.rs:669-720` → T-102 | wave | Reported |
| R101W1-03 | Requests queued on one CA's signing mutex do not share the in-flight outcome: with the crypto gate saturated each waits out its own five-second permit wait in turn (k-th waiter ≈ k × 5 s), unauthenticated. | Low | `crl.rs:482,571` → T-102 (availability) | wave | Reported |
| R101W1-04 | Single-mount `vault_pki` layout: the CA forward runs after the key release; a release that failed (logged and swallowed) leaves the child an issuer in the parent's mount, Vault refuses every forward, and the sweep never retries the release. | Low | `ca.rs:965-998`, `cert.rs:1176-1265` → T-470 | wave | Reported |
| R101W1-05 | An erased account's revoked certificate rows keep the PEM, `subject` and free-form `metadata` for the tenant's lifetime; the per-user erasure does not even clear `metadata`, which the tenant purge does. Documented as a residual, not contradicted by the docs; in tension with Art. 5(1)(e). | Low | `cleanup.rs:1825-1830`, `gdpr-compliance.md:191-216` → T-187 | wave | Reported |
| R101W1-06 | The Vault forward's reason is sanitised for the row only: the two `*.vault_revocation_pending` audit rows (append-only) and the error logs carry it raw and unbounded; the token pattern misses legacy `b.` batch tokens. No token was found to reach any of them. | Informational | `ca_certificates.rs:396`, `certificates.rs:491`, `vault_forward.rs:76-84` | wave | Reported |
| R101W1-07 | `main.rs`'s bootstrap Vault client has no test of its own: the test builds an equivalent client, so a regression to `Client::new()` in `main.rs` passes every test. | Informational | `main.rs:148-155`, `vault_provider_test.rs` → T-476 | wave | Reported |
| R101W1-08 | Text left behind by W1.4/W1.5: two guides still say the purge removes a revoked certificate "once it expires"; the operations page says `vault_revocation` "fails while any remains"; the eight-day purge margin is not tied to `MAX_CRL_NEXT_UPDATE_SECS`. | Informational | `docs/admin/README.md:254`, `website/src/docs/operate.ts:1090,1186`, `tenant_purge.rs:140` | wave | Reported |
| R101W1-09 | Small races and edges: concurrent orphan purges still write two `tenants.purged` rows; issuance can bind a certificate to an account being deleted; `DELETE /users/{unknown}` revokes `metadata.user_id` matches before answering `404`. | Informational | `cleanup.rs:280`, `certificates.rs:58-93`, `users.rs:553-583` | wave | Reported |

**What held.** Every §9 / Phase 23 §7 rule holds for what the wave added (§4).
The wave adds no route. The one new credential-bearing outbound call
(`POST <parent mount>/revoke`) goes through the Vault PKI client, which now
never follows a redirect; all four Vault-facing clients carry
`redirect(Policy::none())` and a `3xx` is an error naming the host (§5). Both
new sweep claims (`claim_vault_forward` on two tables, `claim_purge`) are
conditional writes on the value read, retried on write conflict, and pinned by
two-replica tests. The four migrations are additive (`IF NOT EXISTS`), carry no
`UPDATE`/`DEFAULT`, each has its scope test, and the newest-version assertion
names v98. The per-CA slot map is bounded by the CAs that publish a list
(random and non-publishing ids add nothing; §6); a cached list never waits on a
re-sign; only Ed25519 and RSA PKCS#1 v1.5 keys can reach CRL signing, so byte
identity across replicas holds (§6). The Vault backoff, claim and threshold job
are correct, and a refused row cannot starve a later one (§7). The executor's
reading of Vault's PKI semantics for W1.6 is right (§8). The tenant purge claim
is sound and its overlap after the lease costs work only (§9). The `user_id`
validation is complete (§10). Threat-model amendments are identical across
`Axiam.json`, the STRIDE document and the generated `website/src/threatModel.ts`,
the generator leaves no diff, and the counts read 476 = 438 / 17 / 21 wherever
they appear (§11). `sdks/openapi.json` was regenerated from a server build and
is byte-identical to the committed file; the digest and the management registry
check out (§13).

**Verdict on merge.** R101W1-01 should be fixed in the wave: it is small (one
extra predicate, §2) and the wave itself created the path by which a
non-administrator reaches it. Nothing else blocks.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| CRL distribution URL | W1.1 #609 | `crl.rs` (`CrlDistribution::new`), `crl_test.rs` | **read in full** |
| Vault redirects | W1.2 #611(a) | `vault_pki.rs`, `ca_key_store.rs`, `secrets.rs`, `main.rs`, three test files; every `X-Vault-Token` sender located by grep | **read in full**; tests run |
| CRL per-CA re-sign, light read, 503 | W1.3 #607 | `crl.rs`, `handlers/crl.rs`, `certificate.rs`/`ca_certificate.rs` stamp queries | **read in full**; **probed** the signing queue (§12) |
| CRL identity, epochs, `max-age` | W1.4 #608 | `crl.rs` (`RefreshEpoch`, `list_identity`), `tenant_purge.rs` (`KEPT_REVOCATION`), `boot.rs` (interval validation), every row-deleting and status-writing query on `certificate`/`ca_certificate` | **read in full**; **probed** two monotonicity breaks (§12) |
| Vault sweep backoff, claim, threshold | W1.5 #603 | `vault_forward.rs`, `cert.rs` (sweep), `certificate.rs` (due list, claim, failure, count), `cleanup.rs`, `job_health.rs`, schema v95 | **read in full**; tests run |
| CA revocation forward | W1.6 #612 | `ca.rs` (`revoke_within`, `forward_ca_revocation`, `revoke_tenant_cas`), `vault_pki.rs` (`revoke_signed_ca`, `delete`), `ca_certificate.rs`, `handlers/ca_certificates.rs`, `handlers/tenants.rs`, schema v96, PKI guide policy | **read in full**; Vault semantics checked (§8) |
| Tenant purge claim | W1.7 #610(c) | `tenant.rs` (`claim_purge`, `release_purge_claim`, `purge_tombstoned`, `purge_orphan`), `cleanup.rs` (`sweep_tenant_purge`), schema v97 | **read in full**; tests run |
| Certificate ↔ user binding | W1.8 #533 | `models/certificate.rs`, `cert.rs` (`check_user_binding`), `handlers/certificates.rs`, `handlers/users.rs`, `certificate.rs` (`revoke_user_certificates`), `cleanup.rs` (step b4), `directory.rs`, schema v98, user creation paths (`user.rs`, `oidc.rs` JIT, directory collision probe), GDPR handler | **read in full**; **probed** the cross-account match (§12) |
| Threat model and docs | all | `Axiam.json`, STRIDE, write-up, `website/src/*.ts`, `FINDINGS.md`, PKI, admin, GDPR and deployment guides | entries T-476, T-102, T-470, T-472, T-336, T-187 compared with the code (§11) |

Not run: the `axiam-api-rest` and `axiam-server` integration suites (each needs
a further multi-GB build on a disk with 12 GB left after the targeted builds;
the crate-level tests in §13 cover the logic they pin), the frontend suites, a
real Vault, a multi-replica deployment.

## 2. R101W1-01 — deletion and erasure revoke another account's certificate by name

**Severity: Medium. Wave-introduced (#533). Proposed for a fix in the wave.**

**Evidence.**
* `crates/axiam-db/src/repository/certificate.rs:735-775` —
  `revoke_user_certificates` revokes every active `User` certificate of the
  tenant `WHERE user_id = $user_id OR (user_id = NONE AND (metadata.user_id =
  $user_id OR string::lowercase(subject) IN $names))`, `$names` being the
  account's username and email lowercased. Nothing ties an unbound row to the
  account other than the folded name.
* `crates/axiam-api-rest/src/handlers/users.rs:553-583` (admin deletion) and
  `crates/axiam-server/src/cleanup.rs:841,1830` (Art. 17 purge, step b4) — both
  new in W1.8 — call it with the account's username and email. The purge is
  started by the data subject: `request_account_delete`
  (`handlers/gdpr.rs:471`), self-service.
* `crates/axiam-db/src/schema.rs:594-597` — `idx_user_tenant_username` and
  `idx_user_tenant_email` are unique on the raw values, so accounts differing
  only in case coexist. Only the directory path probes for a case-insensitive
  collision (`directory.rs:189`); the admin API, SCIM and federation JIT do not.
  Federation JIT sets `username = email` from the IdP's claim
  (`crates/axiam-federation/src/oidc.rs:837`).
* **Probe (§13):** account `alice`, an unbound `User` certificate with subject
  `alice`, then an account `Alice` / `ALICE@example.com` created (accepted);
  `revoke_user_certificates` for `Alice` returned **1** and `alice`'s
  certificate read back **Revoked**.

**Consequences.** An administrator deleting one account, or any account holder
erasing their own, revokes the unbound certificates of every other account
whose certificate CN folds to the same string — irreversibly (there is no
un-revoke; the victim needs a new certificate, and its revocation is on the
CRL and, under `vault_pki`, forwarded to Vault). Every certificate issued
before 1.0.1 is unbound, as is any issued later without `user_id`. The
pre-condition for the self-service variant is an account whose username or
email folds to an existing certificate's CN: a case variant of another
account's name (admin, SCIM, or a JIT IdP that admits the address), or a name
no account held when the certificate was issued. T-336's amendment calls the
remaining over-match a residual "with its over-matching"; it does not say the
wave added two triggers, one of them in the account holder's hands.

**Proposed fix (one predicate, plus a guard).**
1. In `revoke_user_certificates`, apply the convention only to an unbound row
   **created at or after the account**: `(user_id = NONE AND created_at >=
   $user_created_at AND (metadata.user_id = $user_id OR
   string::lowercase(subject) IN $names))`. A certificate issued before the
   account existed cannot have been issued for it. The trait gains the account's
   `created_at` (all three callers hold the `User`; linking has it too).
2. Drop a name from `$names` when another account of the tenant (any status
   but the target) has the same folded username or email — the repository
   already has the probe (`SurrealUserRepository::identity_collision`, used by
   the directory path). An ambiguous name is not evidence.
3. Keep the bound match and the `metadata.user_id` match as they are (the
   latter is written by the issuer, not by the account).
4. T-336 and T-187: say the convention is limited to certificates issued after
   the account and to unambiguous names; the PKI guide's `user_id` section and
   `gdpr-compliance.md` likewise.

**Tests.** (a) Repository: `alice` with an unbound CN-`alice` certificate; an
account `Alice` created after it; revoking `Alice`'s certificates leaves
`alice`'s active. (b) Same with the certificate issued after both accounts
exist: the ambiguous name revokes nothing by name. (c) The existing
`deleting_a_user_revokes_their_user_certificates_and_no_one_elses` and the
directory linking test still pass (the legacy row there was created after the
account).

## 3. R101W1-02 — the CRL number can go down

**Severity: Low. Wave-introduced (#608).**

**Evidence.** `crates/axiam-pki/src/crl.rs:669-720`: `thisUpdate =
max(epoch.start, ca.notBefore, newest revocation date)`; number =
`thisUpdate_secs << 24 | count`; epochs are half the configured interval,
aligned to the Unix epoch. The derivation is monotonic only while the interval
is fixed and every clock that writes a revocation date or picks an epoch
agrees. Three cases break it:

1. **Interval change.** Raising `AXIAM__PKI__CRL_NEXT_UPDATE_SECS` (a restart,
   or a rolling deploy with mixed values) moves the epoch start backwards.
   Probe: a list with no recent revocation, 13 h after a 3.5-day boundary —
   1-day config: `thisUpdate` 12:00, number …657369601; 7-day config one second
   later: `thisUpdate` 00:00, number …146881638401 (**lower**). Lowering the
   interval moves `expiring_after` forward and drops entries while `thisUpdate`
   may stay put (a lower count, so a lower number).
2. **A revocation date ahead of the signer.** `revoked_at` is written by the
   datastore's clock (`time::now()`), the epoch by the replica's. Probe: a
   `revoked_at` 10 s past the next boundary and another revoked entry that
   expired just before the current epoch began — signed now: `thisUpdate` 22 s
   **in the future**, count 2; signed one second past the boundary: same
   `thisUpdate`, count 1, number **lower**. A `thisUpdate` in the future is
   also refused by strict relying parties (OpenSSL: `CRL is not yet valid`)
   until their clock catches up.
3. **Replica skew at a boundary.** A replica whose clock has passed the
   boundary serves the new epoch's list (possibly with fewer entries); one that
   has not keeps serving the old. A relying party alternating between them sees
   the number fall back. Rolling upgrades from 1.0.0 do the same for a moment
   (1.0.0's millisecond numbers are lower than the new ones, so only an old
   replica answering after a new one does).

The module doc (`crl.rs` "No replica keeps serving an earlier epoch's list…",
`list_identity` "The number grows with every change"), T-102's #608 amendment
and the PKI guide ("The number grows with every change of the list") state
monotonicity without these conditions; T-102's residual mentions skew and "a
fraction of a second", which understates case 2 and omits case 1. Practical
impact is small — a lower number never carries a revocation the higher one
lacked except an entry that expired — but RFC 5280 §5.2.3 asks for a
monotonically increasing number and some relying parties discard a CRL with a
lower one.

**Proposed fix.** Clamp deterministically: `thisUpdate = min(max(floor,
newest), epoch.end − 1 s)` and each entry's stated revocation date to `≤
thisUpdate`; this keeps every list inside its epoch, so case 2 cannot cross a
boundary and no `thisUpdate` lies beyond the epoch. Document case 1 (and, if
wanted, refuse to start when the interval grew within the last epoch, or persist
a per-CA high-water number) and case 3 in T-102 and the PKI guide; correct the
"only grows" sentences to state their conditions. **Test:** a `revoked_at` past
the next boundary and an expiring entry: the number across the boundary is
greater, and `thisUpdate` is before the epoch's end.

## 4. The §9 rules, against what the wave added

| Rule | Verdict | Evidence |
|---|---|---|
| Every new route carries a limiter from its first commit | **holds (none added)** | `server.rs` is not in the diff; the CRL route keeps `crl`; its new `503` is documented in the OpenAPI text |
| Every credential-bearing outbound request uses `guarded_fetch_no_redirect` | **holds, as the stated operator-configured exception** | the new `POST <mount>/revoke` (`vault_pki.rs` `revoke_signed_ca`) uses the Vault PKI client; Vault's address is operator configuration, not tenant input, and the client now never follows a redirect (T-476, §5) |
| Every refusal of a credential check costs one verify | **not exercised** | no credential check added or changed |
| Every two-writer registry is written conditionally on the version read | **holds** | `claim_vault_forward` (both tables) writes `WHERE vault_next_attempt_at = $seen` (or `= NONE`) with `retry_hot_row`; `claim_purge` `WHERE purge_claimed_at = NONE OR <= $cutoff`; `release_purge_claim` `WHERE purge_claimed_at = $claimed_at`; `mark_revocation_forwarded` is `?? time::now()` (idempotent). `record_vault_forward_failure` is not conditional on the claim, but it is guarded by `vault_revoked_at = NONE` and runs inside the 30 s pass budget, well within the 120 s lease, so a late write can only reschedule a row that is still pending (R101W1-09 notes it) |
| Schema additive, no backfill, newest-version bump, scope test per migration | **holds** | v95–v98: `DEFINE FIELD/INDEX IF NOT EXISTS` only; `v95_adds_only_the_vault_forward_backoff` … `v98_adds_only_the_certificate_user_binding` assert the exact statements and forbid `UPDATE`/`REMOVE`/`DELETE`/`OVERWRITE`/`DEFAULT`; the newest-version assertion names 98; readers default absent counts (D-6) |
| No new crate without a layering row | **holds** | `check-crate-layering.py`: 19 crates, all edges inward; no `Cargo.toml` changed |

## 5. W1.1 and W1.2 — distribution URL, Vault redirects (T-476)

* **#609.** `CrlDistribution::new` stores `parsed.as_str()` without trailing
  slashes and refuses userinfo (`username` non-empty or `password` present).
  The tests cover tab/newline stripping, host case, default port and
  percent-encoding; an issued certificate's CDP carries the normalised form.
  Holds.
* **T-476.** `X-Vault-Token` is sent from exactly three places
  (`secrets.rs:277`, `ca_key_store.rs`, `vault_pki.rs`), over four clients; all
  four are built with `redirect(Policy::none())` (`vault_pki.rs:247`,
  `ca_key_store.rs:203`, `main.rs:151`, `secrets.rs:481`). A `3xx` is mapped to
  an error naming the host that answered, never the `Location` target or the
  token, on every verb (`post`, `post_checked`, `delete`, KV `store`/`load`/
  `delete`, secret `fetch`). Each wiremock test asserts the second host saw no
  request at all. Holds, with R101W1-07 for the `main.rs` client's own test.

## 6. W1.3 and W1.4 — the CRL service

* **Slot map bound (carry 3).** A slot is inserted only after
  `ca_repo.get_by_id(org, ca)` found the CA, `why_unpublished` passed and the
  custodian does not sign remotely; a random id returns `NotFound` before any
  slot, and a CA found not to publish has its slot removed (`forget`). No path
  deletes a `ca_certificate` row, so the map is bounded by the deployment's
  publishing CAs. `the_cache_holds_only_cas_that_publish_a_list` pins it.
* **A cached answer never waits.** The cached path takes the global map's
  `std` mutex (insert/lookup only) and the slot's `published` `std` mutex,
  never across an `await`, and needs no permit; the light read happens before
  any lock. Holds (`a_cached_list_answers_while_another_cas_re_sign_is_in_flight`).
* **The 503 path.** A re-sign waits `permit_wait` (5 s) for a crypto permit,
  then `ServiceUnavailable` → `503`. Per request this holds; across queued
  requests for the same CA it does not bound the wait (R101W1-03).
* **Monotonicity (carry 1).** Within an epoch the entry set only grows: no
  query deletes a `certificate` or `ca_certificate` row except the tenant purge
  (`DELETE … WHERE tenant_id`, which keeps revoked rows until `notAfter + 8d`)
  and the orphan purge (same steps); no query moves a row out of `Revoked`
  (only `revoke_user_certificates` writes `revoked_at = time::now()`, and only
  on `Active` rows; every other revoke is `revoked_at ?? time::now()`). An entry
  leaves only when `expiring_after` moves at a boundary, where `thisUpdate`
  rises to the new epoch's start; a late or same-second revocation raises the
  count. The upgrade from 1.0.0's millisecond numbers (~1.8 × 10¹²) to
  `secs << 24` (~3 × 10¹⁶) is upward. So the number is monotonic per CA **under
  a fixed interval and agreeing clocks**; R101W1-02 lists the three breaks.
  Restarts change nothing (the derivation is stateless).
* **"7 days is the longest a list keeps an expired entry" (carry 1).** An
  entry is listed while `notAfter > expiring_after = epoch.start − half`, so at
  most `2 × half ≤ interval` after it expired; `validate_next_update_secs`
  bounds the interval to 300 … 604 800 s and `boot.rs:1011-1019` applies it to
  `AXIAM__PKI__CRL_NEXT_UPDATE_SECS` (startup fails otherwise); the test state
  uses the default. **True.** The purge's `not_after > time::now() - 8d`
  (`tenant_purge.rs:140`) exceeds it by a day of datastore-vs-replica skew —
  consistent, but hard-coded (R101W1-08).
* **Byte identity (carry 2).** CRL signing loads the key and signs locally with
  rcgen; it is reached only for `database` and `vault` (KV) custody.
  `vault_pki` answers `signs_remotely() == true` and is refused before any read
  (`crl.rs` `current_at`), `external` is refused by `why_unpublished`. CA keys
  can only be Ed25519 or RSA: generation offers the two, import refuses every
  other SPKI OID (`ca.rs:1476-1500`) and checks the key matches the certificate
  (`verify_key_matches_certificate`). rcgen signs an RSA key with PKCS#1 v1.5
  SHA-256 (deterministic) and Ed25519 is deterministic. Vault never produces a
  CRL signature AXIAM serves. **Holds.**

## 7. W1.5 — the Vault sweep (carry 4)

* **Claim and lease.** The due list (`list_due_vault_forwards`) reads up to 100
  rows with `vault_next_attempt_at = NONE OR <= now`, ordered by
  `vault_next_attempt_at` (NONE sorts first in SurrealDB) then `revoked_at`.
  Each row is claimed by a conditional write of the value read to
  `now + 120 s`; a lost race matches nothing (`two_replicas_never_attempt_the_same_row`,
  `of_concurrent_claims_of_one_row_exactly_one_wins`). The pass budget is 30 s,
  checked before each claim, so a claimed row is attempted inside its lease; a
  replica that dies holds a row back for 120 s with nothing counted.
* **Head-of-line with > 100 refused rows (no test; reasoned).** A refusal
  writes `vault_next_attempt_at = now + backoff(attempts)` (1 min doubling to
  6 h), which takes the row out of the due set until it elapses. A new
  revocation has `vault_next_attempt_at = NONE` and sorts **before** every
  attempted row, so it is in the first page of the next pass whatever number
  of refused rows exist; among due attempted rows the soonest due goes first.
  With more than 100 rows due at once (e.g. after an outage) the pass takes the
  oldest-due 100 (fewer if Vault is slow: 30 s budget) and the rest are due at
  the next tick; nothing is permanently blocked. The only throughput limit is
  100 rows (or 30 s) per tick per replica, shared across replicas by the claim.
* **Threshold job.** `vault_revocation_failing` counts unforwarded rows with
  `vault_forward_attempts >= 12` on both tables (same `UNFORWARDED_WHERE`, so a
  row whose issuer is no longer an active `vault_pki` CA, or that expired,
  drops out) and is recorded apart; the pass stops failing for such a row.
  Registered in `SWEEP_JOBS`, pinned by the job-health test.
* **Sanitiser.** The stored reason goes through `sanitise_reason` (control
  characters and whitespace runs collapsed, `hvs.`/`hvb.`/`hvr.`/`s.` tokens
  redacted, 256 characters) and the repository truncates again. The reason is
  built from AXIAM's own text plus Vault's `errors` array; the token is only
  ever in a header, reqwest errors do not print headers, and Vault does not
  echo the token, so **no token reaches the DB or the logs** on any path read.
  The audit rows and logs are not sanitised (R101W1-06).

## 8. W1.6 — the CA forward after `store.delete` (carry 5)

* **Vault's semantics.** Vault's `revokeCert` refuses a serial whose
  certificate equals any issuer's in the same mount ("adding issuer (id: …) to
  its own CRL is not allowed"; issuers are revoked through
  `/issuer/:ref/revoke`). In the single-mount layout (a parent whose locator
  records no root signs from the mount that also holds its children's
  issuers), revoking the child by serial **before** deleting its issuer is
  therefore refused; after the delete, the serial is a stored certificate
  (`sign-intermediate` stored it in that mount's `certs/`) and is accepted. In
  the usual two-mount layout the order is irrelevant. **The executor's claim
  holds**, and the plan's "before `store.delete`" would have failed there.
* **Death between delete and forward.** `repo.revoke` has already set
  `Revoked` and `revoked_at`; `vault_revoked_at` is NONE, so the row is in the
  sweep's CA due list (`ca_certificate.rs` `UNFORWARDED_WHERE`: revoked,
  unexpired, custody `vault_pki`/`external`, parent an active `vault_pki` CA)
  and is forwarded by the next pass. Nothing is lost. Death between
  `repo.revoke` and `store.delete` leaves the issuer in Vault; in the
  single-mount layout every forward is then refused (R101W1-04).
* **Which CAs are forwarded.** Parent active `vault_pki`, child `vault_pki` or
  `external`: correct. A `vault_pki` parent always creates `vault_pki` children
  (`generate_intermediate` delegates to the parent's store when it
  `signs_remotely`) and signs an `external` child's CSR through Vault; import
  sets no parent; a `database`/`vault` child under a `vault_pki` parent cannot
  arise. A revoked parent's issuers were deleted, so `NotNeeded` is right. The
  in-request forward and a concurrent sweep may both forward once (no claim in
  the request path); Vault answers the second with success, and the failure
  record is guarded by `vault_revoked_at = NONE`.
* **Audit.** A pending forward writes `ca_certificate.vault_revocation_pending`
  to the caller's tenant (the CA's tenant may be purged first): sensible.

## 9. W1.7 — one replica purges (carry 6)

* `claim_purge` stamps `purge_claimed_at = now` only while the tenant is
  tombstoned and the field is unset or older than one hour; a write conflict is
  retried and then finds the winner's stamp. A failed purge releases its own
  claim (conditional on its stamp). `purge_tombstoned` now reports `NotFound`
  unless its own final `DELETE … RETURN BEFORE` removed the row, and the sweep
  records `tenants.purged` only on `Ok`, so an overlapping purge after a lapsed
  lease repeats idempotent steps and is not recorded twice
  (`two_replicas_sweeping_at_once_purge_a_tenant_once_and_neither_fails`).
  There is no un-tombstone path, so a stale stamp cannot hold back a live
  tenant.
* **Lease overlap.** A purge outliving the hour overlaps the next claimant;
  both run the same `DELETE … WHERE tenant_id` steps (the certificate tables'
  revoke/strip/delete triple included), the tenant row goes once. Work, not
  correctness. Holds.
* **Orphan residual.** `purge_orphan` is not claimed: two replicas whose daily
  scans coincide both purge and both write `tenants.purged {orphan: true}`
  (R101W1-09). Rare (one scan a day per replica, and a second scan after the
  first purge finds no orphan).

## 10. W1.8 — the binding and the two deletion paths (carry 7)

* **Validation.** `check_user_binding` (service level, before a key is made)
  refuses `user_id` on any type but `User` and refuses a `metadata.user_id`
  that does not parse to the same id; `check_bound_user` (REST) reads the user
  in `principal.tenant_id` — the tenant the certificate is created in — and
  refuses `NotFound`, `Deleted` and `Anonymized` with `400`; other read errors
  propagate. Holds. `metadata.user_id` alone is not promoted into the column.
* **The CN fallback for post-v98 unbound rows.** The plan's rule, applied
  literally; it errs towards revoking, which is the safe direction for the
  account being deleted and the wrong one for everybody else. With the two new
  triggers it becomes R101W1-01. The fix keeps the fallback for certificates
  issued after the account and with an unambiguous name.
* **Ordering and failure.** Admin deletion: sessions, then certificates
  (fail-closed), then the tombstone, so a failure leaves the account intact and
  retryable with its names; a successful revocation followed by a failed
  tombstone leaves revoked certificates on a live account (fail-safe). Purge:
  step (b4) before `anonymize_user`, fail-closed, idempotent (only `Active`
  rows match), count on `gdpr.user_pseudonymized`. A `vault_pki` issuer's
  revocations are left to the sweep (`vault_revoked_at` NONE), as linking
  already relied on. Holds.
* **GDPR residual.** See R101W1-05. `gdpr-compliance.md` states the residual
  plainly (`:191-216`) and T-187 records it, so the documentation is not
  contradicted; the doc's legal basis (Art. 17(3)(b), "legal obligation") is a
  weak fit for retention whose purpose is security (Art. 17(3) does not list
  security; Art. 6(1)(f) legitimate interest is the natural basis), and the
  retention has no purpose at all once the row is more than eight days past
  `notAfter`.

## 11. Threat-model text against the code (carry 9)

| Entry | Verdict |
|---|---|
| T-476 (new) | true (§5); the four clients and the tests it names exist |
| T-102 (#607, #608 amendments) | true for availability per request and for byte identity; "the number grows with every change" holds only under a fixed interval and agreeing clocks (R101W1-02); "waits at most five seconds" is per request, not per caller in a queue (R101W1-03) |
| T-470 (#603, #612 amendments) | true (§7, §8); omits R101W1-04's single-mount dependency on the key release |
| T-472 (#608, #610 amendments) | true (§9); the orphan purge is not covered by the "one replica" sentence (R101W1-09) |
| T-336 (#533 amendment) | true for bound rows; the residual omits that deletion and erasure now run the convention, one of them self-service (R101W1-01) |
| T-187 (#533 amendment) | true, residual stated (R101W1-05) |

**Consistency.** For each of the six entries, every sentence the wave added to
`Axiam.json` (mitigation, and for T-476 title and description) occurs verbatim
in `threat-model-stride.md` (script comparison, 0 missing of 105 sentences);
`website/src/threatModel.ts` is generated from `Axiam.json` and
`node website/scripts/gen-threat-model.mjs` leaves **no diff** ("476 threats
(438 mitigated, 17 open, 21 not applicable)"). Counts: `Axiam.json` 2.40.0,
`threatTop` 476, statuses 438 / 17 / 21; STRIDE header and open-register "17 of
476"; write-up headline table and 1.0.1 paragraph; `docs/compliance/FINDINGS.md:37`;
`website/src/threatModelSummary.ts` (476 / 438). The two "475 threats, 437
mitigated" sentences left in `threat-modeling-and-security.md:213,234` are
dated 1.0.0 history, correctly unchanged. `website/src/security.ts` states no
count.

## 12. Documentation claims

| Claim (where) | Verdict |
|---|---|
| "No replica keeps serving an earlier epoch's list … none answers with a lower number than another has served" (`crl.rs` module doc) | **true only with agreeing clocks and a fixed interval** (R101W1-02) |
| "The number grows with every change of the list, an entry leaving included" (PKI guide) | as above |
| "a re-sign waits for one at most `DEFAULT_CRL_PERMIT_WAIT`; past that the route answers `503` rather than queueing an unauthenticated caller without bound" (`crl.rs` module doc) | **false for callers queued on the same CA** (R101W1-03) |
| "the cleanup job deletes the evidence once no list names it" (`tenant_purge.rs`) | true |
| "A revoked certificate or CA that has not yet expired is kept … The same sweep removes it once it expires" (`docs/admin/README.md:254`), "keeping only a revoked certificate or CA that has not yet expired … until it does" (`operate.ts:1090`) | **stale**: kept until eight days after `notAfter` (R101W1-08) |
| "`vault_revocation` … fails while any remains" (`operate.ts:1186`) | **stale**: a row in backoff, or past the twelve-attempt threshold, does not fail the pass (R101W1-08) |
| "a certificate bound to another account is never revoked on this one's behalf" (T-336) | true for bound certificates (R101W1-01 is about unbound ones) |
| `gdpr-compliance.md` erasure residual | accurate |

## 13. Checks run

Each command with its own exit code (logs in the scratchpad; probe files
deleted before the commit; no `cargo clean`).

| Check | Result |
|---|---|
| `cargo build -p axiam-server --no-default-features` (swagger placeholder, `CARGO_INCREMENTAL=0`) | pass |
| `./target/debug/axiam-server --dump-openapi` vs `sdks/openapi.json` | **byte-identical** |
| `python3 scripts/check-spec-digest.py` | pass (digest matches) |
| `python3 scripts/gen-management-registry.py --check` | pass (190 operations, 28 namespaces, in sync) |
| `python3 scripts/check-crate-layering.py` | pass |
| `node website/scripts/gen-threat-model.mjs` | 476 (438 / 17 / 21); `git status` clean |
| Threat-amendment comparison (JSON vs STRIDE, script) | 0 of 105 added sentences missing |
| `cargo test -p axiam-pki --test crl_test --test vault_pki_test --test vault_ca_key_store_test` | pass (14, 27, 15) |
| `cargo test -p axiam-pki --lib` | pass (130, 1 ignored) |
| `cargo test -p axiam-db --test certificate_repository_test --test ca_certificate_repository_test --test tenant_purge_test --test directory_provisioning_repo_test` | pass (16, 19, 6, 10) |
| `cargo test -p axiam-db --lib schema` | pass (75) |
| `cargo test -p axiam-auth --test vault_provider_test` | pass (11) |
| **Probe 1** (R101W1-03) — temporary `crates/axiam-pki/tests/zz_f4_probe.rs`: crypto gate held, `permit_wait` 200 ms, eight concurrent requests for one unsigned CA | all `503`, at **253, 460, 668, 876, 1084, 1296, 1505, 1714 ms** — serial |
| **Probe 2** (R101W1-02.1) — same file: revocation 10 days old, at a 3.5-day boundary + 13 h, 1-day then 7-day interval | number **lower** after the change |
| **Probe 3** (R101W1-02.2) — same file: `revoked_at` 10 s past the next boundary, another entry expiring at the current epoch's start | `thisUpdate` **22 s in the future**; number **lower** across the boundary |
| **Probe 4** (R101W1-01) — temporary `crates/axiam-db/tests/zz_f4_probe.rs`: `alice`, an unbound CN-`alice` `User` certificate, then account `Alice` | `Alice` created; revoking `Alice`'s certificates revoked **1**, `alice`'s certificate **Revoked** |
| Commit signatures | 8 of 8 carry `BEGIN SSH SIGNATURE` |

## 14. Issue bodies

### R101W1-01 (Medium) — deleting or erasing an account revokes another account's certificate by name

Since #533 (1.0.1 W1.8) both `DELETE /api/v1/users/{id}` and the Art. 17 purge
call `revoke_user_certificates`, which for a certificate without `user_id`
(every certificate issued before 1.0.1, and any issued later without the
field) matches `metadata.user_id` or `lower(subject) IN (lower(username),
lower(email))` (`certificate.rs:735-775`). Usernames and emails are unique
case-sensitively (`schema.rs:594-597`), and only directory provisioning probes
for a case-insensitive collision, so `alice` and `Alice` coexist (probe:
revoking `Alice`'s certificates revoked `alice`'s CN-`alice` certificate). An
account created after a certificate — by an administrator, SCIM or federation
JIT (`username = email` from the IdP) — can be named after its CN, and its
holder can start the erasure (`request_account_delete`). The revocation is
irreversible. **Fix:** apply the convention only to unbound rows with
`created_at >= ` the account's `created_at`, and drop from `$names` any name
another account of the tenant also folds to (reuse
`SurrealUserRepository::identity_collision`); amend T-336, T-187, the PKI guide
and `gdpr-compliance.md`. **Tests:** an account created after a same-CN
certificate does not revoke it; an ambiguous name revokes nothing by name; the
existing deletion and linking tests still pass.

### R101W1-02 (Low) — the CRL number can go down

`list_identity` (`crl.rs:709`) derives `thisUpdate = max(epoch start, CA
notBefore, newest revocation date)` and number `= thisUpdate_secs << 24 |
count`, epochs half the configured interval. It decreases (probes) when (1)
`AXIAM__PKI__CRL_NEXT_UPDATE_SECS` is raised (the epoch start moves back) or
lowered (entries drop with `thisUpdate` unchanged), (2) a `revoked_at` written
by a datastore clock ahead of the replica lies past the next boundary while
another entry expires at it — which also puts `thisUpdate` in the future,
refused by strict relying parties — and (3) replicas' clocks straddle a
boundary (and, briefly, during the upgrade from 1.0.0). The module doc, T-102
and the PKI guide state unconditional monotonicity. **Fix:** clamp
`thisUpdate` to `epoch.end − 1 s` and each entry's stated date to
`thisUpdate`; document interval changes and skew (or persist a per-CA
high-water number); state the conditions where monotonicity is claimed.
**Test:** a future `revoked_at` plus an expiring entry: the number grows across
the boundary and `thisUpdate < epoch end`.

### R101W1-03 (Low) — the CRL route queues unauthenticated callers without bound

`CrlService::current_at` (`crl.rs:482`) queues every request for a CA's
changed list on the CA's `signing` mutex with no timeout; each, once it holds
the mutex, waits up to `permit_wait` (5 s) for a crypto permit and returns
`503` without caching anything, so the next waiter starts its own 5 s. With the
gate saturated (issuance and Argon2id share it) the k-th caller waits about
k × 5 s (probe at 200 ms: 253 … 1714 ms for eight callers), contrary to the
module doc's "rather than queueing an unauthenticated caller without bound".
Bounded per IP by the route's limiter, not across IPs. **Fix:** bound the wait
for the signing mutex by the same `permit_wait` (`tokio::time::timeout` →
`503`), or make the per-CA flight shared (waiters receive the in-flight
outcome, a `503` included), or `try_lock` and answer `503` when a re-sign is in
flight and no current list is cached. **Test:** eight concurrent requests under
a held gate all answer within ~`permit_wait`.

### R101W1-04 (Low) — a failed key release makes a tenant CA's Vault forward permanently refused (single-mount layout)

`CaService::revoke_within` (`ca.rs:965-998`) revokes the row, deletes the CA's
issuers from Vault (`store.delete`, failure logged and swallowed), then
forwards the serial to the parent's mount. Where the parent signs from the
mount that also holds its children's issuers (no root in its locator), Vault
refuses `revoke` while the child is still an issuer there ("adding issuer to
its own CRL is not allowed"). If the delete failed — or the process died
between `repo.revoke` and `store.delete` — every forward is refused and the
sweep (`forward_pending_ca_revocations`) retries only the forward, never the
release; the row turns `vault_revocation_failing` after ~a day and needs an
operator. Meanwhile relying parties reading the parent's list in Vault trust
the revoked CA and its leaves. **Fix:** when a CA forward fails with that
refusal, have the sweep retry the issuer deletion before the next forward; or
revoke the child in place with Vault's `POST <mount>/issuer/<child>/revoke`
(Vault ≥ 1.11), which puts the issuer on its signer's CRL independent of
deletion. Name the dependency in T-470 and the PKI guide. **Test:** wiremock:
issuer `DELETE` fails, `revoke` answers 400 with the issuer message; the next
sweep re-deletes and then forwards.

### R101W1-05 (Low) — an erased account's certificate rows keep personal data for the tenant's lifetime

The Art. 17 purge (step b4, `cleanup.rs:1825-1830`) revokes the account's
`User` certificates and keeps the rows — correctly, the CRL is read from them
— but keeps them whole: the PEM (subject DN), the `subject` column, the
free-form `metadata` and `user_id`. Unlike the tenant purge it does not clear
`metadata`, and no job deletes a certificate row in a live tenant, so the data
outlives any CRL purpose (eight days past `notAfter`). `gdpr-compliance.md`
and T-187 record the residual; the stated basis (Art. 17(3)(b)) fits a
security retention poorly. **Fix:** in step (b4) also clear `metadata` on the
account's certificate rows (as `tenant_purge` does); add a sweep that deletes
revoked or expired certificate rows more than eight days past `notAfter` in
live tenants (the CRL no longer lists them); revisit the legal basis wording
(Art. 6(1)(f) / Art. 32). **Test:** after the purge the rows carry `metadata =
{}`; a row nine days past `notAfter` is deleted by the sweep, and the CRL is
unchanged (it no longer listed the row).

### R101W1-06 (Informational) — Vault refusal text enters the audit log and logs unsanitised

`sanitise_reason` (`vault_forward.rs`) is applied to the row's
`vault_forward_last_error` only. The new `ca_certificate.vault_revocation_pending`
audit row (`ca_certificates.rs:396`), the existing
`certificate.vault_revocation_pending` (`certificates.rs:491`) and the
`tracing::error!` in both forward paths carry the raw reason, unbounded; the
audit log is append-only, so anything that ever reaches it cannot be removed.
No token was found in any reason (the token travels only in a header and Vault
does not echo it). `looks_like_a_token` also misses legacy batch tokens
(`b.` prefix). **Fix:** pass the reason through `sanitise_reason` before the
audit append and the log; add `b.` to the prefixes.

### R101W1-07 (Informational) — the bootstrap Vault client in `main.rs` is not under test

`main.rs:148-155` builds the client the secret provider uses with
`redirect(Policy::none())`; `vault_provider_test.rs` builds its own equivalent
and passes it in. `VaultSecretProvider::fetch` sees a `3xx` only when the client
does not follow it, so reverting `main.rs` to `Client::new()` would follow a
redirect with `X-Vault-Token` and no test would fail. **Fix:** move the builder
to `axiam_auth::secrets::bootstrap_client()` (used by `main.rs`) and test that
it surfaces a `307`; or a source-pin test on `main.rs`.

### R101W1-08 (Informational) — text behind the code after W1.4 and W1.5

(a) `docs/admin/README.md:254` and `website/src/docs/operate.ts:1090` say the
purge keeps a revoked certificate until it expires; it keeps it until eight
days after. (b) `operate.ts:1186` says `vault_revocation` "fails while any
remains"; a row in backoff or past the twelve-attempt threshold no longer fails
it. (c) `KEPT_REVOCATION`'s eight days (`tenant_purge.rs:140`) is not tied to
`axiam_pki::crl::MAX_CRL_NEXT_UPDATE_SECS`; raising the maximum would silently
break the margin (a cross-crate constant assertion or a test in `axiam-server`,
which sees both).

### R101W1-09 (Informational) — small races and edges

(a) `purge_orphan` is not claimed: two replicas whose daily orphan scans
coincide both write `tenants.purged {orphan: true}`; record only when a step
removed rows, or claim with a conditional marker row. (b) `check_bound_user`
validates the account, then issuance runs; a deletion between the two revokes
before the new certificate exists, which then stays active and bound to a
`Deleted` account (admin-only, narrow) — re-check after the create, or revoke
on create when the account is gone. (c) `DELETE /api/v1/users/{unknown}`
revokes certificates whose `metadata.user_id` names the id before the delete
answers `404`; skip the revocation when the account was not found. (d)
`record_vault_forward_failure` is not conditional on the claim it follows;
harmless today (guarded by `vault_revoked_at = NONE`, written inside the lease)
— make it `WHERE vault_next_attempt_at = $lease` if the pass budget ever
approaches the lease.

## 15. Invariants

I1 (nothing registered today changes behaviour unless the wave says so) holds
for what was read: the behaviour changes are the documented ones — a Vault
`3xx` is an error, a CRL re-sign can answer `503`, `max-age` is shorter, the
CRL number and `thisUpdate` are derived, the Vault sweep backs off, a revoked
`vault_pki` tenant CA is forwarded to its parent's mount (a new `pki/revoke`
policy line on the root mount, documented in the PKI guide), one replica
purges a tenant, `user_id` is accepted on two issuance routes, and deletion and
erasure revoke `User` certificates (R101W1-01 is about how far). No contract
text changed (`sdks/CONTRACT.md` is W5's); the OpenAPI file matches the server.
This review changed no file but itself; both probe files were removed before
the commit.
