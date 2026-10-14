# Security review — release 1.0.1, the combined plan branch (F4)

**Date:** 2026-10-14.
**Against:** `claude/release-1.0.1` at `70d59020b`, the whole plan-branch diff
`c6f916e67...70d59020b` (209 files, about 28 000 lines; `c6f916e67` is `main`
— the `v1.0.0` tag `0a90de0a3` plus the release plan). Every commit of the range
carries a signature (`commit.gpgsign`; the sandbox has no `allowedSignersFile`,
so `%G?` cannot verify them here).
**Scope:** what no wave review could see. Each wave was reviewed on its own
branch — [W1](security-review-release-1.0.1-w1-2026-10-13.md),
[W2](security-review-release-1.0.1-w2-2026-10-13.md),
[W3](security-review-release-1.0.1-w3-2026-10-13.md),
[W4](security-review-release-1.0.1-w4-2026-10-13.md),
[W6](security-review-release-1.0.1-w6-2026-10-13.md) — and W5 (contract 1.61)
by [`sdk-contract-1.61-conformance-review.md`](sdk-contract-1.61-conformance-review.md).
Their findings are not repeated here (the Low and Informational ones are #615 …
#653). This review covers: (1) the cross-wave interactions in the merged tree,
first of all where the orchestrator resolved conflicts (plan §11.5); (2) whether
the merged tree still honours the plan's §9 rules wherever the waves touched it;
(3) contract 1.61's text against the merged server (new contradictions only —
the open questions Q1 … Q7 and the §33.3 rule 13 `slow_down` are already in
plan §11.5); (4) what a single-wave review structurally could not see — in
particular **the fix commits that landed after each wave's review** and were
therefore reviewed by nobody (§8).
**Method:** adversarial reading of the merge commits' combined diffs
(`git show --cc`), of every file two waves touched, and of each post-review fix
in full, against [`threat-model-stride.md`](threat-model-stride.md) and
`Axiam.json` (477 threats: 443 Mitigated, 17 Open, 17 Not applicable; ids
unique, `threatTop` 477 — verified by script), the plan's §9 rules and decisions
D-1 … D-7, and the OWASP ASVS 5.0 areas the findings touch (V2 business logic,
V13 configuration, V14 data protection, V16 logging). Claims were checked
against the code on HEAD `70d59020b`, not against commit messages. A regression
gate was running in the same worktree, so **no cargo command was run**: no test
was executed and no probe needed a Rust build; the two scripted checks (threat
model integrity, registry/spec digests) are read-only Python. This review fixes
nothing: every finding has evidence, a proposed fix and an issue body (§10). The
Medium finding is proposed for a fix before the release PR; the rest for
`1.0.x`.

---

## 0. Summary

**One Medium finding, introduced by a fix that landed after its wave's review.**

* **R101-01 (Medium, T-415, T-417).** The in-wave fix of R101W4-01
  (`a234f3221`) makes a SCIM reconciliation run **stop offering references at
  its first refused enqueue, for the rest of the run**. Step 1 offers the
  in-scope users first, oldest account first (`ORDER BY created_at ASC`), and
  the **linked resources last** — and the linked resources are what carries the
  nightly retry of a refused erasure `DELETE` (`erase_pending`) and the
  deprovisioning of every account that left scope, was disabled or was erased.
  Step 2's repairs (a drifted account re-queued, an unlinked downstream account
  of an erased or disabled user adopted and deprovisioned) come after that and
  are skipped too, although step 2 first spends seconds reading the downstream,
  while the queue drains. In the minimal profile (in-process queue of 1 024 per
  kind, one consumer), a target whose in-scope users fill the queue before the
  run reaches its links therefore **never** has a link or a repair offered by
  reconciliation again: every run is the same run, in the same order, and stops
  at the same place. The CHANGELOG and the deployment guide say "the next run
  offers them again", and T-415 says "reconciliation re-queues every linked
  resource, so the `DELETE` is retried nightly until it lands" — neither holds
  for such a target. In 1.0.0 (and after #596, before `a234f3221`) each later
  reference was still offered, so links and repairs got in whenever the
  consumer had freed a slot. The `scim_reconcile` job does turn red on
  `/health/jobs`, every night, with no remedy the operator can apply short of
  leaving the minimal profile.

Two Low and two Informational findings are reported for `1.0.x` (§10).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R101-01** | A reconciliation run stops offering at its first refused enqueue; links (the `erase_pending` retry, deprovisioning) and step 2's repairs come after the in-scope users, so in the minimal profile a target with more in-scope users than the queue absorbs never gets them, run after run. | **Medium** | `reconcile.rs` `queue_again`, `enqueue_everything` → T-415, T-417 | W4 post-review fix (`a234f3221`) | **Fix before the PR** (§2) |
| R101-02 | R101W2-01's fix queues unauthenticated SAML signature verifications (SP ACS, IdP SSO/SLO receiver) on the shared crypto semaphore **without a wait bound**, while every other waiter on it — Argon2id (B1) and W1.3's CRL re-sign (#607) — gives up after 5 s. A flood of signed SAML posts can hold every login and every post-revocation CRL re-sign to their `503`. | Low | `saml.rs` `verify_signature_off_worker`, `saml_idp.rs` `verify_post_signature_off_worker`, `saml_metadata.rs`; `crl.rs` `crypto_permit` → T-102 (availability), T-474 | cross-wave (W2 fix × W1.3) | Reported |
| R101-03 | The tenant purge is not among the steps W4.9 says a cleanup cut can leave: a cut mid-purge holds the tenant back for W1.7's whole one-hour lease (the next start skips it), and a cut while the tenant row's `DELETE` is in flight or before `tenants.purged` is written loses the only record of the purge and of D-5's audit counts for good. | Low | `cleanup.rs` `sweep_tenant_purge`, `boot.rs` `join_cleanup`; T-444, T-472 | cross-wave (W4.9 × W1.7 × W3.5) | Reported |
| R101-04 | Contract §33.3 rule 16 says the CIBA pending list's `429` "is spent per signed-in user, not per address"; since R101W3-04 the route also carries a per-address backstop (ten times the allowance) whose `429` is the governor's, and the OpenAPI text says the same as the contract. | Informational | `CONTRACT.md` §33.3 rule 16, `server.rs` `CIBA_LIST_BACKSTOP_FACTOR`, `ciba_approval.rs` | cross-wave (W3 fix × W5 text) | Reported (W7.3 / contract 1.62) |
| R101-05 | Text the merge made stale: T-472's "the tenant-to-organization cache serves AXIAM session refresh only" (W3.2) while W3.4's scope policy now reads it on every external client's grant; §27.15 note 10's reason for writing the CA forward's row to the organization's log ("the CA's tenant's, which a tenant deletion purges") is half-true since W3.5; T-444's and the deployment guide's "two exceptions" omit the tenant purge (R101-03). | Informational | `Axiam.json` / STRIDE T-472, T-444; `CONTRACT.md` §27.15 note 10; `docs/deployment/README.md:1847` | cross-wave text | Reported (W7.3) |

The cross-wave points that are **not** findings (§3 … §7): the tenant-purge
merge (W1.7's `NotFound` and W3.5's report) is correct and cut-safe in its
steps; W1.4's revoked-row retention and W3.5's export bound do not contradict
each other; W1's `vault_revocation_failing` job and all 22 sweeps survived the
port into `CleanupTask::tick()`, in order, each registered on `/health/jobs`;
the GDPR loop keeps W4's stop check and W1.8's certificate revocation runs
before the anonymization, so no cut can leave an erased account's certificates
active; `server_leaf_profile.rs`'s `user_id: None` is test-only and correct;
migrations v95 … v98 are additive, ordered, scope-tested, and the newest-version
assertion reads 98; no audit action name was added twice; W3's two new
rate-limit keys cannot collide with any route bucket (W2's two collisions are
#632); every remaining redirect-following `guarded_fetch` caller is a
credential-free `GET`; no route was added (191 paths, 190 registry operations in
28 namespaces, spec and registry digests equal).

---

## 1. What was reviewed, and how

| Surface | Waves | Files | Depth |
|---|---|---|---|
| Tenant purge (merge `76f841c89`) | W1.4, W1.7, W3.5, W3.2 | `axiam-db` `tenant.rs` (`claim_purge`, `release_purge_claim`, `purge_tombstoned`), `tenant_purge.rs` (in full), `cleanup.rs` `sweep_tenant_purge`, `tenants.rs` `delete`, T-472 | **read in full**; `--cc` diff of the merge |
| Cleanup tick (merge `0570b3425`) | W1.5, W1.6, W1.8, W3.3, W4.9 | `cleanup.rs` `run`, `tick`, `sweep_pending_purges`, `purge_single_user_inner`, `revoke_erased_users_certificates`, `sweep_unused_external_clients`; `boot.rs` `join_cleanup`, the two `ShutdownBudget`s; `job_health.rs` | **read**; the job list compared with the pre-merge tick and with `job_health` by script |
| Vault forward under the stop budget | W1.5, W1.6, W4.9 | `cert.rs` `forward_pending_revocations`, `failing_revocations`; `vault_forward.rs`; the two `UNFORWARDED_WHERE`s | **read** |
| `server_leaf_profile.rs` `user_id: None` | W1.8 × W3.8 | the test, `CreateCertificate` | read |
| Migrations v95 … v98 | W1 | `schema.rs` (DDL, scope tests, newest-version assertion at `:6441`) | **read** |
| Rate-limit buckets | W2.4, W3.6, R101W3-04 | `server.rs` (every `RateLimitShared` name, counted by script), `ciba_approval.rs`, `ciba_list_limiter.rs`, `ciba.rs` `CibaHintCap`, `rate_limit_counter.rs` `check_at_human` | read; names counted |
| Audit action names | all | every `pub const …: &str = "<a>.<b>"` in `crates/` | counted by script |
| Credential-bearing outbound requests | W1.2, W2.5, R101W2-04, W3 | every `guarded_fetch(` / `guarded_fetch_with_cap(` caller; `backchannel_logout.rs` | read |
| Shared crypto semaphore | W1.3, R101W2-01 | `boot.rs:705,1436`, `crl.rs`, `saml.rs`, `saml_metadata.rs`, `saml_idp.rs`, `saml_idp_slo.rs`, `password_reset.rs`, `service.rs` | **read**; every acquirer listed |
| SCIM bulk producers | R101W4-01 fix | `reconcile.rs` (in full), `provisioner.rs`, `deliverer.rs` digest skip, `inprocess.rs` capacity and consumer, `user.rs` list order; the 1.0.0 `reconcile.rs` | **read in full** |
| Contract 1.61 | W5 | §34.5; §6.1 rule 8; §27.11 rule 5; §27.15 notes 6, 7, 10; §30.3 rule 6; §33.3 rules 13, 16; §35 rule 4 — each against the handler or repository it describes | read; the rules named in §6 checked line by line |
| Threat model | all | `Axiam.json` (ids, counts, T-472 and T-102's merged amendments), STRIDE T-415, T-444 | script + reading |

Not run: any cargo build or test (the regression gate held the worktree); a
probe of R101-01 or R101-02 (both need a Rust build; both are argued from the
code, with the line that decides each). The eleven SDK repositories were not
read. The five threat-model copies were not compared against each other (W7.3's
task).

## 2. R101-01 — a reconciliation run never reaches its links

**What `a234f3221` changed.** R101W4-01 (Medium, W4 review) found that a bulk
producer meeting a full in-process queue wrote one audit row per refusal into
the request-audit channel and crowded every tenant's request rows out. The fix
made each bulk producer stop at its first refusal. In reconciliation it is four
lines of `queue_again` (`crates/axiam-scim/src/outbound/reconcile.rs:566-582`):

```rust
if report.enqueue_failed > 0 {
    report.enqueue_failed += 1;
    return;
}
```

`report` lives for the whole run (`run_claimed`, `:379-415`), so from the first
refusal on **nothing more is offered in step 1 or step 2**. The 1.0.0 body of
the same function (`c6f916e67:…/reconcile.rs:540-552`) offered every reference.

**Why the order makes that a loss, not a deferral.** `enqueue_everything`
(`:424-546`) offers, in this order: every in-scope user (`users.list`, which is
`ORDER BY created_at ASC`, `crates/axiam-db/src/repository/user.rs:1246`); the
pushed groups; then **every linked resource** (`:522-545`) — "this is what
removes a resource that left scope, was erased or was deleted, and what retries
an erasure `DELETE` that was refused". An erased or deleted account is not in
the user loop at all (`:439`), so its link is the only way reconciliation ever
reaches it. Step 2 (`audit_collection`, `:591-658`) then pages the downstream
over HTTP and queues repairs: a linked account that drifted (`audit_linked`,
`:778`), an unlinked downstream account whose `externalId` is an erased or
disabled user of the tenant (adopted and deprovisioned, `:714-715`), and a
re-creation for a link whose downstream resource is gone (`:878`). Every one of
those goes through `queue_again` and is skipped.

**When the queue refuses.** In the minimal profile each kind has one
`tokio::mpsc` of `IN_PROCESS_CAPACITY` = 1 024
(`crates/axiam-amqp/src/outbound/inprocess.rs:63`) and one consumer task that
takes one message at a time. The producer offers a page of 100 references per
datastore read; the consumer spends at least a user read, a link read and a
digest per reference even when it skips the `PATCH` (`deliverer.rs:517-523`),
and an HTTP round trip when it does not. So a target whose in-scope users
exceed the queue plus what the consumer drains while the user loop runs meets
its first refusal inside the user loop — the W4 review put the threshold for a
refusal burst "about five thousand"; the exact figure depends on the
downstream's latency, and the conclusion does not. From then on:

* **The run is the same every night.** The claim has no completion write
  (`:12-15`); the next run lists the same users in the same order and stops at
  the same place. "The next run offers them again" (`CHANGELOG.md:297`,
  `docs/deployment/README.md:1793-1795`, the module documentation at `:20-27`)
  is true of the first ~1 000 users and of nothing after them.
* **T-415's two reconciliation guarantees fail for that target.** "Reconciliation
  re-queues every linked resource, so the `DELETE` is retried nightly until it
  lands, and a downstream account whose `externalId` names an erased user of
  this tenant is deleted when reconciliation finds it" (STRIDE `:3664`). Both
  sit after the stop. A downstream erasure that was refused once (`erase_pending`)
  — or whose live reference was itself refused because a reconciliation had
  just filled the queue — is never retried: the erased person stays in the
  downstream application.
* **T-417 and T-412's deprovisioning.** An account disabled or moved out of
  scope while its live reference was refused, or edited downstream, is never
  repaired; and a target enabled with more users than the queue absorbs never
  creates the newer ones by reconciliation ("enabling a target starts a
  reconciliation that pushes everyone in scope at once", T-412).
* **It is visible, not recoverable.** `ReconcileReport::incomplete`
  (`:157`) makes `scim_reconcile` fail on `/health/jobs` every run. The queue
  size is not configurable; the operator's only remedy is the broker profile.

An administrator can also bring it about: a tenant with self-registration on and
an `all_users` target can be grown past the threshold by anyone who registers
accounts, after which the reconciliation safety net is off for that target.

**Not a finding of the full profile.** With the broker, `enqueue` does not
refuse under load, `enqueue_failed` stays 0 and nothing changes.

**Proposed fix (before the PR).** The reconciler runs in the cleanup task, off
every request path, so it can wait instead of being refused:

1. Give `OutboundPublisher` a provided method `enqueue_paced(&msg, deadline)`
   (default: `enqueue`), implemented by `InProcessOutboundPublisher` with
   `Sender::send_timeout` (or `reserve` under `tokio::time::timeout_at`)
   against the run's own `deadline` (`RECONCILE_WALL_CLOCK`); call it from
   `queue_again` and from the provisioner's and `converge_groups_of`'s bulk
   loops. A paced producer is refused only at its deadline or when the channel
   is closed — no burst of refusals, so R101W4-01 stays closed — and the
   `should_stop` the sweep already passes (`cleanup.rs:404`) ends the wait at a
   stop (#598).
2. In `enqueue_everything`, offer the linked resources — `erase_pending` first —
   **before** the in-scope users, so a run cut by its deadline has spent it on
   erasures and deprovisioning rather than on accounts that are already in step.
3. Keep "stop at the first refusal" only for a closed channel or a passed
   deadline, and scope it to the step, so step 2's repairs are offered after the
   downstream reads.
4. Correct the CHANGELOG line, the deployment guide (`:1793-1795`), the module
   documentation and T-445's 2026-10-13 amendment; amend T-415 with the date.

**Test** (`crates/axiam-scim/tests/outbound_reconcile_test.rs`, using the
shared `Queue` double's pending limit that `a234f3221` added): a queue of
capacity 4 behind a consumer that frees one slot per tick; a target with 20
in-scope users, one `erase_pending` link of an erased user, and a downstream
listing that holds an unlinked account whose `externalId` is a disabled user.
After one run, the erasure's reference and the adoption's reference have both
been **accepted** by the queue and `enqueue_failed` is 0. On HEAD it fails:
neither is offered.

## 3. R101-02 — unauthenticated SAML verifications queue without bound on the crypto gate

The composition root builds one semaphore for CPU-bound crypto
(`crates/axiam-server/src/boot.rs:705`, `resolved_max_concurrent_hashes()`
permits) and since R101W2-01's fix (`7055077a2`) hands it to the SAML service
(`:1436`). Its acquirers on HEAD:

| Acquirer | Caller | Wait |
|---|---|---|
| Argon2id hash and verify (B1) | login, reset, gRPC user service | `timeout(hash_acquire_timeout_secs = 5 s)` — `password_reset.rs:125-129`, `service.rs:396` |
| CRL re-sign (#607, W1.3) | `GET /pki/v1/{org}/ca/{ca}/crl`, unauthenticated | `timeout(DEFAULT_CRL_PERMIT_WAIT = 5 s)` then `503` — `crl.rs:571-592`; the module says why: "Without a bound a saturated gate would queue unauthenticated CRL requests without limit" (`:340-348`) |
| SP ACS response verification (R101W2-01) | `/federation/saml/acs`, `/acs/form`, unauthenticated | `acquire_owned().await`, **no bound** — `saml.rs:740-746` |
| IdP SSO / SLO request verification (R101W2-01) | `/t/{tenant}/saml/sso`, `/slo`, unauthenticated | `acquire_owned().await`, **no bound** — `saml_idp.rs:640` (called at `:702` and `saml_idp_slo.rs:467`) |
| Metadata verification (R101W2-01) | fetch path | `acquire_owned().await`, no bound — `saml_metadata.rs:291-298` |
| The IdP's own RSA-4096 signing | after a sign-in | no bound — `saml_idp.rs:1256` (pre-existing, authenticated) |

tokio's `Semaphore` is fair: a waiter queues behind every earlier one. While
SAML posts arrive faster than the permits verify them, their waiters accumulate
without limit, each holding its request and its document, and every bounded
waiter that arrives behind them — a password login, a CRL re-sign after a
revocation — reaches its 5 s and gives up: logins answer B1's `503`, and the CRL
route answers `503` for every CA whose list changed (an unchanged list is served
from the cache without a permit, `crl.rs:474-477`). A relying party keeps its
previous list until `nextUpdate`, so the revocation does not reach it while the
flood lasts (T-102). The per-address limits of the SAML routes (`login_per_min`
on the ACS, the browser preset on the IdP routes, `server.rs:564-585,1945-1962`)
bound one address, not a distributed sender; the IdP receiver only verifies a
request that names a registered SP and carries an enveloped signature, so the
sender needs an SP entity id (published in the SP's metadata) and not a key. The
W2 review could not weigh this: the fix came after it, and the CRL's wait is W1's.

**Proposed fix:** acquire with the same bound the other unauthenticated
waiters use — `tokio::time::timeout(Duration::from_secs(hash_acquire_timeout_secs), gate.acquire_owned())`
in `verify_signature_off_worker`, `verify_post_signature_off_worker` and the
metadata verifier — and treat the timeout as the refusal each path already has
(`SignatureInvalid` / `SamlResponseFailed`, no oracle: an invalid signature and
a busy gate read alike) or as a `503`. **Test:** with every permit held, an ACS
post and an IdP SSO post each return within the bound plus a margin, and a
waiting CRL re-sign behind them still gets its permit once one is released.

## 4. R101-03 — the tenant purge under the stop budget

W4.9 (#598) made the cleanup join bounded (`join_cleanup`, `boot.rs:3437-3450`:
`ORDERLY_STOP.cleanup` 5 s, `LEASE_LOSS_STOP.cleanup` 2 s, then `abort`) and
listed what a cut can leave: "Every sweep is re-run by the next tick … with two
exceptions" (`docs/deployment/README.md:1847-1859`; T-444's 2026-10-13
amendment, STRIDE `:3706`). W1.7 and W3.5, on other branches, changed the
tenant purge so that neither sentence covers it:

* **A cut mid-purge holds the tenant for an hour.** The purge is claimed by a
  conditional write (`claim_purge`, `tenant.rs:207-238`) and released only when
  it fails with an error (`cleanup.rs:300-315`). An aborted future releases
  nothing, and the next start's sweep finds the claim younger than
  `TENANT_PURGE_LEASE` (1 h, `cleanup.rs:227`) and skips the tenant. The purge's
  steps are idempotent, so nothing is wrong once it resumes; but "re-run by the
  next tick" is false for an hour, and a deployment that restarts more often
  than the lease (a rollout per replica) can keep pushing it back. The sweep
  also has no stop check between tenants, unlike the GDPR loop (`:1863-1871`).
* **A cut at the end loses the record for good.** `purge_tombstoned`'s last
  statement deletes the tenant row (`tenant.rs:313-334`); `sweep_tenant_purge`
  then writes `tenants.purged` with D-5's `audit_exported_through`,
  `audit_rows_deleted` and `audit_rows_kept` (`cleanup.rs:337-355`). A cut while
  that `DELETE` is in flight (the statement can commit after the client
  dropped it) or before the audit write leaves no tenant row, so no later sweep
  sees the tenant and nobody writes the record: the only evidence of which
  audit rows the purge destroyed, and on what bound, is gone. It is the same
  class as R101W4-03 (#624, the erasure's `gdpr.user_pseudonymized`), on the
  sweep that destroys the most.

**Proposed fix:** check the stop between tenants; run each tenant's purge and
its `tenants.purged` write as one spawned task the cleanup abort does not
cancel, joined within the margin (R101W4-03's proposal), or release the claim
from a drop guard; add the tenant purge to T-444's and the guide's list of what
a cut can leave. **Test:** a `cleanup_task.rs` case whose step hook holds the
tick inside a tenant purge across a stop: the next start purges the tenant
without waiting out the lease, and `tenants.purged` exists exactly once.

## 5. R101-04 and R101-05 — text

**R101-04.** §33.3 rule 16 (contract 1.61): "The `429` of its allowance
(`{"error":"rate_limit_exceeded"}`, `Retry-After: 60`) is spent per signed-in
user, not per address". Since R101W3-04 (`6298b509e`, after the W3 review and
before W5 wrote the text) `/ciba/requests` also carries a per-address governor at
`ciba_approval_per_min × 10` (`server.rs:23-26,844-852`), whose `429` is
actix-governor's, not the handler's `too_many_requests` body
(`ciba_approval.rs:389-395`). The OpenAPI response text says only "The signed-in
user's `ciba_approval_per_min` allowance of this route is spent"
(`ciba_approval.rs:290`). Not a defect — the backstop is what §9 requires — but
the contract should name it: "and a per-address backstop of ten times that,
which a console behind one address meets only with hundreds of open tabs".

**R101-05.** Three sentences the merge made stale:
(a) T-472's #601 amendment: "There is no cache on this path … (the
tenant-to-organization cache serves AXIAM session refresh only)". Since W3.4,
`SettingsScopePolicy` reads `TenantOrgCache` on every grant of a `dcr` or `cimd`
client (`scope_policy.rs:60-64`, wired at `boot.rs` with the same `Arc`). The
liveness read itself is still uncached, so the claim about the tombstone holds;
the parenthesis does not.
(b) §27.15 note 10: the CA forward's pending row goes to the organization's log
"and not to the CA's tenant's, which a tenant deletion purges". Since W3.5 the
purge deletes only rows at or before the export bound, so a pending row written
after the export would survive; the rule (organization's log) is right, its
reason is now half of one.
(c) T-444 and `docs/deployment/README.md:1847` — "two exceptions" — omit the
tenant purge (R101-03).
**Proposed fix:** W7.3 corrects (a) and (c) with a dated correction in the
entries' text; (b) and R101-04 go into the next contract revision's record.

## 6. The merge resolutions and the cross-wave invariants — verified

* **Tenant purge (`76f841c89`).** `purge_tombstoned` checks the tombstone,
  runs `purge_rows` (W3.5's report), deletes the tenant row with `RETURN BEFORE`
  inside a count and answers `NotFound` when this call did not remove it (W1.7),
  then `Ok(report)`. `sweep_tenant_purge` maps `NotFound` to "done, not
  recorded", writes `tenants.purged` with the report only on `Ok`, and releases
  the claim only on another error. Overlapping purges after a lapsed lease both
  run idempotent steps; only the winner reports, and its `audit_rows_deleted`
  may be 0 if the loser deleted first (the field is documented as "what the
  resuming pass deleted").
* **W1.4 × W3.5.** The audit stage deletes only `audit_log` rows at or before
  the export bound and signatures covering none of the kept rows; the
  certificate stage keeps revoked rows until `notAfter` + 8 d. The orphan scan
  skips the audit trail, so a deleted tenant's later audit rows never make it an
  orphan; its kept certificate rows do, eight days after each expires, and the
  orphan purge then removes them without touching the audit trail
  (`PurgeScope::Orphan`). The eight days cover §35 rule 4's "until the end of
  the epoch that follows" at the largest interval (two half-intervals of 3.5 d;
  `crl.rs` `RefreshEpoch::of`).
* **Cleanup tick (`0570b3425`).** The 22 job names `tick()` records equal the
  pre-merge inline tick's and are all registered in `job_health.rs` (scripted
  comparison); W1.5's `vault_revocation_failing` follows `vault_revocation`
  inside the same `if let Some(certs)`. A cut of the Vault sweep (its own budget
  is 30 s, longer than the cleanup join) leaves claimed rows for
  `CLAIM_LEASE` (120 s) and nothing counted against them; a revoke Vault took
  but AXIAM did not stamp is sent again, which Vault accepts.
* **W1.8 × W4.9.** `revoke_erased_users_certificates` runs before
  `anonymize_user` and is fatal, so a cut leaves the account due with its names
  intact; `sweep_pending_purges` checks the stop between users and calls W1.8's
  `purge_single_user(&user, pepper)`.
* **W3.3 × W4.9.** The swept client's grants are revoked before the row and
  again after it (`cleanup.rs:799-835`), so a cut leaves no row-less client with
  live device or CIBA grants.
* **`server_leaf_profile.rs`.** `user_id: None` on a `Server` certificate is the
  only valid value (W1.8 refuses `user_id` on any type but `User`); test-only.
* **Migrations.** v95 … v98 in order (`schema.rs:495-514`), each
  `DEFINE FIELD/INDEX IF NOT EXISTS` only, each with a scope test that forbids
  `UPDATE`, `REMOVE`, `DELETE`, `OVERWRITE`, `DEFAULT`; the newest-version
  assertion reads 98 (`:6441`). No backfill (D-6).
* **Threat model.** 477 entries, ids unique, `threatTop` 477, 443 / 17 / 17;
  T-472 and T-102 carry both waves' dated amendments, appended in order.
* **Buckets.** W3's handler keys `ciba_approval_list:{tenant}:{user}` and
  `ciba_hint_cap:{tenant}:{hmac}:{parity}` share no prefix with any
  `RateLimitShared` endpoint name (the route-level `ciba_approval_list` bucket is
  gone); the only duplicated names are W2's two (#632) and three pre-existing
  intentional ones (`login`, `uma_rreg`, `directory_config`).
* **Audit names.** No action constant added in the range duplicates another;
  the one duplicated value in the tree (`ssf.inactive_shared_issuer`) predates
  it.

## 7. The plan's §9 rules on the merged tree

* **Every new route carries a limiter.** No route was added (191 paths before
  and after). Of the routes the waves rewired, `/ciba/requests` keeps a
  per-address governor and the per-user bucket in both counter modes
  (R101W3-04); the five federation routes carry the browser preset (#614).
* **Every credential-bearing outbound request uses `guarded_fetch_no_redirect`.**
  The redirect-following callers left are `discovery_cache.rs:206`,
  `jwks_cache.rs:255`, `saml_metadata.rs:115`, `sp_metadata.rs:173`,
  `cimd.rs:827` and `mds/mod.rs:111` — all `GET` without a credential; the four
  Vault clients refuse redirects (W1.2); back-channel logout, CIBA ping, SSF push,
  webhooks and SCIM go through the no-redirect guard, each pinned by a source
  test.
* **Every refusal of a credential check costs one verify.** W3.2's tenant read
  comes after the credential and answers the same `invalid_client`; W3.6's hint
  cap counts after client authentication and before the hint is resolved.
* **Two-writer registries.** The tenant purge claim, the Vault forward claims
  (leaf and CA) and the SSF stream update (opt-in `expected_updated_at`, W4.5)
  are conditional on what was read.
* **Schema** — §6.

## 8. The commits no F4 review saw

Each wave's review preceded its in-wave fixes. These were read here in full:
`08c4c383c` (R101W1-01: the `$taken` rule is computed inside the revoking
statement, the `created_at` bound applies to the name match only — holds);
`032c3443d`, `7055077a2`, `21025c7ab`, `7eec4ae01` (W2's BOM strip, the
transform allow-list, the DTD flag, the libxml-rs use-after-free — the
allow-list requires one `SignedInfo`, one canonicalization, one `Reference`
bound to the signed element, at most two transforms from the c14n family and
enveloped-signature, and counts `Transform` / `CanonicalizationMethod` by local
name so a mis-namespaced one refuses; `every_signature` finds signatures by
local name and refuses one outside XML-DSig; R101-02 is this review's only
finding there); `e55e5c97e` (R101W2-04: registration validation and delivery
agree, §34.5's text matches `oauth2_clients.rs:478-505,673-675,868-874`); `6298b509e`
(R101W3-04 — R101-04); **`a234f3221` (R101W4-01 — R101-01)**; `ba79a20a3`,
`f3c6a683a`, `121371927` (W6: text, the serial-keyed placement table, the shared
root). #653 (serials derived from the public key) meets two of these: the
placement table keyed on the serial, and every CRL entry. Both are bounded by
proof of possession — two certificates on one key belong to the holder of that
key — so the cross-wave effect is that revoking one revokes its twin on the
list (fail-closed); nothing to add to #653.

## 9. Contract 1.61 against the server

Checked and consistent: §34.5's table and its `backchannel_logout_uri`
paragraph; §6.1 rule 8 and §27.11 rule 5 against `revoke_user_certificates`
(`certificate.rs:735-797`: the binding first, the convention only for unbound
rows, bounded by `created_at` and by names no other account holds, regardless
of a bound service account); §33.3 rule 13's hint cap (two fixed windows of
parity, current plus previous at most three, so at most three in any ten
minutes; counted before the hint is resolved; refused calls count); rule 16's
order, bound and two members; §35 rule 4's epochs and the eight-day purge
margin; §27.15 note 10's organization-log row (`ca_certificates.rs:372-400`)
and the deletion record's `signing_ca_vault_revocations_pending`
(`tenants.rs:771-776`); the registry's 190 operations in 28 namespaces and the
spec digest the registry names. New contradictions: R101-04, R101-05 (b).

---

## 10. Issue bodies

### R101-01 (Medium) — a SCIM reconciliation run never reaches its links in the minimal profile

**Where:** `crates/axiam-scim/src/outbound/reconcile.rs:566-582` (`queue_again`),
`:424-546` (`enqueue_everything`: users, then groups, then links), step 2's
repairs at `:714-715`, `:778`, `:878`; `crates/axiam-amqp/src/outbound/inprocess.rs:63`;
`crates/axiam-db/src/repository/user.rs:1246`. Introduced by `a234f3221`
(the in-wave fix of R101W4-01). Threats: T-415, T-417 (T-412).

Since the R101W4-01 fix, a reconciliation run stops offering references at its
first refused enqueue and counts every later one as failed, for the rest of the
run. Step 1 offers in-scope users first (oldest first), linked resources last;
step 2's repairs come after. In the minimal profile (1 024-slot queue, one
consumer) a target whose in-scope users fill the queue before the run reaches
its links never has a link or a repair offered by reconciliation again: each run
lists the same users in the same order and stops at the same place. So a refused
downstream erasure `DELETE` (`erase_pending`) is never retried, an unlinked
downstream account of an erased or disabled user is never deprovisioned, and
drift past the first ~1 000 users is never repaired — contrary to T-415 and to
the CHANGELOG / deployment guide ("the next run offers them again").
`scim_reconcile` fails on `/health/jobs` every night.

**Fix:** pace bulk producers instead of refusing them — an
`OutboundPublisher::enqueue_paced(&msg, deadline)` (default `enqueue`; in
process: `send_timeout` / `reserve` until the run's deadline, ended by the stop
signal) used by `queue_again`, the provisioner's fan-out and
`converge_groups_of`; offer linked resources (`erase_pending` first) before the
users; scope any remaining stop-at-refusal to a closed channel or a passed
deadline, per step. Correct the CHANGELOG, `docs/deployment/README.md:1793-1795`,
the module docs and T-445; amend T-415, dated.

**Test:** `outbound_reconcile_test.rs` — capacity-4 queue with a consumer that
frees one slot per tick, 20 in-scope users, one `erase_pending` link of an
erased user, and an unlinked downstream account whose `externalId` is a disabled
user: after one run both the erasure's and the adoption's references were
accepted and `enqueue_failed == 0`.

### R101-02 (Low) — unauthenticated SAML verifications wait without bound on the shared crypto semaphore

**Where:** `crates/axiam-federation/src/saml.rs:740-746`,
`crates/axiam-api-rest/src/handlers/saml_idp.rs:640` (called from `:702` and
`saml_idp_slo.rs:467`), `crates/axiam-federation/src/saml_metadata.rs:291-298`;
compare `crates/axiam-pki/src/crl.rs:571-592` and
`crates/axiam-auth/src/password_reset.rs:125-129`. From `7055077a2`
(R101W2-01's fix) meeting W1.3 (#607). Threats: T-102 (availability), T-474.

The SAML verifiers moved under the deployment's one crypto semaphore wait for a
permit with `acquire_owned().await` and no bound; the semaphore is fair, and the
other waiters (Argon2id, the CRL re-sign) give up after 5 s. A sustained flood
of signed SAML posts to the public ACS or the IdP SSO/SLO receiver therefore
queues without limit ahead of every login and every post-revocation CRL re-sign,
which answer `503` for as long as it lasts; a relying party keeps the list from
before the revocation until `nextUpdate`.

**Fix:** bound each SAML acquire by `hash_acquire_timeout_secs` and treat the
timeout as that path's existing refusal (or a `503`).
**Test:** with all permits held, an ACS post and an IdP SSO post return within
the bound; a CRL re-sign queued behind them gets the next permit.

### R101-03 (Low) — a cleanup cut holds a tenant purge for an hour, or loses its `tenants.purged` record

**Where:** `crates/axiam-server/src/cleanup.rs:263-370` (`sweep_tenant_purge`;
claim `:296`, release only on error `:300-315`, the record `:337-355`),
`crates/axiam-db/src/repository/tenant.rs:207-238,294-334`,
`crates/axiam-server/src/boot.rs:3437-3450`; `docs/deployment/README.md:1847-1859`,
T-444. From W4.9 (#598) meeting W1.7 (#610) and W3.5 (#602). Threats: T-444, T-472.

The bounded cleanup join aborts a tenant purge where it is. The claim is not
released, so the next start skips the tenant for the whole one-hour lease; and a
cut while the tenant row's `DELETE` is in flight or before `tenants.purged` is
written leaves no tenant row for any later sweep, so the record — with D-5's
export bound and audit counts — is never written. Neither case is in the
guide's or T-444's list of what a cut can leave.

**Fix:** check the stop between tenants; run each tenant's purge and its record
as one task the abort does not cancel (joined within the margin), or release the
claim from a drop guard; list the case in T-444 and the guide.
**Test:** `cleanup_task.rs`, a step hook that holds the tick inside a tenant
purge across a stop: the next start purges it at once and `tenants.purged`
exists exactly once.

### R101-04 (Informational) — §33.3 rule 16 omits the CIBA list's per-address backstop

**Where:** `sdks/CONTRACT.md` §33.3 rule 16; `crates/axiam-api-rest/src/server.rs:23-26,844-852`;
`crates/axiam-api-rest/src/handlers/ciba_approval.rs:290`.

Contract 1.61 says the list's `429` is spent per signed-in user, not per
address. Since R101W3-04 the route also has a per-address governor at ten times
the allowance, with the governor's own `429`. Name it in the contract's next
record and in the OpenAPI response text.

### R101-05 (Informational) — three sentences the merge made stale

**Where:** T-472's #601 amendment (`Axiam.json`, STRIDE and copies);
`sdks/CONTRACT.md` §27.15 note 10; T-444 and `docs/deployment/README.md:1847`.

(a) "the tenant-to-organization cache serves AXIAM session refresh only" — W3.4's
`SettingsScopePolicy` reads it on every external client's grant
(`crates/axiam-api-rest/src/scope_policy.rs:60-64`). (b) Note 10's reason for the
organization's log ("the CA's tenant's, which a tenant deletion purges") is half
true since W3.5's export bound. (c) "two exceptions" omits the tenant purge
(R101-03). W7.3 for (a) and (c), dated; (b) with R101-04.

## 11. Invariants

* **Append-only audit**: nothing in the range updates an audit row; the tenant
  purge's audit stage deletes only rows an export holds, and signatures over
  nothing still in the log (W3.5); the orphan purge never touches the audit
  trail.
* **Revocation evidence**: a revoked certificate or signing CA stays on its
  issuer's list until the end of the epoch after it expires, and its row stays
  eight days past `notAfter`, through a tenant purge (W1.4); an erased or
  deleted account's `User` certificates are revoked before its names are
  overwritten (W1.8).
* **Fail-closed where it matters**: a tenant purge without an export time keeps
  the whole trail; a tombstoned tenant's clients get `invalid_client`
  everywhere; every SAML signature check refuses an unrecognised transform,
  canonicalization or namespace; the CRL route answers `503` rather than a list
  that misses a revocation. R101-01 is where a safety net fails *open*: the
  reconciliation that should retry an erasure silently never offers it.
* **Additive schema**: v95 … v98, no backfill; the newest-version assertion is 98.
* **Contract**: 1.61 is additive; registry 190 / 28; spec and registry digests
  agree.
* **Threat model**: 477 threats, 443 / 17 / 17, unique ids; version 2.40.0 left
  for W7.3, which also takes R101-05 and the stop-arithmetic text of R101W4-09.
