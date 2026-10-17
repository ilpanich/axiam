# Security review — release 1.1.0, wave W4 (F4)

**Date:** 2026-10-15.
**Against:** `claude/release-1.1.0-w4`, the whole wave diff `3d011573e..5445dadc0`
(6 commits, 30 files, 2 859 lines added and 469 removed). Every commit carries a
signature (`gpgsig` header in 6 of 6; the sandbox has no
`gpg.ssh.allowedSignersFile`, so `%G?` cannot verify them here).
**Scope:** every W4 task of the release-1.1.0 plan (§5):
* W4.1 #626, #629: two issue comments, no commit (out of scope for code review;
  §0.1 of the plan records the lines they name).
* W4.2 #655, #624 (`fff66606b`): tenant purges and erasures run as units of
  their own (`cleanup::AuditedWork`) with a point of no return; the purge claim
  is released on every exit but a removed tenant row.
* W4.3 #625 (`dad34dbe9`): the `axiam.audit.dlq` event is emitted before the
  dead-letter file append.
* W4.4 #628 (`e0670df5e`): the cleanup task is told first (at the loss, after a
  lost lease); the lease release is a bounded budget step; the lease-loss REST
  cut is tested through the listener.
* W4.5 #623 (`1ab46dd50`): the conformance workflow validates `plan_name` and
  `module_timeout` before use; the scripts refuse a non-numeric timeout before
  the arithmetic.
* W4.6 #630, first half (`3b0a540a7`): `gate.py` refuses a plan `baseline.json`
  does not name unless `--new-plan` says it is new.
* W4.7 #627 (`5445dadc0`): the settings page says when a switch turned on stays
  off under the organization.

**Method:** adversarial reading of the diff and of the paths it touches,
against [`threat-model-stride.md`](threat-model-stride.md) and `Axiam.json`
(model 2.41.0, 477 threats), the plan's §10 rules, the 1.0.1 W4 review that filed
most of this wave's issues
([`security-review-release-1.0.1-w4-2026-10-13.md`](security-review-release-1.0.1-w4-2026-10-13.md)),
and the OWASP ASVS 5.0 areas the diff touches (V2 business logic and
concurrency, V13 configuration, V14 data protection, V16 logging). Every commit
message was read in full and its claims are answered in §2 … §8 against the
code, not the message. Cancellation and ordering questions were settled by
reading the statements and the `tokio` semantics they rely on (task abort,
runtime drop, `timeout_at`); the workflow's regular expressions were probed
under bash in the `C` and `C.UTF-8` locales; the bad-input dispatch the
orchestrator ran (38737745432) was checked with `gh run view` (its log is not
reachable from here: the results store answers 403). The wave's own tests and
CI's lints were run (§11). This review fixes nothing. IDs: `R110W4-nn`.

---

## 0. Summary

**No Medium or higher finding; seven Informational.** Nothing needs a fix inside
the wave.

The wave does what its issues ask, on the paths they name. The cancellation
design of W4.2 holds where it matters: a unit before its point of no return
gives itself up at the stop and leaves its work due (the account) or tombstoned
and unclaimed (the tenant); a unit past it has the whole teardown window; the
teardown aborts and *awaits* the unit at the cleanup deadline, so nothing of the
unit's own code runs after `serve` returns. Every release this wave added or
reordered is conditional on the releaser's own stamp — the purge claim on
`purge_claimed_at = $claimed_at` (`tenant.rs:256`), the lease on
`holder = $holder` with a per-process UUID (`minimal_profile_lease.rs:237`,
`boot.rs:415`) — so a release that lands late, or from a guard, can never clear
what a successor took. The workflow validation has no bypass: `^…$` in bash's
`[[ =~ ]]` is a POSIX ERE without `REG_NEWLINE`, so a value with an embedded or
trailing newline does not match (probed), and the validated values are the only
ones that reach `$GITHUB_ENV`.

What is left is text that promises a little more than the code does, two
residuals the executors already named (confirmed, §9), CI noise after a refused
input, and one test whose name claims more than it asserts.

| ID | Finding | Severity | Surface → threat | Origin | Disposition |
|---|---|---|---|---|---|
| R110W4-01 | The purge claim's drop guard spawns its release onto a runtime that `serve`'s return drops at once. At the teardown's cut — the one exit where the guard is the only release, and typically a datastore too slow to answer the awaited release — nothing waits for that release, and the runtime drop cancels it unless it has already landed; the tenant then waits out the one-hour lease. The guide says only a `SIGKILL` leaves it to the lease. | Informational | `cleanup.rs:559-583`, `boot.rs:3487-3516`, `main.rs:674`; guide `README.md:1903-1906` → T-444, T-472 | wave (W4.2) | Issue |
| R110W4-02 | Three claims stated as absolutes are not: a unit "never crosses its point of no return once the stop is requested" (a check-then-act, `cleanup.rs:440→444`, `:1382→1390`); a lost lease's unit "writes nothing after its budget" (a statement sent before the abort can commit after it; the guard's release); the cleanup task is told "at the loss itself" (at the renewal's *detection*, up to `renew_every` = 10 s after a successor could have claimed). All three are benign as built; the text should say so. | Informational | T-444 amendments, guide `README.md:1846-1856`, `boot.rs` comments | wave (W4.2, W4.4) | Issue (text) |
| R110W4-03 | Confirmed residual: an erasure or tenant purge past its point of no return that outlasts the whole window loses its audit row for good (logged at `ERROR`); likewise an orphan purge whose last `DELETE` is in flight at the stop. A marker is needed — for erasures the pending `account_deletion` row can serve, with one reorder. | Informational (was Low as R101W4-03) | `cleanup.rs:1577-1636`, `:465-481` → T-444, T-108 | wave residual (W4.2) | Issue |
| R110W4-04 | Confirmed residual: a GDPR dead-letter file write that fails after its awaiter was cut is not logged (the event, now first, is). Fixable inside `axiam-audit`'s `append_off_thread`. | Informational | `dead_letter.rs:395-402`, `gdpr.rs:224-277` → T-108 | wave residual (W4.3) | Issue |
| R110W4-05 | After a refused dispatch input, the `if: always()` steps run on an empty workspace (`just`, `gate.py` not found) and the gate step goes red as if the plans had regressed; the workflow's own patterns are covered by no test (the shell test covers the scripts' helper). | Informational | `fapi-conformance.yml:128-153, 396-520` | wave (W4.5) | Issue |
| R110W4-06 | T-472 still reads "Neither is fixed in 1.0.1 (#655)" with no pointer to the 1.1.0 fix in T-444; a reader of the 1.1.0 model is told the purge record can be lost. | Informational | `threat-model-stride.md:434` (T-472) | wave (text) | **W8.3** (reconciliation) |
| R110W4-07 | `a_lost_lease_closes_a_request_still_running_at_the_cut_and_the_audit_drain_runs_after_it` shows the cut and the timing, not that the audit drain ran after the cut: the served request's row is written by the worker within milliseconds, long before the cut, and `stopped` being empty at the cut is guaranteed by the held cleanup tick. | Informational | `minimal_profile_boot.rs:1129-1212` | wave (W4.4, test) | Issue |

Executors' follow-ups (§9): the unit that outlasts the window — **confirmed**
(R110W4-03); the dead-letter write failure after a cut — **confirmed**
(R110W4-04); a late-committing lease release — **rejected**, it is harmless
(§4.2); T-472's #655 text — **confirmed** for W8.3 (R110W4-06).

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Audited units, purge claim, erasure split | W4.2 | `cleanup.rs` (sweep, units, `PurgeClaim`, `AuditedWork`, `erase_and_record`, `ErasureUnit`, `purge_single_user`), `boot.rs` `join_cleanup`, `tenant.rs` (`claim_purge`, `release_purge_claim`, the split), `ssf_emitter.rs` `with_cause`, `user.rs` `anonymize_user`, `cleanup_task.rs` | **read in full**; abort/drop/spawn order traced through `tokio` semantics and `main.rs` |
| Dead-letter ordering | W4.3 | `gdpr.rs` `dead_letter_audit`, `dead_letter.rs` `append_off_thread` / `append_blocking`, `gdpr_audit_dlq_test.rs` | **read in full**; tests run |
| Stop order, lease release, budgets | W4.4 | `boot.rs` teardown and budgets, `profile.rs` (`spawn_lease_renewal`, `spawn_lease_loss_stop`, `release_lease_within`), `minimal_profile_lease.rs`, `minimal_profile_boot.rs`, the five copies of the arithmetic | **read in full**; every copy compared (§4.3) |
| Workflow inputs | W4.5 | `fapi-conformance.yml` (every `inputs.*` use, every `if: always()` step), `lib-env.sh`, `run-plan.sh`, `run-some.sh`, `justfile` `conformance-run`, `validate_inputs_test.sh`, `ci.yml` | **read in full**; regexes **probed**; shell test run; run 38737745432 checked |
| Gate | W4.6 | `gate.py`, `test_gate.py`, runbook "The CI gate", `docs/conformance/README.md` | **read**; unit tests run |
| Console | W4.7 | `SettingsPage.tsx`, `policyText.ts`, `surfaceSwitches.tsx`, the test | **read**; vitest, `tsc`, oxlint run |
| Threat model and docs | all | T-444 (two amendments), T-108, STRIDE ↔ `Axiam.json`, `threatModel.ts`, guide, Compose ×2, k8s, `operate.ts`, CHANGELOG | compared with the code (§6, §7); generator run |

Not run: a minimal-profile deployment against a remote SurrealDB (every
cancellation claim here is about the client side; where a statement already sent
can still commit server-side, this review says so rather than measuring it).

## 2. W4.2 — audited units and the bounded join (orchestrator point 1)

### 2.1 Can a unit outlive its budget, or write after a lost lease's budget?

`join_cleanup` (`boot.rs:3487`) takes one deadline, waits for the cleanup task
until it, aborts and **awaits** the task past it, then `AuditedWork::join`
(`cleanup.rs:746`) waits for the unit in the slot until the same deadline and,
past it, aborts and awaits that too. `timeout_at` polls the inner future before
the delay, so a unit that has just finished is not aborted needlessly. A
`JoinHandle` resolves after an abort only once the task's future has been
dropped, so when `join` returns nothing of the unit's own code runs again —
`serve` cannot return while a unit is live. The slot cannot be lost: the handle
is stored synchronously in `run` (`:718-720`, no `await` between spawn and store);
`run` takes it back only once the unit has answered (`:724`); `run` refuses to
spawn once the stop is set (`:714`), so a later sweep in the same tick cannot
overwrite a unit left for the teardown, and the watch value never returns to
`false`.

What can still reach the datastore after the deadline is not unit code:

* a statement whose request was sent before the abort can commit after it (the
  client future is dropped, the server-side statement is not recalled);
* the `PurgeClaim` guard's release, spawned from `drop` (R110W4-01);
* a dead-letter file append already on the blocking pool (a local file, not the
  datastore).

None of these can touch a successor's state: the first is the unit's own,
idempotent or past-the-point-of-no-return work; the second is conditional on
this replica's own `claimed_at` (`tenant.rs:256`); the third is a file. The
absolute "writes nothing after its budget" (T-444, commit body) is the text
point of R110W4-02.

### 2.2 Overlap with the next start, on this or another replica

* **Tenant purge.** The claim keeps every other replica off the tenant while a
  unit runs (`claim_purge` is a conditional `UPDATE`, `tenant.rs:219-222`), and a
  unit that gives itself up releases it, awaited, before the teardown ends. The
  unit is dead before `serve` returns, so it cannot overlap this replica's next
  start.
* **User erasure (no claim).** In the **minimal profile** a successor can start
  once the lease is released; W4.4 sends the cleanup signal **before** that
  release (`boot.rs:3289` then `:3315`), so every unit has given itself up or is
  past its point of no return — `deletion_pending` cleared, the account no longer
  selected — by the time a successor can boot. That ordering is new in this wave
  and closes the overlap the old order (release, then signal) allowed. After a
  *lost* lease the overlap that remains is the detection gap of R110W4-02 (c),
  which predates the wave.
* In the **full profile** every replica runs the GDPR sweep, unchanged: two
  replicas can erase one account concurrently. That is **pre-existing, not new**,
  and is safe in what matters: `anonymize_user` writes the same deterministic
  values twice; the proof's `UNIQUE (tenant_id, user_id)` index rejects the
  second insert, so the slower erasure returns `Err` before `mark_completed` and
  before its audit row — exactly one `gdpr.user_pseudonymized`. What doubles is
  the SSF `account-purged` event (emitted before the proof, `cleanup.rs:1395`).
  T-444's "every erasure step is idempotent" is close enough; the duplicate event
  is outside this wave.

### 2.3 The point of no return against the stop signal

The tenant purge checks `work.stopping()` (`cleanup.rs:440`) and then sends
`remove_purged_tenant` (`:444`); the erasure checks (`:1382`) and then sends
`anonymize_user` (`:1390`). Neither is atomic with the signal: a stop sent
between the check and the statement leaves the unit crossing a few microseconds
*after* the stop was requested. It is benign — the window a crossing unit gets is
measured from the signal, so it loses microseconds of 5 to 18 s (2 to 13 s) —
but "never crosses it once the stop has been requested" (T-444, guide, doc
comment) is not literally true (R110W4-02 (a)). The pre-point steps are under
`until_stopped` (`:683`, `biased` toward the work, so a step that is ready
completes), and a step dropped there is idempotent: the rows purge, the audit
scrub, `prepare` (sessions, links, credentials, graph edges, certificates).

### 2.4 The `PurgeClaim` drop guard

* **Conditional release.** `release_purge_claim(tenant_id, claimed_at)` is
  `UPDATE … SET purge_claimed_at = NONE WHERE purge_claimed_at = $claimed_at`:
  a claim another replica took after the lease (a different stamp) is left
  alone. A late guard release is therefore harmless.
* **When the guard is the only release.** The give-up and failure paths await
  the release themselves (`:431, :435, :441, :451`); `settle` disarms the guard
  once the tenant row is gone. The guard fires on a panic (a live runtime:
  tested, works) and on an abort — at the teardown's cut, i.e. when the awaited
  release itself, or `remove_purged_tenant`, has not answered within the window.
  There the release is `Handle::spawn`ed (`:568`) and `join_cleanup` returns
  without waiting for it; `serve` returns, `main` returns at once
  (`main.rs:674`), and `#[tokio::main]`'s runtime drop cancels the spawned task
  at its first `await`. In the one case the guard exists for — a datastore
  that did not answer the awaited release in seconds — it is unlikely to land
  first — **R110W4-01**.
* "A drop during the runtime's own shutdown" (doc comment, T-444 (iii)) is not
  the case that occurs: the drop happens in `join`, before shutdown; it is the
  spawned release that shutdown cancels.

### 2.5 The split of `purge_tombstoned`

`purge_tombstoned_rows` and `remove_purged_tenant` are public on
`SurrealTenantRepository`. Nothing outside the cleanup unit calls them (every
other caller uses the composition `purge_tombstoned`, unchanged). A caller that
removed the tenant row first would leave the rows to the orphan scan (once at
start and once a day), not expose them: the tenant is tombstoned and filtered
from every read path, and `remove_purged_tenant` refuses a live tenant in the
statement itself. Acceptable as a crate-internal contract; no finding.

### 2.6 The SSF `with_cause` task-local

`CAUSE` is a `tokio::task_local!` scoped by `with_cause`, which wraps a future.
`purge_single_user` passes `with_cause(System, unit.purge(…))` *as the unit*
(`cleanup.rs:2693`), so the scope is established inside the spawned task, around
the session revocations and the `account-purged` emission alike — one `txn`, as
D-52 requires. The commit's reasoning (a spawn would not carry a scope set
outside it) is correct, and it is the only task-local in the workspace. A unit
given up during `prepare` and redone at the next start emits the rest under a
new `txn`; that was already so for a cut tick.

## 3. W4.3 — the dead-letter event and the file (orchestrator point 2)

`dead_letter_audit` now emits `axiam.audit.dlq` (`gdpr.rs:234-242`) before its
first `await`, with the fields operators match on; the file append follows, and
its failure has its own event (`:265-270`), which names the path and the I/O
error and nothing of the record. The order is right and the two tests pin it
(the FIFO test fails on the old order). Two residuals, both as the executor
states them:

* **A cut during the datastore write itself** (before `dead_letter_audit` is
  reached) produces neither the row nor a dead letter nor the event: the write
  never returned an error. That is R110W4-03's class, not W4.3's.
* **A file write that fails after its awaiter was cut** is not logged
  (R110W4-04). The executor's argument against spawning the whole function is
  sound (it would escape the teardown's join); the narrow fix is to log inside
  the blocking closure, which runs to completion regardless.

## 4. W4.4 — the stop order, the lease release, the arithmetic (orchestrator point 3)

### 4.1 Cleanup signalled first, and at the loss

`SIGTERM`/dead component: `cleanup_shutdown_tx.send_replace(true)` right after
the REST listener returns (`boot.rs:3289`), before the gRPC stop and the release
(`:3315`). Lost lease: the lease-loss stop's `stop` callback sends it
(`:3215`) before stopping actix; the teardown's later send is a no-op. Both are
`send_replace`, which cannot fail on dropped receivers. Correct. "At the loss"
is at the renewal's detection: `spawn_lease_renewal` (`profile.rs:285-326`)
learns of a takeover only at its next successful renewal, up to `renew_every`
(10 s) after the successor claimed, and a successor can claim only after the TTL
(30 s) without renewal. During that gap the old instance's cleanup task runs as
usual — inherent in a lease, not new, but the text should not imply the gap is
zero (R110W4-02 (c)).

### 4.2 `release_lease_within`, and a release that commits late

`release_lease_within` (`profile.rs:341`) is `timeout(bound, release)`: on
expiry the future is dropped and a warning logged. A release whose request was
already sent can still commit after the bound. That is harmless: the statement
is `DELETE … WHERE holder = $holder` (`minimal_profile_lease.rs:236-237`), and
`holder` is this process's `Uuid::new_v4()` (`boot.rs:415`), so it can only
delete a lease this instance still holds; a successor's row carries another
holder. **The executor's follow-up "a late-committing lease release" is
rejected** — it needs no issue. (Pre-existing and also harmless: `renewal.abort()`
is not awaited before the release, so a renewal already polled can race it; the
renewal is an `UPDATE … WHERE holder = $holder`, which cannot recreate a deleted
row.)

### 4.3 The arithmetic, every copy

| Copy | States | Verdict |
|---|---|---|
| `boot.rs:3439-3466` consts | `ORDERLY_STOP` 20 + 5 + 1 + 2 + 5 + 5 = 38 s; `LEASE_LOSS_STOP` 5 + 2 + 0 + 1 + 3 + 2 = 13 s | source |
| `boot.rs:3527` `FATAL_STOP_BACKSTOP` | `ORDERLY_STOP.total()` + 1 s = 39 s | derived |
| `boot.rs:3534-3544` const asserts | 38 < 39 < 40; 13 < 15; `LEASE_LOSS_STOP.lease_release` is zero (new); REST cut < actix drain; whole seconds | all compile (§11) |
| `profile.rs:66-71` `LeaseTiming::PRODUCTION` doc | 5 + 2 + 1 + 3 + 2 = 13 s within 15 s | consistent (no release step on that path) |
| guide "Stopping, and the grace period" | six steps, 38 s, 2 s margin; 13 s; backstop 39 s; window 5–18 s / 2–13 s | consistent |
| `docker-compose.minimal.yml`, `docker-compose.prod.yml`, `k8s/server/deployment.yml` | 38 s, 2 s margin, 40 s grace; 13 s | consistent |
| `website/src/docs/operate.ts` | 38 s, 2 s margin; 13 s | consistent |
| `AuditedWork` doc, T-444 | window 5–18 s `SIGTERM` (5 = cleanup bound alone; 18 = 5 + 1 + 2 + 5 + 5), 2–13 s lost lease (signal at the loss, so the whole 13 s) | consistent |
| `CHANGELOG.md:69, 568`, `threat-modeling-and-security.md:495` | 37 s / 38 s | 1.0.1 history; W8.4 writes `[1.1.0]`, W8.3 reconciles the write-up (the executor left it, correctly) |

### 4.4 The exit status on a loss during `SIGTERM`

The flag is read again at the release (`:3312`) and for the exit (`:3365`), so a
loss the renewal reports during the gRPC stop skips the release and exits
non-zero. After `renewal.abort()` no later loss can be observed, which is fine:
the release is conditional, and an instance whose renewal was aborted mid-loss
exits zero having released nothing of anyone's. The budget stays `ORDERLY_STOP`
in that case, so up to 5 + 2 + 5 + 5 = 17 s of steps can follow a loss seen
during the gRPC stop under the lease's 15 s backstop — the 2 s edge 1.0.1 accepted
and documented; W4.4 did not widen it (the skipped release adds nothing).

## 5. W4.5 — workflow inputs (orchestrator point 4)

* **Every use.** `inputs.plan_name` and `inputs.module_timeout` appear only in
  the validation step's `env:` (`fapi-conformance.yml:130-131`); `axiam_image`
  only in "Select the AXIAM image" (`:259`, validated since #592). "Run the three
  test plans" no longer has an `env:` of raw inputs. The step is the first, before
  the checkout.
* **The match.** The patterns are held in variables and expanded unquoted on the
  right of `=~`, so bash compiles them as ERE. Probed in `C` and `C.UTF-8`: `5`,
  `00009` accepted; `5\n`, `5\nX=1`, `\n5`, `5\r`, `٣`, `５`, `123456`, empty and
  `a[$(id)]` refused for the timeout; `fapi2-x` and `-` accepted, `a\nb`, `A`,
  `é`, `ß`, `ｘ`, `a_b` refused for the plan. A trailing newline does **not**
  match `^[0-9]{1,5}$`: without `REG_NEWLINE`, `$` matches only at the end of the
  string. So nothing validated can add a line to `$GITHUB_ENV`, and the values
  appended are the validated variables, not the raw inputs.
* **The refusal line.** `%q` keeps the value on one line; a `::` inside it cannot
  start a workflow command, which must begin the line. The dispatch's annotation
  shows it escaped: `Got: a\[\$\(echo\ INJECTED\ \>\&2\)\]`.
* **The scripts.** `conf_require_uint` (`lib-env.sh:140`) is a regex, never
  arithmetic; both scripts call it before any network or filesystem work, and
  `run-plan.sh` also covers `CONFORMANCE_SUITE_WAIT`, which reached the same
  arithmetic. `10#` is applied only to a value that already matched
  `^[0-9]{1,5}$`, so it can only remove the octal reading of a leading zero.
* **The test.** `validate_inputs_test.sh` (281 checks, run here: pass) feeds the
  helper and both real scripts 16 bad values, including subscript, `$( )`,
  backtick, `;`, newline-carrying ones, and checks the exit status, one stderr
  line, no canary and no bare `INJECTED`; it is wired into `ci.yml`. It does not
  cover the workflow step's own patterns (R110W4-05).
* **`if: always()` after a refusal.** Run 38737745432 refused the payload at the
  validation step; "Render the report", "Collect … logs", "Upload", "Tear down"
  and "Gate on the plan result" then ran on a workspace with no checkout: the
  report step's `just` is not found (it carries on, `|| true`), and the gate
  step fails on a missing `gate.py` and is red beside the real refusal. No input reaches those steps, so it is noise, not
  exposure — but a red "gate" on a refused input reads like a conformance
  regression to whoever triages it (R110W4-05).

## 6. W4.6 — `gate.py --new-plan` (orchestrator point 5)

An unknown plan cannot pass silently any more: a result file whose plan is
neither in `baseline.json` nor in `--new-plan` is a regression (`gate.py:187`),
and so is a `--plan` with neither a result nor a baseline (`:183`). `--new-plan`
is as narrow as it can be: it must also be a `--plan` (so its result file is
required) and must not name a baselined plan (`:173-177`), so a flag left in the
workflow cannot quietly downgrade a recorded plan. A new plan is still red on
`FAILED`, `COULD_NOT_START`, an overrun, or nothing `PASSED`. With no `--plan`
at all, any `--new-plan` is refused. The workflow passes none, and its three
plans are in both baselines. Tests: 37 pass. The second half of #630 (the
re-recorded unattended baseline over a dispatch artifact) is outstanding and
waits for D-4; nothing here depends on it.

## 7. W4.7 — the console message (orchestrator point 6)

No security surface. Correctness: the notice is computed only from a refetch
that succeeded and is not still invalidated (`state.status === "success"`, and
TanStack Query sets `status: "error"` on a failed refetch even when it keeps
the old data, so stale pre-save data never produces the notice); `turnedOn` is
"off when seeded, on in the form", so a save that turned nothing on, or turned
something off, adds nothing. The surface labels move to `policyText.ts` and stay
byte-identical. Vitest (59), `tsc` and oxlint pass.

## 8. The §10 rules, CI parity, the threat model (orchestrator points 7 and 8)

| Rule | Verdict | Evidence |
|---|---|---|
| Every new route carries a limiter | **not touched** | no route added |
| `guarded_fetch_no_redirect` for credential-bearing outbound requests | **not touched** | no outbound HTTP |
| One verify per refusal of a credential check | **not touched** | no credential check changed |
| Two-writer registries written conditionally | **holds** | purge claim: `claim_purge` conditional on the lease, `release_purge_claim` on the claimant's stamp; lease: `release` on the holder |
| Schema | **holds** | no migration |
| Contract | **holds** | `sdks/CONTRACT.md`, `sdks/openapi.json` untouched; spec digest passes |
| Threat model: nothing enters without its test | **holds** | T-444's two amendments and T-108's name tests that exist and pass (§11) |
| `[lints]`, new crates, layering | **holds** | none added; `check-crate-layering.py` passes |

**Threat-model copies.** The two entries the wave amended (T-444 twice, T-108)
are byte-identical in `threat-model-stride.md` and `Axiam.json` (each
`mitigation` string found verbatim in the STRIDE file); statuses unchanged.
`website/src/threatModel.ts` was regenerated twice (W4.2, then W4.4, which also
picked up W4.3's T-108 amendment that `dad34dbe9` had not regenerated); running
`node website/scripts/gen-threat-model.mjs` on the branch head leaves **no
diff** (477 threats: 443 / 19 / 15). Text against code: T-108's amendment
matches (§3). T-444's first amendment says "budgets are unchanged (37 s)", which
the second amendment corrects to 38 s in its own text as a dated correction, as
the rules require. The absolutes in both amendments are R110W4-02, and (iii) of
the first is R110W4-01.

## 9. Executors' follow-ups, confirmed or rejected

| Follow-up | Verdict | Where |
|---|---|---|
| A unit past its point of no return that outlasts the window loses its audit row (needs a schema marker) | **Confirmed**, Informational; for erasures a marker exists without a migration (the pending `account_deletion` row, after one reorder); the tenant purge needs one, or a reconciliation from the system log | R110W4-03 |
| A dead-letter write failure after a cut is not logged (fix inside `axiam-audit` `append_off_thread`) | **Confirmed**, Informational | R110W4-04 |
| A late-committing lease release | **Rejected**: the release is conditional on this process's UUID; nothing to file | §4.2 |
| T-472's text about #655 | **Confirmed**, for W8.3 | R110W4-06 |

## 10. Documentation claims

| Claim (where) | Verdict | Evidence |
|---|---|---|
| A stop no longer holds a tenant purge for an hour (guide, T-444, commit) | **true for give-up, failure and panic**; not reliably for a unit cut at the bound | R110W4-01 |
| "only a process that ends before the release is written (a `SIGKILL`) still leaves the tenant to the lease" (guide `:1903-1906`) | **incomplete** | R110W4-01 |
| A unit never crosses its point of no return once the stop is requested (guide, T-444, docs) | **true up to a check-then-act window** | §2.3, R110W4-02 |
| A lost lease's unit writes nothing after its budget (T-444, commit) | **true of the unit's code**; not of a statement already sent, nor the guard's release | §2.1, R110W4-02 |
| The cleanup task is told "at the loss itself" (guide `:1850`, T-444) | **true at detection** | §4.1, R110W4-02 |
| The window is 5–18 s / 2–13 s; `ORDERLY_STOP` 38 s, backstop 39 s, grace 40 s | **true**, every copy | §4.3 |
| The dead-letter event cannot be skipped by a cancellation (T-108, doc comment) | **true** once `dead_letter_audit` is entered | §3 |
| The workflow validates both inputs before use and before the checkout (commit, workflow comments) | **true** | §5 |
| A plan absent from the baseline is refused unless `--new-plan` (runbook, README, `gate.py` doc) | **true** | §6 |

## 11. Checks run

`RUSTFLAGS=-Dwarnings`, `CARGO_INCREMENTAL=0`, line-tables-only debug info, the
swagger-ui placeholder; each command's own exit code (logs in the scratchpad).

| Check | Result |
|---|---|
| `cargo fmt -p axiam-server -p axiam-db -p axiam-api-rest -- --check` | exit 0 |
| `cargo test -p axiam-server --test cleanup_task` | exit 0 (34 passed, the five new #655/#624 cases among them) |
| `cargo test -p axiam-server --test minimal_profile_boot` | exit 0 (11 passed, the two new #628 cases among them) |
| `cargo test -p axiam-server --lib -- profile` | exit 0 (19 passed, incl. the two `release_lease_within` tests and `a_lost_lease_cuts_the_requests_in_flight_before_the_backstop`) |
| `cargo test -p axiam-server --lib -- cleanup` | exit 0 (3 passed) |
| `cargo test -p axiam-server --test req14_gdpr_test` | exit 0 (4 passed) |
| `cargo test -p axiam-db --test tenant_purge_test` | exit 0 (8 passed; `purge_tombstoned` as the composition of the two halves) |
| `cargo test -p axiam-api-rest --test gdpr_audit_dlq_test` | exit 0 (6 passed, the two new #625 cases among them) |
| `cargo clippy -p axiam-server --lib --tests -- -D warnings` | exit 0 |
| `cargo clippy -p axiam-db --lib --tests -- -D warnings` | exit 0 |
| `cargo clippy -p axiam-api-rest --lib --tests -- -D warnings` | exit 0 |
| `cargo check -p axiam-server --no-default-features` (SAML off) | exit 0 (the const asserts of §4.3 compile in both feature sets) |
| `bash conformance/scripts/tests/validate_inputs_test.sh` | exit 0 (281 checks, 0 failed) |
| `python3 -m unittest discover -s conformance/scripts -p 'test_*.py'` | exit 0 (37) |
| `npx vitest --run src/pages/settings/SettingsPage.test.tsx`; `npx tsc -p tsconfig.app.json --noEmit`; `npm run lint` (oxlint) | exit 0 (59 tests); 0; 0 |
| `node website/scripts/gen-threat-model.mjs` | exit 0, **no diff** (477: 443 / 19 / 15) |
| STRIDE ↔ `Axiam.json` for the amended entries | identical (T-444, T-108) |
| `scripts/check-remediation-evidence.py`, `check-crate-layering.py`, `check-config-key-coverage.py`, `check-spec-digest.py`, `check-conflict-markers.py`, `check-doc-links.sh` | exit 0 each |
| `scripts/check-website-links.py` | exit 1: 23 of 55 external links unreachable through this sandbox's proxy (403 tunnel); environmental, no link the wave touched |
| bash regex probes (§5) | as reported |
| `gh run view 38737745432` | validation step failed on the payload; the five `always()` steps ran; log not reachable (403) |
| Commit signatures | 6 of 6 carry `gpgsig` |

## 12. Issue bodies

### R110W4-01 (Informational) — a tenant purge cut at the teardown's bound still waits out the claim's hour

`PurgeClaim`'s drop guard (`crates/axiam-server/src/cleanup.rs:559-583`) spawns
`release_purge_claim` with `Handle::spawn` when a unit is dropped holding the
claim. The give-up, failure and panic paths are fine (the first two await the
release; a panic leaves a live runtime). The abort at the teardown's deadline
(`AuditedWork::join`, `:746`, from `join_cleanup`, `boot.rs:3487`) is the one exit
where the guard is the only release — it means the awaited release or the row
removal did not answer within the window, i.e. a slow datastore — and there the
spawned task races the process exit: `serve` returns right after the join,
`main` returns (`main.rs:674`), and the `#[tokio::main]` runtime drop cancels the
task at its first `await`. The tenant then waits out `TENANT_PURGE_LEASE` (1 h),
the #655 symptom. The deployment guide (`docs/deployment/README.md:1903-1906`)
says only a `SIGKILL` leaves the tenant to the lease; T-444 (iii) and the
`PurgeClaim` doc call it "a drop during the runtime's shutdown", but the drop
happens before shutdown — it is the spawned release that shutdown cancels.
Impact is a delay of the purge of data already out of every read path.
**Proposed fix:** correct the three texts ("a unit cut at the stop's bound
releases its claim from a spawned task that the process exit may cancel; the
tenant then waits out the lease"). Optionally, have `AuditedWork::join` keep the
guard's release `JoinHandle` (e.g. the guard sends it through the `AuditedWork`
slot) and await it for a few hundred milliseconds out of the margin — which then
needs a budget line of its own. **Test:** a unit held at
`UnitStep::TenantRowsPurged` with the stop set and a release that never answers
is cut by `join`; on a runtime dropped right after, the claim is still set (the
documented behaviour).

### R110W4-02 (Informational) — three absolutes in T-444 and the guide are not quite absolute

(a) "A unit never crosses its point of no return once the stop has been
requested": the check and the statement are separate
(`crates/axiam-server/src/cleanup.rs:440` then `:444`; `:1382` then `:1390`), so
a stop sent between them is followed by the crossing. Benign: the window is
measured from the signal. (b) "A replica that lost its lease writes nothing after
its budget": true of the unit's code (the abort is awaited); a statement already
sent can commit after the abort, and the `PurgeClaim` guard's release is spawned
after it (conditional on its own stamp, so harmless). (c) "The cleanup task is
told at the loss itself" (`docs/deployment/README.md:1850`, T-444, `boot.rs`
comments): at the renewal's *detection* (`crates/axiam-server/src/profile.rs:285-326`),
which can come up to `renew_every` (10 s) after a successor claimed the expired
lease; in that gap the old instance's cleanup task runs beside it (pre-existing).
**Proposed fix:** say "once the stop is requested it starts no new crossing
(a crossing already being sent completes)", "writes nothing of its own code
after its budget; a statement already sent may still commit", and "at the loss
as the renewal detects it, which can be up to `renew_every` after the takeover".
W8.3 can take it with the reconciliation.

### R110W4-03 (Informational) — a unit that outlasts the whole window still loses its audit row

After W4.2 an erasure or a tenant purge cut by the stop loses its record only if
it crossed its point of no return before the stop and then did not finish its
last statements in the whole window (5–18 s `SIGTERM`, 2–13 s lost lease); the
log says so at `ERROR` (`crates/axiam-server/src/boot.rs:3508-3514`). The
erasure proof (or the purge) stands; `gdpr.user_pseudonymized` and the
`account_deletion` completion (`crates/axiam-server/src/cleanup.rs:1577-1636`), or
`tenants.purged`, are never written. The same holds for an orphan purge
(`:465-481`) whose final `DELETE` is in flight at the stop: no row is left for
the next scan to find, so no record. Narrowed from R101W4-03 (Low) to a datastore
that cannot answer two or three statements in seconds. **Proposed fix:** for an
erasure, write `gdpr.user_pseudonymized` *before* `mark_completed`, and have the
GDPR sweep also select `account_deletion` rows still pending whose user is
`status = 'Anonymized'`, writing the row and completing them (no migration; it
covers erasures that have a request row). For the rest, a marker in the same
transaction as the point of no return (`user.erasure_audit_pending`,
`tenant_purge_pending` keyed by id) under the next migration number, cleared with
the record. **Test:** a unit held past its point of no return and cut at the
deadline is recorded by the next start, exactly once.

### R110W4-04 (Informational) — a dead-letter file write that fails after its awaiter was cut is not logged

`dead_letter_audit` (`crates/axiam-api-rest/src/handlers/gdpr.rs:224-277`) now emits
`axiam.audit.dlq` first; the file append runs on the blocking pool via
`append_off_thread` (`crates/axiam-audit/src/dead_letter.rs:395-402`) and runs to
completion if its awaiter is dropped, but its failure is logged by the awaiter
(`gdpr.rs:265-270`), which a cut has dropped. The record's metadata (the
pseudonym of an erasure) is then in neither sink. **Proposed fix:** log the
failure inside the blocking closure (path and I/O error, nothing of the record)
and drop the caller's own failure log, so the log line does not depend on the
awaiter. **Test:** a write to a missing directory, with the awaiting future
dropped before the blocking task finishes, still logs `failed to append audit
dead-letter file`.

### R110W4-05 (Informational) — the conformance workflow runs its `always()` steps on an empty workspace after a refused input

When "Validate dispatch inputs" refuses a value
(`.github/workflows/fapi-conformance.yml:128-153`), "Render the report",
"Collect server and rig logs on failure", "Upload conformance artifacts", "Tear
down" and "Gate on the plan result" (`:396-520`) still run, with no checkout:
`just` and `conformance/scripts/gate.py` are not found, and the gate step is red
beside the refusal (dispatch 38737745432), which reads as a conformance
regression. No input reaches those steps; it is noise. Separately, the
workflow's two patterns are checked only by a dispatch: `validate_inputs_test.sh`
covers `conf_require_uint`, not the YAML. **Proposed fix:** give the validation
step `id: inputs` and guard the five steps with
`if: always() && steps.inputs.outcome == 'success'`; add to
`validate_inputs_test.sh` a check that the patterns in the workflow step equal
`^[a-z0-9-]{1,128}$` and the helper's `^[0-9]{1,5}$` (grep the YAML), so the two
cannot drift. **Test:** the shell test's new check; one bad-input dispatch shows
a single red step.

### R110W4-06 (Informational) — T-472 still says #655 is not fixed

`claude_dev/threat-model-stride.md:434` (T-472, and the same text in
`Axiam.json`) ends its 2026-10-14 correction with "Neither is fixed in 1.0.1
(#655)". True of 1.0.1; a reader of the 1.1.0 model is not told that T-444's
2026-10-15 amendment closes both states (and what remains: R110W4-01, R110W4-03).
**Proposed fix (W8.3):** a dated amendment to T-472 pointing at T-444's #655
amendment and its residuals; status unchanged.

### R110W4-07 (Informational) — the lease-loss REST-cut test does not show the drain ran after the cut

`a_lost_lease_closes_a_request_still_running_at_the_cut_and_the_audit_drain_runs_after_it`
(`crates/axiam-server/tests/minimal_profile_boot.rs:1129-1212`) proves the cut
request's connection closes without a response between 5 s and 10 s after the
loss, the exit is the lease error and the backstop does not run — the oracle the
plan named. Its last part does not prove what its name says: the served
request's audit row is written by the middleware's worker within milliseconds
of the response (1.5 s after the loss, well before the cut), and
`stopped.try_recv()` being empty at the cut (`:1181`) is guaranteed by the
cleanup tick the test holds for an hour. **Proposed fix:** rename it to what it
asserts, or make the drain observable — an audit sink that holds writes until
released after the cut, with the row asserted absent at the cut and present at
the exit. **Test:** the strengthened case fails if the audit drain is moved
before the cut.

## 13. Invariants

* **Nothing changes behaviour silently for an operator**, with one item W8.4's
  `[1.1.0]` must carry: the `SIGTERM` stop adds up to **38 s** (was 37) and the
  dead-component backstop is **39 s** (was 38); the shipped 40 s grace is
  unchanged, so no action is needed for a deployment that follows the guide.
  W4.2 changes when an erasure or tenant purge stops, not what it writes.
* **Append-only audit:** nothing in the wave updates or deletes an audit row.
* **No personal data in logs added by the wave:** the new dead-letter failure
  event carries the path and the I/O error; the new `ERROR` lines carry
  durations; the workflow refusal prints the escaped dispatch input only.
* **Conditional releases:** every release the wave added or moved is
  conditional on the releaser's own stamp or holder; none can clear a
  successor's claim or lease.
* **Fail-closed where it matters:** the workflow on its inputs and the scripts
  on their knobs; the gate on an unknown plan; the console on a failed refetch.
* **Crate layering, spec digest, config-key coverage, remediation evidence:**
  pass.
* **Threat model:** 477 threats (443 / 19 / 15), STRIDE and `Axiam.json` agree
  on every amended entry, the generated website file is current; version
  2.41.0 left for W8.3.
