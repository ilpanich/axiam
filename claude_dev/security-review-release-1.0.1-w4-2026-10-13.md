# Security review — release 1.0.1, wave W4 (F4)

**Date:** 2026-10-13.
**Against:** `claude/release-1.0.1-w4`, the whole wave diff `v1.0.0..334943a41`
(9 commits, 37 files, 3 236 lines added and 577 removed; `v1.0.0` is
`0a90de0a3`). Every commit carries a signature (`gpgsig` present on all 9; the
sandbox has no `allowedSignersFile`, so `%G?` cannot verify them here).
**Scope:** every W4 task of the release plan (§5): W4.1 #597 (no commit — the
open-register sentences and T-469), W4.2 #592 (the conformance workflow's
`axiam_image` input, `4156b8033`), W4.3 #593 (the unattended baseline and the
gate, `ba562d8fc`, recorded in `b34a0d0fb`), W4.4 #600 (the tenant Settings save,
`31ca68717`), W4.5 #590 (the SSF stream `PUT`'s client version and the console's
narrowing, `11de0b3e3`), W4.6 #594 (the GDPR records' dead letter off the worker,
owner-only and synced, `7bbdfa5a2`), W4.7 #595 (the dead-letter envelope,
`94c2747c1`), W4.8 #596 (a refused in-process enqueue off the producer's path,
`82e580e10`) and W4.9 #598 (the two stop budgets, the bounded cleanup join and
the lease-loss REST cut, `334943a41`).
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) and
`Axiam.json` (model 2.40.0 on this branch, 475 threats: 437 / 17 / 21), the
plan's §9 rules (which carry the Phase 23 §7 rules), the 1.0.0 W2 F4 review that
filed most of this wave's issues
([`security-review-release-1.0.0-w2-2026-10-10.md`](security-review-release-1.0.0-w2-2026-10-10.md)),
and the OWASP ASVS 5.0 areas the diff touches (V2 business logic and
concurrency, V3 frontend, V4 API, V13 configuration, V14 data protection, V16
logging and error handling). Claims were checked against the code — and, for
the REST cut, against the `actix-server` 2.9.7 source the lock file pins — not
against the commit messages. Two claims needed a probe (§11). This review fixes
nothing: every finding is reported with its evidence, a proposed fix and an
issue body (§12). The Medium finding is proposed for a fix inside the wave; the
rest for `1.0.x`.

---

## 0. Summary

**One Medium finding, on the audit path the wave set out to take off the
producer's path.**

* **R101W4-01 (Medium, T-445 → T-108).** #596 hands the `delivery_abandoned` row
  of every refused in-process enqueue to the request-audit channel (4 096 slots)
  with `try_record`, and the producer no longer waits. That was the point, but it
  also removed the only pacing a bulk producer had. SCIM reconciliation enqueues
  **one reference per in-scope user** with `try_send` against a 1 024-slot queue
  whose consumer delivers one HTTP call at a time, so in the minimal profile a
  tenant with more than about five thousand in-scope users produces, at every
  nightly run and at every "reconcile now", a burst of refusal rows that fills
  the audit channel in milliseconds. A probe (§2) measured it: 10 000 refusals took 87 ms, filled the channel's 4 096 slots and had 5 904 more dropped, and all 100 request rows offered right after were dropped too.
  While the channel is full, **every tenant's** request-audit rows are dropped,
  and every dropped row — the refusals included — is offered to the dead-letter
  file, whose request share (nine tenths of 192 MiB) is then spent on
  reconciliation noise; once it is full, request-row loss is not recoverable
  until an operator replays and moves the file. Before #596 each refusal awaited
  its own datastore write: the reconciler was slow, and nothing was dropped.
  No attacker is needed; a tenant administrator can bring it forward (the
  on-demand route, once per five minutes per target).

Five Low and five Informational findings are reported for `1.0.x` (§12).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R101W4-01** | Refused-enqueue rows share the request-audit channel with no pacing; a SCIM reconciliation's refusal burst (one per in-scope user past 1 024) fills it, drops every tenant's request rows and spends the dead-letter file's request share. | **Medium** | `inprocess.rs` `refuse`, `middleware.rs` `try_record`, `reconcile.rs` → T-445, T-108 | wave (#596) | **Fix in wave** (proposed §2) |
| R101W4-02 | The `module_timeout` dispatch input reaches bash arithmetic (`$(( … + ${CONFORMANCE_MODULE_TIMEOUT} ))`), where an array subscript runs a command substitution: command execution for anyone who may dispatch, the class #592 closed for `axiam_image`. | Low | `fapi-conformance.yml`, `run-plan.sh`, `run-some.sh` | pre-existing (sibling of #592) | Reported |
| R101W4-03 | A cleanup sweep cut at its new bound can leave a GDPR erasure without its `gdpr.user_pseudonymized` row (and its `account_deletion` row pending) for good: the next start does not resume either. | Low | `cleanup.rs` purge pipeline, `boot.rs` `join_cleanup` → T-444, T-108 | wave (#598; the cut existed before at `SIGKILL`) | Reported |
| R101W4-04 | The GDPR dead letter's second sink (the `axiam.audit.dlq` event) now follows an `await`; a future dropped there — the cleanup cut, the lease-loss REST cut, a dropped handler — skips it although the file write completes. | Low | `gdpr.rs` `dead_letter_audit` | wave (#594) | Reported |
| R101W4-05 | No `[Unreleased]` CHANGELOG line for #590 (a new optional request field; the console now refuses an emptying save) or #594 (the dead-letter file becomes `0600` and is tightened at open, which breaks a reader running as another user). | Low | `CHANGELOG.md` | wave | Reported |
| R101W4-06 | The new `request_audit.dropped` count mixes request rows with outbound refusal rows, so `/health/jobs` can no longer say which were lost. | Low | `/health/jobs`, `try_record` | wave (#596) | Reported (with R101W4-01) |
| R101W4-07 | Turning a surface back on while the organization has it off now saves silently (200, "Settings saved") and the surface stays off; the server's naming `400` is gone. Not a fail-open. | Informational | console settings | wave (#600) | Reported |
| R101W4-08 | The lease release is an unbounded datastore call in the `SIGTERM` teardown, outside `ORDERLY_STOP` and before the cleanup task is told to stop; the REST cut is tested only through its callback. | Informational | `boot.rs` → T-444 | pre-existing, made visible | Reported |
| R101W4-09 | The shipped Compose and k8s comments and the website's *Operate* page still state the old stop arithmetic (no cleanup step; a lost lease drains for 5 s). | Informational | `docker/`, `k8s/`, `website/src/docs/operate.ts` | wave (text) | Reported (W7.3) |
| R101W4-10 | The recorded unattended baseline cannot be re-derived from its run here (artifact and log unreachable); the gate still tolerates every `WAITING` of a `--plan` the main baseline does not name. | Informational | `conformance/` | wave | Reported |
| R101W4-11 | The API still widens a receiver's narrowing on an absent `events_requested` (documented); the W5 SDK ports must send what they read, as the console now does. | Informational | `PUT /api/v1/ssf/streams/{id}` → T-406 | pre-existing, documented | Reported (W5) |

The carry list's points that are not findings: W4.1 holds (§9); the
`axiam_image` validation has no bypass (§5); `gate.py` fails closed (§6); the
envelope, its decoder, the `reason` set and the recipe's lock-step hold (§7);
the GDPR handler's failure semantics are unchanged (§7); the two budgets'
arithmetic and the REST cut's mechanism hold (§8); the threat-model copies agree
(§9); the regenerated spec is byte-identical to `--dump-openapi` and it and the registry pass their checks (§11).

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Conformance workflow input | W4.2 #592 | `fapi-conformance.yml`; every dispatch input traced to its consumers (`justfile` `conformance-run`, `run-plan.sh`, `run-some.sh`, `benchmarks/justfile`, the target Compose file) | **read in full**; the regex **probed** under bash in `C`, `C.UTF-8` (§5); arithmetic injection **probed** |
| Conformance gate | W4.3 #593 | `gate.py`, `test_gate.py`, both baselines, the workflow's gate step, the runbook section | **read in full**; unit tests run; fail-closed **probed**; runs 38317560409 / 38327426158 checked with `gh run view` |
| Tenant Settings save | W4.4 #600 | `SettingsPage.tsx` (`surfaceOverride`, `toOverride`, the save), `surfaceSwitches.tsx`, `services/settings.ts`, `settings.rs` (the server's disable-only rule) | **read**; every (organization, override, form) case walked; vitest run |
| SSF stream `PUT` | W4.5 #590 | `ssf_admin.rs` (`SsfStreamInput`, `check_input`, `update_stream`), `oauth2/src/ssf.rs` (the receiver's writes), `SsfStreamsPage.tsx`, `services/ssf.ts`, `ssf_test.rs`, the spec | **read**; every path that writes `events_requested` listed; tests run |
| Dead letter: off-thread, mode, sync | W4.6 #594 | `dead_letter.rs` (in full), `gdpr.rs`, `tenants.rs`, `cleanup.rs` callers, `request_audit_loss.rs`, `gdpr_audit_dlq_test.rs` | **read in full**; tokio 1.53.1's `File` buffer checked for the one-line claim |
| Dead letter: envelope | W4.7 #595 | `dead_letter.rs`, `loss.rs`, `middleware.rs`, README recipe and its test | **read in full**; the recipe's test reads the README's own filter |
| Refused enqueue | W4.8 #596 | `inprocess.rs`, `middleware.rs` `try_record` / `offer`, `messaging.rs`, `boot.rs` binding; every `enqueue(` producer (`webhook.rs`, `ssf_delivery.rs`, `ciba.rs`, SCIM `provisioner.rs`, `deliverer.rs`, `reconcile.rs`) | **read**; crowding **probed** (§2) |
| Stop budgets, cleanup join, REST cut | W4.9 #598 | `boot.rs` teardown, `profile.rs`, `cleanup.rs` (tick, purge, export), `minimal_profile_boot.rs`; `actix-server` 2.9.7 `server.rs` / `worker.rs` | **read in full**; the drop's effect traced in the dependency's source |
| Threat model and docs | all | `Axiam.json`, STRIDE, write-up, `threatModel.ts`, `threatModelSummary.ts`, `security.ts`, deployment guide, *Operate*, Compose, k8s, CHANGELOG | the four amended entries compared with the code (§9, §10); generator run |

Not run: a `workflow_dispatch` of the conformance workflow (D-7; the review has
no means to dispatch); a real minimal-profile deployment with a SCIM target (the
§2 numbers come from the in-process channel with a stand-in datastore that takes
1 ms per append, which is if anything faster than a networked one).

## 2. R101W4-01 — refused-enqueue rows crowd the request-audit channel

**What #596 changed.** `InProcessOutboundPublisher::enqueue` uses `try_send`
(`inprocess.rs:230`). A refusal used to `await` the consumer's sink — a direct
datastore append — on the producer's task. It now calls `refuse`
(`inprocess.rs:192`), which, once the composition root has bound the middleware
(`boot.rs:2648`), hands the row to `AuditMiddleware::try_record`
(`middleware.rs:253`): the same 4 096-slot channel the request rows use, and the
same `offer` (`middleware.rs:344`) — when the channel is full the row is counted
in `request_audit.dropped` and submitted to the dead-letter file with reason
`channel_full`. The producer waits on nothing.

**Why that matters for one producer in particular.** Every producer but one
enqueues a handful of messages per event. SCIM reconciliation (`reconcile.rs`
step 1, `queue_once` → `queue_again`, `:524-552`) enqueues **one reference per
in-scope user, per pushed group and per linked resource**, in a loop that only
counts an `Err` (`report.enqueue_failed += 1`) and carries on. The SCIM queue
holds 1 024 (`IN_PROCESS_CAPACITY`) and its consumer makes one HTTP call at a
time, so after the first ~1 024 references every further one is refused. Before
#596 each refusal was an awaited append, so the loop ran at datastore speed and
every row landed; since #596 the loop runs at CPU speed and its refusals arrive
at the audit channel faster than the one worker appends. The provisioner
(`provisioner.rs:106-112`, every target × every wanted resource of a change) and
the group fan-out (`deliverer.rs:935-944`) have the same shape at smaller sizes.

**Probe.** A temporary test in `inprocess.rs`'s test module (deleted before this
commit): a SCIM queue of one slot held by a gated deliverer (the consumer that
never keeps up), the audit middleware at its production capacity
(`CHANNEL_CAPACITY`, 4 096) over a stand-in datastore that takes 1 ms per
append, then 10 000 `enqueue` calls in a loop (a reconciliation of a
10 000-user tenant), then 100 `try_record` calls standing in for other tenants'
request rows:

| Measure | Value |
|---|---|
| refused enqueues | 10 000 of 10 000 |
| time for the loop | 87 ms |
| refusal rows the audit channel queued / dropped | 4 096 (full) / 5 904 |
| `request_audit.dropped` after the 100 request rows below | 6 004 |
| request rows dropped, of 100 offered right after | **100** |
| rows the worker had written when the loop ended | 0 |

Before #596 the same loop would have awaited 10 000 appends — about ten
seconds at 1 ms each — and dropped nothing.

**Consequences.**

* **Cross-tenant request-audit loss (T-108).** While the burst occupies the
  channel, every request row of every tenant is dropped. They are counted and
  dead-lettered, but they are dropped — the outcome R1W2-01 was rated Medium for
  in 1.0.0, with a bulk job in place of a sign-in flood.
* **The dead-letter budget (R1W2-02) is spent on noise.** Each dropped refusal is
  a line (~400 bytes with the envelope). A 50 000-user tenant reconciled nightly
  writes roughly 45 000 lines, ~18 MB, into the 172.8 MiB request share; within
  days the share is full, the writer reports `is_full`, and every later
  request-row loss is `not_recoverable` until an operator replays and moves the
  file with the server stopped.
* **No attacker is needed.** The nightly run does it for any tenant above about
  five thousand in-scope users (1 024 queued + 4 096 channel slots); a tenant
  administrator can repeat it with `POST /api/v1/scim-targets/{id}/reconcile`
  (once per `RECONCILE_WALL_CLOCK`, 5 min, per target).
* Context, not a finding of this wave: in the minimal profile a reconciliation
  never gets past the first ~1 024 references of a run at all, since nothing
  waits for room; the rest are refused every night. That gap predates W4; #596
  turned its refusals from slow writes into a flood.

**Proposed fix (in wave).** Two parts, either of which removes the flood; both
keep "one row per refusal" for the producers that refuse one message at a time,
so the pinned tests stand.

1. **Stop the bulk producers at the first refusal.** In `reconcile.rs`
   (`queue_again`), `provisioner.rs` and the group fan-out in `deliverer.rs`,
   treat `OutboundError::Enqueue` as "the queue is full for this run": stop
   enqueuing, count the references not offered (`report.enqueue_failed +=
   remaining`), and record **one** `scim_push.delivery_abandoned` row for the run
   with `refused_count` in its metadata (`QUEUE_FULL_REASON`), not one per
   reference. The next run retries them, as it does today.
2. **Give `try_record` a headroom.** Have it refuse — without offering the row
   to the dead-letter file — when the channel's free capacity
   (`self.tx.capacity()`) is below a reserve kept for request rows (for example
   `CHANNEL_CAPACITY / 4`), and count that refusal in its own counter
   (R101W4-06), so an outbound backlog can neither fill the request rows'
   channel nor their dead-letter share.

**Tests:** the probe, kept: 10 000 refusals through a gated consumer leave at
least the reserve free in the audit channel and every one of 100 subsequent
request rows queued, and write at most one dead-letter line per run; a
reconciliation that meets a full queue writes one abandoned row with the count.
T-445's amendment then says the refusal rows are paced, and T-108's residual
needs no new sentence.

## 3. R101W4-02 — `module_timeout` reaches bash arithmetic

#592 validates `axiam_image` before it reaches `$GITHUB_ENV` (§5). The two other
dispatch inputs go through `env:` to `just conformance-run`
(`fapi-conformance.yml:339-340`): `plan_name` becomes a quoted argument and a
query parameter (`run-plan.sh:67`, harmless — it can add query parameters to a
request to the local suite, nothing more), but `module_timeout` lands in

```bash
deadline=$(( $(date +%s) + ${CONFORMANCE_MODULE_TIMEOUT:-300} ))   # run-plan.sh:120, run-some.sh:83
```

Bash evaluates the expanded text as an arithmetic expression, and an array
subscript inside one is expanded — command substitution included. The probe
`CONFORMANCE_MODULE_TIMEOUT='a[$(echo INJECTED >&2)]'` printed `INJECTED`. So
anyone who may dispatch the workflow runs a command in the job, after the
per-run administrator password was exported to `$GITHUB_ENV`. The blast radius
is small (`permissions: contents: read`; dispatchers can already push a branch),
which is why this is Low, but it is exactly the class #592 closed, and the 1.0.0
CHANGELOG's "closing a template injection for anyone who may dispatch it" is
true only once it is closed too.

**Proposed fix:** validate both remaining inputs in the "Select the AXIAM image"
step (or one before it), with the same fail-before-use shape:
`module_timeout` against `^[0-9]{1,5}$`, `plan_name` against `^[a-z0-9-]{1,128}$`;
and make the two scripts refuse a non-numeric `CONFORMANCE_MODULE_TIMEOUT`
(`[[ ${CONFORMANCE_MODULE_TIMEOUT:-300} =~ ^[0-9]+$ ]] || { echo …; exit 2; }`)
before the arithmetic, so a local run is safe too.

## 4. The §7 rules, against what the wave added

| Rule | Verdict | Evidence |
|---|---|---|
| Every new route carries a limiter from its first commit | **not touched** | the wave adds no route; `PUT /api/v1/ssf/streams/{id}` gained an optional field under its existing governor |
| Every credential-bearing outbound request uses `guarded_fetch_no_redirect` | **not touched** | no outbound HTTP path changed |
| Every refusal of a credential check costs one verify | **not touched** | no credential check changed; T-469 stays Mitigated (§9) |
| Every two-writer registry is written conditionally on the version read | **holds for SSF streams, from the console**; optional for API clients; **not for tenant settings** (pre-existing) | `update_stream` refuses an `expected_updated_at` that is not `old.updated_at` (`ssf_admin.rs:768`) and the repository write is `WHERE updated_at = $expected`; the console always sends the row's `updated_at` (`SsfStreamsPage.tsx:152`). Absent keeps the in-request check (old clients). The tenant settings override (`PUT /settings`, written by tenant and organization administrators) remains last-writer-wins; W4.4 changed its body, not its concurrency |
| Schema: only W1 adds migrations | **holds** | no migration in the diff |
| Contract: W4.5 regenerates the spec in-wave; no `CONTRACT.md` edit | **holds** | `sdks/openapi.json` and the registry regenerated in `11de0b3e3`; `CONTRACT.md` untouched |
| Threat model: nothing enters without its test | **holds** | each of the six amendments names tests that exist and pass (§9, §11) |

## 5. W4.2 — the `axiam_image` validation (#592)

The step holds the pattern in a variable and matches with `[[ =~ ]]`, which bash
compiles as a POSIX ERE without `REG_NEWLINE`, so `$` anchors at the end of the
whole value and the bracket expressions admit no newline. Probed under bash in
the `C` and `C.UTF-8` locales (the runner's): a digest reference and a
`repo:tag@sha256:` reference are accepted; a trailing or leading injected line
(`…\nBASH_ENV=…`, `BASH_ENV=…\n…`), a trailing `\n` or `\r`, a `::stop-commands::`
prefix, a `-v/etc:/x` value, a short digest, uppercase hex, `é` and a fullwidth
`ｘ` are refused; a 100 000-character name is accepted (the pattern has no length
bound, which is harmless: it reaches only the Compose file's `image:` and
`docker` refuses it). `--help@sha256:…` and `../../x@sha256:…` match the pattern
but are not references any registry serves, and the value never reaches an
argument vector (Compose interpolates it into `image:`), so neither is a bypass.
A refused value is echoed `%q`-escaped on one line, and the report step reads the
step's verdict (`AXIAM_TARGET`) instead of the raw input, so "(digest-pinned)" is
printed only for a value that matched. **Verdict: no bypass; the sibling inputs
are R101W4-02.**

## 6. W4.3 — the unattended baseline and the gate (#593)

* **Fail-closed:** an unreadable or non-JSON baseline of either kind exits 1;
  `read_unattended` refuses a `plans` that is not an object and a `waiting` that
  is not a list of strings; a main baseline that is valid JSON of the wrong shape
  crashes the gate (a traceback, exit 1 — red); a plan the main baseline names
  and the unattended baseline omits gets `parked = set()`, so every `WAITING` in
  it is red (probed). `--record-unattended` refuses a run with no result file
  and a plan in which no module `PASSED`. The one tolerant path predates the
  file and is documented: a `--plan` the main baseline does not name is checked
  for outright failures only, `WAITING` included (probed: a plan `q` with a
  `WAITING` module is green). The workflow passes the three FAPI plans, all in
  both baselines.
* **The recorded baseline.** The three lists are subsets of each plan's
  `baseline.json` modules; the mTLS and self-signed lists are identical (27 each;
  the `private_key_jwt` list has 40); against the seed they drop six (seven)
  modules and add one, `…par-ensure-jwt-client-assertions-nbf-8-seconds-in-the-future-is-accepted`,
  which is why recording run 38317560409 ended `failure` (verified with
  `gh run view`: head `31ca68717`, conclusion `failure`); confirmation run
  38327426158 on `b34a0d0fb` ended `success` (verified). Its artifact and its job
  log are not reachable from here either (the blob store answers 403), so the
  transcription could not be re-derived with `--record-unattended`; the green
  confirmation shows nothing parks outside the lists, not that every listed
  module still parks — R101W4-10.

## 7. W4.6 and W4.7 — the dead letter (#594, #595)

* **Off the worker.** `write_audit_with_dead_letter` awaits `append_off_thread`
  (`spawn_blocking` around `append_blocking`); the blocking task runs to
  completion if its awaiter is dropped. The failure semantics are unchanged: the
  function returns `()`, logs, and the handler's response does not depend on the
  dead letter. What did change is that the second sink now follows an `await` —
  R101W4-04.
* **One write per line.** `append_blocking` writes the line and its newline with
  one `write_all` on an `O_APPEND` descriptor; the writer task writes a batch of
  at most 64 bounded lines (~64 KB) with one `write_all` on a tokio `File`, whose
  buffer in tokio 1.53.1 is 2 MiB (`DEFAULT_MAX_BUF_SIZE`), so a batch is one
  `write(2)` and the two writers' appends cannot interleave inside a line. (Had
  the buffer been tokio's older 16 KiB the claim would have failed for a full
  batch; it is worth a comment beside `BATCH`.)
* **Mode.** Both openers pass `mode(0o600)` (umask can only narrow it); an
  existing file with any group/other bit is `fchmod`ed to `0600` at open, and a
  failure (a file owned by another user) is a `WARN` and the record is written.
  Tested for all three openers and for an existing world-readable file.
* **Sync.** `sync_data` after each GDPR record and after each batch the writer
  task writes, before it counts the batch written. The directory entry is not
  synced, which the docs and T-108 say.
* **The budget.** `append_blocking` and the writer both count the line as
  written, envelope included; the reserve arithmetic is unchanged. The path and
  budget for a GDPR record are read once, when `DeadLetterTarget::from_env()`
  builds the target for that record — per record, not once per process, which
  T-108's amendment says correctly ("read once per record"); the plan's "once at
  construction" was not followed literally, and nothing depends on it.
* **Envelope.** `{"occurred_at","reason","entry"}`; `occurred_at` is captured
  when the response finished (`middleware.rs`, before the row is queued, carried
  through the channel beside the entry) and, for a GDPR record, on entry to
  `write_audit_with_dead_letter` — after the action, before the datastore write
  that may be refused; `try_record` stamps the refusal's time. `reason` is a
  closed `enum` serialized as `channel_full` / `channel_closed` /
  `datastore_error`; the error text goes to the log and never to the line
  (`the_reason_is_a_short_name_and_never_the_errors_text`). The decoder is an
  untagged enum that tries the envelope first (it needs `occurred_at` and
  `entry`, which a bare entry lacks) and falls back to the bare form; a malformed
  envelope does not silently decode as a bare entry (it has no `tenant_id`).
* **The recipe in lock-step.** `the_replay_recipe_in_the_docs_restores_dead_lettered_rows`
  extracts the filter from `docs/deployment/README.md` itself, runs it with `jq`
  over enveloped and bare lines, executes the statements against the schema and
  compares every field, `metadata.occurred_at` and `metadata.dead_lettered_reason`
  included; it fails rather than skips in CI when `jq` is missing. The recipe
  merges the two fields into an object `metadata` and wraps a non-object one as
  `original_metadata`, so no row shape is lost.

## 8. W4.9 — the two budgets, the bounded join and the REST cut (#598)

* **Arithmetic.** `ORDERLY_STOP` = 20 + 5 + 2 + 5 + 5 = 37 s <
  `FATAL_STOP_BACKSTOP` = 38 s < `SHIPPED_STOP_GRACE_PERIOD` = 40 s;
  `LEASE_LOSS_STOP` = 5 + 2 + 1 + 3 + 2 = 13 s < 15 s; the lease's REST cut
  (5 s) < actix's 20 s; both outbound bounds > `IN_FLIGHT_STOP_GRACE`; actix's
  timeout is whole seconds. All are `const _: () = assert!(…)` and the crate
  builds (§11). The lease's REST share is 5 s, not the plan's 6, because the
  cleanup join (2 s) is now on that path: 6 + 2 + 1 + 3 + 2 = 14 would still fit,
  5 leaves 2 s of margin — the file's choice, correctly reasoned.
* **What the budgets do not cover:** the lease release on the `SIGTERM` path
  (`boot.rs:3274-3283`), an unbounded datastore call with conflict retries,
  sits between the gRPC stop and the outbound drain — R101W4-08.
* **The REST cut.** On a lost lease the teardown `select!`s the server future
  against the cut and, at the cut, drops it (`boot.rs:3234-3248`). In
  `actix-server` 2.9.7 the graceful `Stop` the lease task sent earlier is being
  handled inside the server future (`handle_cmd` awaits the workers' graceful
  stop and only then takes `accept_handle`), so at the drop `ServerInner::drop`
  finds `accept_handle` still set, sends every worker `stop(false)` and joins the
  acceptor thread. A worker in its graceful-shutdown state polls its stop channel
  first on every wake and answers a forced stop with `shutdown(true)` and
  `Poll::Ready`, which drops its arbiter and with it every connection task — the
  requests are cut and their sockets closed. No leak (the worker threads end, the
  acceptor is joined) and no double stop (the spawned `handle.stop(true)` future
  ends when its completion sender is dropped; a later fatal-stop command finds a
  closed channel). The drop blocks the teardown task for the acceptor's join,
  which has already been told to stop. This is verified in the dependency's
  source; no test drives it (R101W4-08).
* **The cut tick's unresumed states.** (i) An erasure cut between the anonymize
  step (`run_erasure_pipeline_reporting`, `cleanup.rs:1843-1853`) and the
  `gdpr.user_pseudonymized` row (`:1894`) — or before `mark_completed` (`:1859-1872`)
  — is never resumed: the user is no longer due. **Low** (R101W4-03): an erasure
  without its audit record is the accountability gap GDPR Art. 5(2) and T-108
  exist for; the erasure proof stands. (ii) An export cut between `set_ready` and
  its mail: a download nobody was told about, which expires in 24 h and can be
  requested again. **Informational**, recorded in T-444. (iii) After a lost
  lease, a request cut 5 s in whose write had committed has no audit row.
  **Informational**: before #598 the same request ran into the 15 s backstop and
  the process exit, which also lost the whole audit queue; the cut is strictly
  better, and it is documented.
* **"A lease lost after a `SIGTERM` drain may end up to 2 s early."** The budget
  is chosen once, from `lease_lost` as it reads when the REST listener returns;
  a loss later leaves the `ORDERLY_STOP` bounds for 5 + 2 + 5 + 5 = 17 s of steps
  under a 15 s backstop. A loss *during* the `SIGTERM` REST drain is handled
  (the cut fires, and the budget read afterwards is `LEASE_LOSS_STOP`).
  The 2 s edge costs at most the end of the cleanup join or of the audit drain,
  the exit is non-zero either way, and it is documented. **Informational, accepted.**

## 9. Threat-model text against the code

| Entry / text | Verdict | Note |
|---|---|---|
| W4.1: "with no exception" (`threat-modeling-and-security.md:3111`, `website/src/security.ts:639`) | **holds** | both read "That holds for the ten open at High or Critical severity … with no exception: T-102 and T-108 … are mitigated"; STRIDE `:4542` names the four former exceptions as closed |
| W4.1: T-469 | **holds** | Mitigated in `Axiam.json`, STRIDE (`:485`, `:773`) and `threatModel.ts`; the orchestrator's claim is correct |
| T-406 (correction, #590) | **matches** | the client version, the console's refusal, "`[]` is none, absent is all" — all in the code; tests exist and pass |
| T-108 (two amendments, #594, #595) | **matches** | off-thread, `0600`, tightening, sync, envelope, `occurred_at` capture points, closed reasons, recipe; its correction of the 2.40.0 "two calls" sentence is right (one `write_all`, §7) |
| T-445 (amendment, #596) | **matches the mechanism; omits the cost** | "the producer waits on nothing … one row per refusal is kept … when that channel is full the row is counted as a lost audit row" — all true, and the reason the channel is full can be the refusals themselves (R101W4-01) |
| T-444 (amendment, #598) | **matches** | the two budgets, the cut, what each stop can cut and by how much, the 2 s edge; it calls the erasure state "the audit row is never written", which is the R101W4-03 gap stated, not resolved |
| Counts | **consistent** | 475 = 437 / 17 / 21 in `Axiam.json` (script count), STRIDE header and the generated files; `node website/scripts/gen-threat-model.mjs` leaves no diff |
| Model version | **unchanged at 2.40.0** although six amendments entered | statuses did not change, so nothing is wrong today; W7.3's reconciliation should bump it and add the wave to the history paragraph |

## 10. Documentation and CHANGELOG claims

| Claim (where) | Verdict | Evidence |
|---|---|---|
| The image input is refused unless `repo[:tag]@sha256:<64 hex>` (workflow, runbook, write-up correction) | **true** | §5 |
| "closing a template injection for anyone who may dispatch it" (1.0.0 CHANGELOG, carried) | **still partly false** | R101W4-02 |
| Green covers the modules that complete unattended (runbook) | **true for the three gated plans** | §6 |
| A tenant save sends a switch only when changed or carried (CHANGELOG, `settings.ts`) | **true** | `surfaceOverride` (`SettingsPage.tsx:233`); R101W4-07 for the feedback |
| The SSF page never widens a receiver's narrowing (T-406, field docs) | **true for the console** | `emptiesNarrowing` (`SsfStreamsPage.tsx:108`); `[]` is sent only when the stored narrowing was `[]`; R101W4-11 for API clients |
| The dead-letter file is durable and owner-only (`dead_letter.rs`, deployment guide, T-108) | **true, with the directory-entry caveat stated** | §7 |
| "the request path does no file I/O" for the GDPR records (T-108, guide) | **true** | §7 |
| A line carries when and why; the recipe carries both (CHANGELOG, guide) | **true** | §7 |
| A refused enqueue never waits on the datastore on the caller's path (CHANGELOG, guide, T-445) | **true**, and incomplete | R101W4-01 |
| The `SIGTERM` stop adds up to 37 s; the backstop is 38 s (CHANGELOG, guide, T-444) | **true for the steps named** | the lease release is not one of them (R101W4-08) |
| Compose / k8s comments, *Operate* page | **stale** | R101W4-09 |
| `[Unreleased]` covers the wave | **incomplete** | no line for #590 or #594 — R101W4-05 |

## 11. Checks run

Each command with its own exit code (logs in the scratchpad; no `cargo clean`,
per the brief).

| Check | Result |
|---|---|
| `cargo test -p axiam-audit --tests` | pass (22 + 1 + 19 + 31) |
| `cargo test -p axiam-amqp --lib -- outbound::inprocess` (with the §2 probe added, then removed) | pass (21: the 20 in-process tests and the probe) |
| `cargo test -p axiam-api-rest --no-default-features --test ssf_test --test gdpr_audit_dlq_test` | pass (60, 4); `jq` present, so the README recipe was exercised |
| `cargo test -p axiam-server --no-default-features --test minimal_profile_boot`, then `--lib -- profile` | pass (9, including `a_cleanup_tick_that_sleeps_past_the_bound_does_not_delay_the_exit_past_the_grace`; 17); the crate builds, so every `const _` assert of §8 holds |
| `target/debug/axiam-server --dump-openapi` (the `--no-default-features` binary the tests built) compared with `sdks/openapi.json` | **byte-identical** (989 137 bytes) |
| `python3 scripts/check-spec-digest.py` | pass (`sha256:2de3fba4…`) |
| `python3 scripts/gen-management-registry.py --check` | pass (190 operations, 28 namespaces) |
| `python3 scripts/check-crate-layering.py` | pass |
| `python3 -m unittest discover -s conformance/scripts -p 'test_*.py'` | pass (29) |
| gate fail-closed probes (list-shaped baseline; unlisted `WAITING`; plan outside the baseline) | exit 1; red; green (the documented exception) |
| `npx vitest --run` `SettingsPage.test.tsx`, `SsfStreamsPage.test.tsx`, `surfaceSwitches.test.tsx` | pass (3 files, 88 tests) |
| `npx tsc -b`, `npm run lint` (oxlint) in `frontend/` | pass, no warnings |
| `node website/scripts/gen-threat-model.mjs` | no diff; 475 (437 / 17 / 21) |
| bash regex probe (§5), arithmetic-injection probe (§3) | as reported |
| `gh run view 38317560409`, `gh run view 38327426158` | `failure` at `31ca68717`; `success` at `b34a0d0fb` |
| Commit signatures | 9 of 9 carry `gpgsig` |

## 12. Issue bodies

### R101W4-01 (Medium) — refused-enqueue rows crowd the request-audit channel

Since #596 a refused in-process enqueue hands its `<kind>.delivery_abandoned` row
to `AuditMiddleware::try_record` (`crates/axiam-amqp/src/outbound/inprocess.rs:192`,
`crates/axiam-audit/src/middleware.rs:253`) — the request rows' 4 096-slot
channel — instead of awaiting a datastore append. SCIM reconciliation enqueues
one reference per in-scope user with `try_send` against a 1 024-slot queue and
carries on after a refusal (`crates/axiam-scim/src/outbound/reconcile.rs:524-552`),
so in the minimal profile a tenant above ~5 000 in-scope users fills the audit
channel at every nightly run and every `POST /api/v1/scim-targets/{id}/reconcile`:
a probe made 10 000 refusals in 87 ms; they filled the channel (5 904 more were dropped) and the channel then dropped 100 of 100 request rows. While it is full, request rows of every tenant are dropped
(T-108), and every dropped row — refusals included — is a dead-letter line,
spending the file's request share until request-row loss is
`not_recoverable`. Before #596 the loop was paced by the awaited writes and
nothing was dropped.
**Proposed fix:** (1) the bulk producers (`reconcile.rs` `queue_again`,
`provisioner.rs:106-112`, `deliverer.rs:935-944`) stop at the first
`OutboundError::Enqueue` of a run, count the rest in `enqueue_failed` and record
one abandoned row for the run with `refused_count`; (2) `try_record` keeps a
headroom for request rows — it refuses without offering the row to the
dead-letter file when `tx.capacity()` is below a reserve (e.g.
`CHANNEL_CAPACITY / 4`) and counts that in its own counter (R101W4-06).
**Tests:** 10 000 refusals through a gated consumer leave the reserve free and
100 subsequent request rows queued, with at most one dead-letter line; a
reconciliation that meets a full queue writes one abandoned row with the count;
the existing one-row-per-refusal tests stand. T-445's amendment says the rows are
paced.

### R101W4-02 (Low) — the conformance workflow's `module_timeout` input reaches bash arithmetic

`module_timeout` goes through `env:` (`.github/workflows/fapi-conformance.yml:340`)
to `deadline=$(( $(date +%s) + ${CONFORMANCE_MODULE_TIMEOUT:-300} ))`
(`conformance/scripts/run-plan.sh:120`, `run-some.sh:83`). Bash evaluates an
array subscript inside an arithmetic expression, command substitution included:
`a[$(echo INJECTED >&2)]` prints `INJECTED`. Anyone who may dispatch runs a
command in the job (after the per-run admin password reached `$GITHUB_ENV`).
`permissions: contents: read` bounds it. This is the class #592 closed for
`axiam_image`. **Proposed fix:** validate `module_timeout` (`^[0-9]{1,5}$`) and
`plan_name` (`^[a-z0-9-]{1,128}$`) before use in the workflow, failing the job
otherwise, and refuse a non-numeric value in both scripts before the arithmetic.

### R101W4-03 (Low) — a cut erasure loses its audit row for good

`join_cleanup` (`crates/axiam-server/src/boot.rs:3431`) aborts the cleanup task at
its bound (5 s after the audit drain for `SIGTERM`, 2 s after a lost lease). The
task stops between users, but a user's pipeline in progress is cut at the await
it is in. Cut after `run_erasure_pipeline_reporting`
(`crates/axiam-server/src/cleanup.rs:1843-1853`, which anonymizes the user and
clears `deletion_pending`) and before `write_audit_with_dead_letter(…
"gdpr.user_pseudonymized" …)` (`:1894`), the erasure stands without its audit row,
and the `account_deletion` row may stay pending (`:1859-1872`); nothing writes
either later, because the user is no longer due. T-444 records it; nothing
resolves it. **Proposed fix:** run each user's purge from the erasure pipeline to
the audit row as its own task (`tokio::spawn`), which aborting the cleanup task
does not cancel, and let `join_cleanup` wait for the one in flight within the
stop's margin; or persist an "audit pending" marker in the same write that
anonymizes, and have the next tick write the row and complete the deletion.
**Test:** a tick held between the anonymization and the audit row across a stop
still leaves the `gdpr.user_pseudonymized` row (or the next start writes it).

### R101W4-04 (Low) — the GDPR dead letter's structured event can be skipped

`dead_letter_audit` (`crates/axiam-api-rest/src/handlers/gdpr.rs:205-257`) now
awaits `append_off_thread` (`:229`) before it emits the `axiam.audit.dlq` event
(`:250`). The file write runs to completion if the future is dropped, but the
event does not fire. Since #598 the future can be dropped there: the cleanup
task's bounded join aborts the erasure's `gdpr.user_pseudonymized` write, and the
lease-loss cut drops request handlers. The two sinks were meant to be
independent (SECHRD-12). **Proposed fix:** emit the structured event before the
file append (it does not depend on the file's result; log the file's own
failure separately), or spawn the whole `dead_letter_audit` so no drop reaches
it. **Test:** a dead letter whose awaiting future is dropped during the file
write still logs the event.

### R101W4-05 (Low) — `[Unreleased]` misses #590 and #594

`CHANGELOG.md`'s `[Unreleased]` has lines for #600, #595, #596 and #598 only. #590
adds an optional request field (`SsfStreamInput.expected_updated_at`, a `409`
when stale) and changes the console (a save that would empty the receiver's
narrowing is refused). #594 changes what an operator sees: the dead-letter file
is created `0600` and an existing one is tightened at open — a log shipper or
sidecar reading it as another user loses access — and its records are synced.
**Proposed fix:** one `### Added` / `### Changed` line each; #592 and #593
(CI-only) may stay out, as they did in 1.0.0's notes, or get one line together.

### R101W4-06 (Low) — `request_audit.dropped` no longer counts only request rows

`try_record`'s refusals go through `offer` and `RequestAuditLoss::record_dropped`
(`crates/axiam-audit/src/middleware.rs:253, 344`), so `GET /health/jobs`
`request_audit.dropped` and the `channel_full` dead-letter lines mix request rows
with outbound refusal rows, and an operator cannot tell a request-audit outage
from an outbound backlog. **Proposed fix:** count `try_record` refusals in their
own counter (`outbound_abandoned_dropped`) and report it beside `dropped`;
part of R101W4-01's fix.

### R101W4-07 (Informational) — turning a surface back on under an organization `false` saves silently

`surfaceOverride` (`frontend/src/pages/settings/SettingsPage.tsx:233`) omits a
switch the administrator turned on. With the organization off and the tenant's
own override `false`, ticking the switch (it is enabled, the layer reads
"tenant") now saves with `200` and "Settings saved successfully", the tenant's
`false` is dropped, and after the refetch the switch is off and locked
("Disabled by the organization"). Before #600 the page sent `true` and the server
answered `400` naming the field. Not a fail-open: the surface stays off while the
organization has it off, and follows the organization afterwards, which is what
the administrator asked for. **Proposed fix:** after a save that turned a switch
on, when the refetched effective value is still `false`, say "saved — the
organization has this surface off; it stays off until an organization
administrator turns it on".

### R101W4-08 (Informational) — the lease release is outside the stop budget; the REST cut is untested

The `SIGTERM` teardown releases the minimal-profile lease with an unbounded
datastore call under conflict retries (`crates/axiam-server/src/boot.rs:3274-3283`),
after the gRPC stop and before the cleanup task is told to stop (`:3290`). A
datastore that hangs at stop holds the teardown there, outside `ORDERLY_STOP`'s
checked 37 s, and the cleanup task keeps starting sweeps meanwhile; a `SIGTERM`
stop has no backstop, so the orchestrator's `SIGKILL` ends it. Separately, the
lease-loss REST cut (dropping the actix `Server`) is correct in `actix-server`
2.9.7's source but no test drives it: `a_lost_lease_cuts_the_requests_in_flight_before_the_backstop`
checks the callback's timing only. **Proposed fix:** signal the cleanup task
before the release and bound the release (1 s, inside the margin); add a
`minimal_profile_boot.rs` case where a handler sleeps past the cut and the
client's connection is closed at about 5 s while the audit drain still runs.

### R101W4-09 (Informational) — stale stop arithmetic outside the guide

`docker/docker-compose.minimal.yml:193` ("40 s: 20 + 5 + 2 + 5 and a margin"),
`docker/docker-compose.prod.yml:318-321` and `k8s/server/deployment.yml:21-23`
("20 s … 5 s for gRPC and 5 s for the audit queue") omit the outbound and
cleanup steps, and `website/src/docs/operate.ts:122` lists four steps and says a
lost lease drains the audit queue for up to 5 s (3 s now). **Proposed fix:** one
sentence each pointing at `ORDERLY_STOP` / `LEASE_LOSS_STOP` and the guide's
"What a stop can cut"; W7.3 can take it.

### R101W4-10 (Informational) — the unattended baseline's provenance and the gate's one tolerant path

`conformance/baseline-unattended.json` was transcribed from run 38317560409's
gate log because its artifact could not be fetched; it is internally consistent
and confirmation run 38327426158 is green, which shows nothing parks outside
the lists but not that every listed module still parks. Separately, `gate.py`
tolerates every `WAITING` for a `--plan` the main baseline does not name
(documented). **Proposed fix:** at the next dispatch, run
`gate.py --record-unattended` over the artifact and commit the diff (expected
empty); make the gate refuse a `--plan` absent from `baseline.json` unless a flag
says it is new.

### R101W4-11 (Informational) — API clients can still widen a narrowing

`check_input` (`crates/axiam-api-rest/src/handlers/ssf_admin.rs:342-351`) reads an
absent `events_requested` as every allowed event, on update as on create; the
field's doc and T-406 say so, and the console no longer omits it. An API client
or SDK helper that builds a replacement without it still resets the receiver's
narrowing. **Proposed fix (W5):** the SDKs' stream-update helpers send the
`events_requested` and `updated_at` they read; `CONTRACT.md` §32 says absent
resets.

## 13. Invariants

* **Nothing registered today changes behaviour silently**, with two exceptions
  an upgrader must read and the CHANGELOG does not yet say (R101W4-05): the
  dead-letter file's mode and the SSF `409` for a stale client version (opt-in:
  absent keeps the old behaviour). Additive: `expected_updated_at` (optional),
  the envelope (the recipe reads both forms), `ShutdownBudget`.
* **Append-only audit**: nothing in the wave updates or deletes an audit row; the
  replay recipe writes new rows, and the replayed row's `timestamp` is still the
  replay's.
* **No credential, secret or error text reaches a dead-letter line**: `reason` is
  a closed set; the error goes to the log.
* **Fail-closed where it matters**: the gate on its inputs; the settings page on
  an unreadable override (an effective `false` is still sent); the SSF page on an
  emptying edit.
* **Crate layering, spec digest, management registry**: pass.
* **Threat model**: 475 threats, 437 / 17 / 21, consistent across `Axiam.json`,
  STRIDE, the write-up and the generated website files; version 2.40.0 left for
  W7.3; T-445 and T-108 are what R101W4-01 keeps from holding fully.
