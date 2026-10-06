# Audit durability in the minimal profile — review against T19.27

*T23.8.2 (Phase 23, W5, G-8), 2026-10-05. Reviewer: an Opus 5.5 executor.
Subject: branch `claude/phase23-w5` at `805c551` (T23.8.1 landed: `b870dbb`,
`216e05c`, `7d18c5b`, `9baeacc`, `d79f81e`, `dd4b1a1`, `4370cb7`, `a52be02`).
Fixes: `fe75e1b`, `d28c618`.*

## 1. Scope

Every path by which an audit record is written, or should be written, when
`AXIAM__AMQP__ENABLED=false` (the *minimal profile*, D-59), judged against two
standards:

* **T19.27** ([`roadmap.md`](roadmap.md), "GDPR audit durability (DLQ
  fallback)"): a legally significant GDPR record whose datastore write fails is
  not lost to a log line. Built as `write_erasure_audit_with_dlq` /
  `dead_letter_erasure_audit` in `crates/axiam-api-rest/src/handlers/gdpr.rs`
  (an append-only file named by `AXIAM__GDPR_AUDIT_DLQ_FILE`, plus the
  structured `axiam.audit.dlq` event), called by tenant deletion
  (`handlers/tenants.rs`) and the GDPR purge (`crates/axiam-server/src/cleanup.rs`).
* **§4 G-8's "T19.27 must not regress"**: nothing that was durable in the full
  profile may become silently lossy in the minimal one without being a recorded
  trade.

The seven paths the brief names, in its order: the audit middleware; the
in-process outbound dispatcher; the in-process mail worker and the GDPR export
notice; external services' audit events (`axiam.audit.events`); the GDPR
erasure audit itself; the SCIM `NotifyingAuditLog` and the SSF/SCIM dead-letter
rows; and the singleton lease.

## 2. Method

* Read T23.8.1's eight commits in full, the composition root it moved into
  `crates/axiam-server/src/boot.rs` (with `profile.rs` and `messaging.rs`), the
  audit middleware, the outbound outcome table and both transports, the mail
  consumer and its in-process twin, the audit-ingestion consumer, the GDPR
  handlers and the cleanup task.
* For every audit write, asked: *who writes it, through what, and what happens
  to it if the process stops, the datastore fails, or a queue is full — in the
  full profile and in the minimal one?* A difference is a regression unless D-59
  records it as the profile's trade.
* Checked the refactor of the AMQP outbound loop (`216e05c`) line by line
  against the code it replaced, since a "no behaviour change" refactor is where
  an audit row most easily goes missing.
* Checked what an operator is told (boot log, `/health`, the deployment docs,
  the configuration coverage table) and what ships in the compose files and
  Kubernetes manifests.
* Wrote a failing test before each fix; ran the existing T19.27 test
  (`gdpr_audit_dlq_test`) and the audit crate's suite.

## 3. Summary

| Id | Path | Verdict | Disposition |
|---|---|---|---|
| P23W5-A1 | 7. Singleton lease | **Regresses** | Fixed (`d28c618`, `fe75e1b`) |
| P23W5-A2 | 1. Orderly stop (both profiles) | Pre-existing gap | Closed by the A1 fix |
| P23W5-A3 | 1. Audit middleware | Holds | Residual: drop-on-full and warn-only append are pre-existing (A10) |
| P23W5-A4 | 2. In-process dispatcher | Holds | Residual: no terminal row for a delivery lost at stop or refused at enqueue (D-59's trade) — issue |
| P23W5-A5 | 3. Mail and the GDPR export notice | Holds | Residual: a lost `ExportReady` mail strands a ready export — docs |
| P23W5-A6 | 4. External audit ingestion | Holds (refused loudly) | Residual: producers can still publish into a broker nobody reads — docs, issue |
| P23W5-A7 | 5. GDPR erasure audit | Holds | Pre-existing: the DLQ file is provisioned nowhere — issue |
| P23W5-A8 | 5. GDPR request audit | Pre-existing gap | T19.27's own scope (`append_gdpr_audit`) is unmet — issue |
| P23W5-A9 | 6. SCIM/SSF dead-letter rows | Holds | Residual: T-405's "once queued, at-least-once" is false here — T-405 amended |
| P23W5-A10 | 1. Threat model | Pre-existing gap | T-108 describes controls that do not exist — reopened |
| P23W5-A11 | 7. gRPC listener at stop | Pre-existing gap | Issue |
| P23W5-A12 | Full profile's abrupt exits | Pre-existing gap | Issue (same hazard as A1) |

One regression, fixed. T19.27 itself — `write_erasure_audit_with_dlq` and its
two callers — is untouched by T23.8.1 and holds in both profiles.

## 4. Findings

### P23W5-A1 — A lost lease ended the process with the audit queue unwritten — **regresses, fixed**

**Evidence (before the fix).** `crates/axiam-server/src/profile.rs`
`exit_on_lease_lost` was `Arc::new(|| std::process::exit(1))`, called from the
renewal task the moment a renewal found the lease taken. `std::process::exit`
runs no destructor and waits for nothing, so the process ended wherever it was:

* every entry the audit middleware had queued (`CHANNEL_CAPACITY` 4 096) but
  not yet appended — rows whose responses had already gone out;
* a request between its datastore write and its audit write (tenant deletion
  writes `tenants.deleted` after `tenant_repo.delete`);
* a GDPR purge between the anonymisation and `gdpr.user_pseudonymized` — the
  record T19.27 exists to keep, lost without even the `axiam.audit.dlq` line,
  because the dead-letter path only runs on a *failed* write.

The correlation makes it worse than a random crash: a lease is taken over only
after its holder failed to renew for 30 s, which in practice means the holder
could not reach the datastore — exactly when the middleware's queue fills. The
moment the datastore returned, the renewal saw the lease gone and exited before
the worker could write the backlog. The full profile has no such trigger: an
instance that lost the datastore keeps running and drains when it returns.

**Fix.** The renewal task now only raises a flag (`signal_on_lease_lost`). The
composition root waits on it (`spawn_lease_loss_stop`, `boot.rs`) and stops
through the same path as SIGTERM: the REST listener stops accepting and finishes
what is in flight; the cleanup task finishes the tick it is in, so an erasure
and its row stay together; the audit middleware is **drained**
(`AuditMiddleware::drain`, a FIFO barrier bounded at 5 s, `fe75e1b`); then
`serve` returns an error naming the lease, which is `main`'s non-zero exit.
D-59's "exits non-zero rather than run beside another" holds — it now exits
after its in-flight work rather than in the middle of it. The old exit remains
as a **backstop** (`ServeOptions::lease_lost_backstop`) that runs only if the
orderly stop overruns `LeaseTiming::lost_stop_deadline` (15 s in production; the
REST listener's 5 s idle keep-alive and the 5 s drain fit inside it). For that
long at most the instance runs beside the new holder, accepting no new
connection — it had already done so for up to one renewal period (10 s) before
noticing.

**Tests.** `crates/axiam-server/tests/minimal_profile_boot.rs`
`an_instance_that_loses_its_lease_stops_in_order_and_keeps_its_audit_rows`
(boots the real composition root, audits twenty requests, hands the lease to
another holder in the datastore; asserts that `serve` returns an error naming
the lease, that the backstop did not run, that all twenty rows are in the trail,
and that the other holder's lease was left alone) — it **failed first**: the
instance never stopped. `crates/axiam-server/src/profile.rs`
`the_renewal_reaction_only_raises_the_flag`,
`a_lost_lease_starts_the_orderly_stop_at_once_and_the_backstop_only_after_the_deadline`,
`an_orderly_stop_that_finishes_in_time_disarms_the_backstop`,
`a_flag_raised_before_the_watch_starts_still_stops`,
`a_lease_never_lost_never_stops`. `crates/axiam-audit/tests/service_and_middleware.rs`
`drain_returns_once_every_queued_entry_is_written` (failed first against the
flag-only teardown), `drain_is_bounded_when_the_datastore_does_not_answer`,
`drain_of_a_dead_worker_reports_failure_at_once`.

**Residual.** A `SIGKILL`, an OOM kill or the backstop still lose what is queued;
so does a datastore that stays down past the drain's bound (each failed append
is a `WARN`, as before — A10). The gRPC listener is not part of the orderly stop
(A11).

### P23W5-A2 — The orderly stop never waited for the audit queue — **pre-existing gap, closed by the A1 fix**

**Evidence.** `boot.rs` called `audit_shutdown.begin_shutdown()`, which only
sets the flag that changes what the worker *logs* when its channel closes
(`crates/axiam-audit/src/middleware.rs`). Nothing awaited the worker, the
`audit_shutdown` handle itself kept a sender alive until `serve` returned, and
`main`'s return then dropped the runtime and the worker with it. So on every
SIGTERM, in both profiles, entries still queued were lost — and the `audit
worker drained and stopped` line the code documents could practically never be
logged. **Disposition.** The A1 fix replaces `begin_shutdown` in the teardown
with `drain`, so every orderly stop now writes the queue (bounded). Recorded here
because it changes the full profile too: a SIGTERM now waits up to 5 s more.

### P23W5-A3 — The audit middleware path — **holds**

Nothing that was durable is newly routed through the middleware's bounded
channel or through any new in-process channel: AXIAM's own events never touched
AMQP (D-59; confirmed — the server never publishes an `AuditEventMessage`, only
`audit_consumer.rs` reads one). The one new coupling is the notification sink,
which the worker calls after each append and which, in the minimal profile,
publishes to the in-process mail channel: `InProcessMailPublisher::publish` is
`try_send` (`crates/axiam-amqp/src/mail_inprocess.rs`), so a full mail queue
cannot block the audit worker and back the audit channel up into drops. The
middleware's own behaviour — drop with an `ERROR` when its 4 096 slots are full,
`WARN` and move on when an append fails — is unchanged and the same in both
profiles; it is pre-existing and is what A10 is about.

### P23W5-A4 — The in-process outbound dispatcher — **holds** (residual: D-59's trade)

**Same vocabulary, same writer.** `216e05c` moved the outcome table out of the
AMQP loop into `crates/axiam-amqp/src/outbound/outcome.rs` (`decide`,
`classify`, `audit_entry`, `failed_entry`), and both the AMQP loop
(`outbound/consumer.rs`) and the in-process one (`outbound/inprocess.rs`
`process_message`) call it. The diff of the AMQP loop is behaviour-preserving:
the same three actions (`<slug>.delivery_succeeded`, `.delivery_attempt`,
`.delivery_failed`), the same metadata keys, the system actor with a nil id, the
same "record, then settle" order. Both transports write through the same
`AuditLogRepository::append` (`OwnedAuditSink`), and `messaging.rs`
`OutboundTransport::spawn_consumer` hands each kind the same audit repository in
both profiles — `NotifyingAuditLog` for SCIM, the plain repository for the rest
(`boot.rs`). The shared table (`outcome::table`) is asserted by both transports'
tests.

**A retry pending at stop.** The in-process consumer schedules the sleeping
re-dispatch *then* writes `.delivery_attempt`, before it takes the next message,
so the attempt row is written; the retry itself sleeps in a task and is lost
with the process (D-59). What is lost is the **terminal** row: the trail shows
`.delivery_attempt` with `next_retry_in_ms` and nothing after it. A message
queued but never attempted leaves no row at all, and an enqueue refused because
the 1 024-slot queue is full leaves a log line only (every producer — webhook,
SSF, SCIM, CIBA ping — logs and swallows). In the full profile neither happens:
the broker holds the message and the next run writes its row. D-59 records the
loss of the *messages*; it is silent on the *rows*. Proposed issue below
(A4-issue); it needs a vocabulary decision, so no fix here.

### P23W5-A5 — Mail and the GDPR export notice — **holds** (residual)

The in-process worker calls the very `send_with_retry_and_audit` the AMQP
consumer calls, so the `email.delivery_failed` row (D-16, PII-minimal) is
identical by construction; a retry the worker cannot schedule (1 024 sleeping)
writes the same action with `error_class: retry_capacity_exhausted`. A
configuration or infrastructure error writes no row in either profile (the AMQP
consumer nacks to its DLQ, the worker drops — both with a `WARN`). The cleanup
task's `ExportReady` mail uses the same in-process publisher in the minimal
profile (`boot.rs`, `cleanup_mail_publisher`). **Residual:** the export job is
marked `ready` and the download token exists only hashed; its raw value travels
only in that mail. A mail lost on restart therefore strands a ready export the
subject cannot download, and no row says the notice was never sent (the full
profile would have delivered it from the queue). The subject can ask again; the
docs must say so (§7).

### P23W5-A6 — External services' audit events — **holds** (refused loudly; residual for producers)

The `axiam.audit.events` consumer is not started without the broker (`boot.rs`,
inside `if let (Some(amqp), Some(amqp_signing_key))`), and an operator is told
three ways: a boot `WARN` naming "external audit ingestion" as unavailable,
`/health` `unavailable: [..., "amqp_audit_ingestion", ...]`
(`crates/axiam-core/src/models/deployment.rs`), and the deployment docs' *What it
does not provide* table. **Residual.** There is no other ingestion path — no
REST or gRPC route accepts an external audit event — so a service that relied on
it loses its channel entirely, and the producer is not told:

* with no broker at all, its publish fails — loud, on the producer's side;
* with a broker left running from a previous full-profile deployment, the
  durable `axiam.audit.events` queue still exists, the broker confirms the
  publish, and nothing consumes it; switching back to the full profile later
  replays the backlog into the NEW-4 freshness gate, which dead-letters every
  message older than `AXIAM__AMQP__REPLAY_SKEW_SECS` (300 s by default) to
  `axiam.audit.events.dlq`;
* with a fresh broker that has no such queue, a default-exchange publish to it is
  dropped by RabbitMQ unless the producer set `mandatory`.

In no profile does a publish confirm mean "AXIAM recorded it" — CONTRACT §8
defines no end-to-end acknowledgement — but the minimal profile makes "nobody
consumes" the steady state. CONTRACT §8 says nothing about it (G-8 is "no
contract change"). Docs (§7) and an issue for an informative contract note.

### P23W5-A7 — GDPR erasure audit (T19.27 proper) — **holds**; the file sink is provisioned nowhere (pre-existing)

T23.8.1 did not touch `crates/axiam-api-rest/src/handlers/gdpr.rs` or
`handlers/tenants.rs`; it changed `cleanup.rs` only to give the cleanup task the
profile's mail publisher. The two dead-lettering writes — `tenants.deleted`
(system log) and `gdpr.user_pseudonymized` — are composed identically in both
profiles, and `AXIAM__GDPR_AUDIT_DLQ_FILE` is still read at write time.
`cargo test -p axiam-api-rest --test gdpr_audit_dlq_test` passes.

**Pre-existing gap.** The file sink is an operator opt-in that no shipped
deployment opts into: `AXIAM__GDPR_AUDIT_DLQ_FILE` is in the configuration
coverage script's `EXEMPT` table (so neither the website's configuration page
nor `docs/deployment` mentions it), no compose file sets it, and the Kubernetes
server runs with `readOnlyRootFilesystem: true` and no volume for it. In every
shipped deployment the only dead-letter sink is therefore the structured log
event, which is as durable as the log pipeline. `docker-compose.minimal.yml`
(T23.8.3) should be the first file that sets it, on a named volume (§7).

### P23W5-A8 — T19.27's own scope is not met (pre-existing)

T19.27's text names `append_gdpr_audit` as the fire-and-forget write to fix. It
still is: `gdpr.data_export_requested` and `gdpr.erasure_requested`
(`handlers/gdpr.rs`, both through `append_gdpr_audit`) log an `ERROR` on a
failed write and nothing else. Only the two *completion* records dead-letter.
Profile-independent. Issue below.

### P23W5-A9 — SCIM `NotifyingAuditLog` and the dead-letter rows — **holds** (residual)

`NotifyingAuditLog` (T23.6.3) wraps the SCIM kind's audit repository in both
profiles (`boot.rs`), so a `scim_push.delivery_failed` row reaches the
notification rules either way; in the minimal profile that row is the whole
record of a dead letter (no DLQ — D-59), and the rule's mail goes through the
non-blocking in-process publisher. SSF's `ssf_push.delivery_failed` is written
by the plain repository in both. **Residual.** The SSF outbox releases a held
event and deletes its buffer row "only once its message is durably queued"
(`crates/axiam-oauth2/src/ssf_delivery.rs`); an in-process enqueue is not
durable, so a released event is lost on restart, and T-405's "once queued, push
is at-least-once" holds only in the full profile. T-405 is amended (§6).

### P23W5-A10 — T-108's mitigation describes controls that do not exist (pre-existing)

T-108 ("Action succeeds while its audit write fails", High, *Mitigated*) says:
"audit writes share the transactional path with the action they record where
the datastore allows it, and audit failures are surfaced as errors and raise a
compliance notification rather than being swallowed." No code raises a
notification on an audit-write failure (there is no such event type), the
request middleware writes off the request path and drops on a full queue or a
failed append with a log line, and `append_gdpr_audit` swallows. The two GDPR
completion records are the only audit writes with a fallback. T-108 is reopened
and carried to the W5 F4 review with the issue below (§6).

### P23W5-A11 — The gRPC listener is not part of the orderly stop (pre-existing)

The gRPC server is a spawned task (`boot.rs`, `axiam_api_grpc::server::serve`)
with no shutdown signal: on SIGTERM, and now on a lost lease, it keeps serving
until the runtime ends, and an in-flight call that has written but not yet
audited is dropped with it. Both profiles. Issue below.

### P23W5-A12 — The full profile's abrupt exits (pre-existing)

The full profile ends the process with `std::process::exit(1)` when the AMQP
authorization, audit-ingestion or mail consumer exits, and when the gRPC server
fails (`boot.rs`). Each is the hazard A1 removed from the minimal profile: the
audit queue, in-flight requests and a GDPR purge between its erasure and its row
are lost. The minimal profile composes none of the consumer exits. Issue below.

## 5. Verdict by path

| # | Path (brief) | Verdict |
|---|---|---|
| 1 | Audit middleware | Holds (A3). Nothing durable rerouted; the orderly stop now drains (A2). |
| 2 | In-process dispatcher | Holds: same table, writer and vocabulary (A4). A pending retry's attempt row is written; its terminal row is lost with it — D-59's trade, made explicit. |
| 3 | Mail and export notice | Holds (A5); a lost `ExportReady` mail strands a ready export. |
| 4 | External audit ingestion | Holds: refused loudly (boot log, `/health`, docs). Producers are not told (A6). |
| 5 | GDPR erasure audit | Holds — unchanged by the profile (A7). Pre-existing: the file sink is provisioned nowhere (A7) and T19.27's request records were never covered (A8). |
| 6 | `NotifyingAuditLog`, SSF/SCIM dead letters | Holds (A9). |
| 7 | Singleton lease | **Regressed** (A1) — **fixed**. |

## 6. Threat model (2.33.1 → 2.34.0)

* **T-444** (new, Audit middleware & service, Repudiation, Medium, Mitigated) —
  an instance stops while audit rows are queued or in flight and they are lost.
  A1 and A2.
* **T-445** (new, AXIAM deployment, Repudiation, Medium, Open — accepted, D-59) —
  the minimal profile loses queued deliveries and mail, and the terminal audit
  rows they would have produced, on restart, and has no external audit
  ingestion. A4, A5, A6.
* **T-405** amended: "once queued, push is at-least-once" is the full profile's
  property; in the minimal profile a queued push is lost on restart (T-445). A9.
* **T-108** reopened (Open, carried to the W5 F4 review): its text now describes
  what the code does. A10.

445 threats, 420 mitigated / 25 open.

## 7. What T23.8.3's documentation must say

1. **Stopping.** An orderly stop — SIGTERM, or a lost lease — writes the audit
   rows still queued (up to 5 s) before the process exits; a `SIGKILL` or OOM
   kill does not. Give the container a termination grace period above 20 s
   (Kubernetes' default of 30 s is enough). An instance that loses its lease
   stops accepting at once, finishes in-flight requests and exits non-zero
   within 15 s.
2. **The GDPR dead-letter file.** `docker-compose.minimal.yml` sets
   `AXIAM__GDPR_AUDIT_DLQ_FILE` to a path on a **named volume**, and the
   minimal-profile section documents it: what lands there (a failed write of
   `gdpr.user_pseudonymized` or `tenants.deleted`, one JSON line each), that the
   file is append-only, and that an operator replays it into the trail by hand.
   Collect the container log as well: the `axiam.audit.dlq` event is the second
   sink and the only one when the file is unset.
3. **What a restart loses, in audit terms.** A webhook, SSF, SCIM or CIBA ping
   delivery that is queued or waiting for a retry when the process stops leaves
   at most a `<kind>.delivery_attempt` row and never a terminal one; a delivery
   refused because the queue was full leaves only a log line. Outbound SCIM is
   repaired by the next reconciliation; webhooks, SSF events and CIBA pings are
   not.
4. **GDPR export notice.** An `ExportReady` mail lost on restart cannot be
   re-sent — the download token exists only in that mail — so the subject
   requests a new export.
5. **External audit ingestion.** Before switching a deployment to the minimal
   profile, stop or re-point every service that publishes to
   `axiam.audit.events`: nothing consumes it, a broker left running confirms
   publishes anyway, and returning to the full profile later dead-letters
   everything older than `AXIAM__AMQP__REPLAY_SKEW_SECS`. There is no other
   ingestion route.
6. **SSF.** In the minimal profile a Security Event Token released from the
   outbox to the push queue is lost on restart; receivers must already treat
   signals as hints (T-405).

## 8. Issue bodies (not filed)

**A4-issue — The in-process dispatcher's lost deliveries leave no terminal audit row.**
*Severity:* Low. *Evidence:* `crates/axiam-amqp/src/outbound/inprocess.rs`
(`process_message`, `RetryScheduler::schedule`); every producer's enqueue-error
branch (`webhook.rs`, `ssf_delivery.rs`, `provisioner.rs`, `ciba.rs`) logs only.
*Proposed fix:* at the orderly stop, drain each kind's channel and pending
retries into `<kind>.delivery_failed` rows with a fixed reason
(`dispatcher stopped`), and write the same row when an in-process enqueue is
refused (`in-process queue full`), so the trail never ends at an attempt. Needs
a decision: reuse `delivery_failed` (and its notification mapping — a stop would
then mail SCIM rule recipients) or add `delivery_abandoned`.

**A7-issue — The GDPR audit dead-letter file is configured in no shipped deployment.**
*Severity:* Medium. *Evidence:* `scripts/check-config-key-coverage.py` (`EXEMPT`:
`AXIAM__GDPR_AUDIT_DLQ_FILE`); `docker/docker-compose.prod.yml`;
`k8s/server/deployment.yml` (`readOnlyRootFilesystem: true`, no volume).
*Proposed fix:* document the key on the configuration page and in the
deployment guide (drop the exemption); mount a small volume and set the key in
the production compose file and the Kubernetes manifest; warn at boot when it is
unset; document replay.

**A8-issue — `gdpr.data_export_requested` and `gdpr.erasure_requested` are fire-and-forget (T19.27's stated scope).**
*Severity:* Medium. *Evidence:* `crates/axiam-api-rest/src/handlers/gdpr.rs`
`append_gdpr_audit` and its two callers. *Proposed fix:* route
`append_gdpr_audit` through `write_erasure_audit_with_dlq` (renamed for what it
now is), with a test per action in `gdpr_audit_dlq_test`.

**A10-issue — Request-audit loss is silent: no counter, no notification (T-108).**
*Severity:* Medium (T-108 is High). *Evidence:* `crates/axiam-audit/src/middleware.rs`
(drop on a full channel with an `ERROR`; a failed append with a `WARN`); no
notification event for an audit-write failure. *Proposed fix:* a counter of
dropped and failed request-audit entries surfaced where `/health/jobs` already
reports background health, an operator signal when it moves, and a decision on a dead-letter sink for request rows (the T19.27 file is
the obvious candidate); then re-close T-108 with text that matches.

**A11-issue — The gRPC listener has no orderly stop.**
*Severity:* Low. *Evidence:* `crates/axiam-server/src/boot.rs` (the gRPC task is
spawned with no shutdown signal). *Proposed fix:* pass tonic a shutdown future
tied to the REST listener's stop (`serve_with_incoming_shutdown`), and await the
task in the teardown before the audit drain.

**A12-issue — The full profile still exits mid-flight when a consumer dies.**
*Severity:* Medium. *Evidence:* `crates/axiam-server/src/boot.rs` — four
`std::process::exit(1)` calls (authz consumer, audit-ingestion consumer, mail
consumer, gRPC server). *Proposed fix:* route each through the orderly stop the
lost lease now uses (raise a flag, stop the listener, drain, return an error),
with the same backstop.

**A6-issue — CONTRACT §8 does not say that a minimal-profile server consumes nothing.**
*Severity:* Low. *Evidence:* `sdks/CONTRACT.md` §8. *Proposed fix:* an
informative note in §8 (contract minor bump, fanned out to the seven AMQP SDKs'
READMEs): a server in the minimal profile reads no AMQP queue, and a broker
confirm never means AXIAM recorded an event.
