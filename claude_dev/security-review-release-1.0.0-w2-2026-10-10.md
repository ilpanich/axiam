# Security review — release 1.0.0, wave W2 (F4)

**Date:** 2026-10-10.
**Against:** `claude/release-1.0.0-w2`, the whole wave diff `fe369eb..0a68c5f`
(19 commits, 136 files, about 10 100 lines added and 650 removed; `fe369eb` is
the merge of #587 on `main`). Every commit carries a signature
(`gpgsig` present on all 19; the sandbox has no `allowedSignersFile`, so `%G?`
cannot verify them here).
**Scope:** every W2 task of the release plan (§3): W2.1 #550 (the SCIM per-target
breaker), W2.2 #551 (the notification window, T-117), W2.3 #553 (request-audit
loss, T-108), W2.4 #552 (the dead-letter file in prod Compose and k8s, the GDPR
request records), W2.5 #554 / #569 (the fatal stop, the stop budget), W2.6 #566
(the CIBA pending list and badge), W2.7 #535 (the sweep registry), W2.8 #555 (the
SCIM target version, the webhook's redirects, the conformance gate, the
in-process `delivery_abandoned` row, the pepper log line, the §8 note), W2.9
#568 / #567 (`rl-prod-check` rows, loopback bench ports) and W2.10 #536 (the
surface switches and the SSF streams page).
**Method:** adversarial reading of the diff and of every sibling path it
implies, against [`threat-model-stride.md`](threat-model-stride.md) and
`Axiam.json` (model 2.37.0, 469 threats: 428 / 20 / 21), the plan's §7 rules
(binding on every wave), the W6 F4 review's §15 preconditions, and the OWASP ASVS
5.0 areas the diff touches (V2 business logic and concurrency, V3 frontend, V4
API, V7 session, V8 authorization, V12 SSRF, V13 configuration, V14 data
protection, V16 logging). Claims were checked against the code, not the commit
messages. This review fixes nothing (the orchestrator's instruction): every
finding is reported with its evidence, a proposed fix and an issue body (§12).
The two Medium findings are proposed for a fix inside the wave; the rest for
`1.0.x`.

---

## 0. Summary

**Two Medium findings, both on the audit path the wave strengthened.**

* **R1W2-01 (Medium, T-117 → T-108).** The notification window is claimed with a
  hot-row conditional `UPSERT`, retried up to 32 times on a write conflict, and
  the claim runs **inline on the audit worker** — the one task per replica that
  appends every request-audit row. Every replica's claims for one
  `(tenant, rule, event)` contend on one record, so fleet-wide the claims are
  serialized: a probe on the in-memory engine measured the same ~1.4 s for 400
  claims whether one, four or eight "replicas" made them, with per-claim latency
  rising to 15 ms and 29 ms on average and 0.4 s and 0.74 s at worst. An
  unauthenticated failed-sign-in flood against a tenant with a `login_failure`
  rule (the configuration T-117 exists for) therefore slows every replica's audit
  worker; its 4 096-row queue fills and **every tenant's** request-audit rows are
  dropped — counted and dead-lettered since #553, but dropped. The fix for T-117
  became a lever on T-108.
* **R1W2-02 (Medium, T-108).** The dead-letter file has **no size bound**, its
  lines carry attacker-sized fields (the request path and the
  `X-Forwarded-For`-derived address, both unbounded strings), and on Kubernetes
  the `emptyDir`'s `sizeLimit: 256Mi` is enforced by **evicting the pod — which
  deletes the `emptyDir` and the file with it**. The manifest calls that "a
  louder failure"; it is the file destroying itself at the moment it is fullest,
  across every replica of a datastore outage at once, and an unauthenticated
  client can bring the moment forward. On Compose the named volume shares the
  Docker root with the datastore's volume and has no bound at all.

Eight Low and four Informational findings are reported for `1.0.x` (§12). One of
them, **R1W2-10**, is a CI blocker the orchestrator should decide on now: the
wave adds a route and changes six schemas but does not regenerate
`sdks/openapi.json`, so the *SDK OpenAPI Drift Gate* fails on the W2 pull
request (the plan puts the regeneration in W3).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **R1W2-01** | The notification window's claim (hot-row `UPSERT`, 32 conflict retries) runs inline on the single audit worker; contended across replicas it serializes, so a failed-sign-in flood on one tenant drops request-audit rows of every tenant. | **Medium** | audit worker, notification window → T-117, T-108 | wave | **Fix in wave** (proposed §2) |
| **R1W2-02** | The dead-letter file is unbounded, its lines are attacker-sized, and the k8s `sizeLimit` eviction deletes the `emptyDir` holding it; Compose has no bound and shares the datastore's disk. | **Medium** | `dead_letter.rs`, `k8s/server/deployment.yml`, prod Compose → T-108 | wave | **Fix in wave** (proposed §3) |
| R1W2-03 | The SSF streams page saves a whole replacement from its load-time state with no client version: a receiver's pause or narrowing in between is reverted, and an emptied narrowing becomes "every allowed event". | Low | console, `PUT …/ssf/streams/{id}` → T-406 | wave | Reported |
| R1W2-04 | Federation's token exchange (client secret, code, PKCE verifier) and userinfo (bearer) go through the redirect-following `guarded_fetch`, which re-sends the form and the `Authorization` header to every hop: the "credential-bearing → no redirect" rule's last exceptions. | Low | `axiam-federation` → T-112's rule | pre-existing | Reported |
| R1W2-05 | `fapi-conformance.yml` writes the `axiam_image` dispatch input unvalidated into `$GITHUB_ENV` (a newline sets any variable for the later steps), and "digest-pinned" is printed, never checked. | Low | CI | pre-existing (the wave's fix is partial) | Reported |
| R1W2-06 | The conformance gate tolerates `WAITING` even for a module the baseline `PASSED`, so a regression that parks a module is green. | Low | `conformance/scripts/gate.py` | wave | Reported |
| R1W2-07 | GDPR request records now dead-letter with synchronous `std::fs` I/O on the actix request path (`append_blocking`, documented "not for the request path"); its `writeln!` is two `write` calls, so a line can interleave with the writer task's batch; the file is created with the process umask and never `fsync`ed. | Low | `gdpr.rs`, `dead_letter.rs` | wave | Reported |
| R1W2-08 | Dead-letter lines carry no time: a replayed row is stamped at the replay, so the trail loses when the request (or the GDPR erasure) happened and in what order. | Low | `dead_letter.rs`, the replay recipe → T-108 | pre-existing, widened | Reported |
| R1W2-09 | A refused in-process enqueue writes its `delivery_abandoned` row synchronously on the producer's (request) path, with an unthrottled `WARN` per refusal. | Low | `inprocess.rs` → T-445 | wave | Reported |
| R1W2-10 | `sdks/openapi.json` is not regenerated (new `GET /api/v1/ciba/requests`, `CibaPendingList`, `RequestAuditHealth`, six changed schemas): the drift gate fails on the W2 PR. | Low | spec, CI | wave | **Decide now** (regenerate in W2, or accept red until W3) |
| R1W2-11 | The write-up and the website say "with one exception — T-447 — none is an unhandled defect in AXIAM's own request path"; T-469 (Open, a defect) is in the same register, and the STRIDE document says two. | Informational | `threat-modeling-and-security.md`, `security.ts` | wave (text) | Reported (W4.5) |
| R1W2-12 | The stop budget leaves the cleanup join unbounded and outside the 40 s; a lease-loss stop keeps a 15 s backstop under a 20 s REST timeout, so it can be cut before the drain — T-444 says every orderly stop drains. | Informational | `boot.rs` → T-444 | pre-existing, made explicit | Reported |
| R1W2-13 | The CIBA pending list is not bounded per client: a client that may address a user can keep 50 short-lived requests ahead of a real one (soonest expiry first), and the badge's 30-a-minute per-IP bucket is shared behind a NAT. | Informational | `GET /api/v1/ciba/requests` → T-424, T-446 | wave | Reported |
| R1W2-14 | The tenant Settings save sends both surface switches at their effective value, so an unrelated save under an organization `false` pins `false` as the tenant's own override (fail-closed; a later organization `true` no longer reaches it). | Informational | console settings | wave | Reported |

**What held.** Every binding rule of §7 holds for what the wave *added* (§4): the
one new route carries its limiter and its own bucket from its first commit
(`5390159`); it takes a console sign-in only and answers a token carrying
`client_id` `403`; the webhook deliverer — the one credential-bearing outbound
request the W6 F4 review left on the redirect-following guard — now uses
`guarded_fetch_no_redirect`, pinned by a source test; no new credential check was
added; and the SCIM target `PUT` now takes the version the administrator read. The
SCIM breaker is correct against #550 and its threat text is honest about what it
does not do (§5); the fatal stop is race-free (§6); the SSF page never reads,
holds or shows `authorization_header` (§7); the conformance workflow's
`run:` blocks interpolate no `${{ }}` (§8); the dead-letter line is JSON-encoded
and the replay recipe's `jq` filter survives quotes, backslashes and non-ASCII,
by a test that runs it (§3). Threat-model counts agree across `Axiam.json`, the
STRIDE document and the generated website files (428 / 20 / 21), and a generator
run leaves no diff (§10).

**Verdict on merge.** R1W2-01 and R1W2-02 should be fixed in the wave: both make
the T-108 control this wave builds lose rows under conditions an unauthenticated
client influences, and both fixes are small (§2, §3). R1W2-10 needs a decision
before the PR is opened. Nothing else blocks.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| CIBA pending list and badge | W2.6 #566 | `handlers/ciba_approval.rs`, `server.rs`, `ciba.rs`, `repository/ciba_request.rs`, `Topbar.tsx`, `usePendingSignInRequests.ts`, `CibaApprovalPage.tsx` | **read in full**; route → limiter → handler → repository traced; tests run |
| Notification window | W2.2 #551 | `notification.rs`, `notification_window.rs`, schema v85, `notification_rules.rs`, `template.rs`, `middleware.rs` (worker) | **read in full**; contention **probed** (§2) |
| Request-audit loss, dead letter | W2.3 #553, W2.4 #552 | `loss.rs`, `dead_letter.rs`, `middleware.rs`, `gdpr.rs`, `boot.rs`, `health.rs`, `job_health.rs`, prod Compose, k8s | **read in full**; file handling, size, injection into lines, replay recipe |
| Fatal stop, stop budget | W2.5 #554 #569 | `fatal_stop.rs`, `boot.rs` teardown, `api-grpc/server.rs`, Compose / k8s grace | **read in full**; races and ordering traced |
| SCIM breaker | W2.1 #550 | `deliverer.rs`, `scim_target.rs` (state), `outbound_scim_test.rs` | **read in full** |
| SCIM target version | W2.8 | `scim_targets.rs`, `ScimTargetsPage.tsx`, `scimTargets.ts` | **read in full** |
| Webhook redirects | W2.8 | `webhook.rs`, `axiam-pki/src/ssrf.rs`; every `guarded_fetch(` caller in the tree | **read**; tree searched |
| In-process `delivery_abandoned` | W2.8 | `inprocess.rs`, `outcome.rs`, `boot.rs` | **read** (publish path, stop path) |
| Conformance gate and workflow | W2.8 | `gate.py`, `test_gate.py`, `baseline.json`, `fapi-conformance.yml`, `ci.yml` | **read in full**; tests run; every `${{ }}` listed |
| Pepper log line | W2.8 | `legacy_env.rs`, `main.rs` | **read** (no value logged) |
| Sweep registry | W2.7 #535 | `job_health.rs`, `cleanup.rs` | **read**; tests run |
| Bench ports, `rl-prod-check` | W2.9 #567 #568 | target Compose files, `rl_prod_check.py`, the two self-tests | **self-tests run** |
| Surface switches, SSF page | W2.10 #536 | `surfaceSwitches.tsx`, `SettingsPage.tsx`, `SecurityOverridePanel.tsx`, `SsfStreamsPage.tsx`, `ssf.ts`, `ssf_admin.rs` | **read** (header handling, write bodies, permissions) |
| Threat model and docs | all | STRIDE, write-up, `Axiam.json`, website, CHANGELOG, deployment / API / admin guides | entries named in the brief compared with the code (§9, §10) |

Not run: a real multi-replica deployment (the contention numbers are from the
in-memory engine, which understates a networked datastore's latency); the
frontend's vitest and Playwright suites (`frontend/node_modules` is absent in the
sandbox); the conformance workflow (dispatch-only).

## 2. R1W2-01 — the notification window serializes the audit worker

**Severity: Medium. Wave-introduced. Proposed for a fix in the wave.**

**The path.** `audit_worker` (`crates/axiam-audit/src/middleware.rs:249-281`) is
one task per replica. For each row it appends (`:270`) and then awaits the
notification sink inline (`:279`). Since #551 the sink, for every rule that
matches the row's event, awaits `NotificationWindowRepository::claim`
(`crates/axiam-audit/src/notification.rs:241-246`), which is one `UPSERT` on the
record `<tenant>_<rule>_<event>` wrapped in `retry_hot_row`
(`crates/axiam-db/src/repository/notification_window.rs:87`): up to
`HOT_ROW_MAX_WRITE_ATTEMPTS = 32` attempts (`crates/axiam-db/src/helpers.rs:146`)
with a 2, 4, 8 … 64 ms backoff (`:288`), so a claim that keeps losing can hold
the worker for about 1.8 s.

**Why it contends.** Every event inside an open window still *writes* the record
(`suppressed + 1`). Every replica processing the same tenant's failed sign-ins
writes the same record. The datastore orders them, so the claims of the whole
fleet for one `(tenant, rule, event)` are serialized.

**Measured.** A probe (written for this review and removed; §11) gave four and
eight concurrent claimants — each issuing claims back to back, as a replica's
worker does — on one window over `kv-mem`:

| claimants × claims | wall clock | mean claim latency per claimant | worst claim | errors |
|---|---|---|---|---|
| 1 × 400 | 1.35 s | 3.4 ms | 6 ms | 0 |
| 4 × 100 | 1.52 s | 15.2 ms | 404 ms | 0 |
| 8 × 50 | 1.45 s | 29.1 ms | 738 ms | 0 |

Fleet throughput is flat (~280 claims/s in-process); each replica's share falls
as replicas are added. On a networked datastore each attempt costs a round trip,
so the ceiling is lower.

**Consequence.** Failed sign-ins are unauthenticated and spread over addresses
and accounts by design (that is T-117's scenario); a tenant with a
`login_failure` rule — the rule a SOC configures first — makes each such row cost
a contended claim on every replica. When the arrival rate of rows exceeds the
worker's reduced rate, the 4 096-row queue fills and `try_send` drops rows
(`middleware.rs:418`) — **every** tenant's, every route's, not only the
flooded tenant's sign-ins. #553 now counts and dead-letters them, so the loss is
not silent, but an attacker who wants an action of their own to leave no row in
the datastore has a cheap way to open that window. Before #551 the same event did
a rule read and a mail publish per recipient: no conflicting write.

The claim's own semantics are right — exactly one claimant opens a window, the
count carries, a failed claim mails nobody — and its tests pass. The defect is
where it runs and how long it may retry.

**Proposed fix (any one closes it; the first two together are best).**
1. **A conflict is an answer.** A write conflict on the claim means another
   claimant has just written the record, i.e. a window is open or was opened in
   that instant: map it to `Counted` after at most `MAX_WRITE_ATTEMPTS` (4) or
   even one attempt, accepting that the suppressed count may undercount by the
   conflicts (say so in the mail: "at least N").
2. **Count locally inside an open window.** Keep a per-replica map
   `(tenant, rule, event) → (opened_at, local_count)`; while the window this
   replica last saw is open, increment in memory and skip the datastore; flush
   `suppressed += local_count` once, at the first claim after the window closes.
   One write per replica per window instead of one per event.
3. **Take notifications off the audit worker.** Hand matched events to a
   separate bounded queue and task; when it is full, drop the *notification*
   (counted), never the audit row.

**Test.** A worker driven with a sink whose claim takes 50 ms per event and a
burst larger than the queue: no row may be dropped (today some are). For (1)/(2),
eight concurrent claimants make at most eight writes per window.

## 3. R1W2-02 — the dead-letter file is unbounded, and k8s deletes it when it is full

**Severity: Medium. Wave-introduced (the request-audit rows, prod Compose and
k8s provisioning). Proposed for a fix in the wave.**

**No bound in the writer.** `DeadLetterWriter`'s task appends every batch it is
given (`crates/axiam-audit/src/dead_letter.rs:236-252`); `append_blocking`
(`:55-62`) likewise. Nothing counts bytes. Since #553 every request-audit row
that is dropped or fails to append goes there.

**The lines are attacker-sized.** A request-audit row's `action` is
`"{method} {path}"` from `req.path()` (`middleware.rs:339`, `:405`) — any path,
on any route, authenticated or not — and `ip_address` is actix's
`realip_remote_addr()` (`:349`), which takes the first `Forwarded` /
`X-Forwarded-For` value as a string without validating it (pre-existing for the
datastore row). A line is "a few hundred bytes" (the manifest's sizing) only for
an honest client; an unauthenticated one can make each tens of kilobytes, within
actix's request-head limit.

**k8s: the bound is an eviction, and the eviction deletes the file.**
`k8s/server/deployment.yml:192-198` sets `emptyDir.sizeLimit: 256Mi` and says
"a pod that exceeds it is evicted, which is a louder failure than filling the
node's disk". The kubelet enforces an `emptyDir` `sizeLimit` by evicting the pod;
an evicted pod is deleted, and its `emptyDir` with it — the same document lists
"an eviction" among what the volume does not survive. So the file is destroyed
at the moment it holds the most unreplayed rows. During a datastore outage every
replica's file fills at its request rate (each failed append is a line), so the
whole Deployment reaches the limit at about the same time and is evicted
together; at honest line sizes and a few hundred requests a second that is tens
of minutes, with attacker-sized lines minutes. The GDPR records sharing the file
keep their second sink (the `axiam.audit.dlq` log event); the request rows have
no other copy.

**Compose: no bound, shared disk.** `docker/docker-compose.prod.yml:297, 477` put
the file on a named volume with no limit, under the same Docker root as
`surrealdb-data`. A flood while the datastore is slow (the case that fills the
queue) writes to the disk the datastore needs.

**Proposed fix.**
1. A byte budget in `DeadLetterWriter` (`AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES`, read
   with the path; default e.g. 192 MiB, documented as "below the volume's
   limit"), tracked from the file's size at open: past it, request-audit rows are
   refused and counted in `not_recoverable` with a distinct reason, and
   `/health/jobs` says the file is full.
2. A reserve for the GDPR records: `append_blocking` may write past the
   request-row budget up to a hard cap, so an erasure record is never refused
   because request rows filled the file first.
3. Bound the attacker-controlled fields in the line (and preferably in the
   audit entry itself): `action` truncated to e.g. 512 bytes with a marker,
   `ip_address` to the length of an IPv6 literal, or validated as an address.
4. Correct the manifest and `docs/deployment/README.md`: the `sizeLimit` must sit
   above the budget, and reaching it destroys the file.

**Test.** A writer with a 4 KiB budget refuses the request row that would cross
it, counts it, and still writes a GDPR record; a 20 KiB path produces a bounded
line.

**What was checked and holds.** Injection into the JSON lines: none —
`serde_json::to_string` escapes quotes, backslashes and control characters, so a
line cannot be split or closed early. Injection through the replay: the recipe
builds each SurrealQL statement with `jq`'s `@json` for every string and
`tojson` for `metadata`, and `the_replay_recipe_in_the_docs_restores_dead_lettered_rows`
runs the README's own filter over rows holding a quote, a backslash and `é` and
reads them back through the repository (it passed, §11). Path: operator-set,
never derived from a request. The request path does no file I/O for request rows
(`try_send` into a 1 024-row queue).

## 4. The §7 rules, against what the wave added

| Rule | Verdict | Evidence |
|---|---|---|
| Every new route carries a limiter from its first commit | **holds** | `GET /api/v1/ciba/requests` is wrapped in `build_governor` and `RateLimitShared("ciba_approval_list", ciba_approval_per_min)` in `5390159` itself (`server.rs` ~`:808-816`); `the_pending_list_has_a_rate_limit_bucket_of_its_own` shows 200, 200, 429, 429 with the page's bucket untouched. No other route was added. |
| Every approval surface takes a console sign-in only (`client_id` → 403) | **holds** | the list calls `session_evidence` (`ciba_approval.rs:177-199`), which refuses `claims.client_id.is_some()` and a token with no live session row of the same user; `a_token_minted_for_a_client_cannot_list_requests` (client token 403, sessionless 403, none 401). W1's `AuthenticatedUser::minted_for_client()` (`1c89d79`) is the same predicate; the merge should switch the call, as `5390159`'s body says. |
| Every credential-bearing outbound request uses `guarded_fetch_no_redirect` | **holds for the wave**; **not in the tree** | the webhook deliverer moved (`webhook.rs:299-310`), pinned by `delivery_goes_through_the_no_redirect_guarded_fetch_and_nothing_else`; `pinned_client` sets `Policy::none()`. The federation client still sends a client secret and a bearer token through `guarded_fetch` — **R1W2-04**. |
| Every refusal of a credential check costs one verify | **not touched** | the wave adds no credential check. T-469 stays open on this branch (W1 closes it). |
| Every two-writer registry is written conditionally on the version read | **holds for SCIM targets**; **not for the SSF page** | `expected_updated_at` on `ScimTargetInput` (`scim_targets.rs` ~`:810-822`), sent by the console; the SSF page, new in this wave, sends a replacement built from load-time state with no client version — **R1W2-03**. |

## 5. W2.1 — the SCIM breaker (#550)

**Verdict: correct against the issue; T-414's text is accurate.** The breaker
reads the target's delivery state after `admit` and before any resource read or
request (`deliverer.rs` `deliver`); it opens at `BREAKER_THRESHOLD = 5`
consecutive failures and stays open for the consumer's own backoff applied to the
failures past five, capped at the ceiling (`breaker_window`); a refused attempt
writes nothing except, on the consumer's last attempt, `dead_lettered_total += 1`
(`count_dead_letter`), so refusals cannot hold it open; a state read that fails
admits the attempt (fail-open is right here: the breaker only saves a request). A
zero base never opens it; a future stamp reads as "now". The tarpit test opens
the breaker by recording five failures (a real five timeouts would take 50 s) and
asserts no connection reached the tarpit and the healthy delivery finished inside
one request timeout — it tests what it names.

Residuals, all stated in T-414: a downstream that succeeds just inside ten
seconds never trips it; one attempt per window **per replica** still costs a full
timeout (N replicas, N timeouts per window); a tenant with many failing targets
pays five timeouts per target before each opens. The per-target concurrency
budget is deferred to `1.0.x` by the plan.

## 6. W2.5 — the fatal stop and the stop budget (#554, #569)

**Verdict: the fatal stop is sound; the budget text overstates two edges
(R1W2-12).** `FatalStop::raise` records the first component only
(`send_if_modified`); `spawn_fatal_stop` uses `wait_for`, which sees a raise that
happened before it was spawned, so a gRPC bind failure at start cannot be missed;
the backstop (35 s) sits inside the shipped 40 s grace, asserted at compile time;
the teardown reads `component_died` once, after the REST listener returns, so a
consumer that ends *because* of an ordinary stop cannot turn a clean stop into a
non-zero exit; gRPC is given its shutdown future and awaited for at most 5 s
before the outbound and audit drains; the backstop task is aborted after the
cleanup join. The `exit(1)`s are gone from all four sites.

R1W2-12: `cleanup_handle.await` (`boot.rs:3141`) is unbounded and is not in the
"20 + 5 + 2 + 5 + margin" arithmetic — a sweep tick that is long when the stop
arrives is killed by the orchestrator at 40 s (the fatal path has its 35 s
backstop); and the lease-loss stop keeps `lost_stop_deadline = 15 s`
(`profile.rs:72`) while the REST listener now waits up to 20 s, so a lease-loss
stop with a slow request in flight is ended by its backstop before the drain.
`boot.rs`'s comment says the second; T-444 says "every orderly stop drains".

## 7. W2.6 and W2.10 — the console surfaces

**CIBA pending list.** Only the caller's rows (`WHERE tenant_id AND user_id AND
status = 'pending' AND expires_at > time::now()`), so another user's, a decided
and an expired request are absent — the same absence as an unknown id (T-430);
`auth_req_id` is never in the response (it is stored hashed); `status` other than
`pending` is `400`, checked after the session check, so it is no oracle for an
unauthenticated caller; `Cache-Control: no-store`. The list and the page build
their entries with one function. The badge polls once a minute, only while the
tab is visible, never retries, and the approval page invalidates it after a
decision. R1W2-13 records two bounds the list does not have.

**SSF streams page.** `authorization_header` appears in no response type
(`SsfStream` has `authorization_header_set` only); the form field is
`type="password"`, `autoComplete="new-password"`, never pre-filled (`formFrom`
sets `""`), sent only when typed, and refused locally when an origin move needs
it; `clear_authorization_header` is sent only with a stored stream. The route and
nav gate on `ssf_streams:read`, the writes on `ssf_streams:write` in the page and
on the server. The write body has R1W2-03's problem.

**Surface switches.** The server enforces disable-only; the page only refuses to
offer a switch-on the organization withheld, and says "unknown" when it cannot
read the tenant's override. R1W2-14 is a functional side effect, fail-closed.

## 8. W2.8 — the conformance gate and workflow

`gate.py` reads only the suite's result files and the committed baseline, uses no
shell, and fails closed on an unreadable result, a missing plan, a module
missing from the run, an outright failure, a module below its baseline and a plan
that passed nothing; its 16 fixture tests pass and CI runs them. Every `${{ }}`
in `fapi-conformance.yml` is now in an `env:` block (lines 204, 256, 309-310,
323, 379, 409), and none is interpolated into a `run:` script. Two gaps:
R1W2-05 (the image input reaches `$GITHUB_ENV` unvalidated, `:209`) and R1W2-06
(`WAITING` tolerated even for a module the baseline passed, `gate.py:84`, pinned
as intended by `test_a_waiting_interactive_module_is_tolerated_even_if_the_baseline_passed_it`).

## 9. Threat-model text against the code

| Entry | Verdict | Note |
|---|---|---|
| T-414 (SCIM) | **matches** | §5; residuals complete |
| T-117 (notifications) | **matches the behaviour; omits the cost** | the claim runs on the audit worker and serializes across replicas — R1W2-01 should enter its residual (or be fixed) |
| T-108 (request audit) | **matches; residual incomplete** | the file's missing bound and the k8s eviction (R1W2-02), and lines without a time (R1W2-08), belong in "what stays" |
| T-444 (orderly stop) | **overstated at two edges** | R1W2-12 |
| T-445 (minimal profile) | **matches** | the refused-enqueue row is written on the producer's path (R1W2-09) |
| T-416 (SCIM target writes) | **matches** | the client version is optional and the residual says so |
| T-406 (SSF stream writes) | **overstated for the console** | "the administrator's `PUT` answers `409` and the console reloads": a `409` comes only from a write inside the request; a form loaded earlier replaces silently — R1W2-03 |
| T-112 (webhook) | **matches** | one hop, `3xx` is a retry, source-pinned |
| T-129 (jobs) | **matches** | the scan is two-directional and refuses a vacuous read (≥ 15 names) |
| T-431, T-446 (CIBA page, mail) | **match** | the list's rules as stated; the residual of T-446 is closed by a test that had no route before |
| T-447 | **matches this branch** | Open here; W1 (`1c89d79`) closes the device half — W4.5 reconciles |
| Open-register prose | **inaccurate** | R1W2-11 (T-469 omitted in two places) |

## 10. Documentation and CHANGELOG claims

| Claim (where) | Verdict | Evidence |
|---|---|---|
| The list is console-sign-in only, own bucket, no `auth_req_id`, `400` for other statuses (CHANGELOG, API guide, website) | **true** | §4, §7 |
| "The routes need a human session and a CSRF token (the list included)" (*Integrate*) | **imprecise** | the list is a `GET`; CSRF guards the two decisions only |
| The webhook deliverer follows no redirect (CHANGELOG, `security-profiles.md`, website) | **true** | §4 |
| "closing a template injection for anyone who may dispatch it" (CHANGELOG) | **partly** | `run:` blocks are clean; the input still reaches `$GITHUB_ENV` unvalidated — R1W2-05 |
| The tarpit breaker (CHANGELOG, *Integrate*, `data.ts`) | **true** | §5 |
| "the request path does no file I/O" for lost rows (CHANGELOG, T-108, deployment guide) | **true for request rows; false for the GDPR request records** | `gdpr.rs:205` — R1W2-07 |
| "`sizeLimit` … a pod that exceeds it is evicted, which is louder" (manifest, deployment guide) | **misleading** | the eviction deletes the file — R1W2-02 |
| 40 s = 20 + 5 + 2 + 5 + margin (Compose, k8s, deployment guide, *Operate*) | **true for the parts named** | the cleanup join is not one of them — R1W2-12 |
| Five sweeps registered; revocation feed only when on (CHANGELOG) | **true** | `job_health.rs` `sweep_jobs`; tests run |
| A minimal-profile server reads no AMQP queue (API guide, AsyncAPI, *Operate*) | **true** | the consumers are spawned only inside the AMQP branch of `boot.rs` |
| Pepper log names the variable, never the value (CHANGELOG) | **true** | `legacy_env.rs`, `main.rs` |
| Every published bench port is `${BENCH_BIND_ADDR:-127.0.0.1}` (CHANGELOG) | **true** | `bind-addr-selftest.sh`: 12 ports in 9 files |
| Threat model counts 428 / 20 / 21 (STRIDE, generated files) | **true** | script count over `Axiam.json`; generator leaves no diff |
| Model version | **unchanged at 2.37.0** although T-108 and T-117 changed status | the plan gives the version to W4.5 |

## 11. Checks run

Each command with its own exit code (logs in the scratchpad; `cargo clean` after
the last build).

| Check | Result |
|---|---|
| `cargo test -p axiam-audit` | pass (19 + 1 + 7 + 31) |
| `cargo test -p axiam-db --test notification_rule_repository_test --test ciba_request_repository_test` | pass (11, 15) |
| `cargo test -p axiam-scim --lib breaker` | pass |
| `cargo test -p axiam-api-rest --no-default-features --test ciba_approval_test --test webhook_test --test notification_rules_test` | pass (20, 6, 25) |
| `cargo test -p axiam-api-rest --no-default-features --test gdpr_audit_dlq_test --test health_test --test scim_targets_test` | pass (4, 11, 26); `jq` present, so the replay recipe was exercised |
| `cargo test -p axiam-server --no-default-features --test notification_window_test` | pass (4) |
| `cargo test -p axiam-server --no-default-features --lib -- job_health fatal_stop legacy_env` | pass (21) |
| **R1W2-01 probe** — a temporary `crates/axiam-db/tests/zz_f4_window_probe.rs` (1 × 400, 4 × 100, 8 × 50 concurrent claims on one window over `kv-mem`), run and deleted | the table in §2 |
| **R1W2-10** — `cargo build -p axiam-server --no-default-features`, `--dump-openapi`, compared with `sdks/openapi.json` | **differs**: path `/api/v1/ciba/requests`; schemas `CibaPendingList`, `RequestAuditHealth` added; `CreateNotificationRuleRequest`, `UpdateNotificationRuleRequest`, `NotificationRule`, `NotificationRuleResponse`, `ScimTargetInput`, `JobsHealthResponse` changed |
| `python3 -m unittest discover -s conformance/scripts -p 'test_*.py'` | pass (16) |
| `bash benchmarks/runner/bind-addr-selftest.sh`, `bash benchmarks/runner/rl-prod-posture-selftest.sh` | pass |
| `python3 scripts/check-crate-layering.py`, `check-spec-digest.py`, `gen-management-registry.py --check` | pass (against the committed, stale spec) |
| `node website/scripts/gen-threat-model.mjs` | 469 threats (428 / 20 / 21); no diff |
| Commit signatures | 19 of 19 carry `gpgsig` |

## 12. Issue bodies

### R1W2-01 (Medium) — the notification window's claim serializes the audit worker across replicas

`NotificationSink` runs inline on `audit_worker`, the one task per replica that
appends every request-audit row (`crates/axiam-audit/src/middleware.rs:270-279`).
Since #551 it claims the rule's window for every matched event
(`crates/axiam-audit/src/notification.rs:241-246`) with an `UPSERT` on the record
`<tenant>_<rule>_<event>`, retried up to 32 times on a write conflict with up to
64 ms between attempts (`crates/axiam-db/src/repository/notification_window.rs:87`,
`crates/axiam-db/src/helpers.rs:146, 288`). Every event inside an open window
still writes the record, so the claims of all replicas for one
`(tenant, rule, event)` are serialized: on `kv-mem`, 400 claims took ~1.4 s for
1, 4 or 8 concurrent claimants, with the mean claim rising to 15 / 29 ms and the
worst to 0.4 / 0.74 s. A failed-sign-in flood (unauthenticated, T-117's own
scenario) against a tenant with a `login_failure` rule slows every replica's
audit worker until its 4 096-row queue fills, and then request-audit rows of
every tenant are dropped (T-108; counted and dead-lettered since #553).
**Proposed fix:** treat a write conflict on the claim as `Counted` after at most
`MAX_WRITE_ATTEMPTS` (a conflict means a window was just written), and count
inside a window this replica already knows is open in memory, flushing
`suppressed += n` once at the next claim; optionally move notification dispatch
to its own bounded queue so a slow sink drops notifications, never audit rows.
**Tests:** a burst larger than the queue through a worker whose sink takes 50 ms
drops no row; eight concurrent claimants make at most eight writes per window.

### R1W2-02 (Medium) — the audit dead-letter file has no bound, and its k8s `sizeLimit` deletes it

`DeadLetterWriter` and `append_blocking` (`crates/axiam-audit/src/dead_letter.rs:55-62, 236-252`)
append without a byte budget, and since #553 every dropped or failed
request-audit row is a line. A line's `action` is the request path and its
`ip_address` the unvalidated `Forwarded`/`X-Forwarded-For` value
(`middleware.rs:339, 349, 405`), so an unauthenticated client sizes it. On
Kubernetes the file sits in an `emptyDir` with `sizeLimit: 256Mi`
(`k8s/server/deployment.yml:192-198`): exceeding it evicts the pod, and eviction
deletes the `emptyDir` — the file is destroyed when it is fullest, on every
replica of a datastore outage at about the same time. On Compose the volume is
unbounded and shares the Docker root with `surrealdb-data`
(`docker/docker-compose.prod.yml:297, 477`). **Proposed fix:** a byte budget in
the writer (`AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES`, below the volume's limit) past
which request rows are refused and counted `not_recoverable` with their own
reason and `/health/jobs` says the file is full; a reserve above it for the GDPR
records written by `append_blocking`; `action` and `ip_address` bounded in the
line (better, in the entry); the manifest's comment and the deployment guide
corrected. **Tests:** a 4 KiB budget refuses the crossing request row and still
takes a GDPR record; a 20 KiB path yields a bounded line.

### R1W2-03 (Low) — the SSF streams page reverts a receiver's change

`SsfStreamsPage.tsx` `inputFrom` (`:107-131`) builds the `PUT` from the form's
load-time state — `status` and the stored `events_requested` — and the server's
update is conditional only on the version it reads during the request
(`crates/axiam-api-rest/src/handlers/ssf_admin.rs:768`). A receiver that pauses
the stream or narrows `events_requested` between the form's load and its save is
silently reverted, and when the administrator removes every event the receiver
had narrowed to, `events_requested` is omitted and becomes every allowed event —
more events about the tenant's users than the receiver asked for. T-406 says the
console reloads on `409`, which only covers a write inside the request.
**Proposed fix:** `expected_updated_at` on `SsfStreamInput` (additive, as #555 did
for SCIM targets), sent by the page; and never widen on save — send an empty
narrowing as "none" or refuse the save with a message. **Tests:** a receiver
`PATCH` between the page's read and save makes the save `409`; removing the
narrowed events does not widen `events_requested`.

### R1W2-04 (Low) — federation still sends credentials through the redirect-following guard

`guarded_fetch_with_cap` (`crates/axiam-pki/src/ssrf.rs:288-350`) rebuilds the
request with the caller's closure on every hop (`:317`), so a `3xx` re-sends the
body and headers to the `Location`. Its credential-bearing callers:
`axiam-federation/src/oauth2.rs:334` (token exchange: `client_secret`, `code`,
`code_verifier`), `:394` and `:438` (`Authorization: Bearer`),
`axiam-federation/src/oidc.rs:769` (token exchange). Any public HTTPS host the
IdP's token or userinfo endpoint redirects to receives AXIAM's client secret for
that IdP, the authorization code and the PKCE verifier, or the user's access
token; reqwest's own cross-host header stripping does not apply because each hop
is a new request. The W6 F4 review's §15 called the webhook deliverer "the one
exception left"; it was not. **Proposed fix:** `guarded_fetch_no_redirect` for
the four calls (a token or userinfo endpoint has no business redirecting), a
`3xx` being an error naming the endpoint; source-pinned like the deliverers.
Discovery, JWKS and metadata fetches carry no credential and may keep
`guarded_fetch`. **Test:** a token endpoint answering `307` to a second loopback
server: the second server receives nothing.

### R1W2-05 (Low) — the conformance workflow's image input reaches `$GITHUB_ENV` unvalidated

`.github/workflows/fapi-conformance.yml:202-209` writes
`BENCH_AXIAM_IMAGE=${AXIAM_IMAGE}` to `$GITHUB_ENV` from the `axiam_image`
dispatch input. An input with a newline (possible through the API) sets any
variable for every later step (`BASH_ENV`, `NODE_OPTIONS`, …). The summary prints
"(digest-pinned)" (`:335`) for any value, tag or not. The audience is anyone who
may dispatch, i.e. writers, and the workflow has `contents: read`, so the impact
is bounded; but #555 aimed at exactly this input. **Proposed fix:** validate in
that step — `[[ "$AXIAM_IMAGE" =~ ^[a-z0-9./_-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$ ]]`
or fail — before any use.

### R1W2-06 (Low) — the conformance gate cannot see a newly parked module

`gate.py:84` tolerates `WAITING` whatever the baseline says, and
`test_a_waiting_interactive_module_is_tolerated_even_if_the_baseline_passed_it`
pins it. The baseline is the browser-driven 2026-09-25 run, so every module that
needs a browser is `PASSED` there and `WAITING` unattended, and a regression that
makes a module park instead of failing reads green. **Proposed fix:** record a
second, unattended baseline (which modules end `WAITING` on the runner) and treat
a module that completed unattended before and parks now as a regression; say in
the runbook that green covers only the modules that complete unattended.

### R1W2-07 (Low) — the GDPR records' dead-letter path

Since #552 `gdpr.data_export_requested` and `gdpr.erasure_requested` reach
`dead_letter_audit` from the request handlers, which calls
`append_blocking` — synchronous `std::fs` on an actix worker
(`crates/axiam-api-rest/src/handlers/gdpr.rs:205`), against its own doc
("not for the request path", `dead_letter.rs:53`). `writeln!(file, "{line}")`
(`dead_letter.rs:61`) issues two `write` calls (the line, then `\n`), so the
writer task's batch can land between them: two records on one line (jq still
parses it; the guide's `wc -l` / `tail -n +N` bookkeeping miscounts). Both
writers create the file under the process umask (0644) and neither `fsync`s.
**Proposed fix:** `spawn_blocking` (or the writer task with a flush acknowledgement)
for the handlers; one `write_all` of `line + "\n"`; `OpenOptionsExt::mode(0o600)`;
`sync_data` after each batch and each GDPR record.

### R1W2-08 (Low) — dead-letter lines carry no time

A line is a bare `CreateAuditLogEntry`, which has no timestamp; the replay
recipe creates the row at replay time (`docs/deployment/README.md`, "The audit
dead-letter file", which says so). The trail loses when a request happened —
and when an erasure was recorded — and in what order relative to rows written
normally. **Proposed fix:** write `{"occurred_at", "reason", "entry"}` (or put
`occurred_at` and `dead_lettered_reason` into `metadata`), and have the recipe
carry them into the replayed row's metadata; keep reading the old form.

### R1W2-09 (Low) — a refused in-process enqueue writes on the producer's path

`InProcessOutboundPublisher::publish` awaits `abandon(…)` when the queue is full
or closed (`crates/axiam-amqp/src/outbound/inprocess.rs:159`): a `WARN` line and
an audit append, on the path of whatever request produced the event, for every
refusal. A sustained full queue (a slow receiver) turns each event-producing
request into an extra datastore write and log line. **Proposed fix:** count
refusals per kind and write one `delivery_abandoned` row per kind and interval
with the count and the first delivery id, or hand the row to the audit
middleware's non-blocking queue; rate-limit the `WARN`.

### R1W2-10 (Low) — the OpenAPI spec is not regenerated in W2

A fresh `--dump-openapi` (built `--no-default-features`) differs from
`sdks/openapi.json`: path `/api/v1/ciba/requests`; schemas `CibaPendingList`,
`RequestAuditHealth`; `CreateNotificationRuleRequest`,
`UpdateNotificationRuleRequest`, `NotificationRule`, `NotificationRuleResponse`
(`window_minutes`), `ScimTargetInput` (`expected_updated_at`),
`JobsHealthResponse` (`request_audit`). `.github/workflows/sdk-openapi-drift.yml`
runs on a pull request touching `crates/axiam-api-rest/**`, so the W2 PR is red.
**Proposed fix:** regenerate in W2 (`protoc`, the swagger placeholder, `cargo
build -p axiam-server --no-default-features`, `--dump-openapi`,
`check-spec-digest.py`, `gen-management-registry.py`), leaving the SDK fan-out to
W3; or merge W2 knowing the gate is red until W3.

### R1W2-11 (Informational) — the open-register prose omits T-469

`claude_dev/threat-modeling-and-security.md:2832` and `website/src/security.ts:639`:
"With one exception — T-447 … none of these is an unhandled defect in AXIAM's own
request path". T-469 (a locked account answered without the equalising verify;
Open, Medium; "a defect" in the W6 F4 review) is in the table above it, and
`threat-model-stride.md` says "two exceptions, T-447 … and T-469". **Fix:** the
STRIDE wording in both places (W4.5 rewrites them once W1 and W2 are merged).

### R1W2-12 (Informational) — two edges of the stop budget

`cleanup_handle.await` (`crates/axiam-server/src/boot.rs:3141`) is unbounded and
outside the 20 + 5 + 2 + 5 + margin = 40 s arithmetic; a long sweep tick at
`SIGTERM` meets the orchestrator's kill. The lease-loss backstop
(`LeaseTiming::lost_stop_deadline`, 15 s, `profile.rs:72`) is shorter than the
REST shutdown timeout (20 s), so a lease-loss stop with a slow request ends in
the backstop before the drain. T-444 says every orderly stop drains.
**Proposed fix:** bound the cleanup join (and count it in the budget), and give
the lease-loss path a graceful stop shorter than its backstop (or say in T-444
that it can be cut).

### R1W2-13 (Informational) — the CIBA pending list's bounds

The list is soonest-expiry-first, capped at 50 (`crates/axiam-db/src/repository/ciba_request.rs:371`,
`MAX_PENDING_LIST`), and `requested_expiry` is the client's to choose, so a
client that may address a user can keep 50 short-lived requests ahead of
another client's real one; T-424's per-user throttle bounds the mail, not the
list. Each entry costs a client lookup (up to 50 per call). The badge polls the
30-a-minute per-IP bucket, so behind a shared egress address thirty console tabs
silence each other's badges. **Proposed fix:** a per-client cap of pending
requests per user at `bc-authorize`, the list grouped by client with a count,
ordered by creation; cache client names per call.

### R1W2-14 (Informational) — a tenant settings save pins an inherited `false`

`SettingsPage.tsx` always sends `saml_idp_enabled` / `ssf_enabled` at their
effective value. While the organization has a surface off, any unrelated tenant
save writes `false` into the tenant's own override, and when the organization
later turns the surface on, that tenant stays off. Fail-closed, and the CHANGELOG
mentions the always-send; the console does not say it. **Proposed fix:** send the
switch only when the administrator changed it, or only when the tenant's override
already carries it.

## 13. Invariants

* **Nothing registered today changes behaviour silently.** Additive: the list
  route, `window_minutes` (default 15, existing rules read the default),
  `expected_updated_at` (optional), `request_audit` (optional object), schema v85
  (one optional column, one table). Behaviour changes an upgrader must read are in
  the CHANGELOG: one notification mail per rule, event and window; a webhook
  receiver behind a redirect now fails; a dead-letter volume and setting in prod
  Compose and k8s; the 40 s grace; `delivery_abandoned` rows; the
  `revocation_feed` job registered only when the feed is on.
* **The approval surfaces** remain console-sign-in only; no route that decides a
  grant was added or changed.
* **No credential leaves through a redirect from anything the wave touched**;
  the tree's remaining cases are R1W2-04.
* **Append-only audit**: nothing in the wave updates or deletes an audit row;
  `delivery_abandoned` and dead-letter replays are new rows.
* **Crate layering, spec digest, management registry**: pass against the
  committed spec; R1W2-10 is the stale spec itself.
* **Threat model**: 469 threats, 428 / 20 / 21, consistent across the three
  artifacts and the website; version 2.37.0 left for W4.5; T-117 and T-108 are
  Mitigated on this branch, and R1W2-01 / R1W2-02 are what keeps them from being
  fully so.
