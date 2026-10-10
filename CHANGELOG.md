# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A signed-in user's pending CIBA requests are listed, so an account with no
  vouched address can approve one (#566).** D-74 mails the approval prompt only
  to an address something vouches for, and the approval page was reached only by
  the mail's link, so a federated account (which stays `PendingVerification`,
  T-160) never learned its request's id and the client saw `expired_token`. New
  `GET /api/v1/ciba/requests?status=pending` returns the caller's **own** pending,
  unexpired requests, soonest expiry first (at most 50): the client's name, the
  binding message, the scopes, the requested `acr`, the expiry, and the
  `request_id` and `version` the existing approval page uses; never the
  `auth_req_id`. Another user's, a decided and an expired request are absent, so
  the list is no oracle (T-430). Only `status=pending` exists; any other value is
  `400`. The route is a console surface under the approval routes' rules: a
  console sign-in only (a token AXIAM minted for an OAuth2 client is `403`), and a
  rate-limit bucket of its own under `AXIAM__RATE_LIMIT__CIBA_APPROVAL_PER_MIN`
  (default 30 a minute per IP, never moved by a profile). The console's user menu
  shows a badge with the count, refreshed about once a minute and when the menu
  opens, and lists the requests, each opening the approval page. The decisions are
  unchanged (CSRF, the version read, the deciding session audited). The D-74
  decision stands; the limitation noted under 1.0.0-beta18 (a federated account
  gets no approval mail and cannot reach the page) no longer holds. T-446, T-431
  and T-447 are amended (statuses unchanged).

- **The console shows and switches the SAML identity provider and the SSF
  transmitter (#536).** Until now an administrator could not see from the
  console which third parties receive security events about a tenant's users, nor
  turn either surface off during an incident: `saml_idp_enabled` and
  `ssf_enabled` were changed only through the settings API, and there was no SSF
  page. **Settings:** both are now switches on the organization's Settings tab
  (the only place either is turned on), on the tenant's Settings page and as a
  group in the tenant's Security Overrides, with the layered state shown: a
  surface the organization disabled reads "Disabled by the organization" and
  cannot be switched on, one the tenant switched off says so, and an enabled SSF
  transmitter that is inactive (a deployment of more than one tenant without
  per-tenant issuers) says why. **SSF Streams** (Identity group, `/ssf`, seen with
  `ssf_streams:read`; register, replace and delete need `ssf_streams:write`) lists
  each stream's receiver, audience, delivery method, endpoint, status and who set
  it, with `events_delivered` beside `events_allowed`. The push
  `authorization_header` is write-only and never shown; the form says that moving
  a push endpoint to another origin requires it again and refuses the save
  without it; an edit that loses a race (`409`, T-406) reloads the list and says
  the stream changed. T-406 is amended (status unchanged). Upgraders: the tenant
  Settings page now sends both switches at their effective values on every save;
  before, a tenant that had switched a surface off was put back on the
  organization's value by an unrelated save, and so was one saved from the Security
  Overrides panel, which now carries a group for them.

### Changed

- **The SCIM target `PUT` can be made conditional on the version the
  administrator read (#555, P23W5-09).** `PUT /api/v1/scim-targets/{id}` was
  conditional only on the version the server read during the request, so two
  administrators who opened the edit form at the same version both saved and the
  second silently replaced the first's scope, mapping or deprovision policy.
  `ScimTargetInput` gains an optional `expected_updated_at` (the `updated_at` the
  client read): when present and the target has changed since, the answer is
  `409` and nothing is written. The field is additive and ignored on create; a
  body without it behaves exactly as before (last writer wins), so existing
  clients and scripts keep working. The console now sends the `updated_at` its
  edit form was opened from. The client SDKs gain the field with contract 1.60.
  T-416 is amended (status unchanged).
- **The webhook deliverer no longer follows redirects (#555, P23W5-10).**
  Webhook deliveries went through `guarded_fetch`, which follows a `3xx` (every hop
  SSRF-checked) and re-sends the HMAC-signed request and its body to the
  `Location`, so a receiver's operator could forward deliveries - personal data in
  event bodies - to a host the tenant never registered. They now go through
  `guarded_fetch_no_redirect`, like SSF push, outbound SCIM and the CIBA ping: a
  `3xx` is never followed and the attempt is retried (then dead-lettered like any
  failure), with the reason `the receiver answered with a redirect, which is not
  followed`. **Behaviour change for upgraders:** a webhook whose receiver answers
  with a redirect (an `http` to `https` upgrade, a trailing-slash or host
  canonicalisation, a load balancer hop) used to be delivered to the final URL and
  now fails every attempt; register the receiver at its final URL. T-112 is
  amended (status unchanged).
- **The FAPI conformance workflow is gated on a regression, not on a browser
  (#555, P23W5-11).** `fapi-conformance.yml` drives no browser, so every
  interactive module ends `WAITING` on an unattended run and its last step failed
  every run: a gate that is red by design signals nothing. The step now runs
  `conformance/scripts/gate.py` over the suite's machine-readable results and the
  new `conformance/baseline.json` (the 2026-09-25 runs) and fails only on a module
  that `FAILED` (or could not start, was interrupted, or overran the module
  timeout), a module below its baseline, a baselined module the run did not
  report, or a plan that left no result or evaluated nothing; `WAITING` and
  `SKIPPED` are tolerated and named in the job summary. Green means "no
  regression", not "certified". The rules are unit-tested with fixture result
  files (run by CI). The workflow also passes `inputs.axiam_image` (and the
  step outcome) through `env:` instead of interpolating them into `run:` scripts,
  closing a template injection for anyone who may dispatch it. Runbook: "The CI
  gate". Release-pipeline only; no product behaviour changes.
- **The minimal profile records a delivery its in-process dispatcher loses
  (#555, P23W5-A4).** With `AXIAM__AMQP__ENABLED=false`, a webhook, SSF push,
  outbound SCIM or CIBA-ping delivery that was queued or waiting for a retry when
  the process stopped, or that a full queue refused, left at most a
  `<kind>.delivery_attempt` audit row and no terminal one. An orderly stop now
  writes one terminal **`<kind>.delivery_abandoned`** audit row (outcome
  `Failure`, the system actor, the target as the resource, the delivery id, the
  attempts made and a fixed `reason`) for every such delivery, and an enqueue the
  queue refuses writes one too. The consumer gives an attempt already in flight
  500 ms to finish (it keeps its own verdict if it does) and the teardown waits at
  most 2 s (`OUTBOUND_DRAIN_DEADLINE`) before the audit drain; the 40 s grace
  period and the 35 s fatal-stop backstop are unchanged. **For upgraders:**
  `delivery_abandoned` is a new action, deliberately not `delivery_failed`, so a
  tenant's `scim_delivery_failed` notification rule does not mail anyone when an
  instance restarts; alert on `*.delivery_abandoned` separately if a lost
  delivery matters. A `SIGKILL`, an out-of-memory kill and a stop that overruns
  its deadline still lose the queue without a row, and queued mail has no such
  row. The full profile is unchanged. T-445 is amended (status unchanged, still
  Open).

### Fixed

- **The boot log no longer says the pepper is unset when it is set (#555).**
  `AXIAM__AUTH__PEPPER` is read by the configuration layer, so a deployment that
  set it worked (and a release build booted), but the secret-provider branch
  logged `AXIAM__AUTH__PEPPER not set` because the provider looks for the logical
  key `auth_pepper`, which the `env` provider resolves to
  `AXIAM__AUTH__AUTH_PEPPER`. The log now says where the pepper came from - the
  secret provider, or the configuration (`AXIAM__AUTH__PEPPER`) - and, when there
  is none, `no auth pepper configured: set AXIAM__AUTH__PEPPER (or provide
  `auth_pepper` through the secret provider; the env provider reads it from
  AXIAM__AUTH__AUTH_PEPPER)`. Nothing is renamed: the logical key keeps its name
  for the `file` and `vault` providers, and no variable an operator sets changes.
- **The benchmark stacks publish their ports on loopback, not on every interface
  (#567).** Every `benchmarks/targets/*/docker-compose*.yml` published its
  application, TLS and (AXIAM) gRPC ports as `"${BENCH_APP_PORT:-8090}:8090"`,
  which Docker binds on `0.0.0.0` - past `ufw` - while the benchmark posture raises
  AXIAM's limiters and lockout threshold to 1 000 000, so a benchmark host on a LAN
  offered four identity servers with their limits off to the LAN for the length of
  a run. Each published port (and the optional cAdvisor stack's) is now
  `${BENCH_BIND_ADDR:-127.0.0.1}:<host port>:<container port>`. The harness drives
  the stacks on `localhost`, so a run needs nothing. **An operator who reaches a
  stack from a container** (through `host.docker.internal:host-gateway`, the Docker
  bridge) must set `BENCH_BIND_ADDR=0.0.0.0`: the FAPI conformance workflow now
  does, and the conformance runbook says so. The run-6 runbook's interim "firewall
  the ports" instruction is replaced by the loopback default.
  `runner/bind-addr-selftest.sh` (a new step of the CI job "Bench Harness
  Self-Tests") fails when any `ports:` entry of any compose file under
  `benchmarks/` lacks the variable.
- **`rl-prod-check` lists eight limiter families it had silently dropped (#568).**
  `benchmarks/runner/rl_prod_check.py` carried no row for `bc_authorize_per_min`,
  `ciba_approval_per_min`, `device_login_per_min`, `ssf_per_min`,
  `ssf_admin_per_min`, `saml_admin_per_min`, `directory_admin_per_min` and
  `scim_target_admin_per_min`, so `rl-prod-summary.md` could not say "not
  checked" about them: a reader counting `RateLimitConfig`'s knobs against the
  table's rows found the gap only by counting. Each now has a row with its
  route and no scenario (driving them is a separate decision), and
  `runner/rl-prod-posture-selftest.sh` fails when a `*_per_min` field of
  `RateLimitConfig` has no row, so the next family cannot repeat it. Benchmark
  tooling only; no server behaviour changes.
- **Five cleanup sweeps are listed on `GET /health/jobs` from start (#535).** The
  sweeps for SSO hand-off codes, unused dynamically registered clients, unused
  CIMD clients and expired registration tokens, and the revocation-feed prune,
  were recorded by the cleanup loop but not registered, so until their first run
  the endpoint showed them as absent, which reads as "not deployed", the
  silence T-129 exists to break. The first four are now registered on every
  start (DCR and CIMD are tenant settings, so no process switch gates them).
  The revocation-feed prune is registered, and recorded, only when
  `auth.revocation_feed_enabled` is on: a deployment without the feed no longer
  lists a `revocation_feed` job that had nothing to do. A test scans
  `cleanup.rs` so that a sweep recorded and not registered fails the build.
  T-129 is amended; its status is unchanged.
- **A dying consumer or gRPC server no longer ends the process mid-flight, and
  the gRPC server now stops with the REST listener (#554).** In the full profile
  the authz, audit-ingestion and mail consumers and the gRPC server each ended
  the process with `std::process::exit(1)` when they stopped, wherever it was:
  audit rows still queued, requests in flight and a GDPR purge between its
  erasure and its audit row were lost. Each now takes the stop a lost minimal-
  profile lease takes: the REST listener stops accepting and finishes what is in
  flight, the gRPC server is told to stop and awaited (up to 5 s), the audit
  queue is drained, and `serve` returns an error naming the component, so the
  process still exits non-zero and the orchestrator still restarts it. The
  `exit(1)` remains only as a backstop if that has not finished within 35 s (the
  REST shutdown, the gRPC stop, the audit drain and a margin; a lost lease keeps
  its 15 s).
  The gRPC server previously had no shutdown signal at all, so a `SIGTERM` left
  it serving, with its calls cut off, until the runtime went; it now finishes
  its calls first. `start_grpc_server` takes a trailing shutdown future
  (`std::future::pending()` serves for the life of the process). T-444 is
  amended; its status is unchanged.

- **The stop grace period now covers the REST shutdown plus the audit drain
  (#569).** On `SIGTERM` the REST listener waits up to 30 s (actix's default,
  never set) for requests in flight, and the audit drain then takes up to 5 s
  more, but the minimal Compose file and the benchmark overlay allowed 30 s in
  all, the full production Compose file and the Kubernetes manifest the
  platform defaults (10 s and 30 s), so a stop with a request still running
  could be killed during the drain and lose the audit rows the orderly stop
  exists to keep. The shutdown timeout is now set explicitly to 20 s, and the
  grace period is **40 s** (20 s requests, 5 s gRPC, 5 s audit queue, margin) in
  `docker-compose.prod.yml`, `docker-compose.minimal.yml`, the benchmark
  harness's Compose files and `k8s/server/deployment.yml`
  (`terminationGracePeriodSeconds: 40`). Upgraders who copied these settings
  into their own manifests should set their grace period to at least 40 s;
  `docs/deployment/README.md` ("Stopping, and the grace period") gives the
  arithmetic. The benchmark harness's `bench-up` now also creates the
  `docker/.secrets/*.hex` key files (and the directory) under `umask 077`
  instead of writing them and then running `chmod 600`.

### Security

- **A tarpit SCIM downstream no longer stalls every tenant's outbound provisioning
  on a replica (#550, P23W5-07, T-414).** Each replica's `scim_push` consumer
  makes one delivery at a time, so a target that accepted connections and never
  answered held every tenant's SCIM pushes for ten seconds (twenty with a token
  request) per queued reference. The deliverer now has a **per-target breaker**:
  a target with five or more consecutive failures whose last failure is inside
  its window is not called — the attempt is a retry, reason `target is failing;
  backing off`, with no request and no write to the target's delivery state. The
  window is the consumer's own backoff (`AXIAM__SCIM_PUSH__BACKOFF_BASE_MS` and
  `__BACKOFF_CEILING_MS`) applied to the failures past five: 5 s, then doubling
  with each further failure, up to an hour by default. Once it has passed, the
  next reference is tried; a success closes the breaker. Upgraders should know
  that references queued for a failing target while its breaker is open use up
  their `AXIAM__SCIM_PUSH__MAX_ATTEMPTS` without a request and dead-letter as
  before (counted once in `dead_lettered_total`, notified at most once an hour);
  reconciliation queues them again. The 10 000-member group bound
  (`MAX_GROUP_MEMBERS`) is now pinned by a test. The issue's second option, a
  per-target concurrency budget with more than one delivery in flight per
  consumer, is **deferred to 1.0.x**.
- **Lost request-audit rows are counted, signalled and dead-lettered (#553,
  P23W5-A10, T-108).** The audit middleware drops a row when its 4 096-row queue
  is full and loses one when the datastore refuses the append; each left a single
  log line (the second at `WARN`) and nothing to alert on. Both are now counted
  since process start and reported as a new, additive `request_audit` object on
  `GET /health/jobs` (`dropped`, `failed`, `dead_lettered`, `not_recoverable`,
  `dead_letter_configured`, `last_loss_at`, `recent_loss`; the endpoint's
  exposure is unchanged). A loss in the last fifteen minutes turns the endpoint's
  `status` to `degraded` (still HTTP 200), and the server logs the totals on the
  `axiam.audit.loss` target at `ERROR`, the first time and then at most once a
  minute; the per-row `Audit channel full` line is gone, so move any alert that
  matched it. Upgraders: when `AXIAM__GDPR_AUDIT_DLQ_FILE` is set, the lost rows
  are now also appended to that file (one `CreateAuditLogEntry` JSON line each,
  replayable like the GDPR records) through a queue to a writer task, so the
  request path does no file I/O. With it unset, as in any deployment that does
  not mount a volume for it, the rows are counted and logged only and the server
  warns at start. Rows still in memory when a process is killed rather than
  stopped are lost; an orderly stop drains both queues. The file is **bounded**
  (R1W2-02, the wave's security review): the new setting
  `AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES` (bytes; 192 MiB by default, at least 1 MiB;
  any other value fails the boot) caps it, request-audit rows fill at most nine
  tenths of it and are then refused and counted in `not_recoverable`, and
  `request_audit` gains an additive `dead_letter_full`, which also turns `status`
  to `degraded` until the file is replayed and moved with the server stopped. The
  last tenth is kept for the GDPR records. A request row's `action` (the path)
  and `ip_address` (the forwarded client address) are cut to 512 and 64 bytes
  with a `...[truncated]` marker, in the dead-letter line and in the audit row
  itself, so a client can no longer size the lines.
- **The audit dead-letter file is provisioned in the production Compose file and
  the Kubernetes manifests, and the GDPR request records use it (#552,
  P23W5-A7/A8, T-108).** `AXIAM__GDPR_AUDIT_DLQ_FILE` was set only by
  `docker-compose.minimal.yml`; in `docker-compose.prod.yml` and `k8s/` (whose
  server runs with `readOnlyRootFilesystem: true`) it was unset, so an audit row
  the datastore refused was logged and gone. **Operators: this adds a volume and a
  setting.** `docker-compose.prod.yml` gets a named volume `gdpr-audit-dlq`
  (project `docker`, so `docker_gdpr-audit-dlq`), a one-shot `gdpr-audit-dlq-init`
  service that hands it to the server's user (the server now waits for it) and
  `AXIAM__GDPR_AUDIT_DLQ_FILE=/var/lib/axiam/audit-dlq/gdpr-audit-dlq.jsonl`;
  `just prod-clean` (`down -v`) deletes the volume, so replay it first. The
  Kubernetes server gets the same key in the `axiam-config` ConfigMap (so an
  overlay that replaces the container's `env`, like the Raspberry Pi one, keeps
  it) and an `emptyDir` volume `audit-dlq` with `sizeLimit: 256Mi`, mounted at
  `/var/lib/axiam/audit-dlq`. The kubelet enforces that limit by evicting the
  pod, and eviction deletes the `emptyDir` with the file in it, so the limit
  must never be reached: the ConfigMap also sets the file's budget,
  `AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES=201326592` (192 MiB), below it, and both
  Compose files set `AXIAM_GDPR_AUDIT_DLQ_MAX_BYTES` (same default), since their
  volume has no limit and shares the datastore's disk; raise a budget and its
  volume's limit together (R1W2-02). An `emptyDir` survives a container restart and not
  the pod's deletion (a rollout, a drain, an eviction): the Deployment is 2 to 10
  replicas under an HPA and the file is per replica, so a shared ReadWriteOnce
  claim does not fit and a per-replica one means a StatefulSet. Replay the file
  before rolling the Deployment while it holds rows, or mount a per-replica volume
  of your own at that path. Behaviour: the two GDPR request records,
  `gdpr.data_export_requested` and `gdpr.erasure_requested`, whose refused append
  was only logged, now take the same route as the erasure records (file and
  `axiam.audit.dlq` event; the request itself still succeeds); the helper behind
  it is renamed `write_audit_with_dead_letter`. With the variable unset the server
  now logs one warning at start covering the request-audit rows and the GDPR
  records alike. `docs/deployment/README.md` ("The audit dead-letter file") has the
  replay recipe and what each volume survives. The recipe is now checked by a test
  that runs its `jq` filter over lines the writer produced and reads the rows back
  through the audit repository, and that test found a **defect in the previous
  recipe**: its `CREATE audit_log SET …` let SurrealDB generate the record id, and
  AXIAM's audit list cannot parse such an id (`invalid UUID`). The statement now
  creates `type::record("audit_log", <string>rand::uuid::v7())`. If you replayed a
  dead-letter file with the old statement, those rows make that tenant's audit
  listing fail; find them by their non-UUID record id, remove them as the
  datastore's root user (the append-only rule is a table permission) and replay
  them with the new statement.
- **A notification rule mails each recipient once per event type and window, not
  once per event (#551, P23W5-13, T-117).** A rule for an event an attacker can
  raise in volume — failed sign-ins spread over addresses and accounts — mailed
  every recipient once per audit row; the batching the threat model recorded
  never existed. Each rule now has a **window**, `window_minutes` on
  `/api/v1/notification-rules` (an additive, optional field: 1 to 1440, **15 by
  default**, `400` outside those bounds; the console's rule form edits it). Of
  the events of one type that match one rule, the first in a window is mailed and
  the rest are counted; the first mail after the window says how many were not
  sent (`suppressed_count` and `window_note` in the built-in notification
  template; a tenant's or organization's custom template shows them only if it
  uses those placeholders). The window of (tenant, rule, event) is claimed in the
  datastore (schema **v85**, the `notification_window` table), so several
  replicas still mail once; if the claim cannot be made, nobody is mailed and the
  audit row stands. Upgraders should know that existing rules take the 15-minute
  default, so a second incident of the same event type within 15 minutes of the
  first now arrives as a count in the next mail rather than as a mail of its own;
  lower a rule's window (to 1 minute at least) where that matters.
  `scim_delivery_failed` keeps its own limit of one notification per SCIM target
  per hour and is not windowed again.
  The window costs one datastore write per replica and window, not one per event,
  and it is off the audit path (R1W2-01, the wave's security review): inside a
  window a replica knows to be open it counts events in memory and writes the
  count at its next claim and every ten seconds; a claim that loses a write
  conflict four times is counted the same way; and notification rules run on a
  task and bounded queue of their own beside the audit middleware's worker, so a
  slow notification step drops notifications (counted, with a `WARN` on
  `axiam.audit.notification` at most once a minute), never request-audit rows. A
  count a replica holds is lost if the process is killed before its next flush,
  and on several replicas a count can be reported one window late.

### Documentation

- **SDK contract 1.59: the cross-SDK review of the Phase 23 ports (contracts 1.53 –
  1.58).** The review read the eleven SDK repositories at their 2026-10-09
  `claude/contract-1.58-sync` merges rather than the ports' reports; the evidence,
  file and line, is `claude_dev/sdk-phase23-ports-conformance-review.md`. Every SDK
  implements §28.12, §29, §30, §31, §32, the §32.7 receiver helper and §33 — the four
  REST-only SDKs took the helpers' MAYs — and PHP signs §33.2 with ES256 and EdDSA only.
  `sdks/CONTRACT.md` fills §28.12.7 and §29.10 … §33.10 from the code and adds **§34**:
  - **Twelve clarifications, P1 … P12**, among them: `poll` never keeps a `jti` it does
    not return (a batch interrupted by a failed key fetch lost its events in all
    eleven SDKs); a `5xx` on `ciba_poll` is transient whatever its body (the server's
    own `500 {"error":"server_error"}` ended the loop in five); anything that fails
    after a `2xx` ends `ciba_await`; the §9 exemption covers the tenant-path OAuth2
    endpoints; "never retried" includes an HTTP library's transparent re-send.
  - **Forty-two divergences**, each contract fixed, forced by the language, or an SDK
    fix named as one of eleven follow-ups, F-59-01 … F-59-11 (#576 … #586). The most
    serious SDK-side ones: TypeScript printed a write-only secret from a failed
    write's error (#577); Swift's `Sensitive` is printed by `dump` (#584); Java and
    Kotlin re-sent a management write after a dropped connection (#579, #583).
  - §32.8 helper test 8 and §33.8 test 8 are tightened so that the two most common
    defects fail a required test. No wire change; `CONTRACT.md` is the only artefact
    to re-sync, from the merge commit.
- **A minimal-profile server reads no AMQP queue, and a broker confirm never means
  AXIAM recorded an event (#555, P23W5-A6).** With `AXIAM__AMQP__ENABLED=false` the
  authorization-request and audit-ingestion consumers are not started, so a service
  that publishes to a broker left running next to the server is confirmed by that
  broker while nothing reads the message. The deployment guide's minimal-profile
  section, the AMQP section of the API guide, the AsyncAPI description and the
  website's minimal-profile page now say so. The matching informative note for
  `sdks/CONTRACT.md` §8, to be fanned out to the seven AMQP SDKs' READMEs, ships
  with contract 1.60.

## [1.0.0-beta19] - 2026-10-07

### Changed

- Bump config from 0.15.26 to 0.15.27 in the minor-patch group

- Bump the minor-patch group in /frontend with 7 updates

- Bump the npm_and_yarn group across 2 directories with 2 updates

- Bump rustls from 0.23.43 to 0.23.45 in /examples/b3-mesh-delegation-grpc

- Bump dtolnay/rust-toolchain

### Fixed

- Retry a conflicted SAML participant record instead of assuming a winner

- Read the dashboard's clock once, not during render

- Time the dummy-verify floor against a bracketing reference

## [1.0.0-beta18] - 2026-10-06

### Added

- **Benchmark run 6: the runbook and the harness it needs (G-10, T23.10.2(a), D-75,
  D-76).** `claude_dev/run6-runbook.md` (built like run 5's; a complete copy-paste
  section, the four pinned versions, what changed since run 5, the minimal-profile
  measurement, the rate-limit posture per pass, and exactly what to send back for the
  seventh draft). **Keycloak 26.8.0** and **Zitadel v4.19.4** (each with an image
  override, `BENCH_KEYCLOAK_IMAGE` / `BENCH_ZITADEL_IMAGE`; Keycloak 26.8.0 needed no
  configuration change and its six shared cells pass a dry run at p0, p2 and p3). **No
  benchmark credential is a literal any more**: `runner/bench-creds.sh` generates every
  target's passwords per stack into a mode-600 file (removed by `bench-down`), the compose
  files require them (`${VAR:?…}`), the seed and k6 config carry no default, and a new
  `runner/credential-selftest.sh` (CI) fails on the next one. `deploy=minimal` runs
  AXIAM without the broker in the harness (a compose overlay, `axiam_deploy_profile` in
  `meta.json`, a report banner, `BENCH_EXPECT_DEPLOY`, single instance, outbound deliveries
  lost on restart per T-445); `runner/resting-sample.sh` measures a stack's memory at rest;
  `runner/pull-pinned-images.sh` pins every image by digest; `BENCH_SCENARIO_ONLY` runs a
  chosen cell set. **Fixed in the harness:** `rl=prod` left seven REST families at the
  neutralized value while `rl-prod-check` compared them with the shipped one (now pinned
  from the Rust source); `meta.json`'s `image_digest` was the image id; a stale
  `axiam.bulk.env` survived `bench-down` and mislabelled later cells. No measurement is
  published; the maintainer runs run 6 after `1.0.0-beta18` is cut.

- **authentik as a fourth benchmark target (G-10, T23.10.1, D-7).**
  `benchmarks/targets/authentik/` pins **authentik 2026.8.3** in the shape of the
  Keycloak and Zitadel targets: a `server`, a `worker` and PostgreSQL (no Redis;
  authentik dropped it in 2025.10), the run-5 caps on every container (the worker
  carries the server cap, so the stack's configured ceiling is 6 CPU / 5 GiB
  against Keycloak's 4 / 3), the same PostgreSQL image and tuning, container
  names `bench-authentik`, `bench-authentik-worker`, `bench-authentik-postgres`.
  The image is `BENCH_AUTHENTIK_IMAGE` (default `ghcr.io/goauthentik/server`; the
  Docker Hub mirror works the same way). **No credential literal anywhere**: the
  secret key, the PostgreSQL password, the bootstrap admin password and token are
  generated per run by `bench-up` into a mode-600 file under `.seed/` (removed by
  `bench-down`) and are required compose variables; the bench user's password is
  generated by the seed and the client secret by authentik; nothing prints one.
  `runner/seed.sh` seeds it through authentik's REST API (an OAuth2 provider with
  an explicit `grant_types` list, which 2026.x requires, an application, the
  bench user) and its smoke checks assert more than a status, because two
  authentik answers are HTTP 200 on failure (introspection `{"active": false}`
  and a flow-executor password stage handed a wrong password). Wired through
  `lib/targets.js`, the runner's container list, the settle-gate fallback,
  `report.py` (server-only = server + worker) and the justfile (`bench-matrix` and
  `bench-dry-run` skip `p3-mtls`, which authentik's listener cannot do; `bench-up`
  refuses it). **Equivalence, determined on a running container:** client
  credentials, introspection, JWKS and userinfo are the same operation as on the
  other targets (introspection and userinfo read PostgreSQL on every request); the
  **ROPC grant is not a password login** — it accepts an app-password token and
  rejects the real password — so `oauth2_password_login` drives the **flow
  executor** instead (three client calls, about six server requests, measured as
  one operation via the new `doSteps()`), which verifies the real password
  against authentik's real hash (PBKDF2-SHA256, 1 000 000 iterations); `report.py`
  labels that one cell `protocol-variant` (new per-cell mechanism, the other
  targets' login cells are untouched). `token_refresh` is `fallback-op` there:
  authentik issues refresh tokens only from the authorization-code and device
  grants. `runner/scenario-filter-selftest.sh` now also pins the exact scenario
  set each competitor runs (new `BENCH_LIST_SCENARIOS=1` on the runner prints it
  without k6), and a new `runner/authentik-selftest.sh` (CI step "authentik
  target self-test") guards the compose credentials, the container-name lists,
  the report arithmetic and the `p3-mtls` refusal. `benchmarks/README.md` gains
  "The authentik target" with the equivalence table and the memory accounting. No
  measurement is published; run 6 is the measurement (T23.10.2).

- **`docker/docker-compose.minimal.yml` and the minimal-profile guide (G-8,
  T23.8.3).** SurrealDB plus `axiam-server` with `AXIAM__AMQP__ENABLED=false`
  and nothing else — no RabbitMQ, no Vault, no AMQP keys — in its own Compose
  project (`axiam-minimal`), on **one replica by design** (no `deploy.replicas`,
  a fixed container name that refuses `--scale`, the reason in a comment),
  with healthchecks, a **30 s stop grace period**, and the **GDPR audit
  dead-letter file on a named volume** (`AXIAM__GDPR_AUDIT_DLQ_FILE`; a
  one-shot `volume-init` hands both volumes to uid 65532). `just minimal-up`,
  `minimal-down` and `minimal-clean` mirror `dev-up`; `minimal-up` mints the
  secrets the profile needs under `docker/.secrets/` (database credentials, JWT
  keypair, pepper, email, GDPR, MFA, federation, PKI and OPAQUE keys).
  `docs/deployment/README.md` gains the minimal profile's operating guide: how
  to run it, what a restart loses in audit terms (deliveries without a terminal
  row, a lost `ExportReady` mail, SSF events), the orderly stop and its grace
  period, the dead-letter file and how to replay it into the trail, external
  audit producers to stop before switching, when to choose it, and the steps to
  move to and from the full profile. The website's Operate → Deploy page carves
  the minimal profile out of its "stateless, scale horizontally" passage and
  gains a "Minimal profile (no broker)" section;
  `AXIAM__GDPR_AUDIT_DLQ_FILE` leaves the configuration-coverage exemption
  table now that it is documented.
- **Resting footprint, measured and published (G-8, T23.8.3).** At rest, not
  under load, on a freshly migrated empty datastore, as the median resident set:
  **207.3 MiB** for the minimal stack (server 120.7 + SurrealDB 86.6) against
  **330.9 MiB** for the full one (server 130.3 + SurrealDB 86.0 + RabbitMQ
  114.6) — about 124 MiB, 37 %, for the broker. The server ran as the native
  release binary, not as an image; method, raw samples and the script are in
  `benchmarks/resting-footprint/`, and `benchmarks/PUBLIC_BENCH_ANALYSIS.md` §5
  gains the row with its caveats (not comparable with the under-load figures).
  The Zitadel comparison's whole-stack cell and change log carry a dated note.

- **Minimal profile — AXIAM without a broker (G-8, T23.8.1, D-59).**
  `AXIAM__AMQP__ENABLED=false` (default `true`) runs AXIAM with SurrealDB only:
  no RabbitMQ connection and no topology, and neither `AXIAM__AMQP__URL` nor the
  AMQP signing key is required (the refusal of a missing key stands unchanged
  for `true`). **Single-instance by definition**, enforced at boot by a
  **singleton lease** in the datastore (schema **v83**, `minimal_profile_lease`:
  TTL 30 s, renewed every 10 s; a boot that finds another instance's live lease
  waits up to 45 s and then refuses; an instance whose renewal finds the lease
  taken stops in order and exits non-zero; an orderly stop releases it). Two more boot refusals,
  each naming the switch and the fix: the decision-cache broadcast
  (`AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true`) and **any enabled
  reactor registration in the datastore, in any tenant** (a `fail_closed` reactor
  with no transport would deny logins). Not started: the asynchronous
  authorization consumer, the external audit-ingestion consumer, the reactor
  transport, the cross-replica cache invalidation. Webhooks, SSF push, outbound
  SCIM, CIBA ping and transactional mail run on **in-process bounded queues**
  (1 024 per kind) with the same deliverers, the same retry policy
  (`AXIAM__<KIND>__MAX_ATTEMPTS` and the backoff variables), the same outcome
  table and the same audit rows as the AMQP path — a dead letter is the audit
  row only, and **queued messages and mail are lost on restart**. At runtime,
  enabling a reactor registration answers **`409`** naming the profile (the
  build that composes no transport keeps `503`), the gRPC reactor administration
  answers `FAILED_PRECONDITION`, and `GET /health` gains `profile`
  (`"full"` | `"minimal"`) and, in `minimal`, `unavailable`
  (`reactors`, `amqp_authz`, `amqp_audit_ingestion`,
  `decision_cache_broadcast`) — additive; `sdks/openapi.json` regenerated. The
  composition root is now `axiam_server::boot::serve`, generic over the
  datastore connection, so a test boots the whole server with no broker over the
  embedded engine and runs a login, a webhook delivery and an SSF push through
  it. See *Minimal profile (no broker)* in `docs/deployment/README.md`.
- **CIBA — client-initiated backchannel authentication, complete (G-7, T23.7.1 –
  T23.7.3; contract 1.58).** AXIAM is an OpenID Connect CIBA Core 1.0
  authorization server in poll and ping modes (no push), with signed
  authentication requests and the FAPI-CIBA client: `POST /oauth2/bc-authorize`,
  the CIBA grant at the token endpoint, the user's approval on the console after
  a full sign-in (with step-up) and an approval e-mail, the ping on the shared
  outbound dispatcher, rate-limit and lockout coverage of the grant. The three
  entries below are the server work; this one is the rest. **Contract §33** (CIBA,
  the client's half: `ciba_initiate`, `ciba_poll`, `ciba_await` and
  `ciba_handle_ping`, the server rules an SDK can observe, error mapping,
  `Sensitive<T>` for `auth_req_id`, `client_notification_token` and the signed
  request's key material, `ciba_initiate` never retried, sixteen required tests
  per SDK) is **contract 1.58**: additive, SHOULD in the seven full-surface SDKs
  and MAY in the other four, with no operation added to the management registry
  (190 across 28). **§21.3.1 vector A is amended in place**: the discovery
  document's `mtls_endpoint_aliases` has a seventh member,
  `backchannel_authentication_endpoint`, so an SDK whose test pinned the six keys
  must re-vendor `CONTRACT.md` and update the pin (the post-merge SDK fan-out, D-35,
  carries both). **Website:** the *Integrate* page "CIBA (backchannel
  authentication)" (registering a client, the request, approval and step-up,
  polling and `slow_down`, ping, tokens, limits and lockout, what is not
  supported), linked from the OAuth2 and FAPI pages, and the contract anchors
  at 1.58. **Tests:** `frontend/e2e/ciba.spec.ts` drives poll mode end to end
  through the real approval page (tokens carrying the approval's evidence,
  denial, a second redemption refused, expiry, `slow_down` growth, a request for
  nobody, a multi-factor request a password session cannot approve, refused
  parameters, and the limiter counting failed client authentications at
  `bc-authorize` — the Keycloak 26.7.x class); the e2e stack lowers
  `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_MIN` to 20 so the limiter can be
  exhausted quickly (the shipped default stays 60). Ping mode end to end is the
  Rust test `ciba_ping_flow_test` (the approval route, the production deliverer
  through its test seam, a loopback receiver, then the client's redemption):
  a compose receiver cannot satisfy the outbound guard (`https`, a publicly
  routable address, a certificate from the Mozilla roots) without weakening it.

- **CIBA — user approval, e-mail notification and ping mode (G-7, T23.7.2).**
  The user's half of a backchannel authentication request, and the client's
  notification that it was decided. **Approval API** (the device grant's user
  routes' neighbours: a signed-in human session and the CSRF check):
  `GET /api/v1/ciba/requests/{request_id}` returns what the page shows (client
  name, scopes, `binding_message`, the requested authentication classes, expiry
  and the `version` to send back — never the `auth_req_id`), and
  `POST …/approve` / `POST …/deny` decide, conditional on that version. A request
  that is unknown, another user's, expired, already decided or changed since it
  was read is one `404`; a request that asks for a class the session has not
  achieved answers `403 step_up_required` naming it (the page sends the user
  through the existing login hop and back). Each route has its own rate-limit
  bucket under the new `AXIAM__RATE_LIMIT__CIBA_APPROVAL_PER_MIN` (default 30,
  never moved by a profile). Both decisions are audited (`ciba.approved`,
  `ciba.denied`: user, request, client, mode and the `acr` achieved — never the
  `binding_message`). **Console page** `/ciba/approve?request_id=…`: shows the
  client, scopes and binding message (as text), approves or refuses, offers the
  step-up, and says one thing for every request that cannot be decided; a
  signed-out visitor following the mail link is brought back to it after signing
  in. **E-mail notification:** a stored request for a user who may sign in sends
  one `ciba_approval` mail (built-in template, customisable per organization or
  tenant — schema **v82** admits the kind) with the client's name, the binding
  message and a link to the page by record id — never the `auth_req_id` or any
  token; at most three a minute per user whatever the clients asking, so a flood
  of `bc-authorize` requests cannot become a flood of prompts. **Ping mode:** an
  approval or a refusal of a ping-mode request queues one message on the new
  `ciba_ping` kind of the shared outbound dispatcher (`axiam.ciba_ping`,
  `.retry`, `.dlq` with the seven-day TTL; retry variables
  `AXIAM__CIBA_PING__MAX_ATTEMPTS`, `…__BACKOFF_BASE_MS`, `…__BACKOFF_CEILING_MS`,
  defaults 5, 5000, 3600000) holding only the request's record id and tenant; the
  deliverer re-reads the request and the client, opens the sealed credentials and
  sends `POST {"auth_req_id": …}` with `Authorization: Bearer
  <client_notification_token>` to the client's notification endpoint through
  `guarded_fetch_no_redirect` (`https`, no internal address, a redirect is never
  followed): `2xx` delivered, a redirect, 408, 429, 5xx or no answer retried,
  any other `4xx` dead-lettered. `axiam.ciba_ping` is in AsyncAPI.

- **CIBA — Client-Initiated Backchannel Authentication, core (G-7, T23.7.1).**
  OpenID Connect CIBA Core 1.0, poll and ping modes (push is not offered). A
  client that already knows whom it wants to authenticate calls the new
  **`POST /oauth2/bc-authorize`** (also under `/t/{tenant_id}`), authenticating
  exactly as at the token endpoint (the registered method decides; D-17 applies
  to `fapi2` rows), with `scope` (must include `openid`), exactly one of
  `login_hint` (username or e-mail) or `id_token_hint` (an ID token this
  server issued to this client), an optional `binding_message` (at most 64
  printable characters), `requested_expiry` (30–600 s, default 300),
  `acr_values` and RFC 8707 `resource`; a ping-mode client also sends
  `client_notification_token`. The answer is `auth_req_id` (256 bits, stored
  only as its SHA-256), `expires_in` and `interval` (5 s). `login_hint_token`,
  `user_code` and `request_uri` are refused `invalid_request`; CIBA Core §13's
  `invalid_binding_message` is new. **A hint
  naming nobody, a user who may not sign in or a user under brute-force lockout
  is answered exactly like a real one** and the request simply expires —
  `unknown_user_id` is never sent, so the endpoint is not a user oracle. The
  token endpoint accepts `grant_type=urn:openid:params:grant-type:ciba` with
  `auth_req_id`: `authorization_pending`, `slow_down` (the interval grows by 5 s
  per early poll, to 60 s, as for the device grant), `access_denied`,
  `expired_token`, and `invalid_grant` for another client's or tenant's,
  unknown or already-redeemed `auth_req_id`; redemption is single-use on the X6
  two-layer arbiter, and the account is re-read after it (status and lockout).
  Tokens carry the approval's evidence: the ID token's `auth_time`, `acr` and
  `amr`, the access token's `sid` naming the approving session, and a refresh
  token (for a client holding `refresh_token`) with the same snapshot. New
  pending-request store (schema **v80**, `ciba_request`; a ping-mode request's
  `auth_req_id` and notification token sealed under `pki_encryption_key`, so
  ping needs that key), swept by the new `ciba_request` job on `/health/jobs`
  and removed with its user (erasure) and tenant. The approval service API the
  identity pages will call (T23.7.2) is in `axiam_oauth2::ciba::CibaService`
  (`lookup_for_approval`, `approve`, `deny`), every transition conditional on the
  version read and on the request's own user; the user-notification port is
  `CibaUserNotifier` (no notifier is wired yet). **Client metadata:**
  `backchannel_token_delivery_mode` (`poll`/`ping`) and
  `backchannel_client_notification_endpoint` (ping only, under the webhook
  outbound URL policy) on `POST`/`PUT /api/v1/oauth2-clients` and RFC 7591/7592
  registration (the CIBA grant only with an initial access token, never
  anonymously; a CIBA-only registration needs no redirect URI);
  `backchannel_user_code_parameter: true` is refused; a CIBA client must be
  confidential. Discovery, in both issuer forms, gains
  `backchannel_authentication_endpoint`,
  `backchannel_token_delivery_modes_supported` (`poll`, `ping`),
  `backchannel_user_code_parameter_supported: false`,
  `backchannel_authentication_request_signing_alg_values_supported` (`PS256`,
  `ES256`, `EdDSA`) and the grant type, and `mtls_endpoint_aliases` gains a
  seventh member, `backchannel_authentication_endpoint` (a `tls_client_auth`
  client authenticates there). **Signed authentication requests and the
  FAPI-CIBA client (D-61).** `backchannel_authentication_request_signing_alg`
  (`PS256`, `ES256` or `EdDSA`) is accepted at the admin API and RFC 7591/7592
  registration with exactly one of `jwks`/`jwks_uri` (an inline `jwks` must
  hold a key of that algorithm), stored (schema **v81**) and echoed. A client
  that registered it must send **every** request as a signed `request` JWT
  (CIBA Core §7.1.1) under exactly that algorithm, verified against its
  registered keys; one that did not cannot send one. The JWT must carry `iss`
  (the client id), `aud` (the issuer, deployment or tenant-path form, string or
  array), `exp`, `nbf`, `iat` and `jti`; `exp - nbf` is at most 60 minutes and
  `nbf` at most 60 minutes old (FAPI-CIBA), and the `jti` is single-use (the
  proof-replay table, kind `ciba_request_object`). The request's parameters come
  from the JWT only — any authentication-request parameter beside `request` is
  refused — and every failure is `invalid_request` describing it. A `fapi2`
  client may hold the CIBA grant only with signed requests (and, as for every
  grant, `tls_client_auth`/`self_signed_tls_client_auth`/`private_key_jwt` and
  sender-constrained tokens), must send a `binding_message`, and in ping mode a
  `client_notification_token` of at least 22 characters. **Rate
  limits:** the new `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_MIN` (default 60;
  `gateway` 600, `mesh` 6000) is the endpoint's own bucket, keyed like
  `/oauth2/token`, plus a per-client bucket after authentication and a fixed
  three notifications per user per minute; the CIBA grant is counted by
  `TOKEN_PER_MIN` like every grant, and client-authentication failures at
  either endpoint are audited as `oauth2.client_auth_failed`. Every stored
  request is audited as `oauth2.ciba_initiated`. `sdks/openapi.json` is
  regenerated; the contract section (§33), the SDK helper and the website page
  follow in T23.7.3.

- **Outbound SCIM provisioning (G-6, T23.6.1 – T23.6.4, contract 1.57).** A
  tenant administrator can register downstream SCIM 2.0 service providers
  (**targets**) and AXIAM pushes the tenant's user and group lifecycle to them,
  with reconciliation. T23.6.1 added the model (schema v79: `scim_target`,
  `scim_target_link` and `scim_target_state`; the credential, a bearer token or
  an OAuth 2.0 client secret, sealed with AES-256-GCM under
  `pki_encryption_key`, write-only); T23.6.2 the lifecycle-to-SCIM translation
  and delivery on the shared dispatcher; T23.6.3 the nightly and on-demand
  reconciliation, the dead-letter notification (`scim_delivery_failed`) and
  erasure propagation. **T23.6.4 adds the management surface:**
  `GET`/`POST /api/v1/scim-targets`, `GET`/`PUT`/`DELETE
  /api/v1/scim-targets/{id}` and `POST /api/v1/scim-targets/{id}/reconcile`
  (`202` when the run was claimed, `409` while one holds the claim or the
  target is disabled), for human administrators only (a service-account token
  is `401`) under the new permissions `scim_targets:read` and
  `scim_targets:write`. `GET` returns the target with its delivery state (last
  success and failure, a fixed-vocabulary reason, consecutive failures,
  dead-lettered total, last reconciliation) and **never the credential**. Every
  write is validated: `base_url` and `token_url` under the webhook outbound
  address policy (https, no private or local address), a group scope of 1 to
  100 groups of the tenant, bounded name, client id and credential. **The
  credential is bound to its URL:** moving it (`base_url` of a bearer target,
  `token_url` or `base_url` of a client-credentials one — the access tokens the
  secret yields go to `base_url`) or switching the authentication kind
  without supplying it is `400` naming the field; an update is conditional on
  the version it read (`409` when overtaken); a credential without
  `pki_encryption_key` is `503`. Creating a target enabled, or enabling one,
  starts a reconciliation. Deleting a target removes its links and state and
  **does not deprovision anything downstream.** New setting
  `AXIAM__RATE_LIMIT__SCIM_TARGET_ADMIN_PER_MIN` (default 30, one bucket per
  write route, never moved by a profile), documented in
  `docs/deployment/rate-limit-sizing.md` and the deployment guide. The admin
  console gains **Identity → SCIM Targets** (list with delivery state, create
  and edit with the auth-kind switch, a write-only credential field that is
  required when the URL or kind changes, a group scope picker, the deprovision
  policy, delete with the downstream warning, *Reconcile now*). `CONTRACT.md`
  gains **§31 Outbound SCIM targets** (contract **1.57**, non-breaking: SHOULD
  as part of §27, in all eleven SDKs; `ScimTargetInput.credential` is
  `Sensitive<T>`); `sdks/openapi.json` and `sdks/management-registry.json` are
  regenerated (190 operations across 28 namespaces, the new `scim_targets`
  namespace). The website's *Integrate* section gains **Outbound SCIM
  provisioning**, and the three competitor comparisons now record the feature.
  **The SDKs must re-sync `CONTRACT.md`, `openapi.json` and
  `management-registry.json` from the merged commit.**

- **Outbound SCIM provisioning: reconciliation, dead-letter notification and
  erasure propagation (T23.6.3, G-6, D-58).** A `scim_reconcile` job in the
  cleanup loop (listed in `/health/jobs`) reconciles each enabled target once a
  day, claimed in the datastore so replicas do not double-run it: it re-queues a
  reference for every in-scope user and group and every linked resource, pages
  the downstream `GET /Users` and `/Groups` (100 per page, at most 100 pages and
  five minutes per run, through the same no-redirect SSRF guard and credential
  path as delivery), clears the digest of a resource whose downstream copy
  differs, drops the link of one that is gone (it is created again), and
  deprovisions a downstream account whose `externalId` is an out-of-scope,
  disabled or erased user **of this tenant**. A downstream account with no
  `externalId`, a foreign one, or another tenant's user is never touched. A
  new `scim_delivery_failed` notification event (the console's rule editor lists
  it) mails a tenant's rule recipients when a delivery is dead-lettered. GDPR
  erasure reaches the downstream as `DELETE`: the link row (ids and a digest
  only) survives the erasure cascade until that `DELETE` succeeds, a refused one
  leaves it `deprovisioned` with `erase_pending`, and reconciliation retries it.
  `NotificationEventType` gains `scim_delivery_failed`, so `sdks/openapi.json`'s
  enum does too. Documented in the erasure section of
  `docs/compliance/gdpr-compliance.md`.

- **Outbound SCIM provisioning: the source, the client and the deliverer
  (T23.6.2, G-6, D-57).** AXIAM can now push user and group changes to a
  downstream SCIM 2.0 service provider. Management routes, the console and the
  contract section follow in T23.6.4, so nothing registers a target yet.
  `ProvisioningSink` is a new core port the SurrealDB user and group repositories
  call after every committed write of a provisioned field (user create, update of
  username, email, status or name metadata, delete, erasure, the directory-account
  methods and the deletion-request status write; group create, rename, delete and
  every membership change), so the REST API, SCIM inbound, directory sign-in and
  sync, federation just-in-time provisioning and GDPR erasure are all covered
  without touching their call sites; login bookkeeping reports nothing. A
  `ScimProvisioner` turns each report into one **reference**
  (`{resource_type, axiam_id}`, no attribute of a person) per enabled target on a
  new `scim_push` kind of the shared outbound dispatcher (`axiam.scim_push`,
  `.retry`, `.dlq`; the dead-letter queue discards after seven days). The
  `ScimPushDeliverer` re-reads the target, the resource and its link at every
  attempt and sends `POST /Users`, `PATCH` (replace on the mapped attributes
  only, skipped when the digest of the representation is unchanged) or `DELETE`
  (always for an erased user; for a deprovisioned one when the target's policy
  says so, else `active=false`); groups carry `displayName`, `externalId` and the
  linked members. Every request, the OAuth2 token request included, goes through
  the no-redirect SSRF guard; a redirect is never followed. New environment
  variables `AXIAM__SCIM_PUSH__MAX_ATTEMPTS`, `AXIAM__SCIM_PUSH__BACKOFF_BASE_MS`
  and `AXIAM__SCIM_PUSH__BACKOFF_CEILING_MS` (defaults 5, 5000, 3600000),
  documented on the Integrate page; `axiam.scim_push` is in `docs/api/asyncapi.yml`.

- **SAML 2.0 IdP end-to-end tests: a `samael` reference SP and a real Keycloak
  (T23.2.7, G-2).** Tests only; no server, contract or OpenAPI change.
  `saml_idp_e2e_test` drives the production route table with a service provider
  built from `samael`'s SP-side API (it builds and signs the `AuthnRequest`,
  parses and validates the `Response`): SP-initiated login on the HTTP-POST binding
  (signed request, IdP credential issued through the administrator route) and on
  HTTP-Redirect (`signed_redirect`), IdP-initiated login, the attribute mapping,
  the pairwise `NameID` (stable for one SP, different for two SPs and two users),
  single logout from a `samael`-built `LogoutRequest` on both bindings (session
  revoked, `GET /oauth2/revocations` shows it, the `LogoutResponse`'s detached
  signature verifies under `samael`'s URL verifier), a replayed `AuthnRequest` ID,
  an ACS URL outside the registry and its near-miss spellings, the D-20 `404` on
  metadata, SSO and SLO for a tenant without the feature (and the routes absent
  in a build without `saml`), and `samael` refusing the same response under each
  wrong expectation. `saml_idp_keycloak_roundtrip_test` (`#[ignore]`, run by CI's
  compose job beside the X4 step) imports AXIAM's IdP metadata into a real
  Keycloak realm, registers Keycloak's exported SP metadata through
  `parse_sp_metadata` and `create_service_provider`, and carries a broker login
  both ways through a cookie-jar client, on both AuthnRequest bindings, signed:
  Keycloak accepts the response, issues tokens whose claims are the SAML
  attributes, and links the pairwise `NameID`; a tampered response, a response for
  another browser's request and a replay are refused. `saml_idp::test_support`
  re-exports `samael` and `openssl` so the harness needs no new dev-dependency.
  **SP metadata normalisation (D-54):** `parse_sp_metadata` now reads SP metadata
  that `samael` could not type. On the libxml tree, after every byte-level refusal,
  an ISO-8601 `cacheDuration` on the `SPSSODescriptor` is dropped and an
  `AssertionConsumerService` with no `index` is given the lowest unused
  non-negative index in document order, each with a draft warning that names it;
  an `index` that is present but invalid is still refused, and a document needing
  neither yields the same draft as before. The website's SAML IdP page now says an
  SP must sign with a SHA-256 or stronger digest (`samael`'s default signature
  template uses SHA-1, which AXIAM refuses).

- **Shared Signals Framework transmitter: push and poll delivery and the event
  sources (T23.5.3, G-5, D-48, D-49, D-51, D-52, D-53, contract §32.6).** AXIAM now
  transmits. **Push (RFC 8935)**: the `SsfPush` deliverer
  (`axiam_oauth2::ssf_delivery`) runs on the shared outbound dispatcher with
  queues of its own (`axiam.ssf_push`, `.retry`, `.dlq`; retry variables
  `AXIAM__SSF_PUSH__MAX_ATTEMPTS`, `…__BACKOFF_BASE_MS`,
  `…__BACKOFF_CEILING_MS`, documented beside the webhook ones). Each attempt
  re-reads the stream and signs against it as it is then — gone or disabled
  dead-letters, paused or now poll goes to the buffer — and POSTs
  `application/secevent+jwt` with the stored `Authorization` header **only through
  `axiam_pki::ssrf::guarded_fetch_no_redirect` with `allow_private = false`**: one
  resolved, address-pinned hop, a `3xx` returned as the answer and **never
  followed** (so neither the SET nor the credential can reach a host nobody named),
  a 64 KiB response cap. **Response mapping (D-49, D-53)**: `2xx` is delivered; a
  `400` with an RFC 8935 `err` dead-letters with the code in the
  `ssf_push.delivery_failed` audit row, `401` and `403` dead-letter, **any other
  `4xx` except `404`, `408` and `429` dead-letters with the reason
  `HTTP <status>`** (it will not change on retry); `404`, `408`, `429`, `5xx`,
  timeouts, connection failures, a `3xx` and anything else retry. The push
  dead-letter queue carries a **seven-day `x-message-ttl`** (a dead-lettered
  message holds an unsigned subject); the webhook queues' arguments are unchanged.
  **Poll (RFC 8936)**: `POST /ssf/v1/poll/{stream_id}` with the receiver's
  `ssf.manage` token (the same one `404` for a stream that is not its own):
  `maxEvents` clamped to 100, `returnImmediately` honoured (a long poll waits at
  most 30 s, and **at most one long poll waits per stream per instance** — a
  second concurrent one answers at once), `400` on a push stream, a negative
  `maxEvents` or more than 1 000 `ack` / 100 `setErrs` entries, `413` over 32 KiB,
  `ack` deletes exactly that stream's rows, each `setErrs` entry deletes its row
  and writes an `ssf_stream.poll_set_error` audit row with the RFC 8935 code, SETs
  are signed at poll time, a paused or disabled stream answers an empty `sets`;
  bucket `ssf_poll` under `AXIAM__RATE_LIMIT__SSF_PER_MIN`. The **buffer** keeps at
  most 1 000 events per stream (the oldest dropped), seven days at most, one row
  per `jti`; its expiry sweep `ssf_event_buffer` is on `/health/jobs`. Resuming a
  paused push stream releases its held events oldest first. **Event sources** are
  emitted where the change happens, through one emitter (a no-op with
  `ssf_enabled` off, one `txn` per operation): `session-revoked` from the session
  repository's `invalidate`, `invalidate_user_sessions` and
  `invalidate_user_sessions_except` (never from a redemption or expiry, whether or
  not the revocation feed is on); `credential-change` from a password change and
  reset, a SCIM password write, an OPAQUE registration, TOTP confirmation, an MFA
  reset or method deletion and a WebAuthn registration (`Passkey` →
  `fido2-platform`, `SecurityKey` → `fido2-roaming`) — **never `x509`**, because
  certificates bind only to service accounts and an SSF subject is a user;
  `account-disabled` and `account-enabled` from an administrator's status write,
  SCIM `active` and (disable only) a directory deactivation — the directory sync
  never re-enables an account; `account-purged` from `DELETE /api/v1/users/{id}`,
  **SCIM `DELETE /Users/{id}`** and the GDPR erasure, with the subject captured
  before the write; and **`assurance-level-change`** from the honour lane's
  step-up: schema **v78** adds `ssf_step_up`, a ten-minute record (one per tenant
  and user, the latest replacing) of the session the user held and its `acr`,
  written when an authorization request interacts for a step-up with a valid OP
  session and consumed once by the return leg that arrives with a new session of
  the same user, which emits only when the `acr` differs (`previous_level`,
  `change_direction`, `initiating_entity: user`); nothing travels in `return_to`.
  The record's expiry sweep `ssf_step_up` is on `/health/jobs`; the row goes with
  its tenant and with both user-erasure paths. The stream-updated announcement of
  a status change obeys the tenant's `ssf_enabled` like every other producer.
  `openapi.json` regenerated (the poll route, tag `ssf-receiver`); the management
  registry is unchanged apart from its spec digest. **Contract §32 amended in
  place before 1.56 ships (no version bump)** to say all of the above; the
  `axiam.ssf_push` queues are in `docs/api/asyncapi.yml`.
- **The Shared Signals Framework transmitter in the documentation (T23.5.4,
  G-5, contract 1.56 §32).** The website's *Integrate* section gains **Shared
  Signals (SSF) transmitter**, after the SAML identity provider page: the six
  CAEP and RISC events as EdDSA-signed SETs with no `exp` that a receiver must
  de-duplicate on `jti`; the disable-only `ssf_enabled` switch and discovery in
  both issuer forms (an empty `404` when off); registering a receiver
  (`ssf_streams:read` / `ssf_streams:write`, the deployment-unique audience,
  `subject_format`, the write-only sealed `Authorization` header that never follows
  the endpoint to another origin, `receiver_client_id` with `ssf.manage`); the
  receiver's `/ssf/v1/*` API, what it may change, the statuses and who may set
  them, verification every 60 s, poll and push including which responses retry and
  which dead-letter; what triggers each event; the buffer and dead-letter bounds,
  the retry and rate-limit variables; privacy; and what is not supported. The
  settings page lists `ssf_enabled`, and the revocation-feed, back-channel logout
  and *Federation* pages link to it. The SDK receiver helper and the `ssf`
  management namespace remain the post-merge fan-out of D-35.

- **The SAML identity provider in the documentation: website page, contract
  amendment (T23.2.9, G-2, contract 1.55).** The website's *Integrate* section
  gains **AXIAM as a SAML identity provider**: what a per-tenant IdP offers
  (SP-initiated and IdP-initiated sign-on, HTTP-Redirect and HTTP-POST, always-signed
  assertions, a pairwise persistent `NameID`, a signing credential issued by the
  tenant's CA with issue / promote / retire rotation, single logout), how to
  register a service provider (the console's *SAML Service Providers* page or the
  §29 API; metadata import is a parse to a draft), the metadata and endpoint paths
  under `/saml/v2/{tenant}`, the `saml` build feature and the layered
  `saml_idp_enabled` switch (an empty `404` when off), `AXIAM__AUTH__SAML_PAIRWISE_KEY`
  (never change it), the rate-limit buckets, and what is not supported (assertion
  encryption, signed metadata, the artifact and SOAP bindings, a SAML logout chain
  from non-SAML logouts). The *Federation — SAML & OIDC* page no longer reads as
  though AXIAM were only a service provider and links to it, the settings page lists
  `saml_idp_enabled`, and the generated API index now carries the `saml` operations
  (and places the `ssf` tags the generator refused). **Contract 1.55, amended before
  it ships, no version bump:** §29's status text and §29.10 say the routes have
  landed and that all eleven SDKs (Kotlin, Swift, C and C++ over REST included) are
  in scope, §29.8 gains an eighth required test (`get_idp` readiness decoding, no
  caching, the implicit tenant), and the breaking-changes log records the amendment
  with D-43's `401`. The SDK ports remain the post-merge fan-out of D-35; one
  tracking issue covers contract 1.53, 1.54 and 1.55 together.

- **Shared Signals Framework transmitter: the stream registry, SET issuance,
  the stream management API and discovery (T23.5.2, G-5, D-44 … D-52, contract
  1.56 §32).** AXIAM can now act as an SSF 1.0 transmitter of CAEP
  `session-revoked`, `credential-change` and `assurance-level-change` and RISC
  `account-disabled`, `account-enabled` and `account-purged` events; push and
  poll delivery and the event sources follow in T23.5.3, so nothing is
  transmitted yet. **Management** (namespace `ssf`, tag `ssf`):
  `GET`/`POST /api/v1/tenants/{tenant_id}/ssf/streams` and
  `GET`/`PUT`/`DELETE …/ssf/streams/{stream_id}`, permissions
  `ssf_streams:read` / `ssf_streams:write` (human-only), each write validated —
  the push endpoint held to the webhook outbound address policy, the receiver
  bound to an OAuth2 client of the tenant with the `client_credentials` grant
  and the new scope **`ssf.manage`**, the audience **unique across the
  deployment** (`409`), the push `Authorization` header write-only and sealed
  under `pki_encryption_key` (`503` without it), and never following the endpoint
  to another origin. **Receiver protocol** (tag `ssf-receiver`):
  `/.well-known/ssf-configuration?tenant_id=` and, with tenant issuer paths,
  `/.well-known/ssf-configuration/t/{tenant_id}` (one empty `404` for every way of
  having nothing to say); the SSF stream management API `/ssf/v1/stream`
  (`GET`, `PATCH`, `PUT`; `POST`/`DELETE` `403`), `/ssf/v1/status` and
  `/ssf/v1/verify`, authenticated by the receiver's client-credentials token with
  `ssf.manage`, every other stream the same `404`. **SETs**
  (`axiam_oauth2::ssf`): `typ: secevent+jwt`, EdDSA with the deployment key's
  `kid`, the tenant's issuer, the stream's audience, a 128-bit CSPRNG `jti`, no
  `sub`, no `exp`, one event; `iss_sub` subjects by default, `email` only on the
  administrator's choice and only for an address AXIAM vouches for; signed only
  at delivery for an enabled stream that carries the event. A disable-only
  layered setting **`ssf_enabled`** (default `false`) switches a tenant's
  transmitter on. `OutboundKind::SsfPush` (`ssf_push`) is declared for the push
  deliverer. Schema **v77**: `ssf_stream`, `ssf_event_buffer` and
  `security_settings.oidc_ssf_enabled`, deleted with their tenant (the buffer
  with its stream too). New rate-limit knobs `AXIAM__RATE_LIMIT__SSF_PER_MIN`
  (60, one bucket per receiver route and discovery form) and
  `AXIAM__RATE_LIMIT__SSF_ADMIN_PER_MIN` (30, one per write). `openapi.json` and
  `management-registry.json` regenerated (184 operations across 27 namespaces);
  contract 1.56 adds §32 with the optional receiver helper (`verify_set`,
  `poll`) for the seven full-surface SDKs.

- **SAML 2.0 identity provider: single logout (T23.2.4, G-2, D-37 … D-39).**
  `GET`/`POST /saml/v2/{tenant_id}/slo` (HTTP-Redirect and HTTP-POST, a
  `LogoutRequest` or a `LogoutResponse`) and the IdP-initiated trigger
  `GET /saml/v2/{tenant_id}/sso/logout`, behind `saml`, on the D-20 `404`, with
  the `end_session_per_min` preset in the buckets `saml_idp_slo` and
  `saml_idp_sso_logout`. **Every message from an SP is signed by its registered
  certificate**: the Redirect binding over the exact query octets (RSA-SHA-2
  only), the POST binding as the root's one enveloped signature verified on that
  node (SHA-1 refused); `verify_signed_xml` is never called; an SP with no
  certificate cannot initiate, and its `LogoutResponse` only advances the chain.
  A verified request ends **whole AXIAM sessions** — the ones the SP participates
  in, by (tenant, SP, `SessionIndex`) and then the `NameID` value and format, or
  by `NameID` when it names no index — through OIDC back-channel logout and then
  `AuthService::logout`, so `GET /oauth2/revocations` shows them; no match is
  `Success`. The other SPs of those sessions are then told, one at a time
  through the browser, a signed `LogoutRequest` on their registered binding (a
  **detached** query signature on Redirect, so no XML signature exists to harvest;
  an enveloped one on POST, re-verified, through the one auto-post page); each
  answer is consumed once on the X6 arbiter and only from the SP the request went
  to; at most 32 SPs; the run ends with a signed `LogoutResponse` (`Success`, or
  `PartialLogout` when an SP has no endpoint, answered unsigned or not `Success`,
  or the cap was hit) to the initiator. AXIAM signs nothing for an unverified
  request. Every answer to a verified message clears every OP-cookie copy and the
  API cookies; `/slo` never reads the OP cookie. The trigger answers `403` to
  `Sec-Fetch-Site: cross-site`. Audit `saml_idp.logout` (never a `NameID`). The
  IdP metadata now advertises `SingleLogoutService` for both bindings. Schema
  **v76**: `saml_sp_session` (the participant record) and `saml_logout_run` (the
  replay guard and the chain); both are deleted with their tenant, their SP and
  by both erasure paths, swept by the cleanup scheduler and listed on
  `/health/jobs`. Threat model **2.26.0**: **T-366, T-370 … T-379, T-381 … T-384
  and T-312 Mitigated**, each citing its tests (369 mitigated, 15 open); T-380
  stays open, accepted. No contract or OpenAPI change: these are browser routes.

- **SAML IdP registry and credential routes, IdP metadata and SP metadata import
  (T23.2.5, G-2, contract §29).** Eleven routes under
  `/api/v1/tenants/{tenant_id}/saml`, OpenAPI tag `saml`, **compiled into every
  build** and independent of the tenant's `saml_idp_enabled` (only
  `parse-sp-metadata` needs `samael` and answers `503` without it):
  `get_idp` (the IdP's URLs, whether SAML is available and enabled, the credential
  slots), the service-provider registry (list with `search`, create, get, replace,
  delete) and the signing credential (list newest first, issue, promote, retire).
  Every SP write runs the validator and then the four D-42 refusals —
  `encrypt_assertions: true`, an `sp_signing_cert_pem` the SSO endpoint cannot use
  (undecodable, RSA under 2048 bits, anything but RSA or ECDSA on P-256, P-384 or
  P-521), a changed `entity_id` on update, an `allowed_groups` entry outside the
  tenant — each a `400 validation_error` naming the rule; a repeated `entity_id`
  and an occupied slot are `409 conflict`, and an occupied slot is refused
  **before any key is generated**. **Promote** retires the `active` credential
  (its key destroyed) and makes `next` active in **one transaction**, refused
  unless the id is the current `next` and inside its validity window (`409`);
  of two concurrent promotions one wins. **Retire** works on `next` and `active`
  and is idempotent. `SamlIdpCredential` is a response type of its own — no key,
  no ciphertext, no custody. **`parse-sp-metadata` parses to a draft and never
  writes** (D-41): exactly one of `metadata_xml` and `metadata_url`; a URL is
  fetched once, only through the SSRF guard (`https`, no loopback, private,
  link-local or cloud-metadata address, every redirect hop checked); a document
  with any DTD or entity declaration, a non-UTF-8 encoding, over 512 KiB, an
  aggregate or anything but one `EntityDescriptor` with one SAML 2.0
  `SPSSODescriptor` is refused with one of three generic messages that never
  carry the document, a status line or an address; the document's own signature
  is reported, not evaluated; `encrypt_assertions` is never set. **`GET`/`HEAD
  /saml/v2/{tenant_id}/metadata`** serves the tenant's IdP metadata (D-40):
  unauthenticated, unsigned, a fixed escaped template with the `active` and then
  the `next` signing certificate and no encryption key, `Cache-Control: public,
  max-age=3600`, a strong `ETag` and `304`; a tenant with SAML off, an unknown or
  non-canonical id, no publishable credential and a build without SAML all answer
  the same empty `404`. The permissions are `saml_sp:read`, `saml_sp:write` and
  `saml_idp:credential` (human principals only: a service-account token is
  refused with the `401` every human-only route answers; another tenant's id is
  `403`); the seven writes each have a per-IP bucket under
  `AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN` (default 30, never preset), the
  metadata route the `end_session_per_min` preset in the bucket
  `saml_idp_metadata`; seven audit actions (`saml_sp.created`, `.updated`,
  `.deleted`, `.metadata_parsed`; `saml_idp.credential_issued`, `.promoted`,
  `.retired`) carry the actor, ids, the names of what changed and fingerprints,
  never a certificate or a document. Deleting a service provider now removes what
  the datastore holds for it (its pending sign-on requests) in the same
  transaction. `idp_entity_id`, `idp_sso_url` and `idp_slo_url` moved out of the
  `saml`-gated module. `openapi.json` and `management-registry.json` are
  regenerated (179 operations, 26 namespaces). Threat model: T-357 … T-365,
  T-367 … T-369 and T-309 are Mitigated (353 mitigated / 31 open); T-366 stays
  open until T23.2.4 adds the rows its cascade must also remove. A revoked or
  expired issuing CA is now a `400` on `issue_idp_credential` (the generic
  certificate routes keep their existing answer).

- **Directory e2e against a real OpenLDAP and a real Samba AD DC (T23.3.6,
  G-3).** The oracle for the whole G-3 stack: `docker/docker-compose.directory.yml`
  brings up OpenLDAP (slapd with ppolicy, TLS 1.2 floor, a read-only bind
  account) and a Samba Active Directory domain controller, each seeded with
  people, a direct and a nested group, a disabled entry (ppolicy's permanent lock
  `000001010000Z`; `userAccountControl` bit `0x2`) and an entry whose name holds
  filter metacharacters, on fixed private addresses so the T23.3.7 address guard
  and its allow-list are exercised rather than bypassed. The CA, both
  certificates and every password are generated at run time by
  `scripts/gen-directory-e2e-secrets.sh` into the gitignored
  `docker/.secrets/directory/`; nothing is committed. Images are pinned by
  digest. `crates/axiam-server/tests/directory_e2e.rs` (gated by
  `AXIAM_E2E_DIRECTORY=1`; without it every test prints `SKIPPED`, with it a
  missing server is a failure) configures the directory through the §30 routes
  and drives `POST /api/v1/auth/login`, the group mapper, a real authorization
  engine and `sweep_directories` against **both** servers: login with JIT
  creating the account `Active` and marked, a role on a mapped AXIAM group
  effective for the directory member, an unmapped directory group granting
  nothing, a nested group, a disabled account refused with the unknown-user
  answer, seven filter-injection payloads refused (each presented with the real
  password of the entry it would select unescaped) and the metacharacter entry
  signing in only under its exact name, a plaintext URL (and loopback, an
  unlisted private range, the metadata address) refused at config time, StartTLS
  accepted, an untrusted server certificate refused, and the sync job
  deactivating a vanished or directory-disabled user as `Inactive` with the row
  kept and its sessions revoked. New workflow `.github/workflows/directory-e2e.yml`
  runs it on `workflow_dispatch` and on pull requests touching the directory
  code. How to run it locally: `docker/directory/README.md`.

- **Directory management routes, console page and docs (T23.3.8, G-3).** The
  six §30 routes exist: `GET`/`PUT`/`PATCH`/`DELETE`
  `/api/v1/tenants/{tenant_id}/directory`, `POST …/directory/links` (wraps the
  D-28 linking function; the owner is signed out everywhere) and `GET
  …/directory/sync-status`, OpenAPI tag `directory`, the permissions
  `directory:read`, `directory:write` and `directory:link` (service-account
  tokens refused, another tenant's id `403`). **Every write** runs
  `axiam_directory::config::validate` and the address guard on the URL as
  written (a name re-pointed since the last save is caught by an unrelated
  write), each refusal a `400` naming the rule — IPv6-literal hosts, loopback,
  link-local and the metadata address, unresolvable names and unlisted private
  addresses included; **moving `url`, `start_tls`, `bind_dn` or the trust
  anchors without the `bind_secret` is a `400`** on `PUT` and `PATCH` (F4
  P23W2-01); an enabled directory and an effective `opaque_mode = required` are
  refused together in **both** directions (`409`: the directory write, and the
  tenant, tenant-override and organization settings writes); a write that
  carries a secret is `503` without `directory_encryption_key` (the response
  does not name the key; reads, `DELETE`, the sync status and a write with no
  secret still work — the repository's `update` now needs the key only to seal).
  The bind secret is write-only on exactly two request types, and these routes
  have their own JSON error handler so a body in which it has the wrong type is
  not echoed in the `400`. Audit rows `directory.config_created`,
  `directory.config_updated` and `directory.config_deleted` carry the actor, the
  names of the changed fields, `connection_moved`, `secret_replaced` and, on a
  delete or disable, the count of live directory accounts; a refusal by the
  guard or by P23W2-01 is audited with its rule; never the secret, never an
  anchor's content. New per-IP rate-limit bucket
  `AXIAM__RATE_LIMIT__DIRECTORY_ADMIN_PER_MIN` (default 30, never preset) on the
  four writes. `UserRepository::count_live_directory_accounts` is new. The admin
  console gains a per-tenant **Directory** page (view, create, replace, edit,
  delete; the secret write-only and re-asked when the URL, StartTLS, bind DN or
  trust anchors change; group-mapping table; sync status; link an account), the
  website's *Integrate* section an *LDAP / Active Directory* page, the design
  document a directory chapter, and the deployment guide a *Managing a tenant's
  directory* section — including that an entry without a usable e-mail address
  cannot be provisioned (D-29). `sdks/openapi.json` and
  `sdks/management-registry.json` are regenerated (168 operations, 25
  namespaces; `PATCH` bodies are classified `sparse`); the ports follow from
  the merge commit (§30.10).

- **SDK contract 1.55: §29 SAML service provider registration (T23.2.8,
  G-2).** The normative management surface for AXIAM as a SAML 2.0 identity
  provider, ahead of the routes (T23.2.5 implements them and regenerates
  `openapi.json` and `management-registry.json`): a §27 namespace `saml` under
  `/api/v1/tenants/{tenant_id}/saml` with eleven operations — `get_idp`;
  `list_service_providers` (paginated), `create_service_provider`,
  `get_service_provider`, `update_service_provider` (a **replacement**) and
  `delete_service_provider`; `parse_sp_metadata`, which turns an uploaded or
  server-fetched SP metadata document into a draft and stores nothing (fetched
  only through the SSRF guard, any DTD refused, nothing trusted from an unsigned
  document); and `list_idp_credentials`, `issue_idp_credential`,
  `promote_idp_credential` (one transaction: `next` → `active`, the old
  `active` → `retired`) and `retire_idp_credential`. Nothing is `Sensitive`, and
  `SamlIdpCredential` has no key member. Every write runs
  `validate_saml_service_provider`; `encrypt_assertions` and an SP signing
  certificate the SSO endpoint could not use are refused; `entity_id` is unique
  per tenant and immutable; the routes exist in every build and do not depend on
  `saml_idp_enabled` (`parse_sp_metadata` alone answers `503` without SAML);
  permissions `saml_sp:read`, `saml_sp:write` and `saml_idp:credential`; human
  principals only; a rate-limit bucket `AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN`;
  audit rows; no retry of writes; seven portable tests per SDK. Decisions D-37 …
  D-42 pin the rest of W4's SAML work: a per-SP random `SessionIndex` recorded
  before signing (closing T-312 when single logout lands), single logout's
  bindings, verification, narrow signing and revoke-then-propagate chain, the
  IdP metadata document (unsigned, `active` then `next`, the D-20 `404` without
  a credential), SP metadata import, and the credential verbs. The design
  document gains a §8e *SAML 2.0 Identity Provider* chapter. Non-breaking /
  additive; **re-sync `CONTRACT.md` for 1.55 in all eleven SDK repositories**
  from the merged commit.

- **Threat model 2.25.0 (T23.2.8, G-2).** The SAML identity provider's
  remaining elements — the SP registry store and its management routes (SP
  metadata import as an SSRF and XXE surface), the IdP metadata endpoint, and the
  single-logout endpoint with the `saml_sp_session` and `saml_logout_run` stores
  — and **T-357 … T-384**, all entered **Open**: twenty-seven because the
  controls they name are specified and not yet built (T23.2.5 and T23.2.4 close
  them, each with the tests its mitigation lists), and T-380 — a service
  provider's own session outliving an AXIAM session that ends by anything but a
  logout chain — because it is an accepted trade-off (no SAML browser back
  channel). T-309 and T-312 are amended to the decisions that close them. 384
  threats, 340 mitigated / 44 open; `threatTop` corrected to 384.

- **SDK contract 1.54: §30 directory configuration (T23.3.7, G-3).** The
  normative management surface for a tenant's LDAP / Active Directory identity
  source, ahead of the routes (T23.3.8 implements them and regenerates
  `openapi.json` and `management-registry.json`): a §27 namespace `directory` —
  `get`, `set` (replace), `update` (sparse), `delete`, `link_account` (D-28) and
  `get_sync_status` under `/api/v1/tenants/{tenant_id}/directory` — with the
  write-only `bind_secret` **`Sensitive<T>`** in every SDK from the first
  version and never returned; every write validated and run through the address
  guard (`400 validation_error` naming the rule, IPv6-literal hosts included);
  moving the connection (`url`, `start_tls`, `bind_dn`, `trust_anchors_pem`)
  without the secret a `400` (P23W2-01); an enabled directory and
  `opaque_mode = required` refused together, both ways (`409`); `503` without
  `directory_encryption_key`; the permissions `directory:read`,
  `directory:write` and `directory:link`; a rate-limit bucket
  `AXIAM__RATE_LIMIT__DIRECTORY_ADMIN_PER_MIN`; audit rows that record that the
  connection moved and never the secret; no retry of writes; six portable tests
  per SDK. No safety-valve override in this cut (§30.3 rule 7 says why). §29 is
  reserved for G-2's SAML service-provider registration. Non-breaking /
  additive; **re-sync `CONTRACT.md` for 1.54 in all eleven SDK repositories**
  from the merged commit.

- **Directory sources: the sync job (T23.3.5, G-3, D-31).** A background job on
  the cleanup scheduler (`directory_sync` in `GET /health/jobs`, last in each
  tick, one tenant at a time, only tenants whose directory is enabled) keeps
  directory accounts in step with their directory and **cannot grant anything**.
  A vanished entry or one the directory disabled (`userAccountControl` bit `0x2`
  on Active Directory; on OpenLDAP `pwdAccountLockedTime` equal to ppolicy's
  permanent-lock value `000001010000Z` — a timed lockout after failed attempts is
  **not** a disable, since an outsider could trigger it) sets
  the account **`Inactive`** — never `Deleted`, never a hard delete: sessions and
  OAuth2 refresh tokens are revoked through the repositories (so the validation
  cache and revocation feed see it), directory-sourced memberships are removed
  through the D-30 mapper (manual ones kept, decision cache flushed), and
  `account_may_act` then refuses the account on every path, which closes
  T-303's residual for passkeys and the OP cookie. The status is flipped last by
  one compare-and-set, so a failure part-way leaves the account `Active` for the
  next run. **Sync never re-enables, never creates and never links** (D-28): an
  `Inactive` account whose entry is present and enabled is reported once as
  `directory.account_reappeared` ("administrator action required"). A *full* run
  (first, every 24 h, and after any skipped account, bound hit or untrusted
  watermark) looks up every marked account by `entryUUID` or by `objectGUID`
  (the 16 little-endian octets, each escaped, through a new binary-value escaper
  in the one module that puts values into filters) and is the only run that
  concludes "vanished"; an *incremental* run every `sync_interval_secs` searches
  `(<modifyTimestamp|uSNChanged> >= <watermark>)` under `base_dn`, acts only on
  entries whose identifier belongs to a marked account, applies what it read when
  its result bound is hit (and owes a full run), and on Active Directory
  takes the watermark from the rootDSE's `highestCommittedUSN` and falls back to
  a full run when `dsServiceName` changes or no watermark is readable. Present
  and enabled accounts have their username, email and display name refreshed
  through the same cleaners provisioning uses (a colliding change is skipped and
  audited as `directory.sync_attribute_skipped`) and their group mapping applied.
  **The safety valve:** a full run that would deactivate more than 10 % of a
  tenant's directory accounts **and** at least 5 applies nothing, audits
  `directory.sync_safety_valve` once and fails `directory_sync` in job health.
  **Errors change nothing**: a full run reads every answer before it writes any,
  so an unreachable directory, a refused search or a deadline leaves every
  account as it was; an identifier that cannot be put in a filter or matches two
  entries skips that account and is never read as "vanished". State (watermark,
  server identity, last runs, last result) is one row per tenant, schema **v75**
  `directory_sync_state`, deleted in the tenant-delete transaction. There is no
  multi-replica guard (no sweep has one): every replica runs the job and every
  write is idempotent or a compare-and-set. New audit actions
  `directory.account_deactivated`, `.account_reappeared`, `.account_updated`,
  `.sync_attribute_skipped`, `.sync_user_skipped`, `.sync_safety_valve` and
  `.sync_run`; none carries a name, address or DN. `UserRepository` gains
  `list_directory_accounts`, `get_by_directory_external_id`,
  `deactivate_directory_account` and `find_identity_collision_excluding`
  (refusing defaults); `DirectoryGroupMapper` gains
  `remove_directory_memberships`. The attribute cleaners moved from `axiam-auth`
  to `axiam-core` so both callers apply one definition. Operator documentation:
  *Sync* in `docs/deployment/README.md`. No API, contract or SDK change.

- **Directory sources: group mapping (T23.3.4, G-3, D-30).** A directory user's
  groups now become AXIAM group memberships, so roles and permissions assigned
  to those groups apply to them unchanged. **An explicit mapping table only**:
  `DirectoryConfig.group_mappings`, at most 500 rows of `{ directory_group_dn,
  group_id }` stored in the tenant's `directory_config` row (schema **v74**).
  There is no match by name, prefix or wildcard and no AXIAM group is ever
  created from a directory one: a directory group called `admins` gains nothing
  unless a tenant administrator mapped it. A DN is compared after RFC 4514
  normalisation (case of types and values, spacing around the separators,
  `\,` against `\2C`, UTF-8 hex escapes, the order inside a multi-valued RDN);
  every `group_id` must be a group **of the same tenant**, checked in the
  repository's write path before anything is written, and `config::validate`
  refuses a table over 500 rows, a DN that does not parse, a repeated pair, and
  — for OpenLDAP, whose groups are found by search — a table with no
  `group_base_dn`. **The mapping owns only its own memberships**: every
  `member_of` edge it writes carries `source = directory` (new column, schema
  v74; an edge without it is manual), each application adds the missing mapped
  memberships and removes the directory-sourced ones the directory no longer
  backs, and a manual membership — of the same group or another — is never
  touched and never duplicated. Resolution runs over the service-bound pooled
  connection, never the user's bind: Active Directory reads `memberOf` off the
  entry (and each group's own), OpenLDAP searches `group_base_dn` for
  `(&<group_filter>(<member attribute>=<DN>))` with the DN entering the filter
  only through the RFC 4515 escape; nested groups are followed to
  `group_nesting_depth` levels (level N + 1 is never read), a cycle terminates,
  a **hard cap of 1 000 groups per user** refuses rather than truncates (a
  ranged `memberOf` counts as the cap), search references are skipped, a
  referral result fails, and entries go through the fallible parser. It runs on
  **every successful directory sign-in**, a just-provisioned account and an
  existing one alike, before any session or MFA challenge is issued, so a
  removal in the directory takes effect at the next sign-in. **Fail closed**: a
  lookup that fails, times out or hits the cap refuses the sign-in with the
  ordinary failure (not counted against the account) and changes nothing; a
  just-provisioned account whose lookup fails holds no membership and grants
  nothing. A tenant with an empty table asks the directory no group question.
  A membership the mapping changes flushes that one subject's cached
  authorization decisions, locally and on every replica, through the same call
  the group-membership routes make, so a role that arrived through a group the
  directory has since removed does not outlive the sign-in that noticed.
  New audit actions `directory.groups_mapped` (the AXIAM groups added and
  removed and counts, nothing that names a person) and
  `directory.group_mapping_refused`. `DirectoryGroupMapper::apply_for_user`
  (`axiam-core` port, `RepositoryGroupMapper` in `axiam-directory`) is the one
  function the sync job (T23.3.5) will call. `GroupRepository` gains
  `add_directory_member`, `remove_directory_member` and
  `get_user_directory_group_ids`. No API, contract or SDK change: no route
  writes a directory configuration yet (T23.3.8).

- **Directory sources: just-in-time provisioning and linking (T23.3.3, G-3, D-28).**
  A login name that matches no local account is now offered to the tenant's
  directory when it has an enabled directory with `jit_provisioning`: the typed
  name and password are authenticated through the same bind as a directory
  sign-in, timed beside the same dummy Argon2id verify under the same hash
  permit, and on success the account is created **in one write** — `Active`,
  marked with the entry's `entryUUID` / `objectGUID`, an unusable password hash,
  `username` and `email` from the mapped attributes, the display name in
  `metadata.oidc.name` — and the login continues like any other (MFA policy,
  `amr = [pwd]`). A second first login for the same entry finds the first one's
  account; the unique indexes make two concurrent ones yield one account. Every
  other outcome — no directory, `jit_provisioning` off (answered **before** any
  connection), a wrong password, no such entry, a directory that is down — is
  exactly the unknown-name answer at the same cost. **A directory never takes
  over a local account (D-28):** an entry whose username or email equals, in any
  case and across both columns, an existing account's is refused with the
  generic failure and a `directory.jit_refused` audit row; so is an entry with
  no usable e-mail address. Attributes the directory supplies are bounded and
  cleaned (control and bidirectional-override characters) before they are
  stored. Linking an existing account is an explicit act,
  `AuthService::link_local_account_to_directory` (no route yet — T23.3.8): it
  resolves the entry through the directory by the account's login name, refuses
  one already linked to another account, marks the account, then deletes its
  WebAuthn credentials, revokes its `User`-type certificates and every session
  and OAuth2 refresh token (TOTP is kept), and writes `directory.account_linked`;
  interrupted, it is safe to repeat. New audit actions: `directory.jit_provisioned`,
  `directory.jit_refused`, `directory.account_linked`. No API, contract or SDK
  change. Repository additions: `UserRepository::create_directory_account` and
  `find_identity_collision`, `CertificateRepository::revoke_user_certificates`.

- **SAML 2.0 identity provider: the SSO endpoint (T23.2.3, G-2, D-24 … D-27).**
  `/saml/v2/{tenant_id}/sso` serves the Web Browser SSO profile per tenant, on
  the HTTP-Redirect (`GET`) and HTTP-POST (`POST`) bindings, plus
  `/sso/idp-initiated?sp=…` for a service provider that opted in (D-3) and the
  return leg `/sso/continue`. A request is checked in full before anyone is
  asked to sign in — DTDs refused on the bytes (no XML external entity or entity
  expansion reaches the parser), a 64 KiB inflate cap, `IssueInstant` within
  five minutes, the SP found by `Issuer` within the tenant, any signature
  verified (Redirect over the exact query octets; POST as the root's one
  enveloped signature), `Destination` = this tenant's SSO URL, the ACS URL or
  index exactly as registered, HTTP-POST response binding, `RelayState` ≤ 80
  bytes, a request `ID` never seen for that SP — and is then held server-side
  (schema **v73**, `saml_authn_request`) under an opaque handle bound to the
  browser by a cookie. The second leg signs the user in through the same login
  hop and OP-session cookie as `/oauth2/authorize` (which a sign-in now also
  mints at `/saml/v2/{tenant_id}/sso`), applies `account_may_act`,
  `allowed_groups`, `IsPassive` and a `ForceAuthn` bound to the request rather
  than to the hop marker, consumes the handle exactly once, and posts the signed
  response from a page with its own content-security policy (`form-action` the
  ACS origin only). The SPA's `return_to` validator accepts the SAML return leg.
  A tenant whose `saml_idp_enabled` is off, an unknown tenant, and a build
  without `saml` all answer the same empty `404`. Rate-limited at the
  browser-endpoint preset under buckets of their own. Composition: the optional
  deployment key `AXIAM__AUTH__SAML_PAIRWISE_KEY` (D-22) is now read at startup
  (absence logged at INFO); pending requests are swept by the cleanup task
  (`saml_authn_request` on `/health/jobs`). Threat model **2.22.0**: T-317 …
  T-330, T-313 closed.

- **SAML 2.0 identity provider: assertion issuance (T23.2.2, G-2, D-22).**
  `axiam_federation::saml_idp`, a library behind the `saml` feature that the SSO
  endpoint (T23.2.3) will call; no route serves SAML yet. `SamlIdpIssuer::issue`
  turns a verified AXIAM session into a `samlp:Response` for a registered service
  provider: `Issuer` from `idp_entity_id` (`{base}/saml/v2/{tenant}/metadata`,
  the one definition the metadata endpoint will reuse), a bearer
  `SubjectConfirmation` whose `Recipient` and the response's `Destination` are
  the registered HTTP-POST ACS URL used, `InResponseTo` on both when
  SP-initiated and on neither when IdP-initiated, `Conditions` valid five
  minutes and backdated by the existing 60 s skew allowance, the SP's entity id
  as the only `Audience`, `AuthnInstant` = the session's `authenticated_at`,
  `SessionIndex` = the session id, `AuthnContextClassRef` from the session's
  `amr` only (REFEDS MFA, `X509`, `PasswordProtectedTransport` or
  `unspecified`), and an `AttributeStatement` from the SP's attribute mapping
  over user fields, group names and role names. The `NameID` is a persistent
  **pairwise** identifier by default — HMAC-SHA256 under the new optional
  deployment key `saml_pairwise_key` over the tenant, the user and the SP entity
  id (D-22), stable across credential rotation and never containing the user id
  — or the user's email when the SP asks (no address is a refusal). The
  assertion is always signed (enveloped XML-DSig, `rsa-sha256`, `sha256`,
  exclusive c14n, the certificate in `KeyInfo`), the response too when the SP's
  `sign_responses` is set, after the assertion so its signature covers it; the
  issuer then verifies every signature and the document's shape before
  returning. A credential that is not the tenant's, not `active` or outside
  `not_before..not_after` is refused. `failure` builds unsigned, status-only
  responses (`Requester`, `Responder`, `NoPassive`, `AuthnFailed`,
  `RequestDenied`, `InvalidNameIDPolicy`). `check_allowed_groups`,
  `check_acs_url`, `check_request_id` and `check_relay_state` (80 bytes) are
  exposed for the SSO endpoint to call before the login hop. An SP registered
  with `encrypt_assertions` is refused (`Responder`): encryption (D-2) is not
  implemented. Threat model 2.21.0: the trust boundary AXIAM ↔ SAML service
  provider, T-304…T-316.

- **`CertificateType::SamlSigning` (T23.2.1, G-2, D-21).** A fifth certificate
  type for the leaf of a tenant SAML identity provider's signing credential, on
  T22.14's per-type profile: `keyUsage` is `digitalSignature` only (no
  `keyEncipherment` even on an RSA key), `extendedKeyUsage` is
  `id-kp-documentSigning` (RFC 9336, `1.3.6.1.5.5.7.3.36`) so no TLS verifier
  accepts it, and there is no `subjectAltName`; the Vault PKI custodian states
  the purpose as an OID (`ext_key_usage_oids`). It is **internal only and not on
  the wire**: `#[serde(skip)]` keeps it out of every request, response and the
  OpenAPI enum, the certificate inventory refuses it (the `cert_type` assertion
  is unchanged), and `generate` / `sign_csr` refuse it by name. It authenticates
  nobody: the bind endpoint and `MtlsService::authenticate_der` (device login and
  native mTLS) refuse it by type, and both doors are now exhaustive `match`es
  instead of `== Server`, so the next such type is a compile error rather than a
  silently accepted one. Leaf issuance is split so the SAML credential can reuse
  the whole issuing path without writing an inventory row.

- **The SAML IdP signing credential (T23.2.1, G-2, D-21): an RSA-4096 leaf
  with its key sealed at rest.** A new per-tenant `saml_idp_credential` table
  (schema v72) holds the certificate PEM, issuing CA, serial, SHA-256
  fingerprint, `not_after`, a status of `active`, `next` or `retired`, and the
  private key sealed AES-256-GCM under `pki_encryption_key` by
  `DatabaseCaKeyStore`, with the custody recorded on the row so a later custodian
  needs no migration. It is deliberately **not a `certificate` row**, so no
  certificate list or get can return it. At most one `active` and one `next` per
  tenant is a unique index over a computed `slot` field, so the database refuses a
  second one whichever caller wrote it. `SamlIdpCredentialService` in `axiam-pki`
  issues a credential from a caller-named active signing CA of the tenant's
  organization (another organization's CA, another tenant's, a non-signing or an
  expired one is refused), valid at most 730 days and never past its CA, through
  the same issuing path as `CertService::generate` (stopped before the inventory
  write); returns the active credential with its key in a `Zeroizing` buffer for
  the assertion signer; lists credentials without key material; and retires one,
  which destroys its sealed key in the same write. Only one repository method
  selects the key columns, and every `Debug` redacts them. The row is deleted
  with its tenant inside the tenant-delete transaction. Creation is explicit: no
  lazy issuance, no automatic rotation and no REST route yet (the admin route is
  T23.2.5).

- **The SAML service-provider registry (T23.2.1, G-2): model, validation,
  repository, schema v72.** `SamlServiceProvider` in `axiam-core` — entity id
  (unique per tenant), an ACS allow-list (`url`, `binding`, `index`,
  `is_default`), optional SLO endpoint, `NameID` format (persistent pairwise by
  default, email on request), `sign_responses` (default on), `encrypt_assertions`
  (default off, D-2), optional SP signing and encryption certificates,
  `want_authn_requests_signed`, `allow_idp_initiated` (per-SP opt-in, off by
  default, D-3), an attribute mapping table over username, email, display,
  given and family name, groups and roles, and an `allowed_groups` restriction.
  There is deliberately **no `sign_assertions` field**: assertions are signed
  always. `axiam_federation::saml_sp::validate_saml_service_provider` is the
  write-time rule: an ACS URL is refused exactly when an OAuth2 redirect URI
  would be (https except loopback, no fragment) and additionally when it holds a
  `*`, duplicates and a second default are refused, certificates must be exactly
  one parseable `CERTIFICATE` block (a private key is refused by name), and
  encryption or signed requests without their certificate are refused. The
  redirect rule now exists once: the admin OAuth2 client API calls the same
  function. `SamlServiceProviderRepository` with the SurrealDB implementation
  (`create`, `get`, `get_by_entity_id`, `list`, `update`, `delete`), tenant-scoped
  on every verb; the table is deleted with its tenant inside the tenant-delete
  transaction. Nothing serves SAML yet.

- **`saml_idp_enabled`: the layered switch for the SAML identity provider
  (T23.2.1, G-2, D-20).** A new setting on the OIDC policy block, default
  `false`, with exactly the shape of `sensitive_scopes_enabled`: an
  organization baseline, a tenant override that may only turn an organization's
  `true` off (never its `false` on), the same `validate_tenant_override` /
  `clamp_overrides_to_org` treatment, and a clamp that drops a tenant opt-in the
  organization later withdraws. Stored in `security_settings.oidc_saml_idp_enabled`
  (schema v72, `option<bool> DEFAULT false`, so a pre-v72 row reads as off).
  Appears in the settings API (`OidcPolicy`, `SetOrgSettings`,
  `TenantSettingsOverride`; OpenAPI regenerated) and is carried through the
  admin console's whole-row organization save so a save cannot reset it. Nothing
  reads it yet: the SAML endpoints that answer `404` when it is off arrive with
  T23.2.3.

- **Directory sign-in: the LDAP client and the bind-as-user path (T23.3.2,
  G-3).** A tenant's LDAP or Active Directory server can now authenticate its
  accounts. `axiam-directory` gains the client — `ldap3` over rustls only (no
  OpenSSL, no native-tls) — with mandatory TLS verified against the tenant's own
  trust anchors (or the public `webpki-roots` bundle when it configured none) and
  the URL's host, TLS 1.2 as the floor because Active Directory on older Windows
  Server releases has no TLS 1.3 on LDAPS; StartTLS before anything else,
  failing closed when the server refuses it; login names entering filters only
  through RFC 4515 escaping; no DN ever constructed; exactly one matching entry;
  referrals never followed; an empty password refused before any packet; and a
  bounded per-tenant connection pool with connect, operation and end-to-end
  timeouts. The user bind runs on its own connection, which is never pooled. A
  new port, `DirectoryAuthenticator` in `axiam-core`, keeps the layering intact:
  `axiam-server` injects the implementation into `AuthService`, which binds a
  **directory account** — one carrying the new `directory_external_id` marker
  (schema v71, unique per tenant) — to its directory and to nothing else. The
  lockout is checked before the directory is contacted, a failed bind counts
  like a wrong password and a success resets the counter, an unavailable or
  misconfigured directory fails closed and is never answered by the local hash,
  the directory's answer must be the account's own entry, and every refusal is
  the generic `401` with the same equalising Argon2id verify an unknown name
  gets. A directory password is recorded as `amr: ["pwd"]`. Password change,
  reset confirm, a SCIM password write, and OPAQUE login and registration are
  refused for a directory account (`400 validation_error`, SCIM `mutability`,
  OPAQUE's decoy and generic `401`); the reset request answers one exactly as an
  unknown address. The marker's only writer, used first by provisioning
  (T23.3.3), also replaces the account's password hash with an unusable random
  one and drops any OPAQUE record. No account is a directory account yet: there
  is still no provisioning and no management route. Threat model 2.20.0: a new
  trust boundary (AXIAM ↔ tenant directory) and T-291…T-303, one of them open
  (T-300: a tenant-chosen directory host is not held to the private-address
  policy the IdP and webhook fetches apply). The OpenAPI document changes only
  in the unreferenced `User` component, which gains the field.

- **The `axiam-directory` crate and the encrypted directory configuration store
  (T23.3.1, G-3).** The first piece of the LDAP / Active Directory identity
  source: a new crate at layer 3, beside `axiam-federation`, that opts into
  `missing_docs` from its first commit, and a per-tenant `directory_config` table
  (schema v70) with a repository. `axiam_directory::config::validate` refuses, at
  configuration time, a plaintext `ldap://` URL without StartTLS, any other
  scheme, `ldaps://` combined with StartTLS, a URL carrying userinfo, a path, a
  query or a fragment, an empty or control-character DN, a user-filter template
  that is not a single balanced filter with exactly one `{username}` placeholder
  in value position, an empty bind secret, out-of-bounds nesting depth or sync
  interval, and a trust anchor that is not a parseable CA certificate. The bind
  secret is encrypted at rest with AES-256-GCM under a fresh nonce, with a key the
  secret provider holds as the new **optional** `directory_encryption_key`
  (`AXIAM__AUTH__DIRECTORY_ENCRYPTION_KEY`); without it the feature is unavailable
  and saving a configuration is refused with an error naming the key, while the
  server still starts. The secret is write-only: never returned, never in `Debug`,
  decrypted only by the one repository method the bind path will call. A tenant's
  configuration is deleted with the tenant. There is no user-visible surface yet:
  no LDAP client, no sign-in path and no REST route, which arrive in the following
  tasks of the same item.

- **Basic OP `REVIEW` judgements and the maintainer's run checklist (T23.1.6, X7.9).**
  `docs/conformance/REVIEW-JUDGEMENTS.md` records, for each of the four Basic OP
  modules the 2026-09-25 run left in `REVIEW` (`oidcc-prompt-login`,
  `oidcc-max-age-1`, `oidcc-ensure-registered-redirect-uri`,
  `oidcc-ensure-request-object-with-redirect-uri`), the suite log, the module's
  own condition, what AXIAM does and the test that pins it, the clause, and what
  the screenshot evidence does and does not show; facts only a suite log can give
  are marked for the maintainer's run. The FAPI 2.0 entries follow (T23.1.7).
  `claude_dev/fapi-conformance-runbook.md` gains the checklist for the final runs,
  which the maintainer makes personally before the release tag. The conformance
  harness gains three small things the final run needs: `report.py` names the
  `SKIPPED` modules (it counted them and listed none) and keeps earlier dated
  reports linked from `index.md`, and `export-evidence.py` /
  `just conformance-evidence` exports the REVIEW screenshots with a manifest.
  No plan, registrar or server behaviour changed, and no final run has been made.

- **FAPI 2.0 `REVIEW`/`WARNING` judgements and the X5.3 submission package
  (T23.1.7, G-1).** `docs/conformance/REVIEW-JUDGEMENTS.md` gains the three FAPI
  2.0 entries, each over all three variants (`mtls`, `self-signed`,
  `private-key-jwt`) with the 2026-09-25 log ids and the evidence images read:
  `ensure-unsigned-authorization-request-without-using-par-fails`,
  `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` (both
  `REVIEW`) and `test-claims-parameter-identity-claims` (`WARNING`). The last is
  written as open: the 2026-09-25 build published `claims_parameter_supported:
  true`, so the warning is not the "claims not supported" deviation, its cause is
  in the suite log only, and whether to honour the `id_token` member of `claims`
  is left to the maintainer. The runbook's maintainer checklist is completed for
  the FAPI plans, and `claude_dev/fapi-certification-submission.md` gains the
  X5.3 package for both the Basic OP and the FAPI 2.0 certifications: what is
  submitted, the run-dependent fields as placeholders, the files to attach, a
  pre-send checklist, and website wording for the mark that stays unpublished
  until the certification is granted. Documentation only. Every entry is
  *proposed*, no final run has been made, and nothing has been sent to the
  Foundation.

- Verifiable-credentials design (OID4VCI issuer, OID4VP verifier, SD-JWT VC) — design only, no code (T23.9.1)

- RADIUS / EAP-TLS spike — decision record, no code: decline a native RADIUS front end for now, FreeRADIUS-backend route when asked, and the prerequisite finding that the tree publishes no CRL or OCSP (T23.11.1)

- Threat model 2.36.0 — the declined RADIUS front end entered as a design-only tenth diagram with the NAS ↔ AXIAM boundary, T-448 … T-468 recorded *Not applicable* (counted apart from mitigated and open on the website), and T-102 reopened: AXIAM publishes no CRL, so a relying party outside it has no revocation channel; `design-document.md` §6.2 and its `pki` settings corrected (T23.11.1, D7)

- *Identity for agents* guide and website page (T23.15.1)

- Comparison documents refreshed (W6a, G-10 and G-11; documentation only): the RADIUS decision (D-77: native front end declined for now, FreeRADIUS-backend route when a named adopter asks, no CRL published yet) in the authentik comparison's outposts row and gap item 6; a run-6 note beside every run-5 citation (run 6 re-measures Keycloak 26.8.0, Zitadel v4.19.4 and authentik 2026.8.3 against `1.0.0-beta18`, numbers follow); and what AXIAM does not do — CIBA has no push mode and no `user_code`, a federated account gets no approval mail (D-74), and outbound SCIM delivers one attempt at a time per replica until #550 is decided. The website's CIBA, outbound SCIM and PKI pages carry the same limits

- **RFC 7592 client configuration endpoint (T23.4.1).** A dynamically
  registered client can now read, replace and delete its own registration at
  `GET`/`PUT`/`DELETE /oauth2/register/{client_id}`. `POST /oauth2/register`
  returns, once, a `registration_access_token` (32 random bytes, stored only as
  a SHA-256 on the client row, schema v69) and a `registration_client_uri`
  under the issuer the registration used. The token is accepted only as
  `Authorization: Bearer`, only for its own client in its own tenant; unknown
  client, wrong token, other tenant and a client with no token (admin, CIMD,
  older DCR) are all `401 invalid_token`. A `PUT` is a full replacement held to
  the registration's own validation under the tenant's current policy, cannot
  touch the profile, the X7 flags or the provenance, and rotates the token as
  one compare-and-swap. A `DELETE` revokes the client's refresh tokens and
  frees its `dcr_max_clients` slot. The routes share the registration limiter's
  preset in their own bucket, and every request is audited without the token.
  CONTRACT 1.53 adds §28.12 (`read_client_registration`,
  `update_client_registration`, `delete_client_registration`, token
  `Sensitive`); threat T-289, model 2.18.0.

- **Browser sign-on on per-tenant issuer paths (T23.1.8, D-11).** On a
  deployment with `AXIAM__AUTH__TENANT_ISSUER_PATHS` set, every completed
  browser sign-in now sets the `axiam_op_session` cookie twice: at
  `Path=/oauth2/authorize`, unchanged, and at
  `Path=/t/{tenant_id}/oauth2/authorize`, for the session's own tenant only. The
  sign-in paths are password, OPAQUE, MFA verify, forced enrolment, both WebAuthn
  ceremonies and the federation handoff. The two copies carry the same value and
  the same `HttpOnly; Secure; SameSite=Lax` and `Max-Age`. A `browser_sso`
  relying party that discovered a tenant issuer therefore gets the login hop
  instead of a `login_required` that always failed closed. The hop resolves under
  exactly the bare path's rules: tenant-keyed lookup, account re-read,
  `browser_sso` gate, honour lane. A copy presented on another tenant's path names
  no session. Every logout clears every copy: `POST /api/v1/auth/logout`,
  `end_session` (bare and per-tenant), and a stale cookie at the path it arrived
  on. The paths come from one list (`csrf::op_session_cookie_paths`), so W3's SAML
  SSO path is one entry. With the setting off, nothing changes. Browser-only: no
  contract change.

- **`GET /oauth2/authorize/logout`, the cookie half of RP-initiated logout
  (T23.1.8, closes F4 residual P23W1-10).** The OP cookie never reached
  `/oauth2/end_session`, so a logout without an `id_token_hint` `sid` cleared the
  cookie and left the session row live. `end_session` now answers such a request
  with a `302` to the `/logout` sub-path of the authorization endpoint it came
  through, on the bare path or the tenant path. The cookie reaches that sub-path.
  It revokes the one session the cookie names in that tenant, clears every
  cookie, and continues exactly as `end_session` would: the allow-listed
  `post_logout_redirect_uri` by exact match, or AXIAM's page. It is GET-only,
  public, rate-limited with the `end_session` preset in its own bucket, and in
  OpenAPI. It sends no back-channel fan-out, which stays reserved for a signed
  hint. A hinted `end_session` is unchanged. Threat T-290; T-237 and T-238
  amended; model 2.19.0.

- **Admin console: the *SAML Service Providers* page (T23.2.6, G-2, contract
  §29).** One page per tenant at `/saml` (sidebar *Identity*), its nav entry and
  its route both gated on `saml_sp:read`, over the eleven §29 routes; no server,
  contract or threat-model change. **Identity provider panel**: the entity id, the
  metadata URL (copyable), the sign-on and logout URLs, and whether SAML is
  available in the build, enabled for the tenant and serving metadata, with what
  to do when it is not. **Service providers** (`saml_sp:write` for every write): a
  searchable, paginated list; manual entry and edit of every
  `SamlServiceProviderInput` member, with the ACS allow-list (binding, index,
  default), the SLO pair, NameID format, `sign_responses`, the two SP
  certificates as PEM, signed-request and IdP-initiated switches, the attribute
  mappings and an `allowed_groups` picker over the tenant's groups. The **entity
  id is read-only on edit** (D-42) and is taken from the stored registration, not
  the form; **`encrypt_assertions` is shown disabled ("not yet supported") and the
  form has no member that could send it as `true`**; an edit re-reads the
  registration and sends a full `PUT`; delete asks first and says it ends no
  session. **Import from metadata**: paste, upload or an `https` URL into
  `parse_sp_metadata`, shown as a **draft** with its fingerprints and warnings and
  the *signature not verified* warning in front, edited in the ordinary form and
  saved only by the explicit save through `create_service_provider`; both or
  neither of XML and URL is refused before any request. **Signing credentials**
  (`saml_idp:credential` for all three actions): status, fingerprint, validity and
  serial; issue from the organization's active CAs into `active` or `next` for 1
  to 730 days (default 365); promote behind a confirmation that service providers
  must have fetched the new metadata; retire behind a confirmation that retiring
  the **active** credential stops SAML sign-on for the whole tenant at once. The
  `400`, `404`, `409` and `503` messages are shown verbatim, past the generic
  redactor. The `saml_admin` row of the frontend coverage matrix is now *covered*,
  and the Playwright permission matrix has the `/saml` route. The
  `saml_idp_enabled` setting has no console control yet; the page says so and
  points to the settings API. Tests: 121 across the service, the form logic and the
  page (fixtures built at run time).

### Changed

- **The W5 F4 security review (Phase 23, threat model 2.35.0,
  [`security-review-phase23-w5-2026-10-05.md`](claude_dev/security-review-phase23-w5-2026-10-05.md)).**
  Behaviour changes, all to surfaces new in this unreleased wave:
  - **Outbound SCIM: a client-credentials target's secret is bound to
    `base_url` too** (T-409). Every access token the secret yields is sent to
    `base_url`, so an update that moves `base_url` of a client-credentials
    target without `credential` in the same write is now `400` naming
    `base_url`, exactly like a moved `auth.token_url`; the console asks for the
    secret when either URL is edited. Contract 1.57 §31.3 rule 2 amended in
    place.
  - **Outbound SCIM: one `scim_delivery_failed` notification per target per
    hour** (T-418, D-73). Every dead letter still writes its
    `scim_push.delivery_failed` audit row and its count on the target's
    `state`; only the mail to a rule's recipients is coalesced, claimed in the
    datastore so replicas agree. Schema **v84** adds
    `scim_target_state.failure_notified_at`.
  - **CIBA: only a console sign-in decides a request** (T-447). The approval
    routes (`GET /api/v1/ciba/requests/{id}`, `…/approve`, `…/deny`) answer
    `403` to an access token AXIAM minted for an OAuth2 client (code, refresh
    or CIBA grant), which names the user and a session but is not the user at
    the console. Contract 1.58 §33 amended in place; OpenAPI describes the
    `403`.
  - **CIBA: the approval mail goes only to an address something vouches for**
    (D-74, D-25's rule): `email_verified_at` set, or the account `Active`. A
    request for an account whose address is unproven is stored and answered as
    before and waits on the approval page unmailed. A federated account, which
    stays `PendingVerification`, therefore gets no approval mail unless its
    address was verified.
  - **CIBA: `ciba.approved` and `ciba.denied` audit rows carry the deciding
    `session_id`** (T-435).

- **The SAML assertion's `SessionIndex` is a per-SP random token, not the AXIAM
  session id (T23.2.4, D-37, closes T-312).** SPs that compared notes could
  correlate one person's sessions through a `SessionIndex` that was the same at
  every SP of a sign-on. The SSO endpoint's second leg now records — or reads
  back — a `saml_sp_session` row (the `NameID` the SP is given and 32 CSPRNG
  bytes, base64url) after the handle is consumed and **before anything is
  signed**, and the assertion carries that index; a second sign-on to the same SP
  in one session reuses it. A failed write is a `Responder` failure with no
  assertion. `SsoIssuance` gains `session_index` and `IssuedResponse.session_index`
  is a string. An SP that stored the session id as a `SessionIndex` sees a new
  value on its next sign-on.

- **An email `NameID` is issued only for an address something vouches for
  (T23.2.3, D-25, T-313).** The SAML IdP asserts a user's email — as the
  `NameID` of an `emailAddress` service provider, or as an `email` attribute —
  only when it was verified or the account is `Active`. A `PendingVerification`
  account with an unverified address is answered `InvalidNameIDPolicy` at such
  an SP (and the attribute is omitted); it still signs on where the `NameID` is
  the pairwise default.
- **A handler may set a stricter `Content-Security-Policy` of its own
  (T23.2.3, D-27).** The security-headers middleware writes the global policy
  only when the response carries none; the one handler that sets its own is the
  SAML auto-post page. Every other response is unchanged.
- **A sign-in mints a third OP-session cookie copy** at the tenant's SAML SSO
  path (`/saml/v2/{tenant_id}/sso`), same value and attributes; logout and both
  `end_session`s clear it with the others (T23.2.3, D-11).
- Front-channel logout declined by design and recorded (T23.12.1, D-6)
- **The webhook dispatcher is now a shared outbound dispatcher (T23.5.1, D-36);
  internal refactor, no behaviour change.** G-5 (Shared Signals Framework push)
  and G-6 (outbound SCIM) need the same durable queue, one-attempt delivery,
  bounded backoff and dead-letter queue that webhooks already had, and sit in
  layers that cannot reach `axiam-api-rest`. `axiam-core` gains
  `outbound::{OutboundMessage, OutboundKind, OutboundPublisher,
  OutboundDeliverer, DeliveryOutcome}` (two object-safe ports); `axiam-amqp`
  gains `outbound` (per-kind topology declaration, publisher, the consume loop,
  the retry policy and the deliverer registry); `WebhookDeliveryService`
  implements `OutboundDeliverer` and `axiam-server` registers it with the
  generic loop. Webhooks keep exactly their queue, retry-queue and DLQ names and
  arguments (`axiam.webhook`, `.retry`, `.dlq`), their on-the-wire message
  format (so in-flight messages and a rolling upgrade are unaffected), signing
  (`X-Axiam-Timestamp`, `X-Axiam-Signature`), SSRF-guarded delivery, the
  `AXIAM__WEBHOOK__MAX_ATTEMPTS`, `AXIAM__WEBHOOK__BACKOFF_BASE_MS` and
  `AXIAM__WEBHOOK__BACKOFF_CEILING_MS` variables, and the
  `webhook.delivery_*` audit records. A test pins the names byte for byte.
  Source-level moves: `WebhookRetryConfig::from_env()` is now
  `OutboundRetryConfig::from_env_for(OutboundKind::Webhook)`
  (`WebhookRetryConfig` remains as an alias of `OutboundRetryConfig`);
  `WebhookDeliveryService::emit` takes `&dyn OutboundPublisher`. The OpenAPI
  document is unchanged.

### Fixed

- **Audit rows survive an orderly stop, and a lost minimal-profile lease is one
  (T23.8.2, P23W5-A1/A2).** An instance of the minimal profile whose singleton
  lease another instance took over called `std::process::exit(1)` from the
  renewal task, losing every audit row the audit middleware still had queued —
  and a lease is lost exactly when the datastore was unreachable, which is when
  that queue fills — together with any request between its write and its audit
  row and a GDPR purge between the erasure and `gdpr.user_pseudonymized`. It now
  stops through the `SIGTERM` path (no new connections, in-flight requests
  finished, the cleanup task's tick finished, the audit queue written) and exits
  non-zero within 15 s, a backstop ending it after that. Every orderly stop, in
  both profiles, now waits up to 5 s for the audit middleware's queue
  (`AuditMiddleware::drain`); before, the runtime's end dropped the queue even on
  a clean `SIGTERM`. The review, path by path, is
  `claude_dev/audit-durability-review-minimal-profile-2026-10-05.md`; threat model
  2.34.0 (T-444, T-445; T-405 amended; T-108 reopened).
- **CI/harness: `fapi-conformance.yml` gets past its bring-up (D-60).** Its first run
  (37268155503) died in the bring-up and every later step would have failed too.
  `bench-up` no longer passes `docker compose up --wait` for the native-TLS
  overlay (`p2-tls13`, `p3-mtls`), whose `healthcheck: NONE` compose refuses; it
  gates on its host-side `/health` probe and still fails fast, with the usual
  ps+logs dump, when a container exits non-zero (`p0`/`p1` unchanged). A new
  `benchmarks/targets/axiam/docker-compose.conformance.yml` (layered on by the new
  `BENCH_COMPOSE_OVERLAYS` hook) makes the `p3-mtls` listener the conformance
  target: it trusts the conformance and benchmark CAs, presents the conformance
  server certificate, runs `optional_self_signed`, and forwards the mTLS-alias base
  URL and default tenant that compose dropped. The workflow now builds the SPA,
  publishes AXIAM on the port the front door proxies to with the front door's
  issuer, seeds with `profile=p3-mtls` (it seeded the plaintext port), registers
  the clients as the seeder's administrator instead of a bearer secret that cannot
  exist for a deployment the job creates, restarts AXIAM once so discovery carries
  the registered tenant, summarises only that run's reports, and uploads the
  server and front-door logs. New `just bench-logs` prints compose logs without the
  stack's secrets in the environment. Workflow, justfile, compose overlay and
  runbook only; no server code.

- **OpenAPI: `AcsEndpoint.index` is published with `maximum: 65535` (F4 W4
  P23W4-05).** The model and contract §29.2 say an unsigned 16-bit integer; the
  schema said an unbounded `int32`, so a generated SDK accepted values the server
  refuses with `400`.

- **Directory just-in-time provisioning: a lost race checks the winner's status
  before mapping groups (F4 P23W3-05).** When two first sign-ins for one
  directory entry race, the loser continues with the winner's account. It now
  refuses an account that may not sign in — deactivated by the sync job in
  between, or suspended — *before* the group mapping runs, instead of re-adding
  directory memberships to it and refusing afterwards. The memberships granted
  nothing while the account was not active, and the answer is unchanged. Test:
  `p23w3_05_a_lost_race_to_an_inactive_account_maps_no_groups`.

- **A tenant delete that fails is reported as a failure (F4 P23W2-02).**
  Since T23.3.1 the tenant delete removes the tenant's directory configuration
  in the same transaction, but the repository never checked the response: a
  transaction that rolled back answered success, so `DELETE
  /api/v1/organizations/{org_id}/tenants/{tenant_id}` answered `204` and wrote
  a "tenant deleted" audit record for a tenant that still existed, encrypted
  bind secret included. The failure is now an error and nothing is recorded as
  deleted.

- **A `client_secret_basic` client now has the same per-client rate-limit bucket
  as a `client_secret_post` one (T23.1.5).** The layer in front of
  `/oauth2/token`, `/oauth2/revoke` and `/oauth2/introspect` read the bucket's
  `client_id` from the form body alone, and RFC 6749 §2.3.1 lets a Basic client
  name itself in the `Authorization` header alone. Under
  `AXIAM__RATE_LIMIT__KEY=client_id` or `ip_client_id` such a request fell back
  to the per-address key, so a Basic client's secret could be guessed from as
  many addresses as the guesser held. The layer now falls back to the id the
  header decodes to (through the same parser the handlers use; the secret is not
  read and nothing is logged). The default key mode, `ip`, never differed.
  Amends T-253. The audit behind it also added tests, with no behaviour change,
  for the §2.3.1 decoding edges, duplicate `Authorization` headers, the
  registered method at the three ordinary token grants, and the FAPI refusal of
  `client_secret_basic` through the admin API, and for the X7.7 sensitive scopes
  (the verified flag in both directions, the §5.1.1 shape, the claims absent
  from the access token, introspection and a refresh, consent not crossing a
  tenant, the update door onto registration, SCIM as the writer).

- **The login hop on a per-tenant issuer path came back refused (T23.1.8).** Its
  `return_to` was built from the query after the tenant scope had appended
  `tenant_id`. The return leg therefore carried a second tenant selector, and the
  scope that added it refused it with `invalid_request`. The interaction hop had
  the same defect. Both now echo the client's own query.

- **An organization-level administrator's logout revoked nothing after a tenant
  switch (T23.1.8).** `POST /api/v1/auth/logout` revoked the session in the
  acted-upon tenant. The admin UI sends `X-Axiam-Tenant` on every request, so
  after a switch that was a child tenant where the session does not live. The
  answer was `204` and the session stayed live. Logout now revokes, and clears
  the OP cookies, in the principal's own tenant.

- **A refreshed ID token on the honour lane no longer loses `auth_time`, `acr`
  and `amr` once the browser session has rotated (T23.1.2, D-9).** The refresh
  grant read its evidence from the session row the authorization code was
  issued under, and `AuthService::refresh` deletes that row at every
  browser-session rotation — about every fifteen minutes for the admin SPA — so
  after the first rotation the claims vanished, where OIDC Core §12.2 wants the
  original `auth_time`. The evidence is now snapshotted on the OAuth2 refresh
  token (schema v68: three optional columns, no backfill, no index), written at
  code exchange from the code's snapshot and copied verbatim at every OAuth2
  rotation. A grant issued before the migration falls back to the old
  live-session lookup, so nothing gets worse. Emission is unchanged: honour
  lane only, never `fapi2` or `ignore`. Amends T-240.

- **`Authorization: bearer <token>` is accepted at `/oauth2/register` and the
  RFC 7592 client configuration endpoint (F4 P23W1-02).** The scheme was
  matched as the literal `Bearer `, so a lower-case or upper-case scheme was
  read as no token at all and answered with the bare `WWW-Authenticate: Bearer`
  challenge, which a client follows by discarding a token that was good. The
  scheme is now case-insensitive, as RFC 9110 §11.1 requires; a scheme with no
  token after it, and any other scheme, are still no token. A pin was added
  for the 16 KiB body limit on `PUT /oauth2/register/{client_id}`.

### Security

- **Phase 23 W4 security review (F4).**
  `claude_dev/security-review-phase23-w4-2026-10-04.md`: single logout (D-38),
  the SAML SP registry and credential routes, SP metadata import with D-54's
  tree rewrite, SET issuance, the SSF receiver API, push and poll delivery and
  the event sources reviewed adversarially. Five fixes (P23W4-01 … -05, above),
  pins for SET token confusion at every verifier and for the wave's multi-value
  `IN` queries. T-370 and T-377 now state the Redirect `SigAlg` rule exactly;
  T-390's residual is corrected (audience squatting where every tenant's SETs
  share one issuer, P23W4-11, a decision for the maintainer) and the website's
  SSF page tells receivers to take `aud` from their stream and require the push
  `Authorization` header. Threat model 2.30.0: 406 threats, 389 mitigated / 17
  open.

- **SSF requires per-tenant issuers in a multi-tenant deployment (F4 W4 P23W4-11, D-55, #539; threat model 2.31.0, T-390).** With `AXIAM__AUTH__TENANT_ISSUER_PATHS` off and more than one tenant, SSF is inactive for every tenant — discovery `404`, no stream on the receiver API, nothing produced or signed, a queued push dead-lettered, a poll answering nothing — and turning `ssf_enabled` on is `400` naming the cause; streams and settings say why (`transmitter_active`, `oidc.ssf_inactive_reason`), a change is logged once at `WARN` and audited as `ssf.inactive_shared_issuer`. Contract §32 amended in place (1.56).

- **A long poll logs an unsignable held event once (F4 W4 P23W4-03).** When the
  deployment key could not sign a held SSF event, `POST /ssf/v1/poll/{id}`
  logged it at `ERROR` on every half-second look of a long poll — about sixty
  lines per waiting receiver per half minute. Once per request now; the
  long-poll wait can no longer underflow its 30-second cap and panic.

- **A page can no longer spend a user's step-up record (F4 W4 P23W4-02, closes
  T-404's residual).** `/oauth2/authorize` consumed the `ssf_step_up` row on the
  return-leg marker alone, before validating the client and `redirect_uri`, and
  in the session that was asked to step up, so any page could suppress the
  user's `assurance-level-change`. The row is now consumed only for a request
  the authorization service accepted, and only by a return leg in another
  session than the one the step-up was asked of.

- **SSF stream writes no longer undo each other (F4 W4 P23W4-01, adds T-406;
  threat model 2.30.0).** Every stream write was read-modify-write, so a
  receiver's `PATCH`, `PUT` or status write that overlapped an administrator's
  change put back the status, allowance, receiver binding or subject format the
  administrator had just set — a `disabled` included — and the push deliverer
  could send a header supplied for a new endpoint to the old one. Writes are now
  conditional on the version they were prepared from: a receiver's write decides
  again from a fresh read (and answers `409` only if the stream keeps changing),
  an administrator's `PUT /api/v1/tenants/{t}/ssf/streams/{s}` answers `409`
  when the stream changed since it was read, and the deliverer reads the stream
  again before it sends. Contract §32.3 rule 4 and §32.6 amended in place (1.56
  is unreleased). 406 threats, 389 mitigated / 17 open.

- **SSF delivery threats T-402 … T-405 (T23.5.4, threat model 2.29.0).** Held
  and dead-lettered events keeping a person's subject (T-402: seven-day TTL on
  `axiam.ssf_push.dlq` and the buffer; an erased subject can outlive the erasure
  there for up to seven days), long polls held open (T-403: one waiting long
  poll per stream per instance), an `assurance-level-change` forged or
  suppressed through the step-up record (T-404) — all three mitigated with
  their tests — and a lost event nobody is told of (T-405, open: production is
  best effort). T-391 gains the no-redirect push, T-392's delivery text is
  corrected, and the SSF store is renamed `ssf_stream + ssf_event_buffer +
  ssf_step_up`. 405 threats, 388 mitigated / 17 open.

- **SSF push cannot be aimed at an internal address, flood a receiver or grow a
  buffer without bound (T23.5.3, closes T-392, T-394, T-395; threat model
  2.28.0).** Every push goes through the shared SSRF guard with
  `allow_private = false` and follows no redirect; retries are bounded by the
  dispatcher and an answer that cannot change on retry dead-letters at once; the
  poll buffer holds 1 000 events per stream for seven days and its sweep is on
  `/health/jobs`. T-388 (replay) stays open until the SDK receiver helper
  de-duplicates `jti`. 401 threats, 385 mitigated / 16 open.

- **SSF transmitter threats T-385 … T-401 (T23.5.2, threat model 2.27.0).**
  Receiver impersonation, cross-tenant stream access, forged, replayed and
  confused SETs, a SET misaddressed through an audience shared across tenants,
  the push credential, push-endpoint SSRF, API and event flooding, the poll
  buffer, subject-identifier linkability, a receiver widening its events,
  delivery after a stream was disabled, attribution, the receiver binding and
  discovery as an oracle. Thirteen are mitigated with their tests; T-392, T-394
  and T-395 stay open until T23.5.3 builds delivery on the decided controls, and
  T-388 (replay) until the SDK receiver helper de-duplicates `jti`. 401 threats,
  382 mitigated / 19 open.

- **Single logout cannot be forged, replayed or aimed at another session
  (T23.2.4, closes T-366, T-370 … T-379, T-381 … T-384; T-312).** The tenant's
  signing key signs a logout message only for a session whose holder ended it or
  for a verified SP request — never for anyone else — and on the Redirect
  binding with a detached query signature, so no `ds:Signature` over a logout
  message exists to be lifted into an assertion (T-316's constraint, T-373).
  Every SP message is verified per node with the D-23 placement rule or over the
  exact query octets; a replayed request `ID`, a foreign or replayed
  `InResponseTo`, a wrong `Destination`, a stale `IssueInstant`, an `EncryptedID`
  and more than 32 `SessionIndex` values are refused; an SP reaches only the
  sessions it took part in, under the `NameID` it was given, in its own tenant.
  Threat model 2.26.0 (369 mitigated, 15 open); the tests each mitigation cites
  are in `saml_idp_slo_test.rs`, `saml_slo_test.rs` and `saml_idp_sso_test.rs`.

- **Directory management: the address guard's answer to a host name no longer
  maps internal DNS (F4 P23W3-04, adds T-356).** A `PUT` or `PATCH` on
  `/api/v1/tenants/{tenant_id}/directory` told the tenant administrator whether a
  host name did not resolve, resolved into a private range outside the
  allow-list, to loopback, to the metadata service or to an AXIAM listener — at
  30 writes a minute, a way to enumerate the deployment's internal names. For a
  host name, every refusal that depends on what it resolved to is now one `400`
  message ("the directory host does not resolve to an address this deployment
  permits…") and one audit rule, `address_guard.not_permitted`; the specific
  rule goes to the operator's log. An IP literal, an IPv6 literal and an
  unparseable URL keep their specific answers. Contract §30.3 rule 1 amended in
  place (1.54 is unreleased). Threat model 2.24.0: T-356 added (Low,
  Mitigated). Tests: `p23w3_04_a_refused_host_name_gets_one_answer_whatever_it_resolves_to`,
  and `the_address_guard_refuses_each_class_as_a_400_naming_the_rule` updated.

- **Request logs no longer carry credentials from the query string (F4
  P23W3-03, closes T-325).** The request tracer (`tracing-actix-web`'s default
  root span) recorded every request's full target, so the SAML SSO endpoint's
  pending sign-on `handle`, `RelayState` and `SAMLRequest`, `/oauth2/authorize`'s
  `state` and `login_hint`, `end_session`'s `id_token_hint`, password-reset and
  GDPR tokens and administrators' search terms reached the request log wherever
  an operator enabled the tracer's span (the shipped `axiam=info` filter does
  not). `axiam-server` now installs `RedactingRootSpanBuilder`: the same fields,
  span name and target, with every query value recorded as `[redacted]` unless
  its parameter is one of a short list of structural ones (tenant, organization
  and client ids, `response_type`, `scope`, `prompt`, pagination and the like),
  and the `{token}` segment of `/account/export/{token}` redacted too. Parameter
  names stay. Threat model 2.24.0: T-325 closed. Tests: `request_span::tests`
  (three), and `t9_4_the_request_logging_layer_records_no_headers_at_all`, now
  pinning the new builder and that it reads no header but `User-Agent`.

- **Directory sources: a lockout for login names AXIAM holds no account for (F4
  P23W3-02, closes T-332).** With just-in-time provisioning on, a sign-in for an
  unknown name is answered by the tenant's directory, and no AXIAM counter stood
  in front of it — the per-account lockout has no account to count against — so
  the login endpoint could spray passwords at directory users who had never
  signed in to AXIAM, limited only by the per-IP limits and the directory's own
  lockout. Failures the directory decides for an unknown name (a wrong password
  or no such entry; an unusable directory counts against nobody) are now counted
  per tenant and login name, trimmed and case-folded, under the tenant's lockout
  policy (`max_failed_login_attempts`, `lockout_duration_secs`, the backoff and
  its cap). Over the threshold, the name is answered as an unknown user — dummy
  verify included — without asking the directory, even with the right password,
  until the lockout expires; a successful sign-in clears it. The counter is per
  process (with N replicas a name gets at most N times the attempts per window)
  and tracks at most 50 000 names. Threat model 2.24.0: T-332 closed. Tests:
  `p23w3_02_guessing_at_an_unknown_name_stops_reaching_the_directory`,
  `p23w3_02_failures_below_the_threshold_still_provision`, and four unit tests
  in `axiam_auth::unknown_name_lockout`.

- **Directory linking also removes the account's federation links (F4 P23W3-01,
  T-336).** `POST /api/v1/tenants/{tenant_id}/directory/links` (D-28) retired
  the passkeys, `User` certificates, sessions and refresh tokens of the account
  it linked, but not its federation links: a social or upstream-IdP identity
  bound to the account kept signing it in without the directory deciding — the
  same way in that deleting its passkeys closes. Linking now deletes every
  federation link the account holds, before the sessions are revoked, and counts
  them in the `directory.account_linked` audit row (`federation_links_deleted`);
  a deleted link is not re-made at the next upstream sign-in, because federated
  provisioning never links by name or address. The response shape is unchanged.
  Contract §30.3 rule 6 amended in place. Test:
  `p23w3_01_linking_removes_the_accounts_federation_links`.

- **Directory sources: the address guard and the frame cap beneath the LDAP
  client (T23.3.7, G-3, D-19, D-32; closes T-300, amends T-295, adds T-331).**
  A tenant administrator chooses the directory URL, so the connector now holds
  every directory host to a deployment rule before it opens a socket.
  `axiam_directory::address::guard` resolves the host once and judges **every**
  address: loopback, unspecified, link-local (`169.254.169.254`, `fe80::/10`),
  multicast and special-purpose addresses are always refused, IPv4-mapped forms
  as the IPv4 address they carry; a private address (RFC 1918, CGNAT
  `100.64/10`, ULA `fc00::/7`) only inside a network listed in the new
  **`AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS`** (comma-separated CIDR blocks;
  unset admits none — a deployment whose directories are on private networks
  must set it); a metadata endpoint inside a private range whatever the list
  says; and an address of this host on AXIAM's REST or gRPC port. IPv6-literal
  URLs are refused (they could never be certificate-checked). The TCP socket is
  opened to a vetted address and handed to `ldap3`, so nothing resolves the name
  again — DNS rebinding between the check and the connect is impossible — and
  the certificate is still verified against the URL's host, for `ldaps://` and
  StartTLS alike; the guard runs at every connection (pool, user bind, group
  lookup, sync). `DirectoryClient::guard` / `RepositoryDirectoryAuthenticator::guard_url`
  is the call the management routes (T23.3.8) make before saving. The
  classification is `guarded_fetch`'s, moved to `axiam_core::ip_class` so the two
  guards cannot disagree. **Frame cap (P23W2-10):** AXIAM now performs StartTLS
  and the TLS handshake itself and gives `ldap3` one end of a private Unix socket
  pair; a relay forwards each LDAP message from the directory only after
  `axiam_directory::frame` has measured it — a declared length above
  **`AXIAM__DIRECTORY__MAX_MESSAGE_BYTES`** (default 2 MiB, clamped to
  64 KiB … 16 MiB) ends the connection from the header alone — and checked it
  whole: definite lengths, single-octet tags, nesting at most 16 deep, a message
  id and an operation. Before this, a hostile directory could make the shared
  connector buffer whatever it sent until the operation timeout, abort the
  process through `lber`'s unbounded recursion (a few tens of kilobytes of
  nesting), or panic a connection task with a short envelope (T-331). Latent
  until now — no route writes a directory configuration — and closed before
  T23.3.8 adds one. Threat model **2.23.0**: T-300 closed, T-295 amended, T-302
  widened, and **T-331 … T-355** added — the frame guard, just-in-time
  provisioning and linking (T-332 open: an unknown name under
  `jit_provisioning` reaches the directory with no AXIAM counter in front of it),
  group mapping, a new **Directory sync job** process with its
  `directory_sync_state` and `user accounts & member_of` stores, and the sync
  job's threats; 355 threats, 337 mitigated / 18 open. Tests: 13 in
  `connector_guard_test.rs` (every refused class at `guard` and at connect, a
  name resolving to loopback, the listener port, the allow-list both ways, DNS
  rebinding, one resolution per connection, the hostname TLS check over a pinned
  address for ldaps and StartTLS, an IP-only certificate refused, an over-long
  length, 20 000 levels of nesting and a short envelope each aborted at once,
  the configurable cap), 19 unit tests for the guard and the frame reader, 5
  classifier tests in `axiam-core`; every existing directory suite unchanged
  and green.

- **SAML SP: a signed document without an assertion can no longer vouch for a
  forged one (T23.2.2, D-23, T-67).** The SAML assertion consumer verified only
  the *first* `ds:Signature` in a response and bound the assertion to *any*
  `Reference` that named it, verified or not. A document the upstream identity
  provider signed for another purpose — a signed `LogoutRequest` or
  `LogoutResponse`, a signed error response — placed ahead of a forged
  assertion carrying a dummy signature made the forged assertion pass, and the
  ACS signed in (or provisioned) whatever user it named: an authentication
  bypass on every SAML federation whose IdP signs such messages with its
  assertion key. A `ds:Signature` is now accepted only as the enveloped child of
  the `Response` root or of the `Assertion` that is its child, at most one per
  parent and each referencing its parent's `ID`; any other `Signature` element
  refuses the whole response; every signature is verified individually on its
  own node; IDs must be unique `NCName`s; and the assertion must carry its own
  enveloped signature. A response signed only at the `Response` level was
  already refused and still is. Present in every release that shipped SAML
  federation.

- **A directory configuration update can no longer redirect the stored bind
  secret (F4 P23W2-01, T-298).** `DirectoryConfigRepository::update` kept the
  encrypted bind secret whenever the request carried no new one, whatever else
  changed, so an update that repointed the URL (and named a CA of the editor's
  choosing as the trust anchor) would have sent the write-only secret to that
  host in the next service bind. Without a new secret, an update that changes
  `url`, `start_tls`, `bind_dn` or `trust_anchors_pem` is now refused with
  `400 validation_error` and changes nothing; re-entering the secret makes it an
  ordinary update. No route writes a directory configuration yet (T23.3.8 adds
  them), so nothing deployed changes behaviour.

- **A `fapi2` client's authentication method is re-checked at request time at
  PAR, introspection and revocation, as it already was at the token endpoint
  (T23.1.5, D-17).** A `fapi2` row edited in the database to
  `client_secret_basic` or `client_secret_post` — which registration validation
  refuses, so only a direct edit produces it — still authenticated at those
  three endpoints with a correct secret (PAR answered `201`, introspection and
  revocation `200`). The `is_strong()` rule is now one function,
  `fapi::enforce_client_authentication`, extracted from `enforce_token_request`
  and called by all of them after the client authenticates and before anything
  is pushed, revealed or revoked, with the same `invalid_client` as the token
  endpoint. A caller without the secret sees nothing new, RFC 7009 §2.2's "an
  invalid token is a 200" is untouched, and no client registered today changes.
  Amends T-253 (its residual is removed).

- **`max_age=0` on the honour lane is now handled as `prompt=login`, so a
  relying party sending it can sign in (T23.1.4, D-14).** The honour lane
  re-authenticated when `elapsed >= max_age`, which for `0` made the
  reauthentication the login hop produces itself "too old" (`0 >= 0`): the
  return leg answered `login_required`, and no relying party sending
  `max_age=0` could ever obtain a code. OIDC Core §3.1.2.1 (1.0 incorporating
  errata set 2) re-authenticates only when the elapsed time is *greater than*
  `max_age` and says `max_age=0` is equivalent to `prompt=login`. `max_age=0`
  now takes exactly the `prompt=login` path in `honour::evaluate`: the outbound
  leg always sends the browser to sign in again (`reauth=1`, whatever the
  session's age), and the return leg is answered with a code whose ID token
  carries the new `auth_time`. A forged return-leg marker on an old session
  behaves as it does for `prompt=login` (the interaction is skipped, and
  `auth_time` still reports the old authentication; the accepted residual
  P23W1-08 is unchanged), and `prompt=none` with `max_age=0` is
  `login_required`. Positive `max_age` values keep `>=` and an unmet one is
  still `login_required` on the return leg, so `oidcc-max-age-1` is unaffected;
  the ignore lane still drops `max_age` and `fapi2` still refuses it. Amends
  plan §4.3 test T2.1 and T-239's mitigation text (no new threat id).

- **A FAPI 2.0 client's essential `auth_time` request is refused instead of
  dropped (T23.1.4, D-12).** OIDC Core §2 makes `auth_time` REQUIRED in the ID
  token when `claims.id_token.auth_time` is requested as **essential**, and a
  `fapi2` ID token has never carried it, so such a client was served a token
  without the claim it said it could not do without, and no error — the same
  silent downgrade T23.1.1 closed for `claims.id_token.acr`. The `fapi2` gate
  now answers `invalid_request` naming `claims` for it, on both carriers
  (inline and pushed), by the same mechanism: `claims` is security-bearing when
  it asks for `id_token.acr`, asks for `id_token.auth_time` as essential, or
  cannot be read well enough to rule either out. A *voluntary* `auth_time`
  request (`null`, or `essential: false`) stays as it was, because an OP may
  decline it; a `claims` asking only for `userinfo` members is still served.
  Nothing changes for a `standard` client: on the honour lane an essential
  `auth_time` is honoured (the lane emits it for every session), and on the
  ignore lane it is dropped as before. Amends T-239 (no new threat id).
  `sdks/openapi.json` carries the extended discovery description; no contract
  change. The audit that came with it pinned, over HTTP, the honour-lane rows
  that had been tested only below it: `id_token_hint` must be signed by this
  deployment and name this user and this client (an expired-but-signed one is
  accepted), `prompt=select_account`, the ignore-lane twin for an essential
  `claims.id_token.acr`, and RFC 6750 §2.2's media type on `POST
  /oauth2/userinfo`.

- **A federated login's recorded authentication instant is never later than the
  moment AXIAM verified the assertion (T23.1.2, D-10).** X7.2 dated a federated
  session by what the upstream provider said — OIDC `auth_time`, SAML
  `AuthnInstant` — which is right for a provider replaying a session it
  established hours ago, and had no upper bound for one whose clock runs ahead
  of AXIAM's, or which asserts an instant in the future. Such a session was
  recorded as authenticated after the assertion that produced it, so `max_age`
  was satisfied by an authentication that had not happened yet by AXIAM's
  clock, and the ID token's `auth_time` post-dated its own `iat`. The instant is
  now `min(upstream, verification)`. `AuthenticationEvidence::upstream` takes
  the verification instant as an argument rather than reading the clock, and
  the SSO callbacks apply the same bound when they verify the assertion, before
  it crosses the 60-second handoff hop. A past instant is kept; an instant
  within the federation path's existing 60-second clock-skew allowance is
  clamped silently; one further ahead is clamped and logged at `warn`, naming
  the identity provider. No configuration was added. Amends T-240.

- **A FAPI 2.0 client's essential ACR request is refused instead of dropped,
  and a request object pushed to PAR is refused instead of ignored (T23.1.1).**
  An independent audit of the X7.1 profile-confusion matrix
  ([`basic-op-gap-plan.md`](claude_dev/basic-op-gap-plan.md) §7) found two
  places where a `fapi2` client's security-bearing request parameter was
  silently discarded — the downgrade the matrix exists to prevent. Both are
  amendments to T-239; neither changes anything for a `standard` client.

  *`claims.id_token.acr` on `fapi2`.* `claims` left the refused list when its
  `userinfo` member began to be honoured, and took the `id_token.acr` member
  with it — but that member is read only on the honour lane, which a `fapi2`
  client can never be on. A `fapi2` client asking for an **essential**
  `urn:axiam:acr:mfa` therefore received a token minted from whatever the
  session was, with no `acr` and no error, where OIDC Core §5.5.1.1 says to
  treat the outcome as a failed authentication. `claims` is now
  security-bearing exactly when it asks for `id_token.acr` (or cannot be read
  well enough to rule that out), so the gate answers `invalid_request` naming
  it, on both carriers; a `claims` asking only for `userinfo` members is
  served as before. Plan row M3 is restored to the matrix tests.

  *`request` at `/oauth2/par`.* The authorization endpoint refuses a request
  object with `request_not_supported`, but the PAR body had no `request`
  member, so serde dropped it and the push answered `201`. RFC 9101 §6.3 tells
  a client the server uses only the object's parameters, so a `prompt=login`
  or `max_age=0` inside one never reached the `fapi2` gate or the honour lane.
  The push now answers `400 request_not_supported`, before client
  authentication, and a blank value is still a template on both carriers.
  `sdks/openapi.json` gains the refused member; no SDK sends it.

  The audit also added tests the matrix named and did not have: the gate on
  the pushed carrier over HTTP (every refused parameter, plus the
  `standard`/`ignore` twin, the `userinfo`-only twin and P2), a `fapi2` row
  edited to `honour` in the database refused at `/oauth2/authorize`, a
  repeated parameter refused on both carriers, a strong-method client's secret
  in an `Authorization: Basic` header refused at all five client-authenticating
  endpoints (M9), DCR and CIMD forcing `authn_request_params: ignore` and
  `browser_sso: false` whatever the request says, and the stored-mode decode
  failing closed.

- **A suspended account's OP browser session no longer buys authorization
  codes (T23.1.3).** The `axiam_op_session` cookie names a session row, and it
  lives as long as the session does (`refresh_token_lifetime_secs`). Locking or
  deactivating a user through `PUT /api/v1/users/{id}`, or a
  `PendingVerification` account's grace period running out, revokes no
  session: the refresh path re-reads the account's status instead. Until now
  `/oauth2/authorize` was the one place a session became a principal without
  that read. A suspended user's browser therefore kept obtaining codes, and
  with them access, ID and refresh tokens, at every `browser_sso` relying
  party for the rest of the session. The endpoint now re-reads the account
  behind a resolved OP session and applies the sign-in rule (the refresh
  path's `check_user_status`, grace period included, exposed as
  `AuthService::check_session_holder`). An account that fails it is treated as
  a revoked session: the browser is sent to sign in with `reauth=1`, the
  cookie is cleared, and the return leg answers `login_required`. Nothing
  changes for an active account or for a request carrying an access token.
  The same independent audit of X7.3 added tests for the open-redirect
  validator on both sides (one 56-candidate list refused by the server and by
  the SPA), session fixation, the MFA-pending password step, cross-tenant and
  cross-user cookie use, `POST /oauth2/authorize`, the decline path's delivery
  rule and plan row M7's end-to-end half, and found no other defect. Amends
  T-237 and T-238.

- **An OAuth2 grant stops minting tokens once its account is suspended (F4
  P23W1-01).** Locking or deactivating a user through `PUT
  /api/v1/users/{id}` revokes no credential; the session refresh path and,
  since T23.1.3, `/oauth2/authorize` re-read the account instead. The OAuth2
  `refresh_token` grant did not, and every rotation stamps a fresh
  `expires_at`, so a relying party holding a suspended user's refresh token
  kept minting access and ID tokens for as long as it kept refreshing. The
  `refresh_token` and `authorization_code` grants now re-read the account and
  refuse a locked, inactive, deleted, anonymised or removed one through one
  function (`axiam_auth::service::account_may_act`, which
  `AuthService::check_session_holder` now calls too). A refused account is
  `400 invalid_grant`; nothing is minted, rotated or revoked, so reactivating
  the account restores the grant. Found by the Phase 23 W1 security review as
  a sibling the T23.1.3 fix missed. Amends T-39 and T-237.

- **Browser sign-on works again for federated accounts more than a day old (F4
  P23W1-03).** The T23.1.3 fix above held the OP cookie to the password
  sign-in rule *including the email-verification grace period*. Every new
  account is created `PendingVerification` and federation provisioning never
  moves a federated user off it, so every federated account is pending for
  life: once its grace period ended, `/oauth2/authorize` refused its cookie and
  the login hop sent it round the sign-in page to `login_required`. The
  existing-credential rule (`account_may_act`, used by the cookie and by the
  OAuth2 grants) now refuses only `Locked`, `Inactive`, `Anonymized` and
  `Deleted` — the rule T-160 already applies to token exchange — and leaves the
  grace period to password sign-in, where it belongs. Amends T-237.

- **A suspended account is no longer signed back in by its identity provider
  (F4 P23W1-04).** Every federated callback — OIDC, SAML and plain OAuth2
  "Sign in with …" — loaded the linked AXIAM user and issued a full session
  without reading its status. Locking or deactivating the account in AXIAM, by
  hand or through SCIM `active: false`, left the upstream account untouched,
  so the user's next federated sign-in undid the suspension. Token exchange
  already refused this (T-160); the browser path did not. Every federated
  sign-in now applies `account_may_act` before a session or a handoff code
  exists: a locked, inactive, deleted or anonymised account is refused with
  the sign-in error a password login gets, and a pending one — every
  federated account is — signs in as before. Amends T-160.

## [1.0.0-beta17] - 2026-09-25

### Added

- Ask before a role with non-inheritable assignments goes global (T22.11b, S-10b 2/2)

- Non-inheritable role assignments (T22.11b, S-10b 1/2)

- The Server certificate names card (T22.14b, S-7b 2/2)

- Server certificates with a SAN list (T22.14b, S-7b 1/2)

- Server certificates, a name fence and a leaf usage profile (T22.14, DF-001)

- Service accounts on the management routes (T22.13, DF-013)

- Verify client certificates on the gRPC listener (T22.12, DF-005)

- A role assignment can stop at its resource — `inherit: false` (T22.11, DF-021)

- `setup-token --remint`, gated on a deployment nobody has bootstrapped (T22.7, DF-019)

- Bind a device's access token to the certificate that obtained it (T22.3)

- **Non-inheritable role assignments in the admin console (T22.11b, S-10b).**
  Every assign dialog offers *Also applies to the resource's descendants*
  (`inherit`, checked by default) once a resource is chosen for a role that is
  not global — never where the server would refuse `inherit: false` — and
  sends the field only when it is unchecked, so every other body is unchanged.
  The role's and the group's assignment listings badge a non-inheritable row
  *This resource only*, and *Stop here* / *Include descendants* changes the
  flag after a confirmation naming the effect. Because a second assign is a
  `409` by design, the change is unassign-then-assign; a refused second call
  re-assigns the old assignment and says so, and a failed restore says the
  subject no longer holds the role.
  Saving a role as global while it has non-inheritable assignments now asks
  first, naming them: a global role ignores where it is assigned, so each would
  apply everywhere. A confirmation, not a refusal — the server accepts the
  change, as T-285's residual records; a role with none is saved exactly as
  before.

- **Server certificates in the admin console (T22.14b, S-7b).** The
  certificate dialogs — *Generate Certificate* and *Sign a CSR* — offer the
  `Server` type with a list of subject alternative names, one row per DNS name
  or IP address. The list is shown only for `Server` and required there; every
  other type's request body is unchanged. The console checks shape only (a row
  is not empty, and is DNS or IP); admission is the server's, and its `400` is
  shown verbatim, including the refusal of a `Server` CSR under a `vault_pki`
  CA. The CSR dialog no longer claims that a leaf carries no `keyUsage` or
  `extendedKeyUsage`, which stopped being true with the T22.14 profile.
  A **Server Certificate Names** card edits `server_cert_allowed_names` where
  it is written: the organization's Settings tab (the baseline), a tenant's own
  Settings page (shown as the effective list the server reads back), and the
  tenant detail page's Security Overrides panel, where *Override Server
  certificate names* distinguishes "follow the organization" from "issue none".
  Each explains the three entry forms, that an empty list refuses every
  `Server` request, and that a tenant may only narrow; a widening is the
  server's `400`, shown as it comes.

- **Server certificates, and the names they may carry (T22.14, DF-001).**
  AXIAM could not issue a certificate a TLS *server* can present: leaves
  carried no subjectAltName, and neither request body had a field to ask for
  one. So every listener in a deployment anchored in an AXIAM organization root
  had its certificate signed offline.
  - **`cert_type: Server`**, the only type that carries SANs, requested through
    a new optional **`subject_alt_names`** field on `POST /certificates` and
    `POST /certificates/sign-csr`: `[{"dns": "…"}, {"ip": "…"}]`. The field is
    required for `Server` and refused with `400` on every other type. A CSR that
    itself requests a `subjectAltName` is still refused.
  - **`server_cert_allowed_names`**, a new setting in the organization baseline
    (`certificate.server_cert_allowed_names` when read back). It holds DNS
    suffixes (`.lakeside.internal`, strictly below, on label boundaries), exact
    hosts, and IP prefixes. Every SAN and the common name must be admitted. It
    is **empty by default, and empty refuses every `Server` request.**
  - **Tenants may only narrow the list**, through the same interlock as every
    other override: removing or narrowing an entry is accepted; adding or
    widening one is a `400`. When the organization later shrinks its list, each
    tenant's effective list is the intersection of the two.
  - **Refused, each with a test:** a trailing dot, a Unicode label (write the
    `xn--` form), a wildcard anywhere but a whole leftmost label, and an
    IPv4-mapped IPv6 address.
  - **A `Server` certificate authenticates nobody.** Binding one to a service
    account is refused with `400`, and device login refuses it.
  - **Under `vault_pki` custody** a generated `Server` leaf carries its names
    in the CSR AXIAM builds, because `sign-verbatim` ignores `alt_names` and
    `ip_sans`. A caller-CSR `Server` request is refused under such a CA.
  - Schema **v67**: `certificate.cert_type` admits `Server`, and
    `security_settings` gains the baseline column. No row is rewritten.

- **The gRPC listener can verify client certificates (T22.12, DF-005).** Its TLS
  configuration called `with_no_client_auth()`, and no setting could change
  that. The same listener carries `ReactorAdminService` as well as
  `CheckAccess`, and by default skips session revocation, so a bearer token
  was all any caller ever needed. A device token, which is certificate-bound
  since T22.3, was refused on every gRPC call, because no certificate could
  arrive to match it.

  Two flat variables, **off by default**:

  | Variable | Values |
  |---|---|
  | `AXIAM__GRPC_TLS_CLIENT_AUTH` | `off` (default) \| `optional` \| `required` |
  | `AXIAM__GRPC_TLS_CLIENT_CA_PATH` | PEM bundle; required unless `off` |

  - **`off` is the handshake that shipped before this change.** No
    certificate is requested, and one a client holds is never sent. This is
    asserted by comparing handshakes against the pre-change configuration for
    four client shapes.
  - **`optional`** verifies a certificate when one is presented. **`required`**
    refuses the handshake without one, before any RPC runs.
  - **A verified certificate reaches the auth interceptor.** A token bound to
    a certificate (`cnf.x5t#S256`) is accepted over a connection presenting that
    certificate, and refused with another device's certificate or with none.
  - **One reload for both listeners.** Point the bundle at the REST listener's
    trust-anchor bundle, and flagging a CA in the admin console reloads both
    without a restart. The gRPC listener has its own verifier, because its
    policy may differ from REST's. On each reload it re-reads its own bundle.
    A reload that finds the bundle empty or unreadable keeps the previous
    anchors.
  - **Refuses to boot, rather than warning**, on an unknown mode, on
    `optional`/`required` without a bundle, on a bundle under `off`, on an empty
    or unreadable bundle, and on either variable set while the gRPC listener is
    plaintext. `optional_self_signed` is refused: it exists for RFC 8705 OAuth2
    clients, and their endpoint is not on this listener.

  The certificate is proof of possession and a network gate, not an identity:
  every call still needs a token. Threat **T-286**; T-234 and T-283 amended.

- **A role assignment can stop at its resource: `inherit: false` (T22.11,
  DF-021).** A resource-scoped assignment always applied to its resource and
  every descendant, so "this building, not its apartments" could only be written
  as an allow at the building plus a deny at every apartment — a workaround that
  grows with the tree.

  The three assign routes — `POST /api/v1/roles/{role_id}/users`, `.../groups`,
  `.../service-accounts` — take an optional `inherit`. Omitted or `true` is
  today's cascading assignment; `false` applies the assignment at `resource_id`
  only, "here and no further". The flag belongs to the assignment, not to the
  role's grants, so it stops **allows and denies alike**, and it changes which
  assignments reach a resource, never how deny-override weighs them: a
  non-inheritable allow below an inheritable deny is still denied. The
  precedence table gains rows 9–11 and loses none
  (`claude_dev/deny-override-design.md` §2.2).

  - **Refused with `400` where it would be ignored:** `inherit: false` with no
    `resource_id` (a tenant-wide assignment has no resource to stop at), and on
    a role with `is_global: true` (a global role applies everywhere).
  - **No update.** A subject holds a role at most once, so changing the flag is
    unassign-and-assign; both invalidate the subject's cached decisions. Mind
    the direction: `false` on an allow narrows access, `false` on a **deny**
    widens it.
  - **Visible.** Every assignment listing carries `inherit` beside
    `resource_id`, and the `grant.pre_assign` reactor payload carries it too.
    The admin console offers it since T22.11b (below).

  Nothing existing changes meaning: schema v66 adds `has_role.inherit` as
  `option<bool>` with no backfill, and an absent value reads as `true`.
  OpenAPI and the management registry regenerated. Threat **T-285**; T-16 and
  T-87 amended.

- **`axiam-server setup-token --remint` (T22.7, DF-019).** Only the SHA-256 hash
  of the one-time bootstrap setup token is stored, and the first-boot mint is a
  no-op once a token row exists — so an operator who lost the token from the
  first-boot log had exactly one recovery path, which was to wipe the volume.

  The subcommand deletes the stored hash, mints a fresh token and prints **the
  token and nothing else to stdout** — never through `tracing`, so it does not
  reach the container log a second time. There is deliberately no `--print`: the
  plaintext is not stored, and storing it so that it could be printed would be
  the wrong fix.

  **It refuses, with exit code `2` and no write at all, on any deployment that
  has been bootstrapped** — one with a `user` row, or one where a setup token
  has already been redeemed. That gate is the whole security argument. Before
  bootstrap there is no administrator to take over and no credential to reset,
  which is exactly the state the operator who lost the token is in; after
  bootstrap the deployment has an authenticated way to create accounts and a
  password-reset flow, so re-minting is never the answer. Both gates run before
  the existing hash is deleted, so a refused call leaves the current token
  working. Exit `0` minted, `1` could not tell (configuration, datastore).

  Argv parsing moved into a unit-tested function, for one branch in particular:
  `setup-token` with the flag missing or mistyped now exits `2` instead of
  falling through and starting a second server against the production datastore.
  An argument the binary does not recognise still serves, as before.

  Threat **T-284**.

### Changed

- Re-pin the race probe to surrealdb 3.3.0 and record the run

- Name the collect target in the PUT-membership assertion

- 2026-09-25 sweep — 165 modules, 0 FAILED, with REVIEW evidence

- Follow the SDK to grpc 1.84.0

- Admit the surrealdb 3.3 sub-crates and suppress the quick-xml pair it brings back

- Cargo update

- Sweep every stamped page, move DOCS_VERIFIED_RELEASE to beta17 (wave 4)

- Announce 1.0.0-beta16 and beta17, and extend phase 20 (wave 3)

- Bring the Docs pages up to 1.0.0-beta17 (wave 2)

- The Security section at 1.0.0-beta17 — model 2.17.0

- The nine Phase 21 entries enter the Threat Dragon file — model 2.17.0

- Phase 22 recorded complete; briefs for the threat-model reconciliation and the beta17 website pass

- C-12 — the fix PRs merge as they pass review; the 1.52 re-vendor becomes one follow-up PR per SDK

- C-12 — Rust fix PR #116, the plan's C-12 EXECUTED block, evidence file complete

- C-12 — C# fix PR #97 in §27.14, T22.18 and the evidence file

- C-12 — §27.14 rows updated from the Rust and C# fix reports; roadmap counts corrected

- C-12 evidence file — sdk-dogfooding-conformance-review.md

- C-12 — Kotlin fix PR #69 in §27.14 and T22.18

- C-12 — CHANGELOG 1.52 entry and roadmap T22.18 (PR numbers pending)

- §27.14 — C++ fix PR #68; C++ joins R-15 and R-27

- §27.14 R-13 and R-27 corrected against the fix PRs

- Contract 1.52 — §27.14 review table, log entry, footer, website

- Contract 1.52 text — the C-12 clarifications

- The six C-12 open defects, fixed in five SDK PRs

- Remove the fan-out 1.51 resume ledger

- C-2 … C-11 executed — ten SDK ports at contract 1.51; C-12 questions answered by SDK

- TS #117 merged (f21e561)

- Ledger, §8.1: C++ #66 merged (473ccbb), Go #87 merged; artifact drift 0

- Ledger, §8.1: Swift #66 merged (db24d26)

- C++ #66 green

- Swift #66 green

- Interim artifact drift count (6, all in the two open ports)

- Ledger, §8.1: C-11 C++ opened as #66

- TS #117 green

- C-9 PR open (axiam-swift-sdk#66); §8.1 row; ledger

- Go-sdk#87 green

- SSO gate follow-ups open (go-sdk#87, typescript-sdk#117)

- C-11 sent back

- C-10 merged

- C-9 sent back for four missing tests

- Ledger — resume check-ins re-armed

- C-10 CI green

- C-10 valgrind race fixed (7f3d5db)

- C-10 PR open (axiam-c-sdk#65); §8.1 row; ledger

- C-10 sent back — SSO completions leave a stale gate

- C-6 merged

- C-8 merged

- C-8 and C-6 CI green

- C-9 Swift running

- C-6 PR open (axiam-php-sdk#73); §8.1 row; ledger

- C-8 PR open (axiam-kotlin-sdk#68); §8.1 row; ledger

- Ledger — usage-limit cut-off state; resume

- C-4 merged

- C-6 sent back — §27.6.1 additions are not a tier decline

- C-4 CI green

- C-4 PR open (axiam-java-sdk#102); C-10 running

- C-5 merged

- Ledger — PR check-in re-armed

- C-5 CI green

- C-5 PR open (axiam-csharp-sdk#95); §8.1 row; ledger

- C-4 and C-5 sent back; C-6 running

- Ledger — SSO gate defect in merged Go/TS ports, follow-up blocked on user

- C-2 merged — wave 1 complete

- C-3 merged

- C-7 merged

- C-3 CI green

- C-3 PR open (axiam-python-sdk#88); §8.1 row; ledger

- C-3 second review finding (Q5 docs vs code)

- C-3 sent back for two tests; C-8 running

- C-7 CI green

- C-7 coverage fixed (94.6 %)

- Ledger — coverage floors per SDK; C-7 coverage red

- C-7 PR open (axiam-go-sdk#86); §8.1 row; ledger

- C-2 CI green

- C-2 PR open (axiam-typescript-sdk#116); §8.1 row; ledger

- Ledger — wave 2/3 toolchains installed

- Ledger — wave 1 running

- Resume ledger for C-2 … C-11

- C-1 landed — axiam-rust-sdk#115 merged as 8e9eb90

- C-1 executed — Rust reference at contract 1.51; fan-out record, port prompt, questions for C-12

- Remove the progress ledger

- Ledger — PR #497 open

- 1.51 text names §2's AuthError

- Ledger — steps 5 and 6

- Contract 1.51 — roadmap T22.15, plan EXECUTED block, T-210 amended

- Ledger — steps 3 and 4

- Contract 1.51 — the dogfooding remediation (C-0)

- Ledger — version 1.51, §27.1 recount in scope

- Ledger — step 2 re-validation findings

- Ledger — contract 1.50 is already taken on main

- Ledger — step 1

- Progress ledger for contract 1.50

- Match the allow-list row by its exact label

- §13 — what is open after PR G

- Keep the allow-list out of a panic message (CodeQL rust/cleartext-logging)

- Do not print a service account's creation body on failure

- Serialize the last XFF-discarding test on the counter lock

- Label listing asserts by name, not by a URI carrying an id (CodeQL)

- The bind is required for devices, RSA-4096 generates, and the broker caveats (T22.9, DF-002/007/015/020)

- Bump lapin from 4.11.0 to 4.12.0 in the minor-patch group

- Bump github/codeql-action/upload-sarif

- Bump the minor-patch group in /frontend with 10 updates

- Bump dtolnay/rust-toolchain

- Bump docker/build-push-action from 7.3.0 to 7.4.0

- Bump docker/setup-buildx-action from 4.3.0 to 4.4.1

- Fix plan for the axiam-domo-demo dogfooding findings DF-001…DF-027

- Added ko-fi link to README.md

- **Every leaf certificate now carries a usage profile (T22.14, DF-001).** The
  profile covers both leaf paths and both custodians:

  | Type | keyUsage | extendedKeyUsage |
  |---|---|---|
  | `User`, `Service`, `Device` | digitalSignature, plus keyEncipherment for RSA | clientAuth |
  | `Server` | digitalSignature, plus keyEncipherment for RSA | serverAuth |

  Leaves used to carry neither extension, which X.509 reads as "any usage".
  Vault-signed leaves used to carry Vault's default keyUsage and no EKU. The
  profile only narrows: every use AXIAM makes of a User, Service or Device
  certificate is client authentication, and each keeps it.

  **Migration:** certificates issued before this release are not re-issued.
  They carry neither extension and behave as before until rotated. A consumer
  that asserted "no key usage extension" on an AXIAM leaf must accept the
  profile; nothing in AXIAM did. Under `vault_pki` custody every
  `sign-verbatim` call now states `key_usage`, `ext_key_usage` and
  `exclude_cn_from_sans`.

- **Service accounts can call the management API (T22.13, DF-013).** Every
  management route took a user token only, so a service account could
  authenticate and then reach nothing but `/authz/check`. Automation that
  provisions a tenant was therefore given a human administrator's credential —
  all of that person's roles, revocable only by locking the person out, and
  audited as the person.

  A service-account token (`aud` = `axiam:m2m`) is now accepted on eight
  families, and on nothing else:

  | Admitted | Still human-only (`401` for a machine token) |
  |---|---|
  | resources, scopes, permissions, roles (assignments included), groups, service accounts, certificates (generate, sign-csr, bind, list, get, revoke), webhooks | `/auth/me` and all self-service, MFA, sessions, passwords, users, organizations, tenants, settings, CA certificates, PGP keys, SCIM tokens, federation, OAuth2 clients, reactors, audit logs, notification rules, email config, WebAuthn policy |

  - **Admitted is not allowed.** Each route is authorized by the roles assigned
    to the service account, exactly as for a user. An account with no role is
    refused every one of them with `403` `authorization_denied`.
  - **Tenant scope.** An account in an ordinary tenant acts there only.
    `X-Axiam-Tenant` works for an account in the organization scope on the
    same terms as for an organization administrator. No service account
    issues under the organization CA.
  - **A certificate-bound device token** (T22.3) is refused on these routes
    without its certificate.
  - **The audit log** records `service_account` as the actor type for a
    service account's request, where every authenticated entry used to read
    `user`. `grant.pre_assign` reactor payloads gain `actor_type`.
  - **OpenAPI.** A second security scheme, `service_account`, is listed as an
    alternative on exactly the operations that admit one — the eight families
    and the two `/authz/check` routes. `bearer` gains a description saying it
    is a user token. The management registry is regenerated.

  **Behaviour changes for existing clients.**

  - **User tokens: none.** A converted route now authenticates a user token
    with the very code the other routes use, and a test compares the two
    extractors case by case.
  - **Machine-audience tokens that name a person are now `401`**, on
    `/authz/check` too. An RFC 8693 exchange that narrowed a *user's* token to
    `axiam:m2m` produces such a token (`sub_kind` = `user`). It used to be
    accepted there as a machine, with no session check behind it.
  - **A user token with `sid` distinct from `jti`** (the OAuth2 shape) is now
    accepted on `/authz/check`. The two routes had been refusing it as
    "session revoked or expired".

  Threat **T-287**.

- **A certificate bound to no service account is a `401`, not a `403` (T22.4,
  DF-027).** `POST /api/v1/auth/device` answered `403` for exactly one of its
  refusals, and it reached that status by matching the **text** of an error
  message raised in `axiam-pki`. Both halves were wrong. A `403` asserts an
  identity and then refuses what it may do; a certificate bound to no principal
  identifies nobody, which is what its three sibling refusals — unknown,
  untrusted, self-asserted — already said with `401`. And a status that depends
  on the wording of a message in a lower crate is a status nobody can change
  safely: a reword in `axiam-pki` that never mentions HTTP would have moved it.

  Nothing is newly disclosed. The counter-argument — that `403` hid "unknown
  certificate" from "known but unbound" — does not survive the change: both are
  `401` now, and the bodies were always distinct messages, which a new test
  pins. Clients that mapped `403` on this endpoint to "bound, but not
  permitted" should map `401` and read the body.

### Fixed

- Retry seed_permissions' UPSERTs on a write conflict

- Resolve the backend per request, not once at startup (T22.10, DF-026)

- The legacy-variable assertion prints neither of its fields

- The healthcheck follows the listener, and can verify it (T22.8, DF-016)

- `subject` is a common name, and `CN=` is understood once (T22.6, DF-023)

- Name the variable the env provider actually reads (T22.5, DF-018/DF-022)

- Keep the device rate-limit test's login limit off the cold-entry path

- Send the CSRF cookie as a request header, not a response builder

- An unbound certificate is a 401, not a 403 (T22.4)

- Device_auth_test issues under a tenant signing CA and names a peer

- Rate-limit the device mTLS login (T22.2)

- A signing CA issues only for the tenant it signs for (T22.1)

- Build with the native build system when swift-build fails

- **Saving any setting in the console no longer discards a Server-name
  allow-list (T22.14b).** Between #495 and this change the console knew
  nothing of `server_cert_allowed_names`, and three of its settings writes
  lost it silently:
  - the organization **Settings** tab sends the whole baseline, which the
    server stores whole, so a save of any other field stored the list as empty
    and `reconcile_tenant_overrides` narrowed every tenant to nothing. That
    direction fails closed: no `Server` certificate could be issued until the
    list was re-entered through the API;
  - a tenant's own **Settings** page stores only what differs from the
    baseline, so a save dropped a tenant's narrowing and put the tenant back
    on the organization's wider list;
  - the tenant detail page's **Security Overrides** panel replaces the override
    whole, with the same result.

  Each path now carries the list it loaded. Neither widening could exceed the
  organization's own list, which is the fence T-288 describes.

- **The console resolves its backend per request (T22.10, DF-026).** Its nginx
  named the backend literally in `proxy_pass`, and nginx resolves a literal host
  once, when it loads its configuration. A console started before
  `axiam-server` therefore did not start at all — `host not found in upstream
  "axiam-server"` — and one whose backend was recreated on a new address kept
  the old one and answered `502` until it too was restarted.

  **The three proxy blocks now go through a variable**, which moves the lookup
  to request time: a `resolver` with `valid=30s` in the `server` block,
  `set $axiam_backend ${AXIAM_BACKEND_ORIGIN}` once beside it, and
  `proxy_pass $axiam_backend` in each block. Routing is unchanged, because
  neither form has a URI part and nginx then forwards the client's request URI
  as sent. Sixteen request shapes answered identically under both templates on a
  real nginx before this shipped, and CI pins seven of them. `proxy_ssl_*` is
  untouched, so an `https` origin is verified against `AXIAM_BACKEND_SNI` exactly
  as before.

  **`AXIAM_BACKEND_RESOLVER` is new and needs setting almost nowhere.** Left
  unset, an entrypoint hook reads it from the container's `/etc/resolv.conf`:
  `127.0.0.11` under Docker, the cluster DNS Service under Kubernetes. A fixed
  default of `127.0.0.11` would have been correct on Docker alone. **On
  Kubernetes, `AXIAM_BACKEND_ORIGIN` must be the fully qualified Service name**
  (`axiam-server.axiam.svc.cluster.local`), because nginx's resolver does not
  apply `search` domains; the shipped manifests route the API past the console,
  so they are not affected.

  Every build of the frontend image now renders the template and runs `nginx -t`
  on it, and a new path-filtered workflow, **Console image**, builds the image
  on a pull request and drives the start-order scenario: console first, `502`,
  backend up, `200`, backend moved to a new IP, still `200`, no restart.

- **`axiam-server healthcheck` can probe a TLS listener (T22.8, DF-016).** The
  probe was `reqwest::blocking::get("http://127.0.0.1:8090/health")` with
  `AXIAM_HEALTHCHECK_URL` as its only knob. On a deployment that terminates TLS
  in the server process — which is how `k8s/server/configmap.yml` runs — that is
  a plaintext request to a TLS listener, so the container healthcheck fails
  forever, and the only recourse was an `AXIAM_HEALTHCHECK_URL` pointing at an
  `https://` address the probe then could not verify.

  **The scheme now follows the listener**: `https` when
  `AXIAM__SERVER__TLS__ENABLED` is true *and* a certificate path is set, `http`
  otherwise — both on `AXIAM__SERVER__PORT`, which the old default ignored.
  Both conditions, not just the path: `docker-compose.prod.yml` sets
  `AXIAM__SERVER__TLS__CERT_PATH` unconditionally and gates the listener on
  `ENABLED`, so reading the path alone would have moved every Compose
  deployment's probe to `https` against a plaintext listener.

  **Trust anchors follow the certificate.** `AXIAM_HEALTHCHECK_CA_FILE` names a
  PEM bundle; with none set, an `https` self-probe trusts the server's own
  `AXIAM__SERVER__TLS__CERT_PATH` chain, because a process verifying the
  certificate it is itself serving gains no trust it does not already have. A
  self-signed server certificate works as its own anchor — verified against
  rustls rather than assumed — and so does a `fullchain.pem`; a file holding a
  CA-issued leaf *without* its issuer does not, which is what the CA file is
  for. The documentation says all three, and says that the certificate must
  cover `127.0.0.1` for the derived default to verify.

  **There is no switch that skips verification.** A probe that accepted any
  certificate would report healthy for anything listening on the port, which is
  worse than no probe — a deployment then stops looking. Failures go to stderr,
  where `docker inspect` and `kubectl describe` surface them.

  A plaintext deployment on the default port probes exactly what it probed
  before; `docker-compose.prod.yml` is unchanged.

- **`subject` is a common name, and a `CN=` prefix is understood exactly once
  (T22.6, DF-023).** Every AXIAM certificate — root CA, signing CA, leaf — has
  exactly one distinguished-name component. The API field that carries it is
  called `subject`, and every documented example spelled it
  `CN=ACME Corp Root CA`, so callers sent that. rcgen then pushed the whole
  string as the **value** of a CommonName RDN, producing a DN of
  `CN=CN=ACME Corp Root CA`, while the row stored the string as given. Two wrong
  answers that also disagreed with each other — and a common name no relying
  party matching on it will accept.

  `subject` is now normalised once, at the top of `CaService::generate`,
  `CaService::generate_intermediate` and `CertService::generate`, before
  anything reads it — so the certificate, the stored `subject` column and (for
  `vault_pki` custody) the derived intermediate name all carry the same value.
  A bare name passes through unchanged; a single `CN=` component, in any case,
  is understood and stripped.

  **A distinguished name is refused, not reduced** (decision D-2): anything else
  containing `=`, such as `O=Acme, OU=Devices, CN=device-001`, is a `400` naming
  the rule. The certificate has one CN, so a parser that accepted the full DN
  would have to discard most of what it parsed, and doing that silently is worse
  than saying so. An RFC 4514 parser for a field with one consumer is scope with
  no user.

  Paths whose subject comes from a parsed certificate or CSR — `import`,
  `sign_csr`, the `vault_pki` read-back — are unchanged: their value is already
  a common name, read out of the artefact rather than asserted by a caller.

  Existing callers that sent a bare name see no change. Callers that sent
  `CN=…` now get the certificate they always meant, and the stored `subject`
  loses the prefix — a client that matched the stored value literally should
  match the common name instead. The documentation, the OpenAPI descriptions,
  the admin UI placeholder and the end-to-end fixtures all show the bare form.

- **Four documented secret variables were read by nothing (T22.5, DF-018 /
  DF-022).** `AXIAM__PKI__ENCRYPTION_KEY`, `AXIAM__EMAIL_ENCRYPTION_KEY`,
  `AXIAM__GDPR_PSEUDONYM_PEPPER` and `AXIAM__FEDERATION_ENCRYPTION_KEY` were
  named by the deployment guide, the PKI guide, the GDPR guide, the
  configuration page, a dozen error messages, and — worse — by `just dev-up`,
  `just prod-up`, the benchmark compose file and the conformance harness. None
  of the four ever reached the server. Every cryptographic secret is fetched
  through the secret provider, which addresses secrets by a logical name and,
  under the default `env` provider, resolves that name to `AXIAM__AUTH__<KEY>`.
  Two of the four map to `AppConfig` fields marked `#[serde(skip)]`; the other
  two have no `AppConfig` field at all. The effect was silent: the operator set
  the key, the feature that needed it stayed off, and the fault looked like the
  feature — the mail consumer refusing to spawn, the email-config endpoints
  answering `500`, webhook registration failing closed.

  Every message, document, compose file and recipe now names the variable that
  is read: `AXIAM__AUTH__PKI_ENCRYPTION_KEY`,
  `AXIAM__AUTH__EMAIL_ENCRYPTION_KEY`, `AXIAM__AUTH__GDPR_PSEUDONYM_PEPPER`,
  `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY`. **The old spellings are not
  accepted as aliases** (decision D-1): two names for one secret is the trap
  this finding describes, read from the other side. A deployment that still
  sets one gets a `WARN` at startup naming both spellings — and only when the
  variable AXIAM does read is absent, so a migration that sets both is silent.
  The warning is computed from a predicate that answers *is this variable set*,
  never from its value.

  `AXIAM__AMQP__SIGNING_KEY` is deliberately **not** in that set. It is a real,
  honoured variable that `load_config` deserialises into
  `AmqpConfig::signing_key`; the provider's `AXIAM__AUTH__AMQP_SIGNING_KEY`
  merely wins when both are set. Warning about it would tell an operator with a
  working deployment that it is broken.

  The deployment guide and the configuration page now state the rule itself —
  every secret is `AXIAM__AUTH__<KEY>`, with exactly three exceptions
  (`AXIAM__DB__USERNAME`, `AXIAM__DB__PASSWORD`, `AXIAM__AMQP__URL`) that keep
  the spelling they shipped with — so the next key does not have to be
  discovered the same way.

### Security

- **Device tokens are bound to the certificate that obtained them (T22.3,
  DF-014).** `POST /api/v1/auth/device` authenticates a device by a TLS
  handshake with a client certificate and then handed back a plain **bearer**
  token, so the proof of possession bought nothing after the handshake that
  made it: a token read off a device's flash, or out of a log, was as good as
  the key the device protects. `CnfClaim` and the RFC 8705 `x5t#S256`
  confirmation already existed and were minted for OAuth2 mTLS clients; the
  device path alone omitted them.

  The device token now carries `cnf.x5t#S256` over the certificate rustls
  verified for the connection, and both surfaces refuse it where that
  certificate is not presented again — the REST extractor and the gRPC
  interceptor each run the same `verify_token_binding` on every `cnf`-bearing
  token, so **no enforcement code changed**: the claim was all that was
  missing.

  A token minted before this change carries no `cnf` and is accepted exactly as
  before, so the migration lasts one access-token lifetime. Deployments that
  terminate mTLS at a proxy and forward `X-Client-Certificate` keep getting
  bearer device tokens, deliberately: AXIAM cannot re-check a certificate it
  never saw, and binding a token it would then refuse on first use would be
  worse than not binding it. `docs/pki/README.md` says so, and says what to do
  about it.

- **The device mTLS login is rate-limited (T22.2, DF-028).**
  `POST /api/v1/auth/device` was registered bare — no governor, no shared
  store — while `/auth/login`, the three OPAQUE routes, the six WebAuthn
  ceremony routes and the federation sign-in routes all carried both layers.
  It is also public and CSRF-exempt, as it has to be: a device has no session
  and no cookie. So the one auth endpoint that makes the server complete a TLS
  handshake with a client certificate — the most expensive thing an
  unauthenticated caller can ask of it — was the one an unauthenticated caller
  could ask for without limit.

  New knob `AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN`, default **60**, per IP.
  It sits in the machine family, so `AXIAM__RATE_LIMIT__PROFILE` scales it to
  300 (`gateway`) and 3 000 (`mesh`) — the same 5x and 50x `TOKEN_PER_MIN`
  takes, which is what a fleet behind a single NAT should reach for. No
  existing default moves: a device re-authenticates once per access-token
  lifetime (900 s), so sixty per minute holds nine hundred devices on one
  address and no deployment on the shipped posture sees a new 429.

- **A signing CA now issues only for the tenant it signs for (T22.1, DF-017 /
  DF-025).** `prepare_leaf_issuance` scoped the issuing CA to the
  **organization** and never read `ca_certificate.tenant_id` — the column that
  exists to say which tenant a signing CA signs for. Any principal holding
  `certificates:generate` could therefore name any CA of the organization: a
  sibling tenant's signing CA, or the organization anchor above them. The leaf
  came back recorded under the caller's own tenant, with another tenant's
  issuer, chaining to the root every relying party in the organization trusts;
  the `axiam-domo-demo` dogfooding run rode one to a full MQTT session.

  Both leaf paths — `POST /api/v1/certificates` and
  `POST /api/v1/certificates/sign-csr` — now match the issuing CA against the
  tenant being acted on, and answer **404** when it does not match, following
  the cross-organization precedent: a CA the caller may not use is a CA the
  caller cannot see. The check is made before the CA's status and validity
  window are read, so the refusal cannot be used to learn that a CA exists, is
  revoked, or has expired. An organization-level CA is additionally reachable
  by a principal whose own record lives in the organization's reserved scope,
  which is what leaves the intended path — the organization administrator
  minting under the anchor — byte for byte as it was.

  A tenant that was issuing leaves directly under the organization CA needs a
  signing CA of its own before it can issue again. Certificates already issued
  across the boundary are **not** revoked on upgrade: revocation is an
  operator's act. `docs/pki/README.md` has the reach table and the upgrade
  paragraph.

### Documentation

- **SDK contract 1.52: the C-12 cross-SDK conformance review of the eleven 1.51
  ports (T22.18).** C-12 read each SDK's merged `main` rather than the ports' reports.
  The seven questions 1.51 left open had been answered in up to four ways each, and
  several answers were defects. The review evidence is
  `claude_dev/sdk-dogfooding-conformance-review.md`. `sdks/CONTRACT.md` now writes one
  answer to each, as six rules:
  - **N1, §10.1.** Every public entry point that turns an access token into an identity
    is a rule 9 guard, including an overload with no evidence parameter. A guard that
    cannot reach transport evidence must say in its README that it refuses bound
    tokens.
  - **N2, §17.1.** The acting tenant is the fifth component of the memo key.
  - **N3, §27.13.** A `SubjectAltName` with neither branch or both is refused
    client-side, never sent and never dropped.
  - **N4, §6.1 rule 11 (new).** The device credential's lifecycle:
    - the device POST carries no prior session;
    - a refused device login changes nothing;
    - on success, the credential is used for every request, gRPC included;
    - it is held until logout or another session replaces it;
    - it is never refreshed.
  - **N5, §5.2 rule 1.** The acting-tenant header:
    - it is required on authenticated routes, and never sent off-origin;
    - there is one gate per session;
    - a refusal is `AuthzError`;
    - the responses that record and reset the gate are named;
    - tenant IDs compare as UUIDs.
  - **N6, §27.6.1.** Bindings:
    - a global role with `inherit: false` must be refused;
    - a stated `inherit: true` is accepted, and never sent;
    - a failed rebind is reported as data;
    - `plan` shows a binding Update;
    - metadata compares as JSON values;
    - references resolve by kind.

  The new §27.14 records all thirty-seven divergences, none open. Each is resolved as
  contract fixed, SDK fixed, or forced by the language. §27.10's manifest table is
  refilled from the merged ports. There is no wire change: `openapi.json`,
  `management-registry.json` and `proto/` are unchanged. The C-12 fix PRs merge
  as they pass review. Each SDK then re-vendors `CONTRACT.md` from this change's merge
  commit, in one follow-up PR.

- **SDK contract 1.51 — what the Phase 22 server wave means for the eleven SDKs
  (T22.15, C-0; DF-008 … DF-012).** `sdks/CONTRACT.md` now describes what shipped.
  - **Device login.** `authenticate_device()` joins §1's locked vocabulary and is
    specified in §6.1. It returns `{access_token, token_type, expires_in}`, is reachable
    only with a client certificate, answers `401` for every refusal, and its token is
    certificate-bound (`cnf.x5t#S256`).
  - **Token RPCs.** `validate_token` / `introspect_token` wrap the gRPC `TokenService`
    (new §1.1.1). Until now §10.3 required an SDK to read `cnf` there, while §1 allowed no
    method that could return it.
  - **Acting tenant.** The helper moves from MAY to SHOULD, with a fixed shape (§5.2
    rule 1). It is REST-only, and the value is checked client-side as a UUID, because the
    server silently ignores a malformed one.
  - **`/admin/bootstrap`.** §27.0 lists it with its four outcomes, and no helper.
  - **Manifest.** Resource `metadata`, a resource-scoped role binding with `inherit`, and
    `service_accounts` (§27.6.1). `apply` returns a new account's `client_secret` exactly
    as `create` does, even when a later action fails (§27.5 rule 5).
  - **Per-SDK manifest table.** §27.10 records the two tiers as they are, and three
    defects found reading the code. The PHP manifest never reconciles role grants or
    group bindings. The PHP, Swift, C and C++ manifests never send a resource's parent.
    Swift, C and C++ default a resource type to `"folder"`.
  - **Model notes.** A new §27.13 records S-4, S-7, S-9 and S-10. Every new request field
    is optional. The one thing an existing SDK must tolerate is `"Server"` in
    `certificates.list` responses.
  - **Counts.** §27's figures are re-rendered from the registry: 162 operations, not 147.

  Numbered 1.51 because 1.50 was already taken by the `initial_access_token` fix.
  `openapi.json`, `management-registry.json` and `proto/` are unchanged. All eleven SDKs
  must re-vendor, and `scripts/check-sdk-artifact-drift.py` reports them stale until they
  do. Threat **T-210** is amended: its claim that the SDKs already sent `X-Axiam-Tenant`
  was not true of their code.

- **Device certificates require the bind, and the guide said the opposite
  (T22.9, DF-002).** `docs/pki/README.md` and the website's IoT walkthrough both
  stated that a `Device`-type certificate needs no bind to a service account and
  that looking for a bind endpoint was "looking for something that does not
  exist". `DeviceAuthService::authenticate_device` resolves
  `get_bound_service_account` and refuses with `401` when it answers `None`
  (`crates/axiam-pki/src/mtls.rs:154-160`), so the documented path leaves a
  commissioned fleet failing every login with no obvious cause. Both now state
  the order — service account, certificate, bind, login — the permission
  (`certificates:bind`), that both records must be in the caller's tenant, and
  that the certificate must be `Active` and unexpired at bind time.

- **RSA-4096 CA generation is supported, under every custodian (DF-015).** The
  PKI guide said rcgen's `ring` backend "cannot generate RSA keys, so `POST
  .../ca-certificates` with `Rsa4096` fails", and that Vault custody was the
  only way to generate one. Neither is true: the key is generated by the `rsa`
  crate and handed to rcgen as PKCS#8 (`crates/axiam-pki/src/crypto.rs:70-102`),
  and four tests pin generation and self-signature. Replaced with the trade-off
  that actually applies — RSA-4096 key generation is a probabilistic prime
  search, seconds on a server and tens of seconds with a wide variance on small
  ARM hardware, so a client timeout set for Ed25519 will fire.

- **Two things to decide before putting AXIAM in front of RabbitMQ (DF-007,
  DF-020).** A new section in the broker-TLS chapter of the deployment guide.
  First: with broker-wide `fail_if_no_peer_cert`, AXIAM's own AMQPS client needs
  a certificate before AXIAM exists to issue one — there is no ordering that
  resolves it, so issue that one offline from the same root and let AXIAM issue
  the devices' certificates afterwards. Second: AXIAM's access tokens are not
  consumable by `rabbitmq_auth_backend_oauth2`, whose grammar reads permissions
  out of the `scope` claim — AXIAM's `scope` is an application-defined
  authorization-server claim, and on the device path it is omitted entirely
  because that path cannot request scopes. The arrangement that works is
  certificate login plus an HTTP auth backend.

## [1.0.0-beta16] - 2026-09-19

### Added

- Admin UI for the CIMD posture, and the DCR baseline

- Resolve a URL-shaped client_id from its metadata document (T21.5)

- Per-tenant path issuers, opt-in (T21.6)

- RFC 7591 dynamic client registration (T21.4)

- RFC 8707 resource indicators, end to end (T21.3)

- Admin UI for public OAuth2 clients (T21.2)

- Public clients (`none`) and RFC 8252 loopback redirects (T21.2)

- Serve RFC 8414 discovery alongside OIDC discovery (T21.1)

- OpenTofu stages for the Raspberry Pi 5 k3s deployment

- Host scripts for the Raspberry Pi 5 k3s deployment

- A kustomize overlay for one Raspberry Pi 5 on single-node k3s

- Put TLS on the backend leg, and make the ingress verify it

- Ship the cert-manager examples the manifests already require

- **Admin UI for client ID metadata documents, and for the DCR baseline
  (#477).** The CIMD posture — nine fields, every one a security control by the
  policy's own doc comment — was settable only through the settings API. It now
  has a card on three surfaces: the organization Settings tab, which is the
  only place `cimd.enabled` and `cimd.allow_http` can be turned **on**, because
  both are ordered and no tenant may widen them; the tenant settings page; and
  the organization administrator's per-tenant override panel, where the posture
  is taken over whole or inherited whole, exactly as `Option<CimdPolicy>` models
  it. Both interlocks and all three bounds are mirrored client-side in the
  server's own words — CIMD cannot be enabled while
  `external_client_allowed_resources` is empty (D3) or while
  `cimd.trusted_client_id_domains` is, and that list refuses `*` and a wildcard
  over a whole top-level domain — each rendered under the field it names and
  each blocking the save, so an operator meets the refusal in the form rather
  than in a `400` body. The Dynamic Client Registration card is mounted on the
  organization tab for the same reason: `dynamic_registration` is tighten-only
  against a baseline that defaults to `disabled`, so until now nothing in the
  console could raise it. The per-tenant override panel gains a dynamic
  registration group with it, without which saving any other group discarded a
  tenant's registration policy. Its two counters' help text now says what T21.8
  made true: both govern `managed_by: cimd` rows as well, and a never-authorized
  `anonymous` registration is swept after one hour whatever the TTL says.
  Default (`enabled: false`) tenants see none of it — a badge reading
  **Disabled** and nothing else.

- **Client ID metadata documents (CIMD).** A tenant can accept a `client_id`
  that is an `https` URL and fetch the JSON document published there as the
  client's registration — `draft-ietf-oauth-client-id-metadata-document`, the
  mechanism that lets a desktop MCP client be the same client at every
  deployment it talks to with nothing registered in advance. Enabled by the
  new tenant policy `cimd.enabled` (default `false`): with it off, a
  URL-shaped `client_id` is byte-for-byte today's unknown client and no
  document is ever fetched. Enabling it is refused while
  `external_client_allowed_resources` is empty (a client from a stranger's
  document inherits that list as its audiences and must not be able to name
  its own) or while `cimd.trusted_client_id_domains` is empty (the fetch is
  reachable by an unauthenticated caller who chooses the URL). Eight further
  policy fields bound it: `allow_http`, `trusted_redirect_domains`,
  `restrict_same_domain`, `confidential_only`, `min_cache_secs`,
  `max_cache_secs` and `max_metadata_bytes`. A materialised client is
  `managed_by: cimd`, always faces the consent screen, can never carry a FAPI
  profile, holds no secret, and never overwrites a registration an
  administrator created. The document is fetched through AXIAM's shared SSRF
  guard — resolve, canonicalise, validate, pin, no automatic redirects — with
  a streaming size cap, a content-type check and a timeout. A tenant that
  enables it advertises `client_id_metadata_document_supported` in its
  discovery document; every other tenant's document is unchanged, member for
  member. See
  [`docs/admin/client-id-metadata-documents.md`](docs/admin/client-id-metadata-documents.md)
  (T21.5).

- **SDK contract §28 — MCP resource-server helpers (contract 1.48).** The
  eleven SDKs gain a specified surface for the resource-server half of the MCP
  authorization handshake: build and validate the RFC 9728 protected-resource
  metadata document, serve it unauthenticated at the path RFC 9728 §3.1 derives
  from the resource identifier, and build the RFC 6750 `WWW-Authenticate`
  challenge. One new middleware option, `resource_metadata_url`, attaches that
  challenge to the 401s the guard already emits and to the one class of 403
  where a named scope was missing; with the option unset a guard is
  byte-for-byte what it was, which §28.9 makes a required regression. Setting
  it makes the §10.1 row 6 audience check mandatory — a resource server that
  announces itself must check that a token was minted for it. No AXIAM
  behaviour changes: AXIAM is the authorization server and implements none of
  §28. Contract 1.48 also folds in the `openapi.json` entry T21.3 recorded
  unnumbered, and all eleven SDK repositories must re-sync the vendored
  `CONTRACT.md` (T21.9).

- **SDK contract §28.11 — the cross-SDK conformance review (contract 1.49).**
  All eleven ports of §28 were read against the section and against the
  TypeScript reference, and their thirteen divergences are recorded in a new
  §28.11 with no open row; the evidence is
  [`claude_dev/sdk-mcp-helpers-conformance-review.md`](claude_dev/sdk-mcp-helpers-conformance-review.md).
  Contract 1.49 is non-breaking and clarifying — an SDK written against 1.48 is
  conformant unedited. It fixes six places where §28 was wrong or silent: §28.3
  rule 1 now binds the `Content-Type` **media type** rather than the header
  verbatim, because Fastify appends a charset and offers no supported way not
  to; §28.4 and §28.9 test 2 state that how the `error` parameter is typed is
  the SDK's own choice and how the `invalid_grant` vector is discharged where a
  closed type makes it unwritable; §28.5 rule 4 provides for a §11 helper that
  receives a resolved identity rather than a request and so cannot tell "no
  credential" from "credential rejected"; §28.7's C row gains the
  `metadata_url` accessor §28.1 always required, reserves `MCPResourceMetadata`
  as Go's returned type while stating that no other language needs the
  accommodation, and records that "raises the SDK's `ValidationError`" is a
  per-language mapping; and §28.10's posture table is now maintained upstream by
  the review rather than edited by each port in its own vendored copy — the
  instruction that left the eleven holding five distinct byte-states of one
  document. The 1.49 trailer also states the vendoring rule 1.48 lacked: a
  vendored artefact is re-synced from a **merged** `main`, never a phase branch,
  and the `openapi.json` re-sync is deferred to one named follow-up recorded in
  all eleven repositories. No AXIAM behaviour changes and no server API surface
  moves (T21.9).

- **Documentation and a runnable example for fronting an MCP server with
  AXIAM.** [`docs/api/mcp.md`](docs/api/mcp.md) ties together the pieces T21.1
  through T21.6 and T21.9 shipped separately: the RFC 9728 protected-resource
  document and `WWW-Authenticate` challenge an MCP server publishes (built
  with the SDK's §28 helpers, not by AXIAM), the SDK middleware configuration
  that checks it, tenant settings translated from Keycloak's MCP guide for
  MCP Inspector, VS Code and Claude Code, the D3 audience warning, and one
  worked example per registration mode. [`examples/b7-mcp-server/`](examples/b7-mcp-server)
  is a runnable MCP server on the official `@modelcontextprotocol/sdk`
  streamable-HTTP transport, with a `walkthrough.sh` driving 401 → discovery →
  registration → PKCE + `resource` → token → tool call in each of
  pre-registered, dynamic-registration and CIMD mode, and a `smoke-test.sh`
  proving the server runs. No AXIAM behaviour changes (T21.7).

- **`GET /.well-known/oauth-authorization-server`** (T21.1) — the RFC 8414
  authorization-server metadata path, serving the same document as
  `/.well-known/openid-configuration` with the same optional `?tenant_id=`.
  No flag: the alias is always on, since it publishes nothing the OIDC path
  does not already publish. MCP clients probe this path first and several
  client libraries never fall back to the OIDC one.

- **Public clients (`token_endpoint_auth_method: "none"`).** An OAuth2 client
  can be registered with no credential at all (RFC 6749 §2.1) and completes the
  authorization-code flow with PKCE instead — the shape a desktop or CLI
  application (Claude Code, VS Code, the MCP Inspector), a single-page
  application or a mobile app actually has. The registration mints no secret
  and the creation response carries no `client_secret` member. Enabled per
  client by that one field; a deployment that registers none is unaffected.
  Public clients are refused the `client_credentials`, token-exchange and
  uma-ticket grants, the `fapi2` profile, any mTLS or `private_key_jwt`
  binding, and token introspection; a client registered for a credential that
  omits it is still `invalid_client`, and the method cannot be changed across
  the public/confidential line by an update. See
  [`docs/admin/public-clients.md`](docs/admin/public-clients.md) (T21.2).

- **Loopback redirect URIs accept any port (RFC 8252 §7.3).** A registered
  redirect URI whose scheme is `http` and whose host is `127.0.0.1`, `[::1]` or
  `localhost` now matches a request that presents a different port, so a
  desktop client can listen on the ephemeral port its operating system hands
  it. Scheme, host, path, query and fragment must still match exactly;
  `localhost` and `127.0.0.1` remain distinct hosts; every `https` redirect URI
  keeps byte-for-byte matching; and the token request's `redirect_uri` is still
  compared exactly against the one the code was issued to (T21.2).

- `none` is advertised last in `token_endpoint_auth_methods_supported` at
  `/.well-known/openid-configuration` — a capability statement about the
  deployment, not per-client posture (T21.2).

- **Admin UI for public clients.** The OAuth2 client form offers "Public
  client (no secret)" as a Token Endpoint Authentication option, validates
  the T21.2 refusals (credential-bearing grants, the `fapi2` profile, an
  mTLS/`private_key_jwt` credential alongside `none`, and moving a client
  across the public/confidential line by editing it) before the request is
  sent, and skips the one-time secret dialog for a client that has no secret
  to show (T21.2).

- **RFC 8707 resource indicators.** A `resource` parameter on
  `/oauth2/authorize`, `/oauth2/par`, `/oauth2/device_authorization` and
  `/oauth2/token` names the service a token is for, and the access token minted
  carries that URI as its `aud` instead of `axiam:user` / `axiam:m2m` — which
  is what lets an MCP server, a partner API or one service in a mesh check that
  a token was issued for *it*. Enabled per client by the new
  `allowed_resources` registration field, which is empty on every existing
  client; a request that sends no `resource` mints exactly the token it always
  did. Entries are absolute URIs without a fragment, compared after RFC 3986
  §6.2.2 normalisation and never by prefix; an unregistered or malformed value
  is `invalid_target`, and a second value is too. See
  [`docs/api/resource-indicators.md`](docs/api/resource-indicators.md) (T21.3).

- **A grant's audience cannot be widened.** The resource travels with the grant
  — onto the authorization code, the device grant and the refresh token, where
  each rotation copies it forward — so a refresh re-mints the *same* audience.
  A token request or refresh may repeat the resource or omit it; naming a
  different one, or naming one at all on a grant that was issued without one,
  is `invalid_target` (T21.3).

- **`aud` in the introspection response (RFC 7662 §2.2).** Introspection now
  reports the token's audience, and decodes resource-bound tokens rather than
  reporting them inactive — an introspecting resource server's whole audience
  check is "is this token for me", and it had no way to ask. AXIAM's own REST
  and gRPC endpoints are **unchanged**: they still accept only `axiam:user` and
  `axiam:m2m`, so a token minted for another resource server is refused with
  `401` / `UNAUTHENTICATED` there (T21.3).

- **RFC 7591 dynamic client registration.** `POST /oauth2/register?tenant_id=`
  lets a client create itself, which is what MCP Inspector, Claude Code and
  VS Code expect from an authorization server. **Off by default on every
  tenant**: the new `dynamic_registration` tenant policy is `disabled` unless an
  operator sets it, and the endpoint answers `403` until they do, so the path
  exists and the feature does not. The two other modes are
  `initial_access_token` (RFC 7591 §1.2's protected profile — a caller presents
  a single-use token an administrator minted) and `anonymous` (the open
  profile). A tenant on `disabled` also has no `registration_endpoint` in its
  discovery document, which is therefore byte-identical to the one it served
  before. See
  [`docs/admin/dynamic-client-registration.md`](docs/admin/dynamic-client-registration.md)
  (T21.4).

- **A self-registered client cannot choose its own audiences (D3).** It
  inherits the tenant's new `external_client_allowed_resources` list verbatim
  as its `allowed_resources`, and AXIAM **refuses to store a policy** that
  enables `anonymous` registration while that list is empty — an empty list
  would leave a stranger's client able to obtain the `axiam:user` tokens
  AXIAM's own APIs accept. The same list will be shared with Client ID Metadata
  Documents (T21.4).

- **A self-registered client always gets a consent screen (D4).** The first
  authorization per end user for a client an administrator did not create goes
  through the existing consent hop, whatever scopes it asked for, and the grant
  is recorded through the ordinary OIDC-scope consent records — so the end user
  withdraws it from the account page with no new control. The record covers the
  scope set the user was shown, so a client that later asks for more re-prompts
  (T21.4).

- **`POST` / `GET /api/v1/oauth2-clients/registration-tokens`** — mint and list
  the single-use, TTL-bounded initial access tokens `initial_access_token` mode
  requires. The handle is shown once, carries no identity beyond its tenant,
  and is refused for a tenant not in that mode. Gated on `oauth2_clients:create`
  and `oauth2_clients:list` (T21.4).

- **Abuse controls on the registration endpoint.** A per-IP rate limit
  (`AXIAM__RATE_LIMIT__DCR_PER_MIN`, default **5/min** — the smallest in AXIAM,
  because this is the only endpoint that writes for a caller holding no
  credential), a per-tenant ceiling (`dcr_max_clients`, default 20), a
  background sweep that deletes self-registered clients unused for
  `dcr_unused_client_ttl_days` (default 30; `0` disables it) and reports itself
  at `/health/jobs` as `dcr_unused_clients`, and an audit event for **every**
  registration attempt, successful or not. The sweep never touches a client an
  administrator created (T21.4).

- **A `managed_by` discriminator on OAuth2 clients (D5).** `admin` for every
  client that exists today and everything created through
  `POST /api/v1/oauth2-clients`, `dcr` for a self-registered one. A client that
  is not `admin` may never carry the `fapi2` profile, is always consent-gated,
  and is the only kind the sweeper touches. It is set by the creating code path
  and is absent from the update API — a registration's provenance is a fact
  about how it came to exist (T21.4).

- **Admin UI for dynamic client registration.** The tenant settings page gains
  a Dynamic Client Registration card for every `T21.4` policy field
  (`dynamic_registration`, `dcr_allowed_scopes`, `dcr_allowed_redirect_hosts`,
  `external_client_allowed_resources`, `dcr_max_clients`,
  `dcr_unused_client_ttl_days`), refusing to save `anonymous` mode with an
  empty audience list (D3) or a `dcr_allowed_scopes` naming `address`/`phone`
  client-side, with the same messages the server answers with. The OAuth2
  Clients page gains registration-token issuance (single-use, shown once, like
  a client secret; only shown once a tenant is in `initial_access_token`
  mode), a `managed_by` badge and filter in the client list, and a read-only
  detail view for a `dcr`/`cimd` client in place of the edit form — AXIAM does
  not model an administrator editing a self-registration. The audit log viewer
  badges the three new registration events. Default (`disabled`) tenants see
  none of it (T21.4b).

- **Per-tenant path issuers (`AXIAM__AUTH__TENANT_ISSUER_PATHS`, default
  `false`).** With the flag set, each tenant gains a second issuer identifier,
  `{root}/t/{tenant_id}` — one with no query string, so it is an issuer an MCP
  server can name in the `authorization_servers` of its RFC 9728
  protected-resource metadata and an MCP client can turn into a discovery URL.
  Discovery is served at all three conventional forms (RFC 8414 §3.1 path
  insertion at both well-known paths, and the OIDC Discovery §4 append), each
  returning the identical document whose endpoints are
  `{root}/t/{tenant_id}/oauth2/…` with no `tenant_id` query. An Actix scope
  `/t/{tenant_id}` re-bases the existing OAuth2 endpoints — the same handlers,
  no duplicates — and the `iss` of everything minted there is the tenant issuer:
  the access token, the ID token, the RFC 9207 authorization-response parameter
  and the Back-Channel Logout token. One JWKS signs every issuer. AXIAM's own
  extractors accept the root issuer and any `{root}/t/{uuid}`; the audience
  rules are untouched. With the flag unset nothing is mounted and the existing
  `?tenant_id=` documents are byte-identical. See the issuer section of
  [`docs/deployment/README.md`](docs/deployment/README.md) (T21.6).

- **Tenant isolation under path issuers.** Because one key set signs every
  tenant's tokens, two checks were added rather than assumed: a token whose
  `iss` names a different tenant from its `tenant_id` claim is refused, and a
  token presented under `/t/{tenant}` whose tenant is not that one is refused
  with `401` — the same answer a request with no credential gets. A `tenant_id`
  query parameter on a tenant path is `invalid_request`, agreeing or not
  (T21.6).

### Changed

- Re-pin to surrealkv 0.21.4 and record the re-measurement

- Track Package.resolved, as go.sum is tracked for the Go bench

- Record the 2026-09-13/14 quick-task plans and summaries

- Add the 2026-09-13 and 2026-09-14 sweep reports

- Cache client managed_by on the authorize path

- 2026-09-18 sweep — 165 modules, 0 FAILED, with REVIEW evidence

- Follow the Go SDK main onto jwx v3.3.0

- Measure the T21 MCP-authorization surface — discovery and PKCE redemption

- Drop the rkyv suppression the dependency update made stale

- Updated dependencies

- Record the CIMD surface in the matrix, and what it taught

- Extract the DCR card into its own module

- Revalidate the CIMD admin UI plan against main @ 320ef53

- Plan the CIMD admin UI, and the org-settings save that erases it

- Close T-272, T-275 and T-276 in the records

- Pin MCP-06's refusal, and close T-280 in the records

- Decide and plan the four T21.8 findings (#469–#472)

- Bump the migration tripwire to v65, and hold it to v64's standard

- Record the dcr handler's admin surfaces (T21.4)

- Document AXIAM__RATE_LIMIT__DCR_PER_MIN (T21.4)

- Phase 21 executed — status, commits, and what the plan got wrong

- Correct §28.10/§28.11 R-2's count of unrecorded posture rows

- Discharge the I1 conformance condition, and link the filed findings

- Rustfmt the T21.8 harness and the resource guard

- The MCP security review, and nine STRIDE entries for it (T21.8)

- §28 cross-SDK conformance review, contract 1.49 (T21.9 T9d)

- The adversarial half of the T21.8 harness

- The MCP client sequence end to end, in both issuer modes (T21.8)

- Fronting an MCP server with AXIAM, and the b7-mcp-server example

- Client ID metadata documents — operator page, spec, contract (T21.5)

- Add admin UI for dynamic client registration (T21.4b)

- Bring the orchestrator's amendments onto the accumulation branch

- §28 MCP resource-server helpers, contract 1.48 (T21.9)

- Generate the public-client fixture's password (CodeQL)

- Re-derive management-registry.json after the spec regeneration

- Regenerate sdks/openapi.json for the RFC 8414 discovery alias

- MCP plan — definition of done, SDK fan-out (T21.9), kick-off prompt

- AXIAM as an MCP authorization server — phase 21 plan

- Mark the Pi 5 k3s/OpenTofu plan EXECUTED, and close two verification gaps

- The operator guide for AXIAM on a Pi 5 with k3s

- Name the mandatory runtime settings in the base ConfigMap

- K3s + OpenTofu variant of the Raspberry Pi 5 deployment

- Record the beta15 website pass as EXECUTED

- Sweep every stamped page, move DOCS_VERIFIED_RELEASE to beta15

- Announce 1.0.0-beta15, and extend phase 20 (wave 3)

- Bring the Docs pages up to 1.0.0-beta15 (wave 2)

- The Security section at 1.0.0-beta15 — model 2.16.0

- **Token exchange reads `allowed_resources` for its `audience`/`resource`
  target, and the redirect-URI allow-list is deprecated (SEC-089).** A target is
  accepted if it is one of AXIAM's built-in audiences, appears in
  `allowed_resources`, or — for one release — appears in the client's
  `redirect_uris`. The last branch logs a deprecation warning naming the client
  and the target when it is the one that matched; it will be removed in the next
  release. Nothing that worked stops working today. Move exchange targets to
  `allowed_resources` now:
  [`docs/api/token-exchange.md#audience`](docs/api/token-exchange.md#audience)
  (T21.3).

- **The issuer boot check now says what it is about.** A configured
  `AXIAM__AUTH__OAUTH2_ISSUER_URL` must still be a bare root URL, and the
  message says why: the per-tenant issuer path is derived from it as
  `{root}/t/{tenant_id}` and is never configured. Setting
  `AXIAM__AUTH__TENANT_ISSUER_PATHS` without a root issuer is refused at boot
  rather than producing issuers no client can resolve (T21.6).

### Fixed

- Mark the DCR initial access token Sensitive — contract 1.50

- Carry the whole OIDC policy through an organization save

- Reclaim a never-authorized registration in an hour (MCP-05)

- Bound and reclaim CIMD shadow rows (MCP-04)

- Refuse a wildcard trusted-publisher list for CIMD (MCP-03)

- Accept http://[::1] as a redirect URI

- Redirect an authorization error to a loopback client's port (MCP-01)

- Let AXIAM reach the CIMD publisher from its container

- SC2015 on the org-id guard, and drop a dead jq fallback

- Raise the org baseline, and drop the port from a host pattern

- Return run_erasure_pipeline's doc comment to its function

- Reserve the axiam scheme against use as a resource (MCP-02)

- Six stale struct initializers that stopped compiling before T21.5

- Commit the regenerated spec the merge resolution actually produced

- Compare PathItem via JSON in the discovery-alias unit test

- Make the Vault StatefulSet admit under Pod Security `restricted`

- Open the server -> Vault path, both halves

- Give Vault a component label so commonLabels cannot collapse its selector

- **`/oauth2/authorize` throughput regression since T21.4.** The
  external-consent gate read the client row a second time on every
  authorization, only to learn its `managed_by`. That cost about 19% of
  throughput (609/s to 495/s, p95 113 ms to 156 ms). The value can never
  change for a `(tenant, client_id)`, so it is now served from a bounded 60 s
  cache. Missing clients are not cached, and the service still validates the
  client from a fresh read.

- **Saving the organization settings page reset nine OIDC policy fields
  (#477).** The frontend's `SetOrgSettings` carried no OIDC keys, so every save
  from the organization Settings tab omitted `sensitive_scopes_enabled`,
  `default_locale`, `dynamic_registration`, `dcr_allowed_scopes`,
  `dcr_allowed_redirect_hosts`, `external_client_allowed_resources`,
  `dcr_max_clients`, `dcr_unused_client_ttl_days` and the whole `cimd` posture.
  Each is `#[serde(default)]` on the backend and `PUT
  /organizations/{id}/settings` replaces the whole row, so an administrator
  editing a password rule turned dynamic client registration and client ID
  metadata documents off across the organization — and the baseline clamp that
  runs after the write then dropped every tenant's own posture for being more
  permissive than a baseline that had just been reset. Nothing in the response
  said so. The same defect had reached `sensitive_scopes_enabled` and
  `default_locale` since W7 shipped. The organization form now round-trips all
  nine from the GET, with the server's own defaults when the response carries
  no `oidc` block. No API, schema or settings-field change: the write shape was
  short of the contract it already had.

- **`http://[::1]/…` can be registered as a redirect URI (T21.8).** The
  structural validator both registration endpoints share compared the parsed
  host against `::1`, while a URL parser returns an IPv6 literal *with* its
  brackets — so the IPv6 loopback arm was unreachable and the refusal named
  `::1` as allowed in the same message that refused it. Every other loopback
  comparison in AXIAM spells it `[::1]`: the redirect matcher, the dynamic
  registration host allow-list and the CIMD document validator, all tested on
  it. RFC 8252 §7.3 lists the IPv6 loopback beside `127.0.0.1`. This is the one
  change in this group that makes a request that was refused succeed; the
  widening is one host, reachable only from the machine the user is sitting at,
  and a routable IPv6 literal over `http` is still refused.

- **An authorization error is redirected to a desktop client's ephemeral
  loopback port (MCP-01, T21.8, #472).** Six refusal paths in the authorization
  and PAR handlers compared the presented `redirect_uri` with `==` while the
  success path has applied RFC 8252 §7.3's port allowance since T21.2a. The
  effect landed on exactly the clients this phase exists to serve: a client
  that registered `http://127.0.0.1/callback` and listened on the port the
  operating system gave it got its codes redirected and its errors rendered as
  a page nothing was reading. All six now route through
  `any_redirect_uri_matches`, the one comparison the success path uses.
  Ungated — the widening is bounded by what the client registered, and for any
  registration that is not an `http` loopback URI the matcher is string
  equality and the answer is byte-for-byte unchanged. No error is redirected to
  a URI that was not registered, before or after.

### Security

- **The DCR initial access token is now `Sensitive<T>` in every SDK (contract
  1.50).** `oauth2_clients.create_registration_token` returns
  `initial_access_token`, a one-time bearer credential, but T21.4 never added it
  to the management registry's curated secret table. So all eleven SDK
  generators emitted it as a plain string that appeared in debug and `toString`
  output. The registry now marks it, CONTRACT.md §27.5 lists it (fifteen
  operations), and the SDKs pick it up on their 1.50 re-sync. The wire format
  is unchanged. Only the SDK-side type moves, which is source-breaking for a
  caller that reads the field.

- **`cimd.trusted_client_id_domains` no longer accepts `*` (MCP-03, T21.8,
  #469).** Enabling client ID metadata documents with an *empty*
  trusted-publisher list was already refused, because the fetch is triggered by
  an unauthenticated request that names the URL and no second control bounds
  which host a caller may name — AXIAM's SSRF guard bounds addresses, not
  hosts. `["*"]` produced the same posture and was admitted, so the refusal had
  a one-character bypass and the validator's own entry-shape message
  recommended the spelling that produced it. `*` is now refused, and so is a
  wildcard over a whole top-level domain (`*.com`, `*.io`), which is the same
  posture spelled longer. It is a floor rather than a public-suffix check:
  `*.github.io` still passes, because trusting shared hosting is a decision an
  operator may reasonably make and what bounds it is the per-tenant quota, not
  this rule. `*` remains valid in `cimd.trusted_redirect_domains`, whose
  entries are not fetch targets. Enforced at both settings doors. Validation
  runs on write, so a stored `*` keeps working until that settings row is next
  saved — and no released deployment can hold one, because CIMD itself ships in
  this same unreleased version.

- **A registration nobody authorized is reclaimed in an hour, not thirty days
  (MCP-05, T21.8, #471).** In `anonymous` mode `dcr_max_clients` (default 20)
  is a storage bound *and* an availability budget, and one unauthenticated
  stranger could spend all of it in about four minutes at the endpoint's
  five-a-minute rate limit — then hold it for `dcr_unused_client_ttl_days`,
  30 days by default, because one TTL served two situations with nothing in
  common. The 30-day window is sized for a client somebody uses monthly; a
  client registered and never authorized is not that client, and every MCP
  client this phase serves authorizes within seconds of registering because
  registration is the first step of the same flow. The sweeper now measures a
  `managed_by: dcr` row with no `last_authorized_at`, in a tenant whose
  effective mode is `anonymous`, against **one hour** from `created_at`. It
  does not apply in `initial_access_token` or `disabled` mode — there the row
  exists because an administrator minted a handle, and an operator who does
  that on Friday should not find the registration gone on Monday — it does not
  touch a client that has completed a flow, and it is not switched off by
  `dcr_unused_client_ttl_days: 0`, which is a decision about clients somebody
  uses. The hour is a constant, not a tenant setting: making it one needs a new
  `security_settings` column and therefore a schema migration, which is the
  maintainer's call rather than this change's, and the constant's own
  documentation says what promoting it would cost. `docs/admin/dynamic-client-registration.md`
  now also gives the reason to prefer `initial_access_token` that matters most
  — its quota cannot be spent by somebody with no credential. A per-IP share of
  the quota remains the accepted residual.

- **CIMD shadow rows are bounded by a quota and reclaimed by a sweep (MCP-04,
  T21.8, #470).** A `managed_by: cimd` row counted against no ceiling and was
  deleted by nothing, so a tenant whose trusted-publisher list named shared
  hosting grew client rows without limit, one unauthenticated request each.
  Three bounds, and no new setting or migration for any of them.
  `dcr_max_clients` now caps CIMD rows too, **counted separately against the
  same number** so neither mechanism can exhaust the other's allowance, and
  checked *before* the document is fetched — a tenant at its ceiling must not
  be an outbound amplifier either. The refusal is audited as
  `oauth2.client_registration_refused` with `managed_by: cimd` and carries no
  client-supplied string. `dcr_unused_client_ttl_days` now sweeps CIMD rows on
  their own clock and their own `/health/jobs` counter
  (`cimd_unused_clients`): the clock is the last time the document was
  *presented*, which every authorize, token and PAR request moves, so a
  document in daily use is never swept and one nobody has presented for a
  month is — and re-materialises on the next request if it is still published,
  which is what a cache should do. And the in-memory document cache now evicts
  entries past their TTL and their 24-hour stale window on the insert path,
  since a cache that is never evicted is not a cache. Both fields keep their
  `dcr_` names because dynamic registration defined them, on the precedent
  `dcr_allowed_scopes` set. Unreachable with `cimd.enabled` false, which is the
  default.

- **The `axiam` URI scheme is reserved and can no longer be named as a
  `resource` (MCP-02, T21.8).** AXIAM's own token audiences are spelled
  `axiam:user` and `axiam:m2m`, which are well-formed absolute URIs and were
  therefore well-formed RFC 8707 resource indicators. Registering one in
  `allowed_resources` and naming it in `resource` let a grant mint a token
  stamped with AXIAM's own audience — most sharply on `client_credentials`,
  which mints `axiam:m2m` when no resource is named and would have minted
  `axiam:user` when that one was, reaching past the audience boundary
  invariant I3 is built out of instead of being confined by it. Registration
  and every grant now answer `invalid_target` for any `axiam:` value. No
  deployment can have relied on this: `allowed_resources` is new in this
  release, and the refusal is fail-closed.

## [1.0.0-beta15] - 2026-09-15

### Added

- **`conformance/scripts/run-some.sh`** — create one OIDF plan and run only the
  modules you name in it. A whole-plan sweep is the wrong tool while iterating
  on two modules, and the alternative was re-running dozens of authorizations
  for each attempt. `just conformance-up` now also imports
  `conformance/certs/ca.crt` into the suite's JVM truststore and restarts the
  suite, which `suite.env` has claimed it did since W9 and which it did not.

- **A certificate for a key AXIAM never sees.** `POST /api/v1/certificates/sign-csr`
  issues an end-entity certificate from an uploaded PKCS#10 request, so a key
  can be born in an HSM, an offline ceremony or a device's own secure element
  and never cross the wire in either direction (C-1, T-268). The response is a
  `Certificate` and carries no key field, because there is no key to carry.
  Permission `certificates:generate`, the same as generation — a caller allowed
  to mint a certificate under a CA is allowed to mint one for a key they
  already hold, and this path is the less powerful of the two.

  What AXIAM decides rather than the request: possession is proved by the
  request's own signature; the key must be Ed25519 or RSA with a measured
  modulus of at least 4096 bits; a request asking for a `subjectAltName`,
  `keyUsage` or `extendedKeyUsage` is refused by name rather than silently
  stripped, and every other requested extension is discarded. A CSR asking to
  be a CA comes back a leaf. A CSR-signed certificate is byte-for-byte the same
  shape as a generated one, and binds and authenticates over mTLS identically.

  Contract 1.45 adds `certificates.sign_csr` to the §27 management surface,
  taking it from 159 operations to 160. The admin UI's Certificates page gains
  a **Sign a CSR** action that takes the request as a paste or a file upload
  (C-2).

- **A passkey or a security key can be the first factor.** Forced first-login
  enrolment under a tenant that requires MFA offered TOTP only, so a tenant
  whose authenticator policy is built around security keys still had to hand
  every new user a TOTP app to get in (M-3, T-269). `POST
  /api/v1/auth/webauthn/setup/register/start` and `/finish` run the same
  registration ceremony from the same setup token, under the same attestation
  and user-verification policies as the profile page's, and `finish` completes
  the interrupted login exactly as `POST /auth/mfa/setup/confirm` does. The
  setup page now offers the choice. A setup token still adds an account's
  **first** factor and never a second: an account that already has one is
  refused, as it is on the TOTP path.

  Contract 1.45 adds `webauthn_setup_register_start` and
  `webauthn_setup_register_finish` to §24 and §25; the §27 management surface is
  unchanged, since the `webauthn` tag is not part of it.

### Changed

- 2026-09-15 sweep — 165 modules, 0 FAILED, with REVIEW evidence

- The early-refusal pass and the MFA/CSR wave — model 2.16.0

- Bump the minor-patch group across 1 directory with 3 updates

- Bump github/codeql-action/upload-sarif

- Bump the minor-patch group in /frontend with 8 updates

- Rustls 0.23.45 for RUSTSEC-2026-0285

- Contract 1.46 — both forms a spent-request_uri refusal takes

- First-login MFA enrolment residuals, and end-entity certificates from a CSR (#447)

- First-login MFA enrolment residuals and end-entity CSR issuance

- Record the beta14 website pass as EXECUTED

- Sweep every stamped page and move DOCS_VERIFIED_RELEASE to beta14 (waves 3-4)

- Bring the Docs pages up to 1.0.0-beta14 (wave 2)

- Re-derive the Security section at 1.0.0-beta14 (waves 0–1)

- Close T-39 and T-143 — every SDK polls the revocation feed; model 2.14.0

- **A `request_uri` that is already dead is refused before anyone is asked to
  sign in for it.** `/oauth2/authorize` could not read a pushed request while
  answering an anonymous browser — the handle is single-use and is spent later,
  in the handler, once there is a principal to spend it for — so a browser
  presenting a `request_uri` that had already been used, had expired, or had
  been issued to a different client was sent to `/login`, the person typed a
  password, and the request was refused on the way back. The endpoint now reads
  the handle first. It is a **read**: a handle that is merely unfinished still
  reaches the sign-in page, so the same `request_uri` may still be presented
  twice before the first authorization completes, and the single-use decision
  stays exactly where it was.

- **A `request_uri` refusal reaches the relying party when the request named a
  `redirect_uri` that client registered**, as `error=invalid_request_uri` with
  the request's own `state` (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6) — the code a
  relying party can act on by pushing again and restarting. A request that named
  no registered `redirect_uri` is answered exactly as before: the authorization
  endpoint's own error page for a browser, the same JSON object for anything
  else. A handle issued to a **different** client keeps `invalid_request`, which
  is a different failure and stays distinguishable. Measured against the OpenID
  Foundation suite, this closes
  `fapi2-security-profile-final-par-attempt-reuse-request_uri`,
  `-par-attempt-to-use-expired-request_uri` and
  `-par-attempt-to-use-request_uri-for-different-client` — all three REVIEW
  before, all three PASSED after. Contract 1.46 records it in §26.2 rule 3;
  no SDK changes, because §26.2 rule 2's authorization URL carries no
  `redirect_uri` and so never reaches the redirected form.

- **A missing or unsupported `response_type` is refused before the login hop.**
  RFC 6749 §3.1.1 makes it REQUIRED and AXIAM supports exactly `code`; neither
  fact depends on who is signing in, so the endpoint decides it before building
  the login redirect, and only when no `request_uri` is present — with PAR the
  pushed value is authoritative (RFC 9126 §4). Delivered under the same rule as
  every other refusal: to a `redirect_uri` the client registered, with `state`,
  or in place. `oidcc-response-type-missing` and the four FAPI `state` /
  `nonce` modules moved from REVIEW to PASSED when run individually (T-270).

- Forced first-login MFA enrolment now returns the user to the application
  they were signing in to (M-4). A new user of an enforcing tenant who arrived
  through an OAuth2 client's `/oauth2/authorize` hop finished enrolment in the
  admin UI's dashboard instead of back at the relying party; the login hop's
  `return_to` is now carried through the setup page and resumed, re-validated
  at each hand-off.

- `sdks/CONTRACT.md` moves to **1.45** (C-3), additive throughout: the §27
  management surface's `certificates` namespace documents `sign_csr` and
  states plainly that its response is not `GeneratedCertificate` — a type
  whose key field is mandatory and would always be absent is a type that
  lies about every value it holds; §24 and §25 document the two WebAuthn
  setup-registration operations; and §5.2 rule 4 documents the self-service
  `mfa_enforced` refusal. The Breaking Changes Log records the whole revision
  as non-breaking: no existing operation, field, or error code changes
  meaning, and a client built against 1.44 keeps working unchanged against a
  1.45 server. `docs/pki/README.md` gains a "bring a CSR" walkthrough for
  operators, and the website's PKI and MFA pages reflect the same additions.

- The STRIDE threat model moves to **2.15.0** (C-3), reconciling the counts
  T-267 (M-2), T-268 (C-1) and T-269 (M-3) moved: 269 threats identified, 256
  mitigated and 13 open — the open count is unchanged, since all three land
  Mitigated on arrival. `claude_dev/threat-model-stride.md`'s by-STRIDE,
  by-severity and by-diagram tables are updated to match; the website's
  generated threat-model views are regenerated at publish time from the same
  model rather than carried here.

- The STRIDE threat model moves to **2.16.0**: T-270 (the dead `request_uri`
  refused before the login hop, and what the early read must not do) and T-271
  (the FAPI `state` / `nonce` bound) enter Mitigated, taking it to 271 threats,
  258 mitigated and 13 open; T-163, T-238, T-255 and T-256 gain the clause that
  says what moved; T-262 is corrected to record that the SCIM error type
  answered `500` for a day after R-4; T-127 records RUSTSEC-2026-0285.
  `claude_dev/threat-modeling-and-security.md` gains the 2.15.0 and 2.16.0
  handoff paragraphs and `claude_dev/website-security-beta15-update-plan.md`
  is the website's entry point.

### Fixed

- Pin the rig's ns/db and read the minted datastore credentials

- The harness must not hand a reviewer the wrong evidence

- Refuse a dead request_uri before the login hop, and report it to the client

- Refuse an unusable authorization request before the login hop

- A contended write answers 503 with Retry-After, not 500

- Do not put an exempt config key on the docs site

### Security

- An administrative MFA reset now removes a user's passkeys and security keys,
  not only their TOTP secret (M-1, T-34). The reset previously cleared
  `mfa_enabled` and the secret and left every registered WebAuthn credential in
  place, so the authenticator an administrator reset the account over came back
  as a live second factor at the next login — the forced TOTP setup turned the
  flag on again and the credential count had never been zero. Operators who
  reset an account because a key was lost or suspected compromised should know
  that, before this release, the key still worked.

- A user can no longer take their own account below their tenant's MFA floor
  (M-2, T-267). `POST /users/{own id}/reset-mfa` is refused with `403` and the
  error code `mfa_enforced` where the caller's tenant enforces MFA; an
  administrator resets it for them. `users:admin` is unaffected, and where the
  tenant does not enforce MFA the self-service reset still works — such a user
  was free to run at one factor anyway. Contract §5.2 rule 4 carries the rule
  for SDKs.

- **rustls 0.23.45 for RUSTSEC-2026-0285** (T-127). The advisory — TLS 1.3
  handshake messages accepted across encryption-level boundaries, CVSS 5.3,
  against 0.23.43 — was published on 2026-09-14 and the lock was moved the same
  day with `cargo update --precise`, taking `rustls-webpki`, `aws-lc-rs` and
  `aws-lc-sys` with it; no manifest changed. Verified by re-running the OIDF
  FAPI 2.0 mTLS plan against the rebuilt binary. The `1.0.0-beta14` release
  artefacts carry 0.23.43; this is the first release that does not.

- **A FAPI 2.0 client's `state` and `nonce` are bounded at push** (T-271).
  `POST /oauth2/par` refuses either beyond 256 characters with
  `invalid_request` when the client's profile is `fapi2` — six times what a
  32-byte value needs, and below the 384- and 1000-character probes the OpenID
  Foundation suite requires to be refused, pinned by a `const` block. A
  `standard` client is deliberately not bounded: a cap is a breaking change
  for a client that packs data into `state`, and there the exposure is an
  authenticated client reflecting text into its own registered `redirect_uri`
  under the 16 KiB form-body cap and a 60-second handle.

## [1.0.0-beta14] - 2026-09-13

### Added

- Datastore and broker credentials through the provider (R-5, T-132)

- An optional session-revocation feed (R-6, T-39/T-143) — contract 1.44

- An mTLS alias is used verbatim, and the vectors SDKs pin (R-8, T-266) — contract 1.43

- Bound what the audit log collects, not just how long it keeps it (R-7, T-110)

- A contended write answers 503 with Retry-After (R-4, T-262)

- Say so when the default tenant is not a UUID (R-3, T-244)

- The §5.5 claims request survives a refresh (R-2, T-241)

### Changed

- Fill the §10.4.1 and §21.10 rows for csharp, php and swift

- Record csharp, php and swift as not reached, and why

- Record the kotlin SDK PR in §13.1

- Record kotlin in §10.4.1 and §21.10

- Record the cplusplus SDK PR in §13.1

- Record cplusplus in §10.4.1 and §21.10

- Record the c SDK PR in §13.1

- Record c in §10.4.1 and §21.10

- Record the java SDK PR in §13.1

- Record java in §10.4.1 and §21.10

- Record the go SDK PR in §13.1

- Record go in §10.4.1 and §21.10

- Record the python SDK PR in §13.1

- Record python in §10.4.1 and §21.10

- Record rust and typescript in §10.4.1 and §21.10

- The plan for the 2026-09-12 residual pass (R-1…R-8)

- Close T-254 — the grace window is a fapi2 behaviour, and every replay is marked

- Record the beta12…beta13 wave — T-237…T-266, model 2.12.0

### Fixed

- Mint the two redaction fixtures instead of writing them down

- Vector C tests for a downgrade, not for `https` (R-8, T-266)

- Clause 4 forbids appending and stripping, not displacing (R-8, T-266)

- One declared personal-data inventory, and a gate on the schema (R-1, T-261)

- Confine the refresh-rotation grace to fapi2, and mark every replay (T-254)

### Security

- **Datastore and broker credentials come from the secret provider** (T-132)

  `AXIAM__DB__USERNAME`, `AXIAM__DB__PASSWORD` and `AXIAM__AMQP__URL` were read
  before any secret provider existed, so a deployment that kept every key in
  Vault still had its datastore password in the pod spec — which is the exact
  thing T-132 was closed on, one secret class short.

  They are now three more entries on the provider — `db_username`,
  `db_password`, `amqp_url` — fetched in the same round trip as the other
  eleven. **The Vault token, or the `file` provider's mount, is now the only
  credential a container spec has to carry.**

  The environment variables stay, permanently. `env` is a supported provider
  kind, not a legacy path. What changed is that a deployment configuring a
  *different* provider, and still supplying a value through the environment,
  now gets one `WARN` at boot naming the variable — the one case where an
  operator believes something untrue.

  `just vault-seed` carries the three forward and never invents them: a
  datastore password has to match what SurrealDB was configured with, and an
  invented one gives a Vault that looks configured and a server that cannot
  connect. A value already in Vault always wins over one in your shell, so
  re-running the seeder after a rotation cannot undo it. The Vault policy needs
  no change — it grants read on the path, and the new fields are in it.

  `DbConfig` and `AmqpConfig` no longer derive `Debug`. The broker URL carries
  its password inline by the AMQP URI's own design; it now renders as scheme,
  host and path with the userinfo removed, and a value that does not parse as a
  URL is not echoed at all.

- **A refreshing client keeps the claims it asked for** (T-241)

  A client that names claims with the OIDC Core §5.5 `claims` parameter used to
  receive them on its first access token and not on its second. The resolved
  list rode the authorization code; the refresh grant minted a token without
  it, so access to consented claims ended fifteen minutes after the consent was
  given and the only recovery was a whole new authorization — which the end
  user experiences as the consent not having worked.

  The list now rides the refresh token too (schema v61, additive, no backfill),
  and rotation copies it onto each successor exactly as it copies the session.
  A refreshed access token asserts the same `axiam_requested_claims` the
  code-exchanged one did.

  This carries a request, not a release decision. The filter that decides which
  claims may ever be named — `claims_request::RELEASABLE`, which no request can
  use to reach `phone_number`, `phone_number_verified` or `address` — still runs
  at the authorization endpoint and nowhere else, and every consent gate is
  re-asked at each UserInfo call as before. A refresh token issued before v61
  names no claims and mints exactly the token it minted before.

- **A personal-data column can no longer be added to `user` without being
  classified** (T-261)

  Nothing an operator or a client observes changes. Erasure erases exactly what
  it erased, and an Art. 15 export shows exactly what it showed.

  What changes is what happens to the *next* column. Three code paths decided
  what a `user` column means by writing its name out by hand — the Art. 17
  erasure statement, the administrator's tombstone, and the export's `profile`
  section — so a column added to the schema and to none of them survived
  erasure and never reached an export. That is how `phone_number` and `address`
  were nearly stranded, and the fix at the time was to name them in all three
  and write a warning for whoever came next.

  There is now one declaration instead of three lists
  (`axiam_core::personal_data::USER_COLUMNS`), both erasure statements render
  their shared clauses from it, and a test introspects the live `user` schema
  after migrations and fails on any column the declaration does not classify —
  naming the column, and saying what a classification has to answer. The
  comparison runs the other way too: a classification for a column that no
  longer exists reads as coverage and is not.

- **The refresh-rotation grace window is a FAPI 2.0 behaviour again** (T-254)

  A client on the `standard` profile that presents a refresh token it has
  already rotated is answered `400 invalid_grant`, "refresh token already
  consumed". Since 1.0.0-beta13 it was answered `200` for sixty seconds, and
  rotated again.

  FAPI 2.0 Security Profile §5.3.2.1-9 requires an authorization server that
  rotates refresh tokens to keep accepting the previous one for a short period
  — it is the only recovery a client has from a rotation response lost in
  transit — and 1.0.0-beta13 implemented it for every client. But the profile
  that requires the window also binds every token to a key the client must
  hold, so a replay inside it needs the client's private key as well; on
  `standard` the refresh token *is* the credential, and the same sixty seconds
  was a replay window the server could not tell from an honest retry. The
  window now applies only to a client registered `profile: fapi2`, decided by
  the registration and never by the request. `fapi2` clients see no change:
  the previous token still stays redeemable for sixty seconds after rotation.

  **What to do.** Nothing, unless a `standard` client of yours was relying on
  the window — in which case it was relying on behaviour that existed for three
  days. A client that needs the recovery should be registered `profile: fapi2`,
  which brings the sender-constraining that makes the window affordable.

- **A refresh token presented after rotation is now recorded** (T-254)

  Whether it is served under the FAPI grace or refused, presenting an
  already-rotated refresh token leaves two marks. An audit entry under a new
  action, `oauth2.refresh_token_replayed`, naming the client, its profile, the
  session and a `disposition` of `accepted_under_fapi_grace` or `refused` — and
  never the token or its digest. And a pair of counters on the session the
  token belongs to, readable through a new
  `GET /api/v1/users/{user_id}/sessions`, which the admin UI surfaces as a
  **Sessions** action on each row of *Users*: an amber "FAPI grace retry" badge
  or a red "Replay refused" one.

  A `refused` is worth alerting on — nothing a conformant client does produces
  one. A `fapi_grace_retry` on a `fapi2` client is the mechanism working, and a
  rate to watch rather than a page.

  Schema **v60** adds four optional columns and backfills nothing, so a rolled
  back binary reads a migrated database exactly as it read the unmigrated one.
  A credential revoked at logout is not recorded as a replay: only rotation
  stamps the column the two are told apart by.

## [1.0.0-beta13] - 2026-09-12

### Changed

- **Contract 1.43 — an mTLS alias is used verbatim, and the vectors SDKs pin
  are published** (T-266)

  Nothing an operator observes changes; the server publishes exactly what it
  published. This is the SDK half of a rule that has been normative since
  contract 1.40 and was implemented by nobody.

  §21.3 rule 2 gains the clause that was implicit in it: an SDK preserves an
  alias's query component rather than appending to it. AXIAM's aliases carry
  the tenant that way, so an SDK that appends its own `?tenant_id=` produces a
  duplicate the server cannot resolve to one tenant, and one that rebuilds the
  URL from host and path drops whatever else the deployment put there.
  Displacing the tenant with the one the caller authenticated against is
  correct and is explicitly not what the clause forbids — the multi-tenant
  document names no tenant and the client supplies its own. Either way the
  failure shows up only on a two-listener deployment, which is the deployment
  the rule exists for.

  §21.3.1 publishes the three documents every SDK pins — the member present,
  absent, and malformed — inside `CONTRACT.md` itself rather than as a fourth
  vendored artifact, so eleven repositories assert the same bytes. A malformed
  alias must be **refused**, not fallen back from: quietly presenting a
  certificate to the front-channel host authenticates nothing while appearing
  to work. "Malformed" means not an absolute URL, or a scheme weaker than the
  top-level endpoint the alias replaces — comparing like with like, since an
  alias substitutes for exactly one endpoint. Neither "must be `https`" nor
  "weaker than the issuer" survives contact with the topologies AXIAM ships.

  §21.10 records, per SDK, whether it decodes the member and whether it prefers
  the alias — in the style §21.9 already uses for DPoP, where an unrecorded row
  is not a supported answer.

- **A contended write answers `503` with `Retry-After: 1`, not `500`** (T-262)

  A write that loses an optimistic-concurrency race in the datastore, and
  stays lost after every retry the server spends on it, used to reach the
  client as `500 internal_error`. That is the wrong instruction: the request
  was fine, it lost a race, and the correct advice is to come back in a
  moment. An IdP driving SCIM provisioning — Okta, Entra — reads a `500` as a
  failed sync and re-sends the whole record.

  It is now `503` with the slug `write_contention` and a `Retry-After: 1`
  header; over gRPC it is `UNAVAILABLE` rather than `INTERNAL`. `409` was the
  other candidate and is deliberately not used: in SCIM (RFC 7644 §3.12) it
  means your request conflicts with the resource's state, which a caller
  responds to by changing the request — and that cannot help here.

  Uniqueness violations and state preconditions keep their `409` and carry no
  `Retry-After`. The new answer carries no message of its own beyond a fixed
  sentence, so the datastore's own words stay in the server log where they
  were.

  AXIAM's SDKs need no change: their retry policy (CONTRACT §16) already
  treats `5xx` as transient on a side-effect-free operation and already
  honours `Retry-After` as a floor. Note that a contended `PATCH` is a
  mutation, so no SDK retries it automatically — that decision stays with the
  caller.

### Added

- **An optional session-revocation feed** (T-39, T-143)

  `AXIAM__AUTH__REVOCATION_FEED_ENABLED`, default `false`. With it off nothing
  changes at all: the route is not mounted, no row is written, and the
  deployment is byte-identical to one built before the feed existed.

  With it on, `GET /oauth2/revocations` publishes the base64url SHA-256 of each
  session id revoked within the last access-token lifetime. An SDK route guard
  that polls it (contract §10.4, opt-in on that side too) rejects a revoked
  session within one poll interval instead of within one token lifetime — for
  one cacheable fetch per interval, rather than the per-request round trip
  gRPC introspection costs.

  The document carries hashes and nothing else: never a session id, a subject,
  a tenant or a timestamp. It is bounded by your revocation rate over fifteen
  minutes rather than by history, and filtered on read as well as swept, so a
  sweep that falls behind makes the table large and never the document wrong.

  It is not a control. A guard that cannot fetch the feed behaves exactly as it
  does without it; the feed can only turn an accept into a reject, and local
  verification still decides.

- **`AXIAM__AUDIT__MINIMISE` — bound what the audit log collects, not just
  how long it keeps it** (T-110)

  The audit log is append-only, so what reaches it cannot be erased, only aged
  out. `AXIAM__AUDIT_RETENTION_DAYS` has bounded the retention side since
  1.0.0-beta12. Collection was not configurable at all, so a deployment whose
  lawful basis does not support holding a full client address for two years had
  nothing to turn off.

  With this on, a client address is truncated to its `/24` (IPv4) or `/48`
  (IPv6) prefix and a user-agent string is reduced to a coarse family, both
  immediately before the append. An address that does not parse is dropped
  rather than written through: a value that cannot be parsed cannot be shown to
  have been minimised.

  It does not touch the structured metadata AXIAM's own producers write — the
  client and disposition on a refresh-token replay, the names of released
  claims, a federated subject. Those are accountability evidence other controls
  depend on, and none of it is request metadata.

  Deployment-wide and deliberately not per tenant: audit is a control the
  deployment relies on including against a tenant administrator, and a
  per-tenant switch would let a tenant weaken the evidence used to investigate
  it. Default `false`, and **both states are logged at startup** — an operator
  opening an incident needs to know, before reading rows, whether the addresses
  in them are whole.

  Erasure and the Art. 15 export are unaffected: the erasure scrub clears the
  address outright either way, and the export's audit section never carried it.

- **A default tenant that is not a UUID is reported at startup** (T-244)

  `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` is ignored when it does not parse,
  which stays: the value is read while building a public, unauthenticated
  document, and a fat-fingered UUID must not `500` for every relying party. But
  the deployment was never told, so an operator who set it concluded the
  setting does not work.

  There is now one `WARN` at boot naming the variable and saying what will
  happen — the document served is the one served with the variable unset, and
  no endpoint URL will carry a tenant. It describes the value's shape (its
  length, and whether its characters could belong to a UUID) and never the
  value. Nothing is logged on the request path, and the discovery document is
  unchanged in every configuration.

- Hold the full profile claim set, and honour the claims parameter (§5.1, §5.5)

- Answer a person at the authorization endpoint in prose, not JSON

- Bind the authorization code to a DPoP key (RFC 9449 §10)

- Complete the sign-in hops in a real browser, not HtmlUnit

- Serve the SPA on the issuer origin so an authorization can finish

- Basic OP harness, and the first run the harness has ever had (W9)

- Accept client_secret_basic client authentication (W8, G9)

- W7 — the address and phone sensitive scopes (X7 G8)

- W6 — POST /oauth2/userinfo, and the G11 decision

- W5 — the cosmetic parameters, and a real i18n layer

- W4 — the honour lane for the security-bearing parameters

- W3 — the browser login hop and the OP session cookie

- W2 — session authentication evidence, emitted for nobody

- W1 — OIDC authn-request parameter gates, honouring nothing

- Publish RFC 8705 §5 mtls_endpoint_aliases in discovery

- Mirror the beta11 security model and prose

- **The OpenID Connect `address` and `phone` scopes, behind four gates** (X7 G8)

  OIDC Core §5.4 defines two scopes that release a postal address and a
  telephone number. AXIAM holds neither for any purpose of its own — nothing
  authenticates against them, nothing is sent to them, nothing is keyed by
  them — so they are stored to be released to a relying party the end user has
  agreed to, and to nothing else.

  Four things must all be true before either claim reaches a relying party, and
  a different party closes each: the **organization** enabled
  `sensitive_scopes_enabled` (off by default, and the only *disable*-only
  control in the settings model — a tenant may refuse a release its organization
  allows and may never authorise one it forbade); the **operator** registered
  the scope on the client; the **end user** consented, per client and per exact
  scope set; and the client is not on the `fapi2` profile, which collects no
  consent record.

  All four are re-asked **at every UserInfo call**, not once at authorization.
  An access token lives fifteen minutes and the refresh behind it thirty days,
  so a decision taken at issuance would outlive the facts it rested on — which
  is what makes withdrawal effective on the relying party's *next* request with
  the token it already holds, rather than on its next token.

  Claims are returned from **UserInfo only**, never in the ID token: an ID token
  is a long-lived artefact relying parties log and cache. A release is audited
  by claim **name** and never by value, because the audit log is append-only and
  is itself exported to subjects under Art. 15.

  **New self-service surface** (`GET /api/v1/account/consents`,
  `POST`/`DELETE /api/v1/account/consents/oidc-scopes`) and a consent screen in
  all five shipped languages. Withdrawal is one call, no confirmation step, no
  grace period — Art. 7(3) asks for it to be as easy as giving.

  `phoneNumbers` and `addresses` were silently dropped by SCIM and now map onto
  the same columns on create, replace and patch. Provisioning them is not
  authorising them: what a relying party receives is decided four gates later.

  The discovery document advertises the two scopes and the three claims only for
  a tenant that has them, through a new optional `tenant_id` — a caller that
  omits it receives exactly the document it received before, and an unknown
  tenant is answered identically rather than `404`, so discovery is not a
  tenant-enumeration oracle.

  **Nothing registered before this release changes behaviour**, and structurally
  rather than carefully: the two scopes were unregistrable, so no existing
  client carries them and no authorization request could name them.

- Publish RFC 8705 §5 `mtls_endpoint_aliases` in the discovery document

  AXIAM implemented both halves of RFC 8705 — §2 mutual-TLS client
  authentication and §3 certificate-bound access tokens — but published no §5
  metadata, so a deployment that terminates mTLS on a separate host had no way
  to tell clients where that host was. Client configuration had to be passed out
  of band, which is the problem discovery exists to solve.

  Setting `AXIAM__AUTH__OAUTH2_MTLS_BASE_URL` now adds an `mtls_endpoint_aliases`
  object naming the six endpoints where reaching the server over mTLS is
  meaningful: `token`, `userinfo`, `revocation`, `introspection`,
  `device_authorization` and `pushed_authorization_request`. Each is the
  top-level endpoint of the same name re-based on the mTLS host — both are
  derived from one path, so they cannot drift apart.

  `authorization_endpoint`, `end_session_endpoint` and `jwks_uri` are
  deliberately not aliased: the first two are front-channel, where the server
  authenticates the user rather than the client and a browser prompted for a
  client certificate raises a chooser dialog most users cannot answer, and the
  third is public key material that gains nothing from a handshake. The `issuer`
  does not move either — it is an identifier, and OIDC Core §2 requires it to
  match every token's `iss` exactly.

  **Absent by default, and absence is correct.** A present member instructs a
  conforming client to switch hosts, so a single-listener deployment must emit
  none — including one running `client_auth = optional`, where the conventional
  endpoints already serve certificate and non-certificate clients alike. The
  field is omitted rather than serialised as `null`.

  A configured-but-unparseable value fails the discovery request with `500`
  rather than quietly dropping the aliases. Dropping them would route mTLS
  clients to the conventional endpoints — the one outcome the setting exists to
  prevent — and would be indistinguishable, from the client's side, from a
  deployment that has no mTLS host at all.

  SDK contract 1.40 adds §21.3 rule 2, normative for the §21 client role only:
  an SDK making a call over mTLS must prefer an alias over the top-level entry.
  The change is additive and server-side — every existing SDK keeps working
  unchanged against every existing deployment, because no deployment publishes
  the member until an operator configures it.

### Changed

- Stop an_unreachable_vault_is_an_error racing the ports it frees

- Fix four gates this branch broke, and drop two directories it added by accident

- Guard the PATCH no-op list, and test primary_email's two siblings

- Assert what the strict-revocation layer does, not just what it reads

- Cover the reactor health the detail view reports

- Cover the two PATCH paths the op matrix never reached

- Walk the mTLS trust chain, including the cases only data can create

- Assert the invariants the doc comments already claimed

- The 2026-09-11 re-run — zero FAILED across all four plans

- Lift coverage to 96.6%, and fix what writing the tests found

- Un-pend the two scenarios their first runs closed

- Report the SDK actually measured, and measure /oauth2/authorize

- Move four assertions onto the behaviour this branch chose

- Document AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID

- Scope the Trivy filesystem scan to what AXIAM ships

- Re-export the OpenAPI spec for the §5.1 profile claim set

- The run in which every plan reached zero failures

- Where both lanes stand, and the one feature the DPoP lane still needs

- Bump google.golang.org/grpc

- Brief for accepting RFC 8705 §2.2 self-signed client certificates

- The first run in which every module reached an assertion

- Widen the I1 rate-limit band to ±25% to stop CI flakes

- Register /consent in the nav-reach matrix

- Bump @vitest/coverage-v8 to 5.0.0 alongside vitest

- Bump vitest to 5.0.0 alongside @vitest/coverage-v8

- W7 — conformance rows 104–129, GDPR §3.1, and the plan amendment

- W7 — T8.1–T8.6, M8, M10, and the tenant switch at registration

- Bump @vitest/coverage-v8 in /frontend

- Bump vitest from 4.1.11 to 5.0.0 in /frontend

- Bump the minor-patch group with 3 updates

- Bump orhun/git-cliff-action from 4.8.0 to 4.9.0

- Bump @simplewebauthn/browser in /frontend

- Bump the minor-patch group in /frontend with 7 updates

- Record maintainer decisions on the two Basic OP escalations

- OpenID Connect Basic OP gap-closure plan coexisting with FAPI 2.0

- Carry the three remediation details the plan's revision names

- Lock every test that moves the XFF discard counter

- Re-mirror against the post-remediation sources

- Record the beta11 website pass as executed

- Re-read the stamped pages against beta11 and stamp them

- Date the beta post's addendum and extend phase 20

- Carry the beta08…beta11 changes into the Docs pages

### Fixed

- Refuse a Vault CA bundle that parses to no certificates

- Redact a secret whose key carries a prefix

- Retry contended writes instead of reporting them as migration failures

- The DN-mismatch example is prose, not a doctest

- Carry the §5.5 claims request in the batch-authz fixture

- The other three authorization refusals a browser can reach

- A fapi2 client may send `claims`, now that AXIAM honours it

- Make a DPoP proof single-use at the resource endpoints (RFC 9449 §11.1)

- Error_description is NQSCHAR, not prose (RFC 6749 §5.2)

- Compare a DPoP proof's htu in canonical form (RFC 9449 §4.3)

- Five harness gaps, and the evidence the suite was waiting for

- Eight defects the OIDF conformance suite found, one of them a hole

- A self_signed_tls_client_auth client could never open a connection

- Six harness gaps, none of them AXIAM

- Four conformance defects, each one gating a lane

- Private_key_jwt was implemented and never wired to anything

- A subject DN registered as documented could never authenticate

- The FAPI plans asked for the openid scope on a plain-OAuth variant

- Single-quote values written into suite.local.env

- One browser context per test, not per authorization

- Register the Basic OP clients on the honour lane

- Carry the session in `sid` so an OAuth2 access token works at UserInfo

- The driver was polling a long-dead plan

- Drive only a test that is still WAITING

- The driver matches the suite by host, not by base URL

- Deliver an authorization error by redirect when the redirect_uri is registered

- Publish the tenant in the endpoint URLs discovery advertises

- Correct the browser block's match, and discover the tenant instead of trusting a constant

- Advertise the two RFC 8414 members the first conformance run found missing

- The three causes behind W7's five red checks

- The OP session cookie is Secure unconditionally

- Never format a Set-Cookie header carrying a credential

- Box the authorize refusal so the Result's Err stays small

- Don't debug-format a LoginResult into a panic message

- Drop the STRICT_REVOCATION exemption now that it is documented

- **A new personal-data column on `user` was covered by neither erasure path nor
  the Art. 15 export**

  Both erasure statements — the Art. 17 pipeline's `anonymize_user` and the
  administrator's tombstone behind `DELETE /api/v1/users/{id}` — and the export
  job's `profile` section write **explicit column lists**. A column none of them
  names survives erasure and never appears in an export.

  This was latent rather than live: the columns it would have stranded
  (`phone_number`, `address`) are added by this same release, and adding them
  under the assumption that user-row fields are erased for free would have left
  an erased subject holding a telephone number and a postal address
  indefinitely, with the account hidden from the UI — which the tombstone's own
  documentation calls "retention with the UI hidden, not erasure". All three
  paths now name the columns, and the tests erase a subject who has both and
  read the row back rather than inspecting the SQL, so a fourth erasure path
  cannot pass by sharing a statement.

  Recorded in `docs/compliance/gdpr-compliance.md` §1 and §2 as a warning to
  whoever adds the next such column.

## [1.0.0-beta12] - 2026-09-06

### Added

- Four small hardenings the beta11 threat-model review found

- Apply the deployment-origin rule to every SSO start path

- Terminate TLS in the listener — reloadable leaf, TLS 1.3 only

- A `TRUSTED_HOPS` misconfiguration is now visible instead of silent

  Both rate-limit key extractors discard `X-Forwarded-For` entirely when
  `trusted_hops` is greater than or equal to the hops present, and key on the
  connection peer instead. That fallback is correct and unchanged — it is what
  stops a client rotating a single-hop header to mint a fresh bucket per request
  (SECHRD-03). What was wrong is that it happened without a word: with
  `trusted_hops` one too high, every client keys on the proxy's address, the
  whole deployment shares one bucket, and the symptom is "the rate limit is
  mysteriously strict" — which an operator fixes by raising the limit.

  The first discard now logs one `WARN` naming the hop count seen, the
  `trusted_hops` in force and the rule (`proxies − 1`), and every discard
  increments `axiam_rate_limit_xff_discarded_total{protocol="rest"|"grpc"}`. A
  non-zero counter is not automatically a fault; a counter that tracks total
  request volume is. The boot log also states the value and the rule together,
  next to the rate-limit posture line, so the number can be checked against a
  topology before any traffic arrives.

  A request with **no** header is not counted: a client with no proxy in front
  of it is not a misconfiguration, and counting it would bury the signal.

  Narrows T-212 and T-233. `claude_dev/remediation-plan-2026-09-04.md` R-4.

- `just vault-status` reports the Vault's seal type

  AXIAM cannot configure auto-unseal — every Vault OSS seal type needs a cloud
  KMS or a second Vault elsewhere, and `pkcs11` is Enterprise-only — but it can
  make the absence of one **checkable**, the way `just vault-status` already
  makes the token's scope checkable. The report gains a **Seal** section from
  the unauthenticated `sys/seal-status`: the type, `OK` for any auto-unseal
  type, and for `shamir` a clearly worded "no auto-unseal; every restart needs
  `t` of `n` key shares, not production" quoting the quorum from the response.

  A Vault that is sealed *right now* gets its own line, because that is a state
  somebody is about to fix rather than a statement about the configured seal. A
  request that fails reports `unknown`, never `OK`. `--strict` now fails on an
  unconfirmed auto-unseal as well as on an over-scoped token; `just
  vault-status` still does not pass it, so the dev stack's root token on a
  Shamir Vault — both deliberate — does not turn every local run red.

  T-216 stays **open**: this is a check, not a seal.
  `claude_dev/remediation-plan-2026-09-04.md` R-7.

- `/health/jobs` is in the OpenAPI document

  It has carried a `#[utoipa::path]` annotation and a route since T-129 and was
  listed in `paths(…)` by nothing, so it existed in the server and in no
  generated document — the same class of omission contract 1.36 recorded for
  `/auth/me`, `/auth/password/change` and `/admin/bootstrap`. It is the endpoint
  an operator alerts on to learn that a GDPR-erasure or certificate-expiry sweep
  has stopped running.

  It is documented but deliberately **not** §27 client surface: unlike `/health`
  and `/ready`, which answer a fixed one-word contract, this returns a variable
  inventory of a deployment's background jobs, and none of the three is routed
  at the edge. The §27 operation count is unchanged, so **no SDK surface
  regenerates**; the eleven SDKs re-vendor `openapi.json` at the next release as
  they always do.

  `claude_dev/remediation-plan-2026-09-04.md` R-6.

### Changed

- Reconcile the documents after the remediation pass — 220 / 16

- Cover the pre-existing H2 loader and empty-verifier gaps

- A later reload failure must not mask the first

- Serialize the R-4 counter tests

- Prove the renewal on the wire, and reach both handshake bounds

- Remediation plan for the residuals the beta11 threat-model wave left open

- Plan the website's beta11 security and docs catch-up pass

- Record the beta08…beta11 wave — T-212…T-236, model 2.11.0

- The gRPC listener terminates TLS itself: hot-reloadable certificate, TLS 1.3 only

  Until now `start_grpc_server` read `AXIAM__GRPC_TLS_CERT_PATH` /
  `AXIAM__GRPC_TLS_KEY_PATH` once at boot and handed the PEM to tonic's
  `ServerTlsConfig`, which accepts neither a `rustls::ServerConfig` nor a
  certificate resolver. Two consequences followed from that one API limit: the
  leaf was fixed for the process's life, so an ACME renewal at day 60 reached
  the gRPC listener only through a restart and a 90-day certificate expired in
  place without one — while the REST listener beside it kept working, which made
  the failure present as a gRPC bug — and the protocol version stayed at the
  crate default, leaving TLS 1.2 negotiable where REST has been 1.3-only since
  F-04.

  The listener now accepts the TCP connection, completes the handshake with
  `tokio-rustls`, and hands tonic an already-encrypted stream. The rustls
  configuration is built by the composition root over the **same**
  `ReloadableCertResolver` the REST listener serves from whenever both are
  pointed at the same certificate and key — the documented topology — so one
  `SIGHUP`, or one hourly poll, now renews both. A deployment that really does
  point them at different files gets a second registered leaf, reloaded on the
  same triggers.

  **Nothing to change in a deployment.** The environment variables keep their
  flat names and their panic-on-unreadable behaviour, and the `INFO`/`WARN`
  lines an operator greps for are unchanged. The one step that becomes
  unnecessary is the certbot deploy hook's container restart, documented for
  gRPC-over-TLS deployments in the Raspberry Pi runbook §14.5: it is now
  redundant rather than wrong, and removing it saves ~15 seconds of downtime
  every 60 days. A gRPC client that could only speak TLS 1.2 would now be
  refused; none is known, and the mesh clients on this path negotiate 1.3.

  Terminating the handshake ourselves adds one denial-of-service surface — a
  client that opens TCP and never speaks — bounded by 512 concurrent handshakes
  taken with a non-blocking permit (so the accept loop is never starved) and a
  10-second handshake timeout.

  Closes T-234. Narrows T-233 (the TLS-version row is gone) and completes
  T-214's gRPC clause. `claude_dev/remediation-plan-2026-09-04.md` R-1.

- The deployment-origin rule now guards every federated sign-in start, not two of four

  `validate_redirect_uri` accepts any absolute `https://` URL, and until now that
  was the only server-side rule on the OIDC and plain-OAuth2 federation start
  paths. The argument for leaving it there was that the identity provider is
  handed the same `redirect_uri` and compares it against its registered set. It
  does — but that backstop is only as strict as each provider's registration
  hygiene, and several providers accept wildcard or prefix registrations. It is
  also a control AXIAM does not own and cannot inspect. The rule the server
  *does* own — `require_deployment_spa_origin`, added at beta08 for the SAML and
  Apple flows, where the provider never sees the SPA URI at all — is now applied
  uniformly to all four start operations and at the session mint. The provider's
  own check remains, as a second and independent layer.

  **This can break one class of deployment.** If your SPA is served from an
  origin other than your issuer's *and* you sign in through OIDC or plain-OAuth2
  providers, those flows now answer `400` until you set
  `AXIAM__AUTH__SSO_SPA_ORIGINS` to the SPA's origin. That is the same
  requirement the SAML and Apple flows have imposed since beta08, the `400` names
  the variable, and the shipped same-origin topology needs nothing. Origins are
  compared as scheme + host + port, so a different port on the same host is a
  different origin and must be listed.

  The `TODO(T19.14)` that proposed a per-`FederationConfig` registered-redirect
  allowlist is retired rather than carried over: the deployment-origin rule
  already answers where a code may go, and a second list to keep in sync is a
  second place to get wrong.

  `sdks/CONTRACT.md` §12.1 rule 12a widened accordingly (contract 1.39) —
  additive and restrictive server-side only, exactly as 12a itself was. **No SDK
  code changes**: an SDK that passes the deployment's own callback URL is
  unaffected.

  Narrows T-219. `claude_dev/remediation-plan-2026-09-04.md` R-3.

- `ReactorAdminService` is rate-limited as administrative traffic, not as authz

  `GrpcMethodFamily::classify` maps unrecognised gRPC paths into the
  `AuthzCheck` family, so that adding a service without updating the classifier
  fails safe (throttled) rather than open. Correct as a default; wrong as an
  outcome for a service that *is* known. `ReactorAdminService` — reactor CRUD
  and `ListReactorEvents` — was being sized like the hot path at 100/s per IP,
  and **raised** by the `gateway` and `mesh` profiles, which exist to move mesh
  authorization capacity.

  It now maps to `Admin`, whose ceiling is the absolute
  `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` (10/s) that no profile raises. That is
  stricter than its CPU profile demands — it carries no Argon2 cost — and
  generous for reactor administration; an administrative surface that scales
  with authorization throughput is the thing being fixed. Pin the knob, or open
  a case with a benchmark, if `ListReactorEvents` needs more. The catch-all arm
  is unchanged.

  **Operators administering reactors over gRPC at more than 10 requests per
  second per IP will now be throttled** and should pin
  `AXIAM__GRPC__GRPC_ADMIN_PER_SEC`. The REST admin surface is unaffected.

  Closes the follow-up T-233 names. `claude_dev/remediation-plan-2026-09-04.md` R-5.

### Fixed

- Recover the real tenant slug on re-seed, and refuse expired certs

## [1.0.0-beta11] - 2026-09-04

### Changed

- Publish gRPC through the edge, and pin the release

- The Vault seeder's tests now run in CI

  `scripts/test_vault_seed_payload.py` guarded "a password reset for every user
  in every tenant" and ran nowhere. It is now part of the Architecture
  Invariants job, alongside a new `scripts/test_vault_seed_shell.py` that drives
  the real script against a Vault answering `500`, `503`, `403` and `404`, and
  asserts on what was written rather than on an exit code.

### Fixed

- Survive npm-registry outages and drop stale advisory suppressions

- Regenerate each SDK's §27 surface when the spec is re-vendored

- Stop `just prod-up` from rotating every Vault secret

- `just prod-up` could rotate every Vault secret on a running stack

  The seeder's one invariant — a secret already present is never regenerated —
  was enforced by a pure function that has always been correct, behind a shell
  line that was not: `curl --fail ... || echo '{}'` turned *every* failed read
  into "the Vault is empty". Vault with Raft storage returns from `sys/unseal`
  while the node is still a standby contending for leadership, and `prod-up`
  seeded immediately after unsealing — so on a restart-driven run the read could
  be refused, a full set of new keys minted, and the write land moments later
  over the live ones. It reported `→ Seeded` and exited 0. From then on every
  login answered `500` with

      Cryptography error: AES-GCM decrypt: aead::Error

  because `opaque_setup_key` no longer opened the OPAQUE records the datastore
  held. A revoked or write-only token produced the same outcome deterministically.

  `scripts/vault-seed.sh` now waits for an **active** node (not merely a
  listening or unsealed one), passes the read's HTTP status to the payload
  builder so that only `200` or `404` may be read as a statement about the
  contents, and pins the write with KV v2's `cas` to the version it read.
  Anything else stops the seeder with nothing written. `just prod-up` waits for
  `sys/health` to answer `200` after unsealing, before it seeds.

  A replaced key is usually recoverable: KV v2 keeps ten versions, and
  `docs/deployment/vault.md` §8.1 has the `vault kv patch` restore, which costs
  no password resets.

- `scripts/mass-tag.sh` now regenerates each SDK's CONTRACT §27 management
  surface after re-vendoring the spec into it, instead of copying the artifacts
  and leaving the code derived from them behind. A release that carries schema
  changes — as v1.0.0-beta09 did, with the WebAuthn user-verification policy —
  previously tagged every SDK with a surface its own `§27 management surface
  drift-check` rejects. Only the Swift, C and C++ SDKs surfaced it, because
  they are the only three whose drift-check runs on a tag push; the other eight
  gate that job to `pull_request` and published a stale surface.

## [1.0.0-beta10] - 2026-09-03

### Changed

- Grant the server's Vault token the CA-key writes it needs (#412)

- Bump qs

- `just vault-status` reports missing capabilities, not only excess ones

  It probed two paths and called anything beyond `read` over-scoped, so a token
  that could not write a CA signing key reported `ok`. It now probes the CA-key
  paths too, knows what each path is supposed to grant, and prints `MISSING`
  with the capabilities a token lacks.

- A refused Vault call names the policy rule it needs

  A `403` from CA key custody now prints the missing stanza as HCL, addressed to
  the mount and prefix that deployment configured. Other statuses are unchanged:
  a sealed Vault is not a policy problem and is not reported as one.

### Fixed

- CA generation refused with `403 Forbidden` on a Vault-backed deployment

  The Vault policy `just prod-up` wrote — and the one documented as the
  production ceremony — granted `read` on `secret/data/axiam` and nothing on
  `secret/data/axiam/ca-keys/*`, where CA key custody writes one secret per CA.
  Since custody inherits `AXIAM__AUTH__VAULT_ADDR` / `_TOKEN` when no
  `AXIAM__PKI__VAULT_*` pair is set, every such stack booted cleanly, served
  every request, and then refused its first organization CA.

  The policy now lives in `docker/vault/axiam-policy.hcl` — one file, applied by
  `scripts/vault-policy.sh`, quoted by the docs and asserted against by the
  status reporter's tests. `just vault-policy` applies it to a **running**
  deployment: Vault evaluates policies per request, so nothing needs restarting,
  re-initialising or re-seeding, and nothing already stored is lost.

## [1.0.0-beta09] - 2026-09-02

### Changed

- Pin the tenant a check is evaluated in

- Allow the ninth argument on start_registration_for_policy

- Regenerate the OpenAPI spec for the WebAuthn policy field

- Port the grpc 1.83.1 bump from #407 to unblock CI

- Gate that every COPY source survives .dockerignore

- Bump google.golang.org/grpc

### Fixed

- The effective-access preview evaluated in the wrong tenant

- Refresh against the tenant the caller lives in

- A scope grant inherits down the resource hierarchy

- The remaining test callsites the last pass missed

- The three gates the first push missed

- Make user verification a policy instead of a hard-coded constant

- An unscoped role assignment grants tenant-wide, not nothing

- Let Vault write its Raft volume in the prod Compose stack

- Bump x/net and x/text past the CVEs this PR surfaced

- Keep nginx.conf.template in the frontend build context

## [1.0.0-beta08] - 2026-09-01

### Added

- Raft-backed Vault, a scoped server token, and loopback binds

- Template the frontend's backend upstream so it can speak TLS

- Hot-reload the TLS leaf certificate, so ACME renewal needs no restart

- "Sign in with X" buttons, the SSO callback route, and the admin fields

- The public login-provider surface — buttons, OAuth2, handoff codes

- The OAuth2 variant, PKCE, Apple secrets and templated issuers

- Provider kinds, the OAuth2 variant, inheritance and claim mapping

### Changed

- Keep argon2 0.6 out of the wasm getrandom trap

- Migrate password hashing to the argon2 0.6 API

- Cover the reload mechanism, not just the pieces either side of it

- Say what the reload poll actually compares

- Six threats for the publicly exposed backend

- The path-split topology, TLS renewal, Raft, and the TRUSTED_HOPS off-by-one

- Rewrite the Pi runbook for the new topology, a real Vault and the buttons

- The public backend, its own TLS, and the hop that broke the limiter

- Bump the minor-patch group across 1 directory with 5 updates

- Cite the archived Phase 25 plan by path instead of linking it

- Drop response-derived values from assertion messages entirely

- Bump argon2 from 0.5.3 to 0.6.0

- Bump docker/setup-buildx-action from 4.2.0 to 4.3.0

- Bump github/codeql-action/upload-sarif

- Bump the minor-patch group in /frontend with 10 updates

- Bump actions/checkout from 4 to 7

- Bump hadolint/hadolint-action from 3.4.0 to 3.5.0

- Stop assertion messages printing cookies and response bodies

- Cover the OAuth2 failure paths, the handoff repo and the icon field

- Name the four login-provider operations in the §12.2 map

- Threat model, contract 1.37, roadmap and the icon design

- Design the "Sign in with X" login providers

- Record the beta07 website pass against its plans

- Re-verify the docs section and stamp it at 1.0.0-beta07

- Link the normative docs the site never pointed at

- A passkey is a factor, and lockout reads the tenant's policy

- Bring the PKI pages up to the tenant-CA and trust-anchor model

- Cover the management API, and correct the REST conventions

- Document organization-level principals

- Announce the beta phase, and stop calling beta future

- Regenerate the API index and contract anchors at beta07

### Fixed

- Record why the trust-store package is not version-pinned (DL3018)

- Stop trusting a forwarded client certificate by default

- TRUSTED_HOPS is proxies minus one, not proxies

- Confine handoff redirects to this deployment, and follow inheritance at the SAML ACS

## [1.0.0-beta07] - 2026-08-30

### Changed

- Archive phase directories from completed milestones

- Updated .gitignore

- Quick task — bench lockout policy neutralization

- Plan the cumulative beta06 docs catch-up pass

- Record the beta05…beta06 wave — T-200…T-211, model 2.10.0

### Fixed

- Name the k6 setup() exception in the dry-run verdict

- Neutralize the lockout POLICY, not just the deployment default

## [1.0.0-beta06] - 2026-08-30

### Added

- Assigning a role from a user or a group can name its scopes

### Changed

- Mint the child-tenant password into a static, like its two siblings

### Fixed

- The acting-tenant header is `X-Axiam-Tenant`, not `X-Tenant-ID`

- The admin UI was showing the wrong tenant's data, or none at all

## [1.0.0-beta05] - 2026-08-30

### Added

- A role assignment can name the tenants it reaches

- Tenant-scoped role assignments: an organization-level account can now be
  confined to particular tenants of its organization. `tenant_scope` on the
  three assignment endpoints names the tenants an assignment reaches;
  `reachable_tenant_ids` on `/auth/me` reports the result. Such an account is
  refused organization-level actions, sees only the tenants it reaches in the
  tenant roster, and is refused `X-Axiam-Tenant` for any other. Schema 51,
  additive with no backfill — every existing assignment stays unrestricted.

### Changed

- Creating an organization or a tenant needs an organization principal

- Revert "fix(authz): a tenant scope narrows reach across tenants, not within one"

- Undo a gratuitous reformat of the nav destination table

- The nav matrix has to know that one gate is not a permission

- Six suites need an organization principal, and a real trust anchor

- Track the matrix runbook, in claude_dev where it belongs

- The organization lifecycle tests need an organization principal

- Let the typecheck see the suite that reads the repo

- Record wave 4 — the four open items, and what closing them found

- Measure the in-page gates that only exist after a selection

- Read the mail publishers instead of quoting them

- Record wave 3 — the unverified half, and what closing it turned up

- Reuse the captured session instead of signing in mid-test

- Close three gaps where the matrix was measuring nothing

- Measure the mTLS handshake half of §4

- Assert no mail template leaves a placeholder standing

- Sharpen the mTLS and matrix assertions; wave 2 is clean

- Stop asserting one locale's number formatting; add the mTLS check

- Record wave-1 findings and the fixes applied

- Tenancy, group inheritance, service-account and PKI matrix + mail checks

- RBAC/PKI permission matrix harness against the prod stack

- Record the Sigstore half of H-1 as landed (T-148)

### Fixed

- User creation was the next ceiling, for the same reason

- The test stack was one login away from red

- B5's login failure was unreportable, not just failing

- A restricted organization principal can read its own reach

- A tenant scope narrows reach across tenants, not within one

- The preview proxy was swallowing /auth/mfa-setup

- Refresh the management registry's spec digest

- Clear the six failing gates on the E2E matrix branch

- A passkey is a factor, so enrolling one requires MFA

- Stop telling a tenant super-admin it can do everything

- Type the captured request bodies, and make tsc a gate over the specs

- Stop seeding organization-level actions into tenant roles

- Stop a second replica logging out the first, and recover when it happens

- Require a certificate to chain to a CA enabled as an mTLS trust anchor

- Gate the Audit Logs nav entry, and keep the selected tenant

- Make first-run and tenant provisioning idempotent and honest

- Stop demanding a CSRF cookie from a bearer-only caller

- Confine organization-level actions to organization-scoped principals

- Stop nginx swallowing /oauth2-clients into the OAuth2 proxy

- Organization scope, OPAQUE enrolment tenancy, settings inheritance, and RBAC for service accounts (#393)

- Enrolling a passkey or a security key now makes multi-factor authentication
  **required** at sign-in, the way confirming an authenticator app always did.
  The credential was listed on the profile page and accepted at
  `/auth/webauthn/authenticate`, but the login gate reads `mfa_enabled`, which
  only `confirm_mfa` ever set — so an account whose sole factor was a passkey
  signed in with a password and nothing else.

- The admin UI no longer renders organization-level controls to principals the
  server refuses them to. A tenant's `super-admin` holds the whole permission
  registry, so no permission check could have hidden "New Organization", the
  tenant lifecycle buttons or the CA controls; the gate is now the same
  standing the server checks.

- `GET /organizations/{org}/tenants` returns only the tenants the caller may act
  on. Every principal holding `tenants:list` previously saw every tenant of the
  organization, including a tenant administrator whose reach is one tenant.

## [1.0.0-beta04] - 2026-08-28

### Changed

- Record what H-1 actually landed per repo, and the pinning gotcha

### Fixed

- Re-vendor the spec into every SDK repo as part of the release

- Keep secret names out of the response-derived data flow

## [1.0.0-beta03] - 2026-08-28

### Added

- Close T-118, make the Vault posture checkable, attest release artifacts

### Changed

- Answer the pre-beta03 question — no fix required, plan the hardening

- Plan the docs-section beta03 catch-up, wave by wave

- Record the beta01…beta03 wave — T-187…T-199, model 2.8.0

### Fixed

- Build each removal cookie from the setter it mirrors

- A removal cookie must mirror the cookie it clears

- Let an organization-level principal sign in again

- Re-stamp the spec digest the release bump invalidated (#387)

## [1.0.0-beta02] - 2026-08-27

### Added

- Search and paging on every list, and say what a grant reaches

- Organization-level principals

### Changed

- Say what "no body" has to be asserted on

- Contract 1.31 — the PR #383 surface, stated for the SDKs

- Pin filter parsing and the degenerate userName page

- Cover CA import validation and the SCIM token principal

- Cover the Groups collection and the PUT deprovisioning path

- Pin the CA custody decision the beta got wrong

- Cover the mTLS trust-anchor hot reload

- Record §27 as implemented in all eleven SDKs (#385)

- Update three assertions to the behaviour this PR ships

- Give every OpenAPI export a content digest, so two can be told apart (#384)

- Update three Playwright specs to the behaviour this PR ships

- Regenerate the OpenAPI spec and management registry

- Import SubjectScope where the suites construct it

- Thread TenantKind and SubjectScope through the suites

- Organization scope, Vault inheritance, mTLS hot reload

### Fixed

- A projected list element is not an anonymous type

- Stop migrating a CA into database custody from destroying its key

- Drop two unused SubjectScope imports

- Assign b6's tenant admin through the role, not the user

- Sign the fixture admin in by username, drop the new password literal

- Wire the tenant resolver and reseat the examples on organization scope

- Build clean under -D warnings, and cover the new frontend modules

- Satisfy oxlint on the paginated pages

- A resend button that says what happened

- Make cross-tenant reach a claim, not a coincidence

- Resend verification, unique seeded scopes, quiet shutdown

- Inherit the configured Vault for CA signing key custody

## [1.0.0-beta01] - 2026-08-26

### Added

- Classify PUT bodies as sparse update or full replacement

- Derive the §27 management vocabulary from openapi.json

- An organization CA can anchor mTLS, and its key can move to Vault

### Changed

- Add CONTRACT §27 — the management API

- Request 365, not 800 — a bigger number never reaches the issuer check

- Three suites were asserting the behaviour this PR set out to fix

- Generate fixture passwords instead of hard-coding them

- Document AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH

### Fixed

- Clippy errors, and use the lockout helper the tests were missing

- Erase a deleted user's personal data, and free their identifiers

- Guarantee no template placeholder ever renders literally

- Carry the CA's expiry into the certificate form's CA option

- Every template greeted the reader with "{{username}}"

- Stop the random logouts, the stale views, and the nameless scope chip

- Make Delete remove a user, seed a default scope, and sync the sidebar

- Send the activation mail, and make notification rules actually fire

- Lock accounts on the organization's threshold, not the deployment default

- RSA-4096 keygen, and refuse a certificate that outlives its issuer

## [1.0.0-alpha44] - 2026-08-25

### Added

- Hand over the certificate, and manage a tenant's signing CAs

- Tenant signing CAs, signed by the org CA and kept in Vault

- Sdk-dry-run — rehearse all eleven SDK benches in minutes

### Changed

- Cover the copy, focus-trap and revoke paths; sync openapi.json

- Bump scrypt from 0.11.0 to 0.12.0

- Bump the minor-patch group with 3 updates

- Bump github/codeql-action/upload-sarif

- Bump the minor-patch group in /frontend with 7 updates

- Bump softprops/action-gh-release from 2 to 3

- Bump actions/download-artifact from 4 to 8

- Bump actions/upload-artifact from 4 to 7

- Bump actions/setup-node from 6 to 7

### Fixed

- OPAQUE never ran in the browser; build the wasm from source

- A tty stdin let the Kotlin bench hang the whole SDK sweep

- Empty BENCH_ORG_ID made every token_refresh call a 400

- Box the DPoP error so the token path clears result_large_err

- Exempt the three form-seeding effects from set-state-in-effect

- Drop the removed length argument from scrypt::Params::new

## [1.0.0-alpha43] - 2026-08-24

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha42.

## [1.0.0-alpha42] - 2026-08-24

### Changed

- Update .gitignore

### Fixed

- Fold the pending [Unreleased] block into the release being cut

- Drain a rate-limited call's body so h2 stops killing the connection

- Retry the failed-login accrual when it loses a write conflict

## [1.0.0-alpha41] - 2026-08-24

### Added

- Let Vault generate the CA and its signing intermediate (#368)
- Put CA signing keys in Vault, and let an organization bring its own
- Working tenant switcher, opaque menus, a way out of the no-CA dead end
- Make the erasure window a setting and the tenant overrides visible

### Changed

- Exercise the Vault CA key store against a real HTTP server
- Document the six CA key custody variables

### Fixed

- Do not refuse to boot when no CA key custodian is configured
- Make enabling OPAQUE actually enable it
- Make the tenant cascade work, and let an operator prove delivery
- Page list endpoints to the end instead of taking the first 50

## [1.0.0-alpha40] - 2026-08-23

### Added

- Resource-scoped role assignment in the admin UI
- Expose role assignments with the resource they are scoped to
- Close the request-shape gaps an OpenAPI sweep found
- Make the OPAQUE policy settable from the admin UI

### Fixed

- Refuse a settings write that enables OPAQUE without server keys
- Give .glass-card the padding it never had
- Exempt the WebAuthn authentication ceremonies from CSRF

## [1.0.0-alpha39] - 2026-08-23

### Added

- Gate the configuration page against the keys the server reads

- Rate-limit the WebAuthn ceremony routes

### Changed

- Give federation a setup procedure and service accounts an audience warning

- Stamp docs pages per page, not per section

- Walk the code flow, and open the token up

- Show OPAQUE through an SDK, and how each one binds it

- Resolve one tree node by node on the authorization engine page

- Give the operate pages the data they were describing

- State what the config reference covers, and add the keys it lacked

- Add the tutorial that bridges quickstart and core concepts

- Turn SCIM into a walkthrough, and fix what it said about the token

- Show the AMQP topology and one signed message

- Deepen the gRPC page to the surface the server actually serves

- Back the compliance claims with links, and generate contract anchors

- Follow up on #362 — model carries T-182's clause, site documents the throttle

- Index the GDPR endpoints, and fix two summary-extraction bugs

- Say precisely what PUBLIC means on an OAuth2 route

- Generate the REST endpoint index from the OpenAPI document

- Add the missing pushed-authorization page

- Record the rate-limit gate T-182 did not re-establish

- Lead every code sample with Rust

- Bring the passkey, MFA and lifecycle pages up to contract 1.28

- Give the Client SDKs page the matrix and the code it lacked

- Correct and complete the webhook page

- Show the reactor registry instead of describing it

- Put coverage, the open risk register and the evidence on the page

- Make the threat model citable — IDs, deep links and filters

- Emit STRIDE, severity and open-risk data from the threat model

- Plan the docs-section deepening, page by page

- Record the contract 1.28 SDK surface and the passkey cookie fix

### Fixed

- Repair §14.1's link to the device_login heading

- Classify the GDPR paths for the route ↔ OpenAPI parity check

- Register the GDPR endpoints in the OpenAPI document

- Bring the harness and quick runbook up to alpha38

- Benchmark harness and quick runbook brought up to alpha38. The two `opaque_*`
  cells could not pass — missing from `AXIAM_ONLY_SCENARIOS`, so they ran
  against Keycloak and Zitadel and failed in `setup()`, and the bench tenant
  left `opaque_mode` disabled so they 404'd against AXIAM too. `bench-quick`'s
  reactor probe had gone stale into a false negative. `rl_prod_check.py` had
  rows for eleven of sixteen REST rate-limit families, with five absent rather
  than reported unchecked.

### Security

- Rate-limit the six `/api/v1/auth/webauthn/*` ceremony routes. They carried no
  limiter at all — no governor, no shared counter, and no `webauthn_per_min`
  knob existed — while the MFA routes directly above them and the OPAQUE routes
  directly below each carried one. Two of the six are the unauthenticated
  usernameless sign-in path. New `AXIAM__RATE_LIMIT__WEBAUTHN_PER_MIN`,
  defaulting to 10 and applying to each of the six routes independently —
  deliberately the same per-IP sign-in allowance `login_per_min` already
  grants passwords.

## [1.0.0-alpha38] - 2026-08-22

### Changed

- §8b names an enforcement point for Swift, C and C++
- §24.4 rule 1 does not license dumping a response body
- Split §24.6 into a JSON bridge and a linked-API helper
- Add §24 WebAuthn, §25 account lifecycle, §26 PAR; narrow §22.11
- Carry two review details into the Security section
- Record the alpha37 closures, and the passkey sign-in path

### Fixed

- Set session cookies when a passkey ceremony completes

## [1.0.0-alpha37] - 2026-08-21

### Added

- Close T-132, T-131, T-129 and T-153
- Enforce a default audit retention policy (T-119)

### Changed

- Re-export openapi.json for the T-153 metadata_stale deny reason
- Re-export openapi.json after the RefreshRequest org_id change
- Cover the two 0% model files, the settings diff, and the reactor bridge
- Bring the Security section up to alpha34
- Bring the STRIDE model up to alpha34

### Fixed

- Make usernameless passkey sign-in actually work
- Treat npmjs.com as bot-hostile in the website link check
- Repair four broken SDK doc links and check them on a schedule
- Apply the SEC-053 ingress policies, and close three stale threats
- Repair token refresh, passkey origin, and the login-page bounce
- Make prod teardown work and refuse to mint creds for live volumes

## [1.0.0-alpha35] - 2026-08-21

### Added

- `AXIAM__AUTH__VAULT_CA_CERT_PATH` — trust anchor for a Vault fronted by a
  private CA. rustls compiles its roots in, so an internal PKI (cert-manager,
  `just tls-certs`) was previously unverifiable and the server panicked at
  startup with a bare transport error.

### Changed

- Justfile prod-up to use official images instead of local builds.

- Threat model brought up to `1.0.0-alpha38`: the contract 1.28 SDK surface —
  WebAuthn (§24), account lifecycle (§25), PAR (§26) and the Swift/C/C++
  reactor protocol core (§22.11) — is recorded as four new mitigated threats on
  the SDK diagram (T-183…T-186, 186 threats total, 170 mitigated / 16 open),
  T-182 notes the passkey session-cookie fix, and the website Security section
  (`src/security.ts` plus the generated model files) is updated in step.

- Website Security section brought up to `1.0.0-alpha34` from
  `claude_dev/threat-modeling-and-security.md`: OPAQUE (RFC 9807) as an
  optional augmented PAKE, Vault as the production secret provider, TLS-only
  AMQP, purpose-bound SCIM provisioning tokens, sender-constrained OAuth2
  clients and tokens (mTLS, `private_key_jwt`, DPoP, RFC 9207), the WebAuthn
  MDS3 attestation policy, and the SurrealDB persistent-storage-engine
  requirement. Deny-override shipped (SEC-040, T-16/T-87), so it is no longer
  listed as an accepted trade-off.

### Fixed

- Make `just prod-up` able to bring the stack up

- `just prod-up` could not start any stack: `${AXIAM_IMAGE_TAG:latest}` is not
  valid Compose interpolation, the SurrealDB and RabbitMQ credentials the
  compose file requires were never generated, and `AXIAM__AUTH__VAULT_TOKEN`
  was demanded before the Vault that issues it existed.

- Vault's listener key was mode 0600, unreadable to uid 100 in the container,
  so the Vault service restart-looped on "error loading TLS cert".

- Vault's port is published on loopback, which `prod-up` needs to initialise,
  unseal and seed it from the host.

- A Vault init that failed mid-write left an empty `vault-init.json` that
  wedged every later run; initialisation is now driven by Vault's own
  `sys/init` status and validated before it replaces the state file.

## [1.0.0-alpha34] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha33.

## [1.0.0-alpha33] - 2026-08-21

### Added

- Seed every AXIAM secret into Vault, minting what is missing (#350)

### Changed

- Correct the SDK and HTTP samples against the real APIs
- Rebuild the documentation section for a production IAM
- The baseline resolved in step 3b is OPAQUE's, not SRP's
- Publish axiam-opaque via Trusted Publishing, not tokens

### Fixed

- Pin axiam-opaque's MSRV explicitly, and gate its vendored copy
- Cut axiam-opaque on the tag release-opaque.yml triggers on

## [1.0.0-alpha32] - 2026-08-20

### Added

- HashiCorp Vault in the stack, mandatory in production
- Pluggable secret provider for the OPAQUE keys, and a release pipeline
- Migrate the admin UI from SRP to OPAQUE
- C ABI and WebAssembly builds of the shared client core
- OPAQUE endpoints, enrolment rework and the shared client core
- Implement the OPAQUE protocol engine and persistence
- Replace the SRP domain model with OPAQUE (RFC 9807)
- `crates/axiam-opaque` (layer 0): the single definition of AXIAM's OPAQUE
  ciphersuite, key-stretching functions and client operations, bound by every
  SDK and the admin UI. OPAQUE is not a protocol it is reasonable to hand-write
  once per language, which is what SRP's eleven implementations required.
- Schema v42: `opaque_credential` and `opaque_server_setup` (per-tenant OPRF
  seed and AKE keypair, AES-256-GCM at rest); drops `srp_credential`.
- `opaque_login_start` and `opaque_register_start` benchmark scenarios. The
  second is new in kind: SRP enrolment cost the server nothing, whereas
  `register/start` is unauthenticated by necessity and needs its own budget.

### Changed

- Clear the last three CodeQL alerts, and prove the Go exception
- Mint test keys and passwords per run instead of hard-coding them
- Correct comments that still described the new columns as SRP
- Rewrite CONTRACT §23 from SRP-6a to OPAQUE (contract 1.26)
- Design document, conformance fixtures, benchmarks and runbook
- **BREAKING: replaced SRP-6a with OPAQUE (RFC 9807).** SRP is removed
  entirely — endpoints, domain model, storage, SDK surface and fixtures.
  Nothing migrates and nothing needs to: an SRP verifier cannot be converted
  into an OPAQUE record (both are sealed against a plaintext the server has
  never had), and AXIAM is unreleased.
  - `srp_mode`/`srp_group`/`srp_kdf` become
    `opaque_mode`/`opaque_suite`/`opaque_ksf`, keeping the org-baseline plus
    tenant-tighten-only shape and the `disabled` default.
  - `POST /auth/srp/challenge` and `/auth/srp/verify` become
    `POST /auth/opaque/login/start` and `/auth/opaque/login/finish`, joined by
    `POST /auth/opaque/register/start` — OPAQUE needs a server round trip for
    the OPRF, which a client-side SRP verifier did not.
  - `AXIAM__AUTH__SRP_SESSION_KEY` becomes `AXIAM__AUTH__OPAQUE_SESSION_KEY`
    **and** `AXIAM__AUTH__OPAQUE_SETUP_KEY`, split by what rotating them costs.

### Removed

- `server_proof` from the login response. RFC 9807's AKE authenticates the
  server during the handshake, so the client-side `M2` check that CONTRACT
  §23.3 rule 6 had to mandate in capitals no longer exists to be forgotten.
- Verifier invalidation on username change. OPAQUE binds to a random
  server-chosen credential identifier, so a rename is free.
- The account username from `GET /auth/reset/context`, which disclosed it only
  because SRP bound its key derivation to it.
- `pbkdf2_sha256` as a KSF option, and CONTRACT 1.25's errata about the four
  SDKs that could not compute Argon2id. One shared core makes it universal; the
  weaker rung is now scrypt, which is memory-hard.
- `num-bigint` and `num-traits` from `axiam-auth`, whose only consumer was
  SRP's modular exponentiation.

### Fixed

- Route every long-lived secret through the provider
- Place axiam-opaque-wasm in the crate-layering table
- A malformed OPAQUE message from a client returned `500`. Client-supplied
  input (`400`) is now separated from corrupt stored state (`500`) by
  `AuthError::OpaqueMalformed` and distinct hex decoders.

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Cover the untested pure-logic seams in axiam-core (#345)

## [1.0.0-alpha30] - 2026-08-20

### Fixed

- Bump axiam-sdk-wasm/Cargo.toml with the rest of the rust SDK

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP login, enrolment on password change and reset
- CONTRACT.md §23, cross-language SRP vectors, OpenAPI, docs
- SRP challenge/verify endpoints, enrolment and bootstrap support
- SRP-6a core, domain model and org/tenant policy

### Changed

- Generate the frontend tests' password and refusal fixtures
- Give the 4096-bit group check a timeout that fits its cost
- Generate the enrolment salts in the REST tests
- Generate the auth crate's test key, salt and x
- Mint the login test's credentials per run
- §23.3 rule 4 errata and the §23.8 table, at contract 1.25
- Record the two SRP handler modules in the frontend coverage matrix
- Add srp_challenge scenario and register it in the harness

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Enforce the advisory ignore-list invariant instead of asserting it
- Patch h2 0.4 and document why 0.3 must be ignored
- Split AppState into seven cohesive sub-states (F3)
- Name the CI job correctly in the layering docs
- Enforce missing_docs, starting with axiam-authz (F6)
- AccessTokenSpec — one description, one signer (F4)
- One definition of a UNIQUE violation, and a gate (F5)
- Gate the crate dependency graph on pointing inward (F1)
- SOLID / clean-code / clean-architecture review of AXIAM + 11 SDKs
- Bump the minor-patch group with 4 updates
- Bump actions/upload-artifact from 4.6.2 to 7.0.1
- Bump taiki-e/install-action from 2.85.10 to 2.85.13
- Bump github/codeql-action/upload-sarif
- Bump the minor-patch group in /frontend with 5 updates
- Re-trigger CI after the 2026-08-17 GitHub outage
- Bump postcss

### Fixed

- Keep the /oauth2/jwks description byte-stable across F3
- Route every page error through getApiErrorMessage (F8)
- Thread the hash gate into the client-gated auth test
- Use numeric UIDs in USER directives (DL3066)
- Separate expected-throttle cells from genuine failures
- Gate ValidateCredentials' Argon2id verify (B1)

## [1.0.0-alpha27] - 2026-08-17

### Added

- AMQP is TLS-only, server side and in every stack
- Long-lived provisioning tokens, and two SCIM setup traps closed
- Close the residual admin-interface gaps before beta
- Nested-resource authorization depth sweep (N1)
- Nested-resource authorization depth benchmark — `just bench-nested` (N1)

### Changed

- §8b rules 7 and 8, and a gate that checks them (contract 1.23)
- Cover SAML claim extraction and attribute mapping
- Cover the WebAuthn state-token machinery and the SAML bearer-confirmation checks
- §22.14 declarative reactor handler binding (contract 1.22)
- Regenerate openapi.json for the SCIM token endpoints
- Cover the SCIM and MDS error taxonomies, and the token-exchange refusal codes
- **`AppState` split into seven cohesive sub-states (F3).** The REST
  composition root carried **75 public fields**, nearly all concrete
  `Surreal*Repository<C>` values, and every handler received all of them.
  A scan found that **46 of the 75 are referenced by exactly one handler module
  each**; those move into `PkiState`, `WebauthnState`, `GdprState`,
  `MailState`, `EventsState`, `OAuth2State` and `FederationState`, taking the
  root from 75 members to 36.

  **This is a field-grouping change, not a dispatch change.** Boxing the
  repositories behind `Arc<dyn …>` would have collapsed the `C` parameter too,
  and would have put vtable dispatch on the authorization hot path — what a
  service mesh calls on every request — for a cosmetic gain. Every type,
  monomorphisation and generated instruction is what it was; what changes is
  who can see what.

  `state.rs` becomes `state/mod.rs` + `state/bundles.rs`. Migration was
  mechanical and compiler-verified: `state.foo` → `state.<bundle>.foo` at 131
  call sites across 19 files. No handler logic, route, wire format or test
  expectation changed. Rationale in `claude_dev/appstate-substates.md`.

- **Documentation is enforced, one crate at a time (F6).**
  `[workspace.lints.rust] missing_docs = "warn"` now exists and `axiam-authz`
  opts into it, with its ten undocumented items written up. The lint is a
  warning locally and an error in CI (clippy runs `-D warnings`), so a local
  `cargo check` does not fail mid-thought while a pull request cannot merge
  without the sentence.

  Measured, so the next step can be planned rather than discovered:
  **`axiam-core` has 993 sites**. `missing_docs` fires on struct and enum
  *fields*, not only the items containing them, so that is roughly four times
  the number of public types. It is deliberately left for its own change —
  993 doc comments written in a hurry to clear a lint are 993 sentences nobody
  will trust.

- **`AccessTokenSpec`: one description of a token, one signer (F4).** Access-token
  issuance had grown into twelve public functions in three telescoping chains,
  each tier existing only to add one parameter to the tier below
  (`issue_access_token` -> `_bound` adds `cnf` -> `_enriched` adds `ext`). Five
  carried `#[allow(clippy::too_many_arguments)]`; `issue_id_token` takes ten
  positional parameters. Adding one claim meant adding one function per chain,
  so a module whose entire job is "describe a token and sign it" was closed to
  extension — and the signing tail was copied six times, which meant "AXIAM
  signs with EdDSA" could have changed in five of them.

  `AccessTokenSpec` describes a token once; `sign_claims` signs it once. The
  four constructors (`user`, `oauth2_client`, `service_account`, `exchanged`)
  each stamp the `aud`/`sub_kind` pairing that belongs to that principal, which
  is what §4.3 / SEC-006 route narrowing reads and what §17.2 residual 1 was a
  case of getting out of step.

  **All twelve names keep their signatures** as thin delegations, so no caller
  changes. Token bytes, claim order, `jti` policy and every default are
  unchanged, which is what the pre-existing token suites assert. Rationale in
  `claude_dev/token-issuance-spec.md`.

- **UNIQUE-violation detection lives in one place, and CI now says so (F5).**
  Deciding "was this a conflict?" means matching substrings in a SurrealDB
  error message, and that match is a security outcome: at the three replay
  guards it is the difference between refusing a replayed SAML assertion, AMQP
  nonce or DPoP proof and accepting it as fresh. `classify_write_error` had
  documented itself as the only place allowed to do it since D-09; five call
  sites carried their own copy of the marker set anyway, each with a comment
  pointing at one of the others.

  The markers now live once in `axiam_db::helpers`, behind `is_unique_violation`
  and three classifiers (`classify_replay_write_error`,
  `classify_conflict_write_error`, `classify_write_error`), and
  `scripts/check-conflict-markers.py` fails the build if a sixth inline copy
  appears. The three replay tables also share one `cleanup_expired_rows` sweep
  instead of a byte-identical copy each. No behaviour changes: the marker set,
  the fallthrough to 5xx, and every error variant are what they were.

- **BREAKING: AMQP is TLS-only.** `AXIAM__AMQP__URL` must be `amqps://`; every
  other scheme is refused before a socket is opened, in a debug build exactly
  as in a release one. `AXIAM__AMQP__ALLOW_PLAINTEXT` is **removed** — it is no
  longer read, and `scripts/check-amqp-transport.py` reports it as a stale
  leftover wherever it survives. The default `AXIAM__AMQP__URL` changes from
  `amqp://localhost:5672` to `amqps://localhost:5671`.

  The flag did what an escape hatch does. Four stacks reached for it — dev
  compose, the e2e stack, the benchmark target and CI — each with a sound local
  argument (throwaway data, an ephemeral broker carrying synthetic fixtures, a
  hop the harness is trying to measure rather than encrypt). The aggregate was
  that "AMQP is TLS-only" described the production compose file and the k8s
  manifests, and nothing else this repository runs. Broker traffic carries
  authorization requests, audit events and mail payloads across service
  boundaries, and HMAC signing (§8) gives those authenticity and replay
  protection but not confidentiality.

  **To upgrade:** point `AXIAM__AMQP__URL` at your broker's TLS listener and,
  for a privately-issued broker certificate, set
  `AXIAM__AMQP__TLS__CA_CERT_PATH`. `scripts/gen-broker-tls.sh` mints a CA and
  broker certificate if you have no PKI to hand; `just dev-up` and
  `just bench-up` now call it for you. There is still deliberately no
  verification-skip option.

- All four remaining plaintext stacks moved to an AMQPS broker: dev compose,
  the e2e stack, the benchmark target, and CI's test/coverage jobs. CI starts
  RabbitMQ with `docker run` rather than as a `services:` container, because a
  service container starts before any step could mint the certificate it would
  need to mount.

- **Benchmark comparability:** the AXIAM target's broker hop was plaintext
  through run 5 and is now TLS. AMQP-carrying figures (async authz, audit
  ingestion) are not directly comparable across this change, and the Keycloak
  comparison target is unaffected by it. Re-baseline rather than extending a
  trend line through it.

### Fixed

- Install the rustls CryptoProvider before dialling amqps://
- The listener assertion had its own fields backwards
- Assert the AMQPS listener bound, and bound the test that needs it
- The broker's TLS config was never valid Erlang args
- Copy the broker's TLS material in rather than bind-mounting it
- Configure the AMQPS broker with a file, not mangled erl args
- Stop error messages from rendering credentials
- Construct AppState with scim_token_repo, and record the new surface
- Define the scim_token table instead of relying on implicit creation

### Security

- **`h2` bumped to 0.4.16, and RUSTSEC-2026-0258 ignored for the copy that has
  no fix** (h2 queues empty DATA frames without limit — unbounded memory, or a
  panic on length overflow; upstream severity low).

  Two copies of `h2` resolve. The **0.4.x copy (reqwest / tonic / hyper) is
  patched**: `Cargo.lock` moves 0.4.15 → 0.4.16, a lockfile-only change with 91
  dependencies unchanged. The **0.3.27 copy cannot be**: it arrives via
  `actix-http` ← `actix-web` / `actix-governor`, the advisory patches `>=0.4.16`
  only with no 0.3.x backport, and `actix-http` 3.13.3 / `actix-web` 4.14.1 —
  both released 2026-08-09 — are the newest versions and predate the 2026-08-17
  advisory. There is nothing upstream to take.

  **That copy is the one serving the REST listener, so this suppression covers a
  reachable advisory** — unlike every other entry in the ignore list, which are
  never compiled, off by default, or off the reachable path. `tls.rs` advertises
  `h2` in ALPN and refuses to start rather than let ALPN be narrowed to
  HTTP/1.1. Neither the `server.h2` window knobs nor a stream cap bound it
  (empty DATA frames consume no flow-control credit, and `actix-http` never
  sends `SETTINGS_MAX_CONCURRENT_STREAMS`). It is availability-only — no key,
  token or data compromise — and an operator who needs the exposure gone before
  actix ships a fix can terminate TLS at an edge that does not offer HTTP/2
  (`docs/security-profiles.md`, `benchmarks/targets/axiam/tls/tls13-h1.conf`).

  The entry carries that reasoning in full in `deny.toml`, and is to be dropped
  the moment `actix-http` publishes a release built on h2 0.4.

- **The advisory ignore-list is now enforced to be written consistently in both
  places** — `scripts/check-audit-ignore-sync.py`, wired into the Architecture
  Invariants job. `cargo-deny` reads `deny.toml`; `cargo-audit` reads the
  workflow's `ignore:` input and never looks at `deny.toml`, so the list exists
  twice and "keep them in sync" was a comment with nothing behind it. Drift is
  silent in both directions: an ID only in `deny.toml` leaves `cargo audit` red
  for a reason nobody wrote down, and an ID only in the workflow means the
  rationale for suppressing it is recorded in no file at all. Like the other
  gates added here, it ships a `--self-test` that runs on fixtures rather than
  on the repository it guards, and it was verified by deleting an ID from the
  workflow and confirming it names the missing one.

## [1.0.0-alpha26] - 2026-08-16

### Added

- Implement the lapin reactor transport (X1 R2.4)

### Changed

- Close the reactor transport's coverage gaps

### Fixed

- Recover the shared connection from a broker restart
- Close the neutralized-posture holes the alpha25 dry run exposed
- Activate the AXIAM bench user after seeding it

## [1.0.0-alpha25] - 2026-08-16

### Added

- A host allowlist for same-network IdPs behind the SSRF guard (SEC-107)
- Give SCIM provisioning a real bucket (R5.2 tail)
- SDK-Q10 — reason supersedes deny_reason, deprecate-and-add (R5.6)
- GRPC admin service, health surface, integration tests and docs (R2.3, R2.4, R2.6)
- Wire the reactor gate into all five interceptor sites (R2.2, X1)
- Add the axiam-scim crate — SCIM 2.0 provisioning under /scim/v2 (R3.1, B4)
- Per-client logout settings — post_logout_redirect_uris and back-channel URI (R4.2d, B5)
- Scopes CRUD and the effective-access preview with deny cascade (R4.2c, R4.2e)
- Add the device verification page and the GDPR privacy console (R4.1, R4.2a)
- Give FormDialog an accessible error slot and thread mutation errors (R4.3)
- Carry sender-constraining, UMA and X4 provenance on the gRPC surface
- X5.1 second half — private_key_jwt and DPoP (contract 1.16)
- X4 — external-IdP token exchange (RFC 8693, cross-domain)
- X3 — attestation policy enforcement via FIDO MDS3
- X2d — resource registration, RPT introspection, provenance
- X2c — the UMA 2.0 HTTP surface
- X2b — permission endpoint and uma-ticket grant
- X2a — permission ticket domain model and store
- Reactor admin console (X1)
- X1b — REST CRUD, event registry endpoint, OpenAPI
- X1a — event registry, wire protocol and dispatch chain
- §19 config_clamped event — a clamp must be reported (1.9)
- Mount RP-initiated and back-channel logout (B5b)
- Logout-token issuance and session identity for B5
- Mount PAR and teach the authorize endpoint request_uri (B5)
- PAR core — request-URI issuance and single-use consumption (B5)
- Finish the token-exchange grant and wire B2/B3 into the server (B3)
- Wire the token-exchange grant into the REST surface (B3, WIP)
- Token-exchange core — the narrowing rules and their property test (B3, WIP)
- Mount the Device Authorization Grant's REST surface (B2)
- The three unblocked new-feature cells, and why the rest wait (E4)
- Bulk-seed tooling for the seed-size sensitivity cell (E3/J12)
- Device authorization grant — core, storage and state machine (B2, partial)
- A11y smoke suite, coverage matrix, and the deny-effect editor (C3, C4)
- Passkey and security-key enrolment and sign-in (C1, C2)
- RBAC deny-override — explicit deny that beats every allow (B1)
- TLS transport encryption for broker traffic (A6)
- Opt-in strict session-revocation mode + document the default (A4/J10)
- Read-replica routing primitive + staleness contract (A3/J11)
- Link the Coveralls coverage reports
- **WebAuthn attestation policy enforcement (X3).** Registration has always
  accepted any authenticator; tenants can now opt into "only FIDO-certified /
  non-revoked / explicitly-allowed authenticators may register," backed by
  the FIDO Alliance's Metadata Service (MDS3).

  `axiam-pki` gains an MDS3 ingestion pipeline: fetch (or load, air-gapped)
  the ~10 MB signed BLOB, verify its RS256 JWT signature chain against a
  **digest-pinned** vendored GlobalSign Root CA – R3 anchor — matching the
  pinned SHA-256 is the check, the anchor is never re-fetched at runtime —
  pin the leaf's SAN DNS identity (chaining to a public CA root by itself
  only proves "some GlobalSign EV customer," not "FIDO Alliance"), require
  every issuer in the chain to actually be a CA (closing an end-entity
  certificate splice a naive verifier would miss), reject a rollback to an
  older BLOB serial, and mark a BLOB stale past its own `nextUpdate` without
  ever hard-failing ingestion over it. Ingestion is opt-in
  (`AXIAM__PKI__MDS_ENABLED=false` by default — zero outbound calls) with a
  weekly background refresh, an admin-triggered `POST /api/v1/mds/refresh`,
  status via `GET /api/v1/mds/status`, and an `AXIAM__PKI__MDS_BLOB_PATH`
  escape hatch for air-gapped deployments (the BLOB itself is not vendored in
  git).

  Per-tenant policy (`GET|PUT /api/v1/tenants/{tenant_id}/webauthn/attestation-policy`)
  controls attestation mode, required certification level, AAGUID
  allow/block lists, and revoked-status blocking, evaluated by a pure,
  exhaustively-tested decision function
  (`axiam_core::models::webauthn_policy::evaluate`): blocklist beats
  allowlist, compromise/revocation status is sticky across the authenticator's
  whole history, and an AAGUID explicitly allow-listed by an admin is trusted
  even with no MDS entry for it. The default (`mode: none`) reproduces
  today's behavior byte-for-byte, with no MDS lookup at all.

  **Every non-`none` mode excludes synced passkeys** (iCloud Keychain, Google
  Password Manager) **and hybrid sign-in**, not only the strictest setting —
  `webauthn-rs` always requires user verification and always rejects
  synchronised authenticators once attestation is requested at all. AXIAM's
  `mode: indirect` still requests `direct` conveyance on the wire; it differs
  from `mode: direct_required` only in policy strictness afterwards. See
  [`docs/admin/authenticator-policies.md`](docs/admin/authenticator-policies.md)
  for the full trade-off before enabling it.

  Denials return a fixed, non-specific error and audit
  `webauthn.attestation_denied` with the AAGUID and machine-readable reason —
  never a raw library error to the end user. **Existing credentials are never
  auto-revoked** on a policy change: `GET
  /api/v1/tenants/{tenant_id}/webauthn/compliance-report` lists which
  registered credentials would now fail the current policy (a credential
  with no recorded AAGUID — every credential registered before X3 — is
  reported `unknown`, never as a violation), and revocation stays the
  existing admin credential-delete path, a deliberate human action.

  Known, documented limitation: `block_revoked_status` covers `REVOKED` and
  the three `*_COMPROMISE` statuses, not `USER_VERIFICATION_BYPASS` — an
  authenticator with only a UV-bypass advisory still passes that check.
  Operators who care should use `blocked_aaguids`.

- **SCIM 2.0 provisioning (RFC 7643/7644, B4).** A new `axiam-scim` crate mounts
  `/scim/v2`, so an IdP — Okta and Microsoft Entra are the two the scope was
  drawn from — can create, update, deactivate and delete users and groups in a
  tenant without anyone writing a bespoke sync job against `/api/v1`.

  `Users` and `Groups` get full CRUD plus the discovery endpoints
  (`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`). It maps onto the
  **existing** `UserRepository`/`GroupRepository` — there is no parallel SCIM
  store, so a SCIM-provisioned user is an ordinary AXIAM user from the first
  request onward.

  The scope is deliberately the subset those two IdPs actually send, and the
  parts outside it fail loudly rather than silently doing something
  approximate: `PATCH` implements the RFC 7644 §3.5.2 add/replace/remove ops on
  standard attribute paths; filtering is `userName eq` and `externalId eq` with
  paging, and any more complex filter returns **400 `invalidFilter`**; bulk
  operations are not implemented and `POST /Bulk` returns **501**.

  Authorization is a dedicated `scim:provision` permission, checked per request.
  Tenant scoping is not a check SCIM adds but a channel it never opens: the
  tenant comes only from the validated JWT's `tenant_id` claim, never from the
  request path or body, and every repository call takes that tenant as a
  mandatory parameter. The contract tests exercise that adversarially — by UUID,
  cross-tenant, on GET/PUT/PATCH/DELETE/list — rather than only testing "no
  token".

  **Operator note:** the bearer principal must be a tenant *user* that holds
  `scim:provision` (create a `scim-provisioner` user and grant it a role through
  the existing `/api/v1` APIs), **not** a `service_account`. AXIAM's RBAC
  role-assignment edge is hard-scoped to the `user` table today, so a
  `service_account` subject can hold no RBAC permission at all. That predates
  this crate. See [`docs/api/scim-provisioning.md`](docs/api/scim-provisioning.md)
  for the Okta and Entra walkthroughs.

  Rate limiting: one bucket spans the whole `/scim/v2` scope — reads, writes and
  discovery alike — at `scim_per_min = 600` (`AXIAM__RATE_LIMIT__SCIM_PER_MIN`),
  the same 10/s the gRPC Admin family uses. Both surfaces are fully-privileged,
  machine-driven, and sized as a CPU guard on Argon2id, which is SCIM's real
  cost profile: `POST /Users` and a `password` PATCH both hash. The limiters sit
  *outside* the credential check so an unauthenticated flood is shed before it
  reaches Argon2id, which is also why the discovery endpoints share the bucket
  instead of going unmetered.

- **OIDC logout: RP-initiated and back-channel (B5).**
  `GET`/`POST /oauth2/end_session` ends the session named by a signed
  `id_token_hint`, and every client that participated in that session and
  registered a `backchannel_logout_uri` is POSTed a signed logout token.
  Advertised in discovery as `end_session_endpoint`,
  `backchannel_logout_supported` and `backchannel_logout_session_supported`.

  Both halves operate on a **session**, not a user: a user with a phone and a
  laptop who logs out on the laptop keeps the phone signed in. ID tokens now
  carry `sid`, and it survives refresh-token rotation so an RP that stored it
  at login can still match a logout token to its own session.

  The endpoint is unauthenticated by necessity — a user whose session already
  expired must still be able to complete a logout — so what identifies the
  target is the *signature* on the hint. Expiry on the hint is deliberately
  not checked (a logging-out user's ID token has usually expired already); the
  signature is. An unverifiable hint ends **nothing**: there is no fallback to
  "end every session for the named subject", which would be a
  denial-of-service primitive for anyone who knows a user id.

  `post_logout_redirect_uri` is honoured only on **exact match** against the
  client's new `post_logout_redirect_uris` allow-list — a separate list from
  `redirect_uris`, because one receives authorization codes and the other
  receives a browser after logout. A non-matching URI still logs the user out
  and renders AXIAM's own page: refusing to log someone out because their RP
  sent a bad parameter is the wrong failure.

  Logout tokens carry the mandatory `events` member, always name `sid`, live
  120 s, and can never carry `nonce` (the issuer takes no such parameter, so
  it cannot emit one by accident — its presence is how an ID token gets
  replayed as a logout token). Delivery is best-effort with a bounded retry
  and never blocks the logout.

  New: `AXIAM__RATE_LIMIT__END_SESSION_PER_MIN` (30). See
  [`docs/api/logout.md`](docs/api/logout.md) and CONTRACT.md §12.7.

- **Pushed Authorization Requests (RFC 9126, B5).** `POST /oauth2/par` accepts
  an authorization request over a direct, client-authenticated POST and returns
  an opaque single-use `request_uri` to put in the browser redirect instead of
  the parameters. `/oauth2/authorize` accepts it, refuses to mix it with inline
  parameters (where parameter confusion lives), and a client registered
  `require_par` may not send its parameters through the browser at all. New:
  `AXIAM__RATE_LIMIT__PAR_PER_MIN` (120). Required by FAPI 2.0.

- **OAuth2 Token Exchange (RFC 8693, B3).** A service holding a user's access
  token can exchange it for a *narrower* one —
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` on
  `POST /oauth2/token`, advertised in OIDC discovery. Previously a mesh caller
  had two options, both wrong: forward the user's token verbatim
  (over-privileged, and the second hop cannot tell the caller from the user)
  or use its own service credentials (right privileges, no user context).

  One rule governs the feature: **an exchange may only ever narrow.** No
  parameter, configuration or client grant makes the issued token permit
  something the subject token did not already permit. Concretely:

  - `granted = requested ∩ subject_scopes ∩ client_allowed_scopes`. A
    requested scope the subject does not hold is **refused** (`invalid_scope`),
    not silently dropped — silent narrowing produces a token that works for
    some calls and not others, and the caller finds out at the *next* service.
    The client's own registration bounds the result even when the subject token
    is broader, which is what stops a compromised low-privilege service holding
    an admin's token from minting an admin token.
  - `exp = now + min(subject_remaining, max_exchange_lifetime)`. The exchanged
    token never outlives its subject, so an exchange cannot launder lifetime.
    For the same reason **no refresh token is issued** — one would defeat the
    cap outright — and naming `requested_token_type=…:refresh_token` is
    refused rather than answered with an access token.
  - `audience`/`resource` must be registered to the exchanging client; an
    unconstrained `aud` is the mesh equivalent of an open redirect.

  **Delegation vs impersonation** is selected by the presence of `actor_token`,
  and the two are not equally available. Delegation adds an `act` claim naming
  the actor (nested on re-exchange, capped at depth 3 so a signed token cannot
  grow an unbounded field). Impersonation issues a token indistinguishable from
  one the user obtained directly, so it is **off by default** — a client needs
  the explicit `urn:axiam:params:oauth:grant-type:may-impersonate` grant, and
  one without it is refused (`unauthorized_client`) rather than quietly
  downgraded to delegation. Every exchange is audited with client, subject,
  actor, kind, requested and granted scopes, audience and outcome; for
  impersonation that record is the *only* evidence the acting party was not the
  subject.

  v1 accepts AXIAM-issued subject tokens only — accepting another IdP's token
  means accepting whatever it asserts about the subject, and the trust
  configuration that makes that safe is its own feature (X4). A cross-tenant
  subject token answers `invalid_grant` rather than a distinct error, because
  learning a token is valid *somewhere else* is a tenant-enumeration signal.

  New rate-limit bucket `AXIAM__RATE_LIMIT__TOKEN_EXCHANGE_PER_MIN` (120): an
  exchange verifies an inbound JWT, reads the client registration and writes an
  audit record, and it is what an attacker holding one stolen token would
  hammer looking for a widening path. See
  [`docs/api/token-exchange.md`](docs/api/token-exchange.md).

- **OAuth2 Device Authorization Grant is reachable (RFC 8628, B2).** The
  grant's core, storage and state machine landed earlier; nothing was mounted,
  so no device could use it. Now: `POST /oauth2/device_authorization` issues
  the code pair, `POST /oauth2/token` serves
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` with the full §3.5
  answer table (`authorization_pending`, `slow_down`, `expired_token`,
  `access_denied`, `invalid_grant`), and
  `GET /api/v1/device/verify` + `POST /api/v1/device/decide` back the
  verification page. The endpoint is advertised in OIDC discovery, because a
  device that can read discovery is exactly the client that cannot be told the
  URL out of band.

  The verification endpoints live under `/api/v1`, not `/oauth2`, and that is
  the design: approval records the approver as the subject the token is minted
  for (so the caller must be authenticated), and a short typed code is
  guessable from another origin (so CSRF double-submit is what stops a
  malicious page approving on a victim's session — RFC 8628 §5.4's phishing
  shape from the other direction). Unknown, expired and already-decided codes
  answer identically, so the page is not an oracle for which codes are live.

  Two new rate-limit buckets, neither sized from benchmark capacity:
  `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` (12) because the endpoint
  is unauthenticated *and* allocates state, and
  `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` (10), the user-code brute-force
  bound — `RateLimitConfig::validate` now **asserts** the OWASP condition
  against the grant lifetime, so raising it past the point where an
  8-character typed code becomes guessable fails at startup rather than in an
  incident review. See [`docs/api/device-flow.md`](docs/api/device-flow.md).

- **Passkeys and security keys in the admin UI.** The server had shipped the
  full WebAuthn registration and authentication ceremonies for releases, but
  the frontend had zero WebAuthn references — the MFA page advertised passkeys
  as "Coming soon" and the login page could not exercise them. Both are now
  wired: enrol a platform passkey or a cross-platform security key from
  Profile → MFA methods, and sign in with a passkey via browser autofill
  (conditional mediation), an explicit button, or as a second factor. The MFA
  list distinguishes `Passkey` from `Security key` rather than labelling both
  "WebAuthn". All ceremony policy stays server-side.
- **Deny-effect selector in the role editor**, with a distinct `DENY` badge on
  granted permissions. Deny rules were creatable over the API from the moment
  B1 landed and invisible in the console — the worst of both worlds.
- **Frontend coverage matrix** (`claude_dev/frontend-coverage-matrix.md`) plus
  a CI check that fails when a REST handler module has no row, so a new server
  surface cannot ship without someone recording whether it needs a UI.
- **axe-core accessibility smoke suite** over the main pages and the
  design-system components the audit fixed, wired into the fast frontend CI job.
- **RBAC deny-override (explicit deny).** A role→permission grant now carries
  `effect: "allow" | "deny"`, defaulting to `"allow"`. A deny grant overrides
  **every** allow, at any depth of the resource hierarchy and at equal
  specificity — deny-override, not most-specific-wins. Closes SEC-040 and the
  "no explicit deny" entry in the comparison page's cons list. Check responses
  gain `reason_code` (`allowed` | `no_grant` | `denied_by_rule`) so a caller
  can tell "ask an admin for access" apart from "an admin has already
  decided". Fully backward compatible: existing grants and `effect`-less
  requests both mean allow, and no migration is required beyond the additive
  schema field.

- **AMQP transport encryption (`amqps://`).** Broker traffic was plaintext in
  every deployment artifact. `AmqpConfig` now accepts `amqps://` URLs with an
  optional TLS block (custom CA bundle, optional client certificate for mutual
  TLS toward the broker), and the prod compose stack and k8s manifests speak
  TLS 1.3 on port 5671 with the plaintext listener switched off. There is
  deliberately no verification-skip option: `ca_cert_path` covers the
  legitimate reason to want one. HMAC signing stays mandatory — TLS is
  confidentiality in transit, HMAC is end-to-end authenticity across broker
  hops, and neither substitutes for the other. SDK contract §8b.
- **gRPC strict session-revocation mode** (`AXIAM__GRPC__STRICT_REVOCATION`).
  Opt-in per-request revocation enforcement on the gRPC data plane, matching
  REST. See "Changed" for the default this makes explicit.
- **Read-replica routing primitive** (`AXIAM__DB__READ_REPLICAS`, off by
  default) with a documented staleness contract; authorization, identity and
  JWKS reads are replica-eligible, session revocation and write-path reads are
  pinned to the primary and cannot be configured otherwise.
- Rate-limit scenarios for the three limiter families that had none (`revoke`,
  gRPC admin, gRPC infra), so all eight families appear in the enforcement
  verdict table.

### Changed

- Quick-run benchmark runbook for alpha25 (AXIAM-only, p0/p2/p3)
- Execution log update 5b — SEC-096..SEC-107, and a runbook row the fix invalidated
- Contract 1.20 and the SEC-096..SEC-107 dispositions
- Correct the CA-trust claim and the nonce backstop's reach (SEC-105, SEC-106)
- Execution log update 5 — the tracked follow-ups
- Make the frontend job print the coverage it achieved
- Provision the scim:provision principal the SCIM scenario needs
- Detect stale vendored artifacts across the SDK repos (R5.8b)
- Execution log update 4 — R5.8 fan-out, merges, R5.9, R5.2 tail
- Ratchet the Rust line-coverage floor 80 -> 88 (R5.9)
- The two authored k6 scenarios are no longer owed (R5.11)
- Execution log update 2 — final wave status, residuals and new findings
- Add the first coverage floor to vitest.config.ts (R5.9)
- F4-bis review of everything post-2026-08-10 (R6)
- Drop the on-failure server-log dump entirely (R5.1)
- Shrink the smoke failure dump to 40 lines (R5.1)
- Clear the two clippy findings in the reactor test code (R2.2)
- Rustfmt the gate wiring and drop a literal test credential (R2.2)
- Prove X4 token exchange against a real Keycloak (R5.4)
- Close the X2 test gaps — Keycloak RPT compat and a deny-override property test (R5.3)
- Supply the three mandatory startup secrets to the smoke stack (R5.1)
- Assert native constraint validation on the login form (R4.7)
- Make the runtime-smoke failure legible and supply b3's password (R5.1)
- Drop needless borrows in the contract tests (R3.1)
- Join the grants_by_role declaration onto one line (R1.3)
- Add the F3 examples tree with a two-tier CI smoke job (R5.1)
- State the SEC-089 audience allow-list where operators and callers read it (R1.1)
- Refresh the frontend coverage matrix for the R4 surfaces
- Add the execution log for the 2026-08-15 remediation pass
- Add §22 Reactors and bump the contract to 1.18 (R2.1)
- Record token exchange's revocation posture where F4 asked for it (R1.2)
- Add A1's owed sustained-flood integration test (R5.2)
- Run the limiter suite as a dedicated job (R5.2)
- Add the missing flood scenarios and the two unwritten R7 cells (R5.2, R7)
- Correct the stale permissions row in the coverage matrix (R4.9)
- Emit CycloneDX SBOMs for the Rust workspace and frontend (R5.10)
- Truth up stale status lines across five planning docs (R5.11)
- Benchmark Run5 changes
- Consolidated remediation plan from the 2026-08-15 full verification
- Drop the owned copies totp-rs 5.x's Secret::Encoded required
- Keep the RFC 9449 `ath` vector in exactly one place
- Regenerate openapi.json for the contract 1.16 client fields
- Bump totp-rs from 5.7.2 to 6.0.0
- X5 — FAPI 2.0 readiness, conformance harness, and contract 1.15 (#319)
- Contract 1.14 + STRIDE model for the X6 single-use guarantee
- Subject_token_type becomes required (contract 1.13)
- Add X6 — make single-use redemption a guarantee (closes the #302 residual)
- Bump the minor-patch group across 1 directory with 7 updates
- Allow BSL-1.0 for xxhash-rust
- Dispatch /oauth2 errors on the error field (contract 1.12)
- Lift the §12.6 Swift/C/C++ deferral (contract 1.11)
- §20 — the UMA 2.0 contract the SDK fan-out implements
- Shrink test-job target/ so the gRPC relinks stop exhausting runner disk
- Bump Swatinem/rust-cache from 2.9.1 to 2.9.2
- Bump dtolnay/rust-toolchain
- Bump github/codeql-action/upload-sarif
- Bump taiki-e/install-action from 2.85.5 to 2.85.10
- Bump the minor-patch group in /frontend with 6 updates
- Bump actions/attest-build-provenance from 4.1.1 to 4.2.2
- Fold the single-use suite into one test binary
- E2e specs for the reactor console (X1)
- Record the reactor console as a P1 gap (X1)
- Correct the deny-override claim across the live doc set (F2) (#288)
- F4 review of the B-track; fix SEC-088 sub_kind confusion
- §16 preamble rewritten from tests, not greps (1.8.3)
- §16 preamble errata — five SDKs diverged (1.8.2)
- §16 preamble errata — three SDKs diverged, not two (1.8.1)
- Contract 1.8 — retry policy, decision memo, close(), telemetry (D5) (#283)
- Contract 1.7 — device_login credential-adoption errata (D6)
- Contract §12.7 logout helpers; server logout guide (D4)
- Contract §14 device grant, §15 token exchange; B5 design (D4)
- Drive the device-flow suite green — all 14 pass
- Answer the two questions that decide X3's cost, before starting it
- One shared test-password helper; lint the AMQP transport posture
- Add extra B-track features doc (X1-X5) — Reactors, UMA 2.0, MDS3, external-IdP exchange, FAPI 2.0
- Cut refresh rotation from five datastore round trips to three (A2/J2)
- Add A6 — AMQP transport encryption (amqps/TLS)
- Post-run-5 improvement plan — fixes, competitor gaps, frontend/SDK completion
- Update benchmarks page to run 5, add SDK and §10 sections
- Benchmark run 5 — release image, full matrix, three mysteries closed (#275)
- Run 5 targets the published 1.0.0-alpha24 image, not a local build
- **BREAKING (release builds): a plaintext `amqp://` broker URL is now
  refused** unless `AXIAM__AMQP__ALLOW_PLAINTEXT=true`. Mirrors the existing
  fail-closed posture for the AMQP signing key. Debug builds are unaffected,
  so `cargo test` and `cargo run` keep working untouched — but note that the
  dev, e2e and benchmark compose stacks all run the *published release image*
  and so are subject to the guard like any deployment. All three now set
  `AXIAM__AMQP__ALLOW_PLAINTEXT=true` explicitly, each with a comment stating
  why plaintext is acceptable for that stack. Any other release-image stack
  with an `amqp://` URL must do the same or move to `amqps://`; it will
  otherwise refuse to start, by design.
- **Rate limiting: enforcement now matches configuration in both directions.**
  gRPC families were admitting 1/20–1/33 of their configured ceiling under a
  single-IP flood (the shared 60-second pre-check was charging requests the
  per-second governor then rejected), while REST machine endpoints
  over-admitted by up to +50% (fixed-window boundary doubling). The shared
  counter now uses a sliding window, counts admitted capacity rather than
  arrivals, and refunds downstream rejections; a newly seen key gets its
  pro-rata share of the window plus an explicit, documented 10% burst
  allowance — except below 20/min (every human endpoint, no machine one),
  where smoothing a five-request budget would cost a legitimate first-time
  user a whole request for no security benefit. Rollback:
  `AXIAM__RATE_LIMIT__SHARED_WINDOW=fixed`.
- **Refresh rotation is three datastore round trips instead of five**, via an
  atomic `consume_by_token_hash` (which also removes the read-then-delete
  window rather than tolerating it) and a TTL cache for the per-refresh tenant
  lookup. Single-use rotation, the user-status check, and consuming expired
  tokens are all unchanged.
- **Documented: gRPC does not check session revocation by default.** A user
  who logs out keeps passing gRPC authorization until their access token
  expires (up to 15 minutes). This was always true; it is now written down,
  and `AXIAM__GRPC__STRICT_REVOCATION=true` changes it.
- **gRPC `CheckAccessRequest.subject_id` is now optional**, the way the REST
  check body's has always been: an **empty** value means "the subject in the
  verified token" instead of being refused as a malformed UUID. A non-empty
  value must still equal the token's subject — gRPC has no `authz:check_as`
  cross-subject form. Empty carries the meaning rather than the field becoming
  proto3 `optional`, because that is a cardinality change `buf breaking`
  refuses. Purely a widening: every request that worked before still works.

### Deprecated

- **gRPC `CheckAccessResponse.deny_reason` — superseded by `reason`, removed at
  2.0.** The REST decision body has always called the human-readable reason
  `reason`; the gRPC one called the identical string `deny_reason`, so every SDK
  speaking both transports reconciled the two names itself, and not all of them
  reconciled them the same way (SDK-Q10). `CheckAccessResponse` now carries
  **`reason` (field 4)** with explicit presence — absent on an allow, present on
  every refusal, exactly the REST shape — and `deny_reason` is marked
  `[deprecated = true]` while continuing to carry the identical string.

  Nothing breaks today: both fields ship until **AXIAM 2.0**, where
  `deny_reason` is removed. Renaming it now would have broken every deployed
  gRPC client on the wire for no behavioural gain. Clients should read `reason`
  and fall back to `deny_reason` only when `reason` is absent *on a refusal*,
  which means the server predates this change. The rule, and the SDK-side
  obligations that go with it, are in `sdks/CONTRACT.md` §11.2 rule 9
  ("Amended 2026-08 (SDK-Q10)", contract 1.19).

### Fixed

- Normalize extension-less --scenario; read matrix trees in rl-prod-check
- Delete must report NotFound for a foreign or unknown id (SEC-104)
- Deprovisioning must revoke live sessions and refresh tokens (SEC-098)
- Correct the gate's deny paths and refuse an undispatchable registration (SEC-099, SEC-100, SEC-101)
- Stop token exchange stripping sender-constraining (SEC-096, SEC-097, SEC-102)
- B5 back-channel logout URI must be reachable from AXIAM (R5.1)
- B5 must send tenant_id on the RP-initiated logout URL (R5.1)
- Declare the containerized reactor test queue durable, not transient (R2.4)
- Close the three HIGH findings from the F4-bis review (SEC-093, SEC-094, SEC-095)
- Configure a real OIDC issuer URL for the compose stack (R5.1)
- Generate the reactor test fixture's password instead of hard-coding it (R2.3)
- B2 read tenant_id from the wrong path in the /auth/me response (R5.1)
- B2 must send tenant_id to /oauth2/device_authorization (R5.1)
- Correct the role-assignment status codes and stop carrying a literal test password (R5.1)
- B1 asserted 201 where the API returns 204 (R5.1)
- Use express-rate-limit in the B5 RP example (R5.1)
- Close the CodeQL findings in the B3 and B5 examples (R5.1)
- Allow registering the device-code and token-exchange grants
- Enforce bearer SubjectConfirmationData — Recipient, NotOnOrAfter, InResponseTo (R1.5, SEC-005)
- Key batch grants per tenant and document the widening fallback (R1.3)
- Stop claiming the RBAC engine has no deny-override (R4.4)
- Surface delete failures on the tenants page (R4.6)
- Gate every protected route and fail closed on a null /auth/me (R4.5, R4.7)
- Keep proof_replay_repo out of SamlFederationService::new
- Port TOTP to totp-rs 6.0's builder, struct Secret and Token
- The authorization-code grant joins the layered single-use mechanism
- X6 — single-use redemption becomes a guarantee (#302)
- Repair the db test build, split the frontend format helpers
- Commit the vendored MDS trust anchor, which .gitignore ate
- Give resource delete and child create a key to collide on
- Run the serialisation tests and both deployments on surrealkv
- Wire X2 into the server binary and regenerate the derived artifacts
- Stop device-grant and PAR single-use depending on conflict detection
- Decide the ticket race in `consume` instead of asking SurrealDB to
- Serialise single-use consumes for device grants and PAR
- Keep the FormDialog footer reachable on tall forms
- Register the reactor permissions and routes (X1b)
- Deny-override precedence pass — end-to-end tests + SEC-092 (#289)
- Box ClientOutcome::Found — B5's fields tripped large_enum_variant
- Classify the device verification paths; B5 registration groundwork
- Give the authorization test fixture B3's new `act` claim
- One authenticate_client, and use the J1-aware rate-limit check (B3)
- Apply SDK_BENCH_CONCURRENCY to the C++ client, not just its workers (D2/J6)
- Record the Python bench's event loop and prefer uvloop (D1/J5)
- Close the three SDK-harness audits — TS baseline, C# accounting, Rust CPU (D3/J7/J8/J8b)
- Make the required container env provable, and stop dropping investigation artifacts (E1/E2)
- Repair the two specs C1/C2 invalidated
- Set ALLOW_PLAINTEXT on the three release-image stacks A6 broke
- Generate the budget test's password; bump dev-only nanoid past GHSA-2v37-7h3g-55p8
- Exempt human-scale limits from the cold-entry seed (A1 follow-up)
- Pre-mint the refresh session pool inside the login budget (A5/J4)
- Close the two-layer starvation and boundary over-admission (A1/J1)
- Repair the dry-run matrix — teardown, seed idempotency, mTLS probe
- Realign rate-limit assertions with SEC-079; fix run-5 preflight
- Align the footer link columns

### Security

- **The authorization-code grant joins the layered single-use mechanism
  (schema v37).** `authorization_code.consume` was the fourth single-use
  consume in `axiam-db` and the only one X6 left alone — it was outside #302's
  scope. It was not broken: its redemption is a single statement, so it already
  ran in the storage engine's own transaction and two concurrent callers
  conflicted on one key. What it lacked was the second layer.

  It now carries both, identically to the other three: the guarded `UPDATE`
  inside an explicit `BEGIN`/`COMMIT`, and a per-attempt `redemption_id` read
  back in a **separate query after that transaction commits**. The read-back
  must stay outside the transaction — inside one, snapshot isolation shows
  every racer its own write and every racer believes it won.

  The reasoning is the same one that kept the nonce on the other three: a code
  redeemed twice is two token pairs from one authorization, conflict detection
  is not a documented SurrealDB guarantee, and the cost is one extra write and
  one extra read on an operation that happens once per login. A losing racer
  still answers `NotFound`, exactly as an unknown code does, so no caller can
  distinguish "someone else just redeemed this" from "no such code".

  `authorization_code_consume_serialises` now runs 50 rounds of 8 racers rather
  than one, and a new `an_authorization_code_redemption_stamps_its_nonce`
  asserts the second layer directly — a race test alone cannot tell a two-layer
  mechanism from a one-layer one when the engine arbitrates either way. Threat
  T-164 in the STRIDE model is updated accordingly.

- **Single-use redemption is now a guarantee, conditional on a persistent
  storage engine (X6, closes #302).** UMA permission tickets, RFC 8628 device
  grants and RFC 9126 PAR `request_uri`s could each admit a second concurrent
  redemption at a measured ~1 in 640 — two RPTs from one authorization
  decision, two token sets from one user approval, or a replayable
  authorization request. All three consume paths now run **two** layers rather
  than choosing between them: the guarded `UPDATE` is back inside an explicit
  transaction, so the storage engine arbitrates and aborts every loser, and the
  per-attempt redemption nonce is read back in a separate query *after* that
  transaction commits, catching any conflict the engine silently missed. The
  read-back must stay outside the transaction — inside one, snapshot isolation
  shows every racer its own write and all of them believe they won.

  A double redemption now needs two independent failures. The first layer is a
  measured property of the engine (`tools/surreal-race-probe`: zero double
  winners in 40 000 contended attempts on `surrealkv` and 9 600 on `rocksdb`,
  against 12–23 in 1 200 on the in-memory engine), so **a deployment MUST run
  `surrealkv:` or `rocksdb:` and MUST NOT run `memory:`** — see the new section
  at the top of `docs/deployment/README.md`. The shipped compose files and k8s
  StatefulSet already comply.

  `axiam-server` now attests the storage engine at startup. SurrealDB 3.2.4
  publishes no datastore identity over the wire — neither `/version`, nor
  `INFO FOR ROOT` including its `system`/`nodes`/`config` sections, nor any
  `session::*` function — so today that attestation logs a WARN saying the
  engine could not be attested. The hard guard is written and tested: when a
  SurrealDB release does expose the engine, startup refuses a `memory`
  datastore unless `AXIAM__DB__ALLOW_MEMORY_ENGINE=true`, and a unit test fails
  on the bump that makes the name available.

  The probe becomes a version-bump gate: `.github/workflows/surreal-race-probe.yml`
  re-measures `surrealkv` at 5000 × 8 in both shapes whenever `Cargo.lock` moves
  `surrealdb`, `surrealdb-core` or `surrealkv`, and fails on any double-winner
  round. Results are recorded, version-pinned, in
  `tools/surreal-race-probe/RESULTS.md`.

- **SEC-088 (fix): token exchange no longer mints a `sub_kind`/`sub` mismatch.**
  Exchanging to the machine audience rewrote `sub_kind` to `OAuth2Client` while
  leaving `sub` as the subject user's UUID — the one combination the
  `sub_kind`-tells-you-how-to-read-`sub` contract says cannot occur.
  `sub_kind` now always carries through unchanged from the subject token; the
  audience alone conveys "this token reached the M2M audience by exchange." A
  regression test exchanges a user token to `aud=axiam:m2m` and asserts
  `sub_kind == User` and `sub` unchanged.
- **SEC-089 (decision): the token-exchange audience allow-list stays
  `redirect_uris`, documented loudly instead of split into a dedicated field.**
  Adding a redirect URI to a client also authorises it as a token-exchange
  audience for that client; there is no separate audience allow-list in v1.
  This is now stated on `TokenExchangeRequest::audience`, at both allow-list
  check sites in `token_exchange.rs`, on the `redirect_uris` field docs in the
  client-management handler, in `docs/api/token-exchange.md#audience`, and in
  the generated OpenAPI schema. A dedicated `allowed_token_targets` field
  remains the intended eventual fix.
- **SEC-090 (decision): an impersonation exchange intentionally resets the
  actor-chain depth bound.** Impersonation produces a token indistinguishable
  from one the subject obtained directly, so it starts a new, unlinked chain
  rather than extending the delegation one it grew out of. No code change:
  impersonation already requires the dedicated `may-impersonate` grant, and
  the per-hop lifetime cap still bounds every chain regardless of depth.
  Recorded so the reset is not rediscovered as a surprise.
- **SEC-091 (doc): token exchange's revocation posture is now stated where an
  operator will find it.** Exchange does not consult session revocation — the
  same standing posture as non-strict access-token validation elsewhere in
  AXIAM — bounded by two properties already enforced in code: the exchanged
  token's lifetime can never exceed the subject token's remaining lifetime,
  and its granted privilege is always a subset of the subject's and the
  client's scopes. Documented in `docs/security-profiles.md` (Session-revocation
  posture) and cross-referenced from `docs/api/token-exchange.md#sec-091`.
- **SEC-092 (fix): an unrecognised permission-grant `effect` no longer reads
  back as `allow`.** `PermissionGrantRow::try_into_grant` used to default an
  unparseable `effect` to `Allow`; under deny-override that silently defeated
  every deny for the affected role during a rolling upgrade that wrote a newer
  effect value an older node could not parse. The row is now dropped instead
  — it contributes neither an allow nor a deny, decisions fall through to the
  remaining grants and ultimately to default-deny — and logged at `error`
  rather than `warn`, since reaching that branch means the datastore was
  written outside both the API validator and the schema `ASSERT`.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Add the Threat Modeling & Security section
- Service-account client_credentials grant + SEC review (#267)
- Cross-replica decision-cache invalidation over RabbitMQ fanout
- Install the client-secret hasher at startup (OBS-1 fail-closed gate)
- Key client-secret hashing with the server pepper (OBS-1)
- **Service accounts can now authenticate via OAuth2 client-credentials.**
  `POST /api/v1/service-accounts` and `rotate-secret` have always returned a
  `client_secret` to the operator — but **no flow accepted it**. A service
  account's only working authentication path was mTLS
  (`POST /api/v1/auth/device`); the client-credentials grant verified against
  the `oauth2_client` table only, and nothing ever compared
  `service_account.client_secret_hash` against a presented secret.

  The grant now dispatches on the `client_id` prefix — `oa_` for `oauth2_client`,
  `sa_` for `service_account`, both server-generated and disjoint, so one lookup
  still suffices. The prefix is **not** a security decision: it only selects the
  table, and the presented secret must still verify against the row found.

  Three deliberate properties:
  - **The secret is verified before the status check**, so a caller cannot
    distinguish "exists but disabled" from "does not exist" by timing. A
    non-Active account returns the same generic `invalid_client`.
  - **No scope may be requested.** A service account registers no scopes, and
    the subset rule leaves the empty set as the only valid request; its
    authorization comes from the roles assigned to it, as on the mTLS path.
  - **The token's `sub` is the service-account id**, not the client id, and its
    `aud` is `axiam:m2m`, so §4.3/`SEC-006` route narrowing keeps it off user
    routes. A service account is now the same principal however it authenticated
    — see the breaking device-audience change below, which makes the mTLS path
    stamp `axiam:m2m` as well.

- **Legacy client-secret hashes in `service_account` are now countable
  (§15.2).** `count_legacy_secret_hashes(tenant)` plus a startup warning.
  With the grant above in place these rows now migrate lazily on first
  authentication, exactly as `oauth2_client` rows do; the count covers the case
  migration cannot reach — a service account that never authenticates — which is
  what decides whether the legacy hash arm can be retired. **Rotation** clears
  such a row.
- **CI gate: remediation evidence must resolve on `main` (§11.2).**
  `scripts/check-remediation-evidence.py` parses the remediation tables in
  `claude_dev/security-analysis-*.md` and verifies every cited commit is
  reachable from `origin/main` in the repository it claims. A recorded commit
  hash is not evidence a fix shipped — a hash exists the moment a commit is
  authored, on any branch — and this pass caught a real instance of a fix
  recorded as remediated while still unmerged. Rows that cannot be verified are
  printed individually under an explicit `SKIPPED, NOT VERIFIED` banner rather
  than passing silently.

- **`sdks/CONTRACT.md` §10.1 — minimum local-verification set (normative).**
  States once, for every SDK, what a guard must check before turning a token
  into an identity: signature with `alg` pinned before key lookup, `exp`
  REQUIRED, `nbf` honoured when present, `tenant_id` asserted against the
  configured tenant, `iss`/`aud` checked when configured, and a named bounded
  clock skew — all fail-closed. Written because `SEC-071` and `SEC-080` were the
  same defect found independently in two SDKs: each verified a different subset,
  and each subset looked complete in isolation.

### Changed

- Close the review series; make the website section handoff-ready
- Fix the §22.3 residuals (#272)
- Verify §20/§21 — every finding closed
- Bump the minor-patch group across 1 directory with 3 updates
- Record the rule-8 guardrail tests as closed (§21)
- Close SEC-086 fully and SEC-087, fix the CHANGELOG inversion (#269)
- Verify d15878a2 — device audience narrowed; SEC-086 partial, SEC-087 new
- Close SEC-086 and the §17 residuals, narrow the device audience (#268)
- Verify §16 and review the new service-account grant
- Bump pem from 3.0.6 to 4.0.0
- Bump the minor-patch group with 2 updates
- Bump taiki-e/install-action from 2.85.2 to 2.85.5
- Bump github/codeql-action/upload-sarif
- Bump the minor-patch group in /frontend with 8 updates
- Bump docker/login-action from 4.5.1 to 4.6.0
- Bump hadolint/hadolint-action from 3.3.0 to 3.4.0
- Close the §15 partials and observations (#259)
- Verify §14 — SEC-085 closed, no open findings remain
- Close every open item from the 2026-08-02 security analysis (§13) (#258)
- Final verification pass — §12 claims confirmed; one new HIGH (SEC-085)
- Close §4 residual 2 — cross-replica cache invalidation shipped
- Record the CONTRACT §10.1 sweep — five new findings; correct §10.7
- Normative SDK local-verification set; close residual 10.4-3 as misdescribed
- Verify the SEC-079/080 remediation; all findings closed
- Record §10 remediation status as claims pending verification
- Independent re-verification pass; sync threat model for T-145
- Add exact-command reference to the run-5 runbook; fix three harness defects it exposed
- Generate the query-plan fixture password instead of hard-coding it
- Add run-5 runbook; add CONTRACT §13 webhook verification
- Record remediation status for SEC-071..078 and T-145
- Fix authz-path table scans, add session-validation cache and CC stage timings
- Add 2026-08-02 code-level security analysis
- Add public-facing Threat Modeling & Security website section
- Update benchmarks page to run 4 and add resource usage
- Run-4 analysis — post-fix matrix verified, resource usage, prod-limit guidance
- **⚠ BREAKING — a certificate-authenticated device now receives a machine
  token (`aud: axiam:m2m`), not a user token.** `POST /api/v1/auth/device`
  stamped `aud: axiam:user`, so any device that authenticated by mTLS passed
  **every** user-facing route guard. It now stamps `axiam:m2m`, matching the
  client-credentials grant: a service account is the same principal however it
  authenticated, and §4.3/`SEC-006` route narrowing finally applies to both.

  **What breaks.** A device token is no longer accepted on user-facing REST
  routes. It *is* accepted on the authorization-check endpoints — `POST
  /api/v1/authz/check` and `/api/v1/authz/check/batch` — which are the
  machine-facing surface and were widened in the same change so that no
  required device call started failing. Any other endpoint a fleet calls with a
  device token must be migrated deliberately; that access was implicit rather
  than designed.

  **Before upgrading**, check whether your devices call anything beyond the
  authz-check endpoints. SDK guards fronting a resource server that accepts
  device callers must be configured to expect `axiam:m2m` (`CONTRACT.md` §10.1
  rule 6, §12.1) — a guard set to `axiam:user` will now reject device tokens,
  which is the narrowing working as intended.

  gRPC is unchanged: its interceptor accepts both audiences on all services, so
  the m2m/user split is REST-only.

### Fixed

- Supply the mandatory auth pepper to release-mode stacks
- Propagate session-revocation failures; warn on mintable rate-limit key; verify remediation evidence
- Decouple gRPC admin ceiling from authz; bound infra family; tenant-filter member_of; reorder session-cache invalidation
- SDK bench correctness/telemetry + run-5 harness prep (I9-I19)
- Correct gRPC units, scope limits per method, revise internet defaults
- **The cache-invalidation publisher no longer serialises mutations behind a
  network round-trip (§15.3.4).** The channel-slot mutex was held across the
  broker confirm, so every access-narrowing mutation in the process queued on
  one lock while the heartbeat task contended for it — a throughput cliff under
  a slow broker, and a regression against the pre-§13.4 code, which shared the
  channel with no lock at all. The lock now covers only channel acquisition. The
  failure path clears the slot **only if it still holds the same channel**, so a
  concurrent reopen is not discarded.

- **`with_previous_pepper` now carries the weak-pepper warning (§15.3.7)** that
  `from_pepper` has always emitted. Lower impact — a previous key can only
  verify existing hashes, never produce one — but an operator rotating *away*
  from a weak pepper is precisely who should be told it was weak.

- **Cache-invalidation liveness heartbeats (§13.4 observation 1).** Decision-cache
  trust followed **consumer** liveness alone. A party with broker `configure`
  rights could `queue.unbind` a replica's queue from the fanout exchange and the
  replica would notice nothing: its consumer stays subscribed to a queue nothing
  routes to, so trust stays on and it keeps serving cached allows it will never
  be told to invalidate. The publisher sees nothing either — `mandatory` is off,
  so the broker acks an unroutable message. Invalidations were silently
  suppressed, bounded only by `decision_cache_ttl_secs`.

  Each replica now publishes a **self-addressed heartbeat** every
  `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_HEARTBEAT_SECS` (default `10`) and
  watches for its own to come back — a round trip that exercises the whole loop
  (publish → exchange → binding → queue → consumer), so an unbound queue breaks
  it immediately. After three consecutive missed intervals the cache is marked
  UNTRUSTED and the replica falls back to uncached evaluation.

  The watchdog can only **revoke** trust, never grant it: trust is still granted
  in exactly one place, by the consumer on a successful subscribe, so it can
  never resurrect trust on a replica whose consumer has died. Heartbeats never
  touch the cache and never enter the replay-nonce guard. Only applies when
  cross-replica broadcast is enabled. (Superseded below: heartbeats can no
  longer be disabled, and the interval is clamped to `1..=60`.)

- **Cached authorization decisions are now invalidated on user delete/update
  (§13.4 observation 9).** `users::update` and `users::delete` did not invalidate,
  so a deleted or deactivated user's cached `Allow` survived on every replica
  until the TTL expired. Nothing on the session-authenticated request path
  re-reads user status, so the cache was the only place the stale grant could be
  cleared. Both handlers now flush the affected subject.

- **Pepper rotation is no longer an unversioned hard break (§13.4 observation 3).**
  `AXIAM__AUTH__PEPPER` keys client-secret hashing, and the `v2.hs256$` tag
  versions the *algorithm*, not the *key* — so rotating the pepper invalidated
  **every** client secret at once, and every OAuth2 client and service account
  had to be re-issued in lockstep with the restart.

  Set the new `AXIAM__AUTH__PEPPER_PREVIOUS` to the outgoing value for the
  duration of a rotation: pre-rotation hashes still verify, and each secret is
  transparently rewritten under the new pepper the first time its owner
  authenticates, so the rotation drains itself with no downtime and no
  re-issuance. Nothing is ever *written* under the previous key. **See the
  rotation procedure in `docs/deployment/README.md` before rotating.**

  A stored key id was deliberately not used instead: it would hand anyone with a
  table dump an offline oracle for testing pepper guesses, which does not exist
  today. Both keys are tried unconditionally while a rotation is configured, so
  response time does not reveal which pepper era a row is in.

- **Service-account client secrets can now migrate hash schemes (§13.4
  observation 4).** `service_account` wrote the current scheme on create/rotate
  but had no `upgrade_client_secret_hash`, so an existing row never migrated no
  matter how often it authenticated — meaning the legacy v1 verifier arm could
  not be retired on the strength of "no v1 `oauth2_client` rows remain". The
  repository now exposes the same tenant-scoped compare-and-swap upgrade the
  OAuth2 client repository has, which also carries pepper-rotation rewrites.
  (Superseded above: the seam has no production caller because nothing verifies
  a service-account secret, so these rows migrate by **rotation**, not lazily.)

- **The cache-invalidation publisher recovers its channel (§13.4 observation 2).**
  It held one channel created at startup and never replaced, while the consumer
  side was fully supervised with backoff — so a single channel-level exception
  made every access-narrowing mutation return `503` for the rest of the process
  lifetime, clearing only on restart. The channel is now opened lazily and
  reopened after any failure.

- **Cross-replica authorization decision-cache invalidation over RabbitMQ (§4.2, threat-model `T-88`).**
  The decision cache invalidated **process-locally**: on a replica that did not
  handle the mutation, a revoked grant could stay `Allow` until its entry
  TTL-expired (default 5 s). That residual was documented and accepted; it is
  now closable. Setting `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true`
  (on top of `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`) publishes every
  invalidation to the **fanout** exchange `axiam.authz.cache.invalidate`; each
  replica binds its own exclusive auto-delete queue
  `axiam.authz.cache.invalidate.<replica-uuid>` and applies what it receives,
  so a revocation reaches *all* replicas in broker-latency time. Fanout, not a
  work queue: a shared queue would deliver each invalidation to exactly one
  consumer and leave every other replica stale.

  **Default off, and inert when off.** With the switch unset, `invalidate_*` is
  local-only and infallible, no AMQP dependency is acquired by enabling the
  cache, and the previously documented TTL-bounded behaviour is unchanged.

  **Two deliberate behaviour changes when it is on**, both loud:
  - A mutation whose broadcast the broker does not confirm returns **503**
    (`"could not be broadcast to other replicas"`). The database write is
    durable but the fan-out did not happen, and reporting success would hand
    back the TTL window the operator enabled this to remove. These mutations are
    idempotent in the narrowing direction — retry is safe.
  - A replica whose invalidation consumer is not connected (startup, broker
    outage, partition) **stops serving from its cache** and evaluates every
    check against the database — correct, just slower — instead of serving
    allows it can no longer invalidate. Logged at ERROR
    (`AuthZ decision cache UNTRUSTED …`) and surfaced as `trusted` / `bypassed`
    on the periodic `AuthZ decision cache stats (D7)` line. Trust follows the
    consumer's connection liveness **only** — no inbound message can revoke it,
    so a captured broadcast cannot be used as a cache-disabling lever.

  Messages carry the existing §8 envelope (`CacheInvalidationMessage`):
  per-tenant HKDF-SHA256 subkey, `key_version >= 2` floor, per-message `nonce`,
  and an `issued_at` freshness window
  (`AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_SKEW_SECS`, default 30 s, tighter
  than the 5-minute AMQP default because an invalidation is only useful for
  about as long as the cache TTL). Nonce dedup is **per replica, in memory** —
  never the shared durable nonce store, which on a fanout would let one replica
  win and make all the others reject the invalidation as a replay. The
  publisher's own echo is a no-op, and cannot loop: a received message only ever
  reaches `DecisionCache`, never the publishing path. Granularity is exactly the
  cache's existing `invalidate_subject` / `invalidate_tenant`; no finer key is
  invented.

  Requires `AXIAM__AMQP__SIGNING_KEY` (already mandatory) to be shared by every
  replica. Documented in `docs/deployment/README.md`, `docs/admin/README.md` and
  `docs/deployment/authz-read-path.md`.

- **Client secrets are now hashed with HMAC-SHA256 keyed by the server pepper (OBS-1).**
  OAuth2 client secrets and service-account secrets were stored as an unsalted,
  single-round SHA-256 digest — safe only while every secret is 32 CSPRNG bytes with
  no operator-supplied path, an assumption held by nothing stronger than a code
  comment. The digest is now keyed, so a database dump is not offline-attackable
  without the pepper, and the guarantee no longer depends on secret entropy.
  HMAC rather than a KDF is deliberate: the client-credentials grant stays
  MAC-bound, not KDF-bound, and does not regress (verification is now
  allocation-free, where it previously allocated a `String` per request).

  **Operator action required.** `AXIAM__AUTH__PEPPER` is now **mandatory** — a
  release build fails closed at startup if it is unset, the same posture as
  `AXIAM__AUTH__SIGNING_KEY`/`AXIAM__AMQP__SIGNING_KEY` (SECHRD-08 / D-05c).
  There is no unkeyed fallback: silently degrading when unconfigured is exactly
  what OBS-1 objected to. A debug build resolves a documented dev-only pepper
  with a warning. Do not change the pepper after deployment without re-issuing
  every client secret — v2 hashes are not portable across peppers.

  Existing hashes cannot be re-derived (only the digest was stored), so the
  scheme is versioned and migrates lazily. Stored hashes are now tagged
  `v2.hs256$<hex>`; an untagged 64-hex value is verified against the legacy
  scheme and, **on a successful verification only**, rewritten in the new scheme
  with a compare-and-swap so a concurrent secret rotation is never clobbered. A
  failed verification never rehashes and never writes. No schema change and no
  backfill: migration completes as each client next authenticates.

  `axiam_db::hash_client_secret` is removed; hashing is a method on
  `axiam_auth::client_secret::ClientSecretHasher`, so no call site can hash
  without a key. `OAuth2ClientRepository` gains `upgrade_client_secret_hash`
  (breaking for out-of-tree implementors).

- **Session-revocation failures are no longer silently swallowed (OBS-3).**
  `invalidate`, `invalidate_user_sessions` and `cleanup_expired` never checked
  the DELETE result, so a statement-level database error was discarded and the
  method returned `Ok(())` — logout, password-reset revocation and MFA reset
  reported success when the statement may have failed. All five session-deleting
  methods now propagate a `DbError`. Cache invalidation is deliberately ordered
  *above* the newly-fallible step in every path, so a failing DELETE cannot
  strand a positive cache entry.

- **Startup advisory when the rate-limit bucket key is attacker-mintable (§4.1).**
  Under `AXIAM__RATE_LIMIT__KEY=client_id` the whole bucket key is read from the
  unauthenticated form body before the credential check, so a caller rotating
  `client_id` values mints fresh buckets. The shipped default (`ip`) is silent;
  `client_id` now emits a `warn!` naming the caveat and pointing at the sizing
  guide, and `ip_client_id` a softer `info!` — its unforgeable IP half confines
  the collateral to the attacker's own source.
- **gRPC admin ceiling no longer derives from the read-sized authz ceiling
  (SEC-079).** See the entry below for the units correction that made this
  necessary.

### Security

- **A client-existence oracle survived on the `authorization_code` grant
  (SEC-086, second pass).** The first pass unified every token-endpoint
  `error_description` behind one constant, but only two of the three grants
  ordered their checks safely. On `authorization_code` the client lookup ran
  *before* the secret-presence check and the grant-type check ran *before*
  secret verification, so an unauthenticated caller could still separate "no
  such client" from "client exists" — with no secret at all, and again with any
  dummy secret. Both checks now follow verification, matching
  `client_credentials` and `refresh_token`. `unauthorized_client` is now
  reachable only by a caller who has already proven possession of the secret.

- **The failed-client-auth audit row could be written into any tenant
  (SEC-087).** `/oauth2/token` is unauthenticated and takes `tenant_id` from a
  query parameter, so the audit row added in the previous change let an
  anonymous caller append rows to an arbitrary — or nonexistent — tenant's
  append-only log. The tenant is now resolved before the write; the
  caller-supplied `client_id` is truncated; and the recorded IP is the
  transport peer address, with the forgeable `X-Forwarded-For` value kept in
  metadata under a name marking it untrusted.

- **Neither half of the decision-cache staleness bound is operator-removable any
  more (§15.2).** Two gaps compounded: `decision_cache_ttl_secs` was an
  unbounded `u64` (unlike `cleanup_interval_secs`, clamped since T-04-35), and
  the cross-replica heartbeat that shortens the undelivered-invalidation window
  could be switched off with `..._HEARTBEAT_SECS=0` and only a warning. An
  operator could therefore set a multi-hour stale-allow window *and* disable the
  mechanism that detects a replica whose queue has been unbound.

  The TTL is now clamped to 300 s — in the accessor `build_decision_cache`
  calls, not in `main.rs`, so every construction path is covered. Heartbeats
  cannot be disabled while broadcast is on; out-of-range intervals clamp to
  `1..=60`. The `0` escape hatch was introduced in this same unreleased change,
  so removing it breaks nothing.

- **A replayed heartbeat can no longer satisfy the liveness watchdog (§15.2).**
  Heartbeats bypass the replay `NonceGuard` deliberately — they arrive on a
  fixed interval from every replica and would evict real invalidation nonces
  from its bounded capacity. That left a narrow path: a party with broker rights
  who captured one signed heartbeat could replay it inside the freshness window
  to keep a replica's watchdog satisfied while its queue was unbound, which is
  the exact adversary the heartbeat exists to detect. Acceptance is now bound to
  nonces the replica itself published and has not yet seen back.

## [1.0.0-alpha23] - 2026-08-02

### Added

- Rust benchmark improved release build optimizations
- Present the client certificate in the PHP SDK bench
- Wire TLS into the C# SDK bench (CA + client certificate)
- Present the client certificate in the TypeScript SDK bench
- Wire TLS into the Kotlin SDK bench (CA + client certificate)
- Present the client certificate in the Java SDK bench
- Present the client certificate in the Python SDK bench
- Present the client certificate in the Rust SDK bench
- Present the client certificate in the Go SDK bench

### Changed

- All eleven SDK benches now pass the client-cert gate
- Complete the STRIDE threat model in Threat Dragon format

### Fixed

- Make the p2-tls13 and p3-mtls SDK matrices pass
- Make the p3-mtls path actually reachable end to end

## [1.0.0-alpha22] - 2026-07-31

### Added

- Add a dry-run mode to rehearse the matrix in minutes
- Raised RAM resources in benchmarks to improve Keycloak performance (Axiam and Zitadel performs well even with 1024m)
- **OAuth2 Device Authorization Grant is reachable (RFC 8628, B2).** The
  grant's core, storage and state machine landed earlier; nothing was mounted,
  so no device could use it. Now: `POST /oauth2/device_authorization` issues
  the code pair, `POST /oauth2/token` serves
  `grant_type=urn:ietf:params:oauth:grant-type:device_code` with the full §3.5
  answer table (`authorization_pending`, `slow_down`, `expired_token`,
  `access_denied`, `invalid_grant`), and
  `GET /api/v1/device/verify` + `POST /api/v1/device/decide` back the
  verification page. The endpoint is advertised in OIDC discovery, because a
  device that can read discovery is exactly the client that cannot be told the
  URL out of band.

  The verification endpoints live under `/api/v1`, not `/oauth2`, and that is
  the design: approval records the approver as the subject the token is minted
  for (so the caller must be authenticated), and a short typed code is
  guessable from another origin (so CSRF double-submit is what stops a
  malicious page approving on a victim's session — RFC 8628 §5.4's phishing
  shape from the other direction). Unknown, expired and already-decided codes
  answer identically, so the page is not an oracle for which codes are live.

  Two new rate-limit buckets, neither sized from benchmark capacity:
  `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` (12) because the endpoint
  is unauthenticated *and* allocates state, and
  `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` (10), the user-code brute-force
  bound — `RateLimitConfig::validate` now **asserts** the OWASP condition
  against the grant lifetime, so raising it past the point where an
  8-character typed code becomes guessable fails at startup rather than in an
  incident review. See [`docs/api/device-flow.md`](docs/api/device-flow.md).

- gRPC rate limits are now scoped **per method family** instead of server-wide (I2). One
  bucket each for authz-check (`axiam.v1.AuthorizationService`), identity-read
  (`axiam.v1.UserInfoService`, `axiam.v1.TokenService`) and admin
  (`axiam.v1.UserService`), with gRPC reflection and health explicitly never limited and
  an unrecognized path failing safe into the strictest bucket. Two new knobs,
  `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` (default 5x the authz ceiling = 500/s) and
  `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` (default a flat 10/s — see the posture note under
  *Security* below); leaving `GRPC_IDENTITY_PER_SEC` unset derives it from
  `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC`, so a posture preset still moves that pair with one
  variable. Previously a `GetUserInfo` read — measured at 12 665/s — was throttled
  by the *authz* ceiling, because a single server-wide bucket made an authorization sizing
  decision into a userinfo sizing decision
- Startup advisory for mis-sized machine limits: when the shipped `internet` defaults are
  what a process is actually enforcing (no posture preset, no machine limit pinned by
  hand) and the sustained 429 ratio on the machine endpoints exceeds ~50% over a 5-minute
  interval, the server logs "your limits are throttling what looks like legitimate machine
  traffic; see rate-limit-sizing". Built on the write-behind rate-limit counter's existing
  flusher pass — no new background task, no new timer, and human endpoints are excluded
  from the ratio by construction (a 429 storm on `/auth/login` is a credential-stuffing
  signal, not a sizing signal)
- Benchmark dry-run mode (`just bench-dry-run`, `just dry=1 bench-run`) — rehearses the
  whole target × profile matrix over the same bring-up/seed/run/tear-down path in minutes,
  grading each cell on the k6 client contract (connect, request, expected response) instead
  of on performance, so a break surfaces before an hours-long matrix commits to it
- Optional **session-validation cache** (I6), `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`
  (default `0` = off). Every authenticated REST request re-reads the `session` row behind
  the access token's `jti` to enforce D-15 revocation; that read is not covered by the
  authorization decision cache, which is why turning the decision cache on lifted gRPC
  authorization checks 13.1x but REST checks only 5% in benchmark run 4 — the gRPC
  interceptor has no equivalent read. The cache stores **positive answers only**, carries
  each session's own `expires_at` (so expiry is never extended), and is invalidated by every
  session-deleting method on the repository, so on a single replica a logout still takes
  effect immediately. Multi-replica deployments inherit the same bounded-staleness caveat as
  the decision cache and should leave it off or match its TTL
- `AXIAM__SERVER__TCP_NODELAY` (default `true`, I5) — actix-web leaves `TCP_NODELAY` unset
  unless asked, so the REST listener ran with Nagle's algorithm enabled while the gRPC
  listener (tonic, which defaults it on) did not. Set `false` to restore the previous
  behaviour for A/B measurement
- Per-stage timing instrumentation on the OAuth2 client-credentials path (I5) —
  `client_lookup_us`, `secret_verify_us`, `tenant_lookup_us`, `token_mint_us`,
  `handler_total_us` on the `oauth2.client_credentials` span, plus `exchange_us`,
  `serialize_us` and `response_body_bytes` from the token endpoint, re-emitted as DEBUG
  events on `target: "axiam::perf"`. Measurement is unconditional (five `Instant::now()`
  reads, well under 0.1% of the handler) and only reporting is gated by the tracing level
- `crates/axiam-db/tests/authz_query_plan_test.rs` — `EXPLAIN`-based query-plan pins for
  the authorization hot path, so a rewrite that reintroduces a table scan fails in CI rather
  than in production. Includes witness tests proving the removed forms really did scan
- [`docs/deployment/authz-read-path.md`](docs/deployment/authz-read-path.md) — what one
  authorization check costs against SurrealDB, which cache removes which round-trip, and a
  design note on read-replica topology for authorization reads (analysis only; not
  implemented)

### Changed

- Revised the shipped `internet` machine-endpoint rate-limit defaults (I3), sized from the
  run-4 measured capacity of each endpoint: `TOKEN_PER_MIN` 20 → **120**,
  `INTROSPECT_PER_MIN` 10 → **600**, `AUTHZ_CHECK_PER_MIN` 300 → **1800**,
  `REVOKE_PER_MIN` 10 → **60**. The old numbers sat four to five orders of magnitude below
  the machine's ceiling (token 20/min against ~163 000/min of capacity) and broke the first
  healthy integration behind a NAT without protecting anything the new ones fail to
  protect; every revised value still stays 25–2 700x below measured capacity. **Human
  endpoints (login, register, password-reset, MFA) are unchanged** — they are sized against
  credential guessing, never against capacity. The `gateway`/`mesh` presets are unchanged.
  If you pinned any of these with an env var, nothing changes for you: explicit env still
  beats both the preset and the shipped default

### Fixed

- Hold a live pool reference in repositories, not a boot-time clone
- Two **full table scans on the authorization hot path** (I7). Every uncached authorization
  check — REST, gRPC and AMQP alike — walked the whole `grants` table (every role-to-permission
  grant of every tenant) and the whole `has_role` table (every role assignment of every user
  of every tenant), because both predicates were written in forms the SurrealDB planner
  cannot serve from an index: `WHERE meta::id(in) IN $role_ids` wraps the indexed field in a
  function call, and `WHERE in IN (SELECT VALUE out FROM member_of WHERE ...)` leaves a
  correlated sub-select on the right-hand side. `EXPLAIN` reported
  `TableScan { pre_decode_filter: "no (unsupported predicate)" }` for both. They now compare
  against bound record ids and a pre-resolved `LET` binding respectively and plan as
  `IndexScan` over the existing `idx_grants_unique` / `idx_has_role_unique` composite indexes
  — no schema change, identical rows returned. The cost was invisible on a small seed and
  grew with total database size, which is consistent with SurrealDB showing up as the
  product's throughput ceiling in benchmark run 4
- gRPC rate limits were enforced at **1/60th of the configured rate** (I1). The gRPC
  ceiling is per second, but the cross-replica shared pre-check runs the same fixed
  60-second window as the REST limiter and was handed the per-second number verbatim; since
  the stricter of the two cooperating layers wins, `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC=100`
  admitted ~100 requests per *minute*. The per-second → per-window conversion now happens
  once, at the layer boundary, with a saturating multiply, and the production constructor
  takes per-second ceilings so a caller cannot get the units wrong again. Found by benchmark
  run 4's production-posture pass. **Read the gRPC admin-ceiling entry under *Security*
  below before upgrading** — correcting these units raised every gRPC ceiling 60x, which is
  a posture change and not only a units fix
- Stale DB handles after a reconnect: every repository was built at boot from a one-time
  `pool.handle_for_repo()` **clone** of the pooled SurrealDB connection, so when the pool's
  reconnect loop evicted a poisoned connection (observed ~7 minutes into a sustained load
  run) every repository stayed pinned to the dead one and returned 401 permanently until
  the process restarted — while `/ready`, which probes through the pool slot, still
  reported healthy. Repositories now hold a live `DbHandle` over the pool slot and resolve
  the current connection per query, so a swap is picked up on the very next query. The REST
  `AppState.db` (bootstrap handler, tenant seeder) and the gRPC layer's handle held the same
  boot-time clone and were fixed the same way
- `meta.json` could be written as invalid JSON when a host fact spanned two lines — a
  `docker version` against an unreachable daemon prints an empty line and *then* fails, so
  the `|| echo unknown` fallback produced a literal newline mid-string and took `report.py`
  down with an "Invalid control character" for the whole run

### Security

- **gRPC admin/credential-check ceiling is now an absolute 10/s (600/min per IP), not the
  authz ceiling (SEC-079). This is a posture change — read it even if you skipped the
  units fix above.** Correcting the gRPC rate-limit units (I1, under *Fixed*) changed what
  every gRPC ceiling actually enforces from `N` per **minute** to `N` per **second**. The
  units bug had been accidentally supplying 60x more protection than the configuration
  said, so an operator who reads only "corrected gRPC units" will not realise their
  deployed gRPC ceiling rose 60x on upgrade. That matters most on
  `axiam.v1.UserService/ValidateCredentials`, which performs a real Argon2id password
  verification (~19 MiB of memory arena each): its per-IP ceiling would have gone from
  ~100/min to ~6 000/min — a 60x increase in online password-guessing throughput and in the
  Argon2id CPU a caller can conscript. The admin family therefore no longer derives from
  `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` at all; it takes a CPU-appropriate absolute default of
  10/s, unchanged by `AXIAM__RATE_LIMIT__PROFILE`, so raising the authz ceiling for
  service-mesh capacity can no longer widen credential guessing as a side effect. The
  family holds only `GetUser` and `ValidateCredentials`; the high-volume identity read is
  `GetUserInfo` on `UserInfoService`, which is in the identity-read family and unaffected.
  **Action:** if a provisioning or admin workload legitimately exceeds 600 `UserService`
  calls per minute from one source IP, pin `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` — explicit
  configuration still wins over both the default and any posture preset. Per-account
  lockout, the shared failure metering and the process-wide crypto semaphore are unchanged
- gRPC reflection and health are no longer an **unlimited pass-through**. The family is
  selected by prefix-matching the client-supplied gRPC `:path` (`/grpc.reflection.`,
  `/grpc.health.`) and used to bypass both limiter layers entirely. Neither service is
  registered today — requests terminate `Unimplemented`, so the practical effect was
  unmetered HTTP/2 stream churn rather than database work — but registering a health
  service would have made it a genuinely unmetered endpoint. It now has its own bucket at a
  fixed 100/s per IP: orders of magnitude above any real probe cadence, so a liveness probe
  still answers during an incident when every other family is saturated, while the surface
  stops being unbounded
- Group-membership traversal on the authorization read path now carries a read-time tenant
  predicate. `get_user_role_assignments` resolved `member_of` edges with no
  `out.tenant_id` filter; this was not exploitable — group membership is validated against
  the tenant at write time and the outer `has_role` predicate still confined the resulting
  role — but it left group-inherited roles as the one authorization edge with no read-time
  tenant check, so a migration or bulk import writing `member_of` directly would have
  bypassed it. The predicate is served by the existing `idx_member_of_unique` index; the
  query-plan pins confirm the plan is still an `IndexScan`
- Session-cache invalidation now runs immediately after the `DELETE` commits, before the
  deleted rows are deserialized, in `consume` and `invalidate_user_sessions_except`. The
  `DELETE` has already succeeded at the database once the await returns, so a deserialize
  failure of the returned BEFORE image used to return early and leave a **positive**
  session-validation cache entry live for up to the TTL — a deleted session that kept
  validating. Only reachable with the opt-in
  `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` enabled
- **Session revocation no longer reports success when the `DELETE` failed (OBS-3).**
  `SessionRepository::invalidate`, `invalidate_user_sessions` and `cleanup_expired` awaited
  their `DELETE` and returned `Ok(())` without ever calling `.check()` or `.take()`, so a
  statement-level SurrealDB failure was discarded — logout, password-reset session
  revocation and MFA reset all told the caller sessions were revoked when the statement may
  never have run. All five session-deleting methods now `.check()` the response and
  propagate a `DbError`, which surfaces as `500` at `POST /api/v1/auth/logout` and the GDPR
  disable path rather than as a silent `204`. Cache invalidation deliberately still runs
  **before** the new fallible step, so the ordering fix above cannot be reintroduced: an
  erroring `DELETE` drops the cache entry (costing at most one avoidable re-read) instead of
  stranding a positive "still valid" entry
- Startup **warning** when `AXIAM__RATE_LIMIT__KEY=client_id` is active. In that mode the
  rate-limit bucket key for `/oauth2/{token,introspect,revoke}` is the `client_id` read from
  the unauthenticated form body (RFC 6749 §2.3.1) **before** any credential check, so a
  caller rotating `client_id` values mints a fresh bucket per value; under this mode those
  limits are a fairness control between cooperating clients, not an anti-abuse control, and
  the mode assumes an edge (mTLS / API gateway / WAF) that already authenticates callers.
  The warning names that and points at `docs/deployment/rate-limit-sizing.md` §5. The
  shipped default (`ip`) is not attacker-mintable and stays **silent**; the partially
  mintable `ip_client_id` gets a softer `info!` note, because its source-IP half still
  prevents a third party from exhausting a known `client_id`'s bucket from elsewhere. No
  behaviour or limit changes — advisory only, matching the I3 machine-traffic advisory and
  the session-validation cache's startup `warn!`
- CI now verifies that **remediation evidence actually shipped**
  (`scripts/check-remediation-evidence.py`, wired into `docs-ci.yml`). A remediation record
  citing a commit hash is not evidence a fix merged — a hash exists the moment a commit is
  authored, on any branch, and the 2026-08-03 review pass caught a real instance (a Swift
  fix recorded as remediated while still unmerged). Every `(finding id, repo, commit)`
  triple in a remediation table of `claude_dev/security-analysis-*.md` must now resolve to a
  commit reachable from the default branch of the repo it claims: locally via
  `git merge-base --is-ancestor`, and for the out-of-tree SDK repos via the GitHub API when
  the token can read them. Rows that cannot be verified are printed as **SKIPPED by name**
  rather than passing silently, and a row that cannot be parsed into a triple **fails** the
  check naming the row

## [1.0.0-alpha21] - 2026-07-30

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha20.

## [1.0.0-alpha20] - 2026-07-30

### Added

- Opt-in rate-limit posture presets + TLS/h2 tuning surface (G7, G8 in progress)
- G9 — throttle-aware metrics and the gRPC/REST authz analysis
- G2 harness countermeasures, G4 refresh fix, G5 cache-sweep scenario
- Per-task data-collection script for the pre-MVP plan
- Run-3 benchmark page refresh + benchmark-derived sizing docs

### Changed

- Add the run-4 execution runbook
- Bump the version marker to 1.6 and record the follow-up audit findings
- Add §9 rule 6 — single-flight guard implementation invariants (contract 1.6)
- Bump frontend/coverage/website-publish Node from 20 to 22
- Bump jsonwebtoken from 10.4.0 to 11.0.0
- Bump jsdom from 29.1.1 to 30.0.1 in /frontend
- Use the obviously-fake password fixture convention in the users split test
- Verify the write-behind clamp fix on a local rl-fix-local build
- Document the write-behind shared counter and its security bound
- Note why REST and gRPC each hold their own shared counter
- Adapt the shared-store middleware suite to write-behind counting
- Serve shared rate-limit decisions from the write-behind counter
- Add write-behind SharedRateLimitCounter + increment_by
- Mark the bench admin default in h5-revocation-check.sh as a throwaway fixture
- H10(5): finalize §6 execution record with the validated H10 outcome
- H10(4): report.py — settle_timeout refusal is now scenario-aware, not session-wide
- H10(3): consistency pass — methodology.md §12 + append §6 execution record
- H10(2): E4 — fourth public benchmark draft
- H10(1): consistency pass — reconcile PRIVATE_BENCH_ANALYSIS.md with H2/H3/H4/H5/H9 verdicts
- H8(5): profile-scope SDK result storage, README truthful status table, per-language TODO notes
- H8(4): wire BENCH_CA_CERT into 5 SDK benches for p2, integrate E1.3 overhead table into report.py
- H8(3): fix refresh-op concurrency in python/typescript benches (HARNESS-SPEC required conc=1, neither implemented it)
- H8(2): fix server CSRF header-echo + go bench org_slug — both blocked every SDK bench end-to-end
- H8(1): per-language SDK bench fixes — rust seed env, python venv, ts npm link, go.sum, java compile, csharp preflight, php minimum-stability
- H7(1): confirm the REST/gRPC classifier wiring live; correct the stale G9 note
- H7(3b,4): measure the gateway rate-limit preset live; close the Keycloak p0-vs-p2 login asymmetry
- H7(1,3a,5): protocol-variant label, maintainer sign-off block, H4 control-build fix
- H6(7): measure the CC clamp control instead of asserting it, and price the noise
- H6(6): publish the B2 position — TLS priced, HTTP/2 acquitted, CC still open
- H6(5): close B2 in the private analysis
- H6(4): document bench_http_proto in the methodology metric list
- H6(3): the h2 hypothesis is refuted by counting connections
- H6(2): h6-tls-proto task + a connection/worker-affinity probe
- H6(1): capture the negotiated HTTP protocol, and make the h1 control honest
- H5(4,5): decision-cache verdict — default STAYS opt-in, flip blocked on C1/C2/C4
- H5(3): automate the live-stack revocation check; run the K-sweep under TLS
- H5(1): fix the three decision-cache defects surfaced by the G5 review
- H9: DB-pool default decision — keep pool_size=1, close negative
- H2: G1 endgame — the "post-seed transient" is the shared rate-limit write
- H1: drain pause after settle gate to prevent straggler-traffic contamination
- H4: jemalloc as the release-container default allocator (executes G6 PASS)
- H1.5: report.py refuses cells whose meta records settle_timeout:true
- H1.2: fix bench-matrix results-dir clobber + fail-fast task-script guard
- H1.1: settle gate v2 — concurrent burst probe replaces serial canary
- H3: flip authz batch strategy default to coalesced (G3 decision)
- Phase H plan from the verified 2026-07-28 G-task results
- Use UUIDv7 for persisted record identifiers
- Amend CONTRACT to 1.5 from the cross-SDK §12 conformance review
- Add CONTRACT §12 OIDC/SSO relying-party helpers (contract 1.4)
- Add SDK OIDC/SSO relying-party helpers implementation plan
- Correct the published client_id rate-limit guidance with its security caveat
- G7 rate-limit posture decision record
- G8 security-profiles update + implementation status for the pre-MVP plan
- G8 — B2 HTTP/2 investigation and the ALPN knob fix
- Bump base64 from 0.22.1 to 0.23.0
- Bump the minor-patch group in /frontend with 12 updates
- Bump actions/download-artifact from 4.3.0 to 8.0.1
- Bump taiki-e/install-action from 2.83.2 to 2.85.2
- Bump bufbuild/buf-action from 1.4.0 to 1.5.0
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump docker/login-action from 3.4.0 to 4.5.1
- Use UUIDv7 for persisted record identifiers
- Amend CONTRACT to 1.5 from the cross-SDK §12 conformance review
- Add CONTRACT §12 OIDC/SSO relying-party helpers (contract 1.4)
- Add SDK OIDC/SSO relying-party helpers implementation plan
- Run-3 analysis, D9 experiment script, pre-MVP improvement plan

### Fixed

- Select jsonwebtoken 11's rust_crypto backend explicitly
- Stop charging GET /api/v1/users to the users_create limiter
- Make g1-dbdirect's direct SurrealDB probe actually run
- Resolve g1-dbdirect's DB credentials from the running stack
- Interrupt-safe teardown for every task that holds a stack
- Unwedge the G1 tasks' telemetry sampler
- Dial gRPC over TLS in p3-mtls; record real gRPC status
- Resolve p3-mtls client cert path from any CWD

## [1.0.0-alpha19] - 2026-07-25

### Fixed

- Migrate react-router-dom v7 -> react-router v8 (GHSA-qwww-vcr4-c8h2)

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Workspace coverage improvements toward >=90% (T2-T6), scanner-clean
- Plan to push Coveralls badge over 90% with per-task model picks
- Ratchet line-coverage floor 77 -> 80 and surface achieved total
- Runtime-generate the new-password arg in confirm_reset test
- Close residual gaps in password_reset and pgp
- Satisfy rustfmt, clippy, and CodeQL on the new coverage tests
- Exclude axiam-server binary composition root from coverage
- Cover SAML/OIDC non-xmlsec logic and negative paths
- Broker-free seams for authz/audit consumers + fix auth rand_core
- Cover residual repository CRUD/error paths + seeder + nonce-replay
- Cover cleanup.rs expiry sweeps and erasure pipeline branches
- Cover federation/auth/webhook/password-reset/rbac error paths
- Round-2 test-coverage plan for server + C SDK with per-task model picks
- Bump docker/build-push-action from 6.15.0 to 7.3.0 (#213)
- Bump @testing-library/jest-dom in /frontend (#216)
- Bump actions/setup-node from 6.4.0 to 7.0.0 (#214)
- Bump dtolnay/rust-toolchain (#212)
- Test-coverage improvement plan for server + 11 SDKs (2026-07-23 baseline) (#227)
- Bump the minor-patch group in /frontend with 8 updates (#215)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#211)
- Bump actions/attest-build-provenance from 2.4.0 to 4.1.1 (#210)
- Correct model attribution and add phase dates to roadmap (#226)
- Rewrite laptop runbook for run 3 against released 1.0.0-alpha17

## [1.0.0-alpha17] - 2026-07-22

### Changed

- Updated dependencies for security fixes

## [1.0.0-alpha16] - 2026-07-22

### Added

- Add AXIAM gRPC userinfo scenario + protocol-efficiency pairing
- Implement UserInfoService and integration tests
- Add gRPC UserInfoService/GetUserInfo (contract 1.3)
- Add missing SDKs, gRPC + config docs, real benchmark data
- Implement run-2 follow-up tasks (A8, A9, D10, D11, report polish)

### Changed

- Use a random seeded-user password in userinfo tests
- Add gRPC userinfo implementation plan
- Run-2 analysis (1.0.0-alpha15) — update public/private bench docs + plan

### Fixed

- Make concurrent batch future boxable behind AuthzChecker trait

## [1.0.0-alpha15] - 2026-07-21

### Added

- F2 — DbPool of N independent handles, wire repositories, close CQ-B48
- F1 — connection-pool design doc + boundary instrumentation
- D7 — decision caching behind a flag (default off) with revocation invalidation
- D8 — configurable rate-limiter key (ip|client_id|ip_client_id)
- D3 — native mTLS (client-certificate) auth
- B1 — bound concurrent Argon2id hashing (perf + memory-DoS fix)
- AXIAM native (in-process) TLS for the p2-tls13 profile
- TLS profiles for keycloak + zitadel; RSA certs; port pre-flight
- Auto-provision Zitadel client via management API

### Changed

- Regression test for gRPC-over-TLS crypto provider
- Fix stale F1/F2 status rows (still showed "planned" post-merge)
- Mark E1.2 done (four stub SDK benches wired)
- Wire the four stub SDK benches (c, cpp, kotlin, swift)
- Cargo fmt F2 (DbPool)
- Cargo fmt F1 instrumentation wiring
- Laptop re-run runbook + Phase F (DB connection pooling)
- Cargo fmt (rustfmt CI fix)
- Per-task implementation status table
- D9 — optional jemalloc allocator for RSS-retention experiment
- Drive gRPC over TLS at p2 (native gRPC TLS wiring)
- B3 — JWKS in-process cache + HTTP caching headers (ETag/304)
- D1 — coalesce same-subject authz batches + tracing
- B2 — TLS 1.3 throughput diagnosis + fixes on token endpoints
- Zitadel gRPC benchmark coverage
- AMQP async-authz load harness design
- Real Zitadel login via session API v2 (password verification)
- SurrealDB tuning investigation — preliminary static analysis
- Re-run protocol — median-of-N, DB tuning, laptop runbook, prod posture
- Harness correctness & honesty (A1–A7)
- Expand plan E1 — implement & validate the SDK client benches
- Benchmark improvement implementation plan; refine throttling assessment
- Add public + private analysis of the first full benchmark run
- Re-enabled pepper and moved compose to latest AXIAM image version

### Fixed

- Make Keycloak and Zitadel seed users loginable
- Install ring rustls CryptoProvider so gRPC-over-TLS works
- Serialize F1 gauge tests against shared-static race (flaky CI)
- Give the E2E backend-startup step real timeout margin
- Correct actix test app-factory return type (D8 integration test)
- Fill new config fields in remaining test literals
- Clippy collapsible-if, grpc test field, OpenAPI drift
- Gate bench-up on target HTTP readiness

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Require organization context for login/refresh (#204)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Added

- Add --changelog to summarize commits into CHANGELOG.md

### Changed

- Wire org context into the TypeScript bench; list all 11 SDKs in README (#199)

### Fixed

- Wire Keycloak TLS via entrypoint; stop passing empty KC_HTTPS_*
- Correct image labeling metadata for GHCR
- Drop --optimized from Keycloak first start
- Dial gRPC plaintext regardless of HTTP TLS profile
- Merge tlsOptions() into gRPC scenarios so cert-skip applies
- Skip k6 server-cert verify for private-CA TLS profiles
- Neutralize rate limits so p0 measures endpoint capacity
- Apply the configured password pepper when hashing the admin (#200)
- Don't set AXIAM__AUTH__PEPPER (breaks bootstrap-admin login)
- Write resource CSV rows; configure OAuth2/optional secrets; skip OAuth2 when unset
- Supply org context on login; make bench-down work without secrets
- Provide mandatory AMQP signing key for the AXIAM target
- Bootstrap AXIAM secrets in bench-up; auto-track image tag
- Correct just variable-override ordering so bench-matrix works

## [1.0.0-alpha3] - 2026-07-16

Third alpha. Build/release tuning and project-infrastructure changes only. No
server runtime or API behavior changes — the OpenAPI specification is
byte-for-byte identical apart from its `info.version` string.

### Added

- **Public marketing & documentation website**, deployed to GitHub Pages.

### Changed

- **Release build profile** — added `[profile.release]` to the workspace-root
  `Cargo.toml`, tuned for execution speed first and footprint second:
  `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`.
  Cargo only honors profiles at the workspace root, so this single section
  covers `axiam-server` and every crate it links. `panic = "abort"` is
  intentionally omitted to preserve per-request panic isolation on the
  long-running REST/gRPC/AMQP server. Release builds are slower in exchange for
  faster runtime.

## [1.0.0-alpha2] - 2026-07-16

Second alpha. Adds the SDK declarative-authorization contract and release-prep
polish; no server runtime/API behavior changes.

### Added

- **CONTRACT.md §11 — Declarative Authorization Helpers**: the canonical
  `require_auth` / `require_access(action, resource[, scope])` / `require_role`
  vocabulary layered on the §10 guard, with the per-language naming map and
  normative semantics (subject propagation, 401/403/400/503 error mapping,
  fail-closed on transport error, no decision caching). Marked SHOULD-level and
  recorded as non-breaking/additive; contract version bumped to 1.1.
- README build/coverage/license badges.

### Changed

- Roadmap "Development Progress": Phase 17 (SDKs) and Phase 18 (security audit)
  marked Done.

### Fixed / CI

- Added a free-disk-space step to the heavy Rust `test` and `cargo-llvm-cov`
  jobs to prevent the RabbitMQ disk-space alarm that intermittently failed CI.

## [1.0.0-alpha1] - 2026-07-16

Patch release over `1.0.0-alpha` that fixes the release pipeline so the
aarch64 server binary and the OpenAPI drift gate build cleanly. There are no
functional or API changes — the OpenAPI specification is byte-for-byte
identical apart from its `info.version` string.

### Fixed

- **aarch64 release build** — the *Build Release Binary (aarch64)* job failed
  at "Install build dependencies" because the native `ubuntu-24.04-arm` runner
  intermittently could not reach `ports.ubuntu.com` (IPv6 unreachable, IPv4
  timeouts). The apt step now forces IPv4, prefers Azure's in-network ports
  mirror, and retries with backoff, without changing the installed package set.
- **OpenAPI version drift** — the REST spec's `info.version` was a hardcoded
  literal that fell out of sync with the crate version and failed the OpenAPI
  drift gate. It is now bound to `CARGO_PKG_VERSION`, so it always tracks the
  workspace version and cannot drift on a future version bump.

[1.0.0-alpha1]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha1

## [1.0.0-alpha] - 2026-07-15

First alpha release of AXIAM (Access eXtended Identity and Authorization
Management). This is an early, pre-production preview intended for evaluation
and feedback — APIs and data models may still change before the beta and
stable releases.

### Added

- **Multi-tenancy** — organizations as top-level entities containing fully
  data-isolated tenants; all domain entities (users, groups, roles,
  permissions, resources, certificates) are tenant-scoped.
- **Authentication** — username/password (Argon2id), MFA (TOTP), social login
  and certificate-based (mTLS) authentication; EdDSA (Ed25519) JWT access
  tokens with opaque, single-use, rotating refresh tokens.
- **Authorization** — additive, default-deny RBAC engine with role
  inheritance through hierarchical resources, scopes for sub-resource
  granularity, and group-inherited role assignments.
- **OAuth2 / OpenID Connect** — authorization server and OIDC provider
  (Authorization Code + PKCE, Client Credentials, Refresh Token).
- **Federation** — SAML SP and OpenID Connect federation for cross-domain SSO.
- **APIs** — REST (Actix-Web, OpenAPI-documented), gRPC (Tonic) for
  low-latency authz checks, and AMQP (Lapin) for async/deferred authz, audit
  ingestion and event notifications.
- **PKI** — per-tenant X.509 certificate management signed by an organization
  CA, with CA private keys encrypted at rest (AES-256-GCM); GnuPG/OpenPGP
  integration for audit signing and encrypted data exports.
- **Auditing** — append-only audit logging.
- **Webhooks** — real-time event notifications to external systems, signed
  with HMAC-SHA256.
- **Admin frontend** — React + TypeScript administration UI.
- **Packaging & deployment** — multi-arch (amd64/arm64) container images and
  standalone server binaries, Docker Compose and Kubernetes manifests.
- **Client SDKs** — Rust, TypeScript, Python, Java, C#, PHP and Go SDKs, each
  released in its own repository against the shared API contract.

[1.0.0-alpha]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha
