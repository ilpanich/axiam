# Security review — Phase 23, wave W6 (W6a) (F4)

**Date:** 2026-10-06.
**Against:** `claude/phase23-w6`, the whole wave diff `406a155..ed6cbaa` (12
commits, 65 files, about 8 300 lines added and 630 removed; `406a155` is the W5
merge on `main`). No workspace Rust, contract, OpenAPI, frontend or docker file
changed in the wave. The fixes of this review sit on top: `550fe00`
(P23W6-01), `f387ce2` (P23W6-02), `31106cb` (P23W6-03), `c83593a` (the threat
model, 2.36.1: T-469, P23W6-04, P23W6-05) with `00e7a57` (a template-literal
escape it needed), `37a3046` (the runbook and D-74: P23W6-06, P23W6-07),
`6fc3be0` (P23W6-08), and the documentation commit that carries this file.
**Scope:** every W6a task of
[`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md):
G-10's T23.10.1 (the authentik target) and T23.10.2(a) (the run-6 runbook, the
per-stack generated credentials, the minimal-profile overlay, `rl=prod` pinning,
pinned images, provenance, four new CI self-tests), G-11's T23.11.1 (the RADIUS
/ EAP-TLS spike and its threat entries, model 2.36.0: T-448 … T-468 *Not
applicable*, T-102 reopened, the generator's new status), the comparison
refresh (three comparisons, the website's *Integrate* and *Operate* pages) and
D-75 … D-79. W6b (T23.10.2(b), the run-6 report) is not here; it has no code.
**Method:** adversarial reading of the diff and of every path it implies, the
harness traced as a credential handler and as a CI surface, against
[`threat-model-stride.md`](threat-model-stride.md) and `Axiam.json`, the W5
review's §15 (binding on this wave), and the OWASP ASVS 5.0 areas the diff
touches (V2 business logic, V6 authentication, V9 self-contained tokens and
certificates, V13 configuration, V14 data protection, V16 logging). D-75 … D-79
were read verbatim. Every finding fixed here has a self-test or check that
failed before the fix, run and recorded (§13); one that cannot have one says so.
Every claim about the code that the comparisons and the website make in this
wave was traced to the code (§10).

---

## 0. Summary

Eight findings were fixed on the branch. Four are the harness's, all
wave-introduced: the generated broker password reached every full-profile
AXIAM cell's `meta.json`, and from there the `bench-pack` archive, inside
`AXIAM__AMQP__URL`, a key no redaction rule matched (**P23W6-01**, Low); the
`rl=prod` pin that T23.10.2(a) added to pin seven families from the Rust source
fails **open** when the source moves, because `eval "$(…)"` discards the
script's exit status (**P23W6-02**, Low); the seed env, which now carries the
generated admin passwords, was written under the caller's umask and made 600
afterwards (**P23W6-03**, Low); and the AMQP transport check, which CI runs on
every PR, failed on the minimal overlay's `!reset null`, so W6a's PR would have
been red (**P23W6-08**, Low). Two are the threat model's: T-102's 2.36.0 text
said revocation takes effect wherever AXIAM terminates the connection, but only
device sign-in by certificate reads a certificate's status, and AXIAM's own
OAuth2 `tls_client_auth` keeps accepting a revoked AXIAM-issued leaf
(**P23W6-04**, Low, text; the gap is P23W6-10); and the "own request path"
paragraph said three open items in the write-up and two on the website, "and
none is a defect" — it is seven, and three are not trade-offs (**P23W6-05**,
Informational). P23W6-06 and P23W6-07 are fixed in the text they concern (the
runbook; D-74) and reported for the rest.

Six are reported with issue bodies (§14), all pre-existing. The one the spike
handed over is real and slightly worse than described: **a locked account is
refused before any password verification** (**P23W6-09**, Medium, new
**T-469**, Open) — faster than an unknown name in every regime, and under
hash-permit saturation `401` where every verifying branch answers `503`, which a
timing-free test shows; gRPC `ValidateCredentials` runs no verify on any refusal.
**No CRL is published, and AXIAM's own `tls_client_auth` reads no certificate
status** (P23W6-10, Medium, T-102). The benchmark targets publish on every
interface with AXIAM's limiters off (P23W6-06, Low); an unvouched account cannot
approve a CIBA request at all, because nothing lists one (P23W6-07, Low, D-74
amended); `rl-prod-check` has no row for eight limiter families (P23W6-11, Low);
two hygiene items (P23W6-12, Informational).

**The harness held where it mattered.** No credential literal remains in any
compose file, script, scenario or SDK bench, and the self-tests catch the eight
mutations run against them (§3); the CI masking is right; the FAPI conformance
workflow's `BENCH_ADMIN_PASSWORD` wins over the generated one through both of
its `bench-up`s (traced, §3); authentik's compose and seed carry no literal and
its bootstrap token never reaches a results file. The runbook carries W5 F4
§15's three rules verbatim in substance (§5). D-78's *Not applicable* rule is
sound, and the generator's change hides no open entry (§6).

| ID | Finding | Severity | Surface / threat | Origin | Disposition |
|---|---|---|---|---|---|
| **P23W6-01** | `meta.json`'s `axiam_env` redacts by key name; `AXIAM__AMQP__URL` carries the generated broker password in its userinfo, so it was written in clear into every full-profile AXIAM cell and the `bench-pack` archive, whose `SECRET`/`PASSWORD` scan cannot see a hex string. | Low | `run-benchmark.sh`, `bench-pack` | wave | **Fixed** — `550fe00` |
| **P23W6-02** | `eval "$(python3 runner/rl_prod_check.py --print-exports)"`: the script raises when the source moves, but the status is lost, so `bench-up` continues with seven families neutralized under an `rl=prod` label. | Low | justfile `rl=prod` | wave | **Fixed** — `f387ce2` |
| **P23W6-03** | The seed env (now holding the bootstrap admin's and Keycloak's admin passwords) is written under the caller's umask, then `chmod 600`; the stack file keeps a pre-existing empty file's mode; `.seed/` is 0755. | Low | `seed.sh`, `bench-creds.sh` | wave | **Fixed** — `31106cb` |
| **P23W6-04** | T-102 (2.36.0), the design document and the website said revocation takes effect wherever AXIAM terminates the connection; neither listener's handshake reads it, nor OAuth2 `tls_client_auth`. | Low | threat text → **T-102** | wave (text) | **Fixed** — `c83593a` (gap: P23W6-10) |
| **P23W6-05** | "AXIAM's own request path … carries **three** open items" (write-up) / "**two**" (website), "and none is a defect": seven, three of them not trade-offs (T-447, T-102, T-469). | Informational | write-up, `security.ts` | pre-existing | **Fixed** — `c83593a` |
| **P23W6-06** | Every benchmark target publishes its application, TLS and (AXIAM) gRPC ports on every interface, with AXIAM's limiters and lockout raised to 1 000 000; authentik's new target copies the shape. | Low | `targets/*/docker-compose.yml` | pre-existing | **Runbook fixed** (`37a3046`); compose **reported** (§14) |
| **P23W6-07** | Under D-74 an unvouched account (every federated account without a verified address) gets no mail, and the console has no list of pending requests, so the request cannot be reached and expires; D-74 said it "waits on the approval page". | Low | CIBA approval surface; D-74 | pre-existing (W5) | **D-74 amended** (`37a3046`); **reported** (§14) |
| **P23W6-08** | `check-amqp-transport.py` (CI, every PR) read the minimal overlay's `AXIAM__AMQP__URL: !reset null` as the string `'null'` and failed. | Low | CI | wave | **Fixed** — `6fc3be0` |
| **P23W6-09** | `AuthService::login` refuses a locked account before any hash permit or verify: faster than an unknown name, and `401` against `503` under saturation. gRPC `ValidateCredentials` runs no verify on any refusal. | Medium | login → **T-469** (new, Open) | pre-existing | **Reported** (§14) |
| **P23W6-10** | No CRL or OCSP (T-102); and AXIAM's own `tls_client_auth` matches a registered DN/SAN without reading the certificate's status, so a revoked AXIAM-issued leaf keeps authenticating its OAuth2 client. | Medium | PKI, token endpoint → **T-102** | pre-existing | **Reported** (§14) |
| **P23W6-11** | `rl-prod-check` has no row for `bc_authorize`, `ciba_approval`, `device_login`, `ssf`, `ssf_admin`, `saml_admin`, `directory_admin`, `scim_target_admin`. | Low | `rl_prod_check.py` | pre-existing | **Reported** (§14) |
| **P23W6-12** | (a) The minimal compose files' 30 s `stop_grace_period` is less than actix's default 30 s graceful shutdown plus the 5 s audit drain; (b) `bench-up`'s `genhex` writes `docker/.secrets/*.hex` then `chmod 600`. | Informational | minimal profile; harness | pre-existing | **Reported** (§14) |

**Verdict on merge.** Nothing open blocks W6a. The eight fixes are in — the four
in the harness and CI each with a self-test or check that failed before it, the
four in text checked against the code (§7, §9); the threat model is at **2.36.1 — 469
threats, 425 mitigated / 23 open / 21 not applicable** — in the three artifacts
and the website, and a second generator run leaves no diff. No decision is
proposed: D-74 is amended (its consequence was wrong, the decision stands). Six
issue bodies go to the maintainer (§14), none filed here.

---

## 1. What was reviewed, and how

| Surface | Task | Files | Depth |
|---|---|---|---|
| Per-stack credentials | T23.10.2(a) | `runner/bench-creds.sh`, the justfile's `bench-up`/`bench-down`/`bench-logs`/`bench-pack`/`bench-quick`, `runner/seed.sh`, the probes | **read in full**; traced through `fapi-conformance.yml` (§3) |
| What reaches a results file | T23.10.2(a) | `run-benchmark.sh` (`axiam_env_json`, `containers_json`, `meta.json`), `record-provenance.sh`, `resting-sample.sh`, `pull-pinned-images.sh`, `report.py`, k6 `--summary-export` | **read in full** (env, provenance); stub-docker run (P23W6-01) |
| The four target compose files and the minimal overlay | T23.10.1, T23.10.2(a) | `targets/{axiam,keycloak,zitadel,authentik}/docker-compose*.yml` | **read in full**: credentials, ports, the overlay's `!reset`/`!override` |
| authentik target | T23.10.1 | compose, `seed_authentik`, `smoke_authentik`, `scenarios/lib/{targets,metrics,config}.js` | **read in full** (seed, compose); targeted (adapter) |
| CI surface | T23.10.1, T23.10.2(a) | `.github/workflows/ci.yml` (four new steps), the self-tests they run | **every step run**; mutations (§3) |
| `rl=prod` pinning | T23.10.2(a) | `rl_prod_check.py --print-exports`, the justfile branch, `rl-prod-posture-selftest.sh` | **read in full**; fault-injected (P23W6-02) |
| The run-6 runbook | T23.10.2(a) | `claude_dev/run6-runbook.md` | **read** against W5 F4 §15 (§5) |
| RADIUS spike, threat entries, generator | T23.11.1 | the record, `Axiam.json` (2.36.0), `gen-threat-model.mjs`, `ThreatModelExplorer.tsx`, `threatModelTypes.ts` | **read in full** (entries, generator); every `NotApplicable` enumerated by script (§6) |
| T-102 reopening, the login timing | T23.11.1 hand-over | `axiam-pki/src/mtls.rs`, `axiam-oauth2/src/mtls.rs`, `axiam-server/src/tls.rs`, `axiam-auth/src/service.rs`, `service/directory.rs`, `axiam-api-grpc/src/services/user.rs` | **read** at every early return; a timing-free test run (§8) |
| Comparisons and website claims | refresh | three comparisons, `website/src/docs/{integrate,operate}.ts`, `security.ts` | every security-relevant claim traced (§10) |

Not run: a real stack (`docker` exists in the sandbox, but the AXIAM beta18
image does not exist yet and `ghcr.io` blobs are blocked; T23.10.1 and
T23.10.2(a) smoke-tested authentik and Keycloak 26.8.0 there), the FAPI
conformance workflow (it cannot be dispatched from here; traced instead).

---

## 2. P23W6-01 — the broker password in `meta.json` and the pack

**Severity: Low. Fixed in `550fe00`.**

`axiam_env_json()` copies the AXIAM server container's `AXIAM__*` environment
into every cell's `meta.json` and writes `<redacted>` for a key matching
`PASSWORD|SECRET|KEY|PEPPER|PEM|TOKEN`. `targets/axiam/docker-compose.yml`
sets `AXIAM__AMQP__URL: "amqps://${RABBITMQ_DEFAULT_USER}:${RABBITMQ_DEFAULT_PASS}@rabbitmq:5671"`.
The key matches no rule, so the value — with the broker password T23.10.2(a)
now generates per stack — went into every full-profile AXIAM cell, and
`bench-pack` archived it: its leak scan looks for the words `SECRET` and
`PASSWORD`, and a hex string contains neither. A stub docker serving that
environment through `run-benchmark.sh` wrote
`"AXIAM__AMQP__URL": "amqps://bench:<the value>@rabbitmq:5671"`. Before the wave
the value was the published literal, so nothing secret leaked; the wave made it
a credential and left this one path to the archive. Bounded: the broker
publishes no port, so the password opens nothing outside the stack's network,
and it dies with `bench-down`. The server's own `Debug` redacts exactly this
(`axiam-amqp` `redact_amqp_url`).

**Fix.** `axiam_env_json()` renders any `scheme://userinfo@host` value as
`scheme://<redacted>@host` (greedy to the last `@` before the path, so a
password containing `@` is not half-kept); `bench-pack` refuses packed content
that still carries a URL with a `user:password` pair.

**Test.** `credential-selftest.sh` §6 drives `run-benchmark.sh` with a stub
docker serving a fresh value in the URL and under `AXIAM__DB__PASSWORD`, and
asserts the value appears nowhere in the cell, the URL is recorded with its host
and its userinfo redacted, `AXIAM__DB__URL` is kept, and `bench-pack` scans for
userinfo. It failed before the fix on all three counts.

## 3. The benchmark harness as a credential handler and a CI surface

**Verdict: sound, beyond P23W6-01/-02/-03/-06/-08.** Probes:

* **Where a credential can land.** `meta.json`: P23W6-01, now closed;
  `axiam_env` for the competitors is `{}`, so authentik's
  `AUTHENTIK_BOOTSTRAP_TOKEN` (read by `seed_authentik` off `docker inspect`,
  piped, never printed) never reaches it. `containers_json` records image, digest
  and caps only. The k6 `--summary-export` file carries no `setup_data`, so the
  tokens `setup()` mints stay out of `k6.json`. `record-provenance.sh` records
  variable *names* only. `bench-pack` refuses `.seed/` paths and seed files
  (pinned by `pack-selftest.sh`). The seed and smoke paths print status codes and
  short response bodies, never a request. `docker inspect` output is never
  archived.
* **CI masking.** `bench_creds_load` prints `::add-mask::` for every value it
  loads, generated or exported, before anything uses it, and `seed.sh` masks what
  the authentik seed generates (the user password, the client secret, the
  app-password key) as it is produced. The values are single-line hex or
  `Bn-<hex>-Aa1`, which mask cleanly. The generation message names the file,
  never a value.
* **Mode 600, race-free, removed.** The stack file was created under `umask 077`
  in a subshell — race-free for a new file, but `>` into an existing empty file
  kept that file's mode, and `.seed/` was 0755; the seed env, which since this
  wave carries the admin passwords, was written and then `chmod`ed (P23W6-03,
  fixed). `bench-down` removes the stack file and the bulk-seed record; the seed
  env stays, by design, for the SDK benches, and is now 0600 from creation.
* **"An exported value wins" — traced through `fapi-conformance.yml`.** Step
  *Bring up*: `BENCH_ADMIN_PASSWORD` is generated, masked, written to
  `GITHUB_ENV` and exported; `bench-up` → `bench_creds_load axiam` finds no stack
  file, writes one recording the exported admin password and generated datastore,
  broker and bench-user values, sources it (the `[ -n "${VAR:-}" ] || VAR=…`
  lines leave the export alone) and masks all four. `bench-seed` is a new shell:
  `seed.sh` → `bench_creds_load` re-sources the same file, the export (from
  `GITHUB_ENV`) still wins, and the administrator is bootstrapped with the
  workflow's password, which the registrar step reads as `AXIAM_ADMIN_PASSWORD`.
  Step *Publish the registered tenant*: the second `bench-up` re-sources the same
  stack file, so SurrealDB and RabbitMQ get the same passwords for their existing
  volumes and only the server is recreated. *Collect logs*: `bench-logs`
  substitutes `x` for every required variable, which `docker compose logs` never
  uses. *Tear down*: `bench-down` removes the file. **It keeps working.** One
  residual: the server log the workflow uploads on failure is at
  `axiam=debug`; the AMQP URL reaches logs only through `AmqpConfig`'s redacting
  `Debug`.
* **The new CI steps.** Four `run: bash runner/<x>.sh` steps in a job that
  checks out with a SHA-pinned action, under the workflow's
  `permissions: contents: read`, triggered by `pull_request` (not
  `pull_request_target`); none interpolates `${{ }}`, none uses a new action. They
  run the PR's own scripts, which is what CI is for.
* **`--print-exports` against a moved source.** The Python fails closed — every
  extraction raises — but the justfile's `eval "$(…)"` threw the status away
  (P23W6-02, fixed).
* **Do the self-tests catch what they claim?** Mutations run by hand, each
  reverted: removing `scim_per_min` from `PROD_PIN_FIELDS` → the posture
  self-test fails; `KC_DB_PASSWORD: keycloak` in the Keycloak compose file → the
  credential self-test fails; `umask 022` in `bench-creds.sh` → fails;
  `::add-mask::` removed → fails; a literal default in the Go, C, C# and Kotlin
  SDK benches → each fails. The scanner's limits: it knows `str('X', 'lit')`,
  `${X:-lit}` and `env("X", "lit")`/`get("X", "lit")`; a JavaScript
  `__ENV.X || 'lit'` would pass it. The tree has none.
* **authentik.** Compose: every credential a required `${VAR:?…}`, the metrics
  port unpublished. Seed: the bootstrap token read from the container, the user
  password generated (or `BENCH_AUTHENTIK_USER_PASSWORD`), the client secret
  authentik's own; the smoke checks assert `active: true` and a negative password
  control rather than a status.
* **Ports.** Every target binds its ports on all host addresses (P23W6-06):
  AXIAM 8090, 50051 and the edge's 8443; Keycloak 8090 and 8443; Zitadel 8090 (or
  the TLS port); authentik 8090 and 8443. Datastores, brokers and authentik's
  metrics port are unpublished. A loopback default cannot be applied blind: the
  FAPI conformance rig reaches AXIAM at `host.docker.internal` through
  `host-gateway`, i.e. the Docker bridge, which a `127.0.0.1` binding would cut
  off. The runbook now tells the maintainer to firewall the ports for the run;
  the compose change is §14's body.

## 4. P23W6-02, -03, -08 — the three other harness fixes

**P23W6-02 — Severity: Low. Fixed in `f387ce2`.** `bash -c 'set -euo pipefail;
eval "$(python3 -c "import sys; sys.exit(3)")"; echo CONTINUED'` prints
`CONTINUED`: a command substitution's status is lost inside `eval`'s argument.
So the first time the Rust source moved, `rl=prod` would have run with
`device_authorization`, `token_exchange`, `uma_perm`, `uma_ticket`, `par`,
`end_session` and `scim` at 1 000 000, and `rl-prod-check` would FAIL a posture
the harness never applied — the defect T23.10.2(a) fixed, back. **Fix:** an
assignment carries the status to `set -e`; every line must be
`export AXIAM__RATE_LIMIT__*_PER_MIN=<n>`; an empty answer refuses the bring-up.
**Test:** `rl-prod-posture-selftest.sh` runs the justfile's own pin code (between
`rl-prod-pin` markers) under `set -euo pipefail` against a `python3` that fails
and one that prints nothing; both reached the next line before the fix. It also
checks the real pins equal `--print-exports`. The recipe was rendered with
`just -n` (just 1.58).

**P23W6-03 — Severity: Low. Fixed in `31106cb`.** See §3. **Fix:** both files
are removed and recreated under `umask 077`; `.seed/` is created 0700.
**Test:** `credential-selftest.sh` §4b — a pre-existing empty 0644 stack file, the
directory's mode, and `write_seed` run as written with `chmod` observed (the file
must be 600 when `chmod` is reached). Before: 644, 755, 644.

**P23W6-08 — Severity: Low. Fixed in `6fc3be0`.** The minimal overlay removes
the broker URL with `!reset null`; the checker's loader passed tags through as
scalars and reported `'null'` as a non-`amqps://` URL. CI's *AMQP transport
posture* step runs it on every PR. **Fix:** `!reset` loads as a sentinel and
the key counts as removed in that file, as Compose treats it. **Check:** exit 1
on the tree before, 0 after; a plaintext `amqp://` written into the overlay is
still reported.

## 5. The minimal-profile overlay and the run-6 runbook

**The overlay against T23.8.1, T23.8.3 and W5 §9.** `AXIAM__AMQP__ENABLED:
"false"`; the URL, CA path and signing key `!reset`; `volumes: !override []`;
`depends_on: !override` SurrealDB only; RabbitMQ parked in a profile no run
activates. **Single instance**: no replica count exists, `container_name` makes
Compose refuse `--scale`, and the server refuses a second live lease (D-59).
**No broker**: the deploy-profile self-test pins all of it, and
`BENCH_EXPECT_DEPLOY` refuses a stack that is not the profile the pass says.
**The GDPR dead-letter file on tmpfs**: in the benchmark it is never written
(no scenario or seed step makes a GDPR request — checked), so it costs nothing
and leaves nothing behind. It is a data-loss statement for anyone who copies the
overlay: the erasure and tenant-deletion records that could not reach the
datastore would be lost on restart, which is the one fallback T19.27 gives them.
The runbook now says the overlay is not a deployment file and points at
`docker/docker-compose.minimal.yml`, which keeps the file on a named volume
(`37a3046`). **The 30 s stop grace against D-72's 15 s backstop**: they govern
different stops — D-72's backstop bounds the lease-loss stop inside the
process; `stop_grace_period` bounds a `docker stop` (SIGTERM) — and 30 s ≥ 15 s,
so a lease-loss stop racing a `docker stop` completes. The SIGTERM path itself
has no backstop: actix's graceful shutdown waits up to its default 30 s for
in-flight requests, then the audit drain takes up to 5 s, which can outlast the
30 s grace and be killed mid-drain. Pre-existing and shared with
`docker/docker-compose.minimal.yml` (T23.8.3), narrow (it needs a request still
running at stop), reported (P23W6-12).

**The runbook against W5 F4 §15's binding rules.** The rules, verbatim:

> The minimal profile is a benchmark configuration now; measure it as T23.8.3 documents it (single instance, the lease held), and say in the report that its outbound deliveries are lost on restart (T-445) so that no reader mistakes its footprint for the full profile's. Do not benchmark with the approval or SCIM routes' limits raised without saying so — both are never preset. A benchmark that enables a SCIM target on a dead host will reproduce P23W5-07: keep targets disabled, or point them at a loopback server that answers.

* **Measured as T23.8.3 documents it** — §2.5: "SurrealDB and the server, a
  single instance, the lease held", the overlay, the caps, `meta.json`'s
  `axiam_deploy_profile`, `report.py`'s banner (verified: it labels minimal cells
  "NOT the full profile" with T-445), cells in their own results tree.
  **Honoured.**
* **Deliveries lost on restart** — §2.5 and §9 rule 6, both required in the
  report. **Honoured.**
* **Approval and SCIM limits** — §2.6 lists `ciba_approval`, `bc_authorize` and
  `scim_target_admin` as **not raised**, and says that `scim_per_min` (the inbound
  SCIM endpoint; verified never preset: `rate_limit.rs` asserts the presets
  leave it alone) is raised under the neutralized posture and must be stated, at
  every table; §9 rule 5 repeats it. No scenario calls a CIBA or SCIM-target
  route (checked). **Honoured.**
* **SCIM targets** — none is registered anywhere in the harness (checked by
  search); §2.5 says so and gives the loopback rule. **Honoured.**

Two additions, both in `37a3046`: the LAN exposure (P23W6-06) and the overlay
note above. §1.4 now names the userinfo scan (P23W6-01).

## 6. The threat model at 2.36.0 — reviewed

* **D-78's rule is sound.** *Mitigated* would claim controls nobody built (the
  T-108/T-117/T-102 error); *Open* would put twenty-one entries for a surface
  nobody runs into a register meant for exposure. Threat Dragon's own third
  status says exactly what is true, the elements are `outOfScope` with a reason,
  and every entry names the status a build would take. The rule is narrow by
  construction: §2 of the STRIDE document limits it to a surface that is not
  built *and not scheduled*.
* **Is any of T-448 … T-468 about something AXIAM runs today?** Each was read.
  All describe the RADIUS surface. Two have live twins, which is why they matter:
  **T-457** (an Access-Reject that is a user oracle by timing) restates for RADIUS
  what `AuthService::login` does today for a locked account — that twin is now
  **T-469**, Open, on the authentication diagram where it belongs; and **T-460**
  cites the device-grant approval hole, which is T-447, Open. Neither changes
  T-457's or T-460's status.
* **Does the generator hide an open entry?** No. Every `NotApplicable` entry in
  the model (enumerated by script) is one of T-448 … T-468, on the RADIUS diagram,
  on an `outOfScope` element; at 2.35.0 there were none. Any status other than
  `Mitigated` and `NotApplicable` still counts as open, so a typo is shown, not
  hidden.
* **Counts.** At 2.36.0 the three artifacts and the website agreed (468; 425 /
  22 / 21). At 2.36.1 they agree again (§12), including every per-section summary
  line, checked by script against `Axiam.json`.
* **T-102's reopening is accurate** — `grep -rn -i 'crl\|ocsp' crates
  sdks/openapi.json` finds only the `cRLSign` key-usage bit, a rustls verifier
  parameter named `_ocsp` (ignored), and a SAML comment; no route, no
  distribution point, no responder. **Its text overclaimed**, which is P23W6-04
  (§7).
* **The "own request path" paragraph** — fixed as P23W6-05 (§7).

## 7. P23W6-04 and P23W6-05 — the threat-model text

**P23W6-04 — Severity: Low. Fixed in `c83593a`.** T-102 at 2.36.0, the design
document's §6.2, the write-up and the website's *Security* and *Operate* pages
said revocation takes effect "where AXIAM terminates the connection". Only
`DeviceAuthService::authenticate_der` (the REST certificate sign-in) reads a
certificate's status. Neither listener's verifier is given a CRL (there is none),
`crates/axiam-api-grpc` reads no certificate status, and OAuth2
`authenticate_mtls_client` (`crates/axiam-oauth2/src/mtls.rs`) is a pure function
matching the client's registered subject DN, DNS SAN or URI SAN against a
certificate that chained to an installed anchor — and flagging an AXIAM CA as a
listener anchor writes it into that bundle (`axiam-server/src/tls.rs`). So a
revoked AXIAM-issued leaf keeps authenticating its OAuth2 client at AXIAM itself
until it expires or the registration changes. The text now says so in all six
places; the gap is P23W6-10. No test: documentation.

**P23W6-05 — Severity: Informational. Fixed in `c83593a`.** The write-up said
"**three**", the website "**two**", both "and none is a defect". Counting the five
request-path diagrams: authentication 1 (T-469, new), OAuth2 1 (T-447), federation
3 (T-161, T-306, T-380), authorization 0, PKI 2 (T-94, T-102) — **seven**. Four are
residuals that land at least partly outside AXIAM (T-94, T-161, T-306, T-380);
three are not (T-447, a defect, #549; T-102, a missing control; T-469, a defect).
Both texts now say exactly that. No test: documentation.

## 8. P23W6-09 — the locked account answers first (T-469)

**Severity: Medium. Reported (§14); T-469 Open.**

`AuthService::login` (`crates/axiam-auth/src/service.rs`): step 1 resolves the
name; an unknown one goes to `login_unknown_user`, which always runs
`equalising_dummy_verify` under a bounded hash permit (SEC-026). Step 2 then
refuses an account with `locked_until > now` — **before** the directory branch
(deliberately, T-302) and **before** `acquire_hash_permit` and the Argon2id
verify. Every other early return was checked:

| Branch | Verify? | Where |
|---|---|---|
| unknown name, no directory or no JIT | dummy, under a permit | `service/directory.rs` (`authenticate_unknown_name_against_directory`, first return) |
| unknown name under the unknown-name lockout (T-332) | dummy, under a permit | same function, second return |
| unknown name, JIT directory | dummy beside the bind | same function |
| **locked local or directory account** | **none, no permit** | `service.rs` step 2 |
| directory account, status refuses or no authenticator | dummy | `login_directory_account` |
| local account, wrong password | real | step 3 |
| suspended / unverified local account | real, then status | `complete_authenticated_login` |
| gRPC `ValidateCredentials`: unknown, locked, non-active, directory | **none** | `axiam-api-grpc/src/services/user.rs` |

Lockout is triggered by the attacker's own failures. A name that answers fast
after N wrong passwords exists; one that keeps costing a verify does not —
enumeration at N + 1 requests per name, and the real user is locked out on the
way (T-35). Under hash-permit saturation, which an attacker can produce, it is
not even timing: the locked account answers `401` while every verifying branch
answers `503`. A test run here (§13; in the issue body, not the tree) shows it:
with no permit available, an unknown name answers `ServiceUnavailable` and the
locked account answers `InvalidCredentials`. gRPC `ValidateCredentials` is a
wider oracle for a narrower audience — it needs a validated token of the tenant,
and answers an unknown name with no verify at all.

**Threat entry.** **T-469** (Information disclosure, Medium, Open) on the
authentication diagram's *Login endpoints*, model 2.36.1, and T-30's mitigation
now names it as its residual.

## 9. P23W6-07 and D-74's resolution

D-74's text says an unvouched account's CIBA request "is stored, answered as
before (T-422) and waits on the approval page". The console has three CIBA
routes, `GET /api/v1/ciba/requests/{request_id}`, `…/approve`, `…/deny`
(`crates/axiam-api-rest/src/server.rs` ~807–831); the console's only CIBA page is
`ciba/approve`, which takes the record id from the URL the mail carries
(`frontend/src/router.tsx`, `pages/ciba/`); nothing lists a user's pending
requests, and the record id travels nowhere else (D-68). So without the mail the
request cannot be opened and runs to expiry; the client is told
`expired_token`. A federated account (`PendingVerification` for life, T-160)
with no verified address therefore **cannot approve a CIBA request at all**.

**Resolution.** (1) D-74's consequence text is wrong and is **amended** in place
(`37a3046`, an italic line in the row); the **decision stands** — mailing an
unvouched address is the phishing relay D-74 closed. (2) It is a functional
defect, not a security one (it fails closed), and worth an issue body: the
remedy is a signed-in user's own pending-request list on the console, under
§33's approval-surface rules (§14). The Keycloak comparison and the website's
*Integrate* page already state it correctly ("the approval page is reached by a
link only the mail carries, so without it the request runs to expiry").

## 10. Documentation claims — verified against the code

| Claim (where) | Verdict | Evidence |
|---|---|---|
| CIBA has no push mode (Keycloak comparison, *Integrate*) | **true** | `CibaDeliveryMode::from_wire("push")` is `None`; registration refuses it (`ciba.rs` tests) |
| CIBA has no `user_code`, refused at registration and on the request, discovery `false` | **true** | `ciba.rs` ~306 (registration), ~503 (`user_code is not supported`), `oidc.rs` ~478 |
| D-74: mail only to a vouched address; federated accounts unmailed | **true**; the consequence in D-74 itself was wrong | §9 |
| Outbound SCIM: one attempt at a time per replica (three comparisons, *Integrate*) | **true** | one sequential consumer per kind (AMQP and in-process, `inprocess.rs` "one delivery in flight"); W5 §7 |
| No CRL is published (comparisons, *Operate*, design document) | **true** | §6 |
| "A revoked certificate is refused on its next mTLS or certificate sign-in" (*Operate*), "checked on every mTLS authentication AXIAM terminates" (design document) | **false for `tls_client_auth`** — corrected | P23W6-04 |
| "The request is stored, but the approval page is reached by a link only the mail carries" (*Integrate*) | **true** | §9 |
| RADIUS: no support today; FreeRADIUS route on request (authentik comparison) | **true** | no RADIUS code in the tree; D-77 |
| Run-6 versions and pins (Keycloak 26.8.0, Zitadel v4.19.4, authentik 2026.8.3) | **true** | the compose files' image lines |

## 11. Rate limits, CSRF, CSP, console

No route, middleware, handler or console page changed in the wave. The harness
changes the *benchmark's* limiter posture only, and the runbook states it (§5).
`rl-prod-check`'s blind spots are P23W6-11.

## 12. Threat-model reconciliation

Model **2.36.1** (from 2.36.0), in all three artifacts and the website, in
`c83593a`; `node website/scripts/gen-threat-model.mjs` → *469 threats (425
mitigated, 23 open, 21 not applicable)*, and a second run leaves no diff.

| Change | Entry |
|---|---|
| A locked account refused before any verify; gRPC `ValidateCredentials` | **T-469** added (Login endpoints, I, Medium, **Open**); element `hasOpenThreats` set |
| Residual pointer | **T-30** mitigation amended |
| Revocation read at device sign-in only | **T-102** text corrected (stays Open) |
| `threatTop` | 468 → 469 |

Counts: STRIDE *Information disclosure* 110 (7 open, 4 not applicable); severity
*Medium* 195 (10 open, 9 not applicable); diagram *Authentication & session
management* 36 / 1. Open register 23. Checked by script: the STRIDE document's
coverage tables and all ten section summary lines against `Axiam.json`.

## 13. Checks run

Before each fix, the check that failed:

```bash
bash benchmarks/runner/credential-selftest.sh      # P23W6-01: value found in the cell; URL not redacted; no userinfo scan  -> FAILED
bash benchmarks/runner/rl-prod-posture-selftest.sh # P23W6-02: "fails OPEN" with a failing python3 and with an empty one  -> FAILED
bash benchmarks/runner/credential-selftest.sh      # P23W6-03: 644 stack file kept; .seed/ 755; seed env 644 at chmod      -> FAILED
python3 scripts/check-amqp-transport.py            # P23W6-08: "AXIAM__AMQP__URL is 'null'"                                -> exit 1
cargo test -p axiam-auth --test directory_provisioning_test -- w6f4   # P23W6-09 (issue-body test, reverted): 1 failed —
    # "a locked account must cost what an unknown name costs (SEC-026); it answered without asking for a permit"
```

After (`cargo clean` after the one Rust build):

| Check | Result |
|---|---|
| *Bench Harness Self-Tests*, every step: `pack-selftest`, `test-median-provenance`, `test-sdk-version`, `scenario-filter-selftest`, `rl-prod-layout-selftest`, `nested-selftest`, `authentik-selftest`, `credential-selftest`, `rl-prod-posture-selftest`, `deploy-profile-selftest`, `bash -n` over `runner/*.sh sdk/*.sh sdk/*/run.sh` | pass (all eleven) |
| `cargo fmt --all --check` | pass |
| `check-crate-layering` (and `--self-test`), `check-spec-digest` (and `--self-test`), `gen-management-registry --check` (and `--self-test`), `check-config-key-coverage` (and `--self-test`), `check-frontend-coverage`, `check-conflict-markers` (and `--self-test`), `check-docker-context` (and `--self-test`), `check-locale-bundle-sync` (and `--self-test`), `check-audit-ignore-sync` (and `--self-test`) | pass |
| `check-amqp-transport` | **fail before `6fc3be0`** (P23W6-08); pass after |
| `bash scripts/check-doc-links.sh` | pass (recorded in the addendum below) |
| `node website/scripts/gen-threat-model.mjs`, twice | 469 threats (425 / 23 / 21); no diff on the second run |
| website `npm ci && npm run lint && npx tsc -b && npm run build` | pass (after `00e7a57`; `c83593a` alone failed lint, tsc and build on an unescaped backtick in a template literal) |
| `just -n target=axiam rl=prod bench-up` (just 1.58) | the justfile parses; the pin renders |

Not passable here, as in W5: `check-remediation-evidence.py` (shallow clone),
`check-sdk-amqps.py` (needs the eleven SDK repositories beside this one),
`check-website-links.py` (external links through the sandbox proxy). No clippy:
no Rust changed on the branch.

## 14. Issue bodies for the reported findings (not filed)

### P23W6-09 (Medium) — a locked account is refused before any password verification (T-469)

`AuthService::login` refuses an account serving a temporary lockout
(`locked_until > now`, local or directory) at step 2 of
`crates/axiam-auth/src/service.rs`, before `acquire_hash_permit` and the
Argon2id verify, while an unknown name (`equalising_dummy_verify`, SEC-026) and a
wrong password each cost one verify under a bounded permit. Lockout is triggered
by the attacker's own failures, so a name that answers fast after N wrong
passwords is an existing account: an enumeration oracle at N + 1 requests per
name. Under hash-permit saturation the branch answers `401` where every verifying
branch answers `503` (B1's backpressure), which is a status oracle, not a timing
one. gRPC `UserService/ValidateCredentials`
(`crates/axiam-api-grpc/src/services/user.rs`) answers an unknown name and a
locked, non-active or directory account `valid: false` with no verify at all,
for any caller holding a validated token of the tenant.

**Proposed fix.** On the lockout branch, run `equalising_dummy_verify` (same
bounded permit, same timeout) and then refuse — still before the directory is
contacted (T-302) and without verifying the real hash, so a correct password
during a lockout neither succeeds nor shows. In `ValidateCredentials`, run the
same dummy verify (through the same gate and `spawn_blocking`) on every refusal.
Closes T-469; T-30's residual goes with it. **Test** (fails today at the second
assertion; a `crates/axiam-auth/tests/directory_provisioning_test.rs` case, using
its `harness`, `service_with`, `input` and `fresh_credential`):

```rust
#[tokio::test]
async fn a_locked_account_needs_the_hash_permit_an_unknown_name_needs() {
    let h = harness().await;
    h.users
        .update(
            h.tenant_id,
            h.local_user,
            UpdateUser {
                locked_until: Some(Some(Utc::now() + ChronoDuration::minutes(15))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    // No permits at all and no patience: anything that would hash answers 503.
    let saturated = service_with(&h, None, 0, 0);
    let wrong = fresh_credential();
    let unknown = saturated.login(input(&h, "nobody-here", &wrong)).await;
    assert!(
        matches!(unknown, Err(AxiamError::ServiceUnavailable(_))),
        "an unknown name runs the equalising verify, so it needs a permit"
    );
    let locked = saturated.login(input(&h, "bob", &wrong)).await;
    assert!(
        matches!(locked, Err(AxiamError::ServiceUnavailable(_))),
        "a locked account must cost what an unknown name costs (SEC-026)"
    );
}
```

plus the gRPC twin (a saturated gate: an unknown name, a locked account and a
wrong password must all answer the status the gate gives when it cannot hash).
Threat: T-469.

### P23W6-10 (Medium) — publish a CRL per issuing CA; and AXIAM's own `tls_client_auth` reads no certificate status (T-102)

AXIAM publishes no certificate revocation list and runs no OCSP responder: its CAs
carry the `cRLSign` bit and nothing serves a list. A relying party that validates
AXIAM-issued certificates itself (a FreeRADIUS server doing EAP-TLS, a VPN
gateway, a peer service) has no revocation channel and honours a revoked
certificate until it expires (T-102, reopened at 2.36.0; the RADIUS spike's §8
item D1, which D-77 commits to regardless of RADIUS). The W6 F4 review found the
same gap inside AXIAM: only device sign-in by certificate
(`DeviceAuthService::authenticate_der`) reads a certificate's status. OAuth2
`tls_client_auth` (`crates/axiam-oauth2/src/mtls.rs`,
`authenticate_mtls_client`) matches the client's registered subject DN or SAN on
a certificate that chained to a listener anchor — and flagging an AXIAM CA as an
anchor writes it into that bundle — so a revoked AXIAM-issued leaf keeps
authenticating its OAuth2 client at AXIAM's own token endpoint. **Proposed fix:**
(1) `GET` a CRL per issuing CA (RFC 5280 profile), signed through the CA's
existing custodian, with `nextUpdate` and caching headers, its distribution point
in every certificate issued after it ships, rate-limited and unauthenticated (the
spike's B-1); decide OCSP separately. (2) Either load those CRLs into both
listeners' client verifiers (rustls `WebPkiClientVerifier` with CRLs, reloaded
with the anchors) or have `tls_client_auth` look the leaf up by fingerprint and
refuse a non-`Active` one, as device sign-in does — the second also covers a leaf
revoked before the next CRL. Tests: a revoked leaf is refused at the token
endpoint under `tls_client_auth`; the CRL lists it, verifies under the CA, and a
`nextUpdate` is honoured. Contract and OpenAPI gain the route. Closes T-102.

### P23W6-06 (Low) — benchmark stacks listen on every interface

Every `benchmarks/targets/*/docker-compose.yml` publishes its ports without a
host address (`"${BENCH_APP_PORT:-8090}:8090"`), so Docker binds `0.0.0.0` — past
`ufw` — while AXIAM's benchmark posture raises its limiters and lockout threshold
to 1 000 000. On a benchmark host on a LAN, four identity servers with their
limits off are reachable for the length of a run. The credentials are generated
per run since W6 (no published password opens them), so the exposure is a
measurement-integrity and hygiene problem rather than a takeover. **Proposed
fix:** prefix every published port with `${BENCH_BIND_ADDR:-127.0.0.1}:`, and set
`BENCH_BIND_ADDR=0.0.0.0` in `fapi-conformance.yml`'s environment step and in the
conformance runbook, because the conformance rig reaches AXIAM through
`host.docker.internal:host-gateway` (the Docker bridge), which a loopback binding
cuts off. Self-test: every `ports:` entry in a target compose file carries the
variable. The run-6 runbook already tells the maintainer to firewall the ports
(§1.2).

### P23W6-07 (Low) — an account with no vouched address cannot approve a CIBA request

D-74 mails the CIBA approval prompt only to a vouched address. The console has no
list of a signed-in user's pending requests — only
`GET /api/v1/ciba/requests/{request_id}` and its `approve`/`deny`, opened from the
mail's link — so for an account with no vouched address (every federated account
without a verified address, `PendingVerification` for life, T-160) the request
cannot be reached and expires; the client sees `expired_token`. CIBA is
therefore unusable for such accounts. **Proposed fix:** `GET
/api/v1/ciba/requests?status=pending` returning the signed-in user's own pending
requests (client name, binding message, expiry; never the `auth_req_id`), and a
console entry (a badge on the user menu) linking to the existing page — under
§33's approval-surface rules: console sign-in only (a token carrying `client_id`
is `403`, P23W5-04's rule), its own limiter in `ciba_approval_per_min`, never
preset, CSRF on the decisions, the version read, the deciding session audited.
The decision D-74 made stands. Tests: a federated user with no verified address
sees and approves their request; another user's request is not listed; a
client-minted token is `403`. Contract §33 notes the route (console surface, not
SDK surface).

### P23W6-11 (Low) — `rl-prod-check` has no row for eight limiter families

`benchmarks/runner/rl_prod_check.py` compares admitted against configured for 23
families. Eight shipped REST families have no row:
`bc_authorize_per_min`, `ciba_approval_per_min`, `device_login_per_min`,
`ssf_per_min`, `ssf_admin_per_min`, `saml_admin_per_min`,
`directory_admin_per_min`, `scim_target_admin_per_min`. No scenario drives
them, so a production-posture pass says nothing about them — the shape that hid
the unlimited `/auth/webauthn/*` routes until alpha38 (the comment beside its
row). **Proposed fix:** a row each, with `scenario: None` and the route, so the
summary lists them as "not checked" rather than omitting them; a self-test that
every `*_per_min` field of `RateLimitConfig` has a row. Driving them needs
scenarios that are a separate decision (an approval needs a console session; the
admin families are human-only).

### P23W6-12 (Informational) — two hygiene items

(a) `docker/docker-compose.minimal.yml` and the harness overlay set
`stop_grace_period: 30s`. On SIGTERM actix's graceful shutdown waits up to its
default 30 s for in-flight requests (`boot.rs` sets no `shutdown_timeout`), then
the audit drain takes up to 5 s (`AUDIT_DRAIN_DEADLINE`), so a stop with a request
still running can be killed during the drain and lose the audit rows D-72's
orderly stop exists to keep. **Proposed fix:** set `shutdown_timeout` explicitly
(say 20 s) and keep the grace above it plus the drain plus a margin (say 40 s),
documented together; or add a SIGTERM backstop like the lease-loss one. Pair it
with #554's orderly-stop work. (b) `bench-up`'s `genhex` writes
`docker/.secrets/*.hex` with `>` and then `chmod 600`, the P23W6-03 shape, for the
AXIAM key material of a benchmark stack. **Proposed fix:** `(umask 077; …)`, as
`31106cb` does for `.seed/`.

---

## 15. What comes after Phase 23

W6 is the phase's last wave. This section is for the project.

### What stays open from Phase 23

* **#513** — G-1: the OpenID Basic OP and FAPI 2.0 certification submissions, the
  maintainer's conformance runs (and the unattended gate's red-by-design, P23W5-11
  in #555).
* **#547, #548** — SDK fan-out for contracts 1.57 (§31) and 1.58 (§33); with them,
  the older **#540** (1.53–1.55) and **#541** (1.56, which carries the SSF receiver
  helper that closes T-388).
* **#549 … #555** — the W5 findings: the device grant's client-token approval
  (#549, T-447), the tarpit SCIM downstream (#550), request-path notification
  flooding (#551, T-117), the GDPR audit durability gaps (#552), silent
  request-audit loss (#553, T-108), the abrupt full-profile exits (#554), the lows
  (#555).
* **The earlier waves' filed issues, all still open:** W1 #517 (client deletion
  revokes nothing), #518 (`actor_token` not bound), #519 (federated sessions stop
  refreshing), #520 (lows); W2 #523 (tenant delete cascades to nothing), #524,
  #525, #526; W3 #529 (email provider has no address policy), #530 (IdP metadata
  unsigned, uncached), #531 (SHA-1 and DTDs in the SP verifier), #532
  (`/oauth2/authorize` has no limiter), #533 (certificates bound to users); W4 #535,
  #536, #538.
* **G-10's W6b** — T23.10.2(b): the seventh draft of `PUBLIC_BENCH_ANALYSIS.md`,
  the comparisons' performance rows and the website's numbers, after the
  maintainer runs run 6 against `1.0.0-beta18` (D-75, D-76). No G-10 issue exists
  yet; D-76 says one tracks it.
* **This review's six bodies** (§14): P23W6-09 (T-469), P23W6-10 (the CRL and
  `tls_client_auth`, T-102), P23W6-06, P23W6-07, P23W6-11, P23W6-12.

### Binding preconditions any future work inherits

* **RADIUS, if ever reopened (D-77's condition)**, starts from the spike's §6 as
  requirements of its first commit — its own limiter in the machine presets and
  the tenant lockout (T-451); one byte-identical Access-Reject with an equalising
  verify on *every* branch, the locked one included (T-457, and T-469's lesson);
  the per-NAS secret generated, sealed under `pki_encryption_key`, write-only and
  bound to its address, transport and RadSec pin (T-466, T-467);
  `Message-Authenticator` on every packet and `Proxy-State` refused (T-449);
  MD5-only attributes only under an explicit `legacy_udp` flag (T-450) — and its
  entries move from *Not applicable* to Mitigated or Open, with tests, in the
  commit that builds each element.
* **The CRL** is not optional for anything that hands an AXIAM-issued certificate
  to a relying party AXIAM does not front (option B, a VPN, a peer service); it
  ships before any such guide, and it reaches AXIAM's own listeners or
  `tls_client_auth` too (P23W6-10).
* **Approval surfaces.** Any route where a person approves a grant takes a
  console sign-in only (a token carrying `client_id` is `403`), CSRF on cookies,
  the version read, and audits the deciding session; the device grant owes it
  (#549), and a CIBA pending list (P23W6-07) inherits it.
* **`NotificationGate`.** Any notification raised by a background process goes
  through one — `NotifyingAuditLog` has no constructor without it; a request-path
  event waits on #551.
* **`guarded_fetch_no_redirect`.** Every credential-bearing outbound request
  (SCIM, the SCIM token request, CIBA ping, SSF push) uses it with
  `allow_private = false`; the webhook deliverer is the one exception left (#555).
* **Two-writer registries.** A registry an administrator and a background worker
  both write is written conditionally on the version the writer read, the worker
  re-reads before a credential leaves, and a credential is bound to every
  endpoint that receives what it yields (P23W5-01); the client-version half is
  #555's P23W5-09.
* **Every refusal of a credential check costs one verify** (SEC-026, T-469):
  unknown, locked, suspended and directory branches alike, on every transport.
* **The benchmark harness's credential rules** (this wave): no credential literal
  anywhere under `benchmarks/` (the self-test enforces it); every credential
  generated per stack, masked under CI, private from creation and removed with its
  volumes; nothing from a container's environment reaches a results file, a URL's
  userinfo included; a pin that reads source fails closed.

### What is most worth scheduling before 1.0

1. **#549 — the device grant's client-token approval (T-447).** A relying party
   holding any `openid` token can approve a device flow in its user's name and get
   another client's scopes and a refresh token. It is the one open item on the
   request path that grants something, and the fix is P23W5-04's rule, already
   written for CIBA.
2. **T-469 (P23W6-09).** Small (one equalising call on two branches), with the
   test written, and it restores SEC-026's guarantee, which the public security
   page states.
3. **The CRL and `tls_client_auth`'s status check (P23W6-10, T-102).** The only
   High open entry AXIAM can close itself, and the prerequisite for the
   FreeRADIUS route and for any AXIAM-issued certificate used outside AXIAM.
4. **#550 — the SCIM breaker.** One unresponsive downstream stalls every tenant's
   provisioning on a replica; the comparisons now have to say so.
5. **#551 and #553 — notification coalescing on the request path (T-117) and a
   counter for dropped audit rows (T-108).** Both are controls the model once
   claimed and the code never had.
6. **#532 and #531** — a limiter on `/oauth2/authorize` and SHA-1/DTD refusal in
   the SAML SP verifier: cheap, and both are what an external audit flags first.
7. **#517** — client deletion revoking nothing is a correctness gap with a
   security edge (a deleted client's refresh tokens).

### The threat model's open entries at 2.36.1, by kind (23)

| Kind | Entries |
|---|---|
| Defects or missing controls in AXIAM, fix filed or drafted (5) | T-447 (#549), T-469 (§14), T-102 (§14), T-108 (#553), T-117 (#551) |
| Accepted design trade-offs (5) | T-306, T-380, T-161, T-405, T-445 |
| Waiting on a downstream fan-out (1) | T-388 (SDK receiver helper, #541) |
| Deployment responsibility, or inherent to the medium (8) | T-9, T-18, T-123, T-124, T-133, T-134, T-180, T-216 |
| Integrator, device and distribution side (4) | T-94, T-135, T-146, T-148 |

Plus 21 *Not applicable* (T-448 … T-468, the RADIUS front end that is not built).
New threat ids start at **T-470** (`threatTop` is 469).

## 16. Invariants

I1 (nothing registered today changes behaviour) holds: no product code changed.
The harness changes behave differently only where they refuse — `bench-up` under
`rl=prod` refuses when the source pins cannot be read (`f387ce2`), `bench-pack`
refuses an archive carrying a URL with userinfo (`550fe00`) — and `meta.json`'s
`axiam_env` records `AXIAM__AMQP__URL` as `amqps://<redacted>@rabbitmq:5671`.
`check-amqp-transport.py` treats a `!reset` key as removed (`6fc3be0`). No
contract, OpenAPI, schema or SDK-visible field changed.
