# Release 1.0.0 plan — closing the beta line and making the fleet taggable as `v1.0.0`

> **Status: PLAN — W1 starting.** Written on 2026-10-09 against `main` at
> `fe369eb` (the merge of PR #587, contract 1.59) and against the eleven
> `ilpanich/axiam-<lang>-sdk` repositories at their `claude/contract-1.59-sync`
> merges of the same day. It brings the platform and the eleven SDKs to the state
> in which the maintainer runs `scripts/mass-tag.sh --repos all --branch main
> --tag v1.0.0 --changelog` after a dry run and an OpenID Foundation conformance
> check, and every pipeline publishes a stable release.
>
> **What the agent does, and what it does not.** The agent writes code, opens
> pull requests and records results here. It does **not** tag, does **not** run
> the conformance suites, does **not** run benchmark run 6 and does **not**
> merge. Every commit is signed; every pull request lists the issues it closes on
> a `Closes` line, and the issues are closed by the merge, never by hand.
>
> **Waves, and one pull request.** W1 (security findings, Opus 5.5) and W2
> (durability, operations, the CIBA gap) are developed on
> `claude/release-1.0.0-w1` and `claude/release-1.0.0-w2` from `main` and are
> independent; W3 (contract 1.60 and the eleven SDK ports) needs the fields W1
> and W2 add; W4 (release readiness) needs everything. **On 2026-10-09 the
> maintainer asked for a single pull request at the end** (the per-wave PRs'
> CI was failing on Docker Hub's pull limit, not on the change): W1 and W2 are
> merged into this plan's branch, W3 and W4 are committed on top, and the one
> pull request (#589) closes every issue the waves close. The eleven SDK
> repositories get one pull request each. Each section below gets an `EXECUTED`
> block as its wave lands, in the form the Phase 23 plan used.

---

## 0. The state, measured (2026-10-09)

Re-verified from the files and the repositories, not re-derived from the
kickoff prompt.

| Fact | Measured | Evidence |
|---|---|---|
| Platform version | `1.0.0-beta19` | `Cargo.toml` `[workspace.package] version`; `CHANGELOG.md` `## [1.0.0-beta19] - 2026-10-07`; `website/src/version.ts` |
| Latest platform tag on `origin` | `v1.0.0-beta18` (and `axiam-opaque-v1.0.0-beta18`) | `git ls-remote --tags origin` |
| SDK tags | all eleven at `v1.0.0-beta17` | `git ls-remote --tags origin` in each clone |
| Contract | **1.59**; `sdks/CONTRACT.md` at `fe369eb` byte-identical in all eleven SDK clones | `cmp` against each vendored copy |
| SDK `## [Unreleased]` | non-empty in all eleven (61 … 96 lines), carrying the 1.58 and 1.59 ports | `CHANGELOG.md` in each clone |
| Threat model | **2.37.0**, `threatTop` 469; 426 Mitigated / 22 Open / 21 Not applicable; next id **T-470** | `ThreatDragonModels/Axiam/Axiam.json` |
| Open issues | **36** on `ilpanich/axiam`; none on any SDK repository; no open pull request | GitHub |
| Release classification | `release.yml` treats a tag without a `-` segment as stable (`1.0`, `latest`); `release-opaque.yml` moves the npm dist-tag to `latest` on a stable version | lines 214–266 and 289–297 |

### 0.1 What happened to `v1.0.0-beta19`

The beta19 bump did not go through `mass-tag.sh` on `main`. It landed as an
agent-authored pull request — PR #575, commit `e00f3b9`
(`chore(release): prepare axiam 1.0.0-beta19`: `Cargo.toml`, `Cargo.lock`, the
pinned crates, the Sidebar string and its test, both k8s image tags, the
OpenAPI version and digest, the management registry, the CHANGELOG section),
merged as `21a9c22` on 2026-10-07. Beta18 was cut the same way: PR #571
(`4fdd455`) merged as `f28fa5d`, and **the maintainer then put a signed
annotated tag on that merge commit** (`v1.0.0-beta18`, tagger Emanuele Panigati,
message "axiam - 1.0.0-18 BETA Release"). For beta19 the second step — the tag
on `21a9c22` — never ran: no `v1.0.0-beta19` and no `axiam-opaque-v1.0.0-beta19`
exist on `origin`, and therefore no beta19 image, GitHub Release or npm package
was published, although the CHANGELOG and the website's news post say it
shipped on 7 October. It is *a tag never pushed*, not a `mass-tag.sh` run that
stopped after its bump commit (the bump commit is a PR commit, not a script
commit). **The tag is not created by this plan**; `1.0.0` supersedes it. W4
corrects the website post's "shipped" wording to what happened (the code
merged; the tag was skipped) and the `[1.0.0]` narrative says the same.

This also matters for the hand-off: `main` has received its release bumps
through pull requests, and `mass-tag.sh` pushes the bump commit to the branch
directly (`git push origin "$BRANCH"`, line 1331). W4 §7 checks which of the two
routes the maintainer's `main` accepts and writes the hand-off for that one.

### 0.2 What the session could not do

- **SAGE** (`sage_inception`) is not connected in the executing session; this
  plan is built from the repository documents alone.
- **Milestones.** The session's GitHub tooling has no milestone API, and the
  `gh` CLI is not authenticated in the container. The milestones **`1.0.0`** and
  **`1.0.x`** therefore have to be created by the maintainer, and every open
  issue assigned as §1's table says (one column, ready to apply). The one
  comment each deferred issue receives *is* posted by the agent and names its
  milestone.

---

## 1. Triage — every open issue, one milestone each

The rule is fixed: every finding of severity **Medium or higher** ships in
`1.0.0`; every **Low** or **Informational** finding ships in `1.0.0` when its
fix is local (one handler, one guard, one test), and otherwise goes to `1.0.x`
with one comment on the issue naming the milestone and why. Nothing is closed by
deferral. Severity is quoted from the issue.

| # | Title (short) | Severity (as the issue states it) | Milestone | Wave | PR |
|---|---|---|---|---|---|
| 513 | G-1: Basic OP and FAPI 2.0 certification submissions | none (tracking; maintainer's runs) | **1.0.x** | — (code side: #524, #526 in W1) | stays open past the tag |
| 517 | Client deletion revokes nothing; a deleted CIMD client's refresh tokens revive | Medium | 1.0.0 | W1.4 | W1 |
| 518 | RFC 8693 `actor_token` not bound to the exchanging client | Medium | 1.0.0 | W1.5 | W1 |
| 519 | Federated sessions stop refreshing after the verification grace | Medium | 1.0.0 | W1.6 | W1 |
| 520 | Three lows: `claims.id_token.sub`, UserInfo/introspection account status, refresh scope narrowing | Low ×3 (local each) | 1.0.0 | W1.9 | W1 |
| 523 | Tenant deletion deletes only the tenant row | Medium | 1.0.0 | W1.7 | W1 |
| 524 | `require_par` client's unpushed request asks an anonymous browser to sign in | Low (local) | 1.0.0 | W1.13 | W1 |
| 525 | SMTP password kept when the host changes | Low (local) | 1.0.0 | W1.12 | W1 |
| 526 | Discovery auth methods; SCIM phone change keeps `verified_at` | Informational ×2 (local) | 1.0.0 | W1.14 | W1 |
| 529 | Tenant email provider has no outbound address policy | Medium | 1.0.0 | W1.8 | W1 |
| 530 | IdP metadata neither signature-checked nor cached | Low (local to the SAML SP service; the kickoff schedules it) | 1.0.0 | W1.15 | W1 |
| 531 | SAML SP verifier accepts SHA-1 and DTDs | Low (local) | 1.0.0 | W1.11 | W1 |
| 532 | `/oauth2/authorize` has no limiter | Low (local) | 1.0.0 | W1.10 | W1 |
| 533 | Bind certificates to users | Low — **not local** (schema migration, contract field, three revoke paths) | **1.0.x** | — | — |
| 535 | Five cleanup jobs not registered in `/health/jobs` | Low (local) | 1.0.0 | W2.7 | W2 |
| 536 | Console cannot show or switch SAML IdP / SSF | Informational (a page and two controls) | 1.0.0, conditionally (D-8) | W2.10 | W2 |
| 538 | SAML SLO untested against a real SP | Informational — **not local** (Keycloak round trip in CI compose) | **1.0.x** | — | — |
| 541 | SDK ports for contract 1.56 (§32) | tracking; every box ticked | 1.0.0 | — | closed by this plan's PR |
| 547 | SDK ports for contract 1.57 (§31) | tracking; every box ticked | 1.0.0 | — | closed by this plan's PR |
| 548 | SDK ports for contract 1.58 (§33) | tracking; every box ticked | 1.0.0 | — | closed by this plan's PR |
| 549 | A relying party's token approves a device authorization | Medium | 1.0.0 | W1.1 | W1 |
| 550 | A tarpit SCIM downstream stalls provisioning | Medium | 1.0.0 | W2.1 | W2 |
| 551 | Notification rules mail once per event (T-117) | Medium | 1.0.0 | W2.2 | W2 |
| 552 | GDPR audit dead-letter file unprovisioned; request audits fire-and-forget | Medium | 1.0.0 | W2.4 | W2 |
| 553 | Request-audit loss is silent (T-108) | Medium (T-108 High) | 1.0.0 | W2.3 | W2 |
| 554 | Full profile exits mid-flight; gRPC has no orderly stop | Medium (A12), Low (A11) | 1.0.0 | W2.5 | W2 |
| 555 | Six W5 lows and informationals | Low ×3, Informational ×3 (each local) | 1.0.0 | W2.8 | W2 |
| 561 | G-10: benchmark run 6 | none (tracking; maintainer's run) | **1.0.x** (unless results arrive before W4 opens) | W4 (statement only) | stays open |
| 563 | RADIUS on request | none ("Not scheduled") | **1.0.x** (unscheduled, on request) | — | stays open |
| 564 | A locked account is refused before any verify (T-469) | Medium | 1.0.0 | W1.2 | W1 |
| 565 | No CRL; `tls_client_auth` reads no status (T-102) | Medium | 1.0.0 | W1.3 | W1 |
| 566 | No CIBA pending-request list | Low (a route and a badge; scheduled by the kickoff as a defect of an advertised feature) | 1.0.0 | W2.6 | W2 |
| 567 | Benchmark stacks publish ports on every interface | Low (local) | 1.0.0 | W2.9 | W2 |
| 568 | `rl-prod-check` has no row for eight limiter families | Low (local) | 1.0.0 | W2.9 | W2 |
| 569 | Stop grace vs shutdown + drain; `genhex` umask | Informational ×2 (local) | 1.0.0 | W2.5 | W2 |
| 588 | Contract 1.59 follow-ups (A1–A7, B1–B9) | none (contract questions) | 1.0.0 | W3 | W3 |

Count: **30** in `1.0.0` (one conditional), **5** in `1.0.x` (#513, #533, #538,
#561, #563). Of the 30, three (#541, #547, #548) close with this plan's pull
request, the first that cites them.

### 1.1 The sentence posted on each deferred issue

| # | Comment (posted 2026-10-09, one per issue) |
|---|---|
| 513 | "Milestone **1.0.x**: the code this submission depends on (#524, #526) ships in 1.0.0 (W1 of `claude_dev/release-1.0.0-plan.md`); the Basic OP and FAPI 2.0 runs, the sign-off table and the submission are the maintainer's and happen against the 1.0.0 release candidate, so this issue stays open past the tag." |
| 533 | "Milestone **1.0.x**: a Low finding whose fix is not local — a schema migration, an SDK-visible certificate field with contract text, and three revocation paths — so under the 1.0.0 triage rule (`claude_dev/release-1.0.0-plan.md` §1) it ships in a 1.0.x release; the CN / `metadata.user_id` convention stays documented as the 1.0.0 behaviour." |
| 538 | "Milestone **1.0.x**: an Informational coverage gap whose fix is not local — a Keycloak round trip in both SLO directions wired into CI's compose job — so under the 1.0.0 triage rule (`claude_dev/release-1.0.0-plan.md` §1) it ships in a 1.0.x release; the SLO paths keep their in-process tests." |
| 561 | "Milestone **1.0.x**: run 6 needs the maintainer's G-box numbers and is not a 1.0.0 blocker (`claude_dev/release-1.0.0-plan.md` §6). If the results arrive before the W4 pull request is opened, W6b rides in W4 and this issue closes with it; otherwise the website's benchmark page states that its numbers are run 5 against the versions it names." |
| 563 | "Milestone **1.0.x**, unscheduled: RADIUS stays on request, as this issue says (D-77). Its prerequisite, the CRL (#565), ships in 1.0.0." |

---

## 2. Wave W1 — security findings that must not ship in a 1.0

**Branch** `claude/release-1.0.0-w1`, one pull request (D-10 allows a split at
item boundaries past ~4 000 lines). **Model** Opus 5.5 for every item. Each
item lands with the tests its issue names and its threat-model entry flipped in
the same commit; each threat-model change bumps the model's minor version and
regenerates `website/src/threatModel.ts` / `threatModelSummary.ts`.

| Task | Issue | Scope | Threat model |
|---|---|---|---|
| W1.1 | #549 | `GET /api/v1/device/verify` and `POST /api/v1/device/decide` refuse a token carrying `client_id` with `403` (P23W5-04's rule); test with a code-grant token; contract and OpenAPI note the `403` | T-447 → Mitigated |
| W1.2 | #564 | the lockout branch of `AuthService::login` and every refusal of gRPC `ValidateCredentials` run `equalising_dummy_verify` under the same permit; `a_locked_account_needs_the_hash_permit_an_unknown_name_needs` and its gRPC twin | T-469 → Mitigated; T-30 residual removed; the website's SEC-026 claim true again |
| W1.3 | #565 | a CRL per issuing CA at an unauthenticated, rate-limited `GET` (RFC 5280 profile, signed through the custodian, `nextUpdate`, caching headers, the CRL distribution point in every certificate issued afterwards); `tls_client_auth` refuses a non-`Active` leaf by fingerprint lookup. CRLs in the rustls verifiers and OCSP are `1.0.x` (D-6). OpenAPI; an informative CONTRACT section | T-102 → Mitigated |
| W1.4 | #517 | client deletion calls `revoke_all_for_client` first; the CIMD re-materialisation test | T-289, T-272 … T-280 amended |
| W1.5 | #518 | `actor_token` bound to the exchanging client: its `azp`/`client_id` must be the authenticated client (option 1, D-5); `docs/guides/identity-for-agents.md` | new entry or amendment as the review finds |
| W1.6 | #519 | `AuthService::refresh` uses `account_may_act`; the pending-account refresh test | T-160 amended |
| W1.7 | #523 | tenant deletion: tombstone, revoke sessions and refresh tokens in the request, purge every tenant-scoped table from the cleanup job in user-erasure order; keep the system-log row; correct the handler comment; the populated-tenant test (D-4) | entry for tenant deletion |
| W1.8 | #529 | tenant email provider through the directory connector's address guard (resolve once; refuse loopback, link-local, metadata, own listeners; private only under the operator allow-list; pinned address); `api_url` through `guarded_fetch`; a generic test-endpoint error; a limiter on the test route | T-300 family |
| W1.9 | #520 | `claims.id_token.sub` honoured on the honour lane, refused on `fapi2`; `account_may_act` in UserInfo and introspection; stored ∩ client scopes at refresh | T-289, T-55 |
| W1.10 | #532 | `/oauth2/authorize`, both mounts, under the browser-endpoint preset in bucket `oauth2_authorize`; `429` tests; `rate-limit-sizing.md` | — |
| W1.11 | #531 | the SP verifier takes the receiver's SHA-2 allow-list and refuses markup declarations before parsing; SHA-1 refused in 1.0.0 as a documented behaviour change with a per-federation `allow_sha1_signatures` (false by default, audited when set) (D-3) | SAML SP entries |
| W1.12 | #525 | an omitted SMTP password kept only when host, port and TLS mode are unchanged, both scopes | — |
| W1.13 | #524 | a `require_par` client's unpushed request refused before the login hop, in place, never a redirect; anonymous-browser tests on both paths; `REVIEW-JUDGEMENTS.md` open point 6 updated | — |
| W1.14 | #526 | `revocation_endpoint_auth_methods_supported` and `introspection_endpoint_auth_methods_supported` published; `phone_number_verified_at` cleared in `UserRepository::update` when the number changes | — |
| W1.15 | #530 | optional metadata signing certificate; parsed-metadata cache honouring `validUntil`/`cacheDuration` under a cap; SSO-host-change audit | SAML SP entries |
| W1.F4 | — | F4 security review of the wave diff against `threat-model-stride.md`; findings filed on `1.0.x` unless Medium or higher (those are fixed in the wave) | as found |

**Closes:** #549, #564, #565, #517, #518, #519, #523, #529, #520, #532, #531,
#525, #524, #526, #530.

## 3. Wave W2 — durability, operations and the CIBA gap

**Branch** `claude/release-1.0.0-w2`, one pull request. **Model** Sonnet 5.5,
Opus 5.5 where marked.

| Task | Issue | Scope | Model |
|---|---|---|---|
| W2.1 | #550 | per-target breaker in the SCIM deliverer (threshold 5; `Retry` without a network call inside the backoff); the loopback tarpit test and the 10 001-member dead-letter test. The per-target concurrency budget is `1.0.x` | Opus 5.5 |
| W2.2 | #551 | a per-(tenant, rule, event) notification window on the request path, claimed in the datastore like D-73, configurable with a safe default, the next mail carrying the suppressed count; closes T-117 | Opus 5.5 |
| W2.3 | #553 | a counter of dropped and failed request-audit entries in `/health/jobs`, an operator signal when it moves, request rows routed to the T19.27 dead-letter file; T-108 re-closed with text matching the code | Sonnet 5.5 |
| W2.4 | #552 | the dead-letter file mounted and set in `docker-compose.prod.yml` and `k8s/server/deployment.yml`; a boot warning when unset; `append_gdpr_audit` through the dead-letter writer, a test per action | Sonnet 5.5 |
| W2.5 | #554, #569 | the four `process::exit(1)` calls through the orderly stop; tonic given a shutdown future awaited before the audit drain; `shutdown_timeout` explicit and the compose `stop_grace_period` above shutdown + drain + margin, documented together; `genhex` under `umask 077` | Sonnet 5.5 |
| W2.6 | #566 | `GET /api/v1/ciba/requests?status=pending` for the signed-in user (console sign-in only, its own `ciba_approval_per_min` bucket, CSRF, the version read, the deciding session audited) and the console badge; the issue's three tests | Sonnet 5.5 |
| W2.7 | #535 | the five cleanup jobs registered in `SWEEP_JOBS` when their feature is on; the source-scan pin | Sonnet 5.5 |
| W2.8 | #555 | `expected_updated_at` on `ScimTargetInput` (additive; §31 and the SDKs in W3); `guarded_fetch_no_redirect` for the webhook deliverer with a CHANGELOG note; `fapi-conformance.yml` gated on a machine-readable summary and `inputs.axiam_image` through `env:`; terminal `delivery_abandoned` audit rows for the in-process dispatcher's lost deliveries; the CONTRACT §8 note; the `AXIAM__AUTH__PEPPER` log line | Sonnet 5.5 |
| W2.9 | #568, #567 | a row per missing limiter family (`scenario: None`) and the self-test over every `*_per_min` field; `${BENCH_BIND_ADDR:-127.0.0.1}:` on every published port, `0.0.0.0` in `fapi-conformance.yml` and the runbook, the self-test | Sonnet 5.5 |
| W2.10 | #536 | the `saml_idp_enabled` / `ssf_enabled` settings controls (both scopes, layered state) and the SSF streams page; vitest and the Playwright permission matrix — last in the wave; moved to `1.0.x` if not ready when the rest is (D-8) | Sonnet 5.5 |
| W2.F4 | — | F4 security review of the wave diff | Opus 5.5 |

**Closes:** #550, #551, #553, #552, #554, #569, #566, #535, #555, #568, #567,
#536 (if it ships).

## 4. Wave W3 — contract 1.60 and the eleven SDK ports

**Model** Sonnet 5.5. One pull request in `axiam` (branch
`claude/release-1.0.0-w3`), then one per SDK repository (branch
`claude/contract-1.60-sync`), each vendoring from the `axiam` W3 head. The
kickoff asks that each SDK port start from the `axiam` merge commit; the agent
cannot merge, so the ports vendor the W3 head and the PR bodies say which commit
they vendored; the drift job re-checks after the merge.

Contract **1.60** is clarification and additive only:

- the answers to every question in **#588** (A1–A7, B1–B9), each one sentence
  an implementer can test; A6 binds C#, C and C++ to a fresh connection per
  never-retried write (`CURLOPT_FRESH_CONNECT` + `CURLOPT_FORBID_REUSE`; a
  non-pooled handler for writes in C#); B1 makes the replay store fallible
  (breaking Rust's `ReplayStore`, D-7); B2 says a successful cold fill does not
  count toward the once-a-minute limit;
- §31's additive `expected_updated_at` (#555), the `403` on the device approval
  routes (#549), the §8 minimal-profile note (#555), the CRL route as an
  informative section (#565), the `allow_sha1_signatures` federation field
  (#531); no `user_id` certificate field (#533 is `1.0.x`);
- §29.10 … §33.10 and a new §34.4 recording which SDK fixed which row.

`sdks/openapi.json` and `sdks/management-registry.json` regenerated (`protoc`,
the swagger placeholder, `cargo build -p axiam-server --no-default-features`,
`--dump-openapi`, `scripts/check-spec-digest.py`). Per SDK: re-vendor
`CONTRACT.md`, `openapi.json`, `management-registry.json`, `proto/`; regenerate
the §27 surface with the drift job green; fix the rows 1.60 assigns (A2 Go; A3
Python, TypeScript, Kotlin; A4 Swift; A6 C#, C, C++; A7 PHP; B1 Rust and every
SDK whose replay store answers a `bool`); README conformance statement at
**1.60**; `## [Unreleased]` rewritten as the `[1.0.0]` section it becomes. Every
contract error is reported as a question on the `axiam` W3 PR, never worked
around.

**Closes:** #588.

## 5. Wave W4 — release readiness

**Branch** `claude/release-1.0.0-w4`, one pull request, opened last. **Model**
Sonnet 5.5.

| Task | Scope |
|---|---|
| W4.1 | The beta wording, rewritten to what 1.0.0 claims (D-1): `README.md`, `SECURITY.md` (supported `1.0.x`, latest patch only; the caution about no independent penetration test kept, the word beta gone), `docs/README.md`, the `**Milestone:** … — Beta` headers, the FINDINGS / ASVS "Beta ships with no known High holes" lines (re-verified, dated), `website/src/security.ts`, `data.ts`, `docs/getting-started.ts`, `pages/Roadmap.tsx`, the SDK READMEs' prerelease lines, `docs/deployment/README.md` on the `latest` tag |
| W4.2 | The platform CHANGELOG `## [Unreleased]` as the `[1.0.0]` narrative (semver promise, the beta line in one paragraph, W1–W3 by section, the behaviour changes an upgrader must read, the `1.0.x` deferrals with issue numbers); the heading left for the script |
| W4.3 | **Phase 24 — 1.0.0 release** in `roadmap.md` (tasks, status, summary row, total); the website roadmap's phase 20 `focus` extended and a 1.0.0 row |
| W4.4 | The website: "AXIAM 1.0.0" news post (date placeholder, D-2; `App.tsx` default `postSlug`), the SDK reference page at contract 1.60, `API_VERSION` left to the script; `SECURITY_VERIFIED_RELEASE` / `DOCS_VERIFIED_RELEASE` and the handoff block of `threat-modeling-and-security.md` moved to `1.0.0` **only in the final verification pass against the release-candidate commit** |
| W4.5 | The threat model, one pass after W1 and W2: every entry a wave flipped, the JSON, the STRIDE document, the two generated files, the version, the generator's totals line quoted in the commit; §8 of the close-out plan re-run |
| W4.6 | The release pipelines read for the first stable tag (`release.yml`, `release-opaque.yml`, each SDK's publish job): what a tag without `-` does that a beta did not; fix what would fail or mislabel; findings in §9 below |
| W4.7 | `mass-tag.sh` **dry run only**, all twelve clones; the planted-orphan check on a throw-away clone; the script fixed where it is wrong for a non-prerelease version; the exact command in §10 |
| W4.8 | The regression gate, each exit code from the tool, in §9 |
| W4.9 | The hand-off, §10 |

---

## 6. What is deferred, and said so in public

- **#513** (the certification submissions) and the sign-off table in
  `docs/conformance/REVIEW-JUDGEMENTS.md` are the maintainer's; the code side is
  W1's #524 and #526. The issue stays open past the tag.
- **#561** (run 6 and the seventh benchmark draft) needs the G-box numbers; not a
  1.0.0 blocker. If results arrive before W4 is opened, W6b rides in W4;
  otherwise the website benchmark page states that its numbers are run 5 against
  the versions it names.
- **#533** and **#538** go to `1.0.x`; **#563** stays open on request,
  unscheduled.
- Carried into `1.0.x` from items that ship: the SCIM per-target concurrency
  budget (#550), CRLs in the rustls verifiers and OCSP (#565), `may_act`
  (#518).
- The compliance matrices, the security page and the 1.0.0 post name every
  deferred item by issue number. The caution about no third-party audit stays
  verbatim.

## 7. Rules that bind every wave

- `CLAUDE.md` in full: signed commits; pull requests by the agent on behalf of
  the maintainer with issue references; `cargo clean` between plan steps;
  narrowly scoped cargo commands; the swagger placeholder and `protoc` before any
  server build; `--no-default-features` where libxml2 is absent; exit codes from
  the tool, never a pipeline; no `[lints] workspace = true` on an undocumented
  crate; the crate-layering table for any new crate.
- Phase 23 plan §7: every new route carries a limiter from its first commit;
  every approval surface takes a console sign-in only; every credential-bearing
  outbound request uses `guarded_fetch_no_redirect`; every refusal of a
  credential check costs one verify; every two-writer registry is written
  conditionally on the version read.
- Nothing enters the threat model without the test its mitigation names; a
  correction is recorded as a correction.
- Where this plan and a file disagree, the file wins and the commit body says so.

## 8. Decisions requested from the maintainer

**Taken 2026-10-09: the maintainer accepted every recommendation (D-1 … D-10).** D-2's date stays a placeholder until the tag; D-8 is still decided at the end of W2 by its own rule; D-11 is the one action left to the maintainer.

| # | Question | Recommendation | Status |
|---|---|---|---|
| D-1 | What `1.0.0` claims in `README.md`, `SECURITY.md` and the website | "First stable release. REST, gRPC, AMQP and the SDK contract are under semantic versioning from here; security fixes ship in `1.0.x`. No independent third-party audit has been performed; the shared-responsibility checklist applies." No "production-ready" sentence the security page would contradict | accepted |
| D-2 | The release date on the 1.0.0 post and in the sign-off table | The day of the tag; W4 leaves a placeholder | accepted |
| D-3 | #531: refuse SHA-1 in 1.0.0 with an audited per-federation escape hatch | Yes | accepted |
| D-4 | #523: hard cascade or tombstone-and-purge | Tombstone, revoke in the request, purge from the cleanup job in erasure order | accepted |
| D-5 | #518: option 1 (`azp` must be the authenticated client) | Yes; `may_act` later | accepted |
| D-6 | #565: fingerprint lookup in `tls_client_auth` now; CRLs in the rustls verifiers and OCSP in `1.0.x` | Yes | accepted |
| D-7 | #588 B1: a fallible `ReplayStore` across the SDKs, breaking Rust's trait at 1.0.0 | Yes; a 1.0 is the last cheap moment | accepted |
| D-8 | #536 in 1.0.0 or `1.0.x` | 1.0.0 if W2 is otherwise ready, else `1.0.x` | accepted; applied at the end of W2 |
| D-9 | All eleven SDKs tagged `v1.0.0` in the same run as the platform | Yes, `--repos all`; the website SDK page says "released" only after | accepted |
| D-10 | W1 and W2 split into more than one PR each past ~4 000 lines | Yes, by item boundary, each PR with its own issue list | superseded: one pull request for all waves (maintainer, 2026-10-09) |
| D-11 | Create the milestones `1.0.0` and `1.0.x` and apply §1's column (the session cannot) | Yes | **maintainer action** |

## 9. Verification

Per wave (each exit code taken from the tool, not a pipeline):

```bash
export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
cargo fmt --all --check
cargo clippy -p <crate> --all-targets --no-default-features -- -D warnings   # per touched crate
cargo test -p <crate> --test <binary>                                         # per touched test binary
python3 scripts/check-crate-layering.py
python3 scripts/check-spec-digest.py
node website/scripts/gen-threat-model.mjs && git status --short   # generated files committed, no diff
```

The threat-model invariant (close-out plan §8, numbers updated per wave):

```bash
python3 - <<'EOF'
import json, collections
m = json.load(open('ThreatDragonModels/Axiam/Axiam.json')); d = m['detail']
nums = collections.Counter(); st = collections.Counter()
for dg in d['diagrams']:
    for c in dg['cells']:
        for t in c.get('data', {}).get('threats') or []:
            nums[t['number']] += 1; st[t['status']] += 1
top = d['threatTop']
assert sorted(nums) == list(range(1, top + 1)) and max(nums.values()) == 1
print(m['version'], top, dict(st))
EOF
```

W4 fills in: the regression-gate table (W4.8, §9.2) and the release-pipeline
findings (W4.6, §9.1).

### 9.1 The release pipelines, read for the first stable tag (W4.6)

A tag with no `-` segment is the first one these pipelines have seen. What it does
that a beta tag did not, and what was changed so it does it correctly:

| Pipeline | A stable tag | Finding | Change |
|---|---|---|---|
| `release.yml` image scan | Gates on HIGH/CRITICAL | **The beta17 and beta18 server releases failed here.** `trivy-action` in SARIF mode drops the severity filter, so `exit-code: 1` fired on MEDIUM/LOW (`libssl3`, `tzdata` in the distroless base; reproduced locally with the pinned trivy 0.70.0). Nothing in the image is HIGH/CRITICAL. | `limit-severities-for-sarif: true` (a6584ba) |
| `release.yml` GitHub Release | `prerelease=false`, `make_latest=true` | Every beta took "Latest". | `prerelease`/`make_latest` from the tag (3f74053) |
| `release.yml` images | `1.0.0`, `1.0`, `latest`, `sha-…` | Correct already. | — |
| `release.yml`, `release-opaque.yml` | — | No check that the tag equals the declared versions. | `verify-tag-on-main` refuses a mismatch before any build or publish (a2334a1) |
| `release-opaque.yml` GitHub Release | never "Latest" | The opaque release held "Latest" (a library bundle). | `make_latest: false`; prerelease from the stripped tag (3f74053) |
| `release.yml` git-cliff `--latest` | Notes = commits since `v1.0.0-beta18` | A delta, not 1.0 notes (beta19 was never tagged). | Maintainer's choice: `body_path` to hand-written notes (§10) |
| `scripts/mass-tag.sh` | Bumps every declared version | The C++ overlay port `ports/axiam-cpp-sdk/vcpkg.json` was never bumped (stuck at `1.0.0-alpha8`). | Every `ports/*/vcpkg.json` is bumped (627dc83); the port corrected in the C++ SDK PR |
| Python SDK publish | PyPI `1.0.0` | No check that the tag equals `pyproject.toml`. | Tag-vs-version assertion (axiam-python-sdk c704a0b) |
| Python SDK metadata | — | `Development Status :: 2 - Pre-Alpha`. | `5 - Production/Stable` (Python SDK PR) |
| TypeScript SDK, `@axiam/opaque-wasm` | npm `latest` | Correct (dist-tag from the version). README badge and `@beta` install were stale. | README rewritten (TypeScript SDK PR) |
| PHP SDK | Packagist from the tag | `branch-alias dev-main: 0.x-dev`. | `1.x-dev` (axiam-php-sdk 1fb1f73) |
| Java, Kotlin (Maven Central), C# (NuGet), Go (`v1.0.0`, no `/vN`), Rust (crates.io, tag check present), C/C++ (Conan, vcpkg) | Publish `1.0.0` | No failure on a stable version. | — |
| Swift | SwiftPM from the tag | The CocoaPods podspec is versioned but never published, while the README shows a `pod` line. | Maintainer's choice (§10) |

Not verifiable from the sandbox: the full server image scan (no Docker daemon) and
the publish jobs themselves; the first stable tag is their first real run.

## 10. Hand-off (written by W4)

For the maintainer, in order. Nothing below has been done by the session: no tag,
no merge, no conformance run, no benchmark run.

1. **Decide the open items.** Milestones `1.0.0` / `1.0.x` and the D-11 issue
   moves (§8). The release date (D-2): fill `2026-MM-DD` / `2026-MM` in the
   "AXIAM 1.0.0" post in `website/src/data.ts`. `website-publish.yml` deploys on
   every push to `main`, so the post and the "first stable release" wording go live
   when #589 merges — merge it on, or just before, the tag day.
2. **Merge #589** (platform), then the eleven SDK PRs (§11). Each SDK vendors the
   platform's artefacts at 8df0e11; `sdk-artifact-drift.yml` compares them with
   `main` and stays red until both sides are merged.
3. **Pull `main` in all twelve clones**, each unshallowed with tags
   (`git fetch --unshallow --tags` where needed): the changelog ranges start at
   `v1.0.0-beta18` (platform) and `v1.0.0-beta17` (SDKs).
4. **The dry run**, from the platform clone, and read it:
   ```bash
   scripts/mass-tag.sh --repos all --branch main --tag v1.0.0 \
     --message "AXIAM 1.0.0" --changelog --pull --dry-run --root <dir holding the 12 clones>
   ```
   W4.7 ran it against throwaway copies of the final branches (exit 0, all 13
   targets; log in the session's scratchpad `w47-dry6.log`): every manifest, the
   spec re-stamp and registry, `API_VERSION`, both k8s tags, the C++ vcpkg port;
   exactly one empty `## [Unreleased]` per repo with the hand-written prose kept
   as written. `--repos all` includes `axiam-opaque`: it tags
   `axiam-opaque-v1.0.0` and publishes the OPAQUE crates and npm package at 1.0.0
   — leave it out if that should wait.
5. **Conformance.** Build the release-candidate image from `main`, run the OpenID
   Basic OP and FAPI 2.0 suites per
   [`fapi-conformance-runbook.md`](fapi-conformance-runbook.md), and fill the
   sign-off table in `docs/conformance/REVIEW-JUDGEMENTS.md` (#513 stays open for
   the certification submissions). The FAPI registrar now imports its client CA
   into the test organization (R1W1-02); this is its first run with that change.
6. **The final verification pass**, on the release-candidate commit, as a small PR:
   move `SECURITY_VERIFIED_RELEASE` and `DOCS_VERIFIED_RELEASE` to `"1.0.0"`,
   restamp the handoff block in `claude_dev/threat-modeling-and-security.md`
   (model 2.40.0) and the docs "Last verified" lines — only for what was checked.
7. **The real run**, platform first: the same command without `--dry-run`.
8. **Watch the twelve release pipelines and the `latest` tags.** `release.yml`
   should publish `1.0.0`, `1.0` and `latest` images and a non-prerelease GitHub
   Release marked Latest; `release-opaque.yml` a release that is never Latest;
   each SDK its registry (§9.1). The release body is git-cliff's delta since
   `v1.0.0-beta18` — point `body_path` at hand-written notes if you want the 1.0
   summary there instead.

**Upgrade notes that need an operator** (also in the CHANGELOG's "Upgrading from
the beta line"): `tls_client_auth` clients whose CA is trusted only through
`AXIAM__SERVER__TLS__CLIENT_CA_PATH` need that CA imported, keyless, into their
organization (R1W1-02); a Vault token needs `update` on `pki_int/revoke` (T-470);
SAML IdPs signing with SHA-1 need `allow_sha1_signatures` until moved (#531);
webhooks behind redirects must be re-registered (#555); give the server a 40 s
stop grace (#569); private SMTP relays need `AXIAM__EMAIL__ALLOWED_PRIVATE_NETWORKS`
(#529); replay the k8s dead-letter file before a rollout (#552).

**Known, not blocking, for 1.0.x:** the F4 follow-ups #590 – #614; a pre-1.0
server omits `NotificationRuleResponse.window_minutes`, which the SDKs require
(a contract "absent reads 15" sentence would let them read old servers); Java's
generated records have positional constructors, so an additive member breaks a
direct constructor call (the README points at the builders); the distroless base
should move once a build ships libssl3 3.0.22; `crates/axiam-opaque-wasm/Cargo.lock`
and the C/C++ `Doxyfile` `PROJECT_NUMBER` still name beta07; the Rust SDK tracks
`vendor/axiam-opaque/target/` (kept out of the published crate by its `include`
list); the Swift podspec is versioned but never published to CocoaPods while the
README shows a `pod` line.

## 11. Wave results

On the maintainer's instruction (the Docker Hub pull limit made per-wave PR CI
unreliable), W1 … W4 landed on one branch, `ccr-7ed2207b-ouofu1`, and ship as
**one platform PR, #589**; each SDK has its own PR.

| Wave | Where | Closes | Left to the next wave / to 1.0.x |
|---|---|---|---|
| Plan | #589 | #541, #547, #548 | — |
| W1 — security | #589 | #549, #564, #565, #517, #518, #519, #523, #529, #520, #532, #531, #525, #524, #526, #530 | F4 review: R1W1-01 (Medium) and R1W1-02 (High) fixed in 1.0.0 (0b2bddf, adb1df4, T-475); R1W1-03 … 13 filed as #601 – #611; #612 – #614 filed from the wave's residuals |
| W2 — durability, operations, CIBA | #589 | #550, #551, #553, #552, #554, #569, #566, #535, #555, #568, #567, #536 | F4 review: R1W2-01/02 (Medium) fixed; R1W2-03 … 14 filed as #590 – #600 |
| W3 — contract 1.60 | #589; SDK PRs below | #588 | Contract 1.60 in four passes; SDK artefacts vendored at 8df0e11 |
| W4 — release readiness | #589 | — | §10 |

SDK PRs (contract 1.60, README stable, `[Unreleased]` written as the 1.0.0 section;
each merges after #589): axiam-rust-sdk#125, axiam-typescript-sdk#133,
axiam-python-sdk#95, axiam-java-sdk#110, axiam-kotlin-sdk#74,
axiam-csharp-sdk#103, axiam-php-sdk#80, axiam-go-sdk#95, axiam-swift-sdk#72,
axiam-c-sdk#71, axiam-cplusplus-sdk#73.

Deferred, said so in public (§6): #513 (certification submissions, stays open past
the tag), #561 (benchmark run 6), #533, #538 (1.0.x), #563 (RADIUS, on request).

---

## 12. Kickoff prompts

### W1

> Read `CLAUDE.md`, this plan §0–§2 and §7, and
> `claude_dev/security-review-phase23-w6-2026-10-06.md` §15. Check out
> `claude/release-1.0.0-w1` from `main`. Execute W1.1 … W1.15 in order, one
> signed commit per item (two where the threat-model flip is its own commit),
> each with the tests its issue names and its threat-model entry flipped in the
> same commit; run the crate's fmt, clippy and the touched test binaries before
> each commit and `cargo clean` between items. End with the F4 review of the
> wave diff in `claude_dev/security-review-release-1.0.0-w1-<date>.md`; file its
> Low and Informational findings on `1.0.x`, fix Medium and higher in the wave.
> Open one PR, `Closes` the fifteen issues, record it in §11.

### W2

> Read `CLAUDE.md`, this plan §0, §1, §3 and §7, and
> `claude_dev/audit-durability-review-minimal-profile-2026-10-05.md`. Check out
> `claude/release-1.0.0-w2` from `main`. Execute W2.1 … W2.10 in order (W2.10
> last; move it to `1.0.x` with a comment if the rest is ready first), one signed
> commit per item, the same per-commit checks as W1. End with the F4 review.
> Open one PR, record it in §11.

### W3

> Read `CLAUDE.md`, this plan §4, `sdks/CONTRACT.md` §34 and issue #588. Check
> out `claude/release-1.0.0-w3` from `main` with W1 and W2 merged in (or from
> their branches, merged, if they are not yet on `main`). Write contract 1.60,
> regenerate the spec and the registry, open the `axiam` PR. Then, per SDK
> clone, branch `claude/contract-1.60-sync`, re-vendor, regenerate §27, fix the
> rows 1.60 assigns, bring the README to 1.60 and rewrite `## [Unreleased]` as
> the `[1.0.0]` section; run the SDK's own build and tests; open the PR.

### W4

> Read `CLAUDE.md`, this plan §5, §6, §8 and §9. Check out
> `claude/release-1.0.0-w4` on top of W3. Execute W4.1 … W4.9; never run
> `mass-tag.sh` without `--dry-run`. Fill §9's tables and write §10. Open the PR
> last.
