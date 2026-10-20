# Release 1.1.1 plan — the `1.1.x` milestone: the 1.1.0 review findings, contract 1.63, the SDK follow-ups and the RADIUS profile names

> **Status: READY — every decision in §11 has a default the orchestrator
> applies unless the maintainer answers otherwise.** Written 2026-10-19 against
> `main` at `6b7b258` (three website commits after the `v1.1.0` tag at
> `029a2d7`). It covers the **67 open issues** on the `1.1.x` milestone:
> **53 on `ilpanich/axiam`** (#664 … #719, less #700 and #701, closed, and the release PR #716) plus
> **#513** and **#561**, which stay the maintainer's (§0.3), and **12 on the
> eleven SDK repositories** (one each, two on Python). Every one of the 67 is on
> milestone `1.1.x` since 2026-10-19; the SDK milestones were empty until then.
>
> **Why 1.1.1.** Nothing here adds a route. The waves close the Low and
> Informational findings the 1.1.0 reviews filed, the contract items 1.62
> deferred to 1.63, the SDK conformance follow-ups, and one request of the
> maintainer's: the two FreeRADIUS profiles lose their design-note names
> **D3** and **D4** for human-readable ones (W5.1, decision D-1). Two
> additive migrations (v108, v109) and one new configuration key
> (`AXIAM__RATE_LIMIT__TRUSTED_PROXIES`) are what 1.0.1 and 1.1.0 also
> allowed in a patch.
>
> **Shape.** Eight waves. W1 … W6 are independent and branch from `main`;
> W7 (contract 1.63, the eleven SDK re-syncs and their issues) needs every
> wave that changes the spec; W8 (release readiness) needs everything. As
> for 1.1.0, the waves merge into one plan branch, `claude/release-1.1.1`,
> and **one pull request** closes every `ilpanich/axiam` issue on a `Closes`
> line. The eleven SDK repositories get one pull request each, closing their
> own issue(s).
>
> **Execution.** One **Opus 5.5 orchestrator** session runs the plan. It
> spawns one executor per task at the model its row names (§1.1), runs the
> gate of §10 before every commit, and ends each wave but W6 with an F4
> security review of the wave diff (Opus 5.5). The orchestrator writes code
> only to resolve a merge; everything else is an executor's. Every commit is
> signed; nothing is closed by hand.
>
> **Two rules this plan adds to 1.1.0's (§1.2, §1.3).** Test coverage may
> not go down: every fix carries the test its row names, and W8.5 reads the
> two coverage figures before the PR. Documentation moves with the code:
> every row names the documents it touches, and a task is not done while
> any of them says what the tree no longer does.
>
> **What the agent does not do.** It does not tag, does not merge, does not
> run the conformance suites, does not dispatch benchmark runs, and does not
> answer a contract question on its own: every question is in §11, with a
> default.

---

## 0. The state, measured (2026-10-19)

Verified on the tree, not taken from the issues. Where an issue and the tree
disagree, the tree wins and the task says so (§0.1).

| Fact | Measured | Evidence |
|---|---|---|
| Platform version | `1.1.0`; tag `v1.1.0` at `029a2d7`; `main` at `6b7b258` carries three website fixes on top of it | `Cargo.toml:62`; `git ls-remote --tags origin` |
| CHANGELOG | `## [Unreleased]` empty; `## [1.1.0] - 2026-10-16` | `CHANGELOG.md:8-10` |
| Contract | **1.62**; its record is **§34.6**; §34.6 (ae) lists what is "Deferred to contract 1.63" (Q4, Q7); next record **§34.7** | `sdks/CONTRACT.md:13167,13368` |
| Threat model | **2.42.0**, 487 threats, next free id **T-488** | `ThreatDragonModels/Axiam/Axiam.json:2`; `claude_dev/threat-model-stride.md:8-12` |
| Schema | newest migration **v107**; next **v108**; the newest-version assertion must be bumped with each | `crates/axiam-db/src/schema.rs:7020` |
| Coverage | Rust: `cargo-llvm-cov` → Coveralls on every push and PR (no threshold in CI; `just coverage-gate` defaults to 80). Frontend: vitest `thresholds.lines: 96.1` (1.1.0's W8.1 measured 96.57 %) | `.github/workflows/coverage.yml`; `frontend/vitest.config.ts:29-31` |
| RADIUS profile names | `D3` / `D4` appear in `docs/pki/freeradius.md` (40 lines), `docker/radius/README.md` (16), `docker/radius/raddb/{eap,d4/*}`, `docker/docker-compose.radius{,-d4}.yml`, `crates/axiam-server/tests/radius_e2e.rs` (50), `.github/workflows/radius-e2e.yml` (4), `docs/deployment/README.md:956`, `website/src/docs/operate.ts` (22, among them the headings "Two profiles: D3 and D4", "D3: the placement table", "D4: network segments"), `website/src/security.ts` (3), the decide handler's doc comment (hence `sdks/openapi.json`, `sdks/management-registry.json` and the generated `website/src/apiIndex.ts`), contract §36 (3), the STRIDE note and `Axiam.json` (31 each) and four console **comments** (`navSections.tsx:305`, `services/network.ts:5`, `router.test.tsx:40`, `lib/queryInvalidation.ts:142`). **The console shows no `D3`/`D4` string to a user today**; the `D3`/`D4`/`D5` of `frontend/src/pages/settings/*` and `services/settings.ts` are the DCR/CIMD policy decisions of another plan and are **not** RADIUS | `grep -rn -E '\bD[34]\b'` over the tree |
| Open issues | axiam 55 (53 on `1.1.x`, #513 and #561 moved from `1.0.x` to `1.1.x` on 2026-10-19); SDKs 12 (all on each repository's `1.1.x`, set 2026-10-19) | GitHub |
| Open PRs | none on `ilpanich/axiam` | GitHub |
| SDK heads | the eleven contract-1.62 PRs are merged (e.g. ilpanich/axiam-typescript-sdk#141); each `CHANGELOG.md` opens with an empty `[Unreleased]` | each SDK clone |

### 0.1 Where the issues and the tree disagree

| # | What the issue says | What the tree says | Consequence |
|---|---|---|---|
| 715 (a) | the `Service-Type` description should say `403` "until #700 decides" | #700 was closed 2026-10-17 with a **`400`** refused before H1 (rule `3.3:admin-class`); `radius_reply.rs:251-252` already says "refused with a 400" | (a) is **verify and record** (W4.7); no edit unless the spec text drifted |
| 675 | three items: the upgrade note, a boot warning, a `PUT` to public | (1) was written by 1.1.0's W8.4; (2) exists — #712 is about that very count | only (3) remains (W3.1, decision D-4) |
| 686 | "`TRUSTED_HOPS` at a value ≥ 1 (verify the default)" | the default is `0`, and at `0` the caller's entry is read too (#711, R110-01) | #686 is closed by #711's fix (W2.1); the executor corrects #686's body with one comment |
| 698 (a), (d) | the design note's tag text is W6's; the STRIDE summaries are W8.3's | both were taken in 1.1.0 (§13.6, §13.8 of its plan) | W5.8 verifies and keeps (b) and (c) only |
| 674 (h), 684 (g) | the website copy of the threat model is behind | regenerated by 1.1.0's W8.3 (`website/src/threatModel.ts` at 2.42.0) | not part of these issues; W8.3 regenerates once more after this release's entries |
| 689 | "under the next migration number" | the next number is **v108** | W1.7 takes v108; W3.3 takes v109 (§10) |
| 704 | "merge W1 before W6" | 1.1.0 merged in that order; v99 … v107 are recorded in sequence on `main` | the runner hardening and the contiguity test remain (W4.1) |
| 719 | close once `utoipa-swagger-ui` releases on `zip ≥ 9` | not verifiable from the tree | W6.3 checks the index once; if there is no release, the issue **stays open** and the PR does not name it (D-9) |

### 0.2 What this plan could not do

- It did not run the RADIUS end-to-end (no Docker in the planning sandbox).
  W5's oracle is `radius-e2e.yml` on the pull request, whose path filter
  covers every file W5 touches, plus `freeradius -XC` where Docker exists.
- It did not count current line coverage; the figures the gate compares
  against are 1.1.0's (§1.2).
- SAGE memory was not reachable from the planning session; nothing here
  comes from it.

### 0.3 Out of scope, and what each needs from the maintainer

| # | Title | What it needs |
|---|---|---|
| 513 | Phase 23 G-1: OpenID Basic OP and FAPI 2.0 certification submissions | the maintainer's runs and the submission; T23.1.4 … T23.1.7 are a Sonnet 5.5 audit session once the maintainer schedules it |
| 561 | Phase 23 G-10: benchmark run 6 | the G-box numbers of `claude_dev/run6-runbook.md` §12; W6b is one Sonnet 5.5 session once they exist |

Both carry the `1.1.x` milestone at the maintainer's request; neither is on
this plan's `Closes` line.

---

## 1. Scope — every open issue, one wave each

| # | Title (short) | Severity | Wave | Task | Size | Model |
|---|---|---|---|---|---|---|
| 664 | R110W1-04: the orphan-purge marker is recognised by an administrator-writable key | Informational | W1 | W1.1 | S | Sonnet 5.5 |
| 665 | R110W1-05: the Vault-reason sanitiser misses tokens inside a word | Informational | W1 | W1.2 | S | Sonnet 5.5 |
| 667 | The bootstrap and private-CA Vault clients have no request timeout | Informational | W1 | W1.3 | S | Sonnet 5.5 |
| 669 | A unique-serial violation surfaces as 500 instead of 409 | Informational | W1 | W1.4 | S | Sonnet 5.5 |
| 668 | The Art. 17 purge revokes at (b4) and anonymizes after it | Informational | W1 | W1.5 | S | Sonnet 5.5 |
| 714 | R110-04: an orphan purge cut before its guard holds the id for an hour | Low | W1 | W1.6 | M | **Opus 5.5** |
| 689 | R110W4-03: a unit that outlasts the whole window still loses its audit row | Informational | W1 | W1.7 | L | **Opus 5.5** |
| 687 | R110W4-01: a tenant purge cut at the teardown's bound waits out the hour | Informational | W1 | W1.8 | S | Sonnet 5.5 |
| 690 | R110W4-04: a dead-letter write that fails after its awaiter was cut is not logged | Informational | W1 | W1.9 | S | Sonnet 5.5 |
| 692 | R110W4-07: the lease-loss REST-cut test does not show the drain ran | Informational | W1 | W1.10 | M | Sonnet 5.5 |
| 666 | R110W1-06: text and tests behind the code after W1 | Informational | W1 | W1.11 | S | Sonnet 5.5 |
| 688 | R110W4-02: three absolutes in T-444 and the guide | Informational | W1 | W1.12 | S | Sonnet 5.5 |
| 717 | `vault_ca_key_store_test` failure messages print the asserted string | Low | W1 | W1.13 | S | Sonnet 5.5 |
| 711 | R110-01: every per-address limiter keys on a caller-written `X-Forwarded-For` | Low | W2 | W2.1 | M | **Opus 5.5** |
| 686 | Without a proxy, the limiters key on a caller-written entry | Low | W2 | W2.1 | — | (with #711) |
| 673 | R110W2-05: in-process rate-limit governors are never swept | Informational | W2 | W2.2 | M | Sonnet 5.5 |
| 718 | The cold-entry seed leaves a 30/min admin family 3 writes late in a minute | Low | W2 | W2.3 | S | Sonnet 5.5 |
| 685 | The public-client token bucket never refuses on its own | Informational | W2 | W2.4 | S | Sonnet 5.5 |
| 670 | R110W2-02: DPoP-scheme requests are not attributed by the audit middleware | Low | W2 | W2.5 | M | Sonnet 5.5 |
| 671 | R110W2-03: unbounded waiters on the shared crypto semaphore | Informational | W2 | W2.6 | M | Sonnet 5.5 |
| 672 | R110W2-04: the bucket-name scan sees only turbofish registrations | Informational | W2 | W2.7 | S | Sonnet 5.5 |
| 682 | R110W3-09: reserved audit actions can be imitated by lookalikes | Informational | W2 | W2.8 | S | Sonnet 5.5 |
| 674 | R110W2-06: text and pins behind the code after W2 | Informational | W2 | W2.9 | S | Sonnet 5.5 |
| 675 | R110W3-02: confidential device clients refused after the upgrade | Low | W3 | W3.1 | M | **Opus 5.5** |
| 712 | R110-02: #675's boot count reads the tenant table once per client | Low | W3 | W3.2 | S | Sonnet 5.5 |
| 676 | R110W3-03: the `rate_limit_bucket` sweep's cutoff is on the application clock | Informational | W3 | W3.3 | M | Sonnet 5.5 |
| 678 | R110W3-05: concurrent `bc-authorize` calls end in `server_error` | Informational | W3 | W3.4 | S | Sonnet 5.5 |
| 679 | R110W3-06: unknown-client refusals cost no verify outside the device grant | Informational | W3 | W3.5 | M | Sonnet 5.5 |
| 680 | R110W3-07: the admin `PUT` does not bound a self-registered client's grant types | Informational | W3 | W3.6 | S | Sonnet 5.5 |
| 681 | R110W3-08: device-grant tokens carry no `client_id`; DPoP refresh tokens unbound | Informational | W3 | W3.7 | M | **Opus 5.5** |
| 683 | R110W3-10: `/oauth2/device_authorization` requires a body `client_id` | Informational | W3 | W3.8 | S | Sonnet 5.5 |
| 705 | R110W6-08: a UMA resource server can change resources it did not register | Low | W3 | W3.9 | S | Sonnet 5.5 |
| 677 | R110W3-04: "a leaked device code is worth nothing" | Informational | W3 | W3.10 | S | Sonnet 5.5 |
| 684 | R110W3-12: text and hygiene after W3 | Informational | W3 | W3.11 | S | Sonnet 5.5 |
| 704 | R110W6-07: a datastore that recorded v100 without v99 never applies v99 | Low | W4 | W4.1 | M | **Opus 5.5** |
| 702 | R110W6-05: the organization's super-admin holds the network meta permissions everywhere | Low | W4 | W4.2 | M | Sonnet 5.5 |
| 703 | R110W6-06: a cleared network-sensitive write has no row of its own | Low | W4 | W4.3 | M | Sonnet 5.5 |
| 706 | R110W6-09: the decision's two cheaper paths; one is a cross-tenant signal | Informational | W4 | W4.4 | S | **Opus 5.5** |
| 708 | R110W6-14: a network 409's `reason_code` is derived from message text | Low | W4 | W4.5 | M | Sonnet 5.5 |
| 709 | R110W6-15: the console offers the profile editor without `network:grant` | Low | W4 | W4.6 | S | Sonnet 5.5 |
| 715 | R110-05: text the merged tree contradicts | Informational | W4 | W4.7 | S | Sonnet 5.5 |
| — | **The RADIUS profile names** (maintainer's request, 2026-10-19) | — | W5 | W5.1 | M | Sonnet 5.5 |
| 693 | R110W5-05: the RadSec block does not start | Informational | W5 | W5.2 | S | Sonnet 5.5 |
| 694 | R110W5-06: a killed run leaves its temporary files | Informational | W5 | W5.3 | S | Sonnet 5.5 |
| 695 | R110W5-07: staleness is measured on the file; a `304` exits 0 at any age | Informational | W5 | W5.4 | S | Sonnet 5.5 |
| 696 | R110W5-08: the fetch does not ask a cache to revalidate | Informational | W5 | W5.5 | S | Sonnet 5.5 |
| 697 | R110W5-09: the e2e path filter misses CRL and binding inputs | Informational | W5 | W5.6 | S | Sonnet 5.5 |
| 713 | R110-03: the e2e filter misses what the decision rests on | Informational | W5 | W5.6 | — | (with #697) |
| 707 | R110W6-10: the recipe keeps a refused token for half its life | Informational | W5 | W5.7 | M | Sonnet 5.5 |
| 698 | R110W5-10: stale or inconsistent text | Informational | W5 | W5.8 | S | Sonnet 5.5 |
| 699 | `bench-quick` on `p3-mtls` fails at k6 init | Low | W6 | W6.1 | S | Sonnet 5.5 |
| 691 | R110W4-05: the conformance workflow runs its `always()` steps after a refused input | Informational | W6 | W6.2 | S | Sonnet 5.5 |
| 719 | Drop the `zip` 8.6.0 audit ignores once `utoipa-swagger-ui` moves on | Low | W6 | W6.3 | S | Sonnet 5.5 |
| 710 | Contract 1.63: cookies on `/oauth2/*`, SCIM `expected_updated_at`, producer refusal | — | W7 | W7.1 | M | Sonnet 5.5 |
| SDK ×12 | the contract 1.62 conformance follow-ups (§8.2) | Low / Informational | W7 | W7.2 … W7.12 | S–M | Sonnet 5.5 |
| 513, 561 | §0.3 | — | — | — | — | maintainer |

### 1.1 How the model is chosen

The rule of the 1.0.1 and 1.1.0 plans, unchanged, so that the orchestrator
can re-derive it when a task turns out larger than sized. "Best but
cheapest" means the cheapest of the two that can be trusted with the row's
*definition*, not with its typing:

- **Opus 5.5** where the task *defines* behaviour under adversarial input
  or concurrency (a guard whose lifetime is the fix, a cancellation
  boundary, a migration runner, a token-binding rule), or where it changes
  the answer of an **authenticated oracle** (the decide route, W4.4), or
  where the issue proposes two designs and the executor has to choose on
  the evidence in the tree with a credential at stake (W3.1, W3.7). Every
  F4 review and the orchestrator are Opus 5.5.
- **Sonnet 5.5** where the issue already states the fix, the tree holds a
  precedent at a named `file:line`, and the oracle is a test the issue
  names. The recipe and script fixes (W5), the rename (W5.1), the SDK
  sessions (W7) and every text task are of this kind.

Expected cost, counted in executor sessions: W1 14 (three Opus, the F4
included), W2 10 (two Opus), W3 12 (three Opus), W4 8 (three Opus), W5 9
(one Opus), W6 3 (none; its review is W8.2's), W7 13 (one Opus), W8 5 (one
Opus). Roughly **74 sessions, 14 of them Opus**, plus the orchestrator. W1.7
and W3.7 are the long poles; W7's eleven SDK sessions run in parallel.

### 1.2 Test coverage: keep or improve

- Every row names its test. A code change without a test is not a commit;
  a text-only row says "none (text)" and names the checker that reads it.
- **Rust.** Coveralls reports the PR against `main`'s baseline (1.1.0). W8.5
  reads the Coveralls check on the plan PR: a decrease on any touched crate
  is a defect to fix before the review, not a note. Executors do not run
  `just coverage` per commit (too heavy for the sandbox); they run the
  touched test binaries, and W8.1 runs `cargo llvm-cov -p <crate>` on the
  crates whose coverage W8.5 questions.
- **Frontend.** `frontend/vitest.config.ts` `thresholds.lines` is 96.1 and
  the job prints the achieved figure. W4.6 adds tests; W8.5 raises the
  threshold to the achieved figure less 0.1 (the ratchet 1.1.0's comment
  asks for), never lowers it.
- **Scripts.** A shell or Python fix (W5.3 … W5.5, W6.2, W2.7) extends the
  script's own test (`fetch-crl-test.sh`, `validate_inputs_test.sh`, the
  `--self-test` of the Python checkers).

### 1.3 Documentation alignment

Each row names what it changes beyond code; the pattern is 1.1.0's:
`docs/` (the operator's and admin's guides), `website/src/docs/*.ts` (the
readable front door, which links out and duplicates nothing normative),
`sdks/CONTRACT.md` (W7.1 only), the threat model (the entry's own dated
text, in `threat-model-stride.md` and `Axiam.json`, reconciled once by
W8.3), `CHANGELOG.md` (one entry per closed issue, ending in its number;
W8.4 writes them from the §12 records) and the two generated spec files.
`scripts/check-doc-links.sh`, `check-remediation-evidence.py` and the
website's `tsc`/build are the oracles for text.

---

## 2. Wave W1 — PKI, Vault and the cleanup path (branch `claude/release-1.1.1-w1`)

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W1.1 | **#664.** Recognise the orphan marker by what no API writes — `organization_id = <nil>` and the `orphan-purge-<id>` slug — in both reads (`purge_tombstoned`, `purge_orphan`); the `metadata.orphan_purge` key is no longer consulted. Refuse `orphan_purge` in tenant `metadata` on create and update (`422`), since it has no other meaning. | `crates/axiam-db/src/repository/tenant.rs:335-350,494-510`; `handlers/tenants.rs`; `docs/admin/README.md` (tenant metadata) | `tenant_purge_test.rs`: a tenant whose metadata carries `orphan_purge: true` is purged as `Tombstoned` (receipt honoured, `orphan: false`); the orphan tests still pass; the metadata key is refused | S | Sonnet 5.5 |
| W1.2 | **#665.** `sanitise_reason` masks a token at any position preceded by a non-token character (`=`, `"`, `:`, `'`, start), the span only; the legacy `s.` / `b.` prefixes require a body without `.`. Amend T-470 (dated). | `crates/axiam-pki/src/vault_forward.rs:51-90`; STRIDE T-470 | unit cases for `token=hvs.…`, `{"token":"hvs.…"}`, `"hvs.…".`, and the two host names left intact | S | Sonnet 5.5 |
| W1.3 | **#667.** `vault_client_builder().timeout(VAULT_TIMEOUT)` and a connect timeout, documented beside the other Vault timeouts. | `crates/axiam-auth/src/secrets.rs`; `docs/deployment/README.md` (the Vault rows) | `vault_provider_test.rs`: a wiremock Vault that delays past the timeout fails the fetch within the bound, naming the host and no token | S | Sonnet 5.5 |
| W1.4 | **#669.** Map the unique-serial violation with `classify_write_error(e, "certificate")` and the CA equivalent, so it is a typed conflict (`409`). | `crates/axiam-db/src/repository/certificate.rs:411-413`; `ca_certificate.rs` | `certificate_repository_test.rs`, `ca_certificate_repository_test.rs`: a second row with the same issuer and serial is `Conflict`, not `Migration` | S | Sonnet 5.5 |
| W1.5 | **#668.** A second `revoke_user_certificates` by binding after `anonymize_user`, outside the pinned pipeline order, best effort and idempotent. Amend T-336 (the residual closes). | `crates/axiam-server/src/cleanup.rs`; STRIDE T-336 | `cleanup_task.rs`: a step hook issues a bound certificate between (b4) and the anonymization; after the purge it is revoked | S | Sonnet 5.5 |
| W1.6 | **#714.** The unit holds the guard from the `CREATE`: `purge_orphan_unit` calls `claim_orphan_purge` and wraps the claim at once; a taken-over marker whose report removed nothing records nothing. Amend T-444 and T-472. | `crates/axiam-db/src/repository/tenant.rs:570-605`; `crates/axiam-server/src/cleanup.rs:602-622` | `cleanup_task.rs`: hold a unit inside `has_purgeable_rows` across a stop and abort it; the next start's sweep takes the marker at once and `tenants.purged` exists once for the id | M | **Opus 5.5** |
| W1.7 | **#689.** (i) An erasure writes `gdpr.user_pseudonymized` *before* `mark_completed`, and the GDPR sweep also completes `account_deletion` rows still pending whose user is `Anonymized`, writing the row. (ii) For a tenant purge and an orphan purge, a marker in the same transaction as the point of no return (`tenant_purge_pending` keyed by id; `user.erasure_audit_pending` for erasures with no request row), **v108**, cleared with the record. Decision D-7 (default: do (ii)). Amend T-444; the deployment guide's stop-budget section says what is recorded on the next start. | `cleanup.rs:1577-1636,465-481`; `crates/axiam-db/src/schema.rs` (v108, newest-version bump, scope test); `docs/deployment/README.md` | `cleanup_task.rs`: a unit held past its point of no return and cut at the deadline is recorded by the next start, exactly once (erasure, tenant purge, orphan purge); the v108 scope test | L | **Opus 5.5** |
| W1.8 | **#687.** Correct the three texts ("a unit cut at the stop's bound releases its claim from a spawned task the process exit may cancel; the tenant then waits out the lease"). The optional `JoinHandle` await is declined (D-8). | `docs/deployment/README.md:1903-1906`; STRIDE T-444 (iii); the `PurgeClaim` doc | `cleanup_task.rs`: a unit held at `UnitStep::TenantRowsPurged` with the stop set and a release that never answers is cut by `join`; on a runtime dropped right after, the claim is still set | S | Sonnet 5.5 |
| W1.9 | **#690.** Log the dead-letter append failure inside the blocking closure (path and I/O error, nothing of the record); drop the awaiter's own failure log. | `crates/axiam-audit/src/dead_letter.rs:395-402`; `handlers/gdpr.rs:224-277` | a write to a missing directory, with the awaiting future dropped before the task finishes, still logs `failed to append audit dead-letter file` | S | Sonnet 5.5 |
| W1.10 | **#692.** Make the drain observable: an audit sink that holds writes until released after the cut; the row asserted absent at the cut and present at the exit. | `crates/axiam-server/tests/minimal_profile_boot.rs:1129-1212` | the strengthened case fails if the audit drain is moved before the cut (prove it once, then restore) | M | Sonnet 5.5 |
| W1.11 | **#666.** (a) T-472's retention basis follows T-187 and `gdpr-compliance.md`; (b) `CrlService::current_at` keeps the named instant when it is in the past, or its doc says it signs at the wall clock — pick the first, since `resign` already takes an instant; (c) a test pins the `vault_pki` intermediate-default refusal. | STRIDE T-472; `crates/axiam-pki/src/crl.rs:533-540,640`; `ca.rs:254-276` | (c): a 57-character subject with no `intermediate_subject` → `400`, no request to Vault; (b): `crl.rs` unit test for a past instant | S | Sonnet 5.5 |
| W1.12 | **#688.** The three sentences of T-444, the guide and the `boot.rs` comments, as the issue words them. | STRIDE T-444; `docs/deployment/README.md:1850`; `crates/axiam-server/src/boot.rs` | none (text); `check-remediation-evidence.py` | S | Sonnet 5.5 |
| W1.13 | **#717.** Replace `{msg}` / `{err}` with labels in the five assertions, as `057a9c5a2` did elsewhere. | `crates/axiam-pki/tests/vault_ca_key_store_test.rs:132,344,389,390,438` | the file's tests, unchanged in what they assert; CodeQL quiet on the PR | S | Sonnet 5.5 |
| W1.14 | — | F4 review of the W1 diff → `claude_dev/security-review-release-1.1.1-w1-<date>.md`. Medium and higher fixed in the wave; Low and Informational filed on `1.1.x` for 1.1.2. | | | — | **Opus 5.5** |

Closes: #664, #665, #666, #667, #668, #669, #687, #688, #689, #690, #692, #714, #717.

---

## 3. Wave W2 — rate limiting, audit attribution and SAML (branch `claude/release-1.1.1-w2`)

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W2.1 | **#711 and #686.** `AXIAM__RATE_LIMIT__TRUSTED_PROXIES` (CIDRs). `X-Forwarded-For` is honoured only from a listed peer (then `TRUSTED_HOPS` applies as today); every other request is keyed on its peer. With the list empty, today's behaviour, plus one `WARN` at boot when native TLS is on. The gRPC extractor shares the variable and the rule. Amend T-212 (dated; the spread direction is now mitigated), correct the deployment guide's "Direct, no proxy" row (#715 (b)) and comment on #686 that the default reads the header too (#715 (c)). The guide's sentence for the FreeRADIUS servers' listener is **W5.8's**, written in the new profile names. | `crates/axiam-api-rest/src/extractors/rate_limit.rs:131-157`; `crates/axiam-api-grpc` (its extractor); `config/rate_limit.rs`; `boot.rs`; `docs/deployment/README.md:927` and the config reference; `scripts/check-config-key-coverage.py` (the new key) | `rate_limit_keying_test.rs`: with `TRUSTED_PROXIES` empty, two `/auth/login` requests from one peer with different `X-Forwarded-For` **share** a bucket; with the peer listed, they do not; the gRPC twin; the boot `WARN` | M | **Opus 5.5** |
| W2.2 | **#673.** Keep a handle to each governor's limiter and sweep all of them on one interval task, as `CibaListLimiter` does. | `crates/axiam-api-rest/src/server.rs:41-116`; precedent `ciba_list_limiter.rs:20-97` | after a sweep past one replenish period, a map that saw *n* distinct keys holds none | M | Sonnet 5.5 |
| W2.3 | **#718.** Option 1 (D-2): the administrative presets skip the cold-entry seed, as the browser preset does; the sizing guide says which families seed and which do not. | `crates/axiam-db/src/rate_limit_counter.rs:668` (`COLD_ENTRY_BURST_FRACTION`, the preset flag beside it); `docs/deployment/rate-limit-sizing.md` | the limiter's own test: an admin family first seen 3 s before the minute's end still has its full allowance; the shared-replica burst test keeps passing for the public families | S | Sonnet 5.5 |
| W2.4 | **#685.** D-3 (default: **remove** the public-client token bucket; the route limiter is the documented answer, `rate_limit_exceeded`). `docs/admin/public-clients.md` and T-289 say which answer a public client meets first. | `crates/axiam-api-rest/src/handlers/oauth2.rs` (`token_inner`); `docs/admin/public-clients.md`; STRIDE T-289 | a flood from one address against one public client meets `rate_limit_exceeded` first; the device poll's `slow_down` on a too-fast poll is unchanged | S | Sonnet 5.5 |
| W2.5 | **#670.** The audit middleware accepts the `DPoP` scheme (case-insensitive, as `is_dpop_scheme`) beside `Bearer` when choosing the token to validate and cache. | `crates/axiam-audit/src/middleware.rs:636-669` | a DPoP-scheme request with a valid proof produces an audit row naming user and tenant; without a proof it is still refused by the extractor; on `/federation/oidc/authorize` a DPoP-bound token is keyed on `(ip, principal)` | M | Sonnet 5.5 |
| W2.6 | **#671.** Route the ten authenticated acquires through a bounded acquire, with the issue's answers: PKI routes `503`; SLO signing `Err("signing")` (a partial hop); assertion signing a retry page. The Redirect-binding query check stays ungated (decided in the issue). Amend T-102 and T-477. | `handlers/saml_idp.rs:1306`; `saml_idp_slo.rs:777`; `crates/axiam-pki/src/{cert.rs,ca.rs,pgp.rs}` | each site under a saturated permit answers within its bound with the named answer; the existing crypto-gate tests | M | Sonnet 5.5 |
| W2.7 | **#672.** Widen the scan's anchor, refuse `Self::`/aliases outside the defining file, collect the `check_at*` literal prefixes and the gRPC families into the same uniqueness check; in the excluded file skip only `#[cfg(test)]` and doc text. | `crates/axiam-api-rest/tests/rate_limit_bucket_names_test.rs:105-200` | synthetic sources for each escape are flagged | S | Sonnet 5.5 |
| W2.8 | **#682.** Refuse at ingestion an action outside printable ASCII (`[\x21-\x7e]` plus the one space of `METHOD /path`); document the grammar in `asyncapi.yml`. Amend T-118. | `crates/axiam-core/src/models/audit.rs`; `crates/axiam-amqp/src/audit_consumer.rs:139`; `asyncapi.yml` | each lookalike of the issue is nacked and not persisted; the four reserved actions and `METHOD /path` still pass | S | Sonnet 5.5 |
| W2.9 | **#674.** (a) … (g) as listed, (e) as a source-scan test in `axiam-server` that the audit middleware wraps the App outside the routes. | STRIDE T-477, T-474, T-102; `saml_idp.rs:641`; `docs/deployment/README.md` (`END_SESSION_PER_MIN`, `HASH_ACQUIRE_TIMEOUT_SECS` rows); `rate-limit-sizing.md` | (e)'s scan test; `check-remediation-evidence.py` | S | Sonnet 5.5 |
| W2.10 | — | F4 review of the W2 diff → `claude_dev/security-review-release-1.1.1-w2-<date>.md`. | | | — | **Opus 5.5** |

Closes: #670, #671, #672, #673, #674, #682, #685, #686, #711, #718.

---

## 4. Wave W3 — OAuth2, CIBA, the device grant and UMA (branch `claude/release-1.1.1-w3`)

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W3.1 | **#675 (3).** D-4 (default: yes). The admin `PUT` may set `token_endpoint_auth_method: none` on a confidential client whose grants are only the device grant and `refresh_token`, clearing its secret hash in the same write; every other conversion stays refused. One audit row names the conversion. `docs/admin/public-clients.md` and the CHANGELOG upgrade note (W8.4) say so. | `crates/axiam-api-rest/src/handlers/oauth2_clients.rs:955`; `crates/axiam-db` (the client repository); `docs/admin/public-clients.md` | the conversion succeeds and clears the hash; a client holding `client_credentials` or CIBA is still refused; the converted client's device flow works with `client_id` alone; the converse (public → confidential) is still refused | M | **Opus 5.5** |
| W3.2 | **#712.** `LET $live = (…);` then `tenant_id IN $live` in both statements; correct the comment. | `crates/axiam-db/src/repository/oauth2_client.rs:1145-1180` | `oauth2_client_confidential_grant_test.rs`: 201 live tenants, one confidential device client in one of them, 2 000 of a tombstoned tenant; the count is `(1, 1)` within 5 s | S | Sonnet 5.5 |
| W3.3 | **#676.** Evaluate the cutoff in the datastore (`updated_at < time::now() - $retention`) in the selection and the `DELETE`; state the inter-replica-skew assumption in T-424 and `CibaHintCap`'s doc; **v109**: `DEFINE INDEX IF NOT EXISTS rate_limit_bucket_updated_at`. | `crates/axiam-server/src/cleanup.rs:262,300-330`; `crates/axiam-db/src/repository/rate_limit.rs:236-255`; `schema.rs` (v109 after W1's v108 — see §10) | a sweep run with an application clock 5 minutes ahead keeps a previous-window hint row aged 20 minutes; `the_sweep_removes_stale_rows_and_keeps_current_ones`; the v109 scope test | M | Sonnet 5.5 |
| W3.4 | **#678.** When the count's conflict survives the retries, answer `Ok(false)` (`slow_down`); keep `server_error` for non-conflict faults. | `crates/axiam-oauth2/src/ciba.rs:1018-1042` | a store that injects a conflict on every attempt makes `admit` return `Ok(false)` with no count; forty concurrent calls against the in-memory datastore produce no `server_error` | S | Sonnet 5.5 |
| W3.5 | **#679.** Move `UNKNOWN_CLIENT_SECRET_HASH` and `spend_one_verify` into `token.rs` as `pub(crate)`; call it in each `NotFound` and tenant-mismatch arm listed and in the no-header refusal with a body secret. An assertion presented to an unknown client: state the residual in T-289 (no dummy-key verify). | `crates/axiam-oauth2/src/token.rs:1585,1915,2405,2617,3325,1410-1415`; `token_ciba.rs:107`; `token_device.rs:221-233`; STRIDE T-289 | a `#[cfg(test)]` verify counter: one verify for an unknown client with a secret, a wrong secret, and a Basic-registered client with a body secret, on each path | M | Sonnet 5.5 |
| W3.6 | **#680.** On a `dcr`/`cimd` row the admin `PUT` refuses `422 grant_exceeds_registration_policy` a grant `dcr::validate` would refuse, with the same held-grant exemption as scopes. | `handlers/oauth2_clients.rs:432,539`; `docs/admin/dynamic-client-registration.md` | adding `client_credentials` to a `dcr` row is `422` and leaves it unchanged; the same on an `admin` row is accepted | S | Sonnet 5.5 |
| W3.7 | **#681.** (i) The device grant mints with `.client_id(Some(client))`, as CIBA does, and no session; `/api/v1/device/verify` answers it `403 authorization_denied`; T-447's refusal then rests on `minted_for_client`. (ii) D-6 (default: yes): refresh tokens issued to a public DPoP-bound client store the `jkt` and require it at refresh (RFC 9449 §5); a confidential client's are unchanged. Contract §14's sentence is recorded by W7.1; T-289 and T-447 amended. | `crates/axiam-oauth2/src/device_service.rs:501-510`; `crates/axiam-auth/src/token.rs:888-958`; `extractors/auth.rs:476-482,1188`; the refresh-token store; `docs/api/device-flow.md` | a device token carries `client_id`; `/api/v1/device/verify` answers it `403`; a public DPoP client's refresh with another key is refused, with the same key admitted; a confidential client's refresh is unchanged | M | **Opus 5.5** |
| W3.8 | **#683.** `client_id` becomes `Option<String>` resolved with `resolve_client_id`; the route gets `FormConfig::error_handler(par_form_error)`. Regenerate `sdks/openapi.json`. | `crates/axiam-oauth2/src/device_service.rs:113`; `crates/axiam-api-rest/src/server.rs:2116-2123` | a Basic client without a body `client_id` gets a user code; a malformed body gets a JSON `invalid_request`; the drift job | S | Sonnet 5.5 |
| W3.9 | **#705.** Get, update and delete of a resource set whose `uma_registered_by` is not the PAT's `client_id` answer `404`, as for an unknown id. New threat entry **T-488** (Mitigated with the test). `docs/api/uma.md` says a resource server sees only what it registered. | `crates/axiam-api-rest/src/handlers/uma.rs:361-485`; STRIDE §5 (the UMA diagram); `docs/api/uma.md` | `uma_test.rs`: resource server B gets `404` on A's resource set for get, update and delete, and on a resource created through `/api/v1/resources`; A's own still work | S | Sonnet 5.5 |
| W3.10 | **#677.** Reword the three places and T-289's #635 amendment as the issue proposes. | `docs/api/device-flow.md:82-83`; `website/src/docs/oauth2.ts:640`; `device_service.rs:41-43`; STRIDE T-289 | none (text); website `tsc`; `check-remediation-evidence.py` | S | Sonnet 5.5 |
| W3.11 | **#684.** (a) … (f) as listed; (e) regenerates the spec. | STRIDE T-289, T-424; `server.rs:2113-2115`; `token_ciba.rs:292-294`; `device_service.rs:110`; `cleanup.rs:293-295` | `check-remediation-evidence.py`; `check-doc-links.sh`; the drift job | S | Sonnet 5.5 |
| W3.12 | — | F4 review of the W3 diff → `claude_dev/security-review-release-1.1.1-w3-<date>.md`. | | | — | **Opus 5.5** |

Closes: #675, #676, #677, #678, #679, #680, #681, #683, #684, #705, #712.

---

## 5. Wave W4 — network policy and the schema runner (branch `claude/release-1.1.1-w4`)

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W4.1 | **#704.** The runner reads every recorded version and applies, in order, each listed migration not recorded, logging an out-of-order application; `migrations_are_contiguous` asserts versions 1 … N. | `crates/axiam-db/src/schema.rs:2484-2490` | a schema test records 1 … 98 and 100, runs the migrations and asserts v99 applied (`idx_certificate_issuer_serial` exists); the contiguity test | M | **Opus 5.5** |
| W4.2 | **#702.** `super_admin_may_hold` returns `false` for a `network:` action when the tenant's `kind` is `Organization`; `reconcile_default_role_grants` revokes them there at boot (one audit row per revocation). T-483 → Mitigated. The CHANGELOG upgrade note (W8.4) says the organization scope's super-admin loses the six network permissions. | `crates/axiam-core/src/models/network.rs:798-805`; `crates/axiam-db/src/seeder.rs:515-525`; `crates/axiam-authz/src/engine.rs:161-169`; STRIDE T-483 | `seeder_default_data_test.rs::the_organization_scope_super_admin_holds_no_network_permission`; a gate test that an organization-level writer is refused `network:grant` in a child tenant; the reconcile revokes on an upgraded seed | M | Sonnet 5.5 |
| W4.3 | **#703.** After a cleared network-sensitive write, one `network_role.assigned` / `.unassigned` / `network_role.granted` / `.revoked` / `certificate_binding.bound` row with the role, the grantee, the node and the permissions conferred. T-484 → Mitigated. `docs/admin/README.md`'s audit-action list gains the five. | `crates/axiam-api-rest/src/network_gate.rs:84-110`; callers in `roles.rs`, `permissions.rs`, `certificates.rs`; STRIDE T-484 | `network_gate_test.rs`: each cleared network-sensitive write leaves exactly one such row with those members; a non-network write leaves none | M | Sonnet 5.5 |
| W4.4 | **#706.** When no row resolves (fingerprint form) or the row is not this tenant's, run `authenticate_der` over `caller.der` as a decoy and discard the result. T-457 amended; contract §36.11 rule 5's softening (the engine short-circuit that remains) is **W7.1's**. | `crates/axiam-api-rest/src/handlers/network_decide.rs:404-426`; STRIDE T-457 | the unknown fingerprint added to `allow_no_candidate_and_another_tenant_cost_the_same` and to the structural test | S | **Opus 5.5** |
| W4.5 | **#708.** The network repository returns a typed `NetworkConflict` the handler maps to `AxiamError` and `NetworkConflictReason` in one place; the substring matching is deleted; the wire values do not change. | `crates/axiam-api-rest/src/handlers/network.rs:429-457`; `crates/axiam-db/src/repository/network.rs` | a unit test in `axiam-db` that each refusal path returns its typed reason; `every_network_409_carries_its_reason_code` stays as the pin | M | Sonnet 5.5 |
| W4.6 | **#709.** The editor's create and replace are gated on `network:profiles_write` **and** `network:grant`, as the delete is; `PLACEMENT_RACED` renamed `axiam:profiled_placement_raced`. | `frontend/src/pages/network/`; `crates/axiam-db/src/repository/network.rs` | `NetworkAccessPage.test.tsx`: the editor hidden without `network:grant`, shown with it; the race tests | S | Sonnet 5.5 |
| W4.7 | **#715** (a), (d), (e). (a) verify `radius_reply.rs` and the spec say `400` (they do, since #700 — §0.1) and record it; (d) T-481's text: the transactions re-check the row, not the writer's rights; (e) narrow the enumeration test's exemption to `ErasureUnit::prepare`. (b) and (c) are W2.1's. | `crates/axiam-core/src/models/radius_reply.rs:250-253`; STRIDE T-481; `crates/axiam-api-rest/tests/network_gate_enumeration_test.rs:124-128` | the enumeration test; `check-remediation-evidence.py` | S | Sonnet 5.5 |
| W4.8 | — | F4 review of the W4 diff → `claude_dev/security-review-release-1.1.1-w4-<date>.md`, reading H1 … H6 against the code once more. | | | — | **Opus 5.5** |

Closes: #702, #703, #704, #706, #708, #709, #715.

---

## 6. Wave W5 — the FreeRADIUS recipe: the profile names and the review's fixes (branch `claude/release-1.1.1-w5`)

`docs/pki/freeradius.md`, `docker/radius/**`, `docker/docker-compose.radius*.yml`,
`crates/axiam-server/tests/radius_e2e.rs`, `.github/workflows/radius-e2e.yml` and
`website/src/docs/operate.ts` are **W5's files**: no other wave edits them
(W2.1's guide sentence is W5.8's). W5.1 runs **first**, so that every later
W5 commit is written in the new names.

### 6.1 The names (decision D-1)

The spike named its deliverables D1 … D7, and two of them became the recipe's
two profiles. The names say nothing to an operator. From 1.1.1:

| Today | From 1.1.1 (default) | What it is | Alternative, if the maintainer prefers |
|---|---|---|---|
| **D3** | the **Static** profile | FreeRADIUS alone decides, from a placement table you generate and a revocation list you fetch | the **Table** profile |
| **D4** | the **Live** profile | FreeRADIUS asks AXIAM once per authentication (`POST /api/v1/network/decide`), which places, quarantines and revokes at the next authentication | the **Decision** profile |

Slugs, from the names: `static` and `live`. The rename is total where a
reader or an operator meets the name, and historical where the text is a
dated record:

| Site | What changes |
|---|---|
| `docs/pki/freeradius.md` | every `D3`/`D4` (40 lines); section 5's title "The decision per authentication (Live profile)"; the comparison table's headers; the first mention of each name carries "(the design note's **D3** / **D4**)" once, so a reader of the 1.1.0 CHANGELOG finds it |
| `docker/docker-compose.radius-d4.yml` → `docker-compose.radius-live.yml`; `docker/radius/raddb/d4/` → `raddb/live/`; `axiam-d4.sh` → `axiam-live.sh`; the `axiam_d4` module → `axiam_live`; `AXIAM_D4_URL` → `AXIAM_LIVE_URL`; `/var/run/axiam-d4` → `/var/run/axiam-live` | `git mv`; every reference in `raddb/eap`, `raddb/live/*`, `docker/radius/README.md`, the e2e, the workflow's path filter and the compose files |
| `crates/axiam-server/tests/radius_e2e.rs` (50 lines), `.github/workflows/radius-e2e.yml` (4) | comments, the override's path, the environment file, the log lines ("Live cases passed in …") |
| `docs/deployment/README.md:956`; `docs/pki/README.md` where it points at the profiles | the names |
| `website/src/docs/operate.ts` (22 lines) | the headings become "Two profiles: Static and Live", "Static: the placement table", "Live: network segments", … ; the diagram's two labels; the 1.1.0 release note keeps "D4" in parentheses once |
| `website/src/security.ts` (3) | the names, "(formerly D4)" once |
| `crates/axiam-api-rest/src/handlers/network_decide.rs:1,536` (doc comments) | "the Live profile"; then regenerate `sdks/openapi.json`, `sdks/management-registry.json` (`scripts/gen-management-registry.py`) and `website/src/apiIndex.ts` (`website/scripts/gen-api-index.mjs`) |
| the four console comments (`navSections.tsx:305`, `services/network.ts:5`, `router.test.tsx:40`, `lib/queryInvalidation.ts:142`) | "RADIUS Live profile"; **the DCR/CIMD `D3`/`D4`/`D5` under `pages/settings/` and `services/settings.ts` are untouched** |
| `sdks/CONTRACT.md` §36 (3 mentions) | **W7.1's** (the contract is versioned): the names, "(formerly RADIUS D4)" once in §36's head |
| `claude_dev/threat-model-stride.md`, `Axiam.json` (31 each), `website/src/threatModel.ts` | **W8.3's**: the entries' text takes the names with "(formerly D4)" on first use in §5.10; the dated pass descriptions stay as written; the website copy is regenerated |
| `claude_dev/radius-reply-profile-design.md`, `radius-eap-tls-spike-2026-10-06.md`, `release-1.1.0-plan.md`, `CHANGELOG.md` `[1.1.0]` | **history, not rewritten**: the design note and the spike each gain one dated line under their status block ("From 1.1.1 the recipe calls D3 the Static profile and D4 the Live profile"); the plan and the CHANGELOG stay |

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W5.1 | **The rename**, as §6.1 tables it; one commit, `git mv` for the files, `grep -rn -E '\bD[34]\b'` over the tree as the exit check (what remains is the DCR/CIMD decisions, the historical notes and the threat model until W8.3). The CHANGELOG entry (W8.4) tells the recipe's operators which file names moved. | as tabled | `radius-e2e.yml` on the PR (both cases); `freeradius -XC` on both profiles where Docker exists; `scripts/check-radius-vendors-nothing.py`; `check-doc-links.sh`; website `tsc`, lint and build; the drift job; `frontend` `tsc` and lint | M | Sonnet 5.5 |
| W5.2 | **#693.** `tls_max_version = "1.3"` in the RadSec block; say the per-client `require_message_authenticator` is harmless and inert on a RadSec client in 3.2.8 and that the firmware point is for UDP; resolve the contradiction with the bullet that offers RadSec as the remedy. | `docs/pki/freeradius.md` (the RadSec section) | `freeradius -XC` with the block where Docker exists; none otherwise (text) | S | Sonnet 5.5 |
| W5.3 | **#694.** `trap 'exit 1' HUP INT TERM` beside the `EXIT` trap. | `docker/radius/fetch-crl.sh:64` | `docker/radius/tests/fetch-crl-test.sh`: a run killed by `TERM` leaves no `$work` and no `.incoming.*`, under `dash` and under `bash` | S | Sonnet 5.5 |
| W5.4 | **#695.** The script reads the installed list's `nextUpdate` and exits 3 when less than a quarter of its lifetime remains, after a `304` as after a refusal; the guide's alert becomes "exit status non-zero". | `docker/radius/fetch-crl.sh`; `docs/pki/freeradius.md` (the fetch and alert text); `website/src/docs/operate.ts` (the alert sentence) | `fetch-crl-test.sh`: a `304` against a list near `nextUpdate` exits 3; a fresh list exits 0 | S | Sonnet 5.5 |
| W5.5 | **#696.** `-H 'Cache-Control: no-cache'` on the request; the guide keeps its advice for caches that ignore request directives. | `docker/radius/fetch-crl.sh`; `docs/pki/freeradius.md` | `fetch-crl-test.sh`: the request carries the header | S | Sonnet 5.5 |
| W5.6 | **#697 and #713.** Add the eleven paths both issues list to the workflow's filter, and a weekly `schedule:` trigger in place of `Cargo.lock`. | `.github/workflows/radius-e2e.yml:34-61` | the workflow runs on the PR (W5 touches the test); one `workflow_dispatch` where the orchestrator has the means | S | Sonnet 5.5 |
| W5.7 | **#707.** After `axiam_decide`, on a `401`, expire the cache entry and fetch a token and ask once more before rejecting. | `docker/radius/raddb/live/check-eap-tls:56-104`; `axiam_live:100-109`; `docs/pki/freeradius.md` §5 (the token cache paragraph); STRIDE T-486 | the Live e2e: rotate the FreeRADIUS account's binding and assert the next authentication after the `401` is admitted without waiting out the TTL | M | Sonnet 5.5 |
| W5.8 | **#698** (b), (c) and **#711's guide sentence**: expose AXIAM's native listener to the FreeRADIUS servers only and keep the HTTP ingress for everything else (§5, in the new names); (b) the tag paragraph; (c) the two doc summaries in the e2e. (a) and (d) verified done (§0.1). | `docs/pki/freeradius.md:337-339` and §5; `radius_e2e.rs:557-560` | none (text); `check-doc-links.sh` | S | Sonnet 5.5 |
| W5.9 | — | F4 review of the W5 diff → `claude_dev/security-review-release-1.1.1-w5-<date>.md` (the recipe's security wording, the e2e's assertions after the rename). | | | — | **Opus 5.5** |

Closes: #693, #694, #695, #696, #697, #698, #707, #713.

---

## 7. Wave W6 — CI, tooling and dependencies (branch `claude/release-1.1.1-w6`)

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W6.1 | **#699.** `export BENCH_CERTS_DIR="${BENCH_CERTS_DIR:-$PWD/profiles/certs}"` at the top of `bench-quick`; `bench-quick` writes a `meta.json` (image ref, digest or image ID, `build_ref`) as the other recipes do; the quick-bench runbook says so. | `justfile` (`bench-quick`); `claude_dev/quick-bench-runbook-2026-08-16.md` | `just --dry-run profile=p3-mtls bench-quick` shows the absolute path; the k6 init no longer stats a relative path (verified by `just -n` and by reading `run-benchmark.sh:118`'s precedent) | S | Sonnet 5.5 |
| W6.2 | **#691.** The validation step gets `id: inputs`; the five `always()` steps are guarded with `steps.inputs.outcome == 'success'`; `validate_inputs_test.sh` greps the YAML for the two patterns. | `.github/workflows/fapi-conformance.yml:128-153,396-520`; `conformance/scripts/tests/validate_inputs_test.sh` | the shell test's new check; one bad-input dispatch shows a single red step (where the orchestrator has the means, else recorded in §12) | S | Sonnet 5.5 |
| W6.3 | **#719.** Read the sparse index for `utoipa-swagger-ui` once: if a release depends on `zip ≥ 9`, bump it, remove the three IDs from `ci.yml` and `deny.toml`, run `check-audit-ignore-sync.py`; if not, record the version read in §12 and leave the issue open (D-9). | `Cargo.toml`; `.github/workflows/ci.yml`; `deny.toml` | `cargo deny check advisories`; `scripts/check-audit-ignore-sync.py` | S | Sonnet 5.5 |

W6 has no F4 of its own: W8.2's combined review reads its diff.

Closes: #691, #699, and #719 only if W6.3 bumped the crate.

---

## 8. Wave W7 — contract 1.63 and the eleven SDKs (branch `claude/release-1.1.1-w7`, cut from the plan branch after W1 … W6 are merged into it)

### 8.1 W7.1 — the contract text (Sonnet 5.5, M)

`sdks/CONTRACT.md` becomes **1.63**; the record is **§34.7**. Items, each
marked *contract 1.63* inline where its rule lives:

- **(a) #710 item 1 (D-5).** §6.1 rule 11 and §12.1 rule 3 extend to the
  session cookies (`axiam_*`) and the `X-CSRF-Token` header: no session or
  adopted credential of any form on any `/oauth2/*` request. A §14.6 test
  sends no `Cookie` and no `X-CSRF-Token` to either device operation or to a
  token request.
- **(b) #710 item 2 (D-5).** §31.3 rule 4 and §34.6 (g) extend to the SCIM
  read-modify-write: every helper that builds an `expected_updated_at` from
  a read sends the response's own `updated_at` string (an `updatedAtRaw`,
  as for SSF). Names Java, Kotlin (C162-10) and C (C162-09).
- **(c) #710 item 3 (D-5).** §33 (the AMQP producer): a producer MAY refuse
  the reserved `tenants.` / `gdpr.` actions locally with a `ValidationError`
  before publishing; the seven AMQP SDKs do.
- **(d) #681.** §14's sentence on device-grant tokens: they carry
  `client_id` and no session; the session-validated routes answer them
  `403 authorization_denied` (W3.7 (i)); a public DPoP-bound client's
  refresh token is bound to its key (W3.7 (ii)).
- **(e) #706.** §36.11 rule 5 names the engine short-circuit that remains
  after the decoy verify (W4.4).
- **(f) W5.1.** §36's three "RADIUS D4" mentions become "the Live profile",
  "(formerly RADIUS D4)" once in §36's head.
- **(g) §34.6 (ae)** is closed by a pointer to §34.7.
- Regenerate `sdks/openapi.json` and `sdks/management-registry.json`;
  `python3 scripts/check-spec-digest.py`; the drift job green on the wave.

No SDK re-sync is required by (d) … (g); (a) … (c) are what each SDK ports.

### 8.2 W7.2 … W7.12 — the eleven SDK sessions (Sonnet 5.5, one session each, in parallel)

Every SDK: re-vendor `CONTRACT.md`, `openapi.json` and `proto/` from the
plan branch byte for byte; port (a) with its §14.6 test (Kotlin and Swift
already withhold the cookies — test only); the SDK's own issue(s) below;
`CHANGELOG.md` under the patch-bump rule (a source-breaking change is
recorded and bumps the minor, as 1.0.1 did); the README's contract sentence.
Each SDK's PR is a draft on `claude/contract-1.63` and closes its issue(s)
on a `Closes` line. `scripts/check-sdk-artifact-drift.py` in the platform
repository is green once the eleven are merged.

| SDK | Issue | Its items | 1.63 extras | Size |
|---|---|---|---|---|
| TypeScript | ilpanich/axiam-typescript-sdk#142 | C162-07: `plan` refuses, with zero wire calls, an unknown open-enum value on an unstated member; C162-08: a stated `termination_action: null` is refused at `plan` | (c) producer refusal | M |
| Rust | ilpanich/axiam-rust-sdk#132 | C162-07 as above (`src/manifest/network.rs:656`); C162-13: untrack the 438 files under `vendor/axiam-opaque/target/` and ignore the path | (a) the cookie jar and `maybe_csrf_header` on `/oauth2/*` (named in #710); (c) | M |
| Python | ilpanich/axiam-python-sdk#99, #100 | C162-07, C162-08 (`_engine.py`, `_spec.py`); #100: an explicit PAT wins over the adopted credential on `/uma2/*`; the session cookies no longer reach `/oauth2/*` | (a) is #100's second item; (c) | M |
| C | ilpanich/axiam-c-sdk#74 | C162-06: `plan` refuses an unknown enum instead of leaving the member out; C162-09: `expected_updated_at` from the SCIM response's `updated_at` string | (b) is C162-09; REST-only, no (c) | S |
| C++ | ilpanich/axiam-cplusplus-sdk#76 | C162-07; C162-16: `site` carried across pages of `list_segments` | REST-only | S |
| C# | ilpanich/axiam-csharp-sdk#107 | C162-06; C162-15: recorded in the CHANGELOG as a planned 2.0.0 source-breaking change (`token` required), no code now | (c) | S |
| Go | ilpanich/axiam-go-sdk#99 | C162-07 (`management_manifest_network.go:492`) | (c) | S |
| Java | ilpanich/axiam-java-sdk#115 | C162-07: the refusal moves from `apply` to `plan`; C162-10: `updatedAtRaw` kept next to the `OffsetDateTime` and sent for SCIM | (b) is C162-10; (c) | M |
| Kotlin | ilpanich/axiam-kotlin-sdk#77 | C162-07 as Java; C162-10 (`ReplacementBodies.kt:263`) | (b) is C162-10; REST-only; (a) test only | M |
| PHP | ilpanich/axiam-php-sdk#84 | C162-04: the generator's encode path raises `ValidationError` on `Unknown` with zero requests; C162-07 | (c) | M |
| Swift | ilpanich/axiam-swift-sdk#75 | C162-17: document `changing(_:_:)`'s behaviour on an unchanged `eventsRequested` | REST-only; (a) test only | S |

Each session's gate: the SDK's own lint, type-check and unit suite (the
commands each `README.md` names), the conformance fixtures regenerated
where the surface changed (none expected: 1.63 adds no operation), and the
C162-07 test the issues word identically (read a profile with
`termination_action: "future"`, state another member, assert the refusal
and no `PUT`).

### 8.3 W7.13 — conformance review (Opus 5.5)

`claude_dev/sdk-contract-1.63-conformance-review.md`, the 1.62 review's
method applied to the eleven heads: per-SDK report, findings index, and a
§5 of questions **only** for what §11 does not answer. Medium-or-higher
findings are fixed in the SDK PR before W8; Low and Informational are filed
on each repository's `1.1.x` milestone.

Closes: #710, and the twelve SDK issues in their own repositories.

---

## 9. Wave W8 — release readiness 1.1.1 (on `claude/release-1.1.1`)

| Task | What | Model |
|---|---|---|
| W8.1 | **Regression gate** on the merged plan branch, 1.1.0's W8.1 list: `fmt`; workspace clippy `-D warnings` with SAML on and off; every test binary crate by crate; the `client`-feature gRPC tests; the RADIUS e2e (both profiles) where Docker exists, else the workflow on the PR; every `scripts/check-*` and its self-test; frontend lint, `tsc`, a11y, build and vitest; website lint, `tsc`, build, `npm audit`; `cargo deny`, `cargo audit`. Failures fixed on the plan branch, each a signed commit named in §12. | Sonnet 5.5 |
| W8.2 | **Combined F4 review** of the whole diff against `main` → `claude_dev/security-review-release-1.1.1-<date>.md` (W6's diff included); Medium and higher fixed here; Low and Informational filed on `1.1.x` for 1.1.2. | **Opus 5.5** |
| W8.3 | **Threat-model reconciliation**: every entry the waves amended (T-102, T-118, T-212, T-289, T-336, T-424, T-444, T-447, T-457, T-470, T-472, T-474, T-477, T-481, T-483, T-484, T-486), the new T-488, the profile names in §5.10 (§6.1), the counts, `Axiam.json` to **2.43.0**, `website/src/threatModel.ts` and `threatModelSummary.ts` regenerated, `website/src/security.ts`'s counts. | Sonnet 5.5 |
| W8.4 | **CHANGELOG `[1.1.1]`**: one entry per closed issue ending in its number; the upgrade notes — `AXIAM__RATE_LIMIT__TRUSTED_PROXIES` and the boot `WARN` (W2.1), the public-client bucket's removal (W2.4), the organization scope's super-admin losing the network permissions at boot (W4.2), the device-only client conversion (W3.1), the DPoP refresh binding for public clients (W3.7), migrations v108 and v109, the recipe's file renames and the new profile names (W5.1), the fetch script's new exit status (W5.4); `Cargo.toml` and the frontend and website versions to `1.1.1` as 1.1.0's W8.4 did; `claude_dev/roadmap.md` gains the 1.1.1 line under Phase 24's successor; the PR body with the `Closes` lines (every issue of §2 … §8 but #719 if W6.3 left it open) and the issue-by-issue summary. | Sonnet 5.5 |
| W8.5 | **Coverage** (§1.2): read the Coveralls check on the PR and the vitest summary; fix any crate whose coverage fell; raise `thresholds.lines` to the achieved figure less 0.1; record both figures in §12. | Sonnet 5.5 |

The maintainer tags `v1.1.1` after the merge; the eleven SDK tags are theirs
too.

---

## 10. The gate before every commit, and the rules that bind every wave

- `CLAUDE.md` in full: signed commits; narrowly scoped cargo commands;
  `cargo clean` between items; the swagger placeholder and `protoc` before
  any server build; `--no-default-features` where libxml2 is absent; exit
  codes from the tool, never a pipeline; no `[lints] workspace = true` on an
  undocumented crate; no new crate without a row in the layering table.
- Per commit, on the touched crates: `cargo fmt -p <crate> -- --check`,
  `cargo clippy -p <crate> --lib --tests -- -D warnings`, the touched test
  binaries (`--test <name>`), and for W2 the `build-no-saml` `cargo check`.
  Console tasks: `npm --prefix frontend run test -- <file>` and the
  type-check. Script tasks: the script's own test. Workflow tasks: one
  `workflow_dispatch` where the orchestrator has the means, else recorded
  in §12 as not run.
- Phase 23 plan §7, unchanged: every new route carries a limiter from its
  first commit (none is added here); every credential-bearing outbound
  request uses `guarded_fetch_no_redirect`; every refusal of a credential
  check costs one verify (W3.5 is this rule's debt); every two-writer
  registry is written conditionally on the version read.
- **Schema**: W1.7 takes **v108**, W3.3 takes **v109**, in that order on the
  plan branch; each additive (`DEFINE FIELD IF NOT EXISTS`, `DEFINE INDEX IF
  NOT EXISTS`), with its scope test and the newest-version bump; no
  `UPDATE` backfill. W4.1's contiguity test is added last and must pass with
  both.
- **Contract**: no wave but W7 edits `sdks/CONTRACT.md`. W3.8, W3.11, W4.4
  and W5.1 regenerate `sdks/openapi.json` (and W5.1 the registry) in-wave so
  each wave's drift job is green; W7.1 regenerates once more after the text.
- **Test coverage** (§1.2) and **documentation** (§1.3) as stated: a row's
  tests and documents are part of its commit, not of a later one.
- **Threat model**: nothing enters without the test its mitigation names; a
  correction is recorded as a correction, dated, in the entry's own text.
  Each wave edits the entries its tasks name; W8.3 reconciles the copies
  once.
- **The profile names** (§6.1): from W5.1 on, every text any wave writes
  says Static and Live; a wave that merges after W5 and still says D3 or D4
  is corrected at the merge by the orchestrator, and §12 says so.
- **Questions**: a question an executor cannot answer from §11 is recorded
  in §12 and in the conformance review's §5, never worked around and never
  answered by the executor.
- Where this plan and a file disagree, the file wins and the commit body
  says so. An executor that finds a task larger than sized stops at a clean
  commit and reports; the orchestrator re-sizes and re-models by §1.1.

---

## 11. Decisions requested from the maintainer

Each has a **default the orchestrator applies** if the maintainer has not
answered when the task starts. An answer given later is applied by the
wave's next commit, or recorded in §12 as "answered after the fact".

| # | Question | Default |
|---|---|---|
| D-1 | **The profile names.** Static / Live (slugs `static`, `live`), or Table / Decision (`table`, `decision`)? §6.1 tables every site either pair changes. | **Static / Live** |
| D-2 | **#718.** Exempt the administrative presets from the cold-entry seed (option 1), scale the fraction (2), or document (3)? | **Option 1** |
| D-3 | **#685.** Remove the public-client token bucket, or keep it as a backstop for the device poll only? | **Remove** |
| D-4 | **#675 (3).** May the admin `PUT` convert a confidential client holding only the device grant (and `refresh_token`) to public, clearing its secret? | **Yes** (W3.1) |
| D-5 | **Contract 1.63.** Accept #710's three proposals: cookies and the CSRF header off `/oauth2/*`; the SCIM `expected_updated_at` as the server's string; a producer MAY refuse the reserved actions? | **All three** |
| D-6 | **#681 (ii).** Bind a public DPoP-bound client's refresh token to its key in this release (a stolen token no longer refreshes under another key)? | **Yes** (W3.7) |
| D-7 | **#689 (ii).** Add the pending-record markers under v108, or ship (i) alone and keep the orphan-purge residual recorded? | **Add them** |
| D-8 | **#687.** Also await the guard's release for a few hundred milliseconds at the teardown's bound (a new budget line), or correct the texts only? | **Texts only** |
| D-9 | **#719.** If `utoipa-swagger-ui` has no release on `zip ≥ 9` when W6.3 runs, the issue stays open on `1.1.x` and the PR does not name it. | **Stays open** |
| D-10 | **The version.** 1.1.1, with the SDKs on their own patch (or minor where a change is source-breaking)? | **1.1.1** |

---

## 12. Wave results (written by the orchestrator as each wave lands)

### 12.0 Base commit

- **Base:** `main` at `6b15aa36a` (the plan's own commit on top of `6b7b258`), 2026-10-19. `claude/release-1.1.1` and
  `claude/release-1.1.1-w1` … `-w6` were cut from it on 2026-10-19 by the orchestrator.
- **Decisions (§11):** no maintainer answer on any issue or on the plan when the waves started (issues read
  2026-10-19 17:52 UTC); every default applies — D-1 Static/Live, D-2 option 1, D-3 remove, D-4 yes, D-5 all
  three, D-6 yes, D-7 add the markers, D-8 texts only, D-9 stays open unless a release exists, D-10 1.1.1.
- **Execution:** each task is one cloud session (Claude Code on the web) at the model its row names, started by
  the orchestrator with the §13 kickoff of its wave and the task's row; tasks of one wave run one after another on
  the wave branch, the six waves side by side.

### 12.1 W1

- **Head:** `fc77c562f` on `claude/release-1.1.1-w1` (16 commits on `main`, every one carrying a `gpgsig`).
- **Commits:** W1.1 `bc7d9f4d2` (#664), W1.2 `83bec6fc0` (#665), W1.3 `18ca1cacf` (#667), W1.4 `b53d74bb0` (#669), W1.5 `035f51ede` (#668), W1.6 `6cb43c6c3` (#714; Opus 5.5), W1.7 `140911a21` (#689, **v108**; Opus 5.5), W1.8 `056bf289c` (#687), W1.9 `435952fb3` (#690), W1.10 `769d314be` (#692), W1.11 `42ade1e40` (#666), W1.12 `6dffb7060` (#688), W1.13 `189fa248f` (#717), W1.14 `13ec44d74` (F4 review, `claude_dev/security-review-release-1.1.1-w1-2026-10-19.md`), fixes `f4224d5ba` (R111W1-01) and `fc77c562f` (#739, #737 texts).
- **Where the tree overruled the plan:** the W1.6 row joined #714's two alternatives with "and" where the issue offered them with "or"; the clause "a taken-over marker whose report removed nothing records nothing" would lose the record of a unit that removed its rows and gave itself up at the stop, so W1.6 guards the marker with a conditional `CREATE` instead (the F4 confirms: no path to a double or a lost `tenants.purged`). v108 adds `user.erasure_audit_pending` (with its index) and the table `tenant_purge_pending`, which is deliberately outside `TENANT_PURGE_ORDER`. W1.10 needed a test seam (`ServeOptions::audit_hold_for_tests`; not `Deserialize`, unreachable from configuration). W1.11's (b) test lives in `tests/crl_test.rs`, since the service needs the database fixture. W1.13 labelled a sixth message in the same assertion. The line numbers of W1.6, W1.7 and W1.12 were stale.
- **F4 (W1.14):** one Medium, **R111W1-01**. W1.7's owed-erasure claim re-evaluated a subquery for every user row, at the start of every sweep on every replica: 112.8 s at 20 000 users and 2 000 requests. **Fixed in the wave** (`f4224d5ba`): the pending ids are read once (`LET`), and the test's data takes 19 ms against 95.5 s before. Low #736, #737; Informational #738, #739, #740, all on `1.1.x` for 1.1.2. #739's text items and #737's documentation part were taken in the wave (`fc77c562f`), so T-444, T-336, T-472, the deployment guide and the GDPR guide name #737 as the open residual; #737's code and #739 stay open.
- **Re-size (§1.1):** one added Sonnet 5.5 session carried the R111W1-01 fix and the two text items.
- **Executors:** each task at its row's model (W1.6, W1.7 and W1.14 Opus 5.5; the rest Sonnet 5.5).
- **Open contract question (not answered by §11; not answered here):** a `gdpr.user_pseudonymized` row written by the next start's recovery carries `certificates_revoked: null` and `recovered: true`, while CONTRACT §-erasure (~l.9261) says the row "carries the count". The F4 judges the code's choice safe, since any number would be fabricated in an append-only row. It goes to the maintainer through the 1.63 conformance review §5.
- **For W7.1:** the tenant metadata key `orphan_purge` is refused with `422 reserved_metadata_key`; a repeated issuer and serial answers `409 already_exists`. **For W8.2:** neither status is declared in the spec. **For W8:** read CodeQL on the PR, which is W1.13's oracle. **For W8.4:** v108 (additive, no backfill); a unit cut past its point of no return is recorded by the next start; a stored `metadata.orphan_purge` is kept and ignored; a stalled Vault fails the boot after ~10 s.

### 12.2 W2

- **Head:** `37c3f1027` on `claude/release-1.1.1-w2` (11 commits on `main`, every one carrying a `gpgsig`).
- **Commits:** W2.1 `d1c97b6ee` (#711, #686; Opus 5.5), W2.2 `b846942f4` (#673), W2.3 `be74f6231` (#718), W2.4 `d3448c2f4` (#685), W2.5 `2b24f3787` (repair of W2.3, below) and `7f1f9cb9a` (#670), W2.6 `a8a65617b` (#671), W2.7 `6211b4286` (#672), W2.8 `5f17ff98c` (#682), W2.9 `ac3effd10` (#674), W2.10 `37c3f1027` (F4 review, `claude_dev/security-review-release-1.1.1-w2-2026-10-19.md`).
- **Re-size (§1.1):** W2.3 left `rate_limit_bucket_names_test` red (its scan did not know `admin_preset`); W2.4 found it. The repair was folded into the W2.5 session as its first commit (`2b24f3787`), and every later prompt requires the full test binaries of each touched crate.
- **Where the tree overruled the plan:** the keying rule lives in `axiam-core::forwarded_for`, not `config/rate_limit.rs`, and an empty `AXIAM__RATE_LIMIT__TRUSTED_PROXIES` keeps today's behaviour with one boot `WARN` — the row and #711's Fix say so, only #711's Test sentence did not, and the shipped Kubernetes topology (TLS on behind an ingress that re-encrypts) decides; W2.7 reads seven handler prefixes, not eight, since W2.4 removed `oauth2_token_public`, and leaves `ciba_hint_cap` (written by `increment_by`) as T-474's residual; `asyncapi.yml` is `docs/api/asyncapi.yml`; W2.9's (d) and (g) had been made by #670 and #671.
- **F4 (W2.10):** no Critical, High or Medium. Low #731 (the empty-list `WARN` looks at the REST listener's TLS only; the gRPC listener's native TLS reads the same list); Informational #732, #733, #734, #735 and #741 — the last the cross-wave question from §12.4: AMQP-ingested `network_role.*` / `certificate_binding.*` rows are not refused, rated Informational because the reserved set is by design the records the server reads back (R101W3-03, T-118, T-472), nothing reads these back, and every other server action is already open. All on `1.1.x` for 1.1.2. The W5.8 FreeRADIUS sentence matches W2.1's code.
- **Executors:** each task at its row's model (W2.1 and W2.10 Opus 5.5, the rest Sonnet 5.5).
- **For W7.1:** §8 "Actions the audit ingestion refuses" gains W2.8's grammar; §14/§27: a `429` on `/oauth2/token` carries `rate_limit_exceeded` and `Retry-After`, `slow_down` only as the device grant's `400`. **For W7.1/W8.2:** the crypto-gate `503` (PKI routes, login, SAML pages) is not annotated in the spec. **For W8.4:** the new key `AXIAM__RATE_LIMIT__TRUSTED_PROXIES` (empty keeps the old behaviour, a bad value stops the boot); public clients see `429 rate_limit_exceeded` instead of `slow_down` on a flood; an AMQP action outside the grammar is dead-lettered.

### 12.3 W3

- **Head:** `f3503d098` on `claude/release-1.1.1-w3` (13 commits on `main`, every one carrying a `gpgsig`).
- **Commits:** W3.1 `159565de5` (#675; Opus 5.5), W3.2 `502ee243c` (#712), W3.3 `430c4021a` (#676, **v109**: the sweep index), W3.4 `bb3a741ff` (#678), W3.5 `306b4a92e` (#679), W3.6 `1ffc71385` (#680, spec), W3.7 `e0b4bf0bb` and `7a9b002ca` (#681, Opus 5.5; v109 also gains `oauth2_refresh_token.dpop_jkt`), W3.8 `74b56fdda` (#683, spec), W3.9 `0e6ab8d31` (#705, new **T-488**), W3.10 `f5bc5bc6d` (#677), W3.11 `71c4ee193` (#684, spec), W3.12 `f3503d098` (F4 review, `claude_dev/security-review-release-1.1.1-w3-2026-10-19.md`).
- **Where the tree overruled the plan:**
  - W3.7's 403 at `/api/v1/device/*` needed an ordering change, not only the claim. A new `ConsoleSignIn` extractor refuses a token carrying `client_id` after the DPoP replay record and before the session check.
  - Its refresh binding fails closed. A public DPoP-bound client's refresh token bound to no key is `invalid_grant`, whether it was issued before 1.1.1 or while the client was still confidential, because binding on first use would bind a stolen token to its thief.
  - W3.7 extended v109 instead of claiming v110, and both scope tests pin it.
  - W3.5 gates its probe behind a `verify-probe` feature, reached through a self dev-dependency declared in `TEST_ONLY_INVERSIONS`. The F4 confirms the feature is absent from release builds.
  - W3.9 found no UMA element in STRIDE §5, so T-488 hangs on the §5.3 resource-server actor. The list route already filtered by registrant.
  - W3.11's (f) phrase was in T-424's #676 amendment, not in `cleanup.rs`.
  - Every row's line numbers were stale.
- **F4 (W3.12):** no Critical, High or Medium. Filed on `1.1.x` for 1.1.2:
  - Low #749 (R111W3-01): the #675 conversion leaves the client's confidential-era refresh tokens and pending device grants live, and they refresh on `client_id` alone once the client is public.
  - Low #745 (R111W3-02, pre-existing): `/uma2/perm` mints tickets for another resource server's sets and for ordinary resources.
  - Informational #746 and #747.
- **Spec:** the F4 rebuilt it; `--dump-openapi` is byte-identical to `sdks/openapi.json`. The binaries W3.11 could not finish (`device_flow_test`, `ciba_test`, `ciba_approval_test`, `oauth2_flow_test`, `cleanup_task`) all pass.
- **Executors:** each task at its row's model (W3.1, W3.7 and W3.12 Opus 5.5; the rest Sonnet 5.5); none stopped short; no re-size.
- **Open for the maintainer (not answered by §11):**
  - #745: should resources created through `/api/v1/resources` stay UMA-ticketable? The issue sets out three options; `uma_test` relies on tickets for admin-made resources.
  - #749: should the conversion revoke the confidential-era tokens? Filed as Low under the wave rule, so 1.1.1's upgrade note tells operators to revoke them by hand.
- **For W7.1 (§14, §27, §33, UMA):**
  - A device-grant access token carries `client_id` and no `sid`: it gets `403 authorization_denied` at `/api/v1/device/verify` and `/decide` and `401` elsewhere.
  - A public DPoP-bound client's refresh token is bound to its key: another key or an unbound token is `invalid_grant`, which the SDK treats as terminal.
  - `/device_authorization` takes `client_id` from the body, the Basic header or the assertion; a mismatch is `invalid_request`, as is an unreadable body.
  - `oauth2_clients.update` converts a device-only confidential client to `none`, and refuses a grant that registration would refuse with `422 grant_exceeds_registration_policy`.
  - CIBA hint-cap contention answers `429 slow_down`.
  - A resource server's get, update and delete of another's set answer `404`.
- **For W8.3:** T-488 enters the counts; T-289, T-424 and T-447 are amended. **For W8.4:**
  - Public DPoP clients' pre-1.1.1 refresh tokens are refused once.
  - The conversion, and #749's manual revocation.
  - `/api/v1/resources` resources leave `/uma2/rreg`.
  - Device tokens carry `client_id`.
  - v109 (index, plus `dpop_jkt`) is additive.

### 12.4 W4

- **Head:** `178568391` on `claude/release-1.1.1-w4` (9 commits on `main`, every one carrying a `gpgsig`).
- **Commits:** W4.1 `9e1108a43` (#704), W4.2 `912742f84` (#702; T-483 Open → Mitigated), W4.3 `27aa45778` (#703; T-484 Open → Mitigated), W4.4 `bbf0a6483` (#706, Opus 5.5), W4.5 `bb670002f` (#708), W4.6 `d6a69bbe6` (#709; console line coverage 96.58 %), W4.7 `b8ce6ca58` (#715), W4.8 `dbc02db05` (F4 review, `claude_dev/security-review-release-1.1.1-w4-2026-10-19.md`), fix `178568391` (R111W4-01).
- **Where the tree overruled the plan:** `MIGRATIONS` is 1 … 85, 90 … 107 — 86 … 89 were never claimed, so W4.1's contiguity test exempts them by name (`UNCLAIMED_VERSIONS`); W4.4 verifies the caller's own certificate as the decoy for every case that has no row of the caller's tenant, and lists the paths still cheaper (own-tenant revoked or expired rows, an unparsable stored PEM, the engine's no-assignment short-circuit, the global fingerprint read's hit or miss); W4.7 found (a) already answered `400` in the spec and pinned (d), (e).
- **F4 (W4.8):** one Medium, **R111W4-01** — W4.5 retyped the §4.2 rule-2 refusal to `AxiamError::Network(NetworkConflict::StaleRole)` while the boot reconcile still matched `AxiamError::Conflict`, so a deployment whose ordinary-tenant super-admin is held by a group no longer booted (`seeder_default_data_test` red on `b8ce6ca58`). **Fixed in the wave** (`178568391`): the arm matches the typed variant; the oracle test and all 86 `axiam-db` test binaries pass. Low #726, #727; Informational #728, #729, #730, all on `1.1.x` for 1.1.2.
- **Re-size (§1.1):** W4.5's executor ran only the binaries it touched and missed a crate-wide consequence of changing an error type; the fix went to one added Sonnet 5.5 session. Every later F4 and executor prompt requires the full test binaries of each touched crate, and of every crate whose error type a commit changes.
- **Executors:** each task at its row's model (W4.4 and W4.8 Opus 5.5, the rest Sonnet 5.5); the fix session as above.
- **Cross-wave (for the merge and W8.2):** `RESERVED_ACTION_NAMESPACES` is `tenants.`, `gdpr.` only, so an HMAC-authenticated AMQP producer could have W4's `network_role.*` / `certificate_binding.*` rows persisted; put to W2's F4 (W2.10) to rate, since the reserved set is W2.8's code. **For W8.3:** T-457 residual (f), T-483 on an unresolved tenant (#728), T-484 on a role delete (#727) and a cancelled write (#726). **For W8.4:** the organization scope's super-admin loses the six network permissions at the first boot (one `network_role.permission_revoked_by_reconcile` row each); the runner applies an unrecorded lower migration with a `WARN`; R111W4-01's fix belongs in #708's entry.

### 12.5 W5

- **Head:** `fd9992b4f` on `claude/release-1.1.1-w5` (10 commits on `main`, every one carrying a `gpgsig`; merge into the plan branch follows W1 … W4, in order).
- **Commits:** W5.1 `b930db3` (the rename, D-1 default Static/Live), W5.2 `2dab9f6` (#693), W5.3 `b915783` (#694), W5.4 `64cf8ce` (#695), W5.5 `7424392` (#696), W5.6 `c90c8c1` (#697, #713), W5.7 `4cd4a10c9` (#707), W5.8 `8450bc2` (#698, #711's sentence), W5.9 `fd9992b4f` (F4 review, `claude_dev/security-review-release-1.1.1-w5-2026-10-19.md`).
- **Executors:** every task ran at its row's model (Sonnet 5.5; W5.9 Opus 5.5); none stopped short; no re-size.
- **Where the tree overruled the plan:** W5.1 also renamed ~30 "RADIUS D4" comments the §6.1 table did not list (other crates, scripts, the console e2e matrix) and found `docs/pki/README.md` carries no D3/D4; W5.3's trap already existed in `fetch-crl.sh`, so the commit adds the test (TERM, HUP; INT is ignored by a backgrounded shell) and the header text only; W5.6 added twelve paths, the two issues' full lists, not eleven; W5.7's retry needs `axiam_decide { invalid = 1 }`, since `rlm_rest` returns `invalid` for a `401` and the review's form never reached the retry; W5.8 found §5's exposure paragraph already present and replaced only its "planned" sentence.
- **Oracles:** `freeradius -XC` (pinned 3.2.8) passes on both profiles and on the guide's RadSec block, and refuses the block without `tls_max_version` (orchestrator, W5.7, W5.9); the local RADIUS e2e passes on both profiles (W5.9); `radius-e2e.yml` dispatched by the orchestrator: run 39302612696 on `c90c8c1` and run 39306303259 on `8450bc2`, both **success**; `fetch-crl-test.sh` 85/85 under `dash` and `bash`.
- **F4 (W5.9):** no Critical, High or Medium. Low #720 (concurrent `401`s can put the refused token back in the cache; fail-closed), Informational #721 … #725, all on `1.1.x` for 1.1.2.
- **For W7.1:** contract §36's "RADIUS D4" (two places) → "the Live profile", "(formerly RADIUS D4)" once. **For W8.3:** T-462 (exit 3, `no-cache`), T-486's concurrency caveat (#720, #722), T-487's "eighteen" stand-in answers (now nineteen), `docs/compliance/FINDINGS.md:64`, `website/src/data.ts:501`. **For W8.4:** the moved file names and variables, and that a 1.1.0 `raddb` set mixed with 1.1.1 files, or a kept `AXIAM_D4_URL`, rejects every device (fail closed); `fetch-crl.sh`'s new exit status 3.

### 12.6 W6

- **Head:** `45ffae3` on `claude/release-1.1.1-w6` (2 commits on `main`, both carrying a `gpgsig`).
- **Commits:** W6.1 `a9cb5a9` (#699: `bench-quick` anchors `BENCH_CERTS_DIR` and writes `results/quick/meta.json`), W6.2 `45ffae3` (#691: the five cleanup steps guarded by `steps.inputs.outcome == 'success'`).
- **W6.3 (#719):** the sparse index read once on 2026-10-19 at ~18:03 UTC: `utoipa-swagger-ui` newest non-yanked **10.0.1 → `zip ^8.6`** (10.0.0 → `^8.6`). No release on `zip ≥ 9`: no commit; **#719 stays open on `1.1.x` and the PR does not name it (D-9).**
- **Where the tree overruled the plan:** the `justfile` is `benchmarks/justfile` and the runner `benchmarks/runner/run-benchmark.sh`; `bench-quick` wrote no `meta.json` before; the fifth guarded step ("Collect … logs") was `failure() || …`, not `always()`, and carries the guard ANDed.
- **Workflow dispatch (W6.2's oracle):** the orchestrator dispatched `fapi-conformance.yml` on the branch with `plan_name=Bad_Name` (run 39299314310): exactly one red step, "Validate dispatch inputs"; the five guarded steps skipped.
- **Executors:** Sonnet 5.5 for all three, as the rows name; no re-size. No F4 of its own (W8.2 reads it).

### 12.7 W7 — the contract, the eleven SDKs and the conformance review

- **Merges (orchestrator):** W1 `9373afab8`, W2 `73955c4ec`, W3 `45abe6561`, W4 `c4f3275fe`, W5 `4ba5b7c1b`, W6 `6bae7dd38`, every merge commit signed.
  - W3's merge resolved two conflicts. `crates/axiam-db/src/schema.rs`: the migration list keeps v108 and v109, both scope tests are kept, and the newest-version assertion is 109. `Axiam.json`: T-289's mitigation text was merged three-way.
  - W5's merge resolved `docs/deployment/README.md`, taking W2's `TRUSTED_PROXIES` text plus W5's sentence on the Live profile, and regenerated the spec and registry.
  - Checked on the merged tree: `cargo check --workspace --tests --no-default-features` exit 0, no warnings; the schema tests (88), `rate_limit_bucket_names_test` (19), `audit_wraps_routes` and `seeder_default_data_test` (19) pass.
- **W7.1** `a6cd10eba`: contract 1.63, record §34.7 (a … q).
  - Plan vs tree: the device-grant token gets `403` only at `/api/v1/device/verify` and `/decide`, and `401` elsewhere. Item (c)'s rule lives in §8, not §33. Two "RADIUS D4" mentions, not three. The spec needed no regeneration.
- **W8.4a, moved forward** `750be9f0a`: version 1.1.1, as 1.1.0 did with `89e488e3e`, so that the SDKs re-vendor the final spec once. `openapi.json` sha256 `15dace9c…`, spec digest `sha256:443c9d39…`; `management-registry.json` sha256 `b0d5e749…`.
- **W7.2 … W7.12**: eleven Sonnet 5.5 sessions, one draft PR each on `claude/contract-1.63`. The final heads below vendor `d919ba0cc` byte for byte (`CONTRACT.md` sha256 `e267261b…`), and CI is green on every one:

  | SDK | PR | final head | version | closes |
  |---|---|---|---|---|
  | TypeScript | ilpanich/axiam-typescript-sdk#147 | `30778f0c` | 1.1.1 | #142 |
  | Rust | ilpanich/axiam-rust-sdk#136 | `168698b4` | 1.1.1 | #132 |
  | Python | ilpanich/axiam-python-sdk#101 | `b42bbf47` | 1.1.1 | #99, #100 |
  | C | ilpanich/axiam-c-sdk#75 | `3db38bdb` | 1.1.1 | #74 |
  | C++ | ilpanich/axiam-cplusplus-sdk#77 | `12d8a354` | 1.2.0 (SOVERSION 3) | #76 |
  | C# | ilpanich/axiam-csharp-sdk#109 | `6284a76a` | 1.1.1 | #107 |
  | Go | ilpanich/axiam-go-sdk#101 | `f5fc7da2` | 1.1.1 | #99 |
  | Java | ilpanich/axiam-java-sdk#119 | `dcae1850` | 1.2.0 | #115 |
  | Kotlin | ilpanich/axiam-kotlin-sdk#78 | `e200a45e` | 1.2.0 | #77 |
  | PHP | ilpanich/axiam-php-sdk#85 | `f260110a` | 1.1.1 | #84 |
  | Swift | ilpanich/axiam-swift-sdk#76 | `e8492615` | 1.1.1 | #75 |

- **Where the tree overruled the plan:** none of the seven "AMQP SDKs" ships an audit-event publisher. Rust guards `AuditEventMessage::sign`; the other six have nothing to refuse, so (c) became contract text.
  - The C SDK found and fixed a manifest bug: a stated `termination_action` or `service_type` was always refused.
  - Rust untracked the 438 build files under `vendor/axiam-opaque/target/`.
- **W7.13** `1f6134bdc` (Opus 5.5), `claude_dev/sdk-contract-1.63-conformance-review.md`: six Medium, all fixed before W8:
  - C163-01, TypeScript: the `/oauth2/` match also caught the federation callback, breaking Node SSO over OAuth2.
  - C163-02, Swift: C162-07 was not met; the refusal now happens at `plan` and names the member and the value.
  - C163-03, C, and C163-04, C++: the UMA ticket grant carried the session cookie. C++ also gets C163-15, `kVersion`.
  - C163-05, Kotlin: version not bumped.
  - C163-06, contract text: fixed in **W7.1b** `d919ba0cc` together with C163-11.
  - Low and Informational: ilpanich/axiam#750, typescript#148, python#102, c#76, filed by the reviewer; rust#137, cplusplus#78, csharp#110, go#102, java#120, kotlin#79, php#86, swift#77, filed by the orchestrator because the reviewer could not reach those repositories.
- **Re-size (§1.1):** W8.4a was moved forward, and W7.1b added for the contract-text Medium. The W7.13 session sat about an hour on an `add_repo` permission prompt nobody could answer. It was interrupted and continued with plain `git` on the public repositories.
- **Open for the maintainer (the review's §5, not answered by §11):**
  - Q1: the recovered `gdpr.user_pseudonymized` row with `certificates_revoked: null` against §27.11 rule 5 (W1.7's question).
  - Q2: what a device poll does on `429 rate_limit_exceeded`; the review recommends the CIBA rule, in contract 1.64.
  - Q3: keep "naming the member and the value" strict, or relax it. **C163-10 was not applied**, so the contract stays strict; seven SDKs name the member only and carry it as Informational.

### 12.8 W8 — release readiness

- **W8.1 (gate)**, Sonnet 5.5, on `750be9f0a`, with the later docs/website commits re-checked on `5298f2980`. **No failure, no fix commit.**
  - `cargo fmt` passes; clippy `-D warnings` passes with SAML on and off.
  - 7523 Rust tests passed, 0 failed, 40 ignored, over 359 test-binary runs. `federation_test` passes with SAML on (87). `axiam-api-grpc --features client` passes (147).
  - Every `scripts/check-*` passes, with its self-test.
  - Frontend: lint, `tsc`, a11y, build and vitest all pass; 2386 tests, lines 96.58 %. Website: lint, build and `npm audit` pass.
  - `cargo deny` and `cargo audit` (CI's ignores) pass.
  - RADIUS e2e locally, Docker with the pinned 3.2.8 image: **Static** and **Live** both pass. `fetch-crl-test.sh` passes 85/85 under dash and bash.
  - Not runnable here: the SDK drift checks (no SDK clones or token), the external link check (proxy 403), Playwright, Trivy, llvm-cov.
- **W8.2 (combined F4)**, Opus 5.5, `d288c0bd9`, `claude_dev/security-review-release-1.1.1-2026-10-20.md`: **no Critical, High or Medium.**
  - Every merge checked against both parents: the W1/W2/W4/W6 remerge diffs are empty, and the W3/W5 hand resolutions keep both sides.
  - Low #751 … #755, plus #741 re-rated to Low; Informational #756 … #758.
  - #749 stays Low, with an upgrade note. A new upgrade note for #755: roll replicas one at a time.
- **W8.3 (threat model)**, Sonnet 5.5, `8e90728f8`: 2.43.0, 488 threats (457 Mitigated, 21 Open, 10 N/A). T-483 and T-484 are Mitigated, T-488 is new. Static/Live (formerly D3/D4) on first use in §5.10. The website copies are regenerated.
- **W8.4a (version)** `750be9f0a`, moved forward (§12.7). **W8.4** `7ab871fad`, Sonnet 5.5:
  - `CHANGELOG.md` `[1.1.1] - 2026-10-20`: one entry per closed issue (52), and every upgrade note of §9 plus #749 and #755.
  - `website/src/version.ts` `SECURITY_VERIFIED_RELEASE` 1.1.1 / 2026-10-19; the 1.1.1 news post and `postSlug`; the roadmap's "Release 1.1.1" row.
  - `frontend/` and `website/` `package.json` stay `0.0.0`, as in 1.1.0.
- **Closes:** #664 … #699, #702 … #715 (#710 among them), #717, #718 — 52 issues. **Not closed:** #719 (W6.3), #513, #561.

---

## 13. Kickoff prompts

### Orchestrator

> Read `CLAUDE.md`, `claude_dev/release-1.1.1-plan.md` in full, and the
> seven 1.1.0 review documents its issues cite
> (`claude_dev/security-review-release-1.1.0-w1-2026-10-14.md`, `…-w2-2026-10-15.md`,
> `…-w3-2026-10-15.md`, `…-w4-2026-10-15.md`, `…-w5-2026-10-15.md`,
> `…-w6-2026-10-16.md`, `claude_dev/security-review-release-1.1.0-2026-10-16.md`)
> and `claude_dev/sdk-contract-1.62-conformance-review.md`. §11 holds every
> open question with its default: apply the default when the maintainer has
> not answered, and never ask a question §11 already answers. Run W1 … W6 as
> independent branches from `main`, each item by one executor at the model
> its row names, each wave but W6 ending with its F4 review; W5.1 (the
> rename) first within W5. Then W7 on the merged plan branch (W7.1, then
> eleven SDK sessions in parallel, then the conformance review); then W8.
> Record every wave in §12 as it lands. Re-size and re-model by §1.1
> whenever an executor stops short, and say so in §12.

### W1

> Read `CLAUDE.md`, the plan §0–§2 and §10, and the 1.1.0 W1 and W4
> reviews (`claude_dev/security-review-release-1.1.0-w1-2026-10-14.md`,
> `…-w4-2026-10-15.md`) and the combined review's R110-04. Check out
> `claude/release-1.1.1-w1` from `main`. Execute W1.1 … W1.13 in order, one
> signed commit per item, each with the tests and documents its row names;
> W1.7 takes v108 with its scope test and the newest-version bump; the
> threat-model entries a row names in the same commit; run the §10 gate
> before each commit and `cargo clean` between items. End with the F4 review
> (W1.14); fix Medium and higher in the wave, file Low and Informational on
> `1.1.x`. Record the head in §12.1.

### W2

> Read `CLAUDE.md`, the plan §0–§1, §3 and §10, D-2 and D-3, the 1.1.0 W2
> review and the combined review's R110-01. Check out
> `claude/release-1.1.1-w2` from `main`. Execute W2.1 … W2.9 in order, W2.1
> at Opus (it defines the keying rule; the gRPC extractor shares it). The
> FreeRADIUS guide is not yours: record the sentence W5.8 must write in your
> §12.2 note. End with the F4 review (W2.10). Record the head in §12.2.

### W3

> Read `CLAUDE.md`, the plan §0–§1, §4 and §10, D-4 and D-6, the 1.1.0 W3
> review and the combined review's R110-02. Check out
> `claude/release-1.1.1-w3` from `main`. Execute W3.1 … W3.11 in order; W3.3
> takes v109 (its number assumes W1's v108 merges first — the orchestrator
> confirms before you start); W3.1 and W3.7 at Opus; W3.8 and W3.11
> regenerate the spec. The contract is not yours: record in §12.3 what W7.1
> must write for §14. End with the F4 review (W3.12). Record the head in §12.3.

### W4

> Read `CLAUDE.md`, the plan §0–§1, §5 and §10, `claude_dev/radius-reply-profile-design.md`
> §4–§7 and the 1.1.0 W6 review. Check out `claude/release-1.1.1-w4` from
> `main`. Execute W4.1 … W4.7 in order; W4.1 and W4.4 at Opus; W4.6 runs the
> console's test file and type-check. The contract and the recipe guide are
> not yours (W7.1, W5). End with the F4 review (W4.8), which reads H1 … H6
> against the code. Record the head in §12.4.

### W5

> Read `CLAUDE.md`, the plan §0–§1, §6 and §10, D-1, `docs/pki/freeradius.md`
> and `docker/radius/README.md` in full, and the 1.1.0 W5 and W6 reviews.
> Check out `claude/release-1.1.1-w5` from `main`. Execute **W5.1 first**
> (the rename, one commit, `git mv` for the files, the generated spec,
> registry and `apiIndex.ts` regenerated, the DCR/CIMD `D3`/`D4` under
> `frontend/src/pages/settings/` untouched), then W5.2 … W5.8 in the new
> names. The oracle is `radius-e2e.yml` on the pull request; run
> `freeradius -XC` and the e2e locally only where Docker exists. End with
> the F4 review (W5.9). Record the head in §12.5.

### W6

> Read `CLAUDE.md`, the plan §0–§1, §7 and §10, and D-9. Check out
> `claude/release-1.1.1-w6` from `main`. Execute W6.1 … W6.3; for W6.3 read
> the sparse index once and act as D-9 says. No F4 of your own. Record the
> head and the version you read in §12.6.

### W7

> Read `CLAUDE.md`, the plan §8, §10 and §11 (D-5), `sdks/CONTRACT.md` §6.1,
> §12.1, §14, §31.3, §33, §34.6 and §36, and
> `claude_dev/sdk-contract-1.62-conformance-review.md`. On the plan branch,
> execute W7.1 (the §34.7 record, items (a) … (g); regenerate the spec and
> the registry). Then, one session per SDK in parallel, W7.2 … W7.12 on
> `claude/contract-1.63` in each SDK repository, each a draft PR vendoring
> the plan branch byte for byte, with the SDK's own issue(s) and the extras
> of §8.2, closing the issue(s) on a `Closes` line. Then W7.13, the
> conformance review, at Opus; fix Medium and higher in the SDK PRs. Record
> the heads and the PR numbers in §12.7.

### W8

> Read `CLAUDE.md` and the plan §9, §10 and §12. On `claude/release-1.1.1`,
> execute W8.1 … W8.5 in order: the gate, the combined review at Opus, the
> threat-model reconciliation (2.43.0, the profile names in §5.10, the
> website copies), the CHANGELOG and the version, the coverage check. Open
> the pull request against `main` with the `Closes` lines of §2 … §8 (and
> #710), the SDK PRs linked, and the issue-by-issue summary. Record the head
> in §12.8. Do not tag and do not merge.
