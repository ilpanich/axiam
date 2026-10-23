# Release 1.1.2 plan — the `1.1.x` milestone after 1.1.1: the 1.1.1 review findings, contract 1.64 and the SDK follow-ups

> **Status: READY — every decision in §11 has a default the orchestrator
> applies unless the maintainer answers otherwise.** Written 2026-10-22 against
> `main` at `dedbf81` (two merges after the `v1.1.1` tag). It covers the
> **47 open issues** on the `1.1.x` milestone: **36 on `ilpanich/axiam`**
> (#720 … #741, #746, #747, #750 … #758, #760, plus **#513** and **#561**,
> which depend on the maintainer, §0.3) and **11 on the eleven SDK
> repositories** (one each). It also binds what happens to every issue that
> is **opened while the plan runs** (§1.4): the release closes them too.
>
> **Why 1.1.2.** Nothing here adds a route. The waves close the Low and
> Informational findings the 1.1.1 reviews filed (R111W1 … R111W5, R111-01 …
> R111-08), the three contract questions the maintainer answered on
> 2026-10-20 (#760, #750 → contract **1.64**), and the contract 1.63
> conformance follow-ups on the eleven SDKs. No migration is expected
> (§10; v110 is reserved for the one case §4 names). One configuration value
> gains a meaning (`AXIAM__RATE_LIMIT__TRUSTED_PROXIES=none`, D-3).
>
> **Shape.** Nine waves. W1 … W6 are independent and branch from `main`;
> W7 (contract 1.64, the eleven SDK re-syncs and their issues) needs every
> wave that changes the spec; W8 (release readiness) needs everything; W9
> (the sweep) closes what the W8 review files. As for 1.1.1, the waves merge
> into one plan branch, `claude/release-1.1.2`, and **one pull request**
> closes every `ilpanich/axiam` issue on a `Closes` line. The eleven SDK
> repositories get one pull request each, closing their own issue.
>
> **Execution.** One **Opus 5.5 orchestrator** session runs the plan. It
> spawns one executor per task at the model its row names (§1.1), runs the
> gate of §10 before every commit, and ends each wave but W6 with an F4
> security review of the wave diff (Opus 5.5). The orchestrator writes code
> only to resolve a merge; everything else is an executor's. Every commit is
> signed; nothing is closed by hand.
>
> **Three rules this plan keeps from 1.1.1 and one it adds.** Test coverage
> may not go down (§1.2). Documentation moves with the code (§1.3). Where
> the plan and a file disagree, the file wins (§10). **New:** a finding a
> wave review files is fixed in this release, in its wave, whatever its
> severity (§1.4); an issue the maintainer opens on `1.1.x` while the plan
> runs is taken into the wave whose files it touches.
>
> **What the agent does not do.** It does not tag, does not merge, does not
> run the conformance suites, does not dispatch benchmark runs, and does not
> answer a contract question on its own: every question is in §11, with a
> default.

---

## 0. The state, measured (2026-10-22)

Verified on the tree, not taken from the issues. Where an issue and the tree
disagree, the tree wins and the task says so (§0.1).

| Fact | Measured | Evidence |
|---|---|---|
| Platform version | `1.1.1`; tags `v1.1.0`, `v1.1.1`; `main` at `dedbf81` (PR #763, the mass-tag fix, and dependabot #762 after the release) | `Cargo.toml:62`; `git ls-remote --tags origin` |
| CHANGELOG | `## [Unreleased]` empty; `## [1.1.1] - 2026-10-20` | `CHANGELOG.md:8-10` |
| Contract | **1.63**; its record is **§34.7**; next record **§34.8**; §34.7 was amended once (W7.1b, C163-06 and C163-11) | `sdks/CONTRACT.md:13610` |
| Threat model | **2.43.0**, 488 threats (457 Mitigated, 21 Open, 10 N/A); newest id **T-488**; next free **T-489** | `claude_dev/threat-model-stride.md:10-12`; `Axiam.json` |
| Schema | newest migration **v109** (the sweep index and `oauth2_refresh_token.dpop_jkt`); next **v110**; the newest-version assertion must be bumped with each | `crates/axiam-db/src/schema.rs:5216-5578` |
| Coverage | Rust (CI `cargo-llvm-cov`, job 118693623671 on the 1.1.1 head): **91.81 %** lines; per crate api-rest 90.07, oauth2 92.64, db 93.58, core 95.04, server 85.86, audit 91.92, amqp 81.86, api-grpc 95.12, pki 90.78, authz 98.35. Frontend: vitest `thresholds.lines: 96.48` (achieved 96.58 %) | `release-1.1.1-plan.md` §12.8; `frontend/vitest.config.ts:29-31` |
| Spec | `sdks/openapi.json` `info.version` 1.1.1; `docs/api/openapi.json` is a symlink to it | `sdks/openapi.json` |
| SDK heads | the eleven contract-1.63 PRs are merged; each `CHANGELOG.md` opens with an empty `[Unreleased]` over `[1.1.1]` (Go and PHP: `[1.1.1] - Unreleased`, the maintainer's tagging) | each SDK clone |
| Open issues | axiam 36 (all on `1.1.x`); SDKs 11 (one each, all on `1.1.x`) | GitHub, 2026-10-22 |
| Open PRs | none on `ilpanich/axiam` that this plan touches | GitHub |
| Benchmark draft | sixth (run 5, `1.0.0-alpha24`); no run-6 numbers in the tree; `claude_dev/run6-runbook.md` still pins `1.0.0-beta18` as the image to measure | `benchmarks/PUBLIC_BENCH_ANALYSIS.md:1`; `run6-runbook.md:3-8` |
| Certification | T23.1.4 … T23.1.7 executed 2026-10-03 (`competitor-gap-remediation-plan-2026-10-02.md:227-282`); `docs/conformance/` holds runs up to 2026-09-14; nothing sent | the plan; `docs/conformance/` |

### 0.1 Where the issues and the tree disagree

| # | What the issue says | What the tree says | Consequence |
|---|---|---|---|
| 757 | "read the platform PR's code-scanning results against this list; dismiss or fix" | three high `cleartext-logging` alerts were already fixed on PR #759 (`e1f06663e`, 1.1.1 plan §12.8) | W6.1 reads code scanning on `main`, fixes what is still open from the issue's list, and records what `e1f06663e` already took |
| 739 | three `cleanup.rs` comments, T-472, the dead-letter line | the 1.1.1 W1 fix commit `fc77c562f` took "#739's text items" (plan §12.1) yet the issue stayed open; which of (a) … (c) remain is not recorded | W1.7 is **verify and close**: diff each site against the issue's wording, edit only what still differs, and name in the commit body what was already done |
| 750 | "this issue tracks them if that commit does not" (C163-10, C163-11) | W7.1b `d919ba0cc` took **C163-11** (plan §12.7); **C163-10 was not applied** (plan §12.7, Q3) | W7.1 takes C163-10 only; C163-11 is recorded as done |
| 760 | "No SDK parses that row's metadata, so no SDK changes" (Q1); "all eleven SDKs must conform in the 1.64 round" (Q2) | consistent with the tree | Q1 is contract text only (W7.1); Q2 is one code item and one test in each of the eleven SDK sessions (§8.2) |
| 758 (b) | `D3`/`D4` in `Axiam.json` and the generated `threatModel.ts` | the 1.1.1 W8.3 reconciliation kept the dated pass descriptions by design (1.1.1 plan §6.1: "history, not rewritten") | W8.3 edits only the **current** text the issue lists (`reasonOutOfScope`, the "since 1.1.0 (RADIUS D4)" sentence, the STRIDE line 4767); dated pass descriptions stay |
| 725 | add to the CHANGELOG `[1.1.1]` upgrade note | `[1.1.1]` is released and tagged | D-9: the note goes under `[1.1.2]` as "Upgrading from 1.1.0 directly"; `[1.1.1]` is not rewritten |
| 513 | four unchecked boxes (T23.1.4 … T23.1.7) | all four were executed on 2026-10-03 with commits named in the gap plan | W6.4 ticks the boxes with one comment naming the commits; the submission (X5.3) stays the maintainer's |
| 561 | "run 6 … after W6a merges"; the runbook pins `1.0.0-beta18` | 1.1.1 is the current release; no run-6 numbers exist | W6.3 re-pins the runbook to the `1.1.1` image and re-checks the three target versions; W6b (the seventh draft) is a conditional session, §0.3 |

### 0.2 What this plan could not do

- It did not run the RADIUS end-to-end (no Docker in the planning sandbox).
  W5's oracle is `radius-e2e.yml` on the pull request, plus `freeradius -XC`
  where Docker exists.
- It did not count current line coverage; the figures the gate compares
  against are 1.1.1's (§0, §1.2).
- SAGE memory was not reachable from the planning session; nothing here
  comes from it.
- Every `file:line` below is the issue's; the 1.1.1 execution found most of
  them stale by the time the executor read them. Executors re-locate before
  editing and never trust a line number.

### 0.3 Issues that depend on the maintainer, and what this plan does for them

| # | Title | What the plan does | What stays the maintainer's |
|---|---|---|---|
| 513 | Phase 23 G-1: OpenID Basic OP and FAPI 2.0 certification submissions | W6.4: tick T23.1.4 … T23.1.7 on the issue with the commits that executed them; verify `docs/conformance/REVIEW-JUDGEMENTS.md` and the X5.3 package in `fapi-certification-submission.md` still match the 1.1.1 tree (the cookie-off-`/oauth2/*` rule of 1.63 and the 1.1.1 device-grant changes touch the flows) and amend where not | fresh runs of both plans on the `1.1.1` image, the submission, the website mark. The issue closes with the submission, not with this PR |
| 561 | Phase 23 G-10: benchmark run 6 with four targets | W6.3: re-pin `run6-runbook.md` to `ghcr.io/ilpanich/axiam/server:1.1.1`, re-check the Keycloak, Zitadel and authentik patch versions, smoke the compose files where Docker exists; **W6b** (one Sonnet 5.5 session, the seventh draft, the comparison rows, the website numbers) runs as soon as the §10 numbers are in the tree, inside this plan if they arrive before W8, else as the first task of the next | the run on the G-box and the numbers. The issue closes with W6b's merge |

Both carry the `1.1.x` milestone; neither is on this plan's `Closes` line
unless its condition is met before W8.4 writes the PR body.

---

## 1. Scope — every open issue, one wave each

| # | Title (short) | Severity | Wave | Task | Size | Model |
|---|---|---|---|---|---|---|
| 737 | R111W1-03: an erasure cut between its anonymization and its record is recovered without its proof or the second revocation | Low | W1 | W1.1 | L | **Opus 5.5** |
| 738 | R111W1-04: two replicas run one erasure at once | Informational | W1 | W1.2 | M | **Opus 5.5** |
| 753 | R111-03: an erased user's refresh-token rows are revoked, never deleted; no sweep | Low | W1 | W1.3 | M | Sonnet 5.5 |
| 736 | R111W1-02: the CRL cache refuses its own list while the datastore clock leads | Low | W1 | W1.4 | S | Sonnet 5.5 |
| 740 | R111W1-06: the Vault-reason sanitiser misses a token after an escape | Informational | W1 | W1.5 | S | Sonnet 5.5 |
| 758 (e), (f) | erasure rows: `grantee.id` not pseudonymized, no `network_role.unassigned` row; no recovery concurrency test | Informational | W1 | W1.6 | S | Sonnet 5.5 |
| 739 | R111W1-05: text behind the code after W1 | Informational | W1 | W1.7 | S | Sonnet 5.5 |
| 751 | R111-01: a junk `Authorization` header detaches a cookie request from its user in the request row | Low | W2 | W2.1 | M | Sonnet 5.5 |
| 752 | R111-02: audit and log IPs ignore the `TRUSTED_PROXIES` rule | Low | W2 | W2.2 | M | Sonnet 5.5 |
| 754 | R111-04: the principal rate-limit key trusts a token the extractor refuses; no refund on 401 | Low | W2 | W2.3 | M | **Opus 5.5** |
| 731 | R111W2-01: the empty-`TRUSTED_PROXIES` WARN ignores the gRPC listener's TLS | Low | W2 | W2.4 | S | Sonnet 5.5 |
| 732 | R111W2-02: a non-UTF-8 `TRUSTED_PROXIES` is read as empty; no boot-refusal test | Informational | W2 | W2.5 | S | Sonnet 5.5 |
| 733, 758 (g) | R111W2-03: the audit-wrap scan and the gRPC sweep registration pin less than they read | Informational | W2 | W2.6 | M | Sonnet 5.5 |
| 735 | R111W2-05: the bucket-name scan does not read `increment_by` keys | Informational | W2 | W2.7 | S | Sonnet 5.5 |
| 741 | R111W2-06: an AMQP-ingested audit row is indistinguishable from a server-written one | Low | W2 | W2.8 | M | Sonnet 5.5 |
| 758 (a), (c), (d) | `TRUSTED_PROXIES` "honour nobody"; `authenticated: true` on a signature check; action constants not pinned to the grammar | Informational | W2 | W2.9 | M | Sonnet 5.5 |
| 734 | R111W2-04: T-212 and T-428 still name the removed public-client bucket | Informational | W2 | W2.10 | S | Sonnet 5.5 |
| 755 | R111-05: the `_migration_lock` is never checked | Low | W3 | W3.1 | M | **Opus 5.5** |
| 729 | R111W4-05: the runner applies an older migration out of order on a false claim | Informational | W3 | W3.2 | M | **Opus 5.5** |
| 746 | R111W3-03: the admin `PUT` widens a self-registered client's resources and redirects | Informational | W3 | W3.3 | M | Sonnet 5.5 |
| 747 | R111W3-04: text and hygiene after W3; the v109 `EXPLAIN` pin | Informational | W3 | W3.4 | S | Sonnet 5.5 |
| 756 | R111-06: the spec does not declare four refusals | Informational | W3 | W3.5 | M | Sonnet 5.5 |
| 726 | R111W4-02: a cleared network write's success row can be lost | Low | W4 | W4.1 | M | **Opus 5.5** |
| 727 | R111W4-03: deleting a role with a `network:` deny leaves no row | Low | W4 | W4.2 | S | Sonnet 5.5 |
| 728 | R111W4-04: the reconcile revokes from a tenant whose kind it failed to read | Informational | W4 | W4.3 | S | Sonnet 5.5 |
| 730 | R111W4-06: text and audit-row content after W4 | Informational | W4 | W4.4 | M | Sonnet 5.5 |
| 720 | R111W5-01: concurrent 401s put the refused token back in the Live cache | Low | W5 | W5.1 | M | Sonnet 5.5 |
| 721 | R111W5-02: a lock-busy `fetch-crl` run skips the age check | Informational | W5 | W5.2 | S | Sonnet 5.5 |
| 722 | R111W5-03: the 401 retry's comment and tests claim more than they show | Informational | W5 | W5.3 | S | Sonnet 5.5 |
| 723 | R111W5-04: the e2e filter misses five paths | Informational | W5 | W5.4 | S | Sonnet 5.5 |
| 724, 758 (b) code | R111W5-05: rename leftovers and hygiene | Informational | W5 | W5.5 | S | Sonnet 5.5 |
| 725 | R111W5-06: T-462 and the upgrade note after W5 | Informational | W5 | W5.6 | S | Sonnet 5.5 |
| 757 | R111-07: test messages CodeQL flags | Informational | W6 | W6.1 | S | Sonnet 5.5 |
| 758 (h), (i) | `bench-quick` `quickvus`; `apiIndex.ts` regenerated by no CI job; the v109 note | Informational | W6 | W6.2 | S | Sonnet 5.5 |
| 561 | benchmark run 6 — the runbook re-pin (W6b conditional) | — | W6 | W6.3 | S | Sonnet 5.5 |
| 513 | certification — bookkeeping and the package re-check | — | W6 | W6.4 | S | Sonnet 5.5 |
| 760, 750 | contract 1.64 (Q1, Q2, C163-10) and the W1 … W5 items the contract records | — | W7 | W7.1 | M | Sonnet 5.5 |
| SDK ×11 | the contract 1.63 conformance follow-ups and the §14.2 poll rule (§8.2) | Low / Informational | W7 | W7.2 … W7.12 | S–M | Sonnet 5.5 (Rust: see §8.2) |
| — | contract 1.64 conformance review | — | W7 | W7.13 | — | **Opus 5.5** |
| 764 | R112W5-01: the Live token cache's read can insert the `-` sentinel | Low | W5 | sweep | M | **Opus 5.5** |
| 765 | R112W5-02: the concurrent rotation step neither forces nor checks its race | Informational | W5 | sweep | M | **Opus 5.5** |
| 766 | R112W5-03: text after W5 (lock-held alert, T-486, the upgrade note's module) | Informational | W5 | sweep | S | Sonnet 5.5 |
| 767 | R112W5-04: hygiene after W5 (schema test message, `mkdir` lock case, header line) | Informational | W5 | sweep | S | Sonnet 5.5 |
| 774 | R112W5-05: `check-token-cache.py` misses the action-block and optional call forms | Informational | W5 | sweep | S | Sonnet 5.5 |
| 768 | R112W3-01: the admin `PUT` bounds a CIMD client's redirects by the DCR list | Informational | W3 | sweep | S | Sonnet 5.5 |
| 769 | R112W3-02: the migration lease's refresh and own-row release are untested | Informational | W3 | sweep | M | **Opus 5.5** |
| 770 | R112W3-03: the k8s liveness probe kills a replica waiting on the lease | Informational | W3 | sweep | S | Sonnet 5.5 |
| 771 | R112W3-04: the non-additive gap refusal has no procedure | Informational | W3 | sweep | S | Sonnet 5.5 |
| 772 | R112W3-05: the hash gate's `503` undeclared on password change and reset confirm | Informational | W3 | sweep | S | Sonnet 5.5 |
| 773 | R112W3-06: text and hygiene after W3 | Informational | W3 | sweep | S | Sonnet 5.5 |
| 775 | R112W4-01: a revocation's cache flush and stale-claim row still ride the handler's future | Low | W4 | sweep | M | **Opus 5.5** |
| 776 | R112W4-02: an orderly stop does not wait for a cleared write's spawned task | Informational | W4 | sweep | M | **Opus 5.5** |
| 777 | R112W4-03: the reconcile still revokes organization-level actions from an unresolved tenant | Informational | W4 | sweep | S | Sonnet 5.5 |
| 778 | R112W4-04: `refusal_of` reads index names as substrings | Informational | W4 | sweep | S | Sonnet 5.5 |
| 779 | R112W4-05: text after W4 (`before`, T-484's re-bind claim, "five" actions) | Informational | W4 | sweep | S | Sonnet 5.5 |
| 780 | R112W1-01: W1.6 turns `network_gate_enumeration_test` red (blocks W1's merge) | Low | W1 | sweep | S | Sonnet 5.5 |
| 781 | R112W1-02: the refresh-token sweep is one unbounded `DELETE` over full scans | Low | W1 | sweep | M | Sonnet 5.5 |
| 782 | R112W1-03: two new `audit_log` reads on the erasure path scan the tenant's trail | Informational | W1 | sweep | S | Sonnet 5.5 |
| 783 | R112W1-04: T-254 on replay records after #753 | Informational | W1 | sweep | S | Sonnet 5.5 |
| 784 | R112W1-05: a unit stalled past the lease still scrubs and re-anonymizes the erased account | Informational | W1 | sweep | M | **Opus 5.5** |
| 785 | R112W1-06: text and hygiene after W1 | Informational | W1 | sweep | S | Sonnet 5.5 |
| 786 | R112W2-01: a revoked-session token still spends its user's principal allowance (in-process governor) | Low | W2 | sweep | M | **Opus 5.5** |
| 787 | R112W2-02: the D-12 verdict is left by some extractors only | Informational | W2 | sweep | S | Sonnet 5.5 |
| 788 | R112W2-03: the action-grammar pin misses `pub(crate)` and `&'static str` constants | Informational | W2 | sweep | S | Sonnet 5.5 |
| 789 | R112W2-04: "a row without `ingested_via` was written by the server" is false before 1.1.2 | Informational | W2 | sweep | S | Sonnet 5.5 |
| 790 | R112W2-05: the gRPC address rule is a hand-copied twin; no gRPC test of `none` | Informational | W2 | sweep | S | Sonnet 5.5 |
| 791 | R112W4-06: the decision cache can insert a decision computed before a revocation's flush (pre-existing D7) | Informational | W4 | sweep | M | **Opus 5.5** |
| 792 | R112W1-07: a stalled unit's role pass overlapping its successor's can write a second `network_role.unassigned` row | Informational | W1 | sweep | S | Sonnet 5.5 |
| new | every issue filed while the plan runs (§1.4) | any | its wave / W9 | — | by §1.1 | by §1.1 |

### 1.1 How the model is chosen

The rule of the 1.0.1, 1.1.0 and 1.1.1 plans, unchanged, so that the
orchestrator can re-derive it when a task turns out larger than sized.
"Best but cheapest" means the cheapest of the two that can be trusted with
the row's *definition*, not with its typing:

- **Opus 5.5** where the task *defines* behaviour under adversarial input
  or concurrency (a lease whose lifetime is the fix — W1.2, W3.1; a
  cancellation boundary — W4.1; a recovery that must redo part of a cut
  erasure exactly once — W1.1; the migration runner's refusal rule — W3.2),
  or where the issue proposes two designs and the executor has to choose on
  the evidence in the tree with a credential at stake (W2.3). Every F4
  review, the conformance review and the orchestrator are Opus 5.5.
- **Sonnet 5.5** where the issue already states the fix, the tree holds a
  precedent at a named `file:line`, and the oracle is a test the issue
  names. The recipe and script fixes (W5), the SDK sessions (W7), the spec
  and text tasks, and the release-readiness tasks are of this kind.

Expected cost, counted in executor sessions: W1 8 (three Opus, the F4
included), W2 11 (two Opus), W3 6 (three Opus), W4 5 (two Opus), W5 7 (one
Opus), W6 4 (none; its review is W8.2's), W7 13 (one Opus), W8 5 (one
Opus), W9 2 (one Opus). Roughly **61 sessions, 14 of them Opus**, plus the
orchestrator and whatever §1.4 adds. W1.1 and W4.1 are the long poles; W7's
eleven SDK sessions run in parallel.

### 1.2 Test coverage: keep or improve

- Every row names its test. A code change without a test is not a commit;
  a text-only row says "none (text)" and names the checker that reads it.
- **Rust.** Coveralls reports the PR against `main`'s baseline (1.1.1,
  91.81 %, per-crate figures in §0). W8.5 reads the Coveralls check on the
  plan PR: a decrease on any touched crate is a defect to fix before the
  review, not a note. Executors do not run `just coverage` per commit; they
  run the **full test binaries of every crate they touch, and of every
  crate whose error type or public signature a commit changes** (the 1.1.1
  W4.5 lesson), and W8.1 runs `cargo llvm-cov -p <crate>` on the crates
  whose coverage W8.5 questions.
- **Frontend.** `frontend/vitest.config.ts` `thresholds.lines` is 96.48 and
  the job prints the achieved figure. No console task is planned; W8.5
  raises the threshold to the achieved figure less 0.1 if it moved, never
  lowers it.
- **Scripts.** A shell or Python fix (W5.2, W6.2, W2.7's scan) extends the
  script's own test (`fetch-crl-test.sh`, the `--self-test` of the Python
  checkers, the scan test's synthetic sources).
- **SDKs.** Each SDK session runs the SDK's own suite and adds the tests its
  issue names; a session that cannot run a suite (a missing toolchain in
  the sandbox) says so in its PR body and the orchestrator reads CI.

### 1.3 Documentation alignment

Each row names what it changes beyond code; the pattern is 1.1.1's:
`docs/` (the operator's and admin's guides), `website/src/docs/*.ts` (the
readable front door, which links out and duplicates nothing normative),
`sdks/CONTRACT.md` (W7.1 only), the threat model (the entry's own dated
text, in `threat-model-stride.md` and `Axiam.json`, reconciled once by
W8.3), `CHANGELOG.md` (one entry per closed issue, ending in its number;
W8.4 writes them from the §12 records) and the two generated spec files.
`scripts/check-doc-links.sh`, `check-remediation-evidence.py` and the
website's `tsc`/build are the oracles for text.

### 1.4 Issues that arise while the plan runs

1.1.1 sent every Low and Informational finding of its reviews to the next
patch. This plan closes them in the release they are found in:

- **A finding of a wave F4 (W1.8, W2.11, W3.6, W4.5, W5.7).** Medium and
  higher are fixed in the wave before anything else, as before. Low and
  Informational are **also fixed in the wave**: the reviewer files them as
  issues on `1.1.x` (so each has a number for the `Closes` line and the
  CHANGELOG), and one added executor session, the wave's **sweep slot**,
  takes them in order of severity at the model §1.1 gives each; the
  reviewer then re-reads the sweep's diff as a short addendum to the review
  document. A wave is not merged while its review has an open finding.
- **A finding of the combined review (W8.2).** W9.1 takes them all; W9.2
  re-reviews W9.1's diff. If W9.2 files anything, one more round (W9.3,
  W9.4) is allowed; what a third review would file is listed in the PR body
  under "Open after two sweeps" for the maintainer to rate, and the plan
  stops there rather than loop.
- **A finding of the conformance review (W7.13).** Medium and higher are
  fixed in the SDK PR before W8, as before; Low and Informational are fixed
  in the same SDK session before its PR leaves draft. The review's §5
  carries only what §11 does not answer.
- **An issue the maintainer opens on `1.1.x` while the plan runs.** The
  orchestrator reads the milestone at every wave boundary (before cutting
  a wave branch, before each merge into the plan branch, before W8.4). An
  issue whose files belong to a wave not yet merged joins that wave as its
  last numbered task; one that belongs to a merged wave joins W9.1. It is
  sized and modelled by §1.1 and recorded in §12 under "intake". A
  maintainer's issue that asks a question goes to §11 as a decision with
  the orchestrator's proposed default, and waits.
- **An issue outside `1.1.x`** is not this plan's; the orchestrator names
  it in §12 and does nothing else.

---

## 2. Wave W1 — the erasure path, PKI and Vault (branch `claude/release-1.1.2-w1`)

W1.2 runs **before** W1.1: the exclusive claim changes which unit may reach
the recovery that W1.1 completes, and W1.6's concurrency test needs both.

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W1.2 | **#738.** `claim_for_purge` becomes exclusive with a lease: it takes the request when `purge_claimed_at` is `NONE` or older than the lease, stamps the claimant's `now`, and answers `false` to a second claimant; an erasure with no request row is leased by a stamp on the user row. The claim is released on every exit before the point of no return; the proof's unique violation is read as "another unit erased it", not an error. Amend T-444 and T-187 (dated). | `crates/axiam-db/src/repository/account_deletion.rs` (`claim_for_purge`); `crates/axiam-server/src/cleanup.rs` (`sweep_pending_purges`, `ErasureUnit::purge`); STRIDE T-444, T-187; `docs/deployment/README.md` (the sweep paragraph) | `cleanup_task.rs`: two sweeps over one store, run at once against one due account; one unit erases, the other skips without an error, the SSF sink sees one `account_purged`; the lease expires and a stalled claimant's account is taken over | M | **Opus 5.5** |
| W1.1 | **#737.** `record_owed_erasures`, for each claimed account: (1) writes the erasure proof unless one exists for `(tenant_id, user_id)`; (2) runs `revoke_user_certificates(tenant_id, user_id, "", "", …)` once more; then records and settles as today. The unit's guard is armed from a stamp the unit chooses and passes to `anonymize_user` (the orphan unit's pattern since #714), not from a read-back after the proof. Amend T-444 and T-336; the deployment guide's "The erasure and its proof, or the purge, stand" becomes true again and says how. | `cleanup.rs` (`erasure_steps`, `erase_and_record`, `record_owed_erasures`); STRIDE T-444, T-336; `docs/deployment/README.md`; `docs/compliance/gdpr-compliance.md` (the recovery sentence) | `cleanup_task.rs`: a unit held at a new step between the anonymization and the proof, cut at the teardown's bound; the next start's sweep writes the proof and the record once and completes the request at once (not after the lease); a certificate bound at that step is revoked by the recovery; the W1.2 double-sweep test still holds | L | **Opus 5.5** |
| W1.3 | **#753.** Erasure step (a) deletes the user's `oauth2_refresh_token` rows (after the revocation, in the same unit); the cleanup task schedules `RefreshTokenRepository::delete_expired` for revoked and expired rows older than the T-254 replay-detection window. `gdpr-compliance.md`'s "short-lived security/token material" sentence says the row is deleted at erasure and swept after the window. | `cleanup.rs:2544` (step (a)); `crates/axiam-db/src/repository/oauth2_refresh_token.rs` (`delete_expired`); `docs/compliance/gdpr-compliance.md:107-118`; `docs/deployment/README.md` (the cleanup-task table) | `cleanup_task.rs`: after an erasure no `oauth2_refresh_token` row names the user; a tick removes a token expired past the window and keeps a live one and one inside the window; `oauth2_refresh_token` repository test for the sweep's selection | M | Sonnet 5.5 |
| W1.4 | **#736.** `CaSlot::fresh` applies `this_update <= now` only to a named instant: `current()` passes `follow_clock` and skips the condition; the joiner's re-check in `resign` serves the landed list. | `crates/axiam-pki/src/crl.rs` (`fresh`, `resign`, `list_identity`) | `crl_test.rs`: a revocation dated 20 s ahead; `current()` once, then with every permit held `current()` answers the cached bytes; `current_at_signs_a_past_instant_at_that_instant` unchanged | S | Sonnet 5.5 |
| W1.5 | **#740.** `redact_tokens` also treats the end of a recognised escape (`\n`, `\t`, `\r`, `\"`, `\uXXXX`, `%XX`) as a boundary before `hvs.`/`hvb.`/`hvr.`; the escape is kept, the token masked. The legacy-prefix trade-off stays as T-470 documents it. The fake tokens are built at run time (the `b927d7e09` precedent), never literal. | `crates/axiam-pki/src/vault_forward.rs` (`redact_tokens`, `token_len`); STRIDE T-470 (dated) | `vault_forward::tests`: the three escape forms; `s.AbCdEfGh1234.next` documented as unmasked; the two host names intact; idempotence | S | Sonnet 5.5 |
| W1.6 | **#758 (e), (f).** `pseudonymize_actor` also clears `metadata.grantee.id` in `network_role.assigned`/`.unassigned` rows; the erasure's role removal writes one `network_role.unassigned` row per assignment it removes (the W4.3 row shape, system actor); the owed-erasure recovery gets the concurrency test the tenant-purge twin has. | `crates/axiam-db/src/repository/audit.rs:402-470`; `cleanup.rs:2599-2604`; `docs/admin/README.md` (the audit-action list: the erasure writes the row) | `cleanup_task.rs`: after an erasure the user's `network_role.*` rows carry no `grantee.id`; one `network_role.unassigned` row per removed assignment; two recoveries over one store record each owed erasure once | S | Sonnet 5.5 |
| W1.7 | **#739**, verify and close (§0.1). (a) the two `cleanup.rs` sentences and the `AuditedWork` doc worded as #688 does; (b) T-472's "#714 amendment" tail and the orphan-marker sentence corrected, dated, both copies; (c) the `append_off_thread` doc says the join-error branch is logged by the awaiter, or the panic is caught inside the closure (default: the sentence, D-11). Edit only what still differs from the issue's wording. | `cleanup.rs`; STRIDE T-472 (both copies); `crates/axiam-audit/src/dead_letter.rs` | none (text); `check-remediation-evidence.py`; `check-doc-links.sh` | S | Sonnet 5.5 |
| W1.8 | — | F4 review of the W1 diff → `claude_dev/security-review-release-1.1.2-w1-<date>.md`. Medium and higher fixed first; Low and Informational filed on `1.1.x` **and fixed in the wave's sweep slot** (§1.4); the review gains an addendum on the sweep's diff. | | | — | **Opus 5.5** |

Closes: #736, #737, #738, #739, #740, #753, and #758 (with W2, W5, W6, W8.3); from the W1.8 review (§1.4): #780, #781, #782, #783, #784, #785, and from its addendum #792.

---

## 3. Wave W2 — rate limiting, audit attribution and the boot (branch `claude/release-1.1.2-w2`)

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W2.1 | **#751.** One carrier rule for both readers, as a shared helper in `axiam-auth` (`access_token_carrier(req) -> Option<(Carrier, &str)>`): the `axiam_access` cookie first, then `Authorization` (`Bearer` or `DPoP`); a header that yields no verified token falls back to the cookie. The audit middleware and `parse_validated_claims` both call it. | `crates/axiam-audit/src/middleware.rs:634-664`; `crates/axiam-api-rest/src/extractors/auth.rs:716-750`; the new helper in `crates/axiam-auth` | `axiam-audit/tests/service_and_middleware.rs`: a valid cookie plus `Authorization: Basic eDp5` reaches a protected route and its request row names the cookie's user and tenant; the same with an invalid `Bearer`; a header-only request is unchanged; the full `axiam-api-rest` auth test binaries | M | Sonnet 5.5 |
| W2.2 | **#752** (D-5: record both). Every audit and log IP derives from the limiters' rule (`select_rate_limit_ip` with the configured `TrustedProxies`): the request row's `ip_address`, `client_info::client_ip`, and `http.client_ip` on the span; the request row also carries `forwarded_for_claimed` (the leftmost entry as asserted) when it differs. SEC-087's note and T-212 amended (dated). | `crates/axiam-audit/src/middleware.rs:513-516`; `crates/axiam-api-rest/src/extractors/client_info.rs:14-35`; `middleware/request_span.rs:179`; `crates/axiam-core/src/forwarded_for.rs` (the shared selector); `docs/deployment/README.md` (the `TRUSTED_PROXIES` row: "audit rows follow the same rule"); STRIDE T-212, SEC-087 | `service_and_middleware.rs`: with `TRUSTED_PROXIES=10.0.0.0/8`, a non-listed peer carrying `X-Forwarded-For: 1.2.3.4` produces a row whose `ip_address` is the peer and `forwarded_for_claimed` is `1.2.3.4`; from a listed peer, the rightmost untrusted hop; a `network_decide` decision row follows the rule | M | Sonnet 5.5 |
| W2.3 | **#754** (D-4: both). `verified_principal` keys on the principal only for a token the session extractor would admit (a session-carrying token, not `minted_for_client()`, not a resource-audience token), falling back to the address otherwise; the shared counter refunds its charge on `401`/`403` as it does on `429`. | `crates/axiam-api-rest/src/extractors/rate_limit.rs:357-396`; `middleware/rate_limit_shared.rs:458-466`; `docs/deployment/rate-limit-sizing.md` (the principal-key paragraph) | `rate_limit_principal_test.rs`: a device-grant token for user X sent N+1 times to a principal-keyed route gets `401` each time and X's session token still gets through; a resource-audience token likewise; the refund on `403` | M | **Opus 5.5** |
| W2.4 | **#731.** The empty-list WARN is decided on `config.server.tls.enabled || grpc_tls.is_some()`, naming which listener is on native TLS; the gRPC TLS settings are resolved before the WARN (or the gRPC half is emitted where they are resolved). T-212 amended (dated): both listeners. | `crates/axiam-server/src/boot.rs:1592-1606`; `tls.rs:1711`; `crates/axiam-core/src/forwarded_for.rs` (`boot_warning`); STRIDE T-212; `docs/deployment/README.md` (the WARN sentence) | a unit test of the decision with REST TLS off and gRPC TLS on (emitted, naming gRPC); `the_boot_warning_names_the_empty_list_on_native_tls` unchanged | S | Sonnet 5.5 |
| W2.5 | **#732.** `TrustedProxies::from_env`: `NotPresent` → empty; `NotUnicode` → `TrustedProxiesError` naming the variable; a lookup-closure twin (`from_lookup`) so the refusal is testable without the process environment. | `crates/axiam-core/src/forwarded_for.rs`; `boot.rs:1592-1593` | the twin returns an error for a non-UTF-8 value and for an unparsable entry, `Ok(empty)` when absent; the boot path's `panic!` reached through the twin | S | Sonnet 5.5 |
| W2.6 | **#733, #758 (g).** (a) `audit_wraps_routes` becomes behavioural: compose the App as `boot.rs` does and show a principal-keyed bucket on one of the five federation routes (the source scan is kept only as a comment-stripped "the wrap is on the `App::new()` chain" pin); the doc comment and T-477's sentence say "the audit middleware is an App-level wrap" (dated, both copies). (b) a unit test in `axiam-api-grpc`: build a family layer, feed *n* peers, `sweep_all()` past one replenish period, the cells go. | `crates/axiam-server/tests/audit_wraps_routes.rs`; `crates/axiam-api-grpc/src/middleware/rate_limit.rs` (`build_grpc_governor_layer`); STRIDE T-477 | as in the fix; the gRPC sweep test | M | Sonnet 5.5 |
| W2.7 | **#735.** The scan collects the literal prefix of every `increment_by(` / `increment(` key outside `axiam-db` (today `ciba_hint_cap` in `ciba.rs`) into the uniqueness check, or the prefix moves into a `const` the scan already reads. T-474's residual dropped (dated, both copies). | `crates/axiam-api-rest/tests/rate_limit_bucket_names_test.rs`; `crates/axiam-oauth2/src/ciba.rs:994`; STRIDE T-474 | a synthetic source whose `increment_by` prefix equals a middleware name is flagged; the tree passes | S | Sonnet 5.5 |
| W2.8 | **#741** (D-2: stamp). The AMQP consumer sets a server-owned provenance mark on every ingested row — `metadata.source = "amqp"` written **after** the message's metadata is merged, so a producer-supplied `source` cannot override it — and the server's own rows carry no such key. The console's audit list and detail show it; the export carries it. T-118 amended (dated). The contract sentence for §8 is **W7.1's** (W7.1 (d)). | `crates/axiam-amqp/src/audit_consumer.rs` (`process_audit_event`); `frontend/src/pages/audit/*` (one badge); `docs/admin/README.md` (the audit section); `docs/api/asyncapi.yml` (the field); STRIDE T-118 | an ingested `network_segment.created` (and W4's `network_role.assigned`) is persisted with `source: "amqp"`; a producer-supplied `source: "server"` is overwritten; a server-written row has no `source`; the console test for the badge | M | Sonnet 5.5 |
| W2.9 | **#758 (a), (c), (d).** (a) D-3: `AXIAM__RATE_LIMIT__TRUSTED_PROXIES=none` means "honour nobody": every request is keyed on its peer, no WARN; the guide's "Direct, no proxy" row says so; `check-config-key-coverage.py` still passes. (c) D-12: `authenticated` on the request row is set from the extractor's verdict — the extractor records a refusal in a request extension the middleware reads; a token the extractor refused is recorded `authenticated: false` with the outcome. (d) a unit test pins every server action constant (W4's `network_gate.rs:103-128`, `seeder.rs:676`, the reserved ones, W1.6's and W4.2's new ones) to W2.8's grammar. | `crates/axiam-core/src/forwarded_for.rs` (`parse`); `docs/deployment/README.md:936`; `crates/axiam-audit/src/middleware.rs:637-680`; `extractors/auth.rs`; `crates/axiam-core/src/models/audit.rs` (the grammar test) | `rate_limit_keying_test.rs`: with `none`, two requests from one peer with different `X-Forwarded-For` share a bucket and no WARN is emitted; `service_and_middleware.rs`: a device token at `/api/v1/device/verify` yields a row with `authenticated: false` and outcome `403`; the grammar test | M | Sonnet 5.5 |
| W2.10 | **#734.** T-212 drops "and the public-client bucket"; T-428 reads "after its route limiters and its DPoP check (the public-client bucket was removed in 1.1.1, #685)"; dated, both copies. | STRIDE T-212, T-428; `Axiam.json` | none (text); `check-remediation-evidence.py` | S | Sonnet 5.5 |
| W2.11 | — | F4 review of the W2 diff → `claude_dev/security-review-release-1.1.2-w2-<date>.md`; then the sweep slot and the addendum (§1.4). | | | — | **Opus 5.5** |

Closes: #731, #732, #733, #734, #735, #741, #751, #752, #754 (and #758's (a), (c), (d), (g)); from the W2.11 review (§1.4): #786, #787, #788, #789, #790.

---

## 4. Wave W3 — the schema runner, OAuth2 clients and the spec (branch `claude/release-1.1.2-w3`)

W3.1 and W3.2 touch the same function and may be one Opus 5.5 session with
two commits; W3.2 runs after W3.1 so that its refusal test runs under the
lease.

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W3.1 | **#755** (D-7). A real lease: `CREATE _migration_lock:startup SET holder = $id, expires = time::now() + 5m` fails when a live record exists; the runner waits and retries until the record is free or expired, refreshes it while migrating, and deletes only its own; a unique-index conflict on `_migration` is read as "another replica applied it" and the runner continues. The doc comment says what is true. If `_migration_lock` needs a `DEFINE` for the new fields, it is **v110**, additive, with its scope test and the newest-version bump. The CHANGELOG upgrade note of 1.1.1 ("roll replicas one at a time") is withdrawn by W8.4. | `crates/axiam-db/src/schema.rs:2508-2527` (`run_migrations`); `docs/deployment/README.md` (the migration paragraph) | `schema_test.rs`: two concurrent `run_migrations` against one in-memory datastore with a pending migration both return `Ok` and the version is recorded once; an expired lease is taken over; a live lease is waited on | M | **Opus 5.5** |
| W3.2 | **#729.** The runner refuses, with a boot error naming the version, an out-of-order application of a migration whose SQL is not additive (`UPDATE`, `DELETE`, `REMOVE`, `OVERWRITE`, or a `DEFINE` without `IF NOT EXISTS`); an additive one is applied with the existing `WARN`. The doc comment and the #704 sentence corrected. | `schema.rs:2484-2500`; `MIGRATIONS` | a unit test over `MIGRATIONS` that every migration above the newest released version (v107 at 1.1.1) is additive (W1's and W3's per-migration checks generalised); a schema test that a gap below a non-additive migration is a boot error, not an application; the W4.1 contiguity test unchanged | M | **Opus 5.5** |
| W3.3 | **#746** (D-13: two codes). On a `managed_by: dcr | cimd` row the admin `PUT` refuses `422 resource_exceeds_registration_policy` an `allowed_resources` entry outside the tenant's `external_client_allowed_resources`, and `422 redirect_exceeds_registration_policy` a redirect host outside `dcr_allowed_redirect_hosts`, with the held-value exemption the scope and grant checks use. Documented; the spec's `responses(...)` gains both; regenerate. | `crates/axiam-api-rest/src/handlers/oauth2_clients.rs::update`; `crates/axiam-oauth2/src/dcr.rs::validate` (shared helpers); `docs/admin/dynamic-client-registration.md`; `sdks/openapi.json` | `oauth2_client_test.rs`: an outside resource, and an outside redirect host, on a `dcr` row is `422` and leaves it unchanged; the same on an `admin` row is accepted; a held value still saves; the drift job | M | Sonnet 5.5 |
| W3.4 | **#747.** (a) the RFC sentence stays in the schema doc, the implementation note moves to a `//` comment; regenerate the spec. (b) the `oauth2_clients.rs::update` comment: "a self-registration never gives a row the device grant; an older admin edit may have". (c) `docs/api/device-flow.md` §3/§4 and T-447's #681 amendment gain "(a device token issued for another `resource` is refused `401` by the audience check first)". (d) the clustered-SurrealDB skew sentence on T-424, `cleanup.rs` and `CibaHintCap`'s doc. (e) the `EXPLAIN` pin for `rate_limit_bucket_updated_at` on the sweep's selection. | `crates/axiam-oauth2/src/device_service.rs` (the request type); `handlers/oauth2_clients.rs`; `docs/api/device-flow.md`; STRIDE T-447, T-424; `crates/axiam-db/tests/x3_wave2_query_plan_test.rs` | (e) `assert_uses_index(plan, "rate_limit_bucket_updated_at", …)` on the selection as `delete_stale_once` writes it; the drift job for (a); `check-doc-links.sh`, `check-remediation-evidence.py` | S | Sonnet 5.5 |
| W3.5 | **#756** (D-8: declare only). The `responses(...)` entries for `422 reserved_metadata_key` (tenants create/update), `409 already_exists` (the six certificate and CA operations), `503 service_unavailable` (the eight crypto-permit sites and login's hash gate) and `409 conflict` / `stale_version` (the ten role and permission operations); regenerate the spec and the registry; the digest. A unit test in `axiam-api-rest` lists the operations that must declare each of the four and reads the generated spec, so the next handler that returns one is caught. | the handlers the issue lists; `sdks/openapi.json`; `sdks/management-registry.json`; `website/src/apiIndex.ts` | the new spec test; the drift job; `check-spec-digest.py` | M | Sonnet 5.5 |
| W3.6 | — | F4 review of the W3 diff → `claude_dev/security-review-release-1.1.2-w3-<date>.md`; the sweep slot and the addendum. | | | — | **Opus 5.5** |

Closes: #729, #746, #747, #755, #756; from the W3.6 review (§1.4): #768, #769, #770, #771, #772, #773.

---

## 5. Wave W4 — network policy (branch `claude/release-1.1.2-w4`)

W4.1 runs first: W4.2's row and W4.4's row members are built from what
W4.1 carries on `GateClearance`.

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W4.1 | **#726** (D-6: the spawned task). `GateClearance` carries the role's name and its `network:` grants as the gate read them (it already computes `NetworkGrants::of(role_grants(…))`), and for a bind the account the certificate was taken from; `record_cleared` builds the row from the clearance, not from reads after the write. The repository write and the append run as one spawned task the handler awaits through its `JoinHandle`, so a client that goes away does not cancel the append. | `crates/axiam-api-rest/src/network_gate.rs:281-469` (`record_cleared`, `GateClearance`); `crates/axiam-authz/src/network_gate.rs` (what the gate returns); callers in `roles.rs` (six), `permissions.rs` (two), `certificates.rs` (`bind`) | `network_gate_test.rs`: drop the handler future right after the repository write returns (a store wrapper that signals and then pends) and the row exists; delete the role between the write and the append and the row still names it with the grants the gate saw; `r110w6_06_each_cleared_network_write_leaves_exactly_one_row_with_its_members` unchanged | M | **Opus 5.5** |
| W4.2 | **#727.** A `network_role.deleted` success row with the role's id, name and its `network:` grants (action, effect) as the gate read them, carried on the clearance; `record_cleared` gains the arm. Listed in `docs/admin/README.md`; T-484 restated (dated, both copies). | `handlers/roles.rs::delete`; `network_gate.rs` (`record_cleared`); `docs/admin/README.md`; STRIDE T-484 | `network_gate_test.rs`: the delete of a role carrying a `network:join` deny leaves exactly one `network_role.deleted` row naming the deny; one with only a `network:` allow leaves one naming it; one with no `network:` grant leaves none | S | Sonnet 5.5 |
| W4.3 | **#728.** In `reconcile_default_role_grants`, an unresolved tenant kind skips the network half for that tenant this boot, with one `warn` carrying the error; the seeder's withholding stays. T-483 amended (dated). | `crates/axiam-db/src/seeder.rs:309-318,825-862`; STRIDE T-483 | a unit test of the decision: a resolved ordinary tenant, the organization scope, an unresolved tenant — the unresolved case revokes nothing and grants nothing | S | Sonnet 5.5 |
| W4.4 | **#730.** (a) the `network_gate.rs` comment names `NetworkConflict::StaleRole`; (b) the reconcile's revoke counters split (organization-scope network revocations vs ordinary), the `warn` worded for both; (c) `docs/admin/README.md` lists `network_role.permission_revoked_by_reconcile` and says a group cannot hold a network role; (d) `network.rs:96-98` reworded, or `refusal_of` matches the `THROW` form exactly (default: match exactly, D-14); (e) T-457 and the `network_decide.rs` module doc name the global fingerprint read as a residual; (f) `certificate_binding.bound` records `before` (the account the certificate was taken from) and the nodes the gate checked; (g) the assignment row's `node` is the gate's node (`/network`'s id for a tenant-wide assignment). | `network_gate.rs:128-129,424-434`; `crates/axiam-server/src/main.rs:650-656`; `docs/admin/README.md`; `crates/axiam-db/src/repository/network.rs:96-145`; STRIDE T-457, T-484 | (f), (g): extend `r110w6_06_…` with a re-bind (`before` present) and a tenant-wide assignment (`node` = `/network`'s id); (d): a segment named `axiam:network_segment_version_stale` is a `duplicate_name`, not `stale_version`; `check-doc-links.sh`, `check-remediation-evidence.py` | M | Sonnet 5.5 |
| W4.5 | — | F4 review of the W4 diff → `claude_dev/security-review-release-1.1.2-w4-<date>.md`, reading H1 … H6 against the code once more; the sweep slot and the addendum. | | | — | **Opus 5.5** |

Closes: #726, #727, #728, #730; from the W4.5 review (§1.4): #775, #776, #777, #778, #779, and from its addendum #791.

---

## 6. Wave W5 — the FreeRADIUS recipe (branch `claude/release-1.1.2-w5`)

`docs/pki/freeradius.md`, `docker/radius/**`, `docker/docker-compose.radius*.yml`,
`crates/axiam-server/tests/radius_e2e.rs`, `.github/workflows/radius-e2e.yml` and
`website/src/docs/operate.ts` are **W5's files**: no other wave edits them.

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W5.1 | **#720** (D-10). `Cache-Read-Only := yes` beside `Cache-TTL := 0` on the drop, so an absent entry is not created; the retry's store uses a negative TTL (`Cache-TTL := "%{expr:0 - %{1} / 2}"`) that expires what is there and inserts this request's token. `docs/pki/freeradius.md` §5 and T-486 (dated, both copies) say a rotation under load costs one extra login per thread, not a re-poisoned cache. | `docker/radius/raddb/live/check-eap-tls:128-132,158-162`; `docs/pki/freeradius.md` §5; STRIDE T-486 | the Live e2e's rotation step runs two `eapol_test` attempts concurrently after the listener restart and asserts both accepted and the next one using the new token; where that cannot be made deterministic, the `radclient` probe shipped as a case under `docker/radius/tests/` (D-10) | M | Sonnet 5.5 |
| W5.2 | **#721.** `busy()` ends with `if near_expiry; then exit 3; fi; exit 0` (the age check is read-only and runs without the lock); the guide says exit 3 can carry a refusal, its reason on stderr. | `docker/radius/fetch-crl.sh:92-96,200-203`; `docs/pki/freeradius.md:537-548`; `website/src/docs/operate.ts` (the alert sentence) | `fetch-crl-test.sh`: hold the lock (`flock` in the background) beside a list near its end and assert exit 3 with nothing touched; under `dash` and `bash` | S | Sonnet 5.5 |
| W5.3 | **#722.** The `check-eap-tls` comment says every 4xx continues and anything but a `401` is rejected below, a 5xx or a transport failure ends the section; `radius_e2e.rs` counts the stub's decision calls (exactly two) and matches the `REST-HTTP-Status-Code` line; T-486's "refused after the one retry" aligned (dated). | `docker/radius/raddb/live/check-eap-tls:105-106`; `crates/axiam-server/tests/radius_e2e.rs:3183,3382-3385`; STRIDE T-486 | the strengthened e2e assertions, on `radius-e2e.yml` | S | Sonnet 5.5 |
| W5.4 | **#723.** The five paths (`tls.rs`, `extractors/auth.rs`, `axiam-auth/src/token.rs`, `network_decide_guard.rs`, `network_gate.rs`) added to the workflow's filter. | `.github/workflows/radius-e2e.yml:41-78` | the workflow runs on the PR (W5 touches the test); one `workflow_dispatch` where the orchestrator has the means | S | Sonnet 5.5 |
| W5.5 | **#724, #758 (b) code.** The two `D4` comments (`network.rs:752`, `network_decide_test.rs:775-780`); the commit-history correction recorded in `docker/radius/README.md`'s history note (not rewritten); `# shellcheck disable=SC2329` with the reason on `cleanup`; the header's "only SIGKILL" → "a signal other than HUP, INT or TERM". | `crates/axiam-core/src/models/network.rs`; `crates/axiam-api-rest/tests/network_decide_test.rs`; `docker/radius/fetch-crl.sh:81`; `docker/radius/README.md` | `shellcheck` at 0; `grep -rn -E '\bD[34]\b'` over `crates/` finds only the DCR/CIMD decisions | S | Sonnet 5.5 |
| W5.6 | **#725** (D-9). T-462 amended, dated, for exit 3 and `Cache-Control: no-cache`, naming the `fetch-crl-test.sh` cases; the fail-closed rename note written for **W8.4** as an "Upgrading from 1.1.0 directly" paragraph under `[1.1.2]`, listing the moved names (compose override, `raddb/live/`, `axiam_live`, `axiam-live.sh`, `AXIAM_LIVE_URL`/`SITE`, `/var/run/axiam-live`); `[1.1.1]` is not rewritten. | STRIDE T-462 (both copies); the §12.5 note for W8.4 | none (text); `check-remediation-evidence.py` | S | Sonnet 5.5 |
| W5.7 | — | F4 review of the W5 diff → `claude_dev/security-review-release-1.1.2-w5-<date>.md`; the sweep slot and the addendum. | | | — | **Opus 5.5** |

Closes: #720, #721, #722, #723, #724, #725; from the W5.7 review (§1.4): #764, #765, #766, #767, #774.

---

## 7. Wave W6 — CI, tooling and the two maintainer-dependent issues (branch `claude/release-1.1.2-w6`)

| Task | What | Where | Tests | Size | Model |
|---|---|---|---|---|---|
| W6.1 | **#757.** Read code scanning on `main` (the GitHub tool, or the maintainer's export if the API refuses); for each alert on the issue's list still open: labels or status-only messages in place of `{body}`/`{err}` in `device_flow_test.rs`, `vault_provider_test.rs`, `vault_ca_key_store_test.rs`, `network_gate_test.rs`, `vault_pki_test.rs`; a per-process random key in `permit_bound_test.rs` (and `ca_test.rs`, `cert_test.rs`) as `74ca43f9` did. Record what `e1f06663e` already took. | the five test files; `crates/axiam-pki/tests/permit_bound_test.rs:34` | the files' tests unchanged in what they assert; CodeQL quiet on the PR (W8.1 reads it) | S | Sonnet 5.5 |
| W6.2 | **#758 (h), (i).** (i) `bench-quick` validates `quickvus` as a positive integer before the run and fails early, naming it; `docs-ci.yml` (or `ci.yml`) regenerates `website/src/apiIndex.ts` with `gen-api-index.mjs` and fails on a diff, as the spec drift job does for the spec. (h) one sentence in `docs/deployment/README.md`'s migration paragraph: a development datastore that ran v109 before `7a9b002c` has v109 without `dpop_jkt` and fails closed; re-run the migration by deleting the v109 record. | `benchmarks/justfile`; `.github/workflows/docs-ci.yml`; `website/scripts/gen-api-index.mjs`; `docs/deployment/README.md` | `just -n` with a bad `quickvus` shows the refusal; the new CI step red on a deliberately stale `apiIndex.ts` once (prove, then restore) | S | Sonnet 5.5 |
| W6.3 | **#561, the re-pin.** `run6-runbook.md` measures `ghcr.io/ilpanich/axiam/server:1.1.1` (tag `v1.1.1`, commit recorded); the Keycloak, Zitadel and authentik rows re-checked against their registries for a later patch (pinned, dated); the `deploy=minimal` overlay and the credentials generator smoke-run where Docker exists, else recorded as not run. One comment on #561 saying the runbook is ready for the 1.1.1 image. **W6b** (conditional, Sonnet 5.5, M): when `benchmarks/results/run6/` is in the tree, the seventh draft of `PUBLIC_BENCH_ANALYSIS.md`, the three comparison documents' performance rows with dated change-log lines, `website/src/data.ts` and `Benchmarks.tsx`. | `claude_dev/run6-runbook.md`; `benchmarks/targets/*/`; (W6b) `benchmarks/PUBLIC_BENCH_ANALYSIS.md`, `claude_dev/competitor-comparison-*.md`, `website/src/data.ts`, `website/src/pages/Benchmarks.tsx` | `check-doc-links.sh`; (W6b) website `tsc`, lint, build; the numbers cross-checked against the raw results | S (+M) | Sonnet 5.5 |
| W6.4 | **#513, the bookkeeping.** Tick T23.1.4 … T23.1.7 on the issue with one comment naming their commits (`1218dbe` …, `ee3bac0`); re-read `docs/conformance/REVIEW-JUDGEMENTS.md` and the X5.3 package against the 1.1.1 tree (contract 1.63's cookie rule on `/oauth2/*`, the device-grant `403`, the `429 rate_limit_exceeded` at the token endpoint) and amend any judgement or package line the tree contradicts; list on the issue the two maintainer steps left (fresh runs on `1.1.1`, the submission). | `docs/conformance/REVIEW-JUDGEMENTS.md`; `claude_dev/fapi-certification-submission.md`; the issue | none (text); `check-doc-links.sh` | S | Sonnet 5.5 |

W6 has no F4 of its own: W8.2's combined review reads its diff.

Closes: #757, and #758 with the other waves. #561 and #513 stay open unless
§0.3's condition is met.

---

## 8. Wave W7 — contract 1.64 and the eleven SDKs (branch `claude/release-1.1.2-w7`, cut from the plan branch after W1 … W6 are merged into it)

### 8.1 W7.1 — the contract text (Sonnet 5.5, M)

`sdks/CONTRACT.md` becomes **1.64**; the record is **§34.8**. Items, each
marked *contract 1.64* inline where its rule lives:

- **(a) #760 Q1.** §27.11 rule 5: the erasure "carries the count, or `null`
  with `recovered: true` when the row was written by the start-up recovery
  and the count is not known". No SDK change.
- **(b) #760 Q2.** §14.2: "A `429 rate_limit_exceeded` on a poll is not
  terminal: the loop waits `Retry-After` (a minimum, capped at the
  `expires_in` deadline), counts it as one interval, does not raise the
  interval for it, and polls again", mirroring §33.7 rule 5; a §14.6 test
  (a mock answers one poll with `429` and `Retry-After`; the loop waits,
  polls again and completes; the interval is unchanged). **All eleven SDKs
  port it** (§8.2).
- **(c) #750 C163-10.** §27.6.2 item 4, the §27.9 bullet and §34.6 (ab):
  "naming the member, and the value where the SDK's decoded type keeps it
  (an SDK whose open enumeration decodes to a text-less `Unknown` names the
  member and says the value is unknown)". C163-11 is recorded as taken by
  W7.1b in 1.63.
- **(d) #741 (W2.8).** §8: an ingested row carries `metadata.source =
  "amqp"`, server-written; a producer's `source` key is overwritten. An SDK
  that reads audit rows needs no change; the consumer-side verifiers are
  unaffected.
- **(e) #746 (W3.3).** §27.4 rule 7's list gains `422
  resource_exceeds_registration_policy` and `redirect_exceeds_registration_policy`
  (the admin client `PUT`).
- **(f) #727 (W4.2).** Where §8 lists server-written action families
  informatively, `network_role.deleted` joins them; nothing becomes reserved.
- **(g) #756 (W3.5).** A sentence in §2 that the spec now declares the
  four refusals §27.4 rule 7 already lists; SDK error mapping is unchanged.
- **(h) §34.7** is closed by a pointer to §34.8; the Breaking Changes Log
  gains the 1.64 line (none breaking).
- Regenerate `sdks/openapi.json` and `sdks/management-registry.json`;
  `python3 scripts/check-spec-digest.py`; the drift job green on the wave.
- The 1.1.2 version bump (**W8.4a**, moved forward as in 1.1.1) lands
  before the SDKs re-vendor, so they vendor the final spec once.

### 8.2 W7.2 … W7.12 — the eleven SDK sessions (Sonnet 5.5, one session each, in parallel)

Every SDK: re-vendor `CONTRACT.md`, `openapi.json`, `management-registry.json`
and `proto/` from the plan branch byte for byte; port **(b)** with its §14.6
test; the SDK's own issue items below under D-15 (C163-10 under the relaxed
wording: keep the raw value where the issue proposes a non-breaking internal
addition, else say the value is unknown); `CHANGELOG.md` under the patch-bump
rule (a source-breaking change is recorded and bumps the minor); the README's
contract sentence and version snippets. Each SDK's PR is a draft on
`claude/contract-1.64` and closes its issue on a `Closes` line.
`scripts/check-sdk-artifact-drift.py` in the platform repository is green
once the eleven are merged.

| SDK | Issue | Its items | Size | Model |
|---|---|---|---|---|
| TypeScript | ilpanich/axiam-typescript-sdk#148 | **C163-12**: browser persona uses the fetch adapter with `credentials: 'omit'` for `/oauth2/*` (test: the per-request config carries both); **C163-08**: the §14.6 test signs in through `login()` against a mock setting `axiam_access` and `axiam_csrf`, runs the three `/oauth2/*` calls, then a management `POST` asserted to carry both; **C163-09**: assert the stated values in the `PUT` body; **C163-18**: README row labels | M | Sonnet 5.5 |
| Rust | ilpanich/axiam-rust-sdk#137 | **C163-07**: `unknown_open_enum` built with a `ValidationError` source (`e.validation()` is `Some`, `fields[0].field == member`); **C163-13**: `SsfReceiver` uses `http_bare()` for JWKS and discovery (test: no `cookie` on the JWKS GET after a cookie login); **C163-17**: the §14.6 control after the oauth2 calls, the CHANGELOG redirect note, `credentials: "omit"` on wasm32 `oauth2_post`, the dead non-`rest` branch dropped, `sign_payload`'s doc; **the `--no-default-features --features amqp` build fixed** (52 errors; a CI matrix cell added so it stays fixed) | M | Sonnet 5.5; the feature-gating fix escalates to **Opus 5.5** if the session finds it needs a module restructuring rather than `cfg` fixes |
| Python | ilpanich/axiam-python-sdk#102 | **C163-14**: the five `rreg` operations and `uma_request_ticket` send `Cookie: ""` and no `X-CSRF-Token` whenever the request carries a caller-passed `Authorization` (test: cookie login, then `uma_register_resource(pat)` carries the PAT and no session state; a management `POST` as control); **C163-08** as TypeScript; **C163-09**: parametrise over both members, assert the absence of `"future"`, `apply(unchanged)` with no write; **C163-18**: the docstring | M | Sonnet 5.5 |
| C | ilpanich/axiam-c-sdk#76 | **C163-10** (D-15): the refusal message says the value is unknown, no struct change; test `strstr(err.message, "unknown")`; **C163-20**: `build_headers` sends no adopted device bearer on `/oauth2/jwks` and `/oauth2/revocations` (§6.1 rule 11; test: a mock asserting no `Authorization` on both); a stated unknown `termination_action`/`service_type` test; the manifest's `refuse()` sets `transport_cause` 400 like the builders and the header doc says "400 with no HTTP exchange is a local refusal"; **C163-18**: the three texts | M | Sonnet 5.5 |
| C++ | ilpanich/axiam-cplusplus-sdk#78 | **C163-07**: `refuse_unknown_carried` throws `std::invalid_argument` (test catches it); **C163-08**: the control after `oidc_refresh` with `axiam_csrf` set by the mock (close if PR #77 already added it); **C163-09**: the `service_type` refusal, the stated case's body, `NoChange` with no write; **C163-10** (D-15): `termination_action_wire` / `service_type_wire` optionals and the value quoted; **C163-20**: the cookie-less handle pool bounded by `max_concurrent_requests` (test: *n*+1 concurrent `/oauth2/*` calls hold *n* handles) | M | Sonnet 5.5 |
| C# | ilpanich/axiam-csharp-sdk#110 | **C163-07**: `RequireNoUnknownCarried` throws `ValidationError` with a `FieldError`; **C163-08**: a real `AxiamClient` over a mock, `LoginAsync` then the three `/oauth2/*` calls asserting no `cookie`/`x-csrf-token`, then a management `POST` asserting both, full-path lookup; **C163-09**: `NoChange` for `service_type`; **C163-10** (D-15): internal `RawTerminationAction`/`RawServiceType` set at decode and quoted; **C163-20**: a pooled cookie-less handler for `/oauth2/*` (`PooledConnectionLifetime` default, `UseCookies=false`), and the `ConfigureFactoryHandler` doc on hand-composed handlers | M | Sonnet 5.5 |
| Go | ilpanich/axiam-go-sdk#102 | **C163-08**: the sign-in mock, `Login`, the three calls asserting no `Cookie`/CSRF, `Groups().Create` asserting both; **C163-09**: per member "stated → one PUT carrying the stated value" and "nothing differs → `IsConverged()`, no writes"; **C163-16**: `jwk.WithHTTPClient(c.httpc)` on `Register` (test: the JWKS fetch presents the SDK's client certificate / honours its timeout); **C163-18**: "before any write"; the README pin; **C163-19**: `isOAuth2Path` anchored to the base path | M | Sonnet 5.5 |
| Java | ilpanich/axiam-java-sdk#120 | **C163-08**: the login mock returns `axiam_csrf` and `X-CSRF-Token`; no `Cookie`/CSRF on device authorization and the token requests; `management().users().create(..)` as the control; **C163-09**: `NoChange` and `service_type` at `apply`; **C163-10** (D-15): the raw strings captured in `readNetwork`, quoted, length-capped; **C163-18**: the README's source-breaking list, the §31.3 rule 4 citation, "contract 1.63"; **C163-20**: `ManifestValidation` refuses a stated `UNKNOWN` `termination_action`/`service_type` | M | Sonnet 5.5 |
| Kotlin | ilpanich/axiam-kotlin-sdk#79 | **C163-07**: `unknownCarried` returns `ValidationError(msg, listOf(FieldError(member, …)))` (tests at `ManifestNetworkTest.kt:388,400`); **C163-09**: "a stated `serviceType` resolves it"; **C163-10** (D-15): `RAW_TIMESTAMPS`/`keepRawTimestamps` generalised to `termination_action_raw`/`service_type_raw`, quoted; **C163-18**: the README lines and the CHANGELOG label; **C163-19**: the `/oauth2` exclusion follows the discovered endpoints, not the base host | M | Sonnet 5.5 |
| PHP | ilpanich/axiam-php-sdk#86 | **C163-08**: a fifth queued response, `groups()->create`, `history[4]` carries `Cookie` with `axiam_access=` and `X-CSRF-Token: csrf-from-login`; **C163-09**: a data provider over both members for refuse, stated and `NoChange`; **C163-10** (D-15): the raw string recorded in the generated `fromArray()` on `Unknown` and quoted; **C163-18**: the two middleware comments (and a test that a retried request gets fresh headers), the CHANGELOG line on `toArray()`; **C163-19**: `str_starts_with($path, '/oauth2/')` anchored to the base URL's path prefix | M | Sonnet 5.5 |
| Swift | ilpanich/axiam-swift-sdk#77 | **C163-08**: `Set-Cookie: axiam_csrf=…` on the login mock and a management `POST` control after the `/oauth2/*` calls; **C163-18**: the README install snippets say the current version | S | Sonnet 5.5 |

Each session's gate: the SDK's own lint, type-check and unit suite (the
commands each `README.md` names), the conformance fixtures regenerated
where the surface changed (none expected: 1.64 adds no operation), the (b)
test worded identically in every SDK, and the §14.6 test of 1.63 unchanged.

### 8.3 W7.13 — conformance review (Opus 5.5)

`claude_dev/sdk-contract-1.64-conformance-review.md`, the 1.63 review's
method applied to the eleven heads: per-SDK report, findings index, and a
§5 of questions **only** for what §11 does not answer. Every finding is fixed
in the SDK PR before W8 (§1.4); the review gains an addendum per SDK whose
PR changed after the read.

Closes: #750, #760, and the eleven SDK issues in their own repositories.

---

## 9. Wave W8 — release readiness 1.1.2 (on `claude/release-1.1.2`)

| Task | What | Model |
|---|---|---|
| W8.1 | **Regression gate** on the merged plan branch, 1.1.1's W8.1 list: `fmt`; workspace clippy `-D warnings` with SAML on and off; every test binary crate by crate; the `client`-feature gRPC tests; the RADIUS e2e (both profiles) where Docker exists, else the workflow on the PR; every `scripts/check-*` and its self-test; frontend lint, `tsc`, a11y, build and vitest; website lint, `tsc`, build, `npm audit`; `cargo deny`, `cargo audit`; **the examples smoke and the E2E workflow on the PR** (the 1.1.1 lesson: the gate session had no Docker and missed a bootstrap break). Failures fixed on the plan branch, each a signed commit named in §12. | Sonnet 5.5 |
| W8.2 | **Combined F4 review** of the whole diff against `main` → `claude_dev/security-review-release-1.1.2-<date>.md` (W6's diff included); every finding filed on `1.1.x` and handed to W9 (§1.4). | **Opus 5.5** |
| W8.3 | **Threat-model reconciliation**: every entry the waves amended (T-102, T-118, T-187, T-212, T-233, T-336, T-424, T-428, T-444, T-447, T-457, T-462, T-470, T-472, T-474, T-477, T-483, T-484, T-486, SEC-087), the #758 (b) current-text sites, the counts, `Axiam.json` to **2.44.0**, `website/src/threatModel.ts` and `threatModelSummary.ts` regenerated, `website/src/security.ts`'s counts. | Sonnet 5.5 |
| W8.4 | **CHANGELOG `[1.1.2]`**: one entry per closed issue ending in its number; the upgrade notes — `TRUSTED_PROXIES=none` (W2.9), audit rows' `ip_address` now rule-derived and `forwarded_for_claimed` (W2.2), the AMQP provenance mark (W2.8), the migration lease (W3.1; the 1.1.1 "roll replicas one at a time" note withdrawn), the runner's refusal of out-of-order non-additive migrations (W3.2), refresh-token rows deleted at erasure and swept (W1.3), the two new `422` codes (W3.3), the `network_role.deleted` row (W4.2), the "Upgrading from 1.1.0 directly" paragraph (W5.6), v110 if W3.1 took it; `Cargo.toml`, `website/src/version.ts` and the news post to `1.1.2` as 1.1.1's W8.4 did (W8.4a, moved forward before W7.2); `claude_dev/roadmap.md`: the 1.1.1 row reads merged and tagged, a 1.1.2 row is added; the PR body with the `Closes` lines (every issue of §2 … §8, plus W9's and §1.4's intake, less #513 and #561 unless §0.3's condition was met) and the issue-by-issue summary. | Sonnet 5.5 |
| W8.5 | **Coverage** (§1.2): read the Coveralls check on the PR and the vitest summary; fix any crate whose coverage fell below §0's figure; raise `thresholds.lines` to the achieved figure less 0.1 if it moved; record both figures in §12. | Sonnet 5.5 |

The maintainer tags `v1.1.2` after the merge; the eleven SDK tags are theirs
too.

---

## 9bis. Wave W9 — the sweep (on `claude/release-1.1.2`, after W8.2)

| Task | What | Model |
|---|---|---|
| W9.1 | Every issue W8.2 filed, in order of severity, plus any §1.4 intake that joined after its wave merged; one signed commit per issue with the test and documents each names; the §10 gate; W8.3 and W8.4 re-run for what the sweep amended. | by §1.1 per issue (the orchestrator sizes; a wave of Low/Informational text and test items is one Sonnet 5.5 session; a finding that defines behaviour under concurrency or adversarial input is Opus 5.5) |
| W9.2 | Addendum to the combined review on W9.1's diff. If it files nothing, the release is ready. If it files anything, W9.3 (fix) and W9.4 (addendum) once more; anything a third review would file goes to the PR body's "Open after two sweeps" and §12 (§1.4). | **Opus 5.5** |

---

## 10. The gate before every commit, and the rules that bind every wave

- `CLAUDE.md` in full: signed commits; narrowly scoped cargo commands;
  `cargo clean` between items; the swagger placeholder and `protoc` before
  any server build; `--no-default-features` where libxml2 is absent; exit
  codes from the tool, never a pipeline; no `[lints] workspace = true` on an
  undocumented crate; no new crate without a row in the layering table.
- Per commit, on the touched crates: `cargo fmt -p <crate> -- --check`,
  `cargo clippy -p <crate> --lib --tests -- -D warnings`, **the full test
  binaries of every crate the commit touches and of every crate whose
  error type or public signature it changes** (not only the binaries the
  task names), and for W2 the `build-no-saml` `cargo check`. Console tasks:
  `npm --prefix frontend run test -- <file>` and the type-check. Script
  tasks: the script's own test. Workflow tasks: one `workflow_dispatch`
  where the orchestrator has the means, else recorded in §12 as not run.
- Phase 23 plan §7, unchanged: every new route carries a limiter from its
  first commit (none is added here); every credential-bearing outbound
  request uses `guarded_fetch_no_redirect`; every refusal of a credential
  check costs one verify; every two-writer registry is written
  conditionally on the version read.
- **Schema**: no migration is planned. If W3.1 needs a `DEFINE` for the
  lock's fields it takes **v110**, additive, with its scope test and the
  newest-version bump; nothing else claims a number. W3.2's additive check
  must pass with it.
- **Contract**: no wave but W7 edits `sdks/CONTRACT.md`. W3.3, W3.4 and
  W3.5 regenerate `sdks/openapi.json` (and W3.5 the registry) in-wave so
  the wave's drift job is green; W7.1 regenerates once more after the text.
- **Test coverage** (§1.2) and **documentation** (§1.3) as stated: a row's
  tests and documents are part of its commit, not of a later one.
- **Threat model**: nothing enters without the test its mitigation names; a
  correction is recorded as a correction, dated, in the entry's own text.
  Each wave edits the entries its tasks name; W8.3 reconciles the copies
  once. Dated pass descriptions are history and are not rewritten.
- **Test messages**: no assertion interpolates a token, a secret, a whole
  token-endpoint body or a Vault reason (`{body}`, `{err}`, `{msg}`); a
  fake credential is built at run time, never a literal. W6.1 is this
  rule's debt; the F4s read for it.
- **New issues** (§1.4): a wave is not merged while its review has an open
  finding; the milestone is re-read at every wave boundary.
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
| D-1 | **The version.** 1.1.2, with the SDKs on their own patch (or minor where a change is source-breaking)? | **1.1.2** |
| D-2 | **#741.** Stamp provenance on ingested rows (`metadata.source = "amqp"`, server-owned), or reserve every server-written namespace at ingestion? | **Stamp** (W2.8) |
| D-3 | **#758 (a).** Accept `AXIAM__RATE_LIMIT__TRUSTED_PROXIES=none` as "honour nobody", or document the placeholder entry? | **Accept `none`** (W2.9) |
| D-4 | **#754.** Key on the principal only for session-admitted tokens, refund the shared charge on `401`/`403`, or both? | **Both** (W2.3) |
| D-5 | **#752.** Derive the recorded IP from the rule only, or record both `ip_address` (rule) and `forwarded_for_claimed` (as asserted)? | **Both** (W2.2) |
| D-6 | **#726.** Run the write and the append as one spawned task awaited through its `JoinHandle`, or write the row inside the write's transaction? | **The spawned task** (W4.1) |
| D-7 | **#755.** A lease on `_migration_lock` with wait-and-retry, or only tolerate the unique-index conflict? | **The lease, and tolerate the conflict** (W3.1) |
| D-8 | **#756.** Declare the four refusals only, or also add a checker that maps each `AxiamError` variant a handler can return to a declared status? | **Declare, plus the listing test; no variant checker** (W3.5) |
| D-9 | **#725.** Put the fail-closed rename note under `[1.1.2]` as "Upgrading from 1.1.0 directly", or edit the released `[1.1.1]` entry? | **Under `[1.1.2]`** (W5.6) |
| D-10 | **#720.** Prove the fix in the e2e's rotation step with two concurrent `eapol_test` attempts, or ship the `radclient` probe as a deterministic case? | **The e2e, the probe as fallback** (W5.1) |
| D-11 | **#739 (c).** Say the join-error branch is logged by the awaiter, or catch the panic inside the closure with `catch_unwind`? | **The sentence** (W1.7) |
| D-12 | **#758 (c).** Set `authenticated` from the extractor's verdict (a request extension), or rename the field `token_verified`? | **The verdict; the name stays** (W2.9) |
| D-13 | **#746.** Two `422` codes (`resource_exceeds_registration_policy`, `redirect_exceeds_registration_policy`) or one? | **Two** (W3.3) |
| D-14 | **#730 (d).** Match the `THROW` form exactly in `refusal_of`, or reword the comment only? | **Match exactly** (W4.4) |
| D-15 | **C163-10 in the seven SDKs**, now that the contract relaxes the wording (#750): keep the raw value where the issue proposes a non-breaking internal addition (C++, C#, Java, Kotlin, PHP), and say "unknown" where it would change a public struct (C)? | **Yes, as stated** (§8.2) |
| D-16 | **#513.** Should the plan also prepare fresh conformance runs' inputs (the suite's config for the `1.1.1` image) in `conformance/`, or is the package as it stands enough for the maintainer's runs? | **Re-check the package only** (W6.4) |
| D-17 | **#561.** If run-6 numbers arrive after W8.4 wrote the PR body, does W6b ride this PR (delaying it) or the next? | **The next** |

---

## 12. Wave results (written by the orchestrator as each wave lands)

### 12.0 Base commit

- **Base:** `main` at `dc5bfd4` (the plan's own commit on top of `dedbf81`). `claude/release-1.1.2` and
  `claude/release-1.1.2-w1` … `-w6` were cut from it on 2026-10-22 at about 09:11 UTC by the orchestrator.
- **Decisions (§11):** the milestone was read at 09:05 UTC on 2026-10-22. No maintainer answer on the plan, so
  every default D-1 … D-17 applies. Two answers that predate the plan, both on issues, bind W7.1:
  - #750 (2026-10-20, Q3): relax C163-10, as §8.1 (c) writes it. "The seven SDKs then conform as they are", so
    D-15's kept raw value is an improvement the SDK issues propose, not a contract requirement.
  - #760 (2026-10-20, a second comment): contract 1.64 also records #745, fixed in 1.1.1 by `ae8562ef4`.
    §20 rule 9 is extended (`/uma2/perm` mints a ticket only for a set the PAT's own client registered; every
    other id gets an unknown id's `400`, and an SDK must not tell the cases apart), and the error table gains
    the `/uma2/perm` `400` row. **Plan vs issue:** §8.1 does not list it, so W7.1 takes it as item (i).
- **Intake (§1.4):** none at the start. 36 issues on `ilpanich/axiam` and one per SDK repository, as §0 counts.
  By 21:10 UTC the wave reviews had filed 22 more, all on `1.1.x`, all Low or Informational, and every one is worked
  in 1.1.2 in its own wave's sweep slot (the rows above §1.1's rule, after #760 … #758 in the table of §1):
  - W5.7 → #764 … #767 and, from its addendum, #774: all closed in the wave (two addenda, `5d40dad`, `86768f9`).
  - W3.6 → #768 … #773: all closed in the wave (addendum `79f7ae9`).
  - W4.5 → #775 … #779: closed in the wave (addendum `965ee35`); the addendum filed #791 (pre-existing D7), taken in the wave per §1.4 although the reviewer judged it non-blocking.
  - W1.8 → #780 … #785: fixed in the sweep slot (Sonnet for #780 … #783 and #785, `7593223` … `77e7037`; Opus for #784, `ca37ec3`); the addendum filed #792 (Informational, Sonnet), taken in the wave per §1.4.
  - W2.11 → #786 … #790: closed in the wave (Opus for #786, Sonnet for #787 … #790; addendum `f379f67`).
  No issue from outside the plan has been opened on the milestone, and none of the 29 needs the maintainer.
- **Execution:** each task is one Claude Code cloud session, started by the orchestrator with `create_session`
  at the row's model. Each pushes to its wave branch, and the orchestrator reads its report and the branch. The
  first sessions, all started 09:12–09:14 UTC: W1.2 (Opus 5.5), W2.1 (Sonnet 5.5), W3.1 + W3.2 (one Opus 5.5
  session, as §4 allows), W4.1 (Opus 5.5), W5.1 (Sonnet 5.5), W6.1 (Sonnet 5.5).
- **SAGE** was not connected in the orchestrator's session; nothing came from it.

### 12.1 W1 … 12.9 W9

One subsection per wave, in 1.1.1's form: head, commits (task, hash, issue,
model), where the tree overruled the plan, the F4's findings and the sweep
slot's commits, re-sizes, what later waves must know (for W7.1, W8.3, W8.4).

---

## 13. Kickoff prompts

### Orchestrator

> Read `CLAUDE.md`, `claude_dev/release-1.1.2-plan.md` in full, the six
> 1.1.1 review documents its issues cite
> (`claude_dev/security-review-release-1.1.1-w1-2026-10-19.md`, `…-w2-…`,
> `…-w3-…`, `…-w4-…`, `…-w5-2026-10-19.md`, `claude_dev/security-review-release-1.1.1-2026-10-20.md`),
> `claude_dev/sdk-contract-1.63-conformance-review.md`, and §12 of
> `claude_dev/release-1.1.1-plan.md` for what the last release learned.
> §11 holds every open question with its default: apply the default when
> the maintainer has not answered, and never ask a question §11 already
> answers. Run W1 … W6 as independent branches from `main`, each item by
> one executor at the model its row names, each wave but W6 ending with its
> F4 review and its sweep slot (§1.4); W1.2 before W1.1, W3.1 before W3.2,
> W4.1 first in W4. Then W7 on the merged plan branch (W7.1, W8.4a, then
> eleven SDK sessions in parallel, then the conformance review); then W8;
> then W9 until the addendum files nothing or two rounds are spent. Re-read
> the `1.1.x` milestone at every wave boundary and take in what §1.4 says.
> Record every wave in §12 as it lands. Re-size and re-model by §1.1
> whenever an executor stops short, and say so in §12.

### W1

> Read `CLAUDE.md`, the plan §0–§2 and §10, D-11, and the 1.1.1 W1 review
> and the combined review's R111-03. Check out `claude/release-1.1.2-w1`
> from `main`. Execute W1.2, then W1.1, then W1.3 … W1.7, one signed commit
> per item, each with the tests and documents its row names, the
> threat-model entries a row names in the same commit; run the §10 gate
> before each commit (the full test binaries of every touched crate) and
> `cargo clean` between items. End with the F4 review (W1.8), fix every
> finding in the sweep slot and write the addendum. Record the head in §12.1.

### W2

> Read `CLAUDE.md`, the plan §0–§1, §3 and §10, D-2 … D-5 and D-12, the
> 1.1.1 W2 review and the combined review's R111-01, R111-02, R111-04 and
> R111-08. Check out `claude/release-1.1.2-w2` from `main`. Execute W2.1 …
> W2.10 in order, W2.3 at Opus (it defines which tokens may key a
> principal bucket). The contract is not yours: record in §12.2 what W7.1
> must write for §8 (the provenance mark). End with the F4 review (W2.11),
> the sweep slot and the addendum. Record the head in §12.2.

### W3

> Read `CLAUDE.md`, the plan §0–§1, §4 and §10, D-7, D-8 and D-13, the
> 1.1.1 W3 and W4 reviews and the combined review's R111-05 and R111-06.
> Check out `claude/release-1.1.2-w3` from `main`. Execute W3.1, then W3.2
> (both Opus; one session may take both), then W3.3 … W3.5; W3.3, W3.4 and
> W3.5 regenerate the spec and W3.5 the registry, with the digest. v110
> only if W3.1 needs a `DEFINE`, and say so in §12.3. End with the F4
> review (W3.6), the sweep slot and the addendum. Record the head in §12.3.

### W4

> Read `CLAUDE.md`, the plan §0–§1, §5 and §10, D-6 and D-14, the 1.1.1 W4
> review and `claude_dev/radius-reply-profile-design.md` §5.3. Check out
> `claude/release-1.1.2-w4` from `main`. Execute W4.1 (Opus) first, then
> W4.2 … W4.4. End with the F4 review (W4.5), the sweep slot and the
> addendum. Record the head in §12.4.

### W5

> Read `CLAUDE.md`, the plan §0–§1, §6 and §10, D-9 and D-10, the 1.1.1 W5
> review and `docs/pki/freeradius.md` §5. Check out `claude/release-1.1.2-w5`
> from `main`. Execute W5.1 … W5.6 in order; the e2e workflow is your
> oracle, dispatch it where you can and read it on the PR otherwise. End
> with the F4 review (W5.7), the sweep slot and the addendum. Record the
> head in §12.5.

### W6

> Read `CLAUDE.md`, the plan §0–§1, §7 and §10, D-16 and D-17, and the
> combined review's R111-07 and R111-08. Check out `claude/release-1.1.2-w6`
> from `main`. Execute W6.1 … W6.4 in order; W6.3's W6b only if
> `benchmarks/results/run6/` exists. Comment on #561 and #513 as their rows
> say; close neither. Record the head in §12.6.

### W7

> Read `CLAUDE.md`, the plan §0–§1, §8 and §10, D-1 and D-15, §34.7 of
> `sdks/CONTRACT.md` and `claude_dev/sdk-contract-1.63-conformance-review.md`.
> On `claude/release-1.1.2-w7`, cut from the plan branch after W1 … W6 are
> merged: W7.1, then W8.4a (the version), then the eleven SDK sessions in
> parallel, each on its repository's `claude/contract-1.64` as a draft PR
> closing its issue, then the conformance review (W7.13, Opus); every
> finding fixed in its SDK PR before W8. Record the heads in §12.7.

### W8 and W9

> Read `CLAUDE.md`, the plan §0–§1, §9, §9bis and §10, and §12 as written
> so far. On `claude/release-1.1.2`: W8.1 (the gate, with the examples
> smoke and the E2E workflow on the PR), W8.2 (the combined review, Opus),
> W8.3, W8.4 and W8.5; then W9.1 for everything W8.2 filed, W9.2's
> addendum, and at most one more round. The PR body carries every `Closes`
> line and, if any, "Open after two sweeps". Record everything in §12.8 and
> §12.9.
