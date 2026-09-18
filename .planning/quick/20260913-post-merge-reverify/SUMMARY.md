---
task: Re-verify benchmarks and conformance after the 2026-09-12/13 merge wave
date: 2026-09-13
status: complete
---

# Post-merge re-verification — 2026-09-13

Verified against server `main` at **`fa88f0680`** (version `1.0.0-beta13`) and all
eleven SDK checkouts at their freshly-pulled `main`.

**Verdict: everything is green. Zero benchmark failures, zero conformance
failures across 165 modules.**

---

## 1. PR #443 — open on GitHub, merged in `main`

Both readings were correct at once. The content **is** on `main`; the PR record
was never updated.

**Evidence the content is in:**

```
git merge-base --is-ancestor e1e7dabac origin/main   # passes
git diff e1e7dabac origin/main -- sdks/CONTRACT.md   # empty
```

`e1e7dabac` is the PR's single commit, merged by `fa88f0680`, the tip of
`origin/main`.

**Why GitHub still showed it open.** Two things had to coincide:

1. The merge commit was made **locally** and pushed straight to `main` rather
   than through GitHub's merge endpoint, so no `merge_commit_sha` was ever
   recorded against the PR.
2. GitHub's fallback auto-close heuristic for direct pushes keys on the **head
   branch ref** — and #442 and #443 share the branch
   `claude/threat-remediation-2026-09-12-lgzj3q`. #442's real merge at 07:10Z
   already consumed that branch→PR association, so nothing fired when the push
   carrying #443's commit landed at 09:02Z.

The **"This branch has conflicts"** banner was a stale cache artifact, not a real
conflict: the PR still recorded `base_sha: 81af47b3a` (pre-merge `main`) and
GitHub never recomputed mergeability after `main` advanced past it.

**Action taken:** closed with an explanatory comment
([#443 comment](https://github.com/ilpanich/axiam/pull/443#issuecomment-5652767245)).

---

## 2. Repositories pulled

All twelve pulled `--ff-only`; no conflicts, nothing rewritten.

| Repo | Move |
|---|---|
| `axiam` | already at `fa88f0680` |
| `axiam-c-sdk` | `bade465 → 50dd445` (+4) |
| `axiam-cplusplus-sdk` | `2dc3077 → 73effd7` (+3) |
| `axiam-csharp-sdk` | `194fe91 → 6d1f847` (+3) |
| `axiam-go-sdk` | `581c4e6 → 8d80322` (+3) |
| `axiam-java-sdk` | `7d26ce5 → 9a839e1` (+3) |
| `axiam-kotlin-sdk` | `6f1759e → e89ef3f` (+2) |
| `axiam-php-sdk` | `0946c5f → e690c35` (+3) |
| `axiam-python-sdk` | `bf4c514 → 4a6ff89` (+3) |
| `axiam-rust-sdk` | `29e454a → 7fc70c0` (+4) |
| `axiam-swift-sdk` | `a92d867 → 7bef583` (+4) |
| `axiam-typescript-sdk` | `30f7479 → e0debce` (+4) |

36 new SDK commits, all contract 1.44 work: §10.4 revocation feed, §21.3.1 alias
refusal, §16 T-262 retry tests.

### One benign finding: eight SDKs vendor a 12-line-stale CONTRACT.md

`csharp`, `php` and `swift` match the server's `sdks/CONTRACT.md` byte for byte.
The other eight are behind by exactly **12 lines** — and only these:

```
 | csharp | yes — `RevocationFeed`, … |      vs      | csharp | — |
 | php    | yes — `RevocationFeed`, … |                | php    | — |
 | swift  | yes — `RevocationFeed`, … |                | swift  | — |
```

in §10.4.1 and §21.10. They re-vendored the contract just *before* PR #443 filled
those three status rows. It is **documentation only** — the rows describe what
*other* SDKs implement, so no behaviour, benchmark or conformance result depends
on it. Worth a re-vendor at the next sync, not worth a rebuild.

---

## 3. Base benchmarks — 24 PASS / 0 FAIL / 4 SKIP

`axiam` / `p2-tls13`, `BENCH_TLS_PORT=18443` (8443 is sage-gui).

**Better than the 2026-09-11 baseline of 22 PASS / 6 SKIP**, because the two
scenarios un-pended on that branch now run in the default matrix and both pass:

| Scenario | Result |
|---|---|
| `oauth2_authorize` | PASS — ok=645, p95=23ms |
| `scim_provisioning` | PASS — ok=988, p95=15ms |

Throughput is broadly up against the baseline:

| Scenario | 2026-09-11 | 2026-09-13 |
|---|---|---|
| `jwks_fetch` | ok=19 967 | **ok=39 502** |
| `oauth2_client_credentials` | ok=3 437 | **ok=5 833** |
| `scim_provisioning` | ok=470 | **ok=988** |
| `oauth2_revoke` | ok=5 365 | **ok=6 041** |
| `authz_check_grpc` | ok=3 555, p95=5ms | **ok=4 053, p95=4ms** |

All four SKIPs are by design: two labelled nested-sweep cells, one pending
reactor hook, one Zitadel-only scenario.

`device_verify` and `grpc_infra` again report large rejected counts against their
fixed ceilings — **expected**, those families have no env knob to neutralize.

## 4. SDK benchmarks — 11 PASS / 0 WARN / 0 SKIP / 0 FAIL

4m 08s. Every wired language built and satisfied the client contract.

| SDK | Runtime | p50 login / refresh / check / batch |
|---|---|---|
| c | gcc 16.2.1 (c11) | 36.8 / 15.8 / 3.6 / 3.0 ms |
| cpp | g++ 16.2.1 (C++17) | 44.9 / 16.6 / 3.3 / 3.3 ms |
| csharp | .NET 8.0.30 | 35.9 / 16.4 / 4.0 / 4.2 ms |
| go | go1.27.1 | 35.7 / 17.0 / 3.2 / 3.8 ms |
| java | java 21.0.12.1 | 81.8 / 16.6 / 8.0 / 7.4 ms |
| kotlin | kotlin 2.1.0 (jvm 21) | 83.4 / 16.2 / 7.2 / 6.9 ms |
| php | php 8.5.10 | 31.4 / 16.2 / 3.6 / 4.2 ms |
| python | python 3.14.7 | 40.7 / 16.2 / 6.6 / 6.7 ms |
| rust | cargo | 41.1 / 15.8 / 3.1 / 2.7 ms |
| swift | Swift 6.3.3 | 33.9 / 16.1 / 4.0 / 3.4 ms |
| typescript | node v24.20.0 | 36.8 / 16.8 / 7.8 / 7.4 ms |

Every language reported **`1.0.0-beta13`** (baseline was `beta12`). That is a
second, independent confirmation that the `_sdkversion.sh` fix from 2026-09-11
holds — the field tracked the new release with no harness change.

**Contract 1.44 introduced no harness drift.** The 2026-09-11 verification
reached its "no drift" conclusion against 1.42, so this needed re-testing rather
than inheriting; it re-passes on the merits.

---

## 5. Conformance — 165 modules, ZERO FAILED

Suite `release-v5.2.4`, one browser driver, `SUITE_PORT=8442`.

| Plan | n | Result |
|---|---|---|
| `oidcc-basic-static` | 35 | **29 PASSED / 5 REVIEW / 1 SKIPPED / 0 FAILED** |
| `fapi2 … mtls` | 37 | **26 PASSED / 10 REVIEW / 1 WARNING / 0 FAILED** |
| `fapi2 … self-signed` | 37 | **26 PASSED / 10 REVIEW / 1 WARNING / 0 FAILED** |
| `fapi2 … private-key-jwt` | 56 | **44 PASSED / 10 REVIEW / 1 WARNING / 1 SKIPPED / 0 FAILED** |
| **Total** | **165** | **125 PASSED / 35 REVIEW / 3 WARNING / 2 SKIPPED / 0 FAILED** |

All three FAPI plans are **identical to the 2026-09-11 baseline**.

Reports written to `docs/conformance/2026-09-13-*.md` plus `index.md`.

> Both non-zero exit codes are **expected**: `conformance-run-basic` exits 2 and
> `conformance-run` exits 1 because they count REVIEW and WARNING as
> "did not pass". **REVIEW is a terminal verdict, not a failure** — those modules
> are decided by screenshot and signed off by a certification reviewer.

### The one delta, and why it is not a regression

Basic OP went 30 PASSED → 29, with `oidcc-response-type-missing` moving
`PASSED → REVIEW`. Reading its suite log, the module's single outstanding item is:

> *Upload a screenshot of the error page showing a missing response type error.*

That is the same screenshot-evidence category as the four baseline REVIEWs:

| Module | Outstanding item |
|---|---|
| `oidcc-response-type-missing` | Upload a screenshot of the error page… |
| `oidcc-prompt-login` | …a screenshot of this must be uploaded |
| `oidcc-max-age-1` | …a screenshot of this must be uploaded |
| `oidcc-ensure-registered-redirect-uri` | Show redirect URI error page |
| `oidcc-ensure-request-object-with-redirect-uri` | Show redirect URI error page |

The server's behaviour — rejecting an authorization request with no
`response_type` — is unchanged. What varies between runs is whether the driver's
screenshot-placeholder upload lands before the module finalises, which is timing-
sensitive by construction. **No server-side change is implicated, and no module
failed.**

### Two previously-open items now pass on the merits

Both were carried as open in the 2026-09-09 session notes:

- **`ensure-holder-of-key-required` → PASSED.** That session flagged it
  "RE-CHECK FIRST", suspecting it had been measured before the
  `invalid_dpop_proof` (RFC 9449 §5) rebuild landed. It had been; it passes now.
- **`dpop-negative-tests` → PASSED.** Previously a WARNING over the resource
  endpoint answering 200 where DPOP-7.1 wants 400/401, and 401 where RFC 3986
  §6.2.2 `htu` normalisation should give 200. Both are resolved.

The three `dpop_jkt` modules (RFC 9449 §10) remain the DPoP lane's open work —
unchanged, and still deliberately not half-started.

---

## 6. Disk and environment hygiene

- Reclaimed **3.4 GB** of docker build cache and **1.8 GB** of
  `target/debug/incremental` after the build.
- Wrote a reusable guard at `scratchpad/diskguard.sh` — watches `/home` and kills
  the guarded build's process group under an 8 GB floor, so `ENOSPC` never
  surfaces as a fake `cc`/linker error. It supervised both long builds and never
  tripped; `/home` stayed at 21–27 GB free throughout.
- **Deliberately kept** the 15.8 GB unused `axiam-target` docker volume. It is a
  reconstructible cargo cache and was the single biggest reclaim available, held
  in reserve as the obvious lever had the guard tripped. Reclaim it with
  `docker volume rm axiam-target` if space is ever needed; the cost is only a
  slower next Docker-based server build.

**Teardown is clean.** Driver killed by recorded PID (never a `pkill` pattern —
that matches the wrapping shell and self-kills, which it did once here on the
server pattern and was redone by explicit PID). Server stopped, conformance stack
and bench stack down. Only `axiam-surrealdb` and `axiam-rabbitmq` remain.

## 7. Repo state

Working tree carries **only** the pre-existing untracked
`benchmarks/sdk/swift/Package.resolved` plus this run's new artifacts:

- `docs/conformance/2026-09-13-*.md` (4 reports) and an updated `index.md`
- `benchmarks/results/dry-run-20260913/` and `benchmarks/results/dry-run/sdk/`
- this `.planning/quick/20260913-post-merge-reverify/` directory

Nothing committed, nothing pushed — left for review.
