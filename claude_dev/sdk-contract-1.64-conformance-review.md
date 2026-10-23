# CONTRACT 1.64 — cross-SDK conformance review (the 1.1.2 release)

**Date:** 2026-10-23
**Plan item:** W7.13 of [`release-1.1.2-plan.md`](release-1.1.2-plan.md) §8.3.
**Scope:** the eleven `claude/contract-1.64` branches, each a draft PR on its repository's `origin/main`,
vendoring `sdks/CONTRACT.md`, `sdks/openapi.json`, `sdks/management-registry.json` and `proto/` from
axiam `fb92ec4` (contract 1.64, §34.8 items (a) … (j); `chore(release): version 1.1.2`). The rule read is
the one §34.8 binds every SDK to, **(b)**: a `429 rate_limit_exceeded` on a device poll is waited out
(§14.2 rule 9, last paragraph), with its §14.6 test. The review also covers each SDK's own issue items
(plan §8.2, under D-15) and the 1.63 rules the changed code touches. Items (a) and (c) … (j) ask nothing
of an SDK beyond re-vendoring.

**Outcome.** All eleven ports of (b) are present and tested, every vendored file is byte-identical to
`fb92ec4`, every version is 1.1.2, and every suite that could be run here is green. **The ports hold
against a mock but not always against the real server.** The reviewers probed each loop with AXIAM's
real response bodies, which the tests' mocks do not use. **Three findings are Medium**, and all three are
fixed before W8 (§1.4):

- **Python's (b) never engages against AXIAM (C164-01).** The server's 429 body is
  `{"error":"rate_limit_exceeded"}`, with no `error_description`, and Python's token-response mapper
  requires one. The real 429 therefore maps to a `NetworkError`, and the loop re-polls at the plain
  interval without honouring `Retry-After`. The §14.6 test passes only because its mock adds an
  `error_description`.
- **Go's C163-16 fix leaks the session to `/oauth2/jwks` (C164-02).** The fix gave the JWKS fetch
  `c.httpc`, as plan §8.2 literally asked, but `c.httpc` carries the cookie jar. After `Login`, every
  JWKS fetch now carries `axiam_access` and `axiam_csrf`. This regresses the 1.63 rule (§12.1 rule 3),
  and Rust fixed the same defect as C163-13.
- **A `5xx` whose body names an OAuth error ends `device_login` (C164-03).** AXIAM answers a token
  endpoint failure with `500 {"error":"server_error", …}`. Seven SDKs read that body before the status,
  raise a terminal `OAuthProtocolError` and lose an approved grant, which breaks §14.2 rule 6.
  - C# introduced it in this PR.
  - Rust, Python, C, C++, PHP and Swift had it before.
  - The §14.6 test "a `500` mid-poll is retried" names no body, and every suite runs it with an empty
    one. That is the same gap §34.2 P8 closed for CIBA in 1.59/1.60.

Thirteen Low and eight Informational findings follow (§4). Two are contract text: C164-16 (Low) and
C164-18 (Info). One question goes to the maintainer (§5): when the contract text is amended.

## 1. Method

The method is the [1.63 review](sdk-contract-1.63-conformance-review.md)'s (its §1), re-cut for 1.64:

- **One reviewer per SDK.** Each read the repository's `origin/main...HEAD` diff and the files it touches,
  against a common brief: (b), its §14.6 test, the plan §8.2 items, the version and the 1.63 regressions.
  Every cell carries a `path:line` on the commit read.
- **Claims were checked, not trusted.** The CHANGELOGs, the commit messages and the plan's item wording
  were treated as claims. Where the code disagreed, the code won. One example: the plan's literal
  instruction for Go's C163-16 is the cause of C164-02.
- **Probes and mutants.** Wherever a toolchain existed, the reviewer ran the suite. For the (b) test the
  reviewer also ran at least three mutants on a throwaway copy: the 429 made terminal, `+5 s` on the 429,
  and `Retry-After` ignored. Ad-hoc wire probes covered what a test did not. No SDK repository was
  modified.
- **Cross-SDK probes.** When the first reports came in, every remaining reviewer was asked to run the
  loop against three inputs:
  1. AXIAM's **exact** 429 body: `{"error":"rate_limit_exceeded"}` from
     `crates/axiam-api-rest/src/middleware/rate_limit_shared.rs:105`, or the same body with
     `"retry_after":N` from `extractors/rate_limit.rs:219`. Neither carries an `error_description`.
  2. AXIAM's `500 {"error":"server_error","error_description":…}` (`handlers/oauth2.rs:182-185`,
     `:4999-5013`).
  3. A `429` whose body says `slow_down`.

  Python, C# and Swift had finished before this point. The lead reviewer checked those three by reading
  the code, and their rows in §4 say so.

The checks, in order:

1. **Vendoring.** `sha256sum` against `fb92ec4`: `CONTRACT.md` `00451edd…061a`, `openapi.json`
   `aa6a9c4b…32d6`, `management-registry.json` `11d7ec67…1db91`. `cmp` was run on the five `proto/axiam/v1/*.proto`
   files in the nine SDKs that vendor them (all but C and C++), and `scripts/check-sdk-artifact-drift.py`
   was run over local clones (§2).
2. **(b) code.** Every loop around `device_poll` was checked for:
   - the 429 is not terminal;
   - the wait is at least `Retry-After`, and never shorter than the interval;
   - the wait is capped at the `expires_in` deadline, and nothing is sent after it;
   - the interval is not raised;
   - the single `device_poll` still raises the `OAuthProtocolError`;
   - no §16 double wait.

   The reviewers also checked how a missing, HTTP-date or malformed `Retry-After` is handled.
3. **(b) test**, against both §14.6 cases and the contract's wording, and the mutants.
4. **The issue items**, plan §8.2's row (the issues themselves could not be read, §7).
5. **Versioning.** Every version file, the CHANGELOG entry, the README's contract sentence and install
   snippets. A source- or ABI-breaking change was judged against D-1 and the repository's own precedent.
6. **1.63 regressions**: `/oauth2/*` cookie, CSRF and bearer isolation (§12.1 rule 3, §6.1 rule 11), and the
   §27.6.2 refusal at `plan`.
7. **Anything else in the diff.**

**Severity** follows the 1.63 scale: **Medium** (a normative rule broken in a way a caller meets, or a
release defect), **Low** (a deviation with a narrow trigger and no data loss, or an incomplete required
test), **Informational** (posture, text, or test strength that hides no defect). **High** and **Critical**
are reserved for an exploitable security defect or data loss; none was found. Pre-existing defects are
rated by what a caller meets, not by when they were written. A defect found in several SDKs is one
finding with one severity. By §1.4, every finding is fixed in its SDK's PR before W8, whatever its
severity.

| Repo | Commit read | PR | Version | Run by the reviewer |
|---|---|---|---|---|
| `axiam-typescript-sdk` | `46461b6f5` | #150 | 1.1.1 → 1.1.2 | `tsc --noEmit` clean; vitest 1746 passed / 3 skipped / 1 pre-existing wall-clock flake (passes alone); docs, generator `--check`, tsup, bundle-grep, TLS greps; 7 mutants killed |
| `axiam-rust-sdk` | `5e91fa574` | #138 | 1.1.1 → 1.1.2 | `--all-features` lib 234 + `network_manifest_test` 15 + `oauth2_no_session_bearer_test` 3 + `ssf_receiver_test` 19; amqp-only clippy `-D warnings` clean and lib 93; fmt, clippy clean; 5 mutants killed. Not run: wasm32 (no target) |
| `axiam-python-sdk` | `08a691423` | #103 | 1.1.1 → 1.1.2 | ruff, ruff format, mypy `--strict`, interrogate 100 %, generator `--check`; pytest 2124 passed; 5 mutants killed |
| `axiam-c-sdk` | `0a9200858` | #77 | 1.1.1 → 1.1.2 (SOVERSION 2) | ASan+UBSan build, ctest 81/81 serial (one pre-existing timing flake under `-j8`); generator `--check`; 10 mutants killed |
| `axiam-cplusplus-sdk` | `0c7bfd731` | #80 | 1.1.1 → 1.1.2 (SOVERSION 3 → 4) | gcc/C++17 build, ctest 1/1 (1614 cases, 6097 checks); shared build SONAME `libaxiam_cpp.so.4`; generator `--check`; 8 mutants, 1 caught only by the cap case. Not run: sanitizer, valgrind, clang, C++23 legs |
| `axiam-csharp-sdk` | `87b88122e` | #111 | 1.1.1 → 1.1.2 | **none**: no `dotnet` package, and the install script is blocked (403). Read only; mutants judged by reading |
| `axiam-go-sdk` | `a47ac8f94` | #103 | 1.1.1 → 1.1.2 (tag; `[1.1.2] - Unreleased`) | `go build`, `go vet`, `go test ./...` (15 packages, 1677 passes); generator `--check`; 14 mutants killed. govulncheck blocked (403) |
| `axiam-java-sdk` | `b4072a9f1` | #121 | 1.1.1 → 1.1.2 | `./mvnw -B verify` 1505 tests green, jacoco, javadoc, BOM, TLS gate; generator no diff; 10 mutants, 2 survive (C164-11) and 1 survives (C164-12) |
| `axiam-kotlin-sdk` | `25687d50a` | #80 | 1.1.1 → 1.1.2 | `./gradlew test` 1289 green; generator `--check`; TLS gate; 6 mutants, 1 survives (C164-13) |
| `axiam-php-sdk` | `3707a5dac` | #87 | 1.1.1 → 1.1.2 (tag; `[1.1.2] - Unreleased`) | phpunit 2032 tests / 9874 assertions; phpstan (main and examples) clean; docblock 2083/2083; generator `--check`; 12 mutants, 2 survive (C164-10, C164-19). phpstan was installed from a local clone, because GitHub zipballs are blocked |
| `axiam-swift-sdk` | `3180f7133` | #78 | 1.1.1 → 1.1.2 | **none**: no Swift toolchain (swift.org 403, no apt package). Read only; generator `--check`; mutants traced by hand |

The C# PR (#111) and the Kotlin PR (#80) were found by matching each head against
`git ls-remote origin 'refs/pull/*/head'`. Every head was re-read with `git ls-remote` after the eleven
reviews finished, and none had moved.

**Vendoring, all eleven.** `CONTRACT.md`, `openapi.json` and `management-registry.json` are
byte-identical to `fb92ec4` (`00451edd8b0c…d061a`, `aa6a9c4b7c97…dd32d6`, `11d7ec678942…b1db91`). The nine
SDKs that vendor `proto/` have all five files identical, and C and C++ vendor none (`REST_ONLY_REPOS`).

**Versions.** Every SDK is at 1.1.2. The 1.63 review's table records Java, Kotlin and C++ 1.63 as
"→ 1.2.0", but the maintainer released all three as **1.1.1** (tags `v1.1.1`; Maven Central has no 1.2.0).
1.1.2 is therefore the right patch for each. C++'s ABI bump (SOVERSION 3 → 4, for two public types that
gain members) on a patch number follows its own 1.1.1 precedent (SOVERSION 2 → 3). The thrown-type
changes of C163-07 (C#, Kotlin, C++) are not source-breaking:
- In C# and Kotlin, `ValidationError` is a `NetworkError` subtype.
- In C++, the change is behavioural and recorded under *Changed* with its migration.

## 2. What CI did not catch

- **Mocks that are kinder than the server.** The §14.6 (b) tests mock the 429 with an
  `error_description` (Python, Kotlin, Java) or in a shape the server never sends. The rule-6 test mocks
  the `500` with an empty body (C, C++, PHP, C#, and the tests the others inherited). Both server bodies
  are fixed strings in the platform tree, and with them:
  - Python's (b) is inert (C164-01);
  - seven SDKs end an approved flow on a `500` (C164-03).

  The contract's §14.6 sentence "a `500` mid-poll is retried" names no body. P8 fixed the same wording for
  CIBA (§33.8 test 8) and was never carried over to §14.6 (C164-16).
- **A jar on a client the plan named.** Go's C163-16 test proves that the JWKS fetch presents the SDK's
  client certificate and honours its timeout, which is what the plan asked. No test signs in first, so
  nothing sees that `c.httpc` also carries the session (C164-02).
- **The status behind the body.** Ten SDKs read the `error` field before the status. A `429` whose body
  says `slow_down` (the bucket servers through 1.1.0 answered, or any intermediary) therefore raises the
  interval, which rule 9 forbids (C164-04). In Go, C#, Java and Kotlin this is new: before this PR every
  429 was a non-terminal `NetworkError`. Only TypeScript checks the status first.
- **A deadline that is a budget of sleeps.** In eight SDKs the `expires_in` deadline is `expires_in` minus
  the sum of the waits. Request time is never subtracted. The 1.64 "sends nothing after the deadline" is
  measured on the clock. Where the reviewers checked (TypeScript, Rust, C#, Go, Java, Kotlin), the SDK's own CIBA loop already uses one (C164-05).
- **Platform drift job.** `scripts/check-sdk-artifact-drift.py --local-root` was run over the eleven clones
  (the GitHub API is 403 here).
  - At the PR heads, each clone with a local `main` at `HEAD`: **11 repos, 0 artifact problems**. That
    covers ten artifacts in Rust (with `vendor/axiam-opaque/src/lib.rs`), nine in each of the eight other
    gRPC SDKs (with `opaque-test-vectors.json`), and five in C and C++.
  - At `origin/main`: **66 stale artifacts**, exit 1. That is expected until the eleven PRs merge.

## 3. Per-SDK reports

`path:line` is on the commit read. Findings carry their §4 id. A cross-SDK finding (C164-03, -04, -05, -17,
-19 … -24) is listed in every report it touches and described once, in §4.

---

### Report — typescript — commit 46461b6f5 (PR #150)

Version 1.1.1 → 1.1.2 (`package.json:3`, both `package-lock.json` root entries). Branch `claude/contract-1.64`,
five commits, a straight line on `origin/main` (`11da444`, the merge of PR #147). Issue
ilpanich/axiam-typescript-sdk#148; the item list comes from plan §8.2 (the issue, the PR and CI could not
be read: no GitHub access from here).

**Vendoring.** `CONTRACT.md`, `openapi.json` and `management-registry.json` are byte-identical to
`fb92ec4:sdks/*` (sha256 `00451edd…`, `aa6a9c4b…`, `11d7ec67…`). All five `proto/axiam/v1/*.proto` match
`fb92ec4` (`cmp`).

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | **Conforms.** `devicePoll` posts with `devicePoll=true`. `#postForm` turns a `429` whose body has `error == "rate_limit_exceeded"` into an `OAuthProtocolError`, before the §2 mapper (which would give `NetworkError`). It keeps `Retry-After` (delta-seconds; an HTTP-date or garbage is ignored) in a private `WeakMap`, so no public type changes. `deviceLogin` calls `schedule.rateLimited(s)`. The next wait is `max(interval, Retry-After)`: at least `Retry-After` and never shorter than the interval. That wait is consumed once by `tick()` as the one interval, and `#intervalSecs` is untouched. A wait ≥ the remaining life ends the loop at once with the typed `expired_token`, with no sleep and no request ("raise at once" is allowed). A missing `Retry-After` falls back to one ordinary interval. **No double wait:** `session.axios` has no §16 retry layer (`withRetry` is used only at `oidc.ts:2373` and `client.ts:335`), and the response interceptor passes a non-401 through. A `429` never reads as `slow_down`: a `429 {"error":"slow_down"}` is not `rate_limit_exceeded`, so it maps to `NetworkError` and is waited at the unchanged interval (probed). The server's exact body `{"error":"rate_limit_exceeded"}` (no `error_description`) and the `retry_after` variant both map and wait (probed). A `500 {"error":"server_error"}` mid-poll stays `NetworkError` and non-terminal under rule 6 (probed). The single `devicePoll` raises the `OAuthProtocolError`. CIBA (`cibaAwait`, `:2459`) treats `rate_limit_exceeded` as one interval through a wall clock; it was already conformant and is unchanged. Deadline caveat (pre-existing, C164-05). | `src/node/oidc.ts:290-347`, `:353-369`, `:1673-1687`, `:1713-1777`, `:2805-2823`; `src/rest/bareTransport.ts:76-81` |
| 2 | (b) §14.6 test | **Present, non-vacuous, matches the contract's two cases.** The describe title follows the contract's sentence. A recorded-sleep stub (it intercepts `setTimeout` from `src/node/oidc` only, so there is no wall-clock wait) gives `429 Retry-After: 3` → pending → success, with sleeps `[1000, 3000, 1000]`. That shows the wait is ≥ `Retry-After`, the loop polls again and completes, and the poll after the waited-out round is at the prior 1 s, not 6 s. Second case: `Retry-After: 3600`, `expires_in: 5` → `expired_token`, `flow.calls() == 1`, sleeps `[1000]`, so nothing is sent after the deadline. Also tested: no-`Retry-After` → one interval; single `devicePoll` → `rate_limit_exceeded`; `PollSchedule` unit cases. The mock body is the server's exact `{"error":"rate_limit_exceeded"}`. | `test/node/deviceFlow.test.ts:59-63`, `:144-169`, `:297-392` |
| 3 | C163-12 | **Done for the session transport.** The device-token interceptor gives every anchored `/oauth2/*` request `session.oauth2RequestConfig()`. In the browser persona that is `{withCredentials:false, adapter:'fetch', fetchOptions:{credentials:'omit'}}`. `NodeSession` overrides it to the jar-free agent pair. The test captures the final per-request config: adapter and credentials for four routes, a federation path as control, and the Node persona. Mutant killed. **Not done on the bare transport:** the browser's RFC 7592 calls (`readClientRegistration` / `update…` / `delete…`, exported from `./rest`) still use `{withCredentials:false}` on the default (XHR) adapter (C164-06). In axios 1.20.0 `fetchOptions.credentials` is deleted and the effective value comes from `withCredentials:false` → `'omit'` (C164-19). | `src/rest/session.ts:320-322`; `src/node/session.ts:79-81`; `src/rest/interceptors.ts:207-214`; `test/rest/oauth2BrowserCredentials.test.ts:32-66` |
| 4 | C163-08 | **Done.** A real `AxiamClient.login()` against a mock sets `axiam_access` and `axiam_csrf`. The CSRF token comes from the jar and is not set by hand. Then `deviceAuthorize`, `devicePoll` and `loginClientCredentials` run, each asserted to carry no `Cookie` and no `X-CSRF-Token`. The control after them is `groups.create` (a management `POST`), asserted to carry both cookies and `X-CSRF-Token: csrf-value`. The order of the four requests is asserted. Mutant killed. | `test/node/oauth2NoSessionCookies.test.ts:39-99` |
| 5 | C163-09 | **Done.** The stated-member `PUT` body is asserted to carry `termination_action == "radius_request"` and `service_type == "framed_user"`, for both members. Mutant (the stated value dropped from the body) killed. | `test/management/manifestNetwork.test.ts:661-669` |
| 6 | C163-18 | **Partly.** The two §34.7 rows now say `(§27.6.2 item 4, C162-07)` and `(… C162-08)`, but they still *begin* with the §34.6 letters `(ab)` and `(ac)` inside the §34.7 table. That is the drift the 1.63 review named. The CHANGELOG's "labelled … and not by §34.6 letters" is therefore not true (C164-22). | `README.md:50-51`; `CHANGELOG.md:33-35` |
| 7 | Version & docs | **Conforms.** Patch 1.1.2 is right: no export removed or retyped. `PollSchedule` is `@internal`, and `oauth2RequestConfig()` is an added method on `SharedSession`, which is non-breaking. `## [1.1.2] - 2026-10-23` follows the repo's Keep-a-Changelog convention and names 1.64, `fb92ec4`, (b), C163-12/08/09/18 and "closes #148". The README says contract 1.64, has a §34.8 table, and the install pin is `^1.1.2`. There is no version constant in `src`. | `CHANGELOG.md:10-35`; `README.md:23-43`, `:242` |
| 8 | 1.63 regression | **None.** C163-01's anchored `isOAuth2Endpoint` (base-path-relative prefix) is unchanged and is the only gate for the new adapter switch. The federation `oauth2/start` keeps the default adapter (the test at `oauth2BrowserCredentials.test.ts:44-53`), and `federationOauth2Session.test.ts` passes. The CSRF skip and the device-token stripping on `/oauth2/*` are unchanged. The poll path still rides the jar-free agents (the C163-08 test covers `devicePoll`). §6.1 rule 11: the adopted bearer is still not added on `/oauth2/*` (`interceptors.ts:216-228`). §27.6.2 is untouched apart from the test. | `src/rest/interceptors.ts:60-71`, `:163-180`, `:205-238` |
| 9 | Other | The pre-existing §2 mapper gates the `/oauth2/*` row on 400/401 (C164-23). The device deadline counts sleeps only (C164-05). The `devicePoll` TSDoc says a hand-rolled loop "sees exactly what `deviceLogin` sees", but `Retry-After` is not exposed (C164-20). There is a pre-existing wall-clock test that is flaky under full-suite load (C164-23). The last commit is TSDoc only. | see Findings |

**Run by the reviewer** (throwaway copy `/home/user/work/typescript`, Node 22, axios 1.20.0 resolved):
- `npm ci`: OK.
- `npx tsc --noEmit` (= `npm run typecheck`): exit 0.
- `npx vitest run`:
  - With the sandbox's `HTTPS_PROXY` set, 867 tests fail because axios sends `axiam.test` to the agent proxy (403). This is environment-only.
  - With the proxy variables unset: **1746 passed, 3 skipped, 1 failed**. The failure is `deviceFlow.test.ts > loops on authorization_pending rather than raising`, a 5 s timeout. The test is pre-existing and unchanged; it does three real 1 s sleeps. The file alone passes 27/27, twice (C164-23).
- There is no ESLint in this repo. "Lint" is the CI gates, all run:
  - `npm run docs` (typedoc, validation as errors): exit 0, 0 errors. Its 3 warnings are pre-existing, on `middleware.OidcLoginOutcome`.
  - `node scripts/gen-management.mjs --check`: OK, 32 files current, 202 operations.
  - TLS-lint grep: clean.
  - `tsup` build: OK.
  - `npm run bundle-grep`: OK for rest and browser.
  - Token-leak grep on `dist/`: clean.
- **Not run:** `npm run generate` (`buf generate`). It needs remote BSR plugins: `buf` is not installed, and `npx @bufbuild/buf generate` fails with "the server hosted at that remote is unavailable". The build ran on the tree as is.
- **Mutants**, each in the copy and reverted; all killed:
  - M1, a `429` made terminal: 3 of the (b) loop tests fail.
  - M2, `rateLimited` also raises the interval by 5 s: 4 fail.
  - M3, `Retry-After` ignored: 4 fail.
  - M4, the deadline check ignores the pending `Retry-After`: 2 fail, both cap tests.
  - M5, `SharedSession.oauth2RequestConfig` returns `noCredentialsConfig()`: 4 of 6 C163-12 tests fail.
  - M6, no CSRF skip on `/oauth2/*`: the C163-08 test fails.
  - M7, the stated `termination_action` dropped from the `PUT`: the C163-09 test fails.
- **Cross-SDK probes (the lead reviewer's)**, all pass on HEAD:
  - (1) The server's exact `429 {"error":"rate_limit_exceeded","retry_after":4}` with `Retry-After: 4` gives sleeps `[1000,4000,1000]` and completes. The single `devicePoll` on `{"error":"rate_limit_exceeded"}`, with no description, raises `OAuthProtocolError` `rate_limit_exceeded`.
  - (2) `500 {"error":"server_error"}` mid-poll gives sleeps `[1000,1000,1000]`, completes, and is non-terminal.
  - (3) `429 {"error":"slow_down"}` with `Retry-After: 2` gives sleeps `[1000,1000,1000]`, so the interval is not raised.
- **C164-06 probe:** a browser-persona `AxiamClient.readClientRegistration` gets the bare instance's `axios.create` config `{"withCredentials":false}`, with no adapter and no `fetchOptions`. With the C164-06 fix applied, the probe, `clientRegistration.test.ts` and the SSF tests pass (49/49).
- Probe files and `node_modules`, `dist` and `_docs` were deleted. The clone was not modified.

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):

- **C164-06 — Low** — `src/rest/bareTransport.ts:54`. Rule: §12.1 rule 3, last paragraph (1.63), which lists "the RFC 7592 operations" and names `credentials: "omit"` for TypeScript in a browser; C163-12 is incompletely fixed.
  - **What happens.** The browser persona's `readClientRegistration`, `updateClientRegistration` and `deleteClientRegistration` (`src/rest/clientRegistration.ts:310`, `:343`, `:372`) go out on the bare instance with `withCredentials:false` on the default XHR adapter. §28.12.2 rule 1 forces the registration URI onto the base URL's origin, so a same-origin app sends its `axiam_*` cookies on `/oauth2/register/<id>`.
  - **Fix.** In `bareRequest`, replace `...session.noCredentialsConfig(),` with `...session.oauth2RequestConfig(),`. Under Node this is identical, because `NodeSession` overrides it to `noCredentialsConfig()`. Keep `withCredentials:false` after it.
  - **Test** (in `test/rest/oauth2BrowserCredentials.test.ts`). Spy `axios.create` and call `readClientRegistration('https://axiam.test/oauth2/register/c1', token)` on a `createSession` browser client. Assert that the created config has `adapter === 'fetch'` and `fetchOptions` equal to `{credentials:'omit'}`. Add a Node-persona case asserting no `adapter`. It fails on `46461b6f5` and passes with the fix (reviewer probe).
- **C164-22 — Informational** — `README.md:50-51`; `CHANGELOG.md:33-35`. Plan item C163-18.
  - **What happens.** The §34.7 table rows still start with the §34.6 letters "(ab)" and "(ac)", and the CHANGELOG says they no longer do.
  - **Fix.** Replace the two Item cells with `C162-07 (§34.6 (ab)): an unknown open-enum value on an unstated manifest member` and `C162-08 (§34.6 (ac)): \`termination_action\` has no "none" in a manifest`, and drop the trailing parentheticals. Alternatively, keep the cells and reword the CHANGELOG line to "now also name C162-07 / C162-08 and §27.6.2 item 4".
- **C164-19 — Informational** — `src/rest/session.ts:309-321`; `test/rest/oauth2BrowserCredentials.test.ts:38-40`. Test strength for C163-12.
  - **What happens.** axios ≥ 1.18 deletes `fetchOptions.credentials` (`node_modules/axios/lib/adapters/fetch.js:450`) and sets `credentials` from `withCredentials` (`false` → `'omit'`, `:416-417`, `:459`). The setting that withholds the cookie is therefore `adapter:'fetch'` plus `withCredentials:false`, not `fetchOptions`. The outcome is right, but the TSDoc's "Fetch's `credentials: 'omit'` is the setting" and the config-only assertion would not notice if a later axios read `withCredentials` differently.
  - **Fix.** Reword the TSDoc to "the fetch adapter, whose `credentials` axios derives from `withCredentials: false` (`'omit'`); `fetchOptions.credentials` is set as well for adapters that read it".
  - **Test.** Add one case that leaves the capture interceptor out, stubs `globalThis.fetch` with `vi.fn` returning `new Response('{}')`, sends `/oauth2/token`, and asserts `(fetch.mock.calls[0][0] as Request).credentials === 'omit'`. The case must run in an environment with `Request`; Node 22 has it.
- **C164-23 — Informational, pre-existing, not 1.64** — `src/core/errorMapper.ts:286`. Rule: §2, the "Any status from `/oauth2/*` with an `OAuth2ErrorResponse` body" row, and §14.2 rule 9, first paragraph (1.63).
  - **What happens.** The shared mapper qualifies the `/oauth2/*` row only for 400/401, so a `429 {"error":"rate_limit_exceeded"}` on `oidcRefresh`, `loginClientCredentials` or `deviceAuthorize` is a `NetworkError`, not an `OAuthProtocolError`. The PR fixes only `devicePoll`, which is what 1.64 requires.
  - **Fix.** Change the guard to `status >= 400 && status < 500`. Do not include 5xx: §14.2 rule 6 and §33.7 rule 5 keep a 5xx `NetworkError` "whatever its body". Add a test that a `429 {"error":"rate_limit_exceeded"}` from `/oauth2/token` (`loginClientCredentials`) is `OAuthProtocolError`, and that a `500 {"error":"server_error"}` stays `NetworkError`.
  - **Scope.** It changes a thrown type for 403/429 on `/oauth2/*`. Take it in this PR only if judged a fix rather than a source change; otherwise file it on 1.1.x.
- **C164-05 — Informational, pre-existing** — `src/node/oidc.ts:335-347`, `:1726-1741`. Rule: §14.2 rule 4 (the deadline the 1.64 cap is measured against).
  - **What happens.** `PollSchedule` counts only the sleeps against `expires_in`. Request latency, and the time `onUserCode` takes, are not counted, so after slow polls the loop can send a request after the real deadline. `cibaAwait` already uses a wall-clock deadline (`:2440-2444`).
  - **Fix.** Record `const deadline = Date.now() + authorization.expiresIn * 1000` when `deviceAuthorize` returns, through an injectable clock as in `cibaAwait`. Before each sleep, `if (Date.now() + waitSecs * 1000 >= deadline) throw expired_token`. Keep `PollSchedule` for the interval and `Retry-After` arithmetic.
  - **Test.** A fake clock that advances 2 s per poll, with `expires_in: 5` and interval 1, must stop after the poll that crosses 5 s.
- **C164-20 — Informational** — `src/node/oidc.ts:1655-1660`, `:353`. Doc versus behaviour.
  - **What happens.** The `devicePoll` TSDoc says a hand-rolled loop "sees exactly what `deviceLogin` sees", but the `Retry-After` of a `429` is kept in a private `WeakMap`, so a caller's own loop cannot honour it.
  - **Fix.** Either add one sentence ("the `Retry-After` of a `429` is not exposed; a hand-rolled loop should wait at least one interval, or use `deviceLogin`"), or expose it as a non-breaking optional readonly `retryAfterMs?: number` on the thrown `OAuthProtocolError`. The latter would mirror `retryableNetworkError`'s non-enumerable property (`bareTransport.ts:101-107`).
- **C164-23 — Informational, pre-existing** — `test/node/deviceFlow.test.ts:220-233` (and the other wall-clock `deviceLogin` tests in that describe). Test robustness.
  - **What happens.** Four real 1 s sleeps sit under vitest's 5 s default timeout. The test timed out once in a full parallel run and passed alone, twice.
  - **Fix.** Move `recordSleeps()` (`:303-317`) up to the describe and use it in these tests, asserting the recorded delays instead of sleeping. Alternatively, pass a `15_000` timeout to the `it`.

---

### Report — rust — commit 5e91fa574 (PR #138)

Version 1.1.1 → 1.1.2 (patch). Issue ilpanich/axiam-rust-sdk#137. Branch `claude/contract-1.64` is five commits on `origin/main`, in a straight line. No GitHub access from here, so the PR, the issue and CI were not read.

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | **Conforms on AXIAM's real 429.** `classify` maps `rate_limit_exceeded` to `RateLimited`, which is not terminal (`src/oidc/device.rs:247`, `:585-588`). `device_poll_step` parses `Retry-After` only on a non-2xx and keeps it (`:436-447`). The next wait is `max(interval, Retry-After)` (`:552`), so `Retry-After` is a minimum and the interval is still respected. `tick_for(wait)` takes that wait from the remaining life as one interval (`:218-226`). It does not call `slow_down()`, so the interval is not raised. A wait at or past the deadline gives the typed `expired_token` right away, with no sleep and no request (`:554-559`). The single `device_poll` still returns the `OAuthProtocolError` (`:382-384`; probed). §16 does not double-wait: `device_poll` does not go through `RetryRunner`. `Retry-After` is delta-seconds only, as the documented §16 posture says (`src/retry.rs:159-176`). An HTTP-date or invalid value counts as missing, and the loop waits the interval. Server bodies probed: `{"error":"rate_limit_exceeded"}` (no `error_description`, which the wire struct defaults at `src/oidc/exchange.rs:97-101`) and `{"error":"rate_limit_exceeded","retry_after":12}`. Both map to `OAuthProtocolError`, and the loop waits [5, 12]. A bodiless 429 becomes `Network` and is retried at the interval. **Gaps (all three were there before this PR):** dispatch looks at the body only. A `429 {"error":"slow_down"}` raises the interval (C164-04). A `500 {"error":"server_error"}` mid-poll ends `device_login` (C164-03). The deadline counts sleep time only, not wall-clock time (C164-05). | `src/oidc/device.rs:243-249`, `:436-447`, `:540-600` |
| 2 | (b) §14.6 test | **Present and effective.** Four tests. Case 1 is `a_429_on_a_poll_is_waited_out_and_the_interval_is_unchanged` (`:813`): script 429 `Retry-After: 12`, pending, 200. It records the sleeps on an injected `Sleeper` (no wall clock) and asserts sleeps `[5,12,5]`, 3 polls and the token. Case 2 is `a_retry_after_past_the_deadline_ends_in_expired_token` (`:857`): `expires_in` 60, `Retry-After: 3600`. It asserts `expired_token`, exactly 1 poll and sleeps `[5]`. Two extras: `a_short_retry_after_never_goes_below_the_interval` (`:837`) and a schedule unit test (`:878`). The mock body is exactly the server's, with no `error_description`. Wording follows the contract's heading ("a `429` on a poll is waited out", "interval unchanged"). I could not compare it with the other ten SDKs. Mutants (below): 429 terminal, +5 s and ignored `Retry-After` each fail ≥2 tests. | `src/oidc/device.rs:697-883` |
| 3 | C163-07 | **Done.** `unknown_open_enum` now returns `local_refusal("manifest.plan", member, …)`, a `Network` with a `ValidationError` source whose `fields[0].field` is the member. The message still names the member and the value. The test asserts `validation()` is `Some`, `operation == "manifest.plan"` and `fields[0].field == member`. A mutant reverting to `AxiamError::network` fails it. | `src/management/manifest/network.rs:322-334`; `tests/network_manifest_test.rs:765-769` |
| 4 | C163-13 | **Done.** The SSF JWKS verifier and the discovery GET use `http_bare()`. Test: a cookie `login()` against a mock that sets `axiam_access`/`axiam_refresh`/`axiam_csrf`, then a management control carrying a cookie, then `JwksUri` and `DiscoveryUrl` receivers. It asserts no `cookie` on any of the three GETs. A mutant with `http()` restored fails (`/ssf/jwks: no session cookie`). The control (`logout`) runs before the fetches, but `logout` does not clear the jar (the mutant leaked), so the test is not vacuous. Native only; wasm32 is C164-07. | `src/ssf.rs:400`, `:434`; `tests/ssf_receiver_test.rs:973-1073` |
| 5 | C163-17 control | **Done.** `logout` with both `axiam_access=` and `x-csrf-token` asserted now runs after the three `/oauth2/*` calls. The new comment there says `logout` "clears the jar", but the C163-13 mutant shows it does not (C164-23, text only). | `tests/oauth2_no_session_bearer_test.rs:344-359` |
| 6 | C163-17 CHANGELOG redirect note | **Done**, for native builds. On wasm32 the browser follows redirects (C164-07). | `CHANGELOG.md:49-55` |
| 7 | C163-17 wasm32 `credentials: "omit"` | **Done for `oauth2_post`** (`fetch_credentials_omit()` exists in reqwest 0.13.5). Not done for the other `http_bare` callers (C164-07). I did not build for wasm32: no wasm32 target is installed. | `src/client.rs:1096-1114` |
| 8 | C163-17 dead branch | **Done.** `check_action` now calls `local_refusal` unconditionally; `management::error` is no longer gated on `rest`. The message changed to the `local_refusal` form, as the CHANGELOG records. It still does not name the action. | `src/amqp/messages.rs:150-160`; `src/management/mod.rs:90-113` |
| 9 | C163-17 `sign_payload` doc | **Done.** The doc points to `AuditEventMessage::sign`. | `src/amqp/hmac.rs:21-25` |
| 10 | amqp-only build + CI cell | **Fixed and verified.** The fix is `cfg` gating only (`uma`, `management::*` except `error`, `token::revocation`, `certificate_thumbprint_s256`), with no module restructuring. On the reviewer's run, `cargo clippy --lib --no-default-features --features amqp -- -D warnings` is clean and `cargo test --lib --no-default-features --features amqp` passes 93. The CI job `amqp-only` (PR-only, like every other gate job) runs exactly those two commands. It needs no `protoc`, since `build.rs` does nothing without `grpc`. The items gated away had never compiled without `rest`, so nothing is source-breaking. | `.github/workflows/sdk-ci-rust.yml:254-273`; `src/lib.rs:125-126`; `src/token/mod.rs:14-27` |
| 11 | Version & docs | **Conforms.** 1.1.2 in `Cargo.toml`, the `=1.1.2` macros pin, `axiam-sdk-macros/Cargo.toml` and `axiam-sdk-wasm/Cargo.toml`. No lockfile is tracked, and no version constant is in source. The README says contract 1.64 and 1.1.2, has a 1.64 paragraph, and both snippets show `1.1.2`. The CHANGELOG `[1.1.2] - 2026-10-23` names 1.64, `fb92ec4`, item b, C163-07/13/17 and "patch", in the repository's Keep-a-Changelog form. Vendoring: `CONTRACT.md` `00451edd…061a`, `openapi.json` `aa6a9c4b…32d6` and `management-registry.json` `11d7ec67…db91` are byte-identical to platform `fb92ec4a9`, and all five `proto/axiam/v1/*.proto` are identical (`cmp`). A patch is right: the one new public item is the additive `PollSchedule::tick_for`. | `Cargo.toml:25,107`; `README.md:120,130,138-142,433,440`; `CHANGELOG.md:41-85` |
| 12 | 1.63 regression | **None.** Both device operations still use `oauth2_post` (`http_bare`, no jar, no CSRF, no adopted bearer, §6.1 rule 11) at `src/oidc/device.rs:317`, `:426`. The new code adds only a header read. The §27.6.2 refusal is still raised at `plan`, before any write; the three network-manifest tests pass. | as cited |
| 13 | Other | `PollSchedule::tick_for` is a new `pub` method on a public type. It is additive and documented. `device_poll`'s doc says a hand-rolled loop "sees exactly what `device_login` sees", which stopped being true: `device_login` now reads `Retry-After` and a caller of `device_poll` cannot (C164-20). | `src/oidc/device.rs:218`, `:355-362` |

**Run by the reviewer** (all on a throwaway copy `/home/user/work/rust`; the clone was not modified; `protobuf-compiler` installed via apt for `--all-features`):
- `cargo clippy --lib --no-default-features --features amqp -- -D warnings`: clean (exit 0).
- `cargo test --lib --no-default-features --features amqp`: 93 passed.
- `cargo test --all-features --lib --test network_manifest_test --test oauth2_no_session_bearer_test --test ssf_receiver_test`: lib 234 passed, network_manifest 15, oauth2_no_session_bearer 3, ssf_receiver 19, 0 failed.
- `cargo fmt --all --check`: clean.
- `cargo clippy --lib --tests --all-features -- -D warnings`: clean.
- **Mutants**, switched by an env var in one build:
  - 429 made terminal: 3 (b) tests fail.
  - `slow_down()` on 429 (+5 s): 2 fail.
  - `Retry-After` ignored: 2 fail, including the deadline case.
  - SSF back on `http()`: the C163-13 test fails.
  - `unknown_open_enum` back to bare `AxiamError::network`: the C163-07 test fails.
- **Probes** (temporary unit tests):
  - Server-exact 429 body with the `retry_after` member: passes, sleeps [5, 12].
  - Single `device_poll` on 429: `oauth_error_code() == Some("rate_limit_exceeded")`, passes.
  - **`500 {"error":"server_error"}` then 200: FAILS.** `device_login` returns `authentication failed: server_error: ` after 1 poll (C164-03).
  - **`429 {"error":"slow_down"}`, `Retry-After: 1`, then pending, then 200: FAILS.** Sleeps are `[5,10,10]`, not `[5,5,5]` (C164-04).
- **Not run:**
  - The full `cargo test --all-features`, kept to the scoped targets for disk.
  - The wasm32 check: the `wasm32-unknown-unknown` target is not installed.
  - `cargo build --examples`, `cargo doc`, and the macros publish dry-run.
- `target/` was deleted afterwards.

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):
- **C164-03: Medium (proposed; was there before this PR, found by the cross-SDK probe)** at `src/oidc/device.rs:589-597` with `src/oidc/exchange.rs:347-358`.
  - **Rule:** §14.2 rule 6 ("`5xx` and transport failures remain §2 `NetworkError` and are not terminal… a server restart mid-flow must not lose a grant the user has already approved").
  - **What happens:** AXIAM answers a datastore fault on `/oauth2/token` with `500 {"error":"server_error"}`. `oauth2_error_or_fallback` turns any body with an `error` member into `OAuthProtocolError`, so `oauth_error_code()` is `Some`, the `is_none() && is_retryable_transport()` escape is skipped, and `device_login` ends. Probed.
  - **Contract note:** P8 (§34.2) states "whatever its body" for `ciba_poll` "only". If §2's `/oauth2/*` row were read as prevailing for `device_poll`, this would be Low (§4 rules it Medium: rule 6 is explicit), and the contract needs the P8 sentence in §14.2 rule 6. Either way the loop should not end on a 5xx.
  - **Fix, code:** add `status: Option<u16>` to `PollFailure` and set it from `response.status()` at `:436-447`. In the loop, before `classify`: `if failure.status.is_some_and(|s| s >= 500) { continue; }`.
  - **Fix, test:** script `[ResponseTemplate::new(500).set_body_json(json!({"error":"server_error"})), tokens()]`, assert `Ok` with 2 polls and sleeps `[5,5]`.
- **C164-04: Low (was there before this PR)** at `src/oidc/device.rs:243-249`.
  - **Rule:** §14.2 rule 9 ("only the `400` raises the interval: an SDK MUST NOT read a `429` as the polling signal").
  - **What happens:** `classify` dispatches on the body's `error` alone, so a `429 {"error":"slow_down"}` raises the interval by 5 s. Probed: sleeps `[5,10,10]`. AXIAM itself no longer sends that body (1.63), so the trigger is a proxy or an older server.
  - **Fix, code:** with C164-03's `status`, map `status == Some(429)` to `RateLimited` whatever the body (and a bodiless 429 too, so it honours `Retry-After`). Map `SlowDown` only when `status == Some(400)`.
  - **Fix, test:** script `[429 {"error":"slow_down"} Retry-After: 1, pending(), tokens()]`, assert sleeps `[5,5,5]`.
- **C164-05: Low (was there before this PR)** at `src/oidc/device.rs:170-226`, `:552-556`.
  - **Rule:** §14.2 rule 4 / §14.2 rule 9 ("capped at the `expires_in` deadline… nothing sent after it").
  - **What happens:** the deadline is a budget of slept seconds (`remaining_secs`), not a clock. Request latency, including a slow 429 or 5xx answer, is never subtracted, so a long flow can poll after the real `authorization time + expires_in`. Rust's own CIBA loop anchors a real `Instant` (`src/retry.rs:193-205`).
  - **Fix, code:** have `device_login_with` take a `now: &dyn Fn() -> crate::time::Instant` (as `RetryBound` does), set `deadline = now() + expires_in` after `device_authorize`, and before each sleep stop with `expired_token` when `now() + wait >= deadline`. Keep `PollSchedule` for the interval arithmetic.
  - **Fix, test:** a fake clock that advances 30 s per poll with `expires_in` 60, interval 5. Assert at most 2 polls and `expired_token`.
- **C164-07: Low** at `src/client.rs:585-592` (wasm32 `bare_builder` is `reqwest::Client::builder()`).
  - **Rule:** §12.1 rule 3, last paragraph / C163-13 / C163-17.
  - **What happens:** only `oauth2_post` got `fetch_credentials_omit()`. On wasm32 these `http_bare` GETs and RFC 7592 calls keep the browser's default `same-origin` credentials, so a same-origin page sends the HttpOnly `axiam_*` cookie:
    - the client's own and the SSF JWKS GETs (`src/token/jwks.rs:1286-1290`);
    - the SSF discovery GET (`src/ssf.rs:434`) and `src/ssf.rs:675`;
    - `/oauth2/register` (`src/oidc/registration.rs:307`, `:369`, `:399`).
    
    The browser also follows redirects there, so the CHANGELOG line "no longer follow redirects" (`CHANGELOG.md:51`) holds on native targets only.
  - **Fix, code:** add a crate-internal extension trait, e.g. `trait OmitBrowserCredentials { fn omit_browser_credentials(self) -> Self; }` on `reqwest::RequestBuilder`. It calls `fetch_credentials_omit()` under `cfg(target_arch = "wasm32")` and is identity otherwise. Use it in `oauth2_post` and at each site above.
  - **Fix, CHANGELOG:** append "(native targets; in the browser build, redirects are the browser's)" to `:51`.
  - **Fix, test:** a `cfg(target_arch = "wasm32")` compile check is enough (the wasm CI job builds `rest`).
- **C164-23: Informational** at `tests/oauth2_no_session_bearer_test.rs:344-346`.
  - **What happens:** the new comment says "`logout` ends the session and clears the jar". It does not: `logout` (`src/rest/auth.rs:768-836`) clears the token manager, not the reqwest jar, which is why the SSF test (`tests/ssf_receiver_test.rs:1049`) still sees the cookie after `logout` under the mutant.
  - **Fix, comment:** "The control comes last, so the `/oauth2/*` assertions run while the session is live."
  - **Fix, SSF test:** move its `logout` control after the two `verify_set` calls, for the same reason, and change the `seen[0]` assertion to the last entry.
- **C164-20: Informational** at `src/oidc/device.rs:355-362`.
  - **What happens:** the doc says a hand-rolled loop "sees exactly what `device_login` sees". After (b), `device_login` reads `Retry-After` on a 429, and a `device_poll` caller cannot.
  - **Fix:** add to the doc: "A `429` surfaces as an `OAuthProtocolError` with `error == "rate_limit_exceeded"`. It is not terminal: wait at least the server's `Retry-After` (or one interval) without raising the interval (§14.2 rule 9). `device_login` does this for you." Optionally expose the hint later (additive).

---

### Report — python — commit 08a691423 (PR #103)

Version 1.1.1 → 1.1.2. Issue ilpanich/axiam-python-sdk#102 (items taken from plan §8.2, Python row; I could not read the issue, the PR or CI because this session has no GitHub API access).

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | **The loop logic conforms, but the real server's 429 never reaches it (C164-01).** Sync and async `device_login` are identical. A `rate_limit_exceeded` code is classed `"rate_limited"`, which is not terminal and is never read as `slow_down`. `PollSchedule.rate_limited` sets a one-shot floor, and `tick` waits `max(interval, Retry-After)`. That wait counts as one interval and the interval is not raised. If the wait reaches the deadline, `tick` returns False and the loop raises `expired_token` at once (§33.7 rule 5 allows this), sending nothing more. `Retry-After` handling: delta-seconds and HTTP-date both parse, a negative value floors at 0, and NaN, inf or garbage give `None`, which means one plain interval. `device_poll` has no §16 `retry_sync` wrapper, so there is no double wait. **However**, the 429 maps to `OAuthProtocolError` only when the body also has `error_description`. The server sends `{"error":"rate_limit_exceeded"}` (`axiam-api-rest/src/middleware/rate_limit_shared.rs:105`) or `{"error":"rate_limit_exceeded","retry_after":N}` (`extractors/rate_limit.rs:219`), with neither. So the SDK raises a `NetworkError`, classes it `"retry"`, ignores `Retry-After` and polls again at the plain interval. The deadline is the sum of the sleeps, not a clock (C164-05, pre-existing). | `src/axiam_sdk/_oidc.py:301-358`, `:1666-1689`, `:1162`; `_errors.py:275-307`, `:310-331`, `:358-363`; `_client.py:2001-2026`; `_async_client.py:810-835` |
| 2 | (b) §14.6 test | Both cases are present, each with a recorded sleep: `[2, 7, 2]`, `call_count == 3`, tokens returned. In the deadline case `Retry-After: 3600` gives `expired_token`, `call_count == 1` and every wait ≤ the grant. There is also a no-`Retry-After` case, a single-`device_poll` test and an async case. The comments follow the contract's wording. **Vacuous against the real server:** the mocked 429 adds an `error_description` the server never sends (C164-01). The async loop has no deadline case and no missing-`Retry-After` case (C164-15). | `tests/test_device_flow.py:62-68`, `:134-158`, `:360-433`, `:579-601` |
| 3 | C163-14 | **Conforms.** `_apply_bearer_credential` now fires whenever the request has an `Authorization` header, adopted credential or not. Such a request gets `Cookie: ""`, except on `/oauth2/*` and off-origin requests. `_prepare_request` then adds no `X-CSRF-Token` when `Cookie == ""`. All six operations go through this in both clients (sync `_client.py:2425-2520`, async `_async_client.py:1080-1175`, each via `_rest_send_*` with `_uma_protection_headers`). There is no CSRF side effect elsewhere: the server's CSRF middleware exempts a bearer request that has no session cookie (`csrf.rs:161-166`). A cookieless request that is not bearer would fail CSRF anyway, because there is no `axiam_csrf` cookie, and `/api/v1/auth/device` is exempt. The test covers all six operations, sync only (async probed, C164-15), after a real mocked `login()`. It asserts the PAT, no cookie and no CSRF header, then a management POST as the control. | `_client.py:941-996`; `_session.py:420-424`; `tests/test_no_session_cookie_on_oauth2.py:138-203` |
| 4 | C163-08 | **Conforms.** Sync and async both sign in through `login()` against a mock that sets `axiam_access`, `axiam_refresh` and `axiam_csrf` and returns `X-CSRF-Token`. They then call `device_authorize`, `device_poll` and `login_client_credentials`, asserting no `Cookie` or `X-CSRF-Token` on any of them. The control comes last: a `POST /api/v1/groups` asserted to carry `axiam_access=`, `axiam_csrf=` and `X-CSRF-Token == "csrf-from-login"`. The control is a raw request sent through `_rest_send_*`, not a public management call. That is acceptable, because it is the same choke point. | `tests/test_no_session_cookie_on_oauth2.py:42-131` |
| 5 | C163-09 | **Conforms.** Parametrised over `termination_action` and `service_type`. `plan(unchanged)` is converged, then `apply(unchanged)` is followed by `fake.writes() == []`. The stated `PUT` carries the stated value, and `"future"` is absent from the body. The refusal test was already parametrised. (Strength note: with one member unknown, the absence check is implied by the equality check. No defect.) | `tests/management/test_network_manifest.py:852-916` |
| 6 | C163-18 | **Conforms.** The docstring now states "the PAT alone" with its condition (with or without an adopted credential, after a cookie login). | `_client.py:960-972` |
| 7 | Version & docs | **Conforms.** `pyproject.toml:7` and `__init__.py:109` are 1.1.2, and there is no lockfile. `CHANGELOG.md:10-48`, `## [1.1.2] - 2026-10-23`, follows the repo's convention: it names 1.64, `fb92ec4`, (b), C163-14/08/09/18 and C163-10 n/a. The patch bump is right: `OAuthProtocolError.retry_after_ms` is new, optional and defaults to `None`, so nothing breaks. README `:30` says "1.1.2 … contract 1.64", and `:1598-1603` documents (b). The install snippets are unpinned. `CONTRACT.md`, `openapi.json` and `management-registry.json` are byte-identical to `fb92ec4:sdks/`, and `proto/axiam/v1/*` are identical. The CHANGELOG's "Tested per §14.6" and "now carrying `retry_after_ms`" are true only for a body with `error_description` (C164-01). | as cited |
| 8 | 1.63 regression | **None found.** `/oauth2/*` still drops `Cookie` and `X-CSRF-Token` in `_prepare_request` (`_session.py:404-416`), and `_apply_bearer_credential` returns early on `/oauth2/*`, so §6.1 rule 11 still holds (`_client.py:989-990`). The poll path is unchanged apart from the sleep value. The §27.6.2 refusals are still at `plan` with no write (`test_network_manifest.py:852-877`). The other `Authorization` producers (`ssf/_receiver.py:706`, `_registration.py:271`) use the bare transport and are unaffected. | as cited |
| 9 | Other | Nothing else wrong in the diff. CIBA, for comparison, already maps with `description_optional=True` (`_ciba.py:450`), which is why its 429 handling works against the real server and the device grant's does not. | `_ciba.py:450` |

**Run by the reviewer** (throwaway copy `/home/user/work/python`, venv, `pip install -e '.[dev,fastapi,django]'`, Python 3; the copy has been deleted):
- `ruff check .` passed. `ruff format --check .` passed (217 files). `mypy --strict src` passed (98 files). `interrogate -c pyproject.toml src/axiam_sdk` gave 100%. `python scripts/gen_management.py --check` passed.
- `pytest tests -q`: **2124 passed**, 7 warnings (5 min 58 s).
- (b) mutants, each applied to both the sync and async loops, run against `tests/test_device_flow.py`:
  - 429 made terminal: 4 failed.
  - 429 raises the interval by 5 s (`schedule.slow_down()`): 3 failed.
  - `Retry-After` ignored: 3 failed.
- C163-14 mutants, run against `tests/test_no_session_cookie_on_oauth2.py`:
  - The `Cookie == ""` CSRF skip removed: 4 failed (register, update, delete, ticket; the GETs carry no CSRF anyway).
  - The old `token is None` early return restored: 6 failed.
- Probe, the server's exact 429 bodies (`{"error":"rate_limit_exceeded"}` and the `retry_after` variant, `Retry-After: 7`):
  - `device_poll` raised `NetworkError`, not `OAuthProtocolError`.
  - `device_login` slept `[2.0, 2.0]`: the `Retry-After` was ignored.
- Probe, HTTP-date `Retry-After` 30 s ahead: slept 29.16 s, so it is handled.
- Probe, async deadline case: `expired_token` with 1 call, so it conforms.
- Probe, all six async UMA operations after a cookie `login()`: the PAT is sent with no cookie and no CSRF header, and the control carries both. 6 passed.
- **C164-01's fix applied in the copy:**
  - With the HEAD code and the test helper switched to the server's exact body, 4 tests failed.
  - With the fix, `test_device_flow`, `test_oidc*`, `test_ciba` and `test_no_session_cookie_on_oauth2` gave 247 passed, and the full suite gave 2124 passed.
- Not run: CI. There is no GitHub API access, and the clone was not modified.

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):
- **C164-01 (Medium):** `src/axiam_sdk/_oidc.py:1162` together with `_errors.py:303-307`.
  - **Rule broken:** §14.2 rule 9, 1.63 paragraph (the 429 is the `OAuthProtocolError` with `error == "rate_limit_exceeded"`) and its 1.64 paragraph (the loop waits `Retry-After`).
  - **What happens:** `_handle_token_response` maps with the default `description_optional=False`. That needs `error_description`, which the server's 429 body never carries (`rate_limit_shared.rs:105`, `extractors/rate_limit.rs:219`). Against a real AXIAM, `device_poll` raises a bare `NetworkError`, and `device_login` classes it `"retry"`, ignores `Retry-After` and re-polls at the plain interval, so it keeps hitting the limiter until its window ends. The §14.6 test passes only because its mock adds `error_description`.
  - **Code fix** (`_oidc.py:1162`): `raise error_from_oauth2_response(response.status_code, response, "token request failed", description_optional=response.status_code == 429)`. This is scoped to 429 so that the existing §12 mappings stay as they are. Verified above.
  - **Test fix** (`tests/test_device_flow.py:62-68`): make `_rate_limited` send the server's exact body, `content=b'{"error":"rate_limit_exceeded"}'` with `content-type: application/json`, with no `error_description`. Add one parametrised case with `{"error":"rate_limit_exceeded","retry_after":7}`. The single-`device_poll` test then also pins `OAuthProtocolError` for the real body.
- **C164-15 (Info):** `tests/test_no_session_cookie_on_oauth2.py:138-203`.
  - **Plan item:** C163-14, "sync and async".
  - **What happens:** the six-operation C163-14 test covers the sync client only. The async client shares `_apply_bearer_credential`, and the probe passes.
  - **Fix:** add an `@pytest.mark.asyncio` twin, parametrised over the same six operations on `AsyncAxiamClient`. It should `await client.login(...)`, call the operation, assert `authorization == f"Bearer {pat}"`, no `cookie` and no `x-csrf-token`, then `await client._rest_send_async(... "POST", "/api/v1/groups")` and run `_assert_control_carries_both`.
- **C164-15 (Low):** `tests/test_device_flow.py:579-601`.
  - **Rule broken:** the §14.6 1.64 test, second case, for the async loop.
  - **What happens:** the async loop has no deadline case and no missing-`Retry-After` case. The async code passes them (probed).
  - **Fix:** add async twins of `:384-398` and `:400-420`. Record `asyncio.sleep`, use `expires_in=10, interval=1` with `Retry-After: 3600`, and assert `expired_token`, `route.call_count == 1` and every wait ≤ 10. For the second twin, use `_rate_limited(None)` and assert `sleeps == [2, 2]`.
- **C164-05 (Low, pre-existing):** `src/axiam_sdk/_oidc.py:343-358`.
  - **Rule broken:** §14.2 rule 4 (the deadline is the initiate time plus `expires_in`, and nothing is sent past it).
  - **What happens:** `PollSchedule` subtracts only the planned sleeps from `expires_in`. Request latency, retried 5xx round trips and the `on_user_code` callback's run time are never counted, so a slow network or a blocking callback can poll past the real deadline. The server then answers `expired_token`, so no data is lost.
  - **Fix:** in `PollSchedule.__init__`, record `self._deadline = time.monotonic() + expires_in_seconds`, captured right after `device_authorize` returns. In `tick`, compute `remaining = self._deadline - time.monotonic()` and return False if `wait >= remaining`. Tests should then patch `time.monotonic` next to `time.sleep`.
  - **Test:** a fake monotonic clock that advances 3 s per poll, `expires_in=10, interval=2`, asserting no poll is sent once the clock passes 10.

**Added by the lead reviewer (read, not probed).** C164-03: AXIAM's `500` body is `{"error":"server_error","error_description":"…"}` (`OAuth2ErrorResponse`, both members `String`, `crates/axiam-api-rest/src/handlers/oauth2.rs:182-185`), so `_oauth2_error_body` accepts it, `error_from_oauth2_response` returns `OAuthProtocolError("server_error")` and `_device_poll_outcome` (`src/axiam_sdk/_oidc.py:1679-1689`) classes any non-`None` code it does not know as `"terminal"`. C164-04: a `429` whose body is `{"error":"slow_down","error_description":…}` reaches the `"slow_down"` branch first (`:1680-1681`).

---

### Report — c — commit 0a9200858 (PR #77)

Version 1.1.1 → 1.1.2 (patch; SOVERSION stays 2). Branch `claude/contract-1.64`, 4 commits over `origin/main` f2b4f12. No GitHub access was available, so the issue (#76), the PR and its CI were not read. The item list comes from plan §8.2.

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | **Conforms.**<ul><li>`axiam_device_login` treats `429` + `rate_limit_exceeded` as non-terminal. The next wait is `max(Retry-After, interval)`, so Retry-After is a minimum and the interval is respected.</li><li>The wait is reset to the interval after every sleep, and `interval` is not touched (only `slow_down` raises it).</li><li>The deadline check runs on the *next* wait: `now + ceil(wait) >= deadline` gives a typed `expired_token` at once, with nothing sent.</li><li>§16 does not also retry the 429: `OIDC_RETRY_LOOP_OWNS_429` breaks `oidc_post`'s loop on 429. This matches §16.2, where a poll is eligible only on 5xx or transport failure. A single `axiam_device_poll` therefore returns the 429 at once as `AXIAM_ERR_AUTH`, `oauth_error="rate_limit_exceeded"`, `transport_cause=429` (probe).</li><li>`Retry-After` handling (`src/retry.c:69-99`): delta-seconds and IMF-date are parsed; missing, garbage or a past date give -1, so the loop waits the interval; values are clamped at 3600 s.</li><li>The server's exact bodies are handled. `{"error":"rate_limit_exceeded"}` (`rate_limit_shared.rs:105`) and `{"error":"rate_limit_exceeded","retry_after":7}` (`extractors/rate_limit.rs:219`) both map through `oidc_map_grant_error`, which needs no `error_description`, and the loop waits the `Retry-After` header (probe P1). The body's `retry_after` is ignored, which is correct.</li><li>Two gaps, see C164-04 and C164-03:<ul><li>a 429 whose body says `slow_down` **does** raise the interval (C164-04);</li><li>a `500 {"error":"server_error"}` mid-poll is terminal (C164-03, pre-existing).</li></ul></li></ul> | `src/oidc_device.c:288`, `:299-309`, `:331-337`; `src/oidc.c:456-461`, `:916-922`; `src/oidc_internal.h:119-120`, `:157-163`; `src/oidc_device.c:207-211` |
| 2 | (b) §14.6 test | **Conforms, not vacuous.**<ul><li>Case 1: interval 2, `429` with `Retry-After: 20`, then `authorization_pending`, then `200`. It asserts 3 token calls and 3 recorded sleeps `[2000, >=20000, 2000]`. The third sleep is the "interval unchanged" proof; the 3-call count also proves §16 did not retry the 429.</li><li>Case 2: a 30 s grant with `Retry-After: 3600`. It asserts `AXIAM_ERR_AUTH`, `oauth_error=="expired_token"`, 1 token call and 1 sleep.</li><li>An extra case covers a 429 with no Retry-After.</li></ul>The test names and comments follow the contract's wording, and the mocks use the server's exact body. Six mutants all fail at least one case (see Run). | `tests/test_oidc_grants.c:238-302`; `tests/oidc_test_util.h:60`, `:151-153` |
| 3 | C163-10 (D-15) | **Done.** The message now reads "…holds a %s whose value is unknown to this SDK…". No struct changed. The test asserts `strstr(err.message, "unknown")`, which the old text ("does not know") would fail; mutant M9 confirms. | `src/management_manifest.c:1010-1016`; `tests/test_manifest_network.c:664-667` |
| 4 | C163-20 bearer | **Done.** `build_headers(…, oauth2)` skips the adopted `device_access_token` on `/oauth2/*`. Only `transport_once_ex` calls it, and the `/oauth2/jwks` (`jwks.c:80`) and `/oauth2/revocations` (`revocation.c:191`) fetches reach it through `axiam_client_raw_get`. The token, device, PAR, introspect, revoke and UMA paths build their own headers with no device bearer. The test adopts a device token, GETs both paths and asserts no Authorization header; the control `check_access` then carries `Bearer dev-tok`. Mutant M7 fails it. The CHANGELOG names the wrong test file (C164-22). | `src/client.c:255-288`, `:326-328`; `tests/test_device_auth.c:283-312` |
| 5 | C163-20 stated-unknown test | **Done.** A manifest stating `termination_action:"future"`, or `service_type` set to `"future"`, is refused at `plan` by `validate_network` before any write. The test checks the member name, `transport_cause` 400 and reads only. Mutant M10 fails it. | `src/management_manifest.c:140-156`; `tests/test_manifest_network.c:711-738` |
| 6 | C163-20 `refuse()` 400 + doc | **Partly done.**<ul><li>Done: `refuse()` now sets 400. `error.h` and `management_manifest.h` carry the sentence the plan asked for.</li><li>Not done: `refuse()` covers only the network section. The general manifest validation (duplicate key, dangling `depends_on`, cycle, role-binding checks) and the service-account ambiguity refusal still set 0. `axiam_mgmt_plan`'s new doc names exactly those refusals and says they carry 400 (C164-08).</li><li>`oom()` now reports an out-of-memory as a 400 "local refusal" (C164-08).</li></ul> | `src/management_manifest.c:46-50`, `:167-298`, `:645`, `:886-888`; `include/axiam/management_manifest.h:398-402`; `include/axiam/error.h:34` |
| 7 | C163-18 texts | **Done** (three texts: the `CMakeLists.txt` version note, the `scim_target_response_to_input` doc, the `fill_profile_input` comment). They match the 1.63 report's "C stale comments", but the issue text could not be read to confirm the list. No stale `1.1.1` remains outside history. | `CMakeLists.txt:3-5`; `include/axiam/management_helpers.h:129-134`; `src/management_manifest.c:1323-1329` |
| 8 | Version & docs | **Correct.**<ul><li>1.1.2 in CMake (project and CPack), `AXIAM_VERSION`/`_PATCH`, Doxyfile, conanfile, vcpkg.json, README (FetchContent tag, conan), the `test_sensitive` pin and the registry `spec_version`.</li><li>`CONTRACT.md`, `openapi.json` and `management-registry.json` are byte-identical to axiam `fb92ec4` (`cmp`); the SDK vendors no `proto/`.</li><li>The CHANGELOG `## [1.1.2] - 2026-10-23` follows the repo's convention and names 1.64, `fb92ec4`, (b), C163-10/18/20 and #76. The README's contract sentence says 1.64 and has a 1.64 paragraph.</li><li>ABI: no public struct or signature changed (the `error.h` change is a comment; `oidc_token_grant_ex` and `oidc_answer_t` are internal or test-only), so SOVERSION 2 is right.</li><li>The patch bump fits: the only observable changes are the 429 loop and `transport_cause` 0→400 on network-manifest refusals. Neither is source- or ABI-breaking.</li></ul> | `CHANGELOG.md:9-47`; `include/axiam/axiam.h:43-47`; `CMakeLists.txt:7`, `:134`, `:210`; `README.md:16`, `:40-50`, `:223`, `:247` |
| 9 | 1.63 regression | **None.**<ul><li>C163-03: `uma_transport` (not in the diff) still sends the empty `Cookie` jar-withhold signal and only the caller's bearer. `test_oauth2_no_session` still runs `axiam_uma_exchange_ticket` after a real libcurl cookie login, and it passes.</li><li>The poll path still goes through `oidc_transport_once`, which sends no CSRF and the empty `Cookie`.</li><li>The `build_headers` change only removes a header.</li><li>§27.6.2 refusals still happen at `plan`, before any write.</li></ul> | `src/uma.c:130-161`; `src/oidc.c:415-429`; `tests/test_oauth2_no_session.c:144-200` |
| 10 | Other | <ul><li>A `429` whose body is not OAuth JSON falls into the `!code[0]` branch, so its `Retry-After` is ignored (C164-17, Info).</li><li>`error.h` says "nothing was sent", but the plan-time unknown-member refusal comes after GETs (C164-08).</li><li>`gen_management.py --check` is clean.</li><li>`test_client_failing_transport` flaked once under `ctest -j8` (a pre-existing timing test, not touched here; C164-23).</li></ul> | `src/oidc_device.c:319-323`; `tests/test_client_failing_transport.c:301`, `:332` |

**Run by the reviewer** (throwaway copy `/home/user/work/c`; `libcurl4-openssl-dev` and `libssl-dev` installed with apt; the build dir was deleted afterwards):
- Configure and build, the CI's sanitizer leg:
  ```
  cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
  cmake --build build-asan -j8
  ```
  Build: 0 warnings.
- `ctest --test-dir build-asan -j8`: 80/81. `test_client_failing_transport` failed at `:332` (`refresh_calls` expected 1, was 2). It passed 5/5 when re-run alone, and a serial `ctest --test-dir build-asan` gave **81/81 passed**, ASan/UBSan clean.
- `test_oidc_grants` 29/29, `test_device_auth` 13/13, `test_manifest_network` 17/17.
- `python3 scripts/gen_management.py --check`: clean.
- Not run: the plain Debug C-standard matrix, the valgrind leg, Doxygen and the package-recipe jobs. The ASan leg covers the same tests.
- Mutants (each applied, rebuilt, run, then reverted; `ASAN_OPTIONS=detect_leaks=0` so Unity output survives). All are **killed**:
  - M1, 429 made terminal: 3 failures (`:255`, `:279`, `:298`).
  - M2, interval += 5 on 429: `:263` and `:282` fail ("Was 7000").
  - M3, Retry-After ignored: `:261` and `:299` fail.
  - M4, §16 allowed to retry the 429: `:282` and `:299` fail.
  - M5, deadline check uses the interval instead of the wait: `:299` fails (2 calls).
  - M6, wait not reset after the 429: `:263` fails ("Was 20000").
  - M7, bearer sent on `/oauth2/*`: `test_device_auth.c:301` fails. `test_oauth2_no_session` does not catch it.
  - M8, `refuse()` back to 0: 4 failures.
  - M9, message without "unknown": 2 failures.
  - M10, stated unknown `termination_action` accepted: `:729` fails.
- Cross-SDK probes (temporary tests in the copy, against HEAD):
  - P1, the server's exact body `{"error":"rate_limit_exceeded","retry_after":7}` with `Retry-After: 7`: **PASS**, a sleep of 7000 and then completion.
  - P2, single `axiam_device_poll` on a 429: **PASS**, `AXIAM_ERR_AUTH`, `rate_limit_exceeded`, cause 429, 1 call.
  - P3, `500 {"error":"server_error"}` three times, then 200: **FAIL**, the loop ends with "server_error (device poll failed)" (C164-03).
  - P4, `429 {"error":"slow_down"}`, then pending, then 200: **FAIL**, the next wait is 7000, so the interval was raised (C164-04).

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):
- **C164-08 — Low** — `src/management_manifest.c:167-298`, `:645` (and `:886-888`); doc `include/axiam/management_manifest.h:398-402`, `include/axiam/error.h:34`. Rule: plan §8.2 C row ("the manifest's `refuse()` sets `transport_cause` 400 like the builders"), C163-20.
  - What happens: only the network-section refusals go through `refuse()`. Every `axiam_mgmt_manifest_validate`/`plan` refusal named in the new doc still reports `transport_cause` 0: duplicate key `:188`, missing `resource_type` `:202`, dangling `depends_on` `:215`, cycle `:232`, role-binding checks `:254-298`, ambiguous service account `:645`. A caller who follows the doc and dispatches on 400 misses them, and the inconsistency C163-20 named now sits inside the manifest family. Also, `oom()` now reports an out-of-memory as a 400 "local refusal", and `error.h`'s "nothing was sent" is false for the plan-time unknown-member refusal at `:1019`, which follows reads.
  - Fix:
    - Replace each `axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg)` at `:179`, `:188`, `:202`, `:215`, `:232`, `:254`, `:264`, `:278`, `:291`, `:298`, `:645` with `refuse(err, msg)`. Keep `:167` (invalid arguments) and the OOM sites at 0, or route them to `refuse()` too and say so.
    - Make `oom()` call `axiam_error_set(err, AXIAM_ERR_NETWORK, 0, "manifest: out of memory")` directly.
    - In `error.h`, change "nothing was sent" to "the error did not come from the server (no write was sent)".
    - Add a test in `tests/test_manifest_network.c` or the manifest test that asserts `err.transport_cause == 400` for a duplicate key and for a dangling `depends_on`, on both `axiam_mgmt_manifest_validate` and `axiam_mgmt_plan`.
- **C164-04 — Informational** — `src/oidc_device.c:325-330`. Rule: §14.2 rule 9 ("an SDK MUST NOT read a `429` as the polling signal").
  - What happens: the `slow_down` branch matches the `error` field without checking the status, so a `429 {"error":"slow_down"}` adds 5 s to the interval for good (probe P4). AXIAM ≥ 1.1.1 never sends that body, but the 1.1.0 server did, and the rule forbids the reading outright.
  - Fix: `if (strcmp(code, "slow_down") == 0 && poll_err.transport_cause != 429) { … }`. Then route any 429 to the rate-limit branch, e.g. change `:331` to `if (poll_err.transport_cause == 429) {`. Add a §14.6 case: a `429 {"error":"slow_down"}`, then pending, then 200, asserting `sleeps[2] == 2000`.
- **C164-03 — Low (pre-existing, not introduced by this PR)** — `src/oidc_device.c:319-344` with `src/oidc.c:489-511`. Rule: §14.2 rule 6 ("5xx and transport failures … are not terminal … an exhausted retry budget ends that one poll, not the flow").
  - What happens: AXIAM answers `500 {"error":"server_error"}` on a token-endpoint datastore failure. `oidc_map_grant_error` turns that into `AXIAM_ERR_AUTH` with `oauth_error="server_error"`. After the per-poll §16 budget (3 attempts) is spent, the loop hits the terminal fall-through and `axiam_device_login` fails (probe P3). The existing 500 test passes only because its 503 bodies are empty.
  - Fix: in the loop, before the `authorization_pending` check, add `if (poll_err.transport_cause >= 500 && poll_err.transport_cause <= 599) continue;`, or map a 5xx in `oidc_map_grant_error` to the §2 kind with an empty `oauth_error`. Add a test: `500 {"error":"server_error"}` ×3, then 200 → `AXIAM_OK`, 4 token calls.
- **C164-22 — Informational** — `CHANGELOG.md:29-30`. Rule: plan §8.2 (CHANGELOG names the items and their tests).
  - What happens: the C163-20 bearer entry says "Test: `test_oauth2_no_session`". The test is `test_adopted_bearer_is_not_sent_on_jwks_or_revocations` in `tests/test_device_auth.c:283`, and mutant M7 shows `test_oauth2_no_session` does not cover it.
  - Fix: change it to "Test: `test_device_auth` (`test_adopted_bearer_is_not_sent_on_jwks_or_revocations`)".
- **C164-17 — Informational** — `src/oidc_device.c:319-323`. Rule: §14.2 rule 9 (Retry-After is a minimum).
  - What happens: a 429 with a non-OAuth body (a proxy's 429) lands in the `!code[0]` branch, which waits only the interval and ignores its `Retry-After`. That body is not `rate_limit_exceeded`, so this is outside the letter of the rule.
  - Fix: in that branch, `if (poll_err.transport_cause == 429 && retry_after_ms > wait_ms) wait_ms = retry_after_ms;` before `continue`.
- **C164-23 — Informational (pre-existing, not in the diff)** — `tests/test_client_failing_transport.c:301`, `:332`. What happens: the single-flight follower test relies on a 60 ms `usleep` coalescing window, and it failed once under `ctest -j8` with ASan ("Expected 1 Was 2"). Fix: replace the sleep with a condition the leader holds until all `N_FOLLOWERS` have entered `axiam_refresh`, e.g. a counter in the transport plus a bounded wait. If the SDK has no seam for that, add `RUN_SERIAL TRUE` to the test's `set_tests_properties`.

---

### Report — cplusplus — commit 0c7bfd731 (PR #80)

Version 1.1.1 → 1.1.2 (SOVERSION 3 → 4). Issue ilpanich/axiam-cplusplus-sdk#78. Item list from plan §8.2 (C++ row).
I had no GitHub access, so I could not read the issue, the PR or CI. Every `path:line` below is on HEAD `0c7bfd731`.

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | **Conforms for the 429.** The token-endpoint retry stops (`break`) on a `429` whose body names an `error`, so the §16 layer does not retry it. Only the device poll is `retryable=true`, so only the poll path changes. `raise_grant_error` parses `Retry-After` into `OAuthProtocolError::retry_after()`: delta-seconds or IMF-date, unparseable → absent, clamped at 3600 s. `device_login` sets `retry_floor = ceil(Retry-After)` and continues. The next wait is `max(interval, retry_floor)`: at least Retry-After and never less than the interval, and it counts as one interval. `interval` is untouched. The deadline check `now + wait >= deadline` runs before the sleep, so a Retry-After past `expires_in` raises `expired_token` at once and nothing is sent. A missing Retry-After waits the interval. The single `device_poll` raises `OAuthProtocolError{rate_limit_exceeded}` with `retry_after()` and sends one request (probe). AXIAM's exact bodies `{"error":"rate_limit_exceeded"}` and `{..,"retry_after":9}` (no `error_description`) map correctly (probe). **Two gaps, both on the same poll path:** (i) a `500 {"error":"server_error"}` mid-poll is terminal, which breaks §14.2 rule 6 (C164-03, pre-existing); (ii) a `429 {"error":"slow_down"}` raises the interval (C164-04). CIBA (`ciba_await`) treats `rate_limit_exceeded` as one more interval without Retry-After, unchanged and out of scope. | `src/oidc.cpp:441-465`, `:884-896`, `:908`, `:1706-1757`; `src/retry.hpp:88-125`; CIBA `src/oidc.cpp:2540` |
| 2 | (b) §14.6 test | **Present, both cases, recorded sleeper (no wall clock), mock body is AXIAM's exact one.** Case 1 (`:441`): interval 2, Retry-After 9; asserts 2 calls, `sleeps[1] >= 9000`, tokens returned. Interval unchanged (`:461`): `sleeps[2] == 2000` after the 429. Case 2 (`:475`): Retry-After 3600 against `expires_in` 30 → `expired_token`, `token_calls == 1`. Titles read "§14.2 rule 9 (1.64): a 429 rate_limit_exceeded on a poll is waited out …", close to the contract's heading "Contract 1.64, a `429` on a poll is waited out". I could not compare them with the other ten SDKs. Every mutant fails the suite (below). Case 1 alone does not pin "not retried inside the poll": §16's retry also floors at Retry-After. Case 2 catches that mutant (C164-19). | `tests/test_oidc_grants.cpp:441-489` |
| 3 | C163-07 | **Done.** `refuse_unknown_carried` throws `std::invalid_argument`, as §27.6.2 item 4 names for C++ (CONTRACT.md:9023). The test catches that type. Mutant (back to `ValidationError`) fails 2 tests. **Type-change judgement:** not source-breaking, because no signature changes and every caller still compiles. It is a behavioural change: a `catch (axiam::AxiamError&)`, `NetworkError&` or `ValidationError&` around `plan`/`apply` no longer sees it, because `std::invalid_argument` is a `std::logic_error` outside the SDK hierarchy (`errors.hpp:12`, `management.hpp:157`). Under the plan's rule ("the minor where a change is source-breaking") the **patch is right**: it corrects 1.1.1 to the contract's named type, the trigger is narrow (a newer server's unknown value on an unstated member), nothing is written either way, and the CHANGELOG records it under *Changed* with the migration in bold. Under a strict SemVer reading it would be a behavioural break; I propose no change. | `src/management_manifest.cpp:254-268`; `tests/test_manifest_network.cpp:667-688`; `CHANGELOG.md:34-40` |
| 4 | C163-08 | **Done.** The mock now also sets `axiam_csrf`. After `oidc_refresh` and the UMA exchange, the last request (`check_access`) is asserted to be a non-`/oauth2/` `POST` carrying `axiam_session=xyz`, `axiam_csrf=csrf-int` and `X-CSRF-Token: csrf-int`. PR #77 had added the `check_access` control without `axiam_csrf` or the method check; this completes it. | `tests/test_integration_curl.cpp:171`, `:340-357` |
| 5 | C163-09 | **Done.** `service_type` refusal (`:690`), quoting `"future_type"`, GETs only. Stated case (`:740`): the `PUT` body carries `termination_action: "radius_request"` and no `"future"`. `NoChange` (`:760`): `Unchanged`, GETs only. The `NoChange` case runs `plan` only, which never writes, so "no write" there is vacuous; `apply` would show it. It also covers `termination_action` only (C164-12). | `tests/test_manifest_network.cpp:690-770` |
| 6 | C163-10 (D-15) | **Done.** `NetworkReplyProfile` gains `std::optional<std::string> termination_action_wire` and `service_type_wire`, defaulted, at the end. They are filled in `from_json` when the member is a string, emitted by the generator (`MODEL_MEMBERS`/`FROM_JSON_EXTRA`, `--check` current), and never serialised. The refusal quotes the value (`"future"`) or says `unknown`. **ABI:** the struct grew, and so did `OAuthProtocolError` (`retry_after_`), so SOVERSION 3 → 4 is right, and `abi_soname` pins it via `${AXIAM_SOVERSION}`. A shared build gives SONAME `libaxiam_cpp.so.4`. It is source-compatible: members at the end with defaults, so aggregate initialisers still compile, and the new ctor parameter is defaulted. The quoted server text is not length-capped (C164-21). | `include/axiam/management_models.hpp:3274-3282`; `src/management_models.cpp:3908-3913`; `scripts/gen_management.py:364-372`, `:1488-1498`; `CMakeLists.txt:109-116`; `include/axiam/uma.hpp:172-205` |
| 7 | C163-20 | **Done.** `acquire_plain` creates up to `max_concurrent_requests` handles, then waits on `plain_cv`; `release_plain` notifies. It is a separate pool, so the cookie and cookie-less pools cannot starve each other. Test: cap 2, 3 concurrent sessionless `POST /oauth2/token`, all succeed, server max in-flight `== 2`. Mutant (unbounded) fails it. | `src/http_curl.cpp:90-100`, `:156-182`; `tests/test_transport_concurrency.cpp:286-324` |
| 8 | C163-15 / C163-04 regression | `axiam::kVersion = "1.1.2"` matches `project(... VERSION 1.1.2)`, pinned by `tests/test_version_policy.cpp` (green). C163-04 has not regressed: the integration test still runs `uma_exchange_ticket` after a cookie login and counts 4 `/oauth2/*` requests, none with a Cookie or CSRF header. `is_oauth2_url` is still the backstop. | `include/axiam/axiam.hpp:55`; `CMakeLists.txt:6`; `tests/test_integration_curl.cpp:329-345`; `src/http_curl.cpp:525-547` |
| 9 | Version & docs | 1.1.2 in `CMakeLists.txt`, `vcpkg.json`, `ports/axiam-cpp-sdk/vcpkg.json`, `conanfile.py`, `Doxyfile`, `kVersion`, and the README (version line, FetchContent `v1.1.2`, `conan create --version=1.1.2`). There is no lockfile. The CHANGELOG `[1.1.2] - 2026-10-23` names 1.64, `fb92ec4`, (b), #78 and C163-07/-08/-09/-10/-20. The README conformance sentence says contract 1.64. `CONTRACT.md`, `openapi.json`, `management-registry.json` and `opaque-test-vectors.json` are byte-identical to `fb92ec4:sdks/`. Doc drift: the `device_poll`/`device_login` header docs do not mention the 429 (C164-20). 1.1.1's CHANGELOG had a `### Binary compatibility` section; 1.1.2 puts the SOVERSION bump in its intro prose only (C164-22). | `CHANGELOG.md:9-57`; `README.md:15`, `:32-39`, `:120`, `:174`, `:199` |
| 10 | 1.63 regression | None found. `token_grant` still sets `sessionless` on every token request. The new pool bound changes no cookie or CSRF behaviour, and the poll still carries no `Cookie`, CSRF or `Authorization`. The §27.6.2 refusal still happens at `plan`, before any write (GET-only asserted). §6.1 rule 11 is unaffected. | `src/oidc.cpp:877`; tests above |
| 11 | Other | Nothing else wrong in the diff. | — |

**Run by the reviewer** (throwaway copy `/home/user/work/cplusplus`, deleted afterwards; gcc, Ninja):
- `python3 scripts/gen_management.py --check` → "§27 surface is current (7 files)", exit 0.
- `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON -DAXIAM_BUILD_EXAMPLES=ON -DCMAKE_CXX_STANDARD=17 && cmake --build build -j4` → exit 0 (121/121 steps).
- `ctest --test-dir build --output-on-failure` → 1/1 passed; the binary reports **1614 test cases, 6097 checks, 0 failed**.
- `cmake -S . -B build-so -DBUILD_SHARED_LIBS=ON -DAXIAM_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release && cmake --build build-so --target axiam_cpp` → `libaxiam_cpp.so.1.1.2`, SONAME `libaxiam_cpp.so.4`.
- Mutants (each applied alone, rebuilt, full suite run):
  - M1, the 429 raises the interval +5 → 1 fail (`:472`).
  - M2, Retry-After ignored → 3 fail.
  - M3, the 429 terminal → 3 tests / 5 checks fail.
  - M4, the deadline check ignores the Retry-After wait → 1 fail (`:484`).
  - M5, a named 429 retried inside the poll by §16 → only the cap case fails (`:484`); case 1 passes (C164-19).
  - M6, the cookie-less pool unbounded → C163-20 test fails.
  - M7, the refusal thrown as `ValidationError` → 2 fail.
  - M8, the value not quoted → 2 fail.
- Probes (temporary tests in the copy):
  - PROBE-A: 3× `500 {"error":"server_error"}`, then 200 → `device_login` throws `OAuthProtocolError(server_error)` after 3 calls. It never polls again (C164-03).
  - PROBE-B: `429 {"error":"slow_down"}`, pending, 200 → sleeps 2000, 7000, 7000, so the interval was raised (C164-04).
  - PROBE-C: AXIAM's exact `{"error":"rate_limit_exceeded","retry_after":9}` with Retry-After 9 → sleeps 2000, 9000, 2000. Correct.
  - PROBE-D: no Retry-After → sleeps 2000, 2000, which is correct. A single `device_poll` with an HTTP-date Retry-After → raises `rate_limit_exceeded`, `retry_after` 3600000 ms (clamped), 1 call, no sleep.
- Not run: the ASan/UBSan and valgrind CI legs, clang, the C++23 leg, the coverage job, Doxygen. Only the gcc/C++17 Debug leg and a shared Release library build were run.

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):
- **C164-03 — Medium** — `src/oidc.cpp:441-445` (`raise_grant_error`, reached from `token_grant` `:908`) with `device_login` `:1726-1757`. Rule broken: §14.2 rule 6 ("5xx and transport failures remain §2 NetworkError and are not terminal"), the device-poll analogue of §34.2 P8. AXIAM answers `500 {"error":"server_error"}` on a datastore failure. After the §16 budget, `raise_grant_error` dispatches on `error` first and throws `OAuthProtocolError("server_error")`. `device_login`'s `catch (const OAuthProtocolError&)` treats unknown codes as terminal and rethrows, so the grant is lost. This was pre-existing, not introduced by this PR, but it sits on the poll path (b) touches. The existing rule-6 test (`tests/test_oidc_grants.cpp:518`) uses a bodiless `503`, so it passes vacuously for this case.
  - **Fix:** in `token_grant`, before `raise_grant_error`, add `if (resp.status >= 500) throw NetworkError(context + " (HTTP " + std::to_string(resp.status) + ")", "http_" + std::to_string(resp.status));`. Either scope it to `retryable` (the device poll) or apply it to every token grant, as P8 does for CIBA.
  - **Test:** a sibling of `:518` with `token_script = {{500, R"({"error":"server_error"})"} ×3, {200, kSuccessTokens}}`, asserting that `device_login` returns the tokens and `token_calls == 4`.
- **C164-04 — Low** — `src/oidc.cpp:890-896` and `:1738-1743`. Rule broken: §14.2 rule 9 ("only the 400 raises the interval: an SDK MUST NOT read a 429 as the polling signal"). A `429 {"error":"slow_down"}`, as a ≤1.1.0 server or an intermediary sends it, is now raised immediately (the new `break`) and read as `slow_down`, so the interval becomes `+5` permanently (PROBE-B). The trigger is narrow: AXIAM 1.1.2 never sends it.
  - **Fix:** carry the HTTP status on the error. Add `std::optional<long> http_status_` with an accessor to `OAuthProtocolError` (the ABI is already bumped in this release), set it in `raise_grant_error`, and in `device_login` handle `code == "rate_limit_exceeded" || e.http_status() == 429` as the rule-9 wait, before the `slow_down` branch.
  - **Test:** script `{429, R"({"error":"slow_down"})"}`, pending, 200 with interval 2, and assert `sleeps == {2000, 2000, 2000}`.
- **C164-20 — Informational** — `include/axiam/client.hpp:837-883`. Doc drift (§14.2 rule 9). The `device_poll` doc lists only the 400 answers. The `device_login` doc does not say that a `429 rate_limit_exceeded` is waited out.
  - **Fix:** in `device_poll`'s doc, add: "A `429 rate_limit_exceeded` is an OAuthProtocolError carrying `retry_after()`, not retried within the call." In `device_login`'s doc, add: "A `429 rate_limit_exceeded` waits `Retry-After` (a minimum, capped at `expires_in`), counts as one interval and does not raise it (contract 1.64)."
- **C164-12 — Informational** — `tests/test_manifest_network.cpp:760-770`. Plan item C163-09 ("`NoChange` with no write"). The case calls `plan`, which never writes, so the GET-only assertion cannot fail. It also covers `termination_action` only.
  - **Fix:** call `apply(manifest)` instead and assert `report.complete()` and that every wire request is a `GET`. Repeat the case for `service_type: "future_type"`.
- **C164-19 — Informational** — `tests/test_oidc_grants.cpp:441-459`. Test strength (§14.6 1.64). Case 1's "not retried inside the poll" (`token_calls == 2`, `sleeps.size() == 2`) also holds when §16 retries the named 429, because §16 floors at Retry-After. Mutant M5 passes case 1 and is caught only by the cap case.
  - **Fix:** keep the cap case as the guard, and in case 1 script two `429`s then `200`. Assert `token_calls == 3` and `sleeps == {2000, ≥9000, ≥9000}`. Also assert the single `device_poll` raises after exactly one request with `retry_after() == 9000ms`, which fails if §16 retries inside the call.
- **C164-21 — Informational** — `src/management_manifest.cpp:255-260`. Robustness. The server's raw text is quoted into the exception message unbounded and unescaped. Java's item asks for a length cap.
  - **Fix:** truncate `*wire` to 64 bytes (append `…`) before quoting, and replace control characters with `?`.
- **C164-22 — Informational** — `CHANGELOG.md:9-19`. Repository convention: the `[1.1.1]` entry has a `### Binary compatibility` section, while 1.1.2 mentions SOVERSION 3 → 4 only in its intro.
  - **Fix:** add `### Binary compatibility` with: "The shared library's ABI version is now 4 (`libaxiam_cpp.so.4`): `OAuthProtocolError` and `NetworkReplyProfile` gained members at the end; not source-breaking. Rebuild against 1.1.2."

---

### Report — csharp — commit 87b88122e (PR #111)

Version 1.1.1 → 1.1.2. Base `origin/main` (97fc536). Commits: 975787d (vendor), 4e15d14 ((b)), c7fde0a (C163-07/08/09/10/20), 87b8812 (release).
Reviewed by reading only: no .NET toolchain could be installed (see "Run by the reviewer").

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code: §14.2 rule 9 / §34.8 (b) | **Partly conforms.** `DeviceLoginAsync` is the only device loop. On `429 rate_limit_exceeded` it continues (not terminal) and keeps the Retry-After. The next wait is `max(interval, Retry-After)`, so Retry-After is a minimum and the interval is still respected. That wait is counted as one interval, the interval is not raised, and the loop polls again. When the wait reaches the remaining time, the loop raises a typed `expired_token` at once with nothing sent. A bodiless 429 (`NetworkError`, `HttpStatus == 429`) is waited out the same way. The single `DevicePollAsync` raises `OAuthProtocolError("rate_limit_exceeded")`. In 1.1.1 it raised a `NetworkError`, because only 400/401 were parsed. `Retry-After` accepts delta-seconds and HTTP-date; a missing or non-positive value is treated as none. No §16 layer retries the 429: `AxiamHttpMessageHandler` retries only the 401 refresh, and `/oauth2/*` is exempt from that. **Defects (all from `anyStatusErrors: true`):** a `500 {"error":"server_error"}` now ends the loop (C164-03, Medium). A `429` with any OAuth body is dispatched on `error`, so a `429 slow_down` raises the interval (C164-04). The deadline counts only the sleeps, not request time (C164-05, pre-existing). | `AxiamClient.OidcDeviceExchangeLogout.cs:268-330`; `AxiamClient.Oidc.cs:1299-1327`; `Core/NetworkError.cs:157-177`; `Rest/AxiamHttpMessageHandler.cs:258-345` |
| 2 | (b) §14.6 test | **Present and non-vacuous.** It has a recorded sleep (`DevicePollDelay`). Case 1: pending, 429+RA 20, pending, tokens; the sleeps are `[5,5,20,5]`, there are 4 polls and it completes. That asserts a wait ≥ RA, a second poll, and an unchanged interval after the 429. Case 2: RA 120 with `expires_in` 30 gives a typed `expired_token`, 1 poll, sleeps `[5]`, and nothing after. Extras: RA below the interval, no RA, and the single-poll raise. The class summary says it follows the contract's wording; the test names paraphrase it. Not covered: a 5xx with an OAuth body (C164-03) and a 429 `slow_down` (C164-04). | `tests/Axiam.Sdk.Tests/Contract164DevicePollRateLimitTests.cs:21-127` |
| 3 | C163-07 | **Done.** The refusal is now `ValidationError(message, [FieldError(member, …)])`, one per unknown member. `ValidationError : NetworkError` (`ManagementErrors.cs:100`), so a `catch (NetworkError)` still matches: not source-breaking, and not behaviour-breaking for catch clauses. Only an exact-type check (`GetType() == typeof(NetworkError)`, xUnit `ThrowsAsync<NetworkError>`) sees a change, and no remaining test pins this refusal that way. The test asserts `ThrowsAsync<ValidationError>` at plan and apply, a single `FieldError` whose `Field` is the member, and no non-GET request. | `Management/ManifestApi.cs:633-661`; `tests/…/Management/NetworkManifestTests.cs:439-448` |
| 4 | C163-08 | **Done.** A real `AxiamClient` (public constructor, real handler stack and jar) runs over the loopback `DroppingServer`. Its `/api/v1/auth/login` sets `axiam_access` and `axiam_csrf`. The test calls `LoginAsync`, then `DeviceAuthorizeAsync`, `DevicePollAsync` and `LoginClientCredentialsAsync`. It asserts no `cookie` and no `x-csrf-token` on `/oauth2/device_authorization` and on both `/oauth2/token` requests, with `NotEmpty` and count 2 so it cannot pass vacuously. It then sends a management `POST /api/v1/resources` and asserts both the cookie and `x-csrf-token: csrf-value`. `OnPath` compares the full path with the query stripped, not a prefix. | `tests/…/Contract163OAuth2NoCookieTests.cs:40-42`, `:88-145`; `Fixtures/DroppingServer.cs:18-22`, `:128-139` |
| 5 | C163-09 | **Done.** The `NoChange` test is now a `[Theory]` over `termination_action` and `service_type`: `PlanChange.NoChange`, apply, no non-GET. | `tests/…/Management/NetworkManifestTests.cs:461-490` |
| 6 | C163-10 (D-15) | **Done.** `NetworkReplyProfile` is generated `partial` (`gen_management.py:302`) and gains internal `[JsonIgnore]` `RawTerminationAction`/`RawServiceType`. They are set in `ManagementSupport.Decode` through `IKeepsRawEnums`; `DecodeList`/`DecodePage` decode per item, so `ListProfilesAllAsync`, which plan reads, sets them too. The refusal quotes the value, or says it is unknown when none was kept. The test asserts `"future"`/`"future_service"`, quotes included. Side effects: the record's synthesized `Equals` now compares the raw fields (C164-23), and the server's string is echoed without a length cap (C164-21). The "unknown" fallback branch is untested (Info, inside C164-21). | `Management/ManagementChecks.cs:311-353`; `Management/ManagementSupport.cs:126-136`; `Management/ManifestApi.cs:663-667`; `Management/Models/NetworkReplyProfile.cs:19` |
| 7 | C163-20 | **Done, deliberately narrowed (correctly).** A second cookie-less invoker (`UseCookies = false`, default `PooledConnectionLifetime`) carries `/oauth2/*` GETs and retry-eligible POSTs: the device poll, now marked, and `ciba_poll`. Every other `/oauth2/*` POST (refresh, client credentials, revoke, …) keeps the fresh, `Connection: close` path, as §34.2 P11 requires for a request the SDK never re-sends. The CHANGELOG says so. The test asserts two polls on one connection, neither with a cookie. The `ConfigureFactoryHandler` remarks document the hand-composed handler's jar. Doc drift: C164-20. | `Rest/WriteIsolatingHandler.cs:90-103`, `:128-156`, `:198-203`; `AxiamClient.OidcDeviceExchangeLogout.cs:210-212`; `Rest/AxiamHttpClientFactory.cs:177-186`; `tests/…/Contract163OAuth2NoCookieTests.cs:152-181` |
| 8 | Version & docs | **Conforms.** `Version` is 1.1.2 in both csproj files and the README snippets. No version constant in source; no lockfiles. The CHANGELOG `[1.1.2] - 2026-10-23` follows the 1.1.1 convention: it names 1.64, `fb92ec4`, (b), and C163-07/08/09/10/20. The README says contract 1.64 and summarises §34.8. The vendored `CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/` are byte-identical to platform `fb92ec4` (checked with `cmp` and md5). A patch is right: nothing is source-breaking (the refusal's type narrows to a subclass). One behaviour change is not disclosed: a 429 from a single `DevicePollAsync` is now `OAuthProtocolError`, an `AuthError` that a `catch (NetworkError)` no longer catches (C164-22). | `Axiam.Sdk/Axiam.Sdk.csproj:6`; `Axiam.Sdk.AspNetCore/Axiam.Sdk.AspNetCore.csproj:6`; `README.md:27`, `:58`, `:473-474`; `CHANGELOG.md:10-44` |
| 9 | 1.63 regression | **Cookie/CSRF isolation holds.** The new pooled invoker is built with `UseCookies = false` and never gets the jar. The `/oauth2/*` routing predicate and the CSRF skip in `ApplyHeaders` (`AxiamHttpMessageHandler.cs:435-437`) are unchanged, and the device poll still goes through `PostOAuth2FormAsync`. §6.1 rule 11 is untouched. The §27.6.2 refusal still runs in `plan` (`ManifestApi.cs:617-620`, before any step executes), `Update` only. **§14.2 rule 9's 1.63 paragraph regresses** for a 429 `slow_down` (C164-04). | as cited |
| 10 | Other | §14.2 rule 6 regression (C164-03); doc drift (C164-20). | below |

**Run by the reviewer:**
- `apt-get install -y dotnet-sdk-8.0` → `E: Unable to locate package dotnet-sdk-8.0` (exit 100).
- `curl -sSfL -o dotnet-install.sh https://dot.net/v1/dotnet-install.sh` → `curl: (22) … 403` (proxy).
- So I built nothing, ran no tests (`dotnet build`, `dotnet test`, `dotnet format --verify-no-changes`) and ran no mutants. I checked by reading that the new tests compile against the API they use: `OidcTestKit` helper signatures, the public `AxiamClient(Uri, string, AxiamClientOptions?)` constructor, `InternalsVisibleTo("Axiam.Sdk.Tests")` for `DevicePollDelay`, `ValidationError.Fields`, and `ResourcesApi` at `/api/v1/resources`.
- Mutants, judged by reading the test against the code:
  - Remove the `rate_limit_exceeded` catch: the error goes uncaught and case 1 fails.
  - Make the wait `interval + 5`: the sleeps become `[…,20,10]`; fails.
  - Ignore `Retry-After`: `[5,5,5,5]` in case 1; in case 2 a second poll succeeds and no expired_token is raised; fails.
  - Drop `QuoteRaw`'s value: the `"future"` assertion fails.
  - Pass `fresh: true` for retry-eligible requests: the `ConnectionId` assertion fails.
- Vendor check: `git show fb92ec4:sdks/{CONTRACT.md,openapi.json,management-registry.json} | cmp`, plus `proto/` md5 over a `git archive`. All identical.
- I could not read the SDK issue, the PR or CI (no GitHub access).

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):
- **C164-03 — Medium — `Axiam.Sdk/AxiamClient.Oidc.cs:1307-1322` (reached from `AxiamClient.OidcDeviceExchangeLogout.cs:212`); §14.2 rule 6, §14.6 ("a `500` mid-poll is retried").**
  - What happens: `anyStatusErrors: true` sends every non-2xx poll response through `MapOAuth2ErrorAnyStatusAsync`. A 5xx carrying an OAuth body becomes `OAuthProtocolError`. AXIAM itself answers `/oauth2/token` datastore failures with `500 {"error":"server_error"}` (`crates/axiam-api-rest/src/handlers/oauth2.rs:4997-5013`).
  - In `DeviceLoginAsync`, `server_error` matches no catch, so the loop ends. A transient database failure now loses a grant the user already approved. In 1.1.1 only 400/401 were parsed, so the same 500 was a retried `NetworkError`.
  - The existing 500 test uses an empty body (`OidcDeviceFlowTests.cs:217`), so nothing catches this. `CibaPollAsync` already guards it (`AxiamClient.Ciba.cs:197-202`).
  - **Fix (code):** in the `anyStatusErrors` branch, first add `if ((int)response.StatusCode >= 500) throw NetworkError.FromResponse(response, "oidc token request failed");`, as `CibaPollAsync` does.
  - **Fix (test):** in `Contract164DevicePollRateLimitTests` (or `OidcDeviceFlowTests`), add a case where the poll mock answers `JsonStatus(500, OAuth2ErrorJson("server_error","db"))` then `Tokens`. Assert that `DeviceLoginAsync` completes with sleeps `[5,5]`, and that a single `DevicePollAsync` on that 500 throws `NetworkError` (`HttpStatus == 500`).
- **C164-04 — Low — `AxiamClient.OidcDeviceExchangeLogout.cs:309-321` with `AxiamClient.Oidc.cs:1312-1322`; §14.2 rule 9 first paragraph (1.63: "only the `400` raises the interval: an SDK MUST NOT read a `429` as the polling signal").**
  - What happens: the 429 is now dispatched on its body's `error`. A `429 {"error":"slow_down"}`, the answer servers gave through 1.1.0, hits the `slow_down` catch and adds 5 s permanently. In 1.1.1 that 429 was a `NetworkError` and did not raise the interval.
  - **Fix (code):** add `internal int? HttpStatus { get; init; }` to `OAuthProtocolError` and set it in the 429 branch of `PostTokenAsync`. Order the loop's catches as `catch (OAuthProtocolError e) when (e.HttpStatus == 429 || e.Error is "rate_limit_exceeded")` (wait out the Retry-After) before `catch (OAuthProtocolError e) when (e.Error is "slow_down")`.
  - **Fix (test):** a mock that answers `JsonStatus(429, OAuth2ErrorJson("slow_down","x"))` with Retry-After 1, then `Tokens`. Assert sleeps `[5,5]`, not `[5,10]`.
- **C164-05 — Low (pre-existing) — `AxiamClient.OidcDeviceExchangeLogout.cs:268-296`; §14.2 rule 4 ("MUST NOT poll past the deadline"), §14.6 case 2 ("sends nothing after the deadline").**
  - What happens: `remainingSeconds` subtracts only the waits. The time spent in each request (up to the HTTP timeout on a slow 5xx or transport failure) is never counted, so polls can be sent after the real `expires_in` deadline. `CibaPollAsync` uses a wall-clock deadline (`ReceivedAt + ExpiresIn`).
  - **Fix (code):** capture `DateTimeOffset deadline = _timeProvider.GetUtcNow() + TimeSpan.FromSeconds(authorization.ExpiresIn)` as soon as `DeviceAuthorizeAsync` returns. Before each wait, compute `remaining = deadline - now` and raise `expired_token` when `wait >= remaining`. Add an internal `TimeProvider` seam (default `TimeProvider.System`) next to `DevicePollDelay`.
  - **Fix (test):** with a fake time provider that advances by the slept duration plus a simulated 10 s per request, `expires_in` 30 and interval 5, assert that no poll is sent after t = 30 s.
- **C164-22 — Informational — `CHANGELOG.md:21-23`; plan §8.2 / version rule (disclose behaviour changes).**
  - What happens: the entry says the single `DevicePollAsync` raises `OAuthProtocolError` for a 429 "as before for the contract". In 1.1.1 it raised a `NetworkError`. A hand-rolled loop with `catch (NetworkError)` around `DevicePollAsync` now meets an uncaught `AuthError` subtype.
  - **Fix:** replace that sentence with: "A single `DevicePollAsync` now raises the §2 `OAuthProtocolError` (`rate_limit_exceeded`) for a `429` with the error body, as §14.2 rule 9 has required since 1.63; 1.1.1 raised a `NetworkError`, so a hand-rolled loop catching `NetworkError` must also catch `OAuthProtocolError` with `Error == "rate_limit_exceeded"`."
- **C164-23 — Informational — `Management/ManagementChecks.cs:328-334`; D-15 ("non-breaking internal addition").**
  - What happens: the internal init properties are fields of a `sealed record`, so the synthesized `Equals`/`GetHashCode` compare them. A decoded `NetworkReplyProfile` no longer equals a caller-built one with identical public members. That is a public-behaviour change.
  - **Fix:** keep both strings in one internal holder, `internal sealed class RawEnumSpellings { public string? TerminationAction; public string? ServiceType; public override bool Equals(object? o) => o is RawEnumSpellings; public override int GetHashCode() => 0; }`, exposed as `internal RawEnumSpellings? Raw { get; init; }`, so it never affects equality.
  - **Fix (test):** `Assert.Equal(decoded, decoded with { })`, and a decoded profile equals the same profile constructed from its public members.
- **C164-21 — Informational — `Management/ManifestApi.cs:663-667`; §27.6.2 item 4 (diagnostic text from server data).**
  - What happens: the server's raw string is put into the exception message unbounded and unescaped. A newline or a very long value can garble a log line. Separately, the "value is unknown" branch has no test.
  - **Fix (code):** `QuoteRaw` uses `raw.Length > 64 ? raw[..64] + "…" : raw` with control characters replaced by `?`.
  - **Fix (test):** call `RequireNoUnknownCarried` (via plan) with a profile whose raw is null (the record built by hand in `NetworkFake`, or the `with { RawTerminationAction = null }` path) and assert the message contains "unknown".
- **C164-20 — Informational — doc drift.** Four places still describe 1.1.1 behaviour:
  - `Rest/WriteIsolatingHandler.cs:148-149`: the "a connection is already past its lifetime" comment now sits above `UseProxy`. Move it into the `if (fresh)` block.
  - The class remarks at `:38-49` list the retry-eligible POSTs without the device poll, and do not say that `/oauth2/*` GETs and retry-eligible POSTs use a pooled cookie-less handler. Add both.
  - `AxiamClient.Oidc.cs:1280` still says only `ciba_poll` is retry-eligible. Make it "`ciba_poll`, `device_poll`".
  - `Rest/AxiamHttpClientFactory.cs:179-180` implies the X-CSRF-Token is withheld through the cookie-less transport. It is withheld by `AxiamHttpMessageHandler.ApplyHeaders` in every composition, and only the jar depends on the transport. Reword to: "`X-CSRF-Token` is withheld from `/oauth2/*` in every composition; the `axiam_*` cookie is withheld only by the cookie-less transport the SDK's own primary handler builds."

---

### Report — go — commit a47ac8f94 (PR #103)

Version 1.1.1 (tag `v1.1.1` = `origin/main` `835468ef8`) → **1.1.2** (tag-based; `## [1.1.2] - Unreleased`, the repository's maintainer-tagging convention, `CHANGELOG.md:10`). Issue ilpanich/axiam-go-sdk#102. Branch: 5 commits in a straight line on `origin/main`. No GitHub API access: the issue, the PR and CI were not read.

**Vendoring.** `CONTRACT.md`, `openapi.json` and `management-registry.json`, plus all five `proto/axiam/v1/*.proto`, are byte-identical to axiam `fb92ec4` (sha256 compared).

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | **Conforms on AXIAM's real wire.** `mapOAuth2ErrorResponse` now maps a `429` with an `OAuth2ErrorResponse` body to `*OAuthProtocolError` and sets `RetryAfter` from the header: delta-seconds, an HTTP-date, or 0 when the value is invalid or absent (`login.go:678-695`). The exact body `{"error":"rate_limit_exceeded"}`, with no `error_description`, is mapped (the test mock sends exactly that). Adding `"retry_after":N` changes nothing. In `DeviceLogin` the case `rate_limit_exceeded` sets a one-shot floor. `tick()` waits `max(interval, Retry-After)`, takes that wait off the remaining budget (one interval), clears the floor, and stops with the typed `expired_token` at once when the wait reaches the deadline, so nothing is sent after it. The interval is never raised. `DevicePoll` still makes one request and raises. §16 is not involved: `DevicePoll` → `postOAuth2Form` → `doRequest` has no retry wrapper (`retryReadOnly` is used only in authz, management, registration and SSF), so there is no double wait. A `500 {"error":"server_error"}` still falls through to `*NetworkError`, which the loop treats as non-terminal. **Two deviations**, on bodies AXIAM never sends: a `429 {"error":"slow_down"}` raises the interval (C164-04), and a bodiless `429`'s `Retry-After` is ignored (C164-17). Pre-existing: the deadline is a budget of waits, not a wall-clock time (C164-05). | `oidc_wire.go:277-291`; `oidc_device.go:59`, `:68-80`, `:283-290`, `:318-326`, `:338-341`; `errors.go:73` |
| 2 | (b) §14.6 test | **Present, non-vacuous, both cases.** (i) Mock: `429` + `Retry-After: 7`, then pending, then 200. A recorded sleep (`pollSleep`, no wall clock) shows waits `[1s, 7s, 1s]`. The test asserts the token set, 3 calls, and that the poll after the 429 runs at the prior 1 s interval. (ii) `Retry-After: 100` against a 30 s deadline → `*OAuthProtocolError` `expired_token`, `errors.Is(ErrExpiredToken)`, exactly 1 token call. Extra tests: an absent or 0 Retry-After waits the interval; the single `DevicePoll` raises with `RetryAfter == 7s`. The wording follows the contract paragraph ("waits at least the Retry-After", "the interval is unchanged", "capped at the deadline", "nothing is sent after the deadline"). Six mutants all fail the tests (below). The 1.63 §14.6 tests are unchanged. | `contract_164_test.go:45-88`, `:90-120`, `:122-148`, `:150-165` |
| 3 | C163-08 | **Done.** A real `Login` against a mock that sets `axiam_access`, `axiam_refresh` and `axiam_csrf` and returns `X-CSRF-Token`. Then `DeviceAuthorize`, `DevicePoll` and `LoginClientCredentials`: all three carry no `Cookie` and no `X-CSRF-Token`, and the test asserts exactly 3 `/oauth2/*` requests. The control, `Groups().Create`, runs **after** them and carries `axiam_access=` and `csrf-from-login`. Mutants fail it: CSRF on `/oauth2/*`, jar on `/oauth2/*`, CSRF dropped everywhere. | `contract_163_test.go:100-185` |
| 4 | C163-09 | **Done, for both members.** A stated member gives exactly one `PUT /api/v1/network/profiles/{id}` whose `profile.<member>` is the stated value (`default` / `framed_user`), and `future` is absent. When nothing differs, `Plan().IsConverged()` holds and `Apply` writes nothing. Mutants fail it: refusing even when the member is stated, refusing on `NoChange`. | `contract_163_test.go:191-232`, `:234-260` |
| 5 | C163-16 | **Done as asked, but it opens a 1.63 regression (C164-02).** `jwk.WithHTTPClient(hc)` is now passed to `Register`. The tests show the JWKS fetch presents the SDK's client certificate (an mTLS `RequireAndVerifyClientCert` server) and honours `WithTimeout(300ms)`. A mutant that drops the option fails both tests. **But** `hc` is `c.httpc`, which carries the session cookie jar. After `Login`, the JWKS `GET /oauth2/jwks` now sends `axiam_access` and `axiam_csrf` (probed). | `internal/jwks/verifier.go:94-105`; `oidc_wire.go:355`; `oidc_jwks_client_test.go:19-60`, `:62-103` |
| 6 | C163-18 | **Done.** `management_manifest_network.go:379` now says "before any write". The README pin is `@v1.1.2` (`README.md:168`). The CHANGELOG `[1.1.1]` text was also edited after the `v1.1.1` tag (C164-22). | `management_manifest_network.go:379`; `CHANGELOG.md:73-77` |
| 7 | C163-19 | **Done.** `isOAuth2Path` is now a `Client` method: `HasPrefix(path, TrimRight(base.Path,"/")+"/oauth2/")`. It is used for CSRF, the adopted bearer and the jar bypass. The federation `/api/v1/auth/federation/oauth2/{start,callback}` (the only such routes in `openapi.json`) are no longer caught, and `/api/v1/oauth2-clients` never was. A base URL with a `/prefix/` path matches `/prefix/oauth2/token` and not `/prefix/api/v1/auth/federation/oauth2/callback`. The test is unit-level, and two mutants (`Contains`, prefix ignored) fail it. Posture: a discovery URL outside the base path is no longer matched (C164-24). | `client.go:830-840`, `:805`, `:825`, `:900`; `contract_163_test.go:263-289` |
| 8 | Version & docs | **Patch is right.** Go has no version constant (`version.go` holds only `MinGoVersion`), and the release is by tag. Adding `OAuthProtocolError.RetryAfter` is compatible under Go 1 rules. A `429`+OAuth body changing from `*NetworkError` to `*OAuthProtocolError` (for every `postOAuth2Form` caller: token grants, introspect, revoke, PAR, exchange) changes behaviour, not source, and 1.63 rule 9 already required it. It is recorded. The CHANGELOG names 1.64, `fb92ec4`, (b) and C163-08/09/16/18/19. The README conformance sentence says 1.64 and mentions the 429 rule. The `management-registry.json` `spec_version` is 1.1.2. The breaking-literal sentence is slightly wrong (C164-22). | `CHANGELOG.md:10-58`; `README.md:23`, `:168` |
| 9 | 1.63 regression | `/oauth2/*` cookie/CSRF isolation holds for every `doRequest` call: the device poll, token, introspect, revoke, PAR and exchange (C163-08 test and mutants). **The JWKS GET regressed (C164-02).** §6.1 rule 11: the adopted bearer is still withheld on `/oauth2/*` through `c.isOAuth2Path` (`client.go:825`). §27.6.2: the refusal is still in `planNetwork` and only for a drifted (Update) profile (`management_manifest_network.go:361-370`), before any write. | as cited |
| 10 | Other | CIBA, for comparison only (pre-existing, not in this PR): `CibaAwait` keeps polling at the interval on `429 rate_limit_exceeded` and does not honour its `Retry-After` as a minimum (C164-23). `genmanagement -check` is current. | `oidc_ciba.go:628-640`, `:731-733` |

**Run by the reviewer** (throwaway copy `/home/user/work/go`, Go 1.26.0 fetched via `GOTOOLCHAIN=auto`; the copy has since been deleted):
- `go build ./...` passed. `go vet ./...` was clean. `go test ./...` passed: 15 packages ok, 0 failures, 1677 test/subtest passes. `go run ./internal/cmd/genmanagement -check` passed: "32 generated files are current (202 operations)".
- CI (`sdk-ci-go.yml`) runs build, vet, test, govulncheck, the examples and the generator check, and no staticcheck or golangci-lint, so neither was run. `govulncheck` could not run: `vuln.go.dev` answered 403 through the proxy.
- Mutants (each reverted after its run):
  - On the (b) tests: the 429 made terminal; `+5 s` on a 429; Retry-After ignored; no cap (checking the interval, not the wait, against the deadline); the floor never cleared; 429 not mapped. **All six fail**, each failing the expected (b) tests.
  - On the issue items: JWKS without `WithHTTPClient` fails both C163-16 tests. `Contains` matcher and base path ignored both fail C163-19. CSRF on oauth2, jar on oauth2 and no CSRF anywhere all fail C163-08. Refusing when the member is stated, and refusing on NoChange, both fail C163-09. **All fail as expected.**
- Probes:
  - JWKS after `Login`: the `GET /oauth2/jwks` carried `Cookie: axiam_access=…; axiam_csrf=csrf` (C164-02).
  - Loop waits for different first responses:

    | First response | Waits |
    |---|---|
    | `429 {"error":"rate_limit_exceeded","retry_after":7}` + `Retry-After: 7` | `[1s 7s 1s]` (ok) |
    | `500 {"error":"server_error"}` | `[1s 1s 1s]`, completes (ok, non-terminal) |
    | `429 {"error":"slow_down"}` | `[1s 6s 6s]` (C164-04) |
    | bodiless `429` + `Retry-After: 7` | `[1s 1s 1s]` (C164-17) |
    | past HTTP-date | `[1s 1s 1s]` (ok) |
    | `429 {"error":"invalid_grant"}` | terminal after 1 call (C164-04) |

  - Base `/prefix` with a discovery `token_endpoint` outside the prefix on the same host: the jar was attached (C164-24).

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):
- **C164-02 — Medium.** `oidc_wire.go:355` with `internal/jwks/verifier.go:103` breaks §12.1 rule 3, last paragraph (1.63: no session cookie on any `/oauth2/*` request). It is a regression introduced by the C163-16 fix. Before, the JWKS fetch went out on jwx's default client, which has no jar. It now uses `c.httpc`, whose jar holds the `Login` cookies. Every ID-token verification after a cookie sign-in therefore sends `axiam_access` (a bearer-equivalent session token) and `axiam_csrf` to `GET /oauth2/jwks`. This is the same defect the Rust SDK fixes as C163-13. **Fix:** in `oidcJWKSVerifier`, pass a jar-less clone that keeps the TLS, client certificate and timeout: `hc := *c.httpc; hc.Jar = nil; v, err := jwks.NewVerifierForURL(ctx, jwksURI, &hc)` (or `c.bareHTTPClient()` if refusing redirects is acceptable for JWKS). **Test:** in `oidc_jwks_client_test.go`, sign in with a mock that sets `axiam_access` and `axiam_csrf`, have `DevicePoll` (or `OidcRefresh`) return an `id_token` so the verifier fetches, and assert the JWKS request's `Cookie` header is empty. Keep the certificate and timeout tests.
- **C164-04 — Low.** `oidc_wire.go:277-289` with `oidc_device.go:318-320` breaks §14.2 rule 9: "only the `400` raises the interval: an SDK MUST NOT read a `429` as the polling signal". The new mapping turns *any* `429` with an `error` member into `*OAuthProtocolError`, and the loop dispatches on `ErrorCode` alone. As a result, `429 {"error":"slow_down"}` raises the interval by 5 s, `429 {"error":"authorization_pending"}` is read as pending, and `429 {"error":"invalid_grant"}` becomes terminal (before this PR, every 429 was a non-terminal `*NetworkError`). AXIAM never sends these bodies, so the trigger is narrow. **Fix:** in `mapOAuth2ErrorResponse`, map a `429` to `*OAuthProtocolError` only when `wire.Error == "rate_limit_exceeded"`. For any other 429 (body or none), return `newNetworkError(...)` with `RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))`. **Test:** in `contract_164_test.go`, a `429 {"error":"slow_down"}` followed by success gives waits `[1s,1s]` and the interval is not raised.
- **C164-17 — Low.** `oidc_wire.go:291` and `oidc_device.go:338-341`: under §14.2 rule 9, `Retry-After` is a minimum. A bodiless `429` (from a proxy or gateway) becomes a `*NetworkError` with `RetryAfter == 0`, because `errorFromHTTPStatus` → `newNetworkError` never parses the header. The loop then re-polls at the interval, ignoring the server's `Retry-After`. **Fix:** in `mapOAuth2ErrorResponse`, set `RetryAfter` on the fall-through `*NetworkError` for 429 and 503. In `DeviceLogin`'s `*NetworkError` arm, call `schedule.rateLimited(networkErr.RetryAfter)` before `continue` (a zero value is a no-op). **Test:** a bodiless `429` + `Retry-After: 7` gives waits `[1s,7s,…]`.
- **C164-05 — Low (pre-existing, rule 4).** `oidc_device.go:68-80`, `:273-276`: the deadline is `expires_in` minus the *sum of the waits*. The time spent in `OnUserCode`, in each request's round trip and in a slow 5xx is never counted, so on a slow or rate-limited server the loop can send polls after the real `received + expires_in` instant. §14.2 rule 4 and the 1.64 "sends nothing after the deadline" are wall-clock rules; CIBA already does this right (`oidc_ciba.go` `deadline := ReceivedAt.Add(...)`, `clock.Now()`). **Fix:** record `deadline := now() + ExpiresIn` when the `DeviceAuthorize` response arrives, using an injectable `now` next to `pollSleep`. In `tick`, compute `step` and stop when `!now().Add(step).Before(deadline)`. **Test:** an injected clock that advances 10 s inside `OnUserCode`, with `expires_in` 12 and interval 5, gives `expired_token` with 0 polls.
- **C164-24 — Informational (posture, C163-19).** `client.go:839`: the anchor now requires the base URL's path prefix. A discovery-supplied `/oauth2/*` URL outside it is no longer recognised, for example an `mtls_endpoint_aliases` host, or a proxy that strips the prefix. The SDK then attaches the jar, the CSRF header and an adopted bearer to it. This is the Kotlin posture recorded in 1.63, and it is unreachable with AXIAM's own discovery. **Fix:** `p := req.URL.Path; return strings.HasPrefix(p, strings.TrimRight(c.baseURL.Path, "/")+"/oauth2/") || strings.HasPrefix(p, "/oauth2/")`. The federation routes still never match. Change the `"/oauth2/token": false` row under the `/prefix/` base in `TestIsOAuth2PathIsAnchoredToTheBasePath` to `true`.
- **C164-22 — Informational.** `CHANGELOG.md:73-77`: the `[1.1.1]` entry was rewritten, although `v1.1.1` is tagged. The same correction is already recorded under `[1.1.2]` → Changed (`:50-52`). **Fix:** restore the `[1.1.1]` bullet's original text ("before any wire call") and keep the `[1.1.2]` note.
- **C164-22 — Informational.** `CHANGELOG.md:15-16`: "breaks only an unkeyed composite literal of a type that embeds `AuthError`" is inaccurate. What breaks is an unkeyed composite literal of `OAuthProtocolError` itself. **Fix:** "…which breaks only an unkeyed `OAuthProtocolError{…}` composite literal (one that lists fields by position)."
- **C164-23 — Informational (pre-existing, CIBA, for comparison; outside the 1.64 items).** `oidc_ciba.go:634-639`, `:731-733`: a `429 rate_limit_exceeded` on `ciba_poll` is decisive, not §16-retried, and `CibaAwait` re-polls at the plain interval without honouring `Retry-After` as the minimum §33.7 rule 5 requires. **Fix:** carry `RetryAfter` on that `OAuthProtocolError` (as `mapOAuth2ErrorResponse` now does), and in `CibaAwait` sleep `max(interval, RetryAfter)`, capped at the deadline, for that case. Add a test mirroring `TestDeviceLoginWaitsOutA429RetryAfterAndKeepsTheInterval`.

---

### Report — java — commit b4072a9f1 (PR #121)

Version **1.1.1 → 1.1.2** (issue ilpanich/axiam-java-sdk#120). Base `origin/main` = `a05acac`.

The 1.63 review records Java 1.63 as "1.1.0 → 1.2.0"; that is not what shipped. The 1.63 PR wrote a `[1.2.0]` CHANGELOG entry, but the maintainer cut that work as **1.1.1**: tag `v1.1.1`, `a05acac` "prepare axiam-java-sdk 1.1.1", `pom.xml:9` 1.1.1 on main. Maven Central's `maven-metadata.xml` lists `latest`/`release` = 1.1.1 and has no 1.2.0. So the next patch, 1.1.2, is correct.

No GitHub API access was available: the issue, the PR and CI were not read. Item list = plan §8.2 Java row.

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | **Conforms on the AXIAM wire, with one regression.**<br>**Mapping:** `devicePoll` now maps failures with `fromDevicePollResponse`. A `429` with an OAuth body becomes `OAuthProtocolError` carrying the delta-seconds `Retry-After` (0 when absent, HTTP-date or invalid). In 1.1.1 it was a `NetworkError`.<br>**Loop:** `case "rate_limit_exceeded"` continues the loop. The next wait is `max(interval, Retry-After)`, so Retry-After is a minimum and the wait counts as one interval. The value is reset after one use and the interval is never raised. `waitSeconds >= remainingSeconds` throws a local `expired_token` at once, with nothing sent (allowed by §33.7 rule 5).<br>**No double wait:** no §16 retry layer wraps `devicePoll`. It uses plain `executeFormPost`; only `cibaPoll` uses `StatusRetry`.<br>**AXIAM's exact bodies:** `{"error":"rate_limit_exceeded"}` and `…,"retry_after":N}`, with no `error_description`. Both map correctly; the loop waits Retry-After, and a single `devicePoll` raises `error=rate_limit_exceeded`, `retryAfterSeconds=7`, `errorDescription=null` (probe).<br>**`500 {"error":"server_error"}` mid-poll:** still `NetworkError` and non-terminal (rule 6). The new mapping touches only 429; 400/401 go through `fromOAuth2Response` as before (probe).<br>**Regression:** a `429 {"error":"slow_down"}` now raises the interval by 5 s (C164-04). | `ErrorMapper.java:184-206`; `AxiamClient.java:3447-3454`, `:3472-3488`, `:3508-3518`, `:3522` |
| 2 | (b) §14.6 test | **Present, but incomplete.** Both cases exist. Case 1 runs interval 1, RA 2, then pending, then token, and checks 5 requests and elapsed time in [3.9 s, 7 s). Case 2 sends RA 3600 against expires_in 5 and checks `expired_token` and 3 requests.<br>Problems:<ul><li>Case 1 uses a **wall-clock** `System.nanoTime` around real `Thread.sleep`. §14.6 says "a fake clock or a recorded sleep, not a wall-clock sleep".</li><li>Its loose bounds let two wrong loops pass: wait = interval + RA ("on top", 5 s), and a Retry-After that persists past the next poll (an interval effectively raised to RA, 5 s). Both mutants survive.</li><li>Case 2 has no timeout: an uncapped wait hangs instead of failing (C164-11).</li></ul>The mock body carries `error_description`, which the server never sends. The code works without it (probe). | `AxiamClientDeviceFlowTest.java:185-234` |
| 3 | C163-08 | **Done.** `client.login()` runs against a mock that sets `axiam_access` and `axiam_csrf` and returns `X-CSRF-Token`. The four `/oauth2/*` calls (device_authorize, device_poll, refresh, client credentials) are each asserted to carry no `Cookie` and no `X-CSRF-Token`. Then `management().users().create(..)` is asserted to carry the CSRF and the `axiam_csrf` cookie, after the oauth2 calls. The control does not assert `axiam_access=` in the `Cookie` (C164-19, Info). Mutants: the cookie suppression removed fails; the CSRF suppression removed fails. | `OauthNoSessionCredentialTest.java:61-69`, `:106-123`, `:153-167` |
| 4 | C163-09 | **Partly done.** `NoChange` is added, but against a **known** read (`labProfile()`), so it does not test "the same read [with the unknown value] with nothing that differs is NoChange" (§27.9). Mutant: the refusal applied even when nothing drifted survives the whole `NetworkManifestTest` (24/24 green).<br>"service_type at apply" was read as a stated `service_type` against a read with none. The unknown-`service_type` refusal is still asserted at `plan` only, not at `apply` with 0 PUTs, and the stated `service_type` resolving an unknown read is untested (C164-12). | `NetworkManifestTest.java:411-435`, `:438-472` |
| 5 | C163-10 (D-15) | **Done.** `readProfiles` re-walks `network.list_profiles` with the raw JSON. It keeps the textual `termination_action`/`service_type` by segment id; the index alignment with `convertList` holds. `quote` replaces ISO control characters with `?` and caps at 64 characters plus `...`. The message falls back to "is one this SDK does not know" when nothing raw was captured. Non-breaking: package-private `ManagementApi.transport()`, emitted by the generator, which reproduces the tree. Test: BEL replaced, 64-character cap. Mutant: no control-character replacement fails. | `ManifestApi.java:150-153`, `:247-304`, `:654-659`, `:668-685`; `NetworkManifestTest.java:475-492` |
| 6 | C163-18 | **Mostly done.** README source-breaking list: `README.md:103-104`. `ScimTargetResponse.java:30-32` and the generator now cite §31.3 rule 4. The `ManifestApi.java:651` comment now reads "contract 1.62, refusal at plan by 1.63". README says contract 1.64.<br>Left over: `ScimTargetResponse.java:55` (the `updatedAt()` Javadoc) still cites "§32.2, contract 1.62". The README's "where §27.6.2 item 4 allows only naming the member" misstates item 4, which names the value where the SDK keeps it (C164-22). | as cited |
| 7 | C163-20 | **Done.** `validateNetwork` refuses a stated `RadiusTerminationAction.UNKNOWN` and a stated `Optional`-wrapped `RadiusServiceType.UNKNOWN`. The refusal is a `NetworkError` naming the problem, the same path as a stated unknown `kind`. It runs at `build()`, `plan` and `apply`, before any request. Test: both members, zero calls. Mutant: the check removed fails. | `ManifestValidation.java:148-160`; `ManagementManifest.java:1044`; `ManifestApi.java:96,115`; `NetworkManifestTest.java:494-507` |
| 8 | Version / docs | **Correct.** 1.1.2 in `pom.xml:9`, `bom/pom.xml:9,66`, `examples/spring-boot-app/pom.xml:39` and the README snippets (`:323-357`). There is no version constant in source.<br>CHANGELOG `[1.1.2] - 2026-10-23` names 1.64, `fb92ec4`, (b) and C163-08/09/10/18/20. It argues the patch bump: the only additions are `OAuthProtocolError(String,String,long)`, `retryAfterSeconds()` and `ErrorMapper.fromDevicePollResponse`.<br>Vendored `CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/` are byte-identical to axiam `fb92ec4`; the generator re-run gives no diff.<br>Not recorded: the thrown-type change for a single `devicePoll` on 429 (`NetworkError` → `OAuthProtocolError`) (C164-22). The stale, never-published `[1.2.0]` heading remains (`CHANGELOG.md:62`) (C164-22). | as cited |
| 9 | 1.63 regression | **None.** The cookie/CSRF isolation on `/oauth2/*` is unchanged: `devicePoll` still goes through `httpClient`, so `AuthInterceptor` applies. The new `readProfiles` is a management `GET` through `ManagementTransport`, outside `/oauth2`. The §27.6.2 refusal is still at `plan` (`Update` only), before any write. §6.1 rule 11: the adopted-device run is still asserted. | `AuthInterceptor.java:109`, `:163-193` |
| 10 | Other | **Pre-existing:** the device loop's deadline is the sum of its sleeps, not a clock. Request time (including timeouts on `NetworkError` polls) is never subtracted, so polls can run past the real `expires_in` (C164-05). `cibaAwait` uses a clock and `receivedAt + expiresIn`. A bodiless `429` stays a `NetworkError`: the loop continues at the interval and ignores Retry-After. AXIAM always sends a body (folded into C164-04's fix). | `AxiamClient.java:3470-3488`; cf. `:4769-4779` |

**Run by the reviewer** (in a throwaway copy, `/home/user/work/java`; JDK 21.0.12; Maven 3.9.16 through `./mvnw`; Maven Central reachable):
- `./mvnw -B verify`: **BUILD SUCCESS**, **1505 tests, 0 failures, 0 errors, 0 skipped**, jacoco check passed (15 min). Of these, `AxiamClientDeviceFlowTest` 15/15, `NetworkManifestTest` 24/24, `OauthNoSessionCredentialTest` 3/3.
- `./mvnw -B -o compile javadoc:javadoc`: SUCCESS, 0 warnings.
- `./mvnw -B -o -f bom/pom.xml verify`: SUCCESS.
- `bash scripts/tls-bypass-gate.sh`: exit 0.
- `python3 scripts/gen_management.py`: no diff against HEAD.
- Not run: the GPG/Sigstore verify jobs and `central-bundle-gate.sh`, which need an ephemeral key, OIDC, or a deploy.

Mutants (`-Dtest=… -Djacoco.skip=true`):

| Mutant | Outcome |
|---|---|
| `rate_limit_exceeded` case removed (429 terminal) | both (b) tests **fail** |
| `+5 s` on 429 | case 1 **fails** (13.1 s) |
| Retry-After ignored | case 1 **fails** (3.1 s); case 2 **fails** (6 requests, 100 s) |
| wait = interval + RA | **survives** |
| Retry-After not reset | **survives** |
| refusal also on not-drifted | **survives** all of `NetworkManifestTest` |
| `/oauth2` cookie suppression removed | **fails** |
| `/oauth2` CSRF suppression removed | **fails** |
| C163-20 check removed | **fails** |
| quote without control-character replacement | **fails** |

Probes (an ad-hoc test class, deleted afterwards):

| Probe | Result |
|---|---|
| exact AXIAM 429 bodies, both shapes, `Retry-After: 2` | completes in about 3.1 s; single `devicePoll` gives `rate_limit_exceeded`, `retryAfterSeconds=7`, `errorDescription=null` (pass) |
| `500 {"error":"server_error"}` mid-poll | completes, 4 requests (pass) |
| `429 {"error":"slow_down"}` RA 1, then pending, then token, interval 1 | **13.1 s** on HEAD (interval raised to 6), **3.2 s** on `origin/main` (not raised): a regression |

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):

- **C164-04 — Low (a regression in this PR).**
  - **Where:** `ErrorMapper.java:186-192` together with `AxiamClient.java:3508-3511`.
  - **Rule:** §14.2 rule 9: "only the `400` raises the interval: an SDK MUST NOT read a `429` as the polling signal".
  - **What happens:** `fromDevicePollResponse` keeps the body's `error` on a 429, so `429 {"error":"slow_down"}` reaches `case "slow_down"` and the interval rises by 5 s. That answer comes from a server through 1.1.0 (rule 9's removed bucket) or from an intermediary. On 1.1.1 the same response was a `NetworkError` and left the interval unchanged (probe).
  - **Fix (code):** on `status == 429` with an OAuth body, return `new OAuthProtocolError("rate_limit_exceeded", body.errorDescription(), retryAfterSeconds(response))` whatever the body's code is, so a 429 can never reach the `slow_down`/`authorization_pending` branches. Optionally also map a bodiless 429 to the same error, so its `Retry-After` is honoured instead of falling to the `NetworkError` branch.
  - **Fix (test):** `AxiamClientDeviceFlowTest`: a 429 `{"error":"slow_down"}` with `Retry-After: 1`, then pending, then token, at interval 1. With the recorded clock of C164-11, assert sleeps `[1, 1, 1]`.

- **C164-11 — Low (an incomplete required test).**
  - **Where:** `AxiamClientDeviceFlowTest.java:185-234`.
  - **Rule:** §14.6 (contract 1.64): "a fake clock or a recorded sleep, not a wall-clock sleep"; "the poll after the 429 is scheduled at the interval the loop held before it".
  - **What happens:** case 1 times real sleeps between 3.9 and 7 s. The loose bound lets the "on top" (interval + RA) and "sticky Retry-After" mutants pass. Case 2 would hang, not fail, if the cap were lost.
  - **Fix (code):** give `deviceLogin` a clock seam as `cibaAwait` has. Add a package-private `deviceLogin(scope, tenantId, config, onUserCode, CibaClock clock)`, or a shared `PollClock`, with `now()` and `sleep(Duration)`. The public overload passes `CibaClock.system()`.
  - **Fix (test):** case 1 asserts `clock.sleeps == [1, 2, 1]` and 5 requests. Case 2 asserts `expired_token`, 3 requests and `clock.sleeps == [1]` (or `[1, 4]` if the capped wait is served). Wrap case 2 in `assertTimeoutPreemptively(Duration.ofSeconds(10), …)` until the clock lands. Use the server's exact body `{"error":"rate_limit_exceeded"}`, without `error_description`, in the 429 mock.

- **C164-12 — Low (C163-09 incomplete).**
  - **Where:** `NetworkManifestTest.java:438-472`.
  - **Rule:** §27.9 network bullet (the "same read … NoChange" half and "assert the same for `service_type`"); plan §8.2 Java C163-09.
  - **What happens:** the `NoChange` test reads a known profile, so it cannot detect a refusal applied to `NoChange` (that mutant survives). The unknown-`service_type` case is checked at `plan` only. The "stated `service_type` resolves it" half is missing.
  - **Fix (test):**
    - Read `profile(LAB, 3600, false, "future", 600, "lab-in", "framed_user", 5)` with `ProfileSpec.of("lab", 3600)`: assert `NO_CHANGE` and 0 PUT/POST after `apply`. Repeat with `"a_future_service"` as `service_type`.
    - For the `service_type` read, assert `assertThrows(ValidationError.class, () -> apply(other))` and `put.calls() == 0`.
    - Apply `ProfileSpec.of("lab", 1800).withServiceType(RadiusServiceType.FRAMED_USER)` against that read, and assert the PUT body's `service_type == "framed_user"` and that it is not `"a_future_service"`.

- **C164-05 — Informational (pre-existing; rule 4 posture).**
  - **Where:** `AxiamClient.java:3470-3488`.
  - **Rule:** §14.2 rule 4 / §14.6 "sends nothing after the deadline".
  - **What happens:** `remainingSeconds` is decremented only by sleeps. Time spent in requests (up to the read timeout on each failed poll) is not counted, so on a slow or failing server the loop polls past the real deadline.
  - **Fix (code):** compute `Instant deadline = clock.now().plusSeconds(authorization.expiresIn())` when the authorization arrives, and test `!clock.now().plus(wait).isBefore(deadline)` as `cibaAwait` does (`:4772-4779`). This lands with C164-11's clock.

- **C164-19 — Informational (test strength).**
  - **Where:** `OauthNoSessionCredentialTest.java:163-166`.
  - **Rule:** plan §8.2 C163-08 (the control carries the session).
  - **What happens:** the management control asserts the `axiam_csrf` cookie and the CSRF header, but not the `axiam_access` session cookie.
  - **Fix (test):** add `assertTrue(create.getHeader("Cookie").contains("axiam_access=" + sessionAccess))`.

- **C164-22 — Informational (C163-18 leftovers).**
  - **`ScimTargetResponse.java:55`:** the `updatedAt()` Javadoc still says "(CONTRACT.md §32.2, contract 1.62)". Change it to "§31.3 rule 4, contract 1.63", in the generator's derived-accessor template in `scripts/gen_management.py` (the same `schema_name == "ScimTargetResponse"` switch as at `:1066`), then regenerate.
  - **`README.md:89`:** "where §27.6.2 item 4 allows only naming the member" misstates item 4. Replace it with "as §27.6.2 item 4 asks of an SDK that keeps the value (contract 1.64)".

- **C164-22 — Informational (CHANGELOG).**
  - **`CHANGELOG.md:10-40`:** does not say that a single `devicePoll` answered `429` now throws `OAuthProtocolError` (an `AuthError`) where 1.1.1 threw `NetworkError`. A caller catching `NetworkError` around `devicePoll` sees the change. It is not source-breaking, so the patch bump stands. Fix: add under `### Changed`: "`devicePoll` on a `429` with an OAuth body now throws `OAuthProtocolError` (`rate_limit_exceeded`, §14.2 rule 9 since contract 1.63) instead of `NetworkError`."
  - **`CHANGELOG.md:62`:** the `[1.2.0] - 2026-10-20` heading was never published; it shipped as 1.1.1. Fix: retitle it `[1.1.1] — contract 1.63 detail (recorded as 1.2.0 before release)`, or merge it into the `[1.1.1]` section, so the log has no version Maven Central lacks.

---

### Report — kotlin — commit 25687d50a (PR #80)

Version **1.1.1 → 1.1.2** (`gradle.properties:2`). Note the premise "1.63 was 1.2.0" is not what shipped: PR #78
prepared 1.2.0, but the release commit `92ec425` set `version=1.1.1` and tagged `v1.1.1` (no `v1.2.0` tag
exists). So 1.1.2 is the right patch from the current release; see C164-22 for the CHANGELOG this left behind.
Issue ilpanich/axiam-kotlin-sdk#79 and the PR/CI could not be read here (no GitHub access); the item list is plan §8.2's Kotlin row.

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | **Mostly conforms.** A `429` whose OAuth body has `error == "rate_limit_exceeded"` becomes an `OAuthProtocolError` carrying `Retry-After` (delta-seconds or HTTP-date; null if missing or invalid). `deviceLogin` treats it as non-terminal and waits `max(interval, ceil(Retry-After))` as that one interval. The interval is not raised. If the wait reaches the remaining time, the loop raises the local `expired_token` at once, before sleeping or sending. A single `devicePoll` raises the `OAuthProtocolError`. No §16 layer wraps the poll, so nothing waits twice or swallows it. The server's exact body `{"error":"rate_limit_exceeded"}` (no `error_description`, with or without `retry_after`) works (probes P5, P6, P8). `500 {"error":"server_error"}` mid-poll still maps to `NetworkError` and is not terminal (P7). **Defect:** a `429` whose body says `slow_down` raises the interval (C164-04). Also, a bodiless `429` ignores `Retry-After` (C164-17), and the deadline is a counter, not the clock (C164-05). | `oidc/OidcSupport.kt:1138-1188`, `:1979-1987`; `errors/ErrorMapper.kt:95-106`; `errors/OAuthProtocolError.kt:42`; `oidc/OidcTypes.kt:727` |
| 2 | (b) §14.6 test | **Conforms, not vacuous.** The mock sends `429` with `Retry-After: 30`, then pending, then 200. The recorded clock shows `[5, 30, 5]`, three polls and the token set. The deadline case (`expires_in` 20, `Retry-After` 3600) gives typed `expired_token`, one poll, `[5]`. Extra tests: a short `Retry-After`, `slow_down` after a `429`, and a single `devicePoll`. The wording follows §14.6 ("waited out", "polls again", "interval is unchanged", "sends nothing after it"). Mutants M1–M3 are each caught. The mock adds an `error_description`; the code works without one (P5). | `test/.../oidc/OidcDeviceFlowTest.kt:202-299` |
| 3 | C163-07 | **Done.** `unknownCarried` returns `ValidationError(msg, listOf(FieldError(member, msg)))`. `ValidationError` is a `NetworkError` subtype (`errors/ManagementErrors.kt:69-72`), so it breaks neither source nor `catch`. It changes behaviour only in that `is ValidationError` is now true, which was the 1.1.0 type. The tests assert `ValidationError` and `fields`. Mutant M5 is caught. | `management/ManifestApi.kt:581-587`; `ManifestNetworkTest.kt:388-410` |
| 4 | C163-09 | **Done.** A stated `serviceType` (FRAMED_USER) gives `UPDATE`, and the PUT carries `framed_user`. A stated `null` omits the key. Mutant M7 (refuse even when stated) is caught. | `ManifestNetworkTest.kt:429-452` |
| 5 | C163-10 (D-15) | **Done.** `RAW_TIMESTAMPS` is generalised to `RAW_STRINGS` (a list per model) and `keepRawTimestamps` to `keepRawStrings`. The generator's `RAW_VALUE_MEMBERS` emits trailing `serviceTypeRaw`/`terminationActionRaw: String? = null`, applied to list items too (via `decodeList`→`decode`). The refusal quotes the value, truncated at 64 chars. Generator `--check` passes, and a test pins generator/decoder agreement. Quoting does not escape the value (C164-21). | `management/ManagementSupport.kt:158-191`; `scripts/gen_management.py:818-834`, `:889-898`; `models/NetworkReplyProfile.kt:63-64`; `Contract164ModelsTest.kt` |
| 6 | C163-18 | **Done.** README `:121-123` now says `toInput()` carries `updatedAtRaw`. README `:119-120` ("every local refusal … is a ValidationError") is true again. The CHANGELOG label is fixed to "contract 1.62 item (ab), §34.6", and so is the test comment. | `README.md:119-123`; `CHANGELOG.md:110-111`; `ManifestNetworkTest.kt:374` |
| 7 | C163-19 | **Code done; test vacuous for the new wiring.** `oidcDiscover` registers every advertised endpoint plus the `mtls_endpoint_aliases`. `isOauth2Request` matches the base `/oauth2/` prefix or an exact scheme+host+port+path. The integration half of the test only exercises `deviceAuthorize`/`devicePoll`, which already carry `withoutSession = true` (`OidcSupport.kt:1027`, `:1079`). The unit half registers endpoints by hand. Mutant M4 (drop `.also(::registerAdvertisedEndpoints)`) **survives** (C164-13). | `oidc/OidcSupport.kt:159-180`; `internal/SessionState.kt:117-144`; `internal/AuthHeaderInterceptor.kt:50`; `Oauth2NoSessionCredentialTest.kt:214-268` |
| 8 | Version & docs | **Consistent at 1.1.2:** `gradle.properties:2`, README Gradle/Maven snippets `:242`, `:254`, `openapi.json` info.version 1.1.2. No version constant exists in the source. The CHANGELOG `[1.1.2] - 2026-10-23` names 1.64, `fb92ec4`, (b), C163-07/09/10/18/19 and #79. `CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/` are byte-identical to `fb92ec4`. Patch is right: the only model change is two trailing defaulted members, the repo's convention for `updatedAtRaw`. (They do change the JVM constructor/`copy` signature of a response-only data class; that is binary, not source.) The `[1.2.0]` heading below `[1.1.1]` is a version that never shipped (C164-22). | `gradle.properties:2`; `README.md:34`, `:242`, `:254`; `CHANGELOG.md:10-72`, `:74-88` |
| 9 | 1.63 regression | **None found.** The cookie/CSRF/bearer isolation on `/oauth2/*` still holds; it is now a superset (base prefix OR discovered endpoint). The 1.62/1.63 §14.6 tests pass. The poll path keeps `withoutSession = true`. The §27.6.2 refusal still happens at `plan`, with no non-GET request (asserted). | `AuthHeaderInterceptor.kt:50-79`; `Oauth2NoSessionCredentialTest.kt`; `ManifestNetworkTest.kt:390-392` |
| 10 | Other | The CIBA loop (comparison only, outside this PR) waits only the interval on `429 rate_limit_exceeded`, ignoring `Retry-After`. Like the device loop, it would also treat a `429 slow_down` as `slow_down`. Neither is in the issue's scope. | `oidc/OidcSupport.kt:1400-1408` |

**Run by the reviewer** (throwaway copy `/home/user/work/kotlin`; JDK 21; the Gradle 8.10.2 wrapper downloaded; Maven Central worked after one `429 Too Many Requests` retry):
- `python3 scripts/gen_management.py --check` → `OK: 251 generated files are current (202 operations)`.
- `bash scripts/tls-bypass-gate.sh` → exit 0.
- `./gradlew test --no-daemon --console=plain` → **BUILD SUCCESSFUL, 1289 tests, 0 failures, 0 errors, 0 skipped.** (A first run timed out while compiling, and a second hit the Maven Central 429; the third passed.) `koverVerify`/`dokka`/lint were not run.
- Mutants (each against its test class):
  - M1 (429 terminal): 4 tests fail.
  - M2 (interval += 5 on a 429): 2 fail.
  - M3 (ignore `Retry-After`): 3 fail.
  - M5 (`unknownCarried` returns a bare `NetworkError`): 2 fail.
  - M7 (refuse a stated `service_type`): 1 fails.
  - **M4 (discovery does not register the endpoints): all of `Oauth2NoSessionCredentialTest` pass.**
- Probes (`ReviewerProbeTest`, removed afterwards). All recorded-clock sleeps at interval 5:
  - P1 `429 {"error":"slow_down"}`, `Retry-After: 1`, then 200 → `[5, 10]` (**FAIL**, expected `[5, 5]`).
  - P1b same, then a 429 rate_limit, then 200 → `[5, 10, 10]` (**FAIL**: the raise persists).
  - P2 HTTP-date `Retry-After` +40 s → waited about 40 s (pass).
  - P3 missing or garbage `Retry-After` → `[5, 5, 5]` (pass).
  - P4 bodiless `429`, `Retry-After: 30` → `[5, 5]` (`Retry-After` ignored).
  - P5 server-exact `{"error":"rate_limit_exceeded"}` → `[5, 30]` (pass).
  - P6 with `"retry_after":30` → `[5, 30]` (pass).
  - P7 `500 {"error":"server_error"}` → `[5, 5]`, completes (pass).
  - P8 single `devicePoll` with the exact body → `OAuthProtocolError("rate_limit_exceeded")`, `retryAfter` 7 s (pass).
- Build outputs deleted.

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):
- **C164-04 — Low.** `oidc/OidcSupport.kt:1979-1987` with `:1171-1174`.
  - **Rule:** §14.2 rule 9, "only the `400` raises the interval: an SDK MUST NOT read a `429` as the polling signal".
  - **What happens:** the new 429 branch returns `fromOAuth2ResponseAtAnyStatus` for any OAuth `error`. So a `429 {"error":"slow_down"}` (the pre-1.1.1 server's second bucket, or any proxy) reaches `deviceLogin`'s `slow_down` branch. The interval rises by 5 s permanently (probes P1/P1b). The same path would make a `429` carrying `expired_token`/`access_denied` terminal. Before this PR a 429 was a bare `NetworkError`, so this is a regression for that input.
  - **Fix:** in `mapOAuth2ErrorResponse`, map every 429 that carries an OAuth body as the rate-limit answer:
    ```kotlin
    if (response.code == 429) {
        val limited = ErrorMapper.fromOAuth2ResponseAtAnyStatus(fallbackMessage, response)
        if (limited is OAuthProtocolError) {
            val e = if (limited.error == "rate_limit_exceeded") limited
                    else OAuthProtocolError("rate_limit_exceeded", limited.errorDescription)
            e.retryAfter = ErrorMapper.retryAfterOf(response); return e
        }
    }
    ```
    Alternatively, keep the server's `error` and record an internal `httpStatus = 429` that `deviceLogin` checks before dispatching on `error`.
  - **Test:** in `OidcDeviceFlowTest`, mock `429 {"error":"slow_down"}` with `Retry-After: 1`, then 200, and assert the sleeps are `[5L, 5L]`.
- **C164-05 — Low (predates this PR, now on the (b) path).** `oidc/OidcSupport.kt:1132-1155`.
  - **Rule:** §14.2 rule 4 / rule 9 ("capped at the `expires_in` deadline … nothing sent after it").
  - **What happens:** the deadline is `remainingSeconds`, a counter decremented only by the waits. The time spent in `deviceAuthorize`, in each poll round-trip and in OkHttp timeouts is never subtracted, so slow responses let polls go out after the real deadline.
  - **Fix:** take `val deadline = clock.now().plusSeconds(authorization.expiresIn.toLong())` right after `deviceAuthorize` returns, as `cibaAwait` does at `:1378-1385`. Replace the check with `if (!clock.now().plusSeconds(waitSeconds).isBefore(deadline)) throw expired_token`, and drop `remainingSeconds`.
  - **Test:** a `RecordingClock` whose `now()` also advances by a fixed "request time" per poll (e.g. 4 s). With `expires_in = 20`, interval 5 and always-pending, assert that no poll is sent once `now() + 5 ≥ deadline` (2 polls, not 3).
- **C164-17 — Informational.** `oidc/OidcSupport.kt:1979-1987`, `:1185-1188`.
  - **Rule:** §16.1 (`Retry-After` is a floor) for a 429 that is not the §14.2 rule 9 body.
  - **What happens:** a bodiless or non-OAuth `429` (e.g. a proxy) becomes a `NetworkError`. The loop then polls again at the plain interval and ignores its `Retry-After` (P4). AXIAM always sends the OAuth body, so this does not trigger against the platform.
  - **Fix:** in the 429 branch, when no OAuth body parses, still return `OAuthProtocolError("rate_limit_exceeded", "")` with `retryAfter` set (or have `deviceLogin` read `NetworkError.retryAfter`, filling it in `ErrorMapper.fromHttpStatus` for a 429).
  - **Test:** a bodiless `429` with `Retry-After: 30`, then 200 → `[5, 30]`.
- **C164-22 — Informational (release history).** `CHANGELOG.md:74-88`.
  - **Rule:** the repository's Keep-a-Changelog convention.
  - **What happens:** `## [1.2.0] - 2026-10-20` sits below `## [1.1.1] - 2026-10-21`, but 1.2.0 was never released. The 1.63 content shipped as 1.1.1 (tag `v1.1.1`, `92ec425`), including the source-breaking `ScimTargetInput.expectedUpdatedAt` change, so the history reads as if 1.2.0 preceded 1.1.1. The new entry's "the 1.2.0 entry below" (`:54`) perpetuates it.
  - **Fix:** retitle `:88` to `### Contract 1.63 notes (prepared as 1.2.0, released as 1.1.1)` under `[1.1.1]`, folding the auto-generated bullets at `:76-86` into it. Add one line that 1.1.1 contains the source-breaking SCIM change despite its patch number. Change `:54` to "the 1.1.1 entry below".
- **C164-21 — Informational.** `management/ManifestApi.kt:582`.
  - **What happens:** the raw server value is quoted with `"…"` but not escaped. A value containing `"`, newlines or control characters lands verbatim in the exception message and the log.
  - **Fix:** `Json.encodeToString(String.serializer(), raw.take(MAX_QUOTED_VALUE))` (JSON-escapes and quotes), replacing the hand-written quotes.
  - **Test:** in `ManifestNetworkTest`, an unknown `termination_action` of `"a\"b\nc"`; assert the message contains `"a\"b\nc"` escaped and no raw newline.
- **C164-13 — Low (incomplete test).** `test/.../oidc/Oauth2NoSessionCredentialTest.kt:214-268`.
  - **Rule:** plan §8.2 C163-19, "the `/oauth2` exclusion follows the discovered endpoints".
  - **What happens:** the integration half uses only the device operations, which are credential-free by `withoutSession = true` whatever discovery says. The unit half calls `registerOauth2Endpoints` by hand. Nothing fails if `oidcDiscover` stops registering (mutant M4 survives).
  - **Fix:** in the relocated-discovery test, also relocate `revocation_endpoint` (or `token_endpoint`, via `oidcRefresh`/`loginClientCredentials`, which do not set `withoutSession`). After `client.login(...)`, call that operation through the client. Assert its request on `/idp/...` has no `Authorization`, `Cookie` or `X-CSRF-Token`, then make a control management `POST` that carries both.

Summary: (b) is implemented and tested well (1289/1289 green; mutants caught), and works with AXIAM's exact 429 body and a 500 `server_error`. One Low defect: a 429 whose body says `slow_down` raises the interval. All five issue items are done; the C163-19 test is vacuous for the discovery wiring (mutant survives). 1.1.2 is consistent everywhere; the CHANGELOG keeps a phantom `[1.2.0]` heading.

---

### Report — php — commit 3707a5dac (PR #87)

Version 1.1.1 → 1.1.2 (tag-released; `## [1.1.2] - Unreleased` over `## [1.1.1] - Unreleased`, the maintainer's convention per plan §0; tag `v1.1.1` is in `origin/main`). Issue ilpanich/axiam-php-sdk#86. No GitHub access here: the issue, PR and CI were not read; the item list is plan §8.2's PHP row.

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | Conforms on the 1.64 rule. `deviceLogin()` treats `rate_limit_exceeded` as non-terminal. The next round waits `max(interval, ceil(Retry-After))`, which takes the place of that round's interval. The interval is not raised. The deadline check runs before the sleep: it raises `expired_token` at once and sends nothing after the deadline. Missing Retry-After falls back to the interval, and an HTTP-date is honoured (probed). The device poll has no §16 retry layer (`postForm`), so the 429 is not waited twice or swallowed. A single `devicePoll()` raises `OAuthProtocolError` with `retryAfterMs`. The server's exact bodies `{"error":"rate_limit_exceeded"}` and `{…,"retry_after":12}`, with no `error_description`, map to `OAuthProtocolError` and are waited out (probed: slept `[5,12]`). **Defects next to the rule:** a `5xx` with an OAuth body is terminal (C164-03, pre-existing); a `429 slow_down` raises the interval (C164-04); a malformed `Retry-After` can end the flow (C164-09); a body-less 429 ignores `Retry-After` (C164-17). | `src/Oidc/OidcClient.php:891-946` (429 branch `:931-936`, deadline `:904-912`); `src/Core/ErrorMapper.php:88-102`; `src/Core/OAuthProtocolError.php:30-36`; `src/Core/NetworkError.php:103-125` |
| 2 | (b) §14.6 test | Present, worded after the contract paragraph, and not vacuous. `testRateLimitedPollIsWaitedOutAndTheIntervalIsUnchanged` records sleeps `[5,5,17,5]` and checks completion. `…OnlyAMinimum…` checks `[5,5]`. `testRetryAfterPastTheDeadlineIsCappedAndNothingIsSentAfterIt` checks `expired_token` and 2 requests. `testASingleDevicePollStillRaisesTheRateLimitError` checks the single poll. The mocks use the server's exact body. Minor: case 1 puts an `authorization_pending` between the 429 and the 200. Mutants M1, M2, M3 and M5 are killed. M4 survives (sleep the uncapped Retry-After, then raise), because case 2 records no sleep (C164-19). | `tests/OidcDeviceFlowTest.php:282-371` |
| 3 | C163-08 | Done as asked. A fifth queued response and `management()->groups()->create(...)`. `history[4]` is `/api/v1/groups`, its `Cookie` contains `axiam_access=` and it carries `X-CSRF-Token: csrf-from-login`. The control comes after the `/oauth2/*` calls. Mutant M9 (strip on every path) is killed. | `tests/Contract163/OAuth2NoSessionCredentialsTest.php:43-48`, `:81`, `:93-98` |
| 4 | C163-09 | Done. Data provider `unknownProfileMembers` (`termination_action`/`future`, `service_type`/`login`) drives refuse at `plan` with no write, `apply` with no write, the stated member as a PUT carrying the stated wire value, and `NoChange`. Mutant M12 (refusal checks `termination_action` only) is killed (2 failures). | `tests/Contract163/OpenEnumRefusalTest.php:111-205` |
| 5 | C163-10 (D-15) | Done in the generator. `emit_class` adds a private `$unknownEnumValues`, filled in `fromArray()` when a member decodes to `Unknown`, and a public `unknownEnumValue()`. The array is never rendered by `toArray()`/`jsonSerialize()` and is not a constructor parameter. `NetworkReconciler` copies it into a side key the PUT builder never reads. The refusal quotes it as `"future"`, or says `(value unknown)`. `gen_management.py --check` is clean (261 files). Mutants killed: the hand-removed recording in `NetworkReplyProfile.php` (test fails, and `--check` flags the drift); M11 (no quotes). The value is quoted without escaping (C164-21). | `scripts/gen_management.py:1103-1120`, `:1172`, `:1189-1213`; `src/Management/Models/NetworkReplyProfile.php:17-25`, `:71-112`; `src/Management/Manifest/NetworkReconciler.php:38-40`, `:122-137`; `src/Management/Manifest/ManifestApi.php:222-236` |
| 6 | C163-18 | The code is fixed. The `$authzStack` order is swapped (Refresh pushed first, so it runs outside Auth), and the replay rebuilds `Cookie` from the jar. The two middleware comments now give the stack order correctly, which matches Guzzle's `HandlerStack::resolve`. The CHANGELOG `toArray()` line is present. **The test does not test the shipped wiring:** `RetriedRequestHeadersTest` builds its own stack in the fixed order. Reverting the order in `AxiamClient` (M6) leaves the whole suite green, 2032/2032 (C164-10). M7 (no cookie rebuild) is killed. | `src/AxiamClient.php:465-473`; `src/Rest/RefreshMiddleware.php:19-28`, `:73-79`; `src/Rest/AuthMiddleware.php:17-24`, `:126-135`; `tests/Contract164/RetriedRequestHeadersTest.php:84-86`; `CHANGELOG.md:49-52` |
| 7 | C163-19 | Done: the match is now `str_starts_with($path, rtrim(basePath,'/') . '/oauth2/')`. Tested over 5 rows. M8 (bare `/oauth2/`) is killed. Posture: under a prefixed base, a root `/oauth2/*` URL (from discovery) no longer matches, and the test pins that (C164-24). | `src/Rest/AuthMiddleware.php:83-86`, `:114`; `tests/Contract164/BasePathPrefixOAuth2Test.php:24-32` |
| 8 | Version & docs | Correct for a patch. `composer.json` has no version field, there is no version constant in source and no committed lockfile (a library). The CHANGELOG entry names 1.64, `fb92ec4`, (b), #86 and every item, and is placed per the repository's convention. The README says contract 1.64 and has a 1.64 table. The vendored `CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/` are byte-identical to `fb92ec4` (cmp). The additions are backward compatible: a trailing optional constructor parameter on a `final` class, and a new method on `final` models. Gaps: `NetworkError::parseRetryAfterMs` was made public without being listed (C164-22); the install snippets still read `^1.1.0` (C164-22). | `CHANGELOG.md:10-67`; `README.md:27`, `:220`, `:284-296`, `:455` |
| 9 | 1.63 regression | None found. `/oauth2/*` requests still carry no `Cookie`, `X-CSRF-Token` or `Authorization`. The swapped order keeps Auth inside Refresh, so the replay of an `/oauth2/*` request is stripped again. §6.1 rule 11: `canRefresh()` still guards the replay. §27.6.2: the refusal is still at `plan`, before any write, and the side key is never sent. | `src/Rest/AuthMiddleware.php:114-141`; `src/Rest/RefreshMiddleware.php:65-67`; `src/Management/Manifest/ManifestApi.php:265-267`; `NetworkReconciler.php:239-259` (explicit members only) |
| 10 | Other | The replay forces the session jar even if a request's `cookies` option differs; no current caller does that (C164-23). Pre-existing: the device deadline is counted in slept seconds, not wall-clock time (C164-05). | `src/Rest/RefreshMiddleware.php:76-78`; `src/Oidc/OidcClient.php:892`, `:910` |

**Run by the reviewer** (throwaway copy `/home/user/work/php`; PHP 8.3.6, Composer 2.8.12):
- `composer validate --strict`: valid.
- `composer install --no-interaction --prefer-dist` did not complete. The proxy times out on, or refuses (403), `api.github.com` zipballs. Every package fell back to a git clone except `phpstan/phpstan`, which has no usable source path. Workaround: I cloned `github.com/phpstan/phpstan` at `6155239` (2.3.1, the version the resolver locked) and added it as a Composer `path` repository in the copy, then ran `composer update --prefer-source`, which succeeded. Versions were resolved fresh, because the SDK commits no lockfile.
- `vendor/bin/phpunit`: **OK, 2032 tests, 9874 assertions**, 0 skipped.
- `vendor/bin/phpstan analyse --memory-limit=512M`: **No errors**. The CI step for the §27 examples (`--level=6` over the 5 examples): **No errors**.
- `php tools/docblock-coverage.php`: 2083/2083 documented.
- `python3 scripts/gen_management.py --check`: "§27 surface is current (261 files)".
- Mutants (each reverted afterwards):
  - Killed: M1 (429 terminal), M2 (+5 s on 429), M3 (ignore Retry-After), M5 (`min` in place of `max`), M7 (no cookie rebuild), M8 (bare `/oauth2/`), M9 (strip on all paths), M11 (unquoted value), M12 (refusal skips `service_type`), and the hand-removed `unknownEnumValues` recording (test fails, and `--check` fails).
  - **Survived:** M4 (sleep the uncapped Retry-After, then raise `expired_token`). **M6 (stack order reverted in `AxiamClient`): the full suite stays green.**
- Probes of `deviceLogin()` (interval 5, expires 600 unless noted):
  - `429 {"error":"rate_limit_exceeded","retry_after":12}` + `Retry-After: 12`: slept `[5,12]`, completes.
  - **`500 {"error":"server_error"}`: terminal `OAuthProtocolError(server_error)`** after one poll. `503 {"error":"temporarily_unavailable"}`: terminal as well.
  - **`429 {"error":"slow_down"}`: slept `[5,10,10]`** (interval raised).
  - **`Retry-After: 17.0`: `expired_token` at once** (`strtotime` reads it as a time of day, about 7 h ahead).
  - Body-less `429` + `Retry-After: 12`: slept `[5,5]`.
  - HTTP-date +20 s: `[5,20]`. No `Retry-After`: `[5,5]`.
  - Expires 30, `Retry-After: 25`: `expired_token`, 2 requests.
- Not run: the gRPC codegen job (needs protoc from GitHub releases) and `composer audit`. Build outputs deleted (`vendor/`, the phpstan clone).

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):
- **C164-03 — Medium (pre-existing; not introduced by this PR).** `src/Oidc/OidcClient.php:2525-2537` and `:2800-2808`, through `ErrorMapper::fromOAuth2Response` (`src/Core/ErrorMapper.php:88-102`). This breaks §14.2 rule 6 ("`5xx` … remain `NetworkError` and are not terminal"). AXIAM answers `500 {"error":"server_error"}` on a datastore failure at `/oauth2/token`. The device poll maps any status with an `error` body to `OAuthProtocolError`, and `deviceLogin()` (`:938-939`) treats every code other than pending, slow_down and rate_limit_exceeded as terminal. So one server error ends a flow the user may already have approved. The existing §14.6 "500 mid-poll" test uses a body-less `500` (`tests/OidcDeviceFlowTest.php:415`), so it misses this. **Fix:** in `devicePoll()`, map a `5xx` to `NetworkError` whatever its body, as `cibaPollTracked` does (`:2127-2132`). Send the poll with `'http_errors' => false`; if `$status >= 500`, throw `NetworkError::fromResponse($response, 'device poll failed')`; for any other non-2xx, throw `ErrorMapper::fromOAuth2Response($response, …)`. **Test:** queue `500 {"error":"server_error"}`, then the tokens; assert completion and sleeps `[i, i]`. Add the same for `503 {"error":"temporarily_unavailable"}`.
- **C164-04 — Low.** `src/Oidc/OidcClient.php:926-929`. This breaks §14.2 rule 9 ("only the `400` raises the interval: an SDK MUST NOT read a `429` as the polling signal"). A `429` whose body says `slow_down` adds 5 s permanently (probe: `[5,10,10]`), because `OAuthProtocolError` does not carry the status. **Fix:** add a trailing `public readonly ?int $httpStatus = null` to `OAuthProtocolError` and set it in `fromOAuth2Response`. In `deviceLogin()`, test `$e->httpStatus === 429` **before** the error-code dispatch, and handle any 429 as the rate-limit wait; raise the interval only for `slow_down` with a status other than 429. **Test:** `429 {"error":"slow_down"}` + `Retry-After: 1`, then pending, then tokens; assert sleeps `[5,5,5]`.
- **C164-09 — Low.** `src/Core/NetworkError.php:116-125`. This breaks §14.2 rule 9 / §33.7 rule 5 (Retry-After is a *minimum*, capped at the deadline; a malformed value must not end the flow). `strtotime()` accepts non-HTTP-dates: `"17.0"` reads as about +7 h and `"1.5"` as negative. Since this PR the device loop honours the value, so a malformed header makes `deviceLogin()` raise `expired_token` immediately (probe). **Fix:** accept only the RFC 9110 forms. Keep `ctype_digit` for delta-seconds. For a date, use `\DateTimeImmutable::createFromFormat('D, d M Y H:i:s \G\M\T', $header, new \DateTimeZone('UTC'))` and also accept the obsolete RFC 850 and asctime formats. Anything else returns `null`. **Test:** `Retry-After: 17.0` on a poll gives sleeps `[5,5]` and completion.
- **C164-10 — Low.** `tests/Contract164/RetriedRequestHeadersTest.php:84-86`. This leaves the C163-18 test incomplete (plan §8.2: "a test that a retried request gets fresh headers"). The test pushes its own `RefreshMiddleware`/`AuthMiddleware` in the fixed order, so reverting the real order at `src/AxiamClient.php:472-473` leaves all 2032 tests green (M6). **Fix:** drive the test through an `AxiamClient` built on the mock `transportHandler`. Log in (cookies `axiam_access`/`axiam_refresh`/`axiam_csrf`), queue a `401` on a management or authz POST, then the refresh `200` with rotated cookies and CSRF, then a `200`. Assert that the replay carries the new `Authorization`, `X-CSRF-Token` and `Cookie`. Alternatively, assert the order of `$authzStack` through reflection: `(string) $stack` lists the names.
- **C164-19 — Informational.** `tests/OidcDeviceFlowTest.php:334-356`. Case 2 of the §14.6 1.64 test records no sleeps, so it passes when the loop sleeps the uncapped 3600 s and then raises (M4 survives). **Fix:** record the sleeps and assert `self::assertSame([5], $slept)` (or `array_sum($slept) <= 30`).
- **C164-24 — Informational.** `src/Rest/AuthMiddleware.php:86`, `:114`; `tests/Contract164/BasePathPrefixOAuth2Test.php:31`. This weakens the defence-in-depth of §6.1 rule 11 / §12.1 rule 3. With a prefixed base (`https://gw/axiam`), a root `https://gw/oauth2/token` taken from discovery no longer matches: before this PR it did. It would now carry the bearer, the session cookie and the CSRF token. The new test row pins that. **Fix:** `$path = $request->getUri()->getPath(); $isOAuth2Path = str_starts_with($path, $oauth2Prefix) || str_starts_with($path, '/oauth2/');`. Change the test row `'oauth2 outside the prefix is not one'` to expect `true`, renamed to "a root /oauth2/ under a prefixed base is still stripped".
- **C164-17 — Informational.** `src/Oidc/OidcClient.php:940-944`. A body-less `429` (a proxy's) becomes a `NetworkError` whose `retryAfterMs` the loop ignores (probe: `[5,5]` for `Retry-After: 12`). **Fix:** in the `NetworkError` branch, `if ($e->retryAfterMs !== null) { $waitSeconds = max($intervalSeconds, (int) ceil($e->retryAfterMs / 1000.0)); }` before `continue`. Test: body-less 429 + `Retry-After: 12` gives `[5,12]`.
- **C164-21 — Informational.** `src/Management/Manifest/ManifestApi.php:233`. The raw value comes from the server and is placed in the message unescaped, so quotes, newlines or control characters reach logs (Go uses `%q`). **Fix:** `\is_string($raw) ? (string) json_encode($raw, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : '(value unknown)'`. Keep the test's `'"' . $raw . '"'` assertion, which still holds for plain values.
- **C164-22 — Informational.** `src/Core/NetworkError.php:103`. `parseRetryAfterMs` went from `private` to `public static` on a non-final public class, which is a third public addition the CHANGELOG (`:16-18`) does not list. **Fix:** tag it `@internal` in its docblock and add it to the CHANGELOG's list of additions. Alternatively, move the call into a static on `ErrorMapper` and keep the method private.
- **C164-22 — Informational.** `README.md:27`, `:455`. The install snippets still read `composer require "axiam/axiam-sdk:^1.1.0"`. **Fix:** change both to `^1.1.2`, the first release with the 1.64 loop.
- **C164-23 — Informational.** `src/Rest/RefreshMiddleware.php:76-78`. The replay always rebuilds `Cookie` from the session jar, even when the request's `cookies` option was `false` or another jar. No `$authzHttp` caller passes either today; the two that do use `$plainHttp`. **Fix:** `$jar = $options['cookies'] ?? null; $replay = $request->withoutHeader('Cookie'); if ($jar instanceof \GuzzleHttp\Cookie\CookieJarInterface) { $replay = $jar->withCookieHeader($replay); }`.
- **C164-05 — Informational (pre-existing).** `src/Oidc/OidcClient.php:892`, `:910`. The §14.2 rule 4 deadline is tracked as `expires_in` minus the seconds slept, so request time (and transport timeouts on a failing server) is not counted, and real polls can run past `authorization time + expires_in`. **Fix:** take `$deadline = microtime(true) + $authorization->expiresIn` when the authorization returns, and before each sleep compare `microtime(true) + $roundSeconds >= $deadline`. Tests keep the injectable sleep, plus an injectable clock (`?callable $now = null`) so the fake time advances with the sleeps.

---

### Report — swift — commit 3180f7133 (PR #78)

Version 1.1.1 → 1.1.2 (patch). Issue ilpanich/axiam-swift-sdk#77. Review by reading only: no Swift
toolchain could be installed (see "Run by the reviewer"). No GitHub access, so the issue text, the PR
and CI were not read. The item list comes from plan §8.2.

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (b) code | **Conforms.** `devicePollOnce` sends one poll. A non-2xx goes through `oidcMapGrantError`, which dispatches on `error` (rule 5). `rate_limit_exceeded` is wrapped in the internal `DevicePollRateLimited` with `Retry.retryAfter(header)`. That parser handles delta-seconds and HTTP-date, clamps to 3600, and returns `nil` for missing, unparseable or past values. In `deviceLogin`, a 429 is not terminal and never reaches the `slow_down` branch. The next wait is `max(interval, retryAfter)`: Retry-After acts as a floor, a longer interval still wins, and the wait fills one slot. `retryAfter` is reset each turn and `interval` is never touched. The check `now + wait < deadline` runs before the sleep and throws a typed `AuthError(oauthError: "expired_token")` at once, so nothing is sent past `expires_in`. The wait now goes through the actor's `_sleep` seam, whose default is `Task.sleep(max(s,0)·1e9)`, the same as the old inline sleep. The deadline is still wall-clock `Date()` from when the loop starts. Single `devicePoll` unwraps and rethrows the plain `AuthError` with `rate_limit_exceeded`. Apart from that branch, the mapping is the same as the old `oidcTokenGrant` path. **No §16 double-wait:** the poll goes out through `oidcFormPost` → `umaSendAbsolute`, which has no retry wrapper. CIBA, for comparison: `cibaStep` treats `rate_limit_exceeded` as transient and waits only the interval, ignoring Retry-After. That is outside (b). | `Sources/AxiamSDK/Oidc/DeviceGrant.swift:21-31`, `:121-134`, `:137-168`, `:200-229`; `Retry.swift:75-94`; `AxiamClient.swift:85-87`, `:1159-1171`; `Oidc/OidcInternals.swift:180-195`, `:393-403`; `Oidc/Ciba.swift:524-549`, `:618-633` |
| 2 | (b) §14.6 test | **Present and non-vacuous (by reading).** The sleeps are recorded through `_setRetryTestSeams`, never taken. Four cases: (1) `429 + Retry-After: 7`, then pending, then 200 at interval 1: three polls, sleeps exactly `[1,7,1]`, tokens returned. The trailing `1` proves the interval was not raised. (2) Interval 9, `Retry-After 7`: `[9,9]`, so Retry-After is a floor and the interval is unchanged. This is the contract's literal 429→200 case. (3) `Retry-After: 3600` against `expires_in: 600`: typed `expired_token`, one poll, sleeps `[1]`, nothing sent after the deadline. (4) Single `devicePoll` still raises `rate_limit_exceeded`. The doc comment follows the §14.6 wording. Mutants, traced by hand because none could be run: 429 terminal → (1)(2)(3) fail; `+5 s` on 429 → (1) gives `[1,7,6]` and (2) gives `[9,14]`; Retry-After ignored → (1) gives `[1,1,1]` and (3) polls twice; Retry-After replacing the interval → (2) gives `[9,7]`; deadline check dropped → (3) records 3600 and polls again. Every mutant fails at least one case. The fixtures it uses (`TestRouter`, `TestResponse.jsonBody`, `TestServerState.increment/count`, `withClient`, `NSLock.locked`, `Sensitive.expose`) exist with matching signatures. | `Tests/AxiamSDKTests/Contract164DeviceGrantRateLimitTests.swift:99-163`; `Tests/AxiamSDKTests/Support/TestHTTPServer.swift:21-80`; `Support/TestKit.swift:52-71`, `:85-89` |
| 3 | C163-08 | **Done.** The login mock now also sets `Set-Cookie: axiam_csrf=csrf-cookie-1`. A new test signs in through `login()`, runs device_authorize, device_poll, introspect, revoke and client_credentials, and asserts none of `Authorization`, `Cookie` or `X-CSRF-Token` on `/oauth2/*`. It then calls `groups.create` and asserts the `Cookie` carries `axiam_access=…` and `axiam_csrf=…` and `X-CSRF-Token == "csrf-1"`. This matches `rawSend`/`credentialHeaders`, and the `Group`/`CreateGroupRequest` shapes match the mock. Non-vacuous: if management requests dropped the jar or the CSRF echo, the control fails. The 1.63 assertions are unchanged; the extra cookie only makes them stricter. Gap: the adopted-device-bearer run still has no control (C164-14). | `Tests/AxiamSDKTests/Contract162Oauth2NoSessionCredentialTests.swift:49-68`, `:131-145`, `:149-155`; `Sources/AxiamSDK/AxiamClient.swift:1097-1147` |
| 4 | C163-18 | **Done.** The SwiftPM `from: "1.1.2"` and CocoaPods `~> 1.1.2` snippets are current. | `README.md:166`, `:178` |
| 5 | Version & docs | **Conforms.** `AxiamSDK.podspec:3` is 1.1.2. Version comes from tags (`v1.1.1` is the last), and no source constant carries a version. Patch is right: no public signature changed, and the new type is internal. CHANGELOG `## [1.1.2] - 2026-10-23` follows the repo's Keep-a-Changelog convention and names 1.64, `fb92ec4`, (b), (c), C163-08, C163-18 and #77. README says "conforms to contract 1.64" and adds a fourth §14.2 polling bullet. Re-vendor is byte-identical to platform `fb92ec4` for `CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/`. Commits are SSH-signed (`%G?` cannot verify: no allowed-signers file here). | `CHANGELOG.md:10-39`; `README.md:15`, `:1095-1110`; `AxiamSDK.podspec:3` |
| 6 | 1.63 regression | **None.** The `/oauth2/*` poll path is still `oidcFormPost` → `umaSendAbsolute`, which sends no jar, CSRF or bearer. **C163-02 (fixed in PR #76) has not regressed:** `planNetwork` still refuses an unknown `termination_action`/`service_type` on an unstated member of a drifted profile before any write, naming the member and the wire value kept by `ProfileRead`. Its tests (plan and apply refuse, `service_type` alone, a stated value writes without "future", unchanged → no write) are untouched, and the diff does not touch `Sources/AxiamSDK/Management`. §6.1 rule 11 holds: `umaSendAbsolute` carries no `Authorization`. | `Management/ManagementManifestNetwork.swift:493-505`, `:520-536`, `:560-567`; `Tests/AxiamSDKTests/NetworkManifestTests.swift:481-560`; `AxiamClient.swift:1159-1171` |
| 7 | Other | No defect in the diff. Two observations: a body-less 429 on a poll, e.g. from a proxy (C164-17), and the contract's §34.8 (c) text, which puts Swift in the wrong group (C164-18). README has no "Contract 1.63/1.64" note block, but 1.1.1 did not add one either, so this follows the repo's convention. | — |

**Run by the reviewer:**
- Swift toolchain: `curl https://download.swift.org/swift-6.0.3-release/ubuntu2404/…/swift-6.0.3-RELEASE-ubuntu24.04.tar.gz` returned **403** from the proxy. `apt-get install swiftlang` (also after `apt-get update`) failed: **no such package** on Ubuntu 24.04. **Could not build or run `swift build` / `swift test`.** Everything above comes from reading the code. The mutants were traced by hand, not run.
- `python3 -I Scripts/gen_management.py --check` (in a throwaway copy): `§27 surface is current (3 files).` rc=0.
- CI's TLS-bypass grep over `Sources/`: no match. CI's private-key `git grep`: no match.
- Byte comparison of the vendored files against `git show fb92ec4:sdks/…` and `git archive fb92ec4 proto`: all identical.
- Throwaway copy `/home/user/work/swift` removed afterwards.

**Findings** (the reviewer's proposed severity is kept in the text; the binding severity is §4's):
- **C164-14 — Low** — `Tests/AxiamSDKTests/Contract162Oauth2NoSessionCredentialTests.swift:149-155`. Rule: §14.6, the paragraph "Contract 1.62, no session or adopted credential on `/oauth2/*`" ("As the control, the same client's next management request carries the adopted credential or the session"). The adopted-credential run (`authenticateDevice()`) has no control, so its absence assertion could pass if no bearer had been adopted. No defect is hidden: `credentialHeaders` sends the bearer. **Fix:** after `assertNoSessionCredential(transport)` in `testAnAdoptedDeviceBearerNeverReachesAnOauth2Endpoint`, add
  ```swift
  _ = try await client.groups.create(body: CreateGroupRequest(description: "", name: "ops"))
  let post = try XCTUnwrap(transport.requests.last { $0.path.hasSuffix("/api/v1/groups") })
  let auth = post.headers.first { $0.0.caseInsensitiveCompare("Authorization") == .orderedSame }?.1
  XCTAssertEqual(auth, "Bearer device-bearer-tok")
  ```
  The mock already answers `/api/v1/groups`.
- **C164-18 — Informational (contract text, platform repo; no SDK change)** — `/home/user/axiam/sdks/CONTRACT.md` §34.8 (c). The text lists Swift among the SDKs that "name the member and say the value is unknown". Swift keeps the wire text in `ProfileRead` and quotes it in the refusal (`ManagementManifestNetwork.swift:498-505`, `:520-536`, `:560-567`), which the relaxed wording allows. The SDK CHANGELOG (`CHANGELOG.md:28-31`) already says so. **Fix:** in §34.8 (c), move Swift from "C, C++, C#, Java, Kotlin, PHP and Swift name the member and say the value is unknown" to the "keep the text and name both" list. Then re-vendor at the next contract bump.
- **C164-17 — Informational** — `Sources/AxiamSDK/Oidc/DeviceGrant.swift:154-162`. Rule: §14.2 rule 9 (spirit), §16 (Retry-After as a floor). A `429` whose body is not an `OAuth2ErrorResponse`, e.g. a proxy's, maps through `oidcMapError` to a non-`.auth` error. `deviceLogin` then `continue`s at the plain interval and ignores `Retry-After`. It is not terminal and does not raise the interval, so only the floor is lost; the trigger is narrow. **Fix:** in `devicePollOnce`, replace the `if case let .auth…` test with one that also wraps any 429:
  ```swift
  let isRateLimited: Bool = { if case let .auth(a) = error { return a.oauthError == "rate_limit_exceeded" }; return false }()
  if isRateLimited || response.status == 429 { throw DevicePollRateLimited(error: error, retryAfter: Retry.retryAfter(response.firstHeader("retry-after"))) }
  ```
  `devicePoll` still rethrows `limited.error` unchanged. Add a case to `Contract164DeviceGrantRateLimitTests`: `(429, [("Retry-After","7")], <empty body>)` then success, at interval 1, asserting sleeps `[1,7]`.

**Added by the lead reviewer (read, not probed).** C164-03: `oidcMapGrantError` (`Sources/AxiamSDK/Oidc/OidcInternals.swift:393-402`) makes any non-2xx with a non-empty `error` an `.auth` error, so AXIAM's `500 {"error":"server_error",…}` reaches the `default:` arm of `deviceLogin`'s switch (`Oidc/DeviceGrant.swift:244-247`) and ends the flow; the rule-6 `continue` at `:231-235` is reached only for an error without an OAuth code. Pre-existing (`origin/main` maps the same way through `oidcTokenGrant`). C164-04: `devicePollOnce` wraps only `rate_limit_exceeded` (`:154-160`), so a `429 {"error":"slow_down"}` reaches `case "slow_down"` (`:240-243`) and raises the interval. Also: the comment at `:232-233` says the 5xx "already went through the §16 bounded retry inside the poll"; the report's row 1 found no retry wrapper on `oidcFormPost`. Correct the comment with the C164-03 fix.

---

## 4. Findings index

`path:line` is on the commit read (§1). The exact code and test fix for each SDK is the one in its §3
report under the same id. The fix column states it in a form that holds for every SDK the row names.

| ID | Severity | SDK | `path:line` | Rule | What | Fix |
|---|---|---|---|---|---|---|
| C164-01 | **Medium** | python | `src/axiam_sdk/_oidc.py:1162`; `_errors.py:303-307`; test `tests/test_device_flow.py:62-68` | §14.2 rule 9 (1.63 ¶ and the 1.64 ¶) | `_handle_token_response` maps with `description_optional=False`, so AXIAM's real 429 body, which has no `error_description`, is a `NetworkError`. `device_poll` raises the wrong type, and `device_login` re-polls at the interval, ignoring `Retry-After`. The (b) test passes only because its mock adds `error_description`. Probed: sleeps `[2,2]` for `Retry-After: 7`. | `raise error_from_oauth2_response(response.status_code, response, "token request failed", description_optional=response.status_code == 429)`. In the test, `_rate_limited` sends exactly `{"error":"rate_limit_exceeded"}` and a parametrised `{"error":"rate_limit_exceeded","retry_after":7}` (verified in a copy: 4 tests fail before the fix, 2124 pass after). |
| C164-02 | **Medium** | go | `oidc_wire.go:355`; `internal/jwks/verifier.go:103` | §12.1 rule 3, last ¶ (1.63) | Regression from the C163-16 fix. `jwks.NewVerifierForURL(ctx, jwksURI, c.httpc)` gives the JWKS fetch the client that holds the jar, so after `Login` every `GET /oauth2/jwks` carries `axiam_access` and `axiam_csrf` (probed). Plan §8.2's wording (`jwk.WithHTTPClient(c.httpc)`) asked for exactly this, and the jar went unnoticed. | Pass a jar-less copy that keeps the TLS, the client certificate and the timeout: `hc := *c.httpc; hc.Jar = nil; jwks.NewVerifierForURL(ctx, jwksURI, &hc)`. Test in `oidc_jwks_client_test.go`: a cookie `Login` against a mock that sets `axiam_access` and `axiam_csrf`, then an ID-token verification, then assert the JWKS GET carries no `Cookie`. Keep the C163-16 mTLS and timeout tests. |
| C164-03 | **Medium** | csharp (regression); rust, python, c, cplusplus, php, swift (pre-existing) | C# `Axiam.Sdk/AxiamClient.Oidc.cs:1307-1322`; Rust `src/oidc/device.rs:589-597`, `src/oidc/exchange.rs:347-358`; Python `src/axiam_sdk/_oidc.py:1679-1689`; C `src/oidc_device.c:319-344`, `src/oidc.c:489-511`; C++ `src/oidc.cpp:441-445`, `:1726-1757`; PHP `src/Oidc/OidcClient.php:2525-2537`, `:2800-2808`, `:938-939`; Swift `Sources/AxiamSDK/Oidc/OidcInternals.swift:393-402`, `Oidc/DeviceGrant.swift:244-247` | §14.2 rule 6 ("`5xx` … remain §2 `NetworkError` and are **not** terminal … must not lose a grant the user has already approved") | AXIAM answers a datastore fault at `/oauth2/token` with `500 {"error":"server_error","error_description":…}`. These seven read the body first, raise `OAuthProtocolError("server_error")`, and `device_login` treats the unknown code as terminal. In C#, `anyStatusErrors` (new in this PR) does it; in 1.1.1 only a 400 or 401 was parsed. Probed in Rust, C, C++ and PHP (PHP: a `503 temporarily_unavailable` too); read in C#, Python and Swift. TypeScript, Go, Java and Kotlin keep the 5xx a `NetworkError` (probed). | On the device poll, a `5xx` is the §2 `NetworkError` **whatever its body**: check the status before the `error` member, as each SDK's `ciba_poll` already does after §34.2 P8 (C# `AxiamClient.Ciba.cs:197-202`; PHP `cibaPollTracked` `:2127-2132`). Test in each SDK: the poll answers `500 {"error":"server_error","error_description":"db"}` (three times where §16 retries inside the poll), then the tokens; `device_login` completes and the interval is unchanged. Switch the existing rule-6 tests from an empty body to that body. |
| C164-04 | Low | rust, python, c, cplusplus, csharp, go, java, kotlin, php, swift | Rust `src/oidc/device.rs:243-249`; Python `_oidc.py:1680-1681`; C `src/oidc_device.c:325-330`; C++ `src/oidc.cpp:890-896`, `:1738-1743`; C# `AxiamClient.OidcDeviceExchangeLogout.cs:309-321`; Go `oidc_wire.go:277-289`, `oidc_device.go:318-320`; Java `ErrorMapper.java:186-192`, `AxiamClient.java:3508-3511`; Kotlin `oidc/OidcSupport.kt:1979-1987`, `:1171-1174`; PHP `src/Oidc/OidcClient.php:926-929`; Swift `Oidc/DeviceGrant.swift:154-160`, `:240-243` | §14.2 rule 9 ("only the `400` raises the interval: an SDK MUST NOT read a `429` as the polling signal") | The loop dispatches on the body's `error` alone. A `429 {"error":"slow_down"}`, as servers through 1.1.0 or an intermediary send it, raises the interval permanently: probed `[5,10,10]` and similar in Rust, C, C++, Go, Java, Kotlin and PHP; read in C#, Python and Swift. In Go a `429 {"error":"invalid_grant"}` is also terminal. **New in this PR** in Go, C#, Java and Kotlin, where every 429 was a `NetworkError` before. TypeScript is unaffected (probed). | Classify by status first: a `429` on a poll is the rule-9 wait whatever its `error` (map it to `rate_limit_exceeded`, or carry the HTTP status on `OAuthProtocolError` and test it before the code dispatch). `slow_down` raises the interval only on a `400`. Test: `429 {"error":"slow_down"}` with `Retry-After: 1`, then pending, then tokens; the recorded waits stay at the interval. |
| C164-05 | Low | typescript, rust, python, csharp, go, java, kotlin, php (pre-existing) | TS `src/node/oidc.ts:335-347`, `:1726-1741`; Rust `src/oidc/device.rs:170-226`, `:552-556`; Python `_oidc.py:343-358`; C# `AxiamClient.OidcDeviceExchangeLogout.cs:268-296`; Go `oidc_device.go:68-80`, `:273-276`; Java `AxiamClient.java:3470-3488`; Kotlin `oidc/OidcSupport.kt:1132-1155`; PHP `src/Oidc/OidcClient.php:892`, `:910` | §14.2 rule 4 (MUST NOT poll past the deadline); §14.6 1.64 case 2 ("sends nothing after the deadline") | The deadline is `expires_in` minus the waits slept. The request round-trips, the `on_user_code` callback and slow 5xx answers are never subtracted, so a slow or rate-limited server lets the loop poll after `authorization time + expires_in`. The server then answers `expired_token`, so no data is lost. | Take `deadline = now() + expires_in` from an injectable clock when `device_authorize` returns (the CIBA loop's pattern where the SDK has one). Before each wait, stop with the typed `expired_token` when `now() + wait >= deadline`. Keep the interval and `Retry-After` arithmetic as it is. Test: a fake clock that also advances a fixed request time per poll sends no poll at or after the deadline. |
| C164-06 | Low | typescript | `src/rest/bareTransport.ts:54`; `src/rest/clientRegistration.ts:310`, `:343`, `:372` | §12.1 rule 3, last ¶ (RFC 7592 operations; `credentials: "omit"`); C163-12 | C163-12 is not complete. The browser persona's RFC 7592 read, update and delete go out on the bare instance with the XHR adapter, so a same-origin app sends `axiam_*` on `/oauth2/register/<id>`. | In `bareRequest`, replace `...session.noCredentialsConfig()` with `...session.oauth2RequestConfig()` (identical under Node). Test in `test/rest/oauth2BrowserCredentials.test.ts`: a browser `createSession` client's `readClientRegistration` gets `adapter === 'fetch'` and `fetchOptions.credentials === 'omit'`; a Node case gets no adapter. |
| C164-07 | Low | rust | `src/client.rs:585-592`; `src/token/jwks.rs:1286-1290`; `src/ssf.rs:434`, `:675`; `src/oidc/registration.rs:307`, `:369`, `:399`; `CHANGELOG.md:51` | §12.1 rule 3, last ¶; C163-13, C163-17 | On wasm32 only `oauth2_post` got `fetch_credentials_omit()`. The `http_bare` JWKS GETs (the client's and SSF's), SSF discovery and RFC 7592 keep the browser default `same-origin`, and the browser follows redirects there. | A crate-internal `OmitBrowserCredentials` extension on `reqwest::RequestBuilder`: `fetch_credentials_omit()` under `cfg(target_arch = "wasm32")`, identity otherwise. Apply it at each site and in `oauth2_post`. Append "(native targets; in the browser build, redirects are the browser's)" to `CHANGELOG.md:51`. The wasm CI job's build is the check. |
| C164-08 | Low | c | `src/management_manifest.c:179-298`, `:645`, `:886-888`; `include/axiam/management_manifest.h:398-402`; `include/axiam/error.h:34` | plan §8.2 C row (C163-20: "`refuse()` sets `transport_cause` 400 like the builders") | Only the network-section refusals go through `refuse()`. The other `validate`/`plan` refusals (duplicate key, missing `resource_type`, dangling `depends_on`, cycle, role-binding checks, ambiguous service account) still report 0, although the new doc says 400. `oom()` reports an out-of-memory as a 400 "local refusal", and `error.h`'s "nothing was sent" is false after `plan`'s reads. | Replace `axiam_error_set(err, AXIAM_ERR_NETWORK, 0, msg)` at `:179`, `:188`, `:202`, `:215`, `:232`, `:254`, `:264`, `:278`, `:291`, `:298`, `:645` with `refuse(err, msg)`. Make `oom()` set cause 0 directly. In `error.h`, write "the error did not come from the server (no write was sent)". Test `err.transport_cause == 400` for a duplicate key and a dangling `depends_on`, on both `validate` and `plan`. |
| C164-09 | Low | php | `src/Core/NetworkError.php:116-125` | §14.2 rule 9; §33.7 rule 5 (`Retry-After` is a minimum, capped) | `strtotime()` accepts strings that are not HTTP-dates: `"17.0"` reads as about +7 h. Since (b) honours the value, a malformed `Retry-After` makes `deviceLogin()` raise `expired_token` at once (probed). | Accept only the RFC 9110 forms: `ctype_digit` delta-seconds, the IMF-fixdate through `\DateTimeImmutable::createFromFormat('D, d M Y H:i:s \G\M\T', …, UTC)`, and the RFC 850 and asctime forms; anything else returns `null`. Test: `Retry-After: 17.0` on a poll gives waits `[5,5]` and completion. |
| C164-10 | Low | php | `tests/Contract164/RetriedRequestHeadersTest.php:84-86`; `src/AxiamClient.php:472-473` | plan §8.2 PHP C163-18 ("a test that a retried request gets fresh headers") | The test builds its own middleware stack in the right order, so reverting the shipped order in `AxiamClient` leaves all 2032 tests green (mutant M6). | Drive the test through an `AxiamClient` built on the mock `transportHandler`: log in, queue a `401` on a management POST, the refresh `200` with rotated cookies and CSRF, then a `200`. Assert that the replay carries the new `Authorization`, `X-CSRF-Token` and `Cookie`. |
| C164-11 | Low | java | `src/test/…/AxiamClientDeviceFlowTest.java:185-234` | §14.6 1.64 test ("a fake clock or a recorded sleep, not a wall-clock sleep"; "scheduled at the interval the loop held before it") | The (b) test times real sleeps between 3.9 and 7 s. The "wait on top of the interval" and "sticky `Retry-After`" mutants pass, and case 2 would hang rather than fail if the cap were lost. | Give `deviceLogin` a package-private clock seam (`now()`, `sleep(Duration)`) as `cibaAwait` has; the public overload uses the system clock. Case 1 asserts `sleeps == [1, 2, 1]` and 5 requests. Case 2 asserts `expired_token`, 3 requests and `sleeps == [1]`. Mock the 429 with the server's exact body. This also carries C164-05's fix for Java. |
| C164-12 | Low | java, cplusplus | Java `NetworkManifestTest.java:438-472`; C++ `tests/test_manifest_network.cpp:760-770` | §27.9 network bullet; plan §8.2 C163-09 | Java's `NoChange` case reads a known value, so a refusal applied to `NoChange` survives (mutant); its `service_type` refusal is checked at `plan` only; and the "stated `service_type` resolves it" half is missing. C++'s `NoChange` case calls `plan`, which never writes, so the "GET only" assertion cannot fail, and it covers `termination_action` only. | Java: read `termination_action: "future"` with `ProfileSpec.of("lab", 3600)` matching, assert `NO_CHANGE` and 0 PUT/POST after `apply`, and repeat for `service_type`. Assert `ValidationError` from `apply` with `put.calls() == 0`. Add `withServiceType(FRAMED_USER)` → PUT body `service_type == "framed_user"`. C++: call `apply(manifest)`, assert `report.complete()` and only `GET`s, and repeat for `service_type: "future_type"`. |
| C164-13 | Low | kotlin | `src/test/…/oidc/Oauth2NoSessionCredentialTest.kt:214-268` | plan §8.2 Kotlin C163-19 ("the `/oauth2` exclusion follows the discovered endpoints") | The integration half uses only the device operations, which are credential-free by `withoutSession = true` whatever discovery says, and the unit half registers endpoints by hand. Dropping `.also(::registerAdvertisedEndpoints)` from `oidcDiscover` leaves every test green (mutant M4). | In the relocated-discovery test, relocate `token_endpoint` or `revocation_endpoint` to `/idp/…`. After `client.login(...)`, call `oidcRefresh`/`loginClientCredentials` or `revoke` through the client and assert no `Authorization`, `Cookie` or `X-CSRF-Token` on it. Then a management `POST` carries both. |
| C164-14 | Low | swift | `Tests/AxiamSDKTests/Contract162Oauth2NoSessionCredentialTests.swift:149-155` | §14.6, the 1.62/1.63 ¶ ("As the control, the same client's next management request carries the adopted credential") | The adopted-device-bearer run has no control, so its absence assertion would pass if no bearer had been adopted. The sign-in run (C163-08) now has one. | After `assertNoSessionCredential(transport)` in `testAnAdoptedDeviceBearerNeverReachesAnOauth2Endpoint`, call `client.groups.create(body: CreateGroupRequest(description: "", name: "ops"))` and assert that its `Authorization` is `"Bearer device-bearer-tok"`. |
| C164-15 | Low | python | `tests/test_device_flow.py:579-601`; `tests/test_no_session_cookie_on_oauth2.py:138-203` | §14.6 1.64 case 2 (async loop); plan §8.2 C163-14 | The async `device_login` has no deadline case and no missing-`Retry-After` case, and the six-operation C163-14 test covers the sync client only. The async code passes all of them (probed). | Add async twins: `Retry-After: 3600`, `expires_in=10` gives `expired_token`, `call_count == 1` and every wait ≤ 10; `_rate_limited(None)` gives `sleeps == [2, 2]`. Add an `@pytest.mark.asyncio` C163-14 test over the six operations on `AsyncAxiamClient` with the same assertions and control. |
| C164-16 | Low | contract | `sdks/CONTRACT.md:3198-3205` (§14.6 first ¶), `:3207-3218` (the 1.64 ¶), `:3097-3101` (§14.2 rule 6) | §34.2 P8's correction, not carried to §14 | "A `500` mid-poll is retried" names no body. P8 made §33.8 test 8 carry `{"error":"server_error"}` and §33.7 rule 5 say "whatever its body" for CIBA, and the device grant never got the same text. The 1.64 test also does not say the 429 mock is the server's own body. Together these are why C164-01 and C164-03 passed every suite. | §14.2 rule 6: append "— a `5xx` **whatever its body**: AXIAM's own token endpoint answers `500 {"error":"server_error"}` (contract 1.64 correction)". §14.6: "a `500` carrying `{"error":"server_error","error_description":…}` mid-poll is retried rather than treated as terminal". In the 1.64 ¶: "answers one poll with `429 {"error":"rate_limit_exceeded"}` (the server's body: no `error_description`)". Also "a `429` whose body says `slow_down` does not raise the interval" (C164-04). Timing: §5 Q1. |
| C164-17 | Info | swift, c, go, java, kotlin, php | Swift `Oidc/DeviceGrant.swift:154-162`; C `src/oidc_device.c:319-323`; Java `ErrorMapper.java:186-192` (§3 java row 10); Go `oidc_wire.go:291`, `oidc_device.go:338-341`; Kotlin `oidc/OidcSupport.kt:1979-1987`, `:1185-1188`; PHP `src/Oidc/OidcClient.php:940-944` | §14.2 rule 9 (spirit); §16.1 (`Retry-After` is a floor) | A bodiless or non-OAuth `429` (a proxy's) waits only the interval and ignores its `Retry-After`. AXIAM always sends the OAuth body, so this does not trigger against the platform. | Honour the `Retry-After` of any `429` on a poll as the floor of the next wait. This falls out of C164-04's status-first classification. Test: a bodiless `429` with `Retry-After: 7`, then tokens, gives waits `[interval, 7]`. |
| C164-18 | Info | contract | `sdks/CONTRACT.md` §34.8 (c) (`:13864`ff) | §34.8 (c) accuracy | "C, C++, C#, Java, Kotlin, PHP and Swift name the member and say the value is unknown." Swift has kept the wire text in `ProfileRead` and quoted it since its C163-02 fix (`Sources/AxiamSDK/Management/ManagementManifestNetwork.swift:493-536`; on `origin/main` since `b577eb1`). Under D-15, C++, C#, Java, Kotlin and PHP now keep it as well. Only C says the value is unknown. | Reword (c): "TypeScript, Python, Go, Rust and Swift keep the text and name both; C++, C#, Java, Kotlin and PHP keep it through an internal addition in 1.1.2 (D-15) and name both; C names the member and says the value is unknown." Timing: §5 Q1. |
| C164-19 | Info | typescript, cplusplus, java, php | TS `test/rest/oauth2BrowserCredentials.test.ts:38-40`, `src/rest/session.ts:309-321`; C++ `tests/test_oidc_grants.cpp:441-459`; Java `OauthNoSessionCredentialTest.java:163-166`; PHP `tests/OidcDeviceFlowTest.php:334-356` | test strength (§14.6) | TS: axios derives `credentials` from `withCredentials`, and `fetchOptions.credentials` is discarded, so the config assertion and the TSDoc name the wrong setting. C++: case 1 passes when §16 retries the named 429 inside the poll (M5); only the cap case catches it. Java: the C163-08 control does not assert `axiam_access`. PHP: case 2 records no sleeps, so an uncapped 3600 s sleep survives (M4). | TS: reword the TSDoc to say `withCredentials: false` sets `'omit'`, and add a case that stubs `globalThis.fetch` and asserts `Request.credentials === 'omit'`. C++: two `429`s, then `200`; assert `token_calls == 3` and a single `device_poll` raising after one request with `retry_after() == 9000ms`. Java: `assertTrue(create.getHeader("Cookie").contains("axiam_access=" + sessionAccess))`. PHP: record the sleeps and `assertSame([5], $slept)`. |
| C164-20 | Info | typescript, rust, cplusplus, csharp | TS `src/node/oidc.ts:1655-1660`; Rust `src/oidc/device.rs:355-362`; C++ `include/axiam/client.hpp:837-883`; C# `Rest/WriteIsolatingHandler.cs:38-49`, `:148-149`, `AxiamClient.Oidc.cs:1280`, `Rest/AxiamHttpClientFactory.cs:179-180` | doc drift after (b) and C163-20 | TS and Rust: the `device_poll` doc says a hand-rolled loop "sees exactly what `device_login` sees", but `Retry-After` is not exposed. C++: neither doc mentions the 429. C#: four comments describe 1.1.1 (a misplaced lifetime comment, a retry-eligible list without the device poll, "only `ciba_poll` is retry-eligible", and the CSRF withholding attributed to the transport). | TS, Rust, C++: add "A `429` surfaces as `OAuthProtocolError` with `error == "rate_limit_exceeded"`; it is not terminal: wait at least its `Retry-After` (or one interval) without raising the interval; `device_login` does this." C#: move the comment into the `if (fresh)` block; list the device poll and the pooled cookie-less handler; write "`ciba_poll`, `device_poll`"; and "`X-CSRF-Token` is withheld from `/oauth2/*` in every composition; the `axiam_*` cookie only by the cookie-less transport the SDK's own primary handler builds". |
| C164-21 | Info | csharp, cplusplus, kotlin, php | C# `Management/ManifestApi.cs:663-667`; C++ `src/management_manifest.cpp:255-260`; Kotlin `management/ManifestApi.kt:582`; PHP `src/Management/Manifest/ManifestApi.php:233` | §27.6.2 item 4 (diagnostic from server data); Java's item asks for a length cap | The raw server value quoted under D-15 is unescaped. In C# and C++ it is also uncapped. A newline or a control character reaches logs. C# has no test of the "value unknown" branch. | Cap at 64 characters (append `…`) and escape: control characters become `?` (C#, C++), `Json.encodeToString(String.serializer(), raw.take(64))` (Kotlin), `json_encode($raw, JSON_UNESCAPED_SLASHES \| JSON_UNESCAPED_UNICODE)` (PHP). C#: test a profile whose raw value is `null` and assert "unknown". |
| C164-22 | Info | typescript, c, cplusplus, csharp, go, java, kotlin, php | TS `README.md:50-51`, `CHANGELOG.md:33-35`; C `CHANGELOG.md:29-30`; C++ `CHANGELOG.md:9-19`; C# `CHANGELOG.md:21-23`; Go `CHANGELOG.md:15-16`, `:73-77`; Java `CHANGELOG.md:10-40`, `:62`, `README.md:89`, `ScimTargetResponse.java:55`; Kotlin `CHANGELOG.md:54`, `:74-88`; PHP `README.md:27`, `:455`, `CHANGELOG.md:16-18`, `src/Core/NetworkError.php:103` | CHANGELOG/README accuracy (plan §8.2; C163-18) | <ul><li>TS: README rows still read "(ab)"/"(ac)", while the CHANGELOG says they no longer do.</li><li>C: the wrong test is named.</li><li>C++: no `### Binary compatibility` section, which 1.1.1 has.</li><li>C# and Java: a single `device_poll` on a 429 now throws `OAuthProtocolError` where 1.1.1 threw `NetworkError`; C#'s CHANGELOG says "as before" and Java's does not record it.</li><li>Go: the tagged `[1.1.1]` entry was rewritten, and the composite-literal sentence names the wrong type.</li><li>Java: the README misstates item 4, a Javadoc cites §32.2/1.62, and a `[1.2.0]` heading that never shipped remains.</li><li>Kotlin: the same phantom `[1.2.0]` heading.</li><li>PHP: the install snippets read `^1.1.0`, and `parseRetryAfterMs` turned public without record.</li></ul> | Per §3, each SDK's report under C164-22. Summary of the fixes:<ul><li>TS: rename the README cells.</li><li>C: name `test_adopted_bearer_is_not_sent_on_jwks_or_revocations`.</li><li>C++: add the section ("ABI version 4; `OAuthProtocolError` and `NetworkReplyProfile` gained members; not source-breaking; rebuild").</li><li>C# and Java: write that 1.1.1 raised `NetworkError`, so callers catching only that must also catch `OAuthProtocolError` (`rate_limit_exceeded`).</li><li>Go: restore the `[1.1.1]` text, and write "an unkeyed `OAuthProtocolError{…}` literal".</li><li>Java: write "as §27.6.2 item 4 asks of an SDK that keeps the value (contract 1.64)", fix the generator template to "§31.3 rule 4, contract 1.63", and fold `[1.2.0]` into `[1.1.1]` ("prepared as 1.2.0, released as 1.1.1").</li><li>Kotlin: the same fold for `[1.2.0]`.</li><li>PHP: write `^1.1.2`; mark the method `@internal` and record it.</li></ul> |
| C164-23 | Info | typescript, rust, c, csharp, go, php | TS `src/core/errorMapper.ts:286`, `test/node/deviceFlow.test.ts:220-233`; Rust `tests/oauth2_no_session_bearer_test.rs:344-346`; C `tests/test_client_failing_transport.c:301`, `:332`; C# `Management/ManagementChecks.cs:328-334`; Go `oidc_ciba.go:634-639`, `:731-733`; PHP `src/Rest/RefreshMiddleware.php:76-78` | miscellaneous; the first five are pre-existing | <ul><li>TS: the shared mapper gives the `/oauth2/*` row only 400 and 401, so a 429 on `oidcRefresh` or `loginClientCredentials` is a `NetworkError`.</li><li>TS and C: wall-clock flaky tests.</li><li>Rust: a comment says `logout` clears the jar.</li><li>C#: the internal raw properties join the `sealed record`'s `Equals`, so a decoded profile no longer equals one built from its public members.</li><li>Go: CIBA's 429 ignores `Retry-After` (§33.7 rule 5).</li><li>PHP: the replay rebuilds `Cookie` from the session jar even for a request whose `cookies` option differs.</li></ul> | Per §3, each SDK's report under C164-23.<ul><li>TS: guard `status >= 400 && status < 500`, never 5xx (a thrown-type change, so take it only as a fix), and use recorded sleeps.</li><li>C: wait on a condition, or `RUN_SERIAL`.</li><li>Rust: "The control comes last, so the `/oauth2/*` assertions run while the session is live".</li><li>C#: hold both strings in an internal holder whose `Equals` is always true, and test `decoded == decoded with { }`.</li><li>Go: `max(interval, RetryAfter)` capped at the deadline in `CibaAwait`.</li><li>PHP: rebuild from `$options['cookies']` when it is a jar.</li></ul> |
| C164-24 | Info | go, php | Go `client.go:839`; PHP `src/Rest/AuthMiddleware.php:86`, `:114`, `tests/Contract164/BasePathPrefixOAuth2Test.php:31` | §12.1 rule 3 / §6.1 rule 11 posture (C163-19) | Anchoring the `/oauth2/` match to the base URL's path prefix drops a root `/oauth2/*` URL under a prefixed base, as a discovery document or a prefix-stripping proxy may give, and that URL would carry the jar, CSRF and an adopted bearer. Before this PR, PHP stripped it. Not reachable with AXIAM's own discovery. | Match the base prefix **or** a root `/oauth2/` (federation routes still never match). Go: `strings.HasPrefix(p, strings.TrimRight(c.baseURL.Path, "/")+"/oauth2/") \|\| strings.HasPrefix(p, "/oauth2/")`. PHP: `str_starts_with($path, $oauth2Prefix) \|\| str_starts_with($path, '/oauth2/')`. Flip the pinned test rows to `true`. |

**Counts:** Medium 3 (C164-01, -02, -03) · Low 13 (C164-04 … -16; C164-16 is contract text) · Informational 8 (C164-17 … -24; C164-18 is contract text). There is no High or Critical.

**Per SDK** (the fix list for each SDK's session):

| SDK | Findings |
|---|---|
| typescript | C164-05, -06, -19, -20, -22, -23 |
| rust | C164-03, -04, -05, -07, -20, -23 |
| python | **C164-01**, -03, -04, -05, -15 |
| c | C164-03, -04, -08, -17, -22, -23 |
| cplusplus | C164-03, -04, -12, -19, -20, -21, -22 |
| csharp | C164-03 (regression), -04, -05, -20, -21, -22, -23 |
| go | **C164-02**, -04, -05, -17, -22, -23, -24 |
| java | C164-04, -05, -11, -12, -17, -19, -22 |
| kotlin | C164-04, -05, -13, -17, -21, -22 |
| php | C164-03, -04, -05, -09, -10, -17, -19, -21, -22, -23, -24 |
| swift | C164-03, -04, -14, -17 |
| contract (W7.1 follow-up) | C164-16, -18 |

**What each SDK did right, for the record.**
- (b) is ported in all eleven. Each loop waits `max(interval, Retry-After)`, counts the wait as one
  interval, leaves the interval unraised, caps at the deadline with a typed `expired_token`, and keeps the
  single `device_poll` raising.
- No SDK lets §16 re-send the 429 inside the poll.
- Every (b) test has both §14.6 cases and kills the terminal, `+5 s` and ignore-`Retry-After` mutants.
- Every plan §8.2 item is done in code. The exceptions are C164-06 (TypeScript's C163-12 is incomplete)
  and C164-08 (C's `refuse()` item is partial). C164-10, -12, -13 and -15 are test gaps behind code that
  works.
- No 1.63 rule regressed, except C164-02.

## 5. Questions for the maintainer

Only what plan §11 and the contract do not answer.

**Q1. When does the contract text of C164-16 and C164-18 land?**
- **What is open.** Plan §1.4 routes every finding to the SDK sessions and says nothing about a
  contract-text finding found after W7.1. 1.1.1 answered the same situation with a W7.1b amendment of
  §34.7 and a re-vendor in all eleven before W8.
- **Options.**
  - **(a)** A W7.1b amendment of contract 1.64 now: §14.2 rule 6, §14.6 and §34.8 (c), as written in
    §4. The eleven sessions then re-vendor in the same fix pass that takes C164-01 … -24, and this
    review's addendum checks the new hashes.
  - **(b)** Record both in contract 1.65 and fix the SDK code now. Rule 6 and rule 9 already bind as
    written, so no SDK fix depends on the text.
- **Recommendation: (a).** Every SDK PR changes again anyway (§4 per-SDK table), so a re-vendor costs one
  file copy per repository. It puts the "whatever its body" rule into the vendored text the fixes cite,
  and it repeats the 1.1.1 precedent. Under (b), 1.64's §34.8 (c) would ship with a wrong sentence about
  Swift and the five D-15 SDKs.

C164-01 … -15 and -17 … -24 need no decision. The rules they cite are explicit, and the fixes are local
to each SDK.

## 6. What this review could not verify

- **The issues, the PRs and CI of the eleven SDK repositories.** The GitHub tools in this session are
  scoped to `ilpanich/axiam`, and `api.github.com` answers 403 through the proxy. The item list is plan
  §8.2's rows, not the issue texts or their comments, so an item that a comment added or withdrew would
  not be seen. No CI state was read, and PR numbers come from `refs/pull/*/head`.
- **C# and Swift were not built or run.** There was no `dotnet` and no Swift toolchain (installers 403 or
  absent). Both reviews are by reading; the mutants were judged or traced by hand. C164-03 and C164-04
  for C#, Python and Swift are read, not probed.
- **Partial suites and legs not run.**
  - Rust: scoped `cargo test` targets, not the full `--all-features` suite, and no wasm32 build.
  - C++: the gcc/C++17 Debug leg only.
  - C: the ASan/UBSan leg, not the valgrind or C-standard matrix.
  - Kotlin: not `koverVerify`, dokka or lint.
  - PHP: not `composer audit`, the gRPC codegen job or a `composer install` from GitHub zipballs.
  - Go: not `govulncheck` (403).
  - TypeScript: not `buf generate`.
- **Signatures.** The SDK commits are signed (SSH), but no allowed-signers file exists here, so `%G?`
  could not verify them.

## 7. Addenda

One addendum per SDK whose PR changes after the head read in §1, at the orchestrator's request.
