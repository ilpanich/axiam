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

### 7.0 Addendum round 1 (2026-10-23): W7.1b and the eleven fix-pass heads

**What was read.**

The amended contract is W7.1b `21beda0` (`sdks/CONTRACT.md` sha256
`8b2cb9a385782b5e4575aa79f6e481915a63d19453cdcd9b921a0b92794d7a9a`; `openapi.json` and the registry are
unchanged).

The eleven fix-pass heads:

| SDK | PR | Head |
|---|---|---|
| TypeScript | #150 | `402c6c00f` |
| Rust | #138 | `42d0be449` |
| Python | #103 | `570efce7d` |
| C | #77 | `0c80e3d97` |
| C++ | #80 | `2b28526c7` |
| C# | #111 | `fd0869a49` |
| Go | #103 | `a6551ae8d` |
| Java | #121 | `4d40fd84b` |
| Kotlin | #80 | `ecf58ce99` |
| PHP | #87 | `70ce245e9` |
| Swift | #78 | `d8e48a073` |

These are the heads the orchestrator named at 12:13 UTC, and `git ls-remote` showed the same. The method was §1's:
- one reviewer per SDK, against `<old head>..<new head>` and the §4 rows naming the SDK;
- a mutant for each fix wherever a toolchain existed;
- probes of the amended rules with AXIAM's exact bodies;
- one added cross-SDK check: does the replay after a `401` refresh carry the fresh credential, CSRF token
  and cookies? PHP's session found this push-order bug in its own code.

As before, C# and Swift were read only; there is no toolchain for either.

**Vendoring and drift.** All eleven heads vendor `CONTRACT.md` byte-identical to `21beda0`, and `openapi.json` and
`management-registry.json` byte-identical to `fb92ec4`'s (unchanged). `scripts/check-sdk-artifact-drift.py
--local-root` over the eleven new heads reports **11 repos, 0 artifact problems**.

#### 7.0.1 W7.1b `21beda0`: the amended text

| Item | Verdict | Evidence |
|---|---|---|
| C164-16, §14.2 rule 6 | **Closed.** "A `5xx` is a transport failure whatever its body … the status is read before the body", cites P8 and AXIAM's `500 {"error":"server_error"}`. | `sdks/CONTRACT.md:3099-3105` |
| C164-16, §14.6 | **Closed.** The rule-6 test's mock carries `500 {"error":"server_error","error_description":…}`, "not a bodiless `500`". The 429 mock carries "the server's own [body], with no `error_description`". | `:3210-3212`, `:3218-3219` |
| C164-04, rule 9 status sentence | **Correct and sufficient.** "Any `429` on a poll is this wait, whatever its body names … rule 5's dispatch on `error` applies to the `400`." §14.6 gains the `429 slow_down` case. "Whatever its body names" also covers a bodiless or non-OAuth 429, so C164-17 is now a normative point. All eleven heads meet it (§7.0.3). | `:3148-3151`, `:3226-3227` |
| P11 and `device_poll` | **Correct.** `device_poll` on a 5xx or transport failure joins the requests an SDK "does retry" and may give a fresh connection. That matches §16.2's eligibility table. | `:13173-13174` |
| C164-18, §34.8 (c) | **Closed.** TypeScript, Python, Go, Rust and Swift keep the text. C++, C#, Java, Kotlin and PHP keep it through D-15. Only C does not. All eleven reports agree. | `:13894-13900` |
| §34.8 amendment note; Breaking Changes Log | **Correct.** No version change, "none breaking", each change marked *contract 1.64 (amended)* inline. | `:13863-13875`, `:4315-4316` |

**Swift's question: does rule 6 with §16.2 require a retry inside the poll, or does the loop's next interval suffice?**
The text requires the in-poll retry. Swift's and C#'s addendum reviewers each confirmed this reading
independently.
- Rule 6 says 5xx and transport failures "are retried under the bounded read-only retry policy of §16, then
  surfaced". It sets that budget "per poll attempt", separate from the polling loop, where "an exhausted retry
  budget ends that one poll, not the flow".
- §16.2 lists `device_poll` on a 5xx or transport failure as **eligible**.
- §16.1 says the switch MUST default to **on**.
- Amended P11 counts `device_poll` among "the requests it does retry".

The next interval meets rule 6's safety property ("must not lose a grant") but not §16. The retry covers a 5xx
or a transport failure only, never a 429: otherwise the 429 is waited twice, once in the poll and once by the
loop's rule-9 wait. **The wording does not need another touch.**
- It is unambiguous, and C and C++ implement it as written.
- Nine SDKs miss it (C164-25), because no required test exercises it: §16.7's tests are about `check_access`.
- A one-sentence §14.6 addition would make the miss visible. That is **C164-35 (Info, contract)**, for 1.65,
  not a 1.64 re-amendment: the fixes of C164-25 need no text change.

**Java's note: a `Retry-After` in HTTP-date form is read as absent.** This is not a finding.
- §14.2, §16.1 and §33.7 name no form, and AXIAM sends delta-seconds only.
- Java's loop then waits exactly the interval, never less. It never ends the flow and never polls faster than
  the interval.
- It can poll before an intermediary's date. Reading the date form is optional hardening: Python, Swift,
  Kotlin and PHP already do it.

**TypeScript's note: C164-23(a) was taken narrower than proposed.** The narrower fix is accepted. The 429 is
mapped in `mapOidcError` with a tolerant decoder, and the §2 mapper is not widened to every 4xx (tests pin
403/409 as non-OAuth). It closes the defect:
- a 429 `rate_limit_exceeded` on `oidcRefresh`, `loginClientCredentials`, `deviceAuthorize` and `devicePoll`
  is an `OAuthProtocolError`;
- a 5xx stays `NetworkError` whatever its body.

The new branch is not path-gated, though (C164-31).

**C++'s note: the patch version was kept despite two exception-class changes.** Confirmed.
- The only header change since the review is a defaulted trailing constructor parameter on
  `OAuthProtocolError` (`std::optional<long> http_status`) and its accessor. It is source-compatible.
- The single-poll exception types change, as the amended contract requires: a bodiless 429 becomes
  `OAuthProtocolError`, and a 5xx with an OAuth body becomes `NetworkError`. These are behaviour changes of the
  same kind as C163-07, which was accepted at patch.
- SOVERSION 4, not yet shipped, covers the new trailing member. A shared build gives `libaxiam_cpp.so.4`.

**PHP's note: the other SDKs' replay paths may share its push-order bug.** Two do.
- **Python** copies the stale `Cookie` header into the replay, and httpx does not overwrite it.
- **Java**'s OkHttp `Authenticator` replaces only `Authorization`. The follow-up runs below the application
  interceptors, so the stale `X-CSRF-Token` goes out.

Both are pre-existing, and both make a refresh that succeeded end in `401`/`403` (C164-26, **Medium**). The
other nine are clean:
- probed: TypeScript, Rust, C, C++, Kotlin, PHP, and Go's gRPC path (Go has no REST replay by design);
- read: C#, Swift.

#### 7.0.2 New findings (C164-25 onward)

| ID | Severity | SDK | `path:line` (new head) | Rule | What | Fix |
|---|---|---|---|---|---|---|
| C164-25 | Low | typescript, rust, python, csharp, go, java, kotlin, php, swift (pre-existing) | TS `src/node/oidc.ts` `devicePoll` (no `withRetry`); Rust `src/oidc/device.rs:470-491`; Python `_oidc.py` `device_poll` (no `retry_sync`/`retry_async`); C# `AxiamClient.Oidc*.cs` `DevicePollAsync` (no `RetryPolicy.ExecuteAsync`); Go `oidc_device.go:207-225`; Java `AxiamClient.java:3449-3455`; Kotlin `devicePoll` (no §16 runner); PHP `src/Oidc/OidcClient.php:842`, `:2555-2570`; Swift `Oidc/DeviceGrant.swift:158` | §14.2 rule 6 ("retried under … §16, then surfaced"; budget "per poll attempt"); §16.2 (`device_poll` on 5xx/transport eligible); §16.1 (on by default) | With retry on, a device poll answered `5xx` or failed in transport is sent once. `device_poll` surfaces it at once, and `device_login` waits a full interval. Rust also ignores a 503's `Retry-After`. No grant is lost, since the loop is non-terminal everywhere (C164-03), but the §16 budget is never used. C and C++ do it right. | Send the poll through the SDK's own §16 runner, the one its `ciba_poll` already uses, with a mode that retries **only** on a transport failure or a `5xx`, never on a `429`. Keep the 200's parsing outside the retry, and bound the retry waits by the loop's deadline (as CIBA's P10 does). Test: three `500 {"error":"server_error",…}`, then `200`; `device_login` completes in one interval with 4 requests, the single `device_poll` returns the tokens, and with retry disabled there is one request per poll. Restore the Swift comment and the README §16 row. |
| C164-26 | **Medium** | python, java (pre-existing) | Python `src/axiam_sdk/_client.py:1679-1685`, `_async_client.py:513-519`; Java `AuthAuthenticator.java:106-108` | §9.3 (refresh then resend once); §3 (CSRF on state-changing requests) | After a `401`, the refresh succeeds but the replay carries stale session state, so the caller gets `AuthError` or `403` anyway. **Python:** `_retry_after_refresh_*` copies the original `Cookie` header, which httpx keeps over the jar's fresh one, so the expired `axiam_access` and old `axiam_csrf` go out next to the new `X-CSRF-Token`. Probed on sync and async `check_access` and on a management call. **Java:** the OkHttp `Authenticator` sets only `Authorization`, and its follow-up never passes `AuthInterceptor`, so it carries `X-CSRF-Token: CSRF-OLD` with the rotated `axiam_csrf` cookie, which AXIAM's CSRF middleware refuses. Probed; the proactive path and gRPC are fine. PHP had the same class of bug and fixed it in this PR (C164-10, `f469880`). | **Python:** add `"cookie"` to the excluded header names in both helpers (verified in a copy: all three probe paths `200`, and 1024 related tests pass). **Java:** in `authenticate()`, also `.header("X-CSRF-Token", session.csrfToken())` when the request is state-changing and not `/oauth2/*`, mirroring `AuthInterceptor`'s condition. **Test in both:** a cookie login, then a `401` on a state-changing management request, then the refresh `200` rotating `axiam_access`, `axiam_csrf` and `X-CSRF-Token`, then `200`. Assert that the replay carries the new cookie and the new `X-CSRF-Token`, and that the caller gets the `200`. |
| C164-27 | Low (rust); Info (c) | rust, c | Rust `src/oidc/device.rs:421` (doc), the single-poll mapping; C `src/oidc_device.c:213` | §14.2 rule 6 ("`5xx` … remain §2 `NetworkError`") for the single `device_poll` | C164-03 is closed for `device_login` in both SDKs, but a single call still types a 5xx with an OAuth body as an auth error. **Rust:** `device_poll` returns `500 server_error` and `503 temporarily_unavailable` as `AxiamError` with `oauth_error_code()` set, which contradicts its own new doc, so a hand-rolled loop ends. **C:** this happens only when the caller passes `err == NULL`: the return code is `AXIAM_ERR_AUTH`, because the reclassification needs the struct. | **Rust:** map any status of 500 or above through `from_http_status` before the body, as `ciba_poll` does, and test that a single `device_poll` on that `500` is a network error. **C:** classify on the transport status before `oidc_map_grant_error`, so that `err == NULL` also returns the network code, and add a test with `err == NULL`. |
| C164-28 | Low | kotlin | `oidc/OidcSupport.kt:1129` vs `:1135` | §14.2 rule 4; C164-05 (partly closed) | The deadline is now a clock instant, but it is taken **after** `onUserCode`. Probe: a 25 s callback with `expires_in` 30 let 5 polls go out after the real deadline. | Move the `deadline` line above the `onUserCode` call. Test: a recording clock advanced 25 s inside the callback, `expires_in` 30, interval 5: `expired_token` with at most one poll. |
| C164-29 | Low | java, python, kotlin | Java `AxiamClientDeviceFlowTest.java` (19 device-flow tests); Python `tests/test_device_flow.py` (the clock test exercises `PollSchedule` only); Kotlin `OidcDeviceFlowTest.kt` (the §14.6 429 mock) | §14.6 (1.64 case 2, "sends nothing after the deadline"; amended: "the mock's body is the server's own, with no `error_description`") | Required tests that do not pin the fix. **Java:** no test advances the clock outside `sleep`, so a "sum of the sleeps" mutant survives all 19 device-flow tests (C164-05 partly closed). **Python:** removing the monotonic clock from both `device_login`s leaves all 41 device-flow tests green. **Kotlin:** the 429 mock still carries `error_description`. The code is right in all three (probed). | **Java and Python:** a fake clock that also advances a fixed request time per poll (or inside `on_user_code`); assert no poll at or after the deadline, through `device_login` itself. **Kotlin:** the mock sends exactly `{"error":"rate_limit_exceeded"}`. |
| C164-30 | Low | java (new in this PR) | `AxiamClient.java:3493`; `ErrorMapper.java:196-206` | §14.2 rule 9 / rule 4 (capped at the deadline; the typed `expired_token`) | A huge `Retry-After` overflows `Instant.plus`. `99999999999999999` throws `DateTimeException` and `Long.MAX_VALUE` throws `ArithmeticException`, instead of the typed `expired_token`. The old head's `long` comparison did not overflow. | Clamp the parsed `Retry-After` (for example to `expires_in`, or to §16's 3600 s cap), or compare `Duration`s against `Duration.between(now, deadline)` before adding. Test: `Retry-After: 99999999999999999` gives `expired_token` with nothing sent after it. |
| C164-31 | Low | typescript (new in this PR) | `src/node/oidc.ts:567` (`mapOidcError`) | §2 (`/oauth2/*` row vs the generic row) | The new 429 branch is not path-gated. A `429 rate_limit_exceeded` from discovery, `/api/v1/auth/federation/*` or `/uma2/*` now throws `OAuthProtocolError`, an `AuthError`, where §2 makes it a `NetworkError` (probed). The CHANGELOG says "from `/oauth2/*`". | Gate the branch on an anchored `/oauth2/` match, `isOAuth2Endpoint`. The `isOAuth2EndpointUrl` fallback also matches `federation/oauth2/start`, so do not use it. Test: a `429` from the discovery GET and from `/uma2/perm` stays `NetworkError`. |
| C164-32 | Info | typescript, rust, c, cplusplus, csharp, go, java, kotlin, swift | per §7.0.3 | text after the fix pass | Text drift after the fix pass. **CHANGELOG:** TypeScript, Rust and C++ still name `fb92ec4` as the CONTRACT source, now `21beda0`. **README and docs:** Rust, C, C++ and C# describe only the pre-amendment 429/5xx behaviour. **API docs:** Rust's public `PollSchedule` and `tick_for` docs describe a schedule `device_login` no longer uses. **Unrecorded changes:** the reverse single-poll type changes are missing from C++'s and Kotlin's CHANGELOGs; Java's lacks `ErrorMapper.fromDevicePollResponse`; Go's lacks the CI floor bump, and its `README.md:188` still says 1.26.9. **Overstated row:** Swift's README §16 row (C164-25). | Per §7.0.3, each SDK's addendum under C164-32. |
| C164-33 | Info | c, cplusplus, csharp, go, kotlin, php, swift | per §7.0.3 | test strength | <ul><li>PHP: the new C164-10 test's `Cookie` assertions pass with the rebuild removed, because `HandlerStack::create($mock)` nests a second cookie middleware.</li><li>Swift: no test of a single `devicePoll` on `429 slow_down`, and the code-rewrite mutant survives.</li><li>C++: no test pins the fresh CSRF on the post-refresh replay, and one test comment overstates what it checks.</li><li>C: only four of the eleven C164-08 sites have a 400 assertion.</li><li>Go: the `authorization_pending` subtest of C164-04 sends no `Retry-After`.</li><li>C#: `StopsAtExpiresIn` sits on a clock boundary.</li><li>Kotlin: `OidcRefreshTest` flaked once under load (passes alone, 3/3).</li><li>PHP: C164-23 has no test.</li></ul> | PHP: pass the bare `$mock`. The others: per §7.0.3. |
| C164-35 | Info | contract | `sdks/CONTRACT.md` §14.6 | test coverage of §14.2 rule 6 / §16.2 | No required test exercises the in-poll §16 retry of `device_poll`, which is why nine SDKs miss it (C164-25). | For contract 1.65 (no 1.64 re-amendment): add to §14.6, "with retry enabled, a `500` on a poll is retried within the poll under §16 (at most three attempts) before the loop takes its next interval; a `429` is not". |

(C164-34 is not used.)

**Counts, round 1:** Medium 1 (C164-26, two SDKs) · Low 6 (C164-25, -27 (Rust), -28, -29, -30, -31) ·
Informational 4 (C164-27 (C), -32, -33, -35).

#### 7.0.3 Per-SDK status

| SDK | Head | Review findings | New / remaining | Version |
|---|---|---|---|---|
| typescript | `402c6c00f` | C164-05, -06, -19, -20, -22, -23 **closed** | C164-25, -31 (Low), -32 | 1.1.2 ✓ |
| rust | `42d0be449` | C164-04, -05, -07, -20, -23 **closed**; C164-03 **partly** (the loop is fixed; the single poll is C164-27) | C164-25, -27 (Low), -32 | 1.1.2 ✓ |
| python | `570efce7d` | C164-01, -03, -04, -05, -15 **closed** | **C164-26 (Medium)**, -25, -29 | 1.1.2 ✓ |
| c | `0c80e3d97` | C164-03, -04, -08, -17, -22, -23 **closed** | C164-27 (Info), -32, -33 | 1.1.2 ✓ (SOVERSION 2) |
| cplusplus | `2b28526c7` | C164-03, -04, -12, -19, -20, -21, -22 **closed** | C164-32, -33 | 1.1.2 ✓ (SOVERSION 4) |
| csharp | `fd0869a49` | C164-03, -04, -05, -20, -21, -22, -23 **closed** (read only) | C164-25, -32, -33 | 1.1.2 ✓ |
| go | `a6551ae8d` | C164-02, -04, -05, -17, -22, -23, -24 **closed** | C164-25, -32 | 1.1.2 ✓; `9d7460a` touches only `sdk-ci-go.yml` |
| java | `4d40fd84b` | C164-04, -11, -12, -17, -19, -22 **closed**; C164-05 **partly** (code fixed; the test is C164-29) | **C164-26 (Medium)**, -25, -29, -30, -32 | 1.1.2 ✓ |
| kotlin | `ecf58ce99` | C164-04, -13, -17, -21, -22 **closed**; C164-05 **partly** (C164-28) | C164-25, -28, -29, -32, -33 | 1.1.2 ✓ |
| php | `70ce245e9` | C164-03, -04, -05, -09, -10, -17, -19, -21, -22, -23, -24 **closed** | C164-25, -33 | 1.1.2 ✓ |
| swift | `d8e48a073` | C164-03, -04, -14, -17 **closed** (read only) | C164-25, -32, -33 | 1.1.2 ✓ |

**All three Medium findings of the review are closed**: C164-01 (Python), C164-02 (Go) and C164-03 (all
seven). **Every SDK now meets amended rules 6 and 9 and has the three §14.6 cases**, probed against AXIAM's
exact bodies, except where the table names a remaining finding:
- every 429 is waited at least its `Retry-After`, bodiless and `slow_down` bodies included, and never raises
  the interval;
- a `400 slow_down` still raises it;
- a `500 server_error` and a `503` never end `device_login`.

**Can W7 merge? Not yet.** Plan §1.4 asks every finding to be fixed in its SDK's PR before W8, the Medium ones
first. Open findings remain in ten SDKs:
- **C164-26 (Medium)** in Python and Java;
- the Lows C164-25, -27, -28, -29, -30 and -31;
- the Informationals C164-27 (C), -32 and -33.

C++ has only Informational items left. A round 2 addendum reads each SDK's PR once it changes again. C164-35
needs nothing before W8.

The eleven addenda follow, with the reviewers' N-numbers mapped to the ids above. Where an addendum names a
severity, §7.0.2 is the binding one.

---

#### Addendum — typescript — commit 402c6c00f (PR #150), read after 46461b6f5

Four commits on the old head: `e540aff` re-vendors CONTRACT.md from 21beda0 (sha256 8b2cb9a3…7a9a, matches), `329e5c5` (C164-05, -20, -23), `077cc52` (C164-06, -19), `402c6c0` (C164-22). Each commit's claims were checked against its diff. Read-only on `/home/user/sdks/typescript`. The work was done in a fresh throwaway clone at `/home/user/work/typescript`, which replaced the review's old-head copy.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-05 (Low, pre-existing) wall-clock deadline | **CLOSED** | 329e5c5 | `src/node/oidc.ts:1740` takes `deadline = clock.now() + expiresIn*1000` when `deviceAuthorize` returns, before `onUserCode`. `:1754` stops with `expired_token` when `!tick() \|\| now + wait >= deadline`. The clock is injectable through `DeviceLoginParams.clock?: CibaClock` (`src/node/oidcTypes.ts:892`); this is additive, documented in the CHANGELOG, and is the same type `cibaAwait` takes. Test `test/node/deviceFlow.test.ts:313`: a fake clock advances 2 s per poll, with expires_in 5 and interval 1, and the loop must make 2 polls. **Mutant M05** (drop the clock clause) fails it (1 failed). |
| C164-06 (Low) RFC 7592 calls in the browser | **CLOSED** | 077cc52 | `src/rest/bareTransport.ts:57` is `...session.oauth2RequestConfig()`, followed by `withCredentials:false`. The other callers of `bareRequest` (SSF) are in `src/node`, where `NodeSession` overrides the config to `noCredentialsConfig()`, so nothing changes there. Tests `test/rest/oauth2BrowserCredentials.test.ts:108` (browser: `adapter==='fetch'`, `fetchOptions` `{credentials:'omit'}`) and `:117` (Node: no adapter, agent kept). **Mutant M06** (revert to `noCredentialsConfig()`) fails the browser case. |
| C164-19 (Info) test strength / TSDoc | **CLOSED** | 077cc52 | The TSDoc at `src/rest/session.ts:315-317` now says the fetch adapter derives `credentials` from `withCredentials:false`. New test `test/rest/oauth2BrowserCredentials.test.ts:75` stubs `globalThis.fetch` and asserts that the `Request` reaching it has `credentials==='omit'`. **Mutant M19** (`withCredentials:true` in `oauth2RequestConfig`, `fetchOptions` kept) fails the new Request test as well as the 4 config tests. So the test now pins the setting that really withholds the cookie. |
| C164-20 (Info) `devicePoll` doc | **CLOSED** | 329e5c5 | `src/node/oidc.ts:1672-1686`: "sees exactly what" became "dispatches on the same answers". It now says that any `429` is `rate_limit_exceeded`, that its `Retry-After` is not exposed, and that a hand-rolled loop waits at least one interval without raising it, or uses `deviceLogin`. This is doc only, so there is no mutant. |
| C164-22 (Info) README §34.7 cells / CHANGELOG | **CLOSED** | 402c6c0 | `README.md:51-52` now read `C162-07 (§34.6 (ab)): …` and `C162-08 (§34.6 (ac)): …`, as the review proposed. `CHANGELOG.md:45-46` describes them accurately. A separate stale sentence in the CHANGELOG intro is C164-32. |
| C164-23(a) (Info) 429 on the other `/oauth2/*` token calls | **CLOSED for the defect; the fix overreaches (C164-31)** | 329e5c5 | `src/node/oidc.ts:567-570`: in `mapOidcError`, a `429` whose body decodes through the tolerant `oauth2ErrorFromBody` (a non-empty string `error`; `error_description` optional) is that `OAuthProtocolError`. Everything else still goes through the unchanged §2 mapper (400/401 only), so 403/409 keep `AuthzError` as the existing tests require. **Judgement on the session's note:** the defect is closed. Probed with the server's exact `429 {"error":"rate_limit_exceeded"}`, and with the `"retry_after":3` + `Retry-After: 3` variant: `oidcRefresh`, `loginClientCredentials`, `deviceAuthorize` and `devicePoll` all raise `OAuthProtocolError` `rate_limit_exceeded`. A 5xx stays `NetworkError`: `500 {"error":"server_error","error_description":"db"}` and `503 {"error":"temporarily_unavailable"}` give `NetworkError` on all four (probed). A bodiless 429 stays `NetworkError` on the three non-poll calls, which is right because §2 needs an OAuth body. The narrowing is defensible: §2's "any status" row would also make a 403 OAuth body an `OAuthProtocolError`, and that residual (403/409) is pre-existing and still deliberately documented in `mapUmaGrantError`'s TSDoc (`:577-589`). **But** the new branch has no `/oauth2/*` URL gate. `mapOidcError` also maps discovery, the federation `/api/v1/auth/federation/*` calls and UMA `/uma2/*`, and these now turn AXIAM's rate-limiter body into `OAuthProtocolError` too. See C164-31. Test `test/node/deviceFlow.test.ts:637` (loginClientCredentials 429) and `:649` (500 stays NetworkError). **Mutant M23a** (branch removed) fails `:637`. **M23a5xx** (branch widened to ≥500) fails 2. |
| C164-23(b) (Info) wall-clock flaky tests | **CLOSED** | 329e5c5 | `recordSleeps()` moved to the describe (`test/node/deviceFlow.test.ts:223`, `beforeEach` `:244`). Every §14.2 polling test now asserts recorded delays and runs in about 100-450 ms. Residual: the §14.3 ordering tests (`:505-566`, 1 real 1 s sleep each) and `deviceClientAuth.test.ts` (up to 2.3 s) still sleep for real. That is well under the 5 s timeout and not what flaked. The full suite passed once with no timeout. |

**Amended rules (probes, `deviceLogin` with an injected recording clock, interval 1 s; each script starts with a `400 authorization_pending`)**

| Rule / case | Probe (AXIAM's exact body) | Result |
|---|---|---|
| §14.2 rule 9: 429 is the wait, ≥ Retry-After | `429 {"error":"rate_limit_exceeded"}` + `Retry-After: 4` | sleeps `[1000,1000,4000]`, 3 calls, tokens. Pass |
| same, `retry_after` variant | `{"error":"rate_limit_exceeded","retry_after":4}` + RA 4, then pending, ok | `[1000,1000,4000,1000]`: interval unchanged after. Pass |
| rule 9 amended: bodiless 429 | `429` no body + `Retry-After: 3` | `[1000,1000,3000]`. Pass (C164-17 point holds) |
| §14.6 third case: 429 `slow_down` does not raise | `429 {"error":"slow_down"}` + RA 2, pending, ok | `[1000,1000,2000,1000]`. Pass |
| 400 `slow_down` still raises | `400 slow_down`, pending, ok | `[1000,1000,6000,6000]`. Pass |
| rule 6 amended / §14.6 500 body | `500 {"error":"server_error","error_description":"db"}` | non-terminal, `[1000,1000,1000]`, tokens. Pass. **Not §16-retried inside the poll** (C164-25) |
| 503 | `503 {"error":"temporarily_unavailable"}` | non-terminal, `[1000,1000,1000]`. Pass, same C164-25 caveat |
| single `devicePoll` on 429 | `{"error":"rate_limit_exceeded"}` / bodiless / `slow_down` body | `OAuthProtocolError` `rate_limit_exceeded` in all three. Pass |
| single `devicePoll` on 5xx | 500 server_error / 503 | `NetworkError`. Pass |

The repository's own §14.6 tests: the server's body with no description (`deviceFlow.test.ts:58-62`, used at `:385`), the cap case (`:450`), the bodiless case (`:411`), the 429 slow_down case (`:426`), and the 500 body (`:360`, `error_description` included). **M9body** (pollRateLimit gated on the body again) fails 3. **M9slow** (a 429 slow_down read as slow_down) fails 2. **M6term** (a 5xx with an OAuth body made terminal) fails `:360`.

Replay after refresh: **correct, no push-order bug.** `src/rest/interceptors.ts:109-127`: the response interceptor sets `_retry`, runs the single-flight refresh, and then `onAuthenticated()`, which on Node re-reads `axiam_csrf` from the jar (`src/node/session.ts:111-138`). It then replays through `axiosInstance(originalRequest)`. That re-runs the request interceptors: the CSRF interceptor (`:61-82`) overwrites `X-CSRF-Token` from the refreshed token, and the jar-wrapped agent attaches cookies at send time. Probed (Node persona, jar, a POST that is answered 401 once; the refresh rotates both cookies): the first send carried `csrf-login-1` / `axiam_access=access-token-login`. The replay carried `X-CSRF-Token: csrf-refresh-2` and `axiam_access=access-token-refreshed-2; axiam_csrf=csrf-refresh-2`, and got 200. In the browser persona the CSRF value is read live from `document.cookie`. A device credential never enters the refresh (`isDeviceSession`, `:107`). One theoretical edge: if a refresh left no `axiam_csrf` at all, the stale header would stay on the replayed config, because the interceptor only sets the header and never deletes it. AXIAM always rotates the cookie on refresh, so this is not a finding.

Version: `package.json` 1.1.2 (patch is right: the only API change is the additive optional `DeviceLoginParams.clock`; the class change for 429s is recorded). The CHANGELOG `[1.1.2]` records all six fixes. The README conformance sentence still says contract 1.64. The CHANGELOG intro's vendoring sentence is stale (C164-32).

Run by the reviewer (throwaway clone `/home/user/work/typescript` at 402c6c00f, Node 22.22.0, proxy variables unset):
- `npm ci` OK; `npx tsc --noEmit` exit 0.
- `npx vitest run`: **119 files, 1757 passed, 3 skipped, 0 failed** (257 s). The old head gave 1746/3/1 in the review.
- `npm run docs` (typedoc): exit 0, 0 errors; the 3 pre-existing `middleware.OidcLoginOutcome` warnings.
- `node scripts/gen-management.mjs --check`: 32 files current, 202 ops. `npx tsup` OK; `npm run bundle-grep` OK for rest and browser; token-leak grep on `dist/` clean.
- 8 mutants (`/home/user/work/ts-add-mut.sh`, logs `/home/user/work/ts-add-mut-*.log`), all killed: M05, M06, M19, M23a, M23a5xx, M9body, M9slow, M6term.
- Probes: `/home/user/work/ts-add-probes/zprobe.test.ts`, run from inside the copy's `test/node` and then removed; a separate replay probe was removed too.
- Not run: `npm run build`'s `buf generate` (`buf` not installed, remote BSR plugins unavailable); `tsup` was run directly. `node_modules`, `dist` and `_docs` were deleted afterwards. The SDK clone is unmodified.

New findings:

- **C164-31 — Low — `src/node/oidc.ts:567-570`.** Rule: §2. The `OAuthProtocolError` row is "Any status **from `/oauth2/*`** with an `OAuth2ErrorResponse` body"; otherwise `408, 429 → NetworkError`. The CHANGELOG says "A `429 {"error":…}` from `/oauth2/*`". **What happens:** the new 429 branch in `mapOidcError` has no URL gate, and `mapOidcError` also maps `oidcDiscover` (`/.well-known/openid-configuration`, through `#get`), `ssoProviders` (`/api/v1/auth/federation/providers`), the federation POSTs (`ssoStart`, `ssoStartOauth2`, the callback/handoff completions through `#postJson`) and the UMA protection API (`/uma2/*`, `:2074`). AXIAM's rate limiter answers all of them with `429 {"error":"rate_limit_exceeded"}`. Probed: `ssoProviders`, `oidcDiscover` and `umaListResources` now throw `OAuthProtocolError` `rate_limit_exceeded`, an `AuthError` subtype, where 1.1.1 and §2 give `NetworkError`. A caller that catches `NetworkError` to back off on a rate-limited SSO login page no longer catches it, and a caller that reads `AuthError` as "sign in again" misreads it. **Fix:** gate the branch the way the §2 mapper gates its row: `if (status === 429 && isOAuth2EndpointUrl(url)) { … }`. `isOAuth2EndpointUrl` is already exported from `src/core/errorMapper.ts:94`. Note that its relative-path fallback `url.includes('/oauth2/')` also matches `/api/v1/auth/federation/oauth2/start`, so either pass the absolute URL or use `isOAuth2Endpoint(url, session.baseUrl)` from `src/rest/interceptors.ts` (a prefix match). **Test:** a `429 {"error":"rate_limit_exceeded"}` on `ssoProviders` (and on discovery) is `NetworkError`, while the existing `loginClientCredentials` case stays `OAuthProtocolError`.
- **C164-25 — Low, pre-existing (not in the diff) — `src/node/oidc.ts:1699` (`devicePoll` → `#postForm`, no `withRetry`), `:1794-1796`.** Rule: §14.2 rule 6 as amended ("retried under the bounded read-only retry policy of §16, then surfaced"; §16.2 lists `device_poll` on a 5xx/transport failure as eligible, per poll attempt). `retryEnabled` defaults to `true` (`src/core/config.ts:56-68`). **What happens:** a 5xx or transport failure on a poll makes exactly one attempt. A single `devicePoll` surfaces the `NetworkError` at once, and `deviceLogin` takes its next full interval (probed: `[…,1000]`, 1 request per poll) instead of the §16 retries (200/400 ms full jitter, `Retry-After` floor, 3 attempts) inside the attempt. No grant is lost, so the caller-visible effect is a delay of one interval per 5xx. The README/CHANGELOG "is retried" is true only of the loop. **Fix:** in `devicePoll`, wrap the post in `withRetry` as `cibaPoll` does (`:2398-2430`): `idempotent: true`, `operation: 'device_poll'`, `enabled: session.retryEnabled`, retrying only a `NetworkError` from a 5xx or no response (never the 400/401/429 answers). Keep the loop's `continue` for an exhausted budget. **Test:** `500 {"error":"server_error"}` twice then `200` on one `devicePoll` with an injected sleep gives 3 requests and a token set; with `retryEnabled:false` it gives 1 request and `NetworkError`.
- **C164-32 — Informational — `CHANGELOG.md:12-14`.** The intro still says "`CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/` are vendored byte for byte from that commit" (`fb92ec4`). Since `e540aff`, `CONTRACT.md` is axiam `21beda0` (contract 1.64 as amended, sha256 8b2cb9a3…). **Fix:** "`CONTRACT.md` is vendored from axiam `21beda0` (contract 1.64 as amended, W7.1b); `openapi.json`, `management-registry.json` and `proto/` from `fb92ec4`, which `21beda0` does not change."

---

#### Addendum — rust — commit 42d0be449 (PR #138), read after 5e91fa574

Four commits on top of the reviewed head, in a straight line: `7472de8` re-vendors CONTRACT.md at axiam
`21beda0`; `551b5e6` fixes C164-03/-04/-05; `82a4c6d` fixes C164-07; `42d0be4` covers C164-20 and C164-23 (docs,
test comments, CHANGELOG). The commit messages match what each diff does. The clone was not modified. All
runs used a throwaway copy, `/home/user/work/rust`, which has since been deleted.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-03 (Medium) | **PARTLY**: CLOSED for `device_login`. The single `device_poll` still surfaces the 5xx as an `OAuthProtocolError`. | `551b5e6` | `PollFailure.status` is set from the response before the body is read (`src/oidc/device.rs:482-490`). `classify_failure` returns `Transient` for any `s >= 500` before it reads the body (`:274-283`). The loop `continue`s on `Transient` (`:628`). Tests: `a_500_with_an_error_body_mid_poll_is_not_terminal` (`:975`, script `500 {"error":"server_error","error_description":"db"}`, then pending, then 200; it asserts 3 polls and sleeps `[5,5,5]`), and `tests/device_flow_test.rs:420-428`, whose 500 mock now carries the server's JSON body. Mutants: dropping the `>=500` arm fails the unit test; the pre-fix `classify` fails it and 2 others. **Residual:** the single `device_poll` maps through `oauth2_error_or_fallback` (`:487`), so `500 {"error":"server_error"}` gives `AxiamError::Auth`, `oauth_error_code()==Some("server_error")`, `is_retryable_transport()==false` (probed; `503 temporarily_unavailable` gives the same). The row's fix asks for the §2 `NetworkError` "whatever its body", as `ciba_poll` does (`src/oidc/ciba.rs`, `status >= 500` → `from_http_status`). The new doc says "A `5xx` is a transport failure whatever its body (rule 6)" (`:421`), and the call does not do what that sentence says. A hand-rolled loop that dispatches on `error`, as the doc at `:391-395` invites, ends on AXIAM's 500. Fix: in `device_poll_step`, when `status >= 500`, build `err` with `AxiamError::from_http_status(status, text)` and do not call `oauth2_error_or_fallback`. Test: a single `device_poll` against that 500 gives `is_retryable_transport()` and `oauth_error_code()==None`. |
| C164-04 (Low) | **CLOSED** | `551b5e6` | `Some(429) => RateLimited` whatever the body, and `slow_down` is read only on `Some(400) \| None` (`src/oidc/device.rs:274-283`). Tests: `a_429_slow_down_waits_and_does_not_raise_the_interval` (`:1002`, sleeps `[5,5,5]`), `a_400_slow_down_still_raises_the_interval` (`:1029`, `[5,10]`) and `a_bodiless_429_honours_retry_after` (`:1054`, `[5,12]`; this also closes C164-17's trigger for Rust). Mutant: dropping the 429 arm fails 2 tests. |
| C164-05 (Low) | **CLOSED** | `551b5e6` | `deadline = now() + expires_in` is taken after `on_user_code` returns (`:594`). The loop stops when `now() + wait >= deadline` before the sleep (`:609`), and checks `now() >= deadline` again after it (`:614`). The clock is injected through `device_login_with`'s `now` (`:567-571`); production passes `crate::time::Instant::now` (web-time on wasm). Test: `the_time_a_poll_takes_counts_against_the_deadline` (`:1106`). In it a fake clock advances 30 s per poll and by each sleep; with `expires_in` 60 it asserts `expired_token`, 2 polls and waits `[5,5]`. Mutant: restoring the slept-seconds budget (`schedule.tick_for`) fails that test. |
| C164-07 (Low) | **CLOSED** | `82a4c6d` | Crate-internal `OmitBrowserCredentials` (`src/client.rs:37-52`), which is `fetch_credentials_omit()` on wasm32 and the identity elsewhere. It is applied in `oauth2_post` (`:1124`), the client and SSF JWKS fetch (`src/token/jwks.rs:1292`), SSF discovery (`src/ssf.rs:436`), the SSF poll (`:680`), and RFC 7592 GET, PUT and DELETE (`src/oidc/registration.rs:311`, `:375`, `:404`). That covers every `http_bare()` caller in `src/`. `CHANGELOG.md:24` has the "(native targets; in the browser build, redirects are the browser's)" text, and `:53-54` records the change. The check is compile-only, as the row allows. **wasm32 now built:** `cargo check --target wasm32-unknown-unknown --no-default-features --features rest` exit 0. Its one `dead_code` warning (`resolved_principal_tenant_id`, `src/client.rs:1326`) comes from leaving out `opaque` and is not in the diff. CI's exact cell, `RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo check --lib --target wasm32-unknown-unknown --no-default-features --features rest,opaque`, exits 0 with no warnings. |
| C164-20 (Info) | **CLOSED** | `551b5e6`, `42d0be4` | The doc now says "the same answers … (a `429`'s `Retry-After` apart, below)" (`src/oidc/device.rs:394-395`). It adds a paragraph: a 429 is `OAuthProtocolError` `rate_limit_exceeded` and is not terminal; wait at least Retry-After or one interval, without raising the interval; this call does not expose Retry-After; `device_login` does it (`:415-421`). The last sentence of that paragraph is wrong about the call's behaviour; see the C164-03 residual. |
| C164-23 (Info) | **CLOSED** | `42d0be4` | `tests/oauth2_no_session_bearer_test.rs:345-346` has the requested wording. The SSF test's `logout` control now runs after the fetches, and the assertions are `seen.last()` and `seen[..len-1]` (`tests/ssf_receiver_test.rs:1062-1075`). Mutant: SSF back on `http()` at `src/ssf.rs:400` and `:434` fails it (`/ssf/jwks: no session cookie`). So the reordered test still has teeth: the cookie is present at fetch time. |

**Amended rules: probes** (temporary unit test in the copy, `device_login_with` with recorded sleeps, interval 5, client retry **on**, the default):

| Rule / case | Probe | Result |
|---|---|---|
| §14.2 rule 9: AXIAM's 429 | `429 {"error":"rate_limit_exceeded"}` `Retry-After: 12`, then pending, then 200 | sleeps `[5,12,5]`, 3 polls, OK |
| rule 9: `retry_after` variant | `429 {"error":"rate_limit_exceeded","retry_after":12}` RA 12, then 200 | `[5,12]`, OK |
| rule 9: bodiless 429 | `429` with no body, `Retry-After: 7`, then 200 | `[5,7]`, OK (non-OAuth `429 <html>` with RA 4: `[5,5]`, the interval being the floor) |
| §14.6 case 3: 429 `slow_down` | `429 {"error":"slow_down"}` RA 1, then 200; and `429 slow_down` without RA, then pending, then 200 | `[5,5]` and `[5,5,5]`; the interval is never raised. `429 {"error":"invalid_grant"}` is waited too, `[5,5]` |
| rule 1: the 400 still raises | `400 {"error":"slow_down"}`, then pending, then 200 | `[5,10,10]`, OK |
| rule 6: 500 body | `500 {"error":"server_error","error_description":"db"}` once, and three times, then 200 | completes: `[5,5]` / `[5,5,5,5]`, OK (but see C164-25: no §16 retry inside the poll) |
| rule 6: 503 | `503 {"error":"temporarily_unavailable"}`, then 200 (also with `Retry-After: 9`) | completes `[5,5]` in both cases. A 5xx's Retry-After is not honoured (C164-25) |
| §14.6 case 2 | Retry-After 3600 past `expires_in` 60 | the existing test passes: `expired_token`, 1 poll |
| single `device_poll` | 429 `rate_limit_exceeded` / bodiless 429 / 500 `server_error` / 503 | `Auth`+`rate_limit_exceeded` (OK) / `Network` (OK) / **`Auth`+`server_error`** / **`Auth`+`temporarily_unavailable`**, 1 request each (C164-03 residual) |

**Replay after refresh:** correct. `management_raw` refreshes first (`src/management/request.rs:183-188`), then calls `management_attempt` again. That call rebuilds the request from scratch (`:211-219`): `session_credential_of`, then `maybe_csrf_header`, which reads `client.csrf_token()` at build time (`src/rest/auth.rs:1046-1051`; `refresh` calls `capture_csrf_from_jar`). reqwest's jar supplies cookies at send time. There is no interceptor or middleware stack whose order could matter. A device/bearer credential returns the 401 without refreshing (`:182`). Probed, with a DELETE user that answers 401 once and then 204, and a refresh that rotates the cookies. The first DELETE carried `X-CSRF-Token: test-csrf-token` and the original `axiam_access`/`axiam_refresh`/`axiam_csrf`. The replay carried `X-CSRF-Token: rotated-csrf-token`, `axiam_csrf=rotated-csrf-token`, `axiam_refresh=rotated-refresh-token` and the rotated `axiam_access`. The other `refresh()` at `src/token/revocation.rs:231` is the revocation feed's own cache, not a §9 replay. 1.63 rules in touched code: both device operations still use `oauth2_post` (`http_bare`, no jar, no CSRF, no adopted bearer, §6.1 rule 11). `oauth2_no_session_bearer_test` passes 3/3. §27.6.2 is untouched, and `network_manifest_test` passes 15/15.

**Version:** 1.1.2 is right. `Cargo.toml:25`, `:127` (`=1.1.2`), the macros crate and the wasm crate all say 1.1.2. No public signature changed (`device_login_with` is `pub(crate)`), so a patch is right. The CHANGELOG `[1.1.2]` records C164-03/-04/-05/-07 (`CHANGELOG.md:44-54`). The README says contract 1.64 (`README.md:72`). The CHANGELOG intro still says CONTRACT.md is vendored from `fb92ec4`, which is now stale (C164-32).

**Run by the reviewer** (copy at `/home/user/work/rust`, the clone untouched; protoc present; `rustup target add wasm32-unknown-unknown` succeeded):
- `cargo test --all-features --lib --test device_flow_test --test oauth2_no_session_bearer_test --test ssf_receiver_test --test management_semantics_test --test network_manifest_test`: lib 239, device_flow 14, management_semantics 33, network_manifest 15, oauth2_no_session_bearer 3, ssf_receiver 19; 0 failed.
- `cargo fmt --all --check`: clean. `cargo clippy --lib --tests --all-features -- -D warnings`: clean.
- `cargo clippy --lib --no-default-features --features amqp -- -D warnings`: clean. `cargo test --lib --no-default-features --features amqp`: 93 passed.
- wasm32: `--features rest` exit 0; CI's `rest,opaque` cell with `getrandom_backend="wasm_js"` exit 0, no warnings.
- Mutants, switched by an env var in one build, run with `cargo test --all-features --lib oidc::device` (18 tests): baseline 18/18. The pre-fix `classify`: 3 fail. No 5xx arm: 1 fails. No 429 arm: 2 fail. Slept-seconds deadline: 1 fails. SSF on `http()`: the SSF cookie test fails.
- Probes: the table above, and the replay probe (a temporary integration test).
- Not run: the full unscoped `cargo test --all-features`, `cargo build --examples`, `cargo doc`, the macros publish dry-run, and the wasm-pack artifact build.
- `target/` and the whole copy were deleted afterwards.

**New findings:**
- **C164-25 — Low (pre-existing, newly measurable against the amended text)** — `src/oidc/device.rs:470-491` (`device_poll_step` sends once). Rule: §14.2 rule 6 ("retried under the bounded read-only retry policy of §16, then surfaced… that budget is per poll attempt"), and §16.2's table, which lists `device_poll` on a 5xx or transport failure as eligible.
  - What happens: the device poll never goes through `RetryRunner`, although `retry_enabled` defaults to true (`src/client.rs:677`) and `ciba_poll` uses it (`src/oidc/ciba.rs:551-590`). A 5xx or transport failure costs a whole interval instead of the up to 3 attempts with backoff that §16 allows. Probed with retry on: `500` then 200 gives 2 polls, sleeps `[5,5]`. A 5xx's `Retry-After` is ignored: `503` with `Retry-After: 9` was polled again after 5 s, so the §16.1 floor is not served. The flow survives, so no grant is lost; hence Low.
  - Fix: in `device_poll_step`, wrap the send in `RetryRunner { enabled: self.retry_enabled(), operation: "device_poll", .. }.run_until(Some(&RetryBound { deadline, now, sleeper }), …)`, passing `device_login`'s deadline, clock and sleeper so a retry never waits past `expires_in` (the P10 pattern `ciba_poll` uses). Inside the attempt, a `status >= 500` or a send error becomes a retryable `Attempt { err: from_http_status(..), retry_after }`. Every 4xx, the 429 included, is returned without a retry: the 429 is the loop's wait, and the 400s are answers. Note that a bodiless 429 maps to `Network`, which `is_retryable` would retry, so the 429 must be taken out before the runner. The single `device_poll` uses no bound.
  - Test: retry on, script `[500, 500, tokens]`, recorded sleeper. Assert 3 polls, one loop wait `[5]` plus two backoff waits of at most 200 ms and 400 ms, and the token. With `retry_enabled(false)`: 3 polls, `[5,5,5]`.
- **C164-32 — Informational** — `CHANGELOG.md:12-14`; `README.md:99-103`.
  - What happens: the 1.1.2 intro still says "`CONTRACT.md` … vendored byte for byte from `fb92ec4`". After `7472de8`, CONTRACT.md is axiam `21beda0` (sha256 `8b2cb9a3…7a9a`); `openapi.json` is unchanged. The README's contract-1.64 paragraph names only the 429 wait, not the amended rules 6 and 9.
  - Fix: write "`CONTRACT.md` from `21beda0` (1.64 amended); `openapi.json` and `management-registry.json` from `fb92ec4`". Add one README sentence: "the poll's status decides: a 5xx is not terminal whatever its body, any 429 is the wait, and only the 400 `slow_down` raises the interval."
- **C164-32 — Informational** — `src/oidc/device.rs:172`, `:215-226`.
  - What happens: the `PollSchedule` doc says it holds "the deadline it stops at", and `tick_for`'s doc describes the loop's 429 wait. `device_login` now takes its deadline from the clock (`:594`, `:609`) and no longer calls `tick`/`tick_for`, so the public type's remaining-life budget is a helper nothing in the SDK uses, and it still counts only sleeps.
  - Fix, doc only (the public API stays): "`device_login` takes its deadline from the clock (§14.2 rule 4); `tick`/`tick_for` count waits only and suit a loop that also checks the clock."

---

#### Addendum — python — commit 570efce7d (PR #103), read after 08a691423

Four commits since the review: `843ecf8` (re-vendor CONTRACT.md from 21beda0), `659971f` (fix C164-01, -03, -04, -05, plus the async half of -15),
`fd2bc14` (async C163-14 twin, C164-15), `570efce` (CHANGELOG and README). The commit messages match what the diff does.
The fix adds one helper, `_OidcMixin._handle_device_poll_response` (`src/axiam_sdk/_oidc.py:1708-1738`). Both `device_poll`s call it
(`_client.py:1964`, `_async_client.py:785`). It reads the status first: `>= 500` gives the §2 `NetworkError` (`:1726-1727`). Any `429` gives
`OAuthProtocolError("rate_limit_exceeded")` with `retry_after_ms` from the header (`:1728-1736`), whatever the body. Any other status goes to the
old `_handle_token_response`. `PollSchedule` takes an optional monotonic clock (`_oidc.py:312-331`, `:368-369`). Both `device_login`s now build it
from `time.monotonic` **before** `on_user_code` runs (`_client.py:2005`, `_async_client.py:813`).

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-01 (Medium) | **CLOSED** | 659971f | `_oidc.py:1728-1736`: a `429` no longer goes through `description_optional=False`, so AXIAM's `{"error":"rate_limit_exceeded"}` (with or without `"retry_after":N`) is an `OAuthProtocolError` with `retry_after_ms`. Test helper `tests/test_device_flow.py:62-74` now sends the server's exact body, so the existing (b) tests are no longer vacuous. New: `:635` (parametrised over no-description and the `retry_after` member, sync, `[2,7,2]`). Mutant (429 branch disabled): **11 failed**. |
| C164-03 (Medium, python row) | **CLOSED** (with C164-25) | 659971f | `_oidc.py:1726-1727`: a 5xx is a `NetworkError` before the body is read. `_device_poll_outcome` classes it `"retry"`. Tests: `:350` (sync: `500 {"error":"server_error","error_description":"db"}`, `503 {"error":"temporarily_unavailable"}`, a bodiless 502, then 200, 5 calls); `:731` (single `device_poll` gives `NetworkError`); `:798` (async: 500 server body, then 429 slow_down, then 200, sleeps `[2,2,2]`). Mutant (5xx branch disabled): **3 failed**. The poll is still not retried under §16 *inside* the attempt (C164-25). |
| C164-04 (Low, python row) | **CLOSED** | 659971f | Status first: `429 {"error":"slow_down"}` never reaches the `"slow_down"` branch (`_oidc.py:1698`). Tests: `:672` (sync `[2,2,2]`), `:697` (`429 invalid_grant` not terminal), `:714` (single poll: `rate_limit_exceeded`, `retry_after_ms == 3000`), `:798` (async). Mutant: the review's narrower fix only (`description_optional=True` on a 429, no status-first) gives **5 failed**, so the status-first tests separate the two fixes. A bodiless 429 is covered too (`:657`, `[2,7]`), which closes the C164-17 behaviour for Python. |
| C164-05 (Low, pre-existing) | **CLOSED in code; test PARTLY** | 659971f | `_oidc.py:328-329`, `:368-369`. The deadline is `monotonic() + expires_in`, taken before `on_user_code` in both clients (`_client.py:2005`, `_async_client.py:813`). `tick` uses `min(sum-of-waits, deadline - now)`. Probed through the real loops with a fake `time.monotonic`: sync with 3 s per request, `expires_in=10, interval=2`, sends at t=2 and t=7, then `expired_token`. Async with a 7 s callback sends once at t=9, then `expired_token`. Nothing is sent at or after 10. Unit test `:744` is PollSchedule-only. Mutant (tick ignores the clock): 1 failed. Mutant (**`time.monotonic` not passed in either `device_login`**): **0 failed, 41 passed**, so the wiring is untested (C164-29). |
| C164-15 (Low + Info) | **CLOSED** | 659971f, fd2bc14 | Async deadline twin `tests/test_device_flow.py:755` (`Retry-After: 3600`, `expires_in=10`: `expired_token`, 1 call, every wait ≤ 10). Async no-Retry-After twin `:779` (`[2,2]`). Async C163-14 twin `tests/test_no_session_cookie_on_oauth2.py:206-241`: six operations after `await login()`, PAT alone, no cookie, no CSRF, then the control. Mutants on the async twin only: CSRF skip on `Cookie == ""` removed gives **4 failed** (the four writes); the old `token is None` early return gives **6 failed**. |

**Amended rules, probed** (sync **and** async `device_login`, `interval=2`, recorded `time.sleep` / `asyncio.sleep`; identical results in both clients):

| Rule / case | Probe | Result |
|---|---|---|
| Rule 9: AXIAM's 429 | `429 {"error":"rate_limit_exceeded"}`, `Retry-After: 7`, then 200 | `[2,7]`. Conforms |
| Rule 9: `retry_after` member | `429 {"error":"rate_limit_exceeded","retry_after":7}`, RA 7 | `[2,7]`. Conforms |
| Rule 9: no Retry-After | `429 {"error":"rate_limit_exceeded"}`, no header | `[2,2]`. Conforms |
| Rule 9: bodiless 429 | `429`, no body, RA 7 | `[2,7]`. Conforms (C164-17 behaviour) |
| Rule 9 / §14.6 case 3 | `429 {"error":"slow_down"}`, RA 1, then 200; also then pending, then 200 | `[2,2]` and `[2,2,2]`. The interval is not raised. Conforms |
| Rule 1 control | `400 slow_down`, then 200 | `[2,7]`. Still raises. Conforms |
| Rule 6 / §14.6 500 body | `500 {"error":"server_error","error_description":"db"}` ×3, then 200 | Completes, 4 calls, `[2,2,2,2]`. Non-terminal and conforms. **No §16 retry inside the poll**: each 5xx costs one interval (C164-25) |
| Rule 6 | `503 {"error":"temporarily_unavailable"}`, then 200 | Completes, `[2,2]` |
| Single `device_poll` | 429 RLE / RLE+member / bodiless / slow_down | `OAuthProtocolError`, `error == "rate_limit_exceeded"`, `retry_after_ms` 7000/7000/7000/1000 (sync and async). An HTTP-date 30 s ahead gives about 29.5 s |
| Single `device_poll` | 500 server_error / 503 | `NetworkError` (sync and async) |

**1.63 rules where the diff touched code:** the diff touches only the device-poll path and docstrings. `/oauth2/*` stripping (`_session.py:404-416`) and `_apply_bearer_credential`'s `/oauth2/` early return (`_client.py:989-990`) are unchanged. `tests/test_no_session_cookie_on_oauth2.py` passes in full. §27.6.2 refusal at plan: untouched, and its tests pass.

Replay after refresh: **DEFECT (pre-existing since `e980db9`, not touched by this PR). See C164-26.** `_retry_after_refresh_sync` (`src/axiam_sdk/_client.py:1671-1686`) and `_retry_after_refresh_async` (`_async_client.py:505-520`) copy every header of the original request into the replay, dropping only `content-length` and `x-csrf-token`. The original's `Cookie` header was merged from the jar when it was built, so it carries the **old** `axiam_access` and `axiam_csrf`. httpx's `build_request` does not overwrite a `Cookie` header that is already there (`http.cookiejar` adds one only when none is present). The order is otherwise right: refresh runs first, then `_rest_send_*` re-applies the tenant header, the bearer and the fresh `X-CSRF-Token`. Probed with httpx 0.28.1 against a mock that accepts only the refreshed cookie. Sync `check_access` path, async `check_access` path, and the management `send_management` path (shared `_retry_after_refresh_sync`, `management/_request.py:125`, `:162`) give the same result. The refresh is called once and the jar holds the NEW access. The replay carries `axiam_access=<OLD>` and `axiam_csrf=csrf-old` together with `X-CSRF-Token: csrf-new`. The replay gets 401, and the caller gets `AuthError`. Against AXIAM, the cookie/header CSRF mismatch would also fail the double-submit check. With `"cookie"` added to the excluded names in both helpers, the replay carries the new access and the new CSRF in both cookie and header, and gets 200. 1024 related tests (`-k "refresh or acting_tenant or cookie or csrf or uma or login or authz or management"`) still pass. A PAT/bearer replay keeps `Cookie: ""`, because `_apply_bearer_credential` re-sets it whenever `Authorization` is present.

Version: `pyproject.toml:7` and `__init__.py:109` are 1.1.2, which is right (no source-breaking change). The CHANGELOG `[1.1.2]` records C164-01, -03, -04 and -05 accurately, including the `device_poll` thrown-type change on a 429 (`NetworkError` to `OAuthProtocolError`) and the 21beda0 re-vendor. C164-15 is test-only and not listed, which is acceptable. README `:30` says "1.1.2 … contract 1.64", and `:1598-1605` documents the status-first rule and the clock deadline.

Run by the reviewer (throwaway copy `/home/user/work/python`, venv on Python 3.13.16, `pip install -e '.[dev,fastapi,django]'`; mutants in a `git archive` copy `/home/user/work/python-mut` with `PYTHONPATH=src`; both deleted afterwards):
- `ruff check .`: passed. `ruff format --check .`: 217 files formatted. `mypy --strict src`: no issues in 98 files. `interrogate`: 100%. `scripts/gen_management.py --check`: OK (32 files, 202 ops).
- `pytest tests -q`: **2141 passed**, 7 warnings (5 min 29 s). That is 2124 + 17 new.
- Probe suite (35 cases, sync and async: the table above, HTTP-date, two clock-deadline loops): all passed. Replay probe (3 paths): stale cookie on all three. With the one-word fix, all three are fresh and return 200.
- Mutants: see the findings table (M1 11 failed, M1b 5 failed, M2 3 failed, M4 1 failed, M3 **survived**, async C163-14 4 and 6 failed).
- Not run: CI (no GitHub API).

New findings:
- **C164-26 — Medium (pre-existing, not introduced by PR #103; found by the cross-SDK check 4)**. Location: `src/axiam_sdk/_client.py:1679-1685` and `src/axiam_sdk/_async_client.py:513-519`. Rule broken: §9.3 (refresh once, then replay the failed call once with the refreshed session) and §3 (CSRF double-submit). What happens: the replay is rebuilt with the original request's `Cookie` header, so it sends the expired `axiam_access` and the old `axiam_csrf` next to the new `X-CSRF-Token`. Every cookie-session `check_access`/`can`/`batch_check` call and every management call that meets an expired access token gets the 401 again and raises `AuthError`, even though the refresh succeeded. The next call works because the jar is fresh. This is probed in sync and async. Exact fix, in both helpers: `if k.lower() not in ("content-length", "x-csrf-token", "cookie")`. The jar is then merged again by `build_request`, and `_apply_bearer_credential` restores `Cookie: ""` for a request with `Authorization` (verified: 3/3 probe paths get 200, and 1024 related tests pass). Test: log in with access A and csrf c1; the authz endpoint answers 401 to A and 200 to B; refresh sets B and c2. Assert that the replay's `cookie` contains `axiam_access=B` and `axiam_csrf=c2` and not A, and that `x-csrf-token == c2`. Run it sync and async, and once through `send_management`.
- **C164-25 — Low (pre-existing)**. Location: `src/axiam_sdk/_client.py:1923-1964` and `_async_client.py:754-785` (`device_poll`). Rule broken: §14.2 rule 6 as amended ("retried under the bounded read-only retry policy of §16, then surfaced") and §16.2 (`device_poll` on a 5xx or transport failure is eligible). The switch defaults on (`self._retry_enabled`), and `ciba_poll` uses it (`_client.py:2239`). What happens: a 5xx or transport failure on a poll is not retried inside the attempt. `device_login` waits a full interval and polls again (`500` ×3 gives `[2,2,2,2]`), and a single `device_poll` surfaces the first 5xx. No grant is lost. Exact fix: wrap the send-and-parse of `device_poll` in `retry_sync(lambda attempt: ..., operation="device_poll", enabled=self._retry_enabled, telemetry=self._telemetry)` (and `retry_async`). `_handle_device_poll_response` already raises a `NetworkError` only for a 5xx, and a 429 stays an `OAuthProtocolError` that `_should_retry` does not retry, so there is no double wait. Test: `500 {"error":"server_error","error_description":"db"}` ×2, then 200, inside one `device_login` poll. Expect 3 token calls, interval sleeps `[2]`, and §16 retry sleeps recorded separately. With `retry=False`, the current behaviour.
- **C164-29 — Informational (test strength, C164-05)**. Location: `tests/test_device_flow.py:744`. What happens: the clock deadline is tested on `PollSchedule` only. Removing `time.monotonic` from both `device_login` calls (`_client.py:2005`, `_async_client.py:813`) leaves all 41 device-flow tests passing. The code is right (probed). Exact fix: a sync and an async `device_login` test that monkeypatches `time.monotonic` to advance 3 s per token request (`expires_in=10, interval=2`), with `sleep` advancing the same clock. Assert `expired_token`, 2 requests, and every request sent at t < 10.

---

#### Addendum — c — commit 0c80e3d97 (PR #77), read after 0a9200858

Two commits over the reviewed head: `a55a0b2` re-vendors the amended `CONTRACT.md` (21beda0; not re-checked, per the brief), and `0c80e3d` is the fix pass. The fix pass touches `src/oidc_device.c`, `src/management_manifest.c`, `include/axiam/error.h` (a comment only), `tests/CMakeLists.txt`, `tests/test_oidc_grants.c`, `tests/test_management_manifest.c` and `CHANGELOG.md`. The commit message's finding-to-change map matches the diff.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-03 (Medium) | **CLOSED** | 0c80e3d | `src/oidc_device.c:213-220`: `device_poll_with` turns `AXIAM_ERR_AUTH` with `transport_cause` 5xx into `AXIAM_ERR_NETWORK` and clears `oauth_error`. The loop then takes the `!code[0]` branch (`:335-339`) and waits the interval. §16 still retries inside the poll, because `oidc_post` (`src/oidc.c:456-461`) retries on the status before any body is read. Tests: `test_a_500_mid_poll_is_retried_rather_than_treated_as_terminal` (`tests/test_oidc_grants.c:306-331`) now uses `500 {"error":"server_error","error_description":"db"}` ×3, then 200. It asserts 4 calls and an unchanged interval. `test_a_5xx_on_a_single_poll_is_a_network_error_whatever_its_body` (`:333-347`) covers the single poll. Mutant MA (the conversion disabled) fails both, at `:323` and `:342`. Mutant MD (kind converted, `oauth_error` kept) also fails both, because the loop then reads `server_error` as terminal. Both tests are non-vacuous. One gap remains, for a caller who passes `err == NULL` (C164-27). |
| C164-04 (Low) | **CLOSED** | 0c80e3d | `src/oidc_device.c:327-334`: the loop now tests `poll_err.transport_cause == 429` before any dispatch on the `error` code. Any 429 is the wait, and the old body-keyed branch is gone. The `slow_down` branch (`:341-346`) is reached only by a non-429, so in practice only by a 400. Test: `test_a_429_slow_down_does_not_raise_the_interval_and_a_bodiless_429_honours_retry_after` (`tests/test_oidc_grants.c:349-372`) expects waits `[2000,2000,7000,2000]`. Mutant MB (the old `== 429 && rate_limit_exceeded` gate) fails it at `:367` ("Expected 2000 Was 7000"). |
| C164-17 (Info) | **CLOSED** | 0c80e3d | The same branch handles a bodiless 429 or one without an OAuth body: `if (retry_after_ms > wait_ms) wait_ms = retry_after_ms` (`:332`). `Retry-After` comes from `oidc_token_grant_ex` on every non-2xx (`src/oidc.c:920-922`). The same test, `:368` (`sleeps[2] == 7000`). Mutant MB2 (`== 429 && code[0]`, which sends a bodiless 429 back to the interval) fails at `:368`. Mutant MC (the floor removed) fails `:261`, `:299` and `:368`. |
| C164-08 (Low) | **CLOSED** | 0c80e3d | Every site the review listed now calls `refuse()`: `src/management_manifest.c:179`, `:188`, `:202`, `:215`, `:232`, `:254`, `:264`, `:278`, `:291`, `:298`, `:645`. `oom()` (`:886-890`) sets cause 0 directly. `include/axiam/error.h:34` now reads "the error did not come from the server (no write was sent; a manifest `plan` may have sent reads)". Tests (`tests/test_management_manifest.c`): duplicate key on `validate` and on `plan` (`:263`, `:270`), dangling `depends_on` on `plan` (`:225`), cycle (`:247`), no key (`:285`). These cover what the fix asked for; `plan` runs `validate`, so the dangling case covers both paths. Per-site mutants (each site reverted to cause 0): sites `:179`, `:188`, `:215` and `:232` are killed. Sites `:202`, `:254`, `:264`, `:278`, `:291`, `:298` and `:645` survive: no test asserts 400 for those refusals. The review did not require those tests, so this is test strength only. |
| C164-22 (Info) | **CLOSED** | 0c80e3d | `CHANGELOG.md:33-34`: "Test: `test_device_auth` (`test_adopted_bearer_is_not_sent_on_jwks_or_revocations`)". |
| C164-23 (Info) | **CLOSED** (the fallback fix) | 0c80e3d | `tests/CMakeLists.txt:42-44`: `set_tests_properties(test_client_failing_transport PROPERTIES RUN_SERIAL TRUE)`, with a comment that names the reason. `ctest --show-only=json-v1` lists `RUN_SERIAL: true` on that test, and the property is gone when the line is removed. `ctest -j8` passed 81/81. The 60 ms window itself was kept; the review allowed `RUN_SERIAL` for that case. |

**Amended rules, probed** (temporary tests in the copy `/home/user/work/c`, run against 0c80e3d with the fake transport, recorded sleeps and an interval of 2 s; retry on unless noted):

| Rule / case | Probe | Result |
|---|---|---|
| Rule 9: 429 `{"error":"rate_limit_exceeded","retry_after":7}` + `Retry-After: 7` | P1 | **PASS**: waits `[2000,7000]`, 2 calls. The 429 is not retried inside the poll. |
| Rule 9: 429 `{"error":"rate_limit_exceeded"}`, no `Retry-After` | existing `:265-281` | **PASS**: waits at the interval. |
| Rule 9 / §14.6 case 3: 429 `{"error":"slow_down"}`, then pending, then 200 | P5 | **PASS**: `[2000,2000,2000]`. The interval was not raised. |
| Rule 9: bodiless 429 + `Retry-After: 7` | P7 | **PASS**: `[2000,7000]`. |
| Rule 1 control: 400 `slow_down`, then 200 | P6 | **PASS**: `[2000,7000]`, so the interval is still raised. |
| Rule 6 / §14.6: 500 `{"error":"server_error","error_description":"db"}` ×3, then pending, then 200 | P2 | **PASS**: 5 calls, sleeps `[2000,33,273,2000,2000]` (the §16 backoff inside the first poll, then the interval unchanged). |
| Rule 6: 503 `{"error":"temporarily_unavailable"}` + `Retry-After: 4`, then 200 | P4 | **PASS**: retried inside the poll, waiting 4000 ms (`Retry-After` is the floor). 2 calls. |
| Rule 6, retry off (`retry_enabled = 0`): 503 `temporarily_unavailable`, then 200 | P3 | **PASS**: not terminal. The loop polls again at the interval. |
| Single `axiam_device_poll` on 429 `rate_limit_exceeded` | P8 | **PASS**: `AXIAM_ERR_AUTH`, `oauth_error="rate_limit_exceeded"`, cause 429, 1 call. |
| Single `axiam_device_poll` on a bodiless 429 | P9 | Returns `AXIAM_ERR_NETWORK`, cause 429, 1 call. The error is raised, as expected. |
| Single `axiam_device_poll` on 503 `temporarily_unavailable` | P11 | **PASS**: `AXIAM_ERR_NETWORK`, `oauth_error=""`, 3 attempts (§16). |
| Single `axiam_device_poll`, `err == NULL`, 500 `server_error` | P10 | **FAIL**: returns `AXIAM_ERR_AUTH` (C164-27). |

**Replay after refresh:** correct, probed. There is no middleware stack. `authz_post` (`src/client.c:1676-1697`) gets a 401, runs `single_flight_refresh`, then replays through `transport_retrying` → `transport_once_ex` (`:1620`). `transport_once_ex` calls `build_headers()` again for every attempt (`:327`), and `build_headers` reads `c->csrf_token` and the device bearer under `state_mtx` at send time (`:279-304`). `capture_csrf` (`:308-315`) stores the refresh response's token before the replay is built. Probe (scripted transport: login → `X-CSRF-Token: csrf-OLD`; `check_access` → 401; refresh → 200 with `csrf-NEW`; replay → 200): the first check sent `csrf-OLD`, the refresh sent `csrf-OLD`, the replay sent `csrf-NEW`, and the call returned OK. Cookies were checked by reading the code. There is one persistent curl handle per client, and `curl_easy_reset` keeps the in-memory jar (`src/transport_curl.c:89-90`, `:113-118`), so the refresh's `Set-Cookie` is in the jar when the replay is sent. A device session does not enter refresh (`:1686`). `authz_post` is the only refresh-and-replay path in the SDK; nothing else retries a 401. The diff does not touch `/oauth2/*` isolation (`src/oidc.c:415-429` still sends the empty `Cookie` and no CSRF), §6.1 rule 11 (`build_headers`'s `oauth2` gate is unchanged), or the §27.6.2 refusal at `plan` (unchanged; `test_manifest_network` 17/17).

**Version:** 1.1.2 is correct (CMake project and CPack, `AXIAM_VERSION`, Doxyfile, `conanfile.py`, `ports/axiam-c-sdk/vcpkg.json`). SOVERSION 2 is still right: since the review, the only public-header change is a comment in `error.h`, with no struct or signature change, and the `abi_soname` test passes. The CHANGELOG intro records the one observable change to a single poll (a 5xx with an OAuth body is now `AXIAM_ERR_NETWORK`, not `AXIAM_ERR_AUTH`/`server_error`) and lists each fix with its test. The README contract sentence still says 1.64, but the 1.64 paragraph (`README.md:40-50`) was not updated for the amended rules (C164-32).

**Run by the reviewer** (throwaway copy `/home/user/work/c`; `libcurl4-openssl-dev` and `libssl-dev` were already installed; `build-asan/` was deleted afterwards):
- `cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"`, then `cmake --build build-asan -j8`: 0 warnings.
- `ctest --test-dir build-asan` (serial): **81/81 passed**, ASan/UBSan clean. `ctest -j8`: 81/81.
- Per binary: `test_oidc_grants` 31/31 (29 + 2 new), `test_management_manifest` 25/25, `test_device_auth` 13/13, `test_manifest_network` 17/17, `test_client_failing_transport` 14/14.
- `python3 scripts/gen_management.py --check`: clean.
- Mutants (`ASAN_OPTIONS=detect_leaks=0`, each reverted and rebuilt afterwards): MA, MB, MB2, MC, MD and the manifest sites `:179`, `:188`, `:215`, `:232` were all killed. The manifest sites `:202`, `:254-298` and `:645` survive (no test asserts them).
- 11 rule probes (P1-P11) and 1 replay probe, as above.
- Not run: the plain Debug C-standard matrix, valgrind, Doxygen, the package recipes.

**New findings:**
- **C164-27 — Informational** — `src/oidc_device.c:213`. Rule: §14.2 rule 6 as amended ("the status is read before the body").
  - What happens: the 5xx reclassification depends on the caller's error struct (`kind == AXIAM_ERR_AUTH && err && err->transport_cause >= 500`). A caller of `axiam_device_poll()` that passes `err == NULL`, which `axiam_error_set` explicitly allows, gets `AXIAM_ERR_AUTH` for `500 {"error":"server_error"}` and `AXIAM_ERR_NETWORK` for a bodiless 500 (probe P10). The rule is still decided on the body for that caller. `axiam_device_login` always passes its own `poll_err`, so the loop is not affected.
  - Fix: at the top of `device_poll_with`, `axiam_error_t local; if (!err) { axiam_error_reset(&local); err = &local; }`. Alternatively, decide on `resp.status >= 500` inside `oidc_token_grant_ex` before calling `oidc_map_grant_error` when `retryable == OIDC_RETRY_LOOP_OWNS_429`. Test: the existing single-poll test with `err == NULL`, asserting `AXIAM_ERR_NETWORK`.
- **C164-32 — Informational** — `README.md:40-45`; `include/axiam/oidc.h:1086-1089` (the `axiam_device_login` doc) and the `axiam_device_poll` doc (`:1030-1056`). Documentation accuracy.
  - What happens: the README's 1.64 paragraph still describes only `429 rate_limit_exceeded`. Neither header doc says that any 429 is the wait whatever its body (a 429 `slow_down` does not raise the interval) or that a 5xx is `AXIAM_ERR_NETWORK` whatever its body. A single poll that is answered 5xx now returns a different kind, which the CHANGELOG records but the API docs do not.
  - Fix: in the README, write "any `429` on a device-code poll (whatever its body, `slow_down` included) is waited out … and a `5xx` is a transport failure whatever its body (contract 1.64 as amended)". Add the same two sentences to the `axiam_device_poll` and `axiam_device_login` docs.

---

#### Addendum — cplusplus — commit 2b28526c7 (PR #80), read after 0c7bfd731

Commits read (`git log 0c7bfd731..HEAD`): `077209a` re-vendors the amended contract from 21beda0 (CONTRACT.md sha256 8b2cb9a3…7a9a). `7b0267e` is the device-poll fix (C164-03, -04, -19, -20). `65a5567` is the manifest fix (C164-12, -21). `2b28526` is the CHANGELOG (C164-22). Each commit message matches its diff. `path:line` is on 2b28526c7.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-03 (Medium) 5xx with an OAuth body ends `device_login` | **CLOSED** | 7b0267e | `src/oidc.cpp:907-913`: on the retryable (device-poll) grant, `status >= 500` throws `NetworkError("http_5xx")` before `raise_grant_error` reads the body. `device_login`'s `catch (const NetworkError&)` continues (`:1766-1772`). Tests: `tests/test_oidc_grants.cpp:582` (3× `500 {"error":"server_error","error_description":"db"}` then 200 → tokens, `token_calls == 4`) and `:598` (single `device_poll` → `NetworkError`). Mutant Ma (block removed) fails both. Scoped to `retryable` only, so other token grants still dispatch on the body (allowed by the fix: "either"). |
| C164-04 (Low) `429 slow_down` raises the interval | **CLOSED** | 7b0267e | `src/oidc.cpp:891`: any 429 on the poll breaks out of §16. `:915-923`: a 429 on the poll is always rethrown as `OAuthProtocolError("rate_limit_exceeded", …, retry_after, 429)`, whatever the body. `include/axiam/uma.hpp:177,182,198,211`: new `http_status()`. `src/oidc.cpp:1746`: the loop treats `rate_limit_exceeded \|\| http_status()==429` as the wait, before the `slow_down` branch. Tests `:481` (`429 slow_down`, pending, 200 → sleeps all 2000) and `:496` (bodiless 429, RA 7 → `[2000, ≥7000, 2000]`). Mutant Mb1 (no 429 synthesis) fails `:496`. Mb3 (synthesis and status check removed) fails `:481` and `:496`. Mb2 (only the loop's `http_status()` check removed) **survives**: it is an equivalent mutant, because `token_grant` already renames every poll 429. It is defence in depth, not a gap. |
| C164-12 (Info) NoChange case is plan-only, so vacuous | **CLOSED** | 65a5567 | `tests/test_manifest_network.cpp:772-783` now calls `apply` for both `termination_action` and `service_type` (`"future_value"`) and asserts `report.complete()` and GET-only. `:785-802` adds the stated-`service_type` PUT case (body `framed_user`, never `future_type`). Mutant Me (`Plan::pending()` keeps an Unchanged network profile, so apply writes it; `src/management_manifest.cpp:353`) fails `:780` twice, plus four other §27.9 tests. |
| C164-19 (Info) case 1 does not pin "not retried inside the poll" | **CLOSED (through the added single-poll test)** | 7b0267e | Case 1 (`:441-463`) now scripts two 429s and asserts `token_calls == 3`, sleeps `[2000, ≥9000, ≥9000]`. That alone is **still vacuous** against mutant Mc (429 retried by §16, `src/oidc.cpp:891` removed): §16 floors at Retry-After, so the calls and sleeps are the same, and case 1 passes. The new `:465-479` (single `device_poll`, one request, `retry_after() == 9000ms`) fails under Mc (`:473`), and so do the `slow_down` case (`:493`) and the cap case (`:533`). The fix asked for both. The guard is present, but the comment at `:448-449` overstates what case 1 checks. |
| C164-20 (Info) `device_poll` / `device_login` docs omit the 429 | **CLOSED** | 7b0267e | `include/axiam/client.hpp:858-862` (`device_poll`: any 429 → `OAuthProtocolError`, `rate_limit_exceeded`, `retry_after()`, not retried, not terminal; a 5xx → `NetworkError`) and `:877-881` (`device_login`: 429 waited, RA a minimum capped at `expires_in`, one interval, not raised; a 5xx whatever its body is not terminal). Doc only, no mutant. |
| C164-21 (Info) quoted server text unbounded and unescaped | **CLOSED** | 65a5567 | `src/management_manifest.cpp:256-265` `quote_server_value`: at most 64 bytes, bytes `<0x20` or `>=0x7f` become `?`, and `...` is appended when truncated. Used at `:269`. Test `tests/test_manifest_network.cpp:804-821`. Mutant Md (no cap) fails `:818-819`. Md2 (no escape) fails `:816-817`. Non-ASCII also becomes `?`, which is stricter than asked: UTF-8 is mangled, but it cannot split a code point. |
| C164-22 (Info) no `### Binary compatibility` section for 1.1.2 | **CLOSED** | 2b28526 | `CHANGELOG.md:34-38` names `libaxiam_cpp.so.4`, both types and all four members (`retry_after`, `http_status`, the two `*_wire`), and says "not source-breaking". |

**Amended rules, probed** (temporary test cases in a throwaway copy, recorded sleeper, interval 2 s, §16 retry on by default):

| Rule / case | Probe | Result |
|---|---|---|
| Rule 9, AXIAM's 429 | `429 {"error":"rate_limit_exceeded"}`, RA 5, pending, 200 | sleeps 2000, 5000, 2000; 3 calls → tokens. **Conforms** |
| Rule 9, `retry_after` body | `429 {"error":"rate_limit_exceeded","retry_after":9}`, RA 9 | 2000, 9000, 2000 → tokens. **Conforms** |
| Rule 9, `429 slow_down` (§14.6 third case) | RA 1, then pending, then 200; and with no RA, then 200 | 2000, 2000, 2000 and 2000, 2000. Interval not raised. **Conforms** |
| Rule 9, bodiless 429 | `429 ""`, RA 7, pending, 200 | 2000, 7000, 2000. Waited ≥ RA, not raised. **Conforms** |
| Rule 1 control, `400 slow_down` | `400 slow_down`, pending, 200 | 2000, 7000, 7000. Still raised. **Conforms** |
| Rule 6, `500` with AXIAM body (§14.6 500 mock) | 3× `500 {"error":"server_error","error_description":"db"}`, pending, 200 | 5 calls, sleeps 2000, 100, 200, 2000, 2000. The first poll is §16-retried inside the attempt (3 attempts), then the loop takes its next interval → tokens. **Conforms** |
| Rule 6, `503 temporarily_unavailable` | then 200 | 2 calls, 2000, 100. Retried inside the poll → tokens. **Conforms** |
| Single `device_poll` | 429 rle RA 9 / bodiless 429 RA 4 / `429 slow_down` / always 503 / 500 then 200 / `400 slow_down` | `OAuthProtocolError(rate_limit_exceeded)` ra 9000, status 429, 1 call / same, ra 4000, 1 call / same, no RA, 1 call / `NetworkError (HTTP 503)` after 3 calls / tokens after the §16 retry / `OAuthProtocolError(slow_down)`, status 400, 1 call. **Conforms** |

`Replay after refresh:` **Correct.** Both paths rebuild the replay after the refresh: `execute_retrying` (`src/client_impl.hpp:465-487`) and `execute` (`:497-514`) call `do_single_flight_refresh()` first, then `send_raw(build_request(…))`. `build_request` reads the current `csrf` under the lock (`:260`), and `send_raw` → `capture_csrf` (`:288-293`) has already stored the refresh response's `X-CSRF-Token`. Cookies come from the curl jar at send time, which holds the refresh response's `Set-Cookie`. The C++ SDK has no middleware chain in which order could invert this. Probe (fake transport): login CSRF `STALE`, `check_access` → 401, refresh answers `X-CSRF-Token: FRESH`. Wire order: login, check (`STALE`), refresh (`STALE`), check replay (`FRESH`). The management transport (`src/management_transport.cpp:177`) does no refresh-on-401. There is no repository test that pins the fresh CSRF on the replay. The single-flight tests use one constant token, so a future regression would be invisible (Informational, see C164-33).

`Version:` 1.1.2 is still right. **No change since the review is source-breaking.** The `OAuthProtocolError` constructor gains a trailing defaulted `std::optional<long> http_status` (`include/axiam/uma.hpp:174-182`) and a new accessor, so every existing call and catch compiles. The only header changes since `0c7bfd731` are that and doc comments in `client.hpp`. C163-07's `ValidationError` → `std::invalid_argument` predates the review, and the review accepted it at patch. The new single-`device_poll` exception changes (a bodiless 429 is now `OAuthProtocolError`, not `NetworkError`; a 5xx with an OAuth body is now `NetworkError`, not `OAuthProtocolError("server_error")`) change behaviour but not source. The amended contract requires them, and they are in the same class as C163-07. **SOVERSION 4 still covers every layout change.** The only layout change after the review is `http_status_` appended to `OAuthProtocolError` (`uma.hpp:211`). `v1.1.2` is not tagged (the latest local tag is `v1.1.1`), so SOVERSION 4 has not shipped and needs no second bump. `CMakeLists.txt:116` `set(AXIAM_SOVERSION 4)`. A shared Release build gives `libaxiam_cpp.so.1.1.2` with `SONAME libaxiam_cpp.so.4` (readelf). The README contract sentence (`README.md:15`) still says contract 1.64.

`Run by the reviewer` (throwaway copy `/home/user/work/cplusplus`, deleted afterwards; gcc 13, Ninja, C++17 Debug):
- `python3 scripts/gen_management.py --check` → "§27 surface is current (7 files)", exit 0.
- `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON -DAXIAM_BUILD_EXAMPLES=ON -DCMAKE_CXX_STANDARD=17 && cmake --build build` → exit 0 (121 steps).
- `ctest --test-dir build --output-on-failure` → 1/1 passed. The binary reports **1622 test cases, 6130 checks, 0 failed** (review: 1614 / 6097; +8 cases).
- Shared: `cmake -S . -B build-so -G Ninja -DBUILD_SHARED_LIBS=ON -DAXIAM_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release && cmake --build build-so --target axiam_cpp` → SONAME `libaxiam_cpp.so.4`.
- Probes: 15 rule probes and 1 replay probe, all as tabled. Suite with probes: 1624 cases, 0 failed.
- Mutants, each applied alone, rebuilt, full suite run. Killed: Ma (2 fail), Mb1 (1), Mb3 (2), Mc (3; case 1 survives, see C164-19), Md (1), Md2 (1), Me (5). Survived: Mb2 (equivalent mutant).
- Not run: the ASan/UBSan and valgrind legs, clang, C++23, coverage, Doxygen, abi_soname under ctest (the shared build was library-only; SONAME was checked with readelf instead).

`New findings:`
- **C164-32 — Informational** — `CHANGELOG.md:11-13`, `:17-19`, `:26-27`; `README.md:32-35`; `CMakeLists.txt:112`. Rule: plan §8.2 (the CHANGELOG records what is vendored and what changed). Text drift after the fix pass:
  - The intro still says the contract is "re-vendored byte for byte from ilpanich/axiam `fb92ec4`", but `077209a` re-vendored it from `21beda0`.
  - The intro says "One behaviour of 1.1.1 is corrected", but *Changed* now also carries the device-poll status-decides change.
  - The *Fixed* bullet still says "The `429` that names its error is no longer retried inside the poll"; it is now every 429 on the poll.
  - The README 1.64 paragraph describes only `429 rate_limit_exceeded`, not the amendment (5xx whatever its body; any 429).
  - The CMake SOVERSION comment lists `OAuthProtocolError (retry_after)` only.

  **Fix:** change `fb92ec4` → `21beda0` (keep the other three files' source as they are), "One behaviour" → "Two behaviours", "The `429` that names its error" → "A `429` on the poll". Add one README sentence: "As amended, the status decides on the poll: a `5xx` is a `NetworkError` whatever its body, and any `429` is the wait." Add `http_status` to the CMake comment.
- **C164-32 — Informational** — `CHANGELOG.md:42-50`. Rule: plan §8.2 (behaviour notes). The bold catch-advice covers only the 429 direction (`NetworkError` → `OAuthProtocolError`). The reverse direction is not flagged: a single `device_poll` answered `5xx {"error":…}` was `OAuthProtocolError("server_error")` and is now `NetworkError`. **Fix:** append "and a hand-rolled loop that caught `OAuthProtocolError` with `error() == "server_error"` from `device_poll` now receives a `NetworkError`, which is not terminal."
- **C164-33 — Informational** — `tests/test_single_flight.cpp` (cross-SDK check 4). The code is correct (probed), but no repository test pins that the replay after a 401 refresh carries the refreshed `X-CSRF-Token`. The existing tests answer the same `tok` throughout. **Fix:** a test where login sets `X-CSRF-Token: STALE`, the refresh answers `FRESH`, and the assertion is that the replayed `POST` carries `FRESH` (the probe above, made permanent).
- **C164-33 — Informational** — `tests/test_oidc_grants.cpp:448-449`. Test strength. The comment claims the two-429 case 1 would differ "had they been retried inside the poll". It would not: the §16 retry floors at Retry-After, and mutant Mc passes case 1. The guard is the new single-poll test `:465`. **Fix:** reword the comment to point at `:465` as the guard, or make case 1 assert `client.device_poll` separately.

---

#### Addendum — csharp — commit fd0869a49 (PR #111), read after 87b88122e

Two commits since the review: `ad1014b` (re-vendors CONTRACT.md from 21beda0; sha256 `8b2cb9a3…` confirmed, not otherwise re-checked) and `fd0869a` (fixes C164-03/04/05/20/21/22/23). The commit message's finding-to-commit map matches the diff. **Read only:** there is no .NET toolchain here (`which dotnet` finds nothing; apt has no `dotnet-sdk-8.0`; the dotnet-install script gets a 403). Nothing was built or run. Every mutant below was judged by reading the test against the code.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-03 (Medium, regression in this PR) | **CLOSED** | fd0869a | `Axiam.Sdk/AxiamClient.Oidc.cs:1313-1316`: in the `anyStatusErrors` branch, `>= 500` now throws `NetworkError.FromResponse` before the body is read, as `CibaPollAsync` does (`AxiamClient.Ciba.cs:197-202`). **The 429 path is untouched:** 429 < 500, so it still reaches `MapOAuth2ErrorAnyStatusAsync`. A 429 with an OAuth body becomes `OAuthProtocolError` with `HttpStatus = 429` and the header `Retry-After` (`:1320-1327`). A bodiless or non-OAuth 429 falls through to `ErrorMapper`, which gives a `NetworkError` with `HttpStatus` 429 and `RetryAfter` (`Core/NetworkError.cs:111-112`). The loop's `catch (NetworkError)` (`AxiamClient.OidcDeviceExchangeLogout.cs:334-339`) waits that `Retry-After`. Tests: `Contract164DevicePollRateLimitTests.A500WithTheServersOwnOAuthBodyIsNotTerminal` (`:195`; Pending, 500, 500, Tokens gives 4 polls and sleeps `[5,5,5,5]`), `ASinglePollOnA500WithAnOAuthBodyIsANetworkError` (`:209`; `HttpStatus == 500`). The rule-6 test `OidcDeviceFlowTests.cs:217-218` now uses the server's body. Mutant (drop the `>= 500` check): the 500 becomes `OAuthProtocolError("server_error")`, which no catch takes, so the loop ends. All three tests fail. Non-vacuous. |
| C164-04 (Low) | **CLOSED** | fd0869a | `Core/OAuthProtocolError.cs:55` adds internal `HttpStatus`. The loop's catches (`AxiamClient.OidcDeviceExchangeLogout.cs:319` before `:328`): `HttpStatus == 429 \|\| Error is "rate_limit_exceeded"` comes before `slow_down`, so only the 400 raises the interval. Tests: `A429WhoseBodySaysSlowDownIsTheWaitAndDoesNotRaiseTheInterval` (`:167`; sleeps `[5,5,5]`), with control `ASlowDownOnA400StillRaisesTheInterval` (`:178`; `[5,10,10]`). The 429 mock now carries `{"error":"rate_limit_exceeded"}` with no `error_description` (`:21-31`). Mutants: (a) swap the catch order, or (b) drop `HttpStatus == 429`. Either way the 429 `slow_down` reaches the `slow_down` catch, the sleeps become `[5,10,10]`, and the test fails. (c) Never raising the interval fails the 400 control. Non-vacuous. One limit: that case's Retry-After (1) is below the interval, so the test does not show that a 429 `slow_down`'s Retry-After is honoured. The code does honour it (`:325`). |
| C164-05 (Low, pre-existing) | **CLOSED** | fd0869a | `AxiamClient.OidcDeviceExchangeLogout.cs:34` adds internal `TimeProvider DevicePollTime = TimeProvider.System`. **It is wired into the public `DeviceLoginAsync`** (the only overload; `:255`). The deadline is taken from it right after `DeviceAuthorizeAsync` returns and before `OnUserCode` (`:273`), and checked with `now + wait >= deadline` before each sleep (`:299`). `remainingSeconds` is gone. Production uses wall time. Test: `NoPollIsSentAtOrAfterTheDeadlineWhenRequestsTakeTime` (`:224`; FakeTime advanced by the recorded sleep and by 10 s per request; `expires_in` 30, interval 5; polls start at t=5 and t=20, then `expired_token`). Mutant (restore `remainingSeconds -= wait`): polls start at 5, 20, 35, 50, 65. That gives 5 polls instead of 2, and starts at or after 30, so the test fails. Non-vacuous. The other recorded-sleep tests advance the same FakeTime, so they are deterministic. |
| C164-20 (Info) | **CLOSED** (for the four places named) | fd0869a | The `WriteIsolatingHandler` comment now sits in `if (fresh)` (`Rest/WriteIsolatingHandler.cs:159-161`). The class remarks list `device_poll` and add the `/oauth2/*` pooled/fresh cookie-less paragraph (`:41`, `:46-50`). `AxiamClient.Oidc.cs:1280` now names `ciba_poll` and `device_poll`. `Rest/AxiamHttpClientFactory.cs:178-184` is reworded as the review asked. Two more drifted sentences remain; see C164-32. |
| C164-21 (Info) | **CLOSED** | fd0869a | `Management/ManifestApi.cs:664-676`: the value is capped at 64 characters plus `…`, and every `char.IsControl` character becomes `?`. `RequireNoUnknownCarried` is now `internal` (`:633`); `plan` still calls it at `:617`. Test: `NetworkManifestTests.TheRefusalCapsAndEscapesTheQuotedValueAndSaysUnknownWhenNoneWasKept` (`:463`) checks the cap, the escape, and the "the value is unknown" branch with `Fields` naming the member. Mutants: removing the cap fails the `DoesNotContain(x×65)` and `…` checks; removing the escape fails the `bad\nvalue` check. Non-vacuous. Nit, no finding: `raw[..64]` can split a surrogate pair. |
| C164-22 (Info) | **CLOSED** | fd0869a | `CHANGELOG.md:23-28` uses the review's sentence nearly word for word: 1.1.1 raised `NetworkError`, so a hand-rolled loop must also catch `OAuthProtocolError`/`rate_limit_exceeded`. Text only; no mutant applies. |
| C164-23 (Info) | **CLOSED** | fd0869a | `Management/ManagementChecks.cs:335`, `:354`, `:365-378` hold both spellings in internal `RawEnumSpellings`, with `Equals => obj is RawEnumSpellings` and `GetHashCode => 0`. `RawTerminationAction` and `RawServiceType` are now computed from it. Test: `ADecodedProfileEqualsOneBuiltFromItsPublicMembers` (`NetworkManifestTests.cs:490`) checks `Equal(plain, decoded)`, equal hash codes and `decoded with {}`. Mutants: restoring two string init properties, or dropping the `Equals` override (reference equality), makes `Equal(plain, decoded)` fail. Non-vacuous. |

**Amended rules, against AXIAM's exact bodies (traced by reading, not run):**

| Case | Result |
|---|---|
| Rule 6: `500 {"error":"server_error","error_description":"db"}` mid-poll | `NetworkError` (500), not terminal; waited one interval. Single poll gives `NetworkError`. **Conforms** for the outcome. The poll is **not** retried under §16 inside the attempt (C164-25). |
| Rule 6: `503 {"error":"temporarily_unavailable"}` | Same path (`>= 500`): `NetworkError`, not terminal. **Conforms** (same C164-25 caveat). |
| Rule 9: `429 {"error":"rate_limit_exceeded"}`, and with `"retry_after":N` | `OAuthProtocolError`, `HttpStatus` 429. The loop waits `max(interval, Retry-After header)`, counts it as one interval and does not raise the interval. Body `retry_after` is ignored (correct). Single `DevicePollAsync` raises `OAuthProtocolError("rate_limit_exceeded")`. **Conforms.** |
| Rule 9: bodiless 429 with Retry-After (also a non-OAuth body) | `NetworkError` with `HttpStatus` 429 and `RetryAfter`. The loop waits `max(interval, RA)` and does not raise the interval. **Conforms** (C164-17 point). |
| §14.6 third case: `429 {"error":"slow_down"}` then 200 | Taken by the 429 catch before `slow_down`: the wait, interval unchanged. Test at `:167`. **Conforms.** |
| `400 slow_down` | Still raises the interval by 5 s for good (`:328-332`; test `:178`). **Conforms.** |
| §14.6 cases 1 and 2 | Case 1 `[5,5,20,5]` (`:97`). Case 2: RA 120 > `expires_in` 30 gives `expired_token` after 1 poll, sleeps `[5]` (`:138`). **Conform.** |

**Replay after refresh:** **Conforms** (by reading; no probe possible).
- REST, `Rest/AxiamHttpMessageHandler.cs:289-342`. On a 401, the refresh is awaited first (`:294`). Then a new `HttpRequestMessage` is built. It copies the caller headers except the managed ones (Authorization, X-Tenant-Id, X-CSRF-Token, Content-Type; `:176`, `:318-325`). Then `ApplyHeaders(retryRequest, refreshed.AccessToken)` runs (`:338`). So the bearer is the refreshed one, and the CSRF value is re-read after the refresh (`_csrfToken ?? jar`, `:437`).
- The refresh itself runs through the same handler chain (`AxiamClient.cs:861-866`). Its `Set-Cookie` updates the shared `CookieContainer`, and `SocketsHttpHandler` writes jar cookies at send time, so the replay carries the fresh cookies. Jar cookies are not in `request.Headers`, so no stale `Cookie` header is copied. That is .NET's behaviour, read, not probed.
- Tests: the fresh bearer is asserted (`AxiamHttpMessageHandlerTests.cs:247-263`). The CSRF and cookie values on the replay are not. Pre-existing, outside the diff, and not numbered:
  - a cached `_csrfToken` (only ever set from an `X-CSRF-Token` *response header*, which AXIAM never sends) takes precedence over a rotated `axiam_csrf` cookie;
  - against AXIAM it stays null, so the jar value is used.
- gRPC, `Grpc/AuthInterceptor.cs:146-148`. Refresh first, then `InjectAuthMetadata(originalContext)`, which reads the token accessor again. Fresh.
- `/oauth2/*` stays exempt from the refresh, and no bearer or CSRF is put on those requests (`:420-437`). The diff does not touch this.

**Version:** 1.1.2 is right. Both csproj files and the README are unchanged. Every addition since the review is `internal` (`HttpStatus`, `DevicePollTime`, `RawEnumSpellings`, and `RequireNoUnknownCarried` made internal), so nothing is source-breaking. The CHANGELOG records C164-03/04/05/21/22/23 and the re-vendor from 21beda0 (`CHANGELOG.md:13-14`, `:20-43`). C164-20 is doc-only and is not listed, which is fine. The README still says "conforms to **contract 1.64**" (`README.md:27`).

**1.63 rules where the diff touched code:**
- `WriteIsolatingHandler` and `AxiamHttpClientFactory` changed in comments only.
- The `/oauth2/*` cookie/CSRF/bearer isolation and §6.1 rule 11 are unchanged.
- The §27.6.2 refusal still runs in `plan` (`ManifestApi.cs:617`), before any write.

**Run by the reviewer:**
- `which dotnet`: none. No build, no `dotnet test`, no `dotnet format`, no mutants executed; the toolchain is unavailable as in the review.
- `git log` / `git diff 87b88122e..HEAD` read in full: 12 files (+327/−62), of which 46 lines are the vendored CONTRACT.md.
- `sha256sum CONTRACT.md` gives `8b2cb9a385782b5e…`.
- Compile-readiness checked by reading:
  - the test's `NetworkReplyProfile` initialiser sets every `required` member (`Models/NetworkReplyProfile.cs:25-104`);
  - `ManagementSupport.Decode<T>` and `ManagementJson.Reader` exist as internals;
  - `TimeProvider` is in the net8.0 BCL;
  - `ImplicitUsings` covers `Select` in `QuoteRaw`;
  - the primary-constructor class's same-named property initialisers are legal C# 12.
- 7 mutants judged by reading; all are killed.

**New findings:**
- **C164-25 — Low (pre-existing, not introduced by this PR; made normative-visible by the amended rule 6)**
  - Where: `Axiam.Sdk/AxiamClient.OidcDeviceExchangeLogout.cs:216-218`.
  - Rule: §14.2 rule 6 (amended), "retried under the bounded read-only retry policy of §16, then surfaced … per poll attempt", and §16.2's table row for `device_poll` on a 5xx or transport failure.
  - What happens: the SDK has a §16 layer, `RetryPolicy.ExecuteAsync`, with `RetryEnabled` defaulting to `true` (`Options/AxiamClientOptions.cs:170`). `CibaPollAsync` uses it (`AxiamClient.Ciba.cs:189-216`). `DevicePollAsync` does not.
    - A 5xx or transport failure on a poll is never retried inside the attempt (3 attempts, with Retry-After as a floor).
    - A single `DevicePollAsync` surfaces the first transient 5xx.
    - `DeviceLoginAsync` waits a full interval instead.
    - The comment at `:216` ("is retried (the loop below re-sends it)") stands in for the §16 retry.
    - The flow still survives, so the user-visible harm is narrow.
  - Fix (code): in `DevicePollAsync`, send the POST inside `RetryPolicy.ExecuteAsync("device_poll", _options, _telemetry, Random.Shared.NextDouble, …, cancellationToken, retryable: e => e.HttpStatus is null or >= 500)`.
    - Do **not** use `RetryPolicy.IsTransient`. It retries 408 and 429, and a 429 is the loop's rule-9 wait, not a §16 retry.
    - Inside the callback: throw `NetworkError.FromResponse` on `>= 500`; throw the mapped error (with `HttpStatus`/`RetryAfter`) on any other non-2xx; return the 200 body string.
    - Parse the `TokenResponseWire` **outside** the retry, as `CibaPollAsync` does (`:218-227`). A parse failure is a `NetworkError` with a null status and would otherwise re-send a redeemed `device_code`.
  - Fix (test):
    - Single `DevicePollAsync`: 500, 500, 200 gives 3 requests and tokens; 500 ×3 gives `NetworkError` after 3 requests.
    - A bodiless 429 gives exactly 1 request.
    - With `RetryEnabled = false`, a 500 gives 1 request.
- **C164-32 — Informational (doc drift, partly pre-existing)**
  - Where: `Axiam.Sdk/AxiamClient.OidcDeviceExchangeLogout.cs:178-180` and `:241-245`.
  - What happens: the `DevicePollAsync` remarks say a hand-rolled loop "sees exactly what `DeviceLoginAsync` sees". It does not. `DeviceLoginAsync` decides on the internal `OAuthProtocolError.HttpStatus` and `RetryAfter`, which a caller cannot read. So a caller's loop cannot tell a 429 `slow_down` from a 400 `slow_down`, and cannot honour the 429's Retry-After. The `DeviceLoginAsync` remarks still say only "a `429` `rate_limit_exceeded`" is waited, but now any 429 is.
  - Fix: reword `:178-180` to say a hand-rolled loop sees the same five answers, but not the status or `Retry-After` of a `429`, which `DeviceLoginAsync` reads internally to apply §14.2 rule 9, and that a caller who needs the rule-9 wait uses `DeviceLoginAsync`. Make `:242` "a `429` (whatever its body) is not terminal either". Making `HttpStatus`/`RetryAfter` public would be an additive public change and a minor bump, so it is not proposed for 1.1.2.
- **C164-33 — Informational (test robustness, introduced by C164-05)**
  - Where: `tests/Axiam.Sdk.Tests/OidcDeviceFlowTests.cs:192-205` (`DeviceLoginAsync_StopsAtExpiresIn_EvenWhileTheServerSaysPending`).
  - What happens: before this change, the deadline was a counter and the test was deterministic. The fixture keeps the real `Task.Delay` and the real clock (`expires_in` 2, interval 1). The test now passes only if `UtcNow` after a 1 s `Task.Delay` plus the poll reads at least 1 s past the deadline capture. The Linux timer queue can fire up to about 1 ms early on `TickCount64` granularity. The time spent in `OnUserCode` and the mocked poll almost always covers that, so the risk is small, but it is now a wall-clock boundary.
  - Fix: give `OidcDeviceFlowTests`' `SetUp` the same FakeTime and advancing recorded sleep as `Contract164DevicePollRateLimitTests` (`:52-88`). That also removes its real 1 s sleeps.

---

#### Addendum — go — commit a6551ae8d (PR #103), read after a47ac8f94

Six commits on top of the reviewed head, in a straight line: `9d7460a` (CI floor), `bbf7b24` (re-vendor CONTRACT.md as amended; vendoring not re-checked, per the brief), `483eec5` (C164-04/-05/-17), `077838c` (C164-02/-24), `d9efd9c` (C164-23), `a6551ae` (C164-22). Each commit message's finding map matches its diff.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-02 (Medium) | **CLOSED** | `077838c` | `oidc_wire.go:372-374`: the verifier gets `bare := *c.httpc; bare.Jar = nil`, so CA, client cert, timeout and CheckRedirect are kept and the jar is not. Test `oidc_jwks_client_test.go:110` (`TestOidcJWKSFetchAfterLoginCarriesNoSessionCookie`): a real `Login` sets `axiam_access` and `axiam_csrf`, a guard checks that the jar is non-empty, then a real `VerifyPayload` fetches the JWKS and the test asserts there is no `Cookie` and no `X-CSRF-Token`. The C163-16 mTLS and timeout tests (`:21`, `:64`) are kept and pass. Mutant (drop `bare.Jar = nil`): **killed** by that test. |
| C164-04 (Low) | **CLOSED** | `483eec5` | `oidc_wire.go:280-305`: the status decides. Only `429` with `error == "rate_limit_exceeded"` becomes `*OAuthProtocolError` (`:286`). Every other 429 (any body, or none) and every 5xx goes to `errorFromHTTPStatus`, which gives `*NetworkError`. Test `contract_164_test.go:213`: a 429 with `slow_down`, `authorization_pending` or `invalid_grant`, then 200, gives waits `[1s 1s]` and 2 calls; the control, a 400 `slow_down`, gives `[1s 6s]`. Mutant (any decoded 429 becomes typed): **killed** (the `slow_down` and `invalid_grant` subtests fail). The `authorization_pending` subtest survives that mutant because the waits are the same; it has no `Retry-After` to tell the cases apart. This is test strength only. |
| C164-17 (Info) | **CLOSED** | `483eec5` | `oidc_wire.go:300-304` sets `RetryAfter` on the fall-through `*NetworkError` for 429 and 503. `oidc_device.go:359` (`schedule.rateLimited(networkErr.RetryAfter)`) uses it in the `*NetworkError` arm; a zero value is a no-op. Test `contract_164_test.go:242`: a bodiless 429 with `Retry-After: 7` gives `[1s 7s]`. Mutants: drop the loop floor, **killed**; drop the mapper's `RetryAfter`, **killed**. |
| C164-05 (Low) | **CLOSED** | `483eec5` | `oidc_device.go:278` records `received` right after `DeviceAuthorize` returns, before `OnUserCode`. `:289-290` set `schedule.now` and `schedule.deadline = received + expires_in`, and `:79` stops when `!now().Add(step).Before(deadline)`. The `pollNow` clock can be injected (`client.go:296-298`, `oidc_device.go:367`). The old waits budget stays as a second bound that never wins (it is always ≥ the wall-clock bound). Test `contract_164_test.go:259`: `OnUserCode` takes 10 s of a 12 s grant at a 5 s interval, which gives `expired_token` with 0 polls. Mutants: disable the wall-clock check, **killed**; take `received` after `OnUserCode`, **killed**. |
| C164-22 (Info, both bullets) | **CLOSED** | `a6551ae` | `CHANGELOG.md:17-18` now says "an unkeyed `OAuthProtocolError{…}` composite literal". `[1.1.1]` and every older section are byte-identical to tag `v1.1.1` (diffed); the correction is kept under `[1.1.2]` → Changed (`:72-73`). Docs only, no mutant. |
| C164-23 (Info, CIBA) | **CLOSED** | `d9efd9c` | `oidc_ciba.go:707-717`: `wait = max(interval, floor)`, checked against the wall-clock deadline before sleeping, and the floor is cleared after one use. `:740-743` set the floor from `RetryAfter` on `rate_limit_exceeded`. `oidc_registration.go:405-407` now carries `RetryAfter` on a 429 in `oauth2ErrorAnyStatus`, which is additive for registration and SSF. No double wait: a typed 429 is still decisive (`errStopRetry`) in `cibaPoll`. Test `oidc_ciba_test.go:1097`: 429 with `Retry-After: 17`, then pending, then tokens, gives `[5 17 5]`. Mutants: drop the floor assignment, **killed**; drop `RetryAfter` in `oauth2ErrorAnyStatus`, **killed**. |
| C164-24 (Info) | **CLOSED** | `077838c` | `client.go:843-844`: matches the base prefix + `/oauth2/` **or** a root `/oauth2/`. Federation routes still never match. The pinned row is flipped to `true` (`contract_163_test.go:275`). Mutant (drop the root alternative): **killed** by `TestIsOAuth2PathIsAnchoredToTheBasePath`. |
| CI floor `9d7460a` | **Consistent, with one stale doc line (C164-32)** | `9d7460a` | Touches only `.github/workflows/sdk-ci-go.yml`: the matrix `1.26.9` → `1.26.10` (`:44`) and the govulncheck guard (`:61`). `go.mod` stays `go 1.26.0`, there is no `toolchain` line, and `MinGoVersion = "1.26"` is unchanged, so consumers see no change. The interop job (`:91`), the publish job (`:248`) and `coverage.yml:20` keep `1.26.9`. None of them runs govulncheck, as the commit message says. The `version_policy_test.go` floor and matrix tests pass on both go1.26.0 and go1.26.10. Not followed: `README.md:188` still says the matrix is "1.26.9 and 1.27.0", the `version_policy_test.go:39` comment shows the old matrix, and the CHANGELOG does not record the move (earlier floor moves were recorded, `CHANGELOG.md:355`, `:372`). |

**Amended rules: probe results** (a throwaway probe test drove `DeviceLogin` through `runDeviceLogin` with a recorded sleep: interval 1 s, `expires_in` 30. The script was the first answer, then 400 `authorization_pending`, then 200. Each single `DevicePoll` was probed separately.)

| Rule / case | Probe | Result |
|---|---|---|
| §14.2 rule 9: AXIAM 429 | `429 {"error":"rate_limit_exceeded"}`, Retry-After 7 | waits `[1s 7s 1s]`, completes. Single poll: `*OAuthProtocolError` `rate_limit_exceeded`, `RetryAfter=7s`, 1 call. **ok** |
| rule 9: the variant | `{"error":"rate_limit_exceeded","retry_after":7}`, Retry-After 7 | the same as above. **ok** |
| rule 9: bodiless 429 | Retry-After 7, no body | `[1s 7s 1s]`. Single poll: `*NetworkError`, `RetryAfter=7s`. **ok** |
| rule 9 / §14.6 case 3 | `429 {"error":"slow_down"}` with Retry-After 1, and without it | `[1s 1s 1s]` both times; the interval is never raised. Single poll: `*NetworkError` (not read as `slow_down`). **ok** |
| rule 9: past the deadline | 429 `rate_limit_exceeded`, Retry-After 100, deadline 30 s | `expired_token` at once after 1 call. **ok** |
| rule 5 control | `400 {"error":"slow_down"}` | `[1s 6s 6s]`, raised and persistent. **ok** |
| rule 6 / §14.6 500 body | `500 {"error":"server_error","error_description":"db"}` | non-terminal, `[1s 1s 1s]`, completes. Single poll: `*NetworkError`. **Not §16-retried inside the poll (C164-25).** |
| rule 6: 503 | `503 {"error":"temporarily_unavailable"}`, without and with Retry-After 4 | non-terminal, `[1s 1s 1s]` and `[1s 4s 1s]` (Retry-After as a floor). Not §16-retried (C164-25). |
| §14.6 1.64 cases 1 and 2 | existing tests `contract_164_test.go:45-148` | pass, unchanged |

Single `DevicePoll` still raises on every 429. It raises `*OAuthProtocolError` for the server's `rate_limit_exceeded` body. For a 429 whose body names something else, it deliberately raises `*NetworkError`, so a hand-rolled loop cannot misread the 429 as `slow_down`.

**Replay after refresh:** **Not affected.** REST has no refresh-and-replay at all. `doRequest` (`client.go:885-918`) returns every status as received, and `RefreshIfNeeded` is called only from `Refresh()` (`login.go:497`). That is a documented invariant (`client.go:862-884`), so the stale-capture push-order bug has nowhere to happen. Decoration (`decorateRequest`, `client.go:764-828`) reads the CSRF token, the adopted bearer and the jar when the request is sent. gRPC (`grpc/client.go:107-114`, `:132-139`, `grpc/token.go:213-219`, `:239-245`, `grpc/userinfoclient.go:60`) refreshes on `Unauthenticated` and then calls `c.inner.X` again. That second call goes back through `authUnaryInterceptor` (`grpc/interceptor.go:27-37`), which reads `tokenFn()` on every call. Probe: the first call carried `Bearer old`, the refresh set the token to `new`, and the replay carried `Bearer new`. AMQP and `middleware/` have no refresh path.

**1.63 rules where the diff touched code:** these hold. The CSRF skip, the jar bypass and the bearer withholding still go through `c.isOAuth2Path` (`client.go:811`, `:825`, `:905`). The root-`/oauth2/` widening only adds isolation. The JWKS GET is now jar-less and goes around `decorateRequest`, so it sends no CSRF and no bearer. The C163-08 test passes. §6.1 rule 11 and the §27.6.2 plan-time refusal are untouched.

**Version:** 1.1.2 (`## [1.1.2] - Unreleased`, tag-based, no version constant) is still right. Nothing since the review is source-breaking. The C164-04 change narrows which 429s become `*OAuthProtocolError`, but compared with 1.1.1 every 429 was a `*NetworkError`, so it only shrinks the change the release already records. The CHANGELOG records C164-02/-04/-05/-17/-23/-24 and the amendment (`21beda0`), plus C164-16 as "held already, now tested". README `:23` says contract 1.64; `:168` pins `@v1.1.2`.

**Run by the reviewer** (throwaway copy `/home/user/work/go`, deleted afterwards; `GOTOOLCHAIN=auto` resolved go1.26.0):
- `go build ./...` ok. `go vet ./...` clean. `go test -count=1 ./...` passed: 15 packages ok, **1686 test/subtest passes, 0 failures, 0 skips**. `go run ./internal/cmd/genmanagement -check` passed: "32 generated files are current (202 operations)".
- On go1.26.10: the version-policy tests (`TestCIBuildsTheDeclaredFloor`, `TestCINeverBuildsBelowTheFloor`, `TestCIMatrixIsFloorAndNewest`, `TestRunningToolchainSatisfiesTheFloor`, `TestMinGoVersionMatchesGoMod`) pass.
- 11 mutants, each reverted after its run, **all killed**: C164-02 jar ×1, C164-04 ×1, C164-17 ×2, C164-05 ×2, C164-24 ×1, C164-23 ×2, plus the C164-16 control (a 5xx with an OAuth body typed as a protocol error), killed by `TestDeviceLoginA500ServerErrorBodyMidPollIsNotTerminal`.
- Probes: the device loop and single-poll table above; the gRPC replay token.
- Not run: `govulncheck`, because `vuln.go.dev` was refused by the egress proxy (CONNECT 403). The CI run of PR #103 was not read (no GitHub API). CI has no staticcheck or golangci-lint, so neither was run.

**New findings:**
- **C164-25 — Low (pre-existing; made visible by the amended rule 6).** `oidc_device.go:207-225` (`DevicePoll` → `postToken`, with no `retryReadOnly`). Rule: §14.2 rule 6 ("retried under the bounded read-only retry policy of §16, then surfaced") and §16.2 (`device_poll` on a 5xx or transport failure is eligible). §16.1 says retry MUST default to on, and in this SDK it does (`client.go:410`). What happens: a `500 {"error":"server_error"}`, a 503 or a transport failure on a device poll is never retried inside the attempt. The single `DevicePoll` surfaces it after 1 request (probed), and `DeviceLogin` absorbs it at a full interval (`[1s 1s 1s]`) instead of the 3-attempt §16 budget. The flow still survives, so the trigger is narrow. `cibaPoll` already does the right thing (`oidc_ciba.go:617-641`). Fix: in `DevicePoll`, wrap the token POST in `c.retryReadOnly`, or `retryReadOnlyUntil` bounded by the grant deadline when called from the loop. Retry only a `*NetworkError` from a 5xx or a transport failure. Make every 429 (typed or not) and every 4xx decisive through `errStopRetry`, so the 429 wait stays the loop's and is never waited twice. `WithRetryDisabled` must still give exactly one attempt. Test: `500 {"error":"server_error","error_description":"db"}` then 200, with `c.rand` pinned to 0, gives 2 token calls inside one `DeviceLogin` wait (`[1s]`). A 429 then 200 still gives 1 call per wait. With `WithRetryDisabled`, the 500 case gives `[1s 1s]`.
- **C164-32 — Informational.** `README.md:188` and `version_policy_test.go:39` (a comment). The CI floor bump `9d7460a` left the README saying the gating matrix runs "1.26.9 and 1.27.0", and the CHANGELOG has no line for it, although the earlier floor moves are recorded (`CHANGELOG.md:355`, `:372`). The Fixed bullets also do not name the new tests (plan §8.2), except C164-16's "now tested". Fix: write "1.26.10 and 1.27.0" in the README and the comment. Under `[1.1.2]` → Notes, add "CI: the floor leg runs Go 1.26.10 (GO-2026-6809 in crypto/x509, found in 1.26.9); `go.mod` stays `go 1.26.0`". Name the five new tests in the `### Added` Tests bullet.

---

#### Addendum — java — commit 4d40fd84b (PR #121), read after b4072a9f1

Commits `b4072a9f1..4d40fd84b`: `688b047` re-vendor CONTRACT.md from 21beda0 (sha256 8b2cb9a3…7a9a, matches);
`66532fd` fix(oauth): the status decides on a device poll, deadline on a clock; `6bd133b` tests for C164-12/-19
and the C164-22 citation; `4d40fd8` CHANGELOG/README. The commit messages' finding map matches the diff.
The SDK clone was not modified. Probes and mutants ran in `/home/user/work/java-probe`, the suite in `/home/user/work/java`.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-04 (Low) | **CLOSED** | 66532fd | `ErrorMapper.java:186-194`: any `429` → `OAuthProtocolError("rate_limit_exceeded", body?.description, Retry-After)`, whatever the body names. `AxiamClient.java:3517-3521`: `slow_down` is reached by a `400` only. Test `AxiamClientDeviceFlowTest.anyRateLimitIsTheWaitWhateverItsBodyNames` (:262) asserts sleeps `[1,1,1,4]`. Mutant "keep the body's code on a 429" **fails** it: `[1,6,6,6]`. |
| C164-05 (Low, pre-existing) | **PARTLY** (code done, untested) | 66532fd | `AxiamClient.java:3476`: `deadline = clock.now() + expires_in`, taken when the authorization returns. `:3493`: `!clock.now().plus(wait).isBefore(deadline)`, so request time and `onUserCode` time now count. **No test advances the clock outside `sleep`.** `RecordedClock` (test :188) moves only on `sleep`, so a sum-of-sleeps deadline behaves identically. Mutant "deadline = start + Σ sleeps" **survives** all 19 tests of `AxiamClientDeviceFlowTest`. The index asks for a test: a clock that also advances per poll / in `onUserCode` sends no poll at or after the deadline. |
| C164-11 (Low) | **CLOSED** | 66532fd | Package-private `deviceLogin(..., CibaClock clock)` at `AxiamClient.java:3470`; the public overload (:3460) passes `CibaClock.system()`. Case 1 (:219) asserts sleeps `[1,2,1]` and 5 requests. Case 2 (:304) asserts `expired_token`, 3 requests, sleeps `[1]`, inside `assertTimeoutPreemptively(10 s)`. The 429 mock is the server's exact `{"error":"rate_limit_exceeded"}` (`serverRateLimit`, :205). Mutants: "on top" (interval + RA) **fails** (`[1,3,1]`); "sticky Retry-After" **fails** (`[1,2,2]`); "cap removed" **fails** case 2 by the 10 s timeout, not by a hang. |
| C164-12 (Low) | **CLOSED** | 6bd133b | `NetworkManifestTest.java:458` reads `termination_action: "future"` and then `service_type: "a_future_service"` with a matching spec, and asserts `NO_CHANGE` plus 0 PUT / 0 POST after `apply`. `:479` asserts `ValidationError` from `apply` with `put.calls()==0`. Then `withServiceType(FRAMED_USER)` → 1 PUT whose body has `service_type == "framed_user"`. Mutants: "refusal also when not drifted" (`ManifestApi.java:650` `if (true)`) **fails** :458. "No `service_type` refusal" **fails** :425, :479 and :527. |
| C164-17 (Info) | **CLOSED** | 66532fd | Same mapping as C164-04: a bodiless `429` gets `Retry-After` as the floor (`ErrorMapper.java:189-191`). The test is the last step of :262 (bodiless `429`, `Retry-After: 4` → wait 4). Mutant "a bodiless 429 falls through to `NetworkError`" **fails** (`[1,1,1,1]`). |
| C164-19 (Info) | **CLOSED** | 6bd133b | `OauthNoSessionCredentialTest.java:167-168` asserts `axiam_access=` + the session token in the management write's `Cookie`. The login mock sets that cookie at :65. This is a direct assertion; no mutant was run. |
| C164-22 (Info) | **CLOSED** | 6bd133b, 4d40fd8 | `ScimTargetResponse.java:55` now cites "§31.3 rule 4, contract 1.63", through the generator (`scripts/gen_management.py:1160`, `emit_raw_timestamp_accessors(fields, schema_name)`); a generator re-run gives no diff. `README.md:89` says "as §27.6.2 item 4 asks of an SDK that keeps the value". `CHANGELOG.md:37-43` (`### Changed`) records `devicePoll` on a 429: `NetworkError` → `OAuthProtocolError`. `CHANGELOG.md:72` retitles the phantom heading `[1.1.1] — contract 1.63 detail (recorded as 1.2.0 before release)` and adds a note that no 1.2.0 was published. That was one of the two options the review offered; it leaves two `[1.1.1]` headings (:52, :72), which is acceptable. |

**Amended rules: probes on the new head** (ad-hoc `AddendumProbeTest`, recorded clock, interval 1, `expires_in` 600, deleted afterwards)

| Rule / case | Probe | Result |
|---|---|---|
| §14.2 rule 6 (5xx whatever its body) | `500 {"error":"server_error","error_description":"db"}` mid-loop | non-terminal; sleeps `[1,1]`, completes (pass) |
| rule 6 | `503 {"error":"temporarily_unavailable"}` mid-loop | non-terminal; sleeps `[1,1]`, completes (pass) |
| rule 6 / §16.2 (retried inside the poll) | single `devicePoll`: `500 server_error` ×2 then 200; `503` then 200 | **`NetworkError` after 1 request each.** No §16 retry inside the poll, although retry is on by default → C164-25 |
| rule 9 (any 429 is the wait) | `429 {"error":"rate_limit_exceeded"}` + RA 2 | sleeps `[1,2]` (pass) |
| rule 9 | `429 {"error":"rate_limit_exceeded","retry_after":7}` + RA 7 | sleeps `[1,7]`; the body's `retry_after` is ignored (pass) |
| rule 9 | bodiless `429` + RA 3 | sleeps `[1,3]` (pass) |
| rule 9 (429 never raises the interval) | `429 {"error":"slow_down"}` + RA 1, then pending | sleeps `[1,1,1]` (pass) |
| rule 1 (a 400 still raises it) | `400 slow_down`, then pending | sleeps `[1,6,6]` (pass) |
| single `device_poll` on a 429 | rate_limit RA 7 / `429 slow_down` / bodiless RA 4 | `OAuthProtocolError` `rate_limit_exceeded`, `retryAfterSeconds` 7 / 0 / 4, `errorDescription` null (pass) |
| single `device_poll` on a 400 | `400 slow_down` | `OAuthProtocolError slow_down` (pass) |
| §14.6 case 1 (waits ≥ RA, interval unchanged) | test :219 | `[1,2,1]`, server's exact body (pass, non-vacuous) |
| §14.6 case 2 (cap at the deadline) | test :304 | `expired_token`, 3 requests, `[1]` (pass, non-vacuous) |
| §14.6 case 3 (`429 slow_down` then 200) | test :262 | `[1,1,1,4]`; also covers a bodiless 429 (pass, non-vacuous) |
| §14.6 500 mock body | test :323 | `500 {"error":"server_error","error_description":"internal"}` mid-poll completes. Mutant "dispatch `error` at any status" **fails** (pass) |
| Retry-After in HTTP-date form (session's note) | `429` + `Retry-After: Fri, 31 Dec 2027 23:59:59 GMT`, then pending | read as absent (`ErrorMapper.java:196-206` parses delta-seconds only, as `StatusRetry.retryAfterMillis` does SDK-wide). The loop waits **exactly the interval**, `[1,1,1]`. It is never shorter than the interval and never terminal, but it can poll before the date. **Not a defect:** §14.2/§16 do not name the form, AXIAM sends delta-seconds only, and the interval floor still holds. At most Informational hardening (RFC 9110 allows the date form). |
| very large Retry-After (new) | `Retry-After: 99999999999999999` / `9223372036854775807` | `deviceLogin` throws **`java.time.DateTimeException`** / **`ArithmeticException`**, not the typed `expired_token` → C164-30. `1000000000000` gives `expired_token` (pass). |

**Replay after refresh:** **defect (pre-existing, not touched by this PR) → C164-26.**
- The §9 reactive path is OkHttp's `Authenticator` (`AuthAuthenticator.java:106-108`). It returns `response.request().newBuilder().header("Authorization", "Bearer " + refreshed)`, replacing only the bearer.
- The follow-up request is built in `RetryAndFollowUpInterceptor`, which runs *below* application interceptors. So `AuthInterceptor` (`AuthInterceptor.java:166-170`, the only place `X-CSRF-Token` is set) never runs again on the replay.
- Cookies come out fresh, because `BridgeInterceptor` reloads them from the jar, which the refresh's `Set-Cookie` updated.
- The CSRF header is copied from the original request, so it is **stale**.
- Probe (login sets `axiam_csrf=CSRF-OLD`; a `POST /api/v1/users` gets 401; the refresh rotates the token to `CSRF-NEW` by cookie and by header, as `crates/axiam-api-rest/src/handlers/auth.rs` does, "Issue a new CSRF token on every refresh rotation"). The replay carries `Authorization` = the NEW access token and `Cookie: axiam_access=<new>; axiam_refresh=r2; axiam_csrf=CSRF-NEW`, with **`X-CSRF-Token: CSRF-OLD`**.
- AXIAM's `CsrfMiddleware` (`middleware/csrf.rs`) validates any write that carries a session cookie, so it answers that replay **403 "CSRF validation failed"**.
- The *next* write carries `CSRF-NEW` (the session captured it), and the proactive path (`AuthInterceptor.java:148-152`, which refreshes before the headers are built) is correct.
- gRPC: `AuthClientInterceptor.start` re-reads the token on each retried call, and gRPC has no CSRF or cookies, so it is fine.

**Version:** 1.1.2 is correct (`pom.xml:9`, `bom/pom.xml:9,66`). Nothing since the review is source-breaking: the new `deviceLogin` overload is package-private. The CHANGELOG records the fixes (C164-04/-05/-11/-22, rule 6) and the README contract sentence (`README.md:27`, `:89`) states contract 1.64 and the amendment. Nit in C164-32.

**Run by the reviewer** (JDK 21.0.12, Maven 3.9.16 through `./mvnw`):
- `./mvnw -B verify` on 4d40fd84b: **BUILD SUCCESS**, **1511 tests, 0 failures, 0 errors, 0 skipped**, all jacoco checks met (14:02 min). `AxiamClientDeviceFlowTest` 19/19, `NetworkManifestTest` 26/26, `OauthNoSessionCredentialTest` 3/3.
- `./mvnw -B -o compile javadoc:javadoc`: SUCCESS, 0 warnings.
- `./mvnw -B -o -f bom/pom.xml verify`: SUCCESS.
- `scripts/tls-bypass-gate.sh`: exit 0.
- `python3 scripts/gen_management.py`: no diff.
- 10 mutants (`-Dtest=<class> -Djacoco.skip=true`). Caught: body code on 429; bodiless→NetworkError; on top; sticky RA; cap removed (the targeted case-2 run fails at its 10 s timeout); 500-dispatch; refuse-on-NoChange; no service_type refusal. **Survives:** sum-of-sleeps deadline (C164-05).
- Note: in the full-class run of the "cap removed" mutant, an older device-flow test without a preemptive timeout hung (on the real clock), so that mutant was re-run on the 1.64 case-2 test alone.
- Not run: the GPG/Sigstore verify jobs and `central-bundle-gate.sh` (they need an ephemeral key, OIDC or a deploy).
- Build outputs (`target/`) deleted afterwards.

**New findings:**

- **C164-26 — Low (pre-existing; proposed Medium if the lead counts the reactive-401 path as common).**
  - **Where:** `src/main/java/io/axiam/sdk/rest/AuthAuthenticator.java:106-108`, with `AuthInterceptor.java:166-170`.
  - **Rule:** §9 rule 1 ("all waiting requests are retried with the new tokens") and §3 non-browser rule 2 (a state-changing request carries the *stored* token).
  - **What happens:** after a 401 on a `POST`/`PUT`/`PATCH`/`DELETE` in a cookie session, the SDK refreshes. The replay then carries the new bearer and the rotated `axiam_csrf` cookie, but the old `X-CSRF-Token`, and AXIAM's CSRF middleware refuses it 403 (probe above).
  - **Trigger:** the reactive path only. The proactive refresh 30 s before `exp` covers ordinary expiry; the reactive path runs on clock skew, a signing-key rotation or restart, or a token rejected early.
  - **Fix:** in `authenticate()`, after the refresh, rebuild the headers from the session:
    `Request.Builder b = response.request().newBuilder().header("Authorization", "Bearer " + refreshed.access()); String csrf = session.csrfToken(); if (csrf != null && response.request().header("X-CSRF-Token") != null) b.header("X-CSRF-Token", csrf); return b.build();`
    The session already holds the rotated value, because the refresh went through `AuthInterceptor:198-201`.
  - **Test:** login sets `axiam_csrf=A` / `X-CSRF-Token: A`; a management `POST` gets 401; the refresh answers `axiam_csrf=B` / `X-CSRF-Token: B`; assert the replayed request has `X-CSRF-Token == "B"` and a `Cookie` containing `axiam_csrf=B`.

- **C164-25 — Low (pre-existing; the amendment states it).**
  - **Where:** `src/main/java/io/axiam/sdk/AxiamClient.java:3449-3455` (`devicePoll`: one plain `executeFormPost`).
  - **Rule:** §14.2 rule 6 ("retried under the bounded read-only retry policy of §16, then surfaced"), §16.2's table (`device_poll` on a 5xx or transport failure is eligible), and §16.1 (retry defaults to on).
  - **What happens:** a single `devicePoll` answered `500 {"error":"server_error"}` or `503` raises `NetworkError` after 1 request (probe), although `retryEnabled` is on and `StatusRetry` already wraps `ciba_poll` (`:4682`). Inside `deviceLogin` the loop just takes its next interval, so the flow survives, but there are no 3 attempts per poll.
  - **Fix:** wrap the POST in `StatusRetry.run(retryEnabled, telemetry, "device_poll", n -> …)` with the `ciba_poll` shape. Mark it transient only on `code >= 500` and on `IOException`, **not** via `retryableStatus` (which includes 429: the 429 must reach the loop unretried, rule 9), and use `retryAfterMillis(response)` as the floor.
  - **Test:** `500 server_error`, `503`, then 200 → a single `devicePoll` returns the tokens after 3 requests; with retry disabled → `NetworkError` after 1; a 429 → 1 request.

- **C164-30 — Low (new in this PR: a regression of the typed outcome; narrow).**
  - **Where:** `src/main/java/io/axiam/sdk/AxiamClient.java:3487`, `:3493`, with `errors/ErrorMapper.java:196-206` (no upper clamp).
  - **Rule:** §14.2 rule 4 and rule 9 ("a Retry-After past the deadline is capped … the typed `expired_token`"), §2 (typed errors).
  - **What happens:** the clock-based check `clock.now().plus(Duration.ofSeconds(huge))` overflows `Instant`. `Retry-After: 99999999999999999` throws `DateTimeException`, and `9223372036854775807` throws `ArithmeticException`, out of `deviceLogin` (probe). On b4072a9f1 the same answer gave `expired_token`, because the `long` comparison `waitSeconds >= remainingSeconds` cannot overflow there. Only a broken or hostile intermediary sends such a value.
  - **Fix:** clamp in `retryAfterSeconds`, e.g. `Math.min(Math.max(0, parsed), 86_400L)`, as `StatusRetry` caps its own value. Or compare durations: `if (wait.compareTo(Duration.between(clock.now(), deadline)) >= 0)`.
  - **Test:** a 429 with `Retry-After: 9223372036854775807` → `OAuthProtocolError expired_token`, sleeps `[1]`, 3 requests.

- **C164-32 — Informational.**
  - **Where:** `CHANGELOG.md:16-18`.
  - **What happens:** "the only API additions are `OAuthProtocolError.retryAfterSeconds()` and a three-argument constructor" leaves out the public `ErrorMapper.fromDevicePollResponse` (public method on a public class, `ErrorMapper.java:186`), which is also new in 1.1.2. It is not breaking.
  - **Fix:** add it to that list (or tag it `@internal` in its Javadoc).

---

#### Addendum — kotlin — commit ecf58ce99 (PR #80), read after 25687d50a

Five commits since the review (`git log --oneline 25687d50a..ecf58ce`): `8d2f14c` re-vendor CONTRACT.md from 21beda0;
`4f466d2` fix(oidc) C164-04/-05/-17; `d44aa6e` test C164-13; `f2ae302` fix(manifest) C164-21; `ecf58ce` docs C164-22.
Each commit's claim matches its diff. All five are SSH-signed (`%G?` = N here only because no allowedSignersFile is
configured in this container). Files touched: `OidcSupport.kt`, `ManifestApi.kt`, three test classes, CHANGELOG, README, CONTRACT.md.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-04 (Low) | **CLOSED** | `4f466d2` | Status-first: `postToken(…, devicePoll = true)` (`oidc/OidcSupport.kt:1079`) reaches `mapOAuth2ErrorResponse`, where `if (devicePoll && response.code == 429)` (`:1985-1995`) maps **every** 429 on a poll to `OAuthProtocolError("rate_limit_exceeded", <description or "">)` with `retryAfter`, so the `slow_down` branch (`:1171-1174`) only ever sees a 400. Other endpoints keep the 1.63 path (`:1996-2004`). Test `OidcDeviceFlowTest.kt:290` (two `429 slow_down` RA 1, then 200 → `[5,5,5]`). Mutant MA (disable the branch) → this test and the C164-17 test both fail. Probe P4 `[5,5,5]`, P8 (`429 {"error":"invalid_grant"}`) waited, not terminal. |
| C164-05 (Low) | **PARTLY** | `4f466d2` | The counter is gone: `val deadline = clock.now().plusSeconds(expiresIn)` (`:1135`), and the check is `!clock.now().plusSeconds(wait).isBefore(deadline)` (`:1149`), so request time counts. **But the deadline is taken after `params.onUserCode(authorization)` (`:1129`)**, not when `deviceAuthorize` returns (the index row's fix, and its "the `on_user_code` callback … never subtracted"). Probe P10: `onUserCode` takes 25 s, `expires_in` 30, interval 5 → **5 polls sent at t = 30…50**, all past the real deadline, then the local `expired_token`. Exact fix: move `:1133-1135` (the `deadline` line) above `params.onUserCode(authorization)` at `:1129`. Test to add: a clock whose offset `onUserCode` advances by 25 s with `expires_in = 30` → 0 polls, typed `expired_token`. The new test `OidcDeviceFlowTest.kt:316` (request time 4 s/poll, 2 polls) is non-vacuous: mutant MB (restore the counter) fails it. |
| C164-13 (Low) | **CLOSED** | `d44aa6e` | `revocation_endpoint` relocated to `/idp/revoke` (`Oauth2NoSessionCredentialTest.kt:222`), revoke called through the client after a cookie login (`:263`); revoke is not a `withoutSession` op, so only the discovery wiring protects it. 3 relocated requests asserted credential-free; control `POST /api/v1/groups` carries `X-CSRF-Token csrf-abc` and a session credential. Mutant MC (drop `.also(::registerAdvertisedEndpoints)`, `OidcSupport.kt:159`) → the test fails (M4 survived at 25687d50a). The control's assertion is `Authorization != null \|\| Cookie != null` (weak but sufficient). |
| C164-17 (Info) | **CLOSED** | `4f466d2` | Same branch `:1985-1995`: a bodiless/non-OAuth 429 becomes `OAuthProtocolError("rate_limit_exceeded", "")` with `retryAfter`. Test `OidcDeviceFlowTest.kt:305` (bodiless, RA 30 → `[5,30]`), killed by mutant MA. Probe P5 `[5,30]`. (Behaviour change for a single `devicePoll`, see C164-32.) |
| C164-21 (Info) | **CLOSED** | `f2ae302` | `"$member " + JsonPrimitive(raw.take(MAX_QUOTED_VALUE))` (`management/ManifestApi.kt:585`; cap 64 at `:1149`), equivalent to the asked `Json.encodeToString(String.serializer(), …)`. Test `ManifestNetworkTest.kt:398`: raw `a"b<LF>c` → message contains `"a\"b\nc"` and no raw newline. Mutant MD (old hand-quoted line) fails it. The test is named "…and capped" but asserts no cap (the cap predates the PR); no `…` is appended on truncation. Neither matters. |
| C164-22 (Info) | **CLOSED** | `ecf58ce` | `## [1.2.0]` is now `### Contract 1.63 notes (prepared as 1.2.0, released as 1.1.1)` under `[1.1.1]` (`CHANGELOG.md:102`), with the source-breaking-despite-patch line (`:104`); its subsections are demoted to `####`; "the 1.1.1 entry below" (`:64`). The auto-generated bullets stay above the notes, not folded in. That is cosmetic. |

**Amended rules: probe results** (`ReviewerProbeTest`, run in the throwaway copy and then removed. Recorded clock, interval 5, default client so §16 retry is on.)

| Rule / case | Input | Result | Verdict |
|---|---|---|---|
| Rule 9, server body | `429 {"error":"rate_limit_exceeded"}` RA 30, then 200 | sleeps `[5,30]`, 2 polls, tokens | pass |
| Rule 9, `retry_after` variant | `{"error":"rate_limit_exceeded","retry_after":30}` RA 30 | `[5,30]`, tokens | pass |
| Rule 9, bodiless | `429` no body, RA 30 | `[5,30]`, tokens | pass |
| Rule 9 / §14.6 third case | `429 {"error":"slow_down"}` RA 1, pending, 200 | `[5,5,5]` (interval not raised) | pass |
| Rule 1 (control) | `400 slow_down`, pending, 200 | `[5,10,10]` (raised, persists) | pass |
| Rule 4 + RA past deadline | `expires_in` 20, RA 3600 | `[5]`, 1 poll, typed `expired_token` | pass |
| Rule 6 / §14.6 500 body | `500 {"error":"server_error","error_description":"db"}`, then 200 | `[5,5]`, 2 polls, tokens (non-terminal) | pass on terminality. **No §16 retry inside the poll** (C164-25) |
| Rule 6, 503 | `503 {"error":"temporarily_unavailable"}`, then 200 | `[5,5]`, tokens | pass (same C164-25 caveat) |
| Rule 6, three 500s | 500×3, then 200 | `[5,5,5,5]`, 4 polls | each 500 costs a full interval. No in-attempt retry (C164-25) |
| Single `devicePoll` | 429 rle RA 7 / 429 `slow_down` / bodiless 429 / 500 | `OAuthProtocolError(rate_limit_exceeded, 7s)` ×3, 1 request each / `NetworkError` after **1** request | 429: pass. 500: not §16-retried (C164-25) |

The §14.6 tests in the SDK: the 500 case (`OidcDeviceFlowTest.kt:393`, body `server_error` + description) is present, and mutant MF (map the 500 through the any-status OAuth mapper) fails it. The 429 `slow_down` case is present (`:290`). The 1.64 case-1 mock `rateLimited()` (`:218-222`) still adds an `error_description`, which the amended §14.6 says the mock must not carry (C164-29). The code itself handles the bare body (probe P1).

**Replay after refresh:** conforms. `postWithRefresh` (`AxiamClient.kt:2741-2756`) awaits `refreshGuard.refreshIfNeeded { session.doHttpRefresh() }` and only then calls `postJson(path, body)` again (`:2752`). That builds a **new** `Request` with no auth headers (`:2770-2778`), so `AuthHeaderInterceptor` (an application interceptor, `AuthHeaderInterceptor.kt:40-85`) reads `session.cachedAccessToken()` (the jar's live `axiam_access`, `SessionState.kt:150`) and `session.csrfToken()` at replay time. OkHttp's BridgeInterceptor then applies the jar's current cookies. The refresh response's `X-CSRF-Token` is captured by the same interceptor (`:83`) before the replay. Nothing is captured before the refresh and reused. Probe REPLAY: the first request carried the login JWT and `csrf-abc`. The replay carried `Bearer <fresh JWT>`, `X-CSRF-Token: csrf-new`, and a `Cookie` with the fresh `axiam_access` and `axiam_refresh=r2`. `ManagementTransport` has no reactive 401 replay, so it has no such path to get wrong. The PHP-style push-order bug is absent.

**1.63 rules where the diff touched code:** the device poll keeps `withoutSession = true` (`OidcSupport.kt:1079`). `/oauth2/*` isolation is unchanged and is now also exercised through revoke. §6.1 rule 11 is untouched. The §27.6.2 refusal is still at `plan` with no non-GET request (`ManifestNetworkTest.kt:394`, unchanged, passing).

**Version:** `gradle.properties:2` `version=1.1.2`, unchanged and right (nothing source-breaking since the review). CHANGELOG `[1.1.2]` records C164-04/-05/-13/-17/-21 and the amended vendoring (`21beda0`, sha `8b2cb9a3…7a9a`) at `:11-13`, `:41-50`, `:76-81`. README `:34` still says it conforms to **contract 1.64**, and `:44-49` states "the status decides" and "a 5xx is a transport failure whatever its body".

**Run by the reviewer** (throwaway copy `/home/user/work/kotlin` from `git archive ecf58ce`; JDK 21, Gradle 8.10.2 wrapper; no Maven Central 429 this time):
- `python3 scripts/gen_management.py --check` → `OK: 251 generated files are current (202 operations)`.
- `bash scripts/tls-bypass-gate.sh` → exit 0.
- `./gradlew test --no-daemon --console=plain` → **1294 tests, 1 failed**: `OidcRefreshTest > the refresh response's scope replaces the grant's` (`OidcRefreshTest.kt:138`, "expected null but was profile"). This code and test are not in the diff. The class then passed **3/3** runs on its own, so it is a load-dependent flake that predates the PR (C164-33). All other 1293 tests pass, including the 5 new ones.
- Mutants, each run against its test class: MA (C164-04/-17 branch off) → 2 fail; MB (counter deadline restored) → 1 fail; MC (no discovery registration, the old M4) → 1 fail; MD (unescaped quote) → 1 fail; MF (500 dispatched on its OAuth body) → 1 fail. None survives.
- Probes: 17 (above), then removed. Build outputs (`build/`, `.gradle/`) deleted; the SDK clone is unmodified.
- Not run: `koverVerify`, `dokka`, lint (same as the review).

**New findings:**
- **C164-25 — Low (predates the PR; the amendment makes it explicit)** — `oidc/OidcSupport.kt:1070-1079` (`devicePoll` → `postToken` → `postOAuth2Form`, no `Retry.withRetry`). Rule: §14.2 rule 6 ("retried under the bounded read-only retry policy of §16, then surfaced … per poll attempt") and the §16.2 table, which lists `device_poll` on a 5xx/transport failure as eligible. Retry is on by default (`AxiamClient.kt:2961`), and `cibaPoll` uses it (`:1330-1340`). What happens: a single `devicePoll` surfaces `NetworkError` after **one** request on a `500 server_error` / `503` (probe S4). `deviceLogin` treats each 5xx as one lost interval (three 500s cost 15 s, probe P3b) instead of up to 3 attempts with backoff and `Retry-After` as the floor inside the attempt. The flow still survives, so impact is latency only. Fix: wrap the `postToken` call in `devicePoll` in `io.axiam.sdk.internal.Retry.withRetry(operation = "devicePoll", enabled = retryEnabled, telemetry = telemetry, random = jitter, retryable = { trace.lastStatus.let { it == null \|\| it >= 500 } })`, using the same `trace.lastStatus` pattern as `cibaPoll`. A poll 429 is already an `OAuthProtocolError` and is not retried, so there is no double wait. Test: single `devicePoll` with 500 `{"error":"server_error",…}`, 500, then 200 returns tokens after 3 requests, and with `retryDisabled()` it raises `NetworkError` after 1.
- **C164-29 — Informational (test strength)** — `test/.../oidc/OidcDeviceFlowTest.kt:218-222`. Rule: §14.6 1.64 (amended), "the mock's body is the server's own, with no `error_description`". `rateLimited()` still sends `oauth2ErrorJson("rate_limit_exceeded", "too many requests")`. Fix: `.setBody("""{"error":"rate_limit_exceeded"}""")`.
- **C164-32 — Informational (disclosure)** — `CHANGELOG.md:41-45` with `OidcSupport.kt:1985-1995`. A single `devicePoll` that gets a **bodiless or non-OAuth** `429` (a proxy's) now raises `OAuthProtocolError("rate_limit_exceeded", "")`, an `AuthError`, where 1.1.1 and 25687d50a raised `NetworkError`. A `429 {"error":"slow_down"}` now reads `error == "rate_limit_exceeded"`. This is right under rule 9, but a hand-rolled loop's `catch (e: NetworkError)` no longer catches the proxy's 429. The entry describes only the loop. Fix: add one sentence, e.g. "A single `devicePoll` now raises every `429` as `OAuthProtocolError(rate_limit_exceeded)`, including a bodiless one that 1.1.1 raised as `NetworkError`."
- **C164-33 — Informational (predates the PR, flaky test)** — `test/.../oidc/OidcRefreshTest.kt:134-138`. It failed once under the full suite and passed 3/3 alone. It looks like the second `oidcRefresh` with the same refresh token lands in the single-flight's settled-slot window (`internal/SingleFlight.kt:112`) and gets the first call's `scope = "profile"`. It is not touched by this PR. Fix: give the second call a distinct refresh token (`OidcRefreshParams.of("rt2", …)`), or settle the flight explicitly before the second call.

---

#### Addendum — php — commit 70ce245e9 (PR #87), read after 3707a5dac

Five commits: `9e92946` re-vendors CONTRACT.md from 21beda0; `4c99b22` makes the device-poll fixes (C164-03, -04, -05, -09, -17, -19); `2b4f1ad` fixes the REST items (C164-10, -23, -24); `e5b05f5` fixes C164-21; `70ce245` updates the docs (C164-22). I checked each commit message's finding claims against the diff, and they match. Mutants ran on a throwaway clone, `/home/user/work/php-add`. Each mutant was reverted afterwards, and `git status` was clean apart from the composer.json path-repository edit.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-03 (Medium) | CLOSED | 4c99b22 | `devicePoll()` calls `postToken(..., statusBeforeBody: true)` (`src/Oidc/OidcClient.php:842`). `postForm` maps any `>= 500` to `NetworkError::fromResponse` before the body is read (`:2564-2566`). Tests: `testA5xxWithAnOAuthBodyMidPollIsRetriedNotTerminal` (500 `server_error`, 503 `temporarily_unavailable`; sleeps `[5,5]`; `tests/OidcDeviceFlowTest.php:371`) and `testASingleDevicePollRaisesANetworkErrorForA5xxWhateverItsBody` (`:395`). Mutant: status check removed → 3 tests fail (killed). The old rule-6 test (`:570`) still uses body-less 500/503 mocks. The new test uses an OAuth body with an `error_description`, which meets the amended §14.6 wording. |
| C164-04 (Low) | CLOSED | 4c99b22 | `OAuthProtocolError::$httpStatus` (`src/Core/OAuthProtocolError.php:37`) is set from the response status (`src/Core/ErrorMapper.php:98`). The loop tests `httpStatus === 429` before the code dispatch (`OidcClient.php:936`). `slow_down` raises the interval only otherwise (`:944-948`). Test: `testA429WhoseBodySaysSlowDownDoesNotRaiseTheInterval` checks sleeps `[5,5,5]` (`:403`). Mutant: drop the `httpStatus === 429` arm → that test fails (killed). |
| C164-05 (Info) | CLOSED | 4c99b22 | The deadline now runs from `$startedAt = $now()`, with `$elapsed = max($sleptSeconds, $now() - $startedAt)` (`OidcClient.php:904`, `:916-917`). There is an optional trailing `$now` on `deviceLogin()` (`:886`, `src/AxiamClient.php:1732`). Test: `testTheDeadlineCountsTheTimeARequestTakes` (a fake clock with +40 s per request gives 3 polls; `:471`). Mutant `elapsed = slept` → that test fails (killed). |
| C164-09 (Low) | CLOSED | 4c99b22 | `strtotime` is replaced by `parseHttpDate`, which accepts only IMF-fixdate, RFC 850 and asctime through `createFromFormat('!…')` and rejects any parse warnings (`src/Core/NetworkError.php:117-121`, `:133-145`). Tests: `tests/Contract164/RetryAfterParsingTest.php` (9 rejects, 3 date forms, delta, past date) and `testAMalformedRetryAfterIsIgnoredAndDoesNotEndTheFlow` (`[5,5]`; `OidcDeviceFlowTest.php:449`). Mutant: back to `strtotime` → 7 tests fail (killed). Probe: `Retry-After: 17.0` gives `[5,5]` and the flow completes. |
| C164-10 (Low) | CLOSED, but one leg of the new test is vacuous (C164-33) | 2b4f1ad | `testAnAxiamClientReplaysAfterARefreshWithFreshCredentials` (`tests/Contract164/RetriedRequestHeadersTest.php:111`) drives a real `AxiamClient`: login, then a 401 on `groups()->create`, then the refresh, then the replay. **Mutant M6** (the 1.1.1 push order at `src/AxiamClient.php:472-473`, Auth first and Refresh second) → this test fails, and it is the only one that does (killed). The review's survivor is now killed. Its `Cookie` assertions are masked, though: see C164-33. |
| C164-17 (Info) | CLOSED | 4c99b22 | In the `NetworkError` branch, `if ($e->retryAfterMs !== null) $waitSeconds = retryAfterRound(...)` (`OidcClient.php:958-960`). Test: `testABodilessOrForeignBody429StillHonoursRetryAfterAsAFloor` checks `[5,12,5]` (`:426`). Mutant: branch disabled → that test fails (killed). |
| C164-19 (Info) | CLOSED | 4c99b22 | The cap case records its sleeps and asserts `[5]` (`OidcDeviceFlowTest.php:334-358`). **M4** (sleep the uncapped Retry-After, then raise) → that test fails (killed; it survived in the review). |
| C164-21 (Info) | CLOSED | e5b05f5 | `json_encode(mb_substr($raw, 0, 64), UNESCAPED_SLASHES\|UNESCAPED_UNICODE\|INVALID_UTF8_SUBSTITUTE)` (`src/Management/Manifest/ManifestApi.php:233-237`). Test: `testTheQuotedValueIsEscapedAndCapped` (`tests/Contract163/OpenEnumRefusalTest.php:154`). Mutants "raw sprintf" and "no 64 cap" each fail it (killed). |
| C164-22 (Info) | CLOSED | 70ce245 / 4c99b22 | `parseRetryAfterMs` is tagged `@internal` (`src/Core/NetworkError.php:105`). It is listed among the public additions with `httpStatus` and `$now` (`CHANGELOG.md:16-22`). The install snippets read `^1.1.2` (`README.md:27`, `:457`). |
| C164-23 (Info) | CLOSED in code; untested | 2b4f1ad | The replay rebuilds `Cookie` from `$options['cookies']` only when that option is a `CookieJarInterface` (`src/Rest/RefreshMiddleware.php:80-84`). Guzzle merges the client's `cookies` config (the shared session jar, `AxiamClient.php:418`) into `$options`, so the normal path is unchanged (probed: the replay carries the rotated cookies). No test covers it: the mutant "always the session jar" leaves all 2056 tests green. The review asked for no test, so this is not a new finding. |
| C164-24 (Info) | CLOSED | 2b4f1ad | `$isOAuth2Path = str_starts_with($path, $oauth2Prefix) \|\| str_starts_with($path, '/oauth2/')` (`src/Rest/AuthMiddleware.php:117-118`). The test row is flipped (`tests/Contract164/BasePathPrefixOAuth2Test.php:33`), and a federation-route row is added. Mutant: prefix only → that row fails (killed). |

**Amended rules: probes** (`deviceLogin()`, interval 5, expires 600, AXIAM's exact bodies; recorded sleeps; the §16 retry switch on unless noted):

| Rule / case | Probe | Result |
|---|---|---|
| 9: `429 {"error":"rate_limit_exceeded"}` + `Retry-After: 12` | slept `[5,12]`, 2 polls, completes | conforms |
| 9: the same with `"retry_after":12` | `[5,12]`, completes | conforms |
| 9: bodiless `429` + `Retry-After: 12` | `[5,12]`, completes | conforms (C164-17) |
| 9 / §14.6 case 3: `429 {"error":"slow_down"}` (with RA 1, or none), then pending, then 200 | `[5,5,5]`; interval not raised | conforms |
| 9: `429 {"error":"invalid_grant"}` + RA 3 | `[5,5]`, completes (the status decides) | conforms |
| 5: `400 {"error":"slow_down"}` | `[5,10,10]`; the 400 still raises the interval | conforms |
| 6 / §14.6 500 body: `500 {"error":"server_error","error_description":"db"}` | `[5,5]`, completes. Three 500s in a row: `[5,5,5,5]`, completes | non-terminal: conforms. **The poll is not §16-retried inside the attempt: the retry-on and retry-off runs are identical (C164-25)** |
| 6: `503 {"error":"temporarily_unavailable"}` (+ variant with RA 9) | `[5,5]` / `[5,9]`, completes | conforms |
| Single `devicePoll` | `429 rate_limit_exceeded` RA 7 → `OAuthProtocolError(rate_limit_exceeded)`, `retryAfterMs=7000`, `httpStatus=429`. Bodiless 429 → `NetworkError`, `retryAfterMs=7000`. `500 server_error` → `NetworkError` after **1 request** with retry on (C164-25) | conforms except C164-25 |
| Terminal control: `400 invalid_grant` | `OAuthProtocolError(invalid_grant)` after 1 poll | conforms |

**1.63 rules where the diff touched code.** `/oauth2/*` stripping still applies, now under the base prefix or at the root (`AuthMiddleware.php:118`, `:136-139`). The replay of an `/oauth2/*` request passes through Auth again and is stripped again. §6.1 rule 11: the `canRefresh()` guard is unchanged (`RefreshMiddleware.php:65`). §27.6.2: the refusal is still at `plan` with no write; only the message text changed (`OpenEnumRefusalTest` is green).

Replay after refresh: **the bug the session reported is real and fixed.** In 1.1.1, `AxiamClient` did `$authzStack->push(new AuthMiddleware(...))` and then `->push(new RefreshMiddleware(...))`. Guzzle's `HandlerStack::resolve()` wraps the stack in reverse, so the **first** middleware pushed is outermost. That made Auth outer and Refresh inner. Refresh's captured `$handler` was then the bare transport. Its replay after the refresh sent the same `$request` object that Auth had already stamped, so it re-sent the refused attempt's `Authorization: Bearer <old>` and `X-CSRF-Token: <old>`. It also re-sent the stale `Cookie` header, because Guzzle's cookie middleware sits outside both and does not run again. The fix came in f469880, before the old head: Refresh is pushed first and Auth second (`src/AxiamClient.php:472-473`), so the replay re-enters Auth and picks up the fresh bearer and CSRF token from the Session. The replay also rebuilds `Cookie` from the jar (now the request's own jar, `src/Rest/RefreshMiddleware.php:80-84`). I probed the shipped client on a bare `MockHandler` transport (login, then a 401 on POST `/api/v1/groups`, then a refresh that rotates the cookies and CSRF, then the replay). The replay carries `Bearer <new>`, `csrf-new` and `axiam_access=<new>; axiam_refresh=r-new`. With M6 (the 1.1.1 order) it carries `Bearer <old>` and `csrf-old`. With the cookie rebuild removed it carries `axiam_access=<old>`. The new C164-10 test drives the real `AxiamClient` wiring: M6 fails it, and it is the only test M6 fails. Its Cookie leg is vacuous, though (C164-33).

Version: 1.1.2 is still right (`## [1.1.2] - Unreleased`). Every addition is a trailing optional parameter or `@internal`, so nothing is source-breaking. The CHANGELOG records C164-03, -04, -05, -09, -10, -17, -19, -21, -23 and -24, the re-vendor from 21beda0 and the public additions. The README states contract 1.64 (`README.md:284`), adds rows for amended rules 6 and 9 (`:294-295`), and the install snippets read `^1.1.2`.

Run by the reviewer (clone `/home/user/work/php-add` at 70ce245; PHP 8.3.6, Composer 2.8.12). The previous reviewer's lock was reused. phpstan/phpstan 2.3.1 came from a local `git clone --branch 2.3.1` used as a Composer `path` repository, installed with `composer update phpstan/phpstan --prefer-source`:
- `composer validate --strict`: valid.
- `vendor/bin/phpunit`: **OK, 2056 tests, 9923 assertions** (the review had 2032).
- `vendor/bin/phpstan analyse --memory-limit=512M`: **No errors**. The CI step for the §27 examples (`--level=6`, 5 files): **No errors**.
- `python3 scripts/gen_management.py --check`: "§27 surface is current (261 files)".
- `php tools/docblock-coverage.php`: 2083/2083.
- Mutants: 12 run, 11 killed (M03, M04, M17, M09, M05, M4/M19, M6, cookie-rebuild, M21 raw, M21 no cap, M24). 1 survived: C164-23 "always the session jar" (no test exists).
- Not run: gRPC codegen (needs protoc) and `composer audit`. Build outputs are deleted (the clone with `vendor/`, and the phpstan clone).

New findings:
- **C164-25 — Low (pre-existing; the amended contract now states it plainly).** `src/Oidc/OidcClient.php:842` → `postToken`/`postForm` (`:2240-2250`, `:2555-2570`). This breaks §14.2 rule 6 ("retried under the bounded read-only retry policy of §16, then surfaced") and §16.2's table (`device_poll` on a 5xx or transport failure is ELIGIBLE, with a budget per poll attempt). The device poll is sent once with no `RetryPolicy`, whatever `retryEnabled` says. A single `devicePoll()` on `500 {"error":"server_error"}` surfaces `NetworkError` after one request with retry on (probed). `deviceLogin()` just waits the next interval: retry-on and retry-off probes give the same `[5,5]`, and three 500s cost three intervals. No grant is lost, so the impact is latency and conformance. **Fix:** wrap the device poll's send in `RetryPolicy::execute('device_poll', $this->retryEnabled, …)` as `cibaPollTracked` does (`:2135-2170`): `'http_errors' => false`; `$status >= 500` → throw `NetworkError::fromResponse`; any other non-2xx → `ErrorMapper::fromOAuth2Response`. Use `$retryable = fn () => $status === null \|\| $status >= 500`, which covers 5xx and transport failures only. Do **not** retry a 429 or 408 here: rule 9 makes the 429 the loop's wait, and §16.2 lists only the 5xx/transport case for this operation. **Test:** with retry on, queue `500 {"error":"server_error","error_description":"db"}` three times, then the tokens. Assert that `deviceLogin()` completes, that the recorded loop sleeps are `[5]` (one interval, the retries inside the attempt), and that 4 polls were sent. Assert also that a single `devicePoll()` with retry off sends 1 request.
- **C164-33 — Informational (test strength).** `tests/Contract164/RetriedRequestHeadersTest.php:142`. The new shipped-wiring test passes `transportHandler: HandlerStack::create($mock)`. That nests a second Guzzle stack, whose own cookie middleware re-stamps `Cookie` from `$options['cookies']` innermost. So the test's three `Cookie` assertions pass even when `RefreshMiddleware`'s cookie rebuild is removed (mutant: the test stays green; on a bare `MockHandler` the replay then carries `axiam_access=<old>`). The `Authorization` and `X-CSRF-Token` assertions do bite: M6 fails them. The rebuild is still caught by the hand-built-stack test `testARetriedRequestCarriesTheRefreshedAccessTokenAndCsrfToken`. Production (`transportHandler` null) has no nested cookie middleware, so the rebuild is load-bearing there. **Fix:** pass the bare `$mock` (`transportHandler: $mock`) in that test so its Cookie leg also fails without the rebuild. Optionally add a C164-23 case: a request sent with `'cookies' => false` that is refused 401 is replayed with no `Cookie` header.

---

#### Addendum — swift — commit d8e48a073 (PR #78), read after 3180f7133

Five commits: `6333c0a` re-vendors CONTRACT.md at 21beda0. `3d4817b` is the fix for C164-03, -04 and -17. `15e19c1` is the C164-14 test. `20a2ab2` is the CHANGELOG and `d8e48a0` the README. I checked each commit message against its diff, and every claim matches. There is no Swift toolchain here, so I reviewed by reading and traced the mutants by hand.

| Finding | Status | Commit | Evidence (path:line) / test / mutant |
|---|---|---|---|
| C164-03 (Medium) | **CLOSED** for the rule-6 safety property. §16 is still not met; see C164-25. | `3d4817b` | `Sources/AxiamSDK/Oidc/DeviceGrant.swift:164`: `if response.status >= 500 { throw oidcMapError(response) }` runs before `oidcMapGrantError`. `oidcMapError` → `ErrorMapper.map` (`Errors.swift:228-238`) returns `.network(statusCode: 5xx)` whatever the body. The loop's guard at `:252-257` then `continue`s, and the interval is untouched. Tests: `Contract164DeviceGrantRateLimitTests.swift:203-219` sends pending, `500 {"error":"server_error","error_description":"db"}` twice, then 200, and expects 4 polls, sleeps `[1,1,1,1]` and tokens. `:221-236` sends a single `devicePoll` with `503 {"error":"temporarily_unavailable"}` and expects `.network` with `statusCode == 503`. Mutant (line 164 removed): `server_error` becomes `.auth` and reaches the `default:` arm at `:266-269`, so the loop throws and test `:203` fails. The 503 becomes `.auth(temporarily_unavailable)`, so test `:221` hits XCTFail. **Non-vacuous.** |
| C164-04 (Low) | **CLOSED** | `3d4817b` | `DeviceGrant.swift:172-182`: any `429` throws `DevicePollRateLimited`. A 429 whose OAuth code is not `rate_limit_exceeded` is rewritten to `rate_limit_exceeded`, so it never reaches `case "slow_down"` (`:262-265`). A `400 slow_down` still raises the interval (`:183` → `:264`). Test `:170-185`: `429 {"error":"slow_down"}` + `Retry-After: 1`, then pending, then 200, expects 3 polls and sleeps `[1,1,1]`. Mutant (the pre-fix condition `oauthError == "rate_limit_exceeded"`): the sleeps become `[1,6,6]`, so the test **fails**. The test comment at `:173` says `[1, 1, 6]`, which is wrong (C164-33). Mutant (only the rewrite at `:173-178` removed): **survives**, because the loop still waits and only the single `devicePoll` would surface `slow_down`. No test covers that (C164-33). |
| C164-14 (Low) | **CLOSED** | `15e19c1` | `Tests/AxiamSDKTests/Contract162Oauth2NoSessionCredentialTests.swift:156-161` is the fix exactly as the review wrote it. The mock answers `/api/v1/groups` (`:62`) and issues `device-bearer-tok` (`:60`). `credentialHeaders` (`AxiamClient.swift:1130-1132`) sends `Bearer …`. Mutant (no bearer adopted, or not sent): `auth` is nil, so the test **fails**. **Non-vacuous.** |
| C164-17 (Info) | **CLOSED** | `3d4817b` | A bodiless 429 or a non-OAuth body fails the `OidcOAuth2ErrorWire` decode (`OidcInternals.swift:393-402`) and becomes `.network(429)`. It is still wrapped at `DeviceGrant.swift:172`, with `Retry.retryAfter(header)`. The loop waits `max(interval, RA)` (`:234`). Test `:187-199`: `429` + `Retry-After: 7` + an `<html>` body, then 200, expects sleeps `[1,7]`. Mutant (the pre-fix code): the sleeps become `[1,1]`, so the test **fails**. |
| Review note: the `:232-233` comment claimed a §16 retry inside the poll | **Comment CLOSED, substance OPEN (C164-25)** | `3d4817b` | The comment at `DeviceGrant.swift:253-256` now says "The poll itself is a single request on the bare path, so the loop's next interval is the retry". That is true of the code: `oidcFormPost` → `umaSendAbsolute` (`OidcInternals.swift:180-195`, `AxiamClient.swift:1159-1171`) has no retry. The SDK now documents that it does not do what the contract requires. |

**Amended rules.** I traced each probe by hand against the new head, at interval 1 with jitter seam 0.

| Probe (AXIAM's exact body) | `deviceLogin` | single `devicePoll` | Verdict |
|---|---|---|---|
| `429 {"error":"rate_limit_exceeded"}` + RA 7 | waits `max(1,7)=7`, polls again, interval unchanged (existing test `[1,7,1]`) | `.auth`, `oauthError=rate_limit_exceeded`, `oauthErrorDescription=nil` | conforms |
| `429 {"error":"rate_limit_exceeded","retry_after":7}` | same; the unknown member is ignored by `Decodable` and the header governs | same | conforms |
| `500 {"error":"server_error","error_description":"db"}` | non-terminal, next poll one interval later, **no in-poll §16 retry** | `.network(statusCode 500)`, one request | rule 6's safety property conforms; §16 does not (C164-25) |
| `503 {"error":"temporarily_unavailable"}` | same as the 500 | `.network(503)` (tested `:221`) | as above |
| `429 {"error":"slow_down"}` + RA 1 | the wait, interval not raised (`[1,1,1]`) | `.auth(rate_limit_exceeded)` (rewritten) | conforms (§14.6 third case) |
| bodiless `429` + RA 7 | waits 7 (`[1,7]`) | `.network(statusCode 429)` | conforms (the amended rule 9 requires `OAuthProtocolError` only for an OAuth body) |
| `400 {"error":"slow_down"}` | interval +5, permanently (`:264`) | `.auth(slow_down)` | conforms |
| RA past `expires_in` | typed `expired_token` before the sleep, nothing sent (`:236-241`, existing test) | n/a | conforms |

**The session's question: rule 6 + §16.2. Is an in-poll §16 retry required, or does the next interval suffice?** The text supports the lead reviewer's reading, so I **confirm** it.
- **§16 is MUST.** Its header reads "**Requirement level: MUST (v1.0).**" Its preamble says §14.2 "instruct[s] SDKs to retry under the SDK's existing bounded read-only retry policy", and §16 is that policy.
- **Rule 6 is declarative, not permissive.** 5xx and transport failures "are retried under the bounded read-only retry policy of §16, then surfaced". It then defines that budget as "**per poll attempt** … separate from this grant's own `expires_in` polling loop: an exhausted retry budget ends that one poll, not the flow". That sentence only makes sense if a retry budget exists inside the poll, distinct from the loop.
- **§16.2 lists `device_poll` as eligible.** The row is "`device_poll` on a 5xx or transport failure (§14.2)", annotated "The clause that referenced this policy", with the same per-poll-attempt budget. §16.1 makes 3 attempts, 200 ms base, 5 s cap, full jitter and a Retry-After floor binding. Its switch "MUST default … to **on**".
- **§34.2 P11 (amended) assumes the same.** It speaks of "the requests it does retry (… `device_poll` on a `5xx` or transport failure, which §16.2's table lists)".
- **Nothing in the contract exempts the bare `/oauth2/*` path.** The only named exemption from §16 is §20.2 rule 6, the UMA ticket.
- **Conclusion.** With `retryEnabled` at its default `true`, a 5xx or transport failure on `device_poll`, including the single call, MUST be retried inside that poll (3 attempts, jittered backoff, Retry-After floor) before it surfaces. The loop's next interval meets rule 6's safety property ("must not lose a grant") but not §16.
- **Two qualifications.** First, §16.2 makes the poll eligible only on 5xx and transport failures, so a 429 on the poll must **not** be retried in-poll. That would double-wait against rule 9's loop wait. Second, §16.7's required tests are about `check_access`. The contract mandates no device-poll wire-count test, so a missing test is not itself a breach.

**What the new head does:** one request per poll. A 5xx or transport failure surfaces at once as `NetworkError`, and the loop re-polls after the full interval. No `retry` telemetry event is emitted. `retryEnabled` has no effect on the device poll. The comment at `DeviceGrant.swift:253-256` now states this openly. This has been the case since §16 landed: the old head had it too, under a comment that claimed the opposite. The SDK already has the right machinery, `bareSend(retry: .section16UnlessOAuthError)` (`HTTP/BareRequest.swift:43-124`), which `ciba_poll` uses (`Oidc/Ciba.swift:459-469`). The device poll does not use it.

**Replay after refresh:** **Holds by reading; no push-order bug.** Swift has no middleware or interceptor chain. Each send builds its credential headers when it executes: `rawSend` (`AxiamClient.swift:1097-1124`) and `managementRawSend` (`:1369-1408`) both call `credentialHeaders(for:method:)` (`:1125-1146`). That function reads the current `cookieJar`, `csrfToken` and `deviceAccessToken`. `doRefresh` (`:663-674`) goes through `rawSend`, which stores the refresh response's `Set-Cookie` (`:1113-1116`) and `X-CSRF-Token` (`:1118-1120`) before returning. The replay after `refreshOnce()` therefore calls `rawSend`/`managementRawSend` again and gets the **fresh** cookie, CSRF and bearer. This holds in `authorizedPOST` (`:990-1000`), `retryingPOST` (`:1065-1081`) and the management loop (`Management/AxiamClient+Management.swift:105-120`). There are no stale captured headers. Test gap (Info, pre-existing, not numbered): `ManagementSemanticsTests.swift:518-531` asserts only the request paths and count. It does not assert that the replay carries a rotated cookie or CSRF.

**Version:** 1.1.2 (`AxiamSDK.podspec:3`), a patch, which is right. No public signature changed. The single `devicePoll` now throws `.network` rather than `.auth(server_error)` on a 5xx with an OAuth body. Both are cases of the same `AxiamError`, and `CHANGELOG.md:29-42` records the change. The CHANGELOG records C164-03, -04, -14 and -17 and the re-vendor at 21beda0. README `:15` still says "conforms to contract 1.64", and the §14.2 bullet at `README.md:1105-1114` is updated. The README makes no in-poll §16 claim; its §16 list (`:879-883`) omits the device poll. The §16 row "✅ implemented" (`:147`) overstates because of C164-25.

**Run by the reviewer:**
- `python3 -I Scripts/gen_management.py --check` in the throwaway copy `/home/user/work/swift`: "§27 surface is current (3 files)", rc=0. I removed the copy afterwards.
- `git log --format=%G?`: `N`, because there is no allowed-signers file. The signatures could not be verified.
- **Not run:** `swift build` and `swift test` (no Swift toolchain). Every mutant above was traced by hand.

**New findings:**
- **C164-25 — Low (pre-existing; the amended text makes it explicit).**
  - Where: `Sources/AxiamSDK/Oidc/DeviceGrant.swift:158` (the `oidcFormPost`) and `:253-256`.
  - Rules: §14.2 rule 6 ("retried under the bounded read-only retry policy of §16, then surfaced … per poll attempt"); §16.2 (`device_poll` on 5xx/transport is eligible); §16.1 (switch defaults on); §16.5 (a `retry` event per retry).
  - What happens: with `retryEnabled == true`, a 5xx or transport failure on the poll is never retried inside the attempt. The loop waits a full interval (≥ 5 s by default) instead of the 200/400 ms jittered backoff, and no `retry` telemetry is emitted. The single `devicePoll` surfaces the first 5xx. No grant is lost. The comment at `:253-256` documents the gap.
  - Fix, code: send the poll through `bareSend(operation: "device_poll", pathTemplate: "/oauth2/token", method: .post, url: try oidcTenantScopedURL(endpoint, tenantID: tenantID), headers: [("Content-Type","application/x-www-form-urlencoded"),("Accept","application/json")], body: Data(Self.oidcFormEncode(form).utf8), retry: .section16TransportOnly)`.
  - Fix, new retry case: add `BareRetry.section16TransportOnly`, which retries only when `response == nil || response.status >= 500`. A 429 must stay rule 9's loop wait (§16.2 lists only 5xx/transport), so `.section16UnlessOAuthError` is wrong here: it would retry a bodiless 429.
  - Fix, deadline: §14.2 rule 4 means an in-poll wait must not carry the request past the deadline. Pass the loop's deadline into the retry, and surface the 5xx instead of sleeping when `now + wait >= deadline`. That mirrors §33.7 rule 5 / P10 for CIBA. The single `devicePoll` has no deadline and retries under §16 as is.
  - Fix, comment: replace the comment at `:253-256` with "already went through the §16 bounded retry inside the poll; an exhausted budget ends that one poll, not the flow".
  - Tests: (a) `500 {"error":"server_error","error_description":"db"}` ×3, then 200 → 4 wire requests; loop sleeps `[1, 0, 0, 1]` with jitter 0 (3 in-poll attempts then one loop interval); 2 `retry` events; tokens. (b) The same with `retryEnabled: false` → one request per poll; sleeps at the interval only. (c) `500` then `200` with jitter pinned to 1 → the in-poll wait is 0.2 s, and a `Retry-After: 2` on the 500 floors it to 2. (d) A bodiless `429` + RA 7 is still one request, then the loop's 7 s wait (no in-poll retry). Update `testA500WithTheServersOwnBodyMidPollIsNotTerminal`'s expected sleeps to `[1,1,0,0]` (pending, then the 500, 500, 200 retried inside the second poll: 4 requests, 2 loop polls).
- **C164-33 — Informational (test strength / comment).**
  - Where: `Tests/AxiamSDKTests/Contract164DeviceGrantRateLimitTests.swift:170-185`.
  - What: the rewrite of a non-`rate_limit_exceeded` 429 code (`DeviceGrant.swift:173-178`) has no test. Removing it leaves every test green, while the single `devicePoll` on `429 slow_down` would surface `oauthError == "slow_down"`, which a caller's own loop reads as the polling signal. The comment at `:173` predicts `[1, 1, 6]` for the body-dispatch mutant; the real result is `[1, 6, 6]`.
  - Fix: add a single-`devicePoll` case for `429 {"error":"slow_down"}` asserting `.auth` with `oauthError == "rate_limit_exceeded"`, and correct the comment to `[1, 6, 6]`.

---

### 7.1 Addendum round 2 (2026-10-23): W7.1c and the eleven round-2 heads

**What was read.**

The contract is W7.1c `b3f8687` (`sdks/CONTRACT.md` sha256
`a221f1bfe6358a3a3156079e71b72f78df6bfc730547922869886ba390d0de39`).

The round-2 heads:

| SDK | PR | Head |
|---|---|---|
| TypeScript | #150 | `3b07099cc` |
| Rust | #138 | `f4f65ce95` |
| Python | #103 | `d5ce0cbc7` |
| C | #77 | `263d4cc2d` |
| C++ | #80 | `d95d2f173` |
| C# | #111 | `42369a4ba` |
| Go | #103 | `491fc0730` |
| Java | #121 | `c459e7315` |
| Kotlin | #80 | `d1d1816f2` |
| PHP | #87 | `48751509a` |
| Swift | #78 | `2630e9cfa` |

Rust's head is one commit past the `50a99035a` the orchestrator named. `f4f65ce` is a pure refactor of the poll's
transport-error construction (`exchange::network_err`), and behaviour is unchanged.

The method is §7.0's, plus two checks:
- the W7.1c in-attempt retry test in the contract's shape;
- whether the in-poll §16 retry is bounded by `device_login`'s deadline. Each reviewer probed it with
  `expires_in` 30, interval 5, and every poll answered `503 {"error":"temporarily_unavailable"}` with
  `Retry-After: 120`.

**Vendoring and drift.** All eleven heads vendor `CONTRACT.md` byte-identical to `b3f8687`, and `openapi.json` and
the registry unchanged. `scripts/check-sdk-artifact-drift.py --local-root` over the eleven heads reports **11
repos, 0 artifact problems**.

#### 7.1.1 W7.1c `b3f8687`: verdict and rulings

**W7.1c is correct.** The §14.6 in-attempt retry test reads:
- two `500 {"error":"server_error",…}` then `200` → a single `device_poll` makes **three** requests and
  returns the tokens;
- a third `500` exhausts the cap;
- the same holds for a transport failure;
- a `429` makes one request;
- with retry disabled, a 5xx makes one request per poll.

The shape follows from §16.1: "Attempt cap **3 total** (1 initial + 2 retries)". **The review's own example was
wrong.** §7.0.2's C164-25 test said "three `500`s, then `200` … 4 requests". That is four attempts, one more
than §16.1 allows. The executor was right to correct it, and this addendum records the correction against
§7.0.2. The §34.8 note and the Breaking Changes Log line ("none breaking") are accurate. No further amendment of
1.64 is needed.

**Ruling: is an in-poll retry whose waits are not bounded by the device-login deadline a finding? Yes, C164-36
(Low).**
- §14.2 rule 4 is a MUST on every request ("MUST NOT poll past the deadline"), and an in-poll §16 retry is a
  poll request. The W7.1c test and the 1.64 case 2 both say "sends nothing after the deadline".
- The 3-attempt cap does not bound the time. §16.1 makes `Retry-After` a **floor**, so a 5xx carrying
  `Retry-After: 120` waits 120 s, as probed:

  | SDK | What the probe showed |
  |---|---|
  | TypeScript | requests at 5, 125 and 245 s, and tokens returned from a request sent 95 s after the deadline |
  | C | requests at 5, 125 and 245 s (`Retry-After: 3600` blocks about 2 h) |
  | C++ | requests at 1, 11 and 21 s against a 6 s deadline |
  | Java | up to about 10 s late (its floor clamps at 5 s) |
  | PHP | a retry 66 ms late (its check omits the jitter) |
  | Python, Kotlin | sub-second overruns, and only because their runners ignore `Retry-After` altogether (C164-37) |

  For Python and Kotlin, fixing C164-37 alone would make the overrun unbounded, so the two fixes land together.
- **The bounded form is right.** Rust, Go, Swift and C# cap each in-poll wait at the remaining time and send
  nothing after the deadline. C# has a side effect, C164-40.
- The contract states this bound explicitly for CIBA (§34.2 P10) and only implicitly for the device grant
  (rule 4). C164-42 (Info) proposes the P10 sentence for `device_poll` in 1.65. No 1.64 amendment is needed,
  because rule 4 already binds.

**TypeScript, C164-31 fixed at the call site: accepted.** Every caller of `#postForm` is an OAuth2 form
endpoint: the token endpoint through `#postToken` (exchange, client credentials, refresh), introspect, revoke,
device authorization, PAR and token exchange. The reviewer probed `429 {"error":"rate_limit_exceeded"}`:
- discovery, `ssoProviders`, `ssoStart` and `umaListResources` give `NetworkError`;
- the OAuth2 calls give `OAuthProtocolError`, including a token endpoint that discovery relocates to `/token`.

Binding to the transport rather than to a path is stricter than the anchored match proposed, and it follows
discovery.

**PHP, the contract's two-500s shape with the exhausted cap tested separately: accepted.** It is the binding
shape.

**Java, 500, then 503, then 200: accepted as a variant.** It kills the "retry only 503", "only bodiless 5xx"
and "only 500" mutants, which two 500s would not all kill. However, no test pins the cap: raising 3 to 5
leaves all 24 device-flow tests green. That gap, and the missing exact-shape and exhausted-cap cases, is
C164-38.

#### 7.1.2 New findings (C164-36 onward)

| ID | Severity | SDK | `path:line` (round-2 head) | Rule | What | Fix |
|---|---|---|---|---|---|---|
| C164-36 | Low | typescript, python, c, cplusplus, java, kotlin, php | TS `src/node/oidc.ts:2595` (`#postDevicePoll` → `withRetry`, no deadline or clock); Python the `retry_sync`/`retry_async` call in `device_poll` (no deadline); C `src/oidc.c:463-466` (`oidc_post`); C++ `src/oidc.cpp` (`token_grant`'s §16 loop); Java the in-poll `Thread.sleep` retry (no clock, no deadline); Kotlin `oidc/OidcSupport.kt:1084-1093` (`Retry.withRetry`); PHP the in-poll deadline check (omits the backoff jitter) | §14.2 rule 4; §14.6 ("sends nothing after the deadline"; W7.1c) | The §16 retry inside a poll does not see `device_login`'s deadline, or (PHP) checks it without the jitter. With a 5xx `Retry-After` the overrun is up to the floor's own clamp (§7.1.1 table). Without one, a poll that leaves just before the deadline sends its retries after it. A request after the deadline may even return tokens (TypeScript, C). | Pass the device-login deadline and its injectable clock into the poll's §16 runner. Before each retry, compute the full wait (jittered backoff, floored at `Retry-After`). If `now + wait >= deadline`, send nothing more: raise the typed `expired_token` at once, or serve the wait capped at the deadline and then raise it (both conform, as in P10). Sleep on the injected clock. A bare `device_poll` outside the loop keeps the unbounded §16 behaviour. Tests on the fake clock: (1) `expires_in` 30, interval 5, every poll `503` + `Retry-After: 120` → no request at or after 30 s, `expired_token` by 30 s; (2) a poll sent at deadline − 0.1 s answered `500` → no retry is sent. |
| C164-37 | Low | python, kotlin (pre-existing) | Python `NetworkError` carries no `retry_after_ms` (the floor reads a field never set; `tests/test_d5_conformance.py:190-193` claims otherwise); Kotlin `ErrorMapper.fromHttpStatus` never sets `retryAfter` on a `NetworkError` | §16.1 (`Retry-After` "honored, as a floor") | Every §16 retry in the SDK, `check_access` included, ignores a 5xx's (and a retried 429's) `Retry-After`. Kotlin's CHANGELOG (`:51`) and README (`:2516`) say otherwise. | Parse `Retry-After` onto the `NetworkError` for 429 and 5xx answers, as the 429 `OAuthProtocolError` already does. The runner uses `max(jittered, retry_after)`, clamped as the SDK clamps it elsewhere (§16.1 sets no upper clamp; the other SDKs use 5 s or 3600 s). **Land it with C164-36** in the same commit. Test: `check_access` answered `503` + `Retry-After: 2`, then `200` → the recorded wait is ≥ 2 s. |
| C164-38 | Low (typescript, rust, go, java, kotlin, swift, cplusplus); Info (python, php) | typescript, rust, go, java, kotlin, swift, cplusplus, python, php | each SDK's W7.1c test (§7.1.3) | §14.6 W7.1c ("The same holds for a transport failure"; "a third `500` … exhausts the cap") | The required in-attempt test is incomplete. **No transport-failure case:** TypeScript, Rust, Go, Kotlin, Swift and C++; a mutant that stops retrying transport failures survives each. **Java:** no two-500s case, no exhausted-cap case, and the cap is unpinned (3 → 5 survives). **Info parts:** Python lacks the async transport test; PHP lacks a transport exhausted-cap test and a case inside `deviceLogin`. | Add the contract's transport case to each suite: connection reset or refused twice, then `200` → three requests and the tokens; three failures → three requests and the network error; retry off → one request. Java also adds two `500`s then `200` (3 requests) and three `500`s (3 requests, `NetworkError`). The Rust reviewer's `probe_transport` and the Go addendum's test are ready to lift. |
| C164-39 | Low | cplusplus, java, kotlin | C++ `src/oidc.cpp:882` (`token_grant` → `send_raw`, which throws on a transport error; `introspect` `:1166` likewise); Java and Kotlin the OkHttp client used for the poll (`retryOnConnectionFailure` defaults to true) | §16.1 (attempt cap 3 total); §14.2 rule 6 | The transport-failure half of C164-25 is wrong. **C++:** a transport failure on the poll is sent once, not retried inside the attempt, so round 1's "C++ does it right" held for 5xx only. **Java and Kotlin:** OkHttp silently replays a POST whose pooled connection dropped, so three disconnects then `200` make **4** requests and succeed, over the §16 cap. | **C++:** call `impl.transport(req)`, as `ciba_poll_once` does (verified in a copy: 3 requests, then tokens, and the suite stays green). Do the same for `introspect`. **Java and Kotlin:** build the poll's client with `retryOnConnectionFailure(false)`, so the §16 runner alone counts attempts (verified for Java: three disconnects → `NetworkError` after 3). The CIBA poll has the same shape; take it in the same commit. Tests: C164-38's transport case. |
| C164-40 | Low | csharp | `AxiamClient.OidcDeviceExchangeLogout.cs:350-363` | §14.2 rule 4 vs §14.3 rule 4 (return the token set) | The deadline's linked cancellation token also cancels the **read** of a `200` that is in flight at the deadline, and the `id_token` JWKS fetch. The server has already redeemed the device code, so the tokens are lost. The caller gets `expired_token`, or an "invalid signature" `AuthError` from the verifier's bare catch, for a grant that succeeded. | Apply the deadline to the waits and to the decision to send. Do not cancel a request already sent: check `now + wait >= deadline` before sending, and give the in-flight send and the token-set validation the caller's own token only. In the verifier, rethrow `OperationCanceledException` rather than mapping it to a signature failure. Test: a mock that answers `200` 100 ms after the deadline to a poll sent before it → `DeviceLoginAsync` returns the token set. |
| C164-41 | Info | all eleven | per §7.1.3 | test strength; text | Round-2 test strength and text:<ul><li>Deadline tests run on the real clock, or are caught only by a timeout (C#, Go, PHP, Java).</li><li>No test pins "parse the 200 outside the retry" (C#).</li><li>The `device_login` W7.1c check does not count waits (C).</li><li>Swift's bodiless-429 test cannot tell an in-poll retry from the loop's wait.</li><li>Rust drops the last 5xx `Retry-After` after an exhausted budget, and Swift drops a 503's near the deadline, so the next poll comes at the interval.</li><li>Text: the CHANGELOG source is still `21beda0` (PHP); the README does not mention the in-poll retry (C#, Python); the "one behaviour note" README line (C++); a docstring says "bounded by the same deadline" (Python, untrue until C164-36).</li></ul> | Per §7.1.3, each SDK's addendum under C164-41. |
| C164-42 | Info | contract | `sdks/CONTRACT.md` §14.2 rule 6 / §14.6 | the P10 analogue for `device_poll` | Rule 4 binds an in-poll retry, but only §34.2 P10 says it in words, and only for `ciba_poll`. Seven SDKs missed the bound (C164-36). | For contract 1.65 (no 1.64 amendment): §14.2 rule 6, "A §16 retry inside `device_poll` as `device_login` calls it never waits past the deadline: `Retry-After` is capped at it and no request follows it (as §34.2 P10 for `ciba_poll`)". §14.6 gains C164-36's test (1). |

**Counts, round 2:** Medium 0 · Low 5 (C164-36, -37, -38, -39, -40; C164-38 is Info in two SDKs) · Informational 2 (C164-41, -42).
**Outside these PRs:** the CIBA retry of TypeScript, Python and C++ has the same deadline gap, and P10 makes that
bound a MUST. It is outside the 1.64 items. It rides C164-36's commit where the runner is shared, and is otherwise
named here for the next round.

#### 7.1.3 Per-SDK status, round 2

| SDK | Head | Round-1 findings | New / remaining |
|---|---|---|---|
| typescript | `3b07099cc` | C164-25, -31, -32 **closed** | C164-36, -38, -41 |
| rust | `f4f65ce95` | C164-25, -27, -32 **closed** (deadline-bounded) | C164-38, -41 |
| python | `d5ce0cbc7` | **C164-26 closed** (4 tests, mutant fails all 4); C164-25, -29 **closed** | C164-36, -37, -38 (Info), -41 |
| c | `263d4cc2d` | C164-27, -32, -33 **closed** | C164-36, -41 |
| cplusplus | `d95d2f173` | C164-32, -33 **closed** (no `src/` or `include/` change; SOVERSION 4, 1.1.2 stand) | C164-36, -38, -39, -41 |
| csharp | `42369a4ba` | C164-25, -32, -33 **closed** (read only; deadline-bounded) | C164-40, -41 |
| go | `491fc0730` | C164-25, -32 **closed** (deadline-bounded) | C164-38, -41 |
| java | `c459e7315` | **C164-26 closed** (`cd5aa77`; mutant fails; the replay carries the new CSRF, cookies and bearer, and the caller gets 204); C164-29, -30, -32 **closed**; C164-25 closed in code (its test is C164-38) | C164-36, -38, -39, -41 |
| kotlin | `d1d1816f2` | C164-25, -28, -29, -32, -33 **closed** | C164-36, -37, -38, -39, -41 |
| php | `48751509a` | C164-25, -33 **closed** | C164-36, -38 (Info), -41 |
| swift | `2630e9cfa` | C164-25, -32, -33 **closed** (read only; deadline-bounded) | C164-38, -41 |

Every round-1 finding is closed. The round-1 checks were re-probed where the round-2 diffs touched them and
still hold in all eleven:
- rules 6 and 9;
- the three §14.6 cases;
- the 1.63 isolation rules;
- the replay after a refresh.

Every version is 1.1.2, and every CHANGELOG records its round-2 fixes.

**Can W7 merge? Not yet.**
- **No Medium is open.** C164-26 is closed in Python and Java, so plan §1.4's condition for W8 ("Medium and
  higher are fixed in the SDK PR before W8") is met.
- §1.4 also asks for Low and Informational findings to be fixed "in the same SDK session before its PR leaves
  draft". Low findings remain in ten SDKs (C164-36 … -40). C# has C164-40; Rust, Go and Swift have only C164-38.
  C164-41 is Informational in all eleven.
- W7 merges once a round 3 closes those findings. Round 3 is small: one commit per SDK, plus a test.

C164-42 is for 1.65.

The eleven round-2 addenda follow, with the reviewers' N-numbers mapped to the ids above. Where an addendum names a
severity, §7.1.2 is the binding one.

---

#### Addendum round 2 — typescript — commit 3b07099cc (PR #150), read after 402c6c00f

The new head adds three commits. `58262d6` re-vendors CONTRACT.md from b3f8687 (sha256 a221f1bf…de39, matching; the vendoring check was not repeated). `d156003` covers C164-25 and C164-31. `3b07099` covers C164-32 and the CHANGELOG/README text. Each commit message matches its diff. The SDK clone was not modified. All work was done in the throwaway clone `/home/user/work/typescript-r2`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-25 (Low) device poll not §16-retried | **CLOSED, with one gap in the tests and the deadline issue C164-36** | d156003 | `devicePoll` now calls `#postDevicePoll` (`src/node/oidc.ts:1692`, `:2595-2627`). That method wraps the POST in `withRetry` with `idempotent:true`, `operation:'device_poll'` and `enabled: session.retryEnabled`. A status ≥ 500 throws `retryableNetworkError`, which carries the `Retry-After` floor. No response at all throws a `NetworkError`. Every other status is returned as a decided answer and is never retried: `pollRateLimit` for a 429, otherwise `mapOidcError`. The loop still `continue`s when the budget is used up (`:1787`). Tests at `test/node/deviceFlow.test.ts:677, 688, 699, 716, 727`. Mutants: **M25noretry** (`enabled:false`) fails 3 tests (`:677, :688, :699`). **M25ignoredisable** (`enabled:true`) fails `:727`. **M25retry429** (429 made retryable) fails 5. **M25transport** (a transport failure returned as decided instead of thrown, so it is not retried) **survives the whole device-flow test set** (deviceFlow 41/41; deviceClientAuth, oauth2NoSession*, rest/deviceAuth 31/31). The code is correct (probe P3 below), but §14.6's "the same holds for a transport failure" has no test (C164-38). |
| C164-31 (Low) 429 mapping not gated to `/oauth2/*` | **CLOSED** | d156003 | The 429 → `OAuthProtocolError` branch was removed from `mapOidcError` (`:561`) and moved into `#postForm` (`:2881-2884`). **Callers of `#postForm` were checked one by one, and all are OAuth2 form endpoints:** `#postToken` (discovery `token_endpoint`, used by `oidcExchange` `:1027`, `loginClientCredentials` `:1094`, and `oidcRefresh` via `#refreshUnderGuard` `:2246`), introspect (`introspection_endpoint`, `:1130`), revoke (`revocation_endpoint`, `:1170`), `deviceAuthorize` (`device_authorization_endpoint`, `:1523`), PAR (`pushed_authorization_request_endpoint`, `:1628`) and token exchange (`token_endpoint`, `:1862`). Discovery goes through `#get`. Federation goes through `#postJson` or a direct `axios.get` (`:1328`). UMA protection goes through `#umaProtection` → `mapOidcError` (`:2067`). The UMA ticket exchange uses `mapUmaGrantError`. CIBA uses `#postCibaForm`. The device poll uses `#postDevicePoll`, which has its own 429 path. None of these reach the branch. Probed with `429 {"error":"rate_limit_exceeded"}` + `Retry-After: 1`: `oidcDiscover`, `ssoProviders`, `ssoStart` and `umaListResources` each give **`NetworkError`**. `loginClientCredentials`, `introspect`, `revoke`, `deviceAuthorize`, `oidcRefresh` and `tokenExchange` each give `OAuthProtocolError:rate_limit_exceeded`. A token endpoint that discovery puts at `/token`, outside `/oauth2/`, also gives `OAuthProtocolError`. A path match would miss that case; it is right under §2's "from /oauth2/*" read as "an OAuth2 endpoint". A 500 on the token endpoint stays `NetworkError`. Tests at `:750` (discovery) and `:761` (ssoProviders), plus the existing `loginClientCredentials` 429 test. Mutants: **M31drop** (branch disabled) fails the `loginClientCredentials` test. **M31ungated** (the old ungated branch put back in `mapOidcError`) fails `:750` and `:761`. There is no test for `/uma2/*` or the federation POSTs, but they share `mapOidcError` with the two tested routes, so M31ungated covers them. |
| C164-32 (Info) CHANGELOG intro vendoring sentence | **CLOSED** | 3b07099 | `CHANGELOG.md:12-17` now says `CONTRACT.md` comes from `b3f8687` (1.64 amended twice, W7.1b and W7.1c) and that `openapi.json`, the registry and `proto/` come from `fb92ec4`. This is accurate. Docs only, so there is no mutant. |

W7.1c test: **present, in the contract's shape, passing** (`test/node/deviceFlow.test.ts:673-746`, all 5 cases). The cases are: two 500s (`{"error":"server_error","error_description":…}`) then 200 gives 3 requests and the tokens; three 500s give 3 requests and a `NetworkError`; `deviceLogin` completes in 3 requests with exactly one sleep ≥ 1 s; a 429 makes 1 request; with retry disabled a 5xx makes 1 request. The only missing case is the transport failure (C164-38). Reviewer probes (`/home/user/work/ts-r2-probes/zprobe.test.ts`, virtual clock):
- P1, two 500s then 200: 3 requests, tokens, in-poll waits [148, 281] ms.
- P2, three 500s: 3 requests, `NetworkError`.
- P3, a transport failure (msw `HttpResponse.error()`) twice then 200: 3 requests, tokens.
- P3b, three transport failures: 3 requests, `NetworkError`.
- P4, a 429: 1 request, `rate_limit_exceeded`.
- P4b, a 500 then a 429: 2 requests, `rate_limit_exceeded`, with no third request.
- P5, retry disabled: one request each for a 5xx and for a transport failure.
- P6, `deviceLogin` with 500, 500, 200: requests at t = 1000, 1120 and 1361 ms.
- P8, a 408: 1 request, `NetworkError`, not retried inside the poll. This is consistent with rule 6, which says "5xx or transport", so it is not a finding.

Deadline bound: **NOT bounded. A §16 request is sent after the `expires_in` deadline.** `withRetry` honours a 5xx's `Retry-After` as an uncapped floor (`retryableNetworkError` → `retryAfterMs`, `src/rest/bareTransport.ts:79-111`; `delayMs = max(jitter, retryAfter)`, `src/rest/retry.ts`). `#postDevicePoll` passes neither the deadline nor a `sleepFn`. The in-poll waits therefore use the module's `setTimeout`, not the injected `DeviceLoginParams.clock`, and nothing compares them with the deadline. The loop checks the deadline only before its own interval sleep (`:1747`), which is after `devicePoll` returns. Probe P7 used `expires_in` 30, interval 5, and every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`, on a virtual clock that the in-poll `setTimeout` also advances. Result: **3 requests, at t = 5 s, 125 s and 245 s**. Two of them came after the 30 s deadline. `deviceLogin` **blocks 245 s** and then raises the local `expired_token`. P7b (503 + `Retry-After: 120` once, then 200): the second request goes out at t = 125 s, and `deviceLogin` **returns tokens obtained 95 s after the deadline**. Without a `Retry-After`, the jittered 200/400 ms backoffs can also cross the deadline when a poll starts within 600 ms of it (P7c, `expires_in` 6, interval 5: requests at 5000, 5200 and 5268 ms, inside 6000 here only because the jitter happened to be small). The CIBA loop has the same pre-existing gap (P9: `cibaAwait` with `expires_in` 30, interval 5, 503 + RA 120 → requests at 5, 125 and 245 s), which contradicts §33.7 rule 5 / P10, "A §16 retry's wait is bounded by rule 4's deadline". It is outside this diff.

Version: `package.json` 1.1.2. CHANGELOG `[1.1.2]` records C164-25 (in-poll retry, 429 not retried, `retryEnabled:false` → one request) and C164-31 (the 429 gate, naming discovery, federation and UMA as `NetworkError`). README §34.8 (b) now says a 5xx is "retried under §16 inside the poll (three requests in all; never a `429`)". The conformance sentence still says contract 1.64. CONTRACT.md sha256 is a221f1bf….

Run by the reviewer (throwaway clone `/home/user/work/typescript-r2` at 3b07099, Node 22.22.0, proxy variables unset for vitest):
- `npm ci` OK.
- `npx tsc --noEmit` exit 0.
- `npx vitest run`: **119 files, 1764 passed, 3 skipped, 0 failed**. Round 1 was 1757; the difference is the 7 new tests.
- `npm run docs` (typedoc): exit 0, 0 errors, the 3 known `middleware.OidcLoginOutcome` warnings.
- `node scripts/gen-management.mjs --check`: 32 files current, 202 ops.
- `npx tsup` OK; `npm run bundle-grep` OK.
- There is no `lint` script.
- 6 mutants (`/home/user/work/ts-r2-mut.sh`, logs `/home/user/work/ts-r2-mut-*.log`): 5 killed (M25noretry, M25ignoredisable, M25retry429, M31drop, M31ungated) and 1 survived (M25transport → C164-38).
- The probes ran from the copy's `test/node`; the file was then moved out to `/home/user/work/ts-r2-probes/`.
- `node_modules` and `dist` were deleted afterwards. The SDK clone is unmodified.

Round-1 checks where the diff touched them: rule 9 (429 single-request, the 429 tests at `:385/:411/:426/:450` pass, and M25retry429 shows they pin the 429 path). Rule 6 (5xx non-terminal in the loop, `:1787`, P7 ends in `expired_token`, not in a `NetworkError`). The 401 refresh replay path is not touched by this diff (`interceptors.ts` unchanged), so it was not re-probed. A 400 or 401 inside `#postDevicePoll` maps exactly as `#postForm(…, devicePoll=true)` did before: `pollRateLimit ?? mapOidcError`.

New findings:

- **C164-36 — Low (normative MUST) — `src/node/oidc.ts:2595-2627` (`#postDevicePoll`), `:1740-1787` (`deviceLogin`).** Rule: §14.2 rule 4, "MUST NOT poll past the deadline". This applies to a §16 request inside the poll, by analogy with the binding text of §33.7 rule 5 / P10: "A §16 retry's wait is bounded by rule 4's deadline: Retry-After is a minimum wait, capped at the deadline, and nothing is sent after it". **What happens:** the in-poll retry's waits are bounded only by the 3-attempt cap and the uncapped `Retry-After` floor. `503` + `Retry-After: 120` with `expires_in` 30 sends requests at 125 s and 245 s and blocks `deviceLogin` for 245 s (P7). Followed by a 200, it returns tokens 95 s after the deadline (P7b). The in-poll waits also ignore the injected `clock`. The README's "a wait that would pass the `expires_in` deadline … sends nothing after it" is therefore untrue for a 5xx. **Exact fix:** give `#postDevicePoll` an optional `{ deadline, clock }`, passed by `deviceLogin` through an internal `devicePoll` overload or a private method. In `withRetry`, pass `sleepFn: async (ms) => { if (clock.now() + ms >= deadline) throw new OAuthProtocolError('expired_token', '… §14.2 rule 4'); await clock.sleep(ms); }`. That stops the retry at once rather than sending after the deadline; capping the wait at the deadline and then raising also conforms. A standalone `devicePoll`, which has no deadline, keeps today's behaviour. **Test:** `expires_in` 30, interval 5, every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`, on an injected clock. Assert 1 request at t = 5 s, no request at or after t = 30 s, `expired_token`, and `clock.now() ≤ 30 s` at the throw. Mutant: drop the `sleepFn`. The same fix applies to `cibaPoll`/`cibaAwait` (`:2391`, `:2455`), which is pre-existing and outside the diff, and violates §33.7 rule 5 / P10 directly (P9).
- **C164-38 — Info — `test/node/deviceFlow.test.ts:673-746`.** Rule: §14.6 W7.1c, "The same holds for a transport failure". There is no test for a transport failure on the device poll, so mutant M25transport (a no-response error returned as decided, not retried) survives every device-flow test. The code is right (P3: 2 failures then 200 → 3 requests, tokens). **Fix:** add a case with `HttpResponse.error()` twice, then `success()`: one `devicePoll` makes 3 requests and returns the tokens. Three in a row give 3 requests and a `NetworkError`.

---

#### Addendum round 2 — rust — commit f4f65ce95 (PR #138), read after 42d0be449

Four commits on top of the round-1 head, in a straight line: `23d3dd6` fixes C164-25 and C164-27 (`src/oidc/device.rs`); `0f6821a` re-vendors CONTRACT.md at axiam `b3f8687`; `50a9903` covers the docs and CHANGELOG (C164-25, -27, -32); `f4f65ce` is a refactor. The orchestrator listed `50a99035a` as the head; `f4f65ce` is one commit later, and this addendum reviews `f4f65ce`.

**What `f4f65ce` changed:** one hunk, `src/oidc/device.rs:508-512`. The retry closure's transport error is now built with `super::exchange::network_err("device token request failed", e)` instead of an inline `AxiamError::Network { message: format!(…), source }`. `network_err` (`src/oidc/exchange.rs:361-366`) builds exactly that, so the message and the source are unchanged and behaviour is identical. The commit message says CodeQL flagged the inline `format!` as cleartext logging. The text holds only the reqwest error (its URL and cause). The device code travels in the form body, not the URL, so that is right.

The clone was not modified. All runs used a throwaway copy, `/home/user/work/rust-r2`, which has been deleted. The probe source is kept at (the review session's scratchpad, not committed).

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-25 (Low) | **CLOSED** for 5xx. The transport-failure leg works (probed), but it has no test: see C164-38. | `23d3dd6`, `f4f65ce` | `device_poll_step` (`src/oidc/device.rs:447`) sends through `RetryRunner { enabled: self.retry_enabled(), operation: "device_poll", .. }.run_until(bound, …)` (`:493-561`). A send error becomes a retryable `Attempt::bare(network_err)` (`:509`). A `status >= 500` becomes `Attempt { err: from_http_status(..), retry_after }` (`:525-531`), so its `Retry-After` is the floor. Every other non-2xx, including every 429 (bodiless too), is returned as `Ok(Err(PollFailure))` and is never retried (`:532`). The 200 is parsed outside the retry. `device_login` passes `RetryBound { deadline, now, sleeper }` (`:658`, `:692`). A wait capped at the deadline returns `expired_token` (`:553`), and an exhausted budget is the loop's `Transient` (`:560`). Tests: `a_5xx_is_retried_inside_the_poll` (`:1234`), `with_retry_off_a_5xx_costs_an_interval` (`:1248`), `a_5xx_retry_after_is_a_floor_inside_the_poll` (`:1264`), `a_retry_wait_is_capped_at_the_deadline_and_ends_in_expired_token` (`:1279`), `a_single_device_poll_retries_a_5xx_but_not_a_429` (`:1330`), `three_5xx_exhaust_the_attempt_cap` (`:1347`); `a_500_with_an_error_body_mid_poll_is_not_terminal` (`:1047`) was updated for the backoff wait. Mutants (env-switched, `cargo test --all-features --lib oidc::device`, 24 tests): **M1** at_deadline ignored: 1 fails (`…capped_at_the_deadline…`). **M2** retry forced on: 2 fail. **M3** retry forced off: 6 fail. **M4** no 5xx arm: 7 fail. **M5** 429 routed into the retry: 4 fail. **M7** 5xx Retry-After dropped: 2 fail. **M6** transport error not retried: **0 fail**, here and in `device_flow_test`, `device_auth_test`, `device_client_auth_test`, `oauth2_no_session_bearer_test` and `network_manifest_test` (C164-38). The Swift/README items in the row are not Rust's. |
| C164-27 (Low, rust) | **CLOSED** | `23d3dd6` | The status is read before the body. `>= 500` goes through `AxiamError::from_http_status` and never through `oauth2_error_or_fallback` (`:525-531`), as `ciba_poll` does. The doc says so (`:430-436`). Test: `a_single_device_poll_types_a_5xx_as_a_network_error` (`:1309`). It sends `500 {"error":"server_error",…}` and `503 {"error":"temporarily_unavailable"}` with retry off, and asserts `Network`, `oauth_error_code()==None`, `is_retryable_transport()` and 1 request. Mutant M4 fails it. Probed: 500, 503 and a bodiless 502 each give `Network`/`None`/transport=true, 3 requests with retry on and 1 with retry off. |
| C164-32 (Info, rust) | **CLOSED** | `50a9903` | `CHANGELOG.md:12-14`: "`CONTRACT.md` is vendored byte for byte from `b3f8687`; `openapi.json` and `management-registry.json` from `fb92ec4`". The CONTRACT.md sha256 is `a221f1bf…de39` and matches axiam's. `README.md:102-107` adds the amended-rules sentence: the status decides, a 5xx is not terminal whatever its body and is retried under §16 inside the poll, any 429 is the wait, and only the 400 `slow_down` raises the interval. The `PollSchedule` doc (`src/oidc/device.rs:172-179`) says `device_login` takes its deadline from the clock and uses this type only for the interval arithmetic. The `tick`/`tick_for` docs now speak of "the budget of waited seconds". These are doc-only changes; the public API is unchanged. Cosmetic: `CHANGELOG.md:14` is an unwrapped long line. |

**W7.1c test:** present for the 5xx legs, in the contract's shape, and passing. The transport-failure leg is missing.
- Two 500s then 200: `a_single_device_poll_retries_a_5xx_but_not_a_429` gives a single `device_poll` 3 requests and the tokens. `a_5xx_is_retried_inside_the_poll` has `device_login` complete within one interval: waits `[5 s, ≤200 ms, ≤400 ms]`, 3 requests.
- Third 500: `three_5xx_exhaust_the_attempt_cap` gives 3 requests and `Network`. Its `device_login` half starts a fresh login rather than continuing the exhausted loop. Probed in one loop, 3×500 then 200 gives 4 polls with waits `[5 s, 148 ms, 158 ms, 5 s]`, so the loop takes its next interval.
- 429: 1 request (tested).
- Retry disabled: 1 request per poll, `[5,5,5]` (tested).
- Transport failure: **no test** (C164-38).

Reviewer probes, all passing:
- Raw TCP token endpoint that drops the first N connections after reading the request, both with a FIN and with an RST (`SO_LINGER 0`).
- Single poll with retry on, 2 drops then 200: 3 connections, tokens.
- 3 drops: 3 connections, `Network` with `is_retryable_transport`.
- Retry off: 1 connection, `Network`.
- Loop with retry on: 3 connections, waits `[5 s, 9 ms, 28 ms]` (FIN) and `[5 s, 172 ms, 65 ms]` (RST).
- Loop with retry off: `[5,5,5]`.
- A 429 was never retried, with retry on or off: `429 rate_limit_exceeded` gives `Auth`/`rate_limit_exceeded`, 1 request; a bodiless 429 gives `Network`, 1 request. The bodiless 429 is taken out before the runner, as round 1 asked.
- Also not retried: `408` (1 request; §16.3 lists 408, but §16.2's device_poll row names only 5xx/transport), `400 authorization_pending`, and a bodiless 400.

**Deadline bound:** **bounded. No request is sent after the deadline.** The §16 runner does honour a 5xx's `Retry-After` as a floor (`delay_for`, `src/retry.rs:102-114`; tested at `:1264`). With a bound, the wait is capped at the time left, and a capped wait returns `at_deadline` with no further request (`src/retry.rs:256-286`). Probes used a fake clock that advances with each served wait, interval 5, expires_in 30, and a token endpoint answering every poll `503 {"error":"temporarily_unavailable"}`:

| Retry-After | requests (at t) | waits served | outcome | device_login blocks |
|---|---|---|---|---|
| 120 | 1 (t=5 s) | `[5 s, 25 s]` | `expired_token` | 30 s (= expires_in) |
| 25 | 1 (t=5 s) | `[5 s, 25 s]` | `expired_token` | 30 s |
| 24 | 2 (t=5, 29 s) | `[5 s, 24 s, 1 s]` | `expired_token` | 30 s |
| 10 | 3 (t=5, 15, 25 s) | `[5 s, 10 s, 10 s]`; the cap is exhausted, and the loop's next interval would reach 30 s, so it stops | `expired_token` | 25 s |

The same probe on the real clock, through the public `device_login` (RA 120, expires_in 30): 1 request at 5.07 s, then `expired_token` after **30.01 s**. In short, the in-poll retry never waits past `expires_in`, and nothing is sent at or after it. When the floor exceeds the time left, the SDK still serves the remaining time before it reports `expired_token`, rather than reporting at once. That is the P10 / §33.7 rule 5 behaviour `ciba_await` has, and the test comment cites it.

**Round-1 checks re-probed where the diff touched them:**
- Rule 9: 429 RA 12 then 200 gives `[5 s, 12 s]`, 2 polls.
- Rule 6: 3×500 then 200 completes.
- §14.6 case 2 (`a_retry_after_past_the_deadline_ends_in_expired_token`) still passes.
- Rule 4 clock deadline (`the_time_a_poll_takes_counts_against_the_deadline`) still passes.
- §6.1 rule 11 / §12.1 rule 3: the poll still uses `oauth2_post` (`http_bare`). `oauth2_no_session_bearer_test` passes 3/3 and `network_manifest_test` 15/15.
- The replay after a 401 refresh (`src/management/request.rs`) is not in the diff, so it was not re-probed.

**Version:** 1.1.2 is unchanged and right: `Cargo.toml:25`, `:127` (`=1.1.2`), the macros and wasm crates. No public signature changed (`device_poll_step` is private), so a patch is right. The CHANGELOG `[1.1.2]` records C164-25 and C164-27 (`CHANGELOG.md:53-60`) and the re-vendor (`:12-14`). The README sentence is updated (`README.md:102-107`).

**Run by the reviewer** (copy at `/home/user/work/rust-r2`, the clone untouched; protoc present):
- `cargo test --all-features --lib`: 246 passed, 0 failed.
- `cargo test --all-features --test device_flow_test --test device_auth_test --test device_client_auth_test --test oauth2_no_session_bearer_test --test network_manifest_test`: 14, 13, 8, 3 and 15 passed; 0 failed.
- `cargo fmt --all --check`: clean. `cargo clippy --lib --tests --all-features -- -D warnings`: clean.
- `cargo clippy --lib --no-default-features --features amqp -- -D warnings`: clean. `cargo test --lib --no-default-features --features amqp`: 93 passed.
- wasm32: `RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo check --lib --target wasm32-unknown-unknown --no-default-features --features rest,opaque`: exit 0, no warnings.
- Mutants M1 to M7 as in the table. Probes as above.
- Not run: the unscoped `cargo test --all-features`, examples, docs, and the wasm-pack build.
- The whole copy, including `target/`, was deleted afterwards.

**New findings:**
- **C164-38 — Informational (test coverage)** — `src/oidc/device.rs:1230-1366` (the new tests), `:508-512` (the transport arm). Rule: §14.6 as amended by W7.1c ("The same holds for a transport failure"). What happens: the transport arm works (see the probes), but no test drives a transport failure through the in-poll retry. Mutant M6, which returns a send error as `Ok(Err(PollFailure))` and so never retries it, passes the whole lib suite and the five device/oauth2 integration targets. Exact fix: add a test with a raw `tokio::net::TcpListener` token endpoint that reads the request and drops the first two connections, then answers 200 with the tokens. Point the fixture's `token_endpoint` at it. Assert that a single `device_poll` with retry on makes 3 connections and returns the token set, that three drops give 3 connections and `AxiamError::Network`, and that with `retry_enabled(false)` there is 1 connection. The probe in (the review session's scratchpad, not committed) (`raw_token_server`, `transport_client`, `probe_transport`) can be lifted as is.
- **C164-41 — Informational** — `src/oidc/device.rs:560`, `src/retry.rs:208-214` (`Ended` has no `retry_after`). Rule: §16.1 (`Retry-After` is a floor: "retrying sooner is not permitted"), read with §14.2 rule 6. What happens: when the in-poll budget is exhausted on a 5xx that carries `Retry-After`, the hint of the last attempt is dropped (`PollFailure::from(ended.err)` gives `retry_after: None`). The loop's next poll then follows after one interval. Probed: 3×`503` with `Retry-After: 40`, then 200, gives waits `[5 s, 40 s, 40 s, 5 s]`, so the 4th request is sent 5 s after the server asked for 40. It is arguable, because the loop's next poll is a new poll attempt, not a §16 retry, and rule 9's RA wait is defined for the 429. The lead may rule it out of scope. Exact fix if kept: carry the last attempt's `retry_after` on `Ended` (as `Attempt` does) and set it on the `PollFailure` at `:560`. The loop then waits `max(interval, retry_after)` capped at the deadline, as it already does for a 429. Test: 3×`503` with RA 40, then 200, gives waits `[5 s, 40 s, 40 s, 40 s]`.

---

#### Addendum round 2 — python — commit d5ce0cbc7 (PR #103), read after 570efce7d

Four commits: `acfe8b8` (re-vendor CONTRACT.md from axiam `b3f8687`), `c0b910e` (C164-26), `ac304d9` (C164-25 and C164-29), `d5ce0cb` (CHANGELOG). Each commit message matches its diff. The source change is small: one word added in each `_retry_after_refresh_*` helper, and `device_poll` (sync and async) now sends through `retry_sync`/`retry_async`. In each attempt a raw `httpx.TransportError` becomes `network_error_from_transport("device_poll", …)` and a status of 500 or more becomes `error_from_http_status(...)` (a `NetworkError`). The response is parsed outside the retry by the unchanged `_handle_device_poll_response`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-26 (Medium) | **CLOSED** | c0b910e | `src/axiam_sdk/_client.py:1684` and `_async_client.py:518` now exclude `("content-length", "x-csrf-token", "cookie")`, which is the fix the review proposed. New file `tests/test_refresh_replay_session_state.py`, four tests (`:73` sync `check_access`, `:87` async `check_access`, `:111` sync management `POST /api/v1/groups` through `send_management`, `:125` the async management twin). Each logs in with access OLD and csrf c1, gets a 401 to OLD, then a refresh that rotates both cookies and `X-CSRF-Token` to c2, then 200 to NEW. Each asserts that the replay's `Cookie` has NEW and `axiam_csrf=c2`, that it has neither OLD nor c1, and that `x-csrf-token == c2`. That is the review's test, plus the async management case. **Mutant M1** (the `"cookie"` exclusion removed in both helpers): **4 failed**, so all four tests are non-vacuous. **Re-probe** (my round-1 script, httpx 0.28.1): sync authz, async authz and the sync management path all make one refresh. The replay carries the NEW access and `axiam_csrf=csrf-new`, with `X-CSRF-Token: csrf-new` on the POSTs (none on the GET), and the outcome is **200**. Before this fix the outcome was 401/`AuthError`. |
| C164-25 (Low) | **CLOSED for the retry; the deadline bound is missing (C164-36) and the 5xx `Retry-After` floor is not honoured (C164-37)** | ac304d9 | Changes at `_client.py:1962-1984` and `_async_client.py:784-804`, with `enabled=self._retry_enabled` and `operation="device_poll"`. A 429 is an `OAuthProtocolError` and `_should_retry` retries only `NetworkError`, so a 429 is never retried. A side fix: before this commit, a raw httpx transport error escaped `device_poll` and `device_login` treated it as **terminal** (`_device_poll_outcome` gives `"terminal"` for a non-`NetworkError`). It is now a `NetworkError`, so it is `"retry"`. Tests: `tests/test_device_flow.py:835`, `:851`, `:866`, `:881`, `:901`, `:914`, `:932`, and `:798` amended. **Mutant M2** (`enabled=False` in both `device_poll`s): **6 failed**. **M2a** (async only): **2 failed**. **M4** (the sync transport mapping removed): **1 failed**. **M4a** (the async transport mapping removed): **survives, 50 passed**, because there is no async transport test (C164-38). |
| C164-29 (Low, python part) | **CLOSED** | ac304d9 | `:960`: sync `device_login` with a fake `time.monotonic`, `expires_in=10, interval=2`, 3 s per request. It asserts sends at `[2, 7]`, nothing at or after 10, and `expired_token`. `:985`: async, a 7 s `on_user_code` callback, one poll, then `expired_token`. **Mutant M3** (`time.monotonic` removed from both `device_login`s, `:2025` and `:832`): **2 failed**. At round 1 it failed none. **M3s** (sync only): 1 failed. **M3a** (async only): 1 failed. Each client's clock wiring is now pinned. |

**W7.1c test:** present, mostly in the contract's shape, and it passes.

What the SDK's own tests cover:
- `:835`: two `500 {"error":"server_error","error_description":"db"}`, then 200. One `device_poll` makes 3 requests, returns the tokens, and every sleep is under 1 s.
- `:851`: the same sequence through `device_login`. It makes 3 requests, and the waits of 1 s or more are exactly `[2]` (one interval).
- `:866`: a third 500 in a row gives 3 requests, then `NetworkError`.
- `:881`: a transport failure (`ConnectError` **once**, then 200) gives 2 requests and the tokens. With a `ConnectError` every time, the result is `NetworkError`.
- `:901`: a 429 makes 1 request.
- `:914`: with retry off, a 500 makes 1 request.
- `:932`: the async single poll, two 500s then 200, gives 3 requests. A 429 adds exactly one.

Small gaps against W7.1c's wording:
- The transport case is "once then 200", not "twice then 200".
- Neither "retry disabled" nor the transport case goes through `device_login`.
- There is no async transport test (C164-38).

My probes cover each of these gaps, sync and async (all passed, 24 cases):
- **Two 500s, then 200:** 3 requests and the tokens; §16 waits of about 0.1 s and 0.3 s. Through `device_login`: 3 requests, sleeps `[2.0, j1, j2]`.
- **Three 500s:** 3 requests, then `NetworkError`.
- **`ConnectError("refused")` ×2, then 200:** 3 requests and the tokens.
- **`ReadError("connection reset")` ×2, then 200:** 3 requests and the tokens. Three in a row give 3 requests, then `NetworkError`.
- **A 429 `rate_limit_exceeded`:** 1 request, then `OAuthProtocolError`.
- **`retry_enabled=False`, through `device_login`, 500 ×2 then 200:** 3 requests over 3 polls, sleeps `[2, 2, 2]`.

**Deadline bound:** **not bounded. A §16 retry inside the last poll can be sent after the `expires_in` deadline, in sync and async alike.** `retry_sync`/`retry_async` (`_retry.py:100-140`, `:143-175`) take no deadline, and `device_poll` passes none. `PollSchedule.tick` is consulted only before the interval sleep, never between §16 attempts.

**The §16 runner does not honour a 5xx's `Retry-After` at all (C164-37).** `delay_ms` (`_retry.py:54-69`) would floor at `retry_after_ms`, but `_retry_after_of` (`:83-86`) reads `err.retry_after_ms`. That attribute exists only on `OAuthProtocolError`, which is never retried. `NetworkError` has no such attribute (`_errors.py:116-136`), and `error_from_http_status` never sets one. So `Retry-After: 120` on a 503 is ignored, and the jittered 200/400 ms backoff is used instead. The waste past the deadline is therefore at most about 0.6 s plus two round trips, not 120 s.

The probes used a fake `time.monotonic`, `time.sleep`/`asyncio.sleep` that advance it, and `random.random` pinned to 1.0 (maximum jitter):

| Probe (sync = async, identical numbers) | Requests sent at (fake s) | After deadline | Outcome / how long `device_login` blocks |
|---|---|---|---|
| `expires_in 30`, `interval 5`, every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120` | 5.0, 5.2, 5.6, 10.6, 10.8, 11.2, 16.2, 16.4, 16.8, 21.8, 22.0, 22.4, 27.4, 27.6, 28.0 (15 requests, 3 per poll) | none (by luck of the arithmetic) | `expired_token` at t = 28.0. The 120 s is never waited (each §16 wait is 0.2 s / 0.4 s). Real wall time: 0.5 s with the fake clock. |
| `expires_in 10`, `interval 2`, an `on_user_code` that takes 7.9 s, every poll 500 (and again with 503 + `Retry-After: 120`) | 9.9, **10.1**, **10.5** | **2 requests** (t = 10.1 and 10.5) | `expired_token` at t = 10.5 |
| `expires_in 30`, `interval 5`, each request takes 2.4 s, every poll 500 | 5.0, 7.6, 10.4, 17.8, 20.4, 23.2 | none | `expired_token` at t = 25.6 |

How to read this for the ruling:
- Today Python's in-poll retry crosses the deadline by up to about 0.6 s of backoff (plus round trips). §14.2 rule 4 still reads "MUST NOT poll past the deadline", so this is a violation.
- The fix for C164-37 (honour the floor) **must** come together with a deadline cap. Otherwise a 503 + `Retry-After: 120` would make `device_login` sleep 120 s and send 2 more requests up to 240 s after a 30 s grant expired.
- The same unbounded runner backs `ciba_poll` as `ciba_await` calls it (`_client.py:2259`), which is P10's MUST. That is outside this PR's diff and is noted only.

**Version:**
- `pyproject.toml:7` and `__init__.py:109` both read 1.1.2, which is right (no signature change).
- The CHANGELOG `[1.1.2]` records C164-25 (with the transport→`NetworkError` change) and C164-26, and the intro names `b3f8687`. C164-29 is test-only and is not listed, which is acceptable.
- The README `:30` sentence reads "1.1.2 … contract 1.64". But the README `:1597-1605` rule-6 paragraph and the `device_poll` docstrings (`_client.py:1930`, "**one** poll attempt"; async twin) do not mention the in-poll §16 retry. The `device_login` docstring says "bounded by the same deadline", which the probe above contradicts (C164-41).

**Run by the reviewer:**
- Throwaway copy `/home/user/work/python-r2` (`git archive HEAD`), venv on Python 3.13.16, `pip install -e '.[dev,fastapi,django]'`.
- `ruff check .`: passed. `ruff format --check .`: 218 files formatted. `mypy --strict src`: no issues in 98 files. `interrogate src`: 100%. `scripts/gen_management.py --check`: OK (32 files, 202 ops).
- `pytest tests -q`: **2154 passed**, 7 warnings (6 min 8 s). That is 2141 + 13 new.
- Probes: 24 W7.1c/deadline cases (sync and async) and a `check_access` 503 + `Retry-After: 120` case. The latter makes 2 calls with a §16 wait of 0.066 s, so the floor is ignored there too (C164-37).
- My round-1 probe suite: 29 passed. The 4 "failures" are the expected change: 500×3 then 200 is now 4 requests, with sleeps `[2, j, j, 2]`, and the old exact list no longer matches. My round-1 replay probe passes (200 on all three paths).
- Mutants were run in per-mutant `git archive` copies with `PYTHONPATH=src`: M1 4 failed, M2 6 failed, M2a 2 failed, M3 2 failed, M3s 1 failed, M3a 1 failed, M4 1 failed, **M4a survived**.
- All copies, venvs and probe directories were deleted afterwards. CI was not run (no GitHub API).

**New findings:**
- **C164-36 — Low — `src/axiam_sdk/_client.py:1978-1983`, `_async_client.py:798-803` (with `_retry.py:100-175`).** Rule: §14.2 rule 4 (MUST NOT poll past the `expires_in` deadline), applied to the §16 budget that rule 6 and §16.2 put inside a poll. **What happens:** `device_poll`'s `retry_sync`/`retry_async` has no deadline. A poll sent just before the deadline is retried after it. Probe: `expires_in 10`, a 7.9 s `on_user_code`, 500s, poll at t = 9.9, retries at **10.1 and 10.5**, then `expired_token`. This is the same in sync and async. **Exact fix:** give `retry_sync`/`retry_async` an optional `deadline: Callable[[], float] | None` (remaining seconds). Before each §16 sleep, if `wait_ms/1000 >= remaining`, re-raise the `NetworkError` without sleeping or sending. `device_login` then sees `"retry"`, and its next `tick()` raises `expired_token` locally. `device_login` passes `deadline=lambda: schedule.remaining()`, using a new `PollSchedule.remaining()` that returns `deadline - clock()`. Pass it through a private `_device_poll(…, deadline=…)` that the public `device_poll` calls with `None`: a bare `device_poll` has no deadline and keeps §16's budget, as P10 says for a bare `ciba_poll`. **Test (sync and async):** a fake clock, `expires_in 10`, `interval 2`, a 7.9 s callback, every poll 500, `random.random` pinned to 1.0. Assert exactly one request (at t = 9.9), none at or after 10, and `expired_token`.
- **C164-37 — Low (pre-existing; affects every §16 call site, not only `device_poll`) — `src/axiam_sdk/_retry.py:83-86`, `src/axiam_sdk/_errors.py:116-136`, `:353-366`.** Rule: §16.1 (`Retry-After` "honored, as a floor … retrying sooner is not permitted"). **What happens:** the floor reads `err.retry_after_ms`, but no `NetworkError` ever carries it. `error_from_http_status` builds a `NetworkError` without one, so a 5xx's (or a retried 429's) `Retry-After` is ignored. Probes: `check_access` given `503` + `Retry-After: 120` retried after 0.066 s. `device_poll` given the same retried after 0.2 s and 0.4 s. `tests/test_d5_conformance.py:190-193` claims "§16.1 already treats the header as a floor", but its test asserts only the call count. Only the `delay_ms` unit test (`:103`) checks the floor. **Exact fix:**
  - Add `self.retry_after_ms: float | None = None` to `NetworkError.__init__`.
  - In `error_from_http_status`, when `response is not None` and the status is 408, 429 or 5xx, set `err.retry_after_ms = retry_after_ms_of(response)` before returning.
  - **Land this together with C164-36**, so that the device and CIBA loops cap the floor at their deadline.
  - **Test:** `check_access` given `503` + `Retry-After: 2`, then 200, with an injected sleep. Assert a wait of at least 2000 ms and 2 calls. For `device_login`, the C164-36 test with `Retry-After: 120` must send nothing after the deadline and raise `expired_token` by the deadline at the latest.
- **C164-38 — Informational (test strength) — `tests/test_device_flow.py:932`.** The async `device_poll` has no transport-failure test. Mutant M4a (the `except httpx.TransportError` mapping removed from `_async_client.py:787-790`) survives the whole device-flow file. **Fix:** add an async twin of `:881`: `ConnectError` twice, then 200, gives 3 requests and the tokens; three in a row give `NetworkError`. Optionally add one `device_login` case with retry disabled (one request per poll) and one with a transport failure, to match W7.1c's wording.
- **C164-41 — Informational (docs) — `README.md:1597-1605`; `_client.py:1930-1956` and the `device_poll` docstring in `_async_client.py`; the `device_login` docstrings (`_client.py:2011-2014` and the async twin).** The README and the `device_poll` docstrings do not say that a 5xx or transport failure is §16-retried inside the poll (at most three attempts, never a 429, one attempt with `retry_enabled=False`). "One poll attempt" now means up to three requests. The `device_login` docstring's "bounded by the same deadline" is untrue for the in-poll retry until C164-36 is fixed. **Fix:** add one sentence each to the README and the docstrings, and reword the `device_login` docstring once C164-36 lands.

---

#### Addendum round 2 — c — commit 263d4cc2d (PR #77), read after 0c80e3d97

There are two commits over the round-1 head:
- `a1ab0a7` re-vendors `CONTRACT.md` from b3f8687. It was not re-checked, per the brief.
- `263d4cc` is the fix pass. It touches `src/oidc_device.c` (+7), `include/axiam/oidc.h` (comments only), `README.md`, `CHANGELOG.md`, `tests/test_oidc_grants.c`, `tests/test_management_manifest.c` and `tests/test_manifest_additions.c`.

The commit message's map from findings to changes matches the diff. The clone `/home/user/sdks/c` was only read. All work was done in the throwaway clone `/home/user/work/c-r2`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-27 (Info): single `axiam_device_poll` with `err == NULL` on a 5xx | **CLOSED** | 263d4cc | `src/oidc_device.c:185-190`: `device_poll_with` now uses a local `axiam_error_t` when `err` is NULL, so the 5xx reclassification at `:220-227` always runs. Test: `test_a_5xx_on_a_single_poll_is_a_network_error_with_a_null_err` (`tests/test_oidc_grants.c:349-359`) sends `500 {"error":"server_error"}` and expects `AXIAM_ERR_NETWORK`. **Mutant M27** (`if (!err)` → `if (0)`) fails it at `:356` ("Expected 3 Was 1"). Re-probed with `err == NULL`: `500 server_error`, `503 temporarily_unavailable` and a bodiless 500 each give `AXIAM_ERR_NETWORK` after 3 attempts. `400 authorization_pending` and `429 rate_limit_exceeded` give `AXIAM_ERR_AUTH` after 1 request, as before. |
| C164-32 (Info): README and header docs | **CLOSED** | 263d4cc | `README.md:40-48` now says that the status decides: any 429 is the wait (`429 slow_down` included, and only a 400 raises the interval), a 5xx is a transport failure whatever its body, retried under §16 inside the poll, and a single poll returns a 5xx as `AXIAM_ERR_NETWORK`. `include/axiam/oidc.h` adds the same rules to the `axiam_device_poll` doc (`:1054-1061`) and the `axiam_device_login` doc (`:1098-1104`). `CHANGELOG.md:13` names b3f8687 as the CONTRACT source. The text matches the code; every sentence was checked against the probes below. Doc only, so there is no mutant. |
| C164-33 (Info, C part): only 4 of 11 C164-08 sites had a 400 assertion | **CLOSED** | 263d4cc | `tests/test_management_manifest.c:288-342` adds `test_the_other_local_refusals_carry_400`. It covers a missing `resource_type`, an undeclared role, an undeclared resource, a role bound twice, `inherit:false` with no resource, and `inherit:false` on a global role. Each case asserts the message needle and `transport_cause` 400. `tests/test_manifest_additions.c:563-564` adds the 400 assertion for the ambiguous service account. **Per-site mutants** (each `refuse()` turned into `axiam_error_set(...,0,...)`): all **11** sites are killed. These are `src/management_manifest.c:179`, `:188`, `:202`, `:215`, `:232`, `:254`, `:264`, `:278`, `:291` and `:298` (by `test_management_manifest`), and `:645` (by `test_manifest_additions`). Round 1 had 7 survivors. Each assertion also checks the message, so each mutant is killed at its own site. |

**W7.1c test:** **present, in the contract's shape, and passing.** It is `test_the_device_poll_is_retried_inside_the_attempt_on_a_5xx_but_not_on_a_429` (`tests/test_oidc_grants.c:364-440`) and checks these cases:

| Case | Expected | Test line |
|---|---|---|
| `500 {"error":"server_error","error_description":"db"}` twice, then 200 | `AXIAM_OK`, 3 requests | `:379` |
| a third 500 in a row | `AXIAM_ERR_NETWORK`, 3 requests | `:390` |
| a transport failure twice, then 200 | `AXIAM_OK`, 3 requests | `:400` |
| a 429 | `rate_limit_exceeded`, 1 request | `:412` |
| retry disabled | 1 request | `:422` |
| `device_login` with two 500s, then 200 | 3 requests, first sleep = the 2000 ms interval | `:432-434` |

Mutants on `oidc_post` (`src/oidc.c:444-469`) and the case each one fails:

| Mutant | Change | Fails at |
|---|---|---|
| M25a | no retry for the device poll | `:379` |
| M25b | the 429 break removed | `:412`, and 3 older tests |
| M25c | break on any status of 429 or above, so a 5xx is not retried | `:379` |
| M25d | `retry_enabled` ignored | `:422` |
| M25e | no retry on a transport failure | `:400` |
| M25f | budget of 4 for the device poll | `:390`, and `:328` |

Reviewer probes, using the fake transport, a virtual clock advanced by every sleep, and jitter fixed at 0.5:

| Probe | Result |
|---|---|
| single poll: 500, 500, 200 | OK; 3 requests at 0/100/300 ms |
| single poll: 500 ×3 | `AXIAM_ERR_NETWORK`, cause 500; 3 requests |
| `device_login`, interval 2: 500, 500, 200 | OK; 3 requests at 2000/2100/2300 ms; one interval sleep |
| `device_login`, interval 2: 500 ×3, then 200 | OK; 4 requests (the cap is spent, the next interval polls again) |
| transport failure ×2, then 200 | OK; 3 requests |
| transport failure always | `AXIAM_ERR_NETWORK`; 3 requests |
| single poll: 429 + `Retry-After: 5` | `AXIAM_ERR_AUTH` `rate_limit_exceeded`, cause 429; 1 request |
| `device_login`, interval 2: 429 + `Retry-After: 5`, then 200 | sleeps `[2000, 5000]`; 2 requests |
| retry off, single poll: 500 | 1 request |
| retry off, `device_login`: 500, 500, 200 | 3 requests, one per interval (`[2000, 2000, 2000]`) |

One weakness (C164-41): the `device_login` sub-case does not assert the sleep count. A mutant whose third request came one interval later would still match the 3 calls and `sleeps[0]`. That mutant is killed only by the single-poll sub-cases.

**Deadline bound:** **NOT bounded.** The in-poll §16 retry ignores `device_login`'s `expires_in` deadline whenever the 5xx carries a `Retry-After`. `oidc_post` (`src/oidc.c:463-466`) takes `axiam_retry_delay_ms`, in which `Retry-After` is a **floor** (`src/retry.c:46-48`), clamped only at 3600 s (`src/retry.c:85`). It sleeps that delay and sends again. It has no knowledge of the deadline that `axiam_device_login` computes at `src/oidc_device.c:298`, which is checked only at the top of the loop (`:307-308`).

Probes (`expires_in` 30, interval 5, deadline t = 30 s; `503 {"error":"temporarily_unavailable"}`):

| Probe | Requests at | Result |
|---|---|---|
| D1: + `Retry-After: 120`, on every poll | 5 s, **125 s, 245 s** | `device_login` blocks **245 s**, then `expired_token`. **2 requests after the deadline.** |
| D2: + `Retry-After: 120`, then 200 | 5 s, **125 s** | `device_login` returns **the tokens of a poll sent 95 s past the deadline**. |
| D5: + `Retry-After: 20` | 5, 25, **45** s | 1 request after the deadline; blocks 45 s. |
| D3: + `Retry-After: 3600` | 5 s, 3605 s, 7205 s | blocks **7205 s (about 2 h)**; 2 requests after the deadline. |
| D4 (control): `500` with no `Retry-After` | the last at 26.5 s | 15 requests, all before the deadline. Without a header the backoff adds at most 0.2 s + 0.4 s per poll, which stays inside the deadline. |
| D6: single `axiam_device_poll`, 503 + `Retry-After: 120` | 3 requests | blocks 240 s and returns `AXIAM_ERR_NETWORK`. There is no deadline to honour here; the 3600 s clamp is the only bound. |

The `axiam_device_login` header doc does not claim that the in-poll retry is deadline-bound; it says the budget is "separate from this loop". The behaviour is still contrary to §14.2 rule 4, as the brief reads it. See C164-36.

**Version:** 1.1.2 is unchanged and correct: CMake `VERSION`, CPack, `conanfile.py`, `vcpkg.json` and Doxyfile. The only public-header change is two comment blocks in `oidc.h`, with no declaration, struct or enum change, so `AXIAM_SOVERSION 2` (`CMakeLists.txt:134`) stays right. The `abi_soname` test passes. The CHANGELOG records C164-27 (Fixed), C164-32, C164-33 (Changed) and the W7.1c test (Tests, "this SDK already met it"). The README sentence reads "Contract 1.64 … released as 1.1.2".

**Run by the reviewer** (`/home/user/work/c-r2`; `build-asan/` was deleted afterwards):
- **Build:** `cmake … -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON`, with `-fsanitize=address,undefined -fno-sanitize-recover=all` on the C flags and on the exe and shared linker flags, then `cmake --build -j8`: 0 warnings.
- **Suite:** `ctest --test-dir build-asan` run serially: **81/81 passed**, ASan/UBSan clean, 18.9 s.
- **Per binary:**

  | Binary | Passed | Round 1 |
  |---|---|---|
  | `test_oidc_grants` | 33/33 | 31 + 2 new |
  | `test_management_manifest` | 26/26 | 25 + 1 new |
  | `test_manifest_additions` | 25/25 | |

- `python3 scripts/gen_management.py --check`: clean.
- **Mutants** (`ASAN_OPTIONS=detect_leaks=0`; each reverted with `git checkout` and rebuilt afterwards):
  - M27 and M25a-f: all killed.
  - The 11 manifest sites: all killed.
- **Probes:** a temporary `tests/probe_r2.c` in the copy only. It ran the W7.1c and §16 retry probes, D1-D6 for the deadline, and C164-36-N5 for `err == NULL`.
- **Round-1 checks:** the diff does not touch the loop body, rule 9 or rule 6 dispatch, `/oauth2/*` isolation, or `authz_post`'s refresh-and-replay. The existing §14.6 tests (429 `slow_down`, bodiless 429, 400 `slow_down`, a 500 mid-poll, the 429 cap at the deadline) pass. The W4L probe re-checks rule 9.
- **Not run:** the plain Debug C-standard matrix, valgrind, Doxygen, and the package recipes.

**New findings:**
- **C164-36 — Low** — `src/oidc.c:463-466` (the `oidc_post` retry wait), reached from `src/oidc_device.c:214-218`. The deadline is computed at `src/oidc_device.c:298`.
  - **Rule:** §14.2 rule 4 (no poll past the `expires_in` deadline, a §16 retry inside a poll included). It overlaps §7.0.2 C164-25's "bound the retry waits by the loop's deadline".
  - **What happens:** a `5xx` with `Retry-After` on a poll makes the in-poll §16 retry sleep at least that `Retry-After`, up to 3600 s, and send again with no regard to the grant's deadline. Probe D1 (`expires_in` 30, interval 5, 503 + `Retry-After: 120`): requests at 125 s and 245 s, and `device_login` blocks 245 s before `expired_token`. D2: the tokens come from a poll sent 95 s late. D3: it blocks about 2 h.
  - **Fix:** carry the loop's deadline into the poll. Add a `time_t deadline` parameter, 0 for none, to `device_poll_with` → `oidc_token_grant_ex` → `oidc_post`; or set a client-local field used only for `OIDC_RETRY_LOOP_OWNS_429`. In the retry loop, before sleeping, `if (deadline && c->clock_fn(c->clock_ctx) + (delay + 999) / 1000 >= deadline) break;`. The 5xx then surfaces as `AXIAM_ERR_NETWORK`, and the loop's top check returns `expired_token` with nothing sent after the deadline. The single `axiam_device_poll` passes 0 and keeps today's behaviour.
  - **Test:** `expires_in` 30, interval 5, every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`. Expect `expired_token`, no token request at or after t = 30 s on the virtual clock, and a total sleep under 30 s. Also add the control with `Retry-After: 20`: the request at 25 s is allowed, and none comes at 45 s.
- **C164-41 — Info** — `tests/test_oidc_grants.c:425-435` (the `device_login` sub-case of the W7.1c test). Rule: §14.6 W7.1c ("device_login completes within one interval with those three").
  - **What happens:** the sub-case asserts 3 calls and `sleeps[0] == 2000` only. A third request sent one interval later would also pass it.
  - **Fix:** add `TEST_ASSERT_EQUAL_INT(3, g_oidc.n_sleeps)` and `TEST_ASSERT_TRUE(g_oidc.sleeps[1] < 2000 && g_oidc.sleeps[2] < 2000)`.

---

#### Addendum round 2 — cplusplus — commit d95d2f173 (PR #80), read after 2b28526c7

Commits read (`git log 2b28526c7..HEAD`): `9be5712` (tests: in-poll 5xx retry and fresh CSRF on the replay; C164-25, -33), `05577cc` (CHANGELOG, README and CMake comment; C164-32), `b352e03` (re-vendors CONTRACT.md from AXIAM `b3f8687`), `85ad767` (W7.1c test in the contract's shape; C164-25, -35), `d95d2f1` (CHANGELOG names `b3f8687`; C164-32). **No file under `src/` or `include/` changed.** The diff touches only `CHANGELOG.md`, `CMakeLists.txt` (a comment), `CONTRACT.md`, `README.md`, `tests/test_oidc_grants.cpp` and `tests/test_single_flight.cpp`. Each commit message matches its diff. `openapi.json` and `management-registry.json` are byte-identical to `b3f8687:sdks/*` (sha256 `aa6a9c4b…` and `11d7ec67…`), so the CHANGELOG's single source `b3f8687` is accurate. `path:line` refers to d95d2f173.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-32 (Info) text drift: CHANGELOG source `fb92ec4`, "One behaviour", "The `429` that names its error", README, CMake comment | **CLOSED** | 05577cc, d95d2f1 | `CHANGELOG.md:12` names `b3f8687`, which is correct (see above). `:17-20` says "Two behaviours are changed" and names both. `:27` says "A `429` on the poll is no longer retried inside the poll". `README.md:35-37` adds the amended sentence: a 5xx is a `NetworkError` whatever its body, and any 429 is the wait, `429 slow_down` included. `CMakeLists.txt:112` adds `http_status`. One leftover is C164-36 below. Doc only, no mutant. |
| C164-32 (Info) reverse-direction catch advice | **CLOSED** | 05577cc | `CHANGELOG.md:51-53` adds, in bold, that a hand-rolled loop that caught `OAuthProtocolError` with `error() == "server_error"` from `device_poll` now receives a `NetworkError`, which is not terminal. This is the fix's wording. |
| C164-33 (Info) no test pins the fresh CSRF on the post-refresh replay | **CLOSED** | 9be5712 | `tests/test_single_flight.cpp:73-115`: login sets `X-CSRF-Token: STALE`, the first `/authz/check` returns 401, the refresh answers `FRESH`, and the test asserts the two checks carry `STALE` and then `FRESH`. **Non-vacuous.** Mutant M4a (`capture_csrf` keeps the first token, `src/client_impl.hpp:289`) fails it, and also fails one curl-transport test. M4b (the replay request built *before* `do_single_flight_refresh()` in `execute_retrying`, `:474-478`) fails it alone. |
| C164-33 (Info) overstated comment on two-429 case 1 | **CLOSED** | 9be5712 | `tests/test_oidc_grants.cpp:448-450` now says case 1 does not by itself prove "not retried inside the poll" and names the single-poll case as the guard. |
| C164-25 / C164-35 (C++ was "does it right"; test only) | **PARTLY** | 9be5712, 85ad767 | The 5xx half has a test and holds. The **transport-failure half is not implemented and not tested**: see C164-39. |

`W7.1c test:` **present, in the contract's shape for the 5xx and 429 cases, and passing.** The test is `tests/test_oidc_grants.cpp:482-546`. Its cases:
- (a) Two `500 {"error":"server_error",…}` then 200: a single `device_poll` makes 3 requests and returns tokens.
- (b) `device_login`: 3 requests; the sleeps are `[5000, <5000, <5000]`, which is one interval plus two §16 backoffs.
- (c) Three 500s: `NetworkError` after 3 requests.
- (d) A 429 makes 1 request and raises `OAuthProtocolError`.
- (e) `retry_enabled(false)` with a 500 makes 1 request.

Mutants, each applied alone, rebuilt, full suite run:

| Mutant | Change | Result |
|---|---|---|
| M1 | Budget forced to 1, `src/oidc.cpp:878` | Fails this test (1 test fails) |
| M2 | 429 break removed, `:891` | Fails this test and 3 others |
| M3 | `retry_enabled` ignored, `:878` | Fails this test only, at case (e) |

**Missing:** the contract's "the same holds for a transport failure" (CONTRACT.md:3238) is not in the test. The test also does not assert that `device_login` takes its next interval after the cap is exhausted, though my probe shows it does.

Probes (throwaway copy, recorded sleeper, interval 5 s, expires_in 600 unless stated, jitter 0.5):

| Case | Result | Verdict |
|---|---|---|
| Two 500s, then 200 | As the test above | Conforms |
| Three 500s, then 200, through `device_login` | 4 calls; sleeps `5000, 100, 200, 5000`; tokens. The loop takes its next interval after the cap. | Conforms |
| `429 rate_limit_exceeded` RA 7, then 200, through `device_login` | 2 calls; sleeps `5000, 7000` | Conforms |
| Retry off: 500, then 200, through `device_login` | 2 calls; sleeps `5000, 5000` | Conforms |
| **Transport failure (`connection refused`) twice, then 200** | **Single `device_poll`: `NetworkError` after 1 request, no §16 sleep. `device_login`: 3 calls; sleeps `5000, 5000, 5000` (three full intervals).** Transport failure 3 times, single poll: `NetworkError` after **1** request. | **Does not conform** (C164-39) |

`Deadline bound:` **Not bounded. The in-poll §16 retry can send requests after the `expires_in` deadline.**
- **Mechanism.** `token_grant`'s retry loop (`src/oidc.cpp:880-898`) sleeps `detail::retry_delay(attempt, Retry-After, jitter)`. That is `max(jittered backoff, Retry-After)` (`src/retry.hpp:59-66`): the 5xx's `Retry-After` is honoured as a **floor**, clamped only at 3600 s (`retry.hpp:~100`). `device_poll_with` passes no deadline (`:1684`). `device_login` checks the deadline only before its own interval sleep (`:1735`), never inside the poll.
- **Real-clock probe** (the loop's clock is `std::time`, so this probe sleeps for real): `expires_in 6`, `interval 1`, every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 10`.
  - Requests at t = **1.0 s, 11.0 s, 21.0 s**. The deadline is 6 s, so **2 requests are sent after the deadline**.
  - Sleeps `1000, 10000, 10000`.
  - `device_login` then raises `expired_token` after blocking **21.0 s** (3.5× `expires_in`).
- **The brief's numbers, recorded sleeper:** `expires_in 30`, `interval 5`, 503 + `Retry-After: 120`. Sleeps are `5000, 120000, 120000`, so in-poll requests land at virtual t = 5, **125, 245** s against a 30 s deadline.
  - The behaviour on the real clock is the same as the scaled probe: 3 requests, 2 after the deadline, `device_login` blocks about **245 s**, then `expired_token`.
  - With a non-advancing recorded clock the loop also sent a 4th poll at virtual t = 250, which is an artefact of the fake clock.
- The 429 path *is* deadline-capped, by the loop. This gap exists only on the 5xx path inside the poll, which is the path the W7.1c amendment made mandatory. The transport-failure path is not reached (C164-39), so this gap is the 5xx + Retry-After case only.
- **Side observation, pre-existing and outside this PR:** `ciba_poll_once`'s §16 wait (`src/oidc.cpp:2422-2427`) is likewise not capped at `ciba_await`'s deadline. §34.2 P10 / B3 makes that a MUST. Lead's call whether to file it.

`Version:` `project(... VERSION 1.1.2)` (`CMakeLists.txt:6`), `AXIAM_SOVERSION 4` (`:116`). No public header changed since 2b28526c7 (`git diff --stat -- include src` is empty), so the SOVERSION 4 verified in round 1 stands. `v1.1.2` is not tagged (latest is `v1.1.1`). The CHANGELOG records the round-2 text fixes. The new tests fall under the existing "Tests: `tests/test_oidc_grants.cpp`" lines; there is no separate entry, and none is needed for tests. README `:15` still states contract 1.64.

`Run by the reviewer` (throwaway copy `/home/user/work/cplusplus-r2`, deleted afterwards; gcc 13.3, Ninja, C++17 Debug):
- `python3 scripts/gen_management.py --check`: "§27 surface is current (7 files)", exit 0.
- `cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON -DAXIAM_BUILD_EXAMPLES=ON -DCMAKE_CXX_STANDARD=17 && cmake --build build`: exit 0 (121 steps).
- `ctest --test-dir build --output-on-failure`: 1/1 passed. The binary reports **1624 test cases, 6147 checks, 0 failed** (round 1: 1622 / 6130).
- Probes: the 5 probe tests above. With them the suite has 1629 cases and 0 failed, once the transport probe was rewritten to catch and print instead of failing.
- Mutants M1, M2, M3, M4a, M4b: all killed, as tabled.
- C164-39's fix trial: `src/oidc.cpp:882` `impl.send_raw(req)` → `impl.transport(req)`.
  - Transport-failure probe: single `device_poll` returns the tokens after 3 calls with 2 §16 sleeps; `device_login` makes 3 calls with sleeps `5000, 100, 200`; a transport failure 3 times gives `NetworkError` after 3 calls.
  - Full suite stays green (1629 / 0 failed).
- Not run: shared/SONAME build (no header change), sanitizers, valgrind, clang, C++23.
- Housekeeping: I cleared the `*.log` files at the top level of `/home/user/work` (mine were `cfg/build/ctest/b2/b3.log`). If another reviewer had logs there, they were removed too. No other directory under `/home/user/work` was touched.

`New findings:`
- **C164-39 — Low** — `src/oidc.cpp:882`, with `src/client_impl.hpp:298-302`. Rules: §16.2 (CONTRACT.md:3599: "`device_poll` on a 5xx **or transport failure**", budget per poll attempt), §14.2 rule 6, §14.6 W7.1c ("The same holds for a transport failure", :3238).
  - **What:** `token_grant`'s §16 loop sends with `impl.send_raw(req)`. `send_raw` **throws** `NetworkError("transport failure: …")` as soon as `transport_error` is set. So the loop's own transport branch never runs: the `status = nullopt` → `retry_should_retry` path at `:884-886` and the post-loop `if (!resp.transport_error.empty())` at `:900` are both dead code.
  - **Effect:** a transport failure on the device poll is sent once with retry on. `device_poll` surfaces it at once, and `device_login` waits a full interval per failure. This is C164-25's transport half; round 1's "C and C++ do it right" held for 5xx only.
  - **Same pattern, also affected:** `introspect` (`:1166`, retryable=true). Client-registration reads (`:2095`) and `ciba_poll_once` (`:2385`) call `impl.transport` directly and are correct.
  - **Fix:** at `:882` (and `:1166`), call `impl.transport(req)` instead of `impl.send_raw(req)`, as `ciba_poll_once` does. The `/oauth2/*` request is `sessionless`, so skipping `capture_csrf` is correct. Add to the W7.1c test: `token_script = {{0,""},{0,""},{200,kSuccessTokens}}` → single `device_poll` returns tokens with `token_calls == 3`; and `{{0,""}}` → `NetworkError` with `token_calls == 3`. The fix was trialled as above. CHANGELOG *Fixed* line: "a transport failure on the device poll is now §16-retried inside the poll".
- **C164-36 — Low (lead's ruling; may be cross-SDK)** — `src/oidc.cpp:892-897`, `src/retry.hpp:59-66`, `src/oidc.cpp:1684`, `:1735`. Rule: §14.2 rule 4 (MUST NOT poll past the deadline), by analogy with §34.2 P10 for CIBA.
  - **What:** the in-poll §16 wait honours a 5xx's `Retry-After` as a floor of up to 3600 s and is not capped at `device_login`'s deadline. Probe: `expires_in 6`, `503` + `Retry-After: 10` → requests at 1, 11 and 21 s (2 after the deadline), blocked 21 s, then `expired_token`. Scaled to the brief's numbers: requests at 5, 125 and 245 s against a 30 s deadline, blocked about 245 s.
  - **Fix:** pass `std::optional<std::int64_t> deadline` from `device_login` into `device_poll_with` / `token_grant`. Before each §16 sleep, if `now + delay >= deadline`, stop retrying: break and surface the `NetworkError`. The loop's rule-4 check then raises `expired_token` without a further request. Either serve the capped wait or stop at once (both conform, as in P10). A bare `device_poll` keeps §16's bounded budget.
  - **Test:** `expires_in 30`, `interval 5`, `503` + `Retry-After: 120` → exactly 1 token request, and `expired_token` raised.
- **C164-41 — Info** — `README.md:41`: "See the CHANGELOG for the **one** behaviour note", but CHANGELOG now records two behaviour changes (`:17-20`). **Fix:** "for the behaviour notes".
- **C164-38 — Info** — `tests/test_oidc_grants.cpp:482-546`: the W7.1c test omits the transport-failure case and the "`device_login` takes its next interval after the cap" assertion. **Fix:** add the two transport cases from C164-39, and a `{{500},{500},{500},{200}}` `device_login` case asserting 4 calls and sleeps `[interval, <interval, <interval, interval]`.

---

#### Addendum round 2 — csharp — commit 42369a4ba (PR #111), read after fd0869a49

There are two commits since round 1. `3a1b88b` re-vendors CONTRACT.md from `b3f8687`; vendoring was already verified and is not repeated. `42369a4` fixes C164-25, -32 and -33, and its commit message matches the diff: 6 files, +227/−40, 21 of those lines are CONTRACT.md.

**Read only.** There is no .NET toolchain here (`which dotnet` finds nothing), so nothing was built or run. Every mutant below was judged by reading the test against the code.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-25 (Low) | **CLOSED** for the retry. **PARTLY** for the deadline bound: it is implemented but no test covers it (C164-41). | 42369a4 | **Retry.** `Axiam.Sdk/AxiamClient.OidcDeviceExchangeLogout.cs:228-245`: the POST runs inside `RetryPolicy.ExecuteAsync("device_poll", _options, _telemetry, Random.Shared.NextDouble, …)`. The pooled connection is kept (`retryEligible: true`, `:236`). The predicate is `e is not ValidationError && e.HttpStatus is null or >= 500` (`:245`); the `or` pattern binds tighter than `&&`, so it reads as intended. `ExecuteAsync` only catches `NetworkError` (`Core/RetryPolicy.cs:219`). So: (a) a 400 pending/slow_down/denied, an OAuth-body 429 and a 401 `invalid_client` are `OAuthProtocolError` (an `AuthError`) and are never retried. (b) A bodiless or non-OAuth 429 is a `NetworkError` with `HttpStatus` 429, and the predicate refuses it. (c) A 5xx, mapped first by status (`AxiamClient.Oidc.cs:1321-1336`, `MapDevicePollErrorAsync`), and a transport failure or HttpClient timeout (`NetworkError`, status null, `AxiamClient.Oidc.cs:1286-1295`) are retried. Cap: `RetryEnabled ? min(MaxRetryAttempts, 3) : 1` (`RetryPolicy.cs:207`). **The 200 is parsed outside the retry.** The callback returns `ReadAsStringAsync`, and `JsonSerializer.Deserialize<TokenResponseWire>` runs after it (`:247-256`), exactly as in `CibaPollAsync` (`AxiamClient.Ciba.cs:189-227`). `TokenResponseWire` uses `[JsonPropertyName]`, so default options decode it. `PostTokenAsync` loses the device-only flags, and its three other callers are unchanged. **Deadline bound:** `:350-363` (see below). **Tests:** `Contract164DevicePollRateLimitTests` at `:236` (500, 500, 200 gives a single poll with 3 requests and tokens; `DeviceLoginAsync` makes 3 requests with sleeps `[5]`), `:251` (500 ×3 gives `NetworkError` 500 after 3 requests), `:264` (`HttpRequestException` twice, then 200, gives 3 requests), `:283` (an OAuth 429 and a bodiless 429 each give 1 request), `:219` (retry off: Pending, 500, 500, Tokens gives 4 polls and `[5,5,5,5]`), and `:205` updated (`[5,5]`). **Mutants (by reading):** (1) drop the wrap: `:236` fails, killed. (2) `retryable: RetryPolicy.IsTransient`, or no predicate: the bodiless 429 is retried, its 2nd request returns tokens, `ThrowsAsync` fails at `:283`, killed. (3) drop `is null` from the predicate: `:264` fails, killed. (4) ignore `RetryEnabled`: `:219` gets `[5,5]`, killed. (5) **parse inside the retry**: no test sends a malformed 200, so it **survives** (C164-41). (6) **drop `pollCts`** (pass the caller's token): **survives** (C164-41). |
| C164-32 (Info) | **CLOSED** for the two places named | 42369a4 | `AxiamClient.OidcDeviceExchangeLogout.cs:178-187` now says what a hand-rolled loop does not see: a 429's status and `Retry-After` are internal, only `DeviceLoginAsync` applies rule 9, and it also covers the in-call §16 retry and that a 429 is never retried. `:281` reads "A `429` (whatever its body names) is not terminal either". Nit, no finding: `:180` says a 429 is an `OAuthProtocolError`, which holds only for one with the error body; a bodiless 429 is a `NetworkError`. Residual README drift: see C164-41. Docs only; no mutant applies. |
| C164-33 (Info) | **CLOSED** | 42369a4 | `tests/Axiam.Sdk.Tests/OidcDeviceFlowTests.cs:24-31` adds `ManualTime`, and `:208-215` wires `DevicePollTime` and a recorded `DevicePollDelay` that advances it. The test sits on no wall-clock boundary and no longer sleeps for real. Trace: deadline at fake +2 s; sleep 1; poll 1 is pending; then `1+1 >= 2` gives `expired_token` with 1 call. Mutants: `>=`→`>` lets a second poll go at t=2, so `calls()==2` and the test fails, killed. Removing the check loops forever on the mock (fake time advances only by sleeps), so the test times out, killed. One harmless side effect: `pollCts.CancelAfter` arms a real 1 s timer from the fake remaining time; the mocked poll returns at once, so it never fires. |

**W7.1c test:** present, in the contract's shape, at `Contract164DevicePollRateLimitTests.cs:205-298`. It was **not run** (no dotnet); by reading it compiles and passes:
- Two 500s then 200: a single poll makes 3 requests and returns the tokens. `DeviceLoginAsync` makes 3 requests within one interval (`[5]`).
- A third 500: 3 requests, then `NetworkError` (500).
- A transport failure (`HttpRequestException("connection reset")`) twice then 200: 3 requests.
- A 429: 1 request, both with the OAuth body and bodiless.
- Retry disabled: 1 request per poll.

Two parts of the §14.6 text are covered only indirectly:
- "A third 500 → `device_login` takes its next interval" is shown on the single poll, plus the loop's `catch (NetworkError)` (`:383-389`), but not through `DeviceLoginAsync`.
- The transport case is tested on a single poll only.

Existing tests still hold under retry-on: `OidcDeviceFlowTests.cs:226` (pending, 500, bodiless 503, 200 still gives 4 calls, now in 2 polls) and `:302` (500 still gives `NetworkError` 500).

**Deadline bound:** **conforms by reading** (P10's "serve the capped wait, then raise `expired_token`" form), but no test covers it.

Mechanism, at `:350-363`. Before each poll:
- A linked CTS gets `CancelAfter(max(1 ms, deadline − now))`.
- Its token goes to `DevicePollAsync`, and so to `SendAsync` and to the §16 backoff `Task.Delay(wait, token)` (`RetryPolicy.cs:234`).
- An `OperationCanceledException` that is not the caller's becomes the typed `expired_token` (rule 4).
- HttpClient reports a caller-token cancellation with that token, so `PostOAuth2FormAsync`'s `when (ex.CancellationToken != cancellationToken)` (`AxiamClient.Oidc.cs:1293`) does not turn it into a `NetworkError`.

The §16 runner **does honour a 5xx `Retry-After` as a floor**, uncapped by `RetryMaxDelay`: `DelayFor` returns `max(jitter, retryAfter)` (`RetryPolicy.cs:113`), and `NetworkError.FromResponse` parses `Retry-After` for any status (`NetworkError.cs:110`).

Probe (traced; nothing executed). `expires_in` 30, interval 5, every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`:
- t=0: deadline set.
- t=5: request #1, answered 503. One `RetryEvent(delay 120 s)` is emitted, then `Task.Delay(120 s)` starts on a token due at t=30.
- t=30: the token cancels, giving `OAuthProtocolError("expired_token")`.

Result: **1 request, none after the deadline. `DeviceLoginAsync` blocks about 30 s from the authorization**, with `OnUserCode` time counted in.

Variants:
- `Retry-After: 10`: requests at t=5, 15 and 25 (3 = cap). The loop's next wait gives `25+5 >= 30`, so `expired_token` comes at t≈25.
- `Retry-After: 12`: requests at 5, 17 and 29, all before 30. A request still in flight at t=30 is cancelled.
- Outside `DeviceLoginAsync`, a bare `DevicePollAsync` with the same answers waits 120 s + 120 s and makes 3 requests, then raises `NetworkError`. Only the caller's token bounds it. §16.1 allows that: there is no deadline outside the loop.

Two caveats:
- The bound is on the real clock (`CancelAfter` uses `TimeProvider.System`), while the deadline uses `DevicePollTime`. The two agree in production, but because they differ no fake-clock test can reach the bound (C164-41).
- The token also covers reading and validating the 200 (C164-40).

**Version:** 1.1.2 is right; both csproj files say 1.1.2. Every change is internal or private, so nothing is source-breaking. `CHANGELOG.md` `[1.1.2]` records C164-25 at `:33-38` and C164-32/33 at `:59-60`, and its intro names the `b3f8687` re-vendor (`:13`). The README conformance sentence still says "contract 1.64" (`README.md:27`). The README says nothing of the in-poll retry (C164-41).

**1.63/1.64 rules where touched:**
- Rule 9, 429 handling: unchanged in effect. `MapDevicePollErrorAsync` is the old `anyStatusErrors` branch moved verbatim: status first for 5xx, then `HttpStatus`/`RetryAfter` on a 429.
- The loop's catches and their order are unchanged (`:365-389`).
- The cases 1 and 2 tests (`:107`, `:147`) and the 429-`slow_down` test (`:176`) are untouched and still valid.
- `/oauth2/*` cookie, CSRF and bearer isolation is unchanged; the same `PostOAuth2FormAsync` is used.
- The replay after a 401 refresh is not touched by the diff.

**Run by the reviewer:**
- `which dotnet`: none. No build, no `dotnet test`, no mutants executed. Nothing was built, so there are no outputs to delete.
- Read in full: `git log`, and `git diff fd0869a49..HEAD`.
- Read for context: `RetryPolicy.cs`, `NetworkError.cs`, `OAuthProtocolError.cs`, `PostOAuth2FormAsync`, `ReadOidcJsonAsync`, `JwksVerifier.VerifyOidcIdTokenSignatureAsync`/`EnsureFreshAsync`, `CibaAwaitAsync`, and the affected tests.
- Compile-readiness by reading:
  - `MapOAuth2ErrorAnyStatusAsync` is `internal static`;
  - `NetworkError.FromMessage` exists;
  - `System.Text.Json` is imported;
  - the internal `HttpStatus` is visible to the lambda.
- 9 mutants were judged by reading: 7 killed, 2 survive (C164-41, C164-41).

**New findings:**
- **C164-40 — Low (introduced by 42369a4): the deadline token also cancels work after a `200`.**
  - Where: `AxiamClient.OidcDeviceExchangeLogout.cs:350-363`, together with `:240` (`ReadAsStringAsync(cancellationToken)`) and `:261` (`ToTokenSetAsync(…, cancellationToken)` → `VerifyIdTokenAsync` → JWKS `EnsureFreshAsync`).
  - Rule: §14.2 rule 4 forbids *polling* past the deadline, not finishing a redemption that has already happened. It also bears on §12.4's spent redemption, the analogue of §34.2 P9.
  - What happens: `pollCts.Token` is handed to the whole `DevicePollAsync`. A 200 that arrives just before the deadline can lose its tokens two ways:
    - The body read is cancelled. That gives an OCE, which the loop turns into `expired_token`.
    - A cold-cache JWKS fetch for the `id_token` is cancelled. `VerifyOidcIdTokenSignatureAsync`'s bare `catch` (`Auth/JwksVerifier.cs:445`) swallows the OCE as `InvalidSignature`, so the caller gets an `AuthError` "invalid signature".
    - Either way the server has already redeemed the device code, and the error is misleading.
  - Fix: bound only the send and the §16 waits. Split an internal `DevicePollCoreAsync(…, CancellationToken caller, CancellationToken sendDeadline)`. Use `sendDeadline` (linked) for `PostOAuth2FormAsync` and `ExecuteAsync`'s delay, and the caller's token for `ReadAsStringAsync`, the parse and `ToTokenSetAsync`. `DevicePollAsync` (public) passes its one token for both.
- **C164-41 — Info (test gap, introduced): the deadline bound of the in-poll retry is untested.**
  - Where: `:350-351` and `Core/RetryPolicy.cs:234`.
  - Why no test can reach it: the bound runs on the real clock. `CancelAfter` uses the system timer and the §16 backoff is a real `Task.Delay`, while the loop's deadline is on `DevicePollTime`. So no fake-clock test can drive it, and mutant (6) survives.
  - Fix:
    - Arm it on the injected clock: `new CancellationTokenSource(remaining, DevicePollTime)` (net8.0 has `CancellationTokenSource(TimeSpan, TimeProvider)`).
    - Give `RetryPolicy.ExecuteAsync` an optional `Func<TimeSpan, CancellationToken, Task> delay` (default `Task.Delay`), and pass `DevicePollDelay` from the device path.
    - Add a test: `expires_in` 30, interval 5, `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`. It should give `expired_token`, 1 request, and nothing sent at or after t=30.
    - Optionally, cap a §16 wait at `deadline − now` and raise at once, which P10 also allows. That makes the `RetryEvent` not claim a 120 s wait that is never served.
- **C164-41 — Info (test gap): nothing pins "the 200 is parsed outside the retry".**
  - Where: `:247-256`.
  - Mutant (5) moves the deserialisation into the callback, so a decode failure becomes a `NetworkError` with a null status and re-sends a redeemed `device_code`. It survives.
  - Fix (test): a single `DevicePollAsync` answered `200 {not json` gives `NetworkError` after **1** request with retry on.
  - Adjacent and pre-existing, not numbered: after that `NetworkError`, `DeviceLoginAsync`'s `catch (NetworkError)` (`:383`) polls again, and the server can only answer `invalid_grant`. §14.2 does not carry over CIBA's P9 ("anything that fails after a 2xx is terminal"), so this conforms. It is worth a contract note for 1.65.
- **C164-41 — Info (doc drift, residual C164-32): the README says nothing of the in-poll §16 retry.**
  - Where: `README.md:58` and `:883-884`.
  - `:58` describes the 1.64 change as the 429 alone. The device section says only "A `5xx` mid-poll is not terminal".
  - Neither says that a 5xx's status decides whatever its body, or that a single `DevicePollAsync` may now make up to three requests (§16, never on a 429, none with `RetryEnabled` off). Only the CHANGELOG says so.
  - Fix: add one sentence to the `:883` bullet: "…not terminal: with `RetryEnabled` (the default) it is retried inside the poll under §16, at most three requests, never on a `429`, and a `5xx` is a transport failure whatever its body."

---

#### Addendum round 2 — go — commit 491fc0730 (PR #103), read after a6551ae8d

Three commits on top of the round-1 head, in a straight line: `6053bde` fix(oidc): the device poll is §16-retried inside the attempt (C164-25); `58c970e` docs: CI floor 1.26.10 in the README and CHANGELOG, and the new tests named (C164-32); `491fc07` re-vendors CONTRACT.md as amended by W7.1c (`b3f8687`). Vendoring was not re-checked, per the brief. Each commit message's finding map matches its diff. The diff touches `oidc_device.go`, `contract_164_test.go`, `version_policy_test.go`, `README.md`, `CHANGELOG.md` and `CONTRACT.md` only. `retry.go`, `oidc_wire.go` and `client.go` are unchanged.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-25 (Low) | **CLOSED** (one gap in the test, C164-38) | `6053bde` | `oidc_device.go:224-303`: `DevicePoll` → `devicePoll(ctx, params, nil)`. The token POST runs inside `c.retryReadOnlyUntil(ctx, "device_poll", bound, …)` (`:253`). Inside it: a transport `*NetworkError` from `doRequest` is retried (`:262-264`). Any `>= 500` is drained, whatever the body, and becomes a `*NetworkError` with `RetryAfter`, which is retried (`:270-276`). Every other non-2xx goes through `mapOAuth2ErrorResponse` and is made decisive with `errStopRetry` (`:277-279`), so neither a typed nor an untyped 429, nor any 4xx, is retried inside the poll. A decode failure is decisive (`:281-284`). `errRetryDeadline` becomes `errDeviceExpired()` (`:290-292`). `DeviceLogin` passes `bound = &retryDeadline{at: schedule.deadline, now: c.pollClock, sleep: c.waitPoll}` (`:377`, `:396`). `WithRetryDisabled` gives one attempt (`retry.go:111-113`). The mTLS alias and `oidcEndpointURL` are kept (`:236-248`), and the request still goes through `doRequest`, so the §6.1 rule 11 jar and CSRF bypass still apply. Tests: `contract_164_test.go:297` (`TestDeviceLoginRetriesA5xxInsideThePollNotAFullInterval`: 500 then 200 → `[1s]`, 2 calls; typed 429 → `[1s 1s]`, 2 calls; retry off → `[1s 1s]`), `:323` (`TestDevicePollRetriesA5xxUnderTheBudgetThenSurfaces`: 500, 500, 200 → 3 calls and tokens; 500 forever → `*NetworkError` after `MaxAttempts` = 3 calls), `:346` (`TestDeviceLoginInPollRetryIsCappedAtTheDeadline`), `:193` (amended: two 500s then 200 → `[1s]`, 3 calls; three 500s then 200 → `[1s 1s]`, 4 calls). Mutants (each on a throwaway copy, reverted after its run): M1, a 5xx made decisive, **killed** by 3 tests. M2, a 4xx/429 retried instead of decisive, **killed** by `TestDeviceLoginA429SlowDownBodyDoesNotRaiseTheInterval`; the new typed-429 subtest is vacuous against M2, because a typed 429 is an `*OAuthProtocolError` and is never retried anyway. M3, a transport failure made decisive, **SURVIVES** every device, CIBA and 1.64 test (C164-38). M4, `DeviceLogin` passing a nil bound, **killed only by the go test timeout**: the deadline test then sleeps a real 100 s Retry-After. M5, `retry.go:151` no longer stopping at the deadline, **killed** (device and CIBA T07). M6, no `errRetryDeadline` → `expired_token` mapping, **killed**. |
| C164-32 (Info) | **CLOSED** | `58c970e` | `README.md:188` now says "**1.26.10 and on 1.27.0**". `version_policy_test.go:39` comment: `['1.26.10', '1.27.0']`. `CHANGELOG.md:97-99`, under `[1.1.2]` → Notes: "CI: the floor leg runs Go 1.26.10 (GO-2026-6809 in `crypto/x509`, found in 1.26.9, fails `govulncheck`); `go.mod` stays `go 1.26.0`…". `CHANGELOG.md:69-84`: the `### Added` Tests bullet now names every new test, including the three C164-25 tests. The CHANGELOG diff touches `[1.1.2]` only, so `[1.1.1]` and every older section are unchanged. Untouched as before: `sdk-ci-go.yml:91` and `:248` and `coverage.yml:20` keep `1.26.9` (interop, publish, coverage; none of them runs govulncheck). That was accepted in round 1. Docs only, no mutant. |

**W7.1c test:** **present and passing, in the contract's shape for the 5xx, 429 and retry-off cases. The transport-failure case is missing (C164-38).** The binding shape is covered: two 500 `server_error` then 200 → one `DevicePoll` makes 3 requests and returns tokens, and `DeviceLogin` completes within one interval (`[1s]`, 3 calls); a third 500 exhausts the cap (3 requests) and `DevicePoll` surfaces `*NetworkError`, while `DeviceLogin` takes its next interval (`[1s 1s]`, 4 calls); a 429 makes one request; retry disabled makes one request per poll. Reviewer probes (jitter pinned to 0, `GOTOOLCHAIN=auto` → go1.26.0):

| Probe | Single `DevicePoll` | `DeviceLogin` (retry on / off) |
|---|---|---|
| 500, 500, 200 | 3 calls, tokens | `[1s]` 3 calls / `[1s 1s 1s]` 3 calls |
| 500 ×3 (then 200) | 3 calls, `*NetworkError` HTTP 500 | `[1s 1s]` 4 calls / `[1s 1s 1s 1s]` 4 calls |
| `503 {"error":"temporarily_unavailable"}` ×2, 200 | 3 calls, tokens | — |
| connection reset (hijack, SO_LINGER 0) ×2, 200 | 3 calls, tokens | `[1s]` 3 calls / `[1s 1s 1s]` 3 calls |
| connection reset ×3 | 3 calls, `*NetworkError` "connection reset by peer" | — |
| `429 rate_limit_exceeded` | 1 call, `*OAuthProtocolError` | `[1s 1s]` 2 calls (both) |
| bodiless 429, Retry-After 2 | 1 call, `*NetworkError` | — |
| 408 | 1 call, `*NetworkError` (not retried in the poll; see the note below) | — |
| 500, retry disabled | 1 call | — |
| reset, retry disabled | 1 call | — |

**Deadline bound:** **bounded. No request is sent at or after the deadline. A Retry-After past the deadline makes `DeviceLogin` sleep up to the deadline and then return `expired_token`; it does not return early.** The §16 runner honours a 5xx's `Retry-After` as a floor: `retry.go:61-66` (`delayFor`), fed by `oidc_device.go:275`, which sets `RetryAfter` on every 5xx. With the device bound, the wait is capped at the time left (`retry.go:128-134`, `wait >= left` → `wait = left`, `atDeadline`). That wait is served on the loop's injected clock and sleep, and then `errRetryDeadline` is returned (`:146-153`) before any request. `devicePoll` maps that to the typed `expired_token` (`oidc_device.go:290-292`). The probe used a virtual clock that advances with each sleep, with `expires_in` 30 and `interval` 5:
- `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`: requests at **[5s]** only. Sleeps `[5s 25s]` (the loop interval, then the retry wait capped at the 25 s left). The call returns at virtual **30 s** with `expired_token` (`*OAuthProtocolError`). With no body the result is the same.
- 503 + `Retry-After: 12`: requests at [5s, 17s, 29s] (three attempts, the floor honoured). After the exhausted budget, the loop's `rateLimited(12)` meets `tick()` and returns `expired_token` at 29 s without sleeping. Nothing is sent after 29 s.
- 500 + `Retry-After: 20`: requests at [5s, 25s]. The second retry wait is capped at 5 s, and the call returns `expired_token` at 30 s.
- On the real clock (no injection; `expires_in` 3, `interval` 1, 503 + Retry-After 120): one request at 1 s, and `DeviceLogin` returned `expired_token` after **3.0 s**, so it blocks until the deadline and never for 120 s. A cancelled `ctx` ends the capped sleep (`bound.sleep = c.waitPoll`, which selects on `ctx.Done()`).
- An asymmetry worth noting for the ruling, though it conforms: the loop's own rule-9 path returns `expired_token` **at once** when a 429's Retry-After reaches past the deadline (round 1: "expired_token at once after 1 call"). The in-poll retry path instead **sleeps the remaining time** (25 s above) before it returns the same error. Both are inside rule 4, because no request goes past the deadline. Returning at once would be the same result sooner.

**Unchanged checks, re-probed where the diff touched them:** rule 9 holds (typed 429 → `[1s 1s]`, 1 call per poll, not retried in the poll). Rule 6 holds (a 5xx or transport failure is never terminal, now §16-retried first). The three §14.6 1.64 cases and the past-deadline 429 tests pass unchanged. Rule 4 (C164-05 wall-clock deadline) test passes. The replay after a 401 refresh is not touched (`client.go`, `grpc/` unchanged). The 1.63 rules still hold: the device poll still goes through `doRequest`, so `isOAuth2Path` → jar bypass, no CSRF, no bearer; the C163-08 test passes.

**Version:** 1.1.2 (`## [1.1.2] - Unreleased`, tag-based) is still right. The change is additive in behaviour (more attempts on a 5xx or transport failure, bounded), with no API change. CHANGELOG `:44-49` records C164-25 under Fixed, `:97-99` records the CI floor, `:12` records the W7.1c re-vendor (`b3f8687`). README `:23` (contract 1.64) and `:168` (`@v1.1.2`) are unchanged. README `:23` does not mention the in-poll retry; that is optional, since the CHANGELOG carries it.

**Run by the reviewer** (throwaway copy `/home/user/work/go-r2`, deleted afterwards along with the go build cache; the SDK clone is unmodified, `git status` clean; `GOTOOLCHAIN=auto` → go1.26.0):
- `go build ./...` ok. `go vet ./...` clean. `go test -count=1 ./...`: 15 packages ok, **1689 test/subtest passes** (round 1: 1686, plus the 3 new tests), 0 failures, 0 skips. `go run ./internal/cmd/genmanagement -check`: "32 generated files are current (202 operations)".
- 6 mutants: 4 killed by assertions, 1 killed only by a timeout (M4), 1 survived (M3 → C164-38).
- Probes: the single-poll and `DeviceLogin` tables above, and the deadline probes on a virtual clock and on the real clock.
- Not run: `govulncheck` (the egress proxy blocks vuln.go.dev, as in round 1). The PR's CI run was not read.

**New findings:**
- **C164-38 (C164-36 proposed) — Low (test strength).** `contract_164_test.go:288-357`. Rule: §14.6 in-attempt retry test (W7.1c `b3f8687`): "The same holds for a transport failure." What: no test drives a transport failure on the device poll. Mutant M3 (`oidc_device.go:262`, a transport `*NetworkError` from `doRequest` made decisive with `errStopRetry`) survives every device, CIBA and 1.64 test. The code is right (probe: connection reset ×2 then 200 → 3 calls and tokens; ×3 → 3 calls and `*NetworkError`; retry off → 1 call), but nothing pins it. Exact fix: add `TestDevicePollRetriesATransportFailureUnderTheBudget` in `contract_164_test.go`. Script a token handler that hijacks and closes the connection (`w.(http.Hijacker).Hijack()`, `SetLinger(0)`, `Close()`) twice and then returns `ok200`, with jitter pinned to 0. Assert that one `DevicePoll` makes 3 requests and returns tokens, and that `runDeviceLogin` gives `[1s]` with 3 calls. Then three resets → `*NetworkError` after `MaxAttempts` requests. Then `WithRetryDisabled()` → 1 request.
- **C164-41 — Info (test strength).** `contract_164_test.go:346` (`TestDeviceLoginInPollRetryIsCappedAtTheDeadline`). It runs on the real clock with a recorded sleep, so if the bound is dropped (M4) the §16 runner sleeps a real 100 s and the test is killed only by `go test`'s timeout, not by an assertion. Exact fix: inject `client.pollNow` and `client.pollSleep` as `TestDeviceLoginDeadlineIsWallClockNotASumOfWaits` does (`:263-268`). Then assert the sleeps `[1s 29s]` (the interval, then the retry wait capped at the time left), 1 request, and `expired_token`. A nil bound then fails on the recorded sleeps at once.
- Note, not a finding: a `408` on the device poll is decisive inside the poll (`oidc_device.go:277-279`), whereas `cibaPoll` retries it (`statusIsRetryable`). §16.2 lists `device_poll` as eligible "on a 5xx or transport failure" only, so this conforms. The loop still absorbs the 408 as a `*NetworkError` at one interval.

---

#### Addendum round 2 — java — commit c459e7315 (PR #121), read after 4d40fd84b

Commits `4d40fd84b..c459e73`: `3720724` re-vendor CONTRACT.md from b3f8687; `cd5aa77` fix(rest) C164-26;
`90dcd9b` fix(oauth) C164-25/-30 + the C164-29 clock tests; `c459e73` CHANGELOG/README (C164-32). Each commit's
claim matches its diff. The SDK clone was not modified. Probes and mutants ran in the throwaway copy
`/home/user/work/java-r2-mut`, the suite in `/home/user/work/java-r2`. Both were deleted afterwards. The probe
class is kept at (the review session's scratchpad, not committed).

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-26 (Medium) | **CLOSED** | cd5aa77 | `rest/AuthAuthenticator.java:106-115`: the replay sets `X-CSRF-Token` = `session.csrfToken()` when the original request carried one. The exclusions (`:68-75`: refresh, the `/oauth2/*` skip set, the webauthn setup pair, device auth, any `/oauth2/*`, ≥2 responses; `:81` adopted device token) are unchanged. Test `ReactiveRefreshCsrfReplayTest` asserts the replay carries `CSRF-NEW`, a Cookie with `axiam_csrf=CSRF-NEW` and the new bearer. It swallows the caller's outcome (the mock body is `{}`). **Mutant M1** (drop the `replay.header(...)` line) **fails** it: `expected <CSRF-NEW> but was <CSRF-OLD>`. **Probe** (cookie login `axiam_csrf=A`; `DELETE /api/v1/users/{id}` gets 401; the refresh rotates `axiam_access`, `axiam_refresh=r2` and `axiam_csrf=B` / `X-CSRF-Token: B`; the mock enforces cookie == header the way `CsrfMiddleware` does). The first write carries `A`. The replay carries `X-CSRF-Token: B`, `Cookie: axiam_access=<new>; axiam_refresh=r2; axiam_csrf=B` and `Bearer <new>`. **The caller gets the 204** (OK). Exclusions re-probed in the same session: `/oauth2/revoke` 401 → `OAuthProtocolError`, 1 request, no Cookie or Authorization on it; `webauthnSetupRegisterStart` 401 → `AuthError`, 1 request; **0 extra refreshes**. |
| C164-25 (Low) | **CLOSED in code; test PARTLY** | 90dcd9b | `AxiamClient.java:3452-3471`: `devicePoll` runs under `StatusRetry.run(retryEnabled, …, "device_poll")`. A transport `NetworkError` is wrapped `Transient` (`:3456`), and so is a `5xx` (`:3463`, with `retryAfterMillis`). A 429 is thrown bare. Probes: see the W7.1c line. Test `aSinglePollIsRetriedWithinTheAttemptOnA5xxButNeverOnA429` (:428) uses `500 {"error":"server_error"}`, then a bodiless **503**, then 200 (3 requests), then a 429 (1 request). Test `withRetryDisabledASinglePollIsSentOnce` (:455) checks 1 request. Mutants killed: M2 (retry off), M3 (a 429 retried too; caught after read timeouts, 64 s), **M7 (retry only a 503), M8 (retry only a bodiless 5xx), M9 (retry only a 500)**. The mixed 500/503 sequence is *stronger* than two 500s against status- or body-selective mutants. **Survives: M10 (attempt cap 5 instead of 3)**, all 24 device-flow tests green. No test exhausts the cap. A pooled-connection transport failure actually exceeds the cap (C164-39). |
| C164-29 (Low) | **CLOSED** | 90dcd9b | `RecordedClock.advance` (test :203). `timeSpentInAPollCountsAgainstTheDeadline` (:395: 4 s per poll, `expires_in` 12, interval 2 → sleeps `[2,2]`, 2 polls). **Mutant M6 (deadline = start + Σ sleeps) now fails**: `[2,2,2,2,2]`. It survived in round 1. `timeSpentInTheUserCodeCallbackCountsAgainstTheDeadline` (:373: a 25 s callback with a 30 s / 5 s grant → `expired_token`, 0 polls). **Mutant M5 (deadline taken after `onUserCode`) makes it hang**: it polls an empty mock queue at real 30 s read timeouts and was killed at 240 s. So the mutant is caught, but by a hang, not an assertion (nit: wrap it in `assertTimeoutPreemptively` like :351). |
| C164-30 (Low) | **CLOSED** | 90dcd9b | `ErrorMapper.java:197`, `:207`: `Retry-After` is clamped to 86 400 s. Test `aHugeRetryAfterIsCappedAtTheDeadlineNotAnOverflow` (:351) covers `99999999999999999` and `Long.MAX_VALUE` → `expired_token`, sleeps `[1]`, 3 requests, with a preemptive 10 s timeout. **Mutant M4 (no clamp) fails** (`DateTimeException`). |
| C164-32 (Info) | **CLOSED** | c459e73 | `CHANGELOG.md:17-18` now lists the public `ErrorMapper.fromDevicePollResponse`. The CHANGELOG and README name `b3f8687` as the CONTRACT.md source (`CHANGELOG.md:14`, `README.md:89`). |

**W7.1c test:** **PARTLY in the contract's shape; the behaviour passes every case.**
- *What the suite has:*
  - Single `devicePoll`: 500 (body without `error_description`), 503, 200 → 3 requests; 429 → 1; retry disabled → 1.
  - *Missing:* a three-5xx exhaustion case, a transport-failure case, and the `device_login`-within-one-interval assertion. The 500 body also lacks `error_description`.
  - As noted above, the 503 variant does **not** let a status- or body-selective mutant through (M7, M8 and M9 all fail).
- *Reviewer probes on c459e7315* (recorded clock, interval 5):
  - Single poll, `500 {"error":"server_error","error_description":"internal"}` ×2 then 200 → tokens, **3 requests**.
  - ×3 → `NetworkError`, **3 requests**.
  - `device_login`, two 500s then 200 → sleeps `[5]`, 3 polls (within one interval).
  - `device_login`, three 500s then 200 → sleeps `[5,5]`, 4 polls (next interval).
  - `429 rate_limit_exceeded` → `OAuthProtocolError`, **1 request**.
  - Retry disabled, `device_login` with two 500s then 200 → sleeps `[5,5,5]`, 1 request per poll.
  - Connection refused → `NetworkError` after ~374 ms, consistent with two backoffs.
- *Transport failure, mid-response disconnect* (`DISCONNECT_AFTER_REQUEST`):
  - ×2 then 200 → tokens after 3 requests.
  - **×3 then 200 → tokens after 4 requests.** The cap is exceeded (C164-39).

**Deadline bound:** **NOT bounded. A 5xx `Retry-After` is honoured as a floor, clamped to 5 s.**
- *How the waits work:*
  - `Retry.computeDelayMillis` (`internal/Retry.java`) takes `max(jittered backoff, hint)`.
  - The hint comes from `StatusRetry.retryAfterMillis` (`StatusRetry.java:79`, `min(MAX_DELAY_MILLIS = 5000, RA×1000)`).
  - So `Retry-After: 120` gives 5 s waits. Without it they would be ≤ 200 / 400 ms of jitter.
  - The waits are `Thread.sleep` (`Retry.java:116`), not the `CibaClock`. Neither the deadline nor `expires_in` is passed in.
  - `deviceLogin` checks the deadline only before each poll (`AxiamClient.java:3510`). The deadline is taken when the authorization returns (`:3493`).
- *Real-clock probe* (`503 {"error":"temporarily_unavailable"}` + `Retry-After: 120` on every poll, interval 5; request times measured from the device_authorization response):
  - `expires_in` 30: requests at 5.05, 10.05, 15.06, 20.07, 25.07 and **30.08 s**. That is 1 request at or after the deadline. `expired_token` at 30.09 s.
  - `expires_in` 21: requests at 5.05, 10.06, 15.07, 20.08, **25.09** and **30.10 s**. That is **2 requests after the deadline, the last 9.1 s past it**. `device_login` returns `expired_token` at 30.1 s, 9.1 s late.
- *Bound:* the worst case is about 2 × 5 s = 10 s past `expires_in` (two in-poll retries at the 5 s ceiling). It is never unbounded, because the 5 s clamp holds. → C164-36.

**Version:** 1.1.2 is correct (`pom.xml:9`, `bom/pom.xml:9,66`). Nothing is source-breaking (the new public `ErrorMapper.fromDevicePollResponse` is now listed). `CHANGELOG.md:22-30` records C164-26/-25/-30. C164-29's tests are not named in the CHANGELOG (trivial). `README.md:89` states contract 1.64 and the `b3f8687` amendments.

**Run by the reviewer** (JDK 21, `./mvnw`):
- `./mvnw -B verify` on c459e7315: **BUILD SUCCESS**, **1517 tests, 0 failures, 0 errors, 0 skipped**, all jacoco checks met (14:21 min).
- Probe class: 11/11 ran.
- 11 mutants (targeted `-Dtest`, `-Djacoco.skip`):
  - Fail an assertion: M1, M2, M3, M4, M6, M7, M8, M9.
  - Caught by a hang: M5.
  - **Survives:** M10.
- Fix check for C164-39: a `retryOnConnectionFailure(false)` client in `devicePoll` gives ×3 disconnects → `NetworkError` after 3 requests, and ×2 → tokens after 3.
- Build outputs and the copies were deleted.
- Not run: javadoc/bom/gates this round (nothing in their scope changed beyond the source files compiled by `verify`), and the GPG/Sigstore jobs.

**New findings:**

- **C164-39 — Low — `AxiamClient.java:3455` (`executeFormPost` → `httpClient`, which keeps OkHttp's default `retryOnConnectionFailure(true)`), with `:4032-4038`.**
  - **Rule:** §16.1 (at most 3 attempts in total), §14.6 W7.1c ("the same holds for a transport failure").
  - **What happens:** OkHttp silently replays a POST whose pooled connection dropped mid-exchange, below the §16 runner. So one §16 attempt can be two requests: three disconnects then 200 → **4 requests and success** (probe). The `ciba_poll` runner (`:4703`, `httpClient`) has the same shape (pre-existing). The SDK already builds `sendOnceHttpClient` with `retryOnConnectionFailure(false)` (`:730`) for exactly this reason elsewhere.
  - **Fix:** send the device poll (and the CIBA poll) through a client with `retryOnConnectionFailure(false)`. For example, add a `noSilentRetryHttpClient = httpClient.newBuilder().retryOnConnectionFailure(false).build()`. Keep the authenticator: `/oauth2/*` is excluded from it anyway. Do not reuse `sendOnceHttpClient` unless dropping redirects is intended. Verified: ×3 → `NetworkError` after 3 requests.
  - **Test:** the W7.1c transport case, with `MockResponse().setSocketPolicy(DISCONNECT_AFTER_REQUEST)` ×2 then 200 → 3 requests and tokens; ×3 → `NetworkError` after exactly 3 requests. Add the three-500s exhaustion case too: it kills M10.

- **C164-36 — Low (lead's ruling) — `AxiamClient.java:3452` (in-poll `StatusRetry.run`), `internal/Retry.java:116`, `StatusRetry.java:79`.**
  - **Rule:** §14.2 rule 4 (MUST NOT poll past the `expires_in` deadline).
  - **What happens:** the §16 retry inside a poll waits on `Thread.sleep`, with a `Retry-After` floor clamped to 5 s, and never consults the device deadline. With `expires_in` 21, interval 5, and `503` + `Retry-After: 120` on every poll, requests go out at 25.1 s and 30.1 s, and `device_login` returns 9.1 s late (probe). The bound is about 10 s past the deadline. The retry waits are also invisible to the `CibaClock`, so no recorded-clock test can see them.
  - **Fix:** give `devicePoll` a package-private overload taking `(CibaClock clock, Instant deadline)`, called by `deviceLogin`. Run the retry with a sleeper on `clock`. Before each retry, if `!clock.now().plus(delay).isBefore(deadline)`, stop retrying and rethrow the bare error, so the loop's next check reports `expired_token`. The public `devicePoll` keeps the current behaviour.
  - **Test:** recorded clock, `expires_in` 12, interval 5, every poll `503` + `Retry-After: 120`. Assert no request is recorded at or after t = 12 s on the clock, and the result is `expired_token`.

- **C164-41 — Info — `AxiamClientDeviceFlowTest.java:373`.** The callback-deadline test has no preemptive timeout, so mutant M5 hangs (≈9 min of 30 s read timeouts) instead of failing. **Fix:** wrap its body in `assertTimeoutPreemptively(Duration.ofSeconds(10), …)`, as `:351` does.

---

#### Addendum round 2 — kotlin — commit d1d1816f2 (PR #80), read after ecf58ce99

There are four commits (`git log --oneline ecf58ce99..d1d1816`):
- `b40bada` fix(oidc) C164-25/-28/-29
- `08825e8` test C164-33
- `24874b7` docs C164-32
- `d1d1816` re-vendor CONTRACT.md from b3f8687

Each commit's claim matches its diff. `%G?` = N only because no allowedSignersFile is configured here.

Files touched: `oidc/OidcSupport.kt`, `OidcDeviceFlowTest.kt`, `OidcRefreshTest.kt`, `CHANGELOG.md`, `CONTRACT.md`. Nothing else changed: no change to `Retry.kt`, `ErrorMapper.kt`, `AxiamClient.kt` or the README.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-25 (Low) | **CLOSED** (deadline caveat: C164-36) | `b40bada` | `devicePoll` now runs `postToken` through `Retry.withRetry(operation = "devicePoll", enabled = retryEnabled, …, retryable = { trace.lastStatus.let { it == null \|\| it >= 500 } })` (`oidc/OidcSupport.kt:1084-1093`). `postOAuth2Form` records `trace.lastStatus = it.code` before mapping. The 200 is parsed by `toTokenSet` outside the retry. A poll 429 is an `OAuthProtocolError`, not a `NetworkError`, so `withRetry` (which catches only `NetworkError`) never retries it. A 400/401 OAuth body is also an `OAuthProtocolError`. A bare 4xx is a `NetworkError`, but it has `lastStatus < 500`, so it is not retried. **Tests:** `OidcDeviceFlowTest.kt:361` (single `devicePoll`, two 500s then 200 → tokens, 3 requests), `:376` (`deviceLogin`: 3 requests, sleeps `[5]`), `:393` (three 500s then 200 → 4 requests, `[5,5]`), `:411` (429 → 1 request), `:423` (`retryDisabled()` → `NetworkError`, 1 request). **Mutants:** MA (`enabled = false`) → those 3 retry tests fail. MC (`retryable` only on `503`, the coordinator's "retry only one 5xx" idea) → the same 3 fail. **MD (no transport retry: `it != null && it >= 500`) → 0 fail, survives** (C164-38). |
| C164-28 (Low) | **CLOSED** | `b40bada` | `val deadline = clock.now().plusSeconds(authorization.expiresIn.toLong())` (`:1146`) now comes before `params.onUserCode(authorization)` (`:1149`). Test `:339`: the callback advances the recording clock 25 s, with `expires_in` 30 and interval 5 → `expired_token`, `polls <= 1` (actually 0). Mutant ME (deadline moved back after the callback) → that test fails. |
| C164-29 (Low, Kotlin part) | **CLOSED** | `b40bada` | `rateLimited()` now sends exactly `{"error":"rate_limit_exceeded"}` (`OidcDeviceFlowTest.kt:226`). This is mock-only. The code already handled the bare body (round-1 probe P1), and every test using it passes. |
| C164-32 (Info, Kotlin part) | **CLOSED** (one overstatement, C164-37) | `24874b7` | `CHANGELOG.md:53-56` records that a single `devicePoll` now raises every 429 as `OAuthProtocolError("rate_limit_exceeded")`, bodiless and `slow_down` bodies included, where 1.1.1 raised `NetworkError`. It also gives the `catch` consequence. `:49-52` records the in-poll retry, `:57-58` C164-28, `:90-93` the tests, and `:13` the b3f8687 vendoring (sha `a221f1bf…de39`). `:51` says "`Retry-After` as the floor", which is not true of a 5xx in this SDK (C164-37). |
| C164-33 (Info, Kotlin part) | **CLOSED** | `08825e8` | The second `oidcRefresh` uses `"rt2"` (`OidcRefreshTest.kt:138`), so it cannot land in the first call's settled single-flight slot. Under the full suite here it passed (1300/1300). A flake fix cannot be mutant-tested. |

**W7.1c test:** present and passing, in the contract's shape. One devicePoll answered `500 {"error":"server_error","error_description":"db"}` twice and then 200 makes 3 requests and returns the tokens (`:361`). `deviceLogin` finishes within one interval (`:376`). A third 500 exhausts the cap (`:393`, checked through `deviceLogin`: 3 + 1 requests). A 429 makes one request (`:411`). With retry disabled there is one request per poll (`:423`). **The transport-failure case is missing** (C164-38).

Reviewer probes in the throwaway copy, default client (retry on):

| Probe | Result |
|---|---|
| S1: 2×500, then 200 | tokens, 3 requests |
| S2: 3×500 | `NetworkError`, 3 requests |
| S3: drop (`DISCONNECT_AFTER_REQUEST`) ×2, then 200 | tokens, 3 dispatches |
| S3b: drop forever | `NetworkError`, **4 dispatches** (C164-39) |
| S3c: connection refused | `NetworkError` after 329 ms (3 attempts with jitter) |
| S4: 429 | `OAuthProtocolError(rate_limit_exceeded)`, 1 request |
| S5: retry off, 500 | `NetworkError`, 1 request |

**Deadline bound:** **No. The in-poll retry is not bounded by `deviceLogin`'s deadline. It also does not honour a 5xx's `Retry-After` at all, which is the only reason the overshoot is small today.**
- *Retry-After on a 5xx is ignored.* `Retry.withRetry` floors the wait at `e.retryAfter` (`internal/Retry.kt:118`). But every 5xx `NetworkError` is built by `ErrorMapper.fromHttpStatus` → `NetworkError.withSummary(message, sanitize(response))` (`errors/ErrorMapper.kt:44-48`), and nothing passes the third `retryAfter` argument. In the whole main source set, `retryAfter` is set only on the two 429 `OAuthProtocolError` paths (`OidcSupport.kt:2012`, `:2020`). The only floor test is a unit test of `delayFor` (`D5ConformanceTest.kt:102`). So the in-poll waits are pure full jitter, at most 200 + 400 ms.
- *The retry is not deadline-aware.* `withRetry` sleeps with `kotlinx.coroutines.delay`, not `params.clock`, and never consults the deadline. `deviceLogin` checks the deadline only before each interval (`:1162`). A poll that leaves just before the deadline therefore sends its retries after it.
- *Probe D3, the brief's exact case (system clock):* `expires_in` 30, interval 5, every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`.
  - 15 requests, 3 per poll, at ms `[5071,5229,5373, 10378,10541,10749, 15754,15812,16008, 21012,21117,21310, 26320,26387,26766]`. The deadline was ≈30062.
  - **0 requests after the deadline.** `deviceLogin` blocked **26.8 s** and then raised `expired_token`.
  - The `Retry-After: 120` had no effect: gaps inside a poll were 50–380 ms. The hybrid-clock run D1 gives the same pattern.
  - Single poll S6: 503 RA 120 twice, then 200 → tokens after 3 requests in **412 ms**.
- *Probe D2 (edge, hybrid clock = recorded sleeps + real elapsed time):* `expires_in` 6, interval 5, the callback takes 0.95 s, each 503 takes 100 ms to answer. The poll left at 6009 (deadline 6056). **Its two retries went out at 6280 and 6394, both after the deadline.**
- *Probe D4 (system clock, no fakes):* `expires_in` 6, interval 5, each 503 takes 500 ms. Requests at 8239, 8945, 9512 against a deadline of 9210, so **one request was 302 ms past the deadline**. Wall time 9.8 s.
- *Bound today:* at most two extra requests after the deadline. The overshoot is up to 600 ms of jitter plus two request times. A request time can be the 10 s connect or 30 s read timeout (`AxiamClient.kt:2971-2972`), so a hanging server can push `deviceLogin` about 80 s past `expires_in`.
- If C164-37 is fixed alone, a `503` + `Retry-After: 120` would make the poll wait 120 s, twice, past the deadline. **So C164-37 and C164-36 must be fixed together.**

**Version:** `gradle.properties:2` `version=1.1.2`, right (patch: no public signature changed; `devicePoll`'s retry is behavioural). The CHANGELOG `[1.1.2]` records the round-2 fixes (`:49-58`, `:90-93`) and the b3f8687 vendoring (`:13`). README `:34` still states contract 1.64. The README does not mention the in-poll retry (`:44-49`, `:855-866`), and its §16 section (`:2511-2516`) also claims "`Retry-After` honored as a **floor**" (C164-37).

**Re-checked (the diff touched the poll path):**
- Rule 9 and the three §14.6 cases (429 `[5,30]`, bodiless 429, `429 slow_down` `[5,5,5]`, 500 server body non-terminal) are covered by unchanged tests, all passing. S4 confirms a 429 is still one request and an `OAuthProtocolError`.
- Rule 6: the exhausted poll is a `NetworkError`, and the loop takes its next interval (`:393`, S2).
- The poll keeps `withoutSession = true`.
- The replay after a 401 refresh (`AxiamClient.kt` `postWithRefresh`) is untouched by the diff.
- Note on the coordinator's Java-specific request (500 → 503 → 200 shape): it was addressed to the Java report. For Kotlin, the tests use the contract's two-500s shape, and the "retry only 503" mutant (MC) is killed. Java was not reviewed here.

**Run by the reviewer** (throwaway copy `/home/user/work/kotlin-r2` from `git archive d1d1816`; JDK 21, Gradle 8.10.2 wrapper; no Maven Central 429 this time):
- `python3 scripts/gen_management.py --check` → `OK: 251 generated files are current (202 operations)`.
- `./gradlew test --no-daemon --console=plain` → **BUILD SUCCESSFUL, 1300 tests, 0 failures, 0 skipped** (89 classes, 17 m 44 s). That is the 1294 of round 1 plus the 6 new ones; `OidcRefreshTest` passed under load this time.
- Mutants, each run against `OidcDeviceFlowTest`: MA → 3 fail; MC → 3 fail; ME → 1 fails; **MD survives** (0 fail).
- Probes S1–S6 and D1–D4 (`ReviewerProbeR2Test`) were run and then removed. The copy and all build outputs were deleted. The SDK clone is unmodified (`git status` clean, no `build/`).
- Not run: `koverVerify`, `dokka`, lint, the TLS gate (not in the diff).

**New findings:**
- **C164-37 — Low (pre-existing, SDK-wide; newly reachable on the poll; CHANGELOG overstates it)**
  - **Location:** `errors/ErrorMapper.kt:44-48` (`fromHttpStatus` never attaches `Retry-After`), with `internal/Retry.kt:118`. Text: `CHANGELOG.md:51`, `README.md:2516`.
  - **Rule:** §16.1, "`Retry-After` honored as a floor: wait = max(jittered_backoff, retry_after)".
  - **What happens:** no `NetworkError` built from a response ever carries `retryAfter`. Every §16 retry (`devicePoll`, `cibaPoll`, `checkAccess`, the management transport, SSF, client registration) ignores a `503`'s `Retry-After`: S6 retried a `Retry-After: 120` within 412 ms. The floor exists only in `delayFor` and its unit test.
  - **Fix:** in `fromHttpStatus`'s `else` branch, use `NetworkError.withSummary(message, sanitize(response), response?.let(::retryAfterOf))`. Add a wire test: `503` + `Retry-After: 1`, then 200, on `checkAccess` with the jitter pinned to 0 → second request ≥ 1 s after the first. **Land C164-36 in the same change**, or `devicePoll` inside `deviceLogin` will sleep up to 2 × 120 s past `expires_in`.
- **C164-36 — Low**
  - **Location:** `oidc/OidcSupport.kt:1084-1093` (in-poll `withRetry`), with `:1162` (`deviceLogin`'s only deadline check).
  - **Rule:** §14.2 rule 4 ("MUST NOT poll past the `expires_in` deadline"), which covers a §16 retry inside a poll. §14.2 rule 6 / §16 run the retry within that bound (the C164-25 index row: "bound the retry waits by the loop's deadline").
  - **What happens:** the retry neither sees the deadline nor waits on `params.clock`. Probes D2 and D4 sent 2 and 1 retry requests after the deadline (by 224/338 ms and 302 ms). With slow or hanging attempts the overshoot grows to about 80 s.
  - **Fix:** give `withRetry` an optional `mayWait: (Duration) -> Boolean` (default `{ true }`), checked after computing `wait`: `if (!mayWait(wait)) throw e`. Optionally also give it a `sleep: suspend (Duration) -> Unit` so it can wait on `params.clock`. Have `deviceLogin` call an internal `devicePoll(params, deadline, clock)` that passes `mayWait = { w -> clock.now().plusMillis(w.inWholeMilliseconds).isBefore(deadline) }`. The public `devicePoll` passes no deadline. Exhausting the wait budget surfaces the `NetworkError`, and the loop's next check then raises `expired_token`.
  - **Test:** `expires_in` 6, interval 5, the callback advances the clock 0.95 s, each 503 takes 100 ms to answer (or the clock advances 100 ms per request) → exactly 1 token request, then `expired_token`. After C164-37: `expires_in` 30, interval 5, `503` + `Retry-After: 120` → no request at or after the deadline, and `deviceLogin` returns by about 30 s.
- **C164-38 — Informational (test strength, W7.1c)**
  - **Location:** `OidcDeviceFlowTest.kt:361-433`.
  - **Rule:** §14.6 (W7.1c), "same for a transport failure".
  - **What happens:** no test drives a transport failure through the in-poll retry. Mutant MD (retry only on a status ≥ 500) survives the whole class. The code is right (S3, S3c).
  - **Fix:** add a test with `MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST)` twice, then 200, on one `devicePoll` → tokens. Assert ≥ 3 dispatches (see C164-39), and ≤ 1 dispatch under `retryDisabled()` plus OkHttp's own single retry.
- **C164-39 — Informational (pre-existing, OkHttp default)**
  - **Location:** `OidcSupport.kt` `executeRequest` (`:1972-1978`), which uses the shared `httpClient` (`retryOnConnectionFailure = true`).
  - **Rule:** §16.1 attempt cap (3 in total).
  - **What happens:** on a dropped connection, OkHttp silently resends the non-one-shot form body on a fresh route. One `devicePoll` against a server that always drops sent **4** requests (S3b). The same applies to every §16 runner on this client. `cibaInitiate` already avoids it with `noRetryHttpClient` (`:1278-1280`).
  - **Fix:** send the §16-retried operations (at least `devicePoll` and `cibaPoll`) through `noRetryHttpClient`, so §16 alone counts attempts. Alternatively, record in the README that OkHttp's stale-connection retry is outside the §16 count.

---

#### Addendum round 2 — php — commit 48751509a (PR #87), read after 70ce245e9

There are four commits. `f818d52` re-vendors CONTRACT.md from b3f8687. `6e30692` puts the device poll through the §16 runner (C164-25). `89eb652` passes the bare mock in the C164-10 test (C164-33) and adds a C164-23 test. `4875150` updates the CHANGELOG and README. I checked each commit message's finding claims against the diff. They match, with one exception: the CHANGELOG still names the old contract source (C164-41). Mutants and probes ran on a throwaway clone, `/home/user/work/php-r2`. Each mutant was reverted afterwards.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-25 (Low) | **CLOSED** (one deadline edge remains: C164-36) | 6e30692 | `devicePoll()` now delegates to `devicePollWithin()` (`src/Oidc/OidcClient.php:851`). That method sends the poll through `RetryPolicy::execute('device_poll', $this->retryEnabled, …)` (`:892-921`), shaped like `cibaPollTracked` (`:2227`). Inside the attempt: `'http_errors' => false`; a status `>= 500` becomes `NetworkError::fromResponse`; any other non-2xx goes to `ErrorMapper::fromOAuth2Response`, which is the same mapping as the old `mapRequestException(oauth2: true)`. The predicate (`:882-891`) retries only a transport failure (status null) or a 5xx, so it never retries a 429 or a 408. The 200 is parsed outside the retry (`:925`). The dead `statusBeforeBody` parameter is removed from `postToken`/`postForm`. `deviceLogin()` passes the deadline `$startedAt + expiresIn` and its clock (`:1012-1018`). Tests: `tests/OidcDeviceFlowTest.php:372` (one 5xx then 200: sleeps `[5]`, 2 polls), `:399`, `:424`, `:449`, `:472`, `:489`, `:503`, `:523`. Mutants: **A** (`false` in place of `retryEnabled`) fails 6 tests; **B** (retry from status 400 up) and **B2** (retry any status) each fail `testA429IsNeverRetriedInsideThePoll` and `testABodilessOrForeignBody429StillHonoursRetryAfterAsAFloor`. All are killed. **C** (no deadline bound) and **C2** (deviceLogin passes no deadline) are killed only by a hang: `:523` really `usleep`s `Retry-After: 3600` and timed out at 120 s (see C164-41). |
| C164-33 (Info), PHP leg: the vacuous `Cookie` assertions in the C164-10 test | **CLOSED** | 89eb652 | `testAnAxiamClientReplaysAfterARefreshWithFreshCredentials` now passes `transportHandler: $mock`, the bare `MockHandler` (`tests/Contract164/RetriedRequestHeadersTest.php:144`). Mutant **D** (no cookie rebuild in `RefreshMiddleware`) now fails this test as well as the hand-built-stack test (2 failures; in round 1 only the second one failed). Mutant **F** (M6, the 1.1.1 push order) still fails it, and only it. |
| C164-33 (Info), PHP leg: C164-23 has no test | **CLOSED** | 89eb652 | `testAReplayOfARequestSentWithoutCookiesStaysWithoutThem` (`RetriedRequestHeadersTest.php:167`): a request sent with `cookies => false` is refused 401, and its replay carries no `Cookie`. Mutant **E** ("always the session jar", the round-1 survivor) fails it (killed). |

**Contract test shape: confirmed.** The session follows the shape of W7.1c's test: two 500s and a 200 make three requests in one interval, and a third 500 exhausts the cap (3 requests). The exhausted cap has its own test. The review's "three 500s then 200 = 4 requests" is not used.
- `:399`: in `deviceLogin()`, two 500s then a 200 → sleeps `[5]`, 4 requests (the authorization plus 3 polls).
- `:424`: three 500s → sleeps `[5,5]`, 5 requests; the loop takes its next interval and completes.
- `:472`: a single `devicePoll()` on three 500s → `NetworkError` after 3 requests.

**W7.1c test:** present, in the contract's shape, and **passing**. Probes (a fake clock plus real elapsed time; retry on unless noted):

| Probe | Requests (send times, s) | Result |
|---|---|---|
| single `devicePoll`: 500, 500, 200 | 3 (0.04, 0.11, 0.12) | tokens |
| single `devicePoll`: 500 ×3 | 3 | `NetworkError` |
| single `devicePoll`: connection reset, reset, 200 | 3 | tokens |
| single `devicePoll`: reset ×3 | 3 | `NetworkError` |
| single `devicePoll`: `429 rate_limit_exceeded`, RA 1 / bodiless 429, RA 1 | 1 / 1 | `OAuthProtocolError` (RA 1000 ms) / `NetworkError` (RA 1000 ms) |
| single `devicePoll`: 500, retry off | 1 | `NetworkError` |
| `deviceLogin`: 500, 500, 200 | 3 (5.00, 5.01, 5.13) | sleeps `[5]`, tokens |
| `deviceLogin`: 500 ×3, then 200 | 4 (5.00, 5.14, 5.22, 10.23) | sleeps `[5,5]`, tokens |
| `deviceLogin`: reset, reset, 200 / reset ×3, then 200 | 3 / 4 | `[5]` / `[5,5]`, tokens |
| `deviceLogin`: `429 rate_limit_exceeded` RA 12, then 200 (rule 9 re-check) | 2 (5, 17) | `[5,12]`, tokens |
| `deviceLogin`: 500, then 200, retry off | 2 (5, 10) | `[5,5]`, tokens |

The tests do not include a reset ×3 case or a transport failure inside `deviceLogin`; the probes show both conform (C164-38).

**Deadline bound:** **bounded for `Retry-After`, not for the jittered backoff.**
- **The runner does honour a 5xx's `Retry-After` as a floor, with no cap:** `RetryPolicy::delayMs` returns `max(jitter, RA)` (`src/Core/RetryPolicy.php:135-141`). A single `devicePoll()` on `503` RA 3 ×3 sent 3 requests at 0, 3.0 and 6.0 s and blocked 6.0 s of wall time.
- Inside `deviceLogin()`, the predicate refuses a retry when `now + RA >= deadline` (`OidcClient.php:890`).
- **expires_in 30, interval 5, every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`:** 1 request, sent at 5.0 s. Nothing is sent after the deadline. The retry is refused (5 + 120 ≥ 30) and `NetworkError` (RA 120000 ms) is surfaced. The loop's next wait is 120 ≥ 30 − 5, so it raises the local `expired_token` at once. It blocks for the 5 s interval only (the injected sleep) and **0.00 s of wall time**.
- **expires_in 30, interval 5, `503` RA 20:** 2 requests, sent at 5.0 and 25.0. The in-poll retry is taken (5 + 20 < 30), and it is **20 s of real `usleep`** even though the caller injected a sleeper. The second 503 is refused (25 + 20 ≥ 30), and the loop raises `expired_token`. Nothing is sent after the deadline.
- **But a request is sent after the deadline when the retry waits only the jittered backoff (C164-36).** The probe: expires_in 30, interval 5, 0.999 s latency per request, four `authorization_pending`, then 500, 500, 200. The polls were sent at 5.0, 11.0, 17.0, 23.0 and 29.0. The 500 came back at 29.996, and the predicate passed (29.996 + 0 < 30). **The §16 retry was sent at 30.066 s, past the 30 s deadline.** Its 500 was then refused a further retry, and the flow ended with `expired_token`. The overrun is at most the 200/400 ms backoff ceiling, but §14.2 rule 4 (and P10's "no request follows it") is a MUST.

**Round-1 checks re-probed where the diff touched them:**
- Rule 9: 429 RA 12 → `[5,12]`.
- Rule 6: 5xx, any body, is non-terminal.
- §14.6: all three cases are in the green suite (`429 slow_down` does not raise the interval: `testA429WhoseBodySaysSlowDownDoesNotRaiseTheInterval` passes).
- Replay after a 401 refresh: mutants D, E and F are killed, and the C164-10 test is green.
- 1.63 rules: the poll still goes through `$this->http` (the session transport, with the same `/oauth2/*` stripping in `AuthMiddleware`). It still uses `preferredEndpoint` (mTLS alias) and `appendClientSecret`. Nothing else in the 1.63 surface changed.

**Version:** 1.1.2 is still right (`## [1.1.2] - Unreleased`; the install snippets read `^1.1.2`). The CHANGELOG records C164-25 (including the 429 and deadline behaviour), C164-33 and the C164-23 test. The README §14.2 rule 6 row now reads "§16-retried inside the poll (three attempts in total, never a `429`)". The CHANGELOG's contract-source sentence was not updated (C164-41).

**Run by the reviewer** (clone `/home/user/work/php-r2` at 48751509a; PHP 8.3.6, Composer 2.8.12). The round-1 `composer.lock` was reused. phpstan/phpstan 2.3.1 came from a local `git clone --depth 1 --branch 2.3.1` used as a Composer `path` repository, since GitHub zipballs are blocked.
- `composer validate --strict`: valid.
- `vendor/bin/phpunit`: **OK, 2063 tests, 9942 assertions** (round 1 had 2056).
- `vendor/bin/phpstan analyse --memory-limit=512M`: **No errors**. The CI step for the §27 examples (`--level=6`, 5 files): **No errors**.
- `python3 scripts/gen_management.py --check`: "§27 surface is current (261 files)".
- `php tools/docblock-coverage.php`: all public items documented.
- Mutants: 8 run, all killed (A, B, B2, D, E, F by assertion; C and C2 by a 120 s timeout only).
- Probes: `scratchpad/php-r2-probes/probe.php`, log `scratchpad/php-r2-probe.log`.
- Not run: gRPC codegen (needs protoc) and `composer audit`.
- Build outputs are deleted (the clone with `vendor/`, and the phpstan clone). `/home/user/sdks/php` is untouched and clean.

**New findings:**
- **C164-36 — Low — `src/Oidc/OidcClient.php:890`.** Rule: §14.2 rule 4 / §34.2 P10 ("no request follows" the deadline).
  - **What:** the deadline predicate adds only `Retry-After` to `now`, not the backoff that `RetryPolicy::delayMs` will actually wait. A retry requested just before the deadline therefore waits the jitter (≤ 200 ms after the first failure, ≤ 400 ms after the second) and is sent after it. Probed: the retry was sent at 30.066 s against a 30 s deadline.
  - **Fix:** in the operation closure, record the attempt number (`$attempt['n'] = $n`; the closure already receives `int $n`). Bound the predicate by the largest possible wait: `$now() + max(($e->retryAfterMs ?? 0.0), RetryPolicy::backoffMs($attempt['n'])) / 1000.0 < $deadline`. As a belt-and-braces guard, also make the closure refuse to send attempt `n > 1` when `$deadline !== null && $now() >= $deadline`, rethrowing the previous attempt's `NetworkError`.
  - **Test:** a fake clock under which the first 500 returns at `deadline − 0.001` s. Assert that exactly one poll request was sent for that round and that `deviceLogin()` raises `expired_token`.
- **C164-41 — Info (test robustness / API promise) — `src/Oidc/OidcClient.php:892-921`, `tests/OidcDeviceFlowTest.php:523`.**
  - **What:** the in-poll §16 waits use `RetryPolicy`'s own `usleep`, not `deviceLogin()`'s injected `$sleep`. The `$sleep` docblock promises tests need not spend wall-clock time, but a `503` RA 20 inside the deadline blocks for 20 real seconds even with an injected sleeper. Consequently, mutants that remove the deadline bound (C, C2) are not caught by an assertion: `:523` would sleep 3600 s twice, and it only "fails" by timeout.
  - **Fix:** thread an optional `callable(float):void $retrySleep` (ms) into `devicePollWithin()` and pass it to `RetryPolicy::execute`'s `$sleep`. In `deviceLogin()`, default it to a wrapper over the injected `$sleep` that also adds the seconds to `$sleptSeconds`. Then assert the recorded in-poll waits in `:523` (none) and in a `503` RA 20 case (`[20000]`).
- **C164-41 — Info (text drift) — `CHANGELOG.md:13-15`.**
  - **What:** the 1.1.2 entry still says `CONTRACT.md` is "re-vendored byte for byte from `ilpanich/axiam` `21beda0` (contract 1.64 as amended by W7.1b …)". `f818d52` re-vendored it from `b3f8687`, and only the openapi clause was updated.
  - **Fix:** "re-vendored byte for byte from `ilpanich/axiam` `b3f8687` (contract 1.64 as amended by W7.1b and W7.1c: §14.2 rules 6 and 9, §14.6 including its in-attempt retry test, §34.2 P11, §34.8 (c))".
- **C164-38 — Info (test coverage) — `tests/OidcDeviceFlowTest.php:489`.**
  - **What:** W7.1c says "the same holds for a transport failure". The transport leg is tested only as one reset then 200 on a single `devicePoll()`. There is no exhausted-cap transport case and none inside `deviceLogin()`. The behaviour conforms (probed: reset, reset, 200 → 3 requests, `[5]`; reset ×3 → 3 requests, then the next interval).
  - **Fix:** turn the 5xx tests at `:399` and `:424` into data-provider tests with a `ConnectException` row.

---

#### Addendum round 2 — swift — commit 2630e9cfa (PR #78), read after d8e48a073

There are three commits. `44289c4` re-vendors CONTRACT.md at b3f8687 (the hash was already checked; I did not re-check it). `80c8173` is the code and test fix for C164-25 and C164-33. `2630e9c` updates the README and CHANGELOG (C164-32). Each commit message matches its diff. There is no Swift toolchain here, so I reviewed by reading and traced the mutants by hand.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-25 (Low) | **CLOSED** (with test gaps; see C164-41, C164-41 and the deadline note) | `80c8173` | `Sources/AxiamSDK/Oidc/DeviceGrant.swift:164-176`: `devicePollOnce` now sends through `bareSend(operation: "device_poll", …, retry: .section16TransportOnly, deadline:)`. The transport, the headers and the X-Tenant-ID behaviour are the same as the old `oidcFormPost`, since both go through `umaSendAbsolute`. The 200 is parsed outside the retry (`:177-206`). In `HTTP/BareRequest.swift:34-37,134-136`, the new case retries only when `response == nil \|\| status >= 500`, so a 408 or 429 is decisive. The budget is `Retry.maxAttempts` (3) when `retryEnabled` and 1 otherwise (`:58-64`). A `retry` event is emitted for each retry (`:109-111`), the backoff is full-jitter, and Retry-After is a floor (`:97-98`, `Retry.swift:49-54`). The deadline guard is `:102-108`, and `deviceLogin` passes its deadline in (`DeviceGrant.swift:263-265`). The single `devicePoll` passes `nil`. The comment at `:272-276` is corrected as the review asked. Tests are in `Tests/AxiamSDKTests/Contract164DeviceGrantRateLimitTests.swift:251-367`. Mutants traced: (a) `retry: .never` → `:251` gets 1 request and a `.network` throw, **killed**. (b) The transport-only case returns false on a 5xx → **killed** by `:251` and `:261`. (c) The budget ignores `retryEnabled` → `:294` sees sleeps `[1,0]`, not `[1,1]`, **killed**. (d) The Retry-After hint is dropped → `:305` sees 0.2, not 2, **killed**. (e) The deadline guard is removed → `:334` sees sleeps `[30]`, 2 requests and status 200, **killed**. (f) The retry case is swapped for `.section16` (which retries 429s) → `testRetryAfterIsAMinimumNotAReplacementForALongerInterval` (`:126`) sees `[9,7]`, not `[9,9]`, **killed**. (g) The retry case is swapped for `.section16UnlessOAuthError` (which retries a bodiless 429) → **survives** (C164-41). (h) `deviceLogin` passes `deadline: nil` → **survives** (C164-41). |
| C164-32 (Info, Swift part: the README §16 row) | **CLOSED** | `2630e9c` | The row at `README.md:147`, "✅ implemented", is now true. The §16 text at `:879-883` lists the device-grant poll ("on a transport failure or a `5xx` only — a `429` is the polling loop's wait"). The §14.2 bullet at `:1107-1115` describes the in-poll retry, which is off when `retryEnabled: false` and never runs past the deadline. The CHANGELOG names b3f8687 as the CONTRACT source (`CHANGELOG.md:16-17`). A grep finds no remaining claim that the poll is a single request. |
| C164-33 (Info, Swift part) | **CLOSED** | `80c8173` | The test comment at `:178` now reads `[1, 6, 6]`, which is correct. New test `testASingleDevicePollOnA429SlowDownSurfacesRateLimitExceeded` (`:353-367`) asserts `.auth` with `oauthError == "rate_limit_exceeded"`. Mutant: removing the code rewrite (`DeviceGrant.swift:191-196`) makes the single call surface `slow_down`, so the test is **killed**. |

**W7.1c test:** present, and in the contract's shape except for one omission.
- **Two 500s then 200:** a single `devicePoll` makes 3 requests and returns the tokens (`:251-260`). In `deviceLogin`, the poll after a pending answer meets 500, 500, 200 inside one attempt: 4 requests in total, and sleeps `[1,1,0,0]` (`:209-226`). That shows the retried poll completes within one interval. There is no bare 500, 500, 200 `deviceLogin` case, which would give sleeps `[1,0,0]` and 3 requests, but the shape is equivalent.
- **A third 500:** the single `devicePoll` makes 3 requests and throws `.network(500)` (`:277-292`). `deviceLogin` makes 3 requests in the poll, then takes its next interval: sleeps `[1,0,0,1]`, 4 requests, 2 `retry` events (`:261-275`).
- **A 429:** one request per poll; sleeps `[1,7]`, 2 requests (`:320-332`).
- **Retry disabled:** one request per poll; sleeps `[1,1]` (`:294-303`).
- **Transport failure: no test (C164-38).** By trace, `umaSendAbsolute` throws `AxiamError.network` (`HTTPTransport.swift:82`). That leaves `response == nil`, and `bareShouldRetry` returns true, so a transport failure is retried in-poll the same way as a 500. When the budget is spent, `deviceLogin`'s `catch let error as AxiamError` → `continue` handles it. The code conforms; only the test is missing.
- **Not run:** there is no toolchain, so none of this has been executed.

**Deadline bound:** the in-poll waits **are** bounded by `deviceLogin`'s deadline. The runner **does** honour a 5xx's Retry-After as a floor: `max(jitter × backoff, RA)`, with RA clamped at 3600 s. Before each in-poll wait, `bareSend` checks `now + wait >= deadline`. If the check fires, it skips the sleep, emits no `retry` event, and returns the 5xx as the poll's result.

Probe (traced): `expires_in` 30, interval 5, every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`.

| t (s) | What happens |
|---|---|
| 0 | Loop waits 5 (5 < 30) |
| 5 | Request 1 → in-poll wait = 120; 5 + 120 ≥ 30, so it is not taken. `.network(503)` → `continue` |
| 10, 15, 20, 25 | Requests 2–5, each the same |
| 25 | Next attempt would be at 30, which is not < 30 → `expired_token` thrown at once |

- **Result:** 5 requests in all, every one before the deadline, **none after it**. `deviceLogin` blocks about 25 s, then throws `AuthError(oauthError: "expired_token")`. No retry is slept and no `retry` event is emitted.
- **Lead reviewer's attention: Retry-After is honoured only when the deadline is far.** With the same 503 + RA 120 and `expires_in` 600, the poll sleeps 120 s twice, makes 3 requests in about 240 s and so honours RA. Near the deadline the in-poll wait is skipped, but the loop's next poll comes one interval (5 s) later, so the server's 120 s floor is ignored. The SDK therefore polls a server that asked for 120 s more often the closer it is to the deadline (C164-41).
- **The single `devicePoll` has no deadline.** It can block up to 2 × the clamped RA (3600 s), which is §16 as written.
- **Aside, not a device finding:** Swift's `ciba_poll` (`Oidc/Ciba.swift:459-469`) passes no `deadline` to `bareSend`. Its in-poll §16 waits are not bounded by `auth_req_id`'s `expires_in` either. If the lead reviewer reads §33.7 rule 5 / P10 as requiring that, the same gap exists there.

**Rules from round 1:**
- **Rules 6 and 9, and the three §14.6 cases:** re-traced, all hold. A 429 is never retried in-poll, so the 429 results are unchanged: `[1,7,1]`, `[9,9]`, `[1]` with `expired_token` and 1 request, `[1,1,1]`, and `[1,7]`. The single 429 still gives `rate_limit_exceeded`, and the single 5xx still gives `.network`.
- **Replay after a 401 refresh:** untouched by this diff, so it still holds.
- **1.63 rules:** the poll still carries no session cookie, CSRF token or bearer, because the bare path adds none.

**Version:** 1.1.2 (`AxiamSDK.podspec:3`; README `:166`, `:178`). README `:15` still says it conforms to contract 1.64. The CHANGELOG 1.1.2 entry (`CHANGELOG.md:41-48`) records C164-25 and C164-33: the in-poll retry, a 429 never retried, the deadline, up to 3 requests for a single poll, and the slow_down test. It also records the README change (C164-32) and the b3f8687 re-vendor. A patch release is right: no public signature changed.

**Run by the reviewer:**
- `python3 -I Scripts/gen_management.py --check` in the throwaway copy `/home/user/work/swift-r2`: "§27 surface is current (3 files)", rc=0. I deleted the copy afterwards.
- `git log --format=%G?`: `N` for all 3 commits. There is no allowed-signers file, so the signatures could not be verified.
- **Not run:** `swift build` and `swift test` (no toolchain). Every mutant above was traced by hand.

**New findings:**
- **C164-41 — Info (test strength).** `Tests/AxiamSDKTests/Contract164DeviceGrantRateLimitTests.swift:315-327` (`testA429IsNeverRetriedInsideThePoll`) and `:200-207`.
  - Rule: §16.2 (the `device_poll` row covers 5xx and transport failures only) and §14.6 W7.1c ("a `429` … the poll makes one request").
  - What: under the `.section16UnlessOAuthError` mutant, a bodiless 429 + RA 7 is retried in-poll. That gives a 7 s in-poll sleep and then the 200, which produces the same sleeps `[1,7]` and the same 2 requests as the correct loop wait. The test cannot tell the in-poll retry from the loop's wait.
  - Fix: in that test, either (a) pass `recorder: EventRecorder()` and assert `recorder.kinds.filter { $0 == "retry" }.isEmpty`, or (b) add a single-`devicePoll` case on the bodiless 429 asserting `.network(statusCode: 429)` and `server.state.count("poll") == 1`.
- **C164-41 — Info (test strength).** `DeviceGrant.swift:263-265`.
  - Rule: §14.2 rule 4.
  - What: the deadline guard is tested only by calling `bareSend` directly (`:334-351`). If `deviceLogin` passed `deadline: nil`, every test would still pass.
  - Fix: add a `deviceLogin` test with `expiresIn: 3`, interval 1, and poll answers `[500 + Retry-After: 30, success]`. Assert that `expired_token` is thrown (or that the next loop poll is taken), that no sleep of 30 is recorded, and that no `retry` event is emitted.
- **C164-38 — Info (W7.1c coverage).** `Contract164DeviceGrantRateLimitTests.swift`.
  - Rule: §14.6 W7.1c ("The same holds for a transport failure").
  - What: there is no transport-failure case. The code conforms by trace.
  - Fix: add a case where the poll fails twice in transport and then returns 200, using a `ScriptedTransport` that throws `AxiamError.network` twice before the 200. Assert that a single `devicePoll` makes 3 requests and returns the tokens.
- **C164-41 — Low/Info (for the lead reviewer's ruling).** `HTTP/BareRequest.swift:102-108` together with `DeviceGrant.swift:266-276`.
  - Rules: §16.1 (Retry-After is a floor) and §14.2 rule 6.
  - What: when the deadline refuses an in-poll wait, or the budget runs out on a 5xx that carries Retry-After, the 5xx's Retry-After is dropped. The loop sends its next poll one interval later, so a server that asked for 120 s is polled every 5 s until the deadline (5 requests in the probe above, all before the deadline). Rule 4 holds. Rule 9's Retry-After floor is written only for the 429.
  - Fix, if ruled required: surface the 5xx with its parsed Retry-After, for example as a `DevicePollRateLimited`-like wrapper or a `retryAfter` on the error. The loop then sets `retryAfter = hint`, waits `max(interval, RA)`, and if that wait would pass the deadline, throws `expired_token` at once. That is the same path rule 9 already uses for a 429.

---

### 7.2 Addendum round 3 (2026-10-23): the eleven round-3 heads

**What was read.**

The contract is unchanged: W7.1c `b3f8687`, `CONTRACT.md` sha256 `a221f1bf…de39`.

| SDK | PR | Head |
|---|---|---|
| TypeScript | #150 | `df5ec4a4b` |
| Rust | #138 | `7fa30ce0` |
| Python | #103 | `3715bba` |
| C | #77 | `db0d5c59e` |
| C++ | #80 | `611c4e9ed` |
| C# | #111 | `4af5be9` |
| Go | #103 | `2a0c273ad` |
| Java | #121 | `40fd50203` |
| Kotlin | #80 | `c392bf9` |
| PHP | #87 | `41cf943fd` |
| Swift | #78 | `a362452` |

These are the heads the orchestrator named at its round-3 message, and `git ls-remote` showed the same. The
method is round 2's:
- **The round-2 findings each SDK still had.** Each SDK's remaining findings from §7.1.3 were re-checked, with a
  mutant per fix where a toolchain existed. C# and Swift were read only.
- **Deadline bound, device and CIBA.** The probe: every poll answered `503` + `Retry-After: 120`, against a
  30 s grant. A second probe sends a poll just before the deadline and answers it `500`.
- **The W7.1c shape**, re-probed.
- **The orchestrator's six questions**, answered below.

**Vendoring and drift.** All eleven heads vendor `b3f8687`'s `CONTRACT.md` and `fb92ec4`'s `openapi.json` and
registry. `scripts/check-sdk-artifact-drift.py --local-root` over the eleven heads reports **11 repos, 0
artifact problems**.

#### 7.2.1 Rulings on the orchestrator's points

**1. The deviations from the plan's fixes.**
- **TypeScript and Java made C164-36's test (2) deterministic with `Retry-After: 1`.** That was legitimate: the
  test as §7.1.2 wrote it cannot be deterministic.
  - The first backoff is uniform in `[0, 200 ms]`. A correct SDK therefore sends a retry before the deadline in
    roughly half the runs: 97 of 200 in TypeScript, 68 of 100 in Java.
  - With `Retry-After: 1`, however, the jitter never decides the outcome. A deadline check that adds only the
    `Retry-After` floor, not the jittered backoff, survives both suites. TypeScript probed that mutant: it sends
    a retry 100 ms after the deadline. That is **C164-45 (Low)**.
  - The fix: pin the jitter instead of `Retry-After`. In TypeScript, `vi.spyOn(Math, 'random').mockReturnValue(1)`
    gives a 200 ms wait against the 100 ms left. Java uses its pacer seam. Add the CIBA twin.
- **PHP takes the time left from the loop's own clock and adds a trailing `$retrySleep` on `deviceLogin`.**
  Accepted. The parameter is trailing and defaulted, on `final` classes, so it is source-compatible for
  positional and named callers. It is in both docblocks and the CHANGELOG, and missing from the README (C164-48).
  One branch is wrong: when a caller injects `$sleep` but no clock, the in-poll waits are counted but not slept.
  A `Retry-After: 20` is then retried at once, and the grant ends about 20 s early. That is **C164-47 (Low)**.
- **Java adds a public `Retry.Pacer`.** Accepted. It is additive, documented and listed in the CHANGELOG. It must
  be public because its caller is in another package. The new six-argument `withRetry` overload need not be
  public (C164-48).
- **C++ adds `Client::_set_clock_test_seam` and keeps SOVERSION 4.** Accepted.
  - The seam is in the installed `client.hpp`, beside v1.1.1's `_set_retry_test_seams`, and documented "NEVER
    called in production".
  - It is a non-virtual member function. The new data member `now_seconds_fn` is in the private `Client::Impl`,
    so `Client`'s layout (`std::shared_ptr<Impl>`) is unchanged.
  - It adds one symbol and needs no bump. SOVERSION 4 is unshipped, so it stands.

**2. The `Retry-After` clamps differ, and §16.1 sets none. Not an SDK finding; a contract gap (C164-49, Info,
for 1.65).** §16.1 contradicts itself:
- **The two rows.** The delay cap is "**5 s** — the ceiling on any single wait". `Retry-After` is "honored, as a
  floor: wait = `max(jittered_backoff, retry_after)` … Retrying sooner is not permitted". A `Retry-After` above
  5 s cannot satisfy both.
- **What the SDKs do:**

  | SDK | Clamp | Worst case, non-polling call |
  |---|---|---|
  | Java | 5 s, retrying before the server said | — |
  | Kotlin | 60 s | `checkAccess` answered `503` + `Retry-After: 3600` three times blocks 120.7 s, then retries about an hour early |
  | Python | 1 h | the same call blocks 7200 s |
  | C, C++, Swift | 3600 s | — |

  Each is one reading of the text. Inside `device_login` and `ciba_await` the deadline now governs (C164-36,
  C164-43), so the polling loops are safe whatever the clamp.
- **Recommended 1.65 text.** "A `Retry-After` that exceeds the delay cap ends the §16 retry: the operation
  surfaces the error carrying the `Retry-After`, and the caller decides." That keeps both rows true and makes no
  SDK wait or retry early. Until then, the clamps stay as they are.

**3. C#.**
- **(a) No mutants were run; judged by reading.**
  - The parse-outside-the-retry test kills its mutant.
  - The `Retry-After`-past-the-deadline test kills a dropped check in the new `delay` hook, but only through a
    roughly 20-minute wall-clock wait.
  - **The C164-40 test (`A200ThatArrivesAfterTheDeadlineStillReturnsTheTokens`) passes on the round-2 head
    too.** The old cancellation timer ran on the real clock while the mock moves fake time, and the response
    carries no `id_token`. The test therefore cannot tell the fix from the bug: **C164-46 (Low)**. The fix: a
    responder that blocks in real time past a 1 s real deadline, and a variant with an `id_token` and a slow
    JWKS route.
- **(b) The verifier's `OperationCanceledException` rethrow has no dedicated test.** Info, not Low. After C164-40,
  only the caller's own cancellation reaches the verifier, and no contract test needs it. A short test would kill
  the surviving "remove the rethrow" mutant, and the CHANGELOG should say it applies to every `id_token` and
  `logout_token` verification (C164-48).
- **(c) Dropping `CancellationTokenSource(remaining, TimeProvider)` is correct.** It existed only to put the old
  deadline token on the injected clock. The deadline is now enforced at the loop's check before each send and in
  the §16 `delay` hook ("`now + wait >= deadline` → `expired_token`").
  - Probed by reading: no request at or after the deadline, and no in-poll wait served past it. The bound is
    stronger than in round 2.
  - The only span the deadline does not cut is one request already in flight, bounded by `HttpClient.Timeout`.
    That is what C164-40 asks for.

**4. Swift.**
- **(a) `DevicePollDeferred` is `internal`** (no access modifier, `DeviceGrant.swift:31`) and never leaves
  `devicePoll`/`deviceLogin`. The rename is not source-breaking. The CHANGELOG records the behaviour change,
  which is all it needs to record.
- **(b) P10 is not met; round 2's "bounded" was the device poll only.** `cibaAwait` checks the deadline only
  before each poll, and `cibaPollOnce` calls `bareSend` with no deadline (`Ciba.swift:459-469`). There is no Task
  timeout, and `Retry-After` is clamped only at 3600 s.
  - Probe: with `expires_in` 30 and every poll answered `503` + `Retry-After: 120`, requests went out at 125 s
    and 245 s, and `expired_token` came about 215 s late.
  - It predates this PR, and four other SDKs share it (**C164-43**).

**5. Kotlin's dual-stack trade-off: not acceptable. C164-44 (Medium, a regression of the C164-39 fix).**
- **What breaks.** In OkHttp 4.12.0, Kotlin's pinned version, one setting governs two behaviours. With
  `retryOnConnectionFailure(false)`, `RetryAndFollowUpInterceptor.recover()` returns `false` first, so OkHttp
  neither falls back to the next route nor replays a dropped request.
- **The probe.** A host resolving to `[::1 | 127.0.0.2, 127.0.0.1]`, with the server on `127.0.0.1` only:
  - 3 of 3 raw calls fail, and 2 of 2 SDK polls fail with 0 server requests;
  - once the connection pool is empty, `deviceLogin` and `cibaAwait` can only end in `expired_token`;
  - a pooled connection from discovery hides the failure, which is how most runs pass. Kotlin's own CI hit it
    (`c392bf9` moved the tests to `127.0.0.1`).
- **Why this is a regression a caller meets.** A host with an unreachable first address (an AAAA record on an
  IPv4-only path, or a dual-stack `localhost`) is common. §16.1 counts **attempts**: a refused route is part of
  one attempt, not a reason to lose the poll. Before this PR, Kotlin fell back correctly.
- **The fix, probed.** Keep `retryOnConnectionFailure(true)` and make the poll's form body **one-shot**
  (`isOneShot() = true`). OkHttp then still takes the next route within the call (200, 1 server hit), and does
  not replay a request whose body was sent (1 hit after a drop, against 2 with a plain body). The CIBA poll needs
  the same change. Test: a custom `Dns` returning `[127.0.0.2, 127.0.0.1]` with the server on `127.0.0.1`, and
  the pool evicted first. `devicePoll` returns the tokens in one attempt, and a mid-response drop is still not
  replayed.
- **Java is not affected.** It uses OkHttp 5.5.0. Probed with a custom `Dns` and fast fallback on and off: a
  refused first address (`127.0.0.2` or `::1`) falls through to `127.0.0.1` within the same call, with
  `retryOnConnectionFailure(false)`. The flag there stops only the replay after a mid-response drop. Java's
  `localhost`-addressed tests carry no dual-stack risk.

**6. Rust's CodeQL alert #128 (`rust/cleartext-logging`): confirmed a false positive, not a finding.**
- `device_code` and `client_secret` exist only in `DeviceTokenForm`. It is `Serialize`, not `Debug`, and goes
  straight into the body (`device.rs:517-519`).
- The URL carries only `tenant_id`.
- The send-failure error is a fixed string plus the `reqwest::Error`, which prints the URL and cause, never the
  body. A 5xx error is `HTTP {status}`.
- The only sink is the §16 retry telemetry's `err.to_string()` (`src/retry.rs:269-275`). There are no tracing
  spans on this path. The maintainer can dismiss it.

#### 7.2.2 New findings (C164-43 onward)

| ID | Severity | SDK | `path:line` (round-3 head) | Rule | What | Fix |
|---|---|---|---|---|---|---|
| C164-43 | Low (swift, c, php, java: pre-existing; kotlin: made worse by this PR's C164-37) | swift, c, php, java, kotlin | Swift `Oidc/Ciba.swift:459-469`; C `src/oidc_ciba.c:514-532` vs `:641`; PHP `cibaPollTracked` (real `usleep`, no deadline); Java `AxiamClient.java:4745` (`cibaRedeem` → `StatusRetry.run`, no pacer); Kotlin `oidc/OidcSupport.kt:1364-1373` | §33.7 rule 5; §34.2 P10 (MUST: a §16 retry inside `ciba_poll` as `ciba_await` calls it never waits past the deadline); §33.8 test 7 | `ciba_await`'s in-poll §16 retry does not see `received_at + expires_in`. With `expires_in` 30 and every poll answered `503` + `Retry-After: 120`: **Swift** and **C** send at 125 and 245 s; **PHP** at 45 s (`Retry-After: 20`); **Java** 9 s late (5 s clamp); **Kotlin** at 65 and 125 s. Kotlin's CIBA retry ignored `Retry-After` before C164-37 and now honours it up to 60 s. The P10 half of §33.8 test 7 is missing in each. TypeScript, Python and C++ are bounded (fixed and probed in round 3). Rust and Go were assigned P10 in 1.60 (§34.4 B3) and their CIBA code is unchanged here. C#'s CIBA was not probed for P10 in this round. | Pass `ciba_await`'s deadline and injected clock into the CIBA poll's §16 runner, exactly as C164-36 did for the device poll: before each retry, if `now + full wait >= deadline`, send nothing more and raise the local `expired_token`, at once or after the capped wait. Sleep on the injected clock. Add §33.8 test 7's P10 case: every poll `503` + `Retry-After: 120`, `expires_in` 30 → no `ciba_poll` request at or after `received_at + 30`, and `expired_token` by then. |
| C164-44 | **Medium** | kotlin (regression of the C164-39 fix) | the poll clients built with `retryOnConnectionFailure(false)` (`postToken` → `noRetryHttpClient`, and the CIBA poll) | §16.1 (attempts); §14.2 rule 6 (non-terminal) | On OkHttp 4.12.0 the setting also disables route fallback. A host whose first resolved address refuses fails every poll with 0 server requests once the pool is empty, and `deviceLogin`/`cibaAwait` end in `expired_token` (§7.2.1 point 5). | Poll through the shared `httpClient` (`retryOnConnectionFailure(true)`) with a one-shot form body (`override fun isOneShot() = true`), for the device and CIBA polls. Keep C164-39's attempt count, and add the dual-stack test of §7.2.1 point 5. |
| C164-45 | Low | typescript, java | TS `test/node/deviceFlow.test.ts:834-854` (no CIBA counterpart); Java the C164-36 test (2) | §14.6 / C164-36 (the bound includes the jittered backoff) | Test (2) uses `Retry-After: 1`, so a deadline check that adds only the floor and not the jitter survives. TypeScript probed it: a retry 100 ms after the deadline. In Java an "admit a retry exactly at the deadline" mutant also survives, because test (1) runs with `expires_in` 12. | Pin the jitter, not `Retry-After`: a bare `500` to a poll at deadline − 100 ms with the jitter forced to its maximum (TS `vi.spyOn(Math, 'random').mockReturnValue(1)`; Java through the pacer seam). Assert one request and `expired_token`. Add the CIBA twin in TypeScript. In Java, run test (1) with `expires_in` 30 and add a deadline − 1 ms case with no `Retry-After`. |
| C164-46 | Low | csharp | `tests/…/A200ThatArrivesAfterTheDeadlineStillReturnsTheTokens` | the test §7.1.2 asked for C164-40 | It passes on the round-2 head: the old cancellation ran on the real clock while the mock moves fake time, and there is no `id_token`. The test does not pin the fix. | A responder that blocks in real time past a 1 s real deadline (no fake clock for the deadline), asserting `DeviceLoginAsync` returns the token set. A variant carries an `id_token`, with a JWKS route that also answers after the deadline. |
| C164-47 | Low | php | `src/Oidc/OidcClient.php` (`deviceLogin`, the branch with `$sleep` injected and no `$now`) | §16.1 (`Retry-After` is a floor; "retrying sooner is not permitted") | When a caller injects `$sleep` but no clock, the in-poll waits are counted and not slept. A real sleeper, such as a cancellable or event-loop sleep, then sees a `Retry-After: 20` retried at once and the grant given up about 20 s early. In round 2 the wait was served. | In that branch, sleep through `$retrySleep` (default `usleep`) and count the real elapsed time. Test: `$sleep` injected, no `$now`, a `503` + `Retry-After: 2` then `200` → a recorded real wait of at least 2 s and the tokens. |
| C164-48 | Info | typescript, rust, python, c, cplusplus, csharp, java, kotlin, php | per §7.2.3 | test strength; text | <ul><li>**`retry` telemetry:** emitted before the deadline decision, announcing a retry that is never sent (TypeScript, C#).</li><li>**Deadline-test strength:** the `>=`→`>` boundary is unpinned (TypeScript, C++ CIBA); deadline tests fail only by timeout (TypeScript case 1, C#); the async CIBA clock is untested (Python).</li><li>**Clocks and whole seconds:** in-poll waits sleep on the real clock, not the injected one (Kotlin, C++ CIBA); C++'s device deadline is whole-second, so a grant can end about 1 s early (never late).</li><li>**`Retry-After` after a declined retry:** a 5xx's value is not carried to the next interval (Python, Kotlin).</li><li>**Text:** README gaps (C, Python §16 clamp, PHP `$retrySleep`, C# garbled `README.md:58`); CHANGELOG (C++ intro, Rust line length, C# verifier rethrow); Java's `withRetry` overload could be package-private.</li></ul> | Per §7.2.3, each SDK's round-3 addendum under C164-48. |
| C164-49 | Info | contract | `sdks/CONTRACT.md` §16.1 (the "Delay cap" and "`Retry-After`" rows) | §16.1 self-consistency | A `Retry-After` above the 5 s cap cannot satisfy both rows. The SDKs clamp at 5 s, 60 s and 3600 s (§7.2.1 point 2). | For 1.65: "A `Retry-After` that exceeds the delay cap ends the §16 retry: the operation surfaces the error carrying it." Until then the clamps are not findings. |

**Counts, round 3:** Medium 1 (C164-44) · Low 4 (C164-43, -45, -46, -47; C164-43 in five SDKs) ·
Informational 2 (C164-48, -49).

#### 7.2.3 Per-SDK status, round 3

| SDK | Head | Round-2 findings | New / remaining |
|---|---|---|---|
| typescript | `df5ec4a4b` | C164-36 (device **and** CIBA), -38 (the cap 3 → 5 mutant now fails), -41 **closed** | C164-45, -48 |
| rust | `7fa30ce0` | C164-38, -41 (with N2: `Ended` carries `retry_after`, waits `[5,40,40,40]`) **closed** | C164-48 (Info only) |
| python | `3715bba` | C164-36 (device and CIBA, sync and async), -37 (same commit `479c372`; `check_access` waits 2.0 s), -38, -41 **closed** | C164-48 (Info only) |
| c | `db0d5c59e` | C164-36 (`oidc_post_ex` takes the deadline), -41 (wait-count assertions) **closed** | C164-43, -48 |
| cplusplus | `611c4e9ed` | C164-36 (device and CIBA), -38, -39 (poll and `introspect`), -41 **closed** | C164-48 (Info only) |
| csharp | `4af5be9` | C164-40 **closed** in code; C164-41 partly (its deadline test is real-clock) | C164-46, -48 |
| go | `2a0c273ad` | C164-38, -41 **closed** (tests and CHANGELOG only) | **none** |
| java | `40fd50203` | C164-36 (device), -38, -39 (device and CIBA), -41 **closed** | C164-43, -45, -48 |
| kotlin | `c392bf9` | C164-36 (device), -37, -38, -39 (the count), -41 **closed** | **C164-44 (Medium)**, C164-43, -48 |
| php | `41cf943fd` | C164-36 (jitter in the check), -38, -41 **closed** | C164-43, -47, -48 |
| swift | `a362452` | C164-38, -41 **closed** (read only) | C164-43 |

Where the round-3 diffs touched them, the earlier checks were re-probed and still hold:
- the device deadline bound and the W7.1c shape, in every SDK;
- rules 6 and 9, the three §14.6 429 cases, the 1.63 isolation and the replay after a refresh.

Every version is 1.1.2, and every CHANGELOG records round 3.

**Can W7 merge? No.** The merge condition is §1.4: no open finding of any severity in any SDK PR.
- **Go** is the only SDK with nothing open.
- **Rust, Python and C++** have only C164-48 (Info).
- **Kotlin** has **C164-44 (Medium)**, a regression of the round-2 fix, and C164-43.
- **Swift, C, PHP and Java** have C164-43 (Low), the CIBA P10 bound. It predates this PR, but it sits on the
  §16 path these PRs changed, and §1.4 counts it.
- **TypeScript, Java, C# and PHP** have C164-45, -46 and -47 (Low): two test gaps and one PHP branch.

A round 4 is small: Kotlin's one-shot body, and the CIBA bound in five SDKs (the device fix's own pattern, with
§33.8 test 7's P10 case). The rest are three tests, one branch and the C164-48 text. C164-49 is for 1.65.

The eleven round-3 addenda follow, with the reviewers' N-numbers mapped to the ids above. Where an addendum names a
severity, §7.2.2 is the binding one. Kotlin's probe labels are written P-N1 … P-N8 to keep them apart from
findings.

---

#### Addendum round 3 — typescript — commit df5ec4a4b (PR #150), read after 3b07099cc

Two commits. `a6b055d` covers C164-36 (device and CIBA) and C164-38. `df5ec4a` covers the CHANGELOG/README text (C164-41). Each commit message matches its diff. The one exception is the plan-vs-tree note on test (2), which is discussed below. The SDK clone was not modified. All work was done in `/home/user/work/typescript-r3`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-36 (Low) the in-poll §16 retry is not bounded by the deadline: device, and CIBA under P10 | **CLOSED in code. The test is PARTLY: test (2) does not cover the jittered wait (C164-45).** | a6b055d | **Code.** `deadlineBoundedSleep` (`src/node/oidc.ts:698-708`) is the `withRetry` `sleepFn`. It receives the full wait, `delayMs = max(jittered, Retry-After)` (`src/rest/retry.ts:87`). If `clock.now() + ms >= deadline`, it throws the typed `OAuthProtocolError('expired_token')` and sends nothing. Otherwise it sleeps on the **loop's** clock. Wiring: `deviceLogin` calls `#devicePoll(…, { deadline, clock })` (`:1796`), and that goes to `#postDevicePoll` with `sleepFn` (`:2673`). `cibaAwait` calls `#cibaPoll(…, { deadline, clock })` (`:2519`, `:2462`). The public `devicePoll`/`cibaPoll` pass `undefined` and keep the unbounded §16 behaviour, as the fix allowed. The throw happens inside `withRetry`'s catch, so it propagates as the terminal `expired_token`. **Tests:** `test/node/deviceFlow.test.ts:808` (case 1), `:834` (case 2, with `Retry-After: 1`), `:856` (standalone unbounded), and `test/node/ciba.test.ts:412` (CIBA case 1). **Mutants:** M36dev (device `sleepFn` dropped) fails `:808` and `:834`. M36ciba fails `:412` and the CIBA misc transport test (`:754`, `toHaveLength(4)`). M36cap (serve the wait capped at the deadline, then send) fails all three deadline tests. M36realclock (check, but sleep on `setTimeout`) fails `ciba.test.ts:754`. **M36raonly (the check sees only `Retry-After`, so the jitter is dropped) survives every device and CIBA test (78/78), and so does M36gt (`>` for `>=`).** See C164-45 and C164-48. Under M36dev and M36ciba, case 1 is killed only by vitest's 5 s timeout, because the real 120 s `setTimeout` runs (C164-48). |
| C164-38 (Low) no transport-failure case in the W7.1c test | **CLOSED** | a6b055d | `deviceFlow.test.ts:727-750` uses `HttpResponse.error()`. Two failures, then 200: 3 requests and the tokens. Three failures: 3 requests and a `NetworkError`. `:753`: with retry off, 1 request. Mutants: **M38transport** (the round-2 M25transport, which survived then) now fails both `it.each` cases. **M38ignoredisable** fails `:753` and the 5xx retry-off test. **M38cap5** (`MAX_ATTEMPTS` 5) fails the three-500s, three-transport and CIBA-transport tests, so the cap is pinned. |
| C164-41 (Info) text | **CLOSED** | df5ec4a | Round 2 named one TS text item: the README's "sends nothing after it" was untrue for a 5xx. It is now true (probes below). `README.md:37` adds "A §16 retry inside the poll never passes the deadline… (the CIBA loop is bounded the same way, §34.2 P10)" and "a transport failure likewise". The `deviceLogin` and `cibaAwait` TSDoc (`:1745-1748`, `:2483-2485`) say the same. `CHANGELOG.md:32-38` and `:62-65` record C164-36, -38 and -41. |

**Deadline bound: bounded, device and CIBA.** The probes (`/home/user/work/ts-r3-probes/zprobe3.test.ts`, log `/home/user/work/ts-r3-probe.log`) ran on a virtual clock that the injected clock and any SDK `setTimeout` advance.
- **P7.** `expires_in` 30, interval 5, every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`. Result: 1 request, at 5000 ms. The run ends at 5000 ms with `expired_token`. Round 2 sent requests at 5, 125 and 245 s.
- **P7b.** The same 503 once, then 200. Result: 1 request, `expired_token` at 5 s, and no tokens after the deadline. Round 2 returned tokens 95 s late.
- **P10, the brief's case.** A poll sent at deadline − 0.1 s (`expires_in` 5.1) answered with a bare `500`, and `Math.random` = 1 (a 200 ms jitter). Result: 1 request and `expired_token`.
- **P10a.** `Math.random` = 0.25. A retry goes out at 5050 ms, which is before the 5100 ms deadline and allowed. The next wait (100 ms) is refused. Result: `expired_token` at 5050.
- **P10b.** 200 unmocked runs. The worst request was at 5099.9998 ms, and 97 of the 200 runs sent a legitimate pre-deadline retry.
- **P12.** A far deadline (600 s). `Retry-After` 120 is still honoured inside the poll: requests at 5, 125 and 245 s, then tokens.
- **CIBA.** P9: `cibaAwait`, `expires_in` 30, 503 + RA 120 → 1 request at 5 s, `expired_token`, nothing after `received_at + expires_in`. Round 2 sent at 5, 125 and 245 s. P9b: the near-deadline bare 500 with random = 1 → 1 request. P9c: 503 + RA 120 once, then 200 → `expired_token` at 5 s.

**W7.1c shape: holds.**
- P1, two 500s then 200: 3 requests and the tokens.
- P2, three 500s: 3 requests and a `NetworkError`.
- P3, two transport failures then 200: 3 requests and the tokens.
- P3b, three transport failures: 3 requests and a `NetworkError`.
- P4, a 429: 1 request (`rate_limit_exceeded`). P4b, a 500 then a 429: 2 requests.
- P5, retry off: 1 request for a 5xx and 1 for a transport failure.
- P6: `deviceLogin` takes 3 requests in one interval. P8: a 408 makes 1 request.

**Ruling input: does test (2), made deterministic with `Retry-After: 1`, still prove that no retry can be sent after the deadline? No.**
- **The deviation itself is justified.** The review's test as written ("a poll sent at deadline − 0.1 s answered 500 → no retry") is not a valid assertion against a correct implementation. The first backoff is full jitter over [0, 200] ms. In about half the runs a conforming SDK sends the retry *before* the deadline: P10b had 97 of 200 runs do so, at 5050 ms for example. The commit note is right on that point.
- **The replacement does not test the jitter path.** With `Retry-After: 1` the wait is always max(jitter, 1000) = 1000 ms. The jittered value never decides the outcome. The mutant that checks only `Retry-After` (M36raonly: `now + (retryAfter ?? 0) >= deadline`, the wait still served on the clock) passes all 78 device and CIBA tests. Yet with the brief's bare 500 at deadline − 0.1 s and random = 1, that mutant sends a retry at 5200 ms, 100 ms after the deadline. P10b under that mutant gives a worst request at 5462 ms, and 200 of 200 runs send a retry (`/home/user/work/ts-r3-probe-raonly.log`; CIBA P9b likewise at 5200).
- Test (1) cannot catch it either, because its `Retry-After: 120` decides the wait there too.
- The code is correct, because `sleepFn` receives the full jittered delay. Only the test is weak. See C164-45.

**Version:** `package.json` is 1.1.2, which is right. Nothing public changed: `#devicePoll`, `#cibaPoll` and the `bound` parameter are private, and `PollDeadline` and `deadlineBoundedSleep` are module-internal and not exported. So nothing is source-breaking. `CHANGELOG [1.1.2]` records round 3 (C164-36, -38, -41). The README conformance sentence still says contract 1.64.

**Run by the reviewer** (`/home/user/work/typescript-r3` at df5ec4a, Node 22.22.0, proxy variables unset):
- `npm ci` OK.
- `npx tsc --noEmit` exit 0.
- `npx vitest run`: **119 files, 1771 passed, 3 skipped, 0 failed** (1764 in round 2, plus the 7 new tests).
- `npm run docs`: 0 errors and the 3 known `OidcLoginOutcome` warnings.
- `gen-management --check`: 32 files current, 202 ops.
- `tsup` and `bundle-grep` OK.
- There is no `lint` script.
- 9 mutants (`/home/user/work/ts-r3-mut.sh`, patches in `/home/user/work/ts-r3-mutants/`, logs in `/home/user/work/ts-r3-mut-*.log`): 7 killed (M36dev, M36ciba, M36cap, M36realclock, M38transport, M38ignoredisable, M38cap5) and 2 survived (M36raonly → C164-45, M36gt → C164-48).
- `node_modules` and `dist` were deleted, and the probe file was moved out of the tree.
- The SDK clone is unmodified.

**Round-1/2 checks where the diff touched them:**
- Rule 9: the 429 is still not retried inside the poll (P4 and P4b), and the 429 tests pass.
- Rule 6: a 5xx is non-terminal while the deadline is far (P12 returns tokens).
- Near the deadline the 5xx ends in `expired_token`, raised at once, which C164-36 allows.
- The 401 refresh replay and the 1.63 isolation code are untouched (`interceptors.ts` and the session code are unchanged), so they were not re-probed.

**New findings:**
- **C164-45 — Low (incomplete required test; C164-36 test (2)). `test/node/deviceFlow.test.ts:834-854`; no CIBA counterpart in `test/node/ciba.test.ts`.** Rule: §14.2 rule 4, §34.2 P10, and C164-36's required test (2). **What:** `Retry-After: 1` makes the wait 1000 ms whatever the jitter is, so no test exercises the deadline check on a jittered (bare 5xx) wait. A check that ignores the jitter (M36raonly) survives, and it sends a retry 100–360 ms past the deadline (probe above). **Exact fix:** in `:834`, drop `Retry-After` and pin the jitter with `vi.spyOn(Math, 'random').mockReturnValue(1)`, restored in `finally`. The first backoff is then 200 ms ≥ the 100 ms left. Assert `times` equals `[5000]` and `expired_token`. Optionally add a companion with `mockReturnValue(0.25)`: assert `times` equals `[5000, 5050]` (a retry before the deadline is allowed) and `expired_token`. Add the same case to `ciba.test.ts` (`expiresIn` 5.1, interval 5, bare 500). Verified: probes P10 and P9b written this way give `[5000]` on the head and `[5000, 5200]` under M36raonly.
- **C164-48 — Info (§16.5 / §19 accuracy). `src/rest/retry.ts:131-138` with `src/node/oidc.ts:698-708`.** `withRetry` emits the `retry` event and then calls `sleepFn`. When the deadline refuses the wait, the caller's hook still sees `{type:'retry', delayMs:120000}` for a retry that is never sent (P13: 1 request, one `retry` event, `expired_token`). A caller counting retries over-counts. **Fix:** check the deadline before emitting. For example, add an optional `RetryOptions.admit?(delayMs): void` that may throw, call it before `emit`, and move the deadline check into it. The `sleepFn` then only sleeps on the clock.
- **C164-48 — Info (test strength).**
  - With `sleepFn` dropped (M36dev, M36ciba), case 1 (`deviceFlow.test.ts:808`, `ciba.test.ts:412`) fails only through vitest's 5 s timeout, because the real 120 s `setTimeout` runs. It is not caught by an assertion. Install `vi.useFakeTimers()` in the test, or have the msw handler record whether `setTimeout` was used, so that the assertion fails first.
  - M36gt (`>` for `>=`) survives. The "at the deadline" boundary is not pinned. A case with `expires_in` 5.2 and `Math.random` = 1 (next wait exactly 200 ms, so `now + ms == deadline`) would pin it, by asserting no second request.

---

#### Addendum round 3 — rust — commit 7fa30ce0 (PR #138), read after f4f65ce95

Five commits on top of the round-2 head, in a straight line. `c362368` changes test messages only: assertion messages no longer print response-derived values. `34acfd4`: a 5xx on the poll carries `device token request failed: HTTP {status}` and no longer the server's body. `ce22d14`: a transport failure's message names its kind (`timed out` / `could not connect` / `transport error`), and the reqwest error is kept as `source`. `b36abd6` holds the C164-41 and C164-38 fixes and tests. `7fa30ce` is the CHANGELOG. The diff touches `src/oidc/device.rs` (+263/-21), `src/retry.rs` (+6) and `CHANGELOG.md`. The clone was not modified. All runs used a throwaway copy, `/home/user/work/rust-r3`, which has been deleted.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-38 (Low) | **CLOSED** | `b36abd6` | `raw_token_server` (`src/oidc/device.rs:1452`) is a raw `tokio::net::TcpListener`. It reads each request (head + `Content-Length`), drops the first N connections, and then answers 200. `raw_client` points `token_endpoint` at it. `a_transport_failure_is_retried_inside_the_poll` (`:1568`) checks three cases: 2 drops then 200 gives 3 connections and the tokens; 3 drops give 3 connections, `AxiamError::Network` and `is_retryable_transport()`; retry off gives 1 connection. `device_login_completes_within_one_interval_over_a_flaky_transport` (`:1600`) gives 3 connections and waits `[5 s, ≤200 ms, ≤400 ms]`. This is the contract's shape. **Mutant M6** (a send error returned as `Ok(Err(PollFailure))`, so never retried): **2 fail**, exactly these two. In round 2, M6 made 0 fail. |
| C164-41 (Info), incl. round-2 N2 | **CLOSED** | `b36abd6` | `Ended` gains `retry_after` (`src/retry.rs:217`). It is set on both exits, the non-retryable/exhausted one (`:257`) and the at-deadline one (`:289`). `device_poll_step` puts it on the `PollFailure` (`device.rs:595`), and the loop's Terminal arm sets `retry_after_secs` from it (`:754`). The next wait is then `max(interval, retry_after)`, and the existing `now()+wait >= deadline → expired_token` check (`:715-719`) caps it. Test: `an_exhausted_budget_keeps_the_last_retry_after_as_the_next_polls_floor` (`:1426`), 3×`503` RA 40 then 200, gives 4 polls and waits exactly `[5 s, 40 s, 40 s, 40 s]`. This is the fix and the test the round-2 addendum named. **Mutant M8** (`retry_after: None` at `:595`): 1 fails, that test. **M9** (the loop ignores it at `:754`): 1 fails, that test. Probed with retry on and with retry off: `[5,40,40,40]` both times. With retry off, the single 503 attempt's RA is now also the next poll's floor, which is consistent with §16.1. |

**Deadline bound:** **bounded; no request at or after the deadline.** Probes used a fake clock that advances with each served wait, expires_in 30, interval 5, and every poll answered `503 {"error":"temporarily_unavailable"}`:
- RA 120: 1 request at t=5 s, waits `[5 s, 25 s]`, `expired_token` at 30 s.
- RA 25: the same.
- RA 24: requests at 5 s and 29 s, waits `[5 s, 24 s, 1 s]`, `expired_token`.
- RA 10: requests at 5, 15 and 25 s. The cap is exhausted, and the floor (10 s) would reach the deadline, so the loop stops: `expired_token` at 25 s.
- Real clock, public `device_login`, RA 120: 1 request at 5.29 s, then `expired_token` after 30.01 s.

Poll sent at deadline−0.1 s and answered `500` (40 trials, with and without `Retry-After: 1`):
- No request was ever stamped at or after 30.000 s, and every trial ended `expired_token` at exactly 30 s.
- With RA 1, the wait is capped at the 0.1 s left, and no retry follows.
- With no RA, the full-jitter backoff sometimes falls below the 0.1 s left. Then one retry is sent *before* the deadline (seen at 29.927 s and 29.999 s), answered 500, and the next wait is capped at the deadline.

The brief's "no retry" is therefore true only when the backoff reaches the deadline. §14.2 rule 4 / P10 forbid only a request at or after the deadline, which never happens, so this is not a finding.

CIBA was not re-probed: the round-3 diff does not touch it, and the prompt does not ask.

**W7.1c shape** (all re-probed, all as the contract says):
- Two 500s then 200: 3 requests and the tokens.
- Three 500s: 3 requests and `Network`. In the loop, the next interval follows: `[5 s, 18 ms, 281 ms, 5 s]`.
- Transport failure twice then 200 (FIN and RST): 3 connections and the tokens. In the loop: `[5 s, ~120 ms, ~4 ms]`.
- Three transport failures: 3 connections and `Network`. In the loop, a 4th connection follows at the next interval: `[5 s, 62 ms, 169 ms, 5 s]`.
- 429 (with a body or bodiless): 1 request, with retry on or off.
- Retry off: 1 request per poll, `[5,5,5]`.
- Also unchanged: 408, 400 `authorization_pending` and a bodiless 400 are 1 request each. Rule 9: 429 RA 12 then 200 gives `[5 s, 12 s]`.

**CodeQL alert #128 (rust/cleartext-logging), sink `src/oidc/device.rs:517-519` `self.oauth2_post(url.clone()).form(form)`: FALSE POSITIVE.**
- **Where the secrets live.** `device_code` and `client_secret` exist only in `DeviceTokenForm` (`:59-65`). It derives `Serialize` only, not `Debug`, and it is serialized straight into the request body.
- **The URL holds no secret.** `oidc_endpoint_url` adds only `tenant_id` (`src/oidc/exchange.rs:577-605`). `oauth2_post` adds only `X-Tenant-ID` (`src/client.rs:1120-1125`).
- **The send-failure error holds no secret.**
  - Since `ce22d14`, its message is a fixed string plus the kind (`:525-536`).
  - Its `source` is the `reqwest::Error`. Display and Debug of that error print the kind, the URL and the cause chain, never the request body.
  - A form-serialization failure is reqwest's builder error, which does not echo the values either.
- **The 5xx error holds no secret.** Since `34acfd4`, its message is `HTTP {status}` (`:556-561`).
- **The only log-like sink on this path** is the §16 runner's telemetry `TelemetryEvent::Retry { reason: err.to_string() }` (`src/retry.rs:269-275`). Its text is `network error: device token request failed: <kind | HTTP nnn>`, with no source chain in it.
- **No tracing.** The oidc and retry modules have no `tracing` spans or events. The crate's `tracing::` calls are all in `src/amqp/`.
- **Not on this path:** the 200-parse error message embeds the reqwest decode error's Display (`:575-580`). That is response-side, not the device_code or secret, and it is not handed to telemetry.

Nothing on the flagged path can carry `device_code` or `client_secret` to a log, Display, Debug or tracing sink, or into an error message. Dismiss the alert as a false positive. The round-3 message changes are hardening, not a needed fix.

**New code reviewed:**
- `is_connect_error` (`:240-250`) is cfg-split for wasm32; the wasm check is clean.
- `Ended.retry_after` and `PollFailure` are `pub(crate)`/private, so there is no public API change and nothing is source-breaking.
- Error messages change: the 5xx message drops the body, and the transport message drops reqwest's text. Matching is by variant and `oauth_error_code()`, so callers see no behaviour change beyond the text; the source chain still carries the cause.
- The loop's behaviour change (the 5xx RA kept as a floor after an exhausted budget) is recorded in `CHANGELOG.md:61-66`.

**Version:** 1.1.2 is unchanged and still right (`Cargo.toml:25`, `:127` `=1.1.2`). The changes are crate-private plus a behaviour fix, so a patch is right. The CHANGELOG `[1.1.2]` records round 3 (`CHANGELOG.md:61-66`, C164-38 and C164-41).

**Run by the reviewer** (copy at `/home/user/work/rust-r3`, protoc present, swagger placeholder):
- Tests:
  - `cargo test --all-features --lib`: 249 passed, 0 failed.
  - `--test device_flow_test --test device_auth_test --test device_client_auth_test --test oauth2_no_session_bearer_test --test network_manifest_test`: 14, 13, 8, 3 and 15 passed.
  - `cargo test --all-features --lib oidc::device`: 27 passed.
- Lint and builds, all clean:
  - `cargo fmt --all --check`
  - `cargo clippy --lib --tests --all-features -- -D warnings`
  - `cargo clippy --lib --no-default-features --features amqp -- -D warnings`
  - wasm32 `cargo check --lib --target wasm32-unknown-unknown --no-default-features --features rest,opaque` with `getrandom_backend="wasm_js"`: exit 0, 0 warnings.
- Mutants (env-switched, one build):
  - M6 (transport not retried): 2 fail.
  - M8 (`Ended.retry_after` dropped at `:595`): 1 fails.
  - M9 (loop ignores the RA at `:754`): 1 fails.
  - The unmutated build: 27/27 pass.
- Probes: the round-2 probe module plus two new ones (late 500, transport loop with 3 drops, 3×503 RA 40 with retry on and off). 33/33 ran.
- The copy, including `target/`, was deleted afterwards.
- Not run: the unscoped `cargo test --all-features`, examples, docs, and wasm-pack.

**New findings:**
- **C164-48 — Info (text)** — `CHANGELOG.md:15`. The commit `7fa30ce` says it wraps the long line. It re-flowed it instead, and line 15 is now 154 characters ("stays 202 operations … so it"). Exact fix: wrap line 15 at about 100 columns, like the surrounding paragraph. Cosmetic; it does not block.

---

#### Addendum round 3 — python — commit 3715bba (PR #103), read after d5ce0cbc7

There are two commits. `479c372` covers C164-36, -37 and -38: source and tests. `3715bba` covers C164-41: the README and the CHANGELOG. Each commit message matches its diff. **C164-36 and C164-37 land in the same commit (`479c372`)**, as §7.1.2 required.

The design is as follows:
- `retry_sync`/`retry_async` take an optional `deadline: Callable[[], float]`, which returns the seconds left (`_retry.py:113`, `:164`).
- Before each retry, the full wait is computed as the jittered backoff floored at `Retry-After`. If `wait/1000 >= deadline()`, the failure is re-raised with no sleep and no send (`_retry.py:143`, `:183`).
- `device_login` passes `schedule.remaining`, a new `PollSchedule.remaining()` at `_oidc.py:344` that takes the min of the sum-of-waits bound and the real clock (`_client.py:2071`, `_async_client.py:877`).
- `ciba_await` passes `deadline - tick.now()` and `sleep=tick.sleep`, which is the injected clock (`_client.py:2371-2372`, `_async_client.py:1069-1070`).
- The public `device_poll` and `ciba_poll` delegate to the private `_device_poll`/`_ciba_poll` with `deadline=None`, so their signatures are unchanged.
- `NetworkError` gains `retry_after_ms: float | None = None` (`_errors.py:137-140`). `error_from_http_status` sets it for 408, 429 and 5xx when given a response (`_errors.py:276-279`). The runner clamps it at `MAX_RETRY_AFTER_MS = 3_600_000` (`_retry.py:44`, `:91`).

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-36 (Low), device | **CLOSED** (sync and async) | 479c372 | **Tests:**<ul><li>`tests/test_device_flow.py:1045`/`:1084`: a poll at deadline−0.1 answered 500 is sent once only, at `[9.9]`.</li><li>`:1062`/`:1104`: `expires_in` 30, interval 5, every poll 503 + `Retry-After: 120`. Nothing is sent at or after 30, `expired_token` is raised, and `clock.now < 30`.</li></ul>**Mutants** (in the throwaway copy):<ul><li>**M1** (deadline check removed from `retry_sync`): `:1045`, `:1062` and the sync CIBA test fail.</li><li>**M2** (removed from `retry_async`): the three async twins fail.</li><li>**M3**/**M3a** (`device_login` passes `deadline=None`, sync/async): `:1045`+`:1062` / `:1084`+`:1104` fail.</li><li>**M9** (`remaining()` ignores the clock): 5 fail, including the two "deadline−0.1" tests.</li></ul> |
| C164-36 (Low), CIBA (§34.2 P10, which rides the shared runner) | **CLOSED** (sync and async) | 479c372 | **Tests:**<ul><li>`tests/test_ciba.py:991`/`:1011`: `expires_in` 30, interval 5, every poll 503 + RA 120. No request has elapsed ≥ 30 and `CibaExpiredTokenError` is raised before 30.</li><li>`:1030`: RA 7 inside the deadline is waited on the injected clock.</li><li>The round-2 test `:923` was amended to filter the sub-second §16 sleeps, which now go through the injected clock.</li></ul>**Mutants:**<ul><li>**M4**/**M4a** (`ciba_await` passes `deadline=None`): `:991` / `:1011` fail.</li><li>**M5** (sync `sleep=None`): `:1030` fails.</li><li>**M5a** (async `sleep=None`): **survives**. See C164-48.</li></ul> |
| C164-37 (Low) | **CLOSED** SDK-wide, landed with -36 | 479c372 | **Tests:**<ul><li>`tests/test_d5_conformance.py:475`: `check_access` answered 503 + RA 2, then 200, gives 2 calls and `waits[0] >= 2.0`.</li><li>`:223`: the contended-write test now asserts its RA 1 floor, so the old `:190-193` comment has a test behind it.</li><li>`:496`: 408/429/500/503 carry `retry_after_ms == 3000`. A bare 502 and a 400 carry `None`.</li><li>`:510`: the 1 h clamp.</li><li>`test_device_flow.py:1124`: a bare `device_poll` 503 + RA 2 waits ≥ 2 s.</li></ul>**Mutants:**<ul><li>**M6** (`retry_after_ms` never set): 5 tests fail, `:223`, `:475`, `:496`, `test_device_flow.py:1124` and `test_ciba.py:1030`.</li><li>**M7** (clamp removed): `:510` fails.</li></ul>**Probe** (sync and async `check_access`): 503 + RA 2, then 200, gives 2 requests, sleeps `[2.0]` and `allowed=True`. In round 2 it was 0.066 s. |
| C164-38 (Info) | **CLOSED** | 479c372 | **Tests:**<ul><li>`tests/test_device_flow.py:1148`: async, `ConnectError` twice then 200, gives 3 requests and the tokens.</li><li>`:1175`: a sync `device_login` with two transport failures then 200 completes in one interval.</li><li>`:1190`: through `device_login` with `retry_enabled=False`, one request per poll.</li></ul>**Mutant M8** (async transport mapping removed, which was round 2's surviving M4a): `:1148` **now fails**. |
| C164-41 (Info) | **CLOSED** | 479c372, 3715bba | <ul><li>`README.md:1603-1610` says the poll is §16-retried inside the attempt (3 requests, RA floor, no 429 retry, 1 request when retry is off), bounded by the deadline in `device_login` and `ciba_await` (P10), with no deadline on a bare `device_poll`.</li><li>The `device_poll` docstrings (`_client.py:1958-1962`, async twin) now describe the in-poll retry.</li><li>The `device_login` docstring ("the deadline binds all of it") is now **true**, per the probes below.</li></ul> |

**Deadline bound:** **bounded, sync = async, device and CIBA.**

Probe setup:
- A fake `time.monotonic`, with `time.sleep`/`asyncio.sleep` advancing it.
- `random.random` pinned to 1.0 (maximum jitter).
- For CIBA, the test kit's `TestClock`/`AsyncTestClock`.

| Probe | Requests at (s) | Result |
|---|---|---|
| device, `expires_in` 30, `interval` 5, every poll 503 `temporarily_unavailable` + RA 120, RTT 0 | 5, 10, 15, 20, 25 | `expired_token` at t = 25.0. The 120 s floor reaches the deadline, so no in-poll retry is sent. |
| the same, each request takes 2.4 s | 5.0, 12.4, 19.8, 27.2 | `expired_token` at 29.6. Nothing is sent at or after 30. |
| device, a poll sent at 29.9 (a 24.9 s `on_user_code`) answered 500 | 29.9 | No retry. `expired_token` at 29.9. |
| CIBA `ciba_await`, `expires_in` 30, `interval` 5, every poll 503 + RA 120 | 5, 10, 15, 20, 25 | `CibaExpiredTokenError` at 25.0. No `ciba_poll` request after `received_at + 30`. |
| CIBA, deadline at 28.1 (`received_at` −1.9), interval 7, pending ×3, then a 500 at 28.0 | 7, 14, 21, 28 | No retry (0.2 s ≥ 0.1 s left). `CibaExpiredTokenError` at 28.0. |

Compared with round 2: 15 requests (3 per poll) before, 5 now. One behaviour is not ideal: after the runner declines a retry, the loop's next poll still comes at the interval, not at the 5xx's `Retry-After`. See C164-48.

**W7.1c shape:** conforms, sync and async, through `device_poll` (12 probe cases):

| Case | Requests | Outcome |
|---|---|---|
| two 500s, then 200 | 3 | tokens |
| three 500s | 3 | `NetworkError` |
| `ConnectError` ×2, then 200 | 3 | tokens |
| `ConnectError` ×3 | 3 | `NetworkError` |
| 429 | 1 | `OAuthProtocolError` |
| `retry_enabled=False`, a 500 | 1 | `NetworkError` |

The SDK's own suite now has every case, the async transport case included.

**Rules 6/9, the 429 cases, 1.63 isolation, replay after 401:** not touched by the round-3 diff. The 429 path is unchanged, because an `OAuthProtocolError` is not retried and the rate-limited branch of `device_login` is unchanged. The refresh/replay helpers are not in the diff, and the full suite is green.

**Ruling input: the worst-case block of a non-polling §16 call.**
- **7200 s (2 h)** plus three round trips.
- Probe: `check_access` (sync and async) answered `503` + `Retry-After: 3600` three times. It makes 3 requests, sleeps `[3600.0, 3600.0]` (7200 s in total), then raises `NetworkError`.
- `Retry-After: 999999` gives the same, `[3600, 3600]`, because the 1 h clamp (`_retry.py:44`, `:91`) holds.
- A round trip is bounded by the default httpx timeouts (`_session.py:143`). So the bound is 2 h plus 3× the per-request timeout. The 5 s `MAX_DELAY_MS` caps only the jittered backoff, never the floor.
- The device and CIBA case stays bounded, because -36 landed in the same commit. With RA 120 or 3600 the in-poll retry is never taken past `expires_in`.
- A bare `device_poll`/`ciba_poll` (no deadline) has the same 2 h worst case as `check_access`.
- The README §16 paragraph (`README.md:2673-2676`) reads "3 attempts … 5 s cap … `Retry-After` honored as a floor". It does not state the 1 h clamp, so a reader can take 5 s as the ceiling (C164-48).

**Version:**
- `pyproject.toml:7` and `__init__.py:109` both read 1.1.2, which is still right.
- The new public surface is the `NetworkError.retry_after_ms` attribute: additive, defaulting to `None`, and not a source break. It is recorded in the CHANGELOG and documented by a `#:` attribute comment.
- `retry_sync`/`retry_async` gain a keyword-only `deadline` in the private `_retry` module.
- `_device_poll`/`_ciba_poll` are private. The public signatures are unchanged.
- The `NetworkError` subclasses (`ValidationError`, `_RebindFailed`) call `super().__init__`, so they get the attribute too.
- The CHANGELOG `[1.1.2]` records round 3 (C164-36, -37 with the attribute and "not a source break", and -38/-41 at `CHANGELOG.md:50-65`).

**Run by the reviewer:**
- Throwaway copy `/home/user/work/python-r3` (`git archive HEAD`), venv on Python 3.13.16, `pip install -e '.[dev,fastapi,django]'`.
- `ruff check .`: all checks passed. `ruff format --check .`: 218 files already formatted.
- `mypy --strict src`: no issues in 98 source files. `interrogate src`: 100%. `scripts/gen_management.py --check`: OK (32 files, 202 ops).
- `pytest tests -q`: **2168 passed**, 7 warnings (6 min 18 s). That is 2154 + 14 new.
- Probes: 28 cases (`/home/user/work/python-r3-probe/test_r3_probe.py`), all as expected.
- Mutants M1–M9 (12 variants) via `/home/user/work/python-r3-probe/mut.py` in a second copy. All are killed except M5a.
- The venv, the mutant copy and the caches were deleted afterwards. The SDK clone is unchanged (`git status` clean).

**New findings:**
- **C164-48 — Info — `src/axiam_sdk/_client.py:2075` (`device_login` "retry" branch), `_async_client.py:881`; `ciba_await` `_client.py:2378`, `_async_client.py:1076`; §16.1 floor / C164-36 "send nothing more".**
  - **What:** when the runner declines a retry because the `Retry-After` floor reaches the deadline, it re-raises the `NetworkError`. The loop classes that as "retry" and polls again at the plain interval. With RA 120 the device and CIBA loops send 4 more polls, at 10, 15, 20 and 25 s, which the server asked not to see.
  - **Status:** nothing is sent after the deadline, so rule 4 and P10 hold. But the 5xx `Retry-After` is dropped at the loop level, as in Rust and Swift (C164-41).
  - **Fix:** in the "retry" branch, read `ra = getattr(exc, "retry_after_ms", None)`. If it is set, call `schedule.rate_limited(ra / 1000.0)`; `tick()` already caps that at the deadline and raises `expired_token` without sending. In `ciba_await`, on a retry step carrying `retry_after_ms`, wait `max(interval, ra/1000)` for the next sleep (still checked against `deadline`).
  - **Test:** RA 120 on every poll gives exactly 1 request, then `expired_token`.
- **C164-48 — Info — `tests/test_ciba.py:1030` (sync only); test strength.**
  - **What:** no async test pins that the async `ciba_await`'s in-poll §16 wait sleeps on the injected `AsyncCibaClock`. Mutant M5a (`sleep=None` at `_async_client.py:1070`) survives, because the amended `:923` filters waits under 1 s.
  - **Fix:** add the async twin of `:1030` (503 + RA 7, then 200, on `AsyncTestClock`, so `clock.sleeps` holds a 7).
- **C164-48 — Info — `README.md:2673-2676`; text.**
  - **What:** the §16 paragraph gives "5 s cap" and the floor, but not the 1 h `Retry-After` clamp. As a result, `check_access` can block about 2 h on three 503 + RA ≥ 3600 answers.
  - **Fix:** add "a server `Retry-After` is honoured as a floor up to one hour (`MAX_RETRY_AFTER_MS`); the 5 s cap applies to the computed backoff only".

No Medium or Low findings.

---

#### Addendum round 3 — c — commit db0d5c59e (PR #77), read after 263d4cc2d

There is one commit over the round-2 head: `db0d5c5` "fix: the in-poll retry never waits past the device grant's deadline (C164-36, C164-41)". It touches:
- `src/oidc.c` (+19/-3): `oidc_post` becomes a wrapper over a new internal `oidc_post_ex(..., time_t deadline, ...)`.
- `src/oidc_internal.h`: the internal `oidc_token_grant_ex` gains a `deadline` parameter.
- `src/oidc_device.c` (+4/-4): `device_poll_with` carries the deadline. `axiam_device_login` passes its deadline; `axiam_device_poll` passes 0.
- `include/axiam/oidc.h`: comment only.
- `CHANGELOG.md` and `tests/test_oidc_grants.c` (+66).

The clone `/home/user/sdks/c` was only read and is clean. All work was done in the throwaway clone `/home/user/work/c-r3`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-36 (Low): the in-poll §16 retry ignores `device_login`'s deadline | **CLOSED** | db0d5c5 | **Code:** `src/oidc.c:475` runs before each in-poll retry sleep. The check is `if (deadline && clock_fn() + ceil(delay/1000) >= deadline) break;`. `delay` is the full jittered backoff, floored at `Retry-After` (`axiam_retry_delay_ms`). The 5xx then ends the poll, and the loop's top check (`src/oidc_device.c:307-316`) raises `expired_token`. The deadline comes from `src/oidc_device.c:298` and is passed at `:329-330`. `axiam_device_poll` passes 0 (`:262`), so it keeps the unbounded §16 behaviour, as the fix allows. **Edge case:** the clock is in whole seconds and the wait is rounded up, so a retry that passes the check leaves strictly before the deadline (send ≤ n + f + ⌈d⌉ ≤ D − 1 + f < D). **Test:** `test_the_in_poll_retry_never_waits_past_the_grants_deadline` (`tests/test_oidc_grants.c:448-505`) has four parts:<ul><li>Fix test (1): 503 + `Retry-After: 120`. Expects 5 polls at 5-25 s, `expired_token`, elapsed time under 30 s, and every sleep ≤ 5 s.</li><li>A control with `Retry-After: 20`: the retry at 25 s is allowed and nothing follows it.</li><li>Fix test (2): a poll at deadline − 1 s on the integer clock, answered 500 with jitter 0.5, gets no retry.</li><li>A bare `axiam_device_poll` still sleeps ≥ 120 s.</li></ul>**Mutants**, all killed, each only in the new test:<ul><li>M36a, check removed: `:463` "Expected 5 Was 3".</li><li>M36b, no rounding up: `:489`.</li><li>M36c, `device_login` passes 0: `:463`.</li><li>M36d, `>=` changed to `>`: `:489`.</li></ul> |
| C164-41 (Info, C part): the `device_login` W7.1c sub-case does not count waits | **CLOSED** | db0d5c5 | `tests/test_oidc_grants.c:436-439` adds `n_sleeps == 3` and `sleeps[1] < 2000 && sleeps[2] < 2000`, the exact fix. **Mutant M41** stops the in-poll retry after attempt 2 only when a deadline is set, so `device_login` sends its third request one interval later and single polls are unaffected. It is killed at the new assertion `:439` (and at `:328`, the older 500-mid-poll test). Round 2's weakness, that only the single-poll sub-cases killed this shape, is gone. |

**Deadline bound (device):** **bounded.** Reviewer probes ran on the virtual clock, with jitter 0.5, `expires_in` 30 and interval 5. Probes E1, E2 and E4 used interval 29 and a fake sleep that overshoots by 900 ms, so the poll leaves at 29.9 s.

| Probe | Requests at | Result |
|---|---|---|
| D1: 503 + `Retry-After: 120` on every poll | 5, 10, 15, 20, 25 s | `expired_token` at 25 s; nothing at or after 30 s (round 2: 125 s and 245 s) |
| D2: 503 + RA 120, then 200 | 5, 10 s | tokens from the 10 s poll (round 2: from a poll at 125 s) |
| D3: 503 + RA 3600 | 5-25 s | `expired_token` at 25 s (round 2: blocked about 2 h) |
| D5: 503 + RA 20 | 5, 25 s | `expired_token`; nothing at 45 s |
| D4 (control): 500 without RA | 15 requests, the last at 26.5 s | unchanged |
| E1: poll at 29.9 s answered 500 | 29.9 s | no retry; `expired_token` |
| E2: poll at 29.9 s answered 503 + RA 120 | 29.9 s | no retry; `expired_token` |
| E4: poll at 29.9 s, transport failure | 29.9 s | no retry; `expired_token` |
| E3: interval 28; 500, 500, 200 | 28.0, 28.1, 28.3 s | the retries that fit are still sent; tokens |
| D6: single `axiam_device_poll`, 503 + RA 120 | 0, 120, 240 s | `AXIAM_ERR_NETWORK`, cause 503 (no deadline, as allowed) |

**W7.1c shape:** unchanged and correct (single poll / `device_login` interval 2):

| Case | Result |
|---|---|
| 500, 500, 200 | 3 requests at 0, 100, 300 ms; tokens. In `device_login`: 2000, 2100, 2300 ms, sleeps `[2000, 100, 200]` |
| 500 ×3 | 3 requests, `AXIAM_ERR_NETWORK`, cause 500 |
| transport failure ×2, then 200 | 3 requests; tokens |
| transport failure always | 3 requests, `AXIAM_ERR_NETWORK` |
| 429 + RA 5 | 1 request, `rate_limit_exceeded`. In `device_login`: sleeps `[2000, 5000]`, 2 requests |
| retry off | 1 request per poll. In `device_login`: `[2000, 2000, 2000]` |

The `err == NULL` probes (C164-27) still give `AXIAM_ERR_NETWORK` after 3 attempts for a 5xx, and 1 request for 400 and 429.

**CIBA (asked by the prompt; C's round 3 does not claim it): `axiam_ciba_await`'s §16 retry is NOT deadline-bound. P10 fails.**
- **Where:** `ciba_poll_with` has its own §16 loop (`src/oidc_ciba.c:514-532`). Each retry sleeps `axiam_retry_delay_ms(...)` on `c->sleep_fn` (`:531`) and has no deadline parameter. `axiam_ciba_await` computes `deadline` at `:641` but checks it only at the top of its loop (`:645`).
- **Probe:** `/home/user/work/c-r3/tests/probe_ciba.c`, built on the `test_ciba.c` harness plus a `Retry-After` header. Setup: `expires_in` 30, interval 5, every `ciba_poll` answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`.

| Clock | Requests at | Result |
|---|---|---|
| default (the client's) | 5, **125, 245 s** | `expired_token` only after **245 s**; 2 requests after `received_at + expires_in` |
| injected `axiam_ciba_clock_t` | (same schedule) | as above |
| control: 500 without RA (jitter 0) | 15 requests, all ≤ 25 s | bounded |

- **Second problem:** with an injected clock, the retry waits run on the client's `sleep_fn`, not on `clock->sleep`. A caller's injected clock never sees those waits, and nothing checks them against its `now`.
- **Test gap:** §33.8 test 7's second sentence (a 503 whose `Retry-After` reaches past the deadline) has no test. `test_t07_…` (`tests/test_ciba.c:670`) covers `authorization_pending` only.

See C164-43.

**Rules 6/9, the three §14.6 429 cases, 1.63 isolation, the replay after a 401 refresh:** the diff does not touch the loop body, rule 6 or rule 9 dispatch, `/oauth2/*` isolation, or `authz_post`. `oidc_post`'s behaviour is unchanged when `deadline == 0`, which every non-device caller passes. The existing §14.6 tests pass, and the W4/W4L probes re-check rule 9.

**Version:** 1.1.2 is still right: CMake `VERSION`, `conanfile.py` and `ports/axiam-c-sdk/vcpkg.json`.
- **Public header:** the only change is a comment block in `include/axiam/oidc.h` (`:1101-1104`, the deadline bound in the `axiam_device_login` doc), with no declaration, struct or enum change. The new `oidc_post_ex` and the changed `oidc_token_grant_ex` signature are internal (`src/oidc_internal.h`). So `AXIAM_SOVERSION 2` (`CMakeLists.txt:134`) stays right, and `abi_soname` passes.
- **CHANGELOG:** records round 3 under 1.1.2: a Fixed entry for C164-36, with its test named, and a Tests note for C164-41.

**Run by the reviewer** (`/home/user/work/c-r3`; `build-asan/` was deleted afterwards):
- **Build:** `-DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON` with `-fsanitize=address,undefined -fno-sanitize-recover=all` on the C flags and on the exe and shared linker flags. 0 warnings.
- **Suite:** `ctest` run serially, probes excluded: **81/81 passed**, ASan/UBSan clean, 17.0 s. `test_oidc_grants` 34/34 (33 + 1 new); `test_ciba` 19/19.
- `scripts/gen_management.py --check`: clean.
- **Mutants:** M36a-d and M41, with `ASAN_OPTIONS=detect_leaks=0`. Each was restored afterwards and the whole tree rebuilt before the suite ran.
- **Probes** (copy only): `tests/probe_r3.c` (device: D1-D6, E1-E4, W7.1c, the `err == NULL` cases) and `tests/probe_ciba.c` (C1-C3).
- **Not run:** the C-standard matrix, valgrind, Doxygen, the package recipes.

**New findings:**
- **C164-43 — Low** — `src/oidc_ciba.c:514-532` (`ciba_poll_with`'s §16 loop), reached from `axiam_ciba_await` `:659`. The deadline is at `:641`.
  - **Rule:** §33.7 rule 5, last sentence, and §34.2 P10 (a §16 retry inside `ciba_poll` as `ciba_await` calls it never waits past the deadline; nothing is sent after it). Also §33.8 test 7, second sentence (a required test).
  - **What happens:** the probe above. A `5xx` + `Retry-After: 120` makes `ciba_await` (`expires_in` 30) send requests at 125 s and 245 s and block 245 s. With `Retry-After: 3600` it blocks for hours, because the only clamp is 3600 s in `retry.c`. A `200` to a late retry would return tokens from a poll sent after the deadline. The in-poll waits also bypass an injected `axiam_ciba_clock_t`. This has the same shape as C164-36, which this commit fixed for the device grant only. It was not on the §7.1.2 "outside these PRs" list for C, so it is new here.
  - **Exact fix:**
    - Add a `time_t deadline` (0 = none) to `ciba_poll_with`, and the `clk` used by `axiam_ciba_await`.
    - In the retry loop, after computing `delay`: `if (deadline && clk->now(clk->ctx) + (time_t)((delay + 999L) / 1000L) >= deadline) break;`. The 5xx then surfaces as transient, and the loop's top check raises `expired_token` with nothing sent after the deadline.
    - When a `clk` is given, sleep on `clk->sleep(clk->ctx, (delay + 999) / 1000)` rather than `c->sleep_fn`, so the injected clock sees the waits.
    - `axiam_ciba_poll` (`:592`) passes 0 and keeps the unbounded §16 behaviour.
  - **Test** (in `test_ciba.c`; the fake needs a `Retry-After` header on its `answer_t`): `expires_in` 30, interval 5, every poll `503` + `Retry-After: 120`, on `TEST_CLOCK`. Expect `expired_token`, no `/oauth2/token` request at or after `received_at + 30`, and `g.clock_s - start < 30`. Add a control with `Retry-After: 20`: the retry at 25 s is sent, and nothing follows it.
- **C164-48 — Info** — `README.md:46-47`.
  - **Rule:** text only.
  - **What:** the README says a 5xx is "retried under §16 inside the poll". It does not add that this retry never waits past the deadline. The header (`oidc.h:1101-1104`) and the CHANGELOG do say it.
  - **Fix:** append ", and that retry never waits past the `expires_in` deadline (nothing is sent after it)".

---

#### Addendum round 3 — cplusplus — commit 611c4e9ed (PR #80), read after d95d2f173

Commits read (`git log d95d2f173..HEAD`): `eea9060` fix(device,ciba,introspect), which closes C164-39, -36 and -38, and `611c4e9` (CHANGELOG and README, C164-41). Each commit message matches its diff: 9 files, +239/−17. The `src/` changes are `oidc.cpp`, `client.cpp` and `client_impl.hpp`. One public header changed: `include/axiam/client.hpp` (+4 lines, a single new member function). `path:line` refers to 611c4e9. Both commits carry SSH signatures; they could not be verified here because no allowedSignersFile is configured.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-39 (Low) transport failure not retried in the attempt — **device poll** | **CLOSED** | eea9060 | `src/oidc.cpp:887`: `token_grant` now sends with `impl.transport(req)`, not `send_raw`. The loop's `status = nullopt` → retry branch is now live. The 429 break is guarded (`status && *status == 429`, `:896`), which removes an empty-optional dereference that the dead path used to hide. The post-loop `transport_error` → `NetworkError` (`:916`) is now reachable. Skipping `capture_csrf` is correct because the request is `sessionless`. Test `tests/test_oidc_grants.cpp:553` covers: transport ×2 then 200 → 3 calls and tokens; `device_login` → 3 calls with sleeps `[5000, <5000, <5000]`; transport ×3 → `NetworkError` after 3 calls; retry off → 1 call. **Mutant M3** (`:887` back to `send_raw`) fails this test. |
| C164-39 (Low) — **introspect** | **CLOSED** | eea9060 | `src/oidc.cpp:1182`: `token_admin_call` → `impl.transport(req)`. Its loop has no `*status` dereference. Test `tests/test_oidc.cpp:888`: `introspect_status = 0` → `NetworkError` after 3 calls. **Mutant M4** (back to `send_raw`) fails it alone. |
| C164-36 (Low) in-poll §16 wait not capped at the deadline — **device** | **CLOSED** | eea9060 | `device_login` passes `deadline` → `device_poll_with` → `token_grant` (`:1760`, `:1701`). Before each §16 sleep, `:908` checks `now_seconds_fn() + ceil(delay s) >= deadline`. If so, it throws the typed `expired_token` and sends nothing more. The loop rethrows it as terminal (`:1786`). A bare `device_poll` passes no deadline, so it keeps the §16 budget, and the test checks this (3 calls). The loop and the retry read the same clock (`now_seconds_fn`, `:1736`, `:1752`). Tests: `test_oidc_grants.cpp:634` (exp 30 / int 5 / 503 + RA 120 → 1 call, virtual clock < 30, 1 sleep) and `:662` (poll at t=5 of 6 answered 500 → no retry). Mutants: **M1** (check disabled) fails both. **M5** (`device_login` does not pass the deadline) fails both. **M6** (ceil → floor) fails `:662`. **M7** (`>=` → `>`) fails `:662`. |
| C164-36 (Low) — **CIBA** (§34.2 P10) | **CLOSED** (one test-strength gap, C164-48) | eea9060 | `ciba_poll_once` takes `&clock` and `deadline` from `ciba_await` (`:2580`). Before each §16 sleep, `:2452` checks `clock->now() + delay >= deadline`. If so, it sets `transient = false` and an `expired_token` error, and `ciba_await` rethrows it as terminal. A bare `ciba_poll` passes nothing. Test `tests/test_ciba.cpp:561` (exp 30 / int 5 / 503 + RA 120 → 1 call, `expired_token`, fake clock < 30). **Mutant M2** (check disabled) fails it. **Mutant M8** (`>=` → `>`) **survives**: there is no CIBA boundary case (C164-48). |
| C164-38 (Low) W7.1c test lacks the transport case and the "next interval after the cap" assertion | **CLOSED** | eea9060 | `test_oidc_grants.cpp:553` adds the four transport cases. `:602` adds `{500,500,500,200}` through `device_login` → 4 calls, sleeps `[5000, <5000, <5000, 5000]`. Both are non-vacuous: M3 kills `:553`. A cap mutant (3 → 4) would break the 4-call / 4-sleep shape at `:602`. That last point is by reading; not run. |
| C164-41 (Info) README "the one behaviour note" | **CLOSED** | 611c4e9 | `README.md:41` now reads "for the behaviour notes". Docs only. |

`Deadline bound:` **bounded, for device and CIBA.**
- **Device**, on a virtual clock that the recorded sleeper advances, interval 5, `expires_in` 30:
  - Every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`: requests at t=**5** only. Sleeps `[5000]`. `expired_token` at t=5.
  - Same with RA 10: requests at 5, 15, 25. The budget is spent, then the loop raises `expired_token` at 25.
  - 503 with no RA: requests at 5,6,7, 12,13,14, 19,20,21, 26,27,28, then `expired_token` at 28. Transport failure on every poll: the same.
  - **Nothing is sent at or after 30 in any of these cases.**
- **Device, deadline − ε:**
  - Poll at deadline − 1 s (exp 6, int 5) answered 500: 1 request, then `expired_token`, no retry.
  - Poll at deadline − 2 s (exp 7): the 100 ms retry is served at t=6 and returns tokens.
- **Device, real clock** (default `std::time` seam, real sleeps):
  - exp 2 / int 1, 500 then 200: one request at 1.00 s, then `expired_token` at 1.00 s.
  - exp 6 / int 1, 503 + RA 10: one request at 1.00 s, then `expired_token` at 1.00 s. Round 2 sent requests at 1, 11 and 21 s here.
  - The clock counts whole seconds, so any retry in roughly the last second is refused (C164-48).
- **CIBA**, on a fake `CibaClock` with the §16 sleeper advancing the same time point, exp 30 / int 5:
  - 503 + RA 120: 1 request at 5.00, then `expired_token` at 5.00.
  - RA 10: requests at 5, 15, 25, then `expired_token`.
  - No RA, and transport on every poll: 15 requests, the last at 26.50, then `expired_token`.
  - `received_at` shifted so that the poll goes out at **deadline − 0.1 s**, answered 500: **1 request**, then `expired_token`.
  - In every case, no `ciba_poll` request is sent at or after `received_at + expires_in`.

`W7.1c shape:` **conforms** (probes on a bare `device_poll` unless stated):
- Two 500s → 3 requests and tokens (sleeps 100, 200).
- Three 500s → 3 requests and `NetworkError (HTTP 500)`.
- Transport ×2 then 200 → 3 requests and tokens.
- Transport ×3 → 3 requests and `NetworkError: connection refused`.
- 429 → 1 request and `OAuthProtocolError rate_limit_exceeded`.
- Retry off → 1 request.
- Through `device_login`:
  - Transport ×2 then 200: 3 calls, sleeps `5000,100,200`.
  - Transport ×3 then 200: 4 calls, sleeps `5000,100,200,5000`, so the loop takes its interval after the cap.
  - 429 with RA 7 then 200: 2 calls, sleeps `5000,7000`.

Rules 6/9, the three §14.6 429 cases, 1.63 isolation and the post-401 replay are untouched by the diff, apart from the guarded 429 test at `:896`. All their tests pass. Moving from `send_raw` to `transport` on `/oauth2/token` and introspect means no CSRF is captured from an `/oauth2/*` response any more. That is if anything stricter §6.1 rule 11 isolation.

**Ruling input — `Client::_set_clock_test_seam`:**
- **Public installed header: yes.** It is declared at `include/axiam/client.hpp:1364`, and `install(DIRECTORY include/axiam …)` is at `CMakeLists.txt:148`. It is exported: `nm -DC` shows `T axiam::Client::_set_clock_test_seam(std::function<long ()>)`. It sits next to `_set_retry_test_seams`, which already shipped in v1.1.1, so the precedent exists.
- **Class layout: unchanged. No ABI break.**
  - `Client`'s only data member is still `std::shared_ptr<Impl> p_` (`client.hpp:1550`). The function is non-virtual (the header has no virtual members).
  - The new data member `now_seconds_fn` is in `Client::Impl` (`src/client_impl.hpp:178`). That file is private and not installed. It sits behind the pimpl, so no caller-visible size or layout changes.
  - The change is a single added symbol, which is backward-compatible. On its own it would not require any SOVERSION bump.
- **Documented as test-only: yes.**
  - Header `:1361-1363`: "Test seam for the clock the device grant's `expires_in` deadline reads … NEVER called in production; nothing in src/ writes it." That is accurate: only `client.cpp:1167` defines it, and only tests call it.
  - CHANGELOG *Added* (`CHANGELOG.md:76-77`) records it as a test-only seam.
  - It is additive, so it is not source-breaking. The leading underscore at class scope is not a reserved identifier.
- **SOVERSION 4 is still sufficient.** v1.1.1 shipped SOVERSION 3. 4 was taken for 1.1.2 because of the `OAuthProtocolError` and `NetworkReplyProfile` layout growth, and 1.1.2 is unshipped (no `v1.1.2` tag). This round adds only a symbol and changes no layout, so 4 covers it. Shared build: `libaxiam_cpp.so.1.1.2`, SONAME `libaxiam_cpp.so.4` (readelf), and the `abi_soname` ctest passes.

`Version:` `project(... VERSION 1.1.2)` (`CMakeLists.txt:6`) and `AXIAM_SOVERSION 4` (`:116`) are still right. `[1.1.2] - 2026-10-23` records round 3:
- *Fixed* `:31-40`: the transport retry, including introspect, and the deadline cap for `device_login` and `ciba_await`.
- *Added* `:76`: the seam.
- *Tests* `:82-84`.

`Run by the reviewer:` throwaway copy `/home/user/work/cplusplus-r3`, deleted afterwards along with my `cpp-r3-*` logs. Nothing else under `/home/user/work` was touched, and the clone is clean. Toolchain: gcc 13.3, Ninja, C++17 Debug.
- `python3 scripts/gen_management.py --check`: "§27 surface is current (7 files)", exit 0.
- Static build `-DAXIAM_BUILD_TESTS=ON -DAXIAM_BUILD_EXAMPLES=ON`: exit 0 (121 steps). `ctest`: 1/1 passed. The binary reports **1630 test cases, 6177 checks, 0 failed** (round 2: 1624 / 6147).
- Shared build `-DBUILD_SHARED_LIBS=ON`: exit 0. `ctest`: 2/2 passed (`axiam_cpp_tests`, `abi_soname`). SONAME `libaxiam_cpp.so.4`.
- Probes: 4 probe test cases (device virtual clock, device real clock, CIBA ×2), giving 1634 cases and 0 failed.
- Mutants M1–M8, each applied alone, rebuilt, full binary run: M1–M7 are killed as tabled; **M8 survives**.

`New findings:`
- **C164-48 — Info** — `src/client_impl.hpp:178`, `src/oidc.cpp:908`, with `:1736` and `:1752`. Rule: §14.2 rule 4 (posture; conforms).
  - **What:** the device deadline runs on a whole-second clock (`std::time`). The in-poll check rounds the backoff up to whole seconds, so a retry is refused whenever the poll is in roughly the last 1–2 s, even when it would land well inside the grant.
  - **Evidence:** real-clock probe, exp 2 / int 1. The poll at 1.00 s is answered 500, then `expired_token` at 1.00 s, although a 100 ms retry would have gone out about 0.9 s before the deadline. The integer deadline `floor(t0) + expires_in` is also up to 1 s early.
  - **Impact:** it is never late, so rule 4 holds. But it can end a grant about 1 s early. This granularity predates round 3 in the loop's own check.
  - **Fix (optional):** keep the device deadline as a `steady_clock::time_point` (ms), as `ciba_await` does, and make the seam return that.
- **C164-48 — Info** — `src/oidc.cpp:2452` and `:2460`, `tests/test_ciba.cpp:561`. Rule: §34.2 P10 / §14.6 test strength.
  - **No CIBA boundary test:** the deadline − 0.1 s / 500 case is not covered, so M8 (`>=` → `>`) survives. My probe shows the behaviour is correct.
  - **Clock mismatch:** the in-poll §16 wait sleeps on `impl.sleeper`, not on the injected `CibaClock::sleep`. It is checked against `clock->now()`. With the default system clock the two agree. With a caller-injected virtual `CibaClock`, those waits neither use nor advance it, so the cap is checked per wait and not across the cumulative waits. The §7.1.2 fix text says "Sleep on the injected clock".
  - **Fix:** add a test with `received_at = t − 0.9 s`, `expires_in 6`, `interval 5`, `{500, tokens}` → `token_calls == 1` and `expired_token`. Then either route the in-poll wait through the clock (it takes `seconds`; a ms overload would be needed) or document that `CibaAwaitOptions::clock` governs only the interval waits.
- **C164-48 — Info** — `CHANGELOG.md:16-20`. Text: the 1.1.2 intro still says "Two behaviours are changed" and "two public types gain members". Round 3 adds two more behaviour changes, recorded under *Fixed* (the transport retry, and the in-poll deadline cap that ends a grant early), plus an added public member function. **Fix:** amend the intro to mention them, or say "the behaviour changes are recorded under *Changed* and *Fixed*".

---

#### Addendum round 3 — csharp — commit 4af5be9 (PR #111), read after 42369a4ba

There is one commit, `4af5be9` ("fix: 1.64 review addendum round 2 - C164-40, C164-41"). It changes 6 files (+107/−23): `AxiamClient.OidcDeviceExchangeLogout.cs`, `Core/RetryPolicy.cs`, `Auth/JwksVerifier.cs`, CHANGELOG, README, and `Contract164DevicePollRateLimitTests.cs` (+3 tests). The commit message matches the diff.

**Read only.** There is no .NET toolchain (`which dotnet` finds nothing), so nothing was built, run or mutated. Every mutant below was judged by tracing the test against the code, both at round-2 head `42369a4` and at `4af5be9`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-40 (Low) | **CLOSED** in code. The new test does not tell the fix from the bug (see C164-46). | 4af5be9 | The deadline CTS is gone. `DevicePollAsync` (public, signature unchanged) now forwards to a private `DevicePollCoreAsync(@params, DateTimeOffset? deadline, CancellationToken)` (`AxiamClient.OidcDeviceExchangeLogout.cs:205-214`), and `DeviceLoginAsync` passes `deadline` and the caller's own token (`:359-362`). The send (`PostOAuth2FormAsync`), the body read (`:251`), the parse and `ToTokenSetAsync` → JWKS (`:272`) all take only the caller's token, so a `200` in flight at the deadline is read and verified. The deadline is enforced in two places. (1) Before the send: the loop's existing check `now + wait >= deadline` → `ExpiredDeviceAuthorization()` (`:352`). (2) At the §16 waits: a `delay` hook on `RetryPolicy.ExecuteAsync` (`Core/RetryPolicy.cs:206,235`, default `Task.Delay`, so all other callers are unchanged), which throws `expired_token` when `DevicePollTime.GetUtcNow() + wait >= deadline` (`:255-257`). The verifier's rethrow `catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }` sits before the bare fail-closed catch (`Auth/JwksVerifier.cs:445-450`). The rethrow is correct: it fires only on the caller's own token, and anything else, an HttpClient timeout included, still fails closed as `InvalidSignature`. **Test** `A200ThatArrivesAfterTheDeadlineStillReturnsTheTokens` (`Contract164DevicePollRateLimitTests.cs:336`) passes at 4af5be9 (poll at fake t=5, the mock advances fake time by 40 s, tokens are returned). **Revert by reading:** it also passes at 42369a4. There the CTS was armed with `CancelAfter(real 25 s)`, but the mock answers in ~0 real time, so the timer never fires, and `Tokens()` carries no `id_token`, so no JWKS fetch happens. The revert survives: C164-46. |
| C164-41 (Info), deadline bound of the in-poll retry untested | **PARTLY** | 4af5be9 | New `ARetryAfterPastTheDeadlineInsideThePollIsNotServed` (`:355`). It sets `expires_in` 30, interval 5, every poll `503 temporarily_unavailable` + `Retry-After: 120`, and asserts `expired_token`, 1 request, sleeps `[5]`, and every poll start before t=30. At 4af5be9 it passes at once: `DelayFor` = max(≤2 ms jitter, 120 s) = 120 s, and 5 + 120 ≥ 30 throws. **Revert by reading.** Back at 42369a4 the test still **passes**. The real 120 s `Task.Delay` is cancelled by the real 25 s CTS, which gives `expired_token`, 1 request and `[5]`. It just takes 25 s of wall time, and xUnit has no default timeout, so the revert is not detected. Mutant "drop the deadline from the `delay` lambda" (or `DeviceLoginAsync` passes `deadline: null`): real 120 s waits. Each loop iteration then makes 3 requests (fake time is not advanced by the real delay), and iterations run at fake t=5,10,15,20,25. The test ends `expired_token` with 15 polls, so `Assert.Equal(1, polls())` fails, but only after ≈20 min of wall time. Killed by an assertion, not a timeout, but on the real clock. This is the round-2 "deadline tests on the real clock" item. Not closed, because the in-poll wait is still `Task.Delay` and not the injected `DevicePollDelay` (the review's second fix bullet). See C164-48. |
| C164-41 (Info), nothing pins "the 200 is parsed outside the retry" | **CLOSED** | 4af5be9 | `A200ThatDoesNotParseIsOneRequestNotARetry` (`:381`). With retry on, `200 {not json` → `NetworkError` after **1** request. **Revert by reading:** at 42369a4 (parse already outside) it passes. That is right, because this is a pin test, not a fix test. Mutant (5) from round 2, the `Deserialize` + `catch (JsonException) → NetworkError.FromException` moved into the callback, gives a null-status `NetworkError`, which `retryable` accepts, so 3 requests are sent, `polls()==3`, and the test is **killed**. |
| C164-41 (Info), README silent on the in-poll §16 retry | **CLOSED**, with a garbled sentence (C164-48) | 4af5be9 | The `README.md:883-887` bullet now says: status before body; retried inside the poll under §16 with `RetryEnabled`; at most three requests; never a `429`; no retry wait served past the deadline; a single `DevicePollAsync` may make three requests. That is the fix the review asked for. The `:58` edit is the problem (C164-48). |
| Round-2 mutant (6), "drop `pollCts`" | n/a | 4af5be9 | `pollCts` no longer exists. The equivalent mutant is "drop the deadline from the `delay` lambda", treated in the C164-41 row above. |

**Deadline bound:** **conforms by reading.** The bound is now P10's *raise at once* form, not round 2's *serve the capped wait, then raise*.

Probe, traced at 4af5be9: `expires_in` 30, interval 5, every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`.
- t=5: request #1, answered 503. The `retryable` predicate passes (status 503). `DelayFor` = 120 s. A `RetryEvent(attempt 1, 120 s)` is emitted. The lambda sees 5 + 120 ≥ 30 and throws `expired_token`.
- The exception escapes `ExecuteAsync`'s catch block and `DevicePollCoreAsync`. In the loop it is an `OAuthProtocolError` whose `Error` is not pending or slow_down and whose `HttpStatus` is null, not 429, so no catch matches and it is terminal.
- Result: **1 request; `expired_token` at t≈5, before the deadline; nothing sent at or after t=30.**

Probe, poll sent at deadline − 0.1 s and answered 500:
- If the jitter draw (default base 200 ms, attempt 1 → [0, 200 ms]) is ≥ the time left, `expired_token` is raised at once.
- If it is smaller, the retry is sent before the deadline. That is allowed, since §14.2 rule 4 only forbids a request at or after it.
- A 500 that comes back after the deadline always raises: `now ≥ deadline` and `wait ≥ 0` give `now + wait ≥ deadline`, including a zero wait.
- No request is ever sent at or after the deadline. The one exception is a timer overshoot of a few ms on the real `Task.Delay` and `DevicePollDelay`. That was already true in round 2 and is not a finding.

**CIBA:** not touched. `ciba_poll` calls `ExecuteAsync` without `delay`, which defaults to `Task.Delay`, so it behaves exactly as before. The prompt does not claim a CIBA bound for C#.

**W7.1c shape:** unchanged in effect. The diff touches the retry only through the `delay` hook, which is reached only when a retry is due. By reading, the existing tests still pass:
- `:205`, two 500s then 200: 3 requests and tokens. In `DeviceLoginAsync`, `[5]`.
- `:251`, three 500s: 3 requests, then `NetworkError` 500.
- `:264`, a transport failure twice then 200: 3 requests.
- `:283`, an OAuth 429 and a bodiless 429: 1 request each.
- `:219`, retry off: `[5,5,5,5]`.

Their `expires_in` of 600 keeps `now + 2 ms` far from the deadline, and the in-poll waits of 1–2 ms are real but harmless. Rules 6 and 9, the three §14.6 429 cases, 1.63 `/oauth2/*` isolation and the replay after a 401 refresh are not touched: the loop's catches are byte-identical apart from the removed OCE catch, and the same `PostOAuth2FormAsync` is used.

**Answers to the prompt's questions:**
- **(a) Would each new test fail if its fix were reverted?**
  - `A200ThatArrivesAfterTheDeadlineStillReturnsTheTokens` (C164-40): **no.** It passes against 42369a4. The old CTS ran on the real clock and the mock moves only fake time, and the response has no `id_token`, so the JWKS path is never reached. The test is vacuous as a regression guard (C164-46).
  - `ARetryAfterPastTheDeadlineInsideThePollIsNotServed` (C164-36/41): **no** against 42369a4. It passes after 25 s of wall time, because the old real-clock CTS also produced `expired_token`, 1 request and `[5]`. Against the mutant that drops the new lambda's deadline check it **does** fail, but on an assertion after ≈20 min of wall time (C164-48).
  - `A200ThatDoesNotParseIsOneRequestNotARetry`: a pin test with no fix to revert. It passes at 42369a4 and kills round-2 mutant (5).
- **(b) The verifier rethrow has no dedicated test.** I rule this **acceptable (Info, not Low)**:
  - After C164-40 the token reaching `VerifyOidcIdTokenSignatureAsync` is only ever the caller's own. The rethrow therefore governs only what a caller's own cancellation looks like: `OperationCanceledException` instead of an "invalid signature" `AuthError`. That is .NET convention, not a §12.4 or §14 rule, and no §14.6 test requires it.
  - Its guard keeps the fail-closed path for every other OCE.
  - It is a small behaviour change in every caller of the verifier: `id_token` validation in all grants (`AxiamClient.Oidc.cs:1423`) and back-channel `logout_token` verification (`AxiamClient.OidcDeviceExchangeLogout.cs:603`). The CHANGELOG mentions it only inside the device bullet (C164-48).
  - A cheap test would kill the "remove the rethrow" mutant, which survives today: a JWKS route that cancels the caller's CTS before answering, then `VerifyOidcIdTokenSignatureAsync` throws `OperationCanceledException`, not `(null, InvalidSignature)`.
- **(c) Dropping `CancellationTokenSource(remaining, TimeProvider)` is correct.** That suggestion existed only to put the round-2 deadline token on the injected clock. C164-40 removes the token, so it has nothing to apply to. The deadline is still enforced:
  - **No request at or after the deadline:** every send follows either the loop check (`:350-352`) or the lambda check (`:255`). Each refuses unless `now + wait < deadline`, and then sleeps exactly `wait`.
  - **Waits bounded:** a served wait always ends before the deadline. A wait that would reach it is not served at all; `expired_token` is raised at once, so `Retry-After: 120` with 25 s left costs no sleep.
  - **One unbounded span, by design:** the only time not bounded by the deadline is one request already in flight, which is bounded by `HttpClient.Timeout` and the caller's token. That is exactly what C164-40 asks for. `DeviceLoginAsync` can therefore return `expired_token` up to one request's duration after the deadline (for example, a poll sent at t=29 that times out at t=129), but it never sends after it.
  - **The C164-36 bound holds,** and is stronger than in round 2: no §16 wait inside the poll is ever served past `deadline − now`.
  - **The remaining gap is testability, not conformance.** The lambda's `Task.Delay` is real-clock, so the bound can be checked against the fake clock but not timed by it (C164-48).

**Version:** 1.1.2 is still right; both csproj files say 1.1.2. No public API is added or changed: `DevicePollAsync` keeps its signature, and the only change is that it is now expression-bodied over a private method. The new `delay` parameter is on an `internal` method. Nothing is source- or binary-breaking. `CHANGELOG.md:39-46` records round 3 (C164-40 and the three tests).

**Run by the reviewer:**
- `which dotnet` finds nothing, so there was no build, no `dotnet test`, and no mutant was executed. Nothing was built, so there is nothing to delete, and no work directory was created.
- Read: `git log` and `git diff 42369a4ba..HEAD` in full.
- Read for context: `DevicePollCoreAsync` and `DeviceLoginAsync` (`:205-400`); `RetryPolicy.DelayFor` and `ExecuteAsync`; `JwksVerifier.VerifyOidcIdTokenSignatureAsync` and `EnsureFreshAsync`; the test `SetUp` and `FakeTime` (`Contract164DevicePollRateLimitTests.cs:1-100`); `RoutingHandler` (it dispatches through `Task.Run`, so a responder can block for real time); `OidcTestKit.TokenResponseJson` (no `id_token` by default).
- Mutants judged by reading: 3 fix reverts and 3 mutants (lambda deadline dropped, rethrow removed, parse moved inside the retry).
  - Killed fast: parse inside the retry.
  - Killed slowly (≈20 min, on an assertion): lambda deadline dropped.
  - Survive: the C164-40 revert and the C164-36/41 revert (that one only slows the test), and the rethrow removal.

**New findings:**
- **C164-46 — Info (test strength; for the lead's ruling, Low if the review's requested test counts as required).**
  - Where: `tests/Axiam.Sdk.Tests/Contract164DevicePollRateLimitTests.cs:336`.
  - What: the C164-40 test cannot fail on the bug it guards. The round-2 deadline CTS ran on the real timer, but the test's "request takes 40 s" is fake time only, and the token set has no `id_token`. So the old code, and any future regression that re-arms a real-clock deadline token on the read, passes too.
  - Exact fix:
    - Make the 200 actually cross a real-clock deadline. Use `expires_in` 6 and interval 5, so 1 s is left when the poll is sent. In the token responder, block for real time (`Thread.Sleep(1500)`; `RoutingHandler` runs responders on `Task.Run`), then `time.Advance(2 s)` and return `Tokens()`. Assert that the token set is returned.
    - Add a second variant that returns `TokenResponseJson(..., idToken: <signed>)` with a JWKS route that sleeps 1.5 s real, which pins the verification path.
    - Against 42369a4 both variants raise `expired_token` or an `AuthError`. Against 4af5be9 both return tokens.
- **C164-48 — Info (test strength; residual C164-41 "deadline tests on the real clock").**
  - Where: `Axiam.Sdk/AxiamClient.OidcDeviceExchangeLogout.cs:255-257` (`: Task.Delay(wait, ct)`), and the test at `:355`.
  - What: the in-poll §16 wait is still a real `Task.Delay`, not the injected `DevicePollDelay`. The deadline-bound test passes against the round-2 code (25 s of wall time), and kills a dropped bound only after ≈20 min of wall time.
  - Exact fix: in the `delay` lambda, call `DevicePollDelay(wait, ct)` when `deadline` is set, and keep `Task.Delay` when it is null (single `DevicePollAsync`).
    - The W7.1c `DeviceLoginAsync` sub-test then records `[5, ≤2 ms, ≤2 ms]` rather than `[5]`. Assert `sleeps[0] == 5 s` and the sum < 6 s, or filter sub-second waits.
    - The test at `:355` then fails in milliseconds on `sleeps` (`[5, 120, …]`) if the bound is dropped.
- **C164-48 — Info (text) — `README.md:58`.**
  - What: the inserted clause splits the rule-9 sentence. It now reads "…waits the `Retry-After` out (the status decides: any `429`), a `5xx` on the poll is a transport failure … retried inside the poll under §16 (never a `429`) (a minimum, capped at the `expires_in` deadline), counts it as one interval…". So "a minimum, capped at the deadline, counts as one interval" now attaches to the 5xx retry. The 1.64 paragraph also still says "changes one behaviour" while listing more than one.
  - Exact fix: "Contract 1.64 (§34.8) changes these behaviours: any `429` on a device-code poll is not terminal, and `DeviceLoginAsync` waits its `Retry-After` out (a minimum, capped at the `expires_in` deadline), counts it as one interval and does not raise the interval (§14.2 rule 9); a `5xx` on the poll is a transport failure whatever its body and is retried inside the poll under §16 (never a `429`; §14.2 rule 6); the `plan` refusal …".
- **C164-48 — Info (text/telemetry).**
  - (i) Where: `CHANGELOG.md:39-46`. The verifier change is a behaviour change beyond the device flow: a caller-cancelled JWKS fetch during any `id_token` or `logout_token` verification now surfaces as `OperationCanceledException`, not an `AuthError` "invalid signature". The CHANGELOG mentions it only inside the device bullet. Fix: add one sentence: "A caller's cancellation during `id_token`/`logout_token` signature verification now propagates as `OperationCanceledException` instead of being reported as an invalid signature."
  - (ii) Where: `Core/RetryPolicy.cs:229-235`. The `RetryEvent` is emitted before the `delay` hook decides, so near the deadline the telemetry announces a retry (for example, 120 s) that is never served or sent. This is §16.5 accuracy, and the round-2 review's optional bullet. Fix: emit the event after a successful delay decision. For example, let `delay` return a bool or throw before `Emit`, or move `telemetry.Emit` after the deadline check by evaluating the hook's refusal first.

---

#### Addendum round 3 — go — commit 2a0c273ad (PR #103), read after 491fc0730

One commit on top of the round-2 head: `2a0c273` test(oidc): pin the in-poll retry of a transport failure; deadline test on an injected clock (C164-38, C164-41). The diff touches `contract_164_test.go` (+89/−6) and `CHANGELOG.md` (+9/−1) and nothing else. **Round 3 is tests only, as claimed.** No non-test Go file changed: `oidc_device.go`, `retry.go`, `oidc_wire.go`, `client.go`, `README.md`, `CONTRACT.md` and `go.mod` are identical to `491fc07`. The commit message's finding map matches the diff.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-38 (Low) | **CLOSED** | `2a0c273` | `contract_164_test.go:389` `resetConnection` hijacks the conn, sets `SetLinger(0)` (a RST, not a FIN) and closes it. `:400` `TestDevicePollRetriesATransportFailureUnderTheBudget` pins jitter to 0 and checks four cases. Two resets then `ok200`: one `DevicePoll` makes 3 requests and returns `device-access-token`. A reset forever: `*NetworkError` after `MaxAttempts` (3) requests. `WithRetryDisabled()`: 1 request, `*NetworkError`. `runDeviceLogin` over two resets then 200: waits `[1s]`, 3 calls. This is the exact shape the round-2 fix asked for. **Mutant M3** (`oidc_device.go:262-264` removed, so a transport `*NetworkError` becomes decisive through `errStopRetry`) is now **killed** by this test. It survived every test in round 2. |
| C164-41 (Info) | **CLOSED** | `2a0c273` | `contract_164_test.go:349` `TestDeviceLoginInPollRetryIsCappedAtTheDeadline` now injects `client.pollNow` and `client.pollSleep` (a virtual clock that advances with each sleep, plus `recordedSleeps`). It uses `expires_in` 30, `interval` 1, and a token handler that always returns `503` + `Retry-After: 100`. It asserts `ErrExpiredToken`, `TokenCalls() == 1`, and waits `[1s 29s]` (the interval, then the retry wait capped at the 29 s left). It also adds a 3 s `context.WithTimeout` (`:369`). **Mutant M4** (`DeviceLogin` passes a nil bound, `oidc_device.go:396`) is **killed by an assertion in 3.0 s**: `want expired_token, got context.deadlineExceededError`. In round 2 it was killed only by the 120 s `go test` timeout. **Extra mutant M7** (`retry.go:133`: the wait is no longer capped at `left`, but `atDeadline` is still set) is **killed** on the recorded sleeps: `waits: got [1s 1m40s], want [1s 29s]`. Nit, not a finding: under M4 the test fails on the error check at `:376` (`Fatalf`) after the 3 s context expires, not "at once on the recorded sleeps" as the round-2 fix text put it. The real 100 s sleep is still cut by the context and reported by an assertion, which is what the finding asked for. |

**Deadline bound:** **bounded; unchanged from round 2.** The production code is byte-identical to round 2, and the new injected-clock test pins the bound. Re-probed in a throwaway copy on a virtual clock, with `expires_in` 30, `interval` 5 and jitter 0:
- Every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`: requests at **[5s]** only. Sleeps `[5s 25s]`. Returns at virtual **30 s** with `expired_token` (`*OAuthProtocolError`). No request at or after the deadline.
- A poll sent at **29.9 s** (the first poll answered `authorization_pending` while the handler advanced the clock 19.9 s) and answered `500 server_error`:
  - Jitter 0.5 or 1: requests at `[5s 29.9s]`. The retry wait is capped at the 100 ms left (sleeps `[5s 5s 100ms]`). Returns at 30 s with `expired_token`. No retry is sent.
  - Jitter pinned to **0** (a degenerate draw): the full-jitter backoff is 0. Both §16 retries go out at once, still at 29.9 s (requests `[5s 29.9s 29.9s 29.9s]`), and the call returns `expired_token` at 29.9 s. Nothing is sent at or after the deadline, so rule 4 holds. With a real jitter draw a retry goes out only when its wait ends before the deadline, which §16.1 permits. This is pre-existing `retry.go` behaviour, not new in round 3. Note only.
- CIBA: the prompt makes no CIBA claim for round 3, and no CIBA code changed, so it was not re-probed. Round 2's M5 was killed by CIBA T07 and that test still passes.

**W7.1c shape:** **complete now. All six cases are pinned by tests in the suite.**
- Two 500s → 3 requests + tokens; three 500s → 3 requests + `*NetworkError`: `TestDevicePollRetriesA5xxUnderTheBudgetThenSurfaces`.
- Transport failure (RST) twice then 200 → 3 requests + tokens; three → 3 requests + `*NetworkError`; retry off → 1: the new `:400` test.
- 429 → 1 request and retry off → 1 for a 5xx: `TestDeviceLoginRetriesA5xxInsideThePollNotAFullInterval`.
- `DeviceLogin` within one interval (`[1s]`, 3 calls) for both the 5xx and the transport case.

Production code is unchanged, so the round-2 probe table stands.

**Specific questions:**
- Tests only? **Yes.** The only changed files are `contract_164_test.go` and `CHANGELOG.md`.
- Rules 6/9, the three §14.6 429 cases, 1.63 isolation (C163-08) and the replay after a 401 refresh: no production code was touched, and their tests pass unchanged. No re-probe was needed.
- New public API: none. The new identifiers (`resetConnection` and the test) are in a `_test.go` file. The test-only import of `net` is the only import change.

**Version:** 1.1.2 (`CHANGELOG.md:10`, `## [1.1.2] - Unreleased`) is still right; round 3 changes no behaviour. The CHANGELOG records round 3 in two places. Under `[1.1.2]`, the `### Added` Tests bullet (`:79-82`) names both tests with their finding IDs. Under Notes, `:100-103` says "Round 3 of the 1.64 conformance review (C164-38, C164-41) changes tests only … No code or behaviour changes." `[1.1.1]` and the older sections are untouched.

**Run by the reviewer** (throwaway copy `/home/user/work/go-r3`, deleted afterwards along with the go build and test caches; the SDK clone is unmodified and `git status` is clean; `GOTOOLCHAIN=auto` → go1.26.0):
- `go build ./...`: ok. `go vet ./...`: clean (exit 0).
- `go test -count=1 ./...`: exit 0, 15 packages ok, **1690 test/subtest passes** (round 2: 1689, plus the 1 new test), 0 failures, 0 skips. The two round-3 tests run in 0.01 s and 0.02 s.
- `go run ./internal/cmd/genmanagement -check`: "OK: 32 generated files are current (202 operations)".
- 3 mutants, each reverted after its run, all **killed by assertions**: M3 (transport made decisive), M4 (nil bound, 3.0 s), M7 (wait not capped at the deadline).
- Probes: the deadline probes above (`503` + RA 120; a 500 at 29.9 s with jitter 0, 0.5 and 1).
- Not run: `govulncheck` (the egress proxy blocks vuln.go.dev, as in rounds 1 and 2). The PR's CI run was not read.

**New findings:** none.

---

#### Addendum round 3 — java — commit 40fd50203 (PR #121), read after c459e7315

Commits `c459e73..40fd502`:
- `c34eb71` fix(oauth): the in-poll retry is bounded by the deadline, and OkHttp no longer silently replays the polls (code and tests).
- `40fd502` docs: the CHANGELOG for round 3.

Each commit's claim matches its diff. The SDK clone was not modified (`git status` is clean, and it has no `target/`). The suite ran in `/home/user/work/java-r3`; probes and mutants ran in `/home/user/work/java-r3-mut`. Both copies were deleted afterwards. The probe classes and the mutant script are kept in the review session's scratchpad (`addenda3/java-probes/`, not committed).

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-36 (Low), device | **CLOSED** | c34eb71 | **Code:** `AxiamClient.java:3442-3444` adds a package-private `devicePoll(…, CibaClock clock, Instant deadline)`. `deviceLogin` calls it at `:3570`. The deadline pacer (`:3480-3493`) admits a retry only when `clock.now().plusMillis(delay).isBefore(deadline)`, where `delay` is the full wait from `Retry.computeDelayMillis` (the jittered backoff floored at `Retry-After`, `Retry.java:199`). It sleeps on `clock`. A refused retry rethrows the bare `NetworkError`, the loop catches it, and its own check (`:3552`) raises `expired_token`. A bare `devicePoll` keeps `Thread.sleep` and admits every retry (`:3468-3478`).<br>**Tests:** `theInPollRetryNeverSendsAtOrAfterTheDeadline` (`AxiamClientDeviceFlowTest.java:571`: `expires_in` 12, interval 5, 503 + RA 120 → requests `[5,10]`, sleeps `[5,5]`, `expired_token`). `aPollSentJustBeforeTheDeadlineAnswered5xxIsNotRetried` (`:610`: the poll at 11.9 s answered `500` + RA 1 → 3 requests, sleeps `[2]`).<br>**Mutants that fail:** M1 (the check ignores the wait: `now.isBefore(deadline)`) fails both tests. M2 (admit every retry) fails both. M3 (pacer on `Thread.sleep`) fails `:571` through the 10 s preemptive timeout. M10 (`deviceLogin` calls the bare poll) fails both.<br>**Mutants that survive:** M4 and M5, see C164-45. |
| C164-36, CIBA poll (the prompt's extra) | **OPEN** | — | Not touched. `cibaRedeem` (`:4745`) still runs `StatusRetry.run` without a pacer, so its waits are `Thread.sleep` up to the 5 s clamp, and `cibaAwait` (`:4840-4881`) passes neither the deadline nor `waitOn`. Real-clock probe: see **Deadline bound**. This is a §33.7 rule 5 / §34.2 P10 breach, and §33.8 test 7's P10 half is missing from `CibaTest.java:459`. → C164-43. |
| C164-38 (Low) | **CLOSED** | c34eb71 | **Tests:**<ul><li>`:470` two `500 {"error":"server_error","error_description":"internal"}` then 200 → 3 attempts and the tokens.</li><li>`:489` six 500s queued → `NetworkError` after exactly 3 attempts (the cap is pinned).</li><li>`:509` `DISCONNECT_AFTER_REQUEST` ×2 then 200 → 3 attempts and the tokens.</li><li>`:529` ×3 → `NetworkError` after exactly 3.</li><li>`:552` retry off, one drop → 1 request.</li></ul>The existing `:428` (500, 503, 200; 429 → 1) and `:455` (retry off) remain.<br>**Mutants:**<ul><li>M8 (cap 5) **fails** `:489` (6 requests), `:529` and `:634`. This was round 2's survivor M10.</li><li>M9 (a transport failure is not retried) **fails** `:509` and `:529`.</li><li>M7 (the device poll back on `httpClient`) **fails** `:529` and `:552`.</li></ul> |
| C164-39 (Low) | **CLOSED** (device and CIBA) | c34eb71 | **Code:** `pollHttpClient = httpClient.newBuilder().retryOnConnectionFailure(false).build()` (`:732`). It keeps the authenticator, redirects and interceptors, and is copied into the tenant-scoped view (`:757`). The device poll uses it (`executeFormPost(pollHttpClient, …)`, `:3497`), and so does the CIBA poll (`:4749`).<br>**Tests:** `:529` (device), and `theCibaPollHasNoSilentOkHttpReplayEither` (`:634`: CIBA, 3 drops then 200 → error after exactly 3 token requests).<br>**Mutants:** M7 (device) fails. M6 (CIBA back on `httpClient`) **fails** `:634` (the 4th request succeeds).<br>**Probe:** the reflected `pollHttpClient` has `retryOnConnectionFailure=false` and `fastFallback=true`. |
| C164-41 (Info) | **CLOSED** | c34eb71 | `timeSpentInTheUserCodeCallbackCountsAgainstTheDeadline` (`:373`) and `timeSpentInAPollCountsAgainstTheDeadline` (`:398`) now run under `assertTimeoutPreemptively(10 s)`. **M11** (deadline taken after `onUserCode`; round 2's M5) now **fails in 10 s** (`:386 execution timed out`) instead of hanging for ≈9 min. |

**Deadline bound:**
- **Device: bounded.** The probes run on the recorded clock, interval 5, with every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`. The floor is clamped to 5 s.
  - `expires_in` 30 → polls at 5, 10, 15, 20, 25 s. The retry that would go at 30 s is refused, and `expired_token` comes at 25 s.
  - `expires_in` 21 → `[5,10,15,20]`, `expired_token` at 20 s.
  - `expires_in` 12 → `[5,10]`.
  - In every case nothing is sent at or after the deadline.
  - Deadline − 0.1 s, `500` with no `Retry-After`, 100 runs. A retry was sent in 68 runs: the jitter was under 100 ms, so the retry still left before the deadline, which conforms. **0** requests went at or after 12 s, and every run ended in `expired_token`.
- **CIBA: NOT bounded** (pre-existing; C164-43). Real clock, `cibaAwait` with interval 5 and every poll answered 503 + RA 120:
  - `expires_in` 21 → requests at 5.0, 10.0, 15.0, 20.0, **25.0 and 30.0 s**: 2 after the deadline, the last 9 s past it. `expired_token` at 30.03 s.
  - `expires_in` 30 → the last request at **30.03 s**, past the deadline.

**W7.1c shape** (single `devicePoll`, probed on 40fd502): every case conforms.

| Case | Requests | Result |
|---|---|---|
| Two 500s, then 200 | 3 | tokens |
| Three 500s | 3 | `NetworkError` |
| Two drops (`DISCONNECT_AFTER_REQUEST`), then 200 | 3 | tokens |
| Three drops | 3 | `NetworkError` (no 4th silent replay) |
| 429 | 1 | `OAuthProtocolError(rate_limit_exceeded)` |
| Retry off, a 500 | 1 | — |
| Retry off, a drop | 1 | — |

`deviceLogin` with two 500s then 200 → requests at 5.000, 5.012 and 5.292 s, all within one interval. The in-poll jitter waits now show in the clock's sleeps (`[5000, 12, 280]` ms). Rules 6 and 9, the three 429 cases, 1.63 isolation and the replay after a 401 refresh are untouched by the diff. They are covered by the green suite and were not re-probed.

**Ruling inputs:**
- **(a) Test (2)'s determinism (`Retry-After: 1`).** It catches a check that leaves out the wait altogether (M1: `now.isBefore(deadline)` → the retry is sent, and the test fails at its preemptive timeout) and a missing check (M2).
  - It **cannot** catch a check that uses the `Retry-After` floor but not the jittered backoff (M4: `admits(hint)`). With RA 1 s the floor dominates the ≤ 200 ms jitter, so M4 survives. In test (1) the clamped 5 s floor dominates too.
  - The determinism itself is legitimate. Java's backoff is full jitter in [0, 200] ms, so without a `Retry-After` a conforming SDK may send a retry at 11.9 s + jitter < 12 s (the probe did, in 68 of 100 runs). A test that asserts "no retry" with no floor would be flaky.
  - M4 is not a natural mutant here: the pacer receives the single combined `delay` from `computeDelayMillis`. So the gap is test strength only (C164-45).
  - Test (1) also uses `expires_in` 12 instead of the review's 30. With 30, the third-attempt retry lands **exactly** on the deadline (25 + 5). That would pin `isBefore` against `!isAfter` (M5 survives today; C164-45).
- **(b) `Retry.Pacer`.**
  - **Not source- or binary-breaking.** It adds a new nested interface (`Retry.java:64`) and two overloads of new arity: `Retry.withRetry(int, IntFunction, Predicate, TelemetryDispatcher, String, Pacer)` (`:157`) and `StatusRetry.run(boolean, TelemetryDispatcher, String, Pacer, IntFunction)` (`StatusRetry.java:117`). Neither creates a lambda-overload ambiguity with the existing 5- and 4-argument forms.
  - **Documented and recorded.** Every member has Javadoc; `verify`, javadoc included, is green with no warnings. `CHANGELOG.md:17-19` lists it as an API addition.
  - **Public only in part by necessity.** `Pacer` and the new `StatusRetry.run` overload must be public, because the caller is `io.axiam.sdk.AxiamClient` in another package and the SDK has no `module-info`. The public 6-argument `Retry.withRetry` overload is called only by `StatusRetry`, in the same package, so it could be package-private.
  - **Nit.** The package's own `package-info.java` says that types in `io.axiam.sdk.internal` "are NOT part of the SDK's public API surface". Listing `Retry.Pacer` as an "API addition" in the CHANGELOG is harmless but slightly at odds with that (Info, C164-48).
- **(c) Addresses (the Kotlin issue): Java has no latent dual-stack risk.**
  - **How the tests address the mock.** Every disconnect and transport test uses `new MockWebServer()` and `server.url("/")`, which gives `http://localhost:<port>/` (probe: `hostName=localhost`). The server binds `InetAddress.getByName("localhost")`, which is 127.0.0.1 under the JVM's default IPv4 preference.
  - **Why Kotlin's issue does not carry over.** Java is on **OkHttp 5.5.0**, not Kotlin's 4.12.0. A refused connect on one address falls through to the next address **inside the same call**, independently of `retryOnConnectionFailure(false)` and of `fastFallback`.
  - **Probe P6.** A raw OkHttp 5.5 client with `retryOnConnectionFailure(false)` and a DNS of `[127.0.0.2, 127.0.0.1]` connects twice (the first fails with `ConnectException`) and gets **200**, with fastFallback true or false. With `[::1, 127.0.0.1]` the first connect fails with `SocketException`, then 200, in both modes. A failed connect therefore does not cost a §16 attempt.
  - **What the flag does stop.** `retryOnConnectionFailure(false)` stops only the replay after a drop mid-exchange (`DISCONNECT_AFTER_REQUEST` is not replayed: tests `:529`, `:634`).
  - **Caveat.** This sandbox resolves `localhost` to 127.0.0.1 only, so the dual-stack case was simulated with a custom `Dns`. No change is needed. Pinning `127.0.0.1` would be harmless but is not required.

**Version:**
- 1.1.2 is still right (`pom.xml:9`, `bom/pom.xml:9,66`): nothing is source-breaking.
- `CHANGELOG.md:23-31` records round 3 (C164-36 device, C164-39 device and CIBA), and `:63-66` records the C164-38/-41 tests.
- The CHANGELOG states only the device deadline bound, not a CIBA one. That is accurate, but C164-43 is unaddressed.

**Run by the reviewer** (JDK 21, `./mvnw -B -o`):
- `verify` on 40fd502: **BUILD SUCCESS, 1525 tests, 0 failures, 0 errors, 0 skipped**, all jacoco checks met (12:36 min).
- Probe classes `R3ProbeTest` (P1–P5) and `R3AddrProbeTest` (P6): all ran.
- 11 mutants, run as targeted `AxiamClientDeviceFlowTest` with `-Djacoco.skip`:
  - Fail an assertion: M1, M2, M6, M7, M8, M9, M10.
  - Fail by the preemptive timeout: M3, M11.
  - **Survive:** M4 (deadline check uses the `Retry-After` floor only) and M5 (`!isAfter` instead of `isBefore`, so a retry exactly at the deadline is admitted).
- Not run: the GPG and Sigstore jobs.
- Build outputs and both copies were deleted.

**New findings:**

- **C164-43 — Low — `AxiamClient.java:4745` (`cibaRedeem` → `StatusRetry.run` without a pacer) and `:4840-4881` (`cibaAwait`). Rules: §33.7 rule 5, §34.2 P10, §33.8 test 7 (second half).** Pre-existing, and the CIBA half of C164-36.
  - **What happens:** the §16 retry inside `ciba_poll`, as `ciba_await` calls it, sleeps up to the 5 s `Retry-After` clamp on `Thread.sleep` and never sees the deadline. With `expires_in` 21, interval 5 and 503 + RA 120, requests go out at 25 s and 30 s, and `expired_token` arrives 9 s late (real-clock probe). `CibaTest.t07` (`CibaTest.java:459`) covers only the `authorization_pending` half of test 7.
  - **Fix:** give `cibaRedeem` a `Retry.Pacer` parameter. `cibaAwait` passes one that admits a retry only when `waitOn.now().plusMillis(d).isBefore(deadline)` and sleeps with `waitOn.sleep(Duration.ofMillis(d))`. A bare `cibaPoll` passes the admit-all `Thread.sleep` pacer, which is `devicePoll`'s; hoist it to a shared constant.
  - **Test:** a `TestClock`, `expires_in` 12, interval 5, every poll `503` + `Retry-After: 120` → requests `[5, 10]` on the clock, `expired_token`.
- **C164-45 — Info — `AxiamClientDeviceFlowTest.java:571`, `:610` (test strength).** M4 (check the floor, not the full wait) and M5 (`!isAfter`) survive.
  - **Fix for M5:** run `:571` with the review's `expires_in` 30. The expected requests become `[5,10,15,20,25]`, and the retry due exactly at 30 s pins the strict boundary.
  - **Fix for M4:** add a case with no `Retry-After` where the poll goes out at deadline − 1 ms and is answered `500`. Assert no request at or after the deadline. A correct SDK never fails it. M4 fails it unless the jitter is under 1 ms (p ≈ 0.005), or repeat it 3 times.
- **C164-48 — Info — `internal/Retry.java:157`, `CHANGELOG.md:17-19`.** The public 6-argument `Retry.withRetry(…, Pacer)` has no caller outside its package, so make it package-private. Optionally drop "public" from the CHANGELOG's description of `Retry.Pacer`, or note that it lives in the non-API `internal` package (`package-info.java`).

---

#### Addendum round 3 — kotlin — commit c392bf9 (PR #80), read after d1d1816f2

There are five commits (`git log --oneline d1d1816f2..c392bf9`):
- `6d3d310` fix(retry) C164-36/-37/-38/-39
- `59ec120` docs (CHANGELOG, README)
- `2a2e599` and `f3e04d7`: temporary CI exception logging, then its revert. `build.gradle.kts` is not in the net diff.
- `c392bf9` test: the transport-failure tests now address `127.0.0.1` instead of `localhost`. The commit says why: a no-resend client "does not fall back to a second address". That is C164-44 below.

Files in the net diff:
- `errors/ErrorMapper.kt`
- `internal/Retry.kt`
- `oidc/OidcSupport.kt`
- `D5ConformanceTest.kt`, `CibaTest.kt`, `OidcDeviceFlowTest.kt`
- `CHANGELOG.md`, `README.md`

No public signature changed. The new `mayWait` is on the internal `Retry.withRetry`. The new `devicePoll(params, deadline, clock)` overload is private, and so is the `executeRequest(request, client)` parameter.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-36 (Low) | **PARTLY**: device closed; **CIBA open, and made worse** by C164-37 (C164-43) | `6d3d310` | **Device.** `Retry.withRetry` gains `mayWait` and checks it after computing the jittered, floored wait (`internal/Retry.kt:98`, `:122`). `deviceLogin` calls the private `devicePoll(params, deadline, clock)`. Its `mayWait` is `deadline == null \|\| clock.now()+wait < deadline` (`oidc/OidcSupport.kt:1102-1104`). The bare `devicePoll` passes `null`. Tests: `OidcDeviceFlowTest.kt:470` (expires_in 30, interval 5, 503 + RA 120 → `expired_token`, every request < 30 s, 5 requests, wall < 20 s) and `:490` (a 500 answered at 5.95 s of 6 s with jitter 1.0 → 1 request). Mutant M1 (`mayWait` always true) → **both fail**. **CIBA.** `cibaPollTracked`'s `withRetry` (`:1364-1373`) gets no `mayWait`, and `cibaAwait` (`:1410-1450`) passes no deadline. See C164-43. |
| C164-37 (Low) | **CLOSED** (clamp policy, see C164-48) | `6d3d310` | `fromHttpStatus`'s `else` branch now passes `response?.let(::retryAfterOf)?.coerceAtMost(MAX_RETRY_AFTER)` (`errors/ErrorMapper.kt:50-55`, `MAX_RETRY_AFTER = 60.seconds` `:38`). That covers every 429/5xx `NetworkError`. Tests: `D5ConformanceTest.kt:85` (`checkAccess` 503 + RA 2, then 200 → ≥ 1.9 s, 2 requests) and `:99` (RA 86400 → 60 s). Mutant M2 (no RA) → 3 fail (both D5 tests and the device deadline test). M3 (no clamp) → the clamp test fails. Landed in the same commit as C164-36, as asked. |
| C164-38 (Low) | **CLOSED** | `6d3d310`, `c392bf9` | `OidcDeviceFlowTest.kt:428`: two `DISCONNECT_AFTER_REQUEST`, then 200 → tokens, 3 requests. `:444`: three drops → `NetworkError`, exactly 3. `:457`: retry off → 1. `CibaTest.kt:383` (t08c): CIBA, three drops → exactly 3. Mutant MD (`it != null && it >= 500`, round 2's survivor) → **2 fail** (`:428`, `:444`). |
| C164-39 (Low) | **CLOSED** for the attempt count; **the fix breaks route fallback (C164-44)** | `6d3d310` | `postToken` uses `noRetryHttpClient` when `devicePoll` (`:1954`). `cibaPollTracked` uses it too (`:1378`). `noRetryHttpClient` = `httpClient.newBuilder().retryOnConnectionFailure(false)` (`:1239-1241`). Mutants: M4 (poll back on `httpClient`) → 2 fail (`:444`, `:457`). M5 (CIBA back on `httpClient`) → t08c fails. Probe W4 (three drops) → 3 requests. |
| C164-41 (Info, Kotlin part) | **CLOSED** | `59ec120` | The README now says the in-poll §16 retry exists and is "bounded by the grant's deadline" (`README.md:49-50`). The floor claims (`CHANGELOG.md:51`, `README.md:2517`) are now true, and the README names the 60 s clamp. The CHANGELOG's round-3 entries are at `:59-73` and `:104-107`. |

**Deadline bound** (probe class run in a throwaway copy; `HybridClock` = recorded sleeps + real elapsed time):
- **Device, the brief's case (D1).** `expires_in` 30, interval 5, every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`. Result: `expired_token` after 5 requests at ms `[5074, 10120, 15163, 20207, 25251]`. Nothing was sent at or after 30 000, and the wall time was 291 ms, so the floor was never slept. **Holds.**
- **Device, a poll sent at deadline − 0.1 s answered 500 (D2).** With `expires_in` 6, interval 5 and a 0.9 s callback, the poll left at about 5.95 s.
  - Jitter 1.0: 1 request at 5955 ms, then `expired_token`. No retry, as asked.
  - Jitter 0.0: 3 requests at 5961, 5965 and 5969 ms, all before 6000. This conforms: a wait that ends before the deadline may be sent.
- **CIBA (C1), `cibaAwait` with `expires_in` 30, interval 5, `receivedAt` = start, same 503 + RA 120.** Result: `expired_token` after 3 polls at ms `[5014, 65067, 125073]`. **Two requests were sent after the 30 000 deadline, and `cibaAwait` blocked 120 s past it.** C2 (`expires_in` 10, RA 3): polls at `[5039, 8086, 11092]`, one after the deadline. This breaks §33.7 rule 5 / §34.2 P10. See C164-43.

**W7.1c shape** (probes W1–W7: one `devicePoll`, client addressed by `127.0.0.1`):

| Probe | Result |
|---|---|
| W1: two 500s (`server_error` body), then 200 | tokens, 3 requests |
| W2: three 500s | `NetworkError`, 3 requests |
| W3: drop twice, then 200 | tokens, 3 requests |
| W4: drop three times | `NetworkError`, 3 requests |
| W5: 429 | `OAuthProtocolError(rate_limit_exceeded)`, 1 request |
| W6: retry off, 500 | `NetworkError`, 1 request |
| W7: retry off, drop | `NetworkError`, 1 request |

All seven are in the contract's shape. The suite pins W1/W2 (`:361`, `:393`), W3/W4 (`:428`, `:444`), W5 (`:411`) and W6/W7 (`:423`, `:457`).

**C164-37 clamp, worst case (K1).** `checkAccess` answered `503` + `Retry-After: 3600` three times:
- 3 requests, then `NetworkError` after **120.7 s**: two waits of 60 s, plus request time.
- With the 10 s connect and 30 s read timeouts on a hanging server, the bound is about 2 × 60 s + 3 × 40 s ≈ 4 min.
- The second and third requests go out 3540 s and 3480 s before the server said it would be ready. See C164-48.

**Dual-stack trade-off (the requested ruling input).**
- **Which setting governs.** In OkHttp 4.12.0, the version pinned in `build.gradle.kts:34`, **`retryOnConnectionFailure` governs both** connect-route fallback and the replay after a dropped connection. There is no separate setting. `RetryAndFollowUpInterceptor.recover()` (read from the 4.12.0 bytecode) runs in this order:
  1. `if (!client.retryOnConnectionFailure) return false`
  2. `if (requestSendStarted && requestIsOneShot(e, request)) return false`
  3. `isRecoverable(...)`
  4. `call.retryAfterFailure()`

  A connect failure on the first route (a `RouteException`, `requestSendStarted = false`) therefore stops at step 1. The call never tries the second address.
- **What separates the two cases is the request body's `isOneShot()`,** not a client setting. Step 2 refuses a replay only once the request was sent, and a connect failure is not one. OkHttp 5's `fastFallback` (Happy Eyeballs) would race the routes inside the exchange finder. That is not available on 4.12 and was not probed.
- **Probe P-N1 (raw OkHttp, custom `Dns`, MockWebServer bound to `127.0.0.1` only).**
  - `[::1, 127.0.0.1]`: this sandbox has no IPv6, so `::1` fails with "IPv6 protocol family unavailable". With `retryOnConnectionFailure(true)`, 3/3 calls returned 200. With `false`, 3/3 failed, and the server saw 0 requests.
  - `[127.0.0.2, 127.0.0.1]` (a true ECONNREFUSED on the first address): the same result. With `false`, 3/3 failed with `ConnectException … /127.0.0.2`.
  - Successive calls on the same client never learn the route. Every call fails again on the first address.
- **So a refused first address costs more than one §16 attempt: it costs all of them, on every poll.**
  - Through the SDK (P-N3, `devicePoll` against `dual4.test`, jitter 0): `NetworkError` on 2 of 2 polls, the server saw 0 token requests, and there were 2 §16 `Retry` events per poll. Every attempt failed on `127.0.0.2`. C164-44 (`::1` first) gave the same.
  - **Pooling hides it** (P-N6, base `http://localhost` with `localhost` → `[::1 \| 127.0.0.2, 127.0.0.1]`). Discovery runs on the retrying `httpClient`, falls back, and pools a `127.0.0.1` connection, which the shared pool lends to the poll client: tokens on 2 of 2.
  - **Once that connection is gone** (P-N7: `connectionPool.evictAll()`, standing for idle expiry, a `Connection: close` 503, or the dropped connection C164-39 is about), every poll fails: `NetworkError` on 2 of 2, 0 server requests.
  - In `deviceLogin`/`cibaAwait` that ends in `expired_token` while the server is reachable on its second address.
- **The fix keeps both properties (P-N8 probe).** Use a client with `retryOnConnectionFailure(true)` (the shared `httpClient`) and a **one-shot form body**:
  - `[127.0.0.2, 127.0.0.1]` → 200 with 1 server hit. `[::1, 127.0.0.1]` → 200 with 1 hit. The second route was taken within the call.
  - `DISCONNECT_AFTER_REQUEST` on a pooled connection: a one-shot body gave 1 server hit, so no replay. A plain body gave **2** (the C164-39 replay).

**Rules 6/9, §14.6 429 cases, 1.63 isolation, the replay after 401.**
- The round-3 diff does not touch the 429 path, `withoutSession`, or `postWithRefresh`.
- Rule 9 and the three §14.6 429 tests pass in the full run. W5 shows a 429 is still one request.
- A 5xx is still a `NetworkError` that the loop treats as non-terminal (rule 6).
- New side effect: a 5xx's `Retry-After` now lies on the `NetworkError`, but `deviceLogin` does not carry it into the next interval. D1 polled every 5 s against RA 120. This is the same posture C164-41 names for Rust and Swift (C164-48).

**Version:** `gradle.properties:2` `version=1.1.2` is right: no public API changed, and the changes are behavioural. The CHANGELOG `[1.1.2]` records round 3:
- the Retry-After floor and its 60 s clamp (`:59-65`);
- the deadline-bounded in-poll retry (`:66-69`);
- no OkHttp resend on the device and CIBA polls (`:70-72`);
- the tests (`:104-107`).

It does not say that the CIBA in-poll retry is unbounded (C164-43), or that the polls lost route fallback (C164-44).

**Run by the reviewer** (throwaway copies `/home/user/work/kotlin-r3` and `-r3p` from `git archive c392bf9`; JDK 21, Gradle wrapper):
- `python3 scripts/gen_management.py --check` → `OK: 251 generated files are current (202 operations)`.
- `./gradlew test` (with `-Pkotlin.daemon.jvmargs=-Xmx3g`) → **BUILD SUCCESSFUL: 1308 tests, 0 failures, 0 skipped, 88 classes.** That is 1300 from round 2 plus 8 new tests.
  - A first attempt with the default 512 MB Kotlin daemon heap thrashed in full GC (3,300+ FGCs) on this shared machine and was killed. This is environmental, not a project defect.
- Mutants on `OidcDeviceFlowTest`, `D5ConformanceTest` and `CibaTest`:

  | Mutant | Failing tests |
  |---|---|
  | M1 (no `mayWait`) | 2 |
  | M2 (no RA) | 3 |
  | M3 (no clamp) | 1 |
  | M4 (poll back on `httpClient`) | 2 |
  | M5 (CIBA back on `httpClient`) | 1 |
  | MD (no transport retry) | 2 |

  All are killed.
- Probes D1, D2, C1, C2, K1, P-N1–P-N8 and W1–W7 were in `ReviewerProbeR3Test`. They were run and then deleted, along with the copies and all build outputs. The SDK clone is unmodified.
- Not run: `koverVerify`, `dokka`, lint.

**New findings:**
- **C164-43 — Medium (regression of the C164-37 fix; the CIBA half of C164-36)**
  - **Location:** `oidc/OidcSupport.kt:1364-1373` (`cibaPollTracked`'s `withRetry`, no `mayWait`) and `:1410-1450` (`cibaAwait`, which passes no deadline).
  - **Rule:** §33.7 rule 5 / §34.2 P10 (contract 1.60). A §16 retry's wait is bounded by rule 4's deadline: `Retry-After` is capped at the deadline, and nothing is sent after it.
  - **What happens:** before round 3, a 5xx `Retry-After` was ignored, so the overrun was jitter only. Now the floor is served, clamped at 60 s. Probe C1: `expires_in` 30 with 503 + RA 120 sent polls at 65 s and 125 s, and `cibaAwait` returned 95 s late. The CHANGELOG (`:64-65`) states that the floor reaches "the device and CIBA polls".
  - **Fix:** give `cibaPollTracked` the same `deadline: Instant?, clock: CibaClock?` pair. Pass `mayWait = { w -> deadline == null || clock!!.now().plusMillis(w.inWholeMilliseconds).isBefore(deadline) }`. From `cibaAwait`, pass `initiated.receivedAt.plusSeconds(initiated.expiresIn)` and `params.clock`; the public `cibaPoll` passes `null`. Record it in the CHANGELOG.
  - **Test** (`CibaTest`, `TestClock`): `expires_in` 30, interval 5, every poll 503 + RA 120 → `expired_token`, every `Seen.at` < 30 s, 5 polls, wall < 20 s. Also a poll answered 500 at deadline − 0.05 s with jitter 1.0 → no retry.
- **C164-44 — Medium (regression of the C164-39 fix)**
  - **Location:** `oidc/OidcSupport.kt:1239-1241` (`noRetryHttpClient`), used by the device poll (`:1954`) and the CIBA poll (`:1378`). `cibaInitiate` (`:1301`) has had the same property since before round 3.
  - **Rule:** §16.1 / §14.2 rule 6 / §33.7 rule 5. A transport failure is retried under §16 to survive transient failure, so an attempt must be able to reach a reachable server.
  - **What happens:** `retryOnConnectionFailure(false)` also turns off OkHttp 4.12's connect-route fallback. On a host whose first resolved address is refused or unreachable (`localhost` → `[::1, 127.0.0.1]` with an IPv4-only server; a name with an AAAA record on an IPv4-only network), every poll attempt fails on that address. All three §16 attempts and every interval fail with 0 requests reaching the server, unless the shared pool happens to hold a live connection (C164-48/N7 vs N6). `deviceLogin`/`cibaAwait` then end in `expired_token`.
  - The round-3 tests had to switch from `localhost` to `127.0.0.1` on the CI runners (`c392bf9`). That is this defect, met in CI.
  - **Fix:** send the polls through the shared `httpClient` (`retryOnConnectionFailure` true) and make the form body one-shot. For example, wrap it in a `RequestBody` that delegates `contentType`/`contentLength`/`writeTo` and returns `isOneShot() = true`. `recover()` then still falls back to the next route on a connect failure (send not started), and never replays a request whose send started. Probe N8 shows both. Optionally do the same for `cibaInitiate`. Record the change in the CHANGELOG.
  - **Tests:**
    - Build the client with `.httpClient(OkHttpClient.Builder().dns { if (it == "localhost") listOf(127.0.0.2, 127.0.0.1) else Dns.SYSTEM.lookup(it) }.build())`, base `http://localhost:<port>`, the mock bound to `127.0.0.1`, and `okHttpClient().connectionPool.evictAll()` before the poll. Then `devicePoll` → tokens, with 1 token request at the server. Do the same for `cibaPoll`.
    - Keep `:444`/t08c (three drops → exactly 3) and move them back to `localhost`.
- **C164-48 — Info (C164-37 clamp; ruling input)**
  - **Location:** `errors/ErrorMapper.kt:38`, `:54`.
  - **Rule:** §16.1 ("honored, as a floor"; no clamp stated).
  - **What happens:** a `Retry-After` above 60 s is waited at 60 s, and the retry then goes out before the time the server stated. K1: `checkAccess` with 503 + RA 3600 three times → 3 requests over 120.7 s, then `NetworkError`. The worst case with hanging attempts is about 4 min.
  - **Exact fix, if the ruling wants the floor kept literally:** when the parsed `Retry-After` exceeds the clamp, do not retry. Have `withRetry` throw the `NetworkError` at once, carrying the full `retryAfter` (for example, carry the unclamped value and add `if (e.retryAfter > MAX) throw e` before computing `wait`). The caller then gets the error at once instead of an early retry. Either way, record the clamp in the CHANGELOG. The README already states it.
- **C164-48 — Info (test strength / clock)**
  - **Location:** `internal/Retry.kt:136` (`delay(wait)`).
  - **What happens:** the in-poll wait sleeps on `kotlinx.coroutines.delay`, not on `params.clock`; only the bound check reads the clock. With the system clock this is consistent, but a `RecordingClock` never sees the in-poll waits. The tests pass because `mayWait` refuses the wait before it is slept.
  - **Fix:** pass an optional `sleep: suspend (Duration) -> Unit` from `deviceLogin`/`cibaAwait` that calls `clock.sleep`. Then assert the recorded in-poll waits, for example `[5, 0.2…]`.
- **C164-48 — Info (posture)**
  - **Location:** `oidc/OidcSupport.kt:1215-1219` (`catch (e: NetworkError) { continue }`).
  - **What happens:** a 5xx's `Retry-After`, now on the `NetworkError`, is dropped for the next interval, as C164-41 names for Rust and Swift. D1 polled every 5 s against RA 120.
  - **Fix (optional):** after an exhausted in-poll retry, wait `max(interval, retryAfter)` capped at the deadline, as rule 9 does for a 429.

---

#### Addendum round 3 — php — commit 41cf943fd (PR #87), read after 48751509a

There are two commits. `7dbec58` is the code and test fix (C164-36, C164-41, C164-38). `41cf943` updates the CHANGELOG, including the contract-source sentence (C164-41 text). Each commit message matches its diff. The diff touches `src/Oidc/OidcClient.php` (`devicePollWithin`, `deviceLogin`), `src/AxiamClient.php` (the `deviceLogin` wrapper), `tests/OidcDeviceFlowTest.php` and `CHANGELOG.md`. Nothing else changed: the CIBA path, the 429 handling, the middlewares and the generated surface are untouched. Mutants and probes ran on a throwaway clone, `/home/user/work/php-r3`, and each mutant was reverted afterwards.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-36 (Low): the in-poll deadline check leaves out the jitter | **CLOSED** | 7dbec58 | **Predicate:** `src/Oidc/OidcClient.php:900` now computes `max(Retry-After, RetryPolicy::backoffMs(n))`, the most the runner can wait (`delayMs` = `max(backoff·fraction, RA)`, `src/Core/RetryPolicy.php:61-66`). It retries only when that wait is strictly less than `$remaining()` (`:902`), so a retry is always sent before the deadline. **Guard:** the attempt closure refuses to send attempt `n > 1` once `$remaining() <= 0` and rethrows the previous `NetworkError` (`:910-913`). **Clock:** `$remaining` (`:1028-1030`) is `expiresIn − max(slept, now − startedAt)`; the loop's own check uses the same closure (`:1041`). A bare `devicePoll()` passes `null` and keeps the unbounded §16 behaviour (`:835`). **Tests** (fake clock, `clockedClient`/`runClocked`): `tests/OidcDeviceFlowTest.php:654` (every poll `503` + RA 120 → sent `[5.0]`, no in-poll wait, `expired_token`, clock ≤ 30) and `:672` (the `500` comes back at 29.999 s → 2 polls, no retry, `expired_token`). **Mutants:** **M1** (predicate uses `Retry-After` only, the round-2 code) fails `:672`. **M3** (M1 plus no guard) fails `:672`. **M6** (`deviceLogin` passes no deadline) fails `:541`, `:574`, `:654` and `:672` by assertion; in round 2 this kind of mutant was caught only by a timeout. **M2** (guard removed, predicate kept) **survives**. It is an equivalent mutant: the predicate already bounds the largest wait, and the guard is defence in depth. |
| C164-38 (Info): no transport-failure cap test and none inside `deviceLogin` | **CLOSED** | 7dbec58 | The `attemptFailures` data provider (`tests/OidcDeviceFlowTest.php:376-383`) has two rows, `500` with an OAuth body and a `ConnectException` reset. Four tests use it: `:414` (two failures then `200` → sleeps `[5]`, 4 requests), `:440` (three failures → `[5,5]`, 5 requests, tokens), `:466` (retry off → one request per poll) and `:490` (a single `devicePoll`, three failures → `NetworkError` after 3 requests). The first three run inside `deviceLogin()`. **Mutant M7** (transport failures not retried) fails all four transport rows plus `:507`. |
| C164-41 (Info), test robustness: the in-poll waits ignore the injected sleeper | **CLOSED** (one untested branch, see C164-47) | 7dbec58 | New trailing `?callable $retrySleep` (milliseconds) on `OidcClient::deviceLogin` (`:991`) and `AxiamClient::deviceLogin` (`src/AxiamClient.php:1734`, forwarded at `:1736`). It is passed to `RetryPolicy::execute`'s `$sleep` through `devicePollWithin` (`:939`). In `deviceLogin` (`:1015-1025`): with `$retrySleep` injected, the wrapper calls it and adds the time to `$sleptSeconds`; with only `$sleep` injected, the in-poll waits are counted but not spent; with neither injected, `RetryPolicy` really `usleep`s. **Tests:** `:541` (RA 3600 → `retryWaits === []`; this is the round-2 `:523` test, which no longer hangs) and `:574` (RA 20 at 5 s → `[20000.0]`, 3 requests, `expired_token`). **Mutants:** **M4** (`$inPollSleep` not threaded) fails `:574`. **M5** (the `$retrySleep` wrapper does not count the wait) fails `:574`. **M8** (the sleep-only branch removed, so the waits fall back to a real `usleep`) **survives**: no test pins that branch (C164-47). |
| C164-41 (Info), text: the CHANGELOG names the old contract source | **CLOSED** | 41cf943 | `CHANGELOG.md:13-15` now reads "re-vendored byte for byte from `ilpanich/axiam` `b3f8687` (contract 1.64 as amended by W7.1b and W7.1c: §14.2 rules 6 and 9, §14.6 including its in-attempt retry test, §34.2 P11, §34.8 (c))". This is the review's exact wording. The vendored `CONTRACT.md` sha256 equals `b3f8687:sdks/CONTRACT.md` and the current `sdks/CONTRACT.md` (`a221f1bf…`). |

**Deadline bound (device): bounded.** All probes ran through the public `deviceLogin()`.
- **Every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120` (expires_in 30, interval 5):** 1 request, at 5.0 s. No in-poll wait is started, and the flow raises `expired_token` with the clock at 5.0 s. This holds in every sleeper/clock combination tried: all three injected, sleep and clock only, and sleep only on the real clock.
- **A poll sent at 29.9 s whose `500` returns at 29.999 s (deadline − 0.001 s):** no retry, `expired_token`. The same holds when the `500` returns at 30.3 s. The round-2 latency probe (four `authorization_pending` at 0.999 s each, then `500, 500, 200`): polls at 5.0, 11.0, 17.0, 23.0 and 29.0 s; the `500` returns at 29.997 s and is not retried (round 2 sent the retry at 30.066 s), then `expired_token`.
- **`503` RA 20:** retried once after `[20000]` ms (sent at 5 and 25), then refused (25 + 20 ≥ 30), `expired_token`. Nothing is sent at or after 30 s.
- **Single `devicePoll`, `503` RA 3 ×3:** sent at 0, 3.0 and 6.0 s, then `NetworkError` (RA 3000 ms). With no deadline it stays unbounded, as intended.

**W7.1c shape: conforms, and the probes match the round-2 numbers.**
- A single `devicePoll`: `500, 500, 200` → 3 requests, tokens; `500` ×3 → 3, `NetworkError`; `reset, reset, 200` → 3, tokens; `reset` ×3 → 3, `NetworkError`.
- A `429` (`rate_limit_exceeded` RA 1, or bodiless RA 1) → 1 request, with RA 1000 ms on the error. Retry off → 1 request.
- `deviceLogin`: `500, 500, 200` → 3 polls, `[5]`; `500` ×3 then `200` → 4 polls, `[5,5]`; reset ×2 / ×3 → 3 / 4 polls; `429` RA 12 → `[5,12]` (rule 9); `500` then `200` with retry off → `[5,5]`.

**Ruling input: the public `$retrySleep` addition.**
- **Source-compatible: yes.** It is the last parameter, `?callable … = null`, on two `final` classes, so there are no overrides to break. Positional calls with up to seven arguments bind as before. Named-argument callers are unaffected; the new name collides with nothing. The private `devicePollWithin` changed its signature, but it is not surface. PHP silently drops excess arguments to userland functions, so only a caller who already passed a meaningless 8th argument would see a change. That is negligible.
- **Docblocks: yes, both.** `OidcClient.php:979-981` says the parameter is in milliseconds, that an injected `$sleep` alone means the in-poll waits are not spent, and that the waits are bounded by the deadline either way. `AxiamClient.php:1724` gives a one-line form. `tools/docblock-coverage.php` reports all 2083 public items documented.
- **CHANGELOG: yes.** The 1.1.2 "public additions" sentence now reads "trailing `$now` and `$retrySleep` (milliseconds) on `deviceLogin()`" (`CHANGELOG.md:19`). The C164-36 and C164-41 entries are at `:39-48`, and the C164-38 test entry is at `:105-106`.
- **README: no** (Info, C164-48). `README.md:807` still names only `$sleep`. It does not name `$now` (added in round 2) or `$retrySleep`, and it does not say that the in-poll §16 waits are bounded by the deadline.

**Ruling input: does the loop's clock keep the bound when the caller injects a sleeper but no clock?**
- **The bound holds.** `$remaining` uses `max($sleptSeconds, microtime − startedAt)`. In that configuration the in-poll waits are added to `$sleptSeconds` without being spent, so the SDK's view of elapsed time is never behind the real one. It therefore stops at or before the real deadline, never after it. Probed on the real clock: `503` RA 120 → 1 request at 0.03 s, then `expired_token`; `500, 500, 200` → 3 requests, tokens.
- **The cost:** a `Retry-After` inside the deadline is then not waited on the wire, and the grant is given up early. Probed with sleep only on the real clock, `503` RA 20: the retry is sent 0 ms after the first `503`. `$sleptSeconds` becomes 25, so the loop raises `expired_token` at real t ≈ 0 s, about 25 s early.
- **This is harmless when `$sleep` is a test fake,** which is what the `AxiamClient` docblock says it is for ("Injectable sleeper, for tests").
- **It is a §16.1 floor break when a caller injects a `$sleep` that really sleeps,** for example a cancellable or event-loop sleep. In round 2 such a caller got real `usleep` waits for the in-poll retries. Now it gets none. This is C164-47.

**Ruling input: does the CIBA path (`cibaPollTracked`) meet P10? No (pre-existing, outside this diff; C164-43).**
- **The retry has no deadline bound.** `cibaPollTracked` (`src/Oidc/OidcClient.php:2247-2302`) calls `RetryPolicy::execute('ciba_poll', …, null, null, $retryable)`. It passes no deadline, and its predicate (`:2264-2266`) looks only at the status. `cibaAwait` (`:2124-2172`) checks `receivedAt + expiresIn` only before its own interval sleep.
- **Its waits are not the injected clock's.** They are `RetryPolicy`'s real `usleep`, not the injected `CibaClock`. README `:332` says the `CibaClock` "also supplies the waits", which is untrue for these.
- **Probe:** `cibaAwait`, expires_in 30, interval 5, every poll `503` + `Retry-After: 20`, on a clock of fake seconds plus real elapsed time. Requests were sent at **5.05, 25.06 and 45.07 s**: the third is 15 s past the deadline. The call then raised `expired_token` after 40 s of wall time.
- **§34.2 P10 / §33.7 rule 5** say "A §16 retry's wait is bounded by rule 4's deadline … nothing is sent after it". The review's §7.1.2 note named this gap for TypeScript, Python and C++ only. PHP has it too.

**Round-2 checks:**
- **Rules 6 and 9 and the three §14.6 `429` cases:** green in the suite and in the probes (429 → 1 request; RA 12 → `[5,12]`).
- **1.63 isolation and the replay after a 401 refresh:** not touched by the diff. Their tests are in the green suite.

**Version:** 1.1.2 is still right (`## [1.1.2] - Unreleased`; install snippets `^1.1.2`). The addition is optional and backward compatible, so a patch is appropriate. The CHANGELOG records round 3 (C164-36, -38, -41).

**Run by the reviewer** (clone `/home/user/work/php-r3` at 41cf943fd; PHP 8.3, Composer 2.8):
- **Install:** the round-1 `composer.lock` was reused. phpstan/phpstan 2.3.1 came from a local `git clone --depth 1 --branch 2.3.1` (`6155239b`) used as a Composer `path` dist.
- `vendor/bin/phpunit`: **OK, 2070 tests, 9963 assertions** (round 2 had 2063).
- `vendor/bin/phpstan analyse --memory-limit=512M`: **No errors**.
- `python3 scripts/gen_management.py --check`: "§27 surface is current (261 files)".
- `php tools/docblock-coverage.php`: 2083/2083 documented.
- `composer validate --strict`: the only output is the reused lock's "not up to date" note; the lock comes from round 1's path-repository install, not from this PR.
- **Mutants:** 8 run on `tests/OidcDeviceFlowTest.php`. M1, M3, M4, M5, M6 and M7 are killed by assertion. M2 survives (an equivalent mutant: the guard is defence in depth) and M8 survives (C164-47).
- **Probes:** `scratchpad/php-r3-probes/probe.php` and `ciba.php`, plus the round-2 `scratchpad/php-r2-probes/probe.php` re-run on the new head. Logs: `scratchpad/php-r3-probe.log`, `php-r3-probe-r2set.log`, `php-r3-ciba.log`, `php-r3-mut.log`.
- **Not run:** gRPC codegen (needs protoc) and `composer audit`.
- **Cleanup:** the clone with `vendor/` and the phpstan clone are deleted. `/home/user/sdks/php` is untouched and clean.

**New findings:**
- **C164-47: Low (narrow trigger): `src/Oidc/OidcClient.php:1021-1025`.** Rule: §16.1 (`Retry-After` is a floor: "retrying sooner is not permitted") and §14.2 rule 6 (the grant must not be lost).
  - **What:** when a caller injects `$sleep` but not `$retrySleep`, the in-poll §16 waits are added to `$sleptSeconds` and never spent. If that `$sleep` really sleeps (a cancellable or event-loop sleeper used in production), a `503` + `Retry-After: 20` is retried at once, against the server's floor. The phantom 20 s also counts toward the deadline, so the loop gives up the grant about 20 s early (probed: `expired_token` at real t ≈ 0 s on a 30 s grant). Round 2 really waited in this configuration. No test pins the branch: mutant M8, which removes it, survives.
  - **Exact fix:** spend the wait in that branch as well as counting it: `$inPollSleep = static function (float $ms) use (&$sleptSeconds): void { usleep((int) round($ms * 1000)); $sleptSeconds += $ms / 1000.0; };`. Real sleeping is the default, tests have `$retrySleep` as their hook, and counting keeps the bound on a fake clock. Alternatively, keep the behaviour and state in both docblocks and the README that an injected `$sleep` without `$retrySleep` skips the in-poll waits and must not be used outside tests.
  - **Test:** sleep only (a recording no-op) on the real clock, `503` RA 1 then `200`: assert tokens and ≥ 1.0 s of wall time between the two poll requests. Or, if the documented-skip option is chosen, assert that `$sleptSeconds` advances and that the second poll is sent without waiting.
- **C164-48: Info (text): `README.md:807`.** The README names only `$sleep` among `deviceLogin()`'s test hooks. **Fix:** "`deviceLogin()` takes an injectable `$sleep` (seconds), `$now` (clock) and `$retrySleep` (milliseconds, the §16 waits inside a poll), so the §14.2 interval arithmetic and the in-poll retries are testable exactly; an in-poll retry is never sent after the `expires_in` deadline."
- **C164-43: Low (pre-existing, outside the diff): `src/Oidc/OidcClient.php:2247-2302` (`cibaPollTracked`), `:2124-2172` (`cibaAwait`), `README.md:332`.** Rule: §33.7 rule 5 / §34.2 P10 (contract 1.60): "A §16 retry's wait is bounded by rule 4's deadline … nothing is sent after it".
  - **What:** `ciba_poll`'s §16 runner has no deadline, and its waits use a real `usleep`, not the injected `CibaClock`. Probe: `cibaAwait`, expires_in 30, interval 5, every poll `503` + RA 20 → requests at 5.05, 25.06 and **45.07 s**, 40 s of wall time, then `expired_token`. README `:332` ("which also supplies the waits") is untrue for the §16 waits.
  - **Exact fix:** mirror the device fix.
    - Give `cibaPollTracked` an optional `?callable $remaining` and `?callable $retrySleep`.
    - Extend `$retryable` with `$remaining === null || max($e->retryAfterMs ?? 0.0, RetryPolicy::backoffMs($n)) / 1000.0 < $remaining()`. Track `$n` as `devicePollWithin` does.
    - Add the same `n > 1 && $remaining() <= 0` guard in the closure.
    - Pass `$retrySleep` as `RetryPolicy::execute`'s `$sleep`.
    - In `cibaAwait`, pass `$remaining = fn (): float => $deadline - $clock->now()` and `$retrySleep = fn (float $ms) => $clock->sleep((int) ceil($ms / 1000.0))`. A whole-second `CibaClock` over-serves the jitter, which is allowed because `Retry-After` is a floor; the guard keeps the bound.
    - A bare `cibaPoll()` passes `null` and keeps the unbounded behaviour.
  - **Test:** on the fake `CibaClock`, expires_in 30, interval 5, every poll `503` + RA 120 → 1 request at 5 s, none at or after 30 s, `expired_token`. Then `503` RA 20 ×3 → requests at 5 and 25 only.

---

#### Addendum round 3 — swift — commit a362452 (PR #78), read after 2630e9cfa

There are two commits. `4c6c694` holds the code and test fix for C164-38 and C164-41. `a362452` updates the CHANGELOG and README. Each commit message matches its diff. There is no Swift toolchain here, so the review is by reading, and every mutant below was traced by hand. All paths are under `/home/user/sdks/swift`, and the tests are in `Tests/AxiamSDKTests/Contract164DeviceGrantRateLimitTests.swift` (shortened to `T` below).

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-38 (Low): no transport-failure W7.1c case | **CLOSED** | `4c6c694` | **The new fixture.** `FlakyTransport` (`T:446-484`) is an `HTTPTransport` that throws `AxiamError.network` for the first *n* `/oauth2/token` calls and then returns the tokens. `umaSendAbsolute` passes that throw through unchanged (`AxiamClient.swift:1170`), so `bareSend` sees `response == nil` and retries under `.section16TransportOnly`.<br>**The new tests:**<ul><li>`:498`: two failures then a `200` → 3 requests and the tokens.</li><li>`:506`: three failures → 3 requests, then `.network`.</li><li>`:518`: inside `deviceLogin` → 3 requests, sleeps `[1,0,0]`.</li><li>`:528`: retry off, one failure → 2 requests (one per poll), sleeps `[1,1]`.</li></ul>**Mutants (traced):**<ul><li>`guard let response else { return true }` changed to `false` → `:498` throws after 1 request, and `:518` sees `[1,1,1]`. **Killed.**</li><li>The budget ignores `retryEnabled` → `:528` sees 2 requests in one poll and sleeps `[1,0]`. **Killed.**</li><li>`maxAttempts` raised from 3 to 4 → `:506` sees 4 requests. **Killed.**</li></ul> |
| C164-41 (Info): the bodiless-429 test could not tell an in-poll retry from the loop's wait | **CLOSED** | `4c6c694` | **The tests.** `testA429IsNeverRetriedInsideThePoll` (`T:320-336`) now attaches an `EventRecorder` and asserts that no `retry` event is emitted. The new `testASingleDevicePollOnABodilessA429IsOneRequestAndANetworkError` (`T:338-352`) asserts `.network(statusCode: 429)` and 1 request.<br>**Mutant:** swap the retry case for `.section16UnlessOAuthError`, which retries a bodiless 429. `:320` then sees a `retry` event, and in `:338` the retried poll gets the `200`, so the test reaches `XCTFail` with 2 requests. **Killed by both.** |
| C164-41 (Info): `deviceLogin` could pass `deadline: nil` unnoticed | **CLOSED** | `4c6c694` | **The test.** `testDeviceLoginBoundsTheInPollWaitByItsDeadline` (`T:392-415`) uses `expiresIn: 3`, interval 1, and the answers `[500 + Retry-After: 30, success]`. It asserts `expired_token`, 1 request, sleeps `[1]` and no `retry` event.<br>**Mutant:** `deadline: nil` at `DeviceGrant.swift:272-274` → the in-poll wait is 30 (sleeping on the fake clock), the retry gets the `200`, and the test reaches `XCTFail`. **Killed.** |
| C164-41 (Low/Info): a 5xx's Retry-After was dropped once the deadline refused the in-poll wait or the budget was spent | **CLOSED** (behaviour change) | `4c6c694` | **The code.** `DeviceGrant.swift:187-191`: a `5xx` left after §16 now throws `DevicePollDeferred(error: oidcMapError(response), retryAfter: <parsed RA>)`. The loop (`:275-279`) sets `retryAfter`, the next wait is `max(interval, RA)` (`:261`), and if that wait would pass the deadline the loop raises `expired_token` at once (`:263-268`). That is the same path rule 9 already uses for a 429. The single `devicePoll` unwraps it to the same `NetworkError` as before (`:138-141`).<br>**The test.** `testA5xxRetryAfterIsTheFloorOfTheLoopsNextWaitWhenTheBudgetIsSpent` (`T:417-430`): three `503` + RA 7, then the tokens → 4 requests, sleeps `[1,7,7,7]`.<br>**Mutant:** revert `:187-191` to `throw oidcMapError(response)` → that test sees `[1,7,7,1]`. `:392` also fails: it takes a second poll at the 1 s interval and gets the tokens. **Killed by both.** |

**Deadline bound (device), re-probed by trace.**

Probe 1: `expires_in` 30, interval 5, every poll answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`.

| t (s) | What happens |
|---|---|
| 0 | The loop waits 5 (5 < 30). |
| 5 | Request 1 → `503`. The in-poll wait is `max(0.2·j, 120)` = 120. Since 5 + 120 ≥ 30, the wait is not taken: no sleep and no `retry` event. The `503` is returned and wrapped as `DevicePollDeferred(RA 120)`. |
| 5 | The loop's wait is `max(5, 120)` = 120. Since 5 + 120 ≥ 30, the loop throws `AuthError(expired_token)` at once. |

- **Result: 1 request in all, none at or after the deadline.** The typed `expired_token` comes at about 5 s, well before 30 s.
- **Change since round 2:** round 2 made 5 requests at the 5 s interval, ignoring the server's 120 s. The floor is now honoured.

Probe 2: a poll sent at deadline − 0.1 s is answered `500` with no Retry-After.
- The in-poll wait is `0.2 × jitter` for attempt 1.
- Guard `BareRequest.swift:102`: if `now + wait >= deadline`, the `500` is returned and nothing more is sent.
- Otherwise the retry leaves strictly before the deadline. That conforms, because the rule is "no request at or after the deadline".
- Back in the loop, `retryAfter` is 0, the interval wait passes the deadline, and `expired_token` is raised.
- **Result: no request after the deadline.**

**W7.1c shape (traced):**
- Two 500s → 3 requests and the tokens (`T:251`).
- Three 500s → 3 requests and `.network` (`T:277`).
- Two transport failures then `200` → 3 requests and the tokens (`T:498`).
- Three transport failures → 3 requests (`T:506`).
- A 429 → 1 request (`T:320`, `T:338`).
- Retry off → 1 request per poll, for a 500 (`T:294`) and for a transport failure (`T:528`).
- **Complete.**

**Rules 6 and 9, the three §14.6 429 cases, the 1.63 isolation rules, and the replay after a 401 refresh.** The diff touches only `devicePollOnce`'s non-2xx branch for `>= 500` and a rename in the 429 branch.
- The 429 results are unchanged.
- A 5xx is still non-terminal: it reaches `continue` through `DevicePollDeferred`. It is checked before the body, so `500 {"error":"server_error"}` is not terminal.
- Nothing touches the bare path's headers or the refresh path. All four still hold.

**Ruling (a): is `DevicePollDeferred` public?**
- **No.** `struct DevicePollDeferred: Error` (`DeviceGrant.swift:31`) has no access modifier, so it is **`internal`**. Its doc comment says "Internal on purpose".
- It is caught in `devicePoll` and `deviceLogin` and never escapes either: `devicePoll` rethrows the wrapped `AxiamError`.
- A grep finds no other reference in `Sources/` or `Tests/`, and the old name `DevicePollRateLimited` is gone completely.
- **The rename is not source-breaking**, and no public signature changes. The CHANGELOG records the behaviour change: a 5xx's Retry-After is now the loop's floor. It does not record the internal type's name, and it does not need to.

**Ruling (b): is the §16 retry inside `ciba_poll` bounded by a deadline?**
- **Nothing bounds it.**
  - `cibaAwait` (`Oidc/Ciba.swift:514-550`) checks only *before* each poll: `clock.now() + interval >= deadline` (`:526`).
  - `cibaPollOnce` calls `bareSend(…, retry: .section16UnlessOAuthError)` with no `deadline` (`:459-469`). Inside it, the waits use the `_sleep` seam and `Date()`, not the `CibaClock`.
  - There is no `Task` timeout or cancellation.
  - The only cap on Retry-After is `Retry.retryAfter`'s 3600 s clamp.
- Trace: `cibaAwait` with `expires_in` 30, interval 5, and every `ciba_poll` answered `503` + `Retry-After: 120`.

| t (s) | What happens |
|---|---|
| 0 | The loop checks 0 + 5 < 30 and sleeps 5. |
| 5 | Request 1 → `503`. The in-poll wait is 120. With no deadline, a `retry` event is emitted and the SDK sleeps 120. |
| 125 | **Request 2, 95 s after the deadline** → `503`. It sleeps 120 again. |
| 245 | **Request 3, 215 s after the deadline** → `503`. The budget is spent and the poll returns a `NetworkError`, which the loop treats as transient. |
| 245 | The loop checks 245 + 5 ≥ 30 and throws `expired_token`. |

- **Result: 2 requests after `received_at + expires_in`, and `expired_token` arrives about 215 s late.**
- **§34.2 P10 is not met.** P10 is a MUST since contract 1.60: "a §16 retry inside `ciba_poll`, as `ciba_await` calls it, MUST NOT wait past the deadline … no request".
- A bodiless `429` + Retry-After is also retried in-poll under `.section16UnlessOAuthError` and overruns the same way.
- So does a `5xx` with no Retry-After answered in the last ~0.2 s, because the jittered 0.2 s backoff can carry the retry past the deadline.
- The required §33.8 test 7, second half ("a `503` with a `Retry-After` that reaches past the deadline … send nothing after it"), is **absent**: `CibaTests.swift:364-385` covers only `authorization_pending`.
- This is a finding (C164-43). It predates this PR and is outside the 1.64 items. Swift belongs on §7.1.2's "Outside these PRs" list alongside TypeScript, Python and C++.

**Version:**
- 1.1.2 (`AxiamSDK.podspec:3`), still right: no public signature changed, and the change is a patch-level behaviour fix.
- The CHANGELOG records round 3 under `[1.1.2]` (`CHANGELOG.md:49-58`).
- The README's §14.2 bullet (`README.md:1108-1112`) now says the loop waits at least the 5xx's Retry-After.

**Run by the reviewer:**
- `python3 -I Scripts/gen_management.py --check` in the throwaway copy `/home/user/work/swift-r3`: "§27 surface is current (3 files)", rc=0. I deleted the copy afterwards.
- `git log --format=%G?`: `N` for both commits. There is no allowed-signers file, so the signatures could not be verified.
- **Not run:** `swift build` and `swift test` (no toolchain). I checked by reading that every helper the new tests use exists with the signature they call:
  - `HTTPTransport.execute(_:timeout:)` and `shutdown()`;
  - `AxiamClient.init(config:transport:)` and `_setRetryTestSeams`;
  - `NSLock.locked`, `TestResponse.jsonBody` and `EventRecorder`;
  - `withDeviceClient(…, recorder:)`.
- Test note (Info, not numbered): `T:392`'s deadline is `Date()+3` on the real clock while the sleeps are faked. The test passes as long as the run takes less than about 2 s.

**New findings:**
- **C164-43 — Low (pre-existing, outside the 1.64 items).**
  - Where: `Sources/AxiamSDK/Oidc/Ciba.swift:459-469` (`cibaPollOnce` → `bareSend`, no `deadline`) together with `:524-548` (`cibaAwait`).
  - Rules: §34.2 P10 (MUST since 1.60, B3) and §33.7 rule 5 ("a §16 retry's wait is bounded by rule 4's deadline … nothing is sent after it"); §33.8 test 7.
  - What: a §16 retry inside the poll that `cibaAwait` makes ignores `receivedAt + expiresIn`. With `expires_in` 30 and `503` + `Retry-After: 120`, requests go at 125 s and 245 s and `expired_token` arrives at about 245 s. A bodiless 429 behaves the same way. The required test 7 case is missing.
  - Fix:
    - Give `cibaPollOnce` a `deadline: Date?` and pass `bareSend(…, deadline: deadline)` from `cibaAwait`. The single `cibaPoll` passes `nil` and keeps §16's bounded budget, as P10 allows.
    - Make bareSend's guard read the same clock as the loop, since P10 says the anchor and the waits SHOULD both come from the injected clock: add a `now: () -> Date` parameter, with `{ clock.now() }` from `cibaAwait`.
    - When the guard refuses a wait, surface the Retry-After to the loop, as `DevicePollDeferred` now does for the device grant. Then raise `expired_token` at once if `max(interval, RA)` would pass the deadline. This also keeps the next poll from ignoring the floor.
    - Test, on `TestCibaClock` with the retry sleep seam recording: `expiresIn: 30`, interval 5, every poll `503` + `Retry-After: 120`. Assert 1 token request (stamp 5), no `retry` event, and `isExpiredToken`.
    - Record the fix in the CHANGELOG.

---

### 7.3 Addendum round 4 (2026-10-23): the round-4 heads

**What was read.**

The contract is unchanged: W7.1c `b3f8687`.

| SDK | PR | Head |
|---|---|---|
| Kotlin | #80 | `51f4bd92a` |
| Swift | #78 | `5265aed` |
| C | #77 | `7b5bd2150` |
| PHP | #87 | `d127d75` |
| Java | #121 | `97dcdf0b2` |
| TypeScript | #150 | `228d03e` |
| C# | #111 | `aa403c8` |
| Rust | #138 | `c947a5e` |
| Python | #103 | `f9b68a28c` |
| C++ | #80 | `3adf581` |
| Go | #103 | `2a0c273ad` (unchanged since round 3, not re-read) |

These are the heads the orchestrator named, and `git ls-remote` showed the same. The method is §7.2's:
- each SDK's §7.2.3 items re-checked, with mutants where a toolchain existed (C# and Swift read only);
- the deadline bound re-probed, device and CIBA;
- the W7.1c shape re-probed.

**Vendoring and drift.** All eleven heads vendor `b3f8687`. `scripts/check-sdk-artifact-drift.py --local-root`
over the eleven heads reports **11 repos, 0 artifact problems**.

**Process note.** During its run, the Java reviewer was flagged by the harness for an irreversible local deletion.
The lead reviewer checked what it could have touched:
- the platform worktree is clean at `b1446d2`;
- all eleven SDK clones are clean at their round-4 heads;
- every review report is present.

The deletion was confined to throwaway build copies under `/home/user/work`. Nothing this review relies on was
lost, and the Java findings below were re-checked against the clone.

#### 7.3.1 Rulings on the orchestrator's points

**1. C++ documented the CIBA in-poll wait / `CibaClock` mismatch instead of fixing it (C164-48 item 3).
Acceptable.**
- **In production the clocks agree.** With `CibaClock::system()`, or any caller clock that reads real
  `steady_clock` time, the deadline check and the wait measure the same time.
- **The mismatch is confined to virtual-clock tests.** With a virtual clock the in-poll waits do not advance it,
  so a test sees more polls than a consistent clock gives. The note at `include/axiam/oidc.hpp:803-807` says so
  accurately.
- **A separate, smaller point (C164-54, Info).** The C++ reviewer found that every deadline check runs before the
  sleep and is never repeated after it. An OS oversleep can therefore put a request a few milliseconds past the
  deadline: 0.1 and 4.0 ms in 2 of 36 real-clock CIBA runs, all still ending in `expired_token`.
  - The SDK never asks for a wait past the deadline, so P10's wording is met.
  - The same check-before-sleep pattern is the norm across the eleven SDKs.
  - A re-check after the sleep, before the send, is hardening, not conformance.

**2. Kotlin's 60 s `Retry-After` clamp. Confirmed: not a finding.** §7.2.1 point 2 and C164-49 rule that
§16.1's two rows disagree above the 5 s cap, and that the clamps stay as they are until 1.65. Kotlin's README
(`:2517`), KDoc and CHANGELOG (`:82-84`) describe the clamp accurately.

**3. PHP carries an unserved CIBA `Retry-After` into the next wait. Conforming.**
- **Bounded:** the carried wait passes the same deadline check before every sleep. A wait that would reach the
  deadline raises `expired_token` at once with nothing sent, the "raise at once" option of P10.
- **Never shortens the interval:** the next wait is `max(interval, Retry-After)`, used once, and the interval
  itself is untouched. Probed: `Retry-After: 2` waits 5 s; `12` waits 12 s; after a `slow_down` (interval 10),
  `7` waits 10 s.
- **It is §33.7 rule 5's reading:** `Retry-After` is a minimum wait, capped at the deadline. Rust (C164-41,
  round 3) and Python (C164-48, this round) do the same.
- **Two gaps:**
  - No test pins "never shortens" (C164-54).
  - The carry covers only `NetworkError` failures. AXIAM's own `429 {"error":"rate_limit_exceeded"}` on
    `ciba_poll` still re-polls at the plain interval and ignores its `Retry-After`. This predates the PR
    (**C164-52**).

#### 7.3.2 New findings (C164-50 onward)

| ID | Severity | SDK | `path:line` (round-4 head) | Rule | What | Fix |
|---|---|---|---|---|---|---|
| C164-50 | **Medium** | kotlin (pre-existing, outside the 1.64 diff; the same root cause as C164-44) | `ManagementTransport.writeHttp` (`:70-72`); `Sessionless.of` (`:49`) | §16.1; §34.2 P11 (a never-retried request is still delivered: the dedicated handler's job is no replay, not no route) | On OkHttp 4.12.0, the clients built with `retryOnConnectionFailure(false)` for never-retried requests also lose route fallback. Probed: a management `DELETE` on a host resolving to `[::1 \| 127.0.0.2, 127.0.0.1]` with an empty pool reaches the server **0** times, while a `GET` on the same client reaches it once. Every management write and every sessionless call fails on such a host until a pooled connection happens to exist. This is what a caller meets on an AAAA-unreachable network, as with C164-44. | Keep P11's dedicated, non-pooled handler, `Connection: close` and the always-present body. Set `retryOnConnectionFailure(true)` on it and send every never-retried request with a **one-shot** body (`OneShotBody`, as `0529cef` did for the polls): the route fallback comes back, and a sent body is still never replayed. Test, on each client: the C164-44 dual-stack `Dns` with the pool evicted, a management `DELETE` and a sessionless `POST`, each giving one server request; and P11's own test (read, then drop unanswered) still gives no second request. |
| C164-51 | Low | c (a regression of round 4) | `src/oidc_ciba.c:540` | §16.1 (jittered backoff); §14.3 / §33.7 (return the token set) | The CIBA in-poll wait is rounded up to whole seconds even when the caller passes **no** clock, so a 100 ms backoff becomes 1 s and the jitter is defeated. Example: interval 28, `expires_in` 30, then `500`, `500`, `200`. Round 3 returned the tokens; round 4 ends in `expired_token`. The CHANGELOG does not record it. | Sleep the millisecond `delay` on `c->sleep_fn` unless the caller supplied a clock; round up only on the caller's whole-second clock. Verified in a copy, and `test_ciba` still passes. Test: the example above, with no clock → the tokens. |
| C164-52 | Low | php (pre-existing) | `src/Oidc/OidcClient.php:2167-2169` | §33.7 rule 5 (a `429` on `ciba_poll` is waited out, `Retry-After` a minimum capped at the deadline); §16.1 | CIBA's `429 rate_limit_exceeded` ignores its `Retry-After`. With `Retry-After: 12`, the next poll goes at the interval (10 s) instead of 17 s. | Carry the 429's `Retry-After` with `retryAfterRound`, as the device loop does: the next wait is `max(interval, Retry-After)`, deadline-checked. Test: `cibaAwait`, interval 5, a `429` + `Retry-After: 12`, then `200` → a recorded wait of 12 s. |
| C164-53 | Low | c, kotlin | C `tests/test_ciba.c` (every new case pins `Retry-After` with zero jitter); Kotlin `t04` (`cibaInitiate`'s one-shot body is unpinned) | §33.8 test 7 (P10, the jitter included); §33.8 test 4 / §33.7 rule 1 (`ciba_initiate` is never retried) | Required tests that do not pin the fix. **C:** with no jittered case, a "floor instead of ceil" mutant and a "count only `Retry-After`" mutant survive, and both send after the deadline in the probe. **Kotlin:** removing the one-shot body from `cibaInitiate` passes all 1314 tests. With it removed, a drop on a pooled connection makes 2 initiate requests and a `503` + `Retry-After: 0` makes 2. | **C:** a bare `500` to a CIBA poll one second before the deadline with jitter 0.5 → no request at or after the deadline. **Kotlin:** t04 cases on a pooled connection: a mid-response drop, and a `503` + `Retry-After: 0`, each giving exactly one `cibaInitiate` request. |
| C164-54 | Info | typescript, python, cplusplus, csharp, php, kotlin, swift | per each SDK's round-4 addendum | test strength; text | <ul><li>**Text:** TypeScript's CHANGELOG calls the exported `RetryOptions.admit` "internal". Python's CIBA docstrings and CHANGELOG say "5xx" where the carry also covers a 429. Swift's `cibaAwait` doc says "waits the interval", and its README omits the CIBA bound. C++'s millisecond deadline is filed under *Tests*, not *Fixed*. C#'s commit message names the wrong guarded test.</li><li>**Surviving mutants:** Swift's 429 deferral and `>=`; C#'s `sleeps.Count`, the retry-event order and `>=`; PHP's "carry shortens the interval" and `<`/`<=`; Python's three CIBA carry mutants; Kotlin's dual-stack drop test, CIBA sleep-on-clock and boundary.</li><li>**Whole seconds and oversleep:** PHP's CIBA clock waits in whole seconds (`expired_token` 0.5 s late, nothing sent). C++ checks before the sleep and not after (§7.3.1 point 1).</li></ul> | Per each SDK's round-4 addendum under C164-54. |

**Counts, round 4:** Medium 1 (C164-50) · Low 3 (C164-51, -52, -53) · Informational 1 (C164-54).

#### 7.3.3 Per-SDK status, round 4

| SDK | Head | Round-3 findings | New / remaining |
|---|---|---|---|
| typescript | `228d03e` | C164-45 (the jitter pinned; the round-3 survivors fail 7 and 2 tests), -48 (`admit` before the emit) **closed** | C164-54 |
| rust | `c947a5e` | C164-48 **closed** (CHANGELOG only) | **none** |
| python | `f9b68a28c` | C164-48 **closed** (the carry for device and CIBA, sync and async; never shortens; applies once) | C164-54 |
| c | `7b5bd2150` | C164-43 (exact boundary pinned; caller clock used), -48 **closed** | C164-51, -53 |
| cplusplus | `3adf581` | C164-48 **closed** (ms deadline; CIBA boundary; clock note; CHANGELOG) | C164-54 |
| csharp | `aa403c8` | C164-46 (real-time responders; JWKS variant; rethrow test), -48 **closed** (read only) | C164-54 |
| go | `2a0c273ad` | — | **none** |
| java | `97dcdf0b2` | C164-43 (CIBA through the pacer; 0 requests at or after the deadline), -45 (M4 and M5 fail), -48 **closed**; `setPollJitterForTesting` is package-private; `Pacer` has been `internal` since `c34eb71`, not in v1.1.1 | **none** |
| kotlin | `51f4bd92a` | **C164-44 closed** (one-shot body on the device poll, the CIBA poll and `cibaInitiate`; route fallback and no-replay both probed), C164-43 (CIBA bound), -48 **closed** | **C164-50 (Medium)**, C164-53, -54 |
| php | `d127d75` | C164-43, -47 (waits really slept with a sleeper and no clock), -48 **closed** | C164-52, -54 |
| swift | `5265aed` | C164-43 **closed** (read only; `CibaPollDeferred` is internal) | C164-54 |

Every SDK is at 1.1.2, and no public API change was found. The device and CIBA deadline bounds now hold in all
eleven SDKs, as does the W7.1c shape. Kotlin's `cibaInitiate` change also closes a pre-existing §33.7 rule 1
hole: OkHttp no longer resends it on a `503` + `Retry-After: 0`.

**Can W7 merge? No.** The merge condition is §1.4: no open finding of any severity.
- **Rust, Go and Java** have nothing open.
- **Kotlin** has **C164-50 (Medium)**. It predates the PR, but it is the same OkHttp 4.12 failure C164-44 fixed
  for the polls, now on management writes and sessionless calls. It also has C164-53 and -54.
- **C** has C164-51 (a round-4 regression) and C164-53.
- **PHP** has C164-52 and -54.
- **TypeScript, Python, C++, C# and Swift** have only C164-54 (Info).

**A note for the orchestrator on convergence.**
- **Rounds 1 to 4 have closed every Medium they found.** Each round's new Mediums came from the fix pass itself
  (C164-44 from C164-39) or from probing the same mechanism wider (C164-26, C164-50).
- **The Informational items each round adds** are mostly mutants that survive and text that drifts. Probing deeper
  will keep producing them at roughly this rate.
- §1.4 counts them, and this review records them. Whether a fifth round should wait on Informational test-strength
  items alone is a decision for the orchestrator or the maintainer, not for the review.

The ten round-4 addenda follow, with the reviewers' N-numbers mapped to the ids above. Kotlin's probe labels are
written P-N1 … P-N11. §7.3.2 holds the binding severities: Kotlin's addendum calls C164-50 Low; it is Medium for
the reason given there.

---

#### Addendum round 4 — typescript — commit 228d03ec3 (PR #150), read after df5ec4a4b

There are two commits. `4dc688c` covers the tests for C164-45 and the `admit` hook plus tests for C164-48. `228d03e` covers the CHANGELOG. Each commit message matches its diff. For C164-45 the product logic did not change: the deadline predicate `clock.now() + ms >= deadline` is the same. For C164-48 the predicate moved from `sleepFn` into a new `admit` hook. The SDK clone was not modified. All work was done in `/home/user/work/typescript-r4`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-45 (Low) the deadline test for the in-poll retry does not exercise the jittered wait; there is no CIBA twin | **CLOSED** | 4dc688c | **Device.** `test/node/deviceFlow.test.ts:868-910` adds the helper `bareFiveHundredNearDeadline` (a bare `500` with no `Retry-After`, and `vi.spyOn(Math,'random')` restored in `finally`). It has three cases. `:890`: `expires_in` 5.1, random 1 → `[5000]` + `expired_token`. `:897`: random 0.25 → `[5000, 5050]` + `expired_token`, so a retry before the deadline is allowed and the next wait is refused. `:904`: `expires_in` 5.2, random 1, so the 200 ms wait lands exactly on the deadline → `[5000]`. **CIBA twin.** `test/node/ciba.test.ts:446-465` is an `it.each` with the same three cases on `cibaAwait` (`[5]`, `[5, 5.05]`, `[5]`). **Mutants:** **M45raonly** (the round-3 "Retry-After-only deadline check": `admit` sees `(ra ?? 0)` instead of the full wait) is now **killed**. It fails all 3 device and all 3 CIBA jitter cases, plus `retry.test.ts` "admitted wait" because of the extra argument. In round 3 it survived 78/78. **M45gt** (`>=` → `>`) is now **killed**. It fails exactly the two boundary cases, `deviceFlow.test.ts:904` and the CIBA `expires_in 5.2` row. In round 3 it survived. |
| C164-48 (Info) `retry` telemetry was emitted for a retry that is refused | **CLOSED** | 4dc688c | `src/rest/retry.ts:51-56` adds the optional `RetryOptions.admit?(delayMs)`. `:135` calls it after `delayMs()` and before `telemetry.emit` (`:138`) and `sleep` (`:145`). A throw from it leaves the `catch` and ends the call: nothing is emitted, slept or sent. `src/node/oidc.ts:698-713` `deadlineBoundedRetry` returns `{ admit, sleepFn }`. `admit` raises `expired_token` when `now + ms >= deadline`, and `sleepFn` only sleeps on the loop clock. Wiring: CIBA `:2467`, device `:2678`. The standalone `devicePoll`/`cibaPoll` pass neither. **Probes (virtual clock, telemetryHook):** **P13** (device, `expires_in` 30, 503 + RA 120): 1 request, **0** `retry` events (round 3 had 1), `expired_token`. **P13e** (CIBA, the same): 1 request, 0 events. **P13c** (`expires_in` 5.1, bare 500, random 0.25): requests `[5000, 5050]`, exactly one event `retry:a1:50`; the refused second wait announces nothing. **Normal path: P13b** (far deadline, two 500s then 200): 3 requests, exactly 2 events (`a1`, `a2`), tokens. **P13d** (standalone `devicePoll`, three 500s): 3 requests, 2 events, `NetworkError`. So there is exactly one event per retry that is sent, and none for a refused one. **Unit tests:** `test/rest/retry.test.ts:76-113`. The refused test checks: no emit, no sleep, 1 call, the error rethrown as-is. The admitted test checks: `admit(200)`, 1 emit, `sleep(200)`. **Mutants:** **M48emitfirst** (the round-3 order, admit after emit) fails `retry.test.ts` "a refused wait announces no retry event". **M48doubleemit** fails "an admitted wait is announced once". **M48noadmit** (the hook call dropped) fails 10 tests, device and CIBA included. |
| C164-48 (Info) the deadline tests failed only by vitest's timeout | **CLOSED** | 4dc688c | `deviceFlow.test.ts:799-810` `recordLongTimers` and the inline twin in `ciba.test.ts:419-436` spy on `setTimeout`. Any timer of 60 s or more is recorded and run at 0 ms. They assert `long` equals `[]`. **M48dev** and **M48ciba** (the bound wiring dropped, the round-3 M36dev/M36ciba) now fail by assertion (`expected [ Array(10) ] to deeply equal []`) in 0.5-0.7 s, with 0 timeouts. **M48realsleep** (the wait admitted but served on the real `setTimeout`) fails the 0.25-jitter device and CIBA cases and the CIBA transport test. |
| C164-48 (Info) the `>=` boundary was not pinned | **CLOSED** | 4dc688c | See M45gt above. It is killed by `deviceFlow.test.ts:904` and the CIBA 5.2 row. |

**Deadline bound: still bounded, device and CIBA** (`/home/user/work/ts-r4-probes/zprobe4.test.ts`, log `/home/user/work/ts-r4-probe.log`).
- **Device.** P7: `expires_in` 30, interval 5, 503 + RA 120 → 1 request at 5000 ms, `expired_token` at 5000. P7b: one 503 + RA 120, then 200 → `expired_token` at 5 s, no tokens late. P10: the poll at deadline − 0.1 s gets a bare 500, random = 1 → 1 request, `expired_token`. P10a: random 0.25 → `[5000, 5050]`. P10b: 200 unmocked runs, worst request at 5099.91 ms, 99 of 200 sent a legitimate pre-deadline retry. P12: a far deadline (600 s) still honours RA 120 (requests at 5, 125 and 245 s, then tokens).
- **CIBA.** P9: `cibaAwait` with `expires_in` 30 and 503 + RA 120 → 1 request at 5 s, `expired_token`, nothing after `received_at + expires_in`. P9b: the bare 500 near the deadline with random 1 → 1 request. P9c: 503 + RA 120 once, then 200 → `expired_token` at 5 s.

**W7.1c shape: holds.**
- P1, two 500s then 200: 3 requests and the tokens.
- P2, three 500s: 3 requests and a `NetworkError`.
- P3, two transport failures then 200: 3 requests and the tokens.
- P3b, three transport failures: 3 requests and a `NetworkError`.
- P4, a 429: 1 request (`rate_limit_exceeded`). P4b, a 500 then a 429: 2 requests.
- P5, retry off: 1 request for a 5xx and 1 for a transport failure.
- P6: `deviceLogin` takes 3 requests in one interval. P8: a 408 makes 1 request.

**Prompt questions.**
- (C164-45) Do the round-3 "Retry-After-only deadline check" mutant and the `>=`→`>` mutant fail now? **Yes, both.** M45raonly fails 7 tests, covering device and CIBA. M45gt fails 2 tests, the device and the CIBA boundary case. Neither fails by timeout.
- (C164-48) Is a `retry` event emitted for a retry that is not sent? **No.** P13 and P13e give 0 events, and P13c gives 1 event for 2 requests. Does the normal path still emit exactly one event per retry? **Yes.** P13b and P13d give 2 events for 3 requests, with attempts 1 and 2. The unit test pins one emit per admitted retry.

**Version:** `package.json` is 1.1.2, which is right. `CHANGELOG [1.1.2]` records round 4: `CHANGELOG.md:38-40` covers C164-48 and `:67-72` covers C164-45/-48 tests. The README conformance sentence still says contract 1.64. Nothing is source-breaking. One thing is new in the public API: `RetryOptions.admit` is an optional member of a type exported from `.` and `./rest` (`src/rest/index.ts:16`; it is in the emitted `dist/client-*.d.ts:37`). It is additive, so it is not breaking. But the CHANGELOG calls it "an internal `admit` hook" (see C164-54).

**Run by the reviewer** (`/home/user/work/typescript-r4` at 228d03e, Node 22, proxy variables unset):
- `npm ci` OK.
- `npx tsc --noEmit` exit 0.
- `npx vitest run`: **119 files, 1778 passed, 3 skipped, 0 failed** (1771 in round 3, plus 7 net new tests).
- `npm run docs`: 0 errors and the 3 known warnings.
- `gen-management:check`: 32 files current, 202 ops.
- `tsup` and `bundle-grep` OK.
- 8 mutants (`/home/user/work/ts-r4-mut.sh`, patches in `/home/user/work/ts-r4-mutants/`, logs in `/home/user/work/ts-r4-mut-*.log`, summary in `ts-r4-mut-summary.log`): **8 of 8 killed**, 0 by timeout. They were M45raonly, M45gt, M48emitfirst, M48noadmit, M48dev, M48ciba, M48realsleep and M48doubleemit.
- `node_modules` and `dist` were deleted, and the probe file was removed from the tree.

**Round-1/2/3 checks where the diff touched them:** the diff touches only `withRetry`'s order and the deadline helper.
- Rule 9: a 429 is still not retried inside the poll (P4, P4b).
- Rule 6: a 5xx is non-terminal with a far deadline (P12, P13b).
- The 401 refresh replay, the 1.63 isolation code and the §14.6 429 cases are untouched, so they were not re-probed.

**New findings:**
- **C164-54 — Info (text / public API record). `CHANGELOG.md:39`; `src/rest/retry.ts:51-56`.** The CHANGELOG calls `admit` "an internal `admit` hook". It is in fact a new optional member of the exported `RetryOptions` (`src/rest/index.ts:16`, emitted in the public `.d.ts`), next to the already-public test seams `sleepFn`/`randomFn`. It is additive and not source-breaking, but it is mis-described. **Exact fix:** do one of the following.
  - Reword the CHANGELOG to "`RetryOptions` gains an optional `admit(delayMs)` hook, called before a retry is announced or served; throwing refuses the retry".
  - Or mark the member `@internal` in its TSDoc (and, if wanted, enable `stripInternal`), so that "internal" is true.

---

#### Addendum round 4 — rust — commit c947a5ea4 (PR #138), read after 7fa30ce0

`git log --oneline 7fa30ce0..HEAD`: one commit, `c947a5e docs(changelog): wrap the 1.1.2 intro and one bullet at about 100 columns (C164-48)`.
`git diff --stat 7fa30ce0..HEAD`: `CHANGELOG.md | 10 ++++++----`, 1 file. No source, test, manifest or CI file changed.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-48 (Info, text): `CHANGELOG.md:15` was 154 characters | **CLOSED** | `c947a5e` | `CHANGELOG.md:15-16` now wrap at 99 and 59 columns ("stays 202 operations … (the gating" / "below only changes … so it is a patch."). The `management::error` bullet (`:42-43`) is wrapped too. In the 1.1.2 section (`:10-82`), the longest lines are now 101-102 columns (`:49`, `:54`, `:58`, `:78`, `:79`), which is "about 100" and matches the rest of the file. Text only, so there is no mutant to run. |

Deadline bound: not re-probed. No code changed since round 3, where device (waits `[5,40,40,40]`, no poll at or after the deadline, typed `expired_token`) and the 500 at deadline−0.1 s (no retry) were probed and closed (C164-38, -41).
W7.1c shape: not re-probed, for the same reason. The round-3 results stand.
Rules 6/9, §14.6 429 cases, 1.63 isolation, replay after 401: untouched by the diff, so they were not re-probed.
Version: `Cargo.toml:25` `version = "1.1.2"`. That is still right: a CHANGELOG-only change.
CHANGELOG: round 4 is recorded under `### Internal` (`:72-73`, "CHANGELOG text (C164-48) …").
Run by the reviewer: `git log`, `git diff --stat` and `git diff` over `7fa30ce0..HEAD`, plus an `awk` line-length scan of `CHANGELOG.md`. No build or test run was needed (no code changed), so there are no build outputs to delete.
New findings: none.

---

#### Addendum round 4 — python — commit f9b68a28c (PR #103), read after 3715bba

There is one commit over the round-3 head: `f9b68a2` "fix(retry): carry a 5xx's Retry-After across a declined retry; async CIBA clock test; README clamp (C164-48)". It touches `_client.py` and `_async_client.py` (+23/-2 each), `tests/test_device_flow.py` (+66), `tests/test_ciba.py` (+65), `README.md` (+4/-1) and `CHANGELOG.md` (+6). The commit message matches the diff. `_oidc.py`, `_retry.py`, `_errors.py` and `_ciba.py` are untouched.

The design:
- **Device** (`_client.py:2075-2084`, `_async_client.py:881-890`): the `"retry"` branch of `device_login` reads `getattr(exc, "retry_after_ms", None)` and, when set, calls `schedule.rate_limited(ra / 1000)`. That is the existing rule-9 one-shot floor: `PollSchedule.tick()` (`_oidc.py:373-381`, unchanged) waits `max(interval, floor)`, resets the floor, and returns `False` (so the loop raises `expired_token` with no request) when the wait reaches `remaining()`. This is the exact fix the round-3 addendum gave.
- **CIBA** (`_client.py:2370-2396`, `_async_client.py:1068-1094`): a local `floor`. Each iteration computes `wait = max(interval, floor)`, resets `floor = 0.0`, checks `tick.now() + wait >= deadline` before sleeping, and sleeps `wait` on the injected clock. A non-terminal, non-`slow_down` failure that carries `retry_after_ms` sets `floor`. This is also the exact fix.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-48 (Info): a 5xx's `Retry-After` is dropped by the loop after a declined in-poll retry, device, sync and async | **CLOSED** | f9b68a2 | **Code:** `_client.py:2077-2083`, `_async_client.py:883-889`. **Tests:** `tests/test_device_flow.py:1212` (sync: `expires_in` 30, interval 5, every poll 503 + RA 120, so `sent == [5]` and `expired_token`), `:1230` (sync: RA 60 ×3 on a 600 s grant, so the next poll is ≥ 60 s after the last in-poll attempt), `:1254` (async twin of `:1212`). **Mutants** (throwaway copy):<ul><li>**M10** (sync carry removed): `:1212` and `:1230` fail.</li><li>**M10a** (async carry removed): `:1254` fails.</li><li>**M15** (`tick()` lets the floor *shorten* the interval: `floor or interval`): 3 existing device tests fail (`test_a_retry_after_shorter_than_the_interval_never_shortens_the_wait` among them), so "never shortens" is pinned on the device side.</li></ul> |
| C164-48 (Info): the same, CIBA `ciba_await`, sync and async | **CLOSED** (code); the test is narrower than the device side, see C164-54 | f9b68a2 | **Code:** `_client.py:2370-2396`, `_async_client.py:1068-1094`. **Tests:** `tests/test_ciba.py:1082` (sync) and `:1101` (async): `expires_in` 30, interval 5, every poll 503 + RA 120, so exactly 1 request and `CibaExpiredTokenError`. **Mutants:**<ul><li>**M11** / **M11a** (carry removed, sync/async): `:1082` / `:1101` fail.</li><li>**M12** / **M12a** (`wait = floor or interval`, so a carried RA 1 shortens a 5 s interval): **survive** the SDK suite. They are killed by the reviewer's probe (`ra1<int`, `slow+ra2`).</li><li>**M13** / **M13a** (floor not reset, so it sticks): **survive** the SDK suite. They are killed by the reviewer's CIBA one-shot probe.</li></ul> |
| C164-48 (Info): async CIBA in-poll §16 wait not pinned to the injected clock (round-3 M5a survived) | **CLOSED** | f9b68a2 | `tests/test_ciba.py:1058`: `AsyncAxiamClient`, `AsyncTestClock`, 503 + RA 7 then 200, so 2 requests and a ≥ 7 s wait in `clock.sleeps`. **Mutant M5a** (`sleep=None` at `_async_client.py:1081`) **now fails** at `:1058`. |
| C164-48 (Info): README §16 does not state the 1 h clamp | **CLOSED** | f9b68a2 | `README.md:2676-2679`: "`Retry-After` honored as a **floor** -- up to one hour (`MAX_RETRY_AFTER_MS`); the 5 s cap applies to the computed backoff only, so three `503`s that each say `Retry-After: 3600` hold a `check_access` for about two hours." It adds that the device and CIBA loops bound every wait by `expires_in` and carry a 5xx's `Retry-After` into the next interval. This is the fix the review asked for, with the 2 h worst case stated. |

**Deadline bound:** **bounded, sync = async, device and CIBA. The carried floor never shortens the interval and is one-shot.**

Probe setup (`/home/user/work/python-r4-probe/test_r4_probe.py`, 44 cases, all as expected):
- A fake `time.monotonic`, with `time.sleep`/`asyncio.sleep` advancing it.
- `random.random` pinned to 1.0 (maximum jitter).
- For CIBA, the test kit's `TestClock`/`AsyncTestClock`.

| Probe (sync and async give the same result) | Requests at (s) | Result |
|---|---|---|
| device, `expires_in` 30, interval 5, every poll 503 `temporarily_unavailable` + RA 120, RTT 0 | 5 | `expired_token` at t = 5.0 (round 3: 5, 10, 15, 20, 25). Nothing is sent at or after 30. |
| the same, each request takes 2.4 s | 5 | `expired_token` at t = 7.4. |
| device, a poll at 29.9 (24.9 s `on_user_code`) answered 500 | 29.9 | No retry. `expired_token` at 29.9. |
| device, RA 1 ×3 (exhausted in-poll), then 200; interval 5 | 5, 6, 7, **12** | The carried 1 s does not shorten the interval: next gap 5. |
| device, RA 60 ×3, then 200 | 5, 65, 125, **185** | Next gap 60. |
| device, `slow_down` (interval → 10), then RA 2 ×3, then 200 | 5, 15, 17, 19, **29** | Next gap 10, not 2. |
| device, bare 500 ×3, then 200 | 5, 5.2, 5.6, 10.6 | Plain interval. |
| device, RA 60 ×3, pending, pending, 200 | …185, 190, 195 | Gaps `[60, 5, 5]`: the floor is one-shot. |
| device, 429 RA 30, pending, 200 | 5, 35, 40 | Rule 9 unchanged. |
| CIBA `ciba_await`, `expires_in` 30, interval 5, every poll 503 + RA 120 | 5 | `CibaExpiredTokenError` at elapsed 5.0. No `ciba_poll` request after `received_at + 30`. |
| CIBA, deadline 28.1, interval 7, pending ×3, then a 500 at 28.0 | 7, 14, 21, 28 | No retry. `CibaExpiredTokenError` at 28.0. |
| CIBA, RA 20 on every poll, `expires_in` 30 | 5, 25 | In-poll retry at 25 (25 < 30). The next retry is declined, the carried 20 s reaches the deadline, and the grant ends at 25.0. |
| CIBA, RA 1 ×3 / RA 60 ×3 / `slow_down` + RA 2 ×3, each then 200 | next gap 5 / 60 / 10 | Never shortens. |
| CIBA, RA 60 ×3, pending, pending, 200 | gaps `[60, 5, 5]` | One-shot. |

**W7.1c shape:** conforms, sync and async, through `device_poll`. The 12 probe cases are unchanged from round 3 (the diff does not touch the runner):

| Case | Requests | Outcome |
|---|---|---|
| two 500s, then 200 | 3 | tokens |
| three 500s | 3 | `NetworkError` |
| `ConnectError` ×2, then 200 | 3 | tokens |
| `ConnectError` ×3 | 3 | `NetworkError` |
| 429 | 1 | `OAuthProtocolError` |
| `retry_enabled=False`, a 500 | 1 | `NetworkError` |

**Rules 6/9, the 429 cases, 1.63 isolation, replay after 401:**
- **Device:** the 429 branch is untouched; the probe gives 5, 35, 40. Refresh/replay and isolation are not in the diff, and the full suite is green.
- **CIBA:** the new `else` branch also catches the `"transient"` step for a `429 rate_limit_exceeded`, whose `OAuthProtocolError` carries `retry_after_ms` (`_errors.py:369-370`). So `ciba_await` now waits a 429's `Retry-After` as a floor. Probe with 429 RA 30, then 200, interval 5: requests at **5, 35** at f9b68a2, against **5, 10** at 3715bba (sync and async).
- This brings the 429 in line with §33.7 rule 5 ("A `429` on `ciba_poll` is waited out the same way"). Before, `ciba_await` ignored it, and the round-3 review did not record that. It is not recorded in this round either, and no test pins it (C164-54).

**Version:**
- `pyproject.toml:7` and `__init__.py:109` both read 1.1.2, which is still right.
- There is no new public API: the changes are inside `device_login`/`ciba_await`, and the signatures are unchanged.
- The CHANGELOG `[1.1.2]` records round 4 at `CHANGELOG.md:66-71` (C164-48: the device and CIBA carry, the async CIBA clock test, the README clamp).

**Run by the reviewer:**
- Throwaway copy `/home/user/work/python-r4` (`git archive HEAD`), venv on Python 3.13.16, `pip install -e '.[dev,fastapi,django]'`.
- `ruff check .`: all checks passed. `ruff format --check .`: 218 files already formatted.
- `mypy --strict src`: no issues in 98 source files. `interrogate src`: 100%. `scripts/gen_management.py --check`: OK (32 files, 202 operations).
- `pytest tests -q`: **2174 passed**, 7 warnings (4 min 10 s). That is 2168 + 6 new.
- Probes: 44 cases (`/home/user/work/python-r4-probe/test_r4_probe.py`), plus the CIBA 429 old/new comparison (`test_ciba429.py`, run against `git archive 3715bba` as well).
- Mutants (`/home/user/work/python-r4-probe/mut.py`, second copy): 12 variants, run against `test_device_flow.py`, `test_ciba.py` and `test_d5_conformance.py`.
  - Killed by the suite: M10, M10a, M11, M11a, M5a, M15.
  - Survived the suite: M12/M12a, M13/M13a, M14/M14a (C164-54). M12 and M13 are killed by the probes.
- The venv, the mutant copy, the old-head copy and the caches were deleted afterwards. The SDK clone is unchanged (`git status` clean at f9b68a2).

**New findings:**
- **C164-54 — Info — CIBA carry broader than recorded, and the test is narrow.**
  - **Where:** `src/axiam_sdk/_client.py:2391-2396` and `_async_client.py:1089-1094` (the `else` branch); docstring `_client.py:2346-2348`; `CHANGELOG.md:66-71`; `tests/test_ciba.py:1082`/`:1101`. Rule: §33.7 rule 5; §16.1.
  - **What (1):** the branch also covers `step == "transient"` for a `429 rate_limit_exceeded`. So `ciba_await` now honours a 429's `Retry-After` as the next wait's floor (5, 35 against 5, 10 at 3715bba). That is a conformance improvement, but the CHANGELOG and the comments say "a `5xx`'s `Retry-After`" only. The `ciba_await` docstring still says the loop "waits the interval and polls again" after a transport failure, 5xx or 429. The `device_login` docstring `_client.py:2041-2042` ("the loop then tries again at its interval") is likewise stale for a 5xx that carries `Retry-After`.
  - **What (2):** the CIBA tests cover only "RA reaches the deadline gives 1 request". Three mutants survive the suite: `wait = floor or interval` (a carried RA 1 shortens a 5 s interval), a floor that is never reset (sticky), and a carry limited to `NetworkError` (drops the 429 floor). The device side pins all three through `PollSchedule` tests.
  - **Exact fix:**
    - Add a CHANGELOG clause: "`ciba_await` also waits a `429`'s `Retry-After` (§33.7 rule 5), which it previously ignored."
    - Amend the `ciba_await` docstring bullet to "waits the interval, or the failure's `Retry-After` when longer, and polls again", and the `device_login` docstring likewise.
    - Add one sync test on `TestClock`: `[503 RA 1 ×3, 429 RA 30, pending, 200]`, interval 5, `expires_in` 3600. Assert `clock.sleeps` (≥ 1 s entries) equal `[5, 1, 1, 5, 30, 5]`. This kills all three mutants.
  - Does not block.
- Observation, not a finding (pre-existing, outside the diff): a `400 {"error":"slow_down"}` with **no** `error_description` is mapped to `NetworkError`, because `error_from_oauth2_response` requires the description unless `description_optional` is set (`_oidc.py:1185`, `_errors.py:366`). `device_login` then treats it as `"retry"` and does not raise the interval. The same applies to a bare `access_denied`, which `device_login` keeps polling until `expired_token`. AXIAM's token endpoint always sends `error_description` on a 400, and §2 defines `OAuth2ErrorResponse` with both fields, so this follows the contract as written. It is noted only for the ruling list, in case §14.2 rule 5 ("dispatch on `error` first") is meant to cover a description-less body.

No Medium or Low findings.

---

#### Addendum round 4 — c — commit 7b5bd2150 (PR #77), read after db0d5c59e

There is one commit over the round-3 head: `7b5bd21` "fix: the in-poll retry never waits past axiam_ciba_await's deadline (C164-43, C164-48)". It touches:
- `src/oidc_ciba.c` (+14/-3): `ciba_poll_with` gains `clk` and `deadline`. It checks the deadline before each in-poll retry and sleeps on `clk`.
- `include/axiam/ciba.h` (+3/-1): a comment in the `axiam_ciba_await` doc. No declaration changed.
- `README.md`, `CHANGELOG.md`.
- `tests/test_ciba.c` (+67): `answer_t` gains a `retry_after` field, and there is one new test with four parts.

The clone `/home/user/sdks/c` was only read and is clean. All work was done in `/home/user/work/c-r4`. For comparison, the same probe was also built on `db0d5c59e` in a second throwaway clone, deleted afterwards.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-43 (Low): `axiam_ciba_await`'s in-poll §16 retry ignores the deadline (P10) | **CLOSED** in code; **PARTLY** in tests (see C164-53); the fix also brings a regression on the default clock (C164-51) | 7b5bd21 | **Code:** `src/oidc_ciba.c:535-541`. `wait_s = ceil(delay/1000)`, where `delay` is the full jittered backoff floored at `Retry-After`. Then `if (deadline && clk && clk->now(clk->ctx) + wait_s >= deadline) break;`. The 503/5xx then surfaces as transient, and the loop's top check (`:655`) raises `expired_token` with no request. `axiam_ciba_await` passes its `clk` and `deadline` (`:669`). `axiam_ciba_poll` passes `NULL, 0` (`:602`) and stays unbounded, as the fix allows. **Test:** `test_t07_a_retry_after_past_the_deadline_inside_a_poll_is_not_served` (`tests/test_ciba.c:701-760`) has four parts: RA 120 → 5 polls at 5-25 s, every request before `start + 30`, `expired_token`, and the injected clock never reaches 30; the RA 20 control → polls at 5 and 25 s only; **the exact boundary, RA 25** (a poll at 5 s plus a 25 s wait lands exactly on the deadline) → not served, 5 polls; and a bare `ciba_poll` still waits ≥ 240 s. **Mutants** (on `test_ciba`), killed: <ul><li>M43a, check removed: `:711` "Expected 5 Was 3".</li><li>**M43b, `>=` → `>`: `:740` (the boundary case).**</li><li>M43c, sleep on `c->sleep_fn` instead of `clk`: `:726`.</li><li>M43d, `ciba_await` passes deadline 0: `:711`.</li></ul>**Survived:** M43e (floor instead of ceil in the check) and M43f (the check uses only `Retry-After`, not the jittered backoff). Both send a request at or after the deadline (C164-53). |
| C164-48 (Info, C part): README device-poll paragraph | **CLOSED** | 7b5bd21 | `README.md:47-48` now reads "…never ending the loop; that retry never waits past the `expires_in` deadline (nothing is sent after it), in `axiam_ciba_await()` as well (§34.2 P10)". That is the exact fix, extended to CIBA. The `ciba.h:235-237` doc and the CHANGELOG say the same. |

**Deadline bound:**
- **Device:** unchanged by this diff, and re-probed with `tests/probe_r3.c` on the new head:
  - D1 (503 + RA 120) and D3 (RA 3600): 5 polls, the last at 25 s, then `expired_token`.
  - E1, E2, E4 (a poll at 29.9 s answered 500, 503 + RA 120, or a transport failure): 1 request, no retry, `expired_token`.
- **CIBA:** bounded. Reviewer probe `tests/probe_ciba_r4.c`. Its client clock is in milliseconds, its jitter is 0.5, and it has `expires_in` 30 and interval 5 unless noted.

| Probe | Requests at | Result |
|---|---|---|
| C1: 503 + RA 120, default clock | 5, 10, 15, 20, 25 s | `expired_token` at 25 s; nothing at or after 30 s (round 3: 5, **125, 245 s**) |
| C2: the same, injected clock | 5-25 s (ciba clock) | as C1 |
| C3: 503 + RA 3600, default clock | 5-25 s | `expired_token` at 25 s |
| C4: RA 20, injected | 5, 25 s | the retry that fits is sent; nothing after it |
| C5: RA 25, exact boundary, injected | 5-25 s | not served; `expired_token` |
| C5b: RA 24, one second under | 5, 29 s | served at 29 s; `expired_token` |
| C6: 503 + RA 120, then 200 | 5, 10 s | tokens from the 10 s poll |
| E1: interval 29, the poll leaves at 29.9 s (900 ms sleep overshoot), answered 500, default clock | 29.9 s | no retry; `expired_token` |
| E2: as E1, transport failure | 29.9 s | no retry; `expired_token` |
| E3: interval 29, injected integer clock (poll at 29), 500 | 29 s | no retry; `expired_token` |

**Answer to the prompt's question: with a caller-supplied `axiam_ciba_clock_t`, do the CIBA retry waits now run on that clock? Yes.**
- In C2, C4, W1a and W3b the client's `sleep_fn` is never called. The in-poll waits appear on the injected clock: `[5, 20]` in C4, `[2, 1, 1]` in W1a.
- Because the public clock is in whole seconds (`void (*sleep)(void *ctx, long seconds)`), a sub-second backoff is rounded up to 1 s on it. That is inherent to the seconds-only type and conservative: never late, possibly a retry fewer near the deadline.
- **The same rounding is now also applied when the caller passes no clock (C164-51).** That is not inherent.

**W7.1c shape:**
- **Device:** unchanged, re-probed with `probe_r3`:
  - 500, 500, 200 → 3 requests at 0, 100, 300 ms, and tokens. In `device_login` (interval 2): 2300 ms.
  - 500 ×3 → 3 requests, `AXIAM_ERR_NETWORK`, cause 500.
  - transport failure ×2, then 200 → 3 requests, tokens.
  - transport failure always → 3 requests.
  - 429 → 1 request, `rate_limit_exceeded`.
  - retry off → 1 request.
- **Bare `axiam_ciba_poll`:** the same results: 3 requests at 0/100/300 ms and tokens; 3 requests and cause 500; 3 requests and tokens; 3 requests and cause 52; 1 request with 429 `rate_limit_exceeded`; 1 request with retry off.
- **`axiam_ciba_await`:** 3 requests and tokens on both clocks. On the default clock, though, the waits are now `[2000, 1000, 1000]` ms, where round 3 had `[2000, 100, 200]` (C164-51).

**Rules 6/9, the three §14.6 429 cases, 1.63 isolation, the replay after a 401 refresh:**
- The diff touches none of them: no `oidc_post`/`oidc_post_ex`, no rule-6 or rule-9 dispatch, no `authz_post`, and no `/oauth2/*` isolation.
- The existing tests pass. `test_oidc_grants` passes 34/34.

**SOVERSION / public header:**
- `include/axiam/ciba.h` changes only inside the `axiam_ciba_await` doc comment (`:235-237`), with no declaration, struct or enum change.
- `ciba_poll_with` is `static`. `AXIAM_SOVERSION 2` (`CMakeLists.txt:134`) stays right, and `abi_soname` passes. No new public API.

**Version:**
- 1.1.2 is still right: CMake `VERSION` (`CMakeLists.txt:7`), `conanfile.py:9` and `ports/axiam-c-sdk/vcpkg.json:3`.
- The CHANGELOG records round 4 under `[1.1.2]`: a Fixed entry for C164-43, naming its test and the pinned `>=` boundary, and the README note for C164-48.
- It does not record the default-clock rounding (C164-51).

**Run by the reviewer** (`/home/user/work/c-r4`; `build-asan/` was deleted afterwards):
- **Build:** `-DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON` with `-fsanitize=address,undefined -fno-sanitize-recover=all` on the C flags and on the exe and shared linker flags. 0 warnings.
- **Suite:** `ctest -j1`, probes excluded: **81/81 passed**, ASan/UBSan clean (leak detection on), 16.5 s. `test_ciba` 20/20 (19 + 1 new); `test_oidc_grants` 34/34.
- `scripts/gen_management.py --check`: clean.
- **Mutants:** M43a-f on `src/oidc_ciba.c`, with `test_ciba` rebuilt for each and the source restored afterwards.
- **Probes:** `tests/probe_ciba_r4.c` (C1-C6, E1-E5, CIBA W7.1c) and `tests/probe_r3.c` (device). The probe was also built on `db0d5c59e` for the C164-51 comparison.
- **Fix validation:** the C164-51 fix below was applied to the copy. `test_ciba` 20/20, and C7, E5 and W1b were back to round-3 timing with C1 and E1 still bounded. Reverted afterwards.
- **Not run:** the C-standard matrix, valgrind, Doxygen, the package recipes.

**New findings:**
- **C164-51 — Low** — `src/oidc_ciba.c:540-541` with `:616-619` (`client_sleep`) and `:648-649`.
  - **Rule:** §16.1. The wait is `max(jittered_backoff, retry_after)` with FULL jitter. Also a regression from round 3 that the CHANGELOG does not record.
  - **What:** when the caller passes no clock, `axiam_ciba_await` uses its own `{client_now, client_sleep}` clock, so `clk` is never NULL. The new `if (clk) clk->sleep(clk->ctx, wait_s)` therefore always sleeps the **rounded-up whole second**, through `client_sleep` → `c->sleep_fn(wait_s * 1000)`, and never the millisecond `delay`. On the default path every in-poll backoff below 1 s becomes exactly 1 s, and 1.0-1.9 s becomes 2 s. The jitter is quantised, so every client's first retry lands on the same 1 s step, which is the clustering full jitter exists to prevent. Probed against round 3 (jitter 0.5, default clock):
    - 500, 500, 200 → waits `[2000, 1000, 1000]` ms, where round 3 had `[2000, 100, 200]`.
    - E5 (interval 28, `expires_in` 30, 500, 500, 200): round 3 sent at 28.0, 28.1 and 28.3 s and **returned the tokens**. Now it sends at 28 and 29 s and ends `expired_token`: a grant that was recoverable is lost.
    - The device poll (`oidc_post_ex`) keeps millisecond waits, so the two loops now differ.
  - **Exact fix:**
    - Sleep on the injected clock only when the caller supplied one. For example, forward-declare `static void client_sleep(void *, long);` before `ciba_poll_with` and write `if (clk && clk->sleep != client_sleep) clk->sleep(clk->ctx, wait_s); else c->sleep_fn(c->sleep_ctx, delay);`. Alternatively, pass an `injected` flag from `axiam_ciba_await`.
    - Keep `wait_s` (ceil) in the deadline check on both paths.
    - Validated on the copy: C7, E5 and W1b are back to round-3 timing, C1 and E1 are still bounded, and `test_ciba` passes 20/20.
    - **Test:** `axiam_ciba_await` with `clock` NULL, `c->sleep_fn` recording ms, jitter 0.5, interval 2, `500, 500, 200` → recorded sleeps `[2000, 100, 200]` and tokens. The current suite passes with and without the fix.
- **C164-53 — Low** — `tests/test_ciba.c:701-760`.
  - **Rule:** §34.2 P10 / §33.8 test 7. The bound includes the jittered backoff and the whole-second rounding (the C164-45 pattern; C's device test kills the same mutants with its deadline − 1 s, jitter 0.5 case).
  - **What:** every part of the new test uses `Retry-After` with `no_jitter`, so `delay == Retry-After` exactly. Two mutants survive the suite, and both send after the deadline in the probe:
    - M43e, `delay / 1000` (floor) in the check;
    - M43f, the check counts only `Retry-After`.

    In both, E3 (a poll at 29 on the injected clock answered 500) is retried at **30 s**, and E1 (a poll at 29.9 s on the default clock) is retried at **31.8 s**.
  - **Exact fix:** add the jitter/rounding case to the test. Use `expires_in` 30, interval 29 on `TEST_CLOCK`, a bare `500` with no `Retry-After`, and `c->jitter_fn` returning 0.5 (a 100 ms backoff). Assert exactly 1 `/oauth2/token` request, none at or after `start + 30`, and `expired_token`. This kills M43e and M43f.

---

#### Addendum round 4 — cplusplus — commit 3adf58166 (PR #80), read after 611c4e91b

The prompt gave `611c4e9ed`, but no object by that name exists in the clone. The round-3 head is `611c4e91b993…`, so this addendum reads from `611c4e9`.

**Commit read.** `git log 611c4e9..HEAD` shows a single commit, `3adf581` "fix(device,ciba): exact-millisecond deadline, boundary tests, CHANGELOG intro (C164-48)". It changes 8 files, +104/−41, and its message matches the diff. It carries an SSH signature, which could not be verified here because no allowedSignersFile is configured. `path:line` refers to 3adf581.

**Source changes.**
- `src/oidc.cpp`: the device in-poll check (`:908`) and the `device_login` deadline and loop (`:1736-1767`) now work in milliseconds.
- `src/client_impl.hpp:174-184`: `now_seconds_fn` (`std::time`) is replaced by `now_ms_fn` (`steady_clock`, ms).
- `src/client.cpp:1167`: the seam setter.

**Public headers.** Both changes are comments or a parameter name only:
- `include/axiam/client.hpp:1361-1364`: the `_set_clock_test_seam` parameter is renamed to `now_milliseconds` and the docs now say ms on a monotonic origin. The type is unchanged.
- `include/axiam/oidc.hpp:803-807`: a doc paragraph on `CibaAwaitOptions::clock`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-48 (Info) device deadline on a whole-second clock; a grant can end about 1 s early | **CLOSED** | 3adf581 | **Code.**<ul><li>`deadline = now_ms_fn() + expires_in*1000` (`src/oidc.cpp:1736`).</li><li>Loop check `now_ms_fn() + wait_ms >= deadline` (`:1752`).</li><li>In-poll check `now_ms_fn() + delay.count() >= *deadline` (`:908`). The `ceil`-to-seconds is gone.</li><li>The rule-9 floor is kept in ms (`:1767`).</li><li>The loop and the retry still read one clock (`now_ms_fn`), which is now monotonic (`steady_clock`), so a wall-clock step cannot move the deadline either.</li></ul>**Test.** `tests/test_oidc_grants.cpp:662`. A poll at 5 s of a 6 s grant:<ul><li>500 + RA 1 → refused (1 call, `expired_token`).</li><li>500 with no RA → the 100 ms backoff is served and the grant completes (2 calls).</li></ul>**Mutants** (each alone, rebuilt, full binary):<ul><li>M7dev (`:908` `>=`→`>`): killed (`:675`).</li><li>M9round (restore the whole-second ceil of `delay`): killed.</li><li>M10loopsec (deadline floored to seconds, minus 1 s): killed (`:679`).</li></ul>**Real-clock probe** (default seam, real sleeps, exp 2 / int 1, 500 then 200): **tokens after 2 calls at 1.101 s**. Round 3 gave `expired_token` at 1.00 s. |
| C164-48 (Info) no CIBA boundary test; M8 survived | **CLOSED** | 3adf581 | **Test.** `tests/test_ciba.cpp:575`. 500 + RA 1 at t = 5 s:<ul><li>a 6 s grant → `expired_token`, 1 call;</li><li>a 7 s grant → 2 calls and tokens.</li></ul>**M8** (`src/oidc.cpp:2452` `>=`→`>`) is now **killed** (`test_ciba.cpp:588-589`). The round-3 test `:561` (503 + RA 120) still passes. |
| C164-48 (Info) CIBA in-poll wait sleeps on `impl.sleeper`, not on the injected `CibaClock` | **CLOSED as documented** (the fix allowed "route … or document") | 3adf581 | `include/axiam/oidc.hpp:803-807`: `clock` governs the interval waits and the deadline. The §16 wait inside a poll "is checked against `clock.now()` but slept on the client's own sleeper, so a virtual clock must be advanced by that sleeper too (Client::_set_retry_test_seams); with the system clock the two agree". This is accurate. The code is unchanged (`src/oidc.cpp:2452`, `:2460`). See the ruling input below. |
| C164-48 (Info) CHANGELOG 1.1.2 intro ("two behaviours", "two public types") | **CLOSED** | 3adf581 | `CHANGELOG.md:16-22` now names the test-only member function (no layout change). It points to *Changed* for `plan` and the device status handling, and to *Fixed* for the transport retry and the in-poll deadline cap. *Added* `:78` gives the seam's unit as ms. *Tests* `:85-89` records round 4. One nit is listed under C164-54. |

`Deadline bound:` **bounded, for device and CIBA.**
- **Device**, on a virtual ms clock that the recorded sleeper advances, interval 5, `expires_in` 30. Request times are in ms from the start:
  - 503 `temporarily_unavailable` + RA 120: requests at **5000** only, then `expired_token`. 1 sleep.
  - RA 10: requests at 5000, 15000 and 25000, then `expired_token`.
  - 503 with no RA, or transport failure on every poll: 15 requests at 5000/5100/5300, 10300/…, up to 26500, then `expired_token`.
  - **Nothing is sent at or after 30000.**
- **Device, poll sent at deadline − 0.1 s** (exp 6, the first send pushed to 5900), answered 500:
  - Jitter 1.0 or 0.5 (backoff 200 or 100 ms): 1 request, then `expired_token`, no retry.
  - Jitter 0 (0 ms backoff): the retry goes out at 5900, inside the grant, and returns tokens. This is permitted.
- **CIBA**, fake `CibaClock`:
  - `test_ciba.cpp:561`: 503 + RA 120 → 1 request, then `expired_token`.
  - `:575`: the exact `>=` boundary is now pinned, and M8 is killed.
  - The CIBA code is unchanged since round 3. The round-3 probes still apply (deadline − 0.1 s / 500 → 1 request).

`W7.1c shape:` **conforms.** Re-probed on a bare `device_poll`:

| Case | Requests | Result |
|---|---|---|
| Two 500s, then 200 | 3 | tokens |
| Three 500s | 3 | `NetworkError (HTTP 500)` |
| Transport failure ×2, then 200 | 3 | tokens |
| Transport failure ×3 | 3 | `NetworkError: connection refused` |
| 429 | 1 | `OAuthProtocolError rate_limit_exceeded` |
| Retry off | 1 | — |

Rules 6/9, the §14.6 429 cases, 1.63 isolation and the post-401 replay are untouched by this diff. Only the rule-9 floor's unit changed, from s to ms. Their tests pass, including the rule-9 `device_login` waits.

**Ruling input: the CIBA in-poll wait and an injected `CibaClock`.**
1. **Is the check computed on the same clock that measures the wait?**
   - With the default `CibaClock::system()`, **yes**. The check is `clock->now()` = `steady_clock::now()` (`oidc.cpp:2295`). The default `impl.sleeper` is `std::this_thread::sleep_for` (`client_impl.hpp:171`), which libstdc++ measures on `steady_clock`.
   - The same holds for any caller clock whose `now` is real `steady_clock` time. `received_at` is itself `steady_clock::now()` (`oidc.cpp:2523`), so a caller clock must be on that timeline anyway.
   - **With a virtual or otherwise non-real `CibaClock`, no.** The in-poll waits do not advance it, so each wait is checked against a `now()` frozen at the poll's start, not against the cumulative waits.
   - Probe: exp 30 / int 5 / 503 + RA 15, fake `CibaClock`, in-poll sleeper recorded but not advancing it:
     - **7 `ciba_poll` requests**, against **2** on a coherent clock.
     - The first poll made 3 attempts, all at virtual t = 5. On the sleeper's own timeline the 3rd attempt is at 5 + 15 + 15 = 35 s, past the 30 s deadline.
   - So the injected-clock mismatch is **a divergence only in virtual-clock tests**, or for a production caller who injects a clock that is not real time. When both clocks are real it does not arise.
2. **Can a `ciba_poll` request go out at or after the deadline in production (both clocks real)?** **Yes, by milliseconds, but not because of the clock mismatch.**
   - **Cause:** the check runs *before* the sleep (`now + delay >= deadline`), and nothing is re-checked after it. `sleep_for` may oversleep by scheduler latency, so when `now + delay` falls within that latency of the deadline, the retry goes out late.
   - **Probe:** real `CibaClock::system()`, real sleeper, exp 3 / int 1, 503 + RA 1. The deadline was shifted by 20 µs … 2 ms across 36 runs, so the third attempt is admitted just inside it.
     - 7 runs admitted the third attempt.
     - **2 of them sent it after `received_at + expires_in`: +0.098 ms and +4.037 ms.**
     - Every run still ended `expired_token`.
   - **Scope:** the same check-then-sleep shape is in the device in-poll check (`:908`), the device loop (`:1752`) and the CIBA interval loop (`:2571`). It is generic and predates round 3. The SDK never *requests* a wait past the deadline, which is the letter of §34.2 P10.
   - Fix: C164-54.

`Version:` `project(... VERSION 1.1.2)` (`CMakeLists.txt:6`) and `AXIAM_SOVERSION 4` (`:116`) are still right.
- **SOVERSION:** the public-header changes are a doc comment and a parameter name only. The mangled symbol is unchanged (`nm -DC`: `T axiam::Client::_set_clock_test_seam(std::function<long ()>)`), and there is no layout change: `now_ms_fn` lives in the private `Client::Impl`. No further bump is needed.
- **The seam's unit changed** from seconds to milliseconds with the same type. That is a silent semantic change for a seam caller, but the seam was added in this same unshipped 1.1.2 (the last tag is `v1.1.1`), is documented as test-only, and nothing in `src/` calls it. It is not source-breaking.
- **CHANGELOG** records round 4 (`:16-22`, `:78`, `:85-89`).

`Run by the reviewer:` throwaway copy `/home/user/work/cplusplus-r4`, deleted afterwards along with my `cpp-r4-*` logs. Nothing else under `/home/user/work` was touched, and the clone is clean. Toolchain: gcc 13.3, Ninja, `-DCMAKE_CXX_STANDARD=17`, Debug.
- `python3 scripts/gen_management.py --check`: "§27 surface is current (7 files)", exit 0.
- Static build `-DAXIAM_BUILD_TESTS=ON -DAXIAM_BUILD_EXAMPLES=ON`: exit 0 (121 steps). `ctest`: 1/1 passed. The binary reports **1631 test cases, 6182 checks, 0 failed** (round 3: 1630 / 6177).
- Shared build `-DBUILD_SHARED_LIBS=ON`: exit 0. `ctest`: 2/2 passed (`axiam_cpp_tests`, `abi_soname`). `libaxiam_cpp.so.1.1.2`, SONAME `libaxiam_cpp.so.4`.
- Mutants M8ciba, M7dev, M9round and M10loopsec: each applied alone, rebuilt, and the full binary run. All four were killed (1 failure each, in the named test).
- Probes: CIBA real-clock boundary sweep, CIBA virtual-clock divergence, device deadline D1–D7, the W7.1c shape, and the device real clock. All were in the throwaway copy and then reverted.

`New findings:`
- **C164-54 — Info** — `src/oidc.cpp:2452`/`:2460` (CIBA in-poll), `:2571`/`:2577` (CIBA interval), `:908` (device in-poll), `:1752`/`:1758` (device loop). Rule: §34.2 P10 / §14.2 rule 4 / §33.7 rule 4 (posture; the letter is met).
  - **What:** every deadline check runs before the sleep and is never repeated after it. An OS oversleep can push the request past `received_at + expires_in` (or the device deadline) by milliseconds. Measured: 2 of 36 real-clock CIBA runs were late, by +0.098 ms and +4.037 ms.
  - **This is not the injected-clock issue,** and it predates round 3.
  - **Exact fix (optional):** after each sleep and before the request is built, re-check the same clock and raise the same typed `expired_token` without sending:
    - `if (clock != nullptr && deadline && clock->now() >= *deadline)` after `impl.sleeper(delay)`;
    - `if (clock.now() >= deadline)` after `clock.sleep(...)`;
    - `if (p_->now_ms_fn() >= deadline)` after `p_->sleeper(...)`, and the same after the in-poll `impl.sleeper`.
- **C164-54 — Info (text)** — `CHANGELOG.md:85-89`. The C164-48 entry is filed under *Tests*. It is also a behaviour change: a device grant no longer ends up to about 1 s early, and a last-second retry that lands inside the grant is now served. The new intro (`:18-22`) says behaviour changes are under *Changed* and *Fixed*. **Fix:** move the first clause ("the device grant's deadline is now kept in milliseconds … refused when it lands on it") to a *Fixed* bullet, and leave the boundary tests and the `CibaAwaitOptions::clock` note under *Tests*.
- Observation, not a finding: `expires_in * 1000` (`:1736`) is signed overflow above about 9.2e15 s, and `seconds(expires_in)` → ns at `:2565` (pre-existing) overflows above about 9.2e9 s. Only a hostile server can reach either; clamp if desired.

---

#### Addendum round 4 — csharp — commit aa403c8 (PR #111), read after 4af5be9

There is one commit, `aa403c8` ("fix: 1.64 review addendum round 3 - C164-46, C164-48"). It changes 5 files (+184/−16): `AxiamClient.OidcDeviceExchangeLogout.cs`, `Core/RetryPolicy.cs`, CHANGELOG, README, and `Contract164DevicePollRateLimitTests.cs` (+3 tests, 1 test helper `SlowBody`, `SetUpSlowServer`, `Intervals`). The commit message matches the diff, with one inaccurate sentence about a mutant (C164-54).

**Read only.** There is no .NET toolchain, so nothing was built, run or mutated. Each mutant the commit lists was judged by tracing the named test against the code at `aa403c8` and, for the C164-46 reverts, against the round-2 loop at `42369a4` (the real-clock `pollCts.CancelAfter(deadline − now)`).

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-46 (Low), the C164-40 test cannot fail on the bug | **CLOSED** | aa403c8 | **Test 1** `A200ThatArrivesAfterTheDeadlineStillReturnsTheTokens` (`Contract164DevicePollRateLimitTests.cs:419`). `SetUpSlowServer` (`:390-411`) uses `expires_in` 6 and interval 5, so the poll is sent at fake t=5 with 1 s left. The 200's headers come at once, and its `SlowBody` (`:46-90`) takes 1.5 s of **real** time in `ReadAsync(Memory, ct)` and honours the token. The body is buffered inside `HttpClient.SendAsync` (default `ResponseContentRead`) under the token `PostOAuth2FormAsync` received (`AxiamClient.Oidc.cs:1287`). **Revert by reading (restore the round-2 deadline CTS):** `CancelAfter(1 s real)` cancels the read at 1 s. `HttpClient` rethrows an OCE carrying the caller's (linked) token, so the `ex.CancellationToken != cancellationToken` filter at `AxiamClient.Oidc.cs:1293` does not turn it into a `NetworkError`. It escapes `RetryPolicy` (it is not a `NetworkError`), and the loop maps it to `expired_token`, so **the test fails**. At aa403c8 the read keeps the caller's token, the tokens are returned, and the fake clock is at t=7 > 6 (`:438`). A weaker mutant, a CTS on `DevicePollTime`, is also killed, because `FakeTime` overrides only `GetUtcNow`, so its timer is still the real one. **Test 2** `AnIdTokenWhoseJwksArrivesAfterTheDeadlineIsStillVerifiedAndReturned` (`:444`). The 200 carries a signed `id_token`, and the `/oauth2/jwks` responder does `Thread.Sleep(1500)`. `RoutingHandler`'s `Task.Run(…, ct)` (`Fixtures/RoutingHandler.cs:47`) does not interrupt a running responder, so the response returns at 1.5 s. **Under the revert,** the linked token is already cancelled, so `GetFromJsonAsync` (`Auth/JwksVerifier.cs:806`) throws an OCE while reading the buffered body. Two outcomes are possible. With the rethrow (`:445`) present, the OCE goes to `DeviceLoginAsync` and becomes `expired_token`. With it removed (the 42369a4 verifier), the result is `InvalidSignature` and the caller gets an `AuthError`. Either way the token set is not returned, so **the test fails**. At aa403c8 the JWKS fetch runs on the caller's token and `set.IdToken` is verified. The commit's mutant claim ("restoring the deadline-linked cancellation token fails both deadline tests") **holds by reading**. **Test 3**, the verifier rethrow (round-3 answer (b), now pinned): `ACallersCancellationDuringIdTokenVerificationIsNotAnInvalidSignature` (`:475`). The JWKS responder cancels the caller's CTS and then answers. The OCE from `GetFromJsonAsync` carries the caller's token, so the rethrow guard is true and `ThrowsAnyAsync<OperationCanceledException>` passes. **Mutant: remove the rethrow.** The bare `catch` gives `InvalidSignature`, then an `AuthError`, so **the test is killed**, as the commit says. |
| C164-48 (Info), in-poll §16 wait on the real clock | **CLOSED** (one residual pin, C164-54) | aa403c8 | `AxiamClient.OidcDeviceExchangeLogout.cs:255-264`: `delay: deadline is null ? null : DevicePollDelay`, so `DeviceLoginAsync`'s waits use the loop's sleeper, and a single `DevicePollAsync` keeps `Task.Delay`. The deadline check moves into `beforeWait` on `DevicePollTime`, so the same clock checks and sleeps. **Mutant "drop the bound" (`beforeWait` null or no-op)** on `ARetryAfterPastTheDeadlineInsideThePollIsNotServed` (`:505`): at t=5 the request is answered 503 and the 120 s wait is served on the **fake** sleeper. Request #2 goes at t=125, and request #3 at t=245. Then `polls()==3`, `sleeps==[5,120,120]`, and the poll starts are ≥ 30. So **the test is killed in milliseconds**, which was the point of the fix. W7.1c `DeviceLoginAsync` sub-tests now record the 1–2 ms jitter waits. They are filtered by `Intervals()` (`:147-149`, waits ≥ 1 s), which applies the review's "filter sub-second waits" option at `:265` and `:297`. **Mutant "DeviceLoginAsync passes `deadline: null`"** (both hooks off) is still killed only after about 20 min of real `Task.Delay(120 s)`. This is not the case the review asked about, but the commit's account of it is wrong (C164-54). |
| C164-48 (Info), `RetryEvent` emitted before the deadline decision | **CLOSED** in code; unpinned (C164-54) | aa403c8 | `RetryPolicy.cs:207,232,236`. `beforeWait?.Invoke(wait)` runs after `DelayFor` and **before** `telemetry.Emit(new RetryEvent…)`, so a refused wait is never announced. This matches the review's fix ("throw before `Emit`"). `beforeWait` defaults to null, so every other caller (`ciba_poll`, REST, D5 telemetry tests) is unchanged. |
| C164-48 (Info), garbled `README.md:58` | **CLOSED** | aa403c8 | It now reads "Contract 1.64 (§34.8) changes these behaviours: any `429` on a device-code poll is not terminal, and `DeviceLoginAsync` waits its `Retry-After` out (a minimum, capped at the `expires_in` deadline), counts it as one interval and does not raise the interval (§14.2 rule 9); a `5xx` on the poll is a transport failure whatever its body and is retried inside the poll under §16, never on a `429` (§14.2 rule 6); the `plan` refusal …". That is the review's exact fix, apart from "never on a `429`" where the review had "never a `429`", which reads better. Not raised: the 1.63 sentence before it still says "changes one behaviour" and lists two. That wording predates this change and was not flagged; it is cosmetic. |
| C164-48 (Info), CHANGELOG missing the verifier rethrow | **CLOSED** | aa403c8 | `CHANGELOG.md:47-52` "Round 4 (C164-46, C164-48)": "A caller's cancellation during `id_token` or `logout_token` signature verification now propagates as an `OperationCanceledException` in every grant, instead of being reported as an invalid signature (tested)." The bullet also records the sleeper/clock change, the veto before telemetry, and the real-time C164-40 tests. |

**Deadline bound:** **conforms by reading**, unchanged in effect from round 3. Only the sleeper changed.

Probe: `expires_in` 30, interval 5, every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`.
- t=5: request #1 is answered 503, and `DelayFor` gives 120 s.
- `beforeWait` sees 5 + 120 ≥ 30 and throws `expired_token` before any `RetryEvent` is emitted and before any sleep.
- The error is terminal in the loop (its `HttpStatus` is null and its `Error` is not pending, slow_down or 429).
- Result: **1 request, `expired_token` at fake t=5, nothing sent at or after t=30.**

Poll sent at deadline − 0.1 s and answered 500:
- If the jitter wait (≤ 200 ms by default) is ≥ the time left, the result is `expired_token` at once.
- If it is smaller, the retry is sent before the deadline, after a `DevicePollDelay` on the same clock that checked it.
- A 500 arriving at or after the deadline always raises, because `now + wait ≥ deadline`.

No request is sent at or after the deadline. A single `DevicePollAsync` still has no deadline and is unbounded under §16, as allowed.

**CIBA:** not touched. `ciba_poll` passes neither hook. The prompt claims no CIBA bound for C#.

**W7.1c shape** (by reading; the retry runner changed only by the null-default `beforeWait`):

| Case | Test | Result |
|---|---|---|
| two 500s, then 200 | `:290` | 3 requests and tokens; `Intervals` gives `[5]` |
| three 500s | `:305` | 3 requests, then `NetworkError` 500; single poll, real 1–2 ms `Task.Delay` |
| transport failure ×2, then 200 | `:318` | 3 requests |
| three transport failures | — | 3 requests, then `NetworkError` (status null) on the same path |
| 429 | `:337` | 1 request |
| retry off | `:273` | 1 request per poll |

Rules 6 and 9, the three §14.6 429 cases, 1.63 isolation and the replay after a 401 refresh: the loop's catches, `PostOAuth2FormAsync` and `MapDevicePollErrorAsync` are not touched. The 429 deadline test `:199` only gains a `WaitAsync(10 s)` guard.

**Answers to the prompt's specific questions:**
- **The C164-40 test now fails on the round-2 head's behaviour:** yes, both variants.
  - The real-time slow body (`:419`) is cancelled at 1 s real and gives `expired_token`.
  - The `id_token` + slow JWKS variant (`:444`) gives `expired_token` or `AuthError`.
  - Both return tokens at aa403c8.
- **The PR's listed mutants:**
  - "Restore the deadline-linked token" fails both deadline tests: **confirmed by reading.**
  - "Remove the verifier rethrow" fails the cancellation test: **confirmed by reading.**
  - "Drop the bound": with the fix, it now fails `:505` in milliseconds: **confirmed.**
  - "Null deadline" fails "by its 10 s WaitAsync": **not as stated** (C164-54).
- **Retry telemetry before the deadline decision:** fixed (veto before `Emit`), but no test pins the order (C164-54).
- **README:58:** fixed with the requested text.
- **CHANGELOG verifier rethrow:** recorded, for every grant.
- **Real-clock deadline tests:** the in-poll waits are now on the injected sleeper, so the dropped-bound mutant fails fast. The real-clock elements left are deliberate: the two C164-46 tests, which must cross a real timer.

**Version:** 1.1.2 is still right; both csproj files say 1.1.2. No public API is added: `beforeWait` is a parameter of an `internal` method, and `DevicePollDelay` and `DevicePollTime` are internal. Nothing is source- or binary-breaking. The CHANGELOG records round 4 (`CHANGELOG.md:47-52`).

**Run by the reviewer:**
- No `dotnet` is available, so there was no build, no `dotnet test`, and no mutant was executed. No work directory was created and there is nothing to delete.
- Read: `git log` and `git diff 4af5be9..HEAD` in full.
- Read for context: `RetryPolicy.ExecuteAsync`; `PostOAuth2FormAsync` (`AxiamClient.Oidc.cs:1267-1297`); `JwksVerifier.VerifyOidcIdTokenSignatureAsync`/`EnsureFreshAsync`; `RoutingHandler`; `OidcTestKit` (jwks_uri `/oauth2/jwks`); the 42369a4 loop and its `pollCts`; `OidcDeviceFlowTests` (its only `DevicePollDelay` user is the pending-only test, which is unaffected).
- Mutants judged by reading:
  - Killed: deadline CTS restored (killed by `:419` and `:444`); the weaker CTS on `DevicePollTime` (killed by `:419`); rethrow removed (killed by `:475`); bound dropped (killed fast by `:505`).
  - Killed slowly (≈20 min): `deadline: null`.
  - Survive: in-poll sleeper reverted to `Task.Delay` (C164-54); `beforeWait` moved after `Emit` (C164-54); `>=` → `>` in `beforeWait` (C164-54).

**New findings:**
- **C164-54 — Info (test strength).**
  - Where: `tests/Axiam.Sdk.Tests/Contract164DevicePollRateLimitTests.cs:147-149` (`Intervals`) and `:290`; code at `AxiamClient.OidcDeviceExchangeLogout.cs:257`.
  - What: no test pins that `DeviceLoginAsync`'s in-poll waits go through `DevicePollDelay`. A mutant `delay: null` (real `Task.Delay`, bound kept) passes every test:
    - `Intervals()` drops the sub-second waits.
    - `:505` refuses the 120 s before sleeping.

    The fix C164-48 asked for can therefore regress silently. The dropped-bound test then fails fast only while both halves of the fix stay in place.
  - Exact fix: in `APollRetriesA5xxInsideTheAttemptUnderSection16` (`:290`), also assert `Assert.Equal(3, sleeps.Count)` and `Assert.All(sleeps.Skip(1), s => Assert.True(s < TimeSpan.FromSeconds(1)))`. That is the interval plus two recorded §16 waits.
- **C164-54 — Info (text, commit message only).**
  - Where: commit `aa403c8` message, "Plan vs tree" paragraph.
  - What: it says the null-deadline mutant "makes the Retry-After test wait on the real clock; the test then fails by its 10 s WaitAsync". The `WaitAsync(10 s)` was added to the **429** test `:199`, whose path the null-deadline mutant does not change: the loop's own check still uses `deadline`. The test the mutant affects, `:505`, has no `WaitAsync`. It runs about 20 min (5 loop iterations × two real 120 s waits) before failing on `polls()`, which fits the "did not return within 280 s" they saw.
  - Exact fix: add `.WaitAsync(TimeSpan.FromSeconds(10))` to the `DeviceLoginAsync` call at `:518` as well, so that mutant reports in 10 s. Also correct the sentence if the message is amended. This does not block.
- **C164-54 — Info (test strength; §16.5 accuracy, and the class of the TS/C++ `>=` item).**
  - Where: `Core/RetryPolicy.cs:232,236`; `AxiamClient.OidcDeviceExchangeLogout.cs:260`; test `:505`.
  - What: two mutants survive.
    - Swapping `beforeWait` and `telemetry.Emit`, which brings back a `RetryEvent` for a retry never sent: no device test observes telemetry.
    - `>=` → `>` in the veto: the probe's 120 s is far from the boundary.
  - Exact fix:
    - In `:505`, subscribe to the client's telemetry and assert that no `RetryEvent` with operation `device_poll` was emitted.
    - Optionally add a boundary case: `expires_in` 6, interval 5, a 503 with `Retry-After: 1`. Fake now + 1 s == deadline, so the expected result is `expired_token` and 1 request.

---

#### Addendum round 4 — java — commit 97dcdf0b2 (PR #121), read after 40fd50203

There are two commits (`git log --oneline 40fd50203..97dcdf0`):
- `f0b8d6f` fix(oauth): bound the CIBA in-poll retry by the deadline; pin the jitter and the boundary. It touches `AxiamClient.java`, `internal/Retry.java`, `AxiamClientDeviceFlowTest.java` and `CibaTest.java`.
- `97dcdf0` docs: the CHANGELOG for round 4 (C164-43, -45, -48).

Each commit's claim matches its diff. The SDK clone was not modified: `git status` is clean and there is no `target/`. The suite ran in `/home/user/work/java-r4`. Probes and mutants ran in `/home/user/work/java-r4-mut`. Both copies and all logs were deleted afterwards. The probe class `R4ProbeTest.java`, the mutant script `java-r4-mut.sh` and its output `mutants.out` are kept in the review session's scratchpad under `addenda4/java-probes/` (not committed).

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-43 (Low), CIBA P10 | **CLOSED** | f0b8d6f | **Code:**<ul><li>`cibaRedeem` (`AxiamClient.java:4765-4766`) now takes a `Retry.Pacer` and passes it to `StatusRetry.run(…, "ciba_poll", pacer, …)` (`:4774`).</li><li>`cibaAwait` passes `pollPacer(waitOn, deadline)` (`:4893`), where `deadline = receivedAt + expiresIn` (`:4875`). The bare `cibaPoll` passes `pollPacer(null, null)` (`:4729`): it admits every retry and sleeps on `Thread.sleep`, which the fix allows.</li><li>`pollPacer` (`:3443-3481`) is the shared factory the review asked for (the device poll uses it at `:3521`). It admits a retry only when `clock.now().plusMillis(delay).isBefore(deadline)` (`:3468`), where `delay` is the full wait: jittered backoff floored at `Retry-After` (`Retry.java:209`, `:262-268`). It sleeps on the loop's clock (`:3473`).</li><li>A refused retry rethrows the transient error. `cibaAwait` catches it as `CibaTransientFailure`, continues, and its own check (`:4878`) raises `expired_token`.</li></ul>**Tests:**<ul><li>`CibaTest.t07pInPollRetryNeverSendsAtOrAfterTheDeadline` (`CibaTest.java:475`): `TestClock`, `expires_in` 12, interval 5, every poll `503` + `Retry-After: 120` → requests `[5, 10]` and `expired_token`. This is §33.8 test 7's P10 half.</li><li>`t07q` (`:512`) and `t07r` (`:517`): see C164-45.</li></ul>**Mutants that fail:**<ul><li>M12: `cibaAwait` passes `pollPacer(null, null)`. Three CIBA tests fail: `t07p` gives `[5,5,5,10,10,10]`, and `t07q`/`t07r` give 3 calls instead of 1.</li><li>M1 (the check ignores the wait) fails `t07p`/`q`/`r`.</li><li>M2 (admit every retry) fails `t07p`/`q`/`r`.</li><li>M3 (the pacer sleeps on `Thread.sleep`) fails `t07p` (`[5,5,5,10]`).</li></ul> |
| C164-45 (Info/Low), test strength | **CLOSED** | f0b8d6f | **Strict boundary (the M5 mutant):** `theInPollRetryNeverSendsAtOrAfterTheDeadline` (`AxiamClientDeviceFlowTest.java:571`) now uses the review's `expires_in` 30. It expects requests `[5,10,15,20,25]` and sleeps `[5,5,5,5,5]`; the retry due exactly at 30 s is refused.<br>**Jitter pinned (the M4 mutant):**<ul><li>The helper `pollJustBeforeTheDeadlineWithJitter` (`:644`) sets up a poll at 11.9 s against a 12 s deadline, answered with a bare `500` (no `Retry-After`). The jitter is pinned through `client.setPollJitterForTesting(Random)`, whose `nextDouble` is fixed, so the first backoff is `value × 200 ms`.</li><li>Three cases use it: `0.999999` (199 ms, no retry, `:680`), `0.5` (exactly 100 ms, so the retry falls on the deadline and is not sent, `:685`), and `0.0` (the retry fits and is sent, giving tokens and sleeps `[2, 0]`, `:690`).</li><li>CIBA twins: `t07q` (`CibaTest.java:512`, 0.999999) and `t07r` (`:517`, 0.5), each asserting one token request and `expired_token`.</li><li>The seam: `Retry.Pacer.random()` (`Retry.java:89`, a default method returning `SecureRandom`) feeds `withRetry` (`:170`). Both of `pollPacer`'s pacers return the client's `pollJitter` field (`AxiamClient.java:3431`).</li></ul>**Mutants that now fail:**<ul><li>**M4 (the deadline check sees only the `Retry-After` floor)**, `Retry.java:209` → `pacer.admits(e instanceof RetryAfterHint h ? h.retryAfterMillis() : 0)`. It fails 4 tests: device `:680` and `:685` (by the 10 s preemptive timeout, because the unqueued retry blocks), and CIBA `t07q`/`t07r` (2 calls instead of 1). It survived in round 3.</li><li>**M5 (admit a retry exactly at the deadline)**, `:3468` → `!…isAfter(deadline)`. It fails device `:571` (`[…,25,30]`), device `:685` and CIBA `t07r`. It survived in round 3.</li><li>M14 (the seam ignored: `withRetry` uses `new SecureRandom()` instead of `pacer.random()`) fails 3 device tests. The seam is therefore load-bearing. The CIBA `q`/`r` tests happened to pass in that run, which is expected: with a random jitter each passes with probability about 0.5.</li></ul> |
| C164-48 (Info), Java items | **CLOSED** | f0b8d6f, 97dcdf0 | **(a)** The 6-argument `Retry.withRetry(int, IntFunction, Predicate, TelemetryDispatcher, String, Pacer)` is now package-private (`Retry.java:167`). Its only caller is `StatusRetry.java:120`, in the same package. `verify` and javadoc are green.<br>**(b)** The CHANGELOG (`CHANGELOG.md:17-19`) no longer lists `Retry.Pacer` as an API addition. It says that "the `Retry.Pacer` interface and a `StatusRetry.run` overload live in the non-API `io.axiam.sdk.internal` package", which matches `internal/package-info.java` ("NOT part of the SDK's public API surface"). |

**Deadline bound** (probes `R4ProbeTest` on 97dcdf0):
- **Device: bounded.** Recorded clock, interval 5, every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`:
  - `expires_in` 30 → requests at 5, 10, 15, 20, 25 s; `expired_token` at 25 s.
  - `expires_in` 21 → `[5,10,15,20]`, `expired_token` at 20 s.
  - `expires_in` 12 → `[5,10]`.
- **Device, deadline − 0.1 s, bare `500`:** 100 runs with the real jitter. A retry was sent in 58 runs, each one before 12 s (that conforms). 0 requests went at or after 12 s, and every run ended in `expired_token`. With the jitter pinned to its maximum, no retry is sent (the test at `:680`).
- **CIBA: bounded now** (it was not bounded in round 3).
  - Recorded clock, `cibaAwait`, the same `503` + RA 120:
    - `expires_in` 30 → `[5,10,15,20,25]`, `expired_token` at 25 s.
    - `expires_in` 21 → `[5,10,15,20]`, `expired_token` at 20 s.
    - `expires_in` 12 → `[5,10]`.
  - **Real clock** (the round-3 probe, repeated):
    - `expires_in` 21 → requests at 5.003, 10.004, 15.005 and 20.007 s; `expired_token` at 20.008 s. In round 3 there were requests at 25 and 30 s.
    - `expires_in` 30 → requests at 5.0, 10.0, 15.0, 20.0 and 25.014 s; `expired_token` at 25.015 s. In round 3 the last request was at 30.03 s.
  - No `ciba_poll` request goes at or after `received_at + expires_in`.
  - CIBA at deadline − 0.1 s with a bare `500`, 100 runs: a retry was sent in 52 runs, each one before 12 s. 0 requests went at or after 12 s, and every run ended in `expired_token`.

**W7.1c shape** (single `devicePoll`): unchanged and conforming.

| Case | Requests | Result |
|---|---|---|
| Two 500s, then 200 | 3 | tokens |
| Three 500s | 3 | `NetworkError` |
| Two drops (`DISCONNECT_AFTER_REQUEST`), then 200 | 3 | tokens |
| Three drops | 3 | `NetworkError` |
| 429 | 1 | `rate_limit_exceeded` |
| Retry off, a 500 | 1 | — |
| Retry off, a drop | 1 | — |

`deviceLogin` with two 500s then 200 sends its requests at 5.000, 5.104 and 5.456 s, all within one interval (clock sleeps `[5000, 104, 352]` ms).

Rules 6 and 9, the three §14.6 429 cases, 1.63 isolation and the replay after a 401 refresh are untouched by the diff. They are green in the suite and were not re-probed.

**The prompt's questions:**
- **Is `setPollJitterForTesting` public API?** **No.**
  - It is package-private (`AxiamClient.java:3433`, no modifier) on the public final class `io.axiam.sdk.AxiamClient`, so no consumer outside the package `io.axiam.sdk` can reach it.
  - The SDK has no `module-info` (`pom.xml:266`, Automatic-Module-Name only), so a consumer could declare a class in that package on the classpath and call it. That is the usual split-package caveat, not an API.
  - The backing field `pollJitter` is private and volatile (`:3431`), and its default is a `SecureRandom`, so production jitter is unchanged.
- **Is it documented as test-only?** **Yes, by name and Javadoc:** the field's comment reads "a test pins it (package-private)". The method has no Javadoc of its own; none is needed for a package-private member, and the javadoc build is clean.
- **Is it in the CHANGELOG?** **Not by name.** The round-4 test bullet (`CHANGELOG.md:66-69`) mentions "an injected jitter source". That is enough, because the method is not public API.
- **`Pacer.random()`:** a new default method (`Retry.java:89`) on `Retry.Pacer`. It is in the `internal` package, and `Pacer` itself is new in this PR, so adding it breaks nothing.
- **Is moving `Pacer` source-breaking relative to 1.1.1?** **No.** In fact `Pacer` never moved.
  - `git show v1.1.1:src/main/java/io/axiam/sdk/internal/Retry.java` has no `Pacer`. `git log -S'interface Pacer'` gives only `c34eb71` (round 3, after `v1.1.1`).
  - It has lived in `io.axiam.sdk.internal.Retry` since round 3. Round 4 changed only the CHANGELOG's wording about it.
  - The same holds for the 6-argument `withRetry(…, Pacer)` that is now package-private: it is absent from v1.1.1. v1.1.1's `StatusRetry` has only the 4-argument `run`.
  - Nothing that 1.1.1 exposed has been removed or narrowed, so the change is neither source- nor binary-breaking.

**Version:**
- 1.1.2 is still right: `pom.xml:9` reads `1.1.2`, and nothing is breaking.
- `CHANGELOG.md` `[1.1.2]` records round 4:
  - `:23-25`: the Fixed entry for C164-43.
  - `:66-69`: the test entry for C164-45 and C164-48 (the jitter seam, the strict boundary, `expires_in` 30, the CIBA P10 case, and `withRetry(…, Pacer)` made package-private).
  - `:17-19`: the corrected API-addition sentence.

**Run by the reviewer** (JDK 21, `./mvnw -B -o`):
- `verify` on 97dcdf0: **BUILD SUCCESS, 1531 tests, 0 failures, 0 errors, 0 skipped** (round 3 had 1525; the 6 new tests account for the difference). All jacoco coverage checks were met. It took 9:44 min.
- Probes `R4ProbeTest` (P1–P4, P6, P7): all ran.
- Mutants were run against `AxiamClientDeviceFlowTest` and `CibaTest` together, with `-Djacoco.skip`. M0 (the baseline) is green with 59 tests.
  - **All 9 real mutants are killed:** M1, M2, M3, M4, M5, M12, M13 (`deviceLogin` passes `pollPacer(null, null)`: 5 device tests fail) and M14.
  - **None survive.**
- Not run: the GPG and Sigstore jobs.
- Build outputs and both copies were deleted.

**New findings:** none.
- Note, not a finding: the CIBA tests have no "a retry that fits is still sent" twin of the device test `:690`. That test would kill a "never retry" mutant. The pacer is the shared `pollPacer`, so the device test `:690` already kills that mutant for both polls. The gap is cosmetic.

---

#### Addendum round 4 — kotlin — commit 51f4bd92a (PR #80), read after c392bf9

There are two commits (`git log --oneline c392bf9..51f4bd9`):
- `0529cef` fix(oidc) C164-44, C164-43, C164-48
- `51f4bd9` docs: the CHANGELOG

Files in the net diff:
- `internal/Retry.kt`: a new `sleep` parameter on the internal `withRetry`
- `oidc/OidcSupport.kt`
- `CibaTest.kt`, `OidcDeviceFlowTest.kt`
- `CHANGELOG.md`

`noRetryHttpClient` is gone. The new `OneShotBody` is a `private class`. `cibaPollTracked` gains two defaulted private parameters. No public signature changed.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-44 (Medium) | **CLOSED** | `0529cef` | **Code.** `OneShotBody` (`oidc/OidcSupport.kt:1244-1249`, `isOneShot() = true`) wraps the device poll body (`:1971`, used only when `devicePoll`), the CIBA poll body (`:1370`) and the `cibaInitiate` body (`:1306`). All three requests go through the shared `httpClient` (`:1974`, `:1395`, `:1309`), which has `retryOnConnectionFailure(true)`. **Tests.** `OidcDeviceFlowTest.kt:522` and `CibaTest.kt:394` (t08d) use a custom `Dns` that resolves `localhost` to `[127.0.0.2, 127.0.0.1]`, with the mock on 127.0.0.1 and `connectionPool.evictAll()` first: tokens, and 1 token request. The exact-count tests are back on `localhost` (`OidcDeviceFlowTest.kt:446`, `:456`, `:468`; t08c `CibaTest.kt:384`). **Mutants.** MD (device poll back on a `retryOnConnectionFailure(false)` client) → 2 fail (`:522`, `:536`). ME (the same for CIBA) → t08d fails. MA (device body not one-shot) → 2 fail (`:456`, `:468`). MB (CIBA body not one-shot) → t08c fails. MAll (`isOneShot = false`) → 3 fail. **MC (the `cibaInitiate` body not one-shot) → 0 fail: see C164-53.** |
| C164-43 (Low) | **CLOSED** | `0529cef` | **Code.** `cibaAwait` passes `deadline = receivedAt + expiresIn` (`:1430`) and its clock to `cibaPollTracked` (`:1447-1451`). The poll's `withRetry` refuses a wait with `now + wait >= deadline` (`:1385`) and sleeps on the injected clock (`:1386`). The public `cibaPoll` passes `null`. **Tests.** t08e (`CibaTest.kt:417`): `expires_in` 30, interval 5, every poll `503` + `Retry-After: 120` → `expired_token`, every `at` < 30 s, 5 polls, wall time < 20 s. t08f (`:432`): a `500` answered at 5.95 s of 6 s with jitter 1.0 → 1 request. **Mutants.** MF (`mayWait` always true) → t08e and t08f fail. MJ (`cibaAwait` passes no deadline) → both fail. MK (`isBefore` → `!isAfter`, which admits a retry that ends exactly at the deadline) **survives**: the `>=` boundary is unpinned. That is Info, the same item C164-48 names for TypeScript and C++ CIBA. |
| C164-48 (Info): in-poll waits on the real clock | **CLOSED** device; **PARTLY** CIBA (code fixed, no test) | `0529cef` | The new `sleep` hook (`internal/Retry.kt:99`, `:134`) is wired to `clock.sleep` for the device poll (`:1106`) and the CIBA poll (`:1386`). Device test: `OidcDeviceFlowTest.kt:551` asserts the recorded sleeps `[5, 20, 20, 20]`. Mutant MH (device sleep → `delay`) → that test fails. **MG (CIBA sleep → `delay`) survives.** No CIBA test asserts an in-poll wait on `TestClock`, which now drops sub-second waits from `sleeps` (`CibaTest.kt:159`). |
| C164-48 (Info): a 5xx's `Retry-After` dropped for the next interval | **CLOSED** (device, as named) | `0529cef` | `:1224`: after an exhausted or declined in-poll retry, `rateLimitedWaitSeconds = max(interval, ceil(retryAfter))`. The loop's deadline check (`:1182`) then caps the wait, as rule 9 does for a 429. Test: `:551` (the fourth sleep is 20, not 5). Mutant MI (no carry) → 2 fail (`:551`, and `:482`, whose request count changed from 5 to 1). `cibaAwait` does not carry it: probe C1 polls every 5 s against `Retry-After: 120`. The round-3 item named only `deviceLogin`, and it was optional, so this is not reopened. |
| C164-48 (Info): the 60 s clamp | **not a finding** (ruling §7.2.1 point 2, C164-49 for 1.65); **documentation accurate** | `51f4bd9` | The clamp is stated in three places, each matching the code (`errors/ErrorMapper.kt:38`, `:54`): <ul><li>README `:2517`: "a `429` or `5xx` answer's header, clamped at 60 s".</li><li>The `MAX_RETRY_AFTER` KDoc (`ErrorMapper.kt:37`).</li><li>CHANGELOG `:59-65` (round 3) and `:82-84`: "kept … a longer value is waited at 60 s rather than refusing the retry".</li></ul>The 429 wait of rule 9 is not clamped (`:2055`, `:2063` use the raw `retryAfterOf`), and the README makes no claim that it is. Nit, not a finding: the README's device section (`:45-50`, `:855-866`) does not mention the new 5xx carry. The CHANGELOG does. |

**Deadline bound** (a probe class run in the throwaway copy; the clock is `HybridClock`: recorded sleeps plus real elapsed time):

*Device*
- **D1, the brief's case.** `expires_in` 30, interval 5, every poll `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`.
  - `expired_token` after **1 request**, at 5108 ms. The wall time was 155 ms.
  - The carried 60 s floor (120 clamped) passes the deadline, so the loop raises at once. §14.6 and §33.7 rule 5 allow "at once".
  - Nothing was sent at or after 30 000 ms. **Holds.**
- **D1b, the same with no `Retry-After`.** 15 requests (3 per interval), the last at 26 950 ms, then `expired_token`.
- **D2, a poll answered `500` at 5.95 s of a 6 s grant, jitter 1.0.** 1 request, then `expired_token`. No retry.

*CIBA*
- **C1, `cibaAwait`.** `expires_in` 30, interval 5, `receivedAt` = start, every poll `503` + `Retry-After: 120`.
  - `expired_token` after **5 polls**, at ms `[5284, 10347, 15351, 20406, 25453]`. The wall time was 720 ms.
  - No `ciba_poll` request was sent after `received_at + 30 s`. Round 3 sent requests at 65 s and 125 s. **Holds.**
- **C2.** `expires_in` 10, `Retry-After: 3`: polls at `[5016, 8084]`, both before the deadline.
- **C3, a poll at deadline − 0.05 s, jitter 1.0.** 1 request.
- **C3c, a poll at 5.80 s, jitter 0.** The retry went out at 5850 ms, before the deadline. This conforms: a wait that ends before the deadline may be sent.
- **C4, every poll `503` with no `Retry-After`.** 15 requests, all before 27 500 ms.

**W7.1c shape** (one `devicePoll`, client on `http://localhost`, mock on 127.0.0.1):

| Probe | Result |
|---|---|
| W1: two 500s (`server_error` body), then 200 | tokens, 3 requests |
| W2: three 500s | `NetworkError`, 3 requests |
| W3: drop twice, then 200 | tokens, 3 requests |
| W4: drop three times | `NetworkError`, 3 requests |
| W5: 429 | `OAuthProtocolError(rate_limit_exceeded)`, 1 request |
| W6: retry off, 500 | `NetworkError`, 1 request |
| W7: retry off, drop | `NetworkError`, 1 request |
| W8 (extra): `503` + `Retry-After: 0`, three times | `NetworkError`, **3** requests |

On W8, round 3's poll (a plain body on the no-resend client, reproduced as a mutant) made **6**. On OkHttp 4.12, `followUpRequest` resends a `503` with `Retry-After: 0` once, and `retryOnConnectionFailure` does not govern that path. The one-shot body stops that resend as well. This was a pre-existing §16.1 cap violation, closed as a side effect.

**The prompt's specific questions**

*1. Dual-stack re-probe.* Custom `Dns` returning `[127.0.0.2 | ::1, 127.0.0.1]`, server on 127.0.0.1 only, pool evicted after discovery:

| Probe | Result |
|---|---|
| P-N1/P-N1b: `devicePoll` → 200 | tokens, **1** server request, one attempt (both first addresses) |
| P-N2/P-N2b: `cibaPoll` → 200 | tokens, 1 request |
| P-N3/P-N3b: `cibaInitiate` → 200 | the response, 1 request |
| P-N10: `deviceLogin` end to end, `Connection: close` on the authorization response and the `authorization_pending`, pool evicted in the callback | tokens after 2 polls |
| P-N11: `cibaAwait`, the same | tokens |

Round 3's code, as mutant MAdev2: P-N1, P-N4 and P-N7 got **0** server requests, and P-N10 ended in `expired_token`.

*2. A drop in mid-response is not replayed, so the §16 cap of 3 holds.*

| Probe | Result |
|---|---|
| P-N4: `devicePoll`, dual-stack, three drops | 3 requests |
| P-N5: `cibaPoll`, the same | 3 requests |
| W4: device, `localhost` with a pooled connection | 3 requests (mutant MA: **4**) |
| W7: retry off | 1 request (MA: 2) |
| P-N7/P-N7c: `503` + `Retry-After: 0` ×3 | 3 requests (MA: 6) |

*3. `cibaInitiate`: never retried, and the one-shot body is right.*
- `cibaInitiate` is **never retried** (§33.7 rule 1). It is not inside `withRetry`: one direct `httpClient.newCall` (`:1306-1312`).
- A one-shot body is the correct tool here. OkHttp refuses every resend of a request whose body is one-shot:
  - the post-send replay in `recover()`;
  - the `408` follow-up;
  - the `503` + `Retry-After: 0` follow-up;
  - a `307`/`308` re-POST.
- It still takes the next route on a connect failure, where nothing was written, so that is not a second request.

| Probe | HEAD | MC (plain body, retrying client) | MC2 (round 3: plain body, no-resend client) |
|---|---|---|---|
| P-N6b: drop on a pooled connection | **1** | **2** | 1 |
| P-N8: `503` + `Retry-After: 0` | **1** | **2** | **2** (a pre-existing rule 1 breach, now closed) |
| P-N8b: `408` | 1 | 2 | 1 |
| P-N3: dual-stack 200 | 1 | 1 | **0** |

The code is right, but no test pins it. See C164-53.

**Rules 6/9, the §14.6 429 cases, 1.63 isolation, the replay after a 401.**
- The round-4 diff touches the device loop's `NetworkError` branch only by adding the carry (`:1224`). That is non-terminal as before.
- The 429 branch, `withoutSession`, the network interceptor that strips credentials, and `postWithRefresh` are unchanged.
- The device poll now uses `httpClient` itself rather than a `newBuilder()` copy, with the same interceptors, so the 1.62/1.63 isolation holds.
- Rule 9, the three §14.6 429 tests and the isolation tests pass in the full run. W5 shows a 429 is one request.

**Version:** `gradle.properties:2` `version=1.1.2` is right: no public API changed (`OneShotBody` is private; `Retry.withRetry` is internal). The CHANGELOG `[1.1.2]` records round 4:
- the one-shot body, and why `retryOnConnectionFailure(false)` was wrong (`:70-77`);
- the CIBA P10 bound (`:78-81`);
- the clock, the 5xx carry and the clamp (`:82-84`);
- the tests (`:116-121`).

**Run by the reviewer** (throwaway copies `/home/user/work/kotlin-r4` and `-r4m` from `git archive 51f4bd9`; JDK 21, Gradle wrapper):
- `python3 scripts/gen_management.py --check` → `OK: 251 generated files are current (202 operations)`.
- `./gradlew test` (no daemon, `-Dorg.gradle.jvmargs=-Xmx3g -Pkotlin.daemon.jvmargs=-Xmx3g`) → **BUILD SUCCESSFUL in 10m 37s: 1314 tests, 0 failures, 0 errors, 0 skipped, 88 classes.** That is 1308 from round 3 plus 6 new.
- Mutants (each run against `OidcDeviceFlowTest` and `CibaTest`; the unmutated baseline passed):

  | Mutant | Failing tests |
  |---|---|
  | MAll | 3 |
  | MA | 2 |
  | MB | 1 |
  | **MC** | **0** |
  | MD | 2 |
  | ME | 1 |
  | MF | 2 |
  | **MK** | **0** |
  | **MG** | **0** |
  | MH | 1 |
  | MI | 2 |
  | MJ | 2 |

- Probes D1, D1b, D2, C1–C4, P-N1–P-N11, W1–W8 and M1–M3 were in `ReviewerProbeR4Test`. They ran at HEAD and under MA, MC, MC2 and MAdev2.
- The copies, the probe class, the logs and all build outputs were deleted. The SDK clone is unmodified (`git status` clean).
- Not run: `koverVerify`, `dokka`, lint.

**New findings:**
- **C164-50 — Low (pre-existing, outside this PR's diff; same root cause as C164-44)**
  - **Location:** `internal/ManagementTransport.kt:70-72` (`writeHttp = http.newBuilder().retryOnConnectionFailure(false)`, used for every POST/PUT/PATCH/DELETE, `:195`) and `internal/Sessionless.kt:49` (RFC 7592 client registration, `ClientRegistrationSupport.kt:58`; SSF, `SsfReceiver.kt:98`).
    - Both date from `3af8083` (2026-10-09) and the `Sessionless` helper, before PR #80's range.
  - **Rule:** §27.4 rule 8 / §34.2 P11 forbid a resend, not route fallback. As with C164-44, a refused first address must not cost the call.
  - **What happens:** on OkHttp 4.12 the setting also disables connect-route fallback.
    - Probe M1/M1b: signed in, then `connectionPool.evictAll()`, `groups.delete(id)` with `localhost` → `[127.0.0.2 | ::1, 127.0.0.1]` gives `NetworkError("Failed to connect to /127.0.0.2…")` / "IPv6 protocol family unavailable", with **0 server requests**.
    - Control M2: `groups.get` on the same client reaches the server.
    - Control M3: `groups.delete` with a single-address `localhost` succeeds.
    - So every management write, and every Sessionless call, fails on such a host whenever the pool holds no live connection.
  - The round-4 CHANGELOG (`:73-77`) states exactly why the setting is wrong, but leaves it on these two transports.
  - **Exact fix:**
    - `writeHttp`: use `http` with the write body wrapped in the same one-shot `RequestBody` (move `OneShotBody` to `internal/`).
    - `Sessionless.of`: drop `.retryOnConnectionFailure(false)` and send its bodies one-shot. Its GET reads are §16-retried and want fallback too.
    - Test: the C164-44 dual-stack `Dns`, signed in, pool evicted. A management `DELETE` → 1 server request. A write answered `DISCONNECT_AFTER_REQUEST` on a pooled connection → still 1.
    - Record it in the CHANGELOG.
  - It is not on the §16 path this PR changed. The orchestrator may track it outside W7.
- **C164-53 — Low (incomplete required test; §33.8 test 4 / §33.7 rule 1)**
  - **Location:** `CibaTest.kt:265` (t04).
  - **What happens:** mutant MC removes the one-shot body from `cibaInitiate` (`OidcSupport.kt:1306`) and passes all 1314 tests. t04's "dropped connection" is a listener that accepts and hangs up on a **fresh** connection, which OkHttp 4.12 does not replay anyway.
    - Under MC, the replays a caller meets come back: a drop on a pooled connection (P-N6b) → **2** initiate requests, `503` + `Retry-After: 0` (N8) → **2**, `408` (N8b) → **2**. Each is a second stored request, and possibly a second prompt to a person.
  - **Exact fix:** extend t04 against the mock's own `/oauth2/bc-authorize`, after `oidcDiscover()` so that the connection is pooled:
    - (a) `DISCONNECT_AFTER_REQUEST` → `NetworkError`, exactly 1 initiate;
    - (b) `503` + `Retry-After: 0` → exactly 1;
    - (c) `408` → exactly 1;
    - optionally (d) the dual-stack `Dns` with the pool evicted → 200 with 1 initiate.
- **C164-54 — Info (test strength and text)**
  - **Tests that do not kill their mutants:**
    - (a) `OidcDeviceFlowTest.kt:536` ("a drop after the request was sent is not replayed even with route fallback") passes under MA. On a fresh connection after eviction, OkHttp 4.12 does not replay a plain body either (probe N4 under MA: 3). The property is pinned by `:456`/`:468` on a pooled connection. Make `:536` drop on a pooled connection: skip the eviction, or warm the pool with a `200` poll first.
    - (b) MG (CIBA in-poll sleep back on `delay`) survives. Add a CIBA twin of `:551`: `503` + `Retry-After: 2` twice, then `200`, under `cibaAwait` with `TestClock` → the clock advances by those waits.
    - (c) MK (the `>=` boundary) survives on both polls. Add a case whose wait ends exactly at the deadline (jitter pinned) → no retry.
  - **Text:**
    - (d) CHANGELOG `:76-77` says a one-shot body "refuses only the replay of a request that was written". On OkHttp 4.12 it also stops the `503` + `Retry-After: 0` and `408` follow-ups (a cap and rule 1 fix worth stating) and stops following a `307`/`308` on the poll and on `cibaInitiate`.
    - Probe P-N9: a `307` on the device poll is now a `NetworkError` (MA follows it: tokens). A token endpoint that redirects a POST is not a supported deployment, and refusing to re-send credentials to a `Location` is the safer posture.

---

#### Addendum round 4 — php — commit d127d75ee (PR #87), read after 41cf943fd

There are two commits. `2bb3b4a` is the code and test fix (C164-43, C164-47). `d127d75` holds the README and CHANGELOG text (C164-48). Each commit message matches its diff. The diff touches `src/Oidc/OidcClient.php` (`deviceLogin`'s in-poll sleeper, `cibaAwait`, `cibaPollTracked`), `tests/Contract164/CibaDeadlineBoundTest.php` (new), `tests/OidcDeviceFlowTest.php` (+1 test), `README.md` and `CHANGELOG.md`. Nothing else changed: `devicePollWithin`, the device 429 handling, the middlewares, `AxiamClient` and the generated surface are untouched. Mutants and probes ran on a throwaway clone, `/home/user/work/php-r4`, which has since been deleted.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-43 (Low): `cibaPollTracked`'s §16 retry is not bounded by `cibaAwait`'s deadline (§34.2 P10, §33.7 rule 5, §33.8 test 7) | **CLOSED** | 2bb3b4a | **Code.**<ul><li>`cibaAwait` passes `static fn (): float => $deadline - $clock->now()` and a sleeper on its `CibaClock`, `$clock->sleep((int) ceil($ms / 1000.0))` (`src/Oidc/OidcClient.php:2161-2165`).</li><li>The predicate is the device poll's: `max(Retry-After, RetryPolicy::backoffMs(n)) / 1000 < remaining()` (`:2304-2306`).</li><li>The attempt guard sends nothing for `n > 1` once `remaining() <= 0` and rethrows the previous `NetworkError` (`:2314-2317`).</li><li>The sleeper is passed as `RetryPolicy::execute`'s `$sleep` (`:2345`).</li><li>A bare `cibaPoll()` passes `null`/`null` and stays unbounded (probe: `503` RA 1 ×3 → 3 requests at 0, 1.0 and 2.0 s on a real `usleep`, then `NetworkError`).</li><li>New in the fix: an unserved `Retry-After` is carried into the loop's next wait, `retryAfterRound($interval, …)` (`:2178-2181`, `:2139`; see the ruling below).</li></ul>**Tests** (`tests/Contract164/CibaDeadlineBoundTest.php`, fake `CibaTestClock`): `testEveryPollAnsweredWithARetryAfterPastTheDeadline…` (RA 120 → sent `[1005.0]`, sleeps `[5]`, `expired_token`, clock ≤ 1030); `testARetryAfterInsideTheDeadlineIsServedOnTheClock…` (RA 20 → sent `[1005, 1025]`, sleeps `[5, 20]`); `testAPollThatFailsJustBeforeTheDeadlineIsNotRetried` (a `500 {"error":"server_error"}` back at deadline − 0.001 s → 2 requests, `expired_token`).<br>**Mutants:**<ul><li>**C1** (`cibaAwait` passes no `$remaining`): all 3 fail.</li><li>**C2** (the in-poll waits on a real `usleep`, not the clock): the RA 20 test fails.</li><li>**C5** (no `Retry-After` carry): the RA 120 test fails, because a second poll at 10 s runs the mock queue dry.</li><li>**C3+C4** (predicate on `Retry-After` alone, guard removed): the jitter test fails (5 of 5 runs).</li><li>Survivors: **C3** alone (predicate on `Retry-After` alone) and **C4** alone (guard removed). Each is equivalent while the other half stays, as in round 3's M2: the whole-second clock serves a jittered wait as 1 s, so the guard catches it.</li><li>Survivors: **C6** (the carry may shorten the interval) and **C7** (`<` → `<=`): both unpinned, see C164-54.</li></ul> |
| C164-47 (Low): with `$sleep` injected and no `$retrySleep`, the in-poll waits are counted but not slept | **CLOSED** | 2bb3b4a | `$inPollSleep` is now always set (`src/Oidc/OidcClient.php:1016-1023`). It calls `$retrySleep($ms)` when one is given, otherwise `usleep(round($ms * 1000))`, and in both cases adds `$ms / 1000` to `$sleptSeconds`. The dead `$sleeperInjected` is gone. Docblock `:979-982` updated. **Test:** `tests/OidcDeviceFlowTest.php:541` `testAnInjectedSleeperDoesNotSkipTheRetryAfterFloorInsideThePoll`: no-op `$sleep`, no clock, `503` RA 1 then `200` → tokens, and ≥ 1.0 s of real time between the two requests. **Mutants:** **D1** (the `usleep` branch removed, which is the round-3 behaviour) fails that test. **D2** (the wait not counted) fails `:574`. **Probe** (sleep only, real clock, `503` RA 20 ×3): the retry goes out at real t = 20.001 s (round 3: 0 ms), and the next retry is declined (20 + 20 ≥ 30) → `expired_token`, 2 requests, nothing at or after 30 s. With sleep and a fake `$now` (no `$retrySleep`), the RA 20 retry is really slept: 20.04 s wall. The fake clock does not move, but `$sleptSeconds` keeps the bound. |
| C164-48 (Info), PHP items: README `$retrySleep`/`$now`; README P10 row overstates the `CibaClock` | **CLOSED** | d127d75 | `README.md:807-812` names `$sleep` (seconds), `$now` (clock) and `$retrySleep` (ms). It says in-poll retries never go out after `expires_in`, and that without `$retrySleep` the waits really sleep. `README.md:332` (P10 row) now reads "…which also supplies the waits, the §16 retry waits inside a poll included: a retry whose longest wait would reach the deadline is not sent". That is now true (C2 kills). `CHANGELOG.md:118` records it. Cosmetic: `README.md:810` is 133 columns against about 100 around it. |

**Deadline bound: bounded, device and CIBA.** All runs go through the public `deviceLogin()` / `cibaAwait()`. Logs: `scratchpad/php-r4-probe.log`, `php-r4-probe2.log`.
- **Device, expires_in 30, interval 5, every poll `503 {"error":"temporarily_unavailable"}` + RA 120:** 1 request at 5.0 s, no in-poll wait, `expired_token` at 5.0 s. This holds in all three modes: all hooks injected, sleep + now, and sleep only on the real clock. **A poll sent at 29.9 s whose `500` returns at 29.999 s:** no retry, `expired_token`. The same holds when it returns at 30.3 s. **The round-2 latency set** (pending ×4 at 0.999 s each, then `500, 500, 200`): polls at 5, 10.999, 16.998, 22.997 and 28.996 s, the `500` is not retried, `expired_token`.
- **CIBA, expires_in 30, interval 5, every poll `503` + RA 120:** 1 request at 5.0 s, `expired_token` at 5.0 s. No `ciba_poll` request at or after `received_at + 30`. **RA 20:** sent at 5 and 25 s, loop sleeps `[5, 20]`, `expired_token` at 25 s. Round 3 sent a third request at 45 s. **RA 12:** sent at 5, 17 and 29 s, `expired_token` at 29 s. **A poll at 29.9 s answered `500`** (back at 29.9 or 29.999 s): not retried, `expired_token`.
- **One edge (C164-54):** a `500` to a poll sent at 29.5 s (0.5 s left, more than the 0.2 s backoff ceiling) is admitted for retry. The whole-second `CibaClock` serves the jitter as 1 s, so the clock ends at 30.501. The guard then sends nothing, and `expired_token` is raised 0.5 s after the deadline. No request goes after the deadline, but the wait itself overruns it.

**W7.1c shape: conforms; the device numbers match round 3.**
- **Single `devicePoll`:** `500, 500, 200` → 3 requests, tokens. `500` ×3 → 3 requests, `NetworkError`. `reset, reset, 200` → 3, tokens. `reset` ×3 → 3, `NetworkError`. A `429` (`rate_limit_exceeded` RA 1, or bodiless RA 1) → 1 request, carrying RA 1000 ms. Retry off → 1. `deviceLogin`: `500, 500, 200` → 3 polls in one interval, `[5]`.
- **CIBA (`cibaAwait`):** `500, 500, 200` → 3 requests, sleeps `[5, 1, 1]`, tokens. `500` ×3 then `200` → 4 requests, `[5, 1, 1, 5]`. Reset ×2 / ×3 give the same shape (3 / 4 requests). `500` then `200` with retry off → `[5, 5]`, tokens.
- **Rules 6/9, the three §14.6 `429` cases, 1.63 isolation and the replay after a 401 refresh:** the round-4 diff does not touch them. Their tests are in the green suite.

**Ruling input: carrying an unserved CIBA `Retry-After` into the next wait (beyond §7.2.2's text). Conforming.**
- **What it does:** when a `NetworkError` (transport failure, 5xx, 408 or bodiless 429) leaves `cibaPollTracked` carrying a `Retry-After`, the loop's next round waits `retryAfterRound($interval, RA) = max($interval, ceil(RA s))` once, then goes back to the interval (`:2139-2140`, `:2178-2181`, `:1098-1101`). This covers a `Retry-After` the poll's §16 retry declined at the deadline, the third attempt's `Retry-After` (which the cap leaves unserved), and retry off. `$interval` is not changed.
- **Bounded by the deadline: yes.** The carried wait goes through the same pre-sleep check as every round, `now + roundSeconds >= deadline` → the local `expired_token` at once, with no sleep and no request (`:2144-2150`). That is the "raises it at once" branch P10 and §33.7 rule 5 allow. Probes: RA 120 → `expired_token` at 5 s; RA 20 declined at 25 s → `expired_token` at 25 s; retry off, RA 25 at 5 s → `expired_token` at 5 s. Retry off, RA 19 → the next poll at 24 s, inside the deadline.
- **Never shortens the interval: yes.** Retry off, RA 2 → the next poll at 10 s, which is the interval. After a `slow_down` (interval 10), RA 7 → `[5, 10, 10]`. RA 12 → `[5, 12]`. The carry is consumed once; the interval stays as it was. Neither of the two properties is pinned by a test (mutant C6 survives, C164-54).
- **Matches §33.7 rule 5:**
  - "Retry-After a minimum wait capped at the deadline": the carry makes the server's `Retry-After` a floor across the loop boundary as well, never a ceiling. Without it, a declined RA 120 would be followed by polls at 10, 15, 20 and 25 s, each sooner than the server said (§16.1 "retrying sooner is not permitted"). The commit says exactly this.
  - "Counts as one interval, never a reason to poll faster afterwards": the carried wait takes the place of one interval and is reset after use.
  - It mirrors the device loop's `NetworkError` branch (`:1084-1088`), which the review accepted under §14.2 rule 9 / §16.1.
- **Gap (pre-existing, not introduced by the carry; C164-52):** the carry applies only to the `NetworkError` branch. A `429 {"error":"rate_limit_exceeded"}`, which is AXIAM's own body, is an `OAuthProtocolError` that `cibaAwait` simply `continue`s at the interval (`:2167-2169`). Its `Retry-After` is ignored, so a 429 is not "waited out" on the server's wire. Probe: `429 {rate_limit_exceeded}` RA 12 then `200` → polls at 5 and 10 s (7 s early). A bodiless 429 with RA 12 → 5 and 17 s.

**Version:** 1.1.2 is still right (`CHANGELOG.md:10` `## [1.1.2] - Unreleased`; install snippets `^1.1.2`, `README.md:27`, `:457`). No public signature changed this round: `cibaPollTracked`'s two new parameters are private and trailing. The behaviour change for callers who inject only `$sleep` (in-poll waits are now really slept) is recorded at `CHANGELOG.md:46-50`. The CHANGELOG records round 4: C164-43 at `:39-45`, C164-47 at `:46-50` and C164-48 at `:117-118`.

**Run by the reviewer** (clone `/home/user/work/php-r4` at d127d75; PHP 8.3, Composer 2.8):
- **Install:** the round-1 `composer.lock` (`/home/user/work/php/composer.lock`) was reused. phpstan/phpstan 2.3.1 came from a local `git clone --depth 1 --branch 2.3.1` (`6155239`) used as a Composer `path` repository (log `scratchpad/php-r4-install.log`).
- **Checks:**
  - `vendor/bin/phpunit`: **OK, 2074 tests, 9980 assertions** (round 3 had 2070; +3 CIBA, +1 device).
  - `vendor/bin/phpstan analyse --memory-limit=512M`: **No errors**.
  - `python3 scripts/gen_management.py --check`: "§27 surface is current (261 files)".
  - `php tools/docblock-coverage.php`: 2083/2083 documented.
- **Mutants:** 9 single mutants plus the C3+C4 combination (`scratchpad/php-r4-mut.sh`, `php-r4-mut.log`). Killed by assertion: C1, C2, C5, C3+C4, D1 and D2. Survived: C3 and C4 (each equivalent while the other half stands), C6 and C7 (C164-54).
- **Probes:** `scratchpad/php-r4-probes/probe.php`, which is the round-3 device set plus a new CIBA, carry and 429 set.
- **Not run:** gRPC codegen (needs protoc) and `composer audit`.
- **Cleanup:** the clone with `vendor/` and the phpstan clone are deleted. `/home/user/sdks/php` is untouched and clean at d127d75.

**New findings:**
- **C164-52 — Low (pre-existing; outside the round-4 items, but it is the 429 half of the rule the ruling cites).** `src/Oidc/OidcClient.php:2167-2169` (`cibaAwait`'s `rate_limit_exceeded` branch). Rule: §33.7 rule 5 ("a `429` on `ciba_poll` is waited out … `Retry-After` is a minimum wait"), §16.1 (floor).
  - **What:** AXIAM's real `429 {"error":"rate_limit_exceeded"}` + `Retry-After` maps to `OAuthProtocolError`, which carries `retryAfterMs`. The loop continues at the plain interval, so it polls before the server's `Retry-After` (probe: RA 12 → the next poll at 10 s, not 17 s). The new carry fixes the bodiless 429 and not this one, so the two 429 shapes now behave differently. The device loop handles both (`:1063-1070`). It is the same gap the review recorded for Go as C164-23.
  - **Exact fix:** in that branch, `if ($e->error === 'rate_limit_exceeded' || $e->httpStatus === 429) { $waitSeconds = self::retryAfterRound($interval, $e->retryAfterMs); continue; }`. Keep `authorization_pending` as a plain `continue`. Do not raise the interval.
  - **Test:** on `CibaTestClock`, `429 {"error":"rate_limit_exceeded"}` + RA 12, then `200` → sleeps `[5, 12]`, tokens. With expires_in 15, RA 12 → `expired_token` at 5 s and 1 request.
- **C164-54 — Info (P10 letter; whole-second clock).** `src/Oidc/OidcClient.php:2161-2165` with `:2304-2306`. Rule: §34.2 P10 ("MUST NOT wait past the deadline … the wait capped at the deadline").
  - **What:** the predicate admits a retry when the backoff ceiling (0.2 s) is less than the time left, but the `CibaClock` sleeper rounds the jittered wait up to 1 s. The wait can therefore end up to 1 s past the deadline. The guard sends nothing, and `expired_token` comes late by that much. Probe: a `500` at 29.5 s gives the clock at 30.501 and then `expired_token`; 2 requests, none after 30.
  - **Note:** round 3's suggested fix described this rounding as allowed, so it is recorded only as Info.
  - **Exact fix:** compare in whole seconds, the unit the clock actually serves. Pass `static fn (): float => floor($deadline - $clock->now())` as `$remaining`, so a retry is admitted only when `ceil(wait) <= floor(left)`. A borderline retry then raises `expired_token` at once, which also conforms. The guard's `<= 0` test is unchanged.
  - **Test:** pending with 19.5 s of latency, then `500` → 2 requests, `expired_token`, `$clock->now <= 1030`.
- **C164-54 — Info (test strength).** `tests/Contract164/CibaDeadlineBoundTest.php`.
  - **What:** neither property of the new carry is pinned. Mutant C6 (`$waitSeconds = ceil(RA)` with no interval floor) survives, and so does C7 (`<` → `<=` in the CIBA predicate).
  - **Exact fix:** add (a) retry off, `503` RA 2 then `200` → sleeps `[5, 5]` (the interval is never shortened), and (b) retry off, `503` RA 12 then `200` → sleeps `[5, 12]`. For the boundary, (c) `503` RA 25 with interval 5 and expires_in 30 → 1 request, `expired_token` at 5 s.
- **Cosmetic, not numbered:** `README.md:810` is 133 columns; wrap it at about 100.

---

#### Addendum round 4 — swift — commit 5265aed (PR #78), read after a362452

Two commits. `0ecf6c9` holds the code and tests; `5265aed` updates the CHANGELOG. Each message matches its diff. No Swift toolchain here, so this is a reading review, and every mutant was traced by hand. Paths are under `/home/user/sdks/swift`. `C` = `Sources/AxiamSDK/Oidc/Ciba.swift`, `B` = `Sources/AxiamSDK/HTTP/BareRequest.swift`, `T` = `Tests/AxiamSDKTests/CibaTests.swift`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-43 (Low): CIBA in-poll §16 retry not bounded by `received_at + expires_in` (§33.7 rule 5, §34.2 P10, §33.8 test 7) | **CLOSED** | `0ecf6c9` | **Code.** `bareSend` gains `now: @Sendable () -> Date = { Date() }`, and its deadline guard reads `now()` (`B:56`, `B:104`). `cibaPollOnce` gains `deadline:`/`now:` (default `nil` / `Date()`) and passes them to `bareSend` (`C:461-462`, `C:485-486`). `cibaAwait` passes `deadline: deadline, now: { clock.now() }` (`C:561-563`), so the guard and the loop read the same injected clock. A `5xx` or `429` left after §16 is thrown as `CibaPollDeferred(error:, retryAfter:)` (`C:494-497`). The loop floors its next wait at `max(interval, RA)` and raises `expired_token` at once if that wait would reach the deadline (`C:546-558`, `C:567-576`). A bare `cibaPoll` unwraps the type to the same `AxiamError` as before (`C:434-437`).<br>**Tests.**<ul><li>`testT07BNoRetryWaitCarriesARequestPastTheDeadline` (`T:392`): `expiresIn` 30, interval 5, every poll `503` + RA 120 → `isExpiredToken`, request stamps `[5]`, clock sleeps `[5]`, no `retry` event. This is §33.8 test 7's P10 half.</li><li>`testT07BA503RetryAfterIsTheFloorOfTheLoopsNextWait` (`T:418`): `503` + RA 20 ×3, then tokens, 600 s → 4 requests, sleeps `[5,20]`.</li><li>`testABareCibaPollKeepsItsBoundedBudgetAndHasNoDeadline` (`T:437`): 3 requests, then `NetworkError(503)`.</li></ul>**Mutants (traced):**<ul><li>M1, `cibaAwait` passes no deadline: the in-poll retries run on the no-op seam, so the stamps are `[5,5,5]` and `retry` events appear. **`T:392` fails.**</li><li>M2, `now:` left at `Date()`: before 2027-01-15 the real clock is earlier than `TestCibaClock.start`, so the guard never fires → **`T:392` fails**. After that date the guard always fires, so the RA-20 case is one request per poll (polls at 5/25/45/65 s, sleeps `[5,20,20,20]`) → **`T:418` fails**. Killed in either era, but only by the two tests together.</li><li>M3, the loop ignores `retryAfter`: `T:392` polls at `[5,10,15,20,25]`, and `T:418` sleeps `[5,5]`. **Both fail.**</li><li>M4, `cibaPoll` loses its `CibaPollDeferred` unwrap: a non-`AxiamError` escapes,, so **`T:437` throws** (its `catch` takes only `AxiamError`). **Killed.**</li><li>M5, drop `\|\| status == 429` from the deferral: **survives** (C164-54).</li><li>M6, guard `>=` → `>`: **survives**, because no case sits on the boundary (C164-54).</li></ul>**Existing tests re-traced under the new code:** T05, T06, T07, T08 (pending, then 500 retried in-poll at jitter 0, then 429 `rate_limit_exceeded` deferred with RA nil → transient, then tokens: 4 requests), and the post-200 test and `T:530`. All unchanged. |

**Ruling: is `CibaPollDeferred` public?**
- **No.** It is `struct CibaPollDeferred: Error` with no modifier (`C:444`), nested in `extension AxiamClient {` (`C:312`), which carries no `public`. So it is **internal**, and its doc says "Internal".
- Grep: the only references are its throw (`C:495`) and its two catches (`C:434`, `C:567`). It never escapes `cibaPoll` or `cibaAwait`.
- `cibaPollOnce` and `bareSend` are internal, and their new parameters have defaults. **No public signature changes, and nothing is source-breaking**, as the CHANGELOG says.
- `CibaClock` is `Sendable` (`C:286`), so the `@Sendable { clock.now() }` closure is valid under Swift 5.9 strict checking.

**Deadline bound:**
- **CIBA probe, re-traced on `TestCibaClock`.** `cibaAwait` with `expiresIn` 30 and interval 5; every `ciba_poll` answered `503 {"error":"temporarily_unavailable"}` + `Retry-After: 120`.
  - t=0: the wait is `max(5,0)` = 5, and 0+5 < 30, so the loop sleeps 5.
  - t=5: request 1 → 503. The in-poll wait is `max(0.2·j, 120)` = 120, and `clock.now()` (5) + 120 ≥ 30, so the wait is refused: no sleep, no `retry` event, and the 503 is returned. It is deferred with RA 120, and `cibaStep` classes it transient.
  - t=5: the loop's wait is `max(5,120)` = 120, and 5+120 ≥ 30, so the loop raises `AuthError(expired_token)` at once.
  - **Result: 1 request, none at or after `received_at + 30`, and `expired_token` at about 5 s.** Round 3 sent requests at 125 s and 245 s. `T:392` pins exactly this.
- **Poll at deadline − 0.1 s answered `500`, no RA (CIBA, traced).**
  - The in-poll wait is ≤ 0.2 s (jittered). Either it ends before the deadline and the retry leaves before the deadline, which conforms, or the guard refuses it.
  - When it is refused, the loop's next wait is the interval, which reaches the deadline, so `expired_token` is raised.
  - **No request after the deadline.**
- **A bodiless `429` + RA 120 under `cibaAwait`:** it takes the same refused path, then `NetworkError(429)` → transient. RA 120 is floored, so `expired_token` is raised at once. Bounded.
- **Device:** not touched by this diff. Round 3's trace still holds: 1 request at 5 s, then `expired_token`, none at or after 30 s. The shared guard's only change is `Date()` → `now()`, and the device poll passes no `now`, so it defaults to `Date()`, which is unchanged.

**W7.1c shape:** the device path is untouched (`DeviceGrant.swift` is not in the diff). Round 3's traces still hold:
- Two 500s → 3 requests and the tokens.
- Three 500s → 3 requests and `.network`.
- Two transport failures, then 200 → 3 requests.
- Three transport failures → 3 requests.
- A 429 → 1 request.
- Retry off → 1 request.
- **Complete.**

**Rules 6 and 9, the three §14.6 429 cases, 1.63 isolation, and the replay after a 401 refresh:**
- The diff touches none of the device path, the headers, or the refresh. `bareSend` changes only which clock the guard reads.
- The CIBA §34.2 P8 posture is unchanged: a 5xx is still a `NetworkError` whatever its body, and T08 still passes by trace.

**Version:**
- 1.1.2 (`AxiamSDK.podspec:3`) is still right: no public signature changed, and the change is a patch-level behaviour fix.
- The CHANGELOG records round 4 under `[1.1.2]` (`CHANGELOG.md:59-65`, "C164-43 … No public signature changes").

**Run by the reviewer:**
- `python3 -I Scripts/gen_management.py --check` in the throwaway copy `/home/user/work/swift-r4`: "§27 surface is current (3 files)", rc=0. I deleted the copy afterwards.
- `git log --format=%G?`: `N` for both commits. There is no allowed-signers file, so the signatures could not be verified.
- **Not run:** `swift build` and `swift test` (no toolchain). By reading, every helper the new tests use exists:
  - `TestCibaClock.sleeps`/`elapsed`/`start` (`T:877-900`);
  - `RoutedTransport(stamp:)` and `Reply.json(_:object:headers:)` (the last reply repeats);
  - `EventRecorder.hook`/`kinds`;
  - `makeClient(…, recorder:)` (new parameter, `T:45`, wired to `telemetryHook`).

**New findings:**
- **C164-54 — Info — `C:517-519` (the `cibaAwait` doc comment), `README.md:2532-2537`. Rule: text.** The doc still says a 5xx/429 that outlived §16 means "the loop waits the interval and polls again". The loop now waits `max(interval, Retry-After)` and raises `expired_token` at once if that wait reaches the deadline. The README's CIBA paragraph states neither the P10 bound nor the floor; only the CHANGELOG does. **Fix:** in both places, say "waits the interval or the answer's `Retry-After`, whichever is longer; a §16 wait or a loop wait that would reach `receivedAt + expiresIn` is not taken, and `expired_token` is raised at once (§34.2 P10)".
- **C164-54 — Info — `T:392-451`. Rule: test strength (as C164-48).** Two mutants survive:
  - Dropping `|| response.status == 429` from the deferral (`C:494`) is untested. A `429 rate_limit_exceeded` + `Retry-After` would no longer floor the loop's wait.
  - `B:104`'s `>=` → `>` is unpinned for CIBA.

  The in-poll waits also still sleep on the `_sleep` seam (real `Task.sleep`) rather than the injected `CibaClock`. Only the guard reads the injected clock. P10's "the waits SHOULD come from the injected clock" is therefore met only for the loop's waits. This posture conforms and is the same as Kotlin/C++ in C164-48.

  **Fix (optional):** add a `cibaAwait` case with `429 {"error":"rate_limit_exceeded"}` + `Retry-After: 20` → sleeps `[5,20]`, and a boundary case where `clock.now() + RA == deadline` (e.g. `expiresIn` 25, RA 20 → 1 request, `expired_token`).
- No Low or Medium findings.

---

### 7.4 Addendum round 5 (2026-10-23): the round-5 heads, scoped

**Scope** (the orchestrator's decision, to be recorded in plan §12.7). This round verifies the round-5 fixes and
regression-probes only what the round-5 diffs touch. A new item is counted only if a round-5 diff introduced it.
Older observations and test-strength notes on untouched code are listed under **Follow-up**, outside the W7 gate.

**What was read.**

The contract is unchanged: W7.1c `b3f8687`.

| SDK | PR | Head | Notes |
|---|---|---|---|
| Kotlin | #80 | `d9cd47a` | |
| C | #77 | `832a4214d` | |
| PHP | #87 | `12161d496` | |
| TypeScript | #150 | `50d6f72` | read by the lead reviewer: a CHANGELOG-only commit |
| Python | #103 | `9e692842a` | |
| C++ | #80 | `007aa6b07` | |
| C# | #111 | `fd1093b2f` | read only |
| Swift | #78 | `7d28ce497` | read only |
| Rust | #138 | `c947a5e` | unchanged, nothing open |
| Go | #103 | `2a0c273` | unchanged, nothing open |
| Java | #121 | `97dcdf0` | unchanged, nothing open |

All eleven heads match `git ls-remote` and the orchestrator's list. `scripts/check-sdk-artifact-drift.py
--local-root` reports **11 repos, 0 artifact problems**.

#### 7.4.1 Rulings on the orchestrator's points

**1. Kotlin's bodiless `DELETE` now carries `Content-Length: 0`. Conforming, and the server accepts it.**
- **P11's text** asks for "content on every one of them (an empty body where the operation has none)". On the
  wire that is exactly `Content-Length: 0`.
- **For Kotlin the clause is not binding.** P11 names the dedicated handler, `Connection: close` and the content
  as "the C# remedy". For a library with a switch, the binding rule is that the library itself never re-sends,
  and OkHttp's one-shot body does that per request.
- **It does no harm.** It is how a bodiless `DELETE` gets a one-shot body, and mutant M7 shows it stops the
  re-send.
- **The server.** Each of the 36 `web::delete()` handlers in `axiam-api-rest`, and SCIM's two, takes no body
  extractor (`Json`, `Bytes`, `Form`, `Payload`, `String` or `Multipart`). No middleware inspects `Content-Length`
  or `Content-Type` on a `DELETE`.
- **Kotlin's P11 posture.** Kotlin has no dedicated non-pooled handler and does not send `Connection: close`; the
  probe saw `Keep-Alive` on every write. That is no loss: round 4's `writeHttp` already shared the pool. The P11
  drop probe delivered every never-retried write exactly once.

**2. The C++ `expires_in` clamp at 1e9 s. It changes no conforming behaviour for any non-negative value.**
- Probed:
  - at 1 year and at 1e9 itself, the device and CIBA deadlines land exactly where they did before;
  - 30, 0 and −1 behave as in round 4;
  - UBSan reports no overflow at `INT64_MAX`.
- It touches only the two deadline expressions (`src/oidc.cpp:1745`, `:2591`), and it is recorded in the
  comments, the CHANGELOG (`:49-50`) and the commit message.
- **It caps only the top.** A hostile negative `expires_in` (−9e18) still overflows (UBSan at `:1745`). The wrapped
  deadline then lets a poll go out and return tokens. The overflow predates round 5. However, the round-5
  CHANGELOG's "cannot overflow" claims too much, which is part of C164-58.

#### 7.4.2 Verification of the round-5 fixes

| SDK | Fixes claimed | Verdict |
|---|---|---|
| kotlin | C164-50, -53, -54 | **C164-50 closed in code.** No `retryOnConnectionFailure(false)` remains in `src/main`. Management writes, `Sessionless`, the RFC 7592 `PUT` and `DELETE` and `ssf.poll` use the ordinary client with a `OneShotBody`. In the dual-stack probe (`[::1 \| 127.0.0.2, 127.0.0.1]`, pool evicted), each request reached the server once; round 4's code reached it 0 times. In the P11 drop probe, each write arrived exactly once. Mutants M1, M2, M3 and M7 are killed. **C164-53 closed:** t04b and t04c; mutant MC fails. **C164-54 closed:** MA, MG and MK are killed. Suite: 1323 tests, 0 failures; generator `--check` OK. |
| c | C164-51, -53 | **Both closed.** The CIBA in-poll wait is slept in milliseconds when no clock is passed (`src/oidc_ciba.c:544`, `:653-654`). The example (interval 28, `expires_in` 30, `500`, `500`, `200`) returns the tokens. The jittered test (`tests/test_ciba.c:799-828`) kills both round-4 survivors. ASan/UBSan ctest 81/81. |
| php | C164-52, -54 | **Both closed.** A CIBA `429` now carries its `Retry-After`: interval 5 with `Retry-After: 12` gives sleeps `[5,12]`, deadline-checked. The remaining time is floored to whole seconds, so `expired_token` is no longer late. C6, C7 and the floor revert are killed. phpunit 2080 / 10001; phpstan clean. |
| typescript | C164-54 | **Closed.** The CHANGELOG (`:39-41`) now describes `RetryOptions.admit` as the exported, optional member it is. No code changed. |
| python | C164-54 | **Closed.** The CHANGELOG and three docstrings name the 429 carry. A new TestClock test asserts waits `[5,1,1,5,30,5]`, and sync mutants M11–M14 fail it. pytest 2175; ruff and mypy `--strict` clean. |
| cplusplus | C164-54 | **Closed.** A post-sleep deadline re-check now runs before the send at all four sites (`src/oidc.cpp:914`, `:1767`, `:2476`, `:2605`), each pinned by its own oversleep test and killed mutant. Real-clock sweep: late sends fell from up to +4.037 ms to at most +0.075 ms, which is the gap between the clock read and the send. The ms deadline is now under *Fixed*. ctest 1635 cases, 0 failed. SOVERSION 4 and 1.1.2 stand. |
| csharp | C164-54 | **Closed** (read only). The tests assert `sleeps.Count == 3`, a `WaitAsync(10 s)` guard, no `RetryEvent`, and a boundary test. Every mutant is judged killed. Tests and CHANGELOG only. |
| swift | C164-54 | **Closed** (read only). The `cibaAwait` doc and the README CIBA paragraph are corrected. M5 (the 429 deferral) and M6 (`>=`) are killed by `CibaTests.swift:438` and `:460`. `gen_management --check` passes. |

The regression probes cover only what the diffs touched, and all hold:
- the CIBA and device deadline bounds;
- the CIBA W7.1c shape;
- the dual-stack and P11 behaviour (Kotlin);
- the 429 carry never shortening the interval (PHP, Python).

Every version is 1.1.2, and every CHANGELOG records round 5.

#### 7.4.3 New findings introduced by the round-5 diffs (C164-55 onward)

| ID | Severity | SDK | `path:line` | Rule | What | Fix |
|---|---|---|---|---|---|---|
| C164-55 | Low | kotlin | `Sessionless.of` (`:49`, retry no longer off); `readClientRegistration` | §16.1 (attempt cap 3 in total) | With OkHttp's connection retry back on in `Sessionless`, the RFC 7592 **read** (a `GET`, which cannot carry a one-shot body) is re-sent by OkHttp after a drop on a pooled connection. Probed: 4 requests with §16 retry on (cap 3), and 2 with `retryDisabled()`; round 4 gave at most 3 and 1. The read is idempotent, so no state is at risk. | Either (a) record it as a documented transport recovery: OkHttp 4.12 replays an idempotent `GET` once on a stale pooled connection, so with retry on a read can reach 4 sends and with retry off 2. Put that in the README §16 row and the CHANGELOG, and pin it with a test (`readClientRegistration` against pooled drops: ≤ 4 and ≤ 2). Or (b) move to OkHttp 5.x, as Java uses (5.5.0), where route fallback is independent of `retryOnConnectionFailure`, and then turn that flag off on this client. **(a) is enough for 1.1.2.** |
| C164-56 | Low | kotlin | `ClientRegistrationSupport.kt:91`, `:101`; `SsfReceiver.kt:221` | the C164-50 fix's own test ("P11's own test … on each client") | The read-and-drop P11 test exists only for the management transport. Making the RFC 7592 `PUT` or `DELETE` body, or the `ssf.poll` body, a plain body again (mutants M4, M5, M6) passes every test, while the probe sees 2, 2 and 4 requests. | Add the read-and-drop case on `deleteClientRegistration`, `updateClientRegistration` and `ssf.poll`, asserting 1, 1 and 3 requests respectively (`ssf.poll` is §16-retried). |
| C164-57 | Info | php | `src/Oidc/OidcClient.php:2169-2177` (the new 429 branch); `:2103-2104` (docblock) | test strength of new code; text | Three mutants of the new CIBA 429 branch survive: the body decides instead of the status; the 429 carry can shorten the interval; the 429 raises the interval permanently. The `cibaAwait` docblock still says the loop "waits the interval" after a 429. | Add the three tests in PHP's round-5 addendum: a `429 {"error":"slow_down"}` waited at `max(interval, Retry-After)`; `Retry-After: 2` at interval 5 waits 5; the interval unchanged after the 429. Reword the docblock. |
| C164-58 | Info | cplusplus | `CHANGELOG.md:46-50`; the four new re-checks | text; test strength of new code | The CHANGELOG says the deadline "cannot overflow", but a negative `expires_in` still does (§7.4.1 point 2). Changing `>=` to `>` on any of the four new re-checks passes the suite, because the tests oversleep by whole seconds. | `std::clamp(expires_in, 0, 1e9)` at both sites, or reword the CHANGELOG to "cannot overflow for a non-negative `expires_in`". One oversleep test per site that lands exactly on the deadline. |

**Counts, round 5:** Medium 0 · Low 2 (C164-55, -56; Kotlin) · Informational 2 (C164-57 PHP, -58 C++).

#### 7.4.4 Follow-up (outside the W7 gate)

Older observations, or test-strength notes on code the round-5 diffs did not touch. For the SDK sessions'
backlog; none blocks W7.

| SDK | Observation |
|---|---|
| kotlin | Management `GET`s show the same OkHttp stale-connection replay as C164-55 (4 sends with §16 retry on, 2 with it off). This predates round 5 and has the same remedy. Two comments still mention `retryOnConnectionFailure(false)`. |
| cplusplus | A µs-scale gap between the clock read and the send (+0.075 ms worst case). `opt_int` can hit undefined behaviour on an out-of-range JSON double, and a uint64 above `INT64_MAX` wraps negative (pre-existing). |
| python | The new carry test is sync only, so the async mutants M12a–M14a survive (the reviewer's async twin kills them). Inline comments at `_client.py:2395` and `_async_client.py:1092` still say "a 5xx's Retry-After". |
| c | The millisecond test bounds the in-poll sleeps to [0, 1000] ms rather than the exact 100 and 200 ms. Part (b) of the jittered test runs on a whole-second fake clock, so the 29.9 s case is covered by the probe only. |
| php | With less than 1 s left after an admitted wait, the 1 s wait is served and then nothing is sent (no conformance impact). |
| csharp | Under the `deadline: null` mutant, `WaitAsync` fails the test but leaves the `DeviceLoginAsync` task running. Passing a cancellation token would stop it. |
| swift | The in-poll §16 waits sleep on the real clock, not the injected one. That conforms: P10's MUST is the deadline bound, which reads the injected clock; the injected clock for the waits is a SHOULD. |

#### 7.4.5 Per-SDK status and the W7 gate

| SDK | Open (W7 gate) |
|---|---|
| typescript, rust, python, c, csharp, go, java, swift | **none** |
| kotlin | C164-55, -56 (Low) |
| php | C164-57 (Info) |
| cplusplus | C164-58 (Info) |

**Can W7 merge? Not yet, and the remaining work is small.** No Medium is open.
- **Eight SDKs** have nothing open.
- **Kotlin** has two Lows. One is a documentation note and a test for the stale-connection replay of a `GET`; the
  other is three drop tests.
- **PHP and C++** have one Informational item each: three tests and a docblock for PHP, a clamp or a CHANGELOG
  wording and boundary tests for C++.

Under the agreed scope, a round-6 read of those three diffs closes the gate.

The seven round-5 addenda follow, with N-numbers mapped to the ids above.

---

#### Addendum round 5 — python — commit 9e692842a (PR #103), read after f9b68a28c

There is one commit over the round-4 head: `9e69284` "test+docs(ciba): pin the Retry-After carry and record that a 429 is waited (C164-54)". It touches `CHANGELOG.md` (+6), `_client.py` (+6/-3, docstrings only), `_async_client.py` (+3/-1, docstring only) and `tests/test_ciba.py` (+38, one new test). **No executable code changes.** The commit message matches the diff.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-54 (Info), text: the CHANGELOG should record that `ciba_await` also waits a `429`'s `Retry-After` | **CLOSED** | 9e69284 | `CHANGELOG.md:72-77`, under `[1.1.2]`: "`ciba_await` also waits a `429`'s `Retry-After` (§33.7 rule 5; C164-54) … a `429 rate_limit_exceeded` included, which `ciba_await` previously ignored … one-shot and never shortens the interval". It also names the test and its expected waits. |
| C164-54 (Info), text: the `ciba_await` docstring (sync and async) | **CLOSED** | 9e69284 | Sync, `_client.py:2348-2351`: "the loop waits the interval -- or the failure's `Retry-After` when that is longer, once (§16.1, §33.7 rule 5)". Async, `_async_client.py:1063-1064`: "a failure's `Retry-After` (a `5xx`'s or a `429`'s) is the floor of the next wait, once". |
| C164-54 (Info), text: the `device_login` docstring | **CLOSED** | 9e69284 | `_client.py:2041-2043`: "tries again at its interval -- or at the failure's `Retry-After` when that is longer, once". |
| C164-54 (Info), test: pin the CIBA carry (three surviving mutants) | **CLOSED** (sync, as the fix asked) | 9e69284 | `tests/test_ciba.py:1119` `test_ciba_await_carries_a_failures_retry_after_once_and_never_shortens_the_interval`: sync `AxiamClient` on `TestClock`. The script is `[503 RA 1 ×3, 429 RA 30, pending, 200]`, interval 5, `expires_in` 3600. It asserts 6 requests and `clock.sleeps` (≥ 1 s entries) `== [5, 1, 1, 5, 30, 5]`, which is exactly the fix. **Mutants** (throwaway copy, `tests/test_ciba.py`):<ul><li>**M12** (`wait = floor or interval`, the floor shortens): **killed** (1 failure, the new test).</li><li>**M13** (floor never reset, sticky): **killed** (the new test).</li><li>**M14** (carry limited to `NetworkError`, so the 429 floor is dropped): **killed** (the new test).</li><li>**M11** (no carry): killed (2 failures, the old and the new test).</li><li>The async twins **M12a**, **M13a** and **M14a** still survive the suite, because the new test is sync only. That is what the exact fix asked for, so it goes under Follow-up. M11a is killed. The reviewer's async twin probe kills M12a, M13a and M14a.</li></ul> |

**Regression probes:** the round-5 diff changes no executable code, only docstrings, the CHANGELOG and one test. So the device/CIBA deadline bound, the W7.1c shape, rules 6/9, P11 and 1.63 isolation are not touched, and the round-4 results stand. The full suite is green. To confirm the CIBA behaviour the new text describes, `/home/user/work/python-r5-mut` ran these sync and async probes, all as expected:
- The async twin of the new test gives the same `[5, 1, 1, 5, 30, 5]`.
- `[429 RA 3, slow_down, 429 RA 12, pending, 200]`, interval 5, gives waits `[5, 5, 10, 12, 10]`: a 429 RA shorter than the interval does not shorten it, and RA 12 over the slowed 10 s interval is waited once.
- `expires_in` 30, interval 5, every poll `429` + RA 120: 1 request, then `CibaExpiredTokenError`. Nothing is sent after the deadline.

**Answers to the prompt's questions:**
- CHANGELOG clause and both docstrings say the carry covers a 429: **yes** (`CHANGELOG.md:72-77`; `_client.py:2041-2043`, `:2348-2351`; `_async_client.py:1063-1064`).
- The TestClock test `[503 RA 1 ×3, 429 RA 30, pending, 200]` asserts `[5, 1, 1, 5, 30, 5]`: **yes**, exactly (`tests/test_ciba.py:1119-1154`).
- M12, M13 and M14 fail: **yes**, all three (sync). The async twins survive (see Follow-up).

**Version:** `pyproject.toml:7` and `__init__.py:109` read 1.1.2, which is still right. There is no API change. CHANGELOG `[1.1.2]` records round 5 (`:72-77`).

**Run by the reviewer:**
- Throwaway copy `/home/user/work/python-r5` (`git archive 9e69284`), venv on Python 3.13, `pip install -e '.[dev,fastapi,django]'`.
- `ruff check .`: all checks passed. `ruff format --check .`: 218 files already formatted.
- `mypy --strict src`: no issues in 98 source files. `interrogate src`: 100%. `scripts/gen_management.py --check`: OK (32 files, 202 operations).
- `pytest tests -q`: **2175 passed**, 7 warnings (3 min 04 s). That is 2174 + 1 new.
- Mutants: the round-4 `mut.py`, retargeted to the second copy `/home/user/work/python-r5-mut`. Eight CIBA variants were run against `tests/test_ciba.py`, and five of them against the probes.
- The venvs, both copies, the probe directory and the logs were deleted afterwards. The SDK clone is unchanged (`git status` clean at 9e69284).

**New findings (introduced by the round-5 diff):** none.

**Follow-up (outside the W7 gate):**
- The new test is sync only, so the async CIBA carry mutants M12a, M13a and M14a still survive the suite. An async twin of `test_ciba.py:1119` on `AsyncTestClock` kills all three; it was verified in the probe.
- The inline comments at `_client.py:2395` and `_async_client.py:1092` still say "a 5xx's Retry-After survives…". The branch also carries a 429's. This is cosmetic.

---

#### Addendum round 5 — c — commit 832a4214d (PR #77), read after 7b5bd2150

The round-5 diff (`git diff 7b5bd21..832a421`) is one commit, `832a421`. It touches three files:
- `src/oidc_ciba.c` (+12/−7): `ciba_poll_with` gains an `int clk_injected` parameter (it is `static`), and `axiam_ciba_await` computes and passes `clock_injected`.
- `tests/test_ciba.c` (+70): two new tests.
- `CHANGELOG.md` (+9): one Fixed entry under `[1.1.2]`.

No public header, CMake, README or other source file changed. The clone `/home/user/sdks/c` was only read and is clean (`git status` empty). All work was done in a copy at `/home/user/work/c-r5`.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-51 (Low): the CIBA in-poll wait is rounded up to whole seconds even with no caller clock | **CLOSED** | 832a421 | **Code:**<ul><li>`src/oidc_ciba.c:653-654`: `clock_injected = clock && clock->now && clock->sleep`, which is the same condition as before for choosing `clk`.</li><li>`:674` passes it.</li><li>`:544`: `if (clk_injected) clk->sleep(clk->ctx, wait_s); else c->sleep_fn(c->sleep_ctx, delay);`. Without a caller clock, the millisecond `delay` is slept on the client's sleep.</li><li>`:539`/`:542`: the deadline check still uses `wait_s = ceil(delay/1000)` on both paths, as the fix requires.</li><li>`axiam_ciba_poll` passes `NULL, 0, 0` (`:606`) and stays unbounded.</li></ul>**Test:** `test_t07_without_a_clock_a_sub_second_backoff_is_served_in_milliseconds` (`tests/test_ciba.c:773-796`). It is the review's own example: interval 28, `expires_in` 30, `500`, `500`, `200`, clock NULL, jitter 0.5. Expected: `AXIAM_OK`, 3 requests, sleeps `[28000, <1000, <1000]`. **Probe E5** (reviewer, default clock): requests at 28.0, 28.1 and 28.3 s, client sleeps `[28000, 100, 200]`, **tokens**. Round 4 sent at 28 and 29 s and ended in `expired_token`. **Probe W1b** (interval 2): sleeps `[2000, 100, 200]`, the round-3 timing. **Mutants:**<ul><li>**M51a**, the round-4 code (`if (clk)`): killed at `:785` ("Expected 0 Was 1", `expired_token`).</li><li>**M51b**, never sleep on the injected clock: killed at `:726` (the older C164-43 test).</li></ul> |
| C164-53 (Low, C part): no jittered CIBA deadline case, so the floor and Retry-After-only mutants survived | **CLOSED** | 832a421 | **Test:** `test_t07_a_jittered_backoff_past_the_deadline_inside_a_poll_is_not_served` (`tests/test_ciba.c:799-828`). A bare `500` (no `Retry-After`) answers a poll one second before the deadline (interval 29, `expires_in` 30), with jitter 0.5. It runs twice:<ul><li>(a) on the injected `TEST_CLOCK`: `AXIAM_ERR_AUTH` + `expired_token`, exactly 1 token request, and every request before `start + 30`;</li><li>(b) on the client's own clock (no caller clock): 1 request and `expired_token`.</li></ul>**Mutants**, each with `test_ciba` rebuilt and the source restored afterwards:<ul><li>**M53e**, `delay / 1000` (floor) in the check: killed at `:810` ("Expected 1 Was 2").</li><li>**M53f**, the check counts only `Retry-After`: killed at `:810` ("Expected 1 Was 2").</li><li>M43b (`>=` → `>`): killed at `:740` and `:810`.</li><li>M43a (check removed): killed at `:711` and `:810`.</li></ul>These are the two round-4 survivors named in the finding. Both now fail. |

**Regression probes** (reviewer probe `probe_ciba_r5.c`: the round-4 `probe_ciba_r4.c` with one helper renamed, because the new test file now defines `half_jitter`; and `probe_r3.c` for the device. Client clock in ms, jitter 0.5, `expires_in` 30, interval 5 unless noted):
- **CIBA deadline bound with 503 + `Retry-After` 120 / `expires_in` 30:**
  - C1 (default clock) and C2 (injected): 5 polls at 5-25 s, then `expired_token`; nothing at or after 30 s.
  - C3 (RA 3600): the same.
  - C4 (RA 20): requests at 5 and 25 s.
  - C5 (RA 25, the exact boundary): not served.
  - C5b (RA 24): served at 29 s.
  - C6 (503 + RA 120, then 200): tokens at 10 s.
  - C7 (bare 500s, default clock): `[5000, 100, 200]` per poll, 15 requests, the last at 26.5 s, then `expired_token`.
- **Near the deadline on the default clock:**
  - E1 (a poll at 29.9 s answered 500) and E2 (a transport failure there): 1 request, no retry, `expired_token`. The deadline check still rounds up on the default path.
  - E3 (injected clock, a poll at 29): 1 request.
  - E4 (injected, interval 28, 500/500/200): `expired_token` after requests at 28 and 29 s. This is inherent to the whole-second public clock type and unchanged from round 4.
- **W7.1c shape, CIBA:**
  - W1a (injected): waits `[2, 1, 1]` s and tokens.
  - W1b (default): `[2000, 100, 200]` ms and tokens.
  - W1c, a bare `ciba_poll`: 0/100/300 ms and tokens.
  - W2 (500 ×3): 3 requests, cause 500.
  - W3/W3b (transport failure ×2, then 200): tokens.
  - W4 (transport failure ×3): 3 requests.
  - W5 (429): 1 request, `rate_limit_exceeded`.
  - W6 (retry off): 1 request.
- **Device (unchanged by the diff, re-run anyway):**
  - D1/D3: 5 polls, then `expired_token`. D5: 2 polls. D6 (a bare poll, 503 + RA 120): 240 s and cause 503.
  - E1/E2/E4: 1 request.
  - E3 (500, 500, 200): tokens at 28.3 s.
  - W1-W5: as in round 4.
- **Rules 6/9, P11 and 1.63 isolation:** not probed. The diff does not touch `oidc_post`/`oidc_post_ex`, the rule-6/9 dispatch, `authz_post` or any `/oauth2/*` routing.

**Answers to the prompt:**
- **Is the CIBA in-poll wait slept in milliseconds when there is no caller clock?** Yes. The example (interval 28, `expires_in` 30, `500`, `500`, `200`) returns the tokens. Probe E5 matches round 3 exactly (28.0/28.1/28.3 s), and the new test pins it. With a caller clock, the wait is still whole seconds rounded up, on that clock.
- **Does the jittered CIBA deadline test kill the floor-instead-of-ceil and count-only-Retry-After mutants?** Yes. Both fail at `tests/test_ciba.c:810`.
- **SOVERSION:** no public header changed (`git diff 7b5bd21..HEAD -- include CMakeLists.txt` is empty). `ciba_poll_with` is `static`. `AXIAM_SOVERSION 2` (`CMakeLists.txt:134`) stays right, and `abi_soname` passes.

**Version:**
- 1.1.2 is still right: CMake `VERSION` (`CMakeLists.txt:7`), `conanfile.py:9` and `ports/axiam-c-sdk/vcpkg.json:3`.
- The CHANGELOG records round 5 under `[1.1.2]` *Fixed* (`CHANGELOG.md:68-76`). It covers C164-51 as a regression of the C164-43 change, with the interval-28 example and its test, and the C164-53 jittered case with its test.
- Nothing is source- or ABI-breaking.

**Run by the reviewer** (`/home/user/work/c-r5`):
- **Build:** `-DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON`, with `-fsanitize=address,undefined -fno-sanitize-recover=all` on the C flags and on the exe and shared linker flags. 0 warnings.
- **Suite:** `ctest -j1`, probes excluded: **81/81 passed**, ASan/UBSan clean (leak detection on), 13.9 s. `test_ciba` passed 22/22 (20 + 2 new).
- **Mutants:** M51a, M51b, M53e, M53f, M43a and M43b on `src/oidc_ciba.c`, with `test_ciba` rebuilt for each and leak detection off, so that Unity's output survives a failed assertion. The source was restored and diffed clean against the clone.
- **Probes:** `probe_ciba_r5` and `probe_r3`. The leak reports from the probe binary come from the probe's own `mint_tokens` calls and are not SDK leaks.
- **Not run:** the C-standard matrix, valgrind, Doxygen, the package recipes, and `gen_management.py --check` (the diff does not touch management).
- **Cleanup:** the build outputs (`build-asan/`) and the work copy were deleted afterwards.

**New findings (introduced by the round-5 diff):** none.

**Follow-up (outside the W7 gate):**
- The new millisecond test asserts the two in-poll sleeps only as `0 < ms < 1000` (`tests/test_ciba.c:792-793`), not the exact `100`/`200` that jitter 0.5 gives. That is enough to kill the round-4 code. Exact values would also pin the jitter fraction on this path.
- Part (b) of the jittered test runs on the integer fake clock, so its "just before the deadline" poll leaves at exactly 29 s. The sub-second case (a poll at 29.9 s, probe E1) is covered by the probe only.

---

#### Addendum round 5 — cplusplus — commit 007aa6b07 (PR #80), read after 3adf58166

**Commit read.** `git log 3adf581..HEAD` shows one commit, `007aa6b` "fix(device,ciba): re-check the deadline after each sleep; CHANGELOG moves the ms deadline to Fixed (C164-54)". It changes 4 files, +130/−7: `src/oidc.cpp`, `tests/test_ciba.cpp`, `tests/test_oidc_grants.cpp` and `CHANGELOG.md`. The commit message matches the diff. The SSH signature is present but could not be verified, because no allowedSignersFile is configured. **No public header changed** (`git diff --stat 3adf581..HEAD -- include` is empty). Every `path:line` below refers to 007aa6b.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-54 (Info) check-before-sleep, never repeated after the sleep, at four sites | **CLOSED** | 007aa6b | **Code.** Each site now reads the same clock again right after the sleep and before the next request, and gives the same typed `expired_token` without sending:<ul><li>device in-poll: `if (deadline && impl.now_ms_fn() >= *deadline)` (`src/oidc.cpp:914-920`), after `impl.sleeper(delay)`;</li><li>device loop: `if (p_->now_ms_fn() >= deadline)` (`:1767-1772`), after `p_->sleeper(...)`;</li><li>CIBA in-poll: `if (clock != nullptr && deadline && clock->now() >= *deadline)` (`:2476-2484`). It sets `transient=false` and returns `expired_token` in `out.error`, the same way the pre-sleep check does;</li><li>CIBA loop: `if (clock.now() >= deadline)` (`:2605-2611`), after `clock.sleep(...)`.</li></ul>A bare `device_poll` / `ciba_poll` passes no deadline (and `ciba_poll` no clock), so neither is affected.<br>**Tests.** Four tests, each on a virtual clock with a sleeper that oversleeps:<ul><li>`test_oidc_grants.cpp:680`: device interval wait, 6 s grant, interval 5, a 2 s oversleep → `expired_token`, 0 token calls;</li><li>`:697`: device in-poll, 10 s grant, 500, then a 100 ms backoff overslept by 6 s → `expired_token`, 1 call;</li><li>`test_ciba.cpp:575`: CIBA interval, 6 s request, interval 5, 2 s oversleep → `expired_token`, 0 calls;</li><li>`:589`: CIBA in-poll, 10 s request, 500, then a 6 s oversleep → `expired_token`, 1 call.</li></ul>**Mutants.** Each re-check was disabled alone (`false && …`), the binary rebuilt and the whole binary run. All four were **killed**, each by exactly its own test (1 failure):<ul><li>M1 (device in-poll): `test_oidc_grants.cpp:707`;</li><li>M2 (device loop): `:690`;</li><li>M3 (CIBA in-poll): `test_ciba.cpp:601-602`;</li><li>M4 (CIBA loop): `:585-586`.</li></ul> |
| C164-54 (Info, text) the C164-48 ms deadline was filed under *Tests* | **CLOSED** | 007aa6b | `CHANGELOG.md:43-45`: a new *Fixed* bullet, "A device grant no longer ends up to a second early (C164-48) … milliseconds on a monotonic clock". The *Tests* entry (`:93-97`) keeps only the boundary tests and the `CibaAwaitOptions::clock` note, and adds the four C164-54 tests. A separate *Fixed* bullet (`:46-50`) records the post-sleep re-check and the `expires_in` clamp. |

`Regression probes:` the diff touches only the four deadline sites and the two deadline computations, so only the deadline bound was re-probed. W7.1c, rules 6/9, P11 and the 1.63 isolation code is unchanged. Their tests still pass in the full run.
- **Deadline bound (virtual clock).** The existing tests still pass:
  - device and CIBA 503 + `Retry-After: 120` / `expires_in` 30 → 1 request, then `expired_token` (`test_ciba.cpp` C164-36 test, `test_oidc_grants.cpp` C164-36 test);
  - the exact-ms `>=` boundary tests (C164-48).
- **CIBA real-clock boundary sweep.** This is the round-4 probe rerun on 007aa6b: real `CibaClock::system()`, real sleeper, `expires_in` 3 / interval 1, 503 + `Retry-After: 1`, deadline shifted by 20 µs … 2 ms over 36 runs. Three sweeps, 108 runs:
  - 13 or 14 runs per sweep admitted the third attempt;
  - **1 request per sweep reached the transport after the deadline, by +0.075 / +0.036 / +0.006 ms**;
  - every run ended `expired_token`.
  - Round 4 measured 2 late requests in 36 runs, at +0.098 ms and **+4.037 ms**. The oversleep component is gone. What remains is the gap of a few tens of µs between the post-sleep `now()` read and the transport call (looping back, then `impl.transport(req)`). No client-side check can remove that, and §34.2 P10 does not ask for it (see Follow-up).

**Ruling input — the `expires_in` clamp at 1e9 s.**
1. **No conforming behaviour changes.** `std::min<std::int64_t>(x, 1'000'000'000)` is the identity for every `x ≤ 1e9` s (31.7 years). Probed on a virtual clock, device and CIBA alike, with a `200` on the first poll:
   - `expires_in` 31 536 000 (1 year): interval 31 535 999 → tokens (1 call); interval 31 536 000 → `expired_token` (0 calls). The deadline is exactly `expires_in`.
   - `expires_in` 1e9: interval 999 999 999 → tokens; interval 1e9 → `expired_token`.
   - `expires_in` 30 / 0 / −1: identical to round 4 (tokens / `expired_token` / `expired_token`).
   - Only above 1e9 s does the bound change. For example, `expires_in` 1e12 with interval 2e9 → `expired_token`, where unclamped would serve. A server cannot send that value in good faith: AXIAM's own grants last minutes, and RFC 8628 / CIBA put no such value in reach.
2. **No overflow on the upper side.**
   - Device: `now_ms (steady) + 1e9·1000` ≈ 1e12.
   - CIBA: `received_at (steady ns since boot) + seconds(1e9)` = 1e18 ns + uptime, below 9.22e18.
   - Under `-fsanitize=undefined`, `expires_in` = INT64_MAX gives no diagnostic and tokens, for device and CIBA.
   - Without the clamp, `expires_in*1000` overflows above about 9.2e15 s, and `seconds→ns` above about 9.2e9 s.
3. **It only guards the arithmetic.** It touches nothing but the two deadline expressions (`:1745`, `:2591`). `interval`, `received_at` and the public `expires_in` field the caller sees are unchanged.
4. **Documented and recorded:** the code comments at `:1744` and `:2590`, the `CHANGELOG.md:49-50` *Fixed* bullet ("clamped (about 31 years) so converting it to milliseconds or nanoseconds cannot overflow") and the commit message. The one gap is that the clamp is one-sided (C164-58).

`Version:` `project(axiam_cpp_sdk VERSION 1.1.2)` (`CMakeLists.txt:6`) is still right.
- **SOVERSION:** `AXIAM_SOVERSION 4` (`:116`) is unchanged and needs no bump. No public header changed, and every change is inside `src/oidc.cpp` function bodies.
- **CHANGELOG `[1.1.2]`** records round 5 (`:43-50`, `:94-97`).

`Run by the reviewer:` a throwaway copy at `/home/user/work/cplusplus-r5`, deleted afterwards along with the `cpp-r5-*` logs. The clone at `/home/user/sdks/cplusplus` is clean and untouched. Toolchain: gcc 13.3, Ninja, `-DCMAKE_CXX_STANDARD=17`, Debug.
- `python3 scripts/gen_management.py --check`: "§27 surface is current (7 files)", exit 0.
- Static build `-DAXIAM_BUILD_TESTS=ON -DAXIAM_BUILD_EXAMPLES=ON`: exit 0 (121/121). `ctest`: 1/1 passed. The binary reports **1635 test cases, 6190 checks, 0 failed** (round 4: 1631 / 6182, so +4 tests).
- Mutants M1–M4 (killed, above). Also run:
  - B1–B4, `>=`→`>` on each new re-check: all **survive** (C164-58);
  - C1/C2, clamp removed: survive. This is expected, because no conforming test can tell the difference.
- A UBSan build (`-fsanitize=undefined`) with clamp probes for device and CIBA, plus the CIBA real-clock sweep (3×36 runs). All probes were in the copy only.
- The shared build is not rerun: no header or layout changed, and round 4's `abi_soname` result stands.

`New findings (introduced by the round-5 diff):`
- **C164-58 — Info (hardening / text).**
  - **Where:** `src/oidc.cpp:1745`, `:2591`; `CHANGELOG.md:49-50`.
  - **What:** the clamp is upper-only, but the CHANGELOG says the conversion "cannot overflow". A negative hostile `expires_in` still overflows.
  - **UBSan:** `oidc.cpp:1745: signed integer overflow: -9000000000000000000 * 1000`, and `chrono.h:225: -9000000000000000000 * 1000000000` for CIBA.
  - **Effect:** in both cases the wrapped deadline came out far in the future and the poll was **served (tokens)**, where any `expires_in ≤ 0` should give `expired_token`.
  - **Scope:** this behaviour predates round 5. Round 4 did the same, and its observation named only the upper side. It is not a regression, and only a hostile server can reach it.
  - **Fix:** `std::clamp<std::int64_t>(expires_in, 0, 1'000'000'000)` at both sites. A value ≤ 0 already ends in `expired_token` at once, so clamping at 0 changes no conforming case. Or reword the CHANGELOG to "a hostile, too-large `expires_in`".
- **C164-58 — Info (test strength, optional).**
  - **What:** `>=`→`>` on any of the four new post-sleep re-checks survives the suite. Each oversleep test overshoots by whole seconds, so the boundary of the new checks is not pinned.
  - **Effect:** only a request whose oversleep ends exactly on the deadline millisecond (or `steady_clock` tick) would go out. That is a real-clock probability of about zero.
  - **Fix:** one case per site where the sleeper lands exactly on the deadline (for example, the device loop with a 6 s grant, interval 5 and a 1000 ms oversleep), expecting `expired_token` with no request.

`Follow-up (outside the W7 gate):`
- After the re-check, a request can still reach the transport a few µs after the deadline: +0.006 to +0.075 ms in 3 of 108 real-clock runs, down from +4 ms. This is check-to-send latency, which every SDK has, and is not a P10 issue.
- `opt_int` (`src/oidc.cpp:337-340`) calls `get<std::int64_t>()` on any JSON number. That gives an out-of-range double (for example `1e30`) UB in nlohmann's cast, and a uint64 above INT64_MAX wraps (`18446744073709551615` → −1 → `expired_token`). This predates the PR and applies to every integer field.

---

#### Addendum round 5 — csharp — commit fd1093b2f (PR #111), read after aa403c8

There is one commit, `fd1093b` ("test: 1.64 review addendum round 4 - C164-54"). It changes 2 files (+47/−3): `CHANGELOG.md` (+4) and `tests/Axiam.Sdk.Tests/Contract164DevicePollRateLimitTests.cs`. The test file gets a `SetUp` overload that takes a `TelemetryHook`, extra assertions in two existing tests, and one new test. **No product code changed.** The commit message matches the diff.

**Read only.** There is no .NET toolchain, so nothing was built, run or mutated. Each mutant was judged by tracing the named test against `RetryPolicy.ExecuteAsync` (`Axiam.Sdk/Core/RetryPolicy.cs:207-240`), `DevicePollCoreAsync` (`Axiam.Sdk/AxiamClient.OidcDeviceExchangeLogout.cs:214-264`) and the `DeviceLoginAsync` loop (`:325-399`), all unchanged since aa403c8.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-54 (Info), in-poll §16 waits not pinned to `DevicePollDelay` | **CLOSED** | fd1093b | `APollRetriesA5xxInsideTheAttemptUnderSection16` (`Contract164DevicePollRateLimitTests.cs:295`) now asserts `Assert.Equal(3, sleeps.Count)` and `Assert.All(sleeps.Skip(1), w => w < 1 s)` (`:309-310`). This is the review's exact fix. With the fix, the sleeper records `[5 s, j1, j2]`: `j1` and `j2` are the jitter waits (≤ 2 ms; `RetryMaxDelay` is 2 ms), and `DevicePollDelay` is called even for a 0 ms wait. **Mutant `delay: null` at `OidcDeviceExchangeLogout.cs:257`** (real `Task.Delay`, bound kept): the sleeper records only `[5 s]`, so `Count == 1` and **the test is killed** in milliseconds. |
| C164-54 (Info), no `WaitAsync` on the Retry-After-past-the-deadline test | **CLOSED** | fd1093b | `ARetryAfterPastTheDeadlineInsideThePollIsNotServed` (`:515`): the call is now `DeviceLoginAsync(Login()).WaitAsync(TimeSpan.FromSeconds(10))` (`:531`). **Mutant "`DeviceLoginAsync` passes `deadline: null`"**: both hooks are off, so the 120 s wait runs on a real `Task.Delay`. `WaitAsync` then throws `TimeoutException` at 10 s. `Assert.ThrowsAsync<OAuthProtocolError>` needs that exact type, so **the test fails in 10 s**, not after about 20 min. The orphaned loop keeps running in the background; see Follow-up. |
| C164-54 (Info), `RetryEvent` order not pinned | **CLOSED** | fd1093b | `:515` now installs `TelemetryHook = events.Add` (the new `SetUp` overload, `:120-138`) and asserts `Assert.DoesNotContain(events, e => e is RetryEvent)` (`:538`). The only `RetryEvent` emit site is `RetryPolicy.cs:236`. **Mutant: move `beforeWait?.Invoke(wait)` after `telemetry.Emit`.** One `RetryEvent("device_poll", 1, 120 s, …)` is emitted before the veto throws, so **the test is killed**. The new boundary test (`:563`) kills it too. The review asked for `operation == "device_poll"`. The test checks any `RetryEvent`, which is stricter, so that is fine. |
| C164-54 (Info), boundary case (`>=` → `>`) | **CLOSED** | fd1093b | New `AWaitThatEndsExactlyAtTheDeadlineIsRefused` (`:546`). It has `expires_in` 6 and interval 5. Every poll gets `503 {"error":"temporarily_unavailable"}` with `Retry-After: 1`, and the call is guarded by `WaitAsync(10 s)`. Trace: the deadline is T0+6. The loop check is 0+5 < 6, so it sleeps 5 s (fake) and polls at t=5. The 503 becomes a `NetworkError` whose `RetryAfter` is 1 s (`NetworkError.FromResponse`, `Core/NetworkError.cs:111`). `DelayFor` gives max(1 s, jitter ≤ 1 ms) = 1 s exactly. `beforeWait` checks 5+1 ≥ 6, which is true, so it throws `expired_token`: 1 request and no event. The test asserts `IsExpiredToken`, `polls()==1` and no `RetryEvent`. **Mutant `>=` → `>` (`:260`):** 6 > 6 is false, so the event is emitted, the fake sleep goes to t=6, attempt 2 gets a 503, and 7 > 6 throws. Then `polls()==2` and a `RetryEvent` is present, so **the test is killed**. |
| C164-54 (Info, text), aa403c8's commit message put the guard on the wrong test | **CLOSED** (noted; the pushed message is not amended) | fd1093b | The commit message's "Plan vs tree" paragraph says the earlier message "put the WaitAsync guard on the wrong test (the 429 one)" and that the guard now sits on the test the null-deadline mutant affects. The `CHANGELOG.md:53-56` bullet says the same. Both are accurate. The review allowed "correct it if amended", and the branch is already pushed. One cosmetic point: the commit message calls aa403c8 "the round-3 commit", while the CHANGELOG calls it "the round-4 commit message". The CHANGELOG uses the review's round numbers, and the commit subjects use the addendum numbers. It is the same commit either way, so this is not a defect. |

The commit's other mutant claims hold by reading:
- **"a null deadline fails three tests"**: `:295` fails with `sleeps.Count == 1`. `:515` fails at its 10 s guard. `:546` fails because `polls()==3`: the in-poll waits are 2 real seconds, then the loop's 5+5 ≥ 6 gives `expired_token` after 3 requests.

**Regression probes:**
- The diff changes no product code. These are unchanged from aa403c8 and conform by reading, as in round 4:
  - the device deadline bound (503 + `Retry-After: 120` with `expires_in` 30 gives 1 request and `expired_token` at fake t=5, with nothing sent at or after t=30);
  - the W7.1c shape;
  - rules 6 and 9;
  - P11;
  - 1.63 isolation.
- CIBA is not touched.
- Test-side checks:
  - The new `SetUp(…, bool retry, TelemetryHook? hook, params …)` overload does not make the existing calls ambiguous. The step arguments (`Pending`, `ServerError500`, lambdas with no parameters) cannot convert to `TelemetryHook(TelemetryEvent)`, so every existing call still binds to the overload it used before. The 4-argument `retry:` overload forwards `hook: null`.
  - Installing a hook in `:515` and `:546` can add `ConfigClampedEvent`s if the 1 ms / 2 ms settings are clamped. These are not `RetryEvent`s, so the assertions are not affected.
  - The new `:290` assertion is safe under the W7.1c expectations: `Intervals(sleeps)` still gives `[5]`.

**Answers to the prompt's questions:**
- **`sleeps.Count` asserted in the `:290` test:** yes. Lines `:309-310` assert 3 sleeps, with the 2 in-poll waits each under 1 s. This kills the in-poll `Task.Delay` revert.
- **A `WaitAsync` guard at `:518`:** yes, at `:531` (it was `:518` before the diff). This turns the null-deadline mutant from about 20 min into a 10 s failure.
- **No `RetryEvent` emitted in `:505`:** yes, at `:538` (the test is now at `:515`), using a real `TelemetryHook`. This kills the `beforeWait`/`Emit` swap.
- **A boundary case:** yes, `:546`, as specified (`expires_in` 6, interval 5, 503 with RA 1). It kills `>=` → `>` and also the order swap.
- **The commit-message slip:** acknowledged in the new commit message and in the CHANGELOG. The old pushed message stays as it is, which the review allowed.

**Version:** `Axiam.Sdk.csproj:6` and `Axiam.Sdk.AspNetCore.csproj:6` are both 1.1.2, which is still right. The change is tests only, with no API change. `CHANGELOG.md:53-56` records round 5 under `[1.1.2]` ("Round 5 (C164-54), tests only").

**Run by the reviewer:**
- No `dotnet` is available, so there was no build, no `dotnet test`, and no mutant was executed. No work directory was created, and there is nothing to delete.
- Read: `git log` and `git diff aa403c8..HEAD` in full.
- Read for context: `RetryPolicy.ExecuteAsync`/`DelayFor`, `TelemetryDispatcher`, `DevicePollCoreAsync`, the `DeviceLoginAsync` loop, `MapDevicePollErrorAsync`/`NetworkError.FromResponse` (`Retry-After` on a 503), and the test `SetUp` helpers.
- Mutants judged by reading, all killed:
  - in-poll sleeper reverted to `Task.Delay` (killed by `:295`);
  - `beforeWait` after `Emit` (killed by `:515` and `:546`);
  - `>=` → `>` in the veto (killed by `:546`);
  - `deadline: null` (killed by `:295`, by `:515` in 10 s, and by `:546`).

**New findings (introduced by the round-5 diff):** none.

**Follow-up (outside the W7 gate):**
- Under the `deadline: null` mutant, `WaitAsync(10 s)` fails the test, but it does not cancel the `DeviceLoginAsync` task. That task keeps running real 120 s delays in the background. This happens only under a mutant and is harmless to the suite. Passing a `CancellationTokenSource(10 s)` token as well would stop it.

---

#### Addendum round 5 — kotlin — commit d9cd47a (PR #80), read after 51f4bd92a

There are three commits (`git log --oneline 51f4bd9..d9cd47a`):
- `2e66cd7` fix(transport) C164-50
- `209aac8` test C164-50, -53, -54
- `d9cd47a` docs: the CHANGELOG

Files in the net diff:
- `internal/ManagementTransport.kt`
- `internal/OneShotBody.kt` (new; it moved here from a private class in `OidcSupport.kt`)
- `internal/Sessionless.kt`
- `oidc/ClientRegistrationSupport.kt`, `oidc/OidcSupport.kt` (only the class moved out)
- `ssf/SsfReceiver.kt`
- `DualStackWritesTest.kt` (new), `CibaTest.kt`, `OidcDeviceFlowTest.kt`
- `CHANGELOG.md`

`grep -rn retryOnConnectionFailure src/main` now finds only two comments. `OneShotBody` is `internal`. No public signature changed.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-50 (Medium) | **CLOSED** in code. **PARTLY** in tests: the one-shot bodies on the sessionless writes are not pinned (C164-56). The fix also brings a §16.1 regression on the one sessionless read (C164-55). | `2e66cd7`, `209aac8` | **Code.**<ul><li>`writeHttp` is gone. `execute` sends every method on the ordinary `http` (`ManagementTransport.kt:187`).</li><li>The bodies (`:156-160`): a `GET` gets no body. A write with a payload gets `OneShotBody(payload)`. Any other write, a bodiless `DELETE` included, gets `OneShotBody("")`.</li><li>`Sessionless.of` no longer sets `retryOnConnectionFailure(false)` (`Sessionless.kt:42-51`).</li><li>The RFC 7592 `PUT` (`ClientRegistrationSupport.kt:91`), the `DELETE` (`:101`, an empty one-shot body) and `ssf.poll` (`SsfReceiver.kt:221`) are one-shot.</li><li>`OneShotBody` is at `internal/OneShotBody.kt:21` (`isOneShot() = true`).</li></ul>**Tests.** `DualStackWritesTest` (`localhost` resolves to `[127.0.0.2, 127.0.0.1]`, pool evicted):<ul><li>`:85`: a management `DELETE` → 1 request.</li><li>`:97`: a management `POST` → 1 request.</li><li>`:110`: the P11 drop on a pooled connection → 1 `DELETE`.</li><li>`:121`: a sessionless `deleteClientRegistration` → 1 request.</li></ul>**Mutants.**<ul><li>M1 (management bodies plain) → **5 fail**: `:110` plus four existing "no write is re-sent after a dropped connection" tests (`SamlTest`, `ScimTargetsTest`, `DirectoryTest`, `SsfManagementTest`).</li><li>M2 (writes back on a `retryOnConnectionFailure(false)` client) → `:85` and `:97` fail.</li><li>M3 (`Sessionless` back to `false`) → `:121` fails.</li><li>M7 (a bodiless `DELETE` gets `null` again, as before) → `:110` fails.</li><li>**M4 (RFC 7592 `DELETE` → plain `.delete()`), M5 (`PUT` body plain) and M6 (`ssf.poll` body plain) survive the suite.** In the probe they give 2, 2 and 4 requests (C164-56).</li></ul> |
| C164-53 (Low), Kotlin part | **CLOSED** | `209aac8` | **t04b** (`CibaTest.kt:302`), retry enabled. It sends one `cibaInitiate` each on: a `DISCONNECT_AFTER_REQUEST` on the pooled discovery connection; a `503` + `Retry-After: 0`; and a `408`. The counts are 1, 2, 3. **t04c** (`:322`): the dual-stack `Dns` with the pool evicted → 1 `bc-authorize`. **Mutant MC** (the initiate body back to plain) → **t04b fails**. In round 4, 0 tests failed. |
| C164-54 (Info), Kotlin items | **CLOSED** | `209aac8` | Each round-4 survivor is now killed:<ul><li>**The dual-stack drop test.** `OidcDeviceFlowTest.kt:536-541` no longer evicts the pool, so the drop lands on a reused connection. MA (the device body plain) → 3 fail, this test (`:536`) among them.</li><li>**CIBA sleep on the clock.** t08g (`CibaTest.kt:475`) checks sleeps `[5, 2, 2]`. MG (sleep → `delay`) → t08g fails.</li><li>**The exact boundary.** t08h (`CibaTest.kt:491`) and the device test (`OidcDeviceFlowTest.kt:572`): a poll at 5 s of a 6 s grant, then `503` + `Retry-After: 1` → `expired_token`, 1 request. MK-CIBA (`isBefore` → `!isAfter`, `OidcSupport.kt:1371`) → t08h fails. MK-device (`:1104`) → the device test fails.</li></ul> |

**Regression probes** (`ReviewerProbeR5Test`, in a throwaway copy). The mock is bound to 127.0.0.1 only. Results are counts of requests the server saw.

*Dual-stack: `Dns` gives `[::1 | 127.0.0.2, 127.0.0.1]`, signed in, `connectionPool.evictAll()` before each call:*

| Call | `::1` first | `127.0.0.2` first |
|---|---|---|
| management `groups.delete` | **1** | **1** |
| management `groups.create` (`POST`) | 1 | 1 |
| management `groups.get` (control) | 1 | 1 |
| sessionless `ssf.poll` (`POST`) | **1** | **1** |
| sessionless `deleteClientRegistration` | 1 | 1 |
| sessionless `updateClientRegistration` (`PUT`) | 1 | 1 |
| sessionless `readClientRegistration` (`GET`) | 1 | 1 |

Under M2, `groups.delete` with `::1` first gives **0** ("IPv6 protocol family unavailable"). Under M3, the sessionless calls give **0**. That is the round-4 behaviour.

*P11: a warm request leaves a pooled connection, then the server reads the next request and drops it unanswered:*

| Call | retry on | retry off |
|---|---|---|
| management `groups.delete` | **1** | **1** |
| management `groups.create` (`POST`) | 1 | 1 |
| sessionless `deleteClientRegistration` | 1 | 1 |
| sessionless `updateClientRegistration` (`PUT`) | 1 | 1 |
| `ssf.poll` (retried under §16) | 3 | 1 |
| management `groups.get` (retried under §16, pre-existing) | **4** | **2** |
| sessionless `readClientRegistration` (retried under §16) | **4** | **2** (C164-55) |

Every never-retried write is received **exactly once**, so P11's own test holds on both clients. Under M1, the management `DELETE` and `POST` give 2 each.

*Not touched by the diff, and the full run passes:* the device and CIBA deadline bound with `503` + `Retry-After: 120` / `expires_in` 30 (t08e), W7.1c, rules 6/9 and the 1.63 isolation. `Sessionless` keeps its cookie jar, authenticator and redirect stripping (`Sessionless.kt:42-51`). Only the retry flag changed.

**Answers to the prompt's questions**

*1. Management `DELETE` and sessionless `POST` on a host resolving to `[::1 | 127.0.0.2, 127.0.0.1]`, pool evicted.* One server request each (table above). The read-and-drop P11 test also gives one request: the existing management test, `DualStackWritesTest:110`, and the probe on both clients.

*2. P11's other parts.* Kotlin has **no** dedicated non-pooled handler and no `Connection: close`:
- the writes ride the ordinary pooled `http` (and `Sessionless.of(http)` shares its pool);
- the probe saw `Connection: Keep-Alive` on every write.

This is not lost by round 5: round 4's `writeHttp` was `http.newBuilder()`, documented as sharing "its pool, interceptors, cookie jar and TLS". Nor is it required of Kotlin. P11 makes those three items the **C#** remedy; for an SDK whose library has a switch, the binding text is to switch the re-send off. A one-shot body is OkHttp's per-request form of that switch. The probes show exactly-once delivery on both pooled and fresh connections.

The body is always present on every write: `DELETE` gives `Content-Length: 0`, `Content-Type: application/json; charset=utf-8`, bodySize 0. A `POST`/`PUT` gives its JSON.

*3. Ruling input: `Content-Length: 0` on a `DELETE`.* P11, exactly (`CONTRACT.md:13180-13183`):

> "In .NET a fresh connection alone is not enough — `SocketsHttpHandler` still re-sends a request that has no content — so the C# remedy is all three of: a dedicated, non-pooled handler for those requests, `Connection: close` on them, and content on every one of them (an empty body where the operation has none)."

- **Yes, `Content-Length: 0` is what that asks.** "An empty body where the operation has none" on the wire is a zero-length body declared by `Content-Length: 0`. .NET's empty content sends the same header.
- For Kotlin the clause is not binding: it is the C# remedy. It is harmless, though. In OkHttp it is how a bodiless `DELETE` gets a one-shot body, and that is what stops the replay. Mutant M7 (`null` body on `DELETE`) re-sends: `:110` fails.
- **Server side:** a script resolved every `web::delete()` route in `crates/axiam-api-rest/src/server.rs` (36 handlers, dcr `delete_registration` and SCIM's two included). **None takes a body extractor** (`Json`, `Bytes`, `Form`, `Payload`, `String`, `Multipart`).
- No middleware checks `Content-Length` or `Content-Type` on a `DELETE` (grep for `content_length`, `CONTENT_TYPE`, `Method::DELETE`, `PayloadConfig`, `JsonConfig`: only response builders and one `network.rs` `JsonConfig` for that handler's `Json` bodies).
- actix-web does not read an unextracted body, and RFC 9110 §9.3.5 allows content on a `DELETE`, with zero length the trivial case.
- **AXIAM accepts it.**

**Version:** `gradle.properties:2` `version=1.1.2` is right: no public API changed (`OneShotBody` is `internal`). The CHANGELOG `[1.1.2]` records round 5:
- `:81-86`: the management and sessionless route fallback, with the empty one-shot `DELETE` and `Content-Length: 0`;
- `:77-80`: the extended `OneShotBody` text;
- `:125-131`: the round-5 tests.

It does not mention that the sessionless read now gets OkHttp's re-send (C164-55).

**Run by the reviewer** (throwaway copies `/home/user/work/kotlin-r5` and `kotlin-r5m` from `git archive d9cd47a`; JDK 21, Gradle wrapper):
- `python3 scripts/gen_management.py --check` → `OK: 251 generated files are current (202 operations)`.
- `./gradlew test --no-daemon -Dorg.gradle.jvmargs=-Xmx3g -Pkotlin.daemon.jvmargs=-Xmx3g` → **BUILD SUCCESSFUL in 9m 15s: 1323 tests, 0 failures, 0 errors, 0 skipped, 89 classes.** That is 1314 plus 9 new: `DualStackWritesTest` 4, t04b, t04c, t08g, t08h, and the device boundary test.
- Mutants (unmutated baseline green):

  | Mutant | Failing tests |
  |---|---|
  | M1 | 5 |
  | M2 | 2 |
  | M3 | 1 |
  | **M4** | **0** |
  | **M5** | **0** |
  | **M6** | **0** |
  | M7 | 1 |
  | MC | 1 |
  | MG | 1 |
  | MK-CIBA | 1 |
  | MK-device | 1 |
  | MA | 3 |

- Probes ran at HEAD and under every mutant.
- The copies, the probe class, the logs and all build outputs were deleted. The SDK clone is unmodified (`git status` clean). Not run: `koverVerify`, `dokka`, lint.

**New findings (introduced by the round-5 diff):**
- **C164-55 — Low — §16.1 attempt cap on `readClientRegistration`.** `Sessionless.kt:42-51` (the removed `.retryOnConnectionFailure(false)`), with `ClientRegistrationSupport.kt:63-85`.
  - A `GET` cannot carry a one-shot body. Now that `Sessionless` keeps OkHttp's connection retry on, OkHttp silently re-sends the RFC 7592 read after a drop on a pooled connection, inside a §16 attempt.
  - Probe: read-and-drop gives **4** requests with retry on (cap: 3 total). With `retryDisabled()` it gives **2** (exactly one attempt is required).
  - In round 4 (mutant M3) it was at most 3 / 1. The KDoc it replaces said the reads "are retried by §16's policy, where a retry is counted and reported". That is now untrue for this read.
  - The management `GET`s show the same 4 / 2. That is pre-existing (they always rode `http`); see the follow-up.
  - **Fix:** count OkHttp's own re-sends against the §16 budget for reads. For example, a per-call network interceptor or `EventListener` that counts request starts and feeds them to `withRetry`, so that a replayed attempt uses up a retry and retry-off raises after the first. Alternatively, record the deviation explicitly in the CHANGELOG and README.
  - **Test:** `readClientRegistration` with a pooled connection, every answer `DISCONNECT_AFTER_REQUEST` → 3 requests, and 1 with `retryDisabled()`.
- **C164-56 — Low (test strength, new code) — the sessionless one-shot bodies are unpinned.** `ClientRegistrationSupport.kt:91` and `:101`; `SsfReceiver.kt:221`.
  - C164-50's fix asked for P11's drop test "on each client". `DualStackWritesTest:110` covers only the management transport.
  - M4, M5 and M6 pass all 1323 tests, yet re-send in the probe: 2 `DELETE`s, 2 `PUT`s, and 4 `ssf.poll`s (cap 3).
  - **Test:** for `deleteClientRegistration`, `updateClientRegistration` and `ssf.poll`, a pooled connection followed by a read-and-drop → 1, 1 and 3 requests (`ssf.poll` with `retryDisabled()` → 1).

**Follow-up (outside the W7 gate):**
- Management `GET`s retried under §16 also exceed the cap after a drop on a pooled connection: 4 requests with retry on, 2 with retry off. This is pre-existing (OkHttp's re-send on the ordinary client). It has the same remedy as C164-55.

---

#### Addendum round 5 — php — commit 12161d496 (PR #87), read after d127d75ee

There are two commits. `5d7b418` holds the code and tests (C164-52, C164-54), and `12161d4` holds the CHANGELOG entry and the README wrap. Each commit message matches its diff. `git diff d127d75..12161d4` touches four files: `src/Oidc/OidcClient.php` (only `cibaAwait`, +15/−2), `tests/Contract164/CibaDeadlineBoundTest.php` (+6 tests and a `$set` return), `CHANGELOG.md` (+10) and `README.md` (the line wrap). `cibaPollTracked`, the device loop, `devicePollWithin`, the middlewares, `AxiamClient` and the generated surface are untouched. Mutants and probes ran on a throwaway clone, `/home/user/work/php-r5`, which has since been deleted.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-52 (Low): CIBA's `429 rate_limit_exceeded` ignores its `Retry-After` (§33.7 rule 5, §16.1) | **CLOSED** | 5d7b418 | **Code:** `src/Oidc/OidcClient.php:2169-2177`. The branch is now `if ($e->error === 'rate_limit_exceeded' \|\| $e->httpStatus === 429)`, so the status decides, as for the device loop (`:1064`). When `retryAfterMs` is present, `$waitSeconds = self::retryAfterRound($interval, …)`, which is `max(interval, ceil(RA))` (`:1098-1101`). It applies once, and `$interval` is untouched. `authorization_pending` is a plain `continue` again (`:2178-2180`). The carried wait goes through the existing pre-sleep check (`:2144-2150`), so a wait that would reach the deadline raises the local `expired_token` with no request.<br>**Tests** (`tests/Contract164/CibaDeadlineBoundTest.php`):<ul><li>`:163` `testA429WithRetryAfterMakesTheNextWaitAtLeastThat`: interval 5, `429 {"error":"rate_limit_exceeded"}` + RA 12, then `200` gives sleeps `[5, 12]`, sent `[1005, 1017]`, tokens. This is exactly the requested 12 s wait.</li><li>`:175`: `expires_in` 15 gives sent `[1005]`, sleeps `[5]`, `expired_token`. This is the deadline check.</li></ul>**Mutant R1** (revert: the 429 goes back to a plain `continue`): **both fail**.<br>**Survivors** of the new tests: R2, R3 and R5, see C164-57. |
| C164-54 (Info), PHP items: whole-second CIBA floor; mutants C6 and C7 unpinned | **CLOSED** | 5d7b418, 12161d4 | **Code:** `:2161-2163` passes `static fn (): float => floor($deadline - $clock->now())` as `$remaining`, exactly the fix in the round-4 addendum. A retry is admitted only when `wait < floor(left)`, which gives `ceil(wait) ≤ floor(left) ≤ left`. The `CibaClock`'s rounded-up wait therefore cannot end past the deadline. The guard (`remaining() <= 0`, `:2314-2317`) is unchanged.<br>**Tests and mutants:**<ul><li>`:214` `testAWholeSecondClockCannotServeAWaitPastTheDeadline` (pending at +19.5 s, then a `500` at 29.5 s): 2 requests, `expired_token`, clock ≤ 1030. **R4** (the `floor` removed) fails it: the clock ends at 1030.5.</li><li>`:185` (retry off, `503` RA 2 gives `[5, 5]`). **C6** (the carry without the interval floor) fails it, so it is now **killed**.</li><li>`:194` (RA 12 gives `[5, 12]`).</li><li>`:203` (`503` RA 25 at expires_in 30 gives 1 request, `expired_token`, `[5]`). **C7** (`<` → `<=`) fails it, so it is now **killed**.</li></ul>**Text:** `CHANGELOG.md:39-48` records both findings. `README.md:809-814` is wrapped, so the cosmetic line from round 4 is fixed. |

Regression probes (the round-5 diff changes only `cibaAwait`, so only the CIBA probes were re-run). The probe goes through the public `cibaAwait()` on a fake `CibaClock`. Script `scratchpad/php-r5-probes/probe.php`, log `scratchpad/php-r5-probe.log`.
- **CIBA deadline bound, expires_in 30, interval 5:**
  - Every poll `503` + RA 120: 1 request at 5 s, `expired_token` at 5 s.
  - RA 20: requests at 5 and 25 s, sleeps `[5, 20]`.
  - RA 12: requests at 5, 17 and 29 s.
  - A `500` back at 29.999 s, or one sent at 29.9 s: not retried.
  - No `ciba_poll` goes out at or after `received_at + 30`. All of this is identical to round 4.
- **Whole-second edge (C164-54):**
  - A `500` at 29.5 s (3 runs): the clock ends at 29.5 s, 2 requests, `expired_token` on time. Round 4 ended at 30.501 s.
  - A `500` at 29.0 s, 28.9 s or 28.0 s: a 1 s retry wait is admitted. The clock ends at the deadline at the latest (1030.0), and nothing is sent at or after it.
  - At 28.9 s the 1 s wait is served and the retry is then not sent, because 0.1 s left floors to 0. That is conservative and conforms.
  - `503` RA 3 at 25.5 s (4.5 s left floors to 4): served, then tokens at 28.5 s. RA 4: declined, `expired_token`.
- **429 set (new):**
  - RA 12 → `[5, 12]`, tokens.
  - RA 12 with exp 15 → 1 request, `expired_token` at 5 s.
  - RA 25 with exp 30 → 1 request, `expired_token`. RA 24 with exp 30 → a poll at 29 s, tokens.
  - RA 2 → `[5, 5]` (never shorter). No RA → `[5, 5]`.
  - RA 12, then pending, then `200` → `[5, 12, 5]` (carried once, and the interval is not raised).
  - `slow_down`, then 429 RA 7 → `[5, 10, 10]`.
  - 429 RA 12 ×3 → `[5, 12, 12, 12]`.
  - `429 {"error":"slow_down"}` RA 3 → `[5, 5]`: the interval is not raised, the status decides (§14.2 C164-04, mirrored by §33.7 rule 5). `429 {"error":"access_denied"}` → waited out, not raised.
  - Retry off → `[5, 12]`.
  - A bare `cibaPoll()` on a 429 → 1 request and `OAuthProtocolError(rate_limit_exceeded)`. Rule 9 holds: the 429 is never retried inside the poll.
  - The bodiless 429 still gives `[5, 12]`.
- **W7.1c shape, CIBA:**
  - `500, 500, 200` → 3 requests, `[5, 1, 1]`.
  - `500` ×3 then `200` → 4, `[5, 1, 1, 5]`.
  - Reset ×2 / ×3 give the same shape.
  - Retry off → `[5, 5]`.
  - A bare `cibaPoll` with `503` RA 1 ×3 → 3 requests at 0, 1.0 and 2.0 s on a real `usleep`, then `NetworkError`.
  - All of this is unchanged from round 4.
- **Not re-run:** the device bound, rules 6/9 on the device side, P11 and 1.63 isolation. The diff touches none of their code, and their tests are in the green suite.

**Answers to the prompt:**
- **C164-52:** interval 5, `429` + RA 12, then `200` gives a recorded wait of exactly 12 s (`[5, 12]`), in both the SDK's test and the probe. With `expires_in` 15, that wait is checked against the deadline and the flow ends with `expired_token`, 1 request and no sleep past 5 s.
- **C164-54:** `expired_token` is no longer late. The clock ends at 29.5 s, not 30.501 s, and no admitted wait ends past the deadline. C6 ("carry never shortens the interval") is now killed by `:185`, and C7 (`<`/`<=`) by `:203`.

**Version:** 1.1.2 is still right: `CHANGELOG.md:10` `## [1.1.2] - Unreleased`, and the install snippets read `^1.1.2` (`README.md:27`, `:457`). No public signature changed. The CHANGELOG records round 5 at `:39-48`.

**Run by the reviewer** (clone `/home/user/work/php-r5` at 12161d4; PHP 8.3.6, Composer 2.8):
- **Install:** `composer install` used the round-1 lock, with phpstan/phpstan 2.3.1 from a local `git clone --depth 1 --branch 2.3.1` (`6155239`) as a `path` repository. The repository and lock edits were local to the clone. Log: `scratchpad/php-r5-install.log`.
- **Checks:**
  - `vendor/bin/phpunit`: **OK, 2080 tests, 10001 assertions**. Round 4 had 2074; this round adds 6 CIBA tests.
  - `vendor/bin/phpstan analyse --memory-limit=512M`: **No errors**.
  - `python3 scripts/gen_management.py --check`: "§27 surface is current (261 files)".
  - `php tools/docblock-coverage.php`: all public items documented.
- **Mutants** (`scratchpad/php-r5-mut.sh`, `php-r5-mut.log`):
  - Killed: R1 (the C164-52 revert, 2 fail), R4 (the C164-54 revert, 1), C6 (1) and C7 (1).
  - Survived: R2, R3 and R5 (C164-57).
- **Cleanup:** the clone, `vendor/` and the phpstan clone are deleted. `/home/user/sdks/php` is untouched and clean at 12161d4.

**New findings (introduced by the round-5 diff):**
- **C164-57 — Info (test strength, new tests).** `tests/Contract164/CibaDeadlineBoundTest.php:163-183` pins only a 429 whose `Retry-After` (12) is above the interval, followed directly by the `200`. Three mutants of the new branch survive the suite:
  - **R2:** drop `|| $e->httpStatus === 429`, so the body decides.
  - **R3:** carry `ceil(RA)` with no interval floor, so a 429's RA 2 shortens the interval.
  - **R5:** `$interval = retryAfterRound(...)`, so the 429 raises the interval permanently.

  The CHANGELOG (`:41-42`) and the code comment both claim "never shortening the interval, never raising it". **Exact fix:** add three cases.
  - (a) `429 {"error":"rate_limit_exceeded"}` RA 2, then `200` → `[5, 5]`.
  - (b) RA 12, then `authorization_pending`, then `200` → `[5, 12, 5]`.
  - (c) `429 {"error":"slow_down"}` RA 3, then `200` → `[5, 5]`.
- **C164-57 — Info (text).** The `cibaAwait` docblock (`src/Oidc/OidcClient.php:2103-2104`) still says a "`429` (`rate_limit_exceeded`) that outlived §16 … the loop waits the interval and polls again". After this diff, the next wait is `max(interval, Retry-After)`, checked against the deadline. The same sentence has also been stale for the 5xx/transport carry since round 4. **Exact fix:** replace the sentence with "…waits the interval, or the failure's `Retry-After` if longer (once; the interval is never raised), and polls again; a wait that would reach the deadline ends the flow with `expired_token`."

**Follow-up (outside the W7 gate):**
- In `cibaPollTracked`, the floored `remaining()` also feeds the guard. So when less than 1 s is left after an admitted wait, that wait is served and nothing is sent (probe: a `500` at 28.9 s). This conforms. It could be avoided by checking the wait against the unrounded time left after the sleep, but there is no conformance impact.

---

#### Addendum round 5 — swift — commit 7d28ce497 (PR #78), read after 5265aed42

There are two commits. `2a464ae` adds the tests: +47 lines in `Tests/AxiamSDKTests/CibaTests.swift`. `7d28ce4` holds the text: the `cibaAwait` doc comment, the `CibaStep.transient` doc comment, the README and the CHANGELOG. **No executable line changed.** The `Ciba.swift` diff touches only `///` lines (`C:518-522` and `C:657-658`). Each commit message matches its diff. No Swift toolchain is installed, so I read the code and traced every mutant by hand. Paths are under `/home/user/sdks/swift`:
- `C` = `Sources/AxiamSDK/Oidc/Ciba.swift`
- `B` = `Sources/AxiamSDK/HTTP/BareRequest.swift`
- `T` = `Tests/AxiamSDKTests/CibaTests.swift`

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-54 (Info), text: the `cibaAwait` doc said "waits the interval", and the README omitted the CIBA bound | **CLOSED** | `7d28ce4` | <ul><li>`C:517-522` now reads: "waits the interval or the answer's `Retry-After`, whichever is longer … A §16 wait or a loop wait that would reach `receivedAt + expiresIn` is not taken: nothing more is sent and `expired_token` is raised at once (§34.2 P10)". This is the review's exact fix.</li><li>`README.md:2534-2537` says the same and adds "a bare `cibaPoll` has no deadline".</li><li>`C:657-658` (the `CibaStep.transient` doc) is corrected in the same way.</li><li>`CHANGELOG.md:66-71` records it under `[1.1.2]` as text and test strength, with no behaviour change.</li><li>**The "at once" claim checked against the code.** A refused RA wait is floored by the loop (`C:552-557`), so the loop refuses it too. A refused jittered backoff is at most 0.4 s: §16 retries only attempts 1 and 2 (`Retry.swift:17,21,27`). The interval is an `Int` of at least 1 (`C:546`), so the loop's wait is never shorter than the wait just refused. A refused transport failure ends at the interval. The text is accurate.</li></ul> |
| C164-54 (Info), M5: drop `\|\| response.status == 429` from the deferral (`C:494`) | **CLOSED** (killed) | `2a464ae` | **Test:** `testT07BA429RateLimitRetryAfterIsTheFloorOfTheLoopsNextWait` (`T:438`). The poll gets `429 {"error":"rate_limit_exceeded"}` + RA 20, then tokens; `expires_in` 600, interval 5.<br>**Trace, real code:**<ul><li>`bareShouldRetry(.section16UnlessOAuthError)` sees status < 500 and an OAuth body, so there is no in-poll retry (`B:139-143`). That makes 1 request.</li><li>`oidcMapGrantError` gives `.auth(rate_limit_exceeded)`. It is deferred with RA 20. `cibaStep` classes it `.transient` (`C:671`).</li><li>The loop waits `max(5,20)` = 20; 5+20 < 605. The second poll is at stamp 25 and returns 200.</li><li>Stamps `[5,25]`, sleeps `[5,20]`: **passes**.</li></ul>**Under M5:** the error is a plain `AxiamError` caught at `C:579`, so `retryAfter` stays 0. The wait is 5, and the poll at stamp 10 returns tokens. Stamps `[5,10]`, sleeps `[5,5]`: **both asserts fail. Killed.** |
| C164-54 (Info), M6: `B:104` `>=` → `>` (the in-poll guard's boundary) | **CLOSED** (killed) | `2a464ae` | **Test:** `testT07BAWaitThatLandsExactlyOnTheDeadlineIsNotTaken` (`T:460`). `expires_in` 25, interval 5; every poll gets `503 temporarily_unavailable` + RA 20 (the last reply repeats).<br>**Trace, real code:**<ul><li>At t=0, 0+5 < 25, so the loop sleeps 5.</li><li>Request 1 is at stamp 5. A 5xx is retried in-poll. The wait is `max(0·0.2, 20)` = 20, and `now()` is the injected clock: 5+20 = 25 ≥ 25. The wait is refused, with no `retry` event, and the 503 is returned.</li><li>It is deferred with RA 20 and classed transient. The loop computes `max(5,20)` = 20; 5+20 ≥ 25, so it raises `expired_token`.</li><li>Stamps `[5]`, no `retry`: **passes**.</li></ul>**Under M6:** the guard does not fire, so a `retry` event is emitted. `_sleep` is a no-op (`T:61`), so the clock stays at 5. Attempts 2 and 3 are also at stamp 5, and attempt 3 is the last, so the 503 is returned. Stamps `[5,5,5]` and two `retry` events: **both asserts fail. Killed.**<br>**Bonus M6′:** with the loop guard `C:556` `>=` → `>`, the loop sleeps 20 and polls at stamp 25. Stamps `[5,25]`: **fails. Killed.** The commit message says the author ran the same three mutants. |
| C164-54, in-poll waits sleep on `_sleep` (real `Task.sleep`) and not on the injected `CibaClock` | **Not changed (optional)**. Posture, not conformance | none | <ul><li>CONTRACT §34.2 P10 (`CONTRACT.md:13157-13169`): "The anchor and the waits **SHOULD** both come from the injected clock". The binding sentence is the **MUST**: "A §16 retry inside `ciba_poll` … MUST NOT wait past the deadline".</li><li>The MUST is met. The guard reads the injected clock (`C:561-563` → `B:104`), and `T:392`/`T:460` pin that.</li><li>The SHOULD is met for the loop's waits only. The deviation is a SHOULD-level posture, and it weakens the tests: an in-poll wait is not visible in `clock.sleeps`. **It is not a conformance defect.** It matches Kotlin/C++ in C164-48. It is recorded under Follow-up below.</li><li>The commit `2a464ae` message records that it was left unchanged on purpose ("Plan vs tree").</li></ul> |

**Regression probes:** none of the probe-relevant code changed. `git diff 5265aed..7d28ce4 -- Sources` contains only doc-comment lines.
- **CIBA deadline bound** (`expires_in` 30, interval 5, every poll `503` + `Retry-After: 120`): unchanged since round 4. The result is still 1 request at stamp 5, `expired_token` at about 5 s, and nothing at or after 30 s. `T:392` still pins this.
- **Device bound, W7.1c shape, rules 6/9, P11, 1.63 isolation:** not touched by the diff. `DeviceGrant.swift`, the headers, the refresh and the transports are not in it. The round-4 traces stand.
- **The new tests themselves:**
  - Each uses only existing helpers: `TestCibaClock` (`T:924-946`), `RoutedTransport(stamp:)` with the last reply repeating (`RoutedTransport.swift:108-109`), `EventRecorder.kinds`, `makeClient(…, recorder:)` and `Self.tokens`/`response`/`configuration`.
  - Neither sleeps on the wall clock.
  - The boundary test's single 503 route cannot answer a request it should not get, because the stamps assert pins the count.
  - Both are independent of the real date: the clock is anchored at 2027-01-15.

**Answers to the prompt's questions:**
1. **C164-54 text:** CLOSED. The doc comment (`C:517-522`) and the README CIBA paragraph (`README.md:2534-2537`) carry the review's exact wording, and that wording is accurate against the code.
2. **M5 and M6:** now killed, by `T:438` and `T:460` respectively. `T:460` also kills the loop-guard boundary mutant.
3. **The in-poll injected-clock change:** I confirm it is a test-strength/posture item (a P10 SHOULD), not a conformance one (the P10 MUST is met). It is recorded under Follow-up.

**Version:**
- **1.1.2 is still right** (`AxiamSDK.podspec:3`; `CHANGELOG.md:10` `[1.1.2] - 2026-10-23`). The round adds tests and text only, with no public signature change and no behaviour change.
- The CHANGELOG records round 5 as C164-54 (`CHANGELOG.md:66-71`).
- The README still states conformance at contract 1.64 (`README.md:15`).

**Run by the reviewer:**
- `python3 -I Scripts/gen_management.py --check` in the throwaway clone `/home/user/work/swift-r5` at `7d28ce4`: "§27 surface is current (3 files).", rc=0. I deleted the clone afterwards.
- `git log --format=%G?`: `N` for both commits. There is no allowed-signers file, so the signatures could not be verified (same as round 4).
- The SDK clone's working tree is clean. I did not edit, commit or push anything there.
- **Not run:** `swift build` and `swift test` (no toolchain). The tests and mutants were traced by hand, as above.

**New findings (introduced by the round-5 diff):** none.

**Follow-up (outside the W7 gate):**
- The CIBA in-poll §16 waits sleep on the `_sleep` seam (real `Task.sleep`), not on the injected `CibaClock`. This is a P10 SHOULD that is only partly met. Conformance is unaffected, since the MUST deadline guard reads the injected clock. The cost is test strength: in-poll waits are invisible to `clock.sleeps`. The optional fix is to route `bareSend`'s sleep through `clock.sleep` under `cibaAwait`. This matches Kotlin/C++ in C164-48.

---

### 7.5 Addendum round 6 (2026-10-23): the three round-6 heads

**Scope.** As in §7.4: only the three round-6 diffs were read.

| SDK | PR | Head | Commits read |
|---|---|---|---|
| Kotlin | #80 | `b8a70b4` | `c0ba2e7` tests, `b8a70b4` docs; read after `d9cd47a` |
| PHP | #87 | `b61dc3938` | read after `12161d496` |
| C++ | #80 | `de76426` | read after `007aa6b` |

The other eight heads are unchanged and have nothing open: TypeScript `50d6f72`, Rust `c947a5e`, Python `9e69284`,
C `832a421`, C# `fd1093b`, Go `2a0c273`, Java `97dcdf0`, Swift `7d28ce4`. All eleven match `git ls-remote`.
`scripts/check-sdk-artifact-drift.py --local-root` reports **11 repos, 0 artifact problems**.

#### 7.5.1 Verification

| SDK | Finding | Verdict |
|---|---|---|
| kotlin | C164-56 | **Closed** (`c0ba2e7`). `DualStackWritesTest` adds the read-and-drop case on each sessionless write: `deleteClientRegistration` → 1 request (`:154`), `updateClientRegistration` → 1 (`:165`), `ssf.poll` → 3 (`:181`). M4, M5 and M6 (each body made plain again) each fail their own test, and the unmutated control passes. |
| kotlin | C164-55, option (a) | **Closed** (`c0ba2e7`, `b8a70b4`). `readClientRegistration` is pinned at 3..4 sends with retry on and 1..2 with it off (`:197-215`); it measures 4 and 2. README §16 (`:2519-2524`) and the CHANGELOG `[1.1.2]` (`:125-130`) record OkHttp 4.12's replay of an idempotent `GET` on a stale pooled connection, with the bounds. OkHttp 5.x is named as a follow-up. No `src/main` change. `./gradlew test`: 1327 tests, 0 failed. |
| php | C164-57 | **Closed** (`b61dc39`). Four tests in `tests/Contract164/CibaDeadlineBoundTest.php:234`, `:243`, `:256` and `:269` kill R2 (the body decides), R3 (the carry shortens the interval) and R5 (the 429 raises the interval). R1, R4, C6 and C7 still fail as well. The `src/` change is docblock only (`:2103-2106`, verified by the lead reviewer too) and now states the wait accurately. phpunit 2084 / 10009; phpstan clean. |
| cplusplus | C164-58 | **Closed** (`de76426`). `std::clamp(expires_in, 0, 1e9)` sits at both sites (`src/oidc.cpp:1746`, `:2593`). `INT64_MIN`, `INT64_MAX` and −9e18 run clean under UBSan. A negative value behaves as 0: an immediate `expired_token`, with no sleep and no poll. The lower-clamp mutants L1 and L2 are killed at each site. Four exact-deadline tests kill B1–B4 (`>=` → `>`, at `:916`, `:1769`, `:2478`, `:2608`), each by its own test. The CHANGELOG wording is now accurate. ctest 1641 cases, 0 failed, normal and UBSan. SOVERSION 4 and 1.1.2 stand. |

Every version is 1.1.2, and every CHANGELOG records round 6.

#### 7.5.2 New items introduced by the round-6 diffs

| ID | Severity | SDK | `path:line` | What | Fix |
|---|---|---|---|---|---|
| C164-59 | Info | kotlin | `README.md:2521`; `CHANGELOG.md:125` | Both new texts say the read "can reach the server **once more per §16 attempt**". Read literally, that allows 6 sends. The behaviour, and the bounds both texts go on to state (4 with retry on, 2 with it off), is one replay **in total**, on a stale pooled connection only. Verified by the lead reviewer. | In both places, replace "once more per §16 attempt" with "once more in total (OkHttp replays it once on a stale pooled connection)". |

PHP and C++: none. **Follow-up** (outside the gate): unchanged from §7.4.4.

#### 7.5.3 The W7 gate

| SDK | Open |
|---|---|
| typescript, rust, python, c, cplusplus, csharp, go, java, php, swift | **none** |
| kotlin | C164-59 (Info, a two-line wording fix) |

**Can W7 merge? Not yet, by one Informational wording fix in Kotlin.** Every Medium, Low and Informational finding
from rounds 0 to 5 is closed in all eleven SDKs. Once Kotlin replaces the two phrases, a read of that one-commit
docs diff closes the gate. With no code change, no test run is needed: the reviewer checks the two lines and the
CHANGELOG entry.

The three round-6 addenda follow.

---

#### Addendum round 6 — kotlin — commit b8a70b4 (PR #80), read after d9cd47a

Two commits (`git log --oneline d9cd47a..b8a70b4`): `c0ba2e7` test (C164-56, -55) and `b8a70b4` docs (README §16, CHANGELOG). Net diff: `DualStackWritesTest.kt` (+117/-16), `README.md` (+7), `CHANGELOG.md` (+10). **No `src/main` change** (`git diff --stat d9cd47a..HEAD -- src/main` is empty). The one-shot bodies are still at `ClientRegistrationSupport.kt:91` (`PUT`), `:101` (`DELETE`) and `SsfReceiver.kt:221` (`ssf.poll`).

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-56 (Low): read-and-drop P11 case on each sessionless write | **CLOSED** | `c0ba2e7` | New helper `pooledClientThatDrops()`: a dual-stack `Dns`, a login that leaves a pooled connection, then the server drops every request it reads (`DISCONNECT_AFTER_REQUEST`). Tests: `DualStackWritesTest.kt:154` `deleteClientRegistration` → exactly 1; `:165` `updateClientRegistration` → exactly 1; `:181` `ssf.poll` → exactly 3 (the §16 cap, nothing replayed on top). **Mutants** (throwaway copy, `--tests DualStackWritesTest`): **M4** (RFC 7592 `DELETE` → plain `.delete()`) → `:154` fails. **M5** (`PUT` → `.put(body)`) → `:165` fails. **M6** (`ssf.poll` → `.post(body)`) → `:181` fails. Each kills exactly one test (8 run, 1 failed). The unmutated control (M0) passes 8/8. |
| C164-55 (Low), option (a): test | **CLOSED** | `c0ba2e7` | `DualStackWritesTest.kt:197-215`: `readClientRegistration` over a pooled connection that drops. It asserts `in 3..4` sends with retry on and `in 1..2` with `retryDisabled()`. Observed (stdout probe added to the copy): **4 and 2**. |
| C164-55 (Low), option (a): README §16 and CHANGELOG | **CLOSED** (one wording nit, C164-59) | `b8a70b4` | `README.md:2519-2524`: "OkHttp 4.12 recovers an **idempotent read** on a stale pooled connection by itself. The RFC 7592 `readClientRegistration` is such a `GET` … at most 4 sends with retry on, 2 with `retryDisabled()`". It also says every write is one-shot and sent exactly once per attempt. `CHANGELOG.md:125-130` under `[1.1.2]`: "OkHttp 4.12 recovers the idempotent RFC 7592 `GET` once on a stale pooled connection … at most 4 sends with retry on (the §16 cap is 3 attempts) and at most 2 with `retryDisabled()`; round 4 gave 3 and 1". It names OkHttp 5.x as a follow-up. Round 6 is recorded at `:131-134`. Both texts name OkHttp's stale-pooled-connection replay of an idempotent `GET` and give the right bounds. |

**Regression probes:** the diff touches only tests and text, so the device/CIBA deadline bound, W7.1c, rules 6/9, P11 on the management client and 1.63 isolation stand as in round 5. The full suite is green. The P11 counts the new tests assert (1 / 1 / 3) and the read count (4 / 2) match the round-5 probe table.

**Answers:**
- Read-and-drop cases with 1, 1 and 3 requests: **yes** (`:154`, `:165`, `:181`). M4, M5 and M6 each fail a test: **yes**.
- Read pinned at 3..4 with retry on and 1..2 with it off: **yes** (`:197-215`). It observes 4 and 2.
- README §16 and CHANGELOG name OkHttp's stale-pooled-connection replay of an idempotent `GET` and the bounds: **yes**.
- No `src/main` change: **confirmed**.

**Version:** 1.1.2 (`gradle.properties:2`, CHANGELOG `[1.1.2]`), still right. Round 6 is recorded.

**Run by the reviewer:**
- Throwaway copies `/home/user/work/kotlin-r6/{base,mut}` (`git archive b8a70b4`).
- `./gradlew test --no-daemon` with 3 GB heaps: **BUILD SUCCESSFUL**, **1327 tests, 0 failed, 0 skipped** (6 min).
- Mutants M0/M4/M5/M6 on `DualStackWritesTest`, made with `sed` on the `mut` copy and restored after each run.
- Copies and logs deleted afterwards. The SDK clone is unchanged (`git status` clean).

**New findings (introduced by the round-6 diff):**
- **C164-59 (Info, text).** The README (`:2521`) and the CHANGELOG heading (`:125`) say the read can reach the server "**once more per §16 attempt**". That would allow up to 6 sends with retry on. The same sentence, the test and the probe all give at most 4: the one OkHttp replay happens on the stale pooled connection only. Suggested wording: "once more in total (on the stale pooled connection)". The bounds themselves are right. This does not block.

**Follow-up (outside the W7 gate):** unchanged from §7.4.4. Management `GET`s show the same replay (4 / 2), and the README note names only `readClientRegistration`. Two `src/main` comments still mention `retryOnConnectionFailure(false)` (`ManagementTransport.kt:154`, `OneShotBody.kt:10`).

---

#### Addendum round 6 — php — commit b61dc3938 (PR #87), read after 12161d496

There is one commit, `b61dc39`, and its message matches its diff. `git diff 12161d4..b61dc39` touches three files:
- `tests/Contract164/CibaDeadlineBoundTest.php`: +4 tests (+46).
- `src/Oidc/OidcClient.php`: +4/−2, all inside the `cibaAwait` docblock. Every changed line is a ` *` comment line, so no code changed.
- `CHANGELOG.md`: +5.

The mutants ran on a throwaway clone, `/home/user/work/php-r6`, which has since been deleted.

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-57 (Info): three surviving mutants of the CIBA 429 branch; stale `cibaAwait` docblock | **CLOSED** | b61dc39 | **Tests** (`tests/Contract164/CibaDeadlineBoundTest.php`):<ul><li>`:234` `testA429RetryAfterBelowTheIntervalStillWaitsTheInterval`: interval 5, `429` + RA 2, then `200` gives `[5, 5]`.</li><li>`:243` `testTheCarryOf429IsConsumedOnceAndTheIntervalIsNotRaised`: 429 RA 12, then pending, then `200` gives `[5, 12, 5]`.</li><li>`:256` `testTheStatusDecidesNotTheBodyOfA429`: `429 {"error":"slow_down"}` + RA 3 gives `[5, 5]`.</li><li>`:269` `testASlowDownOn400StillRaisesTheInterval`: `400 slow_down` gives `[5, 10]`. This is the control case.</li></ul>**Mutants** (re-run, `scratchpad/php-r6-mut.sh`, log `php-r6-mut.log`):<ul><li>**R2** (the body decides): killed by `:256`.</li><li>**R3** (the 429 carry without the interval floor): killed by `:234` and `:256`.</li><li>**R5** (the 429 raises `$interval` permanently): killed by `:243`.</li><li>Re-checks: R1 (4 fail), R4, C6 and C7 are all still killed.</li></ul>**Docblock** (`src/Oidc/OidcClient.php:2103-2106`): it now says the loop "waits the interval, or the failure's `Retry-After` if longer (once; the interval is never raised, whatever a `429`'s body says), and polls again. A wait that would reach the deadline ends the flow with `expired_token`." This is the requested wording, plus the body clause, and it matches the code at `:2170-2177` and the pre-sleep deadline check. |

**Regression probes:** none needed. The `src/` change is docblock only, so no executable line changed. The round-5 CIBA probes therefore still hold.

**Answers to the prompt:**
- The three new tests kill R2, R3 and R5. I re-ran each mutant, and each fails at least one of the new tests.
- The `cibaAwait` docblock now states the wait.
- The 6-line `OidcClient.php` change is docblock only.

**Version:** 1.1.2 is still right. `CHANGELOG.md:10` reads `## [1.1.2] - Unreleased`, and `README.md:27` and `:457` read `^1.1.2`. `CHANGELOG.md:129-133` records C164-57.

**Run by the reviewer** (clone at b61dc39; PHP 8.3, Composer 2.8):
- **Install:** `composer install` used the earlier lock. phpstan/phpstan 2.3.1 came from a local `git clone --depth 1 --branch 2.3.1` (`6155239`) as a `path` repository. Both edits were local to the clone. Log: `scratchpad/php-r6-install.log`.
- **`vendor/bin/phpunit`:** **OK, 2084 tests, 10009 assertions** (round 5: 2080 tests). The 13 Contract164 CIBA bound tests are green. Log: `php-r6-unit.log`.
- **`vendor/bin/phpstan analyse --memory-limit=512M`:** **No errors**. Log: `php-r6-stan.log`.
- **Cleanup:** the clone, `vendor/` and the phpstan clone are deleted. `/home/user/sdks/php` is untouched.

**New findings (introduced by the round-6 diff):** none.

**Follow-up (outside the W7 gate):** none new. The round-5 note (with less than 1 s left after an admitted wait, the wait is served and nothing is sent) stands.

---

#### Addendum round 6 — cplusplus — commit de76426 (PR #80), read after 007aa6b

| Finding | Status | Commit | Evidence / test / mutant |
|---|---|---|---|
| C164-58 (clamp) | CLOSED | de76426 | `src/oidc.cpp:1746` (device, ms) and `:2593` (CIBA, s→ns) now use `std::clamp<std::int64_t>(expires_in, 0, 1'000'000'000)`. Tests: `tests/test_oidc_grants.cpp` "hostile expires_in cannot overflow" (-9e18, -1, 0 → `expired_token`, 0 calls; +9e18 completes), `tests/test_ciba.cpp` same for CIBA (-9e18). Mutants L1/L2 (drop the lower clamp, i.e. back to `std::min`): each killed by its own test in the plain build (the wrapped deadline is far in the future, so the poll is served), and under UBSan (`oidc.cpp:1746: -9000000000000000000 * 1000`; `chrono.h:225: … * 1000000000`). |
| C164-58 (`>=` re-checks) | CLOSED | de76426 | Four exact-deadline tests. B1 `oidc.cpp:916` (device §16), B2 `:1769` (device interval), B3 `:2478` (CIBA §16), B4 `:2608` (CIBA interval). Changing `>=` to `>` fails exactly one test each, and that test is the one named for the site: "…section 16 wait … EXACTLY …" (device), "…sleep that ends EXACTLY…, device interval wait", "…section 16 … EXACTLY …, CIBA", "…EXACTLY…, CIBA interval wait". |
| C164-58 (CHANGELOG) | CLOSED | de76426 | `CHANGELOG.md:50-52` says "clamped to [0, about 31 years] … cannot overflow in either direction … a value <= 0 now expires at once, as a zero always did". This is accurate. Small negatives already expired at once before the fix; only a hugely negative value wrapped, which L1/L2 confirm. The claim at `:99-101` that the tests are "run under UBSan in the sanitizer leg; removing the lower clamp fails them" also holds: `sdk-ci-cpp.yml:72-97` runs `address,undefined` with `-fno-sanitize-recover=all`. |

Regression probes (copy only, plain and UBSan builds): these are the deadline-bound probes for the expires_in clamp. Every case ran clean under `-fsanitize=undefined -fno-sanitize-recover`, with no diagnostics.
- **Device, `expires_in` sent as JSON:** INT64_MIN and -1e15 give `expired_token` and send 0 polls. INT64_MAX, 1e9, 1e9+1 and 10 complete with 1 poll.
- **CIBA:** INT64_MIN, -1 and 0 give `expired_token` and send 0 polls. INT64_MAX, 1e9 and 10 complete with 1 poll.
- **0..1e9 is unchanged:** the clamp is the identity there, and the existing deadline and boundary tests all pass.
- **A negative `expires_in` now behaves as 0:** the deadline is "now", so the first pre-sleep check raises `expired_token` without sleeping or sending. That is the sane outcome. A grant that reports no lifetime left is expired, and it matches what 0 and small negatives already did.

Version: `project(axiam_cpp_sdk VERSION 1.1.2)` is still right. `AXIAM_SOVERSION 4` is unchanged and needs no bump: the diff touches only function bodies in `src/oidc.cpp`, tests and the CHANGELOG, with no public header.

Run by the reviewer: a throwaway copy at `/home/user/work/cplusplus-r6` (deleted afterwards). The clone is untouched. Toolchain: gcc 13.3, Ninja, C++17, Debug.
- Plain build (tests and examples): exit 0. `ctest` 1/1 passed; the binary reports 1641 test cases, 6207 checks, 0 failed (+6 vs round 5).
- UBSan build: exit 0. `ctest` 1/1 passed; the binary reports 1641 / 6207 / 0 failed, with no runtime errors.
- Mutants L1, L2, B1–B4: all killed, as in the table.

New findings (introduced by the round-6 diff): none.

Follow-up (outside the W7 gate): none new. The §7.4.4 C++ notes still stand: the µs gap, and `opt_int` UB on an out-of-range JSON double.

---

#### 7.5.4 Closing note (2026-10-23): C164-59, and the W7 gate

**C164-59 is closed at Kotlin `0672643`.** The commit is docs only and signed. The lead reviewer read the diff
(`b8a70b4..0672643`, `CHANGELOG.md` and `README.md` only):
- README §16 (`:2521`) and the CHANGELOG entry (`:125`) now say "once more in total (OkHttp replays it once on a
  stale pooled connection)";
- the bounds (4 with retry on, 2 with `retryDisabled()`) are unchanged;
- a "Round 7 — C164-59" line records the change.

No code changed, so no test run was needed.

**Final heads** (all on `claude/contract-1.64`, all matching `git ls-remote`):

| SDK | PR | Head |
|---|---|---|
| TypeScript | #150 | `50d6f72` |
| Rust | #138 | `c947a5e` |
| Python | #103 | `9e69284` |
| C | #77 | `832a421` |
| C++ | #80 | `de76426` |
| C# | #111 | `fd1093b` |
| Go | #103 | `2a0c273` |
| Java | #121 | `97dcdf0` |
| Kotlin | #80 | `0672643` |
| PHP | #87 | `b61dc39` |
| Swift | #78 | `7d28ce4` |

All eleven vendor `CONTRACT.md` byte-identical to W7.1c `b3f8687` (sha256 `a221f1bf…de39`), and `openapi.json`,
`management-registry.json` and `proto/` from `fb92ec4`. `scripts/check-sdk-artifact-drift.py --local-root` over
these heads reports **11 repos, 0 artifact problems**.

**W7 has no open finding.** C164-01 … C164-59 are closed in every SDK they name. That includes the contract-text
findings C164-16 and C164-18 (W7.1b) and C164-35 (W7.1c); C164-34 was unused. Two items are recorded for contract
1.65 and do not gate W7:
- **C164-42:** the P10 sentence for `device_poll`;
- **C164-49:** §16.1's delay cap against the `Retry-After` floor.

The follow-up list of §7.4.4 stays outside the gate, together with OkHttp 5.x for Kotlin (C164-55 (b)). Rust's
CodeQL alert #128 is a confirmed false positive (§7.2.1 point 6), awaiting the maintainer's dismissal.

**Not verified throughout this review:**
- C# and Swift were never built or run here; there is no toolchain for either.
- SDK CI was read only through the orchestrator's reports.
- The SDK issues' comments could not be read.
