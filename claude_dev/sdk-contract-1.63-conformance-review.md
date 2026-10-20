# CONTRACT 1.63 — cross-SDK conformance review (the 1.1.1 release)

**Date:** 2026-10-20
**Plan item:** W7.13 of [`release-1.1.1-plan.md`](release-1.1.1-plan.md) §8.3.
**Scope:** the eleven `claude/contract-1.63` branches, each a draft PR on its repository's `origin/main`,
vendoring `sdks/CONTRACT.md`, `sdks/openapi.json`, `sdks/management-registry.json` and `proto/` from
axiam `a6cd10eba` (contract 1.63, §34.7 items (a) … (q)). The rows read are those §34.7 binds an SDK
to — (a) no session cookie and no `X-CSRF-Token` on any `/oauth2/*` request, with its §14.6 test;
(b) the SCIM `expected_updated_at` as the response's own string (Java, Kotlin, C); (c) the producer's
local refusal of the reserved audit actions (a MAY) — and the SDK's own issue items of plan §8.2:
C162-04, C162-06, C162-07, C162-08, C162-09, C162-10, C162-13, C162-15, C162-16, C162-17, Python #100.
Items (d) … (q) ask nothing of an SDK beyond re-vendoring.

**Outcome.** The three rules are ported in substance by all eleven, every vendored file is
byte-identical to `a6cd10eba`, and every suite that could be run here is green. **Six findings are
Medium** and are fixed before W8 (§6): five in SDK PRs and one in the contract text.

- TypeScript's new `/oauth2/` matcher also catches `/api/v1/auth/federation/oauth2/*`, which breaks
  the Node "Sign in with X" OAuth2 completion. It is a regression in the PR (C163-01).
- Swift refuses an unknown open-enum value at `apply`, after earlier writes, not at `plan`. The
  1.62 review mis-read the Swift code, so the plan never gave Swift the C162-07 item (C163-02).
- C and C++ still send the session cookie on the UMA ticket grant to `/oauth2/token`
  (C163-03, C163-04).
- Kotlin records 1.2.0 under `[Unreleased]` without bumping any version file (C163-05).
- §8 and §34.7 (c) say the seven AMQP SDKs refuse the reserved audit actions. Six of them ship
  nothing that produces an `AuditEventMessage`, and the seventh, Rust, ships a signing helper and no
  publisher (C163-06, contract text).

Fourteen Low or Informational findings are filed on `1.1.x` or listed for filing (§4, §7). The
review asks the maintainer three questions (§5), two of them carried over from W7.1.

## 1. Method

The method is that of the [1.62 review](sdk-contract-1.62-conformance-review.md) (its §1),
re-cut for 1.63:

- **One reviewer per SDK.** Each read the repository's `origin/main...HEAD` diff and the files it
  touches. Every cell carries a `path:line` on the commit read.
- **Claims were checked, not trusted.** The executors' notes (the orchestrator's table), the
  CHANGELOGs and the commit messages were treated as claims and checked against the code. Where
  they disagreed, the code won.
- **Probes and mutants.** Wherever a toolchain existed, the reviewer ran the touched tests and,
  for the new tests, a mutant with the fix reverted, to show the test is not vacuous. Ad-hoc wire
  probes were written for the questions a test did not answer. Probes and mutants ran on throwaway
  copies; no SDK repository was modified.

1. **Vendoring.** `sha256sum` of the three files against `a6cd10eba`
   (`9997c7fb…658f`, `fb85bb1c…7f0b`, `d69eccdf…00e6`), and `cmp` of the five `proto/axiam/v1/*.proto`
   files in the nine SDKs that vendor them.
2. **(a)** Where the jar and the CSRF header are attached, and where the `/oauth2/*` exclusion sits.
   - Every `/oauth2/*` route the SDK calls is enumerated: device authorization, the token endpoint in
     every grant (UMA included), introspect, revoke, PAR, CIBA, token exchange, RFC 7591/7592, JWKS
     and the revocation feed.
   - How the exclusion matches: by path or by transport, anchored or not, with discovery-supplied
     absolute URLs and a base path.
   - Whether management requests still carry both headers.
   - The §14.6 test, against its five parts: a cookie login, the two device operations, a token
     request, no `Cookie` and no `X-CSRF-Token` on all three, and the management control after them.
3. **(b)** Every helper that builds `expected_updated_at` from a SCIM read (get and list decode), and
   §31.8 test 3's 1.63 assertion with a non-canonical string.
4. **(c)** Whether anything builds, signs or publishes an `AuditEventMessage` (publish, sign, the DTO,
   the queue name), and whether the refusal is ASCII-case-insensitive and names only the namespace.
5. **C162-06/07** (§27.6.2 item 4, §27.9):
   - Refused at `plan`, before any write, and only for an `Update`; `Create` and `NoChange` are not
     refused, and a stated member resolves it.
   - The error type, whether the value is named, and whether the raw string survives decoding.
   - The three halves of the §27.9 test.
   - **C162-08:** refused at `plan` with zero wire calls, and its type.
6. **The issue items**: C162-04, C162-09, C162-10, C162-13, C162-15, C162-16, C162-17 and Python #100.
7. **Versioning.** Every version file, the CHANGELOG entry and the README's conformance sentence.
   Whether the PR contains a source- or ABI-breaking change, judged against the plan §8.2 rule (the
   patch, or the minor where a change is source-breaking).
8. **Anything else in the diff.**
9. **CI**, read through the GitHub API where this session could reach it (TypeScript, Python, C);
   for the other eight, the orchestrator's notes.

**Severity** uses the scale of the 1.62 review:

- **Medium:** a normative rule broken in a way a caller meets, or a release defect. Fixed in the SDK
  PR, or in the contract text, before W8.
- **Low:** a deviation with a narrow trigger and no data loss.
- **Informational:** posture, text, or test strength that hides no defect.

Low and Informational findings are filed on `1.1.x`.

| Repo | Commit read | PR | Version | CI on that commit | Run by the reviewer |
|---|---|---|---|---|---|
| `axiam-typescript-sdk` | `7c2aa475b` | [#147](https://github.com/ilpanich/axiam-typescript-sdk/pull/147) | 1.1.0 → 1.1.1 | green (9 runs, read) | `tsc --noEmit` clean; vitest 1725 passed / 3 skipped |
| `axiam-rust-sdk` | `2e86fb781` | [#136](https://github.com/ilpanich/axiam-rust-sdk/pull/136) | 1.1.0 → 1.1.1 | green (orchestrator; head moved from `ecf4bc23` for CodeQL) | `--all-features` lib 230, `network_manifest_test` 15, `oauth2_no_session_bearer_test` 3; two mutants fail as expected |
| `axiam-python-sdk` | `27dccaeec` | [#101](https://github.com/ilpanich/axiam-python-sdk/pull/101) | 1.1.0 → 1.1.1 | green (15 runs, read) | pytest 2109 passed; ruff, mypy clean |
| `axiam-c-sdk` | `05483b25d` | [#75](https://github.com/ilpanich/axiam-c-sdk/pull/75) | 1.1.0 → 1.1.1 | green (22 runs incl. ASan+UBSan & valgrind, read) | ASan/UBSan build, ctest 81/81 |
| `axiam-cplusplus-sdk` | `a36aeb7ac` | [#77](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/77) | 1.1.0 → 1.2.0 (SOVERSION 3) | green (orchestrator) | ctest 2/2 (1604 cases, `abi_soname`); generator `--check` |
| `axiam-csharp-sdk` | `9b36f7ab1` | [#109](https://github.com/ilpanich/axiam-csharp-sdk/pull/109) | 1.1.0 → 1.1.1 | green (orchestrator) | none — no `dotnet` in the sandbox; read only |
| `axiam-go-sdk` | `a5b7c8077` | [#101](https://github.com/ilpanich/axiam-go-sdk/pull/101) | 1.1.0 → 1.1.1 (tag) | green (orchestrator) | `go vet`, `go test ./...` green; three mutants fail as expected |
| `axiam-java-sdk` | `83891062c` | [#119](https://github.com/ilpanich/axiam-java-sdk/pull/119) | 1.1.0 → 1.2.0 | green (orchestrator) | 47 targeted tests green; e2e cookie-login probe |
| `axiam-kotlin-sdk` | `3d2504207` | [#78](https://github.com/ilpanich/axiam-kotlin-sdk/pull/78) | **not bumped** (1.2.0 under `[Unreleased]`) | green (orchestrator) | full `gradlew test` 1278 green; generator `--check` |
| `axiam-php-sdk` | `f9acc00ba` | [#85](https://github.com/ilpanich/axiam-php-sdk/pull/85) | 1.1.0 → 1.1.1 (tag) | green (orchestrator) | phpunit 2018 OK; phpstan L6 clean; docblock 2030/2030; generator `--check` |
| `axiam-swift-sdk` | `4091f8196` | [#76](https://github.com/ilpanich/axiam-swift-sdk/pull/76) | 1.1.0 → 1.1.1 | green (orchestrator) | none — no Swift toolchain; generator `--check` only |

**Vendoring, all eleven.** `CONTRACT.md`, `openapi.json` and `management-registry.json` are
byte-identical to `a6cd10eba`. The nine that vendor `proto/` (all but C and C++) have all five
files identical. Every branch is a straight line on its `origin/main`.

## 2. What CI did not catch

- **A route that only *contains* `/oauth2/`.** TypeScript's matcher is
  `path.includes('/oauth2/')`. It now runs for every request, not only after a device adoption, so
  `POST /api/v1/auth/federation/oauth2/callback` goes out on the jar-free agents and its `Set-Cookie`
  never reaches the jar. The client then reports itself authenticated and sends no cookie on its
  next call. The existing `ssoCompleteOauth2` tests pre-seed the jar, so they cannot see it
  (C163-01). Go has the same matcher but its jar still stores, so it is harmless there (C163-19).
- **The UMA ticket grant.** C and C++ send it to `/oauth2/token?tenant_id=…` from a call site that
  bypasses the new cookie-less path. Each §14.6 test runs the two device operations and one other
  grant, so neither saw it. A wire probe in each SDK showed `Cookie: axiam_…` on that request
  (C163-03, C163-04).
- **A half-applied manifest.** Swift has no §27.9 test for an unknown value on an unstated member,
  so nothing showed that its only refusal is the generated `encode(to:)` inside `apply`. That
  refusal fires after the identity entities, the policy and the segments are written (C163-02).
- **The §14.6 control.** The contract asks for the same client's *next* state-changing management
  request to carry `Cookie` and `X-CSRF-Token`, so that the assertion cannot pass for want of them.
  Eight of the eleven tests:
  - sign in by seeding the jar by hand;
  - put the control before the `/oauth2/*` calls; or
  - have no control at all (C163-08).

  Only C, Kotlin and, nearly, Rust (its control comes first) meet the paragraph as written. Every
  probe the reviewers ran showed the code is right; the tests are weaker than the rule.
- **The version file.** No job compares `gradle.properties` with the CHANGELOG heading, or C++'s
  `axiam::kVersion` with `PROJECT_VERSION` (C163-05, C163-15).

## 3. Per-SDK reports

`path:line` is on the commit read. The cross-SDK findings (C163-07 … C163-11) are listed in every
report they touch and described once, in §4.

---

### Report — typescript — commit 7c2aa475b (PR #147)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Every real `/oauth2/*` request in Node rides the jar-free agent pair, and the CSRF interceptor skips it. The device-token interceptor now swaps for every match, not only after adoption. Routes covered: every grant at the token endpoint, UMA included; device_authorization; introspect; revoke; PAR; bc-authorize; token exchange. RFC 7592 uses the bare transport; JWKS and revocations use `fetch`/`jose` with no jar. **The matcher is `includes('/oauth2/')`: C163-01.** Browser persona: C163-12. | `src/rest/interceptors.ts:66-71`, `:157-164`, `:191-213`; `src/node/session.ts:65-72`; `src/node/oidc.ts:2743-2755` |
| 2 | (a) §14.6 test | Present and green. The mock sets `axiam_access` and `axiam_csrf`. The three operations assert no `Cookie` and no `X-CSRF-Token`. Deviations: a raw `axios.post` stands in for the login, the CSRF token is set by hand, and the control (`/api/v1/echo`) runs **before** the `/oauth2/*` calls (C163-08). | `test/node/oauth2NoSessionCookies.test.ts:37-90`, `:69-88` |
| 3 | (b) | Not named; already sends the read's string (1.62 review). | — |
| 4 | (c) | No producer. Exports a generic `signPayload(key, bytes)` and an `AuditEventMessage` interface documented as *received*. Nothing builds, canonicalises, signs or publishes that type, and the only `sendToQueue` is the reactor reply. The executor's "N/A" is right; §34.7's "TypeScript … add it" is wrong (C163-06). | `src/amqp/hmac.ts:27`; `src/amqp/messages.ts:71-112`; `src/amqp/reactor/runtime.ts:395` |
| 5 | C162-07 | Conforms. The refusal sits in `profileReplaceInput`, reached only for a drifted profile inside `#compute`, which runs in `plan` and in `apply` before `#execute`. `Create` and `NoChange` are not refused, and a stated member resolves it. Raises `ValidationError` naming member and value; the open enums are `string & {}`, so the raw string is kept. Tests cover both members, refusal with no write, the stated member as an `Update` without `"future"`, and `NoChange`. The stated value itself is not asserted (C163-09). | `src/management/manifest/engine.ts:1270-1320`; `test/management/manifestNetwork.test.ts:632-676` |
| 6 | C162-08 | Conforms. A stated `terminationAction: null` is a `validate()` problem: zero requests (the test asserts an empty log), plain `NetworkError` like every other manifest refusal (B5). Segment `enabled`/`filterIds` cannot be stated as none. | `src/management/manifest/plan.ts:353-356`, `:411-418`; test `:678-691` |
| 7 | Version | 1.1.1 in `package.json` and both lock entries. The CHANGELOG names 1.63, `a6cd10eba`, (a), C162-07/08 and why (c) does not apply; the README says 1.63. No source-breaking change, so the patch is right. | `package.json:3`; `CHANGELOG.md:10-40`; `README.md:23` |

**Findings:** C163-01 (**Medium**), C163-08 (Low), C163-09 (Info), C163-12 (Low), C163-18 (Info,
README labels "(ab)"/"(ac)"). Filed: ilpanich/axiam-typescript-sdk#148.

---

### Report — rust — commit 2e86fb781 (PR #136)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Conforms for every `/oauth2/*` POST. A new `oauth2_post` sends on `http_bare`: no jar, no redirects, the same TLS/mTLS identity, `X-Tenant-ID` only. The 11 former `http()+maybe_csrf_header` sites moved to it, covering the token grants (UMA included), introspect, revoke, device ×2, PAR, CIBA ×2 and token exchange. The client's own JWKS verifiers moved too. The exclusion is by transport, so a discovery URL cannot escape it. **Missed: the SSF receiver's JWKS GET (C163-13).** | `src/client.rs:543-559`, `:1094-1102`; `src/oidc/exchange.rs:627`; `src/uma.rs:440`; gap `src/ssf.rs:400` |
| 2 | (a) §14.6 test | Effective. Cookie `login()` against a mock setting `axiam_access`, `axiam_refresh` and `axiam_csrf`; `login_client_credentials`, `device_authorize` and `device_poll` each assert no `axiam_`/`Cookie` and no `x-csrf-token`. The control (`logout`, carrying both) runs before the oauth2 calls (C163-17). The mutant with `oauth2_post` reverted fails the test. | `tests/oauth2_no_session_bearer_test.rs:272-345` |
| 3 | (b) | Not named; `updated_at` is a `String` copied verbatim. | `src/management/checks.rs:124`, `:301` |
| 4 | (c) | `AuditEventMessage::check_action` and `sign` are **new** in this PR. `sign` refuses `tenants.`/`gdpr.` (ASCII case ignored; `tenantsX` and `éenants.x` pass) before signing, with `Network` + `ValidationError` (operation `audit.publish`, field `action`), naming the namespaces only. There is no publisher. The public `sign_payload` bypasses the check, which is acceptable under a MAY (C163-17). The non-`rest` branch is dead: `--no-default-features --features amqp` fails to compile on main and on head (52 errors), pre-existing. | `src/amqp/messages.rs:32-44`, `:150-191` |
| 5 | C162-07 | Behaviour conforms: refused at `plan` (apply computes the whole plan first), `Update` only, a stated member resolves it, raw string kept (`Unknown(String)`) and quoted with member and value. All three §27.9 halves are tested; the mutant fails. **Type:** bare `AxiamError::network(..)`, so `e.validation()` is `None` (C163-07). | `src/management/manifest/network.rs:319-328`, `:631-700`; `tests/network_manifest_test.rs:748-810` |
| 6 | C162-13 | Conforms. The 438 files are untracked, `.gitignore` covers the path, and nothing the build needs was removed. | `.gitignore:8-9` |
| 7 | Version | 1.1.1 in `Cargo.toml` (and the `=1.1.1` macros pin), macros and wasm crates and README. The CHANGELOG names 1.63, `a6cd10eba`, (a), (c), C162-07, C162-13 and "patch". The new methods are additive, so the patch is right under the plan rule. | `CHANGELOG.md:10-40` |

**Findings:** C163-07 (Low), C163-13 (Low), C163-17 (Info). Issue text in §7 (not filed: this
session could not write to the repository).

---

### Report — python — commit 27dccaeec (PR #101)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Conforms. One choke point, `_Session._prepare_request`, strips `Cookie` and `X-CSRF-Token` from any path starting with `/oauth2/` and keeps `X-Tenant-ID`; every REST send goes through it. The credential-free pair never touches the jar. A probe with a real mocked cookie login sent neither on `/oauth2/token`. | `src/axiam_sdk/_session.py:404-415`, `:442-476`, `:509-528` |
| 2 | (a) §14.6 test | Sync and async; device ×2 and client credentials; asserts none of either header. Gaps: no cookie login (private attributes are seeded), and the control runs first (C163-08). | `tests/test_no_session_cookie_on_oauth2.py:52-118` |
| 3 | (b) | Not named; `updated_at: str` is passed through. | `management/conversions.py:109` |
| 4 | (c) | No producer. A consumer, `verify_hmac` and the reactor's `publish_reply`; no `AuditEventMessage` type at all. | `amqp/_hmac.py:29`; `amqp/_reactor_protocol.py:589` |
| 5 | C162-07 | Conforms: `plan`, `Update` only, `ValidationError` via `local_refusal`, naming member and value. The raw string is kept (`Literal[...] \| str`). Two test halves are thin (C163-09). | `manifest/_engine.py:875-922`; tests `:853-905` |
| 6 | C162-08 | Conforms. "The plan problems channel" is `validate()`: every problem is collected and raised as one `NetworkError` **before any read**, so there are zero wire calls (the test asserts none). Same type as the duplicate key and the duplicate Filter-Id (B5). | `manifest/_plan.py:221-301`; tests `:908-921` |
| 7 | #100 | Item 2 is (a), above. Item 1: with an adopted credential, the PAT wins and `Cookie: ""` is set. **With a cookie-login session the PAT is sent beside `axiam_access` and `X-CSRF-Token`; the server reads the cookie first and refuses `403`** (C163-14; fails closed; pre-existing). | `_client.py:978-988`; `_oidc.py:1831-1840` |
| 8 | Version | 1.1.1 in `pyproject.toml` and `__init__`. The CHANGELOG names all items and (c) N/A; README 1.63. Patch is right. | `CHANGELOG.md:10-44` |

**Findings:** C163-08 (Low), C163-09 (Info), C163-14 (Low), C163-18 (Info, docstring). Filed:
ilpanich/axiam-python-sdk#102.

---

### Report — c — commit 05483b25d (PR #75)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Three paths are covered:<ul><li>`transport_once_ex` (relative paths) drops CSRF and adds the empty-`Cookie` signal on `/oauth2/`;</li><li>`oidc_transport_once` (absolute discovery URLs) always sends the signal and never CSRF;</li><li>`send_bare` already sent the signal.</li></ul>`axiam_curl_transport` honours the signal by saving, clearing and restoring the jar. **Not covered: the UMA ticket grant through `uma_transport` (C163-03).** A probe sent `Cookie` on `POST /oauth2/token?tenant_id=` after `axiam_login`. | `src/client.c:318-322`, `:357-379`; `src/oidc.c:426-429`; `src/transport_curl.c:214-243`; gap `src/uma.c:130-157`, `:803-804` |
| 2 | (a) §14.6 test | Conforms, all five parts. It uses the real libcurl cookie engine; the login sets `axiam_access` and `axiam_csrf` plus `X-CSRF-Token`; device ×2 and client credentials; the control is the following `logout`, asserted to carry both. | `tests/test_oauth2_no_session.c:98-103`, `:163-200` |
| 3 | (b) C162-09 | Conforms. `expected_updated_at` is set to the raw response string (`axiam_strdup0` at parse). OOM frees `out`. A `+02:00`/6-digit spelling is tested verbatim. | `src/management_helpers.c:167-179`; `tests/test_scim_targets.c:540-586` |
| 4 | C162-06 | Conforms on behaviour: `plan`, `Update` only, an unstated member; `Create`/`NoChange` are not refused; a stated member, and a stated null `service_type`, resolve it. All three halves are tested for both members. `AXIAM_ERR_NETWORK` is C's validation category, the same `refuse()` as every manifest refusal. Names the member, **not the value** (the raw string is dropped at decode, C163-10). | `src/management_manifest.c:998-1020`; `tests/test_manifest_network.c:634-703` |
| 5 | Extra fix | Real. On main, `!…_from_wire(stated, &x)` refused **every** stated `termination_action`/`service_type`, because the generated `_from_wire` returns 0 for any string. Fixed with `known_*`, and the "stated" half of the test would fail on main. | `origin/main:src/management_manifest.c:129`, `:137`; head `:51-61`, `:139-152` |
| 6 | Memory/ABI | Ownership correct on every refusal path; the jar save and restore run under `ctx->mtx`. No public struct grew, `SOVERSION` stays 2; ASan/UBSan clean. | `src/management_manifest.c:787-793` |
| 7 | Version | 1.1.1 across CMake, `axiam.h`, Doxyfile, conan, vcpkg and README. The CHANGELOG names all items. A stale `CMakeLists.txt:4` comment says 1.1.0 (C163-18). The CHANGELOG's "any `/oauth2/*` request" is false until C163-03 is fixed. | `CHANGELOG.md:9-35` |

**Findings:** C163-03 (**Medium**), C163-10 (Info), C163-18 (Info), C163-20 (Info). Filed:
ilpanich/axiam-c-sdk#76.

---

### Report — cplusplus — commit a36aeb7ac (PR #77)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | CSRF is added only in `build_request`, and no `/oauth2/*` request uses it. Every hand-built `/oauth2/*` request sets `sessionless`, routed to the new cookie-less handle pool: token (5 grants), introspect, revoke, device, PAR, CIBA ×2, JWKS, revocations and RFC 7592. **Missed: `uma_exchange_ticket` (C163-04)**; a probe saw `cookie=[axiam_session=xyz]` on `/oauth2/token`. | `src/oidc.cpp:872`, `:1129`, `:1595`; `src/http_curl.cpp:517`, `:540-556`; gap `src/client.cpp:1494-1506` |
| 2 | Handle pool | Sound. Plain handles never get `COOKIEFILE` or `SHARE`; `plain_mtx` guards the lists. TLS verify, CA blob, mTLS cert and key, timeouts and no-redirect are set per transfer on whichever handle, so §6.1 client certificates are kept on `/oauth2/token`. The pool sits outside `max_concurrent_requests` (C163-20). | `src/http_curl.cpp:90-186`, `:359-460` |
| 3 | (a) §14.6 test | Real libcurl transport, a cookie login, device ×2 and `oidc_refresh` with no `Cookie` and an empty CSRF header. **No control** (C163-08). | `tests/test_integration_curl.cpp:303-333` |
| 4 | C162-07 | Behaviour conforms (`plan`, `Update` only, `NoChange` and a stated member probed). **Type:** `axiam::management::ValidationError` (the server's 400/422 class, a `NetworkError`), not the `std::invalid_argument` §27.6.2 item 4 names for C++ (C163-07). The value is not named (C163-10). Missing §27.9 halves: the `service_type` refusal, the stated PUT body and `NoChange` (C163-09). | `src/management_manifest.cpp:247-265`; tests `:667-699` |
| 5 | C162-16 | Conforms. `PageRequest::site` is carried by `next()`; an explicit argument wins; tested over two pages. Generator `--check` is current. | `include/axiam/management.hpp:55-61`; tests `:701-725` |
| 6 | Version | 1.2.0 with `SOVERSION` 3 is warranted: `PageRequest` is embedded in `Page<T>`, so it is an ABI break, pinned by `abi_soname`. Source-compatible for aggregate init. The CHANGELOG records the minor and the ABI change. **`axiam::kVersion` is still `"1.1.0"`** (C163-15). | `CMakeLists.txt:6`, `:115`; `include/axiam/axiam.hpp:55` |

**Findings:** C163-04 (**Medium**), C163-07 (Low), C163-08 (Low), C163-09 (Low), C163-10 (Info),
C163-15 (Low), C163-20 (Info). Issue text in §7.

---

### Report — csharp — commit 9b36f7ab1 (PR #109)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Conforms. `WriteIsolatingHandler` sends any `/oauth2/…` or `/t/{id}/oauth2/…` request (matched on `AbsolutePath`) through a `SocketsHttpHandler` with `UseCookies=false`; `ApplyHeaders` skips CSRF on the same predicate. Every OAuth2 operation goes through `PostOAuth2FormAsync`; RFC 7591/7592 already used a cookie-less client. Management and `/auth/refresh` keep both headers. | `Rest/WriteIsolatingHandler.cs:86-150`; `Rest/AxiamHttpMessageHandler.cs:118-143`, `:422-437`; `AxiamClient.Oidc.cs:1267-1287` |
| 2 | Caller-supplied handler | Not a breach of the SDK's client. `AxiamClient` has no public handler seam; `ConfigureFactoryHandler` gives a fresh, empty jar that the SDK's login never fills. Only a hand-composed `AxiamHttpMessageHandler` over the caller's own `UseCookies=true` handler would add cookies, which no `DelegatingHandler` can strip. That composition is unsupported, and the CHANGELOG discloses it (C163-20). | `AxiamClient.cs:250-266` |
| 3 | (a) §14.6 test | Wire-level, with controls before and after. Gaps: the jar is seeded by hand; raw POSTs are sent, not the SDK operations; one query row re-checks an earlier request; the after-control checks the cookie only (C163-08). | `tests/…/Contract163OAuth2NoCookieTests.cs:20-77` |
| 4 | (c) | No producer: `Hmac.Verify`, the consumer, and the reactor reply. | `Amqp/Hmac.cs:46`; `Reactor/ReactorServer.cs:371` |
| 5 | C162-06 | Behaviour conforms (`plan`, `Update` only, stated member, `NoChange`). **Type:** bare `NetworkError` (C163-07); the SDK has `ValidationError : NetworkError` and uses it for local refusals of caller values. The value is not named (C163-10). `NoChange` is tested for `termination_action` only (C163-09). | `Management/ManifestApi.cs:614-656`, `:1196-1206`; tests `:411-474` |
| 6 | C162-15 | Conforms: recorded under "Planned" as a 2.0.0 source-breaking change, with no code change. | `CHANGELOG.md` `[1.1.1]` |
| 7 | Version | 1.1.1 in both csproj files and the README; the CHANGELOG names all items; patch is right. Every `/oauth2/*` request now opens a fresh connection (`PooledConnectionLifetime = Zero`): a cost, not a defect (C163-20). | `Axiam.Sdk.csproj:6`; `README.md:473-474` |

**Findings:** C163-07 (Low), C163-08 (Low), C163-09 (Info), C163-10 (Info), C163-20 (Info). Issue
text in §7.

---

### Report — go — commit a5b7c8077 (PR #101)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Conforms. `doRequest` sends `/oauth2/` paths through a shallow copy of the `http.Client` whose `Jar` is `noOutboundCookieJar`: `Cookies()` returns nil and `SetCookies` forwards, so stores still work. `decorateRequest` drops CSRF. A caller's `http.Client` cannot escape this, because `buildHTTPClient` replaces its `Jar` and Transport. The matcher is `Contains` (C163-19). | `client.go:802`, `:828-830`, `:890-894`; `webauthn.go:591-601` |
| 2 | (a) §14.6 test | Device ×2 only. No cookie login (the jar and `csrfToken` are seeded), no token request, and the "control" counts jar entries instead of checking a request (C163-08). Mutants fail. | `contract_163_test.go:15-60` |
| 3 | (c) | No producer: `auditEventCanonical` is used only to verify; the only publish is `PublishReply`. | `amqp/hmac.go:111-131`; `amqp/reactor_transport.go:258-270` |
| 4 | C162-07 | Conforms: `planNetwork`, `Update` only; `*ValidationError` via `localRefusal`, naming member and value (`%q`); string-typed enums keep the raw value. The test covers the refusal half only (C163-09); probes show the stated and `NoChange` halves are correct. | `management_manifest_network.go:361-395`; test `:62-90` |
| 5 | Version | Tag-based. `## [1.1.1] - Unreleased` names everything. No exported change, so the patch is right. README install pin still `@v1.1.0` (C163-18). | `CHANGELOG.md:10-36` |
| 6 | Other | Pre-existing: the JWKS verifier fetches through jwx's default client, ignoring the SDK's custom CA, mTLS and timeout (C163-16). Doc "before any wire call" should read "before any write" (C163-18). | `internal/jwks/verifier.go:81-95` |

**Findings:** C163-08 (Low), C163-09 (Low), C163-16 (Low), C163-18 (Info), C163-19 (Info). Issue text
in §7.

---

### Report — java — commit 83891062c (PR #119)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Conforms. `isOauth2Call` is anchored (`(?:/t/[^/]+)?/oauth2/.*`; the federation routes are not matched). It suppresses CSRF and swaps in a load-suppressed jar via `Chain#withCookieJar`; saves still delegate. Every `/oauth2/*` site uses `httpClient`, `sendOnceHttpClient` (which keeps the interceptor) or `sessionlessHttpClient`. An e2e probe after a real `login()` showed `cookie=null csrf=null` on device ×2, refresh and client credentials, and both headers on `POST /api/v1/users`. | `AuthInterceptor.java:109`, `:163-231`; `SessionState.java:302-318` |
| 2 | (a) §14.6 test | Interceptor-level only: hand-seeded jar, raw POSTs, no SDK operations (C163-08). | `CsrfInterceptorTest.java:84-127` |
| 3 | (b) C162-10 | Conforms. `ScimTargetResponse` keeps `updatedAtRaw` and derives `updatedAt()`; `ReplacementBodies.from` sends the raw string. get, list, create and update all decode the same way; a probe shows a list item byte for byte. The 1.63 test uses `…00.120000+02:00`. | `ScimTargetResponse.java:49-61`; `ReplacementBodies.java:162-172`; `ScimTargetsTest.java:172-186` |
| 4 | (c) | No producer: `Hmac.verify` and the reactor reply. | `amqp/Hmac.java:53` |
| 5 | C162-07 | Conforms: moved to `plan`, `Update` only (a probe shows `NoChange` and 0 PUTs), `ValidationError` via `LocalRefusal`. The value is not named (C163-10). Missing: the `NoChange` half, and `service_type` at `apply` (C163-09). A caller-stated `UNKNOWN` still fails at `apply` (C163-20). | `ManifestApi.java:582-621`; `NetworkManifestTest.java:411-435` |
| 6 | Version | 1.2.0 is correct: `ScimTargetResponse`'s canonical constructor changed (`OffsetDateTime updatedAt` → `String updatedAtRaw`), which breaks source and binary for positional construction and deconstruction; recorded with a migration note. The README's list of source-breaking changes omits it (C163-18). | `pom.xml:9`; `CHANGELOG.md:10-44` |

**Findings:** C163-08 (Low), C163-09 (Low), C163-10 (Info), C163-18 (Info), C163-20 (Info). Issue
text in §7.

---

### Report — kotlin — commit 3d2504207 (PR #78)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Conforms. A base-host request whose path starts with `<basePath>/oauth2/` gets no bearer and no CSRF header, and a network interceptor strips `Cookie` after `BridgeInterceptor`. `Sessionless` has no jar. Kotlin **does** keep a jar and sends both headers on management requests, so §14.6's "never sends cookies" is wrong (C163-11). | `internal/AuthHeaderInterceptor.kt:43-79`, `:120-134`; `internal/SessionState.kt:109-110` |
| 2 | (a) §14.6 test | Conforms, all five parts. The login mock sets `axiam_access`, `axiam_refresh` and `axiam_csrf` plus the header; device ×2, client credentials, refresh, introspect and revoke; the control is the next `POST /api/v1/groups`. | `oidc/Oauth2NoSessionCredentialTest.kt:129-153` |
| 3 | (b) C162-10 | Conforms. `updatedAtRaw` is filled on every decode, including list items; `toInput()` sends it; `expectedUpdatedAt: String?`; the 9-digit `+00:00` test passes. | `ReplacementBodies.kt:258-266`; `ManagementSupport.kt:151-220`; `ScimTargetsTest.kt:151-166` |
| 4 | C162-07 | Behaviour conforms (`plan`, `Update` only, `NoChange`, stated member). **Type:** a bare `NetworkError`, a regression from 1.1.0's apply-time `ValidationError` (C163-07); the tests pin `NetworkError`. The value is not named (C163-10). | `ManifestApi.kt:549-577`; `ManifestNetworkTest.kt:375-422` |
| 5 | Version | **Not bumped**: `gradle.properties` is `version=1.1.0`, the README snippets say 1.1.0, and the CHANGELOG has `[Unreleased]` "Next release: 1.2.0". The 1.1.0 precedent bumped inside the contract PR (`07855aa`, PR #76). 1.2.0 is the right number: `ScimTargetInput.expectedUpdatedAt` went `Instant?` → `String?` (C163-05). | `gradle.properties:2`; `CHANGELOG.md:8-50` |

**Findings:** C163-05 (**Medium**), C163-07 (Low), C163-09 (Info), C163-10 (Info), C163-18 (Info),
C163-19 (Info). Issue text in §7.

---

### Report — php — commit f9acc00ba (PR #85)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Conforms. `AuthMiddleware`, on both session clients, removes `Cookie` and `X-CSRF-Token` on paths starting with `/oauth2/` and never adds CSRF there; `$bareHttp` has neither jar nor middleware. Every `/oauth2/*` call goes through the two session clients. A comment states the Guzzle stack order backwards (C163-18). | `src/Rest/AuthMiddleware.php:106`, `:118-131`; `src/AxiamClient.php:411-469` |
| 2 | (a) §14.6 test | Real login with `axiam_*` cookies and `X-CSRF-Token`; device ×2 and client credentials; asserts none of `Cookie`, CSRF or `Authorization`. **No control** (C163-08); a probe shows a following management POST carries both. | `tests/Contract163/OAuth2NoSessionCredentialsTest.php:28-85` |
| 3 | C162-04 | Conforms. Every open enum gets a generated `toWire()` that raises `ValidationError` on `Unknown`, used by `toArray()`; `jsonSerialize()` never throws. All 43 enums are tested, with zero requests through `replaceProfile`. **`SsfEventType` stays exempt:** an unseen URI round-trips (`SsfUnseenEventTypeTest`). `toArray()` on a response holding `Unknown` now throws; the CHANGELOG should say so (C163-18). | `scripts/gen_management.py:941-1049`; `Models/RadiusTerminationAction.php:53-62`; `tests/Contract163/OpenEnumRefusalTest.php:58-107` |
| 4 | C162-07 | Conforms: `planAgainst`, `Update` only, stated member (stated `null` included), `ValidationError`. The value is not named (C163-10). The `service_type` half is untested (C163-09). | `src/Management/Manifest/ManifestApi.php:210-270` |
| 5 | Version | Tag-based. `## [1.1.1] - Unreleased` names everything; `toWire()` is additive, so the patch is right. | `CHANGELOG.md:8-46` |

**Findings:** C163-08 (Low), C163-09 (Low), C163-10 (Info), C163-18 (Info), C163-19 (Info). Issue
text in §7.

---

### Report — swift — commit 4091f8196 (PR #76)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | (a) code | Conforms. Every `/oauth2/*` request goes out through `umaSendAbsolute` or `bareSend`, which never read the jar or the CSRF token. The transport (AsyncHTTPClient) is internal, so a caller cannot supply a session. Swift **does** keep a jar and sends `Cookie` and `X-CSRF-Token` on management requests (C163-11). | `AxiamClient.swift:1134-1146` |
| 2 | (a) §14.6 test | The existing Contract162 test covers a cookie login, device ×2, a token request, introspect and revoke, asserting none of `Authorization`, `Cookie` or `X-CSRF-Token`. **No control**, and the mock sets no `axiam_csrf` (C163-08). The executor's "(a) rests on the existing test" holds for the assertion, not the control. | `Tests/…/Contract162Oauth2NoSessionCredentialTests.swift:112-118` |
| 3 | C162-17 | Conforms (documentation). | — |
| 4 | C162-07 | **Not conformant (C163-02).** `planNetwork` returns an `Update` for a profile read with `termination_action: "future"` and a manifest changing another member. The only refusal is the generated `encode(to:)`, which throws while `apply` builds that profile's body, **after** the earlier entities, the policy and the segments are written. `apply` records it in `ApplyReport.failedNetwork`. The message names the Swift type, not the member or the value. The 1.62 review's "Swift refuses at plan" cited `:94`, which is the refusal of a *stated* unknown segment `kind`. There is no §27.9 test. | `Management/ManagementManifestNetwork.swift:428-502`; `Generated/ManagementModels.swift:1403-1409`; `ManagementManifest.swift:873-888` |
| 5 | C162-08 | N/A: the manifest type cannot state none. | — |
| 6 | Version | 1.1.1, doc-only diff; the patch is right. README install snippets still say 1.1.0 (C163-18). | — |

**Findings:** C163-02 (**Medium**), C163-08 (Low), C163-11 (contract text), C163-18 (Info). Issue
text in §7.

## 4. Findings index

| ID | Severity | SDK | `path:line` | What | Disposition |
|---|---|---|---|---|---|
| C163-01 | **Medium** | typescript | `src/rest/interceptors.ts:157-164`, `:194-199` | `isOAuth2Endpoint` is `path.includes('/oauth2/')`, and the PR applies it to every request, so `POST /api/v1/auth/federation/oauth2/callback` (`ssoCompleteOauth2`) and `/start` ride the jar-free agents. The callback's `Set-Cookie` never reaches the jar, and the client claims to be authenticated but sends no cookie and no CSRF afterwards. "Sign in with X" over OAuth2 is broken in Node. Regression of this PR: a probe passes on `origin/main` and fails on the head. | **fix in PR #147** (§6) |
| C163-02 | **Medium** | swift | `ManagementManifestNetwork.swift:428-502`; `ManagementModels.swift:1403-1409` | An unknown `termination_action`/`service_type` on an unstated member is refused only at `apply` (generated `encode`), after earlier writes, leaving a half-applied manifest. §27.6.2 item 4 requires `plan` to refuse, naming member and value; there is no §27.9 test. Not in the plan's item list, because the 1.62 review mis-read `:94`. | **fix in PR #76** (§6) |
| C163-03 | **Medium** | c | `src/uma.c:130-157`, `:803-804` | `axiam_uma_exchange_ticket`'s `POST /oauth2/token?tenant_id=…` goes through `uma_transport`, which never adds the empty-`Cookie` signal, so after `axiam_login` it carries `axiam_*`. This breaks §12.1 rule 3 (1.63), "the token endpoint's every grant", and the CHANGELOG's "any `/oauth2/*` request". The server ignores the cookie, so nothing fails; but it is the release's normative item, and the fix is one line. | **fix in PR #75** (§6) |
| C163-04 | **Medium** | cplusplus | `src/client.cpp:1494-1506` | Same as C163-03: `uma_exchange_ticket` does not set `req.sessionless`, so it uses the cookie-enabled pool. The comment at `:1495-1497` and the CHANGELOG claim otherwise. | **fix in PR #77** (§6) |
| C163-05 | **Medium** | kotlin | `gradle.properties:2`; `README.md:226`, `:238`; `CHANGELOG.md:8` | The PR records 1.2.0 under `[Unreleased]` but leaves every version file at 1.1.0. Tagging the merge would publish 1.1.0 coordinates again, which Maven Central refuses. The 1.1.0 precedent bumped in the PR. 1.2.0 itself is right (`ScimTargetInput.expectedUpdatedAt` `Instant?` → `String?`). | **fix in PR #78** (§6) |
| C163-06 | **Medium** | contract | `sdks/CONTRACT.md:1127-1137` (§8); `:13635-13643` (§34.7 (c)); `:13689-13693` (§34.7 (m)); `:4233-4240` (Breaking Changes Log) | "An SDK that ships an AMQP producer for `axiam.audit.events` (Rust, TypeScript, Python, Java, C#, PHP and Go) … **The seven SDKs do.**" No SDK ships a publisher. Six ship no builder or signer of the message (consumer and verifier only), and Rust ships `AuditEventMessage::sign` (new in this PR) with the guard. The release's normative record states a behaviour six SDKs do not have. | **contract text before W8** (§6); W7.1 follow-up |
| C163-07 | Low | rust, kotlin, csharp, cplusplus | Rust `manifest/network.rs:319-328`; Kotlin `ManifestApi.kt:573-577`; C# `ManifestApi.cs:633-656`; C++ `management_manifest.cpp:254`, `:260` | The C162-06/07 refusal is not the type §27.6.2 item 4 names. Rust raises a bare `AxiamError::Network` with no `ValidationError` source. Kotlin and C# raise a bare `NetworkError` (Kotlin's was a `ValidationError` in 1.1.0). C++ raises `management::ValidationError`, the server's 400/422 class, not `std::invalid_argument`. A `catch` of the validation type misses it; a `catch` of `NetworkError` still catches it in all four, and nothing is written. | file on `1.1.x` |
| C163-08 | Low | typescript, python, csharp, go, java, cplusplus, php, swift | each §14.6 test (§3) | The 1.63 §14.6 test lacks some of its parts:<ul><li>a cookie login through the SDK (TS, Py, C#, Go, Java seed it);</li><li>the SDK's own device operations (C#, Java send raw POSTs);</li><li>a token request (Go);</li><li>the control *after* the `/oauth2/*` calls (TS and Py run it first; C++, PHP and Swift have none; Go counts jar entries).</li></ul>No defect is hidden: every reviewer probed the full sequence and it passed. C and Kotlin meet the paragraph; Rust's control comes first (C163-17). | file on `1.1.x` |
| C163-09 | Low (go, java, cplusplus, php); Info (typescript, python, csharp, kotlin) | each C162-07 test (§3) | Halves of the §27.9 C162-07 bullet missing: the "states the member → `Update` carrying the stated value" half (Go, C++, TS asserts only absence); the `NoChange` half (Go, Java, C++, Py `plan` only); the `service_type` half (C++, PHP, Py, C#'s `NoChange`, Kotlin's "stated `service_type`"). The code passes every missing half (probed). | file on `1.1.x` |
| C163-10 | Low (contract text); Info (c, cplusplus, csharp, java, kotlin, php, swift) | §27.6.2 item 4, §27.9, §34.6 (ab); each SDK's open-enum decode | "Naming the member **and the value**": seven SDKs decode an unknown value to a text-less `Unknown` and name the member only; TS, Py, Go and Rust keep the string and name both. The value is diagnostic; keeping it costs a model change in each of the seven (a minor in C). **Ruled: the contract changes**, see §6 and Q3. | contract text (ilpanich/axiam#750); SDK side Info |
| C163-11 | Low | contract | §34.7 (a); §14.6 (`:3177`ff, "An SDK that never sends cookies (Kotlin, Swift)…") | Kotlin and Swift keep a jar and send both headers on management requests; they withhold them **on `/oauth2/*`** only. "Passes by construction" is wrong for both, and the control applies to them. | contract text (ilpanich/axiam#750) |
| C163-12 | Low | typescript | `src/rest/session.ts:303-305`; `interceptors.ts:198-199` | Browser persona: `withCredentials:false` does not stop the XHR adapter sending same-origin cookies, so a same-origin app still sends `axiam_*` to `/oauth2/*`; §12.1 rule 3 names `credentials: "omit"`. | filed |
| C163-13 | Low | rust | `src/ssf.rs:400`, `:430-436` | `SsfReceiver`'s JWKS verifier uses `client.http()` (with the jar), so after a cookie `login()` the `GET /oauth2/jwks` carries `axiam_*`. A narrow trigger, and a public-key GET; the PR moved the client's other two JWKS verifiers to `http_bare`. | file on `1.1.x` |
| C163-14 | Low | python | `_client.py:978-988`; `_session.py:416-424` | An explicit PAT on `/uma2/*` travels beside a cookie-login session's `axiam_access` and CSRF. The server reads the cookie first and refuses `403`: the session fallback §20.2 rule 1 forbids. Fails closed; pre-existing; #100 item 1 fixed the adopted-credential case only. | filed |
| C163-15 | Low | cplusplus | `include/axiam/axiam.hpp:55` | `axiam::kVersion` is `"1.1.0"` in a 1.2.0 build (its doc says it matches the CMake version; 1.1.0's release bumped it). | file on `1.1.x` (or with C163-04) |
| C163-16 | Low | go | `internal/jwks/verifier.go:81-95` | Pre-existing: `jwk.Cache.Register` without `jwk.WithHTTPClient`, so the JWKS fetch ignores the SDK's custom CA, mTLS and timeout. | file on `1.1.x` |
| C163-17 | Info | rust | `tests/oauth2_no_session_bearer_test.rs:324`; `src/client.rs:555-558`, `:590-591`; `src/amqp/messages.rs:150-176` | The §14.6 control runs before the oauth2 calls. `/oauth2/*` no longer follows redirects, which the CHANGELOG does not record. On wasm32, `http_bare` uses the browser's default `same-origin` credentials. The non-`rest` branch of `check_action` is dead (the amqp-only build fails on main too). `sign_payload` could point to `AuditEventMessage::sign`. | file on `1.1.x` |
| C163-18 | Info | typescript, python, c, go, java, kotlin, php, swift | §3 per SDK | Text and doc drift: TS README "(ab)/(ac)"; a Python docstring; C stale comments; Go "before any wire call" and the `@v1.1.0` pin; the Java README breaking-change list and a §-citation; Kotlin README "ValidationError" and "(ab)"; the PHP stack-order comment and the `toArray()` throw unrecorded; Swift README `1.1.0`. | file on `1.1.x` |
| C163-19 | Info | go, kotlin, php, csharp | Go `client.go:828-830`; Kotlin `SessionState.kt:109-110`; PHP `AuthMiddleware.php:106`; C# `WriteIsolatingHandler.cs:86-98` | The posture of the `/oauth2/` match:<ul><li>Go matches anywhere in the path. This is harmless, because its jar still stores and the server exempts the federation routes from CSRF; anchor it as Java does.</li><li>PHP and C# miss a base URL with a path prefix.</li><li>Kotlin anchors to the base host and path while endpoints come from discovery.</li></ul>None is reachable against AXIAM's own discovery document. | file on `1.1.x` |
| C163-20 | Info | c, cplusplus, csharp, java | §3 per SDK | <ul><li>C: an adopted device bearer still reaches `/oauth2/jwks` and `/oauth2/revocations` (pre-existing); a stated unknown enum is untested; the local-refusal `transport_cause` differs between families.</li><li>C++: the cookie-less pool sits outside `max_concurrent_requests`.</li><li>C#: every `/oauth2/*` request opens a new connection; a hand-composed handler over a `UseCookies=true` handler is undocumented.</li><li>Java: a caller-stated `UNKNOWN` fails at `apply`.</li></ul> | file on `1.1.x` |

**Counts:** Medium 6 (five SDK, one contract) · Low 10 · Informational 4. There is no High.

### Rulings on the orchestrator's cross-cutting points

1. **(c) and the "seven AMQP SDKs".**
   - **Not one SDK publishes to `axiam.audit.events`.**
     - TypeScript, Python, Java, C#, PHP and Go consume and verify. Their only publish is the §22
       reactor reply, and they have no builder or signer of an `AuditEventMessage`.
     - TypeScript and Rust export a generic HMAC over caller bytes (`signPayload`/`sign_payload`)
       and a DTO documented as received.
     - Rust alone has a message-level helper, `AuditEventMessage::sign`, new in this PR, guarded by
       `check_action`.
   - So "(c) N/A" is correct for six, and Rust's guard is the whole of (c) in practice. A guard on a
     generic byte signer would be wrong: it cannot know the bytes are an audit message.
   - The text is the defect: C163-06, Medium, because the release's normative record misdescribes
     six SDKs. Exact replacement in §6.
   - **No SDK publishes audit events without the guard.**
2. **"Naming the member and the value".** Ruled for **the contract wording to change** (C163-10).
   - The safety property of §27.6.2 item 4 is "refuse at `plan`, nothing written". Every SDK that
     refuses at `plan` meets it.
   - The value is a diagnostic. Seven SDKs decode an unknown open-enum value to a text-less
     `Unknown`; recovering it costs a generated model member in each, and in C a minor release under
     its README policy.
   - TS, Py, Go and Rust already name it. The others are asked, Informationally, to keep the raw
     string when they next regenerate.
   - If the maintainer prefers the strict wording, the seven change in 1.1.x, not before W8 (Q3).
3. **The error type.** §27.6.2 item 4 names the validation error for C162-06/07, and the 1.62
   review's §6 text repeated it.
   - Raising the bare `NetworkError` (Rust, Kotlin, C#) or the server's `ValidationError` class (C++)
     is a deviation. It is **Low** (C163-07), not Medium: in all four the raised type is a
     `NetworkError`, which is every SDK's catch-all for a local refusal (§27.4 rule 7). The refusal
     itself is correct, and nothing is written.
   - **C162-08 is different.** Item 4 says "rule 2's client-side error", which is each SDK's
     documented manifest refusal type (§34.2 B5). TypeScript's and Python's `NetworkError` there
     conform; the executors' notes describe conformance, not a defect.
   - C's `AXIAM_ERR_NETWORK` *is* C's validation category: it has no other.
4. **Versioning.** The plan §8.2 rule is "the patch, or the minor where a change is source-breaking".
   Against it:
   - **Patch is right** for TypeScript, Rust, Python, C, C#, Go, PHP and Swift. Rust's two new
     methods are additive, and PHP's `toWire()` is additive.
   - **Java 1.2.0 is right.** The canonical record constructor changed.
   - **C++ 1.2.0 with `SOVERSION` 3 is right.** `PageRequest`, embedded in `Page<T>`, grew, which is
     an ABI break. The 1.62 review's C162-01/02 established that an ABI break moves `SOVERSION` and
     the minor. C++ is source-compatible for aggregate initialisation; its stale `kVersion` is
     C163-15.
   - **Kotlin's 1.2.0 is right in substance but not applied** (C163-05). `[Unreleased]` without a
     bump differs from the ten others and from its own 1.1.0.
5. **W7.1's open questions.**
   - (q), the recovered `gdpr.user_pseudonymized` row, is Q1.
   - A `429 rate_limit_exceeded` on a device poll is Q2. §14.2 rule 9 says what it is (an
     `OAuthProtocolError`, never the polling signal) but not what the polling loop does next, and
     §33.7 rule 5 answers exactly that for CIBA. No SDK was checked against a rule that does not
     exist yet.
6. **The coming re-vendor.** The 1.1.0 spec version in today's vendored files is not counted. What
   the re-vendor must carry is in §6.

**Ruled without a finding** (the executors' notes):

- TypeScript: "C162-07 fires only on an Update" is the rule (`Create` carries nothing from a read;
  `NoChange` writes nothing).
- Python: the "plan problems channel" refuses C162-08 before any read.
- C: "refusal names member not value" is C163-10; "AXIAM_ERR_NETWORK" is C's validation category.
- C++: the cookie-less handle pool is sound, and §6.1 client certificates are kept.
- C#: the caller-supplied handler cannot be given to `AxiamClient`.
- Go: "/oauth2/* drops all cookies" is right and cannot be bypassed by a caller's `http.Client`.
- Java: "(c) N/A" is right.
- Rust: the amqp-only build failure is pre-existing (52 errors on main and head, not 51).
- Swift: "(a) rests on the existing Contract162 test" holds for the assertion, not the control
  (C163-08).

## 5. Questions for the maintainer

Each is a question §11 of the plan does not answer; none was worked around. Q1 and Q2 are W7.1's
open questions; Q3 follows from this review's ruling on C163-10.

**Q1 (W7.1 (q)) — the recovered `gdpr.user_pseudonymized` row.**
- **What happens.** After a crash mid-erasure, the next start's recovery writes the row with
  `certificates_revoked: null` and `recovered: true`. [§27.11](../sdks/CONTRACT.md) rule 5 says the
  erasure "carries the count on its `gdpr.user_pseudonymized` row". The security review judged
  `null` safe, since any number the recovery wrote would be fabricated in an append-only row.
- **Options.**
  - (a) Amend rule 5: "carries the count, or `null` with `recovered: true` when the row was written
    by the start-up recovery and the count is not known".
  - (b) Keep the sentence and have the recovery count the user's revoked certificates.
- **Recommendation: (a).** A recovered count would be a reconstruction presented as a record. No SDK
  parses the row's metadata (it is a server audit record), so no SDK changes.

**Q2 (W7.1) — what does a device poll do on `429 rate_limit_exceeded`?**
- **What the contract says.** §14.2 rule 9 makes the `429` an `OAuthProtocolError` with
  `error == "rate_limit_exceeded"` and forbids reading it as `slow_down`. It is silent on the loop.
  An SDK whose `device_login` ends on every `OAuthProtocolError` outside the five polling codes
  therefore ends an approved flow on a rate-limit hit.
- **The analogy.** §33.7 rule 5 answers the same question for CIBA: "a `429` on `ciba_poll` is
  waited out … and counts as one interval, never a reason to poll faster afterwards", with
  `Retry-After` as a minimum wait capped at the deadline.
- **Options.**
  - (a) Add the CIBA sentence to §14.2: "A `429 rate_limit_exceeded` on a poll is not terminal: the
    loop waits `Retry-After` (a minimum, capped at the `expires_in` deadline), counts it as one
    interval, does not raise the interval for it, and polls again."
  - (b) Make it terminal and say so.
- **Recommendation: (a), in contract 1.64**, with a §14.6 test. It binds all eleven, and none was
  reviewed against it here, because it is not yet a rule.

**Q3 — keep "naming the member and the value" strict, or relax it (C163-10)?**
- **Recommendation:** relax it to "naming the member, and the value where the SDK's decoded type
  keeps it", in the W7.1 follow-up that carries C163-06 (exact text in §6), and ask the seven SDKs
  to keep the raw string Informationally at their next regeneration.
- **The strict alternative** makes C, C++, C#, Java, Kotlin, PHP and Swift change their generated
  models in 1.1.x: a minor release in C and C++, and an additive member elsewhere. This review's
  disposition is unaffected either way, since no SDK fix before W8 depends on the answer.

## 6. Fix-pass work list (before W8)

**Every SDK (all eleven), once the contract text below has landed: the re-vendor.**

1. **Re-vendor** byte for byte from the plan branch's final head:
   - `openapi.json` and `management-registry.json` as of `750be9f0a` (`chore(release): version 1.1.1`):
     - `openapi.json` sha256 `15dace9c72952d6e4bfb8b479aa6d23338c2e8ab9b156f6489e82654bd1985bf`;
       `info.version` `1.1.1`; `x-axiam-spec-digest` and the registry's `spec_digest`
       `sha256:443c9d39bb7da2d55f72583d9a74b37a76e90bf30b9f9fff2a7f12c6395f8098`;
     - `management-registry.json` sha256
       `b0d5e7498b8ae8ef85f8cfc9e5617a772dae205fcf25ecaebf371280167a2976`; `spec_version` `1.1.1`.
   - `CONTRACT.md` from the commit that carries C163-06, and C163-10/C163-11 if taken. Until then it
     is `9997c7fb…` (unchanged since `a6cd10eba`).
   - `proto/` is unchanged.
2. **Run the generator `--check` and the suite.** No generated file embeds the version or the digest
   (as in 1.62), so `--check` should stay clean.
3. **Update the provenance.** Replace the "re-vendored from `a6cd10eba`" sentences in each
   CHANGELOG and README with the new commit. Where a CHANGELOG says "the seven AMQP SDKs refuse"
   or "(c) N/A", make it agree with the corrected §8: Rust "refuses in `AuditEventMessage::sign`";
   the others "ship no helper that builds or signs an `AuditEventMessage`".

**TypeScript — PR #147 — C163-01 (Medium).**
- **Fix.** `src/rest/interceptors.ts`: make `isOAuth2Endpoint(url, session)` a prefix match on the
  path relative to the base URL:
  1. `const p = new URL(url, session.baseUrl).pathname`;
  2. strip the base URL's own pathname prefix;
  3. `return p.startsWith('/oauth2/')`.

  Use it in both the CSRF interceptor (`:66-71`) and the device-token interceptor (`:194`).
  Optionally align `src/node/oidc.ts:2724` and `SKIP_REFRESH` (`interceptors.ts:104`), which use
  the same `includes`.
- **Test** (fails on `7c2aa475b`, passes after). A mock answers
  `POST /api/v1/auth/federation/oauth2/callback` with `Set-Cookie: axiam_access=fed-access`,
  `axiam_csrf=c`. Call `ssoCompleteOauth2`, then a management `POST`, and assert
  `Cookie: axiam_access=fed-access` and `X-CSRF-Token: c` on it. Add the same assertion for
  `ssoStartOauth2` carrying no stripped header. The reviewer's probe
  (`zzFederationJar.probe.test.ts`) is this test.

**Swift — PR #76 — C163-02 (Medium).**
- **Fix.** `Management/ManagementManifestNetwork.swift`, `planNetwork` (`:428-502`): for a found
  profile whose action would be `Update`, raise the SDK's validation error before returning the
  plan when:
  - `spec.terminationAction == nil` and `found.terminationAction == .unknown`; or
  - `service_type` is unstated (not `.some`) and `found.serviceType == .unknown`.

  The error is `AxiamError.network(NetworkError(…, statusCode: 400, isValidation: true))`, which is
  Swift's P12.2 mapping. Its message names `network.profiles[<key>].termination_action` (or
  `.service_type`) and the value. To name the value:
  - keep the raw string, by decoding the two open-enum members of `NetworkReplyProfile` through a
    small wrapper that keeps the wire text (or reading the list page's raw JSON in the manifest
    read); or
  - if Q3 is answered as recommended, name the member and say the value is unknown.
- **Tests** (§27.9; each fails on `4091f8196`). A `MockTransport` read of a profile with
  `termination_action: "future"`, and separately `service_type: "future_service"`:
  1. A manifest changing `sessionTimeoutSecs` makes `plan` throw a validation error naming the member
     (and the value, if kept), and the mock saw no non-GET request; `apply` throws the same with
     zero writes.
  2. A manifest stating the member gives an `Update` whose PUT body carries the stated value and
     never `"future"`.
  3. Nothing differs: `NoChange`, no write.
- **Changelog.** Record the fix in `CHANGELOG.md` `[1.1.1]` as C162-07, which the 1.62 review mis-cited
  for Swift.

**C — PR #75 — C163-03 (Medium).**
- **Fix.** `src/uma.c`, `uma_transport` (`:130-157`): append the empty-`Cookie` signal for every call:
  `headers = axiam_kv_append(headers, "Cookie", "")`, failing the request when the allocation fails,
  as `send_bare` does at `src/client.c:365-369`.
  - The function's other callers are the PAT-authenticated `/uma2/*` Protection API calls, where
    withholding the jar is consistent with §20.2 rule 1.
  - To scope the change to the grant only, add the signal at `:803` instead.
- **Test** (fails on `05483b25d`: the probe saw `cookie=1`). In `tests/test_oauth2_no_session.c`,
  serve `/.well-known/uma2-configuration`, call `axiam_uma_exchange_ticket` after the cookie login,
  and assert `cookie == 0 && csrf == 0` on `POST /oauth2/token?tenant_id=`.

**C++ — PR #77 — C163-04 (Medium), with C163-15.**
- **Fix.**
  - `src/client.cpp`, `Client::uma_exchange_ticket` (`:1494-1506`): set `req.sessionless = true;`
    after `req.body = form;`.
  - Recommended backstop: `CurlTransport::perform` treats any request whose URL path starts with
    `/oauth2/` as sessionless, so a future call site cannot miss it.
  - Same commit: `include/axiam/axiam.hpp:55` `kVersion = "1.2.0"`, optionally pinned by
    `tests/test_version_policy.cpp` against a `PROJECT_VERSION` compile definition.
- **Test** (fails on `a36aeb7ac`). Extend the §14.6 integration test:
  1. Serve `/.well-known/uma2-configuration` with `token_endpoint` under `/oauth2/token`.
  2. Log in, call `uma_exchange_ticket`, and assert no `Cookie` on that request.
  3. While there, add the management control C163-08 asks for.

**Kotlin — PR #78 — C163-05 (Medium).**
- **Fix.**
  - `gradle.properties` `version=1.2.0`, and the README install snippets (`:226`, `:238`) to 1.2.0.
  - `CHANGELOG.md`: rename `## [Unreleased]` to `## [1.2.0] - <date>` with an empty `[Unreleased]`
    above it, and drop "no tag is cut here".
- **Check.** `./gradlew help -q --console=plain` prints the project version `1.2.0`. The
  `version-policy`-style assertion that the CHANGELOG's first released heading equals
  `gradle.properties` is optional.

**Contract — C163-06 (Medium), with C163-10 and C163-11 (Low).** A W7.1 follow-up commit on the plan
branch; then regenerate nothing (no spec change). The exact text follows.

- **§8, the paragraph "A producer MAY refuse them locally (contract 1.63; #710 item 3)",** in full:
  > **A producer MAY refuse them locally (contract 1.63; #710 item 3).** No SDK ships a publisher for
  > `axiam.audit.events`: the seven AMQP SDKs (Rust, TypeScript, Python, Java, C#, PHP and Go)
  > consume and verify §8's messages, and an application that publishes audit events builds, signs
  > and publishes the `AuditEventMessage` itself. An SDK helper that builds or signs an
  > `AuditEventMessage` MAY refuse, before it signs, an action that begins with `tenants.` or
  > `gdpr.`, ASCII case ignored, by raising the §2 `ValidationError` whose message names the
  > reserved namespace and never the payload: a silent dead-letter, with no error from an
  > acknowledging broker, is the costlier failure, and the check is one prefix comparison. **The
  > Rust SDK's `AuditEventMessage::sign` does**, and a refused message is never signed. The other six
  > ship no such helper and have nothing to refuse. A generic HMAC over caller-supplied bytes (Rust's
  > `sign_payload`, TypeScript's `signPayload`) is not such a helper. Refusing locally changes nothing
  > the server accepts, and an SDK that does not refuse still conforms: the server's refusal is the
  > authority, and a producer MUST NOT take the absence of a local check as leave to publish such an
  > action. **The grammar is a MAY too, and an SDK need not port it**: a helper that refuses the
  > reserved prefixes MAY refuse an action outside the grammar with the same `ValidationError` at the
  > same point; none is required to. The SDK's own actions (`user.login` and the like, and
  > `METHOD /path`) are inside it.
- **§34.7 (c),** in full:
  > **(c) An SDK helper MAY refuse the reserved audit actions locally (D-5; MAY; #710 item 3).**
  > [§8](…): a helper that builds or signs an `AuditEventMessage` MAY refuse, before signing, an
  > action that begins with `tenants.` or `gdpr.` (ASCII case ignored) with a `ValidationError`
  > naming the namespace and never the payload. The server's refusal is unchanged and stays the
  > authority. No SDK ships a publisher for `axiam.audit.events`. Rust ships such a helper
  > (`AuditEventMessage::sign`) and refuses there. TypeScript, Python, Java, C#, PHP and Go consume
  > and verify only and have nothing to refuse. Kotlin, Swift, C and C++ ship no AMQP. The
  > producer-side refusal of the action **grammar** (item m) is a MAY an SDK need not port. *Where
  > the plan said "§33" for this item the rule lives in §8; §33 is CIBA.*
- **§34.7 (m),** the sentence "The seven AMQP SDKs MAY refuse it locally with the same
  `ValidationError` and are not required to": replace with "A helper that refuses the reserved
  prefixes of (c) MAY refuse it locally with the same `ValidationError` and is not required to".
- **The Breaking Changes Log entry** (2026-10-20): replace "a producer's local refusal of the reserved
  `tenants.` and `gdpr.` audit actions (§8; MAY, the seven AMQP SDKs do)" with "a local refusal of the
  reserved `tenants.` and `gdpr.` audit actions by an SDK helper that builds or signs an
  `AuditEventMessage` (§8; MAY; Rust's `AuditEventMessage::sign` does, and no SDK ships a
  publisher)". In the same entry's head, replace "a third that seven may" with "a third that an
  audit-message helper may".
- **C163-10.** In §27.6.2 item 4, replace "**naming the member and the value**" with "**naming the
  member, and the value where the SDK's decoded type keeps it** (an SDK whose open enumeration
  decodes to a text-less `Unknown` names the member and says the value is unknown)". In the §27.9
  bullet, replace "raises the validation error naming the member and the value" with "raises the
  validation error naming the member and, where the SDK keeps it, the value". Make the same change in
  §34.6 (ab). Apply only if Q3 is answered as recommended, or by default.
- **C163-11.** In §14.6, replace "An SDK that never sends cookies (Kotlin, Swift) runs the same test;
  it passes by construction" with "Kotlin and Swift already withheld both on `/oauth2/*` before 1.63;
  they run the same test, control included". In §34.7 (a), replace "Kotlin and Swift already withhold
  them and add the test only" with "Kotlin and Swift already withhold them on `/oauth2/*` and add the
  test only".

**No other SDK has a Medium-or-higher item.** Rust, Python, C#, Go, Java and PHP need only the
re-vendor.

## 7. Issues for `1.1.x`

**Filed** by this review, each with its body ending in the Claude Code footer:

- ilpanich/axiam-typescript-sdk#148 — C163-08, C163-09, C163-12, C163-18
  (milestone `1.1.x`).
- ilpanich/axiam-python-sdk#102 — C163-08, C163-09, C163-14, C163-18 (milestone
  `1.1.x`).
- ilpanich/axiam-c-sdk#76 — C163-10, C163-18, C163-20 (milestone `1.1.x`).
- ilpanich/axiam#750 — C163-10, C163-11, contract text (milestone `1.1.x`). This is
  redundant if the C163-06 follow-up takes them.

**Not filed. This session could not write to these eight repositories:** the GitHub connector here
reaches only `axiam`, `axiam-typescript-sdk`, `axiam-python-sdk` and `axiam-c-sdk`, and attaching the
others was refused. The orchestrator, or the SDK sessions, file the texts below on each repository's
`1.1.x` milestone. Search first: each repository's 1.62 follow-up issue is #132 (Rust), #76 (C++),
#107 (C#), #99 (Go), #115 (Java), #77 (Kotlin), #84 (PHP) and #75 (Swift), each closed by its 1.63
PR. Title each *Contract 1.63 conformance follow-ups (IDs)*, and end each body with the footer.

- **Rust (C163-07, C163-13, C163-17).**
  - **C163-07 (Low).** `src/management/manifest/network.rs:319-328` `unknown_open_enum` returns
    `AxiamError::network(..)` without a `ValidationError` source, so `e.validation()` is `None`. Build
    it with `network_with_source` and
    `ValidationError { status: 400, operation: "manifest.plan", fields: [FieldError { field: member, .. }] }`
    (or `local_refusal`). Test: `tests/network_manifest_test.rs:762-768` asserts `error.validation()`
    and `fields[0].field == member`.
  - **C163-13 (Low).** `src/ssf.rs:400` (and `:433`): use `self.client.http_bare()` for the
    `SsfReceiver` JWKS verifier and discovery. Test: cookie login against a mock setting `axiam_*`,
    an `SsfReceiver` with `jwks_uri={mock}/oauth2/jwks`, `verify_set`, and no `cookie` header on the
    JWKS GET.
  - **C163-17 (Info).**
    - Move the §14.6 control (`logout`) after the oauth2 calls.
    - Record in the CHANGELOG that `/oauth2/*` and the JWKS fetch no longer follow redirects.
    - On wasm32, use `credentials: "omit"` in `oauth2_post`.
    - Drop the dead non-`rest` branch of `check_action`; `ValidationError` is not `rest`-gated.
    - Point `sign_payload`'s doc to `AuditEventMessage::sign`.
    - Pre-existing: `--no-default-features --features amqp` does not compile (52 errors).
- **C++ (C163-07, C163-08, C163-09, C163-10, C163-15 unless fixed with C163-04, C163-20).**
  - **C163-07 (Low).** `src/management_manifest.cpp:254`, `:260` `refuse_unknown_carried` throws
    `management::ValidationError` (the server's 400/422 class). Throw `std::invalid_argument`, as
    §27.6.2 item 4 and the SDK's own P12.2 refusals do. Test: catch `const std::invalid_argument&`.
  - **C163-08 (Low).** `tests/test_integration_curl.cpp:331-333` has no control. After
    `oidc_refresh`, make a state-changing management request and assert `Cookie` and
    `X-CSRF-Token: csrf-int`; have the mock also set `axiam_csrf`.
  - **C163-09 (Low).** `tests/test_manifest_network.cpp:667-699`: add the `service_type` refusal,
    the stated case's `replace_profile` body (`"radius_request"`, never the unknown value), and
    `NoChange` with no write.
  - **C163-10 (Info).** Keep `std::optional<std::string> termination_action_wire`/`service_type_wire`
    beside the open-enum members and quote the value in the refusal.
  - **C163-20 (Info).** The cookie-less handle pool is outside `max_concurrent_requests`.
- **C# (C163-07, C163-08, C163-09, C163-10, C163-20).**
  - **C163-07 (Low).** `Management/ManifestApi.cs:633-656` `RequireNoUnknownCarried` throws
    `NetworkError.FromMessage`; throw
    `new ValidationError(msg, [new FieldError(member, …)])`. Test: `Assert.ThrowsAsync<ValidationError>`.
  - **C163-08 (Low).** `Contract163OAuth2NoCookieTests.cs`: build a real `AxiamClient` over a mock
    whose login sets `axiam_access` and `axiam_csrf`; call `LoginAsync`, `DeviceAuthorizeAsync`,
    `DevicePollAsync` and a token call, asserting no `cookie` or `x-csrf-token`; then a management
    `POST` asserting both. Match the full path in the lookup.
  - **C163-09 (Info).** Test `NoChange` for `service_type` too.
  - **C163-10 (Info).** Keep internal `RawTerminationAction`/`RawServiceType` on
    `NetworkReplyProfile`, set at the `NetworkApi` decode, and quote the value.
  - **C163-20 (Info).**
    - The cookie-less `/oauth2/*` handler has `PooledConnectionLifetime = Zero`, so every poll opens
      a new TLS connection; consider a pooled cookie-less handler.
    - Document in `ConfigureFactoryHandler` that a hand-composed handler over a `UseCookies=true`
      handler would send its own jar to `/oauth2/*`.
- **Go (C163-08, C163-09, C163-16, C163-18, C163-19).**
  - **C163-08 (Low).** `contract_163_test.go:15-60`:
    - mount a sign-in mock answering `Set-Cookie: axiam_access`, `axiam_csrf` and `X-CSRF-Token`,
      and call `Login`;
    - run `DeviceAuthorize`, `DevicePoll` and `LoginClientCredentials`, asserting no `Cookie` and
      no CSRF;
    - then call `Groups().Create` and assert both.
  - **C163-09 (Low).** `contract_163_test.go:62-90`: add, per member, "stated → one PUT carrying
    the stated value" and "nothing differs → `IsConverged()`, no writes".
  - **C163-16 (Low, pre-existing).** `internal/jwks/verifier.go:81-95`: pass
    `jwk.WithHTTPClient(c.httpc)` to `Register`, so the JWKS fetch uses the SDK's CA, mTLS and
    timeout.
  - **C163-18 (Info).** `CHANGELOG.md:24-26` and `management_manifest_network.go:378-379` say
    "before any wire call"; it should read "before any write". README `@v1.1.0` pin.
  - **C163-19 (Info).** `client.go:828-830` `isOAuth2Path` matches `/oauth2/` anywhere (it catches
    `/api/v1/auth/federation/oauth2/*`, which is harmless here). Anchor it to the base path, as Java
    does.
- **Java (C163-08, C163-09, C163-10, C163-18, C163-20).**
  - **C163-08 (Low).** Extend `OauthNoSessionCredentialTest`:
    - the login mock also returns `Set-Cookie: axiam_csrf` and `X-CSRF-Token`;
    - assert no `Cookie` and no CSRF on device authorization and the token requests;
    - the control is `management().users().create(..)` carrying both.
  - **C163-09 (Low).** `NetworkManifestTest.java:411-435`: add `NoChange` (same read, nothing
    differs, no PUT) and `service_type` at `apply`.
  - **C163-10 (Info).** Capture the raw `termination_action`/`service_type` from the list-profiles
    JSON in `ManifestApi.readNetwork` and quote them, length-capped.
  - **C163-18 (Info).** The README's source-breaking list omits 1.2.0's `ScimTargetResponse.updatedAtRaw`;
    `ScimTargetResponse.java:30-32` cites §32.2 (1.62) where §31.3 rule 4 (1.63) applies;
    `ManifestApi.java:593` says "contract 1.62".
  - **C163-20 (Info).** `ManifestValidation` refuses a stated `UNKNOWN` `kind` but not a stated
    `UNKNOWN` `termination_action`/`service_type`, which then fails at `apply`; refuse it at
    validation.
- **Kotlin (C163-07, C163-09, C163-10, C163-18, C163-19).**
  - **C163-07 (Low).** `ManifestApi.kt:573-577` `unknownCarried` returns `NetworkError`; return
    `ValidationError(msg, listOf(FieldError(member, …)))`, as 1.1.0's apply-time refusal did. Test:
    `ManifestNetworkTest.kt:388`, `:400` with `assertThrows(ValidationError::class.java)`.
  - **C163-09 (Info).** Add "a stated `serviceType` resolves it".
  - **C163-10 (Info).** Generalise `RAW_TIMESTAMPS`/`keepRawTimestamps` to add trailing
    `termination_action_raw`/`service_type_raw` members, and quote the value.
  - **C163-18 (Info).** `README.md:104-105` (local refusals are `ValidationError`), `:106-107`
    (`toInput()` carries `updatedAtRaw`); the CHANGELOG's "(ab)" label is a 1.62 item letter.
  - **C163-19 (Info).** The `/oauth2` exclusion is anchored to the base host and path while
    endpoints come from discovery.
- **PHP (C163-08, C163-09, C163-10, C163-18, C163-19).**
  - **C163-08 (Low).** `tests/Contract163/OAuth2NoSessionCredentialsTest.php:71-85`: queue a fifth
    response, call `groups()->create`, and assert `history[4]` carries `Cookie` with `axiam_access=`
    and `X-CSRF-Token: csrf-from-login`.
  - **C163-09 (Low).** `OpenEnumRefusalTest.php:111-178`: a data provider over `termination_action`
    and `service_type` for the refuse, stated and `NoChange` tests.
  - **C163-10 (Info).** Record the raw string in the generated `fromArray()` when an open enum
    decodes to `Unknown`, and quote it.
  - **C163-18 (Info).**
    - `AuthMiddleware.php:118-121` states the Guzzle stack order backwards.
    - `RefreshMiddleware.php:19-23` claims an order `AxiamClient.php:467-468` does not build; check
      that a retried request gets fresh headers.
    - Record in the CHANGELOG that `toArray()` on a response holding `Unknown` now throws.
  - **C163-19 (Info).** `str_starts_with($path, '/oauth2/')` misses a base URL with a path prefix,
    which `JwksVerifier.php:761` makes reachable.
- **Swift (C163-08, C163-18).**
  - **C163-08 (Low).** `Contract162Oauth2NoSessionCredentialTests.swift:112-118`: add
    `Set-Cookie: axiam_csrf=…` to the login mock, and after the `/oauth2/*` calls a management
    `POST` asserted to carry `Cookie` and `X-CSRF-Token`.
  - **C163-18 (Info).** The README install snippets still say `1.1.0`.
