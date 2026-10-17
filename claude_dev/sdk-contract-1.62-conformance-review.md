# CONTRACT 1.62 — cross-SDK conformance review (the 1.1.0 release)

**Date:** 2026-10-16
**Plan item:** W7.13 of [`release-1.1.0-plan.md`](release-1.1.0-plan.md) §8.3.
**Scope:** the eleven `claude/contract-1.62` branches, each a draft PR on top of its repository's
`origin/main`, vendoring `sdks/CONTRACT.md`, `sdks/openapi.json`, `sdks/management-registry.json`
and `proto/` from axiam `d76c5a80b` (branch `claude/release-1.1.0`). The rows read are those
§34.6 binds an SDK to: (e) the change-taking stream form, (f) an assigned `null` is "none",
(g) the response's own `updated_at` string, (h) the three meanings at the `update_stream` call
site, (i) the untyped request `user_id`, (j) the version and change-log fold, (l) the `network`
namespace (§36, twelve operations, no decision route), (m)/(t) the device grant's client
authentication, and (n)/(u)/(v)/(w) `network` as a §27.6 manifest namespace (§27.6.2), with the
§36.8, §32.8 test 7, §14.6 and §27.9 "Manifest, `network`" tests. Items (a)–(d), (k), (o)–(s)
ask nothing of an SDK beyond regenerating.

**Outcome.** No wire defect in what the release adds: every SDK carries the twelve operations and
no method for `POST /api/v1/network/decide`, exposes a `409`'s `reason_code` and a `403`'s
`action`/`resource_id`, sends the device grant's secret in the form body at both endpoints and
never `Authorization: Basic`, offers the change-taking form with the cut, keeps the server's own
`updated_at` string, sends the request `user_id` as a string, plans and applies `network` in
policy → segments → profiles order with the segment write's version carried to the profile, and
is at 1.1.0 with the never-tagged `[1.0.1]` folded into `[1.1.0]`. **Three findings are Medium
and are fixed in the SDK PRs before W8** (§6): the C and C++ shared libraries keep `SOVERSION 1`
although caller-allocated public types grew (C162-01, C162-02), and PHP sends an event-type URI it
has never seen as `""` instead of echoing it (C162-03, a 1.60 rule the 1.62 change-taking form
now depends on). Eleven Low or Informational findings are filed on `1.1.x` (§4). The review asks
the maintainer ten questions (§5), five of them carried over from W7.1. **Every SDK PR must also
re-vendor `openapi.json` and `management-registry.json` from `89e488e3e`** (the platform's
`chore(release): version 1.1.0`, `spec_digest`
`sha256:cf0fc71c2061576b077afd48d9903f9f4ef26d66e9edbebe5e3020be89fc59a7`); that is a required
item of the fix pass, not a finding.

## 1. Method

The 1.61 review's method (its §1), with the checklist re-cut for 1.62. One reviewer read every
repository's `origin/main..origin/claude/contract-1.62` diff and the files it touches, every cell
carrying a `path:line` on the commit below; where a README, a CHANGELOG, a commit message or the
orchestrator's running notes (the port executors' reports) disagreed with the code, the code won.
The executors' reports were treated as claims and each was checked against the code.

1. **Vendoring.** `CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/`
   byte-identical to axiam `d76c5a80b` (`cmp`; per-file `cmp` for `proto/axiam/v1/*.proto`).
   *New in 1.62:* also compared with `89e488e3e`, which differs from `d76c5a80b` in two members
   of each JSON file (`info.version`/`spec_version` `1.0.1` → `1.1.0`, and the digest) and in
   nothing else (`CONTRACT.md` and `proto/` are identical between the two). No generated file in
   any SDK embeds either value (searched), so the re-vendor is mechanical and `--check` stays clean.
2. **(l) The surface.** The twelve paths of §36.1 in the non-test sources; no `network/decide`
   outside tests and doc comments; the §36.8 test 1 assertion present.
3. **(e), (h).** The change-taking form exists, takes the stream and the changes, sends
   `events_requested` and `expected_updated_at` as read, cuts to a lowered ceiling only when the
   changes name no `events_requested`, sends a named `events_requested` as given; the plain
   converter's documentation names the caller's duty; the `update_stream` documentation states the
   three meanings; §32.8 test 7 present.
4. **(f), (g), (i).** An assigned `null` on `user_id` ×2 and `expected_updated_at` ×2 is dropped;
   `SsfStream` keeps the server's own `updated_at` string and both forms send it (Java, Kotlin
   changed; C# already did); the request `user_id` is a string.
5. **(m), (t).** Both device operations: a configured secret in the form body; no
   `Authorization` header; a public client sends none and is not refused; `client_id` on every
   poll; `401 invalid_client` an `OAuthProtocolError`, one request, outside the §9 guard; mTLS via
   the aliases; `private_key_jwt` and DPoP proofs (searched: no SDK implements either client role).
   *New:* what else rides on those two requests when the client holds a session or an adopted
   credential (C162-05).
6. **(n), (u), (v), (w).** Natural keys with the wire `kind`; order; `filter_ids` as a set, a
   duplicate refused with zero wire calls; the full replacement body built from the read; the
   segment write's `version` as the profile's `segment_version`; a `409`/`403` as the action's
   failure with `reason_code`; judged on the read for a clamped profile; pruning. *New:* what an
   `Update` does with an open-enum value read as unknown (C162-06/07), and with a stated `null`
   on a member that has a server default (C162-08).
7. **§36.8 tests 1–5** present (by name and by what they assert), `reason_code` accessor.
8. **(j) and the README.** Version 1.1.0 in every version file; `## [1.1.0]` directly under
   `## [Unreleased]` with no `## [1.0.1]` left, and the 1.61 entries inside it; the SemVer sentence
   ("a contract record may add a member or widen a type in a minor release … a removal waits for
   2.0.0"); conformance stated at 1.62.
9. **Anything else in the diff**, and the cross-SDK consistency points the executors raised.

No suite was run by the reviewer: every PR's CI was green on the commit read according to the
orchestrator's notes, and the Rust PR's seventeen check runs were re-read through the GitHub API
(all `success` or `skipped`). Disk was shared with other work, so no heavy target was built.
**Severity** uses the scale of the release's F4 reviews: **Medium** (a normative rule broken in a
way a caller meets, or a memory-safety hazard) is fixed in the SDK PR before W8; **Low**
(a deviation with a narrow trigger, no data loss) and **Informational** (posture, text, or a
question's dependent) are filed on the `1.1.x` milestone.

| Repo | Commit read | PR | CI on that commit |
|---|---|---|---|
| `axiam-rust-sdk` | `4c02dc1` | [#131](https://github.com/ilpanich/axiam-rust-sdk/pull/131) | green (re-read: 17 runs) |
| `axiam-typescript-sdk` | `973427c` | [#141](https://github.com/ilpanich/axiam-typescript-sdk/pull/141) | green |
| `axiam-python-sdk` | `71db0de` | [#98](https://github.com/ilpanich/axiam-python-sdk/pull/98) | green |
| `axiam-go-sdk` | `5ebfb22` | [#98](https://github.com/ilpanich/axiam-go-sdk/pull/98) | green |
| `axiam-java-sdk` | `dfcc1eb` | [#114](https://github.com/ilpanich/axiam-java-sdk/pull/114) | green |
| `axiam-php-sdk` | `7a238fa` | [#83](https://github.com/ilpanich/axiam-php-sdk/pull/83) | green |
| `axiam-kotlin-sdk` | `07855aa` | [#76](https://github.com/ilpanich/axiam-kotlin-sdk/pull/76) | green |
| `axiam-csharp-sdk` | `f70d039` | [#106](https://github.com/ilpanich/axiam-csharp-sdk/pull/106) | green |
| `axiam-c-sdk` | `18be8e1` | [#73](https://github.com/ilpanich/axiam-c-sdk/pull/73) | green |
| `axiam-cplusplus-sdk` | `d3670ed` | [#75](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/75) | green |
| `axiam-swift-sdk` | `4d34370` | [#74](https://github.com/ilpanich/axiam-swift-sdk/pull/74) | green (first compile was CI's: no Swift toolchain in the sandbox) |

**Vendoring, all eleven:** `CONTRACT.md`, `openapi.json` and `management-registry.json` are
byte-identical to `d76c5a80b`; the nine that vendor `proto/` (all but C and C++) have its five
files identical. Every branch is a straight line on its `origin/main` (merge base = `origin/main`).

## 2. What CI did not catch

Every suite was green, every required test of 1.62 exists by name in all eleven, and the
generators' `--check` jobs were clean. What the suites do not see:

- **A binary built against 1.0.0 run against the 1.1.0 shared library.** No job does it. In C,
  `axiam_error_t` grew by 176 bytes and the SDK resets the whole struct on entry to nearly every
  call (`axiam_error_reset`/`axiam_error_set`, 850 call sites), so a caller's 1.0.0-sized stack
  object is overrun; three manifest structs grew the same way. The library's `SOVERSION` is still
  `1`, so the loader cannot refuse the mismatch (C162-01). C++ has the same shape with no
  change-log word about it (C162-02).
- **An event-type URI the SDK has never seen, round-tripped.** §32.8 test 3 decodes one; nothing
  sends it back. PHP decodes it to `SsfEventType::Unknown`, whose wire value is `''`, so its
  change-taking form, the model form 1.62 asked the other ten to copy, sends `""` (C162-03).
- **A device grant run by a client that already holds a session.** Every §14.6 test starts from a
  fresh client, so "no `Authorization` header at either endpoint" holds in the tests and not after
  a login (Java, C#) or an adopted device credential (TypeScript, Python) (C162-05).
- **An unknown open-enum value read back into a manifest `Update`.** §36.8 test 4 decodes one;
  no §27.9 test then changes another member of that profile. The eleven do four different things
  (C162-06, C162-07, Q2).
- **A stated `null` on `termination_action`.** The idempotence test uses concrete values; Python
  never converges and TypeScript silently writes the server default (C162-08).
- **The contract's own tables.** §21.9 says seven SDKs generate DPoP proofs; none does (Q10).
  §27.10 still says `network` is "pending" in every SDK. §27.2 rule 1's counts are stale (C162-14).
- **Pruning.** §27.9's network test has a "with it on" half; no SDK offers pruning in any
  namespace, so every SDK tests only "nothing is pruned" (C162-11, Q5).
- **The re-vendor.** Each SDK's drift job compares with axiam `main`, which carries neither
  `d76c5a80b` nor `89e488e3e`, so nothing in CI says that the vendored spec is one commit old.

## 3. Per-SDK reports

Each report has the nine checks, then that SDK's findings. `path:line` is on the commit read.
The cross-SDK findings (C162-05 … C162-08, C162-11, C162-12) are listed in every report they
touch and described once, in §4.

---

### Report — rust — commit 4c02dc1 (PR #131)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical to `d76c5a80b` (×3, `proto/` ×5); re-vendor from `89e488e3e` required | — |
| 2 | (l) surface | `client.network()` with the twelve; `list_segments_all` carries `site`; deletes take `version: i64`; test asserts no decide method | `src/management/ops/network.rs:89`, `:165`, `:275`; `tests/network_management_test.rs:153` |
| 3 | (e), (h) | `SsfStreamInput::from_stream_with(&stream, SsfStreamChanges)`; cut only when `events_requested` not named; `Some(None)` leaves the key out; plain `From` documents the duty; `update_stream` states the three meanings | `src/management/checks.rs:156`, `:218`; `:87-112` (duty); `src/management/ops/ssf.rs:141-163`; `tests/ssf_management_test.rs:514`, `:571`, `:607`, `:638`, `:664` |
| 4 | (f), (g), (i) | `Option<String>` everywhere: one state for none; `updated_at` is a `String`; request `user_id: Option<String>` (source-breaking, recorded) | `src/management/models.rs:1126`, `:5566`; `tests/contract_161_test.rs:226` |
| 5 | (m), (t) | `client_secret` in both forms when `.oidc_client_secret` set, none otherwise; raw `http()` with no session header; mTLS aliases; DPoP not generated (doc says so) | `src/oidc/device.rs:49-66`, `:283`, `:375`; `tests/device_client_auth_test.rs:155`, `:244`, `:288`, `:374`, `:399`, `:432` |
| 6 | (n)–(w) manifest | `NetworkSpec { policy: Option, segments, profiles }` (two policies unrepresentable: conformant); duplicate key, duplicate Filter-Id and dangling segment refused in `validate`; set compare; full body from the read; `segment_version` from the write's response; no pruning (documented); unknown enum re-sent (C162-07) | `src/management/manifest/network.rs:330-383`, `:430-560`, `:656`, `:704-760`; `tests/network_manifest_test.rs:359`-`:893` |
| 7 | §36.8, `reason_code` | five groups present; `AxiamError::reason_code()` for a `409` only | `src/error.rs:135`, `:257-275`; `src/management/error.rs:123`; `tests/network_management_test.rs:388`, `:481`, `:578`, `:634`, `:725`, `:759`, `:824`, `:919` |
| 8 | (j), README | `1.1.0` (crate and `=1.1.0` macros pin); `[1.1.0]` holds the 1.61 entries; SemVer sentence; conformance 1.62 — but §36 not named (C162-12) | `Cargo.toml`; `CHANGELOG.md:10`; `README.md:61-72` |
| 9 | Other | the manifest macro/builder do not declare `network` (documented); `main` tracks 438 build artifacts under `vendor/axiam-opaque/target/` (pre-existing, C162-13) | `src/management/manifest/network.rs:56-58` |

**Findings:** C162-07 (Informational, re-sends an unknown enum), C162-11, C162-12, C162-13.

---

### Report — typescript — commit 973427c (PR #141)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical; re-vendor required | — |
| 2 | (l) surface | `client.network.*` twelve plus `listSegmentsAll`; surface test pins the registry's twelve | `src/management/ops/network.ts`; `test/management/contract162.test.ts` "§36.8 (1)" |
| 3 | (e), (h) | `ssfStreamInputWith(stream, changes)`: `undefined` is no change, `null` on `events_requested` is a deliberate reset (key left out); plain converter names the duty; call-site text | `src/management/checks.ts:89-113`, `:160-181`; `src/management/ops/ssf.ts:116-129`; `test/management/contract162Ssf.test.ts` |
| 4 | (f), (g), (i) | `omitNullMembers` on `user_id` (×2) and `expected_updated_at` (SSF create/update, SCIM update) — the rule 1.61 asked for (Q3); `updated_at` a string; `user_id` already a string | `src/management/models.ts:77`; `src/management/ops/ssf.ts:91`, `:146`; `ops/certificates.ts`, `ops/scim_targets.ts` |
| 5 | (m), (t) | `#appendClientSecret` at both; `/oauth2/device_authorization` added to `SKIP_REFRESH`; tests assert no header and one request on `401` — **but an adopted §6.1 device token rides on every same-origin request, `/oauth2/*` included** (C162-05) | `src/node/oidc.ts:1465`, `:1632`; `src/rest/interceptors.ts:44`, `:175-191`; `test/node/deviceClientAuth.test.ts` |
| 6 | (n)–(w) manifest | order, set compare, stated order sent, zero-call refusals, write-response version, clamped 403, no pruning; unknown enum re-sent from the read (C162-07); stated `null` `terminationAction` omitted from an `Update`, so the server default is written (C162-08) | `src/management/manifest/engine.ts:1250-1291`; `test/management/manifestNetwork.test.ts` |
| 7 | §36.8, `reason_code` | five groups; `ConflictError.reasonCode`; `403` body's `action`/`resourceId` now reach `AuthzError` | `src/management/errors.ts:54-75`; `src/management/request.ts:140-161` |
| 8 | (j), README | `package.json` `1.1.0`; `[1.1.0]` folds 1.61; SemVer sentence; conformance 1.62 naming §36 | `package.json:3`; `CHANGELOG.md:10`; `README.md:23`, `:221-224` |
| 9 | Other | the executor's question "a profile whose segment is absent on the server" is answered by the code: `Create` after the segment's `Create` in the same apply | `src/management/manifest/engine.ts` |

**Findings:** C162-05, C162-07, C162-08, C162-11.

---

### Report — python — commit 71db0de (PR #98)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical; re-vendor required | — |
| 2 | (l) surface | `client.network.*` sync and async; `delete_*` take `version: int` | `src/axiam_sdk/management/ops/network.py`; `tests/management/test_network.py` |
| 3 | (e), (h) | `ssf_stream_edit(stream, changes)` (a mapping of member names; an unknown name is a local `ValidationError`); duty text on `ssf_stream_input`; call-site text on both clients | `src/axiam_sdk/management/conversions.py:166-205`; `ops/ssf.py:223-235`, `:344-356`; `tests/management/test_ssf.py` |
| 4 | (f), (g), (i) | `_NEVER_NULL_MEMBERS` (held since 1.61); strings | `src/axiam_sdk/management/_wire.py:63`, `:113`; `tests/test_contract_162.py` |
| 5 | (m), (t) | `_append_client_secret` in both forms; tests cover post/basic registrations, public, mTLS over real TLS, `401` once — **but the adopted §6.1 credential is applied by `_rest_send_*` to the device endpoints** (C162-05) | `src/axiam_sdk/_oidc.py:1513`, `:1565-1597`; `src/axiam_sdk/_client.py:941-982`, `:1883-1892`; `tests/test_device_grant_client_auth.py` |
| 6 | (n)–(w) manifest | `NetworkSpec`; carries an unknown enum from the read (C162-07); `termination_action` may be stated `None`, is compared as drift and left out of the body, so `plan` never converges (C162-08); no pruning | `src/axiam_sdk/management/manifest/_spec.py:344`; `_engine.py:710-712`, `:860-863`, `:916-922`; `tests/management/test_network_manifest.py` |
| 7 | §36.8, `reason_code` | five groups; `ConflictError.reason_code` | `src/axiam_sdk/management/_errors.py:62-80` |
| 8 | (j), README | `1.1.0` in `pyproject.toml` and `__version__`; fold; SemVer; conformance 1.62 naming §36 | `README.md:21-30`; `CHANGELOG.md:10` |
| 9 | Other | a network-only manifest reads only network; `get_policy` only when a policy is stated | `_engine.py` |

**Findings:** C162-05, C162-07, C162-08, C162-11.

---

### Report — go — commit 5ebfb22 (PR #98)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical; re-vendor required | — |
| 2 | (l) surface | `client.Network()` twelve; `int64` version query params | `management_network.go`; `management_contract162_test.go` |
| 3 | (e), (h) | `SsfStream.ToInputWith(SsfStreamChanges)`; a nil `EventsRequested` leaves the read (so the form cannot express a reset — not required); duty text on `ToInput`; call-site text | `management_checks.go:175-222`; `management_ssf.go:176-190`; `management_ssf_contract162_test.go` |
| 4 | (f), (g), (i) | pointers (`omitempty`); request `UserID *string` (breaking, recorded) | `management_models.go:763`, `:4268`; `CHANGELOG.md:48-53` |
| 5 | (m), (t) | `appendOidcClientSecret` at both; an adopted credential is **never** applied to an `/oauth2/*` path | `oidc_device.go:64-133`, `:155-192`; `client.go:806-822`; `oidc_device_credentials_test.go` |
| 6 | (n)–(w) manifest | `NetworkSpec`; `TerminationAction *T` has no "none" (converges); re-sends an unknown enum from the read (C162-07); no pruning | `management_manifest_network.go:77-80`, `:105`, `:395`, `:490-498` |
| 7 | §36.8, `reason_code` | five groups; `ConflictError.ReasonCode`; `403` `Action`/`ResourceID` | `management_errors.go:83`, `:125` |
| 8 | (j), README | no version file (tag-versioned); fold; SemVer sentence; conformance 1.62 — §36 not named (C162-12) | `CHANGELOG.md:10`; `README.md:23`, `:2333-2337` |
| 9 | Other | the executor's §21.9 question: Go verifies DPoP proofs and generates none — the contract row is wrong (Q10) | `internal/dpop/dpop.go` |

**Findings:** C162-07, C162-11, C162-12.

---

### Report — java — commit dfcc1eb (PR #114)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical; re-vendor required | — |
| 2 | (l) surface | `client.network()` twelve plus `*All`; `df1f5c2` adds the §27.3 direct accessor | `src/main/java/io/axiam/sdk/management/NetworkApi.java`; `NetworkManagementTest.java` |
| 3 | (e), (h) | `ReplacementBodies.ssfStream(stream, SsfStreamChanges)`, a builder that keeps "never set" apart from "set to `null`"; event types are strings, so an unseen URI round-trips | `ReplacementBodies.java:124-138`; `SsfStreamChanges.java:27-118`; `SsfApi.java` |
| 4 | (f), (g), (i) | `@JsonInclude(NON_NULL)`; `SsfStream.updatedAtRaw` (the response string) sent by both forms; request `userId` is a `String` (record constructors change, recorded) | `models/SsfStream.java:68`; `ReplacementBodies.java:95`; `models/CreateCertificateRequest.java:49` |
| 5 | (m), (t) | secret in the body at both; test asserts no header — **but `AuthInterceptor` adds the cached session token to every same-host request, `/oauth2/*` included** (C162-05) | `oidc/OidcOperations.java:267-301`; `rest/AuthInterceptor.java:150-156`; `DeviceGrantClientAuthTest.java:93-128` |
| 6 | (n)–(w) manifest | `NetworkSpec(List<PolicySpec> …)`, more than one policy refused in validation; an unknown enum from the read refused at apply (C162-07) | `ManagementManifest.java:424`; `ManifestValidation.java:105-110`; `ManifestApi.java:1000-1012` |
| 7 | §36.8, `reason_code` | five groups; `ConflictError.reasonCode()` | `errors/ConflictError.java:68` |
| 8 | (j), README | `pom.xml`, BOM, Spring example `1.1.0`; fold; SemVer; conformance 1.62 — §36 not named (C162-12) | `README.md:27`, `:86-88` |
| 9 | Other | SCIM read-modify-write renders the typed `updatedAt` again (instant-preserving) (C162-10) | `ReplacementBodies.java:169-170` |

**Findings:** C162-05, C162-07, C162-10, C162-11, C162-12.

---

### Report — php — commit 7a238fa (PR #83)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical; re-vendor required | — |
| 2 | (l) surface | `NetworkApi` twelve | `src/Management/NetworkApi.php`; `tests/Contract162/NetworkManagementTest.php` |
| 3 | (e), (h) | `ReadModifyWrite::ssfStream($stream, $changes)` — the model form — meets (e): as read, `[]` as `[]`, cut only without a named `events_requested`; **W7.1's Q10 is answered by this reading** — except that an unseen event-type URI goes out as `""` (C162-03) | `src/Management/ReadModifyWrite.php:111-143`; `src/Management/SsfApi.php` |
| 4 | (f), (g), (i) | `?string`, omitted when `null`; strings | `tests/Contract162/RequestMembersAndSsfFormTest.php` |
| 5 | (m), (t) | secret in the body at both; the auth middleware never attaches a bearer to `/oauth2/*` | `src/Oidc/OidcClient.php:741`; `src/Rest/AuthMiddleware.php:104-116`; `tests/Contract162/DeviceGrantAuthenticationTest.php` |
| 6 | (n)–(w) manifest | `NetworkReconciler`; an unknown enum refused at apply (`ManifestException`) (C162-07); a hand-built segment whose `kind` is neither value refused (`7a238fa`) | `src/Management/Manifest/NetworkReconciler.php:247-266`; `tests/Contract162/NetworkManifestTest.php` |
| 7 | §36.8, `reason_code` | five groups; `ConflictError::reasonCode()`; `ManagementErrorMapper` now appends the server's `message` to every management `403`/`409` exception message (not parsed: conforms) | `src/Management/ConflictError.php:28-45`; `ManagementErrorMapper.php` |
| 8 | (j), README | no version file (composer); fold; SemVer; conformance 1.62 naming §36 | `README.md:33-36`, `:220` |
| 9 | Other | every other open enum's `Unknown` case has wire value `''` and is re-sent so, leaving the refusal to the server (C162-04) | e.g. `Models/RadiusTerminationAction.php` |

**Findings:** **C162-03 (Medium)**, C162-04, C162-07, C162-11.

---

### Report — kotlin — commit 07855aa (PR #76)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical; re-vendor required | — |
| 2 | (l) surface | `client.network` twelve; required query params now required arguments | `management/NetworkApi.kt` |
| 3 | (e), (h) | `SsfStream.toInput(SsfStreamChanges)` with `JsonNullable` for the optional members; `SsfApi` call-site text | `ReplacementBodies.kt:134-237`; `SsfApi.kt` |
| 4 | (f), (g), (i) | `SsfStream.updatedAtRaw`, filled by the client's decode for single reads and list items alike; request `userId: String?` (breaking, recorded) | `models/SsfStream.kt`; `ManagementSupport.kt:151-161`, `:180-194`; `ReplacementBodies.kt:124` |
| 5 | (m), (t) | device ops posted `withoutSession` (no bearer, no cookie); secret in the body | `oidc/OidcSupport.kt:1008`, `:1060`, `:1863-1873` |
| 6 | (n)–(w) manifest | `ManagementManifest.NetworkSpec`; `UNKNOWN` refused at serialization (C162-07) | `ManifestApi.kt:548`, `:1097`; `models/RadiusTerminationAction.kt` |
| 7 | §36.8, `reason_code` | five groups; `ConflictError.reasonCode` | `errors/ManagementErrors.kt:58` |
| 8 | (j), README | `gradle.properties` `1.1.0`; fold; SemVer; conformance 1.62 — §36 not named (C162-12) | `README.md:21-34` |
| 9 | Other | `privacy.cancelDelete(token: String)` was `String?` (C162-15); SCIM read-modify-write sends the typed `Instant` rendered again (C162-10); other `/oauth2/*` calls still carry the cached session token (C162-05, informational part) | `PrivacyApi.kt:91`; `ReplacementBodies.kt:263`; `internal/AuthHeaderInterceptor.kt:61-64` |

**Findings:** C162-05 (informational part), C162-07, C162-10, C162-11, C162-12, C162-15.

---

### Report — csharp — commit f70d039 (PR #106)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical; re-vendor required | — |
| 2 | (l) surface | `client.Network` twelve | `Management/NetworkApi.cs`; `AxiamClient.Management.cs:367-371` |
| 3 | (e), (h) | `stream.ToInput(SsfStreamChanges)` | `Management/ManagementChecks.cs:181`; `SsfStreamChanges.cs` |
| 4 | (f), (g), (i) | `UpdatedAtAsRead` (held since 1.61); request `UserId` `string?` (breaking, recorded) | `Models/CreateCertificateRequest.cs:76` |
| 5 | (m), (t) | secret in the body at both; refresh-guard exemption for `/oauth2/device_authorization` added (was missing) — **but the message handler adds the session's (or a static device) bearer to every same-origin request, `/oauth2/*` included** (C162-05) | `AxiamClient.OidcDeviceExchangeLogout.cs:134`, `:202`; `Rest/AxiamHttpMessageHandler.cs:70-91`, `:394-399` |
| 6 | (n)–(w) manifest | an unknown `termination_action`/`service_type` from the read is **left out** of the replacement, so the server's default is written in its place (C162-06) | `Management/ManifestApi.cs:1155-1170` |
| 7 | §36.8, `reason_code` | `ConflictError.ReasonCode` | `Management/ManagementErrors.cs:89` |
| 8 | (j), README | both `.csproj` `1.1.0`; fold; SemVer; conformance 1.62 | `README.md:21-27` |
| 9 | Other | `privacy.CancelDeleteAsync(string? token = null)` keeps a required parameter optional (C162-15) | `Management/PrivacyApi.cs:135` |

**Findings:** C162-05, C162-06, C162-11, C162-15.

---

### Report — c — commit 18be8e1 (PR #73)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical (no `proto/`); re-vendor required | — |
| 2 | (l) surface | flat `axiam_network_*` twelve | `include/axiam/management_ops.h`; `src/management_ops.c`; `tests/test_contract_162_network.c` |
| 3 | (e), (h) | `axiam_mgmt_ssf_stream_apply_changes(stream, changes)` (`NULL` changes = plain converter); call-site text | `include/axiam/management_helpers.h:106-127`; `src/management_helpers.c:109-164`; `management_ops.h:2979-2990` |
| 4 | (f), (g), (i) | `char *`, `NULL` omitted; strings | — |
| 5 | (m), (t) | secret in the body at both; `oidc_post` sends only tenant, accept and content-type headers | `src/oidc_device.c:71-90`; `src/oidc.c:415-465`; `tests/test_device_grant_client_auth.c` |
| 6 | (n)–(w) manifest | three-state `axiam_mgmt_field_state_t` (conforms); an unknown enum from the read is left out of the body (C162-06) | `include/axiam/management_manifest.h`; `src/management_manifest.c:1290-1300` |
| 7 | §36.8, `reason_code` | `axiam_error_t.reason_code`, `action`, `resource_id` | `include/axiam/error.h:63-85` |
| 8 | (j), README | CMake, CPack, conan, vcpkg `1.1.0`; fold; SemVer sentence; conformance 1.62 — §36 not named (C162-12) | `README.md:16-34` |
| 9 | Other | **`SOVERSION` stays 1 while four caller-allocated structs grew** (C162-01); the SCIM converter carries no `expected_updated_at` (C162-09) | `CMakeLists.txt:134`; `CHANGELOG.md:23-31`; `src/management_helpers.c:167-173` |

**Findings:** **C162-01 (Medium)**, C162-06, C162-09, C162-11, C162-12.

---

### Report — cplusplus — commit d3670ed (PR #75)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical (no `proto/`); re-vendor required | — |
| 2 | (l) surface | `NetworkApi` twelve; `list_segments(page, site)` | `include/axiam/management.hpp:2271`; `tests/test_network.cpp` |
| 3 | (e), (h) | `SsfStream::to_input(const SsfStreamChanges&)` | `include/axiam/management_models.hpp:4915`, `:5513`; `src/management_helpers.cpp` |
| 4 | (f), (g), (i) | `std::optional<std::string>`; strings | — |
| 5 | (m), (t) | `add_client_auth` at both; the request is built by hand with no session header | `src/oidc.cpp:1575-1600`, `:1640` |
| 6 | (n)–(w) manifest | `termination_action` is `std::optional` with no "none" (converges); unknown enum re-sent from the read (C162-07) | `include/axiam/management_manifest.hpp:162-167`; `src/management_manifest.cpp:238` |
| 7 | §36.8, `reason_code` | `ConflictError::reason_code()` | `include/axiam/management.hpp:127-128` |
| 8 | (j), README | CMake, conan, vcpkg, `kVersion` `1.1.0`; fold; SemVer; conformance 1.62 naming §36 | `include/axiam/axiam.hpp:55`; `README.md:15`, `:75-76` |
| 9 | Other | **`SOVERSION` stays 1 while `ApplyReport`, `PlannedChange`, `ManifestEntity`, `ConflictError` and the models grew; the change log names only a `-Wswitch` warning** (C162-02); no auto-pager, and `PageRequest::next()` does not carry `site` (C162-16) | `CMakeLists.txt:109-113`; `include/axiam/management_manifest.hpp:180`, `:233`, `:287`; `CHANGELOG.md:14-24`; `README.md:2084` |

**Findings:** **C162-02 (Medium)**, C162-07, C162-11, C162-16.

---

### Report — swift — commit 4d34370 (PR #74)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Vendoring | identical; re-vendor required | — |
| 2 | (l) surface | `client.network` twelve | `Generated/ManagementNamespaces.swift`; `Tests/AxiamSDKTests/NetworkManagementTests.swift` |
| 3 | (e), (h) | `SsfStreamInput.changing(stream) { … }`: a closure edits the copy; `eventsRequested` left equal to the read is treated as unnamed and cut (C162-17) | `Sources/AxiamSDK/Management/ManagementChecks.swift:227-276` |
| 4 | (f), (g), (i) | optionals, `encodeIfPresent`; strings | — |
| 5 | (m), (t) | secret in the body; `oidcFormPost` sends only the listed headers; `invalid_client` is an `AuthError` carrying `oauthError` (Swift's §2 shape of `OAuthProtocolError`) | `Oidc/DeviceGrant.swift:57-80`; `Oidc/OidcInternals.swift:180-195` |
| 6 | (n)–(w) manifest | `.unknown` refused at `plan` (the strictest of the eleven) | `ManagementManifestNetwork.swift:94`, `:383-386` |
| 7 | §36.8, `reason_code` | `AuthzError.reasonCode` | `Sources/AxiamSDK/Errors.swift:106-121` |
| 8 | (j), README | podspec `1.1.0`; fold; SemVer; conformance 1.62 — §36 not named (C162-12) | `README.md:15`, `:112` |
| 9 | Other | compiled only by CI | — |

**Findings:** C162-11, C162-12, C162-17.

## 4. Findings index

| ID | Severity | SDK | `path:line` | What | Disposition |
|---|---|---|---|---|---|
| C162-01 | **Medium** | c | `CMakeLists.txt:134`; `include/axiam/error.h:63-85`; `src/error.c:29-31`, `:45-49`; `include/axiam/management_manifest.h` (three structs); `CHANGELOG.md:23-31` | `axiam_error_t` (+176 bytes), `axiam_mgmt_manifest_t`, `axiam_mgmt_plan_t` and `axiam_mgmt_apply_report_t` grew in a minor release while the shared library keeps `SOVERSION 1`. The caller allocates them; the SDK writes the new members (`axiam_error_reset` on entry to nearly every call). A binary built against 1.0.0 that loads the 1.1.0 `libaxiam.so.1` — a routine package upgrade — gets out-of-bounds stack writes. The change log's "not supported" is not enforced by anything. | **fix in PR #73** (§6) |
| C162-02 | **Medium** | cplusplus | `CMakeLists.txt:109-113`; `include/axiam/management_manifest.hpp:180`, `:233`, `:287`; `include/axiam/management.hpp:127`; `CHANGELOG.md:14-24` | Same as C162-01 for the C++ library: value types returned or filled by the library grew, `SOVERSION` stays 1, and the change log does not say a rebuild is required | **fix in PR #75** (§6) |
| C162-03 | **Medium** | php | `src/Management/Models/SsfEventType.php:49-60`; `SsfStream.php:82-84`, `:116-118`; `SsfStreamInput.php:79`, `:85`, `:106`, `:121`; `ReadModifyWrite.php:111-143` | An event-type URI the SDK has never seen decodes to `SsfEventType::Unknown` (wire value `''`) and is sent back as `""` by `toArray`, by the plain converter and by the change-taking form. §34.2 P12.2(b) (since 1.60) requires it to decode with its value and go back unchanged; P12.2(a) forbids `""`. The R-22 row of §34.3 never listed PHP. A stream holding such a URI cannot be edited from PHP | **fix in PR #83** (§6) |
| C162-04 | Low | php | every generated open enum (`case Unknown = ''`), e.g. `Models/RadiusTerminationAction.php` | A read-back unknown value of any other open enum is re-sent as `""` and refused by the server, where P12.2(a) asks for a local `ValidationError` before the request (the manifest path already refuses locally) | file on `1.1.x` |
| C162-05 | Low | typescript, python, java, csharp (kotlin: other `/oauth2/*` only) | TS `src/rest/interceptors.ts:175-191`; Py `src/axiam_sdk/_client.py:941-982`; Java `rest/AuthInterceptor.java:150-156`; C# `Rest/AxiamHttpMessageHandler.cs:394-399`; Kotlin `internal/AuthHeaderInterceptor.kt:61-64` | A session or adopted credential is sent as `Authorization: Bearer` to `/oauth2/device_authorization` and `/oauth2/token`: TypeScript and Python after `authenticate_device`, Java and C# whenever a session exists (C# also its static device token). §14.6 (1.62) says no `Authorization` header at either device endpoint; the server ignores a non-Basic header, so nothing fails, but an access token goes where §12.1 rule 3's reasoning says credentials should not. Go and PHP exclude every `/oauth2/*` path; Kotlin excludes the device operations; Rust, C, C++ and Swift build those requests without session headers | file on `1.1.x`; scope by Q1 |
| C162-06 | Low | csharp, c | C# `Management/ManifestApi.cs:1155-1170`; C `src/management_manifest.c:1290-1300` | A manifest `Update` of a profile whose read `termination_action` or `service_type` is unknown leaves the member out of the replacement, so the server writes its default (`radius_request`, or no service type) over a value nobody stated — silent drift. Non-conformant whatever Q2's answer | file on `1.1.x` |
| C162-07 | Informational | rust, typescript, python, go, cplusplus (re-send); java, kotlin, php (refuse at apply); swift (refuse at plan) | Rust `manifest/network.rs:656`; TS `manifest/engine.ts:1286`; Py `_engine.py:916-922`; Go `management_manifest_network.go:492`; C++ `src/management_manifest.cpp:238`; Java `ManifestApi.java:1004-1010`; PHP `NetworkReconciler.php:247-266`; Swift `ManagementManifestNetwork.swift:94` | The same case, handled three more ways: §27.6.2 item 4 says carry the read; §36.2 and P12.2(a) say never re-send an unknown value | follows Q2; file on `1.1.x` for the SDKs Q2's answer makes non-conformant |
| C162-08 | Low | python, typescript | Py `manifest/_spec.py:344`, `_engine.py:860-863`, `:918-922`; TS `manifest/spec.ts:248`, `manifest/engine.ts:1262`, `:1286-1287` | `termination_action` stated `null`: Python compares it as drift and omits it, so every `plan` is an `Update` (§27.6 rule 6 fails); TypeScript does not compare it but omits it from any `Update`, writing the server default. Rust, Go, C, C++ and Swift have no "none" for it | follows Q3; file on `1.1.x` |
| C162-09 | Low | c | `src/management_helpers.c:167-173` | `axiam_mgmt_scim_target_response_to_input` converts through JSON and so drops `updated_at`; the body carries no `expected_updated_at` (§31.3 rule 4: the composed form SHOULD send it) | file on `1.1.x` |
| C162-10 | Informational | java, kotlin | Java `ReplacementBodies.java:169-170`; Kotlin `ReplacementBodies.kt:263` | The SCIM read-modify-write renders the typed `updated_at` again (instant-preserving, nanoseconds kept). §34.6 (g) names §32 only, so it conforms | follows Q4 |
| C162-11 | Informational | all eleven | each SDK's manifest network module | No SDK offers pruning in any namespace (true since 1.30), so §27.6.2 item 6 and §27.9's "with it on" assertion have nothing to bind; every SDK documents and tests "nothing is pruned". §27.10's table still says `network` "pending" | follows Q5; contract text |
| C162-12 | Informational | rust, go, java, kotlin, c, swift (csharp states §27 by section list) | each `README.md` conformance sentence | The Conformance Statement has no §36 sentence (W7.1's Q3), so TypeScript, Python, PHP and C++ name §36 and six do not | follows Q6; align in the fix pass if answered |
| C162-13 | Informational | rust | `vendor/axiam-opaque/target/**` on `main` (438 files) | Build artifacts are tracked in the repository (pre-existing, not in the PR) | file on `1.1.x` |
| C162-14 | Informational | contract | `sdks/CONTRACT.md:8111` (§27.2 rule 1); `:8979` (§27.10); §36.10 | §27.2 rule 1 says eighteen namespaces have `list` and seventeen `get`; the registry has nineteen and nineteen. §27.10's `network` row and §36.10 still say "pending"/"none implements §36 yet" | contract text, with Q10 |
| C162-15 | Informational | kotlin, csharp | Kotlin `PrivacyApi.kt:91`; C# `PrivacyApi.cs:135` | `privacy.cancel_delete`'s `token` is required in the registry. Kotlin's generator now makes required query parameters required arguments, narrowing `cancelDelete(String?)` to `String` (recorded as source-breaking; a `null` was always a guaranteed `400`); C# keeps it optional | accepted as is for 1.1.0; file a 2.0.0 note for C# |
| C162-16 | Informational | cplusplus | `README.md:2084`; `include/axiam/management.hpp:2271` | No auto-pager (C++'s §27 posture); `PageRequest::next()` carries `search` and not `site`, so a caller paging `list_segments` repeats `site` by hand (§36.8 test 4 "the auto-pager carrying `site`") | file on `1.1.x` |
| C162-17 | Informational | swift | `ManagementChecks.swift:269` | `changing(_:_:)` treats an `eventsRequested` set to exactly the value read as not named, and cuts it; §32.2 would send it as given (and the server would answer `400`). Benign; documented | file on `1.1.x` (doc) |

**Counts:** Medium 3 · Low 6 · Informational 8. No High. The required re-vendor from `89e488e3e`
applies to all eleven and is not counted.

**Ruled without a finding** (the orchestrator's candidates):

- *"Two policies" unrepresentable* (Rust, Go, C, Swift: an optional single policy) conforms — the
  type is §27.6.2's "a manifest carries at most one"; Java holds a list and refuses more than one.
- *C's three-state optional* (`UNSTATED`/`SET`/`NULL`) is the faithful C form of §27.6.2 item 4.
- *Change-taking form and `null`/`undefined`* (TypeScript): `undefined` is "not a change" and `null`
  on `events_requested` is a deliberate reset (key left out). Rust (`Some(None)`), Java, Kotlin and
  Go's `Nullable` read it the same way; §32.2 lets the caller name an `events_requested` and the
  server judges it, and an absent one resets — the forms are consistent with it.
- *DPoP posture (§21.9)*: see Q10 — the code is right and the contract row is not.

## 5. Questions for the maintainer

Each is a contract question §12 and §13 do not answer. None was worked around. Q1–Q5 are this
review's; Q6–Q9 are W7.1's open questions (Q3, Q2, Q6, Q8 of its list); W7.1's Q10 ("PHP's form
(e) not checked") is answered by this review: `ReadModifyWrite::ssfStream` meets (e), and its one
defect is C162-03. Q10 here is the §21.9 table.

**Q1 — Does "no `Authorization` header" at the device endpoints (§14.6) bind a session or adopted
credential, and only there?** §6.1 says an adopted device token is "the credential of every request
the client makes"; §12.1 rule 3 forbids `Basic` on `/oauth2/*`; §14.6 (1.62) says no
`Authorization` header at either device operation. Four SDKs send the session's or the adopted
bearer to the device endpoints (C162-05). *Options:* (a) no SDK attaches a session or adopted
credential to any `/oauth2/*` request (what Go and PHP do; §6.1 amended to exclude `/oauth2/*`);
(b) only the two device operations are stripped (what Kotlin does); (c) §14.6 is amended to "no
`Authorization: Basic`", and a bearer is allowed. **Recommendation: (a)** — the token endpoint reads
no bearer, the header is the channel the §12.1 rule 3 rationale names, and Go and PHP show it costs
nothing. Fix in 1.1.x (Low), not before W8.

**Q2 — What does a manifest `Update` do with an open-enum value it read as unknown?** §27.6.2 item 4
says every unstated member is carried from the read; §36.2 says an SDK "never re-sends one it decoded
as unknown"; P12.2(a) says refuse locally with a `ValidationError`. The eleven re-send (5), refuse at
apply (3), refuse at plan (1), or omit (2, C162-06). *Options:* (a) re-send verbatim, as P12.2(b)
does for event types, amending §36.2; (b) refuse at `plan`, with zero wire calls, unless the
manifest states that member (Swift); (c) refuse at the action in `apply`. **Recommendation: (b)** —
it keeps §36.2 and P12.2, and refusing before any write avoids a half-applied manifest; a manifest
that states the member resolves it. Omitting is non-conformant under every option.

**Q3 — Can `termination_action` be stated "none" in a manifest?** §27.6.2's table lists it among
the optional members and item 4 says a stated `null` is "none" and left out; the server then writes
its default, `radius_request`, and reads it back, so a stated `null` either never converges
(Python) or silently means "the default" (TypeScript). *Options:* (a) `termination_action` has no
"none" in a manifest: a stated `null` is refused at `plan` (Rust, Go, C, C++ and Swift cannot express
it); (b) a stated `null` means "the server default" and compares equal to `radius_request`.
**Recommendation: (a).** The same holds for any member with a server default (`dictionary` is
never a manifest member).

**Q4 — Does §34.6 (g) extend to the SCIM read-modify-write (§31.3 rule 4)?** (g) names §32.2 only;
Java and Kotlin render SCIM's typed `updated_at` again, keeping the instant (C162-10), and C sends
none (C162-09). *Options:* (a) yes, in 1.63: every helper that builds an `expected_updated_at` from
a read sends the response's own string; (b) no: an instant-preserving rendering conforms for §31.
**Recommendation: (a), in 1.63**, for one rule across both namespaces; nothing fails today because
the server compares instants.

**Q5 — Is a manifest prune option required?** §27.6 rule 4 makes deletion opt-in; §27.6.2 item 6 and
§27.9's network test describe the opt-in as if it existed; no SDK has one in any namespace
(C162-11). *Options:* (a) state that pruning is a MAY none of the eleven offers, make §27.9's
"with it on" half conditional on offering it, and record §27.10's `network` row as "yes; no
pruning" for all eleven; (b) require a per-namespace prune option. **Recommendation: (a)** — rule 4
is satisfied by never deleting, and a prune option is a feature no consumer has asked for.

**Q6 (W7.1 Q3) — A Conformance Statement sentence for §36.** §30, §31 and §32 each have one ("a §27
namespace, stated by name"); §36 has none, and the READMEs split (C162-12). **Recommendation:** add
"§36 is a §27 namespace, stated by name for the `409` `reason_code` accessor and §36.3's call-site
documentation", and have all eleven name §36 in the fix pass if the text lands before it.

**Q7 (W7.1 Q2) — Should an AMQP producer refuse the reserved `tenants.`/`gdpr.` actions locally?**
§8 (1.62) says the ingestion dead-letters them with no error to the producer and adds nothing an
SDK must implement; none of the seven AMQP SDKs refuses them. *Options:* (a) keep it informative;
(b) a MAY (or SHOULD) local `ValidationError` before publishing, in 1.63. **Recommendation: (b) as a
MAY in 1.63** — a silent dead-letter is the costlier failure, and the check is one prefix compare.

**Q8 (W7.1 Q6) — `strands_profile` within one apply.** §27.6.2 item 5 (W7.1's wording) says the SDK
does not reorder to avoid it, so narrowing an envelope while moving a profile's `filter_id` takes two
applies. **Recommendation: confirm the text as written.** All eleven implement it; reordering would
make `plan`'s order depend on the read and break rule 8's stability argument.

**Q9 (W7.1 Q8) — The policy-first order.** §27.6.2 item 2 derives it from H3 (a profile is checked
against the cap at write). Raising the cap and a profile in one manifest needs the policy first;
lowering both works in that order too (the profile is written at or below the new cap), and lowering
the cap below a stated profile is refused `403`, which is the manifest's own inconsistency.
**Recommendation: confirm the text.**

**Q10 — §21.9's DPoP table.** It says Rust, TypeScript, Python, Go, Java, Kotlin and C# generate
proofs. None does: every SDK has a verifier only (no `dpop+jwt` signer in any non-test source), and
the Rust, TypeScript, Python, Go, Java, Kotlin and C# READMEs and device-grant docs say "generates no
DPoP proof". The executors' question (Go, Kotlin) is therefore broader: **the contract rows are wrong,
not the SDKs.** *Options:* (a) correct the seven rows to "no — see its README" in 1.62 now, together
with C162-14's §27.2/§27.10/§36.10 text and whatever Q1–Q9 settle (one W7.1c commit, re-vendored
by the fix pass in place of `89e488e3e`'s `CONTRACT.md`); (b) correct them in 1.63. §14.2 rule 8's
proof sentence and §14.6's "for an SDK that generates DPoP proofs" are then vacuous for all eleven,
which is honest. **Recommendation: (a)**, since all eleven re-vendor anyway; the release should not
ship a posture table that is false in seven rows.

## 6. Fix-pass work list (before W8)

**Every SDK (all eleven):**

1. Re-vendor `openapi.json` and `management-registry.json` from axiam **`89e488e3e`** (the two
   JSON files only; `CONTRACT.md` and `proto/` are unchanged — unless Q10 (a) lands a W7.1c commit
   first, in which case re-vendor all four from that commit). Check: `cmp` against the commit;
   `info.version` and `spec_version` `1.1.0`; digest
   `sha256:cf0fc71c2061576b077afd48d9903f9f4ef26d66e9edbebe5e3020be89fc59a7` in both.
2. Run the SDK's generator `--check` (expected clean: no generated file embeds the version or the
   digest) and the suite.
3. Update the "re-vendored from `d76c5a80b`" sentences in `CHANGELOG.md` `[1.1.0]` and the README
   to name the new commit.
4. If Q6 is answered before the pass: name §36 in the conformance sentence (Rust, Go, Java,
   Kotlin, C#, C, Swift).

**C — PR #73 — C162-01 (Medium).**
- `CMakeLists.txt`: decouple the shared library's ABI version from the package version —
  `set(AXIAM_SOVERSION 2)` (with a comment: the ABI version, bumped whenever a caller-allocated
  public struct changes size) and `SOVERSION ${AXIAM_SOVERSION}` on the `axiam` target in place of
  `${PROJECT_VERSION_MAJOR}`. `VERSION` stays `${PROJECT_VERSION}` (1.1.0), so the file is
  `libaxiam.so.1.1.0` with SONAME `libaxiam.so.2`.
- `CHANGELOG.md` `[1.1.0]` "Breaking changes", first bullet: replace "the shared library's `SOVERSION`
  stays 1; … not supported" with "the shared library's ABI version is now **2** (`libaxiam.so.2`):
  a binary built against 1.0.x keeps loading `libaxiam.so.1` and must be rebuilt to use 1.1.0; the
  loader refuses the mismatch instead of running it".
- `README.md` stability paragraph: a struct that grows bumps the shared library's `SOVERSION`
  (the ABI version), which moves independently of the package's SemVer.
- Test: `tests/CMakeLists.txt`, under `if(AXIAM_BUILD_SHARED AND UNIX AND NOT APPLE)`, an
  `add_test(NAME abi_soname …)` that runs `readelf -d $<TARGET_FILE:axiam>` and passes only when the
  `SONAME` is `libaxiam.so.2` (fails on the commit read).

**C++ — PR #75 — C162-02 (Medium).**
- `CMakeLists.txt:109-113`: the same decoupling, `SOVERSION 2` on `axiam_cpp`.
- `CHANGELOG.md` `[1.1.0]`: a "Binary compatibility" bullet naming the types that grew
  (`ApplyReport`, `PlannedChange`, `ManifestEntity`, `ConflictError`, the 1.61 and 1.62 model
  members) and the new SONAME; `README.md` the same sentence as C's.
- Test: the same `readelf` SONAME check when the library is built shared
  (`BUILD_SHARED_LIBS=ON`), in `tests/CMakeLists.txt`.

**PHP — PR #83 — C162-03 (Medium).**
- `scripts/gen_management.py`: emit the event-type members of `SsfStream` and `SsfStreamInput`
  (`events_allowed`, `events_requested`, `events_delivered`) as `list<SsfEventType|string>`: decode
  a known URI to its case and an unseen one to **its string** (not `Unknown`); `toArray` writes
  `$v instanceof SsfEventType ? $v->value : $v`. This widens a type, which the README's SemVer
  sentence allows in a minor release; record it in `CHANGELOG.md` `[1.1.0]` and say that §34.2
  P12.2(b) is now met. `SsfEventType::Unknown` stays for compatibility and is never produced by
  these models. Regenerate; `--check` clean.
- `ReadModifyWrite::ssfStream` needs no logic change (its ceiling compare already maps an enum to its
  value); confirm the cut keeps an unseen URI that is in the new ceiling.
- Tests (in `tests/Contract162/RequestMembersAndSsfFormTest.php` or a new
  `SsfUnseenEventTypeTest.php`): a read whose `events_requested` and `events_allowed` hold
  `https://example.test/secevent/new-event` (1) decodes with that string; (2) `ReadModifyWrite::
  ssfStream($stream)` and `ssfStream($stream, ['description' => 'x'])` encode it back byte for byte;
  (3) through `SsfApi::updateStream` the wire body carries it, never `""`; (4) a lowered ceiling that
  still holds it keeps it after the cut, one that does not drops it. Each fails on `7a238fa`.

**No other SDK has a Medium-or-higher item.** The Low and Informational findings go to the `1.1.x`
milestone with the issue text below.

### Issue texts for `1.1.x` (the orchestrator files them)

- **C162-04 (php, Low)** — *Open enums re-send an unknown value as `""`.* Every generated open enum
  maps an unknown value to `Unknown` with wire value `''`, and a request built from a read sends it
  so, leaving the refusal to the server. CONTRACT §34.2 P12.2(a) (1.60) asks for a local
  `ValidationError` before the request, never `""`. Fix in the generator's `toArray`/encode path;
  test each request model with an `Unknown` member raising `ValidationError` with zero requests.
- **C162-05 (typescript, python, java, csharp; kotlin partial; Low)** — *A session or adopted bearer
  is sent to `/oauth2/*`.* (Per-SDK paths in the review's §4.) After a login (Java, C#) or
  `authenticate_device` (TypeScript, Python, C#), `device_authorize` and `device_poll` carry
  `Authorization: Bearer <access token>`; CONTRACT §14.6 says no `Authorization` header at either.
  Apply the answer to Q1 (recommended: never attach a session/adopted credential to `/oauth2/*`, as
  the Go and PHP SDKs do). Test: adopt a credential, then run both device operations and assert no
  `Authorization` header.
- **C162-06 (csharp, c, Low)** — *A manifest Update omits an unknown `termination_action` /
  `service_type`, writing the server default.* `ManifestApi.cs:1155-1170` / `management_manifest.c:
  1290-1300`. Replace with the behaviour Q2 settles (recommended: refuse at `plan`, zero wire calls,
  unless stated). Test: read a profile with `termination_action: "future"`, state another member,
  assert the refusal and no `PUT`.
- **C162-07 (rust, typescript, python, go, cplusplus, java, kotlin, php; Informational)** — align
  with Q2's answer; test as C162-06.
- **C162-08 (python, typescript, Low)** — *A stated `null` `termination_action` in a manifest.*
  Python never converges; TypeScript writes the default on an unrelated Update. Apply Q3
  (recommended: refuse at `plan`). Test: state `None`/`null`, assert the refusal with zero requests.
- **C162-09 (c, Low)** — *`axiam_mgmt_scim_target_response_to_input` drops `updated_at`.* Set the
  body's `expected_updated_at` to the response's `updated_at` string (§31.3 rule 4's SHOULD). Test:
  the converted body carries the read's string byte for byte.
- **C162-10 (java, kotlin, Informational)** — after Q4: keep the SCIM response's own `updated_at`
  string (`updatedAtRaw`) and send it from the read-modify-write, as for SSF.
- **C162-11 (all, Informational)** — after Q5: README line "manifest pruning: not offered in any
  namespace" where missing; contract text by the release.
- **C162-12 (rust, go, java, kotlin, c, swift, Informational)** — after Q6: name §36 in the
  conformance sentence.
- **C162-13 (rust, Informational)** — *438 build artifacts tracked under
  `vendor/axiam-opaque/target/`.* Remove them from the index and add the path to `.gitignore`.
- **C162-15 (csharp, Informational)** — `CancelDeleteAsync(string? token = null)`: the registry's
  `token` is required; make it a required argument at 2.0.0 (Kotlin did it in 1.1.0 and recorded it).
- **C162-16 (cplusplus, Informational)** — carry `site` across `list_segments` pages (a
  `NetworkSegmentPageRequest` or a `site` member the next request keeps), or an auto-pager.
- **C162-17 (swift, Informational)** — document in `changing(_:_:)` that setting `eventsRequested`
  to the value read is treated as not naming it.

**Contract text (for the release, with Q10):** §21.9's seven rows; §27.2 rule 1's counts (nineteen
and nineteen); §27.10's `network` row and §36.10's posture (all eleven implement §36 and §27.6.2,
none prunes); and whatever Q1–Q9 settle.
