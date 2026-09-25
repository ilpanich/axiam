# CONTRACT 1.51 ports — cross-SDK conformance review (C-12)

**Date:** 2026-09-24
**Scope:** the eleven contract 1.51 ports (plan C-1 … C-11), read from each SDK
repository's merged `main`. The review covered:

- the acting-tenant helper (§5.2 rule 1);
- the device login (§6.1 rules 6–10);
- rule 9 of §10.1;
- `validate_token` / `introspect_token` (§1.1.1);
- the decision memo (§17);
- the 1.51 DTOs (§27.13);
- the manifest additions (§27.6.1).

**Outcome:** the contract is amended to **1.52**, a set of clarifications with no wire
change, written as six rules N1 … N6. Thirty-seven divergences are recorded in
`CONTRACT.md` §27.14, **none open**. One fix PR per SDK, eleven in all, is held until
the axiam PR carrying 1.52 merges. Each one then re-vendors `CONTRACT.md` from that
merge commit.

Every cell below was determined by reading the shipped source, not a PR description or
a port's self-report. Where they disagreed, the code won and the disagreement is
recorded (§5). Every path is relative to the SDK's repository root, and every line
number is on the `main` commit listed here.

| Repo | `main` read | 1.51 port | Earlier fixes |
|---|---|---|---|
| `axiam-rust-sdk` (reference) | `8e9eb90` | [#115](https://github.com/ilpanich/axiam-rust-sdk/pull/115) | — |
| `axiam-typescript-sdk` | `39c794f` | [#116](https://github.com/ilpanich/axiam-typescript-sdk/pull/116) | [#117](https://github.com/ilpanich/axiam-typescript-sdk/pull/117) (SSO gate), [#118](https://github.com/ilpanich/axiam-typescript-sdk/pull/118) (rule 9) |
| `axiam-python-sdk` | `8156a84` | [#88](https://github.com/ilpanich/axiam-python-sdk/pull/88) | [#89](https://github.com/ilpanich/axiam-python-sdk/pull/89) (device POST, restore outcome) |
| `axiam-java-sdk` | `fa6803a` | [#102](https://github.com/ilpanich/axiam-java-sdk/pull/102) | — |
| `axiam-kotlin-sdk` | `fbf98c5` | [#68](https://github.com/ilpanich/axiam-kotlin-sdk/pull/68) | — |
| `axiam-csharp-sdk` | `af77b52` | [#95](https://github.com/ilpanich/axiam-csharp-sdk/pull/95) | [#96](https://github.com/ilpanich/axiam-csharp-sdk/pull/96) (device POST, WebAuthn header) |
| `axiam-php-sdk` | `33c8095` | [#73](https://github.com/ilpanich/axiam-php-sdk/pull/73) | [#74](https://github.com/ilpanich/axiam-php-sdk/pull/74) (a refused device login kept the session; bearer and CSRF withheld) |
| `axiam-go-sdk` | `d5658ea` | [#86](https://github.com/ilpanich/axiam-go-sdk/pull/86) | [#87](https://github.com/ilpanich/axiam-go-sdk/pull/87) (SSO gate) |
| `axiam-swift-sdk` | `db24d26` | [#66](https://github.com/ilpanich/axiam-swift-sdk/pull/66) | — |
| `axiam-c-sdk` | `0b87547` | [#65](https://github.com/ilpanich/axiam-c-sdk/pull/65) | — |
| `axiam-cplusplus-sdk` | `b650258` | [#66](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/66) | [#67](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/67) (`inherit` decoding, restore outcome, device body) |

All eleven vendored the same `CONTRACT.md` 1.51 (sha256 `0ac7fd75f83c…`) from axiam
`56fbe44`.

The review has three parts:

1. The seven questions the 1.51 ports left open, answered per SDK (§1).
2. A code probe of each rule's edges: which requests carry the header, what a refused
   device login changes, and which verifiers read `cnf` (§2).
3. Every README and CHANGELOG sentence about 1.51, read against the code (§3).

Each defect became a fix with a test that fails on `main` and passes on the fix branch
(§4). Each divergence that no SDK had wrong became a rule in 1.52.

## 1. The seven questions, answered by SDK

The answers come from each SDK's merged `main` (read-only, with a file:line for every
cell), not from the ports' reports. Several reports mislabelled their own choice as
Rust's or the reverse, and the code settles it. **Bold** marks a cell that is a defect
against the contract or the reference, not just a different choice; each one is listed
below the table.

| Question | Rust | TypeScript | Python | Java | C# | PHP | Go | Kotlin | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **1. §10.1 rule 9 at the default entry point** | `verify` refuses; the actix guard calls `verify_with_proofs` with the peer certificate | `authenticateRequest` (every guard) refuses; **`Verifier.verifyAccessToken`, which its own doc names as the guard entry, does not** | `verify_access_token` refuses; `verify_with_proofs` takes evidence | `verifyAccessToken` refuses; the Spring filter calls `verifySenderConstrained` | `VerifyAsync` refuses; the middleware calls `VerifyWithProofsAsync` | `verify` / `verifyLocally` refuse; `verifyWithProofs` takes evidence | `VerifyAccessToken` refuses; the middleware passes `r.TLS` evidence | `verifySession` (proofs default to none) refuses | `authenticate` (`.none`) refuses | `axiam_jwt_verify_ex` refuses; `…_with_evidence` takes it | `TokenAuthenticator::authenticate` refuses; `authenticate_sender_constrained` takes it |
| **2. §17 memo key and acting tenant** | fifth component | fifth component | fifth component | fifth component | fifth component | fifth component | fifth component | fifth component | fifth component | fifth parameter | fifth component |
| **3. Generated DTOs**: `SubjectAltName`; absent role-side `inherit` | serde enum; `default_true` | tagged union; `roleAssignmentInherits()` | two classes; `= True` | sealed type with a serializer; `inherits()` | converter; `= true` | `toArray()`; absent means true | struct of two optional fields (tagging by convention); `Inherits()` | sealed type with a `KSerializer`; `= true` | enum with a custom `encode`; `inherits` | build function; absent means 1 | struct of two optionals (by convention); **an absent `inherit` fails the whole listing** |
| **4. Device token beside a cookie jar** | withheld: empty `Cookie` on the login and after | withheld: jar-free agent, empty `Cookie` | jar **cleared** on adoption; **the device POST itself carries the jar** | withheld: a load-suppressed jar | a new jar-free handle, and the original's session is kept; **the device POST itself carries the jar** | jar **cleared before** the POST, so a failed device login loses the session | withheld: a no-outbound jar wrapper | withheld: a strip-cookie marker | withheld: empty `Cookie` | withheld: jar snapshotted, cleared and restored per request | withheld: `no_stored_cookies`; **sends body `{}`** |
| **5. Who holds a login result** (record / reset / a 200 with no user object) | login, `verify_mfa` / OPAQUE, MFA setup, WebAuthn setup and authentication, the three SSO completions, device, logout / decode fails | adds OPAQUE, MFA setup, WebAuthn setup / WebAuthn auth, SSO ×3 (#117), device, logout / not handled | as TS / as TS / records `false` | as TS / as TS, **plus refresh** / records `false` | as TS / as TS, **plus refresh, and before the request**; device returns a new handle / unknown | as TS / as TS / throws, gate unchanged | as TS / as TS (SSO via #87) / records `false` | as TS / as TS / records `false` | as TS / as TS / decode fails | as TS / as TS / unknown | as TS / as TS / unknown |
| **6. Global role with `inherit: false`** | refused client-side | refused | refused | refused | refused | refused | refused (checked only with a resource) | refused | refused (checked only with a resource) | refused | refused |
| **7. Update of a binding is two calls** (all: unassign, assign carrying `tenant_scope`, restore on failure) | `BindingUpdateFailed { error, restore }` | `rebind-failed`, `restoreSucceeded` | **the restore outcome is only in the message string** | `StepOutcome.restored` | `RestoreSucceeded` | `BindingRebindFailed(restored, restoreError)` | two `AppliedStep`s (`StatusRestored` / `StatusRestoreFailed`) | `BINDING_UPDATE_FAILED`, `restoreSucceeded` | `BindingOutcome.restored` | `restore_attempted` / `restore_succeeded` | **the restore outcome is swallowed and not reported** |

Question 6 checks only a role the manifest declares global; a global role it does
not declare goes to the server, which answers `400`, in all eleven.

**Defects found first.** None failed a test, because none had one. All six were fixed and
merged before the rules were written, in the five "earlier fixes" PRs listed in the
table at the top.

1. **TypeScript, §10.1 rule 9 (security).** `Verifier.verifyAccessToken`
   (`src/node/jwks.ts`) never reads `cnf`. Its doc says anything guarding a route MUST
   use it, so a guard written by the doc accepts a device token lifted off a device.
   The shipped middleware is safe, because it goes through `authenticateRequest`.
   This is C-1's defect one layer down, and question 1 exists for exactly this.
2. **C++, §27.13 S-10 rule 3.** `from_json` for the three role-side assignments reads
   `j.at("inherit")` (`src/management_models.cpp`), so a listing from a pre-1.51
   server fails whole, as a `NetworkError`. The worker's accessor fix covered only
   the subject-side `RoleAssignment`.
3. **C++, §27.6.1 "report both outcomes".** `reconcile_role_bindings`
   (`src/management_manifest.cpp`) swallows the restore's result, and `ApplyReport`
   has no field for it.
4. **C++, §6.1 rule 6 "no request body".** `authenticate_device()` sends `{}`
   (`src/client.cpp`).
5. **Python, §27.6.1 "report both outcomes", weakly.** The restore outcome reaches
   the caller only inside `StepOutcome.message`.
6. **Python and C#, question 4.** The device POST goes out with the prior session's
   cookies, and in C# with a bearer read from the jar. The reference withholds them
   on that call. The contract is silent, which is question 4's own candidate
   amendment. PHP clears the jar before the call, so a refused device login still
   ends the session.

Not defects, but divergences the contract should settle in 1.52:
- **Question 5, the record set.** Ten SDKs record from OPAQUE, MFA setup and WebAuthn
  setup, whose `200` carries the user object (`crates/axiam-api-rest/src/handlers/opaque.rs`
  uses the password builder). Only Rust resets on those paths. The spec leaves the
  OPAQUE `200` body undocumented.
- **Question 5, a 200 with no user object.** It is handled four ways: `false`
  (Python, Java, Kotlin, Go), unknown (C#, C, C++), a failed decode (Rust, Swift) or
  a throw (TS, PHP).
- **Question 5, refresh.** Java and C# reset the gate on refresh, and C# does so
  before the request.
- **Question 3, `SubjectAltName` in Go and C++.** Both are structs whose tagging
  holds only by convention; the constructors are correct.

## 2. Code probes of each rule's edges

I fetched `origin/main` in all 11 repos and read only `origin/main`. Short heads: rust 8e9eb90, typescript 39c794f, python 8156a84, java fa6803a, kotlin fbf98c5, csharp af77b52, php 33c8095, go d5658ea, swift db24d26, c 0b87547, cplusplus b650258. Paths below are relative to each repository's root, and line numbers are on `origin/main`.

### P1. Is `X-Axiam-Tenant` sent when an acting tenant is set?

Columns: login / verify_mfa / refresh / logout / `/oauth2/*` / WebAuthn and self-service / the WebAuthn setup pair / `authenticate_device`.

- **Rust:** NO / NO / yes / yes / NO / yes / NO / NO.
  - `login` and `verify_mfa` build requests with no tenant headers at all: `src/rest/auth.rs:515-518` and `:602-605`. So "Rust withholds it from login/verify_mfa" is **confirmed**. These two calls also omit `X-Tenant-ID`.
  - refresh `auth.rs:688`, logout `:796`.
  - OIDC calls send only `X-Tenant-ID` (e.g. `src/oidc/exchange.rs:613-614`).
  - `webauthn_post` `src/rest/webauthn.rs:566` and `account_post` `src/rest/account.rs:491` send it. `password_reset_context` does not (`account.rs:441-443`), nor does the setup pair (`webauthn.rs:600-604`).
  - Device login sends `X-Tenant-ID` only: `auth.rs:890-894`.
- **TypeScript:** NO (`src/rest/auth.ts:175-178`) / NO (`:235`) / yes on explicit `refresh()` (`:273-275`) but NO on the reactive 401 refresh (`src/rest/interceptors.ts:98`) / yes (`auth.ts:320`) / NO (no `actingTenantHeaders` anywhere in `src/node/oidc.ts`) / yes (`src/rest/webauthn.ts:560-563`, `src/rest/accountLifecycle.ts:374`) / yes (same `post()` helper, `webauthn.ts:209-214`) / NO (`auth.ts:418-427`).
- **Python:** yes on everything except the setup pair.
  - Every call goes through `_rest_send_sync`/`_async` (`src/axiam_sdk/_client.py:904-917`). `_apply_acting_tenant` (`:875-883`) has no path or host filter.
  - login `:1199`, verify_mfa `:1395`, refresh `:1433`, logout `:1448`, oauth2 `:1684`/`:1752`, device `:1183`.
  - The setup pair uses `_credential_free_request`, so NO (`_async_client.py:1359`, `:1400`).
- **Java:** NO / NO / yes / yes / NO / yes / NO / NO.
  - The header is added only when the call site tags the request (`rest/AuthInterceptor.java:121`, `:146-148`).
  - login `AxiamClient.java:1363` and verify `:1448` are untagged. refresh `:1481` goes through `SessionState.java:528-529`; logout `:1512`.
  - WebAuthn is tagged at `:4231/4273/4320/4377/4606`, self-service at `:4717-4809` and `:5066`. The setup pair is not (`:4454`, `:4502`), nor is device (`:3222-3225`).
- **Kotlin:** yes / yes / yes / yes / NO / yes / yes / yes.
  - `postJson` `AxiamClient.kt:2432-2434` covers login `:758`, verify `:828`, logout `:866`. Refresh goes through `internal/SessionState.kt:161-162`.
  - OIDC calls in `oidc/OidcSupport.kt` add no header.
  - Setup pair `:1808`/`:2448-2455`; device `:931`/`:2472-2476`.
- **C#:** yes on everything, including off-origin `/oauth2` endpoints.
  - The header is an `HttpClient.DefaultRequestHeaders` entry (`AxiamClient.cs:301-305`, `:474-477`), so every request through `_httpClient` carries it, with no host guard. That covers login, verify, refresh and logout (`:1339`), oauth2 (`AxiamClient.Oidc.cs:1274`) and WebAuthn (`Webauthn.cs:545`).
  - The setup pair and device add it by hand: `ApplyAnonymousTenantHeaders` `AxiamClient.cs:427-433`, `AxiamClient.Device.cs:105-108`.
- **PHP:** yes on everything same-origin, including `/oauth2/*`.
  - Set in `src/Rest/AuthMiddleware.php:97-100`. The bearer is skipped for `/oauth2` (`:108-113`), but the acting-tenant header is not.
  - Device: `AxiamClient.php:1212-1220`.
- **Go:** yes / yes / yes / yes / yes (same-origin only) / yes / NO / yes.
  - `decorateRequest` `client.go:775-777` via `doRequest`: login `login.go:353`, `:440`, `:507`, `:576`; oauth2 `oidc_wire.go:246`; `webauthn.go:571`; `account.go:405`/`:449`.
  - Setup pair `webauthn.go:617-631` does not add it. Device `device_auth.go:154-156` does.
- **Swift:** yes / yes / yes / yes / NO / yes / yes / yes.
  - `rawSend` `Sources/AxiamSDK/AxiamClient.swift:1089-1091` covers login `:221`, verify `:265`, logout `:285`, refresh `:655`.
  - oauth2 goes through `umaSendAbsolute` `:1144-1156`, which adds no acting-tenant header.
  - Setup pair `:1259-1261`; device `:409-411`.
- **C:** yes / yes / yes / yes / NO / yes / yes / yes.
  - `build_headers` `src/client.c:255-266`: login `:830`, verify `:1193`, refresh `:406`, logout `:1242`; `send_raw` for account and webauthn, including setup (`webauthn.c:792`).
  - `oidc_transport_once` `oidc.c:416-421` adds none. Device `client.c:1373-1374`.
- **C++:** yes / yes / yes / yes / NO / yes / yes / yes.
  - `build_request` `src/client_impl.hpp:251`: login `client.cpp:437`, refresh `client_impl.hpp:528`, verify and logout through `execute` (`client_impl.hpp:470`); `webauthn.cpp:200/239`, `account.cpp:64`.
  - oauth2 is hand-built (`oidc.cpp:569` etc.) and adds none. Device `client.cpp:1030-1033`.

**gRPC metadata:** no SDK sends it. A search for an `x-axiam-tenant` metadata key found only a TypeScript test file (`test/rest/actingTenant.test.ts:87`). Rust documents this at `src/grpc/interceptor.rs:29-30`. Kotlin, Swift, C and C++ ship no gRPC.

### P2. Does the on-client form return a new handle or mutate?

- **Rust:** NEW handle; `self` unchanged (`client.rs:936-963`). The memo lives in the shared `Arc` inner (`:725`), so it is shared.
- **TypeScript:** NEW handle (`src/rest/client.ts:187-206`, `:257-265`). The memo is on the shared session (`session.ts:97`, `client.ts:138`).
- **Python:** NEW handle via `copy.copy` (`_client.py:1129-1141`). The memo is shared because the copy is shallow (`:317`).
  - Unlike every other handle-based SDK, `_principal_scope` (the gate) is a per-handle attribute (`:373`, `:603`, `:1042`). A login or device login on one handle does not update the gate on sibling handles.
- **Java:** NEW handle through the rebind constructor (`AxiamClient.java:718-737`, `:767-797`). Memo shared (`:734`).
- **Kotlin:** NEW handle over the shared `Core` (`AxiamClient.kt:389-417`). Memo shared (`:155`). Gate shared (`:198-200`).
- **C#:** NEW handle (`AxiamClient.cs:367-386`, `:438-485`). The memo is shared (`:481`), which contradicts the method's own remarks (`:339-345`: "its own §17 decision memo").
- **PHP:** MUTATES and returns `$this` (`AxiamClient.php:560-579`). This is documented as deliberate. The state lives in the `Session` object (`Session.php:195`) and there is no `__clone`, so a `clone $client` shares it and IS affected.
- **Go:** NEW `*Client` by struct copy (`client.go:480-500`). The memo is in the shared `clientSession`.
- **Swift:** MUTATES (`AxiamClient.swift:443-472`). `AxiamClient` is an `actor` (`:11`), a reference type, so every reference sees the change.
- **C:** MUTATES (`client.c:1268-1340`). In addition, logout clears the acting tenant (`:1255` calls `reset_acting_tenant_and_gate` at `:707-720`). No other SDK does this.
- **C++:** MUTATES (`client.cpp:857-900`). `Client` holds a `shared_ptr<Impl>` (`include/axiam/client.hpp:1314`) and has no user-declared copy constructor, so copies share `Impl` and ARE affected.

### P3. `authenticate_device` adoption

For each SDK: where the token lands, what later requests carry, and whether a refused device login changes client state.

- **Rust:** SAME object, and all clones share it (`auth.rs:921-934`).
  - Management and authz calls send Bearer plus `Cookie: ""` (`client.rs:1004-1017`, used only at `management/request.rs:231` and `authz.rs:311`). They also send the stale cached `X-CSRF-Token`, which is never cleared (`client.rs:1214`).
  - **Hole:** `account_post` (`account.rs:486-491`), `webauthn_post` (`webauthn.rs:561-566`) and `logout` (`auth.rs:795-797`) send no bearer. The jar is never cleared, so these calls still carry the previous session's cookie.
  - Refused: the memo is cleared before the wire (`auth.rs:886`). Nothing else changes.
- **TypeScript:** SAME session (`auth.ts:428-433`).
  - Later requests carry Bearer, `Cookie: ''` and jar-free agents (`interceptors.ts:160-175`), plus the stale `session.csrfToken` (`:45-60`).
  - Refused: before the wire, the memo is cleared and any previously adopted device token is dropped (`auth.ts:409-414`). `login` and `verifyMfa` also drop the device token before the wire (`:168`, `:232`).
- **Python:** SAME session (`_client.py:1032-1042`, `_session.py:204-226`). Adoption clears the jar and resets the refresh guard.
  - Later requests carry Bearer and `Cookie: ""` (`_client.py:885-902`), plus the stale `_csrf_token` (`_session.py:345-349`).
  - Refused: no state change (`_client.py:1006-1024` raises before adoption).
- **Java:** SAME session (`AxiamClient.java:3238`).
  - Later requests carry Bearer, because `cachedAccessToken` prefers the adopted token (`SessionState.java:317-320`, `AuthInterceptor.java:149-151`). The cookie jar is load-suppressed, so no `Cookie` header is sent (`:170-177`). The stale CSRF token is still sent (`:152-155`).
  - Refused: `onCredentialChange()` runs before the wire (`:3220`, body at `:865-869`). It clears the memo, resets the gate, and drops any previously adopted device token.
  - Separately, the device-login request itself carries `Authorization: Bearer <the prior cookie session's access token>`. The interceptor does not exclude the device path from its bearer branch.
- **Kotlin:** SAME core (`AxiamClient.kt:951-958`).
  - Later requests carry Bearer, the `Cookie` header is stripped, and no CSRF is sent (`internal/AuthHeaderInterceptor.kt:51-62`).
  - Refused: the memo is cleared before the wire (`:927`).
- **C#:** **NEW handle** — confirmed. `AuthenticateDeviceAsync` returns `(AxiamClient Client, DeviceToken Token)` (`AxiamClient.Device.cs:136-140`). The handle is built at `:226-306` with a fresh jar, fresh memo, fresh session (gate unknown) and a static bearer.
  - That handle sets `_actingTenant = null` and adds no default header, so an acting tenant (construction-time or on-client) is **dropped** on the returned handle.
  - Later requests carry the bearer only: no cookie, no CSRF.
  - The original client is untouched, including its memo. Refused: no state change.
- **PHP:** SAME object (`AxiamClient.php:1245-1251`). Adoption clears the memo, resets the gate and clears the jar.
  - Later requests carry Bearer (`Session.php:175-178`, `:252-263`) and no `Cookie` header, because the jar is empty. The stale CSRF token is still sent (`AuthMiddleware.php:125-130`, `Session.php:150`).
  - Refused: no state change.
- **Go:** SAME session (`device_auth.go:119-128`).
  - Later requests carry Bearer (`client.go:790-800`). `noOutboundCookieJar` means no `Cookie` header at all (`:846-853`), although the comment there says "explicit empty Cookie". The stale CSRF token is still sent (`:779-783`).
  - Refused: no state change.
- **Swift:** SAME actor (`AxiamClient.swift:386-392`).
  - Later requests carry Bearer, `Cookie: ""`, and no CSRF (`:1119-1122`).
  - Refused: the memo is cleared before the wire (`:376`).
- **C:** SAME client (`client.c:1476-1496`).
  - Later requests carry Bearer and `Cookie: ""` (`:268-289`), plus the stale CSRF token (`:292-296`).
  - Refused: no state change; the memo is cleared only after success (`:1485`).
- **C++:** SAME `Impl` (`client.cpp:1060-1070`).
  - Later requests carry Bearer with `no_stored_cookies` (`client_impl.hpp:253-262`), plus the stale CSRF token (`:245`).
  - Refused: the memo is cleared before the wire (`client.cpp:1018`).

### P4. §6.1 rule 7: compile-time gate or runtime refusal?

All 11 SDKs refuse at runtime with an auth error and zero wire calls. None uses a distinct type.

- **Rust:** runtime (`auth.rs:879-884`). README says so explicitly (`README.md:83`, `:91-96`).
- **TypeScript:** runtime (`auth.ts:403-408`). README: "typestate Declined" (`README.md:45`).
- **Python:** runtime (`_client.py:1172`, `_reachable_only_with_client_cert` `:974`). README says it raises before any wire call (`README.md:1920-1922`) but does not say "runtime rather than a type".
- **Java:** runtime (`AxiamClient.java:3209-3217`). README says "zero wire calls otherwise" (`README.md:59`), not explicit about the type-system choice.
- **Kotlin:** runtime (`AxiamClient.kt:916-925`). The type-system reasoning is only in a code comment. README (`~:281-284`) describes the refusal, not the choice.
- **C#:** runtime (`AxiamClient.Device.cs:84-95`). README explicit (`README.md:54`).
- **PHP:** runtime (`AxiamClient.php:1202-1209`). README (`README.md:239-240`) not explicit.
- **Go:** runtime (`device_auth.go`). README says "zero wire calls" (`README.md:351-353`), not explicit.
- **Swift:** runtime (`AxiamClient.swift:369-374`). README (`~:340-342`) not explicit.
- **C:** runtime (`client.c:1411-1418`). README explicit "Decline (typestate)" (`README.md:228-240`).
- **C++:** runtime (`client.cpp:1004-1011`). README explicit (`README.md:461-465`).

### P5. `SubjectAltName` serialization

- **Go** (`management_models.go:3053-3058`): a plain struct of two `*string` fields with `omitempty`. There is no `MarshalJSON` and no validation; the only helpers are the constructors (`:3061-3068`).
  - Neither set: `{}`. Both set: `{"dns":"…","ip":"…"}`.
  - The type's own doc (`:3047-3049`) says "never an empty object", but nothing enforces that.
- **C++** (`src/management_models.cpp:1199-1207`): `j = object(); if (dns) j["dns"]=…; if (ip) j["ip"]=…`. No validation.
  - Neither set: `{}`. Both set: `{"dns":"…","ip":"…"}` (nlohmann's default object type is key-sorted).
  - `from_json` (`:1209-1216`) silently accepts both shapes.
  - The header comment (`include/axiam/management_models.hpp:1356-1360`) wrongly calls this a "SPARSE body".
  - An engaged but empty vector emits `"subject_alt_names":[]` (`:1228-1230`), against the SHOULD-omit rule.
- **C** (`include/axiam/management_models.h:5805-5816`): a `kind` plus `value` pair, so "neither" and "both" cannot be expressed.
  - A `NULL` value makes `build` return NULL (`src/management_models.c:8143`), and the element is silently dropped from the array (`:2050-2051`).
  - An out-of-range `kind` silently becomes `"dns"` (`:8150`).
  - A non-NULL array with count 0 emits `[]` (`:2047-2048`).
- **TypeScript** (`src/management/models.ts:3827-3835`): the type is `{dns}|{ip}` with no discriminator. I believe `{}` does not compile but `{dns, ip}` does, because TypeScript's excess-property check on a non-discriminated union accepts keys from any member. `JSON.stringify` would then emit both. There is no runtime check. This is from reading the type; I did not compile it.
- **PHP:** the shipped arms are `final` classes (`SubjectAltNameDns.php:14`), but `SubjectAltNameVariant` is an open interface a caller can implement. I did not trace what the transport does with a foreign implementation.
- **Python:** a union of two model classes, `SubjectAltNameDns | SubjectAltNameIp` (`models.py:4142-4156`). I did not verify how strictly those models validate.
- **Closed sum types** (neither and both unrepresentable): Rust `enum` (`models.rs:4074`), Java `sealed interface` (`SubjectAltName.java:23`), Kotlin `sealed interface` (`SubjectAltName.kt:31`), C# abstract record with a private constructor (`SubjectAltName.cs:28-30`), Swift `enum` (`ManagementModels.swift:867`).

### P6. §10.1 rule 9: every public verifier, guard and helper

Signature-only functions explicitly marked unchecked are excluded.

- **Rust:** all refuse a `cnf` token without evidence.
  - `JwksVerifier::verify` (`token/jwks.rs:830`), `verify_with_proofs` (`:850`), `verify_sender_constrained(None)` (`:936`).
  - The actix `AxiamUser` extractor (`middleware/actix.rs:389-460`) passes the peer certificate as evidence.
  - The macros `require_auth`, `require_access` and `require_role` (`axiam-sdk-macros/src/lib.rs:55`, `:127`, `:287`) all inject `AxiamUser`.
  - gRPC `TokenGrpcClient::validate_token` (`grpc/token.rs:360`) returns `valid:true` for a bound token and does **not** refuse. It leaves that to `status()` and `verify_possession()` (`:173`, `:270`), which is the §10.3 design.
- **TypeScript:** the fixed `verifyAccessToken` now refuses (`node/jwks.ts:499-559`, rule 9 at `:557`). I found no other hole.
  - `authenticateRequest` (`middleware/verifyCore.ts:147-166`) defaults proofs to `{}` and refuses.
  - Express `axiamMiddleware` (`express.ts:86`) and the Fastify plugin (`fastify.ts:121-125`) pass the socket's certificate.
  - `requireAuth`/`requireAccess`/`requireRole` (Express `:159/181/262`, Fastify `:181/193/269`) and NestJS `AxiamGuard` (`nestjs/guard.ts:100-125`) consume the identity those produce.
  - gRPC `validateToken` (`grpc/client.ts:871`) does not refuse; same §10.3 design.
- **Python:** all refuse.
  - `verify_access_token` (`_jwks.py:468-509`), `verify_with_proofs` (`:511`), `verify_sender_constrained(None)` (`:560`).
  - The Django middleware (`django/middleware.py:386`) and FastAPI (`fastapi/__init__.py:281`, `:313`, `:406`) call only `verify_access_token`. They therefore never accept a bound token, even over mTLS.
  - gRPC `verify_possession` lives at `_models.py:726`/`:789`; the validate call itself does not refuse.
- **Java:** all refuse.
  - `verifyAccessToken` (`internal/JwksVerifier.java:378`) and `verifySenderConstrained` (`:579`).
  - The Spring `AxiamAuthenticationFilter` passes the servlet's peer certificate (`:224`).
  - gRPC `validateToken` (`GrpcAuthzClient.java:542`) does not refuse.
  - `verifyForOidc` (`:862`) is public and signature-only, documented for ID tokens; I excluded it, but its name does not say "unchecked".
- **Kotlin:** all refuse.
  - `AxiamClient.verifySession` (`AxiamClient.kt:1406-1422`) defaults proofs to none.
  - ktor `AxiamAuthentication.kt:107` calls `verifySession(token)` with no proofs, so it never accepts a bound token.
  - `JwksVerifier.verifyForIdToken` (`internal/JwksVerifier.kt:152`) is public and signature-only; excluded.
- **C#:** all refuse.
  - `VerifyAsync` (`Auth/JwksVerifier.cs:221-233`) and `VerifyWithProofsAsync` (`:259`).
  - ASP.NET `AxiamAuthMiddleware.cs:224` passes connection proofs.
  - gRPC `ValidateTokenAsync` (`TokenGrpcClient.cs:190`) does not refuse.
- **PHP:** the guard paths refuse.
  - `verifyLocally` (`AxiamClient.php:1956`) goes to `JwksVerifier::verify` (`Auth/JwksVerifier.php:197`). `verifyWithProofs` (`:1977`/`:219`).
  - Laravel `AxiamMiddleware.php:170` and Symfony `AxiamAuthSubscriber.php:183` use `verifyLocally`.
  - `verifyLocallyOrFallback` (`:1998`) refuses the caller's bound token but then returns the client's *own* session claims. It is documented as never for guards.
  - `validateToken` (`:1384`) does not refuse.
  - `verifyIdTokenSignature` (`JwksVerifier.php:585`) is public and signature-only; excluded.
- **Go:** all refuse.
  - `VerifyAccessToken` (`internal/jwks/verifier.go:120`) and `VerifyAccessTokenWithProofs` (`:139`), exposed through the `JWKSVerifier` alias (`jwks.go:28`).
  - `middleware.Middleware` passes `r.TLS` peer certificates (`middleware/nethttp.go:183-191`).
  - gRPC `ValidateToken` (`grpc/token.go:205`) does not refuse.
  - `VerifyPayload` (`verifier.go:276`) is publicly reachable through the alias and is signature-only for ID tokens; excluded, but not named "unchecked".
- **Swift:** all refuse.
  - `authenticate` (`Guard/AxiamRequestAuthenticator.swift:315`) defaults proofs to `.none`; `authenticateSenderConstrained` (`:123`).
  - `requireAuth`/`requireAccess`/`requireRole` (`Guard/AxiamGuards.swift:27`, `:41`, `:121`) always pass no proofs, so they never accept a bound token.
  - `JwksVerifier` is internal.
- **C:** refuses on the default paths.
  - `axiam_jwt_verify` (`src/jwks.c:348-352`); `axiam_jwt_verify_ex` refuses only when flags are non-zero (`:257-263`).
  - With `flags == AXIAM_JWT_VERIFY_SIGNATURE_ONLY` the `cnf` check is skipped. That flag is documented as unsafe, but `jwks.h:113-115` says `_ex` refuses `cnf` unconditionally, so the header comment is inaccurate.
  - The `_with_evidence` variants are at `:364-376`. The guards (`guard.c:50-62`, `require_*`) never pass evidence.
- **C++:** all refuse.
  - `TokenAuthenticator::authenticate`/`try_authenticate` (`include/axiam/authenticator.hpp:126`; enforcement at `src/authenticator.cpp:219-226`), and `authenticate_sender_constrained` (`:151`).
  - `guard_authenticator` (`:180`) calls `try_authenticate` with no evidence.
  - `JwksVerifier::verify_with_reason` (`jwks.hpp:147`) is public and signature-only by its doc; excluded, but not named "unchecked".

### P7. Manifest global-role check

All 11 refuse `inherit: false` client-side only when the role is declared `is_global` in the manifest. A binding that names a role the manifest does not declare is refused before any request as a dangling reference; no SDK resolves it against the server.

- **Rust:** `management/manifest/plan.rs:328-333`, `:392-426`.
- **TypeScript:** `management/manifest/plan.ts:262-284`.
- **Python:** `management/manifest/_plan.py:327-352`.
- **Java:** `management/ManifestValidation.java:122-155`. It also refuses an explicitly stated `inherit: true` (`:136-143`) and `inherit` without a resource (`:131-135`).
- **Kotlin:** `ManifestValidation.kt:113-126`.
- **C#:** `ManifestValidation.cs:137-155`.
- **PHP:** `ManifestValidation.php:110-145`. The undeclared-role check goes through `depends` (`:66-84`, fed by `ManifestBuilder.php:183-195`), and it ignores entity kind. A role key that collides with, say, a group key passes validation and only fails at apply time (`ManifestApi.php:530`, `:679-688`), after earlier writes have landed.
- **Go:** `management_manifest.go:583-600`. The global check runs only when `Resource != ""`.
- **Swift:** `Management/ManagementManifest.swift:858-895`.
- **C:** `src/management_manifest.c:112-167`. Also refuses `inherit:false` with no resource.
- **C++:** `src/management_manifest.cpp:176-212`.

### P8. The §17 memo

No SDK clears the memo when the acting tenant changes. Every SDK relies on the key alone, and every key includes the acting tenant.

- **Rust:** cleared on login `auth.rs:512`, verify `:587`, refresh `:649`, logout `:758`, device `:886` (before the wire). Key: `memo.rs:52-64`, `authz.rs:229`.
- **TypeScript:** cleared on login, verifyMfa, refresh, logout and device (`auth.ts:164`, `~229`, `~270`, `~315`, `412`). Key: `decisionMemo.ts:65-73`.
- **Python:** cleared on login `:1195`, verify `:1391`, refresh `:1408`, logout `:1443`; device only on success (`:1034`). Key: `_decision_memo.py:65-86`.
- **Java:** `onCredentialChange` (`:865-869`) at `:1350`, `:1443`, `:1473` (refresh), `:1499`, `:3220`. It also resets the gate and drops an adopted device token, **on refresh too**. Key: `internal/DecisionMemo.java:155-165`.
- **Kotlin:** memo-only clear (`:1716-1718`) at `:750`, `:823`, `:849`, `:858`, `:927`. Key: `DecisionMemo.kt:180-186`.
- **C#:** `OnCredentialChange` clears the memo and resets the session (`:612-615`) at `:631`, `:720`, `:748` (refresh resets the gate), `:766`. The device handle gets a new memo; the original's memo is not cleared. Key: `Core/DecisionMemo.cs:129-136`.
- **PHP:** `onCredentialChange` (`:965-968`) at `:1068`, `:1086`, `:1103`, `:1117`, `:1247`. Key: `Core/DecisionMemo.php:121-128`.
- **Go:** `onCredentialChange` (`client.go:617-619`) at `login.go:339/423/479/549` and `device_auth.go:125`. Key: `decision_memo.go:64-73`.
- **Swift:** `memo.clear()` at `AxiamClient.swift:211`, `:259`, `:284`, `:376`, `:739`. Key: `DecisionMemo.swift:93-95`.
- **C:** cleared at `client.c:825`, `:1188`, `:1240`, `:1485`, plus refresh. Key: `memo.c:73-89`.
- **C++:** cleared at `client.cpp:422`, `:798`, `:841`, `:1018` and `client_impl.hpp:504`. Key: `decision_memo.hpp:92-96`.

### Divergences the contract text should settle (all settled in 1.52)

1. **Which calls carry `X-Axiam-Tenant`.** §5.2 rule 1 says "every /api/v1 REST request" but does not name login, verify_mfa, `/oauth2`, the device login or the setup pair.
   - login and verify_mfa: omitted by Rust (`auth.rs:515`), TypeScript (`auth.ts:175`) and Java (`AxiamClient.java:1363`); sent by the other 8.
   - Device login: omitted by Rust, TypeScript and Java; sent by the other 8.
   - `/oauth2/*`: sent by Python, C#, PHP and Go; omitted by the other 7. C# and Python send it even to an off-origin discovered endpoint.
   - WebAuthn setup pair: omitted by Rust, Python, Java and Go; sent by the other 7.
   - TypeScript sends it on explicit `refresh()` but not on the reactive refresh (`interceptors.ts:98`).
   - Rust omits it on `password_reset_context` (`account.rs:441`).
2. **New handle versus mutate.** Seven SDKs return a new handle. PHP, Swift, C and C++ mutate in place, and in C++ and PHP every copy or clone is affected (`client.hpp:1314`, `Session.php:195`). The contract table in §5.2 fixes names but not semantics.
3. **Where the gate state lives.** Python keeps it per handle (`_client.py:373`); every other handle-based SDK shares it across handles.
4. **Error type for a gate refusal.** Swift throws `AxiamError.auth` (`AxiamClient.swift:450-461`) and C returns `AXIAM_ERR_NETWORK` (`client.c:1306-1318`); the other 9 throw an authz error.
5. **Lifecycle of the gate and the acting tenant.** Java (`:1473`) and C# (`:748`) reset the gate on refresh; Java's refresh also drops the adopted device token. C's logout clears the acting tenant itself (`client.c:1255`).
6. **Adopting on the same client versus returning a new one.** Only C# returns a new handle, and that handle silently drops the acting tenant (`AxiamClient.Device.cs:226-306`).
7. **What a refused device login does.** Rust, TypeScript, Java, Kotlin, Swift and C++ clear the memo before the wire. TypeScript and Java also drop the previous device token, and Java also resets the gate. Python, C#, PHP, Go and C change nothing.
8. **What requests carry after adoption.**
   - `Cookie`: an explicit empty header in Rust, TypeScript, Python, Swift and C; no header at all in Java, Kotlin, PHP, Go, C++ and C#.
   - Stale `X-CSRF-Token`: still sent by Rust, TypeScript, Python, Java, PHP, Go, C and C++; not sent by Kotlin, Swift or C#.
9. **Rust applies the bearer only to management and authz calls.** Self-service, WebAuthn and logout still send the previous session's jar cookie after adoption (`account.rs:486`, `webauthn.rs:561`, `auth.rs:795`). This is the stale-cookie hazard §6.1 describes.
10. **Java's device-login request carries `Bearer <prior cookie access token>`** (`AuthInterceptor.java:149-151`).
11. **Guards that never accept a bound token.** Python Django/FastAPI, Kotlin ktor, PHP Laravel/Symfony, Swift guards, C guards and C++ `guard_authenticator` offer no evidence path, even over mTLS. Rust actix, TypeScript Express/Fastify, Java Spring, C# ASP.NET and Go net/http pass the peer certificate. Both are conformant, but a device token works behind only half of the frameworks.
12. **Public signature-only ID-token helpers without "unchecked" in the name.** Java `verifyForOidc`, Kotlin `verifyForIdToken`, Go `VerifyPayload`, PHP `verifyIdTokenSignature`, C++ `verify_with_reason`. Separately, C's `axiam_jwt_verify_ex(flags=0)` skips `cnf`, contradicting `jwks.h:113-115`.
13. **gRPC `validate_token`/`introspect_token` return `valid` for bound tokens** in Rust, TypeScript, Python, Java, C#, PHP and Go, and leave the refusal to `status()`/`verify_possession()`. Rule 9 says "wherever an SDK… turns a token into an identity"; the contract should say explicitly that this surface is exempt.
14. **Externally tagged unions in languages without sum types.** Go and C++ serialize both "neither" (`{}`) and "both" without validation. C silently drops a NULL element. TypeScript's type appears to accept both keys. The contract should say whether an SDK must validate before sending.
15. **Manifest binding validation beyond the MAY.**
    - Java refuses an explicit `inherit: true` (the contract only says "MUST NOT send" it) and `inherit` without a resource.
    - C refuses `inherit:false` without a resource.
    - Go runs the global check only for scoped bindings.
    - PHP's dangling-reference check ignores entity kind.
16. **Internal contradictions and side notes.**
    - C#'s `ActingTenant` remarks say "its own memo" while the code shares it (`AxiamClient.cs:339-345` vs `:481`).
    - Go's comment claims an "explicit empty Cookie" but the code sends none (`client.go:846-853`).
    - Rust's login, verify_mfa and self-service calls omit `X-Tenant-ID`, which §5 rule 2 makes unconditional; this is outside §5.2 but worth recording.

## 3. README and CHANGELOG against the code

Every README and CHANGELOG sentence about 1.51 was read against the code. Section (a) of each SDK lists the sentences the code contradicts, and (b) what the README omits. Each item is fixed in that SDK's docs commit (§4).

I read all six repos on origin/main after a fresh `fetch`. Rust was at 8e9eb90, TypeScript 39c794f, Python 8156a84, Java fa6803a, Kotlin fbf98c5 and C# af77b52. Every repo has at least one mismatch. The most serious are:
- **Python:** after a device login, management calls are refused client-side.
- **Python:** the README's own manifest example is refused by `plan()`.
- **TypeScript:** a failed re-authentication with `authenticateDevice()` goes into the refresh guard.
- **Java:** a gRPC `UNAUTHENTICATED` on the device token goes into the refresh guard.
- **Java and C#:** the §10.1 section names the wrong entry point for the middleware or filter.
- **Java and C#:** the conformance line leaves out §21, although both ship it.

All six conformance lines name contract 1.51. Every "declines webhooks" statement holds: no manifest has a webhooks section.

---

### Rust (axiam-rust-sdk)

**(a) Contradicted**
1. **Acting-tenant header scope.** CHANGELOG.md:19–20 says "Each `/api/v1` REST request of such a handle carries `X-Axiam-Tenant`." These requests do not send it:
   - the device login POST (src/rest/auth.rs:889–894 sets only `X-Tenant-ID`);
   - `login` (auth.rs:515–518);
   - every OPAQUE request: src/rest/opaque.rs:244, 287 and 405, which includes the self-enrolment `register/start`;
   - the SSO/federation requests (src/oidc/federation.rs:378, 466, 585).

   Only the paths that go through `tenant_headers_of` or `acting_tenant_of` send it: authz, management, refresh, logout, account and webauthn.
2. **"Nothing is ever deleted" / "there is no rollback".** README.md:1882 and 1891 say this. A 1.51 binding `Update` unassigns first (src/management/manifest/mod.rs:1342), and on failure re-assigns the previous binding (mod.rs ~1355–1368).

**(b) Omitted.** The README has no API documentation for the 1.51 manifest. The only mention is the 1.51 table (README.md:85–87). Missing:
- `RoleBinding`, `ServiceAccountSpec` and `ResourceSpec::with_metadata`;
- the `manifest!` statements `metadata`, `at <resource>[, here only]` and `service_account`;
- `Outcome::BindingUpdateFailed { restore }` and `ApplyReport::created_service_accounts()`.

README.md:1894 lists the refusals made "before the first request" but leaves out three:
- one role bound twice to a subject (plan.rs:409–416);
- a global role with `inherit: false` (plan.rs:421);
- an ambiguous service-account name. This one fails `plan` after its GETs, as `AxiamError::Network` (mod.rs:885).

**(c)** None.

Everything else I checked matched: the helper names, the `Uuid` type, the header sent only when set, REST-only, the login-result gate, and which calls record or reset the scope (auth.rs:487, 539, 626, 811, 937). For the device login: no body, the token is adopted, the jar is withheld on the POST and afterwards, no refresh, 429 maps to Network, zero wire calls without a certificate, and rule 7 is a runtime check. Rule 9 entry points, `inherit` sent only as false (mod.rs:1424), and the conformance line also matched.

### TypeScript (axiam-typescript-sdk)

**(a) Contradicted**
1. **A 401 on re-authentication goes into the refresh guard.** README.md:265–270 says "A later 401 … without a refresh attempt" and "Every refusal is a 401 … mapped to AuthError verbatim". The CHANGELOG says the same.
   - `/api/v1/auth/device` is not in `SKIP_REFRESH` (src/rest/interceptors.ts:25–32).
   - `authenticateDevice()` clears `deviceAccessToken` before its POST (src/rest/auth.ts:414).
   - `session.authenticated` is still true from an earlier login (auth.ts:183, 237) or an earlier successful device login (auth.ts:430).
   - So a 401 on the documented recovery path (calling `authenticateDevice()` again) takes the refresh branch (interceptors.ts:90): it POSTs `/api/v1/auth/refresh` and returns "session refresh failed; re-authentication required" instead of the server's message (interceptors.ts:104–110).
   - The comment at auth.ts:441–446 assumes `authenticated` is false at that point.
2. **Metadata equality.** README.md:2366 says metadata "drifts by JSON equality of the whole object". The code compares `JSON.stringify` output (src/management/manifest/engine.ts:981–983), which depends on key order. The same object with keys in a different order is reported as drift on every plan.

**(b) Omitted.** Nothing says the device token is REST-only.
- The gRPC interceptor sends `tokenManager.cachedAccessToken()` (src/grpc/interceptor.ts:30), not the device token.
- `callWithRefresh` refreshes on `UNAUTHENTICATED` with no device check (src/grpc/callWithRefresh.ts:36–37).

**(c)** No stale version numbers. The "named rather than folded" list (README.md:62–65) leaves out §17, §19, §20, §21 and §23, all of which the statement names. This is cosmetic.

Everything else I checked matched:
- **Acting tenant:** the UUID check; the construction form and the helpers; the call sites that send the header; which calls record the scope (auth.ts:70, opaque.ts:259, webauthn.ts:272, accountLifecycle.ts:199) and which reset it (webauthn.ts:412, oidc.ts:2159, auth.ts:339, 433).
- **Device login:** the jar is withheld afterwards (interceptors.ts:160–176).
- **Rule 9:** it is applied in `verifyAccessToken` and `authenticateRequest`.
- **Manifest:** `inherit` is sent only as false (engine.ts:858), the refusals, the rebind outcome, and the typestate decline.

### Python (axiam-python-sdk)

**(a) Contradicted**
1. **Management after a device login.** README.md:1936–1939 says the device token "works with `check_access`/`batch_check` and the §27 management families a service account may use." Every management call is refused client-side instead:
   - `adopt_bearer_credential` clears the cookie jar (src/axiam_sdk/_session.py:219);
   - `send_management` and its async twin call `_require_session` (management/_request.py:92, 121);
   - that raises `AuthError("no active session — call login() …")` when there is no `axiam_access` cookie (_request.py:76–79).
2. **The README manifest example is refused by `plan()`.** README.md:1755–1756 binds `"editor"` to group `staff` twice, once plain and once as a `ScopedRoleBinding`. README.md:1777 and `_plan.py:329–336` both reject that, so `plan()`/`apply()` raise on the example as written.
3. **`clear_acting_tenant()` example.** README.md:1196 shows `acme.clear_acting_tenant()  # or: back to the org's own scope`. The method returns a new handle and does not change `acme` (_client.py:1134–1141). The example throws the result away, so `acme` keeps sending the header.

**(b) Omitted**
- **The device credential is never released.** `clear_bearer_credential` (_session.py:228) has no caller, and `login`, `verify_mfa` and `logout` never clear `bearer_token`. Every later request keeps sending `Authorization: Bearer <device>` with `Cookie: ""` (_client.py:899–902). A later `login()`'s cookies are never sent, and the acting-tenant gate then records the user's reach while requests run as the device.
- **Manifest bullets.**
  - The README leaves out the global-role plus `inherit=False` refusal (_plan.py:344–351), which the CHANGELOG includes.
  - The restore result is only described as "the step's outcome names both". The actual fields are `StepOutcome.restore_succeeded` and `restore_error` (_plan.py:116, 129).

**(c)** None.

### Java (axiam-java-sdk)

**(a) Contradicted**
1. **§10.1 entry point.** README.md:125–128 says `AxiamAuthenticationFilter` applies the set "through the single `JwksVerifier.verifyAccessToken(token, configuredTenantId)` entry point", and the table there has no rule 9 row. The filter actually calls `verifySenderConstrained` (AxiamAuthenticationFilter.java:224). The callout at README.md:66–86 is correct; this section contradicts it.
2. **Acting-tenant table row.** README.md:58 says the header goes "on every `/api/v1` POST this client sends once a login result is held". Two things are wrong:
   - It is sent whenever the handle has an acting tenant, whether or not a login result is held (ManagementTransport.java:256–258, AuthInterceptor.java:136–138).
   - It is not limited to POSTs: management GET, PUT and DELETE requests are tagged too (ManagementTransport.java:245–258).

   The CHANGELOG's "once set" matches the code.
3. **gRPC refresh on the device token.** README.md:59 and the CHANGELOG say the device login "never enters the §9 refresh guard for this credential's own 401s". That holds on REST (AuthAuthenticator.java:67–79) but not on gRPC.
   - On `UNAUTHENTICATED`, `refreshIfNeeded(…, session::doHttpRefresh)` runs with no `hasAdoptedAccessToken` check (GrpcAuthzClient.java:715–737).
   - `doHttpRefresh` reads `cachedAccessToken()`, which returns the adopted device token (SessionState.java:317–319), and POSTs `/api/v1/auth/refresh` (497–537).
4. **Cookie mechanism.** The CHANGELOG says "every subsequent request also carries an explicit empty `Cookie` header". The code swaps in a `LoadSuppressedCookieJar` instead (AuthInterceptor.java:151–172), and its comment says setting the header would be overwritten. The effect is equivalent; the description is wrong.

**(b) Omitted**
- **`refresh()` resets the gate.** It calls `onCredentialChange()` (AxiamClient.java:1473), which resets the principal scope and drops an adopted device token (865–869). The "Which sessions gate" table (README.md:92–104) does not list `refresh()` or `logout()`.
- **Device login POST.** The cookie is withheld, but `Authorization: Bearer <prior session's axiam_access>` is still attached. The `isDeviceAuthCall` check only swaps the jar (AuthInterceptor.java:130–141 and 165–168), and the proactive near-expiry refresh (126–131) is not excluded for this path. C# treats this same leak as a defect.
- **`scoped(role, resource, true)` is refused** by validation (ManifestValidation.java:136–143). The README row doesn't say so.

**(c) Section list.** The conformance line (README.md:27–39) leaves out §21, although the SDK ships it (README.md:358; oidc/MtlsEndpointAliases.java). The "named rather than folded" sentence (41–44) also leaves out §17, §19 and §21.

### Kotlin (axiam-kotlin-sdk)

**(a) Contradicted**
1. **"Refused at `build()`".** README.md:1941–1944 says one role bound twice, or a global role bound `atOnly`, is "refused at `build()`". `Builder.build()` (ManagementManifest.kt:537–545) only throws on the builder's dangling-reference problems (lines 311–524). The binding checks live in `ManifestValidation.validate`, which runs from `plan()` and `apply()` (ManifestApi.kt:137, 157). The refusal still happens before any request.
2. **§1 in the conformance line.** README.md:27 claims §1 (as part of "§1–§7"). The same README declines §1.1 `getUserInfo` and §1.1.1 `validateToken`/`introspectToken` as deferred gRPC (README.md:94–100, and the CHANGELOG's Declined section). The statement needs a qualifier.

**(b) Omitted**
- **No webhooks decline.** Neither the README nor the CHANGELOG says webhooks are declined; the other five SDKs do.
- **Manifest section gaps.** It does not mention:
  - unassign-then-assign with restore reporting (`BINDING_UPDATE_FAILED`, `StepOutcome.restoreSucceeded`; ManagementPlan.kt:156–182, ManifestApi.kt:602–641);
  - `inherit` sent only as false (ManifestApi.kt:660–661);
  - `tenant_scope` carried across a rebind.
- **Device section gaps.** It does not say that a later 401 never refreshes (AxiamClient.kt:2409) or that a 429 is not an AuthError (931–943).
- **The device token survives a later login.** `onCredentialChange` only clears the memo (AxiamClient.kt:1716–1718); only logout's `session.clear()` releases the device token. `AuthHeaderInterceptor.kt:59–62` keeps sending the device bearer and stripping the cookie, so the new login session is never used. The README only describes the opposite direction ("replaces whatever cookie session").

**(c) Stale.** README.md:54–58 says §28 is "vendored ahead of `axiam` `main`" from the MCP branch, "where contract 1.48 lands". The CHANGELOG `[Unreleased]` says the files were re-vendored from axiam `56fbe44` (contract 1.51).

The acting-tenant record/reset list in the README (login, verifyMfa, loginOpaque, mfaSetupConfirm, webauthnSetupRegisterFinish; refresh does not reset) matches the code. The KDoc at AxiamClient.kt:385–387 says the opposite for OPAQUE and the MFA setup, but that is a code comment, not the README.

### C# (axiam-csharp-sdk)

**(a) Contradicted.** §10.1 entry point:
- README.md:96–98 says "`AxiamAuthMiddleware` verifies access tokens locally through one implementation, `JwksVerifier.VerifyAsync`".
- README.md:111 calls `VerifyAsync` "the middleware's default entry point".
- The middleware actually calls `VerifyWithProofsAsync(token, tenantId, proofs, …)` (Axiam.Sdk.AspNetCore/AxiamAuthMiddleware.cs:224).

**(b) Omitted**
- **Construction-time acting tenant.** `AxiamClientOptions.ActingTenant` (Options/AxiamClientOptions.cs:63) is not in the README. Only `ActingTenant(Guid)` and `ClearActingTenant()` are documented (README.md:56, 1634ff); the CHANGELOG mentions the option only inside a Fixed note.
- **The device handle drops the acting tenant.** The login POST sends it (AxiamClient.Device.cs:111), but the handle `AuthenticateDeviceAsync` returns has `_actingTenant = null` (AxiamClient.Device.cs:217).

**(c) Stale / section list**
- README.md:23–26 lists "the §1.1.1 gRPC `validate_token`/`introspect_token` operations, contract 1.3". §1.1.1 arrived in contract 1.51 (CHANGELOG `[Unreleased]` header; README table row at 54).
- The conformance line leaves out §21, although the SDK ships it (README.md:554; Auth/Oidc/OidcTypes.cs and AxiamClient.Oidc.cs).
- The "named rather than folded" sentence (37–39) leaves out §17, §19 and §28.

Everything else I checked matched:
- **Device login:** no body; the anonymous transport withholds cookie and Authorization on the POST; a fresh jar on the returned handle; a refresh guard that throws with no wire call; 429 maps to NetworkError; zero wire calls without a certificate; rule 7 is a runtime check.
- **Manifest:** `inherit` sent only as false (ManifestApi.cs:917), whole-object `JsonElementDeepEquals`, the rebind restore result as `StepOutcome.RestoreSucceeded`, and the refusals.
- **Acting tenant:** the memo is shared (AxiamClient.cs:479), and the decline statements hold.

I read `origin/main` in all five repos after `git fetch -q origin main`: php 33c8095, go d5658ea, swift db24d26, c 0b87547, cplusplus b650258. All five vendor the same CONTRACT.md 1.51 (sha256 0ac7fd75f83c). I checked nothing out and changed nothing. Only mismatches are listed; every item cites the code.

Every repo has at least one mismatch. The most serious ones:
- **PHP:** a later 401 on the device token triggers a refresh, which the CHANGELOG says never happens.
- **Go:** the CHANGELOG says a DPoP-bound token is always refused, but the code accepts one with matching evidence.
- **Swift:** the acting-tenant reach check compares UUIDs case-sensitively and would likely refuse every tenant. The CHANGELOG also says login/verifyMfa don't send the header, but they do.
- **C:** the conformance sentence names no contract version and says "six" WebAuthn wire operations where the code ships eight.
- **Go, Swift and C++:** after `authenticate_device()`, the device token is never cleared. A later `login()` on the same client is silently ignored, and the READMEs don't say so.

### PHP (axiam-php-sdk)

**(a) Contradicted**
1. CHANGELOG.md:42-43 says `authenticateDevice()` "Never enters the §9 single-flight refresh guard — there is no refresh token to spend." That holds only for the device POST itself.
   - The adopted token is used by the authz client, and `$authzHttp` carries `RefreshMiddleware` (AxiamClient.php:434).
   - That middleware sends every 401 to `Session::refreshIfNeeded()` (RefreshMiddleware.php:48-58).
   - `buildRefreshCall()` (Session.php:399-430) only stops before the wire when the token lacks `tenant_id`/`org_id`. CONTRACT.md:433-435 says access tokens carry both claims.
   - Nothing in `Session` checks for a device credential. So a later 401 on the device token makes a real `POST /api/v1/auth/refresh`, against §6.1 rule 6 ("without a refresh attempt").
   - tests/Contract151DeviceAuthTest.php:257 only tests the device POST's own 401.
2. README:256 says "`resources[].metadata` — already supported before 1.51." Two parts of the §27.6.1 item 1 rule are missing:
   - A stated `{}` can't be expressed: `if ($metadata !== [])` treats it as unstated (ManifestBuilder.php:38).
   - Drift uses strict `!==` (ManifestEntity.php:51). That comparison depends on key order, so it is not "JSON value equality of the whole object".
3. README:267-268 says "a global role bound with `inherit: false`, is refused while the manifest is built." It is refused only when that role is declared in the same manifest with `isGlobal: true` (ManifestValidation.php:109-113, 137).

**(b) Omitted**
- **Acting tenant is REST-only.** The README's 1.51 section (lines 230-238) never says the acting tenant is REST-only, or that gRPC calls (including the new `validateToken`/`introspectToken`) act on the token's tenant. §5.2 rule 1 says an SDK MUST document this; only the CHANGELOG mentions it.
- **§10.1 table.** The table (README ~302-312) lists rules 1-7 only, while saying it applies "the complete §10.1 minimum" set. There is no row for rule 8 or rule 9.
- **Framework bridges can't accept bound tokens.** The Laravel/Symfony bridges always call `verifyLocally()` (Laravel/AxiamMiddleware.php:170, Symfony/AxiamAuthSubscriber.php:183) and have no way to pass evidence. A bridge user therefore can't accept device tokens. The README's "calls `verifyWithProofs()` instead" hides this.
- **Binding updates are invisible to `plan()`.** `planAgainst` drops `grants`/`roles` from drift (ManifestApi.php:78-80), and edge reconciliation only runs inside `apply()`. So a binding "Update" (README:264-266) never appears in `plan()`.
- **Logout.** The list of calls that set or reset the scope leaves out `logout()`, which resets it (AxiamClient.php:1134).
- **Rule 7.** The README never says rule 7 is enforced at run time (AxiamClient.php:1203).

**Conformance statement (item 6).** It names 1.51 (README:194), but the section list leaves out §21. The code ships §21.7.2 DPoP verification (src/Auth/DpopVerifier.php) and §21.3 `mtls_endpoint_aliases` (README:1910).

**(c)** No stale version numbers found.

### Go (axiam-go-sdk)

**(a) Contradicted**
1. CHANGELOG.md:129-130 says `VerifyAccessTokenWithProofs` refuses "a DPoP-bound token … (this package verifies no DPoP proof)". The code accepts one:
   - The `jkt` branch accepts when `proofs.DPoPThumbprint` matches (internal/jwks/validate.go:286-330).
   - The package exports `VerifyDPoPProof` (jwks.go).
   - The README's own text on this is correct.
2. README:44 and CHANGELOG:106 and 117 name the API `jwks.Verifier.VerifyAccessToken`. That package is `internal/jwks` and can't be imported by users. The public name is `axiam.JWKSVerifier` (jwks.go).

**(b) Omitted**
- **The device credential is permanent.** It is never cleared: the only setter is `adoptDeviceCredential` (client.go:624), called only from device_auth.go:129. `Logout` (login.go:545-587) doesn't clear it. After `AuthenticateDevice`, every request, including a later `Login()`, sends the device bearer with an empty `Cookie` (client.go:854-857), so a later password session is never used.
- **Client-credentials adoption doesn't reset the acting-tenant gate.** `LoginClientCredentials(AdoptAsCredential)` and device-grant adoption skip `resetScopeUnknown()` (oidc.go:607-609, oidc_device.go:239-241). The previous login's gate stays in force, even though the godoc (client.go:466-469) says a client-credentials token "has nothing to gate on".
- **Rule 7.** Enforced at run time (device_auth.go, `presentsClientCertificate`), and the README records no decline of the compile-time form.

**Conformance statement.** Names 1.51; the section list matches the code.

**(c)** None.

### Swift (axiam-swift-sdk)

**(a) Contradicted**
1. CHANGELOG.md:30 says `X-Axiam-Tenant` is sent "(login/verifyMfa excluded …)". It isn't excluded: `login` (AxiamClient.swift:221) and `verifyMfa` (:265) both go through `rawSend`, which adds the header whenever it is set (:1089-1091).
2. The README (lines ~291-294) says a tenant is refused only when it is outside `reachableTenantIDs`. The check at AxiamClient.swift:456-457 is `reachable.contains(tenantID.uuidString)`:
   - `reachable` holds the server's raw strings (Models.swift:72, AxiamClient.swift:1470).
   - Foundation's `uuidString` is upper-case.
   - Inferred, not verified here: a Rust server serializes UUIDs in lower case, so every reachable tenant would be refused.
   - The tests feed upper-case `uuidString` values into the stub responses (ActingTenantTests.swift:182, 200, 247), which hides this.
3. README ~552 says `authenticate(_:presentedProofs:)` "applies **all eight** rules". README:564 labels `cnf` as rule 8, and README:569 says "Rule 8 (`cnf`)".
   - In CONTRACT.md:1255-1256, rule 8 is "subject of the decision" and `cnf` is rule 9.
   - The code's own doc also calls it rule 9 (Guard/AxiamRequestAuthenticator.swift:131).
   - The README table leaves out the contract's rule 8.

**(b) Omitted**
- **The device token is permanent.** `deviceAccessToken` is cleared only by `close()` (:181) and `logout()` (:290). A later `login()` (:221-229) doesn't clear it, so requests keep carrying the device bearer with `Cookie: ""` (:1120-1121). `canRefresh` stays false (:70).
- **Guards can't accept bound tokens.** `AxiamGuards.requireAuth`, `requireAccess` and `requireRole` call `authenticate(context)` with no proofs (AxiamGuards.swift:30, 50, 125). Guarded routes therefore always refuse device tokens, and there is no evidence parameter.
- **Rule 7.** Enforced at run time (AxiamClient.swift:372); no typestate decline is recorded.

**Conformance statement.** Names 1.51; the section list matches.

**(c)** None.

### C (axiam-c-sdk)

**(a) Contradicted**
1. README:1033-1035 and CHANGELOG say `axiam_jwt_verify()` / `axiam_jwt_verify_ex()` "now refuse" a `cnf`-bound token. `check_claims`, where the rule-9 check lives, runs only when `flags != 0` (jwks.c:546). So `axiam_jwt_verify_ex(..., AXIAM_JWT_VERIFY_SIGNATURE_ONLY /*0*/, ...)` still accepts a bound token.
2. README:1339-1341 says "A caller running two tenants concurrently from one login constructs two `axiam_client_t` (`axiam_client_config_clone()` is cheap)". The clone copies configuration only (config.c:273-300). Each new client starts with no session, so this needs two logins, not one.

**(b) Omitted**
- **gRPC declines.** The statement's range "§1–§7, §9–§13" takes in §1.1.1 `validate_token`/`introspect_token` and §10.3. The gRPC scope note (README:42-46) only excludes `axiam_get_user_info`; there is no 1.51 decline like the ones Swift and C++ have.
- **Logout drops the acting tenant.** `axiam_logout()` also discards the acting tenant (client.c:1253-1255, `reset_acting_tenant_and_gate`), which the README doesn't say.
- **Manifest table.** The README table's `service_accounts` row doesn't say it takes `roles[]` bindings (management_manifest.h:113-120), and nothing documents rebind restore reporting (`restore_attempted`/`restore_succeeded`, management_manifest.h:244-245).
- **429 mapping.** The README's device section doesn't say a 429 maps to `AXIAM_ERR_NETWORK`.

**(c) Stale / version**
- The conformance statement (README:16) names no contract version at all. "Contract 1.51" appears only in a separate paragraph (README:25).
- The same statement says "§24's six wire operations". The code ships eight (webauthn.h:215-337, including `setup_register_start`/`_finish` from 1.45).

### C++ (axiam-cplusplus-sdk)

**(a) Contradicted**
No README/CHANGELOG sentence is directly contradicted.

**(b) Omitted**
- **The device token is permanent.** `device_access_token` and `device_session` are only ever set (client.cpp:1065-1066) and never cleared, not even by `logout()` or `login()`. So after `authenticate_device()`:
  - every request carries the device bearer and withholds cookies (client_impl.hpp:260-263);
  - refresh stays disabled for any later cookie session (client_impl.hpp:447, 478).
- **A malformed 200 is adopted.** A 200 with a malformed body is still accepted: it stores an empty token and sets `device_session = true` (client.cpp:1049-1066).
- **Guards can't accept bound tokens.** `guard_authenticator()` only calls `try_authenticate` (authenticator.hpp:186). There is no non-throwing sender-constrained version, so `AxiamGuard` routes always refuse device tokens.
- **Plain binding with inherit false.** `validate()` accepts `{role, nullopt, false}` (a plain binding with `inherit: false`) and sends `inherit: false` with no resource (management_manifest.cpp:175-210, 431-437).

**Conformance statement.** Names 1.51; the section list and declines match.

**(c)** None.

### Checked in all five, no mismatch beyond the above
- **Acting tenant:** helper names; UUID check with its error type; header sent only when set; no gRPC metadata key; the §17 memo key.
- **Scope set/reset sites:** match the README lists everywhere except the gaps noted above.
- **`authenticate_device()`:** no body; token adopted; cookie jar withheld on the device POST; 401 → AuthError; 429 → NetworkError, no retry; zero wire calls without a certificate.
- **Rule 7:** runtime in all five. C and C++ record the decline; PHP, Go and Swift don't state it.
- **Manifest:** `inherit` is sent only as false, `tenant_scope` is carried across a rebind, restore-on-failure works, ambiguous service-account names fail `plan`, and a `client_secret` survives a later failure.
- **Declines:** every listed decline matches the code.

## 4. The fix wave

The fixes are on one branch per repository, `fix/c12-conformance`, cut from the `main`
read above. Each follows the same procedure:

1. A test is written first and run against the unfixed code, where it must fail. The
   failing output is quoted in the commit body.
2. The fix goes in, and an I4 twin pins the case that was already right.
3. The fix is reverted once, and the new test must fail again. The mutation is named in
   the commit.

Commits cite "CONTRACT 1.52 N-x (C-12)". For every PR, the orchestrator:

- read the diff;
- re-ran the suite at the PR's head;
- ran the new tests against `main`'s sources ("red on `main`"), to show that each one
  catches the defect it names.

Every PR is held until this revision merges, then re-vendors `CONTRACT.md` from its merge
commit (§6).

| SDK | PR | Head | Rules fixed | Suite at head (orchestrator) | Red on `main` |
|---|---|---|---|---|---|
| Rust | {{ROW:rust}} |
| TypeScript | [#119](https://github.com/ilpanich/axiam-typescript-sdk/pull/119) | `5e89f35` | N4.5 REST and gRPC, N4.3, N6.5, N3, N4.2, N4.4, N5.6, N5.5, N6.2 | 1432 passed, 3 skipped (Node 22) | 18 failed |
| Python | [#90](https://github.com/ilpanich/axiam-python-sdk/pull/90) | `bd9b953` | N4.7, N4.4, N5.3, N5.1, N4.5, N4.2, N5.6 | 1770 passed; coverage 98.58 % (floor 98) | 12 of 14 failed; the other two are I4 twins |
| Java | [#103](https://github.com/ilpanich/axiam-java-sdk/pull/103) | `783c924` | N4.1, N4.3 and N4.5 on gRPC, N4.2, N4.4, N6.2 | 1244 tests; JaCoCo met (95.05 %) | 6 of 31 in the three changed test classes (4 failures, 2 errors) |
| Kotlin | [#69](https://github.com/ilpanich/axiam-kotlin-sdk/pull/69) | `ef08f40` | N4.4 | 1062 tests; Kover 98.08 % (floor 98) | 3 of 14 in `DeviceAuthTest` failed |
| C# | [#97](https://github.com/ilpanich/axiam-csharp-sdk/pull/97) | `b8ef9bc` | N4.6, N5.1, N4.4, N6.2, N6.3, N4.2, N4.5 on gRPC | 1265 passed (`Axiam.Sdk.Tests`, net8.0) | 7 of 60 in the three changed REST test classes failed. The gRPC and manifest tests use API this PR adds and cannot compile against `main` |
| PHP | [#75](https://github.com/ilpanich/axiam-php-sdk/pull/75) | `1c9a02d` | N4.5 REST and gRPC, N6.4, N6.5, N6.6, N5.6, N4.4 | 1684 tests, 5225 assertions | 12 failures, 7 errors |
| Go | [#88](https://github.com/ilpanich/axiam-go-sdk/pull/88) | `aa35be7` | N4.4, N5.5, N3 | `go test ./...`, 15 packages pass | all six new tests failed |
| Swift | [#67](https://github.com/ilpanich/axiam-swift-sdk/pull/67) | `e897e0d` | N5.6, N5.4, N4.4 | 1191 tests, 0 failures (Swift 6.3 container) | `DeviceMtlsLoginTests` 2 of 7, `ActingTenantTests` 4 of 15 failed |
| C | [#66](https://github.com/ilpanich/axiam-c-sdk/pull/66) | `1c4bb3f` | N5.4, N5.6, N3 | 64/64 test binaries (gcc, C11) | `test_acting_tenant` failed |
| C++ | [#68](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/68) | `8605d9e` | N4.4, N4.2, N6.2, N3, N5.6, N4.7 | 1315 test cases, 4169 checks (gcc, C++17) | 19 failed, each a C-12 test |

Every PR also carries a docs commit: the README and CHANGELOG sentences listed in §3,
corrected against the code. CI was green on every head before this revision's PR opened.

**What every port had in common.** Four defects recur across unrelated codebases, which
is why the contract now states them as rules:

1. **The device credential outlived a later login.** A device login set it, and only
   `close()`, or nothing at all, cleared it. So a later `login` was silently shadowed
   by it (N4.4).
2. **A refresh guard reached the device token.** Some SDKs exclude the device path from
   the refresh guard on REST, but they reached the guard on gRPC or on re-authentication
   (N4.5).
3. **Reach compared strings.** Every fixture used all-digit UUIDs, where case cannot
   differ, so no test could see it (N5.6).
4. **A malformed `200` on the device login was adopted** as an empty credential (N4.2).

## 5. What the reports got wrong

Every claim the ports and fix workers made was checked against the code. These did not
survive:

- **N5.6 slipped through two review rounds.** TypeScript's first fix PR compared with
  `includes`, and Python's with a plain `in`. The worker's own sweep had marked both
  "conforms". The orchestrator's red check used a hex-letter UUID, which found them.
  TypeScript was sent back and fixed it in `814bb91`. Python's fix, `bd9b953`, is the
  orchestrator's own. The same note then went to every later worker, and C and C++
  found the defect in their own code.
- **Kotlin's SSO call site had no test.** The N4.4 fix released the device credential at
  three call sites, but tests pinned only two of them. Removing the SSO hook's line left
  the suite green. The worker was sent back for `ef08f40`, whose test fails with that
  line alone removed.
- **Swift's "rule 7" finding could not be located from the brief.** The orchestrator
  wrote the README sentence itself (`e897e0d`).
- **The C worker committed on the wrong local branch.** It noticed before pushing and
  cherry-picked the commit across. The pushed branch was confirmed equal to its intended
  history.
- **Two rows of an early §27.14 draft were wrong,** and are corrected in the table as
  published. Python's refresh defect was on REST, not gRPC: its gRPC clients take a
  caller-supplied `token_fn`. And C also compared reach with `strcmp()`.
- **The early-fix list was missing a PR.** It left out
  [axiam-php-sdk#74](https://github.com/ilpanich/axiam-php-sdk/pull/74), which had
  already stopped a refused device login from ending the session, before this review
  read `main`.

{{SELFREPORT:rust}}
- **C#'s first push released the device credential before the request,** so a refused
  later login left a device handle with no credential at all. Its gRPC refresh
  exemption was also fixed when the client was constructed. Both were sent back and
  fixed in `fa6b010` and `b8ef9bc`, each with a test that fails on the first push. The
  worker also found five defects its findings did not list: N4.4, N6.2, N6.3, N4.2 and
  N4.5 on gRPC.

## 6. Follow-up: the 1.52 re-vendor

The eleven fix PRs are held. Once this revision merges, one commit is pushed to each PR:

- `CONTRACT.md` is copied byte for byte from the merge commit;
- the README conformance line moves to 1.52;
- a CHANGELOG line records the re-vendor.

`python3 scripts/check-sdk-artifact-drift.py --local-root ..` must then report no drift,
and the PRs merge after that. `openapi.json`, `management-registry.json` and `proto/`
are unchanged by 1.52 and are not touched.

Nothing is tagged or published.
