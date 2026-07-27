# CONTRACT §12 OIDC/SSO — cross-SDK conformance review (T9)

**Date:** 2026-07-27
**Scope:** CONTRACT §12 (OIDC/SSO relying-party helpers), implemented independently in eight SDKs
against contract 1.4 (`/home/user/axiam` @ `9c5de58`).
**Outcome:** contract amended to **1.5** (non-breaking / clarifying); one repo **BLOCKED**, seven
**SAFE TO MERGE**; 19 follow-up items recorded (F-01–F-19, of which F-16 was fixed in this review,
leaving 18 open).

Branch under review in every repo: `claude/sdk-oidc-sso-plan-8t4hgm`.

| Repo | Commit reviewed |
|---|---|
| `axiam` (contract) | `9c5de58` |
| `axiam-typescript-sdk` (reference) | `2efd754` |
| `axiam-python-sdk` | `e98ffbf` |
| `axiam-go-sdk` | `ba9bd84` |
| `axiam-rust-sdk` | `b2d7930` |
| `axiam-php-sdk` | `6d5775e` |
| `axiam-java-sdk` | `c7b6866` |
| `axiam-csharp-sdk` | `cf59dc8` |
| `axiam-kotlin-sdk` | `c65edca` |

---

## 1. Conformance matrix

Legend: **P** = pass · **F** = fail · **D** = divergent but legal (a contract MAY, or a
per-language equivalence) · **P\*** = pass with a recorded caveat · **n/a** = not applicable.
Every cell was determined by reading the shipped source, not by reading an agent's report.

### 1.1 Vocabulary and surface

| Rule | TS | PY | GO | RS | PHP | JV | C# | KT |
|---|---|---|---|---|---|---|---|---|
| All nine §12.2 operations present, exact per-language name | P | P | P | P | P | P | P | P |
| C# `OidcBegin` has **no** `Async` suffix; no `OidcBeginAsync` exists | n/a | n/a | n/a | n/a | n/a | n/a | P | n/a |
| Python: identical names on sync + async client; no `async_*` anywhere | n/a | P | n/a | n/a | n/a | n/a | n/a | n/a |
| Kotlin: `suspend`, no `*Async`/`Deferred` twins | n/a | n/a | n/a | n/a | n/a | n/a | n/a | P |
| Java: only the permitted `*Async` twins (and no `oidcBeginAsync`) | n/a | n/a | n/a | n/a | n/a | P | n/a | n/a |
| No additional diverging auth/authz method names | P | P | P | P | P | P | P | P |
| Argument order / params shape consistent, subject-before-object | P | P | P | P | P | P | P | P |
| Host object for the nine methods | D | P | P | P | P | P | P | P |

`D` for TypeScript: the nine live on a Node-only `OidcClient` rather than `AxiamClient`, because
its CI forbids `node:crypto`/`jose` from reaching the browser bundle. Contract 1.5 §12.2 now
permits this explicitly.

### 1.2 Error taxonomy

| Rule | TS | PY | GO | RS | PHP | JV | C# | KT |
|---|---|---|---|---|---|---|---|---|
| `OAuthProtocolError` is a **sub-type** of the existing auth-error type | P | P | P | D | P | P | P | P |
| `message` field exactly `"<error>: <error_description>"` | P | P | P | P | P | P | P | P |
| `error` + `error_description` publicly accessible (per-language casing) | P | P | D | P | P | P | P | P |
| Existing consumer `catch`/`except`/`match` code still works | P | P | P | **F** | P\* | P | P | P |
| 400 from `/oauth2/*` with an OAuth2 body → `OAuthProtocolError` | P | P | P | P | P | P | P | P |
| 401 from `/oauth2/*` with an OAuth2 body → `OAuthProtocolError` | P | P | P | P | P | P | P | P |
| 401 from `/oauth2/*` never enters the §9 refresh guard (tested) | P | P | P | P | P | P | P | P |

- **RS `D`** on sub-typing: Rust models it as two new fields (`oauth`, `reason`) on the existing
  `AxiamError::Auth` struct variant rather than a peer type — an idiomatic and legal realisation.
- **RS `F`** on consumer compatibility: adding fields to a public, non-`#[non_exhaustive]` struct
  variant is **source-breaking** for downstream crates. `AxiamError::Auth { .. }` still matches,
  but `AxiamError::Auth { message }` (exhaustive destructure) is `E0027` and every
  `AxiamError::Auth { message: … }` construction is `E0063`. The commit mechanically fixed 33
  construction sites and 9 patterns inside the repo, including one in a shipped `examples/` file —
  which is precisely the evidence that downstream code breaks too. Contract 1.4's log calls §12
  "non-breaking"; for Rust it is not. Pre-1.0 (`1.0.0-alpha18`), so tolerable, but it must be
  documented and `#[non_exhaustive]` should be added now.
- **GO `D`**: the `error` field is exported as `ErrorCode`, because a field named `Error` would
  collide with the promoted `Error()` method that satisfies the `error` interface. Contract 1.5 §2
  now blesses this. Go's `Error()` also prefixes `"authentication failed: "`; the `Message` field
  itself is exact, which is what 1.5 requires.
- **PHP `P*`**: `AuthError::__construct` gained `$reason` as the **second positional** parameter,
  so any downstream caller passing `$previous` positionally breaks. No such call site exists in
  the repo (all 22 verified), but the ordering is a latent trap — `$reason` should be keyword-only
  or last.

The 401-out-of-guard property is realised two ways, both tested and both conformant: an explicit
`/oauth2/*` skip list (TS `SKIP_REFRESH`, Java `OAUTH2_SKIP_REFRESH_PATHS`, C#
`ReactiveRefreshExemptPaths`) or structurally, by routing §12 calls through a transport that has no
401→refresh interceptor at all (Python, Go, Rust, PHP, Kotlin). The structural variant is more
robust today but more fragile to a future generic interceptor; each of those five repos should
carry a regression comment or test naming that invariant (follow-up F-14).

### 1.3 `Sensitive` / §7

| Rule | TS | PY | GO | RS | PHP | JV | C# | KT |
|---|---|---|---|---|---|---|---|---|
| Exactly the 5 §12.5 fields wrapped (access/refresh/id token, client_secret, code_verifier) | P | P | P | P | P | P | P | P |
| `state` and `nonce` are **not** wrapped | P | P | P | P | P | P | P | P |
| Redaction in every stringification sink | P | P | P | P | P | P | P | P |
| Redaction in every structured-serialization sink | P | P\* | P | n/a | P | P\* | P | n/a |
| Raw value not reachable **implicitly** (no public field/`Deref`/auto-unbox) | P | P | D | P | P | P | P | P |
| §12 caller can read the returned tokens | P | P | P | P | P | **F** | P | **F** |

- `n/a` for Rust and Kotlin on structured serialization: neither wrapper nor any §12 DTO implements
  `Serialize`/`@Serializable`, so a leak there is a compile error rather than a runtime risk. That
  is the strongest possible outcome, not a gap.
- **PY/JV `P*`**: the behaviour is correct but the assertion is missing — Python has no
  `model_dump_json()` test on `OidcTokenSet`/`AuthorizationRequest`, and Java has no Jackson test
  on the three DTOs (only on a bare `Sensitive`). Follow-up F-11/F-12.
- **GO `D`**: `type Sensitive string` means `string(tok.AccessToken)` reaches the raw value from any
  package. That is an *explicit* conversion and it is the shape §7's Go row itself prescribes;
  contract 1.5 §7 rule 2 now says so.
- **JV/KT `F`**: `Sensitive.expose()` is package-private (Java, in `io.axiam.sdk`) and `internal`
  (Kotlin). Both SDKs return `OidcTokenSet` objects whose `access_token`/`refresh_token`/`id_token`
  **the caller cannot read at all**. This is not a §7 violation — under contract 1.5 rule 3 a
  module-private accessor stays conformant — but it defeats the purpose of §12, which exists to
  hand tokens to a relying party so it can forward, persist, and later revoke them. Highest-value
  follow-up (F-02, F-03).

### 1.4 PKCE and ID-token validation

| Rule | TS | PY | GO | RS | PHP | JV | C# | KT |
|---|---|---|---|---|---|---|---|---|
| PKCE `S256` only; `plain` structurally unreachable | P | P | P | P | P | P | P | P |
| RFC 7636 Appendix B vector asserted in a real test | P | P | P | P | P | P | P | P |
| §12.4 r1 `alg` = `EdDSA`, checked before signature work (+ failing test) | P | P | P | P | P | P | P | P |
| §12.4 r2 signature + `kid`, one re-fetch, no-`kid` rejected (+ test) | P | P | P | P | P | P | P | P |
| §12.4 r3 `iss` exact string match (+ test) | P | P | P | P | P | P | P | P |
| §12.4 r4 `aud` contains `client_id`, `azp` when multiple (+ test) | P | P | P | P | P | P | P | P |
| §12.4 r5 `exp`/`iat`/`nbf`, skew clamped ≤60 s (+ test) | P | P | P | P | P | P | P | P |
| §12.4 r6 `nonce` constant-time compare (+ test) | P | P | P | P | P | P | P | P |
| §12.4 r7 all-or-nothing discard (+ test) | P | P | P | P | P | P\* | P\* | P\* |
| Exactly the seven contract reason codes, no eighth | P | P | P | P | P | P | P | P |
| No "skip validation" option on any public API | P | P | P | P | P | P | P | P |

All eight use the contract's reason-code strings verbatim, and all eight independently converged
on the same many-to-one mappings (`token_expired` for every time failure, `unknown_kid` for a
missing `kid`, `invalid_alg` for an unparseable header). Contract 1.5 §12.3 rule 3 now records that
vocabulary as closed and pins those mappings, so the convergence is no longer accidental.

`P*` on rule 7 for Java, C#, and Kotlin: validation demonstrably precedes token-set construction,
so no partial object can exist, but the tests only assert that an error is thrown — they do not
positively assert the access/refresh token is absent from the outcome (TS, Python, Go, Rust, PHP
all do). Follow-up F-13.

### 1.5 Cross-cutting rules

| Rule | TS | PY | GO | RS | PHP | JV | C# | KT |
|---|---|---|---|---|---|---|---|---|
| Stateless: no `state`/`nonce`/`code_verifier` in SDK or process-global state | P | P | P | P | P | P | P | P |
| State store: 10-min TTL, clamped as a maximum | P | P | P | P | P | P | P | P |
| State store: single-use `consume`, atomic delete-before-check | P | P | P | P | P | P | P | P |
| State store: lazy sweep, no background timer/thread | P | P | P | P | P | P | P | P |
| Discovery cache TTL floor ≥ 5 min | P | P | P | P | P | P | P | P |
| Discovery cache single-flight (tested with N concurrent cold callers) | P | P | P | P | P | P | P | P |
| Discovery cache per-origin, never tenant-keyed, never process-global | P | P | D | P | P | P | D | D |
| Token endpoint: form-encoded body, never JSON | P | P | P | P | P | P | P | P |
| `tenant_id` sent as a **query** parameter, never a body field | P | P | P | P | P | P | P | P |
| `client_secret_post` only — no `Authorization: Basic` anywhere | P | P | P | P | P | P | P | P |
| `X-Tenant-ID` still emitted on `/oauth2/*` | P | P | P\* | P | P | P\* | P\* | P |
| Grant form-field sets exactly per §12.1; optionals omitted not emptied | P | P | P | P | P | P | P | P |
| Endpoints read from the discovery document, never hardcoded | P | P | P | P | P\* | P | P | P |
| `sso_complete` goes through the §4 cookie-jar path | P | P | P | P | P | P | P | P |
| `sso_complete` performs the same post-login session sync as `login()` | P | P | P | **F** | P | P | P | P |
| `revoke`: 200 = success, idempotent on unknown token, 5xx = network error | P | D | P | P | P | P | P | P |
| Spaces in authorization-URL query values encoded `%20`, not `+` | P | P | P | **F** | P | P | P | P |
| Reserved-param collision raises a programming error, not the taxonomy | P | P | P | D | P | P | P | P |
| `oidc_begin` takes `client_id` from client config, not per call | P | P | P | P | P | P | P | P |
| `AuthorizationRequest` = exactly `url`/`state`/`nonce`/`code_verifier` | P | P | P | P | P | P | P | P |
| `sso_start` defaults tenant/org from session, prefers UUID, raises client-side | P | P | P | P\* | P | P | P | P |
| No new **runtime** dependency added | P | P | P | D | P | P | P | P |
| No TLS-bypass surface anywhere in shipped source | P | P | P | P | P | P | P | P |
| Conformance statement updated to claim §12 | P | P | P | P | P | P | P\* | P |

- **GO/C#/KT `D`** on cache keying: the cache is two per-instance scalar fields with no explicit
  origin key, safe because a client is bound to one base URL for life. Contract 1.5 §12.3 rule 6
  now states that a per-client-instance cache satisfies the origin requirement by construction.
  Legal, and the previous wording was self-contradictory anyway.
- **`X-Tenant-ID` `P*`** (Go, Java, C#): the header interceptor returns early for a foreign host,
  and §12 builds absolute URLs from the discovery document. A deployment whose document advertises
  `token_endpoint` on a different host than `base_url` would silently drop the header. Harmless
  today (the `/oauth2/*` handlers never read it — see §3 below) but untested in all eight repos.
  Follow-up F-15.
- **PHP `P*`** on endpoint sourcing: the pre-existing §10 `JwksVerifier` retains a hardcoded
  `baseUrl + '/oauth2/jwks'` fallback used only when discovery is unavailable or cross-origin. The
  §12 path always uses `jwks_uri`.
- **PY `D`** on `revoke`: Python accepts **only** `200`; a `204` would raise. Conformant to the
  contract as worded (1.4 and 1.5 both make `200` the MUST), but the other seven accept any 2xx,
  which is what 1.5 recommends. Follow-up F-08.
- **RS `F`** on `sso_complete`: it captures cookies and re-syncs CSRF but never calls
  `absorb_session_cookies`, so unlike every sibling it does not seed the token manager or resolve
  `tenant_id`/`org_id`. A subsequent `refresh()` fails with "no access token to refresh". F-05.
- **RS `F`** on `%20`: **verified by execution** (see §5). F-04.
- **RS `D`** on the collision guard: it raises `AxiamError::Network`, a §2 taxonomy error, where the
  other seven raise the language's programming-error type. Legal under the contract (which is silent
  on the type) but it misclassifies a caller bug as a transport failure. F-09.
- **RS `D`** on dependencies: `Cargo.toml` gains two `[dependencies]` entries (`getrandom`,
  `base64`), both already unconditional transitive deps. **`Cargo.lock` is unchanged by the
  commit** — verified — so zero new crates enter the graph and the vulnerability-scan intent is
  satisfied. Reported as `D`, not `F`.
- **C# `P*`**: `README.md:20` claims §1–§12 but the checklist heading immediately below still reads
  "### §1–§11 conformance checklist". Cosmetic. F-16.

### 1.6 §9 single-flight refresh — the one row with real failures

| Rule | TS | PY | GO | RS | PHP | JV | C# | KT |
|---|---|---|---|---|---|---|---|---|
| `oidc_refresh` burst of N produces exactly **one** wire call | P | P | P | **F** | **F** | P | P | P |
| That one outcome is shared with all N callers (§9 rule 2) | P | P | P | **F** | **F** | P | P | P |
| §9 test requirement satisfied for `oidc_refresh` (N ≥ 5) | P (3) | P (6) | P (10) | **F** | **F** | P (5) | P (5) | P (6) |
| Guard mechanism | shared `Promise` + session guard, bounded 3 retries | coalescer + `run_exclusive` | own `chan` future | **bare `Mutex<()>`** | `{ran,promise}` + bounded 3 retries | `SingleFlight` + `runExclusive` (bound 3) | `SemaphoreSlim` + cached `Task<T>` | `Mutex` + shared `Deferred` |

TypeScript's N is 3 in its guard-contention test but its coalescing test asserts one wire call for
concurrent callers; treated as satisfied.

Adjudicated in §2.2 and §2.3 below.

### 1.7 Contract MAYs — divergence here is not a defect

| Item | TS | PY | GO | RS | PHP | JV | C# | KT |
|---|---|---|---|---|---|---|---|---|
| `login_client_credentials` credential adoption (§12.1 MAY) | D opt-in | D skipped | D opt-in | D skipped | D opt-in | D skipped | D flag + `NotSupportedException` | D skipped |
| Optional `OidcStateStore` offered (§12.3 r1 MAY) | D yes | D yes | D yes | D yes | D yes | D yes | D yes | D yes |

Where adoption **is** implemented (TS, Go, PHP), it was verified in all three that the adopted
token (a) is opt-in and default-off, (b) lives behind `Sensitive` in a private field, (c) is
attached only as an `Authorization: Bearer` header by a private interceptor that explicitly skips
`/oauth2/*`, and (d) never enters the cookie jar or a public property. All three carry a test
asserting the token endpoint sees no `Authorization` header. **Five different positions on one MAY,
zero defects.**

---

## 2. Adjudication of the hard problems

### 2.1 §7 vs §12 — the token-accessor conflict (highest priority)

**What §7 said (1.4):** "The raw token string MUST NOT be exposed via any public getter API," and
internal code reaches it "via a crate/module-private method or friend function, not a public API."
**What §12 requires:** returning `access_token`/`refresh_token`/`id_token` *to the caller*, who
must read them to persist, forward, or later revoke them. These are mutually unsatisfiable.

**What all eight actually did** (read from source, not reports):

| SDK | Wrapper | Accessor | Visibility | Changed by this commit? |
|---|---|---|---|---|
| TypeScript | `class Sensitive<T>`, private `#value` | `expose()` | public (doc-tagged `@internal`) | no — doc comments only |
| Python | `pydantic.SecretStr` | `get_secret_value()` | public by design | no |
| Go | `type Sensitive string` | `expose()` unexported **plus** `string(x)` conversion | effectively public | no |
| Rust | newtype `Sensitive<T>(T)` | `expose()` | **widened `pub(crate)` → `pub`** | **yes** |
| PHP | `final class` + static `WeakMap` | `reveal()` | public | no |
| Java | `final class Sensitive` | `expose()` | **package-private** (`io.axiam.sdk`) | no |
| C# | `readonly struct Sensitive<T>` | `Expose()` (+ public `Wrap()`) | **both added public** | **yes** |
| Kotlin | `class Sensitive<T>`, private `value` | `expose()` | **`internal`** | no |

So six of eight are readable by a caller; **Java and Kotlin are not** — their `OidcTokenSet`
carries tokens no consumer of the library can extract. Redaction, by contrast, is airtight in all
eight, including the sinks a naive wrapper misses (Go `%#v`/`Format`/`GoString`/`MarshalJSON`, Node
`util.inspect`, Java `@JsonSerialize` + non-`Serializable`, C# `JsonConverterFactory` + suppressed
struct equality, PHP's zero-introspectable-properties `WeakMap` trick, Kotlin's hand-written
`toString` overrides on `data class` DTOs).

**Ruling.** There is no single rule that *requires* a public accessor and that all eight satisfy,
so §7 must permit rather than require one. Contract 1.5 splits §7 into four numbered rules:

1. **Redaction — unconditional MUST**, now enumerating the easily-missed sinks explicitly. No
   other section relaxes it.
2. **No implicit reachability — MUST**: no public field, `Deref`, implicit conversion, auto-unbox,
   or value-comparing inherited equality. Go's named-type conversion is named as an *explicit*
   conversion and accepted for that language, since §7's own Go row prescribes that shape.
3. **One explicit accessor — MAY, and RECOMMENDED where §12 ships.** A module-private accessor
   stays conformant, but then the §12 token set is unreadable by the caller, so the SDK **SHOULD**
   widen it — and widening is explicitly noted as non-breaking and additive.
4. **Point-of-use discipline — MUST**: never pass the accessor's result to a sink.

A rationale paragraph records why the text changed, so the next reader does not re-derive the
conflict. The **C and C++ rows are untouched**, with a sentence explaining that both defer §12
and therefore never hand token material to a caller — rule 3 has nothing to enable there, and
would apply unchanged to any later port.

This makes all eight conformant **and** keeps the Java/Kotlin gap visible as a SHOULD violation
rather than papering over it. The gap is a functional defect, recorded as F-02/F-03: high severity,
non-blocking (widening `internal`/package-private to public breaks no one and can land after
merge), but it must ship before either SDK is released advertising §12.

### 2.2 Rust's §9 single-flight is partial — conformance gap, not a contract flaw

**Verified facts.** `AxiamClientInner.oidc_refresh_guard` is a bare `tokio::sync::Mutex<()>`
(`src/client.rs:465`), acquired at `src/oidc/exchange.rs:530-532`. It holds no result slot — there
is no `OnceCell`, `Shared`, `broadcast`, or `Option<Result<…>>` anywhere near it. `Sensitive<T>`,
`OidcTokenSet`, and `AxiamError` are each **not** `Clone` (verified derive-by-derive; `AxiamError`
boxes a `dyn StdError` and cannot easily become `Clone`). Consequently N concurrent callers produce
**N wire calls**, issued serially. There is also **no concurrency test for `oidc_refresh` at all**
— the repo's only §9 burst test covers the §1 cookie path via a different guard.

**Ruling: this is a conformance gap requiring a Rust code fix, not grounds to amend §9.** Three
reasons:

1. **The observable behaviour genuinely differs, and differs badly.** AXIAM refresh tokens are
   opaque, server-stored, and **single-use with rotation**. Serialization without sharing therefore
   means callers 2..N deliberately replay an already-consumed refresh token and each receives
   `invalid_grant`. Seven SDKs: N callers, one wire call, all N succeed. Rust: N callers, N wire
   calls, one succeeds and N−1 fail with an auth error. That is not an implementation detail; it is
   the difference the rule exists to prevent.
2. **§9 rule 2 is already a MUST in contract 1.4.** Nothing new is being demanded. Amending §9 to
   permit serialization would weaken a correctness rule for all eleven languages to accommodate one
   port, and would silently license the same regression elsewhere.
3. **The language does not make sharing impractical.** The claim rests on `Sensitive`/`AxiamError`
   not being `Clone`, but `Sensitive` already has a working `pub(crate) fn clone_inner()` for
   exactly this kind of duplication, and cloning a redacted wrapper cannot leak anything — every
   other SDK's wrapper is freely copyable (C#'s is a `struct`). The non-`Clone` decision was about
   preventing leak paths, and a `Clone` impl is not one.

**Precise fix (F-01).** In `axiam-rust-sdk`:

1. `src/sensitive.rs` — add `impl<T: Clone> Clone for Sensitive<T>` (a manual impl, not a derive,
   with a doc comment noting that duplicating a redacted wrapper cannot leak: only `expose()` can).
2. `src/oidc/exchange.rs` / `src/oidc/id_token.rs` — derive `Clone` on `OidcTokenSet`,
   `IdTokenClaims`, and `Audience`.
3. `src/error.rs` — add `pub(crate) fn clone_for_waiter(&self) -> AxiamError`, reconstructing the
   same variant field-wise (`OAuthProtocolError` is two `String`s and `IdTokenFailureReason` is a
   fieldless enum, so `Auth` clones exactly; other variants clone with `source: None`).
4. `src/client.rs` — replace `oidc_refresh_guard: tokio::sync::Mutex<()>` with
   `oidc_refresh_inflight: tokio::sync::Mutex<Option<tokio::sync::broadcast::Sender<Result<OidcTokenSet, Arc<AxiamError>>>>>`.
   `tokio`'s `sync` feature is already enabled — **no new dependency**.
5. `src/oidc/exchange.rs::oidc_refresh` — leader/waiter election: under the mutex, if a `Sender`
   is present, `subscribe()`, drop the lock, `recv().await`, and map `Arc<AxiamError>` back through
   `clone_for_waiter`; otherwise create the channel, publish it, drop the lock, perform the single
   `post_token`, clear the slot under the lock, then `send` the result. The public signature
   `Result<OidcTokenSet, AxiamError>` is preserved.
6. `tests/oidc_token_ops_test.rs` — add the §9 burst test: ≥5 concurrent `oidc_refresh` calls
   against a counting `/oauth2/token` mock, asserting exactly **one** request **and** that all
   callers observe the same `access_token`. Mirror `tests/single_flight_refresh_test.rs`.

**This is the sole reason `axiam-rust-sdk` is BLOCKED.** Merging it would ship a README claiming
"§1–§12 conformance" while violating a §12-referenced MUST and omitting a MUST-level test.

### 2.3 Five guard-contention designs — observably equivalent, and the 3-attempt bound should not have propagated

| SDK | Coalescer | Interaction with the §1 guard | Observable result for N concurrent callers |
|---|---|---|---|
| TS | shared `Promise` in `#pendingRefresh` | runs inside the session `refreshGuard`; bounded 3 retries if busy | 1 wire call, shared outcome |
| Python | `_SyncSingleFlight` / `_AsyncSingleFlight` | `RefreshGuard.run_exclusive_sync/async`, blocking, no retry | 1 wire call, shared outcome |
| Go | own `oidcRefreshFuture` (mutex + `chan`) | deliberately does **not** use `Client.guard` | 1 wire call, shared outcome |
| Java | `SingleFlight.run` | `RefreshGuard.runExclusive`, bounded 3 attempts | 1 wire call, shared outcome |
| C# | cached `Task<OidcTokenSet>` + `SemaphoreSlim(1,1)` | dedicated instance, not the cookie guard | 1 wire call, shared outcome |
| Kotlin | shared `CompletableDeferred` | dedicated instance of the §9 Kotlin mechanism | 1 wire call, shared outcome |
| PHP | `Session::refreshGuard()` → `{ran, promise}` | bounded 3 retries; on `ran=false` waits then **re-acquires** | **N wire calls** (see below) |
| Rust | none | bare `Mutex<()>` | **N wire calls** |

**Verdict on the six that pass: observably equivalent, and that is what matters.** A behavioural
contract governs what an observer can detect — one wire call per burst, one outcome delivered to
everyone, no stale token set, no refresh-retry loop. All six deliver exactly that. The differences
(shared promise vs. condition variable vs. channel vs. cached task; reusing the §1 guard object vs.
a dedicated instance of the same mechanism) are invisible from outside and should never have been
contract-relevant.

**Verdict on the TypeScript 3-attempt bound: an implementation detail that should not have been
propagated.** It exists only because TS's `RefreshGuard` returns `Promise<void>`, so the refreshed
token set cannot travel back through the guard and the caller must loop to re-acquire it. It is not
a property of the OIDC flow. It nonetheless propagated to PHP and Java, and in PHP it is where the
result-sharing was lost: because `oidcRefresh` treats `ran === false` as "the guard is busy with
*someone else's* refresh", a second concurrent `oidcRefresh` caller waits on the leader's promise
and then issues **its own** token POST — structurally the same defect as Rust's. The mitigating
facts are that vanilla PHP has no concurrency for these synchronous calls (`refreshPromise` is a
per-instance property and `->wait()` blocks), so the path is only reachable under Fibers/Swoole,
and that PHP has no `oidcRefresh` burst test to expose it either way. Recorded as F-06 (high
severity, non-blocking).

**Contract wording adopted (1.5).** §9 gains **rule 5**, which pins observable behaviour and frees
mechanism:

- Rules 1–4 constrain observable behaviour only; the per-language table is guidance, not a mandate.
- An operation may use a **dedicated instance of an equally strong mechanism** where the shared
  guard's API is specialized to another token namespace (naming the real reason: the §1 guard
  compares cookie-access-token freshness, which is meaningless for a `refresh_token` grant) — but
  never a weaker mechanism.
- Where an implementation composes an operation-specific coalescer *with* the shared guard, a
  **bounded** (never unbounded) wait is permitted, exhaustion MUST raise `AuthError` rather than
  return a stale token set, and **the specific bound is explicitly not part of this contract**.

§9 rule 2 additionally now states the observable requirement in one sentence, with the single-use
rotation reasoning, so "serialize but do not share" can never again be read as conformant. §9's
test requirement is clarified to apply **per refresh operation**, so `oidc_refresh` needs its own
burst test. §12.1's "MUST run under the §9 single-flight refresh guard" becomes "MUST be governed
by a §9-conformant single-flight guard", pointing at rule 5.

### 2.4 Verification of the numbers I was given

All eight suites and all eight coverage gates were **re-run locally**. Everything reported by the
implementing agents held up; Rust's previously unmeasured coverage clears its floor.

| SDK | Tests reported | Tests measured | Coverage reported | Coverage measured | Floor | Gate |
|---|---|---|---|---|---|---|
| TypeScript | 465 / 97.24% lines | **465 passed, 49 files** | 97.24 L / 92.51 B | **97.24 L / 92.51 B / 97.02 S / 97.58 F** | 94 L / 86 B / 94 S / 95 F | **PASS** |
| Python | 434 / 98.88% | **434 passed** | 98.88 | **98.88** | 97 (`fail_under`) | **PASS** |
| Go | ~116 / 94.7% | **all packages ok** (448 incl. subtests) | 94.7 | **94.7** | 94 (`coverage.yml`) | **PASS** |
| Rust | 75 new tests / **never measured** | all test binaries pass | — | **91.52% lines** (90.93 regions, 86.55 functions) | 90 lines | **PASS**, margin 1.52 |
| PHP | 436 / 96.23% | **436 tests, 1115 assertions** | 96.23 | **96.23** | 94 (`coverage.yml`) | **PASS** |
| Java | 350 / 94.4% JaCoCo | **350 passed, 0 failures** | 94.4 | **94.02** (1619/1722 lines) | 0.93 BUNDLE LINE COVEREDRATIO | **PASS**, margin 0.0102 |
| C# | 328 / 96.03% | **328 passed** (37 + 291) | 96.03 | **96.05** (union-merged lcov) | 94 (`coverage.yml`) | **PASS** |
| Kotlin | 209 / 99.02% Kover | **209 passed, 0 failures** | 99.02 | **99.02** (1209/1221 lines) | `minBound(98)` LINE | **PASS**, margin 1.02 |

Notes on the two thinnest margins and the one previously-unknown number:

- **Rust 91.52% vs floor 90** is real but thin, and the §12 code is where the slack is:
  `oidc/discovery.rs` 81.13% lines, `oidc/exchange.rs` 86.96% (51 uncovered lines across 850
  source lines with **zero** inline unit tests), `oidc/authorize.rs` 90.43%. Roughly 15 untested
  error arms sit in `exchange.rs` — malformed-body parse failures on all four endpoints, the
  `oidc_endpoint_url` parse-failure arm, and a **dead** tenant-missing branch in `sso_start`
  (unreachable: `TenantIdentifier` is a two-variant enum and §5 guarantees one is set). Adding the
  F-01 concurrency test plus a few malformed-body tests would restore margin. F-10.
- **Java 94.02% vs floor 0.93** leaves 0.0102 of headroom. Four one-line delegating overloads
  (`oidcRefresh(Sensitive)`, `oidcRefreshAsync(Sensitive)`, `introspect(Sensitive)`,
  `revoke(Sensitive)`) have no test referencing them. F-17.
- I could not measure a **branch** figure for Go, PHP, or C# — none of the three configures a
  branch gate, and their floors are line-based, which is what I measured.

Additional facts established by execution rather than reading:

- **Rust emits `+` for spaces in the authorization URL.** `url::Url::query_pairs_mut()` returns a
  `form_urlencoded::Serializer`, so `append_pair("scope", "openid profile email")` yields
  `scope=openid+profile+email`. Confirmed with a standalone program against the same `url 2.5.8`
  the repo locks. All seven siblings emit `%20` (TS post-processes `URLSearchParams`, Python uses
  `quote(safe='')`, Go post-processes `Encode()`, PHP uses `rawurlencode`, Java/Kotlin use
  OkHttp `addQueryParameter`, C# uses `Uri.EscapeDataString`). F-04.
- **Rust's `Cargo.lock` is unchanged by the commit**, confirming that `getrandom` and `base64` were
  already in the graph and that the two new `[dependencies]` entries add no crates.
- **The mixed slug-header / UUID-query pair is safe.** `crates/axiam-api-rest/src/handlers/oauth2.rs`
  reads the tenant exclusively from `web::Query<TenantQuery>` and never inspects `X-Tenant-ID`;
  `/oauth2/token` is a public path (`middleware/authz.rs:222`) and CSRF-exempt
  (`middleware/csrf.rs:71`). The header is inert on those endpoints.

---

## 3. Contract 1.5 changes made

All edits are in `/home/user/axiam/sdks/CONTRACT.md` (1090 → 1374 lines) and are non-breaking and
clarifying. **Every change describes behaviour all eight SDKs already exhibit**, with two
deliberate exceptions noted below.

| # | Section | Change |
|---|---|---|
| 1 | §7 | Restructured "Required behavior" into four numbered rules separating unconditional redaction (r1) from the explicit-accessor MAY (r3), with no-implicit-reachability (r2) and point-of-use discipline (r4). Added a rationale paragraph and a sentence keeping the C/C++ rows' intent intact. **§2.1 ruling.** |
| 2 | §9 r2 | Added the observable requirement — one wire call per burst, that outcome shared with all N — with the single-use-rotation reasoning. |
| 3 | §9 r5 (new) | Mechanism is free; a dedicated guard instance for a second token namespace is permitted; a bounded wait for a shared guard is permitted and its bound is explicitly not contract-worthy. **§2.3 ruling.** |
| 4 | §9 test requirement | Clarified: assert shared outcome too, and apply the requirement **per refresh operation**. |
| 5 | §2 construction rules | The `"<error>: <error_description>"` requirement binds the `message` *field*; a rendered prefix (Go `Error()`, Rust `Display`) is fine. Field names follow per-language casing; Go's `ErrorCode` rename accepted. |
| 6 | §12.1 note 2 | Documented that a slug `X-Tenant-ID` legitimately accompanies a UUID `?tenant_id=` (the handlers read only the query parameter), and that a slug-only client with no resolved UUID cannot call five of the nine operations. **Defect 4.** |
| 7 | §12.1 note 5 | Corrected `revoke`: `200` MUST be success, any other `2xx` MAY be (RECOMMENDED), `5xx` MUST NOT be and stays a `NetworkError`. Removed 1.4's "Only 401 is an error". Added the mandatory idempotence test. **Defect 7.** |
| 8 | §12.1 | `client_id` removed from `oidc_begin`'s per-call inputs; stated that it comes from client configuration for §12.4 r4 consistency, and that a missing one fails fast with no wire call (taxonomy **or** programming error). **Defect 5.** |
| 9 | §12.1 | New paragraph: `AuthorizationRequest` deliberately carries **no** `redirect_uri`; the caller must carry it between begin and exchange; the store entry is where the glue parks it. Adding the field is explicitly deferred. **Defect 6, resolved as "document", matching all eight.** |
| 10 | §12.1 | `oidc_refresh`: "MUST run under the §9 guard" → "MUST be governed by a §9-conformant single-flight guard", citing r5, r2's observable requirement, and the per-operation test requirement. |
| 11 | §12.2 | New normative paragraph permitting either host object, with the browser-bundle rationale; names stay fixed; a separate host must be documented and must not split the nine. **Defect 8.** |
| 12 | §12.3 r1 | Enumerated store-entry fields (incl. `redirect_uri`); TTL is a clamped maximum; sweeping MUST be lazy with no background timer/thread. |
| 13 | §12.3 r3 | Declared the seven reason codes a **closed** vocabulary and pinned the many-to-one mappings — every r5 time failure → `token_expired`, no-`kid` → `unknown_kid`, unparseable header → `invalid_alg`, unclassified → `invalid_signature`. **Defect 3, resolved by documenting rather than adding codes, since adding any would break all eight.** |
| 14 | §12.3 r6 | Rewrote the self-contradiction: sharing one document across tenants of an origin is correct and intended; a per-client-instance cache satisfies the origin requirement by construction; a process-global/cross-client cache MUST key on the normalized origin. Added the TTL-floor-raising clarification. **Defect 1.** |
| 15 | §12.4 r2 | "One JWKS re-fetch then fail" is normative **per cooldown window**, not per token, with the fetch-amplification reasoning and the observable requirements. **Defect 2.** |
| 16 | §12.4 r5 | `exp` and `iat` are both required; skew above 60 s is clamped, not rejected; every failure reports `token_expired`. |
| 17 | Conformance Statement | Added a per-SDK table for the eight §12 implementers (recording Kotlin's pre-existing §8 carve-out and both async conventions) and the three unchanged deferrers; recorded that credential adoption is a MAY with five legal positions. |
| 18 | Breaking Changes Log | Added the contract 1.5 entry in the existing format, itemising all of the above. |
| 19 | Version footer | `1.4` → `1.5` with the new provenance clause appended in the existing style. |

**The two deliberate exceptions to "all eight already satisfy it".** Change 2 (§9 r2's observable
statement) and change 4 (the per-operation test requirement) restate MUSTs that contract 1.4
*already* imposed; Rust fails the first and Rust and PHP fail the second. I am not creating new work
by contract fiat — I am removing the ambiguity that let a pre-existing MUST be read as satisfied.
Both gaps appear in the follow-up list with concrete fixes, and both are called out here rather than
being buried.

**Deliberately not changed:** `AuthorizationRequest` did **not** gain a `redirect_uri` field. All
eight ship the four-field shape, so adding it would invent work and change an already-published
type; the footgun is documented instead. No reason code was added, for the same reason.

**Re-synced** to all eight SDK repos as `<repo>/CONTRACT.md` (byte-identical to the source).
Conformance statements were checked in all eight: each already names the right section range, so
seven required no editing (Kotlin's `§1–§7, §9–§12` is correct given its pre-existing §8 deferral
and now matches the new conformance table). One was corrected: `axiam-csharp-sdk/README.md:27`'s
checklist heading still read "§1–§11" under a statement claiming §1–§12 — see F-16. Contract 1.5
changes no claimed section range, so no statement's `§1–§12` needed to move.

---

## 4. Follow-up list (severity-ordered)

Nothing below is a hot-fix I applied — this review changed contract text, vendored copies, and this
document only. Exactly **one** item blocks a merge.

### Blocking

**F-01 — Rust `oidc_refresh` violates §9 rule 2, and its §9 test is absent. BLOCKS MERGE.**
Repo `axiam-rust-sdk`. Files `src/client.rs:465`, `src/oidc/exchange.rs:526-560`,
`src/sensitive.rs`, `src/error.rs`, `src/oidc/id_token.rs`, `tests/oidc_token_ops_test.rs`.
Defect: the guard is a bare `tokio::sync::Mutex<()>` with no result slot, so N concurrent callers
issue N serialized wire calls; with single-use rotating refresh tokens callers 2..N replay a
consumed token and fail `invalid_grant`. No `oidc_refresh` concurrency test exists.
Fix: the six steps in §2.2 above (manual `Clone` for `Sensitive<T>`; `Clone` on `OidcTokenSet`/
`IdTokenClaims`/`Audience`; `AxiamError::clone_for_waiter`; swap the mutex for
`Mutex<Option<broadcast::Sender<Result<OidcTokenSet, Arc<AxiamError>>>>>` — `tokio`'s `sync` feature
is already on, so no new dependency; leader/waiter election in `oidc_refresh`; the ≥5-caller burst
test asserting one request and one shared `access_token`). Severity **critical**.

### High — fix before any release advertising §12; do not block merge

**F-02 — Java: a §12 caller cannot read the tokens it is handed.**
Repo `axiam-java-sdk`, file `src/main/java/io/axiam/sdk/Sensitive.java:65`. `String expose()` is
package-private in `io.axiam.sdk`, so a consumer holding an `OidcTokenSet` (package
`io.axiam.sdk.oidc`) cannot extract `accessToken()`/`refreshToken()`/`idToken()` at all. Fix: make
`expose()` `public`, with Javadoc citing contract 1.5 §7 rule 3 (as Rust and C# did); add a test
asserting a caller outside `io.axiam.sdk` can read an exchanged access token, and one asserting
`toString`/Jackson still redact. Widening is additive and breaks nothing. Severity **high**.

**F-03 — Kotlin: same defect.**
Repo `axiam-kotlin-sdk`, file `src/main/kotlin/io/axiam/sdk/Sensitive.kt:28`. `internal fun
expose(): T`. Same fix (make it `public`, KDoc the §12 reason, add the caller-readability and
still-redacts tests). Severity **high**.

**F-04 — Rust emits `+` instead of `%20` in the authorization URL.**
Repo `axiam-rust-sdk`, file `src/oidc/authorize.rs:223-233`. `url::Url::query_pairs_mut()` is a
`form_urlencoded::Serializer`, so a multi-valued `scope` becomes `scope=openid+profile+email` —
verified by execution. §12.1 rule 5 requires RFC 3986 percent-encoding and all seven siblings emit
`%20`. Fix: build the query with an explicit RFC 3986 encoder over the unreserved set
`[A-Za-z0-9-._~]` (Kotlin's `percentEncode` is the closest model), or keep `query_pairs_mut()` and
post-process `+` → `%20` as TypeScript and Go do; then add an assertion on the **raw** URL string
(`%20` present, `+` absent) — the existing test at `tests/oidc_pkce_test.rs:72-78` reads the value
back through `query_pairs()`, which decodes `+` to a space and so passes either way. Severity
**high** (interop and cross-SDK byte-consistency, not a functional break: Actix's
`serde_urlencoded` decodes `+` as a space).

**F-05 — Rust `sso_complete` does not perform the post-login session sync.**
Repo `axiam-rust-sdk`, file `src/oidc/exchange.rs:801-845`. It captures cookies and re-syncs CSRF
but never calls `absorb_session_cookies` (`src/rest/auth.rs:184`), so unlike all seven siblings it
does not seed the token manager or resolve `tenant_id`/`org_id`; a subsequent `refresh()` fails
with "no access token to refresh". Fix: call `absorb_session_cookies()` on success, mirroring
`login`/`verify_mfa`; add a test asserting `resolved_org_id()` is populated and `refresh()` works
after `sso_complete`. Severity **high**.

**F-06 — PHP `oidcRefresh` does not share one result across concurrent callers, and has no burst
test.** Repo `axiam-php-sdk`, files `src/Oidc/OidcClient.php:389-412`, `src/Session.php:214-236`.
On `ran === false` it waits on the leader's promise and then **re-acquires the guard**, issuing its
own token POST — so a second concurrent `oidcRefresh` produces a second wire call and replays a
consumed refresh token. Only reachable under Fibers/Swoole (vanilla PHP has no concurrency for
these synchronous calls), and there is no `oidcRefresh` concurrency test either way. Fix: have
`refreshGuard` distinguish "busy with the same kind" (return the shared promise and **use** its
result) from "busy with a different kind" (wait, then retry), or give `oidcRefresh` its own
coalescer keyed to the OIDC namespace as Go, C#, and Kotlin did; add the §9 burst test.
Severity **high**.

**F-07 — Rust `AxiamError::Auth` is source-breaking and the enum is not `#[non_exhaustive]`.**
Repo `axiam-rust-sdk`, file `src/error.rs:25-47`. Adding `oauth`/`reason` to a public struct variant
makes every downstream `AxiamError::Auth { message: … }` construction `E0063` and every exhaustive
destructure `E0027`; 33 constructions and 9 patterns were rewritten inside the repo, one of them in
a shipped `examples/` file. Fix: add `#[non_exhaustive]` to `AxiamError` (and/or to the `Auth`
variant) so future additive fields cannot break consumers again, and record the break honestly in
the repo `CHANGELOG.md` — it is acceptable at `1.0.0-alpha18` but must not be described as
non-breaking. Severity **high** (documentation and future-proofing; the code works).

### Medium

**F-08 — Python `revoke` accepts only `200`.**
Repo `axiam-python-sdk`, file `src/axiam_sdk/_oidc.py:638`
(`response.status_code == httpx.codes.OK`). Conformant to the contract's MUST but the outlier
against seven SDKs and against 1.5's RECOMMENDED "any 2xx". Fix: accept `200 <= status < 300`;
add a `204` test. Severity **medium**.

**F-09 — Rust's reserved-param collision guard raises a taxonomy error.**
Repo `axiam-rust-sdk`, file `src/oidc/authorize.rs:198-207` returns `AxiamError::Network`. The other
seven raise a programming-error type (`Error`, `ValueError`, plain `error`, `InvalidArgumentException`,
`IllegalArgumentException`, `ArgumentException`), which is what the port brief specified: a caller
passing a reserved `extra_param` is a bug, not a transport failure. Fix: introduce (or reuse) a
non-taxonomy programming-error path, or at minimum document the deviation. Severity **medium**.

**F-10 — Rust §12 coverage is thin and contains a dead branch.**
Repo `axiam-rust-sdk`. `src/oidc/discovery.rs` 81.13% lines, `src/oidc/exchange.rs` 86.96% (850
source lines, **zero** inline unit tests, ~15 untested error arms), `src/oidc/authorize.rs` 90.43%;
total 91.52% against a 90 floor. `src/oidc/exchange.rs:716-724` is unreachable (`TenantIdentifier`
is a two-variant enum and §5 guarantees one is set). Fix: delete the dead branch; add
malformed-body tests for all four parse sites, a failing-discovery test, and an invalid-endpoint-URL
test. F-01's burst test also helps. Severity **medium** (the gate passes today, but the margin is
1.52 points).

**F-11 — Python: no serialization-leak assertion.**
Repo `axiam-python-sdk`, file `tests/test_oidc_redaction.py`. No test exercises
`model_dump_json()` or `model_dump(mode="json")` on `OidcTokenSet`/`AuthorizationRequest`, and
`src/axiam_sdk/_models.py:163-164`'s claim that "`model_dump` redacts" is imprecise: in pydantic
python-mode `model_dump()` returns the `SecretStr` **object**, so the raw value stays reachable off
the returned dict (the existing test passes only because `str(dict)` uses the redacting repr). Fix:
add `model_dump_json()` assertions and correct the comment. Severity **medium**.

**F-12 — Java: no Jackson-leak assertion on the §12 DTOs.**
Repo `axiam-java-sdk`, file `src/test/java/io/axiam/sdk/SensitiveTest.java`. The only Jackson
redaction test targets a bare `Sensitive`; nothing serializes `OidcTokenSet`,
`AuthorizationRequest`, or `OidcStateEntry`. Correct by construction (`@JsonSerialize` is
class-level) but unasserted. Fix: add `ObjectMapper.writeValueAsString` assertions for all three.
Severity **medium**.

**F-13 — Java, C#, Kotlin: §12.4 rule 7 tests are weaker than the rule.**
Files `src/test/java/io/axiam/sdk/AxiamClientOidcCoverageTest.java`,
`tests/Axiam.Sdk.Tests/OidcExchangeTests.cs:374`,
`src/test/kotlin/io/axiam/sdk/oidc/OidcCoverageGapsTest.kt:82`. Each asserts only that an error is
thrown. Fix: mirror the five siblings that additionally assert a sentinel access token
(`"should-never-be-returned"`) appears nowhere in the outcome or the error. Severity **medium**.

**F-14 — Five SDKs rely on a structural, undocumented invariant to keep 401-from-`/oauth2/*` out of
the §9 guard.** Repos `axiam-python-sdk`, `axiam-go-sdk`, `axiam-rust-sdk`, `axiam-php-sdk`,
`axiam-kotlin-sdk`. Each is correct today only because no 401→refresh interceptor sits on the
transport §12 uses; adding one later would silently break the rule (which the three list-based
SDKs are immune to). Fix: add a comment at the transport seam naming the invariant, plus a
regression test asserting a 401 from `/oauth2/introspect` triggers zero `/api/v1/auth/refresh`
calls (Python, Go, Rust, and PHP already have such a test — Kotlin's `hitRefreshEndpoint()` check
is the weakest). Severity **medium**.

**F-15 — `X-Tenant-ID` is dropped on `/oauth2/*` when discovery advertises a foreign host.**
Repos `axiam-go-sdk` (`client.go:313-316`), `axiam-java-sdk` (`AuthInterceptor.java:87`),
`axiam-csharp-sdk` (`Rest/AxiamHttpMessageHandler.cs:171`). The header interceptor returns early
for a non-base-URL host and §12 builds absolute URLs from the discovery document, so a
proxy-fronted deployment loses the header §12.1 note 2 calls unconditional. Harmless today (the
handlers ignore it — verified) but a latent surprise. Fix: emit `X-Tenant-ID` for
discovery-document-derived `/oauth2/*` URLs regardless of host, or document the exception; add a
test in all eight asserting the header on a `/oauth2/token` request (**no repo has one**).
Severity **medium**.

### Low

**F-16 — C# README heading contradicted its own conformance claim. FIXED IN THIS REVIEW.**
Repo `axiam-csharp-sdk`: `README.md:20` claimed §1–§12 while `README.md:27` still read
"### §1–§11 conformance checklist", even though the table below it already carried a §12 row.
Corrected to "§1–§12" as part of the conformance-statement re-sync. No further action.
Severity **low**.

**F-17 — Java: four untested one-line overloads against a 0.0102 coverage margin.**
Repo `axiam-java-sdk`, `AxiamClient.java:1061`, `:1079`, `:1149`, `:1195`
(`oidcRefresh(Sensitive)`, `oidcRefreshAsync(Sensitive)`, `introspect(Sensitive)`,
`revoke(Sensitive)`). Fix: one test each, or route the `String` overloads through them.
Severity **low**.

**F-18 — PHP `AuthError`'s new `$reason` is the second positional parameter.**
Repo `axiam-php-sdk`, `src/Core/AuthError.php:24-28`. Any downstream caller passing `$previous`
positionally breaks. No such site exists in the repo. Fix: move `$reason` last or make it
named-only. Severity **low**.

**F-19 — Rust doc link points at the wrong file for the RFC 7636 vector.**
`src/oidc/authorize.rs:87` says the Appendix B vector is verified in `tests/oidc_pkce_test.rs`; it
is actually at `src/oidc/authorize.rs:251`. Also `src/oidc/id_token.rs:31`'s `ID_TOKEN_ALG` is a
public constant with zero references anywhere. Fix: correct the link, remove or use the constant.
Severity **low**.

---

## 5. What I verified by execution vs. by reading

### Verified by execution (I ran it)

- **All eight test suites**, from a clean or force-rerun state: TypeScript 465/465 (`vitest run`),
  Python 434/434 (`pytest`), Go all packages ok (`go test ./...`), Rust all test binaries ok (via
  `cargo llvm-cov`, exit 0), PHP 436 tests / 1115 assertions (`phpunit`), Java 350/350 with 0
  failures/errors (`mvn -o verify`, parsed from `target/surefire-reports`), C# 328/328 (37 + 291,
  `dotnet test`), Kotlin 209/209 (`./gradlew clean test --rerun-tasks` — an initial run came back
  `UP-TO-DATE` from a warm build directory and was discarded).
- **All eight coverage gates**, using each repo's own CI command and floor: TypeScript vitest
  thresholds, Python `fail_under = 97`, Go's `awk` 94 floor over the scoped profile, Rust
  `cargo llvm-cov report --fail-under-lines 90` (exit 0, **91.52% lines**), PHP's 94 floor via
  `pcov`, Java's JaCoCo `BUNDLE`/`LINE`/`COVEREDRATIO` `0.93` (`mvn verify` exit 0, ratio recomputed
  from `jacoco.csv`), C#'s 94 floor over a properly union-merged lcov, Kotlin `koverVerify`
  `minBound(98)` (exit 0, 99.02% recomputed from the Kover XML). **Every gate passes.**
- **`cargo-llvm-cov` was not installed**; I installed it plus `llvm-tools-preview` and ran the exact
  CI command, resolving the one number nobody had.
- **The Rust `+`-vs-`%20` defect**, with a standalone program against the same `url 2.5.8` the repo
  locks: `append_pair("scope", "openid profile email")` → `scope=openid+profile+email`.
- **Rust's `Cargo.lock` is unchanged** by the commit (`git show --stat HEAD -- Cargo.lock` empty).
- **The server's tenant handling on `/oauth2/*`**, by reading the handler and its middleware
  registrations: query-only, public path, CSRF-exempt.
- **Per-file Rust coverage** for the §12 modules, from the llvm-cov report.

### Verified by reading source (not executed)

- The whole conformance matrix in §1 apart from the test-execution and coverage rows: every naming,
  argument-order, error-mapping, `Sensitive`-wrapping, redaction-sink, PKCE, ID-token-rule,
  state-store, discovery-cache, wire-shape, cookie-jar, dependency, and TLS-policy cell was
  established by reading the shipped source and the corresponding tests, at file:line.
- That each §12.4 rule has a failing test: I read the test bodies and their assertions; I did not
  individually confirm each of the ~56 rule-tests fails when its rule is removed. The suites do
  pass as a whole, which I did run.
- The §9 concurrency claims for the six passing SDKs: I read the coalescer code and the burst
  tests' assertions (N and the shared-value check). I did not instrument them to count wire calls
  independently — but each test asserts the count itself, and each suite passed.
- Rust's N-wire-calls-for-N-callers behaviour is a reading of the guard code plus the absence of any
  result slot and of any `Clone` on the three relevant types. There is no test to run, which is
  itself part of F-01.
- PHP's `oidcRefresh` retry-instead-of-share behaviour is a reading of
  `OidcClient.php:389-412` against `Session.php:214-236`. It is not reachable in vanilla PHP, so it
  cannot be demonstrated by execution without a Fibers harness.

### Could not verify

- **Branch coverage for Go, PHP, and C#.** None configures a branch gate; their floors are
  line-based, which is what I measured.
- **Live server behaviour.** No AXIAM instance was running, so every wire-shape claim rests on the
  SDK's own mock-server tests plus the handler source. The mixed slug-header/UUID-query pairing is
  confirmed against `handlers/oauth2.rs`, not against a live 200.
- **`cargo audit`** in the Rust repo, and the TypeScript `npm run build` codegen step (`buf` is not
  installed in this environment). Both are environment limits, not findings, and the `Cargo.lock`
  check covers the substance of the dependency question.

---

## 6. Merge verdict

| Repo | Verdict | Reason |
|---|---|---|
| `axiam` (contract) | **SAFE TO MERGE** | contract 1.5 amendments + this document |
| `axiam-typescript-sdk` | **SAFE TO MERGE** | fully conformant; 465 tests and all four thresholds verified |
| `axiam-python-sdk` | **SAFE TO MERGE** | conformant; F-08/F-11 are non-blocking |
| `axiam-go-sdk` | **SAFE TO MERGE** | conformant; F-14/F-15 non-blocking |
| `axiam-rust-sdk` | **BLOCKED** | **F-01**: §9 rule 2 result-sharing absent (N callers → N serialized refresh calls, N−1 failing `invalid_grant` against single-use rotating tokens) and no `oidc_refresh` burst test, while the README claims §1–§12. F-04, F-05, F-07 should ride along in the same fix commit. |
| `axiam-php-sdk` | **SAFE TO MERGE** | F-06 is the same defect class as F-01 but unreachable in vanilla PHP; high-priority follow-up, not a merge blocker |
| `axiam-java-sdk` | **SAFE TO MERGE** | F-02 (unreadable tokens) is high severity but additive to fix and breaks nothing today |
| `axiam-csharp-sdk` | **SAFE TO MERGE** | conformant; F-13/F-16 cosmetic-to-medium |
| `axiam-kotlin-sdk` | **SAFE TO MERGE** | F-03 mirrors F-02; same reasoning |

Eight of nine repos are safe. One is blocked on a single, precisely-specified fix.
