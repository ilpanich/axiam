# CONTRACT §28 MCP resource-server helpers — cross-SDK conformance review (T21.9 T9d)

**Date:** 2026-09-17
**Scope:** CONTRACT.md §28 (MCP resource-server helpers, RFC 9728 + RFC 6750), implemented
independently in eleven SDKs against contract 1.48 (`/home/user/axiam` @ `abdb3b6`,
branch `claude/t21-7-mcp-docs`).
**Outcome:** contract amended to **1.49** (non-breaking / clarifying); all eleven ports
**conformant on the normative rules**; thirteen divergences recorded in `CONTRACT.md`
§28.11, **none open**; four follow-ups (F-28-01 … F-28-04), of which three are pushed by
this review and one is blocked on Phase 21 merging.

Every cell below was determined by reading the shipped source of the merged port, not by
reading its PR description. Where a self-report and the code disagreed, the code won and the
disagreement is recorded.

Branch in every SDK repository: `claude/t21-9c-mcp-helpers` (TypeScript: `claude/t21-9b-mcp-helpers`).

| Repo | PR | PR head read | Merge commit read |
|---|---|---|---|
| `axiam-typescript-sdk` (reference, T9b) | [#110](https://github.com/ilpanich/axiam-typescript-sdk/pull/110) | `041d36c` | `772ca42` |
| `axiam-rust-sdk` | [#109](https://github.com/ilpanich/axiam-rust-sdk/pull/109) | `eec5440` | `913d200` |
| `axiam-python-sdk` | [#83](https://github.com/ilpanich/axiam-python-sdk/pull/83) | `f3b256e` | `20cc949` |
| `axiam-java-sdk` | [#98](https://github.com/ilpanich/axiam-java-sdk/pull/98) | `1dcd798` | `85f1b3b` |
| `axiam-kotlin-sdk` | [#65](https://github.com/ilpanich/axiam-kotlin-sdk/pull/65) | `40bc3f1` | `e2558f8` |
| `axiam-csharp-sdk` | [#91](https://github.com/ilpanich/axiam-csharp-sdk/pull/91) | `90a3a51` | `e13726c` |
| `axiam-php-sdk` | [#70](https://github.com/ilpanich/axiam-php-sdk/pull/70) | `8219d13` | `ef4a44b` |
| `axiam-go-sdk` | [#81](https://github.com/ilpanich/axiam-go-sdk/pull/81) | `0ec9527` | `e97bc44` |
| `axiam-swift-sdk` | [#63](https://github.com/ilpanich/axiam-swift-sdk/pull/63) | `93a7c8a` | `5ceef64` |
| `axiam-c-sdk` | [#62](https://github.com/ilpanich/axiam-c-sdk/pull/62) | `fc96ca9` | `9cb6e32` |
| `axiam-cplusplus-sdk` | [#63](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/63) | `a180257` | `b36b5f8` |

> One self-reported cross-reference is wrong and is corrected here: the Kotlin PR names the
> Java port as `axiam-java-sdk` PR **#123**. The Java port is PR **#98**. No code is affected;
> the Kotlin README's prose pointer is to the Java SDK's classes, which exist and are correct.

---

## 1. Conformance matrix

Legend: **P** = pass · **F** = fail · **D** = divergent but legal (a per-language equivalence
§28.11 records) · **P\*** = pass with a recorded caveat · **n/a** = not applicable.

### 1.1 Vocabulary and surface (§28.1, §28.7)

| Rule | TS | RS | PY | JV | KT | C# | PHP | GO | SW | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| All three §28.1 operations present, under §28.7's row | P | P | P | P | P | P | P | P | P\* | P | P\* |
| `serve_*` present, or absent per §28.3's carve-out | P | P | P | P | P | P | P | P | D | P | P |
| Value exposes `metadata_path` **and** `metadata_url` (§28.1 MUST) | P | P | P | P | P | P | P | P | P | P\* | P |
| Returned type name does not collide with the pinned function name | P | P | P | P | P | P | P | D | P | n/a | P |
| No `Async`/`suspend`/`async` suffix or shape on any of the three | n/a | n/a | P | P | P | P | n/a | n/a | P | n/a | n/a |
| Option spelled `resource_metadata_url` per §28.7 (Go: `…URL`) | P | P | P | P | P | P | P | P | P | P | P |
| No client half of the handshake shipped under a §28 name | P | P | P | P | P | P | P | P | P | P | P |

- **SW `P*` / `D`** on `serve_*`: `axiam-swift-sdk`'s core carries no Vapor dependency, matching
  its own pre-§28 §10/§11 shape, so the route is a documented `AsyncMiddleware` wiring rather
  than a first-party function. §28.7 names Vapor as the framework surface but §28.3 only
  requires "one route, on the framework's own router"; a framework the SDK does not depend on
  cannot be registered against from inside it. Recorded, not fixed — forcing a Vapor dependency
  into this SDK for §28 would be a larger change than §28 itself.
- **C `P*`** on `metadata_url`: satisfied by `axiam_protected_resource_metadata_url`, which
  §28.7's 1.48 row did not name. Contract fixed (§28.11 R-6).
- **GO `D`**: `MCPResourceMetadata`. §28.11 R-5; now reserved in §28.7.
- **C++ `P*`**: `protected_resource_metadata()` returns the value type with all three members,
  exactly as §28.7's C++ row already spelled it. No accommodation needed, and the C++ port said
  so rather than copying C's.

### 1.2 The document and its validation (§28.2, §28.3)

| Rule | TS | RS | PY | JV | KT | C# | PHP | GO | SW | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| All nine §28.2 rules enforced, at construction | P | P | P | P | P | P | P | P | P | P | P |
| Refuses; never normalises, trims, lowercases or re-encodes | P | P | P | P | P | P | P | P | P | P | P |
| Loopback carve-out is exactly the three named hosts, no flag widens it | P | P | P | P | P | P | P | P | P | P | P |
| No refusal added beyond §28.2's list | P | P | P | P | P | P | P | P | P | P | P |
| §28.3's five `metadata_path` derivations, trailing slash preserved | P | P | P | P | P | P | P | P | P | P | P |
| Exactly one route registered; no root form for a pathed resource | P | P | P | P | P | n/a | P | P | n/a | n/a | n/a |
| Document served unauthenticated under a global guard | P | D | P | P | P | P | P | P | P | P\* | P\* |
| `Content-Type` media type is `application/json` | P\* | P | P | P | P | P\* | P\* | P | n/a | n/a | n/a |

- **RS `D`**: Actix's `AxiamUser` is a per-route `FromRequest` extractor, never an `App::wrap`,
  so the document route composes no guard and is unauthenticated by construction. There is no
  global guard to exempt it *from*. Structural, and the strongest form of the property.
- **C / C++ `P*`**: no router, so §28.3 rules 1–6 bind the README's documented adapter
  (CivetWeb / Crow / Pistache) rather than SDK code, exactly as §28.3's last paragraph provides
  for. Both READMEs state the six rules at the adapter.
- **TS / C# / PHP `P*`** on `Content-Type`: they assert the media type with parameters dropped,
  because Fastify appends `; charset=utf-8` unconditionally. §28.11 R-4; contract fixed.
- **GO** additionally pins the route with Go 1.22's `{$}` so a trailing-slash `metadata_path`
  is not treated as a subtree wildcard — a Go-specific correctness fix in service of §28.3's
  "exactly one route, at exactly the derived path", not a divergence.

### 1.3 The challenge (§28.4)

| Rule | TS | RS | PY | JV | KT | C# | PHP | GO | SW | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Returns the header **value**, never the line, never a map | P | P | P | P | P | P | P | P | P | P | P |
| Parameter order and the `, ` separator, exactly | P | P | P | P | P | P | P | P | P | P | P |
| `resource_metadata` always present; the other three omitted when absent | P | P | P | P | P | P | P | P | P | P | P |
| Every value quoted; **no value ever escaped** | P | P | P | P | P | P | P | P | P | P | P |
| Refuses an `error` outside RFC 6750 §3.1's three | P | D | P | P | D | P | P | P | D | P | D |
| Refuses `error_description` outside `NQSCHAR` | P | P | P | P | P | P | P | P | P | P | P |
| Refuses a malformed `scope` (leading / doubled space, empty) | P | P | P | P | P | P | P | P | P\* | P | P |
| Refuses a `resource_metadata` carrying `"`, `\`, space or a control char | P | P | P | P | P | P | P | P | P | P | P |
| The four §28.4 test vectors asserted as exact strings | P | P | P | P | P | P | P | P | P | P | P |
| The automatic challenge carries **no** `error_description` | P | P | P | P | P | P | P | P | P | P | P |
| Nothing derived from the credential reaches the challenge (§28.8) | P | P | P | P | P | P | P | P | P | P | P |

- **`D`** on the `error` refusal: Rust, Kotlin, Swift and C++ make a fourth value
  unrepresentable rather than refusing it at run time, and TypeScript and Python use a closed
  type *plus* a runtime check. §28.11 R-7; §28.4 and §28.9 test 2 now state the rule. All eleven
  hold the property; only the mechanism differs.
- **SW `P*`**: a malformed `scope` on `requireAccess` degrades to "no challenge header on this
  one denial" rather than failing at route registration, because that factory is not `throws`
  and predates §28. The 403, its status and its body are unaffected. Defensible — §28 is never
  a source of truth about a token — but it is the one place an SDK reports a §28 programming
  error later than §28.4 intends, and it is recorded in Swift's own PR.

### 1.4 The middleware option (§28.5)

| Rule | TS | RS | PY | JV | KT | C# | PHP | GO | SW | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 — unset, the guard is byte-for-byte what it was; header **absence** asserted | P | P | P | P | P | P | P | P | P | P | P |
| 2 — `expected_audience` mandatory once set, refused **at construction** | D | D | D | D | D | D | D | D | D | D | D |
| 2 — no second audience option added | P | P | P | P | P | P | P | P | P | P | P |
| 3 — the two-string cross-check where both are visible | P | P | P | P | P | P | P | P | P | P | P |
| 4 — the §10 guard's own 401 carries the challenge, correct vector | P | P | P | P | P | P | P | P | P | P | P |
| 4 — §11's `require_auth` 401 carries it | P | P | P | P | P | P | **D** | **D** | P | P | **D** |
| 4 — §11's `require_role` 401 carries it | P | P | P | P | P | P | D | **F** | P | P | D |
| 5 — `insufficient_scope` on `no_grant` + a named scope, and only there | P | P | P | P | P | P | P | P | P | P | P |
| 5 — no header on `denied_by_rule`, on an absent code, or with no scope | P | P | P | P | P | P | P | P | P | P | P |
| 5 — the JSON body is unchanged (`authorization_denied`) | P | P | P | P | P | P | P | P | P | P | P |
| 6 — the route's own scope, verbatim; never synthesised | P | P | P | P | P | P | P | P | P | P | P |
| 7 — no other response gains a header | P | P | P | P | P | P | P | P | P | P | P |
| 8 — no AMQP form invented | P | P | P | P | P | P | P | P | P | P | P |
| 8 — gRPC form, where a guard exists to extend | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

- **`D` on rule 2's mechanism, everywhere**: six mechanisms, all refusing at construction.
  §28.11 R-10. The row is `D` rather than `P` in every column on purpose — "the SDK's
  `ValidationError`" never had one meaning across eleven languages, and pretending otherwise is
  how the next port guesses.
- **PHP / C++ `D` on `require_auth`**: both helpers receive an already-resolved identity, not a
  request, so neither can tell vector 1 from vector 2. §28.11 R-8; §28.5 rule 4 now provides for
  it. Reachable only where the §10 guard did not run.
- **GO `D` on `require_auth` / `F` on `require_role`**: Go's `RequireAuth` *does* carry the
  challenge and *does* pick the vector from the request
  (`setMCPChallenge401FromRequest`, `middleware/require.go:159`). `RequireRole` does not —
  not because it lacks the request (its handler has `r`) but because
  `RequireRole(roles ...string)` has spent Go's one permitted variadic on `roles`, leaving no
  room for `opts ...RequireOption`. That is a constraint on *this signature*, not on Go: an
  additive companion constructor is ordinary Go (`regexp.Compile`/`MustCompile`), and this SDK
  had already added `WithRequireResourceMetadataURL` for the sibling guards. The port declared
  it as "a real gap, not an oversight" and left it; **this review treats it as a fix**, because
  §28.5 rule 4 names the `authentication_failed` 401 of §11 without qualifying which helper
  emits it. §28.11 R-9, follow-up F-28-03.
- **Rule 8 is `n/a` in every column, and that is the finding**: all seven full-surface SDKs
  reported, independently and correctly, that their `grpc`/`amqp` packages are *outbound
  clients* to AXIAM rather than inbound guards, so there is no `UNAUTHENTICATED` status of their
  own to attach `www-authenticate` to. Rule 8's "where a transport-appropriate equivalent
  exists" is satisfied vacuously in all eleven. No SDK invented an AMQP form.

### 1.5 What §28 does not change (§28.6), and `Sensitive<T>` (§28.8)

| Rule | TS | RS | PY | JV | KT | C# | PHP | GO | SW | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| §16 retry not entered by any §28 operation | P | P | P | P | P | P | P | P | P | P | P |
| §9 refresh guard not entered; the SDK's own session untouched | P | P | P | P | P | P | P | P | P | P | P |
| No new error type introduced for §28 | P | P | P | P | P | P | P | P | P | P | P |
| §10.1 row 6's audience check unchanged in what it does | P | P | P | P | P | P | P | P | P | P | P |
| §11's statuses and bodies unchanged | P | P | P | P | P | P | P | P | P | P | P |
| Nothing in §28 wrapped in `Sensitive<T>` | P | P | P | P | P | P | P | P | P | P | P |

### 1.6 Required tests (§28.9)

| Test | TS | RS | PY | JV | KT | C# | PHP | GO | SW | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 — document shape, five path derivations, every negative | P | P | P | P | P | P | P | P | P | P | P |
| 2 — the four vectors, every refusal, no escaping | P | P\* | P | P | P\* | P | P | P | P\* | P | P\* |
| 3 — 401 with the challenge; unauthenticated `200` on the document | P | P | P | P | P | P | P | P | P\* | P | P\* |
| 4 — 403 `insufficient_scope` + the three no-header cases | P | P | P | P | P | P | P | P | P | P | P |
| 5 — wrong `aud` refused, right `aud` admitted, config negative | P | P | P | P | P | P | P | P | P | P | P |
| The regression: unset ⇒ no header, asserted as **absence** | P | P | P | P | P | P | P | P | P | P | P |
| Uses §28.9's own fixture verbatim | P | P | P | P | P | P | P | P | P | P | P |

- **`P*` on test 2** (Rust, Kotlin, Swift, C++): the `invalid_grant` vector is discharged
  structurally, with a comment at the test site. §28.9 test 2 now says this is the required
  form, and each of the four carries the comment — checked, not assumed.
- **SW / C++ `P*` on test 3**: asserted against the guard's own entry points rather than a
  live HTTP pipeline, because neither SDK ships one. Both follow their repositories' existing
  `test_guard` / `test_uma_challenge` precedent.

---

## 2. What the self-reports got wrong

The eleven PR descriptions are the input to this review, not its conclusion. Four claims did
not survive being checked.

1. **Go: "every other SDK with a single namespace (Rust, Python, Java, Kotlin, C#, PHP, Swift)
   will hit the same wall."** None of the seven does. Rust and Python spell the function
   `snake_case` and the type `PascalCase`, so there is no collision to have. Java, Kotlin, C#,
   PHP and Swift put the function on a class, object or client — `Mcp.protectedResourceMetadata`,
   `AxiamMcp.ProtectedResourceMetadata`, `AxiamClient.protectedResourceMetadata` — so the
   free type name is never in contention. C# is the closest call and still compiles, because
   the method is a member rather than a package-scope name. Go's constraint is real and Go's
   is the only one; §28.7 now says so, so that the next port does not take the accommodation
   pre-emptively.

2. **C#: a closed enum "would make the required refusal test only reachable via an unsafe
   enum cast."** True of C#, but offered as a reason the reference must be string-typed — and
   the reference is not. TypeScript's `BearerChallengeError` is a closed string-literal union
   and its test reaches `invalid_grant` through `as never`. Both positions were always
   conformant; §28 simply never said so, which is why four ports argued themselves into one
   answer and seven into the other.

3. **Swift: "matches T9b's own CHANGELOG note that it scoped its `openapi.json` re-sync out
   too."** TypeScript did scope it out — and so did C# and C++, while Rust, Python, Java,
   Kotlin, PHP, Go and C re-synced. Following the reference here meant joining a four-repo
   minority, not following a settled practice, and the contract's own 1.48 trailer had asked
   for the re-sync. §28.11 R-1.

4. **Go: "no defect found in §28 itself."** Its own divergence 4 describes a 401 that §28.5
   rule 4 requires to carry a challenge and does not. It is recorded here as a fix, not as a
   forced constraint. Eight of the eleven reported "no defect found"; between them the three
   that did report one (TypeScript's `Content-Type`, C's naming-table row, C++'s concurrence)
   caught three of the six contract defects this review is fixing, and the other three —
   §28.5 rule 4's resolved-identity case, §28.4's `error` typing, §28.10's maintenance — were
   each argued around in two or more repositories without anyone naming the contract as the
   thing at fault. That asymmetry is the case for this task existing.

Two claims survived unchanged and deserve saying so: **C's report that §28.7's C row is
incomplete against §28.1's own MUST** is exactly right, and **C++'s refusal to copy C's
accommodation because §28.7 already spells the C++ row correctly** is exactly the kind of
reading the review hopes for.

---

## 3. Test runs

"Re-run every SDK's §28 tests" is in the task. Nine of eleven were run here, on the merged
`main` of each repository. Two could not be, and are taken on their merged PR's own CI run,
named:

| SDK | Run here | Evidence |
|---|---|---|
| TypeScript | ✅ | `npx vitest run test/middleware/mcp.{contract,express,fastify}.test.ts` — **48 passed**, 3 files |
| Rust | ✅ | `cargo test --all-features --test mcp_contract_test --test mcp_actix_test` — **12 + 13 passed**, 0 failed |
| Python | ✅ | `pytest tests/test_mcp.py tests/test_fastapi_mcp.py tests/test_django_mcp.py` — **71 passed** |
| Java | ✅ | `mvn -B test -Dtest='McpTest,McpGuardTest,Rule8CallerCredentialTest'` — **59 run, 0 failures** (the build then fails JaCoCo's gate, which is an artefact of running a filtered subset, not a test failure) |
| Kotlin | ✅ | `./gradlew test --tests '*McpTest' --tests '*KtorMcpTest'` — **17 passed**, 0 failed |
| Go | ✅ | `go test ./ ./middleware -count=1` — both packages **ok**; 59 §28 test cases under the MCP filter |
| C | ✅ | `cmake -DAXIAM_BUILD_TESTS=ON && ctest` — `test_mcp` and `test_mcp_guard` pass; full suite **56/56** |
| C++ | ✅ | `cmake -DAXIAM_BUILD_TESTS=ON && ctest` — `axiam_cpp_tests` passes (the repository runs one aggregate binary) |
| **C#** | ❌ | No .NET toolchain in this sandbox and `builds.dotnet.microsoft.com` is blocked by the environment's egress policy. Taken on CI: **`SDK CI — C#` run #154** ([35223167418](https://github.com/ilpanich/axiam-csharp-sdk/actions/runs/35223167418)) on head `90a3a51`, conclusion `success`; `Coverage` #243 likewise |
| **PHP** | ❌ | `php` is present but `composer install` cannot complete: every dist and source fetch fails `Could not authenticate against github.com` through the sandbox proxy, with and without `COMPOSER_MAX_PARALLEL_HTTP=1`, `--prefer-dist` and `--prefer-source`. Taken on CI: **`SDK CI — PHP` run #129** ([35224007931](https://github.com/ilpanich/axiam-php-sdk/actions/runs/35224007931)) on head `8219d13`, conclusion `success` |
| **Swift** | ❌ | No Swift toolchain in this sandbox. Taken on CI: **`sdk-ci-swift` run #121** ([35237308282](https://github.com/ilpanich/axiam-swift-sdk/actions/runs/35237308282)) on head `93a7c8a`, conclusion `success`; `coverage` #188 likewise |

No suite is reported green here that was not seen to go green, either locally or in a named
CI run.

---

## 4. The vendored-artefact finding (§28.11 R-1), in full

This is the row the task called the most consequential, and it is worse than "five repos ahead
of three".

**`CONTRACT.md`.** All eleven vendor a file whose latest changelog entry reads *contract 1.48*.
They are **five distinct files**:

| Bytes | Repos |
|---|---|
| `9117b2e3…` | Rust, Python, Java, Kotlin, Go, Swift, C++ — the baseline |
| `8319d6f3…` | C# — baseline + its own §28.10 row |
| `6953b037…` | PHP — baseline + its own §28.10 row |
| `c0f3e3be…` | C — baseline + its own §28.10 row |
| `4237529f…` | TypeScript — an **earlier** snapshot, 83 lines short of the baseline: it predates T21.6's unnumbered entry |
| `87cab31e…` | `ilpanich/axiam` `sdks/CONTRACT.md` @ `abdb3b6` — 48 lines ahead of the baseline (T21.5's entry landed after the ports vendored) |

Three of the five states exist *because* §28.10 told each port to edit its own row in a
vendored file. That instruction is the defect, and §28.10 is fixed rather than the three
repositories that followed it.

**`openapi.json`.** A clean two-way split, and neither side matches upstream:

| `info.x-axiam-spec-digest` | Paths | Repos |
|---|---|---|
| `c5dd559a…` | 162 | Rust, Python, Java, Kotlin, PHP, Go, C — re-synced from `claude/t21-2a-public-clients` |
| `baa77fe1…` | 156 | TypeScript, C#, Swift, C++ — not re-synced |
| `edb709e9…` | 162 | `ilpanich/axiam` @ `abdb3b6` — **matched by none of the eleven** |

The seven that complied with 1.48's "re-sync `openapi.json`" also regenerated their §27
management surfaces from it, pulling T21.2a/T21.4's schema deltas into reviewed-elsewhere
generated code. The four that declined gave that as their reason and were right about the
consequence. **Both sides were reasoning correctly from a rule that could not be satisfied**:
1.48 asked for a re-sync of "the T21.3 half" of a generated file, which cannot be half
re-synced, from a branch that kept moving. The seven were stale against the branch they synced
from within hours of syncing.

**The rule, now in the 1.49 trailer.** A vendored artefact is re-synced from a **merged**
`main`, never a phase branch. The `openapi.json` half of 1.48 — and the `CONTRACT.md` re-sync
for 1.49 — happen together, once, as **F-28-01**, after Phase 21 lands, so the eleven return
to one file in one step. F-28-01 is recorded in all eleven repositories' `CHANGELOG.md` so it
cannot be lost the way T21.3's version number nearly was.

---

## 5. The Java constructor pin (§28.11 R-12), judged

`Rule8CallerCredentialTest.theFilterConstructorExposesNoSecondCredential` exists to pin the
property SEC-085 violated: **no second credential in the guard's dependency surface**. §28 added
a three-argument `AxiamAuthenticationFilter(verifier, tenantId, resourceMetadataUrl)` overload,
and the pin widened from "exactly one public constructor with these two parameters" to "every
public constructor takes only a `JwksVerifier` and `String`s".

**It still pins most of the property, and it has lost one edge.** It still asserts the exact
constructor count (2), still requires the first parameter to be the verifier, still rejects any
parameter that is not a `String`, and the separate field scan still rejects an `AxiamClient`,
`Session`, `TokenManager` or `Credentials` field. Every object-shaped credential — which is
what SEC-085 was — is still refused.

What it would now admit is a **`String`-shaped** credential: a fourth parameter carrying a
client secret or a bearer token would satisfy "a verifier and Strings", and the field scan
matches on type name, so a `String` field carrying it passes too. The old assertion refused any
third parameter at all and would have caught it.

That is a real, narrow weakening of a security-invariant test, and the task's rule — do not
relax an existing test's expectation — points at the repair rather than away from it: the fix
**adds** an assertion and removes none. F-28-04 pins the filter's declared instance fields to an
allow-list by name, so that any new field of any type fails the test until someone adds it
deliberately. That restores the guardrail the test's own comment asks for ("so the properties
above cannot be quietly undone by widening the constructor later") without touching a single
existing expectation.

---

## 6. Follow-ups

| Id | What | Where | State |
|---|---|---|---|
| **F-28-01** | Re-sync `CONTRACT.md` (1.49) and `openapi.json` in all eleven repositories, from `main`, once Phase 21 merges; regenerate each §27 surface in the same commit | all eleven | **open, blocked on a merge** — recorded in all eleven `CHANGELOG.md` files by this review so it cannot be lost |
| **F-28-02** | README conformance statement follows the code: name §28, and the contract version the repository actually vendors | Rust, Java, Go, Swift (omit §28); Python, C# (stale version) | pushed by this review |
| **F-28-03** | `RequireRole` gains an additive options-carrying companion so its missing-identity 401 can carry the challenge | Go | pushed by this review |
| **F-28-04** | `Rule8CallerCredentialTest` gains a field allow-list, restoring the edge the §28 widening lost | Java | pushed by this review |

F-28-01 is the one row §28.11 would otherwise have to carry as **open**. It is not open: the
rule is decided and written into the contract, the work is named, and all eleven repositories
record it. What is outstanding is a merge, not a decision.

---

## 7. What §28 and the plan got wrong that this review could not fix

- **The plan's §4.0 item 5 makes T9 own SDK code, and T9d owns the review — but neither owns
  the moment the eleven re-sync.** T9c's ports each re-synced independently, from whatever
  branch was current when they ran, which is exactly how the eleven ended up holding five
  files. A phase that fans out to eleven repositories needs one re-sync step at its end, owned
  by one task, after the phase merges. F-28-01 is that step; the plan has no task for it, and
  this review cannot create one. **This is the item to carry into Phase 22's plan.**
- **`§28.7`'s framework list names Vapor for Swift, but `axiam-swift-sdk`'s core carries no
  Vapor dependency**, and neither does §10's guard there. The naming map inherited §10's table
  without checking that each SDK actually depends on the framework named. Swift's answer — a
  documented wiring example — is the same answer it already gives for §10, so the SDK is
  self-consistent and the table is optimistic. Left as recorded rather than changed, because
  the alternative is either a new dependency in that SDK or a §10-wide table revision, and both
  are larger than §28.
- **Nothing in any SDK repository's CI notices that a vendored `CONTRACT.md` is stale.** Checked
  across all eleven `.github/workflows/`: every `CONTRACT.md` mention is a comment or a path
  filter, and the only drift gates (`gen_management.py --check` and its per-language siblings)
  derive from `openapi.json`. That is why R-1 could reach five byte-states without one red
  build. A `CONTRACT.md` digest gate, mirroring §27.8's, would have caught it on the first
  push — but adding one to eleven repositories is a change to eleven CI configurations and
  belongs in a task that says so.
