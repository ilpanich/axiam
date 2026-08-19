# SOLID / Clean Code / Clean Architecture Review — AXIAM + 11 SDKs

**Date:** 2026-08-18
**Scope:** `ilpanich/axiam` @ `c030e2e` and all eleven `axiam-<lang>-sdk` repos @ `1.0.0-alpha27`
**Constraints honoured throughout:** no proposal may weaken security, degrade hot-path
performance, reduce test coverage, or reduce documentation.

---

## 1. Verdict

The codebase is in **good** shape against all three rule sets. The layering is sound, the
domain boundary is a real boundary, function-size discipline is unusually strong, and the
test posture is stronger than most production IAM products. The problems that exist are
**localised and structural**, not systemic — every one of them is fixable by extraction or
by adding a CI gate, and none requires re-architecting anything.

The single biggest risk is not any individual smell. It is that **none of the architectural
rules the codebase actually follows are machine-enforced**, so they will erode.

| Dimension | Assessment |
|---|---|
| Dependency direction / layering | Strong, but convention-only |
| SRP | Strong at function level; violated at 3 specific seams |
| OCP | Good in the authz engine; inverted in token issuance |
| LSP | No issues found |
| ISP | Strong — 46 aggregate-scoped repository traits |
| DIP | Correct at the domain boundary; concrete types leak into `AppState` |
| DRY | Good, except `axiam-db/src/repository/` |
| Test coverage | Excellent and enforced everywhere except `main.rs` |
| Documentation | Excellent in SDKs (85–100%), unenforced in the server (~69%) |

---

## 2. What is already right (protect this)

These properties are load-bearing. Any refactor must preserve them.

**2.1 The domain is a real domain.** `axiam-core` has **zero** internal dependencies. The
graph flows one way: `core` ← `auth`/`authz`/`pki`/`email` ← `db` ← `federation`/`oauth2`
← `api-rest`/`api-grpc`/`amqp` ← `server`. The only backward reference found is
`axiam-federation/src/oidc.rs` constructing `axiam_db::Surreal*Repository` types, and that
is inside `#[cfg(test)]` (module starts line 725; uses at 1091–1108) — test-only, not a
production leak.

**2.2 DIP is done properly where it matters.** `axiam-core/src/repository.rs` declares
**46 traits / 262 methods**, segregated per aggregate (`UserRepository` 10 methods,
`RoleRepository` 14, `PermissionRepository` 12 …) rather than one fat `Repository`. That is
ISP satisfied by construction. `AuthorizationEngine<R, P, Res, S, G>` is generic over those
traits, not over SurrealDB.

**2.3 One policy engine, three protocol adapters — no duplicated authorization rules.**

- REST — `axiam-api-rest/src/handlers/authz_check.rs:208, :292`
- gRPC — `axiam-api-grpc/src/services/authorization.rs:159, :214`
- AMQP — `axiam-amqp/src/authz_consumer.rs:167`

All three call the same `AuthorizationEngine::check_access` / `check_access_batch`. For an
IAM product this is *the* clean-architecture property that matters, and it holds. Nothing in
this review should be allowed to break it.

**2.4 Function-size discipline is excellent.** Across 1 275 production Rust functions:
**median 9 lines, mean 17.4**, only 10 above 100 lines, 4 above 200. SDK medians run 4–11
lines (Java 4, TS 4, Rust 7, Kotlin 8, Go 8, Swift 8, PHP 7, Python 9, C 9, C++ 11).

**2.5 Test posture.** Server: ~94.9k production LOC against ~115.9k test LOC (**1.22 : 1**).
Enforced floors: Rust workspace **88%** (`coverage.yml:171`), frontend **92.4%**
(`vitest.config.ts:25`). **Every one of the eleven SDKs enforces a coverage floor** —
C 98% line / 84% branch, Kotlin 98%, C++ 96%, Python 97%, PHP 94%, C# 94%, Go 94%,
TS 94%, Swift 92%, Rust 90%, Java (JaCoCo BUNDLE rule). Test/prod line ratios run 0.84–1.53.

**2.6 Cross-SDK contract discipline.** `CONTRACT.md` is **byte-identical across all twelve
checkouts** (`da6c3056…`). `reactor_v2_reference_vectors.json` is byte-identical across the
server and ten SDKs (`5b49f3b8…`). Each SDK carries ~1 600–2 800 `§`-section
back-references into the contract. This is materially better traceability than most
multi-language SDK families achieve.

**2.7 Low debt, no unsafe in production.** Only ~12 `TODO`/`FIXME` markers in production
Rust, each carrying a ticket ID (`T19.8`, `T19.14`, `T19.15`, `plan 04-05`); the other 240
live in `.planning/` and `claude_dev/` where they belong. **All 11 `unsafe` blocks in the
server are inside `#[cfg(test)]` modules** (env-var manipulation, each with a `SAFETY:`
comment). The Rust SDK contains **zero** `unsafe`.

**2.8 Security tooling.** `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo audit`, `cargo deny` (advisories + licenses + bans + sources), `npm audit`, plus
FAPI 2.0 conformance pinned to a specific OIDF suite release (`release-v5.1.34`, never
`latest`) with reports kept alongside rather than over one another.

---

## 3. Findings, ranked

### F1 — No machine-enforced architecture rule *(highest leverage, lowest cost)*

The layering in §2.1 is held together by discipline alone. There is **no** `deptrac`,
`ArchUnit`, `import-linter`, `dependency-cruiser`, or equivalent in any of the twelve repos,
and no CI job that fails when a dependency edge is added in the wrong direction.

Two edges already sit outside the ideal shape:

- `axiam-scim` → `axiam-api-rest` — adapter depending on another adapter.
- `axiam-db` → `axiam-auth`, `axiam-pki` — infrastructure depending on domain services
  (`repository/user.rs:7` delegates password hashing to `axiam_auth::password`;
  `repository/service_account.rs:3` and `oauth2_client.rs:3` use `axiam_auth::client_secret`;
  `mds_ingest.rs:25` uses `axiam_pki::mds`).

Both are *defensible* — hashing genuinely belongs next to the write, and re-implementing it
in `axiam-db` would be worse. The problem is that nobody decided this on purpose and nothing
records the decision.

**Action.** Add a dependency-direction gate: a ~30-line CI script that parses each
`crates/*/Cargo.toml` and checks the internal edges against an explicit allow-list, with the
two exceptions above listed and justified inline. Zero runtime cost, zero security impact,
and it converts a convention into a guarantee.

---

### F2 — `axiam-server::main()` is 1 887 lines and excluded from coverage

`crates/axiam-server/src/main.rs:157` — a single function performing config load, MFA/
federation/email/GDPR key resolution, Ed25519 key pre-parsing, storage-engine attestation,
schema migrations, bootstrap-token minting, **two encryption backfills**, permission seeding,
AMQP connection + primary/retry/DLQ topology, ~75 service constructions, TLS setup, and
listener bind.

It is also the **only file deliberately excluded from the coverage gate**:

```
coverage.yml:142  cargo llvm-cov report --lcov --ignore-filename-regex 'crates/axiam-server/src/main\.rs'
```

So the code that decides whether the process boots fail-closed — key absence handling,
backfill idempotence, migration ordering — is the least-tested code in the product.

**Action.** Extract into `bootstrap/` submodules (`keys.rs`, `migrations.rs`, `backfill.rs`,
`topology.rs`, `wiring.rs`), each independently unit-testable, leaving `main()` at ~100 lines
of sequencing. **Then delete the coverage exclusion.** Pure extraction: no behaviour change,
no runtime cost, and it turns the largest untested surface into a tested one.

---

### F3 — `AppState` is a 75-field god object of concrete repository types

`crates/axiam-api-rest/src/state.rs` — `AppState<C: Connection + Clone>` carries **75 public
fields**, nearly all concrete `Surreal*Repository<C>` values. Every handler receives the whole
thing regardless of what it uses. This is the source of three downstream costs:

- `C: Connection + Clone` propagates through every handler signature in the crate.
- `state.rs` references `axiam_db` 19 times — the adapter's widest coupling to infrastructure.
- 25 `#[allow(clippy::too_many_arguments)]` sites sit downstream of the same pressure.

**Do not fix this by boxing everything in `Arc<dyn Repository>`.** That trades static dispatch
for vtable dispatch on the authorization hot path and directly contradicts the performance
constraint.

**Action.** Split into cohesive sub-states — `AuthState`, `PkiState`, `OidcState`, `GdprState`,
`MailState`, `WebauthnState`, `FederationState` — held as fields of `AppState`, with handlers
taking only the sub-state they use. Identical monomorphisation, identical performance, far
smaller blast radius per change. Do it one bundle at a time; each is independently shippable.

---

### F4 — Telescoping token-issuance API (OCP inverted)

`crates/axiam-auth/src/token.rs` exposes **twelve** `issue_*` functions:

```
issue_access_token → issue_access_token_bound → issue_access_token_enriched
issue_client_credentials_token → …_bound → …_enriched
issue_service_account_client_credentials_token → …_enriched
issue_rpt   issue_exchanged_token   issue_id_token   issue_service_account_token
```

Each tier exists only to add one parameter to the tier below (`issue_access_token_bound`
is literally a one-line delegation adding `cnf`; `_enriched` adds `ext`). Five carry
`#[allow(clippy::too_many_arguments)]`; `issue_id_token` takes **10** positional parameters,
five of which are `Option`. Adding one claim today means adding a function and widening a
chain — the definition of a module that is closed to extension.

**Action.** Introduce one `AccessTokenSpec` parameter struct (or a typed builder) and a single
`issue(spec)`. Keep the existing twelve names as thin `#[deprecated]` delegations for one
release cycle. The struct is stack-allocated and monomorphised — **zero** runtime cost — and
correctness is provable by asserting byte-identical tokens against the existing test suite
and `benches/auth_bench.rs`.

---

### F5 — Near-duplicate repositories in `axiam-db` *(the one finding with a security edge)*

A 12-line normalised-block scan over production Rust found **1 219 duplicate block groups**,
heavily concentrated in `crates/axiam-db/src/repository/`:

| Pair | Duplicate blocks | Note |
|---|---|---|
| `email_verification_token.rs` ↔ `password_reset_token.rs` | 55 | ~90% identical (58 differing lines of 567 after normalising entity names) |
| `ca_certificate.rs` ↔ `certificate.rs` | 26 | |
| `amqp_nonce_replay.rs` ↔ `saml_replay.rs` | 8 | **both exactly 114 lines**; header says "Mirrors `super::saml_replay`" |
| `notification_rule.rs` ↔ `webhook.rs` | 10 | |
| `oauth2_client.rs` ↔ `service_account.rs` | 8 | |

The duplication is deliberate and documented, which is better than accidental — but the
failure mode is real and specific: **a security fix applied to one twin and not the other.**
Single-use-token redemption and replay rejection are exactly the code paths where that
asymmetry produces a vulnerability rather than a bug.

**Action.** Collapse the twins with a declarative macro (`impl_single_use_token_repo!`,
`impl_replay_repo!`). In Rust this is zero-cost — no generics, no vtables, identical
generated code. Start with the two replay repositories (114 lines each, exact structural
twins) as a low-risk proof, then the two token repositories.

---

### F6 — Documentation is enforced in the SDKs and unenforced in the server

Measured coverage of documented public API:

| Component | Public decls | Documented | Gate |
|---|---:|---:|---|
| Rust SDK | 302 | **100%** | `#![warn(missing_docs)]` (`src/lib.rs:49`) |
| C# SDK | 124 | 99% | — |
| Python SDK | 302 | 96% | `interrogate --fail-under=100` |
| TypeScript SDK | 261 | 95% | — |
| Kotlin SDK | 178 | 94% | — |
| Go SDK | 272 | 93% | — |
| PHP SDK | 289 | 92% | — |
| Swift SDK | 100 | 89% | — |
| Java SDK | 276 | 85% | — |
| **`axiam` server** | **1 590** | **~69%** | **none** |

Neither `Cargo.toml` nor any crate root sets `missing_docs`; there is no `[workspace.lints]`
section at all, and `clippy.toml` only tunes three thresholds. The 69% understates the real
state — REST handlers carry `#[utoipa::path(...)]` and are therefore documented in the
OpenAPI spec even without a `///` — but there is nothing stopping it from drifting downward.

**Action.** Add `[workspace.lints.rust] missing_docs = "warn"` and ratchet crate by crate,
starting with `axiam-core` (the crate every other crate reads) and `axiam-authz`. Purely
additive.

---

### F7 — The Rust SDK is the outlier on D5 conformance

Ten of eleven SDKs ship a single named D5 conformance suite covering `CONTRACT.md` §16–§19
(`D5ConformanceTest.java/.kt/.php`, `D5ConformanceTests.cs/.swift`, `test_d5_conformance.c/
.cpp/.py`, `d5_conformance_test.go`, `d5Conformance.test.ts`). The **Rust SDK has only
`tests/d5_config_clamped.rs` (102 lines)** and scatters the rest across differently-named files.

Against the Go suite's 29 test cases (`d5_conformance_test.go`, 586 lines), the Rust SDK has
no equivalent of:

- `TestTelemetry_PanickingHookCannotFailTheOperation`
- `TestTelemetry_NoEventCarriesAToken` ← **security invariant, currently unasserted**
- `TestTelemetry_EmitsRequestPairPerAttemptWithRetryBetween`
- `TestTelemetryEvents_AreAClosedSet`

`src/telemetry.rs` (188 lines) has **zero** inline tests and no dedicated integration test.

The behaviour is implemented correctly — `src/telemetry.rs:186` wraps every `sink.emit` in
`std::panic::catch_unwind` — so this is a **test gap, not a defect**. But the Go suite's own
header explains precisely why that distinction is thin:

> "the TypeScript SDK shipped a retry helper that was exported, unit-tested and green while
> no production path called it, so that SDK performed no read-only retries at all and every
> test passed."

**Action.** Port the Go D5 suite to `axiam-rust-sdk/tests/d5_conformance.rs`. Roughly one day,
and it closes the only cross-SDK conformance asymmetry found in this review.

---

### F8 — Frontend: transport type leaking into presentation; fat page components

**8a — `AxiosError` in the view layer, and a redaction bypass on three pages.** Eight
non-test page components import and cast `AxiosError` directly: `LoginPage`, `BootstrapPage`,
`ProfilePage`, `ChangePasswordPage`, `MfaSetupPage`, `MfaManagementPage`, `ResetPasswordPage`,
`VerifyEmailPage`. The abstraction to hide it **already exists** — `src/lib/apiError.ts:103`
exports `getApiErrorMessage(err: unknown): string`, which passes **every** server-supplied
branch through `redactSecrets` before returning.

Three of the eight hand-roll that same extraction and skip the redaction:

- `pages/profile/ProfilePage.tsx:118`
- `pages/profile/ChangePasswordPage.tsx:61`
- `pages/profile/MfaManagementPage.tsx:222`

all of the shape `axiosErr.response?.data?.message ?? …?.error ?? "<fallback>"`, rendered
straight into the UI. That is a defence-in-depth regression, not a live vulnerability — but it
is exactly the leak `redactSecrets` exists to stop, and it is the clearest case in this review
of a layering violation turning into a security-relevant one. (`LoginPage`, `MfaSetupPage`,
`ResetPasswordPage` and `VerifyEmailPage` do call `redactSecrets`; `BootstrapPage` branches on
`response?.status` only and leaks nothing.)

**8b — Fat pages.** `OrganizationDetailPage.tsx` — 1 245 lines, 27 `useState`, 5 `useEffect`.
`ReactorsPage.tsx` — 909 lines, 22 `useState`. `OAuth2ClientsPage.tsx` — 1 084 lines,
16 `useState`. The service layer is clean (pages never call `fetch`/`axios` directly), so
this is component-level SRP only.

Frontend test ratio is **0.54** versus the server's 1.22 — the lowest in the product.

**Action 8a (do now, ~1 hour):** replace all eight ad-hoc casts with `getApiErrorMessage`
(`BootstrapPage`'s status-code branch can keep its own narrow helper). Mechanical, covered by
the existing 92.4% floor, and it closes the three-page redaction bypass.
**Action 8b (slower):** extract per-tab feature hooks from the three largest pages,
alongside `useCrudMutations`/`usePermissions` which already exist and show the pattern.

---

### F9 — Vendored `openapi.json` is one version stale *(cosmetic)*

All eleven SDK copies are byte-identical to one another and **identical to upstream in every
path (111), every schema, and every operation** — the *only* difference is
`info.version`: `1.0.0-alpha26` in the SDKs versus `1.0.0-alpha27` in `axiam/sdks/openapi.json`.

The drift gate is evidently comparing content modulo version, which is the right call. The
re-sync simply did not happen on the version bump.

**Action.** Re-sync during the next release chore, or teach the release job to carry the
version bump into the vendored copies.

---

## 4. Explicitly *not* worth doing

**`AxiamError` mixing domain and infrastructure concerns.** `axiam-core/src/error.rs` carries
`Database(String)`, `EmailDelivery(String)`, `WebhookDelivery(String)`, `Certificate(String)`
in the *domain* error enum, all stringly-typed. This is a textbook clean-architecture
violation and it is **not worth fixing**: the blast radius is ~95k LOC, and this single enum
is exactly what makes the uniform REST/gRPC/AMQP error mapping simple. Note it in the design
doc; apply per-crate error enums only to *new* crates.

**A generic CRUD abstraction over the ~29 REST handler modules.** The repeated shape
(permission check → validate → reactor hook → repo call → webhook emit) looks like
duplication, but `RequirePermission` and `state.emit_webhook` already factor out the parts
that carry risk, and the residue is genuinely per-endpoint. A generic layer here would cost
more in indirection than it saves.

**The `AxiamClient` facade breadth across SDKs.** 39–94 public methods (PHP 39, Python 50,
Java 94) spanning login / MFA / OIDC / device / UMA / token-exchange / introspect / SSO looks
like an SRP violation, but it is a **deliberate and correct DX choice** for a client SDK — and
the implementations *are* delegating: Java's `AxiamClient` methods have a median length of
**4 lines**. The one genuine SRP wrinkle is that Java's facade also carries TLS/keystore
construction inline (`buildKeyManagers`, `parsePrivateKey`, `buildTrustManager`,
`CompositeX509TrustManager` at line 2426); moving that to an internal `TlsMaterial` helper is
a nice-to-have, not a priority.

**C# function-size profile.** Median 18 lines with 16 functions above 60 — the loosest of the
eleven. Worth a look during normal maintenance, not a project.

---

## 5. Suggested sequence

**Week 1 — cheap, zero-risk, high leverage**
1. F1 — dependency-direction CI gate.
2. F9 — re-sync vendored `openapi.json`.
3. F8a — swap 8 `AxiosError` casts for `getApiErrorMessage` (closes a redaction bypass on 3 pages).
4. F6 — `missing_docs = "warn"` on `axiam-core` only.

**Weeks 2–4 — structural, still low risk**
5. F2 — extract `main()` into `bootstrap/`; **delete the coverage exclusion.**
6. F7 — port the Go D5 conformance suite to the Rust SDK.

**Ongoing / opportunistic**
7. F5 — macro-collapse the twin repositories (start with the two replay repos).
8. F4 — `AccessTokenSpec` parameter struct; deprecate the twelve `issue_*` functions.
9. F3 — split `AppState` one sub-state bundle at a time.
10. F6 — ratchet `missing_docs` across the remaining crates.
11. F8b — extract feature hooks from the three largest frontend pages.

---

## 6. Guardrails for every item above

- **No `Arc<dyn …>` on the authorization hot path.** F3 is a field-grouping change, not a
  dispatch change.
- **No change** to deny-override precedence, Argon2id parameters, key handling, fail-closed
  boot behaviour, or any wire format.
- Every item is either CI-only or a pure refactor provable against the existing suites.
- The coverage floors (88 / 92.4 / 90–98) are the safety net. **Ratchet them up as the
  refactors land; never lower one to accommodate a refactor.** F2 in particular should *raise*
  the server floor by bringing `main.rs` back under measurement.


---

## Appendix — implementation status (2026-08-18)

Everything below except **F2** was implemented in the same session that produced
this review. F2 (extracting `axiam-server::main()` and removing its coverage
exclusion) was **explicitly deferred by the maintainer**: bringing 2 119 lines
of untested composition root under the coverage gate without first writing tests
for it would drop the workspace percentage below the floor, and whether those
tests can be written at all is an open question. The finding stands as written;
the work does not.

| Finding | Status | Where |
|---|---|---|
| F1 — no architecture gate | done | `scripts/check-crate-layering.py`, CI job *Architecture Invariants* |
| F2 — `main()` 1 887 lines, coverage-excluded | **deferred by maintainer** | — |
| F3 — 75-field `AppState` | done | `crates/axiam-api-rest/src/state/` |
| F4 — 12 telescoping `issue_*` | done | `crates/axiam-auth/src/token.rs` |
| F5 — near-duplicate repositories | done | `axiam_db::helpers`, `scripts/check-conflict-markers.py` |
| F6 — rustdoc unenforced | done | `[workspace.lints]`, `missing_docs` on `axiam-core` + `axiam-authz` |
| F7 — Rust SDK D5 gap | done | `axiam-rust-sdk/tests/d5_conformance.rs` |
| F8 — `AxiosError` in the view layer | done | `frontend/src/lib/apiError.ts` |
| F9 — stale vendored `openapi.json` | done | all eleven SDK repos |

### Two things the implementation changed about the review's own conclusions

**F1 — `axiam-db` → `axiam-auth` is not a violation.** The review flagged it as
"infrastructure depending on domain services". Building the gate forced the
question properly: under the Clean Architecture dependency rule an outer ring
(an adapter) reaching *inward* for a domain service is exactly what is
permitted. Password hashing belongs next to the write, and re-implementing
Argon2id inside `axiam-db` to tidy the graph would have been the actual mistake.
The gate encodes inward-only and reports zero production violations today.

**F5 was worse than "duplication", and F8 was worse than "a layering smell".**
Both turned out to have a live defect underneath:

- The three replay guards each hand-rolled the UNIQUE-violation marker set that
  `axiam_db::helpers::classify_write_error` had documented since D-09 as
  belonging in exactly one place — as did `federation_login_state` and the REST
  bootstrap handler. Five copies, each a security decision, none enforced.
- `getApiErrorMessage` read `response.data.error` first, which in
  `axiam_api_rest::error::ErrorBody` is a machine slug rather than prose, so
  ~40 call sites rendered `validation_error` where the server had written a
  sentence. Six pages had hand-rolled the correct order inline — and three of
  those dropped `redactSecrets` on the way past. The pages that would have
  exposed the bug were the ones routing around it.

Both are fixed, and both now have a CI gate or a regression test rather than a
convention.
