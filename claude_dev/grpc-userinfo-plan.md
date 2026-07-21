# gRPC UserInfo — Implementation Plan

> **Status:** proposed — Phase 20 candidate
> **Branch (all repos):** `claude/grpc-userinfo-implementation-3txsph`
> **Goal:** add a Zitadel-style gRPC identity RPC ("userinfo over gRPC", equivalent of
> `zitadel.auth.v1.AuthService/GetMyUser`) to the AXIAM server, expose it in every SDK
> that has (or gains) a gRPC transport, update the server↔SDK contract, and cover
> everything with tests and benchmarks.

---

## 1. Motivation & background

- AXIAM serves OIDC userinfo only over REST (`GET /oauth2/userinfo`,
  `crates/axiam-api-rest/src/handlers/oauth2.rs:357`). Zitadel additionally exposes the
  same logical operation over gRPC (`AuthService/GetMyUser`: empty request, identity
  derived entirely from the `authorization` bearer metadata).
- Our own benchmark suite already documents the gap: `benchmarks/scenarios/zitadel_userinfo_grpc.js`
  is **Zitadel-only** ("AXIAM and Keycloak expose no equivalent gRPC identity RPC") and is
  excluded from cross-vendor winner tables (`runner/report.py` `NON_COMPARATIVE_SCENARIOS`).
- Adding the RPC (a) gives service-mesh consumers a low-latency identity call on the
  existing `:50051` gRPC port, (b) turns the userinfo-gRPC benchmark into a real
  AXIAM-vs-Zitadel protocol comparison, and (c) extends the SDK contract with one new
  canonical operation.

## 2. Design decisions (locked before implementation)

### 2.1 Proto surface — new file `proto/axiam/v1/userinfo.proto`

A **new service** rather than a new RPC on `UserService`: `UserService.GetUser` is an
admin-style lookup taking `tenant_id`/`user_id` in the body, while userinfo is a
*self* lookup with identity taken from the token. Adding a service/file is additive
(passes `buf breaking` `FILE` mode in `sdk-buf-gates.yml`); reusing `UserService` would
mix two auth models in one service.

```proto
syntax = "proto3";

package axiam.v1;

option php_metadata_namespace = "Axiam\\Sdk\\Grpc\\Gen\\Metadata";
// PHP-only codegen options — must match authorization.proto's values so all
// files in package axiam.v1 agree (buf PACKAGE_SAME_PHP_NAMESPACE). Ignored
// by every other language's codegen.
option php_namespace = "Axiam\\Sdk\\Grpc\\Gen";

// OIDC-style userinfo for the *authenticated* caller. Identity is derived
// entirely from the `authorization: Bearer <access_token>` metadata header
// (validated by the server's auth interceptor) — the request body is empty,
// mirroring zitadel.auth.v1.AuthService/GetMyUser.
service UserInfoService {
  rpc GetUserInfo(GetUserInfoRequest) returns (GetUserInfoResponse);
}

message GetUserInfoRequest {}

message GetUserInfoResponse {
  // Subject (user) UUID — always present.
  string sub = 1;
  // Tenant UUID — always present.
  string tenant_id = 2;
  // Organization UUID — always present.
  string org_id = 3;
  // Present only when the token carries the "email" scope.
  optional string email = 4;
  // Present only when the token carries the "profile" scope.
  optional string preferred_username = 5;
}
```

Notes:
- Field set and scope gating mirror the REST handler exactly
  (`UserInfoResponse` in `crates/axiam-oauth2/src/oidc.rs:141-150` + scope logic in
  `handlers/oauth2.rs:361-416`): `email` scope → `email`, `profile` scope →
  `preferred_username`; `sub`/`tenant_id`/`org_id` always returned.
- `proto3 optional` gives wire-level presence, matching REST's
  `skip_serializing_if = Option::is_none`.
- Request/response names follow buf `STANDARD` lint (`RPC_REQUEST_STANDARD_NAME`;
  `RPC_RESPONSE_STANDARD_NAME` is already excepted in `buf.yaml` but we conform anyway).
- No `last_login` field in v1 (Zitadel returns it; AXIAM does not track it in the
  user record surfaced by `UserRepository` — deliberately out of scope, documented).

### 2.2 Authentication

Reuse the existing `AuthInterceptor` (`crates/axiam-api-grpc/src/middleware/auth.rs`):
it validates the `authorization` bearer token and injects `ValidatedClaims` into request
extensions. The handler reads `sub`, `tenant_id`, `org_id`, `scope` from the claims —
no request fields, no new auth code paths. Invalid/missing token → `UNAUTHENTICATED`
(already produced by the interceptor), which maps to `AuthenticationError` in the SDK
error taxonomy (CONTRACT §2 gRPC table — **no contract change needed** for errors).

### 2.3 Contract semantics — new canonical operation `get_user_info`

CONTRACT.md §1 locks the SDK method vocabulary, so this is a formal contract amendment
(contract version bump 1.2 → 1.3 + Breaking Changes Log entry — additive, not breaking):

| Language | Method name | Notes |
|---|---|---|
| Rust, C++ | `get_user_info` | |
| TypeScript, PHP, Java, Kotlin, Swift | `getUserInfo` | Java also gets `getUserInfoAsync` per §1 async rules |
| Python | `get_user_info` | sync + `AsyncAxiamClient.get_user_info` |
| C# | `GetUserInfoAsync` | TAP-only per §1 |
| Go | `GetUserInfo` | |
| C | `axiam_get_user_info` | only if/when C gains gRPC (see Phase E) |

Semantics (normative):
- **Transport: gRPC only.** Calls `axiam.v1.UserInfoService/GetUserInfo` on the SDK's
  gRPC channel with `authorization: Bearer <current access token>` and the `x-tenant-id`
  metadata key (CONTRACT §5 rule already covers all outgoing RPCs).
- Requires a prior successful `login()` (or an explicitly injected token); calling it
  without a token raises `AuthenticationError` client-side without a wire call.
- A gRPC `UNAUTHENTICATED` response participates in the §9 single-flight refresh guard
  exactly like a REST 401 (the contract text already says "401 (or gRPC
  `UNAUTHENTICATED`)" — reference it, don't duplicate it).
- Returns a small struct/record `UserInfo { sub, tenant_id, org_id, email?, preferred_username? }`.
- SDKs without a gRPC transport (Kotlin, Swift, C, C++ today) MUST document the
  operation as a deferred follow-up in their scope section, same pattern as their
  existing "gRPC transport deferred" carve-out. They MUST NOT silently substitute the
  REST endpoint (the REST endpoint is intentionally not part of the SDK vocabulary —
  see `benchmarks/sdk/HARNESS-SPEC.md`).

### 2.4 Explicit non-goals (v1 of this feature)

- No gRPC health/reflection wiring (net-new infra, separate task if ever needed).
- No `last_login` claim (not tracked).
- No REST fallback method in SDKs.
- No new AMQP surface.

---

## 3. Work breakdown

Phases A–F. Within a phase tasks are independent unless a dependency is listed. Every
task = one signed commit (repo dev process). **Model** column = cheapest Claude model
that reliably completes the task (see §6 for rationale); prices per MTok in/out:
Haiku 4.5 `claude-haiku-4-5` $1/$5 · Sonnet 5 `claude-sonnet-5` $3/$15 · Opus 4.8
`claude-opus-4-8` $5/$25.

### Phase A — Contract & proto (repo `ilpanich/axiam`)

| ID | Task | Model |
|---|---|---|
| A1 | Proto definition + gates | **Opus 4.8** |
| A2 | CONTRACT.md amendment | **Opus 4.8** |
| A3 | HARNESS-SPEC amendment | **Sonnet 5** |

**A1 — `proto/axiam/v1/userinfo.proto`**
1. Create the file exactly as in §2.1 (copy the PHP-namespace option block verbatim from
   `user.proto:5-9`).
2. Run `buf lint proto` and `buf format -w proto` locally; run
   `buf breaking proto --against '.git#branch=main,subdir=proto'` — must pass (additive).
3. Acceptance: `sdk-buf-gates.yml` green on the PR; no changes to existing proto files.

**A2 — `sdks/CONTRACT.md`**
1. §1: add a `get userinfo` row to the naming map table with the per-language spellings
   from §2.3; extend the "Additional languages" paragraph (Kotlin/Swift/C/C++) with the
   new name and the "deferred until gRPC transport exists" note.
2. Add a short **§1.1 "gRPC-only operations"** subsection stating the normative semantics
   from §2.3 (transport, metadata, auth failure behavior, return shape, deferral rule).
3. §5: no change needed (the `x-tenant-id` rule already says "every outgoing RPC") — add
   `GetUserInfo` to any RPC enumeration if one exists; otherwise leave.
4. Closing notes: bump "Contract version: 1.2 — Phase 15" → "1.3 — Phase 20 (gRPC
   userinfo)"; append a Breaking Changes Log entry marked **additive**.
5. Acceptance: contract self-consistent; §1 note "No SDK is permitted to expose
   additional … method names" updated to include the new canonical name.

**A3 — `benchmarks/sdk/HARNESS-SPEC.md`**
1. Move `userinfo` out of the "Out of SDK-harness scope" paragraph: keep `oauth2_token`
   and `introspect` there; add a new `get_user_info` row to the op table ("gRPC-only —
   only SDKs with a gRPC transport implement it; benches emit `pending` otherwise").
2. Document required env (`BENCH_GRPC_ADDR` already exists) and that the op needs a
   token minted by a prior `login`.
3. Acceptance: spec text matches what Phase D benches implement.

### Phase B — Server implementation (repo `ilpanich/axiam`, crate `axiam-api-grpc`)

Depends on A1. Remember the sandbox rules: `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip` before any build touching `axiam-api-rest`, scope cargo commands with `-p`, `cargo clean` between plan steps.

| ID | Task | Model |
|---|---|---|
| B1 | Service implementation + registration | **Sonnet 5** |
| B2 | Unit + integration tests, CI wiring | **Sonnet 5** |

**B1 — implement `UserInfoService`**
1. `crates/axiam-api-grpc/build.rs`: add `../../proto/axiam/v1/userinfo.proto` to the
   `compile_protos` list.
2. New `crates/axiam-api-grpc/src/services/userinfo.rs`:
   - `UserInfoServiceImpl` holding `user_repo: U` (+ nothing else — claims come from the
     interceptor). Mirror the structure of `services/user.rs`.
   - `get_user_info`: read `ValidatedClaims` from `request.extensions()` (as
     `services/token.rs:32-38` does); parse the space-delimited `claims.0.scope`;
     if `email` **or** `profile` scope present, fetch the user via
     `user_repo.get_by_id(tenant_id, sub)`; gate `email` / `preferred_username` per scope
     exactly like `handlers/oauth2.rs:381-392`; repo error → `Status::internal` with a
     generic message (no detail leakage); missing claims → `Status::unauthenticated`.
   - Export from `services/mod.rs`.
3. `crates/axiam-api-grpc/src/server.rs`: construct
   `UserInfoServiceServer::with_interceptor(UserInfoServiceImpl::new(user_repo.clone()), AuthInterceptor::new(auth_config.clone()))`
   and `.add_service(...)` in **both** the TLS and plaintext branches
   (`server.rs:164-166` and `:175-178`).
4. No changes to `axiam-server/src/main.rs` (user repo already threaded into
   `start_grpc_server`).
5. Gate: `cargo clippy -p axiam-api-grpc --lib`, `cargo fmt -p axiam-api-grpc -- --check`,
   `cargo test -p axiam-api-grpc --lib`.

**B2 — tests**
1. Unit tests (in `tests/grpc_units.rs` or `#[cfg(test)]` in `userinfo.rs`): scope-string
   parsing, claim gating matrix (none / email / profile / both), missing-claims path.
2. New integration test `crates/axiam-api-grpc/tests/grpc_userinfo_test.rs`, cloned from
   the `grpc_authz_test.rs` harness (in-process tonic server on `127.0.0.1:0`, SurrealDB
   `Mem` + migrations, `authed_client!`-style bearer injection). Cases:
   - valid token, `openid` only → sub/tenant/org present, email & username absent;
   - `openid email profile` → all fields, values match the seeded user;
   - no/garbage token → `UNAUTHENTICATED`;
   - token for a user deleted after issuance → deterministic error (assert the chosen
     status; document it in the proto comment);
   - tenant isolation: token from tenant A never returns tenant B data.
3. `Cargo.toml`: add the `[[test]]` block with `required-features = ["client"]`.
4. `.github/workflows/ci.yml`: extend the gRPC test invocation (line ~265) with
   `--test grpc_userinfo_test`.
5. Acceptance: `cargo test -p axiam-api-grpc --features client --test grpc_userinfo_test`
   green locally and in CI.

### Phase C — Server-side benchmarks (repo `ilpanich/axiam`)

Depends on B. | ID | Task | Model |
|---|---|---|
| C1 | k6 scenario `userinfo_grpc.js` (AXIAM) | **Sonnet 5** |
| C2 | Runner/report pairing | **Sonnet 5** |

**C1 —** new `benchmarks/scenarios/userinfo_grpc.js` modeled on `authz_check_grpc.js`
(AXIAM dials dedicated plaintext `:50051`, see `lib/config.js` `grpcPlaintext`): load
`proto/axiam/v1/userinfo.proto` from the repo's `proto/` tree (add a vendored trimmed
copy under `scenarios/proto/axiam/` if the k6 import-root convention requires it, with a
README mirroring `scenarios/proto/zitadel/README.md`), `setup()` mints a real user token
via `mintUserToken()`, invoke `axiam.v1.UserInfoService/GetUserInfo` with `{}` +
bearer metadata, record `bench_op_latency_ms`, grpc status, error rate — same metric
shape as `zitadel_userinfo_grpc.js`.

**C2 —** `runner/run-benchmark.sh`: schedule `userinfo_grpc` for AXIAM; decide pairing in
`runner/report.py`: keep both scenarios in the *protocol-efficiency* class but now emit
an AXIAM↔Zitadel gRPC-userinfo comparison table (remove `zitadel_userinfo_grpc` from
`NON_COMPARATIVE_SCENARIOS` only if the harness rules in `docs/methodology.md` §3 are
updated in the same commit; Keycloak still has no equivalent, so the table is two-vendor
— document that). Update `benchmarks/README.md` + `docs/methodology.md`.

### Phase D — gRPC-capable SDKs (7 repos: rust, typescript, python, java, csharp, php, go)

Depends on A (contract/proto) and B (a server to integration-test against; unit tests
use in-process mock servers and don't block). Each repo gets **two commits**: a
mechanical sync commit and an implementation commit. Per-repo checklist:

**D\<lang\>.1 — sync vendored contract inputs** — Model: **Haiku 4.5**
1. Copy `sdks/CONTRACT.md` → repo root `CONTRACT.md`; copy `proto/` tree (now including
   `userinfo.proto`) over the vendored `proto/` (openapi.json unchanged — no REST change).
2. Regenerate stubs: `buf generate` (all except C#; C# uses `Grpc.Tools` at build time —
   just ensure `userinfo.proto` is included in the `.csproj` `<Protobuf>` globs).
3. Commit only sync + generated artifacts; build must still pass.

**D\<lang\>.2 — implement `get_user_info` + tests + docs** — Model: **Sonnet 5**
1. Add the canonical method (per-language spelling from §2.3) to the client class next
   to the existing gRPC-backed calls, reusing the existing channel/interceptor machinery
   (e.g. Rust: `src/grpc/client.rs` + `interceptor.rs`; each SDK already injects
   `authorization` and `x-tenant-id` metadata — reuse, don't duplicate).
2. Behavior per §2.3: pre-flight `AuthenticationError` when no token; map
   `UNAUTHENTICATED` through the §9 single-flight refresh guard exactly like existing
   gRPC calls; return a typed `UserInfo` model with optional `email`/`preferred_username`.
3. Tests (same framework each repo already uses for its gRPC calls — in-process/mock
   gRPC server): happy path with all claims; minimal-claims path (optionals absent);
   unauthenticated → error type per CONTRACT §2; refresh-then-retry path; metadata
   assertion (`authorization` + `x-tenant-id` present).
4. Docs: README method table + conformance statement (now "§1–§11" wording per contract
   1.3), CHANGELOG entry, example snippet in `examples/`.
5. Acceptance: repo CI green; method naming matches CONTRACT §1 exactly.

Applies to: `axiam-rust-sdk`, `axiam-typescript-sdk`, `axiam-python-sdk`,
`axiam-java-sdk`, `axiam-csharp-sdk`, `axiam-php-sdk`, `axiam-go-sdk`.
(PHP note: route through the existing transport dispatcher that "already prefers gRPC";
Java note: `getUserInfo` + `getUserInfoAsync`; C# note: `GetUserInfoAsync` only.)

### Phase E — REST-only SDKs (kotlin, swift, c, cplusplus)

These four have **no gRPC transport** (explicitly deferred in each repo's v1 scope), so
"add the gRPC userinfo call" decomposes into a default track and an opt-in track:

**E\<lang\>.1 (default, do now) — sync + documented deferral** — Model: **Haiku 4.5**
1. Sync `CONTRACT.md` + `proto/` (Swift already vendors `proto/`; add the tree to C/C++
   /Kotlin if absent — it's a contract-mandated vendored input regardless of transport).
2. README scope table: add `get_user_info` under the existing "gRPC transport — deferred
   follow-up" row; CHANGELOG entry noting contract 1.3 adoption.
3. Acceptance: no code change, CI green, scope statement honest.

**E\<lang\>.2 (opt-in, separate decision) — minimal gRPC transport (UserInfo only)**
Not scheduled by default — sized here so the decision can be made deliberately:
- Kotlin: `grpc-kotlin` + Netty/OkHttp channel, TLS per §6 — moderate. Model: **Sonnet 5**.
- Swift: `grpc-swift` (SwiftNIO), TLS via NIOSSL — moderate. Model: **Sonnet 5**.
- C++: `gRPC` C++ core, CMake/vcpkg integration cost is high. Model: **Opus 4.8**.
- C: gRPC has no supported pure-C API surface worth shipping (gRPC Core is explicitly
  not a public API); realistic option is wrapping the C++ lib behind the `axiam_` C API,
  which drags a C++ toolchain into a C11 SDK. **Recommendation: keep deferred.** If
  forced: **Opus 4.8**.

Recommendation: ship E*.1 in this phase; open one GitHub issue per repo for E*.2 and
decide after v1.0-beta.

### Phase F — SDK benchmarks + closeout (repo `ilpanich/axiam` + SDK repos)

Depends on D. | ID | Task | Model |
|---|---|---|
| F1 | Add `get_user_info` op to the 7 gRPC-capable SDK benches (`benchmarks/sdk/<lang>/`): timed loop after `login`, concurrency `SDK_BENCH_CONCURRENCY`, emit `ok/pending/error` records per harness spec; the 4 REST-only benches emit `pending` with reason `grpc-not-supported`. | **Sonnet 5** |
| F2 | End-of-phase regression gate in `axiam`: full `just check` / unscoped `cargo test` (per repo rules this is the one allowed unscoped run), `sdk-openapi-drift` (expected no-op), buf gates. | **Haiku 4.5** |
| F3 | Docs & roadmap: append Phase 20 tasks to `claude_dev/roadmap.md`, update `website/src/docs.ts` + `docs/` gRPC pages with the new RPC, note in `docs/compliance/oidc-conformance.md` that gRPC userinfo mirrors the REST claim set. | **Sonnet 5** |
| F4 | PRs: one PR per repo referencing the tracking issue(s); axiam PR description lists the phase issues per repo guidelines. | **Haiku 4.5** |

---

## 4. Sequencing

```
A1 ─┬─▶ B1 ─▶ B2 ─▶ C1 ─▶ C2 ─▶ F2
A2 ─┤                            ▲
A3 ─┴─▶ D<lang>.1 ─▶ D<lang>.2 ─▶ F1 ─▶ F3 ─▶ F4
        E<lang>.1 (anytime after A2)
```

D-repo tasks are mutually independent → the 7 SDK repos can run in parallel sessions.

## 5. Test & benchmark summary (what "done" means)

| Layer | Coverage |
|---|---|
| Server unit | scope parsing, claim gating matrix, error paths (`grpc_units` / inline) |
| Server integration | `grpc_userinfo_test.rs`: token validity, scope gating, tenant isolation, deleted-user, wired into `ci.yml` |
| Contract gates | `buf lint` + `buf breaking` (additive), `sdk-openapi-drift` no-op |
| SDK unit/integration | per-repo mock-server tests: claims mapping, error taxonomy, single-flight refresh on `UNAUTHENTICATED`, metadata injection |
| Server benchmark | k6 `userinfo_grpc.js` (AXIAM) paired with `zitadel_userinfo_grpc.js`; report.py two-vendor table; methodology updated |
| SDK benchmark | `get_user_info` op in all 7 gRPC-capable benches; REST-only benches emit `pending` |

## 6. Model selection rationale ("best but cheapest")

Current models/pricing (per MTok input/output): **Haiku 4.5** (`claude-haiku-4-5`,
$1/$5), **Sonnet 5** (`claude-sonnet-5`, $3/$15 — intro $2/$10 through 2026-08-31),
**Opus 4.8** (`claude-opus-4-8`, $5/$25), Fable 5 (`claude-fable-5`, $10/$50).

- **Opus 4.8** only where a mistake is expensive to unwind across 12 repos: the proto
  wire contract (A1) and the normative CONTRACT.md amendment (A2), plus the C/C++ gRPC
  transports if E*.2 is ever green-lit (heavy build-system + FFI reasoning).
- **Sonnet 5** for all implementation work (server Rust, SDK clients, tests, k6,
  report.py): near-Opus coding quality at 3/5 the price; every one of these tasks has a
  strong local safety net (compilers, existing test harnesses, CI gates) that catches
  slips cheaply.
- **Haiku 4.5** for mechanical work with no design freedom: vendored-file syncs, stub
  regeneration commits, CHANGELOG/README rows, regression-gate runs, PR assembly.
- **Fable 5 is not recommended for any task here** — nothing in this plan needs
  frontier-length autonomous reasoning, so it is never the cheapest adequate choice.

Per-task assignments are in the tables of §3.

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| buf `PACKAGE_SAME_PHP_NAMESPACE` failure on new file | copy the option block verbatim from `user.proto:5-9` (A1 step 1) |
| Contract drift across 11 vendored copies | D*.1/E*.1 are single-purpose sync commits; F2 verifies `CONTRACT.md` sha match across repos |
| Report pairing invalidates historical benchmark data | C2 updates `docs/methodology.md` in the same commit; keep the scenario key `userinfo_grpc` distinct from REST `userinfo` |
| `deleted-after-issuance` behavior undefined | B2 pins it with a test and the proto comment documents the chosen status |
| C SDK gRPC expectation | explicitly deferred with rationale (E, §2.4); tracked as issues |
