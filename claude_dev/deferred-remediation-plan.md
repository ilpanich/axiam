# Plan — Fix the Remaining (Deferred) Review Items

> Execution plan for the items deferred from the 2026-07-08 final review. Intended to be
> executed with Opus/Sonnet — each task carries a recommended model. Companion:
> [`remediation-2026-07-08.md`](remediation-2026-07-08.md) (what's already fixed) and
> [`final-review-2026-07-08.md`](final-review-2026-07-08.md) (the review).

## Context

The 2026-07-08 final review's HIGH/MED findings and the actionable LOW items are **already fixed, tested, and pushed** on `claude/code-quality-security-review-1r6bln` (commits `4951835`, `65765e9`). This plan covers the **deferred** items that remain — all LOW/MED.

Deferred items, grouped:
- **Backend correctness/perf**: CQ-B11 (409-on-duplicate), CQ-B16 (delete-missing-id → 404), CQ-B13 (authz N+1), CQ-B23 (OIDC discovery cache / body cap / error mapping).
- **NEW-4**: AMQP replay protection (nonce + issued_at inside the HMAC) — server + all 7 SDKs.
- **SDK contract-conformance**: SDK-Q02, Q03, Q08, Q09, Q10.

Each task has exact anchors (confirmed by exploration), the existing pattern to reuse, a **recommended model**, and any **decision point** with my recommended default. Do these as **separate commits** in the listed order; run the per-task verification before moving on. Set `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip` for any build of `axiam-api-rest`/`axiam-server`; the SAML feature needs `libxml2-dev` + `xmlsec1` installed; `cargo clean` between Rust-heavy plan steps (disk quota ~38 GB); run integration-test binaries **individually** (parallel linking exhausts the quota).

---

## Group A — Backend correctness & perf (do first; low risk)

### A1. CQ-B11 — duplicate create/RELATE should return 409, not 500  ·  Model: **Sonnet**
Reuse `classify_write_error(err, entity)` (`crates/axiam-db/src/helpers.rs:65-75`; routes "already exists/unique" → `DbError::AlreadyExists` → HTTP 409, unit-tested). Route these three write-path `.check()`/RELATE sites through it (keep any preceding domain-specific THROW branch; replace only the `Migration` fall-through):
- `crates/axiam-db/src/repository/role.rs:143-145` (`create`)
- `crates/axiam-db/src/repository/permission.rs:333-341` (`grant_to_role`, else-arm after the cross-tenant THROW)
- `crates/axiam-db/src/repository/certificate.rs:412-419` (cert→service-account binding, else-arm)

Also collapse the two hand-rolled `contains("already exists"|"unique")` triplets in `crates/axiam-db/src/seeder.rs:384-386,457-459`. **Leave `saml_replay.rs:70-83` alone** — it maps to `ReplayDetected`, not `AlreadyExists`. Do **not** touch the ~285 read-path `Uuid::parse_str → Migration` sites — out of scope.
- **Test**: assert a duplicate role create and duplicate permission grant return 409 (extend `crates/axiam-api-rest/tests/qual03_error_taxonomy_test.rs`).
- **Verify**: `cargo test -p axiam-db --lib` + the taxonomy integration test.

### A2. CQ-B16 — delete of a nonexistent id must return 404  ·  Model: **Sonnet**
Copy the "RETURN BEFORE → NotFound" pattern from `crates/axiam-db/src/repository/webhook.rs:234-257` / `federation_link.rs:198-221` into:
- `crates/axiam-db/src/repository/organization.rs:193-201` (hard delete)
- `crates/axiam-db/src/repository/user.rs:474-491` (soft-delete `UPDATE`; use `RETURN BEFORE` on the UPDATE, map empty → `DbError::NotFound`)

No handler changes — `crates/axiam-api-rest/src/error.rs:38` maps `NotFound` → 404; the `?` in `handlers/users.rs:355` / `handlers/organizations.rs:230` surfaces it. **Confirmed safe**: the GDPR/erasure pipeline (`crates/axiam-server/src/cleanup.rs`) does not call these deletes; the only callers are the two handlers.
- **Test**: assert DELETE of a random UUID → 404 (was 204).
- **Verify**: `cargo test -p axiam-api-rest --test rbac_test` (or the org/user handler tests) individually.

### A3. CQ-B13 — authz N+1  ·  Model: **Opus** (subtle SurrealQL semantics)
Two loops on the hot `check_access` path:
- **Per-role grant lookup**: `crates/axiam-authz/src/engine.rs:129-162` calls `permission_repo.get_role_permission_grants` once per role. Add a batched method (e.g. `get_role_permission_grants_for_roles(tenant_id, role_ids)`) in `crates/axiam-db/src/repository/permission.rs` (mirror `:483-519`) using `WHERE in IN $role_records AND out.tenant_id=$tenant_id`, returning the `in`/role id for grouping. Update the trait (`crates/axiam-core/src/repository.rs:379`). Preserve the `seen_roles` dedupe.
- **Ancestor walk**: `crates/axiam-db/src/repository/resource.rs:433-488` (`get_ancestors`) issues one SELECT per level. Replace with a single recursive/graph traversal (`->child_of->`), **preserving** `MAX_ANCESTOR_DEPTH=50` error semantics (`req14_tenant_isolation_test.rs:430-433`) and tenant scoping.
- **Verify**: `cargo test -p axiam-authz` + `cargo test -p axiam-db --test resource_scope_test --test req14_tenant_isolation_test --test role_permission_test`.

### A4. CQ-B23 — OIDC discovery cache + streaming body cap + error mapping  ·  Model: **Sonnet**
- **Cache**: add a `DiscoveryCache` modeled on `crates/axiam-federation/src/jwks_cache.rs` (1h TTL + 24h stale-serve, keyed by `(tenant_id, config_id)` or `metadata_url`). Wire into `oidc.rs:131-203` (`discover`) so `build_authorization_url` (`:241`) / `handle_callback` (`:306`) don't re-fetch per login.
- **Body cap**: `oidc.rs:164-176` buffers then checks 256 KiB → switch to a streaming/`take`-capped read (same for token-exchange from `:319`).
- **Error mapping**: `crates/axiam-federation/src/error.rs:132` catch-all `_ => Internal` (500) swallows `DiscoveryFailed`/token-exchange failures. Add explicit arms mapping upstream-IdP failures to a 502/400-class error.
- **Verify**: `cargo test -p axiam-federation` (add a cache-hit test mirroring `jwks_cache.rs:317+`; use the `allow_private` wiremock seam).

---

## Group B — NEW-4: AMQP replay protection  ·  Model: **Opus** (cross-cutting, byte-exact)

**Nature**: the server only *verifies* these messages; external producers sign them → a **versioned protocol change** gated on the existing `key_version` field.

**DECISION (confirmed)**: **Hard cutover + DB-backed nonce store.** Bump `CURRENT_KEY_VERSION` to **2** and require `nonce`+`issued_at` on every message. Consumers **reject** (nack, requeue:false) any message with `key_version < 2`, any message with a stale `issued_at` (outside the skew window), or a replayed `nonce`. No grace window / dual-accept path. Nonce dedup lives in a durable `amqp_nonce_replay` table modeled on the SAML replay repo (survives restarts, replica-shared). **This is a breaking change for external producers** — they must upgrade to emit the v2 schema *before* the server that enforces it is deployed; call this out prominently in `sdks/CONTRACT.md` §8, the AsyncAPI spec, and the changelog.

**Server (5 files):**
1. `crates/axiam-amqp/src/messages.rs` — set `CURRENT_KEY_VERSION = 2` (`messages.rs:32-46`); add `nonce: Uuid` + `issued_at: DateTime<Utc>` to `AuthzRequest` (after `key_version`, ~L137) and `AuditEventMessage` (~L174), **always-emitted** (`#[serde(default=...)]`, no `skip_serializing_if`) so they are inside the HMAC before `hmac_signature`. Add a freshness helper (configurable skew window, e.g. ±5 min).
2. `crates/axiam-amqp/src/authz_consumer.rs` — after signature verify (post-L122): **reject** any message with `key_version < 2`, a stale `issued_at`, or a replayed `nonce` (nack requeue:false, mirror the existing invalid-signature path). Extend `start_authz_consumer` (L28) with the nonce store + skew config.
3. `crates/axiam-amqp/src/audit_consumer.rs` — same, post-L119; extend `start_audit_consumer` (L39).
4. `crates/axiam-server/src/main.rs` — thread nonce store + skew config into both spawns (L639-648, L672-681).
5. New nonce store: trait in `crates/axiam-core/src/repository.rs` (mirror `AssertionReplayRepository` L895-912), impl mirroring `crates/axiam-db/src/repository/saml_replay.rs`, table in `schema.rs`, `cleanup_expired` hook in `cleanup.rs`.

**SDKs**: 6 of 7 re-serialize the whole received body minus `hmac_signature` (order-preserving) → nonce/issued_at auto-covered by the HMAC; they need only **validation** (reject `key_version < 2`, stale `issued_at`, and replayed `nonce` — hard-cutover parity with the server) plus optional DTO fields:
- **Go — MANDATORY struct edit**: `sdks/go/amqp/hmac.go` typed canonical structs (`authzRequestCanonical` L89-97, `auditEventCanonical` L105-115) — add `Nonce`/`IssuedAt` json-tagged fields in the exact slot (after `KeyVersion`) in **both**, else verification breaks. Validation in `consumer.go`/`event.go`.
- **Rust** `sdks/rust/src/amqp/consumer.rs` (validation) + `messages.rs` DTO (also add the missing `key_version`).
- **TypeScript** `sdks/typescript/src/amqp/consumer.ts` (validation) + `messages.ts` DTO (also add missing `key_version`).
- **Python** `_hmac.py`/consumer, **PHP** `Hmac.php`/consumer, **Java** `Hmac.java`/consumer, **C#** `Hmac.cs`/consumer — validation only.
- Regenerate `amqp_hmac_vectors.json` fixtures (python/php/java/csharp); update each SDK's hmac/consumer tests + `crates/axiam-amqp/src/messages.rs` tests (L326-361).

**Docs**: `sdks/CONTRACT.md` §8 and `docs/api/asyncapi.yml`.
**Verify**: `cargo test -p axiam-amqp`; per-SDK suites. Regression tests **must** sign over real server-declaration-order bytes with the new fields present (not self-serialized).

---

## Group C — SDK contract-conformance  ·  Model: **Sonnet** (mechanical, once rulings set)

### C1. SDK-Q03 — CONTRACT §8 + mirror-struct `key_version` drift
Only two typed mirrors drifted: **Rust SDK** `sdks/rust/src/amqp/messages.rs:28-44,53-68` and **TS SDK** `sdks/typescript/src/amqp/messages.ts:19-34,56-67` — add `key_version` + fix the inaccurate "field order matches server" comments. Document `key_version` + per-tenant HKDF in `sdks/CONTRACT.md` §8 (`:220-252`). Go/Python/PHP/Java consumers are schema-agnostic. Folds into Group B if NEW-4 is done.

### C2. SDK-Q10 — normalize authz request/decision models
- Rename gRPC deny field to match REST: `deny_reason`/`denyReason` → `reason` (Rust `grpc/client.rs:59-63`; TS `grpc/client.ts:81-84`); reconcile the two same-named `AccessDecision` types.
- TS: remove the declared-but-never-serialized `resourceType` from `AccessCheck` (`rest/types.ts:63-69`) — server has no `resource_type`.
- Align gRPC `subject_id` optionality with REST where the proto allows.
- **Verify**: `cargo test` (rust sdk) + `tsc --noEmit && vitest`.

### C3. SDK-Q02 — AuthzError fields (server change) + NetworkError cause  ·  Model: **Sonnet** (spans server + SDKs)
**Key fact**: the server's 403 body is `{error, message}` only — no structured `action`/`resource_id` (`crates/axiam-api-rest/src/error.rs:29-33,67`). **DECISION (confirmed): add structured fields to the server** so the CONTRACT §2 "from body" wording becomes genuinely satisfiable.
- **Server**: extend `AxiamError::AuthorizationDenied` (`crates/axiam-core/src/error.rs:16-17`) with `action: Option<String>` + `resource_id: Option<String>`; serialize them in `ErrorBody` (`crates/axiam-api-rest/src/error.rs:29-33`, keep them optional/omitted-when-null so other error kinds are unaffected); populate them at the denial site in `RequirePermission::check` (`crates/axiam-api-rest/src/authz.rs`), which already holds the checked `action`/`resource_id`. Update the handful of other `AuthorizationDenied { reason }` constructors to the new field set (grep for `AuthorizationDenied`).
- **SDKs**: each mapper now parses `action`/`resource_id` from the JSON error body — Rust (`error.rs:77-81,108-112`), Go (`errors.go:167,190`), Python (`_errors.py:176,222`), Java (`ErrorMapper.java:53,81`) fill their existing (currently-dead) fields; **C#** (`Core/AuthzError.cs`) and **PHP** (`Core/AuthzError.php`) gain the two fields. TS already populates from call-args — switch it to read the body too (`rest/authz.ts:76-91`).
- **NetworkError cause (MUST per §2)**: C# (`Core/NetworkError.cs:69,82`), PHP (`Core/NetworkError.php:28-34,68-78`), Java (`errors/NetworkError.java:35-37`) drop the transport cause. Chain a **sanitized** cause exposed via `InnerException`/`getPrevious`/`getCause`. Rust/Go/Python/TS already retain a cause slot.
- **Verify**: `cargo test -p axiam-api-rest` (assert the 403 body carries action/resource_id) + per-SDK error-mapper unit tests asserting the fields are parsed from the body.

### C4. SDK-Q08 / SDK-Q09 — async naming & PHP `can()` arg order (BREAKING)
**DECISION (recommended default in bold)**: **Make the breaks now (pre-1.0).**
- **Q09**: align PHP `can($resource,$action)` (`sdks/php/src/AxiamClient.php:289`) → `can($action, $resource)` (matches every other SDK and its own `checkAccess` at `:283`).
- **Q08**: separate `AsyncAxiamClient` for Python (move `async_*` off the sync class: `_client.py:160,178,269,342,373,386,398`); leave Java `*Async` and C# `*Async`-only as idiomatic but record the exception in CONTRACT §1 (`:31`).
- Update `sdks/CONTRACT.md` §1 + changelog. Alternatives: document-only, or PHP-only.
- **Verify**: per-SDK build/test; grep for old PHP-order call sites.

---

## Model recommendation summary

| Task | Model | Why |
|---|---|---|
| A1 CQ-B11, A2 CQ-B16 | **Sonnet** | Copy an existing helper/pattern into a few named sites. |
| A3 CQ-B13 | **Opus** | SurrealQL recursive-query rewrite must preserve depth/cycle/tenant semantics. |
| A4 CQ-B23 | **Sonnet** | Model a cache on `JwksCache`; mechanical error-mapping. |
| B NEW-4 | **Opus** | 13+ files across 8 codebases, byte-exact HMAC ordering, backward-compat gating. |
| C1 Q03, C2 Q10 | **Sonnet** | Mechanical struct/field/doc edits. |
| C3 Q02 | **Sonnet** | Server error-type + all-SDK mapper change (mechanical but cross-cutting). |
| C4 Q08/Q09 | **Sonnet** | Mechanical once the ruling is applied. |

## Confirmed decisions (2026-07-08)
1. **Scope** — execute **all three groups** (A, B, and C).
2. **NEW-4 rollout** — **hard cutover + DB nonce store** (bump `key_version` to 2, reject v1/missing-field/stale/replayed messages; durable `amqp_nonce_replay` table). Breaking for external producers — they must upgrade first; document in CONTRACT §8 + AsyncAPI + changelog.
3. **Breaking SDK changes (Q08/Q09)** — **make the breaks now** (PHP `can(action, resource)`; separate `AsyncAxiamClient` for Python; document the Java/C# async exceptions in CONTRACT §1).
4. **SDK-Q02** — **add structured `action`/`resource_id` to the server** `AuthorizationDenied` body, then parse them from the body in every SDK mapper.

## Verification (whole plan)
- Rust: `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; targeted `cargo test -p <crate>` per task (integration-test binaries **individually**).
- SDKs: per-language suites (`go test ./...`, `cargo test`, `tsc --noEmit && vitest run`, `pytest`, `mvn test`, `composer test`).
- End-to-end where a control changed: NEW-4 — exercise a signed message with the new fields and confirm a replayed/stale message is nacked; CQ-B23 — confirm a second discovery call is served from cache.
