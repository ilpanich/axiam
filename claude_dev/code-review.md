# AXIAM — Full Code Review (Quality & Correctness)

- **Date**: 2026-06-09
- **Scope**: Entire repository at commit `6f2676d` — all 13 Rust crates (~47k LoC), React/TypeScript frontend (~17k LoC), workspace config, build tooling.
- **Method**: Manual line-level review split across backend core crates, backend API/protocol crates, and the frontend, verified with `cargo clippy --workspace --all-targets` (**clean — zero warnings**), `tsc -b` (**clean**), `eslint .` (**9 errors**, see CQ-F06), Playwright/e2e inventory, and dependency inspection.
- **Companion document**: [`security-review.md`](security-review.md). Findings that are primarily security issues live there; overlapping items are cross-referenced as `SEC-NNN`.

Finding IDs: `CQ-Bnn` = backend, `CQ-Fnn` = frontend. IDs are stable — use them to drive and track fixes.

---

## Executive summary

The architecture is sound and consistent: clean crate layering (core traits → db impls → protocol crates → server), thin handlers, complete OpenAPI registration, a real frontend services layer with react-query, strict TypeScript with zero `any`, and genuinely good REST integration tests (~230 test fns against in-memory SurrealDB). Clippy is clean.

The dominant problems are:

1. **Composition bugs in `main.rs`** — services constructed inconsistently produce real defects (the pepper bug CQ-B01 breaks login for REST-created users; the PKI zero-key fallback is SEC-012).
2. **Blocking CPU work on async executors** (Argon2, RSA-4096/PGP keygen) with zero `spawn_blocking` in the workspace.
3. **Mechanical duplication with drift** — ~28 near-identical repository files, ~14 near-identical frontend CRUD pages; the copies have already diverged in correctness-relevant ways (tenant guarding, error mapping, debouncing, pagination).
4. **Reliability gaps** in AMQP (audit events silently dropped), migrations (non-idempotent, non-transactional), and multi-statement graph mutations (no transactions).

| Priority | Backend | Frontend |
|---|---|---|
| High | 9 | 8 |
| Medium | 17 | 10 |
| Low | 8 | 7 |

### Suggested fix order

1. CQ-B01 (pepper), CQ-B02 (blocking async), CQ-B05 (AMQP audit loss), CQ-B06 (migrations) — production-breaking or data-loss class.
2. CQ-B03 / CQ-B04 (settings snapshot + double-`Option` clearing) — silent wrong behavior.
3. CQ-F01–CQ-F08 — user-visible frontend bugs, lint gate.
4. Structural debt: CQ-B09/CQ-B10 (dup hashing, repo boilerplate), CQ-F15 (CRUD page abstraction) — do these before more handlers/pages land.
5. Test gaps: axiam-pki (zero tests), gRPC/AMQP/federation (zero tests), webauthn/password-reset/notification handlers (zero REST tests).

---

# Backend findings

## High

### CQ-B01 [HIGH] Users created via REST can never log in when a password pepper is configured
- **File**: `crates/axiam-server/src/main.rs:96`; `crates/axiam-db/src/repository/user.rs:178-196`; `crates/axiam-auth/src/service.rs:183-187`
- **Type**: Bug (composition)
- **Issue**: `SurrealUserRepository::new` hardcodes `pepper: None` (the `with_pepper` constructor exists but is never called), so `POST /api/v1/users` hashes **without** the pepper, while login/gRPC/password-reset verify **with** `config.auth.pepper`. With a pepper configured, every REST-created user fails login until they password-reset.
- **Fix**: Construct with `with_pepper(db, config.auth.pepper)` in `main.rs` — but the better fix is CQ-B09: a single hashing path in axiam-auth.

### CQ-B02 [HIGH] Blocking CPU-heavy crypto on async executor threads (no `spawn_blocking` anywhere)
- **File**: Argon2: `crates/axiam-auth/src/service.rs:183`, `crates/axiam-db/src/repository/user.rs:196`, `crates/axiam-auth/src/policy.rs:243-263` (history loop — up to N verifications per password change), `password_reset.rs:178`, `crates/axiam-api-grpc/src/services/user.rs:126-131`. Keygen: `crates/axiam-pki/src/ca.rs:62`, `cert.rs:110`, `pgp.rs:42, 196-228`.
- **Type**: Bug (async)
- **Issue**: Argon2id (~20-100 ms CPU + 19 MiB per call) runs inline in `/auth/login` and friends; RSA-4096/PGP generation (seconds of CPU) runs inline in certificate/PGP services. A burst of logins or one cert request stalls Tokio/Actix workers, delaying all requests including health checks.
- **Fix**: Wrap hash/verify/keygen/sign/encrypt in `tokio::task::spawn_blocking`; consider a semaphore to bound concurrent hashes. Also verify rcgen's backend actually supports RSA generation (ring does not; aws-lc-rs does) — nothing tests the `Rsa4096` path (CQ-B24).

### CQ-B03 [HIGH] Tenant settings store a write-time merged snapshot — org baseline changes never propagate
- **File**: `crates/axiam-db/src/repository/settings.rs:524-542`; `crates/axiam-api-rest/src/handlers/settings.rs:134-149`; `diff_against_org` in core settings model
- **Type**: Bug (design)
- **Issue**: `PUT /settings` persists the fully *merged* row (org baseline + overrides). When the org later changes a baseline value, every field where the stored row still holds the old org value now *differs* from the new baseline, so `diff_against_org` misclassifies it as a tenant override and the stale value wins — the opposite of the code comment's claim. Which fields were "explicitly overridden" is unrecoverable from a merged row. Security implication tracked as SEC-033 (MFA enforcement freezes).
- **Fix**: Persist the sparse `TenantSettingsOverride` (`Option` fields) and merge against the live org baseline at read time.

### CQ-B04 [HIGH] "Clear field" double-`Option` semantics unreachable from JSON
- **File**: `crates/axiam-core/src/models/resource.rs:37` (`parent_id: Option<Option<Uuid>>` via `handlers/resources.rs:112-122`); `handlers/federation.rs:50` (`metadata_url: Option<Option<String>>`)
- **Type**: Bug (serde)
- **Issue**: With plain serde, JSON `null` deserializes the outer `Option` to `None` ("no change"); `Some(None)` ("clear") is unreachable without `serde_with::double_option` (not used anywhere in the workspace). Consequently `PUT /resources/{id}` can never move a resource to root, and `PUT /federation-configs/{id}` can never clear `metadata_url`. The federation handler even validates the `Some(Some(""))` case clients cannot send. The frontend compounds this by sending `undefined` for "clear" (CQ-F12).
- **Fix**: `#[serde(default, with = "serde_with::rust::double_option")]` on these fields; add a test asserting `null` clears the parent.

### CQ-B05 [HIGH] AMQP: audit events and authz requests silently dropped on transient failures; no dead-letter queue
- **File**: `crates/axiam-amqp/src/audit_consumer.rs:140`; `authz_consumer.rs:122, 146, 175-181`; `connection.rs:100-115`
- **Type**: Bug (reliability / compliance)
- **Issue**: `BasicNackOptions::default()` is `requeue: false` — a transient DB outage permanently drops audit events (a compliance feature), and failed publishes drop authz requests with no response to the caller. No DLX is declared, so poison messages vanish rather than being quarantined. Conversely, broker-nack handling uses `requeue: true`, which can hot-loop.
- **Fix**: Declare queues with a dead-letter exchange; requeue on transient errors, dead-letter on parse errors, cap redeliveries.

### CQ-B06 [HIGH] Migration runner is not idempotent, not transactional, and has no concurrency guard
- **File**: `crates/axiam-db/src/schema.rs:117-440, 787-844`
- **Type**: Bug
- **Issue**: The doc comment claims "All DEFINE statements are idempotent", but only the `_migration` DDL uses `IF NOT EXISTS`; V1–V14 use plain `DEFINE`, which errors on re-run in SurrealDB ≥2. Migration apply + record insert are two statements with no transaction — if the record insert fails, the next startup re-runs the migration and fails permanently. Two replicas starting concurrently race the same window.
- **Fix**: `IF NOT EXISTS`/`OVERWRITE` on all DDL; wrap apply+record in a transaction; serialize startup migration via a lock record.

### CQ-B07 [HIGH] Multi-statement graph deletes run unguarded and without transactions
- **File**: `crates/axiam-db/src/repository/role.rs:252-270` (same pattern: permission.rs:247-264, resource.rs:257-277, group/service_account deletes)
- **Type**: Bug
- **Issue**: `DELETE has_role WHERE out = role:...; DELETE grants ...; DELETE role WHERE tenant_id = $tenant_id;` — only the final record delete is tenant-guarded. A wrong-tenant call leaves the role intact but destroys all its edges (silently revoking assignments — see SEC-007 for the isolation angle). No `BEGIN/COMMIT`, so partial failure leaves the graph inconsistent.
- **Fix**: Verify tenant ownership first (or guard edge deletes with `out.tenant_id = $tenant_id`); wrap multi-statement mutations in transactions.

### CQ-B08 [HIGH] Resource hierarchy: cycles not prevented; `get_ancestors` silently truncates; orphaned children on delete
- **File**: `crates/axiam-db/src/repository/resource.rs:86, 172-255, 350-393`
- **Type**: Bug
- **Issue**: `update` allows setting `parent_id` to a descendant (or self) — no cycle check. With a cycle, `get_ancestors` loops `MAX_ANCESTOR_DEPTH=50` iterations pushing duplicates and returns garbage **without error**, making authorization decisions depth-dependent. `delete` cleans edges but leaves children's `parent_id` dangling.
- **Fix**: Reject parent updates creating cycles (walk new parent's ancestors); return an error (not truncation) past MAX depth; null children's `parent_id` on delete. The frontend parent picker has the matching bug (CQ-F12).

### CQ-B09 [HIGH] Password hashing/verification duplicated between axiam-db and axiam-auth — both live in production
- **File**: `crates/axiam-db/src/repository/user.rs:138-159, 482-503` vs `crates/axiam-auth/src/password.rs:13-66`
- **Type**: Duplication (correctness-critical)
- **Issue**: `hash_password`/`verify_password` are copy-pasted with different error types; gRPC uses the db copy, login uses the auth copy. Drift in pepper handling or Argon2 params changes who can log in — CQ-B01 is exactly this class of failure. Partial duplication also in `generate_client_id/secret` (service_account.rs vs oauth2_client.rs).
- **Fix**: One implementation (axiam-auth or a small shared crypto module); delete the db copy; route gRPC through it.

## Medium

### CQ-B10 [MEDIUM] ~28 repositories duplicate Row/CountRow/UUID-parse/pagination boilerplate, with visible drift
- **File**: `crates/axiam-db/src/repository/*.rs` (e.g. user.rs:21-132, role.rs:13-95, group.rs:15-118)
- **Type**: Duplication
- **Issue**: Every repo re-implements `XxxRow`+`XxxRowWithId`, `CountRow` (20+ copies), the count+select pagination pair, `.check().map_err(...)`, and per-field UUID/status parsing (~80 copies). Drift is already real: some repos `.check()` and some don't; some return `NotFound` on 0-row delete and some return `Ok(())`; one repo lacks `#[derive(Clone)]`.
- **Fix**: Shared helpers — `parse_uuid(field, s)`, generic `paginate<T>(db, table, where, pagination)`, one `CountRow`, `take_first_or_not_found`. Would roughly halve the crate and eliminate per-repo drift.

### CQ-B11 [MEDIUM] `DbError::Migration` is a catch-all for every non-NotFound failure; conflicts surface as 500s
- **File**: `crates/axiam-db/src/error.rs:5-17` (used in ~200 places)
- **Type**: Error handling
- **Issue**: Constraint violations (duplicate username on the unique index), row-decode failures, even Argon2 errors all become "Migration failed: …". `AxiamError::AlreadyExists` exists but is never produced by the db layer — duplicate-username create returns a misleading 500 instead of 409.
- **Fix**: Add `DbError::Query`/`Decode`/`Conflict` variants; detect SurrealDB index-violation errors → `AlreadyExists`; remove crypto from the db error space (per CQ-B09).

### CQ-B12 [MEDIUM] `login` swallows database errors from the email lookup
- **File**: `crates/axiam-auth/src/service.rs:167-171`
- **Type**: Error handling
- **Issue**: `.map_err(|_| AuthError::InvalidCredentials)` — a DB outage during the email-fallback lookup reports "invalid credentials" instead of an internal error, hiding incidents.
- **Fix**: Match `NotFound` only (as the username branch does); propagate other errors.

### CQ-B13 [MEDIUM] AuthZ engine: N+1 queries, sequential ancestor walk, dead generic parameter
- **File**: `crates/axiam-authz/src/engine.rs:33-35, 121-133`; `crates/axiam-db/src/repository/resource.rs:350-393`
- **Type**: Performance / Design
- **Issue**: One query per applicable role plus one per hierarchy level — a single `check_access` (the hot path of an IAM product) can cost 3 + roles + depth round-trips. `group_repo` is `#[allow(dead_code)]` yet forces a fifth generic parameter on every instantiation.
- **Fix**: Batched `get_permission_grants_for_roles(&[Uuid])`; recursive/graph query for ancestors (the `child_of` edges exist but are unused for traversal); drop the dead generic.

### CQ-B14 [MEDIUM] Ed25519 PEM keys re-parsed on every token issue/validate; four near-identical JWT helpers
- **File**: `crates/axiam-auth/src/token.rs:68, 106, 183, 196`; `service.rs:659-723`; `webauthn.rs:313-327`
- **Type**: Performance / Duplication
- **Issue**: `EncodingKey::from_ed_pem` per call on the hottest path (every request-level validation); key-parse errors surface at request time instead of startup. The issue/decode helpers for access/client-credentials/MFA-challenge/MFA-setup tokens are near-verbatim copies.
- **Fix**: Parse keys once at construction (fail fast); one parameterized issue/decode helper. (Pairs with SEC-006's `token_use` claim work.)

### CQ-B15 [MEDIUM] `CertService::generate` reconstructs the CA certificate instead of using the stored one
- **File**: `crates/axiam-pki/src/cert.rs:108-122, 185-192`
- **Type**: Bug (latent)
- **Issue**: The issuer handed to rcgen is a fresh self-signed reconstruction (default serial/validity, CN-only DN, no SKI continuity) — not the stored `public_cert_pem`. Signatures verify (same key) but Authority Key Identifier / issuer DN can diverge from the real CA cert, breaking strict chain validation in some verifiers. Also `cert.rs` duplicates `generate_keypair`/`compute_fingerprint`/`to_rcgen_time` verbatim from `ca.rs`.
- **Fix**: `CertificateParams::from_ca_cert_pem(&ca_cert.public_cert_pem)`; share the helpers.

### CQ-B16 [MEDIUM] Org/tenant delete: no cascade; all deletes report success for missing records
- **File**: `crates/axiam-db/src/repository/organization.rs:210-218`, `tenant.rs:221-229` (pattern also user.rs:411-428, session.rs)
- **Type**: Bug / Design
- **Issue**: Deleting an org leaves its tenants; deleting a tenant orphans users/sessions/roles/settings/tokens/certs. All `delete()`s return `Ok(())` whether or not anything matched, while `update()` returns `NotFound` — an inconsistent contract that hides caller bugs.
- **Fix**: Cascade in a transaction or refuse to delete non-empty parents; `RETURN BEFORE` to detect 0-row deletes → `NotFound`.

### CQ-B17 [MEDIUM] Duplicate graph edges: `RELATE` without uniqueness, comment claims dedup that doesn't exist
- **File**: `crates/axiam-db/src/repository/group.rs:385-388`; role.rs:331-343; permission.rs:323-328
- **Type**: Bug
- **Issue**: Comment says "IF NOT EXISTS avoids duplicates" but the query has no such clause and no unique index exists on edge tables. Repeated calls create duplicate `member_of`/`has_role`/`grants` edges; `get_members` counts edges for `total` while the item list dedupes — pagination totals drift.
- **Fix**: Unique indexes on `(in, out[, resource_id])` or upsert semantics; fix the comment.

### CQ-B18 [MEDIUM] OAuth2: repository errors collapsed into `invalid_client`/`invalid_grant`; client-auth block duplicated 3×
- **File**: `crates/axiam-oauth2/src/token.rs:171-175, 206-214, 339-343, 447-451` (helper exists at 723-747)
- **Type**: Error handling / Duplication
- **Issue**: Any DB error becomes 401 `invalid_client`/400 `invalid_grant` — clients are told their credentials are wrong during an outage. The 15-line lookup+`ct_eq` client-auth block is re-implemented inline in three grant handlers although `authenticate_client()` exists — drift risk on a security-critical comparison.
- **Fix**: `NotFound` → invalid_client, other errors → `server_error`; route all call sites through `authenticate_client`.

### CQ-B19 [MEDIUM] OIDC discovery advertises endpoints that don't work as advertised (`?tenant_id=` required)
- **File**: `crates/axiam-oauth2/src/oidc.rs:36-41` vs `crates/axiam-api-rest/src/handlers/oauth2.rs:43-46, 172-177`
- **Type**: API design
- **Issue**: `/oauth2/token|revoke|introspect` hard-require a non-standard `tenant_id` query param, but discovery advertises bare URLs; standards-compliant clients get a plain-text Actix 400 (not an RFC 6749 error body, since extractor failures bypass `build_oauth2_error_response`).
- **Fix**: Per-tenant issuer paths (or resolve tenant from `client_id`); RFC-shaped error when `tenant_id` is missing.

### CQ-B20 [MEDIUM] gRPC server: no graceful shutdown, no message-size/time limits, batch all-or-nothing
- **File**: `crates/axiam-api-grpc/src/server.rs:39-44`; `services/authorization.rs:91-117`
- **Type**: API design / Bug
- **Issue**: `serve` (not `serve_with_shutdown`), no `max_decoding_message_size`/`timeout`/`concurrency_limit`/TLS. `BatchCheckAccess` is unbounded, serial, and one malformed UUID fails the whole batch. (Missing auth and lockout accounting are SEC-003/SEC-026.)
- **Fix**: Graceful shutdown, limits, per-item batch error semantics, max batch size.

### CQ-B21 [MEDIUM] Inconsistent error envelopes and JSON body limits across the REST surface
- **File**: `crates/axiam-api-rest/src/server.rs:37`; `error.rs`
- **Type**: Error handling / API design
- **Issue**: Only `/auth` gets the 64 KiB JSON limit (`/api/v1/*` gets Actix's 2 MiB default — presumably unintentional). Three error shapes coexist: the `{"error","message"}` envelope, Actix plain-text extractor failures (no `JsonConfig::error_handler`/`QueryConfig`/`PathConfig` anywhere), and OAuth2's `{"error","error_description"}`.
- **Fix**: App-wide `JsonConfig`/`QueryConfig`/`PathConfig` with a standard-envelope error handler; one global body limit.

### CQ-B22 [MEDIUM] Webhook delivery is fire-and-forget, unbounded, unrecorded — and currently dead code
- **File**: `crates/axiam-api-rest/src/webhook.rs:34-129`; wired at main.rs:274 but no handler calls `.deliver()`
- **Type**: Reliability / Dead code
- **Issue**: Deliveries (with up to 10 retries and up-to-1h sleeps) live in detached `tokio::spawn` tasks — lost on restart, no persistence/history, no per-tenant concurrency bound. `UpdateWebhookRequest` cannot rotate the secret.
- **Fix**: Route deliveries through the existing RabbitMQ infra (durable queue + consumer); add secret rotation; or remove until wired.

### CQ-B23 [MEDIUM] Federation: discovery fetched twice per login, size cap applied after full buffering, IdP 4xx → HTTP 500, `attribute_map` ignored for OIDC
- **File**: `crates/axiam-federation/src/oidc.rs:131-140, 203, 267, 432-552`; `error.rs:52-56`; contrast saml.rs:425
- **Type**: Bug / Error handling
- **Issue**: (a) the 256 KiB cap is checked **after** `bytes()` buffers the whole response; (b) discovery is fetched on both `authorize` and `callback` with no cache; (c) `TokenExchangeFailed`/`DiscoveryFailed` map to `Internal` → 500 even for user-caused invalid codes; (d) `config.attribute_map` is honored for SAML but never read on the OIDC provisioning path despite the DTO documenting it.
- **Fix**: Stream-limited reads; per-config discovery cache (TTL); 4xx-class mapping for IdP-rejected exchanges; apply the map in OIDC provisioning or document SAML-only.

### CQ-B24 [MEDIUM] Test coverage holes in security-critical crates
- **Type**: Testing
- **Inventory**:
  - **axiam-pki: zero tests** — CA generation, leaf signing, AES round-trips, fingerprints, mTLS, PGP all untested. Most urgent given key material (and the rcgen-RSA backend question in CQ-B02).
  - **axiam-api-grpc, axiam-amqp, axiam-federation: zero tests** (federation notable given hand-rolled SAML XML and JWT-peek logic).
  - REST handler groups with no tests: webauthn (4 endpoints), email_verification, password_reset, notification_rules, mfa_methods.
  - axiam-db: ~half the repos untested (audit, settings, oauth2*, federation*, certificates/CA, pgp, webhook, notification_rule, email_*).
  - authz engine: missing edge cases — cycles/>50 depth, duplicate assignments, scope on ancestor, concurrent grant changes.
- **Fix**: Prioritize axiam-pki unit tests and federation tests alongside the SEC-004/005 work; add the missing handler test files following the existing (good) integration-test pattern.

### CQ-B25 [MEDIUM] DTO strategy drift; server-set fields accepted in bodies then silently overwritten
- **File**: e.g. `handlers/certificates.rs:40-41`, `pgp_keys.rs:34-35`, `ca_certificates.rs:34-35`, `groups.rs:130`, `organizations.rs:27`
- **Type**: API design
- **Issue**: Half the API binds core domain structs straight to the wire (organizations/tenants/groups/roles/permissions/resources/scopes/service-accounts/certificates), half defines request DTOs. `CreateCertificate.tenant_id`/`CreateCaCertificate.organization_id` appear in OpenAPI yet are overwritten from JWT/path — confusing for SDK generators. (Mass-assignment angle: SEC-035.)
- **Fix**: Standardize on request DTOs, or `#[serde(skip_deserializing)]` + `#[schema(ignore)]` for server-set fields.

### CQ-B26 [MEDIUM] Validation inconsistency; admin user creation bypasses the tenant password policy
- **File**: `handlers/users.rs:80-95` vs `password_reset.rs:147-166`; `notification_rules.rs:258-273`
- **Type**: Bug / API design
- **Issue**: `users::create` does no validation (no email format, no username constraints, **no password policy**) while the same tenant's reset flow enforces policy; notification rules validate emails with `contains('@')` while users don't validate at all.
- **Fix**: Enforce the effective password policy in `users::create`; one shared email/username validator.

## Low

### CQ-B27 [LOW] Composition drift in `main.rs`: federation/email/reset services rebuilt per request from cloned repos
- **File**: `handlers/federation.rs:412-417, 469-474, 631-636, 681-686, 731-736`; `email_verification.rs:62-66`; `password_reset.rs:70-75`
- **Fix**: Compose once in `main.rs` (like `AuthService`/`TokenService`); a `bootstrap`/`AppState` module would have prevented CQ-B01 too.

### CQ-B28 [LOW] Copy-pasted `client_ip`/`user_agent` helpers with drift (length caps only in one copy)
- **File**: `handlers/auth.rs:113-124` (uncapped) vs `handlers/webauthn.rs:90-105` (capped)
- **Fix**: One capped shared implementation.

### CQ-B29 [LOW] Dead code wired into the composition root
- **File**: `main.rs:211/267` (NotificationPublisher never consumed); `axiam-audit/src/service.rs` (`AuditService`), `notification.rs` (`NotificationDispatcher`) exported but unused — notification rules currently match but never send.
- **Fix**: Wire up or remove until the email phase lands.

### CQ-B30 [LOW] Pagination count+data non-transactional; `Pagination` unbounded (see SEC-010)
- **File**: pattern everywhere, e.g. `user.rs:430-476`
- **Fix**: Clamp in `Pagination`; batch count+select or document approximation; `RETURN BEFORE` + `len()` for delete counts (copy `password_history::prune`).

### CQ-B31 [LOW] Silently dropped errors: passkey decrypt failures and best-effort session invalidation unlogged
- **File**: `crates/axiam-auth/src/webauthn.rs:200-203` (`.filter_map(|c| ....ok())`); `service.rs:440-443` (`let _ =`)
- **Fix**: Log decrypt failures with credential ID (a key-rotation bug would currently look like "no credentials"); `warn!` on failed invalidation.

### CQ-B32 [LOW] `DeviceIdentity.org_id` returned as `Uuid::nil()` placeholder
- **File**: `crates/axiam-pki/src/mtls.rs:69-74`
- **Fix**: Drop the field or make it `Option<Uuid>` — half-initialized typed structs invite bugs.

### CQ-B33 [LOW] Stringly-typed `AxiamError`; misc API-shape inconsistencies
- **File**: `crates/axiam-core/src/error.rs:22-47`; revoke endpoints returning `200 {"status":"revoked"}` vs deletes 204; PUT-with-PATCH-semantics everywhere; `GET /oauth2/authorize` returns 401 JSON instead of redirecting (doc comment promises redirect); multiple adjacent `Uuid` params with per-method argument orders (`add_member(tenant, user, group)` vs `get_members(tenant, group, ...)`).
- **Fix**: Structured error variants/codes before the API ossifies; pick one state-transition response convention; consider PATCH or documented merge semantics; consider newtype IDs (`UserId`, `GroupId`) to kill swap-bug risk.

### CQ-B34 [LOW] Dependency hygiene: unused deps, non-unified workspace versions, three `rand` majors
- **File**: `crates/axiam-authz/Cargo.toml` (serde/tokio/tracing/thiserror unused), `axiam-pki` (base64/rand/tokio unused; `rand_core 0.6` vs workspace rand 0.9; `time`/`smallvec` pinned directly), `axiam-auth` (webauthn-rs-proto unused), `axiam-db` (tokio unused, `surrealdb-types` pinned directly); rand 0.8 + 0.9 + 0.10 simultaneously in tree.
- **Fix**: `cargo machete`/`cargo udeps`; move stragglers into `[workspace.dependencies]`; consolidate rand.

### CQ-B35 [LOW] `check_hibp` signature is vestigial `Result` whose future `Err` would be silently swallowed
- **File**: `crates/axiam-auth/src/policy.rs:173-220, 310-315` (`let Ok(Some(violation)) = ...`)
- **Issue**: Also note HIBP enforcement depends on callers passing `http_client: Some(_)` — policy can be skipped by call-site omission.
- **Fix**: Return `Option<PolicyViolation>` (best-effort by contract) or propagate with `?`.

### CQ-B36 [LOW] Audit middleware drops entries on channel-full/DB-failure with no metric
- **File**: `crates/axiam-audit/src/middleware.rs:52-58, 161-163`
- **Fix**: Acceptable backpressure design, but make drops a counted/alertable event (metric + rate-limited error log).

---

# Frontend findings

## High

### CQ-F01 [HIGH] Hardcoded placeholder user ID sent to the PGP key API
- **File**: `frontend/src/pages/pgp/PgpKeysPage.tsx:268`
- **Issue**: `const currentUserId = "current-user";` — every generated PGP key is attributed to that literal string instead of `useAuthStore` `user.id`.
- **Fix**: `const userId = useAuthStore((s) => s.user?.id)`; block submission if absent.

### CQ-F02 [HIGH] ConfirmDialog hardcodes the confirm button label to "Delete"
- **File**: `frontend/src/components/ConfirmDialog.tsx:103-107`
- **Issue**: No `confirmLabel` prop; "Revoke Certificate", "Rotate Client Secret", "Reset MFA", "Revoke Permission" dialogs all show a destructive **Delete** button — wrong and misleading for irreversible-but-different actions.
- **Fix**: Add `confirmLabel`/`variant` props (default "Delete").

### CQ-F03 [HIGH] Audit log "Clear" doesn't cancel pending debounce timers — cleared filters resurrect invisibly
- **File**: `frontend/src/pages/audit/AuditLogsPage.tsx:1018-1065`
- **Issue**: Timers stored in `useState` (extra re-render per keystroke), never cleared in `clearFilters` or on unmount — type "alice", click Clear within 400 ms, and the table silently filters by an invisible value.
- **Fix**: Timers in `useRef`, cleared in `clearFilters` and unmount cleanup — or reuse the existing debounced `SearchInput` component.

### CQ-F04 [HIGH] Duplicated debounced user search with a stale-response race and no unmount cleanup
- **File**: `frontend/src/pages/roles/RoleDetailPage.tsx:285-307`; `frontend/src/pages/groups/GroupDetailPage.tsx:83-104`
- **Issue**: No request sequencing/AbortController — a slow older response overwrites newer results (classic typeahead race); the timer survives dialog close and `setResults` fires after unmount. The whole dialog is a near-verbatim duplicate across the two pages.
- **Fix**: One shared `UserSearchDialog` using `useQuery({ queryKey: ["user-search", debouncedTerm] })` — react-query solves race, caching, and cleanup.

### CQ-F05 [HIGH] Logout doesn't clear the react-query cache (or call the backend)
- **File**: `frontend/src/components/layout/Topbar.tsx:86-89`; `frontend/src/lib/api.ts:111`
- **Issue**: All cached queries survive logout; logging in as a different user/tenant briefly renders the previous tenant's cached data (staleTime 60 s). Server-side revocation gap tracked as SEC-015.
- **Fix**: `queryClient.clear()` on logout and on the 401-refresh-failure path; call `POST /auth/logout`.

### CQ-F06 [HIGH] `npm run lint` fails — 9 ESLint errors, two of them real hook bugs
- **File**: `frontend/package.json:10`
- **Inventory**: `react-hooks/refs` in OrganizationDetailPage.tsx:633 (CQ-F07); `react-hooks/set-state-in-effect` in MfaManagementPage.tsx:99 and ResourceTree.tsx:302; `react-refresh/only-export-components` in button/badge/PasswordPolicyChecker; `no-empty-object-type` in input/textarea.
- **Fix**: Fix the two hook-rule errors, move non-component exports to separate files, then **wire lint into CI** so the gate stays green. (`tsc -b` is clean.)

### CQ-F07 [HIGH] Org Settings tab: dead "sync" logic + display/save drift
- **File**: `frontend/src/pages/organizations/OrganizationDetailPage.tsx:631-635`
- **Issue**: `const syncedRef = { current: false }` is a plain object recreated every render — the whole block is a no-op (and an eslint error). Inputs display defaults (`merged.password_min_length ?? 12`) but `handleSubmit` sends `merged` without those defaults — what the user sees as "12" is not what gets saved.
- **Fix**: Delete the dead block; adopt the `DEFAULT_SETTINGS`-merged-via-`useMemo` pattern already used in SettingsPage.tsx:149-151 (the two settings screens implement the same concept two different ways).

### CQ-F08 [HIGH] Tenants table fabricates "Status: Active" for every tenant
- **File**: `frontend/src/pages/tenants/TenantsPage.tsx:~370`
- **Issue**: `render: () => <StatusBadge status="active" />` — `Tenant` has no status field; the column unconditionally shows "Active". Fabricated data in an IAM admin console.
- **Fix**: Remove the column or add a real status field to the DTO.

## Medium

### CQ-F09 [MEDIUM] Mutation errors surface raw Axios messages — or nothing at all
- **File**: pervasive; e.g. `UsersPage.tsx:247-251`, `TenantsPage.tsx` deleteMutation, `CertificatesPage.tsx:710-716`
- **Issue**: (1) `err.message` is "Request failed with status code 409" — the backend's error body is discarded everywhere except Login/Profile/MfaManagement. (2) Every delete/revoke/rotate mutation lacks `onError`: on failure the ConfirmDialog spinner stops, the dialog stays open, zero feedback. `@radix-ui/react-toast` is installed but unused.
- **Fix**: One `getApiErrorMessage(err)` helper in `lib/api.ts`; global `MutationCache.onError` toast on the `QueryClient`.

### CQ-F10 [MEDIUM] Dashboard duplicates server state under parallel query keys — counts stay stale after mutations
- **File**: `frontend/src/pages/DashboardPage.tsx:568-591`
- **Issue**: `["dashboard-users"]` etc. vs canonical `["users", ...]` — CRUD invalidations never reach the dashboard; failed stat queries silently render "—".
- **Fix**: Reuse canonical key prefixes so existing invalidations cover the dashboard; add error states.

### CQ-F11 [MEDIUM] `FormDialog` sets `noValidate`, making every `required`/`type="email"`/`type="url"` attribute inert
- **File**: `frontend/src/components/FormDialog.tsx:99`; consumers UsersPage.tsx:109-117, WebhooksPage.tsx:132-140
- **Issue**: Manual handlers only check non-emptiness — email format (user create/edit), URL format (webhooks, SAML/OIDC fields) are never validated anywhere; `"not-an-email"` goes to the API. Only NotificationRulesPage has a real email regex.
- **Fix**: Drop `noValidate` or lift NotificationRulesPage's validators into a shared module. (Backend should validate too — CQ-B26.)

### CQ-F12 [MEDIUM] Resource parent picker allows cycles; parent/resource scope can never be cleared
- **File**: `frontend/src/pages/resources/ResourcesPage.tsx` (ResourceFormFields ~line 70; handleEditSubmit); `ResourceTree.tsx:20-41`; same pattern in PermissionsPage
- **Issue**: (1) Edit excludes only the resource itself from the parent dropdown, not its descendants — cycles possible, and `buildTree` then drops the whole subtree from the view (no node appears as root). (2) "Move to root" sends `parent_id: undefined` (= unchanged in a Partial PUT), so de-parenting is impossible; same for making a resource-scoped permission global. Pairs with backend CQ-B04/CQ-B08.
- **Fix**: Exclude descendants from the dropdown; send explicit `parent_id: null` once the backend accepts it.

### CQ-F13 [MEDIUM] Federation edit dialog reuses stale form state across providers and silently ignores type switches
- **File**: `frontend/src/pages/federation/FederationPage.tsx:320-338, 503-543`
- **Issue**: `load()` overwrites only fields present on the loaded provider — editing a SAML provider then an OIDC one leaves SAML fields populated; the type `<select>` is editable in edit mode but `UpdateProviderRequest` has no `type` field, producing half-applied edits.
- **Fix**: `editForm.reset()` before `load()`; type selector read-only in edit mode.

### CQ-F14 [MEDIUM] Users pagination: skeleton flash on every page change; stranded empty page after deleting the last row
- **File**: `frontend/src/pages/users/UsersPage.tsx:216-224, 469-491`
- **Issue**: No `placeholderData` (AuditLogsPage has it — inconsistent); `page` isn't clamped when `total` shrinks, leaving "No users found" with Next disabled.
- **Fix**: `placeholderData: keepPreviousData`; clamp page in delete `onSuccess`.

### CQ-F15 [MEDIUM] ~14 near-identical CRUD pages; small components copy-pasted up to 6×
- **File**: `frontend/src/pages/{users,roles,groups,permissions,resources,webhooks,oauth2,federation,service-accounts,notifications,pgp,certificates,tenants,organizations}/*.tsx`
- **Issue**: Identical create/edit/delete state-cluster + mutation + reset template repeated per page (~3,000+ lines). `ToggleField` defined **6 times**, `SectionCard`/`InfoRow` 3×, `ActionBadge` 2×, `slugify` 2×. The copies have already drifted (placeholderData, error extraction, debouncing each have 2-3 competing implementations) — CQ-F09's fix must currently be applied 14 times.
- **Fix**: Extract `useCrudMutations(entityKey, service)`, shared `ToggleField`, move `SectionCard`/`InfoRow`/`ActionBadge` into `components/`.

### CQ-F16 [MEDIUM] Whole-store zustand subscriptions in layout components re-render the entire tree on token refresh
- **File**: `AppLayout.tsx:9`, `Topbar.tsx:20`, `DashboardPage.tsx:566`
- **Issue**: `const { isAuthenticated } = useAuthStore()` subscribes to the whole store — every silent `updateAccessToken` re-renders AppLayout → entire page tree.
- **Fix**: Selector form: `useAuthStore((s) => s.isAuthenticated)`.

### CQ-F17 [MEDIUM] Profile/MFA/auth pages bypass the services layer; `MfaMethod` defined 3 times with diverging types
- **File**: `ProfilePage.tsx:489-506`, `MfaManagementPage.tsx:17-50`, vs `services/users.ts:17`
- **Issue**: Inline `api.get(...)` calls and three competing declarations of the same DTO (`method_type: "totp" | "webauthn"` vs `string`).
- **Fix**: `services/profile.ts` (or extend the users service with `me` endpoints); import the single `MfaMethod`.

### CQ-F18 [MEDIUM] Role/group assignments are write-only in the UI; unassign service methods are dead code
- **File**: `UserDetailPage.tsx` ("Role Assignments" renders static help text), `RoleDetailPage.tsx:851-871` (`onAssigned={() => {}}`), `services/roles.ts:66-81` (unassign methods never imported)
- **Issue**: Admins can assign roles but can never see or remove existing assignments anywhere in the app.
- **Fix**: Fetch and render assignments (needs a list endpoint) or remove the misleading sections; wire up or delete the unassign methods.

### CQ-F19 [MEDIUM] VerifyEmailPage fires a state-changing GET twice under StrictMode
- **File**: `frontend/src/pages/auth/VerifyEmailPage.tsx:41-67`
- **Issue**: The `cancelled` flag stops stale state updates but not the duplicate request; with a single-use token the second call fails and the winner is timing-dependent — flaky "Verification failed" screens. Verification via GET is semantically a mutation. (The deeper proxy bug is SEC-030.)
- **Fix**: `useRef` fired-guard or a mutation keyed by token; prefer POST.

## Low

### CQ-F20 [LOW] TenantsPage shows "No tenants found" while organizations are still loading; N+1 tenant fan-out
- **File**: `frontend/src/pages/tenants/TenantsPage.tsx:~190-210`
- **Fix**: Treat `orgsLoading || tenantsPending` as loading; gate on `orgsQuery.isSuccess`.

### CQ-F21 [LOW] Dead code: `Placeholder.tsx` (124 lines, nothing imports it); stray icon re-exports at the bottom of RoleDetailPage
- **Fix**: Delete both.

### CQ-F22 [LOW] Five unused @radix-ui dependencies while their functionality is hand-rolled
- **File**: `frontend/package.json:11-18`
- **Issue**: Only `react-slot` and `react-label` are imported; `react-dialog`, `react-dropdown-menu`, `react-select`, `react-separator`, `react-toast` sit unused while FormDialog/ConfirmDialog/Topbar reimplement focus traps (duplicated in 2 files) and menus by hand.
- **Fix**: Adopt the Radix primitives (removes ~250 lines of a11y plumbing) or drop the deps.

### CQ-F23 [LOW] Client-side password policy hardcoded — can diverge from server policy; absent on admin user creation
- **File**: `frontend/src/components/PasswordPolicyChecker.tsx:45-53`; UsersPage "New User" applies no policy check
- **Fix**: Fetch the effective policy from the settings endpoint and pass it through; reuse the checker on user creation.

### CQ-F24 [LOW] DataTable fallback row key relies on an unchecked double cast
- **File**: `frontend/src/components/DataTable.tsx:79`
- **Fix**: Constrain `T extends { id?: string }` or require `getRowKey`.

### CQ-F25 [LOW] No i18n; dates hardcoded to `en-US`
- **File**: entire frontend; `lib/utils.ts:40, 48`
- **Fix**: Use `navigator.language` for `Intl.DateTimeFormat` now; decide on an i18n framework before more pages land (GDPR/EU target market).

### CQ-F26 [LOW] DOM selector built by interpolating API-supplied IDs
- **File**: `frontend/src/components/ResourceTree.tsx:81`
- **Issue**: An ID containing `"` or `]` throws or matches the wrong node (keyboard-nav breakage; not XSS).
- **Fix**: `CSS.escape(id)`.

---

## Architecture observations

**Backend.** Layering is clean and consistent: RPITIT repository traits in axiam-core with no DB dependency; services generic over traits; SurrealDB impls isolated in axiam-db; thin handlers; a complete OpenAPI registration that actually matches the route table (verified by diffing). The three systemic weaknesses: (1) the repository layer's mechanical duplication with measurable drift (tenant guarding, `.check()` usage, NotFound-on-delete, edge dedup each done differently per file); (2) no transactions around multi-statement graph mutations; (3) composition drift in `main.rs` — some services built once, some rebuilt per request, one built with wrong arguments (CQ-B01). A single `bootstrap`/`AppState` module would eliminate that class. The AMQP layer has good publisher-confirm hygiene but no consumer reliability story (DLQ/requeue policy); reconnect is "exit(1) and let the orchestrator restart" — workable but should be documented.

**Frontend.** Clear 3-layer shape (typed services → react-query for server state → pages over shared primitives), correct zustand/react-query separation, good query-key/invalidation discipline (dashboard excepted), and unusually good hand-rolled accessibility. The dominant debt is the unfactored CRUD-page template (~80 % identical, already diverging) and systematically missing mutation-error surfacing. Profile/auth pages bypassing the services layer and a few display-only sections presenting incomplete or fabricated data round out the list.

## Test coverage summary

| Area | State |
|---|---|
| axiam-api-rest | **Good**: 20 integration files, ~230 tests, real in-memory SurrealDB, negative cases (oauth2_flow_test.rs alone: 37 tests). Gaps: webauthn, email_verification, password_reset, notification_rules, mfa_methods handlers. |
| axiam-auth | Best-covered crate (1,253-line service test + solid unit tests). `webauthn.rs` itself untested. |
| axiam-authz | One good 793-line engine test. Missing: cycles/depth-limit, duplicate assignments, ancestor scopes, concurrency. |
| axiam-db | ~Half the repos tested (good tenant-isolation assertions where present). Untested: audit, settings, oauth2*, federation*, certs/CA, pgp, webhook, notification, email tokens. |
| axiam-email | Good template/factory/mock tests; HTTP providers + SMTP untested. |
| axiam-pki | **Zero tests.** |
| axiam-api-grpc / axiam-amqp / axiam-federation / axiam-audit | **Zero tests** (audit covered indirectly via REST middleware test). |
| Frontend | 11 Playwright specs (~2,166 lines) with fully mocked APIs — effectively UI component tests; decent happy-path CRUD coverage. **No unit tests at all** (no vitest/jest/RTL). Untested pure logic: `buildTree`, `checkPasswordPolicy`, `formatRelativeTime`, parsers, and especially the concurrency-sensitive axios refresh-queue interceptor. `tsc` clean; `eslint` failing (CQ-F06). |

## Static analysis results

- `cargo clippy --workspace --all-targets`: **clean, zero warnings** (with `clippy.toml` present — good baseline discipline).
- `cargo audit`: 7 advisories — tracked as **SEC-013** in the security review.
- `tsc -b`: clean. `eslint .`: 9 errors (CQ-F06). `npm audit`: 7 vulnerabilities — tracked as **SEC-029**.
- Note: the build requires `protoc` (axiam-api-grpc build script); document it as a prerequisite or vendor via `protoc-bin-vendored`.
