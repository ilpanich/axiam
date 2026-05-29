---
phase: 04-federation-verification-session-security
plan: "02"
subsystem: federation
tags: [oidc, jwks, jwt, aes-gcm, encryption, migration]
dependency_graph:
  requires:
    - axiam_auth::crypto (encrypt_separate/decrypt_separate from plan 04-01)
    - FederationConfig.allowed_algorithms (schema from plan 04-01)
    - FederationConfig.client_secret_nonce/ciphertext/key_version (schema 04-01)
    - AuthConfig.federation_encryption_key (config from plan 04-01)
  provides:
    - axiam_federation::jwks_cache::JwksCache (D-01/D-02/D-03)
    - axiam_federation::oidc::OidcFederationService with full OIDC verification
    - axiam_federation::secrets::{encrypt_client_secret,decrypt_client_secret,migrate_plaintext_federation_secrets}
    - FederationConfigRepository::{list_with_legacy_plaintext_secret,set_encrypted_secret}
    - Boot backfill in main.rs (D-12)
  affects:
    - axiam-api-rest handlers (oidc_authorize, oidc_callback) — now require JwksCache app_data
    - axiam-server main.rs — boot sequence expanded
tech_stack:
  added: []
  patterns:
    - "JwksCache = Arc<RwLock<HashMap<(tenant_id, config_id), JwksCacheEntry>>> — custom TTL logic"
    - "jsonwebtoken::Validation with set_issuer/set_audience/leeway=60 for D-05 claim validation"
    - "split-column AES-256-GCM: client_secret_nonce + client_secret_ciphertext separate columns (D-11)"
    - "idempotent boot backfill: predicate client_secret_ciphertext IS NONE AND client_secret != ''"
key_files:
  created:
    - crates/axiam-federation/src/jwks_cache.rs
    - crates/axiam-federation/src/secrets.rs
    - crates/axiam-server/tests/federation_secret_backfill.rs
  modified:
    - crates/axiam-federation/src/oidc.rs
    - crates/axiam-federation/src/error.rs
    - crates/axiam-federation/src/lib.rs
    - crates/axiam-federation/Cargo.toml
    - crates/axiam-core/src/repository.rs
    - crates/axiam-db/src/repository/federation_config.rs
    - crates/axiam-api-rest/src/handlers/federation.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-server/Cargo.toml
decisions:
  - "JwksCache uses direct chrono Duration comparison instead of to_std() to avoid false misses on sub-millisecond clock jitter"
  - "client_secret cleared to '' (empty string) not NONE after backfill — TYPE string schema constraint prevents NONE"
  - "OidcFederationService::new gains Arc<JwksCache> parameter — breaking change covered by handler update"
  - "populate_cache test helper takes Arc<JwksCache> by value (not &JwksCache) to avoid deref coercion ambiguity"
metrics:
  duration: "~90m"
  completed: "2026-05-29"
  tasks: 3
  files_modified: 12
---

# Phase 04 Plan 02: OIDC Signature Verification + Federation Secret Encryption Summary

Replaced the `TODO(T19.6)` unverified ID-token decode with full JWKS-backed cryptographic
verification, and added AES-256-GCM encryption at rest for federation client secrets with
an idempotent boot backfill.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | JwksCache D-01/D-02/D-03 + FederationError variants | dde8ee0 | jwks_cache.rs, error.rs, Cargo.toml |
| 2 | OIDC ID-token signature + claim verification; TODO(T19.6) replaced | 8f92876 | oidc.rs, handlers/federation.rs |
| 3 | Federation secret encryption + repo methods + boot backfill | ce5a1bb | secrets.rs, repository.rs, main.rs, backfill test |

## What Was Built

### Task 1 — JwksCache with D-01/D-02/D-03 semantics

Created `crates/axiam-federation/src/jwks_cache.rs`:

- `JwksCache(pub(crate) Arc<RwLock<JwksCacheMap>>)` keyed by `(tenant_id, config_id)`.
- `TTL = 1h`, `STALE_WINDOW = 24h`, `FORCED_REFETCH_COOLDOWN = 60s`.
- `get_or_fetch`: fast path on TTL hit; slow path fetches; stale-while-revalidate on error.
- `force_refetch_if_allowed`: unknown-kid path; rate-limited at 60s to prevent JWKS amplification.
- Clock jitter fix: uses `entry.fetched_at + ttl_chrono > now` instead of `to_std()` (which errors
  on negative durations from sub-millisecond jitter).

Extended `FederationError` with 7 new variants: `JwksFetchFailed`, `JwksKidUnknown`,
`JwtSignatureInvalid`, `JwtClaimRejected`, `AlgorithmNotAllowed`, `CryptoError`, `ConfigIncomplete`.

### Task 2 — OIDC ID-token signature verification (TODO(T19.6) replaced)

`OidcFederationService` gains `cache: Arc<JwksCache>` field.

`verify_id_token` implements the full flow:
1. Raw JOSE header alg=none pre-check (case-insensitive, belt-and-suspenders per D-04).
2. `decode_header` for `alg` + `kid`.
3. Algorithm allow-list check against `config.allowed_algorithms`; "none" silently dropped.
4. JWKS lookup via cache; forced refetch on unknown kid.
5. `DecodingKey::from_jwk` + `Validation` with `set_issuer`, `set_audience`, `leeway=60`, required claims.
6. `jsonwebtoken::decode::<IdTokenClaims>` — maps `InvalidSignature` → `JwtSignatureInvalid`, rest → `JwtClaimRejected`.

The `nonce` comparison against `expected_nonce` is kept at the caller level; a
`// TODO(plan 04-05)` comment marks the planned migration to `federation_login_state` state lookup.

7 unit tests cover every rejection path:
- `verify_rejects_alg_none_in_raw_header` (case-insensitive: "none", "None", "NONE")
- `verify_rejects_disallowed_alg`
- `verify_rejects_wrong_iss`
- `verify_rejects_wrong_aud`
- `verify_rejects_expired` (beyond 60s leeway)
- `verify_accepts_within_60s_skew` (30s past exp)
- `verify_rejects_unknown_kid_after_forced_refetch`

### Task 3 — Federation client-secret encryption at rest

`secrets.rs`:
- `encrypt_client_secret(key, plaintext)` → `(nonce_b64, ciphertext_b64)` via `encrypt_separate`.
- `decrypt_client_secret(key, nonce_b64, ct_b64)` → UTF-8 plaintext via `decrypt_separate`.
- `decrypt_client_secret_or_legacy(key, nonce, ct, legacy)`: prefers encrypted columns; falls back
  to legacy plaintext during the boot backfill window (RESEARCH §8 risk #5).
- `migrate_plaintext_federation_secrets(fed_repo, audit_repo, key)`: idempotent boot backfill;
  per-row error → log + continue; emits `federation_secret_migrated` audit entry per row.
- `current_key_version() -> i64 { 1 }` — enables future key rotation.

New trait methods on `FederationConfigRepository`:
- `list_with_legacy_plaintext_secret()` — SurrealQL: `WHERE client_secret_ciphertext IS NONE AND client_secret IS NOT NONE AND client_secret != ""`
- `set_encrypted_secret(tenant_id, config_id, nonce, ct, key_version)` — sets split-column values, clears `client_secret = ''`.

`main.rs` boot sequence: after `run_migrations`, before HTTP `bind`, calls the backfill if `federation_encryption_key` is set; warns if absent.

Integration test `federation_secret_backfill.rs`: spins up in-memory SurrealDB, inserts a legacy row, runs migration, asserts nonce + ciphertext populated + distinct, `client_secret = ""`, decrypt round-trip = "supersecret", second run returns 0.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Clock jitter causes cache miss on freshly-inserted entries**
- **Found during:** Task 1 unit test debugging (`stale_while_revalidate_on_fetch_err` passing but `cache_hit_within_ttl` failing)
- **Issue:** `chrono::Duration::to_std()` returns `Err` for negative durations. When `populate_cache` sets `fetched_at = Utc::now()` and `get_or_fetch` also calls `Utc::now()` nanoseconds later, the signed duration is negative, `to_std()` returns `Err`, `unwrap_or(Duration::MAX)` gives MAX which is not <= TTL — cache miss.
- **Fix:** Changed TTL/stale/cooldown checks to compare `entry.fetched_at + ttl_chrono > now` (forward comparison) instead of computing age with `to_std()`.
- **Files modified:** `crates/axiam-federation/src/jwks_cache.rs`
- **Commit:** dde8ee0 (already included in the task commit)

**2. [Rule 1 - Bug] client_secret cannot be set to NONE — TYPE string constraint**
- **Found during:** Task 3 integration test (migrated = 0, assertion failed)
- **Issue:** `client_secret` field has `TYPE string` in the SurrealDB schema. Setting `client_secret = NONE` in the UPDATE is rejected. The backfill found 0 rows to migrate because the initial `list_with_legacy_plaintext_secret` query returned the row but the UPDATE silently failed.
- **Fix:** Set `client_secret = ''` (empty string) instead of NONE. The predicate `client_secret != ""` in `list_with_legacy_plaintext_secret` correctly excludes cleared rows.
- **Files modified:** `crates/axiam-db/src/repository/federation_config.rs`, `crates/axiam-server/tests/federation_secret_backfill.rs`
- **Commit:** ce5a1bb

**3. [Rule 1 - Bug] test helper `populate_cache(&cache, ...)` causes deref coercion ambiguity**
- **Found during:** Task 2 unit test — tests panicking with `block_on` nested runtime error
- **Issue:** Using `&Arc<JwksCache>` as a `&JwksCache` via deref coercion; combined with `block_on()` inside an async context (nested runtime panic).
- **Fix:** Changed `populate_cache` to take `Arc<JwksCache>` by value; caller passes `Arc::clone(&cache)`. Changed from sync function using `block_on` to `async fn` with `.await`.
- **Files modified:** `crates/axiam-federation/src/oidc.rs`
- **Commit:** 8f92876

**4. [Rule 3 - Blocking] Worktree initialized at old base before wave 1 changes**
- **Found during:** Task 1 compilation — `FederationConfig` missing `allowed_algorithms` field
- **Issue:** The worktree was initialized from an older commit that predated wave 1 (plan 04-01). The `FederationConfig` in the worktree had no Phase 4 fields.
- **Fix:** `git reset --hard 46d6b8a80760bb5a4932831fe3f5b7206fa20169` to advance the worktree to the correct post-wave-1 base.
- **Commit:** N/A (worktree state fix)

## Threat Surface Scan

No new network endpoints added. The JWT signature verification path now accepts tokens from external IdPs at the OIDC callback endpoint (`POST /api/v1/federation/oidc/callback`) — this endpoint already existed and was already unauthenticated in the public allowlist. The threat register items T-04-07..T-04-13 are addressed:

| Threat | Mitigation |
|--------|-----------|
| T-04-07 | JWKS fetched from configured `jwks_uri` only; `DecodingKey::from_jwk` enforces signature check |
| T-04-08 | Raw alg=none pre-check + `Validation::algorithms = allowed_algorithms`; "none" cannot be in allow-list |
| T-04-09 | 1h TTL bounds staleness; forced refetch rate-limited to prevent key-spray amplification |
| T-04-11 | 60s rate limit on forced refetches (`forced_refetch_rate_limited` test) |
| T-04-12 | Per-row error → log+continue; decrypt-or-legacy fallback covers in-flight reads |
| T-04-13 | `Validation::set_audience(&[client_id])` — token must be issued to THIS relying party |

## Self-Check: PASSED

Files created/modified verified present:
- `crates/axiam-federation/src/jwks_cache.rs` — JwksCache with TTL/stale/cooldown constants present
- `crates/axiam-federation/src/secrets.rs` — encrypt_client_secret, decrypt_client_secret present
- `crates/axiam-federation/src/oidc.rs` — TODO(T19.6) absent, decode_header + DecodingKey::from_jwk + set_audience present
- `crates/axiam-core/src/repository.rs` — list_with_legacy_plaintext_secret + set_encrypted_secret present
- `crates/axiam-db/src/repository/federation_config.rs` — client_secret_ciphertext IS NONE query present
- `crates/axiam-server/src/main.rs` — migrate_plaintext_federation_secrets call present
- `crates/axiam-server/tests/federation_secret_backfill.rs` — integration test present

Commits verified:
- dde8ee0 (Task 1)
- 8f92876 (Task 2)
- ce5a1bb (Task 3)

Test results:
- `cargo test -p axiam-federation --lib`: 10 passed (3 jwks_cache + 7 oidc)
- `cargo test -p axiam-server --test federation_secret_backfill`: 1 passed
- `cargo clippy -p axiam-federation -p axiam-core -p axiam-db -p axiam-api-rest -p axiam-server -- -D warnings`: clean

All acceptance criteria met per plan spec.
