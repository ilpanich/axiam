# Phase 24: Security Hardening I — Authentication & Access-Control Surfaces - Research

**Researched:** 2026-07-03
**Domain:** Rust/Actix-Web/Tonic/SurrealDB auth-and-authz hardening (TOTP replay CAS, rate-limit keying + shared store, bootstrap atomicity, path-allowlist normalization, constant-time reset)
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Rate-limit topology & keying (SECHRD-03)**
- **D-01a — Shared store, not documented-multiplier.** Implement a **SurrealDB-backed shared rate-limit store** (reuse the existing SurrealDB — no new infra dependency like Redis) so buckets are shared across replicas under HPA. This closes the multi-replica gap rather than only documenting the per-replica multiplier.
- **D-01b — Fail open with per-replica in-memory fallback.** When the shared store is unreachable (DB blip), the limiter falls back to the existing per-replica in-memory governor and logs/alarms. A counter-store outage must never hard-block all auth traffic. (Availability-first posture standard for rate limiters; brute-force protection degrades gracefully to per-pod, never off.)
- **D-01c — Coverage: REST + gRPC both this phase.** Move both the REST governor endpoints (login, `/auth/mfa/*`, `/oauth2/introspect|revoke`, etc.) **and** the gRPC limiter onto the shared store now.
  - Coordination note for planner/executor: CORR-01 (Phase 26) reworks the gRPC governor's *throughput/quota semantics* (`rate_limit.rs:40-47`, `per_millisecond(1000/authz_per_sec)`). This phase's shared-store swap on the gRPC limiter MUST NOT re-introduce the inverted `per_second` bug and MUST leave the quota math in a state CORR-01 can build on (or align with it). Treat the gRPC change as store/key-extractor only; do not "fix" throughput here. **Research finding: the current code no longer matches this `per_millisecond` description — see Summary.**
- **D-01d — Keying bug (the core AC):** when `trusted_hops >= hops.len()`, ignore XFF entirely and use `peer_addr()` (do NOT return `hops[0]`). Correct the `trusted_hops` docs for nginx `proxy_add_x_forwarded_for` (rightmost entry = real client). Negative test: rotating `X-Forwarded-For` per request no longer yields a fresh bucket.

**GDPR audit-write durability (SECHRD-12 / T19.27)**
- **D-02 — Both file + syslog.** When the erasure audit DB-write fails, dead-letter to **both** an append-only local file (on a mounted volume, matching AXIAM's append-only audit posture) **and** structured audit syslog. Most robust — the record survives a DB failure even if one sink is absent; a SIEM can ingest either.

**Bootstrap gate (SECHRD-04)**
- **D-03a — Gate: env var OR one-time setup token.** Accept **either** `AXIAM_BOOTSTRAP_ADMIN_EMAIL` **or** a one-time setup token as the mandatory first-run gate. Both unset ⇒ **refuse bootstrap** (fail closed). An unset gate never allows arbitrary bootstrap.
- **D-03b — Setup token: server-generated, logged once at first boot.** The server mints the setup token on first run and logs it exactly once for the operator to copy; it is consumed once (persist a consumed-once record so it cannot be replayed). No pre-provisioning required.
- **D-03c — Atomicity (the core AC):** first-super-admin creation is a single conditional/transactional operation keyed on a uniqueness invariant — two concurrent first-run requests ⇒ at most one super-admin. Concurrency test proves the single-admin invariant.

**Constant-time reset (SECHRD-12 / T19.23)**
- **D-04 — Mirror the real Argon2 cost.** On the ineligible/unknown/federated reset branch, perform a **dummy Argon2 hash (same params) + the same async wait** as the valid branch, so timing self-calibrates and stays indistinguishable. Consistent with the existing dummy-Argon2-on-user-not-found login pattern already in the codebase. Do NOT pad to a hand-tuned fixed duration (drifts if Argon2 params change).

### Claude's Discretion
These are prescriptive enough in the acceptance criteria that the researcher/planner should nail them directly — no user decision needed:

- **SECHRD-01 mechanics:** turn `update_totp_step` (`repository/user.rs:483-497`) into a **conditional CAS** — `UPDATE … SET totp_last_used_step = $step WHERE tenant_id = $tenant_id AND (totp_last_used_step = NONE OR totp_last_used_step < $step)` — and have the handler treat a **no-op update (no row affected)** as replay-rejected. Record the **actual matched step** (incl. the −1 skew step, not always `current_step`) in `verify_code_with_replay_check` so a skew-accepted code can't be replayed in a later wall-clock step. Seed `totp_last_used_step` at enrollment-confirm time. Concurrency test: N parallel submissions of one valid code ⇒ exactly one success.
- **SECHRD-11 mechanics:** in `is_public_path` (`middleware/authz.rs:38-45`), require a **path-segment boundary** on `*` prefix entries (so `/api/v1/auth/*` does not match `/api/v1/authz/...`), and **normalize the path** (collapse `//`, resolve/**reject** `..` traversal) before the allowlist check. Negative test: a non-canonical route cannot slip past the allowlist.
- **SECHRD-12 residual mechanics:** wrap the peppered-password buffer with `zeroize` and the pepper with `secrecy`, wiped before return (T19.24); block reuse of the **current** password on the unauthenticated reset path and seed the initial password into history (SEC-028 residual).
- **Test placement:** Rust negative/concurrency tests in the owning crate's `tests/` (`axiam-auth`, `axiam-db`, `axiam-api-rest`, `axiam-api-grpc`); per-crate `cargo check/test -p <crate>` only.
- **Per-PLAN `<threat_model>`:** the security capability is active — each PLAN.md carries an ASVS-aligned threat-model block for the control it touches.

### Deferred Ideas (OUT OF SCOPE)
- **gRPC governor throughput-semantics fix** — CORR-01, Phase 26 (this phase only swaps the gRPC limiter store; it does not touch the inverted-quota bug).
- **SSRF address-pinning, mTLS CA validity, GDPR erasure durability/ledger, federation nonce, AMQP signing, egress/k8s secrets** — SECHRD-02/05/06/07/08/09/10, Phase 25 (parallel-capable with this phase after Phase 23).
- **Playwright-in-CI with request-body assertions** — CORR-04, Phase 26 (what actually gates the reset/enumeration behavior in CI).
- A **hand-tuned fixed-duration** constant-time reset — rejected in favor of mirroring real Argon2 cost (D-04); revisit only if the dummy-hash approach proves insufficient under profiling.

None of these expand Phase 24 scope — they are the correct home for adjacent work.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-------------------|
| SECHRD-01 | TOTP step check-and-update must be atomic; close skew-boundary and enrollment-confirm replay windows | Pattern 1 (CAS via `SELECT * FROM (UPDATE ... WHERE guard)`, proven live at `oauth2_auth_code.rs::consume`); exact SurrealQL + trait-signature-change guidance in Code Examples; test plan in Validation Architecture; Assumption A1 flags the one open API question (explicit-step totp-rs verification) |
| SECHRD-03 | Fix XFF leftmost-hop fallback; reconcile `trusted_hops` nginx guidance; implement multi-replica shared rate-limit store | Summary's `StateStore`-is-synchronous correction (Pitfall 1) reframes the implementation shape; Pattern (System Architecture Diagram) gives the async-precheck-plus-fallback design; Code Examples gives the SurrealQL windowed-counter CAS; Pitfall 2 flags the gRPC `SmartIpKeyExtractor` parity question as Open Question 1 |
| SECHRD-04 | Close bootstrap initialized-check TOCTOU; require the bootstrap gate unconditionally | Pattern 2 (uniqueness-invariant CREATE, proven live at `saml_replay.rs::insert_assertion`) + Pattern 3 (setup-token single-use consumption) directly replace the current SELECT-then-branch TOCTOU at `bootstrap.rs:97-140`; exact transaction-extension code in Pattern 2 |
| SECHRD-11 | Require path-segment boundary in public-path wildcard matching; normalize path before the exclusion check | Pitfall 6 clarifies today's `PUBLIC_PATHS` has only one wildcard entry (test-design implication); Don't Hand-Roll row recommends segment-split over regex; existing `is_public_path` `mod tests` style identified as the test-extension point |
| SECHRD-12 | Constant-time password-reset; zeroize peppered buffer + secrecy pepper; GDPR audit-write DLQ; block current-password reuse + seed initial passwords into history | Pattern 4 (dummy-Argon2, proven live at `AuthService::login` SEC-026) + Pitfall 3 (wiring gap: `PasswordResetService` needs `crypto_semaphore`/pepper plumbing); Code Examples gives the `Zeroizing<String>`/`SecretString` rewrite; Pitfall 4 (current-password-reuse ordering bug) and Pitfall 5 (two separate user-creation write paths for history-seeding) are both novel findings not named verbatim in the ACs; Assumption A4 flags the D-02 "structured audit syslog" interpretation as needing confirmation |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

- **Passwords:** Argon2id, OWASP-recommended parameters — this phase's dummy-hash reuse (Pattern 4) and zeroize wrapping (Code Examples) must keep the existing `argon2::Params::new(19456, 2, 1, None)` unchanged, never introduce a second parameter set.
- **RBAC engine is additive-only (allow-wins, default-deny)** — SECHRD-11's path-normalization/segment-boundary fix must preserve default-deny: a normalization failure or ambiguous path MUST fall through to the existing 401/403 credential check, never to an implicit "allow" (see Pattern/Anti-Patterns: "fail-closed").
- **Fail-closed default, with one documented exception** — D-01b's shared-rate-limit-store fail-**open** fallback is the ONE deliberate exception CLAUDE.md-style fail-closed posture allows in this phase (explicitly called out in CONTEXT.md); every other fix in this phase (TOTP CAS, bootstrap atomicity, path allowlist, constant-time reset) must fail closed.
- **Audit logs: append-only (no UPDATE/DELETE)** — D-02's GDPR audit DLQ file sink must itself be append-only (open in append mode, never truncate/rewrite), consistent with the existing `audit_log` table's UPDATE/DELETE-forbidden posture.
- **No `unwrap()`/`expect()` on security paths; secrets never serialized/logged/defaulted** — applies directly to the new `bootstrap_lock`/`rate_limit_bucket`/`bootstrap_setup_token` SurrealQL error handling (must `?`-propagate or explicitly match, not `.unwrap()`) and to `secrecy::SecretString` usage (its `Debug` impl already redacts by default — do not bypass with `.expose_secret()` in any `tracing`/log call).
- **Per-crate build discipline:** `just build`/`just test`/`cargo check -p <crate>` — never a full-workspace build during iterative development; `just check` (fmt + clippy -D warnings + test) before commit. This phase's cross-crate changes (e.g., Pitfall 3's `axiam-auth`+`axiam-api-rest`+`axiam-server` `crypto_semaphore` plumbing) should still be committed as atomic, compilable-at-each-commit units per CLAUDE.md's "Each roadmap task requires a signed commit before proceeding to the next."
- **TLS 1.3 minimum for all external communication** — not implicated by any of this phase's 5 fixes (no new external communication introduced; the shared rate-limit store and audit DLQ are both intra-cluster/local-disk).

## Summary

All five code surfaces named in CONTEXT.md were read at their current file:line and largely match the citations (drift noted per-surface below). The codebase already contains **three separate proven patterns** this phase should reuse verbatim rather than invent:

1. **CAS via `SELECT * FROM (UPDATE table SET ... WHERE guard-conditions)`** — already implemented in `oauth2_auth_code.rs::consume()` for exactly the same problem class (atomic "claim once" semantics). This is the direct template for SECHRD-01's `update_totp_step` CAS and can also back the SECHRD-04 setup-token single-use consumption.
2. **Uniqueness-invariant CREATE → UNIQUE-index violation → typed error** — already implemented in `saml_replay.rs::insert_assertion()` (string-matches `"already contains"`/`"already exists"`/`"unique"` in the SurrealDB error and maps to a domain error). This is the direct template for SECHRD-04's "at most one super-admin" atomicity: create a deterministic-ID singleton lock record (`CREATE type::record('bootstrap_lock', $tenant_id)`) inside the same transaction that creates the admin user; the loser of the race gets a UNIQUE violation, not a partial admin.
3. **Dummy-Argon2 timing equalization** — already implemented in `AuthService::login()` (SEC-026) using a `DUMMY_HASH` constant + `crypto_semaphore`-gated `spawn_blocking`. SECHRD-12's constant-time reset is a structural copy of this pattern into `PasswordResetService`, which currently has neither a semaphore field nor access to the constant.

The **one place CONTEXT.md's mental model needs correcting** is the shared rate-limit store (D-01a/b): `governor::StateStore::measure_and_replace` is a **synchronous, non-blocking** trait (verified by reading `governor-0.10.4/src/state.rs`). It cannot issue an async SurrealDB round-trip from inside it. "Swap the store" is therefore not a literal `impl StateStore for SurrealStore` — it must be a new async pre-check layer (Actix middleware for REST, a `tower::Layer`/service wrapper for gRPC) that runs an async SurrealDB CAS-increment *before* delegating to the existing (untouched) in-memory `Governor`/`GovernorLayer`, falling back to that in-memory governor on any DB error. This reframing does not change the ACs or D-01a/b's intent — it changes the *implementation shape* the planner must specify tasks against.

A second correction: the CORR-01 gRPC throughput bug CONTEXT.md warns not to re-break (`per_millisecond(1000/authz_per_sec)` at `rate_limit.rs:40-47`) **appears to already be fixed** in the current codebase (last touched 2026-06-20, well before this milestone) — the code now reads `.per_second(authz_per_sec as u64).burst_size(authz_per_sec * 2)` with a comment `// CQ-B44: was .per_second(1)... Fixed`. REQUIREMENTS.md's CORR-01 description is stale. This phase must still leave that exact call untouched when swapping the store/key-extractor (the coordination note's *intent* — "don't touch quota math" — still applies), but the planner should not architect around a `per_millisecond` bug that isn't in the file.

**Primary recommendation:** For each of the 5 requirements, extend an existing, already-tested pattern in the same file/module rather than introducing a new abstraction. Only genuinely new surface is: (a) a `rate_limit_bucket` SurrealDB table + a small async pre-check middleware/layer (REST + gRPC) with fail-open fallback, and (b) two new direct dependencies, `zeroize` and `secrecy` (both `[VERIFIED: crates.io]`, both already transitively present via other deps — only `zeroize` is; `secrecy` is a wholly new addition to the dependency graph).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| TOTP step CAS (SECHRD-01) | Database / Storage (SurrealDB CAS query) | API / Backend (`AuthService` treats no-row-affected as reject) | Atomicity must be enforced at the storage layer; a CAS in application code re-introduces the TOCTOU |
| Rate-limit keying (SECHRD-03) | API / Backend (Actix `KeyExtractor` / tonic key extractor) | Database / Storage (shared bucket counter) | Key derivation is a request-parsing concern; the bucket counter needs a cross-replica store |
| Bootstrap atomicity (SECHRD-04) | Database / Storage (uniqueness-invariant CREATE) | API / Backend (gate check, setup-token minting) | The "at most one super-admin" guarantee can only be made atomic by the DB; the gate/token logic is a pure API-layer precondition |
| Public-path allowlist hardening (SECHRD-11) | API / Backend (Actix middleware, pre-router) | — | Path normalization + segment-boundary matching is a pure request-parsing concern, no DB/CDN involvement |
| Constant-time reset + zeroize + audit DLQ (SECHRD-12) | API / Backend (`axiam-auth` service layer) | Database / Storage (password_history seeding), Browser/Client (none — purely server-side) | Timing equalization and secret hygiene are process-local; the DLQ write path additionally touches local-disk + structured logging (adjacent to, not owned by, the DB tier) |

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `secrecy` 0.10.3 | crates.io | published 2018-10-04 (current major line stable) | 2.27M/week | github.com/iqlusioninc/crates/tree/main/secrecy | OK | Approved — NEW direct dependency (currently absent from Cargo.lock entirely) |
| `zeroize` 1.9.0 | crates.io | published 2018-10-03 | 10.8M/week | github.com/RustCrypto/utils | OK | Approved — already present transitively (Cargo.lock has 21 dependents); promote to a direct `axiam-auth` dependency |

**Packages removed due to [SLOP] verdict:** none.
**Packages flagged as suspicious [SUS]:** none.

Both verdicts obtained via `gsd-tools query package-legitimacy check --ecosystem crates secrecy zeroize` (OK/OK) and cross-verified directly against the crates.io registry with `cargo info secrecy` / `cargo search zeroize` (not WebSearch/training data) — tag `[VERIFIED: crates.io]`, not `[ASSUMED]`.

**Installation (add to `[workspace.dependencies]` in root `Cargo.toml`, mirroring the existing `argon2`/`aes-gcm` style, then `{ workspace = true }` in `crates/axiam-auth/Cargo.toml`):**
```toml
# workspace Cargo.toml
zeroize = "1"
secrecy = "0.10"
```
```toml
# crates/axiam-auth/Cargo.toml [dependencies]
zeroize = { workspace = true }
secrecy = { workspace = true }
```
No lockfile churn beyond these two entries — both are leaf-ish crates with minimal transitive graphs (`secrecy` has zero non-dev deps beyond an optional `serde`; `zeroize` is already resolved workspace-wide at 1.9.0, `secrecy` 0.10.3 constrains `Zeroize` internally so no version conflict).

## Standard Stack

### Core (already in use — no new stack decisions needed)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `surrealdb` | 3.1.5 `[VERIFIED: Cargo.lock]` | CAS updates, uniqueness-invariant CREATE, rate-limit bucket store | Already the only datastore (D-01a mandates reuse, no Redis) |
| `actix-governor` | 0.10.0 `[VERIFIED: Cargo.lock]` | REST per-endpoint in-memory rate limiter (kept as fail-open fallback) | Already wired at every rate-limited REST endpoint |
| `tower_governor` | 0.8.0 `[VERIFIED: Cargo.lock]` | gRPC rate limiter (kept as fail-open fallback) | Already wired as `GovernorLayer` on the gRPC server |
| `governor` | 0.10.4 `[VERIFIED: Cargo.lock]` | Underlying token-bucket algorithm for both of the above | Shared dependency of `actix-governor`/`tower_governor` |
| `argon2` | 0.5 `[VERIFIED: Cargo.lock]` | Real + dummy password hashing (constant-time reset reuses existing calls) | Already OWASP-tuned (`m=19456,t=2,p=1`, Argon2id) in `password.rs` |
| `totp-rs` | 5.x `[VERIFIED: Cargo.lock]` | TOTP verification (unchanged this phase — only the persistence-side CAS changes) | Already in use |

### Supporting — new direct dependencies
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `zeroize` | 1.9.0 | `Zeroizing<String>` wrapper around the peppered-password buffer in `password.rs` (`hash_password`/`verify_password`) | Any `String`/`Vec<u8>` holding a password+pepper concatenation before it's fed to Argon2 |
| `secrecy` | 0.10.3 | `SecretString` (= `SecretBox<str>`) wrapping `AuthConfig.pepper` / any pepper value carried across function boundaries | Any secret value that survives longer than one stack frame and could otherwise be accidentally `Debug`-printed or cloned into logs |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Custom async pre-check middleware for shared rate-limit (this research's recommendation) | Fork/re-implement `governor::StateStore` with an internal `block_on` | Rejected: blocking inside an async Tokio worker thread from a sync trait method risks stalling the runtime under load — exactly the DoS class rate limiting exists to prevent |
| `secrecy` for the peppered buffer too | `zeroize::Zeroizing<String>` for everything (no `secrecy`) | D-04's own "Claude's Discretion" text explicitly assigns `zeroize` to the buffer and `secrecy` to the pepper — matches CLAUDE.md's "secrets never serialized/logged/defaulted" posture better (secrecy's `Debug` impl redacts by default; `Zeroizing<String>` does not) |
| `UPDATE ... WHERE` CAS (recommended) | Optimistic-concurrency version column (`revision` field) | SurrealDB CAS-via-WHERE is already proven in this exact codebase (`oauth2_auth_code.rs`); a version column is a bigger schema change for no additional atomicity benefit here |

**Installation:** see Package Legitimacy Audit above.

**Version verification:** `surrealdb 3.1.5`, `actix-governor 0.10.0`, `tower_governor 0.8.0`, `governor 0.10.4`, `argon2 0.5` all confirmed via `Cargo.lock` (`[VERIFIED: Cargo.lock]`, exact resolved versions, not registry-latest). `zeroize 1.9.0` / `secrecy 0.10.3` confirmed via `cargo info`/`cargo search` against the live crates.io registry (`[VERIFIED: crates.io]`) on 2026-07-03.

## Architecture Patterns

### System Architecture Diagram — shared rate-limit check (SECHRD-03, new)

```
Incoming request (REST: ServiceRequest / gRPC: tonic Request)
        │
        ▼
┌─────────────────────────────┐
│ Key extraction               │  REST: fixed XForwardedForKeyExtractor
│ (unchanged logic, bug fixed) │  gRPC: SmartIpKeyExtractor (unchanged;
└──────────────┬───────────────┘        see Pitfall 6 below)
               │ IpAddr key
               ▼
┌───────────────────────────────────────┐
│ NEW: SharedRateLimitCheck (async)      │
│  1. UPSERT rate_limit_bucket:{key,     │
│     endpoint} windowed-counter CAS      │
│  2. count <= limit? -> allow            │
│  3. DB error/timeout? -> fall through   │──── fail-open ────┐
└──────────────┬──────────────────────────┘                   │
               │ allowed (or DB unreachable)                   │
               ▼                                                ▼
      request proceeds to handler          existing in-memory Governor/
                                            GovernorLayer (per-replica,
                                            UNCHANGED) makes the call instead
```

### Recommended Project Structure (delta only — files touched, not a new layout)
```
crates/
├── axiam-db/src/
│   ├── repository/user.rs          # update_totp_step -> CAS UPDATE...WHERE
│   ├── repository/rate_limit.rs    # NEW: SurrealRateLimitBucketRepository (windowed CAS counter)
│   └── schema.rs                   # NEW schema version: rate_limit_bucket table + bootstrap_lock/bootstrap_setup_token tables
├── axiam-auth/src/
│   ├── totp.rs                     # verify_code_with_replay_check -> return actual matched step (incl. -1 skew)
│   ├── password.rs                 # hash_password/verify_password -> Zeroizing<String> buffer, SecretString pepper
│   └── password_reset.rs           # PasswordResetService -> + crypto_semaphore field, dummy-hash on both Ok(None) branches
├── axiam-api-rest/src/
│   ├── extractors/rate_limit.rs    # XForwardedForKeyExtractor -> fix >= hops.len() branch
│   ├── middleware/rate_limit_shared.rs  # NEW: async pre-check Actix middleware wrapping build_governor()
│   ├── middleware/authz.rs         # is_public_path -> segment-boundary + path normalization
│   └── handlers/bootstrap.rs       # mandatory gate (env OR token) + CAS/lock-based atomicity
├── axiam-api-grpc/src/
│   └── middleware/rate_limit.rs    # store swap only — leave per_second/burst_size math untouched
└── axiam-server/src/
    └── cleanup.rs                  # optional: periodic rate_limit_bucket expiry sweep (same ticker as existing cleanup_expired calls)
```

### Pattern 1: SurrealDB CAS via `SELECT * FROM (UPDATE ... WHERE guard)`
**What:** Wrap a conditional `UPDATE` in a subquery `SELECT`; the result set contains a row only if the `WHERE` guard matched (and thus the update applied). Zero rows = CAS lost (concurrent winner already updated, or precondition false).
**When to use:** Any "claim once" / "advance only if still valid" operation — the exact shape of SECHRD-01's TOTP step advance.
**Example (already live in this codebase — `oauth2_auth_code.rs::consume`):**
```rust
// Source: crates/axiam-db/src/repository/oauth2_auth_code.rs:213-243 (verified live in repo, 2026-07-03)
let result = self.db.query(
    "SELECT meta::id(id) AS record_id, * FROM \
     (UPDATE oauth2_auth_code SET used = true \
      WHERE tenant_id = $tenant_id AND code_hash = $code_hash \
        AND client_id = $client_id AND redirect_uri = $redirect_uri \
        AND used = false AND expires_at > time::now())"
).bind(...).await.map_err(DbError::from)?;
let mut result = result.check().map_err(|e| DbError::Migration(e.to_string()))?;
let rows: Vec<AuthCodeRowWithId> = result.take(0).map_err(DbError::from)?;
let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound { .. })?;
```
**Direct application to SECHRD-01 — recommended `update_totp_step` rewrite:**
```rust
// crates/axiam-db/src/repository/user.rs — replace the unconditional UPDATE at line 484
async fn update_totp_step(&self, tenant_id: Uuid, id: Uuid, step: u64) -> AxiamResult<bool> {
    // NOTE: signature change — Result<bool> not Result<()>. `false` = CAS lost
    // (replay or a concurrent winner already advanced the step); caller MUST
    // treat `false` as "reject this code", not swallow it.
    let mut result = self.db.query(
        "SELECT meta::id(id) AS record_id, * FROM \
         (UPDATE type::record('user', $id) SET \
            totp_last_used_step = $step, updated_at = time::now() \
          WHERE tenant_id = $tenant_id \
            AND (totp_last_used_step = NONE OR totp_last_used_step < $step))"
    )
    .bind(("id", id.to_string()))
    .bind(("tenant_id", tenant_id.to_string()))
    .bind(("step", step))
    .await.map_err(DbError::from)?
    .check().map_err(|e| DbError::Migration(e.to_string()))?;
    let rows: Vec<UserRowWithId> = result.take(0).map_err(DbError::from)?;
    Ok(!rows.is_empty())
}
```
This exactly matches the AC's literal SurrealQL (`WHERE totp_last_used_step < $step`), extended with `= NONE OR` to cover the unseeded (first-ever) case — mirrors `increment_failed_logins`'s existing use of `IF/THEN` against `NONE`-able fields.

**Trait signature change required:** `axiam-core/src/repository.rs:165` `update_totp_step` currently returns `AxiamResult<()>`. Change to `AxiamResult<bool>` (or keep `()` and instead have the CAS-miss surface as a typed error, e.g. reuse `AxiamError::ReplayDetected` — mirrors the SAML pattern in Pattern 2 below and lets the handler `?`-propagate a 401 without new branching). **Recommend the `ReplayDetected` error route** for symmetry with the existing SAML replay pattern and because `AuthError::MfaInvalidCode` (already returned on `!valid`) is the natural sibling — the handler's existing `if !valid { return Err(MfaInvalidCode) }` branch can simply also catch the CAS-miss case as the same error, no new response shape needed.

### Pattern 2: Uniqueness-invariant CREATE → typed "already exists" error
**What:** `CREATE` a record with a deterministic ID (or rely on a `UNIQUE` index); the loser of a race gets a driver-level error whose message contains `"already contains"` / `"already exists"` / `"unique"` — mapped in Rust to a domain error via string-match on `result.check()`'s `Err`.
**When to use:** "At most one of X may ever exist" invariants — exactly SECHRD-04's "at most one super-admin".
**Example (already live — `saml_replay.rs::insert_assertion`):**
```rust
// Source: crates/axiam-db/src/repository/saml_replay.rs:61-93 (verified live, 2026-07-03)
let result = self.db.query(
    "CREATE type::record('saml_assertion_replay', $row_id) SET tenant_id = $tenant_id, ..."
).bind(...).await.map_err(DbError::from)?;
result.check().map_err(|e| {
    let msg = e.to_string();
    if msg.contains("already contains") || msg.contains("already exists") || msg.contains("unique") {
        AxiamError::ReplayDetected
    } else {
        AxiamError::Database(msg)
    }
}).map(|_| ())
```
**Direct application to SECHRD-04 — bootstrap atomicity:**
Add a `bootstrap_lock` table with a schema-level UNIQUE-by-construction key (the record ID itself is the tenant_id), and fold its `CREATE` into the SAME transaction as the admin-user `CREATE` + `RELATE` in `bootstrap.rs` (that file already builds a hand-written `BEGIN TRANSACTION ... COMMIT TRANSACTION` string — see current code at lines 171-187):
```rust
let txn_query = format!(
    "BEGIN TRANSACTION; \
     CREATE type::record('bootstrap_lock', $tenant_id) SET locked_at = time::now(); \
     CREATE type::record('user', $user_id) SET ...; \
     RELATE user:`{user_id_str}` -> has_role -> role:`{role_id_str}` SET resource_id = NONE; \
     COMMIT TRANSACTION"
);
```
Two concurrent requests: the `bootstrap_lock` `CREATE` for the SAME `tenant_id` record ID can only succeed once — the loser's *entire transaction* rolls back atomically (no partial admin, no orphan role RELATE), and the error surfaces via the SAME `result.check()` string-match as Pattern 2 above, mapped to (recommend) `AxiamError::AlreadyExists { entity: "bootstrap".into() }` (already a variant in `axiam-core/src/error.rs:10-11`, currently unused for this path — the handler today uses the semantically-wrong `NotFound{entity:"bootstrap", id:"already initialized"}` at line 135-138, which the planner may also clean up as an incidental correctness fix, though not a strict AC).

This also eliminates the existing SELECT-then-act TOCTOU at `bootstrap.rs` lines 97-140 (list roles → find super-admin → list users → check `total > 0`) — that whole block can be **deleted and replaced by the lock-record CREATE's success/failure**, which is both simpler and actually atomic.

### Pattern 3: Setup-token single-use consumption (D-03b) — reuse Pattern 1 (CAS) or Pattern 2 (uniqueness)
Either works; recommend Pattern 2 (simpler): mint a random token, store `bootstrap_setup_token:{sha256(token)}` at generation time (`CREATE`, first-boot only, logged once), and have the bootstrap handler consume it via a **second** `CREATE type::record('bootstrap_setup_token_consumed', $token_hash)` inside the same transaction as Pattern 2 above — a second concurrent request with the SAME token hits the SAME uniqueness violation and rolls back. No separate "used" boolean/CAS-update needed; consumption-by-existence is simpler and matches the SAML-replay precedent exactly.

### Pattern 4: Dummy-Argon2 timing equalization (already live — SEC-026)
**What:** On an "operation not possible for this input" branch, run the SAME cost operation (Argon2 hash/verify, same params) as the "operation succeeded" branch, gated by the same `crypto_semaphore`, inside `spawn_blocking`.
**Example (already live — `AuthService::login`):**
```rust
// Source: crates/axiam-auth/src/service.rs:210-227 (verified live, 2026-07-03)
Err(AxiamError::NotFound { .. }) => {
    // SEC-026: timing equalization — run a dummy Argon2 verify so
    // user-not-found takes the same time as wrong-password (ASVS V2).
    let _permit = self.crypto_semaphore.acquire().await.ok();
    let pepper_owned = self.config.pepper.clone();
    let _ = tokio::task::spawn_blocking(move || {
        password::verify_password("dummy", DUMMY_HASH, pepper_owned.as_deref())
    }).await;
    return Err(AuthError::InvalidCredentials.into());
}
```
**Direct application to SECHRD-12 — `initiate_reset`'s two `Ok(None)` branches (unknown email, federated user; `password_reset.rs` lines 94-98 and 100-108):**
```rust
// Add to PasswordResetService: crypto_semaphore: Arc<Semaphore> field + ctor param
// (mirrors AuthService's existing field exactly — same Arc, shared app-wide).
Err(AxiamError::NotFound { .. }) => {
    self.dummy_hash_wait(pepper).await;  // new private helper, same body as SEC-026's block
    return Ok(None);
}
// ...
if !links.is_empty() {
    self.dummy_hash_wait(pepper).await;
    return Ok(None);
}
```
`DUMMY_HASH` currently lives as a private `const` in `service.rs` — **move it to a shared location** (recommend `crate::password` module, `pub(crate) const DUMMY_HASH`) so both `AuthService` and `PasswordResetService` reference the identical constant (avoids drift between two copies).

**Wiring gap to close:** `PasswordResetService` currently has no `crypto_semaphore` field and `initiate_reset` has no `pepper` parameter (unlike `confirm_reset`, which already takes `pepper: Option<&str>`). Both the constructor and `initiate_reset`'s signature need to grow. The REST handler (`handlers/password_reset.rs::request_reset`) already has `auth_config: web::Data<AuthConfig>` in scope (has `.pepper`) but does **not** currently have the app-wide `crypto_semaphore: Arc<Semaphore>` in scope — it is constructed once in `axiam-server/src/main.rs:353` and moved into `AuthService`/`CaService`/`PgpService`/`CertService` constructors but **never separately registered as `web::Data`**. The planner must add `.app_data(web::Data::new(Arc::clone(&crypto_semaphore)))` in `main.rs`'s app-builder closure (alongside the other 46 `app_data` registrations) and thread it into `PasswordResetService::new(...)` at both call sites in `handlers/password_reset.rs`.

### Pattern 5: SurrealDB `BEGIN/COMMIT` transaction with explicit slot-numbering quirk
**What:** SurrealDB v3's driver returns `BEGIN TRANSACTION` as result slot 0; the first real statement is slot 1 (documented in-repo as a "MEMORY.md" gotcha, referenced at `bootstrap.rs:158-159`).
**When to use:** Any multi-statement atomic write — directly relevant to Pattern 2/3 above (bootstrap transaction grows from 2 statements to 3-4).
**Note:** the current `bootstrap.rs` code only calls `.check()` and never `.take(N)` on the transaction result (it doesn't need row data back), so this slot-numbering quirk does not bite the recommended change — flagging it only because a future edit that DOES need `.take()` on one of the new `CREATE bootstrap_lock`/`CREATE bootstrap_setup_token_consumed` statements must count slots starting from 1, not 0.

### Anti-Patterns to Avoid
- **Read-then-write TOCTOU for "is this the first X" checks:** the exact bug being fixed in `bootstrap.rs` today (list roles → list users → branch). Never reintroduce this shape for any new uniqueness check this phase adds.
- **Blocking a `governor::StateStore::measure_and_replace` call on an async DB round-trip:** the trait is synchronous; do not attempt `futures::executor::block_on` inside it. Build the shared-store check as a layer that runs BEFORE the existing governor, not as a `StateStore` impl.
- **Hand-tuned fixed-duration sleep for constant-time reset:** explicitly rejected in D-04/Deferred — a `tokio::time::sleep(Duration::from_millis(N))` drifts the moment Argon2 params change and provides no actual CPU-cost floor under contention. Use the real dummy-Argon2 call.
- **Manual `.zeroize()` call at the end of a function instead of `Zeroizing<T>`:** a manual call is skipped on any early `?` return (e.g., the `argon2.hash_password(...)` error path in `hash_password`). Use `zeroize::Zeroizing<String>` so the wipe is drop-based and fires on every exit path.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Compare-and-set DB update | A custom optimistic-lock/version-column scheme | `SELECT * FROM (UPDATE ... WHERE guard)` | Already proven correct under concurrency in this exact codebase (`oauth2_auth_code.rs`) and requires no schema change |
| "At most one" invariant | An application-level distributed lock (Redis SETNX, etc.) | SurrealDB `CREATE` on a deterministic record ID + UNIQUE-violation error mapping | D-01a already forbids new infra (no Redis); SurrealDB record-ID uniqueness is a DB-native primitive, zero extra moving parts |
| Secret wiping | Manual `unsafe` memset / `std::ptr::write_volatile` calls | `zeroize::Zeroizing<T>` / `secrecy::SecretBox<T>` | Both crates already implement the correct volatile-write + compiler-barrier technique; hand-rolling risks the compiler optimizing the wipe away |
| Rate-limit token bucket algorithm | A custom leaky-bucket/sliding-window implementation | Keep `governor`'s GCRA algorithm for the in-memory fallback; a simpler fixed-window counter in SurrealDB for the shared layer is acceptable because it only needs to be *approximately* right (fail-open by design) | `governor` is already battle-tested and wired at every REST/gRPC rate-limited endpoint; reinventing it for the fallback path adds risk for zero benefit |
| Path traversal detection | A regex-based `..`-matcher | `Path::components()`-style segment split + explicit `ParentDir` rejection, or a simple `path.split('/').any(|s| s == "..")` check | Regex-based traversal filters are a well-known source of bypasses (double-encoding, mixed separators); segment-wise comparison after a plain `split('/')` is sufficient here because `is_public_path` only needs a fail-closed decision (deny → falls through to the normal 401/403 credential check), not a rewritten canonical path |

**Key insight:** every one of this phase's five fixes has a structurally identical fix already merged elsewhere in the codebase for a different requirement (SEC-026, SEC-008-precursor via `oauth2_auth_code`, D-09 via `saml_replay`). This phase is largely "apply the established pattern to a surface that was missed," which is exactly why the acceptance criteria are so prescriptive — there is very little genuine design space left, only application-of-precedent plus the one new component (shared rate-limit store).

## Common Pitfalls

### Pitfall 1: `governor::StateStore` is synchronous — cannot be a drop-in SurrealDB adapter
**What goes wrong:** An implementer reads D-01a as "implement `StateStore` backed by SurrealDB" and tries to call `.await` inside `measure_and_replace`, which doesn't compile (the trait method is `fn`, not `async fn`), or reaches for `block_on` and stalls the Tokio runtime under load.
**Why it happens:** CONTEXT.md's "store swap" phrasing is accurate at the requirements level but doesn't specify the trait boundary.
**How to avoid:** Build a separate async pre-check (Actix middleware / tower Layer) that runs before the existing `Governor`/`GovernorLayer`, per the System Architecture Diagram above. The in-memory governor is retained unmodified as the fail-open fallback.
**Warning signs:** any `futures::executor::block_on` or `tokio::runtime::Handle::block_on` appearing inside code that also holds an `actix_governor`/`tower_governor` type.

### Pitfall 2: `SmartIpKeyExtractor` (gRPC) has no `trusted_hops` concept at all
**What goes wrong:** The planner assumes fixing `XForwardedForKeyExtractor`'s `>= hops.len()` branch (REST) also fixes the gRPC governor, because CONTEXT.md lists both files under SECHRD-03's code surfaces.
**Why it happens:** `tower_governor::key_extractor::SmartIpKeyExtractor` (verified by reading `tower_governor-0.8.0/src/key_extractor.rs`) unconditionally takes the FIRST parseable IP in `X-Forwarded-For` (`s.split(',').find_map(...)`), with zero `trusted_hops` parameter — it is a *different, more naive* extractor than the REST one.
**How to avoid:** Treat gRPC's key-extractor fix as a separate decision, not a byproduct of the REST fix. Given D-01c frames the gRPC change as "store/key-extractor only" (not "store only"), the safe interpretation is: replace `SmartIpKeyExtractor` with a small custom `KeyExtractor` mirroring the (fixed) REST logic — same `trusted_hops` config, same "fall through to peer/connect-info when hops insufficient" rule — for parity. If the planner instead judges gRPC is only reachable from a trusted service mesh (per CLAUDE.md's "gRPC for low-latency authz checks in service mesh") and descopes the gRPC key-extractor fix, that must be an explicit, recorded decision (this is genuinely underspecified by the ACs — flagged in Open Questions below), not a silent gap.
**Warning signs:** a negative test asserting rotating-XFF-same-bucket that only exercises the REST endpoint, leaving the gRPC governor completely unverified.

### Pitfall 3: `PasswordResetService` lacks the `crypto_semaphore`/`pepper` plumbing SEC-026's pattern needs
**What goes wrong:** Implementer tries to call `password::verify_password("dummy", DUMMY_HASH, pepper)` directly inside `initiate_reset` without `spawn_blocking`, defeating the CPU-isolation guarantee (CQ-B02/REQ-14 AC-2) the rest of the codebase enforces for all Argon2 calls, or blocks the async executor thread.
**Why it happens:** `PasswordResetService::new` currently takes 6 repository params and no semaphore; `initiate_reset` currently takes no pepper param (only `confirm_reset` does).
**How to avoid:** Grow the constructor (`crypto_semaphore: Arc<Semaphore>`) and `initiate_reset`'s signature (`pepper: Option<&str>`), update both call sites in `handlers/password_reset.rs`, and register `crypto_semaphore` as `web::Data` in `main.rs` (see Pattern 4 above). This touches `axiam-auth::PasswordResetService` and `axiam-api-rest::handlers::password_reset` plus `axiam-server::main` — three crates, one logical change; the planner should sequence this as a single task/wave to avoid a broken intermediate compile state (per-crate `cargo check` discipline still applies per-commit, but the three edits are interdependent).
**Warning signs:** `cargo check -p axiam-auth` passes but `cargo check -p axiam-api-rest` fails with a missing-argument error on `PasswordResetService::new`.

### Pitfall 4: Current-password-reuse check runs BEFORE the old hash is in history
**What goes wrong:** `confirm_reset` calls `evaluate_password` (which checks `password_history_repo.get_recent(...)`) BEFORE it stores the pre-reset password hash into history (`password_reset.rs` — `evaluate_password` at line 182, history `.create()` at line 203, in that order). A user resetting to their CURRENT password is not blocked by the history check, because that hash isn't in the history table yet.
**Why it happens:** the history-seed write and the history-check read are ordered for a different purpose (compute the check before mutating state) and nobody added an explicit "does `new_password` match `user.password_hash`" comparison.
**How to avoid:** Add an explicit `password::verify_password(new_password, &user.password_hash, pepper)` check in `confirm_reset` (reject if `Ok(true)`) — independent of and in addition to the `password_history_count`-based check. This must run inside the CPU-isolation semaphore like every other Argon2 call in this codebase (`confirm_reset` doesn't currently acquire `crypto_semaphore` for password work at all — it delegates purely to `evaluate_password`→`check_history`, which itself calls `verify_password` synchronously with no semaphore/spawn_blocking; note this is a **pre-existing gap** the planner may choose to fix in the same pass since it's directly adjacent, though it's not explicitly named in the ACs).
**Warning signs:** a test that resets a user's password to their OWN CURRENT password and expects rejection currently passes only by accident (if `password_history_count` happens to already contain that exact hash from a prior reset in the test) — the true regression test must exercise a user who has NEVER reset before (fresh signup password, zero history rows).

### Pitfall 5: Seeding "initial password into history" has two separate production write paths, not one
**What goes wrong:** Fixing only `SurrealUserRepository::create_with_consent` (used by `handlers/users.rs::create`, admin-created users) misses `handlers/bootstrap.rs`'s bootstrap admin creation, which uses its OWN hand-written `CREATE`/transaction and does not call `create_with_consent` or `create` at all.
**Why it happens:** two independent user-creation code paths exist by design (bootstrap self-disables after first use and intentionally bypasses the normal consent-required creation flow).
**How to avoid:** Add a third `CREATE type::record('password_history', $ph_id) SET ...` statement to BOTH: (a) `create_with_consent`'s existing `BEGIN/CREATE user/CREATE consent/COMMIT` transaction, and (b) `bootstrap.rs`'s `BEGIN/CREATE user/RELATE/COMMIT` transaction (which, per Pattern 2/3 above, is already growing to include the lock + setup-token-consumption statements this same phase). Federated-user creation (`oidc.rs:556`, `saml.rs:714`) has no local password and should NOT seed history (there is no `password_hash` to seed — federated users can't reach the password-reset flow at all, per `password_reset.rs`'s existing federated-user check).
**Warning signs:** a test seeding history via `handlers/users.rs::create` passes, but a bootstrap-created super-admin can immediately "reset" back to their own bootstrap password with zero history rows blocking it.

### Pitfall 6: `is_public_path`'s current wildcard set has only ONE entry (`/api/docs/*`) — the segment-boundary bug is latent, not yet exploitable
**What goes wrong:** A planner writes a negative test against a HYPOTHETICAL future entry (e.g. `/api/v1/auth/*` vs `/api/v1/authz/...`, the example from the roadmap/AC text) without first confirming today's `PUBLIC_PATHS` (`crates/axiam-api-rest/src/permissions.rs:193-...`) has no such adjacent-prefix collision to exploit against a REAL route.
**Why it happens:** the AC's illustrative example (`/api/v1/auth/*` / `/api/v1/authz/...`) doesn't correspond to any current PUBLIC_PATHS entry — the ONLY wildcard entry today is `"/api/docs/*"`.
**How to avoid:** the negative test should be written against `is_public_path` DIRECTLY (unit test, as the existing `mod tests` in `authz.rs` already does), using a SYNTHETIC wildcard entry or by asserting the exact AC example (`/api/v1/auth/*` doesn't match `/api/v1/authz/...`) as a property of the matching FUNCTION regardless of what's currently in `PUBLIC_PATHS` — this is what the existing `public_paths_are_recognized`/`protected_paths_are_not_public` unit tests already do (call `is_public_path` directly, not through the live registry), so the new tests should follow the same style.
**Warning signs:** a "negative test" that can never fail because `PUBLIC_PATHS` currently contains no adjacent-prefix pair to collide.

## Runtime State Inventory

> Not applicable — this phase is a security-hardening fix-in-place phase, not a rename/refactor/migration. No entity names, IDs, or identifiers change. Explicitly verified: no `rename`/`rebrand` scope in CONTEXT.md, no schema-migration-of-existing-data implied by any of the 5 ACs (SECHRD-04's new `bootstrap_lock`/`bootstrap_setup_token` tables and SECHRD-03's new `rate_limit_bucket` table are net-new additive schema, not migrations of existing rows).

## Code Examples

### TOTP CAS + skew-step recording (SECHRD-01)
```rust
// crates/axiam-auth/src/totp.rs — verify_code_with_replay_check currently
// computes `current_step` independently and compares `current_step <= last`,
// but on a totp-rs skew-tolerant match (±1 window) the code that validated
// may correspond to `current_step - 1`, not `current_step`. To record the
// ACTUAL matched step (the AC's core correctness requirement), replace the
// single `totp.check_current(code)` call with an explicit per-candidate-step
// check across the tolerated window and return whichever step matched:
let candidate_steps = [current_step.saturating_sub(1), current_step, current_step + 1];
for step in candidate_steps {
    if totp_rs::TOTP::generate(&totp_config, step * 30) == code {   // illustrative; use totp-rs's actual step-based generate API
        if step <= last_used_step.unwrap_or(0) { return Ok((false, step)); }
        return Ok((true, step));
    }
}
Ok((false, current_step))
```
**Note:** `totp-rs` 5.x's exact API for "verify against an explicit step" vs. its built-in `check_current` (which internally applies `skew` but does not expose WHICH step matched) needs a direct API check during implementation — `[ASSUMED]`, not verified against `totp-rs` 5.x source in this research pass (not vendored locally; only `governor`/`tower_governor`/`secrecy`/`zeroize` sources were pulled). The planner/executor should run `cargo doc -p totp-rs --open` or check `~/.cargo/registry/src/.../totp-rs-5.*/src/lib.rs` for `TOTP::check` (many versions expose a `check(code, time)` taking an explicit unix timestamp, which can be called once per candidate step's timestamp — `step * 30`, `(step-1)*30`, `(step+1)*30` — to determine which one matched).

### Rate-limit shared bucket CAS (SECHRD-03) — SurrealQL sketch
```sql
-- New table (additive schema migration, mirrors seeder_state's shape):
-- DEFINE TABLE IF NOT EXISTS rate_limit_bucket SCHEMAFULL TYPE NORMAL;
-- DEFINE FIELD IF NOT EXISTS count ON TABLE rate_limit_bucket TYPE int DEFAULT 0;
-- DEFINE FIELD IF NOT EXISTS window_start ON TABLE rate_limit_bucket TYPE datetime;

UPSERT type::record('rate_limit_bucket', $key) SET
  count = IF window_start = NONE OR window_start < $window_start
            THEN 1 ELSE count + 1 END,
  window_start = IF window_start = NONE OR window_start < $window_start
            THEN $window_start ELSE window_start END,
  updated_at = time::now()
RETURN AFTER;
-- Rust side: take(0) the single returned row's `count`; allow if count <= limit.
```
This follows the exact "SurrealDB evaluates each RHS against the pre-update document" semantics already documented in-repo at `increment_failed_logins`'s comment (`user.rs:570-573`) — `count` on the RHS refers to the OLD value, so `count + 1` is correct read-before-write-in-one-statement, no separate SELECT needed. `$key` should be `format!("{endpoint}:{ip}")` (or hash it) to keep bucket identity aligned with the existing per-endpoint `build_governor(requests_per_min)` calls (each endpoint has its own limit today — the shared store must preserve that per-endpoint granularity, not introduce one global bucket).

### Zeroizing the peppered-password buffer (SECHRD-12 / T19.24)
```rust
// crates/axiam-auth/src/password.rs
use zeroize::Zeroizing;

pub fn hash_password(password: &str, pepper: Option<&str>) -> Result<String, AuthError> {
    let params = argon2::Params::new(19456, 2, 1, None)
        .map_err(|e| AuthError::Crypto(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let peppered: Zeroizing<String>;
    let input: &[u8] = match pepper {
        Some(p) => {
            peppered = Zeroizing::new(format!("{p}{password}"));
            peppered.as_bytes()
        }
        None => password.as_bytes(),
    };
    // peppered is zeroized on drop at end of scope, including on the
    // `?`-propagated error path below (Drop runs during unwind/early-return).
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let hash = argon2.hash_password(input, &salt)
        .map_err(|e| AuthError::Crypto(format!("hash error: {e}")))?;
    Ok(hash.to_string())
}
```
Apply the identical change to `verify_password`. `AuthConfig.pepper: Option<String>` should become `Option<secrecy::SecretString>` — this is a wider-reaching type change (every call site that does `self.config.pepper.clone()` / `.as_deref()` today, e.g. `service.rs:221`, `password_reset.rs`'s new field) needs `.expose_secret()` added at the point it's turned into `&str` for `hash_password`/`verify_password`. Recommend scoping this precisely: `AuthConfig.pepper` becomes `SecretString`, but `hash_password`/`verify_password`'s own `pepper: Option<&str>` parameter signature stays unchanged (callers call `.expose_secret()` once, at the boundary, not deeper).

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Unconditional `UPDATE ... SET totp_last_used_step = $step` | Conditional `UPDATE ... WHERE totp_last_used_step < $step`, treat no-row-affected as reject | This phase (SECHRD-01) | Closes the N-parallel-submission race entirely at the storage layer |
| SELECT-then-branch bootstrap "already initialized" check | Uniqueness-invariant `CREATE` inside the same transaction as admin creation | This phase (SECHRD-04) | Removes the TOCTOU window between the check and the admin-creation write |
| `trusted_hops >= hops.len()` → `hops[0]` (leftmost, attacker-controlled) | `trusted_hops >= hops.len()` → `peer_addr()` | This phase (SECHRD-03) | Closes the rotating-XFF rate-limit-evasion bypass |
| Per-replica in-memory-only rate limiting | Shared SurrealDB-backed bucket, fail-open to per-replica in-memory | This phase (SECHRD-03/D-01a-b) | Closes the multi-replica HPA rate-limit-multiplier gap without new infra |

**Deprecated/outdated:** none — no library version bumps in scope this phase; all five fixes are logic/architecture changes on the currently-pinned stack.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `totp-rs` 5.x exposes a way to verify a code against an EXPLICIT time-step/timestamp (not just `check_current`'s implicit-now + internal skew) | Code Examples / TOTP CAS | If no such API exists, the "record the actual matched step, incl. -1 skew" AC requires re-deriving the skew check manually against raw HMAC-SHA1/HOTP values instead of delegating to `totp-rs` — larger implementation, same outcome |
| A2 | gRPC's `SmartIpKeyExtractor` should be replaced with a custom `trusted_hops`-aware extractor for parity with the REST fix | Pitfall 2 | If the correct call is "gRPC is mesh-internal only, leave `SmartIpKeyExtractor` as-is," implementing the swap anyway is extra unrequired work (low risk — strictly more secure, not a regression) but could conflict with an as-yet-undocumded CORR-01/Phase-26 expectation about the gRPC extractor type; flagged as an Open Question for discuss-phase/planner sign-off, not silently assumed |
| A3 | `confirm_reset` should also gain a semaphore-gated `crypto_semaphore.acquire()` around its existing `verify_password`/`evaluate_password` Argon2 work (currently ungated, unlike `AuthService::login`) | Pitfall 4 | This is adjacent cleanup, not a named AC; if descoped, `confirm_reset`'s Argon2 calls remain outside the CPU-isolation semaphore (pre-existing behavior, not a regression this phase introduces) |
| A4 | "Structured audit syslog" (D-02) is satisfied by a structured `tracing` JSON event (existing `tracing-subscriber` "json" feature, captured by the container log driver) rather than a literal UNIX-syslog-socket write | Don't Hand-Roll / D-02 design | If the user actually wants a real `syslog(3)`-protocol UDP/TCP sink, a new crate (e.g. `syslog` or `journald`) must be added — no such crate is in `Cargo.lock` today, and the distroless deployment (per CLAUDE.md/06-01 decisions) has no local syslogd to talk to, making a literal syslog socket write dubious in this deployment model. HIGH-impact assumption — recommend the planner confirm this interpretation in the plan's `<threat_model>` block or via a discuss-phase-style checkpoint before implementation, since it changes whether a new dependency is needed. |

## Open Questions (RESOLVED during planning — 2026-07-03)

> Both questions were resolved by the orchestrator from the locked CONTEXT.md decisions and recorded in the implementing plans. Assumption A4 (D-02 "syslog") is likewise resolved below.

1. **Does the gRPC governor's key extractor need the same `trusted_hops` fix as REST, or is mesh-internal exposure a sufficient mitigation?**
   - **RESOLVED: fix it (parity).** CONTEXT.md D-01c scopes the gRPC change as "store/key-extractor only" and the phase goal is "resists IP-spoofing," so the gRPC limiter gets BOTH the shared-store swap AND a `trusted_hops`-aware key extractor that stops unconditionally trusting the leftmost XFF hop. The throughput/quota math (`per_millisecond`/`Quota::per_second`) is left byte-for-byte untouched (CORR-01/Phase 26 owns it). Recorded in **24-07-PLAN.md**.
   - What we know: `SmartIpKeyExtractor` (gRPC) unconditionally trusts the leftmost XFF entry with zero configurability; CLAUDE.md documents gRPC as "for low-latency authz checks in service mesh" (suggesting internal-only exposure); CONTEXT.md's canonical_refs lists the gRPC `rate_limit.rs` file under SECHRD-03's surfaces.
   - Rationale: parity is low-cost and strictly safer; leaving a known IP-spoof keying bug in gRPC while fixing REST would contradict the phase goal.

2. **Does `confirm_reset`'s current-password-reuse gap (Pitfall 4) get its own explicit fix, or does seeding history + the existing count-based check suffice once ordering is corrected?**
   - **RESOLVED: explicit comparison.** The unauthenticated reset path blocks reuse of the current password via an explicit `verify_password(new_password, &user.password_hash, ...)` check, independent of the history-count window (matches the AC's literal wording and is robust regardless of `password_history_count` policy). The initial/bootstrap password is additionally seeded into history (Pitfall 5). Recorded in **24-09-PLAN.md**.
   - What we know: reordering (seed history before evaluating, or add a direct hash comparison) both close the SPECIFIC "reset to your current password" gap the AC names; the direct comparison is more robust and self-documenting.

**Assumption A4 (D-02 "structured audit syslog") — RESOLVED: structured `tracing` JSON event.** A literal `syslog(3)` sink would require a new crate (e.g. `syslog`), which contradicts CONTEXT.md `<specifics>`' locked constraint "no new crates beyond `zeroize`/`secrecy`," and the distroless deployment has no local syslogd. The structured `tracing` JSON event (existing `tracing-subscriber` "json" feature, captured by the container log driver) is SIEM-ingestible and satisfies D-02's stated rationale ("a SIEM can ingest either"), while the append-only file on a mounted volume is the DB-independent durable sink. This is the only interpretation consistent with all locked decisions taken together. Recorded in **24-06-PLAN.md**.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| SurrealDB (embedded/local engine, `kv-mem` in tests) | All 5 fixes (CAS updates, new tables) | ✓ | 3.1.5 (`surrealdb` crate) | — |
| `zeroize` crate | SECHRD-12 (T19.24) | ✓ (registry-reachable; not yet a direct dep) | 1.9.0 | — |
| `secrecy` crate | SECHRD-12 (T19.24) | ✓ (registry-reachable; net-new dep) | 0.10.3 | — |
| Rust toolchain / `cargo` | All | ✓ | edition 2024, `rust-version = "1.93"` (workspace) | — |
| `cargo clippy -D warnings`, `cargo fmt` | Pre-commit discipline (CLAUDE.md) | ✓ (confirmed via `justfile` `lint`/`fmt-check` recipes) | — | — |
| Network egress to crates.io (for adding zeroize/secrecy) | Package legitimacy verification, `cargo build` after Cargo.toml edit | ✓ (verified — `cargo info`/`cargo search` succeeded this session via the pre-configured proxy) | — | — |

**Missing dependencies with no fallback:** none.
**Missing dependencies with fallback:** none — both new crates are ordinary crates.io dependencies with no system-library requirement (unlike e.g. `samael`'s `xmlsec` FFI dependency elsewhere in this workspace).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `cargo test` (built-in Rust test harness), `#[tokio::test]` for async |
| Config file | none — per-crate `Cargo.toml` `[dev-dependencies]`; workspace-level `tokio-test` also available |
| Quick run command | `cargo test -p <crate> <test_name>` (e.g. `cargo test -p axiam-auth totp_replay`) |
| Full suite command | `cargo test --workspace` (CI-only per CLAUDE.md — local dev uses per-crate `-p`) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SECHRD-01 | N parallel submissions of one valid TOTP code succeed at most once | concurrency (`tokio::spawn` × N, `join_all`, assert exactly 1 success) | `cargo test -p axiam-db totp_step_cas_concurrent` (new) or `-p axiam-auth` if testing at the service layer | ❌ Wave 0 — extend `crates/axiam-auth/tests/req14_totp_replay_test.rs` (currently unit-only, no CAS/concurrency coverage) or add `crates/axiam-db/tests/totp_step_cas_test.rs` |
| SECHRD-01 | −1-skew-accepted code cannot be replayed in a later wall-clock step | unit (fixed clock / explicit step params) | `cargo test -p axiam-auth totp_skew_step_recorded` (new) | ❌ Wave 0 — needs an explicit-step-taking test helper (see Assumption A1) |
| SECHRD-03 | Rotating XFF per request no longer yields a fresh bucket | integration (actix `test::call_service`, N requests with N different XFF values, assert 429 after limit) | `cargo test -p axiam-api-rest rate_limit_xff_rotation_rejected` (new) | ❌ Wave 0 |
| SECHRD-03 | Shared store enforces limit across "replicas" (simulate 2 `Governor` instances sharing 1 SurrealDB) | integration | `cargo test -p axiam-api-rest rate_limit_shared_store_cross_instance` (new) | ❌ Wave 0 |
| SECHRD-04 | Two concurrent first-run bootstraps create at most one super-admin | concurrency (`tokio::spawn` × 2 against the SAME in-memory DB, assert exactly 1 `Created`, 1 error) | `cargo test -p axiam-api-rest bootstrap_concurrent_race_single_admin` (new) — extend `bootstrap_test.rs` | ❌ Wave 0 |
| SECHRD-04 | Bootstrap refused when gate (env var / setup token) unset | integration, must use existing `env_lock()`/`env_guard()` helper | `cargo test -p axiam-api-rest bootstrap_refused_when_gate_unset` (new) — extend `bootstrap_test.rs` | ❌ Wave 0 (helper exists at `bootstrap_test.rs:56-67`, reuse it) |
| SECHRD-11 | Non-canonical/wrong-segment path cannot slip past the allowlist | unit (direct `is_public_path` calls, mirrors existing `mod tests` style) | `cargo test -p axiam-api-rest is_public_path` | ❌ Wave 0 — extend the existing `#[cfg(test)] mod tests` in `middleware/authz.rs` (currently 3 tests, add segment-boundary + `//`/`..` cases) |
| SECHRD-12 | Ineligible/unknown/federated reset is time-indistinguishable | timing (statistical — measure N samples of each branch, assert overlapping distributions / bounded delta) | `cargo test -p axiam-auth reset_timing_indistinguishable -- --ignored` (timing tests are commonly `#[ignore]`d in CI to avoid flakiness; run explicitly) | ❌ Wave 0 |
| SECHRD-12 | Peppered buffer zeroized | unit (cannot directly assert memory is wiped without `unsafe`/process inspection; test instead asserts `Zeroizing<String>` type is used at the call site — a compile-time/structural check, or a `miri`-based test if the team has that tooling) | `cargo test -p axiam-auth` (structural) | N/A — this AC is inherently hard to assert at the `cargo test` level; recommend a code-review/grep-gate style check (mirrors the existing `tls-bypass-gate.sh` pattern used in several SDK crates) rather than a runtime test: grep for `Zeroizing` wrapping the peppered buffer |
| SECHRD-12 | Current-password reuse blocked on reset path | unit/integration | `cargo test -p axiam-auth confirm_reset_rejects_current_password` (new) — extend `password_reset.rs`'s existing `mod tests` | ❌ Wave 0 |
| SECHRD-12 | GDPR audit-write DLQ (file + syslog) on DB-write failure | integration (inject a failing `AuditLogRepository` mock, assert file line + structured log event both emitted) | `cargo test -p axiam-api-rest gdpr_audit_dlq_on_db_failure` (new) | ❌ Wave 0 — needs a mockable/injectable audit-write failure point in `append_gdpr_audit` (currently takes a concrete `&SurrealAuditLogRepository<C>`, not a trait object — may need a trait-based seam for injectability, or drive the failure via a real DB in a broken state) |

### Sampling Rate
- **Per task commit:** `cargo test -p <crate> <specific_test>` for the crate(s) touched by that task
- **Per wave merge:** `cargo test -p axiam-db -p axiam-auth -p axiam-api-rest -p axiam-api-grpc` (the four crates every SECHRD-01/03/04/11/12 surface lives in)
- **Phase gate:** `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --all -- --check` + full per-touched-crate test run green before `/gsd-verify-work` (per CLAUDE.md `just check` / per-crate discipline)

### Wave 0 Gaps
- [ ] `crates/axiam-db/tests/totp_step_cas_test.rs` — new file, covers SECHRD-01 concurrency AC
- [ ] `crates/axiam-api-rest/tests/rate_limit_shared_store_test.rs` — new file, covers SECHRD-03 (both keying-bug and shared-store ACs)
- [ ] `crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs` — new file, covers SECHRD-03 gRPC coverage (D-01c)
- [ ] Extend `crates/axiam-api-rest/tests/bootstrap_test.rs` — SECHRD-04 concurrency + mandatory-gate cases
- [ ] Extend `crates/axiam-api-rest/src/middleware/authz.rs`'s inline `mod tests` — SECHRD-11 normalization cases
- [ ] Extend `crates/axiam-auth/src/password_reset.rs`'s inline `mod tests` — SECHRD-12 current-password-reuse + timing cases
- [ ] `crates/axiam-api-rest/tests/gdpr_audit_dlq_test.rs` — new file (or extend `gdpr_test.rs`), covers SECHRD-12 DLQ AC; requires deciding the audit-repo injectability seam first (see table note above)
- [ ] No new test-framework install needed — `cargo test`/`tokio::test`/`actix_web::test` already fully wired workspace-wide

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|-------------------|
| V2 Authentication | yes | Argon2id (existing, unchanged params) for both real and dummy password/reset hashing; TOTP (RFC 6238) with atomic anti-replay (this phase's SECHRD-01) |
| V3 Session Management | no (out of scope — session/JWT surfaces untouched this phase) | — |
| V4 Access Control | yes | `AuthzMiddleware`'s public-path allowlist (SECHRD-11) is the default-deny gate for every non-public route; bootstrap (SECHRD-04) is the initial super-admin provisioning control |
| V5 Input Validation | yes | Path normalization before allowlist matching (SECHRD-11); `X-Forwarded-For` header parsing hardening (SECHRD-03) |
| V6 Cryptography | yes | `zeroize`/`secrecy` for secret hygiene (SECHRD-12); Argon2id params unchanged — never hand-rolled |
| V11 Business Logic | yes | Rate limiting (SECHRD-03) and bootstrap single-admin invariant (SECHRD-04) are business-logic-level anti-abuse controls |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| TOTP replay (submit the same valid code twice, or a skew-tolerated code again later) | Spoofing / Elevation of Privilege | DB-level compare-and-set on the last-used step (SECHRD-01) |
| Rate-limit bucket evasion via header spoofing | Denial of Service / Spoofing | Ignore untrusted XFF hops, key on verified peer address when the header can't be trusted (SECHRD-03) |
| TOCTOU race on "is this the first admin" checks | Elevation of Privilege | Atomic uniqueness-invariant CREATE inside the SAME transaction as the privileged write (SECHRD-04) |
| Path-prefix confusion in an authorization allowlist (`/auth/*` matching `/authz/...`) | Elevation of Privilege / Information Disclosure | Segment-boundary-aware wildcard matching + path normalization before the check (SECHRD-11) |
| Timing side-channel enabling user enumeration on password reset | Information Disclosure | Constant-time-equivalent dummy work on the "doesn't exist"/"can't reset" branch (SECHRD-12) |
| Secret material lingering in process memory after use | Information Disclosure (via memory dump/core dump) | `zeroize`/`secrecy` wrapping (SECHRD-12) |
| Silent loss of legally-significant GDPR audit events on a transient DB failure | Repudiation | Dead-letter to durable local storage + structured log on write failure (SECHRD-12/D-02) |

## Sources

### Primary (HIGH confidence — read directly from the live repo / vendored crate source this session)
- `crates/axiam-db/src/repository/oauth2_auth_code.rs` (CAS pattern, lines 198-243)
- `crates/axiam-db/src/repository/saml_replay.rs` (uniqueness-violation pattern, full file)
- `crates/axiam-db/src/repository/user.rs` (`update_totp_step` current state, `increment_failed_logins` IF/THEN-against-NONE pattern)
- `crates/axiam-auth/src/service.rs` (dummy-Argon2 SEC-026 pattern, `crypto_semaphore` wiring)
- `crates/axiam-auth/src/password.rs`, `password_reset.rs`, `totp.rs` (current signatures)
- `crates/axiam-api-rest/src/extractors/rate_limit.rs`, `server.rs`, `middleware/authz.rs`, `permissions.rs` (current SECHRD-03/11 surfaces)
- `crates/axiam-api-rest/src/handlers/bootstrap.rs`, `handlers/gdpr.rs`, `handlers/password_reset.rs` (current SECHRD-04/12 surfaces)
- `crates/axiam-api-grpc/src/middleware/rate_limit.rs` (current gRPC governor state — CORR-01 drift finding)
- `crates/axiam-server/src/main.rs`, `cleanup.rs` (DI/service-construction patterns, `crypto_semaphore` origin)
- `crates/axiam-core/src/repository.rs`, `error.rs` (trait signatures, existing error variants)
- `/root/.cargo/registry/src/.../governor-0.10.4/src/state.rs` (`StateStore` trait is synchronous — direct source read)
- `/root/.cargo/registry/src/.../tower_governor-0.8.0/src/key_extractor.rs` (`SmartIpKeyExtractor` leftmost-XFF behavior — direct source read)
- `/root/.cargo/registry/src/.../zeroize-1.9.0/src/lib.rs`, `/root/.cargo/registry/src/.../secrecy-0.10.3/src/lib.rs` (API surface confirmation)
- `cargo info secrecy`, `cargo search zeroize`, `gsd-tools query package-legitimacy check` (registry-verified package legitimacy, 2026-07-03)
- `git log` on `crates/axiam-api-grpc/src/middleware/rate_limit.rs` (2026-06-20 last-touch date, predates milestone start — supports the CORR-01-already-fixed finding)

### Secondary (MEDIUM confidence)
- `.planning/REQUIREMENTS.md` §SECHRD-01/03/04/11/12, §CORR-01 (acceptance criteria, cross-checked against live code — one discrepancy flagged: CORR-01)
- `.planning/phases/24-.../24-CONTEXT.md` (locked decisions, canonical refs — cross-checked against live code, drift noted per-surface)
- `claude_dev/roadmap.md` T19.23/24/25/27 descriptions

### Tertiary (LOW confidence)
- `totp-rs` 5.x explicit-step verification API (Assumption A1 — not source-verified this session, crate not vendored locally)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every version pinned and verified against `Cargo.lock`/live registry, no new stack decisions beyond 2 small crates
- Architecture: HIGH for Patterns 1/2/4 (proven-live code in this exact repo); MEDIUM for the new shared-rate-limit-store component (novel to this codebase, though built from well-understood primitives) and for the gRPC key-extractor question (Open Question 1, genuinely underspecified)
- Pitfalls: HIGH — 5 of 6 pitfalls identified via direct code reading (not speculation); Pitfall 1 (StateStore sync) verified against vendored crate source

**Research date:** 2026-07-03
**Valid until:** 30 days (stable stack, no fast-moving dependencies; re-verify if Phase 23 or Phase 26 land first and touch any of the same files, per the D-01c/CORR-01 and D-02/SECHRD-06 coordination notes)
