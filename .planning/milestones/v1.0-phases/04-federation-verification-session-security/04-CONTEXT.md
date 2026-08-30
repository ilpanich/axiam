# Phase 4: Federation Verification & Session Security - Context

**Gathered:** 2026-05-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Cryptographically verify external federation tokens before trusting them (OIDC ID-token signatures via JWKS, SAML XML signatures via `xmlsec`), enforce strict claim validation, and prevent replay of SAML assertions. Encrypt federation client secrets at rest with AES-256-GCM. Wire session/refresh-token invalidation into the password-change and password-reset flows. Add a new authenticated `POST /api/v1/auth/password/change` endpoint that uses the same hooks. Introduce an audience-based discriminator that distinguishes user JWTs from service-account JWTs. Expose new public (unauthenticated) federation endpoints under `/api/v1/auth/federation/...` for first-time SSO, separate from the existing authenticated link-account endpoints.

</domain>

<decisions>
## Implementation Decisions

### OIDC Verification Policy
- **D-01:** JWKS cache TTL is 1 hour (per REQ-5). Cache is per-process in-memory keyed by `(tenant_id, federation_config_id)`. No cross-pod sharing — each pod fetches independently. Acceptable for MVP beta.
- **D-02:** On unknown `kid` in an inbound ID token, the verifier triggers a single forced JWKS refetch (bypassing TTL) and retries verification once. If the `kid` is still missing, verification fails closed. Refetch is rate-limited to **one per 60 seconds per config** to prevent amplification under signature-spray attacks.
- **D-03:** When the IdP JWKS endpoint is unreachable and the cache is **stale** (past TTL), serve the last-known-good JWKS for up to **24 hours** past TTL with a `warn!` log. Fail closed only when no cached keys exist at all (cold start + IdP unreachable). Stale-while-revalidate semantics.
- **D-04:** Algorithm pinning is **per-config**. Add a new column `allowed_algorithms: Vec<String>` to `federation_config` (schema migration). Default for new OIDC configs is `["RS256"]`. The verifier rejects any token signed with an algorithm not in the list. The string `"none"` is **hardcoded-rejected** at the verifier regardless of column contents — the column cannot be used to opt back into `none`.
- **D-05:** Standard claims hardening: `iss` is REQUIRED and must equal the IdP's `issuer` from the discovery document. `exp` / `iat` are validated against `now ± 60s` clock skew (per REQ-5). `aud` must contain the federation `client_id`. `nonce` must equal the value the relying party originally bound to the state.

### SAML Signature Verification & Replay
- **D-06:** Enable the `samael` crate's `xmlsec` feature (currently disabled via `default-features = false`). This pulls runtime deps `libxml2` and `libxmlsec1` into the server Docker image — `docker/Dockerfile.server` must be updated to `apt-get install libxml2 libxmlsec1`.
- **D-07:** IdP signing certificate is **persisted** on the federation config row, not refetched per login. Add column `idp_signing_cert_pem: Option<String>` to `federation_config`. Admin pastes it during config creation, or (optionally, future improvement) it is auto-extracted from the IdP metadata XML when the admin saves the metadata URL.
- **D-08:** SAML responses must be signed at the **Response level** or the **Assertion level** (samael xmlsec covers both). Reject responses lacking a `<ds:Signature>` element when the federation config has a non-null `idp_signing_cert_pem`. A null cert means "config not finished" → fail closed.
- **D-09:** Replay protection via a new SurrealDB table `saml_assertion_replay` with fields `{ tenant_id, assertion_id, expires_at }` and a uniqueness constraint on `(tenant_id, assertion_id)`. The ACS handler INSERTs the row inside the same transaction as the rest of the assertion processing; a duplicate-key error → 401 with reason "assertion replay". A periodic background job (e.g., daily) deletes rows where `expires_at < now`.

### Federation Client Secret Encryption
- **D-10:** New dedicated environment variable `AXIAM_FEDERATION_ENCRYPTION_KEY` carries a 32-byte key (base64-encoded). Loaded once at server startup, mirroring the `mfa_encryption_key` loading pattern in `axiam-auth/src/config.rs`. Distinct from MFA and PKI keys — separate blast radius.
- **D-11:** Storage uses **three separate columns** on `federation_config`:
  - `client_secret_ciphertext: Option<String>` — base64 AES-256-GCM ciphertext (no associated data; tag appended).
  - `client_secret_nonce: Option<String>` — base64 12-byte nonce.
  - `client_secret_key_version: Option<i64>` — integer pointer to the active key. Starts at `1`.
  Schema migration ADDs the three columns. The legacy `client_secret: String` column stays during the transition (will be nulled-out post-backfill). A later phase / followup may DROP it.
- **D-12:** **Startup migration heuristic:** on server boot, scan `federation_config` rows. For each row where `client_secret_ciphertext IS NULL` AND legacy `client_secret IS NOT NULL`, the server encrypts the plaintext into the new columns, sets `client_secret_key_version = 1`, and clears (`NULL`) the legacy `client_secret`. Idempotent — re-running the boot does nothing on already-migrated rows. Each migration emits an audit log entry (`event: federation_secret_migrated`).
- **D-13:** Future key rotation writes new ciphertext with `key_version = 2` and a second env var `AXIAM_FEDERATION_ENCRYPTION_KEY_V2`. The decrypt path selects the key by `key_version`. Rotation itself is OUT OF SCOPE for Phase 4 — only the data model that supports it is delivered now.

### Session & Refresh-Token Invalidation
- **D-14:** Add **new authenticated** endpoint `POST /api/v1/auth/password/change` accepting `{ current_password: String, new_password: String }`. Self-service, requires an active session (JWT cookie). Verifies `current_password` via Argon2id, validates `new_password` against the existing password policy, then UPDATEs the user's password hash. RBAC: any authenticated user on their own account (no permission required — implicit self-service like the `/users/{own_id}` profile endpoint).
- **D-15:** **Invalidation scope on password change:** all of the user's sessions/refresh tokens are revoked EXCEPT the one that issued the change request. Requires a new service method `revoke_all_sessions_except(tenant_id, user_id, current_session_id)` on top of the existing `revoke_all_sessions`. The session_id comes from the `AccessTokenClaims.jti`-linked session row (verify the link mechanism during planning).
- **D-16:** **Invalidation scope on password reset confirm:** all of the user's sessions die — caller is unauthenticated mid-reset, so there is no "current session" to preserve. Wire `AuthService::revoke_all_sessions(tenant_id, user_id)` into `PasswordResetService::confirm_reset` right after the password hash is updated, replacing the `TODO(T19)` at `crates/axiam-auth/src/password_reset.rs:190`.
- **D-17:** **Invalidation scope on MFA reset:** unchanged from Phase 3 — `AuthService::reset_mfa` already calls `invalidate_user_sessions`. Restate explicitly in tests; no code change.
- **D-18:** **Refresh-token revocation cascades from session invalidation.** The session row owns the refresh-token hash; `session_repo.invalidate_user_sessions` is the single chokepoint and also marks/deletes refresh tokens. The planner must verify this is what the current `invalidate_user_sessions` implementation does — if not, fix it as part of this phase rather than introducing a parallel sweep path.

### Service-Account Token Discrimination
- **D-19:** Distinct OAuth2 `aud` (audience) values discriminate user JWTs from service-account JWTs:
  - `axiam:user` — issued by the user-login flow (`/auth/login` and refresh).
  - `axiam:m2m` — issued by the OAuth2 Client Credentials flow.
  Both flows must SET the new `aud` claim. The JWT extractor MUST validate `aud` against an expected value per route group (REST handlers expect `axiam:user`; service-mesh gRPC handlers may accept either or only `axiam:m2m`).
- **D-20:** Existing in-flight tokens at deploy time (issued before this change) will have no `aud` claim. The verifier treats absent `aud` as `axiam:user` for backward compatibility — for **15 minutes** (= max access-token lifetime). After that window, refresh-issued tokens always set `aud` explicitly, and the back-compat branch can be tightened in a followup.
- **D-21:** The new `aud` claim is added to `AccessTokenClaims` in `axiam-auth/src/token.rs`. Both `issue_access_token` (user flow) and `issue_client_credentials_token` (M2M flow) set it. `decode_access_token` validates it via `jsonwebtoken::Validation::set_audience(&["axiam:user", "axiam:m2m"])` to accept both, and the caller (extractor) narrows to the specific expected value.

### First-Time SSO Endpoints
- **D-22:** Add **new public** endpoints under `/api/v1/auth/federation/...`:
  - `POST /api/v1/auth/federation/oidc/start` — body `{ federation_config_id, redirect_uri }`. Returns the IdP authorize URL plus a server-generated `state` and `nonce`. Server stores `(state, nonce, config_id, expires_at)` for callback correlation.
  - `POST /api/v1/auth/federation/oidc/callback` — body `{ state, code }`. Server looks up the stored state, performs the verified OIDC callback flow (D-01..D-05), provisions or links the user, and issues local JWT cookies (same as `/auth/login`).
  - `POST /api/v1/auth/federation/saml/login` — initiates the SAML AuthnRequest. Returns the POST binding payload (or a redirect URL for HTTP-Redirect binding).
  - `POST /api/v1/auth/federation/saml/acs` — the SAML ACS endpoint. Performs sig verification (D-06..D-09), provisions/links the user, issues local JWT cookies.
  All four are added to the `PUBLIC_ALLOWLIST` (Phase 3 D-04 extends).
- **D-23:** Existing authenticated `/api/v1/federation-configs/.../oidc/authorize` and friends remain for the **link-account** flow (already-logged-in user attaches a federation identity). Clear separation: `/auth/federation/*` = first-time login, `/federation/*` = link-account.
- **D-24:** State/nonce storage for first-time SSO uses a new SurrealDB table `federation_login_state` with TTL (`expires_at`, typically 10 minutes). One row per pending login attempt. Cleanup on consumption + periodic background sweep (same job as SAML replay cleanup, D-09).

### Claude's Discretion
- Exact JWKS cache crate (custom HashMap-with-Mutex vs `moka::future::Cache`)
- AES-256-GCM crate (likely `aes-gcm` consistent with MFA path) and nonce-generation source
- Whether `revoke_all_sessions_except` lives on `SessionRepository` (DB-level filter) or in `AuthService` (fetch-then-filter-then-invalidate). Prefer DB-level if a single SurrealQL DELETE/UPDATE expresses it.
- Audience check enforcement granularity per route (one global expected aud for the REST extractor, or per-handler narrowing)
- Whether the first-time SSO endpoints return tokens in JSON body (legacy shape) or only cookies (Phase 1 D-13 shape) — recommend cookies-only for consistency
- Exact background job mechanism for replay/state cleanup (cron-like loop, AMQP scheduled message, or DB-side TTL if SurrealDB supports it)
- Frontend changes for first-time SSO: a "Continue with SSO" button on the login page (minimal scope — defer the full UI to a later phase if needed)
- Whether to also revoke OAuth2 authorization codes / device codes on password change (probably yes for completeness, but not strictly REQ-7)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Security Requirements & Architecture
- `claude_dev/design-document.md` — Master architecture document; federation, session management, encryption-at-rest sections
- `.planning/REQUIREMENTS.md` §REQ-5 — Federation Token Verification acceptance criteria (10 items)
- `.planning/REQUIREMENTS.md` §REQ-7 — Session Security acceptance criteria (4 items)
- `.planning/ROADMAP.md` Phase 4 — Scope definition and success criteria

### Federation (current implementation, partly stubbed)
- `crates/axiam-federation/src/oidc.rs` — `OidcFederationService`, ID-token claim decoding without signature verification (TODO T19.6 at line 285), exchange_code, provision_or_link_user
- `crates/axiam-federation/src/saml.rs` — `SamlFederationService`, ACS handler, condition validation, missing XML signature verification (TODO T19.7 at line 354)
- `crates/axiam-federation/src/error.rs` — `FederationError` variants
- `crates/axiam-federation/src/lib.rs` — `validate_metadata_url` helper, public API
- `crates/axiam-api-rest/src/handlers/federation.rs` — REST handlers; OIDC authorize/callback at lines 413/470, SAML at 646/696/752 — all currently behind `AuthenticatedUser`
- `crates/axiam-api-rest/src/server.rs` — Federation route registration (lines 465–527); `PUBLIC_ALLOWLIST` will be extended for the new `/auth/federation/*` paths

### Token & Session Plumbing
- `crates/axiam-auth/src/token.rs` — `AccessTokenClaims` (no `aud` today, no `sub_kind`); `issue_access_token` (line 43), `issue_client_credentials_token` (line 81), `decode_access_token` (line 195)
- `crates/axiam-auth/src/service.rs` — `AuthService::revoke_all_sessions` (line 499), `reset_mfa` (line 548), session/refresh issuance (lines 425–500). NEW: needs `change_password` and `revoke_all_sessions_except`
- `crates/axiam-auth/src/password_reset.rs` — `PasswordResetService::confirm_reset`; TODO at line 190 ("invalidate all active sessions for the user") is the wiring target
- `crates/axiam-api-rest/src/handlers/password_reset.rs` — Existing public reset endpoints
- `crates/axiam-api-rest/src/handlers/auth.rs` — Login/refresh/logout handlers; new `change_password` handler lives here
- `crates/axiam-api-rest/src/extractors/auth.rs` — JWT cookie extractor; will validate the new `aud` claim

### Encryption Patterns to Mirror
- `crates/axiam-auth/src/config.rs` line 31 — `mfa_encryption_key: Option<[u8; 32]>` loading pattern; replicate for `federation_encryption_key`
- `crates/axiam-auth/src/totp.rs` — AES-256-GCM `encrypt_secret`/`decrypt_secret` helpers; reusable or model
- `crates/axiam-pki/src/ca.rs` lines 25, 84 — Another encryption-at-rest reference (CA private keys)

### Database Schema
- `crates/axiam-db/src/schema.rs` line 362 — Current plaintext `client_secret` definition; migration replaces this with three new columns
- `crates/axiam-db/src/repository/` — Federation config + session repositories
- `crates/axiam-core/src/models/federation.rs` — `FederationConfig` model; needs the three new ciphertext fields, `allowed_algorithms`, `idp_signing_cert_pem`

### Library Documentation
- `samael` crate `xmlsec` feature — https://crates.io/crates/samael; enabling adds `libxml2` + `libxmlsec1` system deps
- `jsonwebtoken` crate `Validation` API — for `aud` and algorithm enforcement
- `aes-gcm` crate — already in workspace transitively (via MFA path)

### Codebase Maps
- `.planning/codebase/ARCHITECTURE.md` — Crate dependency graph
- `.planning/codebase/CONVENTIONS.md` — Naming/middleware patterns
- `.planning/codebase/STACK.md` — Tech-stack inventory
- `.planning/codebase/CONCERNS.md` — Known issues / debt

### Prior Phase Context
- `.planning/phases/01-cookie-based-authentication/01-CONTEXT.md` — Cookie auth, CSRF, JWT cookie config (D-05..D-15)
- `.planning/phases/02-security-headers-rate-limiting/02-CONTEXT.md` — Rate limiting (applies to new password-change and federation endpoints), security headers
- `.planning/phases/03-rbac-enforcement/03-CONTEXT.md` — `PUBLIC_ALLOWLIST` (D-04) and self-service ownership pattern (D-13..D-14)

### Docker / Deployment
- `docker/Dockerfile.server` line 82 — Runtime apt-get; will add `libxml2 libxmlsec1`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `OidcFederationService::decode_id_token_claims` (oidc.rs:404) — Already extracts claims; rebuild around it with signature verification + iss + alg pinning
- SAML condition validator (saml.rs:382–412) — NotBefore / NotOnOrAfter / Audience checks already correct; signature verification slots in just before this block
- `AuthService::revoke_all_sessions` (service.rs:499) — Ready for password-reset and password-change wiring
- `AuthService::reset_mfa` (service.rs:548) — Reference for the "invalidate sessions after auth-state change" pattern
- AES-256-GCM helpers in `totp.rs` — Same primitive needed for federation secrets
- `AccessTokenClaims` (token.rs:17) — Add `aud` field; `jsonwebtoken::Validation` supports audience enforcement out of the box
- `AuthenticatedUser` extractor — Already provides `(user_id, tenant_id, org_id, session_id)` — verify it carries `session_id` for D-15 `revoke_all_sessions_except`
- `AxiamError` ResponseError mapping — 401/403/422 already wired; new error variants (replay detected, invalid sig, audience mismatch) reuse this

### Established Patterns
- Actix-Web middleware via `.wrap()` in `server.rs`
- Public allowlist extension via the `PUBLIC_ALLOWLIST` constant (Phase 3 pattern)
- Repository trait pattern: data access through `web::Data<SurrealXxxRepository<C>>` injected as app data
- AuthConfig env-var loading: 32-byte keys via base64 → `[u8; 32]`
- Schema migrations: SurrealDB `DEFINE FIELD ... TYPE option<string>` for new nullable columns; new tables get `DEFINE TABLE ... TYPE NORMAL SCHEMAFULL` followed by `DEFINE FIELD` and `DEFINE INDEX` statements
- Background jobs are not yet a project-wide pattern — Phase 4 introduces the first (replay + state cleanup). Planner should propose a uniform mechanism (likely a tokio task spawned at startup) and document it

### Integration Points
- `crates/axiam-server/src/main.rs` — Loads new `AXIAM_FEDERATION_ENCRYPTION_KEY` env, kicks off startup migration of plaintext `client_secret` rows, spawns the federation cleanup task
- `crates/axiam-api-rest/src/server.rs` — Registers four new `/auth/federation/*` routes, registers `/auth/password/change`, extends `PUBLIC_ALLOWLIST` for the federation endpoints
- `crates/axiam-db/src/schema.rs` — Migration adds `allowed_algorithms`, `idp_signing_cert_pem`, `client_secret_ciphertext`, `client_secret_nonce`, `client_secret_key_version` to `federation_config`; creates `saml_assertion_replay` and `federation_login_state` tables
- `crates/axiam-api-rest/src/extractors/auth.rs` — JWT decoder validates `aud` against expected value with the 15-minute backward-compat branch
- `crates/axiam-api-grpc/` — gRPC handlers may need to accept `axiam:m2m` audience (verify during planning)
- `docker/Dockerfile.server` — Add `libxml2 libxmlsec1` to the runtime stage

</code_context>

<specifics>
## Specific Ideas

- The user explicitly preferred OAuth2 `aud` over a new `sub_kind` claim for service-account discrimination — keeps the JWT shape standards-compliant.
- The user preferred separate ciphertext columns over a versioned string envelope, **and** prefers the startup migration to run automatically rather than requiring an admin step. The migration's detection heuristic is "ciphertext column NULL while legacy column non-NULL" — not a string prefix check.
- The user accepted the `samael` `xmlsec` feature option even though it adds two C library dependencies (`libxml2`, `libxmlsec1`) to the Docker image. The trade-off is treated as worthwhile because reimplementing XML c14n by hand is a known foot-gun.
- Stale-while-revalidate on JWKS outage was preferred over fail-closed — operational availability wins over absolute freshness within a bounded staleness window.

</specifics>

<deferred>
## Deferred Ideas

- **Federation key rotation flow** — The data model supports `client_secret_key_version`, but the actual rotation procedure (generate v2 key, rewrap all rows, retire v1) is not delivered in Phase 4. Belongs in a future operations / key-management phase.
- **Drop legacy `client_secret` column** — After backfill ships and all rows are confirmed migrated, a later migration can DROP the legacy column. Not in Phase 4 scope.
- **Audience tightening** — The 15-minute backward-compat window for tokens lacking an `aud` claim becomes a hard reject in a follow-up. File as a Phase 19/followup task.
- **Federation metadata auto-refresh** — Periodic metadata refresh + auto-extract of `idp_signing_cert_pem` from IdP metadata. Phase 4 ships with admin-pasted certs; auto-refresh is a future enhancement.
- **"My sessions" UI** — Users seeing and revoking individual sessions (D-SESS-3 option 3) is a UX improvement that belongs in a dedicated UI phase.
- **`POST /users/{own_id}/sessions/revoke-all`** admin endpoint — Force-revoke a target user's sessions as an admin action; not strictly REQ-7 but a natural extension.

### Reviewed Todos (not folded)
None — no pending todos matched Phase 4 via `gsd-sdk todo.match-phase`.

</deferred>

---

*Phase: 04-federation-verification-session-security*
*Context gathered: 2026-05-12*
