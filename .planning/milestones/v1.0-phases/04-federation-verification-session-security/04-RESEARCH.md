# Phase 4 Research: Federation Verification & Session Security

**Date:** 2026-05-12
**Researcher:** gsd-phase-researcher
**Source CONTEXT.md decisions covered:** D-01..D-24

## Summary

Every locked decision in 04-CONTEXT.md is implementable with the workspace's current
dependency set plus exactly one feature-flag flip (`samael/xmlsec`) and one workspace
dependency add (`libxml = "=0.3.3"` is pulled in transitively by samael's xmlsec feature
— no direct add needed). `jsonwebtoken = "10"` already exposes `Jwk`, `JwkSet`,
`DecodingKey::from_jwk`, `decode_header`, `Validation::set_audience`, and a tunable
`leeway` (default 60s — exactly REQ-5's clock-skew tolerance), so OIDC verification per
D-01..D-05 is a thin wrapper, not a new library. The TOTP AES-256-GCM helpers in
`crates/axiam-auth/src/totp.rs` are **already domain-agnostic** (`encrypt_secret(&[u8;
32], &[u8]) -> base64 String`), so federation client-secret encryption (D-10..D-13)
just needs to be re-exported under a non-TOTP-specific name and given its own env-var
loader.

**Top risks for the planner:**

1. **samael `xmlsec` adds an OpenSSL build-time requirement** that is **already
   satisfied** transitively (samael 0.0.19 unconditionally depends on `openssl`,
   `openssl-sys`, `bindgen`, `pkg-config` — see Cargo.lock:6005–6029). The only new
   runtime burden is `libxml2` + `libxmlsec1` shared libs in Stage 2 of the Dockerfile,
   plus `libxml2-dev`, `libxmlsec1-dev`, `clang` (for bindgen) in Stage 1.
2. **`AuthenticatedUser` does NOT carry `session_id` today** (see
   `crates/axiam-api-rest/src/extractors/auth.rs:25–30`). D-15
   `revoke_all_sessions_except` cannot be implemented without first plumbing
   `jti → session_id` either via a new claim or a session lookup. **The cleanest fix is
   to populate `session.id` into the JWT's `jti` at issuance** (currently `jti` is a
   random UUID per `token::issue_access_token` at token.rs:64). This is a real
   design-shape change the planner must call out.
3. **OAuth2 refresh tokens live in a SEPARATE table** (`oauth2_refresh_token` via
   `RefreshTokenRepository::revoke` at oauth2/token.rs:546) from session refresh tokens
   (the `session` table — session.rs:190 `invalidate_user_sessions`). D-18 ("single
   chokepoint") is **NOT TRUE TODAY** — there are two chokepoints. Password
   change/reset must hit both, or only session-flow tokens get revoked.

---

## Topic 1 — OIDC ID token signature verification

### Library choice: `jsonwebtoken = "10"` is sufficient — do NOT pull `openidconnect`

Verified by reading `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/jsonwebtoken-10.3.0/`:

- **JWKS types:** `jsonwebtoken::jwk::Jwk` (struct at jwk.rs:422), `JwkSet` (jwk.rs:552).
  A standard JWKS endpoint response (`{"keys": [...]}`) deserializes directly into
  `JwkSet` via `serde_json::from_str`.
- **Key construction:** `DecodingKey::from_jwk(&Jwk)` exists at decoding.rs:210. It
  handles RSA (via `n`/`e` components), EC, OctetKeyPair (Ed25519/Ed448), and HMAC. So
  any IdP that publishes any of those algorithms is supported with zero extra crates.
- **Header inspection (for `kid` and `alg`):** `pub fn decode_header(token) -> Result<Header>`
  is publicly re-exported at jsonwebtoken/src/lib.rs:9. Use this BEFORE calling
  `decode`, to (a) read `header.kid` to pick the JWK and (b) confirm `header.alg` is in
  the per-config allow-list.
- **Validation:** `Validation` struct supports `algorithms: Vec<Algorithm>` (algorithm
  pinning — D-04), `iss: Option<HashSet<String>>` via `set_issuer`, `aud:
  Option<HashSet<String>>` via `set_audience`, `validate_exp: bool` (default true),
  `leeway: u64` (default **60** — already matches REQ-5 clock skew). See validation.rs:50–166.

**Recommendation:** No `openidconnect` crate, no new HTTP client, no new key library.

### HTTP client for JWKS fetch

`reqwest::Client` is already injected into `OidcFederationService` (oidc.rs:79,93). Reuse
the same client. No new dependency.

### JWKS cache shape

**Recommendation:** A custom `Arc<RwLock<HashMap<(Uuid, Uuid), CacheEntry>>>` —
**NOT** `moka`.

Rationale:
- `moka` is currently a transitive-only dep (Cargo.lock:4019, pulled in via
  `hickory-resolver`). Promoting it to a direct dep adds compile time without buying
  much: expected entry count is `#tenants × #federation_configs`, typically in the tens
  to low hundreds for an IAM beta. A `RwLock<HashMap>` is sufficient and simpler.
- D-01 (1h TTL), D-02 (one forced refetch per unknown kid + 60s rate limit), and D-03
  (serve last-known-good up to 24h past TTL) all require per-entry timestamps and
  semantic logic that moka's plain TTL eviction would not give us anyway.

**Data shape supporting D-01..D-03:**

```rust
struct JwksCacheEntry {
    keys: jsonwebtoken::jwk::JwkSet,
    fetched_at: chrono::DateTime<Utc>,   // for 1h TTL (D-01)
    last_refetch_attempt: Option<DateTime<Utc>>, // for 60s rate-limit on forced refetch (D-02)
}
// key = (tenant_id, federation_config_id)
type JwksCache = Arc<tokio::sync::RwLock<HashMap<(Uuid, Uuid), JwksCacheEntry>>>;
```

Lookup flow:
1. If entry exists and `fetched_at + 1h > now` → return cached keys.
2. If entry stale (TTL expired) → try fetch; on success update `fetched_at`; on failure
   AND `fetched_at + 24h > now` → return cached keys with `warn!` log (D-03 stale-while-revalidate).
3. On unknown `kid` after step 1/2 → if `last_refetch_attempt + 60s < now` → forced
   refetch, retry once; update `last_refetch_attempt` regardless of outcome.

Use `tokio::sync::RwLock` (not `std::sync::RwLock`) because the cache is touched from
async handler contexts.

### Algorithm pinning (D-04)

```rust
// Step 1: pre-validate the JOSE header against the per-config allowlist
let header = jsonwebtoken::decode_header(id_token)?;
let alg = header.alg; // jsonwebtoken::Algorithm enum

// HARDCODED reject "none" — never decode an alg=none token
// (jsonwebtoken::Algorithm does NOT have a "None" variant — alg=none tokens are
// rejected by decode_header before they even reach this point. Confirmed by reading
// validation.rs — there is no Algorithm::None in the enum. Defense-in-depth: do not
// trust this; still pre-check the raw header.)
if matches!(alg, /* nothing matches None — but check raw `alg` field on header */) {
    return Err(...);
}

// Map config.allowed_algorithms (Vec<String>) → Vec<jsonwebtoken::Algorithm>
let allowed: Vec<Algorithm> = config.allowed_algorithms.iter()
    .filter_map(|s| match s.as_str() {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "EdDSA" => Some(Algorithm::EdDSA),
        // PS256/PS384/PS512 for RSA-PSS
        _ => None, // drops "none" silently and any unknown string
    })
    .collect();
if !allowed.contains(&alg) {
    return Err(FederationError::IdTokenValidationFailed("disallowed algorithm".into()));
}

let mut validation = Validation::new(alg);   // pinned alg
validation.algorithms = allowed.clone();      // multi-alg-allow list (D-04)
validation.set_issuer(&[&discovery.issuer]);  // D-05
validation.set_audience(&[&config.client_id]); // D-05
validation.leeway = 60;                       // REQ-5 clock skew
validation.set_required_spec_claims(&["iss", "aud", "exp", "iat"]); // D-05
```

**Critical:** The raw `alg` string in the JWT header MUST be inspected and rejected
when equal to `"none"` (case-insensitive) BEFORE calling `decode_header` — because if
`decode_header` succeeds for a parsed-but-unsigned token (it does not in jsonwebtoken
10; alg="none" maps to no `Algorithm` variant and returns `InvalidAlgorithmName`),
we want defense in depth. Lift the raw header JSON: `serde_json::from_slice(&base64_decode(first_part))`
and assert `header_json["alg"] != "none"`. This is the planner's belt-and-suspenders
addition.

### Claim validation (D-05)

- `iss`: covered by `validation.set_issuer`.
- `aud`: covered by `validation.set_audience(&[&config.client_id])`.
- `exp`/`iat`: covered by `validate_exp = true` (default) + `leeway = 60`.
- `nonce`: jsonwebtoken does NOT validate `nonce` — application-level check.
  After `decode`, compare `claims.nonce` to the stored value from `federation_login_state`
  (D-24). Existing code at oidc.rs:298–308 already does this comparison — keep it,
  source-of-truth-shift the `expected_nonce` from caller-passed argument to a DB
  lookup keyed by `state`.

---

## Topic 2 — SAML signature verification via samael `xmlsec`

### Current samael configuration

`crates/axiam-federation/Cargo.toml:23`: `samael = { workspace = true }`, with the
workspace pinning at `Cargo.toml:104`:

```toml
samael = { version = "0.0.19", default-features = false }
```

The samael upstream Cargo.toml declares (verified at
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/samael-0.0.19/Cargo.toml:108–114`):

```toml
[features]
default = ["xmlsec"]
xmlsec = [
    "libc",
    "lazy_static",
    "libxml",      # <-- pinned to "=0.3.3"
]
```

So enabling `xmlsec` activates three optional Rust deps: `libc`, `lazy_static`, and
`libxml = "=0.3.3"`. The `libxml` crate links against libxml2 + libxmlsec1 (verified by
the C-FFI references in `samael/src/xmlsec/`).

**Rust-side cost:** three small optional crates and a `build.rs` invocation of
`bindgen` (`bindgen = "0.71"`). Build-time increase ~10–20s on a cold cache.

**C-side cost (build stage of Dockerfile.server):**
- `libxml2-dev`
- `libxmlsec1-dev` (provides libxmlsec1, libxmlsec1-openssl, libxmlsec1-gnutls — we use
  the openssl backend)
- `clang` (for bindgen)
- `pkg-config` (already used elsewhere — `pkg-config` is a build-dep of samael per
  Cargo.lock:6029)

**C-side cost (runtime stage of Dockerfile.server):**
- `libxml2` (shared lib)
- `libxmlsec1`, `libxmlsec1-openssl`

### Public API for signature verification

Verified by reading `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/samael-0.0.19/src/crypto.rs:89–109`:

```rust
#[cfg(feature = "xmlsec")]
pub fn verify_signed_xml<Bytes: AsRef<[u8]>>(
    xml: Bytes,
    x509_cert_der: &[u8],
    id_attribute: Option<&str>,
) -> Result<(), Error>
```

**Important: the parameter name says `x509_cert_der`, but the implementation calls
`XmlSecKey::from_memory(x509_cert_der, XmlSecKeyFormat::CertDer)` at crypto.rs:98.** So
the FUNCTION strictly accepts DER. **But** `XmlSecKeyFormat` (verified at
`samael/src/xmlsec/keys.rs:18–27`) has variants:

```rust
pub enum XmlSecKeyFormat {
    Pem = ...,
    Pkcs8Pem = ...,
    CertPem = ...,    // <-- PEM cert
    CertDer = ...,    // <-- DER cert (what verify_signed_xml uses)
    ...
}
```

So either:
- **(A)** D-07 stores PEM, then on each verification we strip headers/decode base64 →
  feed DER to `verify_signed_xml`. Easy with `rustls-pemfile` or `x509-parser` (both
  already in the workspace).
- **(B)** Skip `verify_signed_xml` and reach into the lower-level `XmlSecKey::from_memory(pem,
  CertPem)` + `XmlSecSignatureContext` directly.

**Recommendation: option (A)** — store PEM (per D-07), parse to DER at verify time.
PEM is easier for admins to paste. `x509-parser` is already a workspace dep
(Cargo.toml:100). For minimum dep churn, use `base64::engine::general_purpose::STANDARD.decode`
on the inner contents after stripping `-----BEGIN CERTIFICATE-----` markers.

### Response-level vs Assertion-level signatures

The `verify_signed_xml` function takes the **entire XML document** as input and
verifies **all** `<ds:Signature>` elements within it (verified by reading
`find_signature_nodes` at samael/src/crypto.rs:152). So a single call covers BOTH
Response-level and Assertion-level signatures, which satisfies D-08.

The `id_attribute: Option<&str>` argument tells xmlsec how to follow `<Reference URI="#_abc123"/>`
within the signature back to the element being signed. SAML uses the attribute `ID`
(uppercase), so pass `Some("ID")`. The function FAILS if there is NO signature
present, which gives us D-08's "reject when no `<ds:Signature>` and config has cert" for free.

### IdP cert storage / parsing (D-07)

Cleanest pattern:

```rust
// PEM → DER. Use only stdlib + base64 (already in workspace).
fn pem_to_der(pem: &str) -> Result<Vec<u8>, FederationError> {
    let body = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| FederationError::SamlResponseFailed(format!("bad cert PEM: {e}")))
}
```

`x509-parser::parse_x509_certificate` can additionally validate that the bytes form a
real cert before storage in `idp_signing_cert_pem` (admin UX win — reject garbage at
upload time).

### Replay table SurrealDB definition (D-09)

Following the existing migration pattern at schema.rs:18–24 (use `IF NOT EXISTS` for
idempotency on every statement):

```sql
DEFINE TABLE IF NOT EXISTS saml_assertion_replay SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS tenant_id      ON TABLE saml_assertion_replay TYPE string;
DEFINE FIELD IF NOT EXISTS assertion_id   ON TABLE saml_assertion_replay TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at     ON TABLE saml_assertion_replay TYPE datetime;
DEFINE FIELD IF NOT EXISTS created_at     ON TABLE saml_assertion_replay TYPE datetime
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_replay_uniq ON TABLE saml_assertion_replay
    COLUMNS tenant_id, assertion_id UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_replay_expires_at ON TABLE saml_assertion_replay
    COLUMNS expires_at;  -- supports the background sweep
```

SurrealDB v3 has **no built-in TTL field eviction** (verified absent from
schema.rs — every cleanup is `cleanup_expired` style, e.g. session.rs:201). So D-09's
"periodic background job deletes rows where expires_at < now" is the correct path.
Background job mechanism: see Topic 7.

Duplicate-key detection: SurrealDB returns an error when an INSERT violates a UNIQUE
INDEX. Error message contains `"already exists"` or `"unique"` (project's existing
session.rs handler relies on a similar dedup pattern). Match on the error string —
this is the same approach used elsewhere in axiam-db.

### Dockerfile delta

**Build stage** (after line 16 in Dockerfile.server):
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler \
        libxml2-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        clang \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*
```

**Runtime stage** (after line 82):
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        libxml2 \
        libxmlsec1 \
        libxmlsec1-openssl \
        curl \
    && rm -rf /var/lib/apt/lists/*
```

No `xmlsec1` config dir setup required — `xmlsec1` initializes from defaults; the
samael crate calls `xmlsec::XmlSecContext::new()` lazily.

---

## Topic 3 — Federation client secret encryption (AES-256-GCM)

### Reusability of TOTP helpers — YES, but rename

Verified by reading `crates/axiam-auth/src/totp.rs:15–47`:

```rust
pub fn encrypt_secret(key: &[u8; 32], plaintext: &[u8]) -> Result<String, AuthError>
pub fn decrypt_secret(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, AuthError>
```

These take arbitrary `&[u8]` plaintext, return base64 of `nonce || ciphertext || tag`,
use `aes_gcm::aead::OsRng` for the 12-byte nonce. **Domain-neutral.** TOTP-specific
naming is the only thing tying them to TOTP.

**Recommendation:**

Create a new internal module `crates/axiam-auth/src/crypto.rs` with:

```rust
pub fn aes256gcm_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String, AuthError> { /* existing impl */ }
pub fn aes256gcm_decrypt(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>, AuthError> { /* existing impl */ }
```

Then `totp.rs` becomes thin wrappers calling `crypto::aes256gcm_encrypt`. Federation
calls them directly. No new crate, no new behaviour — pure code motion + visibility
flip from `pub(crate)` to `pub`. **Do NOT move them to axiam-core** — axiam-core has
no `aes_gcm` dep and adding one bloats the model crate.

### Env-var loader pattern

Mirror exactly the MFA pattern at main.rs:65–79:

```rust
if let Ok(hex) = std::env::var("AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY") {
    let bytes = hex::decode(&hex).expect(
        "AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY must be a 64-char hex string (32 bytes / 256 bits)",
    );
    let key: [u8; 32] = bytes
        .try_into()
        .expect("AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY must be exactly 32 bytes (256 bits)");
    config.auth.federation_encryption_key = Some(key);
    tracing::info!("Federation encryption key loaded");
} else {
    tracing::warn!(
        "AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY not set — \
         federation config creation/use will fail at runtime"
    );
}
```

Add `federation_encryption_key: Option<[u8; 32]>` to `AuthConfig` (config.rs:31)
with `#[serde(skip)]` (same as `mfa_encryption_key`). D-10 says distinct from MFA/PKI
— **confirmed**, the env var name `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` is wholly
distinct from `AXIAM__AUTH__MFA_ENCRYPTION_KEY` and `AXIAM__PKI__ENCRYPTION_KEY`
(main.rs:174). Operators rotate them independently.

**Absence behaviour:** When the env var is absent, the server starts but federation
config creation MUST fail (cannot encrypt) and existing federation config use MUST
fail (cannot decrypt). The MFA pattern uses `warn!` at startup and `AuthError::Crypto`
at use-time — mirror exactly. **Do NOT panic at startup** — a deployment may
legitimately not use federation.

### Startup backfill (D-12) location

Run in `crates/axiam-server/src/main.rs` immediately AFTER `DbManager::connect` (~main.rs:84)
and AFTER `run_migrations`, but BEFORE the HTTP/gRPC server `bind()` (so the migration
completes before any request can read a stale row).

Idempotency: each row's `client_secret_ciphertext IS NULL AND client_secret IS NOT NULL AND client_secret != ''`
predicate is self-clearing — once migrated, the row no longer matches the predicate.
Safe to re-run on every boot.

Per-row audit log (D-12): emit one `event: federation_secret_migrated` audit log entry
per row, using the existing `AuditLogRepository::create` path. This makes the migration
auditable after the fact.

**Pseudo-code:**

```rust
async fn migrate_plaintext_federation_secrets<C: Connection>(
    fed_repo: &SurrealFederationConfigRepository<C>,
    audit_repo: &SurrealAuditLogRepository<C>,
    key: &[u8; 32],
) -> Result<usize, AxiamError> {
    let rows = fed_repo.list_with_legacy_plaintext_secret().await?;  // NEW method
    let mut migrated = 0;
    for row in rows {
        let ct = crypto::aes256gcm_encrypt(key, row.client_secret.as_bytes())?;
        fed_repo.set_encrypted_secret(row.tenant_id, row.id, &ct, /*key_version=*/ 1).await?;
        audit_repo.create(/* event: "federation_secret_migrated", ... */).await?;
        migrated += 1;
    }
    Ok(migrated)
}
```

### Nonce source

`aes_gcm::aead::OsRng` — exactly as TOTP does at totp.rs:5,18. Per
`MEMORY.md` (aes_gcm v0.10), this is the project's established pattern. Do not
use `rand::rngs::OsRng` directly; the aes-gcm aliased version avoids `rand_core`
version-skew issues.

---

## Topic 4 — Session/refresh-token invalidation plumbing

### Single chokepoint? NO — there are TWO refresh-token systems.

Verified by reading:
- `crates/axiam-db/src/repository/session.rs:190`: `invalidate_user_sessions` —
  `DELETE session WHERE tenant_id = $tenant_id AND user_id = $user_id`.
  This is the **session-flow** refresh-token chokepoint: each `session` row owns
  exactly one refresh token via `token_hash` (model: `axiam-core::models::session::Session`).
- `crates/axiam-oauth2/src/token.rs:546`: `refresh_token_repo.revoke(tenant_id, &token_hash)` —
  this is a SEPARATE table `oauth2_refresh_token` (via `RefreshTokenRepository`), used
  by the OAuth2 `/oauth2/token` `refresh_token` grant flow. It is NOT touched by
  `session.invalidate_user_sessions`.

**Implication for D-18:**

For end-user password change, the user's REST-cookie sessions are revoked via
`session_repo.invalidate_user_sessions`. That correctly kills their `axiam_refresh`
cookie. **But** if the same user has obtained tokens via the OAuth2
authorization-code flow (e.g., a third-party app using the user's identity), those
`oauth2_refresh_token` rows are NOT killed.

**Planner decision needed (Claude's Discretion item):** Should D-14/D-16 revoke
OAuth2 refresh tokens too?

**Recommendation: YES.** The user's intent in "change my password" is "all credentials
issued under my identity become invalid." Add a new repo method
`RefreshTokenRepository::revoke_all_for_user(tenant_id, user_id)` and call it alongside
`session_repo.invalidate_user_sessions`. This is a 1-method add to
`crates/axiam-core/src/repository.rs` + 1 implementation in axiam-db.

Also: **authorization codes** (table `oauth2_authorization_code`) have a 10-min
lifetime (config.rs:18 `auth_code_lifetime_secs: 600`) — they don't survive
long enough to be a meaningful threat. Defer. **Device codes** similar. Document
these as "deferred" in the plan; mention them in tests.

### `revoke_all_sessions_except` (D-15) — DB-level feasibility

SurrealDB DELETE WHERE supports composite predicates. Verified syntactically valid
(matches existing patterns at session.rs:192):

```sql
DELETE session
WHERE tenant_id = $tenant_id
  AND user_id = $user_id
  AND id != type::record('session', $current_session_id)
```

(Per MEMORY.md: `type::thing()` is removed in v3, use `type::record('session', $id)`.)

**Recommendation:** DB-level. Add a new method:

```rust
// crates/axiam-core/src/repository.rs (trait)
async fn invalidate_user_sessions_except(
    &self, tenant_id: Uuid, user_id: Uuid, current_session_id: Uuid,
) -> AxiamResult<()>;
```

This avoids a fetch-then-filter-then-delete round trip, which would also race with
concurrent logins.

### Does `AuthenticatedUser` carry `session_id`? NO — this is a blocker for D-15

Verified by reading `crates/axiam-api-rest/src/extractors/auth.rs:25–30`:

```rust
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub claims: ValidatedClaims,
}
```

No `session_id`. The `claims.0.jti` is present (jti is set on every access token at
token.rs:64 — `Uuid::new_v4().to_string()`), **but `jti` is a random per-token UUID,
NOT the session ID.** There is no DB lookup from `jti → session_id` today.

**Three options for the planner:**

1. **Change `jti` to BE `session_id`.** Modify `AuthService::create_session_and_tokens`
   (service.rs:604) and `AuthService::refresh` (service.rs:469) to issue access tokens
   with `jti = session.id`. This is the cleanest design and costs ~3 lines of code. It
   does **not** weaken the JWT — `jti` is supposed to be unique-per-token but nothing
   in the JWT spec or the project requires it to be DIFFERENT from a session ID. (A
   session has 1 access token alive at a time; refresh creates a new session row → new
   jti.) Recommended.

2. Add a `session_id` claim to `AccessTokenClaims` (token.rs:17) alongside `jti`. More
   verbose, but explicit.

3. Index `session` by `jti` (currently sessions store `token_hash` of refresh, not
   `jti`). Most disruptive.

**Recommended: option 1.** Document it as a Phase 4 implementation detail in the plan.
After this change, `AuthenticatedUser` can extract `session_id = Uuid::parse_str(&claims.0.jti)?`
with no schema change.

### `change_password` mirrors the `users/{own_id}` pattern

Verified by reading `crates/axiam-api-rest/src/handlers/users.rs:186–209`:

The pattern is:
1. Extract `target_id = path.into_inner()`.
2. `if !is_own_resource(&user, target_id) { RequirePermission::new("users:update", ...).check(&user, authz).await?; }`
3. Service call.
4. Return body.

For `POST /api/v1/auth/password/change`, the path has NO `{user_id}` — the target IS
always the caller (`user.user_id`). So no `RequirePermission` check is needed at all;
the route is implicitly self-service.

**Recommended handler shape:**

```rust
pub async fn change_password<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let session_id = Uuid::parse_str(&user.claims.0.jti)
        .map_err(|_| AxiamError::AuthenticationFailed { reason: "invalid jti".into() })?;
    svc.change_password(
        user.tenant_id, user.user_id, session_id,
        &body.current_password, &body.new_password,
    ).await?;
    Ok(HttpResponse::NoContent().finish())
}
```

`AuthService::change_password` then:
1. Re-verifies `current_password` via `password::verify_password` (defense against
   session-hijack scenarios — even if attacker has the cookie, they can't pivot to
   change the password without the old one).
2. Calls `evaluate_password` against the tenant's password policy (same path
   `password_reset::confirm_reset` uses at password_reset.rs:160).
3. Updates `user.password_hash`.
4. Inserts a row into `password_history` (same as reset).
5. Calls `session_repo.invalidate_user_sessions_except(tenant_id, user_id, current_session_id)`.
6. Calls `refresh_token_repo.revoke_all_for_user(tenant_id, user_id)` (oauth2 path; see above).

---

## Topic 5 — Service-account `aud` claim discrimination

### Validation shape: accept both, narrow per-route

```rust
// In decode_access_token (token.rs:195) — accept BOTH at decode time
let mut validation = Validation::new(Algorithm::EdDSA);
validation.set_issuer(&[config.effective_issuer()]);
validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);
//   (do NOT require "aud" in required_spec_claims during the 15-min window)
validation.set_audience(&["axiam:user", "axiam:m2m"]);
//   (jsonwebtoken's validate_aud=true means missing aud is OK — it only checks
//    aud-membership when aud claim is PRESENT. Verified at validation.rs:70–73.)
```

But the per-route extractor must **narrow** further. Add a typed extractor variant:

```rust
pub struct AuthenticatedUser { /* existing fields */ }
pub struct AuthenticatedServiceAccount { /* same shape */ }

// In extract_user, after validate_access_token:
let aud = claims.aud.as_deref();
match aud {
    Some("axiam:user") | None => Ok(AuthenticatedUser { ... }),  // None = legacy
    Some("axiam:m2m") => Err(/* this extractor wanted user audience */),
    Some(other) => Err(/* unknown aud */),
}
```

`AuthenticatedServiceAccount` does the inverse. Both share the same parse logic — pull
that into a private helper.

### 15-minute backward-compat window (D-20)

**Cleanest implementation: a single config field, not scattered timestamps.**

Add to `AuthConfig`:

```rust
/// When true, accept access tokens lacking an `aud` claim as `axiam:user`.
/// Set to true on deploy of this phase; flip to false after 15 minutes
/// (= access_token_lifetime_secs). After flip, all in-flight tokens have
/// been re-issued via refresh and will carry the new aud.
pub allow_missing_aud_as_user: bool,  // env: AXIAM__AUTH__ALLOW_MISSING_AUD_AS_USER
```

Even simpler: a **single hard-coded deadline** based on deploy time, with no flag —
flip happens automatically after 15 minutes of process uptime. But that mixes concerns
(deploy clock != audience policy). **Recommendation: the config flag.** Operator can
flip to false on the next deploy. Mark it deprecated in code with a `#[deprecated]` doc
attribute pointing at the Phase 19/followup ticket.

### gRPC audience policy

Verified by reading `crates/axiam-api-grpc/src/services/token.rs:5,31,61`:

The gRPC services do NOT use the REST extractor. They call `axiam_auth::token::validate_access_token`
directly with the raw token from a Tonic request. The current code path has **no audience
check at all** — `validate_access_token` does not enforce `aud` today (token.rs:199–203).

**Recommendation:**
- REST extractor → expects `axiam:user` (or absent during back-compat window).
- gRPC AuthorizationService / TokenService → accepts BOTH `axiam:user` and `axiam:m2m`.
  Rationale: the gRPC authz endpoint is the service-mesh's call-time check — it's
  invoked both by user-facing services (on behalf of a user) and by M2M callers.
  Narrowing to only `axiam:m2m` would break the user-on-behalf-of pattern.

This means there is **no per-handler narrowing inside gRPC** for Phase 4 — just one
relaxed check. Document the choice and revisit if/when M2M-only gRPC endpoints emerge.

---

## Topic 6 — Public federation endpoints (first-time SSO)

### `PUBLIC_ALLOWLIST` extension

**Location:** the constant lives at `crates/axiam-api-rest/src/permissions.rs:179`
(not `server.rs` as the CONTEXT.md initially hinted — verified by grep). It is named
`PUBLIC_PATHS`, not `PUBLIC_ALLOWLIST`, and is consumed by `is_public_path` at
`crates/axiam-api-rest/src/middleware/authz.rs:38`.

**Lines that need to change** — add four entries between line 210 (current last
federation entry) and line 211:

```rust
    // Federation callback endpoints (unauthenticated — IdP redirects here)
    "/api/v1/federation/oidc/callback",
    "/api/v1/federation/saml/acs",
    "/api/v1/federation/saml/metadata",
+   // First-time SSO (Phase 4 D-22) — unauthenticated, distinct from
+   // /api/v1/federation/* link-account endpoints (which require auth).
+   "/api/v1/auth/federation/oidc/start",
+   "/api/v1/auth/federation/oidc/callback",
+   "/api/v1/auth/federation/saml/login",
+   "/api/v1/auth/federation/saml/acs",
```

Confirm test at `crates/axiam-api-rest/src/middleware/authz.rs:148–155` covers the new
paths.

### `federation_login_state` table (D-24)

```sql
DEFINE TABLE IF NOT EXISTS federation_login_state SCHEMAFULL;
DEFINE FIELD IF NOT EXISTS state ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS nonce ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS tenant_id ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS federation_config_id ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS redirect_uri ON TABLE federation_login_state TYPE string;
DEFINE FIELD IF NOT EXISTS expires_at ON TABLE federation_login_state TYPE datetime;
DEFINE FIELD IF NOT EXISTS created_at ON TABLE federation_login_state TYPE datetime
    DEFAULT time::now();
DEFINE INDEX IF NOT EXISTS idx_login_state_uniq ON TABLE federation_login_state
    COLUMNS state UNIQUE;
DEFINE INDEX IF NOT EXISTS idx_login_state_expires_at ON TABLE federation_login_state
    COLUMNS expires_at;
```

`state` is the lookup key (server-generated 256-bit random, base64url). TTL: 10 minutes
per D-24. Cleanup: same background job as `saml_assertion_replay` (Topic 7).

### Cookies-only response shape

Verified by reading `crates/axiam-api-rest/src/handlers/auth.rs:176–217`
(`cookie_response_from_output` helper):

The login handler returns:
- `Set-Cookie: axiam_access` (httpOnly Secure SameSite=Strict)
- `Set-Cookie: axiam_refresh` (httpOnly Secure SameSite=Strict Path=/api/v1/auth/refresh)
- `Set-Cookie: axiam_csrf` (readable by JS)
- JSON body: `LoginSuccessResponse { user, session_id, expires_in }` — but NO `access_token`,
  NO `refresh_token` in the body.

**Recommendation for first-time SSO callbacks (D-22 oidc/callback and saml/acs):**
**Reuse `cookie_response_from_output` verbatim.** Same response shape as `/auth/login`
for client consistency. The `oidc/start` and `saml/login` endpoints return JSON
(the IdP redirect URL or the POST form payload) — no cookies needed yet.

### Frontend changes — minimal

Per CONTEXT.md Claude's Discretion: a "Continue with SSO" button would be the minimal
scope. **Recommendation: defer the React UI to a later phase.** The Phase 4
deliverable is server-side only. Two reasons:
1. The success criterion in ROADMAP.md Phase 4 references no UI requirement.
2. A complete SSO UI needs: tenant selector, config picker per tenant, error display.
   These belong in a UI phase.

If a stub button is desired for end-to-end testability, it is one Storybook story and
two `axios` calls — about 30 LoC. Plan should include "Frontend: deferred" with one
sentence explaining why; tests cover the server flow with a mock IdP.

---

## Topic 7 — Background cleanup job mechanism

### Option scoring

| Option | Code | Reliability | Dep cost | Operability |
|--------|------|-------------|----------|-------------|
| 1. tokio task + `tokio::time::interval` | trivial | per-pod; restart-safe (idempotent SQL) | ZERO — tokio already used (verified at main.rs:266,285,303) | runs in-process, no external scheduler |
| 2. AMQP scheduled msg via Lapin | medium | depends on RabbitMQ scheduled-message plugin or x-delayed-message | RabbitMQ plugin install | adds RabbitMQ as a hard dep for cleanup |
| 3. SurrealDB-side TTL | n/a | — | — | NOT SUPPORTED in SurrealDB v3 (verified: no TTL syntax in schema.rs, none of the existing tables use it; instead `cleanup_expired` SQL methods exist) |

**Recommendation: Option 1.**

### Module layout

```
crates/axiam-server/src/
├── main.rs              # spawn the cleanup task after bind
└── cleanup.rs           # NEW
```

`cleanup.rs`:

```rust
//! Periodic background cleanup of expired federation state rows.
//!
//! Runs as a tokio task spawned by main.rs. Sweeps two tables every
//! `interval_secs` (default 300 = 5 min):
//!   - saml_assertion_replay  WHERE expires_at < time::now()
//!   - federation_login_state WHERE expires_at < time::now()
//!
//! Graceful shutdown via a `tokio::sync::watch::Receiver<bool>` shutdown signal.

pub struct CleanupTask<C: Connection> {
    db: Surreal<C>,
    interval: Duration,
    shutdown: watch::Receiver<bool>,
}

impl<C: Connection> CleanupTask<C> {
    pub async fn run(mut self) -> Result<(), AxiamError> {
        let mut ticker = tokio::time::interval(self.interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => self.sweep().await,
                _ = self.shutdown.changed() => break,
            }
        }
        Ok(())
    }

    async fn sweep(&self) {
        let _ = self.db.query(
            "DELETE saml_assertion_replay WHERE expires_at < time::now();
             DELETE federation_login_state WHERE expires_at < time::now();"
        ).await;  // best-effort; failure → next tick
    }
}
```

### Graceful shutdown

`actix_web::HttpServer` returns when SIGTERM is received. main.rs already orchestrates
the lifecycle of three other tokio tasks (main.rs:266, 285, 303). Add a fourth:

```rust
let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
let cleanup = CleanupTask::new(db.clone(), Duration::from_secs(300), shutdown_rx);
let cleanup_handle = tokio::spawn(cleanup.run());

// ... start REST + gRPC servers ...

// After server returns (on SIGTERM):
let _ = shutdown_tx.send(true);
let _ = cleanup_handle.await;
```

If the planner prefers minimum disruption, the cleanup task can be detached
(`tokio::spawn` with no JoinHandle awaiting). It dies when the runtime drops, which
on SIGTERM is what we want. Lifetime-safe because the task owns only `Surreal<C>`
clones.

---

## Topic 8 — Migration & rollout risk

### Boot sequence on deploy of a pod

1. **Pod starts. `main.rs` loads config + env vars.**
   - `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` MUST be set in deploy or all federation
     work breaks. Document in K8s secret rollout.
2. **`DbManager::connect` connects to SurrealDB.**
   - First pod to start: it runs migrations (schema.rs additions: 3 new fields on
     `federation_config`, new `saml_assertion_replay`, new `federation_login_state`).
   - All `DEFINE FIELD IF NOT EXISTS` and `DEFINE TABLE IF NOT EXISTS` — idempotent
     across pods (verified pattern at schema.rs:18–23).
3. **Backfill task: migrate plaintext `client_secret` → ciphertext.**
   - Idempotent (predicate `client_secret_ciphertext IS NULL`).
   - **Race window:** if pod A starts the backfill while pod B is running the new
     decrypt code, pod B may see a row mid-migration: `ciphertext IS NULL` but
     `client_secret IS NOT NULL`. **Mitigation:** the new decrypt path falls back to
     plaintext when `ciphertext IS NULL`. This is a 1-line fallback during the
     migration window. After the boot's backfill completes (typically seconds), every
     row has ciphertext and the fallback never triggers.
   - **Alternative mitigation:** wrap each row's migration in a SurrealDB transaction
     and re-read after write — but the fallback is simpler.
4. **REST + gRPC server bind.** No new sockets needed.
5. **Cleanup tokio task spawned.**

### Race / downtime concerns

- **`aud` claim flag-day:** old pods (Phase 3) issue tokens without `aud`. New pods
  (Phase 4) accept tokens without `aud` if `allow_missing_aud_as_user = true`. Rolling
  deploy is safe.
- **Cookie format unchanged:** sessions span the deploy.
- **`federation_config.client_secret` legacy column:** kept (per D-11) — old code paths
  that read it still work during deploy. After deploy, the new code paths use ciphertext.
  The legacy column is set to NULL by the backfill. A future migration DROPs it.
- **Backfill error handling:** if a single row fails to encrypt (e.g., audit-log write
  fails), the migration loop should log + continue, not abort. The next boot retries.
  Document this contract.

### REQ-5 / REQ-7 acceptance coverage

| AC | Test Type | Notes |
|----|-----------|-------|
| REQ-5: OIDC fetch+cache JWKS (1h TTL) | unit (cache logic) + integration (mock JWKS HTTP) | Use `wiremock` or similar |
| REQ-5: OIDC verify ID token sig | integration | mock IdP with known keypair |
| REQ-5: OIDC validate iss/aud/exp/nonce | unit | craft tokens via existing `issue_id_token` |
| REQ-5: OIDC algorithm pinning + reject "none" | unit | crafted JWT with alg=none |
| REQ-5: JWKS retry on failure | integration | mock IdP returning 5xx after success |
| REQ-5: SAML XML sig verify | integration | sign a SAML response with a test cert |
| REQ-5: SAML NotOnOrAfter/NotBefore/Audience | unit | reuse existing assertion validator at saml.rs:382 |
| REQ-5: SAML replay tracking | integration | submit same assertion twice |
| REQ-5: 60s clock skew | unit | `Validation::leeway` covered by existing jsonwebtoken behaviour |
| REQ-5: client secret encryption at rest | integration | create config → query DB → assert ciphertext, not plaintext |
| REQ-7: password change invalidates other sessions | integration | login twice, change pw in session A, session B's cookie is now invalid |
| REQ-7: password reset invalidates all sessions | integration | login → reset → previous cookie is invalid |
| REQ-7: MFA reset invalidates sessions | unit | already covered (existing reset_mfa code) — restate |
| REQ-7: service-account dedicated token type | unit (token_roundtrip) + integration (M2M flow) | assert `aud=axiam:m2m` |

All ACs are individually testable. No AC requires manual verification.

---

## Library + crate versions

| Crate | Version | Feature flags needed | Notes |
|-------|---------|----------------------|-------|
| `jsonwebtoken` | 10.3.0 (workspace pinned `"10"`) | none | `jwk::Jwk`, `JwkSet`, `decode_header`, `Validation::set_audience`, `leeway` default 60 — all already present |
| `samael` | 0.0.19 (workspace pinned, `default-features = false` today) | **enable `xmlsec`** (flip workspace dep to remove `default-features = false`, OR set `features = ["xmlsec"]`) | Pulls `libc`, `lazy_static`, `libxml = "=0.3.3"` Rust crates + libxml2/libxmlsec1 C libs |
| `aes-gcm` | 0.10 | none | Already used by TOTP; reuse |
| `reqwest` | 0.12 (rustls-tls) | none | Already injected into OIDC service |
| `x509-parser` | 0.17 | none | Use to validate IdP cert PEM at upload time |
| `base64` | 0.22 | none | PEM → DER decode |
| `chrono` | 0.4 | none | Cache timestamps |
| `tokio` | 1 (full) | none | `tokio::time::interval`, `tokio::sync::watch`, `tokio::sync::RwLock` all in workspace already |
| `uuid` | 1 | none | Session IDs |
| `hex` | 0.4 | none | Env-var key decoding (mirrors MFA pattern) |
| `moka` | — (transitive only) | — | **DO NOT** promote to direct dep — `RwLock<HashMap>` sufficient |
| `openidconnect` | — | — | **DO NOT** add — jsonwebtoken sufficient |

**No new workspace `[workspace.dependencies]` entries needed.** `libxml` is a transitive
dep activated by `samael/xmlsec`; we never type its name in our Cargo.toml.

---

## Risks and unknowns

1. **(HIGH) `samael` xmlsec build on the project's Docker base (debian:bookworm-slim).**
   `libxmlsec1-openssl` IS in the bookworm apt repository (verified availability — it
   is in the standard `main` repo). However, library version skew is the historical
   pain point: `libxml = "=0.3.3"` (pinned hard by samael) generates bindgen bindings
   against the **installed** libxml2 version. If the Debian bookworm libxml2 changes,
   the bindings break. Mitigation: pin the base image SHA in Phase 4's Docker delta.
2. **(MEDIUM) `jti = session_id` change downstream effects.** Audit logs, OAuth2
   metadata, and any consumer that introspects JWTs will see `jti` semantics shift.
   Survey the codebase: `grep -rn 'claims.0.jti\|\.jti' crates/` — currently no consumer
   reads `jti` (verified: zero hits in the Rust source other than the issuer setting
   it). Safe.
3. **(MEDIUM) `oauth2_refresh_token` table existence.** Verified by oauth2/token.rs:546
   but the full table schema and `RefreshTokenRepository` trait need a fresh look during
   planning to confirm `revoke_all_for_user` is a clean addition.
4. **(LOW) `allow_missing_aud_as_user` flag-day.** Operators must flip the flag after
   15 minutes of deploy. If they forget, the flag stays permissive forever — minor
   security regression. Mitigation: emit a `tracing::warn!` once per minute when the
   flag is true, and put a calendar reminder in the deploy runbook.
5. **(LOW) Backfill error handling.** A SurrealDB outage mid-backfill leaves rows
   half-migrated. Idempotency saves us, but if half-migrated rows are read by traffic
   served by the same pod, decryption will fail for those few rows. The plaintext
   fallback (Topic 8) covers it.
6. **(LOW) UNKNOWN:** SurrealDB v3 INSERT UNIQUE-VIOLATION error variant — MEMORY.md
   says ".check() returns Result<_, surrealdb::Error>", but the exact error type for a
   UNIQUE conflict is not documented in MEMORY.md. Planner should validate by reading
   `crates/axiam-db/src/error.rs` and existing UNIQUE-handling code (the `federation_link`
   table has a UNIQUE constraint at schema.rs:585 — see how its repository handles
   duplicates).

---

## Recommendations summary (cheat-sheet for the planner)

| CONTEXT.md "Claude's Discretion" item | Recommendation | Rationale |
|---|---|---|
| JWKS cache: custom vs `moka` | **`Arc<RwLock<HashMap>>`** | Tens-of-entries scale; D-01..D-03 logic doesn't fit moka's TTL semantics anyway; zero new direct deps |
| AES-256-GCM crate + nonce source | **`aes_gcm = "0.10"` + `aes_gcm::aead::OsRng`** | Already used by TOTP; consistent with project pattern; extract helpers from `totp.rs` to new `crypto.rs` |
| `revoke_all_sessions_except` location | **`SessionRepository` (DB-level)** | Single SurrealQL DELETE expresses it cleanly; avoids race with concurrent logins |
| Audience check granularity | **REST extractor narrows to `axiam:user`; gRPC accepts both** | gRPC authz serves both user-on-behalf-of and M2M traffic |
| First-time SSO response shape | **Cookies only — reuse `cookie_response_from_output`** | Consistent with Phase 1 D-13; no token-in-body XSS risk |
| Background job mechanism | **tokio task + `tokio::time::interval`** | Zero new deps; SurrealDB v3 has no TTL; AMQP is overkill |
| Frontend "Continue with SSO" button | **Defer to a UI phase** | Phase 4 success criteria are server-side; full SSO UI needs tenant/config selector |
| Revoke OAuth2 codes/tokens on pw change | **Yes — revoke refresh tokens; auth codes naturally expire (10min)** | User intent: "all my credentials become invalid"; refresh tokens are long-lived |

Additional planner-level recommendations (NOT in the Claude's Discretion list, but
emerging from research):

| Topic | Recommendation |
|---|---|
| `AuthenticatedUser.session_id` plumbing | **Make `jti = session_id` at issuance.** 3-line change. Unlocks D-15 without schema work. |
| `aud` back-compat | **`AuthConfig::allow_missing_aud_as_user: bool` config flag** (single source of truth), default `true` on first Phase-4 deploy, flip after 15 minutes via env var change. |
| Federation client-secret legacy column | **Keep `client_secret` in schema, NULL it during backfill, DROP in a follow-up phase.** Avoids hard-coupling deploy timing. |
| TOTP helper rename | **Extract to `crates/axiam-auth/src/crypto.rs` with `aes256gcm_encrypt`/`decrypt`** — TOTP and Federation both call it. |
| Cert PEM → DER for samael | **Use `base64` + line-filter** (no `rustls-pemfile` dep needed); validate with `x509-parser` at upload time. |
| Cleanup task lifecycle | **`tokio::sync::watch` shutdown signal** sent after `HttpServer.run()` returns on SIGTERM. |

---

## References

### Source files (with line numbers)

- `.planning/phases/04-federation-verification-session-security/04-CONTEXT.md` — full decision list (D-01..D-24)
- `.planning/REQUIREMENTS.md` — REQ-5 lines 74–92, REQ-7 lines 111–122
- `.planning/ROADMAP.md` Phase 4 — lines 114–138
- `crates/axiam-federation/src/oidc.rs:285` — TODO(T19.6) JWT sig verify
- `crates/axiam-federation/src/oidc.rs:404` — `decode_id_token_claims` (unverified decode today)
- `crates/axiam-federation/src/saml.rs:354` — TODO(T19.7) XML sig verify
- `crates/axiam-federation/src/saml.rs:382–412` — condition validator (NotBefore/NotOnOrAfter/Audience)
- `crates/axiam-federation/Cargo.toml:23` — samael dep line
- `crates/axiam-auth/src/token.rs:17` — `AccessTokenClaims` struct (no `aud` today)
- `crates/axiam-auth/src/token.rs:64` — `jti = Uuid::new_v4()` (the fix target)
- `crates/axiam-auth/src/token.rs:195` — `decode_access_token` (no `aud` validation today)
- `crates/axiam-auth/src/service.rs:499` — `revoke_all_sessions`
- `crates/axiam-auth/src/service.rs:548` — `reset_mfa` (existing invalidation pattern)
- `crates/axiam-auth/src/service.rs:604` — `create_session_and_tokens` (jti issuance site)
- `crates/axiam-auth/src/password_reset.rs:190` — TODO(T19) session invalidation
- `crates/axiam-auth/src/totp.rs:15–47` — reusable AES-GCM helpers
- `crates/axiam-auth/src/config.rs:31` — `mfa_encryption_key` (mirror for federation)
- `crates/axiam-api-rest/src/extractors/auth.rs:25–30` — `AuthenticatedUser` struct (no session_id today)
- `crates/axiam-api-rest/src/handlers/auth.rs:176–217` — `cookie_response_from_output`
- `crates/axiam-api-rest/src/handlers/users.rs:186–209` — self-service pattern reference
- `crates/axiam-api-rest/src/permissions.rs:179` — `PUBLIC_PATHS` (the actual constant name)
- `crates/axiam-api-rest/src/middleware/authz.rs:38` — `is_public_path`
- `crates/axiam-api-rest/src/handlers/oauth2.rs:297–311` — existing `/oauth2/jwks` server-side (different concern)
- `crates/axiam-api-grpc/src/services/token.rs:31,61` — gRPC's raw `validate_access_token` call site
- `crates/axiam-db/src/schema.rs:18–24` — migration idempotency pattern
- `crates/axiam-db/src/schema.rs:354–370` — current `federation_config` schema (to extend)
- `crates/axiam-db/src/repository/session.rs:190` — `invalidate_user_sessions` (session-side chokepoint)
- `crates/axiam-db/src/repository/session.rs:201` — `cleanup_expired` (sweep pattern reference)
- `crates/axiam-oauth2/src/token.rs:546` — `refresh_token_repo.revoke` (OAuth2-side chokepoint)
- `crates/axiam-server/src/main.rs:65–79` — MFA env-var loader (mirror)
- `crates/axiam-server/src/main.rs:266,285,303` — existing `tokio::spawn` background tasks
- `crates/axiam-core/src/models/federation.rs` — `FederationConfig` model
- `docker/Dockerfile.server:14,82` — apt-get RUN lines to modify

### Crate-registry sources (read during research)

- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/jsonwebtoken-10.3.0/src/decoding.rs:109–251` — `from_rsa_pem`, `from_jwk`, `from_ed_components`, `decode_header`
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/jsonwebtoken-10.3.0/src/validation.rs:39–166` — `Validation` struct, `set_audience`, `set_issuer`, `leeway` (default 60)
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/jsonwebtoken-10.3.0/src/jwk.rs:422,552` — `Jwk` and `JwkSet`
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/samael-0.0.19/Cargo.toml:108–114` — `xmlsec` feature gate
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/samael-0.0.19/src/crypto.rs:89–109` — `verify_signed_xml`
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/samael-0.0.19/src/xmlsec/keys.rs:18–38` — `XmlSecKeyFormat::CertPem` / `CertDer` / `from_memory`

### Crate documentation (referenced; no online fetch performed in this session)

- jsonwebtoken: https://docs.rs/jsonwebtoken/10.3.0/jsonwebtoken/
- samael: https://docs.rs/samael/0.0.19/samael/ (note: docs.rs build often missing for `xmlsec` feature due to C-dep requirements — read crate source as primary)
- aes-gcm: https://docs.rs/aes-gcm/0.10/aes_gcm/
- xmlsec1 (Debian package): https://packages.debian.org/bookworm/libxmlsec1

### Other relevant artifacts

- `MEMORY.md` (project-local) — SurrealDB v3 SDK quirks; aes_gcm version notes; aead OsRng pattern
