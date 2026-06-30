# Phase 16: Rust SDK - Pattern Map

**Mapped:** 2026-06-30
**Files analyzed:** 24 (new files to create under `sdks/rust/`)
**Analogs found:** 24 / 24 (all are server-side `crates/axiam-*` files — see CRITICAL note)

> **CRITICAL — mirror, never import.** `sdks/rust/` is a pure external client crate and **MUST NOT** depend on any `crates/axiam-*` workspace crate (CONTEXT.md domain boundary). Every analog below lives in a server crate. The planner/implementer must **copy the pattern, wire format, struct shape, or algorithm** shown in each excerpt — re-implementing it standalone inside `sdks/rust/src/...` using only external crates (`reqwest`, `tonic`, `lapin`, `jsonwebtoken`, `hmac`, `sha2`, `hex`, `actix-web`) — and must **not** add a `Cargo.toml` dependency on `axiam-core`, `axiam-auth`, `axiam-amqp`, `axiam-api-grpc`, `axiam-api-rest`, or `axiam-federation`. Where an analog imports server-only types (`axiam_auth::token::ValidatedClaims`, `SurrealSessionRepository`, etc.) the SDK file defines its own equivalent plain struct instead.

## File Classification

| New File (`sdks/rust/...`) | Role | Data Flow | Closest Analog (mirror only) | Match Quality |
|---|---|---|---|---|
| `src/lib.rs` | config/entrypoint | n/a | `sdks/rust/src/lib.rs` (existing placeholder, extend) | exact (already exists) |
| `src/client.rs` | service/provider | request-response | `crates/axiam-api-rest/src/handlers/auth.rs` (client-side mirror of server flow) | role-match |
| `src/error.rs` | utility (error enum) | n/a | `crates/axiam-core/src/error.rs` (`AxiamError` enum shape, not imported) | role-match |
| `src/sensitive.rs` | utility (newtype wrapper) | n/a | none in-repo (CONTRACT.md §7 code example is the canonical source) | no analog |
| `src/token/manager.rs` | service (state holder) | event-driven | RESEARCH.md "Single-flight refresh guard" pattern (no direct repo analog; CONTRACT §9) | no analog (use RESEARCH.md pattern) |
| `src/token/refresh_guard.rs` | service (concurrency guard) | event-driven | RESEARCH.md §9 pattern (`tokio::sync::Mutex` double-check) | no analog |
| `src/token/jwks.rs` | service (verifier) | request-response | `crates/axiam-federation/src/oidc.rs:370-429,600-657` | exact (algorithm/library match) |
| `src/rest/auth.rs` | controller (client-side) | request-response | `crates/axiam-api-rest/src/handlers/auth.rs` (login/verify_mfa/refresh/logout + cookie handling) | exact |
| `src/rest/authz.rs` | service (client-side) | request-response | `crates/axiam-api-grpc/src/services/authorization.rs` (request/response shape parity with REST counterpart) | role-match |
| `src/grpc/channel.rs` | provider (connection mgmt) | request-response | RESEARCH.md Pattern 3 / Pitfall 5 (`Endpoint::connect_lazy`) — tonic upstream pattern | no in-repo analog |
| `src/grpc/interceptor.rs` | middleware | request-response | `crates/axiam-api-grpc/src/services/authorization.rs` (claims/tenant injection semantics it must satisfy server-side) | role-match |
| `src/grpc/gen/` (build-time) | generated stubs | n/a | `proto/axiam/v1/authorization.proto`, `token.proto`, `user.proto` + `sdks/buf.gen.yaml` | exact (codegen source) |
| `build.rs` | config | n/a | `sdks/buf.gen.yaml` (buf plugin config this build script must invoke/match) | role-match |
| `src/amqp/consumer.rs` | service (event-driven consumer) | event-driven | `crates/axiam-amqp/src/messages.rs` (message types + ack/nack lifecycle this must mirror) | exact |
| `src/amqp/hmac.rs` | utility (crypto) | transform | `crates/axiam-amqp/src/messages.rs:35-50` (`sign_payload`/`verify_payload`) | exact |
| `src/middleware/actix.rs` | middleware (FromRequest extractor) | request-response | `crates/axiam-api-rest/src/extractors/auth.rs` (cookie-then-header `FromRequest`) | exact |
| `examples/login_mfa.rs` | example | request-response | `crates/axiam-api-rest/src/handlers/auth.rs` (login→verify_mfa two-phase flow) | role-match |
| `examples/rest_check_access.rs` | example | request-response | `crates/axiam-api-grpc/src/services/authorization.rs` (check_access/batch semantics) | role-match |
| `examples/grpc_check_access.rs` | example | request-response | `crates/axiam-api-grpc/src/services/authorization.rs` | exact |
| `examples/amqp_consumer.rs` | example | event-driven | `crates/axiam-amqp/src/messages.rs` | role-match |
| `examples/actix_route_guard.rs` | example | request-response | `crates/axiam-api-rest/src/extractors/auth.rs` | exact |
| `tests/single_flight_refresh_test.rs` | test | event-driven | RESEARCH.md "Test design" under §9 pattern (wiremock + `tokio::spawn` x5) | no in-repo analog |
| `tests/sensitive_redaction_test.rs` | test | n/a | CONTRACT.md §7 requirement | no analog |
| `tests/amqp_hmac_test.rs` | test | transform | `crates/axiam-amqp/src/messages.rs` test module (lines ~220-260, fixture style) | exact |
| `.github/workflows/sdk-ci-rust.yml` | CI config | n/a | existing Phase 15 scaffold file (inspect/extend, not re-created from scratch) | role-match |

## Pattern Assignments

### `src/rest/auth.rs` (controller, request-response)

**Analog:** `crates/axiam-api-rest/src/handlers/auth.rs` — **mirror only, do not import.**

**Key fact this file's logic depends on** (lines 74-76):
```rust
/// Login success response body.
///
/// Tokens are delivered via `Set-Cookie` headers — not in this body.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LoginSuccessResponse {
    pub user: LoginUserInfo,
    pub session_id: Uuid,
    pub expires_in: u64,
}
```
The SDK's `login()`/`verify_mfa()`/`refresh()` response DTOs must be defined with **no `access_token` field** — confirms D-05. Define a parallel plain `struct LoginResult { user: ..., session_id: Uuid, expires_in: u64 }` in the SDK with `serde::Deserialize` only (no `utoipa::ToSchema`, no server dependency).

**Cookie-setting pattern to mirror (read side)** (lines 167-213, `cookie_response_from_output`):
```rust
let csrf_token = generate_csrf_token();
Ok(HttpResponse::Ok()
    .cookie(access_cookie(&out.access_token, config.access_token_lifetime_secs, config.cookie_secure))
    .cookie(refresh_cookie(&out.refresh_token, config.refresh_token_lifetime_secs, config.cookie_secure))
    .cookie(csrf_cookie(&csrf_token, config.access_token_lifetime_secs, config.cookie_secure))
    .json(LoginSuccessResponse { ... }))
```
This confirms three cookies are set: `axiam_access`, `axiam_refresh`, `axiam_csrf` (names per `crates/axiam-api-rest/src/middleware/csrf.rs`, cited in RESEARCH.md Sources). The SDK's `login`/`verify_mfa`/`refresh` implementations must, after each call, read `axiam_access` out of the `reqwest::cookie::Jar` (Pattern 1, RESEARCH.md lines 223-247) and `axiam_csrf` for §3 CSRF forwarding — **never** expect these in the JSON body.

**Error-shape note:** match HTTP status → `AxiamError` variant per CONTRACT.md §2 table exactly (401→AuthError, 403→AuthzError, etc.) — this is a contract requirement, not something to infer from `auth.rs`.

---

### `src/token/jwks.rs` (service, request-response)

**Analog:** `crates/axiam-federation/src/oidc.rs:370-429, 600-657` — **mirror only, do not import.**

**Core verify pattern to copy** (lines 389-429, condensed in RESEARCH.md Pattern 2):
```rust
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use jsonwebtoken::jwk::JwkSet;

fn verify_local(token: &str, jwks: &JwkSet, issuer: &str, audience: &str)
    -> Result<Claims, AxiamError>
{
    let header = decode_header(token)?;
    if header.alg != Algorithm::EdDSA {
        return Err(AxiamError::Auth { message: "unexpected alg".into() });
    }
    let jwk = jwks.keys.iter()
        .find(|j| j.common.key_id.as_deref() == header.kid.as_deref())
        .or_else(|| (jwks.keys.len() == 1).then(|| &jwks.keys[0]))
        .ok_or(AxiamError::Auth { message: "unknown kid".into() })?;

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|_| AxiamError::Auth { message: "bad JWK".into() })?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.leeway = 0;
    let data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(data.claims)
}
```

**kid-rotation refetch pattern to copy** (`oidc.rs:600-624`, server's `find_jwk` + forced-refetch-on-unknown-kid):
```rust
let jwk = find_jwk(&jwks, header.kid.as_deref());
let jwk = if let Some(j) = jwk {
    j
} else {
    let refreshed_jwks = self.cache
        .force_refetch_if_allowed(&self.http_client, cache_key, &discovery.jwks_uri)
        .await?;
    find_jwk(&refreshed_jwks, header.kid.as_deref())
        .ok_or(FederationError::JwksKidUnknown)?
};
```
and the `find_jwk` helper (lines ~640-657) — copy this exact "if kid is None and exactly one key in the set, use that key" fallback, since `/oauth2/jwks` serves a single org-wide Ed25519 key (RESEARCH.md D-11 finding).

**Endpoint to call:** `GET {base_url}/oauth2/jwks` (NOT `/.well-known/jwks.json` — confirmed anti-pattern in RESEARCH.md). Org-wide, not tenant-scoped.

**alg=none defense-in-depth (optional but recommended):** mirror `reject_alg_none_raw` (`oidc.rs` ~600s block) if the planner wants belt-and-suspenders header inspection before `decode_header`.

---

### `src/amqp/hmac.rs` (utility, transform)

**Analog:** `crates/axiam-amqp/src/messages.rs:35-50` — **mirror only, do not import. Must be byte-identical wire format.**

```rust
pub fn sign_payload(key: &[u8], payload_json: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_payload(key: &[u8], payload_json: &[u8], signature_hex: &str) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    let expected = hex::decode(signature_hex).unwrap_or_default();
    mac.verify_slice(&expected).is_ok()
}
```
Crates: `hmac = "0.12"`, `sha2 = "0.10"`, `hex = "0.4"` — exact same majors as the server.

**Struct field order is load-bearing (Pitfall 1).** The SDK's local `AuthzRequest`/`AuditEventMessage` structs must replicate field declaration order and `#[serde(...)]` attributes byte-for-byte from `messages.rs:56-103`:
```rust
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthzRequest {
    pub correlation_id: Uuid,
    pub tenant_id: Uuid,
    pub subject_id: Uuid,
    pub action: String,
    pub resource_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuditEventMessage {
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub actor_type: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}
```
Before computing/verifying HMAC: `hmac_signature` MUST be `None`/omitted (matches `#[serde(skip_serializing_if = "Option::is_none")]`), exactly as the doc comment on `sign_payload` (lines 31-34) states.

**Test fixture to reuse (oracle):** `crates/axiam-amqp/src/messages.rs` test module (~lines 220-260) — copy the literal `key = b"test-amqp-signing-key"` style fixture into `tests/amqp_hmac_test.rs` and assert the SDK produces an identical hex string, proving wire compatibility (not just internal self-consistency).

---

### `src/amqp/consumer.rs` (service, event-driven)

**Analog:** `crates/axiam-amqp/src/messages.rs` (message type shapes) + RESEARCH.md Code Example "AMQP HMAC verify before handler invocation" (already a concrete, ready-to-adapt implementation — use directly):
```rust
async fn handle_delivery<F, Fut>(
    delivery: lapin::message::Delivery,
    signing_key: &[u8],
    handler: F,
) where
    F: Fn(serde_json::Value) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut body: serde_json::Value = match serde_json::from_slice(&delivery.data) {
        Ok(v) => v,
        Err(_) => {
            let _ = delivery.nack(lapin::options::BasicNackOptions { requeue: false, ..Default::default() }).await;
            return;
        }
    };
    let sig = body.get("hmac_signature").and_then(|v| v.as_str()).map(str::to_owned);
    if let Some(obj) = body.as_object_mut() {
        obj.remove("hmac_signature");
    }
    let canonical = serde_json::to_vec(&body).unwrap();
    let verified = match sig {
        Some(s) => verify_payload(signing_key, &canonical, &s),
        None => false, // strict mode default
    };
    if !verified {
        tracing::warn!(target: "axiam_sdk::security", "AMQP HMAC verification failed; nacking without requeue");
        let _ = delivery.nack(lapin::options::BasicNackOptions { requeue: false, ..Default::default() }).await;
        return;
    }
    handler(body).await;
    let _ = delivery.ack(lapin::options::BasicAckOptions::default()).await;
}
```
D-07's closure-handler API (`consume(queue, |event| async {...})`) wraps this so the handler closure never sees an unverified message.

---

### `src/grpc/interceptor.rs` (middleware, request-response)

**Analog:** `crates/axiam-api-grpc/src/services/authorization.rs` (server-side claims/tenant cross-validation this client must satisfy) + RESEARCH.md Pattern 3 (ready-to-use):
```rust
use tonic::{Request, Status};
use tonic::service::Interceptor;

#[derive(Clone)]
struct AuthInterceptor {
    token_manager: std::sync::Arc<crate::token::TokenManager>,
    tenant_id: String,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let token = self.token_manager.access_token_blocking()
            .ok_or_else(|| Status::unauthenticated("no access token"))?;
        req.metadata_mut().insert("authorization", format!("Bearer {}", token.expose()).parse().unwrap());
        req.metadata_mut().insert("x-tenant-id", self.tenant_id.parse().unwrap());
        Ok(req)
    }
}
```
**Server-side fact this must match** (`authorization.rs` lines 81-94): the server cross-validates `body.tenant_id` against `claims.tenant_id` and rejects mismatch — confirms `x-tenant-id` metadata must always be the **UUID** form (resolve `tenant_slug`→UUID once at login via decoded JWT claims; see RESEARCH.md Open Question #1).

**Critical constraint (Pitfall 3):** `Interceptor::call` is **sync** — never `.lock().await` the async refresh `Mutex` inside it. Use a non-blocking read primitive (`ArcSwapOption` or `RwLock` read guard) for the cached token; drive refresh from the async call-site wrapper on `Status::Unauthenticated`.

---

### `src/middleware/actix.rs` (middleware, request-response)

**Analog:** `crates/axiam-api-rest/src/extractors/auth.rs` — **mirror only, do not import** (the server file imports `axiam_auth`/`axiam_core`/`axiam_db`, none of which the SDK may depend on).

**Cookie-then-header extraction pattern to copy** (lines 148-183, `parse_validated_claims`):
```rust
let token = if let Some(cookie) = req.cookie("axiam_access") {
    cookie.value().to_owned()
} else {
    let header = req.headers().get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(/* AuthError: missing credentials */)?;
    let header = header.trim();
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or("");
    let credentials = parts.next().unwrap_or("").trim();
    if !scheme.eq_ignore_ascii_case("bearer") || credentials.is_empty() {
        return Err(/* AuthError: invalid scheme */);
    }
    credentials.to_owned()
};
```

**`FromRequest` shape to copy** (lines 87-119, `impl actix_web::FromRequest for AuthenticatedUser`):
```rust
impl actix_web::FromRequest for AxiamUser {
    type Error = crate::AxiamApiSdkError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            // §10.1 extract (cookie OR Bearer header, as above)
            // §10.2 verify locally against cached JWKS via src/token/jwks.rs — no server round-trip
            // §10.3 build AxiamUser{user_id, tenant_id, roles} and return
        })
    }
}
```
Where the server version reads a DB session repo for revocation checks, the SDK version instead calls its own in-process `JwksVerifier` (`src/token/jwks.rs`) — see RESEARCH.md's full ready-to-use `FromRequest` code example (lines 533-588) for the complete adaptation including `app_data::<web::Data<JwksVerifier>>()` lookup.

**Error mapping:** `AuthError` → HTTP 401, `AuthzError` → HTTP 403 (CONTRACT.md §10 closing requirement), standardized JSON error body.

---

### `src/error.rs` (utility, n/a)

**Analog:** `crates/axiam-core/src/error.rs` (`AxiamError` enum — naming/shape precedent only, NOT imported; the SDK's `AxiamError`/`AxiamSdkError` is its own type per D-06).

**Required shape (CONTRACT.md §2, binding):**
```rust
#[derive(thiserror::Error, Debug)]
pub enum AxiamError {
    #[error("authentication failed: {message}")]
    Auth { message: String },
    #[error("authorization denied: {message}")]
    Authz { message: String, action: Option<String>, resource_id: Option<String> },
    #[error("network error: {0}")]
    Network(#[from] /* underlying transport error, never the raw token */ NetworkErrorCause),
}
```
Map HTTP/gRPC status codes to these three per the CONTRACT.md §2 tables exactly. Never embed raw token strings in any variant's Display/message (Pitfall 4 / §7 cross-cutting concern).

---

### `src/sensitive.rs` (utility, n/a)

**No in-repo analog** — RESEARCH.md's ready-made code example is the canonical source (use directly, this is new infrastructure, not a mirror of existing code):
```rust
use std::fmt;

pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    pub fn new(value: T) -> Self { Self(value) }
    pub(crate) fn expose(&self) -> &T { &self.0 }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sensitive(<redacted>)")
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[SENSITIVE]")
    }
}
```
No `Serialize`/`Deserialize`, no public `Deref`, `expose()` is `pub(crate)` only (CONTRACT.md §7).

---

## Shared Patterns

### Cookie names (cross-cutting)
**Source:** `crates/axiam-api-rest/src/middleware/csrf.rs` (per RESEARCH.md Sources) — exact cookie names: `axiam_access`, `axiam_refresh`, `axiam_csrf`.
**Apply to:** `src/rest/auth.rs`, `src/middleware/actix.rs`, `src/client.rs` (jar construction).

### EdDSA/JWKS verification (cross-cutting)
**Source:** `crates/axiam-federation/src/oidc.rs:370-429,600-657`.
**Apply to:** `src/token/jwks.rs`, `src/middleware/actix.rs`, `src/grpc/interceptor.rs` (proactive expiry check), `examples/actix_route_guard.rs`.

### HMAC-SHA256 wire protocol (cross-cutting, byte-identical requirement)
**Source:** `crates/axiam-amqp/src/messages.rs:35-50, 56-103`.
**Apply to:** `src/amqp/hmac.rs`, `src/amqp/consumer.rs`, `tests/amqp_hmac_test.rs`.

### Sensitive-value never logged (cross-cutting)
**Source:** RESEARCH.md `Sensitive<T>` example (no in-repo precedent; CONTRACT.md §7 binding).
**Apply to:** every file holding a token: `src/token/manager.rs`, `src/token/refresh_guard.rs`, `src/grpc/interceptor.rs`, `src/rest/auth.rs`, `src/client.rs`.

### Tenant header/metadata injection (cross-cutting)
**Source:** `crates/axiam-api-grpc/src/services/authorization.rs:81-94` (server-side cross-validation this client traffic must satisfy) + CONTRACT.md §5.
**Apply to:** `src/client.rs` (REST `X-Tenant-ID` header), `src/grpc/interceptor.rs` (`x-tenant-id` metadata).

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `src/sensitive.rs` | utility | n/a | No existing redaction-wrapper type in the codebase; server uses ad-hoc redaction in tracing spans only. Use RESEARCH.md's code example directly. |
| `src/token/manager.rs` | service | event-driven | No client-side token-state-holder exists server-side (server is stateless re: its own tokens). Use RESEARCH.md `TokenManager` example directly. |
| `src/token/refresh_guard.rs` | service | event-driven | Single-flight client-side refresh concurrency control has no server-side analog (server has no refresh-storm concern). Use RESEARCH.md §9 pattern directly. |
| `src/grpc/channel.rs` | provider | request-response | Lazy-connect shared channel construction is a pure client concern; mirrors `tonic::transport::Endpoint::connect_lazy()` upstream API, not repo code. |
| `tests/single_flight_refresh_test.rs` | test | event-driven | `wiremock`-based mock server test has no existing test harness precedent in this repo (closest is the gRPC in-process test server from `07-03-PLAN.md`, a different transport). |
| `tests/sensitive_redaction_test.rs` | test | n/a | New, asserts Debug/Display never leak `eyJ` — no existing equivalent test. |

## Metadata

**Analog search scope:** `crates/axiam-amqp/`, `crates/axiam-api-rest/`, `crates/axiam-api-grpc/`, `crates/axiam-federation/`, `crates/axiam-core/`, `sdks/rust/` (existing scaffold), `sdks/CONTRACT.md`, `sdks/buf.gen.yaml`, `proto/axiam/v1/*.proto`
**Files scanned:** 8 read directly (`16-CONTEXT.md`, `16-RESEARCH.md`, `sdks/CONTRACT.md`, `crates/axiam-api-rest/src/extractors/auth.rs`, `crates/axiam-amqp/src/messages.rs`, `crates/axiam-api-grpc/src/services/authorization.rs`, `crates/axiam-federation/src/oidc.rs`, `crates/axiam-api-rest/src/handlers/auth.rs`) + glob of existing `sdks/rust/` scaffold
**Pattern extraction date:** 2026-06-30
**Boundary reminder:** All "exact"/"role-match" analogs above are server-internal source files under `crates/axiam-*` — every excerpt is to be **reimplemented standalone** in `sdks/rust/`, never imported as a dependency.
