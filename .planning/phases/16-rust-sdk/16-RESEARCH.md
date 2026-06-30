# Phase 16: Rust SDK - Research

**Researched:** 2026-06-30
**Domain:** Rust async HTTP/gRPC/AMQP client SDK; JWT/JWKS local verification; Cargo workspace publishing
**Confidence:** HIGH

## Summary

This phase builds `sdks/rust/axiam-sdk`, a pure external client crate against the frozen AXIAM v1.0 API. The 12 open research items are all resolved with HIGH confidence because the answers were extracted directly from the server's own working code in this repository — there is no guessing involved for the load-bearing facts (cookie names, JWKS path/format, JWT algorithm, HMAC protocol, dependency versions).

The single most important finding (D-05) is that **AXIAM never returns the access token in any JSON response body — ever**. `login`, `verify_mfa`, and `refresh` all deliver tokens exclusively via `Set-Cookie: axiam_access=...; HttpOnly`. This is a deliberate, hardened design (REQ-1, OWASP ASVS 3.4.x) and the SDK must not fight it. Because `reqwest::cookie::Jar` **does** expose cookie values by name even when the cookie carries the `HttpOnly` attribute (HttpOnly only restricts *browser JavaScript* access via `document.cookie`; it has no effect on a non-browser HTTP client's own cookie jar, which is a local in-process data structure, not a browser document), the SDK can read `axiam_access` straight out of the `Jar` after every login/refresh/verify_mfa call. This is the recommended, contract-compliant extraction path, with no fallback needed.

The second major finding (D-11) is the exact JWKS path: **`GET /oauth2/jwks`**, not `/.well-known/jwks.json`. It is a single, organization-wide endpoint (not tenant-scoped), serving exactly one Ed25519 key (`kty: OKP, crv: Ed25519, alg: EdDSA`) with a deterministic `kid`. The server's own `axiam-federation` crate already verifies third-party Ed25519 JWTs against fetched JWKS using `jsonwebtoken = "10"` and its `DecodingKey::from_jwk(&jwk)` constructor — this is the exact, proven pattern (not a recommendation made from training data) the SDK should mirror for verifying *its own* tokens locally.

**Primary recommendation:** Use `jsonwebtoken = "10"` (the same crate, same major version, already proven against Ed25519/JWKS in this codebase) for D-03/D-11 local verification; read tokens from `reqwest::cookie::Jar` by the `axiam_access` cookie name for D-05; pin MSRV to **1.88** (the floor set by tonic 0.14.6, lapin 4.10.0, and jsonwebtoken 10.4.0); and use `backon` (not the unmaintained `backoff` crate) for D-12 retry/backoff.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Login / MFA / refresh / logout (REST) | API / Backend (consumed) | — | SDK is a pure client; auth logic lives server-side. SDK only orchestrates calls + cookie/token state. |
| Token storage & redaction (`Sensitive<T>`) | SDK (client-side library) | — | No server tier owns this; it's an in-process client safety property. |
| Local JWT/JWKS verification | SDK (client-side library) | API / Backend (JWKS source) | SDK fetches JWKS from the API tier but performs verification itself to avoid a round-trip per check. |
| Single-flight refresh guard | SDK (client-side library) | — | Pure client-side concurrency control; server has no knowledge of in-flight refreshes. |
| `check_access` / `batch_check` (gRPC + REST) | API / Backend (decision) | SDK (transport client) | `AuthorizationEngine` is the sole decision authority (server); SDK only transports the request/response. |
| AMQP event consumption + HMAC verify | SDK (client-side library) | Message Broker / Storage (RabbitMQ delivers) | SDK is a consumer of a server-published stream; verification is a client-side trust boundary check before handing events to user code. |
| Actix-Web middleware/extractor (§10) | Frontend Server (SSR) / API tier of the *consumer's* app | SDK (provides the extractor) | The SDK ships the building block; the tier that uses it is whatever Actix-Web app embeds the SDK (could be a backend-for-frontend or another API service). |
| Publish pipeline (crates.io) | CI/CD (build tier) | — | Out of the runtime architecture entirely; a release-time concern. |

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RUST-01 | Full SDK capability baseline (REST+gRPC+AMQP), `reqwest::cookie::Jar` cookie persistence, Actix-Web middleware/extractor, single-flight concurrency test, examples, crates.io publish CI | All sections below; concurrency test design in Validation Architecture; JWKS/token-source findings unblock D-03/D-04/D-05 directly |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|---------------|
| `tokio` | `1` (full) | Async runtime | Pinned in workspace `Cargo.toml:33`; required by tonic/lapin/reqwest. `[VERIFIED: workspace Cargo.toml]` |
| `reqwest` | `0.12` (rustls-tls, json) | REST transport, cookie jar | Pinned in workspace `Cargo.toml:71`; RUST-01 acceptance criterion. `[VERIFIED: workspace Cargo.toml + cargo info]` |
| `tonic` | `0.14` | gRPC transport | Pinned in workspace `Cargo.toml:49`; RUST-01 acceptance criterion. `[VERIFIED: workspace Cargo.toml + cargo info]` |
| `lapin` | `4` | AMQP transport | Pinned in workspace `Cargo.toml:56`; RUST-01 acceptance criterion. `[VERIFIED: workspace Cargo.toml + cargo info]` |
| `jsonwebtoken` | `10` (matches workspace `10.4.0`) | Local EdDSA JWT verification against JWKS | Same crate the server uses for its own outbound token issuance (`axiam-auth/src/token.rs`) AND for verifying third-party EdDSA JWTs via JWKS (`axiam-federation/src/oidc.rs:411`, `DecodingKey::from_jwk`). `[VERIFIED: workspace Cargo.toml + crates/axiam-federation/src/oidc.rs]` |
| `hmac` | `0.12` | AMQP §8 HMAC-SHA256 signing/verify | Identical to server's `axiam-amqp/src/messages.rs` reference impl; constant-time `verify_slice`. `[VERIFIED: crates/axiam-amqp/src/messages.rs]` |
| `sha2` | `0.10` | HMAC-SHA256 digest | Paired with `hmac` in server reference impl. `[VERIFIED: crates/axiam-amqp/src/messages.rs]` |
| `hex` | `0.4` | Hex-encode/decode HMAC signatures | Matches server's `hex::encode`/`hex::decode` usage exactly. `[VERIFIED: crates/axiam-amqp/src/messages.rs]` |
| `thiserror` | `1` or `2` | `AxiamError` enum derive (D-06) | Idiomatic Rust error enum derive; matches server's own error style (`axiam_core::error::AxiamError`). `[CITED: crates.io thiserror]` |
| `serde` / `serde_json` | workspace-pinned | Request/response (de)serialization | Used everywhere in the server REST/gRPC layer; canonical-JSON requirement for HMAC (§8) needs deterministic field order — see Pitfall 1. `[VERIFIED: workspace Cargo.toml]` |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `backon` | `1.6` | Retry/backoff for D-12 idempotent-only retries | Maintained replacement for the unmaintained `backoff` crate; built-in jitter + `Retry-After` honoring via custom builder. `[VERIFIED: npm-equivalent crates.io check via package-legitimacy gate — OK, 1.6M weekly downloads]` |
| `actix-web` | `4` | §10 middleware/extractor target framework | Pinned in workspace `Cargo.toml:36`; RUST-01 deliverable. `[VERIFIED: workspace Cargo.toml]` |
| `tracing` | `0.1` | D-13 feature-gated `observability` instrumentation | Standard Rust async tracing; used throughout the server already. `[VERIFIED: workspace Cargo.toml + package-legitimacy OK]` |
| `wiremock` | `0.6` | REST mock server for single-flight refresh test | Async, hyper-based, integrates cleanly with `reqwest` + `tokio::test`; supports request-count assertions out of the box. `[VERIFIED: package-legitimacy OK, 1M weekly downloads]` |
| `tonic-build` / `tonic-prost-build` | `0.14` | Local `build.rs` codegen fallback (see D-09 below) | Already a workspace dependency for the server's own gRPC codegen; SDK reuses the same major version for compatibility. `[VERIFIED: workspace Cargo.toml]` |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `jsonwebtoken` for JWKS verify | `jwt-authorizer` | Wraps `jsonwebtoken` + adds an Axum-coupled validator layer; SDK needs framework-agnostic verification (Actix is only one of several consumers), so the extra coupling is unwanted. |
| `jsonwebtoken` for JWKS verify | `josekit` | Broader JOSE support (JWE, JWS, JWT) but heavier, less actively used in the Rust web ecosystem, and the server doesn't use it — would mean carrying two different EdDSA implementations with potential behavioral drift. |
| `jsonwebtoken` for JWKS verify | `biscuit-auth` | Wrong tool — Biscuit is a different token format (capability tokens), not a JWT/JWKS library; would require the server to change its token format. Rejected outright. |
| `backon` for retry/backoff | `backoff` (ihrwein) | Original/most-cited crate but effectively unmaintained (no significant activity in years); `backon` is the actively-maintained successor with the same exponential+jitter feature set. |
| `tower-retry` for D-12 | Hand-rolled retry loop | `tower::retry` exists but is most natural for the gRPC/tonic path (already tower-based); for REST (`reqwest`) and AMQP reconnects a uniform `backon`-based helper is simpler to keep behaviorally identical across all three transports — single retry policy implementation reused everywhere. |

**Installation:**
```bash
cargo add tokio --features full
cargo add reqwest --no-default-features --features json,rustls-tls,cookies
cargo add tonic@0.14
cargo add lapin@4
cargo add jsonwebtoken@10
cargo add hmac@0.12 sha2@0.10 hex@0.4
cargo add thiserror
cargo add backon
cargo add tracing --optional
cargo add actix-web@4 --optional   # only for the middleware sub-module / examples
cargo add --dev wiremock@0.6 tokio-test
```

**Version verification:** All versions above were confirmed live against the crates.io registry via `cargo info <pkg>` during this research session (not training-data recall):

| Package | Resolved version | MSRV | Source |
|---------|------------------|------|--------|
| tonic | 0.14.6 | 1.88 | `cargo info tonic@0.14` |
| reqwest | 0.12.28 | 1.64.0 | `cargo info reqwest@0.12` |
| lapin | 4.10.0 | 1.88.0 | `cargo info lapin@4` |
| jsonwebtoken | 10.4.0 | 1.88.0 | `cargo info jsonwebtoken@10` |
| tokio | 1.52.3 | 1.71 | `cargo info tokio@1` |
| backon | 1.6.0 | 1.85 | `cargo info backon` |
| tower | 0.5.3 | 1.64.0 | `cargo info tower` |

All packages additionally resolve together **today**, in this exact workspace's `Cargo.lock`, with zero version conflicts (tonic 0.14.6, reqwest 0.12.28, lapin 4.10.0, jsonwebtoken 10.4.0 all already coexist as transitive/direct workspace deps). `[VERIFIED: Cargo.lock]`

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|--------------|---------|-------------|
| jsonwebtoken | crates.io | 2015 (~11 yrs) | 2.7M/wk | github.com/Keats/jsonwebtoken | OK | Approved |
| backon | crates.io | 2022 (~4 yrs) | 1.6M/wk | github.com/Xuanwo/backon | OK | Approved |
| tonic | crates.io | 2018 (~8 yrs) | 5.8M/wk | github.com/hyperium/tonic | OK | Approved (already pinned workspace dep) |
| reqwest | crates.io | 2016 (~10 yrs) | 10.5M/wk | github.com/seanmonstar/reqwest | OK | Approved (already pinned workspace dep) |
| lapin | crates.io | 2019 (~7 yrs) | 173K/wk | github.com/amqp-rs/lapin | OK | Approved (already pinned workspace dep) |
| tokio | crates.io | 2016 (~10 yrs) | 14.1M/wk | github.com/tokio-rs/tokio | OK | Approved (already pinned workspace dep) |
| hmac | crates.io | 2016 (~10 yrs) | 7.9M/wk | github.com/RustCrypto/MACs | OK | Approved (already pinned workspace dep) |
| sha2 | crates.io | 2016 (~10 yrs) | 14.4M/wk | github.com/RustCrypto/hashes | OK | Approved (already pinned workspace dep) |
| hex | crates.io | 2015 (~11 yrs) | 8.7M/wk | github.com/KokaKiwi/rust-hex | OK | Approved (already pinned workspace dep) |
| thiserror | crates.io | 2019 (~7 yrs) | 21.7M/wk | github.com/dtolnay/thiserror | OK | Approved |
| tracing | crates.io | 2017 (~9 yrs) | 12.0M/wk | github.com/tokio-rs/tracing | OK | Approved |
| wiremock | crates.io | 2020 (~6 yrs) | 1.0M/wk | github.com/LukeMathWalker/wiremock-rs | OK | Approved (dev-dependency only) |
| mockall | crates.io | 2019 (~7 yrs) | 2.4M/wk | github.com/asomers/mockall | OK | Approved if needed (dev-dependency only) |

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

All packages in this table were verified via the `gsd-tools query package-legitimacy check --ecosystem crates` seam against the live crates.io registry during this research session, AND cross-checked against this workspace's own `Cargo.toml`/`Cargo.lock` for the four protocol crates (tonic/reqwest/lapin/jsonwebtoken pin to the exact same versions already running in production server code) — these four therefore carry the strongest possible provenance: `[VERIFIED: crates.io registry + workspace Cargo.lock]`. The remaining packages (`backon`, `thiserror`, `tracing`, `wiremock`, `mockall`) are `[VERIFIED: crates.io registry]` via the legitimacy gate but were not already workspace deps prior to this research.

## Architecture Patterns

### System Architecture Diagram

```
                    ┌─────────────────────────────────────────────┐
                    │         Consumer application (binary)        │
                    │   (uses axiam-sdk as a library dependency)    │
                    └───────────────────┬───────────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────────┐
                    │              axiam-sdk crate                   │
                    │                                                 │
   ┌────────────┐   │  ┌──────────────┐   ┌──────────────────────┐  │
   │ login() ───┼──▶│  │ AximaClient  │   │ TokenManager          │  │
   │ verify_mfa │   │  │ (builder,    │──▶│  - Sensitive<String>  │  │
   │ refresh()  │   │  │  tenant_*    │   │  - single-flight Mutex│  │
   │ logout()   │   │  │  required)   │   │  - proactive refresh  │  │
   └────────────┘   │  └──────┬───────┘   └──────────┬─────────────┘  │
                    │         │                       │                │
        ┌───────────┼─────────┼───────────────────────┼────────────┐  │
        │  REST      │  gRPC   │            AMQP        │  JWKS      │  │
        │ (reqwest)  │ (tonic) │           (lapin)       │ verifier   │  │
        │            │         │                          │(jsonwebtoken)│
        └─────┬──────┴────┬───┴──────────┬───────────────┴─────┬────┘  │
              │            │              │                      │      │
   ┌──────────▼───┐  ┌────▼──────────┐ ┌─▼────────────────┐ ┌──▼────┐  │
   │ Cookie Jar   │  │ tower interceptor│ │ closure-handler  │ │ JWKS  │  │
   │ (reqwest::   │  │ injects auth +  │ │ consumer: verify │ │ cache │  │
   │  cookie::Jar)│  │ x-tenant-id     │ │ HMAC before user │ │ (TTL, │  │
   └──────────────┘  └─────────────────┘ │ handler runs     │ │ kid-  │  │
                    │                                       └───────────┘ │ refetch)│
                    └─────────────────────────────────────────────────┘  └───┬───┘
                                        │                                      │
   ════════════════════════ network boundary ═══════════════════════════════│══════
                                        │                                      │
                    ┌───────────────────▼──────────────┐   ┌─────────────────▼────────┐
                    │   AXIAM Server (frozen v1.0 API)   │   │  GET /oauth2/jwks         │
                    │  POST /api/v1/auth/login           │   │  (Ed25519 OKP key,        │
                    │  POST /api/v1/auth/mfa/verify       │   │   single org-wide key)    │
                    │  POST /api/v1/auth/refresh          │   └───────────────────────────┘
                    │  POST /api/v1/auth/logout           │
                    │  POST /api/v1/authz/check[/batch]   │
                    │  gRPC CheckAccess/BatchCheckAccess  │
                    │  AMQP axiam.authz.request /         │
                    │       axiam.audit.events            │
                    └─────────────────────────────────────┘

Actix-Web extractor path (§10, separate consuming process):
  Incoming HTTP request → FromRequest::from_request(req)
    → read axiam_access cookie OR Authorization: Bearer header
    → verify locally via cached JWKS (no AXIAM server round-trip)
    → inject AxiamUser{user_id, tenant_id, roles} into request extensions
    → handler runs, or 401/403 short-circuit on verification failure
```

### Recommended Project Structure
```
sdks/rust/
├── Cargo.toml                  # features: default=["rest","grpc","amqp"], observability
├── build.rs                    # gRPC codegen — only runs when `grpc` feature is on
├── src/
│   ├── lib.rs                  # crate root, re-exports, conformance doc comment
│   ├── client.rs                # AximaClient + builder (tenant_*, base_url, timeouts, custom_ca)
│   ├── error.rs                 # AxiamError enum (D-06), HTTP/gRPC status mapping (§2)
│   ├── sensitive.rs              # Sensitive<T> wrapper (§7)
│   ├── token/
│   │   ├── mod.rs
│   │   ├── manager.rs            # TokenManager: holds Sensitive<String> tokens, exp tracking
│   │   ├── refresh_guard.rs      # single-flight tokio::sync::Mutex guard (§9)
│   │   └── jwks.rs                # JWKS fetch/cache/kid-rotation + local EdDSA verify (D-03/D-11)
│   ├── rest/
│   │   ├── mod.rs                 # feature = "rest"
│   │   ├── auth.rs                 # login, verify_mfa, refresh, logout
│   │   └── authz.rs                 # check_access/can, batch_check
│   ├── grpc/
│   │   ├── mod.rs                  # feature = "grpc"
│   │   ├── channel.rs               # shared lazily-connected tonic::Channel
│   │   ├── interceptor.rs            # auth + x-tenant-id injection, UNAUTHENTICATED→refresh
│   │   └── gen/                      # gitignored — buf-generated stubs land here at build time
│   ├── amqp/
│   │   ├── mod.rs                   # feature = "amqp"
│   │   ├── consumer.rs               # closure-handler consume() (D-07)
│   │   └── hmac.rs                    # §8 sign/verify, byte-identical to server reference
│   └── middleware/
│       └── actix.rs                  # feature = "actix" (or always-on small sub-module) — §10 extractor
├── examples/
│   ├── login_mfa.rs
│   ├── rest_check_access.rs
│   ├── grpc_check_access.rs
│   ├── amqp_consumer.rs
│   └── actix_route_guard.rs
└── tests/
    ├── single_flight_refresh_test.rs   # wiremock-backed, asserts exactly 1 refresh call
    ├── sensitive_redaction_test.rs       # asserts Debug/Display never leak token
    └── amqp_hmac_test.rs                  # byte-identical HMAC vectors vs. server reference
```

### Pattern 1: Token extraction from the cookie jar (D-05)

**What:** After every `login`/`verify_mfa`/`refresh` call, read the freshly-set `axiam_access` cookie value directly out of the client's `reqwest::cookie::Jar` rather than expecting it in the JSON body.
**When to use:** Required for D-03 (local JWKS verification needs the raw JWT) and D-04 (gRPC metadata injection needs the raw token string).
**Why this works:** `HttpOnly` is a **browser** directive (it tells `document.cookie` / browser-side JS to refuse access). A `reqwest::cookie::Jar` is an in-process Rust data structure, not a browser document — `HttpOnly` has zero effect on it. `reqwest::cookie::CookieStore` trait exposes `cookies(&url) -> Option<HeaderValue>` and the concrete `Jar` type stores all cookies regardless of the `HttpOnly` flag; reqwest's cookie engine (built on the `cookie` crate) tracks and returns them by name via `Jar`'s `Iterator`/lookup support.
**Example:**
```rust
// Source: pattern verified against crates/axiam-api-rest/src/middleware/csrf.rs
// (COOKIE_ACCESS = "axiam_access") + reqwest 0.12 cookie_store(true) behavior.
use reqwest::cookie::{CookieStore, Jar};
use std::sync::Arc;
use url::Url;

const COOKIE_ACCESS: &str = "axiam_access";

fn extract_access_token(jar: &Jar, base_url: &Url) -> Option<crate::Sensitive<String>> {
    let header = jar.cookies(base_url)?; // HeaderValue, e.g. "axiam_access=eyJ...; axiam_csrf=..."
    let raw = header.to_str().ok()?;
    raw.split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(&format!("{COOKIE_ACCESS}=")))
        .map(|v| crate::Sensitive::new(v.to_string()))
}
```
**Fallback:** None needed — the jar-read path is reliable because the SDK's own `reqwest::Client` owns the `Jar` instance it set via `.cookie_provider(Arc::new(jar))` during construction (§4 requirement already mandates this). There is no scenario where the SDK has a session but cannot read its own jar.

### Pattern 2: Local JWKS verification (D-03/D-11)

**What:** Fetch `GET {base_url}/oauth2/jwks` once, cache by `kid`, verify the access token's EdDSA signature and `exp` locally using `jsonwebtoken::DecodingKey::from_jwk`.
**When to use:** Every time the SDK needs to know token validity/expiry without a server round-trip (proactive refresh scheduling, §10 extractor).
**Example (mirrors live server code, not invented):**
```rust
// Source: crates/axiam-federation/src/oidc.rs:389-429 (server's own EdDSA/JWKS
// verification of THIRD-PARTY IdP tokens) — same crate, same pattern, applied
// here by the SDK to AXIAM's OWN tokens.
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
    validation.leeway = 0; // SDK is talking to its own issuer; no federation skew needed

    let data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(data.claims)
}
```
**On unknown `kid`:** refetch the JWKS once (rate-limited), matching the exact rotation-handling pattern at `crates/axiam-federation/src/oidc.rs:397-407`.

### Pattern 3: gRPC interceptor (D-04)

**What:** A `tonic`/`tower` interceptor injecting `authorization: Bearer <token>` and `x-tenant-id` metadata on every outgoing RPC, reading the token from the shared `TokenManager` (never logging it).
**Example:**
```rust
// Source: tonic 0.14 interceptor pattern (tonic::service::Interceptor trait)
use tonic::{Request, Status};
use tonic::service::Interceptor;

#[derive(Clone)]
struct AuthInterceptor {
    token_manager: std::sync::Arc<crate::token::TokenManager>,
    tenant_id: String,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let token = self.token_manager.access_token_blocking() // see Pitfall 3
            .ok_or_else(|| Status::unauthenticated("no access token"))?;
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", token.expose()).parse().unwrap(),
        );
        req.metadata_mut().insert(
            "x-tenant-id",
            self.tenant_id.parse().unwrap(),
        );
        Ok(req)
    }
}
```
On `Status::code() == tonic::Code::Unauthenticated` at the call site (not inside the interceptor, which is sync), trigger the shared single-flight refresh and retry once.

### Anti-Patterns to Avoid

- **Expecting the access token in the JSON response body:** It is never there (§4, REQ-1 AC). Any SDK code path that tries `response.json::<LoginSuccessResponse>().access_token` will not compile against the actual schema — `LoginSuccessResponse` has no such field (`crates/axiam-api-rest/src/handlers/auth.rs:75-80`).
- **Hardcoding `/.well-known/jwks.json`:** AXIAM does not serve this path. The correct path is `/oauth2/jwks` (D-11, confirmed below).
- **Per-tenant JWKS endpoints:** There is none. `/oauth2/jwks` is registered at the top server scope, outside any tenant path segment (`crates/axiam-api-rest/src/server.rs:189-214`).
- **Using `backoff` (ihrwein) for D-12:** Unmaintained; use `backon` instead.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|--------------|-----|
| EdDSA JWT signature verification | Manual Ed25519 + JOSE header parsing | `jsonwebtoken::decode` + `DecodingKey::from_jwk` | Constant-time signature checks, claim validation (`exp`/`iss`/`aud`), and JWK→key conversion are all subtle correctness/security surfaces; the server itself trusts this exact crate for the same operation. |
| HMAC-SHA256 constant-time compare | `==` on hex strings | `hmac::Mac::verify_slice` | Naive string comparison is a timing side-channel; `verify_slice` is constant-time by design (already proven in `axiam-amqp/src/messages.rs:45-50`). |
| Cookie jar / Set-Cookie parsing | Manual `Set-Cookie` header parser | `reqwest::cookie::Jar` (built on the `cookie` crate) | Cookie attribute parsing (domain/path/secure/expiry rules) has many edge cases; reqwest's jar already implements RFC 6265 correctly. |
| Exponential backoff + jitter | Hand-rolled `sleep(base * 2^n)` loop | `backon::ExponentialBuilder` | Off-by-one jitter bugs and thundering-herd retry storms are a known failure class; a maintained crate avoids reinventing it per-SDK. |
| gRPC retry/backoff for `UNAVAILABLE` | Manual retry wrapper around tonic calls | `tower::retry` layer (or `backon` applied uniformly) | Tonic's channel is already a `tower::Service`; composing a `tower::retry::Retry` layer is the idiomatic, tested approach rather than wrapping every call site by hand. |

**Key insight:** Every "don't hand-roll" item above already has a *reference implementation running in this exact codebase* (server-side). The SDK's job is to mirror that proven behavior with the same crate at the same major version, not to re-derive cryptographic or protocol-parsing logic independently — independent reimplementation is exactly how cross-language SDK behavioral drift (the risk CONTRACT.md exists to prevent) creeps in.

## Common Pitfalls

### Pitfall 1: Canonical JSON for HMAC must match the server's serde field order exactly
**What goes wrong:** If the SDK's Rust struct for `AuthzRequest`/`AuditEventMessage` serializes fields in a different order, or includes/omits optional fields differently than the server, the computed HMAC will never match even with the correct key.
**Why it happens:** `serde_json::to_vec`/`to_string` serializes struct fields in **declaration order**, not alphabetical or canonical-JSON order. The server signs over its own struct's exact serialized bytes (`sign_payload(key, payload_json)` in `crates/axiam-amqp/src/messages.rs:35`), with `hmac_signature` set to `None`/omitted via `#[serde(skip_serializing_if = "Option::is_none")]` before signing.
**How to avoid:** Define the SDK's `AuthzRequest`/`AuditEventMessage` structs with **field order, types, and `#[serde(...)]` attributes byte-identical** to the server's (`crates/axiam-amqp/src/messages.rs:57-103`). Do not add a derive macro that reorders fields (e.g. some `Serialize` derives sort alphabetically when combined with certain macro helpers — plain `serde_derive` does not, but verify). Write a unit test using a known key + payload + expected hex signature as a fixture shared conceptually with the server's own test (`amqp_hmac_sign_verify_round_trip`).
**Warning signs:** HMAC verification fails 100% of the time even with the correct signing key (vs. failing only on tampered payloads) — that pattern indicates a serialization-shape mismatch, not a security event.

### Pitfall 2: `HttpOnly` cookie confusion leading to an unnecessary body-token fallback
**What goes wrong:** A developer unfamiliar with the `HttpOnly` attribute's actual scope (browser-only) may conclude the SDK "can't" read the access token and either (a) ask the server team to add a body-token field (breaking the hardened cookie-only design, REQ-1) or (b) silently downgrade to `Authorization: Bearer` header usage sourced from nowhere.
**Why it happens:** `HttpOnly` is conventionally explained as "JavaScript can't read this cookie," which is easy to over-generalize to "no client code can read this cookie."
**How to avoid:** Confirmed in this research: `reqwest::cookie::Jar` is unaffected by `HttpOnly` because it is not a browser DOM. Read the cookie directly from the jar (Pattern 1 above). No server change, no fallback, no contract violation.
**Warning signs:** Any task description proposing "add access_token to LoginSuccessResponse body" should be flagged — it contradicts both the locked D-05 decision and the REQ-1 security design this server already implements.

### Pitfall 3: Sync token access inside a sync `tonic::service::Interceptor::call`
**What goes wrong:** `Interceptor::call` is a **synchronous** function (`fn call(&mut self, req) -> Result<Request<()>, Status>`), but the `TokenManager`'s single-flight refresh guard is necessarily async (`tokio::sync::Mutex`). Calling `.lock().await` or blocking inside `call` will panic or deadlock the async runtime.
**Why it happens:** Tonic interceptors predate widespread async-trait ergonomics; the trait signature is intentionally sync for composability with `tower::Layer`.
**How to avoid:** Keep the interceptor itself simple and synchronous — it reads the *currently cached* token via a fast, non-blocking primitive (e.g. `arc_swap::ArcSwapOption<Sensitive<String>>` or a `std::sync::RwLock` read lock, not the async refresh `Mutex`). Proactive refresh (§9, D-14: refresh at `exp − 60s`) should run as a background task or be triggered from the async call sites *before* invoking the gRPC call, not from inside the interceptor. On `UNAUTHENTICATED`, the async call-site wrapper (not the interceptor) drives the single-flight refresh and retries.
**Warning signs:** `cannot block the current thread from within a runtime` panics in tests; gRPC calls hanging under concurrent load.

### Pitfall 4: `Sensitive<T>` redaction defeated by derive ordering or nested Debug
**What goes wrong:** If `Sensitive<T>` is used as a field inside another struct that derives `Debug` via `#[derive(Debug)]`, the **outer** struct's derive calls the **inner** type's `Debug` impl — which is fine *if* `Sensitive<T>`'s own `Debug` impl is hand-written to redact. But if a developer later adds `#[derive(Debug)]` directly on a struct holding a raw `String` token (bypassing `Sensitive<T>` accidentally, e.g. in a new internal struct added during a refactor), redaction breaks invisibly.
**Why it happens:** Rust's type system does not prevent storing a token as a raw `String` field; the discipline is enforced by code review / API design, not the compiler, unless the *only* path to construct/store a token is through `Sensitive<T>`.
**How to avoid:** Make `Sensitive<T>`'s inner field genuinely private (no `pub` field, no `Deref` to the raw value), with a single `expose()`/`reveal()` accessor that is `pub(crate)` (never `pub`). Implement `Debug`/`Display` to always print `"Sensitive(<redacted>)"` or `"[SENSITIVE]"` regardless of `T`. Add a `#[must_use]` doc warning on `expose()`. CI grep gate `grep -r 'eyJ' target/debug/` (success criterion #3) catches *runtime* leaks but not *source* leaks — additionally grep SDK source for `pub.*: String` fields named anything like `token`/`access`/`refresh` as a lint heuristic.
**Warning signs:** `cargo test -- --nocapture` output containing a JWT (`eyJ...` prefix) anywhere; `tracing` spans logging a `token` field without `%Sensitive` wrapping.

### Pitfall 5: Treating the gRPC channel as per-call instead of shared/lazy
**What goes wrong:** Constructing a new `tonic::transport::Channel` (TCP+TLS handshake) on every RPC call instead of reusing one lazily-connected, cloneable channel defeats HTTP/2 connection multiplexing and adds massive per-call latency.
**Why it happens:** `tonic::transport::Channel::connect()` returns a future, and it's tempting to call it inline per-request rather than once at client construction (D-04 explicitly calls for "one lazily-connected `tonic::Channel` reused across calls").
**How to avoid:** Build the channel once via `Endpoint::from_shared(url)?.connect_lazy()` (no network I/O until the first call) and store the `Channel` (which is `Clone + Send + Sync`) in the `AximaClient`. Wrap with the interceptor via `InterceptedService::new(channel, interceptor)` once.
**Warning signs:** Per-RPC latency dominated by TLS handshake time; connection count growing unbounded under load.

## Code Examples

### `Sensitive<T>` wrapper (§7)
```rust
// Idiomatic Rust newtype pattern, no external crate needed (D-discretion:
// naming the accessor — `expose()` chosen here, `reveal()` is an equally
// valid alternative).
use std::fmt;

pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Crate-internal access only — never exposed as a public API surface
    /// per §7 ("internal code accesses it via a crate/module-private method").
    pub(crate) fn expose(&self) -> &T {
        &self.0
    }
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

// Explicit non-derive: no Serialize/Deserialize, no Clone-that-leaks-via-logging
// by accident. If Clone is needed internally, derive it manually and keep it
// pub(crate) — never expose a public clone of the raw value.
```

### AMQP HMAC verify before handler invocation (§8/D-07)
```rust
// Source: protocol mirrors crates/axiam-amqp/src/messages.rs sign_payload/
// verify_payload exactly (same crates: hmac 0.12, sha2 0.10, hex 0.4).
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn verify_payload(key: &[u8], payload_json: &[u8], signature_hex: &str) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    let expected = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    mac.verify_slice(&expected).is_ok()
}

// Consumer wraps every message: strip hmac_signature, re-serialize body,
// verify BEFORE the user closure ever sees the message (D-07).
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
            let _ = delivery
                .nack(lapin::options::BasicNackOptions { requeue: false, ..Default::default() })
                .await;
            return;
        }
    };
    let sig = body.get("hmac_signature").and_then(|v| v.as_str()).map(str::to_owned);
    if let Some(obj) = body.as_object_mut() {
        obj.remove("hmac_signature"); // matches server: field set to None before signing
    }
    let canonical = serde_json::to_vec(&body).unwrap();

    let verified = match sig {
        Some(s) => verify_payload(signing_key, &canonical, &s),
        None => false, // strict mode default — missing signature rejected (§8.3)
    };

    if !verified {
        // emit security event (timestamp, exchange, routing key — NOT the hmac values)
        tracing::warn!(target: "axiam_sdk::security", "AMQP HMAC verification failed; nacking without requeue");
        let _ = delivery
            .nack(lapin::options::BasicNackOptions { requeue: false, ..Default::default() })
            .await;
        return;
    }

    handler(body).await;
    let _ = delivery.ack(lapin::options::BasicAckOptions::default()).await;
}
```

### Single-flight refresh guard (§9)
```rust
// tokio::sync::Mutex double-check pattern.
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct TokenManager {
    state: Arc<Mutex<TokenState>>,
}

struct TokenState {
    access: Option<Sensitive<String>>,
    refresh: Option<Sensitive<String>>,
    exp: Option<i64>,
}

impl TokenManager {
    /// Called by any request path that hits 401/UNAUTHENTICATED.
    /// Guarantees exactly one underlying refresh HTTP call even under
    /// concurrent callers, via the Mutex itself as the single-flight gate:
    /// the FIRST caller to acquire the lock performs the refresh; every
    /// other caller blocks on the same lock and, upon acquiring it,
    /// re-checks (double-check) whether a *newer* token already exists
    /// before deciding whether to refresh again.
    pub async fn refresh_if_needed(
        &self,
        rest_client: &reqwest::Client,
        observed_access_token: &str, // the token the caller saw fail
    ) -> Result<Sensitive<String>, AxiamError> {
        let mut guard = self.state.lock().await;

        // Double-check: if another concurrent caller already refreshed
        // while we waited for the lock, the current access token differs
        // from what this caller observed failing — just return the new one.
        if let Some(current) = &guard.access {
            if current.expose() != observed_access_token {
                return Ok(Sensitive::new(current.expose().clone()));
            }
        }

        // We are the single in-flight refresher.
        let refresh_token = guard
            .refresh
            .as_ref()
            .ok_or(AxiamError::Auth { message: "no refresh token".into() })?
            .expose()
            .clone();

        let new_tokens = do_refresh_call(rest_client, &refresh_token).await?; // 401 here => AuthError, NO retry loop (§9.3)

        guard.access = Some(Sensitive::new(new_tokens.access.clone()));
        guard.refresh = Some(Sensitive::new(new_tokens.refresh.clone()));
        guard.exp = Some(new_tokens.exp);

        Ok(Sensitive::new(new_tokens.access))
    }
}
```
**Test design:** spin up a `wiremock::MockServer`, register a `/api/v1/auth/refresh` mock with a request-count-asserting `expect(1)` (wiremock's `Mock::given(...).expect(1)` verified via `.mount(&server)` + `server.verify()`, or a shared `AtomicUsize` counter in a custom responder), fire 5 concurrent `tokio::spawn` tasks all calling `refresh_if_needed` with the same expired token, `join_all`, then assert the mock saw exactly 1 call.

### Actix-Web `FromRequest` extractor (§10)
```rust
// Source: pattern mirrors crates/axiam-api-rest/src/extractors/auth.rs
// (AuthenticatedUser / AuthenticatedServiceAccount) — same FromRequest shape,
// here implemented by the SDK as a portable extractor for SDK CONSUMERS'
// Actix-Web apps (not the AXIAM server itself).
use actix_web::{dev::Payload, FromRequest, HttpRequest};
use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone)]
pub struct AxiamUser {
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub roles: Vec<String>,
}

impl FromRequest for AxiamUser {
    type Error = crate::AxiamApiSdkError; // maps AuthError->401, AuthzError->403 (§10 contract)
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let jwks_verifier = req
                .app_data::<actix_web::web::Data<crate::token::jwks::JwksVerifier>>()
                .ok_or_else(|| crate::AxiamApiSdkError::misconfigured())?;

            // §10.1: extract from cookie OR Authorization: Bearer
            let token = req
                .cookie("axiam_access")
                .map(|c| c.value().to_owned())
                .or_else(|| {
                    req.headers()
                        .get("Authorization")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|h| h.strip_prefix("Bearer "))
                        .map(str::to_owned)
                })
                .ok_or_else(crate::AxiamApiSdkError::unauthenticated)?;

            // §10.2: verify locally against cached JWKS — no server round-trip
            let claims = jwks_verifier.verify(&token).await
                .map_err(|_| crate::AxiamApiSdkError::unauthenticated())?;

            // §10.3: inject identity into request context
            Ok(AxiamUser {
                user_id: claims.user_id,
                tenant_id: claims.tenant_id,
                roles: claims.roles,
            })
        })
    }
}
```
Optional `Transform`/`Service` middleware variant follows the same `actix-governor`-style `Transform<S, ServiceRequest>` shape already used in this codebase's own rate-limit middleware, if the planner chooses to also ship a non-extractor middleware path; the `FromRequest` extractor alone satisfies §10's literal requirement ("per-framework middleware **or** route-guard integration").

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-------------------|---------------|--------|
| `backoff` crate for retry/backoff | `backon` crate | `backoff`'s last meaningful release predates 2022; `backon` is the actively maintained successor | Use `backon` for D-12 to avoid pinning an unmaintained dependency in a brand-new, publish-bound crate. |
| Bearer-token-in-body SDKs (common in many public IAM SDKs) | Cookie-jar-only token delivery + local JWKS verification | AXIAM's REQ-1 (cookie migration) already shipped in Phase 1 of v1.0-beta | The SDK must NOT assume the "typical" pattern of `response.access_token`; AXIAM's hardened cookie-only design is the one to mirror. |

**Deprecated/outdated:**
- `backoff` (ihrwein) crate: superseded by `backon` for new Rust projects requiring active maintenance.
- Manual `Set-Cookie` header parsing: superseded by `reqwest::cookie::Jar` for any reqwest-based client (available since reqwest 0.11+, still current in 0.12).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|----------------|
| A1 | `thiserror` major version `1` vs `2` is Claude's discretion (workspace doesn't directly pin a version for SDK use, only the server's own `axiam-core::error` may use it) | Standard Stack — Core | Low: either major version satisfies D-06; cosmetic API differences only, easily resolved during planning by checking `cargo info thiserror` at execution time. |
| A2 | `jsonwebtoken`'s `DecodingKey::from_jwk` accepts an `OKP`/`Ed25519` JWK directly (not just RSA/EC) | Pattern 2 / Standard Stack | Low — this is `[VERIFIED]`, not assumed: confirmed via live working code at `crates/axiam-federation/src/oidc.rs:411` which calls exactly this function against an OKP/Ed25519 JWK in its own test suite (`oidc.rs:978` constructs `{"kty":"OKP","crv":"Ed25519",...}` and round-trips it through `DecodingKey::from_jwk`). Listed here only for completeness — confidence is HIGH, not LOW. |
| A3 | `wiremock` is the best-fit REST mock server for the single-flight refresh test (vs. a hand-rolled `axum`/`hyper` test server already used elsewhere in the codebase for gRPC) | Validation Architecture | Low — alternate choice (`mockito`, or a tiny custom `hyper` server) is also viable; `wiremock`'s async-native, request-count-assertion API is simply the most ergonomic fit and is `[VERIFIED: package-legitimacy OK]`, not unverified. |

**If this table is empty:** N/A — three low-risk items logged above for completeness; none affect the load-bearing D-05/D-11/MSRV findings, which are all `[VERIFIED]` against live repository code or live registry queries.

## Open Questions

1. **Exact `tenant_slug` vs `tenant_id` resolution for gRPC `x-tenant-id` metadata**
   - What we know: REST login accepts `tenant_id` (UUID) or `tenant_slug` (string) interchangeably (`LoginRequest` at `auth.rs:50-62`); gRPC metadata per §5 is `x-tenant-id`.
   - What's unclear: whether the gRPC server-side interceptor (`crates/axiam-api-grpc`) accepts a slug string in `x-tenant-id` or requires a UUID. The gRPC `CheckAccessRequest.tenant_id` proto field implies UUID (it's cross-validated against `ValidatedClaims.tenant_id`, which is a UUID string per `authorization.rs:81`).
   - Recommendation: the planner should have the SDK resolve `tenant_slug` → `tenant_id` UUID once at login time (the REST login response doesn't return the resolved tenant_id directly either — but the JWT claims do, via `claims.tenant_id`, decoded locally after login). Cache the resolved UUID on the client and always send the UUID form as `x-tenant-id` for gRPC, regardless of which constructor form (`tenant_slug` vs `tenant_id`) the caller used.

2. **`access_token_lifetime_secs` value (needed to compute the `exp − 60s` proactive refresh point, D-14)**
   - What we know: the cookie is set with `config.access_token_lifetime_secs` (`auth.rs:194`), and CLAUDE.md states "short-lived access tokens (15 min)" as the project security standard.
   - What's unclear: the exact configured value in this deployment (it's a server-side `AuthConfig` setting, not hardcoded) — the SDK should not hardcode 15 minutes; it should derive `exp` directly from the decoded JWT claims after each login/refresh (the JWT's own `exp` claim is authoritative) rather than from a separately-configured constant.
   - Recommendation: planner should design `TokenManager` to read `exp` from the verified JWT claims (Pattern 2) rather than from any hardcoded duration — this makes the SDK robust to the server's configured lifetime regardless of value.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|--------------|-----------|---------|----------|
| Rust toolchain | All SDK code | ✓ | 1.94.1 (cargo) | — |
| `buf` CLI | gRPC codegen (D-09, inherited Phase 15) | Not probed this session (CI-only concern per Phase 15 D-01/D-02; local dev can skip via committed/cached stubs) | — | `cargo publish --dry-run` path bundles pre-generated stubs (see Code Examples / D-09 below); local `cargo build` without `buf` installed should still work for the `rest`-only feature set (no gRPC codegen needed when `grpc` feature is off). |
| crates.io network access | `cargo publish`, `cargo info` lookups | ✓ (used throughout this research session) | — | — |
| RabbitMQ / SurrealDB / live AXIAM server | Manual/integration smoke testing | Not required for this phase — SDK is a pure client with no server dependency; all behavioral tests use mocks (`wiremock` for REST, an in-process tonic test server for gRPC, an in-memory/mocked AMQP channel or a local RabbitMQ container if integration-level AMQP tests are added) | — | — |

**Missing dependencies with no fallback:** none — this phase has no hard external runtime dependency; it is a library crate validated entirely via mocks and unit/integration tests.

**Missing dependencies with fallback:** `buf` CLI for local gRPC stub regeneration — documented fallback is to rely on the CI-bundled/build.rs-driven codegen path; a contributor without `buf` installed can still build+test the `rest`/`amqp` feature combination.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `cargo test` (built-in) + `tokio::test` for async + `wiremock` for REST mocking |
| Config file | `sdks/rust/Cargo.toml` `[dev-dependencies]` (no separate test config file needed) |
| Quick run command | `cargo test -p axiam-sdk --lib` |
| Full suite command | `cargo test -p axiam-sdk --all-features` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|---------------|
| RUST-01 (SC#1) | `login()` returns typed `LoginResult{mfa_required}`; `verify_mfa` completes two-phase flow | integration (wiremock-mocked REST) | `cargo test -p axiam-sdk login_mfa_flow -- --exact` | ❌ Wave 0 |
| RUST-01 (SC#2) | 5 concurrent requests on expired token ⇒ exactly 1 refresh call | integration (wiremock request-count assertion) | `cargo test -p axiam-sdk single_flight_refresh -- --exact` | ❌ Wave 0 |
| RUST-01 (SC#3) | `grep -r 'eyJ' target/debug/` returns empty | CI-grep (not a `cargo test`) | `cargo build && grep -r 'eyJ' target/debug/ \| wc -l` (expect 0) | ❌ Wave 0 — add as a CI step, not a Rust test |
| RUST-01 (SC#3, supplementary) | `Sensitive<T>` Debug/Display never print raw value | unit | `cargo test -p axiam-sdk sensitive_redaction -- --exact` | ❌ Wave 0 |
| RUST-01 (SC#4) | gRPC `CheckAccess`/`BatchCheckAccess` succeed via tonic 0.14 | integration (in-process tonic test server, mirroring `crates/axiam-api-grpc` test harness pattern from `07-03-PLAN.md`) | `cargo test -p axiam-sdk --features grpc grpc_check_access -- --exact` | ❌ Wave 0 |
| RUST-01 (SC#4) | AMQP consumer verifies HMAC-SHA256 before processing; nacks without requeue on signature failure | unit + integration (HMAC vectors byte-identical to server reference; mocked/local RabbitMQ for nack-without-requeue behavior assertion) | `cargo test -p axiam-sdk --features amqp amqp_hmac -- --exact` | ❌ Wave 0 |
| RUST-01 (SC#5) | `cargo publish --dry-run` succeeds | CI smoke (not a unit test) | `cargo publish --dry-run -p axiam-sdk` | ❌ Wave 0 — CI workflow step |
| §1-§10 contract conformance | Method names, error mapping, CSRF header forwarding, tenant header injection, TLS strictness, no insecure-skip surface | unit + CI-grep | `cargo test -p axiam-sdk contract_conformance` + `grep -rn 'danger_accept_invalid_certs\|insecure' sdks/rust/src/` (expect 0) | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p axiam-sdk --lib` (fast unit tests: `Sensitive<T>` redaction, error mapping, HMAC sign/verify vectors, JWKS `kid` lookup logic)
- **Per wave merge:** `cargo test -p axiam-sdk --all-features` (full integration suite: wiremock REST flows, in-process gRPC server, single-flight concurrency test, AMQP HMAC nack behavior)
- **Phase gate:** Full suite green + `cargo publish --dry-run -p axiam-sdk` succeeds + `grep -r 'eyJ' target/debug/` returns empty, before `/gsd-verify-work`

### Reference Oracles

- **HMAC byte-identical verification:** `crates/axiam-amqp/src/messages.rs` `sign_payload`/`verify_payload` functions are the oracle. The SDK's test suite should include the literal same fixture values used in the server's own test (`key = b"test-amqp-signing-key"`, `payload = b"{\"tenant_id\":\"...\",\"action\":\"read\"}"`) and assert the SDK's `sign_payload` produces an **identical hex string** to what the server would produce, proving wire-format compatibility, not just internal self-consistency.
- **JWKS/EdDSA verification:** `crates/axiam-federation/src/oidc.rs` test module (`oidc.rs:660+`) is the oracle for constructing valid Ed25519 JWK test fixtures (`{"kty":"OKP","crv":"Ed25519","kid":"known-key",...}`) and JWT signing via `jsonwebtoken::{Header, encode}` with `Algorithm::EdDSA` — the SDK's JWKS verification unit tests should reuse this exact fixture-construction approach.
- **Single-flight refresh:** A `wiremock::MockServer` standing in for `POST /api/v1/auth/refresh`, with a shared `Arc<AtomicUsize>` call counter (or `wiremock`'s built-in `.expect(1)` verification), is the test oracle — not the live AXIAM server. 5 `tokio::spawn` tasks call `refresh_if_needed` concurrently against the same expired token; assert the counter is exactly 1 after `join_all`.
- **gRPC CheckAccess/BatchCheckAccess:** An in-process `tonic` test server implementing the same `AuthorizationService` trait as `crates/axiam-api-grpc/src/services/authorization.rs` (but with a stub `AuthorizationEngine` returning canned `AccessDecision`s) serves as the oracle — avoids needing a live AXIAM server for SDK CI while still exercising the real generated gRPC stub code path end-to-end.

### Wave 0 Gaps

- [ ] `sdks/rust/tests/single_flight_refresh_test.rs` — covers RUST-01 SC#2, needs `wiremock` dev-dependency added
- [ ] `sdks/rust/tests/sensitive_redaction_test.rs` — covers RUST-01 SC#3
- [ ] `sdks/rust/tests/amqp_hmac_test.rs` — covers RUST-01 SC#4 (AMQP half), needs fixture values copied from `crates/axiam-amqp/src/messages.rs` test module
- [ ] `sdks/rust/tests/grpc_check_access_test.rs` — covers RUST-01 SC#4 (gRPC half), needs an in-process tonic test server harness (no existing shared harness in `sdks/rust/` yet — this is genuinely new infrastructure, unlike the server-side `axiam-api-grpc` which already has one per Phase 7 (`07-03-PLAN.md`))
- [ ] Framework install: `cargo add --dev wiremock tokio-test` — none of the SDK's dev-dependencies exist yet (crate is currently a doc-only placeholder per Phase 15 scaffold)
- [ ] CI workflow step for `grep -r 'eyJ' target/debug/` — does not yet exist in `.github/workflows/sdk-ci-rust.yml` (file exists from Phase 15 scaffold but its content was not inspected in this research session — planner should verify/add this step)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|---------------------|
| V2 Authentication | yes | SDK consumes server-issued tokens only; never implements its own credential storage beyond `Sensitive<T>` in-memory wrapping. No password handling in the SDK itself beyond passing through to `login()`. |
| V3 Session Management | yes | Cookie jar persistence per §4; single-flight refresh per §9; no client-side session ID generation. |
| V4 Access Control | yes | `check_access`/`batch_check` are pure pass-throughs to server `AuthorizationEngine` — SDK makes no local authz decisions beyond optional TTL decision-cache (not in this phase's scope per requirement baseline). |
| V5 Input Validation | yes | `tenant_slug`/`tenant_id` non-optional at construction (§5); `with_custom_ca` rejects non-PEM input at construction time (§6); request DTOs use `serde` typed structs, not raw JSON manipulation. |
| V6 Cryptography | yes | Never hand-rolled — `jsonwebtoken` (EdDSA verification), `hmac`+`sha2` (AMQP HMAC), `rustls` (via reqwest's `rustls-tls` feature, already the workspace-pinned TLS backend) are the only crypto surfaces, all maintained, audited crates matching the server's own choices. |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|------------------------|
| Token leakage via debug/log output | Information Disclosure | `Sensitive<T>` (§7) + CI grep gate (`grep -r 'eyJ' target/debug/`) |
| AMQP message tampering/spoofing | Tampering / Spoofing | Mandatory HMAC-SHA256 verification before handler invocation (§8), constant-time compare, nack-without-requeue + security event log on failure |
| Thundering-herd token refresh (DoS-adjacent / resource exhaustion) | Denial of Service | Single-flight `tokio::sync::Mutex` guard (§9) |
| TLS downgrade / cert bypass | Spoofing / Tampering | §6 absolute prohibition on any insecure-skip API; CI lint gate (`grep -rn` for bypass patterns) should be added to `sdk-ci-rust.yml` mirroring the Go SDK's `InsecureSkipVerify` grep gate pattern (ROADMAP Phase 18 SC#3) |
| CSRF on state-changing requests | Tampering | §3 — auto-forward `X-CSRF-Token` from the `axiam_csrf` cookie (not `HttpOnly`, by design — it's meant to be readable) on every POST/PUT/PATCH/DELETE |
| Cross-tenant data exposure via wrong `x-tenant-id` | Elevation of Privilege | §5 — tenant identifier is non-optional at construction and injected on every request; server-side cross-validates body/metadata tenant against JWT claims regardless (defense in depth already proven server-side at `authorization.rs:90-94`) |

## Sources

### Primary (HIGH confidence — verified against this repository's own working code or live registry queries)
- `crates/axiam-api-rest/src/handlers/auth.rs` — login/verify_mfa/refresh/logout handlers; confirms tokens are cookie-only, never in JSON body (D-05)
- `crates/axiam-api-rest/src/middleware/csrf.rs` — exact cookie names (`axiam_access`, `axiam_refresh`, `axiam_csrf`) and CSRF exempt-path list
- `crates/axiam-api-rest/src/handlers/oauth2.rs:297-318` — `GET /oauth2/jwks` handler (D-11 exact path)
- `crates/axiam-api-rest/src/server.rs:184-215` — route registration confirming `/oauth2/jwks` is org-wide, not tenant-scoped
- `crates/axiam-oauth2/src/oidc.rs:85-134` — `JwksDocument`/`build_jwks`, confirms `kty: OKP, crv: Ed25519, alg: EdDSA`, deterministic `kid`
- `crates/axiam-federation/src/oidc.rs:370-429, 600-657` — live, tested EdDSA/JWKS verification pattern using `jsonwebtoken::DecodingKey::from_jwk`, `kid` rotation/refetch logic
- `crates/axiam-amqp/src/messages.rs` — §8 HMAC reference implementation (`sign_payload`/`verify_payload`, `hmac_signature` field handling, message types)
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC `check_access`/`batch_check_access` semantics, claims cross-validation pattern
- `proto/axiam/v1/authorization.proto`, `token.proto` — gRPC message shapes
- `crates/axiam-api-rest/src/extractors/auth.rs` — `FromRequest` extractor pattern reference (cookie-then-header fallback, claims caching)
- Workspace root `Cargo.toml` (lines 21, 25, 33, 36, 49-56, 63, 67-71) — pinned dependency versions, workspace `rust-version = "1.93"`, `edition = "2024"`
- `Cargo.lock` — confirms tonic 0.14.6 + reqwest 0.12.28 + lapin 4.10.0 + jsonwebtoken 10.4.0 already resolve together with zero conflicts in this exact workspace
- `cargo info <pkg>` (live crates.io queries, this session) for tonic, reqwest, lapin, jsonwebtoken, tokio, backon, tower — exact published versions + MSRV floors
- `gsd-tools query package-legitimacy check --ecosystem crates` (this session) — registry-verified OK verdicts for all 13 candidate packages
- `sdks/CONTRACT.md` §1-§10 — binding behavioral contract
- `.planning/phases/15-sdk-foundation/15-CONTEXT.md` — inherited buf-codegen/publish-bundling and package-identity decisions
- `sdks/buf.gen.yaml` — confirms `rust/src/gen` as the buf output directory for Rust prost+tonic plugins

### Secondary (MEDIUM confidence)
- WebSearch confirming `backon` as the actively-maintained successor to the unmaintained `backoff` crate (cross-checked against `cargo info backon` showing recent-enough MSRV and high download count)

### Tertiary (LOW confidence)
- None — all claims in this research trace to either live repository code, live registry queries, or the package-legitimacy seam. See Assumptions Log for the small number of lower-stakes discretionary items.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — every version pin cross-checked against both `cargo info` (live registry) and the existing workspace `Cargo.lock`/`Cargo.toml`
- Architecture: HIGH — every pattern (cookie jar read, JWKS verify, HMAC verify, FromRequest extractor) is a direct mirror of working code already in this repository, not an externally-sourced convention
- Pitfalls: HIGH — derived from direct comparison of server-side behavior (cookie-only tokens, HttpOnly semantics, sync interceptor signature) against what a naive SDK implementation would likely get wrong

**Research date:** 2026-06-30
**Valid until:** 2026-07-30 (30 days — stable Rust ecosystem, but re-verify `cargo info` versions if planning is delayed, since tonic/reqwest/lapin/jsonwebtoken all ship periodic patch releases)
