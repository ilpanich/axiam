# Phase 25: Security Hardening II — Pattern Map

**Mapped:** 2026-07-04
**Files analyzed:** 20 (7 findings, SECHRD-02/05/06/07/08/09/10)
**Analogs found:** 20 / 20 (every fix mirrors an existing in-repo pattern — no greenfield architecture this phase)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/axiam-federation/src/ssrf.rs` (NEW) | utility | request-response (outbound fetch guard) | `crates/axiam-api-rest/src/webhook.rs` (`is_private_ip`/`resolve_and_validate_host`) + `crates/axiam-federation/src/jwks_cache.rs:225-274` (`is_private_jwks_ip`) | exact (byte-identical duplicate logic already exists in both files — this is a dedup+extend, not new design) |
| `crates/axiam-federation/src/jwks_cache.rs` (MODIFIED — route `fetch_jwks` through `ssrf.rs`) | service | request-response | itself (pre-refactor) | exact |
| `crates/axiam-federation/src/oidc.rs` (MODIFIED — `discover`/`exchange_code`) | service | request-response | `jwks_cache.rs` fetch path | role-match |
| `crates/axiam-federation/src/saml.rs` (MODIFIED — `fetch_idp_metadata`) | service | request-response | `jwks_cache.rs` fetch path | role-match |
| `crates/axiam-api-rest/src/webhook.rs` (MODIFIED — delivery loop pins IP) | service | request-response (outbound, retry) | itself (`resolve_and_validate_host` + backoff loop at lines ~200-260) | exact |
| `crates/axiam-pki/src/mtls.rs` (MODIFIED — add issuing-CA check) | service | request-response (auth) | itself — leaf-cert check at lines 59-70 is the mirror source for the new issuer check | exact |
| `crates/axiam-server/src/cleanup.rs` (MODIFIED — reorder purge, extract `run_erasure_pipeline`, fix `org_id`) | service | batch/CRUD (GDPR purge + export) | itself (existing `purge_single_user` body) | exact |
| `crates/axiam-db/src/repository/session.rs` (MODIFIED — add `list_by_user`) | model/repository | CRUD | sibling repos' existing `get_by_*`/list methods (see below) | role-match |
| `crates/axiam-db/src/repository/export_job.rs` (MODIFIED — widen dedup filter) | model/repository | CRUD | itself (`has_pending_for_user`, lines ~99-126) | exact |
| `crates/axiam-api-rest/src/handlers/federation.rs` (MODIFIED — `oidc_authorize`/`oidc_callback` nonce-from-state) | controller | request-response | itself — `oidc_start_public`/`oidc_callback_public` (lines 1106-1300) is the exact working mirror | exact |
| `crates/axiam-amqp/src/messages.rs` (MODIFIED — HKDF per-tenant subkey derivation) | utility | transform (sign/verify) | itself (`sign_payload`/`verify_payload`, lines 26-46) | exact |
| `crates/axiam-amqp/src/audit_consumer.rs` (MODIFIED — mandatory signing_key, remove fail-open branch) | service | event-driven (consumer) | itself; mirror `authz_consumer.rs`'s identical structure | exact |
| `crates/axiam-amqp/src/authz_consumer.rs` (MODIFIED — same) | service | event-driven | `audit_consumer.rs` (near-identical twin) | exact |
| `crates/axiam-amqp/src/mail_consumer.rs` (MODIFIED — add backoff before republish) | service | event-driven (retry) | `crates/axiam-api-rest/src/webhook.rs` exponential-backoff loop (lines ~210-220) | role-match (only in-repo backoff precedent) |
| `crates/axiam-amqp/src/config.rs` (MODIFIED — `signing_key` mandatory-with-dev-default) | config | — | itself (current `Option<String>` field + `Default` impl) | exact |
| `crates/axiam-core/src/models/federation.rs` (MODIFIED — `skip_serializing` + manual `Debug`) | model | transform (serde) | `crates/axiam-core/src/models/certificate.rs:61-63` (`encrypted_private_key` `#[serde(skip_serializing)]`) | exact |
| `crates/axiam-core/src/models/certificate.rs` (MODIFIED — manual `Debug` redacting CA/PGP blobs) | model | transform (serde) | itself (already has `skip_serializing` for `Serialize`; needs the same discipline extended to `Debug`) | exact |
| `crates/axiam-db/src/repository/federation_config.rs` (MODIFIED — narrow `SELECT *` in `list()`) | model/repository | CRUD | itself | exact |
| `k8s/network-policy/server-egress.yml` (MODIFIED — SMTP rule + CIDR exclusions) | config | — | itself (existing `443` rule + `# TODO` placeholders) | exact |
| `k8s/server/secret.yml` + `.github/workflows/ci.yml` (MODIFIED — secret keys + `AXIAM__…` prefix fix) | config | — | itself | exact |

## Pattern Assignments

### `crates/axiam-federation/src/ssrf.rs` (NEW utility, request-response)

**Analogs:** `crates/axiam-federation/src/jwks_cache.rs:225-274` and `crates/axiam-api-rest/src/webhook.rs:55-95` (byte-identical duplicate guard logic in both — consolidate, don't invent).

**IP classification pattern to copy verbatim** (`webhook.rs:55-73`, identical to `jwks_cache.rs:225-`):
```rust
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_broadcast() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0 == 0xfe80) // fe80::/10
                || (v6.segments()[0] & 0xfe00 == 0xfc00) // fc00::/7
        }
    }
}
```

**Resolve pattern to extend with pinning** (`webhook.rs:80-95`, currently validates but does NOT pin — the anti-pattern this phase fixes):
```rust
async fn resolve_and_validate_host(url: &str) -> Result<(), WebhookError> {
    let parsed = url::Url::parse(url).map_err(|_| WebhookError::InvalidUrl)?;
    let host = parsed.host_str().ok_or(WebhookError::InvalidUrl)?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host, port)).await.map_err(|_| WebhookError::ResolveFailed)?;
    for addr in addrs {
        if is_private_ip(addr.ip()) {
            return Err(WebhookError::SsrfBlocked);
        }
    }
    Ok(())   // <-- validates, but the caller's later client.post() re-resolves independently: NO PIN
}
```
**Fix contract (D-01a/b/c):** the new `ssrf.rs` must return the validated `IpAddr` itself (not `()`), and the caller must build a fresh `reqwest::Client::builder().resolve(host, SocketAddr::new(ip, port)).redirect(Policy::none())` from it — see RESEARCH.md Pattern 1 for the full `guarded_fetch` orchestration (resolve → validate A+AAAA → pin → send → on 3xx re-run whole guard against `Location`, max 3 hops, using `Url::join` for relative redirects).

**Error type convention to mirror:** `webhook.rs`'s `WebhookError` enum (`thiserror::Error`, `InvalidUrl`/`ResolveFailed`/`SsrfBlocked` variants) — give `ssrf.rs`'s `SsrfError` the same shape so all 4 call sites (JWKS, OIDC, SAML, webhook) get identical error semantics.

**Call-site conversion pattern:** each of `jwks_cache::fetch_jwks` (`:262-274`), `oidc::discover`/`exchange_code` (`:91,109,782` — raw `reqwest::Client` construction, no guard today), `saml::fetch_idp_metadata` (`:94,110,1170` — same gap) replaces its ad-hoc client-build-and-send with a single call to the new shared `guarded_fetch(url, |client, u| client.get(u))`.

---

### `crates/axiam-api-rest/src/webhook.rs` (MODIFIED, service/request-response)

**Analog:** itself. Backoff-retry loop to keep intact (only the per-attempt send changes to route through `ssrf::guarded_fetch`):
```rust
// lines ~210-220 — the ONLY in-repo exponential-backoff precedent; mirror
// this shape for the AMQP mail_consumer.rs backoff (SECHRD-08/D-05d):
let multiplier = webhook.retry_policy.backoff_multiplier;
for attempt in 0..=max_retries {
    if attempt > 0 {
        let delay_secs = (initial_delay as f64) * multiplier.powi((attempt - 1) as i32);
        tokio::time::sleep(std::time::Duration::from_secs_f64(delay_secs)).await;
    }
    // SEC-019: Re-resolve host at each delivery attempt to defeat...
```
**Error-to-response mapping convention** (fail-closed, `ServiceUnavailable` not a raw 500 — mirror for AMQP signing-key-unset / mTLS CA-not-Active):
```rust
impl From<WebhookError> for crate::error::AxiamApiError {
    fn from(err: WebhookError) -> Self {
        match err {
            WebhookError::EncryptionKeyMissing => {
                axiam_core::error::AxiamError::ServiceUnavailable(
                    "webhook subsystem unavailable: encryption key not configured".to_string(),
                ).into()
            }
            other => axiam_core::error::AxiamError::Crypto(other.to_string()).into(),
        }
    }
}
```

---

### `crates/axiam-pki/src/mtls.rs` (MODIFIED, service/request-response)

**Analog:** itself — leaf-cert check (`:58-66`) is the literal template for the new issuing-CA check inserted before `verify_signature` (`:97-103`).

**Pattern to mirror exactly:**
```rust
// EXISTING leaf check (mtls.rs:58-66):
if cert.status != CertificateStatus::Active {
    return Err(AxiamError::Certificate("certificate is not active".into()));
}
let now = Utc::now();
if now < cert.not_before || now > cert.not_after {
    return Err(AxiamError::Certificate("certificate is expired or not yet valid".into()));
}
// ... ca_cert already fetched via self.ca_cert_repo.get_by_issuer_id(cert.issuer_ca_id) at :74-83 ...
// NEW — insert before client_x509.verify_signature(...) call (~:97):
if ca_cert.status != CertificateStatus::Active {
    return Err(AxiamError::Certificate("issuing CA is not active".into()));
}
if now < ca_cert.not_before || now > ca_cert.not_after {
    return Err(AxiamError::Certificate("issuing CA certificate is expired or not yet valid".into()));
}
```
Both `CaCertificate` and the leaf `Certificate`/`DeviceIdentity` model already expose `status: CertificateStatus`, `not_before`, `not_after` — no schema change needed. `ca_cert_repo.get_by_issuer_id` fails closed today with a `Certificate` error if no CA is found; keep that discipline for the new check (return `AxiamError::Certificate`, never `unwrap`/`expect`).

---

### `crates/axiam-api-rest/src/handlers/federation.rs` (MODIFIED, controller, request-response)

**Analog:** itself — `oidc_start_public`/`oidc_callback_public` (lines 1106-1300) is a byte-for-byte working reference for what `oidc_authorize`/`oidc_callback` (lines 526-648) must become.

**Working pattern to replicate (public path, `:1255-1268`):**
```rust
let login_state = login_state_repo
    .consume_by_state(&b.state)
    .await?
    .ok_or_else(|| {
        AxiamApiError(AxiamError::AuthenticationFailed {
            reason: "state not found or expired".into(),
        })
    })?;
let tenant_id = login_state.tenant_id;
let config_id = login_state.federation_config_id;
// Nonce comes from the state row — NOT from the HTTP body (T-04-30).
let expected_nonce = login_state.nonce.clone();
```
And the corresponding start-side persistence (`:1156-1200`, `oidc_start_public`):
```rust
let state = random_base64url();
let nonce = random_base64url();
let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
// ... build_authorization_url(tenant_id, config_id, &redirect_uri, &state, &nonce) ...
login_state_repo
    .insert(&axiam_core::repository::FederationLoginState {
        state: state.clone(), nonce, tenant_id,
        federation_config_id: b.federation_config_id,
        redirect_uri: b.redirect_uri, expires_at,
        request_id: String::new(),
    })
    .await?;
```
**Buggy pattern to remove (`oidc_authorize`/`oidc_callback`, `:544,571,613,638`):** currently `req.nonce` (client-supplied, from `OidcAuthorizeRequest`/`OidcCallbackRequest` JSON body) is validated only for non-emptiness and passed straight to `build_authorization_url`/`handle_callback` — never checked against server state. Fix: add `login_state_repo: web::Data<SurrealFederationLoginStateRepository<C>>` as a handler parameter (already registered as `app_data` in `main.rs:738`, used by the public path — a drop-in addition) and apply the exact `oidc_start_public`/`oidc_callback_public` plumbing above.

---

### `crates/axiam-amqp/src/messages.rs` + `config.rs` + `audit_consumer.rs`/`authz_consumer.rs` (MODIFIED)

**Analog:** the file's own existing shared-key HMAC path.

**Current shared-key sign/verify to extend with HKDF per-tenant derivation** (`messages.rs:33-49`):
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
Keep `sign_payload`/`verify_payload` signatures unchanged (they take `key: &[u8]` already); add a new `derive_tenant_key(master: &[u8], tenant_id: Uuid, key_version: u8) -> [u8; 32]` using `hkdf::Hkdf::<Sha256>::new(Some(salt), master).expand(info, &mut out)` with `info = b"axiam-amqp-v1" || tenant_id.as_bytes()` (D-05b), and call it at each producer/consumer call site instead of passing the raw master key.

**Anti-pattern to remove — the fail-open branch, present identically in BOTH consumers** (`audit_consumer.rs:91-99`, `authz_consumer.rs:88-98`):
```rust
if let Some(ref key) = signing_key {
    let sig_ok = envelope.hmac_signature.as_deref()
        .is_some_and(|sig| verify_payload(key, &canonical_bytes, sig));
    if !sig_ok {
        warn!(/* ... */);
        // (currently still processes the message after warning — SECHRD-08 anti-pattern)
    }
} else {
    warn!(/* "processing unsigned message" — the fail-open path to delete */);
}
```
**Config field to make mandatory** (`config.rs:19-21`, currently `Option<String>` with an explicit "migration mode" doc comment — the exact anti-pattern D-05c closes):
```rust
/// When `None`, signatures are accepted but not required (migration mode).
/// In production this MUST be set; consumers log a warning if absent.
#[serde(default)]
pub signing_key: Option<String>,
```
Fix: `signing_key: Vec<u8>` (or keep `Option<String>` at the raw-env layer but resolve to a mandatory `Vec<u8>` before constructing consumers — ship a documented dev-key default in `.env.example`/`config` per D-05c so local/test runs still work without an explicit `AXIAM__AMQP__SIGNING_KEY`).

**`mail_consumer.rs` backoff insertion point** (`:325-345`, `SendOutcome::RetryNeeded` branch) — currently republishes with zero delay; insert a `tokio::time::sleep` scaled by `retry_msg.attempt_count` **before** `channel.basic_publish`, mirroring `webhook.rs`'s `(initial_delay as f64) * multiplier.powi((attempt-1) as i32)` shape (see webhook.rs excerpt above — this is the only in-repo backoff precedent).

**`cleanup.rs` `org_id: Uuid::nil()` fix (`:508`)** — resolve the real `org_id` from the tenant before building the ExportReady message (producer-side, planner's discretion per D-05d); mirror how `oidc_start_public` resolves `org_id`/`tenant_id` from slugs (`federation.rs:1123-1157`) as the "resolve real ID before use, never a placeholder" convention already established in this codebase.

---

### `crates/axiam-server/src/cleanup.rs` (MODIFIED, service, batch)

**Analog:** itself (Pattern 3 in RESEARCH.md — extraction, not new architecture).

**Anti-pattern to remove — non-fatal `pseudonymize_actor`** (comment at `:328-336` explicitly says "Errors here are logged but not fatal" — an intentional prior design choice, not an oversight):
```rust
if let Err(e) = self.audit_repo.pseudonymize_actor(tenant_id, user_id, pseudonym).await {
    tracing::warn!(error = %e, "pseudonymize_actor failed, continuing purge");
}
```
**Fix — propagate with `?`, and move erasure-proof write to literally last:**
```rust
async fn run_erasure_pipeline<A, EP, U>(
    audit_repo: &A, erasure_proof_repo: &EP, user_repo: &U,
    tenant_id: Uuid, user_id: Uuid, pseudonym: &str, email_hash: &str,
) -> AxiamResult<()>
where A: AuditLogRepository, EP: ErasureProofRepository, U: UserRepository {
    audit_repo.pseudonymize_actor(tenant_id, user_id, pseudonym).await?;   // FATAL now
    user_repo.anonymize_user(tenant_id, user_id, email_hash, pseudonym).await?;
    erasure_proof_repo.create(CreateErasureProof {
        pseudonym: pseudonym.into(), tenant_id, erased_at: Utc::now(),
    }).await?;   // LAST — DB UNIQUE index on user_id makes a retry's duplicate no-op (D-03b)
    Ok(())
}
```
`CleanupTask::purge_single_user` is NOT generic over repo traits (concrete `Arc<SurrealXxxRepository<C>>` fields at `:54-80`) — extract this free function so a unit test can inject a synthetic failing `AuditLogRepository` double without a larger refactor; this mirrors the existing test-seam gap already documented in `axiam-server/tests/cleanup_task.rs`'s own comment ("This does NOT exercise `CleanupTask` itself...").

---

### `crates/axiam-db/src/repository/export_job.rs` (MODIFIED, model/CRUD)

**Analog:** itself — widen the existing status filter, same query shape:
```rust
// CURRENT (only 'queued'):
"SELECT count() AS total FROM export_job \
 WHERE tenant_id = $tenant_id AND user_id = $user_id \
 AND status IN ['queued'] GROUP ALL"
// FIX (D-03d):
"SELECT count() AS total FROM export_job \
 WHERE tenant_id = $tenant_id AND user_id = $user_id \
 AND status IN ['queued', 'ready', 'failed'] GROUP ALL"
```

### `crates/axiam-db/src/repository/session.rs` (NEW method `list_by_user`)

**No existing analog method** — `SessionRepository` trait (`axiam-core/src/repository.rs:461`) only has `get_by_id`/`get_by_token_hash`/`invalidate*`/`cleanup_expired`. Model the new `list_by_user(tenant_id, user_id) -> Vec<Session>` after sibling repos' existing list-by-scope methods in the same file (`get_by_id`/`cleanup_expired` query shape — tenant-scoped `SELECT * FROM session WHERE tenant_id = $tenant_id AND user_id = $user_id`). Export exactly `{id, created_at, expires_at, ip_address, user_agent}` per session in `cleanup.rs`'s export aggregation — the `Session` model has **no `last_seen` field** (do not invent one) and `token_hash` must be excluded (live credential material, D-03c).

---

### `crates/axiam-core/src/models/federation.rs` + `certificate.rs` (MODIFIED, model, serde)

**Analog:** `certificate.rs:59-63` — the existing, working `skip_serializing` convention:
```rust
/// AES-256-GCM encrypted private key (only for signing CAs).
#[serde(skip_serializing)]
#[schema(read_only)]
pub encrypted_private_key: Option<Vec<u8>>,
```
**Gap to close:** `FederationConfig` (`federation.rs:16-48`) has `#[derive(Debug, Clone, Serialize, Deserialize)]` with **zero** `skip_serializing` on `client_secret: String` / `client_secret_ciphertext: Option<String>` / `client_secret_nonce: Option<String>` / `client_secret_key_version: Option<i64>` — apply the same `#[serde(skip_serializing)]` attribute used above to all four fields.
**Additional gap (both models):** `#[derive(Debug, ...)]` on `CaCertificate` and `FederationConfig` means `Debug` still prints `encrypted_private_key`/`client_secret*` in full — `#[serde(skip_serializing)]` only affects `Serialize`, not `{:?}`. Replace `derive(Debug)` with a manual `impl fmt::Debug` that redacts these fields (e.g., prints `"[REDACTED]"` in place of the secret), following the same struct field order as the derive would have produced, so log/trace output stays useful for non-secret fields.
**List-query hydration gap:** `crates/axiam-db/src/repository/federation_config.rs:214,362` uses `SELECT *` for `list()`, needlessly pulling `client_secret_ciphertext`/`_nonce` for every row of a list view — narrow the projection to exclude those columns (mirror any existing narrowed-`SELECT` pattern elsewhere in the repo layer if one exists; otherwise write an explicit field list).

---

### `k8s/network-policy/server-egress.yml` + `k8s/server/secret.yml` + `.github/workflows/ci.yml` (MODIFIED, config)

**Analog:** itself — the `443` rule's existing `# TODO` placeholders are the template for the new SMTP rule:
```yaml
# server-egress.yml:42-43 (existing TODO placeholders to fill, not a new section):
# TODO: operator must add cluster pod CIDR here (e.g., 10.244.0.0/16)
# TODO: operator must add cluster service CIDR here (e.g., 10.96.0.0/12)
```
Add a new SMTP egress rule (ports 25/465/587) shaped like the existing `443` rule but scoped `to: [ipBlock: cidr: <SMTP_RELAY_CIDR_PLACEHOLDER>]` with a fail-closed/empty default (D-07b — never `0.0.0.0/0:587`), parameterized via kustomize/Helm values (D-07a).

**Confirmed CI bug to fix** (`.github/workflows/ci.yml:229-233`):
```yaml
# WRONG (current):
env:
  AXIAM_DATABASE__URL: "ws://localhost:8000"
  AXIAM_DATABASE__USERNAME: root
  AXIAM_DATABASE__PASSWORD: root
  AXIAM_AMQP__URL: "amqp://localhost:5672"
# FIX — matches AppConfig's actual field name (`db`, not `database`) and
# main.rs:767's .separator("__") with prefix "AXIAM":
env:
  AXIAM__DB__URL: "ws://localhost:8000"
  AXIAM__DB__USERNAME: root
  AXIAM__DB__PASSWORD: root
  AXIAM__AMQP__URL: "amqp://localhost:5672"
```

## Shared Patterns

### Fail-closed error mapping (ASVS-aligned "operator-actionable, not a raw 500")
**Source:** `crates/axiam-api-rest/src/webhook.rs` `impl From<WebhookError> for AxiamApiError` (`EncryptionKeyMissing` → `AxiamError::ServiceUnavailable`, not a panic or generic 500).
**Apply to:** AMQP signing-key-unset startup failure, mTLS CA-not-Active refusal — Phase 23 already established `AxiamError::ServiceUnavailable`→503 for a missing key as the precedent (per RESEARCH.md "Established Patterns").

### SSRF IP classification (byte-identical duplicate today — the dedup target)
**Source:** `crates/axiam-federation/src/jwks_cache.rs:225` (`is_private_jwks_ip`) and `crates/axiam-api-rest/src/webhook.rs:55-73` (`is_private_ip`) — identical bodies.
**Apply to:** the new shared `axiam-federation::ssrf` module; all 4 fetch call sites (JWKS, OIDC discovery/token, SAML metadata, webhook delivery).

### Secret non-serialization via `#[serde(skip_serializing)]`
**Source:** `crates/axiam-core/src/models/certificate.rs:61-63` (`encrypted_private_key`).
**Apply to:** `FederationConfig`'s 4 secret fields (`client_secret`, `client_secret_ciphertext`, `client_secret_nonce`, `client_secret_key_version`); also extend the discipline to manual `Debug` impls on both `CaCertificate` and `FederationConfig` (current gap: `derive(Debug)` still prints these fields even where `skip_serializing` is present).

### Exponential backoff retry loop
**Source:** `crates/axiam-api-rest/src/webhook.rs` delivery loop (`(initial_delay as f64) * multiplier.powi((attempt-1) as i32)`, `tokio::time::sleep` before each retry attempt after the first).
**Apply to:** `crates/axiam-amqp/src/mail_consumer.rs`'s zero-delay republish on `SendOutcome::RetryNeeded` (Pitfall 6 — no new broker-level delay mechanism, in-process sleep only, per "no new infra" constraint).

### CA/leaf certificate status+validity gate before cryptographic verification
**Source:** `crates/axiam-pki/src/mtls.rs:58-66` (leaf cert `status`/`not_before`/`not_after` check).
**Apply to:** the new issuing-CA check inserted before `verify_signature` at `mtls.rs:~97` — identical shape, same `AxiamError::Certificate` error type, same `Utc::now()` clock source.

### Manual test-double injection for repo-trait-generic code
**Source:** `crates/axiam-pki/tests/mtls_chain_test.rs` pattern (real in-memory SurrealDB + direct repo manipulation) and `crates/axiam-server/tests/req14_gdpr_test.rs`'s narration-via-repo-methods approach.
**Apply to:** the new `run_erasure_pipeline` extracted function (SECHRD-06) — inject a synthetic always-`Err` `AuditLogRepository` double alongside real in-memory repos for the other two args.

## No Analog Found

None — every one of the 7 findings has a same-file or same-crate working reference implementation to mirror (see RESEARCH.md "Don't Hand-Roll" and "Code Examples" sections for the full citation trail). The `SessionRepository::list_by_user` method is new but follows an established sibling-method query shape in the same repository file, not a novel pattern.

## Metadata

**Analog search scope:** `crates/axiam-federation`, `crates/axiam-api-rest` (webhook.rs, handlers/federation.rs, middleware/rate_limit_shared.rs), `crates/axiam-pki`, `crates/axiam-server` (cleanup.rs), `crates/axiam-db/src/repository` (session.rs, export_job.rs, federation_config.rs), `crates/axiam-amqp` (messages.rs, config.rs, audit_consumer.rs, authz_consumer.rs, mail_consumer.rs), `crates/axiam-core/src/models` (federation.rs, certificate.rs), `k8s/network-policy`, `.github/workflows/ci.yml`.
**Files scanned:** ~24 direct reads (all file:line citations verified against current HEAD, not just RESEARCH.md's prior-session reads — no drift detected).
**Pattern extraction date:** 2026-07-04
