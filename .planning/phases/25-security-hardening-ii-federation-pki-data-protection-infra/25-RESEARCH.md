# Phase 25: Security Hardening II — Federation, PKI, Data-Protection & Infra - Research

**Researched:** 2026-07-04
**Domain:** SSRF/DNS-rebind defense, mTLS chain validation, GDPR erasure durability, OIDC replay defense, per-tenant AMQP message authentication, k8s network egress
**Confidence:** HIGH (all seven fixes are grounded in exact file:line reads of the current codebase; only the precise reqwest pinning idiom and the AMQP backoff curve carry `[CITED]`/`[ASSUMED]` tags)

## Summary

This phase closes seven residual findings from `security-review-postremediation.md` across federation, PKI, GDPR, AMQP, and k8s infra. Every fix follows the fail-closed, negative-test-per-fix discipline already established in Phases 23/24. None of the seven require new architecture — each is a surgical extension of an existing, already-partially-correct control:

- **SECHRD-02** extends the SSRF guard that already exists for JWKS (`jwks_cache.rs:225` `is_private_jwks_ip`) and webhooks (`webhook.rs:58` `is_private_ip`) to OIDC discovery/token-exchange and SAML metadata, and — critically — adds **IP pinning**, which neither existing guard does today. Both existing guards only *validate* the resolved IP; they do not stop `reqwest` from re-resolving DNS a second time when the actual request is sent. This is the exact TOCTOU/rebind gap the phase must close, and the CONTEXT.md claim that "webhook delivery already re-resolves+pins from Phase 11" is **only half true** — it re-resolves and validates, but does **not** pin (see Pitfall 1).
- **SECHRD-05** adds one more `status == Active` + validity check to `mtls.rs`, mirroring the leaf-cert check three lines above it — the CA repository method (`get_by_issuer_id`) and the `CaCertificate` model already expose everything needed.
- **SECHRD-06** requires reordering `cleanup.rs::purge_single_user` so that a swallowed `pseudonymize_actor` error (currently a `tracing::warn!` no-op at line 330-336) becomes fatal, and moving the erasure-proof write to strictly last. It also requires extending `export_job.rs::has_pending_for_user`'s status filter and adding real (metadata-only) session rows to the export — which requires a **new `SessionRepository::list_by_user` method that does not exist yet**.
- **SECHRD-07** is the easiest fix: an exact working reference implementation of "nonce from server state" already exists 550 lines away in the same file (`oidc_callback_public` at line 1234-1300) — the account-linking path (`oidc_authorize`/`oidc_callback` at line 526-648) just needs the same `FederationLoginState` plumbing.
- **SECHRD-08** requires promoting the AMQP signing key from `Option<Vec<u8>>` (fail-open today — `audit_consumer.rs:112` and `authz_consumer.rs:114` both process unsigned messages with only a warning) to a mandatory, per-tenant HKDF-derived key, plus fixing the two `Uuid::nil()` placeholders in `cleanup.rs` (lines 391, 508) and adding backoff to `mail_consumer.rs`'s retry republish (currently republishes with **zero delay**, line 331-359).
- **SECHRD-09** requires `#[serde(skip_serializing)]` on 4 fields of `FederationConfig` (currently has **none** — it fully round-trips `client_secret`/`client_secret_ciphertext`/`client_secret_nonce`/`client_secret_key_version` through both `Debug` and `Serialize`), plus narrowing the `SELECT *` in `federation_config.rs::list()` that needlessly hydrates those same encrypted columns for every row of a list view.
- **SECHRD-10** requires adding an SMTP egress rule (currently **completely absent** from `server-egress.yml`), filling in the two `# TODO` cluster-CIDR exclusion placeholders already sitting in the file, adding 4 missing keys to `k8s/server/secret.yml`, and fixing a **confirmed double bug** in `.github/workflows/ci.yml:230-233`: the `test` job env vars use `AXIAM_DATABASE__*` (wrong section name AND wrong separator) instead of `AXIAM__DB__*`.

**Primary recommendation:** Build one shared, fresh-per-request, IP-pinning HTTP fetch helper in `axiam-federation` (reusable by `axiam-api-rest` webhook delivery, since `axiam-api-rest` already depends on `axiam-federation`); make every other fix a minimal, localized change to the exact file:line locations identified below — no new crates beyond `hkdf`, no new services, no schema redesign.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| SSRF address pinning (outbound fetches) | API/Backend (`axiam-federation`, `axiam-api-rest`) | — | Server-initiated egress; the guard must live where the HTTP client is constructed, not at the DB or frontend tier |
| mTLS CA status/validity | API/Backend (`axiam-pki`) | Database (`axiam-db` CA repo, read-only) | Chain-of-trust decision belongs in the auth-domain crate; DB only supplies the CA row |
| GDPR erasure durability | API/Backend (`axiam-server::cleanup`) | Database (`axiam-db` erasure_proof/export_job/user repos) | Ordering/atomicity logic is a backend workflow concern; DB enforces the uniqueness invariant via index |
| GDPR export session data | Database (`axiam-db` new `SessionRepository::list_by_user`) | API/Backend (`cleanup.rs` aggregation) | New read path needed at DB tier; backend assembles the export JSON |
| OIDC nonce from server state | API/Backend (`axiam-api-rest` handlers, `axiam-federation` service) | Database (`FederationLoginState` repo) | Replay defense is a request-handling concern; the login-state row is the source of truth |
| AMQP per-tenant signing | API/Backend (`axiam-amqp` producers/consumers) | — | Message-level authentication is a transport-adjacent backend concern; RabbitMQ itself stays a dumb broker (no ACL/vhost changes) |
| Federation/PKI secret non-serialization | API/Backend (`axiam-core` models) | — | Serde/Debug behavior is a model-definition concern, enforced at the type level |
| K8s network egress + secrets | CDN/Infra (`k8s/` manifests) | CI/CD (`.github/workflows/ci.yml`) | Cluster-boundary and CI-environment configuration, no application code involved |

## User Constraints (from CONTEXT.md)

<user_constraints>

### Locked Decisions (12, all "robust/fail-closed" fork chosen)

- **D-01a** — One shared SSRF-guarded HTTP client/resolver for ALL outbound fetches (webhook, OIDC discovery, OIDC token exchange, SAML metadata, JWKS). Generalize `is_private_jwks_ip` (`jwks_cache.rs:225`) into one reusable helper.
- **D-01b** — Disable auto-redirects; on a 3xx, re-run the full SSRF guard against the redirect target and re-issue explicitly.
- **D-01c** — Resolve fresh per request (no cross-request DNS cache); guard both A and AAAA; pin the exact connected `IpAddr`. Fold the existing webhook re-resolve (Phase 11) onto the shared helper without regressing it.
- **D-02** — mTLS: assert the **immediate issuing CA only** has `status == Active` and is within its validity window before `verify_signature` in `mtls.rs`. Full CA-chain-walk deferred (flat hierarchy today).
- **D-03a** — GDPR: proof-last, idempotent retry (not a wrapped DB transaction). Run PII-bearing steps in order; write the erasure proof only after every step succeeds; on failure leave re-selection flags set.
- **D-03b** — Erasure-proof uniqueness via a DB `UNIQUE` index on `user_id` (not a deterministic-proof-id upsert).
- **D-03c** — Export session data: metadata only (created_at/expires_at/ip_address/user_agent), redact the opaque token/hash. **Note:** the model has no `last_seen` field (see Pitfall 4) — do not invent one.
- **D-03d** — Export dedup blocks `queued` OR `ready`-undownloaded OR `failed` (not only `queued` as today).
- **D-04** — Federation nonce: account-linking callback derives `expected_nonce` from stored login state, ignoring `req.nonce`. (Prescriptive, no fork.)
- **D-05a** — AMQP: HKDF-derived per-tenant subkeys from one master `AXIAM__AMQP__SIGNING_KEY` (not stored per-tenant keys, not per-tenant broker queues+ACLs).
- **D-05b** — HKDF construction: HKDF-SHA256, fixed app salt, `info = "axiam-amqp-v1" || tenant_id`, plus a `key_version` byte on the message for future master-key rotation.
- **D-05c** — Signing always required in every environment (no unsigned code path, no warn-and-process bypass); ship a documented dev key in config/`.env.example`.
- **D-05d** — ExportReady resolves the real `org_id` (producer or consumer site is planner's choice); mail-retry republish uses a backoff delay.
- **D-06** — `#[serde(skip_serializing)]` on `FederationConfig` `client_secret`/`client_secret_ciphertext`/`_nonce`/`_key_version`; `Debug` impls don't print CA/PGP/secret blobs; list queries don't hydrate encrypted columns needlessly. (Prescriptive, no fork.)
- **D-07a** — SMTP egress (25/465/587) restricted to a configurable, Helm/kustomize-parameterized relay CIDR.
- **D-07b** — Relay-CIDR default is fail-closed/restrictive (mail off until operator configures it) — never ship `0.0.0.0/0:587` as a default.
- **D-07c** — Tighten the existing `0.0.0.0/0:443` rule with pod/service cluster-CIDR exclusions (currently `# TODO` placeholders); complete the k8s secret set; fix CI `AXIAM__…` prefix.

### Claude's Discretion

- SSRF pin mechanism: `Client::resolve()`/`resolve_to_addrs()` static override vs. a custom `dns_resolver` — planner's choice; contract is "the validated `IpAddr` is what the socket connects to."
- mTLS clock source: system UTC (`Utc::now()`), matching the existing leaf-cert check.
- ExportReady `org_id` resolution site: producer- vs. consumer-side; backoff delay value/curve — align with existing AMQP retry conventions (there currently are none for AMQP retries specifically; the webhook exponential-backoff pattern in `webhook.rs:212-220` is the closest in-repo precedent).
- Federation nonce + secret-skip (SECHRD-07/09): single-path implementations, no user decision needed.
- `443` cluster-CIDR exclusion values: kustomize/Helm placeholders, cluster-specific.
- Test placement: Rust negative/replay/concurrency tests in the owning crate's `tests/` (`axiam-federation`, `axiam-pki`, `axiam-amqp`, `axiam-server`, `axiam-db`, `axiam-api-rest`); per-crate `cargo check/test -p <crate>` only, never full workspace.
- Per-PLAN `<threat_model>`: ASVS-aligned threat-model block required per plan.

### Deferred Ideas (OUT OF SCOPE)

- Full CA-chain-walk mTLS validation (issuer + intermediates + root) — flat org/tenant-CA→device-cert hierarchy today; revisit if intermediate CAs are introduced.
- CRL/OCSP revocation checking for mTLS — post-v1.0-beta.
- PGP-encrypted GDPR export — ties to CMPL-02 (compliance phase).
- Per-tenant broker queues + RabbitMQ ACLs — rejected in favor of HKDF-derived per-tenant keys.
- Single wrapped DB transaction for the GDPR purge — rejected in favor of proof-last idempotent retry.
- DNS-resolution caching for outbound fetches — rejected (fresh-per-request chosen) to avoid a rebind window.
- Master-key rotation runbook/tooling — docs/ops item; the `key_version` byte makes it rotation-ready.
- All Phase 26-29 + compliance/docs items (CORR/PERF/FUNC/QUAL/CMPL/DOCS).

</user_constraints>

## Phase Requirements

<phase_requirements>

| ID | Description | Research Support |
|----|-------------|------------------|
| SECHRD-02 | SSRF address pinning: extend private/loopback/link-local/ULA guard beyond JWKS to OIDC discovery+token exchange+SAML metadata; pin validated IP into the connection | Shared-guard design in "Architecture Patterns" Pattern 1; exact call sites in "Code Examples"; Pitfall 1 documents the webhook pinning gap |
| SECHRD-05 | mTLS CA status/validity: assert issuing CA `Active` + in-validity-window before `verify_signature`; fail closed | `mtls.rs:59-70` (leaf check pattern to mirror), `74-83` (CA lookup already present), `97-103` (insertion point) |
| SECHRD-06 | GDPR erasure durability: fatal `pseudonymize_actor` failure, unique erasure proof, export dedup on queued/ready/failed, real sessions data | `cleanup.rs:317-411` current ordering bug; `export_job.rs:99-126` dedup gap; new `SessionRepository::list_by_user` requirement (Pitfall 4) |
| SECHRD-07 | Federation nonce from server state (authenticated/account-linking callback) | Exact working reference at `handlers/federation.rs:1234-1300` (`oidc_callback_public`) vs. the buggy path at `595-648` |
| SECHRD-08 | AMQP signing mandatory+per-tenant; ExportReady real `org_id`+backoff | `messages.rs` HMAC helpers, `config.rs:19` current fail-open comment, `audit_consumer.rs:112`/`authz_consumer.rs:114` warn-and-process branches, `mail_consumer.rs:331-359` zero-delay republish |
| SECHRD-09 | Federation secret non-serialization | `federation.rs` model (`axiam-core`) has zero `skip_serializing` today; `federation_config.rs:214,362` `SELECT *` hydration |
| SECHRD-10 | Network egress + k8s secret completeness | `server-egress.yml` (no SMTP rule, two `# TODO` CIDR placeholders), `secret.yml` (4 missing keys), `ci.yml:229-233` (confirmed wrong-prefix bug) |

</phase_requirements>

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `hkdf` | 0.13.0 [VERIFIED: cargo registry — `cargo search hkdf`; `gsd-tools package-legitimacy check` verdict OK, published 2015, 3.59M weekly downloads, repo `github.com/RustCrypto/KDFs/`] | HKDF-SHA256 per-tenant AMQP subkey derivation (D-05a/b) | RustCrypto's canonical HKDF impl; same family as the already-pinned `hmac 0.12`/`sha2 0.10` — no new crypto backend introduced |
| `reqwest` | 0.12.28 [VERIFIED: codebase — `Cargo.lock`] | Outbound HTTP for OIDC/SAML/webhook/JWKS fetches | Already the workspace HTTP client (`rustls-tls`, no default features); `ClientBuilder::resolve()`/`resolve_to_addrs()` [CITED: docs.rs/reqwest ClientBuilder + github.com/seanmonstar/reqwest PR history] supports per-host static IP override needed for pinning |
| `tokio::net::lookup_host` | (tokio, already a dependency) | A/AAAA DNS resolution for the SSRF guard | Already used by both existing guards (`jwks_cache.rs:262`, `webhook.rs:88`) — no new resolver library needed |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `hmac`/`sha2` | 0.12.1 / 0.10.9 [VERIFIED: codebase — `Cargo.lock`] | Already used for `sign_payload`/`verify_payload` in `messages.rs`; `hkdf` reuses the same `hmac`/`sha2` traits | No change needed — HKDF-SHA256 keys off the same primitives |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `ClientBuilder::resolve()`/`resolve_to_addrs()` for pinning | Custom `hyper` connector / `reqwest::dns::Resolve` trait impl | More control over multi-address happy-eyeballs, but far more code for a single-address pin need; `resolve()`/`resolve_to_addrs()` is the documented, minimal-surface mechanism [CITED: docs.rs reqwest] |
| HKDF-derived per-tenant AMQP keys (D-05a, locked) | Stored per-tenant keys / per-tenant broker queues+ACLs | Already decided against in CONTEXT.md — listed only for completeness |

**Installation:**
```bash
# Add to crates/axiam-amqp/Cargo.toml [dependencies] and workspace Cargo.toml
cargo add hkdf --package axiam-amqp
```

**Version verification:** `hkdf` confirmed at 0.13.0 via `cargo search hkdf` (2026-07-04) and via `gsd-tools query package-legitimacy check --ecosystem crates hkdf` → verdict `OK` (published 2015-01-03, 3,588,275 weekly downloads, repo `github.com/RustCrypto/KDFs/`, no postinstall script, not deprecated). `reqwest` 0.12.28 and `hmac`/`sha2` versions confirmed directly from the committed `Cargo.lock` (workspace-pinned, no drift risk).

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|--------------|---------|-------------|
| `hkdf` | crates.io | ~11 years (since 2015-01-03) | 3,588,275/wk | `github.com/RustCrypto/KDFs/` | OK | Approved — only new dependency this phase introduces |

**Packages removed due to SLOP verdict:** none
**Packages flagged as suspicious (SUS):** none

No other new packages are introduced by this phase — every other fix reuses already-pinned workspace dependencies (`reqwest`, `hmac`, `sha2`, `tokio`, `chrono`, `serde`, `x509_parser`).

## Architecture Patterns

### System Architecture Diagram

```
                     ┌─────────────────────────────────────────────┐
                     │        Shared SSRF-Guarded Fetch Helper      │
                     │        (new module, lives in axiam-federation)│
                     │                                               │
   URL to fetch ───▶ │ 1. parse URL, extract host+port              │
                     │ 2. tokio::net::lookup_host (A + AAAA)         │
                     │ 3. reject if ANY resolved IP is               │
                     │    loopback/private/link-local/ULA/unspec.    │
                     │ 4. pick one validated IpAddr                  │
                     │ 5. build fresh Client::builder()              │
                     │      .resolve(host, SocketAddr::new(ip,port)) │
                     │      .redirect(Policy::none())                │
                     │ 6. send request                               │
                     │ 7. if 3xx: extract Location, GOTO 1           │
                     │    (bounded hop count, e.g. max 3)            │
                     └───────────────┬───────────────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┬─────────────────┐
              ▼                      ▼                      ▼                 ▼
     JWKS fetch                OIDC discovery +      SAML metadata      Webhook delivery
  (jwks_cache.rs)              token exchange         fetch (saml.rs)   (webhook.rs, axiam-api-rest)
                                (oidc.rs)

   ──────────────────────────────────────────────────────────────────────────────────

              mTLS Device Auth (mtls.rs)                    GDPR Purge Pipeline (cleanup.rs)
   client PEM ──▶ fingerprint lookup ──▶ leaf status/expiry  user due ──▶ revoke sessions
                       │                    (existing)            │        ──▶ delete fed links
                       ▼                                          │        ──▶ delete WebAuthn/pwd history
              lookup issuing CA (existing)                        │        ──▶ prune graph edges
                       │                                          │        ──▶ pseudonymize_actor  [FATAL now]
                       ▼ NEW                                      │        ──▶ mark_completed
          assert CA.status==Active                                │        ──▶ anonymize_user       [LAST]
          AND now in [not_before,not_after]                       └──▶ ──▶ erasure_proof.create  [PROOF-LAST]
                       │                                                    (UNIQUE index on user_id)
                       ▼ (fail closed if not)
              verify_signature(leaf, CA pubkey)  (existing)

   ──────────────────────────────────────────────────────────────────────────────────

   OIDC account-linking callback (federation.rs:595)      AMQP message flow
   req.state ──▶ login_state_repo.consume_by_state ──▶     Producer (external/SDK) ──▶ HKDF-derive
   expected_nonce = login_state.nonce  [NOT req.nonce]     per-tenant subkey ──▶ sign_payload ──▶
   ──▶ service.handle_callback(..., expected_nonce)        publish (hmac_signature + key_version)
                                                                    │
                                                                    ▼
                                                          Consumer: derive same per-tenant
                                                          subkey from tenant_id in message ──▶
                                                          verify_payload ──▶ FAIL CLOSED if
                                                          missing/invalid (no warn-and-process)
```

### Recommended Project Structure

No new crates or top-level modules — additions are localized:
```
crates/
├── axiam-federation/
│   └── src/
│       ├── ssrf.rs              # NEW — shared guard: is_disallowed_ip, resolve_and_pin, guarded_fetch
│       ├── jwks_cache.rs         # MODIFIED — fetch_jwks() calls the shared guard instead of its own inline check
│       ├── oidc.rs               # MODIFIED — discover()/exchange_code() route through guarded_fetch
│       └── saml.rs               # MODIFIED — fetch_idp_metadata() routes through guarded_fetch
├── axiam-api-rest/
│   └── src/
│       ├── webhook.rs            # MODIFIED — resolve_and_validate_host()/delivery loop use the shared guard
│       └── handlers/federation.rs # MODIFIED — oidc_authorize/oidc_callback gain login_state_repo param
├── axiam-pki/
│   └── src/mtls.rs               # MODIFIED — add issuing-CA status/validity check before verify_signature
├── axiam-server/
│   └── src/cleanup.rs            # MODIFIED — reorder purge_single_user; fix org_id; call new session list method
├── axiam-db/
│   └── src/repository/
│       ├── session.rs            # MODIFIED — add list_by_user (new trait method + impl)
│       ├── export_job.rs         # MODIFIED — has_pending_for_user status filter widened
│       └── federation_config.rs  # MODIFIED — list()/get_by_id() column projection narrowed
├── axiam-amqp/
│   └── src/
│       ├── messages.rs           # MODIFIED — sign_payload/verify_payload gain per-tenant HKDF derivation
│       ├── audit_consumer.rs     # MODIFIED — signing_key: Vec<u8> (mandatory), fail-closed branch
│       ├── authz_consumer.rs     # MODIFIED — same
│       ├── mail_consumer.rs      # MODIFIED — backoff delay before republish
│       └── config.rs             # MODIFIED — signing_key becomes mandatory-with-dev-default semantics
└── axiam-core/
    └── src/models/
        ├── federation.rs         # MODIFIED — skip_serializing + manual Debug on FederationConfig
        └── certificate.rs        # MODIFIED — manual Debug on CaCertificate/GeneratedCaCertificate (redact key material)

k8s/
├── network-policy/server-egress.yml  # MODIFIED — add SMTP rule, fill CIDR exclusions
└── server/secret.yml                 # MODIFIED — add 4 missing keys

.github/workflows/ci.yml              # MODIFIED — fix AXIAM_DATABASE__* → AXIAM__DB__*
```

### Pattern 1: Shared SSRF Guard — Resolve-Once-and-Pin

**What:** A small set of pure/async functions that (a) classify an `IpAddr` as disallowed, (b) resolve a host to a single validated `IpAddr`, and (c) build a *fresh, single-use* `reqwest::Client` per call with that IP pinned via `ClientBuilder::resolve()`.
**When to use:** Every outbound fetch to an admin-supplied or IdP-supplied URL: JWKS, OIDC discovery, OIDC token exchange, SAML metadata, webhook delivery.
**Example:**
```rust
// Source: derived from jwks_cache.rs:225-274 (existing partial guard) +
// reqwest docs.rs ClientBuilder::resolve [CITED: docs.rs/reqwest/struct.ClientBuilder.html]
use std::net::{IpAddr, SocketAddr};

pub fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_broadcast() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0 == 0xfe80) // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00 == 0xfc00) // unique-local fc00::/7
        }
    }
}

/// Resolve `host:port`, reject if ANY resolved A/AAAA record is disallowed,
/// and return ONE validated address to pin into the connection.
pub async fn resolve_and_pick(host: &str, port: u16) -> Result<IpAddr, SsrfError> {
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| SsrfError::ResolveFailed)?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() {
        return Err(SsrfError::ResolveFailed);
    }
    if addrs.iter().any(|ip| is_disallowed_ip(*ip)) {
        return Err(SsrfError::Blocked);
    }
    Ok(addrs[0]) // pin the first resolved address
}

/// Build a fresh, single-use client pinned to `ip` for `host`. No connection
/// pooling/caching across requests — matches D-01c ("fresh per request").
pub fn pinned_client(host: &str, ip: IpAddr, port: u16) -> Result<reqwest::Client, SsrfError> {
    reqwest::Client::builder()
        .resolve(host, SocketAddr::new(ip, port))
        .redirect(reqwest::redirect::Policy::none()) // D-01b: no auto-redirect
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| SsrfError::ClientBuildFailed)
}

/// Orchestrates guard + pin + fetch + bounded manual redirect re-validation (D-01b).
pub async fn guarded_fetch(
    url: &str,
    build_request: impl Fn(&reqwest::Client, &str) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, SsrfError> {
    const MAX_HOPS: u8 = 3;
    let mut current = url.to_string();
    for _ in 0..MAX_HOPS {
        let parsed = url::Url::parse(&current).map_err(|_| SsrfError::InvalidUrl)?;
        let host = parsed.host_str().ok_or(SsrfError::InvalidUrl)?.to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);
        let ip = resolve_and_pick(&host, port).await?;
        let client = pinned_client(&host, ip, port)?;
        let resp = build_request(&client, &current)
            .send()
            .await
            .map_err(|_| SsrfError::RequestFailed)?;
        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or(SsrfError::InvalidUrl)?;
            current = url::Url::parse(&parsed)
                .and_then(|base| base.join(location))
                .map_err(|_| SsrfError::InvalidUrl)?
                .to_string();
            continue; // D-01b: re-run the FULL guard against the redirect target
        }
        return Ok(resp);
    }
    Err(SsrfError::TooManyRedirects)
}
```
Callers (`jwks_cache::fetch_jwks`, `oidc::discover`/`exchange_code`, `saml::fetch_idp_metadata`, `webhook::deliver`'s per-attempt send) replace their ad-hoc validate-then-send sequence with a single `guarded_fetch(url, |client, u| client.get(u))` (or `.post(u).form(...)` for token exchange) call.

### Pattern 2: Mirror the Existing Public-Path Nonce Fix (SECHRD-07)

**What:** The public (unauthenticated first-time SSO) OIDC path already does exactly what SECHRD-07 requires; the authenticated account-linking path just needs the same two pieces of plumbing.
**When to use:** `oidc_authorize`/`oidc_callback` in `handlers/federation.rs:526-648`.
**Example:**
```rust
// Source: handlers/federation.rs:1160-1211 (oidc_start_public) and :1247-1267
// (oidc_callback_public) — the EXACT pattern to replicate for the authenticated path.

// In oidc_authorize: generate server-side nonce (ignore req.nonce for storage),
// persist a FederationLoginState row keyed by req.state before returning the URL:
let server_nonce = random_base64url();
login_state_repo
    .insert(&axiam_core::repository::FederationLoginState {
        state: req.state.clone(),
        nonce: server_nonce.clone(),
        tenant_id: user.tenant_id,
        federation_config_id: req.config_id,
        redirect_uri: req.redirect_uri.clone(),
        expires_at: Utc::now() + chrono::Duration::minutes(10),
        request_id: String::new(),
    })
    .await?;
// ... build_authorization_url(..., &req.state, &server_nonce) — use server_nonce, not req.nonce

// In oidc_callback: consume by req.state, derive expected_nonce from the row,
// IGNORE req.nonce entirely:
let login_state = login_state_repo
    .consume_by_state(&req.state)
    .await?
    .ok_or_else(|| AxiamApiError(AxiamError::AuthenticationFailed {
        reason: "state not found or expired".into(),
    }))?;
let expected_nonce = login_state.nonce.clone(); // NOT req.nonce
let result = service.handle_callback(user.tenant_id, req.config_id, &req.code,
    &req.redirect_uri, &expected_nonce).await?;
```
Note: `oidc_authorize`/`oidc_callback` currently take `req.state`/`req.nonce` from the request body but never persist them — adding `login_state_repo: web::Data<SurrealFederationLoginStateRepository<C>>` as a handler parameter is a drop-in addition since this repo is **already registered as `app_data`** in `main.rs:738` (used by the public path).

### Pattern 3: Test-Seam Extraction for the GDPR Ordering Fix (SECHRD-06)

**What:** `CleanupTask` is NOT generic over repository traits — its fields are concrete `Arc<SurrealXxxRepository<C>>` types (`cleanup.rs:54-80`). This means a test cannot inject a "fails on demand" `AuditLogRepository` double into `CleanupTask::purge_single_user` without a larger refactor. The existing test file `axiam-server/tests/cleanup_task.rs` explicitly documents this limitation ("This does NOT exercise `CleanupTask` itself... instead it verifies the underlying methods") and `req14_gdpr_test.rs::purge_reselectable_after_partial_failure` narrates the ordering invariant by testing `AccountDeletionRepository` methods directly rather than running the full pipeline.
**When to use:** To make the SECHRD-06 negative test meaningful (not just a repo-method-in-isolation narration), extract the erasure step sequence into a small trait-generic free function.
**Example:**
```rust
// Source: derived from cleanup.rs:246-411's existing purge_single_user body —
// extract-function refactor only (no new architecture), enabling test injection.
async fn run_erasure_pipeline<A, EP, U>(
    audit_repo: &A,
    erasure_proof_repo: &EP,
    user_repo: &U,
    tenant_id: Uuid,
    user_id: Uuid,
    pseudonym: &str,
    email_hash: &str,
) -> AxiamResult<()>
where
    A: AuditLogRepository,
    EP: ErasureProofRepository,
    U: UserRepository,
{
    // FATAL now — no tracing::warn! swallow (closes the SECHRD-06 gap):
    audit_repo.pseudonymize_actor(tenant_id, user_id, pseudonym).await?;
    // Anonymize BEFORE the proof write, so a proof is never written for a
    // user who isn't actually anonymized yet (D-03a "proof-last"):
    user_repo.anonymize_user(tenant_id, user_id, email_hash, pseudonym).await?;
    erasure_proof_repo
        .create(CreateErasureProof { pseudonym: pseudonym.into(), tenant_id, erased_at: Utc::now() })
        .await?; // LAST — DB UNIQUE index on user_id makes a retry's duplicate no-op (D-03b)
    Ok(())
}
```
`CleanupTask::purge_single_user` calls this with its concrete `Arc<SurrealXxxRepository<C>>` fields (auto-derefs to the trait); a unit test in `axiam-server/tests/` calls it with a local test-double `AuditLogRepository` whose `pseudonymize_actor` always returns `Err`, then asserts `user_repo.anonymize_user` and `erasure_proof_repo.create` were never reached (e.g. via a `Cell<bool>` flag in the double, or by asserting the user's `deletion_pending` flag is still `true` after the call using a real in-memory SurrealDB for `user_repo`/`erasure_proof_repo` but a synthetic failing double only for `audit_repo`).

### Anti-Patterns to Avoid

- **Reusing the injected `web::Data<reqwest::Client>` for guarded fetches:** the shared pooled client cannot have a per-request `.resolve()` override applied after construction. Build a fresh, cheap `Client` per guarded fetch instead (these are low-frequency calls — JWKS/OIDC/SAML/webhook — not a hot path where connection-pool reuse matters).
- **Trusting `req.nonce` (or any client-supplied replay-defense value) anywhere federation state exists to check it against:** if a `FederationLoginState` row exists for the flow, it is always the sole source of truth — this is already the codebase's own convention on the public path.
- **Swallowing `pseudonymize_actor` failures with `tracing::warn!` and continuing:** this is the exact SECHRD-06 bug. Any failure in a PII-bearing purge step must propagate with `?`.
- **Making the AMQP `signing_key` an `Option` that silently degrades to "accept anything" when absent:** D-05c requires this to be a hard failure at startup (or a documented dev default), never a runtime warn-and-continue branch.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Per-tenant key derivation | A custom KDF (e.g., `SHA256(master \|\| tenant_id)`) | `hkdf::Hkdf::<Sha256>::new(Some(salt), master).expand(info, &mut out)` | HKDF is a proven extract-and-expand construction with domain separation via `info`; ad-hoc concatenation hashing has no formal security proof and is easy to get subtly wrong (e.g. length-extension exposure without a proper extract step) |
| IP-address classification (private/loopback/link-local/ULA) | New logic | The existing `is_private_jwks_ip`/`is_private_ip` bodies (byte-identical in both files today) — just deduplicate into one function | Two independent hand-rolled copies already exist and already agree; a third one risks drifting from both |
| SSRF-safe HTTP fetch with redirect handling | A bespoke redirect-following loop with ad-hoc URL joining | `reqwest::redirect::Policy::none()` + explicit `Location` header extraction + `Url::join` (already how `url` crate is used elsewhere in this codebase) | `Url::join` correctly handles relative/absolute Location headers per RFC 3986; hand-rolled string concatenation is a common source of SSRF-guard bypasses via malformed redirect targets |

**Key insight:** Every one of this phase's fixes is "make an existing correct pattern consistent" rather than "invent a new pattern" — the codebase already contains a correct reference implementation for 4 of the 7 findings (JWKS SSRF guard, webhook SSRF guard, public-path nonce validation, leaf-cert status/validity check). The main risk is copying the *wrong* half of an existing pattern (e.g., copying webhook's "resolve and validate" without adding the pin it's missing).

## Common Pitfalls

### Pitfall 1: "Already re-resolves+pins" is a codebase-drift claim, not current fact
**What goes wrong:** CONTEXT.md states webhook delivery "already re-resolves+pins from Phase 11." Reading `webhook.rs:83-98` shows `resolve_and_validate_host` resolves and validates the IP, then simply returns `Ok(())` — the actual `client.post(&webhook.url)` call at line 234 re-resolves DNS independently via `reqwest`'s normal resolution path. There is no `.resolve()` override anywhere in this file. This is a genuine, currently-open DNS-rebind TOCTOU window, not a regression risk.
**Why it happens:** "Re-resolve at each attempt" (defeating a rebind *between delivery retries*, e.g. minutes apart) was conflated with "pin the resolved IP into the connection" (defeating a rebind *between the check and the send*, milliseconds apart) — they are different defenses and only the first exists today.
**How to avoid:** Route `webhook.rs`'s delivery loop through the new shared `guarded_fetch`/`pinned_client` helper (Pattern 1) rather than assuming the existing `resolve_and_validate_host` call already provides pinning.
**Warning signs:** Any code path that calls a resolve/validate function and then makes an HTTP call through a *different* client than the one the validated IP was bound to.

### Pitfall 2: `pseudonymize_actor` is currently non-fatal by design comment, not by oversight
**What goes wrong:** `cleanup.rs:328-336` has an explicit comment "Errors here are logged but not fatal" — this was an intentional prior design choice, not a bug that was simply missed. A planner reading only the SECHRD-06 finding text might not realize they need to *remove* a deliberate `if let Err(e) = ... { tracing::warn!(...) }` guard and replace it with `?`.
**Why it happens:** Earlier phases treated pseudonymization as best-effort (audit trail is a secondary concern to the primary deletion), but GDPR Art. 17 requires the erasure proof to certify that PII scrubbing actually happened.
**How to avoid:** Explicitly diff the before/after: the fix is `self.audit_repo.pseudonymize_actor(...).await?;` (propagate), not a new check layered on top.
**Warning signs:** `cargo clippy` will not catch this — the `if let Err` pattern compiles cleanly either way. Only the negative test (Pattern 3) catches the regression.

### Pitfall 3: Erasure-proof write is currently BEFORE `anonymize_user`, not after
**What goes wrong:** In `cleanup.rs`, step order today is: (d) pseudonymize_actor [swallowed], (e) create erasure_proof, (f) mark account_deletion completed, (g) anonymize_user. If `anonymize_user` (g) fails AFTER the erasure proof (e) is already written, the system has already certified an erasure that didn't fully happen — the opposite of "proof-last."
**Why it happens:** The comment at `cleanup.rs:377-378` explains anonymize_user was moved *last* specifically so a partial-failure retry can still read the user row (CQ-B38/D-05) — but this same "last" positioning conflicts with D-03a's "proof only after every step succeeds," since the proof (e) currently comes *before* the last step (g), not after it.
**How to avoid:** Move the `erasure_proof_repo.create(...)` call to be the literal last statement in `purge_single_user`, strictly after `anonymize_user` succeeds (see Pattern 3's example ordering: pseudonymize → anonymize → proof).
**Warning signs:** A negative test that fails `anonymize_user` (e.g., by pre-anonymizing the user out-of-band, or by causing `email_hash` collision — check `SurrealUserRepository::anonymize_user`'s actual failure modes) but still finds an `erasure_proof` row.

### Pitfall 4: The export "sessions" field cannot use the fields listed in the phase brief verbatim
**What goes wrong:** The `research_focus` brief (and D-03c) mention `created_at/expires_at/last_seen/ip/user_agent`. The actual `Session` model (`axiam-core/src/models/session.rs`) has `id, tenant_id, user_id, token_hash, ip_address, user_agent, expires_at, created_at` — **there is no `last_seen` field anywhere in the schema** (`schema.rs:334-340` confirms). There is also **no `SessionRepository::list_by_user` method** — the trait only has `get_by_id`, `get_by_token_hash`, `invalidate*`, and `cleanup_expired`.
**Why it happens:** `last_seen` was likely aspirational language in the finding description, not a verified field name.
**How to avoid:** (1) Add `list_by_user(tenant_id, user_id) -> Vec<Session>` to `SessionRepository` trait (`axiam-core/src/repository.rs:461`) and implement it in `SurrealSessionRepository`; (2) export exactly `{id, created_at, expires_at, ip_address, user_agent}` per session — omit `last_seen` (doesn't exist) and `token_hash` (excluded per D-03c, it's live credential material).
**Warning signs:** A plan or task that references `session.last_seen` will fail to compile — catch this at plan-review time, not execution time.

### Pitfall 5: AMQP signing today has TWO separate warn-and-process branches, and mail messages aren't signed at all
**What goes wrong:** `audit_consumer.rs:112-116` and `authz_consumer.rs:114-118` both have an `else { warn!(...) }` branch that processes the message anyway when `signing_key` is `None`. `AmqpConfig::signing_key` doc comment (`config.rs:19-20`) explicitly states "When `None`, signatures are accepted but not required (migration mode)." D-05c requires removing BOTH warn-and-process branches, and the `Option<Vec<u8>>` type in `main.rs:522-534`/`audit_consumer.rs:38`/`authz_consumer.rs:30` should become a mandatory `Vec<u8>` (loaded from either the env var or the shipped dev-key default) at the config layer, with startup failing fast if genuinely unset in a production-flagged environment. Separately, `OutboundMailMessage`/`mail_consumer.rs` has **no HMAC field or verification at all** — SECHRD-08's per-tenant-signing requirement is scoped to `AuthzRequest`/`AuditEventMessage` (the two types that already carry `hmac_signature`), not mail.
**Why it happens:** The `hmac_signature` field was added incrementally per message type as external-facing cross-service messages, while `OutboundMailMessage` is entirely internal (server enqueues its own mail to itself) and was never considered an authentication boundary.
**How to avoid:** Scope the per-tenant-signing fix to `AuthzRequest` + `AuditEventMessage` (both consumed from potentially-external publishers, e.g. the client SDKs per `REQUIREMENTS.md` FND-03's AMQP consumer contract); do not add signing to the mail pipeline (out of scope, no finding references it).
**Warning signs:** A plan that tries to add `hmac_signature` to `OutboundMailMessage` is over-scoping — mail is enqueued exclusively by AXIAM's own `cleanup.rs`/handlers, not by external tenants, so tenant-to-tenant spoofing risk doesn't apply there.

### Pitfall 6: `mail_consumer.rs`'s "retry" has zero backoff today
**What goes wrong:** On `SendOutcome::RetryNeeded`, the consumer immediately calls `channel.basic_publish` with no delay (`mail_consumer.rs:329-359`) — this is a hot-retry loop against a possibly-down SMTP relay, not exponential backoff.
**Why it happens:** RabbitMQ has no native per-message delay without a plugin (`rabbitmq_delayed_message_exchange`) or a TTL+DLX "parking lot" queue pattern; neither exists in this codebase's `connection.rs` queue declarations.
**How to avoid:** The lowest-risk, in-scope fix is an in-process `tokio::time::sleep` before the `basic_publish` call, scaled by `msg.attempt_count` (mirrors the existing exponential-backoff pattern already used for webhook retries at `webhook.rs:212-220`, which also runs in-process). Do not introduce a new delayed-exchange plugin dependency — out of scope per "no new infra" in CONTEXT.md Specific Ideas.
**Warning signs:** A plan proposing a RabbitMQ plugin install or a new delay-queue+DLX topology is over-engineering relative to the locked "no new infra" constraint.

### Pitfall 7: `443` egress CIDR exclusions are TODO comments, not a missing feature
**What goes wrong:** `server-egress.yml:42-43` already contains `# TODO: operator must add cluster pod CIDR here...` / `# TODO: operator must add cluster service CIDR here...` as literal comments inside the `except:` list — this looks like it needs a whole new rule, but it's actually two lines to uncomment/parameterize with a placeholder value (e.g., `10.244.0.0/16` for the pod CIDR, `10.96.0.0/12` for the service CIDR, both already suggested in the comment text).
**How to avoid:** Add the two placeholder CIDR entries directly under `except:`, sourced from a Helm/kustomize value per D-07c's discretion note — don't restructure the whole egress rule.

## Code Examples

### Existing (correct) reference pattern for "nonce from server state"
```rust
// Source: crates/axiam-api-rest/src/handlers/federation.rs:1255-1267
// (oidc_callback_public — the PUBLIC first-time-SSO path, already correct)
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
This is the exact pattern SECHRD-07 needs replicated at `handlers/federation.rs:595-648` (the authenticated account-linking `oidc_callback`), which today does `service.handle_callback(user.tenant_id, req.config_id, &req.code, &req.redirect_uri, &req.nonce)` — passing the raw request-supplied nonce straight through.

### Existing (correct) reference pattern for leaf-cert status/validity — mirror for the issuing CA
```rust
// Source: crates/axiam-pki/src/mtls.rs:59-70 (leaf check — the pattern to mirror)
if cert.status != CertificateStatus::Active {
    return Err(AxiamError::Certificate("certificate is not active".into()));
}
let now = Utc::now();
if now < cert.not_before || now > cert.not_after {
    return Err(AxiamError::Certificate(
        "certificate is expired or not yet valid".into(),
    ));
}
// ... (existing CA lookup at :74-83 already fetches `ca_cert: CaCertificate`) ...
// NEW — insert before the verify_signature call at :97-103:
if ca_cert.status != CertificateStatus::Active {
    return Err(AxiamError::Certificate("issuing CA is not active".into()));
}
if now < ca_cert.not_before || now > ca_cert.not_after {
    return Err(AxiamError::Certificate(
        "issuing CA certificate is expired or not yet valid".into(),
    ));
}
```

### Current export dedup gap and fix (SECHRD-06/D-03d)
```rust
// Source: crates/axiam-db/src/repository/export_job.rs:102-126 (current — only 'queued')
"SELECT count() AS total FROM export_job \
 WHERE tenant_id = $tenant_id AND user_id = $user_id \
 AND status IN ['queued'] \
 GROUP ALL"

// FIX — widen to also block 'ready' (undownloaded — by definition, since a
// downloaded job's status becomes 'downloaded', a distinct enum value) and 'failed':
"SELECT count() AS total FROM export_job \
 WHERE tenant_id = $tenant_id AND user_id = $user_id \
 AND status IN ['queued', 'ready', 'failed'] \
 GROUP ALL"
```

### Confirmed CI env-var bug (SECHRD-10)
```yaml
# Source: .github/workflows/ci.yml:229-233 (current — WRONG, uses single underscore
# AND wrong section name; config.rs's AppConfig field is `db`, not `database`, and
# main.rs:767 sets .separator("__") with prefix "AXIAM")
env:
  AXIAM_DATABASE__URL: "ws://localhost:8000"
  AXIAM_DATABASE__USERNAME: root
  AXIAM_DATABASE__PASSWORD: root
  AXIAM_AMQP__URL: "amqp://localhost:5672"

# FIX:
env:
  AXIAM__DB__URL: "ws://localhost:8000"
  AXIAM__DB__USERNAME: root
  AXIAM__DB__PASSWORD: root
  AXIAM__AMQP__URL: "amqp://localhost:5672"
```
Note: this env block currently has NO visible effect on the test run (the `AppConfig` fields it targets never actually receive these values due to the wrong prefix/separator), yet CI has been green — worth flagging to the planner that either (a) `cargo test --workspace` doesn't depend on these particular config values being externally overridden (tests likely construct their own in-memory DB/config directly, as seen in every `tests/*.rs` file read during this research), or (b) there's a latent config gap. Either way, fixing the prefix is the SECHRD-10 AC regardless of current effective impact.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Validate-then-send SSRF guard (JWKS, webhook) | Validate-and-pin (resolve-once, connect-to-pinned-IP) | This phase (SECHRD-02) | Closes the TOCTOU window between DNS validation and the actual TCP connect — the textbook DNS-rebinding SSRF bypass |
| Single shared AMQP HMAC key, optional | Per-tenant HKDF-derived subkey, mandatory | This phase (SECHRD-08) | A compromised tenant-A message-signing capability (e.g. leaked SDK config) can no longer forge tenant-B audit/authz events |
| `FederationConfig` fully `Debug`/`Serialize`-able | `skip_serializing` + redacted `Debug` on secret fields | This phase (SECHRD-09) | Removes an entire class of accidental-logging / accidental-API-response secret leaks |

**Deprecated/outdated:**
- The `is_private_jwks_ip`/`is_private_ip` duplicated logic (two files, byte-identical bodies) — superseded by one shared `is_disallowed_ip` in the new `axiam-federation::ssrf` module.
- `AmqpConfig::signing_key: Option<String>` with a "migration mode" fallback — superseded by a mandatory key (dev default shipped) per D-05c.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `ClientBuilder::resolve()`/`resolve_to_addrs()` is the correct/idiomatic reqwest 0.12 mechanism for per-request IP pinning (vs. a custom `dns_resolver`) | Standard Stack, Pattern 1 | If the API shape differs slightly from what's assumed here (e.g., `resolve()` silently no-ops for a domain it's called on more than once per `ClientBuilder` instance — it should be fine since a fresh builder is created per call), the planner needs to re-verify against the exact `reqwest = 0.12.28` docs before task-writing; this was CITED from web search + docs.rs description, not from reading reqwest's own source in this sandbox |
| A2 | Backoff delay for `mail_consumer.rs`'s retry republish should be an in-process `tokio::time::sleep` (mirroring `webhook.rs`'s pattern) rather than a broker-level delay mechanism | Pitfall 6 | If the planner instead expects a RabbitMQ delayed-exchange plugin, this assumption steers away from that — a low-risk, in-scope choice given the "no new infra" constraint, but worth confirming with the user if a broker-level solution is later deemed necessary for horizontal scaling (an in-process sleep blocks that consumer's processing of the queue during the delay window; at 1 consumer per queue today per `main.rs`'s single `tokio::spawn` per consumer, this is a real throughput tradeoff worth flagging to the planner) |
| A3 | Erasure-proof write should be strictly the LAST statement in `purge_single_user`, after `anonymize_user`, reordering the existing (b3)(c)(d)(e)(f)(g)(h) sequence | Pitfall 3, Pattern 3 | If reordering breaks the "anonymize_user last so partial failures leave the user re-selectable" invariant established in Phase 10 (CQ-B38/SEC-056), the fix needs care: the recommended order is pseudonymize → anonymize_user → erasure_proof.create → mark_completed/audit-event, i.e. anonymize_user is still effectively "near-last" (before the proof, not after) so re-selectability is preserved as long as `find_due_for_purge`'s `deletion_pending` flag is only cleared by `anonymize_user`, which is unchanged by this reorder |

## Open Questions

1. **Should the shared SSRF guard module physically live in `axiam-federation` or a new tiny crate?**
   - What we know: `axiam-api-rest` already depends on `axiam-federation` (confirmed via `Cargo.toml`), so no dependency cycle exists either way.
   - What's unclear: whether a future SDK-facing or non-federation caller might need the guard without pulling in all of `axiam-federation`'s SAML/OIDC surface (and its optional `samael`/`libxml` build-time deps behind the `saml` feature).
   - Recommendation: put it in `axiam-federation` as a feature-independent module (not gated by `saml`) since that's the only place two of the three consumers (OIDC, SAML) already live, and `axiam-api-rest` already accepts the dependency; revisit only if a third, federation-unrelated consumer emerges later.

2. **Does the CI env-var bug (Pitfall/Code Example above) actually affect the current green CI, and if so how?**
   - What we know: `AXIAM_DATABASE__*` (wrong prefix) is set in `ci.yml:230-233`; the actual config loader expects `AXIAM__DB__*`.
   - What's unclear: whether `cargo test --workspace` currently passes because tests never read these particular env vars (each `tests/*.rs` file reviewed constructs its own in-memory `Surreal::new::<Mem>(())` directly, bypassing `AppConfig` entirely) or because of some other override path.
   - Recommendation: fix the prefix regardless (it's the literal AC), but the planner should note this is unlikely to change CI's pass/fail outcome — it's a config-hygiene fix, not a currently-manifesting bug.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[tokio::test]` / `#[test]`, workspace-standard (no new framework) |
| Config file | none — per-crate `Cargo.toml` `[dev-dependencies]` |
| Quick run command | `cargo test -p <crate> --lib` or `-p <crate> --test <specific_file>` |
| Full suite command | `cargo test --workspace --no-fail-fast` (phase-gate only, per CLAUDE.md build-hygiene: `cargo clean` between plan steps, `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip` for any `axiam-api-rest` build/test) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|-------------|
| SECHRD-02 | Internal/loopback `token_endpoint` from an OIDC discovery doc is rejected | unit (pure) | `cargo test -p axiam-federation --lib ssrf_rejects_loopback_token_endpoint` | ❌ Wave 0 — new `ssrf.rs` module needed first |
| SECHRD-02 | A `302 → internal IP` redirect is rejected (not silently followed) | unit/integration (wiremock on loopback via existing `allow_private_networks`-style test seam) | `cargo test -p axiam-federation --lib ssrf_rejects_redirect_to_internal` | ❌ Wave 0 |
| SECHRD-02 | Webhook delivery pins the resolved IP (no second DNS resolution at send time) | integration (custom `reqwest::dns::Resolve` test double asserting call count/args) | `cargo test -p axiam-api-rest --test webhook_test webhook_pins_resolved_ip` | ❌ Wave 0 — extend `webhook_test.rs` |
| SECHRD-05 | Revoked issuing CA → device auth fails closed | integration (real in-memory DB, mirrors `mtls_chain_test.rs` pattern: generate CA, `ca_repo.revoke(...)`, then `DeviceAuthService::authenticate`) | `cargo test -p axiam-pki --test mtls_chain_test mtls_rejects_revoked_issuing_ca` | ❌ Wave 0 — extend `mtls_chain_test.rs` |
| SECHRD-05 | Expired issuing CA → device auth fails closed | integration (backdate `not_after` via direct SurrealDB `UPDATE` query in test setup, since no repo method sets arbitrary validity window) | `cargo test -p axiam-pki --test mtls_chain_test mtls_rejects_expired_issuing_ca` | ❌ Wave 0 |
| SECHRD-06 | Failed `pseudonymize_actor` → user re-selectable, no erasure proof written | unit (Pattern 3's extracted `run_erasure_pipeline` fn + a synthetic failing `AuditLogRepository` double) | `cargo test -p axiam-server --test cleanup_task erasure_pipeline_fatal_on_pseudonymize_failure` | ❌ Wave 0 — requires the Pattern 3 extraction first |
| SECHRD-06 | Duplicate export request rejected when `queued`/`ready`-undownloaded/`failed` exists | integration (real in-memory DB, `export_job_repo.create` then assert `has_pending_for_user` true for each status) | `cargo test -p axiam-db --lib export_job_dedup_blocks_ready_and_failed` | ❌ Wave 0 — extend `export_job.rs`'s own `#[cfg(test)]` module |
| SECHRD-06 | Export contains real (metadata-only) `sessions` data | integration (mirrors `gdpr_test.rs` pattern: create a session, run export aggregation, assert non-empty `sessions` array with no `token_hash`) | `cargo test -p axiam-api-rest --test gdpr_test export_includes_real_session_metadata` | ❌ Wave 0 — requires new `SessionRepository::list_by_user` first |
| SECHRD-07 | Request-supplied nonce cannot satisfy verification (replay rejected) | integration (mirrors `req5_oidc_e2e.rs` pattern: wiremock IdP, real ID token signed with a KNOWN nonce, submit callback with a DIFFERENT `req.nonce`, assert 401/rejection) | `cargo test -p axiam-server --test req5_oidc_e2e oidc_linking_ignores_client_supplied_nonce` | ❌ Wave 0 |
| SECHRD-08 | Tenant-A signature cannot validate a tenant-B message | unit (pure — derive both subkeys via HKDF, sign with tenant-A's, verify with tenant-B's, assert failure) | `cargo test -p axiam-amqp --lib per_tenant_signature_cross_tenant_rejected` | ❌ Wave 0 |
| SECHRD-08 | ExportReady mail deliverable end-to-end | integration (mirrors `mail_consumer_test.rs` pattern, asserting `org_id != Uuid::nil()` reaches the rendered template context) | `cargo test -p axiam-amqp --test mail_consumer_test export_ready_resolves_real_org_id` | ❌ Wave 0 — extend `mail_consumer_test.rs` |
| SECHRD-09 | Federation secret never serialized/printed | unit (pure — `serde_json::to_string(&config)` + `format!("{:?}", config)`, assert neither contains the plaintext secret substring) | `cargo test -p axiam-core --lib federation_config_secret_not_serialized` | ❌ Wave 0 |
| SECHRD-10 | SMTP egress + completed secret set work under default-deny | manual/CI-only (NetworkPolicy YAML cannot be unit-tested in Rust; validate via `kubectl apply --dry-run=server` or a k8s-in-docker smoke test if available, else `checkpoint:human-verify`) | n/a — manual | n/a |

### Test Doubles Needed
- **SSRF guard:** a controllable HTTP server on loopback (reuse the `allow_private_networks`-style escape-hatch pattern already established in `jwks_cache.rs:81` for the "server itself is on loopback" case) that returns a 3xx with a `Location` header pointing at a genuinely non-loopback private address (e.g. `10.0.0.5`) — this proves the redirect-hop re-validation without needing a real external network.
- **mTLS:** direct SurrealDB `UPDATE` in test setup to backdate `not_after` on a generated CA row (no repository method exists for this — document as a test-only escape hatch, not a new production API).
- **GDPR erasure:** a synthetic `AuditLogRepository` test double (local struct in the test file) whose `pseudonymize_actor` always returns `Err(AxiamError::Internal(...))`, used only with the Pattern 3 extracted function — NOT with the full `CleanupTask` (which is not generic over repo traits).
- **AMQP per-tenant signing:** no test double needed — this is pure function testing (`hkdf`/`hmac` are deterministic).
- **OIDC nonce replay:** the existing `req5_oidc_e2e.rs` wiremock-based mock IdP pattern (already used for REQ-5 conformance tests) — reuse rather than build new mock infrastructure.

### Sampling Rate
- **Per task commit:** `cargo test -p <touched_crate> --lib` (or `--test <specific_file>` for integration tests)
- **Per wave merge:** `cargo test -p <crate1> -p <crate2> ...` for all crates touched in the wave
- **Phase gate:** `cargo test --workspace --no-fail-fast` full suite green before `/gsd-verify-work` (with `cargo clean` beforehand per CLAUDE.md disk-hygiene rule, and `SWAGGER_UI_DOWNLOAD_URL` set for any `axiam-api-rest` build)

### Wave 0 Gaps
- [ ] `crates/axiam-federation/src/ssrf.rs` — new module, no existing file
- [ ] `SessionRepository::list_by_user` trait method + `SurrealSessionRepository` impl — required before the SECHRD-06 sessions-export test can even compile
- [ ] Extraction of `run_erasure_pipeline` (Pattern 3) from `cleanup.rs::purge_single_user` — required before the SECHRD-06 fatal-pseudonymize-failure test can inject a failure
- [ ] `hkdf` crate added to `crates/axiam-amqp/Cargo.toml` and workspace `Cargo.toml`

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|-------------------|
| V4 Access Control | yes (SECHRD-05) | Issuing-CA status/validity gate before `verify_signature` — fail closed (ASVS 4.1) |
| V5 Input Validation | yes (SECHRD-02) | Resolve-and-pin SSRF guard on all admin/IdP-supplied URLs (ASVS 5.2 — untrusted URL/host validation, SSRF category explicitly called out in ASVS 4.0) |
| V6 Cryptography | yes (SECHRD-08) | HKDF-SHA256 per-tenant key derivation via `hkdf` crate — never hand-rolled (ASVS 6.2) |
| V8 Data Protection | yes (SECHRD-06, SECHRD-09) | GDPR erasure durability (Art. 17 mapping); secret non-serialization (ASVS 8.3 — sensitive data not exposed via logs/API responses) |
| V13 API and Web Service | yes (SECHRD-07) | Server-side state (not client-supplied) as the sole source of truth for replay-defense values (ASVS 13.2, mirrors CSRF/nonce token handling guidance) |
| V1 Architecture | yes (SECHRD-10) | Network segmentation / default-deny egress with explicit allowlists (ASVS 1.2, defense-in-depth for a compromised pod) |

### Known Threat Patterns for this Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| SSRF via admin-configured OIDC/SAML metadata URL pointing at internal services | Tampering / Information Disclosure | Resolve-and-pin guard rejecting private/loopback/link-local/ULA ranges, applied to ALL outbound fetch call sites uniformly (this phase) |
| DNS rebinding (validate public IP, then have DNS flip to internal IP before/at connect time) | Tampering | Pin the exact validated `IpAddr` into the TCP connection via `reqwest::ClientBuilder::resolve()` — no second resolution occurs |
| XSW-adjacent replay: client supplies a stale/attacker-chosen nonce to bypass server-side replay tracking | Spoofing | Server-side state (`FederationLoginState`) as sole nonce source, never trusting request body (this phase, SECHRD-07) |
| Cross-tenant message forgery on a shared message bus | Spoofing / Elevation of Privilege | Per-tenant HMAC subkeys (HKDF-derived) so a leaked/compromised tenant's signing capability cannot forge another tenant's messages (this phase, SECHRD-08) |
| Secret leakage via accidental `Debug`/`Serialize` derive on a struct holding ciphertext/plaintext secret fields | Information Disclosure | `#[serde(skip_serializing)]` + manual `Debug` redaction on every secret-bearing model (this phase, SECHRD-09; already the convention for `CaCertificate::encrypted_private_key`, just not yet applied to `FederationConfig`) |
| Revoked/expired CA still trusted for chain verification | Spoofing / Elevation of Privilege | Explicit CA `status`+validity check before any cryptographic chain verification (this phase, SECHRD-05) |

## Sources

### Primary (HIGH confidence — direct codebase reads, this session)
- `crates/axiam-federation/src/jwks_cache.rs`, `oidc.rs`, `saml.rs`, `lib.rs`, `secrets.rs` — existing SSRF guard, OIDC/SAML fetch call sites, nonce handling
- `crates/axiam-api-rest/src/webhook.rs`, `src/handlers/federation.rs`, `src/handlers/gdpr.rs` — webhook SSRF guard, OIDC authorize/callback handlers (both authenticated and public paths), export request handler
- `crates/axiam-pki/src/mtls.rs`, `crates/axiam-core/src/models/certificate.rs`, `crates/axiam-core/src/repository.rs` (CaCertificateRepository) — mTLS chain verification, CA model
- `crates/axiam-server/src/cleanup.rs`, `crates/axiam-db/src/repository/export_job.rs`, `crates/axiam-core/src/models/session.rs`, `crates/axiam-core/src/repository.rs` (SessionRepository) — GDPR purge/export pipeline
- `crates/axiam-amqp/src/messages.rs`, `audit_consumer.rs`, `authz_consumer.rs`, `mail_consumer.rs`, `mail_publisher.rs`, `config.rs`, `connection.rs` — AMQP signing and mail retry
- `crates/axiam-core/src/models/federation.rs`, `crates/axiam-db/src/repository/federation_config.rs` — federation secret serialization gap
- `k8s/network-policy/server-egress.yml`, `default-deny.yml`, `k8s/server/secret.yml`, `.github/workflows/ci.yml` — network egress and CI env var bug
- `crates/axiam-pki/tests/mtls_chain_test.rs`, `crates/axiam-server/tests/cleanup_task.rs`, `crates/axiam-server/tests/req14_gdpr_test.rs` — existing test patterns/precedents used to shape the Validation Architecture section
- `Cargo.lock`, `Cargo.toml` (workspace + `axiam-amqp`) — dependency version verification

### Secondary (MEDIUM confidence)
- `docs.rs/reqwest` `ClientBuilder::resolve`/`resolve_to_addrs` — confirmed via WebSearch [CITED: docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html, github.com/seanmonstar/reqwest commit history]; not read directly from reqwest's own source in this sandbox

### Tertiary (LOW confidence)
- None — every claim in this document is either a direct codebase read or a cited public-docs reference; no unverified training-knowledge claims about AXIAM's own code were made. The two entries in the Assumptions Log (A1, A2) are the only genuinely `[ASSUMED]`-tagged items, both scoped to implementation-mechanism choices explicitly left to planner discretion in CONTEXT.md.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — `hkdf` verified via `cargo search` + `gsd-tools package-legitimacy check`; `reqwest`/`hmac`/`sha2` versions read directly from `Cargo.lock`
- Architecture: HIGH — every pattern is either an existing, working in-repo reference (SECHRD-07, SECHRD-05) or a minimal extension of one (SECHRD-02, SECHRD-08, SECHRD-09); the one genuinely new piece (GDPR test-seam extraction, Pattern 3) is explicitly flagged as a recommendation, not a verified-in-repo fact
- Pitfalls: HIGH — all 7 pitfalls are grounded in specific file:line reads showing the exact current (buggy) behavior, not speculation

**Research date:** 2026-07-04
**Valid until:** 2026-08-03 (30 days — stable, internal-codebase-grounded findings; re-verify file:line citations if the codebase has drifted significantly, e.g. after Phase 24 gap-closure work lands additional commits)
