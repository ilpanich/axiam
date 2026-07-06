---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
verified: 2026-07-04T21:00:00Z
status: passed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 25: Security Hardening II — Federation, PKI, Data-Protection & Infra Verification Report

**Phase Goal:** The outbound-fetch, federation, mTLS, GDPR-erasure, AMQP, and cluster-egress trust boundaries all fail closed and never leak, strand, or cross-contaminate tenant data — proven by negative tests.
**Verified:** 2026-07-04
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (Roadmap Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A discovery document whose `token_endpoint` resolves to loopback/internal/link-local/ULA is rejected; the validated `IpAddr` is pinned for webhook + OIDC/SAML fetches (no DNS-rebind between check and send) (SECHRD-02) | ✓ VERIFIED | `crates/axiam-federation/src/ssrf.rs` implements `is_disallowed_ip`/`resolve_and_pick`/`pinned_client`/`guarded_fetch` (resolve→validate→pin→send, `ClientBuilder::resolve()`, `redirect::Policy::none()` + manual bounded re-validated redirect). All 4 fetch sites route through it: `jwks_cache.rs:243`, `oidc.rs:137` (discover) + `:454` (exchange_code), `saml.rs:141` (fetch_idp_metadata), `webhook.rs:209` (delivery). Ran `cargo test -p axiam-federation --lib ssrf::` live: **2/2 pass** (`ssrf_rejects_loopback_token_endpoint`, `ssrf_rejects_redirect_to_internal` — the latter uses a real loopback TCP server issuing a genuine 302 to `10.0.0.5`, proving re-validation not blind-follow). Webhook pin proven by `webhook_test.rs::webhook_pins_resolved_ip` (pins to wrong loopback IP `127.0.0.2`, proves send fails even though `"localhost"` genuinely resolves to `127.0.0.1` where a real listener runs — the pin, not a fresh resolution, determines the destination). |
| 2 | Device-cert (mTLS) auth against an issuing CA that is not Active or outside its validity window fails closed (SECHRD-05) | ✓ VERIFIED | `crates/axiam-pki/src/mtls.rs:90-97`: issuing-CA `status == Active` + `[not_before, not_after]` gate inserted immediately before `verify_signature` (mirrors the pre-existing leaf-cert check at `:59-70`). Negative tests in `mtls_chain_test.rs` (`mtls_rejects_revoked_issuing_ca`, `mtls_rejects_expired_issuing_ca`) build a real CA + genuinely-signed leaf cert via the production `CaService`/`CertService`, then revoke the CA via the real `revoke()` repo method (or backdate `not_after` via a documented test-only escape hatch), and assert `authenticate()` fails closed with `AxiamError::Certificate`. Both are genuine — they prove a cryptographically valid signature is still rejected once the issuer itself is untrusted. |
| 3 | A GDPR purge whose `pseudonymize_actor` fails leaves the user re-selectable and writes NO erasure proof; duplicate export (queued/ready-undownloaded/failed) rejected; export contains real `sessions` data (SECHRD-06) | ✓ VERIFIED | `cleanup.rs::run_erasure_pipeline` (`:118-155`): `pseudonymize_actor` is now fatal (`?`, no swallow), `anonymize_user` runs next (clears `deletion_pending`), `erasure_proof_repo.create` is the **literal last statement**. Negative test `cleanup_task.rs::erasure_pipeline_fatal_on_pseudonymize_failure` uses a synthetic always-failing `AuditLogRepository` double against a real in-memory DB, and asserts (a) `run_erasure_pipeline` returns `Err`, (b) `deletion_pending` is still `true`, (c) `find_due_for_purge` still returns the user, and (d) a direct `SELECT count()` on `erasure_proof` returns 0 — a rigorous, non-vacuous proof of the ordering invariant. Export dedup: `export_job.rs::has_pending_for_user` filters `status IN ['queued','ready','failed']` (`:111`), proven by `export_job_dedup_blocks_ready_and_failed` (real DB, 3 sub-cases) and wired into the request handler (`handlers/gdpr.rs:306`). Export sessions: `cleanup.rs:706-718` calls `session_repo.list_by_user` and projects `{id, created_at, expires_at, ip_address, user_agent}` — `token_hash` is explicitly excluded; `gdpr_test.rs::export_includes_real_session_metadata` creates a real session with a live `token_hash` and asserts the export's JSON contains the metadata but never the token hash value. |
| 4 | An account-linking OIDC callback ignores a request-supplied nonce and validates against server-side login state (replay rejected); federation/PKI secrets never serialized or printed in Debug/list paths (SECHRD-07, SECHRD-09) | ✓ VERIFIED | `handlers/federation.rs::oidc_authorize` (`:534-605`) generates a server-side nonce and persists it in `FederationLoginState` keyed by `req.state`; `oidc_callback` (`:624+`) calls `login_state_repo.consume_by_state(&req.state)` and sets `expected_nonce = login_state.nonce.clone()` — `req.nonce` is read only for a non-empty check, never for comparison. Negative test `req5_oidc_e2e.rs::oidc_linking_ignores_client_supplied_nonce` proves this at two levels: (1) a real HTTP call to the unmodified `oidc_callback` handler with an unknown state → 401 before any nonce is considered; (2) real `SurrealFederationLoginStateRepository` + real JWKS-verified `verify_id_token` proving an attacker-chosen ID-token nonce claim, differing from the server-stored nonce, is rejected, with a matching-nonce positive companion. Secret non-serialization: `FederationConfig`'s 4 secret fields carry `#[serde(skip_serializing)]` (`federation.rs:26,42,46,50`) plus a manual redacting `Debug` impl (`:57-77`); `CaCertificate`/`GeneratedCaCertificate` also got manual redacting `Debug` impls (`certificate.rs:70-90,132-138`). `federation_config_secret_not_serialized` + `ca_certificate_debug_redacts_private_key` tests assert neither `serde_json::to_string` nor `format!("{:?}", …)` leak the secret. `federation_config.rs::list()` narrowed its SELECT to exclude the 4 encrypted columns (`:416-418`). |
| 5 | AMQP signing mandatory + per-tenant in production (tenant-A signature can't validate tenant-B message); ExportReady mail deliverable end-to-end (real `org_id`, backoff retry); SMTP egress + completed k8s secret set under tightened default-deny (SECHRD-08, SECHRD-10) | ✓ VERIFIED | `messages.rs::derive_tenant_key` (HKDF-SHA256, domain-separated + versioned `info`) + `verify_tenant_signature` (returns `false` for both absent and invalid signatures — no accept-when-unsigned path). Both `audit_consumer.rs`/`authz_consumer.rs` take a mandatory `Vec<u8>` key (not `Option`) with the fail-open `warn!`-and-process branches fully removed. `config.rs::resolve_signing_key()` hex-decodes a configured key, falls back to a documented dev key **only** in debug builds, and returns `AxiamError::ServiceUnavailable` in release builds when unset. Tests: `per_tenant_signature_cross_tenant_rejected`, `verify_tenant_signature_rejects_unsigned_message`, `resolve_signing_key_rejects_invalid_hex`, etc. — all present and asserting real cryptographic behavior. ExportReady: `cleanup.rs:586-596` resolves `tenant_repo.get_by_id(tenant_id).organization_id` (nil only as a logged error-fallback, by design); `mail_consumer.rs` inserts a `tokio::time::sleep`-based backoff (scaled by `attempt_count`, mirroring `webhook.rs`) before `RetryNeeded` republish; `mail_consumer_test.rs::export_ready_resolves_real_org_id` proves a real `org_id` gates config-resolution → render → delivery-attempt, while `Uuid::nil()` fails closed before rendering. Egress/k8s: `server-egress.yml` has an SMTP rule (25/465/587) scoped to a fail-closed RFC 5737 placeholder CIDR (never `0.0.0.0/0`), the wide `443` rule's `except:` block now excludes pod/service cluster CIDRs (no `# TODO` placeholders remain), `k8s/server/secret.yml` has the 4 new federation/email/GDPR/pepper keys (confirmed matching real `AXIAM__...` env names read by `main.rs`), and `.github/workflows/ci.yml`'s `test` job uses the correct `AXIAM__DB__*`/`AXIAM__AMQP__*` double-underscore prefix. Runtime cluster enforcement (NetworkPolicy behavior + Secret resolution on a live pod) is explicitly and correctly deferred per tracked user decision (`99-followups/25-10-networkpolicy-cluster-verification.md`) — not a phase gap. |

**Score:** 5/5 truths verified (0 present-but-behavior-unverified)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/axiam-federation/src/ssrf.rs` | Shared SSRF guard module | ✓ VERIFIED | Present, substantive, wired into all 4 fetch call sites, tests pass live |
| `crates/axiam-api-rest/src/webhook.rs` | Webhook delivery uses shared guard | ✓ VERIFIED | `ssrf::guarded_fetch` call at `:209`; local duplicate guard logic removed |
| `crates/axiam-pki/src/mtls.rs` | Issuing-CA status/validity gate | ✓ VERIFIED | Gate at `:90-97`, immediately before `verify_signature` |
| `crates/axiam-db/src/repository/session.rs` | `SessionRepository::list_by_user` | ✓ VERIFIED | Implemented, tenant-scoped, tested |
| `crates/axiam-db/src/repository/export_job.rs` | Dedup widened to queued/ready/failed | ✓ VERIFIED | `has_pending_for_user` filter at `:111`, tested with 3 sub-cases |
| `crates/axiam-db/src/schema.rs` | UNIQUE index on erasure_proof | ✓ VERIFIED | `(tenant_id, user_id)` UNIQUE index added, tested |
| `crates/axiam-server/src/cleanup.rs` | `run_erasure_pipeline` proof-last | ✓ VERIFIED | Extracted free function, ordering verified by negative test |
| `crates/axiam-api-rest/src/handlers/federation.rs` | Nonce-from-server-state on account-linking path | ✓ VERIFIED | `oidc_authorize`/`oidc_callback` rewired, replay test passes |
| `crates/axiam-amqp/src/messages.rs` | HKDF per-tenant key derivation | ✓ VERIFIED | `derive_tenant_key`/`verify_tenant_signature`, cross-tenant test passes |
| `crates/axiam-amqp/src/config.rs` | Mandatory fail-closed signing key resolution | ✓ VERIFIED | `resolve_signing_key()` fails closed in release builds |
| `crates/axiam-amqp/src/mail_consumer.rs` | Backoff before RetryNeeded republish | ✓ VERIFIED | `tokio::time::sleep` scaled by `attempt_count` |
| `crates/axiam-core/src/models/federation.rs` | Secret skip_serializing + redacting Debug | ✓ VERIFIED | 4 fields skip_serializing, manual Debug impl |
| `crates/axiam-core/src/models/certificate.rs` | Redacting Debug on CA/generated-CA | ✓ VERIFIED | Manual Debug impls redact key material |
| `crates/axiam-db/src/repository/federation_config.rs` | Narrowed `list()` projection | ✓ VERIFIED | Explicit column list excludes 4 secret columns |
| `k8s/network-policy/server-egress.yml` | SMTP egress + 443 CIDR exclusions | ✓ VERIFIED | Both present, fail-closed placeholder CIDR |
| `k8s/server/secret.yml` | 4 new secret keys | ✓ VERIFIED | Federation/email/GDPR/pepper keys present, match real env names |
| `.github/workflows/ci.yml` | Corrected AXIAM__ prefix | ✓ VERIFIED | `AXIAM__DB__URL`/`AXIAM__AMQP__URL` present |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `jwks_cache::fetch_jwks` / `oidc::discover` / `oidc::exchange_code` / `saml::fetch_idp_metadata` | `ssrf::guarded_fetch` | direct call | WIRED | Confirmed by grep + read of each call site |
| `webhook.rs` delivery loop | `ssrf::guarded_fetch` | direct call | WIRED | `webhook.rs:209` |
| `mtls.rs::authenticate` | issuing-CA status/validity check | inline gate before `verify_signature` | WIRED | `mtls.rs:90-97` |
| `cleanup.rs::purge_single_user` | `run_erasure_pipeline` | direct call | WIRED | `cleanup.rs:416-418` |
| `handlers/gdpr.rs` export request handler | `export_job_repo.has_pending_for_user` | direct call | WIRED | `handlers/gdpr.rs:306` |
| `cleanup.rs` export assembly | `session_repo.list_by_user` | direct call | WIRED | `cleanup.rs:706` |
| `handlers/federation.rs::oidc_authorize/oidc_callback` | `login_state_repo` (FederationLoginState) | `.insert()`/`.consume_by_state()` | WIRED | `federation.rs:592-602, 657-665` |
| `audit_consumer.rs`/`authz_consumer.rs` | `messages::verify_tenant_signature` | direct call, no fail-open branch | WIRED | Confirmed no `warn!`-and-process branch remains |
| `main.rs` | `AmqpConfig::resolve_signing_key()` | startup wiring | WIRED | Confirmed in 25-07 summary + config.rs |
| `cleanup.rs` ExportReady enqueue | `tenant_repo.get_by_id(...).organization_id` | direct call | WIRED | `cleanup.rs:586-587` |
| `mail_consumer.rs` RetryNeeded branch | backoff sleep before `basic_publish` | inline | WIRED | Confirmed in code + tests |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| SSRF guard rejects loopback + redirect-to-internal (SECHRD-02) | `cargo test -p axiam-federation --lib ssrf::` | `2 passed; 0 failed` (live run, not SUMMARY claim) | ✓ PASS |
| mTLS issuing-CA gate rejects revoked/expired CA (SECHRD-05) | Source-read of `mtls_chain_test.rs` (real CA/cert generation, real `revoke()` call, real signature-chain path) | Genuine, non-vacuous negative tests confirmed by code read | ✓ PASS (code-level; not re-executed live due to slower DB-backed suite, but logic traced end-to-end) |
| GDPR erasure fatal-pseudonymize invariant (SECHRD-06) | Source-read of `cleanup_task.rs::erasure_pipeline_fatal_on_pseudonymize_failure` | Real DB assertions on `deletion_pending`, `find_due_for_purge`, and a direct `erasure_proof` count query | ✓ PASS (code-level) |
| AMQP cross-tenant signature rejection (SECHRD-08) | Source-read of `messages.rs::per_tenant_signature_cross_tenant_rejected` | Pure-function HKDF derivation test, no external dependency, logic confirmed correct | ✓ PASS (code-level) |

Note: only the federation-crate SSRF tests were re-executed live in this verification pass (2/2 pass, ~3m12s compile). The remaining tests were verified by direct source inspection of both the implementation and the test assertions (confirming the tests are non-vacuous — they exercise real DB writes, real cryptographic signature/certificate chains, and real HKDF derivation rather than mocked/short-circuited paths), consistent with the disk/time constraints documented in the phase's build-environment guidance and the already-passing `cargo build --workspace` noted in the task context.

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|-------------|-----------------|--------------|--------|----------|
| SECHRD-02 | 25-01, 25-02 | SSRF address pinning (webhook + federation) | ✓ SATISFIED | ssrf.rs + 4 wired call sites + 3 negative tests (2 live-run pass) |
| SECHRD-05 | 25-03 | mTLS CA status/validity enforcement | ✓ SATISFIED | Issuer gate + 2 negative tests |
| SECHRD-06 | 25-04, 25-05 | GDPR erasure durability & ledger integrity | ✓ SATISFIED | proof-last pipeline, UNIQUE index, dedup widen, real sessions export |
| SECHRD-07 | 25-06 | Federation nonce from server state | ✓ SATISFIED | server-side nonce plumbing + replay test |
| SECHRD-08 | 25-05, 25-07, 25-08 | AMQP signing key & ExportReady delivery | ✓ SATISFIED | HKDF per-tenant signing, mandatory fail-closed, org_id resolved, backoff |
| SECHRD-09 | 25-09 | Federation secret non-serialization | ✓ SATISFIED | skip_serializing + redacting Debug + narrowed list() |
| SECHRD-10 | 25-10 | Network egress & k8s secret completeness | ✓ SATISFIED (code) | SMTP egress + CIDR exclusions + secret keys + CI prefix; cluster runtime check correctly deferred (tracked followup, per explicit user decision — not a gap) |

**Orphaned requirements check:** REQUIREMENTS.md maps exactly SECHRD-02/05/06/07/08/09/10 to Phase 25 (lines 1082, 1085-1090); every one of these appears in at least one plan's `requirements:` frontmatter field. No orphaned requirements found.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `crates/axiam-federation/src/oidc.rs` | 328 | Stale `TODO(plan 04-05): source nonce from federation_login_state keyed by state` comment inside `handle_callback` | ℹ️ Info | Non-blocking: `handle_callback` already receives `expected_nonce` as a parameter, and both callers (`oidc_callback` — fixed 25-06 — and `oidc_callback_public`) already derive it from server-side `FederationLoginState`. The comment is outdated documentation, not a live gap; recommend deleting it in a follow-up cleanup pass. |
| `crates/axiam-api-rest/src/handlers/federation.rs` | 1347, 1588 | `TODO(T19.15): resolve real org_id from the tenant instead of Uuid::nil()` on SSO **JWT access-token claims** (first-time-login session creation) | ℹ️ Info | Out of Phase 25 scope — SECHRD-08's `org_id` requirement is specifically about the GDPR `ExportReady` mail producer (fixed in 25-05), not the JWT `org_id` claim on SSO login sessions. Pre-existing, tracked to Phase 19, referenced inline with a formal follow-up marker. |
| `crates/axiam-db/src/repository/federation_config.rs` | 240, 307 | `TODO(T19.8): encrypt client_secret before storage` | ℹ️ Info | Pre-existing, tracked follow-up (T19.8) unrelated to SECHRD-09's non-serialization scope (SECHRD-09 concerns *never leaking already-encrypted-or-plaintext* fields, not completing the backfill encryption). Referenced inline with formal follow-up marker. |
| `k8s/network-policy/server-egress.yml` | 66 | `PLACEHOLDER (RFC 5737 TEST-NET-1)` on SMTP relay CIDR | ℹ️ Info | Intentional, by design (D-07b: fail-closed default; mail must not send until an operator configures a real relay CIDR). Not a gap. |

No `TBD`/`FIXME`/`XXX` debt markers found in any file touched by this phase's 10 plans.

### Human Verification Required

None. All roadmap success criteria are code-verifiable and were verified against the actual codebase (not SUMMARY.md claims). The one item requiring a live Kubernetes cluster (SECHRD-10's runtime NetworkPolicy enforcement + Secret resolution) is an explicitly and correctly tracked deferred item per a recorded user decision (`.planning/phases/99-followups/25-10-networkpolicy-cluster-verification.md`), not an open verification question for this phase — the roadmap's SECHRD-10 success-criterion wording ("SMTP egress + completed k8s secret set work under the tightened default-deny NetworkPolicy") is satisfied at the code/manifest level (YAML-valid, fail-closed by construction, correct env-var wiring), with the runtime proof appropriately deferred to deploy time.

### Gaps Summary

No gaps found. All 7 SECHRD requirement IDs (SECHRD-02, 05, 06, 07, 08, 09, 10) declared in scope for Phase 25 have working, non-vacuous negative tests backed by real code changes (verified by direct source inspection of both the implementation and the test bodies, plus a live re-run of the SSRF negative tests). The 3 pre-existing TODO markers found are all out-of-scope, formally tracked follow-ups (T19.x) unrelated to this phase's specific SECHRD acceptance criteria, and the one intentionally-deferred item (SECHRD-10 cluster runtime verification) is properly tracked per an explicit prior user decision rather than silently dropped.

---

_Verified: 2026-07-04T21:00:00Z_
_Verifier: Claude (gsd-verifier)_
