# Phase 25: Security Hardening II — Federation, PKI, Data-Protection & Infra - Context

**Gathered:** 2026-07-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Make the **outbound-fetch, federation, mTLS, GDPR-erasure, AMQP, and cluster-egress** trust boundaries all **fail closed** — never leak, strand, or cross-contaminate tenant data. Scope is exactly **SECHRD-02, SECHRD-05, SECHRD-06, SECHRD-07, SECHRD-08, SECHRD-09, SECHRD-10** — each fix ships a **negative test** proving the attack/leak is now rejected (the phase's defining success signal). No other findings, no refactors beyond what a given fix strictly requires. Sibling to Phase 24, which already shipped SECHRD-01/03/04/11/12.

- **SECHRD-02 / SEC-019+064** — SSRF address pinning: extend the private/loopback/link-local/ULA guard beyond JWKS to OIDC discovery + token exchange + SAML-metadata fetches, and pin the validated `IpAddr` into the connection (no DNS-rebind between check and send).
- **SECHRD-05 / SEC-061** — mTLS CA status/validity: assert the **issuing CA** is `Active` and within its validity window before `verify_signature`; revoked/expired CA ⇒ device auth fails closed.
- **SECHRD-06 / SEC-063+065+066+CQ-B38** — GDPR erasure durability & ledger: `pseudonymize_actor` failure is fatal to the purge (leave re-selection flags set, write no proof); erasure proof unique per user; export dedup blocks `queued`/`ready`-undownloaded/`failed`; export contains real `sessions` data.
- **SECHRD-07 / SEC-004** — federation nonce from server state: the account-linking OIDC callback derives `expected_nonce` from stored login state, ignoring `req.nonce`; replay rejected.
- **SECHRD-08 / SEC-022+055** — AMQP signing key + ExportReady delivery: signing mandatory & fail-closed in prod, **per-tenant** so a tenant-A signature can't validate a tenant-B message; ExportReady resolves real `org_id` (not `Uuid::nil()`); mail-retry uses backoff.
- **SECHRD-09 / SEC-017+043** — federation secret non-serialization: `#[serde(skip_serializing)]` on federation/PKI secret fields; `Debug` impls don't print secret/CA/PGP blobs; list queries don't hydrate encrypted columns.
- **SECHRD-10 / SEC-053+052** — network egress & k8s secret completeness: SMTP egress NetworkPolicy under tightened default-deny, `0.0.0.0/0:443` tightened with cluster-CIDR exclusions, k8s secret set completed + CI `AXIAM__…` prefix.

**Out of scope (tracked elsewhere in v1.2):** all Phase 24 items (SECHRD-01/03/04/11/12 — already landed); gRPC governor throughput semantics + SurrealDB token renewal + durable webhook delivery + Playwright-in-CI + frontend flows (CORR-01..06 → Phase 26); performance/load hardening (PERF-* → Phase 27); functional completeness incl. unauthenticated first-time federation login (FUNC-* → Phase 28); structural refactors (QUAL-* → Phase 29); GDPR completeness certification / CRL/OCSP revocation (CMPL-02 / post-v1.0-beta). Full CA-chain-walk and PGP-encrypted export are explicitly deferred (see Deferred Ideas).

</domain>

<decisions>
## Implementation Decisions

> Captured interactively during discuss-phase (2026-07-04). The user selected the more robust / fail-closed option on **all 12 forks** (4 primary + 4 second-order + 4 third-order). This is consistent with the Phase 24 posture. The remaining acceptance-criteria mechanics are single-path prescriptive and flow straight into planning (see "Claude's Discretion").

### SSRF address pinning (SECHRD-02)
- **D-01a — One shared SSRF-guarded HTTP client/resolver.** All outbound fetches — webhook delivery, OIDC discovery, OIDC token exchange, SAML metadata, and JWKS — funnel through a **single** guarded client that performs the private/loopback/link-local/ULA check and resolve-once-and-pin in one place. **Generalize the existing `is_private_jwks_ip`** (`jwks_cache.rs:225`) into one reusable helper. DRY, single audit point — rather than duplicating the guard at each call site.
- **D-01b — Disable auto-redirects; re-validate on 3xx.** The guarded client follows **no** redirects automatically. On a 3xx, re-run the full SSRF guard (private-IP check + resolve-pin) against the redirect target and re-issue explicitly. Closes the classic `302 → internal IP` bypass with the least surface.
- **D-01c — Resolve fresh per request; guard A + AAAA; pin the connected IP.** No cross-request DNS cache (avoids stale-pin and narrows the rebind window). Resolve **both** A and AAAA records, reject if **any** resolved address is private/loopback/link-local/ULA, and pin the exact `IpAddr` used to connect. (Note: webhook delivery already re-resolves+pins from Phase 11 — fold it onto the shared helper; don't regress it.)

### mTLS CA status & validity (SECHRD-05)
- **D-02 — Immediate issuing CA only.** In `mtls.rs`, before `verify_signature`, assert the cert's **direct issuing CA** has `status == Active` **and** now is within the CA's validity window. Revoked/expired issuing CA ⇒ device auth fails closed. Matches the AC wording and AXIAM's flat org/tenant-CA→device-cert model. `mtls.rs` already checks the leaf cert (`status`, `not_before`/`not_after`); this adds the **issuer** check. Full-chain walk is deferred (over-engineering for the current flat hierarchy).

### GDPR erasure durability & ledger (SECHRD-06)
- **D-03a — Proof-last, idempotent retry (not a wrapped transaction).** Run PII-bearing steps in order; write the erasure proof **only after every step succeeds**. On any failure (esp. `audit_repo.pseudonymize_actor`), leave the user's re-selection flags set so a retry re-runs cleanly and **no false proof** is ever written. Fits SurrealDB's per-statement semantics and `cleanup.rs`'s current structure better than a fragile multi-table transaction spanning cross-store mail/audit side-effects.
- **D-03b — Erasure-proof uniqueness via a DB UNIQUE index on `user_id`.** A late-stage retry's duplicate proof CREATE no-ops/fails idempotently at the schema level. Simplest, DB-enforced, directly encodes "unique per user" as an invariant.
- **D-03c — Export session data: metadata only, redact token material.** The export includes real `sessions` rows (created_at/expires_at/last_seen/ip/user_agent) but **NOT** the opaque refresh/session token or its hash — a GDPR data export must not hand the user back live credential material. Also honors per-item shutdown checks.
- **D-03d — Export dedup blocks more states.** Duplicate-export guard blocks when a `queued` **or** `ready`-but-undownloaded **or** `failed` job exists (not only `queued`, as today at `export_job.rs:99-108`).

### Federation nonce from server state (SECHRD-07)
- **D-04 — Server-side nonce only.** `handlers/federation.rs:595-648` (account-linking OIDC callback) derives `expected_nonce` from stored login state (same as the public path), **ignoring** `req.nonce`. Replay test: a request-supplied nonce cannot satisfy verification. (Prescriptive — no fork; recorded for completeness.)

### AMQP signing key + ExportReady delivery (SECHRD-08)
- **D-05a — HKDF-derived per-tenant subkeys from one master key.** One master `AXIAM__AMQP__SIGNING_KEY`; per-tenant HMAC subkey = **HKDF-SHA256(master, salt, info)**. A tenant-A signature cannot validate a tenant-B message, with **no per-tenant secret storage/rotation**. Minimal change to the existing shared-key HMAC path in `messages.rs` (`sign_message`/`verify_message`).
- **D-05b — HKDF construction: domain-separated + versioned.** Fixed app salt, `info = "axiam-amqp-v1" || tenant_id`, plus a **`key_version` byte carried on the message** so the master key can be rotated later without breaking in-flight messages. Domain-separated from any other HKDF use.
- **D-05c — Signing always required; ship a dev key.** Signing is mandatory in **every** environment — **no unsigned code path exists** (no warn-and-process branch to regress into a prod bypass). Ship a documented dev key in `config`/`.env.example` so local/test runs work. Prod fails closed if the master key is unset.
- **D-05d — ExportReady resolves real `org_id` + backoff retry.** The ExportReady producer/consumer resolves the real `org_id` from the tenant (`cleanup.rs:508` no longer enqueues `Uuid::nil()`); mail-retry republish uses a backoff delay. End-to-end deliverability proven by test.

### Federation secret non-serialization (SECHRD-09)
- **D-06 — `skip_serializing` + Debug scrubbing.** `#[serde(skip_serializing)]` on `FederationConfig` `client_secret` / `client_secret_ciphertext` / `_nonce` / `_key_version`; `Debug` impls don't print CA/PGP/secret blobs; list queries don't hydrate encrypted columns needlessly. Reuse the existing AES-256-GCM at-rest + serde-skip conventions. (Prescriptive — recorded for completeness.)

### Network egress & k8s secret completeness (SECHRD-10)
- **D-07a — SMTP egress restricted to a configurable relay CIDR.** Allow 25/465/587 egress **only** to a Helm/kustomize-parameterized SMTP-relay CIDR (documented placeholder), keeping default-deny meaningful.
- **D-07b — Fail-closed default (mail off until configured).** The relay-CIDR default is restrictive (empty selector / documented example CIDR) so **no** SMTP egress is allowed until the operator sets their relay CIDR. Mail visibly won't send until configured — consistent with default-deny. Never ship `0.0.0.0/0:587` as a default.
- **D-07c — Tighten `0.0.0.0/0:443` + complete the secret set.** The `443` egress rule gets pod/service cluster-CIDR exclusions; the k8s secret includes federation/email/GDPR/pepper keys; CI `test` job uses the correct `AXIAM__…` prefix.

### Claude's Discretion
These are prescriptive enough in the acceptance criteria that the researcher/planner should nail them directly — no user decision needed:

- **SSRF pin mechanism (SECHRD-02):** the exact reqwest mechanism for pinning the resolved IP (`Client::resolve()` static override vs a custom `dns_resolver`) is planner's choice — the contract is "the validated `IpAddr` is what the socket connects to."
- **mTLS clock source (SECHRD-05):** system UTC (`Utc::now()` / equivalent) as already used for the leaf-cert validity check in `mtls.rs`.
- **ExportReady `org_id` resolution site (SECHRD-08):** producer-side vs consumer-side resolution is planner's choice provided the delivered mail carries the real `org_id`; backoff delay value/curve is planner's choice (align with existing AMQP retry conventions).
- **Federation nonce + secret-skip (SECHRD-07/09):** single-path implementations of the ACs above.
- **`443` cluster-CIDR exclusion values (SECHRD-10):** parameterize via kustomize/Helm values with a documented placeholder; exact CIDRs are cluster-specific.
- **Test placement:** Rust negative/replay/concurrency tests in the owning crate's `tests/` (`axiam-federation`, `axiam-pki`, `axiam-amqp`, `axiam-server`, `axiam-db`, `axiam-api-rest`); per-crate `cargo check/test -p <crate>` only (never full workspace).
- **Per-PLAN `<threat_model>`:** the security capability is active — each PLAN.md carries an ASVS-aligned threat-model block for the control it touches.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Authoritative finding descriptions
- `claude_dev/security-review-postremediation.md` — SEC-019/064 (SSRF), SEC-061 (mTLS CA), SEC-063/065/066 (GDPR erasure/ledger/export), SEC-004 (federation nonce), SEC-022/055 (AMQP signing + ExportReady), SEC-017/043 (federation secret serialization), SEC-053/052 (egress + k8s secrets) — exact issue + suggested fix per finding.
- `claude_dev/code-review-postremediation.md` — CQ-B38 residual (GDPR export sessions / per-item shutdown), CQ-B05 residual (AMQP), cross-references for the touched surfaces.
- `claude_dev/roadmap.md` — original T18/T19 descriptions for these surfaces.

### Requirements & roadmap
- `.planning/REQUIREMENTS.md` §SECHRD-02, SECHRD-05, SECHRD-06, SECHRD-07, SECHRD-08, SECHRD-09, SECHRD-10 — full acceptance criteria + verification baseline (lines 678-779).
- `.planning/ROADMAP.md` §"Phase 25" (lines 1081-1096) — goal + 5 success criteria (each includes a negative test).
- `CLAUDE.md` — security standards: AES-256-GCM at rest, EdDSA/Ed25519, HMAC-SHA256 webhook/AMQP signing, X.509 RSA-4096/Ed25519, append-only audit, fail-closed default, TLS 1.3 min, per-crate build discipline.

### Prior-phase carry-forward
- `.planning/phases/24-security-hardening-i-authentication-access-control-surfaces/24-CONTEXT.md` — sibling phase; **D-02** added a GDPR audit dead-letter (file + syslog) in `cleanup.rs` that this phase's SECHRD-06 builds on **additively** (keep it, don't conflict); fail-closed-default + negative-test-per-fix bar established there.
- `.planning/phases/23-security-regressions-high-findings/23-CONTEXT.md` — Phase 23 posture (fail-closed default; negative-test-per-fix bar; SAML XSW binding + logout revocation groundwork).

### Code surfaces (verify current file:line before editing — may have drifted)
- **SECHRD-02:** `crates/axiam-federation/src/jwks_cache.rs:225` (`is_private_jwks_ip` — generalize into shared guard), `:62,102,158` (JWKS fetch); `crates/axiam-federation/src/oidc.rs:91,109,782` (discovery/token `reqwest::Client`); `crates/axiam-federation/src/saml.rs:94,110,1170` (metadata `reqwest::Client`); `crates/axiam-api-rest/src/webhook.rs` + `handlers/webhooks.rs` (webhook delivery — already re-resolves+pins from Phase 11, fold onto shared helper).
- **SECHRD-05:** `crates/axiam-pki/src/mtls.rs:39-66,98` (leaf-cert `status`/validity already checked at `:59-66`; add the **issuing-CA** `status==Active` + validity check before `verify_signature` at `:98`).
- **SECHRD-06:** `crates/axiam-server/src/cleanup.rs:327-344` (purge ordering / `pseudonymize_actor` failure), `:337-380` (erasure-proof rows), `:391` (`actor_id: Uuid::nil()`), `:503-519` (ExportReady enqueue), `:508` (`org_id: Uuid::nil()`); `crates/axiam-db/src/repository/export_job.rs:99-108` (dedup — currently only `queued`), `:45-53` (status parse: `queued`/`ready`/`failed`), export session assembly (real `sessions`, not `[]`).
- **SECHRD-07:** `crates/axiam-api-rest/src/handlers/federation.rs:595-648` (account-linking callback — derive `expected_nonce` from stored login state).
- **SECHRD-08:** `crates/axiam-amqp/src/messages.rs:26-46` (`compute_hmac`/`verify` — single shared key today), `:67-72,100-102` (`hmac_signature` fields); AMQP config/env for `AXIAM__AMQP__SIGNING_KEY`; `crates/axiam-server/src/cleanup.rs:503-519` (ExportReady producer). Existing test: `messages.rs:184` (`amqp_hmac_sign_verify_round_trip`).
- **SECHRD-09:** `crates/axiam-core/src/models` federation config model (`client_secret`/`_ciphertext`/`_nonce`/`_key_version`), list-query hydration, `Debug` impls on CA/PGP/secret-bearing structs.
- **SECHRD-10:** `k8s/network-policy/server-egress.yml`, `k8s/network-policy/default-deny.yml`, `k8s/network-policy/allow-dns-egress.yml`; k8s Secret manifests under `k8s/server/`; `k8s/kustomization.yml`; CI `test` job env (`AXIAM__…` prefix).

### Codebase maps (context)
- `.planning/codebase/ARCHITECTURE.md`, `CONVENTIONS.md`, `TESTING.md`, `CONCERNS.md`, `INTEGRATIONS.md` — trait-in-core / impl-in-db / thin-handler layering, per-crate build discipline, existing test bias (zero tests historically for axiam-pki/axiam-federation/axiam-amqp — this phase adds negative tests there).

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`is_private_jwks_ip` (`jwks_cache.rs:225`)** — already checks loopback/private/link-local/ULA for both v4 and v6. **Generalize** into the one shared SSRF guard (D-01a); do not duplicate.
- **Webhook re-resolve+pin (Phase 11, `webhook.rs`)** — already resolves and pins at delivery; fold it onto the shared helper (D-01c) without regressing its behavior.
- **`mtls.rs:59-66`** — the leaf-cert `status==Active` + `not_before`/`not_after` check is the exact pattern to mirror for the **issuing-CA** check (D-02).
- **`messages.rs` HMAC-SHA256 sign/verify path (SEC-022/055)** — the existing single-key path is extended with an HKDF-derived per-tenant subkey (D-05a/b); keep the round-trip test and add per-tenant negative tests.
- **AES-256-GCM at-rest + `#[serde(skip_serializing)]` conventions** — reuse for federation secret hygiene (D-06); the same conventions used for webhook secrets (Phase 11) and MFA/CA keys.
- **Phase 24 GDPR audit dead-letter in `cleanup.rs` (D-02)** — additive base for SECHRD-06 erasure durability; keep it, build the proof-last ordering around it.
- **k8s `default-deny` + per-receiver ingress NetworkPolicies (Phase 11)** — the egress policies (D-07) slot into this existing default-deny posture.

### Established Patterns
- Trait-in-core / impl-in-db / thin-handler; per-crate `cargo check/test -p <crate>` (never full workspace); `cargo fmt` + `clippy -D warnings` before commit.
- **Fail-closed is the default** for every control in this phase (SSRF, mTLS, erasure durability, AMQP signing, egress) — no warn-and-process, no zero-key fallback, no unconditional allow.
- Append-only audit; DB errors mapped to typed variants (Phase 23 added `AxiamError::ServiceUnavailable`→503 for a missing key — a similar operator-actionable variant fits AMQP-signing-key-unset and mTLS CA-not-Active refusals).
- Every fix ships a regression test that fails-before/passes-after; **security fixes additionally ship a negative/replay/concurrency test** proving the attack/leak is rejected (the phase's defining signal).
- **swagger-ui GitHub-egress workaround** (per CLAUDE.md) required for any build/test touching `axiam-api-rest`: `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`.

### Integration Points
- **SECHRD-06 ↔ Phase 24 D-02** — both touch `cleanup.rs`; the erasure-proof-last ordering must preserve the audit dead-letter behavior added in Phase 24.
- **SECHRD-06 ↔ CMPL-02 (Phase → compliance)** — GDPR erasure durability feeds the later compliance certification; the export-session redaction (D-03c) and dedup (D-03d) are the durable base CMPL-02 builds on.
- **SECHRD-02 shared guard** spans `axiam-federation` (OIDC/SAML/JWKS) + `axiam-api-rest` (webhook) — decide the helper's home crate (likely `axiam-federation` or a small shared util) so both consumers can depend on it without a cycle.
- **SECHRD-08 per-tenant keying** touches both the AMQP producer and consumer sign/verify paths — the `key_version` byte + tenant-scoped `info` must be symmetric on both ends.

</code_context>

<specifics>
## Specific Ideas

- Every one of the 7 fixes ships a **negative / replay / concurrency test** demonstrating the attack/leak is now rejected — the phase's defining success signal, not optional. Concretely: internal/loopback `token_endpoint` from a discovery doc → rejected, and a `302 → internal` redirect → rejected (SECHRD-02); revoked/expired issuing CA → device auth fails (SECHRD-05); failed `pseudonymize_actor` → user re-selected + no proof, and duplicate export request → rejected (SECHRD-06); request-supplied nonce → replay rejected (SECHRD-07); tenant-A signature on a tenant-B message → rejected, and ExportReady mail → deliverable end-to-end (SECHRD-08); federation secret → never serialized/printed (SECHRD-09); SMTP egress + completed secret set → works under default-deny (SECHRD-10).
- No new `unwrap()`/`expect()`/constant-key fallbacks on security paths. Secrets (AMQP master/derived keys, federation secrets, pepper) never serialized, logged in cleartext, or defaulted — the one deliberate exception elsewhere (Phase 24 setup-token single log line) does not recur here.
- Reuse existing SurrealDB + AES-256-GCM/serde-skip conventions — no new infra (no Redis, no per-tenant broker vhosts) and no new crates beyond `hkdf` (already-available `hmac`/`sha2` family) for the per-tenant key derivation.

</specifics>

<deferred>
## Deferred Ideas

- **Full CA-chain-walk mTLS validation** (issuer + intermediates + root status/validity) — deferred; AXIAM's PKI is a flat org/tenant-CA→device-cert hierarchy today. Revisit if intermediate CAs are introduced.
- **CRL / OCSP revocation checking** for mTLS — beyond the AC (status flag + validity window); post-v1.0-beta.
- **PGP-encrypted GDPR export** — the export-session redaction (D-03c) is in scope; optional PGP encryption of the export bundle ties to CMPL-02 (compliance phase), not here.
- **Per-tenant broker queues + RabbitMQ ACLs** — considered for SECHRD-08 and rejected in favor of HKDF-derived per-tenant keys (D-05a); revisit only if app-layer signing proves insufficient.
- **Single wrapped DB transaction for GDPR purge** — considered for SECHRD-06 and rejected in favor of proof-last idempotent-retry (D-03a) given cross-store side-effects; revisit only if ordering proves insufficient.
- **DNS-resolution caching for outbound fetches** — considered for SECHRD-02 and rejected (fresh-per-request chosen, D-01c) to avoid a rebind window; revisit only under a demonstrated perf need.
- **Master-key rotation tooling** — the `key_version` byte (D-05b) makes AMQP signing rotation-ready, but the operator rotation procedure/runbook is a docs/ops item (compliance/docs phase), not code here.
- All Phase 26–29 + compliance/docs items (CORR/PERF/FUNC/QUAL/CMPL/DOCS) — correct homes for adjacent work; none expand Phase 25 scope.

### Reviewed Todos (not folded)
None — `todo.match-phase 25` returned zero matches.

</deferred>

---

*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Context gathered: 2026-07-04*
