# Phase 30: Compliance & Documentation - Research

**Researched:** 2026-07-06
**Domain:** Compliance certification (ASVS/ISO27001/CyberSecurity Act) + GDPR verification + API/deployment/admin documentation consolidation
**Confidence:** MEDIUM (existing-code evidence is HIGH; ISO27001/CRA mapping altitude and CI tooling choice are the genuinely net-new, lower-confidence areas)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**CMPL-01 — Security audit checklist**
- **D-01 — Master audit that cites existing artifacts.** `claude_dev/security-audit.md` is the single top-level certification document. It maps controls to ASVS L2 + ISO 27001 + CyberSecurity Act with evidence pointers that **link into** the existing `docs/compliance/` files (and code/tests) rather than duplicating them. The `docs/compliance/` set remains the detailed backing evidence.
- **D-02 — ISO 27001 / CyberSecurity Act depth = control-family + evidence pointer.** Map ISO 27001 Annex A control **families** (e.g. A.5, A.8, A.9) and CyberSecurity Act essential-requirement **themes** to pass/fail with a pointer to code/tests/ASVS rows. Right altitude for an IAM MVP beta — auditable without a full ISMS certification effort. (ASVS L2 is already control-by-control from Phase 7 and is cited, not redone.)
- **D-03 — Cite phase evidence, spot-verify.** Trust the negative tests and verifications from Phases 23–29 as the evidence trail (each Success Criterion was proven in-code), spot-checking a representative sample. Do **not** re-run a full fresh re-audit. Open/deferred items are cross-referenced to v1.2 REQ-IDs.

**CMPL-02 — GDPR completeness**
- **D-04 — Job = verify + close any real gap + document.** Audit that the export blob covers every table (verify consents + sessions + all user-owned entities are present), confirm erasure durably pseudonymizes audit PII (SECHRD-06), confirm consent is recorded **and** exportable; fix only genuine gaps found; then write the GDPR compliance documentation. Minimal net-new code.
- **D-05 — Keep the shipped async export; document it as satisfying the SC.** The roadmap SC names `GET /api/v1/users/:id/export`, but the shipped design is an async job: `POST /api/v1/account/export` (enqueue) → `GET /api/v1/account/export/{token}` (single-use encrypted download). This async design was a deliberate SECHRD-06 choice. Treat it as the **canonical** export API and document that it fulfills CMPL-02's intent (covers every table incl. sessions, optional PGP). The SC's `GET /users/:id/export` is descriptive shorthand, not a literal contract — **no new endpoint**. Note the reconciliation explicitly in the GDPR doc for honest closure.
- **D-06 — Consent scope = record + export (present); UI/withdrawal deferred.** CMPL-02's "consent recorded and exportable" is satisfied by the existing consent repo/model + inclusion in the export blob (`cleanup.rs` `consents_json`). Consent-capture UI and withdrawal flows are new capabilities → deferred, not built in this phase.

**DOCS-01 — Documentation**
- **D-07 — Generate REST/gRPC, hand-author AMQP.**
  - REST: publish the utoipa-generated OpenAPI spec — regenerate/commit the OpenAPI JSON under `docs/api/` from the `axiam-api-rest` `ApiDoc` aggregator; document how to view it.
  - gRPC: reference `proto/axiam/v1/*.proto` with a short usage guide.
  - AMQP: hand-author a **net-new AsyncAPI 2.x** spec for the queues/messages (derive from `crates/axiam-amqp/src/messages.rs` + the publishers/consumers) since none exists.
- **D-08 — Deployment/admin/PKI guides are operator+integrator, task-oriented.** Deployment guide for operators (Docker/K8s, required env/secrets, NetworkPolicies — drawn from `k8s/` manifests, `docker/`, and the SECHRD-10 secret set); admin + PKI guides task-oriented (bootstrap, cert issuance/mTLS). Practical getting-it-running depth, not exhaustive reference or bare quickstart.
- **D-09 — Sectioned `docs/` + link out (single source of truth).** Organize `docs/` into `api/`, `deployment/`, `admin/`, `pki/`, `compliance/` (keep the existing `docs/compliance/` in place), with a `docs/README.md` landing/index. **Link out** to the 7 `sdks/*/README.md` and to `claude_dev/security-audit.md` rather than copying — no duplication/drift.

**Cross-cutting docs decisions**
- **D-10 — OpenAPI publishing = spec file + static reference (no new live Swagger UI).** Commit the OpenAPI JSON under `docs/api/` and document viewing it with any Swagger/Redoc viewer. Do **not** newly wire in-app Swagger UI in this phase — avoids the known `utoipa-swagger-ui` GitHub-egress build fragility (see `SWAGGER_UI_DOWNLOAD_URL` workaround in CLAUDE.md). If a `/swagger` route already exists, just document it.
- **D-11 — Light docs CI: spec-validate + link-check.** Add a small CI step that validates the OpenAPI + AsyncAPI specs parse and checks internal doc links resolve. Cheap drift/broken-link guard, scoped to docs, no heavy tooling.
- **D-12 — Version-stamp docs to v1.2/beta + "last verified" date.** Each doc (and `security-audit.md`) carries the milestone (v1.2 beta) and a last-verified date, with a short note that it describes the beta state. Honest, point-in-time evidence.

### Claude's Discretion
- Exact ISO 27001 Annex A family granularity and CyberSecurity Act theme grouping within the D-02 "control-family + evidence pointer" altitude.
- Precise section layout inside each guide, and the specific link-check / spec-validate tooling used in CI (D-11), provided it stays lightweight.

### Deferred Ideas (OUT OF SCOPE)
- Consent-capture UI + consent-withdrawal flows — new user-facing capabilities beyond CMPL-02's "recorded and exportable"; belongs in a future consent-management phase.
- Live in-app Swagger/Redoc UI route — deferred to avoid the `utoipa-swagger-ui` GitHub-egress build fragility; revisit post-beta if the egress workaround is no longer needed.
- Full ISO 27001 control-by-control (93-control) audit + formal ISMS certification — beyond MVP-beta altitude; the family-level mapping is sufficient for this milestone.
- Literal synchronous `GET /api/v1/users/:id/export` endpoint — only if a future consumer specifically requires it; the async flow satisfies CMPL-02.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CMPL-01 | Security audit checklist mapped to ASVS L2 / ISO 27001 / CyberSecurity Act, pass/fail + evidence, open items cross-referenced to v1.2 REQ-IDs, in `claude_dev/security-audit.md` | `## security-audit.md Master-Doc Structure`, `## ISO 27001 Annex A + CyberSecurity Act Mapping`, existing `docs/compliance/*` evidence files enumerated below |
| CMPL-02 | Export covers every table incl. sessions (optional PGP); erasure durably pseudonymizes audit PII (SECHRD-06); consent recorded and exportable | `## CMPL-02 Verification Map`, exact code + test evidence pointers in `cleanup.rs`, `gdpr.rs`, `gdpr_test.rs` |
| DOCS-01 | Consolidated REST/gRPC/AMQP API docs, deployment guide, admin+PKI guides, SDK links, under `docs/` | `## AsyncAPI 2.x Spec Skeleton`, `## OpenAPI Publishing Mechanism`, `## Recommended docs/ Structure`, `## Light Docs CI` |
</phase_requirements>

## Summary

Phase 30 is a **verify-and-document** phase, not a build phase — this is the single most important framing for planning. Prior scouting (confirmed by this research) establishes that the vast majority of the underlying machinery already exists and is already tested: the ASVS L2 checklist (`docs/compliance/asvs-l2-checklist.md`, 103 controls, zero open High/Critical items) shipped in Phase 7; the GDPR export sweep in `crates/axiam-server/src/cleanup.rs::aggregate_export_data` (L624-799) already assembles profile, consents, sessions (metadata-only), MFA flag, federation identities, role assignments, group memberships, paginated audit entries, and WebAuthn credentials into one JSON blob that `cleanup.rs::sweep_pending_exports` (~L645-791 region) then AES-256-GCM-encrypts (with optional PGP layer, evidenced by `EncryptedExport`/`EncryptRequest` in `axiam_core::models::pgp_key`); erasure durability (pseudonymization to `DELETED_USER_<hash>`, `erasure_proof` write) is proven by `gdpr_test.rs::deletion_pseudonymization`; and consent record+export is proven by `gdpr_test.rs::consent_on_registration` + the `consents_json` block. The REST OpenAPI spec is already generated via utoipa and already has a `--dump-openapi` CLI mechanism (`axiam-server/src/main.rs` L130-144) with a working CI drift gate (`sdk-openapi-drift.yml`) that produces `sdks/openapi.json`. The 7 SDK READMEs and 3 `.proto` files already exist.

The genuinely net-new work for this phase is narrow: (1) hand-author an AsyncAPI 2.6 document describing the 5 real AMQP message types and their queues (no such doc exists yet); (2) build the `claude_dev/security-audit.md` master citation document with an ISO 27001 Annex-A-family + CyberSecurity-Act-theme mapping table (no such mapping exists yet — this research proposes a concrete family/theme table below); (3) write the deployment/admin/PKI guides and a `docs/README.md` index that link out to everything else; (4) publish a second, docs-facing copy of the OpenAPI JSON under `docs/api/`; (5) add a small, egress-conscious CI job that parses the OpenAPI + AsyncAPI specs and checks internal doc links. Everything else is citation and light gap-verification, consistent with D-01/D-03/D-04's "cite, don't re-prove" philosophy.

**Primary recommendation:** Treat this phase as three parallel-safe documentation tracks (compliance master-doc, GDPR verification+doc, API/deployment/admin/PKI docs) that each mostly read and cite existing code/tests/docs, plus one small net-new artifact per track (security-audit.md, AsyncAPI spec, docs/README.md index) and one shared cross-cutting task (light docs CI). No new production Rust code paths are required unless a genuine CMPL-02 gap surfaces during spot-verification (none was found in this research — see `CMPL-02 Verification Map`).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Security audit checklist (`security-audit.md`) | Docs/Static | — | Pure documentation artifact; cites code but adds no runtime behavior |
| ISO 27001 / CyberSecurity Act mapping | Docs/Static | — | Documentation-only cross-reference table |
| GDPR export completeness verification | API/Backend (read-only audit) | Database/Storage | Verifying existing `axiam-server`/`axiam-db` code paths; any genuine gap fix belongs in API/Backend or Database tier depending on where the gap is found |
| GDPR erasure durability verification | API/Backend | Database/Storage | Confirms `cleanup.rs` pseudonymization + `erasure_proof` durable write (already landed in Phase 25/SECHRD-06) |
| Consent record/export verification | API/Backend | Database/Storage | Confirms `consent.rs` repo + inclusion in export blob |
| REST OpenAPI doc publishing | Docs/Static | API/Backend (source) | `utoipa` annotations live in API/Backend; the *publishing* step (commit JSON under `docs/api/`) is a static-docs action, not new backend code |
| gRPC doc (proto reference) | Docs/Static | API/Backend (source) | `.proto` files already exist in `proto/`; only a usage guide is net-new |
| AMQP AsyncAPI spec (net-new) | Docs/Static | API/Backend (source) | Hand-authored spec describing `axiam-amqp` message/queue contracts; the contracts themselves are backend code, unchanged by this phase |
| Deployment guide (Docker/K8s) | Docs/Static | CDN/Static (K8s manifests) | Documents existing `k8s/` + `docker/` infra-as-code; no new infra |
| Admin + PKI guides | Docs/Static | API/Backend (source) | Documents existing `certificates`/`ca_certificates` handlers and admin bootstrap flow |
| Docs CI (spec-validate + link-check) | CI/Build tooling | — | New, small GitHub Actions job; not part of the runtime application tiers |

## security-audit.md Master-Doc Structure

Per D-01, `claude_dev/security-audit.md` is a **citation index**, not a duplicate control-by-control audit. Recommended section layout:

```markdown
# AXIAM Security Audit — v1.2 Beta

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Last verified:** <date this phase is executed>
**Scope:** Authentication, session management, access control, cryptography, PKI

## 1. How to Read This Document
Brief note: this is a master citation index over the detailed evidence already
gathered in `docs/compliance/` and per-phase VERIFICATION.md artifacts (D-01, D-03).
It does not re-run tests; it cites where they live.

## 2. OWASP ASVS Level 2 — Status Summary
Cites `docs/compliance/asvs-l2-checklist.md` (control-by-control, Phase 7) +
`docs/compliance/FINDINGS.md` (deferred items). Table: category | pass count |
deferred count | link to section anchor. Cross-reference any items touched by
Phases 23-29 (e.g. SECFIX-04 SAML XSW binding -> which ASVS V2/V3 row it updates).

## 3. ISO 27001 Annex A — Control-Family Mapping
One row per applicable Annex A 2022 family (see table below). Pass/Fail/Partial +
evidence pointer (code path, test file, or ASVS row it corresponds to).

## 4. CyberSecurity Act — Essential-Requirement Theme Mapping
One row per essential-requirement theme (see table below). Same pass/fail +
evidence-pointer format.

## 5. OAuth2 / OIDC Conformance
Cites `docs/compliance/oauth2-rfc-compliance.md` and
`docs/compliance/oidc-conformance.md` — one-paragraph summary + link, not copied.

## 6. Federation / Test-Coverage Cross-Reference
Cites `docs/compliance/sc4-coverage.md`.

## 7. Open Items / Deferred Findings
Cross-references `docs/compliance/FINDINGS.md` rows AND any newly-deferred
items discovered in Phases 23-29, each tagged with its v1.2 REQ-ID (e.g.
"F-05 CSP header — Medium — deferred post-beta").

## 8. Version & Provenance
v1.2 / beta stamp + last-verified date (D-12).
```

**Evidence pointers to cite (confirmed to exist, exact paths):**
- `docs/compliance/asvs-l2-checklist.md` — 103 ASVS L2 controls (94 Pass / 4 N/A / 5 Deferred), zero High/Critical deferred [VERIFIED: codebase read]
- `docs/compliance/FINDINGS.md` — 5 findings (F-01..F-05), all Low/Medium/Info, none blocking beta [VERIFIED: codebase read]
- `docs/compliance/oauth2-rfc-compliance.md` — RFC 6749/7636/7009/7662 MUST-matrix [VERIFIED: codebase read]
- `docs/compliance/oidc-conformance.md` — OIDC Core 1.0 + Discovery 1.0 matrix [VERIFIED: codebase read]
- `docs/compliance/sc4-coverage.md` — axiam-authz/axiam-federation test-coverage citation table [VERIFIED: codebase read]
- Per-phase `.planning/phases/2{3..9}-*/*-VERIFICATION.md` — each Phase 23-29 success criterion's proof [VERIFIED: codebase — confirmed present for Phase 25 as `25-VERIFICATION.md`]

## ISO 27001 Annex A + CyberSecurity Act Mapping

**Confidence: LOW/MEDIUM** — no single official ASVS↔ISO27001 crosswalk document exists (multiple vendor whitepapers give partial, inconsistent mappings) [CITED: pivotpointsecurity.com/owasp-asvs-vs-iso-27001-alignment, securitycompass.com mapping whitepaper]. The family/theme table below is **this research's proposed mapping** built from (a) general ISO 27001:2022 Annex A structure knowledge and (b) AXIAM's actual control surface — the planner and a human reviewer should sanity-check the family/theme groupings before they're locked into `security-audit.md`, since this is exactly the kind of "compliance framework interpretation" the provenance rules flag for confirmation.

ISO 27001:2022 restructured Annex A into 4 themes and 93 controls (down from 14 clauses/93 controls in the 2013 edition), numbered A.5 (Organizational, 37 controls), A.6 (People, 8), A.7 (Physical, 14), A.8 (Technological, 34) [CITED: general ISO 27001:2022 knowledge, cross-checked against multiple 2026 vendor summaries].

### Recommended ISO 27001 Annex A family table for `security-audit.md`

| Annex A Family | Theme | Applies to AXIAM | AXIAM Evidence Pointer |
|----------------|-------|-------------------|------------------------|
| A.5 (selected: access control policy, supplier/asset mgmt) | Organizational | Yes | RBAC policy design (`axiam-authz`), tenant/org data-isolation model (design-document.md) |
| A.5.15-5.18 (access control, identity mgmt, authn info, access rights) | Organizational | Yes | ASVS V2/V4 rows; `axiam-authz` engine; RBAC enforcement tests (Phase 3, cited in `sc4-coverage.md`) |
| A.6 (screening, responsibilities, training) | People | Partial/N/A | Organizational control outside codebase scope — mark N/A with note (not a code-verifiable control) |
| A.7 (physical/environmental) | Physical | N/A | Cloud/K8s-deployed; physical security is infra-provider responsibility — mark N/A with note |
| A.8.2-8.3 (privileged access rights, info access restriction) | Technological | Yes | RBAC default-deny + admin bootstrap (Phase 3); `docs/compliance/asvs-l2-checklist.md` V4 rows |
| A.8.5 (secure authentication) | Technological | Yes | ASVS V2 rows (Argon2id, MFA/TOTP, WebAuthn) — cite checklist directly |
| A.8.9-8.11 (config mgmt, info deletion, data masking) | Technological | Yes | GDPR erasure/pseudonymization (SECHRD-06); K8s ConfigMap/Secret hygiene |
| A.8.12 (data leakage prevention) | Technological | Yes | Encrypted-at-rest secrets (federation/email/MFA/PKI keys); `Sensitive<T>` token redaction (SDK-side, cite if in-scope) |
| A.8.15-8.16 (logging, monitoring) | Technological | Yes | Audit log service (`axiam-audit`), append-only audit table, ASVS V7 rows |
| A.8.20-8.23 (network security, segregation, web filtering, secure coding) | Technological | Yes | K8s NetworkPolicies (`k8s/network-policy/`), TLS 1.3, security headers (Phase 2) |
| A.8.24 (cryptography) | Technological | Yes | ASVS V6/V8 rows: Argon2id, AES-256-GCM, Ed25519/EdDSA JWT, X.509 PKI |
| A.8.25-8.29 (secure dev lifecycle, security testing) | Technological | Yes | CI security-scan job (cargo-audit/cargo-deny/trivy/hadolint), `ci.yml` |
| A.8.32-8.34 (change mgmt, capacity, audit testing) | Technological | Partial | CI/CD pipeline (`ci.yml`, `release.yml`) covers change control; capacity mgmt is N/A for MVP beta |

### CyberSecurity Act essential-requirement themes

The EU Cyber Resilience Act (CRA) — the current successor framework the project likely means by "CyberSecurity Act" — sets essential requirements in Annex I, Part I (product properties) and Part II (manufacturer vulnerability-handling process) [CITED: digital-strategy.ec.europa.eu/en/policies/cra-summary, streamlex.eu/annexes/cra-en-annex-i]. Recommended themes for the mapping table:

| CSA/CRA Theme | Applies to AXIAM | AXIAM Evidence Pointer |
|---------------|-------------------|------------------------|
| Secure-by-design & default configuration | Yes | Default-deny RBAC, fail-closed encryption keys (SECHRD series), cookie-based auth defaults |
| No known exploitable vulnerabilities | Yes | `cargo-audit`/`cargo-deny`/`trivy`/`npm audit` CI gates (`ci.yml` security-scan job) |
| Confidentiality of stored/transmitted data | Yes | AES-256-GCM at rest, TLS 1.3 in transit, GDPR export encryption |
| Data minimization | Yes | GDPR export excludes `password_hash`/`mfa_secret`/token hashes (D-10 in `cleanup.rs`) |
| Access control / authentication | Yes | Same evidence as ASVS V2/V4 + A.5.15-5.18 |
| Vulnerability handling process | Yes | GitHub issue tracking of deferred findings (`FINDINGS.md` tracking-issue links); dependency scanning cadence |
| Security updates | Partial | Dependabot config (`dependabot.yml` if present) — cite if exists, else mark deferred/N/A for beta |
| SBOM | N/A/Deferred | Not currently generated — note as a deferred item cross-referenced to a future REQ-ID if the planner wants an explicit open item |

**Recommendation to the planner:** present both tables largely as-is above (they are the concrete skeleton D-02's "Claude's Discretion" asks for), but flag the SBOM row and the ISO A.6/A.7 N/A rows explicitly as `[ASSUMED]` interpretations that a human reviewer should confirm before the audit doc is considered final — this keeps D-03's "spot-verify" honest.

## CMPL-02 Verification Map

This is the precise evidence trail the plan should assert against — all confirmed present by this research, no rebuilding needed:

| Assertion | Evidence | Confidence |
|-----------|----------|------------|
| Export blob covers every user-owned table | `crates/axiam-server/src/cleanup.rs::aggregate_export_data` (L624-799) assembles: `profile` (no password_hash/mfa_secret), `consents_json`, `sessions_json` (metadata-only, no token_hash), `mfa.enabled` flag, `federation_identities`, `assignments_json` (role grants incl. inherited), `group_memberships`, paginated `audit_json` (1000-row pages, loops to completion), `webauthn_json` (metadata-only, no passkey_json secret) | [VERIFIED: codebase read] |
| Export includes real sessions (not empty array) | `gdpr_test.rs::export_includes_real_session_metadata` (L322-428) explicitly asserts the sessions array is non-empty and asserts against a seeded session — this is the regression test that would fail if `sessions_json` reverted to a hardcoded `[]` | [VERIFIED: codebase read] |
| Export is encrypted with optional PGP | `axiam_core::models::pgp_key::EncryptedExport`/`EncryptRequest` schemas exist and are wired into the OpenAPI doc (`openapi.rs` L302-303); `sweep_pending_exports` builds the `OutboundMailMessage::ExportReady` notification after encrypting (L600-619 region) | [VERIFIED: codebase read] — confirm AES-256-GCM + optional-PGP wiring specifically inside `sweep_pending_exports` when writing the doc (read the ~L560-620 block once more during planning to quote the exact encrypt call) |
| Erasure durably pseudonymizes audit PII | `gdpr_test.rs::deletion_pseudonymization` (L612-792) — asserts: pseudonym format `DELETED_USER_<hash>` via `gdpr_pseudonym(pepper, tenant_id, user_id)`; `anonymize_user` scrubs profile; `pseudonymize_actor` rewrites audit rows so `actor_id` becomes nil UUID, `actor_pseudonym` metadata is set, original UUID absent from the row, `ip_address` nulled; `erasure_proof` row is written and asserted | [VERIFIED: codebase read] |
| Erasure durability DB invariants (SECHRD-06) | Phase 25 plan `25-04-PLAN.md` built: `SessionRepository::list_by_user` (feeds the export sessions fix above), widened export-job dedup filter (`queued`/`ready`/`failed`), and a DB `UNIQUE` index on `erasure_proof.user_id` (idempotent retry safety) | [VERIFIED: codebase read — `.planning/phases/25-.../25-04-PLAN.md`] |
| Consent recorded and exportable | `gdpr_test.rs::consent_on_registration` (L797-839) — asserts exactly one `terms_of_service` consent row created at registration with `version`, `ip_address`; the same `consent_repo.list_by_user` result is what `aggregate_export_data` serializes into `consents_json` | [VERIFIED: codebase read] |
| Async export API is canonical (D-05) | `crates/axiam-api-rest/src/handlers/gdpr.rs`: `request_account_export` (L273) → enqueue; `download_account_export` (L344) → single-use token download; `request_account_delete` (L442) → Art. 17 erasure request w/ 30-day grace; `cancel_account_delete` (L561) — no literal `GET /users/:id/export` route exists, confirming D-05's reconciliation is accurate | [VERIFIED: codebase read] |

**No genuine CMPL-02 gap was found during this research.** The plan's CMPL-02 track should therefore be scoped as: (1) write the GDPR compliance doc citing the above table, explicitly noting the D-05 async-vs-roadmap-shorthand reconciliation and the D-06 consent-scope boundary; (2) a spot-verification task that re-runs `gdpr_test.rs` (already exists, `cargo test -p axiam-api-rest --test gdpr_test`) as the executable proof cited in the doc; (3) only add new code if the plan-time spot-check surfaces something this research missed (e.g., a newly-added user-owned table since Phase 25 that isn't in `aggregate_export_data` — worth a quick `grep` across `axiam-db/src/repository/` for tables added after Phase 25 as a planning-time sanity check).

## AsyncAPI 2.x Spec Skeleton

**Confidence: MEDIUM** [CITED: asyncapi.com/docs/concepts/asyncapi-document/structure, github.com/asyncapi/spec/blob/v2.6.0/spec/asyncapi.md, github.com/asyncapi/bindings/blob/master/amqp/README.md]

AsyncAPI 2.6 documents are JSON/YAML with these top-level keys: `asyncapi` (version string), `info`, `servers`, `channels`, `components`. Channels map 1:1 to addressable AMQP entities (queue name or routing key); `bindings.amqp` at the channel level distinguishes `is: queue` vs `is: routingKey` and carries exchange/queue properties (name, type, durable, autoDelete, vhost); message-level `bindings.amqp` carries `contentEncoding`/`messageType`. `channels[x].subscribe`/`channels[x].publish` nest the `message` object (referencing `components.messages`).

### Real AMQP surface to describe (confirmed from `crates/axiam-amqp/src/connection.rs` + `messages.rs`)

| Queue (from `connection.rs::queues` module) | Message Type | Direction | DLQ |
|---|---|---|---|
| `axiam.authz.request` | `AuthzRequest` (HMAC-signed, HKDF per-tenant subkey) | consume (server processes) | `axiam.authz.request.dlq` |
| `axiam.authz.response` | `AuthzResponse` | publish | — (response queue, no DLQ needed) |
| `axiam.audit.events` | `AuditEventMessage` (HMAC-signed) | consume | `axiam.audit.events.dlq` |
| `axiam.notifications` | `NotificationEvent` | publish | — |
| `axiam.mail.outbound` | `OutboundMailMessage` (re-exported from `axiam_core::models::mail`, `MailType` enum: `PasswordReset`/`EmailVerification`/`Notification`/`DeletionCancel`/`ExportReady`) | consume | `axiam.mail.outbound.dlq` |
| `axiam.webhook` | `WebhookMessage` | consume | `axiam.webhook.dlq` (via `axiam.webhook.retry` TTL-based retry, no direct consumer on retry queue) |
| `axiam.webhook.retry` | `WebhookMessage` (attempt incremented) | internal (no consumer; TTL expiry re-routes to `axiam.webhook`) | — |

Note the HMAC-SHA256 signing convention (`hmac_signature` + `key_version` fields on `AuthzRequest`/`AuditEventMessage`) and the fail-closed webhook DLQ chain (`WEBHOOK` → nack-no-requeue on max-attempts → `WEBHOOK_DLQ`; `WEBHOOK_RETRY` uses TTL, not a live consumer) are worth calling out as `x-*` extension notes or free-text descriptions in the AsyncAPI doc — AsyncAPI 2.6 has no first-class "HMAC-signed" concept, so this belongs in the message `description` field, not a structured binding.

### Recommended skeleton for `docs/api/asyncapi.yml`

```yaml
asyncapi: 2.6.0
info:
  title: AXIAM AMQP API
  version: "0.1.0"       # match D-12 version-stamp convention
  description: |
    AMQP message contracts for AXIAM's async authorization, audit ingestion,
    mail delivery, webhook delivery, and notification queues. Hand-authored —
    derived from crates/axiam-amqp/src/messages.rs and connection.rs (v1.2 beta).
servers:
  rabbitmq:
    url: <rabbitmq-host>:5672
    protocol: amqp
channels:
  axiam.authz.request:
    bindings:
      amqp:
        is: queue
        queue: { name: axiam.authz.request, durable: true, autoDelete: false }
    subscribe:
      message:
        $ref: '#/components/messages/AuthzRequest'
  axiam.authz.response:
    bindings:
      amqp: { is: queue, queue: { name: axiam.authz.response, durable: true } }
    publish:
      message: { $ref: '#/components/messages/AuthzResponse' }
  # ... one channel per queue in the table above ...
components:
  messages:
    AuthzRequest:
      payload:
        type: object
        properties:
          correlation_id: { type: string, format: uuid }
          tenant_id: { type: string, format: uuid }
          subject_id: { type: string, format: uuid }
          action: { type: string }
          resource_id: { type: string, format: uuid }
          scope: { type: string, nullable: true }
          key_version: { type: integer }
          hmac_signature:
            type: string
            description: "HMAC-SHA256 hex over the payload with hmac_signature=null, signed with a per-tenant HKDF-derived subkey. Consumers reject (nack, no requeue) when absent or invalid — no fail-open path."
    # ... one message schema per type in messages.rs ...
```

This mirrors `messages.rs` field-for-field (the plan's task should literally transcribe each `#[derive(Serialize, Deserialize)]` struct's fields into a JSON-Schema-shaped `payload`). Since AXIAM already has Rust structs with serde derives, a future enhancement (not this phase, per D-07's "hand-author" decision) could be schema generation from `schemars`, but D-07 explicitly calls for hand-authoring here.

### Validation tooling

`@asyncapi/cli validate <file>` performs local JSON-Schema-based validation entirely from the file on disk; it only reaches the network if the document itself contains external `$ref` URLs (which this self-contained spec won't) [CITED: asyncapi.com/docs/guides/validate, asyncapi.com/docs/tools/cli]. Package legitimacy check flagged `@asyncapi/cli` `[SUS]` (registry lookup couldn't retrieve download counts in this sandbox — see Package Legitimacy Audit below); the package is nonetheless the official tool from the AsyncAPI Initiative (repo: `github.com/asyncapi/cli`, matches the org that publishes the spec itself) [CITED: github.com/asyncapi/cli]. Flag it for a `checkpoint:human-verify` before first CI use per the SUS-verdict protocol, not because there's genuine reason to distrust it.

## OpenAPI Publishing Mechanism

**Confidence: HIGH** [VERIFIED: codebase read]

The mechanism D-07/D-10 ask for **already exists** — no new Rust code needed:

- `crates/axiam-server/src/main.rs` (L130-144): a `--dump-openapi` flag prints `serde_json::to_string_pretty(&axiam_api_rest::openapi::api_doc())` to stdout and exits 0, before any tracing/DB/AMQP init — "usable in CI without any running infrastructure" per the existing code comment.
- `crates/axiam-api-rest/src/openapi.rs`: the utoipa `ApiDoc` aggregator (all REST paths/schemas/tags) + a `SamlApiDoc` merged in behind the `saml` feature via `api_doc()`.
- `.github/workflows/sdk-openapi-drift.yml`: already builds with `--no-default-features` (SAML off, deterministic), runs `--dump-openapi`, and diffs against the committed `sdks/openapi.json`, failing the PR on drift.

**For `docs/api/`, the plan has two clean options (present both to the planner, recommend the first):**

1. **Symlink `docs/api/openapi.json -> ../../sdks/openapi.json`.** Zero duplication, zero drift risk, the existing drift gate continues to be the single source of truth. Document in `docs/api/README.md` that the file is the same artifact the SDK drift gate maintains, with a one-line "regenerate with `cargo build -p axiam-server --no-default-features && ./target/debug/axiam-server --dump-openapi > sdks/openapi.json`" instruction. This is the option most consistent with D-09's "single source of truth, link out, no duplication/drift" philosophy already applied elsewhere in this same phase.
2. **A second committed copy under `docs/api/openapi.json`** with its own drift-check line added to the existing `sdk-openapi-drift.yml` (or the new docs-CI job) diffing it against `sdks/openapi.json`. Slightly more discoverable for someone browsing `docs/` who doesn't know to look in `sdks/`, at the cost of one more file the drift gate must track.

No new Swagger UI route (D-10). Document viewing the committed JSON with any external Swagger Editor / Redoc CLI (`npx @redocly/cli preview-docs docs/api/openapi.json` or similar) — this is a documentation instruction, not new app code, so it does not touch the `utoipa-swagger-ui` egress-fragile dependency at all.

## Recommended docs/ Structure

Per D-09:

```
docs/
├── README.md                  # index/landing — links to every section below + SDK READMEs + security-audit.md
├── api/
│   ├── README.md              # REST/gRPC/AMQP overview + how to view each spec
│   ├── openapi.json           # symlink to sdks/openapi.json (or committed copy, see above)
│   ├── asyncapi.yml            # net-new AMQP spec (D-07)
│   └── grpc.md                # short usage guide referencing proto/axiam/v1/*.proto
├── deployment/
│   └── README.md               # Docker/K8s guide: required env (AXIAM__* double-underscore keys),
│                                 secrets (docker/.secrets/, k8s/server/secret.yml keys), NetworkPolicies
├── admin/
│   └── README.md               # bootstrap (AXIAM_BOOTSTRAP_ADMIN_EMAIL), user/role/permission mgmt walkthrough
├── pki/
│   └── README.md               # CA cert issuance, leaf cert issuance, mTLS binding, cert revocation walkthrough
├── compliance/                 # EXISTING — unchanged, kept in place
│   ├── asvs-l2-checklist.md
│   ├── FINDINGS.md
│   ├── oauth2-rfc-compliance.md
│   ├── oidc-conformance.md
│   └── sc4-coverage.md
└── dev-environment.md          # EXISTING — unchanged
```

`docs/README.md` links to: `docs/api/`, `docs/deployment/`, `docs/admin/`, `docs/pki/`, `docs/compliance/`, the 7 `sdks/{rust,typescript,python,java,csharp,php,go}/README.md`, and `claude_dev/security-audit.md`.

### Deployment guide sources (confirmed present)

- `k8s/network-policy/` — 6 policy files: `default-deny.yml`, `allow-dns-egress.yml`, `allow-ingress-to-{frontend,rabbitmq,server,surrealdb}.yml`, `server-egress.yml` [VERIFIED: codebase read]
- `k8s/server/secret.yml` — canonical required env-var list, all `AXIAM__` double-underscore keys: `AXIAM__DB__USERNAME`/`PASSWORD`, `AXIAM__AUTH__JWT_PRIVATE_KEY_PEM`/`JWT_PUBLIC_KEY_PEM`, `AXIAM__AUTH__MFA_ENCRYPTION_KEY`, `AXIAM__PKI__ENCRYPTION_KEY`, `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` (SECHRD-09), `AXIAM__EMAIL_ENCRYPTION_KEY`, `AXIAM__GDPR_PSEUDONYM_PEPPER`, `AXIAM__AUTH__PEPPER` — this file is effectively the deployment guide's "required secrets" table, ready to transcribe [VERIFIED: codebase read]
- `docker/docker-compose.prod.yml` + `docker/.secrets/` convention (referenced in compose comments) — dev-vs-prod secret sourcing pattern [VERIFIED: codebase read]
- `k8s/kustomization.yml`, `k8s/namespace.yml`, `k8s/ingress.yml` — overall manifest structure to reference

### Admin + PKI guide sources (confirmed present)

- `crates/axiam-api-rest/src/handlers/certificates.rs` — `generate`/`list`/`get`/`revoke`/`bind` (leaf cert lifecycle + device binding) [VERIFIED: codebase read]
- `crates/axiam-api-rest/src/handlers/ca_certificates.rs` — `generate`/`list`/`get`/`revoke` (CA cert lifecycle) [VERIFIED: codebase read]
- Admin bootstrap: `AXIAM_BOOTSTRAP_ADMIN_EMAIL` env var pattern (Phase 3, cited in ROADMAP.md Phase 3 scope) [VERIFIED: codebase read via ROADMAP.md]

## Light Docs CI

**Confidence: MEDIUM** — tool choice is genuinely open (D-11 leaves this to discretion); recommend the lightest option consistent with the project's demonstrated egress-sensitivity (CLAUDE.md's swagger-ui workaround, the openapi-drift gate's explicit avoidance of SAML/libxmlsec1 in that job).

### Recommended job (new file, path-filtered, matching existing conventions)

`.github/workflows/docs-ci.yml`, triggered on `paths: ['docs/**', 'claude_dev/security-audit.md', 'crates/axiam-amqp/**', 'crates/axiam-api-rest/src/openapi.rs']`, following the SHA-pinned-action convention already used everywhere else in `.github/workflows/`:

1. **OpenAPI parse check** — reuse the existing pattern from `sdk-openapi-drift.yml` (build `--no-default-features`, run `--dump-openapi`, but here just confirm the output is valid JSON — e.g. `python3 -m json.tool < spec.json > /dev/null` or `jq empty spec.json` — no network needed once the binary is built).
2. **AsyncAPI parse check** — `npx @asyncapi/cli validate docs/api/asyncapi.yml`. Requires `npm`/network to fetch the CLI package (consistent with the existing `npm audit`/frontend jobs which already require registry access in this CI), but the `validate` step itself runs fully offline against the local file.
3. **Internal link check** — recommend a **zero-dependency custom script** over adding a new npm dependency: a short Node or Python script that greps all `docs/**/*.md` + `claude_dev/security-audit.md` for markdown link syntax `[text](path)`, filters to relative (non-`http`) targets, and asserts each resolves to an existing file (optionally checking `#anchor` fragments against heading slugs in the target file). This avoids adding `markdown-link-check` (flagged `[SUS]` below, and it also wants to check external URLs by default, which reintroduces network flakiness D-11 wants to avoid) or `remark-validate-links` (a real, offline-capable option, but pulls in the unified/remark ecosystem for a ~30-line check). A hand-rolled script is the most "lightweight, egress-free" reading of D-11 and needs no `package.json` at all — it can be a `just` recipe wrapping a `bash`/`awk` one-liner or a short Python 3 stdlib script (Python 3 already used in the codebase's `scripts/` directory pattern, confirmed by `scripts/e2e-bootstrap.sh` conventions — verify a Python vs. bash preference against `scripts/` at plan time).

### CI conventions to match (confirmed from existing workflows)

- Actions pinned by commit SHA with a version comment, e.g. `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2` [VERIFIED: codebase read, `ci.yml`/`sdk-openapi-drift.yml`/`sdk-buf-gates.yml` all follow this]
- `permissions: contents: read` at the workflow level [VERIFIED: codebase read]
- Path-filtered triggers on both `pull_request` and `push: branches: [main]` [VERIFIED: codebase read, `sdk-openapi-drift.yml`]
- `RUSTFLAGS: "-Dwarnings"` env convention for Rust-touching jobs (not applicable to a pure-docs job, but keep consistent job/step naming style: `name: <Job Purpose>`) [VERIFIED: codebase read]

## Package Legitimacy Audit

| Package | Registry | Age (latest publish) | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `@asyncapi/cli` | npm | 6.0.2, published 2026-06-07 | unknown (registry lookup returned null in this sandbox) | `github.com/asyncapi/cli` (official AsyncAPI Initiative org) | SUS (automated check: "too-new" + "unknown-downloads") | **Flagged — planner must add a `checkpoint:human-verify` task before first CI use.** This is the official AsyncAPI CLI (matches the spec-publishing org itself, `asyncapi.com`); the SUS verdict is a sandbox download-count-lookup artifact, not a genuine legitimacy concern, but the protocol requires the checkpoint regardless. Has a `postinstall` script (`node ./scripts/enableAutoComplete.js`) — shell-completion setup, not network/filesystem-external; low risk but note it for the human-verify step. |
| `markdown-link-check` | npm | 3.14.2, published 2025-11-19 | unknown (same sandbox lookup limitation) | `github.com/tcort/markdown-link-check` | SUS ("unknown-downloads" only) | **Not recommended for use** — this research recommends the zero-dependency custom link-check script instead (see Light Docs CI above), so this package is not part of the proposed plan. Listed here only because it surfaced during research; no action needed unless the planner chooses this path over the custom-script recommendation, in which case gate it behind `checkpoint:human-verify` too. |

**Packages removed due to `[SLOP]` verdict:** none.
**Packages flagged as suspicious `[SUS]`:** `@asyncapi/cli` (recommended, gate behind checkpoint), `markdown-link-check` (not recommended, custom script preferred).

*Both SUS verdicts stem from this sandbox's inability to fetch npm weekly-download telemetry, not from suspicious registry signals (no missing repo, no anomalous recency, no risky postinstall network calls). Still, per protocol, the planner must add a `checkpoint:human-verify` task before either package is first installed in CI.*

## Architecture Patterns

### System Architecture Diagram (documentation data flow for this phase)

```
Existing evidence sources                    Net-new artifacts (this phase)
──────────────────────────                   ──────────────────────────────
docs/compliance/asvs-l2-checklist.md   ──┐
docs/compliance/FINDINGS.md             ─┤
docs/compliance/oauth2-rfc-compliance.md ┼──cite──► claude_dev/security-audit.md
docs/compliance/oidc-conformance.md     ─┤          (ISO27001 family table +
docs/compliance/sc4-coverage.md         ─┤           CSA theme table + open items
Phase 23-29 VERIFICATION.md files       ─┘           cross-ref'd to v1.2 REQ-IDs)

cleanup.rs::aggregate_export_data       ──┐
gdpr.rs handlers (export/delete/cancel) ──┼──verify──► docs/compliance-gdpr.md (or
gdpr_test.rs (existing tests, re-run)   ──┘           section in docs/compliance/)
                                                       (documents D-05 async
                                                        reconciliation, D-06 scope)

crates/axiam-amqp/src/messages.rs       ──┐
crates/axiam-amqp/src/connection.rs     ──┼──transcribe──► docs/api/asyncapi.yml
(*_publisher.rs / *_consumer.rs)        ──┘                (hand-authored, net-new)

crates/axiam-api-rest/src/openapi.rs    ──┐
axiam-server --dump-openapi (existing)  ──┼──republish──► docs/api/openapi.json
sdks/openapi.json (existing, drift-gated)─┘                (symlink or 2nd copy)

proto/axiam/v1/*.proto (existing)       ────reference────► docs/api/grpc.md

k8s/*, docker/* (existing)              ────transcribe───► docs/deployment/README.md
handlers/{certificates,ca_certificates} ────transcribe───► docs/admin/README.md, docs/pki/README.md
sdks/{7 langs}/README.md (existing)     ────link-out─────► docs/README.md (index)

All docs/api specs                      ────validate─────► .github/workflows/docs-ci.yml
All docs/** internal links              ────check────────► (same CI job)
```

A reader tracing "how does a control get from code to the audit doc" follows: code/tests → phase VERIFICATION.md / docs/compliance/*.md → security-audit.md citation row → (if open) FINDINGS.md-style cross-reference to a v1.2 REQ-ID.

### Recommended Project Structure

See `## Recommended docs/ Structure` above — this phase's primary structural deliverable.

### Pattern 1: Citation-over-duplication documentation
**What:** Every new compliance/doc artifact in this phase links to or transcribes-once-from an existing source of truth, never forking a second copy that can drift.
**When to use:** Throughout this entire phase — it is the phase's central discipline (D-01, D-09, D-10 all instantiate this same pattern for different artifacts).
**Example:** `security-audit.md` row: `| A.8.24 Cryptography | Pass | See docs/compliance/asvs-l2-checklist.md#v6-v8-rows (Argon2id, AES-256-GCM, EdDSA) |` — not a re-transcription of those checklist rows.

### Anti-Patterns to Avoid
- **Re-auditing already-proven controls:** Do not write new tests or re-verify ASVS L2 rows already marked Pass in Phase 7 — D-03 explicitly forbids a full fresh re-audit.
- **Duplicating `docs/compliance/` content into `security-audit.md`:** D-01 requires citation, not copy-paste; a plan task that "writes out" ASVS rows into the new doc violates the locked decision.
- **Building a literal synchronous `GET /users/:id/export`:** explicitly deferred (D-05); do not add this endpoint even though the roadmap SC names it verbatim.
- **Wiring in-app Swagger UI:** explicitly deferred (D-10) to avoid the `utoipa-swagger-ui` GitHub-egress build fragility documented in CLAUDE.md.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| OpenAPI spec generation | A new spec-generation script | The existing `axiam-server --dump-openapi` + `api_doc()` aggregator | Already built, already CI-drift-gated (`sdk-openapi-drift.yml`); duplicating this logic would create two divergent generators |
| GDPR export completeness | A new export-verification test suite from scratch | `gdpr_test.rs::export_completeness` + `export_includes_real_session_metadata` (already assert every section) | These tests already prove the exact CMPL-02 claim; re-running them is the correct verification action, not writing new ones (unless a genuine gap is found) |
| AsyncAPI JSON-Schema validation | A hand-rolled AMQP-spec linter | `@asyncapi/cli validate` (official tool) | JSON-Schema validation against the AsyncAPI 2.6 meta-schema is exactly what the official CLI does; reimplementing schema validation is wasted, error-prone effort |
| Internal doc-link resolution checking | A full-blown documentation site generator with built-in link-checking (e.g. mkdocs, docusaurus) | A ~30-line custom script (or `remark-validate-links` if npm dependency is preferred) | The project has no static site generator in scope for this phase (D-09 is plain `docs/` markdown, not a generated site); pulling in a doc-site framework for link-checking alone is disproportionate |

**Key insight:** This phase's central risk is scope creep into re-building things that already work. Every "don't hand-roll" row above maps to an existing, tested mechanism this phase should cite/reuse, not replace.

## Common Pitfalls

### Pitfall 1: Treating the roadmap SC literally instead of per D-05's reconciliation
**What goes wrong:** A plan task literally tries to add `GET /api/v1/users/:id/export` because that's what `ROADMAP.md` Success Criterion #2 says verbatim.
**Why it happens:** Reading the roadmap SC in isolation without cross-referencing CONTEXT.md's D-05.
**How to avoid:** Always cite D-05 in the GDPR doc and in any plan task description touching this SC; the async `POST /account/export` → `GET /account/export/{token}` flow is canonical.
**Warning signs:** A task titled "add export endpoint" or "new GET route" appearing in the plan.

### Pitfall 2: Duplicating docs/compliance/ content into security-audit.md
**What goes wrong:** The new master doc becomes a second, slightly-different copy of the ASVS checklist, which will drift from the original on the next update.
**Why it happens:** It feels natural to "assemble everything in one place" for a certification doc.
**How to avoid:** Every row in `security-audit.md`'s ASVS/ISO/CSA sections should be a link + one-line summary, never a full transcription. D-01 is explicit about this.
**Warning signs:** `security-audit.md` growing past a few hundred lines with repeated control-text copy.

### Pitfall 3: AsyncAPI schema drifting from the actual Rust structs
**What goes wrong:** The hand-authored `asyncapi.yml` message schemas diverge from `messages.rs` structs over time (e.g. a new field added to `AuthzRequest` never makes it into the spec).
**Why it happens:** No codegen link between the two (D-07 explicitly chooses hand-authoring over codegen for AMQP, unlike REST).
**How to avoid:** The docs-CI internal-consistency check can't catch this (it only validates the spec's own JSON-Schema validity, not drift against Rust source) — recommend a source-code comment convention in `messages.rs` similar to the existing `sdks/openapi.json` drift-gate pattern is out of scope for this phase, but note in `docs/api/README.md` that the AsyncAPI spec is a snapshot, not auto-generated, and should be manually re-verified each time `messages.rs` changes.
**Warning signs:** A future PR modifying `messages.rs` without touching `docs/api/asyncapi.yml`.

### Pitfall 4: ISO 27001/CyberSecurity Act mapping presented as authoritative compliance certification
**What goes wrong:** The mapping tables in this research (or in the eventual `security-audit.md`) get treated as an audited, certifiable ISO 27001 compliance claim rather than an internal self-assessment at MVP-beta altitude.
**Why it happens:** The document's title ("security audit") sounds more authoritative than its actual scope (self-assessed, family-level, no external auditor).
**How to avoid:** `security-audit.md` should state explicitly, near the top, that this is an internal self-assessment at control-family granularity, not a certified ISO 27001 ISMS audit (D-02's own framing: "auditable without a full ISMS certification effort"). This protects against overclaiming compliance status.
**Warning signs:** Marketing or external-facing copy citing "ISO 27001 compliant" without the beta/self-assessment qualifier.

## Code Examples

### Existing OpenAPI dump mechanism (reuse, do not reimplement)
```rust
// Source: crates/axiam-server/src/main.rs L130-144 (existing code, confirmed present)
{
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--dump-openapi") {
        let json = serde_json::to_string_pretty(&axiam_api_rest::openapi::api_doc())
            .expect("OpenAPI serialization failed");
        println!("{json}");
        std::process::exit(0);
    }
}
```

### Existing GDPR export aggregation (cite as evidence, do not rebuild)
```rust
// Source: crates/axiam-server/src/cleanup.rs L783-799 (existing code, confirmed present)
let export = serde_json::json!({
    "export_metadata": { "generated_at": Utc::now(), "tenant_id": tenant_id, "subject_id": user_id, "schema_version": "1.0" },
    "profile": profile,
    "consents": consents_json,
    "sessions": sessions_json, // metadata only; NO token_hash (D-03c)
    "mfa": { "enabled": user.mfa_enabled }, // NO mfa_secret
    "federation_identities": fed_json,
    "assignments": assignments_json,
    "group_memberships": groups_json,
    "audit_entries": audit_json,
    "webauthn_credentials": webauthn_json,
});
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| ISO 27001:2013 Annex A (14 clauses, 93 controls) | ISO 27001:2022 Annex A (4 themes, 93 renumbered controls: A.5 Organizational/A.6 People/A.7 Physical/A.8 Technological) | 2022 revision | Any mapping table must use 2022 control numbers (A.5.x/A.8.x), not legacy A.9/A.10/A.12/A.14 clause numbers — this research's table uses 2022 numbering |
| AsyncAPI 2.x (channels + bindings) | AsyncAPI 3.x (operations decoupled from channels, `reply` support) | 3.0 released 2023, still evolving | D-07 targets 2.x explicitly (simpler, matches AXIAM's request/response-via-separate-queues AMQP pattern); no need to adopt 3.x for this phase |

**Deprecated/outdated:** None directly relevant — both ASVS 4.0.3 (used by Phase 7's checklist, kept as-is) and AsyncAPI 2.6 remain current, supported versions as of this research.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The specific ISO 27001 Annex A family ↔ AXIAM-control groupings in the mapping table (e.g. which sub-controls fall under A.8.5 vs A.8.24) | `## ISO 27001 Annex A + CyberSecurity Act Mapping` | Low-medium — this is an internal self-assessment mapping (not a certified audit), but a materially wrong family assignment could misrepresent coverage in `security-audit.md`; a human reviewer should sanity-check the table before it's treated as final |
| A2 | "CyberSecurity Act" in CLAUDE.md/REQUIREMENTS.md refers to the EU Cyber Resilience Act (CRA) rather than a different national/sectoral "Cybersecurity Act" (e.g. the EU Cybersecurity Act 2019/881 on ENISA + certification schemes) | `## ISO 27001 Annex A + CyberSecurity Act Mapping` | Medium — if the intended framework is actually EU Regulation 2019/881 (ENISA mandate + certification framework) rather than the CRA, the theme table would need different essential-requirement anchors; the planner/discuss-phase should confirm which framework is meant if not already resolved in an earlier phase's CONTEXT.md |
| A3 | `@asyncapi/cli` is safe to add as a docs-CI dev dependency despite its `[SUS]` automated verdict | `## Package Legitimacy Audit` | Low — verdict driven by sandbox download-count-lookup failure, not a genuine registry-legitimacy signal; repo matches the official AsyncAPI org, but flag with `checkpoint:human-verify` regardless per protocol |
| A4 | The SBOM / "security updates" rows in the CyberSecurity Act theme table are correctly marked N/A/Deferred for AXIAM's beta scope | `## ISO 27001 Annex A + CyberSecurity Act Mapping` | Low — if a Dependabot config or SBOM tool already exists elsewhere in the repo unseen by this research, these rows should be upgraded to Pass; worth a quick `ls .github/dependabot.yml` sanity check at plan time (this research did not confirm dependabot.yml's existence directly, only referenced it indirectly via `claude_dev/roadmap.md`'s mention of Phase 6 dependency scanning) |

## Open Questions

1. **Is "CyberSecurity Act" the EU CRA or EU Regulation 2019/881?**
   - What we know: CLAUDE.md and REQUIREMENTS.md both say "CyberSecurity Act" without a citation; the CRA is the more likely intended target given its focus on product-level essential requirements (which maps naturally to an IAM product's controls), while EU 2019/881 is more about ENISA's mandate and voluntary certification schemes.
   - What's unclear: Which framework the original project scoping (PROJECT.md / early milestone docs) intended.
   - Recommendation: Proceed with the CRA-based theme table in this research (most actionable, most control-mappable) but have the planner note this as a discretionary interpretation in the plan, consistent with D-02's "Claude's Discretion" for exact theme grouping.

2. **Does a Dependabot config already exist?**
   - What we know: `ci.yml`'s security-scan job runs `cargo-audit`/`cargo-deny`/`npm audit`; ROADMAP.md Phase 6 scope mentions "Dependabot" by name.
   - What's unclear: This research did not directly `ls .github/dependabot.yml` — the planner should do a 1-second check before finalizing the CSA "security updates" row's evidence pointer.
   - Recommendation: Quick `ls .github/dependabot.yml` at plan/execute time; if present, cite it directly instead of marking the row Partial/Deferred.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Node.js / npm | `@asyncapi/cli` validation step in docs CI | Assumed present (already used by `frontend-quality`/`npm audit` CI jobs) | not directly checked in this sandbox | If unavailable in a given runner, fall back to a Python/bash JSON/YAML-schema sanity check (looser, but egress-free) |
| Rust toolchain / cargo | `--dump-openapi` regeneration | ✓ (existing workspace already builds `axiam-server`) | per `dtolnay/rust-toolchain@stable` pin in CI | — |
| GitHub network egress for `npm install @asyncapi/cli` | AsyncAPI spec validation in docs CI | Unknown in this specific CI runner given the project's documented GitHub-egress fragility (swagger-ui workaround) — likely fine for `npm install` since `npm audit`/frontend CI already succeeds today, but flag for confirmation | — | If `npm install @asyncapi/cli` proves unreliable in CI, fall back to a manual/local-only validation step (developer runs `npx @asyncapi/cli validate` before commit) documented in `docs/api/README.md`, and drop the CI enforcement for the AsyncAPI half only (keep OpenAPI parse + link-check enforced) |

**Missing dependencies with no fallback:** none identified.
**Missing dependencies with fallback:** `@asyncapi/cli` CI validation (fallback: manual pre-commit validation + drop from CI enforcement if network egress proves unreliable).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `cargo test` (Rust integration tests, existing) — this phase adds no new test framework, only documentation artifacts and a docs-CI job |
| Config file | none new — existing `Cargo.toml` / workspace test setup |
| Quick run command | `cargo test -p axiam-api-rest --test gdpr_test` (re-run existing GDPR evidence) |
| Full suite command | `cargo test --workspace` (only if a genuine CMPL-02 gap forces new Rust code) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CMPL-01 | `security-audit.md` has a resolvable evidence pointer for every ASVS L2 / ISO family / CSA theme row | doc-lint (custom link-check script) | `<link-check script> claude_dev/security-audit.md docs/compliance/**` | ❌ Wave 0 — link-check script is net-new (see Light Docs CI) |
| CMPL-01 | Open items are cross-referenced to v1.2 REQ-IDs | manual review / doc-lint (grep for REQ-ID pattern near "Deferred"/"Open" rows) | `grep -c "REQ-\|SECFIX-\|SECHRD-\|CMPL-\|DOCS-" claude_dev/security-audit.md` | ❌ Wave 0 — no existing check, simple grep sanity check suffices |
| CMPL-02 | Export blob includes sessions (non-empty) | integration test (existing) | `cargo test -p axiam-api-rest --test gdpr_test export_includes_real_session_metadata` | ✅ exists |
| CMPL-02 | Export includes consents | integration test (existing) | `cargo test -p axiam-api-rest --test gdpr_test export_completeness` | ✅ exists |
| CMPL-02 | Erasure pseudonymizes audit PII durably | integration test (existing) | `cargo test -p axiam-api-rest --test gdpr_test deletion_pseudonymization` | ✅ exists |
| CMPL-02 | Consent recorded at registration | integration test (existing) | `cargo test -p axiam-api-rest --test gdpr_test consent_on_registration` | ✅ exists |
| DOCS-01 | OpenAPI JSON parses | CI doc-lint | `jq empty docs/api/openapi.json` (or reuse `sdk-openapi-drift.yml`'s existing drift check) | ✅ drift-check exists; new parse-only step is trivial addition |
| DOCS-01 | AsyncAPI spec parses / validates against meta-schema | CI doc-lint | `npx @asyncapi/cli validate docs/api/asyncapi.yml` | ❌ Wave 0 — spec file itself is net-new |
| DOCS-01 | Every internal doc link resolves | CI doc-lint | `<custom link-check script> docs/**/*.md claude_dev/security-audit.md` | ❌ Wave 0 — script is net-new |
| DOCS-01 | docs/README.md links to all 7 SDK READMEs + security-audit.md | doc-lint (covered by the internal link-check above, since these are internal relative links) | same link-check script | ❌ Wave 0 (same script covers this) |

### Sampling Rate
- **Per task commit:** re-run the specific `gdpr_test.rs` test(s) touched (if any code changes) or the relevant doc-lint script (if doc changes)
- **Per wave merge:** `cargo test -p axiam-api-rest --test gdpr_test` (full file) + full docs-CI job (spec-validate + link-check) locally before pushing
- **Phase gate:** Full docs-CI job green in CI + `cargo test --workspace` unaffected (this phase shouldn't touch non-docs Rust code, so a green `ci.yml` build/clippy/test run confirms no regression) before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `docs/api/asyncapi.yml` — net-new AsyncAPI spec (feeds the AsyncAPI-validate check)
- [ ] Custom internal-link-check script (e.g. `scripts/check-doc-links.py` or `.py`/`.sh`, per project's `scripts/` convention) — covers 3 of the DOCS-01 validation rows above
- [ ] `.github/workflows/docs-ci.yml` — new path-filtered CI job wiring both checks above
- [ ] `claude_dev/security-audit.md` — net-new master doc (the doc-lint checks validate its links/REQ-ID cross-refs, but the content itself has no automated "correctness" check beyond that — human review is the primary verification per D-03)

*(No gaps for CMPL-02 — existing `gdpr_test.rs` fully covers the required assertions.)*

## Security Domain

### Applicable ASVS Categories

This phase is itself a documentation/compliance phase, not a feature phase, so it does not introduce new application attack surface. The relevant ASVS lens here is different: this phase's job is to **verify** ASVS L2 compliance status is accurately reported, not to newly satisfy ASVS controls.

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | Cited, not modified | Already Pass per `docs/compliance/asvs-l2-checklist.md` — this phase only cites it |
| V3 Session Management | Cited, not modified | Same |
| V4 Access Control | Cited, not modified | Same |
| V6/V8 Cryptography / Data Protection | Cited, not modified — relevant to GDPR export encryption (AES-256-GCM + optional PGP) which this phase documents/verifies | `crates/axiam-core::models::pgp_key` (existing) |
| V14 Configuration | Marginally relevant | The new docs-CI job itself should not introduce a supply-chain risk — see Package Legitimacy Audit; no secrets are handled by the docs-CI job |

### Known Threat Patterns for this phase's scope

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malicious/typosquatted npm package pulled into docs-CI (`@asyncapi/cli` or a link-checker) | Tampering | `checkpoint:human-verify` before first install (per Package Legitimacy Audit); prefer the zero-dependency custom link-check script to minimize new supply-chain surface |
| `security-audit.md` overclaiming compliance status (misleading external stakeholders) | — (documentation-integrity risk, not a STRIDE category) | Explicit self-assessment framing (Pitfall 4) + version/last-verified stamping (D-12) |
| GDPR export doc inadvertently documenting a real gap as "closed" when spot-verification was too shallow | — (compliance-integrity risk) | This research found no gap; the plan should still execute the existing `gdpr_test.rs` suite as a "trust but verify" step (D-03's "spot-verify"), not skip it |

## Sources

### Primary (HIGH confidence)
- Direct codebase reads: `crates/axiam-server/src/cleanup.rs`, `crates/axiam-server/src/main.rs`, `crates/axiam-api-rest/src/openapi.rs`, `crates/axiam-api-rest/src/handlers/gdpr.rs`, `crates/axiam-api-rest/tests/gdpr_test.rs`, `crates/axiam-amqp/src/messages.rs`, `crates/axiam-amqp/src/connection.rs`, `docs/compliance/*.md`, `k8s/**`, `docker/**`, `.github/workflows/*.yml`, `.planning/phases/25-.../25-04-PLAN.md`, `.planning/ROADMAP.md`, `.planning/REQUIREMENTS.md`

### Secondary (MEDIUM confidence — websearch cross-checked against official domains)
- [AsyncAPI document structure](https://www.asyncapi.com/docs/concepts/asyncapi-document/structure) — top-level document keys
- [AsyncAPI 2.6.0 spec](https://github.com/asyncapi/spec/blob/v2.6.0/spec/asyncapi.md) — canonical spec text
- [AsyncAPI AMQP bindings](https://github.com/asyncapi/bindings/blob/master/amqp/README.md) — channel/message binding shape
- [AsyncAPI CLI validate guide](https://www.asyncapi.com/docs/guides/validate) — validate command behavior
- [AsyncAPI CLI GitHub](https://github.com/asyncapi/cli) — official tool, repo provenance
- [EU CRA summary](https://digital-strategy.ec.europa.eu/en/policies/cra-summary) / [CRA Annex I text](https://streamlex.eu/annexes/cra-en-annex-i/) — essential requirements structure
- [utoipa docs.rs](https://docs.rs/utoipa/latest/utoipa/openapi/struct.OpenApi.html) — `to_pretty_json()` API (confirms AXIAM's existing usage pattern is idiomatic)

### Tertiary (LOW confidence — flagged for validation)
- [Pivot Point Security ASVS/ISO27001 alignment](https://www.pivotpointsecurity.com/owasp-asvs-vs-iso-27001-alignment/) / [Security Compass mapping whitepaper](https://www.securitycompass.com/whitepapers/mapping-security-requirements-to-standards-owasp-asvs-to-iso-27001/) — no single canonical crosswalk exists; this research's family-table is derived, not sourced verbatim, from these partial/inconsistent vendor mappings — see Assumptions Log A1/A2

## Metadata

**Confidence breakdown:**
- CMPL-02 GDPR verification: HIGH — every claim traced to specific existing code lines and existing passing tests
- CMPL-01 existing-evidence citation: HIGH — all `docs/compliance/` files confirmed present and read directly
- CMPL-01 ISO27001/CSA mapping table: LOW/MEDIUM — genuinely interpretive, no canonical source, flagged for human confirmation
- DOCS-01 OpenAPI/gRPC republishing: HIGH — mechanism already exists and confirmed working (drift gate)
- DOCS-01 AsyncAPI spec skeleton: MEDIUM — spec structure verified against official AsyncAPI docs; AXIAM-specific message enumeration verified against source code (HIGH for the enumeration itself)
- DOCS-01 docs CI tooling choice: MEDIUM — options are well-understood, final tool choice is discretionary per D-11

**Research date:** 2026-07-06
**Valid until:** 2026-08-05 (30 days — stable domain; the only fast-moving element is the AsyncAPI/CRA regulatory landscape, which is unlikely to materially shift AXIAM's beta-scope mapping within 30 days)
