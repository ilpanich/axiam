# Phase 30: Compliance & Documentation - Context

**Gathered:** 2026-07-06
**Status:** Ready for planning

<domain>
## Phase Boundary

The **final phase** of the v1.2 milestone. Document and certify the finished,
hardened MVP over the completed work of Phases 23–29 — this phase adds
compliance artifacts and consolidated documentation; it does **not** add new
product capabilities. Requirements **CMPL-01, CMPL-02, DOCS-01 are locked** by
ROADMAP.md / REQUIREMENTS.md — this discussion clarifies HOW to deliver them.

- **CMPL-01** — Security audit checklist → `claude_dev/security-audit.md`,
  mapping controls to OWASP ASVS L2, ISO 27001, and the CyberSecurity Act with
  pass/fail + evidence pointers; open items cross-referenced to v1.2 REQ-IDs (T18.1)
- **CMPL-02** — GDPR completeness: export covers every table incl. real
  sessions (optional PGP), account deletion durably pseudonymizes audit PII
  (ties to SECHRD-06, Phase 25), consent recorded and exportable (T18.2)
- **DOCS-01** — Consolidate REST (OpenAPI) / gRPC (proto) / AMQP (AsyncAPI) API
  docs, Docker/K8s deployment guide, admin + PKI/certificate guides, and links
  to the 7 SDK getting-started READMEs, under `docs/` (T18.4)

**Critical scouting finding (2026-07-06): most of the machinery this phase
certifies already exists.** `docs/compliance/` already holds an ASVS-L2
checklist, OAuth2-RFC, OIDC-conformance, FINDINGS.md, and sc4-coverage (Phase
7). The GDPR export sweep in `crates/axiam-server/src/cleanup.rs`
(`sweep_pending_exports`, ~L645–791) **already assembles consents + real
sessions** into an AES-256-GCM-encrypted blob with optional PGP; erasure
durability (pseudonymize + erasure-proof) landed as SECHRD-06 in Phase 25; a
consent repo + model exist (`axiam-db/.../consent.rs`, `axiam-core/.../gdpr.rs`).
`sdks/openapi.json`, `proto/axiam/v1/*.proto`, and all 7 SDK READMEs exist. So
this phase is predominantly **verify + close any real gap + document**, not
build. Net-new work is limited to: the ISO 27001 + CyberSecurity Act mappings,
an AsyncAPI spec for AMQP, the deployment/admin/PKI guides, and the docs index.

</domain>

<decisions>
## Implementation Decisions

> Captured interactively during discuss-phase (2026-07-06). Consistent with the
> Phase 23–29 posture: no over-engineering, reuse existing conventions, honest
> closure, and — for this certify/document phase specifically — **cite the
> evidence already proven by prior-phase verifications rather than re-auditing.**

### CMPL-01 — Security audit checklist
- **D-01 — Master audit that cites existing artifacts.**
  `claude_dev/security-audit.md` is the single top-level certification document.
  It maps controls to ASVS L2 + ISO 27001 + CyberSecurity Act with evidence
  pointers that **link into** the existing `docs/compliance/` files (and
  code/tests) rather than duplicating them. The `docs/compliance/` set remains
  the detailed backing evidence.
- **D-02 — ISO 27001 / CyberSecurity Act depth = control-family + evidence
  pointer.** Map ISO 27001 Annex A control **families** (e.g. A.5, A.8, A.9) and
  CyberSecurity Act essential-requirement **themes** to pass/fail with a pointer
  to code/tests/ASVS rows. Right altitude for an IAM MVP beta — auditable
  without a full ISMS certification effort. (ASVS L2 is already control-by-control
  from Phase 7 and is cited, not redone.)
- **D-03 — Cite phase evidence, spot-verify.** Trust the negative tests and
  verifications from Phases 23–29 as the evidence trail (each Success Criterion
  was proven in-code), spot-checking a representative sample. Do **not** re-run
  a full fresh re-audit. Open/deferred items are cross-referenced to v1.2 REQ-IDs.

### CMPL-02 — GDPR completeness
- **D-04 — Job = verify + close any real gap + document.** Audit that the export
  blob covers every table (verify consents + sessions + all user-owned entities
  are present), confirm erasure durably pseudonymizes audit PII (SECHRD-06),
  confirm consent is recorded **and** exportable; fix only genuine gaps found;
  then write the GDPR compliance documentation. Minimal net-new code.
- **D-05 — Keep the shipped async export; document it as satisfying the SC.**
  The roadmap SC names `GET /api/v1/users/:id/export`, but the shipped design is
  an async job: `POST /api/v1/account/export` (enqueue) →
  `GET /api/v1/account/export/{token}` (single-use encrypted download). This
  async design was a deliberate SECHRD-06 choice. Treat it as the **canonical**
  export API and document that it fulfills CMPL-02's intent (covers every table
  incl. sessions, optional PGP). The SC's `GET /users/:id/export` is descriptive
  shorthand, not a literal contract — **no new endpoint**. Note the reconciliation
  explicitly in the GDPR doc for honest closure.
- **D-06 — Consent scope = record + export (present); UI/withdrawal deferred.**
  CMPL-02's "consent recorded and exportable" is satisfied by the existing
  consent repo/model + inclusion in the export blob (`cleanup.rs` `consents_json`).
  Consent-capture UI and withdrawal flows are new capabilities → deferred (see
  Deferred Ideas), not built in this phase.

### DOCS-01 — Documentation
- **D-07 — Generate REST/gRPC, hand-author AMQP.**
  - **REST:** publish the utoipa-generated OpenAPI spec — regenerate/commit the
    OpenAPI JSON under `docs/api/` from the `axiam-api-rest` `ApiDoc`
    aggregator (`crates/axiam-api-rest/src/openapi.rs`); document how to view it.
  - **gRPC:** reference `proto/axiam/v1/*.proto` with a short usage guide.
  - **AMQP:** hand-author a **net-new AsyncAPI 2.x** spec for the queues/messages
    (derive from `crates/axiam-amqp/src/messages.rs` + the publishers/consumers)
    since none exists.
- **D-08 — Deployment/admin/PKI guides are operator+integrator, task-oriented.**
  Deployment guide for operators (Docker/K8s, required env/secrets,
  NetworkPolicies — drawn from `k8s/` manifests, `docker/`, and the SECHRD-10
  secret set); admin + PKI guides task-oriented (bootstrap, cert issuance/mTLS).
  Practical getting-it-running depth, not exhaustive reference or bare quickstart.
- **D-09 — Sectioned `docs/` + link out (single source of truth).** Organize
  `docs/` into `api/`, `deployment/`, `admin/`, `pki/`, `compliance/` (keep the
  existing `docs/compliance/` in place), with a `docs/README.md` landing/index.
  **Link out** to the 7 `sdks/*/README.md` and to `claude_dev/security-audit.md`
  rather than copying — no duplication/drift.

### Cross-cutting docs decisions
- **D-10 — OpenAPI publishing = spec file + static reference (no new live
  Swagger UI).** Commit the OpenAPI JSON under `docs/api/` and document viewing
  it with any Swagger/Redoc viewer. Do **not** newly wire in-app Swagger UI in
  this phase — avoids the known `utoipa-swagger-ui` GitHub-egress build
  fragility (see `SWAGGER_UI_DOWNLOAD_URL` workaround in CLAUDE.md). If a
  `/swagger` route already exists, just document it.
- **D-11 — Light docs CI: spec-validate + link-check.** Add a small CI step that
  validates the OpenAPI + AsyncAPI specs parse and checks internal doc links
  resolve. Cheap drift/broken-link guard, scoped to docs, no heavy tooling.
- **D-12 — Version-stamp docs to v1.2/beta + "last verified" date.** Each doc
  (and `security-audit.md`) carries the milestone (v1.2 beta) and a last-verified
  date, with a short note that it describes the beta state. Honest,
  point-in-time evidence.

### Claude's Discretion
- Exact ISO 27001 Annex A family granularity and CyberSecurity Act theme
  grouping within the D-02 "control-family + evidence pointer" altitude.
- Precise section layout inside each guide, and the specific link-check /
  spec-validate tooling used in CI (D-11), provided it stays lightweight.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & roadmap
- `.planning/ROADMAP.md` — Phase 30 section (Goal + 3 Success Criteria) and the v1.2 Coverage Matrix
- `.planning/REQUIREMENTS.md` §CMPL-01 / §CMPL-02 / §DOCS-01 (L1024–1055) — locked acceptance criteria
- `.planning/PROJECT.md` — milestone scope; "Documentation" and "Compliance" feature groups

### CMPL-01 — existing compliance evidence to cite (not duplicate)
- `docs/compliance/asvs-l2-checklist.md` — OWASP ASVS L2 control-by-control (Phase 7); primary backing
- `docs/compliance/FINDINGS.md` — deferred/finding rows referenced by the ASVS checklist
- `docs/compliance/oauth2-rfc-compliance.md` — OAuth2 RFC conformance
- `docs/compliance/oidc-conformance.md` — OIDC conformance
- `docs/compliance/sc4-coverage.md` — federation/test coverage evidence
- `claude_dev/security-review-postremediation.md` — post-remediation findings feeding v1.2 REQ-IDs
- `claude_dev/security-audit.md` — **to be created** (CMPL-01 deliverable)

### CMPL-02 — GDPR implementation to verify + document
- `crates/axiam-server/src/cleanup.rs` — `sweep_pending_exports` (~L645–791) assembles consents + sessions into the encrypted export blob
- `crates/axiam-api-rest/src/handlers/gdpr.rs` — export enqueue (`POST /account/export`), token download (`GET /account/export/{token}`), deletion/erasure paths
- `crates/axiam-db/src/repository/consent.rs` + `crates/axiam-core/src/models/gdpr.rs` — consent record/model
- `crates/axiam-db/src/repository/export_job.rs` — export job + dedup
- `crates/axiam-api-rest/tests/gdpr_test.rs` — existing GDPR tests (evidence)
- `.planning/phases/25-security-hardening-ii-federation-pki-data-protection-infra/` — SECHRD-06 erasure durability artifacts

### DOCS-01 — sources for generated/authored docs
- `crates/axiam-api-rest/src/openapi.rs` — utoipa `ApiDoc` aggregator (REST OpenAPI source)
- `sdks/openapi.json` + `sdks/CONTRACT.md` — existing generated spec + SDK contract
- `proto/axiam/v1/authorization.proto` / `token.proto` / `user.proto` — gRPC source
- `crates/axiam-amqp/src/messages.rs` (+ `*_publisher.rs` / `*_consumer.rs`) — AMQP message source for the net-new AsyncAPI spec
- `k8s/` + `docker/` (Dockerfiles, `docker-compose.prod.yml`, `nginx.conf`) — deployment-guide source
- `crates/axiam-api-rest/src/handlers/{certificates,ca_certificates}.rs`, `crates/axiam-pki/` — PKI/admin-guide source
- `sdks/{rust,typescript,python,java,csharp,php,go}/README.md` — 7 SDK getting-started READMEs (link, don't copy)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`docs/compliance/` (Phase 7):** ASVS-L2 checklist + conformance docs — cited as evidence by `security-audit.md`, kept in place under `docs/compliance/`.
- **GDPR export sweep (`cleanup.rs`):** already emits consents + sessions + user-owned entities into an encrypted (optional-PGP) blob — CMPL-02 is verification of this, not reimplementation.
- **utoipa `ApiDoc` aggregator (`openapi.rs`):** REST OpenAPI already generatable from handler annotations — regenerate → `docs/api/`.
- **`proto/axiam/v1/*.proto`:** gRPC contract already authored — reference + usage guide only.
- **7 SDK READMEs:** getting-started content already written — link from `docs/README.md`.

### Established Patterns
- **Honest closure over the hardened state (Phases 23–29):** each Success
  Criterion was proven with a negative/positive test; the audit cites those
  rather than re-proving them (D-03).
- **Fail-closed / async GDPR export (SECHRD-06):** the async enqueue→token
  download design is intentional; docs describe reality, not the SC's shorthand (D-05).

### Integration Points
- `docs/README.md` (new index) links to `docs/api/`, `docs/deployment/`, `docs/admin/`, `docs/pki/`, `docs/compliance/`, the SDK READMEs, and `claude_dev/security-audit.md`.
- New AsyncAPI spec (`docs/api/`) derives from `axiam-amqp` message types.
- Light CI doc job (D-11) validates the OpenAPI + AsyncAPI specs and internal links.

</code_context>

<specifics>
## Specific Ideas

- `security-audit.md` is a **master doc that cites** existing evidence — no
  copy-paste of ASVS rows.
- ISO 27001 / CyberSecurity Act mapped at **control-family / theme** level with
  evidence pointers, not control-by-control.
- Export API documented as the **async `POST /account/export` → token-download**
  flow (reconciling the roadmap's `GET /users/:id/export` shorthand).
- **No new in-app Swagger UI** — commit the spec, avoid the swagger-ui egress
  build issue.
- All docs stamped **v1.2 / beta + last-verified date**.

</specifics>

<deferred>
## Deferred Ideas

- **Consent-capture UI + consent-withdrawal flows** — new user-facing
  capabilities beyond CMPL-02's "recorded and exportable"; belongs in a future
  consent-management phase.
- **Live in-app Swagger/Redoc UI route** — deferred to avoid the
  `utoipa-swagger-ui` GitHub-egress build fragility; revisit post-beta if the
  egress workaround is no longer needed.
- **Full ISO 27001 control-by-control (93-control) audit + formal ISMS
  certification** — beyond MVP-beta altitude; the family-level mapping is
  sufficient for this milestone.
- **Literal synchronous `GET /api/v1/users/:id/export` endpoint** — only if a
  future consumer specifically requires it; the async flow satisfies CMPL-02.

</deferred>

---

*Phase: 30-compliance-documentation*
*Context gathered: 2026-07-06*
