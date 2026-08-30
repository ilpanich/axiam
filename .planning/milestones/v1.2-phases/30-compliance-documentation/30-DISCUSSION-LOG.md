# Phase 30: Compliance & Documentation - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-06
**Phase:** 30-compliance-documentation
**Areas discussed:** CMPL-01 audit scope/format, CMPL-02 GDPR verify vs build, DOCS-01 depth & generation, Docs structure & consolidation, OpenAPI/Swagger publishing, Docs CI & link-checking, Doc versioning & maintenance, Consent lifecycle scope

---

## CMPL-01 — Audit home (security-audit.md location)

| Option | Description | Selected |
|--------|-------------|----------|
| Master audit that cites existing | Top-level cert doc; evidence pointers link INTO docs/compliance/ | ✓ |
| Self-contained standalone | Restates all evidence inline; more duplication | |
| Extend docs/compliance/ in place | Add ISO/CSA into existing set; thin index | |

**User's choice:** Master audit that cites existing (Rec)
**Notes:** Existing docs/compliance/ stays as detailed backing; no duplication.

## CMPL-01 — Framework depth (ISO 27001 + CyberSecurity Act)

| Option | Description | Selected |
|--------|-------------|----------|
| Control-family + evidence pointer | Map ISO Annex A families + CSA themes to pass/fail + pointer | ✓ |
| Full control-by-control | All 93 ISO controls + each CSA clause individually | |
| Theme summary only | Narrative coverage, few representative controls | |

**User's choice:** Control-family + evidence pointer (Rec)
**Notes:** ASVS L2 already control-by-control from Phase 7; cited, not redone.

## CMPL-01 — Verification approach

| Option | Description | Selected |
|--------|-------------|----------|
| Cite phase evidence, spot-verify | Trust Phase 23–29 negative tests; spot-check a sample | ✓ |
| Full fresh re-audit | Re-verify every control independently now | |

**User's choice:** Cite phase evidence, spot-verify (Rec)
**Notes:** Open items cross-referenced to v1.2 REQ-IDs.

---

## CMPL-02 — Export API reconciliation

| Option | Description | Selected |
|--------|-------------|----------|
| Keep async, document as satisfying SC | Async POST-enqueue + GET-token-download is canonical; SC's GET /users/:id/export is shorthand | ✓ |
| Add a synchronous GET /users/:id/export | Build the literal endpoint alongside async flow | |
| Flag for planner to decide | Capture discrepancy, let planning resolve | |

**User's choice:** Keep async, document as satisfying SC (Rec)
**Notes:** Async design was a deliberate SECHRD-06 choice; no new endpoint. Reconciliation documented in the GDPR doc.

## CMPL-02 — Phase job

| Option | Description | Selected |
|--------|-------------|----------|
| Verify + close any real gap + document | Audit blob completeness, erasure durability, consent export; fix only genuine gaps; document | ✓ |
| Document-only (assume complete) | Trust Phase 25; write docs without re-verifying | |
| Treat as build phase | Assume material GDPR code missing | |

**User's choice:** Verify + close any real gap + document (Rec)
**Notes:** Scouting confirmed export sweep already assembles consents + sessions; minimal net-new code.

---

## DOCS-01 — API docs generation

| Option | Description | Selected |
|--------|-------------|----------|
| Generate REST/gRPC, author AMQP | OpenAPI from utoipa, proto reference, hand-authored AsyncAPI 2.x | ✓ |
| Hand-author narrative docs for all three | Prose reference pages, not spec-driven | |
| Generated specs only, minimal prose | Ship specs with thin intros | |

**User's choice:** Generate REST/gRPC, author AMQP (Rec)
**Notes:** No AsyncAPI spec exists yet — net-new for AMQP.

## DOCS-01 — Guide audience/depth

| Option | Description | Selected |
|--------|-------------|----------|
| Operators + integrators, task-oriented | Practical getting-it-running depth | ✓ |
| Comprehensive reference | Every config knob/endpoint/cert op | |
| Quickstart-only | Minimal happy-path setup | |

**User's choice:** Operators + integrators, task-oriented (Rec)
**Notes:** Deployment guide from k8s/ + docker/ + SECHRD-10 secret set.

## Docs structure & consolidation

| Option | Description | Selected |
|--------|-------------|----------|
| Sectioned docs/ + link out | api/deployment/admin/pki/compliance subdirs + README index; link to SDK READMEs + security-audit.md | ✓ |
| Flat docs/ with everything inline | Copy SDK quickstarts + compliance into docs/ | |
| Let planner decide layout | Capture doc set, defer structure | |

**User's choice:** Sectioned docs/ + link out (Rec)
**Notes:** Single source of truth; existing docs/compliance/ kept in place.

---

## OpenAPI/Swagger publishing

| Option | Description | Selected |
|--------|-------------|----------|
| Spec file + static reference | Commit OpenAPI JSON to docs/api/; view via any Swagger/Redoc; no new live UI | ✓ |
| Wire live Swagger UI route | Serve interactive UI in-app | |
| Both spec + live UI | Commit spec AND wire live UI | |

**User's choice:** Spec file + static reference (Rec)
**Notes:** Avoids known utoipa-swagger-ui GitHub-egress build fragility (SWAGGER_UI_DOWNLOAD_URL workaround).

## Docs CI & link-checking

| Option | Description | Selected |
|--------|-------------|----------|
| Light spec-validate + link-check | CI validates OpenAPI + AsyncAPI parse + internal links resolve | ✓ |
| Manual verification only | Verify by hand, no new CI | |
| You decide | Let planning judge | |

**User's choice:** Light spec-validate + link-check (Rec)
**Notes:** Cheap drift/broken-link guard, scoped to docs.

## Doc versioning & maintenance

| Option | Description | Selected |
|--------|-------------|----------|
| Stamp v1.2/beta + 'last verified' | Milestone + last-verified date + beta-state note per doc | ✓ |
| Unversioned | No version stamps | |

**User's choice:** Stamp v1.2/beta + 'last verified' (Rec)
**Notes:** Honest, point-in-time evidence.

## Consent lifecycle scope

| Option | Description | Selected |
|--------|-------------|----------|
| Record + export in scope; UI/withdrawal deferred | Confirm consent recorded + in export blob + document; defer capture/withdrawal UI | ✓ |
| Include withdrawal/capture flows now | Treat consent UI + withdrawal as in scope | |

**User's choice:** Record + export in scope; UI/withdrawal deferred (Rec)
**Notes:** Consent-capture UI + withdrawal are new capabilities → deferred.

---

## Claude's Discretion

- Exact ISO 27001 Annex A family granularity and CyberSecurity Act theme grouping within the control-family altitude.
- Precise section layout inside each guide, and the specific link-check / spec-validate tooling used in CI (kept lightweight).

## Deferred Ideas

- Consent-capture UI + consent-withdrawal flows — future consent-management phase.
- Live in-app Swagger/Redoc UI route — deferred to avoid swagger-ui egress build fragility.
- Full ISO 27001 control-by-control (93-control) audit + formal ISMS certification — beyond MVP-beta.
- Literal synchronous `GET /api/v1/users/:id/export` endpoint — only if a future consumer requires it.
