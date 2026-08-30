---
phase: 30-compliance-documentation
plan: 04
subsystem: docs
tags: [deployment, kubernetes, docker, admin, rbac, pki, certificates, mtls, docs]

# Dependency graph
requires:
  - phase: 30-compliance-documentation (30-01, 30-02, 30-03)
    provides: v1.2/beta version-stamp convention, citation-over-duplication style, docs/api landing page cross-linked by these guides
provides:
  - "docs/deployment/README.md — Docker Compose + Kubernetes deployment guide, required AXIAM__* secret KEY names table (transcribed from k8s/server/secret.yml, no values), NetworkPolicies summary (all 6 policy files)"
  - "docs/admin/README.md — first-run bootstrap (AXIAM_BOOTSTRAP_ADMIN_EMAIL / one-time setup-token gate), task-oriented org/tenant/user/role/permission management walkthroughs"
  - "docs/pki/README.md — CA + leaf certificate issuance, service-account mTLS binding vs. automatic Device fingerprint auth, revocation, keys-returned-once security model"
affects: [30-05-docs-readme-link-check, 30-06-docs-ci]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Operator/integrator task-oriented guide convention (H1 title, Milestone/Last-verified header, H2 task sections framed as imperative walkthroughs) applied consistently across all three new docs/**/README.md files, matching docs/api/README.md's header style from 30-03"
    - "Deployment guide's required-secrets table transcribes KEY NAMES only from k8s/server/secret.yml with one-line purpose per key — no real or example secret values anywhere"

key-files:
  created:
    - docs/deployment/README.md
    - docs/admin/README.md
    - docs/pki/README.md

key-decisions:
  - "Documented the admin bootstrap gate as it actually ships post-Phase-24 (SECHRD-04): EITHER AXIAM_BOOTSTRAP_ADMIN_EMAIL set-and-matching OR a one-time setup token minted and logged at first boot — not the older single-env-var-only description implied by the phase RESEARCH.md's shorthand. Read crates/axiam-api-rest/src/handlers/bootstrap.rs directly to get the current fail-closed two-gate behavior right rather than transcribing the research doc's simplified framing."
  - "Documented AXIAM_BOOTSTRAP_ADMIN_EMAIL as NOT part of the k8s/server/secret.yml required-secrets set (confirmed absent from all k8s manifests and docker-compose.prod.yml by grep) — it's an optional operator-supplied env var, not a shipped secret key, so it is called out separately in the admin guide rather than added to the deployment guide's secrets table."
  - "Documented the PKI 'bind' endpoint accurately as service-account-specific (POST /api/v1/service-accounts/{sa_id}/bind-certificate) and described IoT Device certificate mTLS authentication as the separate, automatic fingerprint+chain-verification flow in axiam-pki::mtls::DeviceAuthService — the plan's shorthand ('bind a certificate for mTLS device authentication') conflated the two; the actual code has one explicit bind call (service accounts) and one implicit fingerprint-lookup flow (devices), and both are now documented distinctly and correctly."

requirements-completed: [DOCS-01]

coverage:
  - id: D1
    description: "docs/deployment/README.md documents Docker/K8s deployment, the required AXIAM__* env/secret KEY names, and the NetworkPolicies — no real secret values"
    requirement: DOCS-01
    verification:
      - kind: other
        ref: "test -f docs/deployment/README.md && grep -Eq 'v1\\.2' docs/deployment/README.md && grep -q 'AXIAM__AUTH__JWT_PRIVATE_KEY_PEM' docs/deployment/README.md && grep -q 'AXIAM__GDPR_PSEUDONYM_PEPPER' docs/deployment/README.md && grep -Eq 'default-deny|NetworkPolic' docs/deployment/README.md"
        status: pass
      - kind: other
        ref: "grep -n 'BEGIN.*PRIVATE\\|BEGIN.*KEY-----' docs/deployment/README.md (no match — no real PEM/base64 secret material committed)"
        status: pass
    human_judgment: false
  - id: D2
    description: "docs/admin/README.md documents admin bootstrap + user/role/permission management, task-oriented"
    requirement: DOCS-01
    verification:
      - kind: other
        ref: "test -f docs/admin/README.md && grep -Eq 'v1\\.2' docs/admin/README.md && grep -q 'AXIAM_BOOTSTRAP_ADMIN_EMAIL' docs/admin/README.md"
        status: pass
    human_judgment: false
  - id: D3
    description: "docs/pki/README.md documents CA cert issuance, leaf cert issuance, mTLS device binding, and revocation, task-oriented"
    requirement: DOCS-01
    verification:
      - kind: other
        ref: "test -f docs/pki/README.md && grep -Eq 'v1\\.2' docs/pki/README.md && grep -Eiq 'issue|generate' docs/pki/README.md && grep -Eiq 'revoke|revocation' docs/pki/README.md && grep -Eiq 'mTLS|bind' docs/pki/README.md"
        status: pass
    human_judgment: false

duration: 40min
completed: 2026-07-06
status: complete
---

# Phase 30 Plan 04: Deployment / Admin / PKI Operator Guides Summary

**Authored the three task-oriented operator/integrator guides required by DOCS-01/D-08 — Docker/K8s deployment (required secrets + NetworkPolicies), admin bootstrap and RBAC management, and PKI certificate lifecycle — each transcribed and verified directly against the real k8s manifests, docker compose files, and REST handlers rather than invented from the phase research shorthand.**

## Performance

- **Duration:** ~40 min (source-reading heavy: k8s manifests, docker compose, 6 REST handler files, bootstrap.rs, mtls.rs)
- **Completed:** 2026-07-06
- **Tasks:** 3
- **Files modified:** 3 (all created)

## Accomplishments

- `docs/deployment/README.md`: Docker Compose path (`just prod-up`, the `docker/.secrets/` Ed25519-keypair-on-first-run convention, the `${VAR:?message}` fail-fast pattern in `docker-compose.prod.yml`) and Kubernetes path (`kubectl apply -k k8s/`, referencing `kustomization.yml`/`namespace.yml`/`ingress.yml`); a required-secrets table transcribing all 9 `AXIAM__*` KEY NAMES from `k8s/server/secret.yml` (DB creds, JWT Ed25519 keypair, MFA/PKI/federation/email AES-256-GCM keys, GDPR pseudonym pepper, auth pepper) with one-line purpose each and `<set-in-secret-manager>`-style placeholder guidance — no real values; and a NetworkPolicies section covering all 6 files under `k8s/network-policy/` (default-deny baseline, DNS egress, ingress-to-frontend/server, ingress-to-rabbitmq/surrealdb restricted to `component: server`, and the server-egress rule set including the fail-closed SMTP TEST-NET-1 placeholder).
- `docs/admin/README.md`: first-run bootstrap documented against the actual current code (`bootstrap.rs`) rather than the research doc's simplified framing — the fail-closed EITHER/OR gate (`AXIAM_BOOTSTRAP_ADMIN_EMAIL` match OR a one-time setup token minted/logged at first boot and consumed atomically), with the exact log line operators should look for and the full `POST /api/v1/admin/bootstrap` request shape; then task-framed walkthroughs (not an endpoint dump) for creating an organization/tenant, creating a user (noting the atomic terms-of-service consent write), defining roles and permissions, granting permissions to roles with optional scopes, and assigning roles to users or groups.
- `docs/pki/README.md`: certificate lifecycle as operator tasks — issuing an organization CA certificate (`POST .../ca-certificates`), issuing a leaf certificate for a user/service/device (`POST /api/v1/certificates`, `cert_type` one of `User`/`Service`/`Device`), binding a `Service` certificate to a service account for mTLS (`POST /api/v1/service-accounts/{sa_id}/bind-certificate`), the separate automatic fingerprint+CA-chain verification flow for `Device` certificates (`axiam-pki::mtls::DeviceAuthService`, fail-closed if no active CA exists), and revoking CA vs. leaf certificates with a note on CA-retirement migration order. States plainly, per CLAUDE.md's Security Standards, that private keys are returned exactly once and never stored server-side, and that CA signing keys are AES-256-GCM encrypted at rest.

## Task Commits

Each task was committed atomically:

1. **Task 1: Author docs/deployment/README.md** - `d65f25b` (docs)
2. **Task 2: Author docs/admin/README.md** - `c87905b` (docs)
3. **Task 3: Author docs/pki/README.md** - `626579c` (docs)

**Plan metadata:** pending (this commit)

## Files Created/Modified
- `docs/deployment/README.md` - new Docker/K8s operator deployment guide
- `docs/admin/README.md` - new admin bootstrap + RBAC management guide
- `docs/pki/README.md` - new PKI/certificate lifecycle guide

## Decisions Made
- Read `crates/axiam-api-rest/src/handlers/bootstrap.rs` directly (rather than relying solely on the phase RESEARCH.md's "AXIAM_BOOTSTRAP_ADMIN_EMAIL bootstrap pattern from Phase 3" shorthand) and documented the actual current SECHRD-04 fail-closed EITHER/OR gate (env var OR one-time setup token) shipped in Phase 24 — this is materially different from (and supersedes) the Phase 3 env-var-only description, and getting it wrong would have produced an inaccurate, potentially insecure-sounding admin guide.
- Confirmed via grep that `AXIAM_BOOTSTRAP_ADMIN_EMAIL` does not appear in any `k8s/*.yml` or `docker-compose.prod.yml` file, so it is documented in the admin guide as an optional operator-supplied env var rather than added to the deployment guide's `k8s/server/secret.yml`-sourced required-secrets table (keeping that table an exact transcription of the actual shipped secret manifest, per the plan's `key_links` constraint).
- Corrected the PKI guide's framing of "mTLS device binding" against the real code: `certificates.rs::bind` is scoped to service accounts only (`POST /api/v1/service-accounts/{sa_id}/bind-certificate`); IoT device certificates authenticate via a separate, automatic SHA-256-fingerprint + CA-chain-verification flow in `axiam-pki::mtls::DeviceAuthService` with no explicit bind call. Both flows are documented distinctly so an operator issuing a `Device`-type certificate doesn't look for a bind step that doesn't apply to it.
- Enumerated all 6 files under `k8s/network-policy/` in the deployment guide (matching the plan's explicit file list) even though `k8s/kustomization.yml` currently only references 4 of the 6 (`allow-ingress-to-rabbitmq.yml` and `allow-ingress-to-surrealdb.yml` are present on disk but not yet wired into the kustomization resources list) — this is a pre-existing gap in the kustomization manifest, out of scope for this docs-only plan's `files_modified`, and does not affect the accuracy of documenting what each policy file does.

## Deviations from Plan

None — plan executed exactly as written. All three guides transcribe from the exact sources listed in each task's `<read_first>`, and no gaps requiring Rule 1-4 fixes were found; the "Decisions Made" above are documentation-accuracy judgment calls within the plan's own scope, not deviations from it.

## Known Stubs

None. All three guides document real, currently-shipped endpoints, env vars, and manifests — no placeholder content, no unwired data sources.

## Threat Flags

None. This plan documents existing infrastructure and handler behavior; it introduces no new network endpoints, auth paths, file-access patterns, or schema changes. The threat register's T-30-10 (secret-leakage) mitigation was verified directly: no PEM body or base64 key blob appears anywhere in `docs/deployment/README.md`.

## Issues Encountered
- Found that `k8s/kustomization.yml` does not yet reference `allow-ingress-to-rabbitmq.yml` or `allow-ingress-to-surrealdb.yml` (present on disk, both correctly scoped `component: server`-only ingress policies, but not in the `resources:` list). This is a pre-existing infra gap outside this plan's `files_modified` (`k8s/kustomization.yml` was not a task file) — logged here rather than silently fixed, since editing `kustomization.yml` would be a Rule-2/architectural change to infra-as-code outside a documentation plan's scope. Flagging for a future infra-hardening follow-up.

## User Setup Required
None - no external service configuration required; these are documentation artifacts only.

## Next Phase Readiness
- `docs/deployment/README.md`, `docs/admin/README.md`, `docs/pki/README.md` are complete and ready to be linked from `docs/README.md` (30-05) and validated by `scripts/check-doc-links.sh` (30-05) and `docs-ci.yml` (30-06).
- No blockers for 30-05 or 30-06.
- Recommend a future infra task to add the two missing NetworkPolicy files to `k8s/kustomization.yml`'s `resources:` list (see Issues Encountered) — not blocking for this phase's DOCS-01 completion, since the guide accurately describes the policies as they exist on disk.

---
*Phase: 30-compliance-documentation*
*Completed: 2026-07-06*

## Self-Check: PASSED

All created files verified present on disk (`docs/deployment/README.md`, `docs/admin/README.md`, `docs/pki/README.md`, this SUMMARY). All task commits (`d65f25b`, `c87905b`, `626579c`) verified present in `git log`.
