# Phase 6: CI/CD & Infrastructure Hardening - Context

**Gathered:** 2026-06-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Make CI automatically catch vulnerable dependencies and insecure containers, and bring the Docker/K8s deployment configs up to security best-practice. The scan-tool list and success criteria are fixed by ROADMAP.md / REQUIREMENTS.md (REQ-9, REQ-10) — this phase clarifies *how* to wire them, not *whether*.

**In scope:** cargo-audit, cargo-deny, npm audit, trivy, hadolint in CI; remediation of the 36 existing Dependabot vulns; license-policy + license-metadata correction; Vite build hardening (sourcemap:false, SRI); OpenAPI accuracy verification (T19.4); distroless server image; K8s NetworkPolicy + Pod Security Standards; dependabot config; dev-compose cookie auth.

**Out of scope (deferred / other phases):** SBOM publishing; runtime admission control (OPA/Kyverno); namespace-wide PSA `enforce=restricted` (deferred follow-up — see Deferred); the actual integration tests for untested crates (Phase 7, REQ-11).
</domain>

<decisions>
## Implementation Decisions

### Vulnerability gate policy (REQ-9)
- **D-01:** Gate runs **strict — fail on all**. The 36 existing Dependabot vulns (13 high / 15 moderate / 8 low, per STATE.md) are **remediated as part of this phase** (cargo + npm) rather than allowlisted. No blanket baseline.
- **D-02:** Advisories with **no upstream patch** are handled via a **narrow, documented per-CVE exception** in `deny.toml` (cargo-deny `advisories.ignore`). Every ignore entry MUST carry the advisory ID + justification + review date. Fail on everything else.
- **D-03:** cargo-deny **license policy** = permissive allowlist (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-DFS, Zlib, MPL-2.0, and similar) + **deny UNKNOWN/unclear** licenses. Per-crate license-clarification exceptions added as needed.
- **D-04:** **Fix the project's own license metadata to `Apache-2.0`** (canonical `LICENSE` file is Apache-2.0). Three places are currently wrong/missing and MUST be corrected: `Cargo.toml:23` (`AGPL-3.0-or-later` → `Apache-2.0`), `docker/Dockerfile.server:81` label, `docker/Dockerfile.frontend:43` label, and add `"license": "Apache-2.0"` to `frontend/package.json` (no license field today).

### Scan placement & image build (REQ-9)
- **D-05:** **Hybrid placement.** PR-time (in `ci.yml`, no image build): cargo-audit, cargo-deny, npm audit, hadolint, `trivy fs` + `trivy config` (lockfiles/source/Dockerfile). Release-time (in `release.yml`): full `trivy image` scan on the built image.
- **D-06:** `trivy image` scan runs **before cosign signs / before publish** and **blocks the release** on **HIGH/CRITICAL with `--ignore-unfixed`** (skip unfixable OS-base CVEs). This requires reordering `release.yml` to **build → scan → push → sign** (currently build-push-action pushes in one step) — implementation detail for the planner.
- **D-07:** Scan results (trivy, hadolint) **upload SARIF** to the GitHub Security tab via `github/codeql-action/upload-sarif`.

### Server runtime base image (REQ-10)
- **D-08:** Server runtime moves to **`gcr.io/distroless/cc-debian12`**, **keeping SAML on**. The xmlsec native libs (`libxmlsec1`, `libxml2`, and transitive `.so` files) must be **copied from the builder stage** into the distroless image (distroless has no apt). Keep digest-pinning.
- **D-09:** Distroless has no curl/shell, so the curl-based health probes are replaced by an **`axiam-server healthcheck` subcommand** that self-probes `/health` and exits 0/1. `HEALTHCHECK` in `Dockerfile.server` and the `test:` in `docker-compose.prod.yml:50` both call `axiam-server healthcheck`. (Adds one small code task to `axiam-server`.) K8s probes already use kubelet `httpGet` (`/ready`, `/health`) and need no change.
- **D-10:** Frontend image already satisfies non-root/minimal (`nginxinc/nginx-unprivileged:1.29-alpine`, uid 101). Pin its base image tags by digest to match the server (and to satisfy hadolint DL3006/DL3007).

### K8s NetworkPolicy & Pod Security (REQ-10)
- **D-11:** **Default-deny ingress AND egress** at the namespace, plus explicit allows: `server→surrealdb` (8000), `server→rabbitmq` (5672), `ingress→frontend`, `ingress→server`, and a **DNS egress carve-out** (kube-dns UDP/TCP 53). Without DNS egress, service-name resolution silently breaks.
- **D-12:** **External egress** for the server (OIDC JWKS fetch, SAML IdP metadata, email-provider APIs — all dynamic IPs): allow **TCP/443 egress excluding private ranges** (RFC1918 + cluster CIDRs in the `except` list) so external HTTPS works while lateral movement on 443 stays denied.
- **D-13:** **Pod Security Standards** realized in a **single `axiam` namespace at `warn`+`audit`=restricted** (namespace-wide visibility). Server/frontend are made **compliant-by-construction** — add the missing restricted fields to their securityContext: `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `seccompProfile.type: RuntimeDefault` (they already have `runAsNonRoot`, `runAsUser`, `readOnlyRootFilesystem`). Datastores (surrealdb/rabbitmq StatefulSets) hardened best-effort. **Namespace-wide `enforce=restricted` is deferred** until the datastores are verified compliant (PSA labels are namespace-scoped, so `enforce` would reject non-compliant datastores).
- **D-14:** Verify K8s secret hygiene: deployments reference Secrets via `secretRef`/`secretKeyRef` (server uses `envFrom.secretRef: axiam-secrets`; surrealdb/rabbitmq use `secretKeyRef`) — confirm **no inline `value:` literals** for secrets across all manifests.

### OpenAPI accuracy (REQ-9 / T19.4)
- **D-15:** OpenAPI is **code-first via utoipa** (`#[utoipa::path]` + `ToSchema`, served at `/api/docs/openapi.json`, no committed spec file). Accuracy is verified with a **route↔openapi parity test**: assert every registered Actix route has a matching `utoipa::path` in the generated spec (and vice versa). Mirrors Phase 3's `ROUTE_PERMISSION_MAP ↔ PERMISSION_REGISTRY` parity test pattern.

### Dependabot (REQ-9 support)
- **D-16:** Add `.github/dependabot.yml` covering **three ecosystems**: `cargo` (root workspace), `npm` (frontend), `github-actions`. Weekly schedule, grouped minor/patch updates. Complements the D-01 "fix all 36" burndown.

### Frontend build hardening (REQ-9)
- **D-17:** Set `build.sourcemap: false` in `frontend/vite.config.ts` for production now. **SRI plugin choice is deferred to research** — the Vite SRI plugin ecosystem churns; researcher selects the currently best-maintained plugin (e.g. `vite-plugin-sri3` family) compatible with the installed Vite/React versions and pins it.

### Dev-compose cookie auth (REQ-10)
- **D-18:** Dev cookie auth via an **env-gated Secure flag** (e.g. `AXIAM_COOKIE__SECURE`): default **true** in prod, set **false** in `docker-compose.dev.yml` so login works over `http://localhost` (Secure cookies aren't sent over plain HTTP). **Verify the backend already reads such a flag**; wire it through cookie construction if missing.

### Claude's Discretion
- Exact `deny.toml` structure (advisories/licenses/bans/sources sections), cargo-deny `bans` duplicate-handling strictness, and npm `--audit-level` threshold — planner/researcher choose consistent with D-01..D-03.
- Vite SRI plugin selection (D-17).
- CI job ordering, `needs:` graph, and which checks become required status checks.
</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase requirements & scope
- `.planning/ROADMAP.md` §"Phase 6: CI/CD & Infrastructure Hardening" — goal, success criteria, scope list
- `.planning/REQUIREMENTS.md` §REQ-9 (CI/CD Security Hardening) and §REQ-10 (Infrastructure Hardening) — acceptance criteria
- `.planning/PROJECT.md` — milestone constraints (Apache-2.0 correction noted in D-04; OWASP ASVS L2 target)
- `.planning/STATE.md` §Blockers/Concerns — the 36 Dependabot vulns + the `build-no-saml --tests` follow-up note

### CI / release pipelines (modify)
- `.github/workflows/ci.yml` — current jobs: fmt, clippy, build (`--workspace`), `build-no-saml` guard, test (surrealdb + rabbitmq services). Add scan jobs here (PR-time). **Do not break the `build-no-saml` guard** (it deliberately omits libxmlsec1 deps).
- `.github/workflows/release.yml` — current: build+push (build-push-action), cosign sign, attest provenance, binary, GH release. Insert `trivy image` scan before sign/publish (D-06).
- `.github/dependabot.yml` — to be created (D-16).

### Docker (modify)
- `docker/Dockerfile.server` — builder `rust:1.94-bookworm` (digest-pinned), runtime `debian:bookworm-slim` (digest-pinned) → switch runtime to distroless/cc (D-08, D-09). Note libxmlsec1/libxml2/libssl3 runtime deps + the `org.opencontainers.image.licenses` label (D-04).
- `docker/Dockerfile.frontend` — `node:24-alpine` builder + `nginxinc/nginx-unprivileged:1.29-alpine` runtime; pin by digest (D-10), fix license label (D-04).
- `docker/docker-compose.prod.yml:49-54` — server healthcheck uses `curl` → switch to `axiam-server healthcheck` (D-09).
- `docker/docker-compose.dev.yml` — dev cookie-auth Secure flag (D-18).
- `docker/nginx.conf` — existing CSP/security headers (Phase 2); reference for SRI/CSP interaction (D-17).

### Frontend (modify)
- `frontend/vite.config.ts` — add `build.sourcemap: false` + SRI plugin (D-17).
- `frontend/package.json` — add `"license": "Apache-2.0"` (D-04); npm audit target.

### K8s (modify / create)
- `k8s/kustomization.yml` — resource list; add NetworkPolicy manifests.
- `k8s/namespace.yml` — add PSA labels `pod-security.kubernetes.io/{warn,audit}=restricted` (D-13).
- `k8s/server/deployment.yml:55-58` — extend securityContext to restricted (D-13).
- `k8s/frontend/deployment.yml:48-49` — extend securityContext to restricted (D-13).
- `k8s/surrealdb/statefulset.yml`, `k8s/rabbitmq/statefulset.yml` — best-effort restricted hardening; verify `secretKeyRef` usage (D-14).
- `k8s/server/secret.yml`, `k8s/server/configmap.yml`, `k8s/ingress.yml` — secret-hygiene + NetworkPolicy targets.
- NetworkPolicy manifests — to be created (D-11, D-12).

### Project metadata (correct)
- `Cargo.toml:23` — license field `AGPL-3.0-or-later` → `Apache-2.0` (D-04).
- `LICENSE` — canonical Apache-2.0 (source of truth).

### Code (small addition)
- `crates/axiam-server/src/` — add `healthcheck` subcommand (D-09).
- `crates/axiam-api-rest/src/` — utoipa `#[utoipa::path]` annotations + route registration; add route↔openapi parity test (D-15). Precedent: Phase 3 `ROUTE_PERMISSION_MAP ↔ PERMISSION_REGISTRY` test in `crates/axiam-api-rest/src/middleware/authz.rs`.
</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **Phase 3 parity-test pattern** (`crates/axiam-api-rest` middleware/authz tests) — cross-check two registries at test time; directly reusable for the route↔openapi parity test (D-15).
- **utoipa already wired** (`utoipa` + `utoipa-swagger-ui` deps, `ToSchema` derives, `#[utoipa::path]` macros) — spec generation exists; only the *accuracy guard* is missing.
- **cosign + attestation already in `release.yml`** — supply-chain signing exists; trivy slots in ahead of it.
- **Dockerfiles already non-root + digest-pinned (server)** — non-root half of REQ-10 is largely done; distroless is the remaining gap.
- **K8s securityContexts already have runAsNonRoot/runAsUser/readOnlyRootFilesystem** — only 3 restricted fields missing per workload.
- **secretKeyRef already used** on surrealdb/rabbitmq StatefulSets; server uses `envFrom.secretRef`.

### Established Patterns
- **SAML behind `saml` feature; `build-no-saml` CI guard** — the shipped Docker image builds SAML-ON (libxmlsec1). Any image/base change must keep the native libs available at runtime and must not regress the no-SAML build path.
- **Per-crate builds locally; CI uses `--workspace`** — scan steps should respect this (cargo-audit/deny operate on the lockfile, ecosystem-wide).
- **`-Dwarnings` enforced** in CI (`RUSTFLAGS`) — the `healthcheck` subcommand and parity test must be warning-clean.

### Integration Points
- `release.yml` build→scan→push→sign reorder (D-06) is the highest-risk change — current build-push-action pushes immediately; scanning before publish requires `load: true` then a separate push, or scanning the built image ref before the sign step.
- NetworkPolicy egress (D-12) must not break OIDC JWKS fetch (Phase 4), email-provider APIs (Phase 5), or DNS.
</code_context>

<specifics>
## Specific Ideas

- User explicitly chose the **strict/literal option in every area** — strict gate, distroless, default-deny netpol, restricted PSA. Downstream should prefer the rigorous interpretation when a tradeoff arises, documenting exceptions rather than relaxing posture.
- User corrected the project license to **Apache-2.0** — treat the repo's AGPL references as defects to fix (D-04), not as the policy.
</specifics>

<deferred>
## Deferred Ideas

- **Namespace-wide PSA `enforce=restricted`** — defer until surrealdb/rabbitmq StatefulSets are verified compliant with the restricted profile (PSA labels are namespace-scoped; enforcing now would reject non-compliant datastores). Candidate follow-up after Phase 6 or in Phase 7.
- **SBOM generation/publishing** (e.g. syft/cosign attach) — supply-chain enhancement beyond REQ-9's scan scope; future phase.
- **Runtime admission control** (OPA/Gatekeeper, Kyverno) to enforce NetworkPolicy/PSA cluster-side — beyond manifest hardening; future.
- **Egress proxy** for external HTTPS instead of broad 443-egress — tighter exfil control; future hardening if 443-egress-minus-private proves insufficient.
- **`build-no-saml` guard extended to `--tests`** (from STATE.md) — blocked on cleaning `-Dwarnings` drift in axiam-server test files; tracked, not part of Phase 6 scope.

</deferred>

---

*Phase: 6-CI/CD & Infrastructure Hardening*
*Context gathered: 2026-06-04*
