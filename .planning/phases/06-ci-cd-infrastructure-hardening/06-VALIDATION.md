---
phase: 6
slug: ci-cd-infrastructure-hardening
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-04
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from 06-RESEARCH.md §"Validation Architecture". Per-task rows are
> seeded at requirement level; the planner/executor refines them to concrete
> task IDs once PLAN.md files exist.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[test]` via `cargo test`; GitHub Actions for CI gates; Playwright (existing) for frontend |
| **Config file** | `deny.toml` (Wave 0 — create), `.github/workflows/ci.yml` (modify), `frontend/vite.config.ts` (modify) |
| **Quick run command** | `cargo test -p axiam-api-rest` |
| **Full suite command** | `cargo test --workspace` |
| **CI gate command** | `cargo audit && cargo deny check && (cd frontend && npm audit --audit-level=high)` |
| **Estimated runtime** | ~90 seconds (per-crate unit tests); CI gates ~3–5 min |

> **Note:** Most of this phase's "tests" are CI/release pipeline gates and
> build-output assertions, not unit tests. The unit-testable surface is the
> `route↔openapi` parity test (D-15) and the `healthcheck` subcommand (D-09).

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p <touched-crate>` (or `cargo check -p <crate> --tests` for non-test tasks); per project rule, never full-workspace builds.
- **After every plan wave:** Run `cargo test --workspace` + relevant CI gate command locally where feasible (`cargo deny check`, `hadolint docker/Dockerfile.*`).
- **Before `/gsd:verify-work`:** Full suite green + a green CI run on the feature branch proving the scan gates fire.
- **Max feedback latency:** 90 seconds (unit) / one CI run (gates).

---

## Per-Requirement Verification Map

| Req | Decision | Behavior (provable) | Test Type | Automated Command | Wave 0 Dep |
|-----|----------|---------------------|-----------|-------------------|------------|
| REQ-9 | D-01/D-05 | cargo-audit finds no unfixed vulns | CI gate | `cargo audit` | deny.toml not required, but advisories config aligns |
| REQ-9 | D-02/D-03 | cargo-deny license/vuln/bans policy passes | CI gate | `cargo deny check` | ❌ `deny.toml` |
| REQ-9 | D-05 | npm audit passes at high level | CI gate | `cd frontend && npm audit --audit-level=high` | ✅ package.json |
| REQ-9 | D-05 | hadolint passes on both Dockerfiles | CI gate | `hadolint docker/Dockerfile.server docker/Dockerfile.frontend` | ✅ Dockerfiles |
| REQ-9 | D-05/D-07 | trivy fs/config finds no HIGH/CRITICAL (SARIF uploaded) | CI gate | `trivy fs . && trivy config .` | ✅ source |
| REQ-9 | D-06 | trivy image scan blocks release on HIGH/CRITICAL `--ignore-unfixed` | Release gate | `trivy image --ignore-unfixed <ref>` (release.yml) | ❌ `release.yml` reorder |
| REQ-9 | D-15 | OpenAPI parity: every Actix route has a utoipa path & vice versa | Unit test | `cargo test -p axiam-api-rest route_openapi_parity` | ❌ parity test file |
| REQ-9 | D-17 | production build has no sourcemaps | Build output | `npm run build && test -z "$(ls frontend/dist/**/*.map 2>/dev/null)"` | ✅ vite.config.ts |
| REQ-9 | D-17 | SRI integrity hashes present in built index.html | Build output | `grep -q 'integrity="sha' frontend/dist/index.html` | ❌ `vite-plugin-sri3` |
| REQ-9 | D-01 | the 36 Dependabot vulns are remediated | CI gate | `cargo audit` + `npm audit` exit 0 | — |
| REQ-9 | D-04 | license metadata corrected to Apache-2.0 everywhere | Source assert | `grep -q 'Apache-2.0' Cargo.toml frontend/package.json docker/Dockerfile.server docker/Dockerfile.frontend` | — |
| REQ-9 | (CI proof) | a PR with a known vulnerable dep FAILS CI | Negative test | deliberately-vulnerable dep on a throwaway branch → CI red | ❌ throwaway proof branch |
| REQ-10 | D-08/D-09 | distroless server image starts & `/health` returns 200 | Smoke | `docker run <img> axiam-server healthcheck` exits 0 | ❌ Dockerfile + subcommand |
| REQ-10 | D-09 | healthcheck subcommand exits 0 healthy / 1 unhealthy | Unit/integration | `cargo test -p axiam-server healthcheck` | ❌ subcommand |
| REQ-10 | D-13 | restricted-profile securityContext fields present | Manifest assert | `grep -A20 securityContext k8s/server/deployment.yml | grep -E 'allowPrivilegeEscalation: false|drop|RuntimeDefault'` | ✅ manifests |
| REQ-10 | D-13 | namespace carries PSA warn+audit=restricted labels | Manifest assert | `grep 'pod-security.kubernetes.io/warn: restricted' k8s/namespace.yml` | ✅ namespace.yml |
| REQ-10 | D-11/D-12 | NetworkPolicy default-deny + explicit allows apply cleanly | Validation | `kubectl apply --dry-run=client -k k8s/` | ❌ netpol manifests |
| REQ-10 | D-14 | no inline `value:` literals for secrets in K8s manifests | Linting | `! grep -rn 'value:' k8s/ --include='*.yml' | grep -iE 'password|secret|key|token'` | ✅ manifests |
| REQ-10 | D-18 | cookie Secure=false works in dev compose (login over http://localhost) | Integration | login flow over plain HTTP succeeds with `AXIAM_COOKIE__SECURE=false` | ❌ AuthConfig field + csrf.rs |
| REQ-10 | D-16 | dependabot config covers cargo/npm/github-actions | Config assert | `grep -E 'cargo|npm|github-actions' .github/dependabot.yml` (3 hits) | ❌ dependabot.yml |

*Status legend: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Files that must exist before downstream tasks can be verified (created in each plan's first wave):

- [ ] `deny.toml` — workspace root; cargo-deny gate depends on it (D-02/D-03)
- [ ] `.github/dependabot.yml` — three ecosystems (D-16)
- [ ] `crates/axiam-api-rest/src/.../route_openapi_parity` test — D-15 (mirror Phase 3 parity test)
- [ ] `k8s/network-policy/` + NetworkPolicy manifests — D-11/D-12
- [ ] `crates/axiam-auth/src/config.rs` — add `cookie_secure` field with `#[serde(default = "default_true")]` — D-18
- [ ] `crates/axiam-api-rest/src/middleware/csrf.rs` — parameterize `.secure()` (currently hardcoded `true` in 3 helpers) — D-18
- [ ] `release.yml` — trivy image scan + build→scan→push→sign reorder — D-06
- [ ] `docker/Dockerfile.server` — distroless rewrite + xmlsec `.so` COPY from builder — D-08
- [ ] `crates/axiam-server/src/` — `healthcheck` subcommand — D-09
- [ ] `frontend` — `vite-plugin-sri3` install + `vite.config.ts` wiring — D-17

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Distroless image actually serves SAML-ON traffic (xmlsec `.so` present) | REQ-10 / D-08 | Needs a built image + `ldd` of the binary inside; full SAML flow needs an IdP | `docker run --rm --entrypoint sh` won't work (no shell) — instead build with `--target` debug variant or run `axiam-server healthcheck`; confirm no `error while loading shared libraries` at startup |
| NetworkPolicy actually blocks disallowed pod-to-pod traffic | REQ-10 / D-11 | Needs a live cluster (kind/minikube) with CNI that enforces NetworkPolicy | Apply manifests in kind w/ Calico; `kubectl exec` from a test pod, confirm allowed flows connect and denied flows time out |
| External 443 egress works while RFC1918 stays denied (D-12) | REQ-10 / D-12 | Cluster-specific pod/service CIDRs must fill the `except` list | Verify OIDC JWKS fetch + SAML IdP metadata succeed; confirm a curl to a private IP on 443 times out |
| "PR with vulnerable dep fails CI" (success criterion #1) | REQ-9 | Requires pushing a throwaway branch with a planted vuln | On a scratch branch add a known-RUSTSEC dep, push, confirm CI goes red, then delete branch |

---

## Open Items (from research — planner must resolve or placeholder)

- **Cluster CIDRs for D-12 `ipBlock.except`** — operator-specific; planner uses a documented placeholder (e.g. `10.0.0.0/8`, pod/service CIDRs as comments) the operator fills at deploy.
- **D-18 target compose file** — research found `docker-compose.dev.yml` has no `server` service today; planner decides whether D-18 wires the env override into `docker-compose.prod.yml` or adds a dev server service. CONTEXT.md names `docker-compose.dev.yml` — reconcile in plan.
- **Distroless `.so` exact minor versions** — confirm at build time via `ldd`; plan the COPY by glob/path, not hardcoded minor version.

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s (unit) / one CI run (gates)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
