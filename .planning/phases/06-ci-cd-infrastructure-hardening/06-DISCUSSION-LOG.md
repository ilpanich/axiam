# Phase 6: CI/CD & Infrastructure Hardening - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-04
**Phase:** 6-CI/CD & Infrastructure Hardening
**Areas discussed:** Vuln gate policy, Scan placement & image build, Server runtime base, NetworkPolicy & Pod Security, OpenAPI accuracy, Dependabot config, Vite SRI, Dev-compose cookie auth

---

## Vuln gate policy

### Gate behavior (36 existing vulns on main)
| Option | Description | Selected |
|--------|-------------|----------|
| Baseline + fail-new | Allowlist the 36, fail only on new | |
| Severity threshold | Fail high/critical only | |
| Fail on all, fix first | No allowlist; remediate all 36 | ✓ |

### No-patch advisories
| Option | Description | Selected |
|--------|-------------|----------|
| Documented per-CVE exception | Narrow deny.toml ignore + ID/justification/review date | ✓ |
| Block until upstream fixes | No exceptions at all | |
| Fail only on patchable | Unpatched warn, don't block | |

### Dependency license policy
| Option | Description | Selected |
|--------|-------------|----------|
| Permissive allowlist + deny unknown | MIT/Apache/BSD/ISC/... + deny UNKNOWN | ✓ |
| Warn-only on licenses | Don't fail CI on license | |
| You decide | Derive from dep tree | |

**User's choice:** Strict fail-on-all + documented per-CVE exceptions + permissive allowlist/deny-unknown.
**Notes:** User corrected project license — **AXIAM is Apache-2.0, not AGPL-3.0**. Verified: `LICENSE` is Apache-2.0, but `Cargo.toml:23` and both Dockerfile labels say `AGPL-3.0-or-later`, and `frontend/package.json` has no license field. Folded into scope as a metadata-correction decision (D-04).

---

## Scan placement & image build

### Trivy placement
| Option | Description | Selected |
|--------|-------------|----------|
| Hybrid: fs on PR, image on tag | Lightweight PR scans; image scan in release | ✓ |
| Build + scan image on every PR | Full image scan per PR | |
| Image scan release-only | Dep scans on PR, image scan on tag only | |

### Trivy image gate threshold
| Option | Description | Selected |
|--------|-------------|----------|
| HIGH/CRITICAL, ignore-unfixed | Fail on fixable high/critical | ✓ |
| HIGH/CRITICAL, including unfixed | Fail even with no fix | |
| All severities, ignore-unfixed | Fail on any fixable | |

### SARIF upload
| Option | Description | Selected |
|--------|-------------|----------|
| Yes, upload SARIF | Findings in Security tab | ✓ |
| No SARIF | Console output only | |

**User's choice:** Hybrid placement + trivy HIGH/CRITICAL ignore-unfixed (blocks release before sign) + SARIF upload.
**Notes:** Implies a build→scan→push→sign reorder in release.yml.

---

## Server runtime base

### Base image direction
| Option | Description | Selected |
|--------|-------------|----------|
| distroless/cc, keep SAML | Copy libxmlsec1 .so, rework healthcheck | ✓ |
| Keep debian-slim, document | REQ-10 exception | |
| distroless + SAML-off image | Drop SAML from default image | |

### Healthcheck mechanism
| Option | Description | Selected |
|--------|-------------|----------|
| axiam-server healthcheck subcommand | Self-probe binary subcommand | ✓ |
| Drop Docker HEALTHCHECK, K8s-only | Rely on kubelet probes | |
| Separate static probe binary | Extra COPY'd binary | |

**User's choice:** distroless/cc keeping SAML + `axiam-server healthcheck` subcommand.
**Notes:** K8s probes are kubelet httpGet (no container change). Frontend already non-root alpine; pin its base tags.

---

## NetworkPolicy & Pod Security

### NetworkPolicy posture
| Option | Description | Selected |
|--------|-------------|----------|
| Default-deny all + explicit allows + DNS | Ingress+egress deny, allows, DNS carve-out | ✓ |
| Default-deny ingress only + allows | Egress left open | |
| Named allows only, no global deny | Minimal | |

### External egress
| Option | Description | Selected |
|--------|-------------|----------|
| Allow TCP/443 egress broadly | 443 to 0.0.0.0/0 | |
| 443 egress, exclude private ranges | 443 minus RFC1918/cluster | ✓ |
| Defer external egress to research | Planner decides | |

### PSA mode
| Option | Description | Selected |
|--------|-------------|----------|
| Enforce restricted, harden all | Namespace enforce + all workloads | |
| Enforce app, warn datastores | App enforced, datastores warn | ✓ |
| Warn + audit only | No enforce | |

### PSA realization (namespace-scoped constraint surfaced)
| Option | Description | Selected |
|--------|-------------|----------|
| One ns: warn+audit, app compliant-by-construction | Single ns, harden app securityContexts | ✓ |
| Split namespaces, enforce app ns | Datastores to separate ns | |
| You decide during planning | Planner picks mechanism | |

**User's choice:** Default-deny all + DNS + 443-egress-minus-private; single namespace warn+audit=restricted with server/frontend compliant-by-construction; datastores best-effort.
**Notes:** Surfaced that PSA labels are namespace-scoped, so true per-pod enforce within one namespace isn't possible — namespace-wide `enforce=restricted` deferred until datastores verified.

---

## OpenAPI accuracy (T19.4)

| Option | Description | Selected |
|--------|-------------|----------|
| Route↔openapi parity test | Assert every route has utoipa::path | ✓ |
| Commit openapi.json + CI diff | Snapshot + diff | |
| Both | Parity + snapshot | |

**User's choice:** Route↔openapi parity test.
**Notes:** Codebase is code-first utoipa; mirrors Phase 3's registry parity test.

---

## Dependabot config

| Option | Description | Selected |
|--------|-------------|----------|
| cargo + npm + actions | All three ecosystems | ✓ |
| cargo + npm only | No actions | |
| Alerts only, no auto-PRs | No config file | |

**User's choice:** cargo + npm + github-actions.

---

## Vite SRI

| Option | Description | Selected |
|--------|-------------|----------|
| Research picks maintained plugin | sourcemap:false now; plugin via research | ✓ |
| vite-plugin-sri3 | Commit to specific plugin | |
| CSP hash strategy instead | Rely on CSP | |

**User's choice:** sourcemap:false now; SRI plugin selected by research.

---

## Dev-compose cookie auth

| Option | Description | Selected |
|--------|-------------|----------|
| Env-gated Secure flag | AXIAM_COOKIE__SECURE true prod / false dev | ✓ |
| Dev TLS / mkcert | HTTPS in dev | |
| Verify-only, planner decides | Planner picks | |

**User's choice:** Env-gated Secure flag; verify backend support, wire if missing.

---

## Claude's Discretion

- deny.toml structure, cargo-deny bans/duplicate strictness, npm `--audit-level` threshold (consistent with strict gate).
- Vite SRI plugin selection (deferred to research).
- CI job ordering, `needs:` graph, required status checks.

## Deferred Ideas

- Namespace-wide PSA `enforce=restricted` once datastores verified compliant.
- SBOM generation/publishing.
- Runtime admission control (OPA/Kyverno).
- Egress proxy for external HTTPS (vs broad 443-minus-private).
- Extend `build-no-saml` CI guard to `--tests` (blocked on `-Dwarnings` test drift; from STATE.md).
