# Phase 6: CI/CD & Infrastructure Hardening — Research

**Researched:** 2026-06-04
**Domain:** CI/CD security scanning, Dockerfile hardening, Kubernetes security, Vite build hardening
**Confidence:** HIGH (most findings verified via npm registry, official docs, and codebase inspection)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Vulnerability gate policy (REQ-9)**
- D-01: Gate runs strict — fail on all. 36 existing Dependabot vulns (13 high / 15 moderate / 8 low) are remediated as part of this phase. No blanket baseline.
- D-02: Advisories with no upstream patch → narrow, documented per-CVE exception in `deny.toml` (`advisories.ignore`). Every entry MUST carry advisory ID + justification + review date.
- D-03: cargo-deny license policy = permissive allowlist (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-DFS, Zlib, MPL-2.0) + deny UNKNOWN/unclear.
- D-04: Fix project license metadata to `Apache-2.0` in Cargo.toml:23, Dockerfile.server:81 label, Dockerfile.frontend:43 label, and add `"license": "Apache-2.0"` to frontend/package.json.

**Scan placement & image build (REQ-9)**
- D-05: Hybrid placement — PR-time (ci.yml, no image build): cargo-audit, cargo-deny, npm audit, hadolint, `trivy fs` + `trivy config`. Release-time (release.yml): `trivy image`.
- D-06: `trivy image` runs before cosign signs / before publish; blocks on HIGH/CRITICAL --ignore-unfixed. Reorder release.yml: build → scan → push → sign.
- D-07: Scan results (trivy, hadolint) upload SARIF to GitHub Security tab via `github/codeql-action/upload-sarif`.

**Server runtime base image (REQ-10)**
- D-08: Server runtime moves to `gcr.io/distroless/cc-debian12`, keeping SAML on. xmlsec native libs must be COPY'd from builder stage.
- D-09: Replace curl health probe with `axiam-server healthcheck` subcommand that self-probes `/health`, exits 0/1. Used in HEALTHCHECK and docker-compose.prod.yml:50 test.
- D-10: Frontend image: pin base image tags by digest (nginx-unprivileged:1.29-alpine → digest-pinned).

**K8s NetworkPolicy & Pod Security (REQ-10)**
- D-11: Default-deny ingress AND egress at namespace; explicit allows: server→surrealdb (8000), server→rabbitmq (5672), ingress→frontend, ingress→server; DNS egress carve-out (kube-dns UDP/TCP 53).
- D-12: TCP/443 egress for server excluding private ranges (RFC1918 + cluster CIDRs) for OIDC/SAML/email external HTTPS.
- D-13: Pod Security Standards at axiam namespace: `warn+audit=restricted`. Server/frontend securityContexts extended with missing restricted fields. Enforce deferred.
- D-14: Verify no inline `value:` literals for secrets across all K8s manifests.

**OpenAPI accuracy (REQ-9 / T19.4)**
- D-15: Route↔openapi parity test — every registered Actix route must have a matching `utoipa::path` in the generated spec and vice versa.

**Dependabot (REQ-9 support)**
- D-16: Add `.github/dependabot.yml` covering cargo, npm, github-actions. Weekly, grouped minor/patch.

**Frontend build hardening (REQ-9)**
- D-17: `build.sourcemap: false` in vite.config.ts. SRI plugin choice deferred to research.

**Dev-compose cookie auth (REQ-10)**
- D-18: Env-gated `Secure` cookie flag via `AXIAM_COOKIE__SECURE` (or equivalent): default `true` in prod, set `false` in docker-compose.dev.yml.

### Claude's Discretion
- Exact `deny.toml` structure, cargo-deny `bans` duplicate-handling strictness, npm `--audit-level` threshold.
- Vite SRI plugin selection (D-17).
- CI job ordering, `needs:` graph, required status checks.

### Deferred Ideas (OUT OF SCOPE)
- Namespace-wide PSA `enforce=restricted` — defer until surrealdb/rabbitmq verified compliant.
- SBOM generation/publishing.
- Runtime admission control (OPA/Gatekeeper, Kyverno).
- Egress proxy for external HTTPS.
- `build-no-saml` guard extended to `--tests` (needs -Dwarnings cleanup first).
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID     | Description                                         | Research Support                                                            |
|--------|-----------------------------------------------------|-----------------------------------------------------------------------------|
| REQ-9  | CI/CD Security Hardening                            | Tooling versions, action pins, deny.toml schema, SRI plugin, parity test   |
| REQ-10 | Infrastructure Hardening                            | Distroless migration, xmlsec .so files, NetworkPolicy YAML, PSA labels     |
</phase_requirements>

---

## Summary

Phase 6 is primarily a wiring/configuration phase — the hard security engineering was done in Phases 1-5. The main risks are (1) the release.yml reorder for D-06 (build-push-action currently pushes immediately; the scan-before-push pattern needs a two-step build/push), (2) the distroless migration for D-08 which requires manually enumerating shared library files since distroless has no apt, and (3) D-18 which requires a new `cookie_secure` boolean field in AuthConfig (currently hardcoded `true` in three places in `crates/axiam-api-rest/src/middleware/csrf.rs`).

The D-17 SRI plugin research is resolved: `vite-plugin-sri3@2.0.0` is the right pick — it explicitly supports Vite 3-8, was published 2 months ago (2026-03-14), exists on npm (yoyo930021/vite-plugin-sri3), and has no runtime dependencies. The key CSP interaction requires adding a `hash-based integrity` directive or keeping the existing `'self'`-only script-src, since SRI hashes in the integrity attribute are checked by the browser independently of CSP.

The D-15 route↔openapi parity test has a practical implementation path: `ApiDoc::openapi()` (from the existing `openapi.rs`) exposes a `paths` map with all documented operations. The `ROUTE_PERMISSION_MAP` in `permissions.rs` (the Phase 3 precedent) enumerates all registered routes. A test can compare their path sets.

**Primary recommendation:** Tackle in this order: (1) fix license metadata first (trivial, unblocks cargo-deny), (2) add cookie_secure to AuthConfig (unblocks D-18), (3) wire CI scan jobs, (4) distroless migration with xmlsec COPY, (5) K8s hardening, (6) SRI plugin, (7) parity test.

---

## Architectural Responsibility Map

| Capability                    | Primary Tier     | Secondary Tier | Rationale                                                  |
|-------------------------------|-----------------|----------------|------------------------------------------------------------|
| Dependency vuln scanning      | CI Pipeline      | —              | Operates on lockfiles/source; no runtime component         |
| License policy enforcement    | CI Pipeline      | —              | cargo-deny runs on workspace Cargo.lock                    |
| Container vuln scanning       | CI Pipeline      | —              | Trivy fs/config at PR, trivy image at release              |
| SARIF upload                  | CI Pipeline      | GitHub (UI)    | codeql-action/upload-sarif writes to GH Security tab       |
| Image signing / provenance    | CI Pipeline      | —              | cosign sign + attest; must follow trivy gate               |
| Distroless runtime            | Container        | —              | Runtime base image swap; no app code change                |
| Healthcheck subcommand        | axiam-server     | Container      | New CLI subcommand; replaces curl in HEALTHCHECK + compose |
| Cookie Secure flag            | axiam-api-rest   | axiam-server   | New config field in AuthConfig; injected via env var       |
| SRI generation                | Frontend Build   | nginx (served) | Vite plugin adds integrity= at build time; nginx serves it |
| CSP header interaction        | nginx            | —              | Existing CSP at Phase 2; SRI hashes are additive           |
| NetworkPolicy                 | Kubernetes       | —              | New k8s/network-policy/ manifests                          |
| Pod Security Standards        | Kubernetes       | —              | Namespace labels + securityContext fields on workloads     |

---

## Standard Stack

### Core (CI Scanning)

| Tool / Action | Version | Purpose | Why Standard |
|---|---|---|---|
| `actions-rust-lang/audit` | `v1` | Cargo vulnerability audit via RustSec DB | Official Rust Actions org; uses cargo-audit |
| `EmbarkStudios/cargo-deny-action` | `v2` | License + vuln + bans + sources check | Official EmbarkStudios action; wraps cargo-deny |
| `aquasecurity/trivy-action` | `v0.36.0` | Container/filesystem/config scanning | Official Aqua Security GH action; produces SARIF |
| `hadolint/hadolint-action` | `v3.1.0` | Dockerfile linting | Official hadolint action |
| `github/codeql-action/upload-sarif` | `v4` | Upload SARIF to GH Security tab | v3 deprecated Dec 2026; v4 on Node.js 24 [CITED: github.blog/changelog/2025-10-28] |
| `cargo-deny` | `0.19.4` | License/vuln/bans/sources policy | Latest; dep of cargo-deny-action [VERIFIED: crates.io] |
| `cargo-audit` | `0.22.1` | RustSec advisory DB vuln check | Latest; dep of actions-rust-lang/audit [VERIFIED: crates.io] |

### Frontend

| Package | Version | Purpose | Provenance |
|---|---|---|---|
| `vite-plugin-sri3` | `2.0.0` | Vite SRI hash injection | [VERIFIED: npm registry] — peer `vite: ^3||^4||^5||^6||^7||^8`, published 2026-03-14, MIT, github.com/yoyo930021/vite-plugin-sri3 |

### K8s / Docker

| Component | Version/Tag | Notes |
|---|---|---|
| `gcr.io/distroless/cc-debian12:nonroot` | digest-pin | glibc + libgcc + libssl; nonroot UID 65532 [VERIFIED: GoogleContainerTools/distroless] |

---

## Package Legitimacy Audit

| Package | Registry | Age | Source Repo | slopcheck | Disposition |
|---|---|---|---|---|---|
| `vite-plugin-sri3` | npm | 2.5 yrs (first: 2023-11) | github.com/yoyo930021/vite-plugin-sri3 | slopcheck checked wrong ecosystem (crates.io), package confirmed on npm | Approved — npm existence verified, peer deps cover Vite 8, 11 versions published |

**Note:** slopcheck v0.6.1 defaults to crates.io for bare package names; `vite-plugin-sri3` does not exist on crates.io (correct — it is a JS package). The npm registry confirms: version 2.0.0 exists, 11 total versions, peerDependencies `{vite: "^3 || ^4 || ^5 || ^6 || ^7 || ^8"}`, published by GitHub Actions CI. `[ASSUMED]` tag not applied because npm registry confirmation is authoritative for an npm package.

**Packages removed due to slopcheck SLOP verdict:** none
**Packages flagged suspicious:** none

---

## Architecture Patterns

### System Architecture Diagram

```
PR push
   │
   ├─► fmt/clippy/build/build-no-saml/test (existing jobs, unchanged)
   │
   └─► [NEW] scan jobs (parallel)
          ├─► cargo-audit ─────────────────────► FAIL on RUSTSEC advisory
          ├─► cargo-deny ──────────────────────► FAIL on license/vuln/bans
          ├─► npm audit ───────────────────────► FAIL on high/critical
          ├─► hadolint ───────────────────────► SARIF → GH Security tab
          └─► trivy fs + trivy config ─────────► SARIF → GH Security tab

Tag push (v*)
   │
   ├─► build-server-image
   │       ├─► docker/build-push-action (load:true, no push)
   │       ├─► aquasecurity/trivy-action (image, HIGH/CRITICAL --ignore-unfixed)
   │       │       └─► BLOCK if vulnerabilities found
   │       ├─► docker/build-push-action (push:true, same cache → same digest)
   │       ├─► cosign sign @digest
   │       └─► attest-build-provenance @digest
   │
   └─► build-frontend-image (same pattern)
```

### Recommended Project Structure (additions)

```
.github/
├── workflows/
│   ├── ci.yml             # add scan jobs
│   └── release.yml        # reorder build→scan→push→sign
├── dependabot.yml         # new
deny.toml                  # new (workspace root)
docker/
├── Dockerfile.server      # runtime: debian-slim → distroless/cc
├── Dockerfile.frontend    # pin base digest, fix license label
└── docker-compose.dev.yml # add AXIAM__AUTH__COOKIE_SECURE=false
k8s/
├── namespace.yml          # add PSA labels
├── server/
│   └── deployment.yml     # extend securityContext
├── frontend/
│   └── deployment.yml     # extend securityContext
├── surrealdb/statefulset.yml   # best-effort hardening
├── rabbitmq/statefulset.yml    # best-effort hardening
└── network-policy/             # new directory
    ├── default-deny.yml        # default deny ingress+egress
    ├── server-egress.yml       # server→surrealdb, rabbitmq, DNS, external HTTPS
    ├── server-ingress.yml      # ingress→server
    └── frontend-ingress.yml    # ingress→frontend
frontend/
└── vite.config.ts         # add sourcemap:false + vite-plugin-sri3
crates/axiam-auth/src/
└── config.rs              # add cookie_secure: bool (default true)
crates/axiam-api-rest/src/middleware/
└── csrf.rs                # read cookie_secure from AuthConfig
crates/axiam-server/src/
└── main.rs                # pass AuthConfig.cookie_secure into handlers
crates/axiam-api-rest/src/
└── tests/route_openapi_parity_test.rs  # new parity test (D-15)
```

---

## Research Area 1: D-17 — Vite SRI Plugin (RESOLVED)

### Selected Plugin

**`vite-plugin-sri3@2.0.0`** [VERIFIED: npm registry]

- npm: https://www.npmjs.com/package/vite-plugin-sri3
- GitHub: https://github.com/yoyo930021/vite-plugin-sri3
- Peer deps: `vite: "^3 || ^4 || ^5 || ^6 || ^7 || ^8"` — explicitly supports Vite 8.0.x
- No runtime dependencies
- First published: 2023-11-30; latest (2.0.0): 2026-03-14 (2 months ago)
- License: MIT

### vite.config.ts Wiring

```typescript
// Source: https://github.com/yoyo930021/vite-plugin-sri3 (README)
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import sri from "vite-plugin-sri3";
import path from "path";

export default defineConfig({
  plugins: [react(), sri()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    sourcemap: false,   // D-17: never expose source maps in production
  },
  server: {
    // ... existing proxy config unchanged
  },
});
```

The plugin runs in the `transformIndexHtml` Vite hook at build time. It computes SHA-384 hashes over each `<script src>` and `<link rel="stylesheet">` tag in the emitted `index.html` and adds `integrity="sha384-..."` + `crossorigin="anonymous"` attributes.

### CSP Interaction

The existing nginx CSP (Phase 2) is: `script-src 'self'`. This is **compatible** with SRI — browsers enforce SRI independently of CSP. The `integrity=` attribute on `<script>` causes the browser to verify the hash before execution; `'self'` is still satisfied because the script URL is same-origin. No CSP change is required.

**Known pitfall — dynamic chunk splitting:** Vite's code-splitting may produce entry chunks that are referenced via `<link rel="modulepreload">` in addition to `<script type="module">`. `vite-plugin-sri3` handles both tag types. However, if Vite's manifest changes the hash of a chunk between builds but the old `index.html` is cached (CDN or browser), the browser will reject the load. The existing nginx config already sets `Cache-Control: no-cache` on `index.html` (`location = /index.html`) which is the correct mitigation — static assets get `immutable` (1y), `index.html` does not. This is already in place from Phase 2.

---

## Research Area 2: Tooling Versions / Action Pins (REQ-9)

### Recommended Action Versions

| Action | Ref | Notes |
|---|---|---|
| `actions-rust-lang/audit` | `v1` | Maintained by Rust Actions org; wraps cargo-audit 0.22.1 [ASSUMED — version from WebSearch, authoritative action ref from GitHub search] |
| `EmbarkStudios/cargo-deny-action` | `v2` (latest v2.0.20) | wraps cargo-deny 0.19.4 [CITED: github.com/EmbarkStudios/cargo-deny-action] |
| `aquasecurity/trivy-action` | `v0.36.0` | Latest confirmed from release page search [ASSUMED — verify at github.com/aquasecurity/trivy-action/releases] |
| `hadolint/hadolint-action` | `v3.1.0` | Official hadolint action [CITED: github.com/marketplace/actions/hadolint-github-action] |
| `github/codeql-action/upload-sarif` | `v4` | v3 deprecated Dec 2026; v4 uses Node.js 24 [CITED: github.blog/changelog/2025-10-28] |

**Security hardening:** Pin all third-party actions to full commit SHAs (not version tags) to prevent tag-mutable supply-chain attacks. The planner should add SHA pins. Use `nektos/act` or `pin-github-action` tool to resolve tags to SHAs.

### cargo-audit in CI

```yaml
# actions-rust-lang/audit@v1 uses cargo-audit under the hood
- name: Security audit
  uses: actions-rust-lang/audit@v1
  with:
    # Uses deny.toml `[advisories] ignore = [...]` automatically
    denyAdvisories: true
```

### cargo-deny in CI

```yaml
- name: Cargo deny
  uses: EmbarkStudios/cargo-deny-action@v2
  with:
    log-level: warn
    command: check
    arguments: --all-features
```

### npm audit in CI

```yaml
- name: npm audit
  working-directory: frontend
  run: npm audit --audit-level=high
```

`--audit-level=high` blocks on HIGH and CRITICAL, allows moderate/low. Consistent with D-01 (remediate all) but a reasonable fallback level in case a new moderate advisory appears between fix and CI run. The planner may set `--audit-level=moderate` for strictest compliance with D-01.

### trivy in CI (PR-time)

```yaml
# trivy fs (source + lockfiles)
- name: Trivy filesystem scan
  uses: aquasecurity/trivy-action@v0.36.0
  with:
    scan-type: fs
    scan-ref: .
    severity: HIGH,CRITICAL
    format: sarif
    output: trivy-fs.sarif
    ignore-unfixed: true

# trivy config (Dockerfile misconfiguration)
- name: Trivy config scan
  uses: aquasecurity/trivy-action@v0.36.0
  with:
    scan-type: config
    scan-ref: .
    format: sarif
    output: trivy-config.sarif

# Upload both SARIF files
- name: Upload Trivy SARIF
  uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: trivy-fs.sarif
    category: trivy-fs

- name: Upload Trivy config SARIF
  uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: trivy-config.sarif
    category: trivy-config
```

### hadolint in CI

```yaml
- name: Hadolint server Dockerfile
  uses: hadolint/hadolint-action@v3.1.0
  with:
    dockerfile: docker/Dockerfile.server
    format: sarif
    output-file: hadolint-server.sarif
    no-fail: true   # let codeql-action upload even on lint failure

- name: Hadolint frontend Dockerfile
  uses: hadolint/hadolint-action@v3.1.0
  with:
    dockerfile: docker/Dockerfile.frontend
    format: sarif
    output-file: hadolint-frontend.sarif
    no-fail: true

- name: Upload Hadolint SARIFs
  uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: hadolint-server.sarif
    category: hadolint-server

# (repeat for frontend)
```

**hadolint config:** Add a `.hadolint.yaml` at workspace root to suppress rules that conflict with the intentional design (e.g. DL3008 pin apt-get versions — already done via digest-pinning the FROM image; DL4006 `set -o pipefail` on RUN — consider enabling). [ASSUMED — specific rules to suppress depend on Dockerfile content]

---

## Research Area 3: D-06 — Build → Scan → Push → Sign Reorder

### The Problem

`docker/build-push-action@v6` currently has `push: true` which pushes immediately after build. To scan before push without rebuilding, use `load: true` first (loads image into local Docker daemon), scan by image tag, then rebuild with `push: true` using Buildx's layer cache.

### Pattern: Load → Scan → Push (Digest-Consistent)

The cleanest approach that guarantees the pushed image is identical to the scanned image:

```yaml
# Step 1: Build and load locally (no push)
- name: Build image (local scan target)
  id: build-local
  uses: docker/build-push-action@v6
  with:
    context: .
    file: docker/Dockerfile.server
    load: true
    tags: axiam-server:scan-${{ github.sha }}
    # No push: false is implied when load: true

# Step 2: Scan the locally loaded image
- name: Trivy image scan
  uses: aquasecurity/trivy-action@v0.36.0
  with:
    scan-type: image
    image-ref: axiam-server:scan-${{ github.sha }}
    severity: HIGH,CRITICAL
    ignore-unfixed: true
    exit-code: 1          # BLOCK release on findings
    format: sarif
    output: trivy-image.sarif

- name: Upload image scan SARIF
  uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: trivy-image.sarif
    category: trivy-image

# Step 3: Push (uses Buildx cache from Step 1 — same layers, same digest)
- name: Build and push
  id: build
  uses: docker/build-push-action@v6
  with:
    context: .
    file: docker/Dockerfile.server
    push: true
    tags: ${{ steps.meta.outputs.tags }}
    labels: ${{ steps.meta.outputs.labels }}
    cache-from: type=gha
    cache-to: type=gha,mode=max

# Step 4: Sign by digest (SAME digest as scanned image because layers are cache-hits)
- name: Sign image
  run: cosign sign --yes ${{ env.REGISTRY }}/${{ github.repository }}/server@${{ steps.build.outputs.digest }}
```

**Digest consistency guarantee:** Buildx uses content-addressable layers. As long as `cache-from: type=gha` (GitHub Actions cache) is used in both Step 1 and Step 3, and the Dockerfile/context hasn't changed between the two steps (same job, same commit), the pushed image will have the same manifest digest as the locally loaded one. The `steps.build.outputs.digest` from Step 3 is the pushed digest; cosign signs that exact digest. [CITED: docs.docker.com/build/ci/github-actions/test-before-push]

**Limitation:** `load: true` and multi-platform builds are mutually exclusive — `load: true` only works for single-platform. The current release.yml is single-platform (linux/amd64), so this is fine.

---

## Research Area 4: D-08/D-09 — Distroless + xmlsec

### Correct Distroless Variant

**`gcr.io/distroless/cc-debian12:nonroot`** [VERIFIED: GoogleContainerTools/distroless]

Contents of `cc` variant (beyond `static`):
- glibc (`libc6`)
- libgcc1
- libssl3 (OpenSSL 3.x)
- libstdc++6
- ca-certificates

**Nonroot user:** UID 65532, GID 65532, username "nonroot". [VERIFIED: GoogleContainerTools/distroless]

The `cc` variant does NOT include libxmlsec1, libxml2, or libltdl. These must be COPY'd from the builder stage.

### Runtime .so Files to COPY

From Debian bookworm (`/usr/lib/x86_64-linux-gnu/`), the SAML-ON build requires: [CITED: packages.debian.org/bookworm/libxmlsec1, packages.debian.org/bookworm/libxmlsec1-openssl]

```dockerfile
# From the builder (rust:1.94-bookworm which has apt-installed these in builder stage)
# Core xmlsec1 engine
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1.so.1 \
                    /usr/lib/x86_64-linux-gnu/libxmlsec1.so.1.2.37 \
                    /usr/lib/x86_64-linux-gnu/
# OpenSSL backend for xmlsec1
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so.1 \
                    /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so.1.2.37 \
                    /usr/lib/x86_64-linux-gnu/
# libxml2 (xmlsec1 dependency)
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxml2.so.2 \
                    /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14 \
                    /usr/lib/x86_64-linux-gnu/
# libltdl (libtool dlopen — needed by xmlsec1's dynamic engine loading)
COPY --from=builder /usr/lib/x86_64-linux-gnu/libltdl.so.7 \
                    /usr/lib/x86_64-linux-gnu/libltdl.so.7.3.1 \
                    /usr/lib/x86_64-linux-gnu/
# lzma/xz (libxml2 transitive dependency for XML compression)
COPY --from=builder /usr/lib/x86_64-linux-gnu/liblzma.so.5 \
                    /usr/lib/x86_64-linux-gnu/liblzma.so.5.4.1 \
                    /usr/lib/x86_64-linux-gnu/
# ICU libraries (libxml2 transitive — unicode normalization)
# These are large; verify with ldd at build time
COPY --from=builder /usr/lib/x86_64-linux-gnu/libicuuc.so.72 \
                    /usr/lib/x86_64-linux-gnu/libicudata.so.72 \
                    /usr/lib/x86_64-linux-gnu/
```

**Important:** The exact `.so` filenames and minor version numbers depend on the bookworm package versions at the time the builder image is pulled. The correct approach is to add a `RUN ldd /usr/local/bin/axiam-server` step in the builder to enumerate actual runtime dependencies, then COPY precisely those files. [ASSUMED — specific minor versions may differ from bookworm point releases]

**Canonical Dockerfile.server rewrite pattern:**

```dockerfile
FROM rust:1.94-bookworm@sha256:... AS builder
# ... (existing build steps) ...

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:<pinned>

LABEL org.opencontainers.image.licenses="Apache-2.0"   # D-04 fix
# ... other labels ...

# SAML runtime .so files (distroless has no apt)
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1.so.1 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1.so.1.2.37 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so.1 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so.1.2.37 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxml2.so.2 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libltdl.so.7 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/liblzma.so.5 /usr/lib/x86_64-linux-gnu/
# ca-certificates dir (distroless/cc includes these but explicit copy from builder is safer)
# -- distroless/cc already includes /etc/ssl/certs, skip

COPY --from=builder --chown=65532:65532 \
    /build/target/release/axiam-server /usr/local/bin/axiam-server

USER nonroot    # UID 65532

EXPOSE 8090 50051

# D-09: HEALTHCHECK using the healthcheck subcommand (no curl/shell in distroless)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/axiam-server", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/axiam-server"]
```

**D-09 healthcheck subcommand** in `crates/axiam-server/src/main.rs`:

```rust
// Add to CLI arg parsing (clap or manual match):
// axiam-server healthcheck  →  GET http://127.0.0.1:8090/health, exit 0 if 200, exit 1 otherwise
//
// Must use blocking HTTP client (reqwest::blocking or std::net::TcpStream + raw HTTP)
// to avoid async runtime overhead for a simple probe.
// Blocking reqwest is fine — the binary already depends on reqwest.
```

K8s probes already use `httpGet` and need no change.

---

## Research Area 5: D-11/D-12 — NetworkPolicy Patterns

### Default-Deny (namespace-wide)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: axiam
spec:
  podSelector: {}    # matches ALL pods in namespace
  policyTypes:
    - Ingress
    - Egress
  # No ingress/egress rules = deny everything
```

### DNS Egress Carve-Out (required for service-name resolution)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: axiam
spec:
  podSelector: {}    # all pods need DNS
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Server → SurrealDB + RabbitMQ

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: server-to-datastores
  namespace: axiam
spec:
  podSelector:
    matchLabels:
      component: server
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              component: surrealdb
      ports:
        - port: 8000
    - to:
        - podSelector:
            matchLabels:
              component: rabbitmq
      ports:
        - port: 5672
```

### Ingress → Server and Ingress → Frontend

```yaml
# Allow ingress controller to reach server
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-server
  namespace: axiam
spec:
  podSelector:
    matchLabels:
      component: server
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx  # adjust to your ingress namespace
      ports:
        - port: 8090
```

### D-12 — TCP/443 Egress Excluding RFC1918

```yaml
# [CITED: kubernetes.io/docs/concepts/services-networking/network-policies/]
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: server-external-https-egress
  namespace: axiam
spec:
  podSelector:
    matchLabels:
      component: server
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8        # RFC1918 class A
              - 172.16.0.0/12     # RFC1918 class B
              - 192.168.0.0/16    # RFC1918 class C
              - 100.64.0.0/10     # CGN (Carrier-grade NAT)
              # Add cluster pod CIDR and service CIDR (cluster-specific):
              # - 10.96.0.0/12    # typical K8s service CIDR
              # - 10.244.0.0/16   # typical pod CIDR (flannel/calico default)
      ports:
        - protocol: TCP
          port: 443
```

**Cluster CIDR values** (`except` list) are cluster-specific. The planner should document these as `TODO: fill cluster CIDRs` and note they must be set for each deployment target.

---

## Research Area 6: D-13 — Pod Security Standards

### Missing Restricted Fields (current state → required state)

From reading the deployments:

**Server deployment (k8s/server/deployment.yml)** — currently has:
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
```

**Missing for restricted profile** [CITED: kubernetes.io/docs/concepts/security/pod-security-standards/]:
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000        # keep (distroless nonroot UID is 65532 — update this after D-08)
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false    # ADD
  capabilities:
    drop:
      - ALL              # ADD
  seccompProfile:
    type: RuntimeDefault # ADD
```

**Frontend deployment (k8s/frontend/deployment.yml)** — currently has `runAsNonRoot`, `runAsUser: 101`, `runAsGroup: 101`. Missing same three fields.

**SurrealDB / RabbitMQ StatefulSets** — no `securityContext` at all. Best-effort: add `runAsNonRoot: true` + the restricted fields. SurrealDB uses UID 65532 (nonroot). RabbitMQ uses its own UID — check the image. [ASSUMED — specific UIDs for datastore images]

**`runAsUser` after distroless (D-08):** distroless/cc-debian12:nonroot runs as UID 65532. Update `runAsUser: 1000` → `runAsUser: 65532` in the server deployment after D-08.

### Namespace PSA Labels

```yaml
# k8s/namespace.yml
apiVersion: v1
kind: Namespace
metadata:
  name: axiam
  labels:
    app: axiam
    # Pod Security Admission — warn+audit at restricted; enforce deferred (D-13)
    # [CITED: kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/]
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.29
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.29
```

Version `v1.29` pins to a known-stable restricted policy definition. Increment when upgrading the cluster. [CITED: kubernetes.io/docs/concepts/security/pod-security-admission/]

---

## Research Area 7: D-15 — Route↔OpenAPI Parity Test

### Existing Infrastructure

- `openapi.rs`: `pub fn api_doc() -> utoipa::openapi::OpenApi` — already generates the full spec. The `paths()` map in the returned `OpenApi` is a `BTreeMap<String, PathItem>` keyed by the route path.
- `permissions.rs`: `ROUTE_PERMISSION_MAP: &[(&str, &str, &str)]` — `(METHOD, path_pattern, permission)` — the Phase 3 precedent; enumerates all authz-gated routes.
- `PUBLIC_PATHS: &[&str]` — enumerates all auth-exempt routes.

### Test Implementation Pattern

The utoipa `OpenApi` struct exposes `paths` as `Paths { paths: BTreeMap<String, PathItem> }`. Each `PathItem` has optional fields `get`, `post`, `put`, `delete`, etc.

```rust
// crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs
// Source: utoipa docs.rs/utoipa/latest/utoipa/openapi/path/struct.Paths.html (ASSUMED structure)

#[cfg(test)]
mod route_openapi_parity_tests {
    use crate::openapi::api_doc;
    use crate::permissions::{PUBLIC_PATHS, ROUTE_PERMISSION_MAP};

    #[test]
    fn every_route_permission_map_entry_is_in_openapi() {
        let spec = api_doc();
        let openapi_paths: std::collections::HashSet<String> =
            spec.paths.paths.keys().cloned().collect();

        let missing: Vec<_> = ROUTE_PERMISSION_MAP
            .iter()
            .filter(|(_, path, _)| !openapi_paths.contains(*path))
            .collect();

        assert!(
            missing.is_empty(),
            "Routes in ROUTE_PERMISSION_MAP not in OpenAPI spec: {missing:#?}"
        );
    }

    #[test]
    fn every_openapi_path_is_in_route_map_or_public() {
        let spec = api_doc();
        let route_paths: std::collections::HashSet<&str> =
            ROUTE_PERMISSION_MAP.iter().map(|(_, p, _)| *p).collect();
        let public_path_set: std::collections::HashSet<&str> =
            PUBLIC_PATHS.iter().copied().collect();

        let missing: Vec<_> = spec
            .paths
            .paths
            .keys()
            .filter(|p| {
                !route_paths.contains(p.as_str()) && !public_path_set.contains(p.as_str())
            })
            .collect();

        assert!(
            missing.is_empty(),
            "OpenAPI paths not in ROUTE_PERMISSION_MAP or PUBLIC_PATHS: {missing:#?}"
        );
    }
}
```

**Key constraint:** The `PUBLIC_PATHS` entries use prefix notation (`/api/docs/*`) while utoipa path keys use exact OpenAPI path templates (`/api/docs/openapi.json`). The parity test must normalize: strip utoipa's path params (`{id}` → `{param}`) and handle prefix wildcards.

**Actix limitation** (researched): Actix-web has no reflection API to enumerate registered routes programmatically (see github.com/actix/actix-web/issues/2677 — known limitation). The `ROUTE_PERMISSION_MAP` constant in `permissions.rs` is already the manually-maintained route registry (Phase 3 pattern). The parity test compares THAT registry against the utoipa spec, not against Actix's runtime route table. This is the correct and feasible approach.

**SAML feature gate:** The parity test should compile under both `saml` and `--no-default-features`. The SAML paths (`saml_authn_request`, `saml_acs`, `saml_metadata`) are behind `#[cfg(feature = "saml")]` in `openapi.rs`. The ROUTE_PERMISSION_MAP must have `#[cfg(feature = "saml")]`-gated entries for those paths, or the test only checks non-SAML paths by default.

---

## Research Area 8: D-01 — 36-Vuln Remediation Strategy

### Vuln Breakdown (from STATE.md)

36 Dependabot vulns: 13 high / 15 moderate / 8 low. Source: push 2026-06-02.

### Cargo Strategy

1. Run `cargo update` to pull latest compatible versions within `Cargo.toml` semver ranges — this resolves many vulns where the fix exists within the current major.
2. For crates requiring a major version bump: update `Cargo.toml` directly and resolve API changes.
3. For vulns with no fix available: add `deny.toml` exception (D-02 syntax below).
4. Verify with `cargo audit` and `cargo deny check advisories` after each batch.

**cargo-deny `deny.toml` schema** [CITED: embarkstudios.github.io/cargo-deny/checks/cfg.html]:

```toml
# deny.toml (workspace root)
[advisories]
version = 2
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"
notice = "warn"
ignore = [
    # Example of a no-patch-available exception (D-02):
    # { id = "RUSTSEC-2024-XXXX", reason = "No upstream fix available as of 2026-06-04; mitigated by [specific control]. Review by 2026-09-04.", date = "2026-06-04" },
]

[licenses]
version = 2
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Zlib",
    "MPL-2.0",
    "CC0-1.0",
]
deny = []
confidence-threshold = 0.8
exceptions = [
    # Per-crate exceptions for ambiguous license expressions, e.g.:
    # { allow = ["OpenSSL"], name = "ring", version = "*" },
]

[bans]
multiple-versions = "warn"
wildcards = "allow"
highlight = "all"

[sources]
unknown-registry = "warn"
unknown-git = "warn"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

**`advisories.ignore` syntax** [CITED: embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html]:
```toml
ignore = [
    { id = "RUSTSEC-2024-0001", reason = "reason string", date = "YYYY-MM-DD" },
]
```
The `date` field is a custom addition for governance — it is a TOML string, not a parsed date; cargo-deny does not auto-expire. The review date is a human convention enforced by code review.

### npm Strategy

```bash
cd frontend
npm audit --audit-level=high   # see high/critical
npm audit fix                   # auto-fix patchable vulns
npm audit fix --force           # for semver-breaking fixes (review changes)
npm audit                       # verify residual
```

Add `npm audit --audit-level=high` as CI gate (consistent with D-01).

---

## Research Area 9: D-18 — Cookie Secure Flag

### Current State

The `Secure` flag is hardcoded to `true` in all three cookie construction helpers in `crates/axiam-api-rest/src/middleware/csrf.rs`:
- `access_cookie()`: `.secure(true)` at line 193
- `refresh_cookie()`: `.secure(true)` at line 206  
- `csrf_cookie()`: `.secure(true)` at line 222

The `AuthConfig` struct (`crates/axiam-auth/src/config.rs`) does NOT have a `cookie_secure` field. It must be added.

### Implementation Pattern (D-18)

**Step 1 — Add field to `AuthConfig`:**
```rust
// crates/axiam-auth/src/config.rs
/// When false, cookies are served without the Secure flag.
/// ONLY set to false in local HTTP development (docker-compose.dev.yml).
/// Default: true. Controlled via AXIAM__AUTH__COOKIE_SECURE.
#[serde(default = "default_true")]
pub cookie_secure: bool,
```

**Step 2 — Thread `cookie_secure` into cookie helpers:**
The three helpers in `csrf.rs` need the flag passed in. Options:
- Pass `cookie_secure: bool` parameter to each helper.
- Pass `&AuthConfig` to each helper (already done for `access_token_lifetime_secs`).

The second option is cleaner since the helpers already use `AuthConfig` for token lifetimes. Add `.secure(config.cookie_secure)` in place of `.secure(true)`.

**Step 3 — docker-compose.dev.yml:**
```yaml
environment:
  AXIAM__AUTH__COOKIE_SECURE: "false"
```

**Note:** `docker-compose.dev.yml` currently starts only SurrealDB and RabbitMQ (no axiam-server service). D-18 applies to a dev stack that runs the server — either `docker-compose.prod.yml` with `AXIAM__AUTH__COOKIE_SECURE: false` override, or a dev-server compose file that doesn't exist yet. The planner should check whether `docker-compose.dev.yml` is extended with an axiam-server service for D-18, or if `docker-compose.prod.yml` should accept this env override.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---|---|---|---|
| Advisory DB queries | Custom RUSTSEC parser | `cargo-audit` / `cargo-deny` | Handles DB sync, multiple advisory sources, lock file graph traversal |
| Container vuln scanning | Custom image layer analysis | `trivy` | Handles OS packages + language ecosystems, distroless images, SARIF output |
| Dockerfile linting | Manual Dockerfile review | `hadolint` | 80+ rules, DL codes, `ignore` comments for exceptions |
| SRI hash computation | Custom Node.js hash script | `vite-plugin-sri3` | Handles chunk splitting, modulepreload links, crossorigin attribute |
| Image signing | Manual key management | `cosign` (already present) | Keyless signing via Sigstore/OIDC, built into release.yml |

---

## Common Pitfalls

### Pitfall 1: Distroless Missing .so Transitive Deps

**What goes wrong:** The Dockerfile COPY's `libxmlsec1.so` and `libxmlsec1-openssl.so` but misses their transitive deps (libltdl, liblzma, ICU libs). Container starts but crashes at runtime with `error while loading shared libraries`.

**Why it happens:** `ldd` output not checked at build time; transitive deps are invisible.

**How to avoid:** Add a `RUN ldd /usr/local/bin/axiam-server` step in a debug build to enumerate all `.so` files needed. Cross-check against what the `cc` variant already provides (glibc, libgcc, libssl). COPY only the delta.

**Warning signs:** Container exits immediately after start; `docker logs` shows `cannot open shared object file`.

### Pitfall 2: release.yml Digest Mismatch (Two-Step Build)

**What goes wrong:** `build-local` (load:true) and `build-push` (push:true) produce different image digests because GHA cache was invalidated between steps or a layer changed.

**Why it happens:** Buildx layer cache (type=gha) is shared across jobs but can be evicted. If the cache is cold for Step 3, Docker rebuilds all layers and the digest differs.

**How to avoid:** Both build steps in the same job, back-to-back, using `cache-from: type=gha` with the same cache key. Verify by asserting that `docker inspect axiam-server:scan-$SHA --format='{{.Id}}'` equals the OCI digest reported by the push step.

**Warning signs:** cosign signing succeeds but the signed digest doesn't match the locally-scanned image; Trivy reports the scan passed but the pushed image has different content.

### Pitfall 3: NetworkPolicy Breaks DNS → Service Lookups Fail Silently

**What goes wrong:** Default-deny egress is applied without the DNS carve-out. Pods start up fine (IPs are resolved at container creation) but fail when code makes DNS-based lookups (e.g., `surrealdb:8000` after pod restart).

**Why it happens:** Kubernetes service names resolve via kube-dns (UDP 53, kube-system namespace). Without explicit egress to kube-dns, all service name lookups time out.

**How to avoid:** Always apply the `allow-dns-egress` NetworkPolicy before or simultaneously with `default-deny-all`.

**Warning signs:** Pods can connect by ClusterIP but not by service name; DNS resolution times out; `kubectl exec pod -- nslookup surrealdb` fails.

### Pitfall 4: PSA warn+audit Labels Emit Warning Storms on Existing Non-Compliant Pods

**What goes wrong:** Adding PSA `warn=restricted` to the namespace causes Kubernetes to emit a warning on every `kubectl apply` for manifests that are not yet fully restricted. This is noisy but non-breaking (warn does not reject).

**Why it happens:** Existing pods (SurrealDB, RabbitMQ) don't have the restricted fields yet when the namespace label is applied.

**How to avoid:** Add the restricted securityContext fields to all workloads (at least best-effort) BEFORE adding the namespace PSA labels. The warn is advisory — it won't break anything — but quieting it demonstrates real compliance.

### Pitfall 5: cargo-deny `[advisories]` Requires `db-path` to Exist

**What goes wrong:** `cargo deny check` fails locally with `advisory-db not found at ~/.cargo/advisory-db` because the DB hasn't been fetched.

**Why it happens:** First run on a fresh machine or CI without cargo-deny cache.

**How to avoid:** The `EmbarkStudios/cargo-deny-action` handles the DB fetch automatically. For local use, run `cargo deny fetch` first. In CI, use the GHA caching built into the action.

### Pitfall 6: SRI + style-src CSP Conflict

**What goes wrong:** Adding SRI hashes to CSS stylesheets fails if the CSP `style-src` directive only allows `'self' 'unsafe-inline'` (the current nginx.conf has `style-src 'self' 'unsafe-inline'`). SRI-hashed stylesheets are loaded as `<link rel="stylesheet" integrity="sha384-...">` and do NOT require hash-in-CSP — only inline styles need `'unsafe-inline'`. External `<link>` tags with `integrity=` are allowed by `'self'` alone.

**Why it happens:** Confusion between inline styles (need CSP hash or unsafe-inline) and linked stylesheets (need only 'self' + SRI attribute on the tag).

**How to avoid:** No CSP change needed for Vite-generated hashed assets loaded via `<link>`. The existing `style-src 'self' 'unsafe-inline'` is compatible.

---

## Code Examples

### deny.toml — Full Template

```toml
# deny.toml — cargo-deny workspace configuration
# [CITED: embarkstudios.github.io/cargo-deny/checks/cfg.html]

[advisories]
version = 2
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"
notice = "warn"
ignore = [
    # No exceptions currently. Add as:
    # { id = "RUSTSEC-XXXX-XXXX", reason = "No fix available; mitigated by <control>. Review: YYYY-MM-DD" }
]

[licenses]
version = 2
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Zlib",
    "MPL-2.0",
    "CC0-1.0",
    "OpenSSL",
]
confidence-threshold = 0.8
exceptions = []

[bans]
multiple-versions = "warn"
wildcards = "allow"
highlight = "all"

[sources]
unknown-registry = "warn"
unknown-git = "warn"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

### CI scan job snippet (ci.yml addition)

```yaml
security-scan:
  name: Security Scan
  runs-on: ubuntu-latest
  needs: []    # run in parallel with existing jobs
  permissions:
    contents: read
    security-events: write   # required for codeql-action/upload-sarif
  steps:
    - uses: actions/checkout@v4

    # --- Rust ---
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2

    - name: cargo audit
      uses: actions-rust-lang/audit@v1

    - name: cargo deny
      uses: EmbarkStudios/cargo-deny-action@v2
      with:
        command: check
        arguments: --all-features

    # --- npm ---
    - name: npm audit
      working-directory: frontend
      run: |
        npm ci --ignore-scripts
        npm audit --audit-level=high

    # --- Dockerfiles ---
    - name: Hadolint server Dockerfile
      uses: hadolint/hadolint-action@v3.1.0
      with:
        dockerfile: docker/Dockerfile.server
        format: sarif
        output-file: hadolint-server.sarif
        no-fail: true

    - name: Hadolint frontend Dockerfile
      uses: hadolint/hadolint-action@v3.1.0
      with:
        dockerfile: docker/Dockerfile.frontend
        format: sarif
        output-file: hadolint-frontend.sarif
        no-fail: true

    # --- Trivy source + config ---
    - name: Trivy filesystem scan
      uses: aquasecurity/trivy-action@v0.36.0
      with:
        scan-type: fs
        scan-ref: .
        severity: HIGH,CRITICAL
        ignore-unfixed: true
        exit-code: 1
        format: sarif
        output: trivy-fs.sarif

    - name: Trivy config scan
      uses: aquasecurity/trivy-action@v0.36.0
      with:
        scan-type: config
        scan-ref: .
        format: sarif
        output: trivy-config.sarif
        exit-code: 0    # config findings are advisory

    # --- SARIF uploads ---
    - uses: github/codeql-action/upload-sarif@v4
      if: always()
      with:
        sarif_file: hadolint-server.sarif
        category: hadolint-server

    - uses: github/codeql-action/upload-sarif@v4
      if: always()
      with:
        sarif_file: hadolint-frontend.sarif
        category: hadolint-frontend

    - uses: github/codeql-action/upload-sarif@v4
      if: always()
      with:
        sarif_file: trivy-fs.sarif
        category: trivy-fs

    - uses: github/codeql-action/upload-sarif@v4
      if: always()
      with:
        sarif_file: trivy-config.sarif
        category: trivy-config
```

### dependabot.yml

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: cargo
    directory: /
    schedule:
      interval: weekly
      day: monday
    groups:
      minor-patch:
        update-types:
          - minor
          - patch

  - package-ecosystem: npm
    directory: /frontend
    schedule:
      interval: weekly
      day: monday
    groups:
      minor-patch:
        update-types:
          - minor
          - patch

  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
      day: monday
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|---|---|---|---|
| `github/codeql-action@v3` | `github/codeql-action@v4` (Node 24) | v4 released Oct 2025; v3 deprecated Dec 2026 | Use v4 now |
| Curl-based Docker healthcheck | Binary self-probe subcommand | Standard for distroless containers | Required for D-08 |
| Debian-slim runtime base | distroless/cc-debian12 | Growing standard 2023+ | Smaller attack surface, no shell |
| PSA PodSecurityPolicy (removed) | Pod Security Standards (PSA labels) | K8s 1.25+ | PSP was removed; PSA labels are the current standard |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|---|---|---|
| A1 | `actions-rust-lang/audit@v1` is the current maintained version | Tooling Versions | CI uses outdated action; check github.com/actions-rust-lang/audit |
| A2 | `aquasecurity/trivy-action@v0.36.0` is the latest release | Tooling Versions | CI may miss newer version; verify at github.com/aquasecurity/trivy-action/releases |
| A3 | Exact minor version numbers of libxmlsec1/libxml2 .so files in bookworm (1.2.37, 2.9.14) | Distroless COPY | COPY fails if minor version differs; use `ldd` at build time to verify |
| A4 | ICU libraries (libicuuc, libicudata) are required by libxml2 in bookworm | Distroless COPY | Missing dep causes runtime crash; verify with ldd |
| A5 | RabbitMQ StatefulSet container runs as non-root in the official image | PSA hardening | `runAsNonRoot: true` may cause pod rejection if image runs as root |
| A6 | D-18: `docker-compose.dev.yml` will be extended with an axiam-server service | Cookie Secure | If server isn't in dev compose, the env var change has no target |
| A7 | `ROUTE_PERMISSION_MAP` path patterns exactly match utoipa-generated OpenAPI path keys | Parity test | Path normalization mismatches will produce false failures; needs path normalization logic |
| A8 | `deny.toml` `date` field in `ignore` entries is a non-enforced string convention | deny.toml | cargo-deny may reject unknown fields in future versions; verify with current 0.19.4 schema |

---

## Open Questions (RESOLVED)

> All three resolved during planning: cluster CIDRs → documented placeholder in 06-05; D-18 compose target → new axiam-server service added to docker-compose.dev.yml in 06-04; trivy-action version → confirmation moved into 06-02 acceptance criteria.

1. **Cluster-specific CIDRs for D-12 NetworkPolicy**
   - What we know: RFC1918 ranges are fixed; cluster pod/service CIDRs vary by deployment.
   - What's unclear: The axiam K8s manifests don't specify the target cluster or its CIDRs.
   - Recommendation: The planner should add placeholder comments in the NetworkPolicy YAML (`# TODO: add cluster pod CIDR e.g. 10.244.0.0/16`) and a task for the operator to fill them in.

2. **Is `docker-compose.dev.yml` intended to run the axiam-server?**
   - What we know: Current `docker-compose.dev.yml` only has surrealdb + rabbitmq services. D-18 requires the server to receive `AXIAM__AUTH__COOKIE_SECURE=false`.
   - What's unclear: Is D-18 targeting `docker-compose.prod.yml` with an env override, or a new dev-server compose file?
   - Recommendation: The planner should add `AXIAM__AUTH__COOKIE_SECURE: "false"` to the existing `docker-compose.prod.yml` server environment block, clearly commented as a dev-only override. Or create a minimal `docker-compose.dev-server.yml` override file.

3. **Trivy action exact version**
   - What we know: v0.36.0 from web search results.
   - What's unclear: Whether a newer version has been released since the search.
   - Recommendation: Verify at https://github.com/aquasecurity/trivy-action/releases before pinning.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|---|---|---|---|---|
| Docker | D-06 release.yml testing | ✓ (CI) | buildx in GHA | — |
| cosign | D-06 signing | ✓ (existing release.yml) | sigstore/cosign-installer | — |
| cargo-deny | CI D-03 | ✓ (via GHA action) | 0.19.4 | — |
| cargo-audit | CI D-01 | ✓ (via GHA action) | 0.22.1 | — |
| npm | D-01 npm vulns | ✓ (existing CI, frontend/) | npm 10.x | — |
| trivy | CI D-05/D-06 | ✓ (via GHA action) | 0.36.0 | — |
| hadolint | CI D-05 | ✓ (via GHA action) | latest stable | — |
| vite-plugin-sri3 | D-17 | ✗ (not yet installed) | 2.0.0 | No fallback needed; install via npm |

---

## Validation Architecture

### Test Framework

| Property | Value |
|---|---|
| Framework | Rust built-in `#[test]`, cargo test |
| Frontend | Playwright (existing) |
| CI framework | GitHub Actions |
| Quick run command | `cargo test -p axiam-api-rest` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|---|---|---|---|---|
| REQ-9 | cargo-audit finds no unfixed vulns | CI gate | `cargo audit` (CI) | ❌ Wave 0: deny.toml |
| REQ-9 | cargo-deny license/vuln policy passes | CI gate | `cargo deny check` (CI) | ❌ Wave 0: deny.toml |
| REQ-9 | npm audit passes at high level | CI gate | `npm audit --audit-level=high` (CI) | ✅ (in package.json) |
| REQ-9 | hadolint passes | CI gate | `hadolint` (CI) | ✅ (Dockerfiles exist) |
| REQ-9 | trivy fs/config finds no HIGH/CRITICAL | CI gate | `trivy fs .` (CI) | ✅ (source exists) |
| REQ-9 | trivy image scan passes before release | Release gate | `trivy image` (release.yml CI) | ❌ Wave 0: release.yml |
| REQ-9 | OpenAPI parity test passes | Unit test | `cargo test -p axiam-api-rest route_openapi_parity` | ❌ Wave 0 |
| REQ-9 | sourcemap: false in production build | Build output check | `npm run build && test ! -f dist/*.map` | ✅ (vite.config.ts) |
| REQ-9 | SRI hashes present in index.html | Build output check | `grep 'integrity="sha' frontend/dist/index.html` | ❌ Wave 0: plugin |
| REQ-10 | Distroless server image starts and /health returns 200 | Smoke | `docker run axiam-server:scan-$SHA axiam-server healthcheck` | ❌ Wave 0 |
| REQ-10 | healthcheck subcommand exits 0 on healthy server | Unit test | `cargo test -p axiam-server healthcheck` | ❌ Wave 0 |
| REQ-10 | K8s PSA restricted fields present in server deployment | Validation | `kubectl apply --dry-run=client` or yamllint check | ✅ (manifests exist) |
| REQ-10 | No inline value: literals for secrets in K8s manifests | Linting | `grep -r 'value:' k8s/ --include='*.yml'` manual check | ✅ (verified in research) |
| REQ-10 | Cookie Secure=false works in dev compose | Integration | Login test over http://localhost | ❌ Wave 0: AuthConfig field |

### Wave 0 Gaps (files that must be created before implementation)

- [ ] `deny.toml` — workspace root; cargo-deny gate depends on it
- [ ] `.github/dependabot.yml` — D-16
- [ ] `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` — D-15
- [ ] `k8s/network-policy/` directory + 4 NetworkPolicy manifests — D-11/D-12
- [ ] `crates/axiam-auth/src/config.rs` cookie_secure field — D-18
- [ ] `crates/axiam-api-rest/src/middleware/csrf.rs` parameterize `.secure()` — D-18
- [ ] Trivy image scan + reorder in `release.yml` — D-06
- [ ] Distroless rewrite of `docker/Dockerfile.server` — D-08
- [ ] `healthcheck` subcommand in `crates/axiam-server/src/` — D-09
- [ ] `vite-plugin-sri3` npm install + `vite.config.ts` update — D-17

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---|---|---|
| V2 Authentication | Indirect | Cookie Secure flag (D-18) — ASVS 3.4.2 |
| V5 Input Validation | No | Not in scope for this phase |
| V10 Malicious Code | Yes | cargo-audit, cargo-deny, npm audit — supply chain protection |
| V14 Configuration | Yes | Distroless, K8s securityContext, PSA, sourcemap:false |
| V14.4 HTTP Security Headers | Partial | SRI (D-17) complements existing CSP/HSTS from Phase 2 |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---|---|---|
| Compromised dependency (supply chain) | Tampering | cargo-audit + cargo-deny + npm audit (REQ-9) |
| Vulnerable OS base in container | Tampering | trivy image scan before publish (D-06) |
| Container escape via root process | Elevation of Privilege | distroless nonroot UID 65532 (D-08) |
| Lateral movement via unrestricted pod egress | Tampering/Info Disclosure | NetworkPolicy default-deny + explicit allows (D-11) |
| Script injection via tampered CDN asset | Tampering | SRI (D-17) — integrity= prevents load if hash mismatch |
| Cookie theft over HTTP in dev | Info Disclosure | D-18 env-gated Secure flag |
| License compliance risk | — | cargo-deny license policy (D-03) |

---

## Sources

### Primary (HIGH confidence)
- npm registry (`npm view vite-plugin-sri3`) — peer deps, version, publish date
- `crates/axiam-api-rest/src/openapi.rs` (read directly) — confirms `pub fn api_doc()`, `ApiDoc`, utoipa paths structure
- `crates/axiam-api-rest/src/permissions.rs` (read directly) — confirms ROUTE_PERMISSION_MAP pattern
- `crates/axiam-api-rest/src/middleware/csrf.rs` (read directly) — confirms `.secure(true)` hardcoded in all three helpers
- `crates/axiam-auth/src/config.rs` (read directly) — confirms no `cookie_secure` field exists
- `docker/Dockerfile.server` (read directly) — confirms xmlsec runtime deps, current debian-slim base
- `k8s/server/deployment.yml`, `k8s/frontend/deployment.yml` (read directly) — confirms securityContext fields present/missing
- crates.io — cargo-deny 0.19.4, cargo-audit 0.22.1

### Secondary (MEDIUM confidence)
- embarkstudios.github.io/cargo-deny — deny.toml schema, advisories.ignore syntax
- kubernetes.io/docs/concepts/services-networking/network-policies/ — NetworkPolicy YAML patterns
- kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/ — PSA label syntax
- kubernetes.io/docs/concepts/security/pod-security-standards/ — restricted profile field list
- GoogleContainerTools/distroless (GitHub search) — cc-debian12 contents, nonroot UID 65532
- packages.debian.org/bookworm/libxmlsec1 — .so file paths

### Tertiary (LOW confidence — verify before use)
- WebSearch result: trivy-action v0.36.0 (verify at github.com/aquasecurity/trivy-action/releases)
- WebSearch result: actions-rust-lang/audit@v1 (verify at github.com/actions-rust-lang/audit)
- WebSearch result: ICU libraries as libxml2 transitive deps (run `ldd` to confirm)

---

## Metadata

**Confidence breakdown:**
- Standard Stack (tooling versions): MEDIUM — core tools confirmed on crates.io/npm; GHA action versions from WebSearch (verify before pinning)
- Architecture (CI wiring pattern): HIGH — derived from reading existing ci.yml/release.yml and Docker docs
- Pitfalls: HIGH — derived from direct codebase reading + known distroless/K8s patterns
- Distroless .so list: MEDIUM-LOW — library paths from Debian packages.debian.org; exact minor versions need ldd verification

**Research date:** 2026-06-04
**Valid until:** 2026-09-04 (90 days — tooling version checks needed if phase is delayed)
