# Phase 6: CI/CD & Infrastructure Hardening — Pattern Map

**Mapped:** 2026-06-04
**Files analyzed:** 21 new/modified files
**Analogs found:** 17 / 21

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `.github/workflows/ci.yml` | config/pipeline | event-driven | `.github/workflows/ci.yml` (self — add jobs) | self-modify |
| `.github/workflows/release.yml` | config/pipeline | event-driven | `.github/workflows/release.yml` (self — reorder) | self-modify |
| `.github/dependabot.yml` | config | — | none (new file) | no analog |
| `deny.toml` | config | — | none (new file) | no analog |
| `docker/Dockerfile.server` | config/container | — | `docker/Dockerfile.server` (self — replace runtime stage) | self-modify |
| `docker/Dockerfile.frontend` | config/container | — | `docker/Dockerfile.server` (same multi-stage shape) | role-match |
| `docker/docker-compose.prod.yml` | config | — | `docker/docker-compose.prod.yml` (self — env var) | self-modify |
| `docker/docker-compose.dev.yml` | config | — | `docker/docker-compose.dev.yml` (self — add server service) | self-modify |
| `k8s/namespace.yml` | config/k8s | — | `k8s/namespace.yml` (self — add PSA labels) | self-modify |
| `k8s/kustomization.yml` | config/k8s | — | `k8s/kustomization.yml` (self — add resources) | self-modify |
| `k8s/server/deployment.yml` | config/k8s | — | `k8s/server/deployment.yml` (self — extend securityContext) | self-modify |
| `k8s/frontend/deployment.yml` | config/k8s | — | `k8s/frontend/deployment.yml` (self — extend securityContext) | self-modify |
| `k8s/surrealdb/statefulset.yml` | config/k8s | — | `k8s/surrealdb/statefulset.yml` (self — add securityContext) | self-modify |
| `k8s/rabbitmq/statefulset.yml` | config/k8s | — | `k8s/surrealdb/statefulset.yml` (same StatefulSet shape) | role-match |
| `k8s/network-policy/*.yml` (4 files) | config/k8s | — | none (new directory) | no analog |
| `frontend/vite.config.ts` | config/build | — | `frontend/vite.config.ts` (self — add plugin + build opts) | self-modify |
| `frontend/package.json` | config | — | `frontend/package.json` (self — add license field) | self-modify |
| `Cargo.toml` | config | — | `Cargo.toml` (self — fix license field line 23) | self-modify |
| `crates/axiam-auth/src/config.rs` | config/model | — | `crates/axiam-auth/src/config.rs` (self — add field) | self-modify |
| `crates/axiam-api-rest/src/middleware/csrf.rs` | middleware | request-response | `crates/axiam-api-rest/src/middleware/csrf.rs` (self — parameterize) | self-modify |
| `crates/axiam-server/src/main.rs` | service/CLI | request-response | `crates/axiam-server/src/main.rs` (self — add subcommand) | self-modify |
| `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` | test | — | `crates/axiam-api-rest/src/middleware/authz.rs` tests + `permissions.rs` | role-match |

---

## Pattern Assignments

### `.github/workflows/ci.yml` — add `security-scan` job (D-05, D-07)

**Analog:** `.github/workflows/ci.yml` (existing job structure)

**Existing job shape to copy** (lines 17–26, 28–37, 39–47):
```yaml
  fmt:
    name: Rustfmt
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --all -- --check
```

Key conventions from the existing file:
- `permissions: contents: read` at top-level (line 9)
- `env: CARGO_TERM_COLOR: always` + `RUSTFLAGS: "-Dwarnings"` (lines 12–14)
- Cache: `uses: Swatinem/rust-cache@v2` (line 35, 45)
- Apt deps: `sudo apt-get update && sudo apt-get install -y protobuf-compiler` (line 36, 46)
- No `needs:` on independent jobs — they run in parallel (fmt, clippy, build are all independent)

**New job must add `security-events: write`** permission for `codeql-action/upload-sarif`:
```yaml
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: sudo apt-get update && sudo apt-get install -y protobuf-compiler libxmlsec1-dev libxml2-dev
```

**CRITICAL:** The `build-no-saml` guard (lines 49–63) must NOT be broken. The security-scan job can build with SAML ON (full deps) since it is a separate job, not the no-saml path.

---

### `.github/workflows/release.yml` — reorder build→scan→push→sign (D-06)

**Analog:** `.github/workflows/release.yml` (self — current `build-server` job, lines 19–67)

**Current pattern to replace** (lines 47–61) — `build-push-action` with immediate push:
```yaml
      - name: Build and push
        id: build
        uses: docker/build-push-action@v6
        with:
          context: .
          file: docker/Dockerfile.server
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign image with cosign
        run: cosign sign --yes ${{ env.REGISTRY }}/${{ github.repository }}/server@${{ steps.build.outputs.digest }}
```

**New pattern** — split into load→scan→push (three steps replacing one, then sign using pushed digest):
```yaml
      # Step 1: build locally (no push) for scanning
      - name: Build image (scan target)
        id: build-local
        uses: docker/build-push-action@v6
        with:
          context: .
          file: docker/Dockerfile.server
          load: true
          tags: axiam-server:scan-${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      # Step 2: scan — block on HIGH/CRITICAL unfixed
      - name: Trivy image scan
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          scan-type: image
          image-ref: axiam-server:scan-${{ github.sha }}
          severity: HIGH,CRITICAL
          ignore-unfixed: true
          exit-code: 1
          format: sarif
          output: trivy-image.sarif

      - name: Upload image scan SARIF
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: trivy-image.sarif
          category: trivy-image-server

      # Step 3: push (uses GHA cache from Step 1 → same layers → same digest)
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
```

`job.permissions` must add `security-events: write` (currently only `contents/packages/id-token/attestations`).

---

### `docker/Dockerfile.server` — distroless runtime + healthcheck subcommand (D-08, D-09, D-04)

**Analog:** `docker/Dockerfile.server` (self)

**Builder stage** (lines 11–70) — keep exactly as-is. The `FROM rust:1.94-bookworm@sha256:...` digest pin, skeleton trick, and `cargo build --release -p axiam-server` are correct.

**Runtime stage to replace** (lines 75–118):

Current runtime base (line 75):
```dockerfile
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb AS runtime
```
Replace with:
```dockerfile
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:<PIN>
```

Current label with wrong license (line 81):
```dockerfile
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
```
Replace with:
```dockerfile
      org.opencontainers.image.licenses="Apache-2.0"
```

Current runtime apt-install + user creation block (lines 87–98) — **remove entirely** (distroless has no apt, nonroot user is built in as UID 65532).

Current binary COPY (lines 101–102):
```dockerfile
COPY --from=builder --chown=axiam:axiam \
    /build/target/release/axiam-server /usr/local/bin/axiam-server
```
Replace with (distroless nonroot UID 65532):
```dockerfile
COPY --from=builder --chown=65532:65532 \
    /build/target/release/axiam-server /usr/local/bin/axiam-server
```

SAML .so files — insert before the binary COPY (distroless has no apt, must copy from builder):
```dockerfile
# xmlsec1 + dependencies (verify exact minor versions with ldd at build time)
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1.so.1        /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so.1 /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libxml2.so.2            /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libltdl.so.7            /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/liblzma.so.5            /usr/lib/x86_64-linux-gnu/
# ICU libs (libxml2 transitive) — verify with ldd before finalizing
COPY --from=builder /usr/lib/x86_64-linux-gnu/libicuuc.so.72          /usr/lib/x86_64-linux-gnu/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libicudata.so.72        /usr/lib/x86_64-linux-gnu/
```

Current USER (line 105): `USER axiam` → `USER nonroot` (distroless UID 65532 maps to username "nonroot")

Current HEALTHCHECK (lines 115–116) — replace curl with healthcheck subcommand:
```dockerfile
# D-09: no curl in distroless; axiam-server healthcheck self-probes /health
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/axiam-server", "healthcheck"]
```

Current ENTRYPOINT (line 118): `ENTRYPOINT ["axiam-server"]` → use absolute path:
```dockerfile
ENTRYPOINT ["/usr/local/bin/axiam-server"]
```

---

### `docker/Dockerfile.frontend` — digest-pin base images, fix license label (D-10, D-04)

**Analog:** `docker/Dockerfile.frontend` (self, lines 11–45)

Current builder base (line 11):
```dockerfile
FROM node:24-alpine AS builder
```
Pin by digest:
```dockerfile
FROM node:24-alpine@sha256:<PIN> AS builder
```

Current runtime base (line 29):
```dockerfile
FROM nginxinc/nginx-unprivileged:1.29-alpine
```
Pin by digest:
```dockerfile
FROM nginxinc/nginx-unprivileged:1.29-alpine@sha256:<PIN>
```

Current wrong license label (line 43):
```dockerfile
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
```
Replace with:
```dockerfile
      org.opencontainers.image.licenses="Apache-2.0"
```

---

### `docker/docker-compose.prod.yml` — cookie Secure flag env override (D-18)

**Analog:** `docker/docker-compose.prod.yml` (self, lines 26–43 environment block)

Current environment block pattern (lines 26–43):
```yaml
    environment:
      AXIAM__DB__URL: "surrealdb:8000"
      AXIAM__AUTH__JWT_PRIVATE_KEY_PEM: "${AXIAM__AUTH__JWT_PRIVATE_KEY_PEM:?...}"
      RUST_LOG: "${RUST_LOG:-axiam=info}"
```

Add at end of environment block:
```yaml
      # D-18: Set to "false" for local HTTP dev to allow cookies without Secure flag.
      # Default in code is true (prod-safe). Never set false in real production.
      AXIAM__AUTH__COOKIE_SECURE: "${AXIAM__AUTH__COOKIE_SECURE:-true}"
```

Also update the healthcheck (line 50) — switch from curl to healthcheck subcommand:
```yaml
    healthcheck:
      test: ["CMD", "/usr/local/bin/axiam-server", "healthcheck"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
```

---

### `crates/axiam-auth/src/config.rs` — add `cookie_secure` field (D-18)

**Analog:** `crates/axiam-auth/src/config.rs` (self — mirror existing `allow_missing_aud_as_user` pattern)

Existing `default_true()` helper already at line 5:
```rust
fn default_true() -> bool {
    true
}
```

Existing field using it (lines 44–46):
```rust
    /// When `true`, access tokens decoded without an `aud` claim are treated as
    /// `axiam:user`. ...
    #[serde(default = "default_true")]
    pub allow_missing_aud_as_user: bool,
```

New field to add after `allow_missing_aud_as_user` (same pattern):
```rust
    /// When `false`, cookies are served without the Secure flag.
    /// ONLY set to false in local HTTP development (docker-compose.prod.yml with override).
    /// Default: `true`. Controlled via `AXIAM__AUTH__COOKIE_SECURE`.
    #[serde(default = "default_true")]
    pub cookie_secure: bool,
```

Add `cookie_secure: true` in the `Default` impl (lines 90–117) next to `allow_missing_aud_as_user: true`.

---

### `crates/axiam-api-rest/src/middleware/csrf.rs` — parameterize `.secure()` (D-18)

**Analog:** `crates/axiam-api-rest/src/middleware/csrf.rs` (self — three cookie helpers, lines 190–227)

Current signature pattern:
```rust
pub fn access_cookie(token: &str, max_age_secs: u64) -> Cookie<'static> {
    Cookie::build(COOKIE_ACCESS, token.to_owned())
        .http_only(true)
        .secure(true)                // ← hardcoded
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(max_age_secs as i64))
        .finish()
}
```

New signature pattern (add `cookie_secure: bool` parameter, replace `.secure(true)` with `.secure(cookie_secure)`):
```rust
pub fn access_cookie(token: &str, max_age_secs: u64, cookie_secure: bool) -> Cookie<'static> {
    Cookie::build(COOKIE_ACCESS, token.to_owned())
        .http_only(true)
        .secure(cookie_secure)       // ← from config
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(max_age_secs as i64))
        .finish()
}
```

Apply same change to `refresh_cookie` (line 203) and `csrf_cookie` (line 219). All call-sites passing `config.auth.cookie_secure` must be updated (search for `access_cookie(`, `refresh_cookie(`, `csrf_cookie(` in `crates/axiam-api-rest/src/handlers/`).

---

### `crates/axiam-server/src/main.rs` — add `healthcheck` subcommand (D-09)

**Analog:** `crates/axiam-server/src/main.rs` (self — lines 77–end, `#[tokio::main]` entry point)

Current main has no CLI arg parsing (no clap). The healthcheck subcommand can be added with a minimal `std::env::args()` check before the async runtime starts:

```rust
#[tokio::main]
async fn main() -> std::io::Result<()> {
    // D-09: healthcheck subcommand — self-probe /health, exit 0/1
    // Must run before tracing init and before the full async stack spins up.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("healthcheck") {
        let url = std::env::var("AXIAM_HEALTHCHECK_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8090/health".to_owned());
        let status = reqwest::blocking::get(&url)
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        std::process::exit(if status { 0 } else { 1 });
    }
    // ... rest of existing main() unchanged
```

`reqwest` is already in `crates/axiam-server/Cargo.toml` (line 34). Need to add `blocking` feature to reqwest workspace dep or use `reqwest::blocking` (check if `blocking` feature is enabled — workspace Cargo.toml line 71 shows `features = ["json", "rustls-tls"]`; add `"blocking"` to the server-specific dep or override).

Alternatively use `std::net::TcpStream` + raw HTTP for zero-extra-dependency probe:
```rust
use std::net::TcpStream;
use std::io::{Write, Read};
// ... raw HTTP GET to 127.0.0.1:8090, check for "200 OK" in response
```

---

### `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` — parity test (D-15)

**Analog:** `crates/axiam-api-rest/src/middleware/authz.rs` tests (lines 143–177) + `permissions.rs` (lines 188–400)

**Existing parity precedent** — `authz.rs` tests verify `PUBLIC_PATHS` entries against known path strings at lines 147–176. The same pattern (iterate a static list, assert membership) is used here for OpenAPI path keys.

**Key APIs confirmed in the codebase:**
- `crates/axiam-api-rest/src/openapi.rs` line 402: `pub fn api_doc() -> utoipa::openapi::OpenApi`
- `permissions.rs` line 188: `pub const PUBLIC_PATHS: &[&str]`
- `permissions.rs` line 252: `pub const ROUTE_PERMISSION_MAP: &[(&str, &str, &str)]` (METHOD, path, permission)
- utoipa `OpenApi` exposes paths as `spec.paths.paths: BTreeMap<String, PathItem>`

**Test file location:** `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs`

Must also add `mod tests;` to `crates/axiam-api-rest/src/lib.rs` or use `#[cfg(test)] mod tests` convention. Check how existing test modules are declared in the crate (the authz.rs tests are inline; a separate file needs a module declaration in `lib.rs` or a `tests/` integration test).

**Test structure pattern** (mirroring authz.rs inline test style):
```rust
#[cfg(test)]
mod route_openapi_parity_tests {
    use crate::openapi::api_doc;
    use crate::permissions::{PUBLIC_PATHS, ROUTE_PERMISSION_MAP};

    // Every ROUTE_PERMISSION_MAP entry must appear in the OpenAPI spec
    #[test]
    fn every_authed_route_is_in_openapi() {
        let spec = api_doc();
        let openapi_paths: std::collections::HashSet<String> =
            spec.paths.paths.keys().cloned().collect();

        let missing: Vec<_> = ROUTE_PERMISSION_MAP
            .iter()
            .filter(|(_, path, _)| !openapi_paths.contains(*path))
            .collect();

        assert!(
            missing.is_empty(),
            "Routes in ROUTE_PERMISSION_MAP missing from OpenAPI spec:\n{missing:#?}"
        );
    }

    // Every OpenAPI path must be in ROUTE_PERMISSION_MAP or PUBLIC_PATHS
    #[test]
    fn every_openapi_path_is_registered() {
        let spec = api_doc();
        let authed: std::collections::HashSet<&str> =
            ROUTE_PERMISSION_MAP.iter().map(|(_, p, _)| *p).collect();
        let public: std::collections::HashSet<&str> = PUBLIC_PATHS.iter().copied().collect();

        let missing: Vec<_> = spec
            .paths
            .paths
            .keys()
            .filter(|p| !authed.contains(p.as_str()) && !public.contains(p.as_str()))
            .collect();

        assert!(
            missing.is_empty(),
            "OpenAPI paths not in ROUTE_PERMISSION_MAP or PUBLIC_PATHS:\n{missing:#?}"
        );
    }
}
```

**Path normalization caveat:** `PUBLIC_PATHS` uses `*` suffix for prefix entries (e.g. `/api/docs/*`). utoipa keys use exact templates (e.g. `/api/docs/openapi.json`). The second test must handle this: strip `*` from PUBLIC_PATHS and use `starts_with` matching, or exclude the `/api/docs/` subtree explicitly.

**SAML feature gate:** Wrap SAML-path assertions with `#[cfg(feature = "saml")]` — consistent with `openapi.rs` line 404.

---

### `k8s/namespace.yml` — PSA labels (D-13)

**Analog:** `k8s/namespace.yml` (self — currently 7 lines, add labels)

Current labels block:
```yaml
metadata:
  name: axiam
  labels:
    app: axiam
```

Add PSA labels:
```yaml
metadata:
  name: axiam
  labels:
    app: axiam
    # D-13: Pod Security Standards — warn+audit at restricted (enforce deferred)
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.29
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.29
```

---

### `k8s/server/deployment.yml` — extend securityContext (D-13)

**Analog:** `k8s/server/deployment.yml` (self — securityContext at lines 55–58)

Current securityContext:
```yaml
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            readOnlyRootFilesystem: true
```

Extended securityContext (restricted profile requires 3 additional fields; also update `runAsUser` after D-08 distroless migration sets UID to 65532):
```yaml
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532          # distroless/cc-debian12:nonroot UID (D-08)
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false   # ADD (D-13)
            capabilities:
              drop:
                - ALL                 # ADD (D-13)
            seccompProfile:
              type: RuntimeDefault    # ADD (D-13)
```

---

### `k8s/frontend/deployment.yml` — extend securityContext (D-13)

**Analog:** `k8s/frontend/deployment.yml` (self — securityContext at lines 47–50)

Current securityContext:
```yaml
          securityContext:
            runAsNonRoot: true
            runAsUser: 101
            runAsGroup: 101
```

Extended:
```yaml
          securityContext:
            runAsNonRoot: true
            runAsUser: 101
            runAsGroup: 101
            readOnlyRootFilesystem: true      # ADD (verify nginx-unprivileged supports this)
            allowPrivilegeEscalation: false   # ADD (D-13)
            capabilities:
              drop:
                - ALL                 # ADD (D-13)
            seccompProfile:
              type: RuntimeDefault    # ADD (D-13)
```

**Note:** nginx-unprivileged needs `/tmp` and `/var/cache/nginx` writable. If `readOnlyRootFilesystem: true` causes nginx to fail, add `emptyDir` volume mounts for those paths.

---

### `k8s/surrealdb/statefulset.yml` — best-effort securityContext (D-13, D-14)

**Analog:** `k8s/surrealdb/statefulset.yml` (self — no securityContext currently, lines 21–69)

Current state: no securityContext. secretKeyRef already used correctly (lines 36–45). D-14 verified — no inline `value:` secrets.

Add securityContext after `image:` + `command:` + `args:` block:
```yaml
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532          # surrealdb/surrealdb:v3 nonroot UID
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
            seccompProfile:
              type: RuntimeDefault
```

**Note:** If the surrealdb image requires root for volume permissions, add an `initContainer` (the `docker-compose.dev.yml` already shows this pattern — `surrealdb-init` with `chown -R 65532:65532`).

---

### `k8s/network-policy/*.yml` (4 new files) — D-11, D-12

**No existing analog** in the codebase. Patterns come from RESEARCH.md.

Files to create in `k8s/network-policy/`:
1. `default-deny.yml` — default-deny ingress+egress for all pods
2. `allow-dns-egress.yml` — UDP/TCP 53 to kube-system (all pods)
3. `server-egress.yml` — server→surrealdb:8000, server→rabbitmq:5672, TCP/443 external excluding RFC1918
4. `allow-ingress-to-server.yml` — ingress-nginx namespace → server:8090
5. `allow-ingress-to-frontend.yml` — ingress-nginx namespace → frontend:8080

Existing `k8s/kustomization.yml` (lines 9–25) shows resource list pattern. Add NetworkPolicy entries:
```yaml
  - network-policy/default-deny.yml
  - network-policy/allow-dns-egress.yml
  - network-policy/server-egress.yml
  - network-policy/allow-ingress-to-server.yml
  - network-policy/allow-ingress-to-frontend.yml
```

Pod labels for selectors — confirmed from existing manifests:
- server pods: `component: server` (deployment.yml line 8)
- frontend pods: `component: frontend` (frontend/deployment.yml line 8)
- surrealdb pods: `component: surrealdb` (surrealdb/statefulset.yml line 8)
- rabbitmq pods: `component: rabbitmq` (rabbitmq/statefulset.yml — expected same pattern)

---

### `frontend/vite.config.ts` — sourcemap:false + SRI plugin (D-17)

**Analog:** `frontend/vite.config.ts` (self — current 29 lines)

Current config:
```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: { /* existing proxy config — do not change */ },
  },
});
```

Add import + plugin + build section:
```typescript
import sri from "vite-plugin-sri3";

export default defineConfig({
  plugins: [react(), sri()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  build: {
    sourcemap: false,   // D-17: never expose source maps in production
  },
  server: {
    proxy: { /* unchanged */ },
  },
});
```

`vite-plugin-sri3@2.0.0` must be added to `frontend/package.json` devDependencies via `npm install --save-dev vite-plugin-sri3@2.0.0`.

---

## Shared Patterns

### Serde `default_true` pattern for config booleans
**Source:** `crates/axiam-auth/src/config.rs` lines 5–7, 44–46
**Apply to:** New `cookie_secure` field in AuthConfig
```rust
fn default_true() -> bool { true }
// ...
#[serde(default = "default_true")]
pub field_name: bool,
```

### Parity test pattern (two-direction cross-check)
**Source:** `crates/axiam-api-rest/src/middleware/authz.rs` lines 143–177 (PUBLIC_PATHS tests) + `permissions.rs` lines 252+ (ROUTE_PERMISSION_MAP)
**Apply to:** `route_openapi_parity_test.rs`
Pattern: two `#[test]` functions — one checks A⊆B, one checks B⊆A. Collect into `HashSet`, filter mismatches, assert on empty `Vec`. Error message prints the missing entries with `{missing:#?}`.

### K8s restricted securityContext (three missing fields)
**Source:** RESEARCH.md (kubernetes.io/docs)
**Apply to:** `k8s/server/deployment.yml`, `k8s/frontend/deployment.yml`, `k8s/surrealdb/statefulset.yml`, `k8s/rabbitmq/statefulset.yml`
```yaml
securityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
```

### GHA job permissions for SARIF upload
**Apply to:** All scan jobs in `ci.yml` and `release.yml`
```yaml
permissions:
  contents: read
  security-events: write
```

### Digest-pinned FROM in Dockerfiles
**Source:** `docker/Dockerfile.server` line 11 (already pinned builder: `@sha256:6ae102...`)
**Apply to:** New distroless runtime base + `Dockerfile.frontend` bases
Pattern: `FROM image:tag@sha256:<64-char-hex>` — tag for human readability, digest for reproducibility.

---

## License Fix Locations (D-04)

Three hardcoded wrong license strings that MUST be changed to `Apache-2.0`:
1. `Cargo.toml` line 23: `license = "AGPL-3.0-or-later"` → `license = "Apache-2.0"`
2. `docker/Dockerfile.server` line 81: `org.opencontainers.image.licenses="AGPL-3.0-or-later"` → `"Apache-2.0"`
3. `docker/Dockerfile.frontend` line 43: same label, same fix
4. `frontend/package.json`: add `"license": "Apache-2.0"` (field absent entirely)

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `.github/dependabot.yml` | config | — | No existing dependabot config; RESEARCH.md has the full template |
| `deny.toml` | config | — | No cargo-deny config exists; RESEARCH.md has the full template with advisories/licenses/bans/sources sections |
| `k8s/network-policy/*.yml` | config/k8s | — | No NetworkPolicy manifests in repo; RESEARCH.md has all 4 YAML templates |

---

## Metadata

**Analog search scope:** `.github/workflows/`, `docker/`, `k8s/`, `crates/axiam-auth/`, `crates/axiam-api-rest/`, `crates/axiam-server/`, `frontend/`
**Files read:** 16
**Pattern extraction date:** 2026-06-04

---

## PATTERN MAPPING COMPLETE

**Phase:** 6 - CI/CD & Infrastructure Hardening
**Files classified:** 22
**Analogs found:** 18 / 22 (4 new files with no codebase analog — use RESEARCH.md templates)

### Coverage
- Files with self-modify analog: 15
- Files with role-match analog: 3
- Files with no analog (new): 4

### Key Patterns Identified
- All K8s workloads use `component: <name>` label — NetworkPolicy selectors must use this label
- `AuthConfig` uses `fn default_true()` + `#[serde(default = "default_true")]` for boolean flags with prod-safe defaults — `cookie_secure` follows this exact pattern
- Parity tests use two-direction HashSet comparison with `assert!(missing.is_empty(), "{missing:#?}")` — route↔openapi test mirrors this
- Dockerfiles are multi-stage with digest-pinned FROM; server builder already correct — only runtime stage needs replacement
- CI jobs are independent (no `needs:`), parallel — `security-scan` job follows this; `build-no-saml` guard must not be touched
- `release.yml` build-push-action currently single-step push — reorder to load→scan→push→sign requires splitting one step into three with GHA cache for digest consistency
