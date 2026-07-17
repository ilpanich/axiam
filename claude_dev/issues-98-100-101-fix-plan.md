# Fix Plan — Issues #98, #100, #101 (Compliance Findings F-02, F-04, F-05)

**Date:** 2026-07-17
**Validated against:** `main` @ `dd7128f` (1.0.0-alpha8)
**Verdict: all three issues are still valid.** None has been fixed since the Phase 7,
Plan 05 audit (2026-06-07). Details and per-issue fix plans below, ordered by severity.

| Issue | Finding | Severity | Still valid? | Effort |
|-------|---------|----------|--------------|--------|
| [#101](https://github.com/ilpanich/axiam/issues/101) | F-05 — CSP header not set by REST API | Medium | **Yes** (partially — frontend half already fixed) | Small |
| [#100](https://github.com/ilpanich/axiam/issues/100) | F-04 — TLS 1.3 minimum not enforced | Low | **Yes** (situation is slightly different from the issue text) | Medium |
| [#98](https://github.com/ilpanich/axiam/issues/98) | F-02 — Playwright e2e files not in tsconfig | Info | **Yes** | Trivial |

---

## Issue #101 — Content-Security-Policy header not set (ASVS V14.4.4, Medium)

### Current state

- `crates/axiam-api-rest/src/middleware/security_headers.rs` still sets only
  `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` — **no CSP**
  (confirmed, lines 56–75).
- The **frontend half of the suggested fix is already done**: `docker/nginx.conf`
  sets a strict CSP (`default-src 'self'; script-src 'self'; style-src 'self'
  'unsafe-inline'; …; frame-ancestors 'none'`) in the server block and re-adds it
  in both `location` blocks (lines 26, 40, 52). No action needed on the frontend.
- Remaining gap: responses served directly by the Rust REST API carry no CSP.
  This matters for direct-exposure deployments and for the **Swagger UI** pages the
  API itself serves at `/api/docs/` (`crates/axiam-api-rest/src/server.rs:52`) —
  the API is *not* JSON-only, contrary to the issue text.

### Fix plan

1. In `SecurityHeadersMiddleware::call`, add:
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'
   ```
   Rationale: strictly `default-src 'none'` would be ideal for pure-JSON endpoints,
   but the same middleware also covers Swagger UI, which needs same-origin scripts,
   inline styles, and `data:` images (favicon/logo). Mirroring the nginx policy keeps
   one consistent policy and keeps `/api/docs/` working.
2. Update the module doc comment (header list at top of `security_headers.rs`).
3. Tests:
   - Extend the middleware unit/integration test (see existing tests in
     `crates/axiam-api-rest/tests/`) to assert the CSP header value on a JSON
     endpoint response.
   - Manual/e2e verification that Swagger UI at `/api/docs/` still renders with the
     CSP applied (no console CSP violations). If Swagger UI 5.x needs an extra
     directive, relax only what is required and document it.
4. Update `docs/compliance/FINDINGS.md` (F-05 → Resolved) and
   `docs/compliance/asvs-l2-checklist.md` V14.4.4 (Deferred → Pass).

**Build note:** any build/test of `axiam-api-rest` requires
`export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`
in this sandbox (see CLAUDE.md).

---

## Issue #100 — TLS 1.3 minimum not enforced in rustls config (ASVS V9.1.2/V9.1.3, Low)

### Current state

The issue is still valid, but the reality is slightly **worse than described**: the
server does not merely "default to TLS 1.2+" — it has **no TLS support at all**.

- No crate in the workspace depends on `rustls` (checked all `Cargo.toml`s).
- `crates/axiam-server/src/main.rs:951` binds plain HTTP (`.bind(&bind_addr)`);
  the gRPC listener is likewise plaintext.
- `ServerConfig` (`crates/axiam-api-rest/src/config/mod.rs:12`) has only
  `host`/`port` — no cert/key fields.
- TLS is therefore *only* achievable via the proxy layer (the documented pattern),
  and "TLS 1.3 minimum" is currently unenforceable in any direct-TLS deployment
  because direct TLS does not exist.

### Fix plan

1. **Add an optional direct-TLS path (TLS 1.3 only):**
   - Extend `ServerConfig` with an optional `tls` section:
     `{ enabled: bool, cert_path: PathBuf, key_path: PathBuf }` (default: disabled,
     preserving current behavior and the proxy-termination pattern).
   - Add deps to `axiam-server`: `rustls` (ring provider) and `rustls-pemfile`;
     enable the matching `actix-web` rustls feature (e.g. `rustls-0_23`).
   - In `main.rs`, when `tls.enabled`, build a
     `rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])`
     with the loaded cert chain + private key, and use
     `.bind_rustls_0_23(&bind_addr, tls_config)` instead of `.bind(...)`.
     Cipher suites then need no manual filtering — TLS 1.3 suites are all
     ASVS-approved (satisfies V9.1.3).
   - Fail fast with a clear error if `tls.enabled` but cert/key are missing/unreadable.
2. **gRPC (optional, follow-up):** apply the same pattern via tonic's
   `ServerTlsConfig` if direct-TLS parity is wanted for the gRPC listener; otherwise
   explicitly document proxy termination as the supported pattern for gRPC.
3. **Documentation:** state both supported patterns — (a) proxy-terminated TLS
   (recommended; proxy must be configured for TLS 1.3 min) and (b) direct TLS via
   the new config (TLS 1.3 enforced in code). Include a sample nginx/Caddy snippet
   with `ssl_protocols TLSv1.3;`.
4. **Tests:** unit test for config parsing/validation of the `tls` section; an
   integration smoke test that a TLS 1.2 `ClientHello` is rejected when direct TLS
   is enabled (can be done with a rustls client pinned to TLS 1.2).
5. Update `docs/compliance/FINDINGS.md` (F-04 → Resolved) and
   `docs/compliance/asvs-l2-checklist.md` V9.1.2/V9.1.3 (Deferred → Pass).

---

## Issue #98 — Playwright e2e files not in tsconfig includes (Info, IDE-only)

### Current state

Still valid, exactly as described:

- `frontend/e2e/tsconfig.json` does not exist.
- `frontend/tsconfig.app.json` includes only `src`; `frontend/tsconfig.node.json`
  includes only `vite.config.ts` — so **both** `e2e/*.spec.ts` (15 spec files +
  `helpers/`) and `playwright.config.ts` fall outside every project and the IDE
  resolves them with an inferred project without Node types →
  "Cannot find name 'process'".
- `@types/node` is installed (`frontend/package.json`, devDep `^26.1.1`).
- Confirmed `process.env` usage in `playwright.config.ts` and multiple specs.

### Fix plan

1. Create `frontend/e2e/tsconfig.json` covering the spec files:
   ```json
   {
     "compilerOptions": {
       "target": "ES2023",
       "lib": ["ES2023", "DOM"],
       "module": "ESNext",
       "moduleResolution": "bundler",
       "types": ["node"],
       "strict": true,
       "noEmit": true,
       "skipLibCheck": true
     },
     "include": ["./**/*.ts"]
   }
   ```
   (`DOM` lib is needed because specs pass callbacks to `page.evaluate` etc.)
2. Add `"playwright.config.ts"` to the `include` array of
   `frontend/tsconfig.node.json` (it already has `"types": ["node"]`), fixing the
   config file itself.
3. Verification: `npx tsc -p frontend/e2e/tsconfig.json --noEmit` passes, and
   `npm run build` / existing CI type-check remains green (the new tsconfig is not
   referenced from the root `tsconfig.json`, so build behavior is unchanged).
4. Update `docs/compliance/FINDINGS.md` (F-02 → Resolved).

---

## Suggested execution order

1. **#98** — trivial, zero-risk, frontend-only.
2. **#101** — small middleware change + test; verify Swagger UI manually.
3. **#100** — the only change with real design surface (new config section + deps);
   do it last and keep direct TLS opt-in so existing deployments are untouched.

Each fix should update `docs/compliance/FINDINGS.md` / `asvs-l2-checklist.md` in the
same commit, and per repo guidelines the issues are closed only after the PR merges.
