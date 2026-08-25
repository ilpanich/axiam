import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "path";
import { sri } from "vite-plugin-sri3";

// `@axiam/opaque-wasm` is built from `crates/axiam-opaque-wasm` **in this
// repository**, not installed from npm, and resolved here rather than through
// `package.json`.
//
// It is the same first-party artifact `axiam-server` gets through a workspace
// path dependency, and it is resolved the same way for the same reason: a fix
// to `crates/axiam-opaque` — the OPAQUE (RFC 9807) core, i.e. the cryptography
// — must reach the admin UI in the next build, with no version to bump and no
// release to wait on. An npm dependency could not offer that: the wasm is baked
// into the frontend image at build time, so whatever version the pin named is
// what every deployment of that image executes until it is rebuilt. There is no
// "next install" for an operator running a published tag. (The npm package
// still exists and is still published — the TypeScript SDK and third-party
// consumers need it. Only the admin UI stops going through it.)
//
// `just build-opaque-wasm` produces the directory below; the `wasm` stage of
// `docker/Dockerfile.frontend` always does. When it is absent the alias falls
// back to a stub that fails to instantiate, which `lib/opaque.ts` already
// degrades on (`opaqueAvailable() === false`) — so a checkout with no Rust
// toolchain still builds and tests the admin UI, it just cannot do OPAQUE.
//
// Types come from `src/types/opaque-wasm.d.ts` instead of from whichever of the
// two this resolves to: `tsc` has no equivalent of this conditional, and an
// ambient declaration is true of both.
const OPAQUE_WASM_DIR = path.resolve(__dirname, "vendor/opaque-wasm");
const opaqueWasmEntry = path.join(OPAQUE_WASM_DIR, "axiam_opaque.js");
const opaqueWasmAlias = fs.existsSync(opaqueWasmEntry)
  ? opaqueWasmEntry
  : path.resolve(__dirname, "src/lib/opaqueUnavailable.ts");

// The frontend talks to the backend at RELATIVE paths (see src/lib/api.ts:
// `baseURL: "/"`), so both the dev server (`vite`) and the preview server
// (`vite preview`, used by the CI E2E job to serve the production `dist`
// build) must proxy the real backend routes to the AXIAM server on :8090.
// Without the preview proxy the browser's /api and /auth/login calls hit the
// static file server instead of the backend and every authenticated page
// bounces back to /login (the E2E suite then fails on login timeouts).
const backendProxy = {
  "/api": "http://localhost:8090",
  // Proxy only actual backend auth endpoints; exclude frontend-only SPA pages
  // (/auth/forgot-password, /auth/reset-password, /auth/verify-email are SPA routes)
  "^/auth/(login|logout|refresh|register|change-password|resend-verification|mfa)": {
    target: "http://localhost:8090",
    rewrite: (path: string) => path,
  },
  // Use regex to match /oauth2/ and /oauth2? but NOT /oauth2-clients (frontend route)
  "^/oauth2(/|\\?|$)": {
    target: "http://localhost:8090",
    rewrite: (path: string) => path,
  },
};

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), sri()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      "@axiam/opaque-wasm": opaqueWasmAlias,
    },
  },
  // The built package lives outside `frontend/`'s root only in the sense that
  // it is generated, not checked in; `vendor/` is inside the root, so no
  // `server.fs.allow` entry is needed. Excluded from dep pre-bundling because
  // esbuild would rewrite the `new URL('…_bg.wasm', import.meta.url)` the
  // wasm-pack glue uses to locate its payload, and the dev server would then
  // 404 on the wasm.
  optimizeDeps: {
    exclude: ["@axiam/opaque-wasm"],
  },
  build: {
    // D-17: Never expose source maps in production builds (T-06-14).
    sourcemap: false,
  },
  server: {
    proxy: backendProxy,
  },
  // `vite preview` serves the built `dist/` (production bundle) with SPA
  // history fallback AND honours this proxy — so the CI E2E job can exercise
  // the real production build while still reaching the backend on :8090.
  preview: {
    proxy: backendProxy,
  },
});
