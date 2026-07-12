import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { sri } from "vite-plugin-sri3";

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
    },
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
