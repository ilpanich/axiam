import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import { sri } from "vite-plugin-sri3";

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
    proxy: {
      "/api": "http://localhost:8080",
      // Proxy only actual backend auth endpoints; exclude frontend-only SPA pages
      // (/auth/forgot-password, /auth/reset-password, /auth/verify-email are SPA routes)
      "^/auth/(login|logout|refresh|register|change-password|resend-verification|mfa)": {
        target: "http://localhost:8080",
        rewrite: (path) => path,
      },
      // Use regex to match /oauth2/ and /oauth2? but NOT /oauth2-clients (frontend route)
      "^/oauth2(/|\\?|$)": {
        target: "http://localhost:8080",
        rewrite: (path) => path,
      },
    },
  },
});
