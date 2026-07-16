import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The AXIAM public website is a self-contained static single-page app with no
// backend dependency — it renders marketing, docs, benchmarks, roadmap and
// news entirely client-side. It is intentionally separate from `frontend/`
// (the authenticated admin SPA).
//
// Served from a GitHub Pages project site at https://ilpanich.github.io/axiam/,
// so every asset URL must be prefixed with the repository path.
// https://vite.dev/config/
export default defineConfig({
  base: "/axiam/",
  plugins: [react()],
  build: {
    sourcemap: false,
  },
});
