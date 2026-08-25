import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    coverage: {
      // Ratcheted per R5.9 (achieved - 2): a LOCAL `npx vitest run --coverage`
      // on 2026-08-15 measured 94.41% line coverage (3857/4085 lines, 808
      // tests, 67 files). Re-ratchet upward as coverage improves; this is
      // the first floor this file has ever had.
      //
      // That 94.41% was never confirmed from a CI run, because the coverage
      // job passed `--coverage.reporter=lcov` alone, which replaces vitest's
      // text reporter — the job's own achieved percentage appeared nowhere in
      // its log. The job now also emits `text-summary` onto the run summary
      // page, so the NEXT ratchet can use a number CI has printed rather than
      // one measured on somebody's laptop. Do that before moving this floor.
      thresholds: {
        lines: 92.4,
      },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      // Unconditionally the stub, unlike `vite.config.ts`, which prefers the
      // built artifact when there is one. The unit tests never exercise real
      // OPAQUE — `lib/opaque.test.ts` mocks this specifier and injects a module
      // through `__setOpaqueModuleForTests` — so resolving to the real wasm
      // would only make the suite's result depend on whether somebody had run
      // `just build-opaque-wasm`, and jsdom cannot `fetch` the payload anyway.
      "@axiam/opaque-wasm": path.resolve(__dirname, "./src/lib/opaqueUnavailable.ts"),
    },
  },
});
