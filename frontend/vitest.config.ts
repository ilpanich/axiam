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
      // Ratcheted 2026-09-11 to achieved - 0.5. A LOCAL `npx vitest run
      // --coverage --coverage.reporter=text-summary` measured and printed
      // 96.6% line coverage (5745/5947 lines, 1539 tests, 100 files). The
      // floor moved 92.4 -> 96.1.
      //
      // Still a laptop number, not a CI one. The standing rule below is
      // unchanged and unmet, and it is worth restating rather than deleting:
      // only ever move this floor to a percentage something has actually
      // printed, never to an estimate of where coverage "should" be.
      //
      // The previous ratchet's note explains why no CI number exists yet: the
      // coverage job passed `--coverage.reporter=lcov` alone, which replaces
      // vitest's text reporter, so the job's own achieved percentage appeared
      // nowhere in its log. The job now also emits `text-summary` onto the run
      // summary page — so once this branch has been through CI once, prefer
      // that printed number over this one for the next ratchet.
      thresholds: {
        lines: 96.1,
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
