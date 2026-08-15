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
      // Ratcheted per R5.9 (achieved - 2): `npx vitest run --coverage` on
      // 2026-08-15 measured 94.41% line coverage (3857/4085 lines, 808
      // tests, 67 files). Re-ratchet upward as coverage improves; this is
      // the first floor this file has ever had.
      thresholds: {
        lines: 92.4,
      },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
