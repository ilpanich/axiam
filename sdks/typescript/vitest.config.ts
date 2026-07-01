import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // Browser-persona tests opt into jsdom per-file via:
    //   // @vitest-environment jsdom
    include: ['test/**/*.test.ts'],
  },
});
