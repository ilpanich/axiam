import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'rest/index': 'src/rest/index.ts',
    'grpc/index': 'src/grpc/index.ts',
    'amqp/index': 'src/amqp/index.ts',
    'middleware/index': 'src/middleware/index.ts',
  },
  format: ['esm', 'cjs'],
  // package.json's `type: module` makes tsup's default extension mapping
  // ESM=.js / CJS=.cjs — the reverse of the `exports` map's `import`/
  // `require` condition paths (which point at .mjs for ESM and .js for
  // CJS/require, per the exports map established in 17-01). Force the
  // conventional extensions explicitly so `require()` never lands on an
  // ESM file — load-bearing for the CI CJS-require smoke gate
  // (`require('./dist/grpc/index.js')` must resolve to the actual CJS
  // build). (Rule 1 fix, 17-06.)
  outExtension({ format }) {
    return format === 'cjs' ? { js: '.js' } : { js: '.mjs' };
  },
  dts: true,
  sourcemap: true,
  clean: true,
  // splitting: false is load-bearing (RESEARCH Pitfall 2) — without it tsup's
  // own chunk-splitting can hoist shared code across entries into a common
  // chunk that the /rest bundle would then import, defeating SC#1.
  splitting: false,
  treeshake: true,
  external: [
    '@grpc/grpc-js',
    'amqplib',
    'axios',
    'jose',
    'tough-cookie',
    'axios-cookiejar-support',
    'express',
    'fastify',
  ],
});
