import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'rest/index': 'src/rest/index.ts',
    'grpc/index': 'src/grpc/index.ts',
    'amqp/index': 'src/amqp/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  // splitting: false is load-bearing (RESEARCH Pitfall 2) — without it tsup's
  // own chunk-splitting can hoist shared code across entries into a common
  // chunk that the /rest bundle would then import, defeating SC#1.
  splitting: false,
  treeshake: true,
  external: ['@grpc/grpc-js', 'amqplib', 'axios', 'jose', 'tough-cookie', 'axios-cookiejar-support'],
});
