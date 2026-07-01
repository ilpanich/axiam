#!/usr/bin/env node
// SC#1 bundle-and-grep gate (D-02).
//
// Proves — as an end-to-end CI assertion, not config trust — that the
// browser persona (`axiam-sdk` / `axiam-sdk/rest`) never pulls in a
// Node-only transport (`@grpc/grpc-js`, `amqplib`) when bundled for the
// browser.
//
// Mechanism: write a temp fixture that imports { AxiamClient } from the
// built `dist/rest/index.mjs`, bundle it with esbuild using
// `platform: 'browser'` (load-bearing: a Node built-in such as net/tls/dns
// pulled in transitively by grpc-js/amqplib becomes a hard build error
// under platform:'browser' instead of a silent polyfill — see RESEARCH
// Area 1), then grep the bundled output for the forbidden package names.
//
// Exit 0 + OK message on success. Exit 1 with the offending match(es) on
// failure. Run after `npm run build` has produced dist/.

import { build } from 'esbuild';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const FORBIDDEN_PATTERN = /@grpc\/grpc-js|amqplib/;

const REST_ENTRY = fileURLToPath(new URL('../dist/rest/index.mjs', import.meta.url));

async function bundleAndGrep(entryModulePath) {
  const tmpDir = await mkdtemp(join(tmpdir(), 'axiam-bundle-grep-'));
  const fixturePath = join(tmpDir, 'fixture.mjs');

  try {
    await writeFile(
      fixturePath,
      `import { AxiamClient } from ${JSON.stringify(entryModulePath)};\nconsole.log(typeof AxiamClient);\n`,
      'utf8',
    );

    // platform:'browser' is load-bearing (RESEARCH Area 1): it makes a
    // Node built-in (net/tls/dns/etc.) pulled in transitively by
    // @grpc/grpc-js or amqplib a hard build error rather than a silent
    // polyfill, so the gate cannot be defeated by esbuild quietly
    // shimming a Node core module.
    const result = await build({
      entryPoints: [fixturePath],
      bundle: true,
      platform: 'browser',
      format: 'esm',
      write: false,
      logLevel: 'silent',
    });

    return result.outputFiles.map((f) => f.text).join('\n');
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

async function main() {
  if (!existsSync(REST_ENTRY)) {
    console.error(`FAIL: ${REST_ENTRY} does not exist — run "npm run build" first.`);
    process.exit(1);
  }

  let output;
  try {
    output = await bundleAndGrep(REST_ENTRY);
  } catch (err) {
    // esbuild throws when platform:'browser' cannot resolve a Node built-in
    // pulled in transitively — this is itself the gate doing its job (a
    // Node-only transport leaked into the browser persona), so surface it
    // as a normal gate failure rather than an uncaught crash.
    console.error('FAIL: browser bundle failed to build under platform:"browser".');
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }

  const match = output.match(FORBIDDEN_PATTERN);
  if (match) {
    console.error(
      `FAIL: browser bundle of ${REST_ENTRY} contains a forbidden Node-only transport reference: "${match[0]}"`,
    );
    console.error('SC#1 violated — @grpc/grpc-js or amqplib leaked into the /rest browser bundle.');
    process.exit(1);
  }

  console.log(`OK: browser bundle of ${REST_ENTRY} contains no @grpc/grpc-js or amqplib reference (SC#1).`);
}

main();
