// Fastify example — axiamPlugin guarding a protected route (D-27, §10).
//
// Illustrative/compilable: constructs a Node persona session, registers the
// SDK's Fastify plugin (a preHandler hook), and defines one protected GET
// route reading `request.axiamUser`. Does not require a live AXIAM server
// to type-check; running it for real traffic requires a reachable
// AXIAM_BASE_URL (for the plugin's JWKS fetch on cache-miss).
//
// Run: `npx tsx examples/fastify-app.ts` — not part of the automated test
// suite; the compile check (`tsc --noEmit -p examples/tsconfig.json`) is
// the SC#4 gate.

import Fastify from 'fastify';
import { createNodeSession } from 'axiam-sdk/grpc';
import { axiamPlugin, type AxiamFastifyRequest } from 'axiam-sdk/middleware';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantSlug = process.env.AXIAM_TENANT_SLUG ?? 'default';
const listenAddr = process.env.AXIAM_LISTEN_ADDR ?? '127.0.0.1:8081';

const session = createNodeSession({ baseUrl, tenantSlug });

const app = Fastify();

async function main(): Promise<void> {
  await app.register(axiamPlugin(session));

  app.get('/protected', async (request) => {
    const axiamUser = (request as AxiamFastifyRequest).axiamUser;
    return {
      message: `Hello, user ${axiamUser?.userId} (tenant ${axiamUser?.tenantId})`,
      roles: axiamUser?.roles ?? [],
    };
  });

  const [host, port] = listenAddr.split(':');
  await app.listen({ host, port: Number(port) });
  console.log(`Listening on http://${listenAddr} — GET /protected requires an AXIAM session`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
