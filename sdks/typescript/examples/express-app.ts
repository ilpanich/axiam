// Express example — axiamMiddleware guarding a protected route (D-27, §10).
//
// Illustrative/compilable: constructs a Node persona session, registers the
// SDK's Express middleware, and defines one protected GET route reading
// `req.axiamUser`. Does not require a live AXIAM server to type-check;
// running it for real traffic requires a reachable AXIAM_BASE_URL (for the
// middleware's JWKS fetch on cache-miss).
//
// Run: `npx tsx examples/express-app.ts` (after `npm run build`, or against
// source directly with a suitable loader) — not part of the automated test
// suite; the compile check (`tsc --noEmit -p examples/tsconfig.json`) is
// the SC#4 gate.

import express from 'express';
import type { Request, Response } from 'express';
import { createNodeSession } from 'axiam-sdk/grpc';
import { axiamMiddleware, type AxiamRequest } from 'axiam-sdk/middleware';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantSlug = process.env.AXIAM_TENANT_SLUG ?? 'default';
const listenAddr = process.env.AXIAM_LISTEN_ADDR ?? '127.0.0.1:8080';

const session = createNodeSession({ baseUrl, tenantSlug });

const app = express();

app.use(axiamMiddleware(session));

app.get('/protected', (req: Request, res: Response) => {
  const axiamUser = (req as AxiamRequest).axiamUser;
  res.json({
    message: `Hello, user ${axiamUser?.userId} (tenant ${axiamUser?.tenantId})`,
    roles: axiamUser?.roles ?? [],
  });
});

const [host, port] = listenAddr.split(':');
app.listen(Number(port), host, () => {
  console.log(`Listening on http://${listenAddr} — GET /protected requires an AXIAM session`);
});
