# axiam-sdk (TypeScript/JavaScript)

Official TypeScript/JavaScript client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **npm package:** `axiam-sdk`
- **Registry:** [npmjs.com/package/axiam-sdk](https://www.npmjs.com/package/axiam-sdk) _(reserved, not yet published)_
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1–§10.

See [`../CONTRACT.md`](../CONTRACT.md) for the full cross-language behavioral contract.

## Install

```bash
npm install axiam-sdk
```

## Two personas, tree-shaken subpath entries

`axiam-sdk` ships as **one package with two personas**, each reachable through its own
`package.json` subpath so a bundler only pulls in the transport code the caller actually
imports (proven in CI by the SC#1 bundle-and-grep gate — a `/rest`-only browser bundle
never contains `@grpc/grpc-js` or `amqplib`):

| Entry point            | Persona                    | Contents                                                                 |
|-------------------------|-----------------------------|---------------------------------------------------------------------------|
| `axiam-sdk` / `axiam-sdk/rest` | Browser + Node, REST-only  | `AxiamClient`: `login`/`verifyMfa`/`refresh`/`logout`, `can`/`batchCheck` over the FND-04 REST authz endpoint |
| `axiam-sdk/grpc`        | Node only                   | Everything in `/rest` plus `AuthzGrpcClient.checkAccess`/`batchCheck` over gRPC, the Node persona (`createNodeSession`), and the local-JWKS verifier |
| `axiam-sdk/amqp`        | Node only                   | `consume()` — HMAC-verified AMQP audit/authz event consumer (CONTRACT.md §8) |
| `axiam-sdk/middleware`  | Node only                   | `axiamMiddleware` (Express) / `axiamPlugin` (Fastify) — shared local-JWKS verify core (CONTRACT.md §10) |

**Browser code should only ever import from `axiam-sdk` or `axiam-sdk/rest`.** Importing
`axiam-sdk/grpc`, `axiam-sdk/amqp`, or `axiam-sdk/middleware` pulls in Node-only
dependencies (`@grpc/grpc-js`, `amqplib`, `jose`'s Node crypto, `express`/`fastify` types)
that do not belong in a browser bundle.

## Construction

`tenantSlug` (or `tenantId`) is a non-optional constructor parameter (CONTRACT.md §5) —
there is no default tenant:

```typescript
import { AxiamClient } from 'axiam-sdk';

const client = new AxiamClient({
  baseUrl: 'https://iam.example.com',
  tenantSlug: 'acme',
  // customCa is optional — PEM-encoded CA cert for self-signed dev environments (§6)
  // customCa: pemString,
});
```

## Usage per persona

### Browser — login + authz (`axiam-sdk` / `axiam-sdk/rest`)

```typescript
import { AxiamClient } from 'axiam-sdk';

const client = new AxiamClient({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });

const result = await client.login(email, password);
switch (result.status) {
  case 'mfa_required': {
    const code = await promptForMfaCode(result.availableMethods);
    const final = await client.verifyMfa(result.mfaToken, code);
    if (final.status === 'authenticated') console.log(`Authenticated as ${final.user.username}`);
    break;
  }
  case 'authenticated': {
    console.log(`Authenticated as ${result.user.username}`);
    break;
  }
}

// Single access check (REST-backed, browser-safe)
const allowed = await client.can('read', 'doc:1');

// Batch check — results preserve input order
const decisions = await client.batchCheck([
  { action: 'read', resourceId: 'doc:1' },
  { action: 'write', resourceId: 'doc:1' },
]);
```

Tokens arrive exclusively via `httpOnly` `Set-Cookie` — no raw session token is ever
exposed to application code. CSRF forwarding (cookie double-submit, CONTRACT.md §3) and
single-flight refresh (CONTRACT.md §9) are handled automatically.

### Node — gRPC authz (`axiam-sdk/grpc`)

```typescript
import { AuthzGrpcClient, createNodeSession } from 'axiam-sdk/grpc';

const session = createNodeSession({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
const grpcClient = new AuthzGrpcClient(session, { baseUrl: 'https://iam.example.com' });

const decision = await grpcClient.checkAccess({
  tenantId: 'tenant-1',
  subjectId: 'user-1',
  action: 'read',
  resourceId: 'doc:1',
});

grpcClient.close();
```

The gRPC channel is constructed once and reused; `UNAUTHENTICATED` responses transparently
share the same single-flight refresh guard as the REST persona (CONTRACT.md §9).

### Node — AMQP consumer (`axiam-sdk/amqp`)

```typescript
import { consume, Sensitive } from 'axiam-sdk/amqp';

const signingKey = new Sensitive(Buffer.from(process.env.AXIAM_AMQP_SIGNING_KEY ?? '', 'hex'));

await consume('amqp://localhost:5672', 'axiam.audit.events', signingKey, async (event) => {
  // Only a verified event ever reaches this closure — HMAC-SHA256
  // signature checked and stripped by the SDK before your handler runs
  // (CONTRACT.md §8). Verification failures are nacked-without-requeue.
  console.log('verified audit event:', event);
});
```

### Express middleware (`axiam-sdk/middleware`)

```typescript
import express from 'express';
import { createNodeSession } from 'axiam-sdk/grpc';
import { axiamMiddleware, type AxiamRequest } from 'axiam-sdk/middleware';

const session = createNodeSession({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
const app = express();

app.use(axiamMiddleware(session));

app.get('/protected', (req, res) => {
  const axiamUser = (req as AxiamRequest).axiamUser;
  res.json({ userId: axiamUser?.userId, tenantId: axiamUser?.tenantId, roles: axiamUser?.roles });
});
```

### Fastify plugin (`axiam-sdk/middleware`)

```typescript
import Fastify from 'fastify';
import { createNodeSession } from 'axiam-sdk/grpc';
import { axiamPlugin, type AxiamFastifyRequest } from 'axiam-sdk/middleware';

const session = createNodeSession({ baseUrl: 'https://iam.example.com', tenantSlug: 'acme' });
const app = Fastify();

app.register(axiamPlugin(session));

app.get('/protected', (request, reply) => {
  const axiamUser = (request as AxiamFastifyRequest).axiamUser;
  reply.send({ userId: axiamUser?.userId, tenantId: axiamUser?.tenantId, roles: axiamUser?.roles });
});
```

Both middleware integrations verify the session against a locally-cached JWKS (no
`cookie-parser` / `@fastify/cookie` peer dependency required), inject the authenticated
identity into the request context, and surface `AuthError` as HTTP 401 / `AuthzError` as
HTTP 403 with a standardized JSON error body (CONTRACT.md §10).

More runnable examples (all compiling under `tsc --noEmit -p examples/tsconfig.json`) live
in `examples/` at the package root.

## Error handling

Every persona throws exactly the three CONTRACT.md §2 error types — `AuthError`,
`AuthzError`, `NetworkError`:

```typescript
import { AuthError, AuthzError, NetworkError } from 'axiam-sdk';

try {
  await client.can('read', 'doc:1');
} catch (err) {
  if (err instanceof AuthError) {
    // re-authenticate
  } else if (err instanceof AuthzError) {
    // caller lacks permission
  } else if (err instanceof NetworkError) {
    // transport-level failure
  }
}
```

## Security notes

- Token-carrying values are wrapped in `Sensitive<T>` — `toString()`/`toJSON()`/
  `util.inspect` all redact to `[SENSITIVE]`; the raw value is only reachable via an
  explicit accessor (CONTRACT.md §7).
- Strict TLS verification is always on; the only escape hatch is the constructor's
  `customCa` option for self-signed development environments (CONTRACT.md §6).
- AMQP messages are HMAC-SHA256 verified before your handler ever sees them; verification
  failures are nacked without requeue (CONTRACT.md §8).

## Release / versioning

Tagged releases follow the monorepo convention `axiam-typescript-sdk/vX.Y.Z`. CI runs the full
gate suite (build, test, SC#1 bundle-and-grep, CJS-require smoke, token-leak, TLS-lint,
`npm publish --dry-run`) on every pull request touching `sdks/typescript/**`, and publishes
to npm with [provenance](https://docs.npmjs.com/generating-provenance-statements) only when
a `axiam-typescript-sdk/vX.Y.Z` tag is pushed.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
