// Node gRPC example — checkAccess over AuthorizationService (SC#2 Node
// half, D-10/D-13).
//
// Illustrative/compilable: constructs the Node persona session and an
// AuthzGrpcClient reusing it, then calls checkAccess over gRPC. The
// underlying channel is constructed once and reused (D-10 — never
// reconstructed per-call); UNAUTHENTICATED responses transparently share
// the single-flight refresh guard with the REST persona (D-13).
//
// Run: `npx tsx examples/node-grpc.ts` against a reachable AXIAM server;
// the compile check (`tsc --noEmit -p examples/tsconfig.json`) is the SC#4
// gate here, not execution.

import { AuthzGrpcClient, createNodeSession } from 'axiam-sdk/grpc';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantSlug = process.env.AXIAM_TENANT_SLUG ?? 'default';

async function main(): Promise<void> {
  const session = createNodeSession({ baseUrl, tenantSlug });

  // A real caller authenticates first (e.g. session.axios.post('/api/v1/auth/login', ...))
  // so the cookie jar carries a valid axiam_access/axiam_refresh pair before
  // any authz check is made.

  const grpcClient = new AuthzGrpcClient(session, { baseUrl });

  try {
    const decision = await grpcClient.checkAccess({
      tenantId: 'tenant-1',
      subjectId: 'user-1',
      action: 'read',
      resourceId: 'doc:1',
    });
    console.log('checkAccess (gRPC):', decision);

    const batchDecisions = await grpcClient.batchCheck([
      { tenantId: 'tenant-1', subjectId: 'user-1', action: 'read', resourceId: 'doc:1' },
      { tenantId: 'tenant-1', subjectId: 'user-1', action: 'write', resourceId: 'doc:1' },
    ]);
    console.log('batchCheck (gRPC):', batchDecisions);
  } finally {
    grpcClient.close();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
