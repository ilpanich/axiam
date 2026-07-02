// gRPC checkAccess/batchCheck + interceptor + UNAUTHENTICATED single-flight
// retry (D-10/D-13, SC#2 Node half, CONTRACT.md §9). Per D-24, all Node
// unit/concurrency tests here run against a mocked/stubbed transport (no
// live gRPC server) for determinism and speed.

import * as grpc from '@grpc/grpc-js';
import { CookieJar } from 'tough-cookie';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthError, resetRefreshGuard } from '../../src/core/index.js';
import {
  AuthzGrpcClient,
  type AuthorizationServiceClientFactory,
  type WireAuthorizationServiceClient,
  type WireBatchCheckAccessRequest,
  type WireBatchCheckAccessResponse,
  type WireCheckAccessRequest,
  type WireCheckAccessResponse,
} from '../../src/grpc/client.js';
import { NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';
import { ACCESS_COOKIE } from '../../src/node/cookieJar.js';

const BASE_URL = 'https://axiam-grpc.test';

function serviceError(code: grpc.status): grpc.ServiceError {
  const err = new Error(`grpc error ${code}`) as grpc.ServiceError;
  err.code = code;
  err.details = `grpc error ${code}`;
  err.metadata = new grpc.Metadata();
  return err;
}

interface StubClientOptions {
  /** Metadata captured from every start() call made through the interceptor. */
  capturedMetadata: grpc.Metadata[];
  /** Queue of outcomes for checkAccess: 'ok' resolves, a status code rejects with a ServiceError. */
  checkAccessOutcomes: Array<'ok' | grpc.status>;
}

/** Build a stub WireAuthorizationServiceClient honoring the real grpc-js interceptor chain. */
function buildStubClient(options: StubClientOptions): AuthorizationServiceClientFactory {
  return (_baseUrl, _credentials, interceptors) => {
    // Route calls through the real grpc-js interceptor chain so the test
    // proves the interceptor actually adds metadata (not just that the
    // client-level code would, in isolation).
    const runInterceptorChain = (): void => {
      const terminal = new grpc.InterceptingCall({
        start(metadata: grpc.Metadata) {
          options.capturedMetadata.push(metadata);
        },
        sendMessage() {},
        halfClose() {},
        cancelWithStatus() {},
        getPeer: () => 'stub-peer',
        sendMessageWithContext() {},
        startRead() {},
        getAuthContext: () => null,
      });
      let call: grpc.InterceptingCall = terminal;
      for (const interceptor of [...interceptors].reverse()) {
        const inner = call;
        call = interceptor(
          { method_definition: { path: '', requestStream: false, responseStream: false } } as grpc.InterceptorOptions,
          () => inner,
        );
      }
      call.start(new grpc.Metadata());
    };

    const client: WireAuthorizationServiceClient = {
      checkAccess(
        _request: WireCheckAccessRequest,
        _metadata: grpc.Metadata,
        callback: (error: grpc.ServiceError | null, response?: WireCheckAccessResponse) => void,
      ): grpc.ClientUnaryCall {
        runInterceptorChain();
        const outcome = options.checkAccessOutcomes.shift() ?? 'ok';
        if (outcome === 'ok') {
          callback(null, { allowed: true, deny_reason: '' });
        } else {
          callback(serviceError(outcome));
        }
        return {} as grpc.ClientUnaryCall;
      },
      batchCheckAccess(
        request: WireBatchCheckAccessRequest,
        _metadata: grpc.Metadata,
        callback: (error: grpc.ServiceError | null, response?: WireBatchCheckAccessResponse) => void,
      ): grpc.ClientUnaryCall {
        runInterceptorChain();
        callback(null, {
          results: request.requests.map((r) => ({ allowed: r.action !== 'deny-me', deny_reason: '' })),
        });
        return {} as grpc.ClientUnaryCall;
      },
      close() {},
    };
    return client;
  };
}

async function buildTestSession(): Promise<NodeSession> {
  const jar = new CookieJar();
  await jar.setCookie(`${ACCESS_COOKIE}=cached-access-token; Path=/`, BASE_URL);

  const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
  const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
  await tokenManager.syncFromJar();
  const jwksVerifier = createVerifier(BASE_URL);
  return new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
}

describe('gRPC checkAccess/batchCheck (SC#2 Node half)', () => {
  afterEach(() => {
    resetRefreshGuard();
  });

  it('invokes the CheckAccess RPC and returns the decision', async () => {
    const session = await buildTestSession();
    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({ capturedMetadata, checkAccessOutcomes: ['ok'] });
    const client = new AuthzGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const decision = await client.checkAccess({
      tenantId: 't-1',
      subjectId: 's-1',
      action: 'read',
      resourceId: 'r-1',
    });

    expect(decision.allowed).toBe(true);
  });

  it('the interceptor adds authorization + x-tenant-id metadata', async () => {
    const session = await buildTestSession();
    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({ capturedMetadata, checkAccessOutcomes: ['ok'] });
    const client = new AuthzGrpcClient(session, { baseUrl: BASE_URL }, factory);

    await client.checkAccess({ tenantId: 't-1', subjectId: 's-1', action: 'read', resourceId: 'r-1' });

    expect(capturedMetadata).toHaveLength(1);
    const md = capturedMetadata[0];
    expect(md.get('authorization')).toEqual(['Bearer cached-access-token']);
    expect(md.get('x-tenant-id')).toEqual(['acme']);
  });

  it('a stub returning UNAUTHENTICATED once then OK causes exactly one refresh and one retry', async () => {
    const session = await buildTestSession();
    let refreshCalls = 0;
    session.doRefresh = async () => {
      refreshCalls += 1;
      await session.tokenManager.syncFromJar();
    };

    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      checkAccessOutcomes: [grpc.status.UNAUTHENTICATED, 'ok'],
    });
    const client = new AuthzGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const decision = await client.checkAccess({ tenantId: 't-1', subjectId: 's-1', action: 'read', resourceId: 'r-1' });

    expect(decision.allowed).toBe(true);
    expect(refreshCalls).toBe(1);
    // Original attempt + one retry = 2 interceptor invocations.
    expect(capturedMetadata).toHaveLength(2);
  });

  it('two consecutive UNAUTHENTICATED responses surface AuthError with no third attempt', async () => {
    const session = await buildTestSession();
    let refreshCalls = 0;
    session.doRefresh = async () => {
      refreshCalls += 1;
      await session.tokenManager.syncFromJar();
    };

    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({
      capturedMetadata,
      checkAccessOutcomes: [grpc.status.UNAUTHENTICATED, grpc.status.UNAUTHENTICATED, 'ok'],
    });
    const client = new AuthzGrpcClient(session, { baseUrl: BASE_URL }, factory);

    await expect(
      client.checkAccess({ tenantId: 't-1', subjectId: 's-1', action: 'read', resourceId: 'r-1' }),
    ).rejects.toBeInstanceOf(AuthError);

    expect(refreshCalls).toBe(1);
    // Original attempt + one retry = 2 interceptor invocations; no third.
    expect(capturedMetadata).toHaveLength(2);
  });

  it('batchCheck preserves input order', async () => {
    const session = await buildTestSession();
    const capturedMetadata: grpc.Metadata[] = [];
    const factory = buildStubClient({ capturedMetadata, checkAccessOutcomes: [] });
    const client = new AuthzGrpcClient(session, { baseUrl: BASE_URL }, factory);

    const results = await client.batchCheck([
      { tenantId: 't-1', subjectId: 's-1', action: 'read', resourceId: 'r-1' },
      { tenantId: 't-1', subjectId: 's-1', action: 'deny-me', resourceId: 'r-2' },
      { tenantId: 't-1', subjectId: 's-1', action: 'write', resourceId: 'r-3' },
    ]);

    expect(results).toHaveLength(3);
    expect(results[0].allowed).toBe(true);
    expect(results[1].allowed).toBe(false);
    expect(results[2].allowed).toBe(true);
  });
});
