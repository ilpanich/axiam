// gRPC AuthorizationService client — reused channel, checkAccess/batchCheck
// (D-10/D-13, SC#2 Node half).
//
// The generated ts-proto stubs (`src/gen`, produced by `buf generate` at
// build time — Phase 15 D-01/D-20) are NOT committed and are unavailable in
// this sandbox (no `buf` CLI). Rather than importing from a path that does
// not exist here, this module (a) defines local wire-shape interfaces that
// exactly mirror `proto/axiam/v1/authorization.proto`, and (b) builds the
// gRPC client dynamically via grpc-js's own `makeClientConstructor` (the
// same primitive ts-proto's `outputServices=grpc-js` stubs are built on top
// of) rather than importing a generated class. A buf-enabled build can swap
// `buildAuthorizationServiceClient` below for the real ts-proto-generated
// `AuthorizationServiceClient` from `../gen/...` with NO change to the
// public `AuthzGrpcClient` surface, since both satisfy the same
// `WireAuthorizationServiceClient` shape by construction (same .proto).
// End-to-end wiring against real generated stubs is deferred to a
// buf-enabled CI run (RESEARCH.md D-20; environment note in this plan).

import * as grpc from '@grpc/grpc-js';
import type { NodeSession } from '../node/session.js';
import { authInterceptor } from './interceptor.js';
import { callWithRefresh } from './callWithRefresh.js';

// ---------------------------------------------------------------------------
// Wire shapes (proto/axiam/v1/authorization.proto) — mirrored, not imported.
// ---------------------------------------------------------------------------

export interface WireCheckAccessRequest {
  tenant_id: string;
  subject_id: string;
  action: string;
  resource_id: string;
  scope?: string;
}

export interface WireCheckAccessResponse {
  allowed: boolean;
  deny_reason: string;
}

export interface WireBatchCheckAccessRequest {
  requests: WireCheckAccessRequest[];
}

export interface WireBatchCheckAccessResponse {
  results: WireCheckAccessResponse[];
}

type UnaryCallback<T> = (error: grpc.ServiceError | null, response?: T) => void;

/**
 * The subset of a ts-proto (`outputServices=grpc-js`) generated
 * `AuthorizationServiceClient` this module needs. The real generated client
 * satisfies this shape exactly (unary Node-callback methods), so a
 * buf-enabled build's generated client is a drop-in replacement here.
 */
export interface WireAuthorizationServiceClient {
  checkAccess(
    request: WireCheckAccessRequest,
    metadata: grpc.Metadata,
    callback: UnaryCallback<WireCheckAccessResponse>,
  ): grpc.ClientUnaryCall;
  batchCheckAccess(
    request: WireBatchCheckAccessRequest,
    metadata: grpc.Metadata,
    callback: UnaryCallback<WireBatchCheckAccessResponse>,
  ): grpc.ClientUnaryCall;
  close(): void;
}

/** Public (camelCase, §1) single access-check request shape. */
export interface CheckAccessRequest {
  tenantId: string;
  subjectId: string;
  action: string;
  resourceId: string;
  scope?: string;
}

/** Public access-check result shape, shared with the REST `AccessDecision` (§1). */
export interface AccessDecision {
  allowed: boolean;
  denyReason?: string;
}

function toWireRequest(req: CheckAccessRequest): WireCheckAccessRequest {
  return {
    tenant_id: req.tenantId,
    subject_id: req.subjectId,
    action: req.action,
    resource_id: req.resourceId,
    scope: req.scope,
  };
}

function fromWireResponse(resp: WireCheckAccessResponse): AccessDecision {
  return {
    allowed: resp.allowed,
    denyReason: resp.deny_reason ? resp.deny_reason : undefined,
  };
}

function promisifyUnary<TReq, TResp>(
  call: (req: TReq, metadata: grpc.Metadata, callback: UnaryCallback<TResp>) => grpc.ClientUnaryCall,
  request: TReq,
): Promise<TResp> {
  return new Promise((resolve, reject) => {
    call(request, new grpc.Metadata(), (error, response) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(response as TResp);
    });
  });
}

/**
 * Build the gRPC channel credentials for `baseUrl` (§6 — TLS is always
 * strict by default; `customCa` is the ONLY certificate escape hatch, never
 * an insecure/skip-verification surface).
 *
 * A plaintext target (`http://`/`grpc://`) is REFUSED by default (X-2): it
 * would silently drop the channel to `createInsecure()`, sending bearer tokens
 * and tenant metadata in cleartext. Callers who genuinely need a local dev
 * plaintext channel must opt in explicitly with `allowInsecure: true`, which
 * emits a `console.warn`. As a convenience the opt-in is required for ANY host
 * (including loopback) — there is no silent path to an insecure channel.
 */
function buildCredentials(
  baseUrl: string,
  customCa: string | undefined,
  allowInsecure: boolean,
): grpc.ChannelCredentials {
  const isSecure = baseUrl.startsWith('https://') || baseUrl.startsWith('grpcs://');
  if (!isSecure) {
    if (!allowInsecure) {
      throw new Error(
        `AXIAM gRPC refuses to open an insecure (plaintext) channel to "${baseUrl}": ` +
          'bearer tokens and tenant metadata would be sent in cleartext. Use an ' +
          'https:// or grpcs:// target, or pass { allowInsecure: true } to opt in ' +
          'explicitly for a trusted local/dev channel (CONTRACT.md §6).',
      );
    }
    // Explicit opt-in only — never reached without allowInsecure.
    // eslint-disable-next-line no-console
    console.warn(
      `AXIAM gRPC: opening an INSECURE (plaintext) channel to "${baseUrl}" because ` +
        'allowInsecure was set. Bearer tokens and tenant metadata are transmitted in ' +
        'cleartext — never use this outside a trusted local/dev environment.',
    );
    return grpc.ChannelCredentials.createInsecure();
  }
  if (customCa) {
    return grpc.ChannelCredentials.createSsl(Buffer.from(customCa, 'utf8'));
  }
  // Default: verify against the platform's native trust store.
  return grpc.ChannelCredentials.createSsl();
}

function grpcTarget(baseUrl: string): string {
  const url = new URL(baseUrl);
  return url.port ? `${url.hostname}:${url.port}` : url.hostname;
}

const jsonCodec = <T>() => ({
  serialize: (value: T): Buffer => Buffer.from(JSON.stringify(value)),
  deserialize: (bytes: Buffer): T => JSON.parse(bytes.toString('utf8')) as T,
});

/**
 * Construct a real `AuthorizationServiceClient` over grpc-js's own
 * `makeClientConstructor` primitive (the same primitive ts-proto's
 * `outputServices=grpc-js` codegen target uses under the hood). This
 * transport-level client encodes/decodes with JSON as a build-independent
 * stand-in for the protobuf binary codec a buf-enabled build's generated
 * serializers would use — swap this factory for the generated
 * `AuthorizationServiceClient` once `src/gen` exists (D-20).
 */
export function buildAuthorizationServiceClient(
  baseUrl: string,
  credentials: grpc.ChannelCredentials,
  interceptors: grpc.Interceptor[],
): WireAuthorizationServiceClient {
  const checkAccessCodec = jsonCodec<WireCheckAccessRequest>();
  const checkAccessRespCodec = jsonCodec<WireCheckAccessResponse>();
  const batchCodec = jsonCodec<WireBatchCheckAccessRequest>();
  const batchRespCodec = jsonCodec<WireBatchCheckAccessResponse>();

  const ServiceClientConstructor = grpc.makeClientConstructor(
    {
      checkAccess: {
        path: '/axiam.v1.AuthorizationService/CheckAccess',
        requestStream: false,
        responseStream: false,
        requestSerialize: checkAccessCodec.serialize,
        requestDeserialize: checkAccessCodec.deserialize,
        responseSerialize: checkAccessRespCodec.serialize,
        responseDeserialize: checkAccessRespCodec.deserialize,
      },
      batchCheckAccess: {
        path: '/axiam.v1.AuthorizationService/BatchCheckAccess',
        requestStream: false,
        responseStream: false,
        requestSerialize: batchCodec.serialize,
        requestDeserialize: batchCodec.deserialize,
        responseSerialize: batchRespCodec.serialize,
        responseDeserialize: batchRespCodec.deserialize,
      },
    },
    'axiam.v1.AuthorizationService',
  );

  return new ServiceClientConstructor(grpcTarget(baseUrl), credentials, {
    interceptors,
  }) as unknown as WireAuthorizationServiceClient;
}

export type AuthorizationServiceClientFactory = (
  baseUrl: string,
  credentials: grpc.ChannelCredentials,
  interceptors: grpc.Interceptor[],
) => WireAuthorizationServiceClient;

/**
 * gRPC transport for `AuthorizationService` (`checkAccess`/`batchCheck`,
 * SC#2 Node half), reusing one long-lived client/channel per instance (D-10
 * — never reconstructed per-call) and injecting auth + tenant metadata via
 * the synchronous interceptor on every RPC.
 */
export class AuthzGrpcClient {
  readonly #session: NodeSession;
  readonly #inner: WireAuthorizationServiceClient;

  constructor(
    session: NodeSession,
    options: { baseUrl: string; customCa?: string; allowInsecure?: boolean },
    clientFactory: AuthorizationServiceClientFactory = buildAuthorizationServiceClient,
  ) {
    this.#session = session;
    const credentials = buildCredentials(options.baseUrl, options.customCa, options.allowInsecure ?? false);
    this.#inner = clientFactory(options.baseUrl, credentials, [authInterceptor(session)]);
  }

  /** `CheckAccess` over gRPC (SC#2 Node half). UNAUTHENTICATED triggers exactly one shared-guard refresh + one retry (§9.3). */
  async checkAccess(request: CheckAccessRequest): Promise<AccessDecision> {
    const wireRequest = toWireRequest(request);
    const response = await callWithRefresh(this.#session, () =>
      promisifyUnary(this.#inner.checkAccess.bind(this.#inner), wireRequest),
    );
    return fromWireResponse(response);
  }

  /** `BatchCheckAccess` over gRPC — results preserve input order (§1). */
  async batchCheck(requests: CheckAccessRequest[]): Promise<AccessDecision[]> {
    const wireRequest: WireBatchCheckAccessRequest = { requests: requests.map(toWireRequest) };
    const response = await callWithRefresh(this.#session, () =>
      promisifyUnary(this.#inner.batchCheckAccess.bind(this.#inner), wireRequest),
    );
    return response.results.map(fromWireResponse);
  }

  /** Close the underlying gRPC channel. */
  close(): void {
    this.#inner.close();
  }
}
