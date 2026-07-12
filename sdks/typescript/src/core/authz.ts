// Shared authz result shape (SDK-Q10, C2) — dependency-free, per D-04's
// core/*.ts rule (no @grpc/grpc-js, amqplib, axios, jose, or node:util
// imports here).
//
// Both the REST transport (`rest/types.ts`) and the gRPC transport
// (`grpc/client.ts`) resolve to the exact same public decision shape —
// `{ allowed, reason? }` — so it is defined once here and re-exported by
// both `rest/index.ts` and `grpc/index.ts` under the same `AccessDecision`
// name, rather than declaring two structurally-identical interfaces that
// could drift out of sync.

/**
 * The outcome of an access check, shared by the REST (`AxiamClient.checkAccess`
 * / `.batchCheck`) and gRPC (`AuthzGrpcClient.checkAccess` / `.batchCheck`)
 * transports (CONTRACT.md §1). `reason` is present (and non-empty) only when
 * `allowed` is `false`.
 */
export interface AccessDecision {
  /** Whether the checked action on the checked resource is permitted. */
  allowed: boolean;
  /** Present (and non-empty) only when `allowed` is `false`; a human-readable reason the check was denied. */
  reason?: string;
}
