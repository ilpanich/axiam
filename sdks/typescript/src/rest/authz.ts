// checkAccess/can/batchCheck over REST (D-08, FND-04, §1).
//
// Mirrors sdks/rust/src/rest/authz.rs and
// crates/axiam-api-rest/src/handlers/authz_check.rs exactly. tenant_id is
// never sent in the body — the server derives it from the JWT (§5); the SDK
// only sends X-Tenant-ID (already attached by session.ts's request
// interceptor on every call). No client-side cache (D-08) — plain stateless
// async functions.

import { mapHttpStatusToError, NetworkError } from '../core/index.js';
import type { AxiamClient } from './client.js';
import type {
  AccessCheck,
  AccessDecision,
  BatchCheckAccessBodyWire,
  BatchCheckAccessResponseWire,
  CheckAccessBodyWire,
  CheckAccessResponseWire,
} from './types.js';

const CHECK_PATH = '/api/v1/authz/check';
const BATCH_CHECK_PATH = '/api/v1/authz/check/batch';

function toWireBody(check: AccessCheck): CheckAccessBodyWire {
  return {
    action: check.action,
    resource_id: check.resourceId,
    scope: check.scope,
    subject_id: check.subjectId,
  };
}

function fromWireDecision(wire: CheckAccessResponseWire): AccessDecision {
  return { allowed: wire.allowed, reason: wire.reason };
}

/**
 * `POST /api/v1/authz/check` (§1, FND-04).
 *
 * A 403 authz denial (server-side error, distinct from the `allowed: false`
 * decision the endpoint itself returns) is mapped to AuthzError, not treated
 * as a transport failure.
 */
export async function checkAccess(client: AxiamClient, check: AccessCheck): Promise<AccessDecision> {
  try {
    const response = await client.session.axios.post<CheckAccessResponseWire>(CHECK_PATH, toWireBody(check));
    return fromWireDecision(response.data);
  } catch (err) {
    throw mapAuthzError(err, check.action, check.resourceId);
  }
}

/**
 * `can` — alias for checkAccess targeting browser/UI scenarios (§1 note),
 * returning just the boolean `allowed` outcome.
 */
export async function can(client: AxiamClient, action: string, resourceId: string, scope?: string): Promise<boolean> {
  const decision = await checkAccess(client, { action, resourceId, scope });
  return decision.allowed;
}

/**
 * `POST /api/v1/authz/check/batch` (§1). Results are returned in the same
 * order as the input `checks` array (server-guaranteed ordering).
 */
export async function batchCheck(client: AxiamClient, checks: AccessCheck[]): Promise<AccessDecision[]> {
  const body: BatchCheckAccessBodyWire = { checks: checks.map(toWireBody) };
  try {
    const response = await client.session.axios.post<BatchCheckAccessResponseWire>(BATCH_CHECK_PATH, body);
    return response.data.results.map(fromWireDecision);
  } catch (err) {
    throw mapAuthzError(err);
  }
}

function mapAuthzError(err: unknown, action?: string, resourceId?: string): Error {
  if (err && typeof err === 'object' && 'response' in err) {
    const response = (err as { response?: { status?: number; data?: { message?: string } } }).response;
    if (response?.status !== undefined) {
      if (response.status === 403) {
        // Body (response.data) carries the server's own action/resource_id
        // for the denial (structured 403 body) — preferred by the mapper
        // over the call-args action/resourceId below when present.
        return mapHttpStatusToError(403, response.data?.message ?? 'authorization denied', {
          action,
          resourceId,
          body: response.data,
        });
      }
      return mapHttpStatusToError(response.status, response.data?.message ?? 'authz request failed', {
        action,
        resourceId,
        body: response.data,
        cause: err,
      });
    }
  }
  return new NetworkError('authz request failed', err);
}
