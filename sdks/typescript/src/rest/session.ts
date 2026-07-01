// SharedSession — the object other transports (Node persona 17-03, middleware
// 17-05) attach gRPC/JWKS/middleware state to (D-13).
//
// Holds: the axios instance, the tenant header value (computed once at
// construction), a mutable csrfToken store, the base URL, and the bound
// refreshOnce single-flight guard (from core). One login() drives all
// transports.

import axios, { type AxiosInstance } from 'axios';
import type { AxiamClientOptions } from '../core/index.js';
import { DEFAULT_CONNECT_TIMEOUT_MS, DEFAULT_REQUEST_TIMEOUT_MS } from '../core/index.js';

const PEM_MARKER = '-----BEGIN CERTIFICATE-----';

/**
 * The single session object every AXIAM transport (REST here, gRPC/AMQP in
 * 17-03/17-04, middleware in 17-05) attaches to. Constructed once per
 * `AxiamClient` instance.
 */
export class SharedSession {
  readonly axios: AxiosInstance;
  readonly baseUrl: string;
  readonly tenantHeaderValue: string;
  /** Mutable CSRF token store — populated by the request/response interceptors (D-05). */
  csrfToken: string | undefined;
  /** Set true once a successful login/verifyMfa has completed. */
  authenticated = false;

  constructor(options: AxiamClientOptions, axiosInstance: AxiosInstance, tenantHeaderValue: string) {
    this.axios = axiosInstance;
    this.baseUrl = options.baseUrl;
    this.tenantHeaderValue = tenantHeaderValue;
  }
}

/**
 * Resolve the required tenant header value from options (§5). Throws if
 * neither tenantSlug nor tenantId is provided — there is no default tenant.
 */
export function resolveTenantHeaderValue(options: AxiamClientOptions): string {
  if (options.tenantSlug) {
    return options.tenantSlug;
  }
  if (options.tenantId) {
    return options.tenantId;
  }
  throw new Error(
    'AxiamClient construction requires a tenant: provide either tenantSlug or tenantId (CONTRACT.md §5).',
  );
}

/**
 * Build the Node-only `https.Agent` for a customCa PEM. Guarded by
 * `typeof process !== 'undefined'` as a CAPABILITY guard (Node has
 * node:https available), NOT a persona-sniffing branch — browsers ignore
 * customCa entirely since the platform manages TLS verification itself.
 */
function maybeBuildHttpsAgent(customCa: string | undefined): unknown {
  if (!customCa) {
    return undefined;
  }
  if (!customCa.includes(PEM_MARKER)) {
    throw new Error(
      'customCa must be a PEM-encoded certificate (expected to contain "-----BEGIN CERTIFICATE-----") (CONTRACT.md §6).',
    );
  }
  if (typeof process === 'undefined') {
    // Browser: platform manages TLS; customCa has no effect there.
    return undefined;
  }
  // Node capability guard — require lazily so this branch never executes
  // (and never needs to resolve) in a browser bundle.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const https = require('node:https') as typeof import('node:https');
  return new https.Agent({ ca: customCa });
}

/** Build the axios instance + SharedSession for an AxiamClient (D-13/D-25). */
export function createSession(options: AxiamClientOptions): SharedSession {
  const tenantHeaderValue = resolveTenantHeaderValue(options);

  // customCa is validated (PEM-shape) even when running in an environment
  // that will end up ignoring it (browser), so construction fails fast and
  // consistently across personas (§6).
  if (options.customCa !== undefined && !options.customCa.includes(PEM_MARKER)) {
    throw new Error(
      'customCa must be a PEM-encoded certificate (expected to contain "-----BEGIN CERTIFICATE-----") (CONTRACT.md §6).',
    );
  }

  const httpsAgent = maybeBuildHttpsAgent(options.customCa);

  const axiosInstance = axios.create({
    baseURL: options.baseUrl,
    withCredentials: true,
    timeout: options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
    ...(httpsAgent ? { httpsAgent } : {}),
  });

  const session = new SharedSession(options, axiosInstance, tenantHeaderValue);

  // Attach X-Tenant-ID to every outgoing request (§5.2).
  axiosInstance.interceptors.request.use((config) => {
    config.headers = config.headers ?? {};
    config.headers['X-Tenant-ID'] = session.tenantHeaderValue;
    return config;
  });

  return session;
}
