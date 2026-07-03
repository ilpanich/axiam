// AxiamClientOptions — shared client configuration (CONTRACT.md §5/§6).
//
// tenantSlug or tenantId is required at construction time per §5; there is
// no default tenant. customCa is the sole TLS escape hatch (§6) — there is
// no insecure/skip-verification option anywhere in this SDK.

export interface AxiamClientOptions {
  /** Base URL of the AXIAM server, e.g. "https://iam.example.com". */
  baseUrl: string;
  /** Human-readable tenant identifier. At least one of tenantSlug/tenantId is required at runtime. */
  tenantSlug?: string;
  /** Tenant UUID. At least one of tenantSlug/tenantId is required at runtime. */
  tenantId?: string;
  /** PEM-encoded custom CA certificate, for self-signed/dev environments (§6). */
  customCa?: string;
  /** Connection timeout in milliseconds. Defaults to DEFAULT_CONNECT_TIMEOUT_MS. */
  connectTimeoutMs?: number;
  /** Request timeout in milliseconds. Defaults to DEFAULT_REQUEST_TIMEOUT_MS. */
  requestTimeoutMs?: number;
}

export const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
