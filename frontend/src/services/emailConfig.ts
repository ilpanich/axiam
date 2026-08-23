import api from "@/lib/api";

// ─── Provider configuration ───────────────────────────────────────────────────

/**
 * Which email backend delivers verification and password-reset mail.
 *
 * The wire values are the backend's `EmailProviderKind` in `snake_case` —
 * `send_grid` really does carry the underscore, because it is derived from the
 * Rust variant name rather than from the vendor's spelling.
 */
export const EMAIL_PROVIDER_KINDS = [
  "smtp",
  "send_grid",
  "postmark",
  "resend",
  "brevo",
] as const;

export type EmailProviderKind = (typeof EMAIL_PROVIDER_KINDS)[number];

export const EMAIL_PROVIDER_LABELS: Record<EmailProviderKind, string> = {
  smtp: "SMTP",
  send_grid: "SendGrid",
  postmark: "Postmark",
  resend: "Resend",
  brevo: "Brevo",
};

/**
 * `ProviderConfig::Smtp` on the wire.
 *
 * `password` is **write-only**: the backend marks it `skip_serializing`, so it
 * never comes back on a GET. On the write path an empty string is the
 * "no new secret supplied — preserve the stored one" sentinel (D-02), which is
 * what lets an operator edit the host or port without re-entering the
 * password.
 */
export interface SmtpProvider {
  kind: "smtp";
  host: string;
  port: number;
  username: string;
  /** Write-only. Omit or send "" to preserve the stored secret. */
  password?: string;
  /** STARTTLS (true) or implicit TLS (false). */
  starttls: boolean;
}

/** `ProviderConfig::{SendGrid,Postmark,Resend,Brevo}` on the wire. */
export interface ApiProvider {
  kind: Exclude<EmailProviderKind, "smtp">;
  /** Write-only, same omit-preserves-stored contract as SmtpProvider.password. */
  api_key?: string;
  /** Override base URL, for testing or a self-hosted instance. */
  api_url?: string | null;
}

export type ProviderConfig = SmtpProvider | ApiProvider;

// ─── Domain models ────────────────────────────────────────────────────────────

/** A fully resolved org-level email configuration. Secrets are never present. */
export interface EmailConfig {
  id: string;
  scope: string;
  scope_id: string;
  enabled: boolean;
  from_name: string;
  from_email: string;
  reply_to: string | null;
  provider: ProviderConfig;
  created_at: string;
  updated_at: string;
}

/**
 * A tenant's partial overrides. Every field is optional and `undefined` means
 * "inherit the org baseline" — which is why this cannot reuse `EmailConfig`.
 */
export interface EmailConfigOverride {
  enabled?: boolean;
  from_name?: string;
  from_email?: string;
  /**
   * Three states, not two. `undefined` inherits the organization's reply-to;
   * `null` clears it for this tenant; a string replaces it.
   *
   * Schema v43 gave the tenant row its own `reply_to` column plus a
   * `reply_to_overridden` flag, because a stored NULL cannot otherwise be
   * told apart from "never set". Before that the field round-tripped to
   * nothing and the panel deliberately offered no control for it.
   */
  reply_to?: string | null;
  /** Full provider replacement — there is no partial merge within a provider. */
  provider?: ProviderConfig;
}

// ─── Request payloads ─────────────────────────────────────────────────────────

export interface SetOrgEmailConfigPayload {
  enabled: boolean;
  from_name: string;
  from_email: string;
  reply_to: string | null;
  provider: ProviderConfig;
}

export type SetTenantEmailOverridePayload = EmailConfigOverride;

/** What a delivery self-test did — the response of the `/email-config/test` endpoints. */
export interface EmailTestResult {
  /** Which provider the effective configuration resolved to. */
  provider: string;
  /** Where the message went — always the caller's own address. */
  to: string;
  /** The provider's message id, when it returns one. */
  message_id: string | null;
}

// ─── Validation ───────────────────────────────────────────────────────────────

/**
 * Client-side mirror of `axiam_core::models::email::validate_email_config`.
 *
 * Structural only — matching the backend, which deliberately makes no live
 * SMTP/API connectivity check at write time (D-15). Returns `null` when valid.
 */
export function validateOrgEmailConfig(
  input: SetOrgEmailConfigPayload
): string | null {
  if (!input.from_name.trim()) {
    return "From name must not be empty.";
  }
  if (!input.from_email.trim() || !input.from_email.includes("@")) {
    return "From address must be a valid email address.";
  }
  if (
    input.reply_to !== null &&
    (!input.reply_to.trim() || !input.reply_to.includes("@"))
  ) {
    return "Reply-to must be a valid email address if provided.";
  }
  if (input.provider.kind === "smtp") {
    if (!input.provider.host.trim()) {
      return "SMTP host must not be empty.";
    }
    if (!input.provider.port || input.provider.port <= 0) {
      return "SMTP port must be greater than 0.";
    }
  }
  // An empty api_key is the "preserve the stored secret" sentinel, not a
  // violation — so API providers have nothing structural left to check.
  return null;
}

// ─── Service ──────────────────────────────────────────────────────────────────

/**
 * Both scopes are singletons: there is no list, and a GET on a scope that has
 * never been configured answers 404 rather than an empty body. `get*` maps
 * that 404 to `null` so "not configured yet" is a value the caller can render
 * rather than an error it has to special-case.
 */
function nullOn404(err: unknown): null {
  const status = (err as { response?: { status?: number } })?.response?.status;
  if (status === 404) return null;
  throw err;
}

export const emailConfigService = {
  getOrgConfig: (orgId: string): Promise<EmailConfig | null> =>
    api
      .get<EmailConfig>(`/api/v1/organizations/${orgId}/email-config`)
      .then((r) => r.data)
      .catch(nullOn404),

  setOrgConfig: (
    orgId: string,
    payload: SetOrgEmailConfigPayload
  ): Promise<EmailConfig> =>
    api
      .put<EmailConfig>(`/api/v1/organizations/${orgId}/email-config`, payload)
      .then((r) => r.data),

  deleteOrgConfig: (orgId: string): Promise<void> =>
    api
      .delete(`/api/v1/organizations/${orgId}/email-config`)
      .then(() => undefined),

  getTenantOverride: (tenantId: string): Promise<EmailConfigOverride | null> =>
    api
      .get<EmailConfigOverride>(`/api/v1/tenants/${tenantId}/email-config`)
      .then((r) => r.data)
      .catch(nullOn404),

  setTenantOverride: (
    tenantId: string,
    payload: SetTenantEmailOverridePayload
  ): Promise<EmailConfigOverride> =>
    api
      .put<EmailConfigOverride>(
        `/api/v1/tenants/${tenantId}/email-config`,
        payload
      )
      .then((r) => r.data),

  deleteTenantOverride: (tenantId: string): Promise<void> =>
    api.delete(`/api/v1/tenants/${tenantId}/email-config`).then(() => undefined),

  /**
   * Send one real message through the effective configuration.
   *
   * The recipient is fixed server-side to the caller's own address — the
   * endpoint takes no recipient parameter, so it cannot be used to mail anyone
   * else. A rejection comes back as a 400 carrying the provider's own words
   * (an unverified sender domain, a revoked key), which is otherwise only
   * visible in the mail consumer's dead-letter log.
   */
  sendOrgTest: (orgId: string): Promise<EmailTestResult> =>
    api
      .post<EmailTestResult>(`/api/v1/organizations/${orgId}/email-config/test`)
      .then((r) => r.data),

  sendTenantTest: (tenantId: string): Promise<EmailTestResult> =>
    api
      .post<EmailTestResult>(`/api/v1/tenants/${tenantId}/email-config/test`)
      .then((r) => r.data),
};
