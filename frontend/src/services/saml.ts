import api from "@/lib/api";
import type { PaginatedResult } from "@/services/_pagination";

/**
 * SAML 2.0 identity-provider administration client (G-2, T23.2.6).
 *
 * Source of truth for every shape below: contract §29 (`sdks/CONTRACT.md`,
 * "SAML service provider registration"), `sdks/openapi.json` (tag `saml`) and
 * the handler `crates/axiam-api-rest/src/handlers/saml_admin.rs`.
 *
 * # What is deliberately absent
 *
 * - **No `sign_assertions`.** The assertion is signed always; no member exists
 *   to turn that off and none may be added (§29.2).
 * - **No key on {@link SamlIdpCredential}.** The IdP's private key is generated
 *   by the server, sealed, never returned and destroyed on retirement; a type
 *   with a key member that is always absent would lie about every value it
 *   holds (§29.2, §29.5).
 * - **`encrypt_assertions` is `false` on every write the console makes.**
 *   Assertion encryption is not implemented (D-2); the server refuses `true`
 *   with `400`, and a service provider asking for it would be refused at every
 *   sign-on.
 */

// ─── Open string sets ─────────────────────────────────────────────────────────

/**
 * The four string enums of §29.2 (`binding`, `slo_binding`, `name_id_format`,
 * `source`) are **open**: a read decodes a value it does not know, and a write
 * is held to the values below. Reads are therefore typed `string`.
 */
export const SAML_BINDINGS = ["http_post", "http_redirect"] as const;
export type SamlBinding = (typeof SAML_BINDINGS)[number];

export const SAML_BINDING_LABELS: Record<SamlBinding, string> = {
  http_post: "HTTP-POST",
  http_redirect: "HTTP-Redirect",
};

export const NAME_ID_FORMATS = ["persistent", "email_address"] as const;
export type NameIdFormat = (typeof NAME_ID_FORMATS)[number];

export const NAME_ID_FORMAT_LABELS: Record<NameIdFormat, string> = {
  persistent: "Persistent (a pairwise identifier per service provider)",
  email_address: "E-mail address",
};

export const ATTRIBUTE_SOURCES = [
  "username",
  "email",
  "display_name",
  "given_name",
  "family_name",
  "groups",
  "roles",
] as const;
export type AttributeSource = (typeof ATTRIBUTE_SOURCES)[number];

export const ATTRIBUTE_SOURCE_LABELS: Record<AttributeSource, string> = {
  username: "Username",
  email: "E-mail address",
  display_name: "Display name",
  given_name: "Given name",
  family_name: "Family name",
  groups: "Groups",
  roles: "Roles",
};

/** The three SAML `attrname-format` URNs the server accepts (`ATTRIBUTE_NAME_FORMATS`). */
export const ATTRIBUTE_NAME_FORMATS = [
  "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
  "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
  "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
] as const;

export const ATTRIBUTE_NAME_FORMAT_LABELS: Record<
  (typeof ATTRIBUTE_NAME_FORMATS)[number],
  string
> = {
  "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified": "Unspecified",
  "urn:oasis:names:tc:SAML:2.0:attrname-format:uri": "URI",
  "urn:oasis:names:tc:SAML:2.0:attrname-format:basic": "Basic",
};

export const SAML_IDP_SLOTS = ["active", "next"] as const;
export type SamlIdpSlot = (typeof SAML_IDP_SLOTS)[number];

/** `active`, `next` or `retired`; open on the way out. */
export const KNOWN_CREDENTIAL_STATUSES = ["active", "next", "retired"] as const;

// ─── Domain types ─────────────────────────────────────────────────────────────

/** One `AssertionConsumerService` endpoint: the allow-list an assertion may be posted to. */
export interface AcsEndpoint {
  url: string;
  /** Open on the way out. */
  binding: string;
  /** Unsigned 16-bit, unique within the service provider. */
  index: number;
  is_default?: boolean;
}

export interface AttributeMapping {
  saml_name: string;
  name_format?: string | null;
  /** Open on the way out. */
  source: string;
}

/** What every service-provider read and write returns. */
export interface SamlServiceProvider {
  id: string;
  tenant_id: string;
  enabled: boolean;
  display_name: string;
  /** Immutable after create (§29.3 rule 3): the pairwise `NameID` is keyed on it. */
  entity_id: string;
  acs_urls: AcsEndpoint[];
  slo_url?: string | null;
  slo_binding?: string | null;
  name_id_format: string;
  sign_responses: boolean;
  /** Always `false` in this revision (§29.3 rule 2). */
  encrypt_assertions: boolean;
  sp_signing_cert_pem?: string | null;
  sp_encryption_cert_pem?: string | null;
  want_authn_requests_signed: boolean;
  allow_idp_initiated: boolean;
  attribute_mappings: AttributeMapping[];
  allowed_groups: string[];
  created_at: string;
  updated_at: string;
}

/**
 * `create_service_provider`, and `update_service_provider` as a **replacement**.
 *
 * Required: `display_name`, `entity_id`, `acs_urls`. Every optional member that
 * is omitted takes its default on every write, an update included (§27.4 rule
 * 5), so the console always sends the whole registration — see
 * `buildServiceProviderInput` in `pages/saml/samlForm.ts`.
 */
export interface SamlServiceProviderInput {
  display_name: string;
  entity_id: string;
  acs_urls: AcsEndpoint[];
  enabled?: boolean;
  slo_url?: string | null;
  slo_binding?: string | null;
  name_id_format?: string;
  sign_responses?: boolean;
  /** The console only ever sends `false`. */
  encrypt_assertions?: boolean;
  sp_signing_cert_pem?: string | null;
  sp_encryption_cert_pem?: string | null;
  want_authn_requests_signed?: boolean;
  allow_idp_initiated?: boolean;
  attribute_mappings?: AttributeMapping[];
  allowed_groups?: string[];
}

/**
 * `parse_sp_metadata` — **exactly one** of the two members. A sum type, so a
 * request carrying both or neither cannot be built (§29.2).
 */
export type ParseSamlSpMetadata =
  | { metadata_xml: string; metadata_url?: never }
  | { metadata_url: string; metadata_xml?: never };

/**
 * A parse of SP metadata: **a draft, not a registration**. Nothing is stored
 * until the caller submits `service_provider` to `create_service_provider`, and
 * nothing in it is trusted because it came from a document (D-41, §29.3 rule 6).
 */
export interface SamlSpMetadataDraft {
  service_provider: SamlServiceProviderInput;
  /** Lower-case hex SHA-256 of the certificate DER the draft carries, or null. */
  signing_certificate_fingerprint?: string | null;
  encryption_certificate_fingerprint?: string | null;
  /** Human text. Show it; do not parse it. */
  warnings: string[];
}

/** The tenant's IdP signing credential, **public facts only**. */
export interface SamlIdpCredential {
  id: string;
  tenant_id: string;
  issuer_ca_id: string;
  /** Public: it is what the metadata publishes. */
  certificate_pem: string;
  /** Lower-case hex. */
  serial: string;
  /** Lower-case hex SHA-256 of the certificate DER, for an out-of-band comparison. */
  fingerprint: string;
  not_before: string;
  not_after: string;
  /** One of {@link KNOWN_CREDENTIAL_STATUSES}; open on the way out. */
  status: string;
  created_at: string;
  retired_at?: string | null;
}

export interface IssueSamlIdpCredential {
  issuer_ca_id: string;
  slot: SamlIdpSlot;
  /** 1 to 730; the server defaults an omitted value to 365. */
  validity_days?: number;
}

export interface SamlIdpCredentialPromotion {
  active: SamlIdpCredential;
  /** The credential it replaced, or null when there was none. */
  retired?: SamlIdpCredential | null;
}

export interface SamlIdpInfo {
  tenant_id: string;
  /** Whether this server build serves SAML at all. */
  saml_available: boolean;
  /** The tenant's effective `saml_idp_enabled` setting (D-20). */
  saml_idp_enabled: boolean;
  /** Whether `metadata_url` answers now: available, enabled, and a publishable credential exists. */
  metadata_served: boolean;
  entity_id: string;
  metadata_url: string;
  sso_url: string;
  slo_url: string;
  active_credential_id?: string | null;
  next_credential_id?: string | null;
}

export const VALIDITY_DAYS_MIN = 1;
export const VALIDITY_DAYS_MAX = 730;
export const VALIDITY_DAYS_DEFAULT = 365;

// ─── Service ──────────────────────────────────────────────────────────────────

// Every path is written out in full, as a literal, on purpose: `src/test/apiRoutes.test.ts`
// checks every API path literal in the source against `sdks/openapi.json`, and a
// shared prefix constant (the tenant's saml base) is not a route, so it would need an exemption
// that then hides a typo in every suffix.

/** The collection URL, for `usePaginatedList`. */
export const serviceProvidersPath = (tenantId: string) =>
  `/api/v1/tenants/${tenantId}/saml/service-providers`;

export const samlService = {
  /** Readiness: what an SP is given, and whether it answers yet. Never cached. */
  getIdp: (tenantId: string): Promise<SamlIdpInfo> =>
    api
      .get<SamlIdpInfo>(`/api/v1/tenants/${tenantId}/saml/idp`)
      .then((r) => r.data),

  /** One page; `search` matches the display name, the entity id and the id. */
  listServiceProviders: (
    tenantId: string,
    params: { offset?: number; limit?: number; search?: string } = {},
  ): Promise<PaginatedResult<SamlServiceProvider>> =>
    api
      .get<PaginatedResult<SamlServiceProvider>>(
        `/api/v1/tenants/${tenantId}/saml/service-providers`,
        {
          params: {
            ...(params.offset !== undefined ? { offset: params.offset } : {}),
            ...(params.limit !== undefined ? { limit: params.limit } : {}),
            ...(params.search?.trim() ? { search: params.search.trim() } : {}),
          },
        },
      )
      .then((r) => r.data),

  getServiceProvider: (
    tenantId: string,
    spId: string,
  ): Promise<SamlServiceProvider> =>
    api
      .get<SamlServiceProvider>(
        `/api/v1/tenants/${tenantId}/saml/service-providers/${spId}`,
      )
      .then((r) => r.data),

  createServiceProvider: (
    tenantId: string,
    input: SamlServiceProviderInput,
  ): Promise<SamlServiceProvider> =>
    api
      .post<SamlServiceProvider>(
        `/api/v1/tenants/${tenantId}/saml/service-providers`,
        input,
      )
      .then((r) => r.data),

  /**
   * A **replacement** (`PUT`): an omitted optional member resets to its
   * default. Send the whole registration, and never a different `entity_id`
   * (`400`).
   */
  updateServiceProvider: (
    tenantId: string,
    spId: string,
    input: SamlServiceProviderInput,
  ): Promise<SamlServiceProvider> =>
    api
      .put<SamlServiceProvider>(
        `/api/v1/tenants/${tenantId}/saml/service-providers/${spId}`,
        input,
      )
      .then((r) => r.data),

  /**
   * Removes the registration and its participant records. **Ends no session**:
   * users already signed in to the SP stay signed in there until their own
   * session ends (§29.3 rule 5).
   */
  deleteServiceProvider: (tenantId: string, spId: string): Promise<void> =>
    api
      .delete(`/api/v1/tenants/${tenantId}/saml/service-providers/${spId}`)
      .then(() => undefined),

  /** Parses and **never stores**. `503` when the server was built without SAML. */
  parseSpMetadata: (
    tenantId: string,
    body: ParseSamlSpMetadata,
  ): Promise<SamlSpMetadataDraft> =>
    api
      .post<SamlSpMetadataDraft>(
        `/api/v1/tenants/${tenantId}/saml/parse-sp-metadata`,
        body,
      )
      .then((r) => r.data),

  /** A bare array, newest first. Not a page. */
  listIdpCredentials: (tenantId: string): Promise<SamlIdpCredential[]> =>
    api
      .get<SamlIdpCredential[]>(
        `/api/v1/tenants/${tenantId}/saml/idp-credentials`,
      )
      .then((r) => r.data),

  /** Generates an RSA-4096 key server-side: it takes seconds. `409` when the slot is occupied. */
  issueIdpCredential: (
    tenantId: string,
    body: IssueSamlIdpCredential,
  ): Promise<SamlIdpCredential> =>
    api
      .post<SamlIdpCredential>(
        `/api/v1/tenants/${tenantId}/saml/idp-credentials`,
        body,
      )
      .then((r) => r.data),

  /** `next` becomes `active` and the old `active` is retired, in one transaction. `409` for anything but the current `next`. */
  promoteIdpCredential: (
    tenantId: string,
    credentialId: string,
  ): Promise<SamlIdpCredentialPromotion> =>
    api
      .post<SamlIdpCredentialPromotion>(
        `/api/v1/tenants/${tenantId}/saml/idp-credentials/${credentialId}/promote`,
      )
      .then((r) => r.data),

  /**
   * Retires a `next` or an `active` credential and destroys its key. Retiring
   * the **active** one with no successor stops SAML sign-on for the whole
   * tenant at once.
   */
  retireIdpCredential: (
    tenantId: string,
    credentialId: string,
  ): Promise<SamlIdpCredential> =>
    api
      .post<SamlIdpCredential>(
        `/api/v1/tenants/${tenantId}/saml/idp-credentials/${credentialId}/retire`,
      )
      .then((r) => r.data),
};
