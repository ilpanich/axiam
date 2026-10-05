import {
  ATTRIBUTE_NAME_FORMATS,
  ATTRIBUTE_SOURCES,
  NAME_ID_FORMATS,
  SAML_BINDINGS,
  VALIDITY_DAYS_DEFAULT,
  VALIDITY_DAYS_MAX,
  VALIDITY_DAYS_MIN,
  type SamlServiceProvider,
  type SamlServiceProviderInput,
} from "@/services/saml";

/**
 * The service-provider form's local model, and everything that converts it to
 * and from the wire.
 *
 * Kept out of the page so the rules that are easy to get subtly wrong are
 * testable without rendering anything:
 *
 * 1. **`encrypt_assertions` is never `true`.** The model has no member for it:
 *    {@link buildServiceProviderInput} writes the literal `false`, so no state
 *    the page can reach changes what is sent (D-2: encryption is not
 *    implemented, and the server refuses `true`).
 * 2. **`entity_id` is immutable** (§29.3 rule 3). On an edit the payload takes
 *    it from the stored registration, never from the form, so even a form
 *    state that was changed cannot ask the server to move it.
 * 3. **An update is a replacement** (§27.4 rule 5). The payload always carries
 *    every member of `SamlServiceProviderInput`, so an edit resets nothing by
 *    omission.
 *
 * None of the checks here is the authority. The server validates every write
 * (`axiam_federation::saml_sp::validate_saml_service_provider` plus the four
 * D-42 refusals); these only turn a `400`-after-submit into a message at the
 * field, for the mistakes that need no network to detect.
 */

export const ACS_MAX = 32;
export const ACS_INDEX_MAX = 65_535;
export const ATTRIBUTE_MAPPINGS_MAX = 64;
export const ALLOWED_GROUPS_MAX = 256;
export const DISPLAY_NAME_MAX_BYTES = 256;
export const ENTITY_ID_MAX_BYTES = 1_024;
export const SAML_NAME_MAX_BYTES = 256;
export const CERTIFICATE_MAX_BYTES = 16 * 1_024;

export interface AcsRow {
  /** Stable React key; not sent. */
  key: string;
  url: string;
  /** Open on the way in: an unknown value is kept so it is visible, and refused on save. */
  binding: string;
  /** Text, so a half-typed number is representable. */
  index: string;
  isDefault: boolean;
}

export interface MappingRow {
  /** Stable React key; not sent. */
  key: string;
  samlName: string;
  /** `""` is "not set" (sent as `null`). */
  nameFormat: string;
  source: string;
}

export interface SamlForm {
  enabled: boolean;
  displayName: string;
  entityId: string;
  acs: AcsRow[];
  sloUrl: string;
  /** `""` is none. */
  sloBinding: string;
  nameIdFormat: string;
  signResponses: boolean;
  spSigningCertPem: string;
  spEncryptionCertPem: string;
  wantAuthnRequestsSigned: boolean;
  allowIdpInitiated: boolean;
  mappings: MappingRow[];
  /** Ids of AXIAM groups of this tenant. Empty means every active user may sign in. */
  allowedGroups: string[];
}

let rowCounter = 0;

export function newAcsRow(rows: readonly AcsRow[] = []): AcsRow {
  rowCounter += 1;
  const taken = new Set(rows.map((r) => r.index.trim()));
  let index = 0;
  while (taken.has(String(index))) index += 1;
  return {
    key: `acs-${rowCounter}`,
    url: "",
    binding: "http_post",
    index: String(index),
    isDefault: rows.length === 0,
  };
}

export function newMappingRow(
  samlName = "",
  source = "",
  nameFormat = "",
): MappingRow {
  rowCounter += 1;
  return { key: `attr-${rowCounter}`, samlName, nameFormat, source };
}

/** The defaults the server applies to an omitted member (§29.2). */
export function emptyForm(): SamlForm {
  return {
    enabled: true,
    displayName: "",
    entityId: "",
    acs: [newAcsRow()],
    sloUrl: "",
    sloBinding: "",
    nameIdFormat: "persistent",
    signResponses: true,
    spSigningCertPem: "",
    spEncryptionCertPem: "",
    wantAuthnRequestsSigned: false,
    allowIdpInitiated: false,
    mappings: [],
    allowedGroups: [],
  };
}

/**
 * A form seeded from a stored registration **or from an imported draft** — the
 * two share a shape, and a draft may omit any optional member, which takes the
 * server's default exactly as it would on a write.
 *
 * `encrypt_assertions` is read from neither: see the file header, rule 1.
 */
export function formFromServiceProvider(
  sp: SamlServiceProviderInput | SamlServiceProvider,
): SamlForm {
  return {
    enabled: sp.enabled ?? true,
    displayName: sp.display_name,
    entityId: sp.entity_id,
    acs: sp.acs_urls.map((a) => {
      rowCounter += 1;
      return {
        key: `acs-${rowCounter}`,
        url: a.url,
        binding: a.binding,
        index: String(a.index),
        isDefault: a.is_default === true,
      };
    }),
    sloUrl: sp.slo_url ?? "",
    sloBinding: sp.slo_binding ?? "",
    nameIdFormat: sp.name_id_format ?? "persistent",
    signResponses: sp.sign_responses ?? true,
    spSigningCertPem: sp.sp_signing_cert_pem ?? "",
    spEncryptionCertPem: sp.sp_encryption_cert_pem ?? "",
    wantAuthnRequestsSigned: sp.want_authn_requests_signed ?? false,
    allowIdpInitiated: sp.allow_idp_initiated ?? false,
    mappings: (sp.attribute_mappings ?? []).map((m) =>
      newMappingRow(m.saml_name, m.source, m.name_format ?? ""),
    ),
    allowedGroups: [...(sp.allowed_groups ?? [])],
  };
}

// ─── Validation ───────────────────────────────────────────────────────────────

const encoder = new TextEncoder();

function byteLength(text: string): number {
  return encoder.encode(text).length;
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Whether `url` is a registrable endpoint, by the rule an OAuth2 redirect URI
 * is held to (§29.3 rule 1): absolute, `https` (`http` only for `localhost`,
 * `127.0.0.1` and `[::1]`), no fragment, no `*`. Returns the reason, or `null`.
 */
export function endpointProblem(url: string): string | null {
  if (url.includes("*")) return "may not contain *: URLs are matched exactly, with no wildcards";
  if (url.includes("#")) return "may not carry a fragment";
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "must be an absolute URL";
  }
  if (parsed.protocol === "https:") return null;
  if (parsed.protocol === "http:" && LOOPBACK_HOSTS.has(parsed.hostname)) return null;
  return "must be https (http is accepted only for localhost, 127.0.0.1 and [::1])";
}

const CERT_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/**
 * Whether `text` is empty or exactly one `CERTIFICATE` PEM block. A private key
 * is refused by name, as the server refuses it: pasting one here is the mistake
 * that matters, and the page must never send it.
 */
export function certificateProblem(text: string): string | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  if (/PRIVATE KEY-----/.test(trimmed)) {
    return "is a private key. Paste the certificate only, never a key";
  }
  const blocks = trimmed.match(CERT_BLOCK) ?? [];
  if (blocks.length !== 1 || trimmed.replace(CERT_BLOCK, "").trim() !== "") {
    return "must be exactly one PEM certificate (-----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----)";
  }
  if (byteLength(trimmed) > CERTIFICATE_MAX_BYTES) {
    return `is over ${CERTIFICATE_MAX_BYTES / 1024} KiB`;
  }
  return null;
}

function wholeNumber(text: string): number | null {
  return /^\d+$/.test(text.trim()) ? Number(text.trim()) : null;
}

const KNOWN_BINDINGS: readonly string[] = SAML_BINDINGS;
const KNOWN_NAME_ID_FORMATS: readonly string[] = NAME_ID_FORMATS;
const KNOWN_SOURCES: readonly string[] = ATTRIBUTE_SOURCES;
const KNOWN_NAME_FORMATS: readonly string[] = ATTRIBUTE_NAME_FORMATS;

/**
 * The first mistake detectable without a network, or `null`. The server's
 * validator is the authority: this resolves no host, parses no certificate and
 * knows nothing about the tenant's groups.
 *
 * `stored` is the registration being edited, or `null` on create; on an edit
 * the entity id is not checked, because it is not sent.
 */
export function validateForm(
  form: SamlForm,
  stored: SamlServiceProvider | null,
): string | null {
  const name = form.displayName.trim();
  if (!name) return "Enter a display name.";
  if (byteLength(name) > DISPLAY_NAME_MAX_BYTES) {
    return `The display name is at most ${DISPLAY_NAME_MAX_BYTES} bytes.`;
  }
  if (CONTROL_CHARS.test(name)) return "The display name may not contain control characters.";

  if (stored === null) {
    const entityId = form.entityId.trim();
    if (!entityId) return "Enter the service provider's entity ID.";
    if (byteLength(entityId) > ENTITY_ID_MAX_BYTES) {
      return `The entity ID is at most ${ENTITY_ID_MAX_BYTES} bytes.`;
    }
    if (CONTROL_CHARS.test(entityId)) return "The entity ID may not contain control characters.";
  }

  if (form.acs.length === 0) return "Add at least one assertion consumer service (ACS) URL.";
  if (form.acs.length > ACS_MAX) return `At most ${ACS_MAX} ACS endpoints.`;
  const urls = new Set<string>();
  const indexes = new Set<number>();
  let defaults = 0;
  for (const [i, row] of form.acs.entries()) {
    const where = `ACS endpoint #${i + 1}`;
    const url = row.url.trim();
    if (!url) return `${where}: enter the URL.`;
    const problem = endpointProblem(url);
    if (problem) return `${where}: the URL ${problem}.`;
    if (urls.has(url)) return `${where}: the URL is listed twice.`;
    urls.add(url);
    if (!KNOWN_BINDINGS.includes(row.binding)) {
      return `${where}: choose a binding (HTTP-POST or HTTP-Redirect).`;
    }
    const index = wholeNumber(row.index);
    if (index === null || index > ACS_INDEX_MAX) {
      return `${where}: the index must be a whole number from 0 to ${ACS_INDEX_MAX}.`;
    }
    if (indexes.has(index)) return `${where}: the index ${index} is used twice.`;
    indexes.add(index);
    if (row.isDefault) defaults += 1;
  }
  if (defaults > 1) return "At most one ACS endpoint can be the default.";

  const slo = form.sloUrl.trim();
  if (slo) {
    const problem = endpointProblem(slo);
    if (problem) return `The single-logout URL ${problem}.`;
    if (!KNOWN_BINDINGS.includes(form.sloBinding)) {
      return "Choose the binding the single-logout URL accepts.";
    }
  } else if (form.sloBinding !== "") {
    return "A single-logout binding needs a single-logout URL: enter the URL, or clear the binding.";
  }

  if (!KNOWN_NAME_ID_FORMATS.includes(form.nameIdFormat)) {
    return "Choose a NameID format (persistent or e-mail address).";
  }

  for (const [label, text] of [
    ["signing certificate", form.spSigningCertPem],
    ["encryption certificate", form.spEncryptionCertPem],
  ] as const) {
    const problem = certificateProblem(text);
    if (problem) return `The service provider's ${label} ${problem}.`;
  }
  if (form.wantAuthnRequestsSigned && form.spSigningCertPem.trim() === "") {
    return "Requiring signed requests needs the service provider's signing certificate.";
  }

  if (form.mappings.length > ATTRIBUTE_MAPPINGS_MAX) {
    return `At most ${ATTRIBUTE_MAPPINGS_MAX} attribute mappings.`;
  }
  const names = new Set<string>();
  for (const [i, row] of form.mappings.entries()) {
    const where = `Attribute mapping #${i + 1}`;
    const samlName = row.samlName.trim();
    if (!samlName) return `${where}: enter the attribute name.`;
    if (byteLength(samlName) > SAML_NAME_MAX_BYTES) {
      return `${where}: the name is at most ${SAML_NAME_MAX_BYTES} bytes.`;
    }
    if (names.has(samlName)) return `${where}: the name ${samlName} is used twice.`;
    names.add(samlName);
    if (!KNOWN_SOURCES.includes(row.source)) return `${where}: choose where the value comes from.`;
    if (row.nameFormat !== "" && !KNOWN_NAME_FORMATS.includes(row.nameFormat)) {
      return `${where}: choose a name format, or leave it unset.`;
    }
  }

  if (form.allowedGroups.length > ALLOWED_GROUPS_MAX) {
    return `At most ${ALLOWED_GROUPS_MAX} allowed groups.`;
  }
  return null;
}

// ─── Payload ──────────────────────────────────────────────────────────────────

/**
 * A certificate member as sent: `null` when blank, the stored string
 * byte-for-byte when the text only differs from it by surrounding whitespace
 * (so an unrelated edit does not read as a certificate change in the audit
 * row), otherwise the trimmed block with the newline the server stores.
 */
function certificateValue(text: string, storedValue: string | null | undefined): string | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  if (storedValue != null && storedValue.trim() === trimmed) return storedValue;
  return `${trimmed}\n`;
}

/**
 * The complete registration, for `create_service_provider` and — as a
 * replacement — `update_service_provider`.
 *
 * - `encrypt_assertions` is the literal `false` (file header, rule 1).
 * - `entity_id` is the stored one on an edit (rule 2), the typed one on create.
 * - Every optional member is present, so a replacement resets nothing (rule 3).
 */
export function buildServiceProviderInput(
  form: SamlForm,
  stored: SamlServiceProvider | null,
): SamlServiceProviderInput {
  const slo = form.sloUrl.trim();
  return {
    enabled: form.enabled,
    display_name: form.displayName.trim(),
    entity_id: stored ? stored.entity_id : form.entityId.trim(),
    acs_urls: form.acs.map((row) => ({
      url: row.url.trim(),
      binding: row.binding,
      index: Number(row.index.trim()),
      is_default: row.isDefault,
    })),
    slo_url: slo === "" ? null : slo,
    slo_binding: slo === "" ? null : form.sloBinding,
    name_id_format: form.nameIdFormat,
    sign_responses: form.signResponses,
    encrypt_assertions: false,
    sp_signing_cert_pem: certificateValue(form.spSigningCertPem, stored?.sp_signing_cert_pem),
    sp_encryption_cert_pem: certificateValue(
      form.spEncryptionCertPem,
      stored?.sp_encryption_cert_pem,
    ),
    want_authn_requests_signed: form.wantAuthnRequestsSigned,
    allow_idp_initiated: form.allowIdpInitiated,
    attribute_mappings: form.mappings.map((row) => ({
      saml_name: row.samlName.trim(),
      name_format: row.nameFormat === "" ? null : row.nameFormat,
      source: row.source,
    })),
    allowed_groups: [...form.allowedGroups],
  };
}

// ─── Metadata import ──────────────────────────────────────────────────────────

/**
 * What the administrator pasted into the import panel: **exactly one** of an
 * XML document and an `https` URL, or the reason it is not.
 *
 * The XML is sent as typed, not trimmed or re-encoded: the server holds the
 * document to its size cap and refuses markup declarations on the bytes.
 */
export function importRequest(
  xml: string,
  url: string,
): { ok: true; body: { metadata_xml: string } | { metadata_url: string } } | { ok: false; reason: string } {
  const doc = xml.trim();
  const target = url.trim();
  if (doc && target) return { ok: false, reason: "Give either the metadata XML or a URL, not both." };
  if (!doc && !target) return { ok: false, reason: "Paste the metadata XML, or enter its https URL." };
  if (doc) return { ok: true, body: { metadata_xml: xml } };
  if (!/^https:\/\//i.test(target)) {
    return { ok: false, reason: "The metadata URL must start with https://." };
  }
  return { ok: true, body: { metadata_url: target } };
}

/**
 * The warning the server raises for a document that carries a signature it did
 * not evaluate (D-41: there is no anchor to evaluate it against). It is the
 * one warning the page raises above the rest.
 */
export function isSignatureWarning(warning: string): boolean {
  return /signature[^.]*not verified|unverified[^.]*signature/i.test(warning);
}

// ─── Credential issuance ──────────────────────────────────────────────────────

/** The validity entered, or the reason it is not acceptable. */
export function parseValidityDays(
  text: string,
): { ok: true; days: number } | { ok: false; reason: string } {
  const n = wholeNumber(text);
  if (n === null || n < VALIDITY_DAYS_MIN || n > VALIDITY_DAYS_MAX) {
    return {
      ok: false,
      reason: `Validity must be a whole number of days from ${VALIDITY_DAYS_MIN} to ${VALIDITY_DAYS_MAX}.`,
    };
  }
  return { ok: true, days: n };
}

export { VALIDITY_DAYS_DEFAULT };
