import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2 } from "lucide-react";
import {
  federationService,
  validateTokenExchangeTrust,
  DEFAULT_TOKEN_EXCHANGE_TRUST,
  PROVIDER_KINDS,
  PROVIDER_KIND_DEFAULTS,
  type FederationConfig,
  type FederationProtocol,
  type ProviderKind,
  type CreateFederationConfigRequest,
  type UpdateFederationConfigRequest,
  type TokenExchangeTrust,
} from "@/services/federation";
import { ssoLoginService, type PublicFederationProvider } from "@/services/ssoLogin";
import { ProviderIconField } from "./ProviderIconField";
import { ProviderMark } from "@/components/providers/ProviderMark";
import { useAuthStore } from "@/stores/auth";
import { TokenExchangeTrustEditor } from "./TokenExchangeTrustEditor";
import {
  parseScopeMap,
  stringifyAudiences,
  stringifyScopeMap,
} from "./tokenExchangeTrustFormat";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SearchInput } from "@/components/SearchInput";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { cn, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";
import { ToggleField } from "@/components/shared";

// ─── Protocol badge ─────────────────────────────────────────────────────────

const PROTOCOL_BADGE: Record<string, { label: string; className: string }> = {
  OidcConnect: {
    label: "OIDC",
    className: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  },
  Saml: {
    label: "SAML",
    className: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  },
  // Amber rather than another cool colour, deliberately: the OAuth2 variant
  // authenticates by an unsigned userinfo call, and a reader scanning the list
  // should be able to see which providers carry that reduced assurance.
  OAuth2: {
    label: "OAuth2",
    className: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  },
};

function ProtocolBadge({ protocol }: { protocol: string }) {
  const badge = PROTOCOL_BADGE[protocol] ?? {
    label: protocol,
    className: "bg-white/10 text-muted-foreground border-white/20",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        badge.className,
      )}
      title={
        protocol === "OAuth2"
          ? "Authenticates by a userinfo call — there is no signed ID token to verify"
          : undefined
      }
    >
      {badge.label}
    </span>
  );
}

// ─── attribute_map / allowed_algorithms helpers ───────────────────────────────

/** Parse a comma- or space-separated list into a trimmed, non-empty string[]. */
function parseList(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Whether a metadata URL points at an authority that publishes a **templated**
 * issuer.
 *
 * Entra ID's `common` and `organizations` authorities publish
 * `https://login.microsoftonline.com/{tenantid}/v2.0` literally, which means
 * *any* Microsoft tenant can sign in. The server refuses that configuration
 * unless the operator lists the tenants they accept; this is what lets the form
 * say so before they submit, rather than after.
 */
function looksLikeTemplatedIssuer(metadataUrl: string): boolean {
  return /login\.microsoftonline\.com\/(common|organizations)\//i.test(
    metadataUrl,
  );
}

/**
 * Validate + parse the attribute_map textarea. Empty input maps to `{}`.
 * Returns the parsed object, or an `error` string if the JSON is invalid or
 * not a plain object.
 */
function parseAttributeMap(
  raw: string,
): { value: Record<string, unknown> } | { error: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { value: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return { error: "Attribute map must be valid JSON." };
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed)
  ) {
    return { error: "Attribute map must be a JSON object." };
  }
  return { value: parsed as Record<string, unknown> };
}

/** Stringify a server-returned attribute_map for display in the textarea. */
function stringifyAttributeMap(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object" && Object.keys(value).length === 0) return "";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "";
  }
}

// ─── Config form fields ───────────────────────────────────────────────────────

interface ConfigFieldsProps {
  provider: string;
  providerKind: ProviderKind;
  providerSlug: string;
  protocol: FederationProtocol;
  clientId: string;
  clientSecret: string;
  metadataUrl: string;
  idpSigningCertPem: string;
  allowedAlgorithms: string;
  attributeMap: string;
  scopes: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint: string;
  allowedIssuerTenants: string;
  appleTeamId: string;
  appleKeyId: string;
  buttonIcon: string;
  allowTenantInheritance: boolean;
  requirePkce: boolean;
  // Handlers
  onProviderChange: (v: string) => void;
  onProviderKindChange: (v: ProviderKind) => void;
  onProviderSlugChange: (v: string) => void;
  onProtocolChange: (v: FederationProtocol) => void;
  onClientIdChange: (v: string) => void;
  onClientSecretChange: (v: string) => void;
  onMetadataUrlChange: (v: string) => void;
  onIdpSigningCertPemChange: (v: string) => void;
  onAllowedAlgorithmsChange: (v: string) => void;
  onAttributeMapChange: (v: string) => void;
  onScopesChange: (v: string) => void;
  onAuthorizationEndpointChange: (v: string) => void;
  onTokenEndpointChange: (v: string) => void;
  onUserinfoEndpointChange: (v: string) => void;
  onAllowedIssuerTenantsChange: (v: string) => void;
  onAppleTeamIdChange: (v: string) => void;
  onAppleKeyIdChange: (v: string) => void;
  onButtonIconChange: (v: string) => void;
  onAllowTenantInheritanceChange: (v: boolean) => void;
  onRequirePkceChange: (v: boolean) => void;
  idPrefix: string;
  isEditMode?: boolean;
  /** Whether this principal can offer the provider to the organization's tenants. */
  canOfferInheritance?: boolean;
}

const SELECT_CLASS = cn(
  "w-full rounded-md px-3 py-2 text-sm",
  "bg-white/5 border border-primary/20 text-foreground",
  "focus:outline-hidden focus:ring-2 focus:ring-primary/40 focus:border-primary",
  "transition-colors duration-200",
);

function ConfigFields(props: ConfigFieldsProps) {
  const {
    provider,
    providerKind,
    providerSlug,
    protocol,
    clientId,
    clientSecret,
    metadataUrl,
    idpSigningCertPem,
    allowedAlgorithms,
    attributeMap,
    scopes,
    authorizationEndpoint,
    tokenEndpoint,
    userinfoEndpoint,
    allowedIssuerTenants,
    appleTeamId,
    appleKeyId,
    buttonIcon,
    allowTenantInheritance,
    requirePkce,
    idPrefix,
    isEditMode = false,
    canOfferInheritance = false,
  } = props;

  const kindDefaults = PROVIDER_KIND_DEFAULTS[providerKind];
  const isSaml = protocol === "Saml";
  const isOauth2 = protocol === "OAuth2";
  const isOidc = protocol === "OidcConnect";
  const isApple = providerKind === "apple";
  const usesSlug = kindDefaults.usesSlug;
  const templatedIssuer = isOidc && looksLikeTemplatedIssuer(metadataUrl);

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-provider-kind`}>Provider *</Label>
        <select
          id={`${idPrefix}-provider-kind`}
          value={providerKind}
          onChange={(e) =>
            props.onProviderKindChange(e.target.value as ProviderKind)
          }
          disabled={isEditMode}
          className={cn(SELECT_CLASS, isEditMode && "opacity-60 cursor-not-allowed")}
          title={
            isEditMode
              ? "The provider cannot be changed after creation"
              : undefined
          }
        >
          {PROVIDER_KINDS.map((k) => (
            <option key={k} value={k} className="bg-[#0d0d2b] text-foreground">
              {PROVIDER_KIND_DEFAULTS[k].label}
            </option>
          ))}
        </select>
        <p className="text-xs text-muted-foreground">
          {isEditMode
            ? "The provider cannot be changed after creation — it decides the protocol and which inherited provider a tenant overrides."
            : "Selects the sign-in button's branding, the defaults below, and which inherited provider a tenant overrides."}
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-provider`}>Display name *</Label>
        <Input
          id={`${idPrefix}-provider`}
          value={provider}
          onChange={(e) => props.onProviderChange(e.target.value)}
          placeholder={kindDefaults.label}
          required
          autoComplete="off"
        />
        <p className="text-xs text-muted-foreground">
          {kindDefaults.hasBundledMark
            ? "Shown in this list. The sign-in button uses the provider's own required wording."
            : `Shown in this list and on the login button — “Sign in with ${provider.trim() || "…"}”.`}
        </p>
      </div>

      {usesSlug && (
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-provider-slug`}>Identifier</Label>
          <Input
            id={`${idPrefix}-provider-slug`}
            value={providerSlug}
            onChange={(e) => props.onProviderSlugChange(e.target.value)}
            placeholder="okta-eu"
            autoComplete="off"
            pattern="[a-z0-9]+(-[a-z0-9]+)*"
          />
          <p className="text-xs text-muted-foreground">
            Lowercase letters, digits and hyphens. Distinguishes two providers
            of the same kind — and it is what a tenant overrides one of them by,
            so an inherited provider and its tenant override must use the same
            identifier.
          </p>
        </div>
      )}

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-protocol`}>Protocol *</Label>
        <select
          id={`${idPrefix}-protocol`}
          value={protocol}
          onChange={(e) =>
            props.onProtocolChange(e.target.value as FederationProtocol)
          }
          disabled={isEditMode || kindDefaults.protocolOptions.length < 2}
          className={cn(
            SELECT_CLASS,
            (isEditMode || kindDefaults.protocolOptions.length < 2) &&
              "opacity-60 cursor-not-allowed",
          )}
          aria-label="Federation protocol"
        >
          {kindDefaults.protocolOptions.map((p) => (
            <option key={p} value={p} className="bg-[#0d0d2b] text-foreground">
              {p === "OidcConnect"
                ? "OIDC (OpenID Connect)"
                : p === "Saml"
                  ? "SAML"
                  : "OAuth2 (userinfo)"}
            </option>
          ))}
        </select>
        {isOauth2 && (
          <p className="text-xs text-amber-400">
            This provider issues no signed ID token, so AXIAM authenticates by
            calling the userinfo endpoint with the access token it just
            received. There is no signature, nonce or audience to verify — the
            trust is in the endpoints and the client secret configured below.
            PKCE is always sent on this protocol.
          </p>
        )}
        {isEditMode && (
          <p className="text-xs text-muted-foreground">
            Protocol cannot be changed after creation.
          </p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-client-id`}>
          {isApple ? "Services ID *" : "Client ID *"}
        </Label>
        <Input
          id={`${idPrefix}-client-id`}
          value={clientId}
          onChange={(e) => props.onClientIdChange(e.target.value)}
          placeholder={isApple ? "com.example.service" : "your-client-id"}
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-client-secret`}>
          {isApple ? "Signing key (.p8 contents)" : "Client Secret"}{" "}
          {isEditMode ? "" : "*"}
        </Label>
        <Input
          id={`${idPrefix}-client-secret`}
          type="password"
          value={clientSecret}
          onChange={(e) => props.onClientSecretChange(e.target.value)}
          placeholder={
            isEditMode
              ? "Leave blank to keep current secret"
              : isApple
                ? "-----BEGIN PRIVATE KEY-----"
                : "your-client-secret"
          }
          autoComplete="new-password"
        />
        {isApple ? (
          <p className="text-xs text-muted-foreground">
            Apple&rsquo;s client secret is a signed JWT that expires within six
            months. Paste the <strong>private key</strong> from your{" "}
            <code>.p8</code> file here and fill in the two identifiers below:
            AXIAM then mints a fresh five-minute secret on every sign-in, so
            there is no expiry to be caught out by. Leave the identifiers blank
            to paste a pre-made JWT instead — and then remember its expiry
            yourself.
          </p>
        ) : (
          isEditMode && (
            <p className="text-xs text-muted-foreground">
              Leave blank to keep the existing secret unchanged.
            </p>
          )
        )}
      </div>

      {isApple && (
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-apple-team`}>Team ID</Label>
            <Input
              id={`${idPrefix}-apple-team`}
              value={appleTeamId}
              onChange={(e) => props.onAppleTeamIdChange(e.target.value)}
              placeholder="ABCDE12345"
              maxLength={10}
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-apple-key`}>Key ID</Label>
            <Input
              id={`${idPrefix}-apple-key`}
              value={appleKeyId}
              onChange={(e) => props.onAppleKeyIdChange(e.target.value)}
              placeholder="KEYID67890"
              maxLength={10}
              autoComplete="off"
            />
          </div>
        </div>
      )}

      {!isOauth2 && (
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-metadata-url`}>
            {isSaml ? "IdP metadata URL" : "Discovery URL"}
            {isOidc ? " *" : ""}
          </Label>
          <Input
            id={`${idPrefix}-metadata-url`}
            type="url"
            value={metadataUrl}
            onChange={(e) => props.onMetadataUrlChange(e.target.value)}
            placeholder={
              isSaml
                ? "https://idp.example.com/metadata.xml"
                : "https://idp.example.com/.well-known/openid-configuration"
            }
            autoComplete="off"
          />
        </div>
      )}

      {isOauth2 && (
        <>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-authorization-endpoint`}>
              Authorization endpoint *
            </Label>
            <Input
              id={`${idPrefix}-authorization-endpoint`}
              type="url"
              value={authorizationEndpoint}
              onChange={(e) =>
                props.onAuthorizationEndpointChange(e.target.value)
              }
              placeholder={kindDefaults.authorizationEndpoint ?? "https://…"}
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-token-endpoint`}>
              Token endpoint *
            </Label>
            <Input
              id={`${idPrefix}-token-endpoint`}
              type="url"
              value={tokenEndpoint}
              onChange={(e) => props.onTokenEndpointChange(e.target.value)}
              placeholder={kindDefaults.tokenEndpoint ?? "https://…"}
              autoComplete="off"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-userinfo-endpoint`}>
              Userinfo endpoint *
            </Label>
            <Input
              id={`${idPrefix}-userinfo-endpoint`}
              type="url"
              value={userinfoEndpoint}
              onChange={(e) => props.onUserinfoEndpointChange(e.target.value)}
              placeholder={kindDefaults.userinfoEndpoint ?? "https://…"}
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              This call <em>is</em> the authentication on this protocol. HTTPS
              only.
            </p>
          </div>
        </>
      )}

      {!isSaml && (
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-scopes`}>Scopes</Label>
          <Input
            id={`${idPrefix}-scopes`}
            value={scopes}
            onChange={(e) => props.onScopesChange(e.target.value)}
            placeholder={kindDefaults.scopes.join(" ")}
            autoComplete="off"
          />
          <p className="text-xs text-muted-foreground">
            Comma- or space-separated.{" "}
            {kindDefaults.scopes.length > 0
              ? `Defaults to “${kindDefaults.scopes.join(" ")}” when left blank.`
              : "Required — a provider's scope names are its own."}
          </p>
        </div>
      )}

      {/* Templated-issuer allow-list. Only surfaced when it is needed: the
          field is meaningless for a tenant-specific authority, and showing it
          always would invite an operator to fill it in for no reason. */}
      {templatedIssuer && (
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-issuer-tenants`}>
            Accepted provider tenants *
          </Label>
          <Input
            id={`${idPrefix}-issuer-tenants`}
            value={allowedIssuerTenants}
            onChange={(e) => props.onAllowedIssuerTenantsChange(e.target.value)}
            placeholder="72f988bf-86f1-41af-91ab-2d7cd011db47"
            autoComplete="off"
          />
          <p className="text-xs text-amber-400">
            This discovery URL is a multi-tenant authority, which means{" "}
            <strong>any</strong> of the provider&rsquo;s tenants could sign in.
            List the tenant IDs you accept, or use a tenant-specific discovery
            URL instead. AXIAM refuses to save it empty.
          </p>
        </div>
      )}

      {/* SAML-only: the certificate that verifies assertions. */}
      {isSaml && (
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-idp-cert`}>
            IdP Signing Certificate (PEM)
          </Label>
          <Textarea
            id={`${idPrefix}-idp-cert`}
            value={idpSigningCertPem}
            onChange={(e) => props.onIdpSigningCertPemChange(e.target.value)}
            placeholder="-----BEGIN CERTIFICATE-----"
            rows={4}
            className="font-mono text-xs"
          />
          <p className="text-xs text-muted-foreground">
            Required for SAML — used to verify signed assertions.
          </p>
        </div>
      )}

      {/* Accepted signature algorithms. Rendered for OIDC as well as SAML —
          it was SAML-only, which is why an Apple config (ES256-signed client
          secret, and providers that sign with something other than RS256)
          could not be configured at all. Hidden for OAuth2, where there is no
          signature and the control would imply a check that does not happen. */}
      {!isOauth2 && (
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-allowed-algos`}>
            Allowed signature algorithms
          </Label>
          <Input
            id={`${idPrefix}-allowed-algos`}
            value={allowedAlgorithms}
            onChange={(e) => props.onAllowedAlgorithmsChange(e.target.value)}
            placeholder={kindDefaults.allowedAlgorithms.join(" ") || "RS256"}
            autoComplete="off"
          />
          <p className="text-xs text-muted-foreground">
            Comma- or space-separated.{" "}
            {isOidc
              ? "Applied to the ID token's JOSE header; anything outside this list is rejected."
              : "Applied to the assertion signature."}{" "}
            {kindDefaults.allowedAlgorithms.length > 0 &&
              `Defaults to ${kindDefaults.allowedAlgorithms.join(" ")}.`}
          </p>
        </div>
      )}

      {!kindDefaults.hasBundledMark && (
        <ProviderIconField
          value={buttonIcon}
          onChange={props.onButtonIconChange}
          idPrefix={idPrefix}
          displayName={provider}
        />
      )}

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-attribute-map`}>
          Attribute Map (JSON)
        </Label>
        <Textarea
          id={`${idPrefix}-attribute-map`}
          value={attributeMap}
          onChange={(e) => props.onAttributeMapChange(e.target.value)}
          placeholder={'{\n  "email": "mail",\n  "display_name": "cn"\n}'}
          rows={4}
          className="font-mono text-xs"
        />
        <p className="text-xs text-muted-foreground">
          Maps this provider&rsquo;s claims onto AXIAM user fields. Keys must be
          one of <code>external_subject</code>, <code>username</code>,{" "}
          <code>email</code>, <code>email_verified</code> or{" "}
          <code>display_name</code>; values are claim paths (<code>user.email</code>{" "}
          reaches a nested claim) or a literal prefixed with <code>@</code>{" "}
          (<code>&quot;email_verified&quot;: &quot;@true&quot;</code> accepts an
          address the provider does not flag). Leave blank for the defaults.
        </p>
      </div>

      {canOfferInheritance && (
        <ToggleField
          id={`${idPrefix}-allow-inheritance`}
          label="Offer to this organization's tenants"
          checked={allowTenantInheritance}
          onChange={props.onAllowTenantInheritanceChange}
          description="Tenants that have not configured a provider of this kind themselves will show this one on their login page. A tenant's own config of the same kind always wins — including a disabled one."
        />
      )}

      {isOidc && (
        <ToggleField
          id={`${idPrefix}-require-pkce`}
          label="Send PKCE"
          checked={requirePkce}
          onChange={props.onRequirePkceChange}
          description="Adds a proof key to the authorization request. Optional here — the server-side nonce already binds the code to this login — and always on for the OAuth2 protocol, where it is the only replay protection left."
        />
      )}
    </>
  );
}

// ─── Form state hook ──────────────────────────────────────────────────────────

/** Derive a slug from a display name, for the generic kinds. */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function useConfigFormState() {
  const [provider, setProvider] = useState("");
  const [providerKind, setProviderKindRaw] =
    useState<ProviderKind>("generic_oidc");
  const [providerSlug, setProviderSlug] = useState("");
  const [protocol, setProtocol] = useState<FederationProtocol>("OidcConnect");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [metadataUrl, setMetadataUrl] = useState("");
  const [idpSigningCertPem, setIdpSigningCertPem] = useState("");
  const [allowedAlgorithms, setAllowedAlgorithms] = useState("");
  const [attributeMap, setAttributeMap] = useState("");
  const [scopes, setScopes] = useState("");
  const [authorizationEndpoint, setAuthorizationEndpoint] = useState("");
  const [tokenEndpoint, setTokenEndpoint] = useState("");
  const [userinfoEndpoint, setUserinfoEndpoint] = useState("");
  const [allowedIssuerTenants, setAllowedIssuerTenants] = useState("");
  const [appleTeamId, setAppleTeamId] = useState("");
  const [appleKeyId, setAppleKeyId] = useState("");
  const [buttonIcon, setButtonIcon] = useState("");
  const [allowTenantInheritance, setAllowTenantInheritance] = useState(false);
  const [requirePkce, setRequirePkce] = useState(false);
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState("");
  const [tokenExchange, setTokenExchange] = useState<TokenExchangeTrust>(
    DEFAULT_TOKEN_EXCHANGE_TRUST,
  );
  const [audiencesText, setAudiencesText] = useState("");
  const [scopeMapText, setScopeMapText] = useState("");

  /**
   * Selecting a provider rewrites the form's defaults.
   *
   * Only the fields the *previous* kind supplied are replaced, so an operator
   * who has typed a client id and then realises they picked the wrong provider
   * does not lose it — but the endpoints, scopes and discovery URL, which are
   * facts about the provider rather than about this deployment, do change.
   */
  function setProviderKind(next: ProviderKind) {
    const d = PROVIDER_KIND_DEFAULTS[next];
    setProviderKindRaw(next);
    setProtocol(d.protocol);
    setMetadataUrl(d.metadataUrl ?? "");
    setAuthorizationEndpoint(d.authorizationEndpoint ?? "");
    setTokenEndpoint(d.tokenEndpoint ?? "");
    setUserinfoEndpoint(d.userinfoEndpoint ?? "");
    setScopes("");
    setAllowedAlgorithms("");
    if (!d.usesSlug) setProviderSlug("");
    if (d.hasBundledMark) setButtonIcon("");
    if (next !== "apple") {
      setAppleTeamId("");
      setAppleKeyId("");
    }
    // A display name the operator has not touched follows the provider, so the
    // common case is one click.
    setProvider((current) =>
      current === "" ||
      Object.values(PROVIDER_KIND_DEFAULTS).some((x) => x.label === current)
        ? d.label
        : current,
    );
  }

  function reset() {
    setProvider("");
    setProviderKindRaw("generic_oidc");
    setProviderSlug("");
    setProtocol("OidcConnect");
    setClientId("");
    setClientSecret("");
    setMetadataUrl("");
    setIdpSigningCertPem("");
    setAllowedAlgorithms("");
    setAttributeMap("");
    setScopes("");
    setAuthorizationEndpoint("");
    setTokenEndpoint("");
    setUserinfoEndpoint("");
    setAllowedIssuerTenants("");
    setAppleTeamId("");
    setAppleKeyId("");
    setButtonIcon("");
    setAllowTenantInheritance(false);
    setRequirePkce(false);
    setEnabled(true);
    setError("");
    setTokenExchange(DEFAULT_TOKEN_EXCHANGE_TRUST);
    setAudiencesText("");
    setScopeMapText("");
  }

  function load(config: FederationConfig) {
    const kind =
      config.provider_kind ??
      (config.protocol === "Saml" ? "generic_saml" : "generic_oidc");
    setProvider(config.provider);
    setProviderKindRaw(kind);
    setProviderSlug(config.provider_slug ?? "");
    setProtocol(
      config.protocol === "Saml"
        ? "Saml"
        : config.protocol === "OAuth2"
          ? "OAuth2"
          : "OidcConnect",
    );
    setClientId(config.client_id);
    // client_secret is write-only — never returned, so never prefilled.
    setClientSecret("");
    setMetadataUrl(config.metadata_url ?? "");
    setIdpSigningCertPem("");
    setAllowedAlgorithms((config.allowed_algorithms ?? []).join(" "));
    setAttributeMap(stringifyAttributeMap(config.attribute_map));
    setScopes((config.scopes ?? []).join(" "));
    setAuthorizationEndpoint(config.authorization_endpoint ?? "");
    setTokenEndpoint(config.token_endpoint ?? "");
    setUserinfoEndpoint(config.userinfo_endpoint ?? "");
    setAllowedIssuerTenants((config.allowed_issuer_tenants ?? []).join(" "));
    setAppleTeamId(config.apple_team_id ?? "");
    setAppleKeyId(config.apple_key_id ?? "");
    setButtonIcon(config.button_icon ?? "");
    setAllowTenantInheritance(config.allow_tenant_inheritance ?? false);
    setRequirePkce(config.pkce_required ?? false);
    setEnabled(config.enabled);
    setError("");
    const trust = config.token_exchange ?? DEFAULT_TOKEN_EXCHANGE_TRUST;
    setTokenExchange(trust);
    setAudiencesText(stringifyAudiences(trust.accepted_audiences));
    setScopeMapText(stringifyScopeMap(trust.scope_map));
  }

  /** Prefill the create form to override an inherited provider. */
  function seedOverride(p: PublicFederationProvider) {
    reset();
    setProviderKindRaw(p.provider_kind);
    const d = PROVIDER_KIND_DEFAULTS[p.provider_kind];
    setProtocol(p.protocol);
    setProvider(p.display_name);
    setMetadataUrl(d.metadataUrl ?? "");
    setAuthorizationEndpoint(d.authorizationEndpoint ?? "");
    setTokenEndpoint(d.tokenEndpoint ?? "");
    setUserinfoEndpoint(d.userinfoEndpoint ?? "");
    // The slug is what the override matches on, so it has to be the same one.
    if (d.usesSlug) setProviderSlug(slugify(p.display_name));
  }

  /** Everything the form contributes to a create/update payload. */
  function loginProviderPayload() {
    return {
      provider_slug: providerSlug.trim() ? providerSlug.trim() : null,
      allow_tenant_inheritance: allowTenantInheritance,
      scopes: parseList(scopes),
      authorization_endpoint: authorizationEndpoint.trim() || null,
      token_endpoint: tokenEndpoint.trim() || null,
      userinfo_endpoint: userinfoEndpoint.trim() || null,
      allowed_issuer_tenants: parseList(allowedIssuerTenants),
      apple_team_id: appleTeamId.trim() || null,
      apple_key_id: appleKeyId.trim() || null,
      require_pkce: requirePkce,
      button_icon: buttonIcon || null,
    };
  }

  return {
    provider,
    setProvider,
    providerKind,
    setProviderKind,
    providerSlug,
    setProviderSlug,
    protocol,
    setProtocol,
    clientId,
    setClientId,
    clientSecret,
    setClientSecret,
    metadataUrl,
    setMetadataUrl,
    idpSigningCertPem,
    setIdpSigningCertPem,
    allowedAlgorithms,
    setAllowedAlgorithms,
    attributeMap,
    setAttributeMap,
    scopes,
    setScopes,
    authorizationEndpoint,
    setAuthorizationEndpoint,
    tokenEndpoint,
    setTokenEndpoint,
    userinfoEndpoint,
    setUserinfoEndpoint,
    allowedIssuerTenants,
    setAllowedIssuerTenants,
    appleTeamId,
    setAppleTeamId,
    appleKeyId,
    setAppleKeyId,
    buttonIcon,
    setButtonIcon,
    allowTenantInheritance,
    setAllowTenantInheritance,
    requirePkce,
    setRequirePkce,
    enabled,
    setEnabled,
    error,
    setError,
    tokenExchange,
    setTokenExchange,
    audiencesText,
    setAudiencesText,
    scopeMapText,
    setScopeMapText,
    reset,
    load,
    seedOverride,
    loginProviderPayload,
  };
}

/**
 * Spread one form's state into [`ConfigFields`].
 *
 * The create and edit dialogs render the same fields from the same hook, and
 * listing twenty-odd props twice is how one of them ends up missing the one
 * that was added last.
 */
function configFieldProps(
  form: ReturnType<typeof useConfigFormState>,
): Omit<ConfigFieldsProps, "idPrefix" | "isEditMode" | "canOfferInheritance"> {
  return {
    provider: form.provider,
    providerKind: form.providerKind,
    providerSlug: form.providerSlug,
    protocol: form.protocol,
    clientId: form.clientId,
    clientSecret: form.clientSecret,
    metadataUrl: form.metadataUrl,
    idpSigningCertPem: form.idpSigningCertPem,
    allowedAlgorithms: form.allowedAlgorithms,
    attributeMap: form.attributeMap,
    scopes: form.scopes,
    authorizationEndpoint: form.authorizationEndpoint,
    tokenEndpoint: form.tokenEndpoint,
    userinfoEndpoint: form.userinfoEndpoint,
    allowedIssuerTenants: form.allowedIssuerTenants,
    appleTeamId: form.appleTeamId,
    appleKeyId: form.appleKeyId,
    buttonIcon: form.buttonIcon,
    allowTenantInheritance: form.allowTenantInheritance,
    requirePkce: form.requirePkce,
    onProviderChange: form.setProvider,
    onProviderKindChange: form.setProviderKind,
    onProviderSlugChange: form.setProviderSlug,
    onProtocolChange: form.setProtocol,
    onClientIdChange: form.setClientId,
    onClientSecretChange: form.setClientSecret,
    onMetadataUrlChange: form.setMetadataUrl,
    onIdpSigningCertPemChange: form.setIdpSigningCertPem,
    onAllowedAlgorithmsChange: form.setAllowedAlgorithms,
    onAttributeMapChange: form.setAttributeMap,
    onScopesChange: form.setScopes,
    onAuthorizationEndpointChange: form.setAuthorizationEndpoint,
    onTokenEndpointChange: form.setTokenEndpoint,
    onUserinfoEndpointChange: form.setUserinfoEndpoint,
    onAllowedIssuerTenantsChange: form.setAllowedIssuerTenants,
    onAppleTeamIdChange: form.setAppleTeamId,
    onAppleKeyIdChange: form.setAppleKeyId,
    onButtonIconChange: form.setButtonIcon,
    onAllowTenantInheritanceChange: form.setAllowTenantInheritance,
    onRequirePkceChange: form.setRequirePkce,
  };
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function FederationPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const user = useAuthStore((s) => s.user);
  // Only a principal in the organization's own scope can offer a provider to
  // the organization's tenants, so the switch is not shown to anyone else —
  // it would be a control that does nothing wherever they set it.
  const isOrganizationLevel = user?.organization_level ?? false;

  const { data: configs = [], isLoading } = useQuery({
    queryKey: ["federation-configs"],
    queryFn: () => federationService.getAll(),
  });

  /**
   * Providers this workspace can actually sign in with, from the same
   * endpoint the login page renders its buttons from.
   *
   * Fetched in addition to the CRUD list because the CRUD list is
   * tenant-scoped by construction: it returns the configs this tenant owns and
   * cannot mention the organization-level ones it inherits. Without this, a
   * tenant administrator sees an empty Federation page and a login page with a
   * Google button on it, and nothing explains the difference.
   *
   * Its failure mode is deliberately quiet: a fault here must not take the
   * CRUD table with it.
   */
  const { data: effective = [] } = useQuery({
    queryKey: ["federation-effective-providers", user?.orgSlug, user?.tenantSlug],
    enabled: Boolean(user?.orgSlug),
    queryFn: () =>
      ssoLoginService.listProviders(user!.orgSlug!, user?.tenantSlug),
    retry: false,
  });

  /** The inherited half: effective here, but owned by the organization. */
  const inherited: PublicFederationProvider[] = effective.filter(
    (p) => p.inherited,
  );

  // ─── Search ─────────────────────────────────────────────────────────────────
  const [search, setSearch] = useState("");

  const filtered = search
    ? configs.filter(
        (c) =>
          c.provider.toLowerCase().includes(search.toLowerCase()) ||
          c.client_id.toLowerCase().includes(search.toLowerCase()),
      )
    : configs;

  // ─── Create state ──────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const createForm = useConfigFormState();

  const createMutation = useMutation({
    mutationFn: (payload: CreateFederationConfigRequest) =>
      federationService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["federation-configs"],
      });
      setCreateOpen(false);
      createForm.reset();
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      createForm.setError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    createForm.setError("");

    if (!createForm.provider.trim()) {
      createForm.setError("Display name is required.");
      return;
    }
    if (!createForm.clientId.trim()) {
      createForm.setError("Client ID is required.");
      return;
    }
    if (!createForm.clientSecret.trim()) {
      createForm.setError(
        createForm.providerKind === "apple"
          ? "The Apple signing key is required."
          : "Client Secret is required.",
      );
      return;
    }
    if (createForm.protocol === "Saml" && !createForm.idpSigningCertPem.trim()) {
      createForm.setError("IdP signing certificate is required for SAML.");
      return;
    }

    const attrResult = parseAttributeMap(createForm.attributeMap);
    if ("error" in attrResult) {
      createForm.setError(attrResult.error);
      return;
    }

    const metadataUrl = createForm.metadataUrl.trim();
    const login = createForm.loginProviderPayload();
    const payload: CreateFederationConfigRequest = {
      provider: createForm.provider.trim(),
      provider_kind: createForm.providerKind,
      protocol: createForm.protocol,
      client_id: createForm.clientId.trim(),
      client_secret: createForm.clientSecret,
      metadata_url: metadataUrl ? metadataUrl : null,
      attribute_map: attrResult.value,
      ...login,
    };

    if (createForm.protocol === "Saml") {
      payload.idp_signing_cert_pem = createForm.idpSigningCertPem.trim();
    }
    // Sent for every protocol but OAuth2, where the field is meaningless —
    // there is no signature to constrain.
    if (createForm.protocol !== "OAuth2") {
      const algos = parseList(createForm.allowedAlgorithms);
      if (algos.length > 0) payload.allowed_algorithms = algos;
    }

    createMutation.mutate(payload);
  }

  // ─── Edit state ────────────────────────────────────────────────────────────
  const [editConfig, setEditConfig] = useState<FederationConfig | null>(null);
  const editForm = useConfigFormState();

  const editMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: UpdateFederationConfigRequest;
    }) => federationService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["federation-configs"],
      });
      setEditConfig(null);
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      editForm.setError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function openEdit(config: FederationConfig) {
    setEditConfig(config);
    editForm.load(config);
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    editForm.setError("");

    if (!editConfig) return;
    if (!editForm.provider.trim()) {
      editForm.setError("Display name is required.");
      return;
    }
    if (!editForm.clientId.trim()) {
      editForm.setError("Client ID is required.");
      return;
    }

    const attrResult = parseAttributeMap(editForm.attributeMap);
    if ("error" in attrResult) {
      editForm.setError(attrResult.error);
      return;
    }

    const metadataUrl = editForm.metadataUrl.trim();
    const login = editForm.loginProviderPayload();
    const payload: UpdateFederationConfigRequest = {
      provider: editForm.provider.trim(),
      client_id: editForm.clientId.trim(),
      metadata_url: metadataUrl ? metadataUrl : null,
      attribute_map: attrResult.value,
      enabled: editForm.enabled,
      ...login,
    };

    // client_secret is write-only — only send when the admin entered a new one.
    if (editForm.clientSecret.trim()) {
      payload.client_secret = editForm.clientSecret;
    }

    if (editConfig.protocol === "Saml") {
      const cert = editForm.idpSigningCertPem.trim();
      if (cert) payload.idp_signing_cert_pem = cert;
    }
    if (editConfig.protocol !== "OAuth2") {
      payload.allowed_algorithms = parseList(editForm.allowedAlgorithms);
    }
    if (editConfig.protocol === "OidcConnect") {
      // X4. Sent as a complete block, never a patch — the server replaces it
      // wholesale, and a partial send is how an operator keeps an accepted
      // audience they believed they had removed.
      const scopeMapResult = parseScopeMap(editForm.scopeMapText);
      if ("error" in scopeMapResult) {
        editForm.setError(scopeMapResult.error);
        return;
      }
      const trust: TokenExchangeTrust = {
        ...editForm.tokenExchange,
        scope_map: scopeMapResult.value,
      };
      const trustError = validateTokenExchangeTrust(trust);
      if (trustError) {
        editForm.setError(trustError);
        return;
      }
      payload.token_exchange = trust;
    }

    editMutation.mutate({ id: editConfig.id, payload });
  }

  // ─── Delete state ──────────────────────────────────────────────────────────
  const [deleteConfig, setDeleteConfig] = useState<FederationConfig | null>(
    null,
  );

  const deleteMutation = useMutation({
    mutationFn: (id: string) => federationService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["federation-configs"],
      });
      setDeleteConfig(null);
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<FederationConfig>[] = [
    {
      key: "provider",
      header: "Provider",
      render: (row) => (
        <span className="flex items-center gap-2 font-medium text-foreground/90">
          <ProviderMark
            kind={row.provider_kind ?? "generic_oidc"}
            buttonIcon={row.button_icon}
            size={16}
          />
          {row.provider}
        </span>
      ),
    },
    {
      key: "protocol",
      header: "Protocol",
      render: (row) => <ProtocolBadge protocol={row.protocol} />,
    },
    {
      key: "enabled",
      header: "Status",
      render: (row) => (
        <StatusBadge status={row.enabled ? "active" : "inactive"} />
      ),
    },
    {
      key: "client_id",
      header: "Client ID",
      render: (row) => (
        <span className="text-sm text-muted-foreground font-mono">
          {row.client_id}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {formatDate(row.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-24",
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`Edit ${row.provider}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`Delete ${row.provider}`}
            onClick={() => setDeleteConfig(row)}
            className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
          >
            <Trash2 size={14} />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Federation"
        description="Configure cross-domain Single Sign-On via SAML and OpenID Connect identity providers."
        action={
          <Button
            onClick={() => {
              createForm.reset();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New Config
          </Button>
        }
      />

      {/* Search */}
      <div className="mb-4">
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Search by provider or client ID..."
          className="max-w-sm"
        />
      </div>

      {/* Inherited providers.
          Listed separately rather than merged into the table because they are
          not this tenant's rows: they cannot be edited or deleted here, and a
          disabled Edit button in a table of editable ones invites the question
          this section answers directly. */}
      {inherited.length > 0 && (
        <section aria-labelledby="inherited-providers-heading" className="mb-6">
          <h2
            id="inherited-providers-heading"
            className="mb-1 text-sm font-semibold text-foreground/90"
          >
            Inherited from the organization
          </h2>
          <p className="mb-3 text-xs text-muted-foreground">
            Offered on this tenant&rsquo;s login page and managed by the
            organization. Create a provider of the same kind here to override
            one — a tenant&rsquo;s own config always wins, including a disabled
            one.
          </p>
          <ul className="space-y-2 list-none p-0 m-0">
            {inherited.map((p) => (
              <li
                key={p.id}
                className="flex flex-wrap items-center gap-3 rounded-md border border-primary/10 bg-white/[0.03] px-3 py-2"
              >
                <ProviderMark
                  kind={p.provider_kind}
                  buttonIcon={p.button_icon}
                  size={16}
                />
                <span className="font-medium text-foreground/90">
                  {p.display_name}
                </span>
                <ProtocolBadge protocol={p.protocol} />
                <span className="inline-flex items-center rounded border border-cyan-500/30 bg-cyan-500/15 px-2 py-0.5 text-xs font-medium text-cyan-300">
                  Inherited
                </span>
                <span className="flex-1" />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    createForm.seedOverride(p);
                    setCreateOpen(true);
                  }}
                >
                  Override in this tenant
                </Button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <DataTable
        columns={columns}
        data={filtered}
        isLoading={isLoading}
        emptyMessage={
          inherited.length > 0
            ? "No federation configs of this tenant's own."
            : "No federation configs defined."
        }
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          createForm.reset();
        }}
        title="New Federation Config"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
        error={createForm.error}
        errorId="federation-create-error"
      >
        <ConfigFields
          {...configFieldProps(createForm)}
          idPrefix="create"
          canOfferInheritance={isOrganizationLevel}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editConfig !== null}
        onClose={() => setEditConfig(null)}
        title="Edit Federation Config"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
        error={editForm.error}
        errorId="federation-edit-error"
      >
        <ConfigFields
          {...configFieldProps(editForm)}
          idPrefix="edit"
          isEditMode={true}
          canOfferInheritance={isOrganizationLevel}
        />
        {/* Enabled toggle only in edit */}
        <ToggleField
          id="edit-fed-enabled"
          label="Enabled"
          checked={editForm.enabled}
          onChange={editForm.setEnabled}
        />
        {/* X4 — external token-exchange trust. Edit-only: you configure what a
            provider's tokens are worth after the provider exists, and the
            create form is already long. */}
        <TokenExchangeTrustEditor
          value={editForm.tokenExchange}
          onChange={editForm.setTokenExchange}
          audiencesText={editForm.audiencesText}
          onAudiencesTextChange={editForm.setAudiencesText}
          scopeMapText={editForm.scopeMapText}
          onScopeMapTextChange={editForm.setScopeMapText}
          isOidc={editConfig?.protocol !== "Saml"}
          idPrefix="edit"
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteConfig !== null}
        onClose={() => setDeleteConfig(null)}
        onConfirm={() =>
          deleteConfig && deleteMutation.mutate(deleteConfig.id)
        }
        title="Delete Federation Config"
        description={`Are you sure you want to delete the "${deleteConfig?.provider}" config? Users authenticating through this provider will lose SSO access.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}
