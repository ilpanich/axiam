import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Loader2 } from "lucide-react";
import { samlService, type SamlIdpInfo } from "@/services/saml";
import { InfoRow, SectionCard } from "@/components/shared";
import { Badge } from "@/components/ui/badge";
import { CopyValue } from "./CopyValue";
import { samlErrorMessage } from "./samlErrors";

function YesNo({ yes, yesLabel, noLabel }: { yes: boolean; yesLabel: string; noLabel: string }) {
  return <Badge variant={yes ? "default" : "secondary"}>{yes ? yesLabel : noLabel}</Badge>;
}

/**
 * What stops the IdP answering, in the order an administrator can fix it, or
 * `null` when nothing does. Mirrors how `metadata_served` is computed (D-40):
 * available, enabled, and a publishable credential.
 */
function readiness(info: SamlIdpInfo): string | null {
  if (!info.saml_available) {
    return (
      "This server was built without SAML support, so none of these endpoints answers. " +
      "You can still register service providers and issue the signing credential; " +
      "importing from metadata is unavailable in this build."
    );
  }
  if (!info.saml_idp_enabled) {
    return (
      "SAML sign-on is switched off for this tenant (saml_idp_enabled is false), so the metadata, " +
      "sign-on and logout endpoints answer 404. Register service providers and issue a signing " +
      "credential first, then switch it on. It is the saml_idp_enabled security setting: an " +
      "organization turns it on and a tenant may only turn it off. Switch it in the organization's " +
      "Settings tab, or for this tenant under Settings."
    );
  }
  if (!info.metadata_served) {
    return (
      "SAML is enabled, but the metadata is not served yet because the tenant has no active or " +
      "next signing credential. Issue one under Signing credentials below."
    );
  }
  return null;
}

/**
 * The IdP as a service provider's administrator needs it: the four values to
 * paste into the SP, and whether the IdP answers yet (contract §29.2
 * `SamlIdpInfo`). Never cached: the readiness it reports changes with every
 * credential write (§29.9).
 */
export function IdpPanel({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["saml-idp", tenantId],
    queryFn: () => samlService.getIdp(tenantId),
    staleTime: 0,
  });

  return (
    <SectionCard title="Identity provider">
      {isLoading ? (
        <div className="flex items-center justify-center py-6">
          <Loader2 className="animate-spin text-primary" size={24} aria-label="Loading" />
        </div>
      ) : error || !data ? (
        <p role="alert" className="text-sm text-destructive">
          {error ? samlErrorMessage(error, "Failed to load the identity provider.") : "Failed to load the identity provider."}
        </p>
      ) : (
        <IdpDetails info={data} />
      )}
    </SectionCard>
  );
}

function IdpDetails({ info }: { info: SamlIdpInfo }) {
  const problem = readiness(info);
  return (
    <div>
      {problem ? (
        <p
          role="status"
          className="mb-3 flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200"
        >
          <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>{problem}</span>
        </p>
      ) : (
        <p
          role="status"
          className="mb-3 flex items-start gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 p-3 text-sm text-emerald-400"
        >
          <CheckCircle2 size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>SAML sign-on is on and the metadata is being served.</span>
        </p>
      )}
      <InfoRow label="Status">
        <span className="flex flex-wrap gap-2">
          <YesNo yes={info.saml_available} yesLabel="SAML available" noLabel="SAML not in this build" />
          <YesNo yes={info.saml_idp_enabled} yesLabel="Enabled" noLabel="Switched off" />
          <YesNo yes={info.metadata_served} yesLabel="Metadata served" noLabel="Metadata not served" />
        </span>
      </InfoRow>
      <InfoRow label="Entity ID">
        <CopyValue label="entity ID" value={info.entity_id} />
      </InfoRow>
      <InfoRow label="Metadata URL">
        <CopyValue label="metadata URL" value={info.metadata_url} />
        <span className="mt-1 block text-xs text-muted-foreground">
          Unsigned. Give it to the service provider over TLS and compare the signing
          certificate&rsquo;s fingerprint (below) out of band.
        </span>
      </InfoRow>
      <InfoRow label="Sign-on URL">
        <CopyValue label="sign-on URL" value={info.sso_url} />
      </InfoRow>
      <InfoRow label="Logout URL">
        <CopyValue label="logout URL" value={info.slo_url} />
      </InfoRow>
      <InfoRow label="Signing credential">
        <span className="text-sm">
          {info.active_credential_id ? "An active credential signs." : "No active credential."}{" "}
          {info.next_credential_id
            ? "A next credential is published and waiting to be promoted."
            : "No next credential."}
        </span>
      </InfoRow>
    </div>
  );
}
