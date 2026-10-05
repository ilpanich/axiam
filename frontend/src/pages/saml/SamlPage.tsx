import { useAuthStore } from "@/stores/auth";
import { PageHeader } from "@/components/PageHeader";
import { CredentialsPanel } from "./CredentialsPanel";
import { IdpPanel } from "./IdpPanel";
import { ServiceProvidersSection } from "./ServiceProvidersSection";

/**
 * SAML Service Providers (G-2, T23.2.6): the administration of the tenant's
 * SAML 2.0 identity provider, over the routes of contract §29.
 *
 * Reached with `saml_sp:read` (the route and the sidebar entry both gate on
 * it). What each part does beyond reading is gated on its own permission:
 * registering, importing, editing and deleting service providers on
 * `saml_sp:write`; issuing, promoting and retiring the signing credential on
 * `saml_idp:credential`.
 *
 * The protocol itself (sign-on, logout, the metadata document) is browser
 * traffic between a service provider and AXIAM and has no page here.
 */
export function SamlPage() {
  const tenantId = useAuthStore((s) => s.user?.tenant_id);

  return (
    <div className="max-w-5xl space-y-2">
      <PageHeader
        title="SAML Service Providers"
        description="Let this tenant's people sign in to other applications over SAML 2.0, with AXIAM as the identity provider. Register each application, then give it the values below."
      />
      {tenantId ? (
        <>
          <IdpPanel tenantId={tenantId} />
          <ServiceProvidersSection tenantId={tenantId} />
          <CredentialsPanel tenantId={tenantId} />
        </>
      ) : null}
    </div>
  );
}
