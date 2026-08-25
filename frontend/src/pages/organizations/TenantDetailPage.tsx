import { useParams, Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { tenantService, orgService } from "@/services/organizations";
import { PageHeader } from "@/components/PageHeader";
import { TenantEmailConfigPanel } from "./EmailConfigPanel";
import { TenantSecurityOverridePanel } from "./SecurityOverridePanel";
import { SigningCaPanel } from "./SigningCaPanel";
import { usePermissions } from "@/hooks/usePermissions";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { ChevronLeft } from "lucide-react";
import { formatDate } from "@/lib/utils";

export function TenantDetailPage() {
  const { orgId, tenantId } = useParams<{ orgId: string; tenantId: string }>();
  const { can } = usePermissions();

  const { data: org } = useQuery({
    queryKey: ["organizations", orgId],
    queryFn: () => orgService.get(orgId!),
    enabled: !!orgId,
  });

  const { data: tenant, isLoading } = useQuery({
    queryKey: ["tenants", orgId, tenantId],
    queryFn: () => tenantService.get(orgId!, tenantId!),
    enabled: !!orgId && !!tenantId,
  });

  if (!orgId || !tenantId) return null;

  return (
    <div>
      {/* Breadcrumb */}
      <nav
        aria-label="Breadcrumb"
        className="flex items-center gap-2 text-sm text-muted-foreground mb-4"
      >
        <Link
          to="/organizations"
          className="hover:text-foreground transition-colors"
        >
          Organizations
        </Link>
        <span aria-hidden="true">/</span>
        <Link
          to={`/organizations/${orgId}`}
          className="hover:text-foreground transition-colors"
        >
          {org?.name ?? orgId}
        </Link>
        <span aria-hidden="true">/</span>
        <span className="text-foreground">
          {isLoading ? "..." : tenant?.name ?? tenantId}
        </span>
      </nav>

      <PageHeader
        title={isLoading ? "Loading..." : (tenant?.name ?? "Tenant")}
        description={tenant?.metadata?.description as string | undefined}
        action={
          <Button variant="ghost" size="sm" asChild>
            <Link to={`/organizations/${orgId}`}>
              <ChevronLeft size={14} />
              Back to Organization
            </Link>
          </Button>
        }
      />

      {isLoading ? (
        <div className="glass-card animate-pulse space-y-3">
          <div className="h-4 bg-white/10 rounded w-1/3" />
          <div className="h-4 bg-white/10 rounded w-1/2" />
          <div className="h-4 bg-white/10 rounded w-1/4" />
        </div>
      ) : tenant ? (
        <div className="glass-card space-y-4 max-w-lg">
          <dl className="space-y-3">
            <div className="flex gap-4">
              <dt className="w-36 shrink-0 text-sm text-muted-foreground">
                Name
              </dt>
              <dd className="text-sm text-foreground font-medium">
                {tenant.name}
              </dd>
            </div>
            <div className="flex gap-4">
              <dt className="w-36 shrink-0 text-sm text-muted-foreground">
                Slug
              </dt>
              <dd>
                <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-muted-foreground">
                  {tenant.slug}
                </code>
              </dd>
            </div>
            <div className="flex gap-4">
              <dt className="w-36 shrink-0 text-sm text-muted-foreground">
                Status
              </dt>
              <dd>
                <StatusBadge
                  status={tenant.status === "Active" ? "active" : "suspended"}
                />
              </dd>
            </div>
            {(tenant.metadata?.description as string | undefined) && (
              <div className="flex gap-4">
                <dt className="w-36 shrink-0 text-sm text-muted-foreground">
                  Description
                </dt>
                <dd className="text-sm text-foreground">
                  {tenant.metadata?.description as string}
                </dd>
              </div>
            )}
            <div className="flex gap-4">
              <dt className="w-36 shrink-0 text-sm text-muted-foreground">
                Created
              </dt>
              <dd className="text-sm text-foreground">
                {formatDate(tenant.created_at)}
              </dd>
            </div>
            <div className="flex gap-4">
              <dt className="w-36 shrink-0 text-sm text-muted-foreground">
                Tenant ID
              </dt>
              <dd>
                <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-muted-foreground break-all">
                  {tenant.id}
                </code>
              </dd>
            </div>
          </dl>
        </div>
      ) : (
        <p className="text-muted-foreground">Tenant not found.</p>
      )}

      {/* The tenant's own signing CAs. Gated on the CA list permission rather
          than rendered and left to 403, so an operator without it sees no
          half-loaded panel — the same rule the two panels below follow. */}
      {tenant && can("ca_certificates:list") && (
        <div className="mt-6">
          <SigningCaPanel
            orgId={orgId}
            tenantId={tenantId}
            tenantName={tenant.name}
          />
        </div>
      )}

      {/* The tenant's partial overrides on the org baselines — security first,
          because it is the one an operator comes here to check. Both are gated
          on their read permission rather than rendered and left to 403, so an
          operator without it sees no half-loaded panel. */}
      {tenant && can("settings:get") && (
        <div className="mt-6">
          <TenantSecurityOverridePanel tenantId={tenantId} />
        </div>
      )}

      {/* FUNC-03 / D-13 */}
      {tenant && can("email_config:read") && (
        <div className="mt-6">
          <TenantEmailConfigPanel tenantId={tenantId} />
        </div>
      )}
    </div>
  );
}
