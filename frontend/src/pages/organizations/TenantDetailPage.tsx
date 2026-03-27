import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { tenantService, orgService } from "@/services/organizations";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { ChevronLeft } from "lucide-react";

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );

export function TenantDetailPage() {
  const { orgId, tenantId } = useParams<{ orgId: string; tenantId: string }>();

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
        description={tenant?.description}
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
            {tenant.description && (
              <div className="flex gap-4">
                <dt className="w-36 shrink-0 text-sm text-muted-foreground">
                  Description
                </dt>
                <dd className="text-sm text-foreground">
                  {tenant.description}
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
    </div>
  );
}
