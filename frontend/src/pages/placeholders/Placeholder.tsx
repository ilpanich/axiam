import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface PlaceholderPageProps {
  title: string;
  description?: string;
}

export function PlaceholderPage({
  title,
  description,
}: PlaceholderPageProps) {
  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold text-foreground">{title}</h1>
        <Badge variant="secondary">Coming soon</Badge>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Under construction</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            {description ??
              `The ${title} management interface is being implemented. Check back in a future release.`}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

// Individual placeholder exports — suffixed to avoid collisions with real pages
export const OrganizationsPlaceholderPage = () => (
  <PlaceholderPage
    title="Organizations"
    description="Manage top-level organizations and their CA certificates."
  />
);

export const OrganizationDetailPlaceholderPage = () => (
  <PlaceholderPage
    title="Organization Details"
    description="View and manage organization settings, tenants, and certificates."
  />
);

export const TenantsPlaceholderPage = () => (
  <PlaceholderPage
    title="Tenants"
    description="Manage tenants within your organization. Each tenant provides full data isolation."
  />
);

export const UsersPlaceholderPage = () => (
  <PlaceholderPage
    title="Users"
    description="Create and manage user accounts, credentials, and MFA settings."
  />
);

export const UserDetailPlaceholderPage = () => (
  <PlaceholderPage
    title="User Details"
    description="View user profile, roles, groups, and authentication history."
  />
);

export const GroupsPlaceholderPage = () => (
  <PlaceholderPage
    title="Groups"
    description="Organize users into groups. Roles assigned to a group are inherited by all members."
  />
);

export const RolesPlaceholderPage = () => (
  <PlaceholderPage
    title="Roles"
    description="Define roles as collections of permissions. Roles support inheritance through resource hierarchies."
  />
);

export const PermissionsPlaceholderPage = () => (
  <PlaceholderPage
    title="Permissions"
    description="Define fine-grained permissions on resources with scope-level granularity."
  />
);

export const ResourcesPlaceholderPage = () => (
  <PlaceholderPage
    title="Resources"
    description="Organize resources hierarchically. Role assignments cascade to child resources unless overridden."
  />
);

export const CertificatesPlaceholderPage = () => (
  <PlaceholderPage
    title="Certificates"
    description="Manage X.509 certificates for users, services, and IoT devices."
  />
);

export const WebhooksPlaceholderPage = () => (
  <PlaceholderPage
    title="Webhooks"
    description="Configure webhooks to deliver real-time event notifications to external systems via HMAC-SHA256 signed payloads."
  />
);

export const PgpKeysPlaceholderPage = () => (
  <PlaceholderPage
    title="PGP Keys"
    description="Manage OpenPGP keys used for audit log signing and encrypted data exports."
  />
);

export const SettingsPlaceholderPage = () => (
  <PlaceholderPage
    title="Settings"
    description="Configure tenant-level settings including MFA policies, password policies, and session management."
  />
);
