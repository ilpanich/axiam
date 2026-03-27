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

// Individual placeholder exports for each route
export const OrganizationsPage = () => (
  <PlaceholderPage
    title="Organizations"
    description="Manage top-level organizations and their CA certificates."
  />
);

export const OrganizationDetailPage = () => (
  <PlaceholderPage
    title="Organization Details"
    description="View and manage organization settings, tenants, and certificates."
  />
);

export const TenantsPage = () => (
  <PlaceholderPage
    title="Tenants"
    description="Manage tenants within your organization. Each tenant provides full data isolation."
  />
);

export const UsersPage = () => (
  <PlaceholderPage
    title="Users"
    description="Create and manage user accounts, credentials, and MFA settings."
  />
);

export const UserDetailPage = () => (
  <PlaceholderPage
    title="User Details"
    description="View user profile, roles, groups, and authentication history."
  />
);

export const GroupsPage = () => (
  <PlaceholderPage
    title="Groups"
    description="Organize users into groups. Roles assigned to a group are inherited by all members."
  />
);

export const RolesPage = () => (
  <PlaceholderPage
    title="Roles"
    description="Define roles as collections of permissions. Roles support inheritance through resource hierarchies."
  />
);

export const PermissionsPage = () => (
  <PlaceholderPage
    title="Permissions"
    description="Define fine-grained permissions on resources with scope-level granularity."
  />
);

export const ResourcesPage = () => (
  <PlaceholderPage
    title="Resources"
    description="Organize resources hierarchically. Role assignments cascade to child resources unless overridden."
  />
);

export const CertificatesPage = () => (
  <PlaceholderPage
    title="Certificates"
    description="Manage X.509 certificates for users, services, and IoT devices."
  />
);

export const WebhooksPage = () => (
  <PlaceholderPage
    title="Webhooks"
    description="Configure webhooks to deliver real-time event notifications to external systems via HMAC-SHA256 signed payloads."
  />
);

export const PgpKeysPage = () => (
  <PlaceholderPage
    title="PGP Keys"
    description="Manage OpenPGP keys used for audit log signing and encrypted data exports."
  />
);

export const OAuth2ClientsPage = () => (
  <PlaceholderPage
    title="OAuth2 Clients"
    description="Register and manage OAuth2 clients for Authorization Code + PKCE, Client Credentials, and Refresh Token flows."
  />
);

export const AuditLogsPage = () => (
  <PlaceholderPage
    title="Audit Logs"
    description="Browse append-only audit logs. All actions are immutably recorded for compliance."
  />
);

export const SettingsPage = () => (
  <PlaceholderPage
    title="Settings"
    description="Configure tenant-level settings including MFA policies, password policies, and session management."
  />
);

export const ProfilePage = () => (
  <PlaceholderPage
    title="Profile"
    description="Manage your account profile, password, and MFA enrollment."
  />
);

export const PasswordResetPage = () => (
  <PlaceholderPage
    title="Password Reset"
    description="Password reset flow is being implemented."
  />
);

export const EmailVerificationPage = () => (
  <PlaceholderPage
    title="Email Verification"
    description="Email verification flow is being implemented."
  />
);
