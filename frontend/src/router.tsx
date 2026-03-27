import { createBrowserRouter, Navigate } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { LoginPage } from "@/pages/LoginPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { OrganizationsPage } from "@/pages/organizations/OrganizationsPage";
import { OrganizationDetailPage } from "@/pages/organizations/OrganizationDetailPage";
import { TenantDetailPage } from "@/pages/organizations/TenantDetailPage";
import { UsersPage } from "@/pages/users/UsersPage";
import { UserDetailPage } from "@/pages/users/UserDetailPage";
import { GroupsPage } from "@/pages/groups/GroupsPage";
import { GroupDetailPage } from "@/pages/groups/GroupDetailPage";
import { RolesPage } from "@/pages/roles/RolesPage";
import { RoleDetailPage } from "@/pages/roles/RoleDetailPage";
import { PermissionsPage } from "@/pages/permissions/PermissionsPage";
import { ResourcesPage } from "@/pages/resources/ResourcesPage";
import { CertificatesPage } from "@/pages/certificates/CertificatesPage";
import { WebhooksPage } from "@/pages/webhooks/WebhooksPage";
import { PgpKeysPage } from "@/pages/pgp/PgpKeysPage";
import {
  TenantsPage,
  OAuth2ClientsPage,
  AuditLogsPage,
  SettingsPage,
  ProfilePage,
  PasswordResetPage,
  EmailVerificationPage,
} from "@/pages/placeholders/Placeholder";

export const router = createBrowserRouter([
  // Public routes
  {
    path: "/login",
    element: <LoginPage />,
  },
  {
    path: "/auth/reset-password",
    element: <PasswordResetPage />,
  },
  {
    path: "/auth/verify-email",
    element: <EmailVerificationPage />,
  },

  // Protected routes under AppLayout
  {
    path: "/",
    element: <AppLayout />,
    children: [
      {
        index: true,
        element: <Navigate to="/dashboard" replace />,
      },
      {
        path: "dashboard",
        element: <DashboardPage />,
        handle: { crumb: "Dashboard" },
      },
      {
        path: "organizations",
        element: <OrganizationsPage />,
        handle: { crumb: "Organizations" },
      },
      {
        path: "organizations/:orgId",
        element: <OrganizationDetailPage />,
        handle: { crumb: "Organization Details" },
      },
      {
        path: "organizations/:orgId/tenants/:tenantId",
        element: <TenantDetailPage />,
        handle: { crumb: "Tenant Details" },
      },
      {
        path: "tenants",
        element: <TenantsPage />,
        handle: { crumb: "Tenants" },
      },
      {
        path: "users",
        element: <UsersPage />,
        handle: { crumb: "Users" },
      },
      {
        path: "users/:userId",
        element: <UserDetailPage />,
        handle: { crumb: "User Details" },
      },
      {
        path: "groups",
        element: <GroupsPage />,
        handle: { crumb: "Groups" },
      },
      {
        path: "groups/:groupId",
        element: <GroupDetailPage />,
        handle: { crumb: "Group Details" },
      },
      {
        path: "roles",
        element: <RolesPage />,
        handle: { crumb: "Roles" },
      },
      {
        path: "roles/:roleId",
        element: <RoleDetailPage />,
        handle: { crumb: "Role Details" },
      },
      {
        path: "permissions",
        element: <PermissionsPage />,
        handle: { crumb: "Permissions" },
      },
      {
        path: "resources",
        element: <ResourcesPage />,
        handle: { crumb: "Resources" },
      },
      {
        path: "certificates",
        element: <CertificatesPage />,
        handle: { crumb: "Certificates" },
      },
      {
        path: "webhooks",
        element: <WebhooksPage />,
        handle: { crumb: "Webhooks" },
      },
      {
        path: "pgp-keys",
        element: <PgpKeysPage />,
        handle: { crumb: "PGP Keys" },
      },
      {
        path: "oauth2-clients",
        element: <OAuth2ClientsPage />,
        handle: { crumb: "OAuth2 Clients" },
      },
      {
        path: "audit-logs",
        element: <AuditLogsPage />,
        handle: { crumb: "Audit Logs" },
      },
      {
        path: "settings",
        element: <SettingsPage />,
        handle: { crumb: "Settings" },
      },
      {
        path: "profile",
        element: <ProfilePage />,
        handle: { crumb: "Profile" },
      },
    ],
  },

  // Catch-all
  {
    path: "*",
    element: <Navigate to="/dashboard" replace />,
  },
]);
