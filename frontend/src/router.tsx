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
import { AuditLogsPage } from "@/pages/audit/AuditLogsPage";
import { OAuth2ClientsPage } from "@/pages/oauth2/OAuth2ClientsPage";
import { NotificationRulesPage } from "@/pages/notifications/NotificationRulesPage";
import { TenantsPage, SettingsPage } from "@/pages/placeholders/Placeholder";
import { ProfilePage } from "@/pages/profile/ProfilePage";
import { ChangePasswordPage } from "@/pages/profile/ChangePasswordPage";
import { MfaManagementPage } from "@/pages/profile/MfaManagementPage";
import { ForgotPasswordPage } from "@/pages/auth/ForgotPasswordPage";
import { ResetPasswordPage } from "@/pages/auth/ResetPasswordPage";
import { VerifyEmailPage } from "@/pages/auth/VerifyEmailPage";

export const router = createBrowserRouter([
  // Public routes (no AppLayout, no auth required)
  {
    path: "/login",
    element: <LoginPage />,
  },
  {
    path: "/auth/forgot-password",
    element: <ForgotPasswordPage />,
  },
  {
    path: "/auth/reset-password",
    element: <ResetPasswordPage />,
  },
  {
    path: "/auth/verify-email",
    element: <VerifyEmailPage />,
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
        path: "notification-rules",
        element: <NotificationRulesPage />,
        handle: { crumb: "Notification Rules" },
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
      {
        path: "profile/change-password",
        element: <ChangePasswordPage />,
        handle: { crumb: "Change Password" },
      },
      {
        path: "profile/mfa",
        element: <MfaManagementPage />,
        handle: { crumb: "MFA Methods" },
      },
    ],
  },

  // Catch-all
  {
    path: "*",
    element: <Navigate to="/dashboard" replace />,
  },
]);
