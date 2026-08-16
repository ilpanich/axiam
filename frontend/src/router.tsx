import { createBrowserRouter, Navigate } from "react-router";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { AppLayout } from "@/components/layout/AppLayout";
import { LoginPage } from "@/pages/LoginPage";
import { BootstrapPage } from "@/pages/BootstrapPage";
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
import { ReactorsPage } from "@/pages/reactors/ReactorsPage";
import { PgpKeysPage } from "@/pages/pgp/PgpKeysPage";
import { AuditLogsPage } from "@/pages/audit/AuditLogsPage";
import { OAuth2ClientsPage } from "@/pages/oauth2/OAuth2ClientsPage";
import { NotificationRulesPage } from "@/pages/notifications/NotificationRulesPage";
import { ServiceAccountsPage } from "@/pages/service-accounts/ServiceAccountsPage";
import { ScimTokensPage } from "@/pages/scim/ScimTokensPage";
import { FederationPage } from "@/pages/federation/FederationPage";
import { TenantsPage } from "@/pages/tenants/TenantsPage";
import { SettingsPage } from "@/pages/settings/SettingsPage";
import { AttestationPolicyPage } from "@/pages/settings/AttestationPolicyPage";
import { ProfilePage } from "@/pages/profile/ProfilePage";
import { ChangePasswordPage } from "@/pages/profile/ChangePasswordPage";
import { MfaManagementPage } from "@/pages/profile/MfaManagementPage";
import { ForgotPasswordPage } from "@/pages/auth/ForgotPasswordPage";
import { ResetPasswordPage } from "@/pages/auth/ResetPasswordPage";
import { VerifyEmailPage } from "@/pages/auth/VerifyEmailPage";
import { MfaSetupPage } from "@/pages/auth/MfaSetupPage";
import { DevicePage } from "@/pages/device/DevicePage";
import { PrivacyPage } from "@/pages/privacy/PrivacyPage";

export const router = createBrowserRouter([
  // Public routes (no AppLayout, no auth required)
  {
    path: "/login",
    element: <LoginPage />,
  },
  {
    path: "/bootstrap",
    element: <BootstrapPage />,
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
  {
    path: "/auth/mfa-setup",
    element: <MfaSetupPage />,
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
        element: <ProtectedRoute permission="organizations:list" />,
        children: [
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
        ],
      },
      {
        // CQ-F30: tenants gets its own permission (matches Sidebar's
        // "tenants:list" gate) rather than piggybacking on organizations.
        element: <ProtectedRoute permission="tenants:list" />,
        children: [
          {
            path: "tenants",
            element: <TenantsPage />,
            handle: { crumb: "Tenants" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="users:list" />,
        children: [
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
        ],
      },
      {
        element: <ProtectedRoute permission="groups:list" />,
        children: [
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
        ],
      },
      {
        element: <ProtectedRoute permission="roles:list" />,
        children: [
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
        ],
      },
      {
        element: <ProtectedRoute permission="permissions:list" />,
        children: [
          {
            path: "permissions",
            element: <PermissionsPage />,
            handle: { crumb: "Permissions" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="resources:list" />,
        children: [
          {
            path: "resources",
            element: <ResourcesPage />,
            handle: { crumb: "Resources" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="certificates:list" />,
        children: [
          {
            path: "certificates",
            element: <CertificatesPage />,
            handle: { crumb: "Certificates" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="webhooks:list" />,
        children: [
          {
            path: "webhooks",
            element: <WebhooksPage />,
            handle: { crumb: "Webhooks" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="reactors:list" />,
        children: [
          {
            path: "reactors",
            element: <ReactorsPage />,
            handle: { crumb: "Reactors" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="pgp_keys:list" />,
        children: [
          {
            path: "pgp-keys",
            element: <PgpKeysPage />,
            handle: { crumb: "PGP Keys" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="oauth2_clients:list" />,
        children: [
          {
            path: "oauth2-clients",
            element: <OAuth2ClientsPage />,
            handle: { crumb: "OAuth2 Clients" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="audit_logs:list" />,
        children: [
          {
            path: "audit-logs",
            element: <AuditLogsPage />,
            handle: { crumb: "Audit Logs" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="notification_rules:list" />,
        children: [
          {
            path: "notification-rules",
            element: <NotificationRulesPage />,
            handle: { crumb: "Notification Rules" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="service_accounts:list" />,
        children: [
          {
            path: "service-accounts",
            element: <ServiceAccountsPage />,
            handle: { crumb: "Service Accounts" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="scim_tokens:list" />,
        children: [
          {
            path: "scim-tokens",
            element: <ScimTokensPage />,
            handle: { crumb: "SCIM Provisioning" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="federation:list" />,
        children: [
          {
            path: "federation",
            element: <FederationPage />,
            handle: { crumb: "Federation" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="settings:get" />,
        children: [
          {
            path: "settings",
            element: <SettingsPage />,
            handle: { crumb: "Settings" },
          },
        ],
      },
      {
        element: <ProtectedRoute permission="webauthn_policy:read" />,
        children: [
          {
            path: "settings/webauthn-attestation-policy",
            element: <AttestationPolicyPage />,
            handle: { crumb: "WebAuthn Attestation Policy" },
          },
        ],
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
      {
        // B2/R4.1: no permission gate -- approving one's own device grant
        // needs only an authenticated session, the same "requiredPermission:
        // null" class as /profile (see Sidebar.tsx). AppLayout's own guard
        // above still redirects unauthenticated visitors to /login.
        path: "device",
        element: <DevicePage />,
        handle: { crumb: "Connect a Device" },
      },
      {
        // GDPR Art. 15/17 self-service export & erasure -- every
        // authenticated user manages their own data here; the optional
        // "act on behalf of" fields are gated inline on gdpr:export /
        // users:erase (see PrivacyPage.tsx), matching the null-permission
        // self-service class rather than a route-level ProtectedRoute.
        path: "privacy",
        element: <PrivacyPage />,
        handle: { crumb: "Privacy & Data" },
      },
    ],
  },

  // Catch-all
  {
    path: "*",
    element: <Navigate to="/dashboard" replace />,
  },
]);
