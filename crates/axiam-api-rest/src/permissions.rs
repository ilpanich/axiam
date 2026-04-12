//! Compile-time permission registry and public-path allowlist.
//!
//! [`PERMISSION_REGISTRY`] lists every `(action, description)` pair that the
//! permission seeder will UPSERT into SurrealDB on startup.
//!
//! [`PUBLIC_PATHS`] enumerates every path that the [`AuthzMiddleware`] must
//! allow through without requiring a JWT (D-04).
//!
//! [`ROUTE_PERMISSION_MAP`] maps `(HTTP_METHOD, path_pattern, permission)`
//! and is used by the integration test in Plan 05 to verify that every
//! registered route has an authorisation check (D-08).

// ---------------------------------------------------------------------------
// Permission registry (D-05, D-06, D-07)
// ---------------------------------------------------------------------------

/// All permissions managed by AXIAM.
///
/// Format: `(action, human-readable description)`.
/// The seeder generates a deterministic UUID from `namespace = tenant_id` +
/// `name = action` so the same record is always targeted on subsequent
/// restarts (true idempotency via UPSERT).
pub const PERMISSION_REGISTRY: &[(&str, &str)] = &[
    // Users
    ("users:list", "List users in the tenant"),
    ("users:get", "Retrieve a single user"),
    ("users:create", "Create a new user"),
    ("users:update", "Update an existing user"),
    ("users:delete", "Delete a user"),
    (
        "users:admin",
        "Perform administrative user actions (unlock, reset MFA)",
    ),
    // Groups
    ("groups:list", "List groups"),
    ("groups:get", "Retrieve a single group"),
    ("groups:create", "Create a new group"),
    ("groups:update", "Update a group"),
    ("groups:delete", "Delete a group"),
    ("groups:add_member", "Add a user to a group"),
    ("groups:remove_member", "Remove a user from a group"),
    ("groups:list_members", "List members of a group"),
    // Roles
    ("roles:list", "List roles"),
    ("roles:get", "Retrieve a single role"),
    ("roles:create", "Create a new role"),
    ("roles:update", "Update a role"),
    ("roles:delete", "Delete a role"),
    ("roles:assign", "Assign a role to a user or group"),
    ("roles:unassign", "Remove a role from a user or group"),
    // Permissions
    ("permissions:list", "List permissions"),
    ("permissions:get", "Retrieve a single permission"),
    ("permissions:create", "Create a new permission"),
    ("permissions:update", "Update a permission"),
    ("permissions:delete", "Delete a permission"),
    ("permissions:grant", "Grant a permission to a role"),
    ("permissions:revoke", "Revoke a permission from a role"),
    // Resources
    ("resources:list", "List resources"),
    ("resources:get", "Retrieve a single resource"),
    ("resources:create", "Create a new resource"),
    ("resources:update", "Update a resource"),
    ("resources:delete", "Delete a resource"),
    ("resources:list_children", "List child resources"),
    ("resources:list_ancestors", "List ancestor resources"),
    // Scopes
    ("scopes:list", "List scopes on a resource"),
    ("scopes:get", "Retrieve a single scope"),
    ("scopes:create", "Create a new scope"),
    ("scopes:update", "Update a scope"),
    ("scopes:delete", "Delete a scope"),
    // Certificates
    ("certificates:list", "List certificates"),
    ("certificates:get", "Retrieve a single certificate"),
    ("certificates:generate", "Generate a new certificate"),
    ("certificates:revoke", "Revoke a certificate"),
    (
        "certificates:bind",
        "Bind a certificate to a service account",
    ),
    // CA Certificates
    ("ca_certificates:list", "List CA certificates"),
    ("ca_certificates:get", "Retrieve a single CA certificate"),
    ("ca_certificates:generate", "Generate a new CA certificate"),
    ("ca_certificates:revoke", "Revoke a CA certificate"),
    // Audit Logs
    ("audit_logs:list", "List audit logs for the tenant"),
    (
        "audit_logs:list_system",
        "List system-wide audit logs (all tenants)",
    ),
    // Service Accounts
    ("service_accounts:list", "List service accounts"),
    ("service_accounts:get", "Retrieve a single service account"),
    ("service_accounts:create", "Create a new service account"),
    ("service_accounts:update", "Update a service account"),
    ("service_accounts:delete", "Delete a service account"),
    (
        "service_accounts:rotate_secret",
        "Rotate a service account secret",
    ),
    // PGP Keys
    ("pgp_keys:list", "List PGP keys"),
    ("pgp_keys:get", "Retrieve a single PGP key"),
    ("pgp_keys:generate", "Generate a new PGP key"),
    ("pgp_keys:revoke", "Revoke a PGP key"),
    ("pgp_keys:encrypt", "Encrypt data with a PGP key"),
    (
        "pgp_keys:sign_audit_batch",
        "Sign an audit log batch with a PGP key",
    ),
    // Webhooks
    ("webhooks:list", "List webhooks"),
    ("webhooks:get", "Retrieve a single webhook"),
    ("webhooks:create", "Create a new webhook"),
    ("webhooks:update", "Update a webhook"),
    ("webhooks:delete", "Delete a webhook"),
    // OAuth2 Clients
    ("oauth2_clients:list", "List OAuth2 clients"),
    ("oauth2_clients:get", "Retrieve a single OAuth2 client"),
    ("oauth2_clients:create", "Create a new OAuth2 client"),
    ("oauth2_clients:update", "Update an OAuth2 client"),
    ("oauth2_clients:delete", "Delete an OAuth2 client"),
    // Federation
    ("federation:list", "List federation configurations"),
    (
        "federation:get",
        "Retrieve a single federation configuration",
    ),
    ("federation:create", "Create a federation configuration"),
    ("federation:update", "Update a federation configuration"),
    ("federation:delete", "Delete a federation configuration"),
    // Notification Rules
    ("notification_rules:list", "List notification rules"),
    (
        "notification_rules:get",
        "Retrieve a single notification rule",
    ),
    ("notification_rules:create", "Create a notification rule"),
    ("notification_rules:update", "Update a notification rule"),
    ("notification_rules:delete", "Delete a notification rule"),
    // Settings
    ("settings:get", "Read tenant or organization settings"),
    ("settings:update", "Update tenant or organization settings"),
    // Tenants
    ("tenants:list", "List tenants within an organization"),
    ("tenants:get", "Retrieve a single tenant"),
    ("tenants:create", "Create a new tenant"),
    ("tenants:update", "Update a tenant"),
    ("tenants:delete", "Delete a tenant"),
    // Organizations
    ("organizations:list", "List organizations"),
    ("organizations:get", "Retrieve a single organization"),
    ("organizations:create", "Create a new organization"),
    ("organizations:update", "Update an organization"),
    ("organizations:delete", "Delete an organization"),
    ("organizations:get_settings", "Read organization settings"),
    (
        "organizations:update_settings",
        "Update organization settings",
    ),
    // Bootstrap
    (
        "admin:bootstrap",
        "Bootstrap the first admin user in a tenant",
    ),
];

// ---------------------------------------------------------------------------
// Public-path allowlist (D-04)
// ---------------------------------------------------------------------------

/// Paths that do NOT require authentication.
///
/// Matching rules applied by `AuthzMiddleware`:
/// - Entries ending with `*` are prefix-matched (strip the `*`, use `starts_with`).
/// - All other entries are exact-matched against `req.path()`.
pub const PUBLIC_PATHS: &[&str] = &[
    // Authentication flows (under /auth scope)
    "/auth/login",
    "/auth/register",
    "/auth/device",
    "/auth/mfa/verify",
    "/auth/mfa/setup/enroll",
    "/auth/mfa/setup/confirm",
    "/auth/reset",
    "/auth/reset/confirm",
    "/auth/verify-email",
    "/auth/resend-verification",
    // WebAuthn — public registration/authentication initiation
    "/auth/webauthn/register/start",
    "/auth/webauthn/register/finish",
    "/auth/webauthn/authenticate/start",
    "/auth/webauthn/authenticate/finish",
    // Health probes
    "/health",
    "/ready",
    // OIDC discovery and token endpoints
    "/.well-known/openid-configuration",
    "/oauth2/jwks",
    "/oauth2/authorize",
    "/oauth2/token",
    "/oauth2/userinfo",
    "/oauth2/revoke",
    "/oauth2/introspect",
    // Federation callback endpoints (unauthenticated — IdP redirects here)
    "/api/v1/federation/oidc/callback",
    "/api/v1/federation/saml/acs",
    "/api/v1/federation/saml/metadata",
    // Admin bootstrap (public until first admin is created; handler enforces one-shot logic)
    "/api/v1/admin/bootstrap",
    // OpenAPI docs
    "/api/docs/*",
];

// ---------------------------------------------------------------------------
// Route-permission map (D-08)
// ---------------------------------------------------------------------------

/// `(HTTP_METHOD, path_pattern, required_permission)` for every protected route.
///
/// Used by the Plan 05 integration test to verify that every registered route
/// has a matching permission in [`PERMISSION_REGISTRY`].
///
/// Path patterns use `{param}` placeholders (matching server.rs registration
/// patterns). Public routes do NOT appear here — they are exempt from the
/// permission check.
pub const ROUTE_PERMISSION_MAP: &[(&str, &str, &str)] = &[
    // Organizations
    ("GET", "/api/v1/organizations", "organizations:list"),
    ("POST", "/api/v1/organizations", "organizations:create"),
    ("GET", "/api/v1/organizations/{org_id}", "organizations:get"),
    (
        "PUT",
        "/api/v1/organizations/{org_id}",
        "organizations:update",
    ),
    (
        "DELETE",
        "/api/v1/organizations/{org_id}",
        "organizations:delete",
    ),
    // Organization Settings
    (
        "GET",
        "/api/v1/organizations/{org_id}/settings",
        "organizations:get_settings",
    ),
    (
        "PUT",
        "/api/v1/organizations/{org_id}/settings",
        "organizations:update_settings",
    ),
    // Tenants
    (
        "GET",
        "/api/v1/organizations/{org_id}/tenants",
        "tenants:list",
    ),
    (
        "POST",
        "/api/v1/organizations/{org_id}/tenants",
        "tenants:create",
    ),
    (
        "GET",
        "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
        "tenants:get",
    ),
    (
        "PUT",
        "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
        "tenants:update",
    ),
    (
        "DELETE",
        "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
        "tenants:delete",
    ),
    // CA Certificates
    (
        "GET",
        "/api/v1/organizations/{org_id}/ca-certificates",
        "ca_certificates:list",
    ),
    (
        "POST",
        "/api/v1/organizations/{org_id}/ca-certificates",
        "ca_certificates:generate",
    ),
    (
        "GET",
        "/api/v1/organizations/{org_id}/ca-certificates/{id}",
        "ca_certificates:get",
    ),
    (
        "POST",
        "/api/v1/organizations/{org_id}/ca-certificates/{id}/revoke",
        "ca_certificates:revoke",
    ),
    // Users
    ("GET", "/api/v1/users", "users:list"),
    ("POST", "/api/v1/users", "users:create"),
    ("GET", "/api/v1/users/{user_id}", "users:get"),
    ("PUT", "/api/v1/users/{user_id}", "users:update"),
    ("DELETE", "/api/v1/users/{user_id}", "users:delete"),
    ("POST", "/api/v1/users/{user_id}/unlock", "users:admin"),
    ("POST", "/api/v1/users/{user_id}/reset-mfa", "users:admin"),
    ("GET", "/api/v1/users/{user_id}/mfa-methods", "users:get"),
    (
        "DELETE",
        "/api/v1/users/{user_id}/mfa-methods/{method_id}",
        "users:admin",
    ),
    // Groups
    ("GET", "/api/v1/groups", "groups:list"),
    ("POST", "/api/v1/groups", "groups:create"),
    ("GET", "/api/v1/groups/{group_id}", "groups:get"),
    ("PUT", "/api/v1/groups/{group_id}", "groups:update"),
    ("DELETE", "/api/v1/groups/{group_id}", "groups:delete"),
    (
        "GET",
        "/api/v1/groups/{group_id}/members",
        "groups:list_members",
    ),
    (
        "POST",
        "/api/v1/groups/{group_id}/members",
        "groups:add_member",
    ),
    (
        "DELETE",
        "/api/v1/groups/{group_id}/members/{user_id}",
        "groups:remove_member",
    ),
    // Roles
    ("GET", "/api/v1/roles", "roles:list"),
    ("POST", "/api/v1/roles", "roles:create"),
    ("GET", "/api/v1/roles/{role_id}", "roles:get"),
    ("PUT", "/api/v1/roles/{role_id}", "roles:update"),
    ("DELETE", "/api/v1/roles/{role_id}", "roles:delete"),
    ("POST", "/api/v1/roles/{role_id}/users", "roles:assign"),
    (
        "DELETE",
        "/api/v1/roles/{role_id}/users/{user_id}",
        "roles:unassign",
    ),
    ("POST", "/api/v1/roles/{role_id}/groups", "roles:assign"),
    (
        "DELETE",
        "/api/v1/roles/{role_id}/groups/{group_id}",
        "roles:unassign",
    ),
    // Permissions
    ("GET", "/api/v1/permissions", "permissions:list"),
    ("POST", "/api/v1/permissions", "permissions:create"),
    (
        "GET",
        "/api/v1/permissions/{permission_id}",
        "permissions:get",
    ),
    (
        "PUT",
        "/api/v1/permissions/{permission_id}",
        "permissions:update",
    ),
    (
        "DELETE",
        "/api/v1/permissions/{permission_id}",
        "permissions:delete",
    ),
    (
        "GET",
        "/api/v1/roles/{role_id}/permissions",
        "permissions:list",
    ),
    (
        "POST",
        "/api/v1/roles/{role_id}/permissions",
        "permissions:grant",
    ),
    (
        "DELETE",
        "/api/v1/roles/{role_id}/permissions/{permission_id}",
        "permissions:revoke",
    ),
    // Resources
    ("GET", "/api/v1/resources", "resources:list"),
    ("POST", "/api/v1/resources", "resources:create"),
    ("GET", "/api/v1/resources/{resource_id}", "resources:get"),
    ("PUT", "/api/v1/resources/{resource_id}", "resources:update"),
    (
        "DELETE",
        "/api/v1/resources/{resource_id}",
        "resources:delete",
    ),
    (
        "GET",
        "/api/v1/resources/{resource_id}/children",
        "resources:list_children",
    ),
    (
        "GET",
        "/api/v1/resources/{resource_id}/ancestors",
        "resources:list_ancestors",
    ),
    // Scopes
    (
        "GET",
        "/api/v1/resources/{resource_id}/scopes",
        "scopes:list",
    ),
    (
        "POST",
        "/api/v1/resources/{resource_id}/scopes",
        "scopes:create",
    ),
    (
        "GET",
        "/api/v1/resources/{resource_id}/scopes/{scope_id}",
        "scopes:get",
    ),
    (
        "PUT",
        "/api/v1/resources/{resource_id}/scopes/{scope_id}",
        "scopes:update",
    ),
    (
        "DELETE",
        "/api/v1/resources/{resource_id}/scopes/{scope_id}",
        "scopes:delete",
    ),
    // Certificates
    ("GET", "/api/v1/certificates", "certificates:list"),
    ("POST", "/api/v1/certificates", "certificates:generate"),
    ("GET", "/api/v1/certificates/{id}", "certificates:get"),
    (
        "POST",
        "/api/v1/certificates/{id}/revoke",
        "certificates:revoke",
    ),
    (
        "POST",
        "/api/v1/service-accounts/{sa_id}/bind-certificate",
        "certificates:bind",
    ),
    // Audit Logs
    ("GET", "/api/v1/audit-logs", "audit_logs:list"),
    ("GET", "/api/v1/audit-logs/system", "audit_logs:list_system"),
    // Service Accounts
    ("GET", "/api/v1/service-accounts", "service_accounts:list"),
    (
        "POST",
        "/api/v1/service-accounts",
        "service_accounts:create",
    ),
    (
        "GET",
        "/api/v1/service-accounts/{sa_id}",
        "service_accounts:get",
    ),
    (
        "PUT",
        "/api/v1/service-accounts/{sa_id}",
        "service_accounts:update",
    ),
    (
        "DELETE",
        "/api/v1/service-accounts/{sa_id}",
        "service_accounts:delete",
    ),
    (
        "POST",
        "/api/v1/service-accounts/{sa_id}/rotate-secret",
        "service_accounts:rotate_secret",
    ),
    // PGP Keys
    ("GET", "/api/v1/pgp-keys", "pgp_keys:list"),
    ("POST", "/api/v1/pgp-keys", "pgp_keys:generate"),
    ("GET", "/api/v1/pgp-keys/{id}", "pgp_keys:get"),
    ("POST", "/api/v1/pgp-keys/{id}/revoke", "pgp_keys:revoke"),
    ("POST", "/api/v1/pgp-keys/{id}/encrypt", "pgp_keys:encrypt"),
    (
        "POST",
        "/api/v1/pgp-keys/sign-audit-batch",
        "pgp_keys:sign_audit_batch",
    ),
    // Notification Rules
    (
        "GET",
        "/api/v1/notification-rules",
        "notification_rules:list",
    ),
    (
        "POST",
        "/api/v1/notification-rules",
        "notification_rules:create",
    ),
    (
        "GET",
        "/api/v1/notification-rules/{id}",
        "notification_rules:get",
    ),
    (
        "PUT",
        "/api/v1/notification-rules/{id}",
        "notification_rules:update",
    ),
    (
        "DELETE",
        "/api/v1/notification-rules/{id}",
        "notification_rules:delete",
    ),
    // Webhooks
    ("GET", "/api/v1/webhooks", "webhooks:list"),
    ("POST", "/api/v1/webhooks", "webhooks:create"),
    ("GET", "/api/v1/webhooks/{id}", "webhooks:get"),
    ("PUT", "/api/v1/webhooks/{id}", "webhooks:update"),
    ("DELETE", "/api/v1/webhooks/{id}", "webhooks:delete"),
    // OAuth2 Clients
    ("GET", "/api/v1/oauth2-clients", "oauth2_clients:list"),
    ("POST", "/api/v1/oauth2-clients", "oauth2_clients:create"),
    ("GET", "/api/v1/oauth2-clients/{id}", "oauth2_clients:get"),
    (
        "PUT",
        "/api/v1/oauth2-clients/{id}",
        "oauth2_clients:update",
    ),
    (
        "DELETE",
        "/api/v1/oauth2-clients/{id}",
        "oauth2_clients:delete",
    ),
    // Federation
    ("GET", "/api/v1/federation-configs", "federation:list"),
    ("POST", "/api/v1/federation-configs", "federation:create"),
    ("GET", "/api/v1/federation-configs/{id}", "federation:get"),
    (
        "PUT",
        "/api/v1/federation-configs/{id}",
        "federation:update",
    ),
    (
        "DELETE",
        "/api/v1/federation-configs/{id}",
        "federation:delete",
    ),
    // Federation Links (user-scoped, admin view)
    (
        "GET",
        "/api/v1/federation-links/user/{user_id}",
        "federation:list",
    ),
    (
        "DELETE",
        "/api/v1/federation-links/{id}",
        "federation:delete",
    ),
    // Settings
    ("GET", "/api/v1/settings", "settings:get"),
    ("PUT", "/api/v1/settings", "settings:update"),
];
