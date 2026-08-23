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
    // Reactors (X1)
    //
    // Deliberately the same five verbs as every other admin surface rather
    // than a bespoke set. A reactor registration can veto a login or add a
    // claim to a token, so it is emphatically not a low-privilege object —
    // but the privilege lives in `reactors:create`/`update` being admin-only,
    // not in inventing a permission vocabulary an operator has to learn.
    (
        "reactors:list",
        "List reactors and the hookable event registry",
    ),
    ("reactors:get", "Retrieve a single reactor"),
    ("reactors:create", "Register a reactor"),
    ("reactors:update", "Update a reactor registration"),
    ("reactors:delete", "Delete a reactor registration"),
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
    // Email Config (FUNC-03 / D-13)
    (
        "email_config:read",
        "Read organization or tenant email configuration (secrets never returned)",
    ),
    (
        "email_config:write",
        "Create, update, or delete organization or tenant email configuration",
    ),
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
    // GDPR data-subject rights (D-07/D-13)
    (
        "gdpr:export",
        "Request or download a GDPR Art. 15 data export",
    ),
    (
        "users:erase",
        "Request GDPR Art. 17 erasure of a user account",
    ),
    // Authz check-as override (FND-04, D-06)
    (
        "authz:check_as",
        "Perform an authorization check on behalf of another subject (admin override)",
    ),
    // WebAuthn Attestation Policy (X3 wave 3, D5/D9). Deliberately its own
    // pair rather than reusing settings:get/settings:update — see
    // handlers::webauthn_policy's module docs for why the attestation
    // policy is not part of the SecuritySettings inheritance model.
    (
        "webauthn_policy:read",
        "Read a tenant's WebAuthn attestation policy or compliance report",
    ),
    (
        "webauthn_policy:write",
        "Update a tenant's WebAuthn attestation policy",
    ),
    // SCIM 2.0 provisioning (R3.1/B4). A single dedicated permission gates
    // every `/scim/v2/*` route (Users + Groups CRUD/PATCH) — the crate lives
    // outside this one (`axiam-scim`) and is not part of `ROUTE_PERMISSION_MAP`
    // (a different mount point, wired directly in `axiam-server`), but the
    // permission itself is declared here, the same registry every other
    // AXIAM permission is declared in, so it is seeded per-tenant exactly
    // like `users:create` etc. See `axiam_scim::auth` for the enforcement
    // code path.
    (
        // SEC-098: the description names the password capability because the
        // permission is strictly more powerful than `users:create` +
        // `users:update` combined, and nothing else told the operator. RFC
        // 7643 §4.1.1 makes `password` a writable User attribute, and
        // `PATCH /scim/v2/Users/{id}` honours it — so a holder can set ANY
        // user's password in the tenant, including a tenant administrator's,
        // and then log in as them. The native admin API has no equivalent:
        // `handlers::users::update` never writes `password_hash`. An operator
        // granting this to an Okta or Entra integration identity is granting
        // tenant-wide account takeover, and must know that before they grant
        // it.
        "scim:provision",
        "Provision/deprovision users and groups via the SCIM 2.0 endpoint. \
         WARNING: includes setting ANY user's password in this tenant \
         (RFC 7643 §4.1.1), including an administrator's — a capability no \
         native users:* permission confers.",
    ),
    // SCIM provisioning tokens — the long-lived credential an IdP pastes into
    // its SCIM connector (`claude_dev/scim-provisioning-token-design.md`).
    //
    // Separate from `scim:provision` on purpose. Minting a credential for a
    // provisioner is an administrative act; the provisioner itself must not be
    // able to mint more of itself, which is exactly what would happen if these
    // rode along on the permission the token's own principal holds.
    (
        "scim_tokens:create",
        "Mint a SCIM provisioning token. WARNING: the resulting credential \
         authenticates as the tenant user it is bound to, so it inherits \
         everything that user's scim:provision grant confers — including \
         setting any user's password.",
    ),
    (
        "scim_tokens:list",
        "List SCIM provisioning tokens and their status (metadata only — a \
         token's value is shown once, at creation, and never again)",
    ),
    ("scim_tokens:revoke", "Revoke a SCIM provisioning token"),
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
    // Authentication flows (under /api/v1/auth scope)
    "/api/v1/auth/login",
    // OPAQUE login is a sibling of /login and is unauthenticated for the same
    // reason: it is how a caller *becomes* authenticated. Both halves of the
    // exchange must be listed — the start because the caller has no credential
    // yet, and the finish because the credential it presents is a `KE3`, which
    // this middleware knows nothing about.
    //
    // `register/start` is public by necessity rather than by analogy: it is
    // called while creating a user who does not exist yet, so there is nobody
    // to authenticate as. It is safe because the server mints the credential
    // identifier itself, so the OPRF evaluations an anonymous caller can
    // obtain are under identifiers they neither chose nor can predict.
    "/api/v1/auth/opaque/register/start",
    "/api/v1/auth/opaque/login/start",
    "/api/v1/auth/opaque/login/finish",
    // Token-gated: the caller presents a reset token, which is the credential.
    "/api/v1/auth/reset/context",
    // Refresh authenticates via its own opaque `axiam_refresh` cookie, not the
    // access token. It MUST be public: the `axiam_access` cookie expires with
    // the 15-min access token, so a client refreshing after expiry carries no
    // access credential — `AuthzMiddleware` would otherwise 401 it before the
    // handler runs, making token rotation impossible.
    "/api/v1/auth/refresh",
    // SEC-047: /api/v1/auth/register removed from public paths — registration is now gated.
    "/api/v1/auth/device",
    "/api/v1/auth/mfa/verify",
    "/api/v1/auth/mfa/setup/enroll",
    "/api/v1/auth/mfa/setup/confirm",
    "/api/v1/auth/reset",
    "/api/v1/auth/reset/confirm",
    "/api/v1/auth/verify-email",
    "/api/v1/auth/resend-verification",
    // WebAuthn — public registration/authentication initiation
    "/api/v1/auth/webauthn/register/start",
    "/api/v1/auth/webauthn/register/finish",
    "/api/v1/auth/webauthn/authenticate/start",
    "/api/v1/auth/webauthn/authenticate/finish",
    // Usernameless sign-in: public for the same reason as the pair above —
    // these ARE the authentication, so requiring a credential to reach them
    // would be circular.
    "/api/v1/auth/webauthn/authenticate/discoverable/start",
    "/api/v1/auth/webauthn/authenticate/discoverable/finish",
    // Health probes
    "/health",
    "/ready",
    // OIDC discovery and token endpoints
    "/.well-known/openid-configuration",
    // UMA 2.0 discovery (X2). Public for the same reason as OIDC discovery:
    // §2 makes it the document a resource server fetches *before* it holds any
    // credential, and it carries only endpoint URLs the deployment publishes.
    "/.well-known/uma2-configuration",
    "/oauth2/jwks",
    "/oauth2/authorize",
    "/oauth2/token",
    "/oauth2/userinfo",
    "/oauth2/revoke",
    "/oauth2/introspect",
    // B2 / RFC 8628 §3.1. Necessarily public: the grant exists precisely for
    // clients that cannot hold a secret (a television, a headless CLI), so
    // there is no credential the device could present here. `client_id` is
    // still checked against the tenant's registered clients inside the
    // handler — the endpoint is unauthenticated, not unvalidated.
    "/oauth2/device_authorization",
    // B5 / RFC 9126. Public to `AuthzMiddleware` in the same sense the token
    // endpoint is: it takes no AXIAM session or bearer token, because the
    // caller is a client authenticating with its own credentials in the form
    // body — which the handler verifies through the same
    // `authenticate_client` path the token endpoint uses. Unauthenticated by
    // the middleware's definition, not by the endpoint's.
    "/oauth2/par",
    // B5 / RP-Initiated Logout 1.0 §2. Necessarily public: a user whose
    // session has ALREADY expired must still be able to complete a logout,
    // and requiring a live session to end a session is a contradiction. The
    // endpoint identifies what to terminate from a *signed* `id_token_hint`,
    // so it is unauthenticated, not unauthenticated-and-unbounded.
    "/oauth2/end_session",
    // Federation callback endpoints (unauthenticated — IdP redirects here)
    "/api/v1/federation/oidc/callback",
    "/api/v1/federation/saml/acs",
    // NOTE: /api/v1/federation/saml/metadata is intentionally NOT public — its
    // handler requires an authenticated admin (AuthenticatedUser/JWT). It was
    // previously listed here, which contradicted the handler and returned 401
    // to unauthenticated callers (Phase 28 FUNC-01 verification, D-15 scope
    // decision: keep metadata JWT-gated rather than making it public).
    // First-time SSO (Phase 4 D-22) — unauthenticated, distinct from
    // /api/v1/federation/* link-account endpoints (which require auth).
    "/api/v1/auth/federation/oidc/start",
    "/api/v1/auth/federation/oidc/callback",
    "/api/v1/auth/federation/saml/login",
    "/api/v1/auth/federation/saml/acs",
    // Admin bootstrap (public until first admin is created; handler enforces one-shot logic)
    "/api/v1/admin/bootstrap",
    // OpenAPI docs
    "/api/docs/*",
    // GDPR delete-cancel link (emailed, public — single-use token-gated, D-09)
    "/api/v1/auth/account/delete/cancel",
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
    // Reading which roles a subject holds is role data, so it takes the same
    // permission as reading a role's members from the other side.
    ("GET", "/api/v1/users/{user_id}/roles", "roles:get"),
    ("GET", "/api/v1/groups/{group_id}/roles", "roles:get"),
    ("GET", "/api/v1/roles/{role_id}/users", "roles:get"),
    ("POST", "/api/v1/roles/{role_id}/users", "roles:assign"),
    (
        "DELETE",
        "/api/v1/roles/{role_id}/users/{user_id}",
        "roles:unassign",
    ),
    ("GET", "/api/v1/roles/{role_id}/groups", "roles:get"),
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
    // SCIM provisioning tokens
    ("POST", "/api/v1/scim-tokens", "scim_tokens:create"),
    ("GET", "/api/v1/scim-tokens", "scim_tokens:list"),
    ("DELETE", "/api/v1/scim-tokens/{id}", "scim_tokens:revoke"),
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
    // Reactors (X1)
    //
    // `/reactors/events` returns the hookable-event registry. It is gated by
    // `reactors:list` rather than left public: the registry names every hook
    // that exists and what each may mutate, which is a map of the extension
    // surface and not something to hand to an unauthenticated caller.
    ("GET", "/api/v1/reactors/events", "reactors:list"),
    ("GET", "/api/v1/reactors", "reactors:list"),
    ("POST", "/api/v1/reactors", "reactors:create"),
    ("GET", "/api/v1/reactors/{id}", "reactors:get"),
    ("PUT", "/api/v1/reactors/{id}", "reactors:update"),
    ("DELETE", "/api/v1/reactors/{id}", "reactors:delete"),
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
    // The same overrides addressed by tenant id, for the organization's tenant
    // detail page. Same permissions: it is the same tenant-scoped policy, and
    // the handler additionally refuses a tenant that is not the caller's own.
    (
        "GET",
        "/api/v1/tenants/{tenant_id}/settings",
        "settings:get",
    ),
    (
        "PUT",
        "/api/v1/tenants/{tenant_id}/settings",
        "settings:update",
    ),
    (
        "DELETE",
        "/api/v1/tenants/{tenant_id}/settings",
        "settings:update",
    ),
    // Email Config (FUNC-03 / D-13) — single email_config:read/write permission
    // shared across org and tenant scopes (D-03), NOT per-verb-per-scope.
    (
        "GET",
        "/api/v1/organizations/{org_id}/email-config",
        "email_config:read",
    ),
    (
        "PUT",
        "/api/v1/organizations/{org_id}/email-config",
        "email_config:write",
    ),
    (
        "DELETE",
        "/api/v1/organizations/{org_id}/email-config",
        "email_config:write",
    ),
    (
        "GET",
        "/api/v1/tenants/{tenant_id}/email-config",
        "email_config:read",
    ),
    (
        "PUT",
        "/api/v1/tenants/{tenant_id}/email-config",
        "email_config:write",
    ),
    (
        "DELETE",
        "/api/v1/tenants/{tenant_id}/email-config",
        "email_config:write",
    ),
    // The delivery self-test sends real mail through the configured provider.
    // Gated on `email_config:write` rather than `:read`: it is the permission
    // that could change the sender identity anyway, and a read-only viewer
    // should not be able to make the system emit traffic.
    (
        "POST",
        "/api/v1/organizations/{org_id}/email-config/test",
        "email_config:write",
    ),
    (
        "POST",
        "/api/v1/tenants/{tenant_id}/email-config/test",
        "email_config:write",
    ),
    // WebAuthn Attestation Policy (X3 wave 3)
    (
        "GET",
        "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy",
        "webauthn_policy:read",
    ),
    (
        "PUT",
        "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy",
        "webauthn_policy:write",
    ),
    (
        "GET",
        "/api/v1/tenants/{tenant_id}/webauthn/compliance-report",
        "webauthn_policy:read",
    ),
    // FIDO MDS3 (X3 wave 3) — server-global, reuses the CA-admin permission
    // pair (see handlers::mds's module docs for the rationale).
    ("GET", "/api/v1/mds/status", "ca_certificates:list"),
    ("POST", "/api/v1/mds/refresh", "ca_certificates:generate"),
];
