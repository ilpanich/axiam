// AUTO-GENERATED — do not edit by hand.
//
// Produced by `npm run gen:api-index` from `sdks/openapi.json`, which is
// itself drift-gated in CI against a fresh export from the server. Re-run the
// generator whenever the OpenAPI document changes.

/** One REST operation, in the shape the docs `api` block renders. */
export interface ApiOperation {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  summary: string;
  /** Reachable without an access token. */
  public?: boolean;
}

/** One domain's operations, in path order. */
export interface ApiGroup {
  /** Heading anchor, stable across regenerations. */
  id: string;
  label: string;
  blurb: string;
  operations: ApiOperation[];
}

/** The API version the document was exported from. */
export const API_VERSION = "1.0.0-beta07";
export const API_OPERATION_COUNT = 207;
export const API_PATH_COUNT = 142;

export const API_INDEX: ApiGroup[] = [
 {
  "id": "api-authentication-sessions",
  "label": "Authentication & sessions",
  "blurb": "Signing in, keeping a session alive, the account lifecycle, and the WebAuthn ceremonies.",
  "operations": [
   {
    "method": "POST",
    "path": "/api/v1/auth/device",
    "summary": "Authenticate a device via its client certificate (mTLS).",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/login",
    "summary": "",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/logout",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/auth/me",
    "summary": "Returns the authenticated user's profile."
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/mfa/confirm",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/mfa/enroll",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/mfa/setup/confirm",
    "summary": "Confirm MFA enrollment and complete login using a setup token.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/mfa/setup/enroll",
    "summary": "Start MFA enrollment using a setup token (issued during login when MFA is enforced but not yet configured).",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/mfa/verify",
    "summary": "",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/opaque/login/finish",
    "summary": "Returns the same three outcomes as `POST /api/v1/auth/login` — `200` with session cookies, `202` for an MFA challenge, `403` for MFA setup — so a client can share one result handler across both login paths.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/opaque/login/start",
    "summary": "",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/opaque/register/start",
    "summary": "",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/password/change",
    "summary": "Change the authenticated user's password."
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/refresh",
    "summary": "",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/resend-verification",
    "summary": "Creates a new email verification token and enqueues it for async delivery via the mail queue (D-14).",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/reset",
    "summary": "Initiates a password reset by enqueuing an `OutboundMailMessage` to the async mail queue.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/reset/confirm",
    "summary": "Confirms a password reset using a one-time token and a new password.",
    "public": true
   },
   {
    "method": "GET",
    "path": "/api/v1/auth/reset/context",
    "summary": "Password reset would otherwise be a permanent hole in OPAQUE coverage.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/verify-email",
    "summary": "Verifies a user's email using a one-time token.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/webauthn/authenticate/discoverable/finish",
    "summary": "Complete a usernameless ceremony.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/webauthn/authenticate/discoverable/start",
    "summary": "Begin a **usernameless** WebAuthn ceremony for a workspace.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/webauthn/authenticate/finish",
    "summary": "Complete a WebAuthn passkey authentication ceremony.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/webauthn/authenticate/start",
    "summary": "Begin a WebAuthn passkey authentication ceremony.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/webauthn/register/finish",
    "summary": "Complete a WebAuthn passkey registration ceremony."
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/webauthn/register/start",
    "summary": "Begin a WebAuthn passkey registration ceremony for the authenticated user."
   },
   {
    "method": "POST",
    "path": "/api/v1/device/decide",
    "summary": "Record the user's approval or refusal."
   },
   {
    "method": "GET",
    "path": "/api/v1/device/verify",
    "summary": "Look up a pending grant by the code the user typed."
   },
   {
    "method": "POST",
    "path": "/api/v1/mds/refresh",
    "summary": "Fetches (or, when `AXIAM__PKI__MDS_BLOB_PATH` is set, loads locally), verifies, and ingests the FIDO MDS3 BLOB."
   },
   {
    "method": "GET",
    "path": "/api/v1/mds/status",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/tenants/{tenant_id}/webauthn/compliance-report",
    "summary": ""
   }
  ]
 },
 {
  "id": "api-oauth2-openid-connect",
  "label": "OAuth2 & OpenID Connect",
  "blurb": "The authorization server, its clients, and the discovery documents.",
  "operations": [
   {
    "method": "GET",
    "path": "/.well-known/openid-configuration",
    "summary": "Returns the OpenID Provider metadata per OpenID Connect Discovery 1.0.",
    "public": true
   },
   {
    "method": "GET",
    "path": "/api/v1/oauth2-clients",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/oauth2-clients",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/oauth2-clients/{id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/oauth2-clients/{id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/oauth2-clients/{id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/oauth2/authorize",
    "summary": "The user must be authenticated (redirected to login first if not)."
   },
   {
    "method": "POST",
    "path": "/oauth2/device_authorization",
    "summary": "Build an OAuth2 JSON error response with the appropriate HTTP status.",
    "public": true
   },
   {
    "method": "GET",
    "path": "/oauth2/end_session",
    "summary": "/`POST /oauth2/end_session` — OIDC RP-Initiated Logout 1.0 (B5).",
    "public": true
   },
   {
    "method": "POST",
    "path": "/oauth2/introspect",
    "summary": "Accepts form-encoded body.",
    "public": true
   },
   {
    "method": "GET",
    "path": "/oauth2/jwks",
    "summary": "Returns the public signing keys used by the authorization server so that relying parties can verify JWTs without sharing a secret.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/oauth2/par",
    "summary": "Accepts an authorization request over a direct, client-authenticated POST and returns an opaque `request_uri` to put in the browser redirect instead of the parameters.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/oauth2/revoke",
    "summary": "Accepts form-encoded body.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/oauth2/token",
    "summary": "Accepts form-encoded body per RFC 6749.",
    "public": true
   },
   {
    "method": "GET",
    "path": "/oauth2/userinfo",
    "summary": "Returns claims about the authenticated user."
   }
  ]
 },
 {
  "id": "api-federation",
  "label": "Federation",
  "blurb": "SAML service provider and OIDC relying-party configuration, and the SSO entry points.",
  "operations": [
   {
    "method": "POST",
    "path": "/api/v1/auth/federation/oidc/callback",
    "summary": "Consumes the state row (single-use), runs the verified OIDC flow from plan 04-02 (nonce from DB — not caller-supplied), provisions or links the user, and returns Set-Cookie response (no token in body).",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/auth/federation/oidc/start",
    "summary": "Generates a server-side state+nonce pair, persists it in `federation_login_state` (10-min TTL), and returns the IdP authorization URL.",
    "public": true
   },
   {
    "method": "GET",
    "path": "/api/v1/federation-configs",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/federation-configs",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/federation-configs/{id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/federation-configs/{id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/federation-configs/{id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/federation-links/{id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/federation-links/user/{user_id}",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/federation/oidc/authorize",
    "summary": "Builds the authorization URL for the external OIDC provider."
   },
   {
    "method": "POST",
    "path": "/api/v1/federation/oidc/callback",
    "summary": "Handles the callback from the external OIDC provider after user authentication."
   }
  ]
 },
 {
  "id": "api-identity",
  "label": "Identity",
  "blurb": "Users, the groups they belong to, and the service accounts that act without one.",
  "operations": [
   {
    "method": "GET",
    "path": "/api/v1/groups",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/groups",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/groups/{group_id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/groups/{group_id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/groups/{group_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/groups/{group_id}/members",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/groups/{group_id}/members",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/groups/{group_id}/members/{user_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/groups/{group_id}/service-accounts",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/groups/{group_id}/service-accounts",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/groups/{group_id}/service-accounts/{service_account_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/service-accounts",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/service-accounts",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/service-accounts/{sa_id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/service-accounts/{sa_id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/service-accounts/{sa_id}",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/service-accounts/{sa_id}/rotate-secret",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/service-accounts/{service_account_id}/groups",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/users",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/users",
    "summary": "Creates a user and atomically records a `terms_of_service` consent row (REQ-8 / Art. 7 proof of consent)."
   },
   {
    "method": "GET",
    "path": "/api/v1/users/{user_id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/users/{user_id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/users/{user_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/users/{user_id}/mfa-methods",
    "summary": "List all MFA methods registered for a user."
   },
   {
    "method": "DELETE",
    "path": "/api/v1/users/{user_id}/mfa-methods/{method_id}",
    "summary": "Remove a specific MFA method."
   },
   {
    "method": "POST",
    "path": "/api/v1/users/{user_id}/reset-mfa",
    "summary": "Reset MFA for a user — disables MFA, clears the secret, and revokes all existing sessions."
   },
   {
    "method": "POST",
    "path": "/api/v1/users/{user_id}/unlock",
    "summary": "Resets a locked user account: clears `locked_until`, resets `failed_login_attempts` to 0, and sets status back to `Active`."
   },
   {
    "method": "POST",
    "path": "/api/v1/users/me/resend-verification",
    "summary": "Resend the caller's **own** verification email, and say what happened."
   }
  ]
 },
 {
  "id": "api-data-subject-rights",
  "label": "Data-subject rights",
  "blurb": "GDPR export (Art. 15) and erasure (Art. 17), acting on the caller's own account.",
  "operations": [
   {
    "method": "POST",
    "path": "/api/v1/account/delete",
    "summary": "Initiates Art. 17 erasure: immediately disables the account, revokes all sessions, emails a single-use cancel link, and schedules purge at +30 d (D-07/D-08/D-09)."
   },
   {
    "method": "POST",
    "path": "/api/v1/account/export",
    "summary": "Enqueues an async GDPR Art. 15 data-export job."
   },
   {
    "method": "GET",
    "path": "/api/v1/account/export/{token}",
    "summary": "Single-use download of the GDPR export blob (D-13)."
   },
   {
    "method": "GET",
    "path": "/api/v1/auth/account/delete/cancel",
    "summary": "(token-authenticated; listed in `PUBLIC_PATHS`).",
    "public": true
   }
  ]
 },
 {
  "id": "api-authorization",
  "label": "Authorization",
  "blurb": "The graph a decision is read from — roles, permissions, resources and scopes — the check endpoints, and UMA's protection API.",
  "operations": [
   {
    "method": "GET",
    "path": "/.well-known/uma2-configuration",
    "summary": "Advertises only what v1 actually serves.",
    "public": true
   },
   {
    "method": "POST",
    "path": "/api/v1/authz/check",
    "summary": "Evaluate a single authorization check for the authenticated caller (or, if the caller holds `authz:check_as`, for an arbitrary subject)."
   },
   {
    "method": "POST",
    "path": "/api/v1/authz/check/batch",
    "summary": "Evaluate an ordered list of authorization checks."
   },
   {
    "method": "GET",
    "path": "/api/v1/groups/{group_id}/roles",
    "summary": "Lists a group's role assignments with the resource each is scoped to."
   },
   {
    "method": "GET",
    "path": "/api/v1/permissions",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/permissions",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/permissions/{permission_id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/permissions/{permission_id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/permissions/{permission_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/resources",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/resources",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/resources/{resource_id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/resources/{resource_id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/resources/{resource_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/resources/{resource_id}/ancestors",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/resources/{resource_id}/children",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/resources/{resource_id}/scopes",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/resources/{resource_id}/scopes",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/resources/{resource_id}/scopes/{scope_id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/resources/{resource_id}/scopes/{scope_id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/resources/{resource_id}/scopes/{scope_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/roles",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/roles",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/roles/{role_id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/roles/{role_id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/roles/{role_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/roles/{role_id}/groups",
    "summary": "Lists this role's group assignments (the inverse of `GET /groups/{group_id}/roles`), each with the resource it is scoped to — see [`list_users`] for why that field is here."
   },
   {
    "method": "POST",
    "path": "/api/v1/roles/{role_id}/groups",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/roles/{role_id}/groups/{group_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/roles/{role_id}/permissions",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/roles/{role_id}/permissions",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/roles/{role_id}/permissions/{permission_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/roles/{role_id}/service-accounts",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/roles/{role_id}/service-accounts",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/roles/{role_id}/service-accounts/{service_account_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/roles/{role_id}/users",
    "summary": "Lists this role's user assignments (the inverse of `GET /users/{user_id}/roles`)."
   },
   {
    "method": "POST",
    "path": "/api/v1/roles/{role_id}/users",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/roles/{role_id}/users/{user_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/service-accounts/{service_account_id}/roles",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/users/{user_id}/roles",
    "summary": "Lists a user's role assignments with the resource each is scoped to."
   },
   {
    "method": "POST",
    "path": "/uma2/perm",
    "summary": "# Who may call this A **Protection API Token**: an ordinary AXIAM access token carrying the `uma_protection` scope."
   },
   {
    "method": "GET",
    "path": "/uma2/rreg/resource_set",
    "summary": "Lists only the resources **this client** registered."
   },
   {
    "method": "POST",
    "path": "/uma2/rreg/resource_set",
    "summary": "Creates the resource **and** its declared scopes."
   },
   {
    "method": "GET",
    "path": "/uma2/rreg/resource_set/{id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/uma2/rreg/resource_set/{id}",
    "summary": "The scope list is **replaced**, not merged: FedAuthz defines the update as putting the resource set's new state, and a merge would make it impossible to remove a scope."
   },
   {
    "method": "DELETE",
    "path": "/uma2/rreg/resource_set/{id}",
    "summary": ""
   }
  ]
 },
 {
  "id": "api-organizations-tenants",
  "label": "Organizations & tenants",
  "blurb": "The tenancy boundary itself, the first-run bootstrap that creates it, and the settings and mail configuration that hang off it.",
  "operations": [
   {
    "method": "POST",
    "path": "/api/v1/admin/bootstrap",
    "summary": "Creates the initial admin user with the super-admin role and seeds the default permission set.",
    "public": true
   },
   {
    "method": "GET",
    "path": "/api/v1/organizations",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/organizations/{org_id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/organizations/{org_id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/organizations/{org_id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/organizations/{org_id}/email-config",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/organizations/{org_id}/email-config",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/organizations/{org_id}/email-config",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations/{org_id}/email-config/test",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/organizations/{org_id}/settings",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/organizations/{org_id}/settings",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/organizations/{org_id}/tenants",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations/{org_id}/tenants",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations/{org_id}/tenants/{tenant_id}/audit-export",
    "summary": "Streams the tenant's complete audit trail as newline-delimited JSON, one [`axiam_core::models::audit::AuditLogEntry`] per line, newest first, and records the export in that tenant's audit log — which is what [`delete`] then requires (T-118)."
   },
   {
    "method": "GET",
    "path": "/api/v1/settings",
    "summary": "Returns the effective (merged) security settings for the authenticated user's tenant."
   },
   {
    "method": "PUT",
    "path": "/api/v1/settings",
    "summary": "Set tenant-level overrides."
   },
   {
    "method": "GET",
    "path": "/api/v1/tenants/{tenant_id}/email-config",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/tenants/{tenant_id}/email-config",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/tenants/{tenant_id}/email-config",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/tenants/{tenant_id}/email-config/test",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/tenants/{tenant_id}/settings",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/tenants/{tenant_id}/settings",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/tenants/{tenant_id}/settings",
    "summary": ""
   }
  ]
 },
 {
  "id": "api-pki-certificates",
  "label": "PKI & certificates",
  "blurb": "Certificate authorities, issued certificates, and the OpenPGP keys audit exports are signed with.",
  "operations": [
   {
    "method": "GET",
    "path": "/api/v1/certificates",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/certificates",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/certificates/{id}",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/certificates/{id}/revoke",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/organizations/{org_id}/ca-certificates",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations/{org_id}/ca-certificates",
    "summary": "Generate a CA."
   },
   {
    "method": "GET",
    "path": "/api/v1/organizations/{org_id}/ca-certificates/{id}",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations/{org_id}/ca-certificates/{id}/migrate-custody",
    "summary": "Move this CA's signing key to the custodian the deployment is configured for."
   },
   {
    "method": "PUT",
    "path": "/api/v1/organizations/{org_id}/ca-certificates/{id}/mtls-trust-anchor",
    "summary": "Offer this CA — or stop offering it — as a trust anchor for mutual TLS."
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations/{org_id}/ca-certificates/{id}/revoke",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations/{org_id}/ca-certificates/import",
    "summary": "Register a CA an organization already has, instead of generating one."
   },
   {
    "method": "GET",
    "path": "/api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas",
    "summary": "Create a tenant signing CA beneath one of the organization's CAs, with the key generated by whoever the deployment's custodian is."
   },
   {
    "method": "POST",
    "path": "/api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas/sign-csr",
    "summary": "Sign a certificate signing request the tenant produced elsewhere."
   },
   {
    "method": "GET",
    "path": "/api/v1/pgp-keys",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/pgp-keys",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/pgp-keys/{id}",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/pgp-keys/{id}/encrypt",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/pgp-keys/{id}/revoke",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/pgp-keys/sign-audit-batch",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/service-accounts/{sa_id}/bind-certificate",
    "summary": ""
   }
  ]
 },
 {
  "id": "api-eventing",
  "label": "Eventing",
  "blurb": "Webhooks, reactors and notification rules — everything that tells something else what happened.",
  "operations": [
   {
    "method": "GET",
    "path": "/api/v1/notification-rules",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/notification-rules",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/notification-rules/{id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/notification-rules/{id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/notification-rules/{id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/reactors",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/reactors",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/reactors/{id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/reactors/{id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/reactors/{id}",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/reactors/events",
    "summary": "Served rather than documented so an admin UI, an SDK generator and an operator all read the same list the dispatcher enforces."
   },
   {
    "method": "GET",
    "path": "/api/v1/webhooks",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/webhooks",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/webhooks/{id}",
    "summary": ""
   },
   {
    "method": "PUT",
    "path": "/api/v1/webhooks/{id}",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/webhooks/{id}",
    "summary": ""
   }
  ]
 },
 {
  "id": "api-provisioning",
  "label": "Provisioning",
  "blurb": "SCIM provisioning tokens. The SCIM 2.0 endpoints themselves are served under `/scim/v2`.",
  "operations": [
   {
    "method": "GET",
    "path": "/api/v1/scim-tokens",
    "summary": ""
   },
   {
    "method": "POST",
    "path": "/api/v1/scim-tokens",
    "summary": ""
   },
   {
    "method": "DELETE",
    "path": "/api/v1/scim-tokens/{id}",
    "summary": "Revokes rather than deletes: the row is what lets an operator later answer \"was this credential still live on the day of the incident?\", and a deleted row answers nothing."
   }
  ]
 },
 {
  "id": "api-audit-operations",
  "label": "Audit & operations",
  "blurb": "The append-only trail, and the endpoints a monitor reads.",
  "operations": [
   {
    "method": "GET",
    "path": "/api/v1/audit-logs",
    "summary": ""
   },
   {
    "method": "GET",
    "path": "/api/v1/audit-logs/system",
    "summary": "Returns audit entries for unauthenticated/system requests (nil tenant_id)."
   },
   {
    "method": "GET",
    "path": "/health",
    "summary": "",
    "public": true
   },
   {
    "method": "GET",
    "path": "/ready",
    "summary": "",
    "public": true
   }
  ]
 }
];
