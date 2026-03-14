//! OpenAPI specification and Swagger UI configuration.

use utoipa::OpenApi;

use crate::handlers;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "AXIAM API",
        description = "Access eXtended Identity and Authorization Management — REST API",
        version = "0.1.0",
        license(name = "Apache-2.0"),
    ),
    paths(
        // Health
        crate::health::health,
        crate::health::ready,
        // Auth
        handlers::auth::login,
        handlers::auth::logout,
        handlers::auth::refresh,
        handlers::auth::enroll_mfa,
        handlers::auth::confirm_mfa,
        handlers::auth::verify_mfa,
        // Organizations
        handlers::organizations::create,
        handlers::organizations::list,
        handlers::organizations::get,
        handlers::organizations::update,
        handlers::organizations::delete,
        // Tenants
        handlers::tenants::create,
        handlers::tenants::list,
        handlers::tenants::get,
        handlers::tenants::update,
        handlers::tenants::delete,
        // Users
        handlers::users::create,
        handlers::users::list,
        handlers::users::get,
        handlers::users::update,
        handlers::users::delete,
        // Groups
        handlers::groups::create,
        handlers::groups::list,
        handlers::groups::get,
        handlers::groups::update,
        handlers::groups::delete,
        handlers::groups::add_member,
        handlers::groups::list_members,
        handlers::groups::remove_member,
        // Roles
        handlers::roles::create,
        handlers::roles::list,
        handlers::roles::get,
        handlers::roles::update,
        handlers::roles::delete,
        handlers::roles::assign_to_user,
        handlers::roles::unassign_from_user,
        handlers::roles::assign_to_group,
        handlers::roles::unassign_from_group,
        // Permissions
        handlers::permissions::create,
        handlers::permissions::list,
        handlers::permissions::get,
        handlers::permissions::update,
        handlers::permissions::delete,
        handlers::permissions::grant_to_role,
        handlers::permissions::list_role_permissions,
        handlers::permissions::revoke_from_role,
        // Resources
        handlers::resources::create,
        handlers::resources::list,
        handlers::resources::get,
        handlers::resources::update,
        handlers::resources::delete,
        handlers::resources::list_children,
        handlers::resources::list_ancestors,
        // Scopes
        handlers::scopes::create,
        handlers::scopes::list,
        handlers::scopes::get,
        handlers::scopes::update,
        handlers::scopes::delete,
        // CA Certificates
        handlers::ca_certificates::generate,
        handlers::ca_certificates::list,
        handlers::ca_certificates::get,
        handlers::ca_certificates::revoke,
        // Certificates
        handlers::certificates::generate,
        handlers::certificates::list,
        handlers::certificates::get,
        handlers::certificates::revoke,
        handlers::certificates::bind,
        handlers::auth::device_auth,
        // PGP Keys
        handlers::pgp_keys::generate,
        handlers::pgp_keys::list,
        handlers::pgp_keys::get,
        handlers::pgp_keys::revoke,
        handlers::pgp_keys::sign_audit_batch,
        handlers::pgp_keys::encrypt,
        // Webhooks
        handlers::webhooks::create,
        handlers::webhooks::list,
        handlers::webhooks::get,
        handlers::webhooks::update,
        handlers::webhooks::delete,
        // Audit Logs
        handlers::audit::list,
        handlers::audit::list_system,
        // Service Accounts
        handlers::service_accounts::create,
        handlers::service_accounts::list,
        handlers::service_accounts::get,
        handlers::service_accounts::update,
        handlers::service_accounts::delete,
        handlers::service_accounts::rotate_secret,
        // OAuth2 Clients
        handlers::oauth2_clients::create,
        handlers::oauth2_clients::list,
        handlers::oauth2_clients::get,
        handlers::oauth2_clients::update,
        handlers::oauth2_clients::delete,
        // OAuth2 Flow
        handlers::oauth2::authorize,
        handlers::oauth2::token,
        handlers::oauth2::revoke,
        handlers::oauth2::introspect,
        // OIDC
        handlers::oauth2::discovery,
        handlers::oauth2::jwks,
        handlers::oauth2::userinfo,
    ),
    components(schemas(
        // Health
        crate::health::HealthResponse,
        crate::health::ReadyResponse,
        // Auth
        handlers::auth::LoginRequest,
        handlers::auth::LoginSuccessResponse,
        handlers::auth::MfaRequiredResponse,
        handlers::auth::RefreshRequest,
        handlers::auth::LogoutRequest,
        handlers::auth::MfaConfirmRequest,
        handlers::auth::MfaVerifyRequest,
        handlers::auth::MfaEnrollResponse,
        handlers::auth::MfaConfirmResponse,
        // Organizations
        axiam_core::models::organization::Organization,
        axiam_core::models::organization::CreateOrganization,
        axiam_core::models::organization::UpdateOrganization,
        // Tenants
        axiam_core::models::tenant::Tenant,
        axiam_core::models::tenant::CreateTenant,
        axiam_core::models::tenant::UpdateTenant,
        handlers::tenants::CreateTenantRequest,
        // Users
        axiam_core::models::user::User,
        axiam_core::models::user::UserStatus,
        axiam_core::models::user::CreateUser,
        axiam_core::models::user::UpdateUser,
        handlers::users::CreateUserRequest,
        handlers::users::UpdateUserRequest,
        handlers::users::UserResponse,
        // Groups
        axiam_core::models::group::Group,
        axiam_core::models::group::CreateGroup,
        axiam_core::models::group::UpdateGroup,
        handlers::groups::CreateGroupRequest,
        handlers::groups::AddMemberRequest,
        // Roles
        axiam_core::models::role::Role,
        axiam_core::models::role::CreateRole,
        axiam_core::models::role::UpdateRole,
        axiam_core::models::role::RoleAssignment,
        handlers::roles::CreateRoleRequest,
        handlers::roles::AssignRoleToUserRequest,
        handlers::roles::AssignRoleToGroupRequest,
        // Permissions
        axiam_core::models::permission::Permission,
        axiam_core::models::permission::CreatePermission,
        axiam_core::models::permission::UpdatePermission,
        axiam_core::models::permission::PermissionGrant,
        handlers::permissions::CreatePermissionRequest,
        handlers::permissions::GrantPermissionRequest,
        // Resources
        axiam_core::models::resource::Resource,
        axiam_core::models::resource::CreateResource,
        axiam_core::models::resource::UpdateResource,
        handlers::resources::CreateResourceRequest,
        // Scopes
        axiam_core::models::scope::Scope,
        axiam_core::models::scope::CreateScope,
        axiam_core::models::scope::UpdateScope,
        handlers::scopes::CreateScopeRequest,
        // Service Accounts
        axiam_core::models::service_account::ServiceAccount,
        axiam_core::models::service_account::CreateServiceAccount,
        axiam_core::models::service_account::UpdateServiceAccount,
        handlers::service_accounts::CreateServiceAccountRequest,
        handlers::service_accounts::ServiceAccountResponse,
        handlers::service_accounts::ServiceAccountCreatedResponse,
        handlers::service_accounts::RotateSecretResponse,
        // CA Certificates
        axiam_core::models::certificate::CaCertificate,
        axiam_core::models::certificate::CreateCaCertificate,
        axiam_core::models::certificate::GeneratedCaCertificate,
        axiam_core::models::certificate::CertificateStatus,
        axiam_core::models::certificate::KeyAlgorithm,
        // Certificates
        axiam_core::models::certificate::Certificate,
        axiam_core::models::certificate::CreateCertificate,
        axiam_core::models::certificate::GeneratedCertificate,
        axiam_core::models::certificate::CertificateType,
        axiam_core::models::certificate::BindCertificate,
        axiam_core::models::certificate::CertificateBinding,
        axiam_core::models::certificate::DeviceAuthResponse,
        // PGP Keys
        axiam_core::models::pgp_key::PgpKey,
        axiam_core::models::pgp_key::CreatePgpKey,
        axiam_core::models::pgp_key::GeneratedPgpKey,
        axiam_core::models::pgp_key::PgpKeyPurpose,
        axiam_core::models::pgp_key::PgpKeyStatus,
        axiam_core::models::pgp_key::PgpKeyAlgorithm,
        axiam_core::models::pgp_key::SignedAuditBatch,
        axiam_core::models::pgp_key::SignAuditBatchRequest,
        axiam_core::models::pgp_key::EncryptedExport,
        axiam_core::models::pgp_key::EncryptRequest,
        // Audit
        axiam_core::models::audit::AuditLogEntry,
        axiam_core::models::audit::ActorType,
        axiam_core::models::audit::AuditOutcome,
        // Webhooks
        axiam_core::models::webhook::RetryPolicy,
        handlers::webhooks::CreateWebhookRequest,
        handlers::webhooks::UpdateWebhookRequest,
        handlers::webhooks::WebhookResponse,
        // OAuth2 Clients
        handlers::oauth2_clients::CreateOAuth2ClientRequest,
        handlers::oauth2_clients::UpdateOAuth2ClientRequest,
        handlers::oauth2_clients::OAuth2ClientResponse,
        handlers::oauth2_clients::OAuth2ClientCreatedResponse,
        // OAuth2 Flow
        handlers::oauth2::OAuth2ErrorResponse,
        axiam_oauth2::token::TokenResponse,
        axiam_oauth2::token::RevokeRequest,
        axiam_oauth2::token::IntrospectRequest,
        axiam_oauth2::token::IntrospectionResponse,
        // OIDC
        axiam_oauth2::oidc::OidcDiscoveryDocument,
        axiam_oauth2::oidc::JwksDocument,
        axiam_oauth2::oidc::Jwk,
        axiam_oauth2::oidc::UserInfoResponse,
        // Pagination
        axiam_core::repository::Pagination,
    )),
    tags(
        (name = "health", description = "Health and readiness probes"),
        (name = "auth", description = "Authentication — login, logout, refresh, MFA"),
        (name = "organizations", description = "Organization management"),
        (name = "tenants", description = "Tenant management"),
        (name = "users", description = "User management"),
        (name = "groups", description = "Group management and membership"),
        (name = "roles", description = "Role management and assignment"),
        (name = "permissions", description = "Permission management and grants"),
        (name = "resources", description = "Resource management and hierarchy"),
        (name = "scopes", description = "Scope management (sub-resource permissions)"),
        (name = "ca-certificates", description = "CA certificate management"),
        (name = "certificates", description = "Tenant certificate lifecycle"),
        (name = "pgp-keys", description = "OpenPGP key management and audit signing"),
        (name = "audit", description = "Audit log queries"),
        (name = "webhooks", description = "Webhook registration and management"),
        (name = "service-accounts", description = "Service account management"),
        (name = "oauth2-clients", description = "OAuth2 client registration and management"),
        (name = "oauth2", description = "OAuth2 authorization and token endpoints"),
        (name = "oidc", description = "OpenID Connect discovery, JWKS, and UserInfo"),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

/// Adds Bearer JWT security scheme to the OpenAPI spec.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}
