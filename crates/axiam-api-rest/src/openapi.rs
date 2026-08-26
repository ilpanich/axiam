//! OpenAPI specification and Swagger UI configuration.

use utoipa::OpenApi;

use crate::handlers;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "AXIAM API",
        description = "Access eXtended Identity and Authorization Management — REST API",
        // Track the crate/workspace version automatically so the OpenAPI
        // `info.version` never drifts from Cargo.toml (axiam-api-rest inherits
        // `version.workspace = true`). Previously a hardcoded literal, which
        // silently drifted from the committed sdks/openapi.json on a version bump.
        version = env!("CARGO_PKG_VERSION"),
        license(name = "Apache-2.0"),
    ),
    paths(
        // Health
        crate::health::health,
        crate::health::ready,
        // Auth
        handlers::auth::login,
        handlers::opaque::opaque_register_start,
        handlers::opaque::opaque_login_start,
        handlers::opaque::opaque_login_finish,
        handlers::password_reset::reset_context,
        handlers::auth::logout,
        handlers::auth::refresh,
        handlers::auth::enroll_mfa,
        handlers::auth::confirm_mfa,
        handlers::auth::verify_mfa,
        handlers::auth::setup_enroll_mfa,
        handlers::auth::setup_confirm_mfa,
        handlers::auth::reset_mfa,
        // MFA Methods
        handlers::mfa_methods::list_mfa_methods,
        handlers::mfa_methods::delete_mfa_method,
        // WebAuthn
        handlers::webauthn::start_registration,
        handlers::webauthn::finish_registration,
        handlers::webauthn::start_authentication,
        handlers::webauthn::finish_authentication,
        handlers::webauthn::start_discoverable_authentication,
        handlers::webauthn::finish_discoverable_authentication,
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
        handlers::users::unlock,
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
        handlers::roles::list_users,
        handlers::roles::list_groups,
        handlers::roles::list_user_roles,
        handlers::roles::list_group_roles,
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
        handlers::ca_certificates::import,
        handlers::ca_certificates::list,
        handlers::ca_certificates::get,
        handlers::ca_certificates::revoke,
        handlers::ca_certificates::set_mtls_trust_anchor,
        handlers::ca_certificates::migrate_custody,
        handlers::ca_certificates::generate_intermediate,
        handlers::ca_certificates::sign_intermediate_csr,
        handlers::ca_certificates::list_intermediates,
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
        handlers::reactors::list_events,
        handlers::reactors::create,
        handlers::reactors::list,
        handlers::reactors::get,
        handlers::reactors::update,
        handlers::reactors::delete,
        handlers::webhooks::create,
        handlers::webhooks::list,
        handlers::webhooks::get,
        handlers::webhooks::update,
        handlers::webhooks::delete,
        // Audit Logs
        handlers::audit::list,
        handlers::audit::list_system,
        // GDPR — data-subject export (Art. 15) and erasure (Art. 17).
        // These four carried their `#[utoipa::path]` annotations from the day
        // they were written but were never listed here, so every export of this
        // document omitted them: absent from `sdks/openapi.json`, from the
        // served Swagger UI, and from anything generated off either.
        handlers::gdpr::request_account_export,
        handlers::gdpr::download_account_export,
        handlers::gdpr::request_account_delete,
        handlers::gdpr::cancel_account_delete,
        handlers::scim_tokens::create,
        handlers::scim_tokens::list,
        handlers::scim_tokens::revoke,
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
        // Device Authorization Grant (RFC 8628, B2). The token-endpoint arm
        // of the grant is `oauth2::token` above — one path, selected by
        // `grant_type` — so only the two extra paths appear here.
        handlers::oauth2::device_authorization,
        handlers::oauth2::pushed_authorization_request,
        handlers::oauth2::end_session,
        handlers::device::verify,
        handlers::device::decide,
        // OIDC
        handlers::oauth2::discovery,
        handlers::oauth2::jwks,
        handlers::oauth2::userinfo,
        // UMA 2.0 (X2)
        handlers::uma::permission_request,
        handlers::uma::uma2_configuration,
        handlers::uma::register_resource_set,
        handlers::uma::read_resource_set,
        handlers::uma::update_resource_set,
        handlers::uma::delete_resource_set,
        handlers::uma::list_resource_sets,
        // Settings
        handlers::settings::get_org_settings,
        handlers::settings::set_org_settings,
        handlers::settings::get_tenant_settings,
        handlers::settings::set_tenant_settings,
        handlers::settings::get_tenant_override,
        handlers::settings::set_tenant_override,
        handlers::settings::delete_tenant_override,
        // Email Config (FUNC-03 / D-13)
        handlers::email_config::get_org_email_config,
        handlers::email_config::set_org_email_config,
        handlers::email_config::delete_org_email_config,
        handlers::email_config::get_tenant_email_config,
        handlers::email_config::set_tenant_email_config,
        handlers::email_config::delete_tenant_email_config,
        handlers::email_config::test_org_email_config,
        handlers::email_config::test_tenant_email_config,
        // Federation
        handlers::federation::create,
        handlers::federation::list,
        handlers::federation::get,
        handlers::federation::update,
        handlers::federation::delete,
        handlers::federation::oidc_authorize,
        handlers::federation::oidc_callback,
        // SAML SP paths live in `SamlApiDoc` (feature-gated) and are merged in
        // by `api_doc()` when the `saml` feature is enabled.
        handlers::federation::list_user_links,
        handlers::federation::delete_link,
        // First-time SSO — public OIDC start/callback (FUNC-01 / D-12). The
        // SAML counterparts (saml_login_public, saml_acs_public) are
        // `#[cfg(feature = "saml")]` and documented in `SamlApiDoc` instead.
        handlers::federation::oidc_start_public,
        handlers::federation::oidc_callback_public,
        // Email Verification
        handlers::email_verification::verify_email,
        handlers::email_verification::resend_verification,
        // Password Reset
        handlers::password_reset::request_reset,
        handlers::password_reset::confirm_reset,
        // Notification Rules
        handlers::notification_rules::create,
        handlers::notification_rules::list,
        handlers::notification_rules::get,
        handlers::notification_rules::update,
        handlers::notification_rules::delete,
        // Authz check — FND-04 REST authorization surface (same engine as gRPC, D-08)
        handlers::authz_check::check_access,
        handlers::authz_check::batch_check_access,
        // WebAuthn Attestation Policy (X3 wave 3)
        handlers::webauthn_policy::get_policy,
        handlers::webauthn_policy::set_policy,
        handlers::webauthn_policy::compliance_report,
        // FIDO MDS3 (X3 wave 3)
        handlers::mds::status,
        handlers::mds::refresh,
    ),
    components(schemas(
        // Health
        crate::health::HealthResponse,
        crate::health::ReadyResponse,
        // Auth
        handlers::auth::LoginRequest,
        handlers::auth::LoginSuccessResponse,
        axiam_core::models::opaque::OpaqueRegisterStartRequest,
        axiam_core::models::opaque::OpaqueRegisterStartResponse,
        axiam_core::models::opaque::OpaqueLoginStartRequest,
        axiam_core::models::opaque::OpaqueLoginStartResponse,
        axiam_core::models::opaque::OpaqueLoginFinishRequest,
        axiam_core::models::opaque::OpaqueEnrollment,
        handlers::password_reset::ResetContextResponse,
        handlers::auth::MfaRequiredResponse,
        handlers::auth::RefreshRequest,
        handlers::auth::MfaConfirmRequest,
        handlers::auth::MfaVerifyRequest,
        handlers::auth::MfaEnrollResponse,
        handlers::auth::MfaConfirmResponse,
        handlers::auth::MfaSetupRequiredResponse,
        handlers::auth::MfaSetupEnrollRequest,
        handlers::auth::MfaSetupConfirmRequest,
        // WebAuthn
        handlers::webauthn::StartRegistrationResponse,
        handlers::webauthn::FinishRegistrationRequest,
        handlers::webauthn::CredentialResponse,
        handlers::webauthn::StartAuthenticationRequest,
        handlers::webauthn::StartDiscoverableAuthenticationRequest,
        handlers::webauthn::StartAuthenticationResponse,
        handlers::webauthn::FinishAuthenticationRequest,
        handlers::webauthn::WebauthnLoginResponse,
        axiam_core::models::webauthn_credential::WebauthnCredentialType,
        // MFA Methods
        handlers::mfa_methods::MfaMethodResponse,
        axiam_core::models::mfa_method::MfaMethodType,
        // Organizations
        axiam_core::models::organization::Organization,
        axiam_core::models::organization::CreateOrganization,
        axiam_core::models::organization::UpdateOrganization,
        // Tenants
        axiam_core::models::tenant::Tenant,
        axiam_core::models::tenant::TenantStatus,
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
        handlers::roles::RoleUserAssignment,
        handlers::roles::RoleGroupAssignment,
        // Permissions
        axiam_core::models::permission::Permission,
        axiam_core::models::permission::CreatePermission,
        axiam_core::models::permission::UpdatePermission,
        axiam_core::models::permission::PermissionGrant,
        crate::handlers::permissions::ResolvedPermissionGrant,
        crate::handlers::ca_certificates::SetMtlsTrustAnchor,
        crate::handlers::ca_certificates::MtlsTrustAnchorResponse,
        crate::handlers::ca_certificates::MigrateCustodyResponse,
        crate::handlers::permissions::GrantedScope,
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
        axiam_core::models::certificate::ImportCaCertificate,
        axiam_core::models::certificate::CreateCaCertificate,
        axiam_core::models::certificate::GeneratedCaCertificate,
        axiam_core::models::certificate::CreateIntermediateCa,
        axiam_core::models::certificate::SignIntermediateCsr,
        handlers::ca_certificates::CreateIntermediateCaRequest,
        handlers::ca_certificates::SignIntermediateCsrRequest,
        axiam_core::models::certificate::CertificateStatus,
        axiam_core::models::certificate::KeyAlgorithm,
        // Certificates
        axiam_core::models::certificate::Certificate,
        axiam_core::models::certificate::CreateCertificate,
        axiam_core::models::certificate::GeneratedCertificate,
        axiam_core::models::certificate::CertificateType,
        axiam_core::models::certificate::BindCertificate,
        axiam_core::models::scim_token::ScimTokenStatus,
        handlers::scim_tokens::CreateScimTokenRequest,
        handlers::scim_tokens::ScimTokenResponse,
        handlers::scim_tokens::CreateScimTokenResponse,
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
        // Federation
        handlers::federation::CreateFederationConfigRequest,
        handlers::federation::UpdateFederationConfigRequest,
        handlers::federation::FederationConfigResponse,
        // X4 — external-IdP token-exchange trust.
        handlers::federation::TokenExchangeTrustRequest,
        handlers::federation::TokenExchangeTrustResponse,
        handlers::federation::OidcAuthorizeRequest,
        handlers::federation::OidcCallbackRequest,
        handlers::federation::OidcCallbackResponse,
        // SAML SP schemas live in `SamlApiDoc` (feature-gated).
        handlers::federation::FederationLinkResponse,
        axiam_core::models::federation::FederationProtocol,
        // OAuth2 Flow
        handlers::oauth2::OAuth2ErrorResponse,
        axiam_oauth2::token::TokenResponse,
        axiam_oauth2::token::RevokeRequest,
        axiam_oauth2::token::IntrospectRequest,
        axiam_oauth2::token::IntrospectionResponse,
        axiam_oauth2::token::TokenRequest,
        // Device Authorization Grant (RFC 8628, B2)
        axiam_oauth2::device_service::DeviceAuthorizationRequest,
        axiam_oauth2::device_service::DeviceAuthorizationResponse,
        handlers::oauth2::PushedAuthorizationRequest,
        handlers::oauth2::PushedAuthorizationResponse,
        handlers::device::VerifyResponse,
        handlers::device::DecideRequest,
        handlers::device::DecideResponse,
        // Token Exchange (RFC 8693, B3). The request rides on `TokenRequest`
        // at `POST /oauth2/token`; these are the projected shape and the
        // distinct response body, both of which an SDK generator needs.
        axiam_oauth2::token_exchange::TokenExchangeRequest,
        axiam_oauth2::token_exchange::TokenExchangeResponse,
        // UMA 2.0 (X2). The ticket grant's request rides on `TokenRequest` at
        // `POST /oauth2/token` — the `ticket` / `claim_token` fields — so only
        // the Protection API's own bodies and the discovery document are
        // distinct shapes an SDK generator needs.
        axiam_core::models::uma::RequestedPermission,
        axiam_core::models::uma::RptPermission,
        handlers::uma::PermissionRequestBody,
        handlers::uma::PermissionTicketResponse,
        handlers::uma::Uma2Configuration,
        handlers::uma::ResourceSet,
        // OIDC
        axiam_oauth2::oidc::OidcDiscoveryDocument,
        axiam_oauth2::oidc::JwksDocument,
        axiam_oauth2::oidc::Jwk,
        axiam_oauth2::oidc::UserInfoResponse,
        // Settings
        axiam_core::models::settings::SecuritySettings,
        axiam_core::models::settings::SetOrgSettings,
        axiam_core::models::settings::TenantSettingsOverride,
        axiam_core::models::settings::SettingsScope,
        axiam_core::models::settings::PasswordPolicy,
        axiam_core::models::settings::MfaPolicy,
        axiam_core::models::settings::LockoutPolicy,
        axiam_core::models::settings::TokenPolicy,
        axiam_core::models::settings::EmailVerificationPolicy,
        axiam_core::models::settings::CertificatePolicy,
        axiam_core::models::settings::NotificationPolicy,
        // Email Config (FUNC-03 / D-13)
        axiam_core::models::email::EmailConfig,
        axiam_core::models::email::EmailConfigOverride,
        axiam_core::models::email::SetOrgEmailConfig,
        handlers::email_config::EmailTestResult,
        axiam_core::models::email::ProviderConfig,
        axiam_core::models::email::SmtpConfig,
        axiam_core::models::email::ApiProviderConfig,
        axiam_core::models::email::EmailProviderKind,
        // First-time SSO — public OIDC start/callback (FUNC-01 / D-12)
        handlers::federation::OidcStartRequest,
        handlers::federation::OidcStartResponse,
        handlers::federation::OidcPublicCallbackRequest,
        handlers::federation::SsoLoginSuccessResponse,
        // Email Verification
        handlers::email_verification::VerifyEmailRequest,
        handlers::email_verification::ResendVerificationRequest,
        // Password Reset
        handlers::password_reset::RequestResetBody,
        handlers::password_reset::ConfirmResetBody,
        // Notification Rules
        handlers::notification_rules::CreateNotificationRuleRequest,
        handlers::notification_rules::UpdateNotificationRuleRequest,
        handlers::notification_rules::NotificationRuleResponse,
        axiam_core::models::notification_rule::NotificationRule,
        axiam_core::models::notification_rule::NotificationEventType,
        // Authz check (FND-04)
        handlers::authz_check::CheckAccessBody,
        handlers::authz_check::CheckAccessResponse,
        handlers::authz_check::BatchCheckAccessBody,
        handlers::authz_check::BatchCheckAccessResponse,
        // Pagination
        axiam_core::repository::Pagination,
        // WebAuthn Attestation Policy (X3 wave 3)
        axiam_core::models::webauthn_policy::WebauthnAttestationPolicy,
        axiam_core::models::webauthn_policy::AttestationMode,
        axiam_core::models::webauthn_policy::UnknownAaguidAction,
        axiam_core::models::webauthn_policy::AttestationDenyReason,
        axiam_core::models::mds::CertificationLevel,
        handlers::webauthn_policy::PolicyResponse,
        handlers::webauthn_policy::ComplianceReportEntry,
        // FIDO MDS3 (X3 wave 3)
        handlers::mds::MdsStatusResponse,
        handlers::mds::MdsRefreshOutcome,
    )),
    tags(
        (name = "health", description = "Health and readiness probes"),
        (name = "auth", description = "Authentication — login, logout, refresh, MFA"),
        (name = "webauthn", description = "WebAuthn passkey registration and authentication"),
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
        (name = "settings", description = "Organization and tenant security settings"),
        (name = "email-config", description = "Organization and tenant email provider configuration"),
        (name = "federation", description = "OIDC and SAML federation with external IdPs"),
        (name = "federation-sso", description = "First-time SSO — public OIDC/SAML start and callback endpoints"),
        (name = "notification_rules", description = "Notification rule management"),
        (name = "authz", description = "Authorization check (FND-04 REST surface)"),
        (name = "webauthn-policy", description = "Tenant WebAuthn attestation policy and compliance reporting (X3)"),
        (name = "mds", description = "FIDO Alliance Metadata Service (MDS3) ingestion admin (X3)"),
        (name = "gdpr", description = "Data-subject export (Art. 15) and erasure (Art. 17)"),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

/// SAML SP paths and schemas, compiled only with the `saml` feature.
///
/// Kept separate from [`ApiDoc`] because utoipa's `paths()`/`schemas()` macro
/// arguments can't be `#[cfg]`-gated individually. [`api_doc`] merges this into
/// the main document when the feature is on.
#[cfg(feature = "saml")]
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::federation::saml_authn_request,
        handlers::federation::saml_acs,
        handlers::federation::saml_metadata,
        // First-time SSO — public SAML login/ACS (FUNC-01 / D-12).
        handlers::federation::saml_login_public,
        handlers::federation::saml_acs_public,
    ),
    components(schemas(
        handlers::federation::SamlAuthnRequestRequest,
        handlers::federation::SamlAuthnRequestResponse,
        handlers::federation::SamlAcsRequest,
        handlers::federation::SamlMetadataQuery,
        handlers::federation::SamlLoginRequest,
        handlers::federation::SamlLoginResponse,
        handlers::federation::SamlAcsPublicRequest,
    ))
)]
struct SamlApiDoc;

/// Build the full OpenAPI document, merging in the SAML SP endpoints when the
/// `saml` feature is enabled. Use this instead of `ApiDoc::openapi()` directly.
pub fn api_doc() -> utoipa::openapi::OpenApi {
    let doc = ApiDoc::openapi();
    #[cfg(feature = "saml")]
    let doc = doc.merge_from(SamlApiDoc::openapi());
    stamp_spec_digest(doc)
}

/// The extension key carrying the specification's content digest.
///
/// `x-`-prefixed, which is what the OpenAPI specification reserves for extensions, so a
/// validator and a code generator both ignore it.
pub const SPEC_DIGEST_KEY: &str = "x-axiam-spec-digest";

/// Stamp `info.x-axiam-spec-digest` with a SHA-256 over this document's own content.
///
/// **Why `info.version` is not enough.** It tracks `CARGO_PKG_VERSION`, which is the
/// release version — it moves when a release is cut, not when a path is added. Two builds
/// can therefore describe genuinely different APIs under the same string, and they have:
/// `main` and a release branch both reported `1.0.0-alpha44` while differing by two paths
/// (`ca-certificates/{id}/migrate-custody` and `.../mtls-trust-anchor`). A consumer pinning
/// on `info.version` — an SDK deciding whether to regenerate, a gateway caching a spec, a
/// contract test asserting it is current — could not tell those exports apart, and nothing
/// in the document let it.
///
/// The version keeps its meaning: it is the API's semantic version, and consumers should
/// keep reading it as one. This is the other question — "is this the same document?" —
/// answered separately and exactly.
///
/// Computed over the document with this field ABSENT, so the digest is a function of the
/// spec's content rather than of itself, and so re-stamping an already-stamped document is
/// idempotent.
fn stamp_spec_digest(mut doc: utoipa::openapi::OpenApi) -> utoipa::openapi::OpenApi {
    use sha2::{Digest, Sha256};

    // Absent, not empty: an empty `extensions` map serializes as no key at all here (the
    // field is `Option` and flattened), but clearing it explicitly is what makes the digest
    // computed below independent of whatever was there before.
    doc.info.extensions = None;

    let canonical = serde_json::to_vec(&doc).expect("OpenAPI serialization failed");
    let digest = hex::encode(Sha256::digest(&canonical));

    // Exactly one extension, deliberately. `Extensions` is a flattened `HashMap`, whose
    // iteration order is not stable across runs, so two or more entries here would make the
    // serialized bytes vary between builds — and the SDK OpenAPI drift gate compares them
    // byte for byte. A second extension needs an ordered map first.
    doc.info.extensions = Some(
        utoipa::openapi::extensions::ExtensionsBuilder::new()
            .add(SPEC_DIGEST_KEY, format!("sha256:{digest}"))
            .build(),
    );
    doc
}

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

#[cfg(test)]
mod spec_digest_tests {
    use super::{SPEC_DIGEST_KEY, api_doc};

    /// The digest is present, and says which algorithm produced it.
    #[test]
    fn the_document_carries_a_digest() {
        let doc = api_doc();
        let extensions = doc
            .info
            .extensions
            .as_ref()
            .expect("info carries no extensions");
        let value = extensions
            .get(SPEC_DIGEST_KEY)
            .and_then(|v| v.as_str())
            .expect("info carries no spec digest");

        // `sha256:` + 64 hex characters. Naming the algorithm inline is what lets this
        // change one day without every consumer having to guess from the length.
        assert!(
            value.starts_with("sha256:"),
            "unexpected digest form: {value}"
        );
        assert_eq!(value.len(), "sha256:".len() + 64);
        assert!(
            value["sha256:".len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    /// Two exports of the same build agree.
    ///
    /// Not a tautology: the digest is computed over a serialization of the whole document,
    /// and if any part of that serialization were order-unstable — a `HashMap` somewhere in
    /// the tree — this would flake. It is the same property the SDK OpenAPI drift gate
    /// depends on, asserted here where the failure names its cause.
    #[test]
    fn the_digest_is_stable_across_exports() {
        let first = api_doc();
        let second = api_doc();
        assert_eq!(
            first.info.extensions.as_ref().unwrap().get(SPEC_DIGEST_KEY),
            second
                .info
                .extensions
                .as_ref()
                .unwrap()
                .get(SPEC_DIGEST_KEY),
        );
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap(),
        );
    }

    /// A document that differs by one path gets a different digest.
    ///
    /// This is the whole point of the field, and the reason `info.version` could not serve:
    /// the version is the release version and moves when a release is cut, so two builds
    /// describing genuinely different APIs can and do report the same string. `main` and a
    /// release branch both said `1.0.0-alpha44` while differing by two paths.
    #[test]
    fn removing_a_path_changes_the_digest() {
        let full = api_doc();
        let before = full
            .info
            .extensions
            .as_ref()
            .unwrap()
            .get(SPEC_DIGEST_KEY)
            .cloned()
            .unwrap();

        let mut trimmed = api_doc();
        let victim = trimmed
            .paths
            .paths
            .keys()
            .next()
            .expect("the spec has no paths")
            .clone();
        // `remove`, not `shift_remove`: `preserve_path_order` is off in this build, so
        // `PathsMap` is a `BTreeMap`. That is also why the digest is stable — a BTreeMap
        // serializes in key order rather than in insertion order.
        trimmed.paths.paths.remove(&victim);
        let after = super::stamp_spec_digest(trimmed)
            .info
            .extensions
            .as_ref()
            .unwrap()
            .get(SPEC_DIGEST_KEY)
            .cloned()
            .unwrap();

        assert_ne!(
            before, after,
            "dropping {victim} left the digest unchanged, so it does not distinguish content"
        );
    }

    /// Re-stamping an already-stamped document is a no-op.
    ///
    /// The digest is computed with the field cleared, so it is a function of the content
    /// rather than of itself. Were it not, stamping twice would produce a different value
    /// the second time and the field would be unusable for comparison.
    #[test]
    fn stamping_is_idempotent() {
        let once = api_doc();
        let expected = once
            .info
            .extensions
            .as_ref()
            .unwrap()
            .get(SPEC_DIGEST_KEY)
            .cloned()
            .unwrap();

        let twice = super::stamp_spec_digest(once);
        assert_eq!(
            twice.info.extensions.as_ref().unwrap().get(SPEC_DIGEST_KEY),
            Some(&expected)
        );
    }
}
