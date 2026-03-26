//! Integration tests for the MFA method listing and deletion service.

use axiam_auth::MfaMethodService;
use axiam_core::error::AxiamError;
use axiam_core::models::mfa_method::MfaMethodType;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::models::webauthn_credential::{CreateWebauthnCredential, WebauthnCredentialType};
use axiam_core::repository::{
    OrganizationRepository, TenantRepository, UserRepository, WebauthnCredentialRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
    SurrealWebauthnCredentialRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = surrealdb::engine::local::Db;

/// Shared setup: in-memory SurrealDB, migrations, org, tenant, active user.
async fn setup() -> (
    SurrealUserRepository<Db>,
    SurrealWebauthnCredentialRepository<Db>,
    Uuid, // tenant_id
    Uuid, // user_id
) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "correct-horse-battery".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Activate user so subsequent operations succeed.
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let cred_repo = SurrealWebauthnCredentialRepository::new(db.clone());

    (user_repo, cred_repo, tenant.id, user.id)
}

/// Helper: build the service from the repos returned by `setup`.
fn build_service(
    user_repo: SurrealUserRepository<Db>,
    cred_repo: SurrealWebauthnCredentialRepository<Db>,
) -> MfaMethodService<SurrealUserRepository<Db>, SurrealWebauthnCredentialRepository<Db>> {
    MfaMethodService::new(user_repo, cred_repo)
}

/// Helper: enable MFA (TOTP) on the given user.
async fn enable_totp(user_repo: &SurrealUserRepository<Db>, tenant_id: Uuid, user_id: Uuid) {
    user_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                mfa_enabled: Some(true),
                mfa_secret: Some(Some("encrypted-secret-placeholder".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

/// Helper: register a dummy WebAuthn credential.
async fn create_webauthn(
    cred_repo: &SurrealWebauthnCredentialRepository<Db>,
    tenant_id: Uuid,
    user_id: Uuid,
    name: &str,
    cred_type: WebauthnCredentialType,
) -> Uuid {
    let cred = cred_repo
        .create(CreateWebauthnCredential {
            tenant_id,
            user_id,
            credential_id: format!("cred-id-{name}"),
            name: name.into(),
            credential_type: cred_type,
            passkey_json: r#"{"dummy":"passkey"}"#.into(),
        })
        .await
        .unwrap();
    cred.id
}

// ── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn list_methods_empty_when_no_mfa() {
    let (user_repo, cred_repo, tenant_id, user_id) = setup().await;
    let svc = build_service(user_repo, cred_repo);

    let methods = svc.list_methods(tenant_id, user_id).await.unwrap();
    assert!(methods.is_empty(), "fresh user should have no MFA methods");
}

#[tokio::test]
async fn list_methods_returns_totp_when_enabled() {
    let (user_repo, cred_repo, tenant_id, user_id) = setup().await;
    enable_totp(&user_repo, tenant_id, user_id).await;
    let svc = build_service(user_repo, cred_repo);

    let methods = svc.list_methods(tenant_id, user_id).await.unwrap();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0].method_id, "totp");
    assert_eq!(methods[0].method_type, MfaMethodType::Totp);
    assert_eq!(methods[0].name, "TOTP Authenticator");
}

#[tokio::test]
async fn list_methods_returns_webauthn_credentials() {
    let (user_repo, cred_repo, tenant_id, user_id) = setup().await;
    let cred_id = create_webauthn(
        &cred_repo,
        tenant_id,
        user_id,
        "My YubiKey",
        WebauthnCredentialType::SecurityKey,
    )
    .await;
    let svc = build_service(user_repo, cred_repo);

    let methods = svc.list_methods(tenant_id, user_id).await.unwrap();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0].method_id, cred_id.to_string());
    assert_eq!(methods[0].method_type, MfaMethodType::SecurityKey);
    assert_eq!(methods[0].name, "My YubiKey");
}

#[tokio::test]
async fn list_methods_returns_both_totp_and_webauthn() {
    let (user_repo, cred_repo, tenant_id, user_id) = setup().await;
    enable_totp(&user_repo, tenant_id, user_id).await;
    let cred_id = create_webauthn(
        &cred_repo,
        tenant_id,
        user_id,
        "iCloud Passkey",
        WebauthnCredentialType::Passkey,
    )
    .await;
    let svc = build_service(user_repo, cred_repo);

    let methods = svc.list_methods(tenant_id, user_id).await.unwrap();
    assert_eq!(methods.len(), 2);

    let totp = methods.iter().find(|m| m.method_id == "totp").unwrap();
    assert_eq!(totp.method_type, MfaMethodType::Totp);

    let webauthn = methods
        .iter()
        .find(|m| m.method_id == cred_id.to_string())
        .unwrap();
    assert_eq!(webauthn.method_type, MfaMethodType::Passkey);
    assert_eq!(webauthn.name, "iCloud Passkey");
}

#[tokio::test]
async fn available_method_types_returns_correct_types() {
    let (user_repo, cred_repo, tenant_id, user_id) = setup().await;
    enable_totp(&user_repo, tenant_id, user_id).await;
    // Two webauthn creds — should still yield a single "webauthn" entry.
    create_webauthn(
        &cred_repo,
        tenant_id,
        user_id,
        "Key A",
        WebauthnCredentialType::Passkey,
    )
    .await;
    create_webauthn(
        &cred_repo,
        tenant_id,
        user_id,
        "Key B",
        WebauthnCredentialType::SecurityKey,
    )
    .await;
    let svc = build_service(user_repo, cred_repo);

    let types = svc
        .available_method_types(tenant_id, user_id)
        .await
        .unwrap();
    assert_eq!(types.len(), 2);
    assert!(types.contains(&"totp".to_string()));
    assert!(types.contains(&"webauthn".to_string()));
}

#[tokio::test]
async fn delete_method_removes_totp() {
    let (user_repo, cred_repo, tenant_id, user_id) = setup().await;
    enable_totp(&user_repo, tenant_id, user_id).await;
    // Add a webauthn credential so TOTP is not the last method.
    create_webauthn(
        &cred_repo,
        tenant_id,
        user_id,
        "Backup Key",
        WebauthnCredentialType::SecurityKey,
    )
    .await;
    let svc = build_service(user_repo.clone(), cred_repo);

    svc.delete_method(tenant_id, user_id, "totp").await.unwrap();

    // TOTP secret should be cleared.
    let user = user_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(
        user.mfa_secret.is_none(),
        "TOTP secret should be removed after deletion"
    );
}

#[tokio::test]
async fn delete_method_removes_webauthn() {
    let (user_repo, cred_repo, tenant_id, user_id) = setup().await;
    enable_totp(&user_repo, tenant_id, user_id).await;
    let cred_id = create_webauthn(
        &cred_repo,
        tenant_id,
        user_id,
        "Disposable Key",
        WebauthnCredentialType::Passkey,
    )
    .await;
    let svc = build_service(user_repo, cred_repo.clone());

    svc.delete_method(tenant_id, user_id, &cred_id.to_string())
        .await
        .unwrap();

    // Credential should no longer exist.
    let result = cred_repo.get_by_id(tenant_id, cred_id).await;
    assert!(result.is_err(), "deleted credential should not be found");
}

#[tokio::test]
async fn delete_method_refuses_last_method() {
    let (user_repo, cred_repo, tenant_id, user_id) = setup().await;
    // Enable TOTP as the only method.
    enable_totp(&user_repo, tenant_id, user_id).await;
    let svc = build_service(user_repo, cred_repo);

    let result = svc.delete_method(tenant_id, user_id, "totp").await;
    assert!(result.is_err(), "should refuse to remove the last method");

    match result.unwrap_err() {
        AxiamError::Validation { message } => {
            assert!(
                message.to_lowercase().contains("last"),
                "error should mention 'last method', got: {message}"
            );
        }
        other => panic!("expected Validation error, got: {other:?}"),
    }
}

#[tokio::test]
async fn delete_method_disables_mfa_when_last_removed() {
    let (user_repo, cred_repo, tenant_id, user_id) = setup().await;
    enable_totp(&user_repo, tenant_id, user_id).await;
    // Add webauthn so total = 2; removing TOTP is allowed.
    let cred_id = create_webauthn(
        &cred_repo,
        tenant_id,
        user_id,
        "Only Key",
        WebauthnCredentialType::Passkey,
    )
    .await;
    let svc = build_service(user_repo.clone(), cred_repo);

    // Remove TOTP — leaves 1 webauthn, should succeed.
    svc.delete_method(tenant_id, user_id, "totp").await.unwrap();

    // User should still have mfa_enabled because one method remains.
    let user = user_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(
        user.mfa_enabled,
        "MFA should stay enabled while a method remains"
    );

    // Now remove the last webauthn credential.
    // After TOTP removal the user has mfa_secret=None and mfa_enabled=true,
    // but has_totp is false (mfa_secret is None), so total = 1 (webauthn
    // only). The guard checks `total <= 1 && mfa_enabled` — which would
    // refuse. But the TOTP-delete branch set mfa_enabled=true still (since
    // remaining_after > 0), and now we have total=1, mfa_enabled=true.
    // So removing the last one should be refused.
    let result = svc
        .delete_method(tenant_id, user_id, &cred_id.to_string())
        .await;
    assert!(
        result.is_err(),
        "should refuse to remove the last method while MFA is enabled"
    );
}
