//! Integration tests for `SurrealEmailTemplateRepository` (org + tenant
//! scoped custom email template CRUD) using in-memory SurrealDB.

use axiam_core::models::email_template::{SetEmailTemplate, TemplateKind};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{EmailTemplateRepository, OrganizationRepository, TenantRepository};
use axiam_db::repository::{
    SurrealEmailTemplateRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

async fn setup() -> (Db, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org-tmpl".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant-tmpl".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

fn input(kind: TemplateKind) -> SetEmailTemplate {
    SetEmailTemplate {
        kind,
        subject: "Subject {{username}}".into(),
        html_body: "<p>Hi {{username}}</p>".into(),
        text_body: "Hi {{username}}".into(),
    }
}

// ---------------------------------------------------------------------------
// Org-scoped templates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn org_template_get_returns_none_when_unset() {
    let (db, org_id, _tenant_id) = setup().await;
    let repo = SurrealEmailTemplateRepository::new(db);

    let got = repo
        .get_org_template(org_id, TemplateKind::Activation)
        .await
        .unwrap();
    assert!(got.is_none());
}

#[tokio::test]
async fn org_template_set_get_list_delete() {
    let (db, org_id, _tenant_id) = setup().await;
    let repo = SurrealEmailTemplateRepository::new(db);

    let created = repo
        .set_org_template(org_id, input(TemplateKind::Activation))
        .await
        .unwrap();
    assert_eq!(created.subject, "Subject {{username}}");

    let got = repo
        .get_org_template(org_id, TemplateKind::Activation)
        .await
        .unwrap()
        .expect("template should exist");
    assert_eq!(got.kind, TemplateKind::Activation);
    assert_eq!(got.scope_id, org_id);

    let list = repo.list_org_templates(org_id).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].kind, TemplateKind::Activation);

    repo.delete_org_template(org_id, TemplateKind::Activation)
        .await
        .unwrap();
    let after_delete = repo
        .get_org_template(org_id, TemplateKind::Activation)
        .await
        .unwrap();
    assert!(after_delete.is_none());
}

#[tokio::test]
async fn org_template_upsert_overwrites_existing() {
    let (db, org_id, _tenant_id) = setup().await;
    let repo = SurrealEmailTemplateRepository::new(db);

    repo.set_org_template(org_id, input(TemplateKind::PasswordReset))
        .await
        .unwrap();

    let mut updated_input = input(TemplateKind::PasswordReset);
    updated_input.subject = "Updated subject".into();
    let updated = repo.set_org_template(org_id, updated_input).await.unwrap();
    assert_eq!(updated.subject, "Updated subject");

    // Still exactly one row for this (scope, scope_id, kind) — upsert, not insert.
    let list = repo.list_org_templates(org_id).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].subject, "Updated subject");
}

// ---------------------------------------------------------------------------
// Tenant-scoped templates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tenant_template_set_get_list_delete() {
    let (db, _org_id, tenant_id) = setup().await;
    let repo = SurrealEmailTemplateRepository::new(db);

    repo.set_tenant_template(tenant_id, input(TemplateKind::MfaSetupReminder))
        .await
        .unwrap();

    let got = repo
        .get_tenant_template(tenant_id, TemplateKind::MfaSetupReminder)
        .await
        .unwrap()
        .expect("tenant template should exist");
    assert_eq!(got.scope_id, tenant_id);

    let list = repo.list_tenant_templates(tenant_id).await.unwrap();
    assert_eq!(list.len(), 1);

    repo.delete_tenant_template(tenant_id, TemplateKind::MfaSetupReminder)
        .await
        .unwrap();
    assert!(
        repo.get_tenant_template(tenant_id, TemplateKind::MfaSetupReminder)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn org_and_tenant_templates_are_independent() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealEmailTemplateRepository::new(db);

    repo.set_org_template(org_id, input(TemplateKind::AdminNotification))
        .await
        .unwrap();

    // A tenant with the same kind but distinct scope_id must not see the
    // org-scoped row.
    let tenant_view = repo
        .get_tenant_template(tenant_id, TemplateKind::AdminNotification)
        .await
        .unwrap();
    assert!(tenant_view.is_none());

    let org_list = repo.list_org_templates(org_id).await.unwrap();
    let tenant_list = repo.list_tenant_templates(tenant_id).await.unwrap();
    assert_eq!(org_list.len(), 1);
    assert!(tenant_list.is_empty());
}

#[tokio::test]
async fn delete_nonexistent_template_is_a_noop() {
    let (db, org_id, _tenant_id) = setup().await;
    let repo = SurrealEmailTemplateRepository::new(db);

    // Deleting a template kind that was never set must not error.
    let result = repo
        .delete_org_template(org_id, TemplateKind::ExportReady)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn list_templates_orders_by_kind_and_covers_multiple_kinds() {
    let (db, org_id, _tenant_id) = setup().await;
    let repo = SurrealEmailTemplateRepository::new(db);

    repo.set_org_template(org_id, input(TemplateKind::DeletionScheduled))
        .await
        .unwrap();
    repo.set_org_template(org_id, input(TemplateKind::ExportReady))
        .await
        .unwrap();

    let list = repo.list_org_templates(org_id).await.unwrap();
    assert_eq!(list.len(), 2);
    let kinds: Vec<TemplateKind> = list.iter().map(|t| t.kind).collect();
    assert!(kinds.contains(&TemplateKind::DeletionScheduled));
    assert!(kinds.contains(&TemplateKind::ExportReady));
}
