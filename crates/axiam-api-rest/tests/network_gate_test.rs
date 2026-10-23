//! The network write gate on the real routes, against the real authorization
//! engine (RADIUS Live profile, W6.2; `claude_dev/radius-reply-profile-design.md` §4.2,
//! §4.4, §5.3, §5.4).
//!
//! What only the routes and the engine together can show: that the handlers
//! ask the gate before they write, that the gate's "holds" is the engine's
//! answer with deny-override and the hierarchy cascade in force, and that every
//! refusal leaves an audit row with the internal reason and the values before
//! and after. The rules' own positive and negative cases (H1–H6, §4.2 rules
//! 1–3, each §5.3 row) are `axiam-authz`'s `network_gate` unit tests.

use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::network_gate::CacheFlush;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{issue_access_token, issue_service_account_token};
use axiam_authz::AuthorizationEngine;
use axiam_authz::types::{AccessDecision, AccessRequest, SubjectScope};
use axiam_core::models::audit::{AuditLogEntry, AuditOutcome};
use axiam_core::models::certificate::{CertificateType, KeyAlgorithm, StoreCertificate};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::network::{
    NETWORK_GRANT, NETWORK_JOIN, NetworkSegment, NetworkSegmentKind, NetworkWriteClearance,
    NetworkWriteTarget, NewNetworkSegment, branch_node_id, network_root_id, site_node_id,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::PermissionEffect;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, CertificateRepository, GroupRepository,
    NetworkSegmentRepository, OrganizationRepository, Pagination, PermissionRepository,
    RoleRepository, ServiceAccountRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealCertificateRepository, SurrealGroupRepository,
    SurrealNetworkSegmentRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealServiceAccountRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const CSRF_TOKEN: &str = "test-csrf-token";

const ALLOW: PermissionEffect = PermissionEffect::Allow;
const DENY: PermissionEffect = PermissionEffect::Deny;

fn test_auth_config() -> AuthConfig {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// One tenant with the registry and the default roles, as bootstrap leaves it.
struct World {
    db: Surreal<TestDb>,
    org: Uuid,
    tenant: Uuid,
    auth: AuthConfig,
}

impl World {
    async fn new() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        Self::on(db).await
    }

    /// The same world on a datastore the caller opened and migrated.
    async fn on(db: Surreal<TestDb>) -> Self {
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "Net Org".into(),
                slug: "net-org".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let tenant = SurrealTenantRepository::new(db.clone())
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "Net Tenant".into(),
                slug: "net-tenant".into(),
                metadata: None,
            })
            .await
            .unwrap();
        seed_permissions(&db, tenant.id, PERMISSION_REGISTRY)
            .await
            .unwrap();
        seed_default_roles(&db, tenant.id, PERMISSION_REGISTRY)
            .await
            .unwrap();
        Self {
            db,
            org: org.id,
            tenant: tenant.id,
            auth: test_auth_config(),
        }
    }

    fn engine(&self) -> Arc<dyn AuthzChecker> {
        Arc::new(AuthorizationEngine::new(
            SurrealRoleRepository::new(self.db.clone()),
            SurrealPermissionRepository::new(self.db.clone()),
            SurrealResourceRepository::new(self.db.clone()),
            SurrealScopeRepository::new(self.db.clone()),
            SurrealGroupRepository::new(self.db.clone()),
        ))
    }

    fn roles(&self) -> SurrealRoleRepository<TestDb> {
        SurrealRoleRepository::new(self.db.clone())
    }

    async fn role_named(&self, name: &str) -> Uuid {
        self.roles()
            .list(self.tenant, page())
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("role {name} not seeded"))
            .id
    }

    async fn permission_id(&self, action: &str) -> Uuid {
        SurrealPermissionRepository::new(self.db.clone())
            .list(self.tenant, page())
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|p| p.action == action)
            .unwrap_or_else(|| panic!("permission {action} not seeded"))
            .id
    }

    /// A non-global role carrying `grants`, made directly (test setup is not
    /// the subject of these tests).
    async fn role(&self, name: &str, grants: &[(&str, PermissionEffect)]) -> Uuid {
        let role = self
            .roles()
            .create(CreateRole {
                tenant_id: self.tenant,
                name: name.into(),
                description: String::new(),
                is_global: false,
            })
            .await
            .unwrap();
        let perms = SurrealPermissionRepository::new(self.db.clone());
        for (action, effect) in grants {
            perms
                .grant_to_role_with_effect(
                    self.tenant,
                    role.id,
                    self.permission_id(action).await,
                    vec![],
                    *effect,
                )
                .await
                .unwrap();
        }
        role.id
    }

    async fn user(&self, roles: &[(Uuid, Option<Uuid>)]) -> Uuid {
        let users = SurrealUserRepository::new(self.db.clone());
        let user = users
            .create(CreateUser {
                tenant_id: self.tenant,
                username: format!("u{}", Uuid::new_v4().simple()),
                email: format!("{}@example.com", Uuid::new_v4().simple()),
                password: axiam_test_support::test_password(),
                metadata: None,
            })
            .await
            .unwrap();
        users
            .update(
                self.tenant,
                user.id,
                UpdateUser {
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        for (role, at) in roles {
            self.roles()
                .assign_to_user(self.tenant, user.id, *role, AssignmentScope::from(*at))
                .await
                .unwrap();
        }
        user.id
    }

    async fn service_account(&self, roles: &[(Uuid, Option<Uuid>)]) -> Uuid {
        let (account, _secret) = SurrealServiceAccountRepository::new(self.db.clone())
            .create(CreateServiceAccount {
                tenant_id: self.tenant,
                name: format!("sa-{}", Uuid::new_v4().simple()),
                description: None,
            })
            .await
            .unwrap();
        for (role, at) in roles {
            self.roles()
                .assign_to_service_account(
                    self.tenant,
                    account.id,
                    *role,
                    AssignmentScope::from(*at),
                )
                .await
                .unwrap();
        }
        account.id
    }

    fn user_token(&self, user: Uuid) -> String {
        issue_access_token(
            user,
            self.tenant,
            self.org,
            &[],
            &self.auth,
            Uuid::new_v4().to_string(),
            axiam_auth::token::AUD_USER,
        )
        .unwrap()
    }

    fn sa_token(&self, account: Uuid) -> String {
        issue_service_account_token(
            account,
            self.tenant,
            self.org,
            Uuid::new_v4().to_string(),
            None,
            &self.auth,
        )
        .unwrap()
    }

    /// A segment, made through the repository with the clearance the gate
    /// would issue (the segment routes are W6.3's).
    async fn segment(&self, path: &str, vlan: u16, rank: Option<u32>) -> NetworkSegment {
        let kind = if path.starts_with("/network/quarantine/") {
            NetworkSegmentKind::Quarantine
        } else {
            NetworkSegmentKind::Access
        };
        let actor = Uuid::new_v4();
        let clearance = NetworkWriteClearance::issued_by_the_network_gate(
            self.tenant,
            actor,
            NetworkWriteTarget::SegmentCreate { path: path.into() },
        );
        SurrealNetworkSegmentRepository::new(self.db.clone())
            .create(
                NewNetworkSegment {
                    tenant_id: self.tenant,
                    path: path.into(),
                    kind,
                    vlan_id: vlan,
                    filter_ids: vec![],
                    rank,
                    enabled: true,
                    actor,
                },
                &clearance,
            )
            .await
            .unwrap()
    }

    /// An active device certificate row, unbound.
    async fn certificate(&self) -> Uuid {
        SurrealCertificateRepository::new(self.db.clone())
            .create(StoreCertificate {
                tenant_id: self.tenant,
                issuer_ca_id: Uuid::new_v4(),
                subject: format!("device-{}", Uuid::new_v4().simple()),
                public_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
                    .into(),
                fingerprint: Uuid::new_v4().simple().to_string(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                not_before: chrono::Utc::now() - chrono::Duration::minutes(1),
                not_after: chrono::Utc::now() + chrono::Duration::days(30),
                metadata: json!({}),
                user_id: None,
            })
            .await
            .unwrap()
            .id
    }

    async fn audit(&self, action: &str) -> Vec<AuditLogEntry> {
        SurrealAuditLogRepository::new(self.db.clone())
            .list(
                self.tenant,
                AuditLogFilter {
                    action: Some(action.into()),
                    ..Default::default()
                },
                page(),
            )
            .await
            .unwrap()
            .items
    }

    async fn joins(&self, subject: Uuid, node: Uuid) -> String {
        AuthorizationEngine::new(
            SurrealRoleRepository::new(self.db.clone()),
            SurrealPermissionRepository::new(self.db.clone()),
            SurrealResourceRepository::new(self.db.clone()),
            SurrealScopeRepository::new(self.db.clone()),
            SurrealGroupRepository::new(self.db.clone()),
        )
        .check_access(&AccessRequest {
            tenant_id: self.tenant,
            subject_scope: SubjectScope::Tenant,
            subject_id: subject,
            action: NETWORK_JOIN.into(),
            resource_id: node,
            scope: None,
        })
        .await
        .unwrap()
        .reason_code()
        .to_owned()
    }
}

fn page() -> Pagination {
    Pagination {
        offset: 0,
        limit: 1000,
        search: None,
    }
}

macro_rules! app {
    ($w:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($w.auth.clone()))
                .app_data(web::Data::new($w.engine()))
                .app_data(web::Data::new(AppState::for_test(
                    $w.db.clone(),
                    $w.auth.clone(),
                )))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

/// Send `method uri body` as `token`; the status and the JSON body (or null).
async fn call(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let req = match method {
        "POST" => test::TestRequest::post(),
        "PUT" => test::TestRequest::put(),
        "DELETE" => test::TestRequest::delete(),
        _ => test::TestRequest::get(),
    }
    .uri(uri)
    .insert_header(("Authorization", format!("Bearer {token}")))
    .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
    .insert_header(("X-CSRF-Token", CSRF_TOKEN));
    let req = match body {
        Some(b) => req.set_json(b),
        None => req,
    }
    .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The one refusal row of `action`, with its metadata.
#[track_caller]
fn the_row(rows: &[AuditLogEntry]) -> &AuditLogEntry {
    assert_eq!(rows.len(), 1, "exactly one refusal row: {rows:?}");
    assert_eq!(rows[0].outcome, AuditOutcome::Denied);
    &rows[0]
}

// ---------------------------------------------------------------------------
// The oracle of W6.2
// ---------------------------------------------------------------------------

/// Assigning a `network:join` allow at node N without `network:grant` at N is
/// `403`, writes nothing and leaves an audit row naming the internal reason;
/// a network administrator holding `network:grant` at an ancestor of N (the
/// engine's cascade) assigns it.
#[actix_rt::test]
async fn assigning_a_join_without_network_grant_at_the_node_is_403_with_an_audit_row() {
    let w = World::new().await;
    let iot = w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let join = w.role("iot-devices", &[(NETWORK_JOIN, ALLOW)]).await;
    let device = w.service_account(&[]).await;
    let admin = w.user(&[(w.role_named("admin").await, None)]).await;
    let app = app!(w);

    let body = json!({ "service_account_id": device, "resource_id": iot.id });
    let uri = format!("/api/v1/roles/{join}/service-accounts");
    let (status, err) = call(&app, &w.user_token(admin), "POST", &uri, Some(body.clone())).await;
    assert_eq!(status, 403, "unexpected answer (body withheld)");
    assert_eq!(
        err["action"], NETWORK_GRANT,
        "the response names the permission"
    );
    assert_eq!(
        w.joins(device, iot.id).await,
        "no_grant",
        "nothing was written"
    );

    let rows = w.audit("network_role.assign_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.actor_id, admin);
    assert_eq!(row.metadata["rule"], "5.3:assign");
    assert_eq!(row.metadata["missing_permission"], NETWORK_GRANT);
    assert_eq!(row.metadata["node"], iot.id.to_string());
    assert_eq!(row.metadata["after"]["service_account"], device.to_string());
    assert_eq!(row.metadata["before"]["assignments"], "none");

    // A network administrator for the site: network:grant at the site node,
    // which cascades to the segment.
    let netadmin_role = w.role("hq-network-admin", &[(NETWORK_GRANT, ALLOW)]).await;
    let site = site_node_id(w.tenant, NetworkSegmentKind::Access, "hq");
    let netadmin = w
        .user(&[
            (w.role_named("admin").await, None),
            (netadmin_role, Some(site)),
        ])
        .await;
    let (status, _err) = call(&app, &w.user_token(netadmin), "POST", &uri, Some(body)).await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    assert_eq!(w.joins(device, iot.id).await, "allowed");
}

/// Binding a certificate to an account that already holds a join needs
/// `network:grant` at **every** node it joins at (R101W6-03).
#[actix_rt::test]
async fn binding_to_an_account_that_holds_joins_needs_network_grant_at_every_join_node() {
    let w = World::new().await;
    let iot = w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let corp = w.segment("/network/zones/branch/corp", 10, Some(10)).await;
    let join = w.role("devices", &[(NETWORK_JOIN, ALLOW)]).await;
    let join_branch = w.role("branch-devices", &[(NETWORK_JOIN, ALLOW)]).await;
    let device = w
        .service_account(&[(join, Some(iot.id)), (join_branch, Some(corp.id))])
        .await;
    let netadmin_role = w.role("netadmin", &[(NETWORK_GRANT, ALLOW)]).await;
    let admin_role = w.role_named("admin").await;
    let half = w
        .user(&[(admin_role, None), (netadmin_role, Some(iot.id))])
        .await;
    let app = app!(w);

    let cert = w.certificate().await;
    let uri = format!("/api/v1/service-accounts/{device}/bind-certificate");
    let body = json!({ "certificate_id": cert });
    let (status, _err) = call(&app, &w.user_token(half), "POST", &uri, Some(body.clone())).await;
    assert_eq!(status, 403, "unexpected answer (body withheld)");
    let rows = w.audit("certificate_binding.refused").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["rule"], "5.3:bind");
    assert_eq!(row.metadata["node"], corp.id.to_string());
    assert_eq!(row.metadata["before"]["service_account_id"], "unbound");
    assert_eq!(
        row.metadata["after"]["service_account_id"],
        device.to_string()
    );
    let bound = SurrealCertificateRepository::new(w.db.clone())
        .get_bound_service_account(cert)
        .await
        .unwrap();
    assert_eq!(bound, None, "nothing was bound");

    let both = w
        .user(&[
            (admin_role, None),
            (netadmin_role, Some(iot.id)),
            (
                w.role("netadmin-branch", &[(NETWORK_GRANT, ALLOW)]).await,
                Some(corp.id),
            ),
        ])
        .await;
    let (status, _err) = call(&app, &w.user_token(both), "POST", &uri, Some(body)).await;
    assert_eq!(status, 200, "unexpected answer (body withheld)");

    // An account with no join asks nothing beyond certificates:bind.
    let bare = w.service_account(&[]).await;
    let (status, _err) = call(
        &app,
        &w.user_token(half),
        "POST",
        &format!("/api/v1/service-accounts/{bare}/bind-certificate"),
        Some(json!({ "certificate_id": w.certificate().await })),
    )
    .await;
    assert_eq!(status, 200, "unexpected answer (body withheld)");
}

/// H6: a service account cannot bind a certificate to itself, whatever it
/// holds — here the seeded super-admin.
#[actix_rt::test]
async fn a_service_account_cannot_bind_a_certificate_to_itself() {
    let w = World::new().await;
    let sa = w
        .service_account(&[(w.role_named("super-admin").await, None)])
        .await;
    let app = app!(w);
    let token = w.sa_token(sa);

    let (status, _err) = call(
        &app,
        &token,
        "POST",
        &format!("/api/v1/service-accounts/{sa}/bind-certificate"),
        Some(json!({ "certificate_id": w.certificate().await })),
    )
    .await;
    assert_eq!(status, 403, "unexpected answer (body withheld)");
    let rows = w.audit("certificate_binding.refused").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["rule"], "H6");
    assert_eq!(row.actor_id, sa);

    // Binding to another account is the ordinary case.
    let other = w.service_account(&[]).await;
    let (status, _err) = call(
        &app,
        &token,
        "POST",
        &format!("/api/v1/service-accounts/{other}/bind-certificate"),
        Some(json!({ "certificate_id": w.certificate().await })),
    )
    .await;
    assert_eq!(status, 200, "unexpected answer (body withheld)");
}

/// §4.4: a quarantine (a `network:join` deny at `/network/zones`) beats the
/// device's allow, and is removed only by someone holding `network:grant` at
/// that node; nor can someone without it impose one.
#[actix_rt::test]
async fn a_quarantine_is_imposed_and_released_only_with_network_grant_at_its_node() {
    let w = World::new().await;
    let iot = w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let zones = branch_node_id(w.tenant, NetworkSegmentKind::Access);
    let join = w.role("devices", &[(NETWORK_JOIN, ALLOW)]).await;
    let quarantine = w.role("network-quarantined", &[(NETWORK_JOIN, DENY)]).await;
    let device = w.service_account(&[(join, Some(iot.id))]).await;
    let admin_role = w.role_named("admin").await;
    let admin = w.user(&[(admin_role, None)]).await;
    let netadmin = w
        .user(&[
            (admin_role, None),
            (
                w.role("zones-admin", &[(NETWORK_GRANT, ALLOW)]).await,
                Some(zones),
            ),
        ])
        .await;
    let app = app!(w);
    let assign = format!("/api/v1/roles/{quarantine}/service-accounts");
    let body = json!({ "service_account_id": device, "resource_id": zones });

    // A broad administrator cannot quarantine a fleet (a denial of service
    // the audit row should name a network administrator for).
    let (status, _) = call(
        &app,
        &w.user_token(admin),
        "POST",
        &assign,
        Some(body.clone()),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _err) = call(&app, &w.user_token(netadmin), "POST", &assign, Some(body)).await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    assert_eq!(w.joins(device, iot.id).await, "denied_by_rule", "Q2");

    // Release: the administrator without network:grant at /network/zones
    // cannot; the deny stays.
    let release =
        format!("/api/v1/roles/{quarantine}/service-accounts/{device}?resource_id={zones}");
    let (status, _err) = call(&app, &w.user_token(admin), "DELETE", &release, None).await;
    assert_eq!(status, 403, "unexpected answer (body withheld)");
    assert_eq!(w.joins(device, iot.id).await, "denied_by_rule");
    let rows = w.audit("network_role.unassign_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["rule"], "5.3:unassign");
    assert_eq!(row.metadata["node"], zones.to_string());

    // Nor by revoking the deny from the role, nor by deleting the role.
    let deny_perm = w.permission_id(NETWORK_JOIN).await;
    let (status, _) = call(
        &app,
        &w.user_token(admin),
        "DELETE",
        &format!("/api/v1/roles/{quarantine}/permissions/{deny_perm}"),
        None,
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &app,
        &w.user_token(admin),
        "DELETE",
        &format!("/api/v1/roles/{quarantine}"),
        None,
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(w.joins(device, iot.id).await, "denied_by_rule");

    // The network administrator for that node releases it.
    let (status, _err) = call(&app, &w.user_token(netadmin), "DELETE", &release, None).await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    assert_eq!(w.joins(device, iot.id).await, "allowed");
}

/// H6 on the §5.3 writes (R110W6-01): a service account trusted to enrol
/// devices — `admin` (so `roles:assign`, `permissions:grant`, …) and
/// `network:grant` — does not place itself and does not lift its own
/// quarantine, by any of the five doors. Each refusal is a `403` that writes
/// nothing and leaves one audit row with rule `H6`; the same write on another
/// account, or by another administrator, is `204`.
#[actix_rt::test]
async fn a_service_account_cannot_place_itself_or_release_its_own_quarantine() {
    let w = World::new().await;
    let iot = w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let zones = branch_node_id(w.tenant, NetworkSegmentKind::Access);
    let root = network_root_id(w.tenant);
    let devices = w.role("devices", &[(NETWORK_JOIN, ALLOW)]).await;
    let quarantined = w.role("network-quarantined", &[(NETWORK_JOIN, DENY)]).await;
    let admin_role = w.role_named("admin").await;
    let zones_granter = w.role("net-granter", &[(NETWORK_GRANT, ALLOW)]).await;
    let agent = w
        .service_account(&[(admin_role, None), (zones_granter, Some(zones))])
        .await;
    let netadmin = w
        .user(&[
            (admin_role, None),
            (
                w.role("zones-admin", &[(NETWORK_GRANT, ALLOW)]).await,
                Some(zones),
            ),
        ])
        .await;
    let app = app!(w);
    let agent_token = w.sa_token(agent);
    let netadmin_token = w.user_token(netadmin);
    let place = format!("/api/v1/roles/{devices}/service-accounts");

    // 1. Self-assignment of a join: 403, nothing written, one H6 row.
    let (status, _err) = call(
        &app,
        &agent_token,
        "POST",
        &place,
        Some(json!({ "service_account_id": agent, "resource_id": iot.id })),
    )
    .await;
    assert_eq!(status, 403, "unexpected answer (body withheld)");
    assert_eq!(w.joins(agent, iot.id).await, "no_grant", "nothing written");
    let rows = w.audit("network_role.assign_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.actor_id, agent);
    assert_eq!(row.metadata["rule"], "H6");
    assert_eq!(row.metadata["after"]["service_account"], agent.to_string());
    // Positive twin: the agent places another device (its job).
    let other = w.service_account(&[]).await;
    let (status, _err) = call(
        &app,
        &agent_token,
        "POST",
        &place,
        Some(json!({ "service_account_id": other, "resource_id": iot.id })),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    assert_eq!(w.joins(other, iot.id).await, "allowed");
    // ... and another administrator places the agent.
    let (status, _err) = call(
        &app,
        &netadmin_token,
        "POST",
        &place,
        Some(json!({ "service_account_id": agent, "resource_id": iot.id })),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    assert_eq!(w.joins(agent, iot.id).await, "allowed");

    // 2. Quarantined by the network administrator, the agent cannot release
    //    itself by unassigning the deny.
    let (status, _err) = call(
        &app,
        &netadmin_token,
        "POST",
        &format!("/api/v1/roles/{quarantined}/service-accounts"),
        Some(json!({ "service_account_id": agent, "resource_id": zones })),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    assert_eq!(w.joins(agent, iot.id).await, "denied_by_rule");
    let release = |who: Uuid| {
        format!("/api/v1/roles/{quarantined}/service-accounts/{who}?resource_id={zones}")
    };
    let (status, _err) = call(&app, &agent_token, "DELETE", &release(agent), None).await;
    assert_eq!(status, 403, "unexpected answer (body withheld)");
    assert_eq!(
        w.joins(agent, iot.id).await,
        "denied_by_rule",
        "still quarantined"
    );
    let rows = w.audit("network_role.unassign_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.actor_id, agent);
    assert_eq!(row.metadata["rule"], "H6");

    // 3. With network:grant at /network as well (what revoke, role delete and
    //    grant ask), the other three doors stay shut.
    let root_granter = w.role("root-granter", &[(NETWORK_GRANT, ALLOW)]).await;
    w.roles()
        .assign_to_service_account(
            w.tenant,
            agent,
            root_granter,
            AssignmentScope::from(Some(root)),
        )
        .await
        .unwrap();
    let join_perm = w.permission_id(NETWORK_JOIN).await;
    let (status, _err) = call(
        &app,
        &agent_token,
        "DELETE",
        &format!("/api/v1/roles/{quarantined}/permissions/{join_perm}"),
        None,
    )
    .await;
    assert_eq!(status, 403, "revoke of its own deny");
    let (status, _err) = call(
        &app,
        &agent_token,
        "DELETE",
        &format!("/api/v1/roles/{quarantined}"),
        None,
    )
    .await;
    assert_eq!(status, 403, "delete of its own deny role");
    assert_eq!(
        w.joins(agent, iot.id).await,
        "denied_by_rule",
        "still quarantined"
    );
    let fleet = w.role("fleet", &[]).await;
    w.roles()
        .assign_to_service_account(w.tenant, agent, fleet, AssignmentScope::from(Some(iot.id)))
        .await
        .unwrap();
    let (status, _err) = call(
        &app,
        &agent_token,
        "POST",
        &format!("/api/v1/roles/{fleet}/permissions"),
        Some(json!({ "permission_id": join_perm, "effect": "allow" })),
    )
    .await;
    assert_eq!(status, 403, "a join granted to a role it holds");
    let grant_rows = w.audit("network_role.grant_refused").await;
    assert_eq!(grant_rows.len(), 2, "{grant_rows:?}");
    assert!(
        grant_rows
            .iter()
            .all(|r| r.metadata["rule"] == "H6" && r.actor_id == agent)
    );
    let rows = w.audit("network_role.write_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["rule"], "H6");

    // Positive twins of 3: the same writes on roles the agent does not hold.
    let other_fleet = w.role("other-fleet", &[]).await;
    let (status, _err) = call(
        &app,
        &agent_token,
        "POST",
        &format!("/api/v1/roles/{other_fleet}/permissions"),
        Some(json!({ "permission_id": join_perm, "effect": "allow" })),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    let other_quarantine = w.role("other-quarantine", &[(NETWORK_JOIN, DENY)]).await;
    let (status, _err) = call(
        &app,
        &agent_token,
        "DELETE",
        &format!("/api/v1/roles/{other_quarantine}/permissions/{join_perm}"),
        None,
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    let spare_quarantine = w.role("spare-quarantine", &[(NETWORK_JOIN, DENY)]).await;
    let (status, _err) = call(
        &app,
        &agent_token,
        "DELETE",
        &format!("/api/v1/roles/{spare_quarantine}"),
        None,
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");

    // 4. The network administrator releases the agent.
    let (status, _err) = call(&app, &netadmin_token, "DELETE", &release(agent), None).await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    assert_eq!(w.joins(agent, iot.id).await, "allowed");
}

/// H6 through a group (R110W6-01): a deny a group carries reaches its
/// members, so a member does not lift it by unassigning it from the group or
/// by deleting the role — "holds" counts the group. Rule 2 keeps network roles
/// off groups — the API and, since R110W6-04, the repository's own transaction
/// both refuse it — so the edge is written here in raw SurrealQL, as one
/// predating the rule would have been.
#[actix_rt::test]
async fn a_member_cannot_release_a_deny_its_group_carries() {
    let w = World::new().await;
    let iot = w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let zones = branch_node_id(w.tenant, NetworkSegmentKind::Access);
    let root = network_root_id(w.tenant);
    let quarantined = w.role("network-quarantined", &[(NETWORK_JOIN, DENY)]).await;
    let admin_role = w.role_named("admin").await;
    let root_granter = w.role("root-granter", &[(NETWORK_GRANT, ALLOW)]).await;
    let groups = SurrealGroupRepository::new(w.db.clone());
    let group = groups
        .create(CreateGroup {
            tenant_id: w.tenant,
            name: "fleet".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap();
    w.db.query(format!(
        "RELATE group:`{}` -> has_role -> role:`{quarantined}` SET resource_id = $node",
        group.id
    ))
    .bind(("node", zones.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
    let member = w
        .user(&[
            (admin_role, None),
            (
                w.role("devices", &[(NETWORK_JOIN, ALLOW)]).await,
                Some(iot.id),
            ),
            (root_granter, Some(root)),
        ])
        .await;
    groups.add_member(w.tenant, member, group.id).await.unwrap();
    let outsider = w
        .user(&[(admin_role, None), (root_granter, Some(root))])
        .await;
    let app = app!(w);
    assert_eq!(w.joins(member, iot.id).await, "denied_by_rule");

    let unassign = format!(
        "/api/v1/roles/{quarantined}/groups/{}?resource_id={zones}",
        group.id
    );
    let (status, _err) = call(&app, &w.user_token(member), "DELETE", &unassign, None).await;
    assert_eq!(status, 403, "unexpected answer (body withheld)");
    let rows = w.audit("network_role.unassign_refused").await;
    assert_eq!(the_row(&rows).metadata["rule"], "H6");
    let (status, _err) = call(
        &app,
        &w.user_token(member),
        "DELETE",
        &format!("/api/v1/roles/{quarantined}"),
        None,
    )
    .await;
    assert_eq!(status, 403, "unexpected answer (body withheld)");
    let rows = w.audit("network_role.write_refused").await;
    assert_eq!(the_row(&rows).metadata["rule"], "H6");
    assert_eq!(w.joins(member, iot.id).await, "denied_by_rule");

    // Positive twin: an administrator outside the group releases it.
    let (status, _err) = call(&app, &w.user_token(outsider), "DELETE", &unassign, None).await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    assert_eq!(w.joins(member, iot.id).await, "allowed");
}

/// Deny-override holds for the writer: a `network:grant` deny beats an allow
/// at the **same** node (row 6), and a child allow does not undo an inherited
/// deny (row 4).
#[actix_rt::test]
async fn deny_override_holds_for_the_writer_at_equal_specificity() {
    let w = World::new().await;
    let iot = w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let zones = branch_node_id(w.tenant, NetworkSegmentKind::Access);
    let join = w.role("devices", &[(NETWORK_JOIN, ALLOW)]).await;
    let grant = w.role("grant", &[(NETWORK_GRANT, ALLOW)]).await;
    let no_grant = w.role("no-grant", &[(NETWORK_GRANT, DENY)]).await;
    let admin_role = w.role_named("admin").await;
    let same_node = w
        .user(&[
            (admin_role, None),
            (grant, Some(iot.id)),
            (no_grant, Some(iot.id)),
        ])
        .await;
    let inherited = w
        .user(&[
            (admin_role, None),
            (grant, Some(iot.id)),
            (no_grant, Some(zones)),
        ])
        .await;
    let device = w.service_account(&[]).await;
    let app = app!(w);
    let uri = format!("/api/v1/roles/{join}/service-accounts");
    let body = json!({ "service_account_id": device, "resource_id": iot.id });

    for writer in [same_node, inherited] {
        let (status, _err) = call(
            &app,
            &w.user_token(writer),
            "POST",
            &uri,
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, 403, "unexpected answer (body withheld)");
    }
    assert_eq!(w.audit("network_role.assign_refused").await.len(), 2);
    assert_eq!(w.joins(device, iot.id).await, "no_grant");
}

/// The seeded super-admin is the bootstrap: it makes a network administrator
/// (a non-global role carrying `network:grant`) and assigns it at `/network`.
/// The seeded admin, which holds no `network:` permission, can do neither.
#[actix_rt::test]
async fn the_seeded_super_admin_bootstraps_network_administration_and_admin_cannot() {
    let w = World::new().await;
    w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let root = network_root_id(w.tenant);
    let super_admin = w.user(&[(w.role_named("super-admin").await, None)]).await;
    let admin = w.user(&[(w.role_named("admin").await, None)]).await;
    let app = app!(w);
    let grant_perm = w.permission_id(NETWORK_GRANT).await;

    let (status, role) = call(
        &app,
        &w.user_token(super_admin),
        "POST",
        "/api/v1/roles",
        Some(json!({ "name": "network-admin", "description": "", "is_global": false })),
    )
    .await;
    assert_eq!(status, 201, "{role}");
    let role_id = role["id"].as_str().unwrap().to_owned();
    let grant_uri = format!("/api/v1/roles/{role_id}/permissions");
    let grant_body = json!({ "permission_id": grant_perm });

    let (status, _err) = call(
        &app,
        &w.user_token(admin),
        "POST",
        &grant_uri,
        Some(grant_body.clone()),
    )
    .await;
    assert_eq!(status, 403, "unexpected answer (body withheld)");
    let rows = w.audit("network_role.grant_refused").await;
    assert_eq!(the_row(&rows).metadata["node"], root.to_string());

    let (status, _err) = call(
        &app,
        &w.user_token(super_admin),
        "POST",
        &grant_uri,
        Some(grant_body),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");

    let target = w.user(&[]).await;
    let assign_uri = format!("/api/v1/roles/{role_id}/users");
    let assign_body = json!({ "user_id": target, "resource_id": root });
    let (status, _) = call(
        &app,
        &w.user_token(admin),
        "POST",
        &assign_uri,
        Some(assign_body.clone()),
    )
    .await;
    assert_eq!(status, 403, "admin holds no network:grant to delegate");
    let (status, _err) = call(
        &app,
        &w.user_token(super_admin),
        "POST",
        &assign_uri,
        Some(assign_body),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");

    // And assigning the super-admin role itself is now bounded: it carries
    // the meta permissions, which admin does not hold.
    let sa_role = w.role_named("super-admin").await;
    let (status, _) = call(
        &app,
        &w.user_token(admin),
        "POST",
        &format!("/api/v1/roles/{sa_role}/users"),
        Some(json!({ "user_id": target })),
    )
    .await;
    assert_eq!(status, 403);
}

/// §4.1, §4.2: the generic routes do not reach the reserved namespace or the
/// reserved subtree, and the three write-time rules hold on the routes.
#[actix_rt::test]
async fn the_generic_routes_refuse_the_reserved_namespace_subtree_and_rules() {
    let w = World::new().await;
    let iot = w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let zones = branch_node_id(w.tenant, NetworkSegmentKind::Access);
    let super_admin = w.user(&[(w.role_named("super-admin").await, None)]).await;
    let app = app!(w);
    let t = w.user_token(super_admin);
    let join_perm = w.permission_id(NETWORK_JOIN).await;

    let cases: Vec<(&str, String, Option<Value>, &str)> = vec![
        (
            "POST",
            "/api/v1/permissions".into(),
            Some(json!({ "action": "network:join_everything", "description": "" })),
            "network_permission.write_refused",
        ),
        (
            "PUT",
            format!("/api/v1/permissions/{join_perm}"),
            Some(json!({ "action": "devices:join" })),
            "network_permission.write_refused",
        ),
        (
            "DELETE",
            format!("/api/v1/permissions/{join_perm}"),
            None,
            "network_permission.write_refused",
        ),
        (
            "POST",
            "/api/v1/resources".into(),
            Some(json!({ "name": "fake", "resource_type": "network_segment" })),
            "network_resource.write_refused",
        ),
        (
            "POST",
            "/api/v1/resources".into(),
            Some(json!({ "name": "under", "resource_type": "project", "parent_id": iot.id })),
            "network_resource.write_refused",
        ),
        (
            "DELETE",
            format!("/api/v1/resources/{zones}"),
            None,
            "network_resource.write_refused",
        ),
    ];
    for (method, uri, body, audit) in cases {
        let (status, _err) = call(&app, &t, method, &uri, body).await;
        assert_eq!(status, 400, "{method}");
        assert!(
            !w.audit(audit).await.is_empty(),
            "{method} {uri} left no {audit} row"
        );
    }
    // The quarantine branch still exists.
    let (status, _) = call(&app, &t, "GET", &format!("/api/v1/resources/{zones}"), None).await;
    assert_eq!(status, 200);

    // Rule 2: a network role is never assigned to a group.
    let net_role = w.role("net", &[(NETWORK_JOIN, ALLOW)]).await;
    let (status, group) = call(
        &app,
        &t,
        "POST",
        "/api/v1/groups",
        Some(json!({ "name": "fleet", "description": "" })),
    )
    .await;
    assert_eq!(status, 201, "{group}");
    let (status, _err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/roles/{net_role}/groups"),
        Some(json!({ "group_id": group["id"], "resource_id": iot.id })),
    )
    .await;
    assert_eq!(status, 400, "unexpected answer (body withheld)");

    // Rule 1: not made global.
    let (status, _err) = call(
        &app,
        &t,
        "PUT",
        &format!("/api/v1/roles/{net_role}"),
        Some(json!({ "is_global": true })),
    )
    .await;
    assert_eq!(status, 400, "unexpected answer (body withheld)");

    // Rule 3: no network deny on a role assigned with inherit: false.
    let narrow = w.role("narrow", &[]).await;
    let device = w.service_account(&[]).await;
    let (status, _err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/roles/{narrow}/service-accounts"),
        Some(json!({ "service_account_id": device, "resource_id": iot.id, "inherit": false })),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    let (status, _err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/roles/{narrow}/permissions"),
        Some(json!({ "permission_id": join_perm, "effect": "deny" })),
    )
    .await;
    assert_eq!(status, 400, "unexpected answer (body withheld)");
    let rule_rows = w.audit("network_role.grant_refused").await;
    assert!(rule_rows.iter().any(|r| r.metadata["rule"] == "4.2:rule-3"));
}

// ---------------------------------------------------------------------------
// §4.2 rule 2 against a racing write (R110W6-04, #701)
// ---------------------------------------------------------------------------

/// The REST checker of a world, with one interleaving forced into it: when the
/// gate asks its write-time question for `network:grant` — after it has read
/// the role's group holders and found none — another request's group
/// assignment of the role lands first, through the repository, as that
/// request would write it (its own gate read no `network:` grant). Then the
/// engine answers as usual.
struct GroupAssignmentLandsMidGate {
    engine: Arc<dyn AuthzChecker>,
    db: Surreal<TestDb>,
    tenant: Uuid,
    role: Uuid,
    group: Uuid,
    fired: std::sync::atomic::AtomicBool,
}

impl AuthzChecker for GroupAssignmentLandsMidGate {
    fn check_access<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = axiam_core::error::AxiamResult<AccessDecision>>
                + Send
                + 'a,
        >,
    > {
        self.engine.check_access(request)
    }

    fn check_access_uncached<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = axiam_core::error::AxiamResult<AccessDecision>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if request.action == NETWORK_GRANT
                && !self.fired.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                SurrealRoleRepository::new(self.db.clone())
                    .assign_to_group(
                        self.tenant,
                        self.group,
                        self.role,
                        AssignmentScope::from(None),
                    )
                    .await
                    .expect("the racing group assignment lands: the role has no network grant yet");
            }
            self.engine.check_access_uncached(request).await
        })
    }
}

/// R110W6-04 end to end, in the order that loses: a `network:join` grant
/// whose gate read "no group holds the role", and a group assignment of the
/// role that lands before the grant's write. The grant's own transaction sees
/// the group edge and refuses: `409 conflict` with `reason_code`
/// `stale_version`, nothing written, one `network_role.grant_refused` row
/// (`version:stale`, status 409). Sent again, it goes back through the gate,
/// which now refuses it under rule 2 (`400`).
#[actix_rt::test]
async fn a_network_grant_that_loses_to_a_group_assignment_is_409_stale_version_and_audited() {
    let w = World::new().await;
    // The `/network` root the gate checks `network:grant` at.
    w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let role = w.role("fleet-devices", &[]).await;
    let group = SurrealGroupRepository::new(w.db.clone())
        .create(CreateGroup {
            tenant_id: w.tenant,
            name: "fleet".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let writer = w.user(&[(w.role_named("super-admin").await, None)]).await;
    let checker: Arc<dyn AuthzChecker> = Arc::new(GroupAssignmentLandsMidGate {
        engine: w.engine(),
        db: w.db.clone(),
        tenant: w.tenant,
        role,
        group,
        fired: std::sync::atomic::AtomicBool::new(false),
    });
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(w.auth.clone()))
            .app_data(web::Data::new(checker))
            .app_data(web::Data::new(AppState::for_test(
                w.db.clone(),
                w.auth.clone(),
            )))
            .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())),
    )
    .await;
    let grant = json!({ "permission_id": w.permission_id(NETWORK_JOIN).await, "effect": "allow" });
    let uri = format!("/api/v1/roles/{role}/permissions");

    let (status, body) = call(
        &app,
        &w.user_token(writer),
        "POST",
        &uri,
        Some(grant.clone()),
    )
    .await;
    assert_eq!(status, 409, "unexpected answer (body withheld)");
    assert_eq!(
        body["error"], "conflict",
        "unexpected answer (body withheld)"
    );
    assert_eq!(
        body["reason_code"], "stale_version",
        "unexpected answer (body withheld)"
    );
    let rows = w.audit("network_role.grant_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["rule"], "version:stale");
    assert_eq!(row.metadata["status"], 409);
    assert_eq!(row.metadata["write"], "permission_grant");
    assert_eq!(row.metadata["before"]["role_id"], role.to_string());

    // The group assignment won; the grant wrote nothing.
    let grants = SurrealPermissionRepository::new(w.db.clone())
        .get_role_permission_grants(w.tenant, role)
        .await
        .unwrap();
    assert!(grants.is_empty(), "{grants:?}");
    assert_eq!(
        w.roles().get_role_group_ids(w.tenant, role).await.unwrap(),
        vec![group]
    );

    // Again: the gate now sees the group, and rule 2 answers.
    let (status, _body) = call(&app, &w.user_token(writer), "POST", &uri, Some(grant)).await;
    assert_eq!(status, 400, "unexpected answer (body withheld)");
    let rows = w.audit("network_role.grant_refused").await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter().any(|r| r.metadata["rule"] == "4.2:rule-2"),
        "{rows:?}"
    );
}

// The races of R110W6-04 through the real gate, on the engine production runs
// (`surrealkv`). Each round, two requests each run the network gate on a role
// — both are **cleared**, which is the race: each reads the state from before
// the other's write — then wait at a barrier until both have read, then write
// at once, as the handlers do after their gate (the `*_claimed` repository
// writes, with the gate's claim). One of the two must be refused with the
// `409` ("the role changed since it was read"), and the invariant the gate
// enforces must hold afterwards.

/// One request of a race: what it asks the gate, and the write it then makes.
#[derive(Clone, Copy, Debug)]
enum Request {
    Grant {
        role: Uuid,
        permission: Uuid,
        effect: PermissionEffect,
    },
    Revoke {
        role: Uuid,
        permission: Uuid,
    },
    AssignUser {
        role: Uuid,
        user: Uuid,
        node: Option<Uuid>,
        inherit: bool,
    },
    AssignGroup {
        role: Uuid,
        group: Uuid,
    },
    MakeGlobal {
        role: Uuid,
    },
}

/// A migrated `surrealkv` world and its directory, held for the test's life.
async fn serialising_world() -> (Arc<World>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Surreal::new::<surrealdb::engine::local::SurrealKv>(
        dir.path().join("race.db").to_string_lossy().into_owned(),
    )
    .await
    .unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let w = World::on(db).await;
    // The `/network` root the gate checks `network:grant` at.
    w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    (Arc::new(w), dir)
}

/// The gate as `network_gate::authorize` runs it, for `writer`.
async fn gate(
    w: &World,
    writer: Uuid,
    subject_scope: SubjectScope,
    write: axiam_authz::network_gate::NetworkWrite<'_>,
) -> axiam_authz::network_gate::GateVerdict {
    use axiam_authz::network_gate::{GateWriter, RepositoryGateStore, authorize_network_write};
    use axiam_db::repository::{SurrealNetworkPolicyRepository, SurrealReplyProfileRepository};
    let engine = AuthorizationEngine::new(
        SurrealRoleRepository::new(w.db.clone()),
        SurrealPermissionRepository::new(w.db.clone()),
        SurrealResourceRepository::new(w.db.clone()),
        SurrealScopeRepository::new(w.db.clone()),
        SurrealGroupRepository::new(w.db.clone()),
    );
    let store = RepositoryGateStore {
        roles: &SurrealRoleRepository::new(w.db.clone()),
        groups: &SurrealGroupRepository::new(w.db.clone()),
        permissions: &SurrealPermissionRepository::new(w.db.clone()),
        resources: &SurrealResourceRepository::new(w.db.clone()),
        segments: &SurrealNetworkSegmentRepository::new(w.db.clone()),
        profiles: &SurrealReplyProfileRepository::new(w.db.clone()),
        policy: &SurrealNetworkPolicyRepository::new(w.db.clone()),
        certificates: &SurrealCertificateRepository::new(w.db.clone()),
    };
    let writer = GateWriter {
        tenant_id: w.tenant,
        subject_id: writer,
        subject_scope,
    };
    authorize_network_write(&engine, &store, writer, write)
        .await
        .expect("the gate's reads succeed")
}

/// Run `request` as `writer`: the gate (which must clear it), the barrier,
/// then the handler's write with the gate's claim.
async fn send(
    w: Arc<World>,
    writer: Uuid,
    request: Request,
    barrier: Arc<tokio::sync::Barrier>,
) -> Result<(), axiam_core::error::AxiamError> {
    use axiam_authz::network_gate::{Grantee, NetworkWrite};
    let write = match request {
        Request::Grant {
            role,
            permission,
            effect,
        } => NetworkWrite::PermissionGrant {
            role_id: role,
            permission_id: permission,
            effect,
            scope_ids: &[],
        },
        Request::Revoke { role, permission } => NetworkWrite::PermissionRevoke {
            role_id: role,
            permission_id: permission,
        },
        Request::AssignUser {
            role,
            user,
            node,
            inherit,
        } => NetworkWrite::RoleAssign {
            role_id: role,
            grantee: Grantee::User(user),
            resource_id: node,
            inherit,
        },
        Request::AssignGroup { role, group } => NetworkWrite::RoleAssign {
            role_id: role,
            grantee: Grantee::Group(group),
            resource_id: None,
            inherit: true,
        },
        Request::MakeGlobal { role } => NetworkWrite::RoleUpdate {
            role_id: role,
            is_global: Some(true),
        },
    };
    let claim = match gate(&w, writer, SubjectScope::Tenant, write).await {
        Ok(cleared) => cleared.role_claim(),
        Err(refusal) => panic!("{request:?}: the gate refused on its own read: {refusal:?}"),
    };
    barrier.wait().await;
    let (roles, perms) = (w.roles(), SurrealPermissionRepository::new(w.db.clone()));
    match request {
        Request::Grant {
            role,
            permission,
            effect,
        } => {
            perms
                .grant_to_role_claimed(w.tenant, role, permission, vec![], effect, claim)
                .await
        }
        Request::Revoke { role, permission } => {
            perms
                .revoke_from_role_claimed(w.tenant, role, permission, claim)
                .await
        }
        Request::AssignUser {
            role,
            user,
            node,
            inherit,
        } => {
            let scope = AssignmentScope {
                inherit,
                ..AssignmentScope::from(node)
            };
            roles
                .assign_to_user_claimed(w.tenant, user, role, scope, claim)
                .await
        }
        Request::AssignGroup { role, group } => {
            roles
                .assign_to_group_claimed(w.tenant, group, role, AssignmentScope::from(None), claim)
                .await
        }
        Request::MakeGlobal { role } => roles
            .update_claimed(
                w.tenant,
                role,
                axiam_core::models::role::UpdateRole {
                    is_global: Some(true),
                    ..Default::default()
                },
                claim,
            )
            .await
            .map(drop),
    }
}

/// What a role carries and who holds it, after a round.
struct RoleState {
    grants: Vec<(String, PermissionEffect)>,
    users: Vec<(Uuid, bool)>,
    grouped: bool,
    is_global: bool,
}

impl RoleState {
    async fn of(w: &World, role: Uuid) -> Self {
        let grants = SurrealPermissionRepository::new(w.db.clone())
            .get_role_permission_grants(w.tenant, role)
            .await
            .unwrap()
            .into_iter()
            .map(|g| (g.permission.action, g.effect))
            .collect();
        let users = w
            .roles()
            .get_role_user_assignments(w.tenant, role)
            .await
            .unwrap()
            .into_iter()
            .map(|a| (a.subject_id, a.inherit))
            .collect();
        let grouped = !w
            .roles()
            .get_role_group_ids(w.tenant, role)
            .await
            .unwrap()
            .is_empty();
        let is_global = w.roles().get_by_id(w.tenant, role).await.unwrap().is_global;
        Self {
            grants,
            users,
            grouped,
            is_global,
        }
    }

    fn network(&self) -> bool {
        self.grants.iter().any(|(a, _)| a.starts_with("network:"))
    }
}

/// Race `a` (as `writer_a`) against `b` (as `writer_b`) on a fresh role, for
/// `ROUNDS` rounds; `setup` makes the role's starting state and the two
/// requests, `holds` is the invariant. Returns how often each side won.
const ROUNDS: usize = 8;

async fn race<S, F, H>(w: &Arc<World>, writers: (Uuid, Uuid), setup: S, holds: H)
where
    S: Fn(Uuid) -> F,
    F: std::future::Future<Output = (Uuid, Request, Request)>,
    H: Fn(&RoleState) -> bool,
{
    let (mut a_won, mut b_won) = (0, 0);
    for round in 0..ROUNDS {
        let (role, a, b) = setup(
            w.role(&format!("race-{}", Uuid::new_v4().simple()), &[])
                .await,
        )
        .await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let first = tokio::spawn(send(Arc::clone(w), writers.0, a, Arc::clone(&barrier)));
        let second = tokio::spawn(send(Arc::clone(w), writers.1, b, Arc::clone(&barrier)));
        let (ra, rb) = (first.await.unwrap(), second.await.unwrap());
        assert!(
            ra.is_err() || rb.is_err(),
            "round {round}: {a:?} and {b:?} both landed on what the gate read"
        );
        for refused in [&ra, &rb].into_iter().filter(|r| r.is_err()) {
            assert!(
                matches!(
                    refused,
                    Err(axiam_core::error::AxiamError::Network(
                        axiam_core::error::NetworkConflict::StaleRole { .. }
                    ))
                ),
                "round {round}: the loser is the 409, got {refused:?}"
            );
        }
        let state = RoleState::of(w, role).await;
        assert!(
            holds(&state),
            "round {round}: invariant broken after {a:?} / {b:?}"
        );
        a_won += usize::from(ra.is_ok());
        b_won += usize::from(rb.is_ok());
    }
    println!("first won {a_won}, second won {b_won} of {ROUNDS}");
}

/// A super-admin user: holds `network:grant` and the meta permissions at the
/// `/network` root, and every route permission.
async fn network_admin(w: &World) -> Uuid {
    w.user(&[(w.role_named("super-admin").await, None)]).await
}

/// Rule 2: a `network:join` grant to a role racing the role's assignment to a
/// group. Never a group-held network role.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r110w6_04_rule_2_a_grant_racing_a_group_assignment_never_lands_both() {
    let (w, _dir) = serialising_world().await;
    let admin = network_admin(&w).await;
    let join = w.permission_id(NETWORK_JOIN).await;
    let ww = Arc::clone(&w);
    race(
        &w,
        (admin, admin),
        move |role| {
            let w = Arc::clone(&ww);
            async move {
                let group = SurrealGroupRepository::new(w.db.clone())
                    .create(CreateGroup {
                        tenant_id: w.tenant,
                        name: format!("g-{}", Uuid::new_v4().simple()),
                        description: String::new(),
                        metadata: None,
                    })
                    .await
                    .unwrap()
                    .id;
                (
                    role,
                    Request::Grant {
                        role,
                        permission: join,
                        effect: ALLOW,
                    },
                    Request::AssignGroup { role, group },
                )
            }
        },
        |s| !(s.network() && s.grouped),
    )
    .await;
}

/// Interleaving 1 (H6, T-482): a writer holding `network:grant` grants
/// `network:join` to a role and, at once, assigns the role to itself. Each
/// gate reads the other half as absent; never both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r110w6_04_h6_a_join_grant_racing_a_self_assignment_never_lands_both() {
    let (w, _dir) = serialising_world().await;
    let writer = network_admin(&w).await;
    let join = w.permission_id(NETWORK_JOIN).await;
    race(
        &w,
        (writer, writer),
        move |role| async move {
            (
                role,
                Request::Grant {
                    role,
                    permission: join,
                    effect: ALLOW,
                },
                Request::AssignUser {
                    role,
                    user: writer,
                    node: None,
                    inherit: true,
                },
            )
        },
        move |s| {
            let joins = s
                .grants
                .iter()
                .any(|(a, e)| a == NETWORK_JOIN && *e == ALLOW);
            !(joins && s.users.iter().any(|(u, _)| *u == writer))
        },
    )
    .await;
}

/// Interleaving 2 (rule 1): a role made global racing a `network:` grant to
/// it. Never a global role carrying a `network:` permission.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r110w6_04_rule_1_a_global_update_racing_a_network_grant_never_lands_both() {
    let (w, _dir) = serialising_world().await;
    let admin = network_admin(&w).await;
    let join = w.permission_id(NETWORK_JOIN).await;
    race(
        &w,
        (admin, admin),
        move |role| async move {
            (
                role,
                Request::MakeGlobal { role },
                Request::Grant {
                    role,
                    permission: join,
                    effect: ALLOW,
                },
            )
        },
        |s| !(s.network() && s.is_global),
    )
    .await;
}

/// Interleaving 3 (rule 3): an assignment with `inherit: false` racing a
/// `network:join` deny on the role. Never a network deny on a role held with
/// `inherit: false` (a quarantine that reaches nothing below its node).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r110w6_04_rule_3_a_non_inheriting_assignment_racing_a_deny_never_lands_both() {
    let (w, _dir) = serialising_world().await;
    let admin = network_admin(&w).await;
    let join = w.permission_id(NETWORK_JOIN).await;
    let device = w.user(&[]).await;
    let zones = branch_node_id(w.tenant, NetworkSegmentKind::Access);
    race(
        &w,
        (admin, admin),
        move |role| async move {
            (
                role,
                Request::AssignUser {
                    role,
                    user: device,
                    node: Some(zones),
                    inherit: false,
                },
                Request::Grant {
                    role,
                    permission: join,
                    effect: DENY,
                },
            )
        },
        |s| {
            let denies = s
                .grants
                .iter()
                .any(|(a, e)| a.starts_with("network:") && *e == DENY);
            !(denies && s.users.iter().any(|(_, inherit)| !inherit))
        },
    )
    .await;
}

/// Interleaving 4 (§5.3 row 5, H6): an administrator quarantines a role the
/// writer holds (a `network:join` deny) while the writer revokes
/// `network:join` from it, its gate having read no grant to revoke. The revoke
/// never deletes a deny it did not read: if the deny was reported written, it
/// is there afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r110w6_04_a_revoke_racing_a_quarantine_never_deletes_the_deny() {
    let (w, _dir) = serialising_world().await;
    let admin = network_admin(&w).await;
    let writer = network_admin(&w).await;
    let join = w.permission_id(NETWORK_JOIN).await;
    let ww = Arc::clone(&w);
    let (mut quarantined, mut released) = (0, 0);
    for round in 0..ROUNDS {
        let role = w.role(&format!("q-{}", Uuid::new_v4().simple()), &[]).await;
        ww.roles()
            .assign_to_user(w.tenant, writer, role, AssignmentScope::from(None))
            .await
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let deny = Request::Grant {
            role,
            permission: join,
            effect: DENY,
        };
        let revoke = Request::Revoke {
            role,
            permission: join,
        };
        let a = tokio::spawn(send(Arc::clone(&w), admin, deny, Arc::clone(&barrier)));
        let b = tokio::spawn(send(Arc::clone(&w), writer, revoke, Arc::clone(&barrier)));
        let (denied, revoked) = (a.await.unwrap(), b.await.unwrap());
        assert!(
            denied.is_err() || revoked.is_err(),
            "round {round}: the deny and the revoke both landed on what their gates read"
        );
        for refused in [&denied, &revoked].into_iter().filter(|r| r.is_err()) {
            assert!(
                matches!(
                    refused,
                    Err(axiam_core::error::AxiamError::Network(
                        axiam_core::error::NetworkConflict::StaleRole { .. }
                    ))
                ),
                "round {round}: {refused:?}"
            );
        }
        let state = RoleState::of(&w, role).await;
        let deny_there = state
            .grants
            .iter()
            .any(|(a, e)| a == NETWORK_JOIN && *e == DENY);
        if denied.is_ok() {
            assert!(
                deny_there,
                "round {round}: the writer's revoke deleted the quarantine"
            );
            quarantined += 1;
        } else {
            released += 1;
        }
    }
    println!("quarantine won {quarantined}, revoke won {released} of {ROUNDS}");
}

/// #702 (R110W6-05, T-483): an organization-level administrator is not a network
/// administrator in a child tenant. The organization scope's seeded super-admin
/// is global, so it reaches every tenant of the organization; it holds no
/// `network:` permission, and the gate refuses it `network:grant` at the child
/// tenant's `/network` while clearing the child tenant's own super-admin. The
/// one write it still clears is the bootstrap: assigning the child tenant's
/// own seeded super-admin, tenant-wide, to a child-tenant user.
#[actix_rt::test]
async fn an_organization_level_writer_is_refused_network_grant_in_a_child_tenant() {
    let w = World::new().await;
    w.segment("/network/zones/hq/iot", 20, Some(20)).await;
    let org_tenant = SurrealTenantRepository::new(w.db.clone())
        .create(CreateTenant {
            organization_id: w.org,
            kind: TenantKind::Organization,
            name: "Org scope".into(),
            slug: "org-scope".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    seed_permissions(&w.db, org_tenant, PERMISSION_REGISTRY)
        .await
        .unwrap();
    let roles = seed_default_roles(&w.db, org_tenant, PERMISSION_REGISTRY)
        .await
        .unwrap();
    let org_admin = SurrealUserRepository::new(w.db.clone())
        .create(CreateUser {
            tenant_id: org_tenant,
            username: "org-admin".into(),
            email: "org-admin@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    w.roles()
        .assign_to_user(
            org_tenant,
            org_admin,
            roles.super_admin_role_id,
            AssignmentScope::from(None),
        )
        .await
        .unwrap();

    // A role carrying `network:join`, assigned to a user: a write that needs
    // `network:grant` at `/network` of the child tenant (§5.3).
    let fleet = w.role("fleet", &[(NETWORK_JOIN, ALLOW)]).await;
    let target = w.user(&[]).await;
    let assign = || axiam_authz::network_gate::NetworkWrite::RoleAssign {
        role_id: fleet,
        grantee: axiam_authz::network_gate::Grantee::User(target),
        resource_id: None,
        inherit: true,
    };

    let org_scope = SubjectScope::Organization {
        tenant_id: org_tenant,
    };
    assert!(
        gate(&w, org_admin, org_scope, assign()).await.is_err(),
        "the organization scope's super-admin holds no network:grant in the child tenant"
    );

    // Nor a custom role carrying a meta permission: still the §5.3 bound.
    let delegate = w.role("delegate", &[(NETWORK_GRANT, ALLOW)]).await;
    assert!(
        gate(
            &w,
            org_admin,
            org_scope,
            axiam_authz::network_gate::NetworkWrite::RoleAssign {
                role_id: delegate,
                grantee: axiam_authz::network_gate::Grantee::User(target),
                resource_id: None,
                inherit: true,
            },
        )
        .await
        .is_err(),
        "the organization writer does not delegate network:grant it does not hold"
    );

    // The bootstrap (the named exemption `organization-bootstrap`): the child
    // tenant's own seeded super-admin, tenant-wide, to a child-tenant user.
    let child_super_admin = w.role_named("super-admin").await;
    let bootstrap = |resource_id| axiam_authz::network_gate::NetworkWrite::RoleAssign {
        role_id: child_super_admin,
        grantee: axiam_authz::network_gate::Grantee::User(target),
        resource_id,
        inherit: true,
    };
    let cleared = gate(&w, org_admin, org_scope, bootstrap(None))
        .await
        .expect("the organization writer still bootstraps the tenant's super-admin");
    assert!(cleared.is_network_sensitive());
    assert_eq!(
        cleared.exemption(),
        Some(axiam_authz::network_gate::EXEMPTION_ORGANIZATION_BOOTSTRAP)
    );
    assert!(
        gate(
            &w,
            org_admin,
            org_scope,
            bootstrap(Some(network_root_id(w.tenant)))
        )
        .await
        .is_err(),
        "the exemption is tenant-wide only, even at /network itself"
    );

    // The control: the child tenant's own super-admin clears the same write.
    let local = w.user(&[(child_super_admin, None)]).await;
    assert!(
        gate(&w, local, SubjectScope::Tenant, assign())
            .await
            .is_ok(),
        "the child tenant's own super-admin still holds network:grant"
    );
}

// ---------------------------------------------------------------------------
// R110W6-06 (#703, T-484): a cleared network-sensitive write has a row
// ---------------------------------------------------------------------------

/// Every cleared network-sensitive assignment, unassignment, grant, revoke and
/// binding leaves exactly one success row with the role, the grantee, the node
/// and the `network:` permissions conferred; a write that touches no `network:`
/// permission leaves none, and neither does a refused one (it has its own).
#[actix_rt::test]
async fn r110w6_06_each_cleared_network_write_leaves_exactly_one_row_with_its_members() {
    let w = World::new().await;
    let root = network_root_id(w.tenant);
    let admin = network_admin(&w).await;
    let t = w.user_token(admin);
    let app = app!(w);
    let fleet = w.role("fleet", &[(NETWORK_JOIN, ALLOW)]).await;
    let plain = w.role("plain", &[]).await;
    let user = w.user(&[]).await;
    let device = w.service_account(&[]).await;
    let grant_perm = w.permission_id(NETWORK_GRANT).await;

    // A role carrying a network permission, assigned and unassigned.
    let (status, _err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/roles/{fleet}/users"),
        Some(json!({ "user_id": user })),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    let rows = w.audit("network_role.assigned").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.outcome, AuditOutcome::Success);
    assert_eq!(row.actor_id, admin);
    assert_eq!(row.metadata["role_id"], fleet.to_string());
    assert_eq!(row.metadata["role"], "fleet");
    assert_eq!(row.metadata["grantee"]["kind"], "user");
    assert_eq!(row.metadata["grantee"]["id"], user.to_string());
    assert_eq!(
        row.metadata["node"],
        root.to_string(),
        "a tenant-wide assignment is decided, and recorded, at /network (#730 g)"
    );
    assert_eq!(row.resource_id, None, "the row's resource is the caller's");
    assert_eq!(row.metadata["permissions"][0]["action"], NETWORK_JOIN);
    assert_eq!(row.metadata["permissions"][0]["effect"], "allow");

    let (status, _err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/roles/{fleet}/service-accounts"),
        Some(json!({ "service_account_id": device, "resource_id": root })),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    let rows = w.audit("network_role.assigned").await;
    assert_eq!(rows.len(), 2, "one row per assignment: {rows:?}");
    let row = rows
        .iter()
        .find(|r| r.metadata["grantee"]["kind"] == "service_account")
        .expect("the service-account row");
    assert_eq!(row.metadata["grantee"]["id"], device.to_string());
    assert_eq!(row.metadata["node"], root.to_string());
    assert_eq!(row.resource_id, Some(root));

    let (status, _err) = call(
        &app,
        &t,
        "DELETE",
        &format!("/api/v1/roles/{fleet}/users/{user}"),
        None,
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    let rows = w.audit("network_role.unassigned").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].metadata["role_id"], fleet.to_string());
    assert_eq!(rows[0].metadata["grantee"]["id"], user.to_string());
    assert_eq!(rows[0].metadata["permissions"][0]["action"], NETWORK_JOIN);

    // A grant and a revoke of a network permission on a role.
    let (status, _err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/roles/{plain}/permissions"),
        Some(json!({ "permission_id": grant_perm, "effect": "deny" })),
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    let rows = w.audit("network_role.granted").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].metadata["role_id"], plain.to_string());
    assert_eq!(rows[0].metadata["role"], "plain");
    assert_eq!(rows[0].metadata["permissions"][0]["action"], NETWORK_GRANT);
    assert_eq!(rows[0].metadata["permissions"][0]["effect"], "deny");

    let (status, _err) = call(
        &app,
        &t,
        "DELETE",
        &format!("/api/v1/roles/{plain}/permissions/{grant_perm}"),
        None,
    )
    .await;
    assert_eq!(status, 204, "unexpected answer (body withheld)");
    let rows = w.audit("network_role.revoked").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].metadata["permissions"][0]["action"], NETWORK_GRANT);
    assert_eq!(rows[0].metadata["permissions"][0]["effect"], "deny");

    // A binding.
    let cert = w.certificate().await;
    let (status, _err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/service-accounts/{device}/bind-certificate"),
        Some(json!({ "certificate_id": cert })),
    )
    .await;
    assert_eq!(status, 200, "unexpected answer (body withheld)");
    let rows = w.audit("certificate_binding.bound").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].outcome, AuditOutcome::Success);
    assert_eq!(rows[0].metadata["certificate_id"], cert.to_string());
    assert_eq!(rows[0].metadata["grantee"]["id"], device.to_string());
    let text = rows[0].metadata.to_string();
    assert!(!text.contains("BEGIN"), "no certificate in the row");
    assert!(
        rows[0].metadata.get("before").is_none(),
        "a success row names no previous account"
    );
    assert_eq!(
        rows[0].metadata["nodes"],
        json!([root.to_string()]),
        "the node the gate checked network:grant at"
    );

    // The route refuses a certificate that is already bound (409, the unique
    // binding), so a success row never takes a certificate from an account and
    // carries no `before` (R112W4-05); the clearance's own `before` is pinned
    // in `axiam-authz`'s `network_gate/tests.rs`.
    let other = w.service_account(&[]).await;
    let (status, _) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/service-accounts/{other}/bind-certificate"),
        Some(json!({ "certificate_id": cert })),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(w.audit("certificate_binding.bound").await.len(), 1);

    // Nothing else was written: the five actions hold exactly these rows.
    let total = w.audit("network_role.assigned").await.len()
        + w.audit("network_role.unassigned").await.len()
        + w.audit("network_role.granted").await.len()
        + w.audit("network_role.revoked").await.len()
        + w.audit("certificate_binding.bound").await.len();
    assert_eq!(total, 6);
}

/// A write that touches no `network:` permission leaves none of the five rows.
#[actix_rt::test]
async fn r110w6_06_a_non_network_write_leaves_no_row() {
    let w = World::new().await;
    let t = w.user_token(network_admin(&w).await);
    let app = app!(w);
    let plain = w.role("plain", &[]).await;
    let user = w.user(&[]).await;
    let read = w.permission_id("roles:get").await;

    for (method, uri, body) in [
        (
            "POST",
            format!("/api/v1/roles/{plain}/users"),
            Some(json!({ "user_id": user })),
        ),
        (
            "POST",
            format!("/api/v1/roles/{plain}/permissions"),
            Some(json!({ "permission_id": read })),
        ),
        (
            "DELETE",
            format!("/api/v1/roles/{plain}/permissions/{read}"),
            None,
        ),
        (
            "DELETE",
            format!("/api/v1/roles/{plain}/users/{user}"),
            None,
        ),
    ] {
        let (status, _) = call(&app, &t, method, &uri, body).await;
        assert_eq!(status, 204, "{method} route answered {status}");
    }
    for action in [
        "network_role.assigned",
        "network_role.unassigned",
        "network_role.granted",
        "network_role.revoked",
        "certificate_binding.bound",
    ] {
        assert!(w.audit(action).await.is_empty(), "{action}");
    }
}

// ---------------------------------------------------------------------------
// R111W4-02 (#726, T-484): the row cannot be separated from the write
// ---------------------------------------------------------------------------

/// The writer `network_gate::write_and_record` records, as a handler builds it
/// from its principal.
fn actor_for(w: &World, subject: Uuid) -> axiam_api_rest::network_gate::GateActor {
    axiam_api_rest::network_gate::GateActor {
        writer: axiam_authz::network_gate::GateWriter {
            tenant_id: w.tenant,
            subject_id: subject,
            subject_scope: SubjectScope::Tenant,
        },
        actor_type: axiam_core::models::audit::ActorType::User,
        label: None,
    }
}

/// The handler's future is dropped right after the repository write returned
/// — the client went away — and the write's row is still appended: the write
/// and the append are one spawned task that dropping its awaiter does not
/// cancel. The store wrapper signals that the write landed and then pends, so
/// the drop happens between the write and the append, deterministically.
#[actix_rt::test]
async fn r111w4_02_a_handler_dropped_after_its_write_landed_still_leaves_the_row() {
    let w = World::new().await;
    let root = network_root_id(w.tenant);
    let admin = network_admin(&w).await;
    let fleet = w.role("fleet", &[(NETWORK_JOIN, ALLOW)]).await;
    let device = w.service_account(&[]).await;
    let state = AppState::for_test(w.db.clone(), w.auth.clone());
    let write = axiam_authz::network_gate::NetworkWrite::RoleAssign {
        role_id: fleet,
        grantee: axiam_authz::network_gate::Grantee::ServiceAccount(device),
        resource_id: Some(root),
        inherit: true,
    };
    let cleared = gate(&w, admin, SubjectScope::Tenant, write)
        .await
        .expect("the network administrator is cleared");

    let (landed, has_landed) = tokio::sync::oneshot::channel::<()>();
    let release = Arc::new(tokio::sync::Notify::new());
    let roles = w.roles();
    let (tenant, claim, released) = (w.tenant, cleared.role_claim(), Arc::clone(&release));
    let repository_write = async move {
        let written = roles
            .assign_to_service_account_claimed(
                tenant,
                device,
                fleet,
                AssignmentScope::from(Some(root)),
                claim,
            )
            .await;
        landed.send(()).expect("the test waits for the write");
        released.notified().await;
        written
    };
    let (actor, engine) = (actor_for(&w, admin), w.engine());
    let mut handler = Box::pin(axiam_api_rest::network_gate::write_and_record(
        &state,
        &engine,
        &actor,
        write,
        &cleared,
        CacheFlush::Subject(device),
        repository_write,
    ));
    tokio::select! {
        _ = &mut handler => panic!("the write pends until released"),
        landed = has_landed => landed.expect("the write landed"),
    }
    drop(handler);
    assert!(
        w.audit("network_role.assigned").await.is_empty(),
        "the row follows the write, not the gate"
    );

    release.notify_one();
    let mut rows = Vec::new();
    for _ in 0..200 {
        rows = w.audit("network_role.assigned").await;
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(rows.len(), 1, "the dropped handler's write has its row");
    let row = &rows[0];
    assert_eq!(row.outcome, AuditOutcome::Success);
    assert_eq!(row.actor_id, admin);
    assert_eq!(row.metadata["role"], "fleet");
    assert_eq!(row.metadata["grantee"]["id"], device.to_string());
    assert_eq!(row.metadata["node"], root.to_string());
    assert_eq!(row.metadata["permissions"][0]["action"], NETWORK_JOIN);
    assert_eq!(w.joins(device, root).await, "allowed", "the write landed");
}

/// An `InvalidationBroadcaster` that records every event it is handed, as the
/// AMQP fan-out would publish it.
#[derive(Default)]
struct RecordingBroadcaster(std::sync::Mutex<Vec<axiam_authz::InvalidationEvent>>);

impl axiam_authz::InvalidationBroadcaster for RecordingBroadcaster {
    fn broadcast<'a>(
        &'a self,
        event: axiam_authz::InvalidationEvent,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = axiam_core::error::AxiamResult<()>> + Send + 'a>,
    > {
        self.0.lock().unwrap().push(event);
        Box::pin(async { Ok(()) })
    }
}

/// R112W4-01 (#775): the D7 flush of a revocation rides the write's task. A
/// device holds a `network:join` allow, cached; its unassignment lands and the
/// handler's future is dropped there (the client went away). Once released,
/// the task still drops the cached allow locally and publishes the broadcast,
/// before it appends the row — with the flush in the handler's future, as
/// before, the allow stayed cached until the TTL and nothing was published.
#[actix_rt::test]
async fn r112w4_01_a_handler_dropped_after_its_revocation_landed_still_flushes_the_cached_allow() {
    let w = World::new().await;
    let root = network_root_id(w.tenant);
    let admin = network_admin(&w).await;
    let fleet = w.role("fleet", &[(NETWORK_JOIN, ALLOW)]).await;
    let device = w.service_account(&[(fleet, Some(root))]).await;
    let cache = Arc::new(axiam_authz::DecisionCache::new(
        axiam_authz::DecisionCacheConfig {
            ttl: std::time::Duration::from_secs(300),
            ..Default::default()
        },
    ));
    let broadcaster = Arc::new(RecordingBroadcaster::default());
    let engine: Arc<dyn AuthzChecker> = Arc::new(
        AuthorizationEngine::new(
            SurrealRoleRepository::new(w.db.clone()),
            SurrealPermissionRepository::new(w.db.clone()),
            SurrealResourceRepository::new(w.db.clone()),
            SurrealScopeRepository::new(w.db.clone()),
            SurrealGroupRepository::new(w.db.clone()),
        )
        .with_decision_cache(Arc::clone(&cache))
        .with_invalidation_broadcaster(broadcaster.clone()),
    );
    let join = AccessRequest {
        tenant_id: w.tenant,
        subject_scope: SubjectScope::Tenant,
        subject_id: device,
        action: NETWORK_JOIN.into(),
        resource_id: root,
        scope: None,
    };
    assert_eq!(
        engine.check_access(&join).await.unwrap(),
        AccessDecision::Allow
    );
    assert!(cache.get(&join).is_some(), "the allow is cached");

    let state = AppState::for_test(w.db.clone(), w.auth.clone());
    let write = axiam_authz::network_gate::NetworkWrite::RoleUnassign {
        role_id: fleet,
        grantee: axiam_authz::network_gate::Grantee::ServiceAccount(device),
        resource_id: Some(root),
    };
    let cleared = gate(&w, admin, SubjectScope::Tenant, write)
        .await
        .expect("the network administrator is cleared");
    let (landed, has_landed) = tokio::sync::oneshot::channel::<()>();
    let release = Arc::new(tokio::sync::Notify::new());
    let roles = w.roles();
    let (tenant, claim, released) = (w.tenant, cleared.role_claim(), Arc::clone(&release));
    let repository_write = async move {
        let written = roles
            .unassign_from_service_account_claimed(tenant, device, fleet, Some(root), claim)
            .await;
        landed.send(()).expect("the test waits for the write");
        released.notified().await;
        written
    };
    let actor = actor_for(&w, admin);
    let mut handler = Box::pin(axiam_api_rest::network_gate::write_and_record(
        &state,
        &engine,
        &actor,
        write,
        &cleared,
        CacheFlush::Subject(device),
        repository_write,
    ));
    tokio::select! {
        _ = &mut handler => panic!("the write pends until released"),
        landed = has_landed => landed.expect("the write landed"),
    }
    drop(handler);
    assert!(cache.get(&join).is_some(), "the flush follows the write");

    release.notify_one();
    let mut rows = Vec::new();
    for _ in 0..200 {
        rows = w.audit("network_role.unassigned").await;
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        rows.len(),
        1,
        "the dropped handler's revocation has its row"
    );
    assert!(
        cache.get(&join).is_none(),
        "the cached allow is gone by the time the row is readable"
    );
    assert_eq!(
        *broadcaster.0.lock().unwrap(),
        [axiam_authz::InvalidationEvent::Subject {
            tenant_id: w.tenant,
            subject_id: device,
        }],
        "the other replicas are told"
    );
    assert_eq!(
        w.joins(device, root).await,
        "no_grant",
        "the revocation landed"
    );
}

/// R112W4-01 (#775): a stale claim whose handler is dropped while its write is
/// being refused still leaves its `version:stale` row — the refusal row is
/// appended in the write's task, not in the handler's future.
#[actix_rt::test]
async fn r112w4_01_a_handler_dropped_on_a_stale_claim_still_leaves_the_refusal_row() {
    let w = World::new().await;
    let root = network_root_id(w.tenant);
    let admin = network_admin(&w).await;
    let fleet = w.role("fleet", &[(NETWORK_JOIN, ALLOW)]).await;
    let device = w.service_account(&[]).await;
    let read = w
        .permission_id(axiam_core::models::network::NETWORK_READ)
        .await;
    let state = AppState::for_test(w.db.clone(), w.auth.clone());
    let write = axiam_authz::network_gate::NetworkWrite::RoleAssign {
        role_id: fleet,
        grantee: axiam_authz::network_gate::Grantee::ServiceAccount(device),
        resource_id: Some(root),
        inherit: true,
    };
    let cleared = gate(&w, admin, SubjectScope::Tenant, write)
        .await
        .expect("the network administrator is cleared");
    let (landed, has_landed) = tokio::sync::oneshot::channel::<()>();
    let release = Arc::new(tokio::sync::Notify::new());
    let roles = w.roles();
    let permissions = SurrealPermissionRepository::new(w.db.clone());
    let (tenant, claim, released) = (w.tenant, cleared.role_claim(), Arc::clone(&release));
    let repository_write = async move {
        // A grant the gate never saw lands first: the claim is stale.
        permissions
            .grant_to_role_with_effect(tenant, fleet, read, vec![], DENY)
            .await
            .unwrap();
        let written = roles
            .assign_to_service_account_claimed(
                tenant,
                device,
                fleet,
                AssignmentScope::from(Some(root)),
                claim,
            )
            .await;
        landed.send(()).expect("the test waits for the write");
        released.notified().await;
        written
    };
    let (actor, engine) = (actor_for(&w, admin), w.engine());
    let mut handler = Box::pin(axiam_api_rest::network_gate::write_and_record(
        &state,
        &engine,
        &actor,
        write,
        &cleared,
        CacheFlush::Subject(device),
        repository_write,
    ));
    tokio::select! {
        _ = &mut handler => panic!("the write pends until released"),
        landed = has_landed => landed.expect("the write was refused"),
    }
    drop(handler);

    release.notify_one();
    let mut rows = Vec::new();
    for _ in 0..200 {
        rows = w.audit("network_role.assign_refused").await;
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let row = the_row(&rows);
    assert_eq!(row.outcome, AuditOutcome::Denied);
    assert_eq!(row.metadata["rule"], "version:stale");
    assert_eq!(row.metadata["status"], 409);
    assert_eq!(row.metadata["write"], "role_assign");
    assert_eq!(row.metadata["before"]["role_id"], fleet.to_string());
    assert!(
        w.audit("network_role.assigned").await.is_empty(),
        "nothing landed"
    );
    assert_eq!(w.joins(device, root).await, "no_grant", "nothing landed");
}

/// R112W4-02 (#776, T-444): an orderly stop keeps a cleared write and its row
/// together. A real server, one worker; the handler's write lands and pends;
/// its client goes away, so the connection no longer counts, and the server is
/// stopped gracefully — the worker's runtime ends with it. With the task on the
/// composition root's runtime (`NetworkWriteTasks::on`), the write, released,
/// still appends its row, and the stop's wait (`wait_within`) sees it finish
/// inside the bound. With the task on the worker's runtime, as in W4.1, it was
/// dropped with the worker and the row never came.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r112w4_02_an_orderly_stop_waits_for_a_cleared_write_whose_client_has_gone() {
    use std::sync::Mutex;
    use tokio::io::AsyncWriteExt;

    let w = World::new().await;
    let root = network_root_id(w.tenant);
    let admin = network_admin(&w).await;
    let fleet = w.role("fleet", &[(NETWORK_JOIN, ALLOW)]).await;
    let device = w.service_account(&[]).await;
    let write = axiam_authz::network_gate::NetworkWrite::RoleAssign {
        role_id: fleet,
        grantee: axiam_authz::network_gate::Grantee::ServiceAccount(device),
        resource_id: Some(root),
        inherit: true,
    };
    let cleared = gate(&w, admin, SubjectScope::Tenant, write)
        .await
        .expect("the network administrator is cleared");

    let tasks =
        axiam_api_rest::network_gate::NetworkWriteTasks::on(tokio::runtime::Handle::current());
    let mut state = AppState::for_test(w.db.clone(), w.auth.clone());
    state.network_writes = tasks.clone();
    let (landed, has_landed) = tokio::sync::oneshot::channel::<()>();
    let release = Arc::new(tokio::sync::Notify::new());
    // The one request's inputs, taken by the handler.
    let once = Arc::new(Mutex::new(Some((cleared, landed))));
    let (roles, engine, actor) = (w.roles(), w.engine(), actor_for(&w, admin));
    let tenant = w.tenant;
    let released = Arc::clone(&release);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = actix_web::HttpServer::new(move || {
        let (state, once, roles, engine, actor, released) = (
            state.clone(),
            Arc::clone(&once),
            roles.clone(),
            engine.clone(),
            actor.clone(),
            Arc::clone(&released),
        );
        App::new().route(
            "/w",
            web::post().to(move || {
                let (state, once, roles, engine, actor, released) = (
                    state.clone(),
                    Arc::clone(&once),
                    roles.clone(),
                    engine.clone(),
                    actor.clone(),
                    Arc::clone(&released),
                );
                async move {
                    let (cleared, landed) = once.lock().unwrap().take().expect("one request");
                    let claim = cleared.role_claim();
                    let repository_write = async move {
                        let written = roles
                            .assign_to_service_account_claimed(
                                tenant,
                                device,
                                fleet,
                                AssignmentScope::from(Some(root)),
                                claim,
                            )
                            .await;
                        landed.send(()).expect("the test waits for the write");
                        released.notified().await;
                        written
                    };
                    axiam_api_rest::network_gate::write_and_record(
                        &state,
                        &engine,
                        &actor,
                        write,
                        &cleared,
                        CacheFlush::Subject(device),
                        repository_write,
                    )
                    .await
                    .map(|()| actix_web::HttpResponse::NoContent().finish())
                    .map_err(axiam_api_rest::error::AxiamApiError::from)
                }
            }),
        )
    })
    .workers(1)
    .shutdown_timeout(5)
    .listen(listener)
    .expect("listen")
    .run();
    let handle = server.handle();
    let serving = tokio::spawn(server);

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"POST /w HTTP/1.1\r\nHost: axiam\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    has_landed.await.expect("the write landed");
    drop(client);
    assert_eq!(tasks.in_flight(), 1, "the write's task is in flight");

    // SIGTERM's path: stop accepting, wait for connections (there are none
    // left), stop the worker. Only then is the write released.
    handle.stop(true).await;
    serving.await.unwrap().expect("the server stopped in order");
    assert!(
        w.audit("network_role.assigned").await.is_empty(),
        "the row follows the write"
    );
    release.notify_one();
    assert!(
        tasks.wait_within(std::time::Duration::from_secs(5)).await,
        "the stop's wait sees the write finish inside its bound"
    );
    let rows = w.audit("network_role.assigned").await;
    assert_eq!(rows.len(), 1, "the write kept its row through the stop");
    assert_eq!(rows[0].metadata["grantee"]["id"], device.to_string());
    assert_eq!(w.joins(device, root).await, "allowed", "the write landed");
}

/// A role deleted between the write and the append — after a grant the gate
/// never saw — still gets a row naming it, with the grants the gate saw: the
/// row is built from the clearance before the write, not read after it.
#[actix_rt::test]
async fn r111w4_02_a_role_deleted_after_the_write_is_still_named_with_the_grants_the_gate_saw() {
    let w = World::new().await;
    let root = network_root_id(w.tenant);
    let admin = network_admin(&w).await;
    let fleet = w.role("doomed-fleet", &[(NETWORK_JOIN, ALLOW)]).await;
    let device = w.service_account(&[]).await;
    let read = w
        .permission_id(axiam_core::models::network::NETWORK_READ)
        .await;
    let state = AppState::for_test(w.db.clone(), w.auth.clone());
    let write = axiam_authz::network_gate::NetworkWrite::RoleAssign {
        role_id: fleet,
        grantee: axiam_authz::network_gate::Grantee::ServiceAccount(device),
        resource_id: Some(root),
        inherit: true,
    };
    let cleared = gate(&w, admin, SubjectScope::Tenant, write)
        .await
        .expect("the network administrator is cleared");

    let roles = w.roles();
    let permissions = SurrealPermissionRepository::new(w.db.clone());
    let (tenant, claim) = (w.tenant, cleared.role_claim());
    let repository_write = async move {
        let written = roles
            .assign_to_service_account_claimed(
                tenant,
                device,
                fleet,
                AssignmentScope::from(Some(root)),
                claim,
            )
            .await;
        // What a concurrent writer does before the append: regrant, then delete.
        permissions
            .grant_to_role_with_effect(tenant, fleet, read, vec![], DENY)
            .await
            .unwrap();
        roles.delete(tenant, fleet).await.unwrap();
        written
    };
    axiam_api_rest::network_gate::write_and_record(
        &state,
        &w.engine(),
        &actor_for(&w, admin),
        write,
        &cleared,
        CacheFlush::Subject(device),
        repository_write,
    )
    .await
    .expect("the write landed");

    assert!(
        w.roles().get_by_id(w.tenant, fleet).await.is_err(),
        "deleted"
    );
    let rows = w.audit("network_role.assigned").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row = &rows[0];
    assert_eq!(row.metadata["role_id"], fleet.to_string());
    assert_eq!(row.metadata["role"], "doomed-fleet");
    assert_eq!(
        row.metadata["permissions"],
        json!([{ "action": NETWORK_JOIN, "effect": "allow", "scope_ids": [] }]),
        "the grants the gate saw, not the deny written after it"
    );
}

/// R111W4-03 (#727): deleting a role that carries `network:` grants leaves
/// exactly one `network_role.deleted` row naming the role and the grants the
/// gate read; a role with no `network:` grant leaves none.
#[actix_rt::test]
async fn r111w4_03_deleting_a_role_with_network_grants_leaves_one_row_naming_them() {
    let w = World::new().await;
    let admin = network_admin(&w).await;
    let t = w.user_token(admin);
    let app = app!(w);
    let denying = w.role("blocked-fleet", &[(NETWORK_JOIN, DENY)]).await;
    let allowing = w.role("open-fleet", &[(NETWORK_JOIN, ALLOW)]).await;
    let plain = w.role("plain", &[]).await;

    for (role, name, effect, expected) in [
        (denying, "blocked-fleet", "deny", 1),
        (allowing, "open-fleet", "allow", 2),
    ] {
        let (status, _err) = call(&app, &t, "DELETE", &format!("/api/v1/roles/{role}"), None).await;
        assert_eq!(status, 204, "delete refused");
        let rows = w.audit("network_role.deleted").await;
        assert_eq!(rows.len(), expected, "one row per delete: {rows:?}");
        let row = rows
            .iter()
            .find(|r| r.metadata["role_id"] == role.to_string())
            .expect("the row of this delete");
        assert_eq!(row.outcome, AuditOutcome::Success);
        assert_eq!(row.actor_id, admin);
        assert_eq!(row.metadata["role"], name);
        assert_eq!(row.metadata["write"], "role_delete");
        assert_eq!(
            row.metadata["permissions"],
            json!([{ "action": NETWORK_JOIN, "effect": effect, "scope_ids": [] }]),
        );
    }

    let (status, _err) = call(&app, &t, "DELETE", &format!("/api/v1/roles/{plain}"), None).await;
    assert_eq!(status, 204, "delete refused");
    assert_eq!(
        w.audit("network_role.deleted").await.len(),
        2,
        "a role with no network: grant leaves no row"
    );
}
