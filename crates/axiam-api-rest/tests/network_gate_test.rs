//! The network write gate on the real routes, against the real authorization
//! engine (RADIUS D4, W6.2; `claude_dev/radius-reply-profile-design.md` §4.2,
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
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{issue_access_token, issue_service_account_token};
use axiam_authz::AuthorizationEngine;
use axiam_authz::types::{AccessRequest, SubjectScope};
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

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
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
                password: TEST_PASSWORD.into(),
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
    assert_eq!(status, 403, "{err}");
    assert_eq!(
        err["action"], NETWORK_GRANT,
        "the response names the permission: {err}"
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
    let (status, err) = call(&app, &w.user_token(netadmin), "POST", &uri, Some(body)).await;
    assert_eq!(status, 204, "{err}");
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
    let (status, err) = call(&app, &w.user_token(half), "POST", &uri, Some(body.clone())).await;
    assert_eq!(status, 403, "{err}");
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
    let (status, err) = call(&app, &w.user_token(both), "POST", &uri, Some(body)).await;
    assert_eq!(status, 200, "{err}");

    // An account with no join asks nothing beyond certificates:bind.
    let bare = w.service_account(&[]).await;
    let (status, err) = call(
        &app,
        &w.user_token(half),
        "POST",
        &format!("/api/v1/service-accounts/{bare}/bind-certificate"),
        Some(json!({ "certificate_id": w.certificate().await })),
    )
    .await;
    assert_eq!(status, 200, "{err}");
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

    let (status, err) = call(
        &app,
        &token,
        "POST",
        &format!("/api/v1/service-accounts/{sa}/bind-certificate"),
        Some(json!({ "certificate_id": w.certificate().await })),
    )
    .await;
    assert_eq!(status, 403, "{err}");
    let rows = w.audit("certificate_binding.refused").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["rule"], "H6");
    assert_eq!(row.actor_id, sa);

    // Binding to another account is the ordinary case.
    let other = w.service_account(&[]).await;
    let (status, err) = call(
        &app,
        &token,
        "POST",
        &format!("/api/v1/service-accounts/{other}/bind-certificate"),
        Some(json!({ "certificate_id": w.certificate().await })),
    )
    .await;
    assert_eq!(status, 200, "{err}");
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
    let (status, err) = call(&app, &w.user_token(netadmin), "POST", &assign, Some(body)).await;
    assert_eq!(status, 204, "{err}");
    assert_eq!(w.joins(device, iot.id).await, "denied_by_rule", "Q2");

    // Release: the administrator without network:grant at /network/zones
    // cannot; the deny stays.
    let release =
        format!("/api/v1/roles/{quarantine}/service-accounts/{device}?resource_id={zones}");
    let (status, err) = call(&app, &w.user_token(admin), "DELETE", &release, None).await;
    assert_eq!(status, 403, "{err}");
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
    let (status, err) = call(&app, &w.user_token(netadmin), "DELETE", &release, None).await;
    assert_eq!(status, 204, "{err}");
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
    let (status, err) = call(
        &app,
        &agent_token,
        "POST",
        &place,
        Some(json!({ "service_account_id": agent, "resource_id": iot.id })),
    )
    .await;
    assert_eq!(status, 403, "{err}");
    assert_eq!(w.joins(agent, iot.id).await, "no_grant", "nothing written");
    let rows = w.audit("network_role.assign_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.actor_id, agent);
    assert_eq!(row.metadata["rule"], "H6");
    assert_eq!(row.metadata["after"]["service_account"], agent.to_string());
    // Positive twin: the agent places another device (its job).
    let other = w.service_account(&[]).await;
    let (status, err) = call(
        &app,
        &agent_token,
        "POST",
        &place,
        Some(json!({ "service_account_id": other, "resource_id": iot.id })),
    )
    .await;
    assert_eq!(status, 204, "{err}");
    assert_eq!(w.joins(other, iot.id).await, "allowed");
    // ... and another administrator places the agent.
    let (status, err) = call(
        &app,
        &netadmin_token,
        "POST",
        &place,
        Some(json!({ "service_account_id": agent, "resource_id": iot.id })),
    )
    .await;
    assert_eq!(status, 204, "{err}");
    assert_eq!(w.joins(agent, iot.id).await, "allowed");

    // 2. Quarantined by the network administrator, the agent cannot release
    //    itself by unassigning the deny.
    let (status, err) = call(
        &app,
        &netadmin_token,
        "POST",
        &format!("/api/v1/roles/{quarantined}/service-accounts"),
        Some(json!({ "service_account_id": agent, "resource_id": zones })),
    )
    .await;
    assert_eq!(status, 204, "{err}");
    assert_eq!(w.joins(agent, iot.id).await, "denied_by_rule");
    let release = |who: Uuid| {
        format!("/api/v1/roles/{quarantined}/service-accounts/{who}?resource_id={zones}")
    };
    let (status, err) = call(&app, &agent_token, "DELETE", &release(agent), None).await;
    assert_eq!(status, 403, "{err}");
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
    let (status, err) = call(
        &app,
        &agent_token,
        "DELETE",
        &format!("/api/v1/roles/{quarantined}/permissions/{join_perm}"),
        None,
    )
    .await;
    assert_eq!(status, 403, "revoke of its own deny: {err}");
    let (status, err) = call(
        &app,
        &agent_token,
        "DELETE",
        &format!("/api/v1/roles/{quarantined}"),
        None,
    )
    .await;
    assert_eq!(status, 403, "delete of its own deny role: {err}");
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
    let (status, err) = call(
        &app,
        &agent_token,
        "POST",
        &format!("/api/v1/roles/{fleet}/permissions"),
        Some(json!({ "permission_id": join_perm, "effect": "allow" })),
    )
    .await;
    assert_eq!(status, 403, "a join granted to a role it holds: {err}");
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
    let (status, err) = call(
        &app,
        &agent_token,
        "POST",
        &format!("/api/v1/roles/{other_fleet}/permissions"),
        Some(json!({ "permission_id": join_perm, "effect": "allow" })),
    )
    .await;
    assert_eq!(status, 204, "{err}");
    let other_quarantine = w.role("other-quarantine", &[(NETWORK_JOIN, DENY)]).await;
    let (status, err) = call(
        &app,
        &agent_token,
        "DELETE",
        &format!("/api/v1/roles/{other_quarantine}/permissions/{join_perm}"),
        None,
    )
    .await;
    assert_eq!(status, 204, "{err}");
    let spare_quarantine = w.role("spare-quarantine", &[(NETWORK_JOIN, DENY)]).await;
    let (status, err) = call(
        &app,
        &agent_token,
        "DELETE",
        &format!("/api/v1/roles/{spare_quarantine}"),
        None,
    )
    .await;
    assert_eq!(status, 204, "{err}");

    // 4. The network administrator releases the agent.
    let (status, err) = call(&app, &netadmin_token, "DELETE", &release(agent), None).await;
    assert_eq!(status, 204, "{err}");
    assert_eq!(w.joins(agent, iot.id).await, "allowed");
}

/// H6 through a group (R110W6-01): a deny a group carries reaches its
/// members, so a member does not lift it by unassigning it from the group or
/// by deleting the role — "holds" counts the group. Rule 2 keeps network roles
/// off groups, so the edge is written here as one predating the rule would be.
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
    w.roles()
        .assign_to_group(
            w.tenant,
            group.id,
            quarantined,
            AssignmentScope::from(Some(zones)),
        )
        .await
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
    let (status, err) = call(&app, &w.user_token(member), "DELETE", &unassign, None).await;
    assert_eq!(status, 403, "{err}");
    let rows = w.audit("network_role.unassign_refused").await;
    assert_eq!(the_row(&rows).metadata["rule"], "H6");
    let (status, err) = call(
        &app,
        &w.user_token(member),
        "DELETE",
        &format!("/api/v1/roles/{quarantined}"),
        None,
    )
    .await;
    assert_eq!(status, 403, "{err}");
    let rows = w.audit("network_role.write_refused").await;
    assert_eq!(the_row(&rows).metadata["rule"], "H6");
    assert_eq!(w.joins(member, iot.id).await, "denied_by_rule");

    // Positive twin: an administrator outside the group releases it.
    let (status, err) = call(&app, &w.user_token(outsider), "DELETE", &unassign, None).await;
    assert_eq!(status, 204, "{err}");
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
        let (status, err) = call(
            &app,
            &w.user_token(writer),
            "POST",
            &uri,
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, 403, "{err}");
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

    let (status, err) = call(
        &app,
        &w.user_token(admin),
        "POST",
        &grant_uri,
        Some(grant_body.clone()),
    )
    .await;
    assert_eq!(status, 403, "{err}");
    let rows = w.audit("network_role.grant_refused").await;
    assert_eq!(the_row(&rows).metadata["node"], root.to_string());

    let (status, err) = call(
        &app,
        &w.user_token(super_admin),
        "POST",
        &grant_uri,
        Some(grant_body),
    )
    .await;
    assert_eq!(status, 204, "{err}");

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
    let (status, err) = call(
        &app,
        &w.user_token(super_admin),
        "POST",
        &assign_uri,
        Some(assign_body),
    )
    .await;
    assert_eq!(status, 204, "{err}");

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
        let (status, err) = call(&app, &t, method, &uri, body).await;
        assert_eq!(status, 400, "{method} {uri}: {err}");
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
    let (status, err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/roles/{net_role}/groups"),
        Some(json!({ "group_id": group["id"], "resource_id": iot.id })),
    )
    .await;
    assert_eq!(status, 400, "{err}");

    // Rule 1: not made global.
    let (status, err) = call(
        &app,
        &t,
        "PUT",
        &format!("/api/v1/roles/{net_role}"),
        Some(json!({ "is_global": true })),
    )
    .await;
    assert_eq!(status, 400, "{err}");

    // Rule 3: no network deny on a role assigned with inherit: false.
    let narrow = w.role("narrow", &[]).await;
    let device = w.service_account(&[]).await;
    let (status, err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/roles/{narrow}/service-accounts"),
        Some(json!({ "service_account_id": device, "resource_id": iot.id, "inherit": false })),
    )
    .await;
    assert_eq!(status, 204, "{err}");
    let (status, err) = call(
        &app,
        &t,
        "POST",
        &format!("/api/v1/roles/{narrow}/permissions"),
        Some(json!({ "permission_id": join_perm, "effect": "deny" })),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let rule_rows = w.audit("network_role.grant_refused").await;
    assert!(rule_rows.iter().any(|r| r.metadata["rule"] == "4.2:rule-3"));
}
