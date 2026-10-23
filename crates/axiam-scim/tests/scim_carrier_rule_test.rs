//! R112-08 (#801) — SCIM's provisioning-token branch follows the carrier rule
//! and leaves the extractor's verdict (D-12) for the request row.
//!
//! CONTRACT §6.1 rule 11 reads the `axiam_access` cookie first, and the audit
//! middleware names the request row's actor by it. A SCIM request with a
//! session cookie for X **and** a provisioning token used to be served as the
//! token's principal while its row named X `authenticated: true`; a refused
//! token was recorded `authenticated: true` as well. A cookie beside a
//! provisioning token is now refused as ambiguous, and every refusal of the
//! token branch leaves `AuthVerdict::Refused`, so the row says `false`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use actix_web::cookie::Cookie;
use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::extractors::scim_token::{ScimTokenPrincipal, ScimTokenResolver};
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_audit::AuditMiddleware;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::error::AxiamResult;
use axiam_core::models::audit::{AuditLogEntry, CreateAuditLogEntry};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::scim_token::SCIM_TOKEN_PREFIX;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OrganizationRepository, PaginatedResult, Pagination,
    RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

fn generated(prefix: &str) -> String {
    format!("{prefix}{}", Uuid::new_v4().simple())
}

fn test_auth_config() -> AuthConfig {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// Keeps the request rows the middleware writes.
#[derive(Clone, Default)]
struct RecordingRepo {
    entries: Arc<Mutex<Vec<CreateAuditLogEntry>>>,
}

impl AuditLogRepository for RecordingRepo {
    async fn datastore_now(&self) -> AxiamResult<chrono::DateTime<chrono::Utc>> {
        Ok(chrono::Utc::now())
    }
    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            actor_id: input.actor_id,
            actor_type: input.actor_type.clone(),
            action: input.action.clone(),
            resource_id: input.resource_id,
            outcome: input.outcome.clone(),
            ip_address: input.ip_address.clone(),
            metadata: input.metadata.clone().unwrap_or(serde_json::Value::Null),
            timestamp: chrono::Utc::now(),
        };
        self.entries.lock().unwrap().push(input);
        Ok(entry)
    }
    async fn list(
        &self,
        _: Uuid,
        _: AuditLogFilter,
        _: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn list_system(
        &self,
        _: AuditLogFilter,
        _: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn get_by_ids(&self, _: Uuid, _: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!()
    }
    async fn pseudonymize_actor(&self, _: Uuid, _: Uuid, _: &str) -> AxiamResult<u64> {
        unimplemented!()
    }
    async fn prune_older_than(&self, _: chrono::DateTime<chrono::Utc>) -> AxiamResult<u64> {
        unimplemented!()
    }
}

impl RecordingRepo {
    /// The one request row, once the middleware's worker has written it.
    async fn the_row(&self) -> CreateAuditLogEntry {
        for _ in 0..200 {
            if let Some(row) = self.entries.lock().unwrap().first().cloned() {
                return row;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the request row was never written");
    }
}

/// A resolver that accepts exactly one handle, bound to `principal`.
struct StubResolver {
    handle: String,
    principal: ScimTokenPrincipal,
    resolved: Arc<AtomicUsize>,
}

impl ScimTokenResolver for StubResolver {
    fn resolve<'a>(
        &'a self,
        raw_token: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<ScimTokenPrincipal>> + Send + 'a>>
    {
        self.resolved.fetch_add(1, Ordering::SeqCst);
        let hit = raw_token == self.handle;
        let principal = self.principal;
        Box::pin(async move { hit.then_some(principal) })
    }

    fn touch<'a>(
        &'a self,
        _tenant_id: Uuid,
        _token_id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    org_id: Uuid,
    tenant_id: Uuid,
    /// The provisioning token's user, holding `scim:provision`.
    provisioner: Uuid,
    /// The cookie's user, a different account.
    cookie_user: Uuid,
    handle: String,
}

impl Fixture {
    async fn new() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "R112-08 Org".into(),
                slug: generated("org-"),
                metadata: None,
            })
            .await
            .unwrap();
        let tenant = SurrealTenantRepository::new(db.clone())
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "R112-08 Tenant".into(),
                slug: generated("tenant-"),
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
        let provisioner = user_with_role(&db, tenant.id, "admin").await;
        let cookie_user = user_with_role(&db, tenant.id, "admin").await;
        Self {
            db,
            auth: test_auth_config(),
            org_id: org.id,
            tenant_id: tenant.id,
            provisioner,
            cookie_user,
            handle: generated(SCIM_TOKEN_PREFIX),
        }
    }

    fn cookie(&self) -> Cookie<'static> {
        let jwt = issue_access_token(
            self.cookie_user,
            self.tenant_id,
            self.org_id,
            &[],
            &self.auth,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap();
        Cookie::new(axiam_auth::carrier::ACCESS_COOKIE, jwt)
    }

    /// Send `GET /scim/v2/Users` with `authorization` and, if asked, the
    /// cookie; returns the status, the request row, and how many times the
    /// resolver was asked.
    async fn send(
        &self,
        authorization: String,
        with_cookie: bool,
    ) -> (u16, CreateAuditLogEntry, usize) {
        let repo = RecordingRepo::default();
        let resolved = Arc::new(AtomicUsize::new(0));
        let resolver: Arc<dyn ScimTokenResolver> = Arc::new(StubResolver {
            handle: self.handle.clone(),
            principal: ScimTokenPrincipal {
                token_id: Uuid::new_v4(),
                user_id: self.provisioner,
                tenant_id: self.tenant_id,
            },
            resolved: Arc::clone(&resolved),
        });
        let authz: Arc<dyn AuthzChecker> = Arc::new(AuthorizationEngine::new(
            SurrealRoleRepository::new(self.db.clone()),
            SurrealPermissionRepository::new(self.db.clone()),
            SurrealResourceRepository::new(self.db.clone()),
            SurrealScopeRepository::new(self.db.clone()),
            SurrealGroupRepository::new(self.db.clone()),
        ));
        let app = test::init_service(
            App::new()
                .wrap(AuditMiddleware::spawn(repo.clone()))
                .app_data(web::Data::new(self.auth.clone()))
                .app_data(web::Data::new(authz))
                .app_data(web::Data::new(resolver))
                .app_data(web::Data::new(AppState::for_test(
                    self.db.clone(),
                    self.auth.clone(),
                )))
                .configure(axiam_scim::scim_routes::<TestDb>),
        )
        .await;
        let mut req = test::TestRequest::get()
            .uri("/scim/v2/Users")
            .peer_addr("203.0.113.9:5000".parse().unwrap())
            .insert_header(("Authorization", authorization));
        if with_cookie {
            req = req.cookie(self.cookie());
        }
        let status = test::call_service(&app, req.to_request())
            .await
            .status()
            .as_u16();
        (
            status,
            repo.the_row().await,
            resolved.load(Ordering::SeqCst),
        )
    }
}

async fn user_with_role(db: &Surreal<TestDb>, tenant_id: Uuid, role_name: &str) -> Uuid {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: generated("u-"),
            email: format!("{}@example.com", generated("u-")),
            password: generated("pw-"),
            metadata: None,
        })
        .await
        .unwrap();
    users
        .update(
            tenant_id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let roles = SurrealRoleRepository::new(db.clone());
    let role = roles
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 1000,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|r| r.name == role_name)
        .expect("the role is seeded");
    roles
        .assign_to_user(tenant_id, user.id, role.id, AssignmentScope::global())
        .await
        .unwrap();
    user.id
}

fn authenticated(row: &CreateAuditLogEntry) -> bool {
    row.metadata.as_ref().expect("the row has metadata")["authenticated"]
        .as_bool()
        .expect("`authenticated` is a boolean")
}

/// A cookie for X beside a valid provisioning token: refused as ambiguous
/// before the token is resolved, and the row (which names X, the cookie's
/// user, by the carrier rule) says `authenticated: false`.
#[actix_rt::test]
async fn a_cookie_beside_a_valid_provisioning_token_is_refused_as_ambiguous() {
    let f = Fixture::new().await;
    let (status, row, resolved) = f.send(format!("Bearer {}", f.handle), true).await;
    assert_eq!(status, 401);
    assert_eq!(resolved, 0, "the token must not be resolved");
    assert_eq!(row.actor_id, f.cookie_user);
    assert!(
        !authenticated(&row),
        "a refused request must not be recorded as authenticated"
    );
}

/// A cookie for X beside an invalid provisioning token: refused, and the row
/// says `authenticated: false` although the cookie's signature verifies.
#[actix_rt::test]
async fn a_cookie_beside_an_invalid_provisioning_token_is_recorded_unauthenticated() {
    let f = Fixture::new().await;
    let wrong = generated(SCIM_TOKEN_PREFIX);
    let (status, row, _) = f.send(format!("Bearer {wrong}"), true).await;
    assert_eq!(status, 401);
    assert_eq!(row.actor_id, f.cookie_user);
    assert!(!authenticated(&row));
}

/// The token branch alone is unchanged, and the scheme is matched without
/// regard to case, as the carrier rule matches it.
#[actix_rt::test]
async fn a_provisioning_token_alone_is_served_in_any_scheme_case() {
    let f = Fixture::new().await;
    for scheme in ["Bearer", "bearer", "BEARER"] {
        let (status, _, resolved) = f.send(format!("{scheme} {}", f.handle), false).await;
        assert_eq!(status, 200, "scheme {scheme}");
        assert_eq!(resolved, 1, "scheme {scheme}");
    }
}

/// A refused provisioning token with no cookie leaves the verdict too: the
/// row is `authenticated: false` and names no actor.
#[actix_rt::test]
async fn a_refused_provisioning_token_is_recorded_unauthenticated() {
    let f = Fixture::new().await;
    let wrong = generated(SCIM_TOKEN_PREFIX);
    let (status, row, resolved) = f.send(format!("Bearer {wrong}"), false).await;
    assert_eq!(status, 401);
    assert_eq!(resolved, 1);
    assert_eq!(row.actor_id, Uuid::nil());
    assert!(!authenticated(&row));
}
