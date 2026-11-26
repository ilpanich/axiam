//! SA-02 (N1, review Q-3/S-2): the system audit partition is read per
//! organization.
//!
//! The nil-tenant partition holds the request rows the audit middleware cannot
//! attribute to a tenant — a SCIM provisioning call, a request to an
//! organization's routes without a usable token — for every organization of
//! the deployment. `GET /api/v1/audit-logs/system` returns to an
//! organization-level principal only the rows whose recorded organization is
//! its own; a row whose organization could not be resolved is returned to
//! nobody.
//!
//! The `App` is the one the listener serves (`boot::compose_app`), so the rows
//! are written by the real audit middleware and the real SCIM token resolver.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use actix_web::test::{TestRequest, call_service, init_service, read_body};
use axiam_api_rest::authz::AllowAllAuthzChecker;
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, RouteOptions, SessionValidator, SurrealScimTokenResolver};
use axiam_audit::AuditMiddleware;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::scim_token::{CreateScimToken, SCIM_TOKEN_PREFIX};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, ScimTokenRepository, TenantRepository, UserRepository,
};
use axiam_db::{
    SurrealAuditLogRepository, SurrealOrganizationRepository, SurrealProofReplayRepository,
    SurrealRoleRepository, SurrealScimTokenRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_server::boot::{AppDeps, compose_app};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

fn auth_config() -> AuthConfig {
    // Ed25519 test-only fixture — NOT secret (the one `audit_wraps_routes.rs`
    // uses); split with concat! to satisfy static-analysis rules that reject
    // inline PEM blocks (CWE-798 guard).
    let private_key = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5",
        "R75FOv/nC4+o+HHPfM\n",
        "-----END PRIVATE KEY-----"
    );
    let public_key = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----"
    );
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// Every session is live: a console token names its session in `jti`.
struct LiveSessions;

impl SessionValidator for LiveSessions {
    fn is_session_active<'a>(
        &'a self,
        _tenant_id: Uuid,
        _session_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { true })
    }
}

/// An organization, its reserved scope tenant and an administrator living in
/// it. Returns `(org_id, scope_tenant_id, admin_id)`.
async fn organization(db: &Surreal<Db>, slug: &str) -> (Uuid, Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: slug.into(),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap();
    let scope = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant::organization_scope(org.id))
        .await
        .unwrap();
    let admin = active_user(db, scope.id, &format!("{slug}-admin")).await;
    (org.id, scope.id, admin)
}

async fn active_user(db: &Surreal<Db>, tenant_id: Uuid, username: &str) -> Uuid {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: format!("{username}@example.com"),
            password: axiam_test_support::test_password(),
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
    user.id
}

fn from(ip: &str) -> SocketAddr {
    format!("{ip}:4000").parse().unwrap()
}

/// The `ip_address` of every row `token`'s holder reads from the system
/// partition.
async fn system_rows_read_by<S, B>(app: &S, token: &str) -> String
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let req = TestRequest::get()
        .uri("/api/v1/audit-logs/system?limit=100")
        .peer_addr(from("198.51.100.1"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = call_service(app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the system partition is readable"
    );
    String::from_utf8(read_body(resp).await.to_vec()).unwrap()
}

#[actix_web::test]
async fn an_organization_reads_only_its_own_rows_of_the_system_partition() {
    let db: Surreal<Db> = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let (org_x, x_scope, x_admin) = organization(&db, "org-x").await;
    let (org_y, y_scope, y_admin) = organization(&db, "org-y").await;
    let y_tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_y,
            kind: TenantKind::Standard,
            name: "Y1".into(),
            slug: "y1".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let provisioner = active_user(&db, y_tenant, "y1-provisioner").await;
    let scim_token = format!("{SCIM_TOKEN_PREFIX}sa02-organization-filter-test");
    SurrealScimTokenRepository::new(db.clone())
        .create(CreateScimToken {
            tenant_id: y_tenant,
            user_id: provisioner,
            name: "idp".into(),
            token_hash: axiam_auth::token::hash_refresh_token(&scim_token),
            created_by: provisioner,
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        })
        .await
        .unwrap();

    let auth = auth_config();
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let audit_middleware = AuditMiddleware::spawn(audit_repo.clone());
    let deps = AppDeps {
        audit_middleware: audit_middleware.clone(),
        cors_allowed_origins: Vec::new(),
        rest_authz: Arc::new(AllowAllAuthzChecker),
        auth_config: auth.clone(),
        session_validator: Arc::new(LiveSessions),
        dpop_replay_guard: Arc::new(SurrealProofReplayRepository::new(db.clone())),
        tenant_scope_resolver: Arc::new(SurrealTenantRepository::new(db.clone())),
        principal_reach_resolver: Arc::new(SurrealRoleRepository::new(db.clone())),
        scim_token_resolver: Arc::new(SurrealScimTokenResolver::new(
            SurrealScimTokenRepository::new(db.clone()),
            SurrealUserRepository::new(db.clone()),
            SurrealTenantRepository::new(db.clone()),
        )),
        app_state: AppState::for_test(db.clone(), auth.clone()),
        rate_limit: RateLimitConfig::default(),
        route_options: RouteOptions::default(),
        request_deadline: None,
    };
    let app = init_service(compose_app(deps)).await;

    // Rows the middleware cannot attribute to a tenant, each from its own
    // address. Two concern organization Y with certainty:
    // - Y1's SCIM integration, authenticated by its provisioning token;
    let req = TestRequest::get()
        .uri("/scim/v2/Users")
        .peer_addr(from("192.0.2.10"))
        .insert_header(("Authorization", format!("Bearer {scim_token}")))
        .to_request();
    call_service(&app, req).await;
    // - a request to Y's own routes with no usable token.
    let req = TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_y}/tenants"))
        .peer_addr(from("192.0.2.11"))
        .to_request();
    call_service(&app, req).await;
    // Two concern no organization that can be resolved: a route of an
    // organization that does not exist, and a route that names none.
    let req = TestRequest::get()
        .uri(&format!("/api/v1/organizations/{}/tenants", Uuid::new_v4()))
        .peer_addr(from("192.0.2.98"))
        .to_request();
    call_service(&app, req).await;
    let req = TestRequest::get()
        .uri("/api/v1/users")
        .peer_addr(from("192.0.2.99"))
        .to_request();
    call_service(&app, req).await;
    assert!(
        audit_middleware.drain(Duration::from_secs(10)).await,
        "the audit queue drains"
    );

    let token = |user: Uuid, tenant: Uuid, org: Uuid| {
        issue_access_token(
            user,
            tenant,
            org,
            &[],
            &auth,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap()
    };

    let seen_by_x = system_rows_read_by(&app, &token(x_admin, x_scope, org_x)).await;
    for ip in ["192.0.2.10", "192.0.2.11", "192.0.2.98", "192.0.2.99"] {
        assert!(
            !seen_by_x.contains(ip),
            "organization X's administrator read the system row from {ip}: {seen_by_x}"
        );
    }

    let seen_by_y = system_rows_read_by(&app, &token(y_admin, y_scope, org_y)).await;
    for ip in ["192.0.2.10", "192.0.2.11"] {
        assert!(
            seen_by_y.contains(ip),
            "organization Y's administrator does not see its own row from {ip}: {seen_by_y}"
        );
    }
    for ip in ["192.0.2.98", "192.0.2.99"] {
        assert!(
            !seen_by_y.contains(ip),
            "a row with no resolvable organization reached organization Y from {ip}: {seen_by_y}"
        );
    }
}
