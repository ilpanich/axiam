//! User management endpoints (tenant-scoped via JWT).

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::policy::check_complexity;
use axiam_core::error::AxiamError;
use axiam_core::models::settings::PasswordPolicy;
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{PaginatedResult, Pagination, UserRepository};
use axiam_db::SurrealUserRepository;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission, is_own_resource};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Input validation helpers (CQ-B26)
// -----------------------------------------------------------------------

/// Validate email format: must contain exactly one '@' with non-empty local
/// and domain parts, and the domain must contain at least one '.'.
fn validate_email_format(email: &str) -> Result<(), AxiamError> {
    let mut parts = email.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err(AxiamError::Validation {
            message: "email must be a valid email address".into(),
        });
    }
    Ok(())
}

/// Minimum password policy applied at user-create time (CQ-B26).
///
/// The tenant's full policy (HIBP, history) is enforced by AuthService
/// at login.  This guard ensures obviously weak passwords are rejected
/// at the API boundary without requiring the full policy infrastructure.
const MINIMUM_PASSWORD_POLICY: PasswordPolicy = PasswordPolicy {
    min_length: 8,
    require_uppercase: false,
    require_lowercase: false,
    require_digits: false,
    require_symbols: false,
    password_history_count: 0,
    hibp_check_enabled: false,
};

// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub status: Option<UserStatus>,
    pub metadata: Option<serde_json::Value>,
}

/// Public-safe user representation (no password_hash, no mfa_secret).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    pub status: UserStatus,
    pub mfa_enabled: bool,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Number of consecutive failed login attempts.
    pub failed_login_attempts: u32,
    /// Timestamp until which the account is locked, if any.
    pub locked_until: Option<DateTime<Utc>>,
    /// Whether the account is currently locked (locked_until is in the future).
    pub is_locked: bool,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        let is_locked = u
            .locked_until
            .map(|t| t > chrono::Utc::now())
            .unwrap_or(false);
        Self {
            id: u.id,
            tenant_id: u.tenant_id,
            username: u.username,
            email: u.email,
            status: u.status,
            mfa_enabled: u.mfa_enabled,
            metadata: u.metadata,
            created_at: u.created_at,
            updated_at: u.updated_at,
            failed_login_attempts: u.failed_login_attempts,
            locked_until: u.locked_until,
            is_locked,
        }
    }
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /api/v1/users`
///
/// Creates a user and atomically records a `terms_of_service` consent row
/// (REQ-8 / Art. 7 proof of consent).  IP address and User-Agent are
/// captured for the consent record.
#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = UserResponse),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection>(
    http_req: HttpRequest,
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    body: web::Json<CreateUserRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("users:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();

    // CQ-B26: validate email format and password complexity before insert.
    validate_email_format(&req.email)?;
    let pw_violations = check_complexity(&req.password, &MINIMUM_PASSWORD_POLICY);
    if !pw_violations.is_empty() {
        let details: Vec<String> = pw_violations
            .iter()
            .map(|v| v.to_string())
            .collect();
        return Err(AxiamApiError(AxiamError::PasswordPolicy {
            message: details.join("; "),
        }));
    }

    let input = CreateUser {
        tenant_id: user.tenant_id,
        username: req.username,
        email: req.email,
        password: req.password,
        metadata: req.metadata,
    };

    // Capture IP and User-Agent for the Art. 7 proof-of-consent record.
    let ip_address = http_req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string());
    let user_agent = http_req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // The user and its terms_of_service consent are written in one transaction:
    // a consent failure rolls back user creation, so a user can never exist
    // without proof-of-consent (REQ-8, threat T-5-consent-gap).
    let created = repo
        .create_with_consent(input, "terms_of_service", "current", ip_address, user_agent)
        .await?;

    Ok(HttpResponse::Created().json(UserResponse::from(created)))
}

/// `GET /api/v1/users`
#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "users",
    params(Pagination),
    responses(
        (status = 200, description = "List of users", body = inline(PaginatedResult<UserResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("users:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = repo.list(user.tenant_id, query.into_inner()).await?;
    let items: Vec<UserResponse> = result.items.into_iter().map(UserResponse::from).collect();
    Ok(HttpResponse::Ok().json(PaginatedResult {
        items,
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    }))
}

/// `GET /api/v1/users/{user_id}`
#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}",
    tag = "users",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User found", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let target_id = path.into_inner();
    if !is_own_resource(&user, target_id) {
        RequirePermission::new("users:get", Uuid::nil())
            .check(&user, authz.get_ref().as_ref())
            .await?;
    }
    let target = repo.get_by_id(user.tenant_id, target_id).await?;
    Ok(HttpResponse::Ok().json(UserResponse::from(target)))
}

/// `PUT /api/v1/users/{user_id}`
#[utoipa::path(
    put,
    path = "/api/v1/users/{user_id}",
    tag = "users",
    params(("user_id" = Uuid, Path, description = "User ID")),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateUserRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let target_id = path.into_inner();
    if !is_own_resource(&user, target_id) {
        RequirePermission::new("users:update", Uuid::nil())
            .check(&user, authz.get_ref().as_ref())
            .await?;
    }
    let req = body.into_inner();
    let input = UpdateUser {
        username: req.username,
        email: req.email,
        status: req.status,
        metadata: req.metadata,
        ..Default::default()
    };
    let updated = repo.update(user.tenant_id, target_id, input).await?;
    Ok(HttpResponse::Ok().json(UserResponse::from(updated)))
}

/// `DELETE /api/v1/users/{user_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/users/{user_id}",
    tag = "users",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 204, description = "User deleted"),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("users:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    repo.delete(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/users/{user_id}/unlock`
///
/// Resets a locked user account: clears `locked_until`, resets
/// `failed_login_attempts` to 0, and sets status back to `Active`.
#[utoipa::path(
    post,
    path = "/api/v1/users/{user_id}/unlock",
    tag = "users",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User unlocked", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn unlock<C: Connection>(
    auth_user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("users:admin", Uuid::nil())
        .check(&auth_user, authz.get_ref().as_ref())
        .await?;
    let user_id = path.into_inner();
    let tenant_id = auth_user.tenant_id;

    let update = UpdateUser {
        failed_login_attempts: Some(0),
        locked_until: Some(None),
        last_failed_login_at: Some(None),
        status: Some(UserStatus::Active),
        ..Default::default()
    };

    let user = repo.update(tenant_id, user_id, update).await?;
    Ok(HttpResponse::Ok().json(UserResponse::from(user)))
}

// ---------------------------------------------------------------------------
// Tests — consent at registration (REQ-8)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod consent_tests {
    use axiam_core::repository::ConsentRepository;
    use axiam_db::{SurrealConsentRepository, SurrealUserRepository};
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;
    use uuid::Uuid;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        db
    }

    /// The atomic registration path commits exactly one terms_of_service
    /// consent row alongside the new user (threat T-5-consent-gap).
    #[tokio::test]
    async fn registration_creates_consent_row() {
        let db = setup_db().await;
        let user_repo = SurrealUserRepository::new(db.clone());
        let consent_repo = SurrealConsentRepository::new(db.clone());
        let tenant_id = Uuid::new_v4();

        // Atomic user + consent creation — the handler's real path.
        let user = user_repo
            .create_with_consent(
                axiam_core::models::user::CreateUser {
                    tenant_id,
                    username: "testuser".to_string(),
                    email: "test@example.com".to_string(),
                    password: "Test1234!".to_string(),
                    metadata: None,
                },
                "terms_of_service",
                "current",
                Some("127.0.0.1".to_string()),
                Some("test-agent/1.0".to_string()),
            )
            .await
            .unwrap();

        // The consent row must be committed with user_id == the new user's id.
        let consents = consent_repo.list_by_user(tenant_id, user.id).await.unwrap();
        assert_eq!(consents.len(), 1, "expected exactly one consent row");
        assert_eq!(consents[0].consent_type, "terms_of_service");
        assert_eq!(consents[0].version, "current");
        assert_eq!(consents[0].user_id, user.id);
        assert_eq!(consents[0].tenant_id, tenant_id);
        assert_eq!(consents[0].ip_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(consents[0].user_agent.as_deref(), Some("test-agent/1.0"));
    }
}
