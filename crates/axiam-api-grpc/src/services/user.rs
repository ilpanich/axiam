//! UserService gRPC implementation.

use axiam_auth::config::AuthConfig;
use axiam_auth::password;
use axiam_auth::token::ValidatedClaims;
use axiam_core::error::AxiamError;
use axiam_core::models::user::UserStatus;
use axiam_core::repository::UserRepository;
use chrono::Utc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::proto::user_service_server::UserService;
use crate::proto::{
    GetUserRequest, UserResponse, ValidateCredentialsRequest, ValidateCredentialsResponse,
};

pub struct UserServiceImpl<U: UserRepository> {
    user_repo: U,
    auth_config: AuthConfig,
}

impl<U: UserRepository> UserServiceImpl<U> {
    pub fn new(user_repo: U, auth_config: AuthConfig) -> Self {
        Self {
            user_repo,
            auth_config,
        }
    }
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Status> {
    value
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument(format!("invalid {field}")))
}

fn status_to_string(status: &UserStatus) -> String {
    match status {
        UserStatus::Active => "active".into(),
        UserStatus::Inactive => "inactive".into(),
        UserStatus::Locked => "locked".into(),
        UserStatus::PendingVerification => "pending_verification".into(),
        // D-05: anonymized users have their account permanently disabled.
        UserStatus::Anonymized => "anonymized".into(),
    }
}

fn axiam_err_to_status(err: AxiamError) -> Status {
    match &err {
        AxiamError::NotFound { .. } => Status::not_found(err.to_string()),
        _ => Status::internal(err.to_string()),
    }
}

#[tonic::async_trait]
impl<U: UserRepository + 'static> UserService for UserServiceImpl<U> {
    async fn get_user(
        &self,
        request: Request<GetUserRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        // SEC-003: derive authoritative identity from verified JWT claims;
        // never trust the request body's tenant_id outright.
        let claims = request
            .extensions()
            .get::<ValidatedClaims>()
            .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
            .clone();
        let claims_tenant_id = parse_uuid(&claims.0.tenant_id, "claims.tenant_id")?;

        let req = request.into_inner();
        let tenant_id = parse_uuid(&req.tenant_id, "tenant_id")?;
        let user_id = parse_uuid(&req.user_id, "user_id")?;

        // Cross-validate body tenant_id against verified claims (reject on mismatch).
        if tenant_id != claims_tenant_id {
            return Err(Status::permission_denied(
                "tenant_id mismatch: body does not match token claims",
            ));
        }

        let user = self
            .user_repo
            .get_by_id(claims_tenant_id, user_id)
            .await
            .map_err(axiam_err_to_status)?;

        Ok(Response::new(UserResponse {
            id: user.id.to_string(),
            tenant_id: user.tenant_id.to_string(),
            username: user.username,
            email: user.email,
            status: status_to_string(&user.status),
            created_at: user.created_at.to_rfc3339(),
            updated_at: user.updated_at.to_rfc3339(),
        }))
    }

    async fn validate_credentials(
        &self,
        request: Request<ValidateCredentialsRequest>,
    ) -> Result<Response<ValidateCredentialsResponse>, Status> {
        // SEC-003: derive authoritative identity from verified JWT claims;
        // never trust the request body's tenant_id outright.
        let claims = request
            .extensions()
            .get::<ValidatedClaims>()
            .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
            .clone();
        let claims_tenant_id = parse_uuid(&claims.0.tenant_id, "claims.tenant_id")?;

        let req = request.into_inner();
        let tenant_id = parse_uuid(&req.tenant_id, "tenant_id")?;

        // Cross-validate body tenant_id against verified claims (reject on mismatch,
        // fail-closed — no cross-tenant credential oracle per 23-RESEARCH.md
        // Open Question 1 / Assumption A1).
        if tenant_id != claims_tenant_id {
            return Err(Status::permission_denied(
                "tenant_id mismatch: body does not match token claims",
            ));
        }

        let invalid = Response::new(ValidateCredentialsResponse {
            valid: false,
            user_id: String::new(),
        });

        // Look up user by username, then by email.
        let user = match self
            .user_repo
            .get_by_username(claims_tenant_id, &req.username_or_email)
            .await
        {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => {
                match self
                    .user_repo
                    .get_by_email(claims_tenant_id, &req.username_or_email)
                    .await
                {
                    Ok(u) => u,
                    Err(AxiamError::NotFound { .. }) => return Ok(invalid),
                    Err(e) => return Err(Status::internal(e.to_string())),
                }
            }
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        // Enforce lockout (brute force protection).
        if let Some(locked_until) = user.locked_until
            && locked_until > Utc::now()
        {
            return Ok(invalid);
        }

        // Enforce account status (only Active accounts can authenticate).
        if user.status != UserStatus::Active {
            return Ok(invalid);
        }

        // Verify password.
        let valid = password::verify_password(
            &req.password,
            &user.password_hash,
            self.auth_config.pepper.as_deref(),
        )
        .map_err(|e| Status::internal(e.to_string()))?;

        if valid {
            Ok(Response::new(ValidateCredentialsResponse {
                valid: true,
                user_id: user.id.to_string(),
            }))
        } else {
            // SEC-026b / D-06: meter every failed credential check via the
            // shared lockout helper — the single source of truth for
            // failed-attempt accrual, no unmetered credential-check path.
            axiam_auth::lockout::record_failed_login(
                &self.user_repo,
                &self.auth_config,
                claims_tenant_id,
                &user,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
            Ok(invalid)
        }
    }
}
