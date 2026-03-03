//! UserService gRPC implementation.

use axiam_auth::config::AuthConfig;
use axiam_auth::password;
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
        let req = request.into_inner();
        let tenant_id = parse_uuid(&req.tenant_id, "tenant_id")?;
        let user_id = parse_uuid(&req.user_id, "user_id")?;

        let user = self
            .user_repo
            .get_by_id(tenant_id, user_id)
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
        let req = request.into_inner();
        let tenant_id = parse_uuid(&req.tenant_id, "tenant_id")?;

        let invalid = Response::new(ValidateCredentialsResponse {
            valid: false,
            user_id: String::new(),
        });

        // Look up user by username, then by email.
        let user = match self
            .user_repo
            .get_by_username(tenant_id, &req.username_or_email)
            .await
        {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => {
                match self
                    .user_repo
                    .get_by_email(tenant_id, &req.username_or_email)
                    .await
                {
                    Ok(u) => u,
                    Err(_) => return Ok(invalid),
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
            Ok(invalid)
        }
    }
}
