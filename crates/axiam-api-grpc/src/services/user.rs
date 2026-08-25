//! UserService gRPC implementation.

use std::sync::Arc;
use std::time::Duration;

use axiam_auth::config::AuthConfig;
use axiam_auth::crypto_gate::acquire_hash_permit;
use axiam_auth::password;
use axiam_auth::token::ValidatedClaims;
use axiam_core::error::AxiamError;
use axiam_core::models::user::UserStatus;
use axiam_core::repository::UserRepository;
use chrono::Utc;
use secrecy::ExposeSecret;
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::proto::user_service_server::UserService;
use crate::proto::{
    GetUserRequest, UserResponse, ValidateCredentialsRequest, ValidateCredentialsResponse,
};

pub struct UserServiceImpl<U: UserRepository> {
    user_repo: U,
    auth_config: AuthConfig,
    /// The **process-wide** Argon2id gate (B1), shared by `Arc` with the REST
    /// composition root's `AppState::crypto_semaphore`. Not optional and not
    /// built here on purpose: a semaphore constructed inside this service
    /// would bound gRPC in isolation while letting REST + gRPC together
    /// exceed the memory bound the permit count exists to enforce.
    crypto_semaphore: Arc<Semaphore>,
    /// Where the tenant's `max_failed_login_attempts` and backoff come from.
    ///
    /// Held as a trait object rather than as two more repository type
    /// parameters: this service is generic over `U: UserRepository` alone, and
    /// threading a settings repo and a tenant repo through that signature for
    /// one field would reach every call site and every test double.
    ///
    /// Before this existed, `validate_credentials` metered against the
    /// deployment-wide `AuthConfig` while an administrator's organization-level
    /// threshold sat in the database unread — so lowering the threshold in the
    /// admin UI changed nothing on this path.
    lockout_policy: Arc<dyn axiam_auth::lockout::LockoutPolicySource>,
}

impl<U: UserRepository> UserServiceImpl<U> {
    /// `crypto_semaphore` MUST be a clone of the one `Arc<Semaphore>` built at
    /// the composition root (`axiam-server`'s `main`), the same handle
    /// `AppState` holds — see the field docs.
    ///
    /// `lockout_policy` should be a
    /// [`axiam_auth::lockout::SettingsLockoutPolicy`] over the same settings
    /// and tenant repositories REST's login handler reads, so both transports
    /// lock accounts on the same numbers. [`Self::with_static_lockout_policy`]
    /// is the deployment-default shorthand.
    pub fn new(
        user_repo: U,
        auth_config: AuthConfig,
        crypto_semaphore: Arc<Semaphore>,
        lockout_policy: Arc<dyn axiam_auth::lockout::LockoutPolicySource>,
    ) -> Self {
        Self {
            user_repo,
            auth_config,
            crypto_semaphore,
            lockout_policy,
        }
    }

    /// Build with the deployment-wide lockout defaults, for a composition root
    /// with no settings store to consult (and for tests).
    pub fn with_static_lockout_policy(
        user_repo: U,
        auth_config: AuthConfig,
        crypto_semaphore: Arc<Semaphore>,
    ) -> Self {
        let policy = axiam_auth::lockout::policy_from_config(&auth_config);
        Self::new(
            user_repo,
            auth_config,
            crypto_semaphore,
            Arc::new(axiam_auth::lockout::StaticLockoutPolicy(policy)),
        )
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
        UserStatus::Deleted => "deleted".into(),
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

        // Verify password — CPU-bound Argon2id, gated and offloaded exactly as
        // `AuthService::login` does it (axiam-auth/src/service.rs, CQ-B02/B1).
        //
        // Both halves are load-bearing, and this handler had NEITHER until the
        // `grpc_admin_validate` benchmark cell exposed it (~44% INTERNAL at 50
        // VUs, identically across all three TLS profiles):
        //
        //   - The permit bounds peak memory. Each verify allocates a ~19 MiB
        //     arena; 50 concurrent is ~970 MiB against a 1024 MiB cap (the
        //     arithmetic in `AuthConfig::max_concurrent_hashes`'s docs). Without
        //     acquiring here, `AXIAM__AUTH__MAX_CONCURRENT_HASHES` bounded REST
        //     only, and this RPC — an online-password-guessing surface — was the
        //     one credential path that could ignore it.
        //   - `spawn_blocking` keeps the ~34 ms verify off the tonic runtime
        //     threads. Run inline, it starves the reactor that every other task
        //     on this runtime (including the datastore client this handler just
        //     used) needs to make progress.
        //
        // Note this is NOT a substitute for the `grpc_admin` rate-limit ceiling
        // (middleware/rate_limit.rs's `DEFAULT_ADMIN_PER_SEC`): that ceiling
        // bounds guessing *breadth* per IP, this gate bounds *concurrency* per
        // process. The benchmark neutralizes the former, which is precisely why
        // it could reach the missing latter.
        let _permit = acquire_hash_permit(
            &self.crypto_semaphore,
            Duration::from_secs(self.auth_config.hash_acquire_timeout_secs),
        )
        .await
        .map_err(|e| match e {
            // A saturated hash gate is transient server capacity, not a client
            // quota violation — mirror REST's 503 with UNAVAILABLE rather than
            // RESOURCE_EXHAUSTED, which this listener already uses for
            // rate-limit rejections (middleware/rate_limit.rs). Keeping the two
            // distinct is what lets a caller (and the benchmark) tell "you sent
            // too much" apart from "the server is at capacity".
            AxiamError::ServiceUnavailable(msg) => Status::unavailable(msg),
            other => Status::internal(other.to_string()),
        })?;
        let pw_owned = req.password.clone();
        let hash_owned = user.password_hash.clone();
        let pepper_owned = self.auth_config.pepper.clone();
        let valid = tokio::task::spawn_blocking(move || {
            password::verify_password(
                &pw_owned,
                &hash_owned,
                pepper_owned.as_ref().map(|p| p.expose_secret()),
            )
        })
        .await
        .map_err(|e| Status::internal(format!("spawn_blocking join error: {e}")))?
        .map_err(|e| Status::internal(e.to_string()))?;
        // Release the permit before the lockout write below: `record_failed_login`
        // is a datastore round-trip, not an Argon2id operation, and holding a
        // scarce hash permit across it would shrink effective verify concurrency
        // to the datastore's latency.
        drop(_permit);

        if valid {
            Ok(Response::new(ValidateCredentialsResponse {
                valid: true,
                user_id: user.id.to_string(),
            }))
        } else {
            // SEC-026b / D-06: meter every failed credential check via the
            // shared lockout helper — the single source of truth for
            // failed-attempt accrual, no unmetered credential-check path.
            let policy = self.lockout_policy.policy_for(claims_tenant_id).await;
            axiam_auth::lockout::record_failed_login(
                &self.user_repo,
                &policy,
                claims_tenant_id,
                &user,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
            Ok(invalid)
        }
    }
}
