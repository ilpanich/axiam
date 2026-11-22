//! UserService gRPC implementation.
//!
//! # Authorization (SA-12, N4, decision D-2)
//!
//! The `AuthInterceptor` in front of this service authenticates any
//! `axiam:user` or `axiam:m2m` token of the tenant; it authorizes nothing. So
//! each RPC decides for itself, against the same [`AuthorizationEngine`] REST
//! uses:
//!
//! - **`GetUser`** answers a caller reading its own record (`sub ==
//!   user_id`), and otherwise requires [`GET_USER_PERMISSION`] — the rule of
//!   REST's `GET /api/v1/users/{user_id}`, which exempts `is_own_resource`
//!   and otherwise requires `users:get`.
//! - **`ValidateCredentials`** is a password oracle over every account in the
//!   tenant, so it is restricted to a **service-account principal** (`aud =
//!   axiam:m2m` *and* `sub_kind = service_account`, the definition REST's
//!   machine-principal extractor uses) holding
//!   [`VALIDATE_CREDENTIALS_PERMISSION`], which the seeder gives to no role.
//!   Every answer is audited as [`CREDENTIALS_VALIDATED_ACTION`] — the
//!   `PERMISSION_DENIED` refusals of a caller that is not such a principal
//!   included (outcome `Denied`).
//!
//! Before this, the only check was that the body's `tenant_id` matched the
//! token's, so any same-tenant user token read any user's username, email and
//! status, and could drive any account's lockout counter.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axiam_auth::config::AuthConfig;
use axiam_auth::crypto_gate::acquire_hash_permit;
use axiam_auth::password;
use axiam_auth::token::{AUD_M2M, SubjectKind, ValidatedClaims};
use axiam_authz::AuthorizationEngine;
use axiam_authz::types::{AccessRequest, SubjectScope};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{
    AuditLogRepository, GroupRepository, PermissionRepository, ResourceRepository, RoleRepository,
    ScopeRepository, UserRepository,
};
use secrecy::ExposeSecret;
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::proto::user_service_server::UserService;
use crate::proto::{
    GetUserRequest, UserResponse, ValidateCredentialsRequest, ValidateCredentialsResponse,
};

/// The permission `GetUser` requires to read a user other than the caller.
/// The same action string REST's `GET /api/v1/users/{user_id}` checks.
pub const GET_USER_PERMISSION: &str = "users:get";

/// The permission `ValidateCredentials` requires of its (service-account)
/// caller. Registered in `axiam_api_rest::permissions::PERMISSION_REGISTRY`
/// and seeded to **no** role (`axiam_db::seeder`): an operator grants it to the
/// one service account that needs it.
pub const VALIDATE_CREDENTIALS_PERMISSION: &str = "users:validate_credentials";

/// The audit action every `ValidateCredentials` answer is recorded under —
/// `Success` for a valid credential, `Failure` for a refused credential,
/// `Denied` for a caller refused `PERMISSION_DENIED` before any lookup.
pub const CREDENTIALS_VALIDATED_ACTION: &str = "auth.credentials_validated";

/// A boxed, sendable future — the shape the two object-safe seams below
/// return.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The authorization decision `UserServiceImpl` needs: may `subject_id` of
/// `tenant_id` perform `action`, globally (resource nil — REST's
/// `RequirePermission::new(action, Uuid::nil())`).
///
/// A trait object rather than five more type parameters, for the reason
/// `lockout_policy` is one: this service is generic over `U` alone, and the
/// engine's five repository parameters would reach every call site and every
/// test double. Production passes an [`AuthorizationEngine`], which implements
/// it.
pub trait UserServiceAuthorizer: Send + Sync {
    /// `Ok(())` when allowed; `PERMISSION_DENIED` when the engine denies;
    /// `INTERNAL` when it could not decide (fail closed).
    fn require<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        action: &'a str,
    ) -> BoxFuture<'a, Result<(), Status>>;
}

impl<Rl, P, Res, S, G> UserServiceAuthorizer for AuthorizationEngine<Rl, P, Res, S, G>
where
    Rl: RoleRepository + 'static,
    P: PermissionRepository + 'static,
    Res: ResourceRepository + 'static,
    S: ScopeRepository + 'static,
    G: GroupRepository + 'static,
{
    fn require<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        action: &'a str,
    ) -> BoxFuture<'a, Result<(), Status>> {
        Box::pin(async move {
            let decision = self
                .check_access(&AccessRequest {
                    tenant_id,
                    subject_scope: SubjectScope::Tenant,
                    subject_id,
                    action: action.to_string(),
                    resource_id: Uuid::nil(),
                    scope: None,
                })
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            if decision.is_allowed() {
                Ok(())
            } else {
                Err(Status::permission_denied(decision.reason().to_string()))
            }
        })
    }
}

/// Where `ValidateCredentials` writes its `auth.credentials_validated` rows.
///
/// Best effort, as every handler-written audit row on REST is: a failed append
/// is logged and does not change the answer. Every [`AuditLogRepository`] is
/// one.
pub trait CredentialAuditSink: Send + Sync {
    /// Append `entry`, logging (not returning) a failure.
    fn record(&self, entry: CreateAuditLogEntry) -> BoxFuture<'_, ()>;
}

impl<A: AuditLogRepository> CredentialAuditSink for A {
    fn record(&self, entry: CreateAuditLogEntry) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let action = entry.action.clone();
            if let Err(e) = self.append(entry).await {
                tracing::error!(error = %e, action, "failed to write a gRPC credential-check audit row");
            }
        })
    }
}

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
    /// SA-12 (N4): the per-RPC authorization decision. In production an
    /// [`AuthorizationEngine`] built like the listener's other engines (same
    /// repositories, same decision cache and invalidation broadcaster).
    authorizer: Arc<dyn UserServiceAuthorizer>,
    /// SA-12: where `ValidateCredentials` audits its answers.
    audit: Arc<dyn CredentialAuditSink>,
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
    ///
    /// `authorizer` decides `GetUser`'s and `ValidateCredentials`' permission
    /// checks; `audit` receives `ValidateCredentials`' audit rows.
    pub fn new(
        user_repo: U,
        auth_config: AuthConfig,
        crypto_semaphore: Arc<Semaphore>,
        lockout_policy: Arc<dyn axiam_auth::lockout::LockoutPolicySource>,
        authorizer: Arc<dyn UserServiceAuthorizer>,
        audit: Arc<dyn CredentialAuditSink>,
    ) -> Self {
        Self {
            user_repo,
            auth_config,
            crypto_semaphore,
            lockout_policy,
            authorizer,
            audit,
        }
    }

    /// Build with the deployment-wide lockout defaults, for a composition root
    /// with no settings store to consult (and for tests).
    pub fn with_static_lockout_policy(
        user_repo: U,
        auth_config: AuthConfig,
        crypto_semaphore: Arc<Semaphore>,
        authorizer: Arc<dyn UserServiceAuthorizer>,
        audit: Arc<dyn CredentialAuditSink>,
    ) -> Self {
        let policy = axiam_auth::lockout::policy_from_config(&auth_config);
        Self::new(
            user_repo,
            auth_config,
            crypto_semaphore,
            Arc::new(axiam_auth::lockout::StaticLockoutPolicy(policy)),
            authorizer,
            audit,
        )
    }

    /// Record one `ValidateCredentials` answer (SA-12).
    ///
    /// Every answered call writes exactly one row, whichever branch answered,
    /// so the audit write costs every outcome the same round-trip and does
    /// not tell them apart by latency. `resource_id` is the matched account,
    /// when one matched; the presented name is not recorded.
    async fn audit_credential_check(
        &self,
        tenant_id: Uuid,
        caller_id: Uuid,
        matched_user: Option<Uuid>,
        valid: bool,
        ip_address: Option<String>,
    ) {
        self.audit
            .record(CreateAuditLogEntry {
                tenant_id,
                actor_id: caller_id,
                actor_type: ActorType::ServiceAccount,
                action: CREDENTIALS_VALIDATED_ACTION.into(),
                resource_id: matched_user,
                outcome: if valid {
                    AuditOutcome::Success
                } else {
                    AuditOutcome::Failure
                },
                ip_address,
                metadata: Some(serde_json::json!({
                    "transport": "grpc",
                    "rpc": "axiam.v1.UserService/ValidateCredentials",
                })),
                organization_id: None,
            })
            .await;
    }

    /// Record one `ValidateCredentials` call refused `PERMISSION_DENIED` —
    /// not a service account, or one without the permission (QR1-13). The
    /// row names the caller and no account: nothing was looked up.
    async fn audit_credential_denial(
        &self,
        tenant_id: Uuid,
        caller_id: Uuid,
        actor_type: ActorType,
        ip_address: Option<String>,
    ) {
        self.audit
            .record(CreateAuditLogEntry {
                tenant_id,
                actor_id: caller_id,
                actor_type,
                action: CREDENTIALS_VALIDATED_ACTION.into(),
                resource_id: None,
                outcome: AuditOutcome::Denied,
                ip_address,
                metadata: Some(serde_json::json!({
                    "transport": "grpc",
                    "rpc": "axiam.v1.UserService/ValidateCredentials",
                })),
                organization_id: None,
            })
            .await;
    }
}

/// Whether `claims` name a **service account** — the machine principal
/// `ValidateCredentials` admits. The audience alone is not enough, for the
/// reason REST's `AuthenticatedPrincipal` gives: an RFC 8693 exchange can
/// narrow a *user* token to `axiam:m2m`, and that is still a user.
fn is_service_account(claims: &ValidatedClaims) -> bool {
    claims.0.aud.as_deref() == Some(AUD_M2M) && claims.0.sub_kind == SubjectKind::ServiceAccount
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
        // T-262 / R-4: a contended write is transient server state, so
        // UNAVAILABLE — which CONTRACT §2's gRPC table already maps to
        // `NetworkError`, the same place the REST 503 lands. RESOURCE_EXHAUSTED
        // is this listener's rate-limit answer and must stay distinct: "the
        // server is busy" and "you sent too much" are different instructions.
        AxiamError::WriteContention => Status::unavailable(err.to_string()),
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
        let subject_id = parse_uuid(&claims.0.sub, "claims.sub")?;

        let req = request.into_inner();
        let tenant_id = parse_uuid(&req.tenant_id, "tenant_id")?;
        let user_id = parse_uuid(&req.user_id, "user_id")?;

        // Cross-validate body tenant_id against verified claims (reject on mismatch).
        if tenant_id != claims_tenant_id {
            return Err(Status::permission_denied(
                "tenant_id mismatch: body does not match token claims",
            ));
        }

        // SA-12 (N4): the REST twin's rule. One's own record needs no grant;
        // anybody else's needs `users:get`. Decided before the read, so a
        // refused caller cannot tell an existing id from a missing one.
        if subject_id != user_id {
            self.authorizer
                .require(claims_tenant_id, subject_id, GET_USER_PERMISSION)
                .await?;
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
        let caller_id = parse_uuid(&claims.0.sub, "claims.sub")?;
        let ip_address = request.remote_addr().map(|addr| addr.ip().to_string());

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

        // SA-12 (N4, D-2): a password oracle over the whole tenant is for the
        // service that needs one, not for every holder of a tenant token. A
        // service account, and one an operator granted the permission to —
        // decided before the lookup, the hash permit and the lockout
        // accrual, so a refused caller can neither probe nor lock anyone.
        if !is_service_account(&claims) {
            self.audit_credential_denial(claims_tenant_id, caller_id, ActorType::User, ip_address)
                .await;
            return Err(Status::permission_denied(
                "ValidateCredentials is restricted to service-account (axiam:m2m) principals",
            ));
        }
        if let Err(status) = self
            .authorizer
            .require(claims_tenant_id, caller_id, VALIDATE_CREDENTIALS_PERMISSION)
            .await
        {
            if status.code() == tonic::Code::PermissionDenied {
                self.audit_credential_denial(
                    claims_tenant_id,
                    caller_id,
                    ActorType::ServiceAccount,
                    ip_address,
                )
                .await;
            }
            return Err(status);
        }

        let invalid = Response::new(ValidateCredentialsResponse {
            valid: false,
            user_id: String::new(),
        });

        // Look up user by username, then by email.
        let found = match self
            .user_repo
            .get_by_username(claims_tenant_id, &req.username_or_email)
            .await
        {
            Ok(u) => Some(u),
            Err(AxiamError::NotFound { .. }) => {
                match self
                    .user_repo
                    .get_by_email(claims_tenant_id, &req.username_or_email)
                    .await
                {
                    Ok(u) => Some(u),
                    Err(AxiamError::NotFound { .. }) => None,
                    Err(e) => return Err(Status::internal(e.to_string())),
                }
            }
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        // The refusals that need no password: an unknown name, an account
        // serving a temporary lockout, one whose status is not `Active`, and a
        // directory account (G-3, T23.3.2) — whose password is its directory's
        // to check, and this RPC has no directory client. None verifies the
        // account's local hash (a directory account's is an unusable random
        // one) and none counts a failure: the caller did not guess wrong, or
        // the account is already locked. Never a fallback to the local hash,
        // exactly as `AuthService::login` refuses one.
        let matched_user = found.as_ref().map(|user| user.id);
        let user = found.filter(|user| {
            !axiam_auth::lockout::is_locked_out(user)
                && user.status == UserStatus::Active
                && !user.is_directory_account()
        });

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
        //
        // The permit is taken BEFORE the branch on the refusals above, and each
        // of them runs one equalising verify against the dummy hash under it
        // (SEC-026, T-469): an unknown, locked, non-active or directory account
        // costs what a wrong password costs, and under saturation answers the
        // same UNAVAILABLE — so neither the latency nor the status tells an
        // existing account, or its state, to a caller holding a tenant token.
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
        let pepper_owned = self.auth_config.pepper.clone();
        let Some(user) = user else {
            tokio::task::spawn_blocking(move || {
                password::equalising_dummy_verify(pepper_owned.as_ref().map(|p| p.expose_secret()))
            })
            .await
            .map_err(|e| Status::internal(format!("spawn_blocking join error: {e}")))?;
            self.audit_credential_check(
                claims_tenant_id,
                caller_id,
                matched_user,
                false,
                ip_address,
            )
            .await;
            return Ok(invalid);
        };
        let pw_owned = req.password.clone();
        let hash_owned = user.password_hash.clone();
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
            // Item 5 of the 1.1.0 atomicity audit: the lock was checked on the
            // read above, before the verify. Guesses sent together at
            // threshold − 1 all pass that check and a wrong one may lock the
            // account meanwhile; a correct one answering `valid` after the lock
            // committed was one more guess than the policy allows. Asked again
            // now, after the verify — this RPC resets no counter, so there is
            // no lock for it to undo, only an answer to withhold.
            let admitted = self
                .user_repo
                .admit_unless_locked(claims_tenant_id, user.id, false)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            if !admitted {
                self.audit_credential_check(
                    claims_tenant_id,
                    caller_id,
                    matched_user,
                    false,
                    ip_address,
                )
                .await;
                return Ok(invalid);
            }
            self.audit_credential_check(
                claims_tenant_id,
                caller_id,
                matched_user,
                true,
                ip_address,
            )
            .await;
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
            self.audit_credential_check(
                claims_tenant_id,
                caller_id,
                matched_user,
                false,
                ip_address,
            )
            .await;
            Ok(invalid)
        }
    }
}
