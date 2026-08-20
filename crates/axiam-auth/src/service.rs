//! Authentication service — login, logout, token refresh, and MFA.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::password_history::CreatePasswordHistoryEntry;
use axiam_core::models::reactor::{
    ReactorGate, ReactorOutcome, SharedReactorGate, events as reactor_events, noop_reactor_gate,
};
use axiam_core::models::session::CreateSession;
use axiam_core::models::settings::{MfaPolicy, PasswordPolicy};
use axiam_core::models::user::{UpdateUser, User, UserStatus};
use axiam_core::repository::{
    FederationLinkRepository, PasswordHistoryRepository, RefreshTokenRepository, SessionRepository,
    UserRepository,
};
use chrono::{Duration, Utc};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::config::AuthConfig;
use crate::crypto_gate::acquire_hash_permit;
use crate::error::AuthError;
use crate::token::AUD_USER;
use crate::{password, token, totp};

// -----------------------------------------------------------------------
// Input / output types
// -----------------------------------------------------------------------

/// Input for the login flow.
#[derive(Debug)]
pub struct LoginInput {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub username_or_email: String,
    pub password: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// Tenant-effective MFA policy — when present and `mfa_enforced` is
    /// true, users without MFA will be asked to set it up before
    /// completing login.
    pub mfa_policy: Option<MfaPolicy>,
}

/// Successful login result (no MFA required).
#[derive(Debug)]
pub struct LoginOutput {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub expires_in: u64,
}

/// Login result — full success, MFA challenge, or MFA setup required.
#[derive(Debug)]
pub enum LoginResult {
    /// Credentials valid, no MFA — tokens issued.
    Success(LoginOutput),
    /// Credentials valid, MFA required — client must call `verify_mfa`.
    MfaRequired(MfaChallengeOutput),
    /// Credentials valid, MFA enforced by policy but not yet configured
    /// — client must complete MFA enrollment using the setup token.
    MfaSetupRequired(MfaSetupOutput),
}

/// Output returned when MFA enforcement requires initial setup.
#[derive(Debug)]
pub struct MfaSetupOutput {
    /// Short-lived JWT the client must present to `enroll_mfa_with_setup_token`
    /// and `confirm_mfa_with_setup_token`.
    pub setup_token: String,
}

/// MFA challenge token returned when login detects MFA is enabled.
#[derive(Debug)]
pub struct MfaChallengeOutput {
    /// Short-lived JWT encoding user_id + tenant_id + org_id.
    pub challenge_token: String,
    /// Available MFA method types (e.g. `["totp", "webauthn"]`).
    ///
    /// Populated by the REST handler layer (not `AuthService`) because
    /// `AuthService` does not have visibility into WebAuthn credentials.
    pub available_methods: Vec<String>,
}

/// Input for the refresh token rotation flow.
#[derive(Debug)]
pub struct RefreshInput {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub raw_refresh_token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Successful refresh result (new token pair).
#[derive(Debug)]
pub struct RefreshOutput {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub expires_in: u64,
}

/// Result of MFA enrollment (step 1).
#[derive(Debug)]
pub struct EnrollMfaOutput {
    /// Base32-encoded TOTP secret (for manual entry).
    pub secret_base32: String,
    /// `otpauth://` URI for QR code generation.
    pub totp_uri: String,
}

/// Input for MFA verification after login challenge.
#[derive(Debug)]
pub struct VerifyMfaInput {
    pub challenge_token: String,
    pub totp_code: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

// -----------------------------------------------------------------------
// MFA challenge token claims (internal JWT)
// -----------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct MfaChallengeClaims {
    sub: String,
    tenant_id: String,
    org_id: String,
    purpose: String,
    iss: String,
    iat: i64,
    exp: i64,
}

// -----------------------------------------------------------------------
// AuthService
// -----------------------------------------------------------------------

/// Authentication service.
///
/// Generic over repository implementations so that the auth layer
/// has no dependency on the database crate.
///
/// `T` is the OAuth2 refresh-token repository. It is used by
/// `revoke_all_sessions` and `revoke_all_sessions_except` to ensure that
/// both session-flow and OAuth2-flow refresh tokens are revoked whenever
/// a credential change occurs (RESEARCH §4 — "two chokepoints").
#[derive(Clone)]
pub struct AuthService<
    U: UserRepository,
    S: SessionRepository,
    F: FederationLinkRepository,
    T: RefreshTokenRepository,
> {
    user_repo: U,
    session_repo: S,
    federation_repo: F,
    refresh_token_repo: T,
    config: AuthConfig,
    /// Bounding semaphore (CQ-B02): limits concurrent Argon2 operations to prevent
    /// CPU-bound crypto from starving the Tokio async runtime under login bursts.
    crypto_semaphore: Arc<Semaphore>,
    /// X1 — the `login.post_auth` interceptor chain.
    ///
    /// A field rather than a type parameter, and never an `Option`. `AuthService`
    /// is already generic over four repositories and is named explicitly in
    /// `AppState<C>`; a fifth parameter would push the broker choice into the
    /// signature of a crate whose whole design is not to know a broker exists.
    /// A deployment without reactors holds
    /// [`axiam_core::models::reactor::NoopReactorGate`] here, so there is one
    /// login path in every build rather than two that can drift.
    reactor_gate: SharedReactorGate,
}

impl<
    U: UserRepository,
    S: SessionRepository,
    F: FederationLinkRepository,
    T: RefreshTokenRepository,
> AuthService<U, S, F, T>
{
    pub fn new(
        user_repo: U,
        session_repo: S,
        federation_repo: F,
        refresh_token_repo: T,
        config: AuthConfig,
        crypto_semaphore: Arc<Semaphore>,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            federation_repo,
            refresh_token_repo,
            config,
            crypto_semaphore,
            reactor_gate: noop_reactor_gate(),
        }
    }

    /// Attach the reactor gate (X1).
    ///
    /// Builder-style rather than a seventh `new` parameter, for the same reason
    /// `TokenService::with_assertion_verifier` is: every existing construction
    /// site — including every test harness — keeps compiling and keeps its
    /// current behaviour, and the feature is invisible to a deployment that
    /// does not ask for it.
    #[must_use]
    pub fn with_reactor_gate(mut self, gate: SharedReactorGate) -> Self {
        self.reactor_gate = gate;
        self
    }

    /// Authenticate a user with username/email + password.
    ///
    /// Returns `LoginResult::Success` if no MFA, or
    /// `LoginResult::MfaRequired` with a challenge token if MFA is
    /// enabled.
    pub async fn login(&self, input: LoginInput) -> AxiamResult<LoginResult> {
        // 1. Look up user — try username first, then email.
        let user = match self
            .user_repo
            .get_by_username(input.tenant_id, &input.username_or_email)
            .await
        {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => {
                match self
                    .user_repo
                    .get_by_email(input.tenant_id, &input.username_or_email)
                    .await
                {
                    Ok(u) => u,
                    Err(AxiamError::NotFound { .. }) => {
                        // SEC-026: timing equalization — run a dummy Argon2 verify so
                        // user-not-found takes the same time as wrong-password (ASVS V2).
                        //
                        // B1: acquire the crypto permit with the SAME
                        // acquire-with-timeout used by the real wrong-password
                        // verify below (step 3), so the two branches stay
                        // constant-time in BOTH regimes:
                        //   * normal load — both acquire immediately and run
                        //     exactly one Argon2id verify → 401;
                        //   * saturation  — both hit the same timeout and return
                        //     the same 503 backpressure error *before* hashing.
                        // Making only the real path shed load (while this dummy
                        // path waited unboundedly and always hashed) would make
                        // "existing + wrong password → 503" distinguishable from
                        // "no such user → 401" under load — reintroducing the very
                        // enumeration oracle SEC-026 closes. Propagating the error
                        // here keeps them indistinguishable, and also subjects the
                        // enumeration/dummy path to the memory-DoS bound (an
                        // attacker spamming unknown usernames is throttled too).
                        let _permit = acquire_hash_permit(
                            &self.crypto_semaphore,
                            std::time::Duration::from_secs(self.config.hash_acquire_timeout_secs),
                        )
                        .await?;
                        let pepper_owned = self.config.pepper.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            password::verify_password(
                                "dummy",
                                password::DUMMY_HASH,
                                pepper_owned.as_ref().map(|p| p.expose_secret()),
                            )
                        })
                        .await;
                        return Err(AuthError::InvalidCredentials.into());
                    }
                    // CQ-B12: propagate real DB errors instead of swallowing them.
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };

        // 2. Check temporary lockout (brute force protection).
        if let Some(locked_until) = user.locked_until
            && locked_until > Utc::now()
        {
            return Err(AuthError::InvalidCredentials.into());
        }

        // 3. Verify password — CPU-bound Argon2id runs in spawn_blocking behind semaphore (CQ-B02).
        //    B1: bounded acquire — 503 backpressure on timeout instead of unbounded queueing.
        let _permit = acquire_hash_permit(
            &self.crypto_semaphore,
            std::time::Duration::from_secs(self.config.hash_acquire_timeout_secs),
        )
        .await?;
        let pw_owned = input.password.clone();
        let hash_owned = user.password_hash.clone();
        let pepper_owned = self.config.pepper.clone();
        let valid = tokio::task::spawn_blocking(move || {
            password::verify_password(
                &pw_owned,
                &hash_owned,
                pepper_owned.as_ref().map(|p| p.expose_secret()),
            )
        })
        .await
        .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))?
        .map_err(|e| AxiamError::Crypto(e.to_string()))?;

        if !valid {
            self.record_failed_login(input.tenant_id, &user).await?;
            return Err(AuthError::InvalidCredentials.into());
        }

        self.complete_authenticated_login(
            user,
            input.tenant_id,
            input.org_id,
            input.ip_address,
            input.user_agent,
            input.mfa_policy,
        )
        .await
    }

    /// Everything a login does **after** the credential itself has been
    /// checked: reset the failed-attempt counter, gate on account status, fire
    /// the `login.post_auth` reactor hook, apply MFA policy, and either issue
    /// tokens or return the appropriate challenge.
    ///
    /// This is a method rather than the tail of [`Self::login`] because there
    /// is now more than one way to prove a password. OPAQUE
    /// ([`crate::opaque::OpaqueServer::login_finish`]) establishes exactly the
    /// same fact — "this principal knows the password" — by a different route,
    /// and it must land in exactly the same place afterwards. Duplicating this
    /// sequence for the OPAQUE path is how a deployment ends up with lockout
    /// counters that only move on one of the two paths, or an MFA policy that
    /// one of them quietly skips.
    ///
    /// `mfa_policy` is the tenant-effective policy, or `None` to skip
    /// enforcement (the caller could not resolve settings).
    pub async fn complete_authenticated_login(
        &self,
        user: User,
        tenant_id: Uuid,
        org_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
        mfa_policy: Option<MfaPolicy>,
    ) -> AxiamResult<LoginResult> {
        // 4. Reset failed login counter on success.
        if user.failed_login_attempts > 0 {
            self.reset_failed_logins(tenant_id, user.id).await?;
        }

        // 5. Check account status.
        Self::check_user_status(
            &user.status,
            user.created_at,
            self.config.email_verification_grace_period_hours,
        )?;

        // 5c. X1 `login.post_auth` — after the credentials verify, before any
        //     session or challenge is issued.
        //
        //     This is the placement the event name promises and the only one
        //     that is safe. Earlier, and a reactor would be consulted about
        //     credentials that have not been checked, which turns the hook into
        //     a credential-probing oracle for whoever wrote the extension.
        //     Later — after `create_session_and_tokens` — and a veto would be
        //     refusing a session that already exists.
        let reactor_requires_mfa = self
            .intercept_login_post_auth(
                tenant_id,
                org_id,
                &user,
                ip_address.as_deref(),
                user_agent.as_deref(),
            )
            .await?;

        // 5b. MFA enforcement — if policy requires MFA but user hasn't set it up,
        //     return a setup token (unless the user is federated).
        //
        //     A reactor's `require_mfa` composes with the tenant policy by
        //     joining it, never by replacing it: it can only *add* a step-up
        //     demand, which is why it is OR-ed in below rather than consulted
        //     as an alternative.
        let policy_enforces_mfa = mfa_policy
            .as_ref()
            .is_some_and(|policy| policy.mfa_enforced);
        if (policy_enforces_mfa || reactor_requires_mfa) && !user.mfa_enabled {
            let links = self
                .federation_repo
                .get_by_user_id(tenant_id, user.id)
                .await?;
            // A reactor's demand is not waived for a federated user the way the
            // tenant policy's is. The federated carve-out exists because the
            // upstream IdP already performed the second factor; a reactor that
            // asked for step-up *after* seeing this login has, by definition,
            // seen that and asked anyway.
            if links.is_empty() || reactor_requires_mfa {
                let setup_token = self.issue_mfa_setup_token(user.id, tenant_id, org_id)?;
                return Ok(LoginResult::MfaSetupRequired(MfaSetupOutput {
                    setup_token,
                }));
            }
        }

        // 6. Check MFA — trigger for any user with mfa_enabled, regardless
        //    of whether they use TOTP or WebAuthn.
        if user.mfa_enabled {
            let challenge_token = self.issue_mfa_challenge(user.id, tenant_id, org_id)?;
            return Ok(LoginResult::MfaRequired(MfaChallengeOutput {
                challenge_token,
                available_methods: Vec::new(), // populated by REST handler
            }));
        }

        // 7. No MFA — issue tokens directly.
        let output = self
            .create_session_and_tokens(user.id, tenant_id, org_id, ip_address, user_agent)
            .await?;

        Ok(LoginResult::Success(output))
    }

    /// Fire `login.post_auth` for a principal whose authentication has just
    /// succeeded, and apply the verdict (X1 / R2.2, SEC-095).
    ///
    /// Returns `Ok(true)` when a reactor demanded step-up MFA, which the
    /// caller must honour; `Err(ReactorDenied)` when the login is vetoed.
    ///
    /// # Why this is a method rather than an inline block in [`Self::login`]
    ///
    /// It used to be inline, and that is exactly how SEC-095 happened: the
    /// event fired on the password path and nowhere else, so a federated
    /// sign-in — SAML ACS, OIDC callback — created a full session plus
    /// access/refresh tokens without the gate ever being consulted. Nothing
    /// scoped the event to passwords; the registry says "After credentials
    /// verify, before session issuance: veto or require step-up MFA", and
    /// `sdks/CONTRACT.md` §22.5 repeats that with no carve-out. An operator
    /// who registered the feature's own worked example — an embargoed-region
    /// login veto — got a control that was bypassed by clicking "Sign in with
    /// Okta".
    ///
    /// Having ONE payload builder and ONE verdict `match` is the property that
    /// keeps the federated paths honest: a third sign-in path cannot get a
    /// subtly different payload, and a new [`ReactorOutcome`] variant is a
    /// compile error at one site instead of a silent no-op at three.
    ///
    /// Placement at every call site is the same and is load-bearing: **after**
    /// the credentials verify — earlier turns the hook into a
    /// credential-probing oracle for whoever wrote the extension — and
    /// **before** any session or challenge is issued, because a veto that
    /// arrives after `create_session_and_tokens` is refusing a session that
    /// already exists.
    pub async fn intercept_login_post_auth(
        &self,
        tenant_id: Uuid,
        org_id: Uuid,
        user: &User,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> AxiamResult<bool> {
        match self
            .reactor_gate
            .intercept(
                tenant_id,
                reactor_events::LOGIN_POST_AUTH,
                serde_json::json!({
                    // What is being decided, never the means to act on it
                    // elsewhere (§22.3): no password, no token, no session id
                    // — the session does not exist yet.
                    "user_id": user.id,
                    "username": user.username,
                    "tenant_id": tenant_id,
                    "org_id": org_id,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "mfa_enabled": user.mfa_enabled,
                }),
            )
            .await
        {
            ReactorOutcome::Allow => Ok(false),
            ReactorOutcome::Deny { reason } => {
                // The gate has already audited this with the reactor's id; the
                // reason travels in the typed error for the caller's own audit
                // record and never reaches the HTTP response body.
                tracing::info!(
                    target: "axiam::reactor",
                    tenant_id = %tenant_id,
                    user_id = %user.id,
                    "login vetoed by a reactor on login.post_auth"
                );
                Err(AuthError::ReactorDenied { reason }.into())
            }
            ReactorOutcome::RequireMfa => Ok(true),
            // `login.post_auth` is veto-only: the registry marks it
            // `mutable: false`, the reply validator refuses a `mutate` on it,
            // and the gate re-checks. Reaching this arm would mean all three
            // failed, so it is treated as a refusal rather than ignored.
            ReactorOutcome::Mutate { .. } => {
                tracing::error!(
                    target: "axiam::reactor",
                    tenant_id = %tenant_id,
                    "a mutation reached the login.post_auth call site, which is a \
                     veto-only event — refusing the login"
                );
                Err(AuthError::ReactorDenied {
                    reason: "reactor attempted to mutate a veto-only event".into(),
                }
                .into())
            }
        }
    }

    /// [`Self::intercept_login_post_auth`] for a sign-in path that has **no**
    /// step-up branch to route a `require_mfa` into — the SAML ACS and OIDC
    /// callback handlers (SEC-095).
    ///
    /// A federated sign-in completes in one round trip: there is no
    /// `MfaRequired` / `MfaSetupRequired` result for the caller to act on, so
    /// a reactor's step-up demand cannot be honoured. It is **refused**, not
    /// dropped — the same rule `reactor_hooks::impossible` applies on the REST
    /// side. Silently ignoring it would mean a reactor that asked for a second
    /// factor got a session with one, which is worse than an outage for the
    /// operator who configured it: they would never learn their control did
    /// nothing.
    pub async fn intercept_federated_login_post_auth(
        &self,
        tenant_id: Uuid,
        org_id: Uuid,
        user: &User,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> AxiamResult<()> {
        let requires_mfa = self
            .intercept_login_post_auth(tenant_id, org_id, user, ip_address, user_agent)
            .await?;
        if requires_mfa {
            tracing::error!(
                target: "axiam::reactor",
                tenant_id = %tenant_id,
                user_id = %user.id,
                "a reactor demanded step-up MFA on a federated login.post_auth, which \
                 this sign-in path cannot honour — refusing the login rather than \
                 issuing a session the reactor did not authorise"
            );
            return Err(AuthError::ReactorDenied {
                reason: "reactor required step-up MFA on a sign-in path that cannot \
                         perform it"
                    .into(),
            }
            .into());
        }
        Ok(())
    }

    /// Complete MFA verification after a login challenge.
    pub async fn verify_mfa(&self, input: VerifyMfaInput) -> AxiamResult<LoginOutput> {
        // 1. Decode the challenge token.
        let claims = self.decode_mfa_challenge(&input.challenge_token)?;
        let user_id: Uuid = claims
            .sub
            .parse()
            .map_err(|_| AuthError::TokenInvalid("bad sub".into()))?;
        let tenant_id: Uuid = claims
            .tenant_id
            .parse()
            .map_err(|_| AuthError::TokenInvalid("bad tenant_id".into()))?;
        let org_id: Uuid = claims
            .org_id
            .parse()
            .map_err(|_| AuthError::TokenInvalid("bad org_id".into()))?;

        // 2. Fetch user and verify TOTP.
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        Self::check_user_status(
            &user.status,
            user.created_at,
            self.config.email_verification_grace_period_hours,
        )?;

        let encrypted_secret = user
            .mfa_secret
            .as_deref()
            .ok_or(AuthError::MfaNotEnrolled)?;
        let encryption_key = self
            .config
            .mfa_encryption_key
            .as_ref()
            .ok_or_else(|| AuthError::Crypto("MFA encryption key not configured".into()))?;

        let secret_bytes = totp::decrypt_secret(encryption_key, encrypted_secret)?;
        let (valid, used_step) = totp::verify_code_with_replay_check(
            &secret_bytes,
            &input.totp_code,
            &self.config.totp_issuer,
            &user.email,
            user.totp_last_used_step,
        )?;

        if !valid {
            return Err(AuthError::MfaInvalidCode.into());
        }

        // Persist the used step to prevent replay within this window
        // (SEC-008/SECHRD-01). `update_totp_step` is an atomic
        // compare-and-set: `Ok(false)` means the CAS was lost — either this
        // exact step was already consumed (replay) or a concurrent
        // submission of the same code already won. Either way, surface the
        // SAME rejection as an invalid code so a replay/CAS-miss is
        // indistinguishable from a wrong code.
        let advanced = self
            .user_repo
            .update_totp_step(tenant_id, user_id, used_step)
            .await?;
        if !advanced {
            return Err(AuthError::MfaInvalidCode.into());
        }

        // 3. Create session and issue tokens.
        self.create_session_and_tokens(
            user_id,
            tenant_id,
            org_id,
            input.ip_address,
            input.user_agent,
        )
        .await
    }

    /// Decode an MFA challenge token and return the embedded IDs.
    ///
    /// This is used by the WebAuthn REST handler to extract
    /// `(user_id, tenant_id, org_id)` from an MFA challenge token
    /// so it can start a WebAuthn authentication ceremony.
    pub fn decode_mfa_challenge_ids(&self, token: &str) -> Result<(Uuid, Uuid, Uuid), AuthError> {
        let claims = self.decode_mfa_challenge(token)?;
        let user_id: Uuid = claims
            .sub
            .parse()
            .map_err(|_| AuthError::TokenInvalid("bad sub".into()))?;
        let tenant_id: Uuid = claims
            .tenant_id
            .parse()
            .map_err(|_| AuthError::TokenInvalid("bad tenant_id".into()))?;
        let org_id: Uuid = claims
            .org_id
            .parse()
            .map_err(|_| AuthError::TokenInvalid("bad org_id".into()))?;
        Ok((user_id, tenant_id, org_id))
    }

    /// Start MFA enrollment for a user (step 1 of 2).
    ///
    /// Generates a TOTP secret, encrypts it, stores it on the user,
    /// but does NOT enable MFA yet — call `confirm_mfa` with a valid
    /// code to activate.
    pub async fn enroll_mfa(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<EnrollMfaOutput> {
        let encryption_key = self
            .config
            .mfa_encryption_key
            .as_ref()
            .ok_or_else(|| AuthError::Crypto("MFA encryption key not configured".into()))?;

        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;

        let (base32_secret, totp_uri) =
            totp::generate_enrollment(&self.config.totp_issuer, &user.email)?;

        // Parse the base32 secret to raw bytes for encryption. Under totp-rs
        // 6.0 the fallible step is the *parse* rather than the byte extraction:
        // `try_from_base32` rejects a malformed encoding, and `as_bytes` on the
        // result cannot fail.
        let secret = totp_rs::Secret::try_from_base32(&base32_secret)
            .map_err(|e| AuthError::Crypto(format!("secret decode: {e}")))?;
        let secret_bytes = secret.as_bytes().to_vec();
        let encrypted = totp::encrypt_secret(encryption_key, &secret_bytes)?;

        // Store encrypted secret but leave mfa_enabled = false.
        self.user_repo
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    mfa_secret: Some(Some(encrypted)),
                    ..Default::default()
                },
            )
            .await?;

        Ok(EnrollMfaOutput {
            secret_base32: base32_secret,
            totp_uri,
        })
    }

    /// Confirm MFA enrollment (step 2 of 2).
    ///
    /// The user provides a TOTP code to prove they saved the secret.
    /// On success, `mfa_enabled` is set to `true`.
    pub async fn confirm_mfa(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        totp_code: &str,
    ) -> AxiamResult<()> {
        let encryption_key = self
            .config
            .mfa_encryption_key
            .as_ref()
            .ok_or_else(|| AuthError::Crypto("MFA encryption key not configured".into()))?;

        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        let encrypted_secret = user
            .mfa_secret
            .as_deref()
            .ok_or(AuthError::MfaNotEnrolled)?;

        let secret_bytes = totp::decrypt_secret(encryption_key, encrypted_secret)?;
        // SECHRD-01/T-24-03: reuse the same matched-step verification and
        // atomic CAS as `verify_mfa` so replay tracking begins at
        // enrollment-confirm time rather than at first login. A
        // freshly-enrolled user always has `totp_last_used_step = NONE`, so
        // this always succeeds on first use — it only closes the gap where
        // the enrollment code itself could otherwise be replayed before the
        // user's first full login.
        let (valid, used_step) = totp::verify_code_with_replay_check(
            &secret_bytes,
            totp_code,
            &self.config.totp_issuer,
            &user.email,
            user.totp_last_used_step,
        )?;

        if !valid {
            return Err(AuthError::MfaInvalidCode.into());
        }

        // Seed totp_last_used_step atomically. A lost CAS here means the
        // enrollment code was already consumed (e.g. a concurrent duplicate
        // submission) — reject with the same enrollment-failure error rather
        // than introduce a new response shape.
        let advanced = self
            .user_repo
            .update_totp_step(tenant_id, user_id, used_step)
            .await?;
        if !advanced {
            return Err(AuthError::MfaInvalidCode.into());
        }

        // Activate MFA.
        self.user_repo
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    mfa_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }

    /// Rotate a refresh token: consume the old one, verify the user
    /// is still active, and issue a new token pair.
    ///
    /// # Per-stage timing (A2/J2)
    ///
    /// Run 5 measured this endpoint at 545/s and p50 88.8 ms, down from 839/s
    /// and 47.5 ms in run 4 — the whole distribution shifted right with tight
    /// medians in both runs, which is the signature of *added serialized work*
    /// rather than of contention or of a slow tail. Refresh is the one hot
    /// endpoint that is round-trip-bound rather than CPU-bound, so it carries
    /// a stage breakdown (`consume_us`, `user_lookup_us`, `session_create_us`,
    /// `token_mint_us`, `handler_total_us`) on the `auth.refresh` span and as
    /// one DEBUG event on `target: "axiam::perf"` — the same shape
    /// `oauth2.client_credentials` uses, and for the same reason: the next
    /// time this number moves, the stage that moved should be readable off a
    /// log line instead of bisected for.
    ///
    /// Cost is four `Instant::now()` reads and four `Span::record` calls that
    /// are no-ops when nothing is subscribed — immaterial against a path whose
    /// cheapest stage is a datastore round trip.
    ///
    /// # Datastore round trips: three, not five
    ///
    /// The rotation used to issue five sequential statements (session read,
    /// expiry check, consume, user read, session create) plus a tenant read in
    /// the REST handler above it. Two are now gone:
    ///
    /// - the session read and the consume are one atomic
    ///   `consume_by_token_hash` (see that method's docs — it also removes the
    ///   read-then-delete window rather than tolerating it);
    /// - the handler's per-refresh tenant read is served from a TTL cache.
    ///
    /// **No security semantics were weakened to get there.** Single-use
    /// rotation is still enforced by `RETURN BEFORE` (and now with no window
    /// at all), the user-status check still happens before a new session is
    /// minted, and an expired token is still consumed rather than left
    /// replayable.
    #[tracing::instrument(
        name = "auth.refresh",
        skip(self, input),
        fields(
            consume_us = tracing::field::Empty,
            user_lookup_us = tracing::field::Empty,
            session_create_us = tracing::field::Empty,
            token_mint_us = tracing::field::Empty,
            handler_total_us = tracing::field::Empty,
        )
    )]
    pub async fn refresh(&self, input: RefreshInput) -> AxiamResult<RefreshOutput> {
        let started = std::time::Instant::now();

        // 1. Atomically find AND consume the session named by this token
        //    (single-use guarantee, NEW-3). A `None` means no live session
        //    matched — either the token was never valid, or a concurrent
        //    refresh already consumed it. Both are the same answer to the
        //    caller, and both abort BEFORE any new session is minted, so one
        //    refresh token can never yield two live session lineages.
        let t_consume = std::time::Instant::now();
        let token_hash = token::hash_refresh_token(&input.raw_refresh_token);
        let session = self
            .session_repo
            .consume_by_token_hash(input.tenant_id, &token_hash)
            .await?
            .ok_or_else(|| -> AxiamError {
                AuthError::TokenInvalid("refresh token not found or already used".into()).into()
            })?;
        let consume_us = t_consume.elapsed().as_micros() as u64;

        // 2. Reject an expired session. It has already been consumed by the
        //    statement above, which is deliberate: an expired refresh token
        //    must not be left behind to be replayed until the cleanup job
        //    happens to run.
        if session.expires_at <= Utc::now() {
            return Err(AuthError::TokenExpired.into());
        }

        // 3. Verify user is still active.
        let t_user = std::time::Instant::now();
        let user = self
            .user_repo
            .get_by_id(input.tenant_id, session.user_id)
            .await?;
        Self::check_user_status(
            &user.status,
            user.created_at,
            self.config.email_verification_grace_period_hours,
        )?;
        let user_lookup_us = t_user.elapsed().as_micros() as u64;

        // 4. Create new session with rotated refresh token.
        let t_create = std::time::Instant::now();
        let raw_refresh = token::generate_refresh_token();
        let new_hash = token::hash_refresh_token(&raw_refresh);
        let expires_at =
            Utc::now() + Duration::seconds(self.config.refresh_token_lifetime_secs as i64);

        let new_session = self
            .session_repo
            .create(CreateSession {
                tenant_id: input.tenant_id,
                user_id: user.id,
                token_hash: new_hash,
                ip_address: input.ip_address,
                user_agent: input.user_agent,
                expires_at,
            })
            .await?;
        let session_create_us = t_create.elapsed().as_micros() as u64;

        // 5. Issue new access token (jti = new session.id per D-15).
        let t_mint = std::time::Instant::now();
        let access_token = token::issue_access_token(
            user.id,
            input.tenant_id,
            input.org_id,
            &[],
            &self.config,
            new_session.id.to_string(),
            AUD_USER,
        )?;
        let token_mint_us = t_mint.elapsed().as_micros() as u64;

        let handler_total_us = started.elapsed().as_micros() as u64;
        let span = tracing::Span::current();
        span.record("consume_us", consume_us);
        span.record("user_lookup_us", user_lookup_us);
        span.record("session_create_us", session_create_us);
        span.record("token_mint_us", token_mint_us);
        span.record("handler_total_us", handler_total_us);
        tracing::debug!(
            target: "axiam::perf",
            stage = "auth.refresh",
            consume_us,
            user_lookup_us,
            session_create_us,
            token_mint_us,
            handler_total_us,
            "refresh stage timings (A2/J2)"
        );

        Ok(RefreshOutput {
            access_token,
            refresh_token: raw_refresh,
            session_id: new_session.id,
            expires_in: self.config.access_token_lifetime_secs,
        })
    }

    /// Invalidate a single session (logout).
    pub async fn logout(&self, tenant_id: Uuid, session_id: Uuid) -> AxiamResult<()> {
        self.session_repo.invalidate(tenant_id, session_id).await
    }

    /// Revoke all sessions for a user AND all OAuth2 refresh tokens.
    ///
    /// Used by password reset confirm and MFA reset — caller is unauthenticated
    /// so there is no current session to preserve (D-16).
    ///
    /// Revokes both the session-flow refresh tokens (via `session_repo`) AND
    /// the OAuth2-flow refresh tokens (via `refresh_token_repo`). RESEARCH §4
    /// confirmed these are two separate tables; both must be hit.
    pub async fn revoke_all_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.session_repo
            .invalidate_user_sessions(tenant_id, user_id)
            .await?;

        // Also revoke OAuth2 refresh tokens for this user (the second
        // chokepoint identified in RESEARCH §4). Tolerate 0 revocations —
        // user may not have any OAuth2 tokens.
        let oauth2_revoked = self
            .refresh_token_repo
            .revoke_all_for_user(tenant_id, user_id)
            .await?;
        tracing::debug!(
            %tenant_id, %user_id, %oauth2_revoked,
            "revoke_all_sessions: session-flow and OAuth2 refresh tokens revoked"
        );

        Ok(())
    }

    /// Revoke all sessions for a user EXCEPT the current one, AND revoke all
    /// OAuth2 refresh tokens.
    ///
    /// Used on password change — the caller's current session (identified by
    /// `current_session_id` = JWT `jti` = `session.id`) is preserved so the
    /// caller can continue using the application after changing their password
    /// (D-14, D-15).
    ///
    /// Audit-log entry: `event_type = "sessions_revoked_except_current"`.
    pub async fn revoke_all_sessions_except(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        current_session_id: Uuid,
    ) -> AxiamResult<()> {
        let sessions_deleted = self
            .session_repo
            .invalidate_user_sessions_except(tenant_id, user_id, current_session_id)
            .await?;

        // Revoke all OAuth2 refresh tokens for the user. OAuth2 tokens are not
        // session-scoped, so we must revoke all of them even on a "keep current
        // session" path — the caller's browser session continues but any OAuth2
        // app must re-authenticate. Tolerate 0 revocations.
        let oauth2_revoked = self
            .refresh_token_repo
            .revoke_all_for_user(tenant_id, user_id)
            .await?;
        tracing::debug!(
            %tenant_id, %user_id, %sessions_deleted, %oauth2_revoked,
            event_type = "sessions_revoked_except_current",
            "password change: other sessions and all OAuth2 tokens revoked; current session preserved"
        );

        Ok(())
    }

    /// Change a user's password with current-password verification.
    ///
    /// Security protocol (D-14, D-21):
    /// 1. Verify `current_password` against the stored Argon2id hash.
    ///    Mismatch → `AuthenticationFailed` (maps to 401 in the REST layer).
    /// 2. Evaluate `new_password` against the tenant password policy.
    ///    Failure → `Validation` (maps to 422 in the REST layer).
    /// 3. Hash and store the new password.
    /// 4. Store old hash in password history.
    /// 5. Revoke all sessions except the caller's current session.
    /// 6. Emit audit log entry.
    #[allow(clippy::too_many_arguments)] // CQ-B35: http_client param added for HIBP check
    pub async fn change_password<H: PasswordHistoryRepository>(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        current_session_id: Uuid,
        current_password: &str,
        new_password: &str,
        policy: &PasswordPolicy,
        history_repo: &H,
        http_client: Option<&reqwest::Client>, // CQ-B35: pass through to HIBP check
    ) -> AxiamResult<()> {
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;

        // 1. Verify current password — CPU-bound, run in spawn_blocking behind semaphore (CQ-B02).
        //    B1: bounded acquire — held for the whole change_password call so the SEC-028
        //    same-password check and the history verify reuse this single permit.
        let _permit = acquire_hash_permit(
            &self.crypto_semaphore,
            std::time::Duration::from_secs(self.config.hash_acquire_timeout_secs),
        )
        .await?;
        let pw_owned = current_password.to_string();
        let hash_owned = user.password_hash.clone();
        let pepper_owned = self.config.pepper.clone();
        let valid = tokio::task::spawn_blocking(move || {
            password::verify_password(
                &pw_owned,
                &hash_owned,
                pepper_owned.as_ref().map(|p| p.expose_secret()),
            )
        })
        .await
        .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))?
        .map_err(|e| AxiamError::Crypto(e.to_string()))?;

        if !valid {
            return Err(AuthError::InvalidCredentials.into());
        }

        // 1b. SEC-028: Block reset to current password — reject if new password
        //     matches the stored hash. Runs in spawn_blocking (CPU-bound Argon2).
        let new_pw_owned = new_password.to_string();
        let current_hash_owned = user.password_hash.clone();
        let pepper_owned2 = self.config.pepper.clone();
        let is_same = tokio::task::spawn_blocking(move || {
            password::verify_password(
                &new_pw_owned,
                &current_hash_owned,
                pepper_owned2.as_ref().map(|p| p.expose_secret()),
            )
        })
        .await
        .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))?
        .map_err(|e| AxiamError::Crypto(e.to_string()))?;
        if is_same {
            return Err(AuthError::PasswordReusedCurrent.into());
        }

        // 2. Evaluate new password against policy.
        let check = crate::policy::evaluate_password(
            new_password,
            self.config.pepper.as_ref().map(|p| p.expose_secret()),
            policy,
            tenant_id,
            user_id,
            history_repo,
            http_client,
        )
        .await?;

        if !check.is_ok() {
            return Err(AxiamError::PasswordPolicy {
                message: check.error_message(),
            });
        }

        // 3. Hash new password.
        let new_hash = password::hash_password(
            new_password,
            self.config.pepper.as_ref().map(|p| p.expose_secret()),
        )?;

        // 4. Store old password in history before overwriting.
        history_repo
            .create(CreatePasswordHistoryEntry {
                tenant_id,
                user_id,
                password_hash: user.password_hash.clone(),
            })
            .await?;

        // 5. Update user with new password hash.
        self.user_repo
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    password_hash: Some(new_hash),
                    ..Default::default()
                },
            )
            .await?;

        // 6. Revoke all other sessions + OAuth2 tokens; preserve current session.
        self.revoke_all_sessions_except(tenant_id, user_id, current_session_id)
            .await?;

        tracing::info!(
            %tenant_id,
            actor = %user_id,
            target = %user_id,
            mode = "self_service",
            event_type = "password_changed",
            "user changed their password"
        );

        Ok(())
    }

    /// Start MFA enrollment using an MFA setup token (enforcement flow).
    ///
    /// This is the same as `enroll_mfa` but authenticates via the
    /// setup token instead of requiring a pre-existing session.
    pub async fn enroll_mfa_with_setup_token(
        &self,
        setup_token: &str,
    ) -> AxiamResult<EnrollMfaOutput> {
        let (user_id, tenant_id, _org_id) = self.decode_mfa_setup_token(setup_token)?;

        // Guard: if MFA is already configured, reject.
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        if user.mfa_enabled && user.mfa_secret.is_some() {
            return Err(AuthError::MfaAlreadyConfigured.into());
        }

        self.enroll_mfa(tenant_id, user_id).await
    }

    /// Confirm MFA enrollment and complete login using a setup token.
    ///
    /// Decodes the setup token, verifies the TOTP code, enables MFA,
    /// then creates a session and issues tokens — same end state as
    /// `verify_mfa`.
    pub async fn confirm_mfa_with_setup_token(
        &self,
        setup_token: &str,
        totp_code: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AxiamResult<LoginOutput> {
        let (user_id, tenant_id, org_id) = self.decode_mfa_setup_token(setup_token)?;

        // Confirm MFA (validates code, flips mfa_enabled to true).
        self.confirm_mfa(tenant_id, user_id, totp_code).await?;

        // Create session and issue tokens.
        self.create_session_and_tokens(user_id, tenant_id, org_id, ip_address, user_agent)
            .await
    }

    /// Reset MFA for a user — disables MFA, clears the secret, and
    /// revokes all existing sessions.
    pub async fn reset_mfa(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.user_repo
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    mfa_enabled: Some(false),
                    mfa_secret: Some(None),
                    ..Default::default()
                },
            )
            .await?;

        self.session_repo
            .invalidate_user_sessions(tenant_id, user_id)
            .await?;

        Ok(())
    }

    // -------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------

    /// Check user account status, with grace period support for
    /// pending verification.
    ///
    /// `created_at` and `grace_period_hours` are used to determine
    /// if a `PendingVerification` user is still within the login
    /// grace period. Pass `grace_period_hours = 0` to disable the
    /// grace period (always reject pending users).
    fn check_user_status(
        status: &UserStatus,
        created_at: chrono::DateTime<Utc>,
        grace_period_hours: u32,
    ) -> Result<(), AuthError> {
        match status {
            UserStatus::Active => Ok(()),
            UserStatus::Locked => Err(AuthError::AccountLocked),
            UserStatus::Inactive => Err(AuthError::AccountInactive),
            // Anonymized users cannot log in — treat as inactive.
            UserStatus::Anonymized => Err(AuthError::AccountInactive),
            UserStatus::PendingVerification => {
                if grace_period_hours > 0 {
                    let grace_end = created_at + Duration::hours(grace_period_hours as i64);
                    if Utc::now() <= grace_end {
                        return Ok(());
                    }
                }
                Err(AuthError::AccountPendingVerification)
            }
        }
    }

    /// Create a session and issue access + refresh tokens.
    ///
    /// Public so that `WebauthnService` callers (REST handlers) can
    /// complete the login flow after WebAuthn authentication succeeds.
    pub async fn create_session_and_tokens(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        org_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AxiamResult<LoginOutput> {
        let raw_refresh = token::generate_refresh_token();
        let token_hash = token::hash_refresh_token(&raw_refresh);
        let expires_at =
            Utc::now() + Duration::seconds(self.config.refresh_token_lifetime_secs as i64);

        let session = self
            .session_repo
            .create(CreateSession {
                tenant_id,
                user_id,
                token_hash,
                ip_address,
                user_agent,
                expires_at,
            })
            .await?;

        // jti = session.id per D-15 (session-based revocation).
        let access_token = token::issue_access_token(
            user_id,
            tenant_id,
            org_id,
            &[],
            &self.config,
            session.id.to_string(),
            AUD_USER,
        )?;

        Ok(LoginOutput {
            access_token,
            refresh_token: raw_refresh,
            session_id: session.id,
            expires_in: self.config.access_token_lifetime_secs,
        })
    }

    fn issue_mfa_challenge(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        org_id: Uuid,
    ) -> Result<String, AuthError> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let now = Utc::now().timestamp();
        let claims = MfaChallengeClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            org_id: org_id.to_string(),
            purpose: "mfa_challenge".into(),
            iss: self.config.jwt_issuer.clone(),
            iat: now,
            exp: now + self.config.mfa_challenge_lifetime_secs as i64,
        };

        let key = EncodingKey::from_ed_pem(self.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
    }

    fn decode_mfa_challenge(&self, token: &str) -> Result<MfaChallengeClaims, AuthError> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};

        let key = DecodingKey::from_ed_pem(self.config.jwt_public_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad public key: {e}")))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);

        let data =
            jsonwebtoken::decode::<MfaChallengeClaims>(token, &key, &validation).map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    _ => AuthError::TokenInvalid(e.to_string()),
                }
            })?;

        if data.claims.purpose != "mfa_challenge" {
            return Err(AuthError::TokenInvalid("not an MFA challenge token".into()));
        }

        Ok(data.claims)
    }

    /// Issue a short-lived JWT for MFA setup (enforcement flow).
    fn issue_mfa_setup_token(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        org_id: Uuid,
    ) -> Result<String, AuthError> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let now = Utc::now().timestamp();
        let claims = MfaChallengeClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            org_id: org_id.to_string(),
            purpose: "mfa_setup".into(),
            iss: self.config.jwt_issuer.clone(),
            iat: now,
            exp: now + self.config.mfa_challenge_lifetime_secs as i64,
        };

        let key = EncodingKey::from_ed_pem(self.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
    }

    /// Decode and validate an MFA setup token, returning (user_id,
    /// tenant_id, org_id).
    fn decode_mfa_setup_token(&self, token: &str) -> Result<(Uuid, Uuid, Uuid), AuthError> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};

        let key = DecodingKey::from_ed_pem(self.config.jwt_public_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad public key: {e}")))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);

        let data =
            jsonwebtoken::decode::<MfaChallengeClaims>(token, &key, &validation).map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        AuthError::MfaSetupTokenInvalid
                    }
                    _ => AuthError::MfaSetupTokenInvalid,
                }
            })?;

        if data.claims.purpose != "mfa_setup" {
            return Err(AuthError::MfaSetupTokenInvalid);
        }

        let user_id: Uuid = data
            .claims
            .sub
            .parse()
            .map_err(|_| AuthError::MfaSetupTokenInvalid)?;
        let tenant_id: Uuid = data
            .claims
            .tenant_id
            .parse()
            .map_err(|_| AuthError::MfaSetupTokenInvalid)?;
        let org_id: Uuid = data
            .claims
            .org_id
            .parse()
            .map_err(|_| AuthError::MfaSetupTokenInvalid)?;

        Ok((user_id, tenant_id, org_id))
    }

    /// Record one failed authentication attempt against `user_id`, for the
    /// OPAQUE path.
    ///
    /// OPAQUE proves the password without the server seeing it, but a failed
    /// `KE3` is still a wrong password and must accrue toward lockout exactly
    /// as a wrong Argon2id verify does. Without this, turning OPAQUE on would
    /// silently remove brute-force protection from the accounts that adopted
    /// it — the opposite of what enabling an extra security layer is supposed
    /// to do.
    ///
    /// This is why [`crate::opaque::OpaqueRejection`] has two variants rather
    /// than one: the caller cannot accrue an attempt it cannot attribute.
    pub async fn record_failed_opaque_attempt(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<()> {
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        self.record_failed_login(tenant_id, &user).await
    }

    async fn record_failed_login(
        &self,
        tenant_id: Uuid,
        user: &axiam_core::models::user::User,
    ) -> AxiamResult<()> {
        // D-06: delegate to the shared lockout helper — the single source of
        // truth for failed-attempt accrual, also called by gRPC
        // `UserService::validate_credentials` (SEC-026b).
        crate::lockout::record_failed_login(&self.user_repo, &self.config, tenant_id, user).await
    }

    async fn reset_failed_logins(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.user_repo
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    failed_login_attempts: Some(0),
                    last_failed_login_at: Some(None),
                    locked_until: Some(None),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }
}
