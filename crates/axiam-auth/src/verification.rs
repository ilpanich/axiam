//! Email verification service -- token generation, verification,
//! and resend with rate limiting.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email_verification::{
    CreateEmailVerificationToken, EmailVerificationRedemption,
};
use axiam_core::models::user::{User, UserStatus};
use axiam_core::repository::{
    EmailVerificationTokenRepository, FederationLinkRepository, UserRepository,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::error::AuthError;
use crate::token;

/// Maximum number of verification emails per user per day.
const MAX_RESENDS_PER_DAY: u64 = 2;

/// Default token expiry in hours.
const TOKEN_EXPIRY_HOURS: i64 = 24;

/// Email verification service.
///
/// Handles token generation, consumption, and resend with
/// rate limiting. Federated-user detection is also exposed
/// here so the API layer can skip verification for social
/// login users.
///
/// `Clone` (QUAL-07): hoisted `AppState<C>` singleton, cloned per worker.
#[derive(Clone)]
pub struct EmailVerificationService<U, V, F>
where
    U: UserRepository,
    V: EmailVerificationTokenRepository,
    F: FederationLinkRepository,
{
    user_repo: U,
    token_repo: V,
    federation_repo: F,
}

impl<U, V, F> EmailVerificationService<U, V, F>
where
    U: UserRepository,
    V: EmailVerificationTokenRepository,
    F: FederationLinkRepository,
{
    /// Create a new verification service.
    pub fn new(user_repo: U, token_repo: V, federation_repo: F) -> Self {
        Self {
            user_repo,
            token_repo,
            federation_repo,
        }
    }

    /// Generate a verification token for a user's address.
    ///
    /// Returns `(raw_token, expires_at)`. The raw token is used to
    /// build the action URL; only the SHA-256 hash is stored, together with
    /// `email` — the address the token is mailed to. Redemption verifies the
    /// account only while its address is still exactly `email` (item A of the
    /// 1.1.0 atomicity audit): a token never vouches for an address it was not
    /// sent to.
    pub async fn initiate_verification(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        email: &str,
    ) -> AxiamResult<(String, chrono::DateTime<chrono::Utc>)> {
        let raw_token = token::generate_refresh_token();
        let token_hash = token::hash_refresh_token(&raw_token);
        let expires_at = Utc::now() + Duration::hours(TOKEN_EXPIRY_HOURS);

        self.token_repo
            .create(CreateEmailVerificationToken {
                tenant_id,
                user_id,
                token_hash,
                email: email.to_owned(),
                expires_at,
            })
            .await?;

        Ok((raw_token, expires_at))
    }

    /// Verify an email using the raw token.
    ///
    /// One transaction consumes the token and marks the address verified
    /// (activating a `PendingVerification` account), and only while the
    /// account's address is still the one the token was minted for
    /// ([`UserRepository::redeem_email_verification`]). A token for an
    /// address the account has left, and a token minted before 1.1.0 (which
    /// names no address), are refused exactly as an unknown token is.
    ///
    /// Only `PendingVerification` becomes `Active`: an admin-disabled or
    /// locked account is not reactivated by verifying its address.
    pub async fn verify_email(&self, tenant_id: Uuid, raw_token: &str) -> AxiamResult<()> {
        let token_hash = token::hash_refresh_token(raw_token);

        let outcome = self
            .user_repo
            .redeem_email_verification(tenant_id, &token_hash)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => {
                    AxiamError::from(AuthError::VerificationTokenInvalid)
                }
                other => other,
            })?;

        match outcome {
            EmailVerificationRedemption::Verified { .. } => Ok(()),
            EmailVerificationRedemption::AlreadyVerified => {
                Err(AuthError::EmailAlreadyVerified.into())
            }
            EmailVerificationRedemption::AddressMismatch => {
                Err(AuthError::VerificationTokenInvalid.into())
            }
        }
    }

    /// Whether a verification mail may be minted for this user.
    ///
    /// The predicate is **"is the address still unverified"**, which is the same
    /// question [`Self::verify_email`] asks when it consumes the token. Those
    /// two disagreeing is what made "Resend verification email" a button that
    /// did nothing: it gated on `status == PendingVerification`, while the
    /// profile page — correctly — offered the button whenever
    /// `email_verified_at` was unset. Any user who reached `Active` without
    /// verifying (an administrator creating an account, a status edit, a
    /// federated first login later given a password) could complete
    /// verification if they somehow obtained a token, and could never be sent
    /// one. The endpoint answered 200 either way, so nothing anywhere said so.
    ///
    /// Status still has a say, but only to exclude accounts that must not
    /// receive mail at all: a locked or administratively disabled account
    /// should not be handed a live token, and a deleted or anonymised
    /// tombstone has no addressee — its `email` column holds a value derived
    /// from the row id, not a mailbox.
    fn may_resend_verification(user: &User) -> bool {
        user.email_verified_at.is_none()
            && matches!(
                user.status,
                UserStatus::PendingVerification | UserStatus::Active
            )
    }

    /// Resend verification email for a user identified by email.
    ///
    /// Returns `Ok(Some((raw_token, user_id, expires_at)))` on
    /// success, `Ok(None)` if the email doesn't exist or the address is
    /// already verified (to prevent user enumeration). The token is bound to
    /// the address stored on the account, which is the one it is mailed to.
    pub async fn resend_verification(
        &self,
        tenant_id: Uuid,
        email: &str,
    ) -> AxiamResult<Option<(String, Uuid, chrono::DateTime<chrono::Utc>)>> {
        // Look up user -- silently return None if not found.
        let user = match self.user_repo.get_by_email(tenant_id, email).await {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(e),
        };

        if !Self::may_resend_verification(&user) {
            return Ok(None);
        }

        // Rate limit: max resends per day. This count is the early refusal;
        // the cap itself is counted again inside the mint below (item 7 of the
        // 1.1.0 atomicity audit), because requests sent together each read a
        // count under the cap here.
        let count = self.token_repo.count_today(tenant_id, user.id).await?;
        if count >= MAX_RESENDS_PER_DAY {
            return Err(AxiamError::RateLimited);
        }

        let raw_token = token::generate_refresh_token();
        let token_hash = token::hash_refresh_token(&raw_token);
        let expires_at = Utc::now() + Duration::hours(TOKEN_EXPIRY_HOURS);

        // One transaction: the cap and the token, bound to the address on the
        // account (the one it is mailed to). Concurrent resends for one account
        // conflict on the user row, so at most the cap's remainder mint.
        match self
            .token_repo
            .create_within_daily_cap(
                CreateEmailVerificationToken {
                    tenant_id,
                    user_id: user.id,
                    token_hash,
                    email: user.email.clone(),
                    expires_at,
                },
                MAX_RESENDS_PER_DAY,
            )
            .await
        {
            Ok(Some(_)) => Ok(Some((raw_token, user.id, expires_at))),
            Ok(None) => Err(AxiamError::RateLimited),
            // The account went between the lookup and the mint: answered as an
            // unknown address is, so the race reveals nothing either.
            Err(AxiamError::NotFound { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Check if a user has any federation links (social/external
    /// IdP). Federated users typically skip email verification.
    pub async fn is_federated_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<bool> {
        let links = self
            .federation_repo
            .get_by_user_id(tenant_id, user_id)
            .await?;
        Ok(!links.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
    use axiam_core::repository::UserRepository;
    use axiam_db::{
        SurrealEmailVerificationTokenRepository, SurrealFederationLinkRepository,
        SurrealUserRepository, run_migrations,
    };
    use surrealdb::engine::local::Db;

    async fn create_test_user(
        user_repo: &SurrealUserRepository<Db>,
        tenant_id: Uuid,
    ) -> axiam_core::models::user::User {
        user_repo
            .create(CreateUser {
                tenant_id,
                username: "testuser".into(),
                email: "test@example.com".into(),
                password: "OldPassw0rd!Strong".into(),
                metadata: None,
            })
            .await
            .unwrap()
    }

    /// Helper: create an org + tenant and return their IDs.
    async fn create_org_tenant(db: &surrealdb::Surreal<Db>) -> (Uuid, Uuid) {
        use axiam_core::models::organization::CreateOrganization;
        use axiam_core::models::tenant::{CreateTenant, TenantKind};
        use axiam_core::repository::{OrganizationRepository, TenantRepository};
        use axiam_db::{SurrealOrganizationRepository, SurrealTenantRepository};

        let org_repo = SurrealOrganizationRepository::new(db.clone());
        let org = org_repo
            .create(CreateOrganization {
                name: "Test Org".into(),
                slug: "test-org".into(),
                metadata: None,
            })
            .await
            .unwrap();

        let tenant_repo = SurrealTenantRepository::new(db.clone());
        let tenant = tenant_repo
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "Test Tenant".into(),
                slug: "test-tenant".into(),
                metadata: None,
            })
            .await
            .unwrap();

        (org.id, tenant.id)
    }

    /// Full setup: DB + org + tenant + user + repos.
    async fn full_setup() -> (
        SurrealUserRepository<Db>,
        SurrealEmailVerificationTokenRepository<Db>,
        SurrealFederationLinkRepository<Db>,
        Uuid, // tenant_id
        axiam_core::models::user::User,
    ) {
        let db = surrealdb::Surreal::new::<surrealdb::engine::local::Mem>(())
            .await
            .unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        run_migrations(&db).await.unwrap();

        let (_org_id, tenant_id) = create_org_tenant(&db).await;

        let user_repo = SurrealUserRepository::new(db.clone());
        let token_repo = SurrealEmailVerificationTokenRepository::new(db.clone());
        let fed_repo = SurrealFederationLinkRepository::new(db.clone());

        let user = create_test_user(&user_repo, tenant_id).await;

        (user_repo, token_repo, fed_repo, tenant_id, user)
    }

    #[tokio::test]
    async fn verify_email_activates_pending_user() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;

        // User starts as PendingVerification.
        assert_eq!(user.status, UserStatus::PendingVerification);

        let svc = EmailVerificationService::new(user_repo.clone(), token_repo, fed_repo);

        let (raw_token, _expires) = svc
            .initiate_verification(tid, user.id, &user.email)
            .await
            .unwrap();

        svc.verify_email(tid, &raw_token).await.unwrap();

        let updated = user_repo.get_by_id(tid, user.id).await.unwrap();
        assert_eq!(updated.status, UserStatus::Active);
        assert!(updated.email_verified_at.is_some());
    }

    /// Item A of the 1.1.0 atomicity audit, the attack: a token minted for the
    /// address the account had (A) is redeemed after the account moved to an
    /// address it does not own (B). It must verify nothing — B stays
    /// unverified and the account stays `PendingVerification`.
    #[tokio::test]
    async fn a_token_for_the_old_address_does_not_verify_the_new_one() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;
        let svc = EmailVerificationService::new(user_repo.clone(), token_repo, fed_repo);

        let (raw_token, _) = svc
            .initiate_verification(tid, user.id, &user.email)
            .await
            .unwrap();

        // The self-service change (`PUT /users/{me}`, SEC-050).
        user_repo
            .update(
                tid,
                user.id,
                UpdateUser {
                    email: Some("victim@b.example".into()),
                    email_verified_at: Some(None),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let err = svc.verify_email(tid, &raw_token).await.unwrap_err();
        assert!(
            matches!(
                err,
                AxiamError::Validation { ref message }
                    if message == &AuthError::VerificationTokenInvalid.to_string()
            ),
            "the old address's token is refused as an invalid token: {err:?}"
        );
        let after = user_repo.get_by_id(tid, user.id).await.unwrap();
        assert_eq!(after.email, "victim@b.example");
        assert!(after.email_verified_at.is_none(), "B must not be verified");
        assert_eq!(after.status, UserStatus::PendingVerification);
    }

    /// The binding itself, not only the deletion an address change makes: a
    /// live token that names an address other than the account's verifies
    /// nothing, and is spent.
    #[tokio::test]
    async fn a_token_bound_to_another_address_verifies_nothing() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;
        let svc = EmailVerificationService::new(user_repo.clone(), token_repo, fed_repo);

        let (raw_token, _) = svc
            .initiate_verification(tid, user.id, "someone-else@example.com")
            .await
            .unwrap();

        assert!(svc.verify_email(tid, &raw_token).await.is_err());
        let after = user_repo.get_by_id(tid, user.id).await.unwrap();
        assert!(after.email_verified_at.is_none());
        assert_eq!(after.status, UserStatus::PendingVerification);
        // Spent: it is not retried against a later state.
        assert!(svc.verify_email(tid, &raw_token).await.is_err());
    }

    /// A token minted before v102 names no address and so vouches for none
    /// (the CHANGELOG's upgrade notes): refused like an unknown token.
    #[tokio::test]
    async fn a_token_minted_before_the_upgrade_is_refused() {
        let db = surrealdb::Surreal::new::<surrealdb::engine::local::Mem>(())
            .await
            .unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        run_migrations(&db).await.unwrap();
        let (_org, tid) = create_org_tenant(&db).await;
        let user_repo = SurrealUserRepository::new(db.clone());
        let user = create_test_user(&user_repo, tid).await;
        let svc = EmailVerificationService::new(
            user_repo.clone(),
            SurrealEmailVerificationTokenRepository::new(db.clone()),
            SurrealFederationLinkRepository::new(db.clone()),
        );

        // The row exactly as 1.0 wrote it: no `email`.
        let raw_token = token::generate_refresh_token();
        db.query(
            "CREATE email_verification_token SET tenant_id = $tid, user_id = $uid, \
             token_hash = $hash, expires_at = time::now() + 1h, consumed_at = NONE",
        )
        .bind(("tid", tid.to_string()))
        .bind(("uid", user.id.to_string()))
        .bind(("hash", token::hash_refresh_token(&raw_token)))
        .await
        .unwrap()
        .check()
        .unwrap();

        assert!(svc.verify_email(tid, &raw_token).await.is_err());
        let after = user_repo.get_by_id(tid, user.id).await.unwrap();
        assert!(after.email_verified_at.is_none());
        assert_eq!(after.status, UserStatus::PendingVerification);
    }

    #[tokio::test]
    async fn replay_consumed_token_fails() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;
        let svc = EmailVerificationService::new(user_repo, token_repo, fed_repo);

        let (raw_token, _expires) = svc
            .initiate_verification(tid, user.id, &user.email)
            .await
            .unwrap();

        // First use succeeds.
        svc.verify_email(tid, &raw_token).await.unwrap();

        // Second use must fail.
        let result = svc.verify_email(tid, &raw_token).await;
        assert!(result.is_err(), "replayed token should be rejected");
    }

    #[tokio::test]
    async fn resend_respects_rate_limit() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;
        let svc = EmailVerificationService::new(user_repo, token_repo, fed_repo);

        // First MAX_RESENDS_PER_DAY resends should succeed.
        for _ in 0..MAX_RESENDS_PER_DAY {
            let result = svc.resend_verification(tid, &user.email).await.unwrap();
            assert!(result.is_some());
        }

        // Next resend should be rate-limited.
        let result = svc.resend_verification(tid, &user.email).await;
        assert!(
            matches!(result, Err(AxiamError::RateLimited)),
            "expected RateLimited, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn resend_returns_none_for_nonexistent_email() {
        let (user_repo, token_repo, fed_repo, tid, _user) = full_setup().await;
        let svc = EmailVerificationService::new(user_repo, token_repo, fed_repo);

        let result = svc
            .resend_verification(tid, "nobody@example.com")
            .await
            .unwrap();

        assert!(
            result.is_none(),
            "unknown email should silently return None"
        );
    }

    /// The regression this replaced a test for.
    ///
    /// The old assertion was that an `Active` user gets `None`, which is what
    /// the code did and what made "Resend verification email" a button that
    /// silently did nothing. `Active` says only that the account may sign in;
    /// it does not say the address was ever confirmed, and an administrator
    /// creating an account produces exactly that combination. The profile page
    /// offers the button on `email_verified_at`, `verify_email` consumes a
    /// token on `email_verified_at`, and now so does this.
    #[tokio::test]
    async fn resend_works_for_an_active_user_whose_address_is_unverified() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;

        user_repo
            .update(
                tid,
                user.id,
                UpdateUser {
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let svc = EmailVerificationService::new(user_repo.clone(), token_repo, fed_repo);
        let result = svc.resend_verification(tid, &user.email).await.unwrap();

        let (raw_token, user_id, _) = result.expect(
            "an Active user with no email_verified_at is unverified and must be resendable",
        );
        assert_eq!(user_id, user.id);

        // And the token it minted actually verifies — the two predicates agree
        // end to end, not just in their conditions.
        svc.verify_email(tid, &raw_token).await.unwrap();
        assert!(
            user_repo
                .get_by_id(tid, user.id)
                .await
                .unwrap()
                .email_verified_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn resend_returns_none_once_the_address_is_verified() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;
        let svc = EmailVerificationService::new(user_repo.clone(), token_repo, fed_repo);

        let (raw_token, _) = svc
            .initiate_verification(tid, user.id, &user.email)
            .await
            .unwrap();
        svc.verify_email(tid, &raw_token).await.unwrap();

        assert!(
            svc.resend_verification(tid, &user.email)
                .await
                .unwrap()
                .is_none(),
            "a verified address has nothing to resend"
        );
    }

    /// Status still excludes accounts that must not be handed a live token.
    ///
    /// Locked and Inactive are administrative refusals; Deleted and Anonymized
    /// are tombstones whose `email` column holds a value derived from the row
    /// id rather than a mailbox, so there is no addressee to mail at all.
    #[tokio::test]
    async fn resend_is_refused_for_statuses_that_must_not_receive_mail() {
        for status in [
            UserStatus::Locked,
            UserStatus::Inactive,
            UserStatus::Deleted,
            UserStatus::Anonymized,
        ] {
            let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;
            user_repo
                .update(
                    tid,
                    user.id,
                    UpdateUser {
                        status: Some(status.clone()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();

            let svc = EmailVerificationService::new(user_repo, token_repo, fed_repo);
            assert!(
                svc.resend_verification(tid, &user.email)
                    .await
                    .unwrap()
                    .is_none(),
                "{status:?} must not be sent a verification token"
            );
        }
    }

    #[tokio::test]
    async fn verify_inactive_user_sets_verified_but_stays_inactive() {
        let (user_repo, token_repo, fed_repo, tid, user) = full_setup().await;

        // Admin-disable the user.
        user_repo
            .update(
                tid,
                user.id,
                UpdateUser {
                    status: Some(UserStatus::Inactive),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let svc = EmailVerificationService::new(user_repo.clone(), token_repo, fed_repo);

        let (raw_token, _expires) = svc
            .initiate_verification(tid, user.id, &user.email)
            .await
            .unwrap();

        svc.verify_email(tid, &raw_token).await.unwrap();

        let updated = user_repo.get_by_id(tid, user.id).await.unwrap();
        assert_eq!(
            updated.status,
            UserStatus::Inactive,
            "admin-disabled user must stay Inactive after verification"
        );
        assert!(
            updated.email_verified_at.is_some(),
            "email_verified_at should still be set"
        );
    }
}
