//! A grant issued before a credential change mints nothing after it
//! (SA-06, N7; review SR17-1).
//!
//! A password reset, a password change and a SCIM password write stamp the
//! user's `credential_changed_at` (with the datastore's clock, so it compares
//! with the `created_at` of every row below) and revoke the user's sessions
//! and refresh tokens. They cannot revoke what does not exist yet: an
//! authorization code, a device-flow approval or a CIBA approval that was
//! issued under the OLD credential and is redeemed AFTER the change would mint
//! a refresh token the revocation never saw, and that token passes the refresh
//! grant's own check because its `created_at` is later than the change.
//!
//! Each of the three redemption paths therefore applies two rules, both defined
//! here so they cannot drift apart:
//!
//! 1. **Before minting**: refuse when [`changed_since`] says the credential
//!    changed at or after the grant was issued.
//! 2. **After the refresh token is created**: re-read the user
//!    ([`recheck_after_mint`]). A change can land between the pre-check and the
//!    write, and its `revoke_all_for_user` may already have run. A credential
//!    write commits BEFORE its revocation, so either the change is visible to
//!    the re-read (the new token is revoked here) or it commits later and its
//!    revocation removes the token itself. A change at or after the grant's time,
//!    or a user that no longer exists, revokes what was minted and answers `invalid_grant`; a read
//!    error revokes it too and answers a server error.
//!
//! The refresh grant's own rotation applies rule 2 through the same helper
//! (with its own refusal text), so the four copies cannot diverge.
//!
//! **The tie rule, defined once.** Both rules refuse when the change is *at or
//! after* the grant's time ([`User::credential_changed_since`]): a grant issued
//! at the very instant of a change cannot be shown to postdate it, and the safe
//! answer to "is this grant older than the change" is to refuse. The price of a
//! tie (which needs two statements to read one datastore instant) is a sign-in
//! repeated.
//!
//! Session rotation in `axiam-auth` (the versionless legacy-row arm) applies the
//! same rule through the same method, so there is one tie rule in the codebase,
//! defined by [`User::credential_changed_since`].
//!
//! A user with no stored `credential_changed_at` is refused nothing.

use axiam_core::error::AxiamError;
use axiam_core::models::user::User;
use axiam_core::repository::{RefreshTokenRepository, UserRepository};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::OAuth2Error;

/// The `invalid_grant` description for a grant refused because the credential
/// it was issued under has since changed. Identical to the one the account
/// checks beside it already give.
pub(crate) const REFUSED: &str = "the account this grant was issued for can no longer sign in";

/// Whether `user`'s credential changed at or after a grant was issued at
/// `issued_at` (a tie refuses: see the module docs). Both are datastore times.
/// `false` for a user with no change on record.
#[must_use]
pub(crate) fn changed_since(user: &User, issued_at: DateTime<Utc>) -> bool {
    user.credential_changed_since(issued_at)
}

/// Re-read the user after the refresh token `minted_hash` was created from a
/// grant issued at `issued_at`; revoke the token and refuse if the credential
/// has changed since (see the module docs). `refusal` is the `invalid_grant`
/// description for the changed and removed-user outcomes: [`REFUSED`] for the
/// three redemptions, the refresh grant's own text for a rotation.
pub(crate) async fn recheck_after_mint<UR, RT>(
    users: &UR,
    refresh_tokens: &RT,
    tenant_id: Uuid,
    user_id: Uuid,
    issued_at: DateTime<Utc>,
    minted_hash: &str,
    refusal: &str,
) -> Result<(), OAuth2Error>
where
    UR: UserRepository,
    RT: RefreshTokenRepository,
{
    let moved = match users.get_by_id(tenant_id, user_id).await {
        Ok(user) => Ok(changed_since(&user, issued_at)),
        Err(AxiamError::NotFound { .. }) => Ok(true),
        Err(e) => Err(e),
    };
    if matches!(moved, Ok(false)) {
        return Ok(());
    }
    // Never leave the token behind, whatever the cause.
    if let Err(cleanup_err) = refresh_tokens.revoke(tenant_id, minted_hash).await {
        tracing::warn!(
            error = %cleanup_err,
            "grant: failed to revoke a refresh token refused by the credential re-check; \
             token may linger"
        );
    }
    match moved {
        Err(e) => Err(OAuth2Error::ServerError(e.to_string())),
        _ => Err(OAuth2Error::InvalidGrant(refusal.into())),
    }
}

#[cfg(test)]
mod tests {
    //! QR18-1: the helper's outcomes against the real repositories on an
    //! in-memory datastore, and the tie rule (QR18-4).

    use axiam_core::models::oauth2_client::CreateRefreshToken;
    use axiam_core::models::user::{CreateUser, UpdateUser};
    use axiam_db::repository::{SurrealRefreshTokenRepository, SurrealUserRepository};
    use chrono::Duration;
    use surrealdb::Surreal;
    use surrealdb::engine::local::{Db, Mem};

    use super::*;

    const CUSTOM_REFUSAL: &str = "a caller's own refusal text";

    struct Rig {
        db: Surreal<Db>,
        users: SurrealUserRepository<Db>,
        tokens: SurrealRefreshTokenRepository<Db>,
        tenant_id: Uuid,
        user: User,
    }

    async fn rig() -> Rig {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let users = SurrealUserRepository::new(db.clone());
        let tenant_id = Uuid::new_v4();
        let user = users
            .create(CreateUser {
                tenant_id,
                username: "epoch-user".into(),
                email: "epoch-user@example.com".into(),
                // Generated per run: a literal reads as a hard-coded credential (CodeQL).
                password: format!("Fx1!{}", Uuid::new_v4().simple()),
                metadata: None,
            })
            .await
            .unwrap();
        Rig {
            tokens: SurrealRefreshTokenRepository::new(db.clone()),
            users,
            db,
            tenant_id,
            user,
        }
    }

    /// A password write: the repository stamps `credential_changed_at`.
    async fn change_credential(r: &Rig) -> User {
        r.users
            .update(
                r.tenant_id,
                r.user.id,
                UpdateUser {
                    password_hash: Some("$argon2id$replacement".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }

    async fn mint(r: &Rig, hash: &str) {
        r.tokens
            .create(CreateRefreshToken {
                tenant_id: r.tenant_id,
                token_hash: hash.into(),
                client_id: "client".into(),
                user_id: Some(r.user.id),
                scopes: vec!["openid".into()],
                session_id: None,
                requested_userinfo_claims: Vec::new(),
                resource: None,
                auth_time: None,
                acr: None,
                amr: Vec::new(),
                dpop_jkt: None,
                expires_at: Utc::now() + Duration::days(1),
                lineage_id: None,
            })
            .await
            .unwrap();
    }

    async fn token_is_live(r: &Rig, hash: &str) -> bool {
        r.tokens.get_by_token_hash(r.tenant_id, hash).await.is_ok()
    }

    async fn recheck(
        r: &Rig,
        user_id: Uuid,
        issued_at: DateTime<Utc>,
        hash: &str,
    ) -> Result<(), OAuth2Error> {
        recheck_after_mint(
            &r.users,
            &r.tokens,
            r.tenant_id,
            user_id,
            issued_at,
            hash,
            CUSTOM_REFUSAL,
        )
        .await
    }

    #[tokio::test]
    async fn no_change_keeps_the_token() {
        let r = rig().await;
        mint(&r, "h-keep").await;
        // A user with no change on record is refused nothing.
        recheck(&r, r.user.id, Utc::now() - Duration::hours(1), "h-keep")
            .await
            .expect("no credential change: Ok");
        assert!(token_is_live(&r, "h-keep").await, "the token survives");
        // A change that predates the grant is no change after it.
        change_credential(&r).await;
        recheck(&r, r.user.id, Utc::now() + Duration::hours(1), "h-keep")
            .await
            .expect("a change before the grant: Ok");
        assert!(token_is_live(&r, "h-keep").await, "the token survives");
    }

    #[tokio::test]
    async fn a_later_change_revokes_exactly_the_minted_token_and_says_invalid_grant() {
        let r = rig().await;
        mint(&r, "h-minted").await;
        mint(&r, "h-other").await;
        change_credential(&r).await;
        let err = recheck(&r, r.user.id, Utc::now() - Duration::hours(1), "h-minted")
            .await
            .unwrap_err();
        assert!(
            matches!(&err, OAuth2Error::InvalidGrant(d) if d == CUSTOM_REFUSAL),
            "expected invalid_grant with the caller's text, got {err:?}"
        );
        assert!(!token_is_live(&r, "h-minted").await, "revoked");
        assert!(token_is_live(&r, "h-other").await, "only the minted one");
    }

    #[tokio::test]
    async fn a_removed_user_revokes_the_token_and_says_invalid_grant() {
        let r = rig().await;
        mint(&r, "h-gone").await;
        let err = recheck(&r, Uuid::new_v4(), Utc::now(), "h-gone")
            .await
            .unwrap_err();
        assert!(
            matches!(&err, OAuth2Error::InvalidGrant(d) if d == CUSTOM_REFUSAL),
            "expected invalid_grant, got {err:?}"
        );
        assert!(!token_is_live(&r, "h-gone").await, "revoked");
    }

    #[tokio::test]
    async fn a_read_error_revokes_the_token_and_says_server_error() {
        let r = rig().await;
        mint(&r, "h-err").await;
        // Every read of the user row now fails with a datastore error.
        r.db.query("DEFINE FIELD boom ON user COMPUTED (THROW 'user read failed')")
            .await
            .unwrap()
            .check()
            .unwrap();
        let err = recheck(&r, r.user.id, Utc::now(), "h-err")
            .await
            .unwrap_err();
        assert!(
            matches!(err, OAuth2Error::ServerError(_)),
            "expected server_error, got {err:?}"
        );
        assert!(!token_is_live(&r, "h-err").await, "revoked");
    }

    /// QR18-4: a change AT the grant's time refuses (fails closed), like
    /// `User::credential_changed_since`.
    #[tokio::test]
    async fn a_tie_refuses() {
        let r = rig().await;
        let changed = change_credential(&r).await;
        let epoch = changed.credential_changed_at.expect("the write stamps it");
        assert!(changed_since(&changed, epoch), "equal timestamps: refused");
        assert!(changed_since(&changed, epoch - Duration::nanoseconds(1)));
        assert!(!changed_since(&changed, epoch + Duration::nanoseconds(1)));
        assert!(!changed_since(&r.user, epoch), "no change on record");

        mint(&r, "h-tie").await;
        let err = recheck(&r, r.user.id, epoch, "h-tie").await.unwrap_err();
        assert!(matches!(err, OAuth2Error::InvalidGrant(_)), "{err:?}");
        assert!(!token_is_live(&r, "h-tie").await, "revoked");
    }
}
