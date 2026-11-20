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
//! 1. **Before minting**: refuse when [`changed_after`] says the credential
//!    changed after the grant was issued.
//! 2. **After the refresh token is created**: re-read the user
//!    ([`recheck_after_mint`]). A change can land between the pre-check and the
//!    write, and its `revoke_all_for_user` may already have run. A credential
//!    write commits BEFORE its revocation, so either the change is visible to
//!    the re-read (the new token is revoked here) or it commits later and its
//!    revocation removes the token itself. A later change, or a user that no
//!    longer exists, revokes what was minted and answers `invalid_grant`; a read
//!    error revokes it too and answers a server error.
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

/// Whether `user`'s credential changed after a grant was issued at
/// `issued_at`. Both are datastore times. `false` for a user with no change on
/// record.
#[must_use]
pub(crate) fn changed_after(user: &User, issued_at: DateTime<Utc>) -> bool {
    user.credential_changed_at
        .is_some_and(|changed| changed > issued_at)
}

/// Re-read the user after the refresh token `minted_hash` was created from a
/// grant issued at `issued_at`; revoke the token and refuse if the credential
/// has changed since (see the module docs).
pub(crate) async fn recheck_after_mint<UR, RT>(
    users: &UR,
    refresh_tokens: &RT,
    tenant_id: Uuid,
    user_id: Uuid,
    issued_at: DateTime<Utc>,
    minted_hash: &str,
) -> Result<(), OAuth2Error>
where
    UR: UserRepository,
    RT: RefreshTokenRepository,
{
    let moved = match users.get_by_id(tenant_id, user_id).await {
        Ok(user) => Ok(changed_after(&user, issued_at)),
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
        _ => Err(OAuth2Error::InvalidGrant(REFUSED.into())),
    }
}
