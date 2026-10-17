//! Email verification token model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A hashed email verification token stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// SHA-256 hash of the raw token (raw token is never stored).
    pub token_hash: String,
    /// The address the token was minted for, and mailed to (schema v102).
    ///
    /// A token vouches for one mailbox: redeeming it verifies the account only
    /// while the account's address is still this one. `None` on a token minted
    /// before 1.1.0, which no longer verifies anything (the upgrade notes say
    /// so; a fresh one is a resend away).
    pub email: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new verification token.
#[derive(Debug, Clone)]
pub struct CreateEmailVerificationToken {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    /// The address the token is mailed to. Redemption verifies the account
    /// only while its address is still exactly this one.
    pub email: String,
    pub expires_at: DateTime<Utc>,
}

/// What redeeming a verification token did (`UserRepository::
/// redeem_email_verification`).
///
/// A token that is unknown, expired, already consumed, or minted before
/// v102 bound tokens to an address is not an outcome: it is `NotFound`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailVerificationRedemption {
    /// The token was consumed and the account's address marked verified (and
    /// a `PendingVerification` account made `Active`), in one transaction.
    Verified {
        /// The account the token belonged to.
        user_id: Uuid,
    },
    /// The token was consumed, but the address it names was already verified.
    AlreadyVerified,
    /// The token was consumed and verified nothing: the account's address is
    /// no longer the one the token was mailed to (or the account is gone).
    AddressMismatch,
}
