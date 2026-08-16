//! SCIM provisioning tokens — the long-lived credential an IdP pastes once.
//!
//! See `claude_dev/scim-provisioning-token-design.md` for the reasoning. The
//! two properties everything else follows from:
//!
//! 1. **A token is accepted on `/scim/v2/*` and nowhere else.** It is not a
//!    general-purpose API key. AXIAM's security standards say short-lived
//!    access tokens; a year-long credential is defensible here only because
//!    its blast radius is one route family that an external IdP drives.
//!
//! 2. **A token carries no permissions.** It resolves to a tenant user, and
//!    that user's RBAC decides everything through the same
//!    `scim:provision` check that already runs. Unassign the role or
//!    deactivate the user and every token bound to them stops working —
//!    revocation an operator already knows how to perform.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Prefix on every issued handle.
///
/// Load-bearing rather than cosmetic. A credential designed to be pasted into
/// a third-party console and left there will eventually be pasted somewhere
/// else by mistake, and a fixed greppable prefix is what lets a secret scanner
/// (GitGuardian and GitHub secret scanning both run on this repo), or an
/// operator with `grep`, find it. An unadorned base64 blob is indistinguishable
/// from every other opaque blob in a config file.
///
/// It is also what makes credential resolution a dispatch rather than a guess —
/// see `axiam_scim::auth::ScimPrincipal`.
pub const SCIM_TOKEN_PREFIX: &str = "axiam_scim_";

/// Entropy behind the handle. 256 bits, the same as every other opaque bearer
/// handle in the system (refresh tokens, device codes, UMA tickets).
pub const SCIM_TOKEN_ENTROPY_BYTES: usize = 32;

/// The permission a token's bound user must hold for the token to be able to
/// do anything.
///
/// Declared here — rather than only in `axiam_scim::auth`, which owns the
/// enforcement — because the mint endpoint in `axiam-api-rest` has to check it
/// before issuing a credential, and `axiam-api-rest` cannot depend on
/// `axiam-scim` (that dependency runs the other way). `axiam_scim::auth`
/// re-exports this rather than declaring a second copy: two string literals
/// that must agree is one literal too many.
pub const SCIM_PROVISION_ACTION: &str = "scim:provision";

/// Default ceiling on a token's lifetime, in days, when the deployment sets no
/// other. Overridable via `AXIAM__SCIM_TOKEN_MAX_LIFETIME_DAYS`.
///
/// There is deliberately no "never expires" option. A credential with no expiry
/// is one nobody revisits, and the entire point of pasting it into an IdP is
/// that it then leaves the operator's sight. A bounded lifetime forces one
/// deliberate renewal decision a year rather than none, ever.
pub const DEFAULT_MAX_LIFETIME_DAYS: i64 = 365;

/// A provisioning token as stored. The plaintext handle is **not** a field:
/// only its hash is ever persisted, and the plaintext is returned exactly once
/// at creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// The tenant user this token authenticates as. Its RBAC — not anything
    /// on this row — decides what the token may do.
    pub user_id: Uuid,
    /// Operator-facing label, e.g. `"okta-production"`. Exists so a tenant
    /// with several IdPs can revoke the right one without guessing from
    /// timestamps.
    pub name: String,
    /// SHA-256 of the handle, hex-encoded — the same treatment
    /// `axiam_auth::token::hash_refresh_token` gives a refresh token.
    pub token_hash: String,
    /// The administrator who minted it. Distinct from `user_id`: minting a
    /// credential for a provisioner is an administrative act by somebody else.
    pub created_by: Uuid,
    pub expires_at: DateTime<Utc>,
    /// Stamped on each accepted request, best-effort — a failure to record use
    /// must never fail the request it describes.
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ScimToken {
    /// Whether this token may still authenticate, as of `now`.
    ///
    /// Revocation and expiry are checked together and answer the same way,
    /// because the wire response does not distinguish them either — an
    /// attacker probing handles must not learn which arm rejected them.
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }

    /// Presentation status for the admin list.
    pub fn status(&self, now: DateTime<Utc>) -> ScimTokenStatus {
        if self.revoked_at.is_some() {
            ScimTokenStatus::Revoked
        } else if self.expires_at <= now {
            ScimTokenStatus::Expired
        } else {
            ScimTokenStatus::Active
        }
    }
}

/// Why a token is or is not currently usable — for display only. The
/// authentication path never surfaces this distinction on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScimTokenStatus {
    Active,
    Expired,
    Revoked,
}

/// Input for minting a token. `token_hash` is computed by the caller so this
/// type never holds the plaintext.
#[derive(Debug, Clone)]
pub struct CreateScimToken {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub created_by: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn token(expires_in: Duration, revoked: bool) -> ScimToken {
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        ScimToken {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            user_id: Uuid::nil(),
            name: "okta".into(),
            token_hash: "deadbeef".into(),
            created_by: Uuid::nil(),
            expires_at: now + expires_in,
            last_used_at: None,
            revoked_at: revoked.then_some(now),
            created_at: now,
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn a_live_token_is_usable() {
        assert!(token(Duration::days(30), false).is_usable(now()));
        assert_eq!(
            token(Duration::days(30), false).status(now()),
            ScimTokenStatus::Active
        );
    }

    #[test]
    fn an_expired_token_is_not_usable() {
        assert!(!token(Duration::days(-1), false).is_usable(now()));
        assert_eq!(
            token(Duration::days(-1), false).status(now()),
            ScimTokenStatus::Expired
        );
    }

    #[test]
    fn a_revoked_token_is_not_usable_even_before_its_expiry() {
        assert!(!token(Duration::days(30), true).is_usable(now()));
        assert_eq!(
            token(Duration::days(30), true).status(now()),
            ScimTokenStatus::Revoked
        );
    }

    /// Revocation is reported ahead of expiry: an operator who revoked a token
    /// wants to see that they did, not that it later lapsed on its own.
    #[test]
    fn revoked_wins_over_expired_in_the_status_display() {
        assert_eq!(
            token(Duration::days(-1), true).status(now()),
            ScimTokenStatus::Revoked
        );
    }

    /// Exactly-at-expiry is expired, not active — `expires_at > now`.
    #[test]
    fn expiry_boundary_is_exclusive() {
        assert!(!token(Duration::zero(), false).is_usable(now()));
    }
}
