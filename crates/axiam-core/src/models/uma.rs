//! UMA 2.0 domain model (X2) — permission tickets and RPT permissions.
//!
//! See `claude_dev/uma-mapping-design.md` for the one decision the rest of
//! this module follows from: **a UMA resource scope is an AXIAM `action`**,
//! evaluated against the registered resource, and a resource's declared scope
//! set is the allow-list of names a resource server may ask for rather than an
//! input to the decision.
//!
//! # Why the ticket is a server-side record and not a JWT
//!
//! Keycloak encodes permission tickets as signed JWTs. That makes them
//! stateless and makes single-use unenforceable — a client that replays a
//! ticket inside its lifetime gets a second RPT, because there is nowhere to
//! record that the first one happened. UMA 2.0 §3.3 requires a ticket to be
//! single-use, so it is stored: the row is what makes "already used" a fact
//! rather than an intention.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// How long a permission ticket is valid (UMA 2.0 §3.3 leaves this to the
/// server; 60 s is Keycloak's default and is the whole round trip a client
/// needs — request ticket, authenticate, exchange).
pub const TICKET_TTL_SECS: i64 = 60;

/// Default ceiling on an RPT's lifetime. The effective lifetime is the
/// **minimum** of the subject token's remaining life, the configured maximum,
/// and this — see [`rpt_lifetime_secs`].
pub const DEFAULT_RPT_MAX_LIFETIME_SECS: i64 = 300;

/// Ticket handle entropy. 256 bits, same as every other opaque bearer handle
/// in the system (refresh tokens, device codes, `request_uri`).
pub const TICKET_ENTROPY_BYTES: usize = 32;

/// The scope a Protection API Token must carry to use the resource
/// registration and permission endpoints. A PAT is an ordinary AXIAM access
/// token; this scope is what makes it a PAT.
pub const UMA_PROTECTION_SCOPE: &str = "uma_protection";

/// The grant type that exchanges a ticket for an RPT (UMA 2.0 §3.3.1).
pub const UMA_TICKET_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:uma-ticket";

// ---------------------------------------------------------------------------
// Requested and granted permissions
// ---------------------------------------------------------------------------

/// One `(resource, scopes)` pair a resource server requires, as posted to
/// `/uma2/perm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RequestedPermission {
    /// The AXIAM resource id. UMA's `_id` **is** the AXIAM resource id — there
    /// is no parallel resource store to translate through.
    pub resource_id: Uuid,
    /// Scope names, each of which must be declared by the resource. Matched
    /// exactly: no prefix or wildcard semantics in either direction.
    pub resource_scopes: Vec<String>,
}

/// One entry of an RPT's `permissions` claim.
///
/// Field names are Keycloak's (`rsid`/`rsname` aliases aside) so that a
/// resource server migrating from Keycloak can read an AXIAM RPT without a
/// translation layer — the compatibility the §X2 introspection test pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RptPermission {
    pub resource_id: Uuid,
    pub resource_scopes: Vec<String>,
    /// Absolute expiry, seconds since the epoch. Carried per-permission
    /// because UMA allows an RPT to accumulate permissions with different
    /// lifetimes; AXIAM issues them uniformly in v1 but the shape must not
    /// foreclose that.
    pub exp: i64,
}

// ---------------------------------------------------------------------------
// The ticket
// ---------------------------------------------------------------------------

/// A permission ticket: the resource server's statement of what the client
/// would need, redeemable exactly once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionTicket {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// SHA-256 of the ticket handle. The plaintext is a bearer credential for
    /// the 60 s it lives, so it is never stored — the same posture as device
    /// codes, refresh tokens and `request_uri`.
    pub ticket_hash: String,
    /// The resource server that minted it. The exchange is refused if a
    /// different client presents it (§X2: "tickets are bound to the requesting
    /// resource-server client_id"), so a ticket leaked to another client is
    /// not a usable credential.
    pub client_id: String,
    pub permissions: Vec<RequestedPermission>,
    /// Set on redemption. The row is marked rather than deleted so "already
    /// used" and "never existed" stay distinguishable in the audit trail, even
    /// though both answer `invalid_grant` on the wire.
    pub consumed: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Input for minting a ticket.
#[derive(Debug, Clone)]
pub struct CreatePermissionTicket {
    pub tenant_id: Uuid,
    pub ticket_hash: String,
    pub client_id: String,
    pub permissions: Vec<RequestedPermission>,
    pub expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Redemption
// ---------------------------------------------------------------------------

/// Why a ticket cannot be redeemed.
///
/// Every variant answers `invalid_grant` on the wire — the distinctions are
/// for the audit trail and for tests, not for the client. Telling a caller
/// *which* of these it hit would let it probe for valid ticket handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketRejection {
    /// No row for this handle. Also what a forged handle looks like.
    Unknown,
    /// Already redeemed. UMA 2.0 §3.3 single-use.
    Consumed,
    /// Past `expires_at`.
    Expired,
    /// Presented by a client other than the one it was minted for.
    WrongClient,
}

impl TicketRejection {
    /// The OAuth2 error code carried on the wire. Deliberately the same for
    /// every variant.
    pub const fn wire_error(&self) -> &'static str {
        "invalid_grant"
    }

    /// A stable slug for the audit record.
    pub const fn audit_reason(&self) -> &'static str {
        match self {
            Self::Unknown => "ticket_unknown",
            Self::Consumed => "ticket_consumed",
            Self::Expired => "ticket_expired",
            Self::WrongClient => "ticket_wrong_client",
        }
    }
}

impl std::fmt::Display for TicketRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Unknown => "permission ticket not found",
            Self::Consumed => "permission ticket has already been used",
            Self::Expired => "permission ticket has expired",
            Self::WrongClient => "permission ticket was issued to another client",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for TicketRejection {}

impl PermissionTicket {
    /// Whether this ticket may be redeemed *now* by `client_id`.
    ///
    /// Checks are ordered so the cheapest and least informative failure wins:
    /// a caller must not be able to distinguish "expired" from "wrong client"
    /// by timing which check ran.
    pub fn check_redeemable(
        &self,
        client_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), TicketRejection> {
        if self.consumed {
            return Err(TicketRejection::Consumed);
        }
        if now >= self.expires_at {
            return Err(TicketRejection::Expired);
        }
        if self.client_id != client_id {
            return Err(TicketRejection::WrongClient);
        }
        Ok(())
    }

    /// Every `(resource_id, scope)` pair this ticket asks for, flattened.
    ///
    /// This is the exact list the engine must allow **in full** — v1 refuses
    /// partial grants rather than trimming (see the design note).
    pub fn requested_pairs(&self) -> Vec<(Uuid, String)> {
        self.permissions
            .iter()
            .flat_map(|p| {
                p.resource_scopes
                    .iter()
                    .map(move |s| (p.resource_id, s.clone()))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Why a permission request was refused at `/uma2/perm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionRequestError {
    /// `permissions` was empty, or an entry named no scopes. A ticket for
    /// nothing is a ticket that can only ever mint an empty RPT.
    NoPermissions,
    /// A scope name the resource has not declared. Refused here rather than
    /// evaluated and denied, because "this resource has no such scope" and
    /// "you may not have it" are different answers and the resource server
    /// should be able to act on the difference.
    UndeclaredScope { resource_id: Uuid, scope: String },
    /// A blank scope name.
    BlankScope(Uuid),
    /// The same scope named twice for one resource. Refused rather than
    /// deduplicated so a resource server notices it is generating junk.
    DuplicateScope { resource_id: Uuid, scope: String },
}

impl std::fmt::Display for PermissionRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPermissions => {
                write!(
                    f,
                    "a permission request must name at least one resource scope"
                )
            }
            Self::UndeclaredScope { resource_id, scope } => write!(
                f,
                "resource {resource_id} does not declare a scope named '{scope}'"
            ),
            Self::BlankScope(resource_id) => {
                write!(f, "resource {resource_id} was given a blank scope name")
            }
            Self::DuplicateScope { resource_id, scope } => write!(
                f,
                "resource {resource_id} names scope '{scope}' more than once"
            ),
        }
    }
}

impl std::error::Error for PermissionRequestError {}

/// Validate a permission request against each resource's declared scope set.
///
/// `declared` answers "which scope names does this resource expose" — the
/// `Scope` rows for that resource. A resource absent from `declared` has
/// declared nothing, so every scope asked of it is undeclared; that is the
/// same answer as an unregistered resource, deliberately, so a probe cannot
/// distinguish "no such resource" from "no such scope".
pub fn validate_permission_request(
    requested: &[RequestedPermission],
    declared: &dyn Fn(Uuid) -> Vec<String>,
) -> Result<(), PermissionRequestError> {
    if requested.is_empty() || requested.iter().all(|p| p.resource_scopes.is_empty()) {
        return Err(PermissionRequestError::NoPermissions);
    }

    for perm in requested {
        if perm.resource_scopes.is_empty() {
            return Err(PermissionRequestError::NoPermissions);
        }
        let available = declared(perm.resource_id);
        let mut seen: Vec<&str> = Vec::with_capacity(perm.resource_scopes.len());

        for scope in &perm.resource_scopes {
            if scope.trim().is_empty() {
                return Err(PermissionRequestError::BlankScope(perm.resource_id));
            }
            if seen.contains(&scope.as_str()) {
                return Err(PermissionRequestError::DuplicateScope {
                    resource_id: perm.resource_id,
                    scope: scope.clone(),
                });
            }
            seen.push(scope);

            // Exact match only — see the design note. A prefix rule here would
            // let `album:view` quietly satisfy a request for
            // `album:view:thumbnail`.
            if !available.iter().any(|d| d == scope) {
                return Err(PermissionRequestError::UndeclaredScope {
                    resource_id: perm.resource_id,
                    scope: scope.clone(),
                });
            }
        }
    }
    Ok(())
}

/// The lifetime an RPT should get, in seconds.
///
/// The minimum of the subject token's remaining life, the deployment's
/// configured maximum, and [`DEFAULT_RPT_MAX_LIFETIME_SECS`]. An RPT must never
/// outlive the token that authorised it: the subject's session ending is the
/// event that should end the RPT's authority, and an RPT that survived it would
/// be a credential nobody can revoke by logging out.
///
/// Returns `None` when the subject token has already expired — there is no
/// positive lifetime to issue, and issuing a zero-length RPT would be a token
/// that is dead on arrival rather than an error the client can act on.
pub fn rpt_lifetime_secs(subject_remaining_secs: i64, configured_max_secs: i64) -> Option<i64> {
    if subject_remaining_secs <= 0 {
        return None;
    }
    // Floor of 1 so a misconfigured `configured_max_secs` of 0 or a negative
    // value yields a token with *some* life rather than one that is already
    // expired when it is handed over.
    let ceiling = configured_max_secs.clamp(1, DEFAULT_RPT_MAX_LIFETIME_SECS);
    Some(subject_remaining_secs.min(ceiling))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn ticket(consumed: bool, expires_in: i64, client: &str) -> PermissionTicket {
        PermissionTicket {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            ticket_hash: "h".into(),
            client_id: client.into(),
            permissions: vec![],
            consumed,
            expires_at: Utc::now() + Duration::seconds(expires_in),
            created_at: Utc::now(),
        }
    }

    // -- redemption ---------------------------------------------------------

    #[test]
    fn fresh_ticket_from_its_own_client_is_redeemable() {
        let t = ticket(false, 60, "rs-1");
        assert!(t.check_redeemable("rs-1", Utc::now()).is_ok());
    }

    #[test]
    fn consumed_ticket_is_refused() {
        let t = ticket(true, 60, "rs-1");
        assert_eq!(
            t.check_redeemable("rs-1", Utc::now()),
            Err(TicketRejection::Consumed)
        );
    }

    #[test]
    fn expired_ticket_is_refused() {
        let t = ticket(false, -1, "rs-1");
        assert_eq!(
            t.check_redeemable("rs-1", Utc::now()),
            Err(TicketRejection::Expired)
        );
    }

    /// A ticket leaked to another client must not be usable by it.
    #[test]
    fn ticket_presented_by_another_client_is_refused() {
        let t = ticket(false, 60, "rs-1");
        assert_eq!(
            t.check_redeemable("rs-2", Utc::now()),
            Err(TicketRejection::WrongClient)
        );
    }

    /// Every rejection is the same code on the wire; only the audit slug
    /// differs. A client that could tell them apart could probe for handles.
    #[test]
    fn every_rejection_is_invalid_grant_on_the_wire() {
        for r in [
            TicketRejection::Unknown,
            TicketRejection::Consumed,
            TicketRejection::Expired,
            TicketRejection::WrongClient,
        ] {
            assert_eq!(r.wire_error(), "invalid_grant");
        }
    }

    #[test]
    fn audit_reasons_are_distinct() {
        let slugs = [
            TicketRejection::Unknown.audit_reason(),
            TicketRejection::Consumed.audit_reason(),
            TicketRejection::Expired.audit_reason(),
            TicketRejection::WrongClient.audit_reason(),
        ];
        let mut sorted = slugs.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            slugs.len(),
            "audit slugs must be distinguishable"
        );
    }

    // -- pair flattening ----------------------------------------------------

    #[test]
    fn requested_pairs_flattens_every_resource_scope_combination() {
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        let mut t = ticket(false, 60, "rs-1");
        t.permissions = vec![
            RequestedPermission {
                resource_id: r1,
                resource_scopes: vec!["view".into(), "edit".into()],
            },
            RequestedPermission {
                resource_id: r2,
                resource_scopes: vec!["view".into()],
            },
        ];
        let pairs = t.requested_pairs();
        assert_eq!(pairs.len(), 3);
        assert!(pairs.contains(&(r1, "view".to_string())));
        assert!(pairs.contains(&(r1, "edit".to_string())));
        assert!(pairs.contains(&(r2, "view".to_string())));
    }

    // -- validation ---------------------------------------------------------

    fn declares(scopes: &'static [&'static str]) -> impl Fn(Uuid) -> Vec<String> {
        move |_| scopes.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn declared_scopes_validate() {
        let req = vec![RequestedPermission {
            resource_id: Uuid::new_v4(),
            resource_scopes: vec!["view".into(), "edit".into()],
        }];
        assert!(validate_permission_request(&req, &declares(&["view", "edit", "delete"])).is_ok());
    }

    #[test]
    fn empty_request_is_refused() {
        assert_eq!(
            validate_permission_request(&[], &declares(&["view"])),
            Err(PermissionRequestError::NoPermissions)
        );
    }

    #[test]
    fn permission_naming_no_scopes_is_refused() {
        let req = vec![RequestedPermission {
            resource_id: Uuid::new_v4(),
            resource_scopes: vec![],
        }];
        assert_eq!(
            validate_permission_request(&req, &declares(&["view"])),
            Err(PermissionRequestError::NoPermissions)
        );
    }

    #[test]
    fn undeclared_scope_is_refused() {
        let id = Uuid::new_v4();
        let req = vec![RequestedPermission {
            resource_id: id,
            resource_scopes: vec!["delete".into()],
        }];
        assert_eq!(
            validate_permission_request(&req, &declares(&["view", "edit"])),
            Err(PermissionRequestError::UndeclaredScope {
                resource_id: id,
                scope: "delete".into()
            })
        );
    }

    /// An unregistered resource declares nothing, so it fails the same way an
    /// undeclared scope does — a probe cannot tell the two apart.
    #[test]
    fn unregistered_resource_is_indistinguishable_from_undeclared_scope() {
        let id = Uuid::new_v4();
        let req = vec![RequestedPermission {
            resource_id: id,
            resource_scopes: vec!["view".into()],
        }];
        assert_eq!(
            validate_permission_request(&req, &declares(&[])),
            Err(PermissionRequestError::UndeclaredScope {
                resource_id: id,
                scope: "view".into()
            })
        );
    }

    #[test]
    fn blank_scope_is_refused() {
        let id = Uuid::new_v4();
        let req = vec![RequestedPermission {
            resource_id: id,
            resource_scopes: vec!["  ".into()],
        }];
        assert_eq!(
            validate_permission_request(&req, &declares(&["view"])),
            Err(PermissionRequestError::BlankScope(id))
        );
    }

    #[test]
    fn duplicate_scope_is_refused() {
        let id = Uuid::new_v4();
        let req = vec![RequestedPermission {
            resource_id: id,
            resource_scopes: vec!["view".into(), "view".into()],
        }];
        assert_eq!(
            validate_permission_request(&req, &declares(&["view"])),
            Err(PermissionRequestError::DuplicateScope {
                resource_id: id,
                scope: "view".into()
            })
        );
    }

    /// Exact matching: a declared prefix must not satisfy a longer request.
    #[test]
    fn scope_matching_is_exact_not_prefix() {
        let id = Uuid::new_v4();
        let req = vec![RequestedPermission {
            resource_id: id,
            resource_scopes: vec!["album:view:thumbnail".into()],
        }];
        assert!(validate_permission_request(&req, &declares(&["album:view"])).is_err());
    }

    // -- RPT lifetime -------------------------------------------------------

    #[test]
    fn rpt_lifetime_is_capped_by_the_default_ceiling() {
        assert_eq!(rpt_lifetime_secs(3600, 3600), Some(300));
    }

    #[test]
    fn rpt_lifetime_is_capped_by_the_configured_max_when_lower() {
        assert_eq!(rpt_lifetime_secs(3600, 120), Some(120));
    }

    /// An RPT must never outlive the token that authorised it.
    #[test]
    fn rpt_lifetime_never_exceeds_the_subject_token() {
        assert_eq!(rpt_lifetime_secs(45, 3600), Some(45));
    }

    #[test]
    fn expired_subject_token_yields_no_lifetime() {
        assert_eq!(rpt_lifetime_secs(0, 300), None);
        assert_eq!(rpt_lifetime_secs(-10, 300), None);
    }
}
