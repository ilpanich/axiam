//! UMA 2.0 grant (X2) — minting permission tickets and exchanging them for RPTs.
//!
//! See `claude_dev/uma-mapping-design.md` for the decision this module rests
//! on: **a UMA resource scope is an AXIAM `action`**, so evaluating a ticket is
//! the *same* check a live request makes, and B1 deny-override applies to an
//! RPT with no special casing.
//!
//! # Why the evaluator is a trait defined here
//!
//! `axiam-oauth2` does not depend on `axiam-authz` — `axiam-api-rest` is the
//! composition root that owns both. Rather than invert that, this module
//! declares the narrow port it needs ([`PermissionEvaluator`]) and the wiring
//! crate implements it over the engine. The trait is deliberately one method
//! wide: everything else about authorization stays behind it.

use std::future::Future;
use std::pin::Pin;

use axiam_auth::token::{generate_refresh_token, hash_refresh_token};
use axiam_core::models::uma::{
    CreatePermissionTicket, PermissionRequestError, RequestedPermission, RptPermission,
    TICKET_TTL_SECS, TicketRejection, rpt_lifetime_secs, validate_permission_request,
};
use axiam_core::repository::PermissionTicketRepository;
use chrono::{Duration, Utc};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// The port into the authorization engine
// ---------------------------------------------------------------------------

/// What the engine said about one `(resource, scope)` pair.
///
/// Mirrors `axiam_authz::AccessDecision` without importing it. The
/// deny-by-rule distinction is carried because it is the difference between
/// "nobody granted this" and "an admin decided against it", and an audit
/// record that flattens the two loses the only fact worth having.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairOutcome {
    Allowed,
    /// No grant matched.
    NoGrant,
    /// An explicit deny grant matched and overrode any allow (B1).
    DeniedByRule,
}

impl PairOutcome {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Evaluates one `(subject, resource, scope)` triple against the RBAC engine.
pub trait PermissionEvaluator: Send + Sync {
    fn evaluate<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        resource_id: Uuid,
        scope: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<PairOutcome, String>> + Send + 'a>>;
}

/// Answers "which scope names has this resource declared".
///
/// Separate from the evaluator because it answers a different question:
/// *could* this scope be asked for, not *may* this subject have it. Conflating
/// them would make an undeclared scope indistinguishable from a denied one.
pub trait ScopeCatalog: Send + Sync {
    fn declared_scopes<'a>(
        &'a self,
        tenant_id: Uuid,
        resource_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a UMA operation failed, in the shape the token endpoint answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UmaError {
    /// The permission request was malformed or named an undeclared scope.
    InvalidRequest(String),
    /// The ticket could not be redeemed. Every [`TicketRejection`] lands here
    /// and they are indistinguishable to the client by design.
    InvalidGrant(String),
    /// The engine refused at least one requested pair.
    ///
    /// UMA 2.0's answer to a partial grant is claims-gathering, which v1
    /// defers, so a partial result is a refusal rather than a trimmed RPT —
    /// see the design note.
    AccessDenied,
    /// The subject's token has already expired, so there is no lifetime to
    /// issue an RPT for.
    ExpiredSubjectToken,
    Server(String),
}

impl UmaError {
    /// The OAuth2 error code carried on the wire.
    pub const fn wire_error(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidGrant(_) | Self::ExpiredSubjectToken => "invalid_grant",
            Self::AccessDenied => "access_denied",
            Self::Server(_) => "server_error",
        }
    }
}

impl std::fmt::Display for UmaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(m) | Self::InvalidGrant(m) | Self::Server(m) => write!(f, "{m}"),
            Self::AccessDenied => write!(f, "the requesting party is not authorized"),
            Self::ExpiredSubjectToken => write!(f, "the presented token has expired"),
        }
    }
}

impl std::error::Error for UmaError {}

impl From<PermissionRequestError> for UmaError {
    fn from(e: PermissionRequestError) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<TicketRejection> for UmaError {
    fn from(e: TicketRejection) -> Self {
        Self::InvalidGrant(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

/// A minted ticket: the opaque handle to hand back, and the row's id for audit.
#[derive(Debug, Clone)]
pub struct MintedTicket {
    /// The plaintext handle. Returned exactly once; only its hash is stored.
    pub ticket: String,
    pub ticket_id: Uuid,
}

/// A granted RPT's contents, ready to be signed into a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedPermissions {
    pub permissions: Vec<RptPermission>,
    pub lifetime_secs: i64,
}

/// UMA 2.0 permission endpoint and ticket grant.
pub struct UmaService<R, E, C> {
    tickets: R,
    evaluator: E,
    catalog: C,
    /// Deployment ceiling on RPT lifetime, further capped by the protocol
    /// default and by the subject token's own remaining life.
    rpt_max_lifetime_secs: i64,
}

impl<R, E, C> UmaService<R, E, C>
where
    R: PermissionTicketRepository,
    E: PermissionEvaluator,
    C: ScopeCatalog,
{
    pub fn new(tickets: R, evaluator: E, catalog: C, rpt_max_lifetime_secs: i64) -> Self {
        Self {
            tickets,
            evaluator,
            catalog,
            rpt_max_lifetime_secs,
        }
    }

    /// `POST /uma2/perm` — mint a ticket for what the resource server requires.
    ///
    /// The scope names are validated against each resource's declared set
    /// *before* the ticket exists. A ticket naming a scope no resource
    /// declares could never be redeemed, so minting one would hand the caller
    /// a credential guaranteed to fail sixty seconds later instead of an error
    /// it can act on now.
    pub async fn request_ticket(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        requested: Vec<RequestedPermission>,
    ) -> Result<MintedTicket, UmaError> {
        // Resolve every resource's declared scopes up front so validation is a
        // pure function over data — the same function the unit tests drive.
        let mut declared: Vec<(Uuid, Vec<String>)> = Vec::new();
        for perm in &requested {
            if declared.iter().any(|(id, _)| *id == perm.resource_id) {
                continue;
            }
            let scopes = self
                .catalog
                .declared_scopes(tenant_id, perm.resource_id)
                .await
                .map_err(UmaError::Server)?;
            declared.push((perm.resource_id, scopes));
        }

        let lookup = |resource_id: Uuid| -> Vec<String> {
            declared
                .iter()
                .find(|(id, _)| *id == resource_id)
                .map(|(_, s)| s.clone())
                .unwrap_or_default()
        };
        validate_permission_request(&requested, &lookup)?;

        let raw = generate_refresh_token();
        let stored = self
            .tickets
            .create(CreatePermissionTicket {
                tenant_id,
                ticket_hash: hash_refresh_token(&raw),
                client_id: client_id.to_string(),
                permissions: requested,
                expires_at: Utc::now() + Duration::seconds(TICKET_TTL_SECS),
            })
            .await
            .map_err(|e| UmaError::Server(e.to_string()))?;

        Ok(MintedTicket {
            ticket: raw,
            ticket_id: stored.id,
        })
    }

    /// `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket` — redeem a
    /// ticket for an RPT's contents.
    ///
    /// The ticket is consumed **first**. Evaluating before consuming would let
    /// two concurrent redemptions both pass evaluation and both mint, which is
    /// the whole point of single-use; consuming first means a replay is
    /// refused before any decision is made.
    pub async fn exchange_ticket(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        raw_ticket: &str,
        subject_id: Uuid,
        subject_remaining_secs: i64,
    ) -> Result<GrantedPermissions, UmaError> {
        let hash = hash_refresh_token(raw_ticket);

        let ticket = self
            .tickets
            .consume(tenant_id, &hash, client_id)
            .await
            .map_err(|e| UmaError::Server(e.to_string()))?
            .ok_or(UmaError::InvalidGrant(
                // Deliberately one message for unknown, consumed, expired and
                // wrong-client. A caller that could tell them apart could
                // probe for live ticket handles.
                "permission ticket is invalid, expired, or already used".into(),
            ))?;

        // An RPT must never outlive the token that authorised it. Checked
        // before evaluation so an expired subject costs no engine round trips.
        let lifetime = rpt_lifetime_secs(subject_remaining_secs, self.rpt_max_lifetime_secs)
            .ok_or(UmaError::ExpiredSubjectToken)?;

        // Every requested pair must be allowed. Refused pairs are not trimmed
        // — see the design note on why a partial RPT is worse than a refusal.
        for (resource_id, scope) in ticket.requested_pairs() {
            let outcome = self
                .evaluator
                .evaluate(tenant_id, subject_id, resource_id, &scope)
                .await
                .map_err(UmaError::Server)?;
            if !outcome.is_allowed() {
                return Err(UmaError::AccessDenied);
            }
        }

        let exp = (Utc::now() + Duration::seconds(lifetime)).timestamp();
        Ok(GrantedPermissions {
            permissions: ticket
                .permissions
                .into_iter()
                .map(|p| RptPermission {
                    resource_id: p.resource_id,
                    resource_scopes: p.resource_scopes,
                    exp,
                })
                .collect(),
            lifetime_secs: lifetime,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::AxiamResult;
    use axiam_core::models::uma::PermissionTicket;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // -- fakes --------------------------------------------------------------

    #[derive(Default)]
    struct FakeTickets {
        rows: Mutex<Vec<PermissionTicket>>,
    }

    impl PermissionTicketRepository for FakeTickets {
        async fn create(&self, input: CreatePermissionTicket) -> AxiamResult<PermissionTicket> {
            let t = PermissionTicket {
                id: Uuid::new_v4(),
                tenant_id: input.tenant_id,
                ticket_hash: input.ticket_hash,
                client_id: input.client_id,
                permissions: input.permissions,
                consumed: false,
                expires_at: input.expires_at,
                created_at: Utc::now(),
            };
            self.rows.lock().unwrap().push(t.clone());
            Ok(t)
        }

        async fn consume(
            &self,
            tenant_id: Uuid,
            ticket_hash: &str,
            client_id: &str,
        ) -> AxiamResult<Option<PermissionTicket>> {
            let mut rows = self.rows.lock().unwrap();
            let now = Utc::now();
            for row in rows.iter_mut() {
                if row.tenant_id == tenant_id
                    && row.ticket_hash == ticket_hash
                    && row.client_id == client_id
                    && !row.consumed
                    && row.expires_at > now
                {
                    let before = row.clone();
                    row.consumed = true;
                    return Ok(Some(before));
                }
            }
            Ok(None)
        }

        async fn find_by_hash(
            &self,
            tenant_id: Uuid,
            ticket_hash: &str,
        ) -> AxiamResult<Option<PermissionTicket>> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.tenant_id == tenant_id && r.ticket_hash == ticket_hash)
                .cloned())
        }

        async fn cleanup_expired(&self, _tenant_id: Uuid) -> AxiamResult<u64> {
            Ok(0)
        }
    }

    /// Answers from a fixed `(resource, scope) -> outcome` map; anything absent
    /// is `NoGrant`, which is the engine's default-deny.
    struct FakeEvaluator {
        outcomes: HashMap<(Uuid, String), PairOutcome>,
        calls: Mutex<Vec<(Uuid, String)>>,
    }

    impl FakeEvaluator {
        fn new(outcomes: HashMap<(Uuid, String), PairOutcome>) -> Self {
            Self {
                outcomes,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl PermissionEvaluator for FakeEvaluator {
        fn evaluate<'a>(
            &'a self,
            _tenant_id: Uuid,
            _subject_id: Uuid,
            resource_id: Uuid,
            scope: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<PairOutcome, String>> + Send + 'a>> {
            let key = (resource_id, scope.to_string());
            self.calls.lock().unwrap().push(key.clone());
            let outcome = self
                .outcomes
                .get(&key)
                .cloned()
                .unwrap_or(PairOutcome::NoGrant);
            Box::pin(async move { Ok(outcome) })
        }
    }

    struct FakeCatalog(Vec<String>);

    impl ScopeCatalog for FakeCatalog {
        fn declared_scopes<'a>(
            &'a self,
            _tenant_id: Uuid,
            _resource_id: Uuid,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
            let scopes = self.0.clone();
            Box::pin(async move { Ok(scopes) })
        }
    }

    fn service(
        outcomes: HashMap<(Uuid, String), PairOutcome>,
        declared: &[&str],
    ) -> UmaService<FakeTickets, FakeEvaluator, FakeCatalog> {
        UmaService::new(
            FakeTickets::default(),
            FakeEvaluator::new(outcomes),
            FakeCatalog(declared.iter().map(|s| s.to_string()).collect()),
            3600,
        )
    }

    fn allow(pairs: &[(Uuid, &str)]) -> HashMap<(Uuid, String), PairOutcome> {
        pairs
            .iter()
            .map(|(r, s)| ((*r, s.to_string()), PairOutcome::Allowed))
            .collect()
    }

    // -- ticket minting -----------------------------------------------------

    #[tokio::test]
    async fn a_declared_scope_mints_a_ticket() {
        let resource = Uuid::new_v4();
        let svc = service(HashMap::new(), &["view", "edit"]);

        let minted = svc
            .request_ticket(
                Uuid::new_v4(),
                "rs-1",
                vec![RequestedPermission {
                    resource_id: resource,
                    resource_scopes: vec!["view".into()],
                }],
            )
            .await
            .unwrap();

        assert!(!minted.ticket.is_empty());
    }

    /// The plaintext handle must never be what is stored.
    #[tokio::test]
    async fn only_the_hash_of_the_ticket_is_stored() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let svc = service(HashMap::new(), &["view"]);

        let minted = svc
            .request_ticket(
                tenant,
                "rs-1",
                vec![RequestedPermission {
                    resource_id: resource,
                    resource_scopes: vec!["view".into()],
                }],
            )
            .await
            .unwrap();

        let stored = svc.tickets.rows.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_ne!(stored[0].ticket_hash, minted.ticket);
        assert_eq!(stored[0].ticket_hash, hash_refresh_token(&minted.ticket));
    }

    #[tokio::test]
    async fn an_undeclared_scope_is_refused_before_a_ticket_exists() {
        let svc = service(HashMap::new(), &["view"]);

        let err = svc
            .request_ticket(
                Uuid::new_v4(),
                "rs-1",
                vec![RequestedPermission {
                    resource_id: Uuid::new_v4(),
                    resource_scopes: vec!["delete".into()],
                }],
            )
            .await
            .unwrap_err();

        assert_eq!(err.wire_error(), "invalid_request");
        assert!(
            svc.tickets.rows.lock().unwrap().is_empty(),
            "no ticket may be minted for a scope that could never be redeemed"
        );
    }

    // -- exchange -----------------------------------------------------------

    async fn mint_and_exchange(
        svc: &UmaService<FakeTickets, FakeEvaluator, FakeCatalog>,
        tenant: Uuid,
        resource: Uuid,
        scopes: Vec<String>,
        subject_remaining: i64,
    ) -> Result<GrantedPermissions, UmaError> {
        let minted = svc
            .request_ticket(
                tenant,
                "rs-1",
                vec![RequestedPermission {
                    resource_id: resource,
                    resource_scopes: scopes,
                }],
            )
            .await
            .unwrap();
        svc.exchange_ticket(
            tenant,
            "rs-1",
            &minted.ticket,
            Uuid::new_v4(),
            subject_remaining,
        )
        .await
    }

    #[tokio::test]
    async fn an_allowed_ticket_yields_an_rpt() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let svc = service(allow(&[(resource, "view")]), &["view", "edit"]);

        let granted = mint_and_exchange(&svc, tenant, resource, vec!["view".into()], 3600)
            .await
            .unwrap();

        assert_eq!(granted.permissions.len(), 1);
        assert_eq!(granted.permissions[0].resource_id, resource);
        assert_eq!(granted.permissions[0].resource_scopes, vec!["view"]);
    }

    /// The requirement X2 names explicitly: a deny rule must veto an RPT
    /// exactly as it vetoes a live check.
    #[tokio::test]
    async fn a_deny_rule_vetoes_the_rpt() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let mut outcomes = allow(&[(resource, "view")]);
        outcomes.insert((resource, "view".into()), PairOutcome::DeniedByRule);
        let svc = service(outcomes, &["view"]);

        let err = mint_and_exchange(&svc, tenant, resource, vec!["view".into()], 3600)
            .await
            .unwrap_err();
        assert_eq!(err.wire_error(), "access_denied");
    }

    #[tokio::test]
    async fn an_ungranted_scope_is_refused() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let svc = service(HashMap::new(), &["view"]);

        let err = mint_and_exchange(&svc, tenant, resource, vec!["view".into()], 3600)
            .await
            .unwrap_err();
        assert_eq!(err.wire_error(), "access_denied");
    }

    /// Partial grants are refused whole, not trimmed to the allowed subset.
    #[tokio::test]
    async fn a_partially_allowed_ticket_is_refused_not_trimmed() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let svc = service(allow(&[(resource, "view")]), &["view", "edit"]);

        let err = mint_and_exchange(
            &svc,
            tenant,
            resource,
            vec!["view".into(), "edit".into()],
            3600,
        )
        .await
        .unwrap_err();

        assert_eq!(
            err,
            UmaError::AccessDenied,
            "an RPT that silently does less than asked is worse than a refusal"
        );
    }

    /// UMA 2.0 §3.3 single-use, enforced through the service.
    #[tokio::test]
    async fn a_ticket_cannot_be_exchanged_twice() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let svc = service(allow(&[(resource, "view")]), &["view"]);

        let minted = svc
            .request_ticket(
                tenant,
                "rs-1",
                vec![RequestedPermission {
                    resource_id: resource,
                    resource_scopes: vec!["view".into()],
                }],
            )
            .await
            .unwrap();

        let subject = Uuid::new_v4();
        assert!(
            svc.exchange_ticket(tenant, "rs-1", &minted.ticket, subject, 3600)
                .await
                .is_ok()
        );
        let err = svc
            .exchange_ticket(tenant, "rs-1", &minted.ticket, subject, 3600)
            .await
            .unwrap_err();
        assert_eq!(err.wire_error(), "invalid_grant");
    }

    #[tokio::test]
    async fn a_ticket_from_another_client_is_refused() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let svc = service(allow(&[(resource, "view")]), &["view"]);

        let minted = svc
            .request_ticket(
                tenant,
                "rs-1",
                vec![RequestedPermission {
                    resource_id: resource,
                    resource_scopes: vec!["view".into()],
                }],
            )
            .await
            .unwrap();

        let err = svc
            .exchange_ticket(tenant, "rs-2", &minted.ticket, Uuid::new_v4(), 3600)
            .await
            .unwrap_err();
        assert_eq!(err.wire_error(), "invalid_grant");
    }

    /// A refused redemption must not spend engine round trips, and must not
    /// let a caller distinguish rejection reasons by side effect.
    #[tokio::test]
    async fn an_unknown_ticket_is_refused_without_evaluating_anything() {
        let svc = service(HashMap::new(), &["view"]);

        let err = svc
            .exchange_ticket(
                Uuid::new_v4(),
                "rs-1",
                "not-a-real-ticket",
                Uuid::new_v4(),
                3600,
            )
            .await
            .unwrap_err();

        assert_eq!(err.wire_error(), "invalid_grant");
        assert!(svc.evaluator.calls.lock().unwrap().is_empty());
    }

    // -- lifetime -----------------------------------------------------------

    #[tokio::test]
    async fn the_rpt_never_outlives_the_subject_token() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let svc = service(allow(&[(resource, "view")]), &["view"]);

        let granted = mint_and_exchange(&svc, tenant, resource, vec!["view".into()], 42)
            .await
            .unwrap();
        assert_eq!(granted.lifetime_secs, 42);
    }

    #[tokio::test]
    async fn the_rpt_is_capped_by_the_protocol_default() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let svc = service(allow(&[(resource, "view")]), &["view"]);

        let granted = mint_and_exchange(&svc, tenant, resource, vec!["view".into()], 86_400)
            .await
            .unwrap();
        assert_eq!(granted.lifetime_secs, 300);
    }

    #[tokio::test]
    async fn an_expired_subject_token_cannot_mint_an_rpt() {
        let resource = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let svc = service(allow(&[(resource, "view")]), &["view"]);

        let err = mint_and_exchange(&svc, tenant, resource, vec!["view".into()], 0)
            .await
            .unwrap_err();
        assert_eq!(err, UmaError::ExpiredSubjectToken);
    }
}
