//! X2 — the UMA 2.0 HTTP surface: the permission endpoint and discovery.
//!
//! The uma-ticket grant itself lives in [`crate::handlers::oauth2`], because
//! actix deserializes the token endpoint's body once and the grant is not
//! knowable until `grant_type` has been read out of it — the same reason the
//! device and token-exchange grants are dispatched there rather than routed.

use actix_web::{HttpResponse, web};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::SubjectKind;
use axiam_core::error::AxiamError;
use axiam_core::models::uma::{
    RequestedPermission, TICKET_TTL_SECS, UMA_CLAIM_TOKEN_FORMAT, UMA_PROTECTION_SCOPE,
    UMA_TICKET_GRANT_TYPE,
};
use axiam_oauth2::uma::UmaError;
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::AuthzData;
use crate::error::AxiamApiError;
use crate::state::AppState;

/// A validated **Protection API Token** and the resource server it names.
///
/// Its own extractor rather than [`AuthenticatedUser`] or
/// `AuthenticatedPrincipal`, because a PAT is a third principal shape and
/// neither of those can carry it:
///
/// - `AuthenticatedUser` narrows the audience to `axiam:user`, and a PAT is a
///   client-credentials token carrying `axiam:m2m`.
/// - `AuthenticatedPrincipal` accepts `axiam:m2m` but parses `sub` as a UUID,
///   which deliberately excludes OAuth2 clients — their `sub` is a `client_id`
///   string, and they have no row in the role-assignment graph.
///
/// That exclusion is right for RBAC subjects and wrong for this endpoint: the
/// Protection API does not evaluate the caller against grants at all. It only
/// needs to know **which client is speaking**, because that is what the minted
/// ticket is bound to. So this extractor keeps `sub` as the string it is.
pub struct ProtectionApiToken {
    /// The resource server's `client_id` — the token's `sub`, unparsed.
    pub client_id: String,
    pub tenant_id: Uuid,
}

impl actix_web::FromRequest for ProtectionApiToken {
    type Error = AxiamApiError;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        std::future::ready(extract_pat(req))
    }
}

fn extract_pat(req: &actix_web::HttpRequest) -> Result<ProtectionApiToken, AxiamApiError> {
    let claims = crate::extractors::auth::parse_validated_claims(req)?.0;

    // Checked before the scope, so a user token gets the answer that names the
    // real problem rather than being told it is missing a scope it could add.
    if claims.sub_kind != SubjectKind::OAuth2Client {
        return Err(forbidden(
            "a protection API token must be issued to an OAuth2 client, because \
             a permission ticket is bound to the client that minted it"
                .into(),
        ));
    }

    // The `uma_protection` scope is the only thing that distinguishes a PAT
    // from any other client-credentials token, so it is not optional.
    if !claims
        .scope
        .as_deref()
        .is_some_and(|s| s.split(' ').any(|granted| granted == UMA_PROTECTION_SCOPE))
    {
        return Err(forbidden(format!(
            "the protection API requires the '{UMA_PROTECTION_SCOPE}' scope"
        )));
    }

    let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| {
        AxiamApiError(AxiamError::AuthenticationFailed {
            reason: "invalid tenant_id claim".into(),
        })
    })?;

    Ok(ProtectionApiToken {
        client_id: claims.sub,
        tenant_id,
    })
}

/// Body of `POST /uma2/perm` — what the resource server requires.
///
/// UMA 2.0 §3.2 allows either a single object or an array; AXIAM accepts the
/// array form only, because a resource server that needs one pair can send an
/// array of one, and accepting both shapes means two parsers for one meaning.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PermissionRequestBody(pub Vec<RequestedPermission>);

/// `201 Created` body of the permission endpoint (UMA 2.0 §3.2).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PermissionTicketResponse {
    /// The opaque handle. Returned exactly once — only its hash is stored.
    pub ticket: String,
}

/// The UMA 2.0 discovery document (§2).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Uma2Configuration {
    pub issuer: String,
    pub token_endpoint: String,
    pub introspection_endpoint: String,
    pub permission_endpoint: String,
    pub jwks_uri: String,
    pub grant_types_supported: Vec<String>,
    pub uma_profiles_supported: Vec<String>,
    /// Advertised so a resource server can size its retry window against the
    /// ticket TTL instead of discovering it by having a ticket expire.
    pub permission_ticket_lifetime: i64,
}

/// `POST /uma2/perm` — mint a permission ticket (UMA 2.0 §3.2).
///
/// # Who may call this
///
/// A **Protection API Token**: an ordinary AXIAM access token carrying the
/// `uma_protection` scope. Two further conditions, both deliberate:
///
/// 1. **The token must be an OAuth2 client token** (`sub_kind` =
///    `OAuth2Client`). A ticket is bound to the `client_id` that minted it, and
///    for a client-credentials token `sub` *is* the `client_id`. A user token
///    has no client identity in it, so binding one would mean inventing a
///    value and calling it a binding.
/// 2. **The scope is checked here, not by a route guard.** The `uma_protection`
///    scope is what makes an access token a PAT; nothing else about the token
///    distinguishes it.
#[utoipa::path(
    post,
    path = "/uma2/perm",
    tag = "uma",
    request_body = PermissionRequestBody,
    responses(
        (status = 201, description = "Ticket minted", body = PermissionTicketResponse),
        (status = 400, description = "Malformed request or undeclared scope"),
        (status = 401, description = "Missing or invalid PAT"),
        (status = 403, description = "Token lacks the uma_protection scope"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn permission_request<C: Connection + Clone>(
    pat: ProtectionApiToken,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<PermissionRequestBody>,
) -> Result<HttpResponse, AxiamApiError> {
    let minted = state
        .uma_service(authz.get_ref().clone())
        .request_ticket(pat.tenant_id, &pat.client_id, body.into_inner().0)
        .await
        .map_err(uma_error_to_api)?;

    tracing::info!(
        target: "axiam::audit",
        event = "uma.ticket_minted",
        tenant_id = %pat.tenant_id,
        client_id = %pat.client_id,
        ticket_id = %minted.ticket_id,
        "permission ticket minted"
    );

    Ok(HttpResponse::Created()
        .append_header(("Cache-Control", "no-store"))
        .append_header(("Pragma", "no-cache"))
        .json(PermissionTicketResponse {
            ticket: minted.ticket,
        }))
}

/// `GET /.well-known/uma2-configuration` — UMA 2.0 discovery (§2).
///
/// Advertises only what v1 actually serves. Claims-gathering
/// (`claims_interaction_endpoint`) and the resource registration endpoint are
/// absent because they are not implemented; advertising an endpoint that 404s
/// is worse than not advertising it, since a conforming client would route to
/// it on the strength of this document.
#[utoipa::path(
    get,
    path = "/.well-known/uma2-configuration",
    tag = "uma",
    responses((status = 200, description = "UMA 2.0 configuration", body = Uma2Configuration))
)]
pub async fn uma2_configuration(auth_config: web::Data<AuthConfig>) -> HttpResponse {
    let issuer = auth_config
        .oauth2_issuer_url
        .trim_end_matches('/')
        .to_string();

    HttpResponse::Ok().json(Uma2Configuration {
        token_endpoint: format!("{issuer}/oauth2/token"),
        introspection_endpoint: format!("{issuer}/oauth2/introspect"),
        permission_endpoint: format!("{issuer}/uma2/perm"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        issuer,
        grant_types_supported: vec![UMA_TICKET_GRANT_TYPE.to_string()],
        uma_profiles_supported: vec![],
        permission_ticket_lifetime: TICKET_TTL_SECS,
    })
}

/// A 403 with no `action`/`resource_id` hints.
fn forbidden(reason: String) -> AxiamApiError {
    AxiamApiError(AxiamError::AuthorizationDenied {
        reason,
        action: None,
        resource_id: None,
    })
}

/// Map a [`UmaError`] onto the REST error shape.
///
/// `AccessDenied` becomes 403 and every ticket rejection becomes 400 with one
/// message — the service already collapses unknown, consumed, expired and
/// wrong-client into a single `InvalidGrant`, and re-separating them here would
/// undo that.
fn uma_error_to_api(e: UmaError) -> AxiamApiError {
    let inner = match e {
        UmaError::InvalidRequest(message) | UmaError::InvalidGrant(message) => {
            AxiamError::Validation { message }
        }
        UmaError::AccessDenied => AxiamError::AuthorizationDenied {
            reason: "the requesting party is not authorized for every requested permission".into(),
            // Deliberately not naming the pair that failed. A resource server
            // that could tell which of several pairs was refused could probe
            // the grant table one scope at a time.
            action: None,
            resource_id: None,
        },
        UmaError::ExpiredSubjectToken => AxiamError::Validation {
            message: "the presented token has expired".into(),
        },
        UmaError::Server(m) => AxiamError::Internal(m),
    };
    AxiamApiError(inner)
}

/// The claim-token format v1 accepts, re-exported so the token endpoint and
/// discovery agree on one constant.
pub const ACCEPTED_CLAIM_TOKEN_FORMAT: &str = UMA_CLAIM_TOKEN_FORMAT;
