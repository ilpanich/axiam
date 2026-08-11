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
use axiam_core::models::resource::{CreateResource, UpdateResource};
use axiam_core::models::scope::CreateScope;
use axiam_core::models::uma::{
    RequestedPermission, TICKET_TTL_SECS, UMA_CLAIM_TOKEN_FORMAT, UMA_PROTECTION_SCOPE,
    UMA_TICKET_GRANT_TYPE,
};
use axiam_core::repository::{Pagination, ResourceRepository, ScopeRepository};
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
    pub resource_registration_endpoint: String,
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
/// (`claims_interaction_endpoint`) is absent because it is not implemented;
/// advertising an endpoint that 404s is worse than not advertising it, since a
/// conforming client would route to it on the strength of this document.
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
        resource_registration_endpoint: format!("{issuer}/uma2/rreg/resource_set"),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        issuer,
        grant_types_supported: vec![UMA_TICKET_GRANT_TYPE.to_string()],
        uma_profiles_supported: vec![],
        permission_ticket_lifetime: TICKET_TTL_SECS,
    })
}

// ---------------------------------------------------------------------------
// Resource registration API (UMA 2.0 FedAuthz §2)
// ---------------------------------------------------------------------------

/// A resource set as UMA describes it, mapped onto an AXIAM resource.
///
/// # The mapping, in one place
///
/// | UMA | AXIAM |
/// |---|---|
/// | `_id` | the resource id — **not** a parallel identifier |
/// | `name` | `resource.name` |
/// | `type` | `resource.resource_type` |
/// | `resource_scopes` | the `Scope` rows on that resource |
///
/// There is no second resource store. A resource registered here is an
/// ordinary AXIAM resource that the admin UI lists, that role assignments
/// cascade through, and that the authorization engine already understands —
/// which is the entire reason UMA `_id` is the AXIAM id rather than a
/// translation key.
#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ResourceSet {
    /// Present on responses, absent on registration — the server assigns it.
    #[serde(rename = "_id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    pub name: String,
    #[serde(rename = "type", default)]
    pub resource_type: String,
    #[serde(default)]
    pub resource_scopes: Vec<String>,
}

/// `POST /uma2/rreg/resource_set` — register a resource set (FedAuthz §2.2.1).
///
/// Creates the resource **and** its declared scopes. The scope set is what the
/// permission endpoint later validates ticket requests against, so registering
/// a resource with no scopes produces one that can never appear in a ticket —
/// legal, and worth knowing.
#[utoipa::path(
    post,
    path = "/uma2/rreg/resource_set",
    tag = "uma",
    request_body = ResourceSet,
    responses(
        (status = 201, description = "Resource set registered", body = ResourceSet),
        (status = 401, description = "Missing or invalid PAT"),
        (status = 403, description = "Token lacks the uma_protection scope"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn register_resource_set<C: Connection + Clone>(
    pat: ProtectionApiToken,
    state: web::Data<AppState<C>>,
    body: web::Json<ResourceSet>,
) -> Result<HttpResponse, AxiamApiError> {
    let body = body.into_inner();

    let resource = state
        .resource_repo
        .create_uma_registered(
            CreateResource {
                tenant_id: pat.tenant_id,
                name: body.name,
                // UMA's `type` is a free-form string and AXIAM's is too, but a
                // resource server that omits it should not end up with an
                // empty-string type that sorts oddly in the admin UI.
                resource_type: if body.resource_type.is_empty() {
                    "uma_resource".to_string()
                } else {
                    body.resource_type
                },
                parent_id: None,
                metadata: None,
            },
            &pat.client_id,
        )
        .await?;

    let scopes = sync_scopes(&state, pat.tenant_id, resource.id, &body.resource_scopes).await?;

    tracing::info!(
        target: "axiam::audit",
        event = "uma.resource_registered",
        tenant_id = %pat.tenant_id,
        client_id = %pat.client_id,
        resource_id = %resource.id,
        "resource set registered"
    );

    Ok(HttpResponse::Created().json(ResourceSet {
        id: Some(resource.id),
        name: resource.name,
        resource_type: resource.resource_type,
        resource_scopes: scopes,
    }))
}

/// `GET /uma2/rreg/resource_set/{id}` — read a resource set (FedAuthz §2.2.2).
#[utoipa::path(
    get,
    path = "/uma2/rreg/resource_set/{id}",
    tag = "uma",
    params(("id" = Uuid, Path, description = "Resource set id")),
    responses(
        (status = 200, description = "Resource set", body = ResourceSet),
        (status = 404, description = "No such resource set"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn read_resource_set<C: Connection + Clone>(
    pat: ProtectionApiToken,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    let resource = state.resource_repo.get_by_id(pat.tenant_id, id).await?;
    let scopes = declared_scope_names(&state, pat.tenant_id, id).await?;

    Ok(HttpResponse::Ok().json(ResourceSet {
        id: Some(resource.id),
        name: resource.name,
        resource_type: resource.resource_type,
        resource_scopes: scopes,
    }))
}

/// `PUT /uma2/rreg/resource_set/{id}` — update a resource set (FedAuthz §2.2.3).
///
/// The scope list is **replaced**, not merged: FedAuthz defines the update as
/// putting the resource set's new state, and a merge would make it impossible
/// to remove a scope. Removing a scope narrows what tickets may be requested,
/// so a silent merge would keep an authority the resource server tried to drop.
#[utoipa::path(
    put,
    path = "/uma2/rreg/resource_set/{id}",
    tag = "uma",
    params(("id" = Uuid, Path, description = "Resource set id")),
    request_body = ResourceSet,
    responses(
        (status = 200, description = "Resource set updated", body = ResourceSet),
        (status = 404, description = "No such resource set"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_resource_set<C: Connection + Clone>(
    pat: ProtectionApiToken,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<ResourceSet>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    let body = body.into_inner();

    // Read first so an unknown id answers 404 before anything is written.
    state.resource_repo.get_by_id(pat.tenant_id, id).await?;

    let resource = state
        .resource_repo
        .update(
            pat.tenant_id,
            id,
            UpdateResource {
                name: Some(body.name),
                resource_type: if body.resource_type.is_empty() {
                    None
                } else {
                    Some(body.resource_type)
                },
                ..Default::default()
            },
        )
        .await?;

    let scopes = sync_scopes(&state, pat.tenant_id, id, &body.resource_scopes).await?;

    Ok(HttpResponse::Ok().json(ResourceSet {
        id: Some(resource.id),
        name: resource.name,
        resource_type: resource.resource_type,
        resource_scopes: scopes,
    }))
}

/// `DELETE /uma2/rreg/resource_set/{id}` — deregister (FedAuthz §2.2.4).
#[utoipa::path(
    delete,
    path = "/uma2/rreg/resource_set/{id}",
    tag = "uma",
    params(("id" = Uuid, Path, description = "Resource set id")),
    responses(
        (status = 204, description = "Resource set deleted"),
        (status = 404, description = "No such resource set"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_resource_set<C: Connection + Clone>(
    pat: ProtectionApiToken,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    state.resource_repo.get_by_id(pat.tenant_id, id).await?;
    state.resource_repo.delete(pat.tenant_id, id).await?;

    tracing::info!(
        target: "axiam::audit",
        event = "uma.resource_deregistered",
        tenant_id = %pat.tenant_id,
        client_id = %pat.client_id,
        resource_id = %id,
        "resource set deregistered"
    );

    Ok(HttpResponse::NoContent().finish())
}

/// `GET /uma2/rreg/resource_set` — list registered ids (FedAuthz §2.2.5).
///
/// Lists only the resources **this client** registered. FedAuthz says the
/// listing is of the resource sets the PAT's owner registered, and a resource
/// server has no business enumerating the tenant's whole resource tree through
/// an endpoint whose only credential is a protection scope.
#[utoipa::path(
    get,
    path = "/uma2/rreg/resource_set",
    tag = "uma",
    responses((status = 200, description = "Registered resource set ids", body = Vec<Uuid>)),
    security(("bearer_auth" = []))
)]
pub async fn list_resource_sets<C: Connection + Clone>(
    pat: ProtectionApiToken,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let page = state
        .resource_repo
        .list(pat.tenant_id, Pagination::default())
        .await?;

    let ids: Vec<Uuid> = page
        .items
        .into_iter()
        .filter(|r| r.uma_registered_by.as_deref() == Some(pat.client_id.as_str()))
        .map(|r| r.id)
        .collect();

    Ok(HttpResponse::Ok().json(ids))
}

/// Replace a resource's declared scopes with `wanted`, returning the result.
///
/// Adds what is missing and removes what is no longer named. Scopes that are
/// already correct are left alone rather than deleted and recreated, because
/// their ids are referenced by permission grants — recreating a scope would
/// silently detach every grant that named it.
async fn sync_scopes<C: Connection + Clone>(
    state: &web::Data<AppState<C>>,
    tenant_id: Uuid,
    resource_id: Uuid,
    wanted: &[String],
) -> Result<Vec<String>, AxiamApiError> {
    let existing = state
        .scope_repo
        .list_by_resource(tenant_id, resource_id)
        .await?;

    for scope in &existing {
        if !wanted.contains(&scope.name) {
            state.scope_repo.delete(tenant_id, scope.id).await?;
        }
    }

    for name in wanted {
        if existing.iter().any(|s| &s.name == name) {
            continue;
        }
        state
            .scope_repo
            .create(CreateScope {
                tenant_id,
                resource_id,
                name: name.clone(),
                description: String::new(),
            })
            .await?;
    }

    Ok(wanted.to_vec())
}

async fn declared_scope_names<C: Connection + Clone>(
    state: &web::Data<AppState<C>>,
    tenant_id: Uuid,
    resource_id: Uuid,
) -> Result<Vec<String>, AxiamApiError> {
    Ok(state
        .scope_repo
        .list_by_resource(tenant_id, resource_id)
        .await?
        .into_iter()
        .map(|s| s.name)
        .collect())
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
