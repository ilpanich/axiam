//! The outbound SCIM target registry's management routes (G-6, T23.6.4,
//! contract §31).
//!
//! Six routes under `/api/v1/scim-targets`, in the `scim-targets` OpenAPI tag
//! and the management registry. A target is a downstream SCIM 2.0 service
//! provider a tenant's administrator registers; AXIAM then pushes the tenant's
//! users and groups to it (`axiam-scim`, `outbound`). The registry is
//! **human-only** (`scim_targets:*`, a [`HUMAN_ONLY_FAMILIES`] family): it holds
//! a credential to an outbound endpoint and decides where a tenant's people
//! are sent, so a service-account token is `401` at the extractor.
//!
//! The tenant is the token's, as for webhooks: a target of another tenant is
//! `404`, exactly as one that does not exist.
//!
//! # What every write does, in this order
//!
//! 1. the permission (`scim_targets:read` / `scim_targets:write`);
//! 2. the value rules (`400`, each naming its rule or field, never echoing a
//!    URL or the credential): `name`, `base_url` and `token_url` under the
//!    webhook outbound address policy, the OAuth2 client id and scope, the
//!    credential's bounds, the group scope (non-empty, at most
//!    [`MAX_SCOPE_GROUPS`], every group in this tenant);
//! 3. on an update, **the credential's binding to its URL** (D-57): moving the
//!    credential to another URL — `base_url` of a bearer target, `token_url`
//!    of a client-credentials one — or switching the authentication kind
//!    without supplying the credential in the same write is `400` naming the
//!    field;
//! 4. `503` when a credential is to be stored and `pki_encryption_key` is not
//!    configured;
//! 5. the write — an update conditional on the `updated_at` it read, so a
//!    target changed since is `409` (T-406);
//! 6. one audit row with the **names** of what changed, never a URL or the
//!    credential;
//! 7. when the target is created enabled, or an update enables it, a
//!    reconciliation is started, which queues a reference for every user and
//!    group in scope: that is the initial synchronisation.
//!
//! Deleting a target removes its link rows and its delivery state; it does
//! **not** deprovision anything downstream.

use actix_web::error::JsonPayloadError;
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::scim_target::{
    DeprovisionPolicy, NewScimTarget, ScimTarget as StoredTarget, ScimTargetAuth, ScimTargetScope,
    ScimTargetState as StoredState, ScimTargetUpdate, UserNameSource,
};
use axiam_core::repository::{
    AuditLogRepository, GroupRepository, PaginatedResult, Pagination, ScimTargetRepository,
    ScimTargetStateRepository,
};
use axiam_oauth2::ssf::validate_push_endpoint;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::client_info::client_ip;
use crate::state::AppState;
use crate::state::bundles::ScimReconcileStart;

/// Audit action: a target was registered.
pub const AUDIT_TARGET_CREATED: &str = "scim_target.created";
/// Audit action: an administrator replaced a target's configuration.
pub const AUDIT_TARGET_UPDATED: &str = "scim_target.updated";
/// Audit action: a target was deleted (with its links and state).
pub const AUDIT_TARGET_DELETED: &str = "scim_target.deleted";
/// Audit action: an administrator started a reconciliation.
pub const AUDIT_TARGET_RECONCILE_REQUESTED: &str = "scim_target.reconcile_requested";

/// The longest `name`, in bytes.
pub const MAX_NAME_BYTES: usize = 128;
/// The most groups a `groups` scope may list.
pub const MAX_SCOPE_GROUPS: usize = 100;
/// The longest credential (bearer token or client secret), in bytes.
pub const MAX_CREDENTIAL_BYTES: usize = 4096;
/// The longest OAuth2 `client_id`, in bytes.
pub const MAX_CLIENT_ID_BYTES: usize = 256;
/// The longest OAuth2 `scope`, in bytes.
pub const MAX_OAUTH_SCOPE_BYTES: usize = 256;

const BODY_LIMIT: usize = 32_768;

// ---------------------------------------------------------------------------
// Shapes (CONTRACT §31.2)
// ---------------------------------------------------------------------------

/// A target's delivery state, as `GET` projects it. Fixed vocabulary only: the
/// failure reason is one of the deliverer's phrases, never a URL, a response
/// body or a value.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ScimTargetDeliveryState {
    /// When a delivery last succeeded.
    pub last_success_at: Option<DateTime<Utc>>,
    /// When a delivery attempt last failed or was dead-lettered.
    pub last_failure_at: Option<DateTime<Utc>>,
    /// Why, in the deliverer's fixed vocabulary.
    pub last_failure_reason: Option<String>,
    /// Failed attempts since the last success.
    pub consecutive_failures: u64,
    /// Deliveries dead-lettered over the target's lifetime.
    pub dead_lettered_total: u64,
    /// When reconciliation last ran.
    pub last_reconciled_at: Option<DateTime<Utc>>,
}

impl From<StoredState> for ScimTargetDeliveryState {
    fn from(s: StoredState) -> Self {
        Self {
            last_success_at: s.last_success_at,
            last_failure_at: s.last_failure_at,
            last_failure_reason: s.last_failure_reason,
            consecutive_failures: s.consecutive_failures,
            dead_lettered_total: s.dead_lettered_total,
            last_reconciled_at: s.last_reconciled_at,
        }
    }
}

/// A registered SCIM target, as the management API returns it. **The
/// credential is never returned**, and there is no member that says anything
/// about it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ScimTargetResponse {
    /// The target id.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// The name.
    pub name: String,
    /// The downstream's SCIM service root.
    pub base_url: String,
    /// Whether AXIAM pushes to it.
    pub enabled: bool,
    /// How AXIAM authenticates to it (no credential).
    pub auth: ScimTargetAuth,
    /// Which users it provisions.
    pub scope: ScimTargetScope,
    /// Whether groups are pushed too.
    pub push_groups: bool,
    /// Which attribute becomes `userName`.
    pub user_name_from: UserNameSource,
    /// What happens downstream to a user who leaves scope or is no longer
    /// active (erasure always deletes).
    pub deprovision: DeprovisionPolicy,
    /// When the target was registered.
    pub created_at: DateTime<Utc>,
    /// When it was last written: the version an update is conditional on.
    pub updated_at: DateTime<Utc>,
    /// Delivery state: last success and failure, consecutive failures,
    /// dead-lettered total, last reconciliation.
    pub state: Option<ScimTargetDeliveryState>,
}

impl ScimTargetResponse {
    fn new(target: StoredTarget, state: Option<StoredState>) -> Self {
        Self {
            id: target.id,
            tenant_id: target.tenant_id,
            name: target.name,
            base_url: target.base_url,
            enabled: target.enabled,
            auth: target.auth,
            scope: target.scope,
            push_groups: target.push_groups,
            user_name_from: target.user_name_from,
            deprovision: target.deprovision,
            created_at: target.created_at,
            updated_at: target.updated_at,
            state: state.map(Into::into),
        }
    }
}

fn default_enabled() -> bool {
    true
}

/// `create` and `update` (a **replacement**) body.
#[derive(Clone, Deserialize, utoipa::ToSchema)]
pub struct ScimTargetInput {
    /// 1–128 bytes.
    pub name: String,
    /// The downstream's SCIM service root: an `https` URL under the outbound
    /// address policy (no credentials or fragment, at most 2 048 bytes, no
    /// non-public address, no local name).
    pub base_url: String,
    /// `true` by default. A disabled target receives nothing.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// `bearer`, or `oauth2_client_credentials` with `token_url` (the same URL
    /// policy), `client_id` (1–256 bytes) and an optional `scope`.
    pub auth: ScimTargetAuth,
    /// **Write-only.** The bearer token or the OAuth2 client secret, 1–4 096
    /// bytes. Required on create. On update, absent keeps the stored one —
    /// except that moving it to another URL (`base_url` of a bearer target,
    /// `token_url` of a client-credentials one) or switching `auth.type`
    /// requires it again.
    #[serde(default)]
    pub credential: Option<String>,
    /// `all_users`, or `groups` with 1–100 `group_ids` of this tenant: users
    /// who are direct members of any listed group.
    pub scope: ScimTargetScope,
    /// Push groups too (every group for `all_users`, the listed ones for
    /// `groups`). `false` by default.
    #[serde(default)]
    pub push_groups: bool,
    /// `username` (default) or `email`.
    #[serde(default)]
    pub user_name_from: UserNameSource,
    /// `deactivate` (default: `PATCH active=false`) or `delete`.
    #[serde(default)]
    pub deprovision: DeprovisionPolicy,
}

/// `Debug` names the credential's presence and nothing else.
impl std::fmt::Debug for ScimTargetInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimTargetInput")
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("auth", &self.auth.kind_str())
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// The body of a started reconciliation's `202`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ScimReconcileAccepted {
    /// The target being reconciled.
    pub target_id: Uuid,
    /// Always `started`.
    pub status: &'static str,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validation(message: impl Into<String>) -> AxiamApiError {
    AxiamApiError(AxiamError::Validation {
        message: message.into(),
    })
}

/// The JSON configuration of the routes: a body limit and a `400` that never
/// quotes the body (it holds the credential).
pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default().limit(BODY_LIMIT).error_handler(
        |err: JsonPayloadError, _req: &HttpRequest| {
            let message = match err {
                JsonPayloadError::Deserialize(inner) => format!(
                    "the request body is not a valid SCIM target: {}",
                    super::directory::scrub_serde_message(&inner.to_string())
                ),
                JsonPayloadError::ContentType => {
                    "the request body must be application/json".to_string()
                }
                JsonPayloadError::Overflow { .. }
                | JsonPayloadError::OverflowKnownLength { .. } => {
                    "the request body is too large".to_string()
                }
                _ => "the request body could not be read".to_string(),
            };
            AxiamApiError(AxiamError::Validation { message }).into()
        },
    )
}

/// A URL field under the webhook outbound address policy. The shared validator
/// names `endpoint_url`; the message names the field it was given instead.
fn check_url(field: &str, raw: &str) -> Result<(), AxiamApiError> {
    validate_push_endpoint(raw)
        .map(|_| ())
        .map_err(|message| validation(message.replacen("endpoint_url", field, 1)))
}

fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

/// What the input says once its values are checked: the normalised group list
/// (order kept, duplicates removed) and the credential, zeroizing.
struct Checked {
    scope: ScimTargetScope,
    auth: ScimTargetAuth,
    credential: Option<Zeroizing<String>>,
}

fn check_values(input: &ScimTargetInput) -> Result<Checked, AxiamApiError> {
    let name = input.name.trim();
    if name.is_empty() || input.name.len() > MAX_NAME_BYTES || has_control(&input.name) {
        return Err(validation(format!(
            "name must be 1 to {MAX_NAME_BYTES} bytes without control characters"
        )));
    }
    check_url("base_url", &input.base_url)?;

    let auth = match &input.auth {
        ScimTargetAuth::Bearer => ScimTargetAuth::Bearer,
        ScimTargetAuth::OAuth2ClientCredentials {
            token_url,
            client_id,
            scope,
        } => {
            check_url("auth.token_url", token_url)?;
            if client_id.is_empty()
                || client_id.len() > MAX_CLIENT_ID_BYTES
                || has_control(client_id)
            {
                return Err(validation(format!(
                    "auth.client_id must be 1 to {MAX_CLIENT_ID_BYTES} bytes without control \
                     characters"
                )));
            }
            let scope = scope.clone().filter(|s| !s.trim().is_empty());
            if let Some(scope) = &scope
                && (scope.len() > MAX_OAUTH_SCOPE_BYTES || has_control(scope))
            {
                return Err(validation(format!(
                    "auth.scope must be at most {MAX_OAUTH_SCOPE_BYTES} bytes without control \
                     characters"
                )));
            }
            ScimTargetAuth::OAuth2ClientCredentials {
                token_url: token_url.clone(),
                client_id: client_id.clone(),
                scope,
            }
        }
    };

    let credential = match &input.credential {
        None => None,
        Some(value) => {
            if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES {
                return Err(validation(format!(
                    "credential must be 1 to {MAX_CREDENTIAL_BYTES} bytes"
                )));
            }
            if value.trim() != value || has_control(value) {
                return Err(validation(
                    "credential must not carry surrounding whitespace or control characters",
                ));
            }
            // A bearer token travels in a header: visible ASCII only.
            if matches!(auth, ScimTargetAuth::Bearer)
                && !value.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(validation(
                    "a bearer credential must be visible ASCII without spaces",
                ));
            }
            Some(Zeroizing::new(value.clone()))
        }
    };

    let scope = match &input.scope {
        ScimTargetScope::AllUsers => ScimTargetScope::AllUsers,
        ScimTargetScope::Groups(ids) => {
            let mut unique: Vec<Uuid> = Vec::with_capacity(ids.len());
            for id in ids {
                if !unique.contains(id) {
                    unique.push(*id);
                }
            }
            if unique.is_empty() {
                return Err(validation(
                    "scope.group_ids must name at least one group for a groups scope",
                ));
            }
            if unique.len() > MAX_SCOPE_GROUPS {
                return Err(validation(format!(
                    "scope.group_ids may name at most {MAX_SCOPE_GROUPS} groups"
                )));
            }
            ScimTargetScope::Groups(unique)
        }
    };
    Ok(Checked {
        scope,
        auth,
        credential,
    })
}

/// Every group the scope names — that the target did not already name — exists
/// in the tenant.
async fn check_groups<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    scope: &ScimTargetScope,
    already_named: &[Uuid],
) -> Result<(), AxiamApiError> {
    let ScimTargetScope::Groups(ids) = scope else {
        return Ok(());
    };
    for id in ids.iter().filter(|id| !already_named.contains(id)) {
        match state.group_repo.get_by_id(tenant_id, *id).await {
            Ok(_) => {}
            Err(AxiamError::NotFound { .. }) => {
                return Err(validation(
                    "scope.group_ids names a group that does not exist in this tenant",
                ));
            }
            Err(other) => return Err(AxiamApiError(other)),
        }
    }
    Ok(())
}

/// D-57: the credential stays bound to the URL it was registered for. A write
/// that moves it, or switches the kind, must carry it; the `400` names the
/// field.
fn check_binding(
    old: &StoredTarget,
    base_url: &str,
    auth: &ScimTargetAuth,
    supplied: bool,
) -> Result<(), AxiamApiError> {
    if supplied {
        return Ok(());
    }
    match (&old.auth, auth) {
        (ScimTargetAuth::Bearer, ScimTargetAuth::Bearer) if old.base_url != base_url => {
            Err(validation(
                "changing base_url of a bearer target requires the credential in the same write",
            ))
        }
        (
            ScimTargetAuth::OAuth2ClientCredentials { token_url: old, .. },
            ScimTargetAuth::OAuth2ClientCredentials { token_url: new, .. },
        ) if old != new => Err(validation(
            "changing auth.token_url requires the credential in the same write",
        )),
        (ScimTargetAuth::Bearer, ScimTargetAuth::Bearer)
        | (
            ScimTargetAuth::OAuth2ClientCredentials { .. },
            ScimTargetAuth::OAuth2ClientCredentials { .. },
        ) => Ok(()),
        _ => Err(validation(
            "switching auth.type requires the credential in the same write",
        )),
    }
}

fn need_sealing<C: Connection + Clone>(
    state: &AppState<C>,
    sets_credential: bool,
) -> Result<(), AxiamApiError> {
    if sets_credential && !state.scim_targets.target_repo.has_encryption_key() {
        return Err(AxiamApiError(AxiamError::ServiceUnavailable(
            "a SCIM target credential cannot be stored: pki_encryption_key \
             (AXIAM__AUTH__PKI_ENCRYPTION_KEY) is not configured"
                .into(),
        )));
    }
    Ok(())
}

async fn audit<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    user: &AuthenticatedUser,
    action: &str,
    resource_id: Uuid,
    metadata: serde_json::Value,
) {
    if let Err(error) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id: user.tenant_id,
            actor_id: user.user_id,
            actor_type: ActorType::User,
            action: action.to_string(),
            resource_id: Some(resource_id),
            outcome: AuditOutcome::Success,
            ip_address: client_ip(http_req),
            metadata: Some(metadata),
        })
        .await
    {
        tracing::error!(
            target: "axiam::scim_target_admin",
            tenant_id = %user.tenant_id,
            action,
            %error,
            "a SCIM target registry audit row could not be written"
        );
    }
}

/// The names of the members an administrator's update changes. Names only.
fn changed_fields(
    old: &StoredTarget,
    new: &ScimTargetUpdate,
    credential_set: bool,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut note = |differs: bool, name: &'static str| {
        if differs {
            out.push(name);
        }
    };
    note(old.name != new.name, "name");
    note(old.base_url != new.base_url, "base_url");
    note(old.enabled != new.enabled, "enabled");
    note(old.auth != new.auth, "auth");
    note(credential_set, "credential");
    note(old.scope != new.scope, "scope");
    note(old.push_groups != new.push_groups, "push_groups");
    note(old.user_name_from != new.user_name_from, "user_name_from");
    note(old.deprovision != new.deprovision, "deprovision");
    out
}

/// A target's delivery state for a projection. A state row that cannot be read
/// does not fail the read of the target: it is `null`.
async fn state_of<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    target_id: Uuid,
) -> Option<StoredState> {
    match state
        .scim_targets
        .state_repo
        .get(tenant_id, target_id)
        .await
    {
        Ok(row) => Some(row),
        Err(AxiamError::NotFound { .. }) => None,
        Err(error) => {
            tracing::warn!(
                target: "axiam::scim_target_admin",
                %tenant_id,
                %target_id,
                %error,
                "a SCIM target's delivery state could not be read"
            );
            None
        }
    }
}

/// The initial synchronisation: start a reconciliation, which queues a
/// reference for everything in scope. Best effort — the target is written
/// whether or not it could be started, and the nightly job will find it.
async fn start_initial_sync<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    target_id: Uuid,
) {
    let Some(trigger) = state.scim_targets.reconcile.as_ref() else {
        return;
    };
    if let Err(error) = trigger.start(tenant_id, target_id).await {
        tracing::warn!(
            target: "axiam::scim_target_admin",
            %tenant_id,
            %target_id,
            %error,
            "the initial reconciliation of a SCIM target could not be started"
        );
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `GET /api/v1/scim-targets`
#[utoipa::path(
    get,
    path = "/api/v1/scim-targets",
    tag = "scim-targets",
    params(Pagination),
    responses(
        (status = 200, description = "A page of the tenant's outbound SCIM targets, oldest first, \
                                      each with its delivery state; `search` matches name, base \
                                      URL and id, before paging",
         body = inline(PaginatedResult<ScimTargetResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list_targets<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scim_targets:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let page = state
        .scim_targets
        .target_repo
        .list_page(user.tenant_id, query.into_inner())
        .await?;
    let mut items = Vec::with_capacity(page.items.len());
    for target in page.items {
        let delivery = state_of(&state, user.tenant_id, target.id).await;
        items.push(ScimTargetResponse::new(target, delivery));
    }
    Ok(HttpResponse::Ok().json(PaginatedResult {
        items,
        total: page.total,
        offset: page.offset,
        limit: page.limit,
    }))
}

/// `POST /api/v1/scim-targets`
#[utoipa::path(
    post,
    path = "/api/v1/scim-targets",
    tag = "scim-targets",
    request_body = ScimTargetInput,
    responses(
        (status = 201, description = "The target was registered. When it is enabled, a \
                                      reconciliation is started: the initial synchronisation",
         body = ScimTargetResponse),
        (status = 400, description = "A value rule — the message names the rule or the field"),
        (status = 429, description = "Rate limit"),
        (status = 503, description = "The credential cannot be sealed: pki_encryption_key is not \
                                      configured"),
    ),
    security(("bearer" = []))
)]
pub async fn create_target<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    body: web::Json<ScimTargetInput>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scim_targets:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = user.tenant_id;
    let input = body.into_inner();
    let checked = check_values(&input)?;
    let credential = checked
        .credential
        .ok_or_else(|| validation("credential is required to register a target"))?;
    check_groups(&state, tenant_id, &checked.scope, &[]).await?;
    need_sealing(&state, true)?;

    let created = state
        .scim_targets
        .target_repo
        .create(NewScimTarget {
            tenant_id,
            name: input.name.trim().to_owned(),
            base_url: input.base_url,
            enabled: input.enabled,
            auth: checked.auth,
            credential,
            scope: checked.scope,
            push_groups: input.push_groups,
            user_name_from: input.user_name_from,
            deprovision: input.deprovision,
        })
        .await?;

    audit(
        &state,
        &http_req,
        &user,
        AUDIT_TARGET_CREATED,
        created.id,
        serde_json::json!({
            "auth": created.auth.kind_str(),
            "scope": created.scope.kind_str(),
            "enabled": created.enabled,
            "push_groups": created.push_groups,
            "user_name_from": created.user_name_from.as_str(),
            "deprovision": created.deprovision.as_str(),
        }),
    )
    .await;
    if created.enabled {
        start_initial_sync(&state, tenant_id, created.id).await;
    }
    let delivery = state_of(&state, tenant_id, created.id).await;
    Ok(HttpResponse::Created().json(ScimTargetResponse::new(created, delivery)))
}

/// `GET /api/v1/scim-targets/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/scim-targets/{id}",
    tag = "scim-targets",
    params(("id" = Uuid, Path, description = "Target ID")),
    responses(
        (status = 200, description = "The target and its delivery state (last success and \
                                      failure, a fixed-vocabulary failure reason, consecutive \
                                      failures, dead-lettered total, last reconciliation). \
                                      The credential is never returned",
         body = ScimTargetResponse),
        (status = 404, description = "No such target in this tenant"),
    ),
    security(("bearer" = []))
)]
pub async fn get_target<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scim_targets:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let target = state
        .scim_targets
        .target_repo
        .get(user.tenant_id, id)
        .await?;
    let delivery = state_of(&state, user.tenant_id, id).await;
    Ok(HttpResponse::Ok().json(ScimTargetResponse::new(target, delivery)))
}

/// `PUT /api/v1/scim-targets/{id}`
///
/// A **replacement**: an omitted optional member takes its default, except the
/// credential, which absent keeps.
#[utoipa::path(
    put,
    path = "/api/v1/scim-targets/{id}",
    tag = "scim-targets",
    params(("id" = Uuid, Path, description = "Target ID")),
    request_body = ScimTargetInput,
    responses(
        (status = 200, description = "The target's new configuration. Enabling a disabled target \
                                      starts a reconciliation",
         body = ScimTargetResponse),
        (status = 400, description = "A value rule, or a move of the credential to another URL \
                                      (`base_url` of a bearer target, `auth.token_url` of a \
                                      client-credentials one) or a switch of `auth.type` \
                                      without the credential — the message names the field"),
        (status = 404, description = "No such target in this tenant"),
        (status = 409, description = "The target changed since it was read (reload it and retry)"),
        (status = 429, description = "Rate limit"),
        (status = 503, description = "A credential was given and the deployment cannot seal it"),
    ),
    security(("bearer" = []))
)]
pub async fn update_target<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<ScimTargetInput>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scim_targets:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = user.tenant_id;
    let id = path.into_inner();
    let input = body.into_inner();
    let checked = check_values(&input)?;
    let old = state.scim_targets.target_repo.get(tenant_id, id).await?;
    let named: Vec<Uuid> = match &old.scope {
        ScimTargetScope::Groups(ids) => ids.clone(),
        ScimTargetScope::AllUsers => Vec::new(),
    };
    check_groups(&state, tenant_id, &checked.scope, &named).await?;
    check_binding(
        &old,
        &input.base_url,
        &checked.auth,
        checked.credential.is_some(),
    )?;
    need_sealing(&state, checked.credential.is_some())?;

    let credential_set = checked.credential.is_some();
    let update = ScimTargetUpdate {
        name: input.name.trim().to_owned(),
        base_url: input.base_url,
        enabled: input.enabled,
        auth: checked.auth,
        credential: checked.credential,
        scope: checked.scope,
        push_groups: input.push_groups,
        user_name_from: input.user_name_from,
        deprovision: input.deprovision,
        // T-406: the replacement was checked against `old` (the binding, the
        // groups); it lands only if `old` is still the target's version, else
        // `409` and the administrator reloads.
        expected_updated_at: Some(old.updated_at),
    };
    let changed = changed_fields(&old, &update, credential_set);
    let updated = state
        .scim_targets
        .target_repo
        .update(tenant_id, id, update)
        .await?;

    audit(
        &state,
        &http_req,
        &user,
        AUDIT_TARGET_UPDATED,
        id,
        serde_json::json!({ "changed": changed, "enabled": updated.enabled }),
    )
    .await;
    if updated.enabled && !old.enabled {
        start_initial_sync(&state, tenant_id, id).await;
    }
    let delivery = state_of(&state, tenant_id, id).await;
    Ok(HttpResponse::Ok().json(ScimTargetResponse::new(updated, delivery)))
}

/// `DELETE /api/v1/scim-targets/{id}`
///
/// The target, its link rows and its delivery state. **Nothing is
/// deprovisioned downstream**: the users and groups AXIAM created there stay.
#[utoipa::path(
    delete,
    path = "/api/v1/scim-targets/{id}",
    tag = "scim-targets",
    params(("id" = Uuid, Path, description = "Target ID")),
    responses(
        (status = 204, description = "The target, its link rows and its delivery state were \
                                      deleted. Nothing is deprovisioned downstream: the users \
                                      and groups AXIAM created in the service provider remain \
                                      there, and AXIAM no longer knows them"),
        (status = 404, description = "No such target in this tenant"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_target<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scim_targets:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    state
        .scim_targets
        .target_repo
        .delete(user.tenant_id, id)
        .await?;
    audit(
        &state,
        &http_req,
        &user,
        AUDIT_TARGET_DELETED,
        id,
        serde_json::json!({}),
    )
    .await;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/scim-targets/{id}/reconcile`
///
/// Start a reconciliation now.
#[utoipa::path(
    post,
    path = "/api/v1/scim-targets/{id}/reconcile",
    tag = "scim-targets",
    params(("id" = Uuid, Path, description = "Target ID")),
    responses(
        (status = 202, description = "The reconciliation was claimed and runs in the background: \
                                      it queues a reference for every user and group in scope \
                                      and for every linked resource, reads the downstream and \
                                      repairs drift. Its outcome is on the target's delivery \
                                      state",
         body = ScimReconcileAccepted),
        (status = 404, description = "No such target in this tenant"),
        (status = 409, description = "A reconciliation holds the claim (or ran within the last \
                                      five minutes), or the target is disabled"),
        (status = 429, description = "Rate limit"),
        (status = 503, description = "Delivery is not wired in this deployment"),
    ),
    security(("bearer" = []))
)]
pub async fn reconcile_target<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scim_targets:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let trigger = state.scim_targets.reconcile.as_ref().ok_or_else(|| {
        AxiamApiError(AxiamError::ServiceUnavailable(
            "outbound SCIM delivery is not available in this deployment".into(),
        ))
    })?;
    match trigger.start(user.tenant_id, id).await? {
        ScimReconcileStart::Started => {
            audit(
                &state,
                &http_req,
                &user,
                AUDIT_TARGET_RECONCILE_REQUESTED,
                id,
                serde_json::json!({}),
            )
            .await;
            Ok(HttpResponse::Accepted().json(ScimReconcileAccepted {
                target_id: id,
                status: "started",
            }))
        }
        ScimReconcileStart::AlreadyClaimed => Err(AxiamApiError(AxiamError::Conflict {
            reason: "a reconciliation of this target is running or has only just finished".into(),
        })),
        ScimReconcileStart::TargetDisabled => Err(AxiamApiError(AxiamError::Conflict {
            reason: "the target is disabled: enable it to reconcile".into(),
        })),
    }
}
