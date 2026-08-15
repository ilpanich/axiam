//! SCIM `/Users` resource (RFC 7643 §4.1, RFC 7644 §3.2-3.6).
//!
//! Maps onto the EXISTING `UserRepository` (B4) — no parallel storage.
//! AXIAM's `User` model has no `externalId`/`name.*` columns, so those live
//! inside the existing generic `metadata` JSON column under a `"scim"`
//! sub-key (see [`crate::scim_metadata`]); everything else (`userName` <->
//! `username`, `active` <-> `status == Active`, `emails[primary]` <->
//! `email`) is a direct field mapping.
//!
//! Every handler here mirrors the native `POST/GET/PUT/DELETE
//! /api/v1/users` handlers (`axiam_api_rest::handlers::users`) for the parts
//! B4 requires parity on: same `create_with_consent` GDPR path, the same
//! `emit_webhook` event names (`user.created`/`user.updated`/
//! `user.deleted`), and the same D7 `invalidate_subject` cache flush on a
//! status-narrowing update.
//!
//! # ETag (optional-v2)
//!
//! Not implemented. `ServiceProviderConfig` advertises `etag.supported:
//! false`. Emitting a weak ETag (`W/"<updated_at millis>"`) on every
//! response, and honoring `If-Match` on PUT/PATCH/DELETE, is cheap enough to
//! be a reasonable follow-on — it just wasn't judged in-scope for B4's
//! "implement if cheap, otherwise leave a documented TODO."

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::password;
use axiam_core::error::AxiamError;
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{Pagination, UserRepository};
use chrono::{DateTime, Utc};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use surrealdb::Connection;
use uuid::Uuid;

use axiam_api_rest::authz::AuthzData;
use axiam_api_rest::extractors::auth::AuthenticatedUser;
use axiam_api_rest::extractors::client_info::{client_ip, user_agent};
use axiam_api_rest::state::AppState;

use crate::auth::require_scim_provision;
use crate::error::ScimError;
use crate::patch::{PatchRequest, UserPatchDelta, parse_user_patch};
use crate::schema::{SCIM_LIST_RESPONSE_SCHEMA, USER_SCHEMA};
use crate::scim_metadata;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ScimNameInput {
    #[serde(default)]
    pub formatted: Option<String>,
    #[serde(rename = "givenName", default)]
    pub given_name: Option<String>,
    #[serde(rename = "familyName", default)]
    pub family_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ScimEmailInput {
    pub value: String,
    #[serde(default)]
    pub primary: Option<bool>,
}

fn default_active() -> bool {
    true
}

/// Body shape for both `POST /Users` (create) and `PUT /Users/{id}`
/// (full replace) — RFC 7644 §3.3/§3.5.1 use the same resource
/// representation for both.
#[derive(Debug, Deserialize)]
pub struct ScimUserWrite {
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "externalId", default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub name: Option<ScimNameInput>,
    #[serde(default)]
    pub emails: Vec<ScimEmailInput>,
    #[serde(default = "default_active")]
    pub active: bool,
    /// Optional. Okta/Entra do not reliably send a real credential over
    /// SCIM push (provisioned users typically authenticate via SSO/
    /// federation, not a local password) — when absent, [`create`] generates
    /// a random one server-side; it is never returned.
    #[serde(default)]
    pub password: Option<String>,
}

fn primary_email(emails: &[ScimEmailInput]) -> Option<String> {
    emails
        .iter()
        .find(|e| e.primary == Some(true))
        .or_else(|| emails.first())
        .map(|e| e.value.clone())
}

#[derive(Debug, Serialize)]
pub struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none")]
    formatted: Option<String>,
    #[serde(rename = "givenName", skip_serializing_if = "Option::is_none")]
    given_name: Option<String>,
    #[serde(rename = "familyName", skip_serializing_if = "Option::is_none")]
    family_name: Option<String>,
}

impl ScimName {
    fn from_metadata(metadata: &Value) -> Option<Self> {
        let formatted = scim_metadata::get_str(metadata, "formatted");
        let given_name = scim_metadata::get_str(metadata, "givenName");
        let family_name = scim_metadata::get_str(metadata, "familyName");
        if formatted.is_none() && given_name.is_none() && family_name.is_none() {
            return None;
        }
        Some(Self {
            formatted,
            given_name,
            family_name,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ScimEmail {
    value: String,
    primary: bool,
}

/// Shared by `ScimUser` and `ScimGroup` (`groups.rs` constructs this
/// directly — fields are `pub(crate)` for exactly that reuse).
#[derive(Debug, Serialize)]
pub struct ScimMeta {
    #[serde(rename = "resourceType")]
    pub(crate) resource_type: &'static str,
    pub(crate) created: DateTime<Utc>,
    #[serde(rename = "lastModified")]
    pub(crate) last_modified: DateTime<Utc>,
    pub(crate) location: String,
}

#[derive(Debug, Serialize)]
pub struct ScimUser {
    schemas: [&'static str; 1],
    id: String,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    #[serde(rename = "userName")]
    user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<ScimName>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    emails: Vec<ScimEmail>,
    active: bool,
    meta: ScimMeta,
}

pub(crate) fn location_url(req: &HttpRequest, kind: &str, id: &str) -> String {
    let ci = req.connection_info();
    format!("{}://{}/scim/v2/{kind}/{id}", ci.scheme(), ci.host())
}

impl ScimUser {
    fn from_user(user: &User, req: &HttpRequest) -> Self {
        let id = user.id.to_string();
        Self {
            schemas: [USER_SCHEMA],
            external_id: scim_metadata::get_str(&user.metadata, "externalId"),
            user_name: user.username.clone(),
            name: ScimName::from_metadata(&user.metadata),
            emails: if user.email.is_empty() {
                vec![]
            } else {
                vec![ScimEmail {
                    value: user.email.clone(),
                    primary: true,
                }]
            },
            active: user.status == UserStatus::Active,
            meta: ScimMeta {
                resource_type: "User",
                created: user.created_at,
                last_modified: user.updated_at,
                location: location_url(req, "Users", &id),
            },
            id,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ScimListResponse<T> {
    schemas: [&'static str; 1],
    #[serde(rename = "totalResults")]
    total_results: u64,
    #[serde(rename = "itemsPerPage")]
    items_per_page: u64,
    #[serde(rename = "startIndex")]
    start_index: u64,
    #[serde(rename = "Resources")]
    resources: Vec<T>,
}

impl<T> ScimListResponse<T> {
    pub(crate) fn new(resources: Vec<T>, total: u64, start_index: u64) -> Self {
        Self {
            schemas: [SCIM_LIST_RESPONSE_SCHEMA],
            total_results: total,
            items_per_page: resources.len() as u64,
            start_index,
            resources,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ScimListQuery {
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(rename = "startIndex", default)]
    pub start_index: Option<u64>,
    #[serde(default)]
    pub count: Option<u64>,
}

/// Full-tenant scan cap for the `externalId eq` filter (B4's filtering
/// subset has no indexed lookup for it — only `userName` has a dedicated
/// repository method). Documented limitation, not a silent truncation: a
/// tenant with more users than this returns a filtered result computed over
/// only the first [`EXTERNAL_ID_SCAN_CAP`] (by `created_at`), which is the
/// same trade-off `axiam-api-rest`'s own admin-UI search boxes make today.
const EXTERNAL_ID_SCAN_CAP: u64 = 1000;

pub(crate) fn start_index_to_offset(start_index: Option<u64>) -> u64 {
    start_index.unwrap_or(1).max(1) - 1
}

pub(crate) fn clamp_count(count: Option<u64>) -> u64 {
    count.unwrap_or(50).min(200)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /scim/v2/Users`
pub async fn list<C: Connection + Clone>(
    http_req: HttpRequest,
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    query: web::Query<ScimListQuery>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let query = query.into_inner();
    let start_index = query.start_index.unwrap_or(1).max(1);
    let offset = start_index_to_offset(query.start_index);
    let limit = clamp_count(query.count);

    let Some(raw_filter) = query.filter else {
        return list_unfiltered(&http_req, &user, &state, offset, limit, start_index).await;
    };

    let filter = crate::filter::parse_eq_filter(&raw_filter, &["username", "externalid"])?;
    match filter.attr.as_str() {
        "username" => {
            let (items, total) = match state
                .user_repo
                .get_by_username(user.tenant_id, &filter.value)
                .await
            {
                Ok(u) if offset == 0 && limit > 0 => (vec![u], 1),
                Ok(_) => (vec![], 1),
                Err(AxiamError::NotFound { .. }) => (vec![], 0),
                Err(e) => return Err(e.into()),
            };
            let resources: Vec<ScimUser> = items
                .iter()
                .map(|u| ScimUser::from_user(u, &http_req))
                .collect();
            Ok(HttpResponse::Ok().json(ScimListResponse::new(resources, total, start_index)))
        }
        "externalid" => {
            let all = state
                .user_repo
                .list(
                    user.tenant_id,
                    Pagination {
                        offset: 0,
                        limit: EXTERNAL_ID_SCAN_CAP,
                    },
                )
                .await?;
            let matched: Vec<&User> = all
                .items
                .iter()
                .filter(|u| {
                    scim_metadata::get_str(&u.metadata, "externalId").as_deref()
                        == Some(filter.value.as_str())
                })
                .collect();
            let total = matched.len() as u64;
            let page: Vec<ScimUser> = matched
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(|u| ScimUser::from_user(u, &http_req))
                .collect();
            Ok(HttpResponse::Ok().json(ScimListResponse::new(page, total, start_index)))
        }
        // parse_eq_filter already rejects anything not in the allow-list.
        _ => unreachable!("parse_eq_filter enforces the allowed-attribute list"),
    }
}

async fn list_unfiltered<C: Connection + Clone>(
    http_req: &HttpRequest,
    user: &AuthenticatedUser,
    state: &web::Data<AppState<C>>,
    offset: u64,
    limit: u64,
    start_index: u64,
) -> Result<HttpResponse, ScimError> {
    if limit == 0 {
        // Still need an accurate totalResults; LIMIT 1 gets it cheaply.
        let probe = state
            .user_repo
            .list(
                user.tenant_id,
                Pagination {
                    offset: 0,
                    limit: 1,
                },
            )
            .await?;
        return Ok(HttpResponse::Ok().json(ScimListResponse::<ScimUser>::new(
            vec![],
            probe.total,
            start_index,
        )));
    }
    let result = state
        .user_repo
        .list(user.tenant_id, Pagination { offset, limit })
        .await?;
    let resources: Vec<ScimUser> = result
        .items
        .iter()
        .map(|u| ScimUser::from_user(u, http_req))
        .collect();
    Ok(HttpResponse::Ok().json(ScimListResponse::new(resources, result.total, start_index)))
}

/// `GET /scim/v2/Users/{id}`
pub async fn get<C: Connection + Clone>(
    http_req: HttpRequest,
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let target = state
        .user_repo
        .get_by_id(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(ScimUser::from_user(&target, &http_req)))
}

fn build_scim_metadata(external_id: &Option<String>, name: &Option<ScimNameInput>) -> Value {
    let mut metadata = json!({});
    if let Some(ext) = external_id {
        scim_metadata::set_str(&mut metadata, "externalId", Some(ext.clone()));
    }
    if let Some(name) = name {
        if let Some(g) = &name.given_name {
            scim_metadata::set_str(&mut metadata, "givenName", Some(g.clone()));
        }
        if let Some(f) = &name.family_name {
            scim_metadata::set_str(&mut metadata, "familyName", Some(f.clone()));
        }
        if let Some(fmt) = &name.formatted {
            scim_metadata::set_str(&mut metadata, "formatted", Some(fmt.clone()));
        }
    }
    metadata
}

/// A random, high-entropy password for SCIM-provisioned users that didn't
/// supply one. Never returned to any caller; the account is expected to
/// authenticate via SSO/federation, not a local password.
fn random_password() -> String {
    format!("{}{}", Uuid::new_v4(), Uuid::new_v4())
}

/// `POST /scim/v2/Users`
pub async fn create<C: Connection + Clone>(
    http_req: HttpRequest,
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<ScimUserWrite>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let req = body.into_inner();

    let email = primary_email(&req.emails).ok_or_else(|| {
        ScimError::invalid_value(
            "\"emails\" with at least one entry is required to provision an AXIAM user",
        )
    })?;

    let metadata = build_scim_metadata(&req.external_id, &req.name);
    let password = req.password.clone().unwrap_or_else(random_password);

    let input = CreateUser {
        tenant_id: user.tenant_id,
        username: req.user_name.clone(),
        email,
        password,
        metadata: Some(metadata),
    };

    // Mirrors handlers::users::create exactly (axiam-api-rest): the
    // Art. 7 proof-of-consent row is written in the SAME transaction as the
    // user, so a SCIM-provisioned user can never exist without it either.
    let ip_address = client_ip(&http_req);
    let ua = user_agent(&http_req);
    let created = state
        .user_repo
        .create_with_consent(input, "terms_of_service", "current", ip_address, ua)
        .await?;

    // CreateUser has no `status` field — every new user starts
    // PendingVerification regardless of what was requested, which SCIM's
    // `active` (== status == Active) would read back as `false` even for a
    // fixture that explicitly asked for `active: true`. Set the status
    // explicitly with a follow-up update so `active` in the create response
    // matches what was requested, in both directions.
    let final_status = if req.active {
        UserStatus::Active
    } else {
        UserStatus::Inactive
    };
    let final_user = state
        .user_repo
        .update(
            user.tenant_id,
            created.id,
            UpdateUser {
                status: Some(final_status),
                ..Default::default()
            },
        )
        .await?;

    // Same webhook event/payload shape as native user creation.
    state
        .emit_webhook(
            final_user.tenant_id,
            "user.created",
            json!({ "id": final_user.id, "username": final_user.username }),
        )
        .await;

    let scim_user = ScimUser::from_user(&final_user, &http_req);
    Ok(HttpResponse::Created()
        .append_header(("Location", scim_user.meta.location.clone()))
        .json(scim_user))
}

/// `PUT /scim/v2/Users/{id}` — full replace (RFC 7644 §3.5.1).
pub async fn replace<C: Connection + Clone>(
    http_req: HttpRequest,
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<ScimUserWrite>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let id = path.into_inner();
    let current = state.user_repo.get_by_id(user.tenant_id, id).await?;
    let req = body.into_inner();

    let email = primary_email(&req.emails).ok_or_else(|| {
        ScimError::invalid_value("\"emails\" with at least one entry is required")
    })?;

    // PUT is a full replace of the SCIM-visible representation: rebuild the
    // "scim" metadata sub-object from scratch, but leave any OTHER top-level
    // metadata key (written by some other feature) exactly as it was.
    let mut metadata = current.metadata.clone();
    if let Some(obj) = metadata.as_object_mut() {
        obj.remove("scim");
    }
    let scim_fields = build_scim_metadata(&req.external_id, &req.name);
    if let Some(scim_obj) = scim_fields.get("scim") {
        if !metadata.is_object() {
            metadata = json!({});
        }
        metadata
            .as_object_mut()
            .expect("just ensured object above")
            .insert("scim".to_string(), scim_obj.clone());
    }

    let status = if req.active {
        UserStatus::Active
    } else {
        UserStatus::Inactive
    };

    let updated = state
        .user_repo
        .update(
            user.tenant_id,
            id,
            UpdateUser {
                username: Some(req.user_name.clone()),
                email: Some(email),
                status: Some(status),
                metadata: Some(metadata),
                ..Default::default()
            },
        )
        .await?;

    // D7 parity with handlers::users::update: a PUT can narrow access via
    // `status`, so flush this subject's cached authz decisions.
    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id, id)
        .await?;

    state
        .emit_webhook(
            updated.tenant_id,
            "user.updated",
            json!({ "id": updated.id, "username": updated.username }),
        )
        .await;

    Ok(HttpResponse::Ok().json(ScimUser::from_user(&updated, &http_req)))
}

fn user_patch_is_noop(u: &UpdateUser) -> bool {
    u.username.is_none()
        && u.email.is_none()
        && u.status.is_none()
        && u.metadata.is_none()
        && u.password_hash.is_none()
}

fn apply_user_delta_metadata(current: &Value, delta: &UserPatchDelta) -> Option<Value> {
    let touches_metadata = delta.external_id.is_some()
        || delta.given_name.is_some()
        || delta.family_name.is_some()
        || delta.formatted.is_some();
    if !touches_metadata {
        return None;
    }
    let mut metadata = current.clone();
    if let Some(ext) = &delta.external_id {
        scim_metadata::set_str(&mut metadata, "externalId", ext.clone());
    }
    if let Some(g) = &delta.given_name {
        scim_metadata::set_str(&mut metadata, "givenName", g.clone());
    }
    if let Some(f) = &delta.family_name {
        scim_metadata::set_str(&mut metadata, "familyName", f.clone());
    }
    if let Some(fmt) = &delta.formatted {
        scim_metadata::set_str(&mut metadata, "formatted", fmt.clone());
    }
    Some(metadata)
}

/// `PATCH /scim/v2/Users/{id}` (RFC 7644 §3.5.2) — op subset in
/// [`crate::patch`].
pub async fn patch<C: Connection + Clone>(
    http_req: HttpRequest,
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<PatchRequest>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let id = path.into_inner();
    let current = state.user_repo.get_by_id(user.tenant_id, id).await?;
    let delta = parse_user_patch(&body.into_inner())?;

    // Hash with the server-configured pepper, exactly as the bootstrap and login
    // paths do (see `axiam_api_rest::handlers::bootstrap`). Hashing with `None`
    // here would store a hash computed WITHOUT the pepper while login verifies
    // WITH it, so every SCIM-provisioned user would fail authentication.
    let pepper = state.auth_config.pepper.as_ref().map(|p| p.expose_secret());
    let password_hash = match &delta.password {
        Some(pw) => Some(password::hash_password(pw, pepper).map_err(|e| {
            ScimError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("password hashing failed: {e}"),
            )
        })?),
        None => None,
    };

    let update = UpdateUser {
        username: delta.username.clone(),
        email: delta.email.clone(),
        status: delta.active.map(|a| {
            if a {
                UserStatus::Active
            } else {
                UserStatus::Inactive
            }
        }),
        metadata: apply_user_delta_metadata(&current.metadata, &delta),
        password_hash,
        ..Default::default()
    };

    let updated = if user_patch_is_noop(&update) {
        current
    } else {
        let u = state.user_repo.update(user.tenant_id, id, update).await?;
        authz
            .get_ref()
            .as_ref()
            .invalidate_subject(user.tenant_id, id)
            .await?;
        state
            .emit_webhook(
                u.tenant_id,
                "user.updated",
                json!({ "id": u.id, "username": u.username }),
            )
            .await;
        u
    };

    Ok(HttpResponse::Ok().json(ScimUser::from_user(&updated, &http_req)))
}

/// `DELETE /scim/v2/Users/{id}`
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let id = path.into_inner();
    state.user_repo.delete(user.tenant_id, id).await?;

    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id, id)
        .await?;

    state
        .emit_webhook(user.tenant_id, "user.deleted", json!({ "id": id }))
        .await;

    Ok(HttpResponse::NoContent().finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_email_prefers_flagged_entry() {
        let emails = vec![
            ScimEmailInput {
                value: "a@x.com".into(),
                primary: Some(false),
            },
            ScimEmailInput {
                value: "b@x.com".into(),
                primary: Some(true),
            },
        ];
        assert_eq!(primary_email(&emails), Some("b@x.com".to_string()));
    }

    #[test]
    fn primary_email_falls_back_to_first() {
        let emails = vec![ScimEmailInput {
            value: "a@x.com".into(),
            primary: None,
        }];
        assert_eq!(primary_email(&emails), Some("a@x.com".to_string()));
    }

    #[test]
    fn primary_email_none_when_empty() {
        assert_eq!(primary_email(&[]), None);
    }

    #[test]
    fn start_index_and_count_clamp() {
        assert_eq!(start_index_to_offset(None), 0);
        assert_eq!(start_index_to_offset(Some(1)), 0);
        assert_eq!(start_index_to_offset(Some(0)), 0);
        assert_eq!(start_index_to_offset(Some(11)), 10);
        assert_eq!(clamp_count(None), 50);
        assert_eq!(clamp_count(Some(0)), 0);
        assert_eq!(clamp_count(Some(1000)), 200);
    }
}
