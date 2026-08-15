//! SCIM `/Groups` resource (RFC 7643 §4.2, RFC 7644 §3.2-3.6).
//!
//! Maps onto the EXISTING `GroupRepository` (B4) — no parallel storage;
//! membership is the same `member_of` graph edge
//! `add_member`/`remove_member`/`get_members` already maintain for the admin
//! UI.
//!
//! # Webhooks — intentionally none here
//!
//! B4 says "emit the SAME webhooks ... as native user/group CRUD — find
//! where native CRUD emits them and reuse that path." That path is
//! `axiam_api_rest::handlers::users` for users (`user.created`/`updated`/
//! `deleted`, reused in `users.rs`) — but `axiam_api_rest::handlers::groups`
//! emits **no** webhooks at all today (verified: zero `emit_webhook` call
//! sites in that file). Reusing "that path" for groups therefore means
//! reusing its absence, not inventing a `group.created` event native group
//! CRUD has never emitted. Audit logging is unaffected either way — it comes
//! from the global `AuditMiddleware` wrap in `axiam-server`, not from
//! per-handler calls, so `/scim/v2/Groups/*` is audited exactly like
//! `/api/v1/groups/*` regardless.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::models::group::{CreateGroup, Group, UpdateGroup};
use axiam_core::repository::{GroupRepository, Pagination};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use surrealdb::Connection;
use uuid::Uuid;

use axiam_api_rest::authz::AuthzData;
use axiam_api_rest::extractors::auth::AuthenticatedUser;
use axiam_api_rest::state::AppState;

use crate::auth::require_scim_provision;
use crate::error::ScimError;
use crate::patch::{GroupPatchDelta, MemberAction, PatchRequest, parse_group_patch};
use crate::schema::GROUP_SCHEMA;
use crate::scim_metadata;
use crate::users::{
    ScimListQuery, ScimListResponse, ScimMeta, clamp_count, location_url, start_index_to_offset,
};

/// Full-membership scan/embed cap — mirrors `users.rs::EXTERNAL_ID_SCAN_CAP`
/// for the same "documented limitation, not silent truncation" reason. A
/// group with more members than this shows only the first
/// [`MEMBER_EMBED_CAP`] (by creation order) in the `members` array; SCIM's
/// own answer to this (`excludedAttributes=members` + a separate
/// `/Groups/{id}/members`-style fetch) is out of B4's scope.
const MEMBER_EMBED_CAP: u64 = 1000;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ScimMemberInput {
    pub value: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct ScimGroupWrite {
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "externalId", default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub members: Vec<ScimMemberInput>,
}

#[derive(Debug, Serialize)]
pub struct ScimMember {
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display: Option<String>,
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ScimGroup {
    schemas: [&'static str; 1],
    id: String,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    members: Vec<ScimMember>,
    meta: ScimMeta,
}

impl ScimGroup {
    fn build(group: &Group, members: Vec<ScimMember>, req: &HttpRequest) -> Self {
        let id = group.id.to_string();
        Self {
            schemas: [GROUP_SCHEMA],
            external_id: scim_metadata::get_str(&group.metadata, "externalId"),
            display_name: group.name.clone(),
            members,
            meta: ScimMeta {
                resource_type: "Group",
                created: group.created_at,
                last_modified: group.updated_at,
                location: location_url(req, "Groups", &id),
            },
            id,
        }
    }
}

/// Fetch and shape the group's members for embedding in a `ScimGroup`
/// response, capped at [`MEMBER_EMBED_CAP`].
async fn scim_members<C: Connection + Clone>(
    state: &web::Data<AppState<C>>,
    tenant_id: Uuid,
    group_id: Uuid,
) -> Result<Vec<ScimMember>, ScimError> {
    let result = state
        .group_repo
        .get_members(
            tenant_id,
            group_id,
            Pagination {
                offset: 0,
                limit: MEMBER_EMBED_CAP,
            },
        )
        .await?;
    Ok(result
        .items
        .into_iter()
        .map(|u| ScimMember {
            value: u.id.to_string(),
            display: Some(u.username),
            kind: "User",
        })
        .collect())
}

fn build_scim_metadata(external_id: &Option<String>) -> Value {
    let mut metadata = json!({});
    if let Some(ext) = external_id {
        scim_metadata::set_str(&mut metadata, "externalId", Some(ext.clone()));
    }
    metadata
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /scim/v2/Groups`
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

    let groups: Vec<Group> = match query.filter {
        None => {
            let result = state
                .group_repo
                .list(user.tenant_id, Pagination { offset, limit })
                .await?;
            let mut resources = Vec::with_capacity(result.items.len());
            for g in &result.items {
                let members = scim_members(&state, user.tenant_id, g.id).await?;
                resources.push(ScimGroup::build(g, members, &http_req));
            }
            return Ok(HttpResponse::Ok().json(ScimListResponse::new(
                resources,
                result.total,
                start_index,
            )));
        }
        Some(raw) => {
            // Groups only support `externalId eq` (B4: `userName eq` is a
            // User-only attribute).
            let filter = crate::filter::parse_eq_filter(&raw, &["externalid"])?;
            let all = state
                .group_repo
                .list(
                    user.tenant_id,
                    Pagination {
                        offset: 0,
                        limit: MEMBER_EMBED_CAP,
                    },
                )
                .await?;
            all.items
                .into_iter()
                .filter(|g| {
                    scim_metadata::get_str(&g.metadata, "externalId").as_deref()
                        == Some(filter.value.as_str())
                })
                .collect()
        }
    };

    let total = groups.len() as u64;
    let mut resources = Vec::new();
    for g in groups
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
    {
        let members = scim_members(&state, user.tenant_id, g.id).await?;
        resources.push(ScimGroup::build(&g, members, &http_req));
    }
    Ok(HttpResponse::Ok().json(ScimListResponse::new(resources, total, start_index)))
}

/// `GET /scim/v2/Groups/{id}`
pub async fn get<C: Connection + Clone>(
    http_req: HttpRequest,
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let id = path.into_inner();
    let group = state.group_repo.get_by_id(user.tenant_id, id).await?;
    let members = scim_members(&state, user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(ScimGroup::build(&group, members, &http_req)))
}

/// `POST /scim/v2/Groups`
pub async fn create<C: Connection + Clone>(
    http_req: HttpRequest,
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<ScimGroupWrite>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let req = body.into_inner();

    let created = state
        .group_repo
        .create(CreateGroup {
            tenant_id: user.tenant_id,
            name: req.display_name.clone(),
            description: String::new(),
            metadata: Some(build_scim_metadata(&req.external_id)),
        })
        .await?;

    // Best-effort, in request order — not wrapped in a transaction. A member
    // id that doesn't resolve (wrong tenant, unknown user) fails the whole
    // request with that id named in the error, but any members already
    // added before it stay added: `add_member` has no batch/rollback form to
    // build on (out of scope per B4: "explicitly out of scope: bulk
    // operations" — this crate does not introduce a new transaction
    // boundary `axiam-db`'s repositories don't already have).
    for member in &req.members {
        state
            .group_repo
            .add_member(user.tenant_id, member.value, created.id)
            .await?;
    }

    let members = scim_members(&state, user.tenant_id, created.id).await?;
    let scim_group = ScimGroup::build(&created, members, &http_req);
    let location = scim_group.meta.location.clone();
    Ok(HttpResponse::Created()
        .append_header(("Location", location))
        .json(scim_group))
}

/// `PUT /scim/v2/Groups/{id}` — full replace, including membership
/// (RFC 7644 §3.5.1): the requested `members` array becomes the group's
/// entire membership, computed as an add/remove diff against the current
/// set.
pub async fn replace<C: Connection + Clone>(
    http_req: HttpRequest,
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<ScimGroupWrite>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let id = path.into_inner();
    let current = state.group_repo.get_by_id(user.tenant_id, id).await?;
    let req = body.into_inner();

    let mut metadata = current.metadata.clone();
    if let Some(obj) = metadata.as_object_mut() {
        obj.remove("scim");
    }
    if let Some(ext) = &req.external_id {
        scim_metadata::set_str(&mut metadata, "externalId", Some(ext.clone()));
    }

    let updated = state
        .group_repo
        .update(
            user.tenant_id,
            id,
            UpdateGroup {
                name: Some(req.display_name.clone()),
                metadata: Some(metadata),
                ..Default::default()
            },
        )
        .await?;

    let current_member_ids: std::collections::HashSet<Uuid> = state
        .group_repo
        .get_members(
            user.tenant_id,
            id,
            Pagination {
                offset: 0,
                limit: MEMBER_EMBED_CAP,
            },
        )
        .await?
        .items
        .into_iter()
        .map(|u| u.id)
        .collect();
    let requested_ids: std::collections::HashSet<Uuid> =
        req.members.iter().map(|m| m.value).collect();

    for to_add in requested_ids.difference(&current_member_ids) {
        state
            .group_repo
            .add_member(user.tenant_id, *to_add, id)
            .await?;
    }
    for to_remove in current_member_ids.difference(&requested_ids) {
        state
            .group_repo
            .remove_member(user.tenant_id, *to_remove, id)
            .await?;
    }

    let members = scim_members(&state, user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(ScimGroup::build(&updated, members, &http_req)))
}

fn group_patch_is_noop(u: &UpdateGroup, actions: &[MemberAction]) -> bool {
    u.name.is_none() && u.metadata.is_none() && actions.is_empty()
}

/// `PATCH /scim/v2/Groups/{id}` (RFC 7644 §3.5.2) — op subset in
/// [`crate::patch`], including the Okta/Entra `members[value eq "<uuid>"]`
/// single-member-removal shape.
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
    let current = state.group_repo.get_by_id(user.tenant_id, id).await?;
    let delta: GroupPatchDelta = parse_group_patch(&body.into_inner())?;

    let mut metadata_update: Option<Value> = None;
    if let Some(ext) = &delta.external_id {
        let mut metadata = current.metadata.clone();
        scim_metadata::set_str(&mut metadata, "externalId", ext.clone());
        metadata_update = Some(metadata);
    }

    let update = UpdateGroup {
        name: delta.display_name.clone(),
        metadata: metadata_update,
        ..Default::default()
    };

    let group = if group_patch_is_noop(&update, &delta.member_actions) {
        current
    } else if update.name.is_some() || update.metadata.is_some() {
        state.group_repo.update(user.tenant_id, id, update).await?
    } else {
        current
    };

    for action in &delta.member_actions {
        match action {
            MemberAction::Add(member_id) => {
                state
                    .group_repo
                    .add_member(user.tenant_id, *member_id, id)
                    .await?;
            }
            MemberAction::Remove(member_id) => {
                state
                    .group_repo
                    .remove_member(user.tenant_id, *member_id, id)
                    .await?;
            }
            MemberAction::RemoveAll => {
                let existing = state
                    .group_repo
                    .get_members(
                        user.tenant_id,
                        id,
                        Pagination {
                            offset: 0,
                            limit: MEMBER_EMBED_CAP,
                        },
                    )
                    .await?;
                for member in existing.items {
                    state
                        .group_repo
                        .remove_member(user.tenant_id, member.id, id)
                        .await?;
                }
            }
        }
    }

    let members = scim_members(&state, user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(ScimGroup::build(&group, members, &http_req)))
}

/// `DELETE /scim/v2/Groups/{id}`
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let id = path.into_inner();
    // `GroupRepository::delete`'s `WHERE tenant_id = $tenant_id` predicate
    // already makes a cross-tenant delete a correct, silent no-op (no other
    // tenant's row is ever touched) — but unlike `update`/`get_by_id`, it
    // does not check whether it actually deleted a row, so it returns `Ok`
    // even for an id that does not exist in the caller's tenant, which
    // would surface here as a wrong `204` instead of `404` (the same
    // wrong-status gap exists in the native `/api/v1/groups/{id}` DELETE
    // handler — this pre-check is a SCIM-local hardening, not a fix to
    // shared `axiam-db` code). `get_by_id` is already tenant-scoped and
    // correctly 404s, so it doubles as the existence check delete needs.
    state.group_repo.get_by_id(user.tenant_id, id).await?;
    state.group_repo.delete(user.tenant_id, id).await?;
    Ok(HttpResponse::NoContent().finish())
}
