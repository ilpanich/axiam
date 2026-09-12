//! SCIM `/Users` resource (RFC 7643 §4.1, RFC 7644 §3.2-3.6).
//!
//! Maps onto the EXISTING `UserRepository` (B4) — no parallel storage.
//! AXIAM's `User` model has no `externalId`/`name.*` columns, so those live
//! inside the existing generic `metadata` JSON column under a `"scim"`
//! sub-key (see [`crate::scim_metadata`]); everything else (`userName` <->
//! `username`, `active` <-> `status == Active`, `emails[primary]` <->
//! `email`) is a direct field mapping.
//!
//! # `phoneNumbers` and `addresses` (X7 G8 / W7)
//!
//! Both were dropped on the floor until W7 — parsed by nobody, stored nowhere,
//! and absent from every response. They now map onto real columns
//! (`user.phone_number`, `user.address`), and the mapping is a rename rather
//! than a translation because RFC 7643 §4.1.2's address members and OIDC
//! Core §5.1.1's are the same six fields.
//!
//! **AXIAM keeps one of each.** OIDC Core §5.1 defines one `phone_number`
//! claim and one `address` claim, so a multi-valued attribute would be storage
//! with nothing to release it through; the entry marked `primary` wins, else
//! the first, which is the rule `emails` already follows. `type` (`"work"`,
//! `"home"`) is accepted and not stored, for the reason Art. 5(1)(c) gives:
//! it is personal data nothing in this system reads.
//!
//! Provisioning them does **not** release them. What reaches a relying party
//! is decided four gates later, at UserInfo, by the tenant switch, the
//! client's registered scopes, the request's scopes and the subject's consent
//! record — see `axiam_oauth2::sensitive`. An identity provider pushing a
//! postal address is populating a profile, not authorising a disclosure.
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
use axiam_core::models::user::{Address, CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{Pagination, UserRepository};
use chrono::{DateTime, Utc};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use surrealdb::Connection;
use uuid::Uuid;

use axiam_api_rest::authz::AuthzData;
use axiam_api_rest::extractors::client_info::{client_ip, user_agent};
use axiam_api_rest::state::AppState;

use crate::auth::{ScimPrincipal, require_scim_provision};
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

/// RFC 7643 §4.1.2 `phoneNumbers` entry (X7 G8 / W7).
///
/// `type` is accepted and **not stored**. AXIAM holds one telephone number,
/// because OIDC Core §5.1 defines one `phone_number` claim, and keeping a
/// `"work"`/`"mobile"` label for a value whose label nothing reads would be
/// storing personal data with no purpose — which is exactly what Art. 5(1)(c)
/// asks a controller not to do. Accepted rather than refused because every
/// identity provider sends it and refusing would fail the provisioning run.
#[derive(Debug, Deserialize)]
pub struct ScimPhoneInput {
    pub value: String,
    #[serde(default)]
    pub primary: Option<bool>,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

/// RFC 7643 §4.1.2 `addresses` entry (X7 G8 / W7).
///
/// The five components plus `formatted` map one-to-one onto OIDC Core §5.1.1,
/// which is why this mapping needed no translation table: SCIM's
/// `streetAddress`/`locality`/`region`/`postalCode`/`country` and the OIDC
/// members of the same names are the same fields, and RFC 7643 §4.1.2 says so.
#[derive(Debug, Deserialize)]
pub struct ScimAddressInput {
    #[serde(default)]
    pub formatted: Option<String>,
    #[serde(default, rename = "streetAddress")]
    pub street_address: Option<String>,
    #[serde(default)]
    pub locality: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default, rename = "postalCode")]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub primary: Option<bool>,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
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
    /// X7 G8 / W7. Absent and empty mean different things on `PUT`: absent is
    /// "the provisioning client does not manage this attribute", empty is
    /// "this user has none". Both are `Vec` here because RFC 7644 §3.5.1
    /// defines `PUT` as a replace of the whole resource, so an attribute the
    /// client omits *is* being set to nothing — and a provisioning run that
    /// stops sending a telephone number is a run that means to remove it.
    #[serde(default, rename = "phoneNumbers")]
    pub phone_numbers: Vec<ScimPhoneInput>,
    #[serde(default)]
    pub addresses: Vec<ScimAddressInput>,
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

/// The one telephone number AXIAM keeps: the entry marked primary, else the
/// first. The same rule [`primary_email`] uses, deliberately — a provisioning
/// client that learns how AXIAM picks an email should not have to learn a
/// second rule for a telephone number.
///
/// A blank `value` selects nothing rather than storing an empty string: an
/// empty telephone number is an absent one, and storing it would make
/// `phone_number_verified: false` appear for a claim with no value.
fn primary_phone(phones: &[ScimPhoneInput]) -> Option<String> {
    phones
        .iter()
        .find(|p| p.primary == Some(true))
        .or_else(|| phones.first())
        .map(|p| p.value.trim())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

/// The one address AXIAM keeps, chosen by the same rule, and dropped when
/// every member of it is blank.
fn primary_address(addresses: &[ScimAddressInput]) -> Option<Address> {
    let chosen = addresses
        .iter()
        .find(|a| a.primary == Some(true))
        .or_else(|| addresses.first())?;
    let trim = |v: &Option<String>| {
        v.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let address = Address {
        formatted: trim(&chosen.formatted),
        street_address: trim(&chosen.street_address),
        locality: trim(&chosen.locality),
        region: trim(&chosen.region),
        postal_code: trim(&chosen.postal_code),
        country: trim(&chosen.country),
    };
    (!address.is_empty()).then_some(address)
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

/// X7 G8 / W7. One entry, always primary, with no `type`: AXIAM holds one
/// number and does not know what kind it is. Emitting a made-up `"work"` would
/// be answering a question nobody asked it.
#[derive(Serialize)]
pub struct ScimPhone {
    value: String,
    primary: bool,
}

/// X7 G8 / W7. The `Debug` impls on both of these redact, for the reason
/// `axiam_core::models::user::User`'s does — SCIM handlers log requests and
/// responses at debug level in more deployments than not.
impl std::fmt::Debug for ScimPhone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimPhone")
            .field("value", &"<redacted>")
            .field("primary", &self.primary)
            .finish()
    }
}

#[derive(Serialize)]
pub struct ScimAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    formatted: Option<String>,
    #[serde(rename = "streetAddress", skip_serializing_if = "Option::is_none")]
    street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(rename = "postalCode", skip_serializing_if = "Option::is_none")]
    postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    primary: bool,
}

impl std::fmt::Debug for ScimAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimAddress")
            .field("primary", &self.primary)
            .finish_non_exhaustive()
    }
}

impl From<&Address> for ScimAddress {
    fn from(a: &Address) -> Self {
        Self {
            formatted: a.formatted.clone(),
            street_address: a.street_address.clone(),
            locality: a.locality.clone(),
            region: a.region.clone(),
            postal_code: a.postal_code.clone(),
            country: a.country.clone(),
            primary: true,
        }
    }
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
    /// X7 G8 / W7. Omitted rather than emitted empty, per RFC 7643 §3.1:
    /// "attributes that have no value SHOULD be omitted".
    #[serde(rename = "phoneNumbers", skip_serializing_if = "Vec::is_empty")]
    phone_numbers: Vec<ScimPhone>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<ScimAddress>,
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
            phone_numbers: user
                .phone_number
                .iter()
                .map(|value| ScimPhone {
                    value: value.clone(),
                    primary: true,
                })
                .collect(),
            addresses: user.address.iter().map(ScimAddress::from).collect(),
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
    user: ScimPrincipal,
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
                .get_by_username(user.tenant_id(), &filter.value)
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
                    user.tenant_id(),
                    Pagination {
                        offset: 0,
                        limit: EXTERNAL_ID_SCAN_CAP,
                        search: None,
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
    user: &ScimPrincipal,
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
                user.tenant_id(),
                Pagination {
                    offset: 0,
                    limit: 1,
                    search: None,
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
        .list(
            user.tenant_id(),
            Pagination {
                offset,
                limit,
                search: None,
            },
        )
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
    user: ScimPrincipal,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let target = state
        .user_repo
        .get_by_id(user.tenant_id(), path.into_inner())
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
    user: ScimPrincipal,
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
        tenant_id: user.tenant_id(),
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
            user.tenant_id(),
            created.id,
            UpdateUser {
                status: Some(final_status),
                // W7 — written on the same follow-up update the status already
                // needed, so provisioning a user with a telephone number costs
                // no extra round trip. `Some(None)` when the client sent none,
                // because a create is a statement about the whole resource.
                phone_number: Some(primary_phone(&req.phone_numbers)),
                address: Some(primary_address(&req.addresses)),
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
    user: ScimPrincipal,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<ScimUserWrite>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let id = path.into_inner();
    let current = state.user_repo.get_by_id(user.tenant_id(), id).await?;
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
            user.tenant_id(),
            id,
            UpdateUser {
                username: Some(req.user_name.clone()),
                email: Some(email),
                status: Some(status.clone()),
                metadata: Some(metadata),
                // W7 — `PUT` replaces the resource (RFC 7644 §3.5.1), so an
                // omitted `phoneNumbers` clears the stored number rather than
                // leaving it. That is the behaviour a provisioning client
                // relies on to *remove* an attribute, and it is also what
                // makes an identity provider the source of truth rather than
                // one of two.
                phone_number: Some(primary_phone(&req.phone_numbers)),
                address: Some(primary_address(&req.addresses)),
                ..Default::default()
            },
        )
        .await?;

    // D7 parity with handlers::users::update: a PUT can narrow access via
    // `status`, so flush this subject's cached authz decisions.
    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id(), id)
        .await?;

    // SEC-098: a PUT carrying `active: false` is the RFC 7644 §3.5.1 spelling
    // of a deactivation and must revoke on the same terms as the PATCH one.
    if status == UserStatus::Inactive {
        revoke_live_credentials(&state, user.tenant_id(), id, "scim.deactivated").await;
    }

    state
        .emit_webhook(
            updated.tenant_id,
            "user.updated",
            json!({ "id": updated.id, "username": updated.username }),
        )
        .await;

    Ok(HttpResponse::Ok().json(ScimUser::from_user(&updated, &http_req)))
}

/// Revoke every live credential a user holds (SEC-098).
///
/// Both chokepoints, exactly as `AuthService::revoke_all_sessions` does them:
/// the session table (which backs the session-flow refresh token) *and* the
/// OAuth2 refresh-token table. They are two tables and a credential change
/// that hits only one leaves the other spendable.
///
/// # Why SCIM needs this and the native handlers were allowed not to
///
/// Flushing `invalidate_subject` — which every SCIM write already did — clears
/// the *authorization decision* cache. It does not touch a single credential:
/// the attacker's access token still validates until it expires, and their
/// refresh token still mints new ones. So a password rotated through SCIM to
/// lock out a compromised account, or an `active: false` written by an IdP's
/// offboarding job, left the session it was meant to kill alive.
///
/// SCIM is the path an IdP drives *deprovisioning* through. RFC 7644's
/// consumers — Okta, Entra — treat `active: false` and `DELETE` as "this
/// person is gone as of now", and the immediacy is the whole reason the
/// integration exists.
///
/// Best-effort by design: a revocation failure is logged at ERROR and does not
/// fail the SCIM write. The write itself is the durable half (the password is
/// changed, the account is deactivated, and the refresh path re-reads
/// `check_user_status`); refusing the whole operation because the session
/// table blipped would leave the IdP retrying a deprovisioning that has in
/// fact already been applied.
async fn revoke_live_credentials<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    user_id: Uuid,
    reason: &'static str,
) {
    use axiam_core::repository::{RefreshTokenRepository, SessionRepository};

    if let Err(e) = state
        .session_repo
        .invalidate_user_sessions(tenant_id, user_id)
        .await
    {
        tracing::error!(
            %tenant_id, %user_id, reason, error = %e,
            "SCIM: could not invalidate sessions after a credential-affecting write"
        );
    }
    match state
        .refresh_token_repo
        .revoke_all_for_user(tenant_id, user_id)
        .await
    {
        Ok(revoked) => tracing::info!(
            target: "axiam::audit",
            event = "scim.credentials_revoked",
            %tenant_id, %user_id, reason, oauth2_tokens_revoked = revoked,
            "SCIM write revoked every live session and OAuth2 refresh token for the user"
        ),
        Err(e) => tracing::error!(
            %tenant_id, %user_id, reason, error = %e,
            "SCIM: could not revoke OAuth2 refresh tokens after a credential-affecting write"
        ),
    }
}

/// Whether a parsed PATCH asks for no change at all.
///
/// # Every settable field has to appear here
///
/// This is the guard that decides whether `update` is called, so a field the
/// list forgets is a field a PATCH cannot write — and it fails in the worst
/// possible way, with `200 OK` and the unchanged resource echoed back. A caller
/// that sets only that attribute is told it succeeded.
///
/// `phone_number` and `address` (X7 G8 / W7) were added to `UpdateUser` and to
/// the PATCH parser and not to this list, so `PATCH /scim/v2/Users/{id}` with
/// `phoneNumbers` and `addresses` — nothing else — answered 200, wrote nothing,
/// and the OIDF `oidcc-scope-address` and `oidcc-scope-phone` modules then
/// reported UserInfo withholding claims for a user who did not in fact have
/// them. Four release gates were examined before the missing line was found,
/// because every one of them was working.
fn user_patch_is_noop(u: &UpdateUser) -> bool {
    // Destructured rather than field-tested, so that adding a field to
    // `UpdateUser` fails to compile here instead of silently becoming
    // unwritable. The `..` cases are the ones SCIM never sets.
    let UpdateUser {
        username,
        email,
        status,
        metadata,
        password_hash,
        phone_number,
        address,
        ..
    } = u;
    username.is_none()
        && email.is_none()
        && status.is_none()
        && metadata.is_none()
        && password_hash.is_none()
        && phone_number.is_none()
        && address.is_none()
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
    user: ScimPrincipal,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<PatchRequest>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let id = path.into_inner();
    let current = state.user_repo.get_by_id(user.tenant_id(), id).await?;
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
        // W7 — `None` when the PATCH said nothing about the attribute, which
        // is the whole difference between PATCH and PUT: a partial update
        // leaves an unmentioned telephone number alone, where a `PUT` that
        // omits it clears it.
        phone_number: delta.phone_number.clone(),
        address: delta.address.clone(),
        ..Default::default()
    };

    // SEC-098: read before `update` is moved. A password write and a
    // deactivation are the two PATCH shapes that must not leave a live
    // credential behind.
    let revocation_reason = match (
        update.password_hash.is_some(),
        update.status == Some(UserStatus::Inactive),
    ) {
        (true, _) => Some("scim.password_set"),
        (false, true) => Some("scim.deactivated"),
        (false, false) => None,
    };

    let updated = if user_patch_is_noop(&update) {
        current
    } else {
        let u = state.user_repo.update(user.tenant_id(), id, update).await?;
        authz
            .get_ref()
            .as_ref()
            .invalidate_subject(user.tenant_id(), id)
            .await?;
        if let Some(reason) = revocation_reason {
            revoke_live_credentials(&state, user.tenant_id(), id, reason).await;
        }
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
    user: ScimPrincipal,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ScimError> {
    require_scim_provision(&user, authz.get_ref().as_ref()).await?;
    let id = path.into_inner();
    state.user_repo.delete(user.tenant_id(), id).await?;

    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id(), id)
        .await?;

    // SEC-098: `DELETE /Users/{id}` is a soft delete to `Inactive`, so without
    // this the offboarded account keeps a live session and a spendable refresh
    // token. This is the endpoint an IdP calls when someone leaves.
    revoke_live_credentials(&state, user.tenant_id(), id, "scim.deleted").await;

    state
        .emit_webhook(user.tenant_id(), "user.deleted", json!({ "id": id }))
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

    fn phone(value: &str, primary: Option<bool>) -> ScimPhoneInput {
        ScimPhoneInput {
            value: value.into(),
            primary,
            kind: None,
        }
    }

    fn address_input(locality: Option<&str>, primary: Option<bool>) -> ScimAddressInput {
        ScimAddressInput {
            formatted: None,
            street_address: None,
            locality: locality.map(str::to_owned),
            region: None,
            postal_code: None,
            country: None,
            primary,
            kind: None,
        }
    }

    // -----------------------------------------------------------------
    // `primary_phone` / `primary_address`
    //
    // `primary_email` has three tests; its two siblings had none, though all
    // three pick an entry the same way and all three feed the same create and
    // replace paths.
    // -----------------------------------------------------------------

    #[test]
    fn primary_phone_prefers_the_flagged_entry_and_falls_back_to_the_first() {
        assert_eq!(
            primary_phone(&[phone("+15550001", None), phone("+15550002", Some(true))]),
            Some("+15550002".to_string())
        );
        assert_eq!(
            primary_phone(&[phone("+15550001", None), phone("+15550002", None)]),
            Some("+15550001".to_string())
        );
        assert_eq!(primary_phone(&[]), None);
    }

    #[test]
    fn a_blank_phone_number_is_no_phone_number() {
        // Storing it would leave the record looking populated while holding
        // nothing, and `phone_number_verified_at` would then hang off a value
        // nobody can verify.
        assert_eq!(primary_phone(&[phone("   ", Some(true))]), None);
        assert_eq!(primary_phone(&[phone("", None)]), None);
    }

    #[test]
    fn primary_address_prefers_the_flagged_entry_and_trims_its_members() {
        let chosen = primary_address(&[
            address_input(Some("First"), None),
            address_input(Some("  Primary  "), Some(true)),
        ])
        .expect("a populated entry is an address");
        assert_eq!(chosen.locality.as_deref(), Some("Primary"));
    }

    #[test]
    fn an_address_with_nothing_in_it_is_not_an_address() {
        assert_eq!(primary_address(&[]), None);
        assert_eq!(primary_address(&[address_input(Some("   "), None)]), None);
        assert_eq!(primary_address(&[address_input(None, Some(true))]), None);
    }

    // -----------------------------------------------------------------
    // `user_patch_is_noop`
    //
    // The guard that decides whether `update` is called at all. Its doc
    // records what a gap here costs: `phone_number` and `address` were added
    // to `UpdateUser` and to the PATCH parser but not to this list, so a PATCH
    // setting only those answered 200, wrote nothing, and sent two OIDF
    // conformance modules chasing a UserInfo bug that did not exist. Four
    // release gates were examined before the missing line was found.
    //
    // A list is exactly the kind of thing that goes stale silently, so every
    // field it tracks is asserted individually rather than in one lump.
    // -----------------------------------------------------------------

    #[test]
    fn an_empty_update_is_a_noop() {
        assert!(user_patch_is_noop(&UpdateUser::default()));
    }

    #[test]
    fn every_field_the_guard_tracks_makes_a_patch_non_trivial() {
        let cases: Vec<(&str, UpdateUser)> = vec![
            (
                "username",
                UpdateUser {
                    username: Some("alice".into()),
                    ..Default::default()
                },
            ),
            (
                "email",
                UpdateUser {
                    email: Some("alice@example.com".into()),
                    ..Default::default()
                },
            ),
            (
                "status",
                UpdateUser {
                    status: Some(axiam_core::models::user::UserStatus::Inactive),
                    ..Default::default()
                },
            ),
            (
                "metadata",
                UpdateUser {
                    metadata: Some(serde_json::json!({"scim": {}})),
                    ..Default::default()
                },
            ),
            (
                "password_hash",
                UpdateUser {
                    password_hash: Some("hash".into()),
                    ..Default::default()
                },
            ),
            (
                "phone_number",
                UpdateUser {
                    phone_number: Some(Some("+15550001".into())),
                    ..Default::default()
                },
            ),
            (
                "address",
                UpdateUser {
                    address: Some(Some(Address {
                        formatted: None,
                        street_address: None,
                        locality: Some("Townsville".into()),
                        region: None,
                        postal_code: None,
                        country: None,
                    })),
                    ..Default::default()
                },
            ),
        ];

        for (field, update) in cases {
            assert!(
                !user_patch_is_noop(&update),
                "a PATCH setting only {field} must reach `update`; treating it as a \
                 no-op answers 200 and writes nothing"
            );
        }
    }

    #[test]
    fn erasing_a_field_is_not_a_noop_either() {
        // `Some(None)` is "write NULL" — the erasure a data subject asked for.
        // Reading it as "nothing to do" would answer 200 and keep the data.
        assert!(!user_patch_is_noop(&UpdateUser {
            phone_number: Some(None),
            ..Default::default()
        }));
        assert!(!user_patch_is_noop(&UpdateUser {
            address: Some(None),
            ..Default::default()
        }));
    }

    // -----------------------------------------------------------------
    // `apply_user_delta_metadata`
    // -----------------------------------------------------------------

    #[test]
    fn a_delta_touching_no_scim_name_field_leaves_metadata_alone() {
        // `None` means "do not write metadata at all", which is what keeps an
        // `active`-only PATCH from rewriting the SCIM blob it never mentioned.
        let delta = UserPatchDelta {
            active: Some(false),
            ..Default::default()
        };
        assert!(apply_user_delta_metadata(&serde_json::json!({}), &delta).is_none());
    }

    #[test]
    fn each_scim_name_field_lands_in_the_metadata_blob() {
        let delta = UserPatchDelta {
            external_id: Some(Some("ext-1".into())),
            given_name: Some(Some("Ada".into())),
            family_name: Some(Some("Lovelace".into())),
            formatted: Some(Some("Ada Lovelace".into())),
            ..Default::default()
        };

        let metadata = apply_user_delta_metadata(&serde_json::json!({}), &delta)
            .expect("a delta naming SCIM name fields must write metadata");

        assert_eq!(
            scim_metadata::get_str(&metadata, "externalId").as_deref(),
            Some("ext-1")
        );
        assert_eq!(
            scim_metadata::get_str(&metadata, "givenName").as_deref(),
            Some("Ada")
        );
        assert_eq!(
            scim_metadata::get_str(&metadata, "familyName").as_deref(),
            Some("Lovelace")
        );
        assert_eq!(
            scim_metadata::get_str(&metadata, "formatted").as_deref(),
            Some("Ada Lovelace")
        );
    }
}
