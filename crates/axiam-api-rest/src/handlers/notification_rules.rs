//! Notification rule management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::notification_rule::{
    CreateNotificationRule, NotificationEventType, NotificationRule, UpdateNotificationRule,
};
use axiam_core::repository::{NotificationRuleRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::state::AppState;

// -------------------------------------------------------------------
// Request / response DTOs
// -------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateNotificationRuleRequest {
    /// Human-readable name for the rule.
    pub name: String,
    /// Description of what this rule monitors.
    pub description: String,
    /// Event types that trigger this rule.
    pub events: Vec<NotificationEventType>,
    /// Email addresses to notify.
    pub recipient_emails: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateNotificationRuleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub events: Option<Vec<NotificationEventType>>,
    pub recipient_emails: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

/// Notification rule response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NotificationRuleResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub events: Vec<NotificationEventType>,
    pub recipient_emails: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<NotificationRule> for NotificationRuleResponse {
    fn from(r: NotificationRule) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            name: r.name,
            description: r.description,
            events: r.events,
            recipient_emails: r.recipient_emails,
            enabled: r.enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

// -------------------------------------------------------------------
// Handlers
// -------------------------------------------------------------------

/// `POST /api/v1/notification-rules`
#[utoipa::path(
    post,
    path = "/api/v1/notification-rules",
    tag = "notification_rules",
    request_body = CreateNotificationRuleRequest,
    responses(
        (status = 201, description = "Notification rule created",
         body = NotificationRuleResponse),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateNotificationRuleRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("notification_rules:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();

    validate_name(&req.name)?;
    validate_events(&req.events)?;
    validate_recipient_emails(&req.recipient_emails)?;

    let rule = state
        .notification_rule_repo
        .create(CreateNotificationRule {
            tenant_id: user.tenant_id,
            name: req.name,
            description: req.description,
            events: req.events,
            recipient_emails: req.recipient_emails,
        })
        .await?;
    Ok(HttpResponse::Created().json(NotificationRuleResponse::from(rule)))
}

/// `GET /api/v1/notification-rules`
#[utoipa::path(
    get,
    path = "/api/v1/notification-rules",
    tag = "notification_rules",
    params(Pagination),
    responses(
        (status = 200, description = "List of notification rules",
         body = inline(PaginatedResult<NotificationRuleResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("notification_rules:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = state
        .notification_rule_repo
        .list(user.tenant_id, pagination.into_inner())
        .await?;
    let response = PaginatedResult {
        items: result
            .items
            .into_iter()
            .map(NotificationRuleResponse::from)
            .collect(),
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    };
    Ok(HttpResponse::Ok().json(response))
}

/// `GET /api/v1/notification-rules/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/notification-rules/{id}",
    tag = "notification_rules",
    params(("id" = Uuid, Path, description = "Rule ID")),
    responses(
        (status = 200, description = "Notification rule found",
         body = NotificationRuleResponse),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("notification_rules:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let rule = state
        .notification_rule_repo
        .get_by_id(user.tenant_id, id)
        .await?;
    Ok(HttpResponse::Ok().json(NotificationRuleResponse::from(rule)))
}

/// `PUT /api/v1/notification-rules/{id}`
#[utoipa::path(
    put,
    path = "/api/v1/notification-rules/{id}",
    tag = "notification_rules",
    params(("id" = Uuid, Path, description = "Rule ID")),
    request_body = UpdateNotificationRuleRequest,
    responses(
        (status = 200, description = "Notification rule updated",
         body = NotificationRuleResponse),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
    body: web::Json<UpdateNotificationRuleRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("notification_rules:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let req = body.into_inner();

    if let Some(ref name) = req.name {
        validate_name(name)?;
    }
    if let Some(ref events) = req.events {
        validate_events(events)?;
    }
    if let Some(ref emails) = req.recipient_emails {
        validate_recipient_emails(emails)?;
    }

    let rule = state
        .notification_rule_repo
        .update(
            user.tenant_id,
            id,
            UpdateNotificationRule {
                name: req.name,
                description: req.description,
                events: req.events,
                recipient_emails: req.recipient_emails,
                enabled: req.enabled,
            },
        )
        .await?;
    Ok(HttpResponse::Ok().json(NotificationRuleResponse::from(rule)))
}

/// `DELETE /api/v1/notification-rules/{id}`
#[utoipa::path(
    delete,
    path = "/api/v1/notification-rules/{id}",
    tag = "notification_rules",
    params(("id" = Uuid, Path, description = "Rule ID")),
    responses(
        (status = 204, description = "Notification rule deleted"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("notification_rules:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    state
        .notification_rule_repo
        .delete(user.tenant_id, id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

// -------------------------------------------------------------------
// Validation helpers
// -------------------------------------------------------------------

fn validation_err(msg: impl Into<String>) -> AxiamApiError {
    axiam_core::error::AxiamError::Validation {
        message: msg.into(),
    }
    .into()
}

fn validate_name(name: &str) -> Result<(), AxiamApiError> {
    if name.trim().is_empty() {
        return Err(validation_err("name must not be empty"));
    }
    Ok(())
}

fn validate_events(events: &[NotificationEventType]) -> Result<(), AxiamApiError> {
    if events.is_empty() {
        return Err(validation_err("events must not be empty"));
    }
    Ok(())
}

fn validate_recipient_emails(emails: &[String]) -> Result<(), AxiamApiError> {
    if emails.is_empty() {
        return Err(validation_err("recipient_emails must not be empty"));
    }
    if emails.len() > 20 {
        return Err(validation_err(
            "recipient_emails must have at most 20 entries",
        ));
    }
    for email in emails {
        if !email.contains('@') {
            return Err(validation_err(format!("invalid email address: {email}")));
        }
    }
    Ok(())
}
