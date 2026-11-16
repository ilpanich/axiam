//! The organization a **system-partition** request row concerns (SA-02, N1).
//!
//! The request audit middleware (`axiam_audit::AuditMiddleware`) writes a row
//! with a nil tenant for every request it cannot attribute to a tenant: no
//! verifiable access token, no handler-proven [`axiam_audit::AuditAttribution`].
//! That partition is deployment-wide, and `GET /api/v1/audit-logs/system`
//! returns an organization only the rows whose recorded organization is its
//! own. This module is where a request row's organization is decided.
//!
//! [`system_audit_organization`] runs inside the audit middleware (the
//! composition root wraps it there). After the request has been served, and
//! only for a request the middleware will record in the system partition, it
//! resolves the organization from something the server has verified, never
//! from a value the client merely sent:
//!
//! 1. a [`VerifiedAuditTenant`] an extractor inserted after verifying a
//!    credential that names the tenant — a SCIM provisioning token — gives that
//!    tenant's organization;
//! 2. otherwise a path `/api/v1/organizations/{org_id}/…` naming an
//!    organization that exists gives that organization;
//! 3. otherwise a path `/saml/v2/{tenant_id}/…` or `/t/{tenant_id}/…` naming a
//!    live tenant gives its organization.
//!
//! Anything else records no organization, and the row is then returned by the
//! system endpoint to nobody: a request that names no organization in its path
//! (`/oauth2/token?tenant_id=…`, `/api/v1/users` without a token), or one that
//! names an organization or tenant that does not exist. A datastore failure
//! during the lookup counts as unresolved: the row is still written, without
//! an organization. A path segment says which organization a request was
//! addressed to, not who sent it; that is exactly what the row records (the
//! traffic aimed at that organization's routes), and it can only ever be shown
//! to that organization.

use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{HttpMessage, HttpRequest, web};
use axiam_audit::{AuditAttribution, AuditOrganization};
use axiam_auth::token::CachedUserIdentity;
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use surrealdb::Connection;
use uuid::Uuid;

use crate::state::AppState;

/// A tenant an extractor has **verified** a request concerns, for a request
/// that carries no access token: the SCIM provisioning token's tenant, once
/// the token resolved.
///
/// Inserted into the request's extensions; read by [`system_audit_organization`]
/// to record the tenant's organization on the system-partition row. It does
/// not move the row into the tenant's own log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAuditTenant(pub Uuid);

/// Record, for a request the audit middleware writes to the system partition,
/// the organization it concerns, when that can be resolved with certainty (see
/// the module documentation). Wrapped inside the audit middleware with
/// `actix_web::middleware::from_fn(system_audit_organization::<C, _>)`.
pub async fn system_audit_organization<C, B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, actix_web::Error>
where
    C: Connection + Clone + 'static,
    B: MessageBody + 'static,
{
    let res = next.call(req).await?;
    if let Some(org_id) = resolve::<C>(res.request()).await {
        res.request()
            .extensions_mut()
            .insert(AuditOrganization { org_id });
    }
    Ok(res)
}

/// The organization of a request the audit middleware records with a nil
/// tenant, or `None` — for a request it attributes to a tenant, too.
async fn resolve<C: Connection + Clone + 'static>(req: &HttpRequest) -> Option<Uuid> {
    let verified = {
        let ext = req.extensions();
        // A verified token, or a handler's attribution, puts the row in a
        // tenant's log: nothing to resolve. An organization already named by
        // a handler stands.
        if ext.contains::<Arc<CachedUserIdentity>>()
            || ext.contains::<AuditAttribution>()
            || ext.contains::<AuditOrganization>()
        {
            return None;
        }
        ext.get::<VerifiedAuditTenant>().copied()
    };
    let state = req.app_data::<web::Data<AppState<C>>>()?;
    if let Some(VerifiedAuditTenant(tenant_id)) = verified {
        return organization_of_tenant(state, tenant_id).await;
    }
    match path_scope(req.path())? {
        PathScope::Organization(org_id) => {
            state.org_repo.get_by_id(org_id).await.ok().map(|o| o.id)
        }
        PathScope::Tenant(tenant_id) => organization_of_tenant(state, tenant_id).await,
    }
}

/// What a request path names, read from the path itself.
///
/// Not from the router's match: a request refused before its resource is
/// matched — the scope's authorization middleware answers `401` to a missing
/// token first — has no path parameters, and it is exactly the request this
/// module is for.
#[derive(Debug, PartialEq, Eq)]
enum PathScope {
    Organization(Uuid),
    Tenant(Uuid),
}

fn path_scope(path: &str) -> Option<PathScope> {
    let mut segments = path.split('/').skip(1);
    let uuid = |s: Option<&str>| s.and_then(|s| Uuid::parse_str(s).ok());
    match (segments.next()?, segments.next()) {
        ("api", Some("v1")) if segments.next() == Some("organizations") => {
            uuid(segments.next()).map(PathScope::Organization)
        }
        ("saml", Some("v2")) => uuid(segments.next()).map(PathScope::Tenant),
        ("t", tenant) => uuid(tenant).map(PathScope::Tenant),
        _ => None,
    }
}

/// The organization of a live tenant: the server's own record of it, served
/// from [`crate::tenant_org_cache`] when warm.
async fn organization_of_tenant<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
) -> Option<Uuid> {
    if let Some(org_id) = state.tenant_org_cache.get(tenant_id) {
        return Some(org_id);
    }
    let tenant = state.tenant_repo.get_by_id(tenant_id).await.ok()?;
    state
        .tenant_org_cache
        .insert(tenant_id, tenant.organization_id);
    Some(tenant.organization_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_names_an_organization_or_a_tenant_only_where_its_routes_do() {
        let id = Uuid::new_v4();
        assert_eq!(
            path_scope(&format!("/api/v1/organizations/{id}/tenants")),
            Some(PathScope::Organization(id))
        );
        assert_eq!(
            path_scope(&format!("/api/v1/organizations/{id}")),
            Some(PathScope::Organization(id))
        );
        assert_eq!(
            path_scope(&format!("/saml/v2/{id}/acs")),
            Some(PathScope::Tenant(id))
        );
        assert_eq!(
            path_scope(&format!("/t/{id}/oauth2/token")),
            Some(PathScope::Tenant(id))
        );
        for path in [
            "/api/v1/organizations".to_string(),
            "/api/v1/organizations/not-a-uuid/tenants".to_string(),
            format!("/api/v1/users/{id}"),
            format!("/oauth2/token?tenant_id={id}"),
            format!("/scim/v2/Users/{id}"),
            format!("/api/v2/organizations/{id}"),
            "/".to_string(),
            String::new(),
        ] {
            assert_eq!(path_scope(&path), None, "{path}");
        }
    }
}
