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
//!
//! # What the lookup costs (review QR2-8 / SR2-4)
//!
//! The resolver runs for every request the middleware writes to the system
//! partition — every token-less request among them, a cheap `401` included —
//! and outside every scope-level rate limiter. A path naming an organization or
//! tenant would therefore cost one datastore point read per request, and a
//! client looping an invented id could turn each `401` into one.
//! [`SystemAuditOrgCache`] bounds that: an id that resolved is remembered for
//! [`RESOLVED_TTL`], an id the datastore says does not exist for the shorter
//! [`UNRESOLVED_TTL`], so a repeated id costs one read per TTL, not per
//! request. A datastore failure is not remembered. What it cannot bound is a
//! client sending a *different* invented id every time: each still costs one
//! indexed record-id read, limited only by the deployment's edge and
//! unauthenticated rate limits. Do not add a lookup here that is dearer than
//! that.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{HttpMessage, HttpRequest, web};
use axiam_audit::{AuditAttribution, AuditOrganization};
use axiam_auth::token::CachedUserIdentity;
use axiam_core::error::AxiamError;
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
    let scope = path_scope(req.path())?;
    if let Some(remembered) = state.system_audit_org_cache.get(scope) {
        return remembered;
    }
    let looked_up = match scope {
        PathScope::Organization(org_id) => state.org_repo.get_by_id(org_id).await.map(|o| o.id),
        PathScope::Tenant(tenant_id) => match state.tenant_org_cache.get(tenant_id) {
            Some(org_id) => Ok(org_id),
            None => state.tenant_repo.get_by_id(tenant_id).await.map(|t| {
                state.tenant_org_cache.insert(tenant_id, t.organization_id);
                t.organization_id
            }),
        },
    };
    match looked_up {
        Ok(org_id) => {
            state.system_audit_org_cache.insert(scope, Some(org_id));
            Some(org_id)
        }
        // The datastore answered that the id names nothing: remembered, briefly.
        Err(AxiamError::NotFound { .. }) => {
            state.system_audit_org_cache.insert(scope, None);
            None
        }
        // A datastore failure: unresolved for this row, and not remembered.
        Err(_) => None,
    }
}

/// What a request path names, read from the path itself.
///
/// Not from the router's match: a request refused before its resource is
/// matched — the scope's authorization middleware answers `401` to a missing
/// token first — has no path parameters, and it is exactly the request this
/// module is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// How long an organization or tenant the path names, once found, is served
/// from [`SystemAuditOrgCache`] before it is read again.
///
/// A tenant's organization never changes; an organization deleted within this
/// window keeps being recorded on the rows aimed at its routes, which only
/// that (deleted) organization could ever read.
pub const RESOLVED_TTL: Duration = Duration::from_secs(60);

/// How long a path id that named **no** organization or tenant is remembered
/// as unresolved (QR2-8 / SR2-4).
///
/// Short on purpose: the cost of a stale miss is that a row aimed at an
/// organization or tenant created within this window records no organization
/// — written, but returned to nobody — and that should stay a matter of
/// seconds.
pub const UNRESOLVED_TTL: Duration = Duration::from_secs(10);

/// Upper bound on each of the two maps (resolved, unresolved).
///
/// Separate maps, so invented ids — which only ever land in the unresolved
/// one — cannot crowd real organizations out of the resolved one. At the cap a
/// map stops accepting new entries until an expiry sweep frees room, which
/// degrades to the uncached behaviour (one read per request) rather than to
/// unbounded growth or to dropping an organization the datastore does know.
///
/// The sweep is a full scan under the map's lock, so a full map is swept at
/// most once per half of its TTL (review QR3-4): a client looping invented ids
/// fast enough to keep the map full of live entries would otherwise trigger a
/// scan that frees nothing on every insert. Between sweeps an insert into a
/// full map is simply dropped; an entry that expired meanwhile is still removed
/// by the lookup that finds it.
const MAX_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, Copy)]
struct Entry {
    organization_id: Option<Uuid>,
    inserted_at: Instant,
}

/// One of the two bounded maps.
#[derive(Debug, Default)]
struct Bucket {
    entries: HashMap<PathScope, Entry>,
    /// When `entries` was last swept for expired entries (QR3-4).
    last_sweep: Option<Instant>,
    /// Expiry sweeps run over `entries`; tests read it to bound the work.
    #[cfg(test)]
    sweeps: usize,
}

/// What a path id resolved to, remembered for [`RESOLVED_TTL`] when it named
/// something and for [`UNRESOLVED_TTL`] when the datastore said it does not
/// exist. A datastore failure is never remembered.
#[derive(Debug)]
pub struct SystemAuditOrgCache {
    resolved_ttl: Duration,
    unresolved_ttl: Duration,
    resolved: Mutex<Bucket>,
    unresolved: Mutex<Bucket>,
}

impl Default for SystemAuditOrgCache {
    fn default() -> Self {
        Self::new(RESOLVED_TTL, UNRESOLVED_TTL)
    }
}

impl SystemAuditOrgCache {
    /// Build a cache with explicit TTLs (tests pin short ones).
    pub fn new(resolved_ttl: Duration, unresolved_ttl: Duration) -> Self {
        Self {
            resolved_ttl,
            unresolved_ttl,
            resolved: Mutex::new(Bucket::default()),
            unresolved: Mutex::new(Bucket::default()),
        }
    }

    /// `Some(answer)` when `scope` is remembered and not expired — `answer`
    /// itself is `None` for a remembered miss — or `None` when it must be read.
    fn get(&self, scope: PathScope) -> Option<Option<Uuid>> {
        for (map, ttl) in [
            (&self.resolved, self.resolved_ttl),
            (&self.unresolved, self.unresolved_ttl),
        ] {
            let mut guard = lock(map);
            if let Some(entry) = guard.entries.get(&scope).copied() {
                if entry.inserted_at.elapsed() < ttl {
                    return Some(entry.organization_id);
                }
                guard.entries.remove(&scope);
            }
        }
        None
    }

    fn insert(&self, scope: PathScope, organization_id: Option<Uuid>) {
        let (map, ttl) = if organization_id.is_some() {
            (&self.resolved, self.resolved_ttl)
        } else {
            (&self.unresolved, self.unresolved_ttl)
        };
        let mut guard = lock(map);
        if guard.entries.len() >= MAX_ENTRIES && !guard.entries.contains_key(&scope) {
            let sweep_due = guard.last_sweep.is_none_or(|at| at.elapsed() >= ttl / 2);
            if !sweep_due {
                return;
            }
            guard.entries.retain(|_, e| e.inserted_at.elapsed() < ttl);
            guard.last_sweep = Some(Instant::now());
            #[cfg(test)]
            {
                guard.sweeps += 1;
            }
            if guard.entries.len() >= MAX_ENTRIES {
                return;
            }
        }
        guard.entries.insert(
            scope,
            Entry {
                organization_id,
                inserted_at: Instant::now(),
            },
        );
    }
}

/// A poisoned lock means another thread panicked holding a map of ids; there
/// is no invariant to protect, and recovering beats panicking on every request.
fn lock(map: &Mutex<Bucket>) -> MutexGuard<'_, Bucket> {
    map.lock().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_auth::config::AuthConfig;
    use axiam_core::models::organization::CreateOrganization;
    use surrealdb::Surreal;
    use surrealdb::engine::local::{Db, Mem};

    async fn state() -> (Surreal<Db>, web::Data<AppState<Db>>) {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let state = web::Data::new(AppState::for_test(db.clone(), AuthConfig::default()));
        (db, state)
    }

    /// What the resolver records for a token-less request to `path`.
    async fn resolved(state: &web::Data<AppState<Db>>, path: &str) -> Option<Uuid> {
        let req = actix_web::test::TestRequest::get()
            .uri(path)
            .app_data(state.clone())
            .to_http_request();
        resolve::<Db>(&req).await
    }

    /// QR2-8 / SR2-4: a path naming an organization that does not exist is
    /// remembered as unresolved for a short time, so repeating it — an
    /// unauthenticated client looping one invented id — costs no further
    /// datastore read. Observed through the datastore: once the id has been
    /// looked up and missed, a row created under it afterwards is not read
    /// within the negative TTL.
    #[actix_rt::test]
    async fn a_repeated_unknown_organization_is_not_read_again() {
        let (db, state) = state().await;
        let org_id = Uuid::new_v4();
        let path = format!("/api/v1/organizations/{org_id}/tenants");
        assert_eq!(resolved(&state, &path).await, None);

        db.query("CREATE type::record('organization', $id) SET name = 'late', slug = 'late'")
            .bind(("id", org_id.to_string()))
            .await
            .unwrap()
            .check()
            .unwrap();

        assert_eq!(
            resolved(&state, &path).await,
            None,
            "the second lookup of an unknown organization read the datastore \
             instead of the negative cache"
        );
    }

    /// QR2-8: an organization that exists is remembered too, so traffic to its
    /// routes without a token pays the organization read once per TTL, not
    /// once per request. Observed the same way: deleted behind the cache, it
    /// is still served from memory.
    #[actix_rt::test]
    async fn a_known_organization_is_served_from_memory() {
        let (db, state) = state().await;
        let org = state
            .org_repo
            .create(CreateOrganization {
                name: "known".into(),
                slug: "known".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let path = format!("/api/v1/organizations/{}/settings", org.id);
        assert_eq!(resolved(&state, &path).await, Some(org.id));

        db.query("DELETE type::record('organization', $id)")
            .bind(("id", org.id.to_string()))
            .await
            .unwrap()
            .check()
            .unwrap();

        assert_eq!(
            resolved(&state, &path).await,
            Some(org.id),
            "the second lookup of a known organization read the datastore \
             instead of the cache"
        );
    }

    /// Fill the unresolved map to the cap with distinct invented ids.
    fn fill_unresolved(cache: &SystemAuditOrgCache) {
        for _ in 0..MAX_ENTRIES {
            cache.insert(PathScope::Organization(Uuid::new_v4()), None);
        }
        assert_eq!(lock(&cache.unresolved).entries.len(), MAX_ENTRIES);
    }

    /// QR3-4: with the map full of live entries, a stream of new invented ids
    /// must not sweep the whole map under the global lock on every insert. A
    /// sweep that freed nothing is not repeated until half the TTL has passed,
    /// and the cap still holds.
    #[test]
    fn a_full_map_of_live_entries_is_not_swept_on_every_insert() {
        let cache = SystemAuditOrgCache::new(Duration::from_secs(600), Duration::from_secs(600));
        fill_unresolved(&cache);

        for _ in 0..1_000 {
            cache.insert(PathScope::Organization(Uuid::new_v4()), None);
        }

        let guard = lock(&cache.unresolved);
        assert!(
            guard.sweeps <= 1,
            "1000 inserts into a full map of live entries ran {} full sweeps",
            guard.sweeps
        );
        assert_eq!(guard.entries.len(), MAX_ENTRIES, "the cap no longer holds");
    }

    /// QR3-4, the other half: once half the TTL has passed, a full map is
    /// swept again, so expired entries still make room for new ones.
    #[test]
    fn a_full_map_is_swept_again_once_half_the_ttl_has_passed() {
        let ttl = Duration::from_millis(200);
        let cache = SystemAuditOrgCache::new(ttl, ttl);
        fill_unresolved(&cache);
        // A sweep while every entry is live frees nothing; the id is dropped.
        let early = PathScope::Organization(Uuid::new_v4());
        cache.insert(early, None);
        assert_eq!(cache.get(early), None);

        std::thread::sleep(ttl + Duration::from_millis(20));
        let late = PathScope::Organization(Uuid::new_v4());
        cache.insert(late, None);

        assert_eq!(
            cache.get(late),
            Some(None),
            "an insert after the entries expired found no room"
        );
        let guard = lock(&cache.unresolved);
        assert_eq!(guard.sweeps, 2);
        assert_eq!(guard.entries.len(), 1);
    }

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
