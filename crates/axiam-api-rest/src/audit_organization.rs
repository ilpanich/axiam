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
//! starts the lookup of the organization **on a task of its own** and lets the
//! response go (review SR4-3): the audit worker waits for the answer, through
//! an [`axiam_audit::PendingAuditOrganization`], before it writes the row. No
//! response waits on the datastore, so a response's latency says nothing about
//! whether the id its path names exists, whatever the cache below holds. The
//! organization is resolved from something the server has verified, never
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
//! indexed record-id read, limited by the deployment's edge and
//! unauthenticated rate limits and, in how many run at once, by the bound
//! below. Do not add a lookup here that is dearer than that.
//!
//! # How many lookups run at once (review SR15-1)
//!
//! Since SR4-3 nothing makes the client wait for its lookup, so the cache alone
//! would leave a client sending a fresh invented id per request free to pile
//! up detached reads, each outliving the audit worker's wait for it. The
//! datastore reads are therefore bounded process-wide: a lookup that misses
//! the caches takes one of [`MAX_CONCURRENT_LOOKUPS`] permits of a semaphore
//! held beside the cache (`try_acquire_owned`, which never waits) immediately
//! before its read, and keeps it until the read has finished. A lookup the
//! caches answer — this module's own, or [`crate::tenant_org_cache`] — reads
//! nothing and takes no permit (review QR16-2), so a known organization's rows
//! keep recording it however many invented ids hold the permits. A lookup that
//! must read while every permit is taken reads nothing and answers no
//! organization: its row is written without one — returned by the system
//! endpoint to nobody, the same fail-safe answer as an id that names nothing.
//! Either way its response was served exactly as any other.
//!
//! The cache is an optimisation of the lookup's cost, not of any response's
//! latency (review SR4-3): the lookup, cached or not, runs on its own task
//! after the response has gone, so the two TTLs differing — a known id served
//! from memory where an unknown one is read again — cannot be timed by the
//! client. The response path does the same work for every id: it reads the
//! path and spawns the task. Whether a permit is free is decided inside the
//! task, after the caches, so it cannot change the response either.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{HttpMessage, HttpRequest, web};
use axiam_audit::{AuditAttribution, AuditOrganization, PendingAuditOrganization};
use axiam_auth::token::CachedUserIdentity;
use axiam_core::error::AxiamError;
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use surrealdb::Connection;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
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
    // SR4-3: what to look up is read here, synchronously; the lookup itself
    // runs on a task of its own, and the response leaves without it.
    // QR16-2: the response path does the same for every id — it inserts the
    // pending answer and spawns — whether or not the task will need a
    // datastore read. The SR15-1 permit is taken inside the task, only for
    // that read (see `bounded_read`).
    if let Some(lookup) = Lookup::<C>::of(res.request()) {
        let (answer, pending) = PendingAuditOrganization::channel();
        res.request().extensions_mut().insert(pending);
        actix_web::rt::spawn(async move {
            let organization = lookup.run().await;
            // The worker may have stopped waiting; the answer is then unread.
            let _ = answer.send(organization);
        });
    }
    Ok(res)
}

/// What a system-partition request row's organization is to be resolved
/// from, read off the served request; resolved by [`Lookup::run`], off the
/// response path.
struct Lookup<C: Connection + Clone + 'static> {
    state: web::Data<AppState<C>>,
    target: Target,
}

enum Target {
    /// A tenant an extractor verified: its organization.
    VerifiedTenant(Uuid),
    /// What the path names.
    Path(PathScope),
}

impl<C: Connection + Clone + 'static> Lookup<C> {
    /// `None` for a request the audit middleware attributes to a tenant, one
    /// whose organization a handler already named, and one that names nothing
    /// to resolve.
    fn of(req: &HttpRequest) -> Option<Self> {
        let verified = {
            let ext = req.extensions();
            // A verified token, or a handler's attribution, puts the row in a
            // tenant's log: nothing to resolve. An organization already named
            // by a handler stands.
            if ext.contains::<Arc<CachedUserIdentity>>()
                || ext.contains::<AuditAttribution>()
                || ext.contains::<AuditOrganization>()
            {
                return None;
            }
            ext.get::<VerifiedAuditTenant>().copied()
        };
        let target = match verified {
            Some(VerifiedAuditTenant(tenant_id)) => Target::VerifiedTenant(tenant_id),
            None => Target::Path(path_scope(req.path())?),
        };
        let state = req.app_data::<web::Data<AppState<C>>>()?.clone();
        Some(Self { state, target })
    }

    /// The organization, or `None` when it cannot be resolved with certainty.
    async fn run(self) -> Option<Uuid> {
        let state = self.state.get_ref();
        match self.target {
            Target::VerifiedTenant(tenant_id) => organization_of_tenant(state, tenant_id).await,
            Target::Path(scope) => organization_of_path(state, scope).await,
        }
    }
}

/// What the resolver records for a served request, looked up inline: the
/// tests' view of [`Lookup`].
#[cfg(test)]
async fn resolve<C: Connection + Clone + 'static>(req: &HttpRequest) -> Option<Uuid> {
    Lookup::<C>::of(req)?.run().await
}

/// The organization an organization or tenant id in the path names, served
/// from [`SystemAuditOrgCache`] when remembered.
async fn organization_of_path<C: Connection + Clone>(
    state: &AppState<C>,
    scope: PathScope,
) -> Option<Uuid> {
    let cache = &state.system_audit_org_cache;
    if let Some(remembered) = cache.get(scope) {
        return remembered;
    }
    let tenant_cached = match scope {
        PathScope::Tenant(tenant_id) => state.tenant_org_cache.get(tenant_id),
        PathScope::Organization(_) => None,
    };
    let looked_up = match (scope, tenant_cached) {
        // Answered from memory: no read, no permit (QR16-2).
        (PathScope::Tenant(_), Some(org_id)) => Ok(org_id),
        (PathScope::Organization(org_id), _) => {
            // No permit free: unresolved for this row, and not remembered.
            bounded_read(cache, state.org_repo.get_by_id(org_id))
                .await?
                .map(|o| o.id)
        }
        (PathScope::Tenant(tenant_id), None) => {
            bounded_read(cache, state.tenant_repo.get_by_id(tenant_id))
                .await?
                .map(|t| {
                    state.tenant_org_cache.insert(tenant_id, t.organization_id);
                    t.organization_id
                })
        }
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
    let tenant = bounded_read(
        &state.system_audit_org_cache,
        state.tenant_repo.get_by_id(tenant_id),
    )
    .await?
    .ok()?;
    state
        .tenant_org_cache
        .insert(tenant_id, tenant.organization_id);
    Some(tenant.organization_id)
}

/// Run one datastore `read` of the lookup under a [`MAX_CONCURRENT_LOOKUPS`]
/// permit (review SR15-1), taken only now — after the caches missed, so a
/// lookup answered from memory never takes one (review QR16-2) — and held
/// until the read has finished, answered or not. `None` when every permit is
/// taken: the read does not start, and the caller records no organization.
/// Taking the permit never waits.
async fn bounded_read<F: std::future::Future>(
    cache: &SystemAuditOrgCache,
    read: F,
) -> Option<F::Output> {
    let permit = cache.try_lookup_permit()?;
    #[cfg(test)]
    tests::lookup_gate().await;
    let answer = read.await;
    drop(permit);
    Some(answer)
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

/// How many organization lookups may be in flight at once, process-wide
/// (review SR15-1).
///
/// Each lookup is a detached task, and since SR4-3 nothing makes the client
/// wait for it; a client sending a fresh invented id per request would
/// otherwise pile datastore reads up with nothing but the edge rate limit to
/// stop it. A permit is held only for the read itself (review QR16-2): a lookup
/// answered from a cache takes none, and one that must read while every permit
/// is taken reads nothing, and its row records no organization.
pub const MAX_CONCURRENT_LOOKUPS: usize = 128;

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
    /// The permits a lookup holds while its datastore read runs
    /// ([`MAX_CONCURRENT_LOOKUPS`]).
    lookups: Arc<Semaphore>,
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
            lookups: Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
        }
    }

    /// A permit for one lookup's datastore read, or `None` when
    /// [`MAX_CONCURRENT_LOOKUPS`] are already in flight. Never waits.
    fn try_lookup_permit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.lookups).try_acquire_owned().ok()
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

    thread_local! {
        /// SR4-3: a gate every organization lookup's datastore read on this
        /// thread waits on (under its permit), so a test can hold the read
        /// open and see whether the response waits for it.
        static LOOKUP_GATE: std::cell::RefCell<Option<Arc<tokio::sync::Semaphore>>> =
            const { std::cell::RefCell::new(None) };
    }

    thread_local! {
        /// SR15-1 / QR16-2: how many lookup datastore reads have started on
        /// this thread (a lookup answered from a cache starts none).
        static LOOKUPS_STARTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Wait at the gate, when a test on this thread installed one.
    pub(super) async fn lookup_gate() {
        LOOKUPS_STARTED.with(|n| n.set(n.get() + 1));
        let gate = LOOKUP_GATE.with(|g| g.borrow().clone());
        if let Some(gate) = gate {
            let _permit = gate.acquire().await.expect("the test gate is never closed");
        }
    }

    /// SR4-3: the organization of a system-partition row is resolved off the
    /// response path. A token-less request to an organization's routes whose
    /// organization is not cached gets its response while the lookup is held
    /// open; once the lookup is released, the row is written and records the
    /// organization.
    #[actix_rt::test]
    async fn the_response_does_not_wait_for_the_organization_lookup() {
        use actix_web::{App, HttpResponse, test as atest};
        use axiam_audit::AuditMiddleware;
        use axiam_core::repository::{AuditLogFilter, AuditLogRepository, Pagination};
        use axiam_db::SurrealAuditLogRepository;

        let (db, state) = state().await;
        let org = state
            .org_repo
            .create(CreateOrganization {
                name: "uncached".into(),
                slug: "uncached".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let audit = SurrealAuditLogRepository::new(db.clone());
        let app = atest::init_service(
            App::new()
                .app_data(state.clone())
                .wrap(actix_web::middleware::from_fn(
                    system_audit_organization::<Db, _>,
                ))
                .wrap(AuditMiddleware::spawn(audit.clone()))
                .default_service(web::to(|| async { HttpResponse::Unauthorized().finish() })),
        )
        .await;

        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        LOOKUP_GATE.with(|g| *g.borrow_mut() = Some(Arc::clone(&gate)));
        let req = atest::TestRequest::get()
            .uri(&format!("/api/v1/organizations/{}/settings", org.id))
            .to_request();
        let served =
            tokio::time::timeout(Duration::from_secs(2), atest::call_service(&app, req)).await;
        assert!(
            served.is_ok(),
            "the response waited on the organization lookup (SR4-3)"
        );
        assert_eq!(served.unwrap().status(), 401);

        gate.add_permits(1);
        LOOKUP_GATE.with(|g| *g.borrow_mut() = None);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let page = audit
                .list_system(org.id, AuditLogFilter::default(), Pagination::default())
                .await
                .unwrap();
            if let Some(row) = page.items.first() {
                assert_eq!(row.organization_id, Some(org.id));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the row never recorded the organization once the lookup was released"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The audit middleware wrapping the resolver around a handler that
    /// answers `401`, as the scope's authorization middleware does to a
    /// token-less request.
    macro_rules! system_audit_app {
        ($state:expr, $audit:expr) => {
            actix_web::test::init_service(
                actix_web::App::new()
                    .app_data($state.clone())
                    .wrap(actix_web::middleware::from_fn(
                        system_audit_organization::<Db, _>,
                    ))
                    .wrap(axiam_audit::AuditMiddleware::spawn($audit.clone()))
                    .default_service(web::to(|| async {
                        actix_web::HttpResponse::Unauthorized().finish()
                    })),
            )
            .await
        };
    }

    /// The system-partition rows written so far, waiting until there are
    /// `count` of them.
    async fn system_rows(
        audit: &axiam_db::SurrealAuditLogRepository<Db>,
        count: usize,
    ) -> Vec<axiam_core::models::audit::AuditLogEntry> {
        use axiam_core::repository::{AuditLogFilter, AuditLogRepository, Pagination};
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let page = audit
                .list(
                    Uuid::nil(),
                    AuditLogFilter::default(),
                    Pagination::default(),
                )
                .await
                .unwrap();
            if page.items.len() >= count {
                return page.items;
            }
            assert!(
                Instant::now() < deadline,
                "only {} of {count} system-partition rows were written",
                page.items.len()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn organization(state: &web::Data<AppState<Db>>, slug: &str) -> Uuid {
        state
            .org_repo
            .create(CreateOrganization {
                name: slug.into(),
                slug: slug.into(),
                metadata: None,
            })
            .await
            .unwrap()
            .id
    }

    /// SR15-1: the detached lookups are bounded. With every one of the
    /// [`MAX_CONCURRENT_LOOKUPS`] permits taken, a token-less request naming an
    /// organization that exists but is not cached starts no lookup — no
    /// datastore read — and its row is still written, recording no
    /// organization (visible to nobody).
    ///
    /// QR16-2: the permit bounds datastore reads only. A request naming an
    /// organization already in the cache needs no read, so with every permit
    /// taken its row still records that organization.
    #[actix_rt::test]
    async fn with_every_lookup_permit_taken_no_lookup_starts_and_the_row_records_no_organization() {
        use axiam_db::SurrealAuditLogRepository;

        let (db, state) = state().await;
        let org_id = organization(&state, "busy").await;
        let cached_org_id = organization(&state, "cached").await;
        state
            .system_audit_org_cache
            .insert(PathScope::Organization(cached_org_id), Some(cached_org_id));
        let audit = SurrealAuditLogRepository::new(db.clone());
        let app = system_audit_app!(state, audit);

        let held: Vec<_> = (0..MAX_CONCURRENT_LOOKUPS)
            .map(|_| {
                state
                    .system_audit_org_cache
                    .try_lookup_permit()
                    .expect("a free permit")
            })
            .collect();
        assert!(state.system_audit_org_cache.try_lookup_permit().is_none());
        LOOKUPS_STARTED.with(|n| n.set(0));

        // QR16-2: the cached organization is recorded without a permit.
        let req = actix_web::test::TestRequest::get()
            .uri(&format!("/api/v1/organizations/{cached_org_id}/settings"))
            .to_request();
        let res = actix_web::test::call_service(&app, req).await;
        assert_eq!(res.status(), 401);
        let rows = system_rows(&audit, 1).await;
        let cached_row_id = rows[0].id;
        assert_eq!(
            rows[0].organization_id,
            Some(cached_org_id),
            "a cached organization's row recorded no organization with every \
             permit taken (QR16-2)"
        );

        let req = actix_web::test::TestRequest::get()
            .uri(&format!("/api/v1/organizations/{org_id}/settings"))
            .to_request();
        let res = actix_web::test::call_service(&app, req).await;
        assert_eq!(res.status(), 401);

        let rows = system_rows(&audit, 2).await;
        let row = rows
            .iter()
            .find(|r| r.id != cached_row_id)
            .expect("the uncached organization's row");
        assert_eq!(
            LOOKUPS_STARTED.with(|n| n.get()),
            0,
            "a datastore read started with every permit taken (SR15-1)"
        );
        assert_eq!(
            row.organization_id, None,
            "the row recorded an organization looked up with every permit taken (SR15-1)"
        );
        drop(held);
    }

    /// SR15-1, the control: with a permit free, the lookup runs and holds its
    /// permit until its read has finished; the row records the organization,
    /// and the permit is returned.
    #[actix_rt::test]
    async fn a_lookup_holds_its_permit_until_its_read_finishes() {
        use axiam_db::SurrealAuditLogRepository;

        let (db, state) = state().await;
        let org_id = organization(&state, "free").await;
        let audit = SurrealAuditLogRepository::new(db.clone());
        let app = system_audit_app!(state, audit);
        let permits = || state.system_audit_org_cache.lookups.available_permits();

        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        LOOKUP_GATE.with(|g| *g.borrow_mut() = Some(Arc::clone(&gate)));
        LOOKUPS_STARTED.with(|n| n.set(0));
        let req = actix_web::test::TestRequest::get()
            .uri(&format!("/api/v1/organizations/{org_id}/settings"))
            .to_request();
        let res = actix_web::test::call_service(&app, req).await;
        assert_eq!(res.status(), 401);
        // QR16-2: the permit is taken inside the spawned task, just before its
        // read, so wait for the task to reach the gated read.
        let deadline = Instant::now() + Duration::from_secs(5);
        while LOOKUPS_STARTED.with(|n| n.get()) == 0 {
            assert!(Instant::now() < deadline, "the lookup's read never started");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            permits(),
            MAX_CONCURRENT_LOOKUPS - 1,
            "the lookup in flight holds no permit"
        );

        gate.add_permits(1);
        LOOKUP_GATE.with(|g| *g.borrow_mut() = None);
        let rows = system_rows(&audit, 1).await;
        assert_eq!(rows[0].organization_id, Some(org_id));
        let deadline = Instant::now() + Duration::from_secs(5);
        while permits() != MAX_CONCURRENT_LOOKUPS {
            assert!(
                Instant::now() < deadline,
                "the finished lookup kept its permit"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
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
