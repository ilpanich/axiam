//! The LDAP client: a bounded per-tenant connection pool and the
//! bind-as-user flow.
//!
//! # The flow ([`DirectoryClient::authenticate`])
//!
//! 1. **Refuse before I/O** an empty password (an RFC 4513 unauthenticated
//!    bind, which many servers report as success), an empty or overlong login
//!    name, and a stored template without exactly one placeholder.
//! 2. **Service bind.** Take a connection bound as the tenant's `bind_dn` from
//!    the pool, or open one and bind it with the decrypted secret.
//! 3. **Search** `base_dn` (subtree, aliases never dereferenced) with the
//!    tenant's user filter, the login name RFC 4515-escaped into its single
//!    placeholder ([`crate::escape::user_filter_for`]), asking for the mapped
//!    attributes only and a server-side size limit of
//!    [`USER_SEARCH_SIZE_LIMIT`]. Search result references are skipped — never
//!    chased and never counted — and the client stops reading after the second
//!    entry whatever the server's own limit says.
//! 4. **Exactly one entry**, or the generic failure: zero and two are the same
//!    answer to the caller.
//! 5. **User bind** as that entry's DN — the DN the directory returned; AXIAM
//!    never constructs one — with the presented password, on a **fresh**
//!    connection that is unbound and dropped afterwards. A connection bound as
//!    a user is never returned to the pool, so a later search can never run with
//!    the previous user's rights.
//! 6. Return the entry's external identifier and mapped attributes.
//!
//! [`DirectoryClient::lookup`] (T23.3.3, linking an existing account) is steps
//! 1–4 and 6 only: the same escaping, exactly-one rule, bounds and service
//! connection, with no user bind because there is no password to bind with.
//!
//! # Bounds
//!
//! Every connection is opened under a per-tenant permit
//! ([`ClientLimits::max_connections_per_tenant`]) and a process-wide one
//! ([`ClientLimits::max_connections_total`]), acquired within
//! [`ClientLimits::acquire_timeout`]; an exhausted pool is a fast
//! [`DirectoryAuthError::Unavailable`], not a queue. Connecting (TCP, StartTLS
//! and the TLS handshake together) is bounded by
//! [`ClientLimits::connect_timeout`], every operation by
//! [`ClientLimits::operation_timeout`], and the whole authentication by
//! [`ClientLimits::authentication_deadline`]. Idle pooled connections are
//! capped at [`ClientLimits::max_idle_per_tenant`] and discarded after
//! [`ClientLimits::idle_timeout`] or [`ClientLimits::max_connection_age`]. A
//! slow or hostile directory therefore holds at most
//! `max_connections_per_tenant + max_idle_per_tenant` sockets for one tenant,
//! and no login waits on it longer than the deadline.
//!
//! # Errors and logging
//!
//! Directory results map onto [`DirectoryAuthError`], a closed set the login
//! path answers uniformly. The directory's diagnostic text is logged at
//! `debug` only (Active Directory carries its `data 52e` / `533` / `775`
//! sub-codes there, which is the one thing it is read for). The password is
//! never logged, never formatted and never part of an error.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axiam_core::models::directory::{
    DirectoryAccountRestriction, DirectoryAuthError, DirectoryIdentity, UserAttributeMap,
};
use ldap3::asn1::StructureTag;
use ldap3::{
    DerefAliases, Ldap, LdapConnAsync, LdapConnSettings, LdapError, LdapResult, Scope,
    SearchOptions,
};
use rustls::ClientConfig;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::escape::{UserFilterError, user_filter_for};

/// Server-side size limit on the user search. Two, not one: a limit of one
/// would make an ambiguous filter look like a unique match on servers that
/// return the first entry and then `sizeLimitExceeded`.
pub const USER_SEARCH_SIZE_LIMIT: i32 = 2;

/// Default for [`ClientLimits::max_connections_per_tenant`].
pub const MAX_CONNECTIONS_PER_TENANT: usize = 8;
/// Default for [`ClientLimits::max_idle_per_tenant`].
pub const MAX_IDLE_PER_TENANT: usize = 4;
/// Default for [`ClientLimits::max_connections_total`].
pub const MAX_CONNECTIONS_TOTAL: usize = 256;
/// Default for [`ClientLimits::acquire_timeout`].
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);
/// Default for [`ClientLimits::connect_timeout`].
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default for [`ClientLimits::operation_timeout`].
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
/// Default for [`ClientLimits::authentication_deadline`].
pub const AUTHENTICATION_DEADLINE: Duration = Duration::from_secs(15);
/// Default for [`ClientLimits::idle_timeout`].
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Default for [`ClientLimits::max_connection_age`].
pub const MAX_CONNECTION_AGE: Duration = Duration::from_secs(300);

/// Longest external identifier accepted from a directory, in bytes.
const EXTERNAL_ID_MAX_LEN: usize = 256;
/// Longest mapped attribute value carried back, in bytes; longer values are
/// dropped rather than truncated (a truncated e-mail address is a different
/// address).
const ATTRIBUTE_VALUE_MAX_LEN: usize = 1024;

/// The bounds of the client. [`Default`] is the documented constants above;
/// tests shrink them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientLimits {
    /// Connections one tenant may have **in use** at once (service and user
    /// binds together).
    pub max_connections_per_tenant: usize,
    /// Idle service-bound connections kept per tenant.
    pub max_idle_per_tenant: usize,
    /// Connections in use across every tenant.
    pub max_connections_total: usize,
    /// How long to wait for a connection permit before answering
    /// `Unavailable`.
    pub acquire_timeout: Duration,
    /// TCP connect, StartTLS and the TLS handshake, together.
    pub connect_timeout: Duration,
    /// Each LDAP operation (a bind; each reply of a search).
    pub operation_timeout: Duration,
    /// The whole authentication, end to end.
    pub authentication_deadline: Duration,
    /// An idle pooled connection older than this (since last use) is closed.
    pub idle_timeout: Duration,
    /// A pooled connection older than this (since opened) is closed.
    pub max_connection_age: Duration,
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self {
            max_connections_per_tenant: MAX_CONNECTIONS_PER_TENANT,
            max_idle_per_tenant: MAX_IDLE_PER_TENANT,
            max_connections_total: MAX_CONNECTIONS_TOTAL,
            acquire_timeout: ACQUIRE_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            operation_timeout: OPERATION_TIMEOUT,
            authentication_deadline: AUTHENTICATION_DEADLINE,
            idle_timeout: IDLE_TIMEOUT,
            max_connection_age: MAX_CONNECTION_AGE,
        }
    }
}

/// Everything the client needs about one tenant's directory for one
/// authentication, resolved from the stored configuration by the caller.
#[derive(Clone)]
pub struct DirectoryTarget {
    /// The tenant, which scopes the pool.
    pub tenant_id: Uuid,
    /// Changes whenever the stored configuration changes. Pooled connections
    /// from another generation are closed rather than reused, so a new URL,
    /// bind DN, secret or trust store takes effect on the next sign-in.
    pub generation: String,
    /// `ldaps://host[:port]`, or `ldap://host[:port]` with [`Self::start_tls`].
    pub url: String,
    /// Upgrade an `ldap://` connection with StartTLS before anything else.
    pub start_tls: bool,
    /// The service account the search runs as.
    pub bind_dn: String,
    /// Where users are searched for.
    pub base_dn: String,
    /// The user filter template, with exactly one `{username}`.
    pub user_filter: String,
    /// Which attributes to request and map.
    pub attributes: UserAttributeMap,
    /// The verified TLS client configuration ([`crate::tls::client_config`]).
    pub tls: Arc<ClientConfig>,
}

/// A connection bound as the service account, idle in the pool.
struct IdleConnection {
    ldap: Ldap,
    generation: String,
    opened: Instant,
    idle_since: Instant,
}

/// One tenant's slice of the pool.
struct TenantPool {
    permits: Arc<Semaphore>,
    idle: Mutex<Vec<IdleConnection>>,
}

/// A connection in use, holding the permits it was opened under.
struct Lease {
    ldap: Ldap,
    opened: Instant,
    reused: bool,
    _tenant: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

/// Why one step failed, before it is collapsed into a [`DirectoryAuthError`].
/// Carries only fixed text, for the operator's log line.
#[derive(Debug)]
struct Failure {
    error: DirectoryAuthError,
    reason: &'static str,
}

impl Failure {
    fn new(error: DirectoryAuthError, reason: &'static str) -> Self {
        Self { error, reason }
    }
}

/// The LDAP client: one per process, shared by every tenant.
pub struct DirectoryClient {
    limits: ClientLimits,
    global: Arc<Semaphore>,
    tenants: Mutex<HashMap<Uuid, Arc<TenantPool>>>,
}

impl Default for DirectoryClient {
    fn default() -> Self {
        Self::new(ClientLimits::default())
    }
}

impl DirectoryClient {
    /// A client with the given bounds.
    #[must_use]
    pub fn new(limits: ClientLimits) -> Self {
        Self {
            global: Arc::new(Semaphore::new(limits.max_connections_total)),
            limits,
            tenants: Mutex::new(HashMap::new()),
        }
    }

    /// The bounds this client enforces.
    #[must_use]
    pub fn limits(&self) -> ClientLimits {
        self.limits
    }

    /// How many idle connections the pool holds for `tenant_id` right now.
    #[must_use]
    pub fn idle_connections(&self, tenant_id: Uuid) -> usize {
        self.pool_for(tenant_id)
            .idle
            .lock()
            .map(|idle| idle.len())
            .unwrap_or(0)
    }

    /// Authenticate `login_name` / `password` against `target`, binding the
    /// service account with `bind_secret` to search. See the module
    /// documentation for the flow and its bounds.
    ///
    /// # Errors
    ///
    /// A [`DirectoryAuthError`]; see that type for what each variant means.
    pub async fn authenticate(
        &self,
        target: &DirectoryTarget,
        bind_secret: &str,
        login_name: &str,
        password: &str,
    ) -> Result<DirectoryIdentity, DirectoryAuthError> {
        // Step 1: everything refusable without a packet is refused here.
        if password.is_empty() {
            return Err(DirectoryAuthError::InvalidCredentials);
        }
        self.run(target, bind_secret, login_name, Some(password))
            .await
    }

    /// Resolve the entry `login_name` names, exactly as
    /// [`Self::authenticate`] does, but **without binding as it** (T23.3.3:
    /// an administrator linking an existing account holds no directory
    /// password). Steps 1–4 only: the same escaping, the same exactly-one rule,
    /// the same referral and deadline handling, the same service-account
    /// connection; no user bind is attempted and no password is involved.
    ///
    /// # Errors
    ///
    /// A [`DirectoryAuthError`]; a filter that matched no single entry is
    /// [`DirectoryAuthError::InvalidCredentials`], as for authentication.
    pub async fn lookup(
        &self,
        target: &DirectoryTarget,
        bind_secret: &str,
        login_name: &str,
    ) -> Result<DirectoryIdentity, DirectoryAuthError> {
        self.run(target, bind_secret, login_name, None).await
    }

    /// The shared body of [`Self::authenticate`] and [`Self::lookup`]:
    /// `password` is `Some` when the entry must also be bound as.
    async fn run(
        &self,
        target: &DirectoryTarget,
        bind_secret: &str,
        login_name: &str,
        password: Option<&str>,
    ) -> Result<DirectoryIdentity, DirectoryAuthError> {
        if bind_secret.is_empty() {
            // The service bind would be an unauthenticated bind too.
            return Err(self.log(
                target,
                Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the stored bind secret is empty",
                ),
            ));
        }
        let filter = match user_filter_for(&target.user_filter, login_name) {
            Ok(filter) => filter,
            Err(UserFilterError::UnusableLoginName) => {
                return Err(DirectoryAuthError::InvalidCredentials);
            }
            Err(UserFilterError::TemplateWithoutSinglePlaceholder) => {
                return Err(self.log(
                    target,
                    Failure::new(
                        DirectoryAuthError::Misconfigured,
                        "the stored user filter does not carry exactly one placeholder",
                    ),
                ));
            }
        };
        if !transport_is_encrypted(&target.url, target.start_tls) {
            return Err(self.log(
                target,
                Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the stored URL is not ldaps:// or ldap:// with StartTLS",
                ),
            ));
        }

        let flow = self.flow(target, bind_secret, &filter, password);
        match tokio::time::timeout(self.limits.authentication_deadline, flow).await {
            Ok(Ok(identity)) => Ok(identity),
            Ok(Err(failure)) => Err(self.log(target, failure)),
            Err(_) => Err(self.log(
                target,
                Failure::new(
                    DirectoryAuthError::Unavailable,
                    "the authentication deadline elapsed",
                ),
            )),
        }
    }

    async fn flow(
        &self,
        target: &DirectoryTarget,
        bind_secret: &str,
        filter: &str,
        password: Option<&str>,
    ) -> Result<DirectoryIdentity, Failure> {
        // Steps 2-4. A pooled connection that fails at the transport level is
        // retried once on a fresh one: a server that closed an idle socket is
        // ordinary, and must not cost the user a failed sign-in.
        let mut service = self.service_connection(target, bind_secret).await?;
        let entry = match self.find_user(&mut service, target, filter).await {
            Err(failure) if service.reused && failure.error == DirectoryAuthError::Unavailable => {
                self.discard(service).await;
                service = self.fresh_service_connection(target, bind_secret).await?;
                self.find_user(&mut service, target, filter).await
            }
            other => other,
        };
        match entry {
            Ok(Some(entry)) => {
                // The search completed and the connection is still bound as the
                // service account: it may go back.
                self.release(target, service).await;
                let identity = entry.into_identity(&target.attributes)?;
                // Step 5, on a connection of its own — only when there is a
                // password to check (a lookup has none).
                if let Some(password) = password {
                    self.bind_as_user(target, &identity.dn, password).await?;
                }
                Ok(identity)
            }
            Ok(None) => {
                self.release(target, service).await;
                Err(Failure::new(
                    DirectoryAuthError::InvalidCredentials,
                    "the user filter matched no entry",
                ))
            }
            // Any failure — including an ambiguous result read only partway —
            // closes the connection rather than pooling it.
            Err(failure) => {
                self.discard(service).await;
                Err(failure)
            }
        }
    }

    /// A service-bound connection: an idle pooled one of the current
    /// generation if there is one, otherwise a fresh one.
    async fn service_connection(
        &self,
        target: &DirectoryTarget,
        bind_secret: &str,
    ) -> Result<Lease, Failure> {
        let pool = self.pool_for(target.tenant_id);
        let (tenant, global) = self.permits(&pool).await?;
        let (idle, stale) = self.take_idle(&pool, target);
        // Stale sockets are closed while this caller holds a permit, so a
        // closing socket and its replacement are never both counted as free.
        for conn in stale {
            self.close(conn.ldap).await;
        }
        if let Some(idle) = idle {
            return Ok(Lease {
                ldap: idle.ldap,
                opened: idle.opened,
                reused: true,
                _tenant: tenant,
                _global: global,
            });
        }
        let ldap = self.connect(target).await?;
        let mut lease = Lease {
            ldap,
            opened: Instant::now(),
            reused: false,
            _tenant: tenant,
            _global: global,
        };
        if let Err(failure) = self
            .service_bind(&mut lease.ldap, target, bind_secret)
            .await
        {
            self.discard(lease).await;
            return Err(failure);
        }
        Ok(lease)
    }

    async fn fresh_service_connection(
        &self,
        target: &DirectoryTarget,
        bind_secret: &str,
    ) -> Result<Lease, Failure> {
        let pool = self.pool_for(target.tenant_id);
        let (tenant, global) = self.permits(&pool).await?;
        let ldap = self.connect(target).await?;
        let mut lease = Lease {
            ldap,
            opened: Instant::now(),
            reused: false,
            _tenant: tenant,
            _global: global,
        };
        if let Err(failure) = self
            .service_bind(&mut lease.ldap, target, bind_secret)
            .await
        {
            self.discard(lease).await;
            return Err(failure);
        }
        Ok(lease)
    }

    async fn service_bind(
        &self,
        ldap: &mut Ldap,
        target: &DirectoryTarget,
        bind_secret: &str,
    ) -> Result<(), Failure> {
        let result = ldap
            .with_timeout(self.limits.operation_timeout)
            .simple_bind(&target.bind_dn, bind_secret)
            .await
            .map_err(transport_failure)?;
        if result.rc == 0 {
            return Ok(());
        }
        debug_diagnostic("service bind", &result);
        Err(match result.rc {
            // busy, unavailable, timeLimitExceeded, other
            51 | 52 | 3 | 80 => Failure::new(
                DirectoryAuthError::Unavailable,
                "the directory is busy or unavailable",
            ),
            _ => Failure::new(
                DirectoryAuthError::Misconfigured,
                "the directory refused the service bind (check bind_dn and the bind secret)",
            ),
        })
    }

    /// Steps 3-4: the search, and the exactly-one rule. `Ok(None)` is a
    /// completed search that matched nothing (the connection is reusable);
    /// two matches are an error (it is not).
    async fn find_user(
        &self,
        lease: &mut Lease,
        target: &DirectoryTarget,
        filter: &str,
    ) -> Result<Option<RawEntry>, Failure> {
        let attrs = requested_attributes(&target.attributes);
        let options = SearchOptions::new()
            .sizelimit(USER_SEARCH_SIZE_LIMIT)
            .timelimit(i32::try_from(self.limits.operation_timeout.as_secs().max(1)).unwrap_or(5))
            .deref(DerefAliases::Never);
        let mut stream = lease
            .ldap
            .with_search_options(options)
            .with_timeout(self.limits.operation_timeout)
            .streaming_search(&target.base_dn, Scope::Subtree, filter, attrs)
            .await
            .map_err(transport_failure)?;

        let mut entries = Vec::with_capacity(2);
        loop {
            match stream.next().await.map_err(transport_failure)? {
                None => break,
                // A search result reference (RFC 4511 §4.5.3) or an
                // intermediate response: never followed, never a match.
                Some(entry) if entry.is_ref() || entry.is_intermediate() => continue,
                Some(entry) => {
                    let parsed = parse_entry(entry.0).ok_or_else(|| {
                        Failure::new(
                            DirectoryAuthError::Unavailable,
                            "the directory sent a malformed search entry",
                        )
                    })?;
                    entries.push(parsed);
                    if entries.len() > 1 {
                        // Ambiguous. Stop reading: the server's own limit is
                        // not trusted, and the connection is not pooled.
                        return Err(Failure::new(
                            DirectoryAuthError::InvalidCredentials,
                            "the user filter matched more than one entry",
                        ));
                    }
                }
            }
        }
        let done = stream.finish().await;
        match done.rc {
            0 => {}
            4 => {
                return Err(Failure::new(
                    DirectoryAuthError::InvalidCredentials,
                    "the user filter matched more than one entry",
                ));
            }
            10 => {
                debug_diagnostic("user search", &done);
                return Err(Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the directory answered the user search with a referral, which is never followed",
                ));
            }
            3 | 51 | 52 | 80 => {
                debug_diagnostic("user search", &done);
                return Err(Failure::new(
                    DirectoryAuthError::Unavailable,
                    "the directory is busy or unavailable",
                ));
            }
            _ => {
                debug_diagnostic("user search", &done);
                return Err(Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the directory refused the user search (check base_dn and the bind account's read rights)",
                ));
            }
        }
        Ok(entries.pop())
    }

    /// Step 5: bind as the user on a connection of its own, then discard it.
    async fn bind_as_user(
        &self,
        target: &DirectoryTarget,
        dn: &str,
        password: &str,
    ) -> Result<(), Failure> {
        let pool = self.pool_for(target.tenant_id);
        let (_tenant, _global) = self.permits(&pool).await?;
        let mut ldap = self.connect(target).await?;
        let outcome = ldap
            .with_timeout(self.limits.operation_timeout)
            .simple_bind(dn, password)
            .await;
        // Never pooled: unbind (best effort, bounded) and let it drop.
        let _ = tokio::time::timeout(self.limits.operation_timeout, ldap.unbind()).await;
        let result = outcome.map_err(transport_failure)?;
        user_bind_outcome(&result)
    }

    /// Open a connection. The only place a socket is opened, and it refuses
    /// any URL that would not be encrypted before the first bind.
    async fn connect(&self, target: &DirectoryTarget) -> Result<Ldap, Failure> {
        if !transport_is_encrypted(&target.url, target.start_tls) {
            return Err(Failure::new(
                DirectoryAuthError::Misconfigured,
                "the stored URL is not ldaps:// or ldap:// with StartTLS",
            ));
        }
        // `set_no_tls_verify` is never called: verification is the default and
        // stays on. `set_starttls` only has effect on `ldap://`; ldap3 refuses
        // to continue when the server rejects the StartTLS request, and the
        // first bind is sent only after `with_settings` returns, i.e. after the
        // handshake completed against `target.tls`.
        let settings = LdapConnSettings::new()
            .set_conn_timeout(self.limits.connect_timeout)
            .set_config(Arc::clone(&target.tls))
            .set_starttls(target.start_tls);
        let (conn, ldap) = LdapConnAsync::with_settings(settings, &target.url)
            .await
            .map_err(|error| {
                tracing::debug!(
                    target: "axiam::directory",
                    tenant_id = %target.tenant_id,
                    error = %error,
                    "directory connection failed"
                );
                match error {
                    LdapError::LdapResult { .. } => Failure::new(
                        DirectoryAuthError::Unavailable,
                        "the directory refused StartTLS; no bind was sent",
                    ),
                    LdapError::Rustls { .. } | LdapError::DNSName { .. } => Failure::new(
                        DirectoryAuthError::Unavailable,
                        "TLS verification of the directory failed (certificate not trusted, \
                         or not issued for the URL's host)",
                    ),
                    LdapError::Timeout { .. } => Failure::new(
                        DirectoryAuthError::Unavailable,
                        "connecting to the directory timed out",
                    ),
                    _ => Failure::new(
                        DirectoryAuthError::Unavailable,
                        "the directory could not be reached",
                    ),
                }
            })?;
        tokio::spawn(async move {
            if let Err(error) = conn.drive().await {
                tracing::debug!(target: "axiam::directory", error = %error, "directory connection closed");
            }
        });
        Ok(ldap)
    }

    async fn permits(
        &self,
        pool: &TenantPool,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), Failure> {
        let exhausted = || {
            Failure::new(
                DirectoryAuthError::Unavailable,
                "the directory connection pool is exhausted",
            )
        };
        let tenant = tokio::time::timeout(
            self.limits.acquire_timeout,
            Arc::clone(&pool.permits).acquire_owned(),
        )
        .await
        .map_err(|_| exhausted())?
        .map_err(|_| exhausted())?;
        let global = tokio::time::timeout(
            self.limits.acquire_timeout,
            Arc::clone(&self.global).acquire_owned(),
        )
        .await
        .map_err(|_| exhausted())?
        .map_err(|_| exhausted())?;
        Ok((tenant, global))
    }

    fn pool_for(&self, tenant_id: Uuid) -> Arc<TenantPool> {
        let mut tenants = self
            .tenants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(tenants.entry(tenant_id).or_insert_with(|| {
            Arc::new(TenantPool {
                permits: Arc::new(Semaphore::new(self.limits.max_connections_per_tenant)),
                idle: Mutex::new(Vec::new()),
            })
        }))
    }

    /// The freshest usable idle connection, and every stale one (another
    /// generation, idle or alive too long, or closed by the server), which the
    /// caller closes.
    fn take_idle(
        &self,
        pool: &TenantPool,
        target: &DirectoryTarget,
    ) -> (Option<IdleConnection>, Vec<IdleConnection>) {
        let mut idle = pool
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        let mut usable = Vec::new();
        let mut stale = Vec::new();
        for mut conn in idle.drain(..) {
            if conn.generation == target.generation
                && now.duration_since(conn.idle_since) < self.limits.idle_timeout
                && now.duration_since(conn.opened) < self.limits.max_connection_age
                && !conn.ldap.is_closed()
            {
                usable.push(conn);
            } else {
                stale.push(conn);
            }
        }
        let chosen = usable.pop();
        *idle = usable;
        (chosen, stale)
    }

    /// Return a service-bound connection to the pool, or close it when the
    /// pool is full or the connection too old. The lease's permits are held
    /// until the socket is closed, so the bound counts real sockets.
    async fn release(&self, target: &DirectoryTarget, mut lease: Lease) {
        let pool = self.pool_for(target.tenant_id);
        let leftover = {
            let mut idle = pool
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = Instant::now();
            if idle.len() < self.limits.max_idle_per_tenant
                && now.duration_since(lease.opened) < self.limits.max_connection_age
                && !lease.ldap.is_closed()
            {
                idle.push(IdleConnection {
                    ldap: lease.ldap.clone(),
                    generation: target.generation.clone(),
                    opened: lease.opened,
                    idle_since: now,
                });
                false
            } else {
                true
            }
        };
        if leftover {
            self.close(lease.ldap.clone()).await;
        }
        // The permits drop with `lease` here.
    }

    /// Close a lease's connection, then release its permits.
    async fn discard(&self, lease: Lease) {
        self.close(lease.ldap.clone()).await;
    }

    /// Unbind and close, bounded. `ldap3` shuts the socket down before
    /// `unbind` returns.
    async fn close(&self, mut ldap: Ldap) {
        let _ = tokio::time::timeout(self.limits.operation_timeout, ldap.unbind()).await;
    }

    /// Log a failure for the operator — fixed text and the tenant, nothing the
    /// user typed and nothing the directory said — and return its kind.
    fn log(&self, target: &DirectoryTarget, failure: Failure) -> DirectoryAuthError {
        match failure.error {
            DirectoryAuthError::InvalidCredentials | DirectoryAuthError::AccountRestricted(_) => {
                tracing::info!(
                    target: "axiam::directory",
                    tenant_id = %target.tenant_id,
                    outcome = ?failure.error,
                    reason = failure.reason,
                    "directory authentication refused"
                );
            }
            _ => {
                tracing::warn!(
                    target: "axiam::directory",
                    tenant_id = %target.tenant_id,
                    outcome = ?failure.error,
                    reason = failure.reason,
                    "directory authentication could not be performed"
                );
            }
        }
        failure.error
    }
}

/// The transport rule, restated at the point of use: `ldaps://` without
/// StartTLS, or `ldap://` with it. Anything else — including a row written
/// without passing `config::validate` — never reaches a socket.
#[must_use]
pub fn transport_is_encrypted(url: &str, start_tls: bool) -> bool {
    match url::Url::parse(url) {
        Ok(parsed) => match parsed.scheme() {
            "ldaps" => !start_tls,
            "ldap" => start_tls,
            _ => false,
        },
        Err(_) => false,
    }
}

fn transport_failure(error: LdapError) -> Failure {
    tracing::debug!(target: "axiam::directory", error = %error, "directory operation failed");
    match error {
        LdapError::Timeout { .. } => Failure::new(
            DirectoryAuthError::Unavailable,
            "a directory operation timed out",
        ),
        _ => Failure::new(
            DirectoryAuthError::Unavailable,
            "the directory connection failed",
        ),
    }
}

/// The diagnostic text is the directory's own words: `debug` only.
fn debug_diagnostic(operation: &'static str, result: &LdapResult) {
    tracing::debug!(
        target: "axiam::directory",
        operation,
        rc = result.rc,
        diagnostic = %result.text,
        "directory result"
    );
}

/// Map the user bind's result onto the closed error set.
fn user_bind_outcome(result: &LdapResult) -> Result<(), Failure> {
    match result.rc {
        0 => Ok(()),
        49 => {
            debug_diagnostic("user bind", result);
            match ad_sub_code(&result.text) {
                Some(restriction) => Err(Failure::new(
                    DirectoryAuthError::AccountRestricted(restriction),
                    "the directory refused the account",
                )),
                None => Err(Failure::new(
                    DirectoryAuthError::InvalidCredentials,
                    "the directory rejected the password",
                )),
            }
        }
        50 | 53 => {
            debug_diagnostic("user bind", result);
            Err(Failure::new(
                DirectoryAuthError::AccountRestricted(DirectoryAccountRestriction::Disabled),
                "the directory refused to authenticate the account",
            ))
        }
        10 => {
            debug_diagnostic("user bind", result);
            Err(Failure::new(
                DirectoryAuthError::Misconfigured,
                "the directory answered the user bind with a referral, which is never followed",
            ))
        }
        3 | 51 | 52 | 80 => {
            debug_diagnostic("user bind", result);
            Err(Failure::new(
                DirectoryAuthError::Unavailable,
                "the directory is busy or unavailable",
            ))
        }
        _ => {
            debug_diagnostic("user bind", result);
            Err(Failure::new(
                DirectoryAuthError::Misconfigured,
                "the directory returned an unexpected result to the user bind",
            ))
        }
    }
}

/// Read Active Directory's sub-code out of an `invalidCredentials`
/// diagnostic: `80090308: LdapErr: DSID-…, comment: AcceptSecurityContext
/// error, data 533, v…`. `52e` (bad password) and `525` (no such user) are
/// plain invalid credentials and yield `None`, as does any text that is not in
/// this shape (OpenLDAP, or an AD that said nothing).
#[must_use]
pub fn ad_sub_code(diagnostic: &str) -> Option<DirectoryAccountRestriction> {
    let rest = diagnostic.split("data ").nth(1)?;
    let code: String = rest
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_lowercase();
    match code.as_str() {
        "530" | "531" => Some(DirectoryAccountRestriction::NotPermittedNow),
        "532" => Some(DirectoryAccountRestriction::PasswordExpired),
        "533" => Some(DirectoryAccountRestriction::Disabled),
        "701" => Some(DirectoryAccountRestriction::Expired),
        "773" => Some(DirectoryAccountRestriction::PasswordMustChange),
        "775" => Some(DirectoryAccountRestriction::Locked),
        _ => None,
    }
}

fn requested_attributes(map: &UserAttributeMap) -> Vec<String> {
    let mut attrs: Vec<String> = Vec::with_capacity(4);
    for name in [
        &map.external_id,
        &map.username,
        &map.email,
        &map.display_name,
    ] {
        if !attrs.iter().any(|a| a.eq_ignore_ascii_case(name)) {
            attrs.push(name.clone());
        }
    }
    attrs
}

/// A search entry, parsed without panicking.
///
/// `ldap3::SearchEntry::construct` panics on malformed BER; a directory is an
/// external system, so its entries are parsed here with every step fallible.
struct RawEntry {
    dn: String,
    attrs: Vec<(String, Vec<Vec<u8>>)>,
}

fn parse_entry(tag: StructureTag) -> Option<RawEntry> {
    let mut parts = tag.match_id(4)?.expect_constructed()?.into_iter();
    let dn = String::from_utf8(parts.next()?.expect_primitive()?).ok()?;
    let mut attrs = Vec::new();
    for partial in parts.next()?.expect_constructed()? {
        let mut fields = partial.expect_constructed()?.into_iter();
        let name = String::from_utf8(fields.next()?.expect_primitive()?).ok()?;
        let values = fields
            .next()?
            .expect_constructed()?
            .into_iter()
            .map(StructureTag::expect_primitive)
            .collect::<Option<Vec<Vec<u8>>>>()?;
        attrs.push((name, values));
    }
    Some(RawEntry { dn, attrs })
}

impl RawEntry {
    fn values(&self, name: &str) -> Option<&Vec<Vec<u8>>> {
        self.attrs
            .iter()
            .find(|(attr, _)| attr.eq_ignore_ascii_case(name))
            .map(|(_, values)| values)
    }

    fn text(&self, name: &str) -> Option<String> {
        let value = self.values(name)?.first()?;
        if value.is_empty() || value.len() > ATTRIBUTE_VALUE_MAX_LEN {
            return None;
        }
        String::from_utf8(value.clone()).ok()
    }

    fn into_identity(self, map: &UserAttributeMap) -> Result<DirectoryIdentity, Failure> {
        if self.dn.is_empty() {
            return Err(Failure::new(
                DirectoryAuthError::Unavailable,
                "the directory returned an entry without a DN",
            ));
        }
        let external_id = self
            .values(&map.external_id)
            .and_then(|values| match values.as_slice() {
                [only] => decode_external_id(&map.external_id, only),
                _ => None,
            })
            .ok_or_else(|| {
                Failure::new(
                    DirectoryAuthError::Misconfigured,
                    "the matched entry carries no usable identifier attribute \
                     (check attr_external_id and the bind account's read rights)",
                )
            })?;
        Ok(DirectoryIdentity {
            external_id,
            username: self.text(&map.username),
            email: self.text(&map.email),
            display_name: self.text(&map.display_name),
            dn: self.dn,
        })
    }
}

/// Decode an entry identifier into its canonical text.
///
/// * `objectGUID` is 16 raw bytes in Microsoft's mixed-endian layout (the
///   first three fields little-endian); it is decoded with
///   [`Uuid::from_bytes_le`], so it reads the way AD tools display it.
/// * Any other attribute that holds a UUID (`entryUUID`) is normalised to
///   lowercase hyphenated form.
/// * Anything else is taken as non-empty UTF-8 text, at most 256 bytes.
#[must_use]
pub fn decode_external_id(attribute: &str, raw: &[u8]) -> Option<String> {
    if attribute.eq_ignore_ascii_case("objectGUID") {
        let bytes: [u8; 16] = raw.try_into().ok()?;
        return Some(Uuid::from_bytes_le(bytes).hyphenated().to_string());
    }
    let text = std::str::from_utf8(raw).ok()?.trim();
    if text.is_empty() || text.len() > EXTERNAL_ID_MAX_LEN {
        return None;
    }
    Some(match Uuid::parse_str(text) {
        Ok(uuid) => uuid.hyphenated().to_string(),
        Err(_) => text.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_encrypted_transport_shapes_pass() {
        assert!(transport_is_encrypted("ldaps://dc.example.com", false));
        assert!(transport_is_encrypted("ldaps://dc.example.com:636", false));
        assert!(transport_is_encrypted("ldap://dc.example.com:389", true));
        assert!(!transport_is_encrypted("ldap://dc.example.com", false));
        assert!(!transport_is_encrypted("ldaps://dc.example.com", true));
        assert!(!transport_is_encrypted("ldapi:///var/run/slapd", true));
        assert!(!transport_is_encrypted("https://dc.example.com", false));
        assert!(!transport_is_encrypted("not a url", true));
    }

    #[test]
    fn active_directory_sub_codes_map_to_restrictions() {
        let text = |code: &str| {
            format!(
                "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data {code}, v4563"
            )
        };
        assert_eq!(
            ad_sub_code(&text("533")),
            Some(DirectoryAccountRestriction::Disabled)
        );
        assert_eq!(
            ad_sub_code(&text("775")),
            Some(DirectoryAccountRestriction::Locked)
        );
        assert_eq!(
            ad_sub_code(&text("701")),
            Some(DirectoryAccountRestriction::Expired)
        );
        assert_eq!(
            ad_sub_code(&text("532")),
            Some(DirectoryAccountRestriction::PasswordExpired)
        );
        assert_eq!(
            ad_sub_code(&text("773")),
            Some(DirectoryAccountRestriction::PasswordMustChange)
        );
        assert_eq!(
            ad_sub_code(&text("530")),
            Some(DirectoryAccountRestriction::NotPermittedNow)
        );
        assert_eq!(ad_sub_code(&text("52e")), None);
        assert_eq!(ad_sub_code(&text("525")), None);
        assert_eq!(ad_sub_code("Invalid credentials"), None);
        assert_eq!(ad_sub_code(""), None);
    }

    #[test]
    fn the_user_bind_result_maps_onto_the_closed_set() {
        let result = |rc: u32, text: &str| LdapResult {
            rc,
            matched: String::new(),
            text: text.into(),
            refs: vec![],
            ctrls: vec![],
        };
        assert!(user_bind_outcome(&result(0, "")).is_ok());
        assert_eq!(
            user_bind_outcome(&result(49, "")).unwrap_err().error,
            DirectoryAuthError::InvalidCredentials
        );
        assert_eq!(
            user_bind_outcome(&result(49, "AcceptSecurityContext error, data 533, v1"))
                .unwrap_err()
                .error,
            DirectoryAuthError::AccountRestricted(DirectoryAccountRestriction::Disabled)
        );
        assert_eq!(
            user_bind_outcome(&result(53, "")).unwrap_err().error,
            DirectoryAuthError::AccountRestricted(DirectoryAccountRestriction::Disabled)
        );
        assert_eq!(
            user_bind_outcome(&result(10, "")).unwrap_err().error,
            DirectoryAuthError::Misconfigured
        );
        assert_eq!(
            user_bind_outcome(&result(52, "")).unwrap_err().error,
            DirectoryAuthError::Unavailable
        );
    }

    /// AD's `objectGUID` is mixed-endian on the wire. The fixture is the
    /// documented example: the bytes below display as
    /// `{6f9619ff-8b86-d011-b42d-00c04fc964ff}`.
    #[test]
    fn an_object_guid_decodes_the_way_active_directory_displays_it() {
        let raw = [
            0xff, 0x19, 0x96, 0x6f, 0x86, 0x8b, 0x11, 0xd0, 0xb4, 0x2d, 0x00, 0xc0, 0x4f, 0xc9,
            0x64, 0xff,
        ];
        assert_eq!(
            decode_external_id("objectGUID", &raw).as_deref(),
            Some("6f9619ff-8b86-d011-b42d-00c04fc964ff")
        );
        assert_eq!(decode_external_id("objectguid", &raw[..15]), None);
    }

    #[test]
    fn an_entry_uuid_is_normalised_and_other_identifiers_kept() {
        assert_eq!(
            decode_external_id("entryUUID", b"  6F9619FF-8B86-D011-B42D-00C04FC964FF ").as_deref(),
            Some("6f9619ff-8b86-d011-b42d-00c04fc964ff")
        );
        assert_eq!(
            decode_external_id("employeeNumber", b"E-1234").as_deref(),
            Some("E-1234")
        );
        assert_eq!(decode_external_id("entryUUID", b""), None);
        assert_eq!(decode_external_id("entryUUID", &[0xff, 0xfe]), None);
        assert_eq!(
            decode_external_id("entryUUID", "x".repeat(EXTERNAL_ID_MAX_LEN + 1).as_bytes()),
            None
        );
    }

    #[test]
    fn requested_attributes_are_the_map_deduplicated() {
        let map = UserAttributeMap {
            username: "uid".into(),
            email: "mail".into(),
            display_name: "UID".into(),
            external_id: "entryUUID".into(),
        };
        assert_eq!(requested_attributes(&map), vec!["entryUUID", "uid", "mail"]);
    }
}
