//! The Shared Signals Framework event emitter (G-5, T23.5.3, D-52).
//!
//! Neither source G-5 first named can be tailed — the revocation feed
//! publishes unlinkable hashes by design (T-39) and most audit actions are the
//! middleware's `{METHOD} {path}` — so **events are emitted where the change
//! happens**, through this one emitter:
//!
//! ```text
//!   the change site ──► SsfEmitter ──► SsfStreamRepository::list_for_event
//!                                  ──► prepare_event (one per stream)
//!                                  ──► SsfOutbox::submit (push: dispatcher, poll/paused: buffer)
//! ```
//!
//! # Best effort, like `emit_webhook`
//!
//! An emission is a side effect of some other operation — a logout, a password
//! change, a disabled account — and never fails it: every error is logged
//! (never with a subject, a SET or a credential) and swallowed. It is a no-op
//! when no outbox is wired (a harness, a deployment without AMQP) and when the
//! tenant's `ssf_enabled` is off, and it costs one indexed read — the streams
//! that would carry the event — when nothing is registered, before it reads a
//! user or a setting.
//!
//! # One `txn` per originating operation
//!
//! A password reset produces a `credential-change` and a `session-revoked`; they
//! share one `txn` (SSF §4.1.9) so a receiver can tell they are one cause. The
//! operation says so by running inside [`with_cause`]; the emitter reads the
//! cause from a task-local, so the code between the handler and the repository
//! that actually removes a session needs no extra parameter. An emission outside
//! any cause makes a `txn` of its own.
//!
//! # Two ports
//!
//! The emitter also implements the two core ports a layer that cannot reach
//! this crate reports through: [`SessionRevocationSink`] (the session
//! repository, D-52's only source of `session-revoked`) and
//! [`SsfSystemAccountSink`] (the directory sync's deactivation). Both are bound
//! to it through [`Late`] handles because the repositories that hold them are
//! built before the outbox exists.

use std::future::Future;
use std::sync::Arc;

use axiam_auth::config::AuthConfig;
use axiam_core::error::AxiamError;
use axiam_core::models::ssf::{
    Late, SessionRevocationSink, SsfEventType, SsfFuture, SsfOutbox, SsfOutboxError, SsfStream,
    SsfSystemAccountSink,
};
use axiam_core::models::user::User;
use axiam_core::repository::{
    SettingsRepository, SsfStreamRepository, TenantRepository, UserRepository,
};
use axiam_db::{
    SurrealSettingsRepository, SurrealSsfStreamRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_oauth2::ssf::{AssuranceLevel, SsfError, SsfEvent, SsfIssuerGate, prepare_event};
// Re-exported so the crates above this one (SCIM) name the event vocabulary
// through the emitter they call, without a dependency of their own on the
// protocol crate.
pub use axiam_oauth2::ssf::{ChangeType, CredentialType, InitiatingEntity, SsfSubject};
use chrono::Utc;
use surrealdb::Connection;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// The cause of an operation
// ---------------------------------------------------------------------------

/// What one originating operation tells every event it produces.
#[derive(Debug, Clone)]
pub struct SsfCause {
    /// The SET `txn`, shared by every SET this operation produces.
    pub txn: String,
    /// Who did it, for the events that name an initiator (the
    /// `session-revoked` the session repository reports on its own).
    pub initiating_entity: Option<InitiatingEntity>,
}

tokio::task_local! {
    static CAUSE: SsfCause;
}

/// Run `operation` as one cause: every event emitted inside it shares one `txn`
/// and, for a revocation the session repository reports, one initiator.
///
/// Wrap the whole operation — the service call that revokes sessions and the
/// emission of the credential change — not one of them.
pub async fn with_cause<F: Future>(
    initiating_entity: Option<InitiatingEntity>,
    operation: F,
) -> F::Output {
    CAUSE
        .scope(
            SsfCause {
                txn: Uuid::new_v4().to_string(),
                initiating_entity,
            },
            operation,
        )
        .await
}

/// The cause of the operation this code runs inside, if it runs inside one.
#[must_use]
pub fn current_cause() -> Option<SsfCause> {
    CAUSE.try_with(Clone::clone).ok()
}

// ---------------------------------------------------------------------------
// The emitter
// ---------------------------------------------------------------------------

/// What a credential change adds to its event.
#[derive(Debug, Clone, Default)]
pub struct CredentialDetail {
    /// A `fido2-*` credential's AAGUID.
    pub fido2_aaguid: Option<String>,
}

/// Emits CAEP and RISC events from the places a change happens.
///
/// Cheap to clone: the repositories are handles and the outbox is shared, so a
/// clone bound before the outbox exists sees it when it is bound.
#[derive(Clone)]
pub struct SsfEmitter<C: Connection + Clone> {
    stream_repo: SurrealSsfStreamRepository<C>,
    tenant_repo: SurrealTenantRepository<C>,
    settings_repo: SurrealSettingsRepository<C>,
    user_repo: SurrealUserRepository<C>,
    auth_config: AuthConfig,
    outbox: Arc<Late<dyn SsfOutbox>>,
    /// D-55: while the deployment's tenants would share one issuer nothing is
    /// produced, for any tenant.
    gate: Arc<SsfIssuerGate>,
}

impl<C: Connection + Clone> SsfEmitter<C> {
    /// An emitter with no outbox: it does nothing until [`Self::bind_outbox`].
    pub fn new(
        stream_repo: SurrealSsfStreamRepository<C>,
        tenant_repo: SurrealTenantRepository<C>,
        settings_repo: SurrealSettingsRepository<C>,
        user_repo: SurrealUserRepository<C>,
        auth_config: AuthConfig,
        gate: Arc<SsfIssuerGate>,
    ) -> Self {
        Self {
            stream_repo,
            tenant_repo,
            settings_repo,
            user_repo,
            auth_config,
            outbox: Arc::new(Late::default()),
            gate,
        }
    }

    /// Wire the outbox events go to. Bound once: a second call is `false` and
    /// changes nothing.
    pub fn bind_outbox(&self, outbox: Arc<dyn SsfOutbox>) -> bool {
        self.outbox.bind(outbox)
    }

    /// Whether an outbox is wired. Without one nothing is emitted.
    #[must_use]
    pub fn is_wired(&self) -> bool {
        self.outbox.get().is_some()
    }

    /// Whether the tenant exists and its effective `ssf_enabled` is on. Any
    /// failure reads as off: an emission that cannot tell must not guess on.
    async fn switched_on(&self, tenant_id: Uuid) -> bool {
        let tenant = match self.tenant_repo.get_by_id(tenant_id).await {
            Ok(tenant) => tenant,
            Err(AxiamError::NotFound { .. }) => return false,
            Err(error) => {
                tracing::warn!(target: "axiam::ssf", %tenant_id, %error, "SSF emission could not read the tenant");
                return false;
            }
        };
        let switch_on = match self
            .settings_repo
            .get_effective_settings(tenant.organization_id, tenant_id)
            .await
        {
            Ok(settings) => settings.oidc.ssf_enabled,
            Err(error) => {
                tracing::warn!(target: "axiam::ssf", %tenant_id, %error, "SSF emission could not read the settings");
                false
            }
        };
        if !switch_on {
            return false;
        }
        // D-55: the deployment's tenants would share one issuer — nothing is
        // produced, as with the switch off. A count that cannot be read is off.
        match self.gate.check().await {
            Ok(issuer) => !issuer.holds(),
            Err(error) => {
                tracing::warn!(target: "axiam::ssf", %tenant_id, %error, "SSF emission could not count the deployment's tenants");
                false
            }
        }
    }

    /// The streams that would carry `event_type` now: none when no outbox is
    /// wired, when nothing is registered for it, or when the tenant's switch is
    /// off. One indexed read in the common case.
    async fn streams_for(&self, tenant_id: Uuid, event_type: SsfEventType) -> Vec<SsfStream> {
        if !self.is_wired() {
            return Vec::new();
        }
        let streams = match self.stream_repo.list_for_event(tenant_id, event_type).await {
            Ok(streams) => streams,
            Err(error) => {
                tracing::warn!(target: "axiam::ssf", %tenant_id, %error, "SSF streams could not be listed");
                return Vec::new();
            }
        };
        if streams.is_empty() || !self.switched_on(tenant_id).await {
            return Vec::new();
        }
        streams
    }

    /// One event, resolved and submitted per stream.
    async fn fan_out(
        &self,
        streams: &[SsfStream],
        event: &SsfEvent,
        subject: &SsfSubject,
        txn: &str,
    ) {
        let Some(outbox) = self.outbox.get() else {
            return;
        };
        let now = Utc::now();
        for stream in streams {
            let pending = match prepare_event(
                &self.auth_config,
                stream,
                event,
                subject,
                Some(txn),
                now,
            ) {
                Ok(pending) => pending,
                // Not for this stream: it does not carry the event, it was
                // disabled meanwhile, or it names users by an address nothing
                // vouches for (D-46: the event is not sent there).
                Err(
                    SsfError::EventNotDelivered
                    | SsfError::StreamDisabled
                    | SsfError::EmailNotVouched,
                ) => continue,
                Err(error) => {
                    tracing::warn!(target: "axiam::ssf", stream_id = %stream.id, %error, "an SSF event could not be prepared");
                    continue;
                }
            };
            match outbox.submit(stream, &pending).await {
                Ok(()) | Err(SsfOutboxError::Disabled) => {}
                Err(error) => {
                    tracing::warn!(target: "axiam::ssf", stream_id = %stream.id, %error, "an SSF event could not be submitted");
                }
            }
        }
    }

    fn txn() -> String {
        current_cause().map_or_else(|| Uuid::new_v4().to_string(), |cause| cause.txn)
    }

    /// Emit `event` about `subject` (already resolved).
    pub async fn emit(&self, tenant_id: Uuid, event: SsfEvent, subject: SsfSubject) {
        let streams = self.streams_for(tenant_id, event.event_type()).await;
        if streams.is_empty() {
            return;
        }
        self.fan_out(&streams, &event, &subject, &Self::txn()).await;
    }

    /// Emit `event` about the user `user_id`, reading the account only when a
    /// stream will carry it.
    pub async fn emit_for_user(&self, tenant_id: Uuid, user_id: Uuid, event: SsfEvent) {
        let streams = self.streams_for(tenant_id, event.event_type()).await;
        if streams.is_empty() {
            return;
        }
        let user = match self.user_repo.get_by_id(tenant_id, user_id).await {
            Ok(user) => user,
            Err(error) => {
                tracing::warn!(target: "axiam::ssf", %tenant_id, %user_id, %error, "an SSF event's subject could not be read");
                return;
            }
        };
        self.fan_out(
            &streams,
            &event,
            &SsfSubject::from_user(&user),
            &Self::txn(),
        )
        .await;
    }

    /// Whether some stream would carry `event_type` for the tenant right now:
    /// an outbox is wired, the tenant's `ssf_enabled` is on and a stream is
    /// registered for it. For a producer that has to *prepare* an event (D-53 (1)
    /// remembers a step-up before it knows it will be told of one) and would
    /// otherwise do that work for nobody.
    pub async fn carries(&self, tenant_id: Uuid, event_type: SsfEventType) -> bool {
        !self.streams_for(tenant_id, event_type).await.is_empty()
    }

    /// CAEP `assurance-level-change` (D-53 (1)): the `acr` class `user_id`'s
    /// session achieved moved from `previous` to `current` by the user's own
    /// step-up. The caller has already compared them: equal levels are not a
    /// change and nothing is emitted for them.
    pub async fn assurance_level_changed(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        previous: AssuranceLevel,
        current: AssuranceLevel,
    ) {
        if previous == current {
            return;
        }
        self.emit_for_user(
            tenant_id,
            user_id,
            SsfEvent::AssuranceLevelChange {
                current_level: current,
                previous_level: Some(previous),
                initiating_entity: Some(InitiatingEntity::User),
                event_timestamp: Utc::now().timestamp(),
            },
        )
        .await;
    }

    /// CAEP `credential-change` (D-52): a credential of `user_id` was created,
    /// changed or removed.
    pub async fn credential_changed(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        credential_type: CredentialType,
        change_type: ChangeType,
        initiated_by: InitiatingEntity,
        detail: CredentialDetail,
    ) {
        self.emit_for_user(
            tenant_id,
            user_id,
            SsfEvent::CredentialChange {
                credential_type,
                change_type,
                initiating_entity: Some(initiated_by),
                event_timestamp: Utc::now().timestamp(),
                x509_issuer: None,
                x509_serial: None,
                fido2_aaguid: detail.fido2_aaguid,
            },
        )
        .await;
    }

    /// RISC `account-disabled`: `user`'s account was set `Inactive`. A lockout
    /// is not one.
    pub async fn account_disabled(&self, tenant_id: Uuid, user: &User) {
        self.emit(
            tenant_id,
            SsfEvent::AccountDisabled { reason: None },
            SsfSubject::from_user(user),
        )
        .await;
    }

    /// RISC `account-enabled`: `user`'s account went from `Inactive` to `Active`.
    pub async fn account_enabled(&self, tenant_id: Uuid, user: &User) {
        self.emit(
            tenant_id,
            SsfEvent::AccountEnabled,
            SsfSubject::from_user(user),
        )
        .await;
    }

    /// RISC `account-purged`. The subject is the account **as it was before**
    /// the write that destroyed it (its address is gone afterwards), so the
    /// caller captures it first.
    pub async fn account_purged(&self, tenant_id: Uuid, subject: SsfSubject) {
        self.emit(tenant_id, SsfEvent::AccountPurged, subject).await;
    }
}

impl<C: Connection + Clone> SessionRevocationSink for SsfEmitter<C> {
    fn is_active(&self) -> bool {
        self.is_wired()
    }

    fn sessions_revoked<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        session_ids: &'a [Uuid],
    ) -> SsfFuture<'a, ()> {
        Box::pin(async move {
            let streams = self
                .streams_for(tenant_id, SsfEventType::SessionRevoked)
                .await;
            if streams.is_empty() || session_ids.is_empty() {
                return;
            }
            let user = match self.user_repo.get_by_id(tenant_id, user_id).await {
                Ok(user) => user,
                Err(error) => {
                    tracing::warn!(target: "axiam::ssf", %tenant_id, %user_id, %error, "a revoked session's user could not be read");
                    return;
                }
            };
            let subject = SsfSubject::from_user(&user);
            let initiating_entity = current_cause().and_then(|cause| cause.initiating_entity);
            let txn = Self::txn();
            for session_id in session_ids {
                let event = SsfEvent::SessionRevoked {
                    initiating_entity,
                    event_timestamp: Utc::now().timestamp(),
                };
                self.fan_out(
                    &streams,
                    &event,
                    &subject.clone().with_session(*session_id),
                    &txn,
                )
                .await;
            }
        })
    }
}

impl<C: Connection + Clone> SsfSystemAccountSink for SsfEmitter<C> {
    fn is_active(&self) -> bool {
        self.is_wired()
    }

    fn account_disabled<'a>(&'a self, tenant_id: Uuid, user: &'a User) -> SsfFuture<'a, ()> {
        Box::pin(SsfEmitter::account_disabled(self, tenant_id, user))
    }

    fn account_purged<'a>(&'a self, tenant_id: Uuid, user: &'a User) -> SsfFuture<'a, ()> {
        Box::pin(SsfEmitter::account_purged(
            self,
            tenant_id,
            SsfSubject::from_user(user),
        ))
    }
}

// ---------------------------------------------------------------------------
// D-55: the audit row of a shared issuer
// ---------------------------------------------------------------------------

/// Writes `ssf.inactive_shared_issuer` once per tenant whose `ssf_enabled` is
/// on, when the D-55 gate starts to hold (the deployment's tenants would share
/// one issuer, so SSF is inactive for every one of them). Bound to the gate,
/// which calls it once per change per process — never per event.
pub struct SharedIssuerAudit<C: Connection + Clone> {
    org_repo: axiam_db::SurrealOrganizationRepository<C>,
    tenant_repo: SurrealTenantRepository<C>,
    settings_repo: SurrealSettingsRepository<C>,
    audit_repo: axiam_db::SurrealAuditLogRepository<C>,
}

impl<C: Connection + Clone> SharedIssuerAudit<C> {
    /// The audit writer over these repositories.
    pub fn new(
        org_repo: axiam_db::SurrealOrganizationRepository<C>,
        tenant_repo: SurrealTenantRepository<C>,
        settings_repo: SurrealSettingsRepository<C>,
        audit_repo: axiam_db::SurrealAuditLogRepository<C>,
    ) -> Self {
        Self {
            org_repo,
            tenant_repo,
            settings_repo,
            audit_repo,
        }
    }

    /// Every tenant of every organization, page by page.
    async fn every_tenant(&self) -> Result<Vec<axiam_core::models::tenant::Tenant>, AxiamError> {
        use axiam_core::repository::{OrganizationRepository, Pagination};
        const PAGE: u64 = 100;
        let mut tenants = Vec::new();
        let mut offset = 0;
        loop {
            let orgs = self
                .org_repo
                .list(Pagination {
                    offset,
                    limit: PAGE,
                    search: None,
                })
                .await?;
            let got = orgs.items.len() as u64;
            for org in orgs.items {
                let mut tenant_offset = 0;
                loop {
                    let page = self
                        .tenant_repo
                        .list_by_organization(
                            org.id,
                            Pagination {
                                offset: tenant_offset,
                                limit: PAGE,
                                search: None,
                            },
                        )
                        .await?;
                    let n = page.items.len() as u64;
                    tenants.extend(page.items);
                    tenant_offset += n;
                    if n < PAGE {
                        break;
                    }
                }
            }
            offset += got;
            if got < PAGE {
                return Ok(tenants);
            }
        }
    }
}

impl<C: Connection + Clone> axiam_core::models::ssf::SharedIssuerObserver for SharedIssuerAudit<C> {
    fn gate_changed(&self, holds: bool) -> SsfFuture<'_, ()> {
        Box::pin(async move {
            use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
            use axiam_core::models::ssf::{
                AUDIT_SSF_INACTIVE_SHARED_ISSUER, SHARED_ISSUER_INACTIVE_REASON,
            };
            use axiam_core::repository::AuditLogRepository;
            if !holds {
                return;
            }
            let tenants = match self.every_tenant().await {
                Ok(tenants) => tenants,
                Err(error) => {
                    tracing::warn!(target: "axiam::ssf", %error, "the D-55 audit could not list the tenants");
                    return;
                }
            };
            for tenant in tenants {
                let on = self
                    .settings_repo
                    .get_effective_settings(tenant.organization_id, tenant.id)
                    .await
                    .is_ok_and(|s| s.oidc.ssf_enabled);
                if !on {
                    continue;
                }
                if let Err(error) = self
                    .audit_repo
                    .append(CreateAuditLogEntry {
                        tenant_id: tenant.id,
                        actor_id: Uuid::nil(),
                        actor_type: ActorType::System,
                        action: AUDIT_SSF_INACTIVE_SHARED_ISSUER.into(),
                        resource_id: None,
                        outcome: AuditOutcome::Failure,
                        ip_address: None,
                        metadata: Some(serde_json::json!({
                            "reason": SHARED_ISSUER_INACTIVE_REASON,
                        })),
                    })
                    .await
                {
                    tracing::warn!(target: "axiam::ssf", tenant_id = %tenant.id, %error, "the D-55 audit row could not be written");
                }
            }
        })
    }
}
