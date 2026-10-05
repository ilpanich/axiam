//! Reconciliation: the nightly (and on-demand) repair of a target's drift
//! (G-6, T23.6.3, D-58).
//!
//! Delivery is level-triggered and fed by change reports, so what it cannot see
//! is a change nobody reported: a downstream administrator who edited or
//! removed an account, a broker outage that dropped a reference, an erasure
//! `DELETE` that was refused. Reconciliation is the second source of the same
//! references, plus a read of the downstream.
//!
//! # One run, for one target
//!
//! 0. **Claim.** `claim_reconciliation` is a conditional write on the target's
//!    delivery state: it succeeds for one caller per interval, on any replica,
//!    and stamps the start of the run. There is no completion write. The
//!    scheduled job passes [`RECONCILE_INTERVAL`] (24 h); the on-demand entry
//!    passes [`RECONCILE_WALL_CLOCK`], the longest a run may take.
//! 1. **Enqueue.** One reference per in-scope user, per pushed group and per
//!    linked resource, on the shared dispatcher; the deliverer converges each.
//!    A link left `erase_pending` by a refused erasure `DELETE` is a linked
//!    resource like any other: this is what retries it.
//! 2. **Read the downstream.** `GET /Users` (and `/Groups` when the target
//!    pushes groups), `startIndex`/`count = 100`, every request through the
//!    deliverer's own guarded, no-redirect, credential-checked path
//!    (`ScimPushDeliverer::call`; there is no second HTTP path), with a page
//!    budget and a wall-clock budget. For each downstream resource:
//!    * **linked** → when what AXIAM would send now differs from it, the
//!      link's digest is cleared (so the next sync sends it) and the resource
//!      is queued again;
//!    * **not linked, `externalId` is the id of an AXIAM resource of this
//!      tenant that should not be there** (out of scope, disabled, erased) → the
//!      link is adopted and a reference queued, and the deliverer deprovisions
//!      it as it would have had the change been reported;
//!    * **anything else** (no `externalId`, one that is not an AXIAM id of this
//!      tenant, an id of another tenant) → **never touched**: it is an account
//!      the downstream's own application made.
//!
//!    When a collection was listed to its end, a link whose downstream
//!    resource was **not** listed is dropped and the resource queued again
//!    (re-created); a link made after the run began is left alone.
//!
//! The run's findings are logged once, as one line, and returned as a
//! [`ReconcileReport`]. Reasons are a fixed vocabulary: never a URL, a body or
//! a value.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use axiam_core::error::AxiamError;
use axiam_core::models::scim_target::{
    NewScimTargetLink, ScimResourceType, ScimTarget, ScimTargetLink, ScimTargetScope,
};
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{
    GroupRepository, Pagination, ScimTargetLinkRepository, ScimTargetRepository,
    ScimTargetStateRepository, UserRepository,
};
use chrono::{DateTime, Utc};
use reqwest::Method;
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use super::client::{Exit, LIST_BODY_CAP, Payload};
use super::deliverer::{
    DesiredUser, Run, ScimPushDeliverer, collection_of, resource_url, usable_downstream_id,
};
use super::provisioner::{group_in_scope, reference_message};
use super::wire::{GroupRepresentation, UserRepresentation};

/// How long after a run began the scheduled job runs it again: once a day.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The longest one run may take. Also the interval an on-demand run is claimed
/// for: a second request while the first may still be running is "already
/// claimed".
pub const RECONCILE_WALL_CLOCK: Duration = Duration::from_secs(5 * 60);

/// Downstream pages read per collection (`/Users`, `/Groups`) per run. With
/// [`LIST_PAGE_SIZE`] that is at most 10 000 resources of each kind; a larger
/// downstream is audited in part (the run says so) and never has a link
/// dropped for being "missing" from a listing that was cut short.
pub const RECONCILE_MAX_PAGES: u32 = 100;

/// `count` of a downstream list request (RFC 7644 §3.4.2.4).
pub const LIST_PAGE_SIZE: u32 = 100;

/// The page size of AXIAM's own reads while enqueueing.
const AXIAM_PAGE: u64 = 100;

/// How far a run got in reading the downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// Every collection was read to its end.
    Complete,
    /// A budget (pages or wall clock) stopped the listing: what was read was
    /// audited, nothing was concluded from what was not.
    BudgetExhausted,
    /// The downstream could not be read; the reason is a fixed phrase.
    Failed(String),
}

/// What one reconciliation run found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// References queued in step 1 and for repairs (a resource queued twice
    /// counts twice).
    pub enqueued: u64,
    /// References that could not be queued (a broker outage).
    pub enqueue_failed: u64,
    /// Linked resources left `erase_pending` that were queued for another
    /// `DELETE`.
    pub erase_retried: u64,
    /// Links whose digest was cleared because the downstream differs.
    pub drift_cleared: u64,
    /// Links dropped because their downstream resource is gone.
    pub links_dropped: u64,
    /// Downstream resources of this tenant that should not be there, adopted
    /// and queued for deprovisioning.
    pub deprovisioned: u64,
    /// Downstream list pages read.
    pub pages: u32,
    /// How far the downstream listing got.
    pub listing: Listing,
}

impl ReconcileReport {
    fn new() -> Self {
        Self {
            enqueued: 0,
            enqueue_failed: 0,
            erase_retried: 0,
            drift_cleared: 0,
            links_dropped: 0,
            deprovisioned: 0,
            pages: 0,
            listing: Listing::Complete,
        }
    }

    /// Whether the run could not do all of its work: the broker refused a
    /// reference, or the downstream could not be read.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        self.enqueue_failed > 0 || matches!(self.listing, Listing::Failed(_))
    }
}

/// What a request to reconcile a target came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// The caller held the claim and the run was made.
    Ran(ReconcileReport),
    /// Another run holds the claim (or ran within the interval): nothing was
    /// done. The management API answers `409`.
    AlreadyClaimed,
    /// The target is disabled: it receives nothing, so there is nothing to
    /// reconcile, and the claim was not taken.
    TargetDisabled,
}

/// The totals of one pass of the scheduled job over every enabled target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconcileSweep {
    /// Targets whose run this pass made.
    pub reconciled: u64,
    /// Targets whose run could not do all of its work (see
    /// [`ReconcileReport::is_failure`]) or failed on AXIAM's own datastore.
    pub failed: u64,
}

/// The scheduled job's view of reconciliation, object-safe so that the cleanup
/// loop holds one without being generic over the deliverer's repositories.
pub trait ScimReconciliation: Send + Sync {
    /// Reconcile every enabled target whose last run is older than
    /// [`RECONCILE_INTERVAL`] (the claim decides), stopping between targets
    /// once `should_stop` says so.
    ///
    /// # Errors
    ///
    /// The enabled targets could not be listed.
    fn run_due<'a>(
        &'a self,
        should_stop: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> Pin<Box<dyn Future<Output = Result<ReconcileSweep, AxiamError>> + Send + 'a>>;
}

/// An `Exit` from a step that reads AXIAM's own datastore: only a datastore
/// failure can come out of those.
fn datastore(exit: Exit) -> AxiamError {
    match exit {
        Exit::Retry(reason) | Exit::Dead(reason) | Exit::Fail(reason) => {
            AxiamError::Internal(reason)
        }
    }
}

/// The reason an `Exit` is reported with: its fixed phrase.
fn reason_of(exit: Exit) -> String {
    match exit {
        Exit::Retry(reason) | Exit::Dead(reason) | Exit::Fail(reason) => reason,
    }
}

impl<T, L, S, U, G> ScimPushDeliverer<T, L, S, U, G>
where
    T: ScimTargetRepository + 'static,
    L: ScimTargetLinkRepository + 'static,
    S: ScimTargetStateRepository + 'static,
    U: UserRepository + 'static,
    G: GroupRepository + 'static,
{
    /// Reconcile one target **on demand**: the same claim as the scheduled
    /// job, taken for [`RECONCILE_WALL_CLOCK`], so that a request made while a
    /// run is under way (or has only just finished) is
    /// [`ReconcileOutcome::AlreadyClaimed`].
    ///
    /// # Errors
    ///
    /// `NotFound` when the target does not exist in the tenant; any other
    /// failure of AXIAM's own datastore.
    pub async fn reconcile_now(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
    ) -> Result<ReconcileOutcome, AxiamError> {
        self.reconcile(tenant_id, target_id, RECONCILE_WALL_CLOCK)
            .await
    }

    /// Reconcile one target if its last claim is older than `min_interval`.
    async fn reconcile(
        &self,
        tenant_id: Uuid,
        target_id: Uuid,
        min_interval: Duration,
    ) -> Result<ReconcileOutcome, AxiamError> {
        let target = self.targets.get(tenant_id, target_id).await?;
        if !target.enabled {
            return Ok(ReconcileOutcome::TargetDisabled);
        }
        let started_at = Utc::now();
        let seconds = i64::try_from(min_interval.as_secs()).unwrap_or(i64::MAX);
        if !self
            .state
            .claim_reconciliation(tenant_id, target_id, started_at, seconds)
            .await?
        {
            return Ok(ReconcileOutcome::AlreadyClaimed);
        }

        let deadline = Instant::now() + RECONCILE_WALL_CLOCK;
        let mut report = ReconcileReport::new();
        let outcome = self
            .run_claimed(target, started_at, deadline, &mut report)
            .await;
        match &outcome {
            Ok(()) => tracing::info!(
                target: "axiam::scim_reconcile",
                %tenant_id,
                %target_id,
                enqueued = report.enqueued,
                enqueue_failed = report.enqueue_failed,
                erase_retried = report.erase_retried,
                drift_cleared = report.drift_cleared,
                links_dropped = report.links_dropped,
                deprovisioned = report.deprovisioned,
                pages = report.pages,
                listing = match &report.listing {
                    Listing::Complete => "complete",
                    Listing::BudgetExhausted => "budget exhausted",
                    Listing::Failed(reason) => reason.as_str(),
                },
                "SCIM reconciliation finished"
            ),
            Err(_) => tracing::warn!(
                target: "axiam::scim_reconcile",
                %tenant_id,
                %target_id,
                "SCIM reconciliation stopped: AXIAM's datastore could not be read"
            ),
        }
        outcome.map(|()| ReconcileOutcome::Ran(report))
    }

    async fn run_claimed(
        &self,
        target: ScimTarget,
        started_at: DateTime<Utc>,
        deadline: Instant,
        report: &mut ReconcileReport,
    ) -> Result<(), AxiamError> {
        let mut queued = HashSet::new();
        self.enqueue_everything(&target, &mut queued, report)
            .await?;

        let mut run = Run::new(target);
        let mut worst = Listing::Complete;
        let mut collections = vec![ScimResourceType::User];
        if run.target.push_groups {
            collections.push(ScimResourceType::Group);
        }
        for resource_type in collections {
            let listing = self
                .audit_collection(&mut run, resource_type, started_at, deadline, report)
                .await?;
            // A failure outranks a budget, which outranks completeness.
            worst = match (worst, listing) {
                (Listing::Failed(reason), _) | (_, Listing::Failed(reason)) => {
                    Listing::Failed(reason)
                }
                (Listing::BudgetExhausted, _) | (_, Listing::BudgetExhausted) => {
                    Listing::BudgetExhausted
                }
                _ => Listing::Complete,
            };
            if matches!(worst, Listing::Failed(_)) {
                break;
            }
        }
        report.listing = worst;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Step 1: references
    // -----------------------------------------------------------------------

    /// One reference per in-scope user, per pushed group and per linked
    /// resource, each queued once.
    async fn enqueue_everything(
        &self,
        target: &ScimTarget,
        queued: &mut HashSet<(ScimResourceType, Uuid)>,
        report: &mut ReconcileReport,
    ) -> Result<(), AxiamError> {
        let tenant_id = target.tenant_id;

        // Users in scope. An erased or deleted account with a link is queued
        // below with the links; one without a link has nothing to remove.
        match &target.scope {
            ScimTargetScope::AllUsers => {
                let mut offset = 0;
                loop {
                    let page = self.users.list(tenant_id, axiam_page(offset)).await?;
                    for user in &page.items {
                        if !matches!(user.status, UserStatus::Deleted | UserStatus::Anonymized) {
                            self.queue_once(
                                target,
                                ScimResourceType::User,
                                user.id,
                                queued,
                                report,
                            )
                            .await;
                        }
                    }
                    offset += page.items.len() as u64;
                    if page.items.is_empty() || offset >= page.total {
                        break;
                    }
                }
            }
            ScimTargetScope::Groups(listed) => {
                for group_id in listed {
                    let mut offset = 0;
                    loop {
                        let page = match self
                            .groups
                            .get_members(tenant_id, *group_id, axiam_page(offset))
                            .await
                        {
                            Ok(page) => page,
                            // A listed group that no longer exists has no members.
                            Err(AxiamError::NotFound { .. }) => break,
                            Err(error) => return Err(error),
                        };
                        for user in &page.items {
                            self.queue_once(
                                target,
                                ScimResourceType::User,
                                user.id,
                                queued,
                                report,
                            )
                            .await;
                        }
                        offset += page.items.len() as u64;
                        if page.items.is_empty() || offset >= page.total {
                            break;
                        }
                    }
                }
            }
        }

        // Groups the target pushes.
        if target.push_groups {
            match &target.scope {
                ScimTargetScope::AllUsers => {
                    let mut offset = 0;
                    loop {
                        let page = self.groups.list(tenant_id, axiam_page(offset)).await?;
                        for group in &page.items {
                            self.queue_once(
                                target,
                                ScimResourceType::Group,
                                group.id,
                                queued,
                                report,
                            )
                            .await;
                        }
                        offset += page.items.len() as u64;
                        if page.items.is_empty() || offset >= page.total {
                            break;
                        }
                    }
                }
                ScimTargetScope::Groups(listed) => {
                    for group_id in listed {
                        self.queue_once(target, ScimResourceType::Group, *group_id, queued, report)
                            .await;
                    }
                }
            }
        }

        // Everything already linked, wherever it stands now: this is what
        // removes a resource that left scope, was erased or was deleted, and
        // what retries an erasure `DELETE` that was refused.
        let mut offset = 0;
        loop {
            let page = self
                .links
                .list_by_target(tenant_id, target.id, None, axiam_page(offset))
                .await?;
            for link in &page.items {
                if link.erase_pending {
                    report.erase_retried += 1;
                }
                self.queue_once(target, link.resource_type, link.axiam_id, queued, report)
                    .await;
            }
            offset += page.items.len() as u64;
            if page.items.is_empty() || offset >= page.total {
                break;
            }
        }
        Ok(())
    }

    /// Queue a reference unless this run already queued it.
    async fn queue_once(
        &self,
        target: &ScimTarget,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
        queued: &mut HashSet<(ScimResourceType, Uuid)>,
        report: &mut ReconcileReport,
    ) {
        if queued.insert((resource_type, axiam_id)) {
            self.queue_again(target, resource_type, axiam_id, report)
                .await;
        }
    }

    /// Queue a reference, whether or not this run queued it before: a repair
    /// made after the first reference may have been delivered needs another.
    async fn queue_again(
        &self,
        target: &ScimTarget,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
        report: &mut ReconcileReport,
    ) {
        let message = reference_message(target.tenant_id, target.id, resource_type, axiam_id);
        match self.publisher.enqueue(&message).await {
            Ok(()) => report.enqueued += 1,
            Err(_) => report.enqueue_failed += 1,
        }
    }

    // -----------------------------------------------------------------------
    // Step 2: the downstream
    // -----------------------------------------------------------------------

    /// Page one downstream collection and repair what it shows. `Err` only for
    /// a failure of AXIAM's own datastore; whatever the downstream does is a
    /// [`Listing`].
    async fn audit_collection(
        &self,
        run: &mut Run,
        resource_type: ScimResourceType,
        started_at: DateTime<Utc>,
        deadline: Instant,
        report: &mut ReconcileReport,
    ) -> Result<Listing, AxiamError> {
        let target = run.target.clone();
        let mut seen: HashSet<String> = HashSet::new();
        let mut start_index: u64 = 1;
        let mut pages = 0u32;
        loop {
            if pages >= RECONCILE_MAX_PAGES || Instant::now() >= deadline {
                return Ok(Listing::BudgetExhausted);
            }
            let url = list_url(&target.base_url, resource_type, start_index).map_err(datastore)?;
            let response = match self
                .call(run, Method::GET, &url, Payload::scim(None), LIST_BODY_CAP)
                .await
            {
                Ok(response) => response,
                Err(exit) => return Ok(Listing::Failed(reason_of(exit))),
            };
            if !(200..=299).contains(&response.status) {
                return Ok(Listing::Failed(reason_of(
                    self.reject(run, response.status),
                )));
            }
            let Ok(document) = serde_json::from_slice::<Value>(&response.body) else {
                return Ok(Listing::Failed(
                    "the receiver's list response is malformed".to_owned(),
                ));
            };
            pages += 1;
            report.pages += 1;

            let resources = document
                .get("Resources")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice);
            for resource in resources {
                self.audit_resource(run, resource_type, resource, &mut seen, report)
                    .await?;
            }

            let consumed = resources.len() as u64;
            if consumed == 0 {
                break;
            }
            start_index += consumed;
            let listed = start_index - 1;
            match document.get("totalResults").and_then(Value::as_u64) {
                Some(total) if listed >= total => break,
                Some(_) => {}
                // No total: a short page is the last.
                None if consumed < u64::from(LIST_PAGE_SIZE) => break,
                None => {}
            }
        }

        // Only a listing that reached its end may conclude that a link's
        // resource is gone: every early exit above returned.
        self.drop_missing_links(&target, resource_type, &seen, started_at, report)
            .await?;
        Ok(Listing::Complete)
    }

    /// One downstream resource, judged.
    async fn audit_resource(
        &self,
        run: &Run,
        resource_type: ScimResourceType,
        resource: &Value,
        seen: &mut HashSet<String>,
        report: &mut ReconcileReport,
    ) -> Result<(), AxiamError> {
        let target = &run.target;
        let Some(downstream_id) = resource
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| usable_downstream_id(id))
        else {
            return Ok(());
        };
        seen.insert(downstream_id.to_owned());

        let linked = self
            .links
            .get_by_downstream_id(target.tenant_id, target.id, resource_type, downstream_id)
            .await?;
        if let Some(link) = linked {
            return self.audit_linked(target, &link, resource, report).await;
        }

        // Not ours to touch unless `externalId` is the id of an AXIAM resource
        // of this tenant, and then only if that resource should not be there.
        let Some(axiam_id) = resource
            .get("externalId")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
        else {
            return Ok(());
        };
        let unwanted = match resource_type {
            ScimResourceType::User => self.user_should_be_gone(target, axiam_id, resource).await?,
            ScimResourceType::Group => self.group_should_be_gone(target, axiam_id).await?,
        };
        if !unwanted {
            return Ok(());
        }
        let adopted = self
            .links
            .create(NewScimTargetLink {
                tenant_id: target.tenant_id,
                target_id: target.id,
                resource_type,
                axiam_id,
                downstream_id: downstream_id.to_owned(),
            })
            .await;
        match adopted {
            Ok(_) => {
                report.deprovisioned += 1;
                self.queue_again(target, resource_type, axiam_id, report)
                    .await;
                Ok(())
            }
            // Linked meanwhile (another replica, a delivery): not ours to redo.
            Err(AxiamError::AlreadyExists { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// A linked resource: clear its digest when the downstream differs from
    /// what would be sent now. A resource that is to be removed is not drift:
    /// its reference is already queued.
    async fn audit_linked(
        &self,
        target: &ScimTarget,
        link: &ScimTargetLink,
        resource: &Value,
        report: &mut ReconcileReport,
    ) -> Result<(), AxiamError> {
        let drifted = match link.resource_type {
            ScimResourceType::User => {
                let user = match self.users.get_by_id(target.tenant_id, link.axiam_id).await {
                    Ok(user) => Some(user),
                    Err(AxiamError::NotFound { .. }) => None,
                    Err(error) => return Err(error),
                };
                match self.desired_user(target, user).await.map_err(datastore)? {
                    DesiredUser::Present { user, active } => {
                        UserRepresentation::new(&user, target, active).differs_from(resource)
                    }
                    DesiredUser::Remove { .. } => false,
                }
            }
            ScimResourceType::Group => {
                let group = match self.groups.get_by_id(target.tenant_id, link.axiam_id).await {
                    Ok(group) if group_in_scope(target, group.id) => group,
                    Ok(_) | Err(AxiamError::NotFound { .. }) => return Ok(()),
                    Err(error) => return Err(error),
                };
                match self.linked_member_ids(target, &group).await {
                    Ok(members) => GroupRepresentation::new(&group, members).differs_from(resource),
                    // Too large to push: nothing to compare.
                    Err(Exit::Dead(_)) => false,
                    Err(exit) => return Err(datastore(exit)),
                }
            }
        };
        if !drifted {
            return Ok(());
        }
        self.links
            .set_digest(
                link.tenant_id,
                link.target_id,
                link.resource_type,
                link.axiam_id,
                None,
            )
            .await?;
        report.drift_cleared += 1;
        // The reference queued in step 1 may already have been delivered, with
        // the digest still set: queue another, behind the clearing.
        self.queue_again(target, link.resource_type, link.axiam_id, report)
            .await;
        Ok(())
    }

    /// Whether the downstream account named by `axiam_id` is one AXIAM would
    /// not provision now: the user exists **in this tenant** and is erased,
    /// deleted, out of scope or not active, and — for a deactivation policy —
    /// the downstream still has it active. A user of another tenant, and an id
    /// that is no user at all, are not found here and are left alone.
    async fn user_should_be_gone(
        &self,
        target: &ScimTarget,
        axiam_id: Uuid,
        resource: &Value,
    ) -> Result<bool, AxiamError> {
        let user = match self.users.get_by_id(target.tenant_id, axiam_id).await {
            Ok(user) => user,
            Err(AxiamError::NotFound { .. }) => return Ok(false),
            Err(error) => return Err(error),
        };
        Ok(
            match self
                .desired_user(target, Some(user))
                .await
                .map_err(datastore)?
            {
                DesiredUser::Remove { .. } => true,
                DesiredUser::Present { active: false, .. } => resource
                    .get("active")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
                DesiredUser::Present { active: true, .. } => false,
            },
        )
    }

    /// Whether the downstream group named by `axiam_id` is a group of this
    /// tenant that the target no longer pushes.
    async fn group_should_be_gone(
        &self,
        target: &ScimTarget,
        axiam_id: Uuid,
    ) -> Result<bool, AxiamError> {
        match self.groups.get_by_id(target.tenant_id, axiam_id).await {
            Ok(group) => Ok(!group_in_scope(target, group.id)),
            Err(AxiamError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// After a collection was listed to its end: forget the links whose
    /// downstream resource was not in it, and queue those resources again so
    /// that they are re-created. A link made after the run began is not judged
    /// by a listing that may predate it.
    async fn drop_missing_links(
        &self,
        target: &ScimTarget,
        resource_type: ScimResourceType,
        seen: &HashSet<String>,
        started_at: DateTime<Utc>,
        report: &mut ReconcileReport,
    ) -> Result<(), AxiamError> {
        let mut missing: Vec<ScimTargetLink> = Vec::new();
        let mut offset = 0;
        loop {
            let page = self
                .links
                .list_by_target(
                    target.tenant_id,
                    target.id,
                    Some(resource_type),
                    axiam_page(offset),
                )
                .await?;
            missing.extend(
                page.items
                    .iter()
                    .filter(|link| {
                        link.created_at < started_at && !seen.contains(&link.downstream_id)
                    })
                    .cloned(),
            );
            offset += page.items.len() as u64;
            if page.items.is_empty() || offset >= page.total {
                break;
            }
        }
        for link in missing {
            let removed = self
                .links
                .delete(
                    link.tenant_id,
                    link.target_id,
                    link.resource_type,
                    link.axiam_id,
                )
                .await?;
            if removed {
                report.links_dropped += 1;
                self.queue_again(target, link.resource_type, link.axiam_id, report)
                    .await;
            }
        }
        Ok(())
    }
}

impl<T, L, S, U, G> ScimReconciliation for ScimPushDeliverer<T, L, S, U, G>
where
    T: ScimTargetRepository + 'static,
    L: ScimTargetLinkRepository + 'static,
    S: ScimTargetStateRepository + 'static,
    U: UserRepository + 'static,
    G: GroupRepository + 'static,
{
    fn run_due<'a>(
        &'a self,
        should_stop: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> Pin<Box<dyn Future<Output = Result<ReconcileSweep, AxiamError>> + Send + 'a>> {
        Box::pin(async move {
            let targets = self.targets.list_all_enabled().await?;
            let mut sweep = ReconcileSweep::default();
            for target in targets {
                if should_stop() {
                    break;
                }
                match self
                    .reconcile(target.tenant_id, target.id, RECONCILE_INTERVAL)
                    .await
                {
                    Ok(ReconcileOutcome::Ran(report)) => {
                        sweep.reconciled += 1;
                        if report.is_failure() {
                            sweep.failed += 1;
                        }
                    }
                    // Not due, claimed by another replica, or switched off
                    // since the listing: the common case at every tick.
                    Ok(ReconcileOutcome::AlreadyClaimed | ReconcileOutcome::TargetDisabled)
                    | Err(AxiamError::NotFound { .. }) => {}
                    Err(_) => {
                        // `reconcile` logged the one line for this target.
                        sweep.failed += 1;
                    }
                }
            }
            Ok(sweep)
        })
    }
}

fn axiam_page(offset: u64) -> Pagination {
    Pagination {
        offset,
        limit: AXIAM_PAGE,
        search: None,
    }
}

/// `<base>/<collection>?startIndex=<n>&count=100`.
fn list_url(
    base_url: &str,
    resource_type: ScimResourceType,
    start_index: u64,
) -> Result<String, Exit> {
    let plain = resource_url(base_url, collection_of(resource_type), None, None)?;
    let mut url =
        Url::parse(&plain).map_err(|_| Exit::dead("the target's base URL is not valid"))?;
    url.query_pairs_mut()
        .append_pair("startIndex", &start_index.to_string())
        .append_pair("count", &LIST_PAGE_SIZE.to_string());
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budgets_are_the_decided_ones() {
        assert_eq!(RECONCILE_INTERVAL, Duration::from_secs(86_400));
        assert_eq!(RECONCILE_WALL_CLOCK, Duration::from_secs(300));
        assert_eq!(RECONCILE_MAX_PAGES, 100);
        assert_eq!(LIST_PAGE_SIZE, 100);
    }

    #[test]
    fn a_list_url_pages_with_start_index_and_count() {
        let url = list_url("https://idp.example/scim/v2/", ScimResourceType::Group, 201).unwrap();
        assert_eq!(
            url,
            "https://idp.example/scim/v2/Groups?startIndex=201&count=100"
        );
        assert!(matches!(
            list_url("not a url", ScimResourceType::User, 1),
            Err(Exit::Dead(_))
        ));
    }

    #[test]
    fn a_report_is_a_failure_when_the_broker_or_the_downstream_failed() {
        let mut report = ReconcileReport::new();
        assert!(!report.is_failure());
        report.listing = Listing::BudgetExhausted;
        assert!(!report.is_failure(), "a budget is not a failure");
        report.listing = Listing::Failed("x".into());
        assert!(report.is_failure());
        report.listing = Listing::Complete;
        report.enqueue_failed = 1;
        assert!(report.is_failure());
    }
}
