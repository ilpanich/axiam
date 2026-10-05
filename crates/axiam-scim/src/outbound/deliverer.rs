//! The outbound SCIM **deliverer**: one attempt to bring one downstream
//! resource to the state it should have now (G-6, T23.6.2, D-36, D-57).
//!
//! It implements the core [`OutboundDeliverer`] port the dispatcher's consumer
//! calls. The retry schedule, the attempt counter, the dead-letter queue and
//! the audit rows (`scim_push.delivery_succeeded`, `.delivery_attempt`,
//! `.delivery_failed`) are the dispatcher's; a deliverer **classifies, it does
//! not decide**. See [the module documentation](super) for the table of what an
//! attempt does and for the transport rules.
//!
//! # What one attempt does
//!
//! 1. Decode the reference (`{resource_type, axiam_id}`); a malformed one is a
//!    dead letter.
//! 2. Read the target. Gone → dead-letter `target not found`; disabled →
//!    dead-letter `target disabled`.
//! 3. Read the resource and its link, and compute the desired downstream state.
//! 4. Act: `POST`, `PATCH` (skipped when the digest of the representation is the
//!    link's `synced_digest`), or `DELETE`; keep the link row in step.
//! 5. Report to the target's delivery state (`record_success`, `record_failure`,
//!    `record_dead_letter`): atomic writes, never the target row.
//!
//! # Status mapping
//!
//! | The downstream answers | Outcome |
//! |---|---|
//! | `2xx` | delivered |
//! | `409` to a `POST` | adopt the resource whose `externalId` is the AXIAM id (exactly one, else dead-letter `conflict`) |
//! | `404` to a `PATCH` | drop the link and retry (the next attempt re-creates) |
//! | `404` to a `DELETE` | delivered: it is gone |
//! | `3xx` | retry; never followed |
//! | `408`, `429`, `5xx`, a timeout, no connection | retry |
//! | `401`, client-credentials target | flush the cached access token, retry |
//! | `401`, `403`, bearer target | dead-letter: the credential is wrong until someone fixes it |
//! | any other `4xx` | dead-letter, reason `HTTP <status>` |
//!
//! A reason is a fixed vocabulary — never a URL, a body, a name or a value.

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::group::Group;
use axiam_core::models::scim_target::{
    DeprovisionPolicy, NewScimTargetLink, ScimLinkState, ScimResourceType, ScimTarget,
    ScimTargetAuth, ScimTargetLink, ScimTargetScope,
};
use axiam_core::models::user::{User, UserStatus};
use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundKind,
    OutboundMessage, OutboundPublisher,
};
use axiam_core::repository::{
    GroupRepository, Pagination, ScimTargetLinkRepository, ScimTargetRepository,
    ScimTargetStateRepository, UserRepository,
};
use reqwest::Method;
use reqwest::header::HeaderValue;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::client::{
    Exit, LIST_BODY_CAP, Payload, RESPONSE_BODY_CAP, Response, Step, TokenCache, TokenRequest,
    fetch_access_token, send,
};
use super::provisioner::{group_in_scope, reference_message};
use super::wire::{GroupRepresentation, UserRepresentation, digest_of};

/// A group with more members than this is not pushed: the whole list travels in
/// one `PATCH`, and an unbounded read of a group is not a thing an attempt does.
const MAX_GROUP_MEMBERS: u64 = 10_000;
const MEMBER_PAGE: u64 = 100;

/// The longest downstream id AXIAM will link.
const MAX_DOWNSTREAM_ID_BYTES: usize = 256;

const USERS: &str = "Users";
const GROUPS: &str = "Groups";

/// The [`OutboundDeliverer`] of [`OutboundKind::ScimPush`].
pub struct ScimPushDeliverer<T, L, S, U, G> {
    targets: T,
    links: L,
    state: S,
    users: U,
    groups: G,
    /// For the convergence enqueue (a newly linked user's groups) only; the
    /// consumer loop owns every retry.
    publisher: Arc<dyn OutboundPublisher>,
    tokens: TokenCache,
    /// The guarded fetch's `allow_private`. **Always `false`** except for the
    /// integration tests' loopback server, which turn it on through
    /// [`Self::admitting_private_networks_for_tests`] and nothing else.
    allow_private: bool,
}

/// What one attempt carries from step to step.
struct Run {
    /// The target as the attempt read it first: the version every later read
    /// is compared with before the credential is sent.
    target: ScimTarget,
    /// Opened lazily, before the first request.
    authorization: Option<HeaderValue>,
    /// The status of the last response received, if any request was made.
    last_status: Option<u16>,
}

/// What a user should be downstream, now.
enum DesiredUser {
    /// Present, with `active` as given.
    Present { user: Box<User>, active: bool },
    /// Gone: `DELETE` and remove the link.
    Remove,
}

impl<T, L, S, U, G> ScimPushDeliverer<T, L, S, U, G>
where
    T: ScimTargetRepository + 'static,
    L: ScimTargetLinkRepository + 'static,
    S: ScimTargetStateRepository + 'static,
    U: UserRepository + 'static,
    G: GroupRepository + 'static,
{
    /// The production deliverer: every request goes through
    /// `guarded_fetch_no_redirect` with `allow_private = false`.
    pub fn new(
        targets: T,
        links: L,
        state: S,
        users: U,
        groups: G,
        publisher: Arc<dyn OutboundPublisher>,
    ) -> Self {
        Self {
            targets,
            links,
            state,
            users,
            groups,
            publisher,
            tokens: TokenCache::default(),
            allow_private: false,
        }
    }

    /// **Test seam, never used by the composition root.** Lets the first hop
    /// reach a loopback server over plain `http`, the way
    /// `SsfPushDeliverer::admitting_private_networks_for_tests` does. A
    /// deliverer built by [`Self::new`] cannot be switched afterwards by
    /// anything but this call, and production never makes it.
    #[doc(hidden)]
    #[must_use]
    pub fn admitting_private_networks_for_tests(mut self) -> Self {
        self.allow_private = true;
        self
    }

    // -----------------------------------------------------------------------
    // The attempt
    // -----------------------------------------------------------------------

    async fn deliver(&self, msg: &OutboundMessage) -> Result<DeliveryOutcome, OutboundError> {
        let result = self.attempt(msg).await;
        match result {
            Ok(status) => {
                // A request was made and answered: the downstream is reachable
                // and the credential is good. A no-op attempt (nothing to send)
                // proves neither and does not stamp a success.
                if status.is_some() {
                    self.note(
                        self.state
                            .record_success(msg.tenant_id, msg.target_id)
                            .await,
                        msg,
                    );
                }
                Ok(DeliveryOutcome::Delivered {
                    response_status: status,
                })
            }
            Err(Exit::Retry(reason)) => {
                self.note(
                    self.state
                        .record_failure(msg.tenant_id, msg.target_id, &reason)
                        .await,
                    msg,
                );
                Ok(DeliveryOutcome::Retry { reason })
            }
            Err(Exit::Dead(reason)) => {
                self.note(
                    self.state
                        .record_dead_letter(msg.tenant_id, msg.target_id, &reason)
                        .await,
                    msg,
                );
                Ok(DeliveryOutcome::DeadLetter { reason })
            }
            Err(Exit::Fail(reason)) => {
                self.note(
                    self.state
                        .record_failure(msg.tenant_id, msg.target_id, &reason)
                        .await,
                    msg,
                );
                Err(OutboundError::Delivery(reason))
            }
        }
    }

    /// A delivery-state write that fails changes nothing about the outcome; it
    /// is logged, once, with ids only.
    fn note(&self, result: Result<(), AxiamError>, msg: &OutboundMessage) {
        if result.is_err() {
            tracing::warn!(
                target: "axiam::scim_push",
                tenant_id = %msg.tenant_id,
                target_id = %msg.target_id,
                "a SCIM target's delivery state could not be written"
            );
        }
    }

    /// The last response status of the attempt (`None` when no request was
    /// made), or why it stopped.
    async fn attempt(&self, msg: &OutboundMessage) -> Step<Option<u16>> {
        if msg.kind != OutboundKind::ScimPush {
            return Err(Exit::dead("the message is not a SCIM push"));
        }
        let (resource_type, axiam_id) = parse_reference(&msg.payload)
            .ok_or_else(|| Exit::dead("the queued reference is malformed"))?;

        let target = match self.targets.get(msg.tenant_id, msg.target_id).await {
            Ok(target) => target,
            Err(AxiamError::NotFound { .. }) => return Err(Exit::dead("target not found")),
            Err(_) => return Err(Exit::fail("the target could not be read")),
        };
        if !target.enabled {
            return Err(Exit::dead("target disabled"));
        }

        let mut run = Run {
            target,
            authorization: None,
            last_status: None,
        };
        match resource_type {
            ScimResourceType::User => self.sync_user(&mut run, axiam_id).await?,
            ScimResourceType::Group => self.sync_group(&mut run, axiam_id).await?,
        }
        Ok(run.last_status)
    }

    // -----------------------------------------------------------------------
    // Users
    // -----------------------------------------------------------------------

    async fn sync_user(&self, run: &mut Run, user_id: Uuid) -> Step<()> {
        let target = run.target.clone();
        let user = match self.users.get_by_id(target.tenant_id, user_id).await {
            Ok(user) => Some(user),
            Err(AxiamError::NotFound { .. }) => None,
            Err(_) => return Err(Exit::fail("the user could not be read")),
        };
        let link = self
            .read_link(&target, ScimResourceType::User, user_id)
            .await?;

        match self.desired_user(&target, user).await? {
            DesiredUser::Remove => {
                self.remove(run, ScimResourceType::User, user_id, link)
                    .await
            }
            // Nothing downstream to deactivate, and nothing worth creating
            // inactive: a user who is not in scope is simply not provisioned.
            DesiredUser::Present {
                active: false,
                user: _,
            } if link.is_none() => Ok(()),
            DesiredUser::Present { user, active } => match link {
                None => self.create_user(run, &user).await,
                Some(link) => self.update_user(run, &user, active, link).await,
            },
        }
    }

    async fn desired_user(&self, target: &ScimTarget, user: Option<User>) -> Step<DesiredUser> {
        // Erasure and deletion always delete, whatever `deprovision` says.
        let Some(user) = user else {
            return Ok(DesiredUser::Remove);
        };
        if matches!(user.status, UserStatus::Deleted | UserStatus::Anonymized) {
            return Ok(DesiredUser::Remove);
        }
        let in_scope = self.user_in_scope(target, &user).await?;
        if user.status == UserStatus::Active && in_scope {
            return Ok(DesiredUser::Present {
                user: Box::new(user),
                active: true,
            });
        }
        Ok(match target.deprovision {
            DeprovisionPolicy::Deactivate => DesiredUser::Present {
                user: Box::new(user),
                active: false,
            },
            DeprovisionPolicy::Delete => DesiredUser::Remove,
        })
    }

    /// `AllUsers`, or a direct member of a listed group.
    async fn user_in_scope(&self, target: &ScimTarget, user: &User) -> Step<bool> {
        match &target.scope {
            ScimTargetScope::AllUsers => Ok(true),
            ScimTargetScope::Groups(listed) => {
                let groups = self
                    .groups
                    .get_user_groups(target.tenant_id, user.id)
                    .await
                    .map_err(|_| Exit::fail("the user's groups could not be read"))?;
                Ok(groups.iter().any(|group| listed.contains(&group.id)))
            }
        }
    }

    async fn create_user(&self, run: &mut Run, user: &User) -> Step<()> {
        let target = run.target.clone();
        let representation = UserRepresentation::new(user, &target, true);
        let body = encode(&representation)?;
        let url = resource_url(&target.base_url, USERS, None, None)?;
        let response = self
            .call(
                run,
                Method::POST,
                &url,
                Payload::scim(Some(body)),
                RESPONSE_BODY_CAP,
            )
            .await?;
        match response.status {
            200..=299 => {
                let downstream_id = downstream_id_of(&response.body)?;
                let link = self
                    .link_new(&target, ScimResourceType::User, user.id, downstream_id)
                    .await?;
                self.set_synced(
                    &link,
                    Some(digest_of(&representation)),
                    ScimLinkState::Active,
                )
                .await?;
                self.converge_groups_of(&target, user.id).await;
                Ok(())
            }
            409 => {
                // The downstream already holds a user with this `externalId`
                // (or `userName`): adopt exactly the one that carries our id,
                // then bring it to the state we want.
                let downstream_id = self.adopt(run, USERS, user.id).await?;
                let link = self
                    .link_new(&target, ScimResourceType::User, user.id, downstream_id)
                    .await?;
                self.converge_groups_of(&target, user.id).await;
                self.update_user(run, user, true, link).await
            }
            status => Err(self.reject(run, status)),
        }
    }

    async fn update_user(
        &self,
        run: &mut Run,
        user: &User,
        active: bool,
        link: ScimTargetLink,
    ) -> Step<()> {
        let target = run.target.clone();
        let representation = UserRepresentation::new(user, &target, active);
        let digest = digest_of(&representation);
        let state = if active {
            ScimLinkState::Active
        } else {
            ScimLinkState::Deprovisioned
        };
        if link.synced_digest.as_deref() == Some(digest.as_str()) && link.state == state {
            // Nothing the mapping carries has changed since the last send.
            return Ok(());
        }
        let body = encode(&representation.patch())?;
        let url = resource_url(&target.base_url, USERS, Some(&link.downstream_id), None)?;
        let response = self
            .call(
                run,
                Method::PATCH,
                &url,
                Payload::scim(Some(body)),
                RESPONSE_BODY_CAP,
            )
            .await?;
        match response.status {
            200..=299 => self.set_synced(&link, Some(digest), state).await,
            404 => self.drop_link(&link).await,
            status => Err(self.reject(run, status)),
        }
    }

    // -----------------------------------------------------------------------
    // Groups
    // -----------------------------------------------------------------------

    async fn sync_group(&self, run: &mut Run, group_id: Uuid) -> Step<()> {
        let target = run.target.clone();
        let group = match self.groups.get_by_id(target.tenant_id, group_id).await {
            Ok(group) => Some(group),
            Err(AxiamError::NotFound { .. }) => None,
            Err(_) => return Err(Exit::fail("the group could not be read")),
        };
        let link = self
            .read_link(&target, ScimResourceType::Group, group_id)
            .await?;
        let group = match group {
            Some(group) if group_in_scope(&target, group.id) => group,
            // Gone, or no longer pushed: a Group has no `active`, so it is
            // removed.
            _ => {
                return self
                    .remove(run, ScimResourceType::Group, group_id, link)
                    .await;
            }
        };
        let members = self.linked_member_ids(&target, &group).await?;
        let representation = GroupRepresentation::new(&group, members);
        match link {
            None => self.create_group(run, &group, representation).await,
            Some(link) => self.update_group(run, representation, link).await,
        }
    }

    /// The downstream ids of the group's members that have a link on this
    /// target. A member with no link is skipped: it is pushed (and linked) by
    /// its own message, and linking enqueues the group again.
    async fn linked_member_ids(&self, target: &ScimTarget, group: &Group) -> Step<Vec<String>> {
        let mut ids = Vec::new();
        let mut offset = 0u64;
        loop {
            let page = self
                .groups
                .get_members(
                    target.tenant_id,
                    group.id,
                    Pagination {
                        offset,
                        limit: MEMBER_PAGE,
                        search: None,
                    },
                )
                .await
                .map_err(|_| Exit::fail("the group's members could not be read"))?;
            if page.total > MAX_GROUP_MEMBERS {
                return Err(Exit::dead("the group has more members than a push carries"));
            }
            if page.items.is_empty() {
                break;
            }
            for member in &page.items {
                if let Some(link) = self
                    .read_link(target, ScimResourceType::User, member.id)
                    .await?
                {
                    ids.push(link.downstream_id);
                }
            }
            offset += page.items.len() as u64;
            if offset >= page.total {
                break;
            }
        }
        Ok(ids)
    }

    async fn create_group(
        &self,
        run: &mut Run,
        group: &Group,
        representation: GroupRepresentation,
    ) -> Step<()> {
        let target = run.target.clone();
        let body = encode(&representation)?;
        let url = resource_url(&target.base_url, GROUPS, None, None)?;
        let response = self
            .call(
                run,
                Method::POST,
                &url,
                Payload::scim(Some(body)),
                RESPONSE_BODY_CAP,
            )
            .await?;
        match response.status {
            200..=299 => {
                let downstream_id = downstream_id_of(&response.body)?;
                let link = self
                    .link_new(&target, ScimResourceType::Group, group.id, downstream_id)
                    .await?;
                self.set_synced(
                    &link,
                    Some(digest_of(&representation)),
                    ScimLinkState::Active,
                )
                .await
            }
            409 => {
                let downstream_id = self.adopt(run, GROUPS, group.id).await?;
                let link = self
                    .link_new(&target, ScimResourceType::Group, group.id, downstream_id)
                    .await?;
                self.update_group(run, representation, link).await
            }
            status => Err(self.reject(run, status)),
        }
    }

    async fn update_group(
        &self,
        run: &mut Run,
        representation: GroupRepresentation,
        link: ScimTargetLink,
    ) -> Step<()> {
        let target = run.target.clone();
        let digest = digest_of(&representation);
        if link.synced_digest.as_deref() == Some(digest.as_str()) {
            return Ok(());
        }
        let body = encode(&representation.patch())?;
        let url = resource_url(&target.base_url, GROUPS, Some(&link.downstream_id), None)?;
        let response = self
            .call(
                run,
                Method::PATCH,
                &url,
                Payload::scim(Some(body)),
                RESPONSE_BODY_CAP,
            )
            .await?;
        match response.status {
            200..=299 => {
                self.set_synced(&link, Some(digest), ScimLinkState::Active)
                    .await
            }
            404 => self.drop_link(&link).await,
            status => Err(self.reject(run, status)),
        }
    }

    // -----------------------------------------------------------------------
    // Shared steps
    // -----------------------------------------------------------------------

    /// `DELETE` the downstream resource (a `404` is as good as a `204`) and
    /// remove the link. Nothing is sent for a resource that has no link.
    async fn remove(
        &self,
        run: &mut Run,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
        link: Option<ScimTargetLink>,
    ) -> Step<()> {
        let Some(link) = link else {
            return Ok(());
        };
        let target = run.target.clone();
        let collection = collection_of(resource_type);
        let url = resource_url(
            &target.base_url,
            collection,
            Some(&link.downstream_id),
            None,
        )?;
        let response = self
            .call(
                run,
                Method::DELETE,
                &url,
                Payload::scim(None),
                RESPONSE_BODY_CAP,
            )
            .await?;
        match response.status {
            200..=299 | 404 => {}
            status => return Err(self.reject(run, status)),
        }
        self.links
            .delete(target.tenant_id, target.id, resource_type, axiam_id)
            .await
            .map_err(|_| Exit::fail("the link could not be removed"))?;
        Ok(())
    }

    /// `GET <collection>?filter=externalId eq "<axiam id>"`: the one downstream
    /// resource that carries our id, or a dead letter `conflict`.
    async fn adopt(&self, run: &mut Run, collection: &str, axiam_id: Uuid) -> Step<String> {
        let target = run.target.clone();
        let filter = format!("externalId eq \"{axiam_id}\"");
        let url = resource_url(&target.base_url, collection, None, Some(&filter))?;
        let response = self
            .call(run, Method::GET, &url, Payload::scim(None), LIST_BODY_CAP)
            .await?;
        if !(200..=299).contains(&response.status) {
            return Err(self.reject(run, response.status));
        }
        let value: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|_| Exit::retry("the receiver's list response is malformed"))?;
        let wanted = axiam_id.to_string();
        // A service provider that ignores the filter answers with everything:
        // only a resource that really carries our id counts.
        let mut matches = value
            .get("Resources")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|resource| {
                resource
                    .get("externalId")
                    .and_then(serde_json::Value::as_str)
                    == Some(wanted.as_str())
            })
            .filter_map(|resource| resource.get("id").and_then(serde_json::Value::as_str));
        match (matches.next(), matches.next()) {
            (Some(id), None) if usable_downstream_id(id) => Ok(id.to_owned()),
            _ => Err(Exit::dead("conflict")),
        }
    }

    async fn read_link(
        &self,
        target: &ScimTarget,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
    ) -> Step<Option<ScimTargetLink>> {
        self.links
            .get(target.tenant_id, target.id, resource_type, axiam_id)
            .await
            .map_err(|_| Exit::fail("the link could not be read"))
    }

    /// Record a new link, honouring both unique indexes.
    async fn link_new(
        &self,
        target: &ScimTarget,
        resource_type: ScimResourceType,
        axiam_id: Uuid,
        downstream_id: String,
    ) -> Step<ScimTargetLink> {
        let created = self
            .links
            .create(NewScimTargetLink {
                tenant_id: target.tenant_id,
                target_id: target.id,
                resource_type,
                axiam_id,
                downstream_id: downstream_id.clone(),
            })
            .await;
        match created {
            Ok(link) => Ok(link),
            Err(AxiamError::AlreadyExists { .. }) => {
                match self.read_link(target, resource_type, axiam_id).await? {
                    // Another attempt linked this resource first.
                    Some(existing) if existing.downstream_id == downstream_id => Ok(existing),
                    Some(_) => Err(Exit::retry("the link changed during the attempt")),
                    // The downstream id is linked to a *different* resource.
                    None => Err(Exit::dead("conflict")),
                }
            }
            Err(_) => Err(Exit::fail("the link could not be written")),
        }
    }

    async fn set_synced(
        &self,
        link: &ScimTargetLink,
        digest: Option<String>,
        state: ScimLinkState,
    ) -> Step<()> {
        self.links
            .set_digest(
                link.tenant_id,
                link.target_id,
                link.resource_type,
                link.axiam_id,
                digest,
            )
            .await
            .map_err(|_| Exit::fail("the link could not be written"))?;
        if link.state != state || link.erase_pending {
            self.links
                .set_state(
                    link.tenant_id,
                    link.target_id,
                    link.resource_type,
                    link.axiam_id,
                    state,
                    false,
                )
                .await
                .map_err(|_| Exit::fail("the link could not be written"))?;
        }
        Ok(())
    }

    /// The downstream resource is gone: forget the link so that the next
    /// attempt re-creates it, and retry.
    async fn drop_link(&self, link: &ScimTargetLink) -> Step<()> {
        self.links
            .delete(
                link.tenant_id,
                link.target_id,
                link.resource_type,
                link.axiam_id,
            )
            .await
            .map_err(|_| Exit::fail("the link could not be removed"))?;
        Err(Exit::retry("the downstream resource is gone"))
    }

    /// Linking a user changes which members a group can name, so its in-scope
    /// groups are pushed again (D-57). Best effort: a failure is logged once
    /// and the next change of the group converges.
    async fn converge_groups_of(&self, target: &ScimTarget, user_id: Uuid) {
        if !target.push_groups {
            return;
        }
        let groups = match self.groups.get_user_groups(target.tenant_id, user_id).await {
            Ok(groups) => groups,
            Err(_) => {
                tracing::warn!(
                    target: "axiam::scim_push",
                    tenant_id = %target.tenant_id,
                    target_id = %target.id,
                    "a linked user's groups could not be read; they were not queued"
                );
                return;
            }
        };
        let mut failed = 0usize;
        for group in groups.iter().filter(|g| group_in_scope(target, g.id)) {
            let message = reference_message(
                target.tenant_id,
                target.id,
                ScimResourceType::Group,
                group.id,
            );
            if self.publisher.enqueue(&message).await.is_err() {
                failed += 1;
            }
        }
        if failed > 0 {
            tracing::warn!(
                target: "axiam::scim_push",
                tenant_id = %target.tenant_id,
                target_id = %target.id,
                failed,
                "a linked user's groups could not be enqueued"
            );
        }
    }

    // -----------------------------------------------------------------------
    // The request path
    // -----------------------------------------------------------------------

    /// One request, with the credential opened and checked first.
    async fn call(
        &self,
        run: &mut Run,
        method: Method,
        url: &str,
        payload: Payload,
        body_cap: usize,
    ) -> Step<Response> {
        if run.authorization.is_none() {
            run.authorization = Some(self.authorize(&run.target).await?);
        }
        let authorization = run
            .authorization
            .as_ref()
            .ok_or_else(|| Exit::fail("the credential was not opened"))?;
        let response = send(
            self.allow_private,
            method,
            url,
            authorization,
            payload,
            body_cap,
        )
        .await?;
        run.last_status = Some(response.status);
        Ok(response)
    }

    /// The target read once more, and equal to the version the attempt started
    /// from (F4 W4 P23W4-01, T-406): the credential is a separate read from the
    /// URL it is sent to, so it is checked against that URL's version before it
    /// leaves.
    async fn verify_unchanged(&self, started: &ScimTarget) -> Step<()> {
        match self.targets.get(started.tenant_id, started.id).await {
            Ok(again) if again.updated_at == started.updated_at => Ok(()),
            Ok(_) => Err(Exit::retry("the target changed during the attempt")),
            Err(AxiamError::NotFound { .. }) => Err(Exit::dead("target not found")),
            Err(_) => Err(Exit::fail("the target could not be read")),
        }
    }

    /// The `Authorization` header for the target: its bearer token, or an access
    /// token obtained (and cached in memory) with its client credentials.
    async fn authorize(&self, started: &ScimTarget) -> Step<HeaderValue> {
        let cached = match started.auth {
            ScimTargetAuth::OAuth2ClientCredentials { .. } => {
                self.tokens.get(started.id, started.updated_at)
            }
            ScimTargetAuth::Bearer => None,
        };
        let token: Zeroizing<String> = match cached {
            Some(token) => {
                self.verify_unchanged(started).await?;
                token
            }
            None => {
                let credential = match self
                    .targets
                    .decrypt_credential(started.tenant_id, started.id)
                    .await
                {
                    Ok(Some(credential)) => credential,
                    Ok(None) => return Err(Exit::dead("the target has no credential")),
                    Err(AxiamError::NotFound { .. }) => {
                        return Err(Exit::dead("target not found"));
                    }
                    Err(_) => {
                        return Err(Exit::fail("the target's credential could not be opened"));
                    }
                };
                // Before the credential is used, the target is read again.
                self.verify_unchanged(started).await?;
                match &started.auth {
                    ScimTargetAuth::Bearer => credential,
                    ScimTargetAuth::OAuth2ClientCredentials {
                        token_url,
                        client_id,
                        scope,
                    } => {
                        let fetched = fetch_access_token(
                            self.allow_private,
                            TokenRequest {
                                token_url,
                                client_id,
                                client_secret: credential.as_str(),
                                scope: scope.as_deref(),
                            },
                        )
                        .await?;
                        self.tokens.put(
                            started.id,
                            started.updated_at,
                            fetched.token.clone(),
                            fetched.lifetime,
                        );
                        fetched.token
                    }
                }
            }
        };
        let header = Zeroizing::new(format!("Bearer {}", token.as_str()));
        let mut value = HeaderValue::from_str(header.as_str())
            .map_err(|_| Exit::dead("the credential is not valid in a header"))?;
        value.set_sensitive(true);
        Ok(value)
    }

    /// A non-success status that has no meaning of its own for the request that
    /// got it, as an [`Exit`] (see the module documentation's table).
    fn reject(&self, run: &Run, status: u16) -> Exit {
        match status {
            300..=399 => {
                Exit::retry("the receiver answered with a redirect, which is not followed")
            }
            // The access token was refused: it may simply have been revoked or
            // have expired early, so the next attempt fetches a fresh one.
            401 if matches!(
                run.target.auth,
                ScimTargetAuth::OAuth2ClientCredentials { .. }
            ) =>
            {
                self.tokens.flush(run.target.id);
                Exit::retry("the receiver refused the access token (HTTP 401)")
            }
            401 | 403 => Exit::Dead(format!(
                "the receiver refused the credential (HTTP {status})"
            )),
            408 | 429 | 500..=599 => Exit::Retry(format!("the receiver answered HTTP {status}")),
            400..=499 => Exit::Dead(format!("HTTP {status}")),
            _ => Exit::Retry(format!("the receiver answered an unexpected HTTP {status}")),
        }
    }
}

impl<T, L, S, U, G> OutboundDeliverer for ScimPushDeliverer<T, L, S, U, G>
where
    T: ScimTargetRepository + 'static,
    L: ScimTargetLinkRepository + 'static,
    S: ScimTargetStateRepository + 'static,
    U: UserRepository + 'static,
    G: GroupRepository + 'static,
{
    fn kind(&self) -> OutboundKind {
        OutboundKind::ScimPush
    }

    fn deliver_attempt<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<DeliveryOutcome, OutboundError>> {
        Box::pin(self.deliver(msg))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_reference(payload: &serde_json::Value) -> Option<(ScimResourceType, Uuid)> {
    let object = payload.as_object()?;
    let resource_type = ScimResourceType::from_wire(object.get("resource_type")?.as_str()?)?;
    let axiam_id = Uuid::parse_str(object.get("axiam_id")?.as_str()?).ok()?;
    Some((resource_type, axiam_id))
}

fn collection_of(resource_type: ScimResourceType) -> &'static str {
    match resource_type {
        ScimResourceType::User => USERS,
        ScimResourceType::Group => GROUPS,
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Step<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Exit::fail("the document could not be encoded"))
}

/// `<base>/<collection>[/<id>][?filter=<filter>]`, with the id and the filter
/// percent-encoded, so that nothing a downstream (or a person) supplied can
/// change the path or the query.
fn resource_url(
    base_url: &str,
    collection: &str,
    id: Option<&str>,
    filter: Option<&str>,
) -> Step<String> {
    let invalid = || Exit::dead("the target's base URL is not valid");
    let mut url = Url::parse(base_url).map_err(|_| invalid())?;
    {
        let mut segments = url.path_segments_mut().map_err(|_| invalid())?;
        segments.pop_if_empty().push(collection);
        if let Some(id) = id {
            segments.push(id);
        }
    }
    if let Some(filter) = filter {
        url.query_pairs_mut().append_pair("filter", filter);
    }
    Ok(url.to_string())
}

/// Whether a downstream-assigned id is safe to link and to put in a path.
fn usable_downstream_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_DOWNSTREAM_ID_BYTES
        && id != "."
        && id != ".."
        && !id.chars().any(char::is_control)
}

/// The `id` of a created resource.
fn downstream_id_of(body: &[u8]) -> Step<String> {
    let unusable = || Exit::retry("the receiver's response carried no usable id");
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| unusable())?;
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(unusable)?;
    if usable_downstream_id(id) {
        Ok(id.to_owned())
    } else {
        Err(unusable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_is_two_members_and_nothing_else_is_read() {
        let id = Uuid::new_v4();
        let good = serde_json::json!({"resource_type": "user", "axiam_id": id.to_string()});
        assert_eq!(parse_reference(&good), Some((ScimResourceType::User, id)));
        for bad in [
            serde_json::json!({"resource_type": "role", "axiam_id": id.to_string()}),
            serde_json::json!({"resource_type": "user", "axiam_id": "nope"}),
            serde_json::json!({"resource_type": "user"}),
            serde_json::json!([]),
            serde_json::Value::Null,
        ] {
            assert_eq!(parse_reference(&bad), None);
        }
    }

    #[test]
    fn urls_are_built_from_the_base_with_the_id_and_filter_encoded() {
        assert_eq!(
            resource_url("https://idp.example/scim/v2", USERS, None, None).unwrap(),
            "https://idp.example/scim/v2/Users"
        );
        assert_eq!(
            resource_url("https://idp.example/scim/v2/", GROUPS, Some("a/b?c"), None).unwrap(),
            "https://idp.example/scim/v2/Groups/a%2Fb%3Fc"
        );
        let with_filter = resource_url(
            "https://idp.example/scim/v2",
            USERS,
            None,
            Some("externalId eq \"x\""),
        )
        .unwrap();
        assert!(with_filter.starts_with("https://idp.example/scim/v2/Users?filter="));
        assert!(!with_filter.contains(' ') && !with_filter.contains('"'));
        assert!(matches!(
            resource_url("not a url", USERS, None, None),
            Err(Exit::Dead(_))
        ));
    }

    #[test]
    fn a_downstream_id_that_could_redirect_a_path_is_not_linked() {
        for bad in [
            "",
            ".",
            "..",
            "a\nb",
            &"x".repeat(MAX_DOWNSTREAM_ID_BYTES + 1),
        ] {
            assert!(!usable_downstream_id(bad));
        }
        assert!(usable_downstream_id("2819c223-7f76-453a-919d-413861904646"));
        assert!(downstream_id_of(br#"{"id":"abc"}"#).is_ok());
        for bad in [&br#"{}"#[..], br#"{"id":7}"#, br#"{"id":".."}"#, b"x"] {
            assert!(matches!(downstream_id_of(bad), Err(Exit::Retry(_))));
        }
    }

    /// The deliverer's only way out is the shared no-redirect guard, with the
    /// private-network admission off. Pinned against the source of **every**
    /// outbound module so a second HTTP client cannot appear beside it.
    #[test]
    fn the_outbound_modules_use_the_no_redirect_guarded_fetch_and_nothing_else() {
        let sources = [
            include_str!("client.rs"),
            include_str!("deliverer.rs"),
            include_str!("provisioner.rs"),
            include_str!("wire.rs"),
        ];
        let production: Vec<&str> = sources
            .iter()
            .map(|source| source.split("#[cfg(test)]").next().unwrap_or(source))
            .collect();
        let calls: usize = production
            .iter()
            .map(|p| p.matches("guarded_fetch_no_redirect(").count())
            .sum();
        assert_eq!(calls, 1, "one call site, in the client's `send`");
        for p in &production {
            // `guarded_fetch(` would also match inside the names above, so
            // look for the bare call and for the capped variant.
            assert!(!p.contains(" guarded_fetch("), "the redirecting guard");
            assert!(!p.contains("guarded_fetch_with_cap("));
            for forbidden in [
                "reqwest::Client",
                "Client::new",
                "Client::builder",
                "reqwest::get",
            ] {
                assert!(!p.contains(forbidden), "{forbidden}");
            }
        }
        // The flag starts false and only the hidden test seam sets it.
        let deliverer = production[1];
        assert_eq!(deliverer.matches("allow_private: false").count(), 1);
        assert_eq!(deliverer.matches("self.allow_private = true").count(), 1);
    }
}
