//! Applying the group-mapping table to AXIAM's memberships (G-3, T23.3.4,
//! D-30): the half of group mapping that writes.
//!
//! [`RepositoryGroupMapper`] is the [`DirectoryGroupMapper`] the composition
//! root hands to the sign-in path, and the **same function** the sync job
//! (T23.3.5) calls per user: [`DirectoryGroupMapper::apply_for_user`].
//!
//! # What it does
//!
//! 1. Asks the directory which AXIAM groups the user's directory groups map to
//!    ([`RepositoryDirectoryAuthenticator::resolve_mapped_groups`]) — the
//!    *backed* set.
//! 2. Makes the user's **directory-sourced** memberships equal to it
//!    ([`apply_backed_groups`]): every directory-sourced edge no longer backed
//!    is removed, every backed group the user is not yet in is added with
//!    `source = directory`.
//!
//! # What it never does
//!
//! * **Touch a manual membership.** Only edges marked `source = directory` are
//!   ever removed. A backed group the user already belongs to by hand is
//!   reported ([`GroupMappingOutcome::left_manual`]) and left exactly as it is:
//!   no second edge, no change of owner — so the directory can never take a
//!   membership away that an administrator gave.
//! * **Grant by name.** Which AXIAM group a directory group reaches is the
//!   mapping table's say alone (see [`crate::groups::mapped_group_ids`]).
//! * **Act on a partial answer.** A lookup that fails or hits the cap is an
//!   error and **changes nothing**: the memberships stay as they were and the
//!   caller refuses the sign-in.
//!
//! # Order, and why a failure partway is safe
//!
//! Removals first, additions second. The two are independent writes, and the
//! function can stop between them (or midway through either): stopping after
//! the removals leaves the user with *less* than the directory backs, never
//! more. It is idempotent, so the next sign-in finishes the work.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use axiam_core::error::AxiamError;
use axiam_core::models::directory::{
    DirectoryAuthError, DirectoryFuture, DirectoryGroupMapper, GroupMappingOutcome,
};
use axiam_core::models::group::DirectoryMembershipWrite;
use axiam_core::repository::{DirectoryConfigRepository, GroupRepository};
use std::sync::Arc;
use uuid::Uuid;

use crate::authenticator::RepositoryDirectoryAuthenticator;

/// Which memberships to write and which to remove, given what the directory
/// backs and what the directory already owns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MembershipPlan {
    /// Backed groups the user holds no directory-sourced membership of. Each
    /// may turn out to be a manual membership already; the repository decides.
    pub add: Vec<Uuid>,
    /// Directory-sourced memberships the directory no longer backs.
    pub remove: Vec<Uuid>,
}

/// The pure part: `backed` is what the mapping says the user should hold;
/// `directory_owned` is the directory-sourced memberships the user holds now.
///
/// Both lists are sorted, so the plan is deterministic.
#[must_use]
pub fn plan_memberships(backed: &BTreeSet<Uuid>, directory_owned: &[Uuid]) -> MembershipPlan {
    let owned: BTreeSet<Uuid> = directory_owned.iter().copied().collect();
    MembershipPlan {
        add: backed.difference(&owned).copied().collect(),
        remove: owned.difference(backed).copied().collect(),
    }
}

/// Make `user_id`'s directory-sourced memberships equal `backed`.
///
/// See the module documentation for the rules. `outcome.directory_groups_*`
/// are left at their defaults for the caller to fill; everything else is what
/// this call did.
///
/// A backed group that no longer exists (a mapping row outliving its group) is
/// skipped with a warning: it grants nothing, and one stale row must not lock
/// every member of its directory group out.
///
/// # Errors
///
/// [`DirectoryAuthError::Unavailable`] when a repository call fails. Memberships
/// removed before the failure stay removed (see the module documentation).
pub async fn apply_backed_groups<G: GroupRepository>(
    groups: &G,
    tenant_id: Uuid,
    user_id: Uuid,
    backed: &BTreeSet<Uuid>,
) -> Result<GroupMappingOutcome, DirectoryAuthError> {
    let unavailable = |stage: &'static str, error: AxiamError| {
        tracing::error!(
            target: "axiam::directory",
            %tenant_id,
            %user_id,
            stage,
            %error,
            "applying the directory group mapping failed"
        );
        DirectoryAuthError::Unavailable
    };

    let owned = groups
        .get_user_directory_group_ids(tenant_id, user_id)
        .await
        .map_err(|e| unavailable("read_directory_memberships", e))?;
    let plan = plan_memberships(backed, &owned);
    let mut outcome = GroupMappingOutcome::default();

    // Removals first: stopping partway then leaves less access, never more.
    for group_id in plan.remove {
        let removed = groups
            .remove_directory_member(tenant_id, user_id, group_id)
            .await
            .map_err(|e| unavailable("remove_membership", e))?;
        if removed {
            outcome.removed.push(group_id);
        }
    }

    for group_id in plan.add {
        match groups
            .add_directory_member(tenant_id, user_id, group_id)
            .await
        {
            Ok(DirectoryMembershipWrite::Created) => outcome.added.push(group_id),
            // Another sign-in of this user wrote it a moment ago.
            Ok(DirectoryMembershipWrite::AlreadyDirectory) => {}
            Ok(DirectoryMembershipWrite::AlreadyManual) => outcome.left_manual.push(group_id),
            Err(AxiamError::NotFound { ref entity, .. }) if entity == "group" => {
                tracing::warn!(
                    target: "axiam::directory",
                    %tenant_id,
                    %group_id,
                    "a group-mapping row names a group that no longer exists; skipped"
                );
            }
            Err(error) => return Err(unavailable("add_membership", error)),
        }
    }
    Ok(outcome)
}

/// What the mapper calls after it has changed a user's memberships:
/// `(tenant_id, user_id)`. The composition root sets it to flush the
/// authorization engine's decision cache for that subject, exactly as the
/// group-membership routes do — a membership the directory removed must not
/// leave a cached *allow* behind.
pub type MembershipChangeHook =
    Arc<dyn Fn(Uuid, Uuid) -> DirectoryFuture<'static, ()> + Send + Sync>;

/// A hook that may be set **after** the mapper is built.
///
/// The composition root builds the sign-in path (and with it the mapper) before
/// the authorization engine and its decision cache exist, so the hook cannot be
/// handed over at construction. Clones share one slot; it can be set once, and
/// an unset slot does nothing (a deployment without a decision cache has
/// nothing to flush).
#[derive(Clone, Default)]
pub struct MembershipChangeSlot {
    hook: Arc<OnceLock<MembershipChangeHook>>,
}

impl MembershipChangeSlot {
    /// An empty slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hook. `false` when one was already set (the first stays).
    pub fn set(&self, hook: MembershipChangeHook) -> bool {
        self.hook.set(hook).is_ok()
    }

    async fn notify(&self, tenant_id: Uuid, user_id: Uuid) {
        if let Some(hook) = self.hook.get() {
            hook(tenant_id, user_id).await;
        }
    }
}

/// The production [`DirectoryGroupMapper`]: the directory authenticator (which
/// owns the configuration, the bind secret and the pooled client) and a group
/// repository.
pub struct RepositoryGroupMapper<R, G> {
    authenticator: Arc<RepositoryDirectoryAuthenticator<R>>,
    groups: G,
    on_change: MembershipChangeSlot,
}

impl<R, G> RepositoryGroupMapper<R, G> {
    /// A mapper over `authenticator` — share the one the sign-in path uses, so
    /// both read the same configuration and draw on the same bounded pool — and
    /// `groups`.
    pub fn new(authenticator: Arc<RepositoryDirectoryAuthenticator<R>>, groups: G) -> Self {
        Self {
            authenticator,
            groups,
            on_change: MembershipChangeSlot::new(),
        }
    }

    /// Call the slot's hook whenever a user's memberships change (see
    /// [`MembershipChangeHook`]). The slot is shared with the caller, who sets
    /// it when the thing it flushes exists.
    #[must_use]
    pub fn with_change_slot(mut self, slot: MembershipChangeSlot) -> Self {
        self.on_change = slot;
        self
    }
}

impl<R, G> DirectoryGroupMapper for RepositoryGroupMapper<R, G>
where
    R: DirectoryConfigRepository,
    G: GroupRepository,
{
    fn apply_for_user<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        user_dn: &'a str,
    ) -> DirectoryFuture<'a, Result<GroupMappingOutcome, DirectoryAuthError>> {
        Box::pin(async move {
            let mapped = self
                .authenticator
                .resolve_mapped_groups(tenant_id, user_dn)
                .await?;
            let applied =
                apply_backed_groups(&self.groups, tenant_id, user_id, &mapped.group_ids).await;
            // After the writes and before the caller issues anything. Also on a
            // failure: removals made before it already narrowed the user's
            // access, and a cached allow must not outlive them.
            if applied.as_ref().map_or(true, GroupMappingOutcome::changed) {
                self.on_change.notify(tenant_id, user_id).await;
            }
            let mut outcome = applied?;
            outcome.directory_groups_resolved = mapped.directory_groups_resolved;
            outcome.directory_groups_mapped = mapped.group_ids.len();
            Ok(outcome)
        })
    }

    /// The sync job's half (T23.3.5, D-31): an account whose entry has vanished
    /// or been disabled is backed by **no** group, so the backed set is empty
    /// and the directory is not asked. Same function, same rules, same decision
    /// cache flush as [`Self::apply_for_user`].
    fn remove_directory_memberships<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> DirectoryFuture<'a, Result<GroupMappingOutcome, DirectoryAuthError>> {
        Box::pin(async move {
            let applied =
                apply_backed_groups(&self.groups, tenant_id, user_id, &BTreeSet::new()).await;
            if applied.as_ref().map_or(true, GroupMappingOutcome::changed) {
                self.on_change.notify(tenant_id, user_id).await;
            }
            applied
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::new_v4()).collect()
    }

    #[test]
    fn the_plan_adds_what_is_missing_and_removes_what_is_no_longer_backed() {
        let [a, b, c] = ids(3)[..] else {
            unreachable!()
        };
        let backed = BTreeSet::from([a, b]);
        let plan = plan_memberships(&backed, &[b, c]);
        assert_eq!(plan.add, vec![a]);
        assert_eq!(plan.remove, vec![c]);
    }

    #[test]
    fn an_unchanged_directory_plans_nothing() {
        let [a, b] = ids(2)[..] else { unreachable!() };
        let plan = plan_memberships(&BTreeSet::from([a, b]), &[b, a]);
        assert_eq!(plan, MembershipPlan::default());
    }

    #[test]
    fn an_empty_backed_set_removes_every_directory_membership() {
        let owned = ids(3);
        let plan = plan_memberships(&BTreeSet::new(), &owned);
        assert!(plan.add.is_empty());
        assert_eq!(plan.remove.len(), 3);
    }

    #[test]
    fn no_directory_membership_and_a_backed_set_adds_all() {
        let backed: BTreeSet<Uuid> = ids(3).into_iter().collect();
        let plan = plan_memberships(&backed, &[]);
        assert_eq!(plan.add.len(), 3);
        assert!(plan.remove.is_empty());
    }
}
