//! The provisioning event source (G-6, D-57): one port the SurrealDB user and
//! group repositories call **after** a successful write, so that every writer
//! of a provisioned field (the REST API, SCIM inbound, directory JIT and sync,
//! SAML and OIDC federation JIT, erasure) is covered without touching its call
//! site.
//!
//! The port carries **references, never attributes**: a tenant and the id of a
//! user or group (or of a membership). What the downstream service provider
//! should be told is computed later, from the data as it is then, by the
//! deliverer (`axiam-scim`'s `outbound` module).
//!
//! The contract is the one [`crate::models::ssf::SessionRevocationSink`] has:
//! a sink is told after the change committed and **never fails it** — it
//! returns nothing and logs what it cannot do. An unbound [`Late`] handle is a
//! no-op, so a repository whose sink is not wired issues the queries it always
//! did.

use std::sync::Arc;

use uuid::Uuid;

use crate::models::ssf::Late;

/// A boxed, `Send` future, for the object-safe [`ProvisioningSink`].
pub type ProvisioningFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The port the user and group repositories report a committed change through.
///
/// Called from every mutating repository method that can change what a
/// downstream directory is told: user create, update (only when it touches a
/// provisioned field), delete, anonymise and the directory-account methods;
/// group create, update, delete and every membership change. Login
/// bookkeeping (failed-login counters, TOTP step, lock stamps) never calls it.
pub trait ProvisioningSink: Send + Sync {
    /// Whether the sink will do anything. A repository that has to read
    /// something extra to name a change (a group's members before the group is
    /// deleted) does so only when this is `true`.
    fn is_active(&self) -> bool {
        true
    }

    /// The user `user_id` of `tenant_id` was created, changed in a provisioned
    /// field, deleted or erased.
    fn user_changed(&self, tenant_id: Uuid, user_id: Uuid) -> ProvisioningFuture<'_, ()>;

    /// The group `group_id` of `tenant_id` was created, renamed or deleted.
    fn group_changed(&self, tenant_id: Uuid, group_id: Uuid) -> ProvisioningFuture<'_, ()>;

    /// `user_id` joined or left `group_id` (or lost the membership because the
    /// group was deleted).
    fn membership_changed(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> ProvisioningFuture<'_, ()>;
}

impl ProvisioningSink for Late<dyn ProvisioningSink> {
    fn is_active(&self) -> bool {
        self.get().is_some_and(|inner| inner.is_active())
    }

    fn user_changed(&self, tenant_id: Uuid, user_id: Uuid) -> ProvisioningFuture<'_, ()> {
        match self.get() {
            Some(inner) => inner.user_changed(tenant_id, user_id),
            None => Box::pin(async {}),
        }
    }

    fn group_changed(&self, tenant_id: Uuid, group_id: Uuid) -> ProvisioningFuture<'_, ()> {
        match self.get() {
            Some(inner) => inner.group_changed(tenant_id, group_id),
            None => Box::pin(async {}),
        }
    }

    fn membership_changed(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> ProvisioningFuture<'_, ()> {
        match self.get() {
            Some(inner) => inner.membership_changed(tenant_id, group_id, user_id),
            None => Box::pin(async {}),
        }
    }
}

/// One report a [`ProvisioningSink`] received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningEvent {
    /// [`ProvisioningSink::user_changed`].
    User {
        /// The tenant.
        tenant_id: Uuid,
        /// The user.
        user_id: Uuid,
    },
    /// [`ProvisioningSink::group_changed`].
    Group {
        /// The tenant.
        tenant_id: Uuid,
        /// The group.
        group_id: Uuid,
    },
    /// [`ProvisioningSink::membership_changed`].
    Membership {
        /// The tenant.
        tenant_id: Uuid,
        /// The group.
        group_id: Uuid,
        /// The user.
        user_id: Uuid,
    },
}

/// A sink that records what it was told, for tests of the **source** side: a
/// repository, a handler or a job that must (or must not) report a change.
///
/// **Test seam, never used by the composition root.**
#[doc(hidden)]
#[derive(Default)]
pub struct RecordingProvisioningSink {
    events: std::sync::Mutex<Vec<ProvisioningEvent>>,
}

impl RecordingProvisioningSink {
    /// A fresh recorder.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Everything reported so far, oldest first.
    #[must_use]
    pub fn events(&self) -> Vec<ProvisioningEvent> {
        self.events.lock().expect("recorder lock").clone()
    }

    /// Forget what was reported.
    pub fn clear(&self) {
        self.events.lock().expect("recorder lock").clear();
    }

    fn push(&self, event: ProvisioningEvent) {
        self.events.lock().expect("recorder lock").push(event);
    }
}

impl ProvisioningSink for RecordingProvisioningSink {
    fn user_changed(&self, tenant_id: Uuid, user_id: Uuid) -> ProvisioningFuture<'_, ()> {
        self.push(ProvisioningEvent::User { tenant_id, user_id });
        Box::pin(async {})
    }

    fn group_changed(&self, tenant_id: Uuid, group_id: Uuid) -> ProvisioningFuture<'_, ()> {
        self.push(ProvisioningEvent::Group {
            tenant_id,
            group_id,
        });
        Box::pin(async {})
    }

    fn membership_changed(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> ProvisioningFuture<'_, ()> {
        self.push(ProvisioningEvent::Membership {
            tenant_id,
            group_id,
            user_id,
        });
        Box::pin(async {})
    }
}

/// The shared handle the composition root binds once and hands to every
/// repository: see [`ProvisioningSink`] and [`Late`].
pub type SharedProvisioningSink = Arc<Late<dyn ProvisioningSink>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unbound_handle_is_inactive_and_does_nothing() {
        let late: Late<dyn ProvisioningSink> = Late::default();
        assert!(!late.is_active());
        late.user_changed(Uuid::nil(), Uuid::nil()).await;
        late.group_changed(Uuid::nil(), Uuid::nil()).await;
        late.membership_changed(Uuid::nil(), Uuid::nil(), Uuid::nil())
            .await;
    }

    #[tokio::test]
    async fn a_bound_handle_forwards_every_call() {
        let late: Late<dyn ProvisioningSink> = Late::default();
        let recording = RecordingProvisioningSink::new();
        assert!(late.bind(recording.clone()));
        assert!(late.is_active());
        let (t, g, u) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        late.user_changed(t, u).await;
        late.group_changed(t, g).await;
        late.membership_changed(t, g, u).await;
        assert_eq!(
            recording.events(),
            vec![
                ProvisioningEvent::User {
                    tenant_id: t,
                    user_id: u
                },
                ProvisioningEvent::Group {
                    tenant_id: t,
                    group_id: g
                },
                ProvisioningEvent::Membership {
                    tenant_id: t,
                    group_id: g,
                    user_id: u
                },
            ]
        );
    }

    #[tokio::test]
    async fn the_first_binding_stays() {
        let late: Late<dyn ProvisioningSink> = Late::default();
        assert!(late.bind(RecordingProvisioningSink::new()));
        assert!(!late.bind(RecordingProvisioningSink::new()));
    }
}
