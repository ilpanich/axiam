//! Shared harness of the outbound SCIM tests (G-6, T23.6.2): the loopback
//! service provider, an in-process dispatcher, and a world wired the way
//! `axiam-server` wires it — the repositories report to one `Late` sink bound to
//! a [`ScimProvisioner`], which enqueues references on a queue the tests drain
//! through the real [`ScimPushDeliverer`].
//!
//! No credential literal appears anywhere: the sealing key and every credential
//! are generated at run time, and no assertion message formats one.

#![allow(dead_code)]

pub mod scim_server;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

use axiam_core::models::group::CreateGroup;
use axiam_core::models::scim_target::{
    DeprovisionPolicy, NewScimTarget, ScimTarget, ScimTargetAuth, ScimTargetScope, UserNameSource,
};
use axiam_core::models::ssf::Late;
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundMessage,
    OutboundPublisher,
};
use axiam_core::provisioning::ProvisioningSink;
use axiam_core::repository::{GroupRepository, ScimTargetRepository, UserRepository};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealScimTargetLinkRepository, SurrealScimTargetRepository,
    SurrealScimTargetStateRepository, SurrealUserRepository,
};
use axiam_scim::outbound::{ScimProvisioner, ScimPushDeliverer};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use scim_server::TestScimServer;

pub type Deliverer = ScimPushDeliverer<
    SurrealScimTargetRepository<Db>,
    SurrealScimTargetLinkRepository<Db>,
    SurrealScimTargetStateRepository<Db>,
    SurrealUserRepository<Db>,
    SurrealGroupRepository<Db>,
>;

/// A sealing key generated once per test binary, never written down.
pub fn sealing() -> [u8; 32] {
    static SEALING: OnceLock<[u8; 32]> = OnceLock::new();
    *SEALING.get_or_init(|| {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        out
    })
}

pub fn generated(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

/// The in-process dispatcher: `enqueue` queues; [`Queue::drain`] makes one
/// attempt per queued message (messages the deliverer enqueues meanwhile are
/// attempted too) and returns what the deliverer decided.
#[derive(Default)]
pub struct Queue {
    pending: Mutex<VecDeque<OutboundMessage>>,
    all: Mutex<Vec<OutboundMessage>>,
}

impl Queue {
    /// Every message ever enqueued, oldest first.
    pub fn all(&self) -> Vec<OutboundMessage> {
        self.all.lock().unwrap().clone()
    }

    /// Forget what was enqueued (queued and history).
    pub fn clear(&self) {
        self.pending.lock().unwrap().clear();
        self.all.lock().unwrap().clear();
    }

    pub fn pending_len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Attempt every queued message once, in order.
    pub async fn drain(
        &self,
        deliverer: &dyn OutboundDeliverer,
    ) -> Vec<(OutboundMessage, Result<DeliveryOutcome, OutboundError>)> {
        let mut results = Vec::new();
        loop {
            let next = self.pending.lock().unwrap().pop_front();
            let Some(message) = next else {
                return results;
            };
            let outcome = deliverer.deliver_attempt(&message).await;
            results.push((message, outcome));
        }
    }
}

impl OutboundPublisher for Queue {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async move {
            self.pending.lock().unwrap().push_back(msg.clone());
            self.all.lock().unwrap().push(msg.clone());
            Ok(())
        })
    }
}

/// The outcome, unwrapped: a deliverer that errors instead of classifying is a
/// test failure here.
pub fn outcome(result: Result<DeliveryOutcome, OutboundError>) -> DeliveryOutcome {
    result.unwrap_or_else(|_| DeliveryOutcome::Retry {
        reason: "the deliverer failed before it could classify".into(),
    })
}

pub struct World {
    pub db: Surreal<Db>,
    pub tenant_id: Uuid,
    pub users: SurrealUserRepository<Db>,
    pub groups: SurrealGroupRepository<Db>,
    pub targets: SurrealScimTargetRepository<Db>,
    pub links: SurrealScimTargetLinkRepository<Db>,
    pub states: SurrealScimTargetStateRepository<Db>,
    pub queue: Arc<Queue>,
    pub server: TestScimServer,
    /// The one deliverer of this world, as in a deployment: it holds the cache
    /// of client-credentials access tokens, so it must outlive one drain.
    pub deliverer: Deliverer,
    /// Every credential value this world registered, so that a test can assert
    /// that none of them reaches a reason, a state row or a message.
    pub credentials: Mutex<Vec<String>>,
}

impl World {
    pub async fn new() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let queue = Arc::new(Queue::default());
        let targets = SurrealScimTargetRepository::new(db.clone(), Some(sealing()));
        // The wiring of `axiam-server`: one shared late-bound sink, bound to the
        // provisioner over the target registry and the dispatcher.
        let sink: Arc<Late<dyn ProvisioningSink>> = Arc::default();
        let users = SurrealUserRepository::new(db.clone()).with_provisioning_sink(sink.clone());
        let groups = SurrealGroupRepository::new(db.clone()).with_provisioning_sink(sink.clone());
        assert!(sink.bind(Arc::new(ScimProvisioner::new(
            targets.clone(),
            queue.clone()
        ))));
        let server = TestScimServer::start();
        let links = SurrealScimTargetLinkRepository::new(db.clone());
        let states = SurrealScimTargetStateRepository::new(db.clone());
        let deliverer = ScimPushDeliverer::new(
            targets.clone(),
            links.clone(),
            states.clone(),
            users.clone(),
            groups.clone(),
            queue.clone(),
        )
        .admitting_private_networks_for_tests();
        Self {
            links,
            states,
            tenant_id: Uuid::new_v4(),
            db,
            users,
            groups,
            targets,
            queue,
            server,
            deliverer,
            credentials: Mutex::default(),
        }
    }

    /// The deliverer exactly as `axiam-server` builds it: loopback is refused.
    pub fn production_deliverer(&self) -> Deliverer {
        ScimPushDeliverer::new(
            self.targets.clone(),
            self.links.clone(),
            self.states.clone(),
            self.users.clone(),
            self.groups.clone(),
            self.queue.clone(),
        )
    }

    /// Register a bearer target pointing at the loopback server. The server is
    /// told to accept the (generated) credential and to require it.
    pub async fn add_target(&self, tweak: impl FnOnce(&mut NewScimTarget)) -> ScimTarget {
        let credential = Zeroizing::new(generated("cred"));
        self.server.require_auth();
        let mut input = NewScimTarget {
            tenant_id: self.tenant_id,
            name: "Downstream".into(),
            base_url: self.server.base_url(),
            enabled: true,
            auth: ScimTargetAuth::Bearer,
            credential,
            scope: ScimTargetScope::AllUsers,
            push_groups: false,
            user_name_from: UserNameSource::Username,
            deprovision: DeprovisionPolicy::Deactivate,
        };
        tweak(&mut input);
        // A bearer target's credential is the token the server accepts; a
        // client-credentials target gets its access tokens from the token
        // endpoint, and its client secret is accepted nowhere as a bearer.
        if matches!(input.auth, ScimTargetAuth::Bearer) {
            self.server.accept_token(&input.credential);
        }
        self.credentials
            .lock()
            .unwrap()
            .push(input.credential.to_string());
        self.targets.create(input).await.unwrap()
    }

    /// An active user, created through the reporting repository.
    pub async fn active_user(&self, name: &str) -> User {
        let user = self
            .users
            .create(CreateUser {
                tenant_id: self.tenant_id,
                username: name.into(),
                email: format!("{name}@example.com"),
                password: axiam_test_support::test_password(),
                metadata: Some(serde_json::json!({
                    "scim": {"givenName": "Given", "familyName": "Family", "formatted": "Given Family"}
                })),
            })
            .await
            .unwrap();
        self.set_status(user.id, UserStatus::Active).await
    }

    pub async fn set_status(&self, user_id: Uuid, status: UserStatus) -> User {
        self.users
            .update(
                self.tenant_id,
                user_id,
                UpdateUser {
                    status: Some(status),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }

    pub async fn group(&self, name: &str) -> Uuid {
        self.groups
            .create(CreateGroup {
                tenant_id: self.tenant_id,
                name: name.into(),
                description: String::new(),
                metadata: None,
            })
            .await
            .unwrap()
            .id
    }

    /// Drain the queue through the loopback deliverer; every outcome, in order.
    pub async fn sync(&self) -> Vec<DeliveryOutcome> {
        self.queue
            .drain(&self.deliverer)
            .await
            .into_iter()
            .map(|(_, result)| outcome(result))
            .collect()
    }
}

/// Whether every outcome is a delivery.
pub fn all_delivered(outcomes: &[DeliveryOutcome]) -> bool {
    outcomes
        .iter()
        .all(|o| matches!(o, DeliveryOutcome::Delivered { .. }))
}

/// The one outcome of a drain that made exactly one attempt.
pub fn only(mut outcomes: Vec<DeliveryOutcome>) -> DeliveryOutcome {
    assert_eq!(outcomes.len(), 1, "exactly one attempt was expected");
    outcomes.remove(0)
}
