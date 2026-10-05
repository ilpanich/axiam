//! The minimal profile's boot guards (T23.8.1, G-8, D-59).
//!
//! `AXIAM__AMQP__ENABLED=false` runs AXIAM with SurrealDB only. That is safe
//! only under three conditions the process cannot take on trust, so each is
//! checked at boot and refused with an error that names the profile and the
//! fix:
//!
//! 1. **No broadcast.** `decision_cache_broadcast_enabled = true` asks for
//!    cross-replica cache invalidation over AMQP; there is no transport to carry
//!    it. ([`refuse_broadcast`])
//! 2. **No enabled reactor registration** in the datastore, in any tenant. A
//!    `fail_closed` reactor with no transport would deny logins in every tenant
//!    that registered one. ([`refuse_enabled_reactors`])
//! 3. **No second live instance.** Without the broker nothing tells replicas
//!    about each other's mutations, so the profile is single-instance by
//!    definition — and a replica count is the orchestrator's knowledge, not the
//!    process's. A **singleton lease** row in the shared datastore is the only
//!    thing that can tell ([`acquire_lease`], [`spawn_lease_renewal`]); an
//!    instance that loses it exits rather than run beside another — through
//!    the orderly stop, so that the audit rows it still holds are written
//!    first ([`signal_on_lease_lost`], [`spawn_lease_loss_stop`]; T23.8.2,
//!    P23W5-A1), with a backstop if that stop does not finish in time.
//!
//! Every constant is a field of [`LeaseTiming`] so the logic is tested with
//! short values; [`LeaseTiming::PRODUCTION`] is what the server uses.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use axiam_core::repository::ReactorRepository;
use axiam_db::{LeaseClaim, SurrealMinimalProfileLeaseRepository};
use chrono::Utc;
use surrealdb::Connection;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// The switch every refusal names, so the operator finds the setting.
const SWITCH: &str = "AXIAM__AMQP__ENABLED=false";

/// Timing of the singleton lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseTiming {
    /// How long a claim or renewal keeps the lease alive.
    pub ttl: Duration,
    /// How often the holder renews. Well under `ttl`, so one or two missed
    /// renewals do not lose the lease.
    pub renew_every: Duration,
    /// How long a boot that finds another instance's live lease waits for it to
    /// expire before refusing — a rolling update's old pod stops renewing when
    /// it stops, and its lease expires within `ttl`.
    pub boot_wait: Duration,
    /// How often that wait re-tries the claim.
    pub boot_poll: Duration,
    /// How long an instance that lost the lease may take to stop in order —
    /// stop accepting, finish what is in flight, write its queued audit rows —
    /// before the backstop ends the process anyway. It runs beside the new
    /// holder for that long at most, accepting no new connection.
    pub lost_stop_deadline: Duration,
}

impl LeaseTiming {
    /// TTL 30 s, renewed every 10 s, a boot waits up to 45 s (D-59); a lost
    /// lease stops the instance within 15 s (T23.8.2) — the REST listener's
    /// idle keep-alive (5 s) and the audit drain's bound (5 s) fit inside it.
    pub const PRODUCTION: Self = Self {
        ttl: Duration::from_secs(30),
        renew_every: Duration::from_secs(10),
        boot_wait: Duration::from_secs(45),
        boot_poll: Duration::from_secs(1),
        lost_stop_deadline: Duration::from_secs(15),
    };

    fn ttl_chrono(&self) -> chrono::Duration {
        chrono::Duration::from_std(self.ttl).unwrap_or_else(|_| chrono::Duration::seconds(30))
    }
}

impl Default for LeaseTiming {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// Why the minimal profile refuses to boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileRefusal {
    /// `decision_cache_broadcast_enabled = true`.
    BroadcastEnabled,
    /// This many reactor registrations are enabled, across all tenants.
    EnabledReactors(u64),
    /// Another instance holds a live lease and did not release it in time.
    SecondInstance {
        /// The other instance's id.
        holder: String,
        /// When its lease expires unless renewed.
        expires_at: chrono::DateTime<Utc>,
    },
    /// The datastore could not be asked (the lease or the registration count).
    Datastore(String),
}

impl fmt::Display for ProfileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileRefusal::BroadcastEnabled => write!(
                f,
                "{SWITCH} is set together with the decision-cache broadcast \
                 (AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true), which fans cache \
                 invalidations out to other replicas over AMQP. The minimal profile has no \
                 broker and is single-instance, so there is nothing to broadcast to. Unset \
                 the broadcast, or run the full profile (AXIAM__AMQP__ENABLED=true)."
            ),
            ProfileRefusal::EnabledReactors(count) => write!(
                f,
                "{SWITCH} (the minimal profile has no reactor transport) but the datastore \
                 holds {count} enabled reactor registration(s). A fail_closed reactor with no \
                 transport denies login.post_auth, user.pre_create, user.pre_update and \
                 grant.pre_assign in every tenant that registered one. Disable or delete those \
                 registrations (PUT /api/v1/reactors/{{id}} with enabled: false) and start \
                 again, or run the full profile (AXIAM__AMQP__ENABLED=true)."
            ),
            ProfileRefusal::SecondInstance { holder, expires_at } => write!(
                f,
                "{SWITCH} (the minimal profile is single-instance) but another instance \
                 ({holder}) holds the datastore lease until {expires_at} and did not release \
                 it while this one waited. Stop the other instance, or run the full profile \
                 (AXIAM__AMQP__ENABLED=true) with a broker to scale beyond one."
            ),
            ProfileRefusal::Datastore(reason) => write!(
                f,
                "{SWITCH}: the minimal profile's start-up checks could not read the \
                 datastore: {reason}"
            ),
        }
    }
}

impl std::error::Error for ProfileRefusal {}

/// Refuse the broadcast: it has no transport in the minimal profile.
pub fn refuse_broadcast(broadcast_enabled: bool) -> Result<(), ProfileRefusal> {
    if broadcast_enabled {
        Err(ProfileRefusal::BroadcastEnabled)
    } else {
        Ok(())
    }
}

/// Refuse while any reactor registration is enabled, in any tenant.
pub async fn refuse_enabled_reactors<R: ReactorRepository>(
    reactors: &R,
) -> Result<(), ProfileRefusal> {
    match reactors.count_enabled().await {
        Ok(0) => Ok(()),
        Ok(count) => Err(ProfileRefusal::EnabledReactors(count)),
        Err(e) => Err(ProfileRefusal::Datastore(e.to_string())),
    }
}

/// Claim the singleton lease for `instance_id`, waiting up to
/// [`LeaseTiming::boot_wait`] for another instance's live lease to expire.
pub async fn acquire_lease<C: Connection>(
    leases: &SurrealMinimalProfileLeaseRepository<C>,
    instance_id: &str,
    timing: LeaseTiming,
) -> Result<(), ProfileRefusal> {
    let started = tokio::time::Instant::now();
    let mut warned = false;
    loop {
        match leases
            .claim(instance_id, Utc::now(), timing.ttl_chrono())
            .await
        {
            Ok(LeaseClaim::Acquired) => return Ok(()),
            Ok(LeaseClaim::Held { holder, expires_at }) => {
                let waited = started.elapsed();
                if waited >= timing.boot_wait {
                    return Err(ProfileRefusal::SecondInstance { holder, expires_at });
                }
                if !warned {
                    // Once per boot, not once per poll.
                    warn!(
                        %holder,
                        %expires_at,
                        wait_secs = timing.boot_wait.as_secs_f64(),
                        "another instance holds the minimal-profile lease; waiting for it to \
                         expire (a rolling update's old instance stops renewing when it stops)"
                    );
                    warned = true;
                }
                tokio::time::sleep(timing.boot_poll.min(timing.boot_wait - waited)).await;
            }
            Err(e) => return Err(ProfileRefusal::Datastore(e.to_string())),
        }
    }
}

/// A reaction to a lost lease. [`spawn_lease_renewal`] calls one when its
/// renewal finds the lease taken; the composition root passes
/// [`signal_on_lease_lost`], and keeps [`exit_on_lease_lost`] as the backstop
/// of [`spawn_lease_loss_stop`].
pub type OnLeaseLost = Arc<dyn Fn() + Send + Sync>;

/// The backstop: exit the process non-zero at once (the orchestrator restarts
/// the instance, which then waits for the other to go).
///
/// Until T23.8.2 this was the reaction itself, called from the renewal task:
/// the process ended wherever it was, and with it every audit row the
/// middleware still had queued, a request between its write and its audit row,
/// and a GDPR purge between the erasure and `gdpr.user_pseudonymized`
/// (P23W5-A1). It now runs only if the orderly stop has not finished within
/// [`LeaseTiming::lost_stop_deadline`].
pub fn exit_on_lease_lost() -> OnLeaseLost {
    Arc::new(|| std::process::exit(1))
}

/// The reaction the composition root gives the renewal task: raise `lost`.
/// Nothing stops here; [`spawn_lease_loss_stop`] waits on the flag.
pub fn signal_on_lease_lost(lost: watch::Sender<bool>) -> OnLeaseLost {
    Arc::new(move || {
        lost.send_replace(true);
    })
}

/// Once `lost` is raised: log it, call `stop` (the composition root's orderly
/// stop: the REST listener stops accepting and finishes what is in flight, the
/// teardown after it drains the audit queue and the cleanup task, and `serve`
/// returns an error, so the process exits non-zero), and, if the process is
/// still here `deadline` later, run `backstop`. The composition root aborts the
/// returned task when its teardown has finished, which disarms the backstop. A
/// dropped `lost` sender without the flag raised ends the task quietly.
pub fn spawn_lease_loss_stop(
    mut lost: watch::Receiver<bool>,
    stop: impl FnOnce() + Send + 'static,
    deadline: Duration,
    backstop: OnLeaseLost,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if lost.wait_for(|lost| *lost).await.is_err() {
            return;
        }
        error!(
            deadline_secs = deadline.as_secs_f64(),
            "the minimal-profile lease is lost — stopping in order (no new connections, \
             in-flight work finished, queued audit rows written) and then exiting non-zero"
        );
        stop();
        tokio::time::sleep(deadline).await;
        error!(
            "the orderly stop after a lost minimal-profile lease did not finish in time — \
             exiting now"
        );
        backstop();
    })
}

/// Renew the lease every [`LeaseTiming::renew_every`]. When a renewal reports
/// the lease is no longer this instance's, log once at ERROR and call
/// `on_lost`; the task then ends. A datastore error is logged and retried — the
/// instance cannot serve without the datastore either, and the next successful
/// renewal tells it whether it still holds the lease.
pub fn spawn_lease_renewal<C: Connection>(
    leases: SurrealMinimalProfileLeaseRepository<C>,
    instance_id: String,
    timing: LeaseTiming,
    on_lost: OnLeaseLost,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(timing.renew_every);
        ticker.tick().await; // the first tick fires at once: the claim just renewed it
        let mut failing = false;
        loop {
            ticker.tick().await;
            match leases
                .renew(&instance_id, Utc::now(), timing.ttl_chrono())
                .await
            {
                Ok(true) => {
                    if failing {
                        info!("minimal-profile lease renewal recovered");
                        failing = false;
                    }
                }
                Ok(false) => {
                    error!(
                        %instance_id,
                        "the minimal-profile lease was taken by another instance — this instance \
                         is no longer the only one and exits rather than run beside it \
                         ({SWITCH} is single-instance by definition)"
                    );
                    on_lost();
                    return;
                }
                Err(e) => {
                    if !failing {
                        warn!(error = %e, "minimal-profile lease renewal failed; retrying");
                        failing = true;
                    }
                }
            }
        }
    })
}

/// Everything the minimal profile checks at boot, in order: the broadcast
/// switch, the reactor registrations, then the lease. On success the lease is
/// held and its renewal task is returned.
pub async fn enforce_minimal_profile<C, R>(
    broadcast_enabled: bool,
    reactors: &R,
    leases: SurrealMinimalProfileLeaseRepository<C>,
    instance_id: &str,
    timing: LeaseTiming,
    on_lost: OnLeaseLost,
) -> Result<JoinHandle<()>, ProfileRefusal>
where
    C: Connection,
    R: ReactorRepository,
{
    refuse_broadcast(broadcast_enabled)?;
    refuse_enabled_reactors(reactors).await?;
    acquire_lease(&leases, instance_id, timing).await?;
    info!(
        %instance_id,
        ttl_secs = timing.ttl.as_secs_f64(),
        renew_secs = timing.renew_every.as_secs_f64(),
        "minimal profile (AXIAM__AMQP__ENABLED=false): instance lease held"
    );
    Ok(spawn_lease_renewal(
        leases,
        instance_id.to_owned(),
        timing,
        on_lost,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::reactor::{CreateReactor, ReactorMode};
    use axiam_db::SurrealReactorRepository;
    use std::sync::atomic::{AtomicBool, Ordering};
    use surrealdb::Surreal;
    use surrealdb::engine::local::{Db, Mem};
    use uuid::Uuid;

    /// Production-shaped, scaled down by 100: TTL 300 ms, renew 100 ms, a boot
    /// waits up to 450 ms.
    const FAST: LeaseTiming = LeaseTiming {
        ttl: Duration::from_millis(300),
        renew_every: Duration::from_millis(100),
        boot_wait: Duration::from_millis(450),
        boot_poll: Duration::from_millis(20),
        lost_stop_deadline: Duration::from_millis(150),
    };

    async fn db() -> Surreal<Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        db
    }

    fn lost_flag() -> (OnLeaseLost, Arc<AtomicBool>) {
        let flag = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flag);
        (Arc::new(move || f.store(true, Ordering::SeqCst)), flag)
    }

    #[test]
    fn production_timing_is_the_pinned_30_10_45() {
        let t = LeaseTiming::PRODUCTION;
        assert_eq!(t.ttl, Duration::from_secs(30));
        assert_eq!(t.renew_every, Duration::from_secs(10));
        assert_eq!(t.boot_wait, Duration::from_secs(45));
        assert_eq!(t.lost_stop_deadline, Duration::from_secs(15));
        assert_eq!(LeaseTiming::default(), t);
    }

    // ---- a lost lease stops the instance in order (T23.8.2, P23W5-A1) ----

    fn counter() -> (Arc<std::sync::atomic::AtomicU32>, OnLeaseLost) {
        let n = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let m = Arc::clone(&n);
        (
            n,
            Arc::new(move || {
                m.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    #[tokio::test]
    async fn the_renewal_reaction_only_raises_the_flag() {
        let (tx, rx) = watch::channel(false);
        let react = signal_on_lease_lost(tx);
        assert!(!*rx.borrow());
        react();
        assert!(*rx.borrow(), "the lost-lease flag is raised");
    }

    #[tokio::test]
    async fn a_lost_lease_starts_the_orderly_stop_at_once_and_the_backstop_only_after_the_deadline()
    {
        let (tx, rx) = watch::channel(false);
        let (stops, stop) = counter();
        let (backstops, backstop) = counter();
        let task = spawn_lease_loss_stop(rx, move || stop(), FAST.lost_stop_deadline, backstop);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            stops.load(Ordering::SeqCst),
            0,
            "nothing while the lease is held"
        );

        tx.send_replace(true);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            stops.load(Ordering::SeqCst),
            1,
            "the orderly stop starts at once"
        );
        assert_eq!(
            backstops.load(Ordering::SeqCst),
            0,
            "the backstop waits for the deadline"
        );

        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the task ends after the backstop")
            .unwrap();
        assert_eq!(
            backstops.load(Ordering::SeqCst),
            1,
            "an orderly stop that overruns ends in the backstop"
        );
    }

    #[tokio::test]
    async fn an_orderly_stop_that_finishes_in_time_disarms_the_backstop() {
        let (tx, rx) = watch::channel(false);
        let (_, stop) = counter();
        let (backstops, backstop) = counter();
        let task = spawn_lease_loss_stop(rx, move || stop(), FAST.lost_stop_deadline, backstop);
        tx.send_replace(true);
        tokio::time::sleep(Duration::from_millis(20)).await;
        // The composition root's teardown finished: it aborts the task.
        task.abort();
        tokio::time::sleep(FAST.lost_stop_deadline * 2).await;
        assert_eq!(backstops.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_flag_raised_before_the_watch_starts_still_stops() {
        let (tx, rx) = watch::channel(false);
        tx.send_replace(true);
        drop(tx); // the renewal task ended after raising it
        let (stops, stop) = counter();
        let (_, backstop) = counter();
        let task = spawn_lease_loss_stop(rx, move || stop(), Duration::from_secs(60), backstop);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn a_lease_never_lost_never_stops() {
        let (tx, rx) = watch::channel(false);
        let (stops, stop) = counter();
        let (backstops, backstop) = counter();
        let task = spawn_lease_loss_stop(rx, move || stop(), FAST.lost_stop_deadline, backstop);
        drop(tx); // an orderly stop for another reason: the renewal task went
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the watch ends with its sender")
            .unwrap();
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert_eq!(backstops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn broadcast_is_refused_and_the_refusal_names_the_switch_and_the_fix() {
        assert_eq!(refuse_broadcast(false), Ok(()));
        let refusal = refuse_broadcast(true).unwrap_err();
        let text = refusal.to_string();
        assert!(text.contains("AXIAM__AMQP__ENABLED=false"));
        assert!(text.contains("DECISION_CACHE_BROADCAST_ENABLED"));
        assert!(text.contains("AXIAM__AMQP__ENABLED=true"), "names the fix");
    }

    #[tokio::test]
    async fn an_enabled_reactor_registration_in_any_tenant_is_refused() {
        let db = db().await;
        let reactors = SurrealReactorRepository::new(db.clone());
        assert_eq!(refuse_enabled_reactors(&reactors).await, Ok(()));

        let mut disabled = new_reactor(Uuid::new_v4(), "off");
        disabled.enabled = false;
        reactors.create(disabled).await.unwrap();
        assert_eq!(
            refuse_enabled_reactors(&reactors).await,
            Ok(()),
            "a disabled registration is not a reason to refuse"
        );

        reactors
            .create(new_reactor(Uuid::new_v4(), "on"))
            .await
            .unwrap();
        let refusal = refuse_enabled_reactors(&reactors).await.unwrap_err();
        assert_eq!(refusal, ProfileRefusal::EnabledReactors(1));
        let text = refusal.to_string();
        assert!(text.contains("AXIAM__AMQP__ENABLED=false"));
        assert!(text.contains("enabled: false"), "names the fix");
    }

    fn new_reactor(tenant_id: Uuid, name: &str) -> CreateReactor {
        CreateReactor {
            tenant_id,
            name: name.into(),
            description: String::new(),
            events: vec!["login.post_auth".into()],
            mode: ReactorMode::Intercept,
            priority: 0,
            timeout_ms: None,
            failure_policy: None,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn a_free_lease_is_acquired_at_once() {
        let leases = SurrealMinimalProfileLeaseRepository::new(db().await);
        acquire_lease(&leases, "a", FAST).await.unwrap();
        assert_eq!(leases.current().await.unwrap().unwrap().holder, "a");
    }

    #[tokio::test]
    async fn a_second_live_instance_is_refused_after_the_wait() {
        let leases = SurrealMinimalProfileLeaseRepository::new(db().await);
        acquire_lease(&leases, "a", FAST).await.unwrap();
        // `a` keeps renewing, as a live instance does.
        let (never, lost) = lost_flag();
        let renewal = spawn_lease_renewal(leases.clone(), "a".into(), FAST, never);

        let started = tokio::time::Instant::now();
        let refusal = acquire_lease(&leases, "b", FAST).await.unwrap_err();
        assert!(
            started.elapsed() >= FAST.boot_wait,
            "the boot waits the full window before refusing"
        );
        match &refusal {
            ProfileRefusal::SecondInstance { holder, .. } => assert_eq!(holder, "a"),
            other => panic!("expected SecondInstance, got {other:?}"),
        }
        assert!(refusal.to_string().contains("AXIAM__AMQP__ENABLED=false"));
        assert!(!lost.load(Ordering::SeqCst), "a still holds it");
        renewal.abort();
    }

    #[tokio::test]
    async fn a_boot_that_finds_a_dying_instances_lease_waits_and_takes_over() {
        let leases = SurrealMinimalProfileLeaseRepository::new(db().await);
        // `a` claimed, then stopped (no renewal): its lease expires within the TTL.
        acquire_lease(&leases, "a", FAST).await.unwrap();

        let started = tokio::time::Instant::now();
        acquire_lease(&leases, "b", FAST).await.unwrap();
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(150) && waited < FAST.boot_wait,
            "b waited for a's lease to expire, not the whole window: {waited:?}"
        );
        assert_eq!(leases.current().await.unwrap().unwrap().holder, "b");
    }

    #[tokio::test]
    async fn the_holder_keeps_the_lease_by_renewing_it() {
        let leases = SurrealMinimalProfileLeaseRepository::new(db().await);
        acquire_lease(&leases, "a", FAST).await.unwrap();
        let (never, lost) = lost_flag();
        let renewal = spawn_lease_renewal(leases.clone(), "a".into(), FAST, never);

        // Three TTLs later the lease is still a's.
        tokio::time::sleep(FAST.ttl * 3).await;
        let row = leases.current().await.unwrap().unwrap();
        assert_eq!(row.holder, "a");
        assert!(row.expires_at > Utc::now(), "renewed, not expired");
        assert!(!lost.load(Ordering::SeqCst));
        renewal.abort();
    }

    #[tokio::test]
    async fn an_instance_whose_renewal_finds_the_lease_taken_reports_it_lost() {
        let leases = SurrealMinimalProfileLeaseRepository::new(db().await);
        acquire_lease(&leases, "a", FAST).await.unwrap();

        // a stalls (no renewal task yet); b takes the expired lease over.
        tokio::time::sleep(FAST.ttl + Duration::from_millis(50)).await;
        acquire_lease(&leases, "b", FAST).await.unwrap();

        // a wakes up and renews: it must find the lease is not its own.
        let (on_lost, lost) = lost_flag();
        let renewal = spawn_lease_renewal(leases.clone(), "a".into(), FAST, on_lost);
        tokio::time::timeout(Duration::from_secs(2), renewal)
            .await
            .expect("the renewal task ends once the lease is lost")
            .unwrap();
        assert!(lost.load(Ordering::SeqCst), "the lost-lease reaction ran");
        assert_eq!(leases.current().await.unwrap().unwrap().holder, "b");
    }

    #[tokio::test]
    async fn enforce_runs_the_checks_in_order_and_holds_the_lease() {
        let db = db().await;
        let reactors = SurrealReactorRepository::new(db.clone());
        let leases = SurrealMinimalProfileLeaseRepository::new(db.clone());
        let (never, _) = lost_flag();

        // Broadcast first: refused before the datastore is touched.
        let refusal = enforce_minimal_profile(
            true,
            &reactors,
            leases.clone(),
            "a",
            FAST,
            Arc::clone(&never),
        )
        .await
        .unwrap_err();
        assert_eq!(refusal, ProfileRefusal::BroadcastEnabled);
        assert!(leases.current().await.unwrap().is_none(), "no lease taken");

        // Then reactors.
        reactors
            .create(new_reactor(Uuid::new_v4(), "on"))
            .await
            .unwrap();
        let refusal = enforce_minimal_profile(
            false,
            &reactors,
            leases.clone(),
            "a",
            FAST,
            Arc::clone(&never),
        )
        .await
        .unwrap_err();
        assert_eq!(refusal, ProfileRefusal::EnabledReactors(1));
        assert!(leases.current().await.unwrap().is_none(), "no lease taken");
    }

    #[tokio::test]
    async fn enforce_with_nothing_wrong_holds_the_lease_and_renews_it() {
        let db = db().await;
        let reactors = SurrealReactorRepository::new(db.clone());
        let leases = SurrealMinimalProfileLeaseRepository::new(db);
        let (never, _) = lost_flag();
        let renewal = enforce_minimal_profile(false, &reactors, leases.clone(), "a", FAST, never)
            .await
            .unwrap();
        assert_eq!(leases.current().await.unwrap().unwrap().holder, "a");
        renewal.abort();
    }
}
