//! The orderly stop for a component that died (P23W5-A11, A12; D-72).
//!
//! The full profile used to end the process with `std::process::exit(1)` when
//! the authz consumer, the audit-ingestion consumer, the mail consumer or the
//! gRPC server stopped: wherever it was, with the audit rows still queued, the
//! requests in flight and a GDPR purge between its erasure and its audit row
//! all lost — the hazard the minimal profile's lost lease had until T23.8.2.
//!
//! A dying component now [`raise`](FatalStop::raise)s the signal instead.
//! [`spawn_fatal_stop`] waits on it and runs the lost-lease path's stop (the
//! REST listener stops accepting and finishes what is in flight, the teardown
//! after it stops gRPC, drains the audit queue and the cleanup task, and
//! `serve` returns an error, so `main` exits non-zero), with a backstop if that
//! does not finish in time. The deadline is the caller's: it covers the whole
//! stop, which is longer than the lease's.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::error;

use crate::profile::OnLeaseLost;

/// The signal a dying component raises. Cheap to clone into each task.
#[derive(Clone)]
pub struct FatalStop(Arc<watch::Sender<Option<&'static str>>>);

impl FatalStop {
    /// A signal and the receiver [`spawn_fatal_stop`] and the teardown read.
    pub fn new() -> (Self, watch::Receiver<Option<&'static str>>) {
        let (tx, rx) = watch::channel(None);
        (Self(Arc::new(tx)), rx)
    }

    /// `component` has stopped and the process cannot go on without it. The
    /// first component to say so is the one reported.
    pub fn raise(&self, component: &'static str) {
        error!(component, "a component the server needs has stopped");
        self.0.send_if_modified(|first| {
            // Later deaths are consequences of the first.
            if first.is_some() {
                return false;
            }
            *first = Some(component);
            true
        });
    }
}

/// Once the signal is raised: call `stop` (the composition root's orderly
/// stop, as for a lost lease) and, if the process is still here `deadline`
/// later, run `backstop`. The composition root aborts the returned task when
/// its teardown has finished, which disarms the backstop.
pub fn spawn_fatal_stop(
    mut died: watch::Receiver<Option<&'static str>>,
    stop: impl FnOnce() + Send + 'static,
    deadline: Duration,
    backstop: OnLeaseLost,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // The `Ref` is copied out of and dropped here: it is not `Send`.
        let component = match died.wait_for(Option::is_some).await {
            Ok(raised) => (*raised).unwrap_or_default(),
            Err(_) => return,
        };
        error!(
            component,
            deadline_secs = deadline.as_secs_f64(),
            "stopping in order (no new connections, in-flight work finished, queued audit \
             rows written) and then exiting non-zero"
        );
        stop();
        tokio::time::sleep(deadline).await;
        error!("the orderly stop after a component died did not finish in time — exiting now");
        backstop();
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    const DEADLINE: Duration = Duration::from_millis(150);

    fn counter() -> (Arc<AtomicU32>, OnLeaseLost) {
        let n = Arc::new(AtomicU32::new(0));
        let m = Arc::clone(&n);
        (
            n,
            Arc::new(move || {
                m.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    #[test]
    fn the_first_component_to_die_is_the_one_reported() {
        let (fatal, rx) = FatalStop::new();
        assert_eq!(*rx.borrow(), None);
        fatal.raise("AMQP mail consumer");
        fatal.raise("gRPC server");
        assert_eq!(*rx.borrow(), Some("AMQP mail consumer"));
    }

    #[tokio::test]
    async fn a_dead_consumer_starts_the_orderly_stop_at_once_and_the_backstop_only_after_the_deadline()
     {
        let (fatal, rx) = FatalStop::new();
        let (stops, stop) = counter();
        let (backstops, backstop) = counter();
        let task = spawn_fatal_stop(rx, move || stop(), DEADLINE, backstop);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(stops.load(Ordering::SeqCst), 0, "nothing while all run");

        // A consumer task that returns is what raises it, as in `boot`.
        tokio::spawn(async move {
            fatal.raise("AMQP authz consumer");
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(stops.load(Ordering::SeqCst), 1, "the orderly stop starts");
        assert_eq!(backstops.load(Ordering::SeqCst), 0, "the backstop waits");

        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the task ends after the backstop")
            .unwrap();
        assert_eq!(backstops.load(Ordering::SeqCst), 1, "an overrun ends in it");
    }

    #[tokio::test]
    async fn an_orderly_stop_that_finishes_in_time_disarms_the_backstop() {
        let (fatal, rx) = FatalStop::new();
        let (stops, stop) = counter();
        let (backstops, backstop) = counter();
        let task = spawn_fatal_stop(rx, move || stop(), DEADLINE, backstop);
        fatal.raise("gRPC server");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        task.abort(); // the teardown finished
        tokio::time::sleep(DEADLINE * 2).await;
        assert_eq!(backstops.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn two_deaths_stop_once() {
        let (fatal, rx) = FatalStop::new();
        let (stops, stop) = counter();
        let (_, backstop) = counter();
        let task = spawn_fatal_stop(rx, move || stop(), Duration::from_secs(60), backstop);
        fatal.raise("AMQP audit consumer");
        fatal.raise("gRPC server");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn nothing_dying_never_stops() {
        let (fatal, rx) = FatalStop::new();
        let (stops, stop) = counter();
        let (backstops, backstop) = counter();
        let task = spawn_fatal_stop(rx, move || stop(), DEADLINE, backstop);
        drop(fatal); // the sender goes with the server: an ordinary stop
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the watch ends with its sender")
            .unwrap();
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        assert_eq!(backstops.load(Ordering::SeqCst), 0);
    }
}
