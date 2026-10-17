//! The boot-time warning for confidential clients that hold the device grant
//! (R110W3-02, #675).
//!
//! Since 1.1.0 (#635) the device grant authenticates its client at both
//! endpoints by the method the client was registered with. A client registered
//! without `token_endpoint_auth_method` is confidential, and the 1.0.x
//! quickstart registered device clients that way; its devices send only a
//! `client_id`, so after the upgrade every one of them is answered
//! `401 invalid_client` and the server's only trace is a per-request audit row.
//! This is the one line that names the cause once, at startup.
//!
//! What it promises, and how:
//!
//! * **Counts only.** The line carries two numbers. No client id, client name
//!   or tenant name reaches the log.
//! * **Bounded.** One round trip, two aggregates; no row of any client leaves
//!   the datastore (`count_confidential_with_grant`).
//! * **Never fails or delays boot.** [`spawn_boot_scan`] runs on its own task
//!   and the scan has a deadline; an error or a timeout is a `warn!` and the
//!   server carries on.
//! * **Once per process.** The task is spawned at most once, however often the
//!   composition root is entered.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axiam_core::error::AxiamResult;
use axiam_core::models::oauth2_client::ConfidentialGrantCount;
use axiam_core::repository::OAuth2ClientRepository;
use axiam_oauth2::device_service::DEVICE_CODE_GRANT_SPELLINGS;

/// How long the scan may take before boot gives up on it. It runs beside
/// boot, not in front of it, so this bounds a task, not startup.
pub const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

static SPAWNED: AtomicBool = AtomicBool::new(false);

/// Start the scan on its own task, unless this process already did.
///
/// Returns the task's handle when it started one, so a test can wait for it;
/// the composition root drops it.
pub fn spawn_boot_scan<R>(repo: R) -> Option<tokio::task::JoinHandle<()>>
where
    R: OAuth2ClientRepository + 'static,
{
    if SPAWNED.swap(true, Ordering::SeqCst) {
        return None;
    }
    Some(tokio::spawn(async move {
        scan_with(
            repo.count_confidential_with_grant(&DEVICE_CODE_GRANT_SPELLINGS),
            SCAN_TIMEOUT,
        )
        .await;
    }))
}

/// Run one scan under `timeout` and log its outcome: one `warn!` when there is
/// something to say or when the scan could not finish, nothing when the count
/// is zero.
///
/// The scan is a parameter so a test can hand it a failing or a never-ending
/// one.
pub async fn scan_with<F>(scan: F, timeout: Duration)
where
    F: Future<Output = AxiamResult<ConfidentialGrantCount>>,
{
    match tokio::time::timeout(timeout, scan).await {
        Ok(Ok(count)) if count.clients == 0 => {
            tracing::debug!("no confidential OAuth2 client holds the device-code grant");
        }
        Ok(Ok(count)) => tracing::warn!(
            clients = count.clients,
            tenants = count.tenants,
            "{} confidential OAuth2 client(s) in {} tenant(s) hold the device-code grant. Since 1.1.0 \
             such a client must send its credential at both device endpoints \
             (/oauth2/device_authorization and the token poll) or the flow answers 401 \
             invalid_client. A device that sends only a client_id needs a public client \
             (token_endpoint_auth_method: none); a client cannot be changed between public \
             and confidential. See the upgrade note in CHANGELOG.md [1.1.0] and \
             docs/api/device-flow.md",
            count.clients,
            count.tenants,
        ),
        Ok(Err(e)) => tracing::warn!(
            error = %e,
            "could not count the confidential OAuth2 clients that hold the device-code grant; \
             startup continues"
        ),
        Err(_) => tracing::warn!(
            timeout_secs = timeout.as_secs_f32(),
            "counting the confidential OAuth2 clients that hold the device-code grant timed \
             out; startup continues"
        ),
    }
}
