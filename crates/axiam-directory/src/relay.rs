//! The relay between a directory's TLS stream and `ldap3`, which is where the
//! frame guard ([`crate::frame`]) runs.
//!
//! `ldap3 0.12` accepts an already-open stream only as a standard-library TCP
//! or Unix socket, and does its own TLS on the former — so a size check placed
//! under it would see ciphertext. AXIAM therefore does the TLS handshake itself
//! (`DirectoryClient::connect`) and gives `ldap3` one end of a Unix socket
//! pair, as an `ldapi` connection; a task forwards between the pair's other end
//! and the TLS stream:
//!
//! * **`ldap3` → directory**: copied as is. `ldap3` builds these requests.
//! * **directory → `ldap3`**: one LDAP message at a time, each read whole and
//!   checked by [`crate::frame::read_message`] before a byte of it is written
//!   on. The first message refused ends the relay; closing both sockets fails
//!   the operation in flight as the directory being unavailable, and the
//!   connection is never pooled again (`ldap3` reports it closed).
//!
//! The pair is private to the process: nothing else can connect to it, there
//! is no listening socket and no filesystem path. On a platform without Unix
//! sockets the connector refuses to connect rather than run without the guard.

use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

use crate::client::Failure;

/// The URL `ldap3` is given for the local end. Only its scheme is read: with a
/// stream supplied, `ldap3` resolves nothing and opens nothing.
#[cfg(unix)]
const RELAY_URL: &str = "ldapi://axiam-directory-relay";

/// Put the frame guard between `directory` (the verified TLS stream) and a new
/// `ldap3` connection, and return its handle and the relay task (which owns
/// the TCP socket: the socket is closed when the task ends). The relay task and
/// the `ldap3` driver are spawned; both end when either side closes.
#[cfg(unix)]
pub(crate) async fn attach<S>(
    directory: S,
    max_message_bytes: usize,
    tenant_id: Uuid,
) -> Result<(ldap3::Ldap, tokio::task::JoinHandle<()>), Failure>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    use axiam_core::models::directory::DirectoryAuthError;
    use ldap3::{LdapConnAsync, LdapConnSettings, StdStream};

    let unreachable = || {
        Failure::new(
            DirectoryAuthError::Unavailable,
            "the directory connection could not be set up",
        )
    };
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().map_err(|_| unreachable())?;
    ours.set_nonblocking(true).map_err(|_| unreachable())?;
    let ours = tokio::net::UnixStream::from_std(ours).map_err(|_| unreachable())?;
    let relay = tokio::spawn(run(directory, ours, max_message_bytes, tenant_id));

    let settings = LdapConnSettings::new().set_std_stream(StdStream::Unix(theirs));
    let (conn, ldap) = LdapConnAsync::with_settings(settings, RELAY_URL)
        .await
        .map_err(|_| unreachable())?;
    tokio::spawn(async move {
        if let Err(error) = conn.drive().await {
            tracing::debug!(target: "axiam::directory", error = %error, "directory connection closed");
        }
    });
    Ok((ldap, relay))
}

/// Without Unix sockets there is no way to put the guard beneath `ldap3`, and
/// a connector without it is not one AXIAM runs: refuse.
#[cfg(not(unix))]
pub(crate) async fn attach<S>(
    _directory: S,
    _max_message_bytes: usize,
    _tenant_id: Uuid,
) -> Result<(ldap3::Ldap, tokio::task::JoinHandle<()>), Failure>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    Err(Failure::new(
        axiam_core::models::directory::DirectoryAuthError::Unavailable,
        "the directory connector requires a platform with Unix sockets",
    ))
}

/// Forward until either side closes or the directory sends a message the frame
/// guard refuses.
#[cfg(unix)]
async fn run<S>(
    directory: S,
    local: tokio::net::UnixStream,
    max_message_bytes: usize,
    tenant_id: Uuid,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    use tokio::io::AsyncWriteExt;

    let (mut from_directory, mut to_directory) = tokio::io::split(directory);
    let (mut from_ldap3, mut to_ldap3) = local.into_split();

    let upstream = async {
        let _ = tokio::io::copy(&mut from_ldap3, &mut to_directory).await;
        let _ = to_directory.shutdown().await;
    };
    let downstream = async {
        loop {
            match crate::frame::read_message(&mut from_directory, max_message_bytes).await {
                Ok(Some(message)) => {
                    if to_ldap3.write_all(&message).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(refusal) => {
                    tracing::warn!(
                        target: "axiam::directory",
                        %tenant_id,
                        reason = %refusal,
                        "directory connection closed: the frame guard refused a message"
                    );
                    break;
                }
            }
        }
        let _ = to_ldap3.shutdown().await;
    };
    tokio::select! {
        () = upstream => {}
        () = downstream => {}
    }
}
